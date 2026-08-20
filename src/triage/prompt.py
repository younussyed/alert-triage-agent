import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from models import EnrichedAlert

SYSTEM_PROMPT = """You are a cloud security analyst performing first-pass \
triage on AWS security alerts.

You will be given an alert plus enrichment context gathered from the \
environment. Assess whether the alert represents genuine malicious activity.

Reason from the evidence provided. Do not assume facts that are not stated. \
If context is missing or enrichment failed, factor that uncertainty into your \
confidence score rather than guessing.

Weigh these signals:
- Identity risk: new accounts, admin privileges, missing MFA, unfamiliar principals
- Network risk: threat intel hits, unexpected geography, non-corporate ranges
- Behavioral baseline: how often this alert type fires and its historical \
true-positive rate. A noisy alert type with a low historical TP rate is likely noise.
- Absence of a principal is normal for network- and instance-scoped findings; \
it is not itself suspicious.

Verdicts:
- benign: routine activity or known-noisy alert type with no corroborating risk
- suspicious: warrants human review but not conclusive
- malicious: multiple corroborating indicators of genuine compromise
- insufficient_data: cannot assess responsibly with what was provided

Confidence reflects certainty in your verdict, not severity of the alert.

Respond with a single JSON object and nothing else. No markdown fences, \
no preamble. Schema:
{
  "verdict": "benign" | "suspicious" | "malicious" | "insufficient_data",
  "confidence": <float 0.0-1.0>,
  "rationale": "<2-3 sentences citing the specific evidence you relied on>",
  "recommended_action": "<concrete next step for the analyst>",
  "evidence_used": ["<short label>", "..."]
}"""


def build_user_message(enriched: EnrichedAlert) -> str:
    a = enriched.alert
    lines = [
        "## Alert",
        f"ID: {a.alert_id}",
        f"Source: {a.source}",
        f"Title: {a.title}",
        f"Description: {a.description}",
        f"Severity (source-assigned): {a.severity.value} ({a.raw_severity})",
        f"Threat family: {a.threat_family}",
        f"Time: {a.created_at.isoformat()}",
        f"Region: {a.region}",
        f"Resource: {a.resource} ({a.resource_type})",
        "",
        "## Identity context",
    ]

    if enriched.principal_ctx:
        p = enriched.principal_ctx
        lines += [
            f"Principal: {p.name}",
            f"Account age (days): {p.age_days}",
            f"Service account: {p.is_service_account}",
            f"Has admin policy: {p.has_admin_policy}",
            f"Attached policies: {', '.join(p.attached_policies) or 'none'}",
            f"MFA enabled: {p.mfa_enabled}",
        ]
    else:
        lines.append("No IAM principal associated with this finding.")

    lines += ["", "## Network context"]
    if enriched.network_ctx:
        n = enriched.network_ctx
        lines += [
            f"Source IP: {n.ip}",
            f"Country: {n.country}",
            f"Corporate range: {n.is_corporate_range}",
            f"Known cloud provider: {n.is_known_cloud_provider}",
            f"Threat intel hits: {', '.join(n.threat_intel_hits) or 'none'}",
        ]
    else:
        lines.append("No network context available.")

    lines += ["", "## Behavioral baseline"]
    if enriched.behavior_ctx:
        b = enriched.behavior_ctx
        lines += [
            f"This alert type fired {b.alert_type_count_90d} times in 90 days",
            f"Historical true-positive rate: {b.prior_true_positive_rate}",
            f"Principal seen before: {b.principal_seen_before}",
            f"Unusual hour: {b.unusual_hour}",
        ]

    if enriched.enrichment_errors:
        lines += ["", "## Enrichment failures (evidence is incomplete)"]
        lines += [f"- {e}" for e in enriched.enrichment_errors]

    return "\n".join(lines)
