from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Alert(BaseModel):
    """Normalized alert. Every ingestion source maps into this."""
    alert_id: str
    source: str                      # "guardduty", "cloudtrail", etc.
    title: str
    description: str = ""
    severity: Severity
    raw_severity: float | None = None
    created_at: datetime
    region: str = "unknown"
    account_id: str = "unknown"

    # who / what
    principal: str | None = None     # IAM user/role that triggered it
    resource: str | None = None      # affected resource ARN or name
    resource_type: str | None = None
    source_ip: str | None = None

    # classification hints
    threat_family: str | None = None  # e.g. "Recon", "CredentialAccess"
    mitre_technique: str | None = None

    raw: dict[str, Any] = Field(default_factory=dict, repr=False)


class Verdict(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    INSUFFICIENT_DATA = "insufficient_data"


class TriageResult(BaseModel):
    """What the LLM is forced to return. No free-form text."""
    alert_id: str
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    recommended_action: str
    evidence_used: list[str] = Field(default_factory=list)


class PrincipalContext(BaseModel):
    """What we know about the identity that triggered the alert."""
    name: str
    exists: bool = True
    age_days: int | None = None
    is_service_account: bool = False
    has_admin_policy: bool = False
    attached_policies: list[str] = Field(default_factory=list)
    mfa_enabled: bool | None = None


class NetworkContext(BaseModel):
    """What we know about the source of the activity."""
    ip: str | None = None
    country: str | None = None
    is_known_cloud_provider: bool = False
    is_corporate_range: bool = False
    threat_intel_hits: list[str] = Field(default_factory=list)


class BehaviorContext(BaseModel):
    """Historical baseline for this alert / principal."""
    alert_type_count_90d: int = 0
    principal_seen_before: bool = True
    unusual_hour: bool = False
    prior_true_positive_rate: float | None = None


class EnrichedAlert(BaseModel):
    """An Alert plus everything we gathered about it."""
    alert: Alert
    principal_ctx: PrincipalContext | None = None
    network_ctx: NetworkContext | None = None
    behavior_ctx: BehaviorContext | None = None
    enrichment_errors: list[str] = Field(default_factory=list)
