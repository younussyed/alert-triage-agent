import sys
from pathlib import Path
from typing import Protocol

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from models import (
    Alert,
    BehaviorContext,
    EnrichedAlert,
    NetworkContext,
    PrincipalContext,
)


class Enricher(Protocol):
    """Anything that can add context to an alert."""

    def enrich(self, alert: Alert) -> EnrichedAlert: ...


class MockEnricher:
    """Deterministic fake context. Lets the pipeline run without AWS."""

    KNOWN_BAD_IPS = {"192.0.2.55", "198.51.100.99"}
    CORPORATE_RANGES = ("10.", "172.16.", "192.168.")
    SERVICE_ACCOUNT_PREFIXES = ("svc-", "service-", "ci-", "deploy-")

    def _principal(self, alert: Alert) -> PrincipalContext | None:
        if not alert.principal:
            return None
        name = alert.principal
        is_svc = name.startswith(self.SERVICE_ACCOUNT_PREFIXES)
        return PrincipalContext(
            name=name,
            exists=True,
            age_days=3 if name == "admin-user" else 420,
            is_service_account=is_svc,
            has_admin_policy="admin" in name.lower(),
            attached_policies=(
                ["AdministratorAccess"] if "admin" in name.lower()
                else ["ReadOnlyAccess"]
            ),
            mfa_enabled=False if "admin" in name.lower() else None,
        )

    def _network(self, alert: Alert) -> NetworkContext | None:
        if not alert.source_ip:
            return None
        ip = alert.source_ip
        return NetworkContext(
            ip=ip,
            country="RU" if ip in self.KNOWN_BAD_IPS else "US",
            is_known_cloud_provider=False,
            is_corporate_range=ip.startswith(self.CORPORATE_RANGES),
            threat_intel_hits=["abuse.ch"] if ip in self.KNOWN_BAD_IPS else [],
        )

    def _behavior(self, alert: Alert) -> BehaviorContext:
        hour = alert.created_at.hour
        return BehaviorContext(
            alert_type_count_90d=47 if alert.threat_family == "Recon" else 2,
            principal_seen_before=alert.principal != "admin-user",
            unusual_hour=hour < 6 or hour > 22,
            prior_true_positive_rate=0.02 if alert.threat_family == "Recon" else 0.5,
        )

    def enrich(self, alert: Alert) -> EnrichedAlert:
        errors: list[str] = []
        principal_ctx = network_ctx = None

        try:
            principal_ctx = self._principal(alert)
        except Exception as exc:
            errors.append(f"principal lookup failed: {exc}")

        try:
            network_ctx = self._network(alert)
        except Exception as exc:
            errors.append(f"network lookup failed: {exc}")

        return EnrichedAlert(
            alert=alert,
            principal_ctx=principal_ctx,
            network_ctx=network_ctx,
            behavior_ctx=self._behavior(alert),
            enrichment_errors=errors,
        )
