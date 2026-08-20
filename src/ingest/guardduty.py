import json
import sys
from datetime import datetime
from pathlib import Path

import boto3

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from models import Alert, Severity


def _map_severity(score: float) -> Severity:
    # GuardDuty scores 1.0-8.9
    if score >= 7.0:
        return Severity.CRITICAL
    if score >= 4.0:
        return Severity.HIGH
    if score >= 2.0:
        return Severity.MEDIUM
    return Severity.LOW


def normalize(finding: dict) -> Alert:
    svc = finding.get("Service", {})
    action = svc.get("Action", {})
    resource = finding.get("Resource", {})
    keys = resource.get("AccessKeyDetails", {})

    principal = (
        resource.get("AccessKeyDetails", {}).get("UserName")
        or resource.get("AccessKeyDetails", {}).get("PrincipalId")
    )

    source_ip = None
    for key in ("AwsApiCallAction", "NetworkConnectionAction", "PortProbeAction"):
        remote = action.get(key, {}).get("RemoteIpDetails", {})
        if remote.get("IpAddressV4"):
            source_ip = remote["IpAddressV4"]
            break

    resource_type = resource.get("ResourceType")
    resource_name = (
        resource.get("InstanceDetails", {}).get("InstanceId")
        or (resource.get("S3BucketDetails") or [{}])[0].get("Name")
        or keys.get("UserName")
    )

    return Alert(
        alert_id=finding["Id"],
        source="guardduty",
        title=finding.get("Title", finding.get("Type", "unknown")),
        description=finding.get("Description", ""),
        severity=_map_severity(finding.get("Severity", 0)),
        raw_severity=finding.get("Severity"),
        created_at=datetime.fromisoformat(
            finding["CreatedAt"].replace("Z", "+00:00")
        ),
        region=finding.get("Region", "unknown"),
        account_id=finding.get("AccountId", "unknown"),
        principal=principal,
        resource=resource_name,
        resource_type=resource_type,
        source_ip=source_ip,
        threat_family=finding.get("Type", "").split(":")[0] or None,
        raw=finding,
    )


def fetch_findings(region: str = "us-east-1") -> list[Alert]:
    gd = boto3.client("guardduty", region_name=region)
    detectors = gd.list_detectors()["DetectorIds"]
    if not detectors:
        raise RuntimeError("No GuardDuty detector found. Enable GuardDuty first.")

    detector_id = detectors[0]
    ids = gd.list_findings(DetectorId=detector_id, MaxResults=50)["FindingIds"]
    if not ids:
        return []

    findings = gd.get_findings(DetectorId=detector_id, FindingIds=ids)["Findings"]
    return [normalize(f) for f in findings]


if __name__ == "__main__":
    from rich import print as rprint

    alerts = fetch_findings()
    rprint(f"[bold green]Fetched {len(alerts)} alerts[/bold green]")

    out = Path("data/samples/guardduty.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps([a.model_dump(mode="json") for a in alerts], indent=2))
    rprint(f"Saved to {out}")

    for a in alerts[:3]:
        rprint(a)
