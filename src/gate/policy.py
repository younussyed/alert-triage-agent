import sys
from enum import Enum
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from models import EnrichedAlert, TriageResult, Verdict


class Disposition(str, Enum):
    AUTO_CLOSED = "auto_closed"
    ESCALATED = "escalated"


# Finding-type prefixes that may never be auto-closed, regardless of what
# the model concludes. These are cases where a false negative is
# unacceptable: total account compromise, credential theft, anti-forensics.
NEVER_AUTO_CLOSE = (
    "Policy:IAMUser/RootCredentialUsage",
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
    "Stealth:IAMUser/CloudTrailLoggingDisabled",
    "PrivilegeEscalation:",
    "Exfiltration:",
)

AUTO_CLOSE_THRESHOLD = 0.80


class DecisionGate:
    def __init__(self, threshold: float = AUTO_CLOSE_THRESHOLD):
        self.threshold = threshold

    def decide(
        self, enriched: EnrichedAlert, result: TriageResult
    ) -> tuple[Disposition, str]:
        finding_type = enriched.alert.raw.get("Type", "")

        if finding_type.startswith(NEVER_AUTO_CLOSE):
            return Disposition.ESCALATED, "finding type is never auto-closed"

        if enriched.enrichment_errors:
            return Disposition.ESCALATED, "enrichment incomplete"

        if result.verdict is not Verdict.BENIGN:
            return Disposition.ESCALATED, f"verdict is {result.verdict.value}"

        if result.confidence < self.threshold:
            return (
                Disposition.ESCALATED,
                f"confidence {result.confidence:.2f} below {self.threshold:.2f}",
            )

        return Disposition.AUTO_CLOSED, "benign with high confidence"
