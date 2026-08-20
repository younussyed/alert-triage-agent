import json
import sys
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from models import EnrichedAlert, TriageResult, Verdict
from triage.prompt import SYSTEM_PROMPT, build_user_message

DEFAULT_MODEL = "us.anthropic.claude-haiku-4-5-20251001-v1:0"


class TriageAgent:
    def __init__(self, model_id: str = DEFAULT_MODEL, region: str = "us-east-1"):
        self.model_id = model_id
        self.client = boto3.client(
            "bedrock-runtime",
            region_name=region,
            config=Config(retries={"max_attempts": 3, "mode": "adaptive"}),
        )

    def _fallback(self, alert_id: str, reason: str) -> TriageResult:
        """On any failure, escalate. Never auto-close on error."""
        return TriageResult(
            alert_id=alert_id,
            verdict=Verdict.INSUFFICIENT_DATA,
            confidence=0.0,
            rationale=f"Triage failed: {reason}",
            recommended_action="Manual review required.",
            evidence_used=[],
        )

    def triage(self, enriched: EnrichedAlert) -> TriageResult:
        alert_id = enriched.alert.alert_id
        try:
            response = self.client.converse(
                modelId=self.model_id,
                system=[{"text": SYSTEM_PROMPT}],
                messages=[{
                    "role": "user",
                    "content": [{"text": build_user_message(enriched)}],
                }],
                inferenceConfig={"maxTokens": 800, "temperature": 0.0},
            )
        except ClientError as exc:
            return self._fallback(alert_id, f"Bedrock error: {exc}")

        text = response["output"]["message"]["content"][0]["text"].strip()
        text = text.removeprefix("```json").removeprefix("```").removesuffix("```")

        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return self._fallback(alert_id, "model returned non-JSON output")

        payload["alert_id"] = alert_id
        try:
            return TriageResult(**payload)
        except ValidationError as exc:
            return self._fallback(alert_id, f"schema validation failed: {exc}")
