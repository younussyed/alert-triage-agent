import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from enrich.base import MockEnricher
from ingest.from_file import load
from triage.agent import TriageAgent

if __name__ == "__main__":
    from rich import print as rprint

    target = sys.argv[1] if len(sys.argv) > 1 else "data/samples/guardduty_seed.json"
    enricher, agent = MockEnricher(), TriageAgent()

    for alert in load(target):
        result = agent.triage(enricher.enrich(alert))
        rprint(f"\n[bold cyan]{result.alert_id}[/bold cyan] — {alert.title}")
        rprint(f"[bold]{result.verdict.value.upper()}[/bold] "
               f"(confidence {result.confidence})")
        rprint(f"{result.rationale}")
        rprint(f"[dim]Action: {result.recommended_action}[/dim]")
