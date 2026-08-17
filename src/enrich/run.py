import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from enrich.base import MockEnricher
from ingest.from_file import load

if __name__ == "__main__":
    from rich import print as rprint

    target = sys.argv[1] if len(sys.argv) > 1 else "data/samples/guardduty_seed.json"
    enricher = MockEnricher()

    for alert in load(target):
        enriched = enricher.enrich(alert)
        rprint(f"\n[bold cyan]{enriched.alert.alert_id}[/bold cyan] "
               f"{enriched.alert.title}")
        rprint(enriched.principal_ctx)
        rprint(enriched.network_ctx)
        rprint(enriched.behavior_ctx)
