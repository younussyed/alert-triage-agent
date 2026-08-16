import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ingest.guardduty import normalize
from models import Alert


def load(path: str) -> list[Alert]:
    findings = json.loads(Path(path).read_text())
    return [normalize(f) for f in findings]


if __name__ == "__main__":
    from rich import print as rprint

    target = sys.argv[1] if len(sys.argv) > 1 else "data/samples/guardduty_seed.json"
    alerts = load(target)
    rprint(f"[bold green]Loaded {len(alerts)} alerts[/bold green]\n")
    for a in alerts:
        rprint(a)
