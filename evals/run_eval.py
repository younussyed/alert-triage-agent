import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from enrich.base import MockEnricher
from gate.policy import DecisionGate, Disposition
from ingest.from_file import load
from triage.agent import TriageAgent


def main(corpus: str, labels_path: str):
    from rich import print as rprint
    from rich.table import Table

    labels = json.loads(Path(labels_path).read_text())
    alerts = load(corpus)
    enricher, agent, gate = MockEnricher(), TriageAgent(), DecisionGate()

    rows, verdicts = [], Counter()
    tp = fp = tn = fn = 0

    for i, alert in enumerate(alerts, 1):
        meta = labels[alert.alert_id]
        truth = meta["label"]

        enriched = enricher.enrich(alert)
        result = agent.triage(enriched)
        disposition, reason = gate.decide(enriched, result)

        verdicts[result.verdict.value] += 1
        closed = disposition is Disposition.AUTO_CLOSED

        if truth == "malicious":
            if closed:
                fn += 1          # missed a real threat
            else:
                tp += 1
        else:
            if closed:
                tn += 1          # correctly suppressed noise
            else:
                fp += 1          # unnecessary escalation

        rows.append({
            "id": alert.alert_id,
            "truth": truth,
            "difficulty": meta["difficulty"],
            "verdict": result.verdict.value,
            "confidence": result.confidence,
            "disposition": disposition.value,
            "reason": reason,
            "rationale": result.rationale,
        })
        rprint(f"[dim]{i}/{len(alerts)}[/dim] {alert.alert_id} "
               f"truth={truth} verdict={result.verdict.value} "
               f"-> {disposition.value}")

    total = len(alerts)
    escalated = tp + fp
    auto_closed = tn + fn

    table = Table(title="Triage evaluation")
    table.add_column("metric"); table.add_column("value", justify="right")
    table.add_row("alerts", str(total))
    table.add_row("auto-closed", f"{auto_closed} ({auto_closed/total:.0%})")
    table.add_row("escalated", f"{escalated} ({escalated/total:.0%})")
    table.add_row("", "")
    table.add_row("[red]false negatives (missed threats)[/red]", f"[red]{fn}[/red]")
    table.add_row("true positives (caught)", str(tp))
    table.add_row("true negatives (noise suppressed)", str(tn))
    table.add_row("false positives (over-escalated)", str(fp))
    table.add_row("", "")
    if escalated:
        table.add_row("precision", f"{tp/escalated:.2f}")
    if tp + fn:
        table.add_row("recall", f"{tp/(tp+fn):.2f}")
    if tn + fp:
        table.add_row("noise reduction", f"{tn/(tn+fp):.0%}")
    rprint(table)

    rprint(f"\n[bold]verdict distribution:[/bold] {dict(verdicts)}")

    misses = [r for r in rows if r["truth"] == "malicious"
              and r["disposition"] == "auto_closed"]
    if misses:
        rprint("\n[bold red]MISSED THREATS[/bold red]")
        for m in misses:
            rprint(f"  {m['id']} ({m['difficulty']}) — {m['rationale']}")

    out = Path("evals/results.json")
    out.write_text(json.dumps(rows, indent=2) + "\n")
    rprint(f"\n[dim]detail written to {out}[/dim]")


if __name__ == "__main__":
    main(
        sys.argv[1] if len(sys.argv) > 1 else "data/labeled/guardduty_corpus.json",
        sys.argv[2] if len(sys.argv) > 2 else "data/labeled/labels.json",
    )
