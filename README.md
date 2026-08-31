# Alert Triage Agent

An LLM-assisted first-pass triage system for AWS GuardDuty findings. It
enriches each alert with environmental context, asks a model to assess it,
and applies a deterministic policy gate that decides whether a human needs
to look at it.

Built to answer a narrower question than "can an LLM triage alerts" — which
is obviously yes — and instead: **can it do so safely, and how would you
know?**

---

## Result

Evaluated against a 40-alert labeled corpus (20 malicious, 20 benign, 14
marked as deliberately hard):

| | Baseline prompt | Tuned prompt |
|---|---|---|
| Recall (threats caught) | 0.95 | **1.00** |
| False negatives | 1 | **0** |
| Precision | 0.54 | 0.56 |
| Noise reduction | 20% | 20% |
| Verdict distribution | 34/40 `suspicious` | 28 `suspicious`, 8 `benign`, 4 `malicious` |

The headline is the false negative going to zero. Noise reduction did not
improve, and the section on limitations explains why — the ceiling turned
out to be evidence quality, not prompting.

---

## The problem

A mid-sized AWS estate produces hundreds of GuardDuty findings a week. Most
are noise. An analyst still has to open each one.

The failure mode this creates is not wasted time. It is that when everything
looks like noise, alerts start getting closed without being read, and the
real incident gets closed alongside them.

Source-assigned severity does not help much, because it is computed without
environmental context. Two findings of the same type and severity can be a
routine backup job and an active breach:

- `Policy:IAMUser/RootCredentialUsage` at 1pm from the corporate range, with
  MFA, during an annual billing change — routine.
- `Policy:IAMUser/RootCredentialUsage` at 3am from an unrecognised external
  address — full account compromise.

Identical finding type. Identical severity. Opposite dispositions. The
difference is entirely in context the alert does not carry.

---

## Architecture

```
GuardDuty findings (JSON)
          |
   [1] INGESTION          source-specific JSON -> uniform Alert model
          |
   [2] ENRICHMENT         deterministic lookups: identity, network,
          |               behavioural baseline. No model involvement.
          |
   [3] TRIAGE AGENT       Bedrock (Claude Haiku 4.5), schema-constrained
          |               output: verdict + confidence + rationale
          |
   [4] DECISION GATE      plain Python policy. Decides auto-close vs
          |               escalate. Can override the model, never the reverse.
          |
   [5] EVALUATION         scored against ground-truth labels
```

### Design decisions

**Enrichment is deterministic; only judgment is probabilistic.** The model
never gathers facts. Facts come from API calls and lookups — auditable,
repeatable, cheap. The model only reasons over evidence it is handed. When a
verdict is wrong, this makes it possible to tell whether the evidence was bad
or the reasoning was.

**The agent recommends; the gate decides.** Model output is a recommendation
with a confidence score. Separate, non-AI code decides what happens to it.
Certain finding types — root credential usage, instance credential
exfiltration, CloudTrail tampering, anything in the privilege-escalation or
exfiltration families — can never be auto-closed regardless of what the model
concludes. That rule lives in code, not in the prompt, because prompts can be
argued with and code cannot.

**Every failure path escalates.** Bedrock timeout, malformed JSON, schema
validation failure, incomplete enrichment — all produce
`INSUFFICIENT_DATA` at confidence 0.0, which the gate escalates. The system
degrades toward more human review, never less. This was verified accidentally
early on when Bedrock returned errors for a whole run: every alert escalated,
nothing was closed.

**False negatives are weighted above false positives.** These costs are not
symmetric. An over-escalation costs an analyst ten minutes. An auto-closed
intrusion costs a breach. Raw accuracy is therefore the wrong headline metric,
and the gate is deliberately biased toward escalation.

---

## Findings

### Hedging is the default failure mode

The first prompt produced `suspicious` on 34 of 40 alerts. Confidence varied;
the verdict did not. This is worse than useless for triage — an analyst still
reads everything, and now each alert comes with a paragraph of model prose
attached.

The rationales were not wrong. On a noisy recon alert the model correctly
cited the 2% historical true-positive rate, the read-only service account,
and the established principal — and then declined to call it benign anyway.
It treated "some risk signals exist" as sufficient to escalate, which is
always true of anything GuardDuty bothered to alert on.

The fix was to make the cost of hedging explicit in the prompt: declining to
say benign means a human reads the alert. Stating that consequence moved the
distribution.

### Base-rate reasoning can swamp a categorical indicator

The single false negative in the baseline run is the most interesting result
in the project.

`corpus-0003`: interactive developer credentials calling `ListBuckets` from a
**Tor exit node** at 3am. The agent auto-closed it, reasoning that the
principal was 420 days old with read-only permissions, and that the alert type
had fired 47 times in 90 days with a 2% true-positive rate.

Every one of those facts is correct. The error is in the aggregation. Tor
access by interactive user credentials is not a probabilistic signal to be
averaged against a base rate — it is close to disqualifying on its own. There
is no legitimate reason for it.

The fix introduced a class of **dominant indicators** to the prompt: signals
that should not be outweighed by base rate or account age when present on an
authenticated principal. Tor and other anonymising networks, instance role
credentials used outside AWS, root usage from external addresses, disabling
audit logging, making snapshots or sensitive buckets public.

The prompt also draws the distinction the model had missed: a low
true-positive rate *is* strong evidence when the activity is unauthenticated
and untargeted (port scanning, brute-force noise), and weak evidence when the
activity is authenticated and a dominant indicator is present.

That alert now returns `malicious`. Recall went to 1.00.

### The ceiling is evidence, not prompting

After tuning, three alerts sat at confidence 0.78 against an 0.80 threshold —
two points from being auto-closed. Lowering the threshold to 0.75 would have
raised noise reduction from 20% to 35%.

One of those three was `corpus-0022`: a sustained, targeted brute force
against a bastion host that ended in a successful authentication. A true
positive.

The model assigned all three the same verdict at the same confidence. It
could not tell them apart — because the enrichment layer does not supply what
would distinguish them: whether authentication succeeded, and whether attempts
came from a single source over a sustained window versus scattered scanning.

The threshold was left at 0.80. Buying 15 points of noise reduction by
auto-closing a genuine bastion compromise is not a trade worth making, and
the correct fix is not a threshold at all — it is more evidence.

---

## The corpus

`data/labeled/guardduty_corpus.json` — 40 findings
`data/labeled/labels.json` — ground truth with reasoning per case

**The data is synthetic.** Structure and finding-type strings match real
GuardDuty output; all values are fabricated. IP addresses come from RFC 5737
documentation ranges and RFC 1918 private space, so none of them route
anywhere. The account ID is a placeholder.

Constructed deliberately:

- **50/50 malicious to benign.** Not realistic — real ratios are far more
  skewed — but it keeps both error types measurable at this sample size.
- **35% marked `hard`.** A corpus of obvious cases produces high accuracy that
  means nothing.
- **Confusion pairs.** Nearly every malicious case has a benign twin sharing
  its finding type. Root usage at 1pm versus 3am. C2 domain lookups from a
  production host versus from the security team's malware sandbox. Mining
  pool traffic from prod versus from a blockchain research box. Finding type
  alone cannot separate them; only context can.
- **Attack chains.** Three narratives thread across multiple alerts —
  `dev-marcus` (Tor recon, then creating an admin user), `temp-contractor`
  (escalation, snapshot exfiltration, CloudTrail disabled, trust-policy
  enumeration), and `finance-admin` (console compromise, public bucket, mass
  deletion, new admin identity). Individually the alerts look moderate.
  Together they are a breach.
- **Labels carry reasoning**, so a disagreement between agent and label can
  be attributed to whichever is actually wrong.

---

## Limitations

- **Synthetic alerts.** Live GuardDuty was unavailable on the AWS account
  used. The corpus is hand-built.
- **Mocked enrichment.** `MockEnricher` returns deterministic fabricated
  context behind an `Enricher` protocol. An AWS-backed implementation would
  drop in without changes elsewhere.
- **No cross-alert correlation.** Each alert is triaged in isolation. The
  attack chains in the corpus are invisible to the agent — it sees the third
  step of a breach with no knowledge of the first two. This is the largest
  gap and the most obvious next feature.
- **One model tested.** Claude Haiku 4.5, chosen for cost at volume. Whether
  a larger model changes the precision/recall balance is unmeasured.
- **Small sample.** 40 alerts. Differences of a few points are not
  meaningful.
- **Behavioural baselines are invented**, not derived from real historical
  alert data — which is precisely the evidence the analysis above concludes
  is the binding constraint.

---

## Running it

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install boto3 pydantic python-dotenv rich

aws configure          # needs Bedrock access in us-east-1

python src/ingest/from_file.py data/labeled/guardduty_corpus.json
python src/enrich/run.py
python src/triage/run.py
python evals/run_eval.py
```

The evaluation makes one Bedrock call per alert.

## Layout

```
src/
  models.py          Alert, EnrichedAlert, TriageResult (Pydantic)
  ingest/            GuardDuty normalisation, file loader
  enrich/            Enricher protocol, mock implementation
  triage/            prompt construction, Bedrock client
  gate/              decision policy
data/labeled/        corpus and ground-truth labels
evals/               evaluation harness and saved results
```
