# Research roadmap

The first study is Python-only and measures key-origin claim fidelity,
evidence validity and coverage. See [the protocol](RESEARCH.md) and
[literature screening](research/LITERATURE-2026-10-27.md).

## 1. Reproducible baseline

Maintain the full lightweight suite and an installed-wheel smoke scan. Record
backend identity, failures, input revision and configuration hashes. Validate the
bundled exporter on hand-checked inputs and preserve graphs/logs. General semantic
validation remains outstanding. The Java smoke check is recorded in
[the validation snapshot](VALIDATION.md), and the real Python path now runs the
[27-case designed matrix](../research/python-key-origin/README.md) and
[expanded development source study](../research/python-key-origin/expanded-2026-10-30/README.md).
The lightweight demo is documented in
[REPRODUCIBILITY.md](REPRODUCIBILITY.md).

## 2. Annotated corpus

Define immediate/ultimate key origins, source sets, may/must modality and
unresolved reasons. Include negative examples, aliases, wrappers, reassignment and
cross-function flow. Record provenance, disagreements and permitted reuse.
Split by project rather than repeated code fragments.

Pinned populations, source-only forms and human-review auditing are implemented.
The current split has 19 development and 33 reserved nominal candidates. Their
eligibility and origin labels still need actual independent review; the reserved
count is not a statistical power calculation.

## 3. Controlled comparison

A bounded development comparison now records AST/CPG context with both policies;
its new policy consumes source syntax and CALLS witnesses. Establish a common
candidate population and fuller context ablations. A restricted direct-expression
reference and a review-gated always-abstain reference are implemented. Use
identical inputs and account for failed/unparsed
programs. Report detection separately from
context accuracy, abstention, unsupported claims and fallback/coverage rates.

The [method integrity audit](research/METHOD-AUDIT-2026-10-30.md) records later
source-semantics and failure-isolation checks. The
[v0.2 coverage fixes](research/COVERAGE-FIXES-2026-10-30.md) recover one complete
origin and two missed API bindings at 19 development sites under explicit model
assumptions. Eighteen origins remain unresolved; improve and source-review the
method before a held-out run.

## 4. Held-out evidence-policy evaluation

Define immediate versus ultimate origins, possible versus definite sources and
unresolved reasons. Compare AST/CPG context with existing versus constrained
policies on independently reviewed held-out inputs. Keep semantic error and
evidence validity distinct, with coverage reported for both. Application intent
and actual LLM experiments are deferred to a later study.

## 5. Interoperability and release

Select and validate the intended CycloneDX schema, using supported extension
mechanisms. Expand languages with frontend checks and labeled examples. Select
a project license and document third-party artifact provenance before release.

These are pending research milestones, not published results. See
[RESEARCH.md](RESEARCH.md) for hypotheses and the evaluation protocol.
