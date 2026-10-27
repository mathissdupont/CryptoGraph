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
[eight-case feasibility pilot](../research/python-key-origin/README.md).
The lightweight demo is documented in
[REPRODUCIBILITY.md](REPRODUCIBILITY.md).

## 2. Annotated corpus

Define immediate/ultimate key origins, source sets, may/must modality and
unresolved reasons. Include negative examples, aliases, wrappers, reassignment and
cross-function flow. Record provenance, disagreements and permitted reuse.
Split by project rather than repeated code fragments.

## 3. Controlled comparison

A bounded development comparison now records AST/CPG context with both policies;
its new policy consumes source syntax and CALLS witnesses. Establish a common
candidate population, fuller context ablations and a direct-call reference. Use
identical inputs and account for failed/unparsed
programs. Report detection separately from
context accuracy, abstention, unsupported claims and fallback/coverage rates.

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
