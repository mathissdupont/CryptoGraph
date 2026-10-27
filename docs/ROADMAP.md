# Research roadmap

The goal is to measure whether structured program evidence improves
cryptographic context over API/parameter extraction alone.

## 1. Reproducible baseline

Maintain the full lightweight suite and an installed-wheel smoke scan. Record
backend identity, failures, input revision and configuration hashes. Validate the
bundled exporter on hand-checked inputs and preserve graphs/logs. Exporter
validation beyond the controlled Java smoke case remains outstanding; see
[the validation snapshot](VALIDATION.md). The lightweight demo is documented in
[REPRODUCIBILITY.md](REPRODUCIBILITY.md).

## 2. Annotated corpus

Define operation, material-origin and context labels with unresolved intent as a
valid answer. Include negative examples, aliases, wrappers, reassignment and
cross-function flow. Record provenance, disagreements and permitted reuse.
Split by project rather than repeated code fragments.

## 3. Controlled comparison

Implement explicit API-only and graph-enriched conditions. Use identical inputs
and account for failed/unparsed programs. Report detection separately from
context accuracy, abstention, unsupported claims and fallback/coverage rates.

## 4. Evidence-grounded intent

Define a bounded evidence record and intent taxonomy. Add actual model
integration with reproducible settings and provenance. Compare against
baselines on held-out inputs; evaluate unsupported claims and calibration.

## 5. Interoperability and release

Select and validate the intended CycloneDX schema, using supported extension
mechanisms. Expand languages with frontend checks and labeled examples. Select
a project license and document third-party artifact provenance before release.

These are pending research milestones, not published results. See
[RESEARCH.md](RESEARCH.md) for hypotheses and the evaluation protocol.
