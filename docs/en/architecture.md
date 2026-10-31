# Architecture and evidence boundaries

The CLI uses the v2 matcher and builder. Earlier `crypto_matcher.py` and
`cbom_builder.py` remain for compatibility and regression tests.

```text
Source
 -> cpg_loader: Fraunhofer subprocess or lightweight backend
 -> NormalizedGraph: nodes, edges, backend identity
 -> crypto_matcher_v2: API matching and initial signals
 -> context_extractor: call relations, local origins, incoming flow
 -> cbom_builder_v2: normalization, classification, risk, explanations
 -> custom CBOM JSON -> HTML report / experimental CycloneDX hybrid

scan-repo: detect roots -> stage language inputs -> scan jobs
 -> merged-cboms.json + failure summary -> dataset.jsonl
```

## Backends

The Fraunhofer exporter runs in a separate JVM and communicates through JSON.
Pydantic validates graph shape, not semantic completeness or edge correctness.
Python AST-lite extracts syntax and local propagation information. Ruby and
C/C++ lite scan selected source patterns. A common schema does not imply equivalent
analysis. See the [backend matrix](../../README.md#backend-and-language-scope).

`fraunhofer` permits fallback and records actual backend identity.
`fraunhofer-strict` requires the exporter even for Ruby and rejects the empty
C/C++ call-graph fallback. This does not establish graph completeness or coverage.

## Context and uncertainty

`context_extractor.py` follows incoming DFG/DATA_FLOW/REACHES edges toward a sink.
Unrelated graph data flow is not evidence that a particular sink was traced.
Local assignment and parameter-origin heuristics supplement graph information.
Call ancestry does not prove value propagation through actual/formal bindings.

`algorithm_normalizer.py`, `asset_classifier.py`, `flow_analyzer.py`,
`risk_engine.py`, `rule_engine.py` and `inference_explainer.py` construct the
semantic record. Outputs include heuristics. Unknown algorithms require review;
confidence is not a calibrated probability. Explanations describe derivations
that still need source inspection.

## Configuration, artifacts and failures

`config/` installs as `cryptograph.config`, including mappings, source/sink
definitions and rules. `api_mappings.py` normalizes flat and per-language formats.
`scan` accepts explicit configuration paths; `scan-repo` selects language families
and runs staged jobs in a thread pool. Failed jobs remain visible in merged
output and cause CLI exit code 3. Job success is not a parsing coverage score.

An explicit `--run-dir` groups artifacts with a manifest and configuration hashes.
The [reproduction workflow](../REPRODUCIBILITY.md) additionally records source
revision, input hashes, environment and dirty state.

`llm_labeling.py` supplies deterministic baseline labels. External providers are
rejected as unimplemented. The CycloneDX converter needs schema validation work.
See [research scope](../RESEARCH.md) and the [code map](code-map.md).
