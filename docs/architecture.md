# Architecture

CryptoGraph separates graph creation from crypto analysis.

## Backends

The preferred backend is Fraunhofer AISEC CPG. The Python package does not depend on Fraunhofer JVM classes directly. Instead, `cpg_loader` expects an exporter that emits a normalized graph JSON document with call nodes and lightweight properties.

The MVP also includes `ast-lite`, a Python AST fallback backend. It keeps development fast and gives the matcher a stable input shape for local iteration.

`fraunhofer-strict` must be used when validating real CPG behavior. It fails if the JVM exporter fails, so production-like scans cannot silently downgrade to AST data.

## Normalized Graph

The normalized graph uses:

- `nodes`: function, call, callee, argument and nearby flow nodes with file, line, function, arguments and resolved names.
- `edges`: AST function/callee/argument edges plus DFG/EOG edges when Fraunhofer emits them for the source pattern.
- `backend`: provenance for whether results came from Fraunhofer or fallback parsing.

## CPG Inspection

The `cryptograph graph` command exports normalized graph JSON, Graphviz DOT and a standalone HTML viewer. This is a debug surface for understanding the CPG normalization layer, not a product UI.

```bash
docker compose run --rm cryptograph graph --input samples --backend fraunhofer-strict --output output/cpg-fraunhofer.json --dot output/cpg-fraunhofer.dot --html output/cpg-fraunhofer.html
```

The Docker image pins Python Jep to the same major/minor version used by the shaded Fraunhofer exporter dependency and sets `CPG_JEP_LIBRARY` explicitly. This avoids Java Jep/native Jep mismatches when the Python frontend initializes inside the JVM.

## Run Artifacts

CLI commands group generated artifacts under a per-run directory when paths are placed directly under `output/`.

```text
output/run-YYYYMMDDTHHMMSSZ-xxxxxxxx/
```

This keeps large scans reviewable and avoids mixing CBOM, graph JSON, DOT and report files from unrelated runs.

Each scan run writes `manifest.json` with:

- artifact paths
- graph node and edge counts
- finding counts by risk, algorithm and primitive
- config file SHA-256 hashes

## CBOM Evidence Model

Each cryptographic asset includes a stable `asset_id` plus the top-level sections `crypto_metadata`, `usage`, `context`, `flow`, `control`, `risk` and `evidence`. `primitive` describes the cryptographic category, while `usage.operation` describes the action, such as encryption, digest, authentication or key generation.

Evidence carries the matched API, resolved Fraunhofer callee, arguments, graph edge kinds and local graph neighbors such as function, callee and argument nodes. `node_ref` is stable and CBOM-facing; `raw_node_id` is preserved only for debugging.

Risk confidence is a float from `0.0` to `1.0`, derived from API mapping, source location, graph context, call-chain availability, source/sink classification, dataflow evidence, risk-rule matches and Fraunhofer callee availability.

Source/sink classification is configured in `config/source_sinks.json`. The context layer classifies arguments and function scope terms into source categories such as `user_input`, `key_material` and `generated_random`, then connects them to crypto sinks in the CBOM `flow.source_to_sink` field.

Variable-level flow is graph-assisted. The context layer follows normalized `DFG`, `DATA_FLOW` and `REACHES` edges when present, and also records local assignment/function-parameter origins for call arguments. Missing-but-applicable values are emitted as `unknown`; truly not-applicable values are emitted as `null`.

Call graph edges use the normalized `CALLS` edge. When Fraunhofer `invokes` data is unavailable, the exporter adds a local synthetic call edge for same-module function calls so CBOM assets can include a useful call chain.

## Analysis Layers

- `crypto_matcher` maps call nodes to configured cryptographic APIs.
- `context_extractor` adds call-chain, argument-level signals, literal tracking, source/sink classification and graph-assisted dataflow.
- `cbom_builder` converts enriched findings into the CryptoGraph custom CBOM JSON schema.
