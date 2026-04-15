# CryptoGraph Pipeline

CryptoGraph turns Python source code into a graph-backed custom CBOM in six deterministic stages.

## 1. CLI Entry Point

File: `src/cryptograph/main.py`

The `scan` command resolves the run directory, loads the graph backend, finds crypto calls, enriches context, builds the CBOM, writes the optional HTML report, and records a manifest.

## 2. Graph Loading

Files:
- `src/cryptograph/cpg_loader.py`
- `tools/fraunhofer-exporter/src/main/kotlin/io/cryptograph/exporter/Main.kt`
- `src/cryptograph/ast_lite.py`

Fraunhofer CPG is the preferred backend. It emits a normalized graph with function, call, callee, argument, data-flow, and call edges. `ast-lite` is a Python fallback for fast local development.

## 3. Crypto API Matching

File: `src/cryptograph/crypto_matcher_v2.py`

The matcher compares graph call nodes with `config/api_mappings.json` and creates `CryptoFinding` objects. At this point, a finding may still be wrapper-shaped, for example `Cipher` instead of `AES`.

## 4. Context Enrichment

File: `src/cryptograph/context_extractor.py`

The context extractor adds:
- call chain from `CALLS` edges
- argument roles such as key, data, iv, salt, randomness
- literal classification
- local assignment and function-parameter origins
- graph-assisted data-flow using `DFG`, `DATA_FLOW`, and `REACHES`
- source/sink labels from `config/source_sinks.json`

## 5. Semantic CBOM Layers

Files:
- `src/cryptograph/algorithm_normalizer.py`
- `src/cryptograph/asset_classifier.py`
- `src/cryptograph/flow_analyzer.py`
- `src/cryptograph/risk_engine.py`
- `src/cryptograph/rule_engine.py`
- `src/cryptograph/inference_explainer.py`
- `src/cryptograph/cbom_builder_v2.py`

These modules turn raw findings into clean CBOM assets:
- wrapper APIs are normalized into real algorithms and modes
- primary crypto assets are separated from supporting artifacts
- flow fields are kept explicit with `unknown` vs `null`
- risk is calculated from algorithm, mode, key size, source quality, and parameters
- inference fields explain how context and intent were derived

## 6. Output

Each scan writes into a run folder:

```text
output/run-YYYYMMDDTHHMMSSZ-xxxxxxxx/
  result.json
  report.html
  manifest.json
```

The JSON is the main artifact. The HTML report is a human-readable view. The manifest records reproducibility metadata and config hashes.
