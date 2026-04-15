# Code Map

## Main Runtime

- `main.py`: CLI orchestration for scan, graph export, and report generation.
- `cpg_loader.py`: backend selection and Fraunhofer/AST-lite loading.
- `models.py`: shared Pydantic models for graph nodes, edges, graphs, and findings.
- `utils.py`: path, JSON, and run-directory helpers.

## Graph Generation

- `ast_lite.py`: Python AST fallback graph builder.
- `tools/fraunhofer-exporter/.../Main.kt`: Fraunhofer CPG exporter used inside Docker.
- `cpg_visualizer.py`: JSON, DOT, and HTML graph visualization.

## Detection and Enrichment

- `crypto_matcher_v2.py`: maps call nodes to crypto APIs.
- `context_extractor.py`: adds call chain, argument roles, literal tracking, source/sink labels, and data-flow evidence.

## CBOM Semantics

- `algorithm_normalizer.py`: resolves wrappers such as `Cipher(...)` into AES, ChaCha20, modes, padding, and key sizes.
- `asset_classifier.py`: classifies findings as `primary_asset`, `supporting_artifact`, or `ignore`.
- `flow_analyzer.py`: creates stable flow fields for key/data/iv/salt/randomness sources.
- `risk_engine.py`: computes risk level, confidence, tags, and derivation summary.
- `rule_engine.py`: applies conditional rules from `config/rules_v2.json`.
- `inference_explainer.py`: explains usage context, intent, data flow, and derivation path.
- `cbom_builder_v2.py`: assembles the final JSON.

## Reports and Reproducibility

- `report_builder.py`: creates the standalone HTML report from CBOM JSON.
- `manifest.py`: writes run metadata and config hashes.
