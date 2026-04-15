# Implementation Notes

## Fraunhofer CPG Python Frontend

- The Python frontend requires JVM-side setup and the `jep` library (wrapped in Docker).
- Docker is the **preferred execution path** for consistent Java/Python compatibility.
- The Python package does not depend on Fraunhofer JVM classes directly; communication happens via subprocess JSON exchange.

## CPG Exporter Behavior

The current implementation attempts real Fraunhofer `TranslationManager` traversal first:

1. Subprocess spawns `java -jar exporter.jar --input ... --output ...`
2. Exporter writes normalized JSON to output file
3. Python loader reads and validates JSON as `NormalizedGraph`

In current Docker images, the Java/Python boundary can cause JEP initialization failures. The Python CLI isolates this crash in a subprocess and falls back to `ast-lite` automatically when `--backend fraunhofer` is used (without strict mode).

## Dataflow Extraction Strategy

Fraunhofer CPG's Python frontend does not guarantee full interprocedural dataflow for every source-to-sink pattern encountered in real code. Therefore:

1. **Graph edges first**: Follow DFG, DATA_FLOW, REACHES edges when the exporter emits them.
2. **Local analysis fallback**: Extract assignment origins and function parameter origins via AST inspection of the source function.
3. **Combined evidence**: Report both graph-based and local-analysis sources in `sources_reaching_sink`.

This hybrid approach ensures we capture dataflow evidence even when Fraunhofer's interprocedural analysis is incomplete.

## CBOM Compliance

Full compliance with cryptographic component bill of materials (CBOM) standards is intentionally deferred until the detection model stabilizes. Current version uses a **CryptoGraph custom schema** aligned with CBOM principles:

- Stable `asset_id` for each finding
- Top-level sections: `crypto_metadata`, `usage`, `context`, `flow`, `control`, `risk`, `evidence`
- `primitive` (AES, RSA, MD5, etc.) and `operation` (encrypt, digest, sign, etc.)
- Risk confidence derived from multiple signals (API match, source context, dataflow, rule matches)

## Graph Normalization Pipeline

```
Fraunhofer CPG → Exporter JSON → NormalizedGraph
AST → ast-lite builder → NormalizedGraph
```

Both paths produce the same JSON structure, allowing downstream code to be backend-agnostic. The `backend` field tracks provenance at node level.

## Debugging

Enable verbose output to see backend selection and exporter status:

```bash
export CRYPTOGRAPH_DEBUG=1
cryptograph scan --input samples --output result.json
```

Check `stderr` output for fallback messages. For full access to CPG data:

```bash
cryptograph graph --input samples --output cpg.json --html cpg.html
```

## Performance Considerations

- **Graph generation**: Fraunhofer exporter time is dominated by Java startup (~1–2 seconds) and source parsing (scales with codebase size).
- **Matching**: Crypto matcher is O(n) in nodes and rule count; typically <100ms for small to medium codebases.
- **Dataflow**: BFS with MAX_DATAFLOW_DEPTH=24 limit prevents exponential blowup.
- **Memory**: Full graph is kept in memory; for very large codebases, consider implementing shard-based graph partitioning (see scale-notes.md).

## Testing

Local tests use `--backend ast-lite` for fast iteration:

```bash
pytest tests/test_pipeline.py -v
```

Full pipeline tests with Fraunhofer require Docker and Java setup:

```bash
docker compose run --rm cryptograph pytest
```
