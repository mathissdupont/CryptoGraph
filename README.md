# CryptoGraph

CryptoGraph is a graph-based prototype for discovering cryptographic assets from Python source code and generating a custom CryptoGraph CBOM JSON representation.

The MVP is designed to grow beyond toy examples: the Python pipeline works on normalized graph data, while the CPG backend is isolated behind a loader so Fraunhofer AISEC CPG can be used without coupling the matcher to JVM internals.

## Goal

- Detect cryptographic API usage in source code.
- Extract usage context from graph relations and call arguments.
- Produce structured CryptoGraph CBOM JSON output.
- Run reproducibly through Docker for future large-codebase scans.

## Pipeline

```text
source directory
  -> Fraunhofer CPG exporter or ast-lite fallback
  -> normalized graph JSON
  -> crypto matcher
  -> context extractor
  -> CryptoGraph CBOM builder
  -> output/result.json
```

## Quick Start

Local:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
cryptograph scan --input samples --output output/result.json --backend ast-lite
cryptograph report --input output/result.json --output output/report.html
```

Docker:

```bash
docker compose build
docker compose run --rm cryptograph scan --input samples --output output/result.json --report output/report.html
```

The CLI defaults to `--backend fraunhofer`. This mode attempts the JVM Fraunhofer exporter first and falls back to `ast-lite` with a warning if the exporter is unavailable or fails.

When an output path is written directly under `output/`, CryptoGraph creates a run folder and places all artifacts there:

```text
output/run-YYYYMMDDTHHMMSSZ-xxxxxxxx/result.json
output/run-YYYYMMDDTHHMMSSZ-xxxxxxxx/report.html
output/run-YYYYMMDDTHHMMSSZ-xxxxxxxx/manifest.json
```

Use `--run-dir output/my-run` when you want a deterministic artifact directory.

Use strict CPG mode when you do not want fallback output:

```bash
docker compose run --rm cryptograph scan --input samples --output output/result.json --backend fraunhofer-strict
```

## CPG Inspection

CryptoGraph can export the normalized graph as JSON, Graphviz DOT and a standalone HTML viewer:

```bash
docker compose run --rm cryptograph graph --input samples --backend fraunhofer-strict --output output/cpg.json --dot output/cpg.dot --html output/cpg.html
```

This creates a run directory such as:

```text
output/run-YYYYMMDDTHHMMSSZ-xxxxxxxx/cpg.json
output/run-YYYYMMDDTHHMMSSZ-xxxxxxxx/cpg.dot
output/run-YYYYMMDDTHHMMSSZ-xxxxxxxx/cpg.html
```

For local development without the JVM exporter:

```bash
cryptograph graph --input samples --backend ast-lite --output output/cpg.json --dot output/cpg.dot --html output/cpg.html
```

`fraunhofer-strict` is the mode to use when validating real CPG behavior. If Fraunhofer or Jep crashes, the command fails instead of silently producing AST fallback data.

## Current Scope

- Python source samples.
- AES, RSA, SHA, MD5, PBKDF2, HMAC, Fernet, random and secrets APIs.
- Custom CryptoGraph CBOM JSON shaped around crypto metadata, code context, flow, control, inference and evidence.
- Per-asset graph evidence with AST function/callee/argument edges and confidence reasons.
- Source/sink classification and call-chain evidence for crypto flows.
- Per-run manifest with artifact paths, graph counts, finding counts and config hashes.
- Batch-friendly local scanning, with scale notes in `docs/scale-notes.md`.
