# Reproducing the lightweight analysis

Use Python 3.12+ in an isolated environment. From the repository root:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
python scripts/reproduce.py
```

The script parses committed Python samples using `ast-lite`. It does not execute
samples, clone repositories, call an LLM or require Java. The output directory
must be new or empty to prevent stale artifacts. Preserve previous runs by using
`python scripts/reproduce.py --out-dir output/reproduction-2`.

## Artifacts

| File | Purpose |
| --- | --- |
| `cbom.json` | Primary assets, supporting artifacts, context and assessment. |
| `report.html` | Findings from that single CBOM. |
| `manifest.json` | Backend, graph counts, findings and configuration fingerprints. |
| `graph.json`, `graph.dot`, `graph.html` | Normalized graph for inspection. |
| `reproduction.json` | Commit, dirty state, environment, input hashes, commands and observed totals. |

Check backend identity and inspect evidence before interpreting risk or intent.
Timestamps, paths and path-derived identifiers can differ between machines. This
workflow records provenance; it does not promise byte-identical output or supply
accuracy results. A dirty run requires its source diff for full reproduction.

For JSONL data and baseline labels, use the `scan-repo` and labeling commands in
the README. The current HTML report consumes a single CBOM, not the merged
repository wrapper. Generated outputs are ignored by Git; preserve them
separately when sharing results.

## Fraunhofer and Docker

The bundled exporter under `tools/fraunhofer-exporter` declares JDK 17, Kotlin
2.0.21 and Fraunhofer CPG 9.0.2 dependencies. With a compatible Gradle installation,
the intended build is:

```bash
cd tools/fraunhofer-exporter
gradle --no-daemon shadowJar
```

Set `CRYPTOGRAPH_FRAUNHOFER_EXPORTER` to the absolute path of
`build/libs/fraunhofer-exporter.jar`, return to the root and select
`--backend fraunhofer-strict`. Set the variable with `$env:NAME = 'value'` in
PowerShell or `export NAME=value` in Bash.

The existing Docker path builds both exporter and Python runtime:

```bash
docker compose build cryptograph
docker compose run --rm cryptograph scan --input samples --output /app/output/cpg-cbom.json --backend fraunhofer-strict
```

These are integration paths, not validation results. Passing lightweight tests
does not establish that Gradle dependencies resolve, Docker builds, every
frontend parses or interprocedural edges are correct. Preserve exporter logs and
inspect graph direction and actual/formal bindings on hand-checked inputs.
The [validation snapshot](VALIDATION.md) records a successful exporter build and
a controlled Java smoke test; it does not establish other frontend coverage.
The older `scripts/build_fraunhofer_exporter.sh` helper clones upstream and
searches for a JAR; it is not a reproducible build for the bundled exporter.

## Real exporter regression tests

After building, set `CRYPTOGRAPH_TEST_EXPORTER` to the absolute JAR path and run:

```bash
python -m pytest tests/test_exporter_integration.py -q
```

These tests parse a controlled Java cipher example and reject unsupported input.
They skip when the variable is absent. Install `.[dev,ui]` and run
`python -m pytest tests/test_viewer.py -q` for the local interface regression.
