# CryptoGraph

**Explainable cryptographic usage analysis from source code.**

CryptoGraph is a research prototype investigating how to identify cryptographic
operations, recover their usage context, and represent the available evidence in
a structured Cryptographic Bill of Materials (CBOM).

> How can cryptographic usage in source code be identified, contextualized, and
> represented in an explainable, CBOM-compatible format beyond simple API matching?

The implementation combines configurable API matching, normalized program graphs,
local source analysis, and rule-based assessment. It records call context,
inferred material sources, risk derivations, and unresolved fields. Accuracy,
intent inference, and standards interoperability remain under evaluation.

## Try it locally

Requires **Python 3.12+** and Git. The lightweight demo needs no JVM, API key, or
installed cryptography libraries: sample programs are parsed, never executed.

```bash
git clone https://github.com/mathissdupont/CryptoGraph.git
cd CryptoGraph
python -m venv .venv
```

Activate with `source .venv/bin/activate` on Linux/macOS, or
`.\.venv\Scripts\Activate.ps1` in Windows PowerShell. Then:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
python scripts/reproduce.py
```

Open `output/reproduction/report.html` for findings and
`output/reproduction/graph.html` for the graph. The directory also contains CBOM
JSON, a manifest with configuration hashes, and a reproduction record. This is a
functional demonstration, not an accuracy benchmark. Use a new output directory
for subsequent runs: `python scripts/reproduce.py --out-dir output/reproduction-2`.

## What is implemented

| Layer | Current behavior |
| --- | --- |
| Discovery | Match graph call nodes against configurable cryptographic API mappings. |
| Normalization | Resolve recognizable algorithms, modes and parameters; separate primary assets from supporting artifacts. |
| Context | Extract call chains, argument roles, local origins and incoming graph data-flow evidence where available. |
| Assessment | Heuristic risk levels, rule matches, confidence values and derivations. Confidence is not statistically calibrated. |
| Export | Custom CBOM JSON, graph JSON/DOT/HTML, findings report, repository JSONL dataset. |
| Labeling | Deterministic simulated labels and prompt preparation. External LLM providers are not implemented. |
| Interoperability | Experimental CycloneDX-shaped hybrid export; schema conformance is not established. |

## Backend and language scope

Mapping files and language detection do not establish parser coverage or analysis
accuracy. Lightweight paths have regression coverage. The Fraunhofer exporter
needs separate end-to-end evaluation for each language and environment.

| Source | Lightweight path (`--backend ast-lite`) | Fraunhofer path |
| --- | --- | --- |
| Python | Python AST, call structure and local origin heuristics. | Exporter integration present; separate JVM setup required. |
| Ruby | `ruby-lite`, source-pattern scanner. | Non-strict mode selects Ruby lite directly; strict mode requires the exporter. |
| C/C++ | `c-cpp-lite`, selected OpenSSL/TLS source patterns. | Exporter integration present; non-strict mode can use lite when the exporter returns no calls. |
| Java, Kotlin, JavaScript, TypeScript, Go, C# | No general lightweight parser. | Configurations exist; usable graphs and frontend availability must be verified. |

`fraunhofer` is the CLI default and permits fallback. `fraunhofer-strict` requires
the exporter and rejects the empty C/C++ call-graph fallback. Neither mode proves
that a returned graph contains complete data flow. Inspect the actual backend and
evidence. Zero findings does not establish absence of cryptographic misuse.

## CLI examples

```bash
# Scan controlled Python examples with a manifest and report.
cryptograph scan --input samples --backend ast-lite --output output/demo/cbom.json --report output/demo/report.html --run-dir output/demo

# Export the normalized graph.
cryptograph graph --input samples --backend ast-lite --output output/demo/graph.json --html output/demo/graph.html --run-dir output/demo

# Group a local repository by language and export a JSONL dataset.
# Choose a backend that can parse the repository's languages.
cryptograph scan-repo --repo ./samples --backend ast-lite --out-dir output/repo-demo --max-workers 1

# Baseline labels: no external model is called.
python scripts/llm-label-cbom.py --input output/repo-demo/dataset.jsonl --output output/repo-demo/baseline.jsonl --llm-api simulate
```

`scan-repo` preserves partial results and returns exit code **3** when scan jobs
fail. Backend loading errors handled by `scan` / `graph` return **2**. Other
uncaught errors can also produce nonzero exits. Inspect both status and artifacts.

`scan` uses Python mappings by default; supply `--mappings` and `--rules` for other
languages. `scan-repo` selects configurations by language. Kotlin currently
shares Java configuration, and TypeScript shares JavaScript configuration.

Optional local interface:

```bash
python -m pip install -e ".[ui]"
streamlit run viewer/scanner.py --server.port 8502
```

Open `http://localhost:8502`. Interface labels are deterministic baselines.
For exporter/Docker setup, see [reproducibility](docs/REPRODUCIBILITY.md).

## Research direction

The planned comparison uses the same annotated inputs for:

1. API and parameter extraction alone.
2. Graph-enriched contextual analysis.
3. Evidence-grounded intent inference, potentially using an LLM.

These are experimental conditions to implement and evaluate. The repository has
no published ground-truth corpus, precision/recall results, calibrated intent
scores, or demonstrated improvement over an API-only baseline.

See [research scope and evaluation](docs/RESEARCH.md) for hypotheses, annotations,
metrics and threats to validity, and the [roadmap](docs/ROADMAP.md) for milestones.

## Repository guide

```text
src/cryptograph/           Analysis pipeline and CLI
config/                   Bundled mappings, rules and source/sink definitions
tools/fraunhofer-exporter/ Kotlin/JVM graph exporter
samples/                  Controlled examples; some intentionally insecure
tests/                    Regression tests, including legacy compatibility
scripts/                  Reproduction and auxiliary workflows
viewer/                   Streamlit interfaces
docs/                     Current guides and historical implementation notes
output/                   Local generated artifacts (ignored)
results/                  Historical/local scan outputs (ignored)
```

- [Documentation index](docs/README.md)
- [Architecture and evidence boundaries](docs/en/architecture.md)
- [Custom output schema](docs/en/schema.md)
- [Validation snapshot and remaining checks](docs/VALIDATION.md)
- [Contributing and checks](CONTRIBUTING.md)

Historical notes may contain superseded claims and commands; the guides linked
above describe current entry points and limitations. Old scan outputs are not a
benchmark dataset. No project license has been selected in this checkout.
