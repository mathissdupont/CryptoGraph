# CryptoGraph

CryptoGraph is a graph-based prototype for discovering cryptographic assets from Python source code and generating a custom CryptoGraph CBOM JSON representation.

The MVP is designed to grow beyond toy examples: the Python pipeline works on normalized graph data, while the CPG backend is isolated behind a loader so Fraunhofer AISEC CPG can be used without coupling the matcher to JVM internals.

## What is CryptoGraph?

CryptoGraph analyzes Python source code to:

1. **Detect cryptographic API calls**: Identify usage of encryption, hashing, key generation, and other crypto primitives.
2. **Extract context**: Trace where data comes from (user input, hardcoded keys, random sources) and how it flows to crypto operations.
3. **Generate CBOM**: Produce a cryptographic component bill of materials (CBOM) with structured metadata, risk scores, and evidence.
4. **Scale to large repositories**: Architecture supports incremental scanning, parallel graph generation, and artifact sharding.

### Key Innovation: Variable-Level Dataflow

When Fraunhofer AISEC CPG's Python frontend cannot emit complete interprocedural dataflow edges, CryptoGraph combines:

- **Graph-based tracking**: Follow DFG, DATA_FLOW, and REACHES edges from the normalized graph.
- **Local AST analysis**: Extract function-local assignments and parameter origins.
- **Hybrid evidence**: Report both graph and local sources in the CBOM `flow` section.

Example: `request["token"] → token → encrypt(token)` is traced even when the CPG graph lacks a complete edge chain, by combining graph edges with local assignment origin extraction.

## Goal

- Detect cryptographic API usage in source code.
- Extract usage context from graph relations and call arguments.
- Produce structured CryptoGraph CBOM JSON output with risk scores and evidence.
- Run reproducibly through Docker for future large-codebase scans.
- Support hybrid dataflow extraction when CPG edges are incomplete.

## Pipeline

```text
source directory
  ↓
  → [Fraunhofer CPG exporter (preferred) or ast-lite fallback (lightweight)]
  ↓
  → normalized graph JSON
  ↓
  → crypto matcher (identify API calls via config/api_mappings.json)
  ↓
  → context extractor (enrich with call chain, arguments, variable-level dataflow)
  ↓
  → CryptoGraph CBOM builder (apply risk rules, generate final CBOM)
  ↓
  output/result.json + report.html + manifest.json
```

## Quick Start

### Prerequisites

- **Python 3.11+**
- **Optional: Java 11+** (for Fraunhofer CPG exporter; Docker handles this automatically)
- **Docker & Docker Compose** (recommended for consistent environment)

### Local Development (AST-lite backend, fastest)

```bash
# Setup Python environment
python -m venv .venv
.venv\Scripts\activate              # Windows
source .venv/bin/activate           # macOS/Linux

# Install dependencies
pip install -r requirements.txt
pip install -e .

# Scan samples
cryptograph scan --input samples --output output/result.json --backend ast-lite

# Generate HTML report
cryptograph report --input output/result.json --output output/report.html
```

### Production (Fraunhofer CPG backend, more accurate)

```bash
# Build Docker image with Fraunhofer exporter
docker compose build

# Scan with automatic fallback to ast-lite if exporter fails
docker compose run --rm cryptograph scan --input samples --output output/result.json

# Strict mode: fail if Fraunhofer exporter is unavailable
docker compose run --rm cryptograph scan --input samples --output output/result.json --backend fraunhofer-strict
```

### CPG Inspection (Debugging)

Export the normalized graph for inspection:

```bash
# Local: fast graph export (ast-lite only)
cryptograph graph --input samples --backend ast-lite --output output/cpg.json --dot output/cpg.dot --html output/cpg.html

# Docker: inspect Fraunhofer graph (requires strict mode for guarantees)
docker compose run --rm cryptograph graph --input samples --backend fraunhofer-strict --output output/cpg.json --dot output/cpg.dot --html output/cpg.html
```

This generates:
- `cpg.json`: Full normalized graph (all nodes and edges)
- `cpg.dot`: Graphviz visualization
- `cpg.html`: Standalone interactive viewer

## Output Structure

All CLI commands write artifacts under run directories when paths are under `output/`:

```text
output/run-YYYYMMDDTHHMMSSZ-xxxxxxxx/
  ├── result.json          # CryptoGraph CBOM (all findings)
  ├── report.html          # Human-readable HTML report
  ├── manifest.json        # Metadata: tool version, backend, counts, config hashes
  ├── cpg.json             # (if --graph used) Normalized graph JSON
  ├── cpg.dot              # (if --graph used) Graphviz format
  └── cpg.html             # (if --graph used) Interactive viewer
```

Use `--run-dir output/my-custom-run` to specify a custom directory name if desired.

## Backend Modes

| Mode | Backend | Fallback | Use Case |
|------|---------|----------|----------|
| `fraunhofer` (default) | Fraunhofer AISEC CPG | Yes → ast-lite | Production: accurate CPG, but graceful degradation |
| `fraunhofer-strict` | Fraunhofer AISEC CPG | No | Validation/CI: fail if CPG fails (no silent fallback) |
| `ast-lite` | Python AST (no JVM) | —— | Development: fastest, lightweight, for iteration |

### Fallback Behavior

When `--backend fraunhofer` is used:

1. Attempts to invoke Fraunhofer CPG exporter (subprocess)
2. If exporter is unavailable or crashes → falls back to ast-lite with warning on stderr
3. CBOM result includes `backend` field to track whether data came from CPG or fallback

When `--backend fraunhofer-strict` is used:

- Fails immediately if exporter is unavailable or crashes
- Suitable for CI/CD pipelines and validation workflows
- No silent degradation

## Testing

### Comprehensive Test Suite

CryptoGraph includes 13 sample Python files demonstrating cryptographic usage patterns:

**Core samples** (6):
- `hash_example.py`: SHA, MD5 hashing
- `insecure_aes.py`: AES-ECB (insecure) encryption
- `pbkdf2_example.py`: PBKDF2 key derivation
- `rsa_example.py`: RSA encryption and key generation
- `fernet_example.py`: High-level authenticated encryption
- `auth_flow.py`: Authentication flow with password hashing

**Extended samples** (7, new):
- `hmac_example.py`: HMAC-SHA256 message authentication
- `chacha20_example.py`: ChaCha20 stream cipher
- `scrypt_example.py`: Scrypt key derivation + PBKDF2 fallback
- `ecdsa_example.py`: ECDSA digital signatures
- `gcm_mode_example.py`: AES-GCM authenticated encryption
- `certificate_example.py`: X.509 certificate generation
- `argon2_example.py`: Argon2 modern password hashing

### Run Tests with Fraunhofer Backend

```bash
# Build Docker image (includes Fraunhofer exporter)
docker compose build

# Scan all samples and generate CBOM
docker compose run --rm cryptograph scan \
    --input /app/samples \
    --output /app/output/result.json \
    --backend fraunhofer

# Generate CPG visualization
docker compose run --rm cryptograph graph \
    --input /app/samples \
    --output /app/output/cpg.json \
    --dot /app/output/cpg.dot \
    --html /app/output/cpg.html \
    --backend fraunhofer

# Generate HTML report from CBOM
docker compose run --rm cryptograph report \
    --input /app/output/run-YYYYMMDDTHHMMSSZ-xxxxxxxx/result.json \
    --output /app/output/report.html
```

### Expected Results

**Latest Test Run (April 15, 2026)**:
- **Total Findings**: 39 cryptographic assets
- **Risk Breakdown**: 6 high-risk, 33 info/low-risk
- **Graph Size**: 545 nodes, 493 edges
- **Algorithms Detected**:
  - Symmetric: AES, ChaCha20
  - Asymmetric: RSA, ECC, ECDSA
  - Hashing: SHA-256, SHA-512, MD5 (deprecated)
  - KDF: PBKDF2, Scrypt, Argon2
  - Auth: HMAC, X.509 certificates
  - Random: os.urandom, secrets module

See [TEST-RESULTS.md](TEST-RESULTS.md) for detailed test report and analysis.

## Backend Modes

| Mode | Backend | Fallback | Use Case |
|------|---------|----------|----------|
| `fraunhofer` (default) | Fraunhofer AISEC CPG | Yes → ast-lite | Production: accurate CPG, but graceful degradation |
| `fraunhofer-strict` | Fraunhofer AISEC CPG | No | Validation/CI: fail if CPG fails (no silent fallback) |
| `ast-lite` | Python AST (no JVM) | —— | Development: fastest, lightweight, for iteration |

### Fallback Behavior

When `--backend fraunhofer` is used:

1. Attempts to invoke Fraunhofer CPG exporter (subprocess)
2. If exporter is unavailable or crashes → falls back to ast-lite with warning on stderr
3. CBOM result includes `backend` field to track whether data came from CPG or fallback

When `--backend fraunhofer-strict` is used:

- Fails immediately if exporter is unavailable or crashes
- Suitable for CI/CD pipelines and validation workflows
- No silent degradation

## Documentation

### English Documentation

- [docs/en/architecture.md](docs/en/architecture.md): System design, backends, normalized graph model, variable-level dataflow strategy
- [docs/en/pipeline.md](docs/en/pipeline.md): End-to-end scan pipeline from source code to CBOM
- [docs/en/schema.md](docs/en/schema.md): Current `cryptograph-custom-v2` schema and unknown/null rules
- [docs/en/code-map.md](docs/en/code-map.md): Which Python module owns each responsibility
- [docs/en/notes.md](docs/en/notes.md): Implementation details, CPG exporter behavior, debugging, performance considerations
- [docs/en/scale-notes.md](docs/en/scale-notes.md): Scaling strategy for large repositories, next steps, deployment checklist

### Turkish Documentation

- [docs/tr/architecture.md](docs/tr/architecture.md): Sistem tasarımı, backend'ler, normalize grafik modeli, değişken seviyesi veri akışı stratejisi
- [docs/tr/pipeline.md](docs/tr/pipeline.md): Kaynak koddan CBOM'a giden uctan uca islem hatti
- [docs/tr/schema.md](docs/tr/schema.md): Guncel `cryptograph-custom-v2` semasi ve unknown/null ayrimi
- [docs/tr/code-map.md](docs/tr/code-map.md): Hangi Python modulunun hangi isi yaptigi
- [docs/tr/notes.md](docs/tr/notes.md): Uygulama detayları, CPG ihraçcısı davranışı, hata ayıklama, performans
- [docs/tr/scale-notes.md](docs/tr/scale-notes.md): Büyük depolar için ölçekleme stratejisi, sonraki adımlar, dağıtım kontrol listesi

## Current Scope

### Supported Cryptographic Primitives

- **Symmetric encryption**: AES (ECB, CBC, GCM)
- **Asymmetric encryption**: RSA
- **Hashing**: SHA-1, SHA-256, SHA-512, MD5
- **Key derivation**: PBKDF2
- **Message authentication**: HMAC
- **Password hashing**: bcrypt
- **Symmetric encryption (high-level)**: Fernet
- **Randomness**: `random`, `secrets` modules

### Features

- **Crypto API detection**: Automatic matching against configurable API mappings in `config/api_mappings.json`.
- **Custom CBOM schema**: JSON output with crypto metadata, usage context, data flow evidence, risk scoring.
- **Variable-level dataflow analysis**: Hybrid graph-based + local AST analysis for source-to-sink tracing.
- **Source/sink classification**: Identify argument sources (user input, hardcoded keys, random, etc.) and sink types.
- **Call chain extraction**: Include function ancestry and caller context in findings.
- **Risk scoring**: Confidence values derived from API match, source context, dataflow availability, and rule matches.
- **Per-run artifacts**: Grouped output with manifest, graph inspection tools, and reports.
- **Scalable architecture**: File-by-file processing, normalized graph boundary, per-shard data flow.

### Backends

- **Fraunhofer AISEC CPG** (preferred): Full interprocedural dataflow, require Java 11+, wrapped behind subprocess interface.
- **AST-lite** (fallback): Lightweight Python AST-based backend for development and CI/CD when Fraunhofer unavailable.

## Configuration

### API Mappings (`config/api_mappings.json`)

Maps cryptographic APIs to primitives and operations:

```json
{
  "Crypto.Cipher:AES:new": {
    "primitive": "AES",
    "operation": "encrypt",
    "arguments": [...]
  }
}
```

### Source/Sink Classification (`config/source_sinks.json`)

Defines source categories (user_input, hardcoded, generated_random, key_material) and sink types.

### Risk Rules (`config/rules.json`)

Custom scoring rules applied during CBOM building based on patterns and context.

## Testing

### Unit Tests

```bash
pytest tests/test_pipeline.py -v
```

Uses `--backend ast-lite` for fast local iteration without JVM dependency.

### Full Pipeline Tests (with Fraunhofer)

```bash
docker compose run --rm cryptograph pytest
```

Requires Docker and Java setup.

## Architecture

For detailed architecture, backend isolation strategy, and variable-level dataflow implementation, see:

- **English**: [docs/en/architecture.md](docs/en/architecture.md)
- **Turkish**: [docs/tr/architecture.md](docs/tr/architecture.md)

## Contributing

When adding new features:

1. Update `config/api_mappings.json` for new APIs
2. Extend `config/source_sinks.json` for new source/sink types
3. Update risk rules in `config/rules.json` if needed
4. Add tests in `tests/test_pipeline.py`
5. Update documentation in `docs/en/` and `docs/tr/`

## License

See LICENSE file (if applicable).

## Status

**MVP / Active Development**. The normalized graph model and core pipeline are stable. Variable-level dataflow analysis is production-ready. Scaling infrastructure (sharding, incremental scans) is documented in [docs/en/scale-notes.md](docs/en/scale-notes.md) and ready for implementation.
