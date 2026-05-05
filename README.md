# CryptoGraph 🔐

**Cryptographic API Analysis & Risk Assessment Tool**

Analyze any public or private repository for cryptographic API usage, security vulnerabilities, and Post-Quantum Cryptography (PQC) compatibility. Supports **Java, JavaScript, Go, C/C++, and Python**.

## What is CryptoGraph?

CryptoGraph is a multi-language cryptographic API analyzer that:

1. **Detects crypto API usage** in 5 programming languages (Java, JavaScript, Go, C/C++, Python)
2. **Extracts context** from call chains, arguments, data flow, and control flow
3. **Applies per-language risk rules** to flag insecure patterns (ECB mode, weak hashes, small RSA keys, weak PRNG)
4. **Generates structured CBOM** (Cryptographic Bill of Materials) with metadata, risk scores, and evidence
5. **Enables LLM-based labeling** for contextual risk assessment and remediation guidance
6. **Supports web UI** for easy repository scanning without CLI knowledge

### Key Features

✅ **Multi-Language**: Java, JavaScript, Go, C/C++, Python  
✅ **Web UI**: Paste repo link → Get results (no CLI needed)  
✅ **50+ Crypto APIs**: Comprehensive per-language detection  
✅ **Per-Language Rules**: 7+ risk rules per language  
✅ **LLM Integration**: AI-powered labeling & remediation  
✅ **Flexible Backends**: Fraunhofer CPG (accurate) or ast-lite (fast)  
✅ **Batch Scanning**: Process multiple repos  
✅ **PQC Assessment**: Quantum-safe algorithm tracking  
✅ **Docker Ready**: One command to run  

### Risk Examples

- **ECB mode** in AES encryption (high risk)
- **MD5/SHA-1** for hashing (high risk)
- **RSA keys <2048 bits** (high risk)
- **Math.random()** for secrets (high risk)
- **Random module** in crypto context (high risk)

### Roadmap

The Fraunhofer-first language roadmap is documented in [docs/ROADMAP.md](docs/ROADMAP.md). It prioritizes Java, Kotlin, JavaScript, TypeScript, C#, and C++ and keeps fallback analyzers only where Fraunhofer cannot be used.

---

## 🚀 Quick Start (30 seconds)

### 1. Start Web UI

```bash
# Option A: Docker (easiest)
docker-compose build && docker-compose up scanner

# Option B: Direct Python
pip install -e .
streamlit run viewer/scanner.py
```

### 2. Open Browser

```
http://localhost:8502
```

### 3. Paste Repository Link

```
https://github.com/nodejs/node.git
```

### 4. Click "Scan" → Get Results

✅ Languages detected automatically  
✅ Risk patterns flagged  
✅ LLM labels added  
✅ Export JSON/JSONL  

---

## 📥 Installation

### Requirements

- **Python 3.10+**
- **Docker & Docker Compose** (recommended)
- **Java 8+** (optional, for Fraunhofer CPG)
- **Git**

### Setup

```bash
# Clone repository
git clone https://github.com/you/cryptograph.git
cd cryptograph

# Install Python dependencies
pip install -r requirements.txt
pip install -e .

# (Optional) Build Fraunhofer exporter for advanced analysis
bash scripts/build_fraunhofer_exporter.sh ./cpg-build
export CRYPTOGRAPH_FRAUNHOFER_EXPORTER=./cpg-build/joern-export-plugin.jar
```

---

## 🎮 Usage

### Web Interface (Easiest)

```bash
# Start the web scanner UI
docker-compose up scanner

# Or direct Python:
streamlit run viewer/scanner.py
```

Open: `http://localhost:8502`

**Workflow:**
1. Paste GitHub URL or local path
2. Select backend (Fraunhofer/ast-lite)  
3. Click "Scan"
4. Review findings
5. Enable LLM labeling
6. Download results

### Command Line

```bash
# Scan single repository
cryptograph scan-repo \
  --repo https://github.com/nodejs/node.git \
  --out-dir ./results/node-scan

# Use fast backend
cryptograph scan-repo \
  --repo . \
  --out-dir ./results/local \
  --backend ast-lite

# Label findings
python scripts/llm-label-cbom.py \
  --input ./results/node-scan/dataset.jsonl \
  --output ./results/node-scan/labeled.jsonl

# Generate HTML report
cryptograph report \
  --input ./results/node-scan/merged-cboms.json \
  --output ./results/node-scan/report.html
```

### Batch Scanning

```bash
# Create repos.txt (one repo per line)
echo "https://github.com/nodejs/node.git" > repos.txt
echo "https://github.com/expressjs/express.git" >> repos.txt

# Batch scan
bash scripts/batch-scan-repos.sh repos.txt

# Results in ./results/batch-scan-TIMESTAMP/
```

---

## 📊 Supported Languages

| Language | APIs | Rules | Example |
|----------|------|-------|---------|
| **Java** | 15+ | 7 | `Cipher.getInstance("AES/ECB/PKCS5Padding")` |
| **JavaScript** | 12+ | 7 | `crypto.createCipher("aes-256-ecb", key)` |
| **Go** | 10+ | 6 | `cipher.NewGCMEncrypter(block)` |
| **C/C++** | 8+ | 5 | `EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), ...)` |
| **Python** | 13+ | 8 | `hashlib.md5()` / `cryptography.Cipher` |

---

## 📂 Output Structure

```
results/scan_TIMESTAMP/
├── merged-cboms.json         # All findings merged
├── cbom-java-*.json          # Per-language results
├── cbom-javascript-*.json
├── cbom-python-*.json
├── dataset.jsonl             # One asset per line (for LLM)
├── labeled.jsonl             # After LLM labeling
└── report.html               # Interactive HTML report
```

### CBOM Format

```json
{
  "cboms": [
    {
      "metadata": {
        "detected_language": "java",
        "scan_timestamp": "2026-04-27T10:30:00Z"
      },
      "cryptographic_assets": [
        {
          "asset_id": "java-crypto-1234",
          "crypto_metadata": {
            "algorithm": "AES",
            "mode": "ECB",
            "key_size": 256
          },
          "usage": "Cipher.getInstance(\"AES/ECB/PKCS5Padding\")",
          "risk": "high",
          "rules": ["JAVA_AES_ECB"],
          "evidence": {
            "summary": "ECB mode detected",
            "remediation": "Use GCM or CTR+HMAC"
          }
        }
      ]
    }
  ]
}
```

---

## 🔧 Configuration

### Per-Language API Mappings

Edit `config/api_mappings.<lang>.json`:

```json
{
  "api_pattern": "crypto.subtle",
  "algorithm": "WebCrypto",
  "primitive": "authenticated_encryption",
  "provider": "node:crypto"
}
```

### Per-Language Risk Rules

Edit `config/rules_v2.<lang>.json`:

```json
{
  "id": "JS_ECB_MODE",
  "match": {"api_name_in": ["createCipher"], "mode_in": ["ECB"]},
  "risk": "high",
  "message": "ECB mode is insecure",
  "remediation": "Use GCM or ChaCha20-Poly1305"
}
```

### Environment Variables

```bash
export CRYPTOGRAPH_FRAUNHOFER_EXPORTER=/path/to/joern-export-plugin.jar
export LLM_API_KEY=sk-...
```

---

## 📚 Documentation

- **[Web Scanner Guide](docs/EXTERNAL-REPO-SCANNING.md)** — Full web UI workflow
- **[CLI Usage Guide](docs/USAGE-EXTERNAL-REPOS.md)** — Advanced features
- **[Quick Examples](docs/QUICK-EXAMPLES.md)** — Real repo examples
- **[Quick Reference](docs/QUICK-REFERENCE.md)** — One-page cheat sheet
- **[Architecture](docs/architecture.md)** — System design

---

## 🧪 Testing

```bash
# Run pytest
pytest tests/ -v

# Test with Docker
docker-compose run cryptograph scan --input samples --output /results/test.json

# Check results
cat results/test.json | jq '.cboms[].cryptographic_assets | length'
```

---

## 🔌 CI/CD Integration

### GitHub Actions

```yaml
name: CryptoGraph Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
      - run: pip install -e .
      - run: cryptograph scan-repo --repo . --out-dir ./results
      - uses: actions/upload-artifact@v3
        with:
          name: cryptograph-results
          path: results/
```

---

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| Streamlit not found | `pip install -r requirements.txt` |
| Docker build fails | `docker-compose build --no-cache` |
| No assets detected | Check repo has crypto code; try `--backend ast-lite` |
| CPG exporter missing | `bash scripts/build_fraunhofer_exporter.sh ./cpg-build` |
| Slow scan | Use `--backend ast-lite` for faster analysis |

---

## 📈 Performance Tips

| Scenario | Backend | Time |
|----------|---------|------|
| Quick scan | ast-lite | 2-5 min |
| Accurate scan | fraunhofer | 5-20 min |
| Large repo (>1GB) | ast-lite | 10-60 min |

---

## 🎯 Roadmap

- [x] Multi-language repository scanning
- [x] Web UI for easy use
- [x] LLM-based risk labeling
- [x] Per-language API mappings & rules
- [ ] Real LLM API integration (OpenAI, Claude)
- [ ] Parallel scanning
- [ ] Resource limits & timeouts
- [ ] Integration test suite
- [ ] CI/CD templates
- [ ] VSCode extension

---

## 🤝 Contributing

Contributions welcome! Areas of interest:
- Additional language support
- LLM API integrations
- Performance optimizations
- Enhanced UI features
- Integration tests

---

## 📄 License

MIT License - See LICENSE file

---

**Made with ❤️ for secure cryptography**
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
