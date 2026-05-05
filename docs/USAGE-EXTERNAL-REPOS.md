# Using CryptoGraph on External GitHub Repositories

This guide shows how to scan external GitHub repositories for cryptographic API usage and security risks using CryptoGraph's `scan-repo` command.

## Quick Start

### 1. Scan a Public GitHub Repository

```bash
# Scan a repository from GitHub and output results to a local directory
cryptograph scan-repo \
  --repo https://github.com/username/repo.git \
  --out-dir ./results/my-repo-scan
```

**Output files:**
- `merged-cboms.json` — merged CBOMs from all detected language roots
- `dataset.jsonl` — flattened JSONL with one asset per line (ready for LLM labeling)
- `cbom-*.json` — per-language CBOM files
- `repo/` — cloned repository (temporary, can be removed after scan)

### 2. Scan a Local Repository

```bash
# Scan a local repository directory
cryptograph scan-repo \
  --repo /path/to/local/repo \
  --out-dir ./results/local-repo-scan
```

### 3. Use Fraunhofer CPG (Multi-Language Support)

By default, CryptoGraph uses Fraunhofer CPG for robust Java, JavaScript, Go, C/C++ code graph extraction (with ast-lite fallback for Python).

If you need to build the Fraunhofer exporter (one-time setup):

```bash
# Build Fraunhofer exporter (requires git, gradle, Java 8+)
cryptograph scan-repo \
  --repo https://github.com/username/repo.git \
  --out-dir ./results/scan \
  --build-cpg
```

## How It Works

### Workflow

1. **Clone Repository** (if URL): Git clone with `--depth 1` for speed
2. **Detect Languages**: Scan file extensions (`.java`, `.js`, `.go`, `.py`, `.c`, `.cpp`, etc.)
3. **Group by Language**: Organize code roots by detected language
4. **Per-Language Scanning**:
   - Detect language-specific APIs (e.g., `Cipher.getInstance` for Java)
   - Apply language-specific rules (e.g., ECB mode detection for each language)
   - Generate per-language CBOM with `detected_language` metadata
5. **Merge CBOMs**: Combine all language CBOMs into `merged-cboms.json`
6. **Export JSONL**: Flatten assets into `dataset.jsonl` for LLM labeling

### Language Support

| Language | Primary Backend | Fallback | Per-Language Config |
|----------|-----------------|----------|-------------------|
| Java | Fraunhofer CPG | ast-lite | `config/api_mappings.java.json`, `config/rules_v2.java.json` |
| JavaScript | Fraunhofer CPG | ast-lite | `config/api_mappings.javascript.json`, `config/rules_v2.javascript.json` |
| Go | Fraunhofer CPG | ast-lite | `config/api_mappings.go.json`, `config/rules_v2.go.json` |
| C/C++ | Fraunhofer CPG | ast-lite | `config/api_mappings.c_cpp.json`, `config/rules_v2.c_cpp.json` |
| Python | ast-lite (no CPG) | — | `config/api_mappings.python.json`, `config/rules_v2.python.json` |
| Ruby | ruby-lite | — | `config/api_mappings.ruby.json`, `config/rules_v2.ruby.json` |

### Per-Language Configuration

Each language has its own mapping and rule files:

- **Mappings** (`api_mappings.<lang>.json`): Define which crypto APIs to detect
  - Example: `Cipher.getInstance` (Java), `crypto.createCipher` (JS), `EVP_CipherInit_ex` (C/C++)
- **Rules** (`rules_v2.<lang>.json`): Define what constitutes risk
  - Example: ECB mode is high risk, PBKDF2 with <100k iterations is medium risk

Orchestrator automatically selects per-language configs when present.

## Example Usage Scenarios

### Scenario 1: Quick Scan of Popular Open-Source Project

```bash
# Scan a real-world Node.js + TypeScript project
cryptograph scan-repo \
  --repo https://github.com/expressjs/express.git \
  --out-dir ./results/express-scan
```

Check results:
```bash
cat ./results/express-scan/dataset.jsonl | head -5  # First 5 assets
jq '.metadata.detected_language' ./results/express-scan/merged-cboms.json  # Languages found
```

### Scenario 2: Deep Analysis with Per-Language Rules

```bash
# Scan Java project with detailed rules
cryptograph scan-repo \
  --repo https://github.com/spring-projects/spring-framework.git \
  --out-dir ./results/spring-scan
```

View Java-specific findings:
```bash
jq '.cboms[] | select(.metadata.detected_language == "java") | .cryptographic_assets' \
  ./results/spring-scan/merged-cboms.json
```

### Scenario 3: LLM Labeling Workflow

After scanning, use the JSONL dataset for LLM-based labeling:

```bash
# Send to LLM for risk assessment and remediation suggestions
cat ./results/my-repo/dataset.jsonl | while read line; do
  # Process each asset with LLM
  echo "$line" | jq '.input.crypto_metadata, .input.usage, .input.context'
done
```

Or use it programmatically:
```python
import json
with open('./results/my-repo/dataset.jsonl') as f:
    for line in f:
        asset = json.loads(line)
        # Pass to LLM API with asset['input'] for risk labeling
        # asset['labels'] will contain LLM recommendations
```

## Output Structure

### merged-cboms.json

```json
{
  "cboms": [
    {
      "metadata": {
        "detected_language": "java",
        "scan_timestamp": "2026-04-27T...",
        "backend": "fraunhofer"
      },
      "cryptographic_assets": [
        {
          "asset_id": "...",
          "crypto_metadata": {"algorithm": "AES", "mode": "ECB", ...},
          "usage": "...",
          "risk": "high",
          "rules": [...],
          "evidence": {"summary": "..."}
        }
      ]
    }
  ]
}
```

### dataset.jsonl

```jsonl
{"asset_id": "...", "input": {"crypto_metadata": {...}, "usage": "...", "context": {...}, ...}, "labels": {}}
{"asset_id": "...", "input": {...}, "labels": {}}
...
```

Each line is a single asset with:
- `input`: Feature vectors (crypto APIs, usage, context, flow, control, rules)
- `labels`: Empty (to be filled by LLM or human reviewers)

## Advanced Options

### Use ast-lite Backend (No Graph Dependencies)

```bash
cryptograph scan-repo \
  --repo https://github.com/username/repo.git \
  --out-dir ./results/scan \
  --backend ast-lite
```

Faster but less precise (uses AST patterns only, no control flow).

### Strict Mode (Fail on CPG Errors)

```bash
cryptograph scan-repo \
  --repo https://github.com/username/repo.git \
  --out-dir ./results/scan \
  --backend fraunhofer-strict
```

Will fail if CPG build or graph extraction errors occur (vs. falling back to ast-lite).

## Environment Setup

### Prerequisites

1. **Python 3.10+**
   ```bash
   python --version
   ```

2. **Git** (for cloning repos)
   ```bash
   git --version
   ```

3. **Optional: Java + Gradle** (for Fraunhofer CPG build)
   ```bash
   java -version
   gradle --version
   ```

### Install CryptoGraph

```bash
cd /path/to/CryptoGraph
pip install -e .
```

### Set Fraunhofer CPG Exporter Path (Optional)

If you have built the Fraunhofer exporter:

```bash
export CRYPTOGRAPH_FRAUNHOFER_EXPORTER=/path/to/joern-export-plugin.jar
cryptograph scan-repo --repo ...
```

Build script helper:
```bash
bash scripts/build_fraunhofer_exporter.sh ./cpg-build
# Script will print the exporter path and suggest export command
```

## Troubleshooting

### "CPG exporter not found"

**Solution:** Install the Fraunhofer exporter:
```bash
bash scripts/build_fraunhofer_exporter.sh ./cpg-build
# Follow the export instructions printed by the script
```

Or use `--backend ast-lite` to skip CPG.

### "No cryptographic assets found"

This is expected for repos with no crypto usage. Check:
1. Repository actually contains crypto code
2. Per-language config files exist (e.g., `config/api_mappings.java.json`)
3. API patterns match your code (patterns are customizable)

### Scan is very slow

**Solutions:**
- Use `--backend ast-lite` for faster (less precise) results
- Scan a smaller subset (e.g., `src/` directory instead of whole repo)
- Use `--repo <local-path>` to avoid cloning time

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: CryptoGraph Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Install CryptoGraph
        run: |
          pip install -e .
      - name: Scan Repository
        run: |
          cryptograph scan-repo \
            --repo . \
            --out-dir ./cryptograph-results \
            --backend ast-lite
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: cryptograph-results
          path: ./cryptograph-results/
```

## Next Steps

1. **Run a test scan** on a public repo (e.g., `https://github.com/nodejs/node.git`)
2. **Review merged-cboms.json** to understand detected assets
3. **Feed dataset.jsonl to LLM** for risk labeling and remediation suggestions
4. **Customize per-language rules** in `config/api_mappings.<lang>.json` if needed
5. **Integrate into CI/CD** for continuous crypto compliance scanning

## References

- [CryptoGraph Architecture](architecture.md)
- [CBOM Schema](docs/CBOM-REFACTORING.md)
- [Per-Language Configuration](config/)
- [CPG Integration](docs/CPG-INTEGRATION.md)
