# CryptoGraph: Scan External GitHub Repositories

CryptoGraph can analyze **any** public or local GitHub repository for cryptographic API usage and security risks. Here's the complete workflow:

## 30-Second Demo

```bash
# 1. Scan a repo
cryptograph scan-repo \
  --repo https://github.com/nodejs/node.git \
  --out-dir ./results/node-scan

# 2. Label with LLM
python scripts/llm-label-cbom.py \
  --input ./results/node-scan/dataset.jsonl \
  --output ./results/node-scan/labeled.jsonl

# 3. Analyze
jq -r '.labels.risk_level' ./results/node-scan/labeled.jsonl | sort | uniq -c
```

**Output:** Risk distribution of all cryptographic assets found.

---

## Full Workflow

### Phase 1: Repository Scanning (5-30 minutes, depending on repo size)

**Command:**
```bash
cryptograph scan-repo \
  --repo https://github.com/USERNAME/REPO.git \
  --out-dir ./results/my-repo-scan
```

**What happens:**
1. Repository is cloned (with `--depth 1` for speed)
2. CryptoGraph detects languages by file extension (`.java`, `.js`, `.go`, `.c`, `.py`, etc.)
3. For each language root, per-language API mappings and rules are applied
4. **Per-language mappings** detect crypto APIs:
   - Java: `Cipher.getInstance`, `MessageDigest.getInstance`, `KeyPairGenerator`, `SecureRandom`
   - JavaScript: `crypto.createCipher`, `crypto.createHash`, `crypto.randomBytes`
   - Go: `RSA.GenerateKey`, `aes.NewCipher`, `crypto/rand`
   - C/C++: `EVP_CipherInit_ex`, `RSA_generate_key_ex`, `RAND_bytes`
   - Python: `hashlib.md5`, `hashlib.sha1`, `cryptography.Cipher`, `random.random`
5. **Per-language rules** flag security issues:
   - ECB mode (high risk)
   - Weak/deprecated hashes (MD5, SHA-1)
   - Small RSA keys (<2048 bits)
   - Non-cryptographic PRNGs for secrets
6. Generate merged CBOM and JSONL dataset

**Outputs:**
```
results/my-repo-scan/
├── merged-cboms.json       # All findings merged
├── dataset.jsonl           # One asset per line (for LLM)
├── cbom-java-*.json        # Java findings
├── cbom-javascript-*.json  # JavaScript findings
└── ... (per language)
```

### Phase 2: LLM-Based Labeling & Risk Assessment (2-10 minutes)

**Command:**
```bash
python scripts/llm-label-cbom.py \
  --input ./results/my-repo-scan/dataset.jsonl \
  --output ./results/my-repo-scan/labeled.jsonl
```

**What the LLM does:**
1. Reads each cryptographic asset from the scan
2. Analyzes algorithm, mode, usage context, and applicable rules
3. Assigns risk level: `critical`, `high`, `medium`, `low`, `info`
4. Provides actionable remediation suggestion
5. Notes Post-Quantum Cryptography (PQC) compatibility
6. Writes labeled results back to JSONL

**Labeled output example:**
```json
{
  "asset_id": "...",
  "input": {
    "crypto_metadata": {"algorithm": "AES", "mode": "ECB", ...},
    "usage": "...",
    "context": {"file": "src/crypto.js", "function": "encrypt", ...}
  },
  "labels": {
    "risk_level": "critical",
    "reasoning": "ECB mode leaks plaintext patterns",
    "remediation": "Replace ECB with GCM or ChaCha20-Poly1305",
    "pqc_compatible": false,
    "references": ["NIST SP 800-38A", "CWE-327"]
  }
}
```

### Phase 3: Analysis & Reporting (1-5 minutes)

**Query findings:**
```bash
# Risk distribution
jq -r '.labels.risk_level' ./results/my-repo-scan/labeled.jsonl | sort | uniq -c

# High-risk issues only
jq 'select(.labels.risk_level == "critical" or .labels.risk_level == "high")' \
  ./results/my-repo-scan/labeled.jsonl > ./results/high-risk.jsonl

# Remediation suggestions
jq -r '.labels.remediation' ./results/my-repo-scan/labeled.jsonl | \
  sort | uniq -c | sort -rn | head -10
```

**Generate HTML report:**
```bash
cryptograph report \
  --input ./results/my-repo-scan/merged-cboms.json \
  --output ./results/my-repo-scan/report.html
```

---

## Batch Scanning Multiple Repositories

**Create repos.txt:**
```
https://github.com/nodejs/node.git
https://github.com/expressjs/express.git
https://github.com/rails/rails.git
/path/to/local/project
```

**Run batch scan:**
```bash
bash scripts/batch-scan-repos.sh repos.txt

# Merges all results
cat ./results/batch-scan-*/*/dataset.jsonl > ./all-repos.jsonl

# Label all at once
python scripts/llm-label-cbom.py --input ./all-repos.jsonl --output ./all-repos-labeled.jsonl
```

---

## Supported Languages & Coverage

| Language | APIs Detected | Example Rules | Backend |
|----------|---------------|---------------|---------|
| **Java** | 15+ (Cipher, MessageDigest, KeyPairGenerator, Signature, etc.) | ECB, deprecated hash, small RSA, weak PRNG | Fraunhofer CPG |
| **JavaScript** | 12+ (createCipher, createHash, randomBytes, sign, verify, etc.) | ECB, deprecated hash, weak PRNG, deprecated decipher | Fraunhofer CPG |
| **Go** | 10+ (RSA, AES, MD5, math/rand, Argon2, ECDSA, etc.) | CBC mode, MD5, RSA small key, math/rand usage | Fraunhofer CPG |
| **C/C++** | 8+ (EVP, RSA, MD5, HMAC, RAND_bytes, SSL/TLS, etc.) | ECB, MD5, RAND_pseudo_bytes, CBC auth check | Fraunhofer CPG |
| **Python** | 13+ (hashlib, cryptography, secrets, random, bcrypt, etc.) | MD5/SHA1, weak PRNG, ECB mode, RSA small key | ast-lite |

---

## Example: Real Repository Scan

### Scan Node.js Core Crypto Module

```bash
# Scan Node.js
cryptograph scan-repo \
  --repo https://github.com/nodejs/node.git \
  --out-dir ./results/node

# View JavaScript crypto APIs found
jq '.cboms[] | select(.metadata.detected_language == "javascript") | 
  .cryptographic_assets | map(.crypto_metadata.algorithm) | unique' \
  ./results/node/merged-cboms.json

# Label and analyze
python scripts/llm-label-cbom.py \
  --input ./results/node/dataset.jsonl \
  --output ./results/node/labeled.jsonl

# Risk summary
echo "Risk Distribution:"
jq -r '.labels.risk_level' ./results/node/labeled.jsonl | sort | uniq -c

# Export high-risk to CSV
jq -r '[.asset_id, .input.crypto_metadata.algorithm, .labels.risk_level, .labels.remediation] | @csv' \
  ./results/node/labeled.jsonl > ./results/node/high-risk.csv
```

---

## Key Features

✅ **Multi-Language Support:** Java, JavaScript, Go, C/C++, Python  
✅ **Automatic Language Detection:** By file extension  
✅ **Per-Language Rules & Mappings:** Tailored to each language's crypto API patterns  
✅ **Deterministic Detection:** Catches known insecure patterns (ECB, weak hashes, small keys, weak PRNG)  
✅ **LLM Integration:** Send findings to GPT-4, Claude, or other LLMs for contextual risk assessment  
✅ **CycloneDX Export:** Convert to standard SBOM/CBOM format  
✅ **HTML Reports:** Interactive reports with findings and remediation  
✅ **Batch Scanning:** Process multiple repos efficiently  
✅ **PQC Readiness:** Flag compatibility with Post-Quantum Cryptography  

---

## Configuration & Customization

### Custom Per-Language Rules

Edit `config/api_mappings.<lang>.json` to add/modify crypto API patterns:

```json
{
  "api_pattern": "crypto.subtle",
  "algorithm": "WebCrypto",
  "primitive": "authenticated_encryption",
  "provider": "node:crypto"
}
```

Edit `config/rules_v2.<lang>.json` to add/modify risk rules:

```json
{
  "id": "JS_CUSTOM_RULE",
  "match": {"api_name_in": ["crypto.subtle"], "algorithm_in": ["AES-GCM"]},
  "risk": "low",
  "message": "WebCrypto best practice",
  "remediation": "Continue using SubtleCrypto for secure primitives"
}
```

### Fraunhofer CPG (Multi-Language Graphs)

For robust multi-language support, build the Fraunhofer exporter:

```bash
bash scripts/build_fraunhofer_exporter.sh ./cpg-build

# Then use:
export CRYPTOGRAPH_FRAUNHOFER_EXPORTER=/path/to/joern-export-plugin.jar
cryptograph scan-repo --repo ... --out-dir ...
```

---

## Performance & Scalability

| Scenario | Recommendation | Time |
|----------|-----------------|------|
| Quick scan (any repo) | `--backend ast-lite` | 2-5 min |
| Accurate scan (medium repo) | `--backend fraunhofer` (default) | 5-20 min |
| Large repo (>1GB) | `--backend ast-lite` or subset | 10-60 min |
| Batch scan (5 repos) | `bash scripts/batch-scan-repos.sh` | 20-100 min |

---

## Integration with CI/CD

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
      - run: cryptograph scan-repo --repo . --out-dir ./cryptograph-results
      - uses: actions/upload-artifact@v3
        with:
          name: cryptograph-results
          path: cryptograph-results/
```

---

## Documentation

- **[Quick Reference](docs/QUICK-REFERENCE.md)** — Commands and common queries
- **[Full Usage Guide](docs/USAGE-EXTERNAL-REPOS.md)** — Detailed workflow and configuration
- **[Quick Examples](docs/QUICK-EXAMPLES.md)** — Real repository examples and scripts
- **[CPG Integration](docs/CPG-INTEGRATION.md)** — Fraunhofer setup and troubleshooting
- **[Architecture](docs/architecture.md)** — System design and data flow

---

## Getting Started

1. **Install CryptoGraph:**
   ```bash
   pip install -e .
   ```

2. **Try a demo:**
   ```bash
   bash scripts/demo-scan-external-repo.sh https://github.com/nodejs/node.git
   ```

3. **Scan your repo:**
   ```bash
   cryptograph scan-repo --repo . --out-dir ./results/my-scan
   ```

4. **Label with LLM:**
   ```bash
   python scripts/llm-label-cbom.py --input ./results/my-scan/dataset.jsonl --output ./results/my-scan/labeled.jsonl
   ```

5. **Analyze results:**
   ```bash
   jq '.labels.risk_level' ./results/my-scan/labeled.jsonl | sort | uniq -c
   ```

---

## Support

For issues, questions, or contributions, see [CONTRIBUTING.md](docs/) or open an issue on GitHub.
