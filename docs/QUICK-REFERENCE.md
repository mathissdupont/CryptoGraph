# CryptoGraph: Quick Reference Card

## One-Liner: Scan Any GitHub Repo

```bash
cryptograph scan-repo --repo https://github.com/user/repo.git --out-dir ./results/scan
```

## 5-Minute Workflow

### 1. Scan a Repository
```bash
cryptograph scan-repo \
  --repo https://github.com/nodejs/node.git \
  --out-dir ./results/node-scan
```

### 2. Review Findings
```bash
# View merged CBOM
jq '.cboms[] | {lang: .metadata.detected_language, assets: (.cryptographic_assets | length)}' \
  ./results/node-scan/merged-cboms.json

# View high-risk assets
jq '.cboms[].cryptographic_assets[] | select(.risk == "high")' \
  ./results/node-scan/merged-cboms.json
```

### 3. Label with LLM
```bash
python scripts/llm-label-cbom.py \
  --input ./results/node-scan/dataset.jsonl \
  --output ./results/node-scan/labeled.jsonl
```

### 4. Analyze Results
```bash
# Risk distribution
jq -r '.labels.risk_level' ./results/node-scan/labeled.jsonl | sort | uniq -c

# Top remediation suggestions
jq -r '.labels.remediation' ./results/node-scan/labeled.jsonl | \
  sort | uniq -c | sort -rn | head -5
```

---

## Command Reference

### Scan Commands

```bash
# Clone from GitHub and scan
cryptograph scan-repo --repo https://github.com/user/repo.git --out-dir ./results/scan

# Scan local repository
cryptograph scan-repo --repo /path/to/repo --out-dir ./results/scan

# Use fast (ast-lite) backend
cryptograph scan-repo --repo ... --out-dir ... --backend ast-lite

# Strict mode (fail on errors)
cryptograph scan-repo --repo ... --out-dir ... --backend fraunhofer-strict

# Build Fraunhofer CPG exporter first
cryptograph scan-repo --repo ... --out-dir ... --build-cpg
```

### Output Files

```bash
results/scan/
├── merged-cboms.json        # All CBOMs merged
├── dataset.jsonl            # One asset per line (ready for LLM)
├── cbom-*.json              # Per-language CBOMs
└── repo/                    # Cloned repository (temp)
```

### LLM Labeling

```bash
# Default: simulate LLM labeling (heuristic-based)
python scripts/llm-label-cbom.py --input dataset.jsonl --output labeled.jsonl

# Real LLM API (when implemented)
python scripts/llm-label-cbom.py \
  --input dataset.jsonl \
  --output labeled.jsonl \
  --llm-api openai \
  --llm-model gpt-4
```

### Reporting

```bash
# Generate HTML report from CBOM
cryptograph report \
  --input ./results/scan/merged-cboms.json \
  --output ./results/scan/report.html

# Convert to CycloneDX format
cryptograph cyclonedx \
  --input ./results/scan/merged-cboms.json \
  --output ./results/scan/cyclonedx-cbom.json
```

---

## Supported Languages

| Language | APIs Detected | Rules | Backend |
|----------|---------------|-------|---------|
| **Java** | 15+ | 7 | Fraunhofer CPG / ast-lite |
| **JavaScript** | 12+ | 7 | Fraunhofer CPG / ast-lite |
| **Go** | 10+ | 6 | Fraunhofer CPG / ast-lite |
| **C/C++** | 8+ | 5 | Fraunhofer CPG / ast-lite |
| **Python** | 13+ | 8 | ast-lite (no CPG yet) |

---

## Common Use Cases

### Find All ECB Mode Usage
```bash
jq '.cboms[].cryptographic_assets[] | select(.crypto_metadata.mode == "ECB")' merged-cboms.json
```

### Find Deprecated Hash Algorithms
```bash
jq '.cboms[].cryptographic_assets[] | 
  select(.crypto_metadata.algorithm | test("MD5|SHA-1"))' merged-cboms.json
```

### Find Small RSA Keys
```bash
jq '.cboms[].cryptographic_assets[] | 
  select(.crypto_metadata.key_size < 2048)' merged-cboms.json
```

### Get Risk Summary
```bash
jq '[.cboms[].cryptographic_assets[] | .risk] | group_by(.) | map({(.[0]): length}) | add' merged-cboms.json
```

### Export High-Risk Items to CSV
```bash
jq -r '[.cboms[].cryptographic_assets[] | select(.risk == "high") | 
  [.asset_id, .crypto_metadata.algorithm, .risk, .context.file]] | 
  @csv' merged-cboms.json > high-risk.csv
```

---

## Configuration Customization

### Per-Language Mappings

Edit `config/api_mappings.<lang>.json`:
```json
{
  "api_pattern": "crypto.createCipher",
  "algorithm": "AES",
  "primitive": "symmetric_encryption",
  "provider": "node:crypto"
}
```

### Per-Language Rules

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

---

## Environment Variables

```bash
# Fraunhofer CPG exporter path
export CRYPTOGRAPH_FRAUNHOFER_EXPORTER=/path/to/joern-export-plugin.jar

# LLM API key (for future integrations)
export LLM_API_KEY=sk-...
```

---

## Batch Scanning

Create `repos.txt`:
```
https://github.com/nodejs/node.git
https://github.com/expressjs/express.git
/path/to/local/repo
```

Run batch scan:
```bash
bash scripts/batch-scan-repos.sh repos.txt

# Results in: ./results/batch-scan-TIMESTAMP/
```

---

## Performance Tips

| Scenario | Recommendation |
|----------|-----------------|
| Quick initial scan | `--backend ast-lite` |
| Accurate analysis | `--backend fraunhofer` (default) |
| Large repos (>1GB) | `--backend ast-lite` or scan subset |
| Parallel scanning | `cat repos.txt \| parallel -j 4 'cryptograph scan-repo --repo {}'` |

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| CPG exporter not found | Run `bash scripts/build_fraunhofer_exporter.sh ./cpg-build` |
| No assets detected | Check repo has crypto code; try `--backend ast-lite` |
| Scan is slow | Use `--backend ast-lite` or scan smaller directory |
| Memory errors | Use `--backend ast-lite` or reduce scope |

---

## Next Steps

1. **Try a demo:** `bash scripts/demo-scan-external-repo.sh https://github.com/nodejs/node.git`
2. **Scan your repo:** `cryptograph scan-repo --repo . --out-dir ./results/my-scan`
3. **Label with LLM:** `python scripts/llm-label-cbom.py --input ./results/my-scan/dataset.jsonl --output ./results/my-scan/labeled.jsonl`
4. **Integrate to CI/CD:** See [USAGE-EXTERNAL-REPOS.md](USAGE-EXTERNAL-REPOS.md#integration-with-cicd)
5. **Customize rules:** Edit `config/api_mappings.<lang>.json` and `config/rules_v2.<lang>.json`

---

## Documentation

- [Full Usage Guide](USAGE-EXTERNAL-REPOS.md)
- [Quick Examples](QUICK-EXAMPLES.md)
- [Architecture](architecture.md)
- [CPG Integration](CPG-INTEGRATION.md)
- [CBOM Schema](CBOM-REFACTORING.md)
