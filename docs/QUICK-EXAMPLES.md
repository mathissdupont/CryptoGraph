# CryptoGraph: Quick Examples for External Repositories

This document provides copy-paste ready commands for scanning popular open-source projects.

## Example 1: Scan Node.js (JavaScript + C++)

```bash
# Clone and scan (fast, ast-lite backend)
cryptograph scan-repo \
  --repo https://github.com/nodejs/node.git \
  --out-dir ./results/node.js-scan \
  --backend ast-lite

# Check JavaScript findings
jq '.cboms[] | select(.metadata.detected_language == "javascript") | .cryptographic_assets | length' \
  ./results/node.js-scan/merged-cboms.json

# View first 5 assets in JSONL
head -5 ./results/node.js-scan/dataset.jsonl | jq '.input.crypto_metadata'
```

## Example 2: Scan Spring Framework (Java)

```bash
# Full scan with Fraunhofer CPG (more accurate)
cryptograph scan-repo \
  --repo https://github.com/spring-projects/spring-framework.git \
  --out-dir ./results/spring-scan

# Analyze Java-specific findings
jq '.cboms[] | select(.metadata.detected_language == "java") | {
  lang: .metadata.detected_language,
  asset_count: (.cryptographic_assets | length),
  high_risk: [.cryptographic_assets[] | select(.risk == "high")] | length
}' ./results/spring-scan/merged-cboms.json

# Generate HTML report
cryptograph report \
  --input ./results/spring-scan/merged-cboms.json \
  --output ./results/spring-scan/report.html
```

## Example 3: Scan Go Project (Kubernetes-like)

```bash
# Scan Go code
cryptograph scan-repo \
  --repo https://github.com/kubernetes/kubernetes.git \
  --out-dir ./results/k8s-scan

# Filter for ECB mode issues in Go
jq '.cboms[] | select(.metadata.detected_language == "go") | 
  .cryptographic_assets[] | 
  select(.crypto_metadata.mode == "ECB")' \
  ./results/k8s-scan/merged-cboms.json | jq -s 'length'

# Export to labeled dataset for LLM
python scripts/llm-label-cbom.py \
  --input ./results/k8s-scan/dataset.jsonl \
  --output ./results/k8s-scan/labeled.jsonl
```

## Example 4: Scan Python Project (Django)

```bash
# Django uses Python + C (e.g., cryptography package)
cryptograph scan-repo \
  --repo https://github.com/django/django.git \
  --out-dir ./results/django-scan

# Check which Python crypto libraries are detected
jq '.cboms[] | select(.metadata.detected_language == "python") | 
  .cryptographic_assets[] | .crypto_metadata.provider' \
  ./results/django-scan/merged-cboms.json | sort | uniq -c
```

## Example 5: Local Repository Scan

```bash
# Scan your own project (local directory)
cryptograph scan-repo \
  --repo /path/to/my-app \
  --out-dir ./results/my-app-scan

# Quick summary
echo "Assets by language:"
jq -r '.cboms[] | "\(.metadata.detected_language): \(.cryptographic_assets | length)"' \
  ./results/my-app-scan/merged-cboms.json

echo "High-risk issues:"
jq '.cboms[].cryptographic_assets[] | select(.risk == "high")' \
  ./results/my-app-scan/merged-cboms.json | jq -s 'length'
```

## Batch Scanning Multiple Repos

Create a `repos.txt` file:

```
https://github.com/expressjs/express.git
https://github.com/rails/rails.git
https://github.com/golang/go.git
https://github.com/torvalds/linux.git
/path/to/my-local-repo
```

Then run batch scan:

```bash
bash scripts/batch-scan-repos.sh repos.txt

# Merge all datasets
cat ./results/batch-scan-*/*/dataset.jsonl > ./results/all-repos.jsonl

# Label with LLM
python scripts/llm-label-cbom.py \
  --input ./results/all-repos.jsonl \
  --output ./results/all-repos-labeled.jsonl

# Statistics
wc -l ./results/all-repos-labeled.jsonl
jq '.labels.risk_level' ./results/all-repos-labeled.jsonl | sort | uniq -c
```

## Analyze Labeled Results

After LLM labeling, analyze the risks:

```bash
# Count by risk level
jq -r '.labels.risk_level' ./results/my-repo/labeled.jsonl | \
  sort | uniq -c

# Extract high-risk items
jq 'select(.labels.risk_level == "critical" or .labels.risk_level == "high")' \
  ./results/my-repo/labeled.jsonl > ./results/my-repo/high-risk.jsonl

# Group remediation suggestions
jq -r '.labels.remediation' ./results/my-repo/labeled.jsonl | \
  sort | uniq -c | sort -rn | head -10

# Check PQC compatibility
echo "Post-Quantum Cryptography compatible assets:"
jq -r 'select(.labels.pqc_compatible == true) | .input.crypto_metadata.algorithm' \
  ./results/my-repo/labeled.jsonl | sort | uniq -c
```

## Integration Examples

### Export to CSV for Spreadsheet Analysis

```bash
python << 'EOF'
import json
import csv

input_file = "./results/my-repo/labeled.jsonl"
output_file = "./results/my-repo/analysis.csv"

with open(output_file, 'w', newline='') as csv_f:
    writer = csv.writer(csv_f)
    writer.writerow([
        'Asset ID', 'Algorithm', 'Mode', 'Location', 'Risk Level',
        'Remediation', 'PQC Compatible'
    ])
    
    with open(input_file) as json_f:
        for line in json_f:
            asset = json.loads(line)
            writer.writerow([
                asset.get('asset_id'),
                asset.get('input', {}).get('crypto_metadata', {}).get('algorithm'),
                asset.get('input', {}).get('crypto_metadata', {}).get('mode'),
                asset.get('input', {}).get('context', {}).get('file'),
                asset.get('labels', {}).get('risk_level'),
                asset.get('labels', {}).get('remediation'),
                asset.get('labels', {}).get('pqc_compatible')
            ])

print(f"Exported to {output_file}")
EOF
```

### Send to Security Tracking System (Webhook)

```bash
python << 'EOF'
import json
import requests

input_file = "./results/my-repo/labeled.jsonl"
webhook_url = "https://your-security-system.com/api/findings"

high_risk_count = 0
with open(input_file) as f:
    for line in f:
        asset = json.loads(line)
        if asset.get('labels', {}).get('risk_level') in ('critical', 'high'):
            high_risk_count += 1
            # Send to webhook
            payload = {
                'asset_id': asset.get('asset_id'),
                'algorithm': asset.get('input', {}).get('crypto_metadata', {}).get('algorithm'),
                'risk_level': asset.get('labels', {}).get('risk_level'),
                'remediation': asset.get('labels', {}).get('remediation')
            }
            # requests.post(webhook_url, json=payload)

print(f"High-risk findings: {high_risk_count}")
EOF
```

## Performance Tips

### Scan Only Source Code (Skip Tests/Docs)

Create a `.gitignore` alternative or scan specific directories:

```bash
# Instead of scanning entire repo, scan just src/
cryptograph scan-repo \
  --repo ./results/repo-clone/src \
  --out-dir ./results/src-only-scan
```

### Use ast-lite for Fast Initial Scan

```bash
cryptograph scan-repo \
  --repo https://github.com/user/repo.git \
  --out-dir ./results/quick-scan \
  --backend ast-lite  # 2-3x faster, less accurate
```

### Parallel Scanning (Multiple Repos)

```bash
# Use GNU parallel or xargs for parallel scans
cat repos.txt | parallel -j 4 'cryptograph scan-repo --repo {} --out-dir ./results/{/}'
```

## Troubleshooting

### "No assets detected"

1. Check if crypto APIs are actually in the repo:
   ```bash
   find . -name "*.java" -o -name "*.js" | xargs grep -l "Cipher\|crypto\|hash" | head -5
   ```

2. Verify config patterns match your code:
   ```bash
   jq '.mappings[].api_pattern' config/api_mappings.java.json | grep -i aes
   ```

3. Try with `--backend ast-lite` as fallback

### "CPG exporter not found"

See [CPG Integration](../docs/CPG-INTEGRATION.md#troubleshooting) for setup.

### Memory Issues on Large Repos

Use `--backend ast-lite` or scan smaller directories:
```bash
cryptograph scan-repo \
  --repo ./my-huge-repo/src/main \
  --out-dir ./results/subset-scan
```

## Next Steps

1. **Try a demo scan** on a real repo above
2. **Review the CBOM** structure in merged-cboms.json
3. **Label with LLM** using llm-label-cbom.py
4. **Integrate into CI/CD** (see [USAGE-EXTERNAL-REPOS.md](USAGE-EXTERNAL-REPOS.md#integration-with-cicd))
5. **Customize rules** in `config/api_mappings.<lang>.json` for your organization
