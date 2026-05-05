# Integration Guide: Multi-Language Scanning & LLM Labeling

This guide explains how to integrate CryptoGraph's multi-language scanning, web UI, and LLM labeling into your workflows.

---

## Quick Start

### Option 1: Web UI (Easiest)

```bash
# Start web scanner
docker-compose up scanner

# Open http://localhost:8502
# Paste GitHub repo → Click Scan → View Results → Enable LLM
```

**No CLI knowledge required.** UI handles all setup automatically.

### Option 2: CLI (Programmatic)

```python
import subprocess
import json

# Scan repository
result = subprocess.run([
    "cryptograph", "scan-repo",
    "--repo", "https://github.com/nodejs/node.git",
    "--out-dir", "./results/node",
    "--backend", "fraunhofer"
], capture_output=True)

# Load results
with open("./results/node/merged-cboms.json") as f:
    cbom = json.load(f)

# Label with LLM
subprocess.run([
    "python", "scripts/llm-label-cbom.py",
    "--input", "./results/node/dataset.jsonl",
    "--output", "./results/node/labeled.jsonl"
])

# Process labeled results
with open("./results/node/labeled.jsonl") as f:
    for line in f:
        asset = json.loads(line)
        print(f"Risk: {asset['labels']['risk_level']}")
        print(f"Remediation: {asset['labels']['remediation']}")
```

### Option 3: Docker Compose (Container-Based)

```bash
# Scan in container
docker-compose run cryptograph scan-repo \
  --repo https://github.com/nodejs/node.git \
  --out-dir /results/scan

# Label results
docker-compose run cryptograph \
  python scripts/llm-label-cbom.py \
  --input /results/scan/dataset.jsonl \
  --output /results/scan/labeled.jsonl

# Results in ./results/scan/
```

---

## Multi-Language Scanning Integration

### How Language Detection Works

CryptoGraph automatically detects languages by file extension:

```python
from cryptograph.langdetect import detect_language_roots, EXT_LANG_MAP

# Get language roots
roots = detect_language_roots(Path("https://github.com/nodejs/node.git"))
# Output: {"javascript": ["/root/src"], "c_cpp": ["/root/deps"], ...}

# View supported extensions
print(EXT_LANG_MAP)
# {'java': ['.java', '.kt', '.kts'], 'javascript': ['.js', '.jsx'], ...}
```

### Per-Language Configuration

For each detected language, CryptoGraph automatically loads:

1. **API Mappings:** `config/api_mappings.<lang>.json`
2. **Risk Rules:** `config/rules_v2.<lang>.json`

If language-specific files don't exist, falls back to:
- `config/api_mappings.json` (default)
- `config/rules_v2.json` (default)

**Example: JavaScript Scanning**

```json
// config/api_mappings.javascript.json
[
  {
    "api_pattern": "crypto.createCipher",
    "algorithm": "AES",
    "primitive": "symmetric_encryption",
    "provider": "node:crypto",
    "notes": "Deprecated, vulnerable to known-plaintext attacks"
  }
]

// config/rules_v2.javascript.json
[
  {
    "id": "JS_AES_ECB",
    "match": {"api_name_in": ["createCipher"], "mode_in": ["ECB"]},
    "risk": "high",
    "message": "ECB mode leaks plaintext patterns",
    "remediation": "Use GCM or ChaCha20-Poly1305 instead"
  }
]
```

### Adding Support for New Languages

1. **Create API mapping file:**
   ```json
   // config/api_mappings.ruby.json
   [
     {
       "api_pattern": "Digest::MD5.hexdigest",
       "algorithm": "MD5",
       "primitive": "hash",
       "provider": "ruby:digest"
     }
   ]
   ```

2. **Create risk rules file:**
   ```json
   // config/rules_v2.ruby.json
   [
     {
       "id": "RUBY_MD5",
       "match": {"api_name_in": ["Digest::MD5"]},
       "risk": "high",
       "message": "MD5 is cryptographically broken",
       "remediation": "Use Digest::SHA256 or SHA-512"
     }
   ]
   ```

3. **Update language extensions (optional):**
   ```python
   # In langdetect.py
   EXT_LANG_MAP["ruby"] = [".rb"]
   ```

4. **Test:**
   ```bash
   cryptograph scan-repo --repo https://github.com/example/ruby-project.git --out-dir ./results/ruby
   ```

---

## Web UI Integration

### Embedding in Dashboard

The web UI (`viewer/scanner.py`) is a standalone Streamlit app. To embed in a larger dashboard:

```python
# dashboard.py
import streamlit as st
from streamlit_option_menu import option_menu

page = option_menu(
    menu_title="Security Hub",
    options=["CryptoGraph", "SAST", "Dependency Check", "Settings"],
    default_index=0
)

if page == "CryptoGraph":
    st.info("CryptoGraph Scanner")
    # Load scanner UI via iframe or subprocess
    subprocess.run(["streamlit", "run", "viewer/scanner.py"])
```

### Customizing the Web UI

Edit `viewer/scanner.py` to:
- Add company logo
- Change color scheme
- Add custom integrations
- Modify result visualization

```python
# Example: Add company branding
st.set_page_config(
    page_title="ACME CryptoGraph",
    page_icon="🏢",
    layout="wide"
)

st.image("assets/company-logo.png", width=100)
st.title("ACME Security - CryptoGraph Scanner")
```

---

## LLM Labeling Integration

### Current: Heuristic Simulation

By default, LLM labeling uses rule-based heuristics (no API calls):

```bash
python scripts/llm-label-cbom.py \
  --input ./results/scan/dataset.jsonl \
  --output ./results/scan/labeled.jsonl \
  --llm-api simulate  # Default
```

Output includes risk levels, reasoning, and remediation suggestions.

### Future: Real LLM APIs

#### OpenAI Integration (When Implemented)

```python
python scripts/llm-label-cbom.py \
  --input ./results/scan/dataset.jsonl \
  --output ./results/scan/labeled.jsonl \
  --llm-api openai \
  --llm-model gpt-4 \
  --api-key sk-...
```

#### Local LLM (When Implemented)

```python
python scripts/llm-label-cbom.py \
  --input ./results/scan/dataset.jsonl \
  --output ./results/scan/labeled.jsonl \
  --llm-api local \
  --llm-endpoint http://localhost:8000
```

### Processing Labeled Results

```python
import json

with open("./results/scan/labeled.jsonl") as f:
    for line in f:
        asset = json.loads(line)
        
        # Filter by risk
        if asset["labels"]["risk_level"] in ["critical", "high"]:
            print(f"Asset: {asset['asset_id']}")
            print(f"Algorithm: {asset['input']['crypto_metadata']['algorithm']}")
            print(f"Issue: {asset['labels']['reasoning']}")
            print(f"Fix: {asset['labels']['remediation']}\n")
        
        # Check PQC compatibility
        if not asset["labels"]["pqc_compatible"]:
            print(f"⚠️  Not PQC-ready: {asset['asset_id']}")
```

---

## Batch Scanning Integration

### Processing Multiple Repositories

```bash
# 1. Create repos.txt
cat > repos.txt << EOF
https://github.com/nodejs/node.git
https://github.com/expressjs/express.git
https://github.com/spring-projects/spring-framework.git
EOF

# 2. Batch scan
bash scripts/batch-scan-repos.sh repos.txt

# 3. Merge all results
cat results/batch-scan-TIMESTAMP/*/dataset.jsonl > all-repos.jsonl

# 4. Label all at once
python scripts/llm-label-cbom.py --input all-repos.jsonl --output all-repos-labeled.jsonl

# 5. Analyze combined results
jq -r '.labels.risk_level' all-repos-labeled.jsonl | sort | uniq -c
```

### Programmatic Batch Scanning

```python
import subprocess
from pathlib import Path

repos = [
    "https://github.com/nodejs/node.git",
    "https://github.com/expressjs/express.git",
]

results = []

for repo in repos:
    out_dir = f"./results/{repo.split('/')[-1].replace('.git', '')}"
    
    # Scan
    subprocess.run([
        "cryptograph", "scan-repo",
        "--repo", repo,
        "--out-dir", out_dir
    ])
    
    # Label
    subprocess.run([
        "python", "scripts/llm-label-cbom.py",
        "--input", f"{out_dir}/dataset.jsonl",
        "--output", f"{out_dir}/labeled.jsonl"
    ])
    
    results.append(out_dir)

print(f"Scanned {len(results)} repos")
```

---

## CI/CD Integration

### GitHub Actions Workflow

```yaml
name: CryptoGraph Security Scan
on: 
  push:
  pull_request:
  schedule:
    - cron: '0 2 * * 0'  # Weekly

jobs:
  cryptograph:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0
      
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
      
      - name: Label Findings
        run: |
          python scripts/llm-label-cbom.py \
            --input ./cryptograph-results/dataset.jsonl \
            --output ./cryptograph-results/labeled.jsonl
      
      - name: Generate Report
        run: |
          cryptograph report \
            --input ./cryptograph-results/merged-cboms.json \
            --output ./cryptograph-results/report.html
      
      - name: Upload Artifacts
        uses: actions/upload-artifact@v3
        with:
          name: cryptograph-results
          path: cryptograph-results/
      
      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const results = JSON.parse(fs.readFileSync('./cryptograph-results/merged-cboms.json', 'utf8'));
            const assets = results.cboms[0].cryptographic_assets || [];
            const highRisk = assets.filter(a => a.risk === 'high').length;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## 🔐 CryptoGraph Analysis\n- **Total Assets:** ${assets.length}\n- **High Risk:** ${highRisk}\n\n[Full Report](${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID})`
            });
```

### GitLab CI Integration

```yaml
cryptograph:
  stage: security
  image: cryptograph:latest
  script:
    - cryptograph scan-repo --repo . --out-dir ./cryptograph-results
    - python scripts/llm-label-cbom.py 
        --input ./cryptograph-results/dataset.jsonl 
        --output ./cryptograph-results/labeled.jsonl
    - cryptograph report --input ./cryptograph-results/merged-cboms.json 
        --output ./cryptograph-results/report.html
  artifacts:
    paths:
      - cryptograph-results/
    reports:
      sast: cryptograph-results/merged-cboms.json
```

---

## Webhook & Automation

### GitHub Push Trigger

```python
# app.py - Flask webhook handler
from flask import Flask, request
import subprocess
import json

app = Flask(__name__)

@app.route('/webhook/github', methods=['POST'])
def github_webhook():
    payload = request.json
    repo_url = payload['repository']['clone_url']
    
    # Scan pushed repository
    result = subprocess.run([
        "cryptograph", "scan-repo",
        "--repo", repo_url,
        "--out-dir", f"./results/{payload['repository']['name']}"
    ], capture_output=True)
    
    # Label results
    subprocess.run([
        "python", "scripts/llm-label-cbom.py",
        "--input", f"./results/{payload['repository']['name']}/dataset.jsonl",
        "--output", f"./results/{payload['repository']['name']}/labeled.jsonl"
    ])
    
    # Notify (Slack, email, etc.)
    return {"status": "scanned"}

if __name__ == "__main__":
    app.run(port=5000)
```

---

## Output & Reporting

### HTML Report Generation

```bash
cryptograph report \
  --input ./results/scan/merged-cboms.json \
  --output ./results/scan/report.html
```

Opens in browser with:
- Risk distribution charts
- Language breakdown
- Detailed asset listings
- Remediation suggestions
- Export options

### Exporting to Other Formats

**CSV (via jq):**
```bash
jq -r '[.cboms[].cryptographic_assets[] | [.asset_id, .crypto_metadata.algorithm, .risk]] | @csv' \
  ./results/scan/merged-cboms.json > findings.csv
```

**CycloneDX SBOM:**
```bash
cryptograph cyclonedx \
  --input ./results/scan/merged-cboms.json \
  --output ./results/scan/cyclonedx-sbom.json
```

---

## Best Practices

1. **Use Fraunhofer CPG for production scans** (more accurate)
2. **Use ast-lite for quick iterations** (faster)
3. **Enable LLM labeling** for better context understanding
4. **Run regular batch scans** on all repositories
5. **Review high-risk findings first**
6. **Track remediation progress** over time
7. **Share reports with security teams**
8. **Integrate into CI/CD** for continuous monitoring

---

## Troubleshooting

### Issue: No assets detected
**Solution:** Ensure repo has crypto code. Try `--backend ast-lite`

### Issue: Slow scans on large repos
**Solution:** Use `--backend ast-lite` instead of Fraunhofer

### Issue: LLM labeling fails
**Solution:** Check if `scripts/llm-label-cbom.py` is in correct path

### Issue: Docker build fails
**Solution:** Run `docker-compose build --no-cache`

---

## Configuration Files

### Minimal Setup
Use existing `config/api_mappings.json` as-is. No changes needed.

### With New Rules
Create `config/rules_v2.json` from template:
```json
{
  "rules": [
    {
      "id": "AES_ECB_MODE",
      "preconditions": {"algorithm_in": ["AES"]},
      "match": {"mode_in": ["ECB"]},
      "risk": "high",
      "priority": 95,
      "actionable": true,
      "message": "AES ECB mode leaks plaintext patterns...",
      "remediation": "Replace ECB with GCM, CTR, or CBC with authentication"
    }
  ]
}
```

See `config/rules_v2.json` for complete examples.

---

## Module Reference

### 1. risk_engine.py

```python
from cryptograph.risk_engine import RiskEngine

engine = RiskEngine()

score = engine.score(
    algorithm="AES",
    primitive="symmetric_encryption",
    provider="cryptography",
    arguments=["key=b'...'", "mode=ECB"],
    api_name="modes.ECB",
    context={
        "signals": {
            "mode": "ECB",
            "key_size": 256
        }
    }
)

print(f"Risk level: {score.level}")  # "critical"
print(f"Confidence: {score.confidence}")  # 0.98
print(f"Tags: {score.tags}")  # ["ecb_mode_detected"]
print(f"Derivation: {score.derivation}")  # {...how score determined...}
```

**Key Methods**:
- `score()` - Compute risk score
- `risk_tag_explanation()` - Get explanation for a tag

---

### 2. rule_engine.py

```python
from cryptograph.rule_engine import RuleEngine
from cryptograph.utils import load_json

rules_config = load_json("config/rules_v2.json")
engine = RuleEngine(rules_config)

matches = engine.match_rules(
    finding=finding_obj,
    node=graph_node_optional
)

for match in matches:
    print(f"Rule: {match.rule_id}")
    print(f"Priority: {match.priority}")
    print(f"Actionable: {match.is_actionable}")
    print(f"Explanation: {match.explanation}")
```

**Key Methods**:
- `match_rules()` - Find applicable rules
- `filter_for_asset()` - Group rules by category

---

### 3. inference_explainer.py

```python
from cryptograph.inference_explainer import build_inference_explanations

exps = build_inference_explanations(
    function="hash_password_argon2",
    api_name="Argon2",
    algorithm="Argon2",
    primitive="key_derivation",
    arguments=["memory_cost=65540", "time_cost=3"],
    context={...}
)

print(exps["usage_context"].value)  # "authentication_flow"
print(exps["usage_context"].method)  # "function_name_pattern"
print(exps["usage_context"].confidence)  # 0.95
print(exps["usage_context"].evidence)  # [...]

print(exps["intent"].value)  # "derive_password_key"
```

**Key Functions**:
- `build_inference_explanations()` - Build all explanations
- `explanation_summary()` - Serialize to JSON

---

### 4. cbom_builder_v2.py

```python
from cryptograph.cbom_builder_v2 import build_cbom
from cryptograph.utils import load_json

rules_config = load_json("config/rules_v2.json")

cbom = build_cbom(
    findings=findings,
    source="src",
    backend="fraunhofer",
    graph=graph,
    run_id="run-20260415T160000Z",
    rules_config=rules_config
)

# Access structured data
print(f"Total assets: {cbom['summary']['total_assets']}")
print(f"High risk: {cbom['summary']['by_risk'].get('high', 0)}")
print(f"Asset structure:")
for asset in cbom['cryptographic_assets']:
    print(f"  - {asset['asset_id']}: {asset['crypto_metadata']['algorithm']}")
    print(f"    risk: {asset['risk']['level']} ({asset['risk']['confidence']})")
    print(f"    rules: {len(asset['rules'])}")
```

**Key Functions**:
- `build_cbom()` - Main builder
- All internal helper functions available if needed

---

### 5. crypto_matcher_v2.py

```python
from cryptograph.crypto_matcher_v2 import find_crypto_calls
from cryptograph.utils import load_json

mappings = load_json("config/api_mappings.json")
rules_config = load_json("config/rules_v2.json")

findings = find_crypto_calls(
    graph=graph,
    mappings_path=Path("config/api_mappings.json"),
    rules_path=Path("config/rules_v2.json")
)

for finding in findings:
    print(f"API: {finding.api_name}")
    print(f"Algorithm: {finding.algorithm}")
    print(f"Risk: {finding.risk}")
    print(f"Rule IDs: {finding.rule_ids}")
    print(f"Derivation: {finding.context.get('risk_derivation')}")
```

---

## Common Workflows

### 1. Extract Risk Information

```python
asset = cbom['cryptographic_assets'][0]

# Risk level and confidence
print(f"Risk: {asset['risk']['level']} (confidence: {asset['risk']['confidence']})")

# Why is it this risk?
derivation = asset['risk']['derivation_summary']
print(f"Base algorithm: {derivation.get('base_algorithm_risk')}")
if 'mode_escalation' in derivation:
    print(f"Mode escalation: {derivation['mode_escalation']['reason']}")

# What tags apply?
for tag in asset['risk']['tags']:
    print(f"  - {tag}")
```

### 2. Find Actionable Rules

```python
asset = cbom['cryptographic_assets'][0]

actionable_rules = [r for r in asset['rules'] if r['actionable']]
for rule in actionable_rules:
    print(f"Action: {rule['message']}")
    print(f"Explanation: {rule['explanation']}")
```

### 3. Understand Flow

```python
asset = cbom['cryptographic_assets'][0]

flow = asset['flow']
print(f"Key source: {flow.get('key_source', 'N/A')}")
print(f"Data source: {flow.get('data_source', 'N/A')}")
print(f"IV source: {flow.get('iv_source', 'N/A')}")
print(f"Randomness: {flow.get('randomness_source', 'N/A')}")
if 'sink' in flow:
    print(f"Data flows to: {flow['sink']['type']}")
```

### 4. Trace Inference

```python
asset = cbom['cryptographic_assets'][0]

for field, explanation in asset['inference'].items():
    print(f"\n{field}:")
    print(f"  Value: {explanation['value']}")
    print(f"  Method: {explanation['method']}")
    print(f"  Confidence: {explanation['confidence']}")
    print(f"  Evidence:")
    for evidence in explanation['evidence']:
        print(f"    - {evidence}")
```

### 5. Filter Assets by Risk

```python
# Get all high-risk assets
high_risk = [
    a for a in cbom['cryptographic_assets']
    if a['risk']['level'] == 'high'
]

print(f"Found {len(high_risk)} high-risk findings:")
for asset in high_risk:
    print(f"  {asset['crypto_metadata']['algorithm']} "
          f"in {asset['context']['file']}:{asset['context']['line']}")
    for rule in asset['rules']:
        if rule['actionable']:
            print(f"    → {rule['message']}")
```

### 6. Build Risk Report

```python
summary = cbom['summary']

total = summary['total_assets']
by_risk = summary['by_risk']

print("Risk Distribution:")
print(f"  CRITICAL: {by_risk.get('critical', 0)} ({100*by_risk.get('critical', 0)/total:.1f}%)")
print(f"  HIGH:     {by_risk.get('high', 0)} ({100*by_risk.get('high', 0)/total:.1f}%)")
print(f"  MEDIUM:   {by_risk.get('medium', 0)} ({100*by_risk.get('medium', 0)/total:.1f}%)")
print(f"  LOW:      {by_risk.get('low', 0)} ({100*by_risk.get('low', 0)/total:.1f}%)")

# Top dangerous algorithms
by_algo = summary['by_algorithm']
dangerous = ['MD5', 'SHA-1', 'DES', '3DES', 'ECB']
for algo in dangerous:
    count = by_algo.get(algo, 0)
    if count:
        print(f"  {algo}: {count} findings")
```

---

## Upgrading from v1 to v2

### Step 1: Backup Old System
```bash
cp src/cryptograph/cbom_builder.py src/cryptograph/cbom_builder.backup.py
cp src/cryptograph/crypto_matcher.py src/cryptograph/crypto_matcher_backup.py
```

### Step 2: Install New Modules
Copy the following files:
- `src/cryptograph/risk_engine.py`
- `src/cryptograph/rule_engine.py`
- `src/cryptograph/inference_explainer.py`
- `src/cryptograph/cbom_builder_v2.py`
- `src/cryptograph/crypto_matcher_v2.py`

### Step 3: Update Configuration
Ensure `config/rules_v2.json` exists (provided).

### Step 4: Update Main Pipeline
Find where CBOM is generated (typically in main.py or a wrapper):

```python
# Old
findings = find_crypto_calls(graph, mappings_path, rules_path)
cbom = build_cbom(findings, source, backend, graph, run_id)

# New
from cryptograph.utils import load_json
rules_config = load_json("config/rules_v2.json")
findings = find_crypto_calls(graph, mappings_path, rules_path)  # Uses new v2
cbom = build_cbom(findings, source, backend, graph, run_id, rules_config)
```

### Step 5: Test Output
```bash
python -m cryptograph scan --input samples --output test.json --backend fraunhofer
# Verify: check test.json has new structure with improved risk distribution
```

### Step 6: Validate Results
```python
import json
with open("test.json") as f:
    cbom = json.load(f)

# Should have balanced risk distribution
by_risk = cbom['summary']['by_risk']
assert by_risk.get('high', 0) < len(cbom['cryptographic_assets']) * 0.3
assert by_risk.get('low', 0) > 0
print("✅ Risk distribution looks good!")

# Should have fewer rules per asset
avg_rules = sum(len(a['rules']) for a in cbom['cryptographic_assets']) / len(cbom['cryptographic_assets'])
assert avg_rules < 2
print(f"✅ Average rules per asset: {avg_rules:.1f}")

# File size should be smaller
import os
old_size = os.path.getsize("test_old.json") if os.path.exists("test_old.json") else 0
new_size = os.path.getsize("test.json")
print(f"✅ CBOM reduction: {100*(old_size-new_size)/old_size:.0f}%")
```

---

## Troubleshooting

### Issue: ImportError for new modules

**Solution**: Ensure files are in `src/cryptograph/`:
```bash
ls -la src/cryptograph/
# Should show: risk_engine.py, rule_engine.py, ...
```

### Issue: Rules not matching

**Solution**: Check preconditions in rules_v2.json:
```python
rule = rules_config['rules'][0]
print(rule['preconditions'])  # Ensure matches your algorithm/primitive
```

### Issue: Risk scores still wrong

**Solution**: Verify RiskEngine algorithm definitions:
```python
from cryptograph.risk_engine import RiskEngine
engine = RiskEngine()
print(engine.ALGORITHM_RISK.get("Argon2"))  # Should be "low"
```

### Issue: No graph context

**Solution**: Ensure graph is passed to cbom_builder:
```python
cbom = build_cbom(..., graph=graph, ...)  # Don't omit graph parameter
```

---

## Migration Checklist

- [ ] Backup old system (Step 1)
- [ ] Copy new module files (Step 2)
- [ ] Verify rules_v2.json exists (Step 3)
- [ ] Update main pipeline imports (Step 4)
- [ ] Run test scan (Step 5)
- [ ] Validate results (Step 6)
- [ ] Update documentation/runbooks
- [ ] Notify team of changes
- [ ] Plan old system deprecation (if needed)

---

## Support

For questions or issues with the new system:

1. Check `REFACTORING.md` for design details
2. Review `EXAMPLES.md` for concrete examples
3. Check module docstrings in source files
4. Run provided test cases

---

## Next Steps

1. **Short term**: Validate on existing test suite
2. **Medium term**: Integrate into CI/CD pipeline
3. **Long term**: Extend with inter-procedural dataflow analysis
