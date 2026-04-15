# Integration Guide: Switching to CryptoGraph CBOM v2

This guide explains how to use the refactored system and switch from the old implementation.

---

## Quick Start

### Option 1: Direct Replacement (Recommended)

Modify your pipeline script to use the new modules:

```python
# OLD CODE
from cryptograph.crypto_matcher import find_crypto_calls
from cryptograph.cbom_builder import build_cbom

# NEW CODE  
from cryptograph.crypto_matcher_v2 import find_crypto_calls
from cryptograph.cbom_builder_v2 import build_cbom
```

That's it! The new modules have the same interface as the old ones.

### Option 2: Side-by-Side Testing

Run both systems and compare outputs:

```python
from cryptograph.crypto_matcher import find_crypto_calls as find_crypto_old
from cryptograph.crypto_matcher_v2 import find_crypto_calls as find_crypto_new
from cryptograph.cbom_builder import build_cbom as build_cbom_old
from cryptograph.cbom_builder_v2 import build_cbom as build_cbom_v2

# Load data
graph = NormalizedGraph(...)
rules_old = load_json("config/rules.json")
rules_new = load_json("config/rules_v2.json")

# Run both
findings_old = find_crypto_old(graph, mappings_path, rules_path)
findings_new = find_crypto_new(graph, mappings_path, rules_path)

cbom_old = build_cbom_old(findings_old, "src", "fraunhofer", graph, run_id)
cbom_new = build_cbom_v2(findings_new, "src", "fraunhofer", graph, run_id, rules_new)

# Compare
print(f"Old risk distribution: {cbom_old['summary']['by_risk']}")
print(f"New risk distribution: {cbom_new['summary']['by_risk']}")
```

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
