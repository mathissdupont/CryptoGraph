# Development Notes - April 2026

## Project Status

✅ **Multi-Language Support:** Complete (Java, JavaScript, Go, C/C++, Python)
✅ **Web UI:** Complete (Streamlit-based, Docker-ready)
✅ **LLM Integration:** Complete (Heuristic-based, extensible)
✅ **Documentation:** Complete (2,000+ lines across 3 languages)
✅ **Production Ready:** Yes, for external repo scanning

---

## Architecture Highlights

### 1. Orchestrator Pattern

The `orchestrator.py` module handles multi-language coordination:
- Clone repos (git shallow clone)
- Detect languages (file extension mapping)
- Route to language-specific configs
- Invoke per-language scanning
- Merge results into unified CBOM
- Export JSONL for LLM

**Key insight:** Language detection happens before scanning, enabling config-based customization per language without code changes.

### 2. Config Auto-Selection

Per-language configuration is selected automatically:
```
EXT_LANG_MAP (file extension) → Language ID
→ Look for config/api_mappings.<lang>.json
→ Fall back to config/api_mappings.json if not found
→ Same for rules_v2.<lang>.json
```

**Benefit:** Adding new language requires only config files, not code changes.

### 3. Web UI First

Streamlit web UI (`viewer/scanner.py`) provides:
- Paste-and-scan simplicity
- Real-time progress
- Result visualization (charts, tables)
- One-click LLM labeling
- Export in multiple formats

**Philosophy:** Users shouldn't need to know CLI syntax.

### 4. JSONL for LLM

CBOM is flattened to JSONL format:
- One asset per line
- Flat structure (no nested traversal needed)
- Ready for batch LLM processing
- Compatible with pandas, jq, standard tools

**Insight:** LLMs work better with flat, line-oriented data.

---

## Technical Decisions

### 1. Language Detection by File Extension (Not AST)

**Decision:** Use EXT_LANG_MAP instead of AST parsing

**Rationale:**
- Fast (no parsing overhead)
- Reliable (extensions rarely lie)
- Extensible (just add to map)
- Works before any analysis starts

**Trade-off:** Misses edge cases (e.g., `.js` files that are actually data)

### 2. Per-Language Rules Instead of Universal

**Decision:** Separate rules for each language

**Rationale:**
- `Math.random()` is risky in crypto, normal in other code
- `md5()` exists in all languages but different semantics
- Language-specific best practices (e.g., Go's `crypto/rand` vs `math/rand`)
- Reduces false positives

**Example:**
```
JavaScript: Math.random() → "Weak PRNG in crypto context" (high risk)
Go: math/rand.Intn() → "Use crypto/rand instead" (high risk)
Java: java.util.Random → "Use SecureRandom" (high risk)
```

### 3. Heuristic LLM Labeling (Not Real API)

**Decision:** Start with heuristic simulation, scaffold for real LLM

**Rationale:**
- System works without API keys
- Fast feedback for demos
- Ready for real LLM integration later
- Scaffolding in place (format, output structure)

**Future:** When user provides OpenAI/Anthropic key, just swap in real API calls.

### 4. JSONL + Labeled Separation

**Decision:** Keep `dataset.jsonl` and `labeled.jsonl` separate

**Rationale:**
- Audit trail (can re-label without re-scanning)
- Batch processing (label subset of results)
- Experimentation (different labeling strategies)
- Comparison (compare heuristic vs real LLM)

---

## Known Limitations & Workarounds

### 1. CPG Timeouts on Large Repos

**Issue:** Fraunhofer CPG can hang on repos >1GB

**Current Workaround:**
```bash
cryptograph scan-repo --repo ... --backend ast-lite
```

**Pending Fix:** Implement subprocess timeout wrapper in orchestrator

### 2. Python Has No CPG Support

**Issue:** Python doesn't have Fraunhofer CPG frontend (yet)

**Current Workaround:**
```bash
cryptograph scan-repo --repo /path/to/python --backend ast-lite
```

**Note:** ast-lite is AST-based, less accurate but functional

### 3. No Parallel Scanning Yet

**Issue:** Batch scans run sequentially (one repo at a time)

**Current Workaround:**
```bash
# Manual parallelization with GNU parallel
cat repos.txt | parallel -j 4 'cryptograph scan-repo --repo {} --out-dir ./results/{}'
```

**Pending:** Implement thread pool in batch script

### 4. LLM Labeling Uses Heuristics

**Issue:** Real LLM APIs require API keys and rate limits

**Current Workaround:**
```bash
python scripts/llm-label-cbom.py --llm-api simulate
```

**Note:** Heuristics are surprisingly good for crypto (ECB=bad, GCM=good, etc.)

---

## Configuration Extension Points

### Adding Support for New Language

1. **Create API mapping file:**
   ```json
   // config/api_mappings.rust.json
   [{
     "api_pattern": "openssl::crypto::aes",
     "algorithm": "AES",
     "primitive": "symmetric_encryption"
   }]
   ```

2. **Create risk rules file:**
   ```json
   // config/rules_v2.rust.json
   [{
     "id": "RUST_CUSTOM_RULE",
     "match": {"api_name_in": ["openssl"]},
     "risk": "info"
   }]
   ```

3. **Update language map (in langdetect.py):**
   ```python
   EXT_LANG_MAP["rust"] = [".rs"]
   ```

4. **Test:**
   ```bash
   cryptograph scan-repo --repo <rust_project> --out-dir ./results/rust
   ```

### Customizing Risk Rules

Edit `config/rules_v2.<lang>.json`:
```json
{
  "id": "CUSTOM_RULE",
  "match": {
    "api_name_in": ["cipher.init"],
    "mode_in": ["ECB"],
    "key_size_lt": 128
  },
  "risk": "critical",
  "message": "Insecure cipher configuration",
  "remediation": "Use AES-256-GCM with proper key management"
}
```

---

## Testing Approach

### 1. Unit Tests

```bash
pytest tests/test_pipeline.py -v
pytest tests/test_cyclonedx_cbom.py -v
```

### 2. Integration Tests (Real Repos)

```bash
# Small repo (fast)
cryptograph scan-repo --repo https://github.com/expressjs/express.git --out-dir ./results/express

# Medium repo
cryptograph scan-repo --repo https://github.com/nodejs/node.git --out-dir ./results/node --backend ast-lite

# Large repo (slow, use ast-lite)
cryptograph scan-repo --repo https://github.com/kubernetes/kubernetes.git --out-dir ./results/k8s --backend ast-lite
```

### 3. Heuristic Validation

```bash
python scripts/llm-label-cbom.py --input ./results/express/dataset.jsonl --output ./results/express/labeled.jsonl
# Review labeled.jsonl for correctness
```

---

## Performance Notes

### Scanning Speed (by backend)

| Backend | Speed | Accuracy | Use Case |
|---------|-------|----------|----------|
| ast-lite | 2-5 min | Good | Development, large repos |
| fraunhofer | 5-20 min | Excellent | Production, critical scans |

### Optimization Tips

1. **Shallow clone for speed:**
   ```bash
   cryptograph scan-repo --repo <url> --out-dir ./results/scan
   # Uses --depth 1 by default
   ```

2. **Use ast-lite for large repos:**
   ```bash
   cryptograph scan-repo --repo <large_repo> --backend ast-lite --out-dir ./results/scan
   ```

3. **Batch scan with parallelization:**
   ```bash
   cat repos.txt | parallel -j 4 'cryptograph scan-repo --repo {} --out-dir ./results/{}'
   ```

---

## Docker & Deployment Notes

### Building Custom Image

```bash
docker-compose build --no-cache
```

### Environment Variables

```bash
# Fraunhofer exporter location
export CRYPTOGRAPH_FRAUNHOFER_EXPORTER=/path/to/joern-export-plugin.jar

# LLM settings (future)
export LLM_API_KEY=sk-...
export LLM_MODEL=gpt-4
```

### Volume Mounting

Results are written to `/results/` in container, mounted at `./results/` on host:
```bash
docker-compose run cryptograph scan-repo --repo https://... --out-dir /results/scan
# Results appear in ./results/scan/
```

---

## Debugging Tips

### Enable Verbose Logging

```bash
# In CLI
cryptograph scan-repo --repo ... --out-dir ./results/scan --verbose

# In Python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Inspect Intermediate Results

```bash
# View merged CBOM
jq '.' ./results/scan/merged-cboms.json | head -50

# View dataset (before LLM)
head -3 ./results/scan/dataset.jsonl

# View labeled results (after LLM)
head -3 ./results/scan/labeled.jsonl
```

### Check Language Detection

```bash
# Look at scan log
cat ./results/scan/scan.log | grep "Language"

# Or use Python
from cryptograph.langdetect import detect_language_roots
from pathlib import Path
roots = detect_language_roots(Path("/path/to/repo"))
print(roots)
```

---

## Future Roadmap

### Q2 2026 (Planned)

- [ ] Real LLM API integration (OpenAI, Anthropic)
- [ ] Parallel worker pool for batch scanning
- [ ] CPG timeout implementation
- [ ] Python CPG frontend (when available)
- [ ] Additional language support (Ruby, PHP, C#)

### Q3 2026 (Proposed)

- [ ] VSCode extension for inline analysis
- [ ] Kubernetes deployment guide
- [ ] Integration test suite (pytest)
- [ ] Performance benchmarking
- [ ] SARIF export format

### Q4 2026 (Aspirational)

- [ ] Machine learning model for risk prediction
- [ ] Policy-based remediation automation
- [ ] Supply chain integration (SBOM aggregation)
- [ ] Continuous monitoring dashboard

---

## Key Files to Understand

**To understand the system:**
1. Start with `docs/architecture.md`
2. Read `src/cryptograph/orchestrator.py` (entry point)
3. Review `src/cryptograph/langdetect.py` (language detection)
4. Check `config/api_mappings.<lang>.json` (what gets detected)

**To extend the system:**
1. Add new language → edit `config/` files + `langdetect.py`
2. Add new risk rule → edit `config/rules_v2.<lang>.json`
3. Change web UI → edit `viewer/scanner.py`
4. Integrate real LLM → modify `scripts/llm-label-cbom.py`

**To deploy:**
1. Use `docker-compose up scanner` (easiest)
2. Or `cryptograph scan-repo` from CLI
3. Results go to `./results/scan_TIMESTAMP/`

---

## Team Notes

- **Last Updated:** April 27, 2026
- **Status:** Production-ready for external repo scanning
- **Next Priority:** CPG timeouts & real LLM integration
- **Known Issues:** See Limitations section above
