# Architecture

CryptoGraph is a multi-language cryptographic API analyzer with a modular architecture:

```
User Input (Web UI or CLI)
    ↓
Repository Orchestrator (scan-repo command)
    ├─→ Clone/fetch repo (git)
    ├─→ Language Detection (file extensions)
    └─→ Per-Language Scanning (for each detected language)
            ↓
        Language-Specific Config Selection
            ├─→ api_mappings.<lang>.json
            └─→ rules_v2.<lang>.json
            ↓
        Code Analysis Backend
            ├─→ Fraunhofer CPG (accurate, slower)
            └─→ ast-lite (fast, lightweight)
            ↓
        CPG/AST → Normalized Graph
            ↓
        Crypto Matcher (detect APIs per language rules)
            ↓
        Context Extractor (enrich with flow, call chains)
            ↓
        CBOM Builder (apply risk rules, generate findings)
            ↓
        Per-Language CBOM
            ↓
        Merge CBOMs
            ↓
        JSONL Exporter (for LLM)
            ↓
        LLM Labeler (optional: risk assessment + remediation)
            ↓
Output (JSON, HTML, JSONL)
```

---

## Component Overview

### 1. Web UI (`viewer/scanner.py`)

Streamlit-based interface for easy repository scanning:
- Accept GitHub URL or local path
- Select backend (Fraunhofer/ast-lite)
- Display real-time results (languages, assets, risks)
- LLM labeling with AI-generated insights
- Export findings in multiple formats

### 2. Repository Orchestrator (`src/cryptograph/orchestrator.py`)

Coordinates multi-language scanning:
- Detects language roots by file extension (EXT_LANG_MAP)
- Selects per-language config files (api_mappings.<lang>.json, rules_v2.<lang>.json)
- Invokes `_scan()` for each language
- Merges all per-language CBOMs into `merged-cboms.json`
- Exports JSONL dataset for LLM

### 3. Language Detection (`src/cryptograph/langdetect.py`)

File extension-based language identification:
- Maps 26+ file extensions to language IDs
- Groups repository into language roots
- Fallback chain: specific > general > default config

**Supported Languages:**
- Java (.java, .kt, .kts)
- JavaScript (.js, .jsx)
- TypeScript (.ts, .tsx)
- Go (.go)
- Python (.py)
- C/C++ (.c, .cpp, .h)
- Ruby (.rb)
- And 20+ others

### 4. Per-Language Configuration

**API Mappings** (`config/api_mappings.<lang>.json`)

```json
{
  "api_pattern": "crypto.createCipher",
  "algorithm": "AES",
  "primitive": "symmetric_encryption",
  "provider": "node:crypto",
  "notes": "Deprecated, use WebCrypto"
}
```

**Risk Rules** (`config/rules_v2.<lang>.json`)

```json
{
  "id": "JS_AES_ECB",
  "match": {"api_name_in": ["createCipher"], "mode_in": ["ECB"]},
  "risk": "high",
  "message": "ECB mode leaks patterns",
  "remediation": "Use GCM or ChaCha20-Poly1305"
}
```

### 5. Analysis Backends

#### Fraunhofer CPG (Preferred)

- Multi-language code property graph extraction
- Accurate interprocedural dataflow tracking
- Requires: Java 8+, Gradle
- Slower but more accurate
- Built via: `scripts/build_fraunhofer_exporter.sh`
- Invoked via: subprocess to `joern-export-plugin.jar`

#### ast-lite (Fast Fallback)

- Python AST-based analysis (Python code only)
- No JVM overhead
- Fast local iteration
- Lighter dataflow tracking

#### ruby-lite (Fast Fallback)

- Lightweight Ruby call-pattern analysis (.rb)
- No JVM overhead
- Designed to feed the same matcher / CBOM pipeline as the other backends
- Fallback when Fraunhofer unavailable

### 6. Crypto Matching & Context Extraction

**Crypto Matcher:**
- Maps call nodes to configured API patterns
- Extracts algorithm, primitive, mode, key size from patterns
- Per-language rule matching

**Context Extractor:**
- Traces call chains (function → function → crypto API)
- Extracts literal values (hardcoded keys, constants)
- Tracks data flow (user input → crypto sink)
- Records source/sink classification

**CBOM Builder:**
- Applies per-language risk rules
- Assigns risk severity (high/medium/low/info)
- Adds remediation suggestions
- Records evidence (matched API, graph edges, local flow)

### 7. LLM Integration (`scripts/llm-label-cbom.py`)

**Current Mode:** Heuristic simulation (no API calls)
**Future:** Real LLM API (OpenAI, Anthropic, local)

Input: `dataset.jsonl` (one asset per line)
Output: `labeled.jsonl` (with risk_level, reasoning, remediation)

```json
{
  "asset_id": "crypto-java-1234",
  "input": {
    "crypto_metadata": {"algorithm": "AES", "mode": "ECB", ...},
    "usage": "Cipher.getInstance(\"AES/ECB/PKCS5Padding\")",
    "context": {"file": "Crypto.java", "line": 42, ...}
  },
  "labels": {
    "risk_level": "critical",
    "reasoning": "ECB mode leaks plaintext patterns",
    "remediation": "Use GCM or ChaCha20-Poly1305",
    "pqc_compatible": false,
    "references": ["NIST SP 800-38A", "CWE-327"]
  }
}
```

### 8. Output Formats

**merged-cboms.json:** Structured findings with metadata
**dataset.jsonl:** One asset per line for LLM consumption
**labeled.jsonl:** After LLM labeling with risk assessments
**report.html:** Interactive HTML report

---

## Data Flow Example

### Input: GitHub Repository (Node.js)

```
https://github.com/nodejs/node.git
```

### Detection Phase

1. Clone repo
2. Scan files: `*.js` → JavaScript, `*.c` → C, `*.cc` → C++
3. Group by language

### Scanning Phase (JavaScript)

1. Load `config/api_mappings.javascript.json` (12 APIs)
2. Load `config/rules_v2.javascript.json` (7 rules)
3. Run Fraunhofer CPG exporter (or ast-lite fallback)
4. Match crypto APIs: `crypto.createCipher`, `crypto.randomBytes`, etc.
5. Apply rules: Flag ECB, deprecated ciphers, weak PRNG
6. Generate `cbom-javascript-*.json`

### Scanning Phase (C/C++)

1. Load `config/api_mappings.c_cpp.json` (8 APIs)
2. Load `config/rules_v2.c_cpp.json` (5 rules)
3. Run Fraunhofer CPG exporter
4. Match: `EVP_CipherInit_ex`, `RSA_generate_key_ex`, `RAND_bytes`
5. Apply rules: Flag ECB, RAND_pseudo_bytes, key sizes
6. Generate `cbom-c_cpp-*.json`

### Merging Phase

Combine all CBOMs into `merged-cboms.json` with language metadata

### JSONL Export Phase

Flatten each asset into JSONL format for LLM

### LLM Labeling Phase (Optional)

Send each asset to LLM:
- Analyze crypto metadata
- Assess real-world risk
- Provide remediation
- Check PQC compatibility
- Record references

### Output

```
results/scan_20260427_103000/
├── merged-cboms.json       # All findings
├── cbom-javascript-*.json  # JavaScript findings
├── cbom-c_cpp-*.json       # C/C++ findings
├── dataset.jsonl           # For LLM (before labeling)
└── labeled.jsonl           # After LLM labeling
```

---

## Design Decisions

### 1. Per-Language Configs (vs. Single Config)

**Decision:** Separate `api_mappings.<lang>.json` and `rules_v2.<lang>.json`

**Rationale:**
- Each language has different crypto libraries
- JavaScript uses `crypto` module, Java uses `javax.crypto.Cipher`
- Per-language rules avoid false positives (e.g., `Math.random()` is risky in crypto but common elsewhere)
- Allows customization without affecting other languages

### 2. Web UI (vs. CLI Only)

**Decision:** Add Streamlit-based web interface

**Rationale:**
- Users can paste repo link without knowing CLI
- Visual results (charts, tables) are easier to understand
- LLM labeling UI is more intuitive
- Reduces barrier to entry

### 3. JSONL Export (vs. Requiring CBOM Direct Input to LLM)

**Decision:** Export flat JSONL format for LLM

**Rationale:**
- LLMs work better with flat, structured data
- One asset per line makes batch processing natural
- Easier to filter/analyze with standard tools (jq, pandas)
- Avoids tree-traversal complexity in LLM prompts

### 4. Heuristic Labeling (vs. Requiring LLM API Key)

**Decision:** Default to heuristic simulation, optional real LLM

**Rationale:**
- System works out-of-the-box without API key
- Fast feedback for demos and testing
- Scaffolding ready for real LLM API integration
- Users can opt-in to OpenAI/Anthropic without system redesign

---

## Scalability Considerations

### Current

- ✅ Multi-language support with per-language config
- ✅ Web UI for easy access
- ✅ Batch scanning script
- ✅ JSONL export for large datasets

### Pending

- ⏳ Timeouts for CPG jobs (large repos can hang)
- ⏳ Parallel workers for batch scanning
- ⏳ Resource limits (memory, CPU per language)
- ⏳ Incremental scanning (skip unchanged files)

---

## Extension Points

### Adding a New Language

1. Create `config/api_mappings.<new_lang>.json` with API patterns
2. Create `config/rules_v2.<new_lang>.json` with risk rules
3. Add file extension to `EXT_LANG_MAP` in `langdetect.py`
4. (Optional) Add Fraunhofer CPG support if available
5. Test with `cryptograph scan-repo --repo <repo_with_new_lang>`

### Real LLM Integration

1. Modify `scripts/llm-label-cbom.py` to call real API
2. Add environment variables for credentials
3. Implement rate limiting & retry logic
4. Update web UI to show LLM status

### Custom Risk Rules

1. Edit `config/rules_v2.<lang>.json`
2. Add new `match` conditions (api_name_in, mode_in, key_size_lt, etc.)
3. Set `risk` level and `remediation`
4. Restart scanner to reload configs

---

## Testing Strategy

- **Unit Tests:** Per-module functionality
- **Integration Tests:** End-to-end repo scanning
- **Example Repos:** Real GitHub projects (Node.js, Spring, etc.)
- **LLM Tests:** Heuristic labeling correctness
- **Performance Tests:** Scalability on large repos
