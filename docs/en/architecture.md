# Architecture

CryptoGraph separates graph creation from cryptographic analysis by employing a layered pipeline with isolated backend components for CPG generation.

## Core Design Principles

- **Backend isolation**: Fraunhofer AISEC CPG Java internals are wrapped behind a loader interface; the matching engine never depends on JVM classes directly.
- **Normalized graph boundary**: All crypto analysis operates on a uniform JSON graph representation that is independent of the backend (Fraunhofer or AST-lite).
- **Graph-assisted variable tracking**: Data flow follows normalized graph edges (DFG, DATA_FLOW, REACHES) when available, and falls back to local assignment/function-parameter origin extraction when not.
- **Reproducibility**: Docker encapsulation ensures consistent Java/Python compatibility across environments.

## Backends

### Fraunhofer AISEC CPG

The preferred production backend. Requires a Java 11+ JVM and the Fraunhofer CPG exporter JAR. The Python frontend communicates via subprocess execution, avoiding direct JVM coupling.

- **Fallback behavior**: If the exporter is unavailable or crashes, the CLI attempts automatic fallback to `ast-lite` unless `--backend fraunhofer-strict` is specified.
- **Strict mode**: `fraunhofer-strict` fails immediately on any CPG generation error, suitable for validation and CI/CD pipelines.

### AST-lite Fallback

A lightweight Python AST-based fallback that preserves the normalized graph shape. Used when:
- Fraunhofer exporter is unavailable
- JVM initialization fails
- Development requires rapid iteration without Fraunhofer setup

Produces lower-quality dataflow information due to Python-only AST traversal.

### Fixed Backend Labels

- `fraunhofer`: CPG data only.
- `fraunhofer-fallback:ast-lite`: Exporter unavailable; ast-lite used.
- `fraunhofer-failed:ast-lite`: Exporter crashed; fallback applied despite availability.

## Normalized Graph Model

The normalized graph JSON normalizes Fraunhofer and AST-lite outputs to a uniform schema.

### Nodes

Represents semantic code elements:
- `id`: Stable unique identifier (node_ref format).
- `kind`: Node type (call, callee, function, argument, variable, assignment, return, literal).
- `name`: Short name (API name, function name, or variable).
- `properties`:
  - `file`, `line`, `column`: Source location.
  - `function`: Enclosing function name.
  - `resolved_name`: Fully qualified name (often from Fraunhofer).
  - `callee`: Target of a call (call node property).
  - `arguments`, `keywords`: Call site argument list and keyword arguments.
  - `literal_arguments`: String values from literal arguments.
  - `backend`: Provenance (fraunhofer or ast-lite).

### Edges

Directed relationships between nodes:

**AST/CFG edges:**
- `CALLS`: Function call relationship.
- `AST`: Abstract syntax tree parent-child.
- `ARGUMENT`: Argument position in a call.
- `RETURN`: Return value flow.

**Data Flow edges (graph-assisted):**
- `DFG`: Data flow graph edge from Fraunhofer.
- `DATA_FLOW`: Alternative dataflow edge label.
- `REACHES`: Reaching definition edge.

**Control Flow:**
- `EOG`: Evaluated order graph (when emitted by Fraunhofer).

### Backend Property

Tracks the provenance of each node and edge:
- `"fraunhofer"`: True Fraunhofer CPG data.
- `"ast-lite"`: Synthesized from Python AST fallback.

## Variable-Level Dataflow (VDF)

### Challenge

Fraunhofer's Python frontend does not guarantee rich interprocedural dataflow for every source-to-sink pattern. For complex patterns like `request["token"] → token → encrypt(token)`, the graph may lack complete DFG/DATA_FLOW edges.

### Solution: Graph-Assisted + Local Analysis

Variable-level dataflow combines three strategies:

1. **Normalized graph edges**: Follow DFG, DATA_FLOW, and REACHES edges when present.
2. **Local assignment tracking**: When a variable assignment occurs in the function containing the sink (e.g., `token = request["token"]`), record it as `assignment_origin`.
3. **Function parameter origin**: When an argument comes from a function parameter, record the parameter name and index.

### Implementation

In `context_extractor.py`:

- `_extract_argument_signals()` extracts argument values and their sources.
- `_assignment_origin()` walks the function's local assignments to find where a variable was defined.
- `_dataflow_analysis()` combines graph edges and local origins into a unified `sources_reaching_sink` list.
- `_reaching_dataflow_sources()` performs BFS over DFG edges, visiting up to `MAX_DATAFLOW_DEPTH=24` hops.

Example output:
```json
{
  "sources_reaching_sink": [
    {
      "argument_index": 0,
      "argument": "token",
      "via": "assignment_origin",
      "source": "request[\"token\"]",
      "reaches_sink": true
    },
    {
      "argument_index": 0,
      "argument": "token",
      "via": "graph_edge:DFG",
      "source": "...",
      "reaches_sink": true
    }
  ]
}
```

### Missing Dataflow

When no DFG edges or assignment origins are found, the result includes:
```json
{
  "available": false,
  "unresolved_reason": "no_dataflow_edges_or_assignment_origin"
}
```

## Analysis Layers

### 1. Crypto Matcher (`crypto_matcher.py`)

Identifies cryptographic API calls by matching them against configured API/primitive mappings in `config/api_mappings.json`. Outputs `CryptoFinding` objects with:
- API name and resolved callee
- Source file, line, function
- Cryptographic primitive and operation category
- Risk confidence (0.0–1.0)

### 2. Context Extractor (`context_extractor.py`)

Enriches each finding with contextual signals:
- **Call chain**: Caller ancestry from reverse call graph.
- **Argument signals**: Literal values, modes (CBC, GCM, etc.), padding schemes, key sizes.
- **Source/sink classification**: Argument-level source category (user_input, key_material, generated_random, etc.) and crypto sink type.
- **Dataflow analysis**: Variable-level reachability from sources to the crypto sink.
- **Graph context**: Incoming/outgoing edges, edge kinds, nearby call/callee/argument nodes.

### 3. CBOM Builder (`cbom_builder.py`)

Converts enriched findings into the CryptoGraph CBOM JSON schema with stable asset IDs and risk scores derived from API mapping, source location, graph context, dataflow evidence, and risk rule matches.

## Call Graph Construction

### Native Call Edges

Fraunhofer AISEC CPG exports `invokes` relationships representing true interprocedural calls.

### Synthetic Local Edges

When Fraunhofer dataflow is unavailable (e.g., cross-module or module-level calls), the exporter adds synthetic `CALLS` edges for same-module function definitions found by AST analysis. This ensures CBOM assets always include a meaningful call chain.

## CPG Inspection

The `cryptograph graph` command exports the normalized graph for debugging:

```bash
cryptograph graph --input samples --backend fraunhofer-strict --output cpg.json --dot cpg.dot --html cpg.html
```

Outputs:
- **cpg.json**: Full normalized graph (nodes and edges).
- **cpg.dot**: Graphviz DOT format for visualization.
- **cpg.html**: Interactive HTML graph viewer (standalone, no server needed).

## Run Artifacts

All generated artifacts are grouped under a timestamped run directory:

```
output/run-YYYYMMDDTHHMMSSZ-xxxxxxxx/
  ├── cpg.json
  ├── cpg.dot
  ├── cpg.html
  ├── result.json
  ├── report.html
  └── manifest.json
```

The `manifest.json` includes:
- Graph node and edge counts
- Finding counts by risk level, algorithm, and primitive
- Config file SHA-256 hashes for reproducibility
- Tool version and backend label

## Extensibility

### Adding a New Backend

Implement the graph loader interface:

```python
def load_graph(input_path: Path, backend: str) -> NormalizedGraph:
    # Return a NormalizedGraph instance
    pass
```

The backend must emit valid nodes and edges matching the normalized schema.

### Adding Risk Rules

Extend `config/rules.json` with domain-specific risk scoring rules. Rules are applied in the CBOM builder to adjust confidence scores based on context patterns.
