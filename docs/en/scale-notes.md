# Scaling CryptoGraph to Large Repositories

CryptoGraph is architected to scale from toy samples to multi-million-line repositories. The MVP includes scalability-first design decisions that enable growth without major restructuring.

## MVP Scaling Strategy

### File-by-File Scanning

- Process input directories **file-by-file** instead of building a monolithic in-memory graph.
- Each file generates a fragment of the normalized graph.
- Fragments are independently processable and can be cached.

### Normalized Graph Boundary

- CPG generation (Fraunhofer or AST-lite) is isolated behind a `load_graph()` interface.
- All downstream analysis (matching, dataflow, CBOM building) operates on normalized JSON.
- This boundary allows **backend replacement** and **parallelization** without changing analysis code.

### Per-Run Artifact Grouping

All outputs from a scan are grouped under a timestamped run directory:

```
output/run-YYYYMMDDTHHMMSSZ-xxxxxxxx/
  ├── cpg.json (or sharded: cpg-shard-*.json)
  ├── result.json
  ├── report.html
  └── manifest.json
```

Benefits:
- Large scans remain reviewable (no mixing of unrelated runs).
- Retry-friendly: failed shards can be re-run without re-processing the entire input.
- Incremental output: findings can be aggregated across shards.

### Avoiding Monolithic Graph Objects

- Matching logic does **not** depend on a single in-memory JVM graph object.
- All graph queries use node/edge lookups from JSON (no Java object pointers).
- This enables backend swapping and independent shard processing.

## Next Scaling Steps

### 1. Shard Manifests for Large Repositories

Split large repositories into size-bounded shards:

```
manifest.json
├── shards: [
│   { "id": "shard-0", "file_count": 500, "node_count": 12000, ... },
│   { "id": "shard-1", "file_count": 500, "node_count": 11500, ... },
│   ...
│  ]
├── aggregated_findings: { "HIGH": 42, "MEDIUM": 156, ... }
```

### 2. Per-Shard Finding Export

Before aggregation, emit finding files per shard:

```
output/run-xxx/findings-shard-0.json
output/run-xxx/findings-shard-1.json
output/run-xxx/findings-aggregated.json
```

Allows:
- Parallel finding deduplication
- Incremental CBOM building
- Easier retry logic for failed shards

### 3. File Hashing for Incremental Scans

Track file SHA-256 in manifest:

```json
{
  "run_timestamp": "...",
  "files": [
    { "path": "src/auth.py", "sha256": "abc123...", "change_type": "modified|added|unchanged" }
  ]
}
```

Enable incremental scans:
- Skip unchanged files
- Re-process only modified files
- Merge old and new findings

### 4. Worker Queues for Parallel CPG Export

Distribute CPG generation across workers:

```python
# Pseudocode
queue = FileQueue(input_directory)
workers = [ExporterWorker(queue) for _ in range(cpu_count())]
for worker in workers:
    worker.start()

# Each worker:
# - Dequeues a file
# - Runs Fraunhofer or ast-lite
# - Writes normalized graph fragment
# - Enqueues findings for aggregation
```

Considerations:
- Fraunhofer JVM startup overhead (~1–2s per process); amortize by batching files per worker.
- Lock-free graph fragment assembly (each worker is independent).

### 5. Durable Storage for Graph/Finding Artifacts

Store intermediate artifacts in persistent storage:

```
s3://cryptograph-artifacts/run-xxx/
├── cpg-shard-0.json
├── cpg-shard-1.json
├── findings-shard-0.json
├── findings-shard-1.json
└── manifest.json
```

Benefits:
- Retryable scans: re-run failed analysis stages without full re-export.
- Audit trail: keep historical graph data for compliance.
- Distributed processing: workers can fetch/push artifacts from/to cloud storage.

### 6. Run Manifests with Metadata

Extend `manifest.json` to include:

```json
{
  "tool_version": "0.2.0",
  "backend": "fraunhofer",
  "source_hash": "repository SHA-256",
  "shard_count": 12,
  "generation_seconds": 142,
  "matching_seconds": 18,
  "aggregate_findings_by_risk": { "HIGH": 52, "MEDIUM": 201, ... },
  "config_hashes": {
    "api_mappings.json": "...",
    "rules.json": "...",
    "source_sinks.json": "..."
  }
}
```

This enables:
- Version tracking and reproducibility
- Performance attribution (which stage took longest?)
- Config change detection (re-run if config changed)

## Performance Targets

| Operation | Target | Current |
|-----------|--------|---------|
| CPG generation (1k LOC) | < 500 ms | ~1–2 s (JVM startup) |
| Matching (1k nodes) | < 100 ms | ~ 50 ms |
| Dataflow BFS per finding | < 50 ms | ~ 10 ms |
| Full pipeline (10k LOC) | < 30 s | ~ 15 s (ast-lite) |

JVM startup dominates Fraunhofer time; worker batching and incremental processing are critical for large codebases.

## Deployment Checklist

- [ ] Implement per-run directory structure
- [ ] Add manifest generation with node/edge/finding counts
- [ ] Implement shard splitting logic
- [ ] Add per-shard CPG export and finding output
- [ ] Implement file hashing for incremental scans
- [ ] Set up worker queue infrastructure
- [ ] Add cloud storage integration (optional)
- [ ] Implement manifest versioning and metadata tracking
- [ ] Add performance instrumentation (timings per stage)
- [ ] Document runbook for multi-shard scan operations
