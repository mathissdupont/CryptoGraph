# Scale Notes

CryptoGraph is intended to grow toward multi-million-line repositories.

## MVP Scale Strategy

- Scan input directories file-by-file.
- Keep a normalized graph boundary between CPG generation and matching.
- Write artifacts into per-run directories under `output/`.
- Keep graph JSON, DOT, HTML report and CBOM output grouped by scan run.
- Avoid matching logic that depends on a single in-memory JVM graph object.

## Next Scale Steps

- Add shard manifests for large repositories.
- Emit per-shard finding files before final aggregation.
- Add file hashing for incremental scans.
- Add worker queues for parallel CPG export.
- Store graph/finding artifacts in a durable location for retryable scans.
- Add run manifests with tool version, backend, source hash, shard count and timings.
