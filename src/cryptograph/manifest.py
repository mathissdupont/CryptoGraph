from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from cryptograph.models import CryptoFinding, NormalizedGraph
from cryptograph.utils import write_json


def write_manifest(
    run_dir: Path,
    command: str,
    source: Path,
    backend: str,
    graph: NormalizedGraph | None = None,
    findings: list[CryptoFinding] | None = None,
    artifacts: dict[str, Path | None] | None = None,
    config_paths: list[Path] | None = None,
) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = run_dir / "manifest.json"
    payload = {
        "run_id": run_dir.name,
        "tool": "CryptoGraph",
        "generated_at": datetime.now(UTC).isoformat(),
        "command": command,
        "source": str(source),
        "backend": backend,
        "artifacts": {
            name: str(path) for name, path in (artifacts or {}).items() if path is not None
        },
        "graph": _graph_summary(graph),
        "findings": _finding_summary(findings or []),
        "config": [_file_fingerprint(path) for path in config_paths or []],
    }
    write_json(manifest_path, payload)
    return manifest_path


def _graph_summary(graph: NormalizedGraph | None) -> dict:
    if graph is None:
        return {"available": False}
    return {
        "available": True,
        "backend": graph.backend,
        "root": graph.root,
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "node_kinds": _count(node.kind for node in graph.nodes),
        "edge_kinds": _count(edge.kind for edge in graph.edges),
    }


def _finding_summary(findings: list[CryptoFinding]) -> dict:
    return {
        "total": len(findings),
        "by_risk": _count(finding.risk for finding in findings),
        "by_algorithm": _count(finding.algorithm for finding in findings),
        "by_primitive": _count(finding.primitive for finding in findings),
    }


def _file_fingerprint(path: Path) -> dict:
    data = path.read_bytes()
    return {
        "path": str(path),
        "sha256": sha256(data).hexdigest(),
        "bytes": len(data),
    }


def _count(values) -> dict[str, int]:
    result: dict[str, int] = {}
    for value in values:
        key = str(value or "unknown")
        result[key] = result.get(key, 0) + 1
    return result
