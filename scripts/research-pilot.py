"""Capture Python key-origin observations; this is not an accuracy benchmark."""
from __future__ import annotations

import argparse
import hashlib
import platform
import subprocess
import sys
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

from cryptograph.cbom_builder_v2 import build_cbom
from cryptograph.context_extractor import enrich_context
from cryptograph.cpg_loader import CpgLoadError, load_graph
from cryptograph.cpg_visualizer import write_graph_json
from cryptograph.crypto_matcher_v2 import find_crypto_calls
from cryptograph.utils import load_json, project_path, write_json


ROOT = Path(__file__).resolve().parents[1]


def git_value(*arguments: str) -> str | None:
    try:
        return subprocess.check_output(
            ["git", *arguments], cwd=ROOT, text=True, stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=["ast-lite", "fraunhofer-strict"], required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    out = args.out_dir.resolve()
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        parser.error(f"Use a new or empty output directory: {out}")
    out.mkdir(parents=True, exist_ok=True)

    source = ROOT / "research" / "python-key-origin" / "cases"
    definition = source.parent / "cases.json"
    manifest = load_json(definition)
    mappings = project_path("config", "api_mappings.json")
    rules = project_path("config", "rules_v2.json")
    inputs = sorted([
        definition, *source.glob("*.py"), mappings, rules,
        project_path("config", "source_sinks.json"),
        *ROOT.joinpath("src", "cryptograph").glob("*.py"),
        Path(__file__).resolve(), ROOT / "pyproject.toml",
    ])
    dirty = git_value("status", "--porcelain", "--untracked-files=normal")
    record = {
        "kind": "feasibility_observation_not_benchmark",
        "generated_at": datetime.now(UTC).isoformat(),
        "annotation_status": manifest["annotation_status"],
        "revision": git_value("rev-parse", "HEAD"),
        "working_tree_dirty": bool(dirty) if dirty is not None else None,
        "python": sys.version,
        "platform": platform.platform(),
        "dependencies": {name: version(name) for name in ("cryptograph", "networkx", "pydantic")},
        "requested_backend": args.backend,
        "inputs_sha256": {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs},
        "status": "started",
    }
    write_json(out / "run.json", record)
    try:
        graph = load_graph(source, args.backend)
    except CpgLoadError as exc:
        record.update(status="failed", error=str(exc))
        write_json(out / "run.json", record)
        print(str(exc), file=sys.stderr)
        return 2

    findings = enrich_context(find_crypto_calls(graph, mappings, rules), graph)
    cbom = build_cbom(findings, str(source), graph.backend, graph=graph, rules_config=load_json(rules))
    write_json(out / "cbom.json", cbom)
    write_graph_json(graph, out / "graph.json")
    observations = []
    for case in manifest["cases"]:
        matches = [
            asset for asset in cbom["cryptographic_assets"]
            if Path(asset["context"]["file"]).name == case["file"]
            and asset["evidence"]["summary"]["api_call"] == case["target_api"]
        ]
        observations.append({
            "case_id": case["id"],
            "target_count": len(matches),
            "review_question": case["review_question"],
            "observed": [{
                "line": asset["context"]["line"],
                "key_source": asset["flow"]["key_source"],
                "variable_flows": asset["flow"].get("variable_flows", []),
                "argument_signals": asset["evidence"]["debug"]["argument_signals"],
            } for asset in matches],
        })
    write_json(out / "observations.json", {"annotation_status": manifest["annotation_status"], "cases": observations})
    record.update(status="completed", actual_backend=graph.backend, nodes=len(graph.nodes), edges=len(graph.edges))
    write_json(out / "run.json", record)
    for observation in observations:
        values = [item["key_source"] for item in observation["observed"]]
        print(f"{observation['case_id']}: {values}")
    print("Provisional, author-designed cases: no accuracy or novelty conclusion is implied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
