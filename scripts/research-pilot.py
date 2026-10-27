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
from cryptograph.key_origin import MODEL, analyze_key_origins, audit_claim_structure
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
    parser.add_argument("--policy", choices=["existing", "evidence", "both"], default="both")
    parser.add_argument("--check-pilot", action="store_true", help="Require one target and structurally checked evidence for each development case.")
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
        "requested_policy": args.policy,
        "evidence_analysis_model": MODEL,
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
    claims_by_file = {}
    if args.policy != "existing":
        for path in sorted(source.glob("*.py")):
            claims_by_file[path.name] = analyze_key_origins(path, graph)
        write_json(out / "key-origin-claims.json", {
            "analysis_model": MODEL,
            "claims": [claim.model_dump() for claims in claims_by_file.values() for claim in claims],
        })
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
            } for asset in matches] if args.policy != "evidence" else [],
            "evidence_policy": [{
                "claim": claim.model_dump(),
                "structural_errors": audit_claim_structure(claim, source / case["file"], graph),
            } for claim in claims_by_file.get(case["file"], [])],
        })
    write_json(out / "observations.json", {
        "annotation_status": manifest["annotation_status"], "policy": args.policy,
        "analysis_model": MODEL, "cases": observations,
    })
    checks = []
    if args.check_pilot:
        for observation in observations:
            if observation["target_count"] != 1:
                checks.append(f"{observation['case_id']}: expected exactly one legacy target")
            if args.policy != "existing" and (len(observation["evidence_policy"]) != 1 or any(item["structural_errors"] for item in observation["evidence_policy"])):
                checks.append(f"{observation['case_id']}: missing/ambiguous claim or structural error")
    if checks:
        record.update(status="failed", validation_errors=checks)
        write_json(out / "run.json", record)
        print("; ".join(checks), file=sys.stderr)
        return 3
    record.update(status="completed", actual_backend=graph.backend, nodes=len(graph.nodes), edges=len(graph.edges))
    write_json(out / "run.json", record)
    for observation in observations:
        values = [item["key_source"] for item in observation["observed"]]
        print(f"{observation['case_id']}: {values}")
        for item in observation["evidence_policy"]:
            claim = item["claim"]
            print(f"  evidence: {claim['status']} {claim['origins']} ({claim['modality']}); structural errors={item['structural_errors']}")
    print("Provisional, author-designed cases: no accuracy or novelty conclusion is implied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
