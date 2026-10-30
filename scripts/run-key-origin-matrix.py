"""Run matched development cells; optional provisional agreement is never accuracy."""
from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

from cryptograph.utils import load_json, write_json


ROOT = Path(__file__).resolve().parents[1]
CELLS = (("direct_expression", "ast-lite", "none", "direct"),
         ("source_only", "ast-lite", "none", "both"),
         ("ast_calls", "ast-lite", "graph", "both"),
         ("cpg_calls", "fraunhofer-strict", "graph", "both"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--provisional-proposals", type=Path,
                        help="Opt in to development agreement using explicitly unreviewed proposals.")
    parser.add_argument('--dfg-probe', action='store_true', help='Record separate DFG path observations in the CPG cell.')
    args = parser.parse_args()
    out = args.out_dir.resolve()
    if out.exists():
        parser.error("Use a new output directory to preserve prior experiment snapshots.")
    out.mkdir(parents=True)
    packet = ROOT / "research/python-key-origin/review-template.json"
    summary = {"status": "started", "scope": "Development observations only; no independent accuracy or CPG superiority claim.",
               "provisional_reference_checks": bool(args.provisional_proposals), "cells": {}}
    write_json(out / "matrix.json", summary)
    source_snapshots = []
    candidate_snapshots = []
    reference_snapshots = []
    for name, backend, context, policy in CELLS:
        cell = out / name
        command = [sys.executable, str(ROOT / "scripts/research-pilot.py"), "--backend", backend,
                   "--context-evidence", context, "--policy", policy, "--check-pilot", "--out-dir", str(cell)]
        if args.dfg_probe and backend == 'fraunhofer-strict':
            command.append('--dfg-probe')
        with (out / (name + ".log")).open("w", encoding="utf-8") as log:
            run = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        if run.returncode:
            summary.update(status="failed", failed_cell=name, returncode=run.returncode)
            write_json(out / "matrix.json", summary)
            print(f"Cell {name} failed; see {out / (name + '.log')}", file=sys.stderr)
            return run.returncode
        record = load_json(cell / "run.json")
        observations = load_json(cell / "observations.json")
        source_snapshots.append(record["inputs_sha256"])
        candidate_snapshots.append({entry["case_id"]: entry["eligible_target"] for entry in observations["cases"]})
        claims = [item["claim"] for entry in observations["cases"] for item in entry["evidence_policy"]]
        details = {"requested_backend": backend, "actual_backend": record["actual_backend"], "context_evidence": context, "policy": policy,
                   "export_metadata": record['export_metadata'], "exporter_sha256": record['exporter_sha256'],
                   "eligible_sites": len(observations["cases"]),
                   "resolved": sum(claim["status"] == "resolved" for claim in claims),
                   "partial": sum(claim["status"] == "partial" for claim in claims),
                   "abstained": sum(claim["status"] == "abstained" for claim in claims),
                   "claims_using_calls": sum("CALLS" in claim["graph_features_used"] for claim in claims),
                   "legacy_sites_with_exactly_one_match": sum(entry["target_count"] == 1 for entry in observations["cases"]),
                   "legacy_sites_without_match": sum(entry["target_count"] == 0 for entry in observations["cases"]),
                   "legacy_sites_with_multiple_matches": sum(entry["target_count"] > 1 for entry in observations["cases"])}
        if args.provisional_proposals:
            command = [sys.executable, str(ROOT / "scripts/score-key-origin.py"), "--annotations", str(packet),
                       "--observations", str(cell / "observations.json"), "--output", str(cell / "provisional-agreement.json"),
                       "--provisional-proposals", str(args.provisional_proposals.resolve())]
            with (out / (name + "-provisional.log")).open("w", encoding="utf-8") as log:
                score = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
            if score.returncode:
                summary.update(status="failed", failed_cell=name, returncode=score.returncode, stage="provisional_agreement")
                write_json(out / "matrix.json", summary)
                return score.returncode
            diagnostics = load_json(cell / "provisional-agreement.json")
            details["provisional_agreement"] = diagnostics["by_split"]["development"]
            details["provisional_inputs_sha256"] = diagnostics["inputs_sha256"]
            reference_snapshots.append({key: diagnostics["inputs_sha256"][key] for key in ("annotations", "provisional_proposals")})
        summary["cells"][name] = details
        write_json(out / "matrix.json", summary)
        print(f"{name}: {details['resolved']} resolved, {details['partial']} partial, {details['abstained']} abstained", flush=True)
    if (any(snapshot != source_snapshots[0] for snapshot in source_snapshots[1:])
        or any(snapshot != candidate_snapshots[0] for snapshot in candidate_snapshots[1:])
        or any(snapshot != reference_snapshots[0] for snapshot in reference_snapshots[1:])):
        summary.update(status="failed", error="Source/config/code hashes or eligible candidate sites differ across cells")
        write_json(out / "matrix.json", summary)
        return 3
    summary.update(status="completed", matched_input_hashes=True, matched_candidate_sites=True,
                   matched_provisional_reference_snapshots=True if reference_snapshots else None,
                   matrix_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   inputs_sha256=source_snapshots[0])
    write_json(out / "matrix.json", summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
