"""Observe a pinned PQCensus checkout on shared call sites; no key-origin score."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from cryptograph.utils import load_json, write_json

ROOT = Path(__file__).resolve().parents[1]
REVISION = "535d56f15fa9fa83ce3ea46faf0c2ad19291fcd8"
WORKER = """
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / 'src'))
from pqcensus import audit
result = audit(Path(sys.argv[2]))
Path(sys.argv[3]).write_text(json.dumps(result.to_dict(), indent=2) + '\\n', encoding='utf-8')
"""


def matches_target(finding, target):
    """Pinned PQCensus and Python AST both use zero-based byte columns."""
    location = finding["source"]
    span = location["span"]
    return (location["path"] == target["file"]
            and span["start_line"] == target["line"] and span["start_column"] == target["column"]
            and span.get("end_line") == target["end_line"] and span.get("end_column") == target["end_column"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    checkout, out = args.checkout.resolve(), args.out_dir.resolve()
    revision = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(["git", "-C", str(checkout), "status", "--porcelain"], text=True).strip()
    if revision != REVISION or dirty:
        parser.error("Use an unmodified checkout at the documented PQCensus commit.")
    if out.exists():
        parser.error("Use a fresh output directory.")
    out.mkdir(parents=True)
    corpus = ROOT / "research/python-key-origin"
    source = corpus / "cases"
    packet = load_json(corpus / "review-template.json")
    record = {"status": "started", "tool": "PQCensus", "repository": "https://github.com/XiantingWu/PQCensus",
              "revision": revision, "license": "Apache-2.0", "python": sys.version,
              "scope": "Shared-site detection observation only; purpose evidence is not ultimate key-origin evidence.",
              "source_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(source.glob("*.py"))},
              "adapter_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "license_sha256": hashlib.sha256((checkout / "LICENSE").read_bytes()).hexdigest()}
    write_json(out / "run.json", record)
    control = out / "positive-control"
    control.mkdir()
    control_source = 'import hashlib\nfrom cryptography.hazmat.primitives.asymmetric import rsa\nhashlib.sha256(b"control")\nrsa.generate_private_key(public_exponent=65537, key_size=2048)\n'
    (control / "control.py").write_bytes(control_source.encode())
    with (out / "control.log").open("w", encoding="utf-8") as log:
        check = subprocess.run([sys.executable, "-I", "-c", WORKER, str(checkout), str(control), str(out / "raw-control.json")],
                               cwd=out, stdout=log, stderr=subprocess.STDOUT)
    control_result = load_json(out / "raw-control.json") if check.returncode == 0 else {}
    control_lines = {item["source"]["span"]["start_line"] for item in control_result.get("findings", [])}
    record["positive_control"] = {"source_sha256": hashlib.sha256(control_source.encode()).hexdigest(),
                                  "expected_call_lines": [3, 4], "observed_call_lines": sorted(control_lines)}
    if check.returncode or control_result.get("parser_errors") or not {3, 4} <= control_lines:
        record.update(status="failed_positive_control", returncode=check.returncode)
        write_json(out / "run.json", record)
        return 3
    with (out / "tool.log").open("w", encoding="utf-8") as log:
        run = subprocess.run([sys.executable, "-I", "-c", WORKER, str(checkout), str(source), str(out / "raw-audit.json")],
                             cwd=out, stdout=log, stderr=subprocess.STDOUT)
    if run.returncode:
        record.update(status="failed", returncode=run.returncode)
        write_json(out / "run.json", record)
        return run.returncode
    raw = load_json(out / "raw-audit.json")
    # The pinned Python analyzer copies Python AST zero-based byte columns.
    # Match complete source spans, never just a nearby line or algorithm name.
    rows = []
    matched_ids = set()
    for entry in packet["cases"]:
        if record["source_sha256"][Path(entry["source"]).name] != entry["source_sha256"]:
            raise ValueError("Source snapshot differs from candidate inventory")
        target = entry["target"]
        matches = []
        for finding in raw["findings"]:
            if matches_target(finding, target):
                matches.append(finding)
                matched_ids.add(finding["finding_id"])
        rows.append({"case_id": entry["case_id"], "target": target,
                     "matched_findings": [{"finding_id": item["finding_id"], "algorithm": item["algorithm"],
                                           "purpose": item["purpose"], "analyzer": item["analyzer"]} for item in matches],
                     "key_origin_comparability": "not_exposed_in_pinned_finding_contract"})
    result = {"status": "development_detection_observation", "eligible_sites": len(rows),
              "sites_with_findings": sum(bool(row["matched_findings"]) for row in rows),
              "raw_finding_count": len(raw["findings"]),
              "unmatched_findings": len({item["finding_id"] for item in raw["findings"]} - matched_ids),
              "parser_errors": raw["parser_errors"], "scan_summary": raw["summary"], "limits": raw["limits"],
              "key_origin_score": None,
              "scope": "Unmatched findings may be other valid crypto sites; this inventory does not label detection false positives.",
              "cases": rows}
    write_json(out / "shared-sites.json", result)
    record.update(status="completed" if not raw["parser_errors"] else "completed_with_parser_errors")
    write_json(out / "run.json", record)
    print(f"PQCensus: {result['sites_with_findings']}/{len(rows)} declared sites have source-span matches; key-origin score is undefined.")
    return 0 if not raw["parser_errors"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
