"""Local interface for repository scans and deterministic baseline labeling."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path
from uuid import uuid4

import pandas as pd
import streamlit as st


ROOT = Path(__file__).resolve().parents[1]
st.set_page_config(page_title="CryptoGraph Scanner", layout="wide")
st.title("CryptoGraph Repository Scanner")
st.write("Inspect cryptographic operations, context and the evidence available from source code.")

with st.sidebar:
    st.header("Analysis settings")
    backend = st.selectbox("Backend", ["ast-lite", "fraunhofer-strict", "fraunhofer"])
    st.caption("Lite: Python AST and selected Ruby/C/C++ patterns. Other languages need a compatible exporter.")
    workers = st.number_input("Parallel workers", min_value=1, max_value=max(1, os.cpu_count() or 1), value=1)
    timeout = st.number_input("Scan timeout (seconds)", min_value=30, value=3600, step=30)
    st.caption("Findings and confidence are heuristic. Inspect backend identity and unresolved evidence.")

repo = st.text_input("Repository URL or local path", placeholder="./samples")
if st.button("Scan", type="primary"):
    if not repo.strip():
        st.error("Enter a repository URL or local path.")
    else:
        out = ROOT / "output" / "scans" / uuid4().hex
        command = [
            sys.executable, "-X", "utf8", "-m", "cryptograph.main", "scan-repo",
            "--repo", repo.strip(), "--out-dir", str(out), "--backend", backend,
            "--max-workers", str(workers),
        ]
        try:
            with st.spinner("Analyzing repository..."):
                result = subprocess.run(
                    command, cwd=ROOT, capture_output=True, text=True,
                    encoding="utf-8", errors="replace", timeout=int(timeout), check=False,
                )
            st.session_state["scan"] = {
                "out_dir": str(out), "exit_code": result.returncode,
                "log": result.stdout + "\n" + result.stderr,
            }
        except subprocess.TimeoutExpired:
            st.session_state["scan"] = {
                "out_dir": str(out), "exit_code": -1,
                "log": f"Scan timed out after {timeout} seconds; inspect partial artifacts in {out}.",
            }
        except OSError as exc:
            st.error(str(exc))

# Rendering lives outside the scan button so filtering, labeling and downloading
# do not discard results or trigger another repository scan on Streamlit reruns.
scan = st.session_state.get("scan")
if scan:
    out = Path(scan["out_dir"])
    merged_path = out / "merged-cboms.json"
    dataset_path = out / "dataset.jsonl"
    if scan["exit_code"]:
        st.warning(f"Scan incomplete (exit {scan['exit_code']}). Available partial results are shown below.")
    else:
        st.success("Scan jobs completed. Review coverage and evidence before interpreting the findings.")
    with st.expander("Scan log and artifact location"):
        st.code(str(out))
        st.text(scan["log"])

    if merged_path.exists():
        cbom = json.loads(merged_path.read_text(encoding="utf-8"))
        records = cbom.get("cboms", [])
        assets = [asset for record in records for asset in record.get("cryptographic_assets", [])]
        rows = []
        for record in records:
            metadata = record.get("metadata", {})
            for asset in record.get("cryptographic_assets", []):
                risk = asset.get("risk", {})
                rows.append({
                    "Algorithm": asset.get("crypto_metadata", {}).get("algorithm", "unknown"),
                    "Risk": risk.get("level", "unknown") if isinstance(risk, dict) else risk,
                    "Language": metadata.get("detected_language", "unknown"),
                    "Backend": metadata.get("backend", "unknown"),
                    "File": asset.get("context", {}).get("file"),
                    "Line": asset.get("context", {}).get("line"),
                })
        risk_counts = Counter(row["Risk"] for row in rows)
        columns = st.columns(4)
        for column, label, value in zip(
            columns, ["Primary assets", "Critical", "High", "Needs review / medium"],
            [len(assets), risk_counts["critical"], risk_counts["high"], risk_counts["medium"]],
        ):
            column.metric(label, value)
        if cbom.get("errors"):
            st.write("Failed jobs")
            st.json(cbom["errors"])
        if rows:
            selection = st.selectbox("Risk filter", ["all", *sorted(risk_counts)])
            filtered = rows if selection == "all" else [row for row in rows if row["Risk"] == selection]
            st.dataframe(pd.DataFrame(filtered), hide_index=True)
        else:
            st.info("No primary assets were reported. Inspect the log for parsing and backend limitations.")

        st.subheader("Deterministic baseline labels")
        st.caption("No external LLM is called. Baseline risk and PQC labels require review.")
        if dataset_path.exists() and st.button("Generate baseline labels"):
            try:
                result = subprocess.run(
                    [sys.executable, "-X", "utf8", str(ROOT / "scripts" / "llm-label-cbom.py"),
                     "--input", str(dataset_path), "--output", str(out / "baseline.jsonl"),
                     "--llm-api", "simulate"],
                    cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=300, check=False,
                )
                if result.returncode:
                    st.error(result.stderr or result.stdout)
                else:
                    st.success("Baseline labels generated.")
            except (OSError, subprocess.TimeoutExpired) as exc:
                st.error(str(exc))

        st.subheader("Artifacts")
        for name, label, mime in [
            ("merged-cboms.json", "Download CBOM", "application/json"),
            ("dataset.jsonl", "Download dataset", "application/x-ndjson"),
            ("baseline.jsonl", "Download baseline labels", "application/x-ndjson"),
        ]:
            path = out / name
            if path.exists():
                st.download_button(label, path.read_bytes(), file_name=name, mime=mime)
        with st.expander("Raw merged CBOM"):
            st.json(cbom, expanded=False)

st.divider()
st.markdown("[Source and documentation](https://github.com/mathissdupont/CryptoGraph) · "
            "[Issues](https://github.com/mathissdupont/CryptoGraph/issues)")
