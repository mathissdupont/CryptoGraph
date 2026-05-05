import streamlit as st
import subprocess
import json
import os
from pathlib import Path
from datetime import datetime
import pandas as pd

st.set_page_config(page_title="CryptoGraph Scanner", layout="wide", initial_sidebar_state="expanded")

st.title("🔐 CryptoGraph Repository Scanner")
st.markdown("Paste a GitHub repo link and analyze its cryptographic API usage")

# Sidebar
with st.sidebar:
    st.header("⚙️ Settings")
    backend = st.selectbox(
        "Backend",
        ["fraunhofer", "ast-lite", "fraunhofer-strict"],
        help="fraunhofer: Accurate but slower | ast-lite: Fast but basic"
    )
    
    max_workers = st.slider(
        "Parallel Workers",
        min_value=1,
        max_value=(os.cpu_count() or 4) * 2,
        value=max((os.cpu_count() or 4) // 2, 2),
        help="Increase for large repos to scan multiple language-roots in parallel"
    )
    
    build_cpg = st.checkbox("Build Fraunhofer Exporter", value=False)
    auto_label = st.checkbox("Auto-label with LLM", value=True)
    
    st.divider()
    st.markdown("### 📚 About")
    st.info("""
    **CryptoGraph** analyzes repositories for:
    - Insecure crypto patterns
    - Weak algorithms & modes
    - Key size vulnerabilities
    - PRNG misuse
    
    **Supported Languages:**
    Java • JavaScript • Go • C/C++ • Python
    """)

# Main UI
col1, col2 = st.columns([3, 1])

with col1:
    repo_url = st.text_input(
        "GitHub Repository URL",
        placeholder="https://github.com/nodejs/node.git",
        help="Paste any public GitHub repo URL"
    )

with col2:
    scan_button = st.button("🔍 Scan", use_container_width=True, type="primary")

timeout_default = int(os.getenv("CRYPTOGRAPH_SCAN_TIMEOUT_SECONDS", "3600"))
scan_timeout_seconds = st.number_input(
    "Scan timeout (seconds, 0 = unlimited)",
    min_value=0,
    value=timeout_default,
    step=300,
    help="Large C/C++ repos like quickfix can take 1-2 hours with fraunhofer backend. Use 0 for unlimited."
)

if scan_button:
    if not repo_url:
        st.error("Please enter a repository URL")
    else:
        # Create output directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = f"./results/scan_{timestamp}"
        
        st.info(f"📊 Scanning repository...\nOutput: `{out_dir}`")
        
        # Run scan
        with st.spinner("Cloning repository & analyzing code..."):
            try:
                cmd = [
                    "cryptograph", "scan-repo",
                    "--repo", repo_url,
                    "--out-dir", out_dir,
                    "--backend", backend,
                    "--max-workers", str(max_workers)
                ]
                
                if build_cpg:
                    cmd.append("--build-cpg")
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=None if scan_timeout_seconds == 0 else int(scan_timeout_seconds),
                )
                
                if result.returncode != 0:
                    st.error(f"❌ Scan failed:\n{result.stderr}")
                else:
                    st.success("✅ Scan completed!")
                    
                    # Load results
                    merged_cbom_path = Path(out_dir) / "merged-cboms.json"
                    dataset_path = Path(out_dir) / "dataset.jsonl"
                    
                    if merged_cbom_path.exists():
                        with open(merged_cbom_path) as f:
                            cbom = json.load(f)
                        
                        # Display stats
                        st.divider()
                        st.subheader("📈 Scan Results")
                        
                        # Calculate stats
                        total_assets = 0
                        language_counts = {}
                        risk_counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
                        
                        for cbom_item in cbom.get("cboms", []):
                            lang = cbom_item["metadata"]["detected_language"]
                            assets = cbom_item["cryptographic_assets"]
                            
                            total_assets += len(assets)
                            language_counts[lang] = language_counts.get(lang, 0) + len(assets)
                            
                            for asset in assets:
                                risk = asset.get("risk", "info")
                                risk_counts[risk] = risk_counts.get(risk, 0) + 1
                        
                        # Metrics
                        col1, col2, col3, col4 = st.columns(4)
                        col1.metric("🎯 Total Assets", total_assets)
                        col2.metric("🔴 High Risk", risk_counts["high"])
                        col3.metric("🟡 Medium Risk", risk_counts["medium"])
                        col4.metric("🟢 Low Risk", risk_counts["low"])
                        
                        # Language breakdown
                        st.subheader("🗣️ Languages Detected")
                        lang_df = pd.DataFrame(
                            list(language_counts.items()),
                            columns=["Language", "Assets"]
                        ).sort_values("Assets", ascending=False)
                        
                        col1, col2 = st.columns([1, 2])
                        with col1:
                            st.dataframe(lang_df, use_container_width=True, hide_index=True)
                        with col2:
                            st.bar_chart(lang_df.set_index("Language"))
                        
                        # LLM Labeling
                        st.divider()
                        st.subheader("🧠 LLM Labeling")
                        
                        if auto_label and dataset_path.exists():
                            if st.button("📋 Label with LLM", use_container_width=True):
                                with st.spinner("Labeling findings..."):
                                    label_cmd = [
                                        "python", "scripts/llm-label-cbom.py",
                                        "--input", str(dataset_path),
                                        "--output", str(Path(out_dir) / "labeled.jsonl"),
                                        "--llm-api", "simulate"  # Default to simulation
                                    ]
                                    
                                    label_result = subprocess.run(label_cmd, capture_output=True, text=True, timeout=300)
                                    
                                    if label_result.returncode == 0:
                                        st.success("✅ Labeling completed!")
                                        
                                        # Load and display labels
                                        labeled_path = Path(out_dir) / "labeled.jsonl"
                                        if labeled_path.exists():
                                            labels = []
                                            with open(labeled_path) as f:
                                                for line in f:
                                                    labels.append(json.loads(line))
                                            
                                            # Risk distribution
                                            risk_dist = {}
                                            remediation_list = []
                                            
                                            for label in labels:
                                                risk = label["labels"]["risk_level"]
                                                risk_dist[risk] = risk_dist.get(risk, 0) + 1
                                                remediation_list.append(label["labels"]["remediation"])
                                            
                                            col1, col2 = st.columns(2)
                                            
                                            with col1:
                                                st.write("**Risk Distribution (Labeled)**")
                                                risk_df = pd.DataFrame(
                                                    list(risk_dist.items()),
                                                    columns=["Risk Level", "Count"]
                                                )
                                                st.bar_chart(risk_df.set_index("Risk Level"))
                                            
                                            with col2:
                                                st.write("**Top Remediation Suggestions**")
                                                from collections import Counter
                                                top_remediation = Counter(remediation_list).most_common(5)
                                                for i, (rem, count) in enumerate(top_remediation, 1):
                                                    st.markdown(f"{i}. {rem} ({count}x)")
                                            
                                            # Detailed findings
                                            st.subheader("🔍 Detailed Findings")
                                            
                                            # Filter by risk
                                            risk_filter = st.selectbox(
                                                "Filter by Risk Level",
                                                ["all", "critical", "high", "medium", "low", "info"]
                                            )
                                            
                                            filtered = labels
                                            if risk_filter != "all":
                                                filtered = [l for l in labels if l["labels"]["risk_level"] == risk_filter]
                                            
                                            # Display table
                                            display_data = []
                                            for label in filtered[:20]:  # Limit to 20 rows
                                                display_data.append({
                                                    "Asset ID": label["asset_id"][:20] + "...",
                                                    "Algorithm": label["input"]["crypto_metadata"]["algorithm"],
                                                    "Risk": label["labels"]["risk_level"].upper(),
                                                    "Remediation": label["labels"]["remediation"][:50] + "...",
                                                    "PQC Ready": "✅" if label["labels"]["pqc_compatible"] else "❌"
                                                })
                                            
                                            st.dataframe(display_data, use_container_width=True, hide_index=True)
                                    else:
                                        st.error(f"Labeling failed: {label_result.stderr}")
                        else:
                            st.info("💡 Enable 'Auto-label with LLM' to analyze findings with AI")
                        
                        # Raw data section
                        st.divider()
                        st.subheader("📄 Raw Data")
                        
                        tabs = st.tabs(["Merged CBOM", "Dataset"])
                        
                        with tabs[0]:
                            st.json(cbom, expanded=False)
                        
                        with tabs[1]:
                            if dataset_path.exists():
                                with open(dataset_path) as f:
                                    st.text(f.read()[:2000])  # Show first 2000 chars
                        
                        # Export buttons
                        st.divider()
                        st.subheader("💾 Export Results")
                        
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            with open(merged_cbom_path) as f:
                                st.download_button(
                                    "📥 Download CBOM (JSON)",
                                    f.read(),
                                    f"cbom-{timestamp}.json",
                                    "application/json"
                                )
                        
                        with col2:
                            if dataset_path.exists():
                                with open(dataset_path) as f:
                                    st.download_button(
                                        "📥 Download Dataset (JSONL)",
                                        f.read(),
                                        f"dataset-{timestamp}.jsonl",
                                        "text/plain"
                                    )
                        
                        with col3:
                            labeled_path = Path(out_dir) / "labeled.jsonl"
                            if labeled_path.exists():
                                with open(labeled_path) as f:
                                    st.download_button(
                                        "📥 Download Labeled (JSONL)",
                                        f.read(),
                                        f"labeled-{timestamp}.jsonl",
                                        "text/plain"
                                    )
                        
            except subprocess.TimeoutExpired:
                timeout_label = "unlimited" if scan_timeout_seconds == 0 else f"{int(scan_timeout_seconds)} seconds"
                st.error(f"⏱️ Scan timed out after {timeout_label}. Try ast-lite or increase the timeout.")
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")

# Footer
st.divider()
st.markdown("""
---
**CryptoGraph** | Cryptographic API Analysis Tool  
[📖 Documentation](https://github.com/user/cryptograph) | [🐛 Issues](https://github.com/user/cryptograph/issues)
""")
