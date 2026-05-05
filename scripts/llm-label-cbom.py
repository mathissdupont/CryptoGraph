#!/usr/bin/env python3
"""
LLM Integration: Feed CryptoGraph JSONL dataset to LLM for risk assessment and remediation.

Usage:
  python scripts/llm-label-cbom.py --input results/my-repo/dataset.jsonl --output results/my-repo/labeled.jsonl
  
This script:
1. Loads the JSONL dataset from scan-repo output
2. Formats assets for LLM consumption
3. (Optionally) Calls an LLM API (OpenAI, Claude, local LLM)
4. Writes labeled results to output JSONL
"""

import argparse
import json
from pathlib import Path
from typing import Any

from cryptograph.llm_labeling import simulate_label


def load_dataset(input_file: Path) -> list[dict[str, Any]]:
    """Load either dataset.jsonl rows or merged-cboms.json and normalize rows.

    Returns rows in the dataset format expected by the labeler:
      {"asset_id": ..., "input": {...}, "labels": {}}
    """
    if input_file.suffix.lower() == ".jsonl":
        assets = []
        with input_file.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    assets.append(json.loads(line))
        return assets

    payload = json.loads(input_file.read_text(encoding="utf-8"))
    if isinstance(payload, dict) and isinstance(payload.get("cboms"), list):
        return _rows_from_merged_cboms(payload)
    if isinstance(payload, dict) and isinstance(payload.get("cryptographic_assets"), list):
        return _rows_from_merged_cboms({"cboms": [payload]})
    raise ValueError(f"Unsupported input format: {input_file}")


def _rows_from_merged_cboms(merged: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for cbom in merged.get("cboms", []):
        metadata = cbom.get("metadata", {}) if isinstance(cbom.get("metadata", {}), dict) else {}
        for asset in cbom.get("cryptographic_assets", []):
            rows.append(
                {
                    "asset_id": asset.get("asset_id"),
                    "input": {
                        "metadata": {
                            "detected_language": metadata.get("detected_language"),
                            "backend": metadata.get("backend"),
                            "source": metadata.get("source"),
                            "run_id": metadata.get("run_id"),
                        },
                        "crypto_metadata": asset.get("crypto_metadata"),
                        "usage": asset.get("usage"),
                        "context": asset.get("context"),
                        "flow": asset.get("flow"),
                        "control": asset.get("control"),
                        "graph_context": asset.get("graph_context"),
                        "rules": asset.get("rules"),
                        "evidence_summary": (asset.get("evidence") or {}).get("summary", {}),
                    },
                    "labels": {},
                }
            )
    return rows


def format_for_llm(asset: dict[str, Any]) -> str:
    """Format a single asset for LLM prompt."""
    inp = asset.get("input", {})
    meta = inp.get("metadata", {})
    crypto_meta = inp.get("crypto_metadata", {})
    usage = inp.get("usage", "Unknown usage")
    context = inp.get("context", {})
    rules = inp.get("rules", [])
    
    prompt = f"""Analyze this cryptographic asset for security risks and provide remediation advice.

Asset ID: {asset.get('asset_id')}
Language: {meta.get('detected_language', 'unknown')}
Backend: {meta.get('backend', 'unknown')}
Source: {meta.get('source', 'unknown')}

Algorithm: {crypto_meta.get('algorithm', 'Unknown')}
Primitive: {crypto_meta.get('primitive', 'Unknown')}
Mode: {crypto_meta.get('mode', 'N/A')}
Provider: {crypto_meta.get('provider', 'Unknown')}

Usage Context:
  Location: {context.get('file', 'Unknown')}:{context.get('line', '?')}
  Function: {context.get('function', 'Unknown')}
  Description: {usage}

Applicable Rules (from deterministic layer):
{json.dumps(rules, indent=2) if rules else "  (None)"}

Questions for LLM:
1. What is the risk level of this cryptographic usage? (critical/high/medium/low/info)
2. Why is it at this risk level?
3. What is the recommended remediation?
4. Is this compatible with Post-Quantum Cryptography (PQC) standards?
5. What related references or best practices apply?

Please provide concise, actionable feedback."""
    
    return prompt


def simulate_llm_label(asset: dict[str, Any]) -> dict[str, Any]:
    return simulate_label(asset)


def main():
    parser = argparse.ArgumentParser(
        description="Feed CryptoGraph JSONL dataset to LLM for labeling."
    )
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Input dataset JSONL or merged-cboms.json."
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output JSONL file with labels (default: input with .labeled.jsonl suffix)."
    )
    parser.add_argument(
        "--llm-api",
        choices=["openai", "anthropic", "local", "simulate"],
        default="simulate",
        help="LLM API to use (default: simulate for demo)."
    )
    parser.add_argument(
        "--llm-model",
        default="gpt-4.1",
        help="LLM model name (for API calls)."
    )
    parser.add_argument(
        "--api-key",
        help="LLM API key (from env var LLM_API_KEY if not provided)."
    )
    
    args = parser.parse_args()
    
    # Determine output path
    if args.output:
        output_file = args.output
    else:
        output_file = args.input.with_stem(args.input.stem + ".labeled")
    
    print(f"Loading dataset from {args.input}...")
    assets = load_dataset(args.input)
    print(f"Loaded {len(assets)} assets")
    
    print(f"\nLabeling with {args.llm_api} ({args.llm_model})...")
    
    labeled_count = 0
    with open(output_file, "w") as out_f:
        for i, asset in enumerate(assets):
            if args.llm_api == "simulate":
                # Demo: simple heuristic labeling
                label = simulate_llm_label(asset)
            else:
                # TODO: Implement real LLM API calls
                print(f"Warning: LLM API '{args.llm_api}' not yet implemented. Using simulation.")
                label = simulate_llm_label(asset)
            
            # Add label to asset
            asset["labels"] = label
            
            # Write labeled asset
            out_f.write(json.dumps(asset, ensure_ascii=False) + "\n")
            labeled_count += 1
            
            # Progress feedback
            if (i + 1) % max(1, len(assets) // 10) == 0:
                print(f"  {i + 1}/{len(assets)} assets labeled")
    
    print(f"\n✓ Labeled {labeled_count} assets")
    print(f"✓ Wrote to {output_file}")
    
    # Show sample labels
    print(f"\nSample labeled assets (first 3):")
    with open(output_file) as f:
        for i, line in enumerate(f):
            if i >= 3:
                break
            asset = json.loads(line)
            print(f"\n  Asset {i + 1}:")
            print(f"    Algorithm: {asset.get('input', {}).get('crypto_metadata', {}).get('algorithm')}")
            print(f"    Risk: {asset.get('labels', {}).get('risk_level')}")
            print(f"    Remediation: {asset.get('labels', {}).get('remediation')}")


if __name__ == "__main__":
    main()
