#!/bin/bash
# Demo: Scan an external GitHub repository with CryptoGraph
# Usage: bash scripts/demo-scan-external-repo.sh [REPO_URL] [OUTPUT_DIR]

set -e

REPO_URL="${1:-https://github.com/nodejs/node.git}"
OUTPUT_DIR="${2:-./results/demo-scan}"

echo "=========================================="
echo "CryptoGraph External Repository Scanner"
echo "=========================================="
echo ""
echo "Repository: $REPO_URL"
echo "Output Dir: $OUTPUT_DIR"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Run scan-repo command
echo "[1/3] Scanning repository..."
python -m cryptograph.main scan-repo \
  --repo "$REPO_URL" \
  --out-dir "$OUTPUT_DIR" \
  --backend fraunhofer

echo ""
echo "[2/3] Scan complete. Artifacts:"
ls -lh "$OUTPUT_DIR"

echo ""
echo "[3/3] Summary:"
echo ""

# Show languages detected
echo "Languages detected:"
python -c "
import json
with open('$OUTPUT_DIR/merged-cboms.json') as f:
    data = json.load(f)
    langs = set()
    for cbom in data.get('cboms', []):
        lang = cbom.get('metadata', {}).get('detected_language')
        if lang:
            langs.add(lang)
            count = len(cbom.get('cryptographic_assets', []))
            print(f'  - {lang}: {count} crypto assets')
"

echo ""
echo "Dataset JSONL entries:"
wc -l "$OUTPUT_DIR/dataset.jsonl" || echo "  0 entries (no crypto APIs detected)"

echo ""
echo "=========================================="
echo "Next steps:"
echo "1. Review merged-cboms.json for detailed findings"
echo "2. Feed dataset.jsonl to LLM for risk assessment:"
echo "   python scripts/llm-label-cbom.py --input $OUTPUT_DIR/dataset.jsonl"
echo "3. Generate HTML report:"
echo "   cryptograph report --input $OUTPUT_DIR/merged-cboms.json --output $OUTPUT_DIR/report.html"
echo "=========================================="
