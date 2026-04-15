#!/bin/bash
# CryptoGraph Test Runner - Simple Bash Version

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$PROJECT_ROOT/output"
SAMPLES_DIR="$PROJECT_ROOT/samples"

echo "=========================================="
echo "CryptoGraph Test Suite - Fraunhofer Mode"
echo "=========================================="
echo ""
echo "Scanning samples directory..."
echo "  Samples: $SAMPLES_DIR"
echo "  Output: $OUTPUT_DIR"
echo ""

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Run scan with Fraunhofer backend
echo "[STEP 1] Generating CBOM with Fraunhofer CPG backend..."
docker compose run --rm cryptograph scan \
    --input /app/samples \
    --output /app/output/result.json \
    --backend fraunhofer

echo ""
echo "[STEP 2] Generating CPG visualization..."
docker compose run --rm cryptograph graph \
    --input /app/samples \
    --output /app/output/cpg.json \
    --dot /app/output/cpg.dot \
    --html /app/output/cpg.html \
    --backend fraunhofer

echo ""
echo "[STEP 3] Generating HTML report..."
LATEST_RESULT=$(find "$OUTPUT_DIR" -name "result.json" -type f -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2-)

if [ -n "$LATEST_RESULT" ]; then
    LATEST_RESULT_REL="${LATEST_RESULT#$PROJECT_ROOT/}"
    docker compose run --rm cryptograph report \
        --input "/app/$LATEST_RESULT_REL" \
        --output /app/output/report.html
else
    echo "Warning: No result.json found"
fi

echo ""
echo "=========================================="
echo "Test Results"
echo "=========================================="
echo ""

# List output files
echo "Output artifacts:"
find "$OUTPUT_DIR" -type f -name "*.json" -o -name "*.html" -o -name "*.dot" | sort | while read file; do
    size=$(du -h "$file" | cut -f1)
    echo "  [$size] $file"
done

echo ""
echo "Summary:"
if [ -n "$LATEST_RESULT" ] && [ -f "$LATEST_RESULT" ]; then
    finding_count=$(jq '.findings | length' "$LATEST_RESULT" 2>/dev/null || echo "unknown")
    echo "  Total findings: $finding_count"
fi

echo ""
echo "View results:"
REPORT=$(find "$OUTPUT_DIR" -name "report.html" -type f -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2-)
if [ -n "$REPORT" ]; then
    echo "  Report: $REPORT"
fi

CPGHTML=$(find "$OUTPUT_DIR" -name "cpg.html" -type f -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2-)
if [ -n "$CPGHTML" ]; then
    echo "  CPG Graph: $CPGHTML"
fi

echo ""
echo "Test completed successfully!"
