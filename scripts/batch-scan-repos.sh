#!/bin/bash
# Batch scan multiple repositories
# Usage: bash scripts/batch-scan-repos.sh [REPOS_FILE]
# 
# REPOS_FILE format (one repo per line):
#   https://github.com/user1/repo1.git
#   https://github.com/user2/repo2.git
#   /path/to/local/repo
# 
# Output: results/batch-scan-TIMESTAMP/

set -e

REPOS_FILE="${1:-repos.txt}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BATCH_DIR="./results/batch-scan-$TIMESTAMP"

if [ ! -f "$REPOS_FILE" ]; then
    echo "Error: repos file not found: $REPOS_FILE"
    echo ""
    echo "Usage: bash scripts/batch-scan-repos.sh [REPOS_FILE]"
    echo ""
    echo "Example repos.txt:"
    echo "  https://github.com/nodejs/node.git"
    echo "  https://github.com/expressjs/express.git"
    echo "  /path/to/local/repo"
    exit 1
fi

mkdir -p "$BATCH_DIR"

echo "=========================================="
echo "CryptoGraph Batch Repository Scanner"
echo "=========================================="
echo "Batch Directory: $BATCH_DIR"
echo "Repos File: $REPOS_FILE"
echo ""

# Read repos and scan each
line_num=0
total_repos=$(wc -l < "$REPOS_FILE")
while read -r repo; do
    line_num=$((line_num + 1))
    
    # Skip empty lines and comments
    [[ -z "$repo" || "$repo" =~ ^# ]] && continue
    
    echo ""
    echo "[$line_num/$total_repos] Scanning: $repo"
    
    # Sanitize repo name for output directory
    if [[ "$repo" == *"git"* ]]; then
        # Extract last part of git URL (user/repo.git -> repo)
        repo_name=$(basename "$repo" .git)
    else
        # Local path
        repo_name=$(basename "$repo")
    fi
    
    scan_dir="$BATCH_DIR/$repo_name"
    mkdir -p "$scan_dir"
    
    # Run scan with error handling
    if python -m cryptograph.main scan-repo \
        --repo "$repo" \
        --out-dir "$scan_dir" \
        --backend fraunhofer 2>&1 | tee "$scan_dir/scan.log"; then
        
        echo "✓ Scan successful: $scan_dir"
        
        # Quick stats
        if [ -f "$scan_dir/dataset.jsonl" ]; then
            count=$(wc -l < "$scan_dir/dataset.jsonl")
            echo "  Crypto assets found: $count"
        fi
    else
        echo "✗ Scan failed for $repo (see $scan_dir/scan.log)"
    fi
done < "$REPOS_FILE"

echo ""
echo "=========================================="
echo "Batch scan complete!"
echo "Results in: $BATCH_DIR"
echo ""
echo "Summary:"
find "$BATCH_DIR" -name "dataset.jsonl" -exec bash -c '
    repo=$(dirname {})
    count=$(wc -l < {} || echo 0)
    echo "  $(basename $repo): $count assets"
' \;

echo ""
echo "Next steps:"
echo "1. Merge all datasets:"
echo "   cat $BATCH_DIR/*/dataset.jsonl > $BATCH_DIR/merged-dataset.jsonl"
echo "2. Feed to LLM:"
echo "   python scripts/llm-label-cbom.py --input $BATCH_DIR/merged-dataset.jsonl"
echo "=========================================="
