#!/usr/bin/env bash
# Build a Fraunhofer CPG exporter jar suitable for CryptoGraph
# Usage: ./scripts/build_fraunhofer_exporter.sh <clone-dir> [<enabled-languages>]

set -euo pipefail

CLONE_DIR=${1:-/tmp/cpg}
shift || true
ENABLED=${*:-"python,java,go"}

echo "Cloning Fraunhofer CPG into ${CLONE_DIR} (shallow)"
rm -rf "${CLONE_DIR}"
git clone --depth 1 https://github.com/Fraunhofer-AISEC/cpg.git "${CLONE_DIR}"
cd "${CLONE_DIR}"

if [ -f gradle.properties.example ]; then
  cp gradle.properties.example gradle.properties
fi

echo "Enabling languages: ${ENABLED}"
# enabled languages comma separated -> set properties enable<Lang>Frontend=true
IFS="," read -ra LA <<< "${ENABLED}"
for l in "${LA[@]}"; do
  key="enable$(echo ${l} | tr '[:lower:]' '[:upper:]' | sed -E 's/([A-Z]+)/\1/;s/.*/\L&/')Frontend=true"
  # best-effort: append if not present
  if ! grep -q "${l}" gradle.properties; then
    echo "enable${l^}Frontend=true" >> gradle.properties || true
  fi
done

echo "Building CPG (this may take a while)..."
./gradlew assemble --no-daemon

echo "Searching for exporter jar..."
JAR=$(find . -type f -name "*exporter*.jar" -o -name "*cpg*.jar" | head -n 1 || true)
if [ -z "${JAR}" ]; then
  echo "No exporter jar found in build outputs. You may need to locate the correct module or build artifacts manually." >&2
  exit 2
fi

REAL=$(realpath "${JAR}")
echo "Built exporter jar: ${REAL}"
echo
echo "Set environment variable in your shell:"
echo "export CRYPTOGRAPH_FRAUNHOFER_EXPORTER=${REAL}"
echo
exit 0
