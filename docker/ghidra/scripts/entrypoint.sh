#!/usr/bin/env bash
# BinShield Ghidra Headless Entrypoint
#
# Usage:
#   entrypoint.sh <binary_path> <output_path>
#
# The script runs Ghidra analyzeHeadless with the decompile.py postScript,
# writes JSON results to <output_path>, and cleans up temporary project files.

set -euo pipefail

GHIDRA_HOME="${GHIDRA_INSTALL_DIR:-/opt/ghidra}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="${GHIDRA_PROJECT_DIR:-/work/projects}"

BINARY_PATH="${1:-}"
OUTPUT_PATH="${2:-}"

if [[ -z "$BINARY_PATH" ]]; then
  echo "ERROR: binary path is required as the first argument" >&2
  exit 1
fi

if [[ ! -f "$BINARY_PATH" ]]; then
  echo "ERROR: binary file not found: $BINARY_PATH" >&2
  exit 1
fi

if [[ -z "$OUTPUT_PATH" ]]; then
  echo "ERROR: output path is required as the second argument" >&2
  exit 1
fi

# Create a unique project name to avoid collisions in concurrent runs
PROJECT_NAME="binshield_$(date +%s)_$$"
PROJECT_LOC="${PROJECT_DIR}/${PROJECT_NAME}"
mkdir -p "$PROJECT_LOC"

# Export the output path so the Jython script can pick it up
export BINSHIELD_OUTPUT="$OUTPUT_PATH"

cleanup() {
  rm -rf "${PROJECT_LOC}" 2>/dev/null || true
}
trap cleanup EXIT

echo "BinShield: analyzing $BINARY_PATH" >&2
echo "BinShield: project=$PROJECT_NAME output=$OUTPUT_PATH" >&2

# Run Ghidra headless analysis
"${GHIDRA_HOME}/support/analyzeHeadless" \
  "$PROJECT_LOC" "$PROJECT_NAME" \
  -import "$BINARY_PATH" \
  -postScript "$SCRIPT_DIR/decompile.py" \
  -scriptlog "${PROJECT_LOC}/script.log" \
  -deleteProject \
  -noanalysis false \
  2>&1 | while IFS= read -r line; do
    # Forward Ghidra output to stderr for debugging, suppress noisy lines
    case "$line" in
      *"INFO  "*|*"WARN  "*)
        echo "$line" >&2
        ;;
      *"BINSHIELD_RESULT_WRITTEN:"*)
        echo "$line" >&2
        ;;
    esac
  done

# Verify the output was written
if [[ ! -f "$OUTPUT_PATH" ]]; then
  echo "ERROR: Ghidra analysis did not produce output at $OUTPUT_PATH" >&2
  exit 2
fi

echo "BinShield: analysis complete -> $OUTPUT_PATH" >&2
exit 0
