#!/usr/bin/env bash
#
# Compare C++ and TypeScript decompiler output on a real binary.
#
# Usage:
#   scripts/compare.sh /bin/ls
#   scripts/compare.sh /usr/bin/true
#   scripts/compare.sh ./my_binary
#   scripts/compare.sh ./my_binary x86:LE:64:default gcc
#
# Output is saved to: output/compare/<binary-name>/
#   ts_output.c   — full TS decompiled output
#   cpp_output.c  — full C++ decompiled output
#   diffs/        — per-function diff pairs for differing functions
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Locate Ghidra installation ---
find_ghidra_home() {
  if [ -n "${GHIDRA_HOME:-}" ] && [ -d "$GHIDRA_HOME" ]; then
    echo "$GHIDRA_HOME"; return
  fi
  if [ -n "${SLEIGH_PATH:-}" ] && [ -f "$SLEIGH_PATH/support/analyzeHeadless" ]; then
    echo "$SLEIGH_PATH"; return
  fi
  for d in /opt/homebrew/Caskroom/ghidra/*/ghidra_*_PUBLIC /usr/local/Caskroom/ghidra/*/ghidra_*_PUBLIC; do
    if [ -d "$d" ] 2>/dev/null; then echo "$d"; return; fi
  done
  for d in /opt/ghidra /opt/ghidra_* /usr/share/ghidra /usr/local/share/ghidra \
           /snap/ghidra/current "$HOME/ghidra" "$HOME/ghidra_"*; do
    if [ -d "$d" ] && [ -f "$d/support/analyzeHeadless" ] 2>/dev/null; then echo "$d"; return; fi
  done
  local ah; ah=$(command -v analyzeHeadless 2>/dev/null || true)
  if [ -n "$ah" ]; then echo "$(cd "$(dirname "$ah")/.." && pwd)"; return; fi
  return 1
}

GHIDRA_HOME="$(find_ghidra_home)" || {
  echo "Error: Cannot find Ghidra. Set GHIDRA_HOME or SLEIGH_PATH." >&2; exit 1
}
SLEIGH_PATH="${SLEIGH_PATH:-$GHIDRA_HOME}"
WORK_DIR=$(mktemp -d)
trap "rm -rf $WORK_DIR" EXIT

BINARY="$1"
PROCESSOR="${2:-}"
CSPEC="${3:-}"

if [ ! -f "$BINARY" ]; then
  echo "Error: $BINARY not found" >&2
  exit 1
fi

if [ ! -f "$GHIDRA_HOME/support/analyzeHeadless" ]; then
  echo "Error: Ghidra not found at $GHIDRA_HOME" >&2
  echo "Set GHIDRA_HOME to your Ghidra install directory" >&2
  exit 1
fi

# Auto-detect architecture from binary
if [ -z "$PROCESSOR" ]; then
  ARCH=$(file "$BINARY")
  if echo "$ARCH" | grep -q "x86_64\|x86-64"; then
    PROCESSOR="x86:LE:64:default"
    CSPEC="${CSPEC:-gcc}"
  elif echo "$ARCH" | grep -q "arm64\|aarch64"; then
    PROCESSOR="AARCH64:LE:64:v8A"
    CSPEC="${CSPEC:-default}"
  elif echo "$ARCH" | grep -q "x86\|i386\|80386"; then
    PROCESSOR="x86:LE:32:default"
    CSPEC="${CSPEC:-gcc}"
  else
    echo "Error: Cannot auto-detect architecture. Specify manually:" >&2
    echo "  scripts/compare.sh $BINARY <processor> <cspec>" >&2
    echo "  e.g.: scripts/compare.sh $BINARY x86:LE:64:default gcc" >&2
    exit 1
  fi
fi

BINARY_NAME=$(basename "$BINARY")
OUTPUT_DIR="$PROJECT_DIR/output/compare/$BINARY_NAME"
mkdir -p "$OUTPUT_DIR"

echo "=== Comparing decompilers on: $BINARY_NAME ==="
echo "    Architecture: $PROCESSOR / $CSPEC"
echo "    Output dir:   $OUTPUT_DIR"

# Copy export script to work dir
cp "$PROJECT_DIR/scripts/ghidra_export.py" "$WORK_DIR/"

# Step 1: Export via Ghidra headless
echo ""
echo "[1/3] Running Ghidra analysis and export..."
GHIDRA_ARGS="-import $(realpath "$BINARY") -processor $PROCESSOR -cspec $CSPEC"
DECOMP_OUTPUT_DIR="$WORK_DIR" \
  "$GHIDRA_HOME/support/analyzeHeadless" "$WORK_DIR" proj \
  $GHIDRA_ARGS \
  -postScript "$WORK_DIR/ghidra_export.py" \
  -deleteProject \
  2>&1 | grep -E '(Wrote|Error|WARN)' || true

FUNC_COUNT=$(grep -c '<script>' "$WORK_DIR/exported.xml" 2>/dev/null || echo 0)
echo "    Exported $FUNC_COUNT functions"

if [ "$FUNC_COUNT" -eq 0 ]; then
  echo "Error: No functions exported" >&2
  exit 1
fi

# Step 2: Run comparison (saves ts_output.c, cpp_output.c, diffs/ to OUTPUT_DIR)
echo ""
echo "[2/3] Running C++ and TS decompilers..."
cd "$PROJECT_DIR"
SLEIGH_PATH="$SLEIGH_PATH" npx tsx test/run-compare-binary.ts "$WORK_DIR/exported.xml" "$OUTPUT_DIR" 2>&1

echo ""
echo "[3/3] Done."
