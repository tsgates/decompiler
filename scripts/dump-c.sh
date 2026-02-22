#!/usr/bin/env bash
#
# Decompile a single function from a binary and print the C output.
#
# Usage:
#   scripts/dump-c.sh /bin/ls entry
#   scripts/dump-c.sh ./my_binary my_func
#   scripts/dump-c.sh ./my_binary my_func x86:LE:64:default gcc
#
# The Ghidra export is cached under output/cache/<binary-name>/ so subsequent
# invocations with different function names skip the expensive export step.
# Use --fresh to force a re-export.
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

# --- Parse arguments ---
FRESH=0
ARGS=()
for arg in "$@"; do
  if [ "$arg" = "--fresh" ]; then
    FRESH=1
  else
    ARGS+=("$arg")
  fi
done
set -- "${ARGS[@]+"${ARGS[@]}"}"

if [ $# -lt 2 ]; then
  echo "Usage: scripts/dump-c.sh [--fresh] <binary> <function-name> [processor] [cspec]" >&2
  echo "" >&2
  echo "Options:" >&2
  echo "  --fresh    Force re-export (ignore cached Ghidra output)" >&2
  echo "" >&2
  echo "Examples:" >&2
  echo "  scripts/dump-c.sh /bin/ls entry" >&2
  echo "  scripts/dump-c.sh ./a.out my_func" >&2
  echo "  scripts/dump-c.sh ./a.out my_func x86:LE:64:default gcc" >&2
  echo "  scripts/dump-c.sh --fresh /bin/ls entry   # re-export" >&2
  exit 1
fi

BINARY="$1"
FUNC_NAME="$2"
PROCESSOR="${3:-}"
CSPEC="${4:-}"

if [ ! -f "$BINARY" ]; then
  echo "Error: $BINARY not found" >&2
  exit 1
fi

# --- Auto-detect architecture ---
if [ -z "$PROCESSOR" ]; then
  ARCH=$(file "$BINARY")
  if echo "$ARCH" | grep -q "x86_64\|x86-64"; then
    PROCESSOR="x86:LE:64:default"; CSPEC="${CSPEC:-gcc}"
  elif echo "$ARCH" | grep -q "arm64\|aarch64"; then
    PROCESSOR="AARCH64:LE:64:v8A"; CSPEC="${CSPEC:-default}"
  elif echo "$ARCH" | grep -q "x86\|i386\|80386"; then
    PROCESSOR="x86:LE:32:default"; CSPEC="${CSPEC:-gcc}"
  elif echo "$ARCH" | grep -q "ARM"; then
    PROCESSOR="ARM:LE:32:v7"; CSPEC="${CSPEC:-default}"
  elif echo "$ARCH" | grep -q "MIPS"; then
    if echo "$ARCH" | grep -q "64-bit"; then
      PROCESSOR="MIPS:BE:64:default"
    else
      PROCESSOR="MIPS:BE:32:default"
    fi
    CSPEC="${CSPEC:-default}"
  else
    echo "Error: Cannot auto-detect architecture from: $ARCH" >&2
    echo "Specify manually: scripts/dump-c.sh $BINARY $FUNC_NAME <processor> <cspec>" >&2
    exit 1
  fi
fi

# --- Cache key: based on binary realpath + mtime ---
BINARY_REAL="$(realpath "$BINARY")"
BINARY_NAME="$(basename "$BINARY")"
BINARY_MTIME="$(stat -f '%m' "$BINARY_REAL" 2>/dev/null || stat -c '%Y' "$BINARY_REAL" 2>/dev/null)"
CACHE_DIR="$PROJECT_DIR/output/cache/${BINARY_NAME}_${BINARY_MTIME}"
CACHED_XML="$CACHE_DIR/exported.xml"

# --- Step 1: Export via Ghidra (or use cache) ---
if [ "$FRESH" -eq 1 ] || [ ! -f "$CACHED_XML" ]; then
  GHIDRA_HOME="$(find_ghidra_home)" || {
    echo "Error: Cannot find Ghidra installation." >&2
    echo "Set GHIDRA_HOME or SLEIGH_PATH to your Ghidra install directory." >&2
    exit 1
  }

  if [ ! -f "$GHIDRA_HOME/support/analyzeHeadless" ]; then
    echo "Error: analyzeHeadless not found at $GHIDRA_HOME/support/" >&2
    exit 1
  fi

  mkdir -p "$CACHE_DIR"
  WORK_DIR=$(mktemp -d)
  trap "rm -rf $WORK_DIR" EXIT

  cp "$PROJECT_DIR/scripts/ghidra_export.py" "$WORK_DIR/"
  echo "Exporting $BINARY via Ghidra (first time, will be cached)..." >&2
  DECOMP_OUTPUT_DIR="$WORK_DIR" \
    "$GHIDRA_HOME/support/analyzeHeadless" "$WORK_DIR" proj \
    -import "$BINARY_REAL" \
    -processor "$PROCESSOR" -cspec "$CSPEC" \
    -postScript "$WORK_DIR/ghidra_export.py" \
    -deleteProject \
    >/dev/null 2>&1

  if [ ! -f "$WORK_DIR/exported.xml" ]; then
    echo "Error: Ghidra export failed" >&2
    rm -rf "$CACHE_DIR"
    exit 1
  fi

  mv "$WORK_DIR/exported.xml" "$CACHED_XML"
  FUNC_COUNT=$(grep -c '<script>' "$CACHED_XML" 2>/dev/null || echo 0)
  echo "Exported $FUNC_COUNT functions → cached at $CACHE_DIR/" >&2
else
  FUNC_COUNT=$(grep -c '<script>' "$CACHED_XML" 2>/dev/null || echo 0)
  echo "Using cached export ($FUNC_COUNT functions)" >&2
fi

# --- Step 2: Decompile the function ---
SLEIGH_PATH="${SLEIGH_PATH:-${GHIDRA_HOME:-}}"
if [ -z "$SLEIGH_PATH" ]; then
  SLEIGH_PATH="$(find_ghidra_home)" || {
    echo "Error: Cannot find SLEIGH_PATH." >&2; exit 1
  }
fi

echo "Decompiling '$FUNC_NAME'..." >&2
cd "$PROJECT_DIR"
SLEIGH_PATH="$SLEIGH_PATH" npx tsx test/decompile-function.ts "$CACHED_XML" "$FUNC_NAME"
