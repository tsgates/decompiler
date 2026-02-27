#!/usr/bin/env bash
#
# Decompile a single function from a binary and print the C output.
#
# Usage:
#   scripts/dump-c.sh /bin/ls entry
#   scripts/dump-c.sh ./my_binary my_func
#
# The binary-to-XML export is cached under output/cache/<binary-name>/ so
# subsequent invocations with different function names skip the export step.
# Use --fresh to force a re-export.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Parse arguments ---
FRESH=0
ENHANCE=1
ARGS=()
for arg in "$@"; do
  if [ "$arg" = "--fresh" ]; then
    FRESH=1
  elif [ "$arg" = "--no-enhance" ]; then
    ENHANCE=0
  elif [ "$arg" = "--enhance" ]; then
    ENHANCE=1
  else
    ARGS+=("$arg")
  fi
done
set -- "${ARGS[@]+"${ARGS[@]}"}"

if [ $# -lt 2 ]; then
  echo "Usage: scripts/dump-c.sh [--fresh] <binary> <function-name>" >&2
  echo "" >&2
  echo "Options:" >&2
  echo "  --fresh       Force re-export (ignore cached output)" >&2
  echo "  --no-enhance  Disable enhanced display mode" >&2
  echo "" >&2
  echo "Examples:" >&2
  echo "  scripts/dump-c.sh /bin/ls entry" >&2
  echo "  scripts/dump-c.sh ./a.out my_func" >&2
  echo "  scripts/dump-c.sh --fresh /bin/ls entry   # re-export" >&2
  exit 1
fi

BINARY="$1"
FUNC_NAME="$2"

if [ ! -f "$BINARY" ]; then
  echo "Error: $BINARY not found" >&2
  exit 1
fi

# --- Cache key: based on binary realpath + mtime ---
BINARY_REAL="$(realpath "$BINARY")"
BINARY_NAME="$(basename "$BINARY")"
BINARY_MTIME="$(stat -f '%m' "$BINARY_REAL" 2>/dev/null || stat -c '%Y' "$BINARY_REAL" 2>/dev/null)"
CACHE_DIR="$PROJECT_DIR/output/cache/${BINARY_NAME}_${BINARY_MTIME}"
CACHED_XML="$CACHE_DIR/exported.xml"

# --- Step 1: Export binary to XML (or use cache) ---
if [ "$FRESH" -eq 1 ] || [ ! -f "$CACHED_XML" ]; then
  mkdir -p "$CACHE_DIR"
  echo "Exporting $BINARY (first time, will be cached)..." >&2
  npx tsx "$PROJECT_DIR/src/console/binary_to_xml.ts" "$BINARY_REAL" -o "$CACHED_XML"
  FUNC_COUNT=$(grep -c '<script>' "$CACHED_XML" 2>/dev/null || echo 0)
  echo "Exported $FUNC_COUNT functions → cached at $CACHE_DIR/" >&2
else
  FUNC_COUNT=$(grep -c '<script>' "$CACHED_XML" 2>/dev/null || echo 0)
  echo "Using cached export ($FUNC_COUNT functions)" >&2
fi

# --- Validation ---
FUNC_COUNT=$(grep -c '<script>' "$CACHED_XML" 2>/dev/null || echo 0)
if [ "$FUNC_COUNT" -eq 0 ]; then
  echo "Error: No functions found in binary (no <script> blocks in exported XML)" >&2
  exit 1
fi

# Check if the requested function exists as a symbol
if ! grep -q "name=\"${FUNC_NAME}\"" "$CACHED_XML" 2>/dev/null; then
  echo "Error: Function '$FUNC_NAME' not found in binary." >&2
  echo "Available functions:" >&2
  grep '<symbol' "$CACHED_XML" | sed 's/.*name="\([^"]*\)".*/  \1/' >&2
  exit 1
fi

# --- Step 2: Decompile the function ---
echo "Decompiling '$FUNC_NAME'..." >&2
cd "$PROJECT_DIR"
ENHANCE_FLAG=""
if [ "$ENHANCE" -eq 1 ]; then
  ENHANCE_FLAG="--enhance"
fi
npx tsx test/decompile-function.ts $ENHANCE_FLAG "$CACHED_XML" "$FUNC_NAME"
