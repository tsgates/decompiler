#!/usr/bin/env bash
# Run decompilation comparison on all quality test binaries.
# Exports each binary via Ghidra and compares TS vs C++ decompiler.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN_DIR="$SCRIPT_DIR/bin"
RESULTS_DIR="$SCRIPT_DIR/results"

GHIDRA_HOME="${GHIDRA_HOME:-}"
CPP_BIN="$PROJECT_DIR/ghidra-src/Ghidra/Features/Decompiler/src/decompile/cpp/decomp_test_dbg"

mkdir -p "$RESULTS_DIR"

# Summary file
SUMMARY="$RESULTS_DIR/summary.txt"
echo "=== Decompilation Quality Analysis ===" > "$SUMMARY"
echo "Date: $(date)" >> "$SUMMARY"
echo "Compiler: $(cc --version 2>&1 | head -1)" >> "$SUMMARY"
echo "Platform: $(uname -m)" >> "$SUMMARY"
echo "" >> "$SUMMARY"
printf "%-35s %5s %5s %6s\n" "Binary" "Funcs" "Match" "Rate" >> "$SUMMARY"
printf "%-35s %5s %5s %6s\n" "---" "---" "---" "---" >> "$SUMMARY"

TOTAL_FUNCS=0
TOTAL_MATCH=0

# Auto-detect arch
ARCH_FILE=$(file "$BIN_DIR"/01_basic_control_O0)
if echo "$ARCH_FILE" | grep -q "arm64\|aarch64"; then
    PROCESSOR="AARCH64:LE:64:v8A"
    CSPEC="default"
elif echo "$ARCH_FILE" | grep -q "x86_64\|x86-64"; then
    PROCESSOR="x86:LE:64:default"
    CSPEC="gcc"
else
    echo "Unknown arch" >&2; exit 1
fi

for bin in "$BIN_DIR"/*; do
    [ -f "$bin" ] || continue
    [ -x "$bin" ] || continue

    name=$(basename "$bin")
    outdir="$RESULTS_DIR/$name"
    mkdir -p "$outdir"

    echo "=== $name ==="

    # Step 1: Export via Ghidra (cached)
    CACHE_KEY="${name}_$(stat -f '%m' "$bin")"
    CACHE_DIR="$RESULTS_DIR/.cache/$CACHE_KEY"
    CACHED_XML="$CACHE_DIR/exported.xml"

    if [ ! -f "$CACHED_XML" ]; then
        mkdir -p "$CACHE_DIR"
        WORK_DIR=$(mktemp -d)
        cp "$PROJECT_DIR/scripts/ghidra_export.py" "$WORK_DIR/"
        DECOMP_OUTPUT_DIR="$WORK_DIR" \
            "$GHIDRA_HOME/support/analyzeHeadless" "$WORK_DIR" proj \
            -import "$(realpath "$bin")" -processor "$PROCESSOR" -cspec "$CSPEC" \
            -postScript "$WORK_DIR/ghidra_export.py" \
            -deleteProject >/dev/null 2>&1 || true
        if [ -f "$WORK_DIR/exported.xml" ]; then
            mv "$WORK_DIR/exported.xml" "$CACHED_XML"
        fi
        rm -rf "$WORK_DIR"
    fi

    if [ ! -f "$CACHED_XML" ]; then
        echo "  SKIP: Ghidra export failed"
        printf "%-35s %5s %5s %6s\n" "$name" "?" "?" "FAIL" >> "$SUMMARY"
        continue
    fi

    # Step 2: Run TS vs C++ comparison
    cd "$PROJECT_DIR"
    result=$(npx tsx test/run-compare-binary.ts "$CACHED_XML" "$outdir" 2>&1) || true
    echo "$result" > "$outdir/comparison.txt"

    # Parse
    funcs=$(echo "$result" | grep "Functions in TS:" | awk '{print $NF}' || echo "0")
    identical_line=$(echo "$result" | grep "Identical:" || echo "")
    if [ -n "$identical_line" ]; then
        match=$(echo "$identical_line" | sed 's|.*: *\([0-9]*\)/.*|\1|')
        rate=$(echo "$identical_line" | grep -o '[0-9.]*%' || echo "?%")
    else
        match="0"
        rate="?%"
    fi

    echo "  $match/$funcs identical ($rate)"
    printf "%-35s %5s %5s %6s\n" "$name" "$funcs" "$match" "$rate" >> "$SUMMARY"

    TOTAL_FUNCS=$((TOTAL_FUNCS + ${funcs:-0}))
    TOTAL_MATCH=$((TOTAL_MATCH + ${match:-0}))
done

echo "" >> "$SUMMARY"
if [ "$TOTAL_FUNCS" -gt 0 ]; then
    PCT=$(echo "scale=1; $TOTAL_MATCH * 100 / $TOTAL_FUNCS" | bc)
    echo "TOTAL: $TOTAL_MATCH/$TOTAL_FUNCS identical ($PCT%)" >> "$SUMMARY"
fi

echo ""
echo "============================================"
cat "$SUMMARY"
echo "============================================"
