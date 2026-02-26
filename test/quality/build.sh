#!/usr/bin/env bash
# Build all quality test programs at multiple optimization levels
# Links as executables with a dummy main so Ghidra can analyze them
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
BIN_DIR="$SCRIPT_DIR/bin"

mkdir -p "$BIN_DIR"

CC="${CC:-cc}"
OPTS=("O0" "O1" "O2" "Os")

# Create a dummy main wrapper
MAIN_C=$(mktemp /tmp/main_XXXXXX.c)
cat > "$MAIN_C" << 'EOF'
int main(int argc, char **argv) { return 0; }
EOF

for src in "$SRC_DIR"/*.c; do
    base=$(basename "$src" .c)
    for opt in "${OPTS[@]}"; do
        out="$BIN_DIR/${base}_${opt}"
        echo "Building $base ($opt)..."
        $CC -"$opt" -o "$out" "$src" "$MAIN_C" 2>&1 || echo "  FAILED: $out"
    done
done

rm -f "$MAIN_C"

echo ""
echo "Built $(ls "$BIN_DIR"/* 2>/dev/null | wc -l | tr -d ' ') binaries"
ls -la "$BIN_DIR"/
