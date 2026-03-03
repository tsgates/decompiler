#!/usr/bin/env bash
#
# Benchmark TS vs C++ decompiler on system binaries of varying sizes.
#
# Usage: scripts/benchmark.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

CPP_BIN="ghidra-src/Ghidra/Features/Decompiler/src/decompile/cpp/decomp_test_dbg"
export SLEIGHHOME="${SLEIGHHOME:-/opt/homebrew/Caskroom/ghidra/11.4.2-20250826/ghidra_11.4.2_PUBLIC}"

if [ ! -f "$CPP_BIN" ]; then
  echo "Error: C++ decompiler not found at $CPP_BIN" >&2
  exit 1
fi

if [ ! -d "$SLEIGHHOME" ]; then
  echo "Error: SLEIGHHOME not found at $SLEIGHHOME" >&2
  exit 1
fi

# --- Binaries to benchmark (sorted by size) ---
declare -a BINARIES=(
  "/usr/bin/true"
  "/usr/bin/head"
  "/usr/bin/grep"
  "/usr/bin/awk"
  "/bin/bash"
  "/usr/bin/ssh"
  "/usr/bin/vim"
)

CACHE_DIR="$PROJECT_DIR/output/bench-cache"
RESULTS_FILE="$PROJECT_DIR/output/benchmark-results.tsv"
mkdir -p "$CACHE_DIR"

# --- Header ---
printf "%-20s %8s %6s %10s %10s %10s %10s %8s %8s\n" \
  "Binary" "Size" "Funcs" "TS(s)" "C++(s)" "Ratio" "TS_RSS" "C++_RSS" "MemRatio"
printf "%s\n" "$(printf '=%.0s' {1..110})"

# TSV header
echo -e "Binary\tSize_KB\tFunctions\tTS_Time_s\tCPP_Time_s\tTime_Ratio\tTS_RSS_MB\tCPP_RSS_MB\tMem_Ratio" > "$RESULTS_FILE"

for BINARY in "${BINARIES[@]}"; do
  if [ ! -f "$BINARY" ]; then
    echo "Skipping $BINARY (not found)"
    continue
  fi

  BNAME="$(basename "$BINARY")"
  BSIZE_KB=$(( $(stat -f '%z' "$BINARY") / 1024 ))
  BSIZE_HUMAN=$(ls -lh "$BINARY" | awk '{print $5}')

  # --- Step 1: Export to XML (cached) ---
  BMTIME="$(stat -f '%m' "$BINARY")"
  XML_DIR="$CACHE_DIR/${BNAME}_${BMTIME}"
  XML_FILE="$XML_DIR/exported.xml"

  if [ ! -f "$XML_FILE" ]; then
    mkdir -p "$XML_DIR"
    npx tsx src/console/binary_to_xml.ts "$BINARY" -o "$XML_FILE" 2>/dev/null
  fi

  FUNC_COUNT=$(grep -c '<script>' "$XML_FILE" 2>/dev/null || echo 0)
  if [ "$FUNC_COUNT" -eq 0 ]; then
    printf "%-20s %8s %6d  (no functions)\n" "$BNAME" "$BSIZE_HUMAN" 0
    continue
  fi

  DIR="$(dirname "$XML_FILE")"
  BASE="$(basename "$XML_FILE")"

  # --- Step 2: Run TS decompiler ---
  TS_START=$SECONDS
  TS_OUTPUT=$( /usr/bin/time -l npx tsx test/run-ts-bench.ts "$XML_FILE" 2>&1 ) || true
  TS_WALL=$(echo "$TS_OUTPUT" | grep '^ELAPSED:' | cut -d: -f2)
  TS_RSS=$(echo "$TS_OUTPUT" | grep 'maximum resident set size' | awk '{print $1}')
  TS_RSS=${TS_RSS:-0}
  TS_RSS_MB=$(echo "scale=1; $TS_RSS / 1048576" | bc)

  # --- Step 3: Run C++ decompiler ---
  CPP_OUTPUT=$( /usr/bin/time -l "$CPP_BIN" -usesleighenv -path "$DIR" datatests "$BASE" 2>&1 ) || true
  CPP_WALL=$(echo "$CPP_OUTPUT" | grep 'real' | awk '{print $1}' | head -1)
  # Parse /usr/bin/time output for elapsed seconds
  CPP_ELAPSED=$(echo "$CPP_OUTPUT" | grep 'real' | head -1 | sed 's/[^0-9.]//g')
  if [ -z "$CPP_ELAPSED" ]; then
    # Try user+sys time
    CPP_USER=$(echo "$CPP_OUTPUT" | grep 'user' | head -1 | sed 's/[^0-9.]//g')
    CPP_SYS=$(echo "$CPP_OUTPUT" | grep 'sys' | head -1 | sed 's/[^0-9.]//g')
    CPP_ELAPSED=$(echo "${CPP_USER:-0} + ${CPP_SYS:-0}" | bc)
  fi
  CPP_ELAPSED=${CPP_ELAPSED:-0}
  CPP_RSS=$(echo "$CPP_OUTPUT" | grep 'maximum resident set size' | awk '{print $1}')
  CPP_RSS=${CPP_RSS:-0}
  CPP_RSS_MB=$(echo "scale=1; $CPP_RSS / 1048576" | bc)

  # --- Compute ratios ---
  if [ "$(echo "$CPP_ELAPSED > 0" | bc)" -eq 1 ]; then
    TIME_RATIO=$(echo "scale=1; $TS_WALL / $CPP_ELAPSED" | bc)
  else
    TIME_RATIO="N/A"
  fi

  if [ "$(echo "$CPP_RSS > 0" | bc)" -eq 1 ]; then
    MEM_RATIO=$(echo "scale=1; $TS_RSS / $CPP_RSS" | bc)
  else
    MEM_RATIO="N/A"
  fi

  printf "%-20s %8s %6d %10.2fs %10.2fs %9sx %8sMB %7sMB %7sx\n" \
    "$BNAME" "$BSIZE_HUMAN" "$FUNC_COUNT" "$TS_WALL" "$CPP_ELAPSED" "$TIME_RATIO" "$TS_RSS_MB" "$CPP_RSS_MB" "$MEM_RATIO"

  # TSV row
  echo -e "${BNAME}\t${BSIZE_KB}\t${FUNC_COUNT}\t${TS_WALL}\t${CPP_ELAPSED}\t${TIME_RATIO}\t${TS_RSS_MB}\t${CPP_RSS_MB}\t${MEM_RATIO}" >> "$RESULTS_FILE"
done

echo ""
echo "Results saved to: $RESULTS_FILE"
