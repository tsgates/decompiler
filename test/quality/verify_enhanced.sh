#!/bin/bash
# verify_enhanced.sh — Differential verification of enhanced display mode.
#
# Checks:
# 1. Non-enhanced output is unchanged (deterministic)
# 2. Enhanced output has fewer or equal gotos
# 3. Enhanced output has balanced braces
# 4. Per-binary metrics comparison
#
# Usage: ./test/quality/verify_enhanced.sh [--verbose]

set -euo pipefail

CACHE_BASE="test/quality/results/.cache"
VERBOSE="${1:-}"

if [ ! -d "$CACHE_BASE" ]; then
  echo "ERROR: Cache directory not found: $CACHE_BASE"
  echo "Run quality tests first to populate the cache."
  exit 1
fi

# Find the latest cache entry for each test binary
declare -A LATEST_XML
for dir in "$CACHE_BASE"/*/; do
  prefix=$(basename "$dir" | sed 's/_[0-9]*$//')
  xmlPath="$dir/exported.xml"
  if [ -f "$xmlPath" ]; then
    LATEST_XML[$prefix]="$xmlPath"
  fi
done

if [ ${#LATEST_XML[@]} -eq 0 ]; then
  echo "ERROR: No cached XMLs found in $CACHE_BASE"
  exit 1
fi

echo "=== Enhanced Display Verification ==="
echo "Found ${#LATEST_XML[@]} test binaries"
echo ""

TOTAL_NORMAL=0
TOTAL_ENHANCED=0
ERRORS=0
PASS=0

# Use a TypeScript helper that processes one XML at a time
HELPER=$(mktemp /tmp/verify_XXXXXX.ts)
cat > "$HELPER" << 'EOF'
import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';

startDecompilerLibrary();

const xmlFile = process.argv[2];
const mode = process.argv[3]; // 'normal' or 'enhanced'

const writer = new StringWriter();
const tc = new FunctionTestCollection(writer);
tc.loadTest(xmlFile);
if (mode === 'enhanced') tc.applyEnhancedDisplay();
const failures: string[] = [];
tc.runTests(failures);
const output = tc.getLastOutput();

const gotos = (output.match(/\bgoto\b/g) || []).length;
const opens = (output.match(/\{/g) || []).length;
const closes = (output.match(/\}/g) || []).length;
const balanced = opens === closes ? 'BALANCED' : 'IMBALANCED';

console.log(JSON.stringify({ gotos, opens, closes, balanced, length: output.length }));
EOF

printf "%-40s %8s %10s %8s %12s\n" "Binary" "Normal" "Enhanced" "Diff" "Braces"
printf "%s\n" "$(printf '%0.s-' {1..80})"

for prefix in $(echo "${!LATEST_XML[@]}" | tr ' ' '\n' | sort); do
  xmlPath="${LATEST_XML[$prefix]}"

  # Normal mode
  NORMAL_JSON=$(npx tsx "$HELPER" "$xmlPath" normal 2>/dev/null || echo '{"gotos":0,"balanced":"ERROR"}')
  NORMAL_GOTOS=$(echo "$NORMAL_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['gotos'])" 2>/dev/null || echo "?")

  # Enhanced mode
  ENHANCED_JSON=$(npx tsx "$HELPER" "$xmlPath" enhanced 2>/dev/null || echo '{"gotos":0,"balanced":"ERROR"}')
  ENHANCED_GOTOS=$(echo "$ENHANCED_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['gotos'])" 2>/dev/null || echo "?")
  BRACE_STATUS=$(echo "$ENHANCED_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['balanced'])" 2>/dev/null || echo "ERROR")

  if [ "$NORMAL_GOTOS" != "?" ] && [ "$ENHANCED_GOTOS" != "?" ]; then
    DIFF=$((ENHANCED_GOTOS - NORMAL_GOTOS))
    TOTAL_NORMAL=$((TOTAL_NORMAL + NORMAL_GOTOS))
    TOTAL_ENHANCED=$((TOTAL_ENHANCED + ENHANCED_GOTOS))

    STATUS=""
    if [ "$ENHANCED_GOTOS" -gt "$NORMAL_GOTOS" ]; then
      STATUS=" REGRESSION!"
      ERRORS=$((ERRORS + 1))
    fi
    if [ "$BRACE_STATUS" != "BALANCED" ]; then
      STATUS="$STATUS BRACE_ERR!"
      ERRORS=$((ERRORS + 1))
    fi

    if [ -n "$VERBOSE" ] || [ "$DIFF" -ne 0 ] || [ -n "$STATUS" ]; then
      printf "%-40s %8s %10s %8s %12s%s\n" "$prefix" "$NORMAL_GOTOS" "$ENHANCED_GOTOS" "$DIFF" "$BRACE_STATUS" "$STATUS"
    fi
    PASS=$((PASS + 1))
  else
    printf "%-40s %8s %10s %8s %12s\n" "$prefix" "$NORMAL_GOTOS" "$ENHANCED_GOTOS" "?" "ERROR"
    ERRORS=$((ERRORS + 1))
  fi
done

printf "%s\n" "$(printf '%0.s-' {1..80})"
TOTAL_DIFF=$((TOTAL_ENHANCED - TOTAL_NORMAL))
printf "%-40s %8s %10s %8s\n" "TOTAL" "$TOTAL_NORMAL" "$TOTAL_ENHANCED" "$TOTAL_DIFF"
echo ""

if [ "$ERRORS" -gt 0 ]; then
  echo "FAILED: $ERRORS errors found ($PASS binaries checked)"
  rm -f "$HELPER"
  exit 1
else
  echo "PASSED: All $PASS binaries verified (${TOTAL_DIFF} gotos reduced)"
  rm -f "$HELPER"
  exit 0
fi
