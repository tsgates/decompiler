#!/usr/bin/env bash
#
# Update bundled SLEIGH spec files from a Ghidra installation.
#
# Only copies the .sla/.pspec/.cspec files referenced by the trimmed .ldefs.
# The .ldefs files themselves are maintained manually in sleigh/specfiles/
# and are NOT overwritten by this script.
#
# Usage:
#   scripts/update-specfiles.sh                    # auto-detect Ghidra
#   scripts/update-specfiles.sh /path/to/ghidra    # explicit path
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DEST="$PROJECT_DIR/sleigh/specfiles"

# --- Locate Ghidra ---
GHIDRA_HOME="${1:-${GHIDRA_HOME:-}}"
if [ -z "$GHIDRA_HOME" ]; then
  for d in /opt/homebrew/Caskroom/ghidra/*/ghidra_*_PUBLIC /usr/local/Caskroom/ghidra/*/ghidra_*_PUBLIC; do
    if [ -d "$d" ] 2>/dev/null; then GHIDRA_HOME="$d"; break; fi
  done
fi

if [ -z "$GHIDRA_HOME" ] || [ ! -d "$GHIDRA_HOME/Ghidra/Processors" ]; then
  echo "Error: Cannot find Ghidra installation." >&2
  echo "Usage: $0 /path/to/ghidra" >&2
  exit 1
fi

SRC="$GHIDRA_HOME/Ghidra/Processors"
echo "Source: $SRC"
echo "Destination: $DEST"

# --- Copy spec files (excluding .ldefs which are maintained manually) ---
copy_specs() {
  local arch="$1"
  shift
  local srcdir="$SRC/$arch/data/languages"
  local destdir="$DEST/$arch"

  if [ ! -d "$srcdir" ]; then
    echo "  SKIP $arch (not found)"
    return
  fi

  mkdir -p "$destdir"
  local count=0
  for pattern in "$@"; do
    for f in "$srcdir"/$pattern; do
      [ -f "$f" ] || continue
      cp "$f" "$destdir/"
      count=$((count + 1))
    done
  done
  echo "  $arch: $count files ($(du -sh "$destdir" | cut -f1))"
}

echo ""
echo "Copying spec files..."

copy_specs x86 \
  "x86.sla" "x86-64.sla" \
  "x86.pspec" "x86-64.pspec" \
  "x86gcc.cspec" "x86-64-gcc.cspec" "x86win.cspec" "x86-64-win.cspec"

copy_specs AARCH64 \
  "AARCH64.sla" \
  "AARCH64.pspec" \
  "AARCH64.cspec"

copy_specs ARM \
  "ARM8_le.sla" \
  "ARMt.pspec" \
  "ARM.cspec"

echo ""
echo "Total: $(du -sh "$DEST" | cut -f1)"
echo "Done."
echo ""
echo "NOTE: .ldefs files are maintained manually and were not updated."
echo "If Ghidra changes language definitions, update them in sleigh/specfiles/*/*.ldefs"
