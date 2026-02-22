# ghidra-decompiler

A TypeScript port of Ghidra's C++ decompiler engine — ~430K lines across 92 source files.

Produces **byte-identical output** to the C++ reference on all 79 official Ghidra datatests.

## Architecture

```
src/
  core/        — Address spaces, opcodes, float emulation, marshalling (16 files)
  sleigh/      — SLEIGH processor specification runtime (12 files)
  decompiler/  — Decompilation pipeline: SSA, type propagation, rules, C output (52 files)
  console/     — CLI interface, test harness, architecture loaders (9 files)
  util/        — Shared utilities (3 files)
```

The decompiler loads `.sla` / `.pspec` / `.cspec` files from a standard Ghidra installation at runtime via SLEIGH, making it architecture-agnostic — x86, ARM, AARCH64, MIPS, 8051, and others are all supported.

## Prerequisites

- Node.js >= 18
- A [Ghidra](https://ghidra-sre.org/) installation (provides SLEIGH processor specs)
- For C++ comparison: the `decomp_test_dbg` binary built from `ghidra-src/`

Scripts auto-detect Ghidra from common install locations (Homebrew, `/opt/ghidra`, snap, `~/ghidra`, or `analyzeHeadless` on `PATH`). To override, set `GHIDRA_HOME` or `SLEIGH_PATH`:

```bash
export SLEIGH_PATH=/opt/ghidra_11.4.2_PUBLIC   # directory containing Processors/
```

## Quick Start

```bash
npm install
npm test                    # run all 79 datatests
npx vitest run --reporter=verbose   # verbose output
```

## Tests

### Datatests (integration)

The primary test suite runs Ghidra's official decompiler test cases — XML files in `ghidra-src/.../datatests/` that embed binary code, decompiler commands, and expected output patterns.

```bash
# All 79 tests
SLEIGH_PATH=$SLEIGH_PATH npx vitest run test/integration/datatests.test.ts

# Quick subset (8 tests)
SLEIGH_PATH=$SLEIGH_PATH npx vitest run test/integration/datatests-quick.test.ts
```

### C++ Output Comparison

Verifies the TS decompiler produces **exact same output** as the C++ reference for every datatest:

```bash
SLEIGH_PATH=$SLEIGH_PATH npx vitest run test/integration/compare-cpp.test.ts --reporter=verbose
```

### Unit Tests

```bash
npx vitest run test/unit/
```

## Decompiling a Binary

### One-liner: dump a single function

```bash
scripts/dump-c.sh /bin/ls main
scripts/dump-c.sh ./a.out my_func
scripts/dump-c.sh ./a.out my_func x86:LE:64:default gcc
```

This exports the binary via Ghidra headless, decompiles the named function, and prints the C output to stdout. Status messages go to stderr, so you can redirect cleanly:

```bash
scripts/dump-c.sh /bin/ls main > main.c
```

### Using the Console CLI

The decompiler provides an interactive console (like Ghidra's `decomp_dbg`):

```bash
echo 'load file /path/to/exported.xml
lo fu main
decompile
print C
quit' | SLEIGH_PATH=$SLEIGH_PATH npx tsx src/console/consolemain.ts
```

Available console commands:

| Command | Description |
|---------|-------------|
| `load file <xml>` | Load a binary image from XML |
| `lo fu <name>` | Select a function by name |
| `decompile` | Run the decompilation pipeline |
| `print C` | Print decompiled C output |
| `print C flat` | Print flat C (no structure) |
| `print C xml` | Print C output as XML |
| `print C types` | Print recovered type definitions |
| `print C globals` | Print global variable declarations |
| `save <file>` | Save architecture state |
| `restore <file>` | Restore saved state |
| `quit` | Exit |

### Programmatic API

```typescript
import './src/console/xml_arch.js';
import { startDecompilerLibrary } from './src/console/libdecomp.js';
import { FunctionTestCollection } from './src/console/testfunction.js';
import { ConsoleWriter } from './src/util/writer.js';

startDecompilerLibrary(process.env.SLEIGH_PATH);

const writer = new ConsoleWriter();
FunctionTestCollection.runTestFiles(['path/to/exported.xml'], writer);
```

## Comparing on Real Binaries

`scripts/compare.sh` takes a binary, exports it via Ghidra headless, and runs both decompilers side-by-side:

```bash
scripts/compare.sh /usr/bin/true
scripts/compare.sh /bin/ls
scripts/compare.sh ./my_binary x86:LE:64:default gcc
```

Output is saved to `output/compare/<binary>/`:

```
output/compare/ls/
  ts_output.c       — full TS decompiled output
  cpp_output.c      — full C++ decompiled output
  diffs/            — per-function diff pairs for differing functions
    _func.cpp.c
    _func.ts.c
```

## Project Structure

```
ghidra-src/         — Ghidra C++ source (reference implementation)
src/                — TypeScript translation
test/
  integration/      — Datatest and comparison tests
  unit/             — Unit tests
scripts/
  dump-c.sh         — Decompile a single function to C
  compare.sh        — Compare C++ vs TS decompiler output
  ghidra_export.py  — Ghidra headless export script (Jython)
```

## License

This project is a translation of [Ghidra](https://github.com/NationalSecurityAgency/ghidra), which is licensed under the Apache License 2.0.
