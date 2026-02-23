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

### Decompilation Pipeline

The pipeline is driven by an **action tree** — nested, iterating groups of transformations
applied to a `Funcdata` object until convergence. Defined in `coreaction.ts:universalAction()`.

```
                        ┌─────────────────────────────┐
                        │       Machine Code           │
                        │  (x86, ARM, MIPS, ...)       │
                        └──────────────┬──────────────┘
                                       │
                    ┌──────────────────▼──────────────────┐
                    │          SLEIGH Translator           │
                    │  sleigh.ts — .sla processor specs    │
                    │  Lifts machine code → P-code IR      │
                    └──────────────────┬──────────────────┘
                                       │
                              PcodeOp[] + BlockBasic[]
                                       │
  ┌────────────────────────────────────▼────────────────────────────────────┐
  │                     universal (ActionRestartGroup)                       │
  │                                                                         │
  │  ┌─ SETUP ──────────────────────────────────────────────────────────┐   │
  │  │  ActionStart ─────── Gather raw P-code from binary (flow.ts)     │   │
  │  │  ActionConstbase ─── Mark constant varnodes                      │   │
  │  │  ActionDefaultParams  ActionExtraPopSetup                        │   │
  │  │  ActionPrototypeTypes ── Recover function prototypes (fspec.ts)  │   │
  │  │  ActionFuncLink ──── Link call sites to prototypes               │   │
  │  └─────────────────────────────────────────────────────────────────┘   │
  │                               │                                         │
  │  ┌─ fullloop (repeats until no changes) ───────────────────────────┐   │
  │  │                                                                  │   │
  │  │  ┌─ mainloop (repeats until no changes) ─────────────────────┐  │   │
  │  │  │                                                            │  │   │
  │  │  │  ActionHeritage ──── Build SSA form (heritage.ts)          │  │   │
  │  │  │    phi-functions, def-use chains, dominance frontiers      │  │   │
  │  │  │                                                            │  │   │
  │  │  │  ActionDeadCode ──── Remove dead code                      │  │   │
  │  │  │  ActionInferTypes ── Data-flow type recovery (type.ts)     │  │   │
  │  │  │                                                            │  │   │
  │  │  │  ┌─ stackstall (repeats) ─────────────────────────────┐   │  │   │
  │  │  │  │                                                     │   │  │   │
  │  │  │  │  oppool1 (ActionPool — ~100 rules, repeats)         │   │  │   │
  │  │  │  │  ┌───────────────────────────────────────────────┐  │   │  │   │
  │  │  │  │  │  Simplification     Arithmetic    Boolean     │  │   │  │   │
  │  │  │  │  │  RulePropagateCopy  RuleSub2Add   RuleBoolZext│  │   │  │   │
  │  │  │  │  │  RuleCollectTerms   RuleDivOpt    RuleLogic2B │  │   │  │   │
  │  │  │  │  │  RuleMultiCollapse  RuleShift2Mul RuleCondMove│  │   │  │   │
  │  │  │  │  │                                               │  │   │  │   │
  │  │  │  │  │  Bit operations     Comparisons   Extensions  │  │   │  │   │
  │  │  │  │  │  RuleAndMask        RuleEqual2Z   RuleZextElim│  │   │  │   │
  │  │  │  │  │  RuleOrCollapse     RuleLessEqual RuleSextElim│  │   │  │   │
  │  │  │  │  │  RuleShiftBitops    RuleThreeWay  RulePtrFlow │  │   │  │   │
  │  │  │  │  │                                               │  │   │  │   │
  │  │  │  │  │  Float ops          Subvar/Split  Control     │  │   │  │   │
  │  │  │  │  │  RuleFloatCast      RuleSplitFlow RuleSwitchSi│  │   │  │   │
  │  │  │  │  │  RuleInt2FloatCol   RuleSubvarAnd RuleCondNeg │  │   │  │   │
  │  │  │  │  │  + CPU-specific rules from Architecture       │  │   │  │   │
  │  │  │  │  └───────────────────────────────────────────────┘  │   │  │   │
  │  │  │  │                                                     │   │  │   │
  │  │  │  │  ActionDeindirect ── Resolve indirect calls         │   │  │   │
  │  │  │  │  ActionStackPtrFlow ── Stack pointer dataflow       │   │  │   │
  │  │  │  └─────────────────────────────────────────────────────┘   │  │   │
  │  │  │                                                            │  │   │
  │  │  │  ActionBlockStructure ── Build control flow hierarchy      │  │   │
  │  │  │    if/else, while, for, do-while, switch (blockaction.ts)  │  │   │
  │  │  │                                                            │  │   │
  │  │  │  oppool2 (ActionPool — type-driven rules, repeats)         │  │   │
  │  │  │    RulePushPtr, RuleStructOffset0, RulePtrArith            │  │   │
  │  │  │    RuleLoadVarnode, RuleStoreVarnode                       │  │   │
  │  │  │                                                            │  │   │
  │  │  │  ActionConditionalExe ── Conditional execution (condexe.ts)│  │   │
  │  │  └────────────────────────────────────────────────────────────┘  │   │
  │  │                                                                  │   │
  │  │  ActionSwitchNorm ──── Normalize switch tables (jumptable.ts)    │   │
  │  │  ActionReturnSplit ─── Split return values                       │   │
  │  │  ActionStartTypes ──── Enable type recovery for next iteration   │   │
  │  └──────────────────────────────────────────────────────────────────┘   │
  │                               │                                         │
  │  ┌─ CLEANUP ────────────────────────────────────────────────────────┐   │
  │  │  cleanup (ActionPool — presentation rules, repeats)              │   │
  │  │    RuleMultNegOne, RuleAddUnsigned, Rule2Comp2Sub                │   │
  │  │    RuleExpandLoad, RulePieceStructure, RuleSplitCopy             │   │
  │  │    RuleStringCopy, RuleStringStore                               │   │
  │  └──────────────────────────────────────────────────────────────────┘   │
  │                               │                                         │
  │  ┌─ MERGE & NAME ──────────────────────────────────────────────────┐   │
  │  │  ActionStructureTransform ── Final control flow transforms       │   │
  │  │  ActionAssignHigh ────────── Create HighVariable containers      │   │
  │  │  ActionMergeRequired ─────── Required varnode merges (merge.ts)  │   │
  │  │  ActionMarkExplicit/Implied ── Classify variable visibility      │   │
  │  │  ActionMergeCopy ─────────── Strategic varnode merging           │   │
  │  │    Cover analysis: non-intersecting live ranges → one variable   │   │
  │  │  ActionMergeAdjacent ─────── Adjacent range merging              │   │
  │  │  ActionMergeType ─────────── Type-compatible merging             │   │
  │  │  ActionNameVars ──────────── Assign human-readable names         │   │
  │  │  ActionSetCasts ──────────── Insert type casts (cast.ts)         │   │
  │  └──────────────────────────────────────────────────────────────────┘   │
  │                               │                                         │
  │  ActionFinalStructure ─── Last structural pass                          │
  │  ActionStop ──────────── Finalize                                       │
  └─────────────────────────────────────────────────────────────────────────┘
                                       │
                              Funcdata (fully analyzed)
                              ├─ VarnodeBank (SSA varnodes)
                              ├─ PcodeOpBank (simplified ops)
                              ├─ BlockGraph (structured CFG)
                              ├─ HighVariables (merged, named, typed)
                              └─ TypeFactory (recovered types)
                                       │
                    ┌──────────────────▼──────────────────┐
                    │         PrintC (printc.ts)           │
                    │  Walks structured blocks + ops       │
                    │  Emits C tokens with types & casts   │
                    └──────────────────┬──────────────────┘
                                       │
                              Decompiled C output
```

### Key Data Structures

| Structure | File | Role |
|-----------|------|------|
| `Funcdata` | funcdata.ts | Central container: holds all varnodes, ops, blocks, types for one function |
| `PcodeOp` | op.ts | Single p-code operation (COPY, LOAD, INT_ADD, CALL, BRANCH, ...) |
| `Varnode` | varnode.ts | Single SSA value: register, stack slot, constant, or unique temporary |
| `HighVariable` | variable.ts | Merged group of varnodes = one source-level variable |
| `BlockBasic` | block.ts | Basic block of sequential p-code ops |
| `BlockGraph` | block.ts | Hierarchical CFG: if/while/switch composed of sub-blocks |
| `Datatype` | type.ts | Recovered type: int, pointer, struct, array, enum, ... |
| `Heritage` | heritage.ts | SSA builder: dominance frontiers, phi-node insertion, renaming |
| `Merge` | merge.ts | Cover-based varnode merging into HighVariables |
| `JumpTable` | jumptable.ts | Recovered switch table: maps values to block destinations |
| `Action` | action.ts | Base class for pipeline phases; ActionGroup/ActionPool for composition |
| `Rule` | action.ts | Single peephole transformation applied to matching PcodeOps |

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

## Performance

### Datatests (79 test functions)

Benchmarked on Apple M-series (AARCH64). The C++ `decomp_test_dbg` binary spawns one process per test (each reloading SLEIGH specs), while the TS decompiler loads once and runs all tests in-process.

| Metric | TS | C++ | Ratio |
|--------|-----|------|-------|
| Total time (79 tests) | 1.11s | 8.43s | **7.6x faster** |
| Correctness | 79/79 | 79/79 | 100% identical |

### Real Binaries (AARCH64, macOS)

| Binary | Size | Functions | TS Time | C++ Time | Speedup | Identical Output |
|--------|------|-----------|---------|----------|---------|------------------|
| `/usr/bin/true` | 34K | 1 | 0.10s | 0.11s | 1.1x | 100% |
| `/bin/echo` | 51K | 5 | 0.27s | 0.18s | 0.7x | 80% |
| `/bin/ls` | 87K | 54 | 1.31s | 3.60s | 2.8x | 83% |
| `/usr/bin/sort` | 105K | 149 | 3.54s | 37.59s | 10.6x | 75% |
| `/usr/bin/ssh` | 751K | 1021 | 36.93s | 1478.54s | **40.0x** | 54.8% |

The TS speedup scales with function count due to amortized SLEIGH loading. Output differences on real binaries are mostly minor type-inference variations (`int4` vs `int8`, stack address formatting).

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
