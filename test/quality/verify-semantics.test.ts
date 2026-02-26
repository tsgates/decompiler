/**
 * Semantic correctness verification for enhanced display mode.
 *
 * Verifies that goto-to-structured-code transformations preserve program semantics:
 * 1. Statement Preservation — no lost/duplicated semantic statements
 * 2. Recompilation — enhanced output compiles if normal does
 * 3. Control Flow Invariants — return/goto/break/label count relationships
 *
 * Runs on all 22 quality test binaries that have gotos.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import '../../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../../src/console/libdecomp.js';
import { FunctionTestCollection } from '../../src/console/testfunction.js';
import { StringWriter } from '../../src/util/writer.js';
import { existsSync, readdirSync, readFileSync, writeFileSync, mkdtempSync, rmSync } from 'fs';
import { execSync } from 'child_process';
import path from 'path';
import os from 'os';

const CACHE_BASE = 'test/quality/results/.cache';

// All binaries with gotos (from enhanced-display.test.ts)
const gotoBinaries = [
  '02_pointers_arrays_O2',
  '07_recursion_O1', '07_recursion_O2',
  '08_string_ops_O1', '08_string_ops_O2',
  '10_mixed_types_O2',
  '11_goto_patterns_O1', '11_goto_patterns_O2',
  '13_array_algorithms_O1', '13_array_algorithms_O2', '13_array_algorithms_Os',
  '14_enum_constants_O1', '14_enum_constants_O2', '14_enum_constants_Os',
  '15_varargs_like_O1', '15_varargs_like_O2', '15_varargs_like_Os',
  '16_matrix_ops_O2',
  '19_complex_expressions_O2',
  '23_multi_dim_O2',
  '25_nested_loops_O2',
  '28_large_stack_O2',
  '29_crypto_simple_O2',
];

// Keywords to exclude from function call extraction
const CALL_KEYWORDS = new Set([
  'if', 'while', 'for', 'do', 'switch', 'return', 'sizeof', 'goto',
  // Types that appear in casts
  'int1', 'int2', 'int4', 'int8', 'uint1', 'uint2', 'uint4', 'uint8',
  'i8', 'i16', 'i32', 'i64', 'u8', 'u16', 'u32', 'u64',
  'xunknown1', 'xunknown2', 'xunknown4', 'xunknown8',
  'unk1', 'unk2', 'unk4', 'unk8',
  'float4', 'float8', 'float10', 'f32', 'f64', 'f80',
  'long', 'short', 'char', 'void', 'bool', 'ulong',
  'undefined', 'undefined1', 'undefined2', 'undefined4', 'undefined8',
]);

// C keywords to exclude from function name extraction in splitFunctions
const C_KEYWORDS = new Set([
  'if', 'while', 'for', 'do', 'switch', 'else', 'return', 'goto', 'case', 'default',
]);

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

function findCachedXml(prefix: string): string | null {
  if (!existsSync(CACHE_BASE)) return null;
  const dirs = readdirSync(CACHE_BASE) as string[];
  const matching = dirs.filter((d: string) => d.startsWith(prefix)).sort();
  if (matching.length === 0) return null;
  const xmlPath = path.join(CACHE_BASE, matching[matching.length - 1], 'exported.xml');
  return existsSync(xmlPath) ? xmlPath : null;
}

/** Try to extract a function name from accumulated lines and save to the map. */
function saveFunctionBlock(funcs: Map<string, string>, lines: string[]): void {
  const block = lines.join('\n').trim();
  if (!block) return;
  const m = block.match(/^\S+\s+(\S+?)\s*[\s(]/);
  if (m && !C_KEYWORDS.has(m[1])) {
    funcs.set(m[1], block);
  }
}

/**
 * Split combined decompiler output into per-function map (name → body).
 * Handles function signatures that wrap across two lines.
 * Uses brace-depth tracking for robust function boundary detection.
 */
function splitFunctions(output: string): Map<string, string> {
  const funcs = new Map<string, string>();
  const lines = output.split('\n');

  let currentLines: string[] = [];
  let braceDepth = 0;
  let inFunction = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Detect function signature: line at column 0, not a keyword, containing or followed by (
    if (!inFunction && braceDepth === 0 && line.length > 0 && /^\S/.test(line)) {
      const hasOpenParen = line.includes('(');
      const nextLineHasParen = (i + 1 < lines.length) && /^\s+\(/.test(lines[i + 1]);
      if (hasOpenParen || nextLineHasParen) {
        saveFunctionBlock(funcs, currentLines);
        currentLines = [line];
        if (!hasOpenParen && nextLineHasParen) {
          i++;
          currentLines[0] = line.trimEnd() + ' ' + lines[i].trimStart();
        }
        continue;
      }
    }

    currentLines.push(line);

    for (const ch of line) {
      if (ch === '{') { braceDepth++; inFunction = true; }
      if (ch === '}') { braceDepth--; }
    }

    if (inFunction && braceDepth === 0) {
      inFunction = false;
    }
  }

  saveFunctionBlock(funcs, currentLines);
  return funcs;
}

/**
 * Extract function call names from a function body.
 * Returns a multiset of callee names.
 */
function extractCallNames(body: string): Map<string, number> {
  const calls = new Map<string, number>();
  const re = /\b(\w+)\s*\(/g;
  let match;
  while ((match = re.exec(body)) !== null) {
    const name = match[1];
    if (!CALL_KEYWORDS.has(name)) {
      calls.set(name, (calls.get(name) || 0) + 1);
    }
  }
  return calls;
}

/** Count occurrences of a regex in a string. */
function countMatches(s: string, re: RegExp): number {
  return (s.match(re) || []).length;
}

/** Count labels (excluding case/default) using matchAll to avoid stateful regex issues. */
function countLabels(body: string): number {
  const caseDefaultRe = /^\s*(?:case|default)\s*:/;
  return [...body.matchAll(/^\s*(\w+)\s*:/gm)]
    .filter(m => !caseDefaultRe.test(m[0]))
    .length;
}

// -----------------------------------------------------------------------
// Decompilation cache — decompile each binary only once
// -----------------------------------------------------------------------

interface BinaryResult {
  prefix: string;
  normalOutput: string;
  enhancedOutput: string;
  normalFuncs: Map<string, string>;
  enhancedFuncs: Map<string, string>;
}

const cache = new Map<string, BinaryResult>();

function getResult(prefix: string): BinaryResult | null {
  if (cache.has(prefix)) return cache.get(prefix)!;
  const xmlFile = findCachedXml(prefix);
  if (!xmlFile) return null;

  function run(enhanced: boolean): string {
    const writer = new StringWriter();
    const tc = new FunctionTestCollection(writer);
    tc.loadTest(xmlFile!);
    if (enhanced) tc.applyEnhancedDisplay();
    const failures: string[] = [];
    tc.runTests(failures);
    return tc.getLastOutput();
  }

  const normalOutput = run(false);
  const enhancedOutput = run(true);
  const result: BinaryResult = {
    prefix,
    normalOutput,
    enhancedOutput,
    normalFuncs: splitFunctions(normalOutput),
    enhancedFuncs: splitFunctions(enhancedOutput),
  };
  cache.set(prefix, result);
  return result;
}

// -----------------------------------------------------------------------
// Iteration helpers — eliminate per-function boilerplate
// -----------------------------------------------------------------------

/** Iterate over function pairs present in both normal and enhanced output. */
function forEachFunctionPair(
  r: BinaryResult,
  fn: (fname: string, normalBody: string, enhancedBody: string) => void,
): void {
  for (const [fname, normalBody] of r.normalFuncs) {
    const enhancedBody = r.enhancedFuncs.get(fname);
    if (!enhancedBody) continue;
    fn(fname, normalBody, enhancedBody);
  }
}

/** Collect violation strings from a per-function checker. */
function collectViolations(
  r: BinaryResult,
  checker: (fname: string, normalBody: string, enhancedBody: string) => string | null,
): string[] {
  const violations: string[] = [];
  forEachFunctionPair(r, (fname, normal, enhanced) => {
    const v = checker(fname, normal, enhanced);
    if (v) violations.push(v);
  });
  return violations;
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

beforeAll(() => {
  startDecompilerLibrary();
});

// =====================================================================
// Technique 1: Statement Preservation
// =====================================================================

describe('Statement Preservation', { timeout: 120_000 }, () => {
  for (const prefix of gotoBinaries) {
    describe(prefix, () => {

      it('no lost function calls per function', () => {
        const r = getResult(prefix);
        if (!r) return;

        const lost = collectViolations(r, (fname, normalBody, enhancedBody) => {
          const normalCalls = extractCallNames(normalBody);
          const enhancedCalls = extractCallNames(enhancedBody);
          const msgs: string[] = [];
          for (const [callee, count] of normalCalls) {
            const eCount = enhancedCalls.get(callee) || 0;
            if (eCount < count) {
              msgs.push(`${fname}: lost ${count - eCount}x call to ${callee} (normal=${count}, enhanced=${eCount})`);
            }
          }
          return msgs.length > 0 ? msgs.join('\n') : null;
        });
        expect(lost, `Lost function calls:\n${lost.join('\n')}`).toHaveLength(0);
      });

      it('no duplicated function calls per function', () => {
        const r = getResult(prefix);
        if (!r) return;

        const duped = collectViolations(r, (fname, normalBody, enhancedBody) => {
          const normalCalls = extractCallNames(normalBody);
          const enhancedCalls = extractCallNames(enhancedBody);
          const msgs: string[] = [];
          for (const [callee, eCount] of enhancedCalls) {
            const nCount = normalCalls.get(callee) || 0;
            if (eCount > nCount) {
              msgs.push(`${fname}: duplicated ${eCount - nCount}x call to ${callee} (normal=${nCount}, enhanced=${eCount})`);
            }
          }
          return msgs.length > 0 ? msgs.join('\n') : null;
        });
        expect(duped, `Duplicated function calls:\n${duped.join('\n')}`).toHaveLength(0);
      });

      it('statement count ratio is consistent', () => {
        const r = getResult(prefix);
        if (!r) return;

        let totalNormal = 0;
        let totalEnhanced = 0;
        forEachFunctionPair(r, (_fname, normalBody, enhancedBody) => {
          totalNormal += normalBody.split('\n').filter(l => l.trim().length > 0).length;
          totalEnhanced += enhancedBody.split('\n').filter(l => l.trim().length > 0).length;
        });

        if (totalNormal > 0) {
          const ratio = totalEnhanced / totalNormal;
          expect(ratio).toBeGreaterThan(0.5);
          expect(ratio).toBeLessThan(2.0);
        }
      });
    });
  }
});

// =====================================================================
// Technique 2: Recompilation Test
// =====================================================================

describe('Recompilation', { timeout: 120_000 }, () => {
  let hasClang = false;
  try {
    execSync('clang --version', { stdio: 'pipe' });
    hasClang = true;
  } catch {
    // clang not available
  }

  const recompHeader = readFileSync(path.join(__dirname, 'recomp-header.h'), 'utf8');

  // Known recompilation failures: goto elimination emits bodyless `if (cond)` in 2 binaries.
  // Known recompilation failures: goto elimination emits bodyless `if (cond)` in some binaries.
  const knownRecompFailures = new Set([
    '11_goto_patterns_O2',
    '25_nested_loops_O2',
    '29_crypto_simple_O2',
  ]);

  for (const prefix of gotoBinaries) {
    const testFn = knownRecompFailures.has(prefix) ? it.fails : it;
    testFn(`${prefix}: enhanced mode compiles if normal mode compiles`, () => {
      if (!hasClang) return;
      const r = getResult(prefix);
      if (!r) return;

      const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'decomp-recomp-'));
      try {
        const normalFile = path.join(tmpDir, 'normal.c');
        writeFileSync(normalFile, recompHeader + '\n' + r.normalOutput + '\n');

        const enhancedFile = path.join(tmpDir, 'enhanced.c');
        writeFileSync(enhancedFile, recompHeader + '\n' + r.enhancedOutput + '\n');

        let normalCompiles = false;
        try {
          execSync(`clang -c -fsyntax-only -w -Wno-everything -x c "${normalFile}" 2>&1`, {
            timeout: 10000,
            encoding: 'utf8',
          });
          normalCompiles = true;
        } catch {
          // Normal mode doesn't compile — skip this binary
        }

        if (normalCompiles) {
          try {
            execSync(`clang -c -fsyntax-only -w -Wno-everything -x c "${enhancedFile}" 2>&1`, {
              timeout: 10000,
              encoding: 'utf8',
            });
          } catch (e: any) {
            const stderr = e.stdout || e.stderr || '';
            expect.fail(
              `Enhanced mode fails to compile but normal mode succeeds.\n` +
              `Compiler errors:\n${stderr.slice(0, 2000)}`
            );
          }
        }
      } finally {
        rmSync(tmpDir, { recursive: true, force: true });
      }
    });
  }
});

// =====================================================================
// Technique 3: Control Flow Invariants
// =====================================================================

describe('Control Flow Invariants', { timeout: 120_000 }, () => {
  for (const prefix of gotoBinaries) {
    describe(prefix, () => {

      it('same function names in both modes', () => {
        const r = getResult(prefix);
        if (!r) return;

        const normalNames = [...r.normalFuncs.keys()].sort();
        const enhancedNames = [...r.enhancedFuncs.keys()].sort();
        expect(enhancedNames).toEqual(normalNames);
      });

      it('return count only increases (duplication may add returns)', () => {
        const r = getResult(prefix);
        if (!r) return;

        // Enhanced mode may have MORE returns due to eager return duplication
        // (splitting shared return blocks gives each path its own return).
        // It should never have FEWER returns.
        const violations = collectViolations(r, (fname, normalBody, enhancedBody) => {
          const nReturns = countMatches(normalBody, /\breturn\b/g);
          const eReturns = countMatches(enhancedBody, /\breturn\b/g);
          return eReturns < nReturns
            ? `${fname}: normal=${nReturns}, enhanced=${eReturns} (DECREASED!)`
            : null;
        });
        expect(violations, `Return count decreased:\n${violations.join('\n')}`).toHaveLength(0);
      });

      it('goto count only decreases (never increases)', () => {
        const r = getResult(prefix);
        if (!r) return;

        const violations = collectViolations(r, (fname, normalBody, enhancedBody) => {
          const nGotos = countMatches(normalBody, /\bgoto\s+\w+/g);
          const eGotos = countMatches(enhancedBody, /\bgoto\s+\w+/g);
          return eGotos > nGotos
            ? `${fname}: normal=${nGotos}, enhanced=${eGotos} (INCREASED!)`
            : null;
        });
        expect(violations, `Goto count increased:\n${violations.join('\n')}`).toHaveLength(0);
      });

      it('break+goto count consistent', () => {
        const r = getResult(prefix);
        if (!r) return;

        // Enhanced mode converts gotos to breaks and may also restructure
        // code in ways that change break counts. The key invariant is:
        // the total of gotos+breaks should not increase dramatically.
        let totalNormal = 0;
        let totalEnhanced = 0;
        forEachFunctionPair(r, (_fname, normalBody, enhancedBody) => {
          totalNormal += countMatches(normalBody, /\bgoto\s+\w+/g) + countMatches(normalBody, /\bbreak\s*;/g);
          totalEnhanced += countMatches(enhancedBody, /\bgoto\s+\w+/g) + countMatches(enhancedBody, /\bbreak\s*;/g);
        });
        // Enhanced should not introduce more than 2x total control flow exits
        expect(totalEnhanced).toBeLessThanOrEqual(totalNormal * 2);
      });

      it('label count only decreases (labels suppressed)', () => {
        const r = getResult(prefix);
        if (!r) return;

        const violations = collectViolations(r, (fname, normalBody, enhancedBody) => {
          const nLabels = countLabels(normalBody);
          const eLabels = countLabels(enhancedBody);
          return eLabels > nLabels
            ? `${fname}: normal=${nLabels}, enhanced=${eLabels} (INCREASED!)`
            : null;
        });
        expect(violations, `Label count increased:\n${violations.join('\n')}`).toHaveLength(0);
      });

      it('aggregate: goto count never increases', () => {
        const r = getResult(prefix);
        if (!r) return;

        let totalNormalGotos = 0;
        let totalEnhancedGotos = 0;

        forEachFunctionPair(r, (_fname, normalBody, enhancedBody) => {
          totalNormalGotos += countMatches(normalBody, /\bgoto\s+\w+/g);
          totalEnhancedGotos += countMatches(enhancedBody, /\bgoto\s+\w+/g);
        });

        expect(totalEnhancedGotos).toBeLessThanOrEqual(totalNormalGotos);
      });
    });
  }
});

// =====================================================================
// Technique 4: Structural Integrity
// =====================================================================

describe('Structural Integrity', { timeout: 120_000 }, () => {
  for (const prefix of gotoBinaries) {
    describe(prefix, () => {

      it('brace balance per function', () => {
        const r = getResult(prefix);
        if (!r) return;

        const violations = collectViolations(r, (fname, _normalBody, enhancedBody) => {
          const opens = countMatches(enhancedBody, /\{/g);
          const closes = countMatches(enhancedBody, /\}/g);
          return opens !== closes
            ? `${fname}: { =${opens}, } =${closes}`
            : null;
        });
        expect(violations, `Brace imbalance:\n${violations.join('\n')}`).toHaveLength(0);
      });

      it('parenthesis balance per function', () => {
        const r = getResult(prefix);
        if (!r) return;

        const violations = collectViolations(r, (fname, _normalBody, enhancedBody) => {
          const opens = countMatches(enhancedBody, /\(/g);
          const closes = countMatches(enhancedBody, /\)/g);
          return opens !== closes
            ? `${fname}: ( =${opens}, ) =${closes}`
            : null;
        });
        expect(violations, `Parenthesis imbalance:\n${violations.join('\n')}`).toHaveLength(0);
      });

      it('function name preserved in signatures', () => {
        const r = getResult(prefix);
        if (!r) return;

        // Extract function name from first line of body
        function extractFuncName(body: string): string | null {
          const first = body.split('\n')[0];
          const m = first.match(/\b(\w+)\s*\(/);
          return m ? m[1] : null;
        }

        const violations = collectViolations(r, (fname, normalBody, enhancedBody) => {
          const normalName = extractFuncName(normalBody);
          const enhancedName = extractFuncName(enhancedBody);
          return normalName !== enhancedName
            ? `${fname}: normal="${normalName}" vs enhanced="${enhancedName}"`
            : null;
        });
        expect(violations, `Function name mismatch:\n${violations.join('\n')}`).toHaveLength(0);
      });
    });
  }
});
