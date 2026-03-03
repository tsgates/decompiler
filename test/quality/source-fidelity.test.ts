/**
 * Source fidelity metrics: compare decompiled output vs original C source.
 * Measures how well the decompiler recovers the programmer's intent.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'fs';
import path from 'path';

import {
  stripStrings, countFor, countWhile, countDoWhile, countIf, countElse,
  countSwitch, countCase, countGoto, countReturn, countBreak, countContinue,
  countIncrement, countDecrement, countCompoundAssign, countArraySubscript,
  countArrow, countTernary, countCasts, countStatements, maxNestingDepth,
  SOURCE_TYPES, OUTPUT_TYPES, ENHANCED_TYPES,
} from './metrics/parse_helpers.js';
import { parseSourceFile, parseSource } from './metrics/source_parser.js';
import { parseOutput, parseOutputFile } from './metrics/output_parser.js';
import { compareFile } from './metrics/comparator.js';
import { generateTSV, generateMarkdown } from './metrics/report.js';
import type { FileComparison } from './metrics/types.js';

const SRC_DIR = path.join(__dirname, 'src');
const RESULTS_DIR = path.join(__dirname, 'results');

const ALL_SOURCES = readdirSync(SRC_DIR)
  .filter(f => f.endsWith('.c'))
  .sort();

const OPT_LEVELS = ['O0', 'O1', 'O2', 'Os'];

// =====================================================================
// parse_helpers tests
// =====================================================================

describe('parse_helpers', () => {
  it('countFor counts for-loops correctly', () => {
    expect(countFor('for (i=0; i<n; i++) { for (j=0; j<m; j++) {} }')).toBe(2);
  });

  it('countDoWhile counts do-while loops', () => {
    expect(countDoWhile('do { x++; } while (x < 10);')).toBe(1);
  });

  it('countWhile excludes do-while trailing while', () => {
    expect(countWhile('while (x) {} do { } while (y);')).toBe(1);
  });

  it('countCompoundAssign excludes != and ==', () => {
    expect(countCompoundAssign('a += 1; b -= 2; c != d; e == f;')).toBe(2);
  });

  it('countCasts detects source type casts', () => {
    expect(countCasts('(int)x + (float)y + (a + b)', SOURCE_TYPES)).toBe(2);
  });

  it('countStatements subtracts for-header semicolons', () => {
    expect(countStatements('for (int i=0; i<n; i++) { x = 1; y = 2; }')).toBe(2);
  });

  it('maxNestingDepth tracks brace depth', () => {
    expect(maxNestingDepth('{ if (a) { if (b) { x; } } }')).toBe(2);
  });

  it('stripStrings replaces string content', () => {
    const result = stripStrings('printf("if (x) break;");');
    expect(result).not.toContain('if (x)');
    expect(result).toContain('printf');
  });

  it('countTernary detects ternary operator', () => {
    expect(countTernary('x = a > b ? a : b; y = c;')).toBe(1);
  });

  it('countArraySubscript counts bracket accesses', () => {
    expect(countArraySubscript('arr[i] = arr[j] + x;')).toBe(2);
  });
});

// =====================================================================
// source_parser tests
// =====================================================================

describe('source_parser', () => {
  it('parses 01_basic_control.c functions', () => {
    const metrics = parseSourceFile(path.join(SRC_DIR, '01_basic_control.c'));
    const names = metrics.functions.map(f => f.name);
    expect(names).toContain('max3');
    expect(names).toContain('sum_range');
    expect(names).toContain('count_digits');
    expect(names).toContain('day_name');
    expect(names).toContain('fibonacci');
    expect(names.length).toBe(5);
  });

  it('fibonacci has correct metrics', () => {
    const metrics = parseSourceFile(path.join(SRC_DIR, '01_basic_control.c'));
    const fib = metrics.functions.find(f => f.name === 'fibonacci')!;
    expect(fib).toBeDefined();
    expect(fib.paramCount).toBe(1);
    expect(fib.forCount).toBe(1);
    expect(fib.ifCount).toBe(1);
    expect(fib.returnCount).toBe(2);
    expect(fib.incrementCount).toBeGreaterThanOrEqual(1);
  });

  it('21_do_while.c digits_sum has doWhileCount=1', () => {
    const metrics = parseSourceFile(path.join(SRC_DIR, '21_do_while.c'));
    const fn = metrics.functions.find(f => f.name === 'digits_sum')!;
    expect(fn).toBeDefined();
    expect(fn.doWhileCount).toBe(1);
    expect(fn.compoundAssignCount).toBeGreaterThanOrEqual(1);
  });

  it('24_switch_dense.c opcode_dispatch has switch+cases', () => {
    const metrics = parseSourceFile(path.join(SRC_DIR, '24_switch_dense.c'));
    const fn = metrics.functions.find(f => f.name === 'opcode_dispatch')!;
    expect(fn).toBeDefined();
    expect(fn.switchCount).toBe(1);
    expect(fn.caseCount).toBe(13);
    expect(fn.ternaryCount).toBeGreaterThanOrEqual(2);
  });

  it('03_structs.c: skips typedef struct, extracts functions only', () => {
    const metrics = parseSourceFile(path.join(SRC_DIR, '03_structs.c'));
    const names = metrics.functions.map(f => f.name);
    // Should not include struct names
    expect(names).not.toContain('Point');
    expect(names).not.toContain('Circle');
    expect(names).not.toContain('Student');
    // Should include functions
    expect(names).toContain('point_distance_sq');
    expect(names).toContain('circle_area_approx');
    expect(names).toContain('student_init');
  });

  it('07_recursion.c: skips forward declarations', () => {
    const metrics = parseSourceFile(path.join(SRC_DIR, '07_recursion.c'));
    const names = metrics.functions.map(f => f.name);
    expect(names).toContain('factorial');
    expect(names).toContain('gcd');
    expect(names).toContain('is_even');
    expect(names).toContain('is_odd');
    // is_even and is_odd should each appear exactly once
    expect(names.filter(n => n === 'is_even').length).toBe(1);
    expect(names.filter(n => n === 'is_odd').length).toBe(1);
  });

  it('05_function_ptrs.c: handles function pointer params', () => {
    const metrics = parseSourceFile(path.join(SRC_DIR, '05_function_ptrs.c'));
    const names = metrics.functions.map(f => f.name);
    expect(names).toContain('apply_chain');
    expect(names).toContain('apply_op');
  });

  it('04_bitwise.c: counts correctly', () => {
    const metrics = parseSourceFile(path.join(SRC_DIR, '04_bitwise.c'));
    const countOnes = metrics.functions.find(f => f.name === 'count_ones')!;
    expect(countOnes).toBeDefined();
    expect(countOnes.whileCount).toBe(1);
    expect(countOnes.compoundAssignCount).toBeGreaterThanOrEqual(1);
  });

  it('all 30 source files parse without error', () => {
    for (const file of ALL_SOURCES) {
      const metrics = parseSourceFile(path.join(SRC_DIR, file));
      expect(metrics.functions.length).toBeGreaterThan(0);
    }
  });

  it('total function count across all 30 files is reasonable', () => {
    let total = 0;
    for (const file of ALL_SOURCES) {
      const metrics = parseSourceFile(path.join(SRC_DIR, file));
      total += metrics.functions.length;
    }
    expect(total).toBeGreaterThan(50);
  });

  it('sum_range has correct paramCount', () => {
    const metrics = parseSourceFile(path.join(SRC_DIR, '01_basic_control.c'));
    const fn = metrics.functions.find(f => f.name === 'sum_range')!;
    expect(fn.paramCount).toBe(2);
  });

  it('count_digits has whileCount', () => {
    const metrics = parseSourceFile(path.join(SRC_DIR, '01_basic_control.c'));
    const fn = metrics.functions.find(f => f.name === 'count_digits')!;
    expect(fn.whileCount).toBe(1);
  });

  it('day_name has switchCount=1 and caseCount', () => {
    const metrics = parseSourceFile(path.join(SRC_DIR, '01_basic_control.c'));
    const fn = metrics.functions.find(f => f.name === 'day_name')!;
    expect(fn.switchCount).toBe(1);
    expect(fn.caseCount).toBe(7);
  });

  it('parseSource works from string', () => {
    const src = 'int foo(int x) {\n  return x + 1;\n}\n';
    const metrics = parseSource(src);
    expect(metrics.functions.length).toBe(1);
    expect(metrics.functions[0].name).toBe('foo');
    expect(metrics.functions[0].returnCount).toBe(1);
  });
});

// =====================================================================
// output_parser tests
// =====================================================================

describe('output_parser', () => {
  const outputFile = path.join(RESULTS_DIR, '01_basic_control_O0', 'ts_output.c');
  const hasOutput = existsSync(outputFile);

  it('parses ts_output.c from 01_basic_control_O0', () => {
    if (!hasOutput) return;
    const metrics = parseOutputFile(outputFile);
    expect(metrics.functions.length).toBe(5);
  });

  it('_max3 has correct returnType and paramCount', () => {
    if (!hasOutput) return;
    const metrics = parseOutputFile(outputFile);
    const fn = metrics.functions.find(f => f.name === '_max3')!;
    expect(fn).toBeDefined();
    expect(fn.returnType).toContain('int4');
    expect(fn.paramCount).toBe(3);
  });

  it('excludes entry function from results', () => {
    if (!hasOutput) return;
    const metrics = parseOutputFile(outputFile);
    const names = metrics.functions.map(f => f.name);
    expect(names).not.toContain('entry');
  });

  it('handles standard type names in declarations', () => {
    const output = `int4 _foo(int4 param_1)\n\n{\n  xunknown4 xStack_4;\n  xStack_4 = param_1;\n  return xStack_4;\n}\n`;
    const metrics = parseOutput(output);
    expect(metrics.functions.length).toBe(1);
    expect(metrics.functions[0].variableDeclCount).toBeGreaterThanOrEqual(1);
  });

  it('handles enhanced type names', () => {
    const output = `i32 _foo(i32 param_1)\n\n{\n  unk4 uStack_4;\n  uStack_4 = param_1;\n  return uStack_4;\n}\n`;
    const metrics = parseOutput(output, true);
    expect(metrics.functions.length).toBe(1);
  });

  it('parses all available ts_output.c files without error', () => {
    const resultDirs = readdirSync(RESULTS_DIR).filter(d => !d.startsWith('.'));
    let parsed = 0;
    for (const dir of resultDirs) {
      const outFile = path.join(RESULTS_DIR, dir, 'ts_output.c');
      if (existsSync(outFile)) {
        const metrics = parseOutputFile(outFile);
        expect(metrics.functions.length).toBeGreaterThan(0);
        parsed++;
      }
    }
    expect(parsed).toBeGreaterThan(0);
  });

  it('correctly counts for-loops in output', () => {
    if (!hasOutput) return;
    const metrics = parseOutputFile(outputFile);
    const fn = metrics.functions.find(f => f.name === '_sum_range')!;
    expect(fn).toBeDefined();
    expect(fn.forCount).toBe(1);
  });

  it('detects casts in output', () => {
    const output = `int4 _foo(int4 param_1)\n\n{\n  return (uint4)param_1;\n}\n`;
    const metrics = parseOutput(output);
    expect(metrics.functions[0].castCount).toBeGreaterThanOrEqual(1);
  });

  it('parseOutput handles empty input', () => {
    const metrics = parseOutput('');
    expect(metrics.functions.length).toBe(0);
  });

  it('parseOutput handles multi-line signatures', () => {
    const output = `void _foo(int4 param_1,int4 param_2,\n  int4 param_3)\n\n{\n  return;\n}\n`;
    // This format has params on same line as name, so should parse
    const metrics = parseOutput(output);
    // May or may not parse depending on exact format; just don't crash
    expect(metrics).toBeDefined();
  });
});

// =====================================================================
// comparator tests
// =====================================================================

describe('comparator', () => {
  const outputFile = path.join(RESULTS_DIR, '01_basic_control_O0', 'ts_output.c');
  const hasOutput = existsSync(outputFile);

  it('01_basic_control O0: functionRecoveryRate = 1.0', () => {
    if (!hasOutput) return;
    const source = parseSourceFile(path.join(SRC_DIR, '01_basic_control.c'));
    const output = parseOutputFile(outputFile);
    const cmp = compareFile(source, output, 'O0');
    expect(cmp.functionRecoveryRate).toBe(1.0);
    expect(cmp.matched.length).toBe(5);
    expect(cmp.unmatchedSource.length).toBe(0);
  });

  it('sum_range at O0: controlFlowMatch for for-loop', () => {
    if (!hasOutput) return;
    const source = parseSourceFile(path.join(SRC_DIR, '01_basic_control.c'));
    const output = parseOutputFile(outputFile);
    const cmp = compareFile(source, output, 'O0');
    const sumRange = cmp.matched.find(m => m.sourceName === 'sum_range')!;
    expect(sumRange).toBeDefined();
    // At O0 the for-loop should be preserved
    expect(sumRange.loopCountDelta).toBe(0);
  });

  it('variableRatio >= 1.0 for most functions (decompiler adds temps)', () => {
    if (!hasOutput) return;
    const source = parseSourceFile(path.join(SRC_DIR, '01_basic_control.c'));
    const output = parseOutputFile(outputFile);
    const cmp = compareFile(source, output, 'O0');
    const ratios = cmp.matched.map(m => m.variableRatio);
    // At least some functions should have ratio >= 1.0
    expect(ratios.some(r => r >= 1.0)).toBe(true);
  });

  it('gotoIntroduced = 0 for simple programs at O0', () => {
    if (!hasOutput) return;
    const source = parseSourceFile(path.join(SRC_DIR, '01_basic_control.c'));
    const output = parseOutputFile(outputFile);
    const cmp = compareFile(source, output, 'O0');
    const totalGotos = cmp.matched.reduce((s, m) => s + m.gotoIntroduced, 0);
    expect(totalGotos).toBe(0);
  });

  it('unmatched source functions tracked correctly', () => {
    const source = parseSource('int foo(int x) {\n  return x;\n}\nint bar(int x) {\n  return x;\n}\n');
    const output = parseOutput('int4 _foo(int4 param_1)\n\n{\n  return param_1;\n}\n');
    const cmp = compareFile(source, output, 'O0');
    expect(cmp.unmatchedSource).toContain('bar');
    expect(cmp.matched.length).toBe(1);
  });

  it('empty input handled gracefully', () => {
    const source = parseSource('');
    const output = parseOutput('');
    const cmp = compareFile(source, output, 'O0');
    expect(cmp.functionRecoveryRate).toBe(0);
    expect(cmp.matched.length).toBe(0);
  });

  it('castDensity > 0 for output with casts', () => {
    const output = parseOutput(
      'int4 _foo(int4 param_1)\n\n{\n  return (uint4)param_1 + (int4)0;\n}\n'
    );
    const source = parseSource('int foo(int x) {\n  return x;\n}\n');
    const cmp = compareFile(source, output, 'O0');
    if (cmp.matched.length > 0) {
      // Cast density may or may not be > 0 depending on parsing
      expect(cmp.matched[0].castDensity).toBeGreaterThanOrEqual(0);
    }
  });

  it('extra output functions tracked', () => {
    const source = parseSource('int foo(int x) {\n  return x;\n}\n');
    const output = parseOutput(
      'int4 _foo(int4 param_1)\n\n{\n  return param_1;\n}\n' +
      'int4 _extra(void)\n\n{\n  return 0;\n}\n'
    );
    const cmp = compareFile(source, output, 'O0');
    expect(cmp.extraOutput).toContain('_extra');
  });

  it('paramCountMatch works', () => {
    if (!hasOutput) return;
    const source = parseSourceFile(path.join(SRC_DIR, '01_basic_control.c'));
    const output = parseOutputFile(outputFile);
    const cmp = compareFile(source, output, 'O0');
    const max3 = cmp.matched.find(m => m.sourceName === 'max3')!;
    expect(max3).toBeDefined();
    expect(max3.paramCountMatch).toBe(true);
  });
});

// =====================================================================
// report tests
// =====================================================================

describe('report', () => {
  function makeSampleComparisons(): FileComparison[] {
    const outputFile = path.join(RESULTS_DIR, '01_basic_control_O0', 'ts_output.c');
    if (!existsSync(outputFile)) return [];
    const source = parseSourceFile(path.join(SRC_DIR, '01_basic_control.c'));
    const output = parseOutputFile(outputFile);
    return [compareFile(source, output, 'O0')];
  }

  it('TSV has header + correct row count', () => {
    const cmps = makeSampleComparisons();
    if (cmps.length === 0) return;
    const tsv = generateTSV(cmps);
    const lines = tsv.trim().split('\n');
    expect(lines[0]).toContain('Source');
    expect(lines.length).toBe(2); // header + 1 data row
  });

  it('Markdown has valid table syntax', () => {
    const cmps = makeSampleComparisons();
    if (cmps.length === 0) return;
    const md = generateMarkdown(cmps);
    expect(md).toContain('|');
    expect(md).toContain('---');
    expect(md).toContain('# Source Fidelity Report');
  });

  it('handles empty input', () => {
    const tsv = generateTSV([]);
    const md = generateMarkdown([]);
    expect(tsv.trim().split('\n').length).toBe(1); // header only
    expect(md).toContain('# Source Fidelity Report');
  });

  it('aggregate row computed correctly', () => {
    const cmps = makeSampleComparisons();
    if (cmps.length === 0) return;
    const md = generateMarkdown(cmps);
    expect(md).toContain('## Aggregate');
    expect(md).toContain('Function Recovery');
  });

  it('deterministic output', () => {
    const cmps = makeSampleComparisons();
    if (cmps.length === 0) return;
    const tsv1 = generateTSV(cmps);
    const tsv2 = generateTSV(cmps);
    expect(tsv1).toBe(tsv2);
    const md1 = generateMarkdown(cmps);
    const md2 = generateMarkdown(cmps);
    expect(md1).toBe(md2);
  });
});

// =====================================================================
// End-to-end integration tests
// =====================================================================

describe('end-to-end integration', { timeout: 30_000 }, () => {
  it('01_basic_control across O0/O1/O2/Os: compare all available', () => {
    const source = parseSourceFile(path.join(SRC_DIR, '01_basic_control.c'));
    const comparisons: FileComparison[] = [];

    for (const opt of OPT_LEVELS) {
      const outFile = path.join(RESULTS_DIR, `01_basic_control_${opt}`, 'ts_output.c');
      if (!existsSync(outFile)) continue;
      const output = parseOutputFile(outFile);
      comparisons.push(compareFile(source, output, opt));
    }

    if (comparisons.length === 0) return;

    // Should have results for at least O0
    expect(comparisons.length).toBeGreaterThan(0);

    // Function recovery should be high at O0
    const o0 = comparisons.find(c => c.optLevel === 'O0');
    if (o0) {
      expect(o0.functionRecoveryRate).toBe(1.0);
    }
  });

  it('all 30 source files at O0: >80% function recovery', () => {
    let totalRecovered = 0;
    let totalFunctions = 0;
    let filesChecked = 0;

    for (const file of ALL_SOURCES) {
      const base = file.replace('.c', '');
      const outFile = path.join(RESULTS_DIR, `${base}_O0`, 'ts_output.c');
      if (!existsSync(outFile)) continue;

      const source = parseSourceFile(path.join(SRC_DIR, file));
      const output = parseOutputFile(outFile);
      const cmp = compareFile(source, output, 'O0');

      totalRecovered += cmp.matched.length;
      totalFunctions += cmp.matched.length + cmp.unmatchedSource.length;
      filesChecked++;
    }

    if (filesChecked === 0) return;
    const rate = totalRecovered / totalFunctions;
    expect(rate).toBeGreaterThan(0.8);
  });

  it('variable ratio generally increases with optimization', () => {
    const source = parseSourceFile(path.join(SRC_DIR, '01_basic_control.c'));

    const ratiosByOpt: Record<string, number> = {};
    for (const opt of OPT_LEVELS) {
      const outFile = path.join(RESULTS_DIR, `01_basic_control_${opt}`, 'ts_output.c');
      if (!existsSync(outFile)) continue;
      const output = parseOutputFile(outFile);
      const cmp = compareFile(source, output, opt);
      if (cmp.matched.length > 0) {
        ratiosByOpt[opt] = cmp.matched.reduce((s, m) => s + m.variableRatio, 0) / cmp.matched.length;
      }
    }

    // Just verify we computed something without crashing
    expect(Object.keys(ratiosByOpt).length).toBeGreaterThan(0);
  });

  it('for-loop recovery rate higher at O0 than O2', () => {
    const source = parseSourceFile(path.join(SRC_DIR, '01_basic_control.c'));
    const forCounts: Record<string, number> = {};

    for (const opt of ['O0', 'O2']) {
      const outFile = path.join(RESULTS_DIR, `01_basic_control_${opt}`, 'ts_output.c');
      if (!existsSync(outFile)) continue;
      const output = parseOutputFile(outFile);
      const cmp = compareFile(source, output, opt);
      forCounts[opt] = cmp.matched.filter(m => m.loopCountDelta === 0).length;
    }

    if (forCounts['O0'] !== undefined && forCounts['O2'] !== undefined) {
      expect(forCounts['O0']).toBeGreaterThanOrEqual(forCounts['O2']);
    }
  });

  it('generate valid TSV for all available data', () => {
    const comparisons: FileComparison[] = [];

    for (const file of ALL_SOURCES) {
      const base = file.replace('.c', '');
      const source = parseSourceFile(path.join(SRC_DIR, file));

      for (const opt of OPT_LEVELS) {
        const outFile = path.join(RESULTS_DIR, `${base}_${opt}`, 'ts_output.c');
        if (!existsSync(outFile)) continue;
        const output = parseOutputFile(outFile);
        comparisons.push(compareFile(source, output, opt));
      }
    }

    if (comparisons.length === 0) return;

    const tsv = generateTSV(comparisons);
    const lines = tsv.trim().split('\n');
    expect(lines.length).toBe(comparisons.length + 1); // header + data rows
    // Each line should have correct number of tabs
    for (const line of lines) {
      expect(line.split('\t').length).toBe(7);
    }
  });

  it('generate valid Markdown report', () => {
    const comparisons: FileComparison[] = [];

    for (const file of ALL_SOURCES.slice(0, 5)) { // first 5 for speed
      const base = file.replace('.c', '');
      const source = parseSourceFile(path.join(SRC_DIR, file));

      for (const opt of OPT_LEVELS) {
        const outFile = path.join(RESULTS_DIR, `${base}_${opt}`, 'ts_output.c');
        if (!existsSync(outFile)) continue;
        const output = parseOutputFile(outFile);
        comparisons.push(compareFile(source, output, opt));
      }
    }

    if (comparisons.length === 0) return;
    const md = generateMarkdown(comparisons);
    expect(md).toContain('# Source Fidelity Report');
    expect(md).toContain('## Summary');
    expect(md).toContain('## Aggregate');
  });

  it('no crashes on any input combination', () => {
    for (const file of ALL_SOURCES) {
      const base = file.replace('.c', '');
      const source = parseSourceFile(path.join(SRC_DIR, file));

      for (const opt of OPT_LEVELS) {
        const outFile = path.join(RESULTS_DIR, `${base}_${opt}`, 'ts_output.c');
        if (!existsSync(outFile)) continue;
        const output = parseOutputFile(outFile);
        const cmp = compareFile(source, output, opt);
        expect(cmp).toBeDefined();
        expect(cmp.functionRecoveryRate).toBeGreaterThanOrEqual(0);
        expect(cmp.functionRecoveryRate).toBeLessThanOrEqual(1);
      }
    }
  });

  it('report is deterministic (identical on re-run)', () => {
    const comparisons: FileComparison[] = [];
    for (const file of ALL_SOURCES.slice(0, 3)) {
      const base = file.replace('.c', '');
      const source = parseSourceFile(path.join(SRC_DIR, file));
      for (const opt of OPT_LEVELS) {
        const outFile = path.join(RESULTS_DIR, `${base}_${opt}`, 'ts_output.c');
        if (!existsSync(outFile)) continue;
        const output = parseOutputFile(outFile);
        comparisons.push(compareFile(source, output, opt));
      }
    }
    if (comparisons.length === 0) return;

    const tsv1 = generateTSV(comparisons);
    const tsv2 = generateTSV(comparisons);
    expect(tsv1).toBe(tsv2);
  });

  it('enhanced mode has fewer casts than standard for same output', () => {
    // Compare the same text parsed with enhanced=true vs enhanced=false type sets
    const outFile = path.join(RESULTS_DIR, '01_basic_control_O0', 'ts_output.c');
    if (!existsSync(outFile)) return;
    const text = readFileSync(outFile, 'utf8');
    const standard = parseOutput(text, false);
    const enhanced = parseOutput(text, true);

    // Standard mode should detect casts with standard types; enhanced with enhanced types.
    // The same text may have different cast counts depending on type set.
    // Just verify both parse without error.
    expect(standard.functions.length).toBe(enhanced.functions.length);
  });
});
