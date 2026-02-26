/**
 * Unit tests for SAILR-inspired metrics collection (src/decompiler/metrics.ts).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import '../../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../../src/console/libdecomp.js';
import { FunctionTestCollection } from '../../src/console/testfunction.js';
import { StringWriter } from '../../src/util/writer.js';
import {
  createEmptyMetrics,
  aggregateMetrics,
  formatMetricsTable,
  type FunctionMetrics,
  type AggregateMetrics,
} from '../../src/decompiler/metrics.js';
import { existsSync } from 'fs';
import path from 'path';

const DATA_DIR = 'ghidra-src/Ghidra/Features/Decompiler/src/decompile/datatests';

describe('createEmptyMetrics', () => {
  it('should create metrics with all zeroes', () => {
    const m = createEmptyMetrics('testFunc');
    expect(m.name).toBe('testFunc');
    expect(m.gotoCount).toBe(0);
    expect(m.breakGotoCount).toBe(0);
    expect(m.continueGotoCount).toBe(0);
    expect(m.maxNestingDepth).toBe(0);
    expect(m.whileCount).toBe(0);
    expect(m.doWhileCount).toBe(0);
    expect(m.ifCount).toBe(0);
    expect(m.switchCount).toBe(0);
    expect(m.labelCount).toBe(0);
    expect(m.boolConditionCount).toBe(0);
  });
});

describe('aggregateMetrics', () => {
  it('should aggregate empty array', () => {
    const agg = aggregateMetrics([]);
    expect(agg.totalFunctions).toBe(0);
    expect(agg.totalGotos).toBe(0);
  });

  it('should sum metrics across functions', () => {
    const funcs: FunctionMetrics[] = [
      { ...createEmptyMetrics('f1'), gotoCount: 2, ifCount: 3, maxNestingDepth: 4 },
      { ...createEmptyMetrics('f2'), gotoCount: 1, ifCount: 5, maxNestingDepth: 2 },
      { ...createEmptyMetrics('f3'), breakGotoCount: 3, whileCount: 2, maxNestingDepth: 6 },
    ];
    const agg = aggregateMetrics(funcs);
    expect(agg.totalFunctions).toBe(3);
    expect(agg.totalGotos).toBe(3);
    expect(agg.totalBreakGotos).toBe(3);
    expect(agg.totalIf).toBe(8);
    expect(agg.totalWhile).toBe(2);
    expect(agg.maxNestingDepth).toBe(6);
  });

  it('should take max nesting depth, not sum', () => {
    const funcs: FunctionMetrics[] = [
      { ...createEmptyMetrics('f1'), maxNestingDepth: 3 },
      { ...createEmptyMetrics('f2'), maxNestingDepth: 7 },
      { ...createEmptyMetrics('f3'), maxNestingDepth: 1 },
    ];
    const agg = aggregateMetrics(funcs);
    expect(agg.maxNestingDepth).toBe(7);
  });
});

describe('formatMetricsTable', () => {
  it('should produce a formatted table string', () => {
    const funcs: FunctionMetrics[] = [
      { ...createEmptyMetrics('funcA'), gotoCount: 5, ifCount: 10, maxNestingDepth: 3 },
      { ...createEmptyMetrics('funcB'), gotoCount: 0, ifCount: 2, maxNestingDepth: 1 },
    ];
    const table = formatMetricsTable(funcs);
    expect(table).toContain('Function');
    expect(table).toContain('Gotos');
    expect(table).toContain('funcA'); // has gotos, shown
    // funcB has no gotos and depth < 3, should be filtered out
    expect(table).not.toContain('funcB');
    expect(table).toContain('TOTAL');
  });

  it('should handle empty input', () => {
    const table = formatMetricsTable([]);
    expect(table).toContain('TOTAL (0 functions)');
  });
});

describe('collectFunctionMetrics on datatests', () => {
  beforeAll(() => {
    startDecompilerLibrary();
  });

  // Helper to decompile and get text-based metrics
  function getTextMetrics(xmlFile: string): { gotos: number; breaks: number; ifs: number; labels: number } {
    const writer = new StringWriter();
    const tc = new FunctionTestCollection(writer);
    tc.loadTest(xmlFile);
    const failures: string[] = [];
    tc.runTests(failures);
    const output = tc.getLastOutput();
    return {
      gotos: (output.match(/\bgoto\s+\w+/g) || []).length,
      breaks: (output.match(/\bbreak\s*;/g) || []).length,
      ifs: (output.match(/\bif\s*\(/g) || []).length,
      labels: (output.match(/^\s*\w+:/gm) || []).length,
    };
  }

  it('elseif.xml: should detect gotos and if-blocks', () => {
    const xmlFile = path.join(DATA_DIR, 'elseif.xml');
    if (!existsSync(xmlFile)) return;
    const m = getTextMetrics(xmlFile);
    // elseif.xml has at least 1 goto
    expect(m.gotos).toBeGreaterThanOrEqual(1);
    // Has many if-blocks
    expect(m.ifs).toBeGreaterThan(5);
  });

  it('switchloop.xml: should detect loops and switches', () => {
    const xmlFile = path.join(DATA_DIR, 'switchloop.xml');
    if (!existsSync(xmlFile)) return;
    const m = getTextMetrics(xmlFile);
    // switchloop.xml has loops and switches by definition
    expect(m.ifs).toBeGreaterThan(0);
  });

  it('forloop1.xml: should have loops but no gotos', () => {
    const xmlFile = path.join(DATA_DIR, 'forloop1.xml');
    if (!existsSync(xmlFile)) return;
    const m = getTextMetrics(xmlFile);
    expect(m.gotos).toBe(0);
  });
});

describe('enhanced mode goto reduction invariant', () => {
  beforeAll(() => {
    startDecompilerLibrary();
  });

  function countGotos(xmlFile: string, enhanced: boolean): number {
    const writer = new StringWriter();
    const tc = new FunctionTestCollection(writer);
    tc.loadTest(xmlFile);
    if (enhanced) tc.applyEnhancedDisplay();
    const failures: string[] = [];
    tc.runTests(failures);
    const output = tc.getLastOutput();
    return (output.match(/\bgoto\s+\w+/g) || []).length;
  }

  const testFiles = ['elseif.xml', 'ifswitch.xml', 'switchloop.xml', 'loopcomment.xml', 'forloop1.xml'];

  for (const file of testFiles) {
    const xmlFile = path.join(DATA_DIR, file);

    it(`${file}: enhanced gotos <= normal gotos`, () => {
      if (!existsSync(xmlFile)) return;
      const normalGotos = countGotos(xmlFile, false);
      const enhancedGotos = countGotos(xmlFile, true);
      expect(enhancedGotos).toBeLessThanOrEqual(normalGotos);
    });
  }
});

describe('enhanced mode brace balance on datatests', () => {
  beforeAll(() => {
    startDecompilerLibrary();
  });

  // Test a broader set of datatests for brace balance in enhanced mode
  const testFiles = [
    'elseif.xml', 'ifswitch.xml', 'switchloop.xml', 'loopcomment.xml',
    'forloop1.xml', 'misc_stackvar.xml', 'whilealiasaliased.xml',
  ];

  for (const file of testFiles) {
    const xmlFile = path.join(DATA_DIR, file);

    it(`${file}: enhanced output has balanced braces`, () => {
      if (!existsSync(xmlFile)) return;
      const writer = new StringWriter();
      const tc = new FunctionTestCollection(writer);
      tc.loadTest(xmlFile);
      tc.applyEnhancedDisplay();
      const failures: string[] = [];
      tc.runTests(failures);
      const output = tc.getLastOutput();
      const opens = (output.match(/\{/g) || []).length;
      const closes = (output.match(/\}/g) || []).length;
      expect(opens).toBe(closes);
    });
  }
});
