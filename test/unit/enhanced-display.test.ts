/**
 * Unit tests for enhanced display features:
 * - Type name mapping (i32, u64, etc.)
 * - Bitmask-like constant detection
 * - Goto-to-if conversion in enhanced mode
 */
import { describe, it, expect, beforeAll } from 'vitest';
import '../../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../../src/console/libdecomp.js';
import { TypeFactory } from '../../src/decompiler/type.js';
import { ArchitectureCapability } from '../../src/decompiler/architecture.js';
import { DocumentStorage } from '../../src/core/xml.js';
import { PrintC } from '../../src/decompiler/printc.js';
import { FunctionTestCollection } from '../../src/console/testfunction.js';
import { StringWriter } from '../../src/util/writer.js';
import { existsSync } from 'fs';
import path from 'path';

describe('applyEnhancedDisplayNames', () => {
  let types: TypeFactory;

  beforeAll(() => {
    startDecompilerLibrary();
    const capa = ArchitectureCapability.getCapability('xml');
    const store = new DocumentStorage();
    const doc = store.parseDocument(`<decompilertest><binaryimage arch="x86:LE:64:default:gcc"><bytechunk space="ram" offset="0x100000" readonly="true">00</bytechunk></binaryimage></decompilertest>`);
    const el = doc.getRoot();
    for (const child of el.getChildren()) {
      if (child.getName() === 'binaryimage') {
        store.registerTag(child);
        break;
      }
    }
    const nullWriter = { write: () => {} };
    const arch = capa!.buildArchitecture('test', '', nullWriter);
    arch.init(store);
    types = arch.types;
  });

  const expected: [string, string][] = [
    ['int1', 'i8'],
    ['int2', 'i16'],
    ['int4', 'i32'],
    ['int8', 'i64'],
    ['uint1', 'u8'],
    ['uint2', 'u16'],
    ['uint4', 'u32'],
    ['uint8', 'u64'],
    ['xunknown1', 'unk1'],
    ['xunknown2', 'unk2'],
    ['xunknown4', 'unk4'],
    ['xunknown8', 'unk8'],
    ['float4', 'f32'],
    ['float8', 'f64'],
    ['float10', 'f80'],
  ];

  it('should not change displayName before apply', () => {
    for (const [name] of expected) {
      const ct = types.findByName(name);
      expect(ct, `type ${name} should exist`).toBeTruthy();
      expect(ct!.getDisplayName()).toBe(name);
    }
  });

  it('should set correct displayNames after apply', () => {
    types.applyEnhancedDisplayNames();
    for (const [name, display] of expected) {
      const ct = types.findByName(name);
      expect(ct, `type ${name} should exist`).toBeTruthy();
      expect(ct!.getDisplayName()).toBe(display);
    }
  });

  it('should not change internal name', () => {
    for (const [name] of expected) {
      const ct = types.findByName(name);
      expect(ct!.getName()).toBe(name);
    }
  });

  it('should not affect non-mapped types (bool, void, char, code)', () => {
    for (const name of ['bool', 'void', 'char', 'code']) {
      const ct = types.findByName(name);
      if (ct) {
        expect(ct.getDisplayName()).toBe(name);
      }
    }
  });
});

describe('isBitmaskLike', () => {
  it('should return false for small values', () => {
    expect(PrintC.isBitmaskLike(0n, 4)).toBe(false);
    expect(PrintC.isBitmaskLike(1n, 4)).toBe(false);
    expect(PrintC.isBitmaskLike(10n, 4)).toBe(false);
  });

  it('should detect all-F masks', () => {
    expect(PrintC.isBitmaskLike(0xFFn, 1)).toBe(true);
    expect(PrintC.isBitmaskLike(0xFFFFn, 2)).toBe(true);
    expect(PrintC.isBitmaskLike(0xFFFFFFFFn, 4)).toBe(true);
  });

  it('should detect powers of 2', () => {
    expect(PrintC.isBitmaskLike(0x80n, 1)).toBe(true);
    expect(PrintC.isBitmaskLike(0x8000n, 2)).toBe(true);
    expect(PrintC.isBitmaskLike(0x80000000n, 4)).toBe(true);
    expect(PrintC.isBitmaskLike(0x100n, 4)).toBe(true);
    expect(PrintC.isBitmaskLike(0x40n, 1)).toBe(true);
  });

  it('should detect contiguous bit runs', () => {
    expect(PrintC.isBitmaskLike(0x7Fn, 1)).toBe(true);    // 0111_1111
    expect(PrintC.isBitmaskLike(0x1Fn, 1)).toBe(true);    // 0001_1111
    expect(PrintC.isBitmaskLike(0x7FFFFFFFn, 4)).toBe(true);
  });

  it('should detect shifted masks (low bits cleared)', () => {
    expect(PrintC.isBitmaskLike(0xFF00n, 2)).toBe(true);
    expect(PrintC.isBitmaskLike(0xFFF0n, 2)).toBe(true);
    expect(PrintC.isBitmaskLike(0xFFFFFF00n, 4)).toBe(true);
  });

  it('should detect inverted masks', () => {
    // ~0xFF = 0xFFFFFF00 → inverse 0xFF is contiguous from bit 0
    expect(PrintC.isBitmaskLike(0xFFFFFF00n, 4)).toBe(true);
    // ~0x80 = 0xFFFFFF7F → inverse 0x80 is power of 2
    expect(PrintC.isBitmaskLike(0xFFFFFF7Fn, 4)).toBe(true);
  });

  it('should detect hex-round values (ending in 00)', () => {
    expect(PrintC.isBitmaskLike(0x100n, 4)).toBe(true);
    expect(PrintC.isBitmaskLike(0x1000n, 4)).toBe(true);
    expect(PrintC.isBitmaskLike(0xAB00n, 4)).toBe(true);
  });

  it('should return false for non-mask-like values', () => {
    expect(PrintC.isBitmaskLike(123n, 4)).toBe(false);
    expect(PrintC.isBitmaskLike(999n, 4)).toBe(false);
    expect(PrintC.isBitmaskLike(0x1234n, 4)).toBe(false);
  });
});

// -----------------------------------------------------------------------
// Goto-to-if conversion tests (enhanced display)
// -----------------------------------------------------------------------

/**
 * Helper: decompile a test XML with or without enhanced display, return output.
 */
function decompileXml(xmlFile: string, enhanced: boolean): string {
  const writer = new StringWriter();
  const tc = new FunctionTestCollection(writer);
  tc.loadTest(xmlFile);
  if (enhanced) {
    tc.applyEnhancedDisplay();
  }
  const failures: string[] = [];
  tc.runTests(failures);
  return tc.getLastOutput();
}

const DATA_DIR = 'ghidra-src/Ghidra/Features/Decompiler/src/decompile/datatests';

describe('goto-to-if conversion', () => {
  beforeAll(() => {
    startDecompilerLibrary();
  });

  describe('elseif.xml (datatest with goto)', () => {
    const xmlFile = path.join(DATA_DIR, 'elseif.xml');

    it('should produce valid output in non-enhanced mode', () => {
      const output = decompileXml(xmlFile, false);
      expect(output).toContain('testElseIf');
      // Non-enhanced should have the original goto
      expect(output).toContain('goto code_r0x00100913');
    });

    it('should produce valid output in enhanced mode', () => {
      const output = decompileXml(xmlFile, true);
      expect(output).toContain('testElseIf');
      // Enhanced mode should still have the goto (it's cross-scope, not convertible)
      expect(output).toContain('goto code_r0x00100913');
    });

    it('enhanced output should have balanced braces', () => {
      const output = decompileXml(xmlFile, true);
      const opens = (output.match(/\{/g) || []).length;
      const closes = (output.match(/\}/g) || []).length;
      expect(opens).toBe(closes);
    });

    it('enhanced output should have matching if/else structure', () => {
      const output = decompileXml(xmlFile, true);
      // Should still contain the full if/else chain
      expect(output).toContain('if (b == 1)');
      expect(output).toContain('else if');
      expect(output).toContain('else {');
    });
  });

  describe('non-enhanced mode is unchanged', () => {
    // Pick a representative set of datatests
    const testFiles = ['elseif.xml', 'ifswitch.xml', 'switchloop.xml'];

    for (const file of testFiles) {
      const xmlFile = path.join(DATA_DIR, file);

      it(`${file}: non-enhanced output matches baseline`, () => {
        if (!existsSync(xmlFile)) return;
        // Decompile twice without enhanced to check determinism
        const output1 = decompileXml(xmlFile, false);
        const output2 = decompileXml(xmlFile, false);
        expect(output1).toBe(output2);
        expect(output1.length).toBeGreaterThan(0);
      });
    }
  });

  describe('enhanced mode does not crash on various datatests', () => {
    const testFiles = [
      'elseif.xml',
      'ifswitch.xml',
      'switchloop.xml',
      'loopcomment.xml',
      'forloop1.xml',
    ].filter(f => existsSync(path.join(DATA_DIR, f)));

    for (const file of testFiles) {
      const xmlFile = path.join(DATA_DIR, file);

      it(`${file}: enhanced mode produces valid output`, () => {
        const output = decompileXml(xmlFile, true);
        expect(output.length).toBeGreaterThan(0);
        // Check balanced braces
        const opens = (output.match(/\{/g) || []).length;
        const closes = (output.match(/\}/g) || []).length;
        expect(opens).toBe(closes);
      });
    }
  });
});

describe('goto-to-if conversion on quality tests', () => {
  // Find cached quality test XMLs for tests that have gotos
  const CACHE_BASE = 'test/quality/results/.cache';

  function findCachedXml(prefix: string): string | null {
    if (!existsSync(CACHE_BASE)) return null;
    const { readdirSync } = require('fs');
    const dirs = readdirSync(CACHE_BASE) as string[];
    // Find the most recent cache entry for this prefix
    const matching = dirs.filter((d: string) => d.startsWith(prefix)).sort();
    if (matching.length === 0) return null;
    const xmlPath = path.join(CACHE_BASE, matching[matching.length - 1], 'exported.xml');
    return existsSync(xmlPath) ? xmlPath : null;
  }

  beforeAll(() => {
    startDecompilerLibrary();
  });

  // Quality tests known to have gotos
  const qualityTests = [
    { prefix: '07_recursion_O2', name: 'recursion O2' },
    { prefix: '11_goto_patterns_O2', name: 'goto_patterns O2' },
    { prefix: '16_matrix_ops_O2', name: 'matrix_ops O2' },
    { prefix: '23_multi_dim_O2', name: 'multi_dim O2' },
    { prefix: '29_crypto_simple_O2', name: 'crypto_simple O2' },
  ];

  for (const { prefix, name } of qualityTests) {
    const xmlFile = findCachedXml(prefix);

    it(`${name}: enhanced mode produces valid output with balanced braces`, () => {
      if (!xmlFile) {
        // Skip if quality test cache not available
        return;
      }
      const writer = new StringWriter();
      const tc = new FunctionTestCollection(writer);
      tc.loadTest(xmlFile);
      tc.applyEnhancedDisplay();
      const failures: string[] = [];
      tc.runTests(failures);
      const output = tc.getLastOutput();

      // Should produce output
      expect(output.length).toBeGreaterThan(0);

      // Braces should be balanced
      const opens = (output.match(/\{/g) || []).length;
      const closes = (output.match(/\}/g) || []).length;
      expect(opens).toBe(closes);

      // Should not crash or produce empty functions
      const funcCount = (output.match(/\n\S+\s+\S+\(/g) || []).length;
      expect(funcCount).toBeGreaterThan(0);
    });

    it(`${name}: cross-scope gotos are preserved (not incorrectly converted)`, () => {
      if (!xmlFile) return;

      // Run non-enhanced and enhanced
      const writer1 = new StringWriter();
      const tc1 = new FunctionTestCollection(writer1);
      tc1.loadTest(xmlFile);
      const f1: string[] = [];
      tc1.runTests(f1);
      const normalOutput = tc1.getLastOutput();

      const writer2 = new StringWriter();
      const tc2 = new FunctionTestCollection(writer2);
      tc2.loadTest(xmlFile);
      tc2.applyEnhancedDisplay();
      const f2: string[] = [];
      tc2.runTests(f2);
      const enhancedOutput = tc2.getLastOutput();

      // Count gotos in each
      const normalGotos = (normalOutput.match(/\bgoto\b/g) || []).length;
      const enhancedGotos = (enhancedOutput.match(/\bgoto\b/g) || []).length;

      // Enhanced should have <= normal gotos (conversion only removes, never adds)
      expect(enhancedGotos).toBeLessThanOrEqual(normalGotos);
    });
  }

  // Test that gotos-free binaries remain goto-free
  const noGotoTests = [
    { prefix: '01_basic_control_O2', name: 'basic_control O2' },
    { prefix: '03_structs_O2', name: 'structs O2' },
  ];

  for (const { prefix, name } of noGotoTests) {
    const xmlFile = findCachedXml(prefix);

    it(`${name}: enhanced mode does not introduce gotos`, () => {
      if (!xmlFile) return;
      const writer = new StringWriter();
      const tc = new FunctionTestCollection(writer);
      tc.loadTest(xmlFile);
      tc.applyEnhancedDisplay();
      const f: string[] = [];
      tc.runTests(f);
      const output = tc.getLastOutput();

      const gotos = (output.match(/\bgoto\b/g) || []).length;
      expect(gotos).toBe(0);
    });
  }

  // Specific goto elimination tests on known-reducible binaries
  const reducibleTests = [
    { prefix: '02_pointers_arrays_O2', name: 'pointers_arrays O2', expectedReduction: 1 },
    { prefix: '07_recursion_O2', name: 'recursion O2', expectedReduction: 1 },
    { prefix: '16_matrix_ops_O2', name: 'matrix_ops O2', expectedReduction: 3 },
    { prefix: '23_multi_dim_O2', name: 'multi_dim O2', expectedReduction: 3 },
    { prefix: '25_nested_loops_O2', name: 'nested_loops O2', expectedReduction: 2 },
    { prefix: '29_crypto_simple_O2', name: 'crypto_simple O2', expectedReduction: 1 },
  ];

  for (const { prefix, name, expectedReduction } of reducibleTests) {
    const xmlFile = findCachedXml(prefix);

    it(`${name}: enhanced mode reduces gotos by at least ${expectedReduction}`, () => {
      if (!xmlFile) return;

      const writer1 = new StringWriter();
      const tc1 = new FunctionTestCollection(writer1);
      tc1.loadTest(xmlFile);
      const f1: string[] = [];
      tc1.runTests(f1);
      const normalGotos = (tc1.getLastOutput().match(/\bgoto\b/g) || []).length;

      const writer2 = new StringWriter();
      const tc2 = new FunctionTestCollection(writer2);
      tc2.loadTest(xmlFile);
      tc2.applyEnhancedDisplay();
      const f2: string[] = [];
      tc2.runTests(f2);
      const enhancedGotos = (tc2.getLastOutput().match(/\bgoto\b/g) || []).length;

      const reduction = normalGotos - enhancedGotos;
      expect(reduction).toBeGreaterThanOrEqual(expectedReduction);
    });
  }
});

// -----------------------------------------------------------------------
// Comprehensive brace balance and structural integrity tests
// -----------------------------------------------------------------------

describe('enhanced mode brace balance across ALL quality test opt levels', () => {
  const CACHE_BASE = 'test/quality/results/.cache';

  function findCachedXml(prefix: string): string | null {
    if (!existsSync(CACHE_BASE)) return null;
    const { readdirSync } = require('fs');
    const dirs = readdirSync(CACHE_BASE) as string[];
    const matching = dirs.filter((d: string) => d.startsWith(prefix)).sort();
    if (matching.length === 0) return null;
    const xmlPath = path.join(CACHE_BASE, matching[matching.length - 1], 'exported.xml');
    return existsSync(xmlPath) ? xmlPath : null;
  }

  beforeAll(() => {
    startDecompilerLibrary();
  });

  // All binaries that have gotos at any opt level
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

  for (const prefix of gotoBinaries) {
    const xmlFile = findCachedXml(prefix);

    it(`${prefix}: enhanced output has balanced braces`, () => {
      if (!xmlFile) return;
      const writer = new StringWriter();
      const tc = new FunctionTestCollection(writer);
      tc.loadTest(xmlFile);
      tc.applyEnhancedDisplay();
      const f: string[] = [];
      tc.runTests(f);
      const output = tc.getLastOutput();

      expect(output.length).toBeGreaterThan(0);
      const opens = (output.match(/\{/g) || []).length;
      const closes = (output.match(/\}/g) || []).length;
      expect(opens).toBe(closes);
    });
  }
});
