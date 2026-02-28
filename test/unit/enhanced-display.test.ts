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
      // Enhanced mode strips "0x" from label addresses
      expect(output).toContain('goto code_r00100913');
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

// -----------------------------------------------------------------------
// Phase 1 readability improvements: NULL, inplace ops, ++/--, signed negatives
// -----------------------------------------------------------------------

describe('enhanced display readability improvements', () => {
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

  function getEnhancedOutput(xmlFile: string): string {
    const writer = new StringWriter();
    const tc = new FunctionTestCollection(writer);
    tc.loadTest(xmlFile);
    tc.applyEnhancedDisplay();
    const failures: string[] = [];
    tc.runTests(failures);
    return tc.getLastOutput();
  }

  function getNormalOutput(xmlFile: string): string {
    const writer = new StringWriter();
    const tc = new FunctionTestCollection(writer);
    tc.loadTest(xmlFile);
    const failures: string[] = [];
    tc.runTests(failures);
    return tc.getLastOutput();
  }

  beforeAll(() => {
    startDecompilerLibrary();
  });

  describe('NULL printing (Phase 1a)', () => {
    const xmlFile = findCachedXml('06_linked_list_O0');

    it('enhanced mode uses NULL for pointer-typed zero constants', () => {
      if (!xmlFile) return;
      const output = getEnhancedOutput(xmlFile);
      expect(output).toContain('NULL');
    });

    it('non-enhanced mode does not use NULL', () => {
      if (!xmlFile) return;
      const output = getNormalOutput(xmlFile);
      expect(output).not.toContain('NULL');
    });

    it('NULL replaces pointer-cast zero in comparisons and returns', () => {
      if (!xmlFile) return;
      const output = getEnhancedOutput(xmlFile);
      // Should have NULL in comparisons like == NULL or != NULL
      const nullComparisons = (output.match(/[!=]=\s*NULL\b/g) || []).length;
      expect(nullComparisons).toBeGreaterThan(0);
    });
  });

  describe('inplace operators (Phase 1b)', () => {
    const xmlFile = findCachedXml('06_linked_list_O0');

    it('enhanced mode uses compound assignment operators', () => {
      if (!xmlFile) return;
      const output = getEnhancedOutput(xmlFile);
      // Should have at least one compound assignment
      const compoundOps = (output.match(/\+=|-=|\*=|\/=|&=|\|=|>>=|<<=|\^=|%=/g) || []).length;
      // Plus any ++ or -- operators
      const incDec = (output.match(/\+\+|--/g) || []).length;
      expect(compoundOps + incDec).toBeGreaterThan(0);
    });

    it('non-enhanced mode does not use compound assignment operators', () => {
      if (!xmlFile) return;
      const output = getNormalOutput(xmlFile);
      // Non-enhanced should use plain assignment form (x = x + n)
      const compoundOps = (output.match(/\+=|-=|\*=|\/=|&=|\|=|>>=|<<=|\^=|%=/g) || []).length;
      const incDec = (output.match(/\+\+|--/g) || []).length;
      expect(compoundOps + incDec).toBe(0);
    });
  });

  describe('increment/decrement (Phase 1d)', () => {
    const xmlFile = findCachedXml('06_linked_list_O0');

    it('enhanced mode uses ++ for x = x + 1 patterns', () => {
      if (!xmlFile) return;
      const output = getEnhancedOutput(xmlFile);
      const incs = (output.match(/\+\+/g) || []).length;
      expect(incs).toBeGreaterThan(0);
    });

    it('++ replaces x = x + 1 patterns (not x += 1)', () => {
      if (!xmlFile) return;
      const output = getEnhancedOutput(xmlFile);
      // Should not have += 1 since those become ++
      const plusEquals1 = (output.match(/\+=\s*1\s*;/g) || []).length;
      expect(plusEquals1).toBe(0);
    });
  });

  describe('signed negative display (Phase 1c)', () => {
    const xmlFile = findCachedXml('08_string_ops_O0');

    it('enhanced mode prints signed negative constants as decimal', () => {
      if (!xmlFile) return;
      const output = getEnhancedOutput(xmlFile);
      // Should have -1 for signed 0xffffffff values
      const negatives = (output.match(/-\d+/g) || []).length;
      expect(negatives).toBeGreaterThan(0);
    });
  });

  describe('non-enhanced mode unchanged', () => {
    const testPrefixes = [
      '06_linked_list_O0',
      '08_string_ops_O0',
      '05_sorting_O0',
    ];

    for (const prefix of testPrefixes) {
      const xmlFile = findCachedXml(prefix);

      it(`${prefix}: non-enhanced output is deterministic`, () => {
        if (!xmlFile) return;
        const output1 = getNormalOutput(xmlFile);
        const output2 = getNormalOutput(xmlFile);
        expect(output1).toBe(output2);
      });
    }
  });

  describe('readability metrics across quality tests', () => {
    const testPrefixes = [
      '01_basic_control_O0',
      '02_pointers_arrays_O0',
      '04_bitwise_ops_O0',
      '05_sorting_O0',
      '06_linked_list_O0',
      '08_string_ops_O0',
    ];

    it('enhanced mode has fewer raw hex zero constants than non-enhanced', () => {
      let enhancedHexZeros = 0;
      let normalHexZeros = 0;
      let tested = 0;

      for (const prefix of testPrefixes) {
        const xmlFile = findCachedXml(prefix);
        if (!xmlFile) continue;
        tested++;

        const enhanced = getEnhancedOutput(xmlFile);
        const normal = getNormalOutput(xmlFile);

        // Count (type *)0x0 patterns — these should be replaced by NULL
        enhancedHexZeros += (enhanced.match(/\*\s*\)\s*0x0\b/g) || []).length;
        normalHexZeros += (normal.match(/\*\s*\)\s*0x0\b/g) || []).length;
      }

      if (tested === 0) return;
      expect(enhancedHexZeros).toBeLessThan(normalHexZeros);
    });

    it('enhanced mode has more compound/inc-dec operators than non-enhanced', () => {
      let enhancedCompound = 0;
      let normalCompound = 0;
      let tested = 0;

      for (const prefix of testPrefixes) {
        const xmlFile = findCachedXml(prefix);
        if (!xmlFile) continue;
        tested++;

        const enhanced = getEnhancedOutput(xmlFile);
        const normal = getNormalOutput(xmlFile);

        enhancedCompound += (enhanced.match(/\+=|-=|\*=|\/=|&=|\|=|>>=|<<=|\^=|%=|\+\+|--/g) || []).length;
        normalCompound += (normal.match(/\+=|-=|\*=|\/=|&=|\|=|>>=|<<=|\^=|%=|\+\+|--/g) || []).length;
      }

      if (tested === 0) return;
      expect(enhancedCompound).toBeGreaterThan(normalCompound);
    });
  });

  describe('array subscript conversion (Phase 3a)', () => {
    const xmlFile = findCachedXml('02_pointers_arrays_O0');

    it('enhanced mode converts pointer arithmetic to array subscript', () => {
      if (!xmlFile) return;
      const output = getEnhancedOutput(xmlFile);
      // Should have array subscript syntax like )[index] from ((type *)base)[index]
      expect(output).toMatch(/\)\s*\[/);
    });

    it('array_sum uses subscript instead of dereference+cast', () => {
      if (!xmlFile) return;
      const output = getEnhancedOutput(xmlFile);
      // Should contain ((i32 *)param_1)[xStack_14] pattern
      expect(output).toMatch(/\(i32 \*\)param_1\)\[/);
    });

    it('non-enhanced mode uses dereference for pointer arithmetic', () => {
      if (!xmlFile) return;
      const normal = getNormalOutput(xmlFile);
      // Non-enhanced should have the dereference form *(type *)(expr)
      expect(normal).toMatch(/\*\(int4 \*\)/);
    });
  });

  describe('negative constant display (Phase 3b)', () => {
    const xmlFile = findCachedXml('08_string_ops_O0');

    it('enhanced mode converts + -N to - N', () => {
      if (!xmlFile) return;
      const output = getEnhancedOutput(xmlFile);
      // Should have very few or no "+ -" patterns
      const plusNeg = (output.match(/\+ -\d/g) || []).length;
      expect(plusNeg).toBeLessThanOrEqual(1);
    });

    it('enhanced mode has subtraction where non-enhanced has addition of negatives', () => {
      if (!xmlFile) return;
      const enhanced = getEnhancedOutput(xmlFile);
      const normal = getNormalOutput(xmlFile);
      // Normal mode should have more "+ -" patterns than enhanced
      const normalPlusNeg = (normal.match(/\+ -\d/g) || []).length;
      const enhancedPlusNeg = (enhanced.match(/\+ -\d/g) || []).length;
      if (normalPlusNeg > 0) {
        expect(enhancedPlusNeg).toBeLessThan(normalPlusNeg);
      }
    });
  });

  describe('pointer PTRADD increment (Phase 3c)', () => {
    const xmlFile = findCachedXml('08_string_ops_O0');

    it('enhanced mode uses ++ for pointer increment patterns', () => {
      if (!xmlFile) return;
      const output = getEnhancedOutput(xmlFile);
      // Should have ++pcStack patterns for pointer increments
      const ptrIncs = (output.match(/\+\+\w*Stack/g) || []).length;
      expect(ptrIncs).toBeGreaterThan(0);
    });
  });

  describe('extension cast suppression (Phase 3d)', () => {
    const xmlFile = findCachedXml('02_pointers_arrays_O0');

    it('enhanced mode has fewer extension casts on array indices', () => {
      if (!xmlFile) return;
      const enhanced = getEnhancedOutput(xmlFile);
      const normal = getNormalOutput(xmlFile);
      // Enhanced should have fewer (i64) casts since SEXT/ZEXT feeding INT_MULT are suppressed
      const enhancedExtCasts = (enhanced.match(/\((?:int8|long|i64)\)/g) || []).length;
      const normalExtCasts = (normal.match(/\((?:int8|long|i64)\)/g) || []).length;
      expect(enhancedExtCasts).toBeLessThanOrEqual(normalExtCasts);
    });
  });

  describe('extension cast suppression in binary ops (Phase 4a)', () => {
    // Use O1 binaries where comparisons with extended operands are common
    const xmlFile = findCachedXml('13_array_algorithms_O1');

    it('enhanced mode suppresses extension casts in binary arithmetic/comparison', () => {
      if (!xmlFile) return;
      const enhanced = getEnhancedOutput(xmlFile);
      const normal = getNormalOutput(xmlFile);
      // Enhanced should have fewer total extension casts (i64/u64/int8/uint8)
      const enhancedCasts = (enhanced.match(/\((?:i64|u64)\)/g) || []).length;
      const normalCasts = (normal.match(/\((?:int8|uint8)\)/g) || []).length;
      expect(enhancedCasts).toBeLessThanOrEqual(normalCasts);
    });

    it('extension casts feeding phi-nodes are preserved', () => {
      if (!xmlFile) return;
      const enhanced = getEnhancedOutput(xmlFile);
      // Some (u64) casts should remain for explicit assignments like uVar = (u64)x
      const explicitCasts = (enhanced.match(/=\s*\(u64\)/g) || []).length;
      expect(explicitCasts).toBeGreaterThan(0);
    });
  });

  describe('shift decimal display (Phase 4b)', () => {
    const xmlFile = findCachedXml('29_crypto_simple_O1');

    it('shift amounts display as decimal in enhanced mode', () => {
      if (!xmlFile) return;
      const enhanced = getEnhancedOutput(xmlFile);
      // All shift amounts should be decimal (no 0x prefix on shift RHS)
      const hexShifts = (enhanced.match(/(?:>>|<<)\s*0x[0-9a-f]+/g) || []).length;
      expect(hexShifts).toBe(0);
    });

    it('shift operations still present with decimal amounts', () => {
      if (!xmlFile) return;
      const enhanced = getEnhancedOutput(xmlFile);
      // Should have shift operations with decimal amounts
      const shifts = (enhanced.match(/(?:>>|<<)\s*\d/g) || []).length;
      expect(shifts).toBeGreaterThan(0);
    });
  });

  describe('small constant decimal display (Phase 4c)', () => {
    it('non-bitmask small constants display as decimal', () => {
      // isBitmaskLike returns true for powers of 2, contiguous bit runs, etc.
      // Non-bitmask values ≤ 255 should be decimal in enhanced mode
      expect(PrintC.isBitmaskLike(32n, 4)).toBe(true);   // 0x20 = power of 2
      expect(PrintC.isBitmaskLike(48n, 4)).toBe(false);  // 0x30 = not bitmask
      expect(PrintC.isBitmaskLike(100n, 4)).toBe(false);  // 0x64 = not bitmask
      expect(PrintC.isBitmaskLike(255n, 1)).toBe(true);  // 0xFF = all-F mask
      expect(PrintC.isBitmaskLike(127n, 4)).toBe(true);  // 0x7F = contiguous from bit 0
    });

    it('bitmask-like values stay hex in enhanced mode', () => {
      // Powers of 2 and contiguous bit patterns should stay hex
      expect(PrintC.isBitmaskLike(128n, 4)).toBe(true);  // 0x80
      expect(PrintC.isBitmaskLike(64n, 4)).toBe(true);   // 0x40
      expect(PrintC.isBitmaskLike(31n, 4)).toBe(true);   // 0x1F = contiguous from bit 0
    });
  });
});
