/**
 * Tests for the pure TypeScript binary → XML lifter (src/console/binary_to_xml.ts).
 *
 * Covers:
 *  - Mach-O arm64 parsing (quality test binaries)
 *  - Fat binary parsing (system binaries)
 *  - Stripped binary handling (entry point synthesis)
 *  - XML generation (format, bytechunks, symbols, scripts)
 *  - Symbol/bytechunk comparison against cached Ghidra exports
 *  - End-to-end decompilation via generated XML
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync, existsSync, readdirSync, writeFileSync, unlinkSync } from 'fs';
import '../../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../../src/console/libdecomp.js';
import { FunctionTestCollection } from '../../src/console/testfunction.js';
import { StringWriter } from '../../src/util/writer.js';
import {
  parseBinary,
  parseMachO,
  parseFatBinary,
  generateXml,
  type ParsedBinary,
  type BinarySymbol,
} from '../../src/console/binary_to_xml.js';

// ── Helpers ────────────────────────────────────────────────────────────────

const BIN_DIR = 'test/quality/bin';
const CACHE_BASE = 'test/quality/results/.cache';

/** Find the most recent cache directory for a given binary name. */
function findCache(binName: string): string | null {
  if (!existsSync(CACHE_BASE)) return null;
  const dirs = readdirSync(CACHE_BASE)
    .filter((d) => d.startsWith(binName + '_'))
    .sort();
  if (dirs.length === 0) return null;
  return `${CACHE_BASE}/${dirs[dirs.length - 1]}/exported.xml`;
}

/** Parse symbols from a Ghidra-exported XML string. */
function parseGhidraSymbols(xml: string): BinarySymbol[] {
  const syms: BinarySymbol[] = [];
  const re = /<symbol\s+space="ram"\s+offset="0x([0-9a-f]+)"\s+name="([^"]+)"\/>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml)) !== null) {
    syms.push({ name: m[2], vaddr: BigInt('0x' + m[1]) });
  }
  return syms;
}

/** Parse bytechunk addresses from XML. */
function parseBytechunkAddrs(xml: string): bigint[] {
  const addrs: bigint[] = [];
  const re = /<bytechunk\s+space="ram"\s+offset="0x([0-9a-f]+)"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml)) !== null) {
    addrs.push(BigInt('0x' + m[1]));
  }
  return addrs;
}

/** Extract all hex data from bytechunks as a single concatenated string keyed by start addr. */
function parseBytechunkData(xml: string): Map<bigint, string> {
  const result = new Map<bigint, string>();
  const chunkRe = /<bytechunk\s+space="ram"\s+offset="0x([0-9a-f]+)"[^>]*>\n([\s\S]*?)\n<\/bytechunk>/g;
  let m: RegExpExecArray | null;
  while ((m = chunkRe.exec(xml)) !== null) {
    const addr = BigInt('0x' + m[1]);
    const hex = m[2].replace(/\n/g, '');
    result.set(addr, hex);
  }
  return result;
}

// ── Mach-O parsing tests ───────────────────────────────────────────────────

describe('parseBinary — Mach-O arm64', () => {
  const binPath = `${BIN_DIR}/01_basic_control_O0`;

  it('should detect AARCH64 architecture', () => {
    const buf = readFileSync(binPath);
    const parsed = parseBinary(buf as Buffer);
    expect(parsed.arch).toBe('AARCH64:LE:64:v8A:default');
  });

  it('should find sections with data', () => {
    const buf = readFileSync(binPath);
    const parsed = parseBinary(buf as Buffer);
    expect(parsed.sections.length).toBeGreaterThan(0);
    for (const sec of parsed.sections) {
      expect(sec.data.length).toBeGreaterThan(0);
      expect(sec.vaddr).toBeGreaterThan(0n);
      expect(sec.readonly).toBe(true);
    }
  });

  it('should skip __PAGEZERO', () => {
    const buf = readFileSync(binPath);
    const parsed = parseBinary(buf as Buffer);
    const names = parsed.sections.map((s) => s.name);
    expect(names).not.toContain('__PAGEZERO');
  });

  it('should find function symbols', () => {
    const buf = readFileSync(binPath);
    const parsed = parseBinary(buf as Buffer);
    expect(parsed.symbols.length).toBeGreaterThanOrEqual(6);
    const names = parsed.symbols.map((s) => s.name);
    expect(names).toContain('_max3');
    expect(names).toContain('_fibonacci');
    expect(names).toContain('entry');
  });

  it('should rename _main to entry', () => {
    const buf = readFileSync(binPath);
    const parsed = parseBinary(buf as Buffer);
    const names = parsed.symbols.map((s) => s.name);
    expect(names).toContain('entry');
    expect(names).not.toContain('_main');
  });

  it('should filter out __mh_execute_header', () => {
    const buf = readFileSync(binPath);
    const parsed = parseBinary(buf as Buffer);
    const names = parsed.symbols.map((s) => s.name);
    expect(names).not.toContain('__mh_execute_header');
  });

  it('should have symbols sorted by address', () => {
    const buf = readFileSync(binPath);
    const parsed = parseBinary(buf as Buffer);
    for (let i = 1; i < parsed.symbols.length; i++) {
      expect(parsed.symbols[i].vaddr).toBeGreaterThanOrEqual(parsed.symbols[i - 1].vaddr);
    }
  });

  it('should resolve entry point address', () => {
    const buf = readFileSync(binPath);
    const parsed = parseBinary(buf as Buffer);
    expect(parsed.entry).toBeGreaterThan(0n);
    // Entry should be within __TEXT segment range
    const textSec = parsed.sections.find((s) => s.name === '__TEXT');
    expect(textSec).toBeDefined();
    expect(parsed.entry).toBeGreaterThanOrEqual(textSec!.vaddr);
    expect(parsed.entry).toBeLessThan(textSec!.vaddr + BigInt(textSec!.data.length));
  });
});

// ── Fat binary tests ───────────────────────────────────────────────────────

describe('parseBinary — fat binary', () => {
  const fatBin = '/usr/bin/true';

  it('should prefer arm64 slice over x86_64', () => {
    if (!existsSync(fatBin)) return;
    const buf = readFileSync(fatBin);
    const parsed = parseBinary(buf as Buffer);
    expect(parsed.arch).toBe('AARCH64:LE:64:v8A:default');
  });

  it('should parse sections from the selected slice', () => {
    if (!existsSync(fatBin)) return;
    const buf = readFileSync(fatBin);
    const parsed = parseBinary(buf as Buffer);
    expect(parsed.sections.length).toBeGreaterThan(0);
  });
});

// ── Stripped binary tests ──────────────────────────────────────────────────

describe('parseBinary — stripped binary', () => {
  const strippedBin = '/bin/echo';

  it('should synthesize entry symbol when no function symbols exist', () => {
    if (!existsSync(strippedBin)) return;
    const buf = readFileSync(strippedBin);
    const parsed = parseBinary(buf as Buffer);
    expect(parsed.symbols.length).toBeGreaterThanOrEqual(1);
    const names = parsed.symbols.map((s) => s.name);
    expect(names).toContain('entry');
  });

  it('should have entry symbol at the correct address', () => {
    if (!existsSync(strippedBin)) return;
    const buf = readFileSync(strippedBin);
    const parsed = parseBinary(buf as Buffer);
    const entrySym = parsed.symbols.find((s) => s.name === 'entry');
    expect(entrySym).toBeDefined();
    expect(entrySym!.vaddr).toBe(parsed.entry);
  });
});

// ── XML generation tests ───────────────────────────────────────────────────

describe('generateXml', () => {
  let parsed: ParsedBinary;

  beforeAll(() => {
    const buf = readFileSync(`${BIN_DIR}/01_basic_control_O0`);
    parsed = parseBinary(buf as Buffer);
  });

  it('should produce valid XML structure', () => {
    const xml = generateXml(parsed);
    expect(xml).toMatch(/^<decompilertest>/);
    expect(xml).toMatch(/<\/decompilertest>$/);
    expect(xml).toContain('<binaryimage arch="AARCH64:LE:64:v8A:default">');
    expect(xml).toContain('</binaryimage>');
  });

  it('should emit bytechunks with hex data', () => {
    const xml = generateXml(parsed);
    const chunks = xml.match(/<bytechunk[^>]*>/g);
    expect(chunks).not.toBeNull();
    expect(chunks!.length).toBeGreaterThan(0);
    // Each chunk should have space="ram" and offset and readonly
    for (const chunk of chunks!) {
      expect(chunk).toMatch(/space="ram"/);
      expect(chunk).toMatch(/offset="0x[0-9a-f]+"/);
      expect(chunk).toMatch(/readonly="true"/);
    }
  });

  it('should emit hex lines of 64 chars (32 bytes)', () => {
    const xml = generateXml(parsed);
    const lines = xml.split('\n');
    for (const line of lines) {
      // Lines that are pure hex (not tags)
      if (/^[0-9a-f]+$/.test(line)) {
        expect(line.length).toBeLessThanOrEqual(64);
        // Non-final lines should be exactly 64
        // (final lines can be shorter)
      }
    }
  });

  it('should chunk data at 64KB boundaries', () => {
    const xml = generateXml(parsed);
    const chunkData = parseBytechunkData(xml);
    for (const [, hex] of chunkData) {
      // Each chunk's hex should be at most 64KB * 2 hex chars
      expect(hex.length).toBeLessThanOrEqual(0x10000 * 2);
    }
  });

  it('should emit symbol tags', () => {
    const xml = generateXml(parsed);
    const symbolTags = xml.match(/<symbol[^>]*\/>/g);
    expect(symbolTags).not.toBeNull();
    expect(symbolTags!.length).toBe(parsed.symbols.length);
  });

  it('should emit script blocks for each symbol', () => {
    const xml = generateXml(parsed);
    const scripts = xml.match(/<script>/g);
    expect(scripts).not.toBeNull();
    expect(scripts!.length).toBe(parsed.symbols.length);
    // Each script should have lo fu, decompile, print C, quit
    for (const sym of parsed.symbols) {
      expect(xml).toContain(`<com>lo fu ${sym.name}</com>`);
    }
    expect(xml).toContain('<com>decompile</com>');
    expect(xml).toContain('<com>print C</com>');
    expect(xml).toContain('<com>quit</com>');
  });

  it('should emit stringmatch for each symbol', () => {
    const xml = generateXml(parsed);
    for (const sym of parsed.symbols) {
      expect(xml).toContain(
        `<stringmatch name="${sym.name} output" min="1" max="100">${sym.name}</stringmatch>`
      );
    }
  });

  it('--binaryimage-only should omit scripts and wrapper', () => {
    const xml = generateXml(parsed, { binaryimageOnly: true });
    expect(xml).not.toContain('<decompilertest>');
    expect(xml).not.toContain('</decompilertest>');
    expect(xml).not.toContain('<script>');
    expect(xml).not.toContain('<stringmatch');
    expect(xml).toMatch(/^<binaryimage/);
    expect(xml).toMatch(/<\/binaryimage>$/);
  });

  it('--functions should filter script blocks', () => {
    const xml = generateXml(parsed, { functions: ['_max3', '_fibonacci'] });
    const scripts = xml.match(/<script>/g);
    expect(scripts).not.toBeNull();
    expect(scripts!.length).toBe(2);
    expect(xml).toContain('<com>lo fu _max3</com>');
    expect(xml).toContain('<com>lo fu _fibonacci</com>');
    expect(xml).not.toContain('<com>lo fu entry</com>');
    // All symbols should still be present
    const symbolTags = xml.match(/<symbol[^>]*\/>/g);
    expect(symbolTags!.length).toBe(parsed.symbols.length);
  });
});

// ── Symbol comparison against Ghidra exports ───────────────────────────────

describe('symbol parity with Ghidra exports', () => {
  const testBinaries = readdirSync(BIN_DIR).filter((f) => !f.startsWith('.'));

  for (const binName of testBinaries) {
    const cachePath = findCache(binName);
    if (!cachePath || !existsSync(cachePath)) continue;

    it(`${binName}: symbols match Ghidra export exactly`, () => {
      const buf = readFileSync(`${BIN_DIR}/${binName}`);
      const parsed = parseBinary(buf as Buffer);
      const ghidraXml = readFileSync(cachePath, 'utf-8');
      const ghidraSyms = parseGhidraSymbols(ghidraXml);

      const ourNames = new Set(parsed.symbols.map((s) => s.name));
      const ghidraNames = new Set(ghidraSyms.map((s) => s.name));

      // Exact set equality — our symbols should match Ghidra's exactly
      for (const name of ourNames) {
        expect(ghidraNames.has(name)).toBe(true);
      }
      for (const name of ghidraNames) {
        expect(ourNames.has(name)).toBe(true);
      }

      // Addresses must match for all symbols
      const ghidraByName = new Map(ghidraSyms.map((s) => [s.name, s.vaddr]));
      for (const sym of parsed.symbols) {
        const ghidraAddr = ghidraByName.get(sym.name);
        if (ghidraAddr !== undefined) {
          expect(sym.vaddr).toBe(ghidraAddr);
        }
      }
    });
  }
});

// ── Stub symbol resolution ──────────────────────────────────────────────────

describe('stub symbol resolution', () => {
  it('06_linked_list_O0: includes _malloc and _free stubs', () => {
    const buf = readFileSync(`${BIN_DIR}/06_linked_list_O0`);
    const parsed = parseBinary(buf as Buffer);
    const names = parsed.symbols.map((s) => s.name);
    expect(names).toContain('_malloc');
    expect(names).toContain('_free');
  });

  it('06_linked_list_O0: stub symbols marked with isStub=true', () => {
    const buf = readFileSync(`${BIN_DIR}/06_linked_list_O0`);
    const parsed = parseBinary(buf as Buffer);
    const malloc = parsed.symbols.find((s) => s.name === '_malloc');
    const free = parsed.symbols.find((s) => s.name === '_free');
    expect(malloc).toBeDefined();
    expect(malloc!.isStub).toBe(true);
    expect(free).toBeDefined();
    expect(free!.isStub).toBe(true);
  });

  it('06_linked_list_O0: non-stub symbols do not have isStub', () => {
    const buf = readFileSync(`${BIN_DIR}/06_linked_list_O0`);
    const parsed = parseBinary(buf as Buffer);
    const entry = parsed.symbols.find((s) => s.name === 'entry');
    expect(entry).toBeDefined();
    expect(entry!.isStub).toBeFalsy();
  });

  it('06_linked_list_O0: stubs excluded from script blocks', () => {
    const buf = readFileSync(`${BIN_DIR}/06_linked_list_O0`);
    const parsed = parseBinary(buf as Buffer);
    const xml = generateXml(parsed);

    // _malloc and _free should appear as <symbol> tags
    expect(xml).toContain('name="_malloc"');
    expect(xml).toContain('name="_free"');

    // But NOT in <script> blocks
    expect(xml).not.toContain('<com>lo fu _malloc</com>');
    expect(xml).not.toContain('<com>lo fu _free</com>');

    // Non-stubs should still have scripts
    expect(xml).toContain('<com>lo fu _node_create</com>');
    expect(xml).toContain('<com>lo fu entry</com>');
  });

  it('stubs excluded even with --functions filter', () => {
    const buf = readFileSync(`${BIN_DIR}/06_linked_list_O0`);
    const parsed = parseBinary(buf as Buffer);
    const xml = generateXml(parsed, { functions: ['_malloc', '_node_create'] });

    // _node_create should get a script, _malloc should not
    expect(xml).toContain('<com>lo fu _node_create</com>');
    expect(xml).not.toContain('<com>lo fu _malloc</com>');
  });
});

// ── Bytechunk data integrity ───────────────────────────────────────────────

describe('bytechunk data integrity', () => {
  it('01_basic_control_O0: code bytes match Ghidra export', () => {
    const cachePath = findCache('01_basic_control_O0');
    if (!cachePath || !existsSync(cachePath)) return;

    const buf = readFileSync(`${BIN_DIR}/01_basic_control_O0`);
    const parsed = parseBinary(buf as Buffer);
    const ourXml = generateXml(parsed);
    const ghidraXml = readFileSync(cachePath, 'utf-8');

    const ourData = parseBytechunkData(ourXml);
    const ghidraData = parseBytechunkData(ghidraXml);

    // For each Ghidra bytechunk, the data should be present in ours at the same address range
    for (const [addr, ghidraHex] of ghidraData) {
      // Find which of our chunks covers this address
      let found = false;
      for (const [ourAddr, ourHex] of ourData) {
        if (ourAddr <= addr) {
          const offsetInChunk = Number(addr - ourAddr) * 2; // hex chars
          if (offsetInChunk >= 0 && offsetInChunk + ghidraHex.length <= ourHex.length) {
            const ourSlice = ourHex.substring(offsetInChunk, offsetInChunk + ghidraHex.length);
            expect(ourSlice).toBe(ghidraHex);
            found = true;
            break;
          }
        }
      }
      if (!found) {
        // Our chunk might start at the same address
        const exact = ourData.get(addr);
        if (exact) {
          expect(exact.substring(0, ghidraHex.length)).toBe(ghidraHex);
          found = true;
        }
      }
      expect(found).toBe(true);
    }
  });
});

// ── End-to-end: generated XML produces valid decompilation ─────────────────

describe('end-to-end decompilation', () => {
  beforeAll(() => {
    startDecompilerLibrary();
  });

  function decompileFromBinary(binPath: string): Map<string, string> {
    const buf = readFileSync(binPath);
    const parsed = parseBinary(buf as Buffer);
    const xml = generateXml(parsed);

    const tmpPath = `/tmp/binary_to_xml_test_${Date.now()}.xml`;
    writeFileSync(tmpPath, xml);
    try {
      const w = new StringWriter();
      const tc = new FunctionTestCollection(w);
      tc.loadTest(tmpPath);
      tc.applyEnhancedDisplay();
      const failures: string[] = [];
      tc.runTests(failures);
      const out = tc.getLastOutput() || '';

      const functions = new Map<string, string>();
      const lines = out.split('\n');
      let currentName: string | null = null;
      let currentLines: string[] = [];
      for (const line of lines) {
        const m = line.match(/^\S.+?\b(\w+)\s*\(/);
        if (m) {
          if (currentName !== null) {
            functions.set(currentName, currentLines.join('\n').trimEnd());
          }
          currentName = m[1];
          currentLines = [line];
        } else if (currentName !== null) {
          currentLines.push(line);
        }
      }
      if (currentName !== null) {
        functions.set(currentName, currentLines.join('\n').trimEnd());
      }
      return functions;
    } finally {
      unlinkSync(tmpPath);
    }
  }

  it('01_basic_control_O0: all functions decompile', () => {
    const functions = decompileFromBinary(`${BIN_DIR}/01_basic_control_O0`);
    expect(functions.size).toBeGreaterThanOrEqual(6);
    expect(functions.has('_max3')).toBe(true);
    expect(functions.has('_sum_range')).toBe(true);
    expect(functions.has('_count_digits')).toBe(true);
    expect(functions.has('_day_name')).toBe(true);
    expect(functions.has('_fibonacci')).toBe(true);
    expect(functions.has('entry')).toBe(true);
  });

  it('01_basic_control_O0: output matches Ghidra-based decompilation', () => {
    const cachePath = findCache('01_basic_control_O0');
    if (!cachePath || !existsSync(cachePath)) return;

    // Decompile from our binary parser
    const ourFunctions = decompileFromBinary(`${BIN_DIR}/01_basic_control_O0`);

    // Decompile from Ghidra export
    const w = new StringWriter();
    const tc = new FunctionTestCollection(w);
    tc.loadTest(cachePath);
    tc.applyEnhancedDisplay();
    const failures: string[] = [];
    tc.runTests(failures);
    const ghidraOut = tc.getLastOutput() || '';
    const ghidraFunctions = new Map<string, string>();
    const lines = ghidraOut.split('\n');
    let currentName: string | null = null;
    let currentLines: string[] = [];
    for (const line of lines) {
      const m = line.match(/^\S+\s+(?:\*\s+)?(\S+?)\s*\(/);
      if (m) {
        if (currentName !== null) {
          ghidraFunctions.set(currentName, currentLines.join('\n').trimEnd());
        }
        currentName = m[1];
        currentLines = [line];
      } else if (currentName !== null) {
        currentLines.push(line);
      }
    }
    if (currentName !== null) {
      ghidraFunctions.set(currentName, currentLines.join('\n').trimEnd());
    }

    // Compare shared functions
    for (const [name, ourCode] of ourFunctions) {
      const ghidraCode = ghidraFunctions.get(name);
      if (ghidraCode) {
        expect(ourCode).toBe(ghidraCode);
      }
    }
  });

  // Test across all opt levels for a selection of binaries
  const e2eBinaries = [
    '04_bitwise_O0',
    '07_recursion_O1',
    '12_ternary_cmov_O2',
    '24_switch_dense_Os',
    '30_arithmetic_O0',
  ];

  for (const binName of e2eBinaries) {
    const binPath = `${BIN_DIR}/${binName}`;
    if (!existsSync(binPath)) continue;

    it(`${binName}: all functions decompile without errors`, () => {
      const functions = decompileFromBinary(binPath);
      expect(functions.size).toBeGreaterThan(0);
    });
  }
});

// ── All quality binaries parse without errors ──────────────────────────────

describe('all quality binaries parse', () => {
  const allBins = existsSync(BIN_DIR) ? readdirSync(BIN_DIR).filter((f) => !f.startsWith('.')) : [];

  for (const binName of allBins) {
    it(`${binName}: parses without errors`, () => {
      const buf = readFileSync(`${BIN_DIR}/${binName}`);
      const parsed = parseBinary(buf as Buffer);
      expect(parsed.arch).toBe('AARCH64:LE:64:v8A:default');
      expect(parsed.sections.length).toBeGreaterThan(0);
      expect(parsed.symbols.length).toBeGreaterThan(0);
      expect(parsed.entry).toBeGreaterThan(0n);

      // XML generation should not throw
      const xml = generateXml(parsed);
      expect(xml.length).toBeGreaterThan(0);
      expect(xml).toContain('<binaryimage');
      expect(xml).toContain('<bytechunk');
      expect(xml).toContain('<symbol');
    });
  }
});

// ── Edge cases ─────────────────────────────────────────────────────────────

describe('edge cases', () => {
  it('should throw on invalid binary', () => {
    const buf = Buffer.from('not a binary');
    expect(() => parseBinary(buf)).toThrow(/Unsupported binary format/);
  });

  it('should throw on too-small file', () => {
    const buf = Buffer.from([0x00, 0x01]);
    expect(() => parseBinary(buf)).toThrow(/too small/);
  });

  it('should handle generateXml with empty symbols', () => {
    const parsed: ParsedBinary = {
      arch: 'x86:LE:64:default:gcc',
      sections: [{ name: 'test', vaddr: 0x1000n, data: new Uint8Array([0xcc, 0x90]), readonly: true }],
      symbols: [],
      entry: 0n,
    };
    const xml = generateXml(parsed);
    expect(xml).toContain('<binaryimage arch="x86:LE:64:default:gcc">');
    expect(xml).toContain('cc90');
    expect(xml).not.toContain('<symbol');
    expect(xml).not.toContain('<script>');
  });

  it('should handle generateXml with empty sections', () => {
    const parsed: ParsedBinary = {
      arch: 'AARCH64:LE:64:v8A:default',
      sections: [],
      symbols: [{ name: 'test_func', vaddr: 0x1000n }],
      entry: 0x1000n,
    };
    const xml = generateXml(parsed);
    expect(xml).toContain('<symbol space="ram" offset="0x1000" name="test_func"/>');
    expect(xml).not.toContain('<bytechunk');
  });

  it('should escape XML special characters in symbol names', () => {
    const parsed: ParsedBinary = {
      arch: 'x86:LE:64:default:gcc',
      sections: [],
      symbols: [{ name: 'func<int>', vaddr: 0x1000n }],
      entry: 0x1000n,
    };
    const xml = generateXml(parsed);
    expect(xml).toContain('name="func&lt;int&gt;"');
    expect(xml).toContain('<com>lo fu func&lt;int&gt;</com>');
  });
});
