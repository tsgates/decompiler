/**
 * @file compare-cpp.test.ts
 * @description Compares TS decompiler output against C++ reference decompiler
 * output for each datatest XML file.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

// Ensure the XmlArchitectureCapability singleton is registered
import '../../src/console/xml_arch.js';

import { startDecompilerLibrary } from '../../src/console/libdecomp.js';
import { FunctionTestCollection } from '../../src/console/testfunction.js';
import { StringWriter } from '../../src/util/writer.js';

const DATATESTS_DIR = process.env.DATATESTS_PATH || path.resolve(
  __dirname, '..', '..', 'ghidra-src', 'Ghidra', 'Features', 'Decompiler', 'src', 'decompile', 'datatests'
);
const CPP_BINARY = path.resolve(
  __dirname, '..', '..', 'ghidra-src', 'Ghidra', 'Features', 'Decompiler', 'src', 'decompile', 'cpp', 'decomp_test_dbg'
);

function runTsDecompiler(xmlFile: string): string {
  const writer = new StringWriter();
  const failures: string[] = [];
  const tc = new FunctionTestCollection(writer);
  tc.loadTest(xmlFile);
  tc.runTests(failures);
  return tc.getLastOutput();
}

function runCppDecompiler(testName: string): string {
  const result = spawnSync(CPP_BINARY, [
    '-usesleighenv', '-path', DATATESTS_DIR, 'datatests', `${testName}.xml`
  ], {
    env: { ...process.env },
    encoding: 'utf8',
    timeout: 30000,
  });
  if (result.error) {
    throw new Error(`C++ decompiler failed to spawn: ${result.error.message}`);
  }
  const stderr = result.stderr || '';
  const match = stderr.match(/=== C\+\+ DECOMPILER OUTPUT ===\n([\s\S]*?)=== END ===/);
  return match ? match[1] : '';
}

/** Trim trailing whitespace per line, trim leading/trailing blank lines.
 *  Normalize "print raw" pcode lines: replace unique IDs and fspec addresses
 *  that inherently differ between implementations. */
function normalize(s: string): string {
  return s.split('\n').map(l => {
    l = l.trimEnd();
    // Normalize pcode unique IDs: "0x00XXXX:1e" -> "0x00XXXX:_" (hex after last colon in SeqNum)
    // Also handles "i0x0010001c:14" style indirect references
    l = l.replace(/((?:^|[( \t])i?)(0x[0-9a-f]+):([0-9a-f]+)/g, '$1$2:_');
    // Normalize fspec addresses in raw pcode: "ffunc_0xNNNNNNNN" -> "ffunc_NORM"
    l = l.replace(/\bffunc_0x[0-9a-f]+\b/g, 'ffunc_NORM');
    // Normalize NAN sign: C++ outputs "NAN" but TS correctly outputs "-NAN" when sign bit is set
    l = l.replace(/-NAN\b/g, 'NAN');
    return l;
  }).join('\n').trim();
}

// Gather all test files
let testFiles: string[] = [];
try {
  testFiles = fs.readdirSync(DATATESTS_DIR)
    .filter(f => f.endsWith('.xml'))
    .sort()
    .map(f => path.join(DATATESTS_DIR, f));
} catch {
  // Directory may not exist in CI
}

describe('TS vs C++ output comparison', () => {
  beforeAll(() => {
    startDecompilerLibrary();
  });

  if (testFiles.length === 0) {
    it.skip('no datatest files found', () => {});
    return;
  }

  // Verify C++ binary exists and SLEIGHHOME is set (C++ binary needs it)
  if (!fs.existsSync(CPP_BINARY)) {
    it.skip('C++ binary decomp_test_dbg not found', () => {});
    return;
  }
  if (!process.env.SLEIGHHOME) {
    it.skip('SLEIGHHOME not set (needed for C++ binary)', () => {});
    return;
  }

  for (const testFile of testFiles) {
    const basename = path.basename(testFile, '.xml');

    it(`${basename} matches C++`, { timeout: 60000 }, () => {
      const tsOutput = normalize(runTsDecompiler(testFile));
      const cppOutput = normalize(runCppDecompiler(basename));

      if (cppOutput.length === 0) {
        throw new Error(`C++ decompiler produced no output for ${basename}`);
      }

      expect(tsOutput).toBe(cppOutput);
    });
  }
});
