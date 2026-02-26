/**
 * @file datatests.test.ts
 * @description Integration tests that run each XML datatest file through the
 * decompiler pipeline and verify the test properties pass.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

// Ensure the XmlArchitectureCapability singleton is registered
import '../../src/console/xml_arch.js';

import { startDecompilerLibrary } from '../../src/console/libdecomp.js';
import { FunctionTestCollection } from '../../src/console/testfunction.js';
import { StringWriter } from '../../src/util/writer.js';

const DATATESTS_PATH = process.env.DATATESTS_PATH || path.resolve(
  __dirname, '..', '..', 'ghidra-src', 'Ghidra', 'Features', 'Decompiler', 'src', 'decompile', 'datatests'
);

// Processors available via bundled spec files
const BUNDLED_PROCESSORS = new Set(['x86', 'AARCH64', 'ARM']);

function getProcessor(xmlPath: string): string | null {
  const content = fs.readFileSync(xmlPath, 'utf-8');
  const m = content.match(/arch="([^":]+)/);
  return m ? m[1] : null;
}

// Gather test files, filtering to architectures we have spec files for
let testFiles: string[] = [];
try {
  testFiles = fs.readdirSync(DATATESTS_PATH)
    .filter(f => f.endsWith('.xml'))
    .sort()
    .map(f => path.join(DATATESTS_PATH, f))
    .filter(f => {
      const proc = getProcessor(f);
      return proc !== null && BUNDLED_PROCESSORS.has(proc);
    });
} catch {
  // Directory may not exist in CI; tests will be skipped
}

describe('Decompiler datatests', () => {
  beforeAll(() => {
    startDecompilerLibrary();
  });

  if (testFiles.length === 0) {
    it.skip('no datatest files found', () => {});
    return;
  }

  for (const testFile of testFiles) {
    const basename = path.basename(testFile, '.xml');

    it(basename, { timeout: 30000 }, () => {
      const writer = new StringWriter();
      const failures: string[] = [];
      const tc = new FunctionTestCollection(writer);
      tc.loadTest(testFile);
      tc.runTests(failures);

      if (failures.length > 0) {
        const output = writer.toString();
        expect.soft(failures, `Test failures in ${basename}:\n${output}`).toEqual([]);
      }
      expect(tc.getTestsApplied()).toBeGreaterThan(0);
      expect(tc.getTestsSucceeded()).toBe(tc.getTestsApplied());
    });
  }
});
