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

const SLEIGH_PATH = process.env.SLEIGH_PATH || '/opt/ghidra';
const DATATESTS_PATH = process.env.DATATESTS_PATH || path.resolve(
  __dirname, '..', '..', 'ghidra-src', 'Ghidra', 'Features', 'Decompiler', 'src', 'decompile', 'datatests'
);

// Gather all test files
let testFiles: string[] = [];
try {
  testFiles = fs.readdirSync(DATATESTS_PATH)
    .filter(f => f.endsWith('.xml'))
    .sort()
    .map(f => path.join(DATATESTS_PATH, f));
} catch {
  // Directory may not exist in CI; tests will be skipped
}

describe('Decompiler datatests', () => {
  beforeAll(() => {
    startDecompilerLibrary(SLEIGH_PATH);
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
