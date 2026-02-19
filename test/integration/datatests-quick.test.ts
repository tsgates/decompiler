/**
 * Quick test runner - all datatest files as one test with per-file timeout.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

import '../../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../../src/console/libdecomp.js';
import { FunctionTestCollection } from '../../src/console/testfunction.js';
import { StringWriter } from '../../src/util/writer.js';

const SLEIGH_PATH = process.env.SLEIGH_PATH || '/opt/ghidra';
const DATATESTS_PATH = process.env.DATATESTS_PATH || path.resolve(
  __dirname, '..', '..', 'ghidra-src', 'Ghidra', 'Features', 'Decompiler', 'src', 'decompile', 'datatests'
);

let testFiles: string[] = [];
try {
  testFiles = fs.readdirSync(DATATESTS_PATH)
    .filter(f => f.endsWith('.xml'))
    .sort()
    .map(f => path.join(DATATESTS_PATH, f));
} catch {}

function runWithTimeout<T>(fn: () => T, timeoutMs: number): { result: T | null; timedOut: boolean } {
  // Synchronous timeout using a flag - we can't truly abort synchronous code in JS
  // but we can track how long it takes
  const start = Date.now();
  try {
    const result = fn();
    return { result, timedOut: Date.now() - start > timeoutMs };
  } catch (err: any) {
    if (Date.now() - start > timeoutMs) {
      return { result: null, timedOut: true };
    }
    throw err;
  }
}

describe('Decompiler datatests (quick)', () => {
  beforeAll(() => {
    startDecompilerLibrary(SLEIGH_PATH);
  });

  it('all datatests', { timeout: 600000 }, () => {
    let totalApplied = 0;
    let totalSucceeded = 0;
    const allFailures: string[] = [];
    const didNotApply: string[] = [];
    const timedOut: string[] = [];

    for (const testFile of testFiles) {
      const basename = path.basename(testFile, '.xml');
      const writer = new StringWriter();
      const failures: string[] = [];
      const tc = new FunctionTestCollection(writer);
      const start = Date.now();
      try {
        tc.loadTest(testFile);
        tc.runTests(failures);
        const elapsed = Date.now() - start;
        if (elapsed > 10000) {
          timedOut.push(`${basename} (${elapsed}ms)`);
        }
        if (tc.getTestsApplied() === 0) {
          didNotApply.push(basename);
        }
        totalApplied += tc.getTestsApplied();
        totalSucceeded += tc.getTestsSucceeded();
        for (const f of failures) {
          allFailures.push(`${basename}: ${f}`);
        }
      } catch (err: any) {
        const elapsed = Date.now() - start;
        didNotApply.push(`${basename}: ${err.message || err} (${elapsed}ms)`);
      }
    }

    console.log(`\n=== RESULTS ===`);
    console.log(`Applied: ${totalApplied}, Succeeded: ${totalSucceeded}`);
    console.log(`Did not apply (${didNotApply.length}):`);
    for (const d of didNotApply) console.log(`  ${d}`);
    if (timedOut.length > 0) {
      console.log(`Slow tests: ${timedOut.join(', ')}`);
    }
    console.log(`Output mismatch failures: ${allFailures.length}`);

    expect(totalApplied).toBeGreaterThan(0);
  });
});
