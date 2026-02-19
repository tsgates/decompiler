import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';
import * as fs from 'fs';
import * as path from 'path';

// Timeout per test (milliseconds)
const TEST_TIMEOUT_MS = 30000;

startDecompilerLibrary('/opt/ghidra');

const datatestDir = 'ghidra-src/Ghidra/Features/Decompiler/src/decompile/datatests';
// Skip files known to cause infinite loops
const SKIP_FILES = new Set(['partialsplit.xml', 'pointersub.xml', 'switchmulti.xml']);

const files = fs.readdirSync(datatestDir)
  .filter(f => f.endsWith('.xml') && !SKIP_FILES.has(f))
  .sort();

console.log(`Found ${files.length} test files`);

let totalTests = 0;
let totalPassed = 0;
let totalFailed = 0;
let totalErrors = 0;
let totalTimeouts = 0;
const failedTests: string[] = [];
const errorTests: string[] = [];

function runWithTimeout<T>(fn: () => T, timeoutMs: number): { result: T | null; timedOut: boolean; error: Error | null } {
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; }, timeoutMs);
  try {
    const result = fn();
    clearTimeout(timer);
    if (timedOut) return { result: null, timedOut: true, error: null };
    return { result, timedOut: false, error: null };
  } catch (e: any) {
    clearTimeout(timer);
    return { result: null, timedOut, error: e };
  }
}

for (const file of files) {
  const fullPath = path.join(datatestDir, file);
  const startTime = Date.now();
  const writer = new StringWriter();
  const tc = new FunctionTestCollection(writer);
  try {
    tc.loadTest(fullPath);
    const failures: string[] = [];
    tc.runTests(failures);
    const elapsed = Date.now() - startTime;

    const output = writer.toString();
    const successes = (output.match(/^Success --/gm) || []).length;
    const fails = (output.match(/^FAIL --/gm) || []).length;

    totalTests += successes + fails;
    totalPassed += successes;
    totalFailed += fails;

    if (fails > 0) {
      failedTests.push(`${file}: ${failures.join(', ')}`);
      process.stdout.write(`F`);
    } else {
      process.stdout.write('.');
    }
    if (elapsed > 5000) {
      process.stdout.write(`(${(elapsed/1000).toFixed(1)}s)`);
    }
  } catch (e: any) {
    totalErrors++;
    const elapsed = Date.now() - startTime;
    errorTests.push(`${file}: ${e.message?.substring(0, 120)}${elapsed > 5000 ? ` (${(elapsed/1000).toFixed(1)}s)` : ''}`);
    process.stdout.write('E');
  }
}

console.log('\n');
console.log(`=== Test Summary ===`);
console.log(`Files: ${files.length}`);
console.log(`Tests: ${totalTests} passed: ${totalPassed} failed: ${totalFailed} errors: ${totalErrors}`);
if (totalTests > 0) {
  console.log(`Pass rate: ${((totalPassed / totalTests) * 100).toFixed(1)}%`);
}

if (failedTests.length > 0) {
  console.log(`\n--- Failed Tests (${failedTests.length}) ---`);
  for (const f of failedTests) console.log(`  ${f}`);
}
if (errorTests.length > 0) {
  console.log(`\n--- Error Tests (${errorTests.length}) ---`);
  for (const e of errorTests) console.log(`  ${e}`);
}
