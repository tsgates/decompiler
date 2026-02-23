/**
 * Benchmark: Action tree cloning overhead.
 *
 * Measures time to clone the action tree vs time to decompile,
 * to quantify the overhead of the parallel infrastructure.
 *
 * Usage:
 *   SLEIGH_PATH=... npx tsx test/bench-clone-time.ts
 */
import { fileURLToPath } from 'url';
import { dirname } from 'path';
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';
import * as fs from 'fs';
import * as path from 'path';

const SLEIGH_PATH = process.env.SLEIGH_PATH || '/opt/homebrew/Caskroom/ghidra/11.4.2-20250826/ghidra_11.4.2_PUBLIC';
const DATATESTS_DIR = path.resolve(
  __dirname, '..', 'ghidra-src', 'Ghidra', 'Features', 'Decompiler', 'src', 'decompile', 'datatests'
);

startDecompilerLibrary(SLEIGH_PATH);

const testFiles = fs.readdirSync(DATATESTS_DIR)
  .filter(f => f.endsWith('.xml'))
  .sort()
  .map(f => path.join(DATATESTS_DIR, f));

console.log(`Found ${testFiles.length} test files\n`);

// =====================================================================
// Use a representative test to measure clone overhead
// =====================================================================

// We need access to an Architecture's allacts to time cloneCurrentAction()
// The cleanest way is to instrument FunctionTestCollection

// First, load a test and get the architecture
{
  console.log('=== Action Tree Clone Timing (isolated) ===\n');

  // Pick a few representative test files (small, medium, large)
  const candidates = ['nestedoffset.xml', 'floatconv.xml', 'divopt.xml', 'concat.xml', 'modulo.xml'];
  const selectedFiles = candidates.map(c => path.join(DATATESTS_DIR, c)).filter(f => fs.existsSync(f));

  for (const testFile of selectedFiles) {
    const basename = path.basename(testFile, '.xml');

    // Load and run to initialize architecture
    const w = new StringWriter();
    const tc = new FunctionTestCollection(w);
    tc.loadTest(testFile);

    // Access internal architecture through the console data
    const dcp = (tc as any).dcp;
    if (!dcp || !dcp.conf || !dcp.conf.allacts) {
      console.log(`  ${basename}: could not access architecture, skipping`);
      continue;
    }

    const allacts = dcp.conf.allacts;

    // Measure clone time
    const CLONE_ITERATIONS = 100;
    const cloneStart = performance.now();
    for (let i = 0; i < CLONE_ITERATIONS; i++) {
      allacts.cloneCurrentAction();
    }
    const cloneTotal = performance.now() - cloneStart;
    const cloneAvg = cloneTotal / CLONE_ITERATIONS;

    // Measure decompile time (full test run)
    const RUN_ITERATIONS = 10;
    const runTimes: number[] = [];
    for (let i = 0; i < RUN_ITERATIONS; i++) {
      const w2 = new StringWriter();
      const tc2 = new FunctionTestCollection(w2);
      tc2.loadTest(testFile);
      const start = performance.now();
      const fl: string[] = [];
      tc2.runTests(fl);
      const elapsed = performance.now() - start;
      runTimes.push(elapsed);
    }

    // Sort and take median
    runTimes.sort((a, b) => a - b);
    const runMedian = runTimes[Math.floor(runTimes.length / 2)];

    const overheadPct = (cloneAvg / runMedian * 100);

    console.log(`  ${basename.padEnd(20)} clone: ${cloneAvg.toFixed(2)}ms  decompile: ${runMedian.toFixed(1)}ms  overhead: ${overheadPct.toFixed(1)}%`);
  }
}

// =====================================================================
// Bulk clone timing: clone 79 action trees (simulating parallel setup)
// =====================================================================
{
  console.log('\n=== Bulk Clone Timing (simulating 79-function parallel job) ===\n');

  // Load one test to get an architecture
  const w = new StringWriter();
  const tc = new FunctionTestCollection(w);
  tc.loadTest(testFiles[0]);
  const dcp = (tc as any).dcp;
  if (dcp?.conf?.allacts) {
    const allacts = dcp.conf.allacts;

    // Measure time to create 79 clones
    const ITERATIONS = 20;
    const times: number[] = [];
    for (let iter = 0; iter < ITERATIONS; iter++) {
      const start = performance.now();
      for (let i = 0; i < 79; i++) {
        allacts.cloneCurrentAction();
      }
      times.push(performance.now() - start);
    }

    times.sort((a, b) => a - b);
    const median = times[Math.floor(times.length / 2)];
    const min = times[0];
    const avg = times.reduce((a, b) => a + b) / times.length;

    console.log(`  Creating 79 action tree clones:`);
    console.log(`    Median: ${median.toFixed(1)}ms`);
    console.log(`    Min:    ${min.toFixed(1)}ms`);
    console.log(`    Avg:    ${avg.toFixed(1)}ms`);
    console.log(`    Per-clone: ${(median / 79).toFixed(2)}ms`);

    // Compare to total decompilation time
    const decompStart = performance.now();
    for (const f of testFiles) {
      const w2 = new StringWriter();
      const tc2 = new FunctionTestCollection(w2);
      tc2.loadTest(f);
      const fl: string[] = [];
      tc2.runTests(fl);
    }
    const decompTotal = performance.now() - decompStart;

    console.log(`\n  Total decompilation (79 tests): ${(decompTotal / 1000).toFixed(3)}s`);
    console.log(`  Clone overhead for 79 clones:   ${median.toFixed(1)}ms (${(median / decompTotal * 100).toFixed(1)}% of total)`);
  }
}

console.log('\n=== Memory ===');
const mem = process.memoryUsage();
console.log(`  RSS:        ${(mem.rss / (1024*1024)).toFixed(1)} MB`);
console.log(`  Heap used:  ${(mem.heapUsed / (1024*1024)).toFixed(1)} MB`);
