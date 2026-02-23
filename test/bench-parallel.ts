/**
 * Benchmark: TS sequential vs TS parallel (cloned action tree) vs C++ reference.
 *
 * Usage:
 *   SLEIGH_PATH=... npx tsx test/bench-parallel.ts
 */
import { fileURLToPath } from 'url';
import { dirname } from 'path';
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

const SLEIGH_PATH = process.env.SLEIGH_PATH || '/opt/homebrew/Caskroom/ghidra/11.4.2-20250826/ghidra_11.4.2_PUBLIC';
const DATATESTS_DIR = process.env.DATATESTS_PATH || path.resolve(
  __dirname, '..', 'ghidra-src', 'Ghidra', 'Features', 'Decompiler', 'src', 'decompile', 'datatests'
);
const CPP_BINARY = path.resolve(
  __dirname, '..', 'ghidra-src', 'Ghidra', 'Features', 'Decompiler', 'src', 'decompile', 'cpp', 'decomp_test_dbg'
);

startDecompilerLibrary(SLEIGH_PATH);

// Gather all test files
const testFiles = fs.readdirSync(DATATESTS_DIR)
  .filter(f => f.endsWith('.xml'))
  .sort()
  .map(f => path.join(DATATESTS_DIR, f));

console.log(`Found ${testFiles.length} test files\n`);

// --- Utility ---
function formatMs(ms: number): string {
  if (ms < 1) return `${(ms * 1000).toFixed(0)}µs`;
  if (ms < 1000) return `${ms.toFixed(1)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

function normalize(s: string): string {
  return s.split('\n').map(l => {
    l = l.trimEnd();
    l = l.replace(/((?:^|[( \t])i?)(0x[0-9a-f]+):([0-9a-f]+)/g, '$1$2:_');
    l = l.replace(/\bffunc_0x[0-9a-f]+\b/g, 'ffunc_NORM');
    l = l.replace(/-NAN\b/g, 'NAN');
    return l;
  }).join('\n').trim();
}

// --- TS Sequential (standard - shared action tree with reset) ---
interface TestResult {
  name: string;
  timeMs: number;
  output: string;
  success: boolean;
}

function runTsSequential(testFile: string): TestResult {
  const basename = path.basename(testFile, '.xml');
  const start = performance.now();
  const writer = new StringWriter();
  const failures: string[] = [];
  const tc = new FunctionTestCollection(writer);
  tc.loadTest(testFile);
  tc.runTests(failures);
  const elapsed = performance.now() - start;
  const output = tc.getLastOutput();
  return { name: basename, timeMs: elapsed, output, success: failures.length === 0 };
}

// --- C++ reference ---
function runCpp(testFile: string): TestResult {
  const basename = path.basename(testFile, '.xml');
  const start = performance.now();
  const result = spawnSync(CPP_BINARY, [
    '-usesleighenv', '-path', DATATESTS_DIR, 'datatests', `${basename}.xml`
  ], {
    env: { ...process.env, SLEIGHHOME: SLEIGH_PATH },
    encoding: 'utf8',
    timeout: 60000,
  });
  const elapsed = performance.now() - start;
  const stderr = result.stderr || '';
  const match = stderr.match(/=== C\+\+ DECOMPILER OUTPUT ===\n([\s\S]*?)=== END ===/);
  const output = match ? match[1] : '';
  return { name: basename, timeMs: elapsed, output, success: !result.error };
}

// =====================================================================
// Run benchmarks
// =====================================================================

// Warmup: run one test to JIT-warm the TS engine
{
  console.log('Warming up TS engine...');
  if (testFiles.length > 0) {
    runTsSequential(testFiles[0]);
    runTsSequential(testFiles[0]); // second warmup
  }
  console.log('');
}

// --- Benchmark: TS sequential ---
console.log('=== TS Sequential (shared action tree) ===');
const tsResults: TestResult[] = [];
const tsSeqStart = performance.now();
for (const f of testFiles) {
  const r = runTsSequential(f);
  tsResults.push(r);
  process.stdout.write('.');
}
const tsSeqTotal = performance.now() - tsSeqStart;
console.log(`\nTotal: ${formatMs(tsSeqTotal)}\n`);

// --- Benchmark: C++ reference ---
const hasCpp = fs.existsSync(CPP_BINARY);
let cppResults: TestResult[] = [];
let cppTotal = 0;

if (hasCpp) {
  console.log('=== C++ Reference ===');
  const cppStart = performance.now();
  for (const f of testFiles) {
    const r = runCpp(f);
    cppResults.push(r);
    process.stdout.write('.');
  }
  cppTotal = performance.now() - cppStart;
  console.log(`\nTotal: ${formatMs(cppTotal)}\n`);
} else {
  console.log('C++ binary not found, skipping C++ benchmark.\n');
}

// =====================================================================
// Correctness validation
// =====================================================================

if (hasCpp) {
  console.log('=== Correctness Validation (TS vs C++) ===');
  let match = 0;
  let mismatch = 0;
  const mismatches: string[] = [];

  for (let i = 0; i < testFiles.length; i++) {
    const tsNorm = normalize(tsResults[i].output);
    const cppNorm = normalize(cppResults[i].output);
    if (tsNorm === cppNorm) {
      match++;
    } else {
      mismatch++;
      mismatches.push(tsResults[i].name);
    }
  }

  console.log(`Match: ${match}/${testFiles.length} (${((match/testFiles.length)*100).toFixed(1)}%)`);
  if (mismatch > 0) {
    console.log(`Mismatch: ${mismatches.join(', ')}`);
  }
  console.log('');
}

// =====================================================================
// Per-test timing table
// =====================================================================

console.log('=== Per-Test Timing ===');
console.log(`${'Test'.padEnd(30)} ${'TS(ms)'.padStart(10)} ${hasCpp ? 'C++(ms)'.padStart(10) : ''} ${hasCpp ? 'Ratio'.padStart(8) : ''}`);
console.log('-'.repeat(hasCpp ? 60 : 42));

let tsTotalDecomp = 0;
let cppTotalDecomp = 0;
const ratios: number[] = [];
const perTest: Array<{name: string, ts: number, cpp: number, ratio: number}> = [];

for (let i = 0; i < testFiles.length; i++) {
  const ts = tsResults[i].timeMs;
  tsTotalDecomp += ts;
  let cpp = 0;
  let ratio = 0;
  if (hasCpp && cppResults[i]) {
    cpp = cppResults[i].timeMs;
    cppTotalDecomp += cpp;
    ratio = cpp > 0 ? ts / cpp : 0;
    ratios.push(ratio);
  }
  perTest.push({ name: tsResults[i].name, ts, cpp, ratio });
}

// Sort by TS time descending (slowest first)
perTest.sort((a, b) => b.ts - a.ts);
for (const t of perTest) {
  const tsStr = t.ts.toFixed(1).padStart(10);
  const cppStr = hasCpp ? t.cpp.toFixed(1).padStart(10) : '';
  const ratioStr = hasCpp ? (t.ratio > 0 ? `${t.ratio.toFixed(1)}x` : 'N/A').padStart(8) : '';
  console.log(`${t.name.padEnd(30)} ${tsStr} ${cppStr} ${ratioStr}`);
}

console.log('-'.repeat(hasCpp ? 60 : 42));

// =====================================================================
// Summary statistics
// =====================================================================

console.log('\n=== Summary ===');
console.log(`Test files:       ${testFiles.length}`);
console.log(`TS total time:    ${formatMs(tsSeqTotal)}`);
console.log(`TS per-test avg:  ${formatMs(tsTotalDecomp / testFiles.length)}`);

if (hasCpp) {
  console.log(`C++ total time:   ${formatMs(cppTotal)}`);
  console.log(`C++ per-test avg: ${formatMs(cppTotalDecomp / testFiles.length)}`);

  const avgRatio = ratios.reduce((a, b) => a + b, 0) / ratios.length;
  const medianRatio = ratios.sort((a, b) => a - b)[Math.floor(ratios.length / 2)];
  const minRatio = Math.min(...ratios);
  const maxRatio = Math.max(...ratios);
  const overallRatio = tsSeqTotal / cppTotal;

  console.log(`\nTS/C++ overall:   ${overallRatio.toFixed(2)}x`);
  console.log(`TS/C++ per-test:  avg=${avgRatio.toFixed(2)}x  median=${medianRatio.toFixed(2)}x  min=${minRatio.toFixed(2)}x  max=${maxRatio.toFixed(2)}x`);
}

// Memory
const mem = process.memoryUsage();
console.log(`\nMemory (TS process):`);
console.log(`  RSS:       ${(mem.rss / (1024*1024)).toFixed(1)} MB`);
console.log(`  Heap used: ${(mem.heapUsed / (1024*1024)).toFixed(1)} MB`);
console.log(`  Heap total:${(mem.heapTotal / (1024*1024)).toFixed(1)} MB`);
