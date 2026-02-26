/**
 * Benchmark: sequential vs worker-thread parallel decompilation.
 *
 * Tests on:
 *   1. Datatests (79 functions across individual XML files) — sequential baseline
 *   2. Real binary XML from output/cache/ if available — worker parallelism
 *
 * Usage:
 *   npx tsx test/bench-parallel-workers.ts [binary.xml]
 */
import { fileURLToPath } from 'url';
import { dirname } from 'path';
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';
import { WorkerParallelDecompiler } from '../src/decompiler/parallel_workers.js';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

const DATATESTS_DIR = process.env.DATATESTS_PATH || path.resolve(
  __dirname, '..', 'ghidra-src', 'Ghidra', 'Features', 'Decompiler', 'src', 'decompile', 'datatests'
);

// Optional: specify a binary XML file to benchmark
const binaryXml = process.argv[2] || '';
// Max functions to benchmark (avoid OOM on huge binaries)
const MAX_FUNCTIONS = 1500;

function formatMs(ms: number): string {
  if (ms < 1) return `${(ms * 1000).toFixed(0)}us`;
  if (ms < 1000) return `${ms.toFixed(1)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

console.log(`CPUs: ${os.cpus().length} (${os.cpus()[0]?.model || 'unknown'})`);
console.log(`Platform: ${os.platform()} ${os.arch()}`);
console.log('');

// =====================================================================
// Part 1: Sequential baseline on datatests (if available)
// =====================================================================

let datatestFiles: string[] = [];
try {
  datatestFiles = fs.readdirSync(DATATESTS_DIR)
    .filter(f => f.endsWith('.xml'))
    .sort()
    .map(f => path.join(DATATESTS_DIR, f));
} catch {
  // No datatests available
}

if (datatestFiles.length > 0) {
  console.log(`=== Datatests: ${datatestFiles.length} files ===`);

  // Initialize library for sequential runs
  startDecompilerLibrary();

  // Warmup
  {
    const w = new StringWriter();
    const tc = new FunctionTestCollection(w);
    tc.loadTest(datatestFiles[0]);
    tc.runTests([]);
  }

  // Sequential run
  const seqStart = performance.now();
  for (const f of datatestFiles) {
    const w = new StringWriter();
    const tc = new FunctionTestCollection(w);
    tc.loadTest(f);
    tc.runTests([]);
  }
  const seqTime = performance.now() - seqStart;
  console.log(`  Sequential:  ${formatMs(seqTime)}`);
  console.log(`  (Workers not applicable — each file has 1 function)\n`);
}

// =====================================================================
// Part 2: Worker benchmarks on binary XML
// =====================================================================

// Find binary XMLs to test
const xmlsToTest: string[] = [];
if (binaryXml && fs.existsSync(binaryXml)) {
  xmlsToTest.push(binaryXml);
} else {
  // Auto-discover from output/cache/
  const cacheDir = path.resolve(__dirname, '..', 'output', 'cache');
  try {
    const dirs = fs.readdirSync(cacheDir);
    for (const d of dirs.sort()) {
      const xmlPath = path.join(cacheDir, d, 'exported.xml');
      if (fs.existsSync(xmlPath)) {
        xmlsToTest.push(xmlPath);
      }
    }
  } catch {
    // No cache directory
  }
}

if (xmlsToTest.length === 0) {
  console.log('No binary XML files found for worker benchmarks.');
  console.log('Export a binary with Ghidra or specify a path as argument.\n');
} else {
  const workerCounts = [1, 2, 4, Math.max(1, os.cpus().length - 1)];
  // Deduplicate and sort
  const uniqueCounts = [...new Set(workerCounts)].sort((a, b) => a - b);

  for (const xmlPath of xmlsToTest) {
    const binaryName = path.basename(path.dirname(xmlPath));
    const funcNames = WorkerParallelDecompiler.extractFunctionNames(
      fs.readFileSync(xmlPath, 'utf-8')
    );

    if (funcNames.length > MAX_FUNCTIONS) {
      console.log(`=== ${binaryName}: ${funcNames.length} functions (skipped — exceeds ${MAX_FUNCTIONS} limit) ===\n`);
      continue;
    }

    console.log(`=== ${binaryName}: ${funcNames.length} functions ===`);

    // Sequential baseline (using FunctionTestCollection) — single run for both timing and output
    if (!datatestFiles.length) {
      startDecompilerLibrary();
    }
    let seqOutput: string;
    let seqTime: number;
    {
      const seqStart = performance.now();
      const w = new StringWriter();
      const f: string[] = [];
      const tc = new FunctionTestCollection(w);
      tc.loadTest(xmlPath);
      tc.runTests(f);
      seqTime = performance.now() - seqStart;
      seqOutput = tc.getLastOutput();
    }
    console.log(`  Sequential:    ${formatMs(seqTime)}`);

    // Worker runs at various concurrency levels
    for (const nWorkers of uniqueCounts) {
      const nullWriter = { write: (_s: string) => {} };
      const pd = new WorkerParallelDecompiler(xmlPath, nWorkers, nullWriter);

      const wStart = performance.now();
      const results = await pd.decompileAll();
      const wTime = performance.now() - wStart;

      const succeeded = results.filter(r => r.success).length;
      const failed = results.filter(r => !r.success).length;
      const speedup = seqTime / wTime;

      // Verify correctness: worker output should match sequential
      const workerOutput = results.map(r => r.output).join('');
      const outputMatch = workerOutput === seqOutput;

      console.log(
        `  ${nWorkers} worker${nWorkers > 1 ? 's' : ' '}:     ${formatMs(wTime)}` +
        `  (${speedup.toFixed(2)}x speedup)` +
        `  ${succeeded} ok${failed > 0 ? `, ${failed} failed` : ''}` +
        (outputMatch ? '  [output matches]' : '  [OUTPUT MISMATCH]')
      );

      if (!outputMatch && failed === 0) {
        // Find first difference for debugging
        const seqLines = seqOutput.split('\n');
        const wLines = workerOutput.split('\n');
        for (let i = 0; i < Math.max(seqLines.length, wLines.length); i++) {
          if (seqLines[i] !== wLines[i]) {
            console.log(`    First diff at line ${i + 1}:`);
            console.log(`      Sequential: "${(seqLines[i] || '').substring(0, 80)}"`);
            console.log(`      Workers:    "${(wLines[i] || '').substring(0, 80)}"`);
            break;
          }
        }
      }
    }
    console.log('');
  }
}

// =====================================================================
// Memory summary
// =====================================================================

const mem = process.memoryUsage();
console.log('=== Memory (main thread) ===');
console.log(`  RSS:        ${formatBytes(mem.rss)}`);
console.log(`  Heap used:  ${formatBytes(mem.heapUsed)}`);
console.log(`  Heap total: ${formatBytes(mem.heapTotal)}`);
