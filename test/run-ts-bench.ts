/**
 * Benchmark runner: decompile all functions in an XML file and report timing.
 *
 * For large binaries (>BATCH_SIZE functions), processes in batches with
 * fresh FunctionTestCollection per batch to limit memory accumulation.
 *
 * Usage: npx tsx test/run-ts-bench.ts <exported.xml>
 */
import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';
import { readFileSync } from 'fs';

const xmlFile = process.argv[2];
if (!xmlFile) {
  process.stderr.write('Usage: npx tsx test/run-ts-bench.ts <exported.xml>\n');
  process.exit(1);
}

startDecompilerLibrary();

const BATCH_SIZE = 500;

const xmlContent = readFileSync(xmlFile, 'utf8');

// Extract <binaryimage> block (shared across all batches)
const binaryImageMatch = xmlContent.match(/<binaryimage[\s\S]*?<\/binaryimage>/);
if (!binaryImageMatch) {
  process.stderr.write('Error: No <binaryimage> found\n');
  process.exit(1);
}

// Extract all <script> blocks
const scriptBlocks: string[] = [];
const scriptRegex = /<script>[\s\S]*?<\/script>/g;
let m: RegExpExecArray | null;
while ((m = scriptRegex.exec(xmlContent)) !== null) {
  scriptBlocks.push(m[0]);
}

// Extract all <stringmatch> blocks
const matchBlocks: string[] = [];
const matchRegex = /<stringmatch[\s\S]*?<\/stringmatch>/g;
while ((m = matchRegex.exec(xmlContent)) !== null) {
  matchBlocks.push(m[0]);
}

const totalFuncs = scriptBlocks.length;

const start = performance.now();
let totalFailures = 0;

if (totalFuncs <= BATCH_SIZE) {
  // Small enough to do in one shot
  const writer = new StringWriter();
  const tc = new FunctionTestCollection(writer);
  tc.loadTest(xmlFile);
  const failures: string[] = [];
  tc.runTests(failures);
  totalFailures = failures.length;
} else {
  // Process in batches with fresh FunctionTestCollection each time
  const numBatches = Math.ceil(totalFuncs / BATCH_SIZE);
  for (let batch = 0; batch < numBatches; batch++) {
    const startIdx = batch * BATCH_SIZE;
    const endIdx = Math.min(startIdx + BATCH_SIZE, totalFuncs);
    const batchScripts = scriptBlocks.slice(startIdx, endIdx);

    const batchXml = [
      '<decompilertest>',
      binaryImageMatch[0],
      ...batchScripts,
      ...matchBlocks,
      '</decompilertest>',
    ].join('\n');

    try {
      const writer = new StringWriter();
      const tc = new FunctionTestCollection(writer);
      tc.loadTestFromString(batchXml, `batch-${batch}`);
      const failures: string[] = [];
      tc.runTests(failures);
      totalFailures += failures.length;
    } catch (e: any) {
      process.stderr.write(`  Batch ${batch + 1} error: ${e.message?.slice(0, 80)}\n`);
    }

    // Force GC between batches
    if (global.gc) global.gc();
  }
}

const elapsed = (performance.now() - start) / 1000;

// Print elapsed to stdout for the benchmark script to parse
console.log(`ELAPSED:${elapsed.toFixed(3)}`);

if (totalFailures > 0) {
  process.stderr.write(`Failures: ${totalFailures}\n`);
}
