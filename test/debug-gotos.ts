/**
 * Debug script: decompile a test XML and show goto/break counts per function.
 * Usage: npx tsx test/debug-gotos.ts <xml> [--enhance]
 */
import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';

startDecompilerLibrary();

const args = process.argv.slice(2);
const enhanced = args.includes('--enhance');
const xmlFile = args.find(a => !a.startsWith('--'));
if (!xmlFile) { console.log('Usage: npx tsx test/debug-gotos.ts <xml> [--enhance]'); process.exit(1); }

const w = new StringWriter();
const tc = new FunctionTestCollection(w);
tc.loadTest(xmlFile);
if (enhanced) tc.applyEnhancedDisplay();
const f: string[] = [];
tc.runTests(f);
const output = tc.getLastOutput();

// Split into functions
const blocks = output.split(/\n(?=\S+\s+\S+\()/);
let totalGotos = 0;
let totalBreaks = 0;
for (const block of blocks) {
  const trimmed = block.trim();
  if (!trimmed) continue;
  const m = trimmed.match(/^\S+\s+(\S+?)\s*\(/);
  if (!m) continue;
  const name = m[1];
  const gotos = (trimmed.match(/\bgoto\s+\w+/g) || []).length;
  const breaks = (trimmed.match(/\bbreak\s*;/g) || []).length;
  totalGotos += gotos;
  totalBreaks += breaks;
  if (gotos > 0 || breaks > 0) {
    console.log(`  ${name}: ${gotos} gotos, ${breaks} breaks`);
  }
}
console.log(`\nTotal: ${totalGotos} gotos, ${totalBreaks} breaks (${enhanced ? 'enhanced' : 'normal'})`);
