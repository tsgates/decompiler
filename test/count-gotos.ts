import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';

const SLEIGH_PATH = process.env.SLEIGH_PATH || '/opt/homebrew/Caskroom/ghidra/11.4.2-20250826/ghidra_11.4.2_PUBLIC';
startDecompilerLibrary(SLEIGH_PATH);

const xmlFile = process.argv[2];
const enhanced = process.argv.includes('--enhance');
if (!xmlFile) { console.log('Usage: npx tsx test/count-gotos.ts <xml> [--enhance]'); process.exit(1); }

const w = new StringWriter();
const tc = new FunctionTestCollection(w);
try {
  tc.loadTest(xmlFile);
  if (enhanced) tc.applyEnhancedDisplay();
  const f: string[] = [];
  tc.runTests(f);
  const o = tc.getLastOutput();
  const g = (o.match(/\bgoto\b/g) || []).length;
  console.log(`${g}`);
} catch(e: any) {
  console.error(`ERR: ${e.message || e}`);
  process.exit(1);
}
