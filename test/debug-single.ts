import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';

const testName = process.argv[2];
if (!testName) {
  console.error('Usage: npx tsx test/debug-single.ts <testname>');
  process.exit(1);
}

startDecompilerLibrary('/opt/ghidra');
const writer = new StringWriter();
const tc = new FunctionTestCollection(writer);
const fullPath = `ghidra-src/Ghidra/Features/Decompiler/src/decompile/datatests/${testName}.xml`;
tc.loadTest(fullPath);
const failures: string[] = [];
(globalThis as any).__DUMP_OUTPUT__ = true;
tc.runTests(failures);
const output = writer.toString();
console.log(output);
if (failures.length > 0) {
  console.log('\n---FAILURES---');
  for (const f of failures) console.log(f);
}
