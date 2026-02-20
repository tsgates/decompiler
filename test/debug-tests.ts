import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';

startDecompilerLibrary('/opt/ghidra');

const testFiles = process.argv.slice(2);
if (testFiles.length === 0) {
  console.log('Usage: npx tsx test/debug-tests.ts <test1.xml> [test2.xml ...]');
  process.exit(1);
}

for (const testFile of testFiles) {
  console.log(`\n=== ${testFile} ===`);
  const writer = new StringWriter();
  const tc = new FunctionTestCollection(writer);
  tc.loadTest(`ghidra-src/Ghidra/Features/Decompiler/src/decompile/datatests/${testFile}`);
  const failures: string[] = [];
  tc.runTests(failures);
  console.log(writer.toString());
}
