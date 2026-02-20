import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';

(globalThis as any).__DUMP_OUTPUT__ = true;

startDecompilerLibrary('/opt/ghidra');

// Now test both
for (const testFile of ['retstruct.xml', 'piecestruct.xml']) {
  console.error(`\n=== ${testFile} ===`);
  const writer = new StringWriter();
  const tc = new FunctionTestCollection(writer);
  tc.loadTest(`ghidra-src/Ghidra/Features/Decompiler/src/decompile/datatests/${testFile}`);
  const failures: string[] = [];
  tc.runTests(failures);
  console.error(writer.toString());
}
