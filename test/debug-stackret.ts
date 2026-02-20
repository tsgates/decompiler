import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';

startDecompilerLibrary('/opt/ghidra');

(globalThis as any).__DUMP_OUTPUT__ = true;

for (const testFile of ['stackreturn.xml', 'doublemove.xml']) {
  console.log(`\n=== ${testFile} ===`);
  const writer = new StringWriter();
  const tc = new FunctionTestCollection(writer);
  tc.loadTest(`ghidra-src/Ghidra/Features/Decompiler/src/decompile/datatests/${testFile}`);
  const failures: string[] = [];
  tc.runTests(failures);
  console.log(writer.toString());
  if (failures.length > 0) {
    console.log('Failures:', failures);
  }
}
