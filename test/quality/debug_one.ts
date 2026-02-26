/**
 * Debug: decompile a single exported XML and show errors.
 */
import '../../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../../src/console/libdecomp.js';
import { FunctionTestCollection } from '../../src/console/testfunction.js';
import { StringWriter } from '../../src/util/writer.js';

const xmlFile = process.argv[2];

startDecompilerLibrary();
const writer = new StringWriter();
const failures: string[] = [];
const tc = new FunctionTestCollection(writer);
tc.loadTest(xmlFile);

// Monkey-patch to capture console output
const con = (tc as any).console;
const origOptr = con.optr;
const captureWriter = new StringWriter();

// Wrap optr.write to also log to stderr
const origWrite = origOptr.write.bind(origOptr);
con.optr = {
  write(s: string) {
    captureWriter.write(s);
    origWrite(s);
  }
};

tc.runTests(failures);

if (failures.length > 0) {
  console.error("=== FAILURES ===");
  for (const f of failures) console.error("  " + f);
}

const captured = captureWriter.toString();
if (captured.length > 0) {
  console.error("=== CONSOLE OUTPUT ===");
  console.error(captured);
}

console.log("=== DECOMPILED OUTPUT ===");
console.log(tc.getLastOutput());
