import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { ConsoleWriter } from '../src/util/writer.js';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __filename_local = fileURLToPath(import.meta.url);
const __dirname_local = path.dirname(__filename_local);

if (process.env.DUMP_OUTPUT) {
  (globalThis as any).__DUMP_OUTPUT__ = true;
}
if (process.env.DEBUG_READONLY) {
  (globalThis as any).__DEBUG_READONLY__ = true;
}
if (process.env.DEBUG_SPACEBASE) {
  (globalThis as any).__DEBUG_SPACEBASE__ = true;
}
startDecompilerLibrary('/opt/ghidra');
const w = new ConsoleWriter();
const basedir = path.join(__dirname_local, '..', 'ghidra-src', 'Ghidra', 'Features', 'Decompiler', 'src', 'decompile', 'datatests');
const testFile = process.argv[2] || 'switchindirect.xml';
FunctionTestCollection.runTestFiles([
  path.join(basedir, testFile)
], w);
