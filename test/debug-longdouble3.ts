// test/debug-longdouble3.ts - show actual decompiler output
import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';

// Enable dump output
(globalThis as any).__DUMP_OUTPUT__ = true;

startDecompilerLibrary('/opt/ghidra');

const writer = new StringWriter();
const tc = new FunctionTestCollection(writer);
tc.loadTest('ghidra-src/Ghidra/Features/Decompiler/src/decompile/datatests/longdouble.xml');
const failures: string[] = [];
tc.runTests(failures);
// Don't print test results, just use __DUMP_OUTPUT__ for the actual code
