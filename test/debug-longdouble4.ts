// test/debug-longdouble4.ts - detailed regex matching analysis
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

// Before running tests, capture output
const origWriter = new StringWriter();
const failures: string[] = [];
tc.runTests(failures);

// Now let's manually test the regexes against the output
const patterns = [
  { name: '#1', re: /ldarr\[0\] = valpass \+ \(float10\)27\.632/ },
  { name: '#2', re: /ldarr\[1\] = valpass \+ \(float10\)27\.632/ },
  { name: '#3', re: /writeLongDouble\(ldarr,x\);/ },
  { name: '#5', re: /writeLongDouble\(ldarr,ptrldstr->a\);/ },
  { name: '#6', re: /writeLongDouble\(ldarr,ptrldstr->b\);/ },
  { name: '#7', re: /return \(int4\)ptrldstr->c \+ \(int4\)ptrldstr->d \+ \(int4\)ptrldstr->e \+ \(int4\)ptrldstr->f;/ },
  { name: '#8', re: /printf_chk\(1,"%d\\n",v1\);/ },
  { name: '#9', re: /printf_chk\(1,"%d\\n",firstval\.b\);/ },
  { name: '#10', re: /printf_chk\(1,"%d\\n",v2\);/ },
  { name: '#11', re: /writeLongDouble\(ldarr,firstval\.a\);/ },
  { name: '#14', re: /ldarr\[val\] = ldarr\[7 \- val\] \+ ldarr\[val \+ 7\];/ },
];

// Get the decompiler output (from stderr, captured by __DUMP_OUTPUT__)
// We need to capture it differently
