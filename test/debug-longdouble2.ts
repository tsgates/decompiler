// test/debug-longdouble2.ts - show actual decompiler output
import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';

startDecompilerLibrary('/opt/ghidra');

const writer = new StringWriter();
const tc = new FunctionTestCollection(writer);
tc.loadTest('ghidra-src/Ghidra/Features/Decompiler/src/decompile/datatests/longdouble.xml');

// Instead of running tests, let's see the actual decompiler output
const failures: string[] = [];
tc.runTests(failures);

// Print the full decompiled output
const output = writer.toString();
console.log("=== FULL DECOMPILED OUTPUT ===");
console.log(output);
console.log("=== END OUTPUT ===");
console.log("\nFailures:", failures);

// Also print expected patterns
console.log("\n=== EXPECTED PATTERNS ===");
console.log('Test #1: ldarr\\[0\\] = valpass + (float10)27.632');
console.log('Test #2: ldarr\\[1\\] = valpass + (float10)27.632');
console.log('Test #3: writeLongDouble(ldarr,x);');
console.log('Test #5: writeLongDouble(ldarr,ptrldstr->a);');
console.log('Test #6: writeLongDouble(ldarr,ptrldstr->b);');
console.log('Test #7: return (int4)ptrldstr->c + (int4)ptrldstr->d + (int4)ptrldstr->e + (int4)ptrldstr->f;');
console.log('Test #8: printf_chk(1,"%d\\n",v1);');
console.log('Test #9: printf_chk(1,"%d\\n",firstval.b);');
console.log('Test #10: printf_chk(1,"%d\\n",v2);');
console.log('Test #11: writeLongDouble(ldarr,firstval.a);');
console.log('Test #14: ldarr[val] = ldarr[7 - val] + ldarr[val + 7];');
