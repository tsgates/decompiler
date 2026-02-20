import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';
import { Heritage } from '../src/decompiler/heritage.js';
import { OpCode } from '../src/core/opcodes.js';

// Hook into heritage to see space delays and passes
let heritageCallCount = 0;
const origHeritage = Heritage.prototype.heritage;
(Heritage.prototype as any).heritage = function() {
  heritageCallCount++;
  const pass = (this as any).pass;
  if (heritageCallCount <= 5) {
    console.error(`\n=== HERITAGE CALL #${heritageCallCount} (pass=${pass}) ===`);
    const infolist = (this as any).infolist;
    for (let i = 0; i < infolist.length; i++) {
      const info = infolist[i];
      if (info.space) {
        console.error(`  space=${info.space.getName()} isHeritaged=${info.isHeritaged()} delay=${info.delay} deadcodeDelay=${info.deadcodedelay} pass=${pass} will_heritage=${info.isHeritaged() && pass >= info.delay}`);
      }
    }
  }
  return origHeritage.call(this);
};

(globalThis as any).__DUMP_OUTPUT__ = true;

startDecompilerLibrary('/opt/ghidra');

const writer = new StringWriter();
const tc = new FunctionTestCollection(writer);
tc.loadTest('ghidra-src/Ghidra/Features/Decompiler/src/decompile/datatests/partialmerge.xml');
const failures: string[] = [];
tc.runTests(failures);
console.log('Failures:', failures.length);
