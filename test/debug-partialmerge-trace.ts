import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';
import { Heritage } from '../src/decompiler/heritage.js';
import { OpCode } from '../src/core/opcodes.js';

// Hook into rename to dump p-code state after guard/placeMultiequals but before rename
let funcCount = 0;
const origRename = Heritage.prototype.rename;
(Heritage.prototype as any).rename = function() {
  funcCount++;
  if (funcCount === 1) {
    console.error(`\n=== PRE-RENAME for readpartial (heritage pass ${(this as any).pass}) ===`);
    const fd = (this as any).fd;
    const endAlive = fd.endOpAlive();
    let count = 0;
    for (let iter = fd.beginOpAlive(); !iter.equals(endAlive); iter.next()) {
      const op = iter.get();
      const out = op.getOut();
      const outStr = out ? `${out.getAddr().printRaw()}:${out.getSize()}` : 'none';
      let ins: string[] = [];
      for (let i = 0; i < op.numInput(); i++) {
        const inv = op.getIn(i);
        if (inv) {
          const known = inv.isHeritageKnown();
          const active = (inv as any).isActiveHeritage ? (inv as any).isActiveHeritage() : '?';
          ins.push(`${inv.getAddr().printRaw()}:${inv.getSize()}(k=${known},a=${active})`);
        }
      }
      console.error(`  [${count}] ${OpCode[op.code()]} out=${outStr} in=[${ins.join(', ')}]`);
      count++;
    }
  }
  return origRename.call(this);
};

(globalThis as any).__DUMP_OUTPUT__ = true;

startDecompilerLibrary('/opt/ghidra');

const writer = new StringWriter();
const tc = new FunctionTestCollection(writer);
tc.loadTest('ghidra-src/Ghidra/Features/Decompiler/src/decompile/datatests/partialmerge.xml');
const failures: string[] = [];
tc.runTests(failures);
console.log('Failures:', failures.length);
