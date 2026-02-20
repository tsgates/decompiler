import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';
import { Heritage } from '../src/decompiler/heritage.js';
import { OpCode } from '../src/core/opcodes.js';

// Hook into placeMultiequals to see what disjoint ranges exist
let funcCount = 0;
const origPM = Heritage.prototype.placeMultiequals;
(Heritage.prototype as any).placeMultiequals = function() {
  funcCount++;
  if (funcCount === 1) {
    const disjoint = (this as any).disjoint;
    console.error(`\n=== DISJOINT RANGES for readpartial ===`);
    for (let i = 0; i < disjoint.length; i++) {
      const mr = disjoint.get(i);
      const spc = mr.addr.getSpace();
      const spcName = spc ? spc.getName() : 'null';
      console.error(`  [${i}] spc=${spcName} off=0x${mr.addr.getOffset().toString(16)} size=${mr.size} new=${mr.newAddresses()} old=${mr.oldAddresses()}`);
    }
  }
  return origPM.call(this);
};

// Hook into rename to see post-placement state for glob1
const origRename = Heritage.prototype.rename;
let renameCount = 0;
(Heritage.prototype as any).rename = function() {
  renameCount++;
  if (renameCount === 1) {
    console.error(`\n=== PRE-RENAME (all ops) for readpartial ===`);
    const fd = (this as any).fd;
    const endAlive = fd.endOpAlive();
    let count = 0;
    for (let iter = fd.beginOpAlive(); !iter.equals(endAlive); iter.next()) {
      const op = iter.get();
      const out = op.getOut();
      let outSpc = '', outOff = '';
      if (out) {
        const s = out.getAddr().getSpace();
        outSpc = s ? s.getName() : 'null';
        outOff = '0x' + out.getAddr().getOffset().toString(16);
      }
      let ins: string[] = [];
      for (let i = 0; i < op.numInput(); i++) {
        const inv = op.getIn(i);
        if (inv) {
          const s = inv.getAddr().getSpace();
          const sn = s ? s.getName() : 'null';
          const off = '0x' + inv.getAddr().getOffset().toString(16);
          const known = inv.isHeritageKnown();
          const active = (inv as any).isActiveHeritage ? (inv as any).isActiveHeritage() : '?';
          ins.push(`${sn}:${off}:${inv.getSize()}(k=${known},a=${active})`);
        }
      }
      // Show all ops
      const outStr = out ? `${outSpc}:${outOff}:${out.getSize()}` : 'none';
      const show = outStr.includes('100670') || outStr.includes('100674') ||
                   ins.some(s => s.includes('100670') || s.includes('100674'));
      if (show) {
        const outActive = out && (out as any).isActiveHeritage ? (out as any).isActiveHeritage() : '?';
        console.error(`  [${count}] ${OpCode[op.code()]} out=${outStr}(a=${outActive}) in=[${ins.join(', ')}]`);
      }
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
