import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';
import { Heritage } from '../src/decompiler/heritage.js';
import { OpCode } from '../src/core/opcodes.js';

// Hook into placeMultiequals
let pmCount = 0;
const origPM = Heritage.prototype.placeMultiequals;
(Heritage.prototype as any).placeMultiequals = function() {
  pmCount++;
  // Function 1 (readpartial), call #2 would be pass 1 with RAM space
  const pass = (this as any).pass;
  if (pmCount <= 8) {
    const disjoint = (this as any).disjoint;
    let hasRam = false;
    for (let i = 0; i < disjoint.length; i++) {
      const mr = disjoint.get(i);
      const spc = mr.addr.getSpace();
      if (spc && spc.getName() === 'ram') { hasRam = true; break; }
    }
    if (hasRam) {
      console.error(`\n=== placeMultiequals #${pmCount} (pass=${pass}) - HAS RAM ===`);
      for (let i = 0; i < disjoint.length; i++) {
        const mr = disjoint.get(i);
        const spc = mr.addr.getSpace();
        const spcName = spc ? spc.getName() : 'null';
        if (spcName === 'ram') {
          console.error(`  [${i}] spc=${spcName} off=0x${mr.addr.getOffset().toString(16)} size=${mr.size} new=${mr.newAddresses()} old=${mr.oldAddresses()}`);
        }
      }
    }
  }
  return origPM.call(this);
};

// Hook into guard to see reads/writes for glob1 range
const origGuard = (Heritage.prototype as any).guard;
let guardCount = 0;
(Heritage.prototype as any).guard = function(addr: any, size: number, guardPerformed: boolean, read: any[], write: any[], inputvars: any[]) {
  guardCount++;
  const spc = addr.getSpace();
  const spcName = spc ? spc.getName() : 'null';
  if (spcName === 'ram' && guardCount <= 20) {
    console.error(`\n=== guard #${guardCount}: addr=ram:0x${addr.getOffset().toString(16)} size=${size} guardPerformed=${guardPerformed} ===`);
    console.error(`  reads: ${read.length}`);
    for (let i = 0; i < read.length; i++) {
      const vn = read[i];
      console.error(`    [${i}] addr=0x${vn.getAddr().getOffset().toString(16)}:${vn.getSize()} written=${vn.isWritten()} descends=${vn.descend.length}`);
    }
    console.error(`  writes: ${write.length}`);
    for (let i = 0; i < write.length; i++) {
      const vn = write[i];
      const op = vn.getDef();
      console.error(`    [${i}] addr=0x${vn.getAddr().getOffset().toString(16)}:${vn.getSize()} op=${OpCode[op.code()]} marker=${op.isMarker()} retcopy=${op.isReturnCopy()}`);
    }
    console.error(`  inputs: ${inputvars.length}`);
  }
  return origGuard.call(this, addr, size, guardPerformed, read, write, inputvars);
};

// Hook into rename for pass 1
const origRename = Heritage.prototype.rename;
let renameCount = 0;
(Heritage.prototype as any).rename = function() {
  renameCount++;
  const pass = (this as any).pass;
  if (renameCount === 2) { // pass 1 for first func
    console.error(`\n=== PRE-RENAME pass=${pass} ===`);
    const fd = (this as any).fd;
    const endAlive = fd.endOpAlive();
    let count = 0;
    for (let iter = fd.beginOpAlive(); !iter.equals(endAlive); iter.next()) {
      const op = iter.get();
      const out = op.getOut();
      let show = false;
      let outStr = 'none';
      if (out) {
        const s = out.getAddr().getSpace();
        const sn = s ? s.getName() : 'null';
        const off = '0x' + out.getAddr().getOffset().toString(16);
        outStr = `${sn}:${off}:${out.getSize()}`;
        if (sn === 'ram') show = true;
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
          if (sn === 'ram') show = true;
        }
      }
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
