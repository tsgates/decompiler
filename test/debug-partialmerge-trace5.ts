import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';
import { Merge } from '../src/decompiler/merge.js';
import { OpCode } from '../src/core/opcodes.js';

let funcNum = 0;

const origMergeMarker = Merge.prototype.mergeMarker;
Merge.prototype.mergeMarker = function() {
  funcNum++;
  if (funcNum === 1) {
    const data = (this as any).data;
    console.error(`\n=== BEFORE mergeMarker for readpartial ===`);
    // List all varnodes at ram:0x100670 range
    let iter = data.beginLoc();
    const enditer = data.endLoc();
    while (!iter.equals(enditer)) {
      const vn = iter.get();
      iter.next();
      const spc = vn.getAddr().getSpace();
      if (!spc || spc.getName() !== 'ram') continue;
      const off = vn.getAddr().getOffset();
      if (off < 0x100670n || off >= 0x100680n) continue;
      const highId = vn.hasHigh ? (vn.getHigh ? vn.getHigh().getId ? vn.getHigh().getId() : '?' : '?') : '?';
      const persist = vn.isPersist();
      const addrtied = vn.isAddrTied();
      const written = vn.isWritten();
      const input = vn.isInput();
      const free = vn.isFree();
      const writeMask = vn.isWriteMask();
      let defOp = 'none';
      if (written) {
        const op = vn.getDef();
        defOp = OpCode[op.code()];
      }
      console.error(`  vn: off=0x${off.toString(16)} sz=${vn.getSize()} persist=${persist} addrtied=${addrtied} written=${written} input=${input} free=${free} wm=${writeMask} def=${defOp} high=${highId}`);
    }
  }
  return origMergeMarker.call(this);
};

const origMAT = Merge.prototype.mergeAddrTied;
Merge.prototype.mergeAddrTied = function() {
  if (funcNum === 1) {
    console.error(`\n=== BEFORE mergeAddrTied for readpartial ===`);
  }
  const result = origMAT.call(this);
  if (funcNum === 1) {
    const data = (this as any).data;
    console.error(`\n=== AFTER mergeAddrTied for readpartial ===`);
    let iter = data.beginLoc();
    const enditer = data.endLoc();
    while (!iter.equals(enditer)) {
      const vn = iter.get();
      iter.next();
      const spc = vn.getAddr().getSpace();
      if (!spc || spc.getName() !== 'ram') continue;
      const off = vn.getAddr().getOffset();
      if (off < 0x100670n || off >= 0x100680n) continue;
      const persist = vn.isPersist();
      const addrtied = vn.isAddrTied();
      const written = vn.isWritten();
      const input = vn.isInput();
      const free = vn.isFree();
      const writeMask = vn.isWriteMask();
      let defOp = 'none';
      if (written) defOp = OpCode[vn.getDef().code()];
      let highInst = '?';
      try { highInst = '' + vn.getHigh().numInstances(); } catch(e) {}
      console.error(`  vn: off=0x${off.toString(16)} sz=${vn.getSize()} persist=${persist} addrtied=${addrtied} written=${written} input=${input} free=${free} wm=${writeMask} def=${defOp} highInst=${highInst}`);
    }
  }
  return result;
};

(globalThis as any).__DUMP_OUTPUT__ = true;

startDecompilerLibrary('/opt/ghidra');

const writer = new StringWriter();
const tc = new FunctionTestCollection(writer);
tc.loadTest('ghidra-src/Ghidra/Features/Decompiler/src/decompile/datatests/partialmerge.xml');
const failures: string[] = [];
tc.runTests(failures);
console.log('Failures:', failures.length);
