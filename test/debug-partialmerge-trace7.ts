import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';
import { Merge } from '../src/decompiler/merge.js';
import { OpCode } from '../src/core/opcodes.js';
import { Cover } from '../src/decompiler/cover.js';

let funcNum = 0;

// Hook into mergeAddrTied to track which function we're in
const origMAT = Merge.prototype.mergeAddrTied;
Merge.prototype.mergeAddrTied = function() {
  funcNum++;
  if (funcNum === 1) {
    // Monkey-patch eliminateIntersect for this call
    const self = this as any;
    const origEI = self.__proto__.eliminateIntersect || Object.getPrototypeOf(self).eliminateIntersect;
    if (!origEI) {
      console.error('Could not find eliminateIntersect');
    }
  }
  return origMAT.call(this);
};

// We need to hook the private eliminateIntersect method
// Since it's private in TS, we need to access it via prototype
const proto = Merge.prototype as any;
const origEI = proto.eliminateIntersect;
if (origEI) {
  proto.eliminateIntersect = function(vn: any, blocksort: any[]) {
    if (funcNum !== 1) return origEI.call(this, vn, blocksort);

    const spc = vn.getAddr().getSpace();
    const spcName = spc ? spc.getName() : 'null';
    const off = vn.getAddr().getOffset();

    // Only trace glob1 range
    if (spcName !== 'ram' || off < 0x100670n || off >= 0x100680n) {
      return origEI.call(this, vn, blocksort);
    }

    console.error(`\n=== eliminateIntersect for vn=${spcName}:0x${off.toString(16)}:${vn.getSize()} ===`);
    console.error(`  vn is: written=${vn.isWritten()} input=${vn.isInput()} addrTied=${vn.isAddrTied()} addrForce=${vn.isAddrForce()} persist=${vn.isPersist()}`);
    if (vn.isWritten()) {
      console.error(`  def op: ${OpCode[vn.getDef().code()]} at order=${vn.getDef().getSeqNum().getOrder()}`);
    }

    // Dump cover of vn
    const vnCover = vn.getCover();
    if (vnCover) {
      console.error(`  vn cover: ${vnCover.dump()}`);
    }

    // Dump descendants of vn
    console.error(`  vn descendants: ${vn.descend.length}`);
    for (let i = 0; i < vn.descend.length; i++) {
      const op = vn.descend[i];
      const out = op.getOut();
      let outStr = 'none';
      if (out) {
        const oSpc = out.getAddr().getSpace();
        outStr = `${oSpc ? oSpc.getName() : 'null'}:0x${out.getAddr().getOffset().toString(16)}:${out.getSize()}`;
      }
      console.error(`    [${i}] ${OpCode[op.code()]} out=${outStr} blk=${op.getParent().getIndex()} order=${op.getSeqNum().getOrder()}`);
    }

    // List all blocksort entries that are in ram:0x100670 range
    console.error(`  blocksort entries (ram:0x100670 range):`);
    for (const bv of blocksort) {
      const bvn = bv.getVarnode();
      const bSpc = bvn.getAddr().getSpace();
      const bName = bSpc ? bSpc.getName() : 'null';
      const bOff = bvn.getAddr().getOffset();
      if (bName === 'ram' && bOff >= 0x100670n && bOff < 0x100680n) {
        const defStr = bvn.isWritten() ? `${OpCode[bvn.getDef().code()]} order=${bvn.getDef().getSeqNum().getOrder()}` : (bvn.isInput() ? 'INPUT' : 'FREE');
        console.error(`    blkIdx=${bv.getIndex()} vn=${bName}:0x${bOff.toString(16)}:${bvn.getSize()} def=${defStr} addrTied=${bvn.isAddrTied()} addrForce=${bvn.isAddrForce()}`);

        // Dump cover of this blocksort vn
        const bCover = bvn.getCover();
        if (bCover) {
          console.error(`      cover: ${bCover.dump()}`);
        }
      }
    }

    // Now do per-descendant analysis, mimicking the logic of eliminateIntersect
    for (let oIdx = vn.beginDescend(); oIdx < vn.endDescend(); ++oIdx) {
      const single = new Cover();
      single.addDefPoint(vn);
      const op = vn.getDescend(oIdx);
      single.addRefPoint(op, vn);

      const out = op.getOut();
      let outStr = 'none';
      if (out) {
        const oSpc = out.getAddr().getSpace();
        outStr = `${oSpc ? oSpc.getName() : 'null'}:0x${out.getAddr().getOffset().toString(16)}:${out.getSize()}`;
      }
      console.error(`\n  Analyzing descend[${oIdx}]: ${OpCode[op.code()]} out=${outStr}`);
      console.error(`    single cover: ${single.dump()}`);

      // Check each blocksort entry for this single cover
      for (const [blocknum] of single) {
        let slot = findFront(blocknum, blocksort);
        if (slot === -1) continue;
        while (slot < blocksort.length) {
          if (blocksort[slot].getIndex() !== blocknum) break;
          const vn2 = blocksort[slot].getVarnode();
          slot++;
          if (vn2 === vn) continue;

          const bSpc = vn2.getAddr().getSpace();
          const bName = bSpc ? bSpc.getName() : 'null';
          const bOff = vn2.getAddr().getOffset();
          if (bName !== 'ram' || bOff < 0x100670n || bOff >= 0x100680n) continue;

          const boundtype = single.containVarnodeDef(vn2);
          if (boundtype === 0) continue;
          const overlaptype = vn.characterizeOverlap(vn2);

          const defStr = vn2.isWritten() ? `${OpCode[vn2.getDef().code()]} order=${vn2.getDef().getSeqNum().getOrder()}` : (vn2.isInput() ? 'INPUT' : 'FREE');
          console.error(`      vs vn2=${bName}:0x${bOff.toString(16)}:${vn2.getSize()} def=${defStr} boundtype=${boundtype} overlaptype=${overlaptype}`);

          if (overlaptype === 0) {
            console.error(`        -> skip: no overlap`);
            continue;
          }
          if (overlaptype === 1) {
            const off2 = Number(vn.getOffset() - vn2.getOffset());
            const pcs = vn.partialCopyShadow(vn2, off2);
            console.error(`        -> partial overlap, partialCopyShadow=${pcs}`);
            if (pcs) continue;
          }
          if (boundtype === 2) {
            if (vn2.getDef() === null) {
              if (vn.getDef() === null) {
                console.error(`        -> boundtype=2, both inputs, compare`);
              } else {
                console.error(`        -> boundtype=2, vn2 input, vn written => skip`);
                continue;
              }
            } else {
              if (vn.getDef() !== null) {
                const ord = vn2.getDef().getSeqNum().getOrder() < vn.getDef().getSeqNum().getOrder();
                console.error(`        -> boundtype=2, both written, vn2.order < vn.order = ${ord}`);
                if (ord) continue;
              }
            }
          } else if (boundtype === 3) {
            console.error(`        -> boundtype=3: vn2.addrForce=${vn2.isAddrForce()} vn2.written=${vn2.isWritten()}`);
            if (!vn2.isAddrForce()) { console.error(`          skip: not addrForce`); continue; }
            if (!vn2.isWritten()) { console.error(`          skip: not written`); continue; }
            const indop = vn2.getDef();
            console.error(`          vn2 def op: ${OpCode[indop.code()]}`);
            if (indop.code() !== OpCode.CPUI_INDIRECT) { console.error(`          skip: not INDIRECT`); continue; }
          }
          console.error(`        -> WILL SNIP THIS READ`);
        }
      }
    }

    return origEI.call(this, vn, blocksort);
  };
} else {
  console.error('WARNING: Could not find eliminateIntersect on Merge.prototype');
}

// Helper function to match BlockVarnode.findFront
function findFront(blocknum: number, blocksort: any[]): number {
  let lo = 0, hi = blocksort.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (blocksort[mid].getIndex() < blocknum) lo = mid + 1;
    else hi = mid;
  }
  if (lo >= blocksort.length || blocksort[lo].getIndex() !== blocknum) return -1;
  return lo;
}

(globalThis as any).__DUMP_OUTPUT__ = true;

startDecompilerLibrary('/opt/ghidra');

const writer = new StringWriter();
const tc = new FunctionTestCollection(writer);
tc.loadTest('ghidra-src/Ghidra/Features/Decompiler/src/decompile/datatests/partialmerge.xml');
const failures: string[] = [];
tc.runTests(failures);
console.log('Failures:', failures.length);
