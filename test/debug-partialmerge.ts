import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';
import { Merge } from '../src/decompiler/merge.js';
import { OpCode } from '../src/core/opcodes.js';

let funcNum = 0;

const origMarkIC = Merge.prototype.markInternalCopies;
Merge.prototype.markInternalCopies = function() {
  funcNum++;
  if (funcNum === 1) {
    const data = (this as any).data;
    const endAlive = data.endOpAlive();
    for (let iter = data.beginOpAlive(); !iter.equals(endAlive); iter.next()) {
      const op = iter.get();
      if (op.code() === OpCode.CPUI_COPY) {
        const v1 = op.getOut();
        const h1 = v1.getHigh();
        const v2 = op.getIn(0);
        const h2 = v2.getHigh();
        const sameHigh = h1 === h2;
        console.error(`[F1] COPY: out=${v1.getAddr()} sz=${v1.getSize()} implied=${v1.isImplied()} | in=${v2.getAddr()} sz=${v2.getSize()} implied=${v2.isImplied()} | sameHigh=${sameHigh}`);
        if (sameHigh) {
          console.error(`[F1]   -> Will be marked non-printing`);
        } else {
          console.error(`[F1]   -> h1.numInst=${h1.numInstances()} h2.numInst=${h2.numInstances()}`);
          console.error(`[F1]   -> h1.piece=${h1._piece!==null} h2.piece=${h2._piece!==null}`);
          // Check if v1 has no descend and is shadowed
          const hasNoDescend = v1.hasNoDescend();
          console.error(`[F1]   -> v1.hasNoDescend=${hasNoDescend}`);
        }
      } else if (op.code() === OpCode.CPUI_SUBPIECE) {
        const v1 = op.getOut();
        const v2 = op.getIn(0);
        const p1 = v1.getHigh()._piece;
        const p2 = v2.getHigh()._piece;
        console.error(`[F1] SUBPIECE: out=${v1.getAddr()} sz=${v1.getSize()} p=${p1!==null} | in=${v2.getAddr()} sz=${v2.getSize()} p=${p2!==null}`);
        if (p1 !== null && p2 !== null) {
          console.error(`[F1]   -> sameGroup=${p1.getGroup() === p2.getGroup()}`);
        }
      }
    }
  }
  return origMarkIC.call(this);
};

(globalThis as any).__DUMP_OUTPUT__ = true;

startDecompilerLibrary('/opt/ghidra');

const writer = new StringWriter();
const tc = new FunctionTestCollection(writer);
tc.loadTest('ghidra-src/Ghidra/Features/Decompiler/src/decompile/datatests/partialmerge.xml');
const failures: string[] = [];
tc.runTests(failures);
console.log('Failures:', failures.length);
