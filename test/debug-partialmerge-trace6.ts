import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';
import { Merge } from '../src/decompiler/merge.js';
import { OpCode } from '../src/core/opcodes.js';

let funcNum = 0;

const origMIC = Merge.prototype.markInternalCopies;
Merge.prototype.markInternalCopies = function() {
  funcNum++;
  if (funcNum === 1) {
    const data = (this as any).data;
    console.error(`\n=== BEFORE markInternalCopies for readpartial ===`);
    const endAlive = data.endOpAlive();
    for (let iter = data.beginOpAlive(); !iter.equals(endAlive); iter.next()) {
      const op = iter.get();
      if (op.code() !== OpCode.CPUI_COPY && op.code() !== OpCode.CPUI_SUBPIECE) continue;
      const out = op.getOut();
      const outSpc = out.getAddr().getSpace();
      const outName = outSpc ? outSpc.getName() : 'null';
      const outOff = '0x' + out.getAddr().getOffset().toString(16);
      const in0 = op.getIn(0);
      const in0Spc = in0.getAddr().getSpace();
      const in0Name = in0Spc ? in0Spc.getName() : 'null';
      const in0Off = '0x' + in0.getAddr().getOffset().toString(16);

      const outHigh = out.getHigh();
      const in0High = in0.getHigh();
      const sameHigh = outHigh === in0High;
      const outPiece = outHigh._piece;
      const in0Piece = in0High._piece;

      // Check for glob1 range
      const isGlob = (outName === 'ram' && out.getAddr().getOffset() >= 0x100670n && out.getAddr().getOffset() < 0x100680n) ||
                     (in0Name === 'ram' && in0.getAddr().getOffset() >= 0x100670n && in0.getAddr().getOffset() < 0x100680n);
      if (isGlob) {
        console.error(`  ${OpCode[op.code()]} out=${outName}:${outOff}:${out.getSize()} in=${in0Name}:${in0Off}:${in0.getSize()} sameHigh=${sameHigh} outHigh.inst=${outHigh.numInstances()} in0High.inst=${in0High.numInstances()} outPiece=${outPiece !== null} in0Piece=${in0Piece !== null} explicit=${out.isExplicit()} implied=${out.isImplied()} noDescend=${out.hasNoDescend()} retcopy=${op.isReturnCopy()}`);
        if (sameHigh) {
          console.error(`    -> WILL BE NON-PRINTING`);
        }
        // List all instances of output High
        for (let i = 0; i < outHigh.numInstances(); i++) {
          const inst = outHigh.getInstance(i);
          const iSpc = inst.getAddr().getSpace();
          const iName = iSpc ? iSpc.getName() : 'null';
          console.error(`    outHigh inst[${i}]: ${iName}:0x${inst.getAddr().getOffset().toString(16)}:${inst.getSize()} written=${inst.isWritten()} input=${inst.isInput()}`);
        }
        if (!sameHigh) {
          for (let i = 0; i < in0High.numInstances(); i++) {
            const inst = in0High.getInstance(i);
            const iSpc = inst.getAddr().getSpace();
            const iName = iSpc ? iSpc.getName() : 'null';
            console.error(`    in0High inst[${i}]: ${iName}:0x${inst.getAddr().getOffset().toString(16)}:${inst.getSize()} written=${inst.isWritten()} input=${inst.isInput()}`);
          }
        }
      }
    }
  }
  return origMIC.call(this);
};

(globalThis as any).__DUMP_OUTPUT__ = true;

startDecompilerLibrary('/opt/ghidra');

const writer = new StringWriter();
const tc = new FunctionTestCollection(writer);
tc.loadTest('ghidra-src/Ghidra/Features/Decompiler/src/decompile/datatests/partialmerge.xml');
const failures: string[] = [];
tc.runTests(failures);
console.log('Failures:', failures.length);
