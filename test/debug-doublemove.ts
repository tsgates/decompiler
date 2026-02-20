import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';
import { OpCode } from '../src/core/opcodes.js';

startDecompilerLibrary('/opt/ghidra');

// Trace RulePropagateCopy
const { RulePropagateCopy } = await import('../src/decompiler/ruleaction.js');
const origApply = RulePropagateCopy.prototype.applyOp;
let traceEnabled = false;
RulePropagateCopy.prototype.applyOp = function(op: any, data: any) {
  // Manually implement with tracing
  if (op.isReturnCopy()) return 0;
  for (let i = 0; i < op.numInput(); ++i) {
    const vn = op.getIn(i);
    if (!vn.isWritten()) continue;
    const copyop = vn.getDef();
    if (copyop.code() !== OpCode.CPUI_COPY) continue;
    const invn = copyop.getIn(0);
    if (!invn.isHeritageKnown()) {
      if (traceEnabled) console.log(`[PropagateCopy] SKIP: invn not heritageKnown, op=${op.code()}, invn_addr=${invn?.getAddr()?.toString()}`);
      continue;
    }
    if (invn === vn) throw new Error("Self-defined varnode");
    if (op.isMarker()) {
      if (invn.isConstant()) continue;
      if (vn.isAddrForce()) continue;
      if (invn.isAddrTied() && op.getOut().isAddrTied() && !op.getOut().getAddr().equals(invn.getAddr())) {
        if (traceEnabled) console.log(`[PropagateCopy] SKIP: marker addr mismatch, op=${op.code()}`);
        continue;
      }
    }
    if (traceEnabled) console.log(`[PropagateCopy] APPLY: op=${op.code()}, input[${i}], invn_addr=${invn?.getAddr()?.toString()}`);
    data.opSetInput(op, invn, i);
    return 1;
  }
  return 0;
};

(globalThis as any).__DUMP_OUTPUT__ = true;
traceEnabled = true;

const writer = new StringWriter();
const tc = new FunctionTestCollection(writer);
tc.loadTest('ghidra-src/Ghidra/Features/Decompiler/src/decompile/datatests/doublemove.xml');
const failures: string[] = [];
tc.runTests(failures);
console.log(writer.toString());
if (failures.length > 0) {
  console.log('Failures:', failures);
}
