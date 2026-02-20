import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';

startDecompilerLibrary('/opt/ghidra');

const { FuncCallSpecs } = await import('../src/decompiler/fspec.js');
const { Heritage } = await import('../src/decompiler/heritage.js');

// Trace tryOutputStackGuard
const origGuard = Heritage.prototype.tryOutputStackGuard;
if (origGuard) {
  Heritage.prototype.tryOutputStackGuard = function(fc: any, addr: any, transAddr: any, size: any, outputCharacter: any, write: any) {
    console.log(`[tryOutputStackGuard] addr=${addr}, transAddr=${transAddr}, size=${size}, outputChar=${outputCharacter}`);
    const result = origGuard.call(this, fc, addr, transAddr, size, outputCharacter, write);
    console.log(`[tryOutputStackGuard] result=${result}`);
    return result;
  };
} else {
  console.log('tryOutputStackGuard is private, need another approach');
}

// Trace guardCalls
const origGuardCalls = Heritage.prototype.guardCalls as any;
if (origGuardCalls) {
  (Heritage.prototype as any).guardCalls = function(fl: any, addr: any, size: any, write: any) {
    console.log(`[guardCalls] addr=${addr} size=${size}`);
    return origGuardCalls.call(this, fl, addr, size, write);
  };
} else {
  console.log('guardCalls is private');
}

// Trace getSpacebaseOffset
const origGetOffset = FuncCallSpecs.prototype.getSpacebaseOffset;
const origIsStackOutputLock = FuncCallSpecs.prototype.isStackOutputLock;
const patchedGetOffset = function(this: any) {
  const r = origGetOffset.call(this);
  return r;
};

// Override isStackOutputLock to trace
FuncCallSpecs.prototype.isStackOutputLock = function() {
  const r = origIsStackOutputLock.call(this);
  if (r) {
    console.log(`[isStackOutputLock] true, stackoffset=${this.getSpacebaseOffset()}`);
  }
  return r;
};

(globalThis as any).__DUMP_OUTPUT__ = true;

const writer = new StringWriter();
const tc = new FunctionTestCollection(writer);
tc.loadTest('ghidra-src/Ghidra/Features/Decompiler/src/decompile/datatests/stackreturn.xml');
const failures: string[] = [];
tc.runTests(failures);
console.log(writer.toString());
if (failures.length > 0) {
  console.log('Failures:', failures);
}
