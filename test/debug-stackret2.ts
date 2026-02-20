import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';

startDecompilerLibrary('/opt/ghidra');

// Patch Heritage to trace stack delay
const origHeritage = (globalThis as any).__Heritage_heritage_orig;

// Monkey-patch FuncCallSpecs to trace stackoffset
const { FuncCallSpecs } = await import('../src/decompiler/fspec.js');
const origResolve = FuncCallSpecs.prototype.resolveSpacebaseRelative;
FuncCallSpecs.prototype.resolveSpacebaseRelative = function(data: any, phvn: any) {
  console.log(`[resolveSpacebaseRelative] called, stackoffset before = ${this.getSpacebaseOffset()}`);
  origResolve.call(this, data, phvn);
  console.log(`[resolveSpacebaseRelative] stackoffset after = ${this.getSpacebaseOffset()}`);
};

const origAbort = FuncCallSpecs.prototype.abortSpacebaseRelative;
FuncCallSpecs.prototype.abortSpacebaseRelative = function(data: any) {
  console.log(`[abortSpacebaseRelative] called, stackPlaceholderSlot = ${(this as any).stackPlaceholderSlot}`);
  origAbort.call(this, data);
};

// Monkey-patch Heritage.heritage to trace pass
const { Heritage } = await import('../src/decompiler/heritage.js');
const origHeritage2 = Heritage.prototype.heritage;
Heritage.prototype.heritage = function() {
  console.log(`[Heritage.heritage] pass=${(this as any).pass}`);
  // Print space delay info
  for (let i = 0; i < (this as any).infolist.length; i++) {
    const info = (this as any).infolist[i];
    if (info.space) {
      console.log(`  space=${info.space.getName()} delay=${info.delay} hasCallPlaceholders=${info.hasCallPlaceholders}`);
    }
  }
  const result = origHeritage2.call(this);
  console.log(`[Heritage.heritage] done, pass now=${(this as any).pass}`);
  return result;
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
