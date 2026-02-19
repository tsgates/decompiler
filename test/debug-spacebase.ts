import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { ConsoleWriter } from '../src/util/writer.js';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __filename_local = fileURLToPath(import.meta.url);
const __dirname_local = path.dirname(__filename_local);

startDecompilerLibrary('/opt/ghidra');
const w = new ConsoleWriter();
const basedir = path.join(__dirname_local, '..', 'ghidra-src', 'Ghidra', 'Features', 'Decompiler', 'src', 'decompile', 'datatests');

const collection = new FunctionTestCollection(w);
collection.loadTest(path.join(basedir, 'enum.xml'));
const arch = (collection as any).dcp?.conf;
if (arch) {
  console.log('numSpaces:', arch.numSpaces());
  for (let i = 0; i < arch.numSpaces(); i++) {
    const spc = arch.getSpace(i);
    if (spc) {
      const type = spc.getType();
      const n = spc.numSpacebase?.() ?? 0;
      console.log(`Space[${i}]: ${spc.getName()} type=${type} numSpacebase=${n}`);
      if (n > 0) {
        const base = spc.getSpacebase(0);
        console.log(`  base: space=${base.space?.getName?.()} offset=0x${base.offset.toString(16)} size=${base.size}`);
      }
    }
  }
}
