// test/debug-longdouble8.ts - print raw pcode and decompiler XML for 'pass' function
import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { StringWriter } from '../src/util/writer.js';
import { ConsoleCommands } from '../src/console/testfunction.js';
import { mainloop } from '../src/console/ifacedecomp.js';
import { DocumentStorage } from '../src/core/xml.js';
import { ArchitectureCapability } from '../src/decompiler/architecture.js';
import * as fs from 'fs';

startDecompilerLibrary('/opt/ghidra');

const commands = [
  'option readonly on',
  'map addr r0x101000 float10 ldarr[16]',
  'parse line extern void writeLongDouble(float10 *ptrwrite,float10 valwrite);',
  'parse line extern void pass(float10 valpass);',
  'lo fu pass',
  'disassemble',
  'quit',
];

const writer = new StringWriter();
const console2 = new ConsoleCommands(writer, commands);
console2.setErrorIsDone(true);

// Load the test file
const docStorage = new DocumentStorage();
const content = fs.readFileSync('ghidra-src/Ghidra/Features/Decompiler/src/decompile/datatests/longdouble.xml', 'utf-8');
const doc = docStorage.parseDocument(content);
const el = doc.getRoot();

const children = el.getChildren();
for (const child of children) {
  if (child.getName() === 'binaryimage') {
    docStorage.registerTag(child);
    const capa = ArchitectureCapability.getCapability("xml");
    const dcp = console2.getData('decompile') as any;
    dcp.conf = capa!.buildArchitecture("test", "", writer);
    dcp.conf.init(docStorage);
    dcp.conf.readLoaderSymbols("::");
    break;
  }
}

mainloop(console2);
process.stdout.write(writer.toString());
