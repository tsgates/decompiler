// test/debug-longdouble7.ts - Check float10 type properties
import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { StringWriter } from '../src/util/writer.js';
import { ConsoleCommands } from '../src/console/testfunction.js';
import { IfaceCapability } from '../src/console/interface.js';
import { DocumentStorage } from '../src/core/xml.js';
import { ArchitectureCapability } from '../src/decompiler/architecture.js';
import { type_metatype } from '../src/decompiler/type.js';
import * as fs from 'fs';

startDecompilerLibrary('/opt/ghidra');

const commands: string[] = [];
const writer = new StringWriter();
const console2 = new ConsoleCommands(writer, commands);

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

    const arch = dcp.conf;
    const types = arch.types;

    // Look up float10 type
    const float10 = types.getBase(10, type_metatype.TYPE_FLOAT);
    console.log("float10 type:", float10.getName());
    console.log("float10 size:", float10.getSize());
    console.log("float10 alignSize:", float10.getAlignSize());
    console.log("float10 alignment:", float10.getAlignment());
    console.log("float10 metatype:", float10.getMetatype());

    // Also check float4 and float8
    const float4 = types.getBase(4, type_metatype.TYPE_FLOAT);
    console.log("\nfloat4 size:", float4.getSize());
    console.log("float4 alignSize:", float4.getAlignSize());

    const float8 = types.getBase(8, type_metatype.TYPE_FLOAT);
    console.log("\nfloat8 size:", float8.getSize());
    console.log("float8 alignSize:", float8.getAlignSize());

    // Check array of float10
    const arr = types.getTypeArray(10, float10);
    console.log("\nArray of float10 (10 elements):");
    console.log("  array size:", arr.getSize());
    console.log("  array alignSize:", arr.getAlignSize());
    console.log("  element size:", (arr as any).getBase().getSize());
    console.log("  element alignSize:", (arr as any).getBase().getAlignSize());
    console.log("  numElements:", (arr as any).numElements());

    // Check what getFloatFormat returns
    const ff = arch.translate.getFloatFormat(10);
    console.log("\ngetFloatFormat(10):", ff);
    const ff4 = arch.translate.getFloatFormat(4);
    console.log("getFloatFormat(4):", ff4?.getSize());
    const ff8 = arch.translate.getFloatFormat(8);
    console.log("getFloatFormat(8):", ff8?.getSize());

    break;
  }
}
