import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { StringWriter } from '../src/util/writer.js';

startDecompilerLibrary('/opt/ghidra');

// Run specific commands to get raw output
const { IfaceDecompData } = await import('../src/console/ifacedecomp.js');
const { IfaceStatus, InputStream } = await import('../src/console/interface.js');

const iface = new IfaceStatus("test", new StringWriter());
const dcp = new IfaceDecompData();
dcp.registerCmds(iface);
iface.executeCommand('openArch ghidra-src/Ghidra/Features/Decompiler/src/decompile/datatests/stackreturn.xml\n');
iface.executeCommand('map addr r0x100140 int8 perf_ret\n');
iface.executeCommand('map addr r0x100150 int4 small_ret\n');
iface.executeCommand('map addr r0x100158 int8 big_ret\n');
iface.executeCommand('lo fu perfect\n');
iface.executeCommand('map return s0x10 int8\n');
iface.executeCommand('lo fu small\n');
iface.executeCommand('map return s0x10 int8\n');
iface.executeCommand('lo fu big\n');
iface.executeCommand('map return s0x12 int2\n');
iface.executeCommand('lo fu stackreturn\n');
iface.executeCommand('map addr s0xfffffffffffffff0 int8 local\n');
iface.executeCommand('decompile\n');

const rawWriter = new StringWriter();
iface.executeCommand('print raw\n');
console.log('=== RAW OUTPUT ===');
console.log(iface.getOutput());

iface.executeCommand('print C\n');
console.log('=== C OUTPUT ===');
console.log(iface.getOutput());
