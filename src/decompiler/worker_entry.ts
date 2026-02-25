/**
 * @file worker_entry.ts
 * @description Child process entry point for parallel decompilation.
 *
 * Each child process independently loads the XML, initializes its own Architecture,
 * and decompiles functions assigned by the parent process via IPC.
 *
 * Uses child_process.fork() (not worker_threads) because Node.js v23's native
 * type stripping doesn't handle .js→.ts import resolution in worker threads.
 * fork() inherits tsx's ESM loader hooks, giving full module resolution.
 *
 * Protocol (IPC messages):
 *   Parent → Child:  {type:'init', xmlString, sleighPath, workerId}
 *   Child  → Parent: {type:'ready', workerId}
 *   Parent → Child:  {type:'assign', functionName}
 *   Child  → Parent: {type:'result', name, output, timeMs, success, error?, workerId}
 *   Parent → Child:  {type:'shutdown'}
 *   Child  → Parent: {type:'init_error', error, workerId}  (if init fails)
 */

// Register XmlArchitectureCapability singleton (side-effect import)
import '../console/xml_arch.js';

import { startDecompilerLibrary } from '../console/libdecomp.js';
import { DocumentStorage } from '../core/xml.js';
import { ArchitectureCapability } from './architecture.js';
import { ConsoleCommands } from '../console/testfunction.js';
import { StringWriter } from '../util/writer.js';
import { mainloop } from '../console/ifacedecomp.js';
import type { Writer } from '../util/writer.js';

// Wait for init message from parent
process.on('message', handleMessage);

let initialized = false;
let con: InstanceType<typeof ConsoleCommands>;
let commands: string[];
let workerId: number;

function handleMessage(msg: any): void {
  if (msg.type === 'init') {
    if (initialized) return;
    workerId = msg.workerId;
    try {
      // Initialize decompiler library (each child has its own module scope)
      startDecompilerLibrary(msg.sleighPath);

      // Create console infrastructure — ConsoleCommands registers all decompiler
      // commands (load function, decompile, print C, etc.) via IfaceCapability
      commands = [];
      const nullWriter: Writer = { write: () => {} };
      con = new ConsoleCommands(nullWriter, commands);
      con.setErrorIsDone(true);
      const dcp = con.getData('decompile') as any;

      // Parse XML and build Architecture (same pattern as FunctionTestCollection.buildProgram)
      const docStorage = new DocumentStorage();
      const doc = docStorage.parseDocument(msg.xmlString);
      const el = doc.getRoot();
      for (const child of el.getChildren()) {
        if (child.getName() === 'binaryimage') {
          docStorage.registerTag(child);
          break;
        }
      }
      const capa = ArchitectureCapability.getCapability('xml');
      if (!capa) throw new Error('Missing XML architecture capability');
      dcp.conf = capa.buildArchitecture('test', '', nullWriter);
      dcp.conf.init(docStorage);
      dcp.conf.readLoaderSymbols('::');

      if (msg.enhancedDisplay) {
        dcp.conf.applyEnhancedDisplay();
      }

      initialized = true;
      process.send!({ type: 'ready', workerId });
    } catch (err: any) {
      process.send!({
        type: 'init_error',
        error: err.explain ?? err.message ?? String(err),
        workerId,
      });
      process.exit(1);
    }
  } else if (msg.type === 'assign') {
    if (!initialized) return;
    const start = performance.now();
    try {
      // Set up commands for this function
      commands.length = 0;
      commands.push(`load function ${msg.functionName}`);
      commands.push('decompile');
      commands.push('print C');

      // Capture output — optr gets console messages, fileoptr gets C output
      const midBuf = new StringWriter();
      const outBuf = new StringWriter();
      con.optr = midBuf;
      con.fileoptr = outBuf;
      con.reset();

      mainloop(con);

      const output = outBuf.toString();
      const timeMs = performance.now() - start;

      process.send!({
        type: 'result',
        name: msg.functionName,
        output,
        timeMs,
        success: !con.isInError(),
        error: con.isInError() ? midBuf.toString().trim() : undefined,
        workerId,
      });
    } catch (err: any) {
      process.send!({
        type: 'result',
        name: msg.functionName,
        output: '',
        timeMs: performance.now() - start,
        success: false,
        error: err.explain ?? err.message ?? String(err),
        workerId,
      });
    }
  } else if (msg.type === 'shutdown') {
    process.exit(0);
  }
}
