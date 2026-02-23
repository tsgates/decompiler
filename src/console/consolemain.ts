#!/usr/bin/env node
/**
 * @file consolemain.ts
 * @description Console-specific commands and main entry point for the decompiler CLI.
 *
 * Translated from Ghidra's consolemain.cc
 *
 * Defines four console-specific command classes (IfcLoadFile, IfcAddpath,
 * IfcSave, IfcRestore) and the main() function that bootstraps the
 * decompiler interface.
 */

import * as fs from 'fs';
import * as path from 'path';

import { FileManage } from '../core/filemanage.js';
import { DecoderError, LowlevelError } from '../core/error.js';
import { XmlEncode } from '../core/marshal.js';
import { DocumentStorage } from '../core/xml.js';
import { ArchitectureCapability } from '../decompiler/architecture.js';
import {
  InputStream,
  IfaceStatus,
  IfaceCommand,
  IfaceData,
  IfaceCapability,
  IfaceError,
  IfaceParseError,
  IfaceExecutionError,
} from './interface.js';
import { startDecompilerLibrary, shutdownDecompilerLibrary } from './libdecomp.js';
import type { Writer } from '../util/writer.js';

// Forward type declarations for not-yet-wired modules
type IfaceDecompData = any;
type Architecture = any;
type SleighArchitecture = any;
type IfaceTerm = any;

// ---------------------------------------------------------------------------
// Module-level state (replaces C++ static string savefile)
// ---------------------------------------------------------------------------

let savefile: string = '';

// ---------------------------------------------------------------------------
// IfaceDecompCommand base (inline, since ifacedecomp.ts is not yet translated)
// ---------------------------------------------------------------------------

/**
 * Root class for all decompiler specific commands.
 *
 * Commands share the data object IfaceDecompData and are capable of
 * iterating over all functions in the program/architecture.
 */
abstract class IfaceDecompCommand extends IfaceCommand {
  protected status!: IfaceStatus;
  protected dcp!: IfaceDecompData;

  setData(root: IfaceStatus, data: IfaceData | null): void {
    this.status = root;
    this.dcp = data as IfaceDecompData;
  }

  getModule(): string {
    return 'decompile';
  }

  createData(): IfaceData | null {
    // In the full translation this would return new IfaceDecompData().
    // For now, return a minimal object with the expected fields.
    return {
      fd: null,
      conf: null,
      cgraph: null,
      testCollection: null,
      clearArchitecture(): void {
        this.fd = null;
        if (this.conf != null) {
          this.conf = null;
        }
      },
    } as any;
  }
}

// ---------------------------------------------------------------------------
// IfcLoadFile
// ---------------------------------------------------------------------------

/**
 * Load an image file into the decompiler: `load file [<target>] <filename>`
 *
 * Reads an optional target string and a filename from the command line.
 * Finds a matching ArchitectureCapability, builds the architecture, and
 * initialises it. If the file is an XML file, loader symbols are read.
 */
export class IfcLoadFile extends IfaceDecompCommand {
  execute(s: InputStream): void {
    let filename: string;
    let target: string;

    if (this.dcp.conf != null) {
      throw new IfaceExecutionError('Load image already present');
    }

    filename = s.readToken();
    if (!s.eof()) {
      // If there are two parameters, the first is the target and the second
      // is the filename.
      target = filename;
      filename = s.readToken();
    } else {
      target = 'default';
    }

    const capa = ArchitectureCapability.findCapabilityByFile(filename);
    if (capa == null) {
      throw new IfaceExecutionError('Unable to recognize imagefile ' + filename);
    }

    this.dcp.conf = capa.buildArchitecture(filename, target, this.status.optr);

    // Attempt to open file and discern the processor architecture
    const store = new DocumentStorage(); // temporary storage for xml docs

    let errmsg: string = '';
    let iserror = false;
    try {
      this.dcp.conf.init(store);
    } catch (err: any) {
      if (err instanceof DecoderError || err instanceof LowlevelError) {
        errmsg = err.explain;
        iserror = true;
      } else {
        throw err;
      }
    }

    if (iserror) {
      this.status.optr.write(errmsg + '\n');
      this.status.optr.write('Could not create architecture\n');
      this.dcp.conf = null;
      return;
    }

    if (capa.getName() === 'xml') {
      // If file is xml, read in loader symbols
      this.dcp.conf.readLoaderSymbols('::');
    }

    this.status.optr.write(
      filename + ' successfully loaded: ' + this.dcp.conf.getDescription() + '\n'
    );
  }
}

// ---------------------------------------------------------------------------
// IfcAddpath
// ---------------------------------------------------------------------------

/**
 * Add a path to the specification search paths: `addpath <dirname>`
 */
export class IfcAddpath extends IfaceDecompCommand {
  execute(s: InputStream): void {
    const newpath = s.readToken();
    if (newpath.length === 0) {
      throw new IfaceParseError('Missing path name');
    }
    // SleighArchitecture.specpaths.addDir2Path(newpath);
    // TODO: wire up once SleighArchitecture is translated
  }
}

// ---------------------------------------------------------------------------
// IfcSave
// ---------------------------------------------------------------------------

/**
 * Save the current architecture state to a file: `save [<filename>]`
 *
 * If no filename is given, re-uses the previously supplied save filename.
 */
export class IfcSave extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (!s.eof()) {
      savefile = s.readToken();
    }

    if (savefile.length === 0) {
      throw new IfaceParseError('Missing savefile name');
    }

    let fd: number;
    try {
      fd = fs.openSync(savefile, 'w');
    } catch (_e) {
      throw new IfaceExecutionError('Unable to open file: ' + savefile);
    }

    try {
      const encoder = new XmlEncode();
      this.dcp.conf.encode(encoder);
      fs.writeFileSync(fd, (encoder as any).toString());
    } finally {
      fs.closeSync(fd);
    }
  }
}

// ---------------------------------------------------------------------------
// IfcRestore
// ---------------------------------------------------------------------------

/**
 * Restore a saved architecture state from a file: `restore <filename>`
 */
export class IfcRestore extends IfaceDecompCommand {
  execute(s: InputStream): void {
    savefile = s.readToken();
    if (savefile.length === 0) {
      throw new IfaceParseError('Missing file name');
    }

    const store = new DocumentStorage();
    let xmlContent: string;
    try {
      xmlContent = fs.readFileSync(savefile, 'utf-8');
    } catch (_e) {
      throw new IfaceExecutionError('Unable to open file: ' + savefile);
    }

    const doc = store.parseDocument(xmlContent);
    store.registerTag(doc.getRoot());
    this.dcp.clearArchitecture(); // Clear any old architecture

    const capa = ArchitectureCapability.findCapabilityByDocument(doc);
    if (capa == null) {
      throw new IfaceExecutionError('Could not find savefile tag');
    }

    this.dcp.conf = capa.buildArchitecture('', '', this.status.optr);
    try {
      this.dcp.conf.restoreXml(store);
    } catch (err: any) {
      if (err instanceof LowlevelError || err instanceof DecoderError) {
        throw new IfaceExecutionError(err.explain);
      }
      throw err;
    }

    this.status.optr.write(
      savefile + ' successfully loaded: ' + this.dcp.conf.getDescription() + '\n'
    );
  }
}

// ---------------------------------------------------------------------------
// execute  (single-command wrapper with error handling)
// ---------------------------------------------------------------------------

/**
 * Execute one command and handle any exceptions.
 * Error messages are printed to the console. For low-level errors the current
 * function is reset to null.
 *
 * @param status - the console interface
 * @param dcp - the shared program data
 */
function execute(status: IfaceStatus, dcp: IfaceDecompData): void {
  try {
    status.runCommand();
    return;
  } catch (err: any) {
    if (err instanceof IfaceParseError) {
      status.optr.write('Command parsing error: ' + err.explain + '\n');
    } else if (err instanceof IfaceExecutionError) {
      status.optr.write('Execution error: ' + err.explain + '\n');
    } else if (err instanceof IfaceError) {
      status.optr.write('ERROR: ' + err.explain + '\n');
    } else if (err instanceof DecoderError) {
      status.optr.write('Decoding ERROR: ' + err.explain + '\n');
      if (typeof dcp.abortFunction === 'function') {
        dcp.abortFunction(status.optr);
      }
    } else if (err instanceof LowlevelError) {
      status.optr.write('Low-level ERROR: ' + err.explain + '\n');
      if (typeof dcp.abortFunction === 'function') {
        dcp.abortFunction(status.optr);
      }
    } else {
      throw err;
    }
  }
  status.evaluateError();
}

// ---------------------------------------------------------------------------
// mainloop
// ---------------------------------------------------------------------------

/**
 * Execute commands as they become available.
 *
 * Execution loops until either the `done` field in the console is set or all
 * streams have ended. This handles popping script states pushed on by the
 * IfcSource command.
 *
 * @param status - the console interface
 */
function mainloop(status: IfaceStatus): void {
  const dcp = status.getData('decompile') as IfaceDecompData;
  for (;;) {
    while (!status.isStreamFinished()) {
      status.writePrompt();
      execute(status, dcp);
    }
    if (status.done) break;
    if (status.getNumInputStreamSize() === 0) break;
    status.popScript();
  }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

/**
 * Main entry point for the console decompiler.
 *
 * 1. Parse command-line arguments (-i initscript, -s specpath).
 * 2. Discover the Ghidra root from argv[0] or the SLEIGHHOME env variable.
 * 3. Initialise the decompiler library.
 * 4. Create an IfaceTerm console, register all commands plus the four
 *    console-specific commands (load file, addpath, save, restore).
 * 5. If an init script was specified, push it.
 * 6. Run the main command loop.
 * 7. Clean up and exit.
 *
 * @param args - command-line arguments (without the node / script prefix)
 * @returns exit code (0 for success, 1 for error)
 */
export function main(args: string[]): number {
  let initscript: string | null = null;
  /** Parallel decompilation concurrency (0 = disabled/sequential) */
  let parallelConcurrency: number = 0;
  /** Worker-thread parallelism (0 = disabled, N = number of worker threads) */
  let workerCount: number = 0;

  {
    const extrapaths: string[] = [];
    let i = 0;
    while (i < args.length && args[i].startsWith('-')) {
      if (args[i] === '--parallel' || args[i] === '-p') {
        i++;
        const n = parseInt(args[i], 10);
        parallelConcurrency = isNaN(n) ? 4 : Math.max(1, n);
      } else if (args[i] === '--workers' || args[i] === '-w') {
        i++;
        const n = parseInt(args[i], 10);
        workerCount = isNaN(n) ? 4 : Math.max(1, n);
      } else if (args[i][1] === 'i') {
        i++;
        initscript = args[i];
      } else if (args[i][1] === 's') {
        i++;
        extrapaths.push(args[i]);
      }
      i += 1;
    }

    // Discover ghidra root from the script location or SLEIGHHOME
    let ghidraroot: string = FileManage.discoverGhidraRoot(process.argv[1] ?? '');
    if (ghidraroot.length === 0) {
      const sleighhomepath = process.env.SLEIGHHOME;
      if (sleighhomepath == null || sleighhomepath.length === 0) {
        if (extrapaths.length === 0) {
          process.stderr.write('Could not discover root of Ghidra installation\n');
          process.exit(1);
        }
      } else {
        ghidraroot = sleighhomepath;
      }
    }

    startDecompilerLibrary(ghidraroot, extrapaths);
  }

  // Create the console interface.
  // The full IfaceTerm is not yet translated; for now we create a minimal
  // IfaceStatus-derived object that reads from stdin and writes to stdout.
  let status: IfaceStatus;
  try {
    // IfaceTerm constructor: IfaceTerm(prompt, istream, ostream)
    // TODO: Replace with real IfaceTerm once ifaceterm.ts is translated.
    const stdoutWriter: Writer = {
      write(s: string): void {
        process.stdout.write(s);
      },
    };
    status = createMinimalIfaceStatus('[decomp]> ', stdoutWriter);
  } catch (err: any) {
    if (err instanceof IfaceError) {
      process.stderr.write('Interface error during setup: ' + err.explain + '\n');
      process.exit(1);
    }
    throw err;
  }

  // Register commands for decompiler and all modules
  IfaceCapability.registerAllCommands(status);

  // Extra commands specific to the console application
  status.registerCom(new IfcLoadFile(), 'load', 'file');
  status.registerCom(new IfcAddpath(), 'addpath');
  status.registerCom(new IfcSave(), 'save');
  status.registerCom(new IfcRestore(), 'restore');

  if (initscript != null) {
    try {
      status.pushScript(initscript, 'init> ');
    } catch (err: any) {
      if (err instanceof IfaceParseError) {
        status.optr.write(err.explain + '\n');
        status.done = true;
      } else {
        throw err;
      }
    }
  }

  // Make parallel concurrency available to commands via status
  if (parallelConcurrency > 0) {
    (status as any).parallelConcurrency = parallelConcurrency;
  }
  if (workerCount > 0) {
    (status as any).workerCount = workerCount;
  }

  if (!status.done) {
    mainloop(status);
  }

  const retval: number = status.isInError() ? 1 : 0;

  try {
    // Cleanup -- in TS there is no explicit destructor, but we give the
    // status object a chance to release resources.
    if (typeof (status as any).dispose === 'function') {
      (status as any).dispose();
    }
  } catch (err: any) {
    if (err instanceof IfaceError) {
      process.stderr.write(err.explain + '\n');
    }
  }

  shutdownDecompilerLibrary();

  return retval;
}

// ---------------------------------------------------------------------------
// Minimal IfaceStatus for stdin/stdout (stand-in for IfaceTerm)
// ---------------------------------------------------------------------------

import * as readline from 'readline';

/**
 * Create a minimal IfaceStatus implementation that reads lines from stdin
 * and writes output via the given Writer. This is a placeholder until the
 * full IfaceTerm class is translated.
 */
function createMinimalIfaceStatus(prompt: string, writer: Writer): IfaceStatus {
  // We need a concrete subclass of the abstract IfaceStatus.
  // Build it dynamically here so this file remains self-contained.

  let stdinLines: string[] = [];
  let stdinEof = false;
  let stdinLoaded = false;

  /**
   * Eagerly load all of stdin (only suitable for piped / scripted input).
   * For true interactive readline behaviour, IfaceTerm should be used.
   */
  function ensureStdinLoaded(): void {
    if (stdinLoaded) return;
    stdinLoaded = true;
    try {
      const buf = fs.readFileSync(0, 'utf-8'); // fd 0 = stdin
      stdinLines = buf.split('\n');
    } catch (_e) {
      stdinEof = true;
    }
  }

  // Use an anonymous class extending IfaceStatus.
  const StatusImpl = class extends IfaceStatus {
    private lineIndex = 0;

    constructor(prmpt: string, os: Writer) {
      super(prmpt, os);
    }

    protected readLine(): string {
      ensureStdinLoaded();
      if (this.lineIndex >= stdinLines.length) {
        stdinEof = true;
        return '';
      }
      return stdinLines[this.lineIndex++];
    }

    isStreamFinished(): boolean {
      if (this.done || this.isInError()) return true;
      ensureStdinLoaded();
      return this.lineIndex >= stdinLines.length;
    }
  };

  return new StatusImpl(prompt, writer);
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

if (typeof require !== 'undefined' && require.main === module) {
  const code = main(process.argv.slice(2));
  process.exit(code);
}
