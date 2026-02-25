/**
 * @file parallel_workers.ts
 * @description Child-process based parallel decompilation orchestrator.
 *
 * Spawns N child processes via fork(), each with its own Architecture instance.
 * Functions are dispatched one at a time (work-stealing pattern):
 * when a child finishes, it gets the next function from the queue.
 *
 * Uses child_process.fork() instead of worker_threads because Node.js v23's
 * native type stripping doesn't handle .js→.ts import resolution in workers.
 * fork() inherits tsx's ESM loader hooks, giving full module resolution.
 *
 * This gives true multi-core parallelism for CPU-bound decompilation.
 */

import { fork, type ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';
import type { Writer } from '../util/writer.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

export interface WorkerDecompileResult {
  /** Function name */
  name: string;
  /** Decompiled C output */
  output: string;
  /** Decompilation time in milliseconds */
  timeMs: number;
  /** Whether decompilation succeeded */
  success: boolean;
  /** Error message if decompilation failed */
  error?: string;
  /** Which worker processed this function */
  workerId: number;
}

// ---------------------------------------------------------------------------
// WorkerParallelDecompiler
// ---------------------------------------------------------------------------

export class WorkerParallelDecompiler {
  private xmlPath: string;
  private xmlString: string;
  private sleighPath: string;
  private workerCount: number;
  private writer: Writer | null;
  private functionNames: string[];
  private enhancedDisplay: boolean;

  /**
   * @param xmlPath path to the XML file containing the binary image and scripts
   * @param sleighPath SLEIGH_PATH for the decompiler library
   * @param workerCount number of child processes (default: cpu count - 1)
   * @param writer optional writer for progress messages
   * @param enhancedDisplay use standard C types and Ghidra GUI-style globals
   */
  constructor(
    xmlPath: string,
    sleighPath: string,
    workerCount?: number,
    writer?: Writer,
    enhancedDisplay?: boolean,
  ) {
    this.xmlPath = xmlPath;
    this.sleighPath = sleighPath;
    this.workerCount = workerCount ?? Math.max(1, os.cpus().length - 1);
    this.writer = writer ?? null;
    this.enhancedDisplay = enhancedDisplay ?? false;
    this.xmlString = fs.readFileSync(xmlPath, 'utf-8');
    this.functionNames = WorkerParallelDecompiler.extractFunctionNames(this.xmlString);
  }

  /**
   * Extract function names from `<com>lo fu NAME</com>` tags in the XML.
   * This is a lightweight scan — no full XML parse needed.
   */
  static extractFunctionNames(xml: string): string[] {
    const names: string[] = [];
    const regex = /<com>\s*(?:lo(?:ad)?\s+fu(?:nction)?)\s+(\S+)\s*<\/com>/g;
    let match;
    while ((match = regex.exec(xml)) !== null) {
      names.push(match[1]);
    }
    return names;
  }

  /** Number of functions found in the XML. */
  getFunctionCount(): number {
    return this.functionNames.length;
  }

  /** List of function names found in the XML. */
  getFunctionNames(): string[] {
    return [...this.functionNames];
  }

  /**
   * Decompile all functions using child processes.
   *
   * Returns results in the same order as the functions appear in the XML.
   * Work is distributed via a work-stealing queue: when a child finishes,
   * it gets the next unprocessed function.
   */
  async decompileAll(): Promise<WorkerDecompileResult[]> {
    if (this.functionNames.length === 0) return [];

    const workerEntryPath = resolve(__dirname, 'worker_entry.ts');
    const actualWorkerCount = Math.min(this.workerCount, this.functionNames.length);
    const children: ChildProcess[] = [];

    return new Promise<WorkerDecompileResult[]>((resolve, reject) => {
      const results = new Map<string, WorkerDecompileResult>();
      const queue = [...this.functionNames];
      let completed = 0;
      let initErrors = 0;
      let resolved = false;
      const inFlight = new Map<number, string>(); // workerId → functionName

      const assignNext = (workerId: number): void => {
        if (queue.length === 0) return;
        const funcName = queue.shift()!;
        inFlight.set(workerId, funcName);
        children[workerId].send({
          type: 'assign',
          functionName: funcName,
        });
      };

      const finish = (): void => {
        if (resolved) return;
        resolved = true;
        // Shut down all children
        for (const child of children) {
          try { child.send({ type: 'shutdown' }); } catch {}
        }
        // Return results in original order
        const ordered = this.functionNames.map(name =>
          results.get(name) ?? {
            name,
            output: '',
            timeMs: 0,
            success: false,
            error: 'No result received',
            workerId: -1,
          }
        );
        resolve(ordered);
      };

      const checkDone = (): void => {
        if (completed >= this.functionNames.length) {
          finish();
        }
      };

      for (let i = 0; i < actualWorkerCount; i++) {
        const child = fork(workerEntryPath, [], {
          stdio: ['pipe', 'pipe', 'pipe', 'ipc'],
        });

        // Suppress child stdout/stderr (or pipe to writer)
        child.stdout?.on('data', () => {});
        child.stderr?.on('data', (data: Buffer) => {
          // Log stderr from children for debugging
          const msg = data.toString().trim();
          if (msg && !msg.includes('ExperimentalWarning')) {
            this.log(`Worker ${i} stderr: ${msg}\n`);
          }
        });

        child.on('message', (msg: any) => {
          if (msg.type === 'ready') {
            this.log(`Worker ${i} ready\n`);
            assignNext(i);
          } else if (msg.type === 'result') {
            inFlight.delete(i);
            results.set(msg.name, {
              name: msg.name,
              output: msg.output,
              timeMs: msg.timeMs,
              success: msg.success,
              error: msg.error,
              workerId: msg.workerId,
            });
            completed++;
            this.log(
              `[${completed}/${this.functionNames.length}] ${msg.name}` +
              ` (${msg.timeMs.toFixed(0)}ms, w${msg.workerId})` +
              (msg.success ? '' : ` FAILED: ${msg.error}`) + '\n'
            );
            assignNext(i);
            checkDone();
          } else if (msg.type === 'init_error') {
            initErrors++;
            this.log(`Worker ${i} init failed: ${msg.error}\n`);
            if (initErrors >= actualWorkerCount && !resolved) {
              resolved = true;
              reject(new Error(`All ${actualWorkerCount} workers failed to initialize`));
            }
          }
        });

        child.on('error', (err: Error) => {
          this.log(`Worker ${i} error: ${err.message}\n`);
          const funcName = inFlight.get(i);
          if (funcName) {
            inFlight.delete(i);
            if (!results.has(funcName)) {
              results.set(funcName, {
                name: funcName,
                output: '',
                timeMs: 0,
                success: false,
                error: `Worker crashed: ${err.message}`,
                workerId: i,
              });
              completed++;
            }
            checkDone();
          }
        });

        child.on('exit', (_code) => {
          const funcName = inFlight.get(i);
          if (funcName) {
            inFlight.delete(i);
            if (!results.has(funcName)) {
              results.set(funcName, {
                name: funcName,
                output: '',
                timeMs: 0,
                success: false,
                error: 'Worker exited unexpectedly',
                workerId: i,
              });
              completed++;
            }
            checkDone();
          }
        });

        children.push(child);

        // Send init message with XML data
        child.send({
          type: 'init',
          xmlString: this.xmlString,
          sleighPath: this.sleighPath,
          workerId: i,
          enhancedDisplay: this.enhancedDisplay,
        });
      }
    });
  }

  private log(msg: string): void {
    if (this.writer) {
      this.writer.write(msg);
    }
  }
}
