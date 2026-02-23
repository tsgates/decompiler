/**
 * @file parallel.ts
 * @description Parallel decompilation infrastructure.
 *
 * Provides multi-function parallel decompilation by cloning the action tree
 * per-job and buffering shared CommentDB writes.
 *
 * Components:
 * - BufferedCommentDB: wraps a CommentDatabase, buffering mutations per-job
 * - DecompileJob: decompiles a single function with an independent action tree
 * - ParallelDecompiler: orchestrates concurrent DecompileJobs
 */

import type { uint4 } from '../core/types.js';
import { Address } from '../core/address.js';
import type { Encoder, Decoder } from '../core/marshal.js';
import {
  Comment,
  CommentDatabase,
  type CommentSetIterator,
} from './comment.js';
import type { Action } from './action.js';
import type { Writer } from '../util/writer.js';

// ---------------------------------------------------------------------------
// Forward type declarations (avoid circular import issues)
// ---------------------------------------------------------------------------

type Architecture = any;
type Funcdata = any;

// ---------------------------------------------------------------------------
// BufferedCommentDB
// ---------------------------------------------------------------------------

/**
 * A CommentDatabase wrapper that buffers all write operations.
 *
 * Read operations (beginComment, endComment) are delegated to the underlying
 * database. Write operations (addComment, addCommentNoDuplicate, deleteComment,
 * clearType) are captured in internal buffers and only applied to the real
 * database when flush() is called.
 *
 * This allows multiple concurrent decompilation jobs to issue comment mutations
 * independently. After each job completes, its buffered writes are flushed
 * sequentially to the shared database.
 */
export class BufferedCommentDB extends CommentDatabase {
  private underlying: CommentDatabase;
  private pendingAdds: Array<{ tp: uint4; fad: Address; ad: Address; txt: string }> = [];
  private pendingAddsNoDup: Array<{ tp: uint4; fad: Address; ad: Address; txt: string }> = [];
  private pendingDeletes: Comment[] = [];
  private pendingClears: Array<{ fad: Address; tp: uint4 }> = [];

  constructor(underlying: CommentDatabase) {
    super();
    this.underlying = underlying;
  }

  // --- Read operations: delegate to underlying ---

  beginComment(fad: Address): CommentSetIterator {
    return this.underlying.beginComment(fad);
  }

  endComment(fad: Address): CommentSetIterator {
    return this.underlying.endComment(fad);
  }

  // --- Write operations: buffer ---

  clear(): void {
    // Buffer a full clear — on flush, clear the underlying
    this.pendingAdds.length = 0;
    this.pendingAddsNoDup.length = 0;
    this.pendingDeletes.length = 0;
    this.pendingClears.length = 0;
    // Mark that a full clear is pending
    this.pendingClears.push({ fad: new Address(), tp: 0xFFFFFFFF });
  }

  clearType(fad: Address, tp: uint4): void {
    this.pendingClears.push({ fad, tp });
  }

  addComment(tp: uint4, fad: Address, ad: Address, txt: string): void {
    this.pendingAdds.push({ tp, fad, ad, txt });
  }

  addCommentNoDuplicate(tp: uint4, fad: Address, ad: Address, txt: string): boolean {
    this.pendingAddsNoDup.push({ tp, fad, ad, txt });
    // Optimistically return true; actual dedup happens at flush time
    return true;
  }

  deleteComment(com: Comment): void {
    this.pendingDeletes.push(com);
  }

  encode(encoder: Encoder): void {
    this.underlying.encode(encoder);
  }

  decode(decoder: Decoder): void {
    this.underlying.decode(decoder);
  }

  // --- Flush: apply all buffered operations to the underlying DB ---

  /**
   * Apply all buffered mutations to the underlying CommentDatabase.
   * Call this after the decompilation job completes.
   * Operations are applied in order: clears, deletes, adds, adds-no-dup.
   */
  flush(): void {
    // Apply clears
    for (const c of this.pendingClears) {
      if (c.tp === 0xFFFFFFFF && c.fad.isInvalid()) {
        this.underlying.clear();
      } else {
        this.underlying.clearType(c.fad, c.tp);
      }
    }

    // Apply deletes
    for (const com of this.pendingDeletes) {
      this.underlying.deleteComment(com);
    }

    // Apply adds
    for (const a of this.pendingAdds) {
      this.underlying.addComment(a.tp, a.fad, a.ad, a.txt);
    }

    // Apply adds-no-dup
    for (const a of this.pendingAddsNoDup) {
      this.underlying.addCommentNoDuplicate(a.tp, a.fad, a.ad, a.txt);
    }

    // Clear buffers
    this.pendingClears.length = 0;
    this.pendingDeletes.length = 0;
    this.pendingAdds.length = 0;
    this.pendingAddsNoDup.length = 0;
  }

  /** Get the number of pending operations (for diagnostics). */
  getPendingCount(): number {
    return this.pendingClears.length + this.pendingDeletes.length
      + this.pendingAdds.length + this.pendingAddsNoDup.length;
  }
}

// ---------------------------------------------------------------------------
// DecompileJob
// ---------------------------------------------------------------------------

/**
 * Result of a single decompilation job.
 */
export interface DecompileResult {
  /** The function that was decompiled */
  funcdata: Funcdata;
  /** The function name */
  name: string;
  /** Whether decompilation succeeded */
  success: boolean;
  /** Error message if decompilation failed */
  error?: string;
  /** Number of changes made by the action pipeline */
  actionCount: number;
}

/**
 * A single decompilation job that operates on one function.
 *
 * Each job owns an independent clone of the action tree, so its mutable
 * execution state (status, count, stateIndex) does not interfere with
 * other concurrent jobs. The Funcdata is per-function and already isolated.
 */
export class DecompileJob {
  private arch: Architecture;
  private actionTree: Action;
  private fd: Funcdata;
  private bufferedComments: BufferedCommentDB | null;

  /**
   * @param arch the shared Architecture (read-only during decompilation)
   * @param actionTree a cloned, independent action tree for this job
   * @param fd the Funcdata for the function to decompile
   * @param bufferedComments optional buffered comment DB for this job
   */
  constructor(arch: Architecture, actionTree: Action, fd: Funcdata, bufferedComments?: BufferedCommentDB) {
    this.arch = arch;
    this.actionTree = actionTree;
    this.fd = fd;
    this.bufferedComments = bufferedComments ?? null;
  }

  /**
   * Run the decompilation pipeline on this function.
   * @returns the decompilation result
   */
  run(): DecompileResult {
    const name = this.fd.getName();
    try {
      if (this.fd.hasNoCode()) {
        return { funcdata: this.fd, name, success: true, actionCount: 0 };
      }

      // Clear previous analysis
      this.clearAnalysis();

      // Reset and run the action pipeline
      this.actionTree.reset(this.fd);
      const res = this.actionTree.perform(this.fd);

      return {
        funcdata: this.fd,
        name,
        success: res >= 0,
        actionCount: res >= 0 ? res : 0,
      };
    } catch (err: any) {
      return {
        funcdata: this.fd,
        name,
        success: false,
        error: err.explain ?? err.message ?? String(err),
        actionCount: 0,
      };
    }
  }

  /**
   * Clear analysis for this function.
   * If a buffered comment DB is in use, mutations are buffered.
   */
  private clearAnalysis(): void {
    const Comment_warning = 16;       // Comment.warning
    const Comment_warningheader = 32; // Comment.warningheader
    this.fd.clear();
    if (this.bufferedComments !== null) {
      this.bufferedComments.clearType(
        this.fd.getAddress(),
        Comment_warning | Comment_warningheader
      );
    } else {
      this.arch.commentdb?.clearType(
        this.fd.getAddress(),
        Comment_warning | Comment_warningheader
      );
    }
  }

  /** Flush any buffered comment writes to the real DB. */
  flushComments(): void {
    if (this.bufferedComments !== null) {
      this.bufferedComments.flush();
    }
  }

  /** Get the Funcdata for this job. */
  getFuncdata(): Funcdata {
    return this.fd;
  }
}

// ---------------------------------------------------------------------------
// ParallelDecompiler
// ---------------------------------------------------------------------------

/**
 * Orchestrates parallel decompilation of multiple functions.
 *
 * Each function gets its own DecompileJob with a cloned action tree.
 * Jobs are run concurrently (up to a configurable concurrency limit)
 * using Promise.all with a semaphore pattern.
 *
 * In a single-threaded JS environment, the actual execution is sequential
 * (CPU-bound work can't be parallelized with Promises alone), but the
 * architecture correctly isolates mutable state per-job. True parallelism
 * can be achieved in the future by dispatching jobs to worker threads.
 */
export class ParallelDecompiler {
  private arch: Architecture;
  private concurrency: number;
  private writer: Writer | null;

  /**
   * @param arch the Architecture to decompile within
   * @param concurrency maximum number of concurrent jobs (default 1)
   * @param writer optional writer for status messages
   */
  constructor(arch: Architecture, concurrency: number = 1, writer?: Writer) {
    this.arch = arch;
    this.concurrency = Math.max(1, concurrency);
    this.writer = writer ?? null;
  }

  /**
   * Decompile a list of functions concurrently.
   *
   * Each function gets:
   * - A fresh clone of the action tree (independent mutable state)
   * - A BufferedCommentDB wrapper (when concurrency > 1)
   *
   * Results are returned in the same order as the input list.
   *
   * @param funcdataList array of Funcdata objects to decompile
   * @returns array of DecompileResults in input order
   */
  async decompileAll(funcdataList: Funcdata[]): Promise<DecompileResult[]> {
    if (funcdataList.length === 0) return [];

    const useBuffering = this.concurrency > 1;
    const results: DecompileResult[] = new Array(funcdataList.length);

    // Create jobs
    const jobs: Array<{ index: number; job: DecompileJob }> = [];
    for (let i = 0; i < funcdataList.length; i++) {
      const fd = funcdataList[i];
      const clonedAction = this.arch.allacts.cloneCurrentAction();
      const buffered = useBuffering
        ? new BufferedCommentDB(this.arch.commentdb!)
        : undefined;
      const job = new DecompileJob(this.arch, clonedAction, fd, buffered);
      jobs.push({ index: i, job });
    }

    // Execute with concurrency limit
    if (this.concurrency <= 1) {
      // Sequential: no async overhead needed
      for (const { index, job } of jobs) {
        if (this.writer) {
          this.writer.write(`Decompiling ${funcdataList[index].getName()}\n`);
        }
        results[index] = job.run();
        job.flushComments();
      }
    } else {
      // Concurrent: use semaphore pattern with Promise.all
      let running = 0;
      let resolveSlot: (() => void) | null = null;

      const acquireSlot = (): Promise<void> => {
        if (running < this.concurrency) {
          running++;
          return Promise.resolve();
        }
        return new Promise<void>((resolve) => {
          resolveSlot = resolve;
        });
      };

      const releaseSlot = (): void => {
        running--;
        if (resolveSlot !== null) {
          const r = resolveSlot;
          resolveSlot = null;
          running++;
          r();
        }
      };

      const promises = jobs.map(async ({ index, job }) => {
        await acquireSlot();
        try {
          if (this.writer) {
            this.writer.write(`Decompiling ${funcdataList[index].getName()}\n`);
          }
          // Yield to allow other microtasks before heavy CPU work
          await Promise.resolve();
          results[index] = job.run();
        } finally {
          // Flush comments sequentially after job completes
          job.flushComments();
          releaseSlot();
        }
      });

      await Promise.all(promises);
    }

    return results;
  }

  /**
   * Decompile a single function using a cloned action tree.
   * Convenience method equivalent to decompileAll([fd])[0].
   *
   * @param fd the function to decompile
   * @returns the decompilation result
   */
  async decompileOne(fd: Funcdata): Promise<DecompileResult> {
    const results = await this.decompileAll([fd]);
    return results[0];
  }
}
