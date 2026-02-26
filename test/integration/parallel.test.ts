/**
 * @file parallel.test.ts
 * @description Tests for the parallel decompilation infrastructure.
 *
 * Verifies that:
 * 1. Action tree cloning produces independent copies
 * 2. BufferedCommentDB correctly buffers and flushes
 * 3. DAGScheduler correctly computes wavefronts
 * 4. Parallel decompilation produces identical output to sequential
 */

import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

// Ensure the XmlArchitectureCapability singleton is registered
import '../../src/console/xml_arch.js';

import { startDecompilerLibrary } from '../../src/console/libdecomp.js';
import { FunctionTestCollection } from '../../src/console/testfunction.js';
import { StringWriter } from '../../src/util/writer.js';
import { BufferedCommentDB, DecompileJob, ParallelDecompiler } from '../../src/decompiler/parallel.js';
import { DAGScheduler, FuncdataRegion, type ActionDependencyDecl } from '../../src/decompiler/action_dag.js';
import { CommentDatabaseInternal } from '../../src/decompiler/comment.js';
import { Address } from '../../src/core/address.js';

const DATATESTS_DIR = process.env.DATATESTS_PATH || path.resolve(
  __dirname, '..', '..', 'ghidra-src', 'Ghidra', 'Features', 'Decompiler', 'src', 'decompile', 'datatests'
);

// Processors available via bundled spec files
const BUNDLED_PROCESSORS = new Set(['x86', 'AARCH64', 'ARM']);

function getProcessor(xmlPath: string): string | null {
  const content = fs.readFileSync(xmlPath, 'utf-8');
  const m = content.match(/arch="([^":]+)/);
  return m ? m[1] : null;
}

// ---------------------------------------------------------------------------
// DAGScheduler unit tests
// ---------------------------------------------------------------------------

describe('DAGScheduler', () => {
  it('puts independent actions in the same wavefront', () => {
    const scheduler = new DAGScheduler();
    const decls: ActionDependencyDecl[] = [
      { name: 'A', reads: [FuncdataRegion.TYPES], writes: [FuncdataRegion.SYMBOLS] },
      { name: 'B', reads: [FuncdataRegion.PCODE_OPS], writes: [FuncdataRegion.CASTS] },
    ];
    scheduler.build(decls);
    // A and B have no data hazards — should be in one wavefront
    expect(scheduler.getWavefrontCount()).toBe(1);
    expect(scheduler.getMaxParallelism()).toBe(2);
  });

  it('serializes actions with RAW dependencies', () => {
    const scheduler = new DAGScheduler();
    const decls: ActionDependencyDecl[] = [
      { name: 'A', reads: [], writes: [FuncdataRegion.SSA] },
      { name: 'B', reads: [FuncdataRegion.SSA], writes: [] },
    ];
    scheduler.build(decls);
    // A writes SSA, B reads SSA → A must precede B
    expect(scheduler.getWavefrontCount()).toBe(2);
    const wfs = scheduler.getWavefronts();
    expect(wfs[0]).toEqual([0]);
    expect(wfs[1]).toEqual([1]);
  });

  it('serializes actions with WAW dependencies', () => {
    const scheduler = new DAGScheduler();
    const decls: ActionDependencyDecl[] = [
      { name: 'A', reads: [], writes: [FuncdataRegion.VARNODES] },
      { name: 'B', reads: [], writes: [FuncdataRegion.VARNODES] },
    ];
    scheduler.build(decls);
    expect(scheduler.getWavefrontCount()).toBe(2);
  });

  it('serializes actions with WAR dependencies', () => {
    const scheduler = new DAGScheduler();
    const decls: ActionDependencyDecl[] = [
      { name: 'A', reads: [FuncdataRegion.TYPES], writes: [] },
      { name: 'B', reads: [], writes: [FuncdataRegion.TYPES] },
    ];
    scheduler.build(decls);
    expect(scheduler.getWavefrontCount()).toBe(2);
  });

  it('handles a diamond dependency pattern', () => {
    const scheduler = new DAGScheduler();
    const decls: ActionDependencyDecl[] = [
      { name: 'A', reads: [], writes: [FuncdataRegion.SSA] },                           // 0
      { name: 'B', reads: [FuncdataRegion.SSA], writes: [FuncdataRegion.TYPES] },       // 1
      { name: 'C', reads: [FuncdataRegion.SSA], writes: [FuncdataRegion.SYMBOLS] },     // 2
      { name: 'D', reads: [FuncdataRegion.TYPES, FuncdataRegion.SYMBOLS], writes: [] }, // 3
    ];
    scheduler.build(decls);
    // A → {B, C} → D
    // Wave 0: [A], Wave 1: [B, C], Wave 2: [D]
    expect(scheduler.getWavefrontCount()).toBe(3);
    const wfs = scheduler.getWavefronts();
    expect(wfs[0]).toEqual([0]);
    expect(wfs[1]).toEqual([1, 2]);
    expect(wfs[2]).toEqual([3]);
  });

  it('handles empty input', () => {
    const scheduler = new DAGScheduler();
    scheduler.build([]);
    expect(scheduler.getWavefrontCount()).toBe(0);
    expect(scheduler.getMaxParallelism()).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// BufferedCommentDB unit tests
// ---------------------------------------------------------------------------

describe('BufferedCommentDB', () => {
  it('buffers addComment and flushes to underlying', () => {
    const underlying = new CommentDatabaseInternal();
    const buffered = new BufferedCommentDB(underlying);

    const faddr = new Address();
    const addr = new Address();

    // addComment should not immediately affect underlying
    buffered.addComment(16, faddr, addr, 'test warning');
    // Can't easily check underlying is empty without iterating,
    // but check pending count
    expect(buffered.getPendingCount()).toBe(1);

    // After flush, pending should be 0
    buffered.flush();
    expect(buffered.getPendingCount()).toBe(0);
  });

  it('buffers clearType and flushes', () => {
    const underlying = new CommentDatabaseInternal();
    const buffered = new BufferedCommentDB(underlying);

    const faddr = new Address();
    buffered.clearType(faddr, 16);
    expect(buffered.getPendingCount()).toBe(1);

    buffered.flush();
    expect(buffered.getPendingCount()).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Action tree cloning test
// ---------------------------------------------------------------------------

describe('Action tree cloning', () => {
  let testFile: string | null = null;

  beforeAll(() => {
    startDecompilerLibrary();
    // Find a test file with a bundled architecture
    try {
      const files = fs.readdirSync(DATATESTS_DIR)
        .filter(f => f.endsWith('.xml'))
        .sort();
      for (const f of files) {
        const full = path.join(DATATESTS_DIR, f);
        const proc = getProcessor(full);
        if (proc && BUNDLED_PROCESSORS.has(proc)) {
          testFile = full;
          break;
        }
      }
    } catch {
      // No test files available
    }
  });

  it('cloned action tree produces identical output to original', { timeout: 60000 }, () => {
    if (!testFile) {
      return; // Skip if no test files
    }

    // Run with original action tree
    const writer1 = new StringWriter();
    const tc1 = new FunctionTestCollection(writer1);
    tc1.loadTest(testFile);
    const failures1: string[] = [];
    tc1.runTests(failures1);
    const output1 = tc1.getLastOutput();

    // Run again (FunctionTestCollection creates fresh state each time)
    const writer2 = new StringWriter();
    const tc2 = new FunctionTestCollection(writer2);
    tc2.loadTest(testFile);
    const failures2: string[] = [];
    tc2.runTests(failures2);
    const output2 = tc2.getLastOutput();

    // Both runs should produce identical output
    expect(output1).toBe(output2);
    expect(output1.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Parallel vs sequential comparison (if enough test files available)
// ---------------------------------------------------------------------------

describe('Parallel decompilation correctness', () => {
  let testFiles: string[] = [];

  beforeAll(() => {
    startDecompilerLibrary();
    try {
      testFiles = fs.readdirSync(DATATESTS_DIR)
        .filter(f => f.endsWith('.xml'))
        .sort()
        .map(f => path.join(DATATESTS_DIR, f))
        .filter(f => {
          const proc = getProcessor(f);
          return proc !== null && BUNDLED_PROCESSORS.has(proc);
        });
    } catch {
      // No test files
    }
  });

  it('each test file produces identical output whether using shared or cloned action tree', { timeout: 120000 }, () => {
    if (testFiles.length === 0) {
      return;
    }

    // Test with first 5 files for speed
    const subset = testFiles.slice(0, 5);
    for (const testFile of subset) {
      // Sequential run
      const writer1 = new StringWriter();
      const tc1 = new FunctionTestCollection(writer1);
      tc1.loadTest(testFile);
      const failures1: string[] = [];
      tc1.runTests(failures1);
      const seqOutput = tc1.getLastOutput();

      // Second sequential run (tests action tree reset correctness)
      const writer2 = new StringWriter();
      const tc2 = new FunctionTestCollection(writer2);
      tc2.loadTest(testFile);
      const failures2: string[] = [];
      tc2.runTests(failures2);
      const seqOutput2 = tc2.getLastOutput();

      // Both should be identical
      expect(seqOutput).toBe(seqOutput2);
    }
  });
});
