/**
 * @file cover.ts
 * @description Classes describing the topological scope of variables within a function.
 *
 * Faithfully translated from Ghidra's cover.hh / cover.cc.
 */

import type { int4, uintm } from '../core/types.js';
import { OpCode } from '../core/opcodes.js';
import { PcodeOp } from './op.js';

// ---------------------------------------------------------------------------
// Forward type declarations — these will be replaced with real imports later
// ---------------------------------------------------------------------------

/** Forward declaration for FlowBlock */
type FlowBlock = any;
/** Forward declaration for Varnode */
type Varnode = any;
/** Forward declaration for BlockBasic */
type BlockBasic = any;

// ---------------------------------------------------------------------------
// Special sentinel values for CoverBlock start/stop
// ---------------------------------------------------------------------------

// In the C++ code, special pointer values 0, 1, and 2 are used as sentinels
// for the start and stop fields of CoverBlock:
//   null (0) in start => from beginning of block (or empty if stop is also null)
//   null (0) in stop  => empty/uncovered (if start is also null)
//   STOP_END (1)      => to the end of block
//   START_INPUT (2)   => special marker for input varnode
//
// We use distinct sentinel symbols to represent these in TypeScript.

/** Sentinel: coverage extends to the very end of the block. C++ `(PcodeOp*)1`. */
const STOP_END: unique symbol = Symbol('STOP_END');

/** Sentinel: special marker for input varnodes. C++ `(PcodeOp*)2`. */
const START_INPUT: unique symbol = Symbol('START_INPUT');

/**
 * The type for CoverBlock start/stop fields.
 * - `null` corresponds to C++ `(PcodeOp*)0`
 * - `STOP_END` corresponds to C++ `(PcodeOp*)1`
 * - `START_INPUT` corresponds to C++ `(PcodeOp*)2`
 * - Otherwise a real PcodeOp pointer
 */
type CoverBoundary = PcodeOp | null | typeof STOP_END | typeof START_INPUT;

// ---------------------------------------------------------------------------
// PcodeOpSet
// ---------------------------------------------------------------------------

/**
 * A set of PcodeOps that can be tested for Cover intersections.
 *
 * This is a set of PcodeOp objects, designed for quick intersection tests with a Cover.
 * The set is lazily constructed via its populate() method at the time the first intersection
 * test is needed.  Once an intersection has been established between a PcodeOp in this set
 * and a Varnode Cover, affectsTest() can do secondary testing to determine if the
 * intersection should prevent merging.
 */
export abstract class PcodeOpSet {
  /** Ops in this set, sorted on block index, then SeqNum.order */
  opList: PcodeOp[] = [];
  /** Index of first op in each non-empty block */
  blockStart: int4[] = [];
  /** Has the populate() method been called */
  private is_pop: boolean = false;

  constructor() {
    this.is_pop = false;
  }

  /** Return true if this set is populated */
  isPopulated(): boolean {
    return this.is_pop;
  }

  /** Add a PcodeOp into the set */
  protected addOp(op: PcodeOp): void {
    this.opList.push(op);
  }

  /** Sort ops in the set into blocks */
  protected finalize(): void {
    this.opList.sort(PcodeOpSet.compareByBlock);
    let blockNum: int4 = -1;
    for (let i: int4 = 0; i < this.opList.length; ++i) {
      const newBlockNum: int4 = this.opList[i].getParent().getIndex();
      if (newBlockNum > blockNum) {
        this.blockStart.push(i);
        blockNum = newBlockNum;
      }
    }
    this.is_pop = true;
  }

  /**
   * Populate the PcodeOp objects in this set.
   *
   * Call-back to the owner to lazily add PcodeOps to this set.  The override method calls
   * addOp() for each PcodeOp it wants to add, then calls finalize() to make this set ready
   * for intersection tests.
   */
  abstract populate(): void;

  /**
   * (Secondary) test that the given PcodeOp affects the Varnode.
   *
   * This method is called after an intersection of a PcodeOp in this set with a Varnode Cover
   * has been determined.  This allows the owner to make a final determination if merging
   * should be prevented.
   * @param op is the PcodeOp that intersects with the Varnode Cover
   * @param vn is the Varnode whose Cover is intersected
   * @returns true if merging should be prevented
   */
  abstract affectsTest(op: PcodeOp, vn: Varnode): boolean;

  /** Clear all PcodeOps in this set */
  clear(): void {
    this.is_pop = false;
    this.opList.length = 0;
    this.blockStart.length = 0;
  }

  /**
   * Compare PcodeOps for ordering within this set.
   * Compare first by index of the containing basic blocks, then by SeqNum ordering
   * (within the block).
   * @param a is the first PcodeOp to compare
   * @param b is the second PcodeOp to compare
   * @returns negative if a < b, positive if a > b, 0 if equal
   */
  static compareByBlock(a: PcodeOp, b: PcodeOp): number {
    if (a.getParent() !== b.getParent()) {
      return a.getParent().getIndex() - b.getParent().getIndex();
    }
    return a.getSeqNum().getOrder() - b.getSeqNum().getOrder();
  }
}

// ---------------------------------------------------------------------------
// CoverBlock
// ---------------------------------------------------------------------------

/**
 * The topological scope of a variable within a basic block.
 *
 * Within a basic block, the topological scope of a variable can be considered
 * a contiguous range of p-code operations.  This range can be described with
 * a start and stop PcodeOp object, indicating all p-code operations between
 * the two inclusive.  The start and stop may hold special encodings meaning:
 *   - From the beginning of the block
 *   - To the end of the block
 */
export class CoverBlock {
  /** Beginning of the range */
  private start: CoverBoundary;
  /** End of the range */
  private stop: CoverBoundary;

  /** Construct empty/uncovered block */
  constructor() {
    this.start = null;
    this.stop = null;
  }

  /**
   * Get the comparison index for a PcodeOp.
   *
   * PcodeOp objects and CoverBlock start/stop boundaries have a natural ordering
   * that can be used to tell if a PcodeOp falls between boundary points and if
   * CoverBlock objects intersect.  Ordering is determined by comparing the values
   * returned by this method.
   * @param op is the PcodeOp and/or boundary point
   * @returns a value for comparison
   */
  static getUIndex(op: CoverBoundary): uintm {
    if (op === null) {
      // Special marker for very beginning of block: C++ case 0
      return 0;
    }
    if (op === STOP_END) {
      // Special marker for very end of block: C++ case 1
      return 0xFFFFFFFF;  // ~((uintm)0) for 32-bit unsigned
    }
    if (op === START_INPUT) {
      // Special marker for input: C++ case 2
      return 0;
    }
    // Real PcodeOp
    if (op.isMarker()) {
      if (op.code() === OpCode.CPUI_MULTIEQUAL) {
        // MULTIEQUALs are considered very beginning
        return 0;
      } else if (op.code() === OpCode.CPUI_INDIRECT) {
        // INDIRECTs are considered to be at the location of the op they
        // are indirect for.  C++: PcodeOp::getOpFromConst(op->getIn(1)->getAddr())->getSeqNum().getOrder()
        // In the C++ code, the indirect target op is encoded as a constant pointer in input slot 1.
        // getOpFromConst extracts the PcodeOp* from the address offset.
        // In TypeScript, we replicate the same chain of calls.
        const indirectTarget: PcodeOp | null = PcodeOp.getOpFromConst(op.getIn(1)!.getAddr());
        if (indirectTarget === null) return op.getSeqNum().getOrder();
        return indirectTarget.getSeqNum().getOrder();
      }
    }
    return op.getSeqNum().getOrder();
  }

  /** Get the start of the range */
  getStart(): CoverBoundary {
    return this.start;
  }

  /** Get the stop of the range */
  getStop(): CoverBoundary {
    return this.stop;
  }

  /** Clear this block to empty/uncovered */
  clear(): void {
    this.start = null;
    this.stop = null;
  }

  /** Mark whole block as covered */
  setAll(): void {
    this.start = null;       // C++: (PcodeOp*)0
    this.stop = STOP_END;    // C++: (PcodeOp*)1
  }

  /**
   * Reset start of range.
   * If stop is currently null (empty), also set it to STOP_END (cover to end of block).
   */
  setBegin(begin: CoverBoundary): void {
    this.start = begin;
    if (this.stop === null) {
      this.stop = STOP_END;  // C++: (PcodeOp*)1
    }
  }

  /** Reset end of range */
  setEnd(end: CoverBoundary): void {
    this.stop = end;
  }

  /**
   * Return true if this is empty/uncovered.
   * Empty means start === null AND stop === null.
   */
  empty(): boolean {
    return (this.start === null) && (this.stop === null);
  }

  /**
   * Compute intersection with another CoverBlock.
   *
   * Characterize the intersection of this range with another CoverBlock.
   * Return:
   *   - 0 if there is no intersection
   *   - 1 if only the intersection is at boundary points
   *   - 2 if a whole interval intersects
   *
   * @param op2 is the other CoverBlock to compare
   * @returns the intersection characterization
   */
  intersect(op2: CoverBlock): int4 {
    let ustart: uintm, ustop: uintm;
    let u2start: uintm, u2stop: uintm;

    if (this.empty()) return 0;
    if (op2.empty()) return 0;

    ustart = CoverBlock.getUIndex(this.start);
    ustop = CoverBlock.getUIndex(this.stop);
    u2start = CoverBlock.getUIndex(op2.start);
    u2stop = CoverBlock.getUIndex(op2.stop);
    if (ustart <= ustop) {
      if (u2start <= u2stop) {
        // We are both one piece
        if ((ustop <= u2start) || (u2stop <= ustart)) {
          if ((ustart === u2stop) || (ustop === u2start))
            return 1;      // Boundary intersection
          else
            return 0;      // No intersection
        }
      } else {
        // They are two-piece, we are one-piece
        if ((ustart >= u2stop) && (ustop <= u2start)) {
          if ((ustart === u2stop) || (ustop === u2start))
            return 1;
          else
            return 0;
        }
      }
    } else {
      if (u2start <= u2stop) {
        // They are one piece, we are two-piece
        if ((u2start >= ustop) && (u2stop <= ustart)) {
          if ((u2start === ustop) || (u2stop === ustart))
            return 1;
          else
            return 0;
        }
      }
      // If both are two-pieces, then the intersection must be an interval
    }
    return 2;   // Interval intersection
  }

  /**
   * Check containment of given point.
   * If the given PcodeOp or boundary point is contained in this range, return true.
   * @param point is the given PcodeOp
   * @returns true if the point is contained
   */
  contain(point: CoverBoundary): boolean {
    let ustart: uintm, ustop: uintm, upoint: uintm;

    if (this.empty()) return false;
    upoint = CoverBlock.getUIndex(point);
    ustart = CoverBlock.getUIndex(this.start);
    ustop = CoverBlock.getUIndex(this.stop);

    if (ustart <= ustop)
      return ((upoint >= ustart) && (upoint <= ustop));
    return ((upoint <= ustop) || (upoint >= ustart));
  }

  /**
   * Characterize given point as boundary.
   *
   * Return:
   *   - 0 if point not on boundary
   *   - 1 if on tail
   *   - 2 if on the defining point
   *
   * @param point is the given PcodeOp point
   * @returns the characterization
   */
  boundary(point: CoverBoundary): int4 {
    let val: uintm;

    if (this.empty()) return 0;
    val = CoverBlock.getUIndex(point);
    if (CoverBlock.getUIndex(this.start) === val) {
      if (this.start !== null)   // C++: start != (PcodeOp*)0
        return 2;
    }
    if (CoverBlock.getUIndex(this.stop) === val) return 1;
    return 0;
  }

  /**
   * Merge another CoverBlock into this.
   * Compute the union of this with the other given CoverBlock,
   * replacing this in place.
   * @param op2 is the other given CoverBlock
   */
  merge(op2: CoverBlock): void {
    let internal1: boolean, internal2: boolean, internal3: boolean, internal4: boolean;
    let ustart: uintm, u2start: uintm;

    if (op2.empty()) return;   // Nothing to merge in
    if (this.empty()) {
      this.start = op2.start;
      this.stop = op2.stop;
      return;
    }
    ustart = CoverBlock.getUIndex(this.start);
    u2start = CoverBlock.getUIndex(op2.start);
    // Is start contained in op2
    internal4 = ((ustart === 0) && (op2.stop === STOP_END));
    internal1 = internal4 || op2.contain(this.start);
    // Is op2.start contained in this
    internal3 = ((u2start === 0) && (this.stop === STOP_END));
    internal2 = internal3 || this.contain(op2.start);

    if (internal1 && internal2) {
      if ((ustart !== u2start) || internal3 || internal4) {
        // Covered entire block
        this.setAll();
        return;
      }
    }
    if (internal1) {
      this.start = op2.start;   // Pick non-internal start
    } else if ((!internal1) && (!internal2)) {
      // Disjoint intervals
      if (ustart < u2start) {
        // Pick earliest start
        this.stop = op2.stop;   // then take other stop
      } else {
        this.start = op2.start;
      }
      return;
    }
    if (internal3 || op2.contain(this.stop)) {
      // Pick non-internal stop
      this.stop = op2.stop;
    }
  }

  /**
   * Dump a description of the covered range of ops in this block to a string.
   * @returns a human-readable description
   */
  dump(): string {
    let ustart: uintm, ustop: uintm;

    if (this.empty()) {
      return 'empty';
    }

    let s = '';

    ustart = CoverBlock.getUIndex(this.start);
    ustop = CoverBlock.getUIndex(this.stop);
    if (ustart === 0) {
      s += 'begin';
    } else if (ustart === 0xFFFFFFFF) {
      s += 'end';
    } else {
      s += (this.start as PcodeOp).getSeqNum().toString();
    }

    s += '-';

    if (ustop === 0) {
      s += 'begin';
    } else if (ustop === 0xFFFFFFFF) {
      s += 'end';
    } else {
      s += (this.stop as PcodeOp).getSeqNum().toString();
    }

    return s;
  }
}

// ---------------------------------------------------------------------------
// Cover
// ---------------------------------------------------------------------------

/**
 * A description of the topological scope of a single variable object.
 *
 * The topological scope of a variable within a function is the set of
 * locations within the code of the function where that variable holds a value.
 * For the decompiler, a high-level variable in this sense, HighVariable, is a collection
 * of Varnode objects.  In order to merge Varnodes into a HighVariable, the topological
 * scope of each Varnode must not intersect because that would mean the high-level variable
 * holds different values at the same point in the function.
 *
 * Internally this is implemented as a map from basic block index to their non-empty CoverBlock.
 */
export class Cover {
  /** Sorted ascending block indices */
  private blockIndices: int4[] = [];
  /** CoverBlocks parallel to blockIndices */
  private blocks: CoverBlock[] = [];

  /** Global empty CoverBlock for blocks not covered by this */
  private static readonly emptyBlock: CoverBlock = new CoverBlock();

  /** Binary search: index of first element >= idx */
  private _lowerBound(idx: int4): number {
    let lo = 0;
    let hi = this.blockIndices.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (this.blockIndices[mid] < idx) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  }

  /** Get or create a CoverBlock for the given block index */
  private _getOrCreate(idx: int4): CoverBlock {
    const pos = this._lowerBound(idx);
    if (pos < this.blockIndices.length && this.blockIndices[pos] === idx) {
      return this.blocks[pos];
    }
    const block = new CoverBlock();
    this.blockIndices.splice(pos, 0, idx);
    this.blocks.splice(pos, 0, block);
    return block;
  }

  /** Clear this to an empty Cover */
  clear(): void {
    this.blockIndices.length = 0;
    this.blocks.length = 0;
  }

  /**
   * Give ordering of this and another Cover.
   *
   * Compare this with another Cover by comparing just the indices of the first blocks
   * respectively that are partly covered.  Return -1, 0, or 1 if this Cover's first
   * block has a smaller, equal, or bigger index than the other Cover's first block.
   * @param op2 is the other Cover
   * @returns the comparison value
   */
  compareTo(op2: Cover): int4 {
    const a: int4 = this.blockIndices.length === 0 ? 1000000 : this.blockIndices[0];
    const b: int4 = op2.blockIndices.length === 0 ? 1000000 : op2.blockIndices[0];

    if (a < b) return -1;
    if (a === b) return 0;
    return 1;
  }

  /**
   * Get the CoverBlock corresponding to the i-th block.
   * @param i is the index of the given block
   * @returns a reference to the corresponding CoverBlock
   */
  getCoverBlock(i: int4): CoverBlock {
    const pos = this._lowerBound(i);
    if (pos < this.blockIndices.length && this.blockIndices[pos] === i)
      return this.blocks[pos];
    return Cover.emptyBlock;
  }

  /**
   * Characterize the intersection between this and another Cover.
   *
   * Return:
   *   - 0 if there is no intersection
   *   - 1 if the only intersection is on a boundary point
   *   - 2 if the intersection contains a range of p-code ops
   *
   * @param op2 is the other Cover
   * @returns the intersection characterization
   */
  intersect(op2: Cover): int4 {
    let res: int4 = 0;
    const keys1 = this.blockIndices;
    const keys2 = op2.blockIndices;
    let i1 = 0;
    let i2 = 0;

    for (;;) {
      if (i1 >= keys1.length) return res;
      if (i2 >= keys2.length) return res;

      if (keys1[i1] < keys2[i2]) {
        ++i1;
      } else if (keys1[i1] > keys2[i2]) {
        ++i2;
      } else {
        const newres = this.blocks[i1].intersect(op2.blocks[i2]);
        if (newres === 2) return 2;
        if (newres === 1)
          res = 1;
        ++i1;
        ++i2;
      }
    }
  }

  /**
   * Generate a list of blocks that intersect.
   *
   * @param listout will hold the list of intersecting block indices
   * @param op2 is the other Cover
   * @param level is the characterization threshold which must be exceeded
   */
  intersectList(listout: int4[], op2: Cover, level: int4): void {
    listout.length = 0;
    const keys1 = this.blockIndices;
    const keys2 = op2.blockIndices;
    let i1 = 0;
    let i2 = 0;

    for (;;) {
      if (i1 >= keys1.length) return;
      if (i2 >= keys2.length) return;

      if (keys1[i1] < keys2[i2]) {
        ++i1;
      } else if (keys1[i1] > keys2[i2]) {
        ++i2;
      } else {
        const val = this.blocks[i1].intersect(op2.blocks[i2]);
        if (val >= level)
          listout.push(keys1[i1]);
        ++i1;
        ++i2;
      }
    }
  }

  /**
   * Does this cover any PcodeOp in the given PcodeOpSet.
   *
   * @param opSet is the given set of PcodeOps
   * @param rep is the representative Varnode to use for secondary testing
   * @returns true if there is an intersection with this
   */
  intersectByOpSet(opSet: PcodeOpSet, rep: Varnode): boolean {
    if (opSet.opList.length === 0) return false;
    let setBlock: int4 = 0;
    let opIndex: int4 = opSet.blockStart[setBlock];
    let setIndex: int4 = opSet.opList[opIndex].getParent().getIndex();

    const firstBlockIndex: int4 = opSet.opList[0].getParent().getIndex();
    let ck = this._lowerBound(firstBlockIndex);

    while (ck < this.blockIndices.length) {
      const coverIndex: int4 = this.blockIndices[ck];
      if (coverIndex < setIndex) {
        ++ck;
      } else if (coverIndex > setIndex) {
        setBlock += 1;
        if (setBlock >= opSet.blockStart.length) break;
        opIndex = opSet.blockStart[setBlock];
        setIndex = opSet.opList[opIndex].getParent().getIndex();
      } else {
        const coverBlock: CoverBlock = this.blocks[ck];
        ++ck;
        let opMax: int4 = opSet.opList.length;
        setBlock += 1;
        if (setBlock < opSet.blockStart.length)
          opMax = opSet.blockStart[setBlock];
        do {
          const op: PcodeOp = opSet.opList[opIndex];
          if (coverBlock.contain(op)) {
            if (coverBlock.boundary(op) === 0) {
              if (opSet.affectsTest(op, rep))
                return true;
            }
          }
          opIndex += 1;
        } while (opIndex < opMax);
        if (setBlock >= opSet.blockStart.length) break;
      }
    }
    return false;
  }

  /**
   * Characterize the intersection on a specific block.
   *
   * @param blk is the index of the given block
   * @param op2 is the other Cover
   * @returns the characterization
   */
  intersectByBlock(blk: int4, op2: Cover): int4 {
    const pos1 = this._lowerBound(blk);
    if (pos1 >= this.blockIndices.length || this.blockIndices[pos1] !== blk) return 0;

    const pos2 = op2._lowerBound(blk);
    if (pos2 >= op2.blockIndices.length || op2.blockIndices[pos2] !== blk) return 0;

    return this.blocks[pos1].intersect(op2.blocks[pos2]);
  }

  /**
   * Does this contain the given PcodeOp.
   *
   * @param op is the given PcodeOp
   * @param max is 1 to test for any containment, 2 to force interior containment
   * @returns true if there is containment
   */
  contain(op: PcodeOp, max: int4): boolean {
    const pos = this._lowerBound(op.getParent().getIndex());
    if (pos >= this.blockIndices.length || this.blockIndices[pos] !== op.getParent().getIndex()) return false;
    const block = this.blocks[pos];
    if (block.contain(op)) {
      if (max === 1) return true;
      if (0 === block.boundary(op)) return true;
    }
    return false;
  }

  /**
   * Check the definition of a Varnode for containment.
   *
   * @param vn is the given Varnode
   * @returns the containment characterization
   */
  containVarnodeDef(vn: Varnode): int4 {
    let op: CoverBoundary = vn.getDef();
    let blk: int4;

    if (op === null) {
      op = START_INPUT;
      blk = 0;
    } else {
      blk = (op as PcodeOp).getParent().getIndex();
    }
    const pos = this._lowerBound(blk);
    if (pos >= this.blockIndices.length || this.blockIndices[pos] !== blk) return 0;
    const block = this.blocks[pos];
    if (block.contain(op)) {
      const boundtype: int4 = block.boundary(op);
      if (boundtype === 0) return 1;
      if (boundtype === 2) return 2;
      return 3;
    }
    return 0;
  }

  /**
   * Merge this with another Cover block by block.
   * @param op2 is the other Cover
   */
  merge(op2: Cover): void {
    for (let i = 0; i < op2.blockIndices.length; i++) {
      const key = op2.blockIndices[i];
      const block = this._getOrCreate(key);
      block.merge(op2.blocks[i]);
    }
  }

  /**
   * Reset this based on def-use of a single Varnode.
   *
   * @param vn is the single Varnode
   */
  rebuild(vn: Varnode): void {
    const path: Varnode[] = [vn];
    let pos: int4 = 0;

    this.addDefPoint(vn);
    do {
      const curVn: Varnode = path[pos];
      pos += 1;
      for (let d = 0; d < curVn.descend.length; d++) {
        const op: PcodeOp = curVn.descend[d];
        this.addRefPoint(op, vn);
        const outVn: Varnode = op.getOut();
        if (outVn !== null && outVn.isImplied())
          path.push(outVn);
      }
    } while (pos < path.length);
  }

  /**
   * Reset to the single point where the given Varnode is defined.
   *
   * @param vn is the Varnode
   */
  addDefPoint(vn: Varnode): void {
    this.blockIndices.length = 0;
    this.blocks.length = 0;

    const def: PcodeOp | null = vn.getDef();
    if (def !== null) {
      const blockIdx: int4 = def.getParent().getIndex();
      const block = this._getOrCreate(blockIdx);
      block.setBegin(def);
      block.setEnd(def);
    } else if (vn.isInput()) {
      const block = this._getOrCreate(0);
      block.setBegin(START_INPUT);
      block.setEnd(START_INPUT);
    }
  }

  /**
   * Fill-in this recursively from the given block.
   *
   * @param bl is the starting block to add
   */
  private addRefRecurse(bl: FlowBlock): void {
    let j: int4;

    const blIdx: int4 = bl.getIndex();
    const block = this._getOrCreate(blIdx);
    if (block.empty()) {
      block.setAll();
      for (j = 0; j < bl.sizeIn(); ++j)
        this.addRefRecurse(bl.getIn(j));
    } else {
      const op: CoverBoundary = block.getStop();
      const ustart: uintm = CoverBlock.getUIndex(block.getStart());
      const ustop: uintm = CoverBlock.getUIndex(op);
      if ((ustop !== 0xFFFFFFFF) && (ustop >= ustart))
        block.setEnd(STOP_END);

      if ((ustop === 0) && (block.getStart() === null)) {
        if ((op !== null) && (op !== START_INPUT) && (op !== STOP_END) &&
            (op as PcodeOp).code() === OpCode.CPUI_MULTIEQUAL) {
          for (j = 0; j < bl.sizeIn(); ++j)
            this.addRefRecurse(bl.getIn(j));
        }
      }
    }
  }

  /**
   * Add a variable read to this Cover.
   *
   * @param ref is the reading PcodeOp
   * @param vn is the Varnode being read
   */
  addRefPoint(ref: PcodeOp, vn: Varnode): void {
    let j: int4;
    const bl: FlowBlock = ref.getParent();

    const blIdx: int4 = bl.getIndex();
    const block = this._getOrCreate(blIdx);
    if (block.empty()) {
      block.setEnd(ref);
    } else {
      if (block.contain(ref)) {
        if (ref.code() !== OpCode.CPUI_MULTIEQUAL) return;
      } else {
        const op: CoverBoundary = block.getStop();
        const startop: CoverBoundary = block.getStart();
        block.setEnd(ref);
        const ustop: uintm = CoverBlock.getUIndex(block.getStop());
        if (ustop >= CoverBlock.getUIndex(startop)) {
          if ((op !== null) && (op !== START_INPUT) && (op !== STOP_END) &&
              (op as PcodeOp).code() === OpCode.CPUI_MULTIEQUAL &&
              (startop === null)) {
            for (j = 0; j < bl.sizeIn(); ++j)
              this.addRefRecurse(bl.getIn(j));
          }
          return;
        }
      }
    }
    if (ref.code() === OpCode.CPUI_MULTIEQUAL) {
      for (j = 0; j < ref.numInput(); ++j) {
        if (ref.getIn(j) === vn)
          this.addRefRecurse(bl.getIn(j));
      }
    } else {
      for (j = 0; j < bl.sizeIn(); ++j)
        this.addRefRecurse(bl.getIn(j));
    }
  }

  /**
   * Dump a description of this cover to a string.
   * @returns a human-readable description
   */
  dump(): string {
    let s = '';
    for (let i = 0; i < this.blockIndices.length; i++) {
      s += `${this.blockIndices[i]}: ${this.blocks[i].dump()}\n`;
    }
    return s;
  }

  /** Get beginning of CoverBlocks (as sorted entries) */
  [Symbol.iterator](): IterableIterator<[int4, CoverBlock]> {
    const indices = this.blockIndices;
    const blocks = this.blocks;
    let i = 0;
    const iter: IterableIterator<[int4, CoverBlock]> = {
      next(): IteratorResult<[int4, CoverBlock]> {
        if (i >= indices.length) return { done: true, value: undefined };
        const result: [int4, CoverBlock] = [indices[i], blocks[i]];
        i++;
        return { done: false, value: result };
      },
      [Symbol.iterator]() { return this; }
    };
    return iter;
  }

  /** Get the internal map entries for iteration */
  entries(): IterableIterator<[int4, CoverBlock]> {
    return this[Symbol.iterator]();
  }
}

