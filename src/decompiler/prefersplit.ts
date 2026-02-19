/**
 * @file prefersplit.ts
 * @description The PreferSplitRecord and PreferSplitManager classes, translated from
 * Ghidra's prefersplit.hh / prefersplit.cc
 *
 * Manages the splitting of varnodes that are preferred to be represented as
 * two smaller pieces. This includes splitting COPY, PIECE, SUBPIECE, LOAD,
 * STORE, and ZEXT operations into operations on the smaller pieces.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import type { int4, uintb } from '../core/types.js';
import { Address, calc_mask } from '../core/address.js';
import { AddrSpace, spacetype } from '../core/space.js';
import { OpCode } from '../core/opcodes.js';
import { ElementId } from '../core/marshal.js';
import { VarnodeData } from '../core/pcoderaw.js';
import { Varnode } from './varnode.js';
import { PcodeOp } from './op.js';

// ---------------------------------------------------------------------------
// Forward type declarations for types from not-yet-written modules
// ---------------------------------------------------------------------------

type Funcdata = any;
type VarnodeLocSetIterator = any;

// ---------------------------------------------------------------------------
// Marshaling element IDs
// ---------------------------------------------------------------------------

/** Marshaling element \<prefersplit> */
export const ELEM_PREFERSPLIT = new ElementId("prefersplit", 225);

// ---------------------------------------------------------------------------
// PreferSplitRecord
// ---------------------------------------------------------------------------

/**
 * A record describing a preferred split for a varnode storage location.
 * The storage field identifies the full varnode, and splitoffset indicates
 * the number of initial bytes (in address order) to split into the first piece.
 */
export class PreferSplitRecord {
  storage: VarnodeData;
  /** Number of initial bytes (in address order) to split into first piece */
  splitoffset: int4;

  constructor() {
    this.storage = new VarnodeData();
    this.splitoffset = 0;
  }

  /**
   * Comparison operator, sorting by space index, then size (bigger first),
   * then offset.
   */
  lessThan(op2: PreferSplitRecord): boolean {
    if (this.storage.space !== op2.storage.space)
      return (this.storage.space!.getIndex() < op2.storage.space!.getIndex());
    if (this.storage.size !== op2.storage.size)
      return (this.storage.size > op2.storage.size); // Bigger sizes come first
    return this.storage.offset < op2.storage.offset;
  }
}

// ---------------------------------------------------------------------------
// SplitInstance (internal helper)
// ---------------------------------------------------------------------------

/**
 * Tracks a varnode and its split pieces during the splitting process.
 */
class SplitInstance {
  splitoffset: int4;
  vn: Varnode | null;
  hi: Varnode | null; // Most significant piece
  lo: Varnode | null; // Least significant piece

  constructor(v: Varnode | null, off: int4) {
    this.vn = v;
    this.splitoffset = off;
    this.hi = null;
    this.lo = null;
  }
}

// ---------------------------------------------------------------------------
// PreferSplitManager
// ---------------------------------------------------------------------------

/**
 * Manages the process of splitting varnodes that match preferred split records.
 * The manager iterates through records, finds matching varnodes, tests whether
 * they can be split, and performs the split by creating new smaller operations.
 */
export class PreferSplitManager {
  private data: Funcdata | null = null;
  private records: PreferSplitRecord[] | null = null;
  /** Copies of temporaries that need additional splitting */
  private tempsplits: PcodeOp[] = [];

  /**
   * Define the varnode pieces of the given SplitInstance.
   * Creates lo and hi sub-varnodes based on endianness and the split offset.
   */
  private fillinInstance(inst: SplitInstance, bigendian: boolean, sethi: boolean, setlo: boolean): void {
    const vn = inst.vn!;
    let losize: int4;
    if (bigendian)
      losize = vn.getSize() - inst.splitoffset;
    else
      losize = inst.splitoffset;
    const hisize: int4 = vn.getSize() - losize;
    if (vn.isConstant()) {
      const origval: uintb = vn.getOffset();
      const loval: uintb = origval & calc_mask(losize); // Split the constant into two pieces
      const hival: uintb = (origval >> BigInt(8 * losize)) & calc_mask(hisize);
      if (setlo && (inst.lo === null))
        inst.lo = this.data!.newConstant(losize, loval);
      if (sethi && (inst.hi === null))
        inst.hi = this.data!.newConstant(hisize, hival);
    }
    else {
      if (bigendian) {
        if (setlo && (inst.lo === null))
          inst.lo = this.data!.newVarnode(losize, vn.getAddr().add(BigInt(inst.splitoffset)));
        if (sethi && (inst.hi === null))
          inst.hi = this.data!.newVarnode(hisize, vn.getAddr());
      }
      else {
        if (setlo && (inst.lo === null))
          inst.lo = this.data!.newVarnode(losize, vn.getAddr());
        if (sethi && (inst.hi === null))
          inst.hi = this.data!.newVarnode(hisize, vn.getAddr().add(BigInt(inst.splitoffset)));
      }
    }
  }

  /**
   * Create COPY ops based on input and output SplitInstances to replace the original op.
   */
  private createCopyOps(ininst: SplitInstance, outinst: SplitInstance, op: PcodeOp, istemp: boolean): void {
    const hiop: PcodeOp = this.data!.newOp(1, op.getAddr()); // Create two new COPYs
    const loop: PcodeOp = this.data!.newOp(1, op.getAddr());
    this.data!.opSetOpcode(hiop, OpCode.CPUI_COPY);
    this.data!.opSetOpcode(loop, OpCode.CPUI_COPY);

    this.data!.opInsertAfter(loop, op); // Insert new COPYs at same position as original operation
    this.data!.opInsertAfter(hiop, op);
    this.data!.opUnsetInput(op, 0); // Unset input so we can reassign free inputs to new ops

    this.data!.opSetOutput(hiop, outinst.hi); // Outputs
    this.data!.opSetOutput(loop, outinst.lo);
    this.data!.opSetInput(hiop, ininst.hi, 0);
    this.data!.opSetInput(loop, ininst.lo, 0);
    this.tempsplits.push(hiop);
    this.tempsplits.push(loop);
  }

  /**
   * Check that the SplitInstance defined by a COPY def is really splittable.
   * Returns [canSplit, istemp].
   */
  private testDefiningCopy(inst: SplitInstance, def: PcodeOp): [boolean, boolean] {
    const invn: Varnode = def.getIn(0)!;
    let istemp = false;
    if (!invn.isConstant()) {
      if (invn.getSpace()!.getType() !== spacetype.IPTR_INTERNAL) {
        const inrec = this.findRecord(invn);
        if (inrec === null) return [false, istemp];
        if (inrec.splitoffset !== inst.splitoffset) return [false, istemp];
        if (!invn.isFree()) return [false, istemp];
      }
      else {
        istemp = true;
      }
    }
    return [true, istemp];
  }

  /**
   * Do split of preferred split varnode that is defined by a COPY.
   */
  private splitDefiningCopy(inst: SplitInstance, def: PcodeOp, istemp: boolean): void {
    const invn: Varnode = def.getIn(0)!;
    const ininst = new SplitInstance(invn, inst.splitoffset);
    const bigendian: boolean = inst.vn!.getSpace()!.isBigEndian();
    this.fillinInstance(inst, bigendian, true, true);
    this.fillinInstance(ininst, bigendian, true, true);
    this.createCopyOps(ininst, inst, def, istemp);
  }

  /**
   * Check that the SplitInstance read by a COPY readop is really splittable.
   * Returns [canSplit, istemp].
   */
  private testReadingCopy(inst: SplitInstance, readop: PcodeOp): [boolean, boolean] {
    const outvn: Varnode = readop.getOut()!;
    let istemp = false;
    if (outvn.getSpace()!.getType() !== spacetype.IPTR_INTERNAL) {
      const outrec = this.findRecord(outvn);
      if (outrec === null) return [false, istemp];
      if (outrec.splitoffset !== inst.splitoffset) return [false, istemp];
    }
    else {
      istemp = true;
    }
    return [true, istemp];
  }

  /**
   * Do split of varnode that is read by a COPY.
   */
  private splitReadingCopy(inst: SplitInstance, readop: PcodeOp, istemp: boolean): void {
    const outvn: Varnode = readop.getOut()!;
    const outinst = new SplitInstance(outvn, inst.splitoffset);
    const bigendian: boolean = inst.vn!.getSpace()!.isBigEndian();
    this.fillinInstance(inst, bigendian, true, true);
    this.fillinInstance(outinst, bigendian, true, true);
    this.createCopyOps(inst, outinst, readop, istemp);
  }

  /**
   * Check that the SplitInstance defined by ZEXT is really splittable.
   */
  private testZext(inst: SplitInstance, op: PcodeOp): boolean {
    const invn: Varnode = op.getIn(0)!;
    if (invn.isConstant())
      return true;
    const bigendian: boolean = inst.vn!.getSpace()!.isBigEndian();
    let losize: int4;
    if (bigendian)
      losize = inst.vn!.getSize() - inst.splitoffset;
    else
      losize = inst.splitoffset;
    if (invn.getSize() !== losize) return false;
    return true;
  }

  /**
   * Split a ZEXT operation into two pieces.
   */
  private splitZext(inst: SplitInstance, op: PcodeOp): void {
    const ininst = new SplitInstance(op.getIn(0)!, inst.splitoffset);
    let losize: int4;
    let hisize: int4;
    const bigendian: boolean = inst.vn!.getSpace()!.isBigEndian();
    if (bigendian) {
      hisize = inst.splitoffset;
      losize = inst.vn!.getSize() - inst.splitoffset;
    }
    else {
      losize = inst.splitoffset;
      hisize = inst.vn!.getSize() - inst.splitoffset;
    }
    if (ininst.vn!.isConstant()) {
      const origval: uintb = ininst.vn!.getOffset();
      const loval: uintb = origval & calc_mask(losize); // Split the constant into two pieces
      const hival: uintb = (origval >> BigInt(8 * losize)) & calc_mask(hisize);
      ininst.lo = this.data!.newConstant(losize, loval);
      ininst.hi = this.data!.newConstant(hisize, hival);
    }
    else {
      ininst.lo = ininst.vn;
      ininst.hi = this.data!.newConstant(hisize, 0n);
    }

    this.fillinInstance(inst, bigendian, true, true);
    this.createCopyOps(ininst, inst, op, false);
  }

  /**
   * Check that the SplitInstance defined by PIECE is really splittable.
   */
  private testPiece(inst: SplitInstance, op: PcodeOp): boolean {
    if (inst.vn!.getSpace()!.isBigEndian()) {
      if (op.getIn(0)!.getSize() !== inst.splitoffset) return false;
    }
    else {
      if (op.getIn(1)!.getSize() !== inst.splitoffset) return false;
    }
    return true;
  }

  /**
   * Split a PIECE operation into two COPY operations.
   */
  private splitPiece(inst: SplitInstance, op: PcodeOp): void {
    let loin: Varnode = op.getIn(1)!;
    let hiin: Varnode = op.getIn(0)!;
    const bigendian: boolean = inst.vn!.getSpace()!.isBigEndian();
    this.fillinInstance(inst, bigendian, true, true);
    const hiop: PcodeOp = this.data!.newOp(1, op.getAddr());
    const loop: PcodeOp = this.data!.newOp(1, op.getAddr());
    this.data!.opSetOpcode(hiop, OpCode.CPUI_COPY);
    this.data!.opSetOpcode(loop, OpCode.CPUI_COPY);
    this.data!.opSetOutput(hiop, inst.hi); // Outputs are the pieces of the original
    this.data!.opSetOutput(loop, inst.lo);

    this.data!.opInsertAfter(loop, op);
    this.data!.opInsertAfter(hiop, op);
    this.data!.opUnsetInput(op, 0);
    this.data!.opUnsetInput(op, 1);

    if (hiin.isConstant())
      hiin = this.data!.newConstant(hiin.getSize(), hiin.getOffset());
    this.data!.opSetInput(hiop, hiin, 0); // Input for the COPY of the most significant part comes from high part of PIECE
    if (loin.isConstant())
      loin = this.data!.newConstant(loin.getSize(), loin.getOffset());
    this.data!.opSetInput(loop, loin, 0); // Input for the COPY of the least significant part comes from low part of PIECE
  }

  /**
   * Check that the SplitInstance read by SUBPIECE is really splittable.
   */
  private testSubpiece(inst: SplitInstance, op: PcodeOp): boolean {
    const vn: Varnode = inst.vn!;
    const outvn: Varnode = op.getOut()!;
    const suboff: int4 = Number(op.getIn(1)!.getOffset());
    if (suboff === 0) {
      if (vn.getSize() - inst.splitoffset !== outvn.getSize())
        return false;
    }
    else {
      if (vn.getSize() - suboff !== inst.splitoffset)
        return false;
      if (outvn.getSize() !== inst.splitoffset)
        return false;
    }
    return true;
  }

  /**
   * Knowing op is a CPUI_SUBPIECE that extracts a logical piece from inst,
   * rewrite it to a COPY.
   */
  private splitSubpiece(inst: SplitInstance, op: PcodeOp): void {
    const vn: Varnode = inst.vn!;
    const suboff: int4 = Number(op.getIn(1)!.getOffset());
    const grabbinglo: boolean = (suboff === 0);

    const bigendian: boolean = vn.getSpace()!.isBigEndian();
    this.fillinInstance(inst, bigendian, !grabbinglo, grabbinglo);
    this.data!.opSetOpcode(op, OpCode.CPUI_COPY); // Change SUBPIECE to a copy
    this.data!.opRemoveInput(op, 1);

    // Input is most/least significant piece, depending on which the SUBPIECE extracts
    const invn: Varnode = grabbinglo ? inst.lo! : inst.hi!;
    this.data!.opSetInput(op, invn, 0);
  }

  /**
   * Check that the SplitInstance defined by LOAD is really splittable.
   */
  private testLoad(_inst: SplitInstance, _op: PcodeOp): boolean {
    return true;
  }

  /**
   * Knowing op is a CPUI_LOAD that defines the inst varnode, split it into two pieces.
   */
  private splitLoad(inst: SplitInstance, op: PcodeOp): void {
    const bigendian: boolean = inst.vn!.getSpace()!.isBigEndian();
    this.fillinInstance(inst, bigendian, true, true);
    const hiop: PcodeOp = this.data!.newOp(2, op.getAddr()); // Create two new LOAD ops
    const loop: PcodeOp = this.data!.newOp(2, op.getAddr());
    const addop: PcodeOp = this.data!.newOp(2, op.getAddr());
    let ptrvn: Varnode = op.getIn(1)!;

    this.data!.opSetOpcode(hiop, OpCode.CPUI_LOAD);
    this.data!.opSetOpcode(loop, OpCode.CPUI_LOAD);

    this.data!.opSetOpcode(addop, OpCode.CPUI_INT_ADD); // Create a new ADD op to calculate and hold the second pointer

    this.data!.opInsertAfter(loop, op);
    this.data!.opInsertAfter(hiop, op);
    this.data!.opInsertAfter(addop, op);
    this.data!.opUnsetInput(op, 1); // Free up ptrvn

    const addvn: Varnode = this.data!.newUniqueOut(ptrvn.getSize(), addop);
    this.data!.opSetInput(addop, ptrvn, 0);
    this.data!.opSetInput(addop, this.data!.newConstant(ptrvn.getSize(), BigInt(inst.splitoffset)), 1);

    this.data!.opSetOutput(hiop, inst.hi); // Outputs are the pieces of the original
    this.data!.opSetOutput(loop, inst.lo);
    let spaceid: Varnode = op.getIn(0)!;
    const spc: any = spaceid.getSpaceFromConst();
    spaceid = this.data!.newConstant(spaceid.getSize(), spaceid.getOffset()); // Duplicate original spaceid into new LOADs
    this.data!.opSetInput(hiop, spaceid, 0);
    spaceid = this.data!.newConstant(spaceid.getSize(), spaceid.getOffset());
    this.data!.opSetInput(loop, spaceid, 0);
    if (ptrvn.isFree()) // Don't read a free varnode twice
      ptrvn = this.data!.newVarnode(ptrvn.getSize(), ptrvn.getSpace(), ptrvn.getOffset());

    if (spc.isBigEndian()) {
      this.data!.opSetInput(hiop, ptrvn, 1);
      this.data!.opSetInput(loop, addvn, 1);
    }
    else {
      this.data!.opSetInput(hiop, addvn, 1);
      this.data!.opSetInput(loop, ptrvn, 1);
    }
  }

  /**
   * Check that the SplitInstance stored by STORE is really splittable.
   */
  private testStore(_inst: SplitInstance, _op: PcodeOp): boolean {
    return true;
  }

  /**
   * Knowing op stores the value inst, split it into two STORE operations.
   */
  private splitStore(inst: SplitInstance, op: PcodeOp): void {
    this.fillinInstance(inst, inst.vn!.getSpace()!.isBigEndian(), true, true);
    const hiop: PcodeOp = this.data!.newOp(3, op.getAddr()); // Create 2 new STOREs
    const loop: PcodeOp = this.data!.newOp(3, op.getAddr());
    const addop: PcodeOp = this.data!.newOp(2, op.getAddr());
    let ptrvn: Varnode = op.getIn(1)!;

    this.data!.opSetOpcode(hiop, OpCode.CPUI_STORE);
    this.data!.opSetOpcode(loop, OpCode.CPUI_STORE);

    this.data!.opSetOpcode(addop, OpCode.CPUI_INT_ADD); // Create a new ADD op to calculate and hold the second pointer

    this.data!.opInsertAfter(loop, op);
    this.data!.opInsertAfter(hiop, op);
    this.data!.opInsertAfter(addop, op);
    this.data!.opUnsetInput(op, 1); // Free up ptrvn
    this.data!.opUnsetInput(op, 2); // Free up inst

    const addvn: Varnode = this.data!.newUniqueOut(ptrvn.getSize(), addop);
    this.data!.opSetInput(addop, ptrvn, 0);
    this.data!.opSetInput(addop, this.data!.newConstant(ptrvn.getSize(), BigInt(inst.splitoffset)), 1);

    this.data!.opSetInput(hiop, inst.hi, 2); // Varnodes "being stored" are the pieces of the original
    this.data!.opSetInput(loop, inst.lo, 2);
    let spaceid: Varnode = op.getIn(0)!;
    const spc: any = spaceid.getSpaceFromConst();
    spaceid = this.data!.newConstant(spaceid.getSize(), spaceid.getOffset()); // Duplicate original spaceid into new STOREs
    this.data!.opSetInput(hiop, spaceid, 0);
    spaceid = this.data!.newConstant(spaceid.getSize(), spaceid.getOffset());
    this.data!.opSetInput(loop, spaceid, 0);

    if (ptrvn.isFree()) // Don't read a free varnode twice
      ptrvn = this.data!.newVarnode(ptrvn.getSize(), ptrvn.getSpace(), ptrvn.getOffset());
    if (spc.isBigEndian()) {
      this.data!.opSetInput(hiop, ptrvn, 1);
      this.data!.opSetInput(loop, addvn, 1);
    }
    else {
      this.data!.opSetInput(hiop, addvn, 1);
      this.data!.opSetInput(loop, ptrvn, 1);
    }
  }

  /**
   * Test if the varnode in the SplitInstance can be readily split, and if so, do the split.
   * Returns true if the split was performed.
   */
  private splitVarnode(inst: SplitInstance): boolean {
    const vn: Varnode = inst.vn!;
    if (vn.isWritten()) {
      if (!vn.hasNoDescend()) return false; // Already linked in
      const op: PcodeOp = vn.getDef()!;
      switch (op.code()) {
        case OpCode.CPUI_COPY: {
          const [canSplit, istemp] = this.testDefiningCopy(inst, op);
          if (!canSplit) return false;
          this.splitDefiningCopy(inst, op, istemp);
          break;
        }
        case OpCode.CPUI_PIECE:
          if (!this.testPiece(inst, op))
            return false;
          this.splitPiece(inst, op);
          break;
        case OpCode.CPUI_LOAD:
          if (!this.testLoad(inst, op))
            return false;
          this.splitLoad(inst, op);
          break;
        case OpCode.CPUI_INT_ZEXT:
          if (!this.testZext(inst, op))
            return false;
          this.splitZext(inst, op);
          break;
        default:
          return false;
      }
      this.data!.opDestroy(op);
    }
    else {
      if (!vn.isFree()) return false; // Make sure vn is not already a marked input
      const op: PcodeOp | null = vn.loneDescend();
      if (op === null) // vn must be read exactly once
        return false;
      switch (op.code()) {
        case OpCode.CPUI_COPY: {
          const [canSplit, istemp] = this.testReadingCopy(inst, op);
          if (!canSplit) return false;
          this.splitReadingCopy(inst, op, istemp);
          break;
        }
        case OpCode.CPUI_SUBPIECE:
          if (!this.testSubpiece(inst, op))
            return false;
          this.splitSubpiece(inst, op);
          return true; // Do not destroy op, it has been transformed
        case OpCode.CPUI_STORE:
          if (!this.testStore(inst, op))
            return false;
          this.splitStore(inst, op);
          break;
        default:
          return false;
      }
      this.data!.opDestroy(op); // Original op is now dead
    }
    return true;
  }

  /**
   * Process a single PreferSplitRecord, finding and splitting all matching varnodes.
   */
  private splitRecord(rec: PreferSplitRecord): void {
    const addr: any = rec.storage.getAddr();

    const inst = new SplitInstance(null, rec.splitoffset);
    let iter: VarnodeLocSetIterator = this.data!.beginLoc(rec.storage.size, addr);
    let enditer: VarnodeLocSetIterator = this.data!.endLoc(rec.storage.size, addr);
    while (!iter.equals(enditer)) {
      inst.vn = iter.value;
      iter.next();
      inst.lo = null;
      inst.hi = null;
      if (this.splitVarnode(inst)) {
        // If we found something, regenerate iterators, as they may be stale
        iter = this.data!.beginLoc(rec.storage.size, addr);
        enditer = this.data!.endLoc(rec.storage.size, addr);
      }
    }
  }

  /**
   * Test whether a temporary SplitInstance can be further split.
   */
  private testTemporary(inst: SplitInstance): boolean {
    const op: PcodeOp = inst.vn!.getDef()!;
    switch (op.code()) {
      case OpCode.CPUI_PIECE:
        if (!this.testPiece(inst, op))
          return false;
        break;
      case OpCode.CPUI_LOAD:
        if (!this.testLoad(inst, op))
          return false;
        break;
      case OpCode.CPUI_INT_ZEXT:
        if (!this.testZext(inst, op))
          return false;
        break;
      default:
        return false;
    }
    const beginIdx: number = inst.vn!.beginDescend();
    const endIdx: number = inst.vn!.endDescend();
    for (let i = beginIdx; i < endIdx; i++) {
      const readop: PcodeOp = inst.vn!.getDescend(i);
      switch (readop.code()) {
        case OpCode.CPUI_SUBPIECE:
          if (!this.testSubpiece(inst, readop))
            return false;
          break;
        case OpCode.CPUI_STORE:
          if (!this.testStore(inst, readop))
            return false;
          break;
        default:
          return false;
      }
    }
    return true;
  }

  /**
   * Split a temporary varnode that was identified as needing additional splitting.
   */
  private splitTemporary(inst: SplitInstance): void {
    const vn: Varnode = inst.vn!;
    const op: PcodeOp = vn.getDef()!;
    switch (op.code()) {
      case OpCode.CPUI_PIECE:
        this.splitPiece(inst, op);
        break;
      case OpCode.CPUI_LOAD:
        this.splitLoad(inst, op);
        break;
      case OpCode.CPUI_INT_ZEXT:
        this.splitZext(inst, op);
        break;
      default:
        break;
    }

    while (vn.beginDescend() !== vn.endDescend()) {
      const readop: PcodeOp = vn.getDescend(vn.beginDescend());
      switch (readop.code()) {
        case OpCode.CPUI_SUBPIECE:
          this.splitSubpiece(inst, readop);
          break;
        case OpCode.CPUI_STORE:
          this.splitStore(inst, readop);
          this.data!.opDestroy(readop);
          break;
        default:
          break;
      }
    }
    this.data!.opDestroy(op);
  }

  /**
   * Initialize the manager with a Funcdata and the list of PreferSplitRecords.
   */
  init(fd: Funcdata, rec: PreferSplitRecord[]): void {
    this.data = fd;
    this.records = rec;
  }

  /**
   * Find the split record that applies to the given varnode, or return null.
   * Uses binary search on the sorted records array.
   */
  findRecord(vn: Varnode): PreferSplitRecord | null {
    const templ = new PreferSplitRecord();
    templ.storage.space = vn.getSpace();
    templ.storage.size = vn.getSize();
    templ.storage.offset = vn.getOffset();

    // Binary search (equivalent to C++ lower_bound)
    const records = this.records!;
    let lo = 0;
    let hi = records.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (records[mid].lessThan(templ)) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    if (lo === records.length)
      return null;
    if (templ.lessThan(records[lo]))
      return null;
    return records[lo];
  }

  /**
   * Sort the records array so that binary search works correctly.
   * This is a static initialization step.
   */
  static initialize(records: PreferSplitRecord[]): void {
    records.sort((a, b) => {
      if (a.lessThan(b)) return -1;
      if (b.lessThan(a)) return 1;
      return 0;
    });
  }

  /**
   * Perform the primary split pass over all records.
   */
  split(): void {
    for (let i = 0; i < this.records!.length; ++i)
      this.splitRecord(this.records![i]);
  }

  /**
   * Perform additional splitting on temporaries that were created during the
   * primary split pass. Looks at COPY ops in tempsplits and follows connections
   * to find SUBPIECE and PIECE operations on temporaries that need further splitting.
   */
  splitAdditional(): void {
    const defops: PcodeOp[] = [];
    for (let i = 0; i < this.tempsplits.length; ++i) {
      const op: PcodeOp = this.tempsplits[i]; // Look at everything connected to COPYs in tempsplits
      if (op.isDead()) continue;
      const vn: Varnode = op.getIn(0)!;
      if (vn.isWritten()) {
        const defop: PcodeOp = vn.getDef()!;
        if (defop.code() === OpCode.CPUI_SUBPIECE) { // SUBPIECEs flowing into the COPY
          const invn: Varnode = defop.getIn(0)!;
          if (invn.getSpace()!.getType() === spacetype.IPTR_INTERNAL) // Might be from a temporary that needs further splitting
            defops.push(defop);
        }
      }
      const outvn: Varnode = op.getOut()!;
      const beginIdx: number = outvn.beginDescend();
      const endIdx: number = outvn.endDescend();
      for (let j = beginIdx; j < endIdx; j++) {
        const defop: PcodeOp = outvn.getDescend(j);
        if (defop.code() === OpCode.CPUI_PIECE) { // COPY flowing into PIECEs
          const pieceOutvn: Varnode = defop.getOut()!;
          if (pieceOutvn.getSpace()!.getType() === spacetype.IPTR_INTERNAL) // Might be to a temporary that needs further splitting
            defops.push(defop);
        }
      }
    }
    for (let i = 0; i < defops.length; ++i) {
      const op: PcodeOp = defops[i];
      if (op.isDead()) continue;
      if (op.code() === OpCode.CPUI_PIECE) {
        let splitoff: int4;
        const vn: Varnode = op.getOut()!;
        if (vn.getSpace()!.isBigEndian())
          splitoff = op.getIn(0)!.getSize();
        else
          splitoff = op.getIn(1)!.getSize();
        const inst = new SplitInstance(vn, splitoff);
        if (this.testTemporary(inst))
          this.splitTemporary(inst);
      }
      else if (op.code() === OpCode.CPUI_SUBPIECE) {
        let splitoff: int4;
        const vn: Varnode = op.getIn(0)!;
        const suboff: uintb = op.getIn(1)!.getOffset();
        if (vn.getSpace()!.isBigEndian()) {
          if (suboff === 0n)
            splitoff = vn.getSize() - op.getOut()!.getSize();
          else
            splitoff = vn.getSize() - Number(suboff);
        }
        else {
          if (suboff === 0n)
            splitoff = op.getOut()!.getSize();
          else
            splitoff = Number(suboff);
        }
        const inst = new SplitInstance(vn, splitoff);
        if (this.testTemporary(inst))
          this.splitTemporary(inst);
      }
    }
  }
}
