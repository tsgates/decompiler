/**
 * @file variable.ts
 * @description Definitions for high-level variables.
 *
 * Faithfully translated from Ghidra's variable.hh / variable.cc.
 */

import type { int4, uint4 } from '../core/types.js';
import { LowlevelError } from '../core/error.js';
import {
  AttributeId,
  ElementId,
  Encoder,
  ATTRIB_OFFSET,
  ATTRIB_REF,
  ATTRIB_TYPELOCK,
} from '../core/marshal.js';
import type { Writer } from '../util/writer.js';
import { SortedSet } from '../util/sorted-set.js';
import { Cover, PcodeOpSet } from './cover.js';
import { type_metatype, Datatype } from './type.js';
import { spacetype } from '../core/space.js';
import { OpCode } from '../core/opcodes.js';

// ---------------------------------------------------------------------------
// Forward type declarations -- these will be replaced with real imports later
// ---------------------------------------------------------------------------

/** Forward declaration for PcodeOp */
type PcodeOp = any;
/** Forward declaration for Symbol */
type Symbol = any;
/** Forward declaration for SymbolEntry */
type SymbolEntry = any;
/** Forward declaration for Scope */
type Scope = any;
/** Forward declaration for PcodeOpNode */
type PcodeOpNode = any;
/** Forward declaration for EquateSymbol */
type EquateSymbol = any;
/** Forward declaration for Varnode */
type Varnode = any;
/** Forward declaration for TypeFactory */
type TypeFactory = any;

// ---------------------------------------------------------------------------
// Varnode flag constants needed by HighVariable
// (These match the constants defined in varnode.ts)
// ---------------------------------------------------------------------------

const VN_mark = 0x01;
const VN_constant = 0x02;
const VN_annotation = 0x04;
const VN_input = 0x08;
const VN_written = 0x10;
const VN_insert = 0x20;
const VN_implied = 0x40;
const VN_explict = 0x80;
const VN_typelock = 0x100;
const VN_namelock = 0x200;
const VN_persist = 0x4000;
const VN_addrtied = 0x8000;
const VN_unaffected = 0x10000;
const VN_spacebase = 0x20000;
const VN_indirectonly = 0x40000;
const VN_directwrite = 0x80000;
const VN_mapped = 0x200000;
const VN_indirect_creation = 0x400000;
const VN_coverdirty = 0x1000000;
const VN_proto_partial = 0x80000000;

// ---------------------------------------------------------------------------
// New AttributeId / ElementId constants defined in variable.cc
// ---------------------------------------------------------------------------

export const ATTRIB_CLASS = new AttributeId("class", 66);
export const ATTRIB_REPREF = new AttributeId("repref", 67);
export const ATTRIB_SYMREF = new AttributeId("symref", 68);

export const ELEM_HIGH = new ElementId("high", 82);

// We also need ELEM_ADDR for encoding. Forward declare since it may not be
// exported from marshal.ts yet.
let ELEM_ADDR: ElementId;
try {
  // Try to use the one from marshal if available
  ELEM_ADDR = new ElementId("addr", 83);
} catch {
  ELEM_ADDR = new ElementId("addr", 83);
}

// ---------------------------------------------------------------------------
// PieceCompareByOffset comparator
// ---------------------------------------------------------------------------

/**
 * Compare two VariablePiece objects by offset then by size.
 */
function pieceCompareByOffset(a: VariablePiece, b: VariablePiece): number {
  if (a.getOffset() !== b.getOffset())
    return a.getOffset() - b.getOffset();
  return a.getSize() - b.getSize();
}

// ---------------------------------------------------------------------------
// VariableGroup
// ---------------------------------------------------------------------------

/**
 * A collection of HighVariable objects that overlap.
 *
 * A HighVariable represents a variable or partial variable that is manipulated as a unit by the
 * (de)compiler. A formal Symbol may be manipulated using multiple HighVariables that in principle
 * can overlap. For a set of HighVariable objects that mutually overlap, a VariableGroup is a
 * central access point for information about the intersections.
 */
export class VariableGroup {
  /** @internal The set of VariablePieces making up this group */
  public pieceSet: SortedSet<VariablePiece> = new SortedSet<VariablePiece>(pieceCompareByOffset);

  /** @internal Number of contiguous bytes covered by the whole group */
  private size: number = 0;

  /** @internal Byte offset of this group within its containing Symbol */
  private symbolOffset: number = 0;

  constructor() {
    this.size = 0;
    this.symbolOffset = 0;
  }

  /** Return true if this group has no pieces */
  empty(): boolean {
    return this.pieceSet.empty;
  }

  /**
   * Add a new piece to this group.
   * The VariablePiece takes partial ownership of this, via refCount.
   * @param piece is the new piece to add
   */
  addPiece(piece: VariablePiece): void {
    piece._group = this;
    const [, inserted] = this.pieceSet.insert(piece);
    if (!inserted)
      throw new LowlevelError("Duplicate VariablePiece");
    const pieceMax = piece.getOffset() + piece.getSize();
    if (pieceMax > this.size)
      this.size = pieceMax;
  }

  /**
   * Adjust offset for every piece by the given amount.
   * The adjustment amount must be positive, and this effectively increases the size of the group.
   * @param amt is the given amount to add to offsets
   */
  adjustOffsets(amt: number): void {
    for (const piece of this.pieceSet) {
      piece._groupOffset += amt;
    }
    this.size += amt;
  }

  /**
   * Remove a piece from this group.
   * @param piece is the piece to remove
   */
  removePiece(piece: VariablePiece): void {
    this.pieceSet.eraseValue(piece);
    // We currently don't adjust size here as removePiece is currently only called during clean up
  }

  /** Get the number of bytes this group covers */
  getSize(): number {
    return this.size;
  }

  /** Cache the symbol offset for the group */
  setSymbolOffset(val: number): void {
    this.symbolOffset = val;
  }

  /** Get offset of this group within its Symbol */
  getSymbolOffset(): number {
    return this.symbolOffset;
  }

  /**
   * Combine given VariableGroup into this.
   * Every VariablePiece in the given group is moved into this and the VariableGroup object is
   * freed. There must be no matching VariablePieces with the same size and offset between the
   * two groups or a LowlevelError exception is thrown.
   * @param op2 is the given VariableGroup to merge into this
   */
  combineGroups(op2: VariableGroup): void {
    // Collect all pieces first to avoid mutating the set while iterating
    const pieces: VariablePiece[] = [];
    for (const piece of op2.pieceSet) {
      pieces.push(piece);
    }
    for (const piece of pieces) {
      piece.transferGroup(this);
    }
  }
}

// ---------------------------------------------------------------------------
// VariablePiece
// ---------------------------------------------------------------------------

/**
 * Information about how a HighVariable fits into a larger group or Symbol.
 *
 * This is an extension to a HighVariable object that is assigned if the HighVariable is part of
 * a group of mutually overlapping HighVariables. It describes the overlaps and how they affect
 * the HighVariable Cover.
 */
export class VariablePiece {
  /** @internal Group to which this piece belongs */
  public _group: VariableGroup;

  /** @internal HighVariable owning this piece */
  private high: HighVariable;

  /** @internal Byte offset of this piece within the group */
  public _groupOffset: number;

  /** @internal Number of bytes in this piece */
  private size: number;

  /** @internal List of VariablePieces this piece intersects with */
  public intersection: VariablePiece[] = [];

  /** @internal Extended cover for the piece, taking into account intersections */
  private cover: Cover = new Cover();

  /**
   * Construct piece given a HighVariable and its position within the whole.
   * If this is the first piece in the group, allocate a new VariableGroup object.
   * @param h is the given HighVariable to treat as a piece
   * @param offset is the byte offset of the piece within the whole
   * @param grp is another HighVariable in the whole, or null if this is the first piece
   */
  constructor(h: HighVariable, offset: number, grp: HighVariable | null = null) {
    this.high = h;
    this._groupOffset = offset;
    this.size = h.getInstance(0).getSize();
    if (grp !== null)
      this._group = grp._piece!.getGroup();
    else
      this._group = new VariableGroup();
    this._group.addPiece(this);
  }

  /** Destructor equivalent -- removes from group, deletes group if empty */
  destroy(): void {
    this._group.removePiece(this);
    if (this._group.empty()) {
      // group is garbage collected
    } else {
      this.markIntersectionDirty();
    }
  }

  /** Get the HighVariable associated with this piece */
  getHigh(): HighVariable {
    return this.high;
  }

  /** Get the central group */
  getGroup(): VariableGroup {
    return this._group;
  }

  /** Get the offset of this within its group */
  getOffset(): number {
    return this._groupOffset;
  }

  /** Return the number of bytes in this piece */
  getSize(): number {
    return this.size;
  }

  /** Get the cover associated with this piece */
  getCover(): Cover {
    return this.cover;
  }

  /** Get number of pieces this intersects with */
  numIntersection(): number {
    return this.intersection.length;
  }

  /** Get i-th piece this intersects with */
  getIntersection(i: number): VariablePiece {
    return this.intersection[i];
  }

  /** Mark all pieces as needing intersection recalculation */
  markIntersectionDirty(): void {
    for (const piece of this._group.pieceSet) {
      piece.high._highflags |= (HighVariable.intersectdirty | HighVariable.extendcoverdirty);
    }
  }

  /** Mark all intersecting pieces as having a dirty extended cover */
  markExtendCoverDirty(): void {
    if ((this.high._highflags & HighVariable.intersectdirty) !== 0)
      return; // intersection list itself is dirty, extended covers will be recomputed anyway
    for (let i = 0; i < this.intersection.length; ++i) {
      this.intersection[i].high._highflags |= HighVariable.extendcoverdirty;
    }
    this.high._highflags |= HighVariable.extendcoverdirty;
  }

  /** Calculate intersections with other pieces in the group */
  updateIntersections(): void {
    if ((this.high._highflags & HighVariable.intersectdirty) === 0) return;

    const endOffset = this._groupOffset + this.size;
    this.intersection.length = 0;
    for (const otherPiece of this._group.pieceSet) {
      if (otherPiece === this) continue;
      if (endOffset <= otherPiece._groupOffset) continue;
      const otherEndOffset = otherPiece._groupOffset + otherPiece.size;
      if (this._groupOffset >= otherEndOffset) continue;
      this.intersection.push(otherPiece);
    }
    this.high._highflags &= ~HighVariable.intersectdirty;
  }

  /** Union internal covers of all pieces intersecting with this */
  updateCover(): void {
    if ((this.high._highflags & (HighVariable.coverdirty | HighVariable.extendcoverdirty)) === 0) return;
    this.high.updateInternalCover();
    this.cover = new Cover();
    this.cover.merge(this.high._internalCover);
    for (let i = 0; i < this.intersection.length; ++i) {
      const intersectHigh = this.intersection[i].high;
      intersectHigh.updateInternalCover();
      this.cover.merge(intersectHigh._internalCover);
    }
    this.high._highflags &= ~HighVariable.extendcoverdirty;
  }

  /** Move ownership of this to another HighVariable */
  setHigh(newHigh: HighVariable): void {
    this.high = newHigh;
  }

  /**
   * Transfer this piece to another VariableGroup.
   * If there are no remaining references to the old VariableGroup it is deleted.
   * @param newGroup is the new VariableGroup to transfer this to
   */
  transferGroup(newGroup: VariableGroup): void {
    this._group.removePiece(this);
    if (this._group.empty()) {
      // old group is garbage collected
    }
    newGroup.addPiece(this);
  }

  /**
   * Combine two VariableGroups.
   * Combine the VariableGroup associated this and the given other VariablePiece into one group.
   * Offsets are adjusted so that this and the other VariablePiece have the same offset.
   * Combining in this way requires pieces of the same size and offset to be merged. This
   * method does not do the merging but passes back a list of HighVariable pairs that need to be merged.
   * @param op2 is the given other VariablePiece
   * @param mergePairs passes back the collection of HighVariable pairs that must be merged
   */
  mergeGroups(op2: VariablePiece, mergePairs: HighVariable[]): void {
    const diff = this._groupOffset - op2._groupOffset; // Add to op2, or subtract from this
    if (diff > 0)
      op2._group.adjustOffsets(diff);
    else if (diff < 0)
      this._group.adjustOffsets(-diff);

    // Collect pieces from op2's group first, since iteration + mutation is tricky
    const piecesToProcess: VariablePiece[] = [];
    for (const piece of op2._group.pieceSet) {
      piecesToProcess.push(piece);
    }

    for (const piece of piecesToProcess) {
      // Check if a matching piece already exists in this group
      const matchIter = this._group.pieceSet.find(piece);
      if (!matchIter.isEnd) {
        mergePairs.push(matchIter.value.high);
        mergePairs.push(piece.high);
        piece.high._piece = null; // Detach HighVariable from its original VariablePiece
        piece.destroy();
      } else {
        piece.transferGroup(this._group);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// HighVariable
// ---------------------------------------------------------------------------

/**
 * A high-level variable modeled as a list of low-level variables, each written once.
 *
 * In the Static Single Assignment (SSA) representation of a function's data-flow, the Varnode
 * object represents a variable node. This is a low-level variable: it is written to
 * at most once, and there is 1 or more reads. A high-level variable, in the source
 * language may be written to multiple times. We model this idea as a list of Varnode objects,
 * where a different Varnode holds the value of the variable for different parts of the code.
 */
export class HighVariable {
  // --- Dirtiness flags ---
  static readonly flagsdirty = 1;
  static readonly namerepdirty = 2;
  static readonly typedirty = 4;
  static readonly coverdirty = 8;
  static readonly symboldirty = 0x10;
  static readonly copy_in1 = 0x20;
  static readonly copy_in2 = 0x40;
  static readonly type_finalized = 0x80;
  static readonly unmerged = 0x100;
  static readonly intersectdirty = 0x200;
  static readonly extendcoverdirty = 0x400;

  // --- Private/Internal fields ---

  /** @internal The member Varnode objects making up this HighVariable */
  public _inst: Varnode[] = [];

  /** @internal Number of different speculative merge classes in this */
  public _numMergeClasses: number = 1;

  /** @internal Dirtiness flags */
  public _highflags: number = 0;

  /** @internal Boolean properties inherited from Varnode members */
  public _flags: number = 0;

  /** @internal The data-type for this */
  public _type: Datatype | null = null;

  /** @internal The storage location used to generate a Symbol name */
  public _nameRepresentative: Varnode | null = null;

  /** @internal The ranges of code addresses covered by this HighVariable */
  public _internalCover: Cover = new Cover();

  /** @internal Additional info about intersections with other pieces (if non-null) */
  public _piece: VariablePiece | null = null;

  /** @internal The Symbol this HighVariable is tied to */
  public _symbol: Symbol | null = null;

  /** @internal -1=perfect symbol match >=0, offset */
  public _symboloffset: number = -1;

  /**
   * Construct a HighVariable with a single member Varnode.
   * The new instance starts off with no associate Symbol and all properties marked as dirty.
   * @param vn is the single Varnode member
   */
  constructor(vn: Varnode) {
    this._numMergeClasses = 1;
    this._highflags = HighVariable.flagsdirty | HighVariable.namerepdirty |
                      HighVariable.typedirty | HighVariable.coverdirty;
    this._flags = 0;
    this._type = null;
    this._piece = null;
    this._symbol = null;
    this._nameRepresentative = null;
    this._symboloffset = -1;
    this._inst.push(vn);
    vn.setHigh(this, this._numMergeClasses - 1);
    if (vn.getSymbolEntry() !== null)
      this.setSymbol(vn);
  }

  /** Destructor */
  destroy(): void {
    if (this._piece !== null)
      this._piece.destroy();
  }

  // --- Public API ---

  /** Get the data-type */
  getType(): Datatype {
    this.updateType();
    return this._type!;
  }

  /** Get cover data for this variable */
  getCover(): Cover {
    if (this._piece === null)
      return this._internalCover;
    return this._piece.getCover();
  }

  /** Get the Symbol associated with this or null */
  getSymbol(): Symbol | null {
    this.updateSymbol();
    return this._symbol;
  }

  /** Get the SymbolEntry mapping to this or null */
  getSymbolEntry(): SymbolEntry | null {
    for (let i = 0; i < this._inst.length; ++i) {
      const entry = this._inst[i].getSymbolEntry();
      if (entry !== null && entry.getSymbol() === this._symbol)
        return entry;
    }
    return null;
  }

  /** Get the Symbol offset associated with this */
  getSymbolOffset(): number {
    return this._symboloffset;
  }

  /** Get the number of member Varnodes this has */
  numInstances(): number {
    return this._inst.length;
  }

  /** Get the i-th member Varnode */
  getInstance(i: number): Varnode {
    return this._inst[i];
  }

  /**
   * Set a final data-type matching the associated Symbol.
   * If there is an associated Symbol, its data-type (or the appropriate piece) is assigned
   * to this. The dirtying mechanism is disabled so that data-type cannot change.
   * @param typeFactory is the factory used to construct any required piece
   */
  finalizeDatatype(typeFactory: TypeFactory): void {
    if (this._symbol === null) return;
    const cur: Datatype = this._symbol.getType();
    let off = this._symboloffset;
    if (off < 0)
      off = 0;
    const sz: number = this._inst[0].getSize();
    const tp: Datatype | null = typeFactory.getExactPiece(cur, off, sz);
    if (tp === null || tp.getMetatype() === type_metatype.TYPE_UNKNOWN)
      return;
    this._type = tp;
    this.stripType();
    this._highflags |= HighVariable.type_finalized;
  }

  /**
   * Put this and another HighVariable in the same intersection group.
   * If one of the HighVariables is already in a group, the other HighVariable is added to this group.
   * @param off is the relative byte offset of this with the other HighVariable
   * @param hi2 is the other HighVariable
   */
  groupWith(off: number, hi2: HighVariable): void {
    if (this._piece === null && hi2._piece === null) {
      hi2._piece = new VariablePiece(hi2, 0);
      this._piece = new VariablePiece(this, off, hi2);
      hi2._piece.markIntersectionDirty();
      return;
    }
    if (this._piece === null) {
      if ((hi2._highflags & HighVariable.intersectdirty) === 0)
        hi2._piece!.markIntersectionDirty();
      this._highflags |= HighVariable.intersectdirty | HighVariable.extendcoverdirty;
      off += hi2._piece!.getOffset();
      this._piece = new VariablePiece(this, off, hi2);
    } else if (hi2._piece === null) {
      let hi2Off = this._piece.getOffset() - off;
      if (hi2Off < 0) {
        this._piece.getGroup().adjustOffsets(-hi2Off);
        hi2Off = 0;
      }
      if ((this._highflags & HighVariable.intersectdirty) === 0)
        this._piece.markIntersectionDirty();
      hi2._highflags |= HighVariable.intersectdirty | HighVariable.extendcoverdirty;
      hi2._piece = new VariablePiece(hi2, hi2Off, this);
    } else {
      const offDiff = hi2._piece.getOffset() + off - this._piece.getOffset();
      if (offDiff !== 0)
        this._piece.getGroup().adjustOffsets(offDiff);
      hi2._piece.getGroup().combineGroups(this._piece.getGroup());
      hi2._piece.markIntersectionDirty();
    }
  }

  /**
   * Transfer symbol offset of this to the VariableGroup.
   * If this is part of a larger group and has had its symboloffset set, it can be used
   * to calculate the symboloffset of other HighVariables in the same group.
   */
  establishGroupSymbolOffset(): void {
    const group = this._piece!.getGroup();
    let off = this._symboloffset;
    if (off < 0)
      off = 0;
    off -= this._piece!.getOffset();
    if (off < 0)
      throw new LowlevelError("Symbol offset is incompatible with VariableGroup");
    group.setSymbolOffset(off);
  }

  /**
   * Print details of the cover for this (for debug purposes).
   * @param writer is the output writer
   */
  printCover(writer: Writer): void {
    if ((this._highflags & HighVariable.coverdirty) === 0) {
      writer.write(this._internalCover.dump());
    } else {
      writer.write("Cover dirty");
    }
  }

  /**
   * Print information about this HighVariable to stream.
   * @param writer is the output writer
   */
  printInfo(writer: Writer): void {
    this.updateType();
    if (this._symbol === null) {
      writer.write("Variable: UNNAMED\n");
    } else {
      writer.write("Variable: " + this._symbol.getName());
      if (this._symboloffset !== -1)
        writer.write("(partial)");
      writer.write("\n");
    }
    writer.write("Type: ");
    this._type!.printRaw(writer);
    writer.write("\n\n");

    for (let i = 0; i < this._inst.length; ++i) {
      const vn = this._inst[i];
      writer.write(vn.getMergeGroup().toString(10) + ": ");
      vn.printInfo(writer);
    }
  }

  /**
   * Check if this HighVariable can be named.
   * All Varnode objects are assigned a HighVariable, including those that don't get names like
   * indirect variables, constants, and annotations.
   * @return true if this can have a name
   */
  hasName(): boolean {
    let indirectonly = true;
    for (let i = 0; i < this._inst.length; ++i) {
      const vn = this._inst[i];
      if (!vn.hasCover()) {
        if (this._inst.length > 1)
          throw new LowlevelError("Non-coverable varnode has been merged");
        return false;
      }
      if (vn.isImplied()) {
        if (this._inst.length > 1)
          throw new LowlevelError("Implied varnode has been merged");
        return false;
      }
      if (!vn.isIndirectOnly())
        indirectonly = false;
    }
    if (this.isUnaffected()) {
      if (!this.isInput()) return false;
      if (indirectonly) return false;
      const vn = this.getInputVarnode();
      if (!vn.isIllegalInput()) { // A leftover unaff illegal input gets named
        if (vn.isSpacebase())     // A legal input, unaff, gets named
          return false;           // Unless it is the stackpointer
      }
    }
    return true;
  }

  /**
   * Find the first address tied member Varnode.
   * This should only be called if isAddrTied() returns true.
   * @return the first address tied member
   */
  getTiedVarnode(): Varnode {
    for (let i = 0; i < this._inst.length; ++i)
      if (this._inst[i].isAddrTied())
        return this._inst[i];
    throw new LowlevelError("Could not find address-tied varnode");
  }

  /**
   * Find (the) input member Varnode.
   * This should only be called if isInput() returns true.
   * @return the input Varnode member
   */
  getInputVarnode(): Varnode {
    for (let i = 0; i < this._inst.length; ++i)
      if (this._inst[i].isInput())
        return this._inst[i];
    throw new LowlevelError("Could not find input varnode");
  }

  /**
   * Get a member Varnode with the strongest data-type.
   * Find the member Varnode with the most specialized data-type, handling bool specially.
   * @return the representative member
   */
  getTypeRepresentative(): Varnode {
    let rep = this._inst[0];
    for (let i = 1; i < this._inst.length; ++i) {
      const vn = this._inst[i];
      if (rep.isTypeLock() !== vn.isTypeLock()) {
        if (vn.isTypeLock())
          rep = vn;
      } else if (0 > vn.getType().typeOrderBool(rep.getType())) {
        rep = vn;
      }
    }
    return rep;
  }

  /**
   * Get a member Varnode that dictates the naming of this HighVariable.
   * Members are scored based the properties that are most dominating in choosing a name.
   * @return the highest scoring Varnode member
   */
  getNameRepresentative(): Varnode {
    if ((this._highflags & HighVariable.namerepdirty) === 0)
      return this._nameRepresentative!; // Name representative is up to date
    this._highflags &= ~HighVariable.namerepdirty;

    this._nameRepresentative = this._inst[0];
    for (let i = 1; i < this._inst.length; ++i) {
      const vn = this._inst[i];
      if (HighVariable.compareName(this._nameRepresentative, vn))
        this._nameRepresentative = vn;
    }
    return this._nameRepresentative;
  }

  /** Get the number of speculative merges for this */
  getNumMergeClasses(): number {
    return this._numMergeClasses;
  }

  /** Return true if this is mapped */
  isMapped(): boolean {
    this.updateFlags();
    return (this._flags & VN_mapped) !== 0;
  }

  /** Return true if this is a global variable */
  isPersist(): boolean {
    this.updateFlags();
    return (this._flags & VN_persist) !== 0;
  }

  /** Return true if this is address tied */
  isAddrTied(): boolean {
    this.updateFlags();
    return (this._flags & VN_addrtied) !== 0;
  }

  /** Return true if this is an input variable */
  isInput(): boolean {
    this.updateFlags();
    return (this._flags & VN_input) !== 0;
  }

  /** Return true if this is an implied variable */
  isImplied(): boolean {
    this.updateFlags();
    return (this._flags & VN_implied) !== 0;
  }

  /** Return true if this is a spacebase */
  isSpacebase(): boolean {
    this.updateFlags();
    return (this._flags & VN_spacebase) !== 0;
  }

  /** Return true if this is a constant */
  isConstant(): boolean {
    this.updateFlags();
    return (this._flags & VN_constant) !== 0;
  }

  /** Return true if this is an unaffected register */
  isUnaffected(): boolean {
    this.updateFlags();
    return (this._flags & VN_unaffected) !== 0;
  }

  /** Return true if this is an extra output */
  isExtraOut(): boolean {
    this.updateFlags();
    return (this._flags & (VN_indirect_creation | VN_addrtied)) === VN_indirect_creation;
  }

  /** Return true if this is a piece concatenated into a larger whole */
  isProtoPartial(): boolean {
    this.updateFlags();
    return (this._flags & VN_proto_partial) !== 0;
  }

  /** Set the mark on this variable */
  setMark(): void {
    this._flags |= VN_mark;
  }

  /** Clear the mark on this variable */
  clearMark(): void {
    this._flags &= ~VN_mark;
  }

  /** Return true if this is marked */
  isMark(): boolean {
    return (this._flags & VN_mark) !== 0;
  }

  /** Return true if this has merge problems */
  isUnmerged(): boolean {
    return (this._highflags & HighVariable.unmerged) !== 0;
  }

  /**
   * Is this part of the same VariableGroup as op2.
   * Test if the two HighVariables should be pieces of the same symbol.
   * @param op2 is the other HighVariable to compare with this
   * @return true if they share the same underlying VariableGroup
   */
  isSameGroup(op2: HighVariable): boolean {
    if (this._piece === null || op2._piece === null)
      return false;
    return this._piece.getGroup() === op2._piece.getGroup();
  }

  /**
   * Determine if this HighVariable has an associated cover.
   * Constant and annotation variables do not have a cover.
   * @return true if this has a cover
   */
  hasCover(): boolean {
    this.updateFlags();
    return (this._flags & (VN_constant | VN_annotation | VN_insert)) === VN_insert;
  }

  /** Return true if this has no member Varnode */
  isUnattached(): boolean {
    return this._inst.length === 0;
  }

  /** Return true if this is typelocked */
  isTypeLock(): boolean {
    this.updateType();
    return (this._flags & VN_typelock) !== 0;
  }

  /** Return true if this is namelocked */
  isNameLock(): boolean {
    this.updateFlags();
    return (this._flags & VN_namelock) !== 0;
  }

  /**
   * Encode this variable to stream as a <high> element.
   * @param encoder is the stream encoder
   */
  encode(encoder: Encoder): void {
    const vn = this.getNameRepresentative(); // Get representative varnode
    encoder.openElement(ELEM_HIGH);
    encoder.writeUnsignedInteger(ATTRIB_REPREF, BigInt(vn.getCreateIndex()));
    if (this.isSpacebase() || this.isImplied()) // This is a special variable
      encoder.writeString(ATTRIB_CLASS, "other");
    else if (this.isPersist() && this.isAddrTied()) // Global variable
      encoder.writeString(ATTRIB_CLASS, "global");
    else if (this.isConstant())
      encoder.writeString(ATTRIB_CLASS, "constant");
    else if (!this.isPersist() && (this._symbol !== null)) {
      if (this._symbol.getCategory() === 0) // Symbol::function_parameter
        encoder.writeString(ATTRIB_CLASS, "param");
      else if (this._symbol.getScope().isGlobal())
        encoder.writeString(ATTRIB_CLASS, "global");
      else
        encoder.writeString(ATTRIB_CLASS, "local");
    } else {
      encoder.writeString(ATTRIB_CLASS, "other");
    }
    if (this.isTypeLock())
      encoder.writeBool(ATTRIB_TYPELOCK, true);
    if (this._symbol !== null) {
      encoder.writeUnsignedInteger(ATTRIB_SYMREF, BigInt(this._symbol.getId()));
      if (this._symboloffset >= 0)
        encoder.writeSignedInteger(ATTRIB_OFFSET, this._symboloffset);
    }
    this.getType().encodeRef(encoder);
    for (let j = 0; j < this._inst.length; ++j) {
      encoder.openElement(ELEM_ADDR);
      encoder.writeUnsignedInteger(ATTRIB_REF, BigInt(this._inst[j].getCreateIndex()));
      encoder.closeElement(ELEM_ADDR);
    }
    encoder.closeElement(ELEM_HIGH);
  }

  // --- Internal / friend methods ---

  /** @internal Mark the boolean properties as dirty */
  flagsDirty(): void {
    this._highflags |= HighVariable.flagsdirty | HighVariable.namerepdirty;
  }

  /**
   * @internal Mark the cover as dirty.
   * The internal cover is marked as dirty. If this is a piece of a VariableGroup, it and all
   * the other HighVariables it intersects with are marked as having a dirty extended cover.
   */
  coverDirty(): void {
    this._highflags |= HighVariable.coverdirty;
    if (this._piece !== null)
      this._piece.markExtendCoverDirty();
  }

  /** @internal Mark the data-type as dirty */
  typeDirty(): void {
    this._highflags |= HighVariable.typedirty;
  }

  /** @internal Mark the symbol as dirty */
  symbolDirty(): void {
    this._highflags |= HighVariable.symboldirty;
  }

  /** @internal Mark this as having merge problems */
  setUnmerged(): void {
    this._highflags |= HighVariable.unmerged;
  }

  /** @internal Is the cover returned by getCover() up-to-date */
  isCoverDirty(): boolean {
    return (this._highflags & (HighVariable.coverdirty | HighVariable.extendcoverdirty)) !== 0;
  }

  /** @internal Mark the existence of one COPY into this */
  setCopyIn1(): void {
    this._highflags |= HighVariable.copy_in1;
  }

  /** @internal Mark the existence of two COPYs into this */
  setCopyIn2(): void {
    this._highflags |= HighVariable.copy_in2;
  }

  /** @internal Clear marks indicating COPYs into this */
  clearCopyIns(): void {
    this._highflags &= ~(HighVariable.copy_in1 | HighVariable.copy_in2);
  }

  /** @internal Is there at least one COPY into this */
  hasCopyIn1(): boolean {
    return (this._highflags & HighVariable.copy_in1) !== 0;
  }

  /** @internal Is there at least two COPYs into this */
  hasCopyIn2(): boolean {
    return (this._highflags & HighVariable.copy_in2) !== 0;
  }

  /**
   * @internal Update Symbol information for this from the given member Varnode.
   * The given Varnode must be a member and must have a non-null SymbolEntry.
   */
  setSymbol(vn: Varnode): void {
    const entry: SymbolEntry = vn.getSymbolEntry();
    if (this._symbol !== null && this._symbol !== entry.getSymbol()) {
      if ((this._highflags & HighVariable.symboldirty) === 0) {
        throw new LowlevelError(
          'Symbols "' + this._symbol.getName() + '" and "' + entry.getSymbol().getName() +
          '" assigned to the same variable'
        );
      }
    }
    this._symbol = entry.getSymbol();
    if (vn.isProtoPartial() && this._piece !== null) {
      this._symboloffset = this._piece.getOffset() + this._piece.getGroup().getSymbolOffset();
    } else if (entry.isDynamic()) // Dynamic symbols (that aren't partials) match whole variable
      this._symboloffset = -1;
    else if (this._symbol.getCategory() === 1) // Symbol::equate
      this._symboloffset = -1; // For equates, we don't care about size
    else if (this._symbol.getType().getSize() === vn.getSize() &&
             entry.getAddr().equals(vn.getAddr()) && !entry.isPiece())
      this._symboloffset = -1; // A matching entry
    else {
      this._symboloffset = vn.getAddr().overlapJoin(0, entry.getAddr(), this._symbol.getType().getSize()) + entry.getOffset();
    }

    if (this._type !== null && this._type.getMetatype() === type_metatype.TYPE_PARTIALUNION)
      this._highflags |= HighVariable.typedirty;
    this._highflags &= ~HighVariable.symboldirty; // We are no longer dirty
  }

  /**
   * @internal Attach a reference to a Symbol to this.
   * Link information to this from a Symbol that is not attached to a member Varnode.
   * This only works for a HighVariable with a constant member Varnode.
   * @param sym is the given Symbol to attach
   * @param off is the byte offset into the Symbol of the reference
   */
  setSymbolReference(sym: Symbol, off: number): void {
    this._symbol = sym;
    this._symboloffset = off;
    this._highflags &= ~HighVariable.symboldirty;
  }

  /**
   * @internal Transfer ownership of another's VariablePiece to this.
   */
  transferPiece(tv2: HighVariable): void {
    this._piece = tv2._piece;
    tv2._piece = null;
    this._piece!.setHigh(this);
    this._highflags |= (tv2._highflags & (HighVariable.intersectdirty | HighVariable.extendcoverdirty));
    tv2._highflags &= ~(HighVariable.intersectdirty | HighVariable.extendcoverdirty);
  }

  /**
   * @internal Take the stripped form of the current data-type.
   * Except in specific circumstances, convert type into its stripped form.
   */
  stripType(): void {
    if (!this._type!.hasStripped())
      return;
    const meta = this._type!.getMetatype();
    if (meta === type_metatype.TYPE_PARTIALUNION || meta === type_metatype.TYPE_PARTIALSTRUCT) {
      if (this._symbol !== null && this._symboloffset !== -1) { // If there is a bigger backing symbol
        const submeta = this._symbol.getType().getMetatype();
        if (submeta === type_metatype.TYPE_STRUCT || submeta === type_metatype.TYPE_UNION)
          return; // Don't strip the partial union
      }
    } else if (this._type!.isEnumType()) {
      if (this._inst.length === 1 && this._inst[0].isConstant()) // Only preserve partial enum on a constant
        return;
    }
    this._type = this._type!.getStripped();
  }

  /**
   * @internal (Re)derive the internal cover of this from the member Varnodes.
   * Only update if the cover is marked as dirty.
   */
  updateInternalCover(): void {
    if ((this._highflags & HighVariable.coverdirty) !== 0) {
      this._internalCover.clear();
      if (this._inst[0].hasCover()) {
        for (let i = 0; i < this._inst.length; ++i)
          this._internalCover.merge(this._inst[i].getCover());
      }
      this._highflags &= ~HighVariable.coverdirty;
    }
  }

  /**
   * @internal (Re)derive the external cover of this, as a union of internal covers.
   * This is only called by the Merge class which knows when to call it properly.
   */
  updateCover(): void {
    if (this._piece === null)
      this.updateInternalCover();
    else {
      this._piece.updateIntersections();
      this._piece.updateCover();
    }
  }

  /**
   * @internal (Re)derive boolean properties of this from the member Varnodes.
   * Only update if flags are marked as dirty.
   */
  updateFlags(): void {
    if ((this._highflags & HighVariable.flagsdirty) === 0) return; // flags are up to date

    let fl: number = 0;
    for (let i = 0; i < this._inst.length; ++i)
      fl |= this._inst[i].getFlags();

    // Keep these flags
    this._flags &= (VN_mark | VN_typelock);
    // Update all but these
    this._flags |= fl & ~(VN_mark | VN_directwrite | VN_typelock);
    this._highflags &= ~HighVariable.flagsdirty; // Clear the dirty flag
  }

  /**
   * @internal (Re)derive the data-type for this from the member Varnodes.
   * Only update if the data-type is marked as dirty.
   */
  updateType(): void {
    if ((this._highflags & HighVariable.typedirty) === 0) return; // Type is up to date
    this._highflags &= ~HighVariable.typedirty; // Mark type as clean
    if ((this._highflags & HighVariable.type_finalized) !== 0) return; // Type has been finalized
    const vn = this.getTypeRepresentative();

    this._type = vn.getType();
    this.stripType();
    // Update lock flags
    this._flags &= ~VN_typelock;
    if (vn.isTypeLock())
      this._flags |= VN_typelock;
  }

  /** @internal (Re)derive the Symbol and offset for this from member Varnodes */
  updateSymbol(): void {
    if ((this._highflags & HighVariable.symboldirty) === 0) return; // flags are up to date
    this._highflags &= ~HighVariable.symboldirty;
    this._symbol = null;

    for (let i = 0; i < this._inst.length; ++i) {
      const vn = this._inst[i];
      if (vn.getSymbolEntry() !== null) {
        this.setSymbol(vn);
        return;
      }
    }
  }

  /**
   * @internal Remove a member Varnode from this.
   * Search for the given Varnode and cut it out of the list, marking all properties as dirty.
   * @param vn is the given Varnode member to remove
   */
  remove(vn: Varnode): void {
    // Use linear search (equivalent to lower_bound + scan in the C++ code)
    for (let i = 0; i < this._inst.length; ++i) {
      if (this._inst[i] === vn) {
        this._inst.splice(i, 1);
        this._highflags |= (HighVariable.flagsdirty | HighVariable.namerepdirty |
                            HighVariable.coverdirty | HighVariable.typedirty);
        if (vn.getSymbolEntry() !== null)
          this._highflags |= HighVariable.symboldirty;
        if (this._piece !== null)
          this._piece.markExtendCoverDirty();
        return;
      }
    }
  }

  /**
   * @internal Merge another HighVariable into this.
   * The lists of members are merged and the other HighVariable is deleted.
   * @param tv2 is the other HighVariable to merge into this
   * @param isspeculative is true to keep the new members in separate merge classes
   */
  mergeInternal(tv2: HighVariable, isspeculative: boolean): void {
    this._highflags |= (HighVariable.flagsdirty | HighVariable.namerepdirty | HighVariable.typedirty);
    if (tv2._symbol !== null) { // Check if we inherit a Symbol
      if ((tv2._highflags & HighVariable.symboldirty) === 0) {
        this._symbol = tv2._symbol;             // Overwrite our Symbol (assume it is the same)
        this._symboloffset = tv2._symboloffset;
        this._highflags &= ~HighVariable.symboldirty; // Mark that we are not symbol dirty
      }
    }

    if (isspeculative) {
      for (let i = 0; i < tv2._inst.length; ++i) {
        const vn = tv2._inst[i];
        vn.setHigh(this, vn.getMergeGroup() + this._numMergeClasses);
      }
      this._numMergeClasses += tv2._numMergeClasses;
    } else {
      if ((this._numMergeClasses !== 1) || (tv2._numMergeClasses !== 1))
        throw new LowlevelError("Making a non-speculative merge after speculative merges have occurred");
      for (let i = 0; i < tv2._inst.length; ++i) {
        const vn = tv2._inst[i];
        vn.setHigh(this, vn.getMergeGroup());
      }
    }

    // Merge two sorted arrays (equivalent to std::merge with compareJustLoc)
    const instcopy = this._inst.slice();
    const a = instcopy;
    const b = tv2._inst;
    this._inst.length = 0;
    let ai = 0;
    let bi = 0;
    while (ai < a.length && bi < b.length) {
      if (HighVariable.compareJustLoc(a[ai], b[bi])) {
        this._inst.push(a[ai]);
        ai++;
      } else {
        this._inst.push(b[bi]);
        bi++;
      }
    }
    while (ai < a.length) {
      this._inst.push(a[ai]);
      ai++;
    }
    while (bi < b.length) {
      this._inst.push(b[bi]);
      bi++;
    }
    tv2._inst.length = 0;

    if (((this._highflags & HighVariable.coverdirty) === 0) &&
        ((tv2._highflags & HighVariable.coverdirty) === 0))
      this._internalCover.merge(tv2._internalCover);
    else
      this._highflags |= HighVariable.coverdirty;

    tv2.destroy();
  }

  /**
   * @internal Merge with another HighVariable taking into account groups.
   * The HighVariables are merged internally as with mergeInternal. If this is part of a
   * VariableGroup, extended covers of the group may be affected.
   * @param tv2 is the other HighVariable to merge into this
   * @param testCache if non-null is a cache of intersection tests that must be updated
   * @param isspeculative is true to keep the new members in separate merge classes
   */
  merge(tv2: HighVariable, testCache: HighIntersectTest | null, isspeculative: boolean): void {
    if (tv2 === this) return;

    if (testCache !== null)
      testCache.moveIntersectTests(this, tv2);
    if (this._piece === null && tv2._piece === null) {
      this.mergeInternal(tv2, isspeculative);
      return;
    }
    if (tv2._piece === null) {
      // Keep group that this is already in
      this._piece!.markExtendCoverDirty();
      this.mergeInternal(tv2, isspeculative);
      return;
    }
    if (this._piece === null) {
      // Move ownership of the VariablePiece object from the HighVariable that will be freed
      this.transferPiece(tv2);
      this._piece!.markExtendCoverDirty();
      this.mergeInternal(tv2, isspeculative);
      return;
    }
    // Reaching here both HighVariables are part of a group
    if (isspeculative)
      throw new LowlevelError("Trying speculatively merge variables in separate groups");
    const mergePairs: HighVariable[] = [];
    this._piece.mergeGroups(tv2._piece!, mergePairs);
    for (let i = 0; i < mergePairs.length; i += 2) {
      const high1 = mergePairs[i];
      const high2 = mergePairs[i + 1];
      if (testCache !== null)
        testCache.moveIntersectTests(high1, high2);
      high1.mergeInternal(high2, isspeculative);
    }
    this._piece.markIntersectionDirty();
  }

  /**
   * @internal Find the index of a specific Varnode member.
   * @param vn is the given Varnode member
   * @return the index of the member or -1 if it is not a member
   */
  instanceIndex(vn: Varnode): number {
    for (let i = 0; i < this._inst.length; ++i)
      if (this._inst[i] === vn) return i;
    return -1;
  }

  // --- Static methods ---

  /**
   * Compare based on storage location.
   * Compare two Varnode objects based just on their storage address.
   * @param a is the first Varnode to compare
   * @param b is the second Varnode
   * @return true if the first Varnode should be ordered before the second
   */
  static compareJustLoc(a: Varnode, b: Varnode): boolean {
    const aAddr = a.getAddr();
    const bAddr = b.getAddr();
    if (aAddr.getSpace !== undefined) {
      // Use Address comparison
      return aAddr.lessThan !== undefined ? aAddr.lessThan(bAddr) : aAddr < bAddr;
    }
    return false;
  }

  /**
   * Determine which given Varnode is most nameable.
   * Given two Varnode (members), sort them based on naming properties:
   *  - A Varnode with an assigned name is preferred
   *  - An unaffected Varnode is preferred
   *  - A global Varnode is preferred
   *  - An input Varnode is preferred
   *  - An address tied Varnode is preferred
   *  - A non-temporary Varnode is preferred
   *  - A written Varnode is preferred
   *  - An earlier Varnode is preferred
   *
   * @return true if the second Varnode's name would override the first's
   */
  static compareName(vn1: Varnode, vn2: Varnode): boolean {
    if (vn1.isNameLock()) return false; // Check for namelocks
    if (vn2.isNameLock()) return true;

    if (vn1.isUnaffected() !== vn2.isUnaffected()) // Prefer unaffected
      return vn2.isUnaffected();
    if (vn1.isPersist() !== vn2.isPersist()) // Prefer persistent
      return vn2.isPersist();
    if (vn1.isInput() !== vn2.isInput()) // Prefer an input
      return vn2.isInput();
    if (vn1.isAddrTied() !== vn2.isAddrTied()) // Prefer address tied
      return vn2.isAddrTied();
    if (vn1.isProtoPartial() !== vn2.isProtoPartial()) // Prefer pieces
      return vn2.isProtoPartial();

    // Prefer NOT internal
    if ((vn1.getSpace().getType() !== spacetype.IPTR_INTERNAL) &&
        (vn2.getSpace().getType() === spacetype.IPTR_INTERNAL))
      return false;
    if ((vn1.getSpace().getType() === spacetype.IPTR_INTERNAL) &&
        (vn2.getSpace().getType() !== spacetype.IPTR_INTERNAL))
      return true;
    if (vn1.isWritten() !== vn2.isWritten()) // Prefer written
      return vn2.isWritten();
    if (!vn1.isWritten())
      return false;
    // Prefer earlier
    if (vn1.getDef().getTime() !== vn2.getDef().getTime())
      return (vn2.getDef().getTime() < vn1.getDef().getTime());
    return false;
  }

  /**
   * Mark and collect variables in expression.
   * Given a Varnode at the root of an expression, collect all the explicit HighVariables
   * involved in the expression. The expression is traced back from the root
   * until explicit Varnodes are encountered; then their HighVariable is marked and added to the list.
   * The routine returns a value based on PcodeOps encountered in the expression:
   *   - 1 for call instructions
   *   - 2 for LOAD instructions
   *   - 3 for both call and LOAD
   *   - 0 for no calls or LOADS
   *
   * @param vn is the given root Varnode of the expression
   * @param highList will hold the collected HighVariables
   * @return a value based on call and LOAD instructions in the expression
   */
  static markExpression(vn: Varnode, highList: HighVariable[]): number {
    let high = vn.getHigh();
    high.setMark();
    highList.push(high);
    let retVal = 0;
    if (!vn.isWritten()) return retVal;

    const path: { op: PcodeOp; slot: number }[] = [];
    let op: PcodeOp = vn.getDef();
    if (op.isCall())
      retVal |= 1;
    if (op.code() === OpCode.CPUI_LOAD)
      retVal |= 2;
    path.push({ op: op, slot: 0 });
    while (path.length > 0) {
      const node = path[path.length - 1];
      if (node.op.numInput() <= node.slot) {
        path.pop();
        continue;
      }
      const curVn = node.op.getIn(node.slot);
      node.slot += 1;
      if (curVn.isAnnotation()) continue;
      if (curVn.isExplicit()) {
        high = curVn.getHigh();
        if (high.isMark()) continue; // Already in the list
        high.setMark();
        highList.push(high);
        continue; // Truncate at explicit
      }
      if (!curVn.isWritten()) continue;
      op = curVn.getDef();
      if (op.isCall())
        retVal |= 1;
      if (op.code() === OpCode.CPUI_LOAD)
        retVal |= 2;
      path.push({ op: curVn.getDef(), slot: 0 });
    }
    return retVal;
  }
}

// ---------------------------------------------------------------------------
// HighEdge
// ---------------------------------------------------------------------------

/**
 * A record for caching a Cover intersection test between two HighVariable objects.
 *
 * This is just a pair of HighVariable objects that can be used as a map key.
 */
export class HighEdge {
  /** @internal First HighVariable of the pair */
  a: HighVariable;
  /** @internal Second HighVariable of the pair */
  b: HighVariable;

  constructor(a: HighVariable, b: HighVariable) {
    this.a = a;
    this.b = b;
  }
}

// ---------------------------------------------------------------------------
// HighIntersectTest
// ---------------------------------------------------------------------------

/**
 * A cache of Cover intersection tests for HighVariables.
 *
 * A test is performed by calling the intersect() method, which returns the result of a full
 * Cover intersection test, taking into account overlapping pieces, shadow Varnodes etc. The
 * results of the test are cached in this object, so repeated calls do not need to perform the
 * full calculation.
 */
export class HighIntersectTest {
  /** PcodeOps that may indirectly affect the intersection test */
  private affectingOps: PcodeOpSet;

  /**
   * A cache of intersection tests.
   * We use a two-level Map<HighVariable, Map<HighVariable, boolean>> since JavaScript objects
   * cannot be used as map keys in a sorted manner (unlike C++ pointer comparison).
   */
  private highedgemap: Map<HighVariable, Map<HighVariable, boolean>> = new Map();

  /** Constructor */
  constructor(cCover: PcodeOpSet) {
    this.affectingOps = cCover;
  }

  /**
   * Gather Varnode instances of the given HighVariable that intersect a cover on a specific block.
   * @param a is the given HighVariable
   * @param blk is the specific block number
   * @param cover is the Cover to test for intersection
   * @param res will hold the resulting intersecting Varnodes
   */
  private static gatherBlockVarnodes(a: HighVariable, blk: number, cover: Cover, res: Varnode[]): void {
    for (let i = 0; i < a.numInstances(); ++i) {
      const vn = a.getInstance(i);
      if (1 < vn.getCover().intersectByBlock(blk, cover))
        res.push(vn);
    }
  }

  /**
   * Test instances of a the given HighVariable for intersection on a specific block with a cover.
   * @param a is the given HighVariable
   * @param blk is the specific block number
   * @param cover is the Cover to test for intersection
   * @param relOff is the relative byte offset of the HighVariable to the Varnodes
   * @param blist is the list of Varnodes for copy shadow testing
   * @return true if there is an intersection preventing merging
   */
  private static testBlockIntersection(
    a: HighVariable, blk: number, cover: Cover, relOff: number, blist: Varnode[]
  ): boolean {
    for (let i = 0; i < a.numInstances(); ++i) {
      const vn = a.getInstance(i);
      if (2 > vn.getCover().intersectByBlock(blk, cover)) continue;
      for (let j = 0; j < blist.length; ++j) {
        const vn2 = blist[j];
        if (1 < vn2.getCover().intersectByBlock(blk, vn.getCover())) {
          if (vn.getSize() === vn2.getSize()) {
            if (!vn.copyShadow(vn2))
              return true;
          } else {
            if (!vn.partialCopyShadow(vn2, relOff))
              return true;
          }
        }
      }
    }
    return false;
  }

  /**
   * Test if two HighVariables intersect on a given BlockBasic.
   * Intersections are checked only on the specified block.
   * @param a is the first HighVariable
   * @param b is the second HighVariable
   * @param blk is the index of the BlockBasic on which to test intersection
   * @return true if an intersection occurs in the specified block
   */
  private blockIntersection(a: HighVariable, b: HighVariable, blk: number): boolean {
    const blist: Varnode[] = [];

    const aCover = a.getCover();
    const bCover = b.getCover();
    HighIntersectTest.gatherBlockVarnodes(b, blk, aCover, blist);
    if (HighIntersectTest.testBlockIntersection(a, blk, bCover, 0, blist))
      return true;
    if (a._piece !== null) {
      const baseOff = a._piece.getOffset();
      for (let i = 0; i < a._piece.numIntersection(); ++i) {
        const interPiece = a._piece.getIntersection(i);
        const off = interPiece.getOffset() - baseOff;
        if (HighIntersectTest.testBlockIntersection(interPiece.getHigh(), blk, bCover, off, blist))
          return true;
      }
    }
    if (b._piece !== null) {
      const bBaseOff = b._piece.getOffset();
      for (let i = 0; i < b._piece.numIntersection(); ++i) {
        blist.length = 0;
        const bPiece = b._piece.getIntersection(i);
        const bOff = bPiece.getOffset() - bBaseOff;
        HighIntersectTest.gatherBlockVarnodes(bPiece.getHigh(), blk, aCover, blist);
        if (HighIntersectTest.testBlockIntersection(a, blk, bCover, -bOff, blist))
          return true;
        if (a._piece !== null) {
          const aBaseOff = a._piece.getOffset();
          for (let j = 0; j < a._piece.numIntersection(); ++j) {
            const interPiece = a._piece.getIntersection(j);
            const off = (interPiece.getOffset() - aBaseOff) - bOff;
            if (off > 0 && off >= bPiece.getSize()) continue; // Do a piece and b piece intersect at all
            if (off < 0 && -off >= interPiece.getSize()) continue;
            if (HighIntersectTest.testBlockIntersection(interPiece.getHigh(), blk, bCover, off, blist))
              return true;
          }
        }
      }
    }
    return false;
  }

  /**
   * Remove cached intersection tests for a given HighVariable.
   * All tests for pairs where either the first or second HighVariable matches the given one
   * are removed.
   * @param high is the given HighVariable to purge
   */
  private purgeHigh(high: HighVariable): void {
    const highMap = this.highedgemap.get(high);
    if (highMap === undefined) return;

    // For each partner b that high was tested against, remove the reverse entry (b -> high)
    for (const [partner] of highMap) {
      const partnerMap = this.highedgemap.get(partner);
      if (partnerMap !== undefined) {
        partnerMap.delete(high);
        if (partnerMap.size === 0)
          this.highedgemap.delete(partner);
      }
    }

    // Remove all entries for high
    this.highedgemap.delete(high);
  }

  /**
   * Test if a given HighVariable might intersect an address tied HighVariable during a call.
   * @param tied is the address tied HighVariable
   * @param untied is the given HighVariable to consider for intersection
   * @return true if we consider the HighVariables to be intersecting
   */
  private testUntiedCallIntersection(tied: HighVariable, untied: HighVariable): boolean {
    // If the address tied part is global, we do not need to test for crossings
    if (tied.isPersist()) return false;
    const vn = tied.getTiedVarnode();
    if (vn.hasNoLocalAlias()) return false; // A local variable is only in scope if it has aliases
    if (!this.affectingOps.isPopulated())
      this.affectingOps.populate();
    return untied.getCover().intersectByOpSet(this.affectingOps, vn);
  }

  /**
   * Translate any intersection tests for high2 into tests for high1.
   * The two variables will be merged and high2, as an object, will be freed.
   * @param high1 is the variable object being kept
   * @param high2 is the variable object being eliminated
   */
  moveIntersectTests(high1: HighVariable, high2: HighVariable): void {
    const yesinter: HighVariable[] = []; // Highs that high2 intersects
    const nointer: HighVariable[] = [];  // Highs that high2 does not intersect

    const high2Map = this.highedgemap.get(high2);
    if (high2Map !== undefined) {
      for (const [b, intersects] of high2Map) {
        if (b === high1) continue;
        if (intersects) {
          yesinter.push(b);
        } else {
          nointer.push(b);
          b.setMark(); // Mark that high2 did not intersect
        }
      }
    }

    // Purge all high2's tests
    if (high2Map !== undefined) {
      for (const [partner] of high2Map) {
        const partnerMap = this.highedgemap.get(partner);
        if (partnerMap !== undefined) {
          partnerMap.delete(high2);
          if (partnerMap.size === 0)
            this.highedgemap.delete(partner);
        }
      }
      this.highedgemap.delete(high2);
    }

    // For high1's existing tests: if test says no intersection, and there was no test with high2, delete the test
    const high1Map = this.highedgemap.get(high1);
    if (high1Map !== undefined) {
      const toDelete: HighVariable[] = [];
      for (const [b, intersects] of high1Map) {
        if (!intersects) { // If test is intersection==false
          if (!b.isMark()) { // and there was no test with high2
            toDelete.push(b); // Delete the test
          }
        }
      }
      for (const b of toDelete) {
        high1Map.delete(b);
        // Also remove the reverse
        const bMap = this.highedgemap.get(b);
        if (bMap !== undefined) {
          bMap.delete(high1);
          if (bMap.size === 0)
            this.highedgemap.delete(b);
        }
      }
      if (high1Map.size === 0)
        this.highedgemap.delete(high1);
    }

    // Clear marks from nointer
    for (const h of nointer)
      h.clearMark();

    // Reinsert high2's intersection==true tests for high1 now
    for (const b of yesinter) {
      this.setEdge(high1, b, true);
      this.setEdge(b, high1, true);
    }
  }

  /**
   * Make sure given HighVariable's Cover is up-to-date.
   * @param a is the HighVariable to update
   * @return true if the HighVariable was not originally dirty
   */
  updateHigh(a: HighVariable): boolean {
    if (!a.isCoverDirty()) return true;

    a.updateCover();
    this.purgeHigh(a);
    return false;
  }

  /**
   * Test the intersection of two HighVariables and cache the result.
   * If the Covers of the two variables intersect, this routine returns true.
   * @param a is the first HighVariable
   * @param b is the second HighVariable
   * @return true if the variables intersect
   */
  intersection(a: HighVariable, b: HighVariable): boolean {
    if (a === b) return false;
    const ares = this.updateHigh(a);
    const bres = this.updateHigh(b);
    if (ares && bres) { // If neither high was dirty
      const cached = this.getEdge(a, b);
      if (cached !== undefined) // If previous test is present
        return cached; // Use it
    }

    let res = false;
    const blockisect: number[] = [];
    a.getCover().intersectList(blockisect, b.getCover(), 2);
    for (let blk = 0; blk < blockisect.length; ++blk) {
      if (this.blockIntersection(a, b, blockisect[blk])) {
        res = true;
        break;
      }
    }
    if (!res) {
      const aTied = a.isAddrTied();
      const bTied = b.isAddrTied();
      if (aTied !== bTied) { // If one variable is address tied and the other isn't
        if (aTied)
          res = this.testUntiedCallIntersection(a, b);
        else
          res = this.testUntiedCallIntersection(b, a);
      }
    }
    this.setEdge(a, b, res); // Cache the result
    this.setEdge(b, a, res);
    return res;
  }

  /** Clear any cached tests */
  clear(): void {
    this.highedgemap.clear();
  }

  // --- Private helpers for the two-level map ---

  /** @internal Set an edge in the two-level map */
  private setEdge(a: HighVariable, b: HighVariable, val: boolean): void {
    let aMap = this.highedgemap.get(a);
    if (aMap === undefined) {
      aMap = new Map();
      this.highedgemap.set(a, aMap);
    }
    aMap.set(b, val);
  }

  /** @internal Get an edge from the two-level map, or undefined if not present */
  private getEdge(a: HighVariable, b: HighVariable): boolean | undefined {
    const aMap = this.highedgemap.get(a);
    if (aMap === undefined) return undefined;
    return aMap.get(b);
  }
}
