/// \file transform.ts
/// \brief Classes for building large scale transforms of function data-flow

import { Address, calc_mask } from '../core/address.js';
import { OpCode } from '../core/opcodes.js';
import { spacetype } from '../core/space.js';
import { LowlevelError } from '../core/error.js';
import { AttributeId } from '../core/marshal.js';
import { Varnode } from './varnode.js';
import { PcodeOp } from './op.js';

// Forward type declarations for types from not-yet-written modules
type Funcdata = any;

/// Marshaling attribute "vector_lane_sizes"
export const ATTRIB_VECTOR_LANE_SIZES = new AttributeId("vector_lane_sizes", 130);

// =====================================================================
// TransformVar
// =====================================================================

/// Placeholder node for Varnode that will exist after a transform is applied to a function
export class TransformVar {
  /// Types of replacement Varnodes
  static readonly piece = 1;            ///< New Varnode is a piece of an original Varnode
  static readonly preexisting = 2;      ///< Varnode preexisted in the original data-flow
  static readonly normal_temp = 3;      ///< A new temporary (unique space) Varnode
  static readonly piece_temp = 4;       ///< A temporary representing a piece of an original Varnode
  static readonly constant = 5;         ///< A new constant Varnode
  static readonly constant_iop = 6;     ///< Special iop constant encoding a PcodeOp reference

  /// Flags for a TransformVar
  static readonly split_terminator = 1; ///< The last (most significant piece) of a split array
  static readonly input_duplicate = 2;  ///< This is a piece of an input that has already been visited

  vn: Varnode | null = null;            ///< Original big Varnode of which this is a component
  replacement: Varnode | null = null;   ///< The new explicit lane Varnode
  type: number = 0;                     ///< Type of new Varnode
  flags: number = 0;                    ///< Boolean properties of the placeholder
  byteSize: number = 0;                 ///< Size of the lane Varnode in bytes
  bitSize: number = 0;                  ///< Size of the logical value in bits
  val: bigint = 0n;                     ///< Value of constant or (bit) position within the original big Varnode
  def: TransformOp | null = null;       ///< Defining op for new Varnode

  /// Initialize this variable from raw data
  ///
  /// \param tp is the type of variable to create
  /// \param v is the underlying Varnode of which this is a piece (may be null)
  /// \param bits is the number of bits in the variable
  /// \param bytes is the number of bytes in the variable
  /// \param value is the associated value
  initialize(tp: number, v: Varnode | null, bits: number, bytes: number, value: bigint): void {
    this.type = tp;
    this.vn = v;
    this.val = value;
    this.bitSize = bits;
    this.byteSize = bytes;
    this.flags = 0;
    this.def = null;
    this.replacement = null;
  }

  /// Create the new/modified variable this placeholder represents
  /// \param fd is the function in which to create the replacement
  createReplacement(fd: Funcdata): void {
    if (this.replacement !== null)
      return;    // Replacement already created
    switch (this.type) {
      case TransformVar.preexisting:
        this.replacement = this.vn;
        break;
      case TransformVar.constant:
        this.replacement = fd.newConstant(this.byteSize, this.val);
        break;
      case TransformVar.normal_temp:
      case TransformVar.piece_temp:
        if (this.def === null)
          this.replacement = fd.newUnique(this.byteSize);
        else
          this.replacement = fd.newUniqueOut(this.byteSize, this.def.replacement);
        break;
      case TransformVar.piece:
      {
        let bytePos: number = Number(this.val);
        if ((bytePos & 7) !== 0)
          throw new LowlevelError("Varnode piece is not byte aligned");
        bytePos >>= 3;
        if (this.vn!.getSpace()!.isBigEndian())
          bytePos = this.vn!.getSize() - bytePos - this.byteSize;
        let addr: Address = this.vn!.getAddr().add(BigInt(bytePos));
        addr.renormalize(this.byteSize);
        if (this.def === null)
          this.replacement = fd.newVarnode(this.byteSize, addr);
        else
          this.replacement = fd.newVarnodeOut(this.byteSize, addr, this.def.replacement);
        fd.transferVarnodeProperties(this.vn, this.replacement, bytePos);
        break;
      }
      case TransformVar.constant_iop:
      {
        const indeffect: PcodeOp | null = PcodeOp.getOpFromConst(
          new Address(fd.getArch().getIopSpace(), this.val));
        this.replacement = fd.newVarnodeIop(indeffect);
        break;
      }
      default:
        throw new LowlevelError("Bad TransformVar type");
    }
  }

  /// Get the original Varnode this placeholder models
  getOriginal(): Varnode | null { return this.vn; }

  /// Get the operator that defines this placeholder variable
  getDef(): TransformOp | null { return this.def; }
}

// =====================================================================
// TransformOp
// =====================================================================

/// Placeholder node for PcodeOp that will exist after a transform is applied to a function
export class TransformOp {
  /// Special annotations on new pcode ops
  static readonly op_replacement = 1;                    ///< Op replaces an existing op
  static readonly op_preexisting = 2;                    ///< Op already exists (but will be transformed)
  static readonly indirect_creation = 4;                 ///< Mark op as indirect creation
  static readonly indirect_creation_possible_out = 8;    ///< Mark op as indirect creation and possible call output

  op: PcodeOp | null = null;                 ///< Original op which this is splitting (or null)
  replacement: PcodeOp | null = null;        ///< The new replacement op
  opc: OpCode = 0 as OpCode;                 ///< Opcode of the new op
  special: number = 0;                       ///< Special handling code when creating
  output: TransformVar | null = null;        ///< Varnode output
  input: (TransformVar | null)[] = [];       ///< Varnode inputs
  follow: TransformOp | null = null;         ///< The following op after this (if not null)

  /// Create the new/modified op this placeholder represents
  /// \param fd is the function in which to make the modifications
  createReplacement(fd: Funcdata): void {
    if ((this.special & TransformOp.op_preexisting) !== 0) {
      this.replacement = this.op;
      fd.opSetOpcode(this.op, this.opc);
      while (this.input.length < this.op!.numInput())
        fd.opRemoveInput(this.op, this.op!.numInput() - 1);
      for (let i = 0; i < this.op!.numInput(); ++i)
        fd.opUnsetInput(this.op, i);    // Clear any remaining inputs
      while (this.op!.numInput() < this.input.length)
        fd.opInsertInput(this.op, null, this.op!.numInput() - 1);
    }
    else {
      this.replacement = fd.newOp(this.input.length, this.op!.getAddr());
      fd.opSetOpcode(this.replacement, this.opc);
      if (this.output !== null)
        this.output.createReplacement(fd);
      if (this.follow === null) {    // Can be inserted immediately
        if (this.opc === OpCode.CPUI_MULTIEQUAL)
          fd.opInsertBegin(this.replacement, this.op!.getParent());
        else
          fd.opInsertBefore(this.replacement, this.op);
      }
    }
  }

  /// Try to put the new PcodeOp into its basic block
  /// \param fd is the function into which the PcodeOp will be inserted
  /// \return true if the op is successfully inserted or already inserted
  attemptInsertion(fd: Funcdata): boolean {
    if (this.follow !== null) {
      if (this.follow.follow === null) {    // Check if the follow is inserted
        if (this.opc === OpCode.CPUI_MULTIEQUAL)
          fd.opInsertBegin(this.replacement, this.follow.replacement!.getParent());
        else
          fd.opInsertBefore(this.replacement, this.follow.replacement);
        this.follow = null;    // Mark that this has been inserted
        return true;
      }
      return false;
    }
    return true;    // Already inserted
  }

  /// Get the output placeholder variable for this operator
  getOut(): TransformVar | null { return this.output; }

  /// Get the i-th input placeholder variable for this
  getIn(i: number): TransformVar | null { return this.input[i]; }

  /// Set indirect creation flags for this based on given INDIRECT
  /// \param indOp is the given INDIRECT
  inheritIndirect(indOp: PcodeOp): void {
    if (indOp.isIndirectCreation()) {
      if (indOp.getIn(0)!.isIndirectZero())
        this.special |= TransformOp.indirect_creation;
      else
        this.special |= TransformOp.indirect_creation_possible_out;
    }
  }
}

// =====================================================================
// LanedRegister
// =====================================================================

/// Class for iterating over possible lane sizes
export class LanedIterator {
  private size: number;           ///< Current lane size
  private mask: number;           ///< Collection being iterated over

  /// Normalize the iterator, after increment or initialization
  private normalize(): void {
    let flag: number = 1;
    flag <<= this.size;
    while (flag <= this.mask) {
      if ((flag & this.mask) !== 0) return;    // Found a valid lane size
      this.size += 1;
      flag <<= 1;
    }
    this.size = -1;    // Indicate ending iterator
  }

  /// Constructor
  constructor(lanedR?: LanedRegister) {
    if (lanedR !== undefined) {
      this.size = 0;
      this.mask = lanedR.getSizeBitMask();
      this.normalize();
    } else {
      // Constructor for ending iterator
      this.size = -1;
      this.mask = 0;
    }
  }

  /// Preincrement operator
  next(): LanedIterator {
    this.size += 1;
    this.normalize();
    return this;
  }

  /// Dereference operator - get current lane size
  value(): number { return this.size; }

  /// Copy from another iterator
  assign(op2: LanedIterator): LanedIterator {
    this.size = op2.size;
    this.mask = op2.mask;
    return this;
  }

  /// Equal operator
  equals(op2: LanedIterator): boolean { return (this.size === op2.size); }

  /// Not-equal operator
  notEquals(op2: LanedIterator): boolean { return (this.size !== op2.size); }
}

/// Describes a (register) storage location and the ways it might be split into lanes
export class LanedRegister {
  private wholeSize: number;      ///< Size of the whole register
  private sizeBitMask: number;    ///< A 1-bit for every permissible lane size

  /// Constructor for use with decode
  constructor();
  /// Constructor
  constructor(sz: number, mask: number);
  constructor(sz?: number, mask?: number) {
    if (sz !== undefined && mask !== undefined) {
      this.wholeSize = sz;
      this.sizeBitMask = mask;
    } else {
      this.wholeSize = 0;
      this.sizeBitMask = 0;
    }
  }

  /// Parse a vector_lane_sizes attribute
  /// \param registerSize is the size of the laned register in bytes
  /// \param laneSizes is a comma separated list of sizes
  parseSizes(registerSize: number, laneSizes: string): void {
    this.wholeSize = registerSize;
    this.sizeBitMask = 0;
    let pos: number = 0;
    while (pos < laneSizes.length) {
      let nextPos: number = laneSizes.indexOf(',', pos);
      let value: string;
      if (nextPos === -1) {
        value = laneSizes.substring(pos);    // To the end of the string
        pos = laneSizes.length;              // Terminate loop
      } else {
        value = laneSizes.substring(pos, nextPos);
        pos = nextPos + 1;
        if (pos >= laneSizes.length)
          pos = laneSizes.length;    // Terminate loop
      }
      const sz: number = parseInt(value, 10);
      if (isNaN(sz) || sz < 0 || sz > 16)
        throw new LowlevelError("Bad lane size: " + value);
      this.addLaneSize(sz);
    }
  }

  /// Get the size in bytes of the whole laned register
  getWholeSize(): number { return this.wholeSize; }

  /// Get the bit mask of possible lane sizes
  getSizeBitMask(): number { return this.sizeBitMask; }

  /// Add a new size to the allowed list
  addLaneSize(size: number): void { this.sizeBitMask |= (1 << size); }

  /// Is size among the allowed lane sizes
  allowedLane(size: number): boolean { return (((this.sizeBitMask >> size) & 1) !== 0); }

  /// Starting iterator over possible lane sizes
  begin(): LanedIterator { return new LanedIterator(this); }

  /// Ending iterator over possible lane sizes
  end(): LanedIterator { return new LanedIterator(); }
}

// =====================================================================
// LaneDescription
// =====================================================================

/// Description of logical lanes within a big Varnode
///
/// A lane is a byte offset and size within a Varnode. Lanes within a
/// Varnode are disjoint. In general, we expect a Varnode to be tiled with
/// lanes all of the same size, but the API allows for possibly non-uniform lanes.
export class LaneDescription {
  private wholeSize: number;            ///< Size of the region being split in bytes
  private laneSize: number[];           ///< Size of lanes in bytes
  private lanePosition: number[];       ///< Significance positions of lanes in bytes

  /// Construct from another LaneDescription (copy), uniform lanes, or two arbitrary-size lanes
  constructor(op2: LaneDescription);
  constructor(origSize: number, sz: number);
  constructor(origSize: number, lo: number, hi: number);
  constructor(arg0: LaneDescription | number, arg1?: number, arg2?: number) {
    if (arg0 instanceof LaneDescription) {
      // Copy constructor
      const op2 = arg0;
      this.wholeSize = op2.wholeSize;
      this.laneSize = [...op2.laneSize];
      this.lanePosition = [...op2.lanePosition];
    } else if (arg2 !== undefined) {
      // Two lanes of arbitrary size: (origSize, lo, hi)
      const origSize = arg0;
      const lo = arg1!;
      const hi = arg2;
      this.wholeSize = origSize;
      this.laneSize = [lo, hi];
      this.lanePosition = [0, lo];
    } else {
      // Uniform lanes: (origSize, sz)
      const origSize = arg0;
      const sz = arg1!;
      this.wholeSize = origSize;
      const numLanes = Math.floor(origSize / sz);
      this.laneSize = new Array<number>(numLanes);
      this.lanePosition = new Array<number>(numLanes);
      let pos = 0;
      for (let i = 0; i < numLanes; ++i) {
        this.laneSize[i] = sz;
        this.lanePosition[i] = pos;
        pos += sz;
      }
    }
  }

  /// Trim this to a subset of the original lanes.
  /// Given a subrange, specified as an offset into the whole and size,
  /// throw out any lanes that aren't in the subrange.
  /// \param lsbOffset is the number of bytes to remove from the front of the description
  /// \param size is the number of bytes in the subrange
  /// \return true if this was successfully transformed to the subrange
  subset(lsbOffset: number, size: number): boolean {
    if (lsbOffset === 0 && size === this.wholeSize)
      return true;    // subrange is the whole range
    const firstLane: number = this.getBoundary(lsbOffset);
    if (firstLane < 0) return false;
    const lastLane: number = this.getBoundary(lsbOffset + size);
    if (lastLane < 0) return false;
    const newLaneSize: number[] = [];
    this.lanePosition = [];
    let newPosition: number = 0;
    for (let i = firstLane; i < lastLane; ++i) {
      const sz: number = this.laneSize[i];
      this.lanePosition.push(newPosition);
      newLaneSize.push(sz);
      newPosition += sz;
    }
    this.wholeSize = size;
    this.laneSize = newLaneSize;
    return true;
  }

  /// Get the total number of lanes
  getNumLanes(): number { return this.laneSize.length; }

  /// Get the size of the region being split
  getWholeSize(): number { return this.wholeSize; }

  /// Get the size of the i-th lane
  getSize(i: number): number { return this.laneSize[i]; }

  /// Get the significance offset of the i-th lane
  getPosition(i: number): number { return this.lanePosition[i]; }

  /// Get index of lane that starts at the given byte position.
  /// Position 0 will map to index 0 and a position equal to whole size will
  /// map to the number of lanes.  Positions that are out of bounds or that do
  /// not fall on a lane boundary will return -1.
  /// \param bytePos is the given byte position to test
  /// \return the index of the lane that starts at the given position
  getBoundary(bytePos: number): number {
    if (bytePos < 0 || bytePos > this.wholeSize)
      return -1;
    if (bytePos === this.wholeSize)
      return this.lanePosition.length;
    let min = 0;
    let max = this.lanePosition.length - 1;
    while (min <= max) {
      const index = Math.floor((min + max) / 2);
      const pos = this.lanePosition[index];
      if (pos === bytePos) return index;
      if (pos < bytePos)
        min = index + 1;
      else
        max = index - 1;
    }
    return -1;
  }

  /// Decide if a given truncation is natural for this description
  ///
  /// A subset of lanes are specified and a truncation (given by a byte position and byte size).
  /// If the truncation, relative to the subset, contains at least 1 lane and does not split any
  /// lanes, then return true and pass back the number of lanes and starting lane of the truncation.
  /// \param numLanes is the number of lanes in the original subset
  /// \param skipLanes is the starting (least significant) lane index of the original subset
  /// \param bytePos is the number of bytes to truncate from the front of the subset
  /// \param size is the number of bytes to include in the truncation
  /// \return { result: boolean, resNumLanes: number, resSkipLanes: number }
  restriction(numLanes: number, skipLanes: number, bytePos: number, size: number):
      { result: boolean; resNumLanes: number; resSkipLanes: number } {
    const resSkipLanes = this.getBoundary(this.lanePosition[skipLanes] + bytePos);
    if (resSkipLanes < 0) return { result: false, resNumLanes: 0, resSkipLanes: 0 };
    const finalIndex = this.getBoundary(this.lanePosition[skipLanes] + bytePos + size);
    if (finalIndex < 0) return { result: false, resNumLanes: 0, resSkipLanes: 0 };
    const resNumLanes = finalIndex - resSkipLanes;
    return { result: (resNumLanes !== 0), resNumLanes, resSkipLanes };
  }

  /// Decide if a given subset of lanes can be extended naturally for this description
  ///
  /// A subset of lanes are specified and their position within an extension (given by a byte position).
  /// The size in bytes of the extension is also given. If the extension is contained within this description,
  /// and the boundaries of the extension don't split any lanes, then return true and pass back
  /// the number of lanes and starting lane of the extension.
  /// \param numLanes is the number of lanes in the original subset
  /// \param skipLanes is the starting (least significant) lane index of the original subset
  /// \param bytePos is the number of bytes to truncate from the front of the extension
  /// \param size is the number of bytes in the extension
  /// \return { result: boolean, resNumLanes: number, resSkipLanes: number }
  extension(numLanes: number, skipLanes: number, bytePos: number, size: number):
      { result: boolean; resNumLanes: number; resSkipLanes: number } {
    const resSkipLanes = this.getBoundary(this.lanePosition[skipLanes] - bytePos);
    if (resSkipLanes < 0) return { result: false, resNumLanes: 0, resSkipLanes: 0 };
    const finalIndex = this.getBoundary(this.lanePosition[skipLanes] - bytePos + size);
    if (finalIndex < 0) return { result: false, resNumLanes: 0, resSkipLanes: 0 };
    const resNumLanes = finalIndex - resSkipLanes;
    return { result: (resNumLanes !== 0), resNumLanes, resSkipLanes };
  }
}

// =====================================================================
// TransformManager
// =====================================================================

/// Class for splitting larger registers holding smaller logical lanes
///
/// Given a starting Varnode in the data-flow, look for evidence of the Varnode
/// being interpreted as disjoint logical values concatenated together (lanes).
/// If the interpretation is consistent for data-flow involving the Varnode, split
/// Varnode and data-flow into explicit operations on the lanes.
export class TransformManager {
  private fd: Funcdata;                                  ///< Function being operated on
  private pieceMap: Map<number, TransformVar[]> = new Map(); ///< Map from large Varnodes to their new pieces
  private newVarnodes: TransformVar[] = [];              ///< Storage for Varnode placeholder nodes
  private newOps: TransformOp[] = [];                    ///< Storage for PcodeOp placeholder nodes

  /// Constructor
  constructor(f: Funcdata) {
    this.fd = f;
  }

  /// Destructor (no-op in TypeScript, but provided for structural parity)
  destroy(): void {
    // In C++ this deletes the arrays in pieceMap. In JS/TS, GC handles it.
    this.pieceMap.clear();
  }

  /// Should the address of the given Varnode be preserved when constructing a piece
  ///
  /// A new Varnode will be created that represents a logical piece of the given Varnode.
  /// This routine determines whether the new Varnode should be constructed using
  /// storage which overlaps the given Varnode. It returns true if overlapping storage
  /// should be used, false if the new Varnode should be constructed as a unique temporary.
  /// \param vn is the given Varnode
  /// \param bitSize is the logical size of the Varnode piece being constructed
  /// \param lsbOffset is the least significant bit position of the logical value within the given Varnode
  /// \return true if overlapping storage should be used in construction
  preserveAddress(vn: Varnode, bitSize: number, lsbOffset: number): boolean {
    if ((lsbOffset & 7) !== 0) return false;    // Logical value not aligned
    if (vn.getSpace()!.getType() === spacetype.IPTR_INTERNAL) return false;
    return true;
  }

  /// Get function being transformed
  getFunction(): Funcdata { return this.fd; }

  /// Clear mark for all Varnodes in the map
  clearVarnodeMarks(): void {
    for (const [, vArray] of this.pieceMap) {
      const vn: Varnode | null = vArray[0].vn;
      if (vn === null)
        continue;
      vn.clearMark();
    }
  }

  /// Make placeholder for preexisting Varnode
  /// \param vn is the preexisting Varnode to create a placeholder for
  /// \return the new placeholder node
  newPreexistingVarnode(vn: Varnode): TransformVar {
    const res = new TransformVar();
    this.pieceMap.set(vn.getCreateIndex(), [res]);    // Enter preexisting Varnode into map

    // value of 0 treats this as "piece" of itself at offset 0, allows getPiece() to find it
    res.initialize(TransformVar.preexisting, vn, vn.getSize() * 8, vn.getSize(), 0n);
    res.flags = TransformVar.split_terminator;
    return res;
  }

  /// Make placeholder for new unique space Varnode
  /// \param size is the size in bytes of the new unique Varnode
  /// \return the new placeholder node
  newUnique(size: number): TransformVar {
    const res = new TransformVar();
    this.newVarnodes.push(res);
    res.initialize(TransformVar.normal_temp, null, size * 8, size, 0n);
    return res;
  }

  /// Make placeholder for constant Varnode.
  /// Create a new constant in the transform view. A piece of an existing constant
  /// can be created by giving the existing value and the least significant offset.
  /// \param size is the size in bytes of the new constant
  /// \param lsbOffset is the number of bits to strip off of the existing value
  /// \param val is the value of the constant
  /// \return the new placeholder node
  newConstant(size: number, lsbOffset: number, val: bigint): TransformVar {
    const res = new TransformVar();
    this.newVarnodes.push(res);
    res.initialize(TransformVar.constant, null, size * 8, size,
      (val >> BigInt(lsbOffset)) & calc_mask(size));
    return res;
  }

  /// Make placeholder for special iop constant.
  /// Used for creating INDIRECT placeholders.
  /// \param vn is the original iop parameter to the INDIRECT
  /// \return the new placeholder node
  newIop(vn: Varnode): TransformVar {
    const res = new TransformVar();
    this.newVarnodes.push(res);
    res.initialize(TransformVar.constant_iop, null, vn.getSize() * 8, vn.getSize(), vn.getOffset());
    return res;
  }

  /// Make placeholder for piece of a Varnode.
  /// Given a single logical value within a larger Varnode, create a placeholder for
  /// that logical value.
  /// \param vn is the large Varnode
  /// \param bitSize is the size of the logical value in bits
  /// \param lsbOffset is the number of least significant bits of the Varnode dropped from the value
  /// \return the placeholder variable
  newPiece(vn: Varnode, bitSize: number, lsbOffset: number): TransformVar {
    const res = new TransformVar();
    this.pieceMap.set(vn.getCreateIndex(), [res]);
    const byteSize: number = Math.floor((bitSize + 7) / 8);
    const type: number = this.preserveAddress(vn, bitSize, lsbOffset) ?
      TransformVar.piece : TransformVar.piece_temp;
    res.initialize(type, vn, bitSize, byteSize, BigInt(lsbOffset));
    res.flags = TransformVar.split_terminator;
    return res;
  }

  /// Create placeholder nodes splitting a Varnode into its lanes
  ///
  /// Given a big Varnode and a lane description, create placeholders for all the explicit pieces
  /// that the big Varnode will be split into.
  /// \param vn is the big Varnode to split
  /// \param description shows how the big Varnode will be split
  /// \return an array of the new TransformVar placeholders from least to most significant
  newSplit(vn: Varnode, description: LaneDescription): TransformVar[];
  /// Create placeholder nodes splitting a Varnode into a subset of lanes in the given description
  ///
  /// \param vn is the big Varnode to split
  /// \param description gives a list of potential lanes
  /// \param numLanes is the number of lanes in the subset
  /// \param startLane is the starting (least significant) lane in the subset
  /// \return an array of the new TransformVar placeholders from least to most significant
  newSplit(vn: Varnode, description: LaneDescription, numLanes: number, startLane: number): TransformVar[];
  newSplit(vn: Varnode, description: LaneDescription, numLanes?: number, startLane?: number): TransformVar[] {
    if (numLanes !== undefined && startLane !== undefined) {
      return this._newSplitSubset(vn, description, numLanes, startLane);
    }
    return this._newSplitFull(vn, description);
  }

  private _newSplitFull(vn: Varnode, description: LaneDescription): TransformVar[] {
    const num: number = description.getNumLanes();
    const res: TransformVar[] = new Array<TransformVar>(num);
    for (let i = 0; i < num; ++i) {
      res[i] = new TransformVar();
    }
    this.pieceMap.set(vn.getCreateIndex(), res);
    for (let i = 0; i < num; ++i) {
      const bitpos: number = description.getPosition(i) * 8;
      const newVar: TransformVar = res[i];
      const byteSize: number = description.getSize(i);
      if (vn.isConstant()) {
        let val: bigint;
        if (bitpos < 64)    // sizeof(bigint) effectively 8 bytes in the original
          val = (vn.getOffset() >> BigInt(bitpos)) & calc_mask(byteSize);
        else
          val = 0n;    // Assume bits beyond precision are 0
        newVar.initialize(TransformVar.constant, vn, byteSize * 8, byteSize, val);
      }
      else {
        const type: number = this.preserveAddress(vn, byteSize * 8, bitpos) ?
          TransformVar.piece : TransformVar.piece_temp;
        newVar.initialize(type, vn, byteSize * 8, byteSize, BigInt(bitpos));
      }
    }
    res[num - 1].flags = TransformVar.split_terminator;
    return res;
  }

  private _newSplitSubset(vn: Varnode, description: LaneDescription, numLanes: number, startLane: number): TransformVar[] {
    const res: TransformVar[] = new Array<TransformVar>(numLanes);
    for (let i = 0; i < numLanes; ++i) {
      res[i] = new TransformVar();
    }
    this.pieceMap.set(vn.getCreateIndex(), res);
    const baseBitPos: number = description.getPosition(startLane) * 8;
    for (let i = 0; i < numLanes; ++i) {
      const bitpos: number = description.getPosition(startLane + i) * 8 - baseBitPos;
      const byteSize: number = description.getSize(startLane + i);
      const newVar: TransformVar = res[i];
      if (vn.isConstant()) {
        let val: bigint;
        if (bitpos < 64)    // sizeof(uintb)*8 equivalent
          val = (vn.getOffset() >> BigInt(bitpos)) & calc_mask(byteSize);
        else
          val = 0n;    // Assume bits beyond precision are 0
        newVar.initialize(TransformVar.constant, vn, byteSize * 8, byteSize, val);
      }
      else {
        const type: number = this.preserveAddress(vn, byteSize * 8, bitpos) ?
          TransformVar.piece : TransformVar.piece_temp;
        newVar.initialize(type, vn, byteSize * 8, byteSize, BigInt(bitpos));
      }
    }
    res[numLanes - 1].flags = TransformVar.split_terminator;
    return res;
  }

  /// Create a new placeholder op intended to replace an existing op
  ///
  /// \param numParams is the number of Varnode inputs intended for the new op
  /// \param opc is the opcode of the new op
  /// \param replace is the existing op the new op will replace
  /// \return the new placeholder node
  newOpReplace(numParams: number, opc: OpCode, replace: PcodeOp): TransformOp {
    const rop = new TransformOp();
    this.newOps.push(rop);
    rop.op = replace;
    rop.replacement = null;
    rop.opc = opc;
    rop.special = TransformOp.op_replacement;
    rop.output = null;
    rop.follow = null;
    rop.input = new Array<TransformVar | null>(numParams).fill(null);
    return rop;
  }

  /// Create a new placeholder op that will not replace an existing op
  ///
  /// An uninitialized placeholder for the new op is created. When (if) the new op is created
  /// it will not replace an existing op. The op that follows it must be given.
  /// \param numParams is the number of Varnode inputs intended for the new op
  /// \param opc is the opcode of the new op
  /// \param follow is the placeholder for the op that follows the new op when it is created
  /// \return the new placeholder node
  newOp(numParams: number, opc: OpCode, follow: TransformOp): TransformOp {
    const rop = new TransformOp();
    this.newOps.push(rop);
    rop.op = follow.op;
    rop.replacement = null;
    rop.opc = opc;
    rop.special = 0;
    rop.output = null;
    rop.follow = follow;
    rop.input = new Array<TransformVar | null>(numParams).fill(null);
    return rop;
  }

  /// Create a new placeholder op for an existing PcodeOp
  ///
  /// An uninitialized placeholder for the existing op is created. When applied, this causes
  /// the op to be transformed as described by the placeholder, changing its opcode and
  /// inputs. The output however is unaffected.
  /// \param numParams is the number of Varnode inputs intended for the transformed op
  /// \param opc is the opcode of the transformed op
  /// \param originalOp is the preexisting PcodeOp
  /// \return the new placeholder node
  newPreexistingOp(numParams: number, opc: OpCode, originalOp: PcodeOp): TransformOp {
    const rop = new TransformOp();
    this.newOps.push(rop);
    rop.op = originalOp;
    rop.replacement = null;
    rop.opc = opc;
    rop.special = TransformOp.op_preexisting;
    rop.output = null;
    rop.follow = null;
    rop.input = new Array<TransformVar | null>(numParams).fill(null);
    return rop;
  }

  /// Get (or create) placeholder for preexisting Varnode.
  /// Check if a placeholder node was created for the preexisting Varnode,
  /// otherwise create a new one.
  /// \param vn is the preexisting Varnode to find a placeholder for
  /// \return the placeholder node
  getPreexistingVarnode(vn: Varnode): TransformVar {
    if (vn.isConstant())
      return this.newConstant(vn.getSize(), 0, vn.getOffset());
    const entry = this.pieceMap.get(vn.getCreateIndex());
    if (entry !== undefined)
      return entry[0];
    return this.newPreexistingVarnode(vn);
  }

  /// Get (or create) placeholder piece.
  /// Given a big Varnode, find the placeholder corresponding to the logical value
  /// given by a size and significance offset. If it doesn't exist, create it.
  /// \param vn is the big Varnode containing the logical value
  /// \param bitSize is the size of the logical value in bits
  /// \param lsbOffset is the significance offset of the logical value within the Varnode
  /// \return the found/created placeholder
  getPiece(vn: Varnode, bitSize: number, lsbOffset: number): TransformVar {
    const entry = this.pieceMap.get(vn.getCreateIndex());
    if (entry !== undefined) {
      const res: TransformVar = entry[0];
      if (res.bitSize !== bitSize || res.val !== BigInt(lsbOffset))
        throw new LowlevelError("Cannot create multiple pieces for one Varnode through getPiece");
      return res;
    }
    return this.newPiece(vn, bitSize, lsbOffset);
  }

  /// Find (or create) placeholder nodes splitting a Varnode into its lanes
  ///
  /// Given a big Varnode and a lane description, look up placeholders for all its
  /// explicit pieces. If they don't exist, create them.
  /// \param vn is the big Varnode to split
  /// \param description shows how the big Varnode will be split
  /// \return an array of the TransformVar placeholders from least to most significant
  getSplit(vn: Varnode, description: LaneDescription): TransformVar[];
  /// Find (or create) placeholder nodes splitting a Varnode into a subset of lanes from a description
  ///
  /// \param vn is the big Varnode to split
  /// \param description describes all the possible lanes
  /// \param numLanes is the number of lanes in the subset
  /// \param startLane is the starting (least significant) lane in the subset
  /// \return an array of the TransformVar placeholders from least to most significant
  getSplit(vn: Varnode, description: LaneDescription, numLanes: number, startLane: number): TransformVar[];
  getSplit(vn: Varnode, description: LaneDescription, numLanes?: number, startLane?: number): TransformVar[] {
    const entry = this.pieceMap.get(vn.getCreateIndex());
    if (entry !== undefined) {
      return entry;
    }
    if (numLanes !== undefined && startLane !== undefined) {
      return this.newSplit(vn, description, numLanes, startLane);
    }
    return this.newSplit(vn, description);
  }

  /// Mark given variable as input to given op
  /// \param rop is the given placeholder op whose input is set
  /// \param rvn is the placeholder variable to set
  /// \param slot is the input position to set
  opSetInput(rop: TransformOp, rvn: TransformVar, slot: number): void {
    rop.input[slot] = rvn;
  }

  /// Mark given variable as output of given op.
  /// Establish that the given op produces the given var as output.
  /// Mark both the output field of the TransformOp and the def field of the TransformVar.
  /// \param rop is the given op
  /// \param rvn is the given variable
  opSetOutput(rop: TransformOp, rvn: TransformVar): void {
    rop.output = rvn;
    rvn.def = rop;
  }

  /// Should newPreexistingOp be called.
  /// Varnode marking prevents duplicate TransformOp (and TransformVar) records from getting
  /// created, except in the case of a preexisting PcodeOp with 2 (or more) non-constant inputs.
  /// Because the op is preexisting the output Varnode doesn't get marked, and the op will
  /// be visited for each input. This method determines when the TransformOp object should be
  /// created, with the goal of creating it exactly once even though the op is visited more than once.
  /// It currently assumes the PcodeOp is binary, and the slot along which the op is
  /// currently visited is passed in, along with the TransformVar for the other input. It returns
  /// true if the TransformOp should be created.
  /// \param slot is the incoming slot along which the op is visited
  /// \param rvn is the other input
  static preexistingGuard(slot: number, rvn: TransformVar): boolean {
    if (slot === 0) return true;    // If we came in on the first slot, build the TransformOp
    if (rvn.type === TransformVar.piece || rvn.type === TransformVar.piece_temp)
      return false;    // The op was/will be visited on slot 0, don't create TransformOp now
    return true;    // The op was not (will not be) visited on slot 0, build now
  }

  /// Handle some special PcodeOp marking
  /// If a PcodeOp is an INDIRECT creation, we need to do special marking of the op and Varnodes
  /// \param rop is the placeholder op with the special requirement
  private specialHandling(rop: TransformOp): void {
    if ((rop.special & TransformOp.indirect_creation) !== 0)
      this.fd.markIndirectCreation(rop.replacement, false);
    else if ((rop.special & TransformOp.indirect_creation_possible_out) !== 0)
      this.fd.markIndirectCreation(rop.replacement, true);
  }

  /// Create a new op for each placeholder.
  /// Run through the list of TransformOp placeholders and create the actual PcodeOp object.
  /// If the op has an output Varnode, create it. Make sure all the new ops are inserted in
  /// control flow.
  private createOps(): void {
    for (const op of this.newOps) {
      op.createReplacement(this.fd);
    }

    let followCount: number;
    do {
      followCount = 0;
      for (const op of this.newOps) {
        if (!op.attemptInsertion(this.fd))
          followCount += 1;
      }
    } while (followCount !== 0);
  }

  /// Create a Varnode for each placeholder.
  /// Record any input vars in the given container.
  /// \param inputList will hold any inputs
  private createVarnodes(inputList: TransformVar[]): void {
    for (const [, vArray] of this.pieceMap) {
      for (let i = 0; ; ++i) {
        const rvn: TransformVar = vArray[i];
        if (rvn.type === TransformVar.piece) {
          const vn: Varnode | null = rvn.vn;
          if (vn !== null && vn.isInput()) {
            inputList.push(rvn);
            if (vn.isMark())
              rvn.flags |= TransformVar.input_duplicate;
            else
              vn.setMark();
          }
        }
        rvn.createReplacement(this.fd);
        if ((rvn.flags & TransformVar.split_terminator) !== 0)
          break;
      }
    }
    for (const rvn of this.newVarnodes) {
      rvn.createReplacement(this.fd);
    }
  }

  /// Remove old preexisting PcodeOps and Varnodes that are now obsolete
  private removeOld(): void {
    for (const rop of this.newOps) {
      if ((rop.special & TransformOp.op_replacement) !== 0) {
        if (!rop.op!.isDead())
          this.fd.opDestroy(rop.op);    // Destroy old op (and its output Varnode)
      }
    }
  }

  /// Remove old input Varnodes, mark new input Varnodes
  /// \param inputList is the given container of input placeholders
  private transformInputVarnodes(inputList: TransformVar[]): void {
    for (let i = 0; i < inputList.length; ++i) {
      const rvn: TransformVar = inputList[i];
      if ((rvn.flags & TransformVar.input_duplicate) === 0)
        this.fd.deleteVarnode(rvn.vn);
      rvn.replacement = this.fd.setInputVarnode(rvn.replacement);
    }
  }

  /// Set input Varnodes for all new ops
  private placeInputs(): void {
    for (const rop of this.newOps) {
      const op: PcodeOp = rop.replacement!;
      for (let i = 0; i < rop.input.length; ++i) {
        const rvn: TransformVar | null = rop.input[i];
        const vn: Varnode = rvn!.replacement!;
        this.fd.opSetInput(op, vn, i);
      }
      this.specialHandling(rop);
    }
  }

  /// Apply the full transform to the function
  apply(): void {
    const inputList: TransformVar[] = [];
    this.createOps();
    this.createVarnodes(inputList);
    this.removeOld();
    this.transformInputVarnodes(inputList);
    this.placeInputs();
  }
}
