/**
 * @file op.ts
 * @description The PcodeOp and PcodeOpBank classes, translated from Ghidra's op.hh / op.cc
 *
 * PcodeOp is the lowest-level operation of the p-code language.
 * PcodeOpBank is a container for all PcodeOps associated with a single function.
 */

import type { int4, uint4, uintb, uintm } from '../core/types.js';
import { HOST_ENDIAN } from '../core/types.js';
import { Address, SeqNum, calc_mask, sign_extend, coveringmask, pcode_left, pcode_right, mostsigbit_set, leastsigbit_set, popcount, signbit_negative } from '../core/address.js';
import { AddrSpace, spacetype } from '../core/space.js';
import { OpCode, get_opname } from '../core/opcodes.js';
import { LowlevelError } from '../core/error.js';
import {
  AttributeId,
  ElementId,
  Encoder,
  Decoder,
  ATTRIB_REF,
  ATTRIB_SPACE,
  ATTRIB_NAME,
  ATTRIB_VALUE,
  ELEM_VOID,
} from '../core/marshal.js';
import { ATTRIB_CODE, ELEM_SPACEID } from '../core/translate.js';
import { ELEM_OP } from '../decompiler/prettyprint.js';
import { ELEM_ADDR } from '../decompiler/varnode.js';
import type { Writer } from '../util/writer.js';
import { SortedSet, SortedSetIterator } from '../util/sorted-set.js';
import { Varnode } from './varnode.js';

// ---------------------------------------------------------------------------
// Forward type declarations for types from modules not yet written
// ---------------------------------------------------------------------------

type TypeOp = any;         // From typeop.ts (not yet written)
type BlockBasic = any;     // From block.ts (not yet written)
type Funcdata = any;       // From funcdata.ts (not yet written)
type FlowBlock = any;      // From block.ts (not yet written)
type SymbolEntry = any;    // From database.ts (not yet written)
type Datatype = any;       // From type.ts (not yet written)
type AddrSpaceManager = any; // From translate.ts

// ---------------------------------------------------------------------------
// Marshaling element IDs specific to op.cc
// ---------------------------------------------------------------------------

export const ELEM_IOP = new ElementId("iop", 113);
export const ELEM_UNIMPL = new ElementId("unimpl", 114);

// ---------------------------------------------------------------------------
// Helper: 3-argument sign_extend (sign-extend between two byte sizes)
// ---------------------------------------------------------------------------

/**
 * Sign-extend a value from sizein bytes to sizeout bytes.
 * This is the 3-argument overload from Ghidra's address.cc.
 */
function sign_extend_size(val: bigint, sizein: number, sizeout: number): bigint {
  const si = sizein < 8 ? sizein : 8;
  const so = sizeout < 8 ? sizeout : 8;
  // Replicate C++ logic:
  //   intb sval = in;
  //   sval <<= (sizeof(intb) - sizein) * 8;
  //   uintb res = (uintb)(sval >> (sizeout - sizein) * 8);
  //   res >>= (sizeof(uintb) - sizeout)*8;
  let sval = val & 0xFFFFFFFFFFFFFFFFn;
  // Shift left to put sign bit at MSB of 64-bit
  sval = (sval << BigInt((8 - si) * 8)) & 0xFFFFFFFFFFFFFFFFn;
  // Convert to signed
  if (sval >= 0x8000000000000000n) {
    sval = sval - 0x10000000000000000n;
  }
  // Arithmetic shift right by (sizeout - sizein) * 8
  sval = sval >> BigInt((so - si) * 8);
  // Convert back to unsigned
  let res = sval & 0xFFFFFFFFFFFFFFFFn;
  // Logical shift right by (sizeof(uintb) - sizeout)*8
  res = res >> BigInt((8 - so) * 8);
  return res & 0xFFFFFFFFFFFFFFFFn;
}

// ---------------------------------------------------------------------------
// IopSpace
// ---------------------------------------------------------------------------

/**
 * Space for storing internal PcodeOp pointers as addresses.
 *
 * It is convenient and efficient to replace the formally encoded
 * branch target addresses with a pointer to the actual PcodeOp
 * being branched to. This special "iop" space allows a PcodeOp
 * pointer to be encoded as an address so it can be stored as
 * part of an input varnode, in place of the target address, in
 * a branching operation. The pointer is encoded as an offset
 * within the fspec space.
 */
export class IopSpace extends AddrSpace {
  static readonly NAME = "iop";

  constructor(m: AddrSpaceManager, t: any, ind: int4) {
    super(
      m, t,
      spacetype.IPTR_IOP,
      IopSpace.NAME,
      false,
      8,    // sizeof(void *) - pointer size
      1,    // wordsize
      ind,
      0,    // fl
      1,    // dl
      1     // dead
    );
    this.clearFlags(AddrSpace.heritaged | AddrSpace.does_deadcode | AddrSpace.big_endian);
    if ((HOST_ENDIAN as number) === 1) {
      this.setFlags(AddrSpace.big_endian);
    }
  }

  override encodeAttributes(encoder: Encoder, _offset: uintb, _size?: int4): void {
    encoder.writeString(ATTRIB_SPACE, "iop");
  }

  override printRaw(offset: uintb): string {
    // Resolve the PcodeOp from the registry (mirrors C++ pointer cast)
    const op = PcodeOp.getOpFromConst(new Address(this, offset));
    if (op === null) {
      return `iop_${offset.toString(16)}`;
    }

    if (!op.isBranch()) {
      // For CPUI_INDIRECT: print the indirecting op's SeqNum
      return op.getSeqNum().toString();
    }

    // For branch targets: print the target block's start address
    const bs = op.getParent();
    if (bs === null) {
      return `iop_${offset.toString(16)}`;
    }
    let bl: any;
    if (bs.sizeOut() === 2) {
      bl = op.isFallthruTrue() ? bs.getOut(0) : bs.getOut(1);
    } else {
      bl = bs.getOut(0);
    }
    if (bl === null) {
      return `iop_${offset.toString(16)}`;
    }
    const startAddr: Address = bl.getStart();
    return `code_${startAddr.getShortcut()}${startAddr.printRaw()}`;
  }

  override decode(_decoder: Decoder): void {
    throw new LowlevelError("Should never decode iop space from stream");
  }
}

// ---------------------------------------------------------------------------
// PcodeOp flag constants (primary flags)
// ---------------------------------------------------------------------------

export const OP_startbasic         = 1;
export const OP_branch             = 2;
export const OP_call               = 4;
export const OP_returns            = 0x8;
export const OP_nocollapse         = 0x10;
export const OP_dead               = 0x20;
export const OP_marker             = 0x40;
export const OP_booloutput         = 0x80;
export const OP_boolean_flip       = 0x100;
export const OP_fallthru_true      = 0x200;
export const OP_indirect_source    = 0x400;
export const OP_coderef            = 0x800;
export const OP_startmark          = 0x1000;
export const OP_mark               = 0x2000;
export const OP_commutative        = 0x4000;
export const OP_unary              = 0x8000;
export const OP_binary             = 0x10000;
export const OP_special            = 0x20000;
export const OP_ternary            = 0x40000;
export const OP_return_copy        = 0x80000;
export const OP_nonprinting        = 0x100000;
export const OP_halt               = 0x200000;
export const OP_badinstruction     = 0x400000;
export const OP_unimplemented      = 0x800000;
export const OP_noreturn           = 0x1000000;
export const OP_missing            = 0x2000000;
export const OP_spacebase_ptr      = 0x4000000;
export const OP_indirect_creation  = 0x8000000;
export const OP_calculated_bool    = 0x10000000;
export const OP_has_callspec       = 0x20000000;
export const OP_ptrflow            = 0x40000000;
export const OP_indirect_store     = 0x80000000;

// ---------------------------------------------------------------------------
// PcodeOp additional flag constants
// ---------------------------------------------------------------------------

export const OP_special_prop           = 1;
export const OP_special_print          = 2;
export const OP_modified               = 4;
export const OP_warning                = 8;
export const OP_incidental_copy        = 0x10;
export const OP_is_cpool_transformed   = 0x20;
export const OP_stop_type_propagation  = 0x40;
export const OP_hold_output            = 0x80;
export const OP_concat_root            = 0x100;
export const OP_no_indirect_collapse   = 0x200;
export const OP_store_unmapped         = 0x400;

// ---------------------------------------------------------------------------
// PcodeOp class
// ---------------------------------------------------------------------------

/**
 * Lowest level operation of the p-code language.
 *
 * The philosophy here is to have only one version of any type of operation,
 * and to be completely explicit about all effects.
 * All operations except the control flow operations have exactly one
 * explicit output. Any given operation can have multiple inputs, but all
 * are listed explicitly.
 */
export class PcodeOp {
  // Static flag aliases (mirrors C++ PcodeOp::startbasic, etc.)
  static readonly startbasic         = OP_startbasic;
  static readonly branch             = OP_branch;
  static readonly call               = OP_call;
  static readonly returns            = OP_returns;
  static readonly nocollapse         = OP_nocollapse;
  static readonly dead               = OP_dead;
  static readonly marker             = OP_marker;
  static readonly booloutput         = OP_booloutput;
  static readonly boolean_flip       = OP_boolean_flip;
  static readonly fallthru_true      = OP_fallthru_true;
  static readonly indirect_source    = OP_indirect_source;
  static readonly coderef            = OP_coderef;
  static readonly startmark          = OP_startmark;
  static readonly mark               = OP_mark;
  static readonly commutative        = OP_commutative;
  static readonly unary              = OP_unary;
  static readonly binary             = OP_binary;
  static readonly special            = OP_special;
  static readonly ternary            = OP_ternary;
  static readonly return_copy        = OP_return_copy;
  static readonly nonprinting        = OP_nonprinting;
  static readonly halt               = OP_halt;
  static readonly badinstruction     = OP_badinstruction;
  static readonly unimplemented      = OP_unimplemented;
  static readonly noreturn           = OP_noreturn;
  static readonly missing            = OP_missing;
  static readonly spacebase_ptr      = OP_spacebase_ptr;
  static readonly indirect_creation  = OP_indirect_creation;
  static readonly calculated_bool    = OP_calculated_bool;
  static readonly has_callspec       = OP_has_callspec;
  static readonly ptrflow            = OP_ptrflow;
  static readonly indirect_store     = OP_indirect_store;

  // Additional flag aliases
  static readonly special_prop           = OP_special_prop;
  static readonly special_print          = OP_special_print;
  static readonly modified               = OP_modified;
  static readonly warning                = OP_warning;
  static readonly incidental_copy        = OP_incidental_copy;
  static readonly is_cpool_transformed   = OP_is_cpool_transformed;
  static readonly stop_type_propagation  = OP_stop_type_propagation;
  static readonly hold_output            = OP_hold_output;
  static readonly concat_root            = OP_concat_root;
  static readonly no_indirect_collapse   = OP_no_indirect_collapse;
  static readonly store_unmapped         = OP_store_unmapped;

  // ---- Fields (public for friend class access) ----

  /** @internal Pointer to class providing behavioral details of the operation */
  public opcode: TypeOp | null;
  /** @internal Collection of boolean attributes on this op */
  public flags: number;
  /** @internal Additional boolean attributes for this op */
  public addlflags: number;
  /** @internal What instruction address is this attached to */
  public start: SeqNum;
  /** @internal Basic block in which this op is contained */
  public parent: BlockBasic | null;
  /** @internal Index within basic block's op list */
  public basiciter: number;
  /** @internal Position in alive/dead list */
  public insertiter: number;
  /** @internal Position in opcode list */
  public codeiter: number;
  /** @internal The one possible output Varnode of this op */
  public output: Varnode | null;
  /** @internal The ordered list of input Varnodes for this op */
  public inrefs: (Varnode | null)[];

  /**
   * Construct an unattached PcodeOp.
   * @param s indicates the number of input slots reserved
   * @param sq is the sequence number to associate with the new PcodeOp
   */
  constructor(s: number, sq: SeqNum) {
    this.start = sq;
    this.flags = 0;
    this.addlflags = 0;
    this.parent = null;
    this.output = null;
    this.opcode = null;
    this.basiciter = -1;
    this.insertiter = -1;
    this.codeiter = -1;
    this.inrefs = new Array<Varnode | null>(s);
    for (let i = 0; i < s; ++i) {
      this.inrefs[i] = null;
    }
  }

  // ---- Methods used by friend classes (Funcdata, BlockBasic, etc.) ----

  /** @internal Set the opcode for this PcodeOp */
  setOpcode(t_op: TypeOp): void {
    this.flags &= ~(PcodeOp.branch | PcodeOp.call | PcodeOp.coderef | PcodeOp.commutative |
      PcodeOp.returns | PcodeOp.nocollapse | PcodeOp.marker | PcodeOp.booloutput |
      PcodeOp.unary | PcodeOp.binary | PcodeOp.ternary | PcodeOp.special |
      PcodeOp.has_callspec | PcodeOp.return_copy);
    this.opcode = t_op;
    this.flags |= t_op.getFlags();
  }

  /** @internal Set the output Varnode of this op */
  setOutput(vn: Varnode | null): void { this.output = vn; }

  /** @internal Clear a specific input Varnode to null */
  clearInput(slot: number): void { this.inrefs[slot] = null; }

  /** @internal Set a specific input Varnode */
  setInput(vn: Varnode | null, slot: number): void { this.inrefs[slot] = vn; }

  /** @internal Set specific boolean attribute(s) on this op */
  setFlag(fl: number): void { this.flags |= fl; }

  /** @internal Clear specific boolean attribute(s) */
  clearFlag(fl: number): void { this.flags &= ~fl; }

  /** @internal Set specific boolean additional attribute */
  setAdditionalFlag(fl: number): void { this.addlflags |= fl; }

  /** @internal Clear specific boolean additional attribute */
  clearAdditionalFlag(fl: number): void { this.addlflags &= ~fl; }

  /** @internal Flip the setting of specific boolean attribute(s) */
  flipFlag(fl: number): void { this.flags ^= fl; }

  /** @internal Make sure this op has num inputs */
  setNumInputs(num: number): void {
    this.inrefs.length = num;
    for (let i = 0; i < num; ++i) {
      this.inrefs[i] = null;
    }
  }

  /** @internal Eliminate a specific input Varnode */
  removeInput(slot: number): void {
    for (let i = slot + 1; i < this.inrefs.length; ++i) {
      this.inrefs[i - 1] = this.inrefs[i];
    }
    this.inrefs.pop();
  }

  /** @internal Make room for a new input Varnode at a specific position */
  insertInput(slot: number): void {
    this.inrefs.push(null);
    for (let i = this.inrefs.length - 1; i > slot; --i) {
      this.inrefs[i] = this.inrefs[i - 1];
    }
    this.inrefs[slot] = null;
  }

  /** @internal Order this op within the ops for a single instruction */
  setOrder(ord: number): void { this.start.setOrder(ord); }

  /** @internal Set the parent basic block of this op */
  setParent(p: BlockBasic): void { this.parent = p; }

  /** @internal Store the iterator index into this op's basic block */
  setBasicIter(iter: number): void { this.basiciter = iter; }

  // ---- Public query methods ----

  /** Get the number of inputs to this op */
  numInput(): number { return this.inrefs.length; }

  /** Get the output Varnode of this op or null */
  getOut(): Varnode | null { return this.output; }

  /** Get a specific input Varnode to this op */
  getIn(slot: number): Varnode | null { return this.inrefs[slot]; }

  /** Get the parent basic block */
  getParent(): BlockBasic | null { return this.parent; }

  /** Get the instruction address associated with this op */
  getAddr(): Address { return this.start.getAddr(); }

  /** Get the time index indicating when this op was created */
  getTime(): number { return this.start.getTime(); }

  /** Get the sequence number associated with this op */
  getSeqNum(): SeqNum { return this.start; }

  /** Get position within alive/dead list */
  getInsertIter(): number { return this.insertiter; }

  /** Get position within basic block */
  getBasicIter(): number { return this.basiciter; }

  /** Get the slot number of the indicated input varnode */
  getSlot(vn: Varnode | null): number {
    const n = this.inrefs.length;
    for (let i = 0; i < n; ++i) {
      if (this.inrefs[i] === vn) return i;
    }
    return n;
  }

  /**
   * Find the slot for a given Varnode, which may take up multiple input slots.
   *
   * In the rare case that this PcodeOp takes the same Varnode as input multiple times,
   * use the specific descendant iterator index producing this PcodeOp to work out the
   * corresponding slot.
   */
  getRepeatSlot(vn: Varnode, firstSlot: number, iterIdx: number): number {
    let count = 1;
    for (let oi = 0; oi < iterIdx; ++oi) {
      if (vn.descend[oi] === this) {
        count += 1;
      }
    }
    if (count === 1) return firstSlot;
    let recount = 1;
    for (let i = firstSlot + 1; i < this.inrefs.length; ++i) {
      if (this.inrefs[i] === vn) {
        recount += 1;
        if (recount === count) return i;
      }
    }
    return -1;
  }

  /** Get the evaluation type of this op */
  getEvalType(): number {
    return (this.flags & (PcodeOp.unary | PcodeOp.binary | PcodeOp.special | PcodeOp.ternary));
  }

  /** Get type which indicates unusual halt in control-flow */
  getHaltType(): number {
    return (this.flags & (PcodeOp.halt | PcodeOp.badinstruction | PcodeOp.unimplemented |
      PcodeOp.noreturn | PcodeOp.missing));
  }

  /** Return true if this op is dead */
  isDead(): boolean { return (this.flags & PcodeOp.dead) !== 0; }

  /** Return true if this op has an output */
  isAssignment(): boolean { return this.output !== null; }

  /** Return true if this op indicates call semantics */
  isCall(): boolean { return (this.flags & PcodeOp.call) !== 0; }

  /** Return true if this op acts as call but does not have a full specification */
  isCallWithoutSpec(): boolean {
    return (this.flags & (PcodeOp.call | PcodeOp.has_callspec)) === PcodeOp.call;
  }

  /** Return true if a special SSA form op */
  isMarker(): boolean { return (this.flags & PcodeOp.marker) !== 0; }

  /** Return true if op creates a varnode indirectly */
  isIndirectCreation(): boolean { return (this.flags & PcodeOp.indirect_creation) !== 0; }

  /** Return true if this INDIRECT is caused by STORE */
  isIndirectStore(): boolean { return (this.flags & PcodeOp.indirect_store) !== 0; }

  /** Return true if this op is not directly represented in C output */
  notPrinted(): boolean {
    return (this.flags & (PcodeOp.marker | PcodeOp.nonprinting | PcodeOp.noreturn)) !== 0;
  }

  /** Return true if this op produces a boolean output */
  isBoolOutput(): boolean { return (this.flags & PcodeOp.booloutput) !== 0; }

  /** Return true if this op is a branch */
  isBranch(): boolean { return (this.flags & PcodeOp.branch) !== 0; }

  /** Return true if this op is a call or branch */
  isCallOrBranch(): boolean { return (this.flags & (PcodeOp.branch | PcodeOp.call)) !== 0; }

  /** Return true if this op breaks fall-thru flow */
  isFlowBreak(): boolean { return (this.flags & (PcodeOp.branch | PcodeOp.returns)) !== 0; }

  /** Return true if this op flips the true/false meaning of its control-flow branching */
  isBooleanFlip(): boolean { return (this.flags & PcodeOp.boolean_flip) !== 0; }

  /** Return true if the fall-thru branch is taken when the boolean input is true */
  isFallthruTrue(): boolean { return (this.flags & PcodeOp.fallthru_true) !== 0; }

  /** Return true if the first input is a code reference */
  isCodeRef(): boolean { return (this.flags & PcodeOp.coderef) !== 0; }

  /** Return true if this starts an instruction */
  isInstructionStart(): boolean { return (this.flags & PcodeOp.startmark) !== 0; }

  /** Return true if this starts a basic block */
  isBlockStart(): boolean { return (this.flags & PcodeOp.startbasic) !== 0; }

  /** Return true if this is modified by the current action */
  isModified(): boolean { return (this.addlflags & PcodeOp.modified) !== 0; }

  /** Return true if this op has been marked */
  isMark(): boolean { return (this.flags & PcodeOp.mark) !== 0; }

  /** Set the mark on this op */
  setMark(): void { this.flags |= PcodeOp.mark; }

  /** Return true if a warning has been generated for this op */
  isWarning(): boolean { return (this.addlflags & PcodeOp.warning) !== 0; }

  /** Clear any mark on this op */
  clearMark(): void { this.flags &= ~PcodeOp.mark; }

  /** Return true if this causes an INDIRECT */
  isIndirectSource(): boolean { return (this.flags & PcodeOp.indirect_source) !== 0; }

  /** Mark this op as source of INDIRECT */
  setIndirectSource(): void { this.flags |= PcodeOp.indirect_source; }

  /** Clear INDIRECT source flag */
  clearIndirectSource(): void { this.flags &= ~PcodeOp.indirect_source; }

  /** Return true if this produces/consumes ptrs */
  isPtrFlow(): boolean { return (this.flags & PcodeOp.ptrflow) !== 0; }

  /** Mark this op as consuming/producing ptrs */
  setPtrFlow(): void { this.flags |= PcodeOp.ptrflow; }

  /** Return true if this does datatype propagation */
  doesSpecialPropagation(): boolean { return (this.addlflags & PcodeOp.special_prop) !== 0; }

  /** Return true if this needs special printing */
  doesSpecialPrinting(): boolean { return (this.addlflags & PcodeOp.special_print) !== 0; }

  /** Return true if this COPY is incidental */
  isIncidentalCopy(): boolean { return (this.addlflags & PcodeOp.incidental_copy) !== 0; }

  /** Return true if output is 1-bit boolean */
  isCalculatedBool(): boolean {
    return (this.flags & (PcodeOp.calculated_bool | PcodeOp.booloutput)) !== 0;
  }

  /** Return true if we have already examined this cpool */
  isCpoolTransformed(): boolean { return (this.addlflags & PcodeOp.is_cpool_transformed) !== 0; }

  /** Return true if this can be collapsed to a COPY of a constant */
  isCollapsible(): boolean {
    if ((this.flags & PcodeOp.nocollapse) !== 0) return false;
    if (!this.isAssignment()) return false;
    if (this.inrefs.length === 0) return false;
    for (let i = 0; i < this.inrefs.length; ++i) {
      if (!this.getIn(i)!.isConstant()) return false;
    }
    if (this.getOut()!.getSize() > 8) return false;  // sizeof(uintb) = 8
    return true;
  }

  /** Is data-type propagation from below stopped */
  stopsTypePropagation(): boolean { return (this.addlflags & PcodeOp.stop_type_propagation) !== 0; }

  /** Stop data-type propagation from below */
  setStopTypePropagation(): void { this.addlflags |= PcodeOp.stop_type_propagation; }

  /** Allow data-type propagation from below */
  clearStopTypePropagation(): void { this.addlflags &= ~PcodeOp.stop_type_propagation; }

  /** If true, do not remove output as dead code */
  holdOutput(): boolean { return (this.addlflags & PcodeOp.hold_output) !== 0; }

  /** Prevent output from being removed as dead code */
  setHoldOutput(): void { this.addlflags |= PcodeOp.hold_output; }

  /** Output is root of CONCAT tree */
  isPartialRoot(): boolean { return (this.addlflags & PcodeOp.concat_root) !== 0; }

  /** Mark this as root of CONCAT tree */
  setPartialRoot(): void { this.addlflags |= PcodeOp.concat_root; }

  /** Is this a return form COPY */
  isReturnCopy(): boolean { return (this.flags & PcodeOp.return_copy) !== 0; }

  /** Check if INDIRECT collapse is possible */
  noIndirectCollapse(): boolean { return (this.addlflags & PcodeOp.no_indirect_collapse) !== 0; }

  /** Prevent collapse of INDIRECT */
  setNoIndirectCollapse(): void { this.addlflags |= PcodeOp.no_indirect_collapse; }

  /** Is STORE location supposed to be unmapped */
  isStoreUnmapped(): boolean { return (this.addlflags & PcodeOp.store_unmapped) !== 0; }

  /** Mark that STORE location should be unmapped */
  setStoreUnmapped(): void { this.addlflags |= PcodeOp.store_unmapped; }

  /** Return true if this LOADs or STOREs from a dynamic spacebase pointer */
  usesSpacebasePtr(): boolean { return (this.flags & PcodeOp.spacebase_ptr) !== 0; }

  /**
   * Return hash indicating possibility of common subexpression elimination.
   * @returns the calculated hash or 0 if the op is not cse hashable
   */
  getCseHash(): number {
    if ((this.getEvalType() & (PcodeOp.unary | PcodeOp.binary)) === 0) return 0;
    if (this.code() === OpCode.CPUI_COPY) return 0;

    let hash = (this.output!.getSize() << 8) | this.code();
    for (let i = 0; i < this.inrefs.length; ++i) {
      const vn = this.getIn(i)!;
      hash = ((hash << 8) | (hash >>> 24)) & 0xFFFFFFFF;
      if (vn.isConstant()) {
        const off = vn.getOffset();
        hash ^= Number(typeof off === 'bigint' ? (off & 0xFFFFFFFFn) : (off & 0xFFFFFFFF));
      } else {
        hash ^= vn.getCreateIndex();
      }
    }
    return hash >>> 0;
  }

  /**
   * Return true if this and op represent common subexpressions.
   * This is the full test of matching indicated by getCseHash.
   */
  isCseMatch(op: PcodeOp): boolean {
    if ((this.getEvalType() & (PcodeOp.unary | PcodeOp.binary)) === 0) return false;
    if ((op.getEvalType() & (PcodeOp.unary | PcodeOp.binary)) === 0) return false;
    if (this.output!.getSize() !== op.output!.getSize()) return false;
    if (this.code() !== op.code()) return false;
    if (this.code() === OpCode.CPUI_COPY) return false;
    if (this.inrefs.length !== op.inrefs.length) return false;
    for (let i = 0; i < this.inrefs.length; ++i) {
      const vn1 = this.getIn(i)!;
      const vn2 = op.getIn(i)!;
      if (vn1 === vn2) continue;
      if (vn1.isConstant() && vn2.isConstant() && (vn1.getOffset() === vn2.getOffset()))
        continue;
      return false;
    }
    return true;
  }

  /**
   * Can this be moved to after point, without disturbing data-flow.
   * This currently only tests for movement within a basic block.
   */
  isMoveable(point: PcodeOp): boolean {
    if (this === point) return true;
    let movingLoad = false;
    if (this.getEvalType() === PcodeOp.special) {
      if (this.code() === OpCode.CPUI_LOAD)
        movingLoad = true;
      else
        return false;
    }
    if (this.parent !== point.parent) return false;
    if (this.output !== null) {
      // Output cannot be moved past an op that reads it
      for (let idx = this.output.beginDescend(); idx < this.output.endDescend(); ++idx) {
        const readOp: PcodeOp = this.output.descend[idx];
        if (readOp.parent !== this.parent) continue;
        if (readOp.start.getOrder() <= point.start.getOrder())
          return false;
      }
    }
    // Only allow this op to be moved across a CALL in very restrictive circumstances
    let crossCalls = false;
    if (this.getEvalType() !== PcodeOp.special) {
      if (this.output !== null && !this.output.isAddrTied() && !this.output.isPersist()) {
        let i: number;
        for (i = 0; i < this.numInput(); ++i) {
          const vn = this.getIn(i)!;
          if (vn.isAddrTied() || vn.isPersist())
            break;
        }
        if (i === this.numInput())
          crossCalls = true;
      }
    }
    const tiedList: Varnode[] = [];
    for (let i = 0; i < this.numInput(); ++i) {
      const vn = this.getIn(i)!;
      if (vn.isAddrTied())
        tiedList.push(vn);
    }
    // Walk from this op to point in the basic block
    const opList: PcodeOp[] = this.parent.getOpList();
    let biterIdx = this.basiciter;
    do {
      ++biterIdx;
      const op = opList[biterIdx];
      if (op.getEvalType() === PcodeOp.special) {
        switch (op.code()) {
          case OpCode.CPUI_LOAD:
            if (this.output !== null) {
              if (this.output.isAddrTied()) return false;
            }
            break;
          case OpCode.CPUI_STORE:
            if (movingLoad)
              return false;
            else {
              if (tiedList.length !== 0) return false;
              if (this.output !== null) {
                if (this.output.isAddrTied()) return false;
              }
            }
            break;
          case OpCode.CPUI_INDIRECT:
          case OpCode.CPUI_SEGMENTOP:
          case OpCode.CPUI_CPOOLREF:
            break;
          case OpCode.CPUI_CALL:
          case OpCode.CPUI_CALLIND:
          case OpCode.CPUI_NEW:
            if (!crossCalls) return false;
            break;
          default:
            return false;
        }
      }
      if (op.output !== null) {
        if (movingLoad) {
          if (op.output.isAddrTied()) return false;
        }
        for (let i = 0; i < tiedList.length; ++i) {
          const vn = tiedList[i];
          if (vn.overlapVarnode(op.output) >= 0)
            return false;
          if (op.output.overlapVarnode(vn) >= 0)
            return false;
        }
      }
    } while (biterIdx !== point.basiciter);
    return true;
  }

  /** Get the opcode for this op */
  getOpcode(): TypeOp { return this.opcode; }

  /** Get the opcode id (enum) for this op */
  code(): OpCode { return this.opcode!.getOpcode(); }

  /** Return true if inputs commute */
  isCommutative(): boolean { return (this.flags & PcodeOp.commutative) !== 0; }

  /**
   * Calculate the constant output produced by this op.
   * Assuming all the inputs to this op are constants, compute the constant result.
   * @returns [result, markedInput]
   */
  collapse(): { result: bigint; markedInput: boolean } {
    let markedInput = false;
    const vn0 = this.getIn(0)!;
    if (vn0.getSymbolEntry() !== null) {
      markedInput = true;
    }
    switch (this.getEvalType()) {
      case PcodeOp.unary:
        return {
          result: this.opcode!.evaluateUnary(this.output!.getSize(), vn0.getSize(), vn0.getOffset()),
          markedInput
        };
      case PcodeOp.binary: {
        const vn1 = this.getIn(1)!;
        if (vn1.getSymbolEntry() !== null) {
          markedInput = true;
        }
        return {
          result: this.opcode!.evaluateBinary(this.output!.getSize(), vn0.getSize(),
            vn0.getOffset(), vn1.getOffset()),
          markedInput
        };
      }
      default:
        break;
    }
    throw new LowlevelError("Invalid constant collapse");
  }

  /**
   * Execute this operation on the given input values.
   * @returns [result, evalError]
   */
  executeSimple(inValues: bigint[]): { result: bigint; evalError: boolean } {
    const evalType = this.getEvalType();
    let res: bigint;
    try {
      if (evalType === PcodeOp.unary)
        res = this.opcode!.evaluateUnary(this.output!.getSize(), this.inrefs[0]!.getSize(), inValues[0]);
      else if (evalType === PcodeOp.binary)
        res = this.opcode!.evaluateBinary(this.output!.getSize(), this.inrefs[0]!.getSize(), inValues[0], inValues[1]);
      else if (evalType === PcodeOp.ternary)
        res = this.opcode!.evaluateTernary(this.output!.getSize(), this.inrefs[0]!.getSize(), inValues[0], inValues[1], inValues[2]);
      else
        throw new LowlevelError("Cannot perform simple execution of " + get_opname(this.code()));
    } catch (err) {
      if (err instanceof LowlevelError) throw err;
      // EvaluationError equivalent
      return { result: 0n, evalError: true };
    }
    return { result: res, evalError: false };
  }

  /**
   * Propagate constant symbol from inputs to given output.
   * Knowing that this PcodeOp has collapsed its constant inputs, one of which has
   * symbol content, figure out if the symbol should propagate to the new given output constant.
   */
  collapseConstantSymbol(newConst: Varnode): void {
    let copyVn: Varnode | null = null;
    switch (this.code()) {
      case OpCode.CPUI_SUBPIECE:
        if (this.getIn(1)!.getOffset() !== 0n)
          return;
        copyVn = this.getIn(0)!;
        break;
      case OpCode.CPUI_COPY:
      case OpCode.CPUI_INT_ZEXT:
      case OpCode.CPUI_INT_NEGATE:
      case OpCode.CPUI_INT_2COMP:
        copyVn = this.getIn(0)!;
        break;
      case OpCode.CPUI_INT_LEFT:
      case OpCode.CPUI_INT_RIGHT:
      case OpCode.CPUI_INT_SRIGHT:
        copyVn = this.getIn(0)!;
        break;
      case OpCode.CPUI_INT_ADD:
      case OpCode.CPUI_INT_MULT:
      case OpCode.CPUI_INT_AND:
      case OpCode.CPUI_INT_OR:
      case OpCode.CPUI_INT_XOR:
        copyVn = this.getIn(0)!;
        if (copyVn.getSymbolEntry() === null) {
          copyVn = this.getIn(1)!;
        }
        break;
      default:
        return;
    }
    if (copyVn.getSymbolEntry() === null)
      return;
    newConst.copySymbolIfValid(copyVn);
  }

  /**
   * Return the next op in the control-flow from this or null.
   * This is usually in the same basic block, but this routine will follow flow
   * into successive blocks during its search, so long as there is only one path.
   */
  nextOp(): PcodeOp | null {
    let p: BlockBasic = this.parent;
    let opList: PcodeOp[] = p.getOpList();
    let idx = this.basiciter + 1;

    while (idx >= opList.length) {
      if ((p.sizeOut() !== 1) && (p.sizeOut() !== 2)) return null;
      p = p.getOut(0);
      opList = p.getOpList();
      idx = 0;
    }
    return opList[idx];
  }

  /**
   * Return the previous op within this op's basic block or null.
   */
  previousOp(): PcodeOp | null {
    if (this.basiciter === 0) return null;
    const opList: PcodeOp[] = this.parent.getOpList();
    return opList[this.basiciter - 1];
  }

  /**
   * Return starting op for instruction associated with this op.
   * Scan backward within the basic block containing this op and find the first op
   * marked as the start of an instruction.
   */
  target(): PcodeOp {
    if (this.isDead()) {
      // When dead, iterate backwards in insert (dead) list context
      // Since we don't have direct list iteration in TS, we rely on the
      // fact that the deadlist is an array and insertiter is an index.
      // This will be called by PcodeOpBank which has access to the dead list.
      // For now, return this as a fallback (it gets overridden by PcodeOpBank.target).
      return this;
    }
    const opList: PcodeOp[] = this.parent.getOpList();
    let idx = this.basiciter;
    let retop = opList[idx];
    while ((retop.flags & PcodeOp.startmark) === 0) {
      --idx;
      retop = opList[idx];
    }
    return retop;
  }

  /**
   * Print debug description of this op to a Writer.
   */
  printDebug(s: Writer): void {
    s.write(this.start.toString());
    s.write(": ");
    if (this.isDead() || (this.parent === null))
      s.write("**");
    else
      this.printRaw(s);
  }

  /** Print raw info about this op to a Writer */
  printRaw(s: Writer): void { this.opcode!.printRaw(s, this); }

  /** Return the name of this op */
  getOpName(): string { return this.opcode!.getName(); }

  /**
   * Encode a description of this op to stream.
   */
  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_OP);
    encoder.writeSignedInteger(ATTRIB_CODE, this.code());
    // SeqNum encode: write the address attributes and uniq
    this.start.getAddr().getSpace()!.encodeAttributes(encoder, this.start.getAddr().getOffset());
    // Write uniq as ATTRIB_UNIQ (we use the approach from SeqNum.encode in C++)
    // Since SeqNum.encode is not on the TS class, we do it inline:
    // The C++ encodes: ELEM_SEQNUM { space attrs, ATTRIB_UNIQ }
    // But in PcodeOp.encode, it calls start.encode(encoder), which wraps in ELEM_SEQNUM.
    // For simplicity, we encode the SeqNum fields directly as the C++ does.
    // Actually, looking at the C++ code for PcodeOp::encode: it calls start.encode(encoder)
    // which opens ELEM_SEQNUM. Let's emulate that.
    const ELEM_SEQNUM = new ElementId("seqnum", 12);
    const ATTRIB_UNIQ = new AttributeId("uniq", 46);
    encoder.openElement(ELEM_SEQNUM);
    this.start.getAddr().getSpace()!.encodeAttributes(encoder, this.start.getAddr().getOffset());
    encoder.writeUnsignedInteger(ATTRIB_UNIQ, BigInt(this.start.getTime()));
    encoder.closeElement(ELEM_SEQNUM);

    if (this.output === null) {
      encoder.openElement(ELEM_VOID);
      encoder.closeElement(ELEM_VOID);
    } else {
      encoder.openElement(ELEM_ADDR);
      encoder.writeUnsignedInteger(ATTRIB_REF, BigInt(this.output.getCreateIndex()));
      encoder.closeElement(ELEM_ADDR);
    }

    for (let i = 0; i < this.inrefs.length; ++i) {
      const vn = this.getIn(i);
      if (vn === null) {
        encoder.openElement(ELEM_VOID);
        encoder.closeElement(ELEM_VOID);
      } else if (vn.getSpace()!.getType() === spacetype.IPTR_IOP) {
        if ((i === 1) && (this.code() === OpCode.CPUI_INDIRECT)) {
          const indop = PcodeOp.getOpFromConst(vn.getAddr());
          encoder.openElement(ELEM_IOP);
          if (indop !== null) {
            encoder.writeUnsignedInteger(ATTRIB_VALUE, BigInt(indop.getSeqNum().getTime()));
          } else {
            encoder.writeUnsignedInteger(ATTRIB_VALUE, vn.getOffset());
          }
          encoder.closeElement(ELEM_IOP);
        } else {
          encoder.openElement(ELEM_VOID);
          encoder.closeElement(ELEM_VOID);
        }
      } else if (vn.getSpace()!.getType() === spacetype.IPTR_CONSTANT) {
        if ((i === 0) && ((this.code() === OpCode.CPUI_STORE) || (this.code() === OpCode.CPUI_LOAD))) {
          const spc = vn.getSpaceFromConst()!;
          encoder.openElement(ELEM_SPACEID);
          encoder.writeSpace(ATTRIB_NAME, spc);
          encoder.closeElement(ELEM_SPACEID);
        } else {
          encoder.openElement(ELEM_ADDR);
          encoder.writeUnsignedInteger(ATTRIB_REF, BigInt(vn.getCreateIndex()));
          encoder.closeElement(ELEM_ADDR);
        }
      } else {
        encoder.openElement(ELEM_ADDR);
        encoder.writeUnsignedInteger(ATTRIB_REF, BigInt(vn.getCreateIndex()));
        encoder.closeElement(ELEM_ADDR);
      }
    }
    encoder.closeElement(ELEM_OP);
  }

  /**
   * Retrieve the PcodeOp encoded as the address addr.
   *
   * In C++ this casts an integer (the address offset) to a PcodeOp pointer.
   * In TypeScript we cannot do that. This uses a static registry map.
   * Callers should register PcodeOps via PcodeOp.registerOpConst().
   */
  static getOpFromConst(addr: Address): PcodeOp | null {
    const key = Number(addr.getOffset() & 0xFFFFFFFFn);
    return PcodeOp._opRegistry.get(key) ?? null;
  }

  /** Register a PcodeOp in the const-address registry (for IOP encoding) */
  static registerOpConst(op: PcodeOp, id: number): void {
    PcodeOp._opRegistry.set(id, op);
  }

  /** Clear the const-address registry */
  static clearOpRegistry(): void {
    PcodeOp._opRegistry.clear();
  }

  /** @internal Map from integer id to PcodeOp for getOpFromConst */
  private static _opRegistry: Map<number, PcodeOp> = new Map();

  /** Calculate the local output type */
  outputTypeLocal(): Datatype { return this.opcode!.getOutputLocal(this); }

  /** Calculate the local input type */
  inputTypeLocal(slot: number): Datatype { return this.opcode!.getInputLocal(this, slot); }

  /**
   * Calculate known zero bits for output to this op.
   * Compute nonzeromask assuming inputs to op have their masks properly defined.
   */
  getNZMaskLocal(cliploop: boolean): bigint {
    let sa: number, sz1: number, sz2: number, size: number;
    let resmask: bigint, val: bigint;

    size = this.output!.getSize();
    const fullmask: bigint = calc_mask(size);

    switch (this.opcode!.getOpcode()) {
      case OpCode.CPUI_INT_EQUAL:
      case OpCode.CPUI_INT_NOTEQUAL:
      case OpCode.CPUI_INT_SLESS:
      case OpCode.CPUI_INT_SLESSEQUAL:
      case OpCode.CPUI_INT_LESS:
      case OpCode.CPUI_INT_LESSEQUAL:
      case OpCode.CPUI_INT_CARRY:
      case OpCode.CPUI_INT_SCARRY:
      case OpCode.CPUI_INT_SBORROW:
      case OpCode.CPUI_BOOL_NEGATE:
      case OpCode.CPUI_BOOL_XOR:
      case OpCode.CPUI_BOOL_AND:
      case OpCode.CPUI_BOOL_OR:
      case OpCode.CPUI_FLOAT_EQUAL:
      case OpCode.CPUI_FLOAT_NOTEQUAL:
      case OpCode.CPUI_FLOAT_LESS:
      case OpCode.CPUI_FLOAT_LESSEQUAL:
      case OpCode.CPUI_FLOAT_NAN:
        resmask = 1n;
        break;
      case OpCode.CPUI_COPY:
      case OpCode.CPUI_INT_ZEXT:
        resmask = this.getIn(0)!.getNZMask();
        break;
      case OpCode.CPUI_INT_SEXT:
        resmask = sign_extend_size(this.getIn(0)!.getNZMask(), this.getIn(0)!.getSize(), size);
        break;
      case OpCode.CPUI_INT_XOR:
      case OpCode.CPUI_INT_OR:
        resmask = this.getIn(0)!.getNZMask();
        if (resmask !== fullmask)
          resmask |= this.getIn(1)!.getNZMask();
        break;
      case OpCode.CPUI_INT_AND:
        resmask = this.getIn(0)!.getNZMask();
        if (resmask !== 0n)
          resmask &= this.getIn(1)!.getNZMask();
        break;
      case OpCode.CPUI_INT_LEFT:
        if (!this.getIn(1)!.isConstant())
          resmask = fullmask;
        else {
          sa = Number(this.getIn(1)!.getOffset());
          resmask = this.getIn(0)!.getNZMask();
          resmask = pcode_left(resmask, sa) & fullmask;
        }
        break;
      case OpCode.CPUI_INT_RIGHT:
        if (!this.getIn(1)!.isConstant())
          resmask = fullmask;
        else {
          sz1 = this.getIn(0)!.getSize();
          sa = Number(this.getIn(1)!.getOffset());
          resmask = this.getIn(0)!.getNZMask();
          resmask = pcode_right(resmask, sa);
          if (sz1 > 8) {
            // sizeof(uintb) = 8
            if (sa >= 8 * sz1)
              resmask = 0n;
            else if (sa >= 8 * 8) {
              resmask = calc_mask(sz1 - 8);
              resmask >>= BigInt(sa - 8 * 8);
            } else {
              let tmp = 0xFFFFFFFFFFFFFFFFn;
              tmp <<= BigInt(8 * 8 - sa);
              resmask |= tmp;
            }
          }
        }
        break;
      case OpCode.CPUI_INT_SRIGHT:
        if ((!this.getIn(1)!.isConstant()) || (size > 8))
          resmask = fullmask;
        else {
          sa = Number(this.getIn(1)!.getOffset());
          resmask = this.getIn(0)!.getNZMask();
          if ((resmask & (fullmask ^ (fullmask >> 1n))) === 0n) {
            resmask = pcode_right(resmask, sa);
          } else {
            resmask = pcode_right(resmask, sa);
            resmask |= (fullmask >> BigInt(sa)) ^ fullmask;
          }
        }
        break;
      case OpCode.CPUI_INT_DIV:
        val = this.getIn(0)!.getNZMask();
        resmask = coveringmask(val);
        if (this.getIn(1)!.isConstant()) {
          sa = mostsigbit_set(this.getIn(1)!.getNZMask());
          if (sa !== -1)
            resmask >>= BigInt(sa);
        }
        break;
      case OpCode.CPUI_INT_REM:
        val = (this.getIn(1)!.getNZMask() - 1n) & 0xFFFFFFFFFFFFFFFFn;
        resmask = coveringmask(val);
        break;
      case OpCode.CPUI_POPCOUNT:
        sz1 = popcount(this.getIn(0)!.getNZMask());
        resmask = coveringmask(BigInt(sz1));
        resmask &= fullmask;
        break;
      case OpCode.CPUI_LZCOUNT:
        resmask = coveringmask(BigInt(this.getIn(0)!.getSize() * 8));
        resmask &= fullmask;
        break;
      case OpCode.CPUI_SUBPIECE:
        resmask = this.getIn(0)!.getNZMask();
        sz1 = Number(this.getIn(1)!.getOffset());
        if (this.getIn(0)!.getSize() <= 8) {
          // sizeof(uintb) = 8
          if (sz1 < 8)
            resmask >>= BigInt(8 * sz1);
          else
            resmask = 0n;
        } else {
          if (sz1 < 8) {
            resmask >>= BigInt(8 * sz1);
            if (sz1 > 0)
              resmask |= fullmask << BigInt(8 * (8 - sz1));
          } else
            resmask = fullmask;
        }
        resmask &= fullmask;
        break;
      case OpCode.CPUI_PIECE:
        sa = this.getIn(1)!.getSize();
        resmask = this.getIn(0)!.getNZMask();
        resmask = (sa < 8) ? resmask << BigInt(8 * sa) : 0n;
        resmask |= this.getIn(1)!.getNZMask();
        break;
      case OpCode.CPUI_INT_MULT:
        val = this.getIn(0)!.getNZMask();
        resmask = this.getIn(1)!.getNZMask();
        if (size > 8) {
          resmask = fullmask;
        } else {
          sz1 = mostsigbit_set(val);
          sz2 = mostsigbit_set(resmask);
          if (sz1 === -1 || sz2 === -1) {
            resmask = 0n;
          } else {
            const l1 = leastsigbit_set(val);
            const l2 = leastsigbit_set(resmask);
            sa = l1 + l2;
            if (sa >= 8 * size) {
              resmask = 0n;
            } else {
              const w1 = sz1 - l1 + 1;
              const w2 = sz2 - l2 + 1;
              let total = w1 + w2;
              if (w1 === 1 || w2 === 1)
                total -= 1;
              resmask = fullmask;
              if (total < 8 * size)
                resmask >>= BigInt(8 * size - total);
              resmask = (resmask << BigInt(sa)) & fullmask;
            }
          }
        }
        break;
      case OpCode.CPUI_INT_ADD:
        resmask = this.getIn(0)!.getNZMask();
        if (resmask !== fullmask) {
          resmask |= this.getIn(1)!.getNZMask();
          resmask |= (resmask << 1n);
          resmask &= fullmask;
        }
        break;
      case OpCode.CPUI_MULTIEQUAL:
        if (this.inrefs.length === 0)
          resmask = fullmask;
        else {
          let i = 0;
          resmask = 0n;
          if (cliploop) {
            for (; i < this.inrefs.length; ++i) {
              if (this.parent.isLoopIn(i)) continue;
              resmask |= this.getIn(i)!.getNZMask();
            }
          } else {
            for (; i < this.inrefs.length; ++i)
              resmask |= this.getIn(i)!.getNZMask();
          }
        }
        break;
      case OpCode.CPUI_CALL:
      case OpCode.CPUI_CALLIND:
      case OpCode.CPUI_CPOOLREF:
        if (this.isCalculatedBool())
          resmask = 1n;
        else
          resmask = fullmask;
        break;
      default:
        resmask = fullmask;
        break;
    }
    return resmask;
  }

  /**
   * Compare the control-flow order of this and bop.
   * @returns -1, 0, or 1
   */
  compareOrder(bop: PcodeOp): number {
    if (this.parent === bop.parent)
      return (this.start.getOrder() < bop.start.getOrder()) ? -1 : 1;

    // FlowBlock.findCommonBlock is not yet available, so use a simplified approach
    // TODO: Implement properly when block.ts is written
    const common: FlowBlock = (this.parent as any).constructor.findCommonBlock?.(this.parent, bop.parent);
    if (common === this.parent) return -1;
    if (common === bop.parent) return 1;
    return 0;
  }
}

// ---------------------------------------------------------------------------
// PieceNode class
// ---------------------------------------------------------------------------

/**
 * A node in a tree structure of CPUI_PIECE operations.
 *
 * If a group of Varnodes are concatenated into a larger structure, this object is used
 * to explicitly gather the PcodeOps (and Varnodes) in the data-flow and view them as a unit.
 */
export class PieceNode {
  private pieceOp: PcodeOp;
  private slot: number;
  private typeOffset: number;
  private leaf: boolean;

  constructor(op: PcodeOp, sl: number, off: number, l: boolean) {
    this.pieceOp = op;
    this.slot = sl;
    this.typeOffset = off;
    this.leaf = l;
  }

  /** Return true if this node is a leaf of the tree structure */
  isLeafNode(): boolean { return this.leaf; }

  /** Get the byte offset of this node into the data-type */
  getTypeOffset(): number { return this.typeOffset; }

  /** Get the input slot associated with this node */
  getSlot(): number { return this.slot; }

  /** Get the PcodeOp reading this piece */
  getOp(): PcodeOp { return this.pieceOp; }

  /** Get the Varnode representing this piece */
  getVarnode(): Varnode { return this.pieceOp.getIn(this.slot)!; }

  /**
   * Determine if a Varnode is a leaf within the CONCAT tree rooted at the given Varnode.
   */
  static isLeaf(rootVn: Varnode, vn: Varnode, relOffset: number): boolean {
    if (vn.isMapped() && rootVn.getSymbolEntry() !== vn.getSymbolEntry()) {
      return true;
    }
    if (!vn.isWritten()) return true;
    const def: PcodeOp = vn.getDef();
    if (def.code() !== OpCode.CPUI_PIECE) return true;
    const op = vn.loneDescend();
    if (op === null) return true;
    if (vn.isAddrTied()) {
      const addr = rootVn.getAddr().add(BigInt(relOffset));
      if (!vn.getAddr().equals(addr)) return true;
    }
    return false;
  }

  /**
   * Find the root of the CONCAT tree of Varnodes.
   */
  static findRoot(vn: Varnode): Varnode {
    let current: Varnode = vn;
    while (current.isProtoPartial() || current.isAddrTied()) {
      let pieceOp: PcodeOp | null = null;
      for (let idx = current.beginDescend(); idx < current.endDescend(); ++idx) {
        const op: PcodeOp = current.descend[idx];
        if (op.code() !== OpCode.CPUI_PIECE) continue;
        const sl = op.getSlot(current);
        // In C++, Address is a value type and this line creates a copy.
        // In TypeScript, getAddr() returns a reference, so we must explicitly copy
        // to avoid mutating the output varnode's address via renormalize().
        let addr = new Address(op.getOut()!.getAddr());
        if (addr.getSpace()!.isBigEndian() === (sl === 1))
          addr = addr.add(BigInt(op.getIn(1 - sl)!.getSize()));
        addr.renormalize(current.getSize());
        if (addr.equals(current.getAddr())) {
          if (pieceOp !== null) {
            if (op.compareOrder(pieceOp) < 0)
              pieceOp = op;
          } else
            pieceOp = op;
        }
      }
      if (pieceOp === null)
        break;
      current = pieceOp.getOut()!;
    }
    return current;
  }

  /**
   * Build the CONCAT tree rooted at the given Varnode.
   */
  static gatherPieces(stack: PieceNode[], rootVn: Varnode, op: PcodeOp, baseOffset: number, rootOffset: number): void {
    for (let i = 0; i < 2; ++i) {
      const vn = op.getIn(i)!;
      const offset = (rootVn.getSpace()!.isBigEndian() === (i === 1))
        ? baseOffset + op.getIn(1 - i)!.getSize()
        : baseOffset;
      const res = PieceNode.isLeaf(rootVn, vn, offset - rootOffset);
      stack.push(new PieceNode(op, i, offset, res));
      if (!res)
        PieceNode.gatherPieces(stack, rootVn, vn.getDef(), offset, rootOffset);
    }
  }
}

// ---------------------------------------------------------------------------
// PcodeOpBank
// ---------------------------------------------------------------------------

/**
 * Comparator for PcodeOps sorted by SeqNum (space index, offset, time).
 * Replaces the old string-based seqNumKey() with direct numeric comparison.
 */
export function seqNumCompare(a: PcodeOp, b: PcodeOp): number {
  const aAddr = a.getSeqNum().getAddr();
  const bAddr = b.getSeqNum().getAddr();
  const aIdx = aAddr.getSpace()?.getIndex() ?? -1;
  const bIdx = bAddr.getSpace()?.getIndex() ?? -1;
  if (aIdx !== bIdx) return aIdx - bIdx;
  const aOff = aAddr.getOffset();
  const bOff = bAddr.getOffset();
  if (aOff < bOff) return -1;
  if (aOff > bOff) return 1;
  return a.getSeqNum().getTime() - b.getSeqNum().getTime();
}

/**
 * Container class for PcodeOps associated with a single function.
 *
 * The PcodeOp objects are maintained under multiple different sorting criteria to
 * facilitate quick access in various situations. The main sort is by
 * sequence number (SeqNum) using a red-black tree (SortedSet) for O(log n) operations.
 * PcodeOps are also grouped into alive and dead lists
 * to distinguish between raw p-code ops and those that are fully linked into control-flow.
 */
export class PcodeOpBank {
  /** The main sequence number sort: SortedSet<PcodeOp> with seqNumCompare */
  private optree: SortedSet<PcodeOp> = new SortedSet<PcodeOp>(seqNumCompare);
  /** Reusable probe PcodeOp for SortedSet lookups (avoids allocation) */
  private _probe: PcodeOp = new PcodeOp(0, new SeqNum(new Address(null as any, 0n), 0));
  /** List of dead PcodeOps */
  private deadlist: PcodeOp[] = [];
  /** List of alive PcodeOps */
  private alivelist: PcodeOp[] = [];
  /** List of STORE PcodeOps */
  private storelist: PcodeOp[] = [];
  /** List of LOAD PcodeOps */
  private loadlist: PcodeOp[] = [];
  /** List of RETURN PcodeOps */
  private returnlist: PcodeOp[] = [];
  /** List of user-defined PcodeOps */
  private useroplist: PcodeOp[] = [];
  /** List of retired PcodeOps */
  private deadandgone: PcodeOp[] = [];
  /** Counter for producing unique id's for each op */
  private uniqid: number = 0;

  constructor() {
    this.uniqid = 0;
  }

  // ---- Internal methods ----

  /** Set the probe PcodeOp's SeqNum for lookups */
  private _setProbe(addr: Address, time: number): void {
    this._probe.start = new SeqNum(addr, time);
  }

  /** Set the probe PcodeOp's SeqNum from an existing SeqNum */
  private _setProbeSeqNum(sq: SeqNum): void {
    this._probe.start = sq;
  }

  /** Add given PcodeOp to specific op-code list */
  private addToCodeList(op: PcodeOp): void {
    switch (op.code()) {
      case OpCode.CPUI_STORE:
        op.codeiter = this.storelist.length;
        this.storelist.push(op);
        break;
      case OpCode.CPUI_LOAD:
        op.codeiter = this.loadlist.length;
        this.loadlist.push(op);
        break;
      case OpCode.CPUI_RETURN:
        op.codeiter = this.returnlist.length;
        this.returnlist.push(op);
        break;
      case OpCode.CPUI_CALLOTHER:
        op.codeiter = this.useroplist.length;
        this.useroplist.push(op);
        break;
      default:
        break;
    }
  }

  /** Remove given PcodeOp from specific op-code list */
  private removeFromCodeList(op: PcodeOp): void {
    switch (op.code()) {
      case OpCode.CPUI_STORE:
        this._removeFromList(this.storelist, op);
        break;
      case OpCode.CPUI_LOAD:
        this._removeFromList(this.loadlist, op);
        break;
      case OpCode.CPUI_RETURN:
        this._removeFromList(this.returnlist, op);
        break;
      case OpCode.CPUI_CALLOTHER:
        this._removeFromList(this.useroplist, op);
        break;
      default:
        break;
    }
  }

  /** Helper: remove op from a list and fix up codeiter indices */
  private _removeFromList(list: PcodeOp[], op: PcodeOp): void {
    const idx = list.indexOf(op);
    if (idx >= 0) {
      list.splice(idx, 1);
      // Fix codeiter for remaining ops
      for (let i = idx; i < list.length; ++i) {
        list[i].codeiter = i;
      }
    }
  }

  /** Clear all op-code specific lists */
  private clearCodeLists(): void {
    this.storelist.length = 0;
    this.loadlist.length = 0;
    this.returnlist.length = 0;
    this.useroplist.length = 0;
  }

  // ---- Public methods ----

  /** Clear all PcodeOps from this container */
  clear(): void {
    this.optree.clear();
    this.alivelist.length = 0;
    this.deadlist.length = 0;
    this.clearCodeLists();
    this.deadandgone.length = 0;
    this.uniqid = 0;
  }

  /** Set the unique id counter */
  setUniqId(val: number): void { this.uniqid = val; }

  /** Get the next unique id */
  getUniqId(): number { return this.uniqid; }

  /**
   * Create a PcodeOp with at a given Address.
   * A new PcodeOp is allocated with the indicated number of input slots.
   * A sequence number is assigned, and the op is added to the end of the dead list.
   */
  createFromAddr(inputs: number, pc: Address): PcodeOp {
    const op = new PcodeOp(inputs, new SeqNum(pc, this.uniqid++));
    this.optree.insert(op);
    op.setFlag(PcodeOp.dead);
    op.insertiter = this.deadlist.length;
    this.deadlist.push(op);
    return op;
  }

  /**
   * Create a PcodeOp with a given sequence number.
   * A new PcodeOp is allocated, suitable for cloning and restoring from XML.
   */
  createFromSeq(inputs: number, sq: SeqNum): PcodeOp {
    const op = new PcodeOp(inputs, sq);
    if (sq.getTime() >= this.uniqid)
      this.uniqid = sq.getTime() + 1;

    this.optree.insert(op);
    op.setFlag(PcodeOp.dead);
    op.insertiter = this.deadlist.length;
    this.deadlist.push(op);
    return op;
  }

  /**
   * Destroy/retire the given PcodeOp.
   * The given PcodeOp is removed from all internal lists and added to
   * a final deadandgone list.
   */
  destroy(op: PcodeOp): void {
    if (!op.isDead())
      throw new LowlevelError("Deleting integrated op");

    this.optree.eraseValue(op);
    this._removeFromDeadList(op);
    this.removeFromCodeList(op);
    this.deadandgone.push(op);
  }

  /** Destroy/retire all PcodeOps in the dead list */
  destroyDead(): void {
    // Copy the dead list since destroy modifies it
    const ops = [...this.deadlist];
    for (const op of ops) {
      this.destroy(op);
    }
  }

  /**
   * Change the op-code for the given PcodeOp.
   * The PcodeOp is assigned the new op-code, which may involve moving it
   * between the internal op-code specific lists.
   */
  changeOpcode(op: PcodeOp, newopc: TypeOp): void {
    if (op.opcode !== null)
      this.removeFromCodeList(op);
    op.setOpcode(newopc);
    this.addToCodeList(op);
  }

  /**
   * Mark the given PcodeOp as alive.
   * The PcodeOp is moved out of the dead list into the alive list.
   */
  markAlive(op: PcodeOp): void {
    this._removeFromDeadList(op);
    op.clearFlag(PcodeOp.dead);
    op.insertiter = this.alivelist.length;
    this.alivelist.push(op);
  }

  /**
   * Mark the given PcodeOp as dead.
   * The PcodeOp is moved out of the alive list into the dead list.
   */
  markDead(op: PcodeOp): void {
    this._removeFromAliveList(op);
    op.setFlag(PcodeOp.dead);
    op.insertiter = this.deadlist.length;
    this.deadlist.push(op);
  }

  /**
   * Insert the given PcodeOp after a point in the dead list.
   */
  insertAfterDead(op: PcodeOp, prev: PcodeOp): void {
    if (!op.isDead() || !prev.isDead())
      throw new LowlevelError("Dead move called on ops which aren't dead");
    this._removeFromDeadList(op);
    const prevIdx = prev.insertiter;
    this.deadlist.splice(prevIdx + 1, 0, op);
    this._reindexDeadList(prevIdx + 1);
  }

  /**
   * Move a sequence of PcodeOps to a point in the dead list.
   * The point is right after a provided op. All ops must be in the dead list.
   */
  moveSequenceDead(firstop: PcodeOp, lastop: PcodeOp, prev: PcodeOp): void {
    const firstIdx = firstop.insertiter;
    const lastIdx = lastop.insertiter;
    const prevIdx = prev.insertiter;
    if (prevIdx + 1 === firstIdx) return; // Degenerate move

    // Extract the sequence
    const sequence = this.deadlist.splice(firstIdx, lastIdx - firstIdx + 1);
    // Find new insertion point (prevIdx may have shifted)
    const newPrevIdx = prev.insertiter < firstIdx ? prev.insertiter : prev.insertiter - sequence.length;
    this.deadlist.splice(newPrevIdx + 1, 0, ...sequence);
    this._reindexDeadList(0);
  }

  /**
   * Mark any COPY ops in the given range as incidental.
   */
  markIncidentalCopy(firstop: PcodeOp, lastop: PcodeOp): void {
    const firstIdx = firstop.insertiter;
    const lastIdx = lastop.insertiter;
    for (let i = firstIdx; i <= lastIdx; ++i) {
      const op = this.deadlist[i];
      if (op.code() === OpCode.CPUI_COPY)
        op.setAdditionalFlag(PcodeOp.incidental_copy);
    }
  }

  /** Return true if there are no PcodeOps in this container */
  empty(): boolean { return this.optree.empty; }

  /**
   * Find the first executing PcodeOp for a target address.
   * Find the first PcodeOp at or after the given Address assuming they have not
   * yet been broken up into basic blocks. Take into account delay slots.
   */
  target(addr: Address): PcodeOp | null {
    this._setProbe(addr, 0);
    const it = this.optree.lower_bound(this._probe);
    if (it.isEnd) return null;
    return it.value.targetFromDead(this.deadlist);
  }

  /**
   * Find a PcodeOp by sequence number.
   */
  findOp(num: SeqNum): PcodeOp | null {
    this._setProbeSeqNum(num);
    const it = this.optree.find(this._probe);
    return it.isEnd ? null : it.value;
  }

  /**
   * Find the PcodeOp considered a fallthru of the given PcodeOp.
   */
  fallthru(op: PcodeOp): PcodeOp | null {
    if (op.isDead()) {
      // In this case we know an instruction is contiguous in the dead list
      const idx = op.insertiter;
      if (idx + 1 < this.deadlist.length) {
        const retop = this.deadlist[idx + 1];
        if (!retop.isInstructionStart())
          return retop;
      }
      // Find start of instruction
      let startIdx = idx;
      while (startIdx > 0 && !(this.deadlist[startIdx].flags & PcodeOp.startmark)) {
        --startIdx;
      }
      let max = op.getSeqNum();
      for (let i = startIdx; i <= idx; ++i) {
        if (max.lessThan(this.deadlist[i].getSeqNum()))
          max = this.deadlist[i].getSeqNum();
      }
      // upper_bound on max SeqNum
      this._setProbeSeqNum(max);
      const it = this.optree.upper_bound(this._probe);
      if (it.isEnd) return null;
      return it.value;
    } else {
      return op.nextOp();
    }
  }

  /** Start of all PcodeOps in sequence number order */
  beginAll(): SortedSetIterator<PcodeOp> {
    return this.optree.begin();
  }

  /** End sentinel for all PcodeOps */
  endAll(): SortedSetIterator<PcodeOp> {
    return this.optree.end();
  }

  /** Start of all PcodeOps at one Address (lower_bound) */
  beginAtAddr(addr: Address): SortedSetIterator<PcodeOp> {
    this._setProbe(addr, 0);
    return this.optree.lower_bound(this._probe);
  }

  /** End of all PcodeOps at one Address (upper_bound past max time) */
  endAtAddr(addr: Address): SortedSetIterator<PcodeOp> {
    this._setProbe(addr, 0x7FFFFFFF);
    return this.optree.upper_bound(this._probe);
  }

  /** Get the total number of ops in the optree */
  getOpTreeSize(): number { return this.optree.size; }

  /** Start of all PcodeOps marked as alive */
  beginAlive(): number { return 0; }

  /** End of all PcodeOps marked as alive */
  endAlive(): number { return this.alivelist.length; }

  /** Get alive op at index */
  getAliveOp(idx: number): PcodeOp { return this.alivelist[idx]; }

  /** Start of all PcodeOps marked as dead */
  beginDead(): number { return 0; }

  /** End of all PcodeOps marked as dead */
  endDead(): number { return this.deadlist.length; }

  /** Get dead op at index */
  getDeadOp(idx: number): PcodeOp { return this.deadlist[idx]; }

  /** Get ops sharing the given op-code */
  getCodeList(opc: OpCode): PcodeOp[] {
    switch (opc) {
      case OpCode.CPUI_STORE:
        return this.storelist;
      case OpCode.CPUI_LOAD:
        return this.loadlist;
      case OpCode.CPUI_RETURN:
        return this.returnlist;
      case OpCode.CPUI_CALLOTHER:
        return this.useroplist;
      default:
        return [];
    }
  }

  /** Get the alive list */
  getAliveList(): PcodeOp[] { return this.alivelist; }

  /**
   * Get a view of all ops in the optree, sorted by SeqNum.
   * Creates a new array by iterating the SortedSet.
   */
  getOpTreeView(): PcodeOp[] {
    return [...this.optree];
  }

  /** Get the dead list */
  getDeadList(): PcodeOp[] { return this.deadlist; }

  // ---- Private helpers ----

  /** Remove op from dead list using insertiter for O(1) lookup, O(n) splice */
  private _removeFromDeadList(op: PcodeOp): void {
    const idx = op.insertiter;
    if (idx >= 0 && idx < this.deadlist.length && this.deadlist[idx] === op) {
      this.deadlist.splice(idx, 1);
      this._reindexDeadList(idx);
    }
  }

  /** Remove op from alive list and fix indices */
  private _removeFromAliveList(op: PcodeOp): void {
    const idx = op.insertiter;
    if (idx >= 0 && idx < this.alivelist.length && this.alivelist[idx] === op) {
      this.alivelist.splice(idx, 1);
      // Fix insertiter for remaining ops
      for (let i = idx; i < this.alivelist.length; ++i) {
        this.alivelist[i].insertiter = i;
      }
    }
  }

  /** Re-index insertiter values in the dead list starting from given index */
  private _reindexDeadList(fromIdx: number = 0): void {
    for (let i = fromIdx; i < this.deadlist.length; ++i) {
      this.deadlist[i].insertiter = i;
    }
  }
}

// ---------------------------------------------------------------------------
// Extension to PcodeOp for dead-list based target scanning
// ---------------------------------------------------------------------------

// We add a method that can use an external dead list for the target() scan
// when the op is dead (not in a basic block).

declare module './op.js' {
  interface PcodeOp {
    targetFromDead(deadlist: PcodeOp[]): PcodeOp;
  }
}

PcodeOp.prototype.targetFromDead = function (this: PcodeOp, deadlist: PcodeOp[]): PcodeOp {
  let idx = this.isDead() ? this.insertiter : this.basiciter;
  const list = this.isDead() ? deadlist : this.parent.getOpList();
  let retop = list[idx];
  while ((retop.flags & PcodeOp.startmark) === 0) {
    --idx;
    retop = list[idx];
  }
  return retop;
};
