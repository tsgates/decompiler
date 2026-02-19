// =====================================================================
// double_part1.ts - PART 1 of 2
// Translated from Ghidra's double.hh and double.cc (approx lines 1-1800)
// Implements double-precision (split-varnode) analysis.
// =====================================================================

import { Address } from '../core/address.js';
import { AddrSpace } from '../core/space.js';
import { OpCode } from '../core/opcodes.js';
import { Varnode } from './varnode.js';
import { PcodeOp } from './op.js';
import { Funcdata } from './funcdata.js';
import { BlockBasicClass } from './block.js';
import { calc_mask } from '../core/address.js';
import { LowlevelError } from '../core/error.js';
import { TypeOp } from './typeop.js';
import { spacetype } from '../core/space.js';
import { Rule, ActionGroupList } from './action.js';

type BlockBasic = BlockBasicClass;
const IPTR_IOP = spacetype.IPTR_IOP;
const IPTR_INTERNAL = spacetype.IPTR_INTERNAL;

// Forward declarations for types not yet available
type FlowBlock = any;
type SymbolEntry = any;

// Re-export bare CPUI_* constants for use in part2
export const CPUI_COPY = OpCode.CPUI_COPY;
export const CPUI_LOAD = OpCode.CPUI_LOAD;
export const CPUI_STORE = OpCode.CPUI_STORE;
export const CPUI_BRANCH = OpCode.CPUI_BRANCH;
export const CPUI_CBRANCH = OpCode.CPUI_CBRANCH;
export const CPUI_BRANCHIND = OpCode.CPUI_BRANCHIND;
export const CPUI_CALL = OpCode.CPUI_CALL;
export const CPUI_CALLIND = OpCode.CPUI_CALLIND;
export const CPUI_CALLOTHER = OpCode.CPUI_CALLOTHER;
export const CPUI_RETURN = OpCode.CPUI_RETURN;
export const CPUI_INT_EQUAL = OpCode.CPUI_INT_EQUAL;
export const CPUI_INT_NOTEQUAL = OpCode.CPUI_INT_NOTEQUAL;
export const CPUI_INT_SLESS = OpCode.CPUI_INT_SLESS;
export const CPUI_INT_SLESSEQUAL = OpCode.CPUI_INT_SLESSEQUAL;
export const CPUI_INT_LESS = OpCode.CPUI_INT_LESS;
export const CPUI_INT_LESSEQUAL = OpCode.CPUI_INT_LESSEQUAL;
export const CPUI_INT_ZEXT = OpCode.CPUI_INT_ZEXT;
export const CPUI_INT_SEXT = OpCode.CPUI_INT_SEXT;
export const CPUI_INT_ADD = OpCode.CPUI_INT_ADD;
export const CPUI_INT_SUB = OpCode.CPUI_INT_SUB;
export const CPUI_INT_CARRY = OpCode.CPUI_INT_CARRY;
export const CPUI_INT_SCARRY = OpCode.CPUI_INT_SCARRY;
export const CPUI_INT_SBORROW = OpCode.CPUI_INT_SBORROW;
export const CPUI_INT_2COMP = OpCode.CPUI_INT_2COMP;
export const CPUI_INT_NEGATE = OpCode.CPUI_INT_NEGATE;
export const CPUI_INT_XOR = OpCode.CPUI_INT_XOR;
export const CPUI_INT_AND = OpCode.CPUI_INT_AND;
export const CPUI_INT_OR = OpCode.CPUI_INT_OR;
export const CPUI_INT_LEFT = OpCode.CPUI_INT_LEFT;
export const CPUI_INT_RIGHT = OpCode.CPUI_INT_RIGHT;
export const CPUI_INT_SRIGHT = OpCode.CPUI_INT_SRIGHT;
export const CPUI_INT_MULT = OpCode.CPUI_INT_MULT;
export const CPUI_INT_DIV = OpCode.CPUI_INT_DIV;
export const CPUI_INT_SDIV = OpCode.CPUI_INT_SDIV;
export const CPUI_INT_REM = OpCode.CPUI_INT_REM;
export const CPUI_INT_SREM = OpCode.CPUI_INT_SREM;
export const CPUI_BOOL_NEGATE = OpCode.CPUI_BOOL_NEGATE;
export const CPUI_BOOL_XOR = OpCode.CPUI_BOOL_XOR;
export const CPUI_BOOL_AND = OpCode.CPUI_BOOL_AND;
export const CPUI_BOOL_OR = OpCode.CPUI_BOOL_OR;
export const CPUI_MULTIEQUAL = OpCode.CPUI_MULTIEQUAL;
export const CPUI_INDIRECT = OpCode.CPUI_INDIRECT;
export const CPUI_PIECE = OpCode.CPUI_PIECE;
export const CPUI_SUBPIECE = OpCode.CPUI_SUBPIECE;

// =====================================================================
// SplitVarnode class
// =====================================================================

/// A logical value whose storage is split between two Varnodes.
///
/// This is usually a pair of Varnodes lo and hi holding the least and
/// most significant part of the logical value respectively.  It's possible for
/// the logical value to be a constant, in which case lo and hi are set to
/// null and val holds the actual constant.
/// It's also possible for hi to be null by itself, indicating that the most significant
/// part of the variable is zero, and the logical variable is the zero extension of lo.
export class SplitVarnode {
  lo: Varnode | null;
  hi: Varnode | null;
  whole: Varnode | null;
  defpoint: PcodeOp | null;
  defblock: BlockBasic | null;
  val: bigint;
  wholesize: number;

  constructor();
  constructor(sz: number, v: bigint);
  constructor(l: Varnode, h: Varnode);
  constructor(szOrL?: number | Varnode, vOrH?: bigint | Varnode) {
    this.lo = null;
    this.hi = null;
    this.whole = null;
    this.defpoint = null;
    this.defblock = null;
    this.val = 0n;
    this.wholesize = 0;

    if (szOrL === undefined) {
      // Default constructor - uninitialized
    } else if (typeof szOrL === 'number') {
      // SplitVarnode(sz, v) - construct a double precision constant
      const sz = szOrL;
      const v = vOrH as bigint;
      this.val = v;
      this.wholesize = sz;
    } else {
      // SplitVarnode(l, h) - construct from lo and hi piece
      const l = szOrL as Varnode;
      const h = vOrH as Varnode;
      this.initPartial(l.getSize() + h.getSize(), l, h);
    }
  }

  /// Construct given Varnode pieces and a known whole Varnode.
  initAll(w: Varnode, l: Varnode | null, h: Varnode | null): void {
    this.wholesize = w.getSize();
    this.lo = l;
    this.hi = h;
    this.whole = w;
    this.defpoint = null;
    this.defblock = null;
  }

  /// (Re)initialize this SplitVarnode as a constant.
  initPartial(sz: number, v: bigint): void;
  /// (Re)initialize this SplitVarnode given Varnode pieces.
  initPartial(sz: number, l: Varnode | null, h: Varnode | null): void;
  initPartial(sz: number, vOrL: bigint | Varnode | null, h?: Varnode | null): void {
    if (typeof vOrL === 'bigint') {
      // initPartial(sz, v) - constant form
      this.val = vOrL;
      this.wholesize = sz;
      this.lo = null;
      this.hi = null;
      this.whole = null;
      this.defpoint = null;
      this.defblock = null;
    } else {
      // initPartial(sz, l, h) - Varnode pieces form
      const l = vOrL as Varnode | null;
      if (h === undefined) h = null;
      if (h === null) {
        // hi is an implied zero
        this.hi = null;
        if (l !== null && l.isConstant()) {
          this.val = l.getOffset();
          this.lo = null;
        } else {
          this.lo = l;
        }
      } else {
        if (l !== null && l.isConstant() && h.isConstant()) {
          this.val = h.getOffset();
          this.val <<= BigInt(l.getSize() * 8);
          this.val |= l.getOffset();
          this.lo = null;
          this.hi = null;
        } else {
          this.lo = l;
          this.hi = h;
        }
      }
      this.wholesize = sz;
      this.whole = null;
      this.defpoint = null;
      this.defblock = null;
    }
  }

  /// Try to initialize given just the most significant piece split from whole.
  inHandHi(h: Varnode): boolean {
    if (!h.isPrecisHi()) return false;
    if (h.isWritten()) {
      const op = h.getDef()!;
      if (op.code() === OpCode.CPUI_SUBPIECE) {
        const w = op.getIn(0)!;
        if (op.getIn(1)!.getOffset() !== BigInt(w.getSize() - h.getSize())) return false;
        const descendants = w.descend;
        for (const tmpop of descendants) {
          if (tmpop.code() !== OpCode.CPUI_SUBPIECE) continue;
          const tmplo = tmpop.getOut()!;
          if (!tmplo.isPrecisLo()) continue;
          if (tmplo.getSize() + h.getSize() !== w.getSize()) continue;
          if (tmpop.getIn(1)!.getOffset() !== 0n) continue;
          this.initAll(w, tmplo, h);
          return true;
        }
      }
    }
    return false;
  }

  /// Try to initialize given just the least significant piece split from whole.
  inHandLo(l: Varnode): boolean {
    if (!l.isPrecisLo()) return false;
    if (l.isWritten()) {
      const op = l.getDef()!;
      if (op.code() === OpCode.CPUI_SUBPIECE) {
        const w = op.getIn(0)!;
        if (op.getIn(1)!.getOffset() !== 0n) return false;
        const descendants = w.descend;
        for (const tmpop of descendants) {
          if (tmpop.code() !== OpCode.CPUI_SUBPIECE) continue;
          const tmphi = tmpop.getOut()!;
          if (!tmphi.isPrecisHi()) continue;
          if (tmphi.getSize() + l.getSize() !== w.getSize()) continue;
          if (tmpop.getIn(1)!.getOffset() !== BigInt(l.getSize())) continue;
          this.initAll(w, l, tmphi);
          return true;
        }
      }
    }
    return false;
  }

  /// Try to initialize given just the least significant piece (other piece may be zero).
  inHandLoNoHi(l: Varnode): boolean {
    if (!l.isPrecisLo()) return false;
    if (!l.isWritten()) return false;
    const op = l.getDef()!;
    if (op.code() !== OpCode.CPUI_SUBPIECE) return false;
    if (op.getIn(1)!.getOffset() !== 0n) return false;
    const w = op.getIn(0)!;

    const descendants = w.descend;
    for (const tmpop of descendants) {
      if (tmpop.code() !== OpCode.CPUI_SUBPIECE) continue;
      const tmphi = tmpop.getOut()!;
      if (!tmphi.isPrecisHi()) continue;
      if (tmphi.getSize() + l.getSize() !== w.getSize()) continue;
      if (tmpop.getIn(1)!.getOffset() !== BigInt(l.getSize())) continue;
      this.initAll(w, l, tmphi);
      return true;
    }
    this.initAll(w, l, null);
    return true;
  }

  /// Try to initialize given just the most significant piece concatenated into whole.
  inHandHiOut(h: Varnode): boolean {
    const descendants = h.descend;
    let loTmp: Varnode | null = null;
    let outvn: Varnode | null = null;
    for (const pieceop of descendants) {
      if (pieceop.code() !== OpCode.CPUI_PIECE) continue;
      if (pieceop.getIn(0) !== h) continue;
      const l = pieceop.getIn(1)!;
      if (!l.isPrecisLo()) continue;
      if (loTmp !== null) return false; // Whole is not unique
      loTmp = l;
      outvn = pieceop.getOut()!;
    }
    if (loTmp !== null) {
      this.initAll(outvn!, loTmp, h);
      return true;
    }
    return false;
  }

  /// Try to initialize given just the least significant piece concatenated into whole.
  inHandLoOut(l: Varnode): boolean {
    const descendants = l.descend;
    let hiTmp: Varnode | null = null;
    let outvn: Varnode | null = null;
    for (const pieceop of descendants) {
      if (pieceop.code() !== OpCode.CPUI_PIECE) continue;
      if (pieceop.getIn(1) !== l) continue;
      const h = pieceop.getIn(0)!;
      if (!h.isPrecisHi()) continue;
      if (hiTmp !== null) return false; // Whole is not unique
      hiTmp = h;
      outvn = pieceop.getOut()!;
    }
    if (hiTmp !== null) {
      this.initAll(outvn!, l, hiTmp);
      return true;
    }
    return false;
  }

  /// Return true if this is a constant.
  isConstant(): boolean {
    return this.lo === null;
  }

  /// Return true if both pieces are initialized.
  hasBothPieces(): boolean {
    return this.hi !== null && this.lo !== null;
  }

  /// Get the size of this SplitVarnode as a whole in bytes.
  getSize(): number {
    return this.wholesize;
  }

  /// Get the least significant Varnode piece.
  getLo(): Varnode | null {
    return this.lo;
  }

  /// Get the most significant Varnode piece.
  getHi(): Varnode | null {
    return this.hi;
  }

  /// Get the Varnode representing this as a whole.
  getWhole(): Varnode | null {
    return this.whole;
  }

  /// Get the (final) defining PcodeOp of this.
  getDefPoint(): PcodeOp | null {
    return this.defpoint;
  }

  /// Get the defining basic block of this.
  getDefBlock(): BlockBasic | null {
    return this.defblock;
  }

  /// Get the value of this, assuming it is a constant.
  getValue(): bigint {
    return this.val;
  }

  /// Find whole out of which hi and lo are split.
  private findWholeSplitToPieces(): boolean {
    if (this.whole === null) {
      if (this.hi === null) return false;
      if (this.lo === null) return false;
      if (!this.hi.isWritten()) return false;
      let subhi = this.hi.getDef()!;
      if (subhi.code() === OpCode.CPUI_COPY) {
        const otherhi = subhi.getIn(0)!;
        if (!otherhi.isWritten()) return false;
        subhi = otherhi.getDef()!;
      }
      if (subhi.code() !== OpCode.CPUI_SUBPIECE) return false;
      if (subhi.getIn(1)!.getOffset() !== BigInt(this.wholesize - this.hi.getSize())) return false;
      const putativeWhole = subhi.getIn(0)!;
      if (putativeWhole.getSize() !== this.wholesize) return false;
      if (!this.lo.isWritten()) return false;
      let sublo = this.lo.getDef()!;
      if (sublo.code() === OpCode.CPUI_COPY) {
        const otherlo = sublo.getIn(0)!;
        if (!otherlo.isWritten()) return false;
        sublo = otherlo.getDef()!;
      }
      if (sublo.code() !== OpCode.CPUI_SUBPIECE) return false;
      if (putativeWhole !== sublo.getIn(0))
        return false; // Doesn't match between pieces
      if (sublo.getIn(1)!.getOffset() !== 0n)
        return false;
      this.whole = putativeWhole;
    }

    if (this.whole!.isWritten()) {
      this.defpoint = this.whole!.getDef()!;
      this.defblock = this.defpoint!.getParent();
    } else if (this.whole!.isInput()) {
      this.defpoint = null;
      this.defblock = null;
    }
    return true;
  }

  /// Set the basic block and PcodeOp where the pieces are defined.
  private findDefinitionPoint(): boolean {
    let lastop: PcodeOp;
    if (this.hi !== null && this.hi.isConstant()) return false;
    if (this.lo === null || this.lo.isConstant()) return false;
    if (this.hi === null) {
      // Implied zero extension
      if (this.lo.isInput()) {
        this.defblock = null;
        this.defpoint = null;
      } else if (this.lo.isWritten()) {
        this.defpoint = this.lo.getDef()!;
        this.defblock = this.defpoint!.getParent();
      } else {
        return false;
      }
    } else if (this.hi.isWritten()) {
      if (!this.lo.isWritten()) return false;
      lastop = this.hi.getDef()!;
      this.defblock = lastop.getParent();
      const lastop2 = this.lo.getDef()!;
      const otherblock: BlockBasic = lastop2.getParent();
      if (this.defblock !== otherblock) {
        this.defpoint = lastop;
        let curbl: FlowBlock | null = this.defblock;
        while (curbl !== null) {
          curbl = curbl.getImmedDom();
          if (curbl === otherblock) return true;
        }
        this.defblock = otherblock;
        this.defpoint = lastop2;
        curbl = this.defblock;
        while (curbl !== null) {
          curbl = curbl.getImmedDom();
          if (curbl === lastop.getParent()) return true;
        }
        this.defblock = null;
        return false;
      }
      if (lastop2.getSeqNum().getOrder() > lastop.getSeqNum().getOrder())
        lastop = lastop2;
      this.defpoint = lastop;
    } else if (this.hi.isInput()) {
      if (!this.lo.isInput())
        return false;
      this.defblock = null;
      this.defpoint = null;
    }
    return true;
  }

  /// Find the earliest definition point of the lo and hi pieces.
  findEarliestSplitPoint(): PcodeOp | null {
    if (this.hi === null || !this.hi.isWritten()) return null;
    if (this.lo === null || !this.lo.isWritten()) return null;
    const hiop = this.hi.getDef()!;
    const loop = this.lo.getDef()!;
    if (loop.getParent() !== hiop.getParent())
      return null;
    return (loop.getSeqNum().getOrder() < hiop.getSeqNum().getOrder()) ? loop : hiop;
  }

  /// Find whole Varnode formed as a CPUI_PIECE of hi and lo.
  private findWholeBuiltFromPieces(): boolean {
    if (this.hi === null) return false;
    if (this.lo === null) return false;
    let res: PcodeOp | null = null;
    let bb: BlockBasic | null;
    if (this.lo.isWritten())
      bb = this.lo.getDef()!.getParent();
    else if (this.lo.isInput())
      bb = null;
    else
      throw new LowlevelError("Trying to find whole on free varnode");

    const descendants = this.lo.descend;
    for (const op of descendants) {
      if (op.code() !== OpCode.CPUI_PIECE) continue;
      if (op.getIn(0) !== this.hi) continue;
      if (bb !== null) {
        if (op.getParent() !== bb) continue;
      } else if (!op.getParent().isEntryPoint()) {
        continue;
      }
      if (res === null)
        res = op;
      else {
        if (op.getSeqNum().getOrder() < res.getSeqNum().getOrder())
          res = op;
      }
    }

    if (res === null)
      this.whole = null;
    else {
      this.defpoint = res;
      this.defblock = this.defpoint.getParent();
      this.whole = res.getOut()!;
    }
    return this.whole !== null;
  }

  /// Does a whole Varnode already exist or can it be created before the given PcodeOp.
  isWholeFeasible(existop: PcodeOp): boolean {
    if (this.isConstant()) return true;
    if (this.lo !== null && this.hi !== null)
      if (this.lo.isConstant() !== this.hi.isConstant()) return false;
    if (!this.findWholeSplitToPieces()) {
      if (!this.findWholeBuiltFromPieces()) {
        if (!this.findDefinitionPoint())
          return false;
      }
    }
    if (this.defblock === null) return true;
    let curbl: FlowBlock | null = existop.getParent();
    if (curbl === this.defblock)
      return this.defpoint!.getSeqNum().getOrder() <= existop.getSeqNum().getOrder();
    while (curbl !== null) {
      curbl = curbl.getImmedDom();
      if (curbl === this.defblock) return true;
    }
    return false;
  }

  /// Does a whole Varnode already exist or can it be created before the given basic block.
  isWholePhiFeasible(bl: FlowBlock): boolean {
    if (this.isConstant()) return false;
    if (!this.findWholeSplitToPieces()) {
      if (!this.findWholeBuiltFromPieces()) {
        if (!this.findDefinitionPoint())
          return false;
      }
    }
    if (this.defblock === null) return true;
    if (bl === this.defblock) return true;
    while (bl !== null) {
      bl = bl.getImmedDom();
      if (bl === this.defblock) return true;
    }
    return false;
  }

  /// Create a whole Varnode for this, if it doesn't already exist.
  findCreateWhole(data: Funcdata): void {
    if (this.isConstant()) {
      this.whole = data.newConstant(this.wholesize, this.val);
      return;
    } else {
      if (this.lo !== null)
        this.lo.setPrecisLo();
      if (this.hi !== null)
        this.hi.setPrecisHi();
    }

    if (this.whole !== null) return;
    let concatop: PcodeOp;
    let addr: Address;
    let topblock: BlockBasic | null = null;

    if (this.defblock !== null)
      addr = this.defpoint!.getAddr();
    else {
      topblock = data.getBasicBlocks().getStartBlock() as BlockBasic;
      addr = topblock.getStart();
    }

    if (this.hi !== null) {
      concatop = data.newOp(2, addr);
      this.whole = data.newUniqueOut(this.wholesize, concatop);
      data.opSetOpcode(concatop, OpCode.CPUI_PIECE);
      data.opSetOutput(concatop, this.whole);
      data.opSetInput(concatop, this.hi, 0);
      data.opSetInput(concatop, this.lo!, 1);
    } else {
      concatop = data.newOp(1, addr);
      this.whole = data.newUniqueOut(this.wholesize, concatop);
      data.opSetOpcode(concatop, OpCode.CPUI_INT_ZEXT);
      data.opSetOutput(concatop, this.whole);
      data.opSetInput(concatop, this.lo!, 0);
    }

    if (this.defblock !== null)
      data.opInsertAfter(concatop, this.defpoint!);
    else
      data.opInsertBegin(concatop, topblock!);

    this.defpoint = concatop;
    this.defblock = concatop.getParent();
  }

  /// Create a whole Varnode that will be a PcodeOp output.
  findCreateOutputWhole(data: Funcdata): void {
    this.lo!.setPrecisLo();
    this.hi!.setPrecisHi();
    if (this.whole !== null) return;
    this.whole = data.newUnique(this.wholesize);
  }

  /// Create a whole Varnode from pieces, respecting piece storage.
  createJoinedWhole(data: Funcdata): void {
    this.lo!.setPrecisLo();
    this.hi!.setPrecisHi();
    if (this.whole !== null) return;
    let newaddr: Address;
    if (!SplitVarnode.isAddrTiedContiguous(this.lo!, this.hi!, newaddr = new Address())) {
      newaddr = data.getArch().constructJoinAddress(
        data.getArch().translate, this.hi!.getAddr(), this.hi!.getSize(),
        this.lo!.getAddr(), this.lo!.getSize()
      );
    }
    this.whole = data.newVarnode(this.wholesize, newaddr);
    this.whole.setWriteMask();
  }

  /// Rebuild the least significant piece as a CPUI_SUBPIECE of the whole.
  buildLoFromWhole(data: Funcdata): void {
    const loop = this.lo!.getDef();
    if (loop === null)
      throw new LowlevelError("Building low piece that was originally undefined");

    const inlist: Varnode[] = [];
    inlist.push(this.whole!);
    inlist.push(data.newConstant(4, 0n));
    if (loop.code() === OpCode.CPUI_MULTIEQUAL) {
      const bl: BlockBasic = loop.getParent();
      data.opUninsert(loop);
      data.opSetOpcode(loop, OpCode.CPUI_SUBPIECE);
      data.opSetAllInput(loop, inlist);
      data.opInsertBegin(loop, bl);
    } else if (loop.code() === OpCode.CPUI_INDIRECT) {
      const affector = PcodeOp.getOpFromConst(loop.getIn(1)!.getAddr())!;
      if (!affector.isDead())
        data.opUninsert(loop);
      data.opSetOpcode(loop, OpCode.CPUI_SUBPIECE);
      data.opSetAllInput(loop, inlist);
      if (!affector.isDead())
        data.opInsertAfter(loop, affector);
    } else {
      data.opSetOpcode(loop, OpCode.CPUI_SUBPIECE);
      data.opSetAllInput(loop, inlist);
    }
  }

  /// Rebuild the most significant piece as a CPUI_SUBPIECE of the whole.
  buildHiFromWhole(data: Funcdata): void {
    const hiop = this.hi!.getDef();
    if (hiop === null)
      throw new LowlevelError("Building low piece that was originally undefined");

    const inlist: Varnode[] = [];
    inlist.push(this.whole!);
    inlist.push(data.newConstant(4, BigInt(this.lo!.getSize())));
    if (hiop.code() === OpCode.CPUI_MULTIEQUAL) {
      const bl: BlockBasic = hiop.getParent();
      data.opUninsert(hiop);
      data.opSetOpcode(hiop, OpCode.CPUI_SUBPIECE);
      data.opSetAllInput(hiop, inlist);
      data.opInsertBegin(hiop, bl);
    } else if (hiop.code() === OpCode.CPUI_INDIRECT) {
      const affector = PcodeOp.getOpFromConst(hiop.getIn(1)!.getAddr())!;
      if (!affector.isDead())
        data.opUninsert(hiop);
      data.opSetOpcode(hiop, OpCode.CPUI_SUBPIECE);
      data.opSetAllInput(hiop, inlist);
      if (!affector.isDead())
        data.opInsertAfter(hiop, affector);
    } else {
      data.opSetOpcode(hiop, OpCode.CPUI_SUBPIECE);
      data.opSetAllInput(hiop, inlist);
    }
  }

  /// Find the point at which the output whole must exist.
  findOutExist(): PcodeOp | null {
    if (this.findWholeBuiltFromPieces()) {
      return this.defpoint;
    }
    return this.findEarliestSplitPoint();
  }

  /// Check if this is a constant that exceeds precision limits.
  exceedsConstPrecision(): boolean {
    return this.isConstant() && (this.wholesize > 8);
  }

  // ---------------------------------------------------------------
  // Static methods
  // ---------------------------------------------------------------

  /// Check if the values in the given Varnodes differ by the given size.
  static adjacentOffsets(vn1: Varnode, vn2: Varnode, size1: bigint): boolean {
    if (vn1.isConstant()) {
      if (!vn2.isConstant()) return false;
      return (vn1.getOffset() + size1) === vn2.getOffset();
    }

    if (!vn2.isWritten()) return false;
    const op2 = vn2.getDef()!;
    if (op2.code() !== OpCode.CPUI_INT_ADD) return false;
    if (!op2.getIn(1)!.isConstant()) return false;
    const c2 = op2.getIn(1)!.getOffset();

    if (op2.getIn(0) === vn1)
      return size1 === c2;

    if (!vn1.isWritten()) return false;
    const op1 = vn1.getDef()!;
    if (op1.code() !== OpCode.CPUI_INT_ADD) return false;
    if (!op1.getIn(1)!.isConstant()) return false;
    const c1 = op1.getIn(1)!.getOffset();

    if (op1.getIn(0) !== op2.getIn(0)) return false;
    return (c1 + size1) === c2;
  }

  /// Verify that the pointers into the given LOAD/STORE PcodeOps address contiguous memory.
  static testContiguousPointers(
    most: PcodeOp, least: PcodeOp,
    result: { first: PcodeOp | null, second: PcodeOp | null, spc: AddrSpace | null }
  ): boolean {
    result.spc = least.getIn(0)!.getSpaceFromConst();
    if (most.getIn(0)!.getSpaceFromConst() !== result.spc) return false;

    if (result.spc!.isBigEndian()) {
      result.first = most;
      result.second = least;
    } else {
      result.first = least;
      result.second = most;
    }
    const firstptr = result.first.getIn(1)!;
    if (firstptr.isFree()) return false;
    let sizeres: number;
    if (result.first.code() === OpCode.CPUI_LOAD)
      sizeres = result.first.getOut()!.getSize();
    else // CPUI_STORE
      sizeres = result.first.getIn(2)!.getSize();

    return SplitVarnode.adjacentOffsets(result.first.getIn(1)!, result.second.getIn(1)!, BigInt(sizeres));
  }

  /// Return true if the given pieces can be melded into a contiguous storage location.
  static isAddrTiedContiguous(lo: Varnode, hi: Varnode, res: Address): boolean {
    if (!lo.isAddrTied()) return false;
    if (!hi.isAddrTied()) return false;

    const entryLo: SymbolEntry | null = lo.getSymbolEntry();
    const entryHi: SymbolEntry | null = hi.getSymbolEntry();
    if (entryLo !== null || entryHi !== null) {
      if (entryLo === null || entryHi === null)
        return false;
      if (entryLo.getSymbol() !== entryHi.getSymbol())
        return false;
    }
    const spc = lo.getSpace();
    if (spc !== hi.getSpace()) return false;
    const looffset = lo.getOffset();
    const hioffset = hi.getOffset();
    if (spc!.isBigEndian()) {
      if (hioffset >= looffset) return false;
      if (hioffset + BigInt(hi.getSize()) !== looffset) return false;
      // Copy address data from hi
      Object.assign(res, hi.getAddr());
    } else {
      if (looffset >= hioffset) return false;
      if (looffset + BigInt(lo.getSize()) !== hioffset) return false;
      Object.assign(res, lo.getAddr());
    }
    return true;
  }

  /// Create a list of all the possible pairs that contain the same logical value as the given Varnode.
  static wholeList(w: Varnode, splitvec: SplitVarnode[]): void {
    const basic = new SplitVarnode();
    basic.whole = w;
    basic.hi = null;
    basic.lo = null;
    basic.wholesize = w.getSize();

    const descendants = basic.whole.descend;
    let resFlags = 0;
    for (const subop of descendants) {
      if (subop.code() !== OpCode.CPUI_SUBPIECE) continue;
      const vn = subop.getOut()!;
      if (vn.isPrecisHi()) {
        if (subop.getIn(1)!.getOffset() !== BigInt(basic.wholesize - vn.getSize())) continue;
        basic.hi = vn;
        resFlags |= 2;
      } else if (vn.isPrecisLo()) {
        if (subop.getIn(1)!.getOffset() !== 0n) continue;
        basic.lo = vn;
        resFlags |= 1;
      }
    }
    if (resFlags === 0) return;
    if (resFlags === 3 && (basic.lo!.getSize() + basic.hi!.getSize() !== basic.wholesize))
      return;

    splitvec.push(basic);
    SplitVarnode.findCopies(basic, splitvec);
  }

  /// Find copies from (the pieces of) the given SplitVarnode.
  static findCopies(inp: SplitVarnode, splitvec: SplitVarnode[]): void {
    if (!inp.hasBothPieces()) return;

    const loDescendants = inp.getLo()!.descend;
    for (const loop of loDescendants) {
      if (loop.code() !== OpCode.CPUI_COPY) continue;
      const locpy = loop.getOut()!;
      let addr = locpy.getAddr();
      if (addr.isBigEndian())
        addr = addr.subtract(BigInt(inp.getHi()!.getSize()));
      else
        addr = addr.add(BigInt(locpy.getSize()));
      const hiDescendants = inp.getHi()!.descend;
      for (const hiop of hiDescendants) {
        if (hiop.code() !== OpCode.CPUI_COPY) continue;
        const hicpy = hiop.getOut()!;
        if (!hicpy.getAddr().equals(addr)) continue;
        if (hiop.getParent() !== loop.getParent()) continue;
        const newsplit = new SplitVarnode();
        newsplit.initAll(inp.getWhole()!, locpy, hicpy);
        splitvec.push(newsplit);
      }
    }
  }

  /// For the given CBRANCH PcodeOp, pass back the true and false basic blocks.
  static getTrueFalse(
    boolop: PcodeOp, flip: boolean
  ): { trueout: BlockBasic, falseout: BlockBasic } {
    const parent: BlockBasic = boolop.getParent();
    const trueblock: BlockBasic = parent.getTrueOut() as BlockBasic;
    const falseblock: BlockBasic = parent.getFalseOut() as BlockBasic;
    if (boolop.isBooleanFlip() !== flip) {
      return { trueout: falseblock, falseout: trueblock };
    } else {
      return { trueout: trueblock, falseout: falseblock };
    }
  }

  /// Return true if the basic block containing the given CBRANCH performs no other operation.
  static otherwiseEmpty(branchop: PcodeOp): boolean {
    const bl: BlockBasic = branchop.getParent();
    if (bl.sizeIn() !== 1) return false;
    let otherop: PcodeOp | null = null;
    const vn = branchop.getIn(1)!;
    if (vn.isWritten())
      otherop = vn.getDef()!;
    for (let i = 0; i < bl.op.length; ++i) {
      const op = bl.op[i];
      if (op === otherop) continue;
      if (op === branchop) continue;
      return false;
    }
    return true;
  }

  /// Verify that the given PcodeOp is a CPUI_INT_MULT by -1.
  static verifyMultNegOne(op: PcodeOp): boolean {
    if (op.code() !== OpCode.CPUI_INT_MULT) return false;
    const in1 = op.getIn(1)!;
    if (!in1.isConstant()) return false;
    if (in1.getOffset() !== calc_mask(in1.getSize())) return false;
    return true;
  }

  /// Check that the logical version of a binary double-precision operation can be created.
  static prepareBinaryOp(out: SplitVarnode, in1: SplitVarnode, in2: SplitVarnode): PcodeOp | null {
    const existop = out.findOutExist();
    if (existop === null) return null;
    if (!in1.isWholeFeasible(existop)) return null;
    if (!in2.isWholeFeasible(existop)) return null;
    return existop;
  }

  /// Rewrite a double precision binary operation by replacing the pieces with unified Varnodes.
  static createBinaryOp(
    data: Funcdata, out: SplitVarnode, in1: SplitVarnode, in2: SplitVarnode,
    existop: PcodeOp, opc: OpCode
  ): void {
    out.findCreateOutputWhole(data);
    in1.findCreateWhole(data);
    in2.findCreateWhole(data);
    if (existop.code() !== OpCode.CPUI_PIECE) {
      const newop = data.newOp(2, existop.getAddr());
      data.opSetOpcode(newop, opc);
      data.opSetOutput(newop, out.getWhole()!);
      data.opSetInput(newop, in1.getWhole()!, 0);
      data.opSetInput(newop, in2.getWhole()!, 1);
      data.opInsertBefore(newop, existop);
      out.buildLoFromWhole(data);
      out.buildHiFromWhole(data);
    } else {
      data.opSetOpcode(existop, opc);
      data.opSetInput(existop, in1.getWhole()!, 0);
      data.opSetInput(existop, in2.getWhole()!, 1);
    }
  }

  /// Make sure input and output operands of a double precision shift operation are compatible.
  static prepareShiftOp(out: SplitVarnode, inp: SplitVarnode): PcodeOp | null {
    const existop = out.findOutExist();
    if (existop === null) return null;
    if (!inp.isWholeFeasible(existop)) return null;
    return existop;
  }

  /// Rewrite a double precision shift by replacing hi/lo pieces with unified Varnodes.
  static createShiftOp(
    data: Funcdata, out: SplitVarnode, inp: SplitVarnode, sa: Varnode,
    existop: PcodeOp, opc: OpCode
  ): void {
    out.findCreateOutputWhole(data);
    inp.findCreateWhole(data);
    if (sa.isConstant())
      sa = data.newConstant(sa.getSize(), sa.getOffset());
    if (existop.code() !== OpCode.CPUI_PIECE) {
      const newop = data.newOp(2, existop.getAddr());
      data.opSetOpcode(newop, opc);
      data.opSetOutput(newop, out.getWhole()!);
      data.opSetInput(newop, inp.getWhole()!, 0);
      data.opSetInput(newop, sa, 1);
      data.opInsertBefore(newop, existop);
      out.buildLoFromWhole(data);
      out.buildHiFromWhole(data);
    } else {
      data.opSetOpcode(existop, opc);
      data.opSetInput(existop, inp.getWhole()!, 0);
      data.opSetInput(existop, sa, 1);
    }
  }

  /// Make sure input operands of a double precision compare operation are compatible.
  static prepareBoolOp(in1: SplitVarnode, in2: SplitVarnode, testop: PcodeOp): boolean {
    if (!in1.isWholeFeasible(testop)) return false;
    if (!in2.isWholeFeasible(testop)) return false;
    return true;
  }

  /// Rewrite a double precision boolean operation by replacing input pieces with unified Varnodes.
  static replaceBoolOp(
    data: Funcdata, boolop: PcodeOp, in1: SplitVarnode, in2: SplitVarnode, opc: OpCode
  ): void {
    in1.findCreateWhole(data);
    in2.findCreateWhole(data);
    data.opSetOpcode(boolop, opc);
    data.opSetInput(boolop, in1.getWhole()!, 0);
    data.opSetInput(boolop, in2.getWhole()!, 1);
  }

  /// Create a new compare PcodeOp, replacing the boolean Varnode taken as input by the given CBRANCH.
  static createBoolOp(
    data: Funcdata, cbranch: PcodeOp, in1: SplitVarnode, in2: SplitVarnode, opc: OpCode
  ): void {
    let addrop: PcodeOp = cbranch;
    const boolvn = cbranch.getIn(1)!;
    if (boolvn.isWritten())
      addrop = boolvn.getDef()!;
    in1.findCreateWhole(data);
    in2.findCreateWhole(data);
    const newop = data.newOp(2, addrop.getAddr());
    data.opSetOpcode(newop, opc);
    const newbool = data.newUniqueOut(1, newop);
    data.opSetInput(newop, in1.getWhole()!, 0);
    data.opSetInput(newop, in2.getWhole()!, 1);
    data.opInsertBefore(newop, cbranch);
    data.opSetInput(cbranch, newbool, 1);
  }

  /// Check that the logical version of a CPUI_MULTIEQUAL operation can be created.
  static preparePhiOp(out: SplitVarnode, inlist: SplitVarnode[]): PcodeOp | null {
    const existop = out.findEarliestSplitPoint();
    if (existop === null) return null;
    if (existop.code() !== OpCode.CPUI_MULTIEQUAL)
      throw new LowlevelError("Trying to create phi-node double precision op with phi-node pieces");
    const bl: BlockBasic = existop.getParent();
    const numin = inlist.length;
    for (let i = 0; i < numin; ++i)
      if (!inlist[i].isWholePhiFeasible(bl.getIn(i)))
        return null;
    return existop;
  }

  /// Rewrite a double precision MULTIEQUAL operation.
  static createPhiOp(
    data: Funcdata, out: SplitVarnode, inlist: SplitVarnode[], existop: PcodeOp
  ): void {
    out.findCreateOutputWhole(data);
    const numin = inlist.length;
    for (let i = 0; i < numin; ++i)
      inlist[i].findCreateWhole(data);

    const newop = data.newOp(numin, existop.getAddr());
    data.opSetOpcode(newop, OpCode.CPUI_MULTIEQUAL);
    data.opSetOutput(newop, out.getWhole()!);
    for (let i = 0; i < numin; ++i)
      data.opSetInput(newop, inlist[i].getWhole()!, i);
    data.opInsertBefore(newop, existop);
    out.buildLoFromWhole(data);
    out.buildHiFromWhole(data);
  }

  /// Check that the logical version of a CPUI_INDIRECT operation can be created.
  static prepareIndirectOp(inp: SplitVarnode, affector: PcodeOp): boolean {
    if (!inp.isWholeFeasible(affector))
      return false;
    return true;
  }

  /// Rewrite a double precision INDIRECT operation.
  static replaceIndirectOp(
    data: Funcdata, out: SplitVarnode, inp: SplitVarnode, affector: PcodeOp
  ): void {
    out.createJoinedWhole(data);
    inp.findCreateWhole(data);
    const newop = data.newOp(2, affector.getAddr());
    data.opSetOpcode(newop, OpCode.CPUI_INDIRECT);
    data.opSetOutput(newop, out.getWhole()!);
    data.opSetInput(newop, inp.getWhole()!, 0);
    data.opSetInput(newop, data.newVarnodeIop(affector), 1);
    data.opInsertBefore(newop, affector);
    out.buildLoFromWhole(data);
    out.buildHiFromWhole(data);
  }

  /// Rewrite the double precision version of a COPY to an address forced Varnode.
  static replaceCopyForce(
    data: Funcdata, addr: Address, inp: SplitVarnode, copylo: PcodeOp, copyhi: PcodeOp
  ): void {
    let inVn: Varnode = inp.getWhole()!;
    const returnForm = copyhi.isReturnCopy();
    if (returnForm && !inVn.getAddr().equals(addr)) {
      let otherPoint1 = copyhi.getIn(0)!.getDef()!;
      const otherPoint2 = copylo.getIn(0)!.getDef()!;
      if (otherPoint1.getSeqNum().getOrder() < otherPoint2.getSeqNum().getOrder())
        otherPoint1 = otherPoint2;
      const otherCopy = data.newOp(1, otherPoint1.getAddr());
      data.opSetOpcode(otherCopy, OpCode.CPUI_COPY);
      const vn = data.newVarnodeOut(inp.getSize(), addr, otherCopy);
      data.opSetInput(otherCopy, inVn, 0);
      data.opInsertBefore(otherCopy, otherPoint1);
      inVn = vn;
    }
    const wholeCopy = data.newOp(1, copyhi.getAddr());
    data.opSetOpcode(wholeCopy, OpCode.CPUI_COPY);
    const outVn = data.newVarnodeOut(inp.getSize(), addr, wholeCopy);
    outVn.setAddrForce();
    if (returnForm)
      data.markReturnCopy(wholeCopy);
    data.opSetInput(wholeCopy, inVn, 0);
    data.opInsertBefore(wholeCopy, copyhi);
    data.opDestroy(copyhi);
    data.opDestroy(copylo);
  }

  /// Try to perform one transform on a logical double precision operation given a specific input.
  static applyRuleIn(inp: SplitVarnode, data: Funcdata): number {
    for (let i = 0; i < 2; ++i) {
      let vn: Varnode | null;
      vn = (i === 0) ? inp.getHi() : inp.getLo();
      if (vn === null) continue;
      const workishi = (i === 0);
      const descendants = vn.descend;
      for (const workop of descendants) {
        switch (workop.code()) {
          case OpCode.CPUI_INT_ADD:
          {
            const addform = new AddForm();
            if (addform.applyRule(inp, workop, workishi, data))
              return 1;
            const subform = new SubForm();
            if (subform.applyRule(inp, workop, workishi, data))
              return 1;
          }
          break;
          case OpCode.CPUI_INT_AND:
          {
            const equal3form = new Equal3Form();
            if (equal3form.applyRule(inp, workop, workishi, data))
              return 1;
            const logicalform = new LogicalForm();
            if (logicalform.applyRule(inp, workop, workishi, data))
              return 1;
          }
          break;
          case OpCode.CPUI_INT_OR:
          {
            const logicalform = new LogicalForm();
            if (logicalform.applyRule(inp, workop, workishi, data))
              return 1;
          }
          break;
          case OpCode.CPUI_INT_XOR:
          {
            const logicalform = new LogicalForm();
            if (logicalform.applyRule(inp, workop, workishi, data))
              return 1;
          }
          break;
          case OpCode.CPUI_INT_EQUAL:
          case OpCode.CPUI_INT_NOTEQUAL:
          {
            const lessthreeway = new LessThreeWay();
            if (lessthreeway.applyRule(inp, workop, workishi, data))
              return 1;
            const equal1form = new Equal1Form();
            if (equal1form.applyRule(inp, workop, workishi, data))
              return 1;
            const equal2form = new Equal2Form();
            if (equal2form.applyRule(inp, workop, workishi, data))
              return 1;
          }
          break;
          case OpCode.CPUI_INT_LESS:
          case OpCode.CPUI_INT_LESSEQUAL:
          {
            const lessthreeway = new LessThreeWay();
            if (lessthreeway.applyRule(inp, workop, workishi, data))
              return 1;
            const lessconstform = new LessConstForm();
            if (lessconstform.applyRule(inp, workop, workishi, data))
              return 1;
          }
          break;
          case OpCode.CPUI_INT_SLESS:
          {
            const lessconstform = new LessConstForm();
            if (lessconstform.applyRule(inp, workop, workishi, data))
              return 1;
          }
          break;
          case OpCode.CPUI_INT_SLESSEQUAL:
          {
            const lessconstform = new LessConstForm();
            if (lessconstform.applyRule(inp, workop, workishi, data))
              return 1;
          }
          break;
          case OpCode.CPUI_INT_LEFT:
          {
            const shiftform = new ShiftForm();
            if (shiftform.applyRuleLeft(inp, workop, workishi, data))
              return 1;
          }
          break;
          case OpCode.CPUI_INT_RIGHT:
          {
            const shiftform = new ShiftForm();
            if (shiftform.applyRuleRight(inp, workop, workishi, data))
              return 1;
          }
          break;
          case OpCode.CPUI_INT_SRIGHT:
          {
            const shiftform = new ShiftForm();
            if (shiftform.applyRuleRight(inp, workop, workishi, data))
              return 1;
          }
          break;
          case OpCode.CPUI_INT_MULT:
          {
            const multform = new MultForm();
            if (multform.applyRule(inp, workop, workishi, data))
              return 1;
          }
          break;
          case OpCode.CPUI_MULTIEQUAL:
          {
            const phiform = new PhiForm();
            if (phiform.applyRule(inp, workop, workishi, data))
              return 1;
          }
          break;
          case OpCode.CPUI_INDIRECT:
          {
            const indform = new IndirectForm();
            if (indform.applyRule(inp, workop, workishi, data))
              return 1;
          }
          break;
          case OpCode.CPUI_COPY:
            if (workop.getOut()!.isAddrForce()) {
              const copyform = new CopyForceForm();
              if (copyform.applyRule(inp, workop, workishi, data))
                return 1;
            }
            break;
          default:
            break;
        }
      }
    }
    return 0;
  }
}

// =====================================================================
// AddForm class
// =====================================================================

export class AddForm {
  in: SplitVarnode = new SplitVarnode();
  hi1: Varnode | null = null;
  hi2: Varnode | null = null;
  lo1: Varnode | null = null;
  lo2: Varnode | null = null;
  reshi: Varnode | null = null;
  reslo: Varnode | null = null;
  zextop: PcodeOp | null = null;
  loadd: PcodeOp | null = null;
  add2: PcodeOp | null = null;
  hizext1: Varnode | null = null;
  hizext2: Varnode | null = null;
  slot1: number = 0;
  negconst: bigint = 0n;
  existop: PcodeOp | null = null;
  indoub: SplitVarnode = new SplitVarnode();
  outdoub: SplitVarnode = new SplitVarnode();

  checkForCarry(op: PcodeOp): boolean {
    if (op.code() !== OpCode.CPUI_INT_ZEXT) return false;
    if (!op.getIn(0)!.isWritten()) return false;

    const carryop = op.getIn(0)!.getDef()!;
    if (carryop.code() === OpCode.CPUI_INT_CARRY) {
      if (carryop.getIn(0) === this.lo1)
        this.lo2 = carryop.getIn(1)!;
      else if (carryop.getIn(1) === this.lo1)
        this.lo2 = carryop.getIn(0)!;
      else
        return false;
      if (this.lo2!.isConstant()) return false;
      return true;
    }
    if (carryop.code() === OpCode.CPUI_INT_LESS) {
      const tmpvn = carryop.getIn(0)!;
      if (tmpvn.isConstant()) {
        if (carryop.getIn(1) !== this.lo1) return false;
        this.negconst = tmpvn.getOffset();
        this.negconst = (~this.negconst) & calc_mask(this.lo1!.getSize());
        this.lo2 = null;
        return true;
      } else if (tmpvn.isWritten()) {
        const loadd_op = tmpvn.getDef()!;
        if (loadd_op.code() !== OpCode.CPUI_INT_ADD) return false;
        let othervn: Varnode;
        if (loadd_op.getIn(0) === this.lo1)
          othervn = loadd_op.getIn(1)!;
        else if (loadd_op.getIn(1) === this.lo1)
          othervn = loadd_op.getIn(0)!;
        else
          return false;
        if (othervn.isConstant()) {
          this.negconst = othervn.getOffset();
          this.lo2 = null;
          const relvn = carryop.getIn(1)!;
          if (relvn === this.lo1) return true;
          if (!relvn.isConstant()) return false;
          if (relvn.getOffset() !== this.negconst) return false;
          return true;
        } else {
          this.lo2 = othervn;
          const compvn = carryop.getIn(1)!;
          if (compvn === this.lo2 || compvn === this.lo1)
            return true;
        }
      }
      return false;
    }
    if (carryop.code() === OpCode.CPUI_INT_NOTEQUAL) {
      if (!carryop.getIn(1)!.isConstant()) return false;
      if (carryop.getIn(0) !== this.lo1) return false;
      if (carryop.getIn(1)!.getOffset() !== 0n) return false;
      this.negconst = calc_mask(this.lo1!.getSize());
      this.lo2 = null;
      return true;
    }
    return false;
  }

  verify(h: Varnode, l: Varnode, op: PcodeOp): boolean {
    this.hi1 = h;
    this.lo1 = l;
    this.slot1 = op.getSlot(this.hi1);
    for (let i = 0; i < 3; ++i) {
      if (i === 0) {
        const desc = op.getOut()!.loneDescend();
        this.add2 = desc;
        if (this.add2 === null) continue;
        if (this.add2.code() !== OpCode.CPUI_INT_ADD) continue;
        this.reshi = this.add2.getOut()!;
        this.hizext1 = op.getIn(1 - this.slot1)!;
        this.hizext2 = this.add2.getIn(1 - this.add2.getSlot(op.getOut()!))!;
      } else if (i === 1) {
        const tmpvn = op.getIn(1 - this.slot1)!;
        if (!tmpvn.isWritten()) continue;
        this.add2 = tmpvn.getDef()!;
        if (this.add2!.code() !== OpCode.CPUI_INT_ADD) continue;
        this.reshi = op.getOut()!;
        this.hizext1 = this.add2!.getIn(0)!;
        this.hizext2 = this.add2!.getIn(1)!;
      } else {
        this.reshi = op.getOut()!;
        this.hizext1 = op.getIn(1 - this.slot1)!;
        this.hizext2 = null;
      }
      for (let j = 0; j < 2; ++j) {
        if (i === 2) {
          if (!this.hizext1!.isWritten()) continue;
          this.zextop = this.hizext1!.getDef()!;
          this.hi2 = null;
        } else if (j === 0) {
          if (!this.hizext1!.isWritten()) continue;
          this.zextop = this.hizext1!.getDef()!;
          this.hi2 = this.hizext2;
        } else {
          if (!this.hizext2!.isWritten()) continue;
          this.zextop = this.hizext2!.getDef()!;
          this.hi2 = this.hizext1;
        }
        if (!this.checkForCarry(this.zextop!)) continue;

        const lo1Descendants = this.lo1.descend;
        for (const loaddCandidate of lo1Descendants) {
          this.loadd = loaddCandidate;
          if (this.loadd!.code() !== OpCode.CPUI_INT_ADD) continue;
          const tmpvn2 = this.loadd!.getIn(1 - this.loadd!.getSlot(this.lo1))!;
          if (this.lo2 === null) {
            if (!tmpvn2.isConstant()) continue;
            if (tmpvn2.getOffset() !== this.negconst) continue;
            this.lo2 = tmpvn2;
          } else if (this.lo2.isConstant()) {
            if (!tmpvn2.isConstant()) continue;
            if (this.lo2.getOffset() !== tmpvn2.getOffset()) continue;
          } else if (this.loadd!.getIn(1 - this.loadd!.getSlot(this.lo1)) !== this.lo2) {
            continue;
          }
          this.reslo = this.loadd!.getOut()!;
          return true;
        }
      }
    }
    return false;
  }

  applyRule(i: SplitVarnode, op: PcodeOp, workishi: boolean, data: Funcdata): boolean {
    if (!workishi) return false;
    if (!i.hasBothPieces()) return false;
    this.in = i;
    if (!this.verify(this.in.getHi()!, this.in.getLo()!, op))
      return false;

    this.indoub.initPartial(this.in.getSize(), this.lo2, this.hi2);
    if (this.indoub.exceedsConstPrecision())
      return false;
    this.outdoub.initPartial(this.in.getSize(), this.reslo!, this.reshi!);
    this.existop = SplitVarnode.prepareBinaryOp(this.outdoub, this.in, this.indoub);
    if (this.existop === null)
      return false;
    SplitVarnode.createBinaryOp(data, this.outdoub, this.in, this.indoub, this.existop, OpCode.CPUI_INT_ADD);
    return true;
  }
}

// =====================================================================
// SubForm class
// =====================================================================

export class SubForm {
  in: SplitVarnode = new SplitVarnode();
  hi1: Varnode | null = null;
  hi2: Varnode | null = null;
  lo1: Varnode | null = null;
  lo2: Varnode | null = null;
  reshi: Varnode | null = null;
  reslo: Varnode | null = null;
  zextop: PcodeOp | null = null;
  lessop: PcodeOp | null = null;
  negop: PcodeOp | null = null;
  loadd: PcodeOp | null = null;
  add2: PcodeOp | null = null;
  hineg1: Varnode | null = null;
  hineg2: Varnode | null = null;
  hizext1: Varnode | null = null;
  hizext2: Varnode | null = null;
  slot1: number = 0;
  existop: PcodeOp | null = null;
  indoub: SplitVarnode = new SplitVarnode();
  outdoub: SplitVarnode = new SplitVarnode();

  verify(h: Varnode, l: Varnode, op: PcodeOp): boolean {
    this.hi1 = h;
    this.lo1 = l;
    this.slot1 = op.getSlot(this.hi1);
    for (let i = 0; i < 2; ++i) {
      if (i === 0) {
        const desc = op.getOut()!.loneDescend();
        this.add2 = desc;
        if (this.add2 === null) continue;
        if (this.add2.code() !== OpCode.CPUI_INT_ADD) continue;
        this.reshi = this.add2.getOut()!;
        this.hineg1 = op.getIn(1 - this.slot1)!;
        this.hineg2 = this.add2.getIn(1 - this.add2.getSlot(op.getOut()!))!;
      } else {
        const tmpvn = op.getIn(1 - this.slot1)!;
        if (!tmpvn.isWritten()) continue;
        this.add2 = tmpvn.getDef()!;
        if (this.add2!.code() !== OpCode.CPUI_INT_ADD) continue;
        this.reshi = op.getOut()!;
        this.hineg1 = this.add2!.getIn(0)!;
        this.hineg2 = this.add2!.getIn(1)!;
      }
      if (!this.hineg1!.isWritten()) continue;
      if (!this.hineg2!.isWritten()) continue;
      if (!SplitVarnode.verifyMultNegOne(this.hineg1!.getDef()!)) continue;
      if (!SplitVarnode.verifyMultNegOne(this.hineg2!.getDef()!)) continue;
      this.hizext1 = this.hineg1!.getDef()!.getIn(0)!;
      this.hizext2 = this.hineg2!.getDef()!.getIn(0)!;
      for (let j = 0; j < 2; ++j) {
        if (j === 0) {
          if (!this.hizext1!.isWritten()) continue;
          this.zextop = this.hizext1!.getDef()!;
          this.hi2 = this.hizext2;
        } else {
          if (!this.hizext2!.isWritten()) continue;
          this.zextop = this.hizext2!.getDef()!;
          this.hi2 = this.hizext1;
        }
        if (this.zextop!.code() !== OpCode.CPUI_INT_ZEXT) continue;
        if (!this.zextop!.getIn(0)!.isWritten()) continue;
        this.lessop = this.zextop!.getIn(0)!.getDef()!;
        if (this.lessop!.code() !== OpCode.CPUI_INT_LESS) continue;
        if (this.lessop!.getIn(0) !== this.lo1) continue;
        this.lo2 = this.lessop!.getIn(1)!;
        const lo1Descendants = this.lo1.descend;
        for (const loaddCandidate of lo1Descendants) {
          this.loadd = loaddCandidate;
          if (this.loadd!.code() !== OpCode.CPUI_INT_ADD) continue;
          const tmpvn2 = this.loadd!.getIn(1 - this.loadd!.getSlot(this.lo1))!;
          if (!tmpvn2.isWritten()) continue;
          this.negop = tmpvn2.getDef()!;
          if (!SplitVarnode.verifyMultNegOne(this.negop!)) continue;
          if (this.negop!.getIn(0) !== this.lo2) continue;
          this.reslo = this.loadd!.getOut()!;
          return true;
        }
      }
    }
    return false;
  }

  applyRule(i: SplitVarnode, op: PcodeOp, workishi: boolean, data: Funcdata): boolean {
    if (!workishi) return false;
    if (!i.hasBothPieces()) return false;
    this.in = i;

    if (!this.verify(this.in.getHi()!, this.in.getLo()!, op))
      return false;

    this.indoub.initPartial(this.in.getSize(), this.lo2!, this.hi2!);
    if (this.indoub.exceedsConstPrecision())
      return false;
    this.outdoub.initPartial(this.in.getSize(), this.reslo!, this.reshi!);
    this.existop = SplitVarnode.prepareBinaryOp(this.outdoub, this.in, this.indoub);
    if (this.existop === null)
      return false;
    SplitVarnode.createBinaryOp(data, this.outdoub, this.in, this.indoub, this.existop, OpCode.CPUI_INT_SUB);
    return true;
  }
}

// =====================================================================
// LogicalForm class
// =====================================================================

export class LogicalForm {
  in: SplitVarnode = new SplitVarnode();
  loop: PcodeOp | null = null;
  hiop: PcodeOp | null = null;
  hi1: Varnode | null = null;
  hi2: Varnode | null = null;
  lo1: Varnode | null = null;
  lo2: Varnode | null = null;
  existop: PcodeOp | null = null;
  indoub: SplitVarnode = new SplitVarnode();
  outdoub: SplitVarnode = new SplitVarnode();

  findHiMatch(): number {
    const lo1Tmp = this.in.getLo()!;
    const vn2 = this.loop!.getIn(1 - this.loop!.getSlot(lo1Tmp))!;

    const out = new SplitVarnode();
    if (out.inHandLoOut(lo1Tmp)) {
      const hi = out.getHi();
      if (hi !== null && hi.isWritten()) {
        const maybeop = hi.getDef()!;
        if (maybeop.code() === this.loop!.code()) {
          if (maybeop.getIn(0) === this.hi1) {
            if (maybeop.getIn(1)!.isConstant() === vn2.isConstant()) {
              this.hiop = maybeop;
              return 0;
            }
          } else if (maybeop.getIn(1) === this.hi1) {
            if (maybeop.getIn(0)!.isConstant() === vn2.isConstant()) {
              this.hiop = maybeop;
              return 0;
            }
          }
        }
      }
    }

    if (!vn2.isConstant()) {
      const in2 = new SplitVarnode();
      if (in2.inHandLo(vn2)) {
        const hi2Desc = in2.getHi()!.descend;
        for (const maybeop of hi2Desc) {
          if (maybeop.code() === this.loop!.code()) {
            if (maybeop.getIn(0) === this.hi1 || maybeop.getIn(1) === this.hi1) {
              this.hiop = maybeop;
              return 0;
            }
          }
        }
      }
      return -1;
    } else {
      const hi1Desc = this.hi1!.descend;
      let count = 0;
      let lastop: PcodeOp | null = null;
      for (const maybeop of hi1Desc) {
        if (maybeop.code() === this.loop!.code()) {
          if (maybeop.getIn(1)!.isConstant()) {
            count += 1;
            if (count > 1) break;
            lastop = maybeop;
          }
        }
      }
      if (count === 1) {
        this.hiop = lastop;
        return 0;
      }
      if (count > 1)
        return -1;
    }
    return -2;
  }

  verify(h: Varnode, l: Varnode, lop: PcodeOp): boolean {
    this.loop = lop;
    this.lo1 = l;
    this.hi1 = h;
    const res = this.findHiMatch();

    if (res === 0) {
      this.lo2 = this.loop!.getIn(1 - this.loop!.getSlot(this.lo1!))!;
      this.hi2 = this.hiop!.getIn(1 - this.hiop!.getSlot(this.hi1!))!;
      if (this.lo2 === this.lo1 || this.lo2 === this.hi1 ||
          this.hi2 === this.hi1 || this.hi2 === this.lo1) return false;
      if (this.lo2 === this.hi2) return false;
      return true;
    }
    return false;
  }

  // applyRule is defined in part2 via prototype extension
  applyRule(i: SplitVarnode, lop: PcodeOp, workishi: boolean, data: Funcdata): boolean {
    // Stub - implemented in part2
    return false;
  }
}

// =====================================================================
// Equal1Form class
// =====================================================================

export class Equal1Form {
  in1: SplitVarnode = new SplitVarnode();
  in2: SplitVarnode = new SplitVarnode();
  loop: PcodeOp | null = null;
  hiop: PcodeOp | null = null;
  hibool: PcodeOp | null = null;
  lobool: PcodeOp | null = null;
  hi1: Varnode | null = null;
  lo1: Varnode | null = null;
  hi2: Varnode | null = null;
  lo2: Varnode | null = null;
  hi1slot: number = 0;
  lo1slot: number = 0;
  notequalformhi: boolean = false;
  notequalformlo: boolean = false;
  setonlow: boolean = false;

  // applyRule is defined in part2 via prototype extension
  applyRule(i: SplitVarnode, hop: PcodeOp, workishi: boolean, data: Funcdata): boolean {
    // Stub - implemented in part2
    return false;
  }
}

// =====================================================================
// Equal2Form class
// =====================================================================

export class Equal2Form {
  in: SplitVarnode = new SplitVarnode();
  hi1: Varnode | null = null;
  hi2: Varnode | null = null;
  lo1: Varnode | null = null;
  lo2: Varnode | null = null;
  boolAndOr: PcodeOp | null = null;
  param2: SplitVarnode = new SplitVarnode();

  // replace and applyRule are defined in part2 via prototype extension
  replace(data: Funcdata): boolean {
    return false;
  }

  applyRule(i: SplitVarnode, op: PcodeOp, workishi: boolean, data: Funcdata): boolean {
    return false;
  }
}

// =====================================================================
// Equal3Form class
// =====================================================================

export class Equal3Form {
  in: SplitVarnode = new SplitVarnode();
  hi: Varnode | null = null;
  lo: Varnode | null = null;
  andop: PcodeOp | null = null;
  compareop: PcodeOp | null = null;
  smallc: Varnode | null = null;

  // verify and applyRule are defined in part2 via prototype extension
  verify(h: Varnode, l: Varnode, aop: PcodeOp): boolean {
    return false;
  }

  applyRule(i: SplitVarnode, op: PcodeOp, workishi: boolean, data: Funcdata): boolean {
    return false;
  }
}

// =====================================================================
// LessThreeWay class
// =====================================================================

export class LessThreeWay {
  in: SplitVarnode = new SplitVarnode();
  in2: SplitVarnode = new SplitVarnode();
  hilessbl: BlockBasic | null = null;
  lolessbl: BlockBasic | null = null;
  hieqbl: BlockBasic | null = null;
  hilesstrue: BlockBasic | null = null;
  hilessfalse: BlockBasic | null = null;
  hieqtrue: BlockBasic | null = null;
  hieqfalse: BlockBasic | null = null;
  lolesstrue: BlockBasic | null = null;
  lolessfalse: BlockBasic | null = null;
  hilessbool: PcodeOp | null = null;
  lolessbool: PcodeOp | null = null;
  hieqbool: PcodeOp | null = null;
  hiless: PcodeOp | null = null;
  hiequal: PcodeOp | null = null;
  loless: PcodeOp | null = null;
  vnhil1: Varnode | null = null;
  vnhil2: Varnode | null = null;
  vnhie1: Varnode | null = null;
  vnhie2: Varnode | null = null;
  vnlo1: Varnode | null = null;
  vnlo2: Varnode | null = null;
  hi: Varnode | null = null;
  lo: Varnode | null = null;
  hi2: Varnode | null = null;
  lo2: Varnode | null = null;
  hislot: number = 0;
  hiflip: boolean = false;
  equalflip: boolean = false;
  loflip: boolean = false;
  lolessiszerocomp: boolean = false;
  lolessequalform: boolean = false;
  hilessequalform: boolean = false;
  signcompare: boolean = false;
  midlessform: boolean = false;
  midlessequal: boolean = false;
  midsigncompare: boolean = false;
  hiconstform: boolean = false;
  midconstform: boolean = false;
  loconstform: boolean = false;
  hival: bigint = 0n;
  midval: bigint = 0n;
  loval: bigint = 0n;
  finalopc: OpCode = OpCode.CPUI_INT_EQUAL;

  // All methods are defined in part2 via prototype extension
  mapBlocksFromLow(lobl: BlockBasic): boolean { return false; }
  mapOpsFromBlocks(): boolean { return false; }
  checkSignedness(): boolean { return false; }
  normalizeHi(): boolean { return false; }
  normalizeMid(): boolean { return false; }
  normalizeLo(): boolean { return false; }
  checkBlockForm(): boolean { return false; }
  checkOpForm(): boolean { return false; }
  setOpCode(): void {}
  setBoolOp(): boolean { return false; }
  mapFromLow(op: PcodeOp): boolean { return false; }
  testReplace(): boolean { return false; }
  applyRule(i: SplitVarnode, loop: PcodeOp, workishi: boolean, data: Funcdata): boolean { return false; }
}

// =====================================================================
// LessConstForm class
// =====================================================================

export class LessConstForm {
  in: SplitVarnode = new SplitVarnode();
  vn: Varnode | null = null;
  cvn: Varnode | null = null;
  inslot: number = 0;
  signcompare: boolean = false;
  hilessequalform: boolean = false;
  constin: SplitVarnode = new SplitVarnode();

  // applyRule is defined in part2 via prototype extension
  applyRule(i: SplitVarnode, op: PcodeOp, workishi: boolean, data: Funcdata): boolean { return false; }
}

// =====================================================================
// ShiftForm class
// =====================================================================

export class ShiftForm {
  in: SplitVarnode = new SplitVarnode();
  opc: OpCode = OpCode.CPUI_COPY;
  loshift: PcodeOp | null = null;
  midshift: PcodeOp | null = null;
  hishift: PcodeOp | null = null;
  orop: PcodeOp | null = null;
  lo: Varnode | null = null;
  hi: Varnode | null = null;
  midlo: Varnode | null = null;
  midhi: Varnode | null = null;
  salo: Varnode | null = null;
  sahi: Varnode | null = null;
  samid: Varnode | null = null;
  reslo: Varnode | null = null;
  reshi: Varnode | null = null;
  out: SplitVarnode = new SplitVarnode();
  existop: PcodeOp | null = null;

  // All methods are defined in part2 via prototype extension
  verifyShiftAmount(): boolean { return false; }
  mapLeft(): boolean { return false; }
  mapRight(): boolean { return false; }
  verifyLeft(h: Varnode, l: Varnode, loop: PcodeOp): boolean { return false; }
  verifyRight(h: Varnode, l: Varnode, hiop: PcodeOp): boolean { return false; }
  applyRuleLeft(i: SplitVarnode, loop: PcodeOp, workishi: boolean, data: Funcdata): boolean { return false; }
  applyRuleRight(i: SplitVarnode, hiop: PcodeOp, workishi: boolean, data: Funcdata): boolean { return false; }
}

// =====================================================================
// MultForm class
// =====================================================================

export class MultForm {
  in: SplitVarnode = new SplitVarnode();
  add1: PcodeOp | null = null;
  add2: PcodeOp | null = null;
  subhi: PcodeOp | null = null;
  multlo: PcodeOp | null = null;
  multhi1: PcodeOp | null = null;
  multhi2: PcodeOp | null = null;
  midtmp: Varnode | null = null;
  lo1zext: Varnode | null = null;
  lo2zext: Varnode | null = null;
  hi1: Varnode | null = null;
  lo1: Varnode | null = null;
  hi2: Varnode | null = null;
  lo2: Varnode | null = null;
  reslo: Varnode | null = null;
  reshi: Varnode | null = null;
  outdoub: SplitVarnode = new SplitVarnode();
  in2: SplitVarnode = new SplitVarnode();
  existop: PcodeOp | null = null;

  // All methods are defined in part2 via prototype extension
  zextOf(big: Varnode, small: Varnode): boolean { return false; }
  mapResHi(rhi: Varnode): boolean { return false; }
  mapResHiSmallConst(rhi: Varnode): boolean { return false; }
  findLoFromIn(): boolean { return false; }
  findLoFromInSmallConst(): boolean { return false; }
  verifyLo(): boolean { return false; }
  findResLo(): boolean { return false; }
  mapFromIn(rhi: Varnode): boolean { return false; }
  mapFromInSmallConst(rhi: Varnode): boolean { return false; }
  replace(data: Funcdata): boolean { return false; }
  verify(h: Varnode, l: Varnode, hop: PcodeOp): boolean { return false; }
  applyRule(i: SplitVarnode, hop: PcodeOp, workishi: boolean, data: Funcdata): boolean { return false; }
}

// =====================================================================
// PhiForm class
// =====================================================================

export class PhiForm {
  in: SplitVarnode = new SplitVarnode();
  outvn: SplitVarnode = new SplitVarnode();
  inslot: number = 0;
  hibase: Varnode | null = null;
  lobase: Varnode | null = null;
  blbase: BlockBasic | null = null;
  lophi: PcodeOp | null = null;
  hiphi: PcodeOp | null = null;
  existop: PcodeOp | null = null;

  // verify and applyRule are defined in part2 via prototype extension
  verify(h: Varnode, l: Varnode, hphi: PcodeOp): boolean { return false; }
  applyRule(i: SplitVarnode, hphi: PcodeOp, workishi: boolean, data: Funcdata): boolean { return false; }
}

// =====================================================================
// IndirectForm class
// =====================================================================

export class IndirectForm {
  in: SplitVarnode = new SplitVarnode();
  outvn: SplitVarnode = new SplitVarnode();
  lo: Varnode | null = null;
  hi: Varnode | null = null;
  reslo: Varnode | null = null;
  reshi: Varnode | null = null;
  affector: PcodeOp | null = null;
  indhi: PcodeOp | null = null;
  indlo: PcodeOp | null = null;

  // verify and applyRule are defined in part2 via prototype extension
  verify(h: Varnode, l: Varnode, ihi: PcodeOp): boolean { return false; }
  applyRule(i: SplitVarnode, ind: PcodeOp, workishi: boolean, data: Funcdata): boolean { return false; }
}

// =====================================================================
// CopyForceForm class
// =====================================================================

/// Collapse two COPYs into contiguous address forced Varnodes.
///
/// The inputs must be pieces of a logical whole and outputs must be address forced with no descendants.
/// Take into account special form of COPYs holding global variables upto/past a RETURN.
export class CopyForceForm {
  in: SplitVarnode = new SplitVarnode();
  reslo: Varnode | null = null;
  reshi: Varnode | null = null;
  copylo: PcodeOp | null = null;
  copyhi: PcodeOp | null = null;
  addrOut: Address = new Address();

  // verify and applyRule are defined in part2 via prototype extension
  verify(h: Varnode, l: Varnode, w: Varnode | null, cpy: PcodeOp): boolean { return false; }
  applyRule(i: SplitVarnode, cpy: PcodeOp, workishi: boolean, data: Funcdata): boolean { return false; }
}

// =====================================================================
// RuleDoubleIn class
// =====================================================================

/// Simply a double precision operation, pushing down one level, starting from a marked double precision input.
export class RuleDoubleIn extends Rule {
  constructor(g: string) {
    super(g, 0, "doublein");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleDoubleIn(this.getGroup());
  }

  // reset, getOpList, attemptMarking, applyOp are defined in part2 via prototype extension
  reset(data: Funcdata): void {}
  getOpList(oplist: number[]): void {}
  attemptMarking(vn: Varnode, subpieceOp: PcodeOp): number { return 0; }
  applyOp(op: PcodeOp, data: Funcdata): number { return 0; }
}

// =====================================================================
// RuleDoubleOut class
// =====================================================================

/// Simplify a double precision operation, pulling back one level, starting from inputs to a PIECE operation.
export class RuleDoubleOut extends Rule {
  constructor(g: string) {
    super(g, 0, "doubleout");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleDoubleOut(this.getGroup());
  }

  // getOpList, attemptMarking, applyOp are defined in part2 via prototype extension
  getOpList(oplist: number[]): void {}
  attemptMarking(vnhi: Varnode, vnlo: Varnode, pieceOp: PcodeOp): number { return 0; }
  applyOp(op: PcodeOp, data: Funcdata): number { return 0; }
}

// =====================================================================
// RuleDoubleLoad class
// =====================================================================

/// Collapse contiguous loads: `x = CONCAT44(*(ptr+4),*ptr)  =>  x = *ptr`
export class RuleDoubleLoad extends Rule {
  constructor(g: string) {
    super(g, 0, "doubleload");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleDoubleLoad(this.getGroup());
  }

  // getOpList, applyOp are defined in part2 via prototype extension
  getOpList(oplist: number[]): void {}
  applyOp(op: PcodeOp, data: Funcdata): number { return 0; }

  static noWriteConflict(
    op1: PcodeOp, op2: PcodeOp, spc: AddrSpace, indirects: PcodeOp[] | null
  ): PcodeOp | null {
    // Stub - implemented in part2
    return null;
  }
}

// =====================================================================
// RuleDoubleStore class
// =====================================================================

/// Collapse contiguous stores: `*ptr = SUB(x,0); *(ptr + 4) = SUB(x,4)  =>  *ptr = x`
export class RuleDoubleStore extends Rule {
  constructor(g: string) {
    super(g, 0, "doublestore");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleDoubleStore(this.getGroup());
  }

  // getOpList, applyOp are defined in part2 via prototype extension
  getOpList(oplist: number[]): void {}
  applyOp(op: PcodeOp, data: Funcdata): number { return 0; }

  static testIndirectUse(op1: PcodeOp, op2: PcodeOp, indirects: PcodeOp[]): boolean {
    // Stub - implemented in part2
    return false;
  }

  static reassignIndirects(data: Funcdata, newStore: PcodeOp, indirects: PcodeOp[]): void {
    // Stub - implemented in part2
  }
}
// =====================================================================
// double_part2.ts - PART 2 of 2
// Translated from Ghidra's double.cc (approx lines 1800-3647)
// This file is appended to part 1; no imports or class field declarations.
// =====================================================================

// --- LogicalForm continued ---

// LogicalForm::applyRule
LogicalForm.prototype.applyRule = function (
  this: LogicalForm,
  i: SplitVarnode,
  lop: PcodeOp,
  workishi: boolean,
  data: Funcdata
): boolean {
  if (workishi) return false;
  if (!i.hasBothPieces()) return false;
  this.in = i;

  if (!this.verify(this.in.getHi()!, this.in.getLo()!, lop)) return false;

  this.outdoub.initPartial(this.in.getSize(), this.loop!.getOut()!, this.hiop!.getOut()!);
  this.indoub.initPartial(this.in.getSize(), this.lo2!, this.hi2!);
  if (this.indoub.exceedsConstPrecision()) return false;
  this.existop = SplitVarnode.prepareBinaryOp(this.outdoub, this.in, this.indoub);
  if (this.existop === null) return false;

  SplitVarnode.createBinaryOp(data, this.outdoub, this.in, this.indoub, this.existop, this.loop!.code());
  return true;
};

// --- Equal1Form ---

// Equal1Form::applyRule
//
// Given a known double precision input, look for double precision compares of the form
//   a == b,  a != b
// We look for
//     hibool = hi1 == hi2
//     lobool = lo1 == lo2
// each of the bools induces a CBRANCH
Equal1Form.prototype.applyRule = function (
  this: Equal1Form,
  i: SplitVarnode,
  hop: PcodeOp,
  workishi: boolean,
  data: Funcdata
): boolean {
  if (!workishi) return false;
  if (!i.hasBothPieces()) return false;
  this.in1 = i;

  this.hiop = hop;
  this.hi1 = this.in1.getHi()!;
  this.lo1 = this.in1.getLo()!;
  this.hi1slot = this.hiop.getSlot(this.hi1);
  this.hi2 = this.hiop.getIn(1 - this.hi1slot)!;
  this.notequalformhi = this.hiop.code() === CPUI_INT_NOTEQUAL;

  const descendants1 = this.lo1.descend;
  for (const loop of descendants1) {
    this.loop = loop;
    if (loop.code() === CPUI_INT_EQUAL) {
      this.notequalformlo = false;
    } else if (loop.code() === CPUI_INT_NOTEQUAL) {
      this.notequalformlo = true;
    } else {
      continue;
    }
    this.lo1slot = loop.getSlot(this.lo1);
    this.lo2 = loop.getIn(1 - this.lo1slot)!;

    const hiOutDescendants = this.hiop.getOut()!.descend;
    for (const hibool of hiOutDescendants) {
      this.hibool = hibool;
      const loOutDescendants = loop.getOut()!.descend;
      for (const lobool of loOutDescendants) {
        this.lobool = lobool;

        this.in2.initPartial(this.in1.getSize(), this.lo2, this.hi2);
        if (this.in2.exceedsConstPrecision()) continue;

        if (hibool.code() === CPUI_CBRANCH && lobool.code() === CPUI_CBRANCH) {
          // Branching form of the equal operation
          let hibooltrue: BlockBasic | null = null;
          let hiboolfalse: BlockBasic | null = null;
          let lobooltrue: BlockBasic | null = null;
          let loboolfalse: BlockBasic | null = null;

          ({ trueout: hibooltrue, falseout: hiboolfalse } = SplitVarnode.getTrueFalse(
            hibool,
            this.notequalformhi
          ));
          ({ trueout: lobooltrue, falseout: loboolfalse } = SplitVarnode.getTrueFalse(
            lobool,
            this.notequalformlo
          ));

          if (
            hibooltrue === lobool.getParent() &&
            hiboolfalse === loboolfalse &&
            SplitVarnode.otherwiseEmpty(lobool)
          ) {
            if (SplitVarnode.prepareBoolOp(this.in1, this.in2, hibool)) {
              this.setonlow = true;
              SplitVarnode.createBoolOp(
                data,
                hibool,
                this.in1,
                this.in2,
                this.notequalformhi ? CPUI_INT_NOTEQUAL : CPUI_INT_EQUAL
              );
              // We change lobool so that it always goes to the original TRUE block
              data.opSetInput(lobool, data.newConstant(1, this.notequalformlo ? 0n : 1n), 1);
              return true;
            }
          } else if (
            lobooltrue === hibool.getParent() &&
            hiboolfalse === loboolfalse &&
            SplitVarnode.otherwiseEmpty(hibool)
          ) {
            if (SplitVarnode.prepareBoolOp(this.in1, this.in2, lobool)) {
              this.setonlow = false;
              SplitVarnode.createBoolOp(
                data,
                lobool,
                this.in1,
                this.in2,
                this.notequalformlo ? CPUI_INT_NOTEQUAL : CPUI_INT_EQUAL
              );
              // We change hibool so that it always goes to the original TRUE block
              data.opSetInput(hibool, data.newConstant(1, this.notequalformhi ? 0n : 1n), 1);
              return true;
            }
          }
        }
      }
    }
  }
  return false;
};

// --- Equal2Form ---

// Equal2Form::replace
Equal2Form.prototype.replace = function (this: Equal2Form, data: Funcdata): boolean {
  if (this.hi2!.isConstant() && this.lo2!.isConstant()) {
    let val: bigint = this.hi2!.getOffset();
    val <<= BigInt(8 * this.lo1!.getSize());
    val |= this.lo2!.getOffset();
    this.param2.initPartial(this.in.getSize(), val);
    return SplitVarnode.prepareBoolOp(this.in, this.param2, this.boolAndOr!);
  }
  if (this.hi2!.isConstant() || this.lo2!.isConstant()) {
    // Some kind of mixed form
    return false;
  }
  this.param2.initPartial(this.in.getSize(), this.lo2!, this.hi2!);
  return SplitVarnode.prepareBoolOp(this.in, this.param2, this.boolAndOr!);
};

// Equal2Form::applyRule
//
// Given a known double precision input, look for double precision compares of the form
//   a == b,  a != b
// We look for
//     res = (hi1 == hi2) && (lo1 == lo2) or
//     res = (hi1 != hi2) || (lo1 != lo2)
Equal2Form.prototype.applyRule = function (
  this: Equal2Form,
  i: SplitVarnode,
  op: PcodeOp,
  workishi: boolean,
  data: Funcdata
): boolean {
  if (!workishi) return false;
  if (!i.hasBothPieces()) return false;
  this.in = i;
  this.hi1 = this.in.getHi()!;
  this.lo1 = this.in.getLo()!;
  const eqCode: OpCode = op.code();
  const hi1slot: number = op.getSlot(this.hi1);
  this.hi2 = op.getIn(1 - hi1slot)!;
  const outvn: Varnode = op.getOut()!;
  const descendants = outvn.descend;
  for (const boolAndOr of descendants) {
    this.boolAndOr = boolAndOr;
    if (eqCode === CPUI_INT_EQUAL && boolAndOr.code() !== CPUI_BOOL_AND) continue;
    if (eqCode === CPUI_INT_NOTEQUAL && boolAndOr.code() !== CPUI_BOOL_OR) continue;
    const slot: number = boolAndOr.getSlot(outvn);
    const othervn: Varnode = boolAndOr.getIn(1 - slot)!;
    if (!othervn.isWritten()) continue;
    const equalLo: PcodeOp = othervn.getDef()!;
    if (equalLo.code() !== eqCode) continue;
    if (equalLo.getIn(0) === this.lo1) {
      this.lo2 = equalLo.getIn(1)!;
    } else if (equalLo.getIn(1) === this.lo1) {
      this.lo2 = equalLo.getIn(0)!;
    } else {
      continue;
    }
    if (!this.replace(data)) continue;
    if (this.param2.exceedsConstPrecision()) continue;
    SplitVarnode.replaceBoolOp(data, boolAndOr, this.in, this.param2, eqCode);
    return true;
  }
  return false;
};

// --- Equal3Form ---

// Equal3Form::verify
Equal3Form.prototype.verify = function (
  this: Equal3Form,
  h: Varnode,
  l: Varnode,
  aop: PcodeOp
): boolean {
  if (aop.code() !== CPUI_INT_AND) return false;
  this.hi = h;
  this.lo = l;
  this.andop = aop;
  const hislot: number = this.andop.getSlot(this.hi);
  if (this.andop.getIn(1 - hislot) !== this.lo) return false; // hi and lo must be ANDed together
  this.compareop = this.andop.getOut()!.loneDescend();
  if (this.compareop === null) return false;
  if (this.compareop.code() !== CPUI_INT_EQUAL && this.compareop.code() !== CPUI_INT_NOTEQUAL)
    return false;
  const allonesval: bigint = calc_mask(this.lo.getSize());
  this.smallc = this.compareop.getIn(1)!;
  if (!this.smallc.isConstant()) return false;
  if (this.smallc.getOffset() !== allonesval) return false;
  return true;
};

// Equal3Form::applyRule
//
// Given a known double precision input, look for double precision compares of the form
//   a == -1,  a != -1
// We look for
//     hi & lo == -1
Equal3Form.prototype.applyRule = function (
  this: Equal3Form,
  i: SplitVarnode,
  op: PcodeOp,
  workishi: boolean,
  data: Funcdata
): boolean {
  if (!workishi) return false;
  if (!i.hasBothPieces()) return false;
  this.in = i;
  if (!this.verify(this.in.getHi()!, this.in.getLo()!, op)) return false;

  const in2 = new SplitVarnode(this.in.getSize(), calc_mask(this.in.getSize())); // Create the -1 value
  if (in2.exceedsConstPrecision()) return false;
  if (!SplitVarnode.prepareBoolOp(this.in, in2, this.compareop!)) return false;
  SplitVarnode.replaceBoolOp(data, this.compareop!, this.in, in2, this.compareop!.code());
  return true;
};

// --- LessThreeWay ---

// LessThreeWay::mapBlocksFromLow
LessThreeWay.prototype.mapBlocksFromLow = function (
  this: LessThreeWay,
  lobl: BlockBasic
): boolean {
  // Assuming lobl is the block containing the low precision test of a double precision lessthan
  // Map out all the blocks if possible, otherwise return false
  this.lolessbl = lobl;
  if (this.lolessbl.sizeIn() !== 1) return false;
  if (this.lolessbl.sizeOut() !== 2) return false;
  this.hieqbl = this.lolessbl.getIn(0) as BlockBasic;
  if (this.hieqbl.sizeIn() !== 1) return false;
  if (this.hieqbl.sizeOut() !== 2) return false;
  this.hilessbl = this.hieqbl.getIn(0) as BlockBasic;
  if (this.hilessbl.sizeOut() !== 2) return false;
  return true;
};

// LessThreeWay::mapOpsFromBlocks
LessThreeWay.prototype.mapOpsFromBlocks = function (this: LessThreeWay): boolean {
  this.lolessbool = this.lolessbl!.lastOp();
  if (this.lolessbool === null) return false;
  if (this.lolessbool.code() !== CPUI_CBRANCH) return false;
  this.hieqbool = this.hieqbl!.lastOp();
  if (this.hieqbool === null) return false;
  if (this.hieqbool.code() !== CPUI_CBRANCH) return false;
  this.hilessbool = this.hilessbl!.lastOp();
  if (this.hilessbool === null) return false;
  if (this.hilessbool.code() !== CPUI_CBRANCH) return false;

  let vn: Varnode;

  this.hiflip = false;
  this.equalflip = false;
  this.loflip = false;
  this.midlessform = false;
  this.lolessiszerocomp = false;

  vn = this.hieqbool.getIn(1)!;
  if (!vn.isWritten()) return false;
  this.hiequal = vn.getDef()!;
  switch (this.hiequal!.code()) {
    case CPUI_INT_EQUAL:
      this.midlessform = false;
      break;
    case CPUI_INT_NOTEQUAL:
      this.midlessform = false;
      break;
    case CPUI_INT_LESS:
      this.midlessequal = false;
      this.midsigncompare = false;
      this.midlessform = true;
      break;
    case CPUI_INT_LESSEQUAL:
      this.midlessequal = true;
      this.midsigncompare = false;
      this.midlessform = true;
      break;
    case CPUI_INT_SLESS:
      this.midlessequal = false;
      this.midsigncompare = true;
      this.midlessform = true;
      break;
    case CPUI_INT_SLESSEQUAL:
      this.midlessequal = true;
      this.midsigncompare = true;
      this.midlessform = true;
      break;
    default:
      return false;
  }

  vn = this.lolessbool.getIn(1)!;
  if (!vn.isWritten()) return false;
  this.loless = vn.getDef()!;
  switch (this.loless!.code()) {
    // Only unsigned forms
    case CPUI_INT_LESS:
      this.lolessequalform = false;
      break;
    case CPUI_INT_LESSEQUAL:
      this.lolessequalform = true;
      break;
    case CPUI_INT_EQUAL:
      if (!this.loless!.getIn(1)!.isConstant()) return false;
      if (this.loless!.getIn(1)!.getOffset() !== 0n) return false;
      this.lolessiszerocomp = true;
      this.lolessequalform = true;
      break;
    case CPUI_INT_NOTEQUAL:
      if (!this.loless!.getIn(1)!.isConstant()) return false;
      if (this.loless!.getIn(1)!.getOffset() !== 0n) return false;
      this.lolessiszerocomp = true;
      this.lolessequalform = false;
      break;
    default:
      return false;
  }

  vn = this.hilessbool!.getIn(1)!;
  if (!vn.isWritten()) return false;
  this.hiless = vn.getDef()!;
  switch (this.hiless!.code()) {
    case CPUI_INT_LESS:
      this.hilessequalform = false;
      this.signcompare = false;
      break;
    case CPUI_INT_LESSEQUAL:
      this.hilessequalform = true;
      this.signcompare = false;
      break;
    case CPUI_INT_SLESS:
      this.hilessequalform = false;
      this.signcompare = true;
      break;
    case CPUI_INT_SLESSEQUAL:
      this.hilessequalform = true;
      this.signcompare = true;
      break;
    default:
      return false;
  }
  return true;
};

// LessThreeWay::checkSignedness
LessThreeWay.prototype.checkSignedness = function (this: LessThreeWay): boolean {
  if (this.midlessform) {
    if (this.midsigncompare !== this.signcompare) return false;
  }
  return true;
};

// LessThreeWay::normalizeHi
LessThreeWay.prototype.normalizeHi = function (this: LessThreeWay): boolean {
  let tmpvn: Varnode;
  this.vnhil1 = this.hiless!.getIn(0)!;
  this.vnhil2 = this.hiless!.getIn(1)!;
  if (this.vnhil1.isConstant()) {
    // Start with constant on the right
    this.hiflip = !this.hiflip;
    this.hilessequalform = !this.hilessequalform;
    tmpvn = this.vnhil1;
    this.vnhil1 = this.vnhil2;
    this.vnhil2 = tmpvn;
  }
  this.hiconstform = false;
  if (this.vnhil2.isConstant()) {
    if (this.in.getSize() > 8) return false; // Must have enough precision for constant (sizeof(uintb))
    this.hiconstform = true;
    this.hival = this.vnhil2.getOffset();
    ({ trueout: this.hilesstrue, falseout: this.hilessfalse } = SplitVarnode.getTrueFalse(
      this.hilessbool!,
      this.hiflip
    ));
    let inc: bigint = 1n;
    if (this.hilessfalse !== this.hieqbl) {
      // Make sure the hiless false branch goes to the hieq block
      this.hiflip = !this.hiflip;
      this.hilessequalform = !this.hilessequalform;
      tmpvn = this.vnhil1;
      this.vnhil1 = this.vnhil2;
      this.vnhil2 = tmpvn;
      inc = -1n;
    }
    if (this.hilessequalform) {
      // Make sure to normalize lessequal to less
      this.hival += inc;
      this.hival &= calc_mask(this.in.getSize());
      this.hilessequalform = false;
    }
    this.hival >>= BigInt(this.in.getLo()!.getSize() * 8);
  } else {
    if (this.hilessequalform) {
      // Make sure the false branch contains the equal case
      this.hilessequalform = false;
      this.hiflip = !this.hiflip;
      tmpvn = this.vnhil1;
      this.vnhil1 = this.vnhil2;
      this.vnhil2 = tmpvn;
    }
  }
  return true;
};

// LessThreeWay::normalizeMid
LessThreeWay.prototype.normalizeMid = function (this: LessThreeWay): boolean {
  let tmpvn: Varnode;
  this.vnhie1 = this.hiequal!.getIn(0)!;
  this.vnhie2 = this.hiequal!.getIn(1)!;
  if (this.vnhie1.isConstant()) {
    // Make sure constant is on the right
    tmpvn = this.vnhie1;
    this.vnhie1 = this.vnhie2;
    this.vnhie2 = tmpvn;
    if (this.midlessform) {
      this.equalflip = !this.equalflip;
      this.midlessequal = !this.midlessequal;
    }
  }
  this.midconstform = false;
  if (this.vnhie2.isConstant()) {
    if (!this.hiconstform) return false; // If mid is constant, both mid and hi must be constant
    this.midconstform = true;
    this.midval = this.vnhie2.getOffset();
    if (this.vnhie2.getSize() === this.in.getSize()) {
      // Convert to comparison on high part
      const lopart: bigint = this.midval & calc_mask(this.in.getLo()!.getSize());
      this.midval >>= BigInt(this.in.getLo()!.getSize() * 8);
      if (this.midlessform) {
        if (this.midlessequal) {
          if (lopart !== calc_mask(this.in.getLo()!.getSize())) return false;
        } else {
          if (lopart !== 0n) return false;
        }
      } else {
        return false; // Compare is forcing restriction on lo part
      }
    }
    if (this.midval !== this.hival) {
      // If the mid and hi don't match
      if (!this.midlessform) return false;
      this.midval += this.midlessequal ? 1n : -1n;
      this.midval &= calc_mask(this.in.getLo()!.getSize());
      this.midlessequal = !this.midlessequal;
      if (this.midval !== this.hival) return false; // Last chance
    }
  }
  if (this.midlessform) {
    // Normalize to EQUAL
    if (!this.midlessequal) {
      this.equalflip = !this.equalflip;
    }
  } else {
    if (this.hiequal!.code() === CPUI_INT_NOTEQUAL) {
      this.equalflip = !this.equalflip;
    }
  }
  return true;
};

// LessThreeWay::normalizeLo
LessThreeWay.prototype.normalizeLo = function (this: LessThreeWay): boolean {
  // This is basically identical to normalizeHi
  let tmpvn: Varnode;
  this.vnlo1 = this.loless!.getIn(0)!;
  this.vnlo2 = this.loless!.getIn(1)!;
  if (this.lolessiszerocomp) {
    this.loconstform = true;
    if (this.lolessequalform) {
      // Treat as if we see vnlo1 <= 0
      this.loval = 1n;
      this.lolessequalform = false;
    } else {
      // Treat as if we see 0 < vnlo1
      this.loflip = !this.loflip;
      this.loval = 1n;
    }
    return true;
  }
  if (this.vnlo1.isConstant()) {
    // Make sure constant is on the right
    this.loflip = !this.loflip;
    this.lolessequalform = !this.lolessequalform;
    tmpvn = this.vnlo1;
    this.vnlo1 = this.vnlo2;
    this.vnlo2 = tmpvn;
  }
  this.loconstform = false;
  if (this.vnlo2.isConstant()) {
    // Make sure normalize lessequal to less
    this.loconstform = true;
    this.loval = this.vnlo2.getOffset();
    if (this.lolessequalform) {
      this.loval += 1n;
      this.loval &= calc_mask(this.vnlo2.getSize());
      this.lolessequalform = false;
    }
  } else {
    if (this.lolessequalform) {
      this.lolessequalform = false;
      this.loflip = !this.loflip;
      tmpvn = this.vnlo1;
      this.vnlo1 = this.vnlo2;
      this.vnlo2 = tmpvn;
    }
  }
  return true;
};

// LessThreeWay::checkBlockForm
LessThreeWay.prototype.checkBlockForm = function (this: LessThreeWay): boolean {
  ({ trueout: this.hilesstrue, falseout: this.hilessfalse } = SplitVarnode.getTrueFalse(
    this.hilessbool!,
    this.hiflip
  ));
  ({ trueout: this.lolesstrue, falseout: this.lolessfalse } = SplitVarnode.getTrueFalse(
    this.lolessbool!,
    this.loflip
  ));
  ({ trueout: this.hieqtrue, falseout: this.hieqfalse } = SplitVarnode.getTrueFalse(
    this.hieqbool!,
    this.equalflip
  ));
  if (
    this.hilesstrue === this.lolesstrue &&
    this.hieqfalse === this.lolessfalse &&
    this.hilessfalse === this.hieqbl &&
    this.hieqtrue === this.lolessbl
  ) {
    if (SplitVarnode.otherwiseEmpty(this.hieqbool!) && SplitVarnode.otherwiseEmpty(this.lolessbool!))
      return true;
  }
  return false;
};

// LessThreeWay::checkOpForm
LessThreeWay.prototype.checkOpForm = function (this: LessThreeWay): boolean {
  this.lo = this.in.getLo();
  this.hi = this.in.getHi();

  if (this.midconstform) {
    if (!this.hiconstform) return false;
    if (this.vnhie2!.getSize() === this.in.getSize()) {
      if (this.vnhie1 !== this.vnhil1 && this.vnhie1 !== this.vnhil2) return false;
    } else {
      if (this.vnhie1 !== this.in.getHi()) return false;
    }
    // normalizeMid checks that midval == hival
  } else {
    // hi and hi2 must appear as inputs in both hiless and hiequal
    if (this.vnhil1 !== this.vnhie1 && this.vnhil1 !== this.vnhie2) return false;
    if (this.vnhil2 !== this.vnhie1 && this.vnhil2 !== this.vnhie2) return false;
  }
  if (this.hi !== null && this.hi === this.vnhil1) {
    if (this.hiconstform) return false;
    this.hislot = 0;
    this.hi2 = this.vnhil2!;
    if (this.vnlo1 !== this.lo) {
      // Pieces must be on the same side
      let tmpvn: Varnode = this.vnlo1!;
      this.vnlo1 = this.vnlo2;
      this.vnlo2 = tmpvn;
      if (this.vnlo1 !== this.lo) return false;
      this.loflip = !this.loflip;
      this.lolessequalform = !this.lolessequalform;
    }
    this.lo2 = this.vnlo2!;
  } else if (this.hi !== null && this.hi === this.vnhil2) {
    if (this.hiconstform) return false;
    this.hislot = 1;
    this.hi2 = this.vnhil1!;
    if (this.vnlo2 !== this.lo) {
      let tmpvn: Varnode = this.vnlo1!;
      this.vnlo1 = this.vnlo2;
      this.vnlo2 = tmpvn;
      if (this.vnlo2 !== this.lo) return false;
      this.loflip = !this.loflip;
      this.lolessequalform = !this.lolessequalform;
    }
    this.lo2 = this.vnlo1!;
  } else if (this.in.getWhole() === this.vnhil1) {
    if (!this.hiconstform) return false;
    if (!this.loconstform) return false;
    if (this.vnlo1 !== this.lo) return false;
    this.hislot = 0;
  } else if (this.in.getWhole() === this.vnhil2) {
    // Whole constant appears on the left
    if (!this.hiconstform) return false;
    if (!this.loconstform) return false;
    if (this.vnlo2 !== this.lo) {
      this.loflip = !this.loflip;
      this.loval -= 1n;
      this.loval &= calc_mask(this.lo!.getSize());
      if (this.vnlo1 !== this.lo) return false;
    }
    this.hislot = 1;
  } else {
    return false;
  }
  return true;
};

// LessThreeWay::setOpCode
LessThreeWay.prototype.setOpCode = function (this: LessThreeWay): void {
  // Decide on the opcode of the final double precision compare
  if (this.lolessequalform !== this.hiflip) {
    this.finalopc = this.signcompare ? CPUI_INT_SLESSEQUAL : CPUI_INT_LESSEQUAL;
  } else {
    this.finalopc = this.signcompare ? CPUI_INT_SLESS : CPUI_INT_LESS;
  }
  if (this.hiflip) {
    this.hislot = 1 - this.hislot;
    this.hiflip = false;
  }
};

// LessThreeWay::setBoolOp
LessThreeWay.prototype.setBoolOp = function (this: LessThreeWay): boolean {
  // Make changes to the threeway branch so that it becomes a single double precision branch
  if (this.hislot === 0) {
    if (SplitVarnode.prepareBoolOp(this.in, this.in2, this.hilessbool!)) return true;
  } else {
    if (SplitVarnode.prepareBoolOp(this.in2, this.in, this.hilessbool!)) return true;
  }
  return false;
};

// LessThreeWay::mapFromLow
LessThreeWay.prototype.mapFromLow = function (this: LessThreeWay, op: PcodeOp): boolean {
  // Given the less than comparison for the lo piece and an input varnode explicitly marked
  // as isPrecisLo, try to map out the threeway lessthan form
  const loop: PcodeOp | null = op.getOut()!.loneDescend();
  if (loop === null) return false;
  if (!this.mapBlocksFromLow(loop.getParent()! as BlockBasic)) return false;
  if (!this.mapOpsFromBlocks()) return false;
  if (!this.checkSignedness()) return false;
  if (!this.normalizeHi()) return false;
  if (!this.normalizeMid()) return false;
  if (!this.normalizeLo()) return false;
  if (!this.checkOpForm()) return false;
  if (!this.checkBlockForm()) return false;
  return true;
};

// LessThreeWay::testReplace
LessThreeWay.prototype.testReplace = function (this: LessThreeWay): boolean {
  this.setOpCode();
  if (this.hiconstform) {
    this.in2.initPartial(
      this.in.getSize(),
      (this.hival << BigInt(8 * this.in.getLo()!.getSize())) | this.loval
    );
    if (!this.setBoolOp()) return false;
  } else {
    this.in2.initPartial(this.in.getSize(), this.lo2!, this.hi2!);
    if (!this.setBoolOp()) return false;
  }
  return true;
};

// LessThreeWay::applyRule
//
// Given a known double precision input, look for double precision less than forms, i.e.
//    a < b,   a s< b,  a <= b,   a s<= b
LessThreeWay.prototype.applyRule = function (
  this: LessThreeWay,
  i: SplitVarnode,
  loop: PcodeOp,
  workishi: boolean,
  data: Funcdata
): boolean {
  if (workishi) return false;
  if (i.getLo() === null) return false; // Doesn't necessarily need the hi
  this.in = i;
  if (!this.mapFromLow(loop)) return false;
  const res: boolean = this.testReplace();
  if (res) {
    if (this.in2.exceedsConstPrecision()) return false;
    if (this.hislot === 0) {
      SplitVarnode.createBoolOp(data, this.hilessbool!, this.in, this.in2, this.finalopc);
    } else {
      SplitVarnode.createBoolOp(data, this.hilessbool!, this.in2, this.in, this.finalopc);
    }
    // We change hieqbool so that it always goes to the original FALSE block
    data.opSetInput(this.hieqbool!, data.newConstant(1, this.equalflip ? 1n : 0n), 1);
    // The lolessbool block now becomes unreachable and is eventually removed
  }
  return res;
};

// --- LessConstForm ---

// LessConstForm::applyRule
//
// Sometimes double precision compares only involve the high portion of the value.
// The canonical example being determining whether val > 0, where we only have to
// calculate (hi > 0).  This rule takes
//    hi COMPARE #const
// and transforms it to
//    whole COMPARE #constextend
LessConstForm.prototype.applyRule = function (
  this: LessConstForm,
  i: SplitVarnode,
  op: PcodeOp,
  workishi: boolean,
  data: Funcdata
): boolean {
  if (!workishi) return false;
  if (i.getHi() === null) return false; // We don't necessarily need the lo part
  this.in = i;
  this.vn = this.in.getHi()!;
  this.inslot = op.getSlot(this.vn);
  this.cvn = op.getIn(1 - this.inslot)!;
  const losize: number = this.in.getSize() - this.vn.getSize();

  if (!this.cvn.isConstant()) return false;

  this.signcompare =
    op.code() === CPUI_INT_SLESSEQUAL || op.code() === CPUI_INT_SLESS;
  this.hilessequalform =
    op.code() === CPUI_INT_SLESSEQUAL || op.code() === CPUI_INT_LESSEQUAL;

  let val: bigint = this.cvn.getOffset() << BigInt(8 * losize);
  if (this.hilessequalform !== (this.inslot === 1)) {
    val |= calc_mask(losize);
  }

  // This rule can apply and mess up less,equal rules, so we only apply it if it directly affects a branch
  const desc: PcodeOp | null = op.getOut()!.loneDescend();
  if (desc === null) return false;
  if (desc.code() !== CPUI_CBRANCH) return false;

  this.constin.initPartial(this.in.getSize(), val);
  if (this.constin.exceedsConstPrecision()) return false;

  if (this.inslot === 0) {
    if (SplitVarnode.prepareBoolOp(this.in, this.constin, op)) {
      SplitVarnode.replaceBoolOp(data, op, this.in, this.constin, op.code());
      return true;
    }
  } else {
    if (SplitVarnode.prepareBoolOp(this.constin, this.in, op)) {
      SplitVarnode.replaceBoolOp(data, op, this.constin, this.in, op.code());
      return true;
    }
  }
  return false;
};

// --- ShiftForm ---

// ShiftForm::mapLeft
ShiftForm.prototype.mapLeft = function (this: ShiftForm): boolean {
  // Assume reshi, reslo are filled in, fill in other ops and varnodes
  if (!this.reslo!.isWritten()) return false;
  if (!this.reshi!.isWritten()) return false;
  this.loshift = this.reslo!.getDef()!;
  this.opc = this.loshift!.code();
  if (this.opc !== CPUI_INT_LEFT) return false;
  this.orop = this.reshi!.getDef()!;
  if (
    this.orop!.code() !== CPUI_INT_OR &&
    this.orop!.code() !== CPUI_INT_XOR &&
    this.orop!.code() !== CPUI_INT_ADD
  )
    return false;
  this.midlo = this.orop!.getIn(0)!;
  this.midhi = this.orop!.getIn(1)!;
  if (!this.midlo.isWritten()) return false;
  if (!this.midhi.isWritten()) return false;
  if (this.midhi.getDef()!.code() !== CPUI_INT_LEFT) {
    const tmpvn: Varnode = this.midhi;
    this.midhi = this.midlo;
    this.midlo = tmpvn;
  }
  this.midshift = this.midlo.getDef()!;
  if (this.midshift!.code() !== CPUI_INT_RIGHT) return false; // Must be unsigned RIGHT
  this.hishift = this.midhi.getDef()!;
  if (this.hishift!.code() !== CPUI_INT_LEFT) return false;

  if (this.lo !== this.loshift!.getIn(0)) return false;
  if (this.hi !== this.hishift!.getIn(0)) return false;
  if (this.lo !== this.midshift!.getIn(0)) return false;
  this.salo = this.loshift!.getIn(1)!;
  this.sahi = this.hishift!.getIn(1)!;
  this.samid = this.midshift!.getIn(1)!;
  return true;
};

// ShiftForm::mapRight
ShiftForm.prototype.mapRight = function (this: ShiftForm): boolean {
  // Assume reshi, reslo are filled in, fill in other ops and varnodes
  if (!this.reslo!.isWritten()) return false;
  if (!this.reshi!.isWritten()) return false;
  this.hishift = this.reshi!.getDef()!;
  this.opc = this.hishift!.code();
  if (this.opc !== CPUI_INT_RIGHT && this.opc !== CPUI_INT_SRIGHT) return false;
  this.orop = this.reslo!.getDef()!;
  if (
    this.orop!.code() !== CPUI_INT_OR &&
    this.orop!.code() !== CPUI_INT_XOR &&
    this.orop!.code() !== CPUI_INT_ADD
  )
    return false;
  this.midlo = this.orop!.getIn(0)!;
  this.midhi = this.orop!.getIn(1)!;
  if (!this.midlo.isWritten()) return false;
  if (!this.midhi.isWritten()) return false;
  if (this.midlo.getDef()!.code() !== CPUI_INT_RIGHT) {
    // Must be unsigned RIGHT
    const tmpvn: Varnode = this.midhi;
    this.midhi = this.midlo;
    this.midlo = tmpvn;
  }
  this.midshift = this.midhi.getDef()!;
  if (this.midshift!.code() !== CPUI_INT_LEFT) return false;
  this.loshift = this.midlo.getDef()!;
  if (this.loshift!.code() !== CPUI_INT_RIGHT) return false; // Must be unsigned RIGHT

  if (this.lo !== this.loshift!.getIn(0)) return false;
  if (this.hi !== this.hishift!.getIn(0)) return false;
  if (this.hi !== this.midshift!.getIn(0)) return false;
  this.salo = this.loshift!.getIn(1)!;
  this.sahi = this.hishift!.getIn(1)!;
  this.samid = this.midshift!.getIn(1)!;
  return true;
};

// ShiftForm::verifyShiftAmount
ShiftForm.prototype.verifyShiftAmount = function (this: ShiftForm): boolean {
  // Make sure all the shift amount varnodes are consistent
  if (!this.salo!.isConstant()) return false;
  if (!this.samid!.isConstant()) return false;
  if (!this.sahi!.isConstant()) return false;
  const val: bigint = this.salo!.getOffset();
  if (val !== this.sahi!.getOffset()) return false;
  if (val >= BigInt(8 * this.lo!.getSize())) return false; // If shift amount is so big, we would not use this form
  const complementVal: bigint = BigInt(8 * this.lo!.getSize()) - val;
  if (this.samid!.getOffset() !== complementVal) return false;
  return true;
};

// ShiftForm::verifyLeft
ShiftForm.prototype.verifyLeft = function (
  this: ShiftForm,
  h: Varnode,
  l: Varnode,
  loop: PcodeOp
): boolean {
  this.hi = h;
  this.lo = l;

  this.loshift = loop;
  this.reslo = this.loshift.getOut()!;

  const hiDescendants = this.hi.descend;
  for (const hishift of hiDescendants) {
    this.hishift = hishift;
    if (hishift.code() !== CPUI_INT_LEFT) continue;
    const outvn: Varnode = hishift.getOut()!;
    const outvnDescendants = outvn.descend;
    for (const midshift of outvnDescendants) {
      this.midshift = midshift;
      const tmpvn: Varnode | null = midshift.getOut();
      if (tmpvn === null) continue;
      this.reshi = tmpvn;
      if (!this.mapLeft()) continue;
      if (!this.verifyShiftAmount()) continue;
      return true;
    }
  }
  return false;
};

// ShiftForm::verifyRight
ShiftForm.prototype.verifyRight = function (
  this: ShiftForm,
  h: Varnode,
  l: Varnode,
  hiop: PcodeOp
): boolean {
  this.hi = h;
  this.lo = l;
  this.hishift = hiop;
  this.reshi = hiop.getOut()!;

  const loDescendants = this.lo.descend;
  for (const loshift of loDescendants) {
    this.loshift = loshift;
    if (loshift.code() !== CPUI_INT_RIGHT) continue;
    const outvn: Varnode = loshift.getOut()!;
    const outvnDescendants = outvn.descend;
    for (const midshift of outvnDescendants) {
      this.midshift = midshift;
      const tmpvn: Varnode | null = midshift.getOut();
      if (tmpvn === null) continue;
      this.reslo = tmpvn;
      if (!this.mapRight()) continue;
      if (!this.verifyShiftAmount()) continue;
      return true;
    }
  }
  return false;
};

// ShiftForm::applyRuleLeft
ShiftForm.prototype.applyRuleLeft = function (
  this: ShiftForm,
  i: SplitVarnode,
  loop: PcodeOp,
  workishi: boolean,
  data: Funcdata
): boolean {
  if (workishi) return false;
  if (!i.hasBothPieces()) return false;
  this.in = i;

  if (!this.verifyLeft(this.in.getHi()!, this.in.getLo()!, loop)) return false;

  this.out.initPartial(this.in.getSize(), this.reslo!, this.reshi!);
  this.existop = SplitVarnode.prepareShiftOp(this.out, this.in);
  if (this.existop === null) return false;
  SplitVarnode.createShiftOp(data, this.out, this.in, this.salo!, this.existop, this.opc);
  return true;
};

// ShiftForm::applyRuleRight
ShiftForm.prototype.applyRuleRight = function (
  this: ShiftForm,
  i: SplitVarnode,
  hiop: PcodeOp,
  workishi: boolean,
  data: Funcdata
): boolean {
  if (!workishi) return false;
  if (!i.hasBothPieces()) return false;
  this.in = i;

  if (!this.verifyRight(this.in.getHi()!, this.in.getLo()!, hiop)) return false;

  this.out.initPartial(this.in.getSize(), this.reslo!, this.reshi!);
  this.existop = SplitVarnode.prepareShiftOp(this.out, this.in);
  if (this.existop === null) return false;
  SplitVarnode.createShiftOp(data, this.out, this.in, this.salo!, this.existop, this.opc);
  return true;
};

// --- MultForm ---

// MultForm::mapResHiSmallConst
MultForm.prototype.mapResHiSmallConst = function (this: MultForm, rhi: Varnode): boolean {
  // find reshi=hi1*lo2 + (tmp>>32)
  this.reshi = rhi;
  if (!this.reshi.isWritten()) return false;
  this.add1 = this.reshi.getDef()!;
  if (this.add1!.code() !== CPUI_INT_ADD) return false;
  let ad1: Varnode = this.add1!.getIn(0)!;
  let ad2: Varnode = this.add1!.getIn(1)!;
  if (!ad1.isWritten()) return false;
  if (!ad2.isWritten()) return false;
  this.multhi1 = ad1.getDef()!;
  if (this.multhi1!.code() !== CPUI_INT_MULT) {
    this.subhi = this.multhi1;
    this.multhi1 = ad2.getDef()!;
  } else {
    this.subhi = ad2.getDef()!;
  }
  if (this.multhi1!.code() !== CPUI_INT_MULT) return false;
  if (this.subhi!.code() !== CPUI_SUBPIECE) return false;
  this.midtmp = this.subhi!.getIn(0)!;
  if (!this.midtmp!.isWritten()) return false;
  this.multlo = this.midtmp!.getDef()!;
  if (this.multlo!.code() !== CPUI_INT_MULT) return false;
  this.lo1zext = this.multlo!.getIn(0)!;
  this.lo2zext = this.multlo!.getIn(1)!;
  return true;
};

// MultForm::mapResHi
MultForm.prototype.mapResHi = function (this: MultForm, rhi: Varnode): boolean {
  // Find reshi=hi1*lo2 + hi2*lo1 + (tmp>>32)
  this.reshi = rhi;
  if (!this.reshi.isWritten()) return false;
  this.add1 = this.reshi.getDef()!;
  if (this.add1!.code() !== CPUI_INT_ADD) return false;
  let ad1: Varnode = this.add1!.getIn(0)!;
  let ad2: Varnode = this.add1!.getIn(1)!;
  let ad3: Varnode;
  if (!ad1.isWritten()) return false;
  if (!ad2.isWritten()) return false;
  this.add2 = ad1.getDef()!;
  if (this.add2!.code() === CPUI_INT_ADD) {
    ad1 = this.add2!.getIn(0)!;
    ad3 = this.add2!.getIn(1)!;
  } else {
    this.add2 = ad2.getDef()!;
    if (this.add2!.code() !== CPUI_INT_ADD) return false;
    ad2 = this.add2!.getIn(0)!;
    ad3 = this.add2!.getIn(1)!;
  }
  if (!ad1.isWritten()) return false;
  if (!ad2.isWritten()) return false;
  if (!ad3.isWritten()) return false;
  this.subhi = ad1.getDef()!;
  if (this.subhi!.code() === CPUI_SUBPIECE) {
    this.multhi1 = ad2.getDef()!;
    this.multhi2 = ad3.getDef()!;
  } else {
    this.subhi = ad2.getDef()!;
    if (this.subhi!.code() === CPUI_SUBPIECE) {
      this.multhi1 = ad1.getDef()!;
      this.multhi2 = ad3.getDef()!;
    } else {
      this.subhi = ad3.getDef()!;
      if (this.subhi!.code() === CPUI_SUBPIECE) {
        this.multhi1 = ad1.getDef()!;
        this.multhi2 = ad2.getDef()!;
      } else {
        return false;
      }
    }
  }
  if (this.multhi1!.code() !== CPUI_INT_MULT) return false;
  if (this.multhi2!.code() !== CPUI_INT_MULT) return false;

  this.midtmp = this.subhi!.getIn(0)!;
  if (!this.midtmp!.isWritten()) return false;
  this.multlo = this.midtmp!.getDef()!;
  if (this.multlo!.code() !== CPUI_INT_MULT) return false;
  this.lo1zext = this.multlo!.getIn(0)!;
  this.lo2zext = this.multlo!.getIn(1)!;
  return true;
};

// MultForm::findLoFromInSmallConst
MultForm.prototype.findLoFromInSmallConst = function (this: MultForm): boolean {
  // Assuming we have multhi1, lo1, and hi1 in hand, try to label lo2
  const vn1: Varnode = this.multhi1!.getIn(0)!;
  const vn2: Varnode = this.multhi1!.getIn(1)!;
  if (vn1 === this.hi1) {
    this.lo2 = vn2;
  } else if (vn2 === this.hi1) {
    this.lo2 = vn1;
  } else {
    return false;
  }
  if (!this.lo2!.isConstant()) return false;
  this.hi2 = null; // hi2 is an implied zero in this case
  return true;
};

// MultForm::findLoFromIn
MultForm.prototype.findLoFromIn = function (this: MultForm): boolean {
  // Assuming we have multhi1, multhi2, lo1, and hi1 in hand, try to label lo2/hi2 pair
  let vn1: Varnode = this.multhi1!.getIn(0)!;
  let vn2: Varnode = this.multhi1!.getIn(1)!;
  if (vn1 !== this.lo1 && vn2 !== this.lo1) {
    // Try to normalize so multhi1 contains lo1
    const tmpop: PcodeOp = this.multhi1!;
    this.multhi1 = this.multhi2!;
    this.multhi2 = tmpop;
    vn1 = this.multhi1!.getIn(0)!;
    vn2 = this.multhi1!.getIn(1)!;
  }
  if (vn1 === this.lo1) {
    this.hi2 = vn2;
  } else if (vn2 === this.lo1) {
    this.hi2 = vn1;
  } else {
    return false;
  }
  vn1 = this.multhi2!.getIn(0)!; // multhi2 should contain hi1 and lo2
  vn2 = this.multhi2!.getIn(1)!;
  if (vn1 === this.hi1) {
    this.lo2 = vn2;
  } else if (vn2 === this.hi1) {
    this.lo2 = vn1;
  } else {
    return false;
  }
  return true;
};

// MultForm::zextOf
MultForm.prototype.zextOf = function (this: MultForm, big: Varnode, small: Varnode): boolean {
  // Verify that big is (some form of) a zero extension of small
  let op: PcodeOp;
  if (small.isConstant()) {
    if (!big.isConstant()) return false;
    if (big.getOffset() === small.getOffset()) return true;
    return false;
  }
  if (!big.isWritten()) return false;
  op = big.getDef()!;
  if (op.code() === CPUI_INT_ZEXT) return op.getIn(0) === small;
  if (op.code() === CPUI_INT_AND) {
    if (!op.getIn(1)!.isConstant()) return false;
    if (op.getIn(1)!.getOffset() !== calc_mask(small.getSize())) return false;
    const whole: Varnode = op.getIn(0)!;
    if (!small.isWritten()) return false;
    const sub: PcodeOp = small.getDef()!;
    if (sub.code() !== CPUI_SUBPIECE) return false;
    return sub.getIn(0) === whole;
  }
  return false;
};

// MultForm::verifyLo
MultForm.prototype.verifyLo = function (this: MultForm): boolean {
  // Given we have labelled lo1/hi1 lo2/hi2, make sure midtmp is formed properly
  // This also works for the small constant model lo1/hi1 and lo2 const.
  if (this.subhi!.getIn(1)!.getOffset() !== BigInt(this.lo1!.getSize())) return false;
  if (this.zextOf(this.lo1zext!, this.lo1!)) {
    if (this.zextOf(this.lo2zext!, this.lo2!)) return true;
  } else if (this.zextOf(this.lo1zext!, this.lo2!)) {
    if (this.zextOf(this.lo2zext!, this.lo1!)) return true;
  }
  return false;
};

// MultForm::findResLo
MultForm.prototype.findResLo = function (this: MultForm): boolean {
  // Assuming we found midtmp, find potential reslo
  const midDescendants = this.midtmp!.descend;
  for (const op of midDescendants) {
    if (op.code() !== CPUI_SUBPIECE) continue;
    if (op.getIn(1)!.getOffset() !== 0n) continue; // Must grab low bytes
    this.reslo = op.getOut()!;
    if (this.reslo!.getSize() !== this.lo1!.getSize()) continue;
    return true;
  }
  // If we reach here, it may be that separate multiplies of lo1*lo2 were used for reshi and reslo
  const lo1Descendants = this.lo1!.descend;
  for (const op of lo1Descendants) {
    if (op.code() !== CPUI_INT_MULT) continue;
    const vn1: Varnode = op.getIn(0)!;
    const vn2: Varnode = op.getIn(1)!;
    if (this.lo2!.isConstant()) {
      if (
        (!vn1.isConstant() || vn1.getOffset() !== this.lo2!.getOffset()) &&
        (!vn2.isConstant() || vn2.getOffset() !== this.lo2!.getOffset())
      )
        continue;
    } else {
      if (op.getIn(0) !== this.lo2 && op.getIn(1) !== this.lo2) continue;
    }
    this.reslo = op.getOut()!;
    return true;
  }
  return false;
};

// MultForm::mapFromInSmallConst
MultForm.prototype.mapFromInSmallConst = function (this: MultForm, rhi: Varnode): boolean {
  if (!this.mapResHiSmallConst(rhi)) return false;
  if (!this.findLoFromInSmallConst()) return false;
  if (!this.verifyLo()) return false;
  if (!this.findResLo()) return false;
  return true;
};

// MultForm::mapFromIn
MultForm.prototype.mapFromIn = function (this: MultForm, rhi: Varnode): boolean {
  // Try to do full mapping from in given a putative reshi
  if (!this.mapResHi(rhi)) return false;
  if (!this.findLoFromIn()) return false;
  if (!this.verifyLo()) return false;
  if (!this.findResLo()) return false;
  return true;
};

// MultForm::replace
MultForm.prototype.replace = function (this: MultForm, data: Funcdata): boolean {
  // We have matched a double precision multiply, now transform to logical variables
  this.outdoub.initPartial(this.in.getSize(), this.reslo!, this.reshi!);
  this.in2.initPartial(this.in.getSize(), this.lo2!, this.hi2!);
  if (this.in2.exceedsConstPrecision()) return false;
  this.existop = SplitVarnode.prepareBinaryOp(this.outdoub, this.in, this.in2);
  if (this.existop === null) return false;
  SplitVarnode.createBinaryOp(data, this.outdoub, this.in, this.in2, this.existop, CPUI_INT_MULT);
  return true;
};

// MultForm::verify
MultForm.prototype.verify = function (
  this: MultForm,
  h: Varnode,
  l: Varnode,
  hop: PcodeOp
): boolean {
  this.hi1 = h;
  this.lo1 = l;
  const hopOutDescendants = hop.getOut()!.descend;
  for (const add1 of hopOutDescendants) {
    this.add1 = add1;
    if (add1.code() !== CPUI_INT_ADD) continue;
    const add1OutDescendants = add1.getOut()!.descend;
    for (const add2 of add1OutDescendants) {
      this.add2 = add2;
      if (add2.code() !== CPUI_INT_ADD) continue;
      if (this.mapFromIn(add2.getOut()!)) return true;
    }
    if (this.mapFromIn(add1.getOut()!)) return true;
    if (this.mapFromInSmallConst(add1.getOut()!)) return true;
  }
  return false;
};

// MultForm::applyRule
MultForm.prototype.applyRule = function (
  this: MultForm,
  i: SplitVarnode,
  hop: PcodeOp,
  workishi: boolean,
  data: Funcdata
): boolean {
  if (!workishi) return false;
  if (!i.hasBothPieces()) return false;
  this.in = i;

  if (!this.verify(this.in.getHi()!, this.in.getLo()!, hop)) return false;

  if (this.replace(data)) return true;
  return false;
};

// --- PhiForm ---

// PhiForm::verify
// Given a known double precision coming together with two other pieces (via phi-nodes)
// Create a double precision phi-node
PhiForm.prototype.verify = function (
  this: PhiForm,
  h: Varnode,
  l: Varnode,
  hphi: PcodeOp
): boolean {
  this.hibase = h;
  this.lobase = l;
  this.hiphi = hphi;

  this.inslot = this.hiphi.getSlot(this.hibase);

  if (this.hiphi.getOut()!.hasNoDescend()) return false;
  this.blbase = this.hiphi.getParent() as BlockBasic;

  const loDescendants = this.lobase.descend;
  for (const lophi of loDescendants) {
    this.lophi = lophi;
    if (lophi.code() !== CPUI_MULTIEQUAL) continue;
    if (lophi.getParent() !== this.blbase) continue;
    if (lophi.getIn(this.inslot) !== this.lobase) continue;
    return true;
  }
  return false;
};

// PhiForm::applyRule
PhiForm.prototype.applyRule = function (
  this: PhiForm,
  i: SplitVarnode,
  hphi: PcodeOp,
  workishi: boolean,
  data: Funcdata
): boolean {
  if (!workishi) return false;
  if (!i.hasBothPieces()) return false;
  this.in = i;

  if (!this.verify(this.in.getHi()!, this.in.getLo()!, hphi)) return false;

  const numin: number = this.hiphi!.numInput();
  const inlist: SplitVarnode[] = [];
  for (let j = 0; j < numin; ++j) {
    const vhi: Varnode = this.hiphi!.getIn(j)!;
    const vlo: Varnode = this.lophi!.getIn(j)!;
    inlist.push(new SplitVarnode(vlo, vhi));
  }
  this.outvn.initPartial(this.in.getSize(), this.lophi!.getOut()!, this.hiphi!.getOut()!);
  this.existop = SplitVarnode.preparePhiOp(this.outvn, inlist);
  if (this.existop !== null) {
    SplitVarnode.createPhiOp(data, this.outvn, inlist, this.existop);
    return true;
  }
  return false;
};

// --- IndirectForm ---

// IndirectForm::verify
IndirectForm.prototype.verify = function (
  this: IndirectForm,
  h: Varnode,
  l: Varnode,
  ind: PcodeOp
): boolean {
  // Verify the basic double precision indirect form and fill out the pieces
  this.hi = h;
  this.lo = l;
  this.indhi = ind;
  if (this.indhi!.getIn(1)!.getSpace()!.getType() !== IPTR_IOP) return false;
  this.affector = PcodeOp.getOpFromConst(this.indhi!.getIn(1)!.getAddr());
  if (this.affector!.isDead()) return false;
  this.reshi = this.indhi!.getOut()!;
  if (this.reshi!.getSpace()!.getType() === IPTR_INTERNAL) return false; // Indirect must not be through a temporary

  const loDescendants = this.lo.descend;
  for (const indlo of loDescendants) {
    this.indlo = indlo;
    if (indlo.code() !== CPUI_INDIRECT) continue;
    if (indlo.getIn(1)!.getSpace().getType() !== IPTR_IOP) continue;
    if (this.affector !== PcodeOp.getOpFromConst(indlo.getIn(1)!.getAddr())) continue; // hi and lo must be affected by same op
    this.reslo = indlo.getOut()!;
    if (this.reslo!.getSpace()!.getType() === IPTR_INTERNAL) return false; // Indirect must not be through a temporary
    if (this.reslo!.isAddrTied() || this.reshi!.isAddrTied()) {
      let addr: Address = new Address();
      // If one piece is address tied, the other must be as well, and they must fit together as contiguous whole
      if (!SplitVarnode.isAddrTiedContiguous(this.reslo!, this.reshi!, addr)) return false;
    }
    return true;
  }
  return false;
};

// IndirectForm::applyRule
IndirectForm.prototype.applyRule = function (
  this: IndirectForm,
  i: SplitVarnode,
  ind: PcodeOp,
  workishi: boolean,
  data: Funcdata
): boolean {
  if (!workishi) return false;
  if (!i.hasBothPieces()) return false;
  this.in = i;
  if (!this.verify(this.in.getHi()!, this.in.getLo()!, ind)) return false;

  this.outvn.initPartial(this.in.getSize(), this.reslo!, this.reshi!);

  if (!SplitVarnode.prepareIndirectOp(this.in, this.affector!)) return false;
  SplitVarnode.replaceIndirectOp(data, this.outvn, this.in, this.affector!);
  return true;
};

// --- CopyForceForm ---

// CopyForceForm::verify
// Starting with the input pieces, identify the matching COPYs and verify that they act as a single
// address forced COPY with no descendants.
CopyForceForm.prototype.verify = function (
  this: CopyForceForm,
  h: Varnode,
  l: Varnode,
  w: Varnode | null,
  cpy: PcodeOp
): boolean {
  if (w === null) return false;
  this.copyhi = cpy;
  if (this.copyhi.getIn(0) !== h) return false;
  this.reshi = this.copyhi.getOut()!;
  if (!this.reshi.isAddrForce() || !this.reshi.hasNoDescend()) return false;
  const lDescendants = l.descend;
  for (const copylo of lDescendants) {
    this.copylo = copylo;
    if (copylo.code() !== CPUI_COPY || copylo.getParent() !== this.copyhi!.getParent()) continue;
    this.reslo = copylo.getOut()!;
    if (!this.reslo!.isAddrForce() || !this.reslo!.hasNoDescend()) continue;
    if (!SplitVarnode.isAddrTiedContiguous(this.reslo!, this.reshi!, this.addrOut))
      // Output MUST be contiguous addresses
      continue;
    if (this.copyhi.isReturnCopy()) {
      // Special form has additional requirements
      if (h.loneDescend() === null) continue;
      if (l.loneDescend() === null) continue;
      if (!w.getAddr().equals(this.addrOut)) {
        // Unless there are additional COPYs from the same basic block
        if (!h.isWritten() || !l.isWritten()) continue;
        const otherLo: PcodeOp = l.getDef()!;
        const otherHi: PcodeOp = h.getDef()!;
        if (otherLo.code() !== CPUI_COPY || otherHi.code() !== CPUI_COPY) continue;
        if (otherLo.getParent() !== otherHi.getParent()) continue;
      }
    }
    return true;
  }
  return false;
};

// CopyForceForm::applyRule
CopyForceForm.prototype.applyRule = function (
  this: CopyForceForm,
  i: SplitVarnode,
  cpy: PcodeOp,
  workishi: boolean,
  data: Funcdata
): boolean {
  if (!workishi) return false;
  if (!i.hasBothPieces()) return false;
  this.in = i;
  if (!this.verify(this.in.getHi()!, this.in.getLo()!, this.in.getWhole(), cpy)) return false;
  SplitVarnode.replaceCopyForce(data, this.addrOut, this.in, this.copylo!, this.copyhi!);
  return true;
};

// --- RuleDoubleIn ---

// RuleDoubleIn::reset
RuleDoubleIn.prototype.reset = function (this: RuleDoubleIn, data: Funcdata): void {
  data.setDoublePrecisRecovery(true); // Mark that we are doing double precision recovery
};

// RuleDoubleIn::getOpList
RuleDoubleIn.prototype.getOpList = function (this: RuleDoubleIn, oplist: number[]): void {
  oplist.push(CPUI_SUBPIECE);
};

// RuleDoubleIn::attemptMarking
//
// Determine if the given Varnode from a SUBPIECE should be marked as a double precision piece.
// If the given Varnode looks like the most significant piece, there is another SUBPIECE that looks
// like the least significant piece, and the whole is from an operation that produces a logical whole,
// then mark the Varnode (and its companion) as double precision pieces and return 1.
RuleDoubleIn.prototype.attemptMarking = function (
  this: RuleDoubleIn,
  vn: Varnode,
  subpieceOp: PcodeOp
): number {
  const whole: Varnode = subpieceOp.getIn(0)!;
  if (whole.isTypeLock()) {
    if (!whole.getType()!.isPrimitiveWhole()) return 0; // Don't mark for double precision if not a primitive type
  }
  const offset: number = Number(subpieceOp.getIn(1)!.getOffset());
  if (offset !== vn.getSize()) return 0;
  if (offset * 2 !== whole.getSize()) return 0; // Truncate exactly half
  if (whole.isInput()) {
    if (!whole.isTypeLock()) return 0;
  } else if (!whole.isWritten()) {
    return 0;
  } else {
    // Categorize opcodes as "producing a logical whole"
    // Its hard to tell if a logical op is really being used to act on the "logical whole"
    const typeop: TypeOp = whole.getDef()!.getOpcode();
    if (!typeop.isArithmeticOp() && !typeop.isFloatingPointOp()) return 0;
  }
  let vnLo: Varnode | null = null;
  const wholeDescendants = whole.descend;
  for (const op of wholeDescendants) {
    if (op.code() !== CPUI_SUBPIECE) continue;
    if (op.getIn(1)!.getOffset() !== 0n) continue;
    if (op.getOut()!.getSize() === vn.getSize()) {
      vnLo = op.getOut()!;
      break;
    }
  }
  if (vnLo === null) return 0;
  vnLo.setPrecisLo();
  vn.setPrecisHi();
  return 1;
};

// RuleDoubleIn::applyOp
RuleDoubleIn.prototype.applyOp = function (
  this: RuleDoubleIn,
  op: PcodeOp,
  data: Funcdata
): number {
  const outvn: Varnode = op.getOut()!;
  if (!outvn.isPrecisLo()) {
    if (outvn.isPrecisHi()) return 0;
    return this.attemptMarking(outvn, op);
  }
  if (data.hasUnreachableBlocks()) return 0;

  const splitvec: SplitVarnode[] = [];
  SplitVarnode.wholeList(op.getIn(0)!, splitvec);
  if (splitvec.length === 0) return 0;
  for (let i = 0; i < splitvec.length; ++i) {
    const inv: SplitVarnode = splitvec[i];
    const res: number = SplitVarnode.applyRuleIn(inv, data);
    if (res !== 0) return res;
  }
  return 0;
};

// --- RuleDoubleOut ---

// RuleDoubleOut::getOpList
RuleDoubleOut.prototype.getOpList = function (this: RuleDoubleOut, oplist: number[]): void {
  oplist.push(CPUI_PIECE);
};

// RuleDoubleOut::attemptMarking
//
// Determine if the given inputs to a PIECE should be marked as double precision pieces.
// If the concatenation of the pieces is used as a logical whole by other ops, the two pieces
// are marked and 1 is returned.
RuleDoubleOut.prototype.attemptMarking = function (
  this: RuleDoubleOut,
  vnhi: Varnode,
  vnlo: Varnode,
  pieceOp: PcodeOp
): number {
  const whole: Varnode = pieceOp.getOut()!;
  if (whole.isTypeLock()) {
    if (!whole.getType()!.isPrimitiveWhole()) return 0; // Don't mark for double precision if not a primitive type
  }
  if (vnhi.getSize() !== vnlo.getSize()) return 0;

  const entryhi: SymbolEntry | null = vnhi.getSymbolEntry();
  const entrylo: SymbolEntry | null = vnlo.getSymbolEntry();
  if (entryhi !== null || entrylo !== null) {
    if (entryhi === null || entrylo === null) return 0; // One has a symbol, one doesn't
    if (entryhi.getSymbol() !== entrylo.getSymbol()) return 0; // Not from the same symbol
  }

  let isWhole: boolean = false;
  const wholeDescendants = whole.descend;
  for (const descendOp of wholeDescendants) {
    const typeop: TypeOp = descendOp.getOpcode();
    // Categorize op as "reading a logical whole"
    if (typeop.isArithmeticOp() || typeop.isFloatingPointOp()) {
      isWhole = true;
      break;
    }
  }
  if (!isWhole) return 0;
  vnhi.setPrecisHi();
  vnlo.setPrecisLo();
  return 1;
};

// RuleDoubleOut::applyOp
RuleDoubleOut.prototype.applyOp = function (
  this: RuleDoubleOut,
  op: PcodeOp,
  data: Funcdata
): number {
  const vnhi: Varnode = op.getIn(0)!;
  const vnlo: Varnode = op.getIn(1)!;

  // Currently this only implements collapsing input varnodes read by CPUI_PIECE
  // So we put the test for this particular case early
  if (!vnhi.isInput() || !vnlo.isInput()) return 0;
  if (!vnhi.isPersist() || !vnlo.isPersist()) return 0;

  if (!vnhi.isPrecisHi() || !vnlo.isPrecisLo()) {
    return this.attemptMarking(vnhi, vnlo, op);
  }
  if (data.hasUnreachableBlocks()) return 0;

  let addr: Address = new Address();
  if (!SplitVarnode.isAddrTiedContiguous(vnlo, vnhi, addr)) return 0;
  data.combineInputVarnodes(vnhi, vnlo);
  return 1;
};

// --- RuleDoubleLoad ---

// RuleDoubleLoad::noWriteConflict (static)
//
// Scan for conflicts between two LOADs or STOREs that would prevent them from being combined.
// The PcodeOps must be in the same basic block. Each PcodeOp that falls in between is examined
// to determine if it writes to the same address space as the LOADs or STOREs, which indicates that
// combining isn't possible. If the LOADs and STOREs can be combined, the later of the two PcodeOps
// is returned, otherwise null is returned.
RuleDoubleLoad.noWriteConflict = function (
  op1: PcodeOp,
  op2: PcodeOp,
  spc: AddrSpace,
  indirects: PcodeOp[] | null
): PcodeOp | null {
  const bb: BlockBasic = op1.getParent() as BlockBasic;

  // Force the two ops to be in the same basic block
  if (bb !== op2.getParent()) return null;
  if (op2.getSeqNum().getOrder() < op1.getSeqNum().getOrder()) {
    const tmp: PcodeOp = op2;
    op2 = op1;
    op1 = tmp;
  }
  let startop: PcodeOp = op1;
  if (op1.code() === CPUI_STORE) {
    // Extend the range of PcodeOps to include any CPUI_INDIRECTs associated with the initial STORE
    let tmpOp: PcodeOp | null = startop.previousOp();
    while (tmpOp !== null && tmpOp.code() === CPUI_INDIRECT) {
      startop = tmpOp;
      tmpOp = tmpOp.previousOp();
    }
  }
  let iter = startop.getBasicIter();
  const enditer = op2.getBasicIter();
  const opList = bb.op;

  while (iter !== enditer) {
    const curop: PcodeOp = opList[iter];
    let outvn: Varnode | null;
    let affector: PcodeOp;
    iter = iter + 1;
    if (curop === op1) continue;
    switch (curop.code()) {
      case CPUI_STORE:
        if (curop.getIn(0)!.getSpaceFromConst() === spc) return null; // Don't go any further trying to resolve alias
        break;
      case CPUI_INDIRECT:
        affector = PcodeOp.getOpFromConst(curop.getIn(1)!.getAddr())!;
        if (affector === op1 || affector === op2) {
          if (indirects !== null) indirects.push(curop);
        } else {
          if (curop.getOut()!.getSpace() === spc) return null;
        }
        break;
      case CPUI_CALL:
      case CPUI_CALLIND:
      case CPUI_CALLOTHER:
      case CPUI_RETURN:
      case CPUI_BRANCH:
      case CPUI_CBRANCH:
      case CPUI_BRANCHIND:
        return null;
      default:
        outvn = curop.getOut();
        if (outvn !== null) {
          if (outvn.getSpace() === spc) return null;
        }
        break;
    }
  }
  return op2;
};

// RuleDoubleLoad::getOpList
RuleDoubleLoad.prototype.getOpList = function (this: RuleDoubleLoad, oplist: number[]): void {
  oplist.push(CPUI_PIECE);
};

// RuleDoubleLoad::applyOp
RuleDoubleLoad.prototype.applyOp = function (
  this: RuleDoubleLoad,
  op: PcodeOp,
  data: Funcdata
): number {
  let loadlo: PcodeOp;
  let loadhi: PcodeOp; // Load from lowest address, highest (NOT significance)
  let spc: AddrSpace;
  let size: number;

  const piece0: Varnode = op.getIn(0)!;
  const piece1: Varnode = op.getIn(1)!;
  if (!piece0.isWritten()) return 0;
  if (!piece1.isWritten()) return 0;
  const load1: PcodeOp = piece1.getDef()!;
  if (load1.code() !== CPUI_LOAD) return 0;
  let load0: PcodeOp = piece0.getDef()!;
  let opc: OpCode = load0.code();
  let offset: number = 0;
  if (opc === CPUI_SUBPIECE) {
    // Check for 2 LOADs but most significant part of most significant LOAD is discarded
    if (load0.getIn(1)!.getOffset() !== 0n) return 0;
    const vn0: Varnode = load0.getIn(0)!;
    if (!vn0.isWritten()) return 0;
    offset = vn0.getSize() - piece0.getSize();
    load0 = vn0.getDef()!;
    opc = load0.code();
  }
  if (opc !== CPUI_LOAD) return 0;
  const ptrResult: { first: PcodeOp | null, second: PcodeOp | null, spc: AddrSpace | null } = { first: null, second: null, spc: null };
  if (!SplitVarnode.testContiguousPointers(load0, load1, ptrResult)) return 0;
  loadlo = ptrResult.first!;
  loadhi = ptrResult.second!;
  spc = ptrResult.spc!;

  size = piece0.getSize() + piece1.getSize();
  const latest: PcodeOp | null = RuleDoubleLoad.noWriteConflict(loadlo, loadhi, spc, null);
  if (latest === null) return 0; // There was a conflict

  // Create new load op that combines the two smaller loads
  const newload: PcodeOp = data.newOp(2, latest.getAddr());
  const vnout: Varnode = data.newUniqueOut(size, newload);
  const spcvn: Varnode = data.newVarnodeSpace(spc);
  data.opSetOpcode(newload, CPUI_LOAD);
  data.opSetInput(newload, spcvn, 0);
  let addrvn: Varnode = loadlo.getIn(1)!;
  let insertAfterOp: PcodeOp = latest;
  if (spc.isBigEndian() && offset !== 0) {
    // If the most significant part of LOAD is discarded, we need to add discard amount to pointer
    const newadd: PcodeOp = data.newOp(2, latest.getAddr());
    const addout: Varnode = data.newUniqueOut(addrvn.getSize(), newadd);
    data.opSetOpcode(newadd, CPUI_INT_ADD);
    data.opSetInput(newadd, addrvn, 0);
    data.opSetInput(newadd, data.newConstant(addrvn.getSize(), BigInt(offset)), 1);
    data.opInsertAfter(newadd, latest);
    addrvn = addout;
    insertAfterOp = newadd;
  }
  data.opSetInput(newload, addrvn, 1);
  // We need to guarantee that newload reads addrvn after
  // it has been defined. So insert it after the latest.
  data.opInsertAfter(newload, insertAfterOp);

  // Change the concatenation to a copy from the big load
  data.opRemoveInput(op, 1);
  data.opSetOpcode(op, CPUI_COPY);
  data.opSetInput(op, vnout, 0);

  return 1;
};

// --- RuleDoubleStore ---

// RuleDoubleStore::getOpList
RuleDoubleStore.prototype.getOpList = function (this: RuleDoubleStore, oplist: number[]): void {
  oplist.push(CPUI_STORE);
};

// RuleDoubleStore::applyOp
RuleDoubleStore.prototype.applyOp = function (
  this: RuleDoubleStore,
  op: PcodeOp,
  data: Funcdata
): number {
  let storelo: PcodeOp;
  let storehi: PcodeOp;
  let spc: AddrSpace;

  const vnlo: Varnode = op.getIn(2)!;
  if (!vnlo.isPrecisLo()) return 0;
  if (!vnlo.isWritten()) return 0;
  const subpieceOpLo: PcodeOp = vnlo.getDef()!;
  if (subpieceOpLo.code() !== CPUI_SUBPIECE) return 0;
  if (subpieceOpLo.getIn(1)!.getOffset() !== 0n) return 0;
  const whole: Varnode = subpieceOpLo.getIn(0)!;
  if (whole.isFree()) return 0;
  const wholeDescendants = whole.descend;
  for (const subpieceOpHi of wholeDescendants) {
    if (subpieceOpHi.code() !== CPUI_SUBPIECE) continue;
    if (subpieceOpHi === subpieceOpLo) continue;
    const offset: number = Number(subpieceOpHi.getIn(1)!.getOffset());
    if (offset !== vnlo.getSize()) continue;
    const vnhi: Varnode = subpieceOpHi.getOut()!;
    if (!vnhi.isPrecisHi()) continue;
    if (vnhi.getSize() !== whole.getSize() - offset) continue;
    const vnhiDescendants = vnhi.descend;
    for (const storeOp2 of vnhiDescendants) {
      if (storeOp2.code() !== CPUI_STORE) continue;
      if (storeOp2.getIn(2) !== vnhi) continue;
      const ptrResult: { first: PcodeOp | null, second: PcodeOp | null, spc: AddrSpace | null } = { first: null, second: null, spc: null };
      if (SplitVarnode.testContiguousPointers(storeOp2, op, ptrResult)) {
        storelo = ptrResult.first!;
        storehi = ptrResult.second!;
        spc = ptrResult.spc!;
        const indirects: PcodeOp[] = [];
        const latest: PcodeOp | null = RuleDoubleLoad.noWriteConflict(
          storelo,
          storehi,
          spc,
          indirects
        );
        if (latest === null) continue; // There was a conflict
        if (!RuleDoubleStore.testIndirectUse(storelo, storehi, indirects)) continue;
        // Create new STORE op that combines the two smaller STOREs
        const newstore: PcodeOp = data.newOp(3, latest.getAddr());
        const spcvn: Varnode = data.newVarnodeSpace(spc);
        data.opSetOpcode(newstore, CPUI_STORE);
        data.opSetInput(newstore, spcvn, 0);
        let addrvn: Varnode = storelo.getIn(1)!;
        if (addrvn.isConstant()) addrvn = data.newConstant(addrvn.getSize(), addrvn.getOffset());
        data.opSetInput(newstore, addrvn, 1);
        data.opSetInput(newstore, whole, 2);
        // We need to guarantee that newstore reads addrvn after
        // it has been defined. So insert it after the latest.
        data.opInsertAfter(newstore, latest);
        data.opDestroy(op); // Get rid of the original STOREs
        data.opDestroy(storeOp2);
        RuleDoubleStore.reassignIndirects(data, newstore, indirects);
        return 1;
      }
    }
  }
  return 0;
};

// RuleDoubleStore::testIndirectUse (static)
//
// Test if output Varnodes from a list of PcodeOps are used anywhere within a range of PcodeOps.
// The range of PcodeOps is bounded by given starting and ending PcodeOps. An output Varnode is
// used within the range if there is a PcodeOp in the range that takes the Varnode as input.
RuleDoubleStore.testIndirectUse = function (
  op1: PcodeOp,
  op2: PcodeOp,
  indirects: PcodeOp[]
): boolean {
  if (op2.getSeqNum().getOrder() < op1.getSeqNum().getOrder()) {
    const tmp: PcodeOp = op2;
    op2 = op1;
    op1 = tmp;
  }
  for (let i = 0; i < indirects.length; ++i) {
    const outvn: Varnode = indirects[i].getOut()!;
    let usecount: number = 0;
    let usebyop2: number = 0;
    const outvnDescendants = outvn.descend;
    for (const op of outvnDescendants) {
      usecount += 1;
      if (op.getParent() !== op1.getParent()) continue;
      if (op.getSeqNum().getOrder() < op1.getSeqNum().getOrder()) continue;
      if (op.getSeqNum().getOrder() > op2.getSeqNum().getOrder()) continue;
      // Its likely that INDIRECTs from the first STORE feed INDIRECTs for the second STORE
      if (
        op.code() === CPUI_INDIRECT &&
        op2 === PcodeOp.getOpFromConst(op.getIn(1)!.getAddr())
      ) {
        usebyop2 += 1; // Note this pairing
        continue;
      }
      return false;
    }
    // As an INDIRECT whose output Varnode feeds into later INDIRECTs must be removed, we need the following test.
    // If some uses of the output feed into later INDIRECTs, but not ALL do, then return false
    if (usebyop2 > 0 && usecount !== usebyop2) return false;
    if (usebyop2 > 1) return false;
  }
  return true;
};

// RuleDoubleStore::reassignIndirects (static)
//
// Reassign INDIRECTs to a new given STORE.
// The INDIRECTs are associated with old STOREs that are being removed.
// Each INDIRECT is moved from its position near the old STORE to be near the new STORE and
// the affect iop operand is set to point at the new STORE.
RuleDoubleStore.reassignIndirects = function (
  data: Funcdata,
  newStore: PcodeOp,
  indirects: PcodeOp[]
): void {
  // Search for INDIRECT pairs. The earlier is deleted. The later gains the earlier's input.
  for (let i = 0; i < indirects.length; ++i) {
    const op: PcodeOp = indirects[i];
    op.setMark();
    const vn: Varnode = op.getIn(0)!;
    if (!vn.isWritten()) continue;
    const earlyop: PcodeOp = vn.getDef()!;
    if (earlyop.isMark()) {
      data.opSetInput(op, earlyop.getIn(0)!, 0); // Grab the earlier op's input, replacing the use of its output
      data.opDestroy(earlyop);
    }
  }
  for (let i = 0; i < indirects.length; ++i) {
    const op: PcodeOp = indirects[i];
    op.clearMark();
    if (op.isDead()) continue;
    data.opUninsert(op);
    data.opInsertBefore(op, newStore); // Move the INDIRECT to the new STORE
    data.opSetInput(op, data.newVarnodeIop(newStore), 1); // Assign the INDIRECT to the new STORE
  }
};
