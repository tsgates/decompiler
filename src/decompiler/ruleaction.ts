// ruleaction_part1.ts
// PART 1 of 6: Translated from Ghidra's ruleaction.hh / ruleaction.cc
// Rule classes: RuleEarlyRemoval through RuleAndCompare (lines 1-1800 of .cc)

// ============================================================
// Imports (all imports needed for entire ruleaction module)
// ============================================================

import { Rule } from "./action.js";
import { OpCode, get_booleanflip } from "../core/opcodes.js";
import { Varnode, contiguous_test, findContiguousWhole } from "./varnode.js";
import { PcodeOp, PieceNode } from "./op.js";
import { Address, calc_mask, pcode_left, pcode_right, leastsigbit_set, sign_extend, signbit_negative, uintb_negate, mostsigbit_set, popcount, count_leading_zeros } from "../core/address.js";
import { AddrSpace, spacetype } from "../core/space.js";
import {
  Datatype,
  type_metatype,
} from "./type.js";
import {
  functionalEquality,
  functionalEqualityLevel,
  TermOrder,
  AdditiveEdge,
  BooleanMatch,
  AddExpression,
} from "./expression.js";
import { CircleRange } from "./rangeutil.js";
import { Funcdata, CloneBlockOps } from "./funcdata.js";
import { FlowBlock } from "./block.js";
import { TypeOp } from "./typeop.js";
import { LowlevelError } from "../core/error.js";
import { set_u128, leftshift128, add128, subtract128, udiv128, uless128, ulessequal128 } from "./multiprecision.js";

// Forward type declarations
type TypeFactory = any;
type TypePointer = any;
type TypePointerRel = any;
type Architecture = any;
type BlockBasic = any;
type JoinRecord = any;
type VarnodeData = any;
type ActionGroupList = any;
type LoadGuard = any;
type FuncCallSpecs = any;
type CPoolRecord = any;
type TypeOpFloatInt2Float = any;
type SegmentOp = any;
declare const EquateSymbol: any;
type TypeEnum = any;
type TypeArray = any;
type TypeSpacebase = any;
type SymbolEntry = any;
type Scope = any;
// CloneBlockOps imported from funcdata.ts

// ============================================================
// Rule Classes: Part 1 (RuleEarlyRemoval through RuleAndCompare)
// ============================================================

/// Get rid of unused PcodeOp objects where we can guarantee the output is unused
export class RuleEarlyRemoval extends Rule {
  constructor(g: string) {
    super(g, 0, "earlyremoval");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleEarlyRemoval(this.getGroup());
  }

  // This rule applies to all ops (no getOpList override)

  applyOp(op: PcodeOp, data: Funcdata): number {
    let vn: Varnode;

    if (op.isCall()) return 0;  // Functions automatically consumed
    if (op.isIndirectSource()) return 0;
    vn = op.getOut()!;
    if (vn === null) return 0;
    if (!vn.hasNoDescend()) return 0;
    if (vn.isAutoLive()) return 0;
    const spc: AddrSpace | null = vn.getSpace();
    if (spc !== null && spc.doesDeadcode()) {
      if (!data.deadRemovalAllowedSeen(spc))
        return 0;
    }

    data.opDestroy(op);  // Get rid of unused op
    return 1;
  }
}

/// Collect terms in a sum: V * c + V * d  =>  V * (c + d)
export class RuleCollectTerms extends Rule {
  constructor(g: string) {
    super(g, 0, "collect_terms");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleCollectTerms(this.getGroup());
  }

  /// Get the multiplicative coefficient
  private static getMultCoeff(vn: Varnode): { vn: Varnode; coef: bigint } {
    let testop: PcodeOp;
    if (!vn.isWritten()) {
      return { vn, coef: 1n };
    }
    testop = vn.getDef()!;
    if ((testop.code() !== OpCode.CPUI_INT_MULT) || (!testop.getIn(1)!.isConstant())) {
      return { vn, coef: 1n };
    }
    const coef = testop.getIn(1)!.getOffset();
    return { vn: testop.getIn(0)!, coef };
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_ADD);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let nextop: PcodeOp = op.getOut()!.loneDescend()!;
    // Do we have the root of an ADD tree
    if ((nextop !== null) && (nextop.code() === OpCode.CPUI_INT_ADD)) return 0;

    const termorder = new TermOrder(op);
    termorder.collect();      // Collect additive terms in the expression
    termorder.sortTerms();    // Sort them based on termorder
    let vn1: Varnode, vn2: Varnode;
    let coef1: bigint, coef2: bigint;
    const order: AdditiveEdge[] = termorder.getSort();
    let i = 0;

    if (!order[0].getVarnode().isConstant()) {
      for (i = 1; i < order.length; ++i) {
        vn1 = order[i - 1].getVarnode();
        vn2 = order[i].getVarnode();
        if (vn2.isConstant()) break;
        const r1 = RuleCollectTerms.getMultCoeff(vn1);
        vn1 = r1.vn; coef1 = r1.coef;
        const r2 = RuleCollectTerms.getMultCoeff(vn2);
        vn2 = r2.vn; coef2 = r2.coef;
        if (vn1 === vn2) {
          // Terms that can be combined
          if (order[i - 1].getMultiplier() !== null)
            return data.distributeIntMultAdd(order[i - 1].getMultiplier()) ? 1 : 0;
          if (order[i].getMultiplier() !== null)
            return data.distributeIntMultAdd(order[i].getMultiplier()) ? 1 : 0;
          coef1 = (coef1 + coef2) & calc_mask(vn1.getSize());  // The new coefficient
          const newcoeff: Varnode = data.newConstant(vn1.getSize(), coef1);
          const zerocoeff: Varnode = data.newConstant(vn1.getSize(), 0n);
          data.opSetInput(order[i - 1].getOp(), zerocoeff, order[i - 1].getSlot());
          if (coef1 === 0n) {
            data.opSetInput(order[i].getOp(), newcoeff, order[i].getSlot());
          } else {
            nextop = data.newOp(2, order[i].getOp().getAddr());
            vn2 = data.newUniqueOut(vn1.getSize(), nextop);
            data.opSetOpcode(nextop, OpCode.CPUI_INT_MULT);
            data.opSetInput(nextop, vn1, 0);
            data.opSetInput(nextop, newcoeff, 1);
            data.opInsertBefore(nextop, order[i].getOp());
            data.opSetInput(order[i].getOp(), vn2, order[i].getSlot());
          }
          return 1;
        }
      }
    }
    coef1 = 0n;
    let nonzerocount = 0;    // Count non-zero constants
    let lastconst = 0;
    for (let j = order.length - 1; j >= i; --j) {
      if (order[j].getMultiplier() !== null) continue;
      vn1 = order[j].getVarnode();
      const val = vn1.getOffset();
      if (val !== 0n) {
        nonzerocount += 1;
        coef1 += val;  // Sum up all the constants
        lastconst = j;
      }
    }
    if (nonzerocount <= 1) return 0;  // Must sum at least two things
    vn1 = order[lastconst].getVarnode();
    coef1 &= calc_mask(vn1.getSize());
    // Lump all the non-zero constants into one varnode
    for (let j = lastconst + 1; j < order.length; ++j) {
      if (order[j].getMultiplier() === null) {
        data.opSetInput(order[j].getOp(), data.newConstant(vn1.getSize(), 0n), order[j].getSlot());
      }
    }
    data.opSetInput(order[lastconst].getOp(), data.newConstant(vn1.getSize(), coef1), order[lastconst].getSlot());

    return 1;
  }
}

/// Look for common sub-expressions (built out of a restricted set of ops)
export class RuleSelectCse extends Rule {
  constructor(g: string) {
    super(g, 0, "selectcse");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSelectCse(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_SUBPIECE);
    oplist.push(OpCode.CPUI_INT_SRIGHT);  // For division optimization corrections
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const vn: Varnode = op.getIn(0)!;
    const opc: OpCode = op.code();
    let otherop: PcodeOp;
    const list: Array<[number, PcodeOp]> = [];
    const vlist: Varnode[] = [];

    for (let iter = vn.beginDescend(); iter < vn.endDescend(); iter++) {
      otherop = vn.getDescend(iter);
      if (otherop.code() !== opc) continue;
      const hash = otherop.getCseHash();
      if (hash === 0) continue;
      list.push([hash, otherop]);
    }
    if (list.length <= 1) return 0;
    data.cseEliminateList(list, vlist);
    if (vlist.length === 0) return 0;
    return 1;
  }
}

/// Concatenation with 0 becomes an extension: V = concat(#0,W)  =>  V = zext(W)
export class RulePiece2Zext extends Rule {
  constructor(g: string) {
    super(g, 0, "piece2zext");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RulePiece2Zext(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_PIECE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const constvn: Varnode = op.getIn(0)!;  // Constant must be most significant bits
    if (!constvn.isConstant()) return 0;   // Must append with constant
    if (constvn.getOffset() !== 0n) return 0;  // of value 0
    data.opRemoveInput(op, 0);  // Remove the constant
    data.opSetOpcode(op, OpCode.CPUI_INT_ZEXT);
    return 1;
  }
}

/// Concatenation with sign bits becomes extension: concat( V s>> #0x1f , V)  => sext(V)
export class RulePiece2Sext extends Rule {
  constructor(g: string) {
    super(g, 0, "piece2sext");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RulePiece2Sext(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_PIECE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const shiftout: Varnode = op.getIn(0)!;
    if (!shiftout.isWritten()) return 0;
    const shiftop: PcodeOp = shiftout.getDef()!;
    if (shiftop.code() !== OpCode.CPUI_INT_SRIGHT) return 0;
    if (!shiftop.getIn(1)!.isConstant()) return 0;
    const n: number = Number(shiftop.getIn(1)!.getOffset());
    const x: Varnode = shiftop.getIn(0)!;
    if (x !== op.getIn(1)!) return 0;
    if (n !== 8 * x.getSize() - 1) return 0;

    data.opRemoveInput(op, 0);
    data.opSetOpcode(op, OpCode.CPUI_INT_SEXT);
    return 1;
  }
}

/// Eliminate BOOL_XOR: V ^^ W  =>  V != W
export class RuleBxor2NotEqual extends Rule {
  constructor(g: string) {
    super(g, 0, "bxor2notequal");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleBxor2NotEqual(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_BOOL_XOR);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    data.opSetOpcode(op, OpCode.CPUI_INT_NOTEQUAL);
    return 1;
  }
}

/// Simplify INT_OR with full mask: V = W | 0xffff  =>  V = W
export class RuleOrMask extends Rule {
  constructor(g: string) {
    super(g, 0, "ormask");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleOrMask(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_OR);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const size: number = op.getOut()!.getSize();
    if (size > 8) return 0;  // FIXME: uintb should be arbitrary precision

    const constvn: Varnode = op.getIn(1)!;
    if (!constvn.isConstant()) return 0;
    const val: bigint = constvn.getOffset();
    const mask: bigint = calc_mask(size);
    if ((val & mask) !== mask) return 0;
    data.opSetOpcode(op, OpCode.CPUI_COPY);
    data.opSetInput(op, constvn, 0);
    data.opRemoveInput(op, 1);
    return 1;
  }
}

/// Collapse unnecessary INT_AND
export class RuleAndMask extends Rule {
  constructor(g: string) {
    super(g, 0, "andmask");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleAndMask(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_AND);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let mask1: bigint, mask2: bigint, andmask: bigint;
    const size: number = op.getOut()!.getSize();
    let vn: Varnode;

    if (size > 8) return 0;  // FIXME: uintb should be arbitrary precision
    mask1 = op.getIn(0)!.getNZMask();
    if (mask1 === 0n)
      andmask = 0n;
    else {
      mask2 = op.getIn(1)!.getNZMask();
      andmask = mask1 & mask2;
    }

    if (andmask === 0n)  // Result of AND is always zero
      vn = data.newConstant(size, 0n);
    else if ((andmask & op.getOut()!.getConsume()) === 0n)
      vn = data.newConstant(size, 0n);
    else if (andmask === mask1) {
      if (!op.getIn(1)!.isConstant()) return 0;
      vn = op.getIn(0)!;  // Result of AND is equal to input(0)
    }
    else
      return 0;
    if (!vn.isHeritageKnown()) return 0;

    data.opSetOpcode(op, OpCode.CPUI_COPY);
    data.opRemoveInput(op, 1);
    data.opSetInput(op, vn, 0);
    return 1;
  }
}

/// Simplify OR with unconsumed input: V = A | B  =>  V = B  if  nzm(A) & consume(V) == 0
export class RuleOrConsume extends Rule {
  constructor(g: string) {
    super(g, 0, "orconsume");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleOrConsume(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_OR);
    oplist.push(OpCode.CPUI_INT_XOR);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const outvn: Varnode = op.getOut()!;
    const size: number = outvn.getSize();
    if (size > 8) return 0;  // FIXME: uintb should be arbitrary precision
    const consume: bigint = outvn.getConsume();
    if ((consume & op.getIn(0)!.getNZMask()) === 0n) {
      data.opRemoveInput(op, 0);
      data.opSetOpcode(op, OpCode.CPUI_COPY);
      return 1;
    }
    else if ((consume & op.getIn(1)!.getNZMask()) === 0n) {
      data.opRemoveInput(op, 1);
      data.opSetOpcode(op, OpCode.CPUI_COPY);
      return 1;
    }
    return 0;
  }
}

/// Collapse unnecessary INT_OR
///
/// Replace V | c with c, if any bit not set in c,
/// is also not set in V   i.e. NZM(V) | c == c
export class RuleOrCollapse extends Rule {
  constructor(g: string) {
    super(g, 0, "orcollapse");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleOrCollapse(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_OR);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const size: number = op.getOut()!.getSize();
    const vn: Varnode = op.getIn(1)!;
    if (!vn.isConstant()) return 0;
    if (size > 8) return 0;  // FIXME: uintb should be arbitrary precision
    const mask: bigint = op.getIn(0)!.getNZMask();
    const val: bigint = vn.getOffset();
    if ((mask | val) !== val) return 0;  // first param may turn on other bits

    data.opSetOpcode(op, OpCode.CPUI_COPY);
    data.opRemoveInput(op, 0);
    return 1;
  }
}

/// Collapse constants in logical expressions: (V & c) & d  =>  V & (c & d)
export class RuleAndOrLump extends Rule {
  constructor(g: string) {
    super(g, 0, "andorlump");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleAndOrLump(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_AND);
    oplist.push(OpCode.CPUI_INT_OR);
    oplist.push(OpCode.CPUI_INT_XOR);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const opc: OpCode = op.code();
    if (!op.getIn(1)!.isConstant()) return 0;
    const vn1: Varnode = op.getIn(0)!;
    if (!vn1.isWritten()) return 0;
    const op2: PcodeOp = vn1.getDef()!;
    if (op2.code() !== opc) return 0;  // Must be same op
    if (!op2.getIn(1)!.isConstant()) return 0;
    const basevn: Varnode = op2.getIn(0)!;
    if (basevn.isFree()) return 0;

    let val: bigint = op.getIn(1)!.getOffset();
    const val2: bigint = op2.getIn(1)!.getOffset();
    if (opc === OpCode.CPUI_INT_AND)
      val &= val2;
    else if (opc === OpCode.CPUI_INT_OR)
      val |= val2;
    else if (opc === OpCode.CPUI_INT_XOR)
      val ^= val2;

    data.opSetInput(op, basevn, 0);
    data.opSetInput(op, data.newConstant(basevn.getSize(), val), 1);
    return 1;
  }
}

/// Apply INT_NEGATE identities: V & ~V  => #0,  V | ~V  ->  #-1
export class RuleNegateIdentity extends Rule {
  constructor(g: string) {
    super(g, 0, "negateidentity");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleNegateIdentity(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_NEGATE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const vn: Varnode = op.getIn(0)!;
    const outVn: Varnode = op.getOut()!;
    for (let iter = outVn.beginDescend(); iter < outVn.endDescend(); iter++) {
      const logicOp: PcodeOp = outVn.getDescend(iter);
      const opc: OpCode = logicOp.code();
      if (opc !== OpCode.CPUI_INT_AND && opc !== OpCode.CPUI_INT_OR && opc !== OpCode.CPUI_INT_XOR)
        continue;
      const slot: number = logicOp.getSlot(outVn);
      if (logicOp.getIn(1 - slot)! !== vn) continue;
      let value: bigint = 0n;
      if (opc !== OpCode.CPUI_INT_AND)
        value = calc_mask(vn.getSize());
      data.opSetInput(logicOp, data.newConstant(vn.getSize(), value), 0);
      data.opRemoveInput(logicOp, 1);
      data.opSetOpcode(logicOp, OpCode.CPUI_COPY);
      return 1;
    }
    return 0;
  }
}

/// Shifting away all non-zero bits of one-side of a logical/arithmetic op
///
/// ( V & 0xf000 ) << 4   =>   #0 << 4
/// ( V + 0xf000 ) << 4   =>    V << 4
export class RuleShiftBitops extends Rule {
  constructor(g: string) {
    super(g, 0, "shiftbitops");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleShiftBitops(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_LEFT);
    oplist.push(OpCode.CPUI_INT_RIGHT);
    oplist.push(OpCode.CPUI_SUBPIECE);
    oplist.push(OpCode.CPUI_INT_MULT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const constvn: Varnode = op.getIn(1)!;
    if (!constvn.isConstant()) return 0;  // Must be a constant shift
    let vn: Varnode = op.getIn(0)!;
    if (!vn.isWritten()) return 0;
    if (vn.getSize() > 8) return 0;  // FIXME: Can't exceed uintb precision
    let sa: number;
    let leftshift: boolean;

    switch (op.code()) {
      case OpCode.CPUI_INT_LEFT:
        sa = Number(constvn.getOffset());
        leftshift = true;
        break;
      case OpCode.CPUI_INT_RIGHT:
        sa = Number(constvn.getOffset());
        leftshift = false;
        break;
      case OpCode.CPUI_SUBPIECE:
        sa = Number(constvn.getOffset());
        sa = sa * 8;
        leftshift = false;
        break;
      case OpCode.CPUI_INT_MULT:
        sa = leastsigbit_set(constvn.getOffset());
        if (sa === -1) return 0;
        leftshift = true;
        break;
      default:
        return 0;  // Never reaches here
    }

    const bitop: PcodeOp = vn.getDef()!;
    switch (bitop.code()) {
      case OpCode.CPUI_INT_AND:
      case OpCode.CPUI_INT_OR:
      case OpCode.CPUI_INT_XOR:
        break;
      case OpCode.CPUI_INT_MULT:
      case OpCode.CPUI_INT_ADD:
        if (!leftshift) return 0;
        break;
      default:
        return 0;
    }

    let i: number;
    for (i = 0; i < bitop.numInput(); ++i) {
      let nzm: bigint = bitop.getIn(i)!.getNZMask();
      const mask: bigint = calc_mask(op.getOut()!.getSize());
      if (leftshift)
        nzm = pcode_left(nzm, sa);
      else
        nzm = pcode_right(nzm, sa);
      if ((nzm & mask) === 0n) break;
    }
    if (i === bitop.numInput()) return 0;
    switch (bitop.code()) {
      case OpCode.CPUI_INT_MULT:
      case OpCode.CPUI_INT_AND:
        vn = data.newConstant(vn.getSize(), 0n);
        data.opSetInput(op, vn, 0);  // Result will be zero
        break;
      case OpCode.CPUI_INT_ADD:
      case OpCode.CPUI_INT_XOR:
      case OpCode.CPUI_INT_OR:
        vn = bitop.getIn(1 - i)!;
        if (!vn.isHeritageKnown()) return 0;
        data.opSetInput(op, vn, 0);
        break;
      default:
        break;
    }
    return 1;
  }
}

/// Simplify INT_RIGHT and INT_SRIGHT ops where an INT_AND mask becomes unnecessary
///
/// ( V & 0xf000 ) >> 24   =>   V >> 24
/// ( V & 0xf000 ) s>> 24  =>   V s>> 24
export class RuleRightShiftAnd extends Rule {
  constructor(g: string) {
    super(g, 0, "rightshiftand");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleRightShiftAnd(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_RIGHT);
    oplist.push(OpCode.CPUI_INT_SRIGHT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const constVn: Varnode = op.getIn(1)!;
    if (!constVn.isConstant()) return 0;
    const inVn: Varnode = op.getIn(0)!;
    if (!inVn.isWritten()) return 0;
    const andOp: PcodeOp = inVn.getDef()!;
    if (andOp.code() !== OpCode.CPUI_INT_AND) return 0;
    const maskVn: Varnode = andOp.getIn(1)!;
    if (!maskVn.isConstant()) return 0;

    const sa: number = Number(constVn.getOffset());
    const mask: bigint = maskVn.getOffset() >> BigInt(sa);
    const rootVn: Varnode = andOp.getIn(0)!;
    const full: bigint = calc_mask(rootVn.getSize()) >> BigInt(sa);
    if (full !== mask) return 0;
    if (rootVn.isFree()) return 0;
    data.opSetInput(op, rootVn, 0);  // Bypass the INT_AND
    return 1;
  }
}

/// Convert LESSEQUAL to LESS: V <= c  =>  V < (c+1)
export class RuleIntLessEqual extends Rule {
  constructor(g: string) {
    super(g, 0, "intlessequal");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleIntLessEqual(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_LESSEQUAL);
    oplist.push(OpCode.CPUI_INT_SLESSEQUAL);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (data.replaceLessequal(op))
      return 1;
    return 0;
  }
}

/// Collapse INT_EQUAL and INT_NOTEQUAL: f(V,W) == f(V,W)  =>  true
///
/// If both inputs to an INT_EQUAL or INT_NOTEQUAL op are functionally equivalent,
/// the op can be collapsed to a COPY of a true or false.
export class RuleEquality extends Rule {
  constructor(g: string) {
    super(g, 0, "equality");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleEquality(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_EQUAL);
    oplist.push(OpCode.CPUI_INT_NOTEQUAL);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (!functionalEquality(op.getIn(0)!, op.getIn(1)!))
      return 0;

    data.opSetOpcode(op, OpCode.CPUI_COPY);
    data.opRemoveInput(op, 1);
    const vn: Varnode = data.newConstant(1, (op.code() === OpCode.CPUI_INT_EQUAL) ? 1n : 0n);
    data.opSetInput(op, vn, 0);
    return 1;
  }
}

/// Order the inputs to commutative operations
///
/// Constants always come last in particular which eliminates
/// some of the combinatorial explosion of expression variations.
export class RuleTermOrder extends Rule {
  constructor(g: string) {
    super(g, 0, "termorder");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleTermOrder(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    const list: number[] = [
      OpCode.CPUI_INT_EQUAL, OpCode.CPUI_INT_NOTEQUAL, OpCode.CPUI_INT_ADD, OpCode.CPUI_INT_CARRY,
      OpCode.CPUI_INT_SCARRY, OpCode.CPUI_INT_XOR, OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR,
      OpCode.CPUI_INT_MULT, OpCode.CPUI_BOOL_XOR, OpCode.CPUI_BOOL_AND, OpCode.CPUI_BOOL_OR,
      OpCode.CPUI_FLOAT_EQUAL, OpCode.CPUI_FLOAT_NOTEQUAL, OpCode.CPUI_FLOAT_ADD,
      OpCode.CPUI_FLOAT_MULT
    ];
    for (const opc of list) {
      oplist.push(opc);
    }
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const vn1: Varnode = op.getIn(0)!;
    const vn2: Varnode = op.getIn(1)!;

    if (vn1.isConstant() && (!vn2.isConstant())) {
      data.opSwapInput(op, 0, 1);  // Reverse the order of the terms
      return 1;
    }
    return 0;
  }
}

/// Pull SUBPIECE back through MULTIEQUAL
export class RulePullsubMulti extends Rule {
  constructor(g: string) {
    super(g, 0, "pullsub_multi");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RulePullsubMulti(this.getGroup());
  }

  /// Compute minimum and maximum bytes being used.
  /// For bytes in given Varnode pass back the largest and smallest index (lsb=0)
  /// consumed by an immediate descendant.
  static minMaxUse(vn: Varnode): { maxByte: number; minByte: number } {
    const inSize: number = vn.getSize();
    let maxByte = -1;
    let minByte = inSize;
    for (let iter = vn.beginDescend(); iter < vn.endDescend(); iter++) {
      const op: PcodeOp = vn.getDescend(iter);
      const opc: OpCode = op.code();
      if (opc === OpCode.CPUI_SUBPIECE) {
        const min: number = Number(op.getIn(1)!.getOffset());
        const max: number = min + op.getOut()!.getSize() - 1;
        if (min < minByte)
          minByte = min;
        if (max > maxByte)
          maxByte = max;
      }
      else {
        // By default assume all bytes are used
        maxByte = inSize - 1;
        minByte = 0;
        return { maxByte, minByte };
      }
    }
    return { maxByte, minByte };
  }

  /// Replace given Varnode with (smaller) newVn in all descendants
  static replaceDescendants(origVn: Varnode, newVn: Varnode, maxByte: number, minByte: number, data: Funcdata): void {
    for (let iter = origVn.beginDescend(); iter < origVn.endDescend(); iter++) {
      const op: PcodeOp = origVn.getDescend(iter);
      if (op.code() === OpCode.CPUI_SUBPIECE) {
        const truncAmount: number = Number(op.getIn(1)!.getOffset());
        const outSize: number = op.getOut()!.getSize();
        data.opSetInput(op, newVn, 0);
        if (newVn.getSize() === outSize) {
          if (truncAmount !== minByte)
            throw new Error("Could not perform -replaceDescendants-");
          data.opSetOpcode(op, OpCode.CPUI_COPY);
          data.opRemoveInput(op, 1);
        }
        else if (newVn.getSize() > outSize) {
          const newTrunc: number = truncAmount - minByte;
          if (newTrunc < 0)
            throw new Error("Could not perform -replaceDescendants-");
          if (newTrunc !== truncAmount) {
            data.opSetInput(op, data.newConstant(4, BigInt(newTrunc)), 1);
          }
        }
        else {
          throw new Error("Could not perform -replaceDescendants-");
        }
      }
      else {
        throw new Error("Could not perform -replaceDescendants-");
      }
    }
  }

  /// Return true if given size is a suitable truncated size
  static acceptableSize(size: number): boolean {
    if (size === 0) return false;
    if (size >= 8) return true;
    if (size === 1 || size === 2 || size === 4 || size === 8)
      return true;
    return false;
  }

  /// Build a SUBPIECE of given base Varnode
  static buildSubpiece(basevn: Varnode, outsize: number, shift: number, data: Funcdata): Varnode {
    let newaddr: Address;
    let new_op: PcodeOp;
    let outvn: Varnode;

    if (basevn.isInput()) {
      const bb: BlockBasic = data.getBasicBlocks().getBlock(0) as BlockBasic;
      newaddr = bb.getStart();
    }
    else {
      if (!basevn.isWritten()) throw new Error("Undefined pullsub");
      newaddr = basevn.getDef()!.getAddr();
    }
    let smalladdr1: Address;
    let usetmp = false;
    if (basevn.getAddr().isJoin()) {
      usetmp = true;
      const joinrec: JoinRecord = data.getArch().findJoin(basevn.getOffset());
      if (joinrec.numPieces() > 1) {
        // If only 1 piece (float extension) automatically use unique
        let skipleft: number = shift;
        for (let i = joinrec.numPieces() - 1; i >= 0; --i) {
          // Move from least significant to most
          const vdata: VarnodeData = joinrec.getPiece(i);
          if (skipleft >= vdata.size) {
            skipleft -= vdata.size;
          }
          else {
            if (skipleft + outsize > vdata.size)
              break;
            if (vdata.space.isBigEndian())
              smalladdr1 = vdata.getAddr().add(BigInt(vdata.size - (outsize + skipleft)));
            else
              smalladdr1 = vdata.getAddr().add(BigInt(skipleft));
            usetmp = false;
            break;
          }
        }
      }
    }
    else {
      if (!basevn.getSpace()!.isBigEndian())
        smalladdr1 = basevn.getAddr().add(BigInt(shift));
      else
        smalladdr1 = basevn.getAddr().add(BigInt(basevn.getSize() - (shift + outsize)));
    }
    // Build new subpiece near definition of basevn
    new_op = data.newOp(2, newaddr);
    data.opSetOpcode(new_op, OpCode.CPUI_SUBPIECE);
    if (usetmp)
      outvn = data.newUniqueOut(outsize, new_op);
    else {
      smalladdr1!.renormalize(outsize);
      outvn = data.newVarnodeOut(outsize, smalladdr1!, new_op);
    }
    data.opSetInput(new_op, basevn, 0);
    data.opSetInput(new_op, data.newConstant(4, BigInt(shift)), 1);

    if (basevn.isInput())
      data.opInsertBegin(new_op, data.getBasicBlocks().getBlock(0) as BlockBasic);
    else
      data.opInsertAfter(new_op, basevn.getDef()!);
    return outvn;
  }

  /// Find a predefined SUBPIECE of a base Varnode
  static findSubpiece(basevn: Varnode, outsize: number, shift: number): Varnode | null {
    for (let iter = basevn.beginDescend(); iter < basevn.endDescend(); iter++) {
      const prevop: PcodeOp = basevn.getDescend(iter);
      if (prevop.code() !== OpCode.CPUI_SUBPIECE) continue;
      // Make sure output is defined in same block as vn_piece
      if (basevn.isInput() && (prevop.getParent().getIndex() !== 0)) continue;
      if (!basevn.isWritten()) continue;
      if (basevn.getDef()!.getParent() !== prevop.getParent()) continue;
      // Make sure subpiece matches form
      if ((prevop.getIn(0)! === basevn) &&
          (prevop.getOut()!.getSize() === outsize) &&
          (Number(prevop.getIn(1)!.getOffset()) === shift)) {
        return prevop.getOut()!;
      }
    }
    return null;
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_SUBPIECE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const vn: Varnode = op.getIn(0)!;
    if (!vn.isWritten()) return 0;
    const mult: PcodeOp = vn.getDef()!;
    if (mult.code() !== OpCode.CPUI_MULTIEQUAL) return 0;
    // We only pull up, do not pull "down" to bottom of loop
    if (mult.getParent().hasLoopIn()) return 0;
    const { maxByte, minByte } = RulePullsubMulti.minMaxUse(vn);
    const newSize: number = maxByte - minByte + 1;
    if (maxByte < minByte || (newSize >= vn.getSize()))
      return 0;  // If all or none is getting used, nothing to do
    if (!RulePullsubMulti.acceptableSize(newSize)) return 0;
    const outvn: Varnode = op.getOut()!;
    if (outvn.isPrecisLo() || outvn.isPrecisHi()) return 0;  // Don't pull apart a double precision object

    // Make sure we don't add new SUBPIECE ops that aren't going to cancel in some way
    if (minByte > 8) return 0;
    let consume: bigint;
    if (minByte < 8)
      consume = calc_mask(newSize) << BigInt(8 * minByte);
    else
      consume = 0n;
    consume = ~consume;  // Check for use of bits outside of what gets truncated later
    const branches: number = mult.numInput();
    for (let i = 0; i < branches; ++i) {
      const inVn: Varnode = mult.getIn(i)!;
      if ((consume & inVn.getConsume()) !== 0n) {
        // Check if bits not truncated are still used
        // Check if there's an extension that matches the truncation
        if (minByte === 0 && inVn.isWritten()) {
          const defOp: PcodeOp = inVn.getDef()!;
          const opc: OpCode = defOp.code();
          if (opc === OpCode.CPUI_INT_ZEXT || opc === OpCode.CPUI_INT_SEXT) {
            if (newSize === defOp.getIn(0)!.getSize())
              continue;  // We have matching extension, so new SUBPIECE will cancel anyway
          }
        }
        return 0;
      }
    }

    let smalladdr2: Address;
    if (!vn.getSpace()!.isBigEndian())
      smalladdr2 = vn.getAddr().add(BigInt(minByte));
    else
      smalladdr2 = vn.getAddr().add(BigInt(vn.getSize() - maxByte - 1));

    const params: Varnode[] = [];

    for (let i = 0; i < branches; ++i) {
      const vn_piece: Varnode = mult.getIn(i)!;
      // Search for a previous SUBPIECE
      let vn_sub: Varnode | null = RulePullsubMulti.findSubpiece(vn_piece, newSize, minByte);
      if (vn_sub === null)
        vn_sub = RulePullsubMulti.buildSubpiece(vn_piece, newSize, minByte, data);
      params.push(vn_sub);
    }
    // Build new multiequal near original multiequal
    const new_multi: PcodeOp = data.newOp(params.length, mult.getAddr());
    smalladdr2!.renormalize(newSize);
    const new_vn: Varnode = data.newVarnodeOut(newSize, smalladdr2!, new_multi);
    data.opSetOpcode(new_multi, OpCode.CPUI_MULTIEQUAL);
    data.opSetAllInput(new_multi, params);
    data.opInsertBegin(new_multi, mult.getParent());

    RulePullsubMulti.replaceDescendants(vn, new_vn, maxByte, minByte, data);
    return 1;
  }
}

/// Pull-back SUBPIECE through INDIRECT
export class RulePullsubIndirect extends Rule {
  constructor(g: string) {
    super(g, 0, "pullsub_indirect");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RulePullsubIndirect(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_SUBPIECE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const vn: Varnode = op.getIn(0)!;
    if (!vn.isWritten()) return 0;
    if (vn.getSize() > 8) return 0;
    const indir: PcodeOp = vn.getDef()!;
    if (indir.code() !== OpCode.CPUI_INDIRECT) return 0;
    if (indir.getIn(1)!.getSpace() === null || indir.getIn(1)!.getSpace()!.getType() !== 4 /*spacetype.IPTR_IOP*/) return 0;

    const targ_op: PcodeOp | null = PcodeOp.getOpFromConst(indir.getIn(1)!.getAddr());
    if (targ_op === null || targ_op.isDead()) return 0;
    if (vn.isAddrForce()) return 0;
    const { maxByte, minByte } = RulePullsubMulti.minMaxUse(vn);
    const newSize: number = maxByte - minByte + 1;
    if (maxByte < minByte || (newSize >= vn.getSize()))
      return 0;
    if (!RulePullsubMulti.acceptableSize(newSize)) return 0;
    const outvn: Varnode = op.getOut()!;
    if (outvn.isPrecisLo() || outvn.isPrecisHi()) return 0;

    let consume: bigint = calc_mask(newSize) << BigInt(8 * minByte);
    consume = ~consume;
    if ((consume & indir.getIn(0)!.getConsume()) !== 0n) return 0;

    let small2: Varnode;
    let smalladdr2: Address;

    if (!vn.getSpace()!.isBigEndian())
      smalladdr2 = vn.getAddr().add(BigInt(minByte));
    else
      smalladdr2 = vn.getAddr().add(BigInt(vn.getSize() - maxByte - 1));

    if (indir.isIndirectCreation()) {
      const possibleout: boolean = !indir.getIn(0)!.isIndirectZero();
      const new_ind: PcodeOp = data.newIndirectCreation(targ_op, smalladdr2, newSize, possibleout);
      small2 = new_ind.getOut()!;
    }
    else {
      const basevn: Varnode = indir.getIn(0)!;
      let small1: Varnode | null = RulePullsubMulti.findSubpiece(basevn, newSize, Number(op.getIn(1)!.getOffset()));
      if (small1 === null)
        small1 = RulePullsubMulti.buildSubpiece(basevn, newSize, Number(op.getIn(1)!.getOffset()), data);
      // Create new indirect near original indirect
      const new_ind: PcodeOp = data.newOp(2, indir.getAddr());
      data.opSetOpcode(new_ind, OpCode.CPUI_INDIRECT);
      small2 = data.newVarnodeOut(newSize, smalladdr2, new_ind);
      data.opSetInput(new_ind, small1, 0);
      data.opSetInput(new_ind, data.newVarnodeIop(targ_op), 1);
      data.opInsertBefore(new_ind, indir);
    }

    RulePullsubMulti.replaceDescendants(vn, small2, maxByte, minByte, data);
    return 1;
  }
}

/// Simplify MULTIEQUAL operations where the branches hold the same value
///
/// Look for a two-branch MULTIEQUAL where both inputs are constructed in
/// functionally equivalent ways. Remove (the reference to) one construction
/// and move the other into the merge block.
export class RulePushMulti extends Rule {
  constructor(g: string) {
    super(g, 0, "push_multi");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RulePushMulti(this.getGroup());
  }

  /// Find a previously existing MULTIEQUAL taking given inputs
  private static findSubstitute(in1: Varnode, in2: Varnode, bb: BlockBasic, earliest: PcodeOp): PcodeOp | null {
    for (let iter = in1.beginDescend(); iter < in1.endDescend(); iter++) {
      const op: PcodeOp = in1.getDescend(iter);
      if (op.getParent() !== bb) continue;
      if (op.code() !== OpCode.CPUI_MULTIEQUAL) continue;
      if (op.getIn(0)! !== in1) continue;
      if (op.getIn(1)! !== in2) continue;
      return op;
    }
    if (in1 === in2) return null;
    const buf1: Varnode[] = [null as any, null as any];
    const buf2: Varnode[] = [null as any, null as any];
    if (0 !== functionalEqualityLevel(in1, in2, buf1, buf2)) return null;
    const op1: PcodeOp = in1.getDef()!;  // in1 and in2 must be written
    const op2: PcodeOp = in2.getDef()!;
    for (let i = 0; i < op1.numInput(); ++i) {
      const vn: Varnode = op1.getIn(i)!;
      if (vn.isConstant()) continue;
      if (vn === op2.getIn(i)!)
        return Funcdata.cseFindInBlock(op1, vn, bb, earliest);
    }

    return null;
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_MULTIEQUAL);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (op.numInput() !== 2) return 0;

    const in1: Varnode = op.getIn(0)!;
    const in2: Varnode = op.getIn(1)!;

    if (!in1.isWritten()) return 0;
    if (!in2.isWritten()) return 0;
    if (in1.isSpacebase()) return 0;
    if (in2.isSpacebase()) return 0;
    const buf1: Varnode[] = [null as any, null as any];
    const buf2: Varnode[] = [null as any, null as any];
    const res: number = functionalEqualityLevel(in1, in2, buf1, buf2);
    if (res < 0) return 0;
    if (res > 1) return 0;
    const op1: PcodeOp = in1.getDef()!;
    if (op1.code() === OpCode.CPUI_SUBPIECE) return 0;  // SUBPIECE is pulled not pushed

    const bl: BlockBasic = op.getParent() as BlockBasic;
    const earliest: PcodeOp = bl.earliestUse(op.getOut()!);
    if (op1.code() === OpCode.CPUI_COPY) {
      // Special case of MERGE of 2 shadowing varnodes
      if (res === 0) return 0;
      const substitute: PcodeOp | null = RulePushMulti.findSubstitute(buf1[0], buf2[0], bl, earliest);
      if (substitute === null) return 0;
      // Eliminate this op in favor of the shadowed merge
      data.totalReplace(op.getOut()!, substitute.getOut()!);
      data.opDestroy(op);
      return 1;
    }
    const op2: PcodeOp = in2.getDef()!;
    if (in1.loneDescend()! !== op) return 0;
    if (in2.loneDescend()! !== op) return 0;

    const outvn: Varnode = op.getOut()!;

    data.opSetOutput(op1, outvn);  // Move MULTIEQUAL output to op1
    data.opUninsert(op1);          // Move the unified op
    if (res === 1) {
      const slot1: number = op1.getSlot(buf1[0]);
      let substitute: PcodeOp | null = RulePushMulti.findSubstitute(buf1[0], buf2[0], bl, earliest);
      if (substitute === null) {
        substitute = data.newOp(2, op.getAddr());
        data.opSetOpcode(substitute, OpCode.CPUI_MULTIEQUAL);
        // Try to preserve the storage location if the input varnodes share it
        if ((buf1[0].getAddr().equals(buf2[0].getAddr())) && (!buf1[0].isAddrTied()))
          data.newVarnodeOut(buf1[0].getSize(), buf1[0].getAddr(), substitute);
        else
          data.newUniqueOut(buf1[0].getSize(), substitute);
        data.opSetInput(substitute, buf1[0], 0);
        data.opSetInput(substitute, buf2[0], 1);
        data.opInsertBegin(substitute, bl);
      }
      data.opSetInput(op1, substitute.getOut()!, slot1);
      data.opInsertAfter(op1, substitute);  // Complete move of unified op into merge block
    }
    else {
      data.opInsertBegin(op1, bl);  // Complete move of unified op into merge block
    }
    data.opDestroy(op);   // Destroy the MULTIEQUAL
    data.opDestroy(op2);  // Remove the duplicate (in favor of the unified)
    return 1;
  }
}

/// Distribute BOOL_NEGATE: !(V && W)  =>  !V || !W
export class RuleNotDistribute extends Rule {
  constructor(g: string) {
    super(g, 0, "notdistribute");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleNotDistribute(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_BOOL_NEGATE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const compop: PcodeOp = op.getIn(0)!.getDef()!;
    if (compop === null) return 0;
    let opc: OpCode;

    switch (compop.code()) {
      case OpCode.CPUI_BOOL_AND:
        opc = OpCode.CPUI_BOOL_OR;
        break;
      case OpCode.CPUI_BOOL_OR:
        opc = OpCode.CPUI_BOOL_AND;
        break;
      default:
        return 0;
    }

    const newneg1: PcodeOp = data.newOp(1, op.getAddr());
    const newout1: Varnode = data.newUniqueOut(1, newneg1);
    data.opSetOpcode(newneg1, OpCode.CPUI_BOOL_NEGATE);
    data.opSetInput(newneg1, compop.getIn(0)!, 0);
    data.opInsertBefore(newneg1, op);

    const newneg2: PcodeOp = data.newOp(1, op.getAddr());
    const newout2: Varnode = data.newUniqueOut(1, newneg2);
    data.opSetOpcode(newneg2, OpCode.CPUI_BOOL_NEGATE);
    data.opSetInput(newneg2, compop.getIn(1)!, 0);
    data.opInsertBefore(newneg2, op);

    data.opSetOpcode(op, opc);
    data.opSetInput(op, newout1, 0);
    data.opInsertInput(op, newout2, 1);
    return 1;
  }
}

/// Simplify INT_AND when applied to aligned INT_ADD: (V + c) & 0xfff0  =>  V + (c & 0xfff0)
///
/// If V and W are aligned to a mask, then
/// ((V + c) + W) & 0xfff0   =>   (V + (c & 0xfff0)) + W
export class RuleHighOrderAnd extends Rule {
  constructor(g: string) {
    super(g, 0, "highorderand");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleHighOrderAnd(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_AND);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const cvn1: Varnode = op.getIn(1)!;
    if (!cvn1.isConstant()) return 0;
    if (!op.getIn(0)!.isWritten()) return 0;
    const addop: PcodeOp = op.getIn(0)!.getDef()!;
    if (addop.code() !== OpCode.CPUI_INT_ADD) return 0;

    let val: bigint = cvn1.getOffset();
    const size: number = cvn1.getSize();
    // Check that cvn1 is of the form 11110000
    if (((val - 1n) | val) !== calc_mask(size)) return 0;

    const cvn2: Varnode = addop.getIn(1)!;
    if (cvn2.isConstant()) {
      const xalign: Varnode = addop.getIn(0)!;
      if (xalign.isFree()) return 0;
      const mask1: bigint = xalign.getNZMask();
      // addop->Input(0) must be unaffected by the AND
      if ((mask1 & val) !== mask1) return 0;

      data.opSetOpcode(op, OpCode.CPUI_INT_ADD);
      data.opSetInput(op, xalign, 0);
      val = val & cvn2.getOffset();
      data.opSetInput(op, data.newConstant(size, val), 1);
      return 1;
    }
    else {
      if (addop.getOut()!.loneDescend()! !== op) return 0;
      for (let i = 0; i < 2; ++i) {
        const zerovn: Varnode = addop.getIn(i)!;
        let mask2: bigint = zerovn.getNZMask();
        if ((mask2 & val) !== mask2) continue;
        const nonzerovn: Varnode = addop.getIn(1 - i)!;
        if (!nonzerovn.isWritten()) continue;
        const addop2: PcodeOp = nonzerovn.getDef()!;
        if (addop2.code() !== OpCode.CPUI_INT_ADD) continue;
        if (nonzerovn.loneDescend()! !== addop) continue;
        const cvn2inner: Varnode = addop2.getIn(1)!;
        if (!cvn2inner.isConstant()) continue;
        const xalign: Varnode = addop2.getIn(0)!;
        mask2 = xalign.getNZMask();
        if ((mask2 & val) !== mask2) continue;
        val = val & cvn2inner.getOffset();
        data.opSetInput(addop2, data.newConstant(size, val), 1);
        // Convert the AND to a COPY
        data.opRemoveInput(op, 1);
        data.opSetOpcode(op, OpCode.CPUI_COPY);
        return 1;
      }
    }
    return 0;
  }
}

/// Distribute INT_AND through INT_OR if result is simpler
export class RuleAndDistribute extends Rule {
  constructor(g: string) {
    super(g, 0, "anddistribute");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleAndDistribute(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_AND);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let orvn: Varnode, othervn: Varnode, newvn1: Varnode, newvn2: Varnode;
    let orop: PcodeOp | null = null;
    let ormask1: bigint, ormask2: bigint, othermask: bigint, fullmask: bigint;
    let i: number;

    const size: number = op.getOut()!.getSize();
    if (size > 8) return 0;  // FIXME: uintb should be arbitrary precision
    fullmask = calc_mask(size);
    for (i = 0; i < 2; ++i) {
      othervn = op.getIn(1 - i)!;
      if (!othervn.isHeritageKnown()) continue;
      orvn = op.getIn(i)!;
      orop = orvn.getDef()!;
      if (orop === null) continue;
      if (orop.code() !== OpCode.CPUI_INT_OR) continue;
      if (!orop.getIn(0)!.isHeritageKnown()) continue;
      if (!orop.getIn(1)!.isHeritageKnown()) continue;
      othermask = othervn.getNZMask();
      if (othermask === 0n) continue;  // This case picked up by andmask
      if (othermask === fullmask) continue;  // Nothing useful from distributing
      ormask1 = orop.getIn(0)!.getNZMask();
      if ((ormask1 & othermask) === 0n) break;  // AND would cancel if distributed
      ormask2 = orop.getIn(1)!.getNZMask();
      if ((ormask2 & othermask) === 0n) break;  // AND would cancel if distributed
      if (othervn.isConstant()) {
        if ((ormask1 & othermask) === ormask1) break;  // AND is trivial if distributed
        if ((ormask2 & othermask) === ormask2) break;
      }
    }
    if (i === 2) return 0;
    othervn = op.getIn(1 - i)!;

    // Do distribution
    const newop1: PcodeOp = data.newOp(2, op.getAddr());
    newvn1 = data.newUniqueOut(size, newop1);
    data.opSetOpcode(newop1, OpCode.CPUI_INT_AND);
    data.opSetInput(newop1, orop!.getIn(0)!, 0);
    data.opSetInput(newop1, othervn, 1);
    data.opInsertBefore(newop1, op);

    const newop2: PcodeOp = data.newOp(2, op.getAddr());
    newvn2 = data.newUniqueOut(size, newop2);
    data.opSetOpcode(newop2, OpCode.CPUI_INT_AND);
    data.opSetInput(newop2, orop!.getIn(1)!, 0);
    data.opSetInput(newop2, othervn, 1);
    data.opInsertBefore(newop2, op);

    data.opSetInput(op, newvn1, 0);
    data.opSetInput(op, newvn2, 1);
    data.opSetOpcode(op, OpCode.CPUI_INT_OR);

    return 1;
  }
}

/// Transform INT_LESS of 0 or 1: V < 1  =>  V == 0,  V <= 0  =>  V == 0
export class RuleLessOne extends Rule {
  constructor(g: string) {
    super(g, 0, "lessone");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleLessOne(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_LESS);
    oplist.push(OpCode.CPUI_INT_LESSEQUAL);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const constvn: Varnode = op.getIn(1)!;

    if (!constvn.isConstant()) return 0;
    const val: bigint = constvn.getOffset();
    if ((op.code() === OpCode.CPUI_INT_LESS) && (val !== 1n)) return 0;
    if ((op.code() === OpCode.CPUI_INT_LESSEQUAL) && (val !== 0n)) return 0;

    data.opSetOpcode(op, OpCode.CPUI_INT_EQUAL);
    if (val !== 0n)
      data.opSetInput(op, data.newConstant(constvn.getSize(), 0n), 1);
    return 1;
  }
}

/// Merge range conditions of the form: V s< c, c s< V, V == c, V != c
///
/// Look for combinations of these forms based on BOOL_AND and BOOL_OR, such as
///  <range1>&&<range2> OR <range1>||<range2>
/// Try to union or intersect the ranges to produce a more concise expression.
export class RuleRangeMeld extends Rule {
  constructor(g: string) {
    super(g, 0, "rangemeld");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleRangeMeld(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_BOOL_OR);
    oplist.push(OpCode.CPUI_BOOL_AND);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let sub1: PcodeOp, sub2: PcodeOp;
    let vn1: Varnode, vn2: Varnode;
    let A1: Varnode | null, A2: Varnode | null;

    vn1 = op.getIn(0)!;
    if (!vn1.isWritten()) return 0;
    vn2 = op.getIn(1)!;
    if (!vn2.isWritten()) return 0;
    sub1 = vn1.getDef()!;
    if (!sub1.isBoolOutput())
      return 0;
    sub2 = vn2.getDef()!;
    if (!sub2.isBoolOutput())
      return 0;

    const range1: CircleRange = new CircleRange(true);
    let markup: Varnode | null = null;
    A1 = range1.pullBack(sub1, markup, false);
    if (A1 === null) return 0;
    const range2: CircleRange = new CircleRange(true);
    A2 = range2.pullBack(sub2, markup, false);
    if (A2 === null) return 0;
    if (sub1.code() === OpCode.CPUI_BOOL_NEGATE) {
      // Do an extra pull back, if the last step is a '!'
      if (!A1.isWritten()) return 0;
      A1 = range1.pullBack(A1.getDef()!, markup, false);
      if (A1 === null) return 0;
    }
    if (sub2.code() === OpCode.CPUI_BOOL_NEGATE) {
      if (!A2.isWritten()) return 0;
      A2 = range2.pullBack(A2.getDef()!, markup, false);
      if (A2 === null) return 0;
    }
    if (!functionalEquality(A1, A2)) {
      if (A2.getSize() === A1.getSize()) return 0;
      if ((A1.getSize() < A2.getSize()) && (A2.isWritten()))
        A2 = range2.pullBack(A2.getDef()!, markup, false);
      else if (A1.isWritten())
        A1 = range1.pullBack(A1.getDef()!, markup, false);
      if (A1 !== A2) return 0;
    }
    if (!A1!.isHeritageKnown()) return 0;

    let restype: number;
    if (op.code() === OpCode.CPUI_BOOL_AND)
      restype = range1.intersect(range2);
    else
      restype = range1.circleUnion(range2);

    if (restype === 0) {
      const result = { opc: OpCode.CPUI_COPY as OpCode, c: 0n, cslot: 0 };
      restype = range1.translate2Op(result);
      const opc = result.opc;
      const resc = result.c;
      const resslot = result.cslot;
      if (restype === 0) {
        const newConst: Varnode = data.newConstant(A1!.getSize(), resc);
        if (markup !== null) {
          // We have potential constant markup
          newConst.copySymbolIfValid(markup);
        }
        data.opSetOpcode(op, opc);
        data.opSetInput(op, A1!, 1 - resslot);
        data.opSetInput(op, newConst, resslot);
        return 1;
      }
    }

    if (restype === 2) return 0;  // Cannot represent
    if (restype === 1) {  // Pieces covers everything, condition is always true
      data.opSetOpcode(op, OpCode.CPUI_COPY);
      data.opRemoveInput(op, 1);
      data.opSetInput(op, data.newConstant(1, 1n), 0);
    }
    else if (restype === 3) {  // Nothing left in intersection, condition is always false
      data.opSetOpcode(op, OpCode.CPUI_COPY);
      data.opRemoveInput(op, 1);
      data.opSetInput(op, data.newConstant(1, 0n), 0);
    }
    return 1;
  }
}

/// Merge range conditions of the form: V f< c, c f< V, V f== c etc.
///
/// Convert (V f< W)||(V f== W)   =>   V f<= W (and similar variants)
export class RuleFloatRange extends Rule {
  constructor(g: string) {
    super(g, 0, "floatrange");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleFloatRange(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_BOOL_OR);
    oplist.push(OpCode.CPUI_BOOL_AND);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let cmp1: PcodeOp, cmp2: PcodeOp;

    const vn1: Varnode = op.getIn(0)!;
    if (!vn1.isWritten()) return 0;
    const vn2: Varnode = op.getIn(1)!;
    if (!vn2.isWritten()) return 0;
    cmp1 = vn1.getDef()!;
    cmp2 = vn2.getDef()!;
    let opccmp1: OpCode = cmp1.code();
    // Set cmp1 to LESS or LESSEQUAL operator, cmp2 is the "other" operator
    if ((opccmp1 !== OpCode.CPUI_FLOAT_LESS) && (opccmp1 !== OpCode.CPUI_FLOAT_LESSEQUAL)) {
      cmp1 = cmp2;
      cmp2 = vn1.getDef()!;
      opccmp1 = cmp1.code();
    }
    let resultopc: OpCode = OpCode.CPUI_COPY;
    if (opccmp1 === OpCode.CPUI_FLOAT_LESS) {
      if ((cmp2.code() === OpCode.CPUI_FLOAT_EQUAL) && (op.code() === OpCode.CPUI_BOOL_OR))
        resultopc = OpCode.CPUI_FLOAT_LESSEQUAL;
    }
    else if (opccmp1 === OpCode.CPUI_FLOAT_LESSEQUAL) {
      if ((cmp2.code() === OpCode.CPUI_FLOAT_NOTEQUAL) && (op.code() === OpCode.CPUI_BOOL_AND))
        resultopc = OpCode.CPUI_FLOAT_LESS;
    }

    if (resultopc === OpCode.CPUI_COPY) return 0;

    // Make sure both operators are comparing the same things
    let slot1 = 0;
    let nvn1: Varnode = cmp1.getIn(slot1)!;
    if (nvn1.isConstant()) {
      slot1 = 1;
      nvn1 = cmp1.getIn(slot1)!;
      if (nvn1.isConstant()) return 0;
    }
    if (nvn1.isFree()) return 0;
    const cvn1: Varnode = cmp1.getIn(1 - slot1)!;
    let slot2: number;
    if (nvn1 !== cmp2.getIn(0)!) {
      slot2 = 1;
      if (nvn1 !== cmp2.getIn(1)!)
        return 0;
    }
    else {
      slot2 = 0;
    }
    const matchvn: Varnode = cmp2.getIn(1 - slot2)!;
    if (cvn1.isConstant()) {
      if (!matchvn.isConstant()) return 0;
      if (matchvn.getOffset() !== cvn1.getOffset()) return 0;
    }
    else if (cvn1 !== matchvn)
      return 0;
    else if (cvn1.isFree())
      return 0;

    // Collapse the 2 comparisons into 1 comparison
    data.opSetOpcode(op, resultopc);
    data.opSetInput(op, nvn1, slot1);
    if (cvn1.isConstant())
      data.opSetInput(op, data.newConstant(cvn1.getSize(), cvn1.getOffset()), 1 - slot1);
    else
      data.opSetInput(op, cvn1, 1 - slot1);
    return 1;
  }
}

/// Commute INT_AND with INT_LEFT and INT_RIGHT: (V << W) & d  =>  (V & (W >> c)) << c
///
/// This makes sense to do if W is constant and there is no other use of (V << W).
/// If W is not constant, it only makes sense if the INT_AND is likely to cancel
/// with a specific INT_OR or PIECE.
export class RuleAndCommute extends Rule {
  constructor(g: string) {
    super(g, 0, "andcommute");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleAndCommute(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_AND);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let orvn: Varnode, shiftvn: Varnode, othervn: Varnode, savn: Varnode;
    let shiftop: PcodeOp;
    let ormask1: bigint, ormask2: bigint, othermask: bigint, fullmask: bigint;
    let opc: OpCode = OpCode.CPUI_INT_OR;  // Unnecessary initialization
    let sa: number, i: number;

    const size: number = op.getOut()!.getSize();
    if (size > 8) return 0;  // FIXME: uintb should be arbitrary precision
    fullmask = calc_mask(size);
    orvn = null as any;
    othervn = null as any;
    savn = null as any;
    for (i = 0; i < 2; ++i) {
      shiftvn = op.getIn(i)!;
      shiftop = shiftvn.getDef()!;
      if (shiftop === null) continue;
      opc = shiftop.code();
      if ((opc !== OpCode.CPUI_INT_LEFT) && (opc !== OpCode.CPUI_INT_RIGHT)) continue;
      savn = shiftop.getIn(1)!;
      if (!savn.isConstant()) continue;
      sa = Number(savn.getOffset());

      othervn = op.getIn(1 - i)!;
      if (!othervn.isHeritageKnown()) continue;
      othermask = othervn.getNZMask();
      // Check if AND is only zeroing bits which are already
      // zeroed by the shift
      if (opc === OpCode.CPUI_INT_RIGHT) {
        if ((fullmask >> BigInt(sa)) === othermask) continue;
        othermask <<= BigInt(sa);  // Calc mask as it will be after commute
      }
      else {
        if (((fullmask << BigInt(sa)) & fullmask) === othermask) continue;
        othermask >>= BigInt(sa);
      }
      if (othermask === 0n) continue;  // Handled by andmask
      if (othermask === fullmask) continue;

      orvn = shiftop.getIn(0)!;
      if ((opc === OpCode.CPUI_INT_LEFT) && (othervn.isConstant())) {
        if (shiftvn.loneDescend()! === op) break;
      }

      if (!orvn.isWritten()) continue;
      const orop: PcodeOp = orvn.getDef()!;

      if (orop.code() === OpCode.CPUI_INT_OR) {
        ormask1 = orop.getIn(0)!.getNZMask();
        if ((ormask1 & othermask) === 0n) break;
        ormask2 = orop.getIn(1)!.getNZMask();
        if ((ormask2 & othermask) === 0n) break;
        if (othervn.isConstant()) {
          if ((ormask1 & othermask) === ormask1) break;
          if ((ormask2 & othermask) === ormask2) break;
        }
      }
      else if (orop.code() === OpCode.CPUI_PIECE) {
        ormask1 = orop.getIn(1)!.getNZMask();  // Low part of piece
        if ((ormask1 & othermask) === 0n) break;
        ormask2 = orop.getIn(0)!.getNZMask();  // High part
        ormask2 <<= BigInt(orop.getIn(1)!.getSize() * 8);
        if ((ormask2 & othermask) === 0n) break;
      }
      else {
        continue;
      }
    }
    if (i === 2) return 0;
    // Do the commute
    const newop1: PcodeOp = data.newOp(2, op.getAddr());
    const newvn1: Varnode = data.newUniqueOut(size, newop1);
    data.opSetOpcode(newop1, (opc === OpCode.CPUI_INT_LEFT) ? OpCode.CPUI_INT_RIGHT : OpCode.CPUI_INT_LEFT);
    data.opSetInput(newop1, othervn, 0);
    data.opSetInput(newop1, savn, 1);
    data.opInsertBefore(newop1, op);

    const newop2: PcodeOp = data.newOp(2, op.getAddr());
    const newvn2: Varnode = data.newUniqueOut(size, newop2);
    data.opSetOpcode(newop2, OpCode.CPUI_INT_AND);
    data.opSetInput(newop2, orvn, 0);
    data.opSetInput(newop2, newvn1, 1);
    data.opInsertBefore(newop2, op);

    data.opSetInput(op, newvn2, 0);
    data.opSetInput(op, savn, 1);
    data.opSetOpcode(op, opc);

    return 1;
  }
}

/// Convert PIECE to INT_ZEXT where appropriate: V & concat(W,X)  =>  zext(X)
///
/// Conversion to INT_ZEXT works if we know the upper part of the result is zero.
/// Similarly if the lower part is zero: V & concat(W,X)  =>  V & concat(#0,X)
export class RuleAndPiece extends Rule {
  constructor(g: string) {
    super(g, 0, "andpiece");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleAndPiece(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_AND);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let piecevn: Varnode, othervn: Varnode, highvn: Varnode, lowvn: Varnode, newvn: Varnode;
    let pieceop: PcodeOp;
    let othermask: bigint, maskhigh: bigint, masklow: bigint;
    let opc: OpCode = OpCode.CPUI_PIECE;  // Unnecessary initialization
    let i: number;

    const size: number = op.getOut()!.getSize();
    highvn = null as any;
    lowvn = null as any;
    for (i = 0; i < 2; ++i) {
      piecevn = op.getIn(i)!;
      if (!piecevn.isWritten()) continue;
      pieceop = piecevn.getDef()!;
      if (pieceop.code() !== OpCode.CPUI_PIECE) continue;
      othervn = op.getIn(1 - i)!;
      othermask = othervn.getNZMask();
      if (othermask === calc_mask(size)) continue;
      if (othermask === 0n) continue;  // Handled by andmask
      highvn = pieceop.getIn(0)!;
      if (!highvn.isHeritageKnown()) continue;
      lowvn = pieceop.getIn(1)!;
      if (!lowvn.isHeritageKnown()) continue;
      maskhigh = highvn.getNZMask();
      masklow = lowvn.getNZMask();
      if ((maskhigh & (othermask >> BigInt(lowvn.getSize() * 8))) === 0n) {
        if ((maskhigh === 0n) && (highvn.isConstant())) continue;  // Handled by piece2zext
        opc = OpCode.CPUI_INT_ZEXT;
        break;
      }
      else if ((masklow & othermask) === 0n) {
        if (lowvn.isConstant()) continue;  // Nothing to do
        opc = OpCode.CPUI_PIECE;
        break;
      }
    }
    if (i === 2) return 0;
    let newop: PcodeOp;
    if (opc === OpCode.CPUI_INT_ZEXT) {
      // Change PIECE(a,b) to ZEXT(b)
      newop = data.newOp(1, op.getAddr());
      data.opSetOpcode(newop, opc);
      data.opSetInput(newop, lowvn, 0);
    }
    else {
      // Change PIECE(a,b) to PIECE(a,#0)
      const newvn2: Varnode = data.newConstant(lowvn.getSize(), 0n);
      newop = data.newOp(2, op.getAddr());
      data.opSetOpcode(newop, opc);
      data.opSetInput(newop, highvn, 0);
      data.opSetInput(newop, newvn2, 1);
    }
    newvn = data.newUniqueOut(size, newop);
    data.opInsertBefore(newop, op);
    data.opSetInput(op, newvn, i);
    return 1;
  }
}

/// Convert INT_AND to INT_ZEXT where appropriate: sext(X) & 0xffff  =>  zext(X)
///
/// Similarly concat(Y,X) & 0xffff  =>  zext(X)
export class RuleAndZext extends Rule {
  constructor(g: string) {
    super(g, 0, "andzext");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleAndZext(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_AND);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const cvn1: Varnode = op.getIn(1)!;
    if (!cvn1.isConstant()) return 0;
    if (!op.getIn(0)!.isWritten()) return 0;
    const otherop: PcodeOp = op.getIn(0)!.getDef()!;
    const opc: OpCode = otherop.code();
    let rootvn: Varnode;
    if (opc === OpCode.CPUI_INT_SEXT)
      rootvn = otherop.getIn(0)!;
    else if (opc === OpCode.CPUI_PIECE)
      rootvn = otherop.getIn(1)!;
    else
      return 0;
    const mask: bigint = calc_mask(rootvn.getSize());
    if (mask !== cvn1.getOffset())
      return 0;
    if (rootvn.isFree())
      return 0;
    if (rootvn.getSize() > 8)  // FIXME: Should be arbitrary precision
      return 0;
    data.opSetOpcode(op, OpCode.CPUI_INT_ZEXT);
    data.opRemoveInput(op, 1);
    data.opSetInput(op, rootvn, 0);
    return 1;
  }
}

/// Simplify INT_ZEXT and SUBPIECE in masked comparison:
///   zext(V) & c == 0  =>  V & (c & mask) == 0
///
/// Similarly:  sub(V,c) & d == 0  =>  V & (d & mask) == 0
export class RuleAndCompare extends Rule {
  constructor(g: string) {
    super(g, 0, "andcompare");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleAndCompare(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_EQUAL);
    oplist.push(OpCode.CPUI_INT_NOTEQUAL);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (!op.getIn(1)!.isConstant()) return 0;
    if (op.getIn(1)!.getOffset() !== 0n) return 0;

    let andvn: Varnode, subvn: Varnode, basevn: Varnode, constvn: Varnode;
    let andop: PcodeOp, subop: PcodeOp;
    let andconst: bigint, baseconst: bigint;

    andvn = op.getIn(0)!;
    if (!andvn.isWritten()) return 0;
    andop = andvn.getDef()!;
    if (andop.code() !== OpCode.CPUI_INT_AND) return 0;
    if (!andop.getIn(1)!.isConstant()) return 0;
    subvn = andop.getIn(0)!;
    if (!subvn.isWritten()) return 0;
    subop = subvn.getDef()!;
    switch (subop.code()) {
      case OpCode.CPUI_SUBPIECE:
        basevn = subop.getIn(0)!;
        if (basevn.getSize() > 8) return 0;
        baseconst = andop.getIn(1)!.getOffset();
        andconst = baseconst << (subop.getIn(1)!.getOffset() * 8n);
        break;
      case OpCode.CPUI_INT_ZEXT:
        basevn = subop.getIn(0)!;
        baseconst = andop.getIn(1)!.getOffset();
        andconst = baseconst & calc_mask(basevn.getSize());
        break;
      default:
        return 0;
    }

    if (baseconst === calc_mask(andvn.getSize())) return 0;  // Degenerate AND
    if (basevn.isFree()) return 0;

    constvn = data.newConstant(basevn.getSize(), andconst);
    if (baseconst === andconst)  // If no effective change in constant (except varnode size)
      constvn.copySymbol(andop.getIn(1)!);  // Keep any old symbol
    // New version of and with bigger inputs
    const newop: PcodeOp = data.newOp(2, andop.getAddr());
    data.opSetOpcode(newop, OpCode.CPUI_INT_AND);
    const newout: Varnode = data.newUniqueOut(basevn.getSize(), newop);
    data.opSetInput(newop, basevn, 0);
    data.opSetInput(newop, constvn, 1);
    data.opInsertBefore(newop, andop);

    data.opSetInput(op, newout, 0);
    data.opSetInput(op, data.newConstant(basevn.getSize(), 0n), 1);
    return 1;
  }
}
// ---- PART 2: RuleDoubleSub through RuleMultiCollapse (lines ~1800-3600) ----

/// \class RuleDoubleSub
/// \brief Simplify chained SUBPIECE:  `sub( sub(V,c), d)  =>  sub(V, c+d)`
export class RuleDoubleSub extends Rule {
  constructor(g: string) {
    super(g, 0, "doublesub");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleDoubleSub(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_SUBPIECE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let op2: PcodeOp;
    let vn: Varnode;
    let offset1: number, offset2: number;

    vn = op.getIn(0)!;
    if (!vn.isWritten()) return 0;
    op2 = vn.getDef()!;
    if (op2.code() !== OpCode.CPUI_SUBPIECE) return 0;
    offset1 = Number(op.getIn(1)!.getOffset());
    offset2 = Number(op2.getIn(1)!.getOffset());

    data.opSetInput(op, op2.getIn(0)!, 0);  // Skip middleman
    data.opSetInput(op, data.newConstant(4, BigInt(offset1 + offset2)), 1);
    return 1;
  }
}

/// \class RuleDoubleShift
/// \brief Simplify chained shifts INT_LEFT and INT_RIGHT
///
/// INT_MULT is considered a shift if it multiplies by a constant power of 2.
/// The shifts can combine or cancel. Combined shifts may zero out result.
///
///    - `(V << c) << d  =>  V << (c+d)`
///    - `(V << c) >> c  =>  V & 0xff`
///    - `(V << c) >> d  =>  (V & 0xffff) << (c - d)`
export class RuleDoubleShift extends Rule {
  constructor(g: string) {
    super(g, 0, "doubleshift");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleDoubleShift(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_LEFT);
    oplist.push(OpCode.CPUI_INT_RIGHT);
    oplist.push(OpCode.CPUI_INT_MULT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let sa1: number, sa2: number;
    let mask: bigint;

    if (!op.getIn(1)!.isConstant()) return 0;
    const secvn: Varnode = op.getIn(0)!;
    if (!secvn.isWritten()) return 0;
    const secop: PcodeOp = secvn.getDef()!;
    let opc2: number = secop.code();
    if ((opc2 !== OpCode.CPUI_INT_LEFT) && (opc2 !== OpCode.CPUI_INT_RIGHT) && (opc2 !== OpCode.CPUI_INT_MULT))
      return 0;
    if (!secop.getIn(1)!.isConstant()) return 0;
    let opc1: number = op.code();
    const size: number = secvn.getSize();
    if (!secop.getIn(0)!.isHeritageKnown()) return 0;

    if (opc1 === OpCode.CPUI_INT_MULT) {
      const val: bigint = op.getIn(1)!.getOffset();
      sa1 = leastsigbit_set(val);
      if ((val >> BigInt(sa1)) !== 1n) return 0; // Not multiplying by a power of 2
      opc1 = OpCode.CPUI_INT_LEFT;
    }
    else
      sa1 = Number(op.getIn(1)!.getOffset());
    if (opc2 === OpCode.CPUI_INT_MULT) {
      const val: bigint = secop.getIn(1)!.getOffset();
      sa2 = leastsigbit_set(val);
      if ((val >> BigInt(sa2)) !== 1n) return 0; // Not multiplying by a power of 2
      opc2 = OpCode.CPUI_INT_LEFT;
    }
    else
      sa2 = Number(secop.getIn(1)!.getOffset());
    if (opc1 === opc2) {        // Shifts in the same direction
      if (sa1 + sa2 < 8 * size) {
        const newvn: Varnode = data.newConstant(4, BigInt(sa1 + sa2));
        data.opSetOpcode(op, opc1);
        data.opSetInput(op, secop.getIn(0)!, 0);
        data.opSetInput(op, newvn, 1);
      }
      else {
        const newvn: Varnode = data.newConstant(size, 0n);
        data.opSetOpcode(op, OpCode.CPUI_COPY);
        data.opSetInput(op, newvn, 0);
        data.opRemoveInput(op, 1);
      }
    }
    else {            // Shifts in opposite directions
      if (size > 8) return 0;  // FIXME: precision
      mask = calc_mask(size);
      let diffsa: number;       // Bits (to the left) after cancellation
      if (opc1 === OpCode.CPUI_INT_LEFT) {
        // The INT_LEFT is highly likely to be a multiply
        if (secvn.loneDescend()! === null) return 0;
        mask = (mask << BigInt(sa2)) & mask;  // Most significant bits remain after initial INT_RIGHT
        diffsa = sa1 - sa2;
        if (diffsa !== 0)  // Don't collapse unless shift amounts are identical
          return 0;
      }
      else {
        mask = (mask >> BigInt(sa2)) & mask;  // Least significant bits remain after initial INT_LEFT
        diffsa = sa2 - sa1;
      }
      if (diffsa === 0) {      // Opposite shifts exactly cancel
        const newvn: Varnode = data.newConstant(size, mask);
        data.opSetOpcode(op, OpCode.CPUI_INT_AND);
        data.opSetInput(op, secop.getIn(0)!, 0);
        data.opSetInput(op, newvn, 1);
      }
      else {          // Shifts only partly cancel
        const newAnd: PcodeOp = data.newOp(2, op.getAddr());
        data.opSetOpcode(newAnd, OpCode.CPUI_INT_AND);
        data.opSetInput(newAnd, secop.getIn(0)!, 0);
        data.opSetInput(newAnd, data.newConstant(size, mask), 1);
        const newOut: Varnode = data.newUniqueOut(size, newAnd);
        data.opInsertBefore(newAnd, op);
        let finalopc: number = OpCode.CPUI_INT_LEFT;
        if (diffsa < 0) {
          finalopc = OpCode.CPUI_INT_RIGHT;
          diffsa = -diffsa;
        }
        data.opSetOpcode(op, finalopc);
        data.opSetInput(op, newOut, 0);
        data.opSetInput(op, data.newConstant(4, BigInt(diffsa)), 1);
      }
    }
    return 1;
  }
}

/// \class RuleDoubleArithShift
/// \brief Simplify two sequential INT_SRIGHT: `(x s>> c) s>> d   =>  x s>> saturate(c + d)`
///
/// Division optimization in particular can produce a sequence of signed right shifts.
/// The shift amounts add up to the point where the sign bit has saturated the entire result.
export class RuleDoubleArithShift extends Rule {
  constructor(g: string) {
    super(g, 0, "doublearithshift");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleDoubleArithShift(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_SRIGHT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const constD: Varnode = op.getIn(1)!;
    if (!constD.isConstant()) return 0;
    const shiftin: Varnode = op.getIn(0)!;
    if (!shiftin.isWritten()) return 0;
    const shift2op: PcodeOp = shiftin.getDef()!;
    if (shift2op.code() !== OpCode.CPUI_INT_SRIGHT) return 0;
    const constC: Varnode = shift2op.getIn(1)!;
    if (!constC.isConstant()) return 0;
    const inVn: Varnode = shift2op.getIn(0)!;
    if (inVn.isFree()) return 0;
    const max: number = op.getOut()!.getSize() * 8 - 1;  // This is maximum possible shift.
    let sa: number = Number(constC.getOffset()) + Number(constD.getOffset());
    if (sa <= 0) return 0;  // Something is wrong
    if (sa > max)
      sa = max;        // Shift amount has saturated
    data.opSetInput(op, inVn, 0);
    data.opSetInput(op, data.newConstant(4, BigInt(sa)), 1);
    return 1;
  }
}

/// \class RuleConcatShift
/// \brief Simplify INT_RIGHT canceling PIECE: `concat(V,W) >> c  =>  zext(V)`
///
/// Right shifts (signed and unsigned) can throw away the least significant part
/// of a concatenation.  The result is a (sign or zero) extension of the most significant part.
/// Depending on the original shift amount, the extension may still need to be shifted.
export class RuleConcatShift extends Rule {
  constructor(g: string) {
    super(g, 0, "concatshift");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleConcatShift(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_RIGHT);
    oplist.push(OpCode.CPUI_INT_SRIGHT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (!op.getIn(1)!.isConstant()) return 0;

    const shiftin: Varnode = op.getIn(0)!;
    if (!shiftin.isWritten()) return 0;
    const concat: PcodeOp = shiftin.getDef()!;
    if (concat.code() !== OpCode.CPUI_PIECE) return 0;

    let sa: number = Number(op.getIn(1)!.getOffset());
    const leastsize: number = concat.getIn(1)!.getSize() * 8;
    if (sa < leastsize) return 0;  // Does shift throw away least sig part
    const mainin: Varnode = concat.getIn(0)!;
    if (mainin.isFree()) return 0;
    sa -= leastsize;
    const extcode: number = (op.code() === OpCode.CPUI_INT_RIGHT) ? OpCode.CPUI_INT_ZEXT : OpCode.CPUI_INT_SEXT;
    if (sa === 0) {      // Exact cancelation
      data.opRemoveInput(op, 1);  // Remove thrown away least
      data.opSetOpcode(op, extcode);  // Change to extension
      data.opSetInput(op, mainin, 0);
    }
    else {
      // Create a new extension op
      const extop: PcodeOp = data.newOp(1, op.getAddr());
      data.opSetOpcode(extop, extcode);
      const newvn: Varnode = data.newUniqueOut(shiftin.getSize(), extop);
      data.opSetInput(extop, mainin, 0);

      // Adjust the shift amount
      data.opSetInput(op, newvn, 0);
      data.opSetInput(op, data.newConstant(op.getIn(1)!.getSize(), BigInt(sa)), 1);
      data.opInsertBefore(extop, op);
    }
    return 1;
  }
}

/// \class RuleLeftRight
/// \brief Transform canceling INT_RIGHT or INT_SRIGHT of INT_LEFT
///
/// This works for both signed and unsigned right shifts. The shift
/// amount must be a multiple of 8.
///
/// `(V << c) s>> c  =>  sext( sub(V, #0) )`
export class RuleLeftRight extends Rule {
  constructor(g: string) {
    super(g, 0, "leftright");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleLeftRight(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_RIGHT);
    oplist.push(OpCode.CPUI_INT_SRIGHT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (!op.getIn(1)!.isConstant()) return 0;

    const shiftin: Varnode = op.getIn(0)!;
    if (!shiftin.isWritten()) return 0;
    const leftshift: PcodeOp = shiftin.getDef()!;
    if (leftshift.code() !== OpCode.CPUI_INT_LEFT) return 0;
    if (!leftshift.getIn(1)!.isConstant()) return 0;
    const sa: bigint = op.getIn(1)!.getOffset();
    if (leftshift.getIn(1)!.getOffset() !== sa) return 0; // Left shift must be by same amount

    if ((sa & 7n) !== 0n) return 0;  // Must be multiple of 8
    const isa: number = Number(sa >> 3n);
    const tsz: number = shiftin.getSize() - isa;
    if ((tsz !== 1) && (tsz !== 2) && (tsz !== 4) && (tsz !== 8)) return 0;

    if (shiftin.loneDescend()! !== op) return 0;
    let addr: Address = shiftin.getAddr();
    if (addr.isBigEndian())
      addr = addr.add(BigInt(isa));
    data.opUnsetInput(op, 0);
    data.opUnsetOutput(leftshift);
    addr.renormalize(tsz);
    const newvn: Varnode = data.newVarnodeOut(tsz, addr, leftshift);
    data.opSetOpcode(leftshift, OpCode.CPUI_SUBPIECE);
    data.opSetInput(leftshift, data.newConstant(leftshift.getIn(1)!.getSize(), 0n), 1);
    data.opSetInput(op, newvn, 0);
    data.opRemoveInput(op, 1);  // Remove the right-shift constant
    data.opSetOpcode(op, (op.code() === OpCode.CPUI_INT_SRIGHT) ? OpCode.CPUI_INT_SEXT : OpCode.CPUI_INT_ZEXT);
    return 1;
  }
}

/// \class RuleShiftCompare
/// \brief Transform shifts in comparisons:  `V >> c == d  =>  V == (d << c)`
///
/// Similarly: `V << c == d  =>  V & mask == (d >> c)`
///
/// The rule works on both INT_EQUAL and INT_NOTEQUAL.
export class RuleShiftCompare extends Rule {
  constructor(g: string) {
    super(g, 0, "shiftcompare");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleShiftCompare(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_EQUAL);
    oplist.push(OpCode.CPUI_INT_NOTEQUAL);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let shiftvn: Varnode, constvn: Varnode, savn: Varnode, mainvn: Varnode;
    let shiftop: PcodeOp;
    let sa: number;
    let constval: bigint, nzmask: bigint, newconst: bigint;
    let opc: number;
    let isleft: boolean;

    shiftvn = op.getIn(0)!;
    constvn = op.getIn(1)!;
    if (!constvn.isConstant()) return 0;
    if (!shiftvn.isWritten()) return 0;
    shiftop = shiftvn.getDef()!;
    opc = shiftop.code();
    if (opc === OpCode.CPUI_INT_LEFT) {
      isleft = true;
      savn = shiftop.getIn(1)!;
      if (!savn.isConstant()) return 0;
      sa = Number(savn.getOffset());
    }
    else if (opc === OpCode.CPUI_INT_RIGHT) {
      isleft = false;
      savn = shiftop.getIn(1)!;
      if (!savn.isConstant()) return 0;
      sa = Number(savn.getOffset());
      // There are definitely some situations where you don't want this rule to apply, like jump
      // table analysis where the switch variable is a bit field.
      // When shifting to the right, this is a likely shift out of a bitfield, which we would want to keep
      // We only apply when we know we will eliminate a variable
      if (shiftvn.loneDescend()! !== op) return 0;
    }
    else if (opc === OpCode.CPUI_INT_MULT) {
      isleft = true;
      savn = shiftop.getIn(1)!;
      if (!savn.isConstant()) return 0;
      const val: bigint = savn.getOffset();
      sa = leastsigbit_set(val);
      if ((val >> BigInt(sa)) !== 1n) return 0; // Not multiplying by a power of 2
    }
    else if (opc === OpCode.CPUI_INT_DIV) {
      isleft = false;
      savn = shiftop.getIn(1)!;
      if (!savn.isConstant()) return 0;
      const val: bigint = savn.getOffset();
      sa = leastsigbit_set(val);
      if ((val >> BigInt(sa)) !== 1n) return 0; // Not dividing by a power of 2
      if (shiftvn.loneDescend()! !== op) return 0;
    }
    else
      return 0;

    if (sa === 0) return 0;
    mainvn = shiftop.getIn(0)!;
    if (mainvn.isFree()) return 0;
    if (mainvn.getSize() > 8) return 0;  // FIXME: uintb should be arbitrary precision

    constval = constvn.getOffset();
    nzmask = mainvn.getNZMask();
    if (isleft) {
      newconst = constval >> BigInt(sa);
      if ((newconst << BigInt(sa)) !== constval) return 0;  // Information lost in constval
      let tmp: bigint = (nzmask << BigInt(sa)) & calc_mask(shiftvn.getSize());
      if ((tmp >> BigInt(sa)) !== nzmask) {  // Information is lost in main
        // We replace the LEFT with an AND mask
        // This must be the lone use of the shift
        if (shiftvn.loneDescend()! !== op) return 0;
        sa = 8 * shiftvn.getSize() - sa;
        tmp = (1n << BigInt(sa)) - 1n;
        const newmask: Varnode = data.newConstant(constvn.getSize(), tmp);
        const newop: PcodeOp = data.newOp(2, op.getAddr());
        data.opSetOpcode(newop, OpCode.CPUI_INT_AND);
        const newtmpvn: Varnode = data.newUniqueOut(constvn.getSize(), newop);
        data.opSetInput(newop, mainvn, 0);
        data.opSetInput(newop, newmask, 1);
        data.opInsertBefore(newop, shiftop);
        data.opSetInput(op, newtmpvn, 0);
        data.opSetInput(op, data.newConstant(constvn.getSize(), newconst), 1);
        return 1;
      }
    }
    else {
      if (((nzmask >> BigInt(sa)) << BigInt(sa)) !== nzmask) return 0;  // Information is lost
      newconst = (constval << BigInt(sa)) & calc_mask(shiftvn.getSize());
      if ((newconst >> BigInt(sa)) !== constval) return 0; // Information is lost in constval
    }
    const newconstvn: Varnode = data.newConstant(constvn.getSize(), newconst);
    data.opSetInput(op, mainvn, 0);
    data.opSetInput(op, newconstvn, 1);
    return 1;
  }
}

/// \class RuleLessEqual
/// \brief Simplify 'less than or equal':  `V < W || V == W  =>  V <= W`
///
/// Similarly: `V < W || V != W  =>  V != W`
///
/// Handle INT_SLESS variants as well.
export class RuleLessEqual extends Rule {
  constructor(g: string) {
    super(g, 0, "lessequal");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleLessEqual(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_BOOL_OR);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let compvn1: Varnode, compvn2: Varnode, vnout1: Varnode, vnout2: Varnode;
    let op_less: PcodeOp, op_equal: PcodeOp;
    let opc: number, equalopc: number;

    vnout1 = op.getIn(0)!;
    if (!vnout1.isWritten()) return 0;
    vnout2 = op.getIn(1)!;
    if (!vnout2.isWritten()) return 0;
    op_less = vnout1.getDef()!;
    opc = op_less.code();
    if ((opc !== OpCode.CPUI_INT_LESS) && (opc !== OpCode.CPUI_INT_SLESS)) {
      op_equal = op_less;
      op_less = vnout2.getDef()!;
      opc = op_less.code();
      if ((opc !== OpCode.CPUI_INT_LESS) && (opc !== OpCode.CPUI_INT_SLESS))
        return 0;
    }
    else
      op_equal = vnout2.getDef()!;
    equalopc = op_equal.code();
    if ((equalopc !== OpCode.CPUI_INT_EQUAL) && (equalopc !== OpCode.CPUI_INT_NOTEQUAL))
      return 0;

    compvn1 = op_less.getIn(0)!;
    compvn2 = op_less.getIn(1)!;
    if (!compvn1.isHeritageKnown()) return 0;
    if (!compvn2.isHeritageKnown()) return 0;
    if ((!compvn1.equals(op_equal.getIn(0)!) || !compvn2.equals(op_equal.getIn(1)!)) &&
        (!compvn1.equals(op_equal.getIn(1)!) || !compvn2.equals(op_equal.getIn(0)!)))
      return 0;

    if (equalopc === OpCode.CPUI_INT_NOTEQUAL) { // op_less is redundant
      data.opSetOpcode(op, OpCode.CPUI_COPY); // Convert OR to COPY
      data.opRemoveInput(op, 1);
      data.opSetInput(op, op_equal.getOut()!, 0); // Taking the NOTEQUAL output
    }
    else {
      data.opSetInput(op, compvn1, 0);
      data.opSetInput(op, compvn2, 1);
      data.opSetOpcode(op, (opc === OpCode.CPUI_INT_SLESS) ? OpCode.CPUI_INT_SLESSEQUAL : OpCode.CPUI_INT_LESSEQUAL);
    }

    return 1;
  }
}

/// \class RuleLessNotEqual
/// \brief Simplify INT_LESSEQUAL && INT_NOTEQUAL:  `V <= W && V != W  =>  V < W`
///
/// Handle INT_SLESSEQUAL variant.
export class RuleLessNotEqual extends Rule {
  constructor(g: string) {
    super(g, 0, "lessnotequal");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleLessNotEqual(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_BOOL_AND);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    // Convert [(s)lessequal AND notequal] to (s)less
    let compvn1: Varnode, compvn2: Varnode, vnout1: Varnode, vnout2: Varnode;
    let op_less: PcodeOp, op_equal: PcodeOp;
    let opc: number;

    vnout1 = op.getIn(0)!;
    if (!vnout1.isWritten()) return 0;
    vnout2 = op.getIn(1)!;
    if (!vnout2.isWritten()) return 0;
    op_less = vnout1.getDef()!;
    opc = op_less.code();
    if ((opc !== OpCode.CPUI_INT_LESSEQUAL) && (opc !== OpCode.CPUI_INT_SLESSEQUAL)) {
      op_equal = op_less;
      op_less = vnout2.getDef()!;
      opc = op_less.code();
      if ((opc !== OpCode.CPUI_INT_LESSEQUAL) && (opc !== OpCode.CPUI_INT_SLESSEQUAL))
        return 0;
    }
    else
      op_equal = vnout2.getDef()!;
    if (op_equal.code() !== OpCode.CPUI_INT_NOTEQUAL) return 0;

    compvn1 = op_less.getIn(0)!;
    compvn2 = op_less.getIn(1)!;
    if (!compvn1.isHeritageKnown()) return 0;
    if (!compvn2.isHeritageKnown()) return 0;
    if ((!compvn1.equals(op_equal.getIn(0)!) || !compvn2.equals(op_equal.getIn(1)!)) &&
        (!compvn1.equals(op_equal.getIn(1)!) || !compvn2.equals(op_equal.getIn(0)!)))
      return 0;

    data.opSetInput(op, compvn1, 0);
    data.opSetInput(op, compvn2, 1);
    data.opSetOpcode(op, (opc === OpCode.CPUI_INT_SLESSEQUAL) ? OpCode.CPUI_INT_SLESS : OpCode.CPUI_INT_LESS);

    return 1;
  }
}

/// \class RuleTrivialArith
/// \brief Simplify trivial arithmetic expressions
///
/// All forms are binary operations where both inputs hold the same value.
///   - `V == V  =>  true`
///   - `V != V  =>  false`
///   - `V < V   => false`
///   - `V <= V  => true`
///   - `V & V   => V`
///   - `V | V  => V`
///   - `V ^ V   => #0`
///
/// Handles other signed, boolean, and floating-point variants.
export class RuleTrivialArith extends Rule {
  constructor(g: string) {
    super(g, 0, "trivialarith");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleTrivialArith(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    const list: number[] = [
      OpCode.CPUI_INT_NOTEQUAL, OpCode.CPUI_INT_SLESS, OpCode.CPUI_INT_LESS, OpCode.CPUI_BOOL_XOR, OpCode.CPUI_BOOL_AND, OpCode.CPUI_BOOL_OR,
      OpCode.CPUI_INT_EQUAL, OpCode.CPUI_INT_SLESSEQUAL, OpCode.CPUI_INT_LESSEQUAL,
      OpCode.CPUI_INT_XOR, OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR,
      OpCode.CPUI_FLOAT_EQUAL, OpCode.CPUI_FLOAT_NOTEQUAL, OpCode.CPUI_FLOAT_LESS, OpCode.CPUI_FLOAT_LESSEQUAL
    ];
    oplist.push(...list);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let vn: Varnode | null;
    let in0: Varnode, in1: Varnode;

    if (op.numInput() !== 2) return 0;
    in0 = op.getIn(0)!;
    in1 = op.getIn(1)!;
    if (in0 !== in1) {    // Inputs must be identical
      if (!in0.isWritten()) return 0;
      if (!in1.isWritten()) return 0;
      if (!in0.getDef()!.isCseMatch(in1.getDef()!)) return 0; // or constructed identically
    }
    switch (op.code()) {
      case OpCode.CPUI_INT_NOTEQUAL:   // Boolean 0
      case OpCode.CPUI_INT_SLESS:
      case OpCode.CPUI_INT_LESS:
      case OpCode.CPUI_BOOL_XOR:
      case OpCode.CPUI_FLOAT_NOTEQUAL:
      case OpCode.CPUI_FLOAT_LESS:
        vn = data.newConstant(1, 0n);
        break;
      case OpCode.CPUI_INT_EQUAL:     // Boolean 1
      case OpCode.CPUI_INT_SLESSEQUAL:
      case OpCode.CPUI_INT_LESSEQUAL:
      case OpCode.CPUI_FLOAT_EQUAL:
      case OpCode.CPUI_FLOAT_LESSEQUAL:
        vn = data.newConstant(1, 1n);
        break;
      case OpCode.CPUI_INT_XOR:       // Same size 0
        //  case OpCode.CPUI_INT_SUB:
        vn = data.newConstant(op.getOut()!.getSize(), 0n);
        break;
      case OpCode.CPUI_BOOL_AND:      // Identity
      case OpCode.CPUI_BOOL_OR:
      case OpCode.CPUI_INT_AND:
      case OpCode.CPUI_INT_OR:
        vn = null;
        break;
      default:
        return 0;
    }

    data.opRemoveInput(op, 1);
    data.opSetOpcode(op, OpCode.CPUI_COPY);
    if (vn !== null)
      data.opSetInput(op, vn, 0);

    return 1;
  }
}

/// \class RuleTrivialBool
/// \brief Simplify boolean expressions when one side is constant
///
///   - `V && false  =>  false`
///   - `V && true   =>  V`
///   - `V || false  =>  V`
///   - `V || true   =>  true`
///   - `V ^^ true   =>  !V`
///   - `V ^^ false  =>  V`
export class RuleTrivialBool extends Rule {
  constructor(g: string) {
    super(g, 0, "trivialbool");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleTrivialBool(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    const list: number[] = [OpCode.CPUI_BOOL_AND, OpCode.CPUI_BOOL_OR, OpCode.CPUI_BOOL_XOR];
    oplist.push(...list);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const vnconst: Varnode = op.getIn(1)!;
    let vn: Varnode;
    let val: bigint;
    let opc: number;

    if (!vnconst.isConstant()) return 0;
    val = vnconst.getOffset();

    switch (op.code()) {
      case OpCode.CPUI_BOOL_XOR:
        vn = op.getIn(0)!;
        opc = (val === 1n) ? OpCode.CPUI_BOOL_NEGATE : OpCode.CPUI_COPY;
        break;
      case OpCode.CPUI_BOOL_AND:
        opc = OpCode.CPUI_COPY;
        if (val === 1n)
          vn = op.getIn(0)!;
        else
          vn = data.newConstant(1, 0n); // Copy false
        break;
      case OpCode.CPUI_BOOL_OR:
        opc = OpCode.CPUI_COPY;
        if (val === 1n)
          vn = data.newConstant(1, 1n);
        else
          vn = op.getIn(0)!;
        break;
      default:
        return 0;
    }

    data.opRemoveInput(op, 1);
    data.opSetOpcode(op, opc);
    data.opSetInput(op, vn, 0);
    return 1;
  }
}

/// \class RuleZextEliminate
/// \brief Eliminate INT_ZEXT in comparisons:  `zext(V) == c  =>  V == c`
///
/// The constant Varnode changes size and must not lose any non-zero bits.
/// Handle other variants with INT_NOTEQUAL, INT_LESS, and INT_LESSEQUAL
///   - `zext(V) != c =>  V != c`
///   - `zext(V) < c  =>  V < c`
///   - `zext(V) <= c =>  V <= c`
export class RuleZextEliminate extends Rule {
  constructor(g: string) {
    super(g, 0, "zexteliminate");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleZextEliminate(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    const list: number[] = [
      OpCode.CPUI_INT_EQUAL, OpCode.CPUI_INT_NOTEQUAL,
      OpCode.CPUI_INT_LESS, OpCode.CPUI_INT_LESSEQUAL
    ];
    oplist.push(...list);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let zext: PcodeOp;
    let vn1: Varnode, vn2: Varnode, newvn: Varnode;
    let val: bigint;
    let smallsize: number, zextslot: number, otherslot: number;

    // vn1 equals ZEXTed input
    // vn2 = other input
    vn1 = op.getIn(0)!;
    vn2 = op.getIn(1)!;
    zextslot = 0;
    otherslot = 1;
    if ((vn2.isWritten()) && (vn2.getDef()!.code() === OpCode.CPUI_INT_ZEXT)) {
      vn1 = vn2;
      vn2 = op.getIn(0)!;
      zextslot = 1;
      otherslot = 0;
    }
    else if ((!vn1.isWritten()) || (vn1.getDef()!.code() !== OpCode.CPUI_INT_ZEXT))
      return 0;

    if (!vn2.isConstant()) return 0;
    zext = vn1.getDef()!;
    if (!zext.getIn(0)!.isHeritageKnown()) return 0;
    if (vn1.loneDescend()! !== op) return 0;  // Make sure extension is not used for anything else
    smallsize = zext.getIn(0)!.getSize();
    val = vn2.getOffset();
    if ((val >> BigInt(8 * smallsize)) === 0n) { // Is zero extension unnecessary
      newvn = data.newConstant(smallsize, val);
      newvn.copySymbolIfValid(vn2);
      data.opSetInput(op, zext.getIn(0)!, zextslot);
      data.opSetInput(op, newvn, otherslot);
      return 1;
    }
    // Should have else for doing
    // constant comparison here and now
    return 0;
  }
}

/// \class RuleSlessToLess
/// \brief Convert INT_SLESS to INT_LESS when comparing positive values
///
/// This also works converting INT_SLESSEQUAL to INT_LESSEQUAL.
/// We use the non-zero mask to verify the sign bit is zero.
export class RuleSlessToLess extends Rule {
  constructor(g: string) {
    super(g, 0, "slesstoless");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSlessToLess(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_SLESS);
    oplist.push(OpCode.CPUI_INT_SLESSEQUAL);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const vn: Varnode = op.getIn(0)!;
    const sz: number = vn.getSize();
    if (signbit_negative(vn.getNZMask(), sz)) return 0;
    if (signbit_negative(op.getIn(1)!.getNZMask(), sz)) return 0;

    if (op.code() === OpCode.CPUI_INT_SLESS)
      data.opSetOpcode(op, OpCode.CPUI_INT_LESS);
    else
      data.opSetOpcode(op, OpCode.CPUI_INT_LESSEQUAL);
    return 1;
  }
}

/// \class RuleZextSless
/// \brief Transform INT_ZEXT and INT_SLESS:  `zext(V) s< c  =>  V < c`
export class RuleZextSless extends Rule {
  constructor(g: string) {
    super(g, 0, "zextsless");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleZextSless(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_SLESS);
    oplist.push(OpCode.CPUI_INT_SLESSEQUAL);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let zext: PcodeOp;
    let vn1: Varnode, vn2: Varnode;
    let smallsize: number, zextslot: number, otherslot: number;
    let val: bigint;

    vn1 = op.getIn(0)!;
    vn2 = op.getIn(1)!;
    zextslot = 0;
    otherslot = 1;
    if ((vn2.isWritten()) && (vn2.getDef()!.code() === OpCode.CPUI_INT_ZEXT)) {
      vn1 = vn2;
      vn2 = op.getIn(0)!;
      zextslot = 1;
      otherslot = 0;
    }
    else if ((!vn1.isWritten()) || (vn1.getDef()!.code() !== OpCode.CPUI_INT_ZEXT))
      return 0;

    if (!vn2.isConstant()) return 0;
    zext = vn1.getDef()!;
    if (!zext.getIn(0)!.isHeritageKnown()) return 0;

    smallsize = zext.getIn(0)!.getSize();
    val = vn2.getOffset();
    if ((val >> BigInt(8 * smallsize - 1)) !== 0n) return 0; // Is zero extension unnecessary, sign bit must also be 0

    const newvn: Varnode = data.newConstant(smallsize, val);
    data.opSetInput(op, zext.getIn(0)!, zextslot);
    data.opSetInput(op, newvn, otherslot);
    data.opSetOpcode(op, (op.code() === OpCode.CPUI_INT_SLESS) ? OpCode.CPUI_INT_LESS : OpCode.CPUI_INT_LESSEQUAL);
    return 1;
  }
}

/// \class RuleBitUndistribute
/// \brief Undo distributed operations through INT_AND, INT_OR, and INT_XOR
///
///  - `zext(V) & zext(W)  =>  zext( V & W )`
///  - `(V >> X) | (W >> X)  =>  (V | W) >> X`
///
/// Works with INT_ZEXT, INT_SEXT, INT_LEFT, INT_RIGHT, and INT_SRIGHT.
export class RuleBitUndistribute extends Rule {
  constructor(g: string) {
    super(g, 0, "bitundistribute");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleBitUndistribute(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    const list: number[] = [OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR, OpCode.CPUI_INT_XOR];
    oplist.push(...list);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const vn1: Varnode = op.getIn(0)!;
    const vn2: Varnode = op.getIn(1)!;
    let in1: Varnode, in2: Varnode, vnextra: Varnode;
    let opc: number;

    if (!vn1.isWritten()) return 0;
    if (!vn2.isWritten()) return 0;

    opc = vn1.getDef()!.code();
    if (vn2.getDef()!.code() !== opc) return 0;
    switch (opc) {
      case OpCode.CPUI_INT_ZEXT:
      case OpCode.CPUI_INT_SEXT:
        // Test for full equality of extension operation
        in1 = vn1.getDef()!.getIn(0)!;
        if (in1.isFree()) return 0;
        in2 = vn2.getDef()!.getIn(0)!;
        if (in2.isFree()) return 0;
        if (in1.getSize() !== in2.getSize()) return 0;
        data.opRemoveInput(op, 1);
        break;
      case OpCode.CPUI_INT_LEFT:
      case OpCode.CPUI_INT_RIGHT:
      case OpCode.CPUI_INT_SRIGHT:
        // Test for full equality of shift operation
        in1 = vn1.getDef()!.getIn(1)!;
        in2 = vn2.getDef()!.getIn(1)!;
        if (in1.isConstant() && in2.isConstant()) {
          if (in1.getOffset() !== in2.getOffset())
            return 0;
          vnextra = data.newConstant(in1.getSize(), in1.getOffset());
        }
        else if (in1 !== in2)
          return 0;
        else {
          if (in1.isFree()) return 0;
          vnextra = in1;
        }
        in1 = vn1.getDef()!.getIn(0)!;
        if (in1.isFree()) return 0;
        in2 = vn2.getDef()!.getIn(0)!;
        if (in2.isFree()) return 0;
        data.opSetInput(op, vnextra!, 1);
        break;
      default:
        return 0;
    }

    const newext: PcodeOp = data.newOp(2, op.getAddr());
    const smalllogic: Varnode = data.newUniqueOut(in1!.getSize(), newext);
    data.opSetInput(newext, in1!, 0);
    data.opSetInput(newext, in2!, 1);
    data.opSetOpcode(newext, op.code());

    data.opSetOpcode(op, opc);
    data.opSetInput(op, smalllogic, 0);
    data.opInsertBefore(newext, op);
    return 1;
  }
}

/// \class RuleBooleanUndistribute
/// \brief Undo distributed BOOL_AND through INT_NOTEQUAL
///
///  - `A && B != A && C     =>  A && (B != C)`
///  - `A || B == A || C     =>  A || (B == C)`
///  - `A && B == A && C     => !A || (B == C)`
export class RuleBooleanUndistribute extends Rule {
  constructor(g: string) {
    super(g, 0, "booleanundistribute");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleBooleanUndistribute(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_EQUAL);
    oplist.push(OpCode.CPUI_INT_NOTEQUAL);
  }

  /// Test if the two given Varnodes are matching boolean expressions.
  /// If the expressions are complementary, true is still returned, but the boolean parameter
  /// is flipped.
  private static isMatch(leftVn: Varnode, rightVn: Varnode, rightFlip: { value: boolean }): boolean {
    const val: number = BooleanMatch.evaluate(leftVn, rightVn, 1);
    if (val === BooleanMatch.same)
      return true;
    if (val === BooleanMatch.complementary) {
      rightFlip.value = !rightFlip.value;
      return true;
    }
    return false;
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const vn0: Varnode = op.getIn(0)!;
    if (!vn0.isWritten()) return 0;
    const vn1: Varnode = op.getIn(1)!;
    if (!vn1.isWritten()) return 0;
    const op0: PcodeOp = vn0.getDef()!;
    const opc0: number = op0.code();
    if (opc0 !== OpCode.CPUI_BOOL_AND && opc0 !== OpCode.CPUI_BOOL_OR) return 0;
    const op1: PcodeOp = vn1.getDef()!;
    const opc1: number = op1.code();
    if (opc1 !== OpCode.CPUI_BOOL_AND && opc1 !== OpCode.CPUI_BOOL_OR) return 0;
    const ins: Varnode[] = [
      op0.getIn(0)!,
      op0.getIn(1)!,
      op1.getIn(0)!,
      op1.getIn(1)!
    ];
    if (ins[0].isFree() || ins[1].isFree() || ins[2].isFree() || ins[3].isFree()) return 0;
    const isflipped: boolean[] = [false, false, false, false];
    let centralEqual: boolean = (op.code() === OpCode.CPUI_INT_EQUAL);
    if (opc0 === OpCode.CPUI_BOOL_OR) {
      isflipped[0] = !isflipped[0];
      isflipped[1] = !isflipped[1];
      centralEqual = !centralEqual;
    }
    if (opc1 === OpCode.CPUI_BOOL_OR) {
      isflipped[2] = !isflipped[2];
      isflipped[3] = !isflipped[3];
      centralEqual = !centralEqual;
    }
    let leftSlot: number, rightSlot: number;
    const flipRef2: { value: boolean } = { value: isflipped[2] };
    const flipRef3: { value: boolean } = { value: isflipped[3] };
    if (RuleBooleanUndistribute.isMatch(ins[0], ins[2], flipRef2)) {
      isflipped[2] = flipRef2.value;
      leftSlot = 0;
      rightSlot = 2;
    }
    else {
      flipRef3.value = isflipped[3];
      if (RuleBooleanUndistribute.isMatch(ins[0], ins[3], flipRef3)) {
        isflipped[3] = flipRef3.value;
        leftSlot = 0;
        rightSlot = 3;
      }
      else {
        flipRef2.value = isflipped[2];
        if (RuleBooleanUndistribute.isMatch(ins[1], ins[2], flipRef2)) {
          isflipped[2] = flipRef2.value;
          leftSlot = 1;
          rightSlot = 2;
        }
        else {
          flipRef3.value = isflipped[3];
          if (RuleBooleanUndistribute.isMatch(ins[1], ins[3], flipRef3)) {
            isflipped[3] = flipRef3.value;
            leftSlot = 1;
            rightSlot = 3;
          }
          else
            return 0;
        }
      }
    }
    if (isflipped[leftSlot] !== isflipped[rightSlot]) return 0;
    let combineOpc: number;
    if (centralEqual) {
      combineOpc = OpCode.CPUI_BOOL_OR;
      isflipped[leftSlot] = !isflipped[leftSlot];
    }
    else {
      combineOpc = OpCode.CPUI_BOOL_AND;
    }
    let finalA: Varnode = ins[leftSlot];
    if (isflipped[leftSlot])
      finalA = data.opBoolNegate(finalA, op, false);
    if (isflipped[1 - leftSlot])
      centralEqual = !centralEqual;
    if (isflipped[5 - rightSlot])
      centralEqual = !centralEqual;
    const finalB: Varnode = ins[1 - leftSlot];
    const finalC: Varnode = ins[5 - rightSlot];
    const eqOp: PcodeOp = data.newOp(2, op.getAddr());
    data.opSetOpcode(eqOp, centralEqual ? OpCode.CPUI_INT_EQUAL : OpCode.CPUI_INT_NOTEQUAL);
    const tmp1: Varnode = data.newUniqueOut(1, eqOp);
    data.opSetInput(eqOp, finalB, 0);
    data.opSetInput(eqOp, finalC, 1);
    data.opInsertBefore(eqOp, op);
    data.opSetOpcode(op, combineOpc);
    data.opSetInput(op, tmp1, 1);
    data.opSetInput(op, finalA, 0);
    return 1;
  }
}

/// \class RuleBooleanDedup
/// \brief Remove duplicate clauses in boolean expressions
///
///  - `(A && B) || (A && C)     =>  A && (B || C)`
///  - `(A || B) && (A || C)     =>  A || (B && C)`
///  - `(A || B) || (!A && C)    =>  A || (B || C)`
///  - `(A && B) && (A && C)     =>  A && (B && C)`
///  - `(A || B) || (A || C)     =>  A || (B || C)`
export class RuleBooleanDedup extends Rule {
  constructor(g: string) {
    super(g, 0, "booleandedup");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleBooleanDedup(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_BOOL_AND);
    oplist.push(OpCode.CPUI_BOOL_OR);
  }

  /// Determine if the two given boolean Varnodes always contain matching values.
  /// The boolean values can either always be equal or can always be complements of each other.
  private static isMatch(leftVn: Varnode, rightVn: Varnode, isFlip: { value: boolean }): boolean {
    const val: number = BooleanMatch.evaluate(leftVn, rightVn, 1);
    if (val === BooleanMatch.same) {
      isFlip.value = false;
      return true;
    }
    if (val === BooleanMatch.complementary) {
      isFlip.value = true;
      return true;
    }
    return false;
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const vn0: Varnode = op.getIn(0)!;
    if (!vn0.isWritten()) return 0;
    const vn1: Varnode = op.getIn(1)!;
    if (!vn1.isWritten()) return 0;
    const op0: PcodeOp = vn0.getDef()!;
    const opc0: number = op0.code();
    if (opc0 !== OpCode.CPUI_BOOL_AND && opc0 !== OpCode.CPUI_BOOL_OR) return 0;
    const op1: PcodeOp = vn1.getDef()!;
    const opc1: number = op1.code();
    if (opc1 !== OpCode.CPUI_BOOL_AND && opc1 !== OpCode.CPUI_BOOL_OR) return 0;
    const ins: Varnode[] = [
      op0.getIn(0)!,
      op0.getIn(1)!,
      op1.getIn(0)!,
      op1.getIn(1)!
    ];
    if (ins[0].isFree() || ins[1].isFree() || ins[2].isFree() || ins[3].isFree()) return 0;
    const isflippedRef: { value: boolean } = { value: false };
    let leftA: Varnode, rightA: Varnode;
    let leftO: Varnode, rightO: Varnode;
    let isflipped: boolean;
    if (RuleBooleanDedup.isMatch(ins[0], ins[2], isflippedRef)) {
      isflipped = isflippedRef.value;
      leftA = ins[0];
      rightA = ins[2];
      leftO = ins[1];
      rightO = ins[3];
    }
    else {
      isflippedRef.value = false;
      if (RuleBooleanDedup.isMatch(ins[0], ins[3], isflippedRef)) {
        isflipped = isflippedRef.value;
        leftA = ins[0];
        rightA = ins[3];
        leftO = ins[1];
        rightO = ins[2];
      }
      else {
        isflippedRef.value = false;
        if (RuleBooleanDedup.isMatch(ins[1], ins[2], isflippedRef)) {
          isflipped = isflippedRef.value;
          leftA = ins[1];
          rightA = ins[2];
          leftO = ins[0];
          rightO = ins[3];
        }
        else {
          isflippedRef.value = false;
          if (RuleBooleanDedup.isMatch(ins[1], ins[3], isflippedRef)) {
            isflipped = isflippedRef.value;
            leftA = ins[1];
            rightA = ins[3];
            leftO = ins[0];
            rightO = ins[2];
          }
          else
            return 0;
        }
      }
    }
    const centralOpc: number = op.code();
    let bcOpc: number, finalOpc: number;
    let finalA: Varnode;
    if (isflipped) {
      if (centralOpc === OpCode.CPUI_BOOL_AND && opc0 === OpCode.CPUI_BOOL_AND && opc1 === OpCode.CPUI_BOOL_AND) {
        // (A && B) && (!A && C)
        data.opSetOpcode(op, OpCode.CPUI_COPY);
        data.opRemoveInput(op, 1);
        data.opSetInput(op, data.newConstant(1, 0n), 0);  // Whole expression is false
        return 1;
      }
      if (centralOpc === OpCode.CPUI_BOOL_OR && opc0 === OpCode.CPUI_BOOL_OR && opc1 === OpCode.CPUI_BOOL_OR) {
        // (A || B) || (!A || C)
        data.opSetOpcode(op, OpCode.CPUI_COPY);
        data.opRemoveInput(op, 1);
        data.opSetInput(op, data.newConstant(1, 1n), 0);  // Whole expression is true
        return 1;
      }
      if (centralOpc === OpCode.CPUI_BOOL_OR && opc0 !== opc1) {
        // (A || B) || (!A && C)
        finalA = (opc0 === OpCode.CPUI_BOOL_OR) ? leftA! : rightA!;
        finalOpc = OpCode.CPUI_BOOL_OR;
        bcOpc = OpCode.CPUI_BOOL_OR;
      }
      else {
        return 0;
      }
    }
    else {
      if (centralOpc === opc0 && centralOpc === opc1) {
        // (A && B) && (A && C)    or   (A || B) || (A || C)
        finalA = leftA!;
        finalOpc = centralOpc;
        bcOpc = centralOpc;
      }
      else if (opc0 === opc1 && centralOpc !== opc0) {
        // (A && B) || (A && C)    or   (A || B) && (A || C)
        finalA = leftA!;
        finalOpc = opc0;
        bcOpc = centralOpc;
      }
      else {
        return 0;
      }
    }
    const bcOp: PcodeOp = data.newOp(2, op.getAddr());
    const tmp: Varnode = data.newUniqueOut(1, bcOp);
    data.opSetOpcode(bcOp, bcOpc);
    data.opSetInput(bcOp, leftO!, 0);
    data.opSetInput(bcOp, rightO!, 1);
    data.opInsertBefore(bcOp, op);
    data.opSetOpcode(op, finalOpc);
    data.opSetInput(op, finalA!, 0);
    data.opSetInput(op, tmp, 1);
    return 1;
  }
}

/// \class RuleBooleanNegate
/// \brief Simplify comparisons with boolean values:  `V == false  =>  !V,  V == true  =>  V`
///
/// Works with both INT_EQUAL and INT_NOTEQUAL.  Both sides of the comparison
/// must be boolean values.
export class RuleBooleanNegate extends Rule {
  constructor(g: string) {
    super(g, 0, "booleannegate");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleBooleanNegate(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    const list: number[] = [OpCode.CPUI_INT_NOTEQUAL, OpCode.CPUI_INT_EQUAL];
    oplist.push(...list);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let opc: number;
    let constvn: Varnode;
    let subbool: Varnode;
    let negate: boolean;
    let val: bigint;

    opc = op.code();
    constvn = op.getIn(1)!;
    subbool = op.getIn(0)!;
    if (!constvn.isConstant()) return 0;
    val = constvn.getOffset();
    if ((val !== 0n) && (val !== 1n))
      return 0;
    negate = (opc === OpCode.CPUI_INT_NOTEQUAL);
    if (val === 0n)
      negate = !negate;

    if (!subbool.isBooleanValue(data.isTypeRecoveryOn())) return 0;

    data.opRemoveInput(op, 1);  // Remove second parameter
    data.opSetInput(op, subbool, 0); // Keep original boolean parameter
    if (negate)
      data.opSetOpcode(op, OpCode.CPUI_BOOL_NEGATE);
    else
      data.opSetOpcode(op, OpCode.CPUI_COPY);

    return 1;
  }
}

/// \class RuleBoolZext
/// \brief Simplify boolean expressions of the form zext(V) * -1
///
///   - `(zext(V) * -1) + 1  =>  zext( !V )`
///   - `(zext(V) * -1) == -1  =>  V == true`
///   - `(zext(V) * -1) != -1  =>  V != true`
///   - `(zext(V) * -1) & (zext(W) * -1)  =>  zext(V && W) * -1`
///   - `(zext(V) * -1) | (zext(W) * -1)  =>  zext(V || W) * -1`
export class RuleBoolZext extends Rule {
  constructor(g: string) {
    super(g, 0, "boolzext");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleBoolZext(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_ZEXT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let boolVn1: Varnode, boolVn2: Varnode;
    let multop1: PcodeOp, actionop: PcodeOp;
    let zextop2: PcodeOp, multop2: PcodeOp;
    let coeff: bigint, val: bigint;
    let opc: number;
    let size: number;

    boolVn1 = op.getIn(0)!;
    if (!boolVn1.isBooleanValue(data.isTypeRecoveryOn())) return 0;

    multop1 = op.getOut()!.loneDescend()!;
    if (multop1 === null) return 0;
    if (multop1.code() !== OpCode.CPUI_INT_MULT) return 0;
    if (!multop1.getIn(1)!.isConstant()) return 0;
    coeff = multop1.getIn(1)!.getOffset();
    if (coeff !== calc_mask(multop1.getIn(1)!.getSize()))
      return 0;
    size = multop1.getOut()!.getSize();

    // If we reached here, we are multiplying extended boolean by -1
    actionop = multop1.getOut()!.loneDescend()!;
    if (actionop === null) return 0;
    switch (actionop.code()) {
      case OpCode.CPUI_INT_ADD:
        if (!actionop.getIn(1)!.isConstant()) return 0;
        if (actionop.getIn(1)!.getOffset() === 1n) {
          let vn: Varnode;
          const newop: PcodeOp = data.newOp(1, op.getAddr());
          data.opSetOpcode(newop, OpCode.CPUI_BOOL_NEGATE);  // Negate the boolean
          vn = data.newUniqueOut(1, newop);
          data.opSetInput(newop, boolVn1, 0);
          data.opInsertBefore(newop, op);
          data.opSetInput(op, vn, 0);
          data.opRemoveInput(actionop, 1); // eliminate the INT_ADD operator
          data.opSetOpcode(actionop, OpCode.CPUI_COPY);
          data.opSetInput(actionop, op.getOut()!, 0);  // propagate past the INT_MULT operator
          return 1;
        }
        return 0;
      case OpCode.CPUI_INT_EQUAL:
      case OpCode.CPUI_INT_NOTEQUAL:
        if (actionop.getIn(1)!.isConstant()) {
          val = actionop.getIn(1)!.getOffset();
        }
        else
          return 0;

        // Change comparison of extended boolean to 0 or -1
        // to comparison of unextended boolean to 0 or 1
        if (val === coeff)
          val = 1n;
        else if (val !== 0n)
          return 0;      // Not comparing with 0 or -1

        data.opSetInput(actionop, boolVn1, 0);
        data.opSetInput(actionop, data.newConstant(1, val), 1);
        return 1;
      case OpCode.CPUI_INT_AND:
        opc = OpCode.CPUI_BOOL_AND;
        break;
      case OpCode.CPUI_INT_OR:
        opc = OpCode.CPUI_BOOL_OR;
        break;
      case OpCode.CPUI_INT_XOR:
        opc = OpCode.CPUI_BOOL_XOR;
        break;
      default:
        return 0;
    }

    // Apparently doing logical ops with extended boolean

    // Check that the other side is also an extended boolean
    multop2 = (multop1 === actionop.getIn(0)!.getDef()!) ? actionop.getIn(1)!.getDef()! : actionop.getIn(0)!.getDef()!;
    if (multop2 === null) return 0;
    if (multop2.code() !== OpCode.CPUI_INT_MULT) return 0;
    if (!multop2.getIn(1)!.isConstant()) return 0;
    coeff = multop2.getIn(1)!.getOffset();
    if (coeff !== calc_mask(size))
      return 0;
    zextop2 = multop2.getIn(0)!.getDef()!;
    if (zextop2 === null) return 0;
    if (zextop2.code() !== OpCode.CPUI_INT_ZEXT) return 0;
    boolVn2 = zextop2.getIn(0)!;
    if (!boolVn2.isBooleanValue(data.isTypeRecoveryOn())) return 0;

    // Do the boolean calculation on unextended boolean values
    // and then extend the result
    const newop: PcodeOp = data.newOp(2, actionop.getAddr());
    const newres: Varnode = data.newUniqueOut(1, newop);
    data.opSetOpcode(newop, opc);
    data.opSetInput(newop, boolVn1, 0);
    data.opSetInput(newop, boolVn2, 1);
    data.opInsertBefore(newop, actionop);

    const newzext: PcodeOp = data.newOp(1, actionop.getAddr());
    const newzout: Varnode = data.newUniqueOut(size, newzext);
    data.opSetOpcode(newzext, OpCode.CPUI_INT_ZEXT);
    data.opSetInput(newzext, newres, 0);
    data.opInsertBefore(newzext, actionop);

    data.opSetOpcode(actionop, OpCode.CPUI_INT_MULT);
    data.opSetInput(actionop, newzout, 0);
    data.opSetInput(actionop, data.newConstant(size, coeff), 1);
    return 1;
  }
}

/// \class RuleLogic2Bool
/// \brief Convert logical to boolean operations:  `V & W  =>  V && W,  V | W  => V || W`
///
/// Verify that the inputs to the logical operator are booleans, then convert
/// INT_AND to BOOL_AND, INT_OR to BOOL_OR etc.
export class RuleLogic2Bool extends Rule {
  constructor(g: string) {
    super(g, 0, "logic2bool");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleLogic2Bool(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    const list: number[] = [OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR, OpCode.CPUI_INT_XOR];
    oplist.push(...list);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let boolVn: Varnode;

    boolVn = op.getIn(0)!;
    if (!boolVn.isBooleanValue(data.isTypeRecoveryOn())) return 0;
    const in1: Varnode = op.getIn(1)!;
    if (in1.isConstant()) {
      if (in1.getOffset() > 1n) // If one side is a constant 0 or 1, this is boolean
        return 0;
    }
    else if (!in1.isBooleanValue(data.isTypeRecoveryOn())) {
      return 0;
    }
    switch (op.code()) {
      case OpCode.CPUI_INT_AND:
        data.opSetOpcode(op, OpCode.CPUI_BOOL_AND);
        break;
      case OpCode.CPUI_INT_OR:
        data.opSetOpcode(op, OpCode.CPUI_BOOL_OR);
        break;
      case OpCode.CPUI_INT_XOR:
        data.opSetOpcode(op, OpCode.CPUI_BOOL_XOR);
        break;
      default:
        return 0;
    }
    return 1;
  }
}

/// \class RuleIndirectCollapse
/// \brief Remove a OpCode.CPUI_INDIRECT if its blocking PcodeOp is dead
export class RuleIndirectCollapse extends Rule {
  constructor(g: string) {
    super(g, 0, "indirectcollapse");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleIndirectCollapse(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INDIRECT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let indop: PcodeOp;

    if (op.getIn(1)!.getSpace() === null || op.getIn(1)!.getSpace()!.getType() !== spacetype.IPTR_IOP) return 0;
    const indop_or_null: PcodeOp | null = PcodeOp.getOpFromConst(op.getIn(1)!.getAddr());
    if (indop_or_null === null) return 0;
    indop = indop_or_null;

    // Is the indirect effect gone?
    if (!indop.isDead()) {
      if (indop.code() === OpCode.CPUI_COPY) { // STORE resolved to a COPY
        const vn1: Varnode = indop.getOut()!;
        const vn2: Varnode = op.getOut()!;
        const res: number = vn1.characterizeOverlap(vn2);
        if (res > 0) { // Copy has an effect of some sort
          if (res === 2) { // vn1 and vn2 are the same storage
            // Convert INDIRECT to COPY
            data.opUninsert(op);
            data.opSetInput(op, vn1, 0);
            data.opRemoveInput(op, 1);
            data.opSetOpcode(op, OpCode.CPUI_COPY);
            data.opInsertAfter(op, indop);
            return 1;
          }
          if (vn1.contains(vn2) === 0) {  // INDIRECT output is properly contained in COPY output
            // Convert INDIRECT to a SUBPIECE
            let trunc: bigint;
            if (vn1.getSpace()!.isBigEndian())
              trunc = BigInt(vn1.getOffset()) + BigInt(vn1.getSize()) - (BigInt(vn2.getOffset()) + BigInt(vn2.getSize()));
            else
              trunc = BigInt(vn2.getOffset()) - BigInt(vn1.getOffset());
            data.opUninsert(op);
            data.opSetInput(op, vn1, 0);
            data.opSetInput(op, data.newConstant(4, trunc), 1);
            data.opSetOpcode(op, OpCode.CPUI_SUBPIECE);
            data.opInsertAfter(op, indop);
            return 1;
          }
          data.warning("Ignoring partial resolution of indirect", indop.getAddr());
          return 0;    // Partial overlap, not sure what to do
        }
      }
      else if (op.getOut()!.hasNoLocalAlias()) {
        if (op.isIndirectCreation() || op.noIndirectCollapse())
          return 0;
      }
      else if (indop.usesSpacebasePtr()) {
        if (indop.code() === OpCode.CPUI_STORE) {
          const guard: LoadGuard | null = data.getStoreGuard(indop);
          if (guard !== null) {
            if (guard.isGuarded(op.getOut()!.getAddr()))
              return 0;
          }
          else {
            // A marked STORE that is not guarded should eventually get converted to a COPY
            // so we keep the INDIRECT until that happens
            return 0;
          }
        }
      }
      else
        return 0;
    }

    data.totalReplace(op.getOut()!, op.getIn(0)!);
    data.opDestroy(op);    // Get rid of the INDIRECT
    return 1;
  }
}

/// \class RuleMultiCollapse
/// \brief Collapse MULTIEQUAL whose inputs all trace to the same value
export class RuleMultiCollapse extends Rule {
  constructor(g: string) {
    super(g, 0, "multicollapse");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleMultiCollapse(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_MULTIEQUAL);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const skiplist: Varnode[] = [];
    const matchlist: Varnode[] = [];
    let defcopyr: Varnode | null, copyr: Varnode;
    let func_eq: boolean, nofunc: boolean;
    let newop: PcodeOp;
    let j: number;

    for (let i = 0; i < op.numInput(); ++i)  // Everything must be heritaged before collapse
      if (!op.getIn(i)!.isHeritageKnown()) return 0;

    func_eq = false;    // Start assuming absolute equality of branches
    nofunc = false;     // Functional equalities are initially allowed
    defcopyr = null;
    j = 0;
    for (let i = 0; i < op.numInput(); ++i)
      matchlist.push(op.getIn(i)!);
    for (let i = 0; i < op.numInput(); ++i) { // Find base branch to match
      copyr = matchlist[i];
      if ((!copyr.isWritten()) || (copyr.getDef()!.code() !== OpCode.CPUI_MULTIEQUAL)) {
        defcopyr = copyr;
        break;
      }
    }

    let success: boolean = true;
    op.getOut()!.setMark();
    skiplist.push(op.getOut()!);
    while (j < matchlist.length) {
      copyr = matchlist[j++];
      if (copyr.isMark()) continue; // A varnode we have seen before
      // indicates a loop construct, where the
      // value is recurring in the loop without change
      // so we treat this as equal to all other branches
      // I.e. skip this varnode
      if (defcopyr === null) { // This is now the defining branch
        defcopyr = copyr;    // all other branches must match
        if (defcopyr.isWritten()) {
          if (defcopyr.getDef()!.code() === OpCode.CPUI_MULTIEQUAL)
            nofunc = true;  // MULTIEQUAL cannot match by functional equal
        }
        else
          nofunc = true;    // Unwritten cannot match by functional equal
      }
      else if (defcopyr === copyr) continue; // A matching branch
      else if ((defcopyr !== copyr) && (!nofunc) && functionalEquality(defcopyr, copyr)) {
        // Cannot match MULTIEQUAL by functional equality
        func_eq = true;    // Now matching by functional equality
        continue;
      }
      else if ((copyr.isWritten()) && (copyr.getDef()!.code() === OpCode.CPUI_MULTIEQUAL)) {
        // If the non-matching branch is a MULTIEQUAL
        newop = copyr.getDef()!;
        skiplist.push(copyr); // We give the branch one last chance and
        copyr.setMark();
        for (let i = 0; i < newop.numInput(); ++i) // add its inputs to list of things to match
          matchlist.push(newop.getIn(i)!);
      }
      else {        // A non-matching branch
        success = false;
        break;
      }
    }
    if (success) {
      for (j = 0; j < skiplist.length; ++j) { // Collapse everything in the skiplist
        copyr = skiplist[j];
        copyr.clearMark();
        let currentOp: PcodeOp = copyr.getDef()!;
        if (func_eq) {    // We have only functional equality
          const earliest: PcodeOp | null = currentOp.getParent().earliestUse(currentOp.getOut()!);
          newop = defcopyr!.getDef()!;  // We must copy newop (defcopyr)
          let substitute: PcodeOp | null = null;
          for (let i = 0; i < newop.numInput(); ++i) {
            const invn: Varnode = newop.getIn(i)!;
            if (!invn.isConstant()) {
              substitute = Funcdata.cseFindInBlock(newop, invn, currentOp.getParent(), earliest); // Has newop already been copied in this block
              break;
            }
          }
          if (substitute !== null) { // If it has already been copied,
            data.totalReplace(copyr, substitute.getOut()!); // just use copy's output as substitute for op
            data.opDestroy(currentOp);
          }
          else {      // Otherwise, create a copy
            const needsreinsert: boolean = (currentOp.code() === OpCode.CPUI_MULTIEQUAL);
            const parms: Varnode[] = [];
            for (let i = 0; i < newop.numInput(); ++i)
              parms.push(newop.getIn(i)!); // Copy parameters
            data.opSetAllInput(currentOp, parms);
            data.opSetOpcode(currentOp, newop.code()); // Copy opcode
            if (needsreinsert) {  // If the op is no longer a MULTIEQUAL
              const bl: BlockBasic = currentOp.getParent();
              data.opUninsert(currentOp);
              data.opInsertBegin(currentOp, bl); // Insert AFTER any other MULTIEQUAL
            }
          }
        }
        else {      // We have absolute equality
          data.totalReplace(copyr, defcopyr!); // Replace all refs to copyr with defcopyr
          data.opDestroy(currentOp);  // Get rid of the MULTIEQUAL
        }
      }
      return 1;
    }
    for (j = 0; j < skiplist.length; ++j)
      skiplist[j].clearMark();
    return 0;
  }
}
// ruleaction_part3.ts
// PART 3 of 6: Rule classes from ruleaction.cc lines ~3365-5500
// Classes: RuleSborrow, RuleScarry, RuleTrivialShift, RuleSignShift, RuleTestSign,
// RuleIdentityEl, RuleShift2Mult, RuleShiftPiece, RuleCollapseConstants,
// RuleTransformCpool, RulePropagateCopy, Rule2Comp2Mult, RuleCarryElim,
// RuleSub2Add, RuleXorCollapse, RuleAddMultCollapse, RuleLoadVarnode,
// RuleStoreVarnode, RuleSubExtComm, RuleSubCommute, RuleConcatCommute,
// RuleConcatZext, RuleZextCommute, RuleZextShiftZext, RuleShiftAnd,
// RuleConcatZero, RuleConcatLeftShift, RuleSubZext, RuleSubCancel

// ---------------------------------------------------------------------------
// RuleSborrow
// ---------------------------------------------------------------------------

export class RuleSborrow extends Rule {
  constructor(g: string) {
    super(g, 0, "sborrow");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSborrow(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_SBORROW);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let zside: number;

    const svn: Varnode = op.getOut()!;
    let avn: Varnode = op.getIn(0)!;
    let bvn: Varnode = op.getIn(1)!;

    // Check for trivial case
    if (bvn.isConstant() && bvn.getOffset() === 0n) {
      data.opSetOpcode(op, OpCode.CPUI_COPY);
      data.opSetInput(op, data.newConstant(1, 0n), 0);
      data.opRemoveInput(op, 1);
      return 1;
    }

    for (const compop of svn.descend) {
      if (compop.code() !== OpCode.CPUI_INT_EQUAL && compop.code() !== OpCode.CPUI_INT_NOTEQUAL)
        continue;
      const cvn: Varnode = (compop.getIn(0)! === svn) ? compop.getIn(1)! : compop.getIn(0)!;
      if (!cvn.isWritten()) continue;
      const signop: PcodeOp = cvn.getDef()!;
      if (signop.code() !== OpCode.CPUI_INT_SLESS) continue;
      if (!signop.getIn(0)!.constantMatch(0n)) {
        if (!signop.getIn(1)!.constantMatch(0n)) continue;
        zside = 1;
      } else {
        zside = 0;
      }
      const xvn: Varnode = signop.getIn(1 - zside)!;
      if (!xvn.isWritten()) continue;
      const expr1 = new AddExpression();
      expr1.gatherTwoTermsSubtract(avn, bvn);
      const expr2 = new AddExpression();
      expr2.gatherTwoTermsRoot(xvn);
      if (!expr1.isEquivalent(expr2))
        continue;
      if (compop.code() === OpCode.CPUI_INT_NOTEQUAL) {
        data.opSetOpcode(compop, OpCode.CPUI_INT_SLESS);
        data.opSetInput(compop, avn, 1 - zside);
        data.opSetInput(compop, bvn, zside);
      } else {
        data.opSetOpcode(compop, OpCode.CPUI_INT_SLESSEQUAL);
        data.opSetInput(compop, avn, zside);
        data.opSetInput(compop, bvn, 1 - zside);
      }
      return 1;
    }
    return 0;
  }
}

// ---------------------------------------------------------------------------
// RuleScarry
// ---------------------------------------------------------------------------

export class RuleScarry extends Rule {
  constructor(g: string) {
    super(g, 0, "scarry");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleScarry(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_SCARRY);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let zside: number;

    const svn: Varnode = op.getOut()!;
    let avn: Varnode = op.getIn(0)!;
    let bvn: Varnode = op.getIn(1)!;

    // Check for trivial case
    if ((bvn.isConstant() && bvn.getOffset() === 0n) ||
        (avn.isConstant() && avn.getOffset() === 0n)) {
      data.opSetOpcode(op, OpCode.CPUI_COPY);
      data.opSetInput(op, data.newConstant(1, 0n), 0);
      data.opRemoveInput(op, 1);
      return 1;
    }
    if (!bvn.isConstant()) {
      if (!avn.isConstant()) return 0;
      avn = bvn;
      bvn = op.getIn(0)!;
      let val: bigint = calc_mask(bvn.getSize());
      val = val ^ (val >> 1n);  // Calculate integer minimum
      if (val === bvn.getOffset()) return 0;  // Rule does not work if bvn is the integer minimum
    }

    for (const compop of svn.descend) {
      if (compop.code() !== OpCode.CPUI_INT_EQUAL && compop.code() !== OpCode.CPUI_INT_NOTEQUAL)
        continue;
      const cvn: Varnode = (compop.getIn(0)! === svn) ? compop.getIn(1)! : compop.getIn(0)!;
      if (!cvn.isWritten()) continue;
      const signop: PcodeOp = cvn.getDef()!;
      if (signop.code() !== OpCode.CPUI_INT_SLESS) continue;
      if (!signop.getIn(0)!.constantMatch(0n)) {
        if (!signop.getIn(1)!.constantMatch(0n)) continue;
        zside = 1;
      } else {
        zside = 0;
      }
      const xvn: Varnode = signop.getIn(1 - zside)!;
      if (!xvn.isWritten()) continue;
      const expr1 = new AddExpression();
      expr1.gatherTwoTermsAdd(avn, bvn);
      const expr2 = new AddExpression();
      expr2.gatherTwoTermsRoot(xvn);
      if (!expr1.isEquivalent(expr2))
        continue;
      const newval: bigint = (-bvn.getOffset()) & calc_mask(bvn.getSize());
      const newConst: Varnode = data.newConstant(bvn.getSize(), newval);

      if (compop.code() === OpCode.CPUI_INT_NOTEQUAL) {
        data.opSetOpcode(compop, OpCode.CPUI_INT_SLESS);
        data.opSetInput(compop, avn, 1 - zside);
        data.opSetInput(compop, newConst, zside);
      } else {
        data.opSetOpcode(compop, OpCode.CPUI_INT_SLESSEQUAL);
        data.opSetInput(compop, avn, zside);
        data.opSetInput(compop, newConst, 1 - zside);
      }
      return 1;
    }
    return 0;
  }
}

// ---------------------------------------------------------------------------
// RuleTrivialShift
// ---------------------------------------------------------------------------

export class RuleTrivialShift extends Rule {
  constructor(g: string) {
    super(g, 0, "trivialshift");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleTrivialShift(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_LEFT, OpCode.CPUI_INT_RIGHT, OpCode.CPUI_INT_SRIGHT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const constvn: Varnode = op.getIn(1)!;
    if (!constvn.isConstant()) return 0;
    const val: bigint = constvn.getOffset();
    if (val !== 0n) {
      if (val < BigInt(8 * op.getIn(0)!.getSize())) return 0;  // Non-trivial
      if (op.code() === OpCode.CPUI_INT_SRIGHT) return 0;    // Can't predict signbit
      const replace: Varnode = data.newConstant(op.getIn(0)!.getSize(), 0n);
      data.opSetInput(op, replace, 0);
    }
    data.opRemoveInput(op, 1);
    data.opSetOpcode(op, OpCode.CPUI_COPY);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// RuleSignShift
// ---------------------------------------------------------------------------

export class RuleSignShift extends Rule {
  constructor(g: string) {
    super(g, 0, "signshift");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSignShift(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_RIGHT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const constVn: Varnode = op.getIn(1)!;
    if (!constVn.isConstant()) return 0;
    const val: bigint = constVn.getOffset();
    const inVn: Varnode = op.getIn(0)!;
    if (val !== BigInt(8 * inVn.getSize() - 1)) return 0;
    if (inVn.isFree()) return 0;

    let doConversion = false;
    const outVn: Varnode = op.getOut()!;
    for (const arithOp of outVn.descend) {
      switch (arithOp.code()) {
        case OpCode.CPUI_INT_EQUAL:
        case OpCode.CPUI_INT_NOTEQUAL:
          if (arithOp.getIn(1)!.isConstant())
            doConversion = true;
          break;
        case OpCode.CPUI_INT_ADD:
        case OpCode.CPUI_INT_MULT:
          doConversion = true;
          break;
        default:
          break;
      }
      if (doConversion) break;
    }
    if (!doConversion) return 0;

    const shiftOp: PcodeOp = data.newOp(2, op.getAddr());
    data.opSetOpcode(shiftOp, OpCode.CPUI_INT_SRIGHT);
    const uniqueVn: Varnode = data.newUniqueOut(inVn.getSize(), shiftOp);
    data.opSetInput(op, uniqueVn, 0);
    data.opSetInput(op, data.newConstant(inVn.getSize(), calc_mask(inVn.getSize())), 1);
    data.opSetOpcode(op, OpCode.CPUI_INT_MULT);
    data.opSetInput(shiftOp, inVn, 0);
    data.opSetInput(shiftOp, constVn, 1);
    data.opInsertBefore(shiftOp, op);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// RuleTestSign
// ---------------------------------------------------------------------------

export class RuleTestSign extends Rule {
  constructor(g: string) {
    super(g, 0, "testsign");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleTestSign(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_SRIGHT);
  }

  private findComparisons(vn: Varnode, res: PcodeOp[]): void {
    for (const op of vn.descend) {
      const opc: number = op.code();
      if (opc === OpCode.CPUI_INT_EQUAL || opc === OpCode.CPUI_INT_NOTEQUAL) {
        if (op.getIn(1)!.isConstant())
          res.push(op);
      }
    }
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const constVn: Varnode = op.getIn(1)!;
    if (!constVn.isConstant()) return 0;
    const val: bigint = constVn.getOffset();
    const inVn: Varnode = op.getIn(0)!;
    if (val !== BigInt(8 * inVn.getSize() - 1)) return 0;
    const outVn: Varnode = op.getOut()!;

    if (inVn.isFree()) return 0;
    const compareOps: PcodeOp[] = [];
    this.findComparisons(outVn, compareOps);
    let resultCode = 0;
    for (let i = 0; i < compareOps.length; ++i) {
      const compareOp: PcodeOp = compareOps[i];
      const compVn: Varnode = compareOp.getIn(0)!;
      const compSize: number = compVn.getSize();

      const offset: bigint = compareOp.getIn(1)!.getOffset();
      let sgn: number;
      if (offset === 0n)
        sgn = 1;
      else if (offset === calc_mask(compSize))
        sgn = -1;
      else
        continue;
      if (compareOp.code() === OpCode.CPUI_INT_NOTEQUAL)
        sgn = -sgn;  // Complement the domain

      const zeroVn: Varnode = data.newConstant(inVn.getSize(), 0n);
      if (sgn === 1) {
        data.opSetInput(compareOp, inVn, 1);
        data.opSetInput(compareOp, zeroVn, 0);
        data.opSetOpcode(compareOp, OpCode.CPUI_INT_SLESSEQUAL);
      } else {
        data.opSetInput(compareOp, inVn, 0);
        data.opSetInput(compareOp, zeroVn, 1);
        data.opSetOpcode(compareOp, OpCode.CPUI_INT_SLESS);
      }
      resultCode = 1;
    }
    return resultCode;
  }
}

// ---------------------------------------------------------------------------
// RuleIdentityEl
// ---------------------------------------------------------------------------

export class RuleIdentityEl extends Rule {
  constructor(g: string) {
    super(g, 0, "identityel");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleIdentityEl(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(
      OpCode.CPUI_INT_ADD, OpCode.CPUI_INT_XOR, OpCode.CPUI_INT_OR,
      OpCode.CPUI_BOOL_XOR, OpCode.CPUI_BOOL_OR, OpCode.CPUI_INT_MULT
    );
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const constvn: Varnode = op.getIn(1)!;
    if (!constvn.isConstant()) return 0;
    const val: bigint = constvn.getOffset();
    if ((val === 0n) && (op.code() !== OpCode.CPUI_INT_MULT)) {
      data.opSetOpcode(op, OpCode.CPUI_COPY);
      data.opRemoveInput(op, 1);
      return 1;
    }
    if (op.code() !== OpCode.CPUI_INT_MULT) return 0;
    if (val === 1n) {
      data.opSetOpcode(op, OpCode.CPUI_COPY);
      data.opRemoveInput(op, 1);
      return 1;
    }
    if (val === 0n) {  // Multiply by zero
      data.opSetOpcode(op, OpCode.CPUI_COPY);
      data.opRemoveInput(op, 0);
      return 1;
    }
    return 0;
  }
}

// ---------------------------------------------------------------------------
// RuleShift2Mult
// ---------------------------------------------------------------------------

export class RuleShift2Mult extends Rule {
  constructor(g: string) {
    super(g, 0, "shift2mult");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleShift2Mult(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_LEFT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let flag: number = 0;
    const vn: Varnode = op.getOut()!;
    const constvn: Varnode = op.getIn(1)!;
    if (!constvn.isConstant()) return 0;
    const val: number = Number(constvn.getOffset());
    if (val >= 32) return 0;

    let arithop: PcodeOp | null = op.getIn(0)!.getDef()!;
    const descIter = vn.descend;
    let descIdx = 0;
    const descArr = Array.from(descIter);

    for (;;) {
      if (arithop !== null) {
        const opc: number = arithop.code();
        if (opc === OpCode.CPUI_INT_ADD || opc === OpCode.CPUI_INT_SUB || opc === OpCode.CPUI_INT_MULT) {
          flag = 1;
          break;
        }
      }
      if (descIdx >= descArr.length) break;
      arithop = descArr[descIdx++];
    }

    if (flag === 0) return 0;
    const newconstvn: Varnode = data.newConstant(vn.getSize(), 1n << BigInt(val));
    data.opSetInput(op, newconstvn, 1);
    data.opSetOpcode(op, OpCode.CPUI_INT_MULT);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// RuleShiftPiece
// ---------------------------------------------------------------------------

export class RuleShiftPiece extends Rule {
  constructor(g: string) {
    super(g, 0, "shiftpiece");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleShiftPiece(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_OR);
    oplist.push(OpCode.CPUI_INT_XOR);
    oplist.push(OpCode.CPUI_INT_ADD);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let shiftop: PcodeOp;
    let zextloop: PcodeOp;
    let zexthiop: PcodeOp;
    let vn1: Varnode;
    let vn2: Varnode;

    vn1 = op.getIn(0)!;
    if (!vn1.isWritten()) return 0;
    vn2 = op.getIn(1)!;
    if (!vn2.isWritten()) return 0;
    shiftop = vn1.getDef()!;
    zextloop = vn2.getDef()!;
    if (shiftop.code() !== OpCode.CPUI_INT_LEFT) {
      if (zextloop.code() !== OpCode.CPUI_INT_LEFT) return 0;
      const tmpop = zextloop;
      zextloop = shiftop;
      shiftop = tmpop;
    }
    if (!shiftop.getIn(1)!.isConstant()) return 0;
    vn1 = shiftop.getIn(0)!;
    if (!vn1.isWritten()) return 0;
    zexthiop = vn1.getDef()!;
    if (zexthiop.code() !== OpCode.CPUI_INT_ZEXT &&
        zexthiop.code() !== OpCode.CPUI_INT_SEXT)
      return 0;
    vn1 = zexthiop.getIn(0)!;
    if (vn1.isConstant()) {
      if (vn1.getSize() < 8)  // sizeof(uintb) = 8
        return 0;
    } else if (vn1.isFree()) {
      return 0;
    }
    const sa: number = Number(shiftop.getIn(1)!.getOffset());
    const concatsize: number = sa + 8 * vn1.getSize();
    if (op.getOut()!.getSize() * 8 < concatsize) return 0;
    if (zextloop.code() !== OpCode.CPUI_INT_ZEXT) {
      // Special case triggered by CDQ: IDIV
      if (!vn1.isWritten()) return 0;
      const rShiftOp: PcodeOp = vn1.getDef()!;
      if (rShiftOp.code() !== OpCode.CPUI_INT_SRIGHT) return 0;
      if (!rShiftOp.getIn(1)!.isConstant()) return 0;
      vn2 = rShiftOp.getIn(0)!;
      if (!vn2.isWritten()) return 0;
      const subop: PcodeOp = vn2.getDef()!;
      if (subop.code() !== OpCode.CPUI_SUBPIECE) return 0;
      if (subop.getIn(1)!.getOffset() !== 0n) return 0;
      const bigVn: Varnode = zextloop.getOut()!;
      if (subop.getIn(0)! !== bigVn) return 0;
      const rsa: number = Number(rShiftOp.getIn(1)!.getOffset());
      if (rsa !== vn2.getSize() * 8 - 1) return 0;
      if ((bigVn.getNZMask() >> BigInt(sa)) !== 0n) return 0;
      if (sa !== 8 * vn2.getSize()) return 0;
      data.opSetOpcode(op, OpCode.CPUI_INT_SEXT);
      data.opSetInput(op, vn2, 0);
      data.opRemoveInput(op, 1);
      return 1;
    }
    vn2 = zextloop.getIn(0)!;
    if (vn2.isFree()) return 0;
    if (sa !== 8 * vn2.getSize()) return 0;
    if (concatsize === op.getOut()!.getSize() * 8) {
      data.opSetOpcode(op, OpCode.CPUI_PIECE);
      data.opSetInput(op, vn1, 0);
      data.opSetInput(op, vn2, 1);
    } else {
      const newop: PcodeOp = data.newOp(2, op.getAddr());
      data.newUniqueOut(concatsize / 8, newop);
      data.opSetOpcode(newop, OpCode.CPUI_PIECE);
      data.opSetInput(newop, vn1, 0);
      data.opSetInput(newop, vn2, 1);
      data.opInsertBefore(newop, op);
      data.opSetOpcode(op, zexthiop.code());
      data.opRemoveInput(op, 1);
      data.opSetInput(op, newop.getOut()!, 0);
    }
    return 1;
  }
}

// ---------------------------------------------------------------------------
// RuleCollapseConstants
// ---------------------------------------------------------------------------

export class RuleCollapseConstants extends Rule {
  constructor(g: string) {
    super(g, 0, "collapseconstants");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleCollapseConstants(this.getGroup());
  }

  // applies to all opcodes (no getOpList override)

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (!op.isCollapsible()) return 0;

    let newval: Address;
    let markedInput = false;
    try {
      const collapseResult = op.collapse();
      markedInput = collapseResult.markedInput;
      newval = data.getArch().getConstant(collapseResult.result);
    } catch (err) {
      data.opMarkNoCollapse(op);
      return 0;
    }

    const vn: Varnode = data.newVarnode(op.getOut()!.getSize(), newval);
    if (markedInput) {
      op.collapseConstantSymbol(vn);
    }
    for (let i = op.numInput() - 1; i > 0; --i)
      data.opRemoveInput(op, i);
    data.opSetInput(op, vn, 0);
    data.opSetOpcode(op, OpCode.CPUI_COPY);

    return 1;
  }
}

// ---------------------------------------------------------------------------
// RuleTransformCpool
// ---------------------------------------------------------------------------

export class RuleTransformCpool extends Rule {
  constructor(g: string) {
    super(g, 0, "transformcpool");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleTransformCpool(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_CPOOLREF);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (op.isCpoolTransformed()) return 0;
    data.opMarkCpoolTransformed(op);
    const refs: bigint[] = [];
    for (let i = 1; i < op.numInput(); ++i)
      refs.push(op.getIn(i)!.getOffset());
    const rec: CPoolRecord | null = data.getArch().cpool!.getRecord(refs);
    if (rec !== null) {
      if (rec.getTag() === 6 /* CPoolRecord.instance_of */) {
        data.opMarkCalculatedBool(op);
      } else if (rec.getTag() === 0 /* CPoolRecord.primitive */) {
        const sz: number = op.getOut()!.getSize();
        const cvn: Varnode = data.newConstant(sz, rec.getValue() & calc_mask(sz));
        cvn.updateType(rec.getType(), true, true);
        while (op.numInput() > 1) {
          data.opRemoveInput(op, op.numInput() - 1);
        }
        data.opSetOpcode(op, OpCode.CPUI_COPY);
        data.opSetInput(op, cvn, 0);
        return 1;
      }
      data.opInsertInput(op, data.newConstant(4, BigInt(rec.getTag())), op.numInput());
    }
    return 1;
  }
}

// ---------------------------------------------------------------------------
// RulePropagateCopy
// ---------------------------------------------------------------------------

export class RulePropagateCopy extends Rule {
  constructor(g: string) {
    super(g, 0, "propagatecopy");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RulePropagateCopy(this.getGroup());
  }

  // applies to all opcodes (no getOpList override)

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (op.isReturnCopy()) return 0;
    for (let i = 0; i < op.numInput(); ++i) {
      const vn: Varnode = op.getIn(i)!;
      if (!vn.isWritten()) continue;

      const copyop: PcodeOp = vn.getDef()!;
      if (copyop.code() !== OpCode.CPUI_COPY)
        continue;

      const invn: Varnode = copyop.getIn(0)!;
      if (!invn.isHeritageKnown()) continue;
      if (invn === vn)
        throw new LowlevelError("Self-defined varnode");
      if (op.isMarker()) {
        if (invn.isConstant()) continue;
        if (vn.isAddrForce()) continue;
        if (invn.isAddrTied() && op.getOut()!.isAddrTied() &&
            (!op.getOut()!.getAddr().equals(invn.getAddr())))
          continue;
      }
      data.opSetInput(op, invn, i);
      return 1;
    }
    return 0;
  }
}

// ---------------------------------------------------------------------------
// Rule2Comp2Mult
// ---------------------------------------------------------------------------

export class Rule2Comp2Mult extends Rule {
  constructor(g: string) {
    super(g, 0, "2comp2mult");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new Rule2Comp2Mult(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_2COMP);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    data.opSetOpcode(op, OpCode.CPUI_INT_MULT);
    const size: number = op.getIn(0)!.getSize();
    const negone: Varnode = data.newConstant(size, calc_mask(size));
    data.opInsertInput(op, negone, 1);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// RuleCarryElim
// ---------------------------------------------------------------------------

export class RuleCarryElim extends Rule {
  constructor(g: string) {
    super(g, 0, "carryelim");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleCarryElim(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_CARRY);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const vn2: Varnode = op.getIn(1)!;
    if (!vn2.isConstant()) return 0;
    const vn1: Varnode = op.getIn(0)!;
    if (vn1.isFree()) return 0;
    let off: bigint = vn2.getOffset();
    if (off === 0n) {
      data.opRemoveInput(op, 1);
      data.opSetInput(op, data.newConstant(1, 0n), 0);
      data.opSetOpcode(op, OpCode.CPUI_COPY);
      return 1;
    }
    off = (-off) & calc_mask(vn2.getSize());

    data.opSetOpcode(op, OpCode.CPUI_INT_LESSEQUAL);
    data.opSetInput(op, vn1, 1);
    data.opSetInput(op, data.newConstant(vn1.getSize(), off), 0);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// RuleSub2Add
// ---------------------------------------------------------------------------

export class RuleSub2Add extends Rule {
  constructor(g: string) {
    super(g, 0, "sub2add");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSub2Add(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_SUB);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const vn: Varnode = op.getIn(1)!;
    const newop: PcodeOp = data.newOp(2, op.getAddr());
    data.opSetOpcode(newop, OpCode.CPUI_INT_MULT);
    const newvn: Varnode = data.newUniqueOut(vn.getSize(), newop);
    data.opSetInput(op, newvn, 1);
    data.opSetInput(newop, vn, 0);
    data.opSetInput(newop, data.newConstant(vn.getSize(), calc_mask(vn.getSize())), 1);
    data.opSetOpcode(op, OpCode.CPUI_INT_ADD);
    data.opInsertBefore(newop, op);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// RuleXorCollapse
// ---------------------------------------------------------------------------

export class RuleXorCollapse extends Rule {
  constructor(g: string) {
    super(g, 0, "xorcollapse");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleXorCollapse(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_EQUAL);
    oplist.push(OpCode.CPUI_INT_NOTEQUAL);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (!op.getIn(1)!.isConstant()) return 0;
    const xorop: PcodeOp | null = op.getIn(0)!.getDef()!;
    if (xorop === null) return 0;
    if (xorop.code() !== OpCode.CPUI_INT_XOR) return 0;
    if (op.getIn(0)!.loneDescend()! === null) return 0;
    const coeff1: bigint = op.getIn(1)!.getOffset();
    const xorvn: Varnode = xorop.getIn(1)!;
    if (xorop.getIn(0)!.isFree()) return 0;
    if (!xorvn.isConstant()) {
      if (coeff1 !== 0n) return 0;
      if (xorvn.isFree()) return 0;
      data.opSetInput(op, xorvn, 1);
      data.opSetInput(op, xorop.getIn(0)!, 0);
      return 1;
    }
    const coeff2: bigint = xorvn.getOffset();
    if (coeff2 === 0n) return 0;
    const constvn: Varnode = data.newConstant(op.getIn(1)!.getSize(), coeff1 ^ coeff2);
    constvn.copySymbolIfValid(xorvn);
    data.opSetInput(op, constvn, 1);
    data.opSetInput(op, xorop.getIn(0)!, 0);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// RuleAddMultCollapse
// ---------------------------------------------------------------------------

export class RuleAddMultCollapse extends Rule {
  constructor(g: string) {
    super(g, 0, "addmultcollapse");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleAddMultCollapse(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_ADD, OpCode.CPUI_INT_MULT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const c: Varnode[] = new Array(2);
    let sub: Varnode;
    let sub2: Varnode;
    let newvn: Varnode;
    let subop: PcodeOp;

    const opc: number = op.code();
    c[0] = op.getIn(1)!;
    if (!c[0].isConstant()) return 0;
    sub = op.getIn(0)!;
    if (!sub.isWritten()) return 0;
    subop = sub.getDef()!;
    if (subop.code() !== opc) return 0;
    c[1] = subop.getIn(1)!;
    if (!c[1].isConstant()) {
      if (opc !== OpCode.CPUI_INT_ADD) return 0;
      for (let i = 0; i < 2; ++i) {
        const othervn: Varnode = subop.getIn(i)!;
        if (othervn.isConstant()) continue;
        if (othervn.isFree()) continue;
        sub2 = subop.getIn(1 - i)!;
        if (!sub2.isWritten()) continue;
        const baseop: PcodeOp = sub2.getDef()!;
        if (baseop.code() !== OpCode.CPUI_INT_ADD) continue;
        c[1] = baseop.getIn(1)!;
        if (!c[1].isConstant()) continue;
        const basevn: Varnode = baseop.getIn(0)!;
        if (!basevn.isSpacebase()) continue;
        if (!basevn.isInput()) continue;

        const val: bigint = op.getOpcode().evaluateBinary(c[0].getSize(), c[0].getSize(), c[0].getOffset(), c[1].getOffset());
        newvn = data.newConstant(c[0].getSize(), val);
        if (c[0].getSymbolEntry() !== null)
          newvn.copySymbolIfValid(c[0]);
        else if (c[1].getSymbolEntry() !== null)
          newvn.copySymbolIfValid(c[1]);
        const newop: PcodeOp = data.newOp(2, op.getAddr());
        data.opSetOpcode(newop, OpCode.CPUI_INT_ADD);
        const newout: Varnode = data.newUniqueOut(c[0].getSize(), newop);
        data.opSetInput(newop, basevn, 0);
        data.opSetInput(newop, newvn, 1);
        data.opInsertBefore(newop, op);
        data.opSetInput(op, newout, 0);
        data.opSetInput(op, othervn, 1);
        return 1;
      }
      return 0;
    }
    sub2 = subop.getIn(0)!;
    if (sub2.isFree()) return 0;

    const val: bigint = op.getOpcode().evaluateBinary(c[0].getSize(), c[0].getSize(), c[0].getOffset(), c[1].getOffset());
    newvn = data.newConstant(c[0].getSize(), val);
    if (c[0].getSymbolEntry() !== null)
      newvn.copySymbolIfValid(c[0]);
    else if (c[1].getSymbolEntry() !== null)
      newvn.copySymbolIfValid(c[1]);
    data.opSetInput(op, newvn, 1);
    data.opSetInput(op, sub2, 0);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// RuleLoadVarnode
// ---------------------------------------------------------------------------

export class RuleLoadVarnode extends Rule {
  constructor(g: string) {
    super(g, 0, "loadvarnode");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleLoadVarnode(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_LOAD);
  }

  static correctSpacebase(glb: Architecture, vn: Varnode, spc: AddrSpace): AddrSpace | null {
    if (!vn.isSpacebase()) return null;
    if (vn.isConstant())
      return spc;
    if (!vn.isInput()) return null;
    const assoc: AddrSpace = glb.getSpaceBySpacebase(vn.getAddr(), vn.getSize());
    if (assoc.getContain() !== spc)
      return null;
    return assoc;
  }

  static vnSpacebase(glb: Architecture, vn: Varnode, spc: AddrSpace): { space: AddrSpace | null; val: bigint } {
    let retspace: AddrSpace | null;
    let val: bigint = 0n;

    retspace = RuleLoadVarnode.correctSpacebase(glb, vn, spc);
    if (retspace !== null) {
      return { space: retspace, val: 0n };
    }
    if (!vn.isWritten()) return { space: null, val: 0n };
    const op: PcodeOp = vn.getDef()!;
    if (op.code() !== OpCode.CPUI_INT_ADD) return { space: null, val: 0n };
    const vn1: Varnode = op.getIn(0)!;
    const vn2: Varnode = op.getIn(1)!;
    retspace = RuleLoadVarnode.correctSpacebase(glb, vn1, spc);
    if (retspace !== null) {
      if (vn2.isConstant()) {
        return { space: retspace, val: vn2.getOffset() };
      }
      return { space: null, val: 0n };
    }
    retspace = RuleLoadVarnode.correctSpacebase(glb, vn2, spc);
    if (retspace !== null) {
      if (vn1.isConstant()) {
        return { space: retspace, val: vn1.getOffset() };
      }
    }
    return { space: null, val: 0n };
  }

  static checkSpacebase(glb: Architecture, op: PcodeOp): { space: AddrSpace | null; offoff: bigint } {
    let offvn: Varnode;
    let loadspace: AddrSpace;

    offvn = op.getIn(1)!;
    loadspace = op.getIn(0)!.getSpaceFromConst()!;
    // Treat segmentop as part of load/store
    if (offvn.isWritten() && offvn.getDef()!.code() === OpCode.CPUI_SEGMENTOP) {
      offvn = offvn.getDef()!.getIn(2)!;
      if (offvn.isConstant())
        return { space: null, offoff: 0n };
    } else if (offvn.isConstant()) {
      return { space: loadspace, offoff: offvn.getOffset() };
    }
    const result = RuleLoadVarnode.vnSpacebase(glb, offvn, loadspace);
    return { space: result.space, offoff: result.val };
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const result = RuleLoadVarnode.checkSpacebase(data.getArch(), op);
    const baseoff: AddrSpace | null = result.space;
    let offoff: bigint = result.offoff;
    if (baseoff === null) return 0;

    const size: number = op.getOut()!.getSize();
    offoff = AddrSpace.addressToByte(offoff, baseoff.getWordSize());
    const newvn: Varnode = data.newVarnode(size, new Address(baseoff, offoff));
    data.opSetInput(op, newvn, 0);
    data.opRemoveInput(op, 1);
    data.opSetOpcode(op, OpCode.CPUI_COPY);
    const refvn: Varnode = op.getOut()!;
    if (refvn.isSpacebasePlaceholder()) {
      refvn.clearSpacebasePlaceholder();
      const placeOp: PcodeOp | null = refvn.loneDescend()!;
      if (placeOp !== null) {
        const fc: FuncCallSpecs | null = data.getCallSpecs(placeOp);
        if (fc !== null)
          fc.resolveSpacebaseRelative(data, refvn);
      }
    }
    return 1;
  }
}

// ---------------------------------------------------------------------------
// RuleStoreVarnode
// ---------------------------------------------------------------------------

export class RuleStoreVarnode extends Rule {
  constructor(g: string) {
    super(g, 0, "storevarnode");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleStoreVarnode(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_STORE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const result = RuleLoadVarnode.checkSpacebase(data.getArch(), op);
    const baseoff: AddrSpace | null = result.space;
    let offoff: bigint = result.offoff;
    if (baseoff === null) return 0;

    const size: number = op.getIn(2)!.getSize();
    offoff = AddrSpace.addressToByte(offoff, baseoff.getWordSize());
    const addr = new Address(baseoff, offoff);
    data.newVarnodeOut(size, addr, op);
    op.getOut()!.setStackStore();
    data.opRemoveInput(op, 1);
    data.opRemoveInput(op, 0);
    data.opSetOpcode(op, OpCode.CPUI_COPY);
    if (op.isStoreUnmapped()) {
      data.getScopeLocal()!.markNotMapped(baseoff, offoff, size, false);
    }
    return 1;
  }
}

// ---------------------------------------------------------------------------
// RuleSubExtComm
// ---------------------------------------------------------------------------

export class RuleSubExtComm extends Rule {
  constructor(g: string) {
    super(g, 0, "subextcomm");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSubExtComm(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_SUBPIECE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const base: Varnode = op.getIn(0)!;
    if (!base.isWritten()) return 0;
    const extop: PcodeOp = base.getDef()!;
    if (extop.code() !== OpCode.CPUI_INT_ZEXT && extop.code() !== OpCode.CPUI_INT_SEXT)
      return 0;
    const invn: Varnode = extop.getIn(0)!;
    if (invn.isFree()) return 0;
    const subcut: number = Number(op.getIn(1)!.getOffset());
    if (op.getOut()!.getSize() + subcut <= invn.getSize()) {
      // SUBPIECE doesn't hit the extended bits at all
      data.opSetInput(op, invn, 0);
      if (invn.getSize() === op.getOut()!.getSize()) {
        data.opRemoveInput(op, 1);
        data.opSetOpcode(op, OpCode.CPUI_COPY);
      }
      return 1;
    }

    if (subcut >= invn.getSize()) return 0;

    let newvn: Varnode;
    if (subcut !== 0) {
      const newop: PcodeOp = data.newOp(2, op.getAddr());
      data.opSetOpcode(newop, OpCode.CPUI_SUBPIECE);
      newvn = data.newUniqueOut(invn.getSize() - subcut, newop);
      data.opSetInput(newop, data.newConstant(op.getIn(1)!.getSize(), BigInt(subcut)), 1);
      data.opSetInput(newop, invn, 0);
      data.opInsertBefore(newop, op);
    } else {
      newvn = invn;
    }

    data.opRemoveInput(op, 1);
    data.opSetOpcode(op, extop.code());
    data.opSetInput(op, newvn, 0);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// RuleSubCommute
// ---------------------------------------------------------------------------

export class RuleSubCommute extends Rule {
  constructor(g: string) {
    super(g, 0, "subcommute");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSubCommute(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_SUBPIECE);
  }

  static shortenExtension(extOp: PcodeOp, maxSize: number, data: Funcdata): Varnode {
    const origOut: Varnode = extOp.getOut()!;
    let addr: Address = origOut.getAddr();
    if (addr.isBigEndian())
      addr = addr.add(BigInt(origOut.getSize() - maxSize));
    data.opUnsetOutput(extOp);
    return data.newVarnodeOut(maxSize, addr, extOp);
  }

  static cancelExtensions(longform: PcodeOp, subOp: PcodeOp, ext0In: Varnode, ext1In: Varnode, data: Funcdata): boolean {
    let maxSize: number;
    const outvn: Varnode = longform.getOut()!;
    if (outvn.loneDescend()! !== subOp) return false;
    if (ext0In.getSize() === ext1In.getSize()) {
      maxSize = ext0In.getSize();
      if (ext0In.isFree()) return false;
      if (ext1In.isFree()) return false;
    } else if (ext0In.getSize() < ext1In.getSize()) {
      maxSize = ext1In.getSize();
      if (ext1In.isFree()) return false;
      if (longform.getIn(0)!.loneDescend()! !== longform) return false;
      ext0In = RuleSubCommute.shortenExtension(longform.getIn(0)!.getDef()!, maxSize, data);
    } else {
      maxSize = ext0In.getSize();
      if (ext0In.isFree()) return false;
      if (longform.getIn(1)!.loneDescend()! !== longform) return false;
      ext1In = RuleSubCommute.shortenExtension(longform.getIn(1)!.getDef()!, maxSize, data);
    }
    data.opUnsetOutput(longform);
    const newOutvn: Varnode = data.newUniqueOut(maxSize, longform);
    data.opSetInput(longform, ext0In, 0);
    data.opSetInput(longform, ext1In, 1);
    data.opSetInput(subOp, newOutvn, 0);
    return true;
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const base: Varnode = op.getIn(0)!;
    if (!base.isWritten()) return 0;
    const offset: number = Number(op.getIn(1)!.getOffset());
    const outvn: Varnode = op.getOut()!;
    if (outvn.isPrecisLo() || outvn.isPrecisHi()) return 0;
    const insize: number = base.getSize();
    const longform: PcodeOp = base.getDef()!;
    let j = -1;
    switch (longform.code()) {
      case OpCode.CPUI_INT_LEFT:
        j = 1;
        if (offset !== 0) return 0;
        if (longform.getIn(0)!.isWritten()) {
          const opc: number = longform.getIn(0)!.getDef()!.code();
          if (opc !== OpCode.CPUI_INT_ZEXT && opc !== OpCode.CPUI_PIECE)
            return 0;
        } else {
          return 0;
        }
        break;
      case OpCode.CPUI_INT_REM:
      case OpCode.CPUI_INT_DIV:
      {
        if (offset !== 0) return 0;
        if (!longform.getIn(0)!.isWritten()) return 0;
        const zext0: PcodeOp = longform.getIn(0)!.getDef()!;
        if (zext0.code() !== OpCode.CPUI_INT_ZEXT) return 0;
        const zext0In: Varnode = zext0.getIn(0)!;
        if (longform.getIn(1)!.isWritten()) {
          const zext1: PcodeOp = longform.getIn(1)!.getDef()!;
          if (zext1.code() !== OpCode.CPUI_INT_ZEXT) return 0;
          const zext1In: Varnode = zext1.getIn(0)!;
          if (zext1In.getSize() > outvn.getSize() || zext0In.getSize() > outvn.getSize()) {
            if (RuleSubCommute.cancelExtensions(longform, op, zext0In, zext1In, data))
              return 1;
            return 0;
          }
        } else if (longform.getIn(1)!.isConstant() && (zext0In.getSize() <= outvn.getSize())) {
          const val: bigint = longform.getIn(1)!.getOffset();
          const smallval: bigint = val & calc_mask(outvn.getSize());
          if (val !== smallval)
            return 0;
        } else {
          return 0;
        }
        break;
      }
      case OpCode.CPUI_INT_SREM:
      case OpCode.CPUI_INT_SDIV:
      {
        if (offset !== 0) return 0;
        if (!longform.getIn(0)!.isWritten()) return 0;
        const sext0: PcodeOp = longform.getIn(0)!.getDef()!;
        if (sext0.code() !== OpCode.CPUI_INT_SEXT) return 0;
        const sext0In: Varnode = sext0.getIn(0)!;
        if (longform.getIn(1)!.isWritten()) {
          const sext1: PcodeOp = longform.getIn(1)!.getDef()!;
          if (sext1.code() !== OpCode.CPUI_INT_SEXT) return 0;
          const sext1In: Varnode = sext1.getIn(0)!;
          if (sext1In.getSize() > outvn.getSize() || sext0In.getSize() > outvn.getSize()) {
            if (RuleSubCommute.cancelExtensions(longform, op, sext0In, sext1In, data))
              return 1;
            return 0;
          }
        } else if (longform.getIn(1)!.isConstant() && (sext0In.getSize() <= outvn.getSize())) {
          const val: bigint = longform.getIn(1)!.getOffset();
          const smallval: bigint = val & calc_mask(outvn.getSize());
          const extended: bigint = sign_extend(smallval, insize * 8 - 1);
          if (val !== extended)
            return 0;
        } else {
          return 0;
        }
        break;
      }
      case OpCode.CPUI_INT_ADD:
        if (offset !== 0) return 0;
        if (longform.getIn(0)!.isSpacebase()) return 0;
        break;
      case OpCode.CPUI_INT_MULT:
        if (offset !== 0) return 0;
        break;
      case OpCode.CPUI_INT_NEGATE:
      case OpCode.CPUI_INT_XOR:
      case OpCode.CPUI_INT_AND:
      case OpCode.CPUI_INT_OR:
        break;
      default:
        return 0;
    }

    // Make sure no other piece of base is getting used
    if (base.loneDescend()! !== op) return 0;

    if (offset === 0) {
      const nextop: PcodeOp | null = outvn.loneDescend()!;
      if (nextop !== null && nextop.code() === OpCode.CPUI_INT_ZEXT) {
        if (nextop.getOut()!.getSize() === insize)
          return 0;
      }
    }

    let lastIn: Varnode | null = null;
    let newVn: Varnode | null = null;
    for (let i = 0; i < longform.numInput(); ++i) {
      const vn: Varnode = longform.getIn(i)!;
      if (i !== j) {
        if (lastIn !== vn || newVn === null) {
          const newsub: PcodeOp = data.newOp(2, op.getAddr());
          data.opSetOpcode(newsub, OpCode.CPUI_SUBPIECE);
          newVn = data.newUniqueOut(outvn.getSize(), newsub);
          data.opSetInput(longform, newVn, i);
          data.opSetInput(newsub, vn, 0);
          data.opSetInput(newsub, data.newConstant(4, BigInt(offset)), 1);
          data.opInsertBefore(newsub, longform);
        } else {
          data.opSetInput(longform, newVn, i);
        }
      }
      lastIn = vn;
    }
    data.opSetOutput(longform, outvn);
    data.opDestroy(op);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// RuleConcatCommute
// ---------------------------------------------------------------------------

export class RuleConcatCommute extends Rule {
  constructor(g: string) {
    super(g, 0, "concatcommute");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleConcatCommute(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_PIECE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let hi: Varnode;
    let lo: Varnode;
    let opc: number;
    let val: bigint;

    const outsz: number = op.getOut()!.getSize();
    if (outsz > 8)  // sizeof(uintb) = 8
      return 0;
    for (let i = 0; i < 2; ++i) {
      const vn: Varnode = op.getIn(i)!;
      if (!vn.isWritten()) continue;
      const logicop: PcodeOp = vn.getDef()!;
      opc = logicop.code();
      if (opc === OpCode.CPUI_INT_OR || opc === OpCode.CPUI_INT_XOR) {
        if (!logicop.getIn(1)!.isConstant()) continue;
        val = logicop.getIn(1)!.getOffset();
        if (i === 0) {
          hi = logicop.getIn(0)!;
          lo = op.getIn(1)!;
          val <<= BigInt(8 * lo.getSize());
        } else {
          hi = op.getIn(0)!;
          lo = logicop.getIn(0)!;
        }
      } else if (opc === OpCode.CPUI_INT_AND) {
        if (!logicop.getIn(1)!.isConstant()) continue;
        val = logicop.getIn(1)!.getOffset();
        if (i === 0) {
          hi = logicop.getIn(0)!;
          lo = op.getIn(1)!;
          val <<= BigInt(8 * lo.getSize());
          val |= calc_mask(lo.getSize());
        } else {
          hi = op.getIn(0)!;
          lo = logicop.getIn(0)!;
          val |= (calc_mask(hi.getSize()) << BigInt(8 * lo.getSize()));
        }
      } else {
        continue;
      }
      if (hi.isFree()) continue;
      if (lo.isFree()) continue;
      const newconcat: PcodeOp = data.newOp(2, op.getAddr());
      data.opSetOpcode(newconcat, OpCode.CPUI_PIECE);
      const newvn: Varnode = data.newUniqueOut(outsz, newconcat);
      data.opSetInput(newconcat, hi, 0);
      data.opSetInput(newconcat, lo, 1);
      data.opInsertBefore(newconcat, op);
      data.opSetOpcode(op, opc);
      data.opSetInput(op, newvn, 0);
      data.opSetInput(op, data.newConstant(newvn.getSize(), val), 1);
      return 1;
    }
    return 0;
  }
}

// ---------------------------------------------------------------------------
// RuleConcatZext
// ---------------------------------------------------------------------------

export class RuleConcatZext extends Rule {
  constructor(g: string) {
    super(g, 0, "concatzext");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleConcatZext(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_PIECE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let hi: Varnode = op.getIn(0)!;
    if (!hi.isWritten()) return 0;
    const zextop: PcodeOp = hi.getDef()!;
    if (zextop.code() !== OpCode.CPUI_INT_ZEXT) return 0;
    hi = zextop.getIn(0)!;
    const lo: Varnode = op.getIn(1)!;
    if (hi.isFree()) return 0;
    if (lo.isFree()) return 0;

    const newconcat: PcodeOp = data.newOp(2, op.getAddr());
    data.opSetOpcode(newconcat, OpCode.CPUI_PIECE);
    const newvn: Varnode = data.newUniqueOut(hi.getSize() + lo.getSize(), newconcat);
    data.opSetInput(newconcat, hi, 0);
    data.opSetInput(newconcat, lo, 1);
    data.opInsertBefore(newconcat, op);

    data.opRemoveInput(op, 1);
    data.opSetInput(op, newvn, 0);
    data.opSetOpcode(op, OpCode.CPUI_INT_ZEXT);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// RuleZextCommute
// ---------------------------------------------------------------------------

export class RuleZextCommute extends Rule {
  constructor(g: string) {
    super(g, 0, "zextcommute");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleZextCommute(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_RIGHT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const zextvn: Varnode = op.getIn(0)!;
    if (!zextvn.isWritten()) return 0;
    const zextop: PcodeOp = zextvn.getDef()!;
    if (zextop.code() !== OpCode.CPUI_INT_ZEXT) return 0;
    const zextin: Varnode = zextop.getIn(0)!;
    if (zextin.isFree()) return 0;
    const savn: Varnode = op.getIn(1)!;
    if (!savn.isConstant() && savn.isFree())
      return 0;

    const newop: PcodeOp = data.newOp(2, op.getAddr());
    data.opSetOpcode(newop, OpCode.CPUI_INT_RIGHT);
    const newout: Varnode = data.newUniqueOut(zextin.getSize(), newop);
    data.opRemoveInput(op, 1);
    data.opSetInput(op, newout, 0);
    data.opSetOpcode(op, OpCode.CPUI_INT_ZEXT);
    data.opSetInput(newop, zextin, 0);
    data.opSetInput(newop, savn, 1);
    data.opInsertBefore(newop, op);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// RuleZextShiftZext
// ---------------------------------------------------------------------------

export class RuleZextShiftZext extends Rule {
  constructor(g: string) {
    super(g, 0, "zextshiftzext");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleZextShiftZext(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_ZEXT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const invn: Varnode = op.getIn(0)!;
    if (!invn.isWritten()) return 0;
    const shiftop: PcodeOp = invn.getDef()!;
    if (shiftop.code() === OpCode.CPUI_INT_ZEXT) {
      // Check for ZEXT( ZEXT( a ) )
      const vn: Varnode = shiftop.getIn(0)!;
      if (vn.isFree()) return 0;
      if (invn.loneDescend()! !== op)
        return 0;
      data.opSetInput(op, vn, 0);
      return 1;
    }
    if (shiftop.code() !== OpCode.CPUI_INT_LEFT) return 0;
    if (!shiftop.getIn(1)!.isConstant()) return 0;
    if (!shiftop.getIn(0)!.isWritten()) return 0;
    const zext2op: PcodeOp = shiftop.getIn(0)!.getDef()!;
    if (zext2op.code() !== OpCode.CPUI_INT_ZEXT) return 0;
    const rootvn: Varnode = zext2op.getIn(0)!;
    if (rootvn.isFree()) return 0;

    const sa: bigint = shiftop.getIn(1)!.getOffset();
    if (sa > BigInt(8 * (zext2op.getOut()!.getSize() - rootvn.getSize())))
      return 0;
    const newop: PcodeOp = data.newOp(1, op.getAddr());
    data.opSetOpcode(newop, OpCode.CPUI_INT_ZEXT);
    const outvn: Varnode = data.newUniqueOut(op.getOut()!.getSize(), newop);
    data.opSetInput(newop, rootvn, 0);
    data.opSetOpcode(op, OpCode.CPUI_INT_LEFT);
    data.opSetInput(op, outvn, 0);
    data.opInsertInput(op, data.newConstant(4, sa), 1);
    data.opInsertBefore(newop, op);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// RuleShiftAnd
// ---------------------------------------------------------------------------

export class RuleShiftAnd extends Rule {
  constructor(g: string) {
    super(g, 0, "shiftand");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleShiftAnd(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_RIGHT);
    oplist.push(OpCode.CPUI_INT_LEFT);
    oplist.push(OpCode.CPUI_INT_MULT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const cvn: Varnode = op.getIn(1)!;
    if (!cvn.isConstant()) return 0;
    const shiftin: Varnode = op.getIn(0)!;
    if (!shiftin.isWritten()) return 0;
    const andop: PcodeOp = shiftin.getDef()!;
    if (andop.code() !== OpCode.CPUI_INT_AND) return 0;
    const maskvn: Varnode = andop.getIn(1)!;
    if (!maskvn.isConstant()) return 0;
    let mask: bigint = maskvn.getOffset();
    const invn: Varnode = andop.getIn(0)!;
    if (invn.isFree()) return 0;

    let opc: number = op.code();
    let sa: number;
    if (opc === OpCode.CPUI_INT_RIGHT || opc === OpCode.CPUI_INT_LEFT) {
      sa = Number(cvn.getOffset());
    } else {
      sa = leastsigbit_set(cvn.getOffset());
      if (sa <= 0) return 0;
      let testval: bigint = 1n;
      testval <<= BigInt(sa);
      if (testval !== cvn.getOffset()) return 0;
      opc = OpCode.CPUI_INT_LEFT;
    }
    let nzm: bigint = invn.getNZMask();
    const fullmask: bigint = calc_mask(invn.getSize());
    if (opc === OpCode.CPUI_INT_RIGHT) {
      nzm >>= BigInt(sa);
      mask >>= BigInt(sa);
    } else {
      nzm <<= BigInt(sa);
      mask <<= BigInt(sa);
      nzm &= fullmask;
      mask &= fullmask;
    }
    if ((mask & nzm) !== nzm) return 0;
    data.opSetInput(op, invn, 0);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// RuleConcatZero
// ---------------------------------------------------------------------------

export class RuleConcatZero extends Rule {
  constructor(g: string) {
    super(g, 0, "concatzero");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleConcatZero(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_PIECE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (!op.getIn(1)!.isConstant()) return 0;
    if (op.getIn(1)!.getOffset() !== 0n) return 0;

    const sa: number = 8 * op.getIn(1)!.getSize();
    const highvn: Varnode = op.getIn(0)!;
    const newop: PcodeOp = data.newOp(1, op.getAddr());
    const outvn: Varnode = data.newUniqueOut(op.getOut()!.getSize(), newop);
    data.opSetOpcode(newop, OpCode.CPUI_INT_ZEXT);
    data.opSetOpcode(op, OpCode.CPUI_INT_LEFT);
    data.opSetInput(op, outvn, 0);
    data.opSetInput(op, data.newConstant(4, BigInt(sa)), 1);
    data.opSetInput(newop, highvn, 0);
    data.opInsertBefore(newop, op);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// RuleConcatLeftShift
// ---------------------------------------------------------------------------

export class RuleConcatLeftShift extends Rule {
  constructor(g: string) {
    super(g, 0, "concatleftshift");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleConcatLeftShift(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_PIECE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const vn2: Varnode = op.getIn(1)!;
    if (!vn2.isWritten()) return 0;
    const shiftop: PcodeOp = vn2.getDef()!;
    if (shiftop.code() !== OpCode.CPUI_INT_LEFT) return 0;
    if (!shiftop.getIn(1)!.isConstant()) return 0;
    let sa: number = Number(shiftop.getIn(1)!.getOffset());
    if ((sa & 7) !== 0) return 0;
    const tmpvn: Varnode = shiftop.getIn(0)!;
    if (!tmpvn.isWritten()) return 0;
    const zextop: PcodeOp = tmpvn.getDef()!;
    if (zextop.code() !== OpCode.CPUI_INT_ZEXT) return 0;
    const b: Varnode = zextop.getIn(0)!;
    if (b.isFree()) return 0;
    const vn1: Varnode = op.getIn(0)!;
    if (vn1.isFree()) return 0;
    sa = sa / 8;  // bits to bytes
    if (sa + b.getSize() !== tmpvn.getSize()) return 0;

    const newop: PcodeOp = data.newOp(2, op.getAddr());
    data.opSetOpcode(newop, OpCode.CPUI_PIECE);
    const newout: Varnode = data.newUniqueOut(vn1.getSize() + b.getSize(), newop);
    data.opSetInput(newop, vn1, 0);
    data.opSetInput(newop, b, 1);
    data.opInsertBefore(newop, op);
    data.opSetInput(op, newout, 0);
    data.opSetInput(op, data.newConstant(op.getOut()!.getSize() - newout.getSize(), 0n), 1);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// RuleSubZext
// ---------------------------------------------------------------------------

export class RuleSubZext extends Rule {
  constructor(g: string) {
    super(g, 0, "subzext");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSubZext(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_ZEXT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let basevn: Varnode;
    let constvn: Varnode;
    let val: bigint;

    const subvn: Varnode = op.getIn(0)!;
    if (!subvn.isWritten()) return 0;
    let subop: PcodeOp = subvn.getDef()!;
    if (subop.code() === OpCode.CPUI_SUBPIECE) {
      basevn = subop.getIn(0)!;
      if (basevn.isFree()) return 0;
      if (basevn.getSize() !== op.getOut()!.getSize()) return 0;
      if (basevn.getSize() > 8) return 0;  // sizeof(uintb) = 8
      if (subop.getIn(1)!.getOffset() !== 0n) {
        if (subvn.loneDescend()! !== op) return 0;
        const newvn: Varnode = data.newUnique(basevn.getSize(), null);
        constvn = subop.getIn(1)!;
        const rightVal: bigint = constvn.getOffset() * 8n;
        data.opSetInput(op, newvn, 0);
        data.opSetOpcode(subop, OpCode.CPUI_INT_RIGHT);
        data.opSetInput(subop, data.newConstant(constvn.getSize(), rightVal), 1);
        data.opSetOutput(subop, newvn);
      } else {
        data.opSetInput(op, basevn, 0);
      }
      val = calc_mask(subvn.getSize());
      constvn = data.newConstant(basevn.getSize(), val);
      data.opSetOpcode(op, OpCode.CPUI_INT_AND);
      data.opInsertInput(op, constvn, 1);
      return 1;
    } else if (subop.code() === OpCode.CPUI_INT_RIGHT) {
      const shiftop: PcodeOp = subop;
      if (!shiftop.getIn(1)!.isConstant()) return 0;
      const midvn: Varnode = shiftop.getIn(0)!;
      if (!midvn.isWritten()) return 0;
      subop = midvn.getDef()!;
      if (subop.code() !== OpCode.CPUI_SUBPIECE) return 0;
      basevn = subop.getIn(0)!;
      if (basevn.isFree()) return 0;
      if (basevn.getSize() !== op.getOut()!.getSize()) return 0;
      if (midvn.loneDescend()! !== shiftop) return 0;
      if (subvn.loneDescend()! !== op) return 0;
      val = calc_mask(midvn.getSize());
      let sa: bigint = shiftop.getIn(1)!.getOffset();
      val >>= sa;
      sa += subop.getIn(1)!.getOffset() * 8n;
      const newvn: Varnode = data.newUnique(basevn.getSize(), null);
      data.opSetInput(op, newvn, 0);
      data.opSetInput(shiftop, basevn, 0);
      data.opSetInput(shiftop, data.newConstant(shiftop.getIn(1)!.getSize(), sa), 1);
      data.opSetOutput(shiftop, newvn);
      constvn = data.newConstant(basevn.getSize(), val);
      data.opSetOpcode(op, OpCode.CPUI_INT_AND);
      data.opInsertInput(op, constvn, 1);
      return 1;
    }
    return 0;
  }
}

// ---------------------------------------------------------------------------
// RuleSubCancel
// ---------------------------------------------------------------------------

export class RuleSubCancel extends Rule {
  constructor(g: string) {
    super(g, 0, "subcancel");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSubCancel(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_SUBPIECE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let thruvn: Varnode;
    let base: Varnode;

    base = op.getIn(0)!;
    if (!base.isWritten()) return 0;
    const extop: PcodeOp = base.getDef()!;
    let opc: number = extop.code();
    if (opc !== OpCode.CPUI_INT_ZEXT && opc !== OpCode.CPUI_INT_SEXT && opc !== OpCode.CPUI_INT_AND)
      return 0;
    const offset: number = Number(op.getIn(1)!.getOffset());
    const outsize: number = op.getOut()!.getSize();

    if (opc === OpCode.CPUI_INT_AND) {
      const cvn: Varnode = extop.getIn(1)!;
      if (offset === 0 && cvn.isConstant() && cvn.getOffset() === calc_mask(outsize)) {
        thruvn = extop.getIn(0)!;
        if (!thruvn.isFree()) {
          data.opSetInput(op, thruvn, 0);
          return 1;
        }
      }
      return 0;
    }
    const insize: number = base.getSize();
    const farinsize: number = extop.getIn(0)!.getSize();

    if (offset === 0) {
      thruvn = extop.getIn(0)!;
      if (thruvn.isFree()) {
        if (thruvn.isConstant() && (insize > 8) && (outsize === farinsize)) {
          opc = OpCode.CPUI_COPY;
          thruvn = data.newConstant(thruvn.getSize(), thruvn.getOffset());
        } else {
          return 0;
        }
      } else if (outsize === farinsize) {
        opc = OpCode.CPUI_COPY;
      } else if (outsize < farinsize) {
        opc = OpCode.CPUI_SUBPIECE;
      }
    } else {
      if (opc === OpCode.CPUI_INT_ZEXT && farinsize <= offset) {
        opc = OpCode.CPUI_COPY;
        thruvn = data.newConstant(outsize, 0n);
      } else {
        return 0;
      }
    }

    data.opSetOpcode(op, opc);
    data.opSetInput(op, thruvn!, 0);

    if (opc !== OpCode.CPUI_SUBPIECE)
      data.opRemoveInput(op, 1);
    return 1;
  }
}
// PART 4: Rule classes from ruleaction.cc lines ~5500-7300
// Covers: RuleBoolNegate, RuleLess2Zero, RuleLessEqual2Zero, RuleSLess2Zero,
//         RuleEqual2Zero, RuleEqual2Constant, AddTreeState, RulePtrArith,
//         RuleStructOffset0, RulePushPtr, RulePtraddUndo, RulePtrsubUndo,
//         RuleMultNegOne, RuleAddUnsigned, Rule2Comp2Sub, RuleSubRight

// RuleBoolNegate: Apply identities involving BOOL_NEGATE
//   !!V => V
//   !(V == W) => V != W
//   !(V < W) => W <= V
//   !(V <= W) => W < V
//   !(V != W) => V == W
// Supports signed and floating-point variants.
export class RuleBoolNegate extends Rule {
  constructor(g: string) {
    super(g, 0, "boolnegate");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleBoolNegate(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_BOOL_NEGATE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let vn: Varnode;
    let flip_op: PcodeOp;
    let opc: OpCode;
    let flipyes: boolean;

    vn = op.getIn(0)!;
    if (!vn.isWritten()) return 0;
    flip_op = vn.getDef()!;

    // ALL descendants must be negates
    for (const iter of vn.descend) {
      if (iter.code() !== OpCode.CPUI_BOOL_NEGATE) return 0;
    }

    const result = get_booleanflip(flip_op.code());
    opc = result.result;
    flipyes = result.reorder;
    if (opc === OpCode.CPUI_MAX) return 0;
    data.opSetOpcode(flip_op, opc); // Set the negated opcode
    if (flipyes)       // Do we need to reverse the two operands
      data.opSwapInput(flip_op, 0, 1);
    for (const iter of vn.descend) {
      data.opSetOpcode(iter, OpCode.CPUI_COPY); // Remove all the negates
    }
    return 1;
  }
}

// RuleLess2Zero: Simplify INT_LESS applied to extremal constants
//   0 < V  =>  0 != V
//   V < 0  =>  false
//   ffff < V  =>  false
//   V < ffff =>  V != ffff
export class RuleLess2Zero extends Rule {
  constructor(g: string) {
    super(g, 0, "less2zero");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleLess2Zero(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_LESS);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let lvn: Varnode, rvn: Varnode;
    lvn = op.getIn(0)!;
    rvn = op.getIn(1)!;

    if (lvn.isConstant()) {
      if (lvn.getOffset() === 0n) {
        data.opSetOpcode(op, OpCode.CPUI_INT_NOTEQUAL); // All values except 0 are true -> NOT_EQUAL
        return 1;
      }
      else if (lvn.getOffset() === calc_mask(lvn.getSize())) {
        data.opSetOpcode(op, OpCode.CPUI_COPY); // Always false
        data.opRemoveInput(op, 1);
        data.opSetInput(op, data.newConstant(1, 0n), 0);
        return 1;
      }
    }
    else if (rvn.isConstant()) {
      if (rvn.getOffset() === 0n) {
        data.opSetOpcode(op, OpCode.CPUI_COPY); // Always false
        data.opRemoveInput(op, 1);
        data.opSetInput(op, data.newConstant(1, 0n), 0);
        return 1;
      }
      else if (rvn.getOffset() === calc_mask(rvn.getSize())) { // All values except -1 are true -> NOT_EQUAL
        data.opSetOpcode(op, OpCode.CPUI_INT_NOTEQUAL);
        return 1;
      }
    }
    return 0;
  }
}

// RuleLessEqual2Zero: Simplify INT_LESSEQUAL applied to extremal constants
//   0 <= V  =>  true
//   V <= 0  =>  V == 0
//   ffff <= V  =>  ffff == V
//   V <= ffff =>  true
export class RuleLessEqual2Zero extends Rule {
  constructor(g: string) {
    super(g, 0, "lessequal2zero");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleLessEqual2Zero(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_LESSEQUAL);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let lvn: Varnode, rvn: Varnode;
    lvn = op.getIn(0)!;
    rvn = op.getIn(1)!;

    if (lvn.isConstant()) {
      if (lvn.getOffset() === 0n) {
        data.opSetOpcode(op, OpCode.CPUI_COPY); // All values => true
        data.opRemoveInput(op, 1);
        data.opSetInput(op, data.newConstant(1, 1n), 0);
        return 1;
      }
      else if (lvn.getOffset() === calc_mask(lvn.getSize())) {
        data.opSetOpcode(op, OpCode.CPUI_INT_EQUAL); // No value is true except -1
        return 1;
      }
    }
    else if (rvn.isConstant()) {
      if (rvn.getOffset() === 0n) {
        data.opSetOpcode(op, OpCode.CPUI_INT_EQUAL); // No value is true except 0
        return 1;
      }
      else if (rvn.getOffset() === calc_mask(rvn.getSize())) {
        data.opSetOpcode(op, OpCode.CPUI_COPY); // All values => true
        data.opRemoveInput(op, 1);
        data.opSetInput(op, data.newConstant(1, 1n), 0);
        return 1;
      }
    }
    return 0;
  }
}

// RuleSLess2Zero: Simplify INT_SLESS applied to 0 or -1
export class RuleSLess2Zero extends Rule {
  constructor(g: string) {
    super(g, 0, "sless2zero");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSLess2Zero(this.getGroup());
  }

  /// Get the piece containing the sign-bit
  static getHiBit(op: PcodeOp): Varnode | null {
    const opc: OpCode = op.code();
    if ((opc !== OpCode.CPUI_INT_ADD) && (opc !== OpCode.CPUI_INT_OR) && (opc !== OpCode.CPUI_INT_XOR))
      return null;

    const vn1: Varnode = op.getIn(0)!;
    const vn2: Varnode = op.getIn(1)!;
    let mask: bigint = calc_mask(vn1.getSize());
    mask = (mask ^ (mask >> 1n)); // Only high-bit is set
    const nzmask1: bigint = vn1.getNZMask();
    if ((nzmask1 !== mask) && ((nzmask1 & mask) !== 0n)) // If high-bit is set AND some other bit
      return null;
    const nzmask2: bigint = vn2.getNZMask();
    if ((nzmask2 !== mask) && ((nzmask2 & mask) !== 0n))
      return null;

    if (nzmask1 === mask)
      return vn1;
    if (nzmask2 === mask)
      return vn2;
    return null;
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_SLESS);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let lvn: Varnode, rvn: Varnode, coeff: Varnode, avn: Varnode;
    let feedOp: PcodeOp;
    let feedOpCode: OpCode;
    lvn = op.getIn(0)!;
    rvn = op.getIn(1)!;

    if (lvn.isConstant()) {
      if (!rvn.isWritten()) return 0;
      if (lvn.getOffset() === calc_mask(lvn.getSize())) {
        feedOp = rvn.getDef()!;
        feedOpCode = feedOp.code();
        const hibit: Varnode | null = RuleSLess2Zero.getHiBit(feedOp);
        if (hibit !== null) { // Test for -1 s< (hi ^ lo)
          if (hibit.isConstant())
            data.opSetInput(op, data.newConstant(hibit.getSize(), hibit.getOffset()), 1);
          else
            data.opSetInput(op, hibit, 1);
          data.opSetOpcode(op, OpCode.CPUI_INT_EQUAL);
          data.opSetInput(op, data.newConstant(hibit.getSize(), 0n), 0);
          return 1;
        }
        else if (feedOpCode === OpCode.CPUI_SUBPIECE) {
          avn = feedOp.getIn(0)!;
          if (avn.isFree() || avn.getSize() > 8) // Don't create comparison bigger than 8 bytes
            return 0;
          if (BigInt(rvn.getSize()) + feedOp.getIn(1)!.getOffset() === BigInt(avn.getSize())) {
            // We have -1 s< SUB( avn, #hi )
            data.opSetInput(op, avn, 1);
            data.opSetInput(op, data.newConstant(avn.getSize(), calc_mask(avn.getSize())), 0);
            return 1;
          }
        }
        else if (feedOpCode === OpCode.CPUI_INT_NEGATE) {
          // We have -1 s< ~avn
          avn = feedOp.getIn(0)!;
          if (avn.isFree())
            return 0;
          data.opSetInput(op, avn, 0);
          data.opSetInput(op, data.newConstant(avn.getSize(), 0n), 1);
          return 1;
        }
        else if (feedOpCode === OpCode.CPUI_INT_AND) {
          avn = feedOp.getIn(0)!;
          if (avn.isFree() || rvn.loneDescend()! === null)
            return 0;

          const maskVn: Varnode = feedOp.getIn(1)!;
          if (maskVn.isConstant()) {
            let mask: bigint = maskVn.getOffset();
            mask >>= BigInt(8 * avn.getSize() - 1); // Fetch sign-bit
            if ((mask & 1n) !== 0n) {
              // We have -1 s< avn & 0x8...
              data.opSetInput(op, avn, 1);
              return 1;
            }
          }
        }
        else if (feedOpCode === OpCode.CPUI_PIECE) {
          // We have -1 s< CONCAT(V,W)
          avn = feedOp.getIn(0)!; // Most significant piece
          if (avn.isFree())
            return 0;
          data.opSetInput(op, avn, 1);
          data.opSetInput(op, data.newConstant(avn.getSize(), calc_mask(avn.getSize())), 0);
          return 1;
        }
        else if (feedOpCode === OpCode.CPUI_INT_LEFT) {
          coeff = feedOp.getIn(1)!;
          if (!coeff.isConstant() || coeff.getOffset() !== BigInt(lvn.getSize() * 8 - 1))
            return 0;
          avn = feedOp.getIn(0)!;
          if (!avn.isWritten() || !avn.getDef()!.isBoolOutput())
            return 0;
          // We have -1 s< (bool << #8*sz-1)
          data.opSetOpcode(op, OpCode.CPUI_BOOL_NEGATE);
          data.opRemoveInput(op, 1);
          data.opSetInput(op, avn, 0);
          return 1;
        }
      }
    }
    else if (rvn.isConstant()) {
      if (!lvn.isWritten()) return 0;
      if (rvn.getOffset() === 0n) {
        feedOp = lvn.getDef()!;
        feedOpCode = feedOp.code();
        const hibit: Varnode | null = RuleSLess2Zero.getHiBit(feedOp);
        if (hibit !== null) { // Test for (hi ^ lo) s< 0
          if (hibit.isConstant())
            data.opSetInput(op, data.newConstant(hibit.getSize(), hibit.getOffset()), 0);
          else
            data.opSetInput(op, hibit, 0);
          data.opSetOpcode(op, OpCode.CPUI_INT_NOTEQUAL);
          return 1;
        }
        else if (feedOpCode === OpCode.CPUI_SUBPIECE) {
          avn = feedOp.getIn(0)!;
          if (avn.isFree() || avn.getSize() > 8) // Don't create comparison greater than 8 bytes
            return 0;
          if (lvn.getSize() + Number(feedOp.getIn(1)!.getOffset()) === avn.getSize()) {
            // We have SUB( avn, #hi ) s< 0
            data.opSetInput(op, avn, 0);
            data.opSetInput(op, data.newConstant(avn.getSize(), 0n), 1);
            return 1;
          }
        }
        else if (feedOpCode === OpCode.CPUI_INT_NEGATE) {
          // We have ~avn s< 0
          avn = feedOp.getIn(0)!;
          if (avn.isFree()) return 0;
          data.opSetInput(op, avn, 1);
          data.opSetInput(op, data.newConstant(avn.getSize(), calc_mask(avn.getSize())), 0);
          return 1;
        }
        else if (feedOpCode === OpCode.CPUI_INT_AND) {
          avn = feedOp.getIn(0)!;
          if (avn.isFree() || lvn.loneDescend()! === null)
            return 0;
          const maskVn: Varnode = feedOp.getIn(1)!;
          if (maskVn.isConstant()) {
            let mask: bigint = maskVn.getOffset();
            mask >>= BigInt(8 * avn.getSize() - 1); // Fetch sign-bit
            if ((mask & 1n) !== 0n) {
              // We have avn & 0x8... s< 0
              data.opSetInput(op, avn, 0);
              return 1;
            }
          }
        }
        else if (feedOpCode === OpCode.CPUI_PIECE) {
          // We have CONCAT(V,W) s< 0
          avn = feedOp.getIn(0)!; // Most significant piece
          if (avn.isFree())
            return 0;
          data.opSetInput(op, avn, 0);
          data.opSetInput(op, data.newConstant(avn.getSize(), 0n), 1);
          return 1;
        }
      }
    }
    return 0;
  }
}

// RuleEqual2Zero: Simplify INT_EQUAL applied to 0:
//   0 == V + W * -1  =>  V == W  or  0 == V + c  =>  V == -c
// Also applies to INT_NOTEQUAL.
export class RuleEqual2Zero extends Rule {
  constructor(g: string) {
    super(g, 0, "equal2zero");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleEqual2Zero(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_EQUAL);
    oplist.push(OpCode.CPUI_INT_NOTEQUAL);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let vn: Varnode, vn2: Varnode, addvn: Varnode;
    let posvn: Varnode, negvn: Varnode, unnegvn: Varnode;
    let addop: PcodeOp;

    vn = op.getIn(0)!;
    if ((vn.isConstant()) && (vn.getOffset() === 0n))
      addvn = op.getIn(1)!;
    else {
      addvn = vn;
      vn = op.getIn(1)!;
      if ((!vn.isConstant()) || (vn.getOffset() !== 0n))
        return 0;
    }
    for (const boolop of addvn.descend) {
      // make sure the sum is only used in comparisons
      if (!boolop.isBoolOutput()) return 0;
    }
    addop = addvn.getDef()!;
    if (addop === null) return 0;
    if (addop.code() !== OpCode.CPUI_INT_ADD) return 0;
    vn = addop.getIn(0)!;
    vn2 = addop.getIn(1)!;
    if (vn2.isConstant()) {
      const val = new Address(vn2.getSpace()!, uintb_negate(vn2.getOffset() - 1n, vn2.getSize()));
      unnegvn = data.newVarnode(vn2.getSize(), val);
      unnegvn.copySymbolIfValid(vn2); // Propagate any markup
      posvn = vn;
    }
    else {
      if ((vn.isWritten()) && (vn.getDef()!.code() === OpCode.CPUI_INT_MULT)) {
        negvn = vn;
        posvn = vn2;
      }
      else if ((vn2.isWritten()) && (vn2.getDef()!.code() === OpCode.CPUI_INT_MULT)) {
        negvn = vn2;
        posvn = vn;
      }
      else
        return 0;
      let multiplier: bigint;
      if (!negvn.getDef()!.getIn(1)!.isConstant()) return 0;
      unnegvn = negvn.getDef()!.getIn(0)!;
      multiplier = negvn.getDef()!.getIn(1)!.getOffset();
      if (multiplier !== calc_mask(unnegvn.getSize())) return 0;
    }
    if (!posvn.isHeritageKnown()) return 0;
    if (!unnegvn.isHeritageKnown()) return 0;

    data.opSetInput(op, posvn, 0);
    data.opSetInput(op, unnegvn, 1);
    return 1;
  }
}

// RuleEqual2Constant: Simplify INT_EQUAL applied to arithmetic expressions
//   V * -1 == c  =>  V == -c
//   V + c == d  =>  V == (d-c)
//   ~V == c     =>  V == ~c
export class RuleEqual2Constant extends Rule {
  constructor(g: string) {
    super(g, 0, "equal2constant");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleEqual2Constant(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_EQUAL);
    oplist.push(OpCode.CPUI_INT_NOTEQUAL);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const cvn: Varnode = op.getIn(1)!;
    if (!cvn.isConstant()) return 0;

    const lhs: Varnode = op.getIn(0)!;
    if (!lhs.isWritten()) return 0;
    const leftop: PcodeOp = lhs.getDef()!;
    let a: Varnode;
    let newconst: bigint;
    const opc: OpCode = leftop.code();
    if (opc === OpCode.CPUI_INT_ADD) {
      const otherconst: Varnode = leftop.getIn(1)!;
      if (!otherconst.isConstant()) return 0;
      newconst = cvn.getOffset() - otherconst.getOffset();
      newconst &= calc_mask(cvn.getSize());
    }
    else if (opc === OpCode.CPUI_INT_MULT) {
      const otherconst: Varnode = leftop.getIn(1)!;
      if (!otherconst.isConstant()) return 0;
      // The only multiply we transform, is multiply by -1
      if (otherconst.getOffset() !== calc_mask(otherconst.getSize())) return 0;
      newconst = cvn.getOffset();
      newconst = (-newconst) & calc_mask(otherconst.getSize());
    }
    else if (opc === OpCode.CPUI_INT_NEGATE) {
      newconst = cvn.getOffset();
      newconst = (~newconst) & calc_mask(lhs.getSize());
    }
    else
      return 0;

    a = leftop.getIn(0)!;
    if (a.isFree()) return 0;

    // Make sure the transformed form of a is only used
    // in comparisons of similar form
    for (const dop of lhs.descend) {
      if (dop === op) continue;
      if ((dop.code() !== OpCode.CPUI_INT_EQUAL) && (dop.code() !== OpCode.CPUI_INT_NOTEQUAL))
        return 0;
      if (!dop.getIn(1)!.isConstant()) return 0;
    }

    data.opSetInput(op, a, 0);
    data.opSetInput(op, data.newConstant(a.getSize(), newconst), 1);
    return 1;
  }
}

// AddTreeState: Structure for sorting out pointer expression trees.
// Given a base pointer of known data-type and an additive expression involving
// the pointer, group the terms of the expression.
export class AddTreeState {
  private data: Funcdata;
  private baseOp: PcodeOp;
  private ptr: Varnode;
  private ct: TypePointer;
  private baseType: Datatype;
  private pRelType: TypePointerRel | null;
  private ptrsize: number;
  private size: number;
  private baseSlot: number;
  private biggestNonMultCoeff: number;
  private ptrmask: bigint;
  private offset: bigint;
  private correct: bigint;
  private multiple: Varnode[];
  private coeff: bigint[];
  private nonmult: Varnode[];
  private distributeOp: PcodeOp | null;
  private multsum: bigint;
  private nonmultsum: bigint;
  private preventDistribution: boolean;
  private isDistributeUsed: boolean;
  private isSubtype: boolean;
  private valid: boolean;
  private isDegenerate: boolean;

  constructor(d: Funcdata, op: PcodeOp, slot: number) {
    this.data = d;
    this.baseOp = op;
    this.baseSlot = slot;
    this.biggestNonMultCoeff = 0;
    this.ptr = op.getIn(slot)!;
    this.ct = this.ptr.getTypeReadFacing(op) as TypePointer;
    this.ptrsize = this.ptr.getSize();
    this.ptrmask = calc_mask(this.ptrsize);
    this.baseType = this.ct.getPtrTo();
    this.multsum = 0n;
    this.nonmultsum = 0n;
    this.pRelType = null;
    if (this.ct.isFormalPointerRel()) {
      this.pRelType = this.ct as unknown as TypePointerRel;
      this.baseType = this.pRelType.getParent();
      this.nonmultsum = BigInt(this.pRelType.getAddressOffset());
      this.nonmultsum &= this.ptrmask;
    }
    if (this.baseType.isVariableLength())
      this.size = 0; // Open-ended size being pointed to
    else
      this.size = Number(AddrSpace.byteToAddressInt(BigInt(this.baseType.getAlignSize()), this.ct.getWordSize()));
    this.correct = 0n;
    this.offset = 0n;
    this.valid = true;
    this.preventDistribution = false;
    this.isDistributeUsed = false;
    this.isSubtype = false;
    this.distributeOp = null;
    const unitsize: number = Number(AddrSpace.addressToByteInt(1n, this.ct.getWordSize()));
    this.isDegenerate = (this.baseType.getAlignSize() <= unitsize && this.baseType.getAlignSize() > 0);
    this.multiple = [];
    this.coeff = [];
    this.nonmult = [];
  }

  private clear(): void {
    this.multsum = 0n;
    this.nonmultsum = 0n;
    this.biggestNonMultCoeff = 0;
    if (this.pRelType !== null) {
      this.nonmultsum = BigInt((this.ct as unknown as TypePointerRel).getAddressOffset());
      this.nonmultsum &= this.ptrmask;
    }
    this.multiple = [];
    this.coeff = [];
    this.nonmult = [];
    this.correct = 0n;
    this.offset = 0n;
    this.valid = true;
    this.isDistributeUsed = false;
    this.isSubtype = false;
    this.distributeOp = null;
  }

  /// Prepare analysis if there is an alternate form of the base pointer
  initAlternateForm(): boolean {
    if (this.pRelType === null)
      return false;

    this.pRelType = null;
    this.baseType = this.ct.getPtrTo();
    if (this.baseType.isVariableLength())
      this.size = 0;
    else
      this.size = Number(AddrSpace.byteToAddressInt(BigInt(this.baseType.getAlignSize()), this.ct.getWordSize()));
    const unitsize: number = Number(AddrSpace.addressToByteInt(1n, this.ct.getWordSize()));
    this.isDegenerate = (this.baseType.getAlignSize() <= unitsize && this.baseType.getAlignSize() > 0);
    this.preventDistribution = false;
    this.clear();
    return true;
  }

  /// Given an offset into the base data-type and array hints, find sub-component being referenced
  private hasMatchingSubType(off: bigint, arrayHint: number, newoff: { val: bigint }): boolean {
    if (arrayHint === 0) {
      const subOff = { val: 0n };
      const result = this.baseType.getSubType(off, subOff) !== null;
      newoff.val = subOff.val;
      return result;
    }

    const elSizeBefore = { val: 0n };
    const offBefore = { val: 0n };
    const typeBefore: Datatype | null = this.baseType.nearestArrayedComponentBackward(off, offBefore, elSizeBefore);
    if (typeBefore !== null) {
      if (arrayHint === 1 || Number(elSizeBefore.val) === arrayHint) {
        const sizeAddr: bigint = AddrSpace.byteToAddressInt(BigInt(typeBefore.getSize()), this.ct.getWordSize());
        if (offBefore.val >= 0n && offBefore.val < sizeAddr) {
          newoff.val = offBefore.val;
          return true;
        }
      }
    }
    const elSizeAfter = { val: 0n };
    const offAfter = { val: 0n };
    const typeAfter: Datatype | null = this.baseType.nearestArrayedComponentForward(off, offAfter, elSizeAfter);
    if (typeBefore === null && typeAfter === null) {
      const subOff = { val: 0n };
      const result = this.baseType.getSubType(off, subOff) !== null;
      newoff.val = subOff.val;
      return result;
    }
    if (typeBefore === null) {
      newoff.val = offAfter.val;
      return true;
    }
    if (typeAfter === null) {
      newoff.val = offBefore.val;
      return true;
    }

    let distBefore: bigint = (offBefore.val < 0n) ? -offBefore.val : offBefore.val;
    let distAfter: bigint = (offAfter.val < 0n) ? -offAfter.val : offAfter.val;
    if (arrayHint !== 1) {
      if (Number(elSizeBefore.val) !== arrayHint)
        distBefore += 0x1000n;
      if (Number(elSizeAfter.val) !== arrayHint)
        distAfter += 0x1000n;
    }
    newoff.val = (distAfter < distBefore) ? offAfter.val : offBefore.val;
    return true;
  }

  /// Check a INT_MULT element in the add tree
  private checkMultTerm(vn: Varnode, op: PcodeOp, treeCoeff: bigint): boolean {
    const vnconst: Varnode = op.getIn(1)!;
    const vnterm: Varnode = op.getIn(0)!;
    let val: bigint;

    if (vnterm.isFree()) {
      this.valid = false;
      return false;
    }
    if (vnconst.isConstant()) {
      val = (vnconst.getOffset() * treeCoeff) & this.ptrmask;
      let sval: bigint = sign_extend(val, vn.getSize() * 8 - 1);
      const rem: bigint = (this.size === 0) ? sval : sval % BigInt(this.size);
      if (rem !== 0n) {
        if ((val >= BigInt(this.size)) && (this.size !== 0)) {
          this.valid = false; // Size is too big: pointer type must be wrong
          return false;
        }
        if (!this.preventDistribution) {
          if (vnterm.isWritten() && vnterm.getDef()!.code() === OpCode.CPUI_INT_ADD) {
            if (this.distributeOp === null)
              this.distributeOp = op;
            return this.spanAddTree(vnterm.getDef()!, val);
          }
        }
        const vncoeff: number = (sval < 0n) ? Number(-sval) : Number(sval);
        if (vncoeff > this.biggestNonMultCoeff)
          this.biggestNonMultCoeff = vncoeff;
        return true;
      }
      else {
        if (treeCoeff !== 1n)
          this.isDistributeUsed = true;
        this.multiple.push(vnterm);
        this.coeff.push(sval);
        return false;
      }
    }
    if (Number(treeCoeff) > this.biggestNonMultCoeff)
      this.biggestNonMultCoeff = Number(treeCoeff);
    return true;
  }

  /// Accumulate details of given term and continue tree traversal
  private checkTerm(vn: Varnode, treeCoeff: bigint): boolean {
    let val: bigint;
    let def: PcodeOp;

    if (vn === this.ptr) return false;
    if (vn.isConstant()) {
      val = vn.getOffset() * treeCoeff;
      const sval: bigint = sign_extend(val, vn.getSize() * 8 - 1);
      const rem: bigint = (this.size === 0) ? sval : (sval % BigInt(this.size));
      if (rem !== 0n) { // constant is not multiple of size
        if (treeCoeff !== 1n) {
          // An offset "into" the base data-type makes little sense unless it has subcomponents
          if (this.baseType.getMetatype() === type_metatype.TYPE_ARRAY || this.baseType.getMetatype() === type_metatype.TYPE_STRUCT)
            this.isDistributeUsed = true;
        }
        this.nonmultsum += val;
        this.nonmultsum &= this.ptrmask;
        return true;
      }
      if (treeCoeff !== 1n)
        this.isDistributeUsed = true;
      this.multsum += val; // Add multiples of size into multsum
      this.multsum &= this.ptrmask;
      return false;
    }
    if (vn.isWritten()) {
      def = vn.getDef()!;
      if (def.code() === OpCode.CPUI_INT_ADD) // Recurse
        return this.spanAddTree(def, treeCoeff);
      if (def.code() === OpCode.CPUI_COPY) { // Not finished reducing yet
        this.valid = false;
        return false;
      }
      if (def.code() === OpCode.CPUI_INT_MULT) // Check for constant coeff indicating size
        return this.checkMultTerm(vn, def, treeCoeff);
    }
    else if (vn.isFree()) {
      this.valid = false;
      return false;
    }
    if (Number(treeCoeff) > this.biggestNonMultCoeff)
      this.biggestNonMultCoeff = Number(treeCoeff);
    return true;
  }

  /// Walk the given sub-tree accumulating details
  private spanAddTree(op: PcodeOp, treeCoeff: bigint): boolean {
    let one_is_non: boolean, two_is_non: boolean;

    one_is_non = this.checkTerm(op.getIn(0)!, treeCoeff);
    if (!this.valid) return false;
    two_is_non = this.checkTerm(op.getIn(1)!, treeCoeff);
    if (!this.valid) return false;

    if (this.pRelType !== null) {
      if (this.multsum !== 0n || this.nonmultsum >= BigInt(this.size) || this.multiple.length > 0) {
        this.valid = false;
        return false;
      }
    }
    if (one_is_non && two_is_non) return true;
    if (one_is_non)
      this.nonmult.push(op.getIn(0)!);
    if (two_is_non)
      this.nonmult.push(op.getIn(1)!);
    return false; // At least one of the sides contains multiples
  }

  /// Calculate final sub-type offset
  private calcSubtype(): void {
    let tmpoff: bigint = (this.multsum + this.nonmultsum) & this.ptrmask;
    if (this.size === 0 || tmpoff < BigInt(this.size))
      this.offset = tmpoff;
    else {
      let stmpoff: bigint = sign_extend(tmpoff, this.ptrsize * 8 - 1);
      stmpoff = stmpoff % BigInt(this.size);
      if (stmpoff >= 0n)
        this.offset = stmpoff;
      else {
        if (this.baseType.getMetatype() === type_metatype.TYPE_STRUCT && this.biggestNonMultCoeff !== 0 && this.multsum === 0n)
          this.offset = tmpoff;
        else
          this.offset = stmpoff + BigInt(this.size);
      }
    }
    this.correct = this.nonmultsum;
    this.multsum = (tmpoff - this.offset) & this.ptrmask;
    if (this.nonmult.length === 0) {
      if ((this.multsum === 0n) && this.multiple.length === 0) {
        this.valid = false;
        return;
      }
      this.isSubtype = false;
    }
    else if (this.baseType.getMetatype() === type_metatype.TYPE_SPACEBASE) {
      const offsetbytes: bigint = AddrSpace.addressToByteInt(this.offset, this.ct.getWordSize());
      const extra = { val: 0n };
      if (!this.hasMatchingSubType(offsetbytes, this.biggestNonMultCoeff, extra)) {
        this.valid = false;
        return;
      }
      const extraAddr = AddrSpace.byteToAddress(extra.val, this.ct.getWordSize());
      this.offset = (this.offset - extraAddr) & this.ptrmask;
      this.correct = (this.correct - extraAddr) & this.ptrmask;
      this.isSubtype = true;
    }
    else if (this.baseType.getMetatype() === type_metatype.TYPE_STRUCT) {
      const soffset: bigint = sign_extend(this.offset, this.ptrsize * 8 - 1);
      const offsetbytes: bigint = AddrSpace.addressToByteInt(soffset, this.ct.getWordSize());
      const extra = { val: 0n };
      if (!this.hasMatchingSubType(offsetbytes, this.biggestNonMultCoeff, extra)) {
        if (offsetbytes < 0n || offsetbytes >= BigInt(this.baseType.getSize())) {
          this.valid = false;
          return;
        }
        extra.val = 0n; // No field, but pretend there is something there
      }
      const extraAddr = AddrSpace.byteToAddressInt(extra.val, this.ct.getWordSize());
      this.offset = (this.offset - extraAddr) & this.ptrmask;
      this.correct = (this.correct - extraAddr) & this.ptrmask;
      if (this.pRelType !== null && this.offset === BigInt(this.pRelType.getAddressOffset())) {
        if (!this.pRelType.evaluateThruParent(0n)) {
          this.valid = false;
          return;
        }
      }
      this.isSubtype = true;
    }
    else if (this.baseType.getMetatype() === type_metatype.TYPE_ARRAY) {
      this.isSubtype = true;
      this.correct = (this.correct - this.offset) & this.ptrmask;
      this.offset = 0n;
    }
    else {
      // No struct or array, but nonmult is non-empty
      this.valid = false;
    }
    if (this.pRelType !== null) {
      const ptrOff: bigint = BigInt((this.ct as unknown as TypePointerRel).getAddressOffset());
      this.offset = (this.offset - ptrOff) & this.ptrmask;
      this.correct = (this.correct - ptrOff) & this.ptrmask;
    }
  }

  /// Assign a data-type propagated through the given PcodeOp
  private assignPropagatedType(op: PcodeOp): void {
    const vn: Varnode = op.getIn(0)!;
    const inType: Datatype = vn.getTypeReadFacing(op);
    const newType: Datatype | null = op.getOpcode().propagateType(inType, op, vn, op.getOut()!, 0, -1);
    if (newType !== null)
      op.getOut()!.updateType(newType);
  }

  /// Build part of tree that is multiple of base size
  private buildMultiples(): Varnode | null {
    let resNode: Varnode | null;

    // Be sure to preserve sign in division below
    const smultsum: bigint = sign_extend(this.multsum, this.ptrsize * 8 - 1);
    const constCoeff: bigint = (this.size === 0) ? 0n : (smultsum / BigInt(this.size)) & this.ptrmask;
    if (constCoeff === 0n)
      resNode = null;
    else
      resNode = this.data.newConstant(this.ptrsize, constCoeff);
    for (let i = 0; i < this.multiple.length; ++i) {
      const finalCoeff: bigint = (this.size === 0) ? 0n : (this.coeff[i] / BigInt(this.size)) & this.ptrmask;
      let vn: Varnode = this.multiple[i];
      if (finalCoeff !== 1n) {
        const op: PcodeOp = this.data.newOpBefore(this.baseOp, OpCode.CPUI_INT_MULT, vn, this.data.newConstant(this.ptrsize, finalCoeff));
        vn = op.getOut()!;
      }
      if (resNode === null)
        resNode = vn;
      else {
        const op: PcodeOp = this.data.newOpBefore(this.baseOp, OpCode.CPUI_INT_ADD, vn, resNode);
        resNode = op.getOut()!;
      }
    }
    return resNode;
  }

  /// Build part of tree not accounted for by multiples or offset
  private buildExtra(): Varnode | null {
    let resNode: Varnode | null = null;
    for (let i = 0; i < this.nonmult.length; ++i) {
      const vn: Varnode = this.nonmult[i];
      if (vn.isConstant()) {
        this.correct -= vn.getOffset();
        continue;
      }
      if (resNode === null)
        resNode = vn;
      else {
        const op: PcodeOp = this.data.newOpBefore(this.baseOp, OpCode.CPUI_INT_ADD, vn, resNode);
        resNode = op.getOut()!;
      }
    }
    this.correct &= this.ptrmask;
    if (this.correct !== 0n) {
      const vn: Varnode = this.data.newConstant(this.ptrsize, uintb_negate(this.correct - 1n, this.ptrsize));
      if (resNode === null)
        resNode = vn;
      else {
        const op: PcodeOp = this.data.newOpBefore(this.baseOp, OpCode.CPUI_INT_ADD, vn, resNode);
        resNode = op.getOut()!;
      }
    }
    return resNode;
  }

  /// Transform ADD into degenerate PTRADD
  private buildDegenerate(): boolean {
    if (this.baseType.getAlignSize() < this.ct.getWordSize())
      return false; // Don't transform at all
    if (this.baseOp.getOut()!.getTypeDefFacing().getMetatype() !== type_metatype.TYPE_PTR)
      return false;
    const newparams: Varnode[] = [];
    const slot: number = this.baseOp.getSlot(this.ptr);
    newparams.push(this.ptr);
    newparams.push(this.baseOp.getIn(1 - slot)!);
    newparams.push(this.data.newConstant(this.ct.getSize(), 1n));
    this.data.opSetAllInput(this.baseOp, newparams);
    this.data.opSetOpcode(this.baseOp, OpCode.CPUI_PTRADD);
    return true;
  }

  /// Attempt to transform the pointer expression
  apply(): boolean {
    if (this.isDegenerate)
      return this.buildDegenerate();
    this.spanAddTree(this.baseOp, 1n);
    if (!this.valid) return false;
    if (this.distributeOp !== null && !this.isDistributeUsed) {
      this.clear();
      this.preventDistribution = true;
      this.spanAddTree(this.baseOp, 1n);
    }
    this.calcSubtype();
    if (!this.valid) return false;
    while (this.valid && this.distributeOp !== null) {
      if (!this.data.distributeIntMultAdd(this.distributeOp)) {
        this.valid = false;
        break;
      }
      // Collapse any z = (x * #c) * #d expressions produced by the distribute
      this.data.collapseIntMultMult(this.distributeOp.getIn(0)!);
      this.data.collapseIntMultMult(this.distributeOp.getIn(1)!);
      this.clear();
      this.spanAddTree(this.baseOp, 1n);
      if (this.distributeOp !== null && !this.isDistributeUsed) {
        this.clear();
        this.preventDistribution = true;
        this.spanAddTree(this.baseOp, 1n);
      }
      this.calcSubtype();
    }
    if (!this.valid) {
      // Distribution transforms were made
      const s = "Problems distributing in pointer arithmetic at " + this.baseOp.getAddr().printRaw();
      this.data.warningHeader(s);
      return true;
    }
    this.buildTree();
    return true;
  }

  /// Build the transformed ADD tree
  private buildTree(): void {
    let multNode: Varnode | null = this.buildMultiples();
    const extraNode: Varnode | null = this.buildExtra();
    let newop: PcodeOp | null = null;

    // Create PTRADD portion of operation
    if (multNode !== null) {
      newop = this.data.newOpBefore(this.baseOp, OpCode.CPUI_PTRADD, this.ptr, multNode, this.data.newConstant(this.ptrsize, BigInt(this.size)));
      if (this.ptr.getType()!.needsResolution())
        this.data.inheritResolution(this.ptr.getType()!, newop, 0, this.baseOp, this.baseSlot);
      if (this.data.isTypeRecoveryExceeded())
        this.assignPropagatedType(newop);
      multNode = newop.getOut()!;
    }
    else
      multNode = this.ptr; // Zero multiple terms

    // Create PTRSUB portion of operation
    if (this.isSubtype) {
      newop = this.data.newOpBefore(this.baseOp, OpCode.CPUI_PTRSUB, multNode, this.data.newConstant(this.ptrsize, this.offset));
      if (multNode.getType()!.needsResolution())
        this.data.inheritResolution(multNode.getType()!, newop, 0, this.baseOp, this.baseSlot);
      if (this.data.isTypeRecoveryExceeded())
        this.assignPropagatedType(newop);
      if (this.size !== 0)
        newop.setStopTypePropagation();
      multNode = newop.getOut()!;
    }

    // Add back in any remaining terms
    if (extraNode !== null)
      newop = this.data.newOpBefore(this.baseOp, OpCode.CPUI_INT_ADD, multNode, extraNode);

    if (newop === null) {
      this.data.warning("ptrarith problems", this.baseOp.getAddr());
      return;
    }
    this.data.opSetOutput(newop, this.baseOp.getOut()!);
    this.data.opDestroy(this.baseOp);
  }
}

// RulePtrArith: Transform pointer arithmetic
// A string of INT_ADDs is converted into PTRADDs and PTRSUBs.
export class RulePtrArith extends Rule {
  constructor(g: string) {
    super(g, 0, "ptrarith");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RulePtrArith(this.getGroup());
  }

  /// Test for other pointers in the ADD tree above the given op that might be a preferred base
  private static verifyPreferredPointer(op: PcodeOp, slot: number): boolean {
    const vn: Varnode = op.getIn(slot)!;
    if (!vn.isWritten()) return true;
    const preOp: PcodeOp = vn.getDef()!;
    if (preOp.code() !== OpCode.CPUI_INT_ADD) return true;
    let preslot: number = 0;
    if (preOp.getIn(preslot)!.getTypeReadFacing(preOp).getMetatype() !== type_metatype.TYPE_PTR) {
      preslot = 1;
      if (preOp.getIn(preslot)!.getTypeReadFacing(preOp).getMetatype() !== type_metatype.TYPE_PTR)
        return true;
    }
    return (1 !== RulePtrArith.evaluatePointerExpression(preOp, preslot));
  }

  /// Determine if the expression rooted at the given INT_ADD is ready for conversion.
  /// Returns: 0=no action, 1=push needed, 2=conversion can proceed
  static evaluatePointerExpression(op: PcodeOp, slot: number): number {
    let res: number = 1; // Assume we are going to push
    let count: number = 0; // Count descendants
    const ptrBase: Varnode = op.getIn(slot)!;
    if (ptrBase.isFree() && !ptrBase.isConstant())
      return 0;
    if (op.getIn(1 - slot)!.getTypeReadFacing(op).getMetatype() === type_metatype.TYPE_PTR)
      res = 2;
    const outVn: Varnode = op.getOut()!;
    for (const decOp of outVn.descend) {
      count += 1;
      const opc: OpCode = decOp.code();
      if (opc === OpCode.CPUI_INT_ADD) {
        const otherVn: Varnode = decOp.getIn(1 - decOp.getSlot(outVn)!);
        if (otherVn.isFree() && !otherVn.isConstant())
          return 0;
        if (otherVn.getTypeReadFacing(decOp).getMetatype() === type_metatype.TYPE_PTR)
          res = 2;
      }
      else if ((opc === OpCode.CPUI_LOAD || opc === OpCode.CPUI_STORE) && decOp.getIn(1)! === outVn) {
        if (ptrBase.isSpacebase() && (ptrBase.isInput() || (ptrBase.isConstant())) &&
            (op.getIn(1 - slot)!.isConstant()))
          return 0;
        res = 2;
      }
      else {
        res = 2;
      }
    }
    if (count === 0)
      return 0;
    if (count > 1) {
      if (outVn.isSpacebase())
        return 0;
    }
    return res;
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_ADD);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let slot: number;
    let ct: Datatype;

    if (!data.hasTypeRecoveryStarted()) return 0;

    for (slot = 0; slot < op.numInput(); ++slot) {
      ct = op.getIn(slot)!.getTypeReadFacing(op);
      if (ct.getMetatype() === type_metatype.TYPE_PTR) break;
    }
    if (slot === op.numInput()) return 0;
    if (RulePtrArith.evaluatePointerExpression(op, slot) !== 2) return 0;
    if (!RulePtrArith.verifyPreferredPointer(op, slot)) return 0;

    const state = new AddTreeState(data, op, slot);
    if (state.apply()) return 1;
    if (state.initAlternateForm()) {
      if (state.apply()) return 1;
    }
    return 0;
  }
}

// RuleStructOffset0: Convert a LOAD or STORE to the first element of a structure to a PTRSUB
export class RuleStructOffset0 extends Rule {
  constructor(g: string) {
    super(g, 0, "structoffset0");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleStructOffset0(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_LOAD);
    oplist.push(OpCode.CPUI_STORE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let movesize: number;

    if (!data.hasTypeRecoveryStarted()) return 0;
    if (op.code() === OpCode.CPUI_LOAD) {
      movesize = op.getOut()!.getSize();
    }
    else if (op.code() === OpCode.CPUI_STORE) {
      movesize = op.getIn(2)!.getSize();
    }
    else
      return 0;

    const ptrVn: Varnode = op.getIn(1)!;
    const ct: Datatype = ptrVn.getTypeReadFacing(op);
    if (ct.getMetatype() !== type_metatype.TYPE_PTR) return 0;
    let baseType: Datatype = (ct as TypePointer).getPtrTo();
    let offset: bigint;
    if (ct.isFormalPointerRel() && (ct as unknown as TypePointerRel).evaluateThruParent(0n)) {
      const ptRel: TypePointerRel = ct as unknown as TypePointerRel;
      baseType = ptRel.getParent();
      if (baseType.getMetatype() !== type_metatype.TYPE_STRUCT)
        return 0;
      offset = BigInt(ptRel.getByteOffset());
      if (offset >= BigInt(baseType.getSize()))
        return 0;
      if (baseType.getSize() < movesize)
        return 0;
      const newoff = { val: 0n };
      const subType: Datatype | null = baseType.getSubType(offset, newoff);
      if (subType === null) return 0;
      if (subType.getSize() < movesize) return 0;
      const newoffAddr: bigint = AddrSpace.byteToAddress(newoff.val, ptRel.getWordSize());
      offset = (-newoffAddr) & calc_mask(ptrVn.getSize());
      // Create pointer up to parent
      const newop: PcodeOp = data.newOpBefore(op, OpCode.CPUI_PTRSUB, ptrVn, data.newConstant(ptrVn.getSize(), offset));
      if (ptrVn.getType()!.needsResolution())
        data.inheritResolution(ptrVn.getType()!, newop, 0, op, 1);
      newop.setStopTypePropagation();
      if (newoffAddr !== 0n) {
        // Add newoff in to get back to zero total offset
        const addop: PcodeOp = data.newOpBefore(op, OpCode.CPUI_INT_ADD, newop.getOut()!, data.newConstant(ptrVn.getSize(), newoffAddr));
        data.opSetInput(op, addop.getOut()!, 1);
      }
      else {
        data.opSetInput(op, newop.getOut()!, 1);
      }
      return 1;
    }
    offset = 0n;
    if (baseType.getMetatype() === type_metatype.TYPE_STRUCT) {
      if (baseType.getSize() < movesize)
        return 0;
      const offsetRef = { val: offset };
      const subType: Datatype | null = baseType.getSubType(offset, offsetRef);
      offset = offsetRef.val;
      if (subType === null) return 0;
      if (subType.getSize() < movesize) return 0;
    }
    else if (baseType.getMetatype() === type_metatype.TYPE_ARRAY) {
      if (baseType.getSize() < movesize)
        return 0;
      if (baseType.getSize() === movesize) {
        if ((baseType as TypeArray).numElements() !== 1)
          return 0;
      }
    }
    else
      return 0;

    const newop: PcodeOp = data.newOpBefore(op, OpCode.CPUI_PTRSUB, ptrVn, data.newConstant(ptrVn.getSize(), 0n));
    if (ptrVn.getType()!.needsResolution())
      data.inheritResolution(ptrVn.getType()!, newop, 0, op, 1);
    newop.setStopTypePropagation();
    data.opSetInput(op, newop.getOut()!, 1);
    return 1;
  }
}

// RulePushPtr: Push a Varnode with known pointer data-type to the bottom of its additive expression
export class RulePushPtr extends Rule {
  constructor(g: string) {
    super(g, 0, "pushptr");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RulePushPtr(this.getGroup());
  }

  /// Build a duplicate of the given Varnode as an output of a PcodeOp
  private static buildVarnodeOut(vn: Varnode, op: PcodeOp, data: Funcdata): Varnode {
    if (vn.isAddrTied() || vn.getSpace()!.getType() === spacetype.IPTR_INTERNAL)
      return data.newUniqueOut(vn.getSize(), op);
    return data.newVarnodeOut(vn.getSize(), vn.getAddr(), op);
  }

  /// Generate list of PcodeOps that need to be duplicated as part of pushing the pointer
  private static collectDuplicateNeeds(reslist: PcodeOp[], vn: Varnode): void {
    for (;;) {
      if (!vn.isWritten()) return;
      if (vn.isAutoLive()) return;
      if (vn.loneDescend()! === null) return; // Already has multiple descendants
      const op: PcodeOp = vn.getDef()!;
      const opc: OpCode = op.code();
      if (opc === OpCode.CPUI_INT_ZEXT || opc === OpCode.CPUI_INT_SEXT || opc === OpCode.CPUI_INT_2COMP)
        reslist.push(op);
      else if (opc === OpCode.CPUI_INT_MULT) {
        if (op.getIn(1)!.isConstant())
          reslist.push(op);
      }
      else
        return;
      vn = op.getIn(0)!;
    }
  }

  /// Duplicate the given PcodeOp so that the outputs have only 1 descendant
  static duplicateNeed(op: PcodeOp, data: Funcdata): void {
    const outVn: Varnode = op.getOut()!;
    const inVn: Varnode = op.getIn(0)!;
    const num: number = op.numInput();
    const opc: OpCode = op.code();
    let descendants = Array.from(outVn.descend);
    for (const decOp of descendants) {
      if (!outVn.descend.includes(decOp)) continue; // Already removed
      const slot: number = decOp.getSlot(outVn);
      const newOp: PcodeOp = data.newOp(num, op.getAddr());
      const newOut: Varnode = RulePushPtr.buildVarnodeOut(outVn, newOp, data);
      newOut.updateType(outVn.getType()!);
      data.opSetOpcode(newOp, opc);
      data.opSetInput(newOp, inVn, 0);
      if (num > 1)
        data.opSetInput(newOp, op.getIn(1)!, 1);
      data.opSetInput(decOp, newOut, slot);
      data.opInsertBefore(newOp, decOp);
    }
    data.opDestroy(op);
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_ADD);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let slot: number;
    let vni: Varnode | null = null;

    if (!data.hasTypeRecoveryStarted()) return 0;
    for (slot = 0; slot < op.numInput(); ++slot) {
      vni = op.getIn(slot)!;
      if (vni.getTypeReadFacing(op).getMetatype() === type_metatype.TYPE_PTR) break;
    }
    if (slot === op.numInput()) return 0;

    if (RulePtrArith.evaluatePointerExpression(op, slot) !== 1) return 0;
    const vn: Varnode = op.getOut()!;
    const vnadd2: Varnode = op.getIn(1 - slot)!;
    const duplicateList: PcodeOp[] = [];
    if (vn.loneDescend()! === null)
      RulePushPtr.collectDuplicateNeeds(duplicateList, vnadd2);

    const descendants = Array.from(vn.descend);
    for (const decop of descendants) {
      if (!vn.descend.includes(decop)) continue;
      const j: number = decop.getSlot(vn);

      const vnadd1: Varnode = decop.getIn(1 - j)!;
      let newout: Varnode;

      // Create new INT_ADD for the intermediate result
      const newop: PcodeOp = data.newOp(2, decop.getAddr());
      data.opSetOpcode(newop, OpCode.CPUI_INT_ADD);
      newout = data.newUniqueOut(vnadd1.getSize(), newop);

      data.opSetInput(decop, vni!, 0);
      data.opSetInput(decop, newout, 1);

      data.opSetInput(newop, vnadd1, 0);
      data.opSetInput(newop, vnadd2, 1);

      data.opInsertBefore(newop, decop);
    }
    if (!vn.isAutoLive())
      data.opDestroy(op);
    for (let i = 0; i < duplicateList.length; ++i)
      RulePushPtr.duplicateNeed(duplicateList[i], data);

    return 1;
  }
}

// RulePtraddUndo: Remove PTRADD operations with mismatched data-type information
export class RulePtraddUndo extends Rule {
  constructor(g: string) {
    super(g, 0, "ptraddundo");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RulePtraddUndo(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_PTRADD);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (!data.hasTypeRecoveryStarted()) return 0;
    const size: number = Number(op.getIn(2)!.getOffset());
    const basevn: Varnode = op.getIn(0)!;
    const dt: Datatype = basevn.getTypeReadFacing(op);
    if (dt.getMetatype() === type_metatype.TYPE_PTR) {
      const tp: TypePointer = dt as TypePointer;
      if (tp.getPtrTo().getAlignSize() === Number(AddrSpace.addressToByteInt(BigInt(size), tp.getWordSize()))) {
        const indVn: Varnode = op.getIn(1)!;
        if ((!indVn.isConstant()) || (indVn.getOffset() !== 0n))
          return 0;
      }
    }

    data.opUndoPtradd(op, false);
    return 1;
  }
}

// RulePtrsubUndo: Remove PTRSUB operations with mismatched data-type information
export class RulePtrsubUndo extends Rule {
  static readonly DEPTH_LIMIT: number = 8;

  constructor(g: string) {
    super(g, 0, "ptrsubundo");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RulePtrsubUndo(this.getGroup());
  }

  /// Recursively search for additive constants and multiplicative constants
  private static getConstOffsetBack(vn: Varnode, multiplierRef: { value: bigint }, maxLevel: number): bigint {
    multiplierRef.value = 0n;
    const submultiplier = { value: 0n };
    if (vn.isConstant())
      return vn.getOffset();
    if (!vn.isWritten())
      return 0n;
    maxLevel -= 1;
    if (maxLevel < 0)
      return 0n;
    const op: PcodeOp = vn.getDef()!;
    const opc: OpCode = op.code();
    let retval: bigint = 0n;
    if (opc === OpCode.CPUI_INT_ADD) {
      retval += RulePtrsubUndo.getConstOffsetBack(op.getIn(0)!, submultiplier, maxLevel);
      if (submultiplier.value > multiplierRef.value)
        multiplierRef.value = submultiplier.value;
      retval += RulePtrsubUndo.getConstOffsetBack(op.getIn(1)!, submultiplier, maxLevel);
      if (submultiplier.value > multiplierRef.value)
        multiplierRef.value = submultiplier.value;
    }
    else if (opc === OpCode.CPUI_INT_MULT) {
      const cvn: Varnode = op.getIn(1)!;
      if (!cvn.isConstant()) return 0n;
      multiplierRef.value = cvn.getOffset();
      RulePtrsubUndo.getConstOffsetBack(op.getIn(0)!, submultiplier, maxLevel);
      if (submultiplier.value > 0n)
        multiplierRef.value *= submultiplier.value;
    }
    return retval;
  }

  /// Collect constants and the biggest multiplier in the given PTRSUB expression
  private static getExtraOffset(op: PcodeOp, multiplierRef: { value: bigint }): bigint {
    let extra: bigint = 0n;
    multiplierRef.value = 0n;
    const submultiplier = { value: 0n };
    let outvn: Varnode = op.getOut()!;
    let curOp: PcodeOp | null = outvn.loneDescend()!;
    while (curOp !== null) {
      const opc: OpCode = curOp.code();
      if (opc === OpCode.CPUI_INT_ADD) {
        const slot: number = curOp.getSlot(outvn);
        extra += RulePtrsubUndo.getConstOffsetBack(curOp.getIn(1 - slot)!, submultiplier, RulePtrsubUndo.DEPTH_LIMIT);
        if (submultiplier.value > multiplierRef.value)
          multiplierRef.value = submultiplier.value;
      }
      else if (opc === OpCode.CPUI_PTRSUB) {
        extra += curOp.getIn(1)!.getOffset();
      }
      else if (opc === OpCode.CPUI_PTRADD) {
        if (curOp.getIn(0)! !== outvn) break;
        let ptraddmult: bigint = curOp.getIn(2)!.getOffset();
        const invn: Varnode = curOp.getIn(1)!;
        if (invn.isConstant())
          extra += ptraddmult * invn.getOffset();
        RulePtrsubUndo.getConstOffsetBack(invn, submultiplier, RulePtrsubUndo.DEPTH_LIMIT);
        if (submultiplier.value !== 0n)
          ptraddmult *= submultiplier.value;
        if (ptraddmult > multiplierRef.value)
          multiplierRef.value = ptraddmult;
      }
      else {
        break;
      }
      outvn = curOp.getOut()!;
      curOp = outvn.loneDescend()!;
    }
    extra = sign_extend(extra, 8 * outvn.getSize() - 1);
    return extra;
  }

  /// Remove any constants in the additive expression rooted at the given PcodeOp
  private static removeLocalAddRecurse(op: PcodeOp, slot: number, maxLevel: number, data: Funcdata): bigint {
    const vn: Varnode = op.getIn(slot)!;
    if (!vn.isWritten())
      return 0n;
    if (vn.loneDescend()! !== op)
      return 0n;
    maxLevel -= 1;
    if (maxLevel < 0)
      return 0n;
    const defOp: PcodeOp = vn.getDef()!;
    let retval: bigint = 0n;
    if (defOp.code() === OpCode.CPUI_INT_ADD) {
      if (defOp.getIn(1)!.isConstant()) {
        retval += defOp.getIn(1)!.getOffset();
        data.opRemoveInput(defOp, 1);
        data.opSetOpcode(defOp, OpCode.CPUI_COPY);
      }
      else {
        retval += RulePtrsubUndo.removeLocalAddRecurse(defOp, 0, maxLevel, data);
        retval += RulePtrsubUndo.removeLocalAddRecurse(defOp, 1, maxLevel, data);
      }
    }
    return retval;
  }

  /// Remove constants in the additive expression involving the given Varnode
  private static removeLocalAdds(vn: Varnode, data: Funcdata): bigint {
    let extra: bigint = 0n;
    let curOp: PcodeOp | null = vn.loneDescend()!;
    while (curOp !== null) {
      const opc: OpCode = curOp.code();
      if (opc === OpCode.CPUI_INT_ADD) {
        const slot: number = curOp.getSlot(vn);
        if (slot === 0 && curOp.getIn(1)!.isConstant()) {
          extra += curOp.getIn(1)!.getOffset();
          data.opRemoveInput(curOp, 1);
          data.opSetOpcode(curOp, OpCode.CPUI_COPY);
        }
        else {
          extra += RulePtrsubUndo.removeLocalAddRecurse(curOp, 1 - slot, RulePtrsubUndo.DEPTH_LIMIT, data);
        }
      }
      else if (opc === OpCode.CPUI_PTRSUB) {
        extra += curOp.getIn(1)!.getOffset();
        curOp.clearStopTypePropagation();
        data.opRemoveInput(curOp, 1);
        data.opSetOpcode(curOp, OpCode.CPUI_COPY);
      }
      else if (opc === OpCode.CPUI_PTRADD) {
        if (curOp.getIn(0)! !== vn) break;
        const ptraddmult: bigint = curOp.getIn(2)!.getOffset();
        const invn: Varnode = curOp.getIn(1)!;
        if (invn.isConstant()) {
          extra += ptraddmult * invn.getOffset();
          data.opRemoveInput(curOp, 2);
          data.opRemoveInput(curOp, 1);
          data.opSetOpcode(curOp, OpCode.CPUI_COPY);
        }
        else {
          data.opUndoPtradd(curOp, false);
          extra += RulePtrsubUndo.removeLocalAddRecurse(curOp, 1, RulePtrsubUndo.DEPTH_LIMIT, data);
        }
      }
      else {
        break;
      }
      vn = curOp.getOut()!;
      curOp = vn.loneDescend()!;
    }
    return extra;
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_PTRSUB);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (!data.hasTypeRecoveryStarted()) return 0;

    const basevn: Varnode = op.getIn(0)!;
    const cvn: Varnode = op.getIn(1)!;
    let val: bigint = cvn.getOffset();
    const multiplierRef = { value: 0n };
    let extra: bigint = RulePtrsubUndo.getExtraOffset(op, multiplierRef);
    if (basevn.getTypeReadFacing(op).isPtrsubMatching(val, extra, multiplierRef.value))
      return 0;

    data.opSetOpcode(op, OpCode.CPUI_INT_ADD);
    op.clearStopTypePropagation();
    extra = RulePtrsubUndo.removeLocalAdds(op.getOut()!, data);
    if (extra !== 0n) {
      val = val + extra;
      data.opSetInput(op, data.newConstant(cvn.getSize(), val & calc_mask(cvn.getSize())), 1);
    }
    return 1;
  }
}

// Clean up rules

// RuleMultNegOne: Convert INT_2COMP from INT_MULT:  V * -1  =>  -V
export class RuleMultNegOne extends Rule {
  constructor(g: string) {
    super(g, 0, "multnegone");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleMultNegOne(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_MULT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const constvn: Varnode = op.getIn(1)!;

    if (!constvn.isConstant()) return 0;
    if (constvn.getOffset() !== calc_mask(constvn.getSize())) return 0;

    data.opSetOpcode(op, OpCode.CPUI_INT_2COMP);
    data.opRemoveInput(op, 1);
    return 1;
  }
}

// RuleAddUnsigned: Convert INT_ADD of constants to INT_SUB:  V + 0xff...  =>  V - 0x00...
export class RuleAddUnsigned extends Rule {
  constructor(g: string) {
    super(g, 0, "addunsigned");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleAddUnsigned(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_ADD);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const constvn: Varnode = op.getIn(1)!;

    if (!constvn.isConstant()) return 0;
    const dt: Datatype = constvn.getTypeReadFacing(op);
    if (dt.getMetatype() !== type_metatype.TYPE_UINT) return 0;
    if (dt.isCharPrint()) return 0; // Only change integer forms
    const val: bigint = constvn.getOffset();
    const mask: bigint = calc_mask(constvn.getSize());
    const sa: number = constvn.getSize() * 6; // 1/4 less than full bitsize
    const quarter: bigint = (mask >> BigInt(sa)) << BigInt(sa);
    if ((val & quarter) !== quarter) return 0; // The first quarter of bits must all be 1's
    if (constvn.getSymbolEntry() !== null) {
      const sym = constvn.getSymbolEntry()!.getSymbol();
      if (sym instanceof EquateSymbol) {
        if (sym.isNameLocked())
          return 0; // Don't transform a named equate
      }
    }
    const negatedVal: bigint = (-val) & mask;
    if (dt.isEnumType()) {
      const enumType: TypeEnum = dt as TypeEnum;
      if (!enumType.hasNamedValue(negatedVal) && enumType.hasNamedValue((~val) & mask))
        return 0;
    }
    data.opSetOpcode(op, OpCode.CPUI_INT_SUB);
    const cvn: Varnode = data.newConstant(constvn.getSize(), negatedVal);
    cvn.copySymbol(constvn);
    data.opSetInput(op, cvn, 1);
    return 1;
  }
}

// Rule2Comp2Sub: Convert INT_ADD back to INT_SUB:  V + -W  ==>  V - W
export class Rule2Comp2Sub extends Rule {
  constructor(g: string) {
    super(g, 0, "2comp2sub");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new Rule2Comp2Sub(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_2COMP);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const addop: PcodeOp | null = op.getOut()!.loneDescend()!;
    if (addop === null) return 0;
    if (addop.code() !== OpCode.CPUI_INT_ADD) return 0;
    if (addop.getIn(0)! === op.getOut()!)
      data.opSetInput(addop, addop.getIn(1)!, 0);
    data.opSetInput(addop, op.getIn(0)!, 1);
    data.opSetOpcode(addop, OpCode.CPUI_INT_SUB);
    data.opDestroy(op); // Completely remove 2COMP
    return 1;
  }
}

// RuleSubRight: Convert truncation to cast:  sub(V,c)  =>  sub(V>>c*8,0)
export class RuleSubRight extends Rule {
  constructor(g: string) {
    super(g, 0, "subright");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSubRight(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_SUBPIECE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (op.doesSpecialPrinting())
      return 0;
    if (op.getIn(0)!.getTypeReadFacing(op).isPieceStructured()) {
      data.opMarkSpecialPrint(op); // Print this as a field extraction
      return 0;
    }

    let c: number = Number(op.getIn(1)!.getOffset());
    if (c === 0) return 0; // SUBPIECE is not least sig
    const a: Varnode = op.getIn(0)!;
    const outvn: Varnode = op.getOut()!;
    if (outvn.isAddrTied() && a.isAddrTied()) {
      if (outvn.overlapVarnode(a) === c) // This SUBPIECE should get converted to a marker by ActionCopyMarker
        return 0;
    }
    let opc: OpCode = OpCode.CPUI_INT_RIGHT; // Default shift type
    let d: number = c * 8; // Convert to bit shift
    // Search for lone right shift descendant
    let lone: PcodeOp | null = outvn.loneDescend()!;
    if (lone !== null) {
      const opc2: OpCode = lone.code();
      if ((opc2 === OpCode.CPUI_INT_RIGHT) || (opc2 === OpCode.CPUI_INT_SRIGHT)) {
        if (lone.getIn(1)!.isConstant()) { // Shift by constant
          if (outvn.getSize() + c === a.getSize()) {
            // If SUB is "hi" lump the SUB and shift together
            d += Number(lone.getIn(1)!.getOffset());
            if (d >= a.getSize() * 8) {
              if (opc2 === OpCode.CPUI_INT_RIGHT)
                return 0; // Result should have been 0
              d = a.getSize() * 8 - 1; // sign extraction
            }
            data.opUnlink(op);
            op = lone;
            data.opSetOpcode(op, OpCode.CPUI_SUBPIECE);
            opc = opc2;
          }
        }
      }
    }
    // Create shift BEFORE the SUBPIECE happens
    let ct: Datatype;
    if (opc === OpCode.CPUI_INT_RIGHT)
      ct = data.getArch().types.getBase(a.getSize(), type_metatype.TYPE_UINT);
    else
      ct = data.getArch().types.getBase(a.getSize(), type_metatype.TYPE_INT);
    const shiftop: PcodeOp = data.newOp(2, op.getAddr());
    data.opSetOpcode(shiftop, opc);
    const newout: Varnode = data.newUnique(a.getSize(), ct);
    data.opSetOutput(shiftop, newout);
    data.opSetInput(shiftop, a, 0);
    data.opSetInput(shiftop, data.newConstant(4, BigInt(d)), 1);
    data.opInsertBefore(shiftop, op);

    // Change SUBPIECE into a least sig SUBPIECE
    data.opSetInput(op, newout, 0);
    data.opSetInput(op, data.newConstant(4, 0n), 1);
    return 1;
  }
}

// =====================================================================
// PART 5: Rule classes from ruleaction.cc lines ~7300-9100
// =====================================================================

// RulePtrsubCharConstant
export class RulePtrsubCharConstant extends Rule {
  constructor(g: string) {
    super(g, 0, "ptrsubcharconstant");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RulePtrsubCharConstant(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_PTRSUB);
  }

  /// Try to push constant pointer further
  ///
  /// Given a PTRSUB has been collapsed to a constant COPY of a string address,
  /// try to collapse descendant any PTRADD.
  private pushConstFurther(data: Funcdata, outtype: TypePointer, op: PcodeOp, slot: number, val: bigint): boolean {
    if (op.code() !== OpCode.CPUI_PTRADD) return false;  // Must be a PTRADD
    if (slot !== 0) return false;
    const vn: Varnode = op.getIn(1)!;
    if (!vn.isConstant()) return false;  // that is adding a constant
    let addval: bigint = vn.getOffset();
    addval *= op.getIn(2)!.getOffset();
    val += addval;
    const newconst: Varnode = data.newConstant(vn.getSize(), val);
    newconst.updateType(outtype);  // Put the pointer datatype on new constant
    data.opRemoveInput(op, 2);
    data.opRemoveInput(op, 1);
    data.opSetOpcode(op, OpCode.CPUI_COPY);
    data.opSetInput(op, newconst, 0);
    return true;
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const sb: Varnode = op.getIn(0)!;
    const sbType: Datatype = sb.getTypeReadFacing(op);
    if (sbType.getMetatype() !== type_metatype.TYPE_PTR) return 0;
    const dt: Datatype = (sbType as TypePointer).getPtrTo();
    if (dt.getMetatype() !== type_metatype.TYPE_SPACEBASE) return 0;
    const sbtype: TypeSpacebase = dt as TypeSpacebase;
    const vn1: Varnode = op.getIn(1)!;
    if (!vn1.isConstant()) return 0;
    const outvn: Varnode = op.getOut()!;
    const outtype: TypePointer = outvn.getTypeDefFacing() as TypePointer;
    if (outtype.getMetatype() !== type_metatype.TYPE_PTR) return 0;
    const basetype: Datatype = outtype.getPtrTo();
    if (!basetype.isCharPrint()) return 0;
    const symaddr: Address = sbtype.getAddress(vn1.getOffset(), vn1.getSize(), op.getAddr());
    const scope: Scope = sbtype.getMap();
    if (!scope.isReadOnly(symaddr, 1, op.getAddr()))
      return 0;
    // Check if data at the address looks like a string
    if (!data.getArch().stringManager!.isString(symaddr, basetype))
      return 0;

    // If we reach here, the PTRSUB should be converted to a (COPY of a) pointer constant.
    let removeCopy: boolean = false;
    if (!outvn.isAddrForce()) {
      removeCopy = true;  // Assume we can remove, unless we can't propagate to all descendants
      const descendsCopy = outvn.descend.slice();
      for (let _di = 0; _di < descendsCopy.length; _di++) {
        const subop: PcodeOp = descendsCopy[_di];
        if (!this.pushConstFurther(data, outtype, subop, subop.getSlot(outvn), vn1.getOffset()))
          removeCopy = false;  // If the descendant does NOT propagate const, do NOT remove op
      }
    }
    if (removeCopy) {
      data.opDestroy(op);
    }
    else {  // Convert the original PTRSUB to a COPY of the constant
      const newvn: Varnode = data.newConstant(outvn.getSize(), vn1.getOffset());
      newvn.updateType(outtype);
      data.opRemoveInput(op, 1);
      data.opSetInput(op, newvn, 0);
      data.opSetOpcode(op, OpCode.CPUI_COPY);
    }
    return 1;
  }
}

// RuleExtensionPush
export class RuleExtensionPush extends Rule {
  constructor(g: string) {
    super(g, 0, "extensionpush");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleExtensionPush(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_ZEXT);
    oplist.push(OpCode.CPUI_INT_SEXT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const inVn: Varnode = op.getIn(0)!;
    if (inVn.isConstant()) return 0;
    if (inVn.isAddrForce()) return 0;
    if (inVn.isAddrTied()) return 0;
    const outVn: Varnode = op.getOut()!;
    if (outVn.isTypeLock() || outVn.isNameLock()) return 0;
    if (outVn.isAddrForce() || outVn.isAddrTied()) return 0;
    let addcount: number = 0;    // Number of INT_ADD descendants
    let ptrcount: number = 0;    // Number of PTRADD descendants
    for (let iter = outVn.beginDescend(); iter < outVn.endDescend(); iter++) {
      const decOp: PcodeOp = outVn.getDescend(iter);
      const opc: OpCode = decOp.code();
      if (opc === OpCode.CPUI_PTRADD) {
        // This extension will likely be hidden
        ptrcount += 1;
      }
      else if (opc === OpCode.CPUI_INT_ADD) {
        const subOp: PcodeOp | null = decOp.getOut()!.loneDescend()!;
        if (subOp === null || subOp.code() !== OpCode.CPUI_PTRADD)
          return 0;
        addcount += 1;
      }
      else {
        return 0;
      }
    }
    if ((addcount + ptrcount) <= 1) return 0;
    if (addcount > 0) {
      if (op.getIn(0)!.loneDescend()! !== null) return 0;
    }
    RulePushPtr.duplicateNeed(op, data);  // Duplicate the extension to all result descendants
    return 1;
  }
}

// RulePieceStructure
export class RulePieceStructure extends Rule {
  constructor(g: string) {
    super(g, 0, "piecestructure");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RulePieceStructure(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_PIECE);
    oplist.push(OpCode.CPUI_INT_ZEXT);
  }

  /// Find the base structure or array data-type that the given Varnode is part of
  static determineDatatype(vn: Varnode, baseOffset: { val: number }): Datatype | null {
    const ct: Datatype | null = vn.getStructuredType();
    if (ct === null)
      return ct;

    if (ct.getSize() !== vn.getSize()) {  // vn is a partial
      const entry: SymbolEntry = vn.getSymbolEntry()!;
      baseOffset.val = vn.getAddr().overlap(0, entry.getAddr(), ct.getSize());
      if (baseOffset.val < 0)
        return null;
      baseOffset.val += entry.getOffset();
      // Find concrete sub-type that matches the size of the Varnode
      let subType: Datatype | null = ct;
      let subOffset: { val: bigint } = { val: BigInt(baseOffset.val) };
      while (subType !== null && subType.getSize() > vn.getSize()) {
        subType = subType.getSubType(subOffset.val, subOffset);
      }
      if (subType !== null && subType.getSize() === vn.getSize() && subOffset.val === 0n) {
        // If there is a concrete sub-type
        if (!subType.isPieceStructured())  // and the concrete sub-type is not a structured type itself
          return null;  // don't split out CONCAT forming the sub-type
      }
    }
    else {
      baseOffset.val = 0;
    }
    return ct;
  }

  /// For a structured data-type, determine if the given range spans multiple elements
  static spanningRange(ct: Datatype, offset: number, size: number): boolean {
    if (offset + size > ct.getSize()) return false;
    let newOff: { val: bigint } = { val: BigInt(offset) };
    for (;;) {
      ct = ct.getSubType(newOff.val, newOff)!;
      if (ct === null) return true;  // Don't know what it spans, assume multiple
      if (Number(newOff.val) + size > ct.getSize()) return true;  // Spans more than 1
      if (!ct.isPieceStructured()) break;
    }
    return false;
  }

  /// Convert an INT_ZEXT operation to a PIECE with a zero constant as the first parameter
  static convertZextToPiece(zext: PcodeOp, ct: Datatype, offset: number, data: Funcdata): boolean {
    const outvn: Varnode = zext.getOut()!;
    const invn: Varnode = zext.getIn(0)!;
    if (invn.isConstant()) return false;
    const sz: number = outvn.getSize() - invn.getSize();
    if (sz > 8) return false;  // sizeof(uintb) == 8 in bigint context
    offset += outvn.getSpace()!.isBigEndian() ? 0 : invn.getSize();
    let newOff: { val: bigint } = { val: BigInt(offset) };
    while (ct !== null && ct.getSize() > sz) {
      ct = ct.getSubType(newOff.val, newOff)!;
    }
    const zerovn: Varnode = data.newConstant(sz, 0n);
    if (ct !== null && ct.getSize() === sz)
      zerovn.updateType(ct);
    data.opSetOpcode(zext, OpCode.CPUI_PIECE);
    data.opInsertInput(zext, zerovn, 0);
    if (invn.getType().needsResolution())
      data.inheritResolution(invn.getType(), zext, 1, zext, 0);  // Transfer invn's resolution to slot 1
    return true;
  }

  /// Search for leaves in the CONCAT tree defined by an INT_ZEXT operation and convert them to PIECE
  static findReplaceZext(stack: PieceNode[], structuredType: Datatype, data: Funcdata): boolean {
    let change: boolean = false;
    for (let i = 0; i < stack.length; ++i) {
      const node: PieceNode = stack[i];
      if (!node.isLeafNode()) continue;
      const vn: Varnode = node.getVarnode();
      if (!vn.isWritten()) continue;
      const op: PcodeOp = vn.getDef()!;
      if (op.code() !== OpCode.CPUI_INT_ZEXT) continue;
      if (!RulePieceStructure.spanningRange(structuredType, node.getTypeOffset(), vn.getSize())) continue;
      if (RulePieceStructure.convertZextToPiece(op, structuredType, node.getTypeOffset(), data))
        change = true;
    }
    return change;
  }

  /// Return true if the two given root and leaf should be part of different symbols
  static separateSymbol(root: Varnode, leaf: Varnode): boolean {
    if (root.getSymbolEntry() !== leaf.getSymbolEntry()) return true;  // Forced to be different symbols
    if (root.isAddrTied()) return false;
    if (!leaf.isWritten()) return true;  // Assume to be different symbols
    if (leaf.isProtoPartial()) return true;  // Already in another tree
    const op: PcodeOp = leaf.getDef()!;
    if (op.isMarker()) return true;  // Leaf is not defined locally
    if (op.code() !== OpCode.CPUI_PIECE) return false;
    if (leaf.getType().isPieceStructured()) return true;  // Would be a separate root

    return false;
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (op.isPartialRoot()) return 0;  // Check if CONCAT tree already been visited
    let outvn: Varnode = op.getOut()!;
    const baseOffset: { val: number } = { val: 0 };
    const ct: Datatype | null = RulePieceStructure.determineDatatype(outvn, baseOffset);
    if (ct === null) return 0;

    if (op.code() === OpCode.CPUI_INT_ZEXT) {
      if (RulePieceStructure.convertZextToPiece(op, outvn.getType(), 0, data))
        return 1;
      return 0;
    }
    // Check if outvn is really the root of the tree
    const zext: PcodeOp | null = outvn.loneDescend()!;
    if (zext !== null) {
      if (zext.code() === OpCode.CPUI_PIECE)
        return 0;  // More PIECEs below us, not a root
      if (zext.code() === OpCode.CPUI_INT_ZEXT) {
        // Extension of a structured data-type, convert extension to PIECE first
        if (RulePieceStructure.convertZextToPiece(zext, zext.getOut()!.getType(), 0, data))
          return 1;
        return 0;
      }
    }

    let stack: PieceNode[] = [];
    for (;;) {
      PieceNode.gatherPieces(stack, outvn, op, baseOffset.val, baseOffset.val);
      if (!RulePieceStructure.findReplaceZext(stack, ct, data))  // Check for INT_ZEXT leaves that need to be converted to PIECEs
        break;
      stack = [];  // If we found some, regenerate the tree
    }

    op.setPartialRoot();
    let anyAddrTied: boolean = outvn.isAddrTied();
    const baseAddr: Address = outvn.getAddr().subtract(BigInt(baseOffset.val));
    for (let i = 0; i < stack.length; ++i) {
      const node: PieceNode = stack[i];
      const vn: Varnode = node.getVarnode();
      let addr: Address = baseAddr.add(BigInt(node.getTypeOffset()));
      addr.renormalize(vn.getSize());  // Allow for possible join address
      if (vn.getAddr().equals(addr)) {
        if (!node.isLeafNode() || !RulePieceStructure.separateSymbol(outvn, vn)) {
          // Varnode already has correct address and will be part of the same symbol as root
          // so we don't need to change the storage or insert a COPY
          if (!vn.isAddrTied() && !vn.isProtoPartial()) {
            vn.setProtoPartial();
          }
          anyAddrTied = anyAddrTied || vn.isAddrTied();
          continue;
        }
      }
      if (node.isLeafNode()) {
        const copyOp: PcodeOp = data.newOp(1, node.getOp().getAddr());
        const newVn: Varnode = data.newVarnodeOut(vn.getSize(), addr, copyOp);
        anyAddrTied = anyAddrTied || newVn.isAddrTied();  // Its possible newVn is addrtied, even if vn isn't
        let newType: Datatype | null = data.getArch().types!.getExactPiece(ct, node.getTypeOffset(), vn.getSize());
        if (newType === null)
          newType = vn.getType();
        newVn.updateType(newType);
        data.opSetOpcode(copyOp, OpCode.CPUI_COPY);
        data.opSetInput(copyOp, vn, 0);
        data.opSetInput(node.getOp(), newVn, node.getSlot());
        data.opInsertBefore(copyOp, node.getOp());
        if (vn.getType().needsResolution()) {
          // Inherit PIECE's read resolution for COPY's read
          data.inheritResolution(vn.getType(), copyOp, 0, node.getOp(), node.getSlot());
        }
        if (newType!.needsResolution()) {
          newType!.resolveInFlow(copyOp, -1);  // If the piece represents part of a union, resolve it
        }
        if (!newVn.isAddrTied())
          newVn.setProtoPartial();
      }
      else {
        // Reaching here we know vn is NOT addrtied and has a lone descendant
        // We completely replace the Varnode with one having the correct storage
        const defOp: PcodeOp = vn.getDef()!;
        const loneOp: PcodeOp = vn.loneDescend()!;
        const slot: number = loneOp.getSlot(vn);
        const newVn: Varnode = data.newVarnode(vn.getSize(), addr, vn.getType());
        data.opSetOutput(defOp, newVn);
        data.opSetInput(loneOp, newVn, slot);
        data.deleteVarnode(vn);
        if (!newVn.isAddrTied())
          newVn.setProtoPartial();
      }
    }
    if (!anyAddrTied)
      data.getMerge().registerProtoPartialRoot(outvn);
    return 1;
  }
}

// RuleSubNormal - Pull-back SUBPIECE through INT_RIGHT and INT_SRIGHT
export class RuleSubNormal extends Rule {
  constructor(g: string) {
    super(g, 0, "subnormal");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSubNormal(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_SUBPIECE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const shiftout: Varnode = op.getIn(0)!;
    if (!shiftout.isWritten()) return 0;
    const shiftop: PcodeOp = shiftout.getDef()!;
    let opc: OpCode = shiftop.code();
    if ((opc !== OpCode.CPUI_INT_RIGHT) && (opc !== OpCode.CPUI_INT_SRIGHT))
      return 0;
    if (!shiftop.getIn(1)!.isConstant()) return 0;
    const a: Varnode = shiftop.getIn(0)!;
    if (a.isFree()) return 0;
    const outvn: Varnode = op.getOut()!;
    if (outvn.isPrecisHi() || outvn.isPrecisLo()) return 0;
    let n: number = Number(shiftop.getIn(1)!.getOffset());
    let c: number = Number(op.getIn(1)!.getOffset());
    let k: number = Math.floor(n / 8);
    const insize: number = a.getSize();
    const outsize: number = outvn.getSize();

    // Total shift + outsize must be greater equal to size of input
    if ((n + 8 * c + 8 * outsize < 8 * insize) && (n !== k * 8)) return 0;

    // If totalcut + remain > original input
    if (k + c + outsize > insize) {
      const truncSize: number = insize - c - k;
      if (n === k * 8 && truncSize > 0 && popcount(BigInt(truncSize)) === 1) {
        // We need an additional extension
        c += k;
        const newop: PcodeOp = data.newOp(2, op.getAddr());
        opc = (opc === OpCode.CPUI_INT_SRIGHT) ? OpCode.CPUI_INT_SEXT : OpCode.CPUI_INT_ZEXT;
        data.opSetOpcode(newop, OpCode.CPUI_SUBPIECE);
        data.newUniqueOut(truncSize, newop);
        data.opSetInput(newop, a, 0);
        data.opSetInput(newop, data.newConstant(4, BigInt(c)), 1);
        data.opInsertBefore(newop, op);

        data.opSetInput(op, newop.getOut()!, 0);
        data.opRemoveInput(op, 1);
        data.opSetOpcode(op, opc);
        return 1;
      }
      else
        k = insize - c - outsize;  // Or we can shrink the cut
    }

    // if n == k*8, then a shift is unnecessary
    c += k;
    n -= k * 8;
    if (n === 0) {  // Extra shift is unnecessary
      data.opSetInput(op, a, 0);
      data.opSetInput(op, data.newConstant(4, BigInt(c)), 1);
      return 1;
    }
    else if (n >= outsize * 8) {
      n = outsize * 8;  // Can only shift so far
      if (opc === OpCode.CPUI_INT_SRIGHT)
        n -= 1;
    }

    const newop: PcodeOp = data.newOp(2, op.getAddr());
    data.opSetOpcode(newop, OpCode.CPUI_SUBPIECE);
    data.newUniqueOut(outsize, newop);
    data.opSetInput(newop, a, 0);
    data.opSetInput(newop, data.newConstant(4, BigInt(c)), 1);
    data.opInsertBefore(newop, op);

    data.opSetInput(op, newop.getOut()!, 0);
    data.opSetInput(op, data.newConstant(4, BigInt(n)), 1);
    data.opSetOpcode(op, opc);
    return 1;
  }
}

// RulePositiveDiv - Signed division of positive values is unsigned division
export class RulePositiveDiv extends Rule {
  constructor(g: string) {
    super(g, 0, "positivediv");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RulePositiveDiv(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_SDIV);
    oplist.push(OpCode.CPUI_INT_SREM);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let sa: number = op.getOut()!.getSize();
    if (sa > 8) return 0;  // sizeof(uintb) = 8
    sa = sa * 8 - 1;
    if (((op.getIn(0)!.getNZMask() >> BigInt(sa)) & 1n) !== 0n)
      return 0;  // Input 0 may be negative
    if (((op.getIn(1)!.getNZMask() >> BigInt(sa)) & 1n) !== 0n)
      return 0;  // Input 1 may be negative
    const opc: OpCode = (op.code() === OpCode.CPUI_INT_SDIV) ? OpCode.CPUI_INT_DIV : OpCode.CPUI_INT_REM;
    data.opSetOpcode(op, opc);
    return 1;
  }
}

// RuleDivTermAdd - Simplify expressions associated with optimized division expressions
export class RuleDivTermAdd extends Rule {
  constructor(g: string) {
    super(g, 0, "divtermadd");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleDivTermAdd(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_SUBPIECE);
    oplist.push(OpCode.CPUI_INT_RIGHT);
    oplist.push(OpCode.CPUI_INT_SRIGHT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const nRef: { val: number } = { val: 0 };
    const shiftopcRef: { val: OpCode } = { val: OpCode.CPUI_MAX };
    const subop: PcodeOp | null = RuleDivTermAdd.findSubshift(op, nRef, shiftopcRef);
    if (subop === null) return 0;
    let n = nRef.val;
    let shiftopc = shiftopcRef.val;
    if (n > 127) return 0;  // Up to 128-bits

    const multvn: Varnode = subop.getIn(0)!;
    if (!multvn.isWritten()) return 0;
    const multop: PcodeOp = multvn.getDef()!;
    if (multop.code() !== OpCode.CPUI_INT_MULT) return 0;
    const multConst: bigint[] = [0n, 0n];
    if (!multop.getIn(1)!.isConstantExtended(multConst))
      return 0;

    const extvn: Varnode = multop.getIn(0)!;
    if (!extvn.isWritten()) return 0;
    const extop: PcodeOp = extvn.getDef()!;
    const opc: OpCode = extop.code();
    if (opc === OpCode.CPUI_INT_ZEXT) {
      if (op.code() === OpCode.CPUI_INT_SRIGHT) return 0;
    }
    else if (opc === OpCode.CPUI_INT_SEXT) {
      if (op.code() === OpCode.CPUI_INT_RIGHT) return 0;
    }

    const power: bigint[] = [0n, 0n];
    set_u128(power, 1n);
    leftshift128(power, power, n);      // power = 2^n
    add128(multConst, power, multConst); // multConst += 2^n
    const x: Varnode = extop.getIn(0)!;

    for (let iter = op.getOut()!.beginDescend(); iter < op.getOut()!.endDescend(); iter++) {
      const addop: PcodeOp = op.getOut()!.getDescend(iter);
      if (addop.code() !== OpCode.CPUI_INT_ADD) continue;
      if ((addop.getIn(0)! !== x) && (addop.getIn(1)! !== x))
        continue;

      // Construct the new constant
      const newConstVn: Varnode = data.newExtendedConstant(extvn.getSize(), multConst, op);

      // Construct the new multiply
      const newmultop: PcodeOp = data.newOp(2, op.getAddr());
      data.opSetOpcode(newmultop, OpCode.CPUI_INT_MULT);
      const newmultvn: Varnode = data.newUniqueOut(extvn.getSize(), newmultop);
      data.opSetInput(newmultop, extvn, 0);
      data.opSetInput(newmultop, newConstVn, 1);
      data.opInsertBefore(newmultop, op);

      const newshiftop: PcodeOp = data.newOp(2, op.getAddr());
      if (shiftopc === OpCode.CPUI_MAX)
        shiftopc = OpCode.CPUI_INT_RIGHT;
      data.opSetOpcode(newshiftop, shiftopc);
      const newshiftvn: Varnode = data.newUniqueOut(extvn.getSize(), newshiftop);
      data.opSetInput(newshiftop, newmultvn, 0);
      data.opSetInput(newshiftop, data.newConstant(4, BigInt(n)), 1);
      data.opInsertBefore(newshiftop, op);

      data.opSetOpcode(addop, OpCode.CPUI_SUBPIECE);
      data.opSetInput(addop, newshiftvn, 0);
      data.opSetInput(addop, data.newConstant(4, 0n), 1);
      return 1;
    }
    return 0;
  }

  /// Check for shift form of expression
  ///
  /// Look for: sub(V,c) or sub(V,c) >> n
  /// Pass back total truncation in bits: n+c*8
  static findSubshift(op: PcodeOp, n: { val: number }, shiftopc: { val: OpCode }): PcodeOp | null {
    let subop: PcodeOp;
    shiftopc.val = op.code();
    if (shiftopc.val !== OpCode.CPUI_SUBPIECE) {  // Must be right shift
      const vn: Varnode = op.getIn(0)!;
      if (!vn.isWritten()) return null;
      subop = vn.getDef()!;
      if (subop.code() !== OpCode.CPUI_SUBPIECE) return null;
      if (!op.getIn(1)!.isConstant()) return null;
      n.val = Number(op.getIn(1)!.getOffset());
    }
    else {
      shiftopc.val = OpCode.CPUI_MAX;  // Indicate there was no shift
      subop = op;
      n.val = 0;
    }
    const c: number = Number(subop.getIn(1)!.getOffset());
    if (subop.getOut()!.getSize() + c !== subop.getIn(0)!.getSize())
      return null;  // SUB is not high
    n.val += 8 * c;

    return subop;
  }
}

// RuleDivTermAdd2 - Simplify another expression associated with optimized division
export class RuleDivTermAdd2 extends Rule {
  constructor(g: string) {
    super(g, 0, "divtermadd2");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleDivTermAdd2(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_RIGHT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (!op.getIn(1)!.isConstant()) return 0;
    if (op.getIn(1)!.getOffset() !== 1n) return 0;
    if (!op.getIn(0)!.isWritten()) return 0;
    const subop: PcodeOp = op.getIn(0)!.getDef()!;
    if (subop.code() !== OpCode.CPUI_INT_ADD) return 0;
    let x: Varnode | null = null;
    let compvn: Varnode;
    let compop: PcodeOp;
    let i: number;
    for (i = 0; i < 2; ++i) {
      compvn = subop.getIn(i)!;
      if (compvn.isWritten()) {
        compop = compvn.getDef()!;
        if (compop.code() === OpCode.CPUI_INT_MULT) {
          const invn: Varnode = compop.getIn(1)!;
          if (invn.isConstant()) {
            if (invn.getOffset() === calc_mask(invn.getSize())) {
              x = subop.getIn(1 - i)!;
              break;
            }
          }
        }
      }
    }
    if (i === 2) return 0;
    const z: Varnode = subop.getIn(i)!.getDef()!.getIn(0)!;
    if (!z.isWritten()) return 0;
    const subpieceop: PcodeOp = z.getDef()!;
    if (subpieceop.code() !== OpCode.CPUI_SUBPIECE) return 0;
    const n: number = Number(subpieceop.getIn(1)!.getOffset()) * 8;
    if (n !== 8 * (subpieceop.getIn(0)!.getSize() - z.getSize())) return 0;
    const multvn: Varnode = subpieceop.getIn(0)!;
    if (!multvn.isWritten()) return 0;
    const multop: PcodeOp = multvn.getDef()!;
    if (multop.code() !== OpCode.CPUI_INT_MULT) return 0;
    const multConst: bigint[] = [0n, 0n];
    if (!multop.getIn(1)!.isConstantExtended(multConst)) return 0;
    const zextvn: Varnode = multop.getIn(0)!;
    if (!zextvn.isWritten()) return 0;
    const zextop: PcodeOp = zextvn.getDef()!;
    if (zextop.code() !== OpCode.CPUI_INT_ZEXT) return 0;
    if (zextop.getIn(0)! !== x) return 0;

    for (let iter = op.getOut()!.beginDescend(); iter < op.getOut()!.endDescend(); iter++) {
      const addop: PcodeOp = op.getOut()!.getDescend(iter);
      if (addop.code() !== OpCode.CPUI_INT_ADD) continue;
      if ((addop.getIn(0)! !== z) && (addop.getIn(1)! !== z)) continue;

      const pow: bigint[] = [0n, 0n];
      set_u128(pow, 1n);
      leftshift128(pow, pow, n);         // Calculate 2^n
      add128(multConst, pow, multConst);  // multConst = multConst + 2^n
      const newmultop: PcodeOp = data.newOp(2, op.getAddr());
      data.opSetOpcode(newmultop, OpCode.CPUI_INT_MULT);
      const newmultvn: Varnode = data.newUniqueOut(zextvn.getSize(), newmultop);
      data.opSetInput(newmultop, zextvn, 0);
      const newConstVn: Varnode = data.newExtendedConstant(zextvn.getSize(), multConst, op);
      data.opSetInput(newmultop, newConstVn, 1);
      data.opInsertBefore(newmultop, op);

      const newshiftop: PcodeOp = data.newOp(2, op.getAddr());
      data.opSetOpcode(newshiftop, OpCode.CPUI_INT_RIGHT);
      const newshiftvn: Varnode = data.newUniqueOut(zextvn.getSize(), newshiftop);
      data.opSetInput(newshiftop, newmultvn, 0);
      data.opSetInput(newshiftop, data.newConstant(4, BigInt(n + 1)), 1);
      data.opInsertBefore(newshiftop, op);

      data.opSetOpcode(addop, OpCode.CPUI_SUBPIECE);
      data.opSetInput(addop, newshiftvn, 0);
      data.opSetInput(addop, data.newConstant(4, 0n), 1);
      return 1;
    }
    return 0;
  }
}

// RuleDivOpt - Convert INT_MULT and shift forms into INT_DIV or INT_SDIV
export class RuleDivOpt extends Rule {
  constructor(g: string) {
    super(g, 0, "divopt");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleDivOpt(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_SUBPIECE);
    oplist.push(OpCode.CPUI_INT_RIGHT);
    oplist.push(OpCode.CPUI_INT_SRIGHT);
  }

  /// Check for INT_(S)RIGHT and/or SUBPIECE followed by INT_MULT
  ///
  /// Look for the forms:
  ///  - sub(ext(X) * y, c)       or
  ///  - sub(ext(X) * y, c) >> n  or
  ///  - (ext(X) * y) >> n
  static findForm(op: PcodeOp, n: { val: number }, y: bigint[], xsize: { val: number }, extopc: { val: OpCode }): Varnode | null {
    let curOp: PcodeOp = op;
    let shiftopc: OpCode = curOp.code();
    if (shiftopc === OpCode.CPUI_INT_RIGHT || shiftopc === OpCode.CPUI_INT_SRIGHT) {
      const vn: Varnode = curOp.getIn(0)!;
      if (!vn.isWritten()) return null;
      const cvn: Varnode = curOp.getIn(1)!;
      if (!cvn.isConstant()) return null;
      n.val = Number(cvn.getOffset());
      curOp = vn.getDef()!;
    }
    else {
      n.val = 0;  // No initial shift
      if (shiftopc !== OpCode.CPUI_SUBPIECE) return null;  // In this case SUBPIECE is not optional
      shiftopc = OpCode.CPUI_MAX;
    }
    if (curOp.code() === OpCode.CPUI_SUBPIECE) {  // Optional SUBPIECE
      const c: number = Number(curOp.getIn(1)!.getOffset());
      let inVn: Varnode = curOp.getIn(0)!;
      if (!inVn.isWritten()) return null;
      if (curOp.getOut()!.getSize() + c !== inVn.getSize())
        return null;  // Must keep high bits
      n.val += 8 * c;
      curOp = inVn.getDef()!;
    }
    if (curOp.code() !== OpCode.CPUI_INT_MULT) return null;  // There MUST be an INT_MULT
    let inVn: Varnode = curOp.getIn(0)!;
    if (!inVn.isWritten()) return null;
    if (inVn.isConstantExtended(y)) {
      inVn = curOp.getIn(1)!;
      if (!inVn.isWritten()) return null;
    }
    else if (!curOp.getIn(1)!.isConstantExtended(y))
      return null;  // There MUST be a constant

    let resVn: Varnode;
    const extOp: PcodeOp = inVn.getDef()!;
    extopc.val = extOp.code();
    if (extopc.val !== OpCode.CPUI_INT_SEXT) {
      let nzMask: bigint;
      if (extopc.val === OpCode.CPUI_INT_ZEXT)
        nzMask = extOp.getIn(0)!.getNZMask();
      else
        nzMask = inVn.getNZMask();
      xsize.val = 8 * 8 - count_leading_zeros(nzMask);  // 8*sizeof(uintb)
      if (xsize.val === 0) return null;
      if (xsize.val > 4 * inVn.getSize()) return null;
    }
    else
      xsize.val = extOp.getIn(0)!.getSize() * 8;

    if (extopc.val === OpCode.CPUI_INT_ZEXT || extopc.val === OpCode.CPUI_INT_SEXT) {
      const extVn: Varnode = extOp.getIn(0)!;
      if (extVn.isFree()) return null;
      if (inVn.getSize() === op.getOut()!.getSize())
        resVn = inVn;
      else
        resVn = extVn;
    }
    else {
      extopc.val = OpCode.CPUI_INT_ZEXT;  // Treat as unsigned extension
      resVn = inVn;
    }
    // Check for signed mismatch
    if (((extopc.val === OpCode.CPUI_INT_ZEXT) && (shiftopc === OpCode.CPUI_INT_SRIGHT)) ||
        ((extopc.val === OpCode.CPUI_INT_SEXT) && (shiftopc === OpCode.CPUI_INT_RIGHT))) {
      if (8 * op.getOut()!.getSize() - n.val !== xsize.val)
        return null;
      // op's signedness does not matter because all the extension
      // bits are truncated
    }
    return resVn;
  }

  /// Calculate the divisor
  static calcDivisor(n: bigint, y: bigint[], xsize: number): bigint {
    if (n > 127n || xsize > 64) return 0n;  // Not enough precision
    const power: bigint[] = [0n, 0n];
    const q: bigint[] = [0n, 0n];
    const r: bigint[] = [0n, 0n];
    set_u128(power, 1n);
    if (ulessequal128(y, power))  // Boundary cases, y <= 1, are wrong form
      return 0n;

    subtract128(y, power, y);            // y = y - 1
    leftshift128(power, power, Number(n));  // power = 2^n

    udiv128(power, y, q, r);
    if (0n !== q[1])
      return 0n;  // Result is bigger than 64-bits
    if (uless128(y, q)) return 0n;  // if y < q
    let diff: bigint = 0n;
    if (!uless128(r, q)) {  // if r >= q
      // Its possible y is 1 too big giving us a q that is smaller by 1 than the correct value
      q[0] += 1n;  // Adjust to bigger q
      subtract128(r, y, r);  // and remainder for the smaller y
      add128(r, q, r);
      if (!uless128(r, q)) return 0n;
      diff = q[0];  // Using y that is off by one adds extra error, affecting allowable maxx
    }
    // The optimization of division to multiplication
    // by the reciprocal holds true, if the maximum value
    // of x times q-r is less than 2^n
    let maxx: bigint = (xsize === 64) ? 0n : (1n << BigInt(xsize));
    maxx -= 1n;  // Maximum possible x value
    const tmp: bigint[] = [0n, 0n];
    const denom: bigint[] = [0n, 0n];
    diff += q[0] - r[0];
    set_u128(denom, diff);
    udiv128(power, denom, tmp, r);
    if (0n !== tmp[1])
      return q[0];  // tmp is bigger than 2^64 > maxx
    if (tmp[0] <= maxx) return 0n;
    return q[0];
  }

  /// Replace sign-bit extractions from the first given Varnode with the second Varnode
  static moveSignBitExtraction(firstVn: Varnode, replaceVn: Varnode, data: Funcdata): void {
    const testList: Varnode[] = [];
    testList.push(firstVn);
    if (firstVn.isWritten()) {
      const op: PcodeOp = firstVn.getDef()!;
      if (op.code() === OpCode.CPUI_INT_SRIGHT) {
        // Same sign bit could be extracted from previous shifted version
        testList.push(op.getIn(0)!);
      }
    }
    for (let i = 0; i < testList.length; ++i) {
      const vn: Varnode = testList[i];
      const descendsCopy = vn.descend.slice();
      for (let _di = 0; _di < descendsCopy.length; _di++) {
        const op: PcodeOp = descendsCopy[_di];
        const opc: OpCode = op.code();
        if (opc === OpCode.CPUI_INT_RIGHT || opc === OpCode.CPUI_INT_SRIGHT) {
          let constVn: Varnode = op.getIn(1)!;
          if (constVn.isWritten()) {
            const constOp: PcodeOp = constVn.getDef()!;
            if (constOp.code() === OpCode.CPUI_COPY)
              constVn = constOp.getIn(0)!;
            else if (constOp.code() === OpCode.CPUI_INT_AND) {
              constVn = constOp.getIn(0)!;
              const otherVn: Varnode = constOp.getIn(1)!;
              if (!otherVn.isConstant()) continue;
              if (constVn.getOffset() !== (constVn.getOffset() & otherVn.getOffset())) continue;
            }
          }
          if (constVn.isConstant()) {
            const sa: number = firstVn.getSize() * 8 - 1;
            if (sa === Number(constVn.getOffset())) {
              data.opSetInput(op, replaceVn, 0);
            }
          }
        }
        else if (opc === OpCode.CPUI_COPY) {
          testList.push(op.getOut()!);
        }
      }
    }
  }

  /// Check if form rooted at given PcodeOp is superseded by an overlapping form
  static checkFormOverlap(op: PcodeOp): boolean {
    if (op.code() !== OpCode.CPUI_SUBPIECE) return false;
    const vn: Varnode = op.getOut()!;
    for (let iter = vn.beginDescend(); iter < vn.endDescend(); iter++) {
      const superOp: PcodeOp = vn.getDescend(iter);
      const opc: OpCode = superOp.code();
      if (opc !== OpCode.CPUI_INT_RIGHT && opc !== OpCode.CPUI_INT_SRIGHT) continue;
      const cvn: Varnode = superOp.getIn(1)!;
      if (!cvn.isConstant()) return true;  // Might be a form where constant has propagated yet
      const nRef: { val: number } = { val: 0 };
      const xsizeRef: { val: number } = { val: 0 };
      const yArr: bigint[] = [0n, 0n];
      const extopcRef: { val: OpCode } = { val: OpCode.CPUI_MAX };
      const inVn: Varnode | null = RuleDivOpt.findForm(superOp, nRef, yArr, xsizeRef, extopcRef);
      if (inVn !== null) return true;
    }
    return false;
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const nRef: { val: number } = { val: 0 };
    const xsizeRef: { val: number } = { val: 0 };
    const y: bigint[] = [0n, 0n];
    const extOpcRef: { val: OpCode } = { val: OpCode.CPUI_MAX };
    let inVn: Varnode | null = RuleDivOpt.findForm(op, nRef, y, xsizeRef, extOpcRef);
    if (inVn === null) return 0;
    if (RuleDivOpt.checkFormOverlap(op)) return 0;
    let n = nRef.val;
    let xsize = xsizeRef.val;
    let extOpc = extOpcRef.val;
    if (extOpc === OpCode.CPUI_INT_SEXT)
      xsize -= 1;  // one less bit for signed, because of signbit
    const divisor: bigint = RuleDivOpt.calcDivisor(BigInt(n), y, xsize);
    if (divisor === 0n) return 0;
    let outSize: number = op.getOut()!.getSize();

    if (inVn.getSize() < outSize) {  // Do we need an extension to get to final size
      const inExt: PcodeOp = data.newOp(1, op.getAddr());
      data.opSetOpcode(inExt, extOpc);
      const extOut: Varnode = data.newUniqueOut(outSize, inExt);
      data.opSetInput(inExt, inVn, 0);
      inVn = extOut;
      data.opInsertBefore(inExt, op);
    }
    else if (inVn.getSize() > outSize) {  // Do we need a truncation to get to final size
      const newop: PcodeOp = data.newOp(2, op.getAddr());  // Create new op to hold the INT_DIV or INT_SDIV:INT_ADD
      data.opSetOpcode(newop, OpCode.CPUI_INT_ADD);  // This gets changed immediately, but need it for opInsert
      const resVn: Varnode = data.newUniqueOut(inVn.getSize(), newop);
      data.opInsertBefore(newop, op);
      data.opSetOpcode(op, OpCode.CPUI_SUBPIECE);  // Original op becomes a truncation
      data.opSetInput(op, resVn, 0);
      data.opSetInput(op, data.newConstant(4, 0n), 1);
      op = newop;  // Main transform now changes newop
      outSize = inVn.getSize();
    }
    if (extOpc === OpCode.CPUI_INT_ZEXT) {  // Unsigned division
      data.opSetInput(op, inVn, 0);
      data.opSetInput(op, data.newConstant(outSize, divisor), 1);
      data.opSetOpcode(op, OpCode.CPUI_INT_DIV);
    }
    else {  // Sign division
      RuleDivOpt.moveSignBitExtraction(op.getOut()!, inVn, data);
      const divop: PcodeOp = data.newOp(2, op.getAddr());
      data.opSetOpcode(divop, OpCode.CPUI_INT_SDIV);
      const newout: Varnode = data.newUniqueOut(outSize, divop);
      data.opSetInput(divop, inVn, 0);
      data.opSetInput(divop, data.newConstant(outSize, divisor), 1);
      data.opInsertBefore(divop, op);
      // Build the sign value correction
      const sgnop: PcodeOp = data.newOp(2, op.getAddr());
      data.opSetOpcode(sgnop, OpCode.CPUI_INT_SRIGHT);
      const sgnvn: Varnode = data.newUniqueOut(outSize, sgnop);
      data.opSetInput(sgnop, inVn, 0);
      data.opSetInput(sgnop, data.newConstant(outSize, BigInt(outSize * 8 - 1)), 1);
      data.opInsertBefore(sgnop, op);
      // Add the correction into the division op
      data.opSetInput(op, newout, 0);
      data.opSetInput(op, sgnvn, 1);
      data.opSetOpcode(op, OpCode.CPUI_INT_ADD);
    }
    return 1;
  }
}

// RuleSignDiv2 - Convert INT_SRIGHT form into INT_SDIV: (V + -1*(V s>> 31)) s>> 1  =>  V s/ 2
export class RuleSignDiv2 extends Rule {
  constructor(g: string) {
    super(g, 0, "signdiv2");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSignDiv2(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_SRIGHT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let addout: Varnode, multout: Varnode, shiftout: Varnode, a: Varnode | null;
    let addop: PcodeOp, multop: PcodeOp, shiftop: PcodeOp;

    if (!op.getIn(1)!.isConstant()) return 0;
    if (op.getIn(1)!.getOffset() !== 1n) return 0;
    addout = op.getIn(0)!;
    if (!addout.isWritten()) return 0;
    addop = addout.getDef()!;
    if (addop.code() !== OpCode.CPUI_INT_ADD) return 0;
    let i: number;
    a = null;
    for (i = 0; i < 2; ++i) {
      multout = addop.getIn(i)!;
      if (!multout.isWritten()) continue;
      multop = multout.getDef()!;
      if (multop.code() !== OpCode.CPUI_INT_MULT)
        continue;
      if (!multop.getIn(1)!.isConstant()) continue;
      if (multop.getIn(1)!.getOffset() !==
          calc_mask(multop.getIn(1)!.getSize()))
        continue;
      shiftout = multop.getIn(0)!;
      if (!shiftout.isWritten()) continue;
      shiftop = shiftout.getDef()!;
      if (shiftop.code() !== OpCode.CPUI_INT_SRIGHT)
        continue;
      if (!shiftop.getIn(1)!.isConstant()) continue;
      const n: number = Number(shiftop.getIn(1)!.getOffset());
      a = shiftop.getIn(0)!;
      if (a !== addop.getIn(1 - i)!) continue;
      if (n !== 8 * a.getSize() - 1) continue;
      if (a.isFree()) continue;
      break;
    }
    if (i === 2) return 0;

    data.opSetInput(op, a!, 0);
    data.opSetInput(op, data.newConstant(a!.getSize(), 2n), 1);
    data.opSetOpcode(op, OpCode.CPUI_INT_SDIV);
    return 1;
  }
}

// RuleDivChain - Collapse two consecutive divisions: (x / c1) / c2  =>  x / (c1*c2)
export class RuleDivChain extends Rule {
  constructor(g: string) {
    super(g, 0, "divchain");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleDivChain(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_DIV);
    oplist.push(OpCode.CPUI_INT_SDIV);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const opc2: OpCode = op.code();
    const constVn2: Varnode = op.getIn(1)!;
    if (!constVn2.isConstant()) return 0;
    const vn: Varnode = op.getIn(0)!;
    if (!vn.isWritten()) return 0;
    const divOp: PcodeOp = vn.getDef()!;
    const opc1: OpCode = divOp.code();
    if (opc1 !== opc2 && (opc2 !== OpCode.CPUI_INT_DIV || opc1 !== OpCode.CPUI_INT_RIGHT))
      return 0;
    const constVn1: Varnode = divOp.getIn(1)!;
    if (!constVn1.isConstant()) return 0;
    // If the intermediate result is being used elsewhere, don't apply
    // Its likely collapsing the divisions will interfere with the modulo rules
    if (vn.loneDescend()! === null) return 0;
    let val1: bigint;
    if (opc1 === opc2) {
      val1 = constVn1.getOffset();
    }
    else {  // Unsigned case with INT_RIGHT
      const sa: number = Number(constVn1.getOffset());
      val1 = 1n;
      val1 <<= BigInt(sa);
    }
    const baseVn: Varnode = divOp.getIn(0)!;
    if (baseVn.isFree()) return 0;
    const sz: number = vn.getSize();
    const val2: bigint = constVn2.getOffset();
    const resval: bigint = (val1 * val2) & calc_mask(sz);
    if (resval === 0n) return 0;
    let v1: bigint = val1;
    let v2: bigint = val2;
    if (signbit_negative(v1, sz))
      v1 = (~v1 + 1n) & calc_mask(sz);
    if (signbit_negative(v2, sz))
      v2 = (~v2 + 1n) & calc_mask(sz);
    const bitcount: number = mostsigbit_set(v1) + mostsigbit_set(v2) + 2;
    if (opc2 === OpCode.CPUI_INT_DIV && bitcount > sz * 8) return 0;  // Unsigned overflow
    if (opc2 === OpCode.CPUI_INT_SDIV && bitcount > sz * 8 - 2) return 0;  // Signed overflow
    data.opSetInput(op, baseVn, 0);
    data.opSetInput(op, data.newConstant(sz, resval), 1);
    return 1;
  }
}

// RuleSignForm - Normalize sign extraction: sub(sext(V),c)  =>  V s>> 31
export class RuleSignForm extends Rule {
  constructor(g: string) {
    super(g, 0, "signform");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSignForm(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_SUBPIECE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let sextout: Varnode, a: Varnode;
    let sextop: PcodeOp;

    sextout = op.getIn(0)!;
    if (!sextout.isWritten()) return 0;
    sextop = sextout.getDef()!;
    if (sextop.code() !== OpCode.CPUI_INT_SEXT)
      return 0;
    a = sextop.getIn(0)!;
    const c: number = Number(op.getIn(1)!.getOffset());
    if (c < a.getSize()) return 0;
    if (a.isFree()) return 0;

    data.opSetInput(op, a, 0);
    const n: number = 8 * a.getSize() - 1;
    data.opSetInput(op, data.newConstant(4, BigInt(n)), 1);
    data.opSetOpcode(op, OpCode.CPUI_INT_SRIGHT);
    return 1;
  }
}

// RuleSignForm2 - Normalize sign extraction: sub(sext(V) * small,c) s>> 31  =>  V s>> 31
export class RuleSignForm2 extends Rule {
  constructor(g: string) {
    super(g, 0, "signform2");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSignForm2(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_SRIGHT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const constVn: Varnode = op.getIn(1)!;
    if (!constVn.isConstant()) return 0;
    const inVn: Varnode = op.getIn(0)!;
    const sizeout: number = inVn.getSize();
    if (Number(constVn.getOffset()) !== sizeout * 8 - 1) return 0;
    if (!inVn.isWritten()) return 0;
    const subOp: PcodeOp = inVn.getDef()!;
    if (subOp.code() !== OpCode.CPUI_SUBPIECE) return 0;
    const c: number = Number(subOp.getIn(1)!.getOffset());
    const multOut: Varnode = subOp.getIn(0)!;
    const multSize: number = multOut.getSize();
    if (c + sizeout !== multSize) return 0;  // Must be extracting high part
    if (!multOut.isWritten()) return 0;
    const multOp: PcodeOp = multOut.getDef()!;
    if (multOp.code() !== OpCode.CPUI_INT_MULT) return 0;
    let slot: number;
    let sextOp: PcodeOp | null = null;
    for (slot = 0; slot < 2; ++slot) {  // Search for the INT_SEXT
      const vn: Varnode = multOp.getIn(slot)!;
      if (!vn.isWritten()) continue;
      sextOp = vn.getDef()!;
      if (sextOp!.code() === OpCode.CPUI_INT_SEXT) break;
    }
    if (slot > 1) return 0;
    const a: Varnode = sextOp!.getIn(0)!;
    if (a.isFree() || a.getSize() !== sizeout) return 0;
    const otherVn: Varnode = multOp.getIn(1 - slot)!;
    // otherVn must be a positive integer and small enough so the INT_MULT can't overflow into the sign-bit
    if (otherVn.isConstant()) {
      if (otherVn.getOffset() > calc_mask(sizeout)) return 0;
      if (2 * sizeout > multSize) return 0;
    }
    else if (otherVn.isWritten()) {
      const zextOp: PcodeOp = otherVn.getDef()!;
      if (zextOp.code() !== OpCode.CPUI_INT_ZEXT) return 0;
      if (zextOp.getIn(0)!.getSize() + sizeout > multSize) return 0;
    }
    else
      return 0;
    data.opSetInput(op, a, 0);
    return 0;
  }
}

// RuleSignNearMult - Simplify division form: (V + (V s>> 0x1f)>>(32-n)) & (-1<<n)  =>  (V s/ 2^n) * 2^n
export class RuleSignNearMult extends Rule {
  constructor(g: string) {
    super(g, 0, "signnearmult");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSignNearMult(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_AND);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (!op.getIn(1)!.isConstant()) return 0;
    if (!op.getIn(0)!.isWritten()) return 0;
    const addop: PcodeOp = op.getIn(0)!.getDef()!;
    if (addop.code() !== OpCode.CPUI_INT_ADD) return 0;
    let shiftvn: Varnode;
    let unshiftop: PcodeOp | null = null;
    let i: number;
    for (i = 0; i < 2; ++i) {
      shiftvn = addop.getIn(i)!;
      if (!shiftvn.isWritten()) continue;
      unshiftop = shiftvn.getDef()!;
      if (unshiftop!.code() === OpCode.CPUI_INT_RIGHT) {
        if (!unshiftop!.getIn(1)!.isConstant()) continue;
        break;
      }
    }
    if (i === 2) return 0;
    shiftvn = addop.getIn(i)!;
    const x: Varnode = addop.getIn(1 - i)!;
    if (x.isFree()) return 0;
    let n: number = Number(unshiftop!.getIn(1)!.getOffset());
    if (n <= 0) return 0;
    n = shiftvn.getSize() * 8 - n;
    if (n <= 0) return 0;
    let mask: bigint = calc_mask(shiftvn.getSize());
    mask = (mask << BigInt(n)) & mask;
    if (mask !== op.getIn(1)!.getOffset()) return 0;
    const sgnvn: Varnode = unshiftop!.getIn(0)!;
    if (!sgnvn.isWritten()) return 0;
    const sshiftop: PcodeOp = sgnvn.getDef()!;
    if (sshiftop.code() !== OpCode.CPUI_INT_SRIGHT) return 0;
    if (!sshiftop.getIn(1)!.isConstant()) return 0;
    if (sshiftop.getIn(0)! !== x) return 0;
    const val: number = Number(sshiftop.getIn(1)!.getOffset());
    if (val !== 8 * x.getSize() - 1) return 0;

    let pow: bigint = 1n;
    pow <<= BigInt(n);
    const newdiv: PcodeOp = data.newOp(2, op.getAddr());
    data.opSetOpcode(newdiv, OpCode.CPUI_INT_SDIV);
    const divvn: Varnode = data.newUniqueOut(x.getSize(), newdiv);
    data.opSetInput(newdiv, x, 0);
    data.opSetInput(newdiv, data.newConstant(x.getSize(), pow), 1);
    data.opInsertBefore(newdiv, op);

    data.opSetOpcode(op, OpCode.CPUI_INT_MULT);
    data.opSetInput(op, divvn, 0);
    data.opSetInput(op, data.newConstant(x.getSize(), pow), 1);
    return 1;
  }
}

// RuleModOpt - Simplify expressions that optimize INT_REM and INT_SREM
export class RuleModOpt extends Rule {
  constructor(g: string) {
    super(g, 0, "modopt");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleModOpt(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_DIV);
    oplist.push(OpCode.CPUI_INT_SDIV);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let multop: PcodeOp, addop: PcodeOp;
    let div: Varnode, x: Varnode, outvn: Varnode, outvn2: Varnode, div2: Varnode;

    x = op.getIn(0)!;
    div = op.getIn(1)!;
    outvn = op.getOut()!;
    for (let iter1 = outvn.beginDescend(); iter1 < outvn.endDescend(); iter1++) {
      multop = outvn.getDescend(iter1);
      if (multop.code() !== OpCode.CPUI_INT_MULT) continue;
      div2 = multop.getIn(1)!;
      if (div2 === outvn)
        div2 = multop.getIn(0)!;
      // Check that div is 2's complement of div2
      if (div2.isConstant()) {
        if (!div.isConstant()) continue;
        const mask: bigint = calc_mask(div2.getSize());
        if ((((div2.getOffset() ^ mask) + 1n) & mask) !== div.getOffset())
          continue;
      }
      else {
        if (!div2.isWritten()) continue;
        if (div2.getDef()!.code() !== OpCode.CPUI_INT_2COMP) continue;
        if (div2.getDef()!.getIn(0)! !== div) continue;
      }
      outvn2 = multop.getOut()!;
      for (let iter2 = outvn2.beginDescend(); iter2 < outvn2.endDescend(); iter2++) {
        addop = outvn2.getDescend(iter2);
        if (addop.code() !== OpCode.CPUI_INT_ADD) continue;
        let lvn: Varnode;
        lvn = addop.getIn(0)!;
        if (lvn === outvn2)
          lvn = addop.getIn(1)!;
        if (lvn !== x) continue;
        data.opSetInput(addop, x, 0);
        if (div.isConstant())
          data.opSetInput(addop, data.newConstant(div.getSize(), div.getOffset()), 1);
        else
          data.opSetInput(addop, div, 1);
        if (op.code() === OpCode.CPUI_INT_DIV)  // Remainder of proper signedness
          data.opSetOpcode(addop, OpCode.CPUI_INT_REM);
        else
          data.opSetOpcode(addop, OpCode.CPUI_INT_SREM);
        return 1;
      }
    }
    return 0;
  }
}

// RuleSignMod2nOpt - Convert INT_SREM forms
export class RuleSignMod2nOpt extends Rule {
  constructor(g: string) {
    super(g, 0, "signmod2nopt");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSignMod2nOpt(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_RIGHT);
  }

  /// Verify that the given Varnode is a sign extraction of the form V s>> 63
  static checkSignExtraction(outVn: Varnode): Varnode | null {
    if (!outVn.isWritten()) return null;
    const signOp: PcodeOp = outVn.getDef()!;
    if (signOp.code() !== OpCode.CPUI_INT_SRIGHT)
      return null;
    const constVn: Varnode = signOp.getIn(1)!;
    if (!constVn.isConstant())
      return null;
    const val: number = Number(constVn.getOffset());
    const resVn: Varnode = signOp.getIn(0)!;
    const insize: number = resVn.getSize();
    if (val !== insize * 8 - 1)
      return null;
    return resVn;
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (!op.getIn(1)!.isConstant()) return 0;
    const shiftAmt: number = Number(op.getIn(1)!.getOffset());
    const a: Varnode | null = RuleSignMod2nOpt.checkSignExtraction(op.getIn(0)!);
    if (a === null || a.isFree()) return 0;
    const correctVn: Varnode = op.getOut()!;
    const n: number = a.getSize() * 8 - shiftAmt;
    let mask: bigint = 1n;
    mask = (mask << BigInt(n)) - 1n;
    for (let iter = correctVn.beginDescend(); iter < correctVn.endDescend(); iter++) {
      const multop: PcodeOp = correctVn.getDescend(iter);
      if (multop.code() !== OpCode.CPUI_INT_MULT) continue;
      const negone: Varnode = multop.getIn(1)!;
      if (!negone.isConstant()) continue;
      if (negone.getOffset() !== calc_mask(correctVn.getSize())) continue;
      const baseOp: PcodeOp | null = multop.getOut()!.loneDescend()!;
      if (baseOp === null) continue;
      if (baseOp.code() !== OpCode.CPUI_INT_ADD) continue;
      const slot: number = 1 - baseOp.getSlot(multop.getOut()!);
      let andOut: Varnode = baseOp.getIn(slot)!;
      if (!andOut.isWritten()) continue;
      let andOp: PcodeOp = andOut.getDef()!;
      let truncSize: number = -1;
      if (andOp.code() === OpCode.CPUI_INT_ZEXT) {  // Look for intervening extension after INT_AND
        andOut = andOp.getIn(0)!;
        if (!andOut.isWritten()) continue;
        andOp = andOut.getDef()!;
        if (andOp.code() !== OpCode.CPUI_INT_AND) continue;
        truncSize = andOut.getSize();  // If so we have a truncated form
      }
      else if (andOp.code() !== OpCode.CPUI_INT_AND)
        continue;

      let constVn: Varnode = andOp.getIn(1)!;
      if (!constVn.isConstant()) continue;
      if (constVn.getOffset() !== mask) continue;
      const addOut: Varnode = andOp.getIn(0)!;
      if (!addOut.isWritten()) continue;
      const addOp: PcodeOp = addOut.getDef()!;
      if (addOp.code() !== OpCode.CPUI_INT_ADD) continue;
      // Search for "a" as one of the inputs to addOp
      let aSlot: number;
      for (aSlot = 0; aSlot < 2; ++aSlot) {
        let vn: Varnode = addOp.getIn(aSlot)!;
        if (truncSize >= 0) {
          if (!vn.isWritten()) continue;
          const subOp: PcodeOp = vn.getDef()!;
          if (subOp.code() !== OpCode.CPUI_SUBPIECE) continue;
          if (subOp.getIn(1)!.getOffset() !== 0n) continue;
          vn = subOp.getIn(0)!;
        }
        if (a === vn) break;
      }
      if (aSlot > 1) continue;
      // Verify that the other input to addOp is an INT_RIGHT by shiftAmt
      let extVn: Varnode = addOp.getIn(1 - aSlot)!;
      if (!extVn.isWritten()) continue;
      const shiftOp: PcodeOp = extVn.getDef()!;
      if (shiftOp.code() !== OpCode.CPUI_INT_RIGHT) continue;
      constVn = shiftOp.getIn(1)!;
      if (!constVn.isConstant()) continue;
      let shiftval: number = Number(constVn.getOffset());
      if (truncSize >= 0)
        shiftval += (a.getSize() - truncSize) * 8;
      if (shiftval !== shiftAmt) continue;
      // Verify that the input to INT_RIGHT is a sign extraction of "a"
      extVn = RuleSignMod2nOpt.checkSignExtraction(shiftOp.getIn(0)!)!;
      if (extVn === null) continue;
      if (truncSize >= 0) {
        if (!extVn.isWritten()) continue;
        const subOp: PcodeOp = extVn.getDef()!;
        if (subOp.code() !== OpCode.CPUI_SUBPIECE) continue;
        if (Number(subOp.getIn(1)!.getOffset()) !== truncSize) continue;
        extVn = subOp.getIn(0)!;
      }
      if (a !== extVn) continue;

      data.opSetOpcode(baseOp, OpCode.CPUI_INT_SREM);
      data.opSetInput(baseOp, a, 0);
      data.opSetInput(baseOp, data.newConstant(a.getSize(), mask + 1n), 1);
      return 1;
    }
    return 0;
  }
}

// RuleSignMod2Opt - Convert INT_SREM form: (V - sign)&1 + sign  =>  V s% 2
export class RuleSignMod2Opt extends Rule {
  constructor(g: string) {
    super(g, 0, "signmod2opt");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSignMod2Opt(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_AND);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let constVn: Varnode = op.getIn(1)!;
    if (!constVn.isConstant()) return 0;
    if (constVn.getOffset() !== 1n) return 0;
    const addOut: Varnode = op.getIn(0)!;
    if (!addOut.isWritten()) return 0;
    const addOp: PcodeOp = addOut.getDef()!;
    if (addOp.code() !== OpCode.CPUI_INT_ADD) return 0;
    let multSlot: number;
    let multOp: PcodeOp | null = null;
    let trunc: boolean = false;
    for (multSlot = 0; multSlot < 2; ++multSlot) {
      const vn: Varnode = addOp.getIn(multSlot)!;
      if (!vn.isWritten()) continue;
      multOp = vn.getDef()!;
      if (multOp!.code() !== OpCode.CPUI_INT_MULT) continue;
      constVn = multOp!.getIn(1)!;
      if (!constVn.isConstant()) continue;
      if (constVn.getOffset() === calc_mask(constVn.getSize())) break;  // Check for INT_MULT by -1
    }
    if (multSlot > 1) return 0;
    let base: Varnode | null = RuleSignMod2nOpt.checkSignExtraction(multOp!.getIn(0)!);
    if (base === null) return 0;
    let otherBase: Varnode = addOp.getIn(1 - multSlot)!;
    if (base !== otherBase) {
      if (!base.isWritten() || !otherBase.isWritten()) return 0;
      let subOp: PcodeOp = base.getDef()!;
      if (subOp.code() !== OpCode.CPUI_SUBPIECE) return 0;
      const truncAmt: number = Number(subOp.getIn(1)!.getOffset());
      if (truncAmt + base.getSize() !== subOp.getIn(0)!.getSize()) return 0;  // Must truncate all but high part
      base = subOp.getIn(0)!;
      subOp = otherBase.getDef()!;
      if (subOp.code() !== OpCode.CPUI_SUBPIECE) return 0;
      if (subOp.getIn(1)!.getOffset() !== 0n) return 0;
      otherBase = subOp.getIn(0)!;
      if (otherBase !== base) return 0;
      trunc = true;
    }
    if (base.isFree()) return 0;
    let andOut: Varnode = op.getOut()!;
    if (trunc) {
      const extOp: PcodeOp | null = andOut.loneDescend()!;
      if (extOp === null || extOp.code() !== OpCode.CPUI_INT_ZEXT) return 0;
      andOut = extOp.getOut()!;
    }
    for (let iter = andOut.beginDescend(); iter < andOut.endDescend(); iter++) {
      const rootOp: PcodeOp = andOut.getDescend(iter);
      if (rootOp.code() !== OpCode.CPUI_INT_ADD) continue;
      const slot: number = rootOp.getSlot(andOut);
      otherBase = RuleSignMod2nOpt.checkSignExtraction(rootOp.getIn(1 - slot)!)!;
      if (otherBase !== base) continue;
      data.opSetOpcode(rootOp, OpCode.CPUI_INT_SREM);
      data.opSetInput(rootOp, base, 0);
      data.opSetInput(rootOp, data.newConstant(base.getSize(), 2n), 1);
      return 1;
    }
    return 0;
  }
}

// RuleSignMod2nOpt2 - Convert INT_SREM form: V - (Vadj & ~(2^n-1)) => V s% 2^n
export class RuleSignMod2nOpt2 extends Rule {
  constructor(g: string) {
    super(g, 0, "signmod2nopt2");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSignMod2nOpt2(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_MULT);
  }

  /// Verify a form of V - (V s>> 0x3f)
  private static checkSignExtForm(op: PcodeOp): Varnode | null {
    let slot: number;
    for (slot = 0; slot < 2; ++slot) {
      const minusVn: Varnode = op.getIn(slot)!;
      if (!minusVn.isWritten()) continue;
      const multOp: PcodeOp = minusVn.getDef()!;
      if (multOp.code() !== OpCode.CPUI_INT_MULT) continue;
      const constVn: Varnode = multOp.getIn(1)!;
      if (!constVn.isConstant()) continue;
      if (constVn.getOffset() !== calc_mask(constVn.getSize())) continue;
      const base: Varnode = op.getIn(1 - slot)!;
      const signExt: Varnode = multOp.getIn(0)!;
      if (!signExt.isWritten()) continue;
      const shiftOp: PcodeOp = signExt.getDef()!;
      if (shiftOp.code() !== OpCode.CPUI_INT_SRIGHT) continue;
      if (shiftOp.getIn(0)! !== base) continue;
      const cv: Varnode = shiftOp.getIn(1)!;
      if (!cv.isConstant()) continue;
      if (Number(cv.getOffset()) !== 8 * base.getSize() - 1) continue;
      return base;
    }
    return null;
  }

  /// Verify an if block like V = (V s< 0) ? V + 2^n-1 : V
  private static checkMultiequalForm(op: PcodeOp, npow: bigint): Varnode | null {
    if (op.numInput() !== 2) return null;
    npow -= 1n;  // 2^n - 1
    let slot: number;
    let base: Varnode | null = null;
    for (slot = 0; slot < op.numInput(); ++slot) {
      const addOut: Varnode = op.getIn(slot)!;
      if (!addOut.isWritten()) continue;
      const addOp: PcodeOp = addOut.getDef()!;
      if (addOp.code() !== OpCode.CPUI_INT_ADD) continue;
      const constVn: Varnode = addOp.getIn(1)!;
      if (!constVn.isConstant()) continue;
      if (constVn.getOffset() !== npow) continue;
      base = addOp.getIn(0)!;
      const otherBase: Varnode = op.getIn(1 - slot)!;
      if (otherBase === base)
        break;
    }
    if (slot > 1) return null;
    const bl: BlockBasic = op.getParent() as BlockBasic;
    let innerSlot: number = 0;
    let inner: BlockBasic = bl.getIn(innerSlot)! as BlockBasic;
    if (inner.sizeOut() !== 1 || inner.sizeIn() !== 1) {
      innerSlot = 1;
      inner = bl.getIn(innerSlot)! as BlockBasic;
      if (inner.sizeOut() !== 1 || inner.sizeIn() !== 1)
        return null;
    }
    const decision: BlockBasic = inner.getIn(0)! as BlockBasic;
    if (bl.getIn(1 - innerSlot)! !== decision) return null;
    const cbranch: PcodeOp | null = decision.lastOp();
    if (cbranch === null || cbranch.code() !== OpCode.CPUI_CBRANCH) return null;
    const boolVn: Varnode = cbranch.getIn(1)!;
    if (!boolVn.isWritten()) return null;
    const lessOp: PcodeOp = boolVn.getDef()!;
    if (lessOp.code() !== OpCode.CPUI_INT_SLESS) return null;
    if (!lessOp.getIn(1)!.isConstant()) return null;
    if (lessOp.getIn(1)!.getOffset() !== 0n) return null;
    const negBlock: FlowBlock = cbranch.isBooleanFlip() ? decision.getFalseOut() : decision.getTrueOut();
    const negSlot: number = (negBlock === inner) ? innerSlot : (1 - innerSlot);
    if (negSlot !== slot) return null;
    return base;
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const constVn: Varnode = op.getIn(1)!;
    if (!constVn.isConstant()) return 0;
    const mask: bigint = calc_mask(constVn.getSize());
    if (constVn.getOffset() !== mask) return 0;  // Must be INT_MULT by -1
    const andOut: Varnode = op.getIn(0)!;
    if (!andOut.isWritten()) return 0;
    const andOp: PcodeOp = andOut.getDef()!;
    if (andOp.code() !== OpCode.CPUI_INT_AND) return 0;
    const cv: Varnode = andOp.getIn(1)!;
    if (!cv.isConstant()) return 0;
    const npow: bigint = (~cv.getOffset() + 1n) & mask;
    if (popcount(npow) !== 1) return 0;  // constVn must be of form 11111..000..
    if (npow === 1n) return 0;
    const adjVn: Varnode = andOp.getIn(0)!;
    if (!adjVn.isWritten()) return 0;
    const adjOp: PcodeOp = adjVn.getDef()!;
    let base: Varnode | null;
    if (adjOp.code() === OpCode.CPUI_INT_ADD) {
      if (npow !== 2n) return 0;  // Special mod 2 form
      base = RuleSignMod2nOpt2.checkSignExtForm(adjOp);
    }
    else if (adjOp.code() === OpCode.CPUI_MULTIEQUAL) {
      base = RuleSignMod2nOpt2.checkMultiequalForm(adjOp, npow);
    }
    else
      return 0;
    if (base === null) return 0;
    if (base.isFree()) return 0;
    const multOut: Varnode = op.getOut()!;
    for (let iter = multOut.beginDescend(); iter < multOut.endDescend(); iter++) {
      const rootOp: PcodeOp = multOut.getDescend(iter);
      if (rootOp.code() !== OpCode.CPUI_INT_ADD) continue;
      const slot: number = rootOp.getSlot(multOut);
      if (rootOp.getIn(1 - slot)! !== base) continue;
      if (slot === 0)
        data.opSetInput(rootOp, base, 0);
      data.opSetInput(rootOp, data.newConstant(base.getSize(), npow), 1);
      data.opSetOpcode(rootOp, OpCode.CPUI_INT_SREM);
      return 1;
    }
    return 0;
  }
}

// RuleSegment - Propagate constants through a SEGMENTOP
export class RuleSegment extends Rule {
  constructor(g: string) {
    super(g, 0, "segment");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSegment(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_SEGMENTOP);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const segdef: SegmentOp | null = data.getArch().userops.getSegmentOp(op.getIn(0)!.getSpaceFromConst()!.getIndex());
    if (segdef === null)
      throw new LowlevelError("Segment operand missing definition");

    const vn1: Varnode = op.getIn(1)!;
    const vn2: Varnode = op.getIn(2)!;

    if (vn1.isConstant() && vn2.isConstant()) {
      const bindlist: bigint[] = [];
      bindlist.push(vn1.getOffset());
      bindlist.push(vn2.getOffset());
      const val: bigint = segdef.execute(bindlist);
      data.opRemoveInput(op, 2);
      data.opRemoveInput(op, 1);
      data.opSetInput(op, data.newConstant(op.getOut()!.getSize(), val), 0);
      data.opSetOpcode(op, OpCode.CPUI_COPY);
      return 1;
    }
    else if (segdef.hasFarPointerSupport()) {
      // If the hi and lo pieces come from a contiguous source
      if (!contiguous_test(vn1, vn2)) return 0;
      const whole: Varnode | null = findContiguousWhole(data, vn1, vn2);
      if (whole === null) return 0;
      if (whole.isFree()) return 0;
      // Use the contiguous source as the whole pointer
      data.opRemoveInput(op, 2);
      data.opRemoveInput(op, 1);
      data.opSetInput(op, whole, 0);
      data.opSetOpcode(op, OpCode.CPUI_COPY);
      return 1;
    }
    return 0;
  }
}

// RulePtrFlow - Mark Varnode and PcodeOp objects that are carrying or operating on pointers
export class RulePtrFlow extends Rule {
  private glb: Architecture;
  private hasTruncations: boolean;

  constructor(g: string, conf: Architecture) {
    super(g, 0, "ptrflow");
    this.glb = conf;
    this.hasTruncations = this.glb.getDefaultDataSpace().isTruncated();
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RulePtrFlow(this.getGroup(), this.glb);
  }

  getOpList(oplist: number[]): void {
    if (!this.hasTruncations) return;  // Only stick ourselves into pool if aggressiveness is turned on
    oplist.push(OpCode.CPUI_STORE);
    oplist.push(OpCode.CPUI_LOAD);
    oplist.push(OpCode.CPUI_COPY);
    oplist.push(OpCode.CPUI_MULTIEQUAL);
    oplist.push(OpCode.CPUI_INDIRECT);
    oplist.push(OpCode.CPUI_INT_ADD);
    oplist.push(OpCode.CPUI_CALLIND);
    oplist.push(OpCode.CPUI_BRANCHIND);
    oplist.push(OpCode.CPUI_PTRSUB);
    oplist.push(OpCode.CPUI_PTRADD);
  }

  /// Set ptrflow property on PcodeOp only if it is propagating
  private trialSetPtrFlow(op: PcodeOp): boolean {
    switch (op.code()) {
      case OpCode.CPUI_COPY:
      case OpCode.CPUI_MULTIEQUAL:
      case OpCode.CPUI_INT_ADD:
      case OpCode.CPUI_INDIRECT:
      case OpCode.CPUI_PTRSUB:
      case OpCode.CPUI_PTRADD:
        if (!op.isPtrFlow()) {
          op.setPtrFlow();
          return true;
        }
        break;
      default:
        break;
    }
    return false;
  }

  /// Propagate ptrflow property to given Varnode and the defining PcodeOp
  private propagateFlowToDef(vn: Varnode): boolean {
    let madeChange: boolean = false;
    if (!vn.isPtrFlow()) {
      vn.setPtrFlow();
      madeChange = true;
    }
    if (!vn.isWritten()) return madeChange;
    const op: PcodeOp = vn.getDef()!;
    if (this.trialSetPtrFlow(op))
      madeChange = true;
    return madeChange;
  }

  /// Propagate ptrflow property to reads of given Varnode
  private propagateFlowToReads(vn: Varnode): boolean {
    let madeChange: boolean = false;
    if (!vn.isPtrFlow()) {
      vn.setPtrFlow();
      madeChange = true;
    }
    for (const op of vn.descend) {
      if (this.trialSetPtrFlow(op))
        madeChange = true;
    }
    return madeChange;
  }

  /// Truncate pointer Varnode
  private truncatePointer(spc: AddrSpace, op: PcodeOp, vn: Varnode, slot: number, data: Funcdata): Varnode {
    let newvn: Varnode;
    const truncop: PcodeOp = data.newOp(2, op.getAddr());
    data.opSetOpcode(truncop, OpCode.CPUI_SUBPIECE);
    data.opSetInput(truncop, data.newConstant(vn.getSize(), 0n), 1);
    if (vn.getSpace()!.getType() === spacetype.IPTR_INTERNAL) {
      newvn = data.newUniqueOut(spc.getAddrSize(), truncop);
    } else {
      let addr: Address = vn.getAddr();
      if (addr.isBigEndian())
        addr = addr.add(BigInt(vn.getSize() - spc.getAddrSize()));
      addr.renormalize(spc.getAddrSize());
      newvn = data.newVarnodeOut(spc.getAddrSize(), addr, truncop);
    }
    data.opSetInput(op, newvn, slot);
    data.opSetInput(truncop, vn, 0);
    data.opInsertBefore(truncop, op);
    return newvn;
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let vn: Varnode;
    let spc: AddrSpace;
    let madeChange: number = 0;

    switch (op.code()) {
      case OpCode.CPUI_LOAD:
      case OpCode.CPUI_STORE:
        vn = op.getIn(1)!;
        spc = op.getIn(0)!.getSpaceFromConst() as any as AddrSpace;
        if (vn.getSize() > spc.getAddrSize()) {
          vn = this.truncatePointer(spc, op, vn, 1, data);
          madeChange = 1;
        }
        if (this.propagateFlowToDef(vn))
          madeChange = 1;
        break;
      case OpCode.CPUI_CALLIND:
      case OpCode.CPUI_BRANCHIND:
        vn = op.getIn(0)!;
        spc = data.getArch().getDefaultCodeSpace();
        if (vn.getSize() > spc.getAddrSize()) {
          vn = this.truncatePointer(spc, op, vn, 0, data);
          madeChange = 1;
        }
        if (this.propagateFlowToDef(vn))
          madeChange = 1;
        break;
      case OpCode.CPUI_NEW:
        vn = op.getOut()!;
        if (this.propagateFlowToReads(vn))
          madeChange = 1;
        break;
      case OpCode.CPUI_INDIRECT:
        if (!op.isPtrFlow()) return 0;
        vn = op.getOut()!;
        if (this.propagateFlowToReads(vn))
          madeChange = 1;
        vn = op.getIn(0)!;
        if (this.propagateFlowToDef(vn))
          madeChange = 1;
        break;
      case OpCode.CPUI_COPY:
      case OpCode.CPUI_PTRSUB:
      case OpCode.CPUI_PTRADD:
        if (!op.isPtrFlow()) return 0;
        vn = op.getOut()!;
        if (this.propagateFlowToReads(vn))
          madeChange = 1;
        vn = op.getIn(0)!;
        if (this.propagateFlowToDef(vn))
          madeChange = 1;
        break;
      case OpCode.CPUI_MULTIEQUAL:
      case OpCode.CPUI_INT_ADD:
        if (!op.isPtrFlow()) return 0;
        vn = op.getOut()!;
        if (this.propagateFlowToReads(vn))
          madeChange = 1;
        for (let i = 0; i < op.numInput(); ++i) {
          vn = op.getIn(i)!;
          if (this.propagateFlowToDef(vn))
            madeChange = 1;
        }
        break;
      default:
        break;
    }
    return madeChange;
  }
}
// PART 6 continuation

// =====================================================================
// RuleNegateNegate
// =====================================================================
export class RuleNegateNegate extends Rule {
  constructor(g: string) {
    super(g, 0, "negatenegate");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleNegateNegate(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_NEGATE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const vn1: Varnode = op.getIn(0)!;
    if (!vn1.isWritten()) return 0;
    const neg2: PcodeOp = vn1.getDef()!;
    if (neg2.code() !== OpCode.CPUI_INT_NEGATE)
      return 0;
    const vn2: Varnode = neg2.getIn(0)!;
    if (vn2.isFree()) return 0;
    data.opSetInput(op, vn2, 0);
    data.opSetOpcode(op, OpCode.CPUI_COPY);
    return 1;
  }
}

// =====================================================================
// RuleConditionalMove
// =====================================================================
export class RuleConditionalMove extends Rule {
  constructor(g: string) {
    super(g, 0, "conditionalmove");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleConditionalMove(this.getGroup());
  }

  /// Check if the given Varnode is a boolean value and return the root of the expression.
  private static checkBoolean(vn: Varnode): Varnode | null {
    if (!vn.isWritten()) return null;
    const op: PcodeOp = vn.getDef()!;
    if (op.isBoolOutput()) {
      return vn;
    }
    if (op.code() === OpCode.CPUI_COPY) {
      vn = op.getIn(0)!;
      if (vn.isConstant()) {
        const val: bigint = vn.getOffset();
        if ((val & ~(1n)) === 0n)
          return vn;
      }
    }
    return null;
  }

  /// Determine if the given expression can be propagated out of the condition
  private static gatherExpression(vn: Varnode, ops: PcodeOp[], root: FlowBlock, branch: FlowBlock): boolean {
    if (vn.isConstant()) return true;
    if (vn.isFree()) return false;
    if (vn.isAddrTied()) return false;
    if (root === branch) return true;
    if (!vn.isWritten()) return true;
    const op: PcodeOp = vn.getDef()!;
    if (op.getParent() !== branch) return true;
    ops.push(op);
    let pos: number = 0;
    while (pos < ops.length) {
      const curOp: PcodeOp = ops[pos];
      pos += 1;
      if (curOp.getEvalType() === PcodeOp.special)
        return false;
      for (let i = 0; i < curOp.numInput(); ++i) {
        const in0: Varnode = curOp.getIn(i)!;
        if (in0.isFree() && !in0.isConstant()) return false;
        if (in0.isWritten() && (in0.getDef()!.getParent() === branch)) {
          if (in0.isAddrTied()) return false;
          if (in0.loneDescend()! !== curOp) return false;
          if (ops.length >= 4) return false;
          ops.push(in0.getDef()!);
        }
      }
    }
    return true;
  }

  /// Sort PcodeOps based only on order within a basic block
  private static compareOp(op0: PcodeOp, op1: PcodeOp): number {
    return op0.getSeqNum().getOrder() - op1.getSeqNum().getOrder();
  }

  /// Construct the expression after the merge
  private static constructBool(vn: Varnode, insertop: PcodeOp, ops: PcodeOp[], data: Funcdata): Varnode {
    let resvn: Varnode;
    if (ops.length > 0) {
      ops.sort(RuleConditionalMove.compareOp);
      const cloner: any = new CloneBlockOps(data);
      resvn = cloner.cloneExpression(ops, insertop);
    } else {
      resvn = vn;
    }
    return resvn;
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_MULTIEQUAL);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let bb: BlockBasic;
    let inblock0: FlowBlock;
    let inblock1: FlowBlock;
    let rootblock0: FlowBlock;
    let rootblock1: FlowBlock;

    if (op.numInput() !== 2) return 0;

    const bool0: Varnode | null = RuleConditionalMove.checkBoolean(op.getIn(0)!);
    if (bool0 === null) return 0;
    const bool1: Varnode | null = RuleConditionalMove.checkBoolean(op.getIn(1)!);
    if (bool1 === null) return 0;

    bb = op.getParent() as BlockBasic;
    inblock0 = bb.getIn(0)!;
    if (inblock0.sizeOut() === 1) {
      if (inblock0.sizeIn() !== 1) return 0;
      rootblock0 = inblock0.getIn(0)!;
    } else {
      rootblock0 = inblock0;
    }
    inblock1 = bb.getIn(1)!;
    if (inblock1.sizeOut() === 1) {
      if (inblock1.sizeIn() !== 1) return 0;
      rootblock1 = inblock1.getIn(0)!;
    } else {
      rootblock1 = inblock1;
    }
    if (rootblock0 !== rootblock1) return 0;

    const cbranch: PcodeOp | null = rootblock0.lastOp();
    if (cbranch === null) return 0;
    if (cbranch.code() !== OpCode.CPUI_CBRANCH) return 0;

    const opList0: PcodeOp[] = [];
    if (!RuleConditionalMove.gatherExpression(bool0, opList0, rootblock0, inblock0)) return 0;
    const opList1: PcodeOp[] = [];
    if (!RuleConditionalMove.gatherExpression(bool1, opList1, rootblock0, inblock1)) return 0;

    let path0istrue: boolean;
    if (rootblock0 !== inblock0)
      path0istrue = (rootblock0.getTrueOut() === inblock0);
    else
      path0istrue = (rootblock0.getTrueOut() !== inblock1);
    if (cbranch.isBooleanFlip())
      path0istrue = !path0istrue;

    if (!bool0.isConstant() && !bool1.isConstant()) {
      if (inblock0 === rootblock0) {
        let boolvn: Varnode = cbranch.getIn(1)!;
        let andorselect: boolean = path0istrue;
        if (boolvn !== op.getIn(0)!) {
          if (!boolvn.isWritten()) return 0;
          const negop: PcodeOp = boolvn.getDef()!;
          if (negop.code() !== OpCode.CPUI_BOOL_NEGATE) return 0;
          if (negop.getIn(0)! !== op.getIn(0)!) return 0;
          andorselect = !andorselect;
        }
        const opc: number = andorselect ? OpCode.CPUI_BOOL_OR : OpCode.CPUI_BOOL_AND;
        data.opUninsert(op);
        data.opSetOpcode(op, opc);
        data.opInsertBegin(op, bb);
        const firstvn: Varnode = RuleConditionalMove.constructBool(bool0, op, opList0, data);
        const secondvn: Varnode = RuleConditionalMove.constructBool(bool1, op, opList1, data);
        data.opSetInput(op, firstvn, 0);
        data.opSetInput(op, secondvn, 1);
        return 1;
      } else if (inblock1 === rootblock0) {
        let boolvn: Varnode = cbranch.getIn(1)!;
        let andorselect: boolean = !path0istrue;
        if (boolvn !== op.getIn(1)!) {
          if (!boolvn.isWritten()) return 0;
          const negop: PcodeOp = boolvn.getDef()!;
          if (negop.code() !== OpCode.CPUI_BOOL_NEGATE) return 0;
          if (negop.getIn(0)! !== op.getIn(1)!) return 0;
          andorselect = !andorselect;
        }
        data.opUninsert(op);
        const opc: number = andorselect ? OpCode.CPUI_BOOL_OR : OpCode.CPUI_BOOL_AND;
        data.opSetOpcode(op, opc);
        data.opInsertBegin(op, bb);
        const firstvn: Varnode = RuleConditionalMove.constructBool(bool1, op, opList1, data);
        const secondvn: Varnode = RuleConditionalMove.constructBool(bool0, op, opList0, data);
        data.opSetInput(op, firstvn, 0);
        data.opSetInput(op, secondvn, 1);
        return 1;
      }
      return 0;
    }

    // Below here some change is being made
    data.opUninsert(op);
    const sz: number = op.getOut()!.getSize();
    if (bool0.isConstant() && bool1.isConstant()) {
      if (bool0.getOffset() === bool1.getOffset()) {
        data.opRemoveInput(op, 1);
        data.opSetOpcode(op, OpCode.CPUI_COPY);
        data.opSetInput(op, data.newConstant(sz, bool0.getOffset()), 0);
        data.opInsertBegin(op, bb);
      } else {
        data.opRemoveInput(op, 1);
        let boolvn: Varnode = cbranch.getIn(1)!;
        const needcomplement: boolean = ((bool0.getOffset() === 0n) === path0istrue);
        if (sz === 1) {
          if (needcomplement)
            data.opSetOpcode(op, OpCode.CPUI_BOOL_NEGATE);
          else
            data.opSetOpcode(op, OpCode.CPUI_COPY);
          data.opInsertBegin(op, bb);
          data.opSetInput(op, boolvn, 0);
        } else {
          data.opSetOpcode(op, OpCode.CPUI_INT_ZEXT);
          data.opInsertBegin(op, bb);
          if (needcomplement)
            boolvn = data.opBoolNegate(boolvn, op, false);
          data.opSetInput(op, boolvn, 0);
        }
      }
    } else if (bool0.isConstant()) {
      const needcomplement: boolean = (path0istrue !== (bool0.getOffset() !== 0n));
      const opc: number = (bool0.getOffset() !== 0n) ? OpCode.CPUI_BOOL_OR : OpCode.CPUI_BOOL_AND;
      data.opSetOpcode(op, opc);
      data.opInsertBegin(op, bb);
      let boolvn: Varnode = cbranch.getIn(1)!;
      if (needcomplement)
        boolvn = data.opBoolNegate(boolvn, op, false);
      const body1: Varnode = RuleConditionalMove.constructBool(bool1, op, opList1, data);
      data.opSetInput(op, boolvn, 0);
      data.opSetInput(op, body1, 1);
    } else {
      // bool1 must be constant
      const needcomplement: boolean = (path0istrue === (bool1.getOffset() !== 0n));
      const opc: number = (bool1.getOffset() !== 0n) ? OpCode.CPUI_BOOL_OR : OpCode.CPUI_BOOL_AND;
      data.opSetOpcode(op, opc);
      data.opInsertBegin(op, bb);
      let boolvn: Varnode = cbranch.getIn(1)!;
      if (needcomplement)
        boolvn = data.opBoolNegate(boolvn, op, false);
      const body0: Varnode = RuleConditionalMove.constructBool(bool0, op, opList0, data);
      data.opSetInput(op, boolvn, 0);
      data.opSetInput(op, body0, 1);
    }
    return 1;
  }
}

// =====================================================================
// RuleFloatCast
// =====================================================================
export class RuleFloatCast extends Rule {
  constructor(g: string) {
    super(g, 0, "floatcast");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleFloatCast(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_FLOAT_FLOAT2FLOAT);
    oplist.push(OpCode.CPUI_FLOAT_TRUNC);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const vn1: Varnode = op.getIn(0)!;
    if (!vn1.isWritten()) return 0;
    const castop: PcodeOp = vn1.getDef()!;
    const opc2: number = castop.code();
    if ((opc2 !== OpCode.CPUI_FLOAT_FLOAT2FLOAT) && (opc2 !== OpCode.CPUI_FLOAT_INT2FLOAT))
      return 0;
    const opc1: number = op.code();
    const vn2: Varnode = castop.getIn(0)!;
    const insize1: number = vn1.getSize();
    const insize2: number = vn2.getSize();
    const outsize: number = op.getOut()!.getSize();

    if (vn2.isFree()) return 0;

    if ((opc2 === OpCode.CPUI_FLOAT_FLOAT2FLOAT) && (opc1 === OpCode.CPUI_FLOAT_FLOAT2FLOAT)) {
      if (insize1 > outsize) {
        data.opSetInput(op, vn2, 0);
        if (outsize === insize2)
          data.opSetOpcode(op, OpCode.CPUI_COPY);
        return 1;
      } else if (insize2 < insize1) {
        data.opSetInput(op, vn2, 0);
        return 1;
      }
    } else if ((opc2 === OpCode.CPUI_FLOAT_INT2FLOAT) && (opc1 === OpCode.CPUI_FLOAT_FLOAT2FLOAT)) {
      data.opSetInput(op, vn2, 0);
      data.opSetOpcode(op, OpCode.CPUI_FLOAT_INT2FLOAT);
      return 1;
    } else if ((opc2 === OpCode.CPUI_FLOAT_FLOAT2FLOAT) && (opc1 === OpCode.CPUI_FLOAT_TRUNC)) {
      data.opSetInput(op, vn2, 0);
      return 1;
    }

    return 0;
  }
}

// =====================================================================
// RuleIgnoreNan
// =====================================================================
export class RuleIgnoreNan extends Rule {
  constructor(g: string) {
    super(g, 0, "ignorenan");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleIgnoreNan(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_FLOAT_NAN);
  }

  /// Check if a boolean Varnode incorporates a floating-point comparison with the given value
  private static checkBackForCompare(floatVar: Varnode, root: Varnode): boolean {
    if (!root.isWritten()) return false;
    let def1: PcodeOp = root.getDef()!;
    if (!def1.isBoolOutput()) return false;
    if (def1.code() === OpCode.CPUI_BOOL_NEGATE) {
      const vn: Varnode = def1.getIn(0)!;
      if (!vn.isWritten()) return false;
      def1 = vn.getDef()!;
    }
    if (def1.getOpcode().isFloatingPointOp()) {
      if (def1.numInput() !== 2) return false;
      if (functionalEquality(floatVar, def1.getIn(0)!))
        return true;
      if (functionalEquality(floatVar, def1.getIn(1)!))
        return true;
      return false;
    }
    const opc: number = def1.code();
    if (opc !== OpCode.CPUI_BOOL_AND && opc !== OpCode.CPUI_BOOL_OR)
      return false;
    for (let i = 0; i < 2; ++i) {
      const vn: Varnode = def1.getIn(i)!;
      if (!vn.isWritten()) continue;
      const def2: PcodeOp = vn.getDef()!;
      if (!def2.isBoolOutput()) continue;
      if (!def2.getOpcode().isFloatingPointOp()) continue;
      if (def2.numInput() !== 2) continue;
      if (functionalEquality(floatVar, def2.getIn(0)!))
        return true;
      if (functionalEquality(floatVar, def2.getIn(1)!))
        return true;
    }
    return false;
  }

  /// Test if the given Varnode is produced by a NaN operation.
  private static isAnotherNan(vn: Varnode): boolean {
    if (!vn.isWritten()) return false;
    let op: PcodeOp = vn.getDef()!;
    let opc: number = op.code();
    if (opc === OpCode.CPUI_BOOL_NEGATE) {
      const vnInner: Varnode = op.getIn(0)!;
      if (!vnInner.isWritten()) return false;
      op = vnInner.getDef()!;
      opc = op.code();
    }
    return (opc === OpCode.CPUI_FLOAT_NAN);
  }

  /// Test if a boolean expression incorporates a floating-point comparison, and remove the NaN data-flow
  private static testForComparison(floatVar: Varnode, op: PcodeOp, slot: number, matchCode: number, count: { value: number }, data: Funcdata): Varnode | null {
    const opc: number = op.code();
    if (opc === matchCode) {
      const vn: Varnode = op.getIn(1 - slot)!;
      if (RuleIgnoreNan.checkBackForCompare(floatVar, vn)) {
        data.opSetOpcode(op, OpCode.CPUI_COPY);
        data.opRemoveInput(op, 1);
        data.opSetInput(op, vn, 0);
        count.value += 1;
      } else if (RuleIgnoreNan.isAnotherNan(vn)) {
        return op.getOut()!;
      }
    } else if (opc === OpCode.CPUI_INT_EQUAL || opc === OpCode.CPUI_INT_NOTEQUAL) {
      const vn: Varnode = op.getIn(1 - slot)!;
      if (RuleIgnoreNan.checkBackForCompare(floatVar, vn)) {
        data.opSetInput(op, data.newConstant(1, (matchCode === OpCode.CPUI_BOOL_OR) ? 0n : 1n), slot);
        count.value += 1;
      }
    } else if (opc === OpCode.CPUI_CBRANCH) {
      const parent: BlockBasic = op.getParent() as BlockBasic;
      let outDir: number = (matchCode === OpCode.CPUI_BOOL_OR) ? 0 : 1;
      if (op.isBooleanFlip())
        outDir = 1 - outDir;
      const outBranch: FlowBlock = parent.getOut(outDir);
      const lastOp: PcodeOp | null = outBranch.lastOp();
      if (lastOp !== null && lastOp.code() === OpCode.CPUI_CBRANCH) {
        const otherBranch: FlowBlock = parent.getOut(1 - outDir);
        if (outBranch.getOut(0) === otherBranch || outBranch.getOut(1) === otherBranch) {
          if (RuleIgnoreNan.checkBackForCompare(floatVar, lastOp.getIn(1)!)) {
            data.opSetInput(op, data.newConstant(1, (matchCode === OpCode.CPUI_BOOL_OR) ? 0n : 1n), 1);
            count.value += 1;
          }
        }
      }
    }
    return null;
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (data.getArch().nan_ignore_all) {
      data.opSetOpcode(op, OpCode.CPUI_COPY);
      data.opSetInput(op, data.newConstant(1, 0n), 0);
      return 1;
    }
    const floatVar: Varnode = op.getIn(0)!;
    if (floatVar.isFree()) return 0;
    const out1: Varnode = op.getOut()!;
    const count: { value: number } = { value: 0 };
    const descend1: PcodeOp[] = Array.from(out1.descend);
    for (let idx1 = 0; idx1 < descend1.length; ++idx1) {
      const boolRead1: PcodeOp = descend1[idx1];
      let out2: Varnode | null;
      let matchCode: number = OpCode.CPUI_BOOL_OR;
      if (boolRead1.code() === OpCode.CPUI_BOOL_NEGATE) {
        matchCode = OpCode.CPUI_BOOL_AND;
        out2 = boolRead1.getOut()!;
      } else {
        out2 = RuleIgnoreNan.testForComparison(floatVar, boolRead1, boolRead1.getSlot(out1), matchCode, count, data);
      }
      if (out2 === null) continue;
      const descend2: PcodeOp[] = Array.from(out2.descend);
      for (let idx2 = 0; idx2 < descend2.length; ++idx2) {
        const boolRead2: PcodeOp = descend2[idx2];
        const out3: Varnode | null = RuleIgnoreNan.testForComparison(floatVar, boolRead2, boolRead2.getSlot(out2), matchCode, count, data);
        if (out3 === null) continue;
        const descend3: PcodeOp[] = Array.from(out3.descend);
        for (let idx3 = 0; idx3 < descend3.length; ++idx3) {
          const boolRead3: PcodeOp = descend3[idx3];
          RuleIgnoreNan.testForComparison(floatVar, boolRead3, boolRead3.getSlot(out3), matchCode, count, data);
        }
      }
    }
    return (count.value > 0) ? 1 : 0;
  }
}

// =====================================================================
// RuleUnsigned2Float
// =====================================================================
export class RuleUnsigned2Float extends Rule {
  constructor(g: string) {
    super(g, 0, "unsigned2float");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleUnsigned2Float(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_FLOAT_INT2FLOAT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const invn: Varnode = op.getIn(0)!;
    if (!invn.isWritten()) return 0;
    const orop: PcodeOp = invn.getDef()!;
    if (orop.code() !== OpCode.CPUI_INT_OR) return 0;
    if (!orop.getIn(0)!.isWritten() || !orop.getIn(1)!.isWritten()) return 0;
    let shiftop: PcodeOp = orop.getIn(0)!.getDef()!;
    let andop: PcodeOp;
    if (shiftop.code() !== OpCode.CPUI_INT_RIGHT) {
      andop = shiftop;
      shiftop = orop.getIn(1)!.getDef()!;
    } else {
      andop = orop.getIn(1)!.getDef()!;
    }
    if (shiftop.code() !== OpCode.CPUI_INT_RIGHT) return 0;
    if (!shiftop.getIn(1)!.constantMatch(1n)) return 0;
    const basevn: Varnode = shiftop.getIn(0)!;
    if (basevn.isFree()) return 0;
    if (andop.code() === OpCode.CPUI_INT_ZEXT) {
      if (!andop.getIn(0)!.isWritten()) return 0;
      andop = andop.getIn(0)!.getDef()!;
    }
    if (andop.code() !== OpCode.CPUI_INT_AND) return 0;
    if (!andop.getIn(1)!.constantMatch(1n)) return 0;
    let vn: Varnode = andop.getIn(0)!;
    if (basevn !== vn) {
      if (!vn.isWritten()) return 0;
      const subop: PcodeOp = vn.getDef()!;
      if (subop.code() !== OpCode.CPUI_SUBPIECE) return 0;
      if (subop.getIn(1)!.getOffset() !== 0n) return 0;
      vn = subop.getIn(0)!;
      if (basevn !== vn) return 0;
    }
    const outvn: Varnode = op.getOut()!;
    for (const addop of outvn.descend) {
      if (addop.code() !== OpCode.CPUI_FLOAT_ADD) continue;
      if (addop.getIn(0)! !== outvn) continue;
      if (addop.getIn(1)! !== outvn) continue;
      const zextop: PcodeOp = data.newOp(1, addop.getAddr());
      data.opSetOpcode(zextop, OpCode.CPUI_INT_ZEXT);
      const zextout: Varnode = data.newUniqueOut((basevn.getSize() <= 4 ? 4 : 8), zextop);
      data.opSetOpcode(addop, OpCode.CPUI_FLOAT_INT2FLOAT);
      data.opRemoveInput(addop, 1);
      data.opSetInput(zextop, basevn, 0);
      data.opSetInput(addop, zextout, 0);
      data.opInsertBefore(zextop, addop);
      return 1;
    }
    return 0;
  }
}

// =====================================================================
// RuleInt2FloatCollapse
// =====================================================================
export class RuleInt2FloatCollapse extends Rule {
  constructor(g: string) {
    super(g, 0, "int2floatcollapse");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleInt2FloatCollapse(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_FLOAT_INT2FLOAT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (!op.getIn(0)!.isWritten()) return 0;
    const zextop: PcodeOp = op.getIn(0)!.getDef()!;
    if (zextop.code() !== OpCode.CPUI_INT_ZEXT) return 0;
    const basevn: Varnode = zextop.getIn(0)!;
    if (basevn.isFree()) return 0;
    const multiop: PcodeOp | null = op.getOut()!.loneDescend()!;
    if (multiop === null) return 0;
    if (multiop.code() !== OpCode.CPUI_MULTIEQUAL) return 0;
    if (multiop.numInput() !== 2) return 0;
    const slot: number = multiop.getSlot(op.getOut()!);
    const otherout: Varnode = multiop.getIn(1 - slot)!;
    if (!otherout.isWritten()) return 0;
    const op2: PcodeOp = otherout.getDef()!;
    if (op2.code() !== OpCode.CPUI_FLOAT_INT2FLOAT) return 0;
    if (basevn !== op2.getIn(0)!) return 0;
    let dir2unsigned: number;
    const slot1Out = { value: 0 };
    const condResult = FlowBlock.findCondition(multiop.getParent(), slot, multiop.getParent(), 1 - slot, slot1Out);
    if (condResult === null) return 0;
    const cond: FlowBlock = condResult;
    dir2unsigned = slot1Out.value;
    const cbranchOp: PcodeOp | null = cond.lastOp();
    if (cbranchOp === null || cbranchOp.code() !== OpCode.CPUI_CBRANCH) return 0;
    if (!cbranchOp.getIn(1)!.isWritten()) return 0;
    if (cbranchOp.isBooleanFlip()) return 0;
    const compare: PcodeOp = cbranchOp.getIn(1)!.getDef()!;
    if (compare.code() !== OpCode.CPUI_INT_SLESS) return 0;
    if (compare.getIn(1)!.constantMatch(0n)) {
      if (compare.getIn(0)! !== basevn) return 0;
      if (dir2unsigned !== 1) return 0;
    } else if (compare.getIn(0)!.constantMatch(calc_mask(basevn.getSize()))) {
      if (compare.getIn(1)! !== basevn) return 0;
      if (dir2unsigned === 1) return 0;
    } else {
      return 0;
    }
    const outbl: BlockBasic = multiop.getParent() as BlockBasic;
    data.opUninsert(multiop);
    data.opSetOpcode(multiop, OpCode.CPUI_FLOAT_INT2FLOAT);
    data.opRemoveInput(multiop, 0);
    const newzext: PcodeOp = data.newOp(1, multiop.getAddr());
    data.opSetOpcode(newzext, OpCode.CPUI_INT_ZEXT);
    const newout: Varnode = data.newUniqueOut((basevn.getSize() <= 4 ? 4 : 8), newzext);
    data.opSetInput(newzext, basevn, 0);
    data.opSetInput(multiop, newout, 0);
    data.opInsertBegin(multiop, outbl);
    data.opInsertBefore(newzext, multiop);
    return 1;
  }
}

// =====================================================================
// RuleFuncPtrEncoding
// =====================================================================
export class RuleFuncPtrEncoding extends Rule {
  constructor(g: string) {
    super(g, 0, "funcptrencoding");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleFuncPtrEncoding(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_CALLIND);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const align: number = data.getArch().funcptr_align;
    if (align === 0) return 0;
    const vn: Varnode = op.getIn(0)!;
    if (!vn.isWritten()) return 0;
    const andop: PcodeOp = vn.getDef()!;
    if (andop.code() !== OpCode.CPUI_INT_AND) return 0;
    const maskvn: Varnode = andop.getIn(1)!;
    if (!maskvn.isConstant()) return 0;
    const val: bigint = maskvn.getOffset();
    const testmask: bigint = calc_mask(maskvn.getSize());
    let slide: bigint = 0xFFFFFFFFFFFFFFFFn;
    slide = slide << BigInt(align);
    if ((testmask & slide) === val) {
      data.opRemoveInput(andop, 1);
      data.opSetOpcode(andop, OpCode.CPUI_COPY);
      return 1;
    }
    return 0;
  }
}

// =====================================================================
// RuleThreeWayCompare
// =====================================================================
export class RuleThreeWayCompare extends Rule {
  constructor(g: string) {
    super(g, 0, "threewaycomp");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleThreeWayCompare(this.getGroup());
  }

  /// Make sure comparisons match properly for a three-way
  static testCompareEquivalence(lessop: PcodeOp, lessequalop: PcodeOp): number {
    let twoLessThan: boolean;
    if (lessop.code() === OpCode.CPUI_INT_LESS) {
      if (lessequalop.code() === OpCode.CPUI_INT_LESSEQUAL)
        twoLessThan = false;
      else if (lessequalop.code() === OpCode.CPUI_INT_LESS)
        twoLessThan = true;
      else
        return -1;
    } else if (lessop.code() === OpCode.CPUI_INT_SLESS) {
      if (lessequalop.code() === OpCode.CPUI_INT_SLESSEQUAL)
        twoLessThan = false;
      else if (lessequalop.code() === OpCode.CPUI_INT_SLESS)
        twoLessThan = true;
      else
        return -1;
    } else if (lessop.code() === OpCode.CPUI_FLOAT_LESS) {
      if (lessequalop.code() === OpCode.CPUI_FLOAT_LESSEQUAL)
        twoLessThan = false;
      else
        return -1;
    } else {
      return -1;
    }
    const a1: Varnode = lessop.getIn(0)!;
    const a2: Varnode = lessequalop.getIn(0)!;
    const b1: Varnode = lessop.getIn(1)!;
    const b2: Varnode = lessequalop.getIn(1)!;
    let res: number = 0;
    if (a1 !== a2) {
      if ((!a1.isConstant()) || (!a2.isConstant())) return -1;
      if ((a1.getOffset() !== a2.getOffset()) && twoLessThan) {
        if (a2.getOffset() + 1n === a1.getOffset()) {
          twoLessThan = false;
        } else if (a1.getOffset() + 1n === a2.getOffset()) {
          twoLessThan = false;
          res = 1;
        } else {
          return -1;
        }
      }
    }
    if (b1 !== b2) {
      if ((!b1.isConstant()) || (!b2.isConstant())) return -1;
      if ((b1.getOffset() !== b2.getOffset()) && twoLessThan) {
        if (b1.getOffset() + 1n === b2.getOffset()) {
          twoLessThan = false;
        } else if (b2.getOffset() + 1n === b1.getOffset()) {
          twoLessThan = false;
          res = 1;
        }
      } else {
        return -1;
      }
    }
    if (twoLessThan)
      return -1;
    return res;
  }

  /// Detect a three-way calculation
  static detectThreeWay(op: PcodeOp, isPartialRef: { value: boolean }): PcodeOp | null {
    let vn1: Varnode;
    let vn2: Varnode;
    let tmpvn: Varnode;
    let zext1: PcodeOp;
    let zext2: PcodeOp;
    let addop: PcodeOp;
    let lessop: PcodeOp;
    let lessequalop: PcodeOp;
    let mask: bigint;

    vn2 = op.getIn(1)!;
    if (vn2.isConstant()) {
      // Form 1 :  (z + z) - 1
      mask = calc_mask(vn2.getSize());
      if (mask !== vn2.getOffset()) return null;
      vn1 = op.getIn(0)!;
      if (!vn1.isWritten()) return null;
      addop = vn1.getDef()!;
      if (addop.code() !== OpCode.CPUI_INT_ADD) return null;
      tmpvn = addop.getIn(0)!;
      if (!tmpvn.isWritten()) return null;
      zext1 = tmpvn.getDef()!;
      if (zext1.code() !== OpCode.CPUI_INT_ZEXT) return null;
      tmpvn = addop.getIn(1)!;
      if (!tmpvn.isWritten()) return null;
      zext2 = tmpvn.getDef()!;
      if (zext2.code() !== OpCode.CPUI_INT_ZEXT) return null;
    } else if (vn2.isWritten()) {
      const tmpop: PcodeOp = vn2.getDef()!;
      if (tmpop.code() === OpCode.CPUI_INT_ZEXT) {
        // Form 2 : (z - 1) + z
        zext2 = tmpop;
        vn1 = op.getIn(0)!;
        if (!vn1.isWritten()) return null;
        addop = vn1.getDef()!;
        if (addop.code() !== OpCode.CPUI_INT_ADD) {
          zext1 = addop;
          if (zext1.code() !== OpCode.CPUI_INT_ZEXT)
            return null;
          isPartialRef.value = true;
        } else {
          tmpvn = addop.getIn(1)!;
          if (!tmpvn.isConstant()) return null;
          mask = calc_mask(tmpvn.getSize());
          if (mask !== tmpvn.getOffset()) return null;
          tmpvn = addop.getIn(0)!;
          if (!tmpvn.isWritten()) return null;
          zext1 = tmpvn.getDef()!;
          if (zext1.code() !== OpCode.CPUI_INT_ZEXT) return null;
        }
      } else if (tmpop.code() === OpCode.CPUI_INT_ADD) {
        // Form 3 : z + (z - 1)
        addop = tmpop;
        vn1 = op.getIn(0)!;
        if (!vn1.isWritten()) return null;
        zext1 = vn1.getDef()!;
        if (zext1.code() !== OpCode.CPUI_INT_ZEXT) return null;
        tmpvn = addop.getIn(1)!;
        if (!tmpvn.isConstant()) return null;
        mask = calc_mask(tmpvn.getSize());
        if (mask !== tmpvn.getOffset()) return null;
        tmpvn = addop.getIn(0)!;
        if (!tmpvn.isWritten()) return null;
        zext2 = tmpvn.getDef()!;
        if (zext2.code() !== OpCode.CPUI_INT_ZEXT) return null;
      } else {
        return null;
      }
    } else {
      return null;
    }

    vn1 = zext1!.getIn(0)!;
    if (!vn1.isWritten()) return null;
    vn2 = zext2!.getIn(0)!;
    if (!vn2.isWritten()) return null;
    lessop = vn1.getDef()!;
    lessequalop = vn2.getDef()!;
    const opc: number = lessop.code();
    if ((opc !== OpCode.CPUI_INT_LESS) && (opc !== OpCode.CPUI_INT_SLESS) && (opc !== OpCode.CPUI_FLOAT_LESS)) {
      const tmpop2: PcodeOp = lessop;
      lessop = lessequalop;
      lessequalop = tmpop2;
    }
    const form: number = RuleThreeWayCompare.testCompareEquivalence(lessop, lessequalop);
    if (form < 0)
      return null;
    if (form === 1) {
      const tmpop2: PcodeOp = lessop;
      lessop = lessequalop;
      lessequalop = tmpop2;
    }
    return lessop;
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_SLESS);
    oplist.push(OpCode.CPUI_INT_SLESSEQUAL);
    oplist.push(OpCode.CPUI_INT_EQUAL);
    oplist.push(OpCode.CPUI_INT_NOTEQUAL);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let constSlot: number = 0;
    let form: number;
    let tmpvn: Varnode = op.getIn(constSlot)!;
    if (!tmpvn.isConstant()) {
      constSlot = 1;
      tmpvn = op.getIn(constSlot)!;
      if (!tmpvn.isConstant()) return 0;
    }
    const val: bigint = tmpvn.getOffset();
    if (val <= 2n)
      form = Number(val) + 1;
    else if (val === calc_mask(tmpvn.getSize()))
      form = 0;
    else
      return 0;

    tmpvn = op.getIn(1 - constSlot)!;
    if (!tmpvn.isWritten()) return 0;
    if (tmpvn.getDef()!.code() !== OpCode.CPUI_INT_ADD) return 0;
    const isPartialRef: { value: boolean } = { value: false };
    const lessop: PcodeOp | null = RuleThreeWayCompare.detectThreeWay(tmpvn.getDef()!, isPartialRef);
    if (lessop === null)
      return 0;
    if (isPartialRef.value) {
      if (form === 0)
        return 0;
      form -= 1;
    }
    form <<= 1;
    if (constSlot === 1)
      form += 1;
    const lessform: number = lessop.code();  // Either INT_LESS, INT_SLESS, or FLOAT_LESS
    form <<= 2;
    if (op.code() === OpCode.CPUI_INT_SLESSEQUAL)
      form += 1;
    else if (op.code() === OpCode.CPUI_INT_EQUAL)
      form += 2;
    else if (op.code() === OpCode.CPUI_INT_NOTEQUAL)
      form += 3;

    const bvn: Varnode = lessop.getIn(0)!;
    const avn: Varnode = lessop.getIn(1)!;
    if ((!avn.isConstant()) && (avn.isFree())) return 0;
    if ((!bvn.isConstant()) && (bvn.isFree())) return 0;

    let resolvedLessform: number = lessform;
    switch (form) {
      case 1:   // -1  s<= threeway   =>   always true
      case 21:  // threeway  s<=  1   =>   always true
        data.opSetOpcode(op, OpCode.CPUI_INT_EQUAL);
        data.opSetInput(op, data.newConstant(1, 0n), 0);
        data.opSetInput(op, data.newConstant(1, 0n), 1);
        break;
      case 4:   // threeway  s<  -1   =>   always false
      case 16:  //  1  s<  threeway   =>   always false
        data.opSetOpcode(op, OpCode.CPUI_INT_NOTEQUAL);
        data.opSetInput(op, data.newConstant(1, 0n), 0);
        data.opSetInput(op, data.newConstant(1, 0n), 1);
        break;
      case 2:   // -1  ==  threeway   =>   a < b
      case 5:   // threeway  s<= -1   =>   a < b
      case 6:   // threeway  ==  -1   =>   a < b
      case 12:  // threeway  s<   0   =>   a < b
        data.opSetOpcode(op, resolvedLessform);
        data.opSetInput(op, avn, 0);
        data.opSetInput(op, bvn, 1);
        break;
      case 13:  // threeway  s<=  0   =>   a <= b
      case 19:  //  1  !=  threeway   =>   a <= b
      case 20:  // threeway  s<   1   =>   a <= b
      case 23:  // threeway  !=   1   =>   a <= b
        data.opSetOpcode(op, resolvedLessform + 1);  // LESSEQUAL form
        data.opSetInput(op, avn, 0);
        data.opSetInput(op, bvn, 1);
        break;
      case 8:   //  0  s<  threeway   =>   a > b
      case 17:  //  1  s<= threeway   =>   a > b
      case 18:  //  1  ==  threeway   =>   a > b
      case 22:  // threeway  ==   1   =>   a > b
        data.opSetOpcode(op, resolvedLessform);
        data.opSetInput(op, bvn, 0);
        data.opSetInput(op, avn, 1);
        break;
      case 0:   // -1  s<  threeway   =>   a >= b
      case 3:   // -1  !=  threeway   =>   a >= b
      case 7:   // threeway  !=  -1   =>   a >= b
      case 9:   //  0  s<= threeway   =>   a >= b
        data.opSetOpcode(op, resolvedLessform + 1);  // LESSEQUAL form
        data.opSetInput(op, bvn, 0);
        data.opSetInput(op, avn, 1);
        break;
      case 10:  //  0  ==  threeway   =>   a == b
      case 14:  // threeway  ==   0   =>   a == b
        if (resolvedLessform === OpCode.CPUI_FLOAT_LESS)
          resolvedLessform = OpCode.CPUI_FLOAT_EQUAL;
        else
          resolvedLessform = OpCode.CPUI_INT_EQUAL;
        data.opSetOpcode(op, resolvedLessform);
        data.opSetInput(op, avn, 0);
        data.opSetInput(op, bvn, 1);
        break;
      case 11:  //  0  !=  threeway   =>   a != b
      case 15:  // threeway  !=   0   =>   a != b
        if (resolvedLessform === OpCode.CPUI_FLOAT_LESS)
          resolvedLessform = OpCode.CPUI_FLOAT_NOTEQUAL;
        else
          resolvedLessform = OpCode.CPUI_INT_NOTEQUAL;
        data.opSetOpcode(op, resolvedLessform);
        data.opSetInput(op, avn, 0);
        data.opSetInput(op, bvn, 1);
        break;
      default:
        return 0;
    }
    return 1;
  }
}

// =====================================================================
// RulePopcountBoolXor
// =====================================================================
export class RulePopcountBoolXor extends Rule {
  constructor(g: string) {
    super(g, 0, "popcountboolxor");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RulePopcountBoolXor(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_POPCOUNT);
  }

  /// Extract boolean Varnode producing bit at given Varnode and position
  static getBooleanResult(vn: Varnode, bitPos: number, constRes: { value: number }): Varnode | null {
    constRes.value = -1;
    let mask: bigint = 1n;
    mask <<= BigInt(bitPos);
    let vn0: Varnode;
    let vn1: Varnode;
    let sa: number;
    for (;;) {
      if (vn.isConstant()) {
        constRes.value = Number((vn.getOffset() >> BigInt(bitPos)) & 1n);
        return null;
      }
      if (!vn.isWritten()) return null;
      if (bitPos === 0 && vn.getSize() === 1 && vn.getNZMask() === mask)
        return vn;
      const op: PcodeOp = vn.getDef()!;
      switch (op.code()) {
        case OpCode.CPUI_INT_AND:
          if (!op.getIn(1)!.isConstant()) return null;
          vn = op.getIn(0)!;
          break;
        case OpCode.CPUI_INT_XOR:
        case OpCode.CPUI_INT_OR:
          vn0 = op.getIn(0)!;
          vn1 = op.getIn(1)!;
          if ((vn0.getNZMask() & mask) !== 0n) {
            if ((vn1.getNZMask() & mask) !== 0n)
              return null;
            vn = vn0;
          } else if ((vn1.getNZMask() & mask) !== 0n) {
            vn = vn1;
          } else {
            return null;
          }
          break;
        case OpCode.CPUI_INT_ZEXT:
        case OpCode.CPUI_INT_SEXT:
          vn = op.getIn(0)!;
          if (bitPos >= vn.getSize() * 8) return null;
          break;
        case OpCode.CPUI_SUBPIECE:
          sa = Number(op.getIn(1)!.getOffset()) * 8;
          bitPos += sa;
          mask <<= BigInt(sa);
          vn = op.getIn(0)!;
          break;
        case OpCode.CPUI_PIECE:
          vn0 = op.getIn(0)!;
          vn1 = op.getIn(1)!;
          sa = vn1.getSize() * 8;
          if (bitPos >= sa) {
            vn = vn0;
            bitPos -= sa;
            mask >>= BigInt(sa);
          } else {
            vn = vn1;
          }
          break;
        case OpCode.CPUI_INT_LEFT:
          vn1 = op.getIn(1)!;
          if (!vn1.isConstant()) return null;
          sa = Number(vn1.getOffset());
          if (sa > bitPos) return null;
          bitPos -= sa;
          mask >>= BigInt(sa);
          vn = op.getIn(0)!;
          break;
        case OpCode.CPUI_INT_RIGHT:
        case OpCode.CPUI_INT_SRIGHT:
          vn1 = op.getIn(1)!;
          if (!vn1.isConstant()) return null;
          sa = Number(vn1.getOffset());
          vn = op.getIn(0)!;
          bitPos += sa;
          if (bitPos >= vn.getSize() * 8) return null;
          mask <<= BigInt(sa);
          break;
        default:
          return null;
      }
    }
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const outVn: Varnode = op.getOut()!;

    for (const baseOp of outVn.descend) {
      if (baseOp.code() !== OpCode.CPUI_INT_AND) continue;
      const tmpVn: Varnode = baseOp.getIn(1)!;
      if (!tmpVn.isConstant()) continue;
      if (tmpVn.getOffset() !== 1n) continue;
      if (tmpVn.getSize() !== 1) continue;
      const inVn: Varnode = op.getIn(0)!;
      if (!inVn.isWritten()) return 0;
      const count: number = popcount(inVn.getNZMask());
      if (count === 1) {
        const leastPos: number = leastsigbit_set(inVn.getNZMask());
        const constRes: { value: number } = { value: 0 };
        const b1: Varnode | null = RulePopcountBoolXor.getBooleanResult(inVn, leastPos, constRes);
        if (b1 === null) continue;
        data.opSetOpcode(baseOp, OpCode.CPUI_COPY);
        data.opRemoveInput(baseOp, 1);
        data.opSetInput(baseOp, b1, 0);
        return 1;
      }
      if (count === 2) {
        const pos0: number = leastsigbit_set(inVn.getNZMask());
        const pos1: number = mostsigbit_set(inVn.getNZMask());
        const constRes0: { value: number } = { value: 0 };
        const constRes1: { value: number } = { value: 0 };
        let b1: Varnode | null = RulePopcountBoolXor.getBooleanResult(inVn, pos0, constRes0);
        if (b1 === null && constRes0.value !== 1) continue;
        let b2: Varnode | null = RulePopcountBoolXor.getBooleanResult(inVn, pos1, constRes1);
        if (b2 === null && constRes1.value !== 1) continue;
        if (b1 === null && b2 === null) continue;
        if (b1 === null)
          b1 = data.newConstant(1, 1n);
        if (b2 === null)
          b2 = data.newConstant(1, 1n);
        data.opSetOpcode(baseOp, OpCode.CPUI_INT_XOR);
        data.opSetInput(baseOp, b1, 0);
        data.opSetInput(baseOp, b2, 1);
        return 1;
      }
    }
    return 0;
  }
}

// =====================================================================
// RulePiecePathology
// =====================================================================
export class RulePiecePathology extends Rule {
  constructor(g: string) {
    super(g, 0, "piecepathology");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RulePiecePathology(this.getGroup());
  }

  /// Return true if concatenating with a SUBPIECE of the given Varnode is unusual
  private static isPathology(vn: Varnode, data: Funcdata): boolean {
    const worklist: PcodeOp[] = [];
    let pos: number = 0;
    let slot: number = 0;
    let res: boolean = false;
    for (;;) {
      if (vn.isInput() && !vn.isPersist()) {
        res = true;
        break;
      }
      let op: PcodeOp | null = vn.getDef()!;
      while (!res && op !== null) {
        switch (op.code()) {
          case OpCode.CPUI_COPY:
            vn = op.getIn(0)!;
            op = vn.getDef()!;
            break;
          case OpCode.CPUI_MULTIEQUAL:
            if (!op.isMark()) {
              op.setMark();
              worklist.push(op);
            }
            op = null;
            break;
          case OpCode.CPUI_INDIRECT:
            if (op.getIn(1)!.getSpace() !== null && op.getIn(1)!.getSpace()!.getType() === spacetype.IPTR_IOP) {
              const callOp: PcodeOp | null = PcodeOp.getOpFromConst(op.getIn(1)!.getAddr());
              if (callOp !== null && callOp.isCall()) {
                const fspec: FuncCallSpecs | null = data.getCallSpecs(callOp);
                if (fspec !== null && !fspec.isOutputActive()) {
                  res = true;
                }
              }
            }
            op = null;
            break;
          case OpCode.CPUI_CALL:
          case OpCode.CPUI_CALLIND:
          {
            const fspec: FuncCallSpecs | null = data.getCallSpecs(op);
            if (fspec !== null && !fspec.isOutputActive()) {
              res = true;
            }
            op = null;
            break;
          }
          default:
            op = null;
            break;
        }
      }
      if (res) break;
      if (pos >= worklist.length) break;
      op = worklist[pos];
      if (slot < op.numInput()) {
        vn = op.getIn(slot)!;
        slot += 1;
      } else {
        pos += 1;
        if (pos >= worklist.length) break;
        vn = worklist[pos].getIn(0)!;
        slot = 1;
      }
    }
    for (let i = 0; i < worklist.length; ++i)
      worklist[i].clearMark();
    return res;
  }

  /// Given a known pathological concatenation, trace it forward to CALLs and RETURNs
  private static tracePathologyForward(op: PcodeOp, data: Funcdata): number {
    let count: number = 0;
    let fProto: FuncCallSpecs | null;
    const worklist: PcodeOp[] = [];
    let pos: number = 0;
    op.setMark();
    worklist.push(op);
    while (pos < worklist.length) {
      let curOp: PcodeOp = worklist[pos];
      pos += 1;
      const outVn: Varnode = curOp.getOut()!;
      for (const descendOp of outVn.descend) {
        curOp = descendOp;
        switch (curOp.code()) {
          case OpCode.CPUI_COPY:
          case OpCode.CPUI_INDIRECT:
          case OpCode.CPUI_MULTIEQUAL:
            if (!curOp.isMark()) {
              curOp.setMark();
              worklist.push(curOp);
            }
            break;
          case OpCode.CPUI_CALL:
          case OpCode.CPUI_CALLIND:
            fProto = data.getCallSpecs(curOp);
            if (fProto !== null && !fProto.isInputActive() && !fProto.isInputLocked()) {
              const bytesConsumed: number = op.getIn(1)!.getSize();
              for (let i = 1; i < curOp.numInput(); ++i) {
                if (curOp.getIn(i)! === outVn) {
                  if (fProto.setInputBytesConsumed(i, bytesConsumed))
                    count += 1;
                }
              }
            }
            break;
          case OpCode.CPUI_RETURN:
            if (!data.getFuncProto().isOutputLocked()) {
              if (data.getFuncProto().setReturnBytesConsumed(op.getIn(1)!.getSize()))
                count += 1;
            }
            break;
          default:
            break;
        }
      }
    }
    for (let i = 0; i < worklist.length; ++i)
      worklist[i].clearMark();
    return count;
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_PIECE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const vn: Varnode = op.getIn(0)!;
    if (!vn.isWritten()) return 0;
    const subOp: PcodeOp = vn.getDef()!;

    const opc: number = subOp.code();
    if (opc === OpCode.CPUI_SUBPIECE) {
      if (subOp.getIn(1)!.getOffset() === 0n) return 0;
      if (!RulePiecePathology.isPathology(subOp.getIn(0)!, data)) return 0;
    } else if (opc === OpCode.CPUI_INDIRECT) {
      if (!subOp.isIndirectCreation()) return 0;
      const lsbVn: Varnode = op.getIn(1)!;
      if (!lsbVn.isWritten()) return 0;
      const lsbOp: PcodeOp = lsbVn.getDef()!;
      if ((lsbOp.getEvalType() & (PcodeOp.binary | PcodeOp.unary)) === 0) {
        if (!lsbOp.isCall()) return 0;
        const fc: FuncCallSpecs | null = data.getCallSpecs(lsbOp);
        if (fc === null) return 0;
        if (!fc.isOutputLocked()) return 0;
      }
      let addr: Address = lsbVn.getAddr();
      if (addr.getSpace()!.isBigEndian())
        addr = addr.subtract(BigInt(vn.getSize()));
      else
        addr = addr.add(BigInt(lsbVn.getSize()));
      if (!addr.equals(vn.getAddr())) return 0;
    } else {
      return 0;
    }
    return RulePiecePathology.tracePathologyForward(op, data);
  }
}

// =====================================================================
// RuleXorSwap
// =====================================================================
export class RuleXorSwap extends Rule {
  constructor(g: string) {
    super(g, 0, "xorswap");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleXorSwap(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_XOR);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    for (let i = 0; i < 2; ++i) {
      const vn: Varnode = op.getIn(i)!;
      if (!vn.isWritten()) continue;
      const op2: PcodeOp = vn.getDef()!;
      if (op2.code() !== OpCode.CPUI_INT_XOR) continue;
      const othervn: Varnode = op.getIn(1 - i)!;
      const vn0: Varnode = op2.getIn(0)!;
      const vn1: Varnode = op2.getIn(1)!;
      if (othervn === vn0 && !vn1.isFree()) {
        data.opRemoveInput(op, 1);
        data.opSetOpcode(op, OpCode.CPUI_COPY);
        data.opSetInput(op, vn1, 0);
        return 1;
      } else if (othervn === vn1 && !vn0.isFree()) {
        data.opRemoveInput(op, 1);
        data.opSetOpcode(op, OpCode.CPUI_COPY);
        data.opSetInput(op, vn0, 0);
        return 1;
      }
    }
    return 0;
  }
}

// =====================================================================
// RuleLzcountShiftBool
// =====================================================================
export class RuleLzcountShiftBool extends Rule {
  constructor(g: string) {
    super(g, 0, "lzcountshiftbool");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleLzcountShiftBool(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_LZCOUNT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const outVn: Varnode = op.getOut()!;
    const max_return: bigint = BigInt(8 * op.getIn(0)!.getSize());
    if (popcount(max_return) !== 1) {
      return 0;
    }

    for (const baseOp of outVn.descend) {
      if (baseOp.code() !== OpCode.CPUI_INT_RIGHT && baseOp.code() !== OpCode.CPUI_INT_SRIGHT) continue;
      const vn1: Varnode = baseOp.getIn(1)!;
      if (!vn1.isConstant()) continue;
      const shift: bigint = vn1.getOffset();
      if ((max_return >> shift) === 1n) {
        // Becomes a comparison with zero
        const newOp: PcodeOp = data.newOp(2, baseOp.getAddr());
        data.opSetOpcode(newOp, OpCode.CPUI_INT_EQUAL);
        const b: Varnode = data.newConstant(op.getIn(0)!.getSize(), 0n);
        data.opSetInput(newOp, op.getIn(0)!, 0);
        data.opSetInput(newOp, b, 1);

        // OpCode.CPUI_INT_EQUAL must produce a 1-byte boolean result
        const eqResVn: Varnode = data.newUniqueOut(1, newOp);

        data.opInsertBefore(newOp, baseOp);

        data.opRemoveInput(baseOp, 1);
        if (baseOp.getOut()!.getSize() === 1)
          data.opSetOpcode(baseOp, OpCode.CPUI_COPY);
        else
          data.opSetOpcode(baseOp, OpCode.CPUI_INT_ZEXT);
        data.opSetInput(baseOp, eqResVn, 0);
        return 1;
      }
    }
    return 0;
  }
}

// =====================================================================
// RuleFloatSign
// =====================================================================
export class RuleFloatSign extends Rule {
  constructor(g: string) {
    super(g, 0, "floatsign");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleFloatSign(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    const list: number[] = [
      OpCode.CPUI_FLOAT_EQUAL, OpCode.CPUI_FLOAT_NOTEQUAL, OpCode.CPUI_FLOAT_LESS, OpCode.CPUI_FLOAT_LESSEQUAL, OpCode.CPUI_FLOAT_NAN,
      OpCode.CPUI_FLOAT_ADD, OpCode.CPUI_FLOAT_DIV, OpCode.CPUI_FLOAT_MULT, OpCode.CPUI_FLOAT_SUB, OpCode.CPUI_FLOAT_NEG, OpCode.CPUI_FLOAT_ABS,
      OpCode.CPUI_FLOAT_SQRT, OpCode.CPUI_FLOAT_FLOAT2FLOAT, OpCode.CPUI_FLOAT_CEIL, OpCode.CPUI_FLOAT_FLOOR, OpCode.CPUI_FLOAT_ROUND,
      OpCode.CPUI_FLOAT_INT2FLOAT, OpCode.CPUI_FLOAT_TRUNC
    ];
    oplist.push(...list);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let res: number = 0;
    const opc: number = op.code();
    if (opc !== OpCode.CPUI_FLOAT_INT2FLOAT) {
      let vn: Varnode = op.getIn(0)!;
      if (vn.isWritten()) {
        const signOp: PcodeOp = vn.getDef()!;
        const resCode: number = TypeOp.floatSignManipulation(signOp);
        if (resCode !== OpCode.CPUI_MAX) {
          data.opRemoveInput(signOp, 1);
          data.opSetOpcode(signOp, resCode);
          res = 1;
        }
      }
      if (op.numInput() === 2) {
        vn = op.getIn(1)!;
        if (vn.isWritten()) {
          const signOp: PcodeOp = vn.getDef()!;
          const resCode: number = TypeOp.floatSignManipulation(signOp);
          if (resCode !== OpCode.CPUI_MAX) {
            data.opRemoveInput(signOp, 1);
            data.opSetOpcode(signOp, resCode);
            res = 1;
          }
        }
      }
    }
    if (op.isBoolOutput() || opc === OpCode.CPUI_FLOAT_TRUNC)
      return res;
    const outvn: Varnode = op.getOut()!;
    for (const readOp of outvn.descend) {
      const resCode: number = TypeOp.floatSignManipulation(readOp);
      if (resCode !== OpCode.CPUI_MAX) {
        data.opRemoveInput(readOp, 1);
        data.opSetOpcode(readOp, resCode);
        res = 1;
      }
    }
    return res;
  }
}

// =====================================================================
// RuleFloatSignCleanup
// =====================================================================
export class RuleFloatSignCleanup extends Rule {
  constructor(g: string) {
    super(g, 0, "floatsigncleanup");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleFloatSignCleanup(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_AND);
    oplist.push(OpCode.CPUI_INT_XOR);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (op.getOut()!.getType().getMetatype() !== type_metatype.TYPE_FLOAT) {
      return 0;
    }
    const opc: number = TypeOp.floatSignManipulation(op);
    if (opc === OpCode.CPUI_MAX)
      return 0;
    data.opRemoveInput(op, 1);
    data.opSetOpcode(op, opc);
    return 1;
  }
}

// =====================================================================
// RuleOrCompare
// =====================================================================
export class RuleOrCompare extends Rule {
  constructor(g: string) {
    super(g, 0, "orcompare");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleOrCompare(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_INT_OR);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const outvn: Varnode = op.getOut()!;
    let hasCompares: boolean = false;
    const descendList: PcodeOp[] = Array.from(outvn.descend);
    for (const compOp of descendList) {
      const opc: number = compOp.code();
      if (opc !== OpCode.CPUI_INT_EQUAL && opc !== OpCode.CPUI_INT_NOTEQUAL)
        return 0;
      if (!compOp.getIn(1)!.constantMatch(0n))
        return 0;
      hasCompares = true;
    }
    if (!hasCompares)
      return 0;

    const V: Varnode = op.getIn(0)!;
    const W: Varnode = op.getIn(1)!;

    if (V.isFree()) return 0;
    if (W.isFree()) return 0;

    const iterList: PcodeOp[] = Array.from(outvn.descend);
    for (const equalOp of iterList) {
      const opc: number = equalOp.code();
      const zero_V: Varnode = data.newConstant(V.getSize(), 0n);
      const zero_W: Varnode = data.newConstant(W.getSize(), 0n);
      const eq_V: PcodeOp = data.newOp(2, equalOp.getAddr());
      data.opSetOpcode(eq_V, opc);
      data.opSetInput(eq_V, V, 0);
      data.opSetInput(eq_V, zero_V, 1);
      const eq_W: PcodeOp = data.newOp(2, equalOp.getAddr());
      data.opSetOpcode(eq_W, opc);
      data.opSetInput(eq_W, W, 0);
      data.opSetInput(eq_W, zero_W, 1);

      const eq_V_out: Varnode = data.newUniqueOut(1, eq_V);
      const eq_W_out: Varnode = data.newUniqueOut(1, eq_W);

      data.opInsertBefore(eq_V, equalOp);
      data.opInsertBefore(eq_W, equalOp);

      data.opSetOpcode(equalOp, opc === OpCode.CPUI_INT_EQUAL ? OpCode.CPUI_BOOL_AND : OpCode.CPUI_BOOL_OR);
      data.opSetInput(equalOp, eq_V_out, 0);
      data.opSetInput(equalOp, eq_W_out, 1);
    }

    return 1;
  }
}

// =====================================================================
// RuleExpandLoad
// =====================================================================
export class RuleExpandLoad extends Rule {
  constructor(g: string) {
    super(g, 0, "expandload");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleExpandLoad(this.getGroup());
  }

  /// Check that all uses of given Varnode are of the form (V & C) == D
  private static checkAndComparison(vn: Varnode): boolean {
    for (const op of vn.descend) {
      if (op.code() !== OpCode.CPUI_INT_AND) return false;
      if (!op.getIn(1)!.isConstant()) return false;
      const compOp: PcodeOp | null = op.getOut()!.loneDescend()!;
      if (compOp === null) return false;
      const opc: number = compOp.code();
      if (opc !== OpCode.CPUI_INT_EQUAL && opc !== OpCode.CPUI_INT_NOTEQUAL) return false;
      if (!compOp.getIn(1)!.isConstant()) return false;
    }
    return true;
  }

  /// Expand the constants in the previously scanned forms: (V & C) == D
  private static modifyAndComparison(data: Funcdata, oldVn: Varnode, newVn: Varnode, dt: Datatype, offset: number): void {
    offset = 8 * offset;   // Convert to shift amount
    const iterList: PcodeOp[] = Array.from(oldVn.descend);
    for (const andOp of iterList) {
      const compOp: PcodeOp = andOp.getOut()!.loneDescend()!;
      let newOff: bigint = andOp.getIn(1)!.getOffset();
      newOff <<= BigInt(offset);
      let vn: Varnode = data.newConstant(dt.getSize(), newOff);
      vn.updateType(dt);
      data.opSetInput(andOp, newVn, 0);
      data.opSetInput(andOp, vn, 1);
      newOff = compOp.getIn(1)!.getOffset();
      newOff <<= BigInt(offset);
      vn = data.newConstant(dt.getSize(), newOff);
      vn.updateType(dt);
      data.opSetInput(compOp, vn, 1);
    }
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_LOAD);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const outVn: Varnode = op.getOut()!;
    const outSize: number = outVn.getSize();
    let rootPtr: Varnode = op.getIn(1)!;
    let addOp: PcodeOp | null = null;
    let offset: number = 0;
    let elType: Datatype;
    if (rootPtr.isWritten()) {
      const defOp: PcodeOp = rootPtr.getDef()!;
      if (defOp.code() === OpCode.CPUI_INT_ADD && defOp.getIn(1)!.isConstant()) {
        addOp = defOp;
        rootPtr = defOp.getIn(0)!;
        const off: bigint = defOp.getIn(1)!.getOffset();
        if (off > 16n) return 0;
        offset = Number(off);
        if (defOp.getOut()!.loneDescend()! === null) return 0;
        elType = rootPtr.getTypeReadFacing(defOp);
      } else {
        elType = rootPtr.getTypeReadFacing(op);
      }
    } else {
      elType = rootPtr.getTypeReadFacing(op);
    }
    if (elType.getMetatype() !== type_metatype.TYPE_PTR) return 0;
    elType = (elType as TypePointer).getPtrTo();
    if (elType.getSize() <= outSize) return 0;
    if (elType.getSize() < outSize + offset) return 0;

    const meta: number = elType.getMetatype();
    if (meta === type_metatype.TYPE_UNKNOWN) return 0;
    const addForm: boolean = RuleExpandLoad.checkAndComparison(outVn);
    const spc: AddrSpace = op.getIn(0)!.getSpaceFromConst()!;
    let lsbCut: number = 0;
    if (addForm) {
      if (spc.isBigEndian()) {
        lsbCut = elType.getSize() - outSize - offset;
      } else {
        lsbCut = offset;
      }
    } else {
      // Check for natural integer truncation
      if (meta !== type_metatype.TYPE_INT && meta !== type_metatype.TYPE_UINT) return 0;
      const outMeta: number = outVn.getTypeDefFacing().getMetatype();
      if (outMeta !== type_metatype.TYPE_INT && outMeta !== type_metatype.TYPE_UINT && outMeta !== type_metatype.TYPE_UNKNOWN && outMeta !== type_metatype.TYPE_BOOL)
        return 0;
      // Check that LOAD is grabbing least significant bytes
      if (spc.isBigEndian()) {
        if (outSize + offset !== elType.getSize()) return 0;
      } else {
        if (offset !== 0) return 0;
      }
    }
    // Modify the LOAD
    const newOut: Varnode = data.newUnique(elType.getSize(), elType);
    data.opSetOutput(op, newOut);
    if (addOp !== null) {
      data.opSetInput(op, rootPtr, 1);
      data.opDestroy(addOp);
    }
    if (addForm) {
      if (meta !== type_metatype.TYPE_INT && meta !== type_metatype.TYPE_UINT)
        elType = data.getArch().types.getBase(elType.getSize(), type_metatype.TYPE_UINT);
      RuleExpandLoad.modifyAndComparison(data, outVn, newOut, elType, lsbCut);
    } else {
      const subOp: PcodeOp = data.newOp(2, op.getAddr());
      data.opSetOpcode(subOp, OpCode.CPUI_SUBPIECE);
      data.opSetInput(subOp, newOut, 0);
      data.opSetInput(subOp, data.newConstant(4, 0n), 1);
      data.opSetOutput(subOp, outVn);
      data.opInsertAfter(subOp, op);
    }
    return 1;
  }
}
