/**
 * @file typeop.ts
 * @description Data-type and behavior information associated with specific p-code op-codes.
 * Translated from Ghidra's typeop.hh / typeop.cc
 */

import type { int4, uint4, uintb } from '../core/types.js';
import { OpCode } from '../core/opcodes.js';
import {
  OpBehavior,
  OpBehaviorCopy,
  OpBehaviorEqual,
  OpBehaviorNotEqual,
  OpBehaviorIntSless,
  OpBehaviorIntSlessEqual,
  OpBehaviorIntLess,
  OpBehaviorIntLessEqual,
  OpBehaviorIntZext,
  OpBehaviorIntSext,
  OpBehaviorIntAdd,
  OpBehaviorIntSub,
  OpBehaviorIntCarry,
  OpBehaviorIntScarry,
  OpBehaviorIntSborrow,
  OpBehaviorInt2Comp,
  OpBehaviorIntNegate,
  OpBehaviorIntXor,
  OpBehaviorIntAnd,
  OpBehaviorIntOr,
  OpBehaviorIntLeft,
  OpBehaviorIntRight,
  OpBehaviorIntSright,
  OpBehaviorIntMult,
  OpBehaviorIntDiv,
  OpBehaviorIntSdiv,
  OpBehaviorIntRem,
  OpBehaviorIntSrem,
  OpBehaviorBoolNegate,
  OpBehaviorBoolXor,
  OpBehaviorBoolAnd,
  OpBehaviorBoolOr,
  OpBehaviorFloatEqual,
  OpBehaviorFloatNotEqual,
  OpBehaviorFloatLess,
  OpBehaviorFloatLessEqual,
  OpBehaviorFloatNan,
  OpBehaviorFloatAdd,
  OpBehaviorFloatDiv,
  OpBehaviorFloatMult,
  OpBehaviorFloatSub,
  OpBehaviorFloatNeg,
  OpBehaviorFloatAbs,
  OpBehaviorFloatSqrt,
  OpBehaviorFloatInt2Float,
  OpBehaviorFloatFloat2Float,
  OpBehaviorFloatTrunc,
  OpBehaviorFloatCeil,
  OpBehaviorFloatFloor,
  OpBehaviorFloatRound,
  OpBehaviorPiece,
  OpBehaviorSubpiece,
  OpBehaviorPtradd,
  OpBehaviorPtrsub,
  OpBehaviorPopcount,
  OpBehaviorLzcount,
  calc_mask,
} from '../core/opbehavior.js';
import { Datatype, type_metatype } from './type.js';
import type { Writer } from '../util/writer.js';
import { Varnode } from './varnode.js';
import { AddrSpace, spacetype } from '../core/space.js';
import { FuncCallSpecs } from './fspec.js';

// ---------------------------------------------------------------------------
// Forward type declarations for not-yet-written modules
// ---------------------------------------------------------------------------

type PcodeOp = any;
type PrintLanguage = any;
type CastStrategy = any;
type ConstantPool = any;
type Translate = any;
type Architecture = any;
type TypeFactory = any;

// CastStrategy promotion constants (temporary until CastStrategy is implemented)
const CastStrategyConst = {
  NO_PROMOTION: 0,
  UNSIGNED_EXTENSION: 1,
  SIGNED_EXTENSION: 2,
} as const;

// ---------------------------------------------------------------------------
// PcodeOp flag constants (from op.hh)
// These are used by TypeOp constructors to set opflags.
// ---------------------------------------------------------------------------

const PcodeOpFlags = {
  startbasic: 0x1,
  branch: 0x2,
  call: 0x4,
  returns: 0x8,
  nocollapse: 0x10,
  dead: 0x20,
  marker: 0x40,
  booloutput: 0x80,
  boolean_flip: 0x100,
  coderef: 0x800,
  commutative: 0x4000,
  unary: 0x8000,
  binary: 0x10000,
  special: 0x20000,
  ternary: 0x40000,
  return_copy: 0x80000,
  has_callspec: 0x20000000,
} as const;

// =========================================================================
// TypeOp base class
// =========================================================================

/**
 * Associate data-type and behavior information with a specific p-code op-code.
 *
 * This holds all information about a p-code op-code. The main PcodeOp object holds this
 * as a representative of the op-code. The evaluate* methods can be used to let the op-code
 * act on constant input values.
 */
export abstract class TypeOp {
  static readonly inherits_sign = 1;
  static readonly inherits_sign_zero = 2;
  static readonly shift_op = 4;
  static readonly arithmetic_op = 8;
  static readonly logical_op = 0x10;
  static readonly floatingpoint_op = 0x20;

  protected tlst: TypeFactory;
  protected opcode: OpCode;
  protected opflags: uint4;
  protected addlflags: uint4;
  protected name: string;
  protected behave: OpBehavior | null;

  protected setMetatypeIn(val: type_metatype): void {}
  protected setMetatypeOut(val: type_metatype): void {}
  protected setSymbol(nm: string): void { this.name = nm; }

  constructor(t: TypeFactory, opc: OpCode, n: string) {
    this.tlst = t;
    this.opcode = opc;
    this.name = n;
    this.opflags = 0;
    this.addlflags = 0;
    this.behave = null;
  }

  getName(): string { return this.name; }
  getOpcode(): OpCode { return this.opcode; }
  getFlags(): uint4 { return this.opflags; }
  getBehavior(): OpBehavior | null { return this.behave; }

  evaluateUnary(sizeout: int4, sizein: int4, in1: uintb): uintb {
    return this.behave!.evaluateUnary(sizeout, sizein, in1);
  }

  evaluateBinary(sizeout: int4, sizein: int4, in1: uintb, in2: uintb): uintb {
    return this.behave!.evaluateBinary(sizeout, sizein, in1, in2);
  }

  evaluateTernary(sizeout: int4, sizein: int4, in1: uintb, in2: uintb, in3: uintb): uintb {
    return this.behave!.evaluateTernary(sizeout, sizein, in1, in2, in3);
  }

  recoverInputBinary(slot: int4, sizeout: int4, out: uintb, sizein: int4, inp: uintb): uintb {
    return this.behave!.recoverInputBinary(slot, sizeout, out, sizein, inp);
  }

  recoverInputUnary(sizeout: int4, out: uintb, sizein: int4): uintb {
    return this.behave!.recoverInputUnary(sizeout, out, sizein);
  }

  isCommutative(): boolean {
    return (this.opflags & PcodeOpFlags.commutative) !== 0;
  }

  inheritsSign(): boolean { return (this.addlflags & TypeOp.inherits_sign) !== 0; }
  inheritsSignFirstParamOnly(): boolean { return (this.addlflags & TypeOp.inherits_sign_zero) !== 0; }
  isShiftOp(): boolean { return (this.addlflags & TypeOp.shift_op) !== 0; }
  isArithmeticOp(): boolean { return (this.addlflags & TypeOp.arithmetic_op) !== 0; }
  isLogicalOp(): boolean { return (this.addlflags & TypeOp.logical_op) !== 0; }
  isFloatingPointOp(): boolean { return (this.addlflags & TypeOp.floatingpoint_op) !== 0; }

  getOutputLocal(op: PcodeOp): Datatype | null {
    return this.tlst.getBase(op.getOut().getSize(), type_metatype.TYPE_UNKNOWN);
  }

  getInputLocal(op: PcodeOp, slot: int4): Datatype | null {
    return this.tlst.getBase(op.getIn(slot).getSize(), type_metatype.TYPE_UNKNOWN);
  }

  getOutputToken(op: PcodeOp, castStrategy: CastStrategy): Datatype | null {
    return op.outputTypeLocal();
  }

  getInputCast(op: PcodeOp, slot: int4, castStrategy: CastStrategy): Datatype | null {
    const vn = op.getIn(slot);
    if (vn.isAnnotation()) return null;
    const reqtype = op.inputTypeLocal(slot);
    const curtype = vn.getHighTypeReadFacing(op);
    return castStrategy.castStandard(reqtype, curtype, false, true);
  }

  propagateType(alttype: Datatype, op: PcodeOp, invn: any, outvn: any,
    inslot: int4, outslot: int4): Datatype | null {
    return null;
  }

  abstract push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void;
  abstract printRaw(s: Writer, op: PcodeOp): void;

  getOperatorName(op: PcodeOp): string { return this.name; }

  // Static methods
  static registerInstructions(inst: (TypeOp | null)[], tlst: TypeFactory, trans: Translate): void {
    // Fill array to CPUI_MAX with nulls
    while (inst.length < OpCode.CPUI_MAX) {
      inst.push(null);
    }

    inst[OpCode.CPUI_COPY] = new TypeOpCopy(tlst);
    inst[OpCode.CPUI_LOAD] = new TypeOpLoad(tlst);
    inst[OpCode.CPUI_STORE] = new TypeOpStore(tlst);
    inst[OpCode.CPUI_BRANCH] = new TypeOpBranch(tlst);
    inst[OpCode.CPUI_CBRANCH] = new TypeOpCbranch(tlst);
    inst[OpCode.CPUI_BRANCHIND] = new TypeOpBranchind(tlst);
    inst[OpCode.CPUI_CALL] = new TypeOpCall(tlst);
    inst[OpCode.CPUI_CALLIND] = new TypeOpCallind(tlst);
    inst[OpCode.CPUI_CALLOTHER] = new TypeOpCallother(tlst);
    inst[OpCode.CPUI_RETURN] = new TypeOpReturn(tlst);

    inst[OpCode.CPUI_MULTIEQUAL] = new TypeOpMulti(tlst);
    inst[OpCode.CPUI_INDIRECT] = new TypeOpIndirect(tlst);

    inst[OpCode.CPUI_PIECE] = new TypeOpPiece(tlst);
    inst[OpCode.CPUI_SUBPIECE] = new TypeOpSubpiece(tlst);
    inst[OpCode.CPUI_INT_EQUAL] = new TypeOpEqual(tlst);
    inst[OpCode.CPUI_INT_NOTEQUAL] = new TypeOpNotEqual(tlst);
    inst[OpCode.CPUI_INT_SLESS] = new TypeOpIntSless(tlst);
    inst[OpCode.CPUI_INT_SLESSEQUAL] = new TypeOpIntSlessEqual(tlst);
    inst[OpCode.CPUI_INT_LESS] = new TypeOpIntLess(tlst);
    inst[OpCode.CPUI_INT_LESSEQUAL] = new TypeOpIntLessEqual(tlst);
    inst[OpCode.CPUI_INT_ZEXT] = new TypeOpIntZext(tlst);
    inst[OpCode.CPUI_INT_SEXT] = new TypeOpIntSext(tlst);
    inst[OpCode.CPUI_INT_ADD] = new TypeOpIntAdd(tlst);
    inst[OpCode.CPUI_INT_SUB] = new TypeOpIntSub(tlst);
    inst[OpCode.CPUI_INT_CARRY] = new TypeOpIntCarry(tlst);
    inst[OpCode.CPUI_INT_SCARRY] = new TypeOpIntScarry(tlst);
    inst[OpCode.CPUI_INT_SBORROW] = new TypeOpIntSborrow(tlst);
    inst[OpCode.CPUI_INT_2COMP] = new TypeOpInt2Comp(tlst);
    inst[OpCode.CPUI_INT_NEGATE] = new TypeOpIntNegate(tlst);
    inst[OpCode.CPUI_INT_XOR] = new TypeOpIntXor(tlst);
    inst[OpCode.CPUI_INT_AND] = new TypeOpIntAnd(tlst);
    inst[OpCode.CPUI_INT_OR] = new TypeOpIntOr(tlst);
    inst[OpCode.CPUI_INT_LEFT] = new TypeOpIntLeft(tlst);
    inst[OpCode.CPUI_INT_RIGHT] = new TypeOpIntRight(tlst);
    inst[OpCode.CPUI_INT_SRIGHT] = new TypeOpIntSright(tlst);
    inst[OpCode.CPUI_INT_MULT] = new TypeOpIntMult(tlst);
    inst[OpCode.CPUI_INT_DIV] = new TypeOpIntDiv(tlst);
    inst[OpCode.CPUI_INT_SDIV] = new TypeOpIntSdiv(tlst);
    inst[OpCode.CPUI_INT_REM] = new TypeOpIntRem(tlst);
    inst[OpCode.CPUI_INT_SREM] = new TypeOpIntSrem(tlst);

    inst[OpCode.CPUI_BOOL_NEGATE] = new TypeOpBoolNegate(tlst);
    inst[OpCode.CPUI_BOOL_XOR] = new TypeOpBoolXor(tlst);
    inst[OpCode.CPUI_BOOL_AND] = new TypeOpBoolAnd(tlst);
    inst[OpCode.CPUI_BOOL_OR] = new TypeOpBoolOr(tlst);

    inst[OpCode.CPUI_CAST] = new TypeOpCast(tlst);
    inst[OpCode.CPUI_PTRADD] = new TypeOpPtradd(tlst);
    inst[OpCode.CPUI_PTRSUB] = new TypeOpPtrsub(tlst);

    inst[OpCode.CPUI_FLOAT_EQUAL] = new TypeOpFloatEqual(tlst, trans);
    inst[OpCode.CPUI_FLOAT_NOTEQUAL] = new TypeOpFloatNotEqual(tlst, trans);
    inst[OpCode.CPUI_FLOAT_LESS] = new TypeOpFloatLess(tlst, trans);
    inst[OpCode.CPUI_FLOAT_LESSEQUAL] = new TypeOpFloatLessEqual(tlst, trans);
    inst[OpCode.CPUI_FLOAT_NAN] = new TypeOpFloatNan(tlst, trans);

    inst[OpCode.CPUI_FLOAT_ADD] = new TypeOpFloatAdd(tlst, trans);
    inst[OpCode.CPUI_FLOAT_DIV] = new TypeOpFloatDiv(tlst, trans);
    inst[OpCode.CPUI_FLOAT_MULT] = new TypeOpFloatMult(tlst, trans);
    inst[OpCode.CPUI_FLOAT_SUB] = new TypeOpFloatSub(tlst, trans);
    inst[OpCode.CPUI_FLOAT_NEG] = new TypeOpFloatNeg(tlst, trans);
    inst[OpCode.CPUI_FLOAT_ABS] = new TypeOpFloatAbs(tlst, trans);
    inst[OpCode.CPUI_FLOAT_SQRT] = new TypeOpFloatSqrt(tlst, trans);

    inst[OpCode.CPUI_FLOAT_INT2FLOAT] = new TypeOpFloatInt2Float(tlst, trans);
    inst[OpCode.CPUI_FLOAT_FLOAT2FLOAT] = new TypeOpFloatFloat2Float(tlst, trans);
    inst[OpCode.CPUI_FLOAT_TRUNC] = new TypeOpFloatTrunc(tlst, trans);
    inst[OpCode.CPUI_FLOAT_CEIL] = new TypeOpFloatCeil(tlst, trans);
    inst[OpCode.CPUI_FLOAT_FLOOR] = new TypeOpFloatFloor(tlst, trans);
    inst[OpCode.CPUI_FLOAT_ROUND] = new TypeOpFloatRound(tlst, trans);
    inst[OpCode.CPUI_SEGMENTOP] = new TypeOpSegment(tlst);
    inst[OpCode.CPUI_CPOOLREF] = new TypeOpCpoolref(tlst);
    inst[OpCode.CPUI_NEW] = new TypeOpNew(tlst);
    inst[OpCode.CPUI_INSERT] = new TypeOpInsert(tlst);
    inst[OpCode.CPUI_EXTRACT] = new TypeOpExtract(tlst);
    inst[OpCode.CPUI_POPCOUNT] = new TypeOpPopcount(tlst);
    inst[OpCode.CPUI_LZCOUNT] = new TypeOpLzcount(tlst);
  }

  static selectJavaOperators(inst: (TypeOp | null)[], val: boolean): void {
    if (val) {
      inst[OpCode.CPUI_INT_ZEXT]!.setMetatypeIn(type_metatype.TYPE_UNKNOWN);
      inst[OpCode.CPUI_INT_ZEXT]!.setMetatypeOut(type_metatype.TYPE_INT);
      inst[OpCode.CPUI_INT_NEGATE]!.setMetatypeIn(type_metatype.TYPE_INT);
      inst[OpCode.CPUI_INT_NEGATE]!.setMetatypeOut(type_metatype.TYPE_INT);
      inst[OpCode.CPUI_INT_XOR]!.setMetatypeIn(type_metatype.TYPE_INT);
      inst[OpCode.CPUI_INT_XOR]!.setMetatypeOut(type_metatype.TYPE_INT);
      inst[OpCode.CPUI_INT_OR]!.setMetatypeIn(type_metatype.TYPE_INT);
      inst[OpCode.CPUI_INT_OR]!.setMetatypeOut(type_metatype.TYPE_INT);
      inst[OpCode.CPUI_INT_AND]!.setMetatypeIn(type_metatype.TYPE_INT);
      inst[OpCode.CPUI_INT_AND]!.setMetatypeOut(type_metatype.TYPE_INT);
      inst[OpCode.CPUI_INT_RIGHT]!.setMetatypeIn(type_metatype.TYPE_INT);
      inst[OpCode.CPUI_INT_RIGHT]!.setMetatypeOut(type_metatype.TYPE_INT);
      inst[OpCode.CPUI_INT_RIGHT]!.setSymbol(">>>");
    } else {
      inst[OpCode.CPUI_INT_ZEXT]!.setMetatypeIn(type_metatype.TYPE_UINT);
      inst[OpCode.CPUI_INT_ZEXT]!.setMetatypeOut(type_metatype.TYPE_UINT);
      inst[OpCode.CPUI_INT_NEGATE]!.setMetatypeIn(type_metatype.TYPE_UINT);
      inst[OpCode.CPUI_INT_NEGATE]!.setMetatypeOut(type_metatype.TYPE_UINT);
      inst[OpCode.CPUI_INT_XOR]!.setMetatypeIn(type_metatype.TYPE_UINT);
      inst[OpCode.CPUI_INT_XOR]!.setMetatypeOut(type_metatype.TYPE_UINT);
      inst[OpCode.CPUI_INT_OR]!.setMetatypeIn(type_metatype.TYPE_UINT);
      inst[OpCode.CPUI_INT_OR]!.setMetatypeOut(type_metatype.TYPE_UINT);
      inst[OpCode.CPUI_INT_AND]!.setMetatypeIn(type_metatype.TYPE_UINT);
      inst[OpCode.CPUI_INT_AND]!.setMetatypeOut(type_metatype.TYPE_UINT);
      inst[OpCode.CPUI_INT_RIGHT]!.setMetatypeIn(type_metatype.TYPE_UINT);
      inst[OpCode.CPUI_INT_RIGHT]!.setMetatypeOut(type_metatype.TYPE_UINT);
      inst[OpCode.CPUI_INT_RIGHT]!.setSymbol(">>");
    }
  }

  static floatSignManipulation(op: PcodeOp): OpCode {
    const opc: OpCode = op.code();
    if (opc === OpCode.CPUI_INT_AND) {
      const cvn = op.getIn(1);
      if (cvn.isConstant()) {
        let val: uintb = calc_mask(cvn.getSize());
        val >>= 1n;
        if (val === cvn.getOffset())
          return OpCode.CPUI_FLOAT_ABS;
      }
    } else if (opc === OpCode.CPUI_INT_XOR) {
      const cvn = op.getIn(1);
      if (cvn.isConstant()) {
        let val: uintb = calc_mask(cvn.getSize());
        val = val ^ (val >> 1n);
        if (val === cvn.getOffset())
          return OpCode.CPUI_FLOAT_NEG;
      }
    }
    return OpCode.CPUI_MAX;
  }

  static propagateToPointer(t: TypeFactory, dt: Datatype, sz: int4, wordsz: int4): Datatype | null {
    const meta: type_metatype = dt.getMetatype();
    if (meta === type_metatype.TYPE_PTR) {
      dt = t.getBase(dt.getSize(), type_metatype.TYPE_UNKNOWN);
    } else if (meta === type_metatype.TYPE_PARTIALSTRUCT) {
      dt = (dt as any).getComponentForPtr();
    }
    return t.getTypePointer(sz, dt, wordsz);
  }

  static propagateFromPointer(t: TypeFactory, dt: Datatype, sz: int4): Datatype | null {
    if (dt.getMetatype() !== type_metatype.TYPE_PTR)
      return null;
    const ptrto: Datatype = (dt as any).getPtrTo();
    if (ptrto.isVariableLength())
      return null;
    if (ptrto.getSize() === sz)
      return ptrto;
    if (dt.isPointerRel()) {
      const ptrrel = dt as any;
      const res = t.getExactPiece(ptrrel.getParent(), ptrrel.getByteOffset(), sz);
      if (res !== null && res.isEnumType())
        return res;
    } else if (ptrto.isEnumType() && !ptrto.hasStripped()) {
      return t.getTypePartialEnum(ptrto, 0, sz);
    }
    return null;
  }
}

// =========================================================================
// TypeOpBinary
// =========================================================================

export class TypeOpBinary extends TypeOp {
  private metaout: type_metatype;
  private metain: type_metatype;

  protected setMetatypeIn(val: type_metatype): void { this.metain = val; }
  protected setMetatypeOut(val: type_metatype): void { this.metaout = val; }

  constructor(t: TypeFactory, opc: OpCode, n: string, mout: type_metatype, min: type_metatype) {
    super(t, opc, n);
    this.metaout = mout;
    this.metain = min;
  }

  getOutputLocal(op: PcodeOp): Datatype | null {
    return this.tlst.getBase(op.getOut().getSize(), this.metaout);
  }

  getInputLocal(op: PcodeOp, slot: int4): Datatype | null {
    return this.tlst.getBase(op.getIn(slot).getSize(), this.metain);
  }

  printRaw(s: Writer, op: PcodeOp): void {
    Varnode.printRawStatic(s, op.getOut());
    s.write(" = ");
    Varnode.printRawStatic(s, op.getIn(0));
    s.write(` ${this.getOperatorName(op)} `);
    Varnode.printRawStatic(s, op.getIn(1));
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void {
    // Default - subclasses override
  }
}

// =========================================================================
// TypeOpUnary
// =========================================================================

export class TypeOpUnary extends TypeOp {
  private metaout: type_metatype;
  private metain: type_metatype;

  protected setMetatypeIn(val: type_metatype): void { this.metain = val; }
  protected setMetatypeOut(val: type_metatype): void { this.metaout = val; }

  constructor(t: TypeFactory, opc: OpCode, n: string, mout: type_metatype, min: type_metatype) {
    super(t, opc, n);
    this.metaout = mout;
    this.metain = min;
  }

  getOutputLocal(op: PcodeOp): Datatype | null {
    return this.tlst.getBase(op.getOut().getSize(), this.metaout);
  }

  getInputLocal(op: PcodeOp, slot: int4): Datatype | null {
    return this.tlst.getBase(op.getIn(slot).getSize(), this.metain);
  }

  printRaw(s: Writer, op: PcodeOp): void {
    Varnode.printRawStatic(s, op.getOut());
    s.write(` = ${this.getOperatorName(op)} `);
    Varnode.printRawStatic(s, op.getIn(0));
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void {
    // Default - subclasses override
  }
}

// =========================================================================
// TypeOpFunc
// =========================================================================

export class TypeOpFunc extends TypeOp {
  private metaout: type_metatype;
  private metain: type_metatype;

  protected setMetatypeIn(val: type_metatype): void { this.metain = val; }
  protected setMetatypeOut(val: type_metatype): void { this.metaout = val; }

  constructor(t: TypeFactory, opc: OpCode, n: string, mout: type_metatype, min: type_metatype) {
    super(t, opc, n);
    this.metaout = mout;
    this.metain = min;
  }

  getOutputLocal(op: PcodeOp): Datatype | null {
    return this.tlst.getBase(op.getOut().getSize(), this.metaout);
  }

  getInputLocal(op: PcodeOp, slot: int4): Datatype | null {
    return this.tlst.getBase(op.getIn(slot).getSize(), this.metain);
  }

  printRaw(s: Writer, op: PcodeOp): void {
    Varnode.printRawStatic(s, op.getOut());
    s.write(` = ${this.getOperatorName(op)}(`);
    Varnode.printRawStatic(s, op.getIn(0));
    for (let i = 1; i < op.numInput(); ++i) {
      s.write(",");
      Varnode.printRawStatic(s, op.getIn(i));
    }
    s.write(")");
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void {
    // Default - subclasses override
  }
}


// =========================================================================
// Concrete TypeOp subclasses - Group 1: Copy, Load, Store, Branch, Control Flow
// =========================================================================

export class TypeOpCopy extends TypeOp {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_COPY, "copy");
    this.opflags = PcodeOpFlags.unary | PcodeOpFlags.nocollapse;
    this.behave = new OpBehaviorCopy();
  }

  getInputCast(op: PcodeOp, slot: int4, castStrategy: CastStrategy): Datatype | null {
    const reqtype = op.getOut().getHighTypeDefFacing();
    const curtype = op.getIn(0).getHighTypeReadFacing(op);
    return castStrategy.castStandard(reqtype, curtype, false, true);
  }

  getOutputToken(op: PcodeOp, castStrategy: CastStrategy): Datatype | null {
    return op.getIn(0).getHighTypeReadFacing(op);
  }

  propagateType(alttype: Datatype, op: PcodeOp, invn: any, outvn: any, inslot: int4, outslot: int4): Datatype | null {
    if (inslot !== -1 && outslot !== -1) return null;
    if (invn.isSpacebase()) {
      const spc = this.tlst.getArch().getDefaultDataSpace();
      return this.tlst.getTypePointer(alttype.getSize(), this.tlst.getBase(1, type_metatype.TYPE_UNKNOWN), spc.getWordSize());
    }
    return alttype;
  }

  printRaw(s: Writer, op: PcodeOp): void {
    Varnode.printRawStatic(s, op.getOut());
    s.write(" = ");
    Varnode.printRawStatic(s, op.getIn(0));
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opCopy(op); }
}

export class TypeOpLoad extends TypeOp {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_LOAD, "load");
    this.opflags = PcodeOpFlags.special | PcodeOpFlags.nocollapse;
    this.behave = new OpBehavior(OpCode.CPUI_LOAD, false, true);
  }

  getInputCast(op: PcodeOp, slot: int4, castStrategy: CastStrategy): Datatype | null {
    if (slot !== 1) return null;
    const reqtype: Datatype = op.getOut().getHighTypeDefFacing();
    const invn = op.getIn(1);
    let curtype: Datatype = invn.getHighTypeReadFacing(op);
    const spc = op.getIn(0).getSpaceFromConst();
    if (curtype.getMetatype() === type_metatype.TYPE_PTR)
      curtype = (curtype as any).getPtrTo();
    else
      return this.tlst.getTypePointer(invn.getSize(), reqtype, spc.getWordSize());
    if (curtype !== reqtype && curtype.getSize() === reqtype.getSize()) {
      const curmeta = curtype.getMetatype();
      if (curmeta !== type_metatype.TYPE_STRUCT && curmeta !== type_metatype.TYPE_ARRAY &&
          curmeta !== type_metatype.TYPE_SPACEBASE && curmeta !== type_metatype.TYPE_UNION) {
        if (!invn.isImplied() || !invn.isWritten() || invn.getDef().code() !== OpCode.CPUI_CAST)
          return null;
      }
    }
    const castResult = castStrategy.castStandard(reqtype, curtype, false, true);
    if (castResult === null) return null;
    return this.tlst.getTypePointer(invn.getSize(), castResult, spc.getWordSize());
  }

  getOutputToken(op: PcodeOp, castStrategy: CastStrategy): Datatype | null {
    const ct: Datatype = op.getIn(1).getHighTypeReadFacing(op);
    if (ct.getMetatype() === type_metatype.TYPE_PTR && (ct as any).getPtrTo().getSize() === op.getOut().getSize())
      return (ct as any).getPtrTo();
    return op.getOut().getHighTypeDefFacing();
  }

  propagateType(alttype: Datatype, op: PcodeOp, invn: any, outvn: any, inslot: int4, outslot: int4): Datatype | null {
    if (inslot === 0 || outslot === 0) return null;
    if (invn.isSpacebase()) return null;
    if (inslot === -1) {
      const spc = op.getIn(0).getSpaceFromConst();
      const wordSize = spc !== null ? spc.getWordSize() : 1;
      return TypeOp.propagateToPointer(this.tlst, alttype, outvn.getSize(), wordSize);
    }
    return TypeOp.propagateFromPointer(this.tlst, alttype, outvn.getSize());
  }

  printRaw(s: Writer, op: PcodeOp): void {
    Varnode.printRawStatic(s, op.getOut());
    s.write(" = *(");
    const spc = op.getIn(0).getSpaceFromConst();
    s.write(spc.getName() + ",");
    Varnode.printRawStatic(s, op.getIn(1));
    s.write(")");
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opLoad(op); }
}

export class TypeOpStore extends TypeOp {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_STORE, "store");
    this.opflags = PcodeOpFlags.special | PcodeOpFlags.nocollapse;
    this.behave = new OpBehavior(OpCode.CPUI_STORE, false, true);
  }

  getInputCast(op: PcodeOp, slot: int4, castStrategy: CastStrategy): Datatype | null {
    if (slot === 0) return null;
    const pointerVn = op.getIn(1);
    const pointerType: Datatype = pointerVn.getHighTypeReadFacing(op);
    let pointedToType: Datatype = pointerType;
    const valueType: Datatype = op.getIn(2).getHighTypeReadFacing(op);
    const spc = op.getIn(0).getSpaceFromConst();
    let destSize: int4;
    if (pointerType.getMetatype() === type_metatype.TYPE_PTR) {
      pointedToType = (pointerType as any).getPtrTo();
      destSize = pointedToType.getSize();
    } else {
      destSize = -1;
    }
    if (destSize !== valueType.getSize()) {
      if (slot === 1)
        return this.tlst.getTypePointer(pointerVn.getSize(), valueType, spc.getWordSize());
      else
        return null;
    }
    if (slot === 1) {
      if (pointerVn.isWritten() && pointerVn.getDef().code() === OpCode.CPUI_CAST) {
        if (pointerVn.isImplied() && pointerVn.loneDescend() === op) {
          const newType = this.tlst.getTypePointer(pointerVn.getSize(), valueType, spc.getWordSize());
          if (pointerType !== newType)
            return newType;
        }
      }
      return null;
    }
    return castStrategy.castStandard(pointedToType, valueType, false, true);
  }

  propagateType(alttype: Datatype, op: PcodeOp, invn: any, outvn: any, inslot: int4, outslot: int4): Datatype | null {
    if (inslot === 0 || outslot === 0) return null;
    if (invn.isSpacebase()) return null;
    if (inslot === 2) {
      const spc = op.getIn(0).getSpaceFromConst();
      return TypeOp.propagateToPointer(this.tlst, alttype, outvn.getSize(), spc.getWordSize());
    }
    return TypeOp.propagateFromPointer(this.tlst, alttype, outvn.getSize());
  }

  printRaw(s: Writer, op: PcodeOp): void {
    s.write("*(");
    const spc = op.getIn(0).getSpaceFromConst();
    s.write(spc.getName() + ",");
    Varnode.printRawStatic(s, op.getIn(1));
    s.write(") = ");
    Varnode.printRawStatic(s, op.getIn(2));
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opStore(op); }
}

export class TypeOpBranch extends TypeOp {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_BRANCH, "goto");
    this.opflags = PcodeOpFlags.special | PcodeOpFlags.branch | PcodeOpFlags.coderef | PcodeOpFlags.nocollapse;
    this.behave = new OpBehavior(OpCode.CPUI_BRANCH, false, true);
  }

  printRaw(s: Writer, op: PcodeOp): void {
    s.write(this.name + " ");
    const parent = op.getParent();
    if (parent !== null && parent.sizeOut() === 1) {
      parent.getOut(0).printShortHeader(s);
    } else {
      Varnode.printRawStatic(s, op.getIn(0));
    }
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opBranch(op); }
}

export class TypeOpCbranch extends TypeOp {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_CBRANCH, "goto");
    this.opflags = PcodeOpFlags.special | PcodeOpFlags.branch | PcodeOpFlags.coderef | PcodeOpFlags.nocollapse;
    this.behave = new OpBehavior(OpCode.CPUI_CBRANCH, false, true);
  }

  getInputLocal(op: PcodeOp, slot: int4): Datatype | null {
    if (slot === 1)
      return this.tlst.getBase(op.getIn(1).getSize(), type_metatype.TYPE_BOOL);
    const td = this.tlst.getTypeCode();
    const spc = op.getIn(0).getSpace();
    return this.tlst.getTypePointer(op.getIn(0).getSize(), td, spc.getWordSize());
  }

  printRaw(s: Writer, op: PcodeOp): void {
    s.write(this.name + " ");
    const parent = op.getParent();
    let falseOut: any = null;
    if (parent !== null && parent.sizeOut() === 2) {
      const trueOut = parent.getTrueOut();
      falseOut = parent.getFalseOut();
      trueOut.printShortHeader(s);
    } else {
      Varnode.printRawStatic(s, op.getIn(0));
    }
    s.write(" if (");
    Varnode.printRawStatic(s, op.getIn(1));
    if (op.isBooleanFlip())
      s.write(" == 0)");
    else
      s.write(" != 0)");
    if (falseOut !== null) {
      s.write(" else ");
      falseOut.printShortHeader(s);
    }
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opCbranch(op); }
}

export class TypeOpBranchind extends TypeOp {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_BRANCHIND, "switch");
    this.opflags = PcodeOpFlags.special | PcodeOpFlags.branch | PcodeOpFlags.nocollapse;
    this.behave = new OpBehavior(OpCode.CPUI_BRANCHIND, false, true);
  }

  printRaw(s: Writer, op: PcodeOp): void {
    s.write(this.name + " ");
    Varnode.printRawStatic(s, op.getIn(0));
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opBranchind(op); }
}

export class TypeOpCall extends TypeOp {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_CALL, "call");
    this.opflags = PcodeOpFlags.special | PcodeOpFlags.call | PcodeOpFlags.has_callspec | PcodeOpFlags.coderef | PcodeOpFlags.nocollapse;
    this.behave = new OpBehavior(OpCode.CPUI_CALL, false, true);
  }

  printRaw(s: Writer, op: PcodeOp): void {
    if (op.getOut() !== null) {
      Varnode.printRawStatic(s, op.getOut());
      s.write(" = ");
    }
    s.write(this.name + " ");
    Varnode.printRawStatic(s, op.getIn(0));
    if (op.numInput() > 1) {
      s.write("(");
      Varnode.printRawStatic(s, op.getIn(1));
      for (let i = 2; i < op.numInput(); ++i) {
        s.write(",");
        Varnode.printRawStatic(s, op.getIn(i));
      }
      s.write(")");
    }
  }

  getInputLocal(op: PcodeOp, slot: int4): Datatype | null {
    const vn = op.getIn(0);
    if (slot === 0 || vn.getSpace().getType() !== spacetype.IPTR_FSPEC)
      return super.getInputLocal(op, slot);
    const fc = FuncCallSpecs.getFspecFromConst(vn.getAddr());
    if (fc === null) return super.getInputLocal(op, slot);
    const param = fc.getParam(slot - 1);
    if (param !== null) {
      if (param.isTypeLocked()) {
        const ct = param.getType();
        if (ct.getMetatype() !== type_metatype.TYPE_VOID && ct.getSize() <= op.getIn(slot).getSize())
          return ct;
      } else if (param.isThisPointer()) {
        const ct = param.getType();
        if (ct.getMetatype() === type_metatype.TYPE_PTR && (ct as any).getPtrTo().getMetatype() === type_metatype.TYPE_STRUCT)
          return ct;
      }
    }
    return super.getInputLocal(op, slot);
  }

  getOutputLocal(op: PcodeOp): Datatype | null {
    const vn = op.getIn(0);
    if (vn.getSpace().getType() !== spacetype.IPTR_FSPEC)
      return super.getOutputLocal(op);
    const fc = FuncCallSpecs.getFspecFromConst(vn.getAddr());
    if (fc === null) return super.getOutputLocal(op);
    if (!fc.isOutputLocked()) return super.getOutputLocal(op);
    const ct = fc.getOutputType();
    if (ct.getMetatype() === type_metatype.TYPE_VOID) return super.getOutputLocal(op);
    return ct;
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opCall(op); }
}

export class TypeOpCallind extends TypeOp {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_CALLIND, "callind");
    this.opflags = PcodeOpFlags.special | PcodeOpFlags.call | PcodeOpFlags.has_callspec | PcodeOpFlags.nocollapse;
    this.behave = new OpBehavior(OpCode.CPUI_CALLIND, false, true);
  }

  getInputLocal(op: PcodeOp, slot: int4): Datatype | null {
    if (slot === 0) {
      const td = this.tlst.getTypeCode();
      const spc = op.getAddr().getSpace();
      return this.tlst.getTypePointer(op.getIn(0).getSize(), td, spc.getWordSize());
    }
    const fc = op.getParent().getFuncdata().getCallSpecs(op);
    if (fc === null) return super.getInputLocal(op, slot);
    const param = fc.getParam(slot - 1);
    if (param !== null) {
      if (param.isTypeLocked()) {
        const ct = param.getType();
        if (ct.getMetatype() !== type_metatype.TYPE_VOID) return ct;
      } else if (param.isThisPointer()) {
        const ct = param.getType();
        if (ct.getMetatype() === type_metatype.TYPE_PTR && (ct as any).getPtrTo().getMetatype() === type_metatype.TYPE_STRUCT)
          return ct;
      }
    }
    return super.getInputLocal(op, slot);
  }

  getOutputLocal(op: PcodeOp): Datatype | null {
    const fc = op.getParent().getFuncdata().getCallSpecs(op);
    if (fc === null) return super.getOutputLocal(op);
    if (!fc.isOutputLocked()) return super.getOutputLocal(op);
    const ct = fc.getOutputType();
    if (ct.getMetatype() === type_metatype.TYPE_VOID) return super.getOutputLocal(op);
    return ct;
  }

  printRaw(s: Writer, op: PcodeOp): void {
    if (op.getOut() !== null) {
      Varnode.printRawStatic(s, op.getOut());
      s.write(" = ");
    }
    s.write(this.name);
    Varnode.printRawStatic(s, op.getIn(0));
    if (op.numInput() > 1) {
      s.write("(");
      Varnode.printRawStatic(s, op.getIn(1));
      for (let i = 2; i < op.numInput(); ++i) {
        s.write(",");
        Varnode.printRawStatic(s, op.getIn(i));
      }
      s.write(")");
    }
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opCallind(op); }
}

export class TypeOpCallother extends TypeOp {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_CALLOTHER, "syscall");
    this.opflags = PcodeOpFlags.special | PcodeOpFlags.call | PcodeOpFlags.nocollapse;
    this.behave = new OpBehavior(OpCode.CPUI_CALLOTHER, false, true);
  }

  printRaw(s: Writer, op: PcodeOp): void {
    if (op.getOut() !== null) {
      Varnode.printRawStatic(s, op.getOut());
      s.write(" = ");
    }
    s.write(this.getOperatorName(op));
    if (op.numInput() > 1) {
      s.write("(");
      Varnode.printRawStatic(s, op.getIn(1));
      for (let i = 2; i < op.numInput(); ++i) {
        s.write(",");
        Varnode.printRawStatic(s, op.getIn(i));
      }
      s.write(")");
    }
  }

  getOperatorName(op: PcodeOp): string {
    const bb = op.getParent();
    if (bb !== null) {
      const glb = bb.getFuncdata().getArch();
      const index = Number(op.getIn(0).getOffset());
      const userop = glb.userops.getOp(index);
      if (userop !== null)
        return userop.getOperatorName(op);
    }
    return `${super.getOperatorName(op)}[${op.getIn(0).getOffset()}]`;
  }

  getInputLocal(op: PcodeOp, slot: int4): Datatype | null {
    const userOp = this.tlst.getArch().userops.getOp(Number(op.getIn(0).getOffset()));
    if (userOp !== null) {
      const res = userOp.getInputLocal(op, slot);
      if (res !== null) return res;
    }
    return super.getInputLocal(op, slot);
  }

  getOutputLocal(op: PcodeOp): Datatype | null {
    const userOp = this.tlst.getArch().userops.getOp(Number(op.getIn(0).getOffset()));
    if (userOp !== null) {
      const res = userOp.getOutputLocal(op);
      if (res !== null) return res;
    }
    return super.getOutputLocal(op);
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opCallother(op); }
}

export class TypeOpReturn extends TypeOp {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_RETURN, "return");
    this.opflags = PcodeOpFlags.special | PcodeOpFlags.returns | PcodeOpFlags.nocollapse | PcodeOpFlags.return_copy;
    this.behave = new OpBehavior(OpCode.CPUI_RETURN, false, true);
  }

  printRaw(s: Writer, op: PcodeOp): void {
    s.write(this.name);
    if (op.numInput() >= 1) {
      s.write("(");
      Varnode.printRawStatic(s, op.getIn(0));
      s.write(")");
    }
    if (op.numInput() > 1) {
      s.write(" ");
      Varnode.printRawStatic(s, op.getIn(1));
      for (let i = 2; i < op.numInput(); ++i) {
        s.write(",");
        Varnode.printRawStatic(s, op.getIn(i));
      }
    }
  }

  getInputLocal(op: PcodeOp, slot: int4): Datatype | null {
    if (slot === 0) return super.getInputLocal(op, slot);
    const bb = op.getParent();
    if (bb === null) return super.getInputLocal(op, slot);
    const fp = bb.getFuncdata().getFuncProto();
    const ct = fp.getOutputType();
    if (ct.getMetatype() === type_metatype.TYPE_VOID || ct.getSize() !== op.getIn(slot).getSize())
      return super.getInputLocal(op, slot);
    return ct;
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opReturn(op); }
}


// =========================================================================
// Concrete TypeOp subclasses - Group 2: Comparisons + Integer Arithmetic
// =========================================================================

export class TypeOpEqual extends TypeOpBinary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_EQUAL, "==", type_metatype.TYPE_BOOL, type_metatype.TYPE_INT);
    this.opflags = PcodeOpFlags.binary | PcodeOpFlags.booloutput | PcodeOpFlags.commutative;
    this.addlflags = TypeOp.inherits_sign;
    this.behave = new OpBehaviorEqual();
  }

  getInputCast(op: PcodeOp, slot: int4, castStrategy: CastStrategy): Datatype | null {
    let reqtype: Datatype = op.getIn(0).getHighTypeReadFacing(op);
    const othertype: Datatype = op.getIn(1).getHighTypeReadFacing(op);
    if (0 > othertype.typeOrder(reqtype)) reqtype = othertype;
    if (castStrategy.checkIntPromotionForCompare(op, slot)) return reqtype;
    const slottype = op.getIn(slot).getHighTypeReadFacing(op);
    return castStrategy.castStandard(reqtype, slottype, false, false);
  }

  propagateType(alttype: Datatype, op: PcodeOp, invn: any, outvn: any, inslot: int4, outslot: int4): Datatype | null {
    return TypeOpEqual.propagateAcrossCompare(alttype, this.tlst, invn, outvn, inslot, outslot);
  }

  static propagateAcrossCompare(alttype: Datatype, typegrp: TypeFactory, invn: any, outvn: any, inslot: int4, outslot: int4): Datatype | null {
    if (inslot === -1 || outslot === -1) return null;
    if (invn.isSpacebase()) {
      const spc = typegrp.getArch().getDefaultDataSpace();
      return typegrp.getTypePointer(alttype.getSize(), typegrp.getBase(1, type_metatype.TYPE_UNKNOWN), spc.getWordSize());
    }
    if (alttype.isPointerRel() && !outvn.isConstant()) {
      const relPtr = alttype as any;
      if (relPtr.getParent().getMetatype() === type_metatype.TYPE_STRUCT && relPtr.getByteOffset() >= 0) {
        return typegrp.getTypePointer(relPtr.getSize(), typegrp.getBase(1, type_metatype.TYPE_UNKNOWN), relPtr.getWordSize());
      }
      return alttype;
    }
    return alttype;
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntEqual(op); }
}

export class TypeOpNotEqual extends TypeOpBinary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_NOTEQUAL, "!=", type_metatype.TYPE_BOOL, type_metatype.TYPE_INT);
    this.opflags = PcodeOpFlags.binary | PcodeOpFlags.booloutput | PcodeOpFlags.commutative;
    this.addlflags = TypeOp.inherits_sign;
    this.behave = new OpBehaviorNotEqual();
  }

  getInputCast(op: PcodeOp, slot: int4, castStrategy: CastStrategy): Datatype | null {
    let reqtype: Datatype = op.getIn(0).getHighTypeReadFacing(op);
    const othertype: Datatype = op.getIn(1).getHighTypeReadFacing(op);
    if (0 > othertype.typeOrder(reqtype)) reqtype = othertype;
    if (castStrategy.checkIntPromotionForCompare(op, slot)) return reqtype;
    const slottype = op.getIn(slot).getHighTypeReadFacing(op);
    return castStrategy.castStandard(reqtype, slottype, false, false);
  }

  propagateType(alttype: Datatype, op: PcodeOp, invn: any, outvn: any, inslot: int4, outslot: int4): Datatype | null {
    return TypeOpEqual.propagateAcrossCompare(alttype, this.tlst, invn, outvn, inslot, outslot);
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntNotEqual(op); }
}

export class TypeOpIntSless extends TypeOpBinary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_SLESS, "<", type_metatype.TYPE_BOOL, type_metatype.TYPE_INT);
    this.opflags = PcodeOpFlags.binary | PcodeOpFlags.booloutput;
    this.addlflags = TypeOp.inherits_sign;
    this.behave = new OpBehaviorIntSless();
  }

  getInputCast(op: PcodeOp, slot: int4, castStrategy: CastStrategy): Datatype | null {
    const reqtype = op.inputTypeLocal(slot);
    if (castStrategy.checkIntPromotionForCompare(op, slot)) return reqtype;
    const curtype = op.getIn(slot).getHighTypeReadFacing(op);
    return castStrategy.castStandard(reqtype, curtype, true, true);
  }

  propagateType(alttype: Datatype, op: PcodeOp, invn: any, outvn: any, inslot: int4, outslot: int4): Datatype | null {
    if (inslot === -1 || outslot === -1) return null;
    if (alttype.getMetatype() !== type_metatype.TYPE_INT) return null;
    return alttype;
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntSless(op); }
}

export class TypeOpIntSlessEqual extends TypeOpBinary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_SLESSEQUAL, "<=", type_metatype.TYPE_BOOL, type_metatype.TYPE_INT);
    this.opflags = PcodeOpFlags.binary | PcodeOpFlags.booloutput;
    this.addlflags = TypeOp.inherits_sign;
    this.behave = new OpBehaviorIntSlessEqual();
  }

  getInputCast(op: PcodeOp, slot: int4, castStrategy: CastStrategy): Datatype | null {
    const reqtype = op.inputTypeLocal(slot);
    if (castStrategy.checkIntPromotionForCompare(op, slot)) return reqtype;
    const curtype = op.getIn(slot).getHighTypeReadFacing(op);
    return castStrategy.castStandard(reqtype, curtype, true, true);
  }

  propagateType(alttype: Datatype, op: PcodeOp, invn: any, outvn: any, inslot: int4, outslot: int4): Datatype | null {
    if (inslot === -1 || outslot === -1) return null;
    if (alttype.getMetatype() !== type_metatype.TYPE_INT) return null;
    return alttype;
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntSlessEqual(op); }
}

export class TypeOpIntLess extends TypeOpBinary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_LESS, "<", type_metatype.TYPE_BOOL, type_metatype.TYPE_UINT);
    this.opflags = PcodeOpFlags.binary | PcodeOpFlags.booloutput;
    this.addlflags = TypeOp.inherits_sign;
    this.behave = new OpBehaviorIntLess();
  }

  getInputCast(op: PcodeOp, slot: int4, castStrategy: CastStrategy): Datatype | null {
    const reqtype = op.inputTypeLocal(slot);
    if (castStrategy.checkIntPromotionForCompare(op, slot)) return reqtype;
    const curtype = op.getIn(slot).getHighTypeReadFacing(op);
    return castStrategy.castStandard(reqtype, curtype, true, false);
  }

  propagateType(alttype: Datatype, op: PcodeOp, invn: any, outvn: any, inslot: int4, outslot: int4): Datatype | null {
    return TypeOpEqual.propagateAcrossCompare(alttype, this.tlst, invn, outvn, inslot, outslot);
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntLess(op); }
}

export class TypeOpIntLessEqual extends TypeOpBinary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_LESSEQUAL, "<=", type_metatype.TYPE_BOOL, type_metatype.TYPE_UINT);
    this.opflags = PcodeOpFlags.binary | PcodeOpFlags.booloutput;
    this.addlflags = TypeOp.inherits_sign;
    this.behave = new OpBehaviorIntLessEqual();
  }

  getInputCast(op: PcodeOp, slot: int4, castStrategy: CastStrategy): Datatype | null {
    const reqtype = op.inputTypeLocal(slot);
    if (castStrategy.checkIntPromotionForCompare(op, slot)) return reqtype;
    const curtype = op.getIn(slot).getHighTypeReadFacing(op);
    return castStrategy.castStandard(reqtype, curtype, true, false);
  }

  propagateType(alttype: Datatype, op: PcodeOp, invn: any, outvn: any, inslot: int4, outslot: int4): Datatype | null {
    return TypeOpEqual.propagateAcrossCompare(alttype, this.tlst, invn, outvn, inslot, outslot);
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntLessEqual(op); }
}

export class TypeOpIntZext extends TypeOpFunc {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_ZEXT, "ZEXT", type_metatype.TYPE_UINT, type_metatype.TYPE_UINT);
    this.opflags = PcodeOpFlags.unary;
    this.behave = new OpBehaviorIntZext();
  }

  getOperatorName(op: PcodeOp): string {
    return `${this.name}${op.getIn(0).getSize()}${op.getOut().getSize()}`;
  }

  getInputCast(op: PcodeOp, slot: int4, castStrategy: CastStrategy): Datatype | null {
    const reqtype = op.inputTypeLocal(slot);
    if (castStrategy.checkIntPromotionForExtension(op)) return reqtype;
    const curtype = op.getIn(slot).getHighTypeReadFacing(op);
    return castStrategy.castStandard(reqtype, curtype, true, false);
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntZext(op, readOp); }
}

export class TypeOpIntSext extends TypeOpFunc {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_SEXT, "SEXT", type_metatype.TYPE_INT, type_metatype.TYPE_INT);
    this.opflags = PcodeOpFlags.unary;
    this.behave = new OpBehaviorIntSext();
  }

  getOperatorName(op: PcodeOp): string {
    return `${this.name}${op.getIn(0).getSize()}${op.getOut().getSize()}`;
  }

  getInputCast(op: PcodeOp, slot: int4, castStrategy: CastStrategy): Datatype | null {
    const reqtype = op.inputTypeLocal(slot);
    if (castStrategy.checkIntPromotionForExtension(op)) return reqtype;
    const curtype = op.getIn(slot).getHighTypeReadFacing(op);
    return castStrategy.castStandard(reqtype, curtype, true, false);
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntSext(op, readOp); }
}

export class TypeOpIntAdd extends TypeOpBinary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_ADD, "+", type_metatype.TYPE_INT, type_metatype.TYPE_INT);
    this.opflags = PcodeOpFlags.binary | PcodeOpFlags.commutative;
    this.addlflags = TypeOp.arithmetic_op | TypeOp.inherits_sign;
    this.behave = new OpBehaviorIntAdd();
  }

  getOutputToken(op: PcodeOp, castStrategy: CastStrategy): Datatype | null {
    return castStrategy.arithmeticOutputStandard(op);
  }

  propagateType(alttype: Datatype, op: PcodeOp, invn: any, outvn: any, inslot: int4, outslot: int4): Datatype | null {
    const invnMeta = alttype.getMetatype();
    if (invnMeta !== type_metatype.TYPE_PTR) {
      if (invnMeta !== type_metatype.TYPE_INT && invnMeta !== type_metatype.TYPE_UINT) return null;
      if (outslot !== 1 || !op.getIn(1).isConstant()) return null;
    } else if (inslot !== -1 && outslot !== -1) {
      return null;
    }
    if (outvn.isConstant() && alttype.getMetatype() !== type_metatype.TYPE_PTR)
      return alttype;
    if (inslot === -1) return null;
    return TypeOpIntAdd.propagateAddIn2Out(alttype, this.tlst, op, inslot);
  }

  static propagateAddIn2Out(alttype: Datatype, typegrp: TypeFactory, op: PcodeOp, inslot: int4): Datatype | null {
    let pointer: any = alttype;
    const offRef: { val: uintb } = { val: 0n };
    const command = TypeOpIntAdd.propagateAddPointer(offRef, op, inslot, pointer.getPtrTo().getAlignSize());
    if (command === 2) return null;
    let parent: any = null;
    const parentOffRef = { val: 0n };
    if (command !== 3) {
      const typeOffsetRef = { val: AddrSpace.addressToByteInt(offRef.val, pointer.getWordSize()) };
      const allowWrap = op.code() !== OpCode.CPUI_PTRSUB;
      const parentRef: { val: any } = { val: null };
      do {
        pointer = pointer.downChain(typeOffsetRef, parentRef, parentOffRef, allowWrap, typegrp);
        if (pointer === null) break;
        parent = parentRef.val;
      } while (typeOffsetRef.val !== 0n);
    }
    if (parent !== null) {
      let pt: Datatype;
      if (pointer === null)
        pt = typegrp.getBase(1, type_metatype.TYPE_UNKNOWN);
      else
        pt = pointer.getPtrTo();
      pointer = typegrp.getTypePointerRel(parent, pt, Number(parentOffRef.val));
    }
    if (pointer === null) {
      if (command === 0) return alttype;
      return null;
    }
    if (op.getIn(inslot).isSpacebase()) {
      if (pointer.getPtrTo().getMetatype() === type_metatype.TYPE_SPACEBASE)
        pointer = typegrp.getTypePointer(pointer.getSize(), typegrp.getBase(1, type_metatype.TYPE_UNKNOWN), pointer.getWordSize());
    }
    return pointer;
  }

  static propagateAddPointer(offRef: { val: uintb }, op: PcodeOp, slot: int4, sz: int4): int4 {
    if (op.code() === OpCode.CPUI_PTRADD) {
      if (slot !== 0) return 2;
      const constvn = op.getIn(1);
      const mult: uintb = op.getIn(2).getOffset();
      if (constvn.isConstant()) {
        offRef.val = (constvn.getOffset() * mult) & calc_mask(constvn.getSize());
        return offRef.val === 0n ? 0 : 1;
      }
      if (sz !== 0 && Number(mult % BigInt(sz)) !== 0) return 2;
      return 3;
    }
    if (op.code() === OpCode.CPUI_PTRSUB) {
      if (slot !== 0) return 2;
      offRef.val = op.getIn(1).getOffset();
      return offRef.val === 0n ? 0 : 1;
    }
    if (op.code() === OpCode.CPUI_INT_ADD) {
      const othervn = op.getIn(1 - slot);
      if (!othervn.isConstant()) {
        if (othervn.isWritten()) {
          const multop = othervn.getDef();
          if (multop.code() === OpCode.CPUI_INT_MULT) {
            const constvn = multop.getIn(1);
            if (constvn.isConstant()) {
              const mult: uintb = constvn.getOffset();
              if (mult === calc_mask(constvn.getSize())) return 2;
              if (sz !== 0 && Number(mult % BigInt(sz)) !== 0) return 2;
            }
            return 3;
          }
        }
        if (sz === 1) return 3;
        return 2;
      }
      if (othervn.getTempType().getMetatype() === type_metatype.TYPE_PTR) return 2;
      offRef.val = othervn.getOffset();
      return offRef.val === 0n ? 0 : 1;
    }
    return 2;
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntAdd(op); }
}

export class TypeOpIntSub extends TypeOpBinary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_SUB, "-", type_metatype.TYPE_INT, type_metatype.TYPE_INT);
    this.opflags = PcodeOpFlags.binary;
    this.addlflags = TypeOp.arithmetic_op | TypeOp.inherits_sign;
    this.behave = new OpBehaviorIntSub();
  }

  getOutputToken(op: PcodeOp, castStrategy: CastStrategy): Datatype | null {
    return castStrategy.arithmeticOutputStandard(op);
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntSub(op); }
}

export class TypeOpIntCarry extends TypeOpFunc {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_CARRY, "CARRY", type_metatype.TYPE_BOOL, type_metatype.TYPE_UINT);
    this.opflags = PcodeOpFlags.binary | PcodeOpFlags.commutative | PcodeOpFlags.booloutput;
    this.addlflags = TypeOp.arithmetic_op;
    this.behave = new OpBehaviorIntCarry();
  }

  getOperatorName(op: PcodeOp): string {
    return `${this.name}${op.getIn(0).getSize()}`;
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntCarry(op); }
}

export class TypeOpIntScarry extends TypeOpFunc {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_SCARRY, "SCARRY", type_metatype.TYPE_BOOL, type_metatype.TYPE_INT);
    this.opflags = PcodeOpFlags.binary | PcodeOpFlags.commutative | PcodeOpFlags.booloutput;
    this.addlflags = TypeOp.arithmetic_op;
    this.behave = new OpBehaviorIntScarry();
  }

  getOperatorName(op: PcodeOp): string {
    return `${this.name}${op.getIn(0).getSize()}`;
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntScarry(op); }
}

export class TypeOpIntSborrow extends TypeOpFunc {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_SBORROW, "SBORROW", type_metatype.TYPE_BOOL, type_metatype.TYPE_INT);
    this.opflags = PcodeOpFlags.binary | PcodeOpFlags.booloutput;
    this.addlflags = TypeOp.arithmetic_op;
    this.behave = new OpBehaviorIntSborrow();
  }

  getOperatorName(op: PcodeOp): string {
    return `${this.name}${op.getIn(0).getSize()}`;
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntSborrow(op); }
}

export class TypeOpInt2Comp extends TypeOpUnary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_2COMP, "-", type_metatype.TYPE_INT, type_metatype.TYPE_INT);
    this.opflags = PcodeOpFlags.unary;
    this.addlflags = TypeOp.arithmetic_op | TypeOp.inherits_sign;
    this.behave = new OpBehaviorInt2Comp();
  }

  getOutputToken(op: PcodeOp, castStrategy: CastStrategy): Datatype | null {
    return castStrategy.arithmeticOutputStandard(op);
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opInt2Comp(op); }
}

export class TypeOpIntNegate extends TypeOpUnary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_NEGATE, "~", type_metatype.TYPE_UINT, type_metatype.TYPE_UINT);
    this.opflags = PcodeOpFlags.unary;
    this.addlflags = TypeOp.logical_op | TypeOp.inherits_sign;
    this.behave = new OpBehaviorIntNegate();
  }

  getOutputToken(op: PcodeOp, castStrategy: CastStrategy): Datatype | null {
    return castStrategy.arithmeticOutputStandard(op);
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntNegate(op); }
}

export class TypeOpIntXor extends TypeOpBinary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_XOR, "^", type_metatype.TYPE_UINT, type_metatype.TYPE_UINT);
    this.opflags = PcodeOpFlags.binary | PcodeOpFlags.commutative;
    this.addlflags = TypeOp.logical_op | TypeOp.inherits_sign;
    this.behave = new OpBehaviorIntXor();
  }

  getOutputToken(op: PcodeOp, castStrategy: CastStrategy): Datatype | null {
    return castStrategy.arithmeticOutputStandard(op);
  }

  propagateType(alttype: Datatype, op: PcodeOp, invn: any, outvn: any, inslot: int4, outslot: int4): Datatype | null {
    if (!alttype.isEnumType()) {
      if (alttype.getMetatype() !== type_metatype.TYPE_FLOAT) return null;
      if (TypeOp.floatSignManipulation(op) === OpCode.CPUI_MAX) return null;
    }
    if (invn.isSpacebase()) {
      const spc = this.tlst.getArch().getDefaultDataSpace();
      return this.tlst.getTypePointer(alttype.getSize(), this.tlst.getBase(1, type_metatype.TYPE_UNKNOWN), spc.getWordSize());
    }
    return alttype;
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntXor(op); }
}

export class TypeOpIntAnd extends TypeOpBinary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_AND, "&", type_metatype.TYPE_UINT, type_metatype.TYPE_UINT);
    this.opflags = PcodeOpFlags.binary | PcodeOpFlags.commutative;
    this.addlflags = TypeOp.logical_op | TypeOp.inherits_sign;
    this.behave = new OpBehaviorIntAnd();
  }

  getOutputToken(op: PcodeOp, castStrategy: CastStrategy): Datatype | null {
    return castStrategy.arithmeticOutputStandard(op);
  }

  propagateType(alttype: Datatype, op: PcodeOp, invn: any, outvn: any, inslot: int4, outslot: int4): Datatype | null {
    if (!alttype.isEnumType()) {
      if (alttype.getMetatype() !== type_metatype.TYPE_FLOAT) return null;
      if (TypeOp.floatSignManipulation(op) === OpCode.CPUI_MAX) return null;
    }
    if (invn.isSpacebase()) {
      const spc = this.tlst.getArch().getDefaultDataSpace();
      return this.tlst.getTypePointer(alttype.getSize(), this.tlst.getBase(1, type_metatype.TYPE_UNKNOWN), spc.getWordSize());
    }
    return alttype;
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntAnd(op); }
}

export class TypeOpIntOr extends TypeOpBinary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_OR, "|", type_metatype.TYPE_UINT, type_metatype.TYPE_UINT);
    this.opflags = PcodeOpFlags.binary | PcodeOpFlags.commutative;
    this.addlflags = TypeOp.logical_op | TypeOp.inherits_sign;
    this.behave = new OpBehaviorIntOr();
  }

  getOutputToken(op: PcodeOp, castStrategy: CastStrategy): Datatype | null {
    return castStrategy.arithmeticOutputStandard(op);
  }

  propagateType(alttype: Datatype, op: PcodeOp, invn: any, outvn: any, inslot: int4, outslot: int4): Datatype | null {
    if (!alttype.isEnumType()) return null;
    if (invn.isSpacebase()) {
      const spc = this.tlst.getArch().getDefaultDataSpace();
      return this.tlst.getTypePointer(alttype.getSize(), this.tlst.getBase(1, type_metatype.TYPE_UNKNOWN), spc.getWordSize());
    }
    return alttype;
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntOr(op); }
}

export class TypeOpIntLeft extends TypeOpBinary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_LEFT, "<<", type_metatype.TYPE_INT, type_metatype.TYPE_INT);
    this.opflags = PcodeOpFlags.binary;
    this.addlflags = TypeOp.inherits_sign | TypeOp.inherits_sign_zero | TypeOp.shift_op;
    this.behave = new OpBehaviorIntLeft();
  }

  getInputLocal(op: PcodeOp, slot: int4): Datatype | null {
    if (slot === 1)
      return this.tlst.getBaseNoChar(op.getIn(1).getSize(), type_metatype.TYPE_INT);
    return super.getInputLocal(op, slot);
  }

  getOutputToken(op: PcodeOp, castStrategy: CastStrategy): Datatype | null {
    const res1 = op.getIn(0).getHighTypeReadFacing(op);
    if (res1.getMetatype() === type_metatype.TYPE_BOOL)
      return this.tlst.getBase(res1.getSize(), type_metatype.TYPE_INT);
    return res1;
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntLeft(op); }
}

export class TypeOpIntRight extends TypeOpBinary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_RIGHT, ">>", type_metatype.TYPE_UINT, type_metatype.TYPE_UINT);
    this.opflags = PcodeOpFlags.binary;
    this.addlflags = TypeOp.inherits_sign | TypeOp.inherits_sign_zero | TypeOp.shift_op;
    this.behave = new OpBehaviorIntRight();
  }

  getInputLocal(op: PcodeOp, slot: int4): Datatype | null {
    if (slot === 1)
      return this.tlst.getBaseNoChar(op.getIn(1).getSize(), type_metatype.TYPE_INT);
    return super.getInputLocal(op, slot);
  }

  getInputCast(op: PcodeOp, slot: int4, castStrategy: CastStrategy): Datatype | null {
    if (slot === 0) {
      const vn = op.getIn(0);
      const reqtype = op.inputTypeLocal(slot);
      const curtype = vn.getHighTypeReadFacing(op);
      const promoType: int4 = castStrategy.intPromotionType(vn);
      if (promoType !== CastStrategyConst.NO_PROMOTION && (promoType & CastStrategyConst.UNSIGNED_EXTENSION) === 0)
        return reqtype;
      return castStrategy.castStandard(reqtype, curtype, true, true);
    }
    return super.getInputCast(op, slot, castStrategy);
  }

  getOutputToken(op: PcodeOp, castStrategy: CastStrategy): Datatype | null {
    const res1 = op.getIn(0).getHighTypeReadFacing(op);
    if (res1.getMetatype() === type_metatype.TYPE_BOOL)
      return this.tlst.getBase(res1.getSize(), type_metatype.TYPE_INT);
    return res1;
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntRight(op); }
}

export class TypeOpIntSright extends TypeOpBinary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_SRIGHT, ">>", type_metatype.TYPE_INT, type_metatype.TYPE_INT);
    this.opflags = PcodeOpFlags.binary;
    this.addlflags = TypeOp.inherits_sign | TypeOp.inherits_sign_zero | TypeOp.shift_op;
    this.behave = new OpBehaviorIntSright();
  }

  printRaw(s: Writer, op: PcodeOp): void {
    Varnode.printRawStatic(s, op.getOut());
    s.write(" = ");
    Varnode.printRawStatic(s, op.getIn(0));
    s.write(" s>> ");
    Varnode.printRawStatic(s, op.getIn(1));
  }

  getInputCast(op: PcodeOp, slot: int4, castStrategy: CastStrategy): Datatype | null {
    if (slot === 0) {
      const vn = op.getIn(0);
      const reqtype = op.inputTypeLocal(slot);
      const curtype = vn.getHighTypeReadFacing(op);
      const promoType: int4 = castStrategy.intPromotionType(vn);
      if (promoType !== CastStrategyConst.NO_PROMOTION && (promoType & CastStrategyConst.SIGNED_EXTENSION) === 0)
        return reqtype;
      return castStrategy.castStandard(reqtype, curtype, true, true);
    }
    return super.getInputCast(op, slot, castStrategy);
  }

  getInputLocal(op: PcodeOp, slot: int4): Datatype | null {
    if (slot === 1)
      return this.tlst.getBaseNoChar(op.getIn(1).getSize(), type_metatype.TYPE_INT);
    return super.getInputLocal(op, slot);
  }

  getOutputToken(op: PcodeOp, castStrategy: CastStrategy): Datatype | null {
    const res1 = op.getIn(0).getHighTypeReadFacing(op);
    if (res1.getMetatype() === type_metatype.TYPE_BOOL)
      return this.tlst.getBase(res1.getSize(), type_metatype.TYPE_INT);
    return res1;
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntSright(op); }
}

export class TypeOpIntMult extends TypeOpBinary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_MULT, "*", type_metatype.TYPE_INT, type_metatype.TYPE_INT);
    this.opflags = PcodeOpFlags.binary | PcodeOpFlags.commutative;
    this.addlflags = TypeOp.arithmetic_op | TypeOp.inherits_sign;
    this.behave = new OpBehaviorIntMult();
  }

  getOutputToken(op: PcodeOp, castStrategy: CastStrategy): Datatype | null {
    return castStrategy.arithmeticOutputStandard(op);
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntMult(op); }
}

export class TypeOpIntDiv extends TypeOpBinary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_DIV, "/", type_metatype.TYPE_UINT, type_metatype.TYPE_UINT);
    this.opflags = PcodeOpFlags.binary;
    this.addlflags = TypeOp.arithmetic_op | TypeOp.inherits_sign;
    this.behave = new OpBehaviorIntDiv();
  }

  getInputCast(op: PcodeOp, slot: int4, castStrategy: CastStrategy): Datatype | null {
    const vn = op.getIn(slot);
    const reqtype = op.inputTypeLocal(slot);
    const curtype = vn.getHighTypeReadFacing(op);
    const promoType: int4 = castStrategy.intPromotionType(vn);
    if (promoType !== CastStrategyConst.NO_PROMOTION && (promoType & CastStrategyConst.UNSIGNED_EXTENSION) === 0)
      return reqtype;
    return castStrategy.castStandard(reqtype, curtype, true, true);
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntDiv(op); }
}

export class TypeOpIntSdiv extends TypeOpBinary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_SDIV, "/", type_metatype.TYPE_INT, type_metatype.TYPE_INT);
    this.opflags = PcodeOpFlags.binary;
    this.addlflags = TypeOp.arithmetic_op | TypeOp.inherits_sign;
    this.behave = new OpBehaviorIntSdiv();
  }

  getInputCast(op: PcodeOp, slot: int4, castStrategy: CastStrategy): Datatype | null {
    const vn = op.getIn(slot);
    const reqtype = op.inputTypeLocal(slot);
    const curtype = vn.getHighTypeReadFacing(op);
    const promoType: int4 = castStrategy.intPromotionType(vn);
    if (promoType !== CastStrategyConst.NO_PROMOTION && (promoType & CastStrategyConst.SIGNED_EXTENSION) === 0)
      return reqtype;
    return castStrategy.castStandard(reqtype, curtype, true, true);
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntSdiv(op); }
}

export class TypeOpIntRem extends TypeOpBinary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_REM, "%", type_metatype.TYPE_UINT, type_metatype.TYPE_UINT);
    this.opflags = PcodeOpFlags.binary;
    this.addlflags = TypeOp.arithmetic_op | TypeOp.inherits_sign | TypeOp.inherits_sign_zero;
    this.behave = new OpBehaviorIntRem();
  }

  getInputCast(op: PcodeOp, slot: int4, castStrategy: CastStrategy): Datatype | null {
    const vn = op.getIn(slot);
    const reqtype = op.inputTypeLocal(slot);
    const curtype = vn.getHighTypeReadFacing(op);
    const promoType: int4 = castStrategy.intPromotionType(vn);
    if (promoType !== CastStrategyConst.NO_PROMOTION && (promoType & CastStrategyConst.UNSIGNED_EXTENSION) === 0)
      return reqtype;
    return castStrategy.castStandard(reqtype, curtype, true, true);
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntRem(op); }
}

export class TypeOpIntSrem extends TypeOpBinary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INT_SREM, "%", type_metatype.TYPE_INT, type_metatype.TYPE_INT);
    this.opflags = PcodeOpFlags.binary;
    this.addlflags = TypeOp.arithmetic_op | TypeOp.inherits_sign | TypeOp.inherits_sign_zero;
    this.behave = new OpBehaviorIntSrem();
  }

  getInputCast(op: PcodeOp, slot: int4, castStrategy: CastStrategy): Datatype | null {
    const vn = op.getIn(slot);
    const reqtype = op.inputTypeLocal(slot);
    const curtype = vn.getHighTypeReadFacing(op);
    const promoType: int4 = castStrategy.intPromotionType(vn);
    if (promoType !== CastStrategyConst.NO_PROMOTION && (promoType & CastStrategyConst.SIGNED_EXTENSION) === 0)
      return reqtype;
    return castStrategy.castStandard(reqtype, curtype, true, true);
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIntSrem(op); }
}


// =========================================================================
// Concrete TypeOp subclasses - Group 3: Bool, Float, Special ops
// =========================================================================

export class TypeOpBoolNegate extends TypeOpUnary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_BOOL_NEGATE, "!", type_metatype.TYPE_BOOL, type_metatype.TYPE_BOOL);
    this.opflags = PcodeOpFlags.unary | PcodeOpFlags.booloutput;
    this.addlflags = TypeOp.logical_op;
    this.behave = new OpBehaviorBoolNegate();
  }
  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opBoolNegate(op); }
}

export class TypeOpBoolXor extends TypeOpBinary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_BOOL_XOR, "^^", type_metatype.TYPE_BOOL, type_metatype.TYPE_BOOL);
    this.opflags = PcodeOpFlags.binary | PcodeOpFlags.commutative | PcodeOpFlags.booloutput;
    this.addlflags = TypeOp.logical_op;
    this.behave = new OpBehaviorBoolXor();
  }
  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opBoolXor(op); }
}

export class TypeOpBoolAnd extends TypeOpBinary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_BOOL_AND, "&&", type_metatype.TYPE_BOOL, type_metatype.TYPE_BOOL);
    this.opflags = PcodeOpFlags.binary | PcodeOpFlags.commutative | PcodeOpFlags.booloutput;
    this.addlflags = TypeOp.logical_op;
    this.behave = new OpBehaviorBoolAnd();
  }
  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opBoolAnd(op); }
}

export class TypeOpBoolOr extends TypeOpBinary {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_BOOL_OR, "||", type_metatype.TYPE_BOOL, type_metatype.TYPE_BOOL);
    this.opflags = PcodeOpFlags.binary | PcodeOpFlags.commutative | PcodeOpFlags.booloutput;
    this.addlflags = TypeOp.logical_op;
    this.behave = new OpBehaviorBoolOr();
  }
  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opBoolOr(op); }
}

// Float comparison ops
export class TypeOpFloatEqual extends TypeOpBinary {
  constructor(t: TypeFactory, trans: Translate) {
    super(t, OpCode.CPUI_FLOAT_EQUAL, "==", type_metatype.TYPE_BOOL, type_metatype.TYPE_FLOAT);
    this.opflags = PcodeOpFlags.binary | PcodeOpFlags.booloutput | PcodeOpFlags.commutative;
    this.addlflags = TypeOp.floatingpoint_op;
    this.behave = new OpBehaviorFloatEqual(trans);
  }
  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opFloatEqual(op); }
}

export class TypeOpFloatNotEqual extends TypeOpBinary {
  constructor(t: TypeFactory, trans: Translate) {
    super(t, OpCode.CPUI_FLOAT_NOTEQUAL, "!=", type_metatype.TYPE_BOOL, type_metatype.TYPE_FLOAT);
    this.opflags = PcodeOpFlags.binary | PcodeOpFlags.booloutput | PcodeOpFlags.commutative;
    this.addlflags = TypeOp.floatingpoint_op;
    this.behave = new OpBehaviorFloatNotEqual(trans);
  }
  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opFloatNotEqual(op); }
}

export class TypeOpFloatLess extends TypeOpBinary {
  constructor(t: TypeFactory, trans: Translate) {
    super(t, OpCode.CPUI_FLOAT_LESS, "<", type_metatype.TYPE_BOOL, type_metatype.TYPE_FLOAT);
    this.opflags = PcodeOpFlags.binary | PcodeOpFlags.booloutput;
    this.addlflags = TypeOp.floatingpoint_op;
    this.behave = new OpBehaviorFloatLess(trans);
  }
  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opFloatLess(op); }
}

export class TypeOpFloatLessEqual extends TypeOpBinary {
  constructor(t: TypeFactory, trans: Translate) {
    super(t, OpCode.CPUI_FLOAT_LESSEQUAL, "<=", type_metatype.TYPE_BOOL, type_metatype.TYPE_FLOAT);
    this.opflags = PcodeOpFlags.binary | PcodeOpFlags.booloutput;
    this.addlflags = TypeOp.floatingpoint_op;
    this.behave = new OpBehaviorFloatLessEqual(trans);
  }
  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opFloatLessEqual(op); }
}

export class TypeOpFloatNan extends TypeOpFunc {
  constructor(t: TypeFactory, trans: Translate) {
    super(t, OpCode.CPUI_FLOAT_NAN, "NAN", type_metatype.TYPE_BOOL, type_metatype.TYPE_FLOAT);
    this.opflags = PcodeOpFlags.unary | PcodeOpFlags.booloutput;
    this.addlflags = TypeOp.floatingpoint_op;
    this.behave = new OpBehaviorFloatNan(trans);
  }
  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opFloatNan(op); }
}

// Float arithmetic ops
export class TypeOpFloatAdd extends TypeOpBinary {
  constructor(t: TypeFactory, trans: Translate) {
    super(t, OpCode.CPUI_FLOAT_ADD, "+", type_metatype.TYPE_FLOAT, type_metatype.TYPE_FLOAT);
    this.opflags = PcodeOpFlags.binary | PcodeOpFlags.commutative;
    this.addlflags = TypeOp.floatingpoint_op;
    this.behave = new OpBehaviorFloatAdd(trans);
  }
  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opFloatAdd(op); }
}

export class TypeOpFloatDiv extends TypeOpBinary {
  constructor(t: TypeFactory, trans: Translate) {
    super(t, OpCode.CPUI_FLOAT_DIV, "/", type_metatype.TYPE_FLOAT, type_metatype.TYPE_FLOAT);
    this.opflags = PcodeOpFlags.binary;
    this.addlflags = TypeOp.floatingpoint_op;
    this.behave = new OpBehaviorFloatDiv(trans);
  }
  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opFloatDiv(op); }
}

export class TypeOpFloatMult extends TypeOpBinary {
  constructor(t: TypeFactory, trans: Translate) {
    super(t, OpCode.CPUI_FLOAT_MULT, "*", type_metatype.TYPE_FLOAT, type_metatype.TYPE_FLOAT);
    this.opflags = PcodeOpFlags.binary | PcodeOpFlags.commutative;
    this.addlflags = TypeOp.floatingpoint_op;
    this.behave = new OpBehaviorFloatMult(trans);
  }
  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opFloatMult(op); }
}

export class TypeOpFloatSub extends TypeOpBinary {
  constructor(t: TypeFactory, trans: Translate) {
    super(t, OpCode.CPUI_FLOAT_SUB, "-", type_metatype.TYPE_FLOAT, type_metatype.TYPE_FLOAT);
    this.opflags = PcodeOpFlags.binary;
    this.addlflags = TypeOp.floatingpoint_op;
    this.behave = new OpBehaviorFloatSub(trans);
  }
  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opFloatSub(op); }
}

export class TypeOpFloatNeg extends TypeOpUnary {
  constructor(t: TypeFactory, trans: Translate) {
    super(t, OpCode.CPUI_FLOAT_NEG, "-", type_metatype.TYPE_FLOAT, type_metatype.TYPE_FLOAT);
    this.opflags = PcodeOpFlags.unary;
    this.addlflags = TypeOp.floatingpoint_op;
    this.behave = new OpBehaviorFloatNeg(trans);
  }
  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opFloatNeg(op); }
}

export class TypeOpFloatAbs extends TypeOpFunc {
  constructor(t: TypeFactory, trans: Translate) {
    super(t, OpCode.CPUI_FLOAT_ABS, "ABS", type_metatype.TYPE_FLOAT, type_metatype.TYPE_FLOAT);
    this.opflags = PcodeOpFlags.unary;
    this.addlflags = TypeOp.floatingpoint_op;
    this.behave = new OpBehaviorFloatAbs(trans);
  }
  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opFloatAbs(op); }
}

export class TypeOpFloatSqrt extends TypeOpFunc {
  constructor(t: TypeFactory, trans: Translate) {
    super(t, OpCode.CPUI_FLOAT_SQRT, "SQRT", type_metatype.TYPE_FLOAT, type_metatype.TYPE_FLOAT);
    this.opflags = PcodeOpFlags.unary;
    this.addlflags = TypeOp.floatingpoint_op;
    this.behave = new OpBehaviorFloatSqrt(trans);
  }
  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opFloatSqrt(op); }
}

export class TypeOpFloatInt2Float extends TypeOpFunc {
  constructor(t: TypeFactory, trans: Translate) {
    super(t, OpCode.CPUI_FLOAT_INT2FLOAT, "INT2FLOAT", type_metatype.TYPE_FLOAT, type_metatype.TYPE_INT);
    this.opflags = PcodeOpFlags.unary;
    this.addlflags = TypeOp.floatingpoint_op;
    this.behave = new OpBehaviorFloatInt2Float(trans);
  }

  getInputCast(op: PcodeOp, slot: int4, castStrategy: CastStrategy): Datatype | null {
    if (TypeOpFloatInt2Float.absorbZext(op) !== null)
      return null;
    const vn = op.getIn(slot);
    const reqtype = op.inputTypeLocal(slot);
    const curtype = vn.getHighTypeReadFacing(op);
    let care_uint_int = true;
    if (vn.getSize() <= 8) {
      let val: uintb = vn.getNZMask();
      val >>= BigInt(8 * vn.getSize() - 1);
      care_uint_int = (val & 1n) !== 0n;
    }
    return castStrategy.castStandard(reqtype, curtype, care_uint_int, true);
  }

  static absorbZext(op: PcodeOp): PcodeOp | null {
    const vn0 = op.getIn(0);
    if (vn0.isWritten() && vn0.isImplied()) {
      const zextOp = vn0.getDef();
      if (zextOp.code() === OpCode.CPUI_INT_ZEXT)
        return zextOp;
    }
    return null;
  }

  static preferredZextSize(inSize: int4): int4 {
    if (inSize < 4) return 4;
    if (inSize < 8) return 8;
    return inSize + 1;
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opFloatInt2Float(op); }
}

export class TypeOpFloatFloat2Float extends TypeOpFunc {
  constructor(t: TypeFactory, trans: Translate) {
    super(t, OpCode.CPUI_FLOAT_FLOAT2FLOAT, "FLOAT2FLOAT", type_metatype.TYPE_FLOAT, type_metatype.TYPE_FLOAT);
    this.opflags = PcodeOpFlags.unary;
    this.addlflags = TypeOp.floatingpoint_op;
    this.behave = new OpBehaviorFloatFloat2Float(trans);
  }
  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opFloatFloat2Float(op); }
}

export class TypeOpFloatTrunc extends TypeOpFunc {
  constructor(t: TypeFactory, trans: Translate) {
    super(t, OpCode.CPUI_FLOAT_TRUNC, "TRUNC", type_metatype.TYPE_INT, type_metatype.TYPE_FLOAT);
    this.opflags = PcodeOpFlags.unary;
    this.addlflags = TypeOp.floatingpoint_op;
    this.behave = new OpBehaviorFloatTrunc(trans);
  }
  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opFloatTrunc(op); }
}

export class TypeOpFloatCeil extends TypeOpFunc {
  constructor(t: TypeFactory, trans: Translate) {
    super(t, OpCode.CPUI_FLOAT_CEIL, "CEIL", type_metatype.TYPE_FLOAT, type_metatype.TYPE_FLOAT);
    this.opflags = PcodeOpFlags.unary;
    this.addlflags = TypeOp.floatingpoint_op;
    this.behave = new OpBehaviorFloatCeil(trans);
  }
  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opFloatCeil(op); }
}

export class TypeOpFloatFloor extends TypeOpFunc {
  constructor(t: TypeFactory, trans: Translate) {
    super(t, OpCode.CPUI_FLOAT_FLOOR, "FLOOR", type_metatype.TYPE_FLOAT, type_metatype.TYPE_FLOAT);
    this.opflags = PcodeOpFlags.unary;
    this.addlflags = TypeOp.floatingpoint_op;
    this.behave = new OpBehaviorFloatFloor(trans);
  }
  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opFloatFloor(op); }
}

export class TypeOpFloatRound extends TypeOpFunc {
  constructor(t: TypeFactory, trans: Translate) {
    super(t, OpCode.CPUI_FLOAT_ROUND, "ROUND", type_metatype.TYPE_FLOAT, type_metatype.TYPE_FLOAT);
    this.opflags = PcodeOpFlags.unary;
    this.addlflags = TypeOp.floatingpoint_op;
    this.behave = new OpBehaviorFloatRound(trans);
  }
  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opFloatRound(op); }
}

// =========================================================================
// Special ops: Multi, Indirect, Piece, Subpiece, Cast, Ptradd, Ptrsub, etc.
// =========================================================================

export class TypeOpMulti extends TypeOp {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_MULTIEQUAL, "?");
    this.opflags = PcodeOpFlags.special | PcodeOpFlags.marker | PcodeOpFlags.nocollapse;
    this.behave = new OpBehavior(OpCode.CPUI_MULTIEQUAL, false, true);
  }

  propagateType(alttype: Datatype, op: PcodeOp, invn: any, outvn: any, inslot: int4, outslot: int4): Datatype | null {
    if (inslot !== -1 && outslot !== -1) return null;
    if (invn.isSpacebase()) {
      const spc = this.tlst.getArch().getDefaultDataSpace();
      return this.tlst.getTypePointer(alttype.getSize(), this.tlst.getBase(1, type_metatype.TYPE_UNKNOWN), spc.getWordSize());
    }
    return alttype;
  }

  printRaw(s: Writer, op: PcodeOp): void {
    Varnode.printRawStatic(s, op.getOut());
    s.write(" = ");
    Varnode.printRawStatic(s, op.getIn(0));
    if (op.numInput() === 1)
      s.write(" " + this.getOperatorName(op));
    for (let i = 1; i < op.numInput(); ++i) {
      s.write(" " + this.getOperatorName(op) + " ");
      Varnode.printRawStatic(s, op.getIn(i));
    }
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opMultiequal(op); }
}

export class TypeOpIndirect extends TypeOp {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INDIRECT, "[]");
    this.opflags = PcodeOpFlags.special | PcodeOpFlags.marker | PcodeOpFlags.nocollapse;
    this.behave = new OpBehavior(OpCode.CPUI_INDIRECT, false, true);
  }

  getInputLocal(op: PcodeOp, slot: int4): Datatype | null {
    if (slot === 0) return super.getInputLocal(op, slot);
    const ct = this.tlst.getTypeCode();
    const iop = op.constructor.getOpFromConst(op.getIn(1).getAddr());
    const spc = iop.getAddr().getSpace();
    return this.tlst.getTypePointer(op.getIn(0).getSize(), ct, spc.getWordSize());
  }

  propagateType(alttype: Datatype, op: PcodeOp, invn: any, outvn: any, inslot: int4, outslot: int4): Datatype | null {
    if (op.isIndirectCreation()) return null;
    if (inslot === 1 || outslot === 1) return null;
    if (inslot !== -1 && outslot !== -1) return null;
    if (invn.isSpacebase()) {
      const spc = this.tlst.getArch().getDefaultDataSpace();
      return this.tlst.getTypePointer(alttype.getSize(), this.tlst.getBase(1, type_metatype.TYPE_UNKNOWN), spc.getWordSize());
    }
    return alttype;
  }

  printRaw(s: Writer, op: PcodeOp): void {
    Varnode.printRawStatic(s, op.getOut());
    s.write(" = ");
    if (op.isIndirectCreation()) {
      s.write("[create] ");
    } else {
      Varnode.printRawStatic(s, op.getIn(0));
      s.write(" " + this.getOperatorName(op) + " ");
    }
    Varnode.printRawStatic(s, op.getIn(1));
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opIndirect(op); }
}

export class TypeOpPiece extends TypeOpFunc {
  private nearPointerSize: int4;
  private farPointerSize: int4;

  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_PIECE, "CONCAT", type_metatype.TYPE_UNKNOWN, type_metatype.TYPE_UNKNOWN);
    this.opflags = PcodeOpFlags.binary;
    this.behave = new OpBehaviorPiece();
    this.nearPointerSize = 0;
    this.farPointerSize = t.getSizeOfAltPointer();
    if (this.farPointerSize !== 0)
      this.nearPointerSize = t.getSizeOfPointer();
  }

  getOperatorName(op: PcodeOp): string {
    return `${this.name}${op.getIn(0).getSize()}${op.getIn(1).getSize()}`;
  }

  getInputCast(op: PcodeOp, slot: int4, castStrategy: CastStrategy): Datatype | null {
    return null;
  }

  getOutputToken(op: PcodeOp, castStrategy: CastStrategy): Datatype | null {
    const vn = op.getOut();
    const dt: Datatype = vn.getHighTypeDefFacing();
    const meta = dt.getMetatype();
    if (meta === type_metatype.TYPE_INT || meta === type_metatype.TYPE_UINT)
      return dt;
    return this.tlst.getBase(vn.getSize(), type_metatype.TYPE_UINT);
  }

  propagateType(alttype: Datatype, op: PcodeOp, invn: any, outvn: any, inslot: int4, outslot: int4): Datatype | null {
    if (this.nearPointerSize !== 0 && alttype.getMetatype() === type_metatype.TYPE_PTR) {
      if (inslot === 1 && outslot === -1) {
        if (invn.getSize() === this.nearPointerSize && outvn.getSize() === this.farPointerSize)
          return this.tlst.resizePointer(alttype as any, this.farPointerSize);
      } else if (inslot === -1 && outslot === 1) {
        if (invn.getSize() === this.farPointerSize && outvn.getSize() === this.nearPointerSize)
          return this.tlst.resizePointer(alttype as any, this.nearPointerSize);
      }
      return null;
    }
    if (inslot !== -1) return null;
    let byteOff = TypeOpPiece.computeByteOffsetForComposite(op, outslot);
    let dt: Datatype | null = alttype;
    while (dt !== null && (byteOff !== 0 || dt.getSize() !== outvn.getSize())) {
      const offRef = { val: BigInt(byteOff) };
      dt = dt.getSubType(BigInt(byteOff), offRef);
      byteOff = Number(offRef.val);
    }
    return dt;
  }

  static computeByteOffsetForComposite(op: PcodeOp, slot: int4): int4 {
    const inVn0 = op.getIn(0);
    if (inVn0.getSpace().isBigEndian())
      return slot === 0 ? 0 : inVn0.getSize();
    else
      return slot === 0 ? op.getIn(1).getSize() : 0;
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opPiece(op); }
}

export class TypeOpSubpiece extends TypeOpFunc {
  private nearPointerSize: int4;
  private farPointerSize: int4;

  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_SUBPIECE, "SUB", type_metatype.TYPE_UNKNOWN, type_metatype.TYPE_UNKNOWN);
    this.opflags = PcodeOpFlags.binary;
    this.behave = new OpBehaviorSubpiece();
    this.nearPointerSize = 0;
    this.farPointerSize = t.getSizeOfAltPointer();
    if (this.farPointerSize !== 0)
      this.nearPointerSize = t.getSizeOfPointer();
  }

  getOperatorName(op: PcodeOp): string {
    return `${this.name}${op.getIn(0).getSize()}${op.getOut().getSize()}`;
  }

  getInputCast(op: PcodeOp, slot: int4, castStrategy: CastStrategy): Datatype | null {
    return null;
  }

  getOutputToken(op: PcodeOp, castStrategy: CastStrategy): Datatype | null {
    const outvn = op.getOut();
    const ct: Datatype = op.getIn(0).getHighTypeReadFacing(op);
    const byteOff = TypeOpSubpiece.computeByteOffsetForComposite(op);
    const offsetRef = { val: 0n };
    const field = ct.findTruncation(BigInt(byteOff), outvn.getSize(), op, 1, offsetRef);
    if (field !== null) {
      if (outvn.getSize() === field.type.getSize())
        return field.type;
    }
    const dt: Datatype = outvn.getHighTypeDefFacing();
    if (dt.getMetatype() !== type_metatype.TYPE_UNKNOWN)
      return dt;
    return this.tlst.getBase(outvn.getSize(), type_metatype.TYPE_INT);
  }

  propagateType(alttype: Datatype, op: PcodeOp, invn: any, outvn: any, inslot: int4, outslot: int4): Datatype | null {
    if (this.nearPointerSize !== 0 && alttype.getMetatype() === type_metatype.TYPE_PTR && inslot === -1 && outslot === 0) {
      if (op.getIn(1).getOffset() !== 0n) return null;
      if (invn.getSize() === this.nearPointerSize && outvn.getSize() === this.farPointerSize)
        return this.tlst.resizePointer(alttype as any, this.farPointerSize);
      return null;
    }
    if (inslot !== 0 || outslot !== -1) return null;
    let byteOff = TypeOpSubpiece.computeByteOffsetForComposite(op);
    const meta = alttype.getMetatype();
    let dt: Datatype | null = alttype;
    if (meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_PARTIALUNION) {
      const offRef = { val: BigInt(byteOff) };
      const field = dt!.resolveTruncation(BigInt(byteOff), op, 1, offRef);
      dt = field !== null ? field.type : null;
      byteOff = Number(offRef.val);
    }
    while (dt !== null && (byteOff !== 0 || dt.getSize() !== outvn.getSize())) {
      const offRef = { val: BigInt(byteOff) };
      dt = dt.getSubType(BigInt(byteOff), offRef);
      byteOff = Number(offRef.val);
    }
    return dt;
  }

  static computeByteOffsetForComposite(op: PcodeOp): int4 {
    const outSize = op.getOut().getSize();
    const lsb = Number(op.getIn(1).getOffset());
    const vn = op.getIn(0);
    if (vn.getSpace().isBigEndian())
      return vn.getSize() - outSize - lsb;
    else
      return lsb;
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opSubpiece(op); }
}

export class TypeOpCast extends TypeOp {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_CAST, "(cast)");
    this.opflags = PcodeOpFlags.unary | PcodeOpFlags.special | PcodeOpFlags.nocollapse;
    this.behave = new OpBehavior(OpCode.CPUI_CAST, false, true);
  }

  printRaw(s: Writer, op: PcodeOp): void {
    Varnode.printRawStatic(s, op.getOut());
    s.write(" = " + this.name + " ");
    Varnode.printRawStatic(s, op.getIn(0));
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opCast(op); }
}

export class TypeOpPtradd extends TypeOp {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_PTRADD, "+");
    this.opflags = PcodeOpFlags.ternary | PcodeOpFlags.nocollapse;
    this.addlflags = TypeOp.arithmetic_op;
    this.behave = new OpBehaviorPtradd();
  }

  getInputLocal(op: PcodeOp, slot: int4): Datatype | null {
    return this.tlst.getBase(op.getIn(slot).getSize(), type_metatype.TYPE_INT);
  }

  getOutputLocal(op: PcodeOp): Datatype | null {
    return this.tlst.getBase(op.getOut().getSize(), type_metatype.TYPE_INT);
  }

  getOutputToken(op: PcodeOp, castStrategy: CastStrategy): Datatype | null {
    return op.getIn(0).getHighTypeReadFacing(op);
  }

  getInputCast(op: PcodeOp, slot: int4, castStrategy: CastStrategy): Datatype | null {
    if (slot === 0) {
      const reqtype = op.getIn(0).getTypeReadFacing(op);
      const curtype = op.getIn(0).getHighTypeReadFacing(op);
      if (reqtype.getMetatype() !== type_metatype.TYPE_PTR) return reqtype;
      if (curtype.getMetatype() !== type_metatype.TYPE_PTR) return reqtype;
      const reqbase = (reqtype as any).getPtrTo();
      const curbase = (curtype as any).getPtrTo();
      if (reqbase.getAlignSize() === curbase.getAlignSize()) return null;
      return reqtype;
    }
    return super.getInputCast(op, slot, castStrategy);
  }

  propagateType(alttype: Datatype, op: PcodeOp, invn: any, outvn: any, inslot: int4, outslot: int4): Datatype | null {
    if (inslot === 2 || outslot === 2) return null;
    if (inslot !== -1 && outslot !== -1) return null;
    if (alttype.getMetatype() !== type_metatype.TYPE_PTR) return null;
    if (inslot === -1) return null;
    return TypeOpIntAdd.propagateAddIn2Out(alttype, this.tlst, op, inslot);
  }

  printRaw(s: Writer, op: PcodeOp): void {
    Varnode.printRawStatic(s, op.getOut());
    s.write(" = ");
    Varnode.printRawStatic(s, op.getIn(0));
    s.write(" " + this.name + " ");
    Varnode.printRawStatic(s, op.getIn(1));
    s.write("(*");
    Varnode.printRawStatic(s, op.getIn(2));
    s.write(")");
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opPtradd(op); }
}

export class TypeOpPtrsub extends TypeOp {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_PTRSUB, "->");
    this.opflags = PcodeOpFlags.binary | PcodeOpFlags.nocollapse;
    this.addlflags = TypeOp.arithmetic_op;
    this.behave = new OpBehaviorPtrsub();
  }

  getOutputLocal(op: PcodeOp): Datatype | null {
    return this.tlst.getBase(op.getOut().getSize(), type_metatype.TYPE_INT);
  }

  getInputLocal(op: PcodeOp, slot: int4): Datatype | null {
    return this.tlst.getBase(op.getIn(slot).getSize(), type_metatype.TYPE_INT);
  }

  getInputCast(op: PcodeOp, slot: int4, castStrategy: CastStrategy): Datatype | null {
    if (slot === 0) {
      const reqtype = op.getIn(0).getTypeReadFacing(op);
      const curtype = op.getIn(0).getHighTypeReadFacing(op);
      if (curtype === reqtype) return null;
      if (reqtype.getMetatype() !== type_metatype.TYPE_PTR) return reqtype;
      if (curtype.getMetatype() !== type_metatype.TYPE_PTR) return reqtype;
      let reqbase = (reqtype as any).getPtrTo();
      let curbase = (curtype as any).getPtrTo();
      if (curbase.getMetatype() === type_metatype.TYPE_ARRAY && reqbase.getMetatype() === type_metatype.TYPE_ARRAY) {
        curbase = (curbase as any).getBase();
        reqbase = (reqbase as any).getBase();
      }
      while (reqbase.getTypedef() !== null) reqbase = reqbase.getTypedef();
      while (curbase.getTypedef() !== null) curbase = curbase.getTypedef();
      if (curbase === reqbase) return null;
      return reqtype;
    }
    return super.getInputCast(op, slot, castStrategy);
  }

  getOutputToken(op: PcodeOp, castStrategy: CastStrategy): Datatype | null {
    const ptype: any = op.getIn(0).getHighTypeReadFacing(op);
    if (ptype.getMetatype() === type_metatype.TYPE_PTR) {
      const offRef = { val: AddrSpace.addressToByte(op.getIn(1).getOffset(), ptype.getWordSize()) };
      const unusedParent = { val: null as any };
      const unusedOffset = { val: 0n };
      const rettype = ptype.downChain(offRef, unusedParent, unusedOffset, false, this.tlst);
      if (offRef.val === 0n && rettype !== null)
        return rettype;
      const base = this.tlst.getBase(1, type_metatype.TYPE_UNKNOWN);
      return this.tlst.getTypePointer(op.getOut().getSize(), base, ptype.getWordSize());
    }
    return super.getOutputToken(op, castStrategy);
  }

  propagateType(alttype: Datatype, op: PcodeOp, invn: any, outvn: any, inslot: int4, outslot: int4): Datatype | null {
    if (inslot !== -1 && outslot !== -1) return null;
    if (alttype.getMetatype() !== type_metatype.TYPE_PTR) return null;
    if (inslot === -1) return null;
    return TypeOpIntAdd.propagateAddIn2Out(alttype, this.tlst, op, inslot);
  }

  printRaw(s: Writer, op: PcodeOp): void {
    Varnode.printRawStatic(s, op.getOut());
    s.write(" = ");
    Varnode.printRawStatic(s, op.getIn(0));
    s.write(" " + this.name + " ");
    Varnode.printRawStatic(s, op.getIn(1));
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opPtrsub(op); }
}

export class TypeOpSegment extends TypeOp {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_SEGMENTOP, "segmentop");
    this.opflags = PcodeOpFlags.special | PcodeOpFlags.nocollapse;
    this.behave = new OpBehavior(OpCode.CPUI_SEGMENTOP, false, true);
  }

  printRaw(s: Writer, op: PcodeOp): void {
    if (op.getOut() !== null) {
      Varnode.printRawStatic(s, op.getOut());
      s.write(" = ");
    }
    s.write(this.getOperatorName(op));
    s.write("(");
    const spc = op.getIn(0).getSpaceFromConst();
    s.write(spc.getName() + ",");
    Varnode.printRawStatic(s, op.getIn(1));
    s.write(",");
    Varnode.printRawStatic(s, op.getIn(2));
    s.write(")");
  }

  getOutputToken(op: PcodeOp, castStrategy: CastStrategy): Datatype | null {
    return op.getIn(2).getHighTypeReadFacing(op);
  }

  getInputCast(op: PcodeOp, slot: int4, castStrategy: CastStrategy): Datatype | null {
    return null;
  }

  propagateType(alttype: Datatype, op: PcodeOp, invn: any, outvn: any, inslot: int4, outslot: int4): Datatype | null {
    if (inslot === 0 || inslot === 1) return null;
    if (outslot === 0 || outslot === 1) return null;
    if (invn.isSpacebase()) return null;
    if (alttype.getMetatype() !== type_metatype.TYPE_PTR) return null;
    return this.tlst.resizePointer(alttype as any, outvn.getSize());
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opSegmentOp(op); }
}

export class TypeOpCpoolref extends TypeOp {
  private cpool: ConstantPool;

  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_CPOOLREF, "cpoolref");
    this.cpool = t.getArch().cpool;
    this.opflags = PcodeOpFlags.special | PcodeOpFlags.nocollapse;
    this.behave = new OpBehavior(OpCode.CPUI_CPOOLREF, false, true);
  }

  getOutputLocal(op: PcodeOp): Datatype | null {
    const refs: uintb[] = [];
    for (let i = 1; i < op.numInput(); ++i)
      refs.push(op.getIn(i).getOffset());
    const rec = this.cpool.getRecord(refs);
    if (rec === null) return super.getOutputLocal(op);
    if (rec.getTag() === 3) // CPoolRecord::instance_of
      return this.tlst.getBase(1, type_metatype.TYPE_BOOL);
    return rec.getType();
  }

  getInputLocal(op: PcodeOp, slot: int4): Datatype | null {
    return this.tlst.getBase(op.getIn(slot).getSize(), type_metatype.TYPE_INT);
  }

  printRaw(s: Writer, op: PcodeOp): void {
    if (op.getOut() !== null) {
      Varnode.printRawStatic(s, op.getOut());
      s.write(" = ");
    }
    s.write(this.getOperatorName(op));
    const refs: uintb[] = [];
    for (let i = 1; i < op.numInput(); ++i)
      refs.push(op.getIn(i).getOffset());
    const rec = this.cpool.getRecord(refs);
    if (rec !== null)
      s.write("_" + rec.getToken());
    s.write("(");
    Varnode.printRawStatic(s, op.getIn(0));
    for (let i = 2; i < op.numInput(); ++i) {
      s.write(",");
      Varnode.printRawStatic(s, op.getIn(i));
    }
    s.write(")");
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opCpoolRefOp(op); }
}

export class TypeOpNew extends TypeOp {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_NEW, "new");
    this.opflags = PcodeOpFlags.special | PcodeOpFlags.call | PcodeOpFlags.nocollapse;
    this.behave = new OpBehavior(OpCode.CPUI_NEW, false, true);
  }

  propagateType(alttype: Datatype, op: PcodeOp, invn: any, outvn: any, inslot: int4, outslot: int4): Datatype | null {
    if (inslot !== 0 || outslot !== -1) return null;
    const vn0 = op.getIn(0);
    if (!vn0.isWritten()) return null;
    if (vn0.getDef().code() !== OpCode.CPUI_CPOOLREF) return null;
    return alttype;
  }

  printRaw(s: Writer, op: PcodeOp): void {
    if (op.getOut() !== null) {
      Varnode.printRawStatic(s, op.getOut());
      s.write(" = ");
    }
    s.write(this.getOperatorName(op));
    s.write("(");
    Varnode.printRawStatic(s, op.getIn(0));
    for (let i = 1; i < op.numInput(); ++i) {
      s.write(",");
      Varnode.printRawStatic(s, op.getIn(i));
    }
    s.write(")");
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opNewOp(op); }
}

export class TypeOpInsert extends TypeOpFunc {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_INSERT, "INSERT", type_metatype.TYPE_UNKNOWN, type_metatype.TYPE_INT);
    this.opflags = PcodeOpFlags.ternary;
    this.behave = new OpBehavior(OpCode.CPUI_INSERT, false);
  }

  getInputLocal(op: PcodeOp, slot: int4): Datatype | null {
    if (slot === 0)
      return this.tlst.getBase(op.getIn(slot).getSize(), type_metatype.TYPE_UNKNOWN);
    return super.getInputLocal(op, slot);
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opInsertOp(op); }
}

export class TypeOpExtract extends TypeOpFunc {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_EXTRACT, "EXTRACT", type_metatype.TYPE_INT, type_metatype.TYPE_INT);
    this.opflags = PcodeOpFlags.ternary;
    this.behave = new OpBehavior(OpCode.CPUI_EXTRACT, false);
  }

  getInputLocal(op: PcodeOp, slot: int4): Datatype | null {
    if (slot === 0)
      return this.tlst.getBase(op.getIn(slot).getSize(), type_metatype.TYPE_UNKNOWN);
    return super.getInputLocal(op, slot);
  }

  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opExtractOp(op); }
}

export class TypeOpPopcount extends TypeOpFunc {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_POPCOUNT, "POPCOUNT", type_metatype.TYPE_INT, type_metatype.TYPE_UNKNOWN);
    this.opflags = PcodeOpFlags.unary;
    this.behave = new OpBehaviorPopcount();
  }
  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opPopcountOp(op); }
}

export class TypeOpLzcount extends TypeOpFunc {
  constructor(t: TypeFactory) {
    super(t, OpCode.CPUI_LZCOUNT, "LZCOUNT", type_metatype.TYPE_INT, type_metatype.TYPE_UNKNOWN);
    this.opflags = PcodeOpFlags.unary;
    this.behave = new OpBehaviorLzcount();
  }
  push(lng: PrintLanguage, op: PcodeOp, readOp: PcodeOp | null): void { lng.opLzcountOp(op); }
}
