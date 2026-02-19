/**
 * @file opbehavior.ts
 * @description Classes for describing the behavior of individual p-code operations,
 * translated from Ghidra's opbehavior.hh / opbehavior.cc
 */

import { LowlevelError } from './error.js';
import { OpCode, get_opname } from './opcodes.js';

// ---------------------------------------------------------------------------
// Utility functions (from address.hh / address.cc)
// ---------------------------------------------------------------------------

/**
 * Calculate a mask for a given byte size.
 * If size >= 8, returns 0xFFFFFFFFFFFFFFFF (all 64 bits set).
 * Otherwise returns (1 << (size*8)) - 1.
 */
export function calc_mask(size: number): bigint {
  if (size >= 8) return 0xFFFFFFFFFFFFFFFFn;
  if (size <= 0) return 0n;
  return (1n << BigInt(size * 8)) - 1n;
}

/**
 * Return true if the sign-bit is set (i.e. the value is negative in signed interpretation).
 */
export function signbit_negative(val: bigint, size: number): boolean {
  const mask = 0x80n << BigInt(8 * (size - 1));
  return (val & mask) !== 0n;
}

/**
 * Negate (bitwise NOT) the value, keeping only the lower size bytes.
 */
export function uintb_negate(val: bigint, size: number): bigint {
  return (~val) & calc_mask(size);
}

/**
 * Sign-extend a value from sizein bytes to sizeout bytes.
 * The result keeps only the lower sizeout bytes.
 */
export function sign_extend(val: bigint, sizein: number, sizeout: number): bigint {
  // Clamp to 8 bytes max (64-bit)
  sizein = sizein < 8 ? sizein : 8;
  sizeout = sizeout < 8 ? sizeout : 8;

  // Treat val as a signed value of sizein bytes by shifting left then arithmetic right
  // In bigint, >> is arithmetic shift for negative values.
  // We need to simulate the C++ behavior:
  //   sval = (intb)in;
  //   sval <<= (sizeof(intb) - sizein) * 8;
  //   res = (uintb)(sval >> (sizeout - sizein) * 8);
  //   res >>= (sizeof(uintb) - sizeout) * 8;

  // Convert to signed 64-bit
  let sval = BigInt.asIntN(64, val);
  sval = sval << BigInt((8 - sizein) * 8);
  // Arithmetic right shift back
  let res = sval >> BigInt((sizeout - sizein) * 8);
  // Logical right shift by remaining amount (use BigInt.asUintN to convert to unsigned first)
  let ures = BigInt.asUintN(64, res);
  ures = ures >> BigInt((8 - sizeout) * 8);
  return ures;
}

/**
 * Sign-extend a value starting at the given bit position.
 * This is the intb sign_extend(intb val, int4 bit) overload from address.hh.
 */
export function sign_extend_by_bit(val: bigint, bit: number): bigint {
  const sa = 64 - (bit + 1);
  let sval = BigInt.asIntN(64, val);
  sval = (sval << BigInt(sa)) >> BigInt(sa);
  return sval;
}

/**
 * Zero extend val starting at the given bit position.
 * Equivalent to clearing all bits above position 'bit'.
 */
export function zero_extend(val: bigint, bit: number): bigint {
  const sa = 64 - (bit + 1);
  // Shift left to clear upper bits, then logical shift right
  let uval = BigInt.asUintN(64, val);
  uval = (uval << BigInt(sa)) >> BigInt(sa);
  return BigInt.asUintN(64, uval);
}

/**
 * Count the number of set bits (1-bits) in the given 64-bit value.
 */
export function popcount(val: bigint): number {
  val = BigInt.asUintN(64, val);
  val = (val & 0x5555555555555555n) + ((val >> 1n) & 0x5555555555555555n);
  val = (val & 0x3333333333333333n) + ((val >> 2n) & 0x3333333333333333n);
  val = (val & 0x0f0f0f0f0f0f0f0fn) + ((val >> 4n) & 0x0f0f0f0f0f0f0f0fn);
  val = (val & 0x00ff00ff00ff00ffn) + ((val >> 8n) & 0x00ff00ff00ff00ffn);
  val = (val & 0x0000ffff0000ffffn) + ((val >> 16n) & 0x0000ffff0000ffffn);
  let res = Number(val & 0xffn);
  res += Number((val >> 32n) & 0xffn);
  return res;
}

/**
 * Count the number of leading zero bits in a 64-bit value.
 */
export function count_leading_zeros(val: bigint): number {
  val = BigInt.asUintN(64, val);
  if (val === 0n) return 64;

  let mask = 0xFFFFFFFFFFFFFFFFn; // all 64 bits
  let maskSize = 32;
  mask = mask & (mask << BigInt(maskSize));
  let bit = 0;

  do {
    if ((mask & val) === 0n) {
      bit += maskSize;
      maskSize >>= 1;
      mask = mask | (mask >> BigInt(maskSize));
    } else {
      maskSize >>= 1;
      mask = mask & (mask << BigInt(maskSize));
    }
  } while (maskSize !== 0);

  return bit;
}

// ---------------------------------------------------------------------------
// EvaluationError
// ---------------------------------------------------------------------------

/**
 * Exception thrown when emulation evaluation of an operator fails.
 * Can be thrown for either forward or reverse emulation.
 */
export class EvaluationError extends LowlevelError {
  constructor(s: string) {
    super(s);
    this.name = 'EvaluationError';
  }
}

// ---------------------------------------------------------------------------
// OpBehavior base class
// ---------------------------------------------------------------------------

/**
 * Class encapsulating the action/behavior of specific pcode opcodes.
 *
 * At the lowest level, a pcode op is one of a small set of opcodes that
 * operate on varnodes (address space, offset, size). Classes derived from
 * this base class encapsulate this basic behavior for each possible opcode.
 */
export class OpBehavior {
  private opcode: OpCode;
  private isunary: boolean;
  private isspecial: boolean;

  /**
   * A behavior constructor.
   * @param opc - the opcode of the behavior
   * @param isun - true if the behavior is unary, false if binary
   * @param isspec - true if the behavior is neither unary nor binary (special)
   */
  constructor(opc: OpCode, isun: boolean, isspec: boolean = false) {
    this.opcode = opc;
    this.isunary = isun;
    this.isspecial = isspec;
  }

  /** Get the opcode for this pcode operation */
  getOpcode(): OpCode {
    return this.opcode;
  }

  /** Check if this is a special operator */
  isSpecial(): boolean {
    return this.isspecial;
  }

  /** Check if operator is unary */
  isUnary(): boolean {
    return this.isunary;
  }

  /** Emulate the unary op-code on an input value */
  evaluateUnary(sizeout: number, sizein: number, in1: bigint): bigint {
    const name = get_opname(this.opcode);
    throw new LowlevelError('Unary emulation unimplemented for ' + name);
  }

  /** Emulate the binary op-code on input values */
  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    const name = get_opname(this.opcode);
    throw new LowlevelError('Binary emulation unimplemented for ' + name);
  }

  /** Emulate the ternary op-code on input values */
  evaluateTernary(sizeout: number, sizein: number, in1: bigint, in2: bigint, in3: bigint): bigint {
    const name = get_opname(this.opcode);
    throw new LowlevelError('Ternary emulation unimplemented for ' + name);
  }

  /** Reverse the unary op-code operation, recovering the input value */
  recoverInputUnary(sizeout: number, out: bigint, sizein: number): bigint {
    throw new LowlevelError('Cannot recover input parameter without loss of information');
  }

  /** Reverse the binary op-code operation, recovering an input value */
  recoverInputBinary(slot: number, sizeout: number, out: bigint, sizein: number, inp: bigint): bigint {
    throw new LowlevelError('Cannot recover input parameter without loss of information');
  }

  /**
   * Build all pcode behaviors, indexed by opcode.
   * @param trans - the Translate object needed by floating point behaviors
   * @returns array of OpBehavior objects indexed by OpCode
   */
  static registerInstructions(trans: any): OpBehavior[] {
    const inst: (OpBehavior | null)[] = new Array(OpCode.CPUI_MAX).fill(null);

    inst[OpCode.CPUI_COPY] = new OpBehaviorCopy();
    inst[OpCode.CPUI_LOAD] = new OpBehavior(OpCode.CPUI_LOAD, false, true);
    inst[OpCode.CPUI_STORE] = new OpBehavior(OpCode.CPUI_STORE, false, true);
    inst[OpCode.CPUI_BRANCH] = new OpBehavior(OpCode.CPUI_BRANCH, false, true);
    inst[OpCode.CPUI_CBRANCH] = new OpBehavior(OpCode.CPUI_CBRANCH, false, true);
    inst[OpCode.CPUI_BRANCHIND] = new OpBehavior(OpCode.CPUI_BRANCHIND, false, true);
    inst[OpCode.CPUI_CALL] = new OpBehavior(OpCode.CPUI_CALL, false, true);
    inst[OpCode.CPUI_CALLIND] = new OpBehavior(OpCode.CPUI_CALLIND, false, true);
    inst[OpCode.CPUI_CALLOTHER] = new OpBehavior(OpCode.CPUI_CALLOTHER, false, true);
    inst[OpCode.CPUI_RETURN] = new OpBehavior(OpCode.CPUI_RETURN, false, true);

    inst[OpCode.CPUI_MULTIEQUAL] = new OpBehavior(OpCode.CPUI_MULTIEQUAL, false, true);
    inst[OpCode.CPUI_INDIRECT] = new OpBehavior(OpCode.CPUI_INDIRECT, false, true);

    inst[OpCode.CPUI_PIECE] = new OpBehaviorPiece();
    inst[OpCode.CPUI_SUBPIECE] = new OpBehaviorSubpiece();
    inst[OpCode.CPUI_INT_EQUAL] = new OpBehaviorEqual();
    inst[OpCode.CPUI_INT_NOTEQUAL] = new OpBehaviorNotEqual();
    inst[OpCode.CPUI_INT_SLESS] = new OpBehaviorIntSless();
    inst[OpCode.CPUI_INT_SLESSEQUAL] = new OpBehaviorIntSlessEqual();
    inst[OpCode.CPUI_INT_LESS] = new OpBehaviorIntLess();
    inst[OpCode.CPUI_INT_LESSEQUAL] = new OpBehaviorIntLessEqual();
    inst[OpCode.CPUI_INT_ZEXT] = new OpBehaviorIntZext();
    inst[OpCode.CPUI_INT_SEXT] = new OpBehaviorIntSext();
    inst[OpCode.CPUI_INT_ADD] = new OpBehaviorIntAdd();
    inst[OpCode.CPUI_INT_SUB] = new OpBehaviorIntSub();
    inst[OpCode.CPUI_INT_CARRY] = new OpBehaviorIntCarry();
    inst[OpCode.CPUI_INT_SCARRY] = new OpBehaviorIntScarry();
    inst[OpCode.CPUI_INT_SBORROW] = new OpBehaviorIntSborrow();
    inst[OpCode.CPUI_INT_2COMP] = new OpBehaviorInt2Comp();
    inst[OpCode.CPUI_INT_NEGATE] = new OpBehaviorIntNegate();
    inst[OpCode.CPUI_INT_XOR] = new OpBehaviorIntXor();
    inst[OpCode.CPUI_INT_AND] = new OpBehaviorIntAnd();
    inst[OpCode.CPUI_INT_OR] = new OpBehaviorIntOr();
    inst[OpCode.CPUI_INT_LEFT] = new OpBehaviorIntLeft();
    inst[OpCode.CPUI_INT_RIGHT] = new OpBehaviorIntRight();
    inst[OpCode.CPUI_INT_SRIGHT] = new OpBehaviorIntSright();
    inst[OpCode.CPUI_INT_MULT] = new OpBehaviorIntMult();
    inst[OpCode.CPUI_INT_DIV] = new OpBehaviorIntDiv();
    inst[OpCode.CPUI_INT_SDIV] = new OpBehaviorIntSdiv();
    inst[OpCode.CPUI_INT_REM] = new OpBehaviorIntRem();
    inst[OpCode.CPUI_INT_SREM] = new OpBehaviorIntSrem();

    inst[OpCode.CPUI_BOOL_NEGATE] = new OpBehaviorBoolNegate();
    inst[OpCode.CPUI_BOOL_XOR] = new OpBehaviorBoolXor();
    inst[OpCode.CPUI_BOOL_AND] = new OpBehaviorBoolAnd();
    inst[OpCode.CPUI_BOOL_OR] = new OpBehaviorBoolOr();

    inst[OpCode.CPUI_CAST] = new OpBehavior(OpCode.CPUI_CAST, false, true);
    inst[OpCode.CPUI_PTRADD] = new OpBehavior(OpCode.CPUI_PTRADD, false);
    inst[OpCode.CPUI_PTRSUB] = new OpBehavior(OpCode.CPUI_PTRSUB, false);

    inst[OpCode.CPUI_FLOAT_EQUAL] = new OpBehaviorFloatEqual(trans);
    inst[OpCode.CPUI_FLOAT_NOTEQUAL] = new OpBehaviorFloatNotEqual(trans);
    inst[OpCode.CPUI_FLOAT_LESS] = new OpBehaviorFloatLess(trans);
    inst[OpCode.CPUI_FLOAT_LESSEQUAL] = new OpBehaviorFloatLessEqual(trans);
    inst[OpCode.CPUI_FLOAT_NAN] = new OpBehaviorFloatNan(trans);

    inst[OpCode.CPUI_FLOAT_ADD] = new OpBehaviorFloatAdd(trans);
    inst[OpCode.CPUI_FLOAT_DIV] = new OpBehaviorFloatDiv(trans);
    inst[OpCode.CPUI_FLOAT_MULT] = new OpBehaviorFloatMult(trans);
    inst[OpCode.CPUI_FLOAT_SUB] = new OpBehaviorFloatSub(trans);
    inst[OpCode.CPUI_FLOAT_NEG] = new OpBehaviorFloatNeg(trans);
    inst[OpCode.CPUI_FLOAT_ABS] = new OpBehaviorFloatAbs(trans);
    inst[OpCode.CPUI_FLOAT_SQRT] = new OpBehaviorFloatSqrt(trans);

    inst[OpCode.CPUI_FLOAT_INT2FLOAT] = new OpBehaviorFloatInt2Float(trans);
    inst[OpCode.CPUI_FLOAT_FLOAT2FLOAT] = new OpBehaviorFloatFloat2Float(trans);
    inst[OpCode.CPUI_FLOAT_TRUNC] = new OpBehaviorFloatTrunc(trans);
    inst[OpCode.CPUI_FLOAT_CEIL] = new OpBehaviorFloatCeil(trans);
    inst[OpCode.CPUI_FLOAT_FLOOR] = new OpBehaviorFloatFloor(trans);
    inst[OpCode.CPUI_FLOAT_ROUND] = new OpBehaviorFloatRound(trans);

    inst[OpCode.CPUI_SEGMENTOP] = new OpBehavior(OpCode.CPUI_SEGMENTOP, false, true);
    inst[OpCode.CPUI_CPOOLREF] = new OpBehavior(OpCode.CPUI_CPOOLREF, false, true);
    inst[OpCode.CPUI_NEW] = new OpBehavior(OpCode.CPUI_NEW, false, true);
    inst[OpCode.CPUI_INSERT] = new OpBehavior(OpCode.CPUI_INSERT, false);
    inst[OpCode.CPUI_EXTRACT] = new OpBehavior(OpCode.CPUI_EXTRACT, false);
    inst[OpCode.CPUI_POPCOUNT] = new OpBehaviorPopcount();
    inst[OpCode.CPUI_LZCOUNT] = new OpBehaviorLzcount();

    return inst as OpBehavior[];
  }
}

// ---------------------------------------------------------------------------
// Concrete behavior subclasses
// ---------------------------------------------------------------------------

/** CPUI_COPY behavior */
export class OpBehaviorCopy extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_COPY, true);
  }

  evaluateUnary(sizeout: number, sizein: number, in1: bigint): bigint {
    return in1;
  }

  recoverInputUnary(sizeout: number, out: bigint, sizein: number): bigint {
    return out;
  }
}

/** CPUI_INT_EQUAL behavior */
export class OpBehaviorEqual extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_EQUAL, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    return (in1 === in2) ? 1n : 0n;
  }
}

/** CPUI_INT_NOTEQUAL behavior */
export class OpBehaviorNotEqual extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_NOTEQUAL, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    return (in1 !== in2) ? 1n : 0n;
  }
}

/** CPUI_INT_SLESS behavior */
export class OpBehaviorIntSless extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_SLESS, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    if (sizein <= 0) return 0n;
    const mask = 0x80n << BigInt(8 * (sizein - 1));
    const bit1 = in1 & mask;
    const bit2 = in2 & mask;
    if (bit1 !== bit2) {
      return (bit1 !== 0n) ? 1n : 0n;
    }
    return (in1 < in2) ? 1n : 0n;
  }
}

/** CPUI_INT_SLESSEQUAL behavior */
export class OpBehaviorIntSlessEqual extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_SLESSEQUAL, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    if (sizein <= 0) return 0n;
    const mask = 0x80n << BigInt(8 * (sizein - 1));
    const bit1 = in1 & mask;
    const bit2 = in2 & mask;
    if (bit1 !== bit2) {
      return (bit1 !== 0n) ? 1n : 0n;
    }
    return (in1 <= in2) ? 1n : 0n;
  }
}

/** CPUI_INT_LESS behavior */
export class OpBehaviorIntLess extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_LESS, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    return (in1 < in2) ? 1n : 0n;
  }
}

/** CPUI_INT_LESSEQUAL behavior */
export class OpBehaviorIntLessEqual extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_LESSEQUAL, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    return (in1 <= in2) ? 1n : 0n;
  }
}

/** CPUI_INT_ZEXT behavior */
export class OpBehaviorIntZext extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_ZEXT, true);
  }

  evaluateUnary(sizeout: number, sizein: number, in1: bigint): bigint {
    return in1;
  }

  recoverInputUnary(sizeout: number, out: bigint, sizein: number): bigint {
    const mask = calc_mask(sizein);
    if ((mask & out) !== out) {
      throw new EvaluationError('Output is not in range of zext operation');
    }
    return out;
  }
}

/** CPUI_INT_SEXT behavior */
export class OpBehaviorIntSext extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_SEXT, true);
  }

  evaluateUnary(sizeout: number, sizein: number, in1: bigint): bigint {
    return sign_extend(in1, sizein, sizeout);
  }

  recoverInputUnary(sizeout: number, out: bigint, sizein: number): bigint {
    const masklong = calc_mask(sizeout);
    const maskshort = calc_mask(sizein);

    if ((out & (maskshort ^ (maskshort >> 1n))) === 0n) {
      // Positive input
      if ((out & maskshort) !== out) {
        throw new EvaluationError('Output is not in range of sext operation');
      }
    } else {
      // Negative input
      if ((out & (masklong ^ maskshort)) !== (masklong ^ maskshort)) {
        throw new EvaluationError('Output is not in range of sext operation');
      }
    }
    return out & maskshort;
  }
}

/** CPUI_INT_ADD behavior */
export class OpBehaviorIntAdd extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_ADD, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    return (in1 + in2) & calc_mask(sizeout);
  }

  recoverInputBinary(slot: number, sizeout: number, out: bigint, sizein: number, inp: bigint): bigint {
    return (out - inp) & calc_mask(sizeout);
  }
}

/** CPUI_INT_SUB behavior */
export class OpBehaviorIntSub extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_SUB, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    return (in1 - in2) & calc_mask(sizeout);
  }

  recoverInputBinary(slot: number, sizeout: number, out: bigint, sizein: number, inp: bigint): bigint {
    let res: bigint;
    if (slot === 0) {
      res = inp + out;
    } else {
      res = inp - out;
    }
    return res & calc_mask(sizeout);
  }
}

/** CPUI_INT_CARRY behavior */
export class OpBehaviorIntCarry extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_CARRY, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    return (in1 > ((in1 + in2) & calc_mask(sizein))) ? 1n : 0n;
  }
}

/** CPUI_INT_SCARRY behavior */
export class OpBehaviorIntScarry extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_SCARRY, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    const res = in1 + in2;
    const shiftAmt = BigInt(sizein * 8 - 1);
    let a = Number((in1 >> shiftAmt) & 1n);
    let b = Number((in2 >> shiftAmt) & 1n);
    let r = Number((res >> shiftAmt) & 1n);
    r ^= a;
    a ^= b;
    a ^= 1;
    r &= a;
    return BigInt(r);
  }
}

/** CPUI_INT_SBORROW behavior */
export class OpBehaviorIntSborrow extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_SBORROW, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    const res = in1 - in2;
    const shiftAmt = BigInt(sizein * 8 - 1);
    let a = Number((in1 >> shiftAmt) & 1n);
    let b = Number((in2 >> shiftAmt) & 1n);
    let r = Number((res >> shiftAmt) & 1n);
    a ^= r;
    r ^= b;
    r ^= 1;
    a &= r;
    return BigInt(a);
  }
}

/** CPUI_INT_2COMP behavior (two's complement) */
export class OpBehaviorInt2Comp extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_2COMP, true);
  }

  evaluateUnary(sizeout: number, sizein: number, in1: bigint): bigint {
    return uintb_negate(in1 - 1n, sizein);
  }

  recoverInputUnary(sizeout: number, out: bigint, sizein: number): bigint {
    return uintb_negate(out - 1n, sizein);
  }
}

/** CPUI_INT_NEGATE behavior (bitwise NOT) */
export class OpBehaviorIntNegate extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_NEGATE, true);
  }

  evaluateUnary(sizeout: number, sizein: number, in1: bigint): bigint {
    return uintb_negate(in1, sizein);
  }

  recoverInputUnary(sizeout: number, out: bigint, sizein: number): bigint {
    return uintb_negate(out, sizein);
  }
}

/** CPUI_INT_XOR behavior */
export class OpBehaviorIntXor extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_XOR, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    return in1 ^ in2;
  }
}

/** CPUI_INT_AND behavior */
export class OpBehaviorIntAnd extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_AND, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    return in1 & in2;
  }
}

/** CPUI_INT_OR behavior */
export class OpBehaviorIntOr extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_OR, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    return in1 | in2;
  }
}

/** CPUI_INT_LEFT behavior */
export class OpBehaviorIntLeft extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_LEFT, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    if (in2 >= BigInt(sizeout * 8)) {
      return 0n;
    }
    return (in1 << in2) & calc_mask(sizeout);
  }

  recoverInputBinary(slot: number, sizeout: number, out: bigint, sizein: number, inp: bigint): bigint {
    if (slot !== 0 || inp >= BigInt(sizeout * 8)) {
      return super.recoverInputBinary(slot, sizeout, out, sizein, inp);
    }
    const sa = inp;
    if (((out << (BigInt(8 * sizeout) - sa)) & calc_mask(sizeout)) !== 0n) {
      throw new EvaluationError('Output is not in range of left shift operation');
    }
    return out >> sa;
  }
}

/** CPUI_INT_RIGHT behavior */
export class OpBehaviorIntRight extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_RIGHT, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    if (in2 >= BigInt(sizeout * 8)) {
      return 0n;
    }
    return (in1 & calc_mask(sizeout)) >> in2;
  }

  recoverInputBinary(slot: number, sizeout: number, out: bigint, sizein: number, inp: bigint): bigint {
    if (slot !== 0 || inp >= BigInt(sizeout * 8)) {
      return super.recoverInputBinary(slot, sizeout, out, sizein, inp);
    }
    const sa = inp;
    if ((out >> (BigInt(8 * sizein) - sa)) !== 0n) {
      throw new EvaluationError('Output is not in range of right shift operation');
    }
    return out << sa;
  }
}

/** CPUI_INT_SRIGHT behavior (arithmetic right shift) */
export class OpBehaviorIntSright extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_SRIGHT, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    if (in2 >= BigInt(8 * sizeout)) {
      return signbit_negative(in1, sizein) ? calc_mask(sizeout) : 0n;
    }
    if (signbit_negative(in1, sizein)) {
      let res = in1 >> in2;
      let mask = calc_mask(sizein);
      mask = (mask >> in2) ^ mask;
      res |= mask;
      return res;
    }
    return in1 >> in2;
  }

  recoverInputBinary(slot: number, sizeout: number, out: bigint, sizein: number, inp: bigint): bigint {
    if (slot !== 0 || inp >= BigInt(sizeout * 8)) {
      return super.recoverInputBinary(slot, sizeout, out, sizein, inp);
    }
    const sa = Number(inp);
    let testval = out >> BigInt(sizein * 8 - sa - 1);
    let count = 0;
    for (let i = 0; i <= sa; ++i) {
      if ((testval & 1n) !== 0n) count += 1;
      testval >>= 1n;
    }
    if (count !== sa + 1) {
      throw new EvaluationError('Output is not in range of right shift operation');
    }
    return out << inp;
  }
}

/** CPUI_INT_MULT behavior */
export class OpBehaviorIntMult extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_MULT, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    return (in1 * in2) & calc_mask(sizeout);
  }
}

/** CPUI_INT_DIV behavior (unsigned division) */
export class OpBehaviorIntDiv extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_DIV, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    if (in2 === 0n) {
      throw new EvaluationError('Divide by 0');
    }
    return in1 / in2;
  }
}

/** CPUI_INT_SDIV behavior (signed division) */
export class OpBehaviorIntSdiv extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_SDIV, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    if (in2 === 0n) {
      throw new EvaluationError('Divide by 0');
    }
    const num = sign_extend_by_bit(in1, 8 * sizein - 1);
    const denom = sign_extend_by_bit(in2, 8 * sizein - 1);
    let sres = num / denom;
    sres = zero_extend(sres, 8 * sizeout - 1);
    return BigInt.asUintN(64, sres);
  }
}

/** CPUI_INT_REM behavior (unsigned remainder) */
export class OpBehaviorIntRem extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_REM, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    if (in2 === 0n) {
      throw new EvaluationError('Remainder by 0');
    }
    return in1 % in2;
  }
}

/** CPUI_INT_SREM behavior (signed remainder) */
export class OpBehaviorIntSrem extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_INT_SREM, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    if (in2 === 0n) {
      throw new EvaluationError('Remainder by 0');
    }
    const val = sign_extend_by_bit(in1, 8 * sizein - 1);
    const mod = sign_extend_by_bit(in2, 8 * sizein - 1);
    let sres = val % mod;
    sres = zero_extend(sres, 8 * sizeout - 1);
    return BigInt.asUintN(64, sres);
  }
}

/** CPUI_BOOL_NEGATE behavior */
export class OpBehaviorBoolNegate extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_BOOL_NEGATE, true);
  }

  evaluateUnary(sizeout: number, sizein: number, in1: bigint): bigint {
    return in1 ^ 1n;
  }
}

/** CPUI_BOOL_XOR behavior */
export class OpBehaviorBoolXor extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_BOOL_XOR, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    return in1 ^ in2;
  }
}

/** CPUI_BOOL_AND behavior */
export class OpBehaviorBoolAnd extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_BOOL_AND, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    return in1 & in2;
  }
}

/** CPUI_BOOL_OR behavior */
export class OpBehaviorBoolOr extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_BOOL_OR, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    return in1 | in2;
  }
}

// ---------------------------------------------------------------------------
// Float behavior subclasses
// ---------------------------------------------------------------------------

/** CPUI_FLOAT_EQUAL behavior */
export class OpBehaviorFloatEqual extends OpBehavior {
  private translate: any;

  constructor(trans: any) {
    super(OpCode.CPUI_FLOAT_EQUAL, false);
    this.translate = trans;
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    const format = this.translate?.getFloatFormat(sizein);
    if (format == null) {
      return super.evaluateBinary(sizeout, sizein, in1, in2);
    }
    return format.opEqual(in1, in2);
  }
}

/** CPUI_FLOAT_NOTEQUAL behavior */
export class OpBehaviorFloatNotEqual extends OpBehavior {
  private translate: any;

  constructor(trans: any) {
    super(OpCode.CPUI_FLOAT_NOTEQUAL, false);
    this.translate = trans;
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    const format = this.translate?.getFloatFormat(sizein);
    if (format == null) {
      return super.evaluateBinary(sizeout, sizein, in1, in2);
    }
    return format.opNotEqual(in1, in2);
  }
}

/** CPUI_FLOAT_LESS behavior */
export class OpBehaviorFloatLess extends OpBehavior {
  private translate: any;

  constructor(trans: any) {
    super(OpCode.CPUI_FLOAT_LESS, false);
    this.translate = trans;
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    const format = this.translate?.getFloatFormat(sizein);
    if (format == null) {
      return super.evaluateBinary(sizeout, sizein, in1, in2);
    }
    return format.opLess(in1, in2);
  }
}

/** CPUI_FLOAT_LESSEQUAL behavior */
export class OpBehaviorFloatLessEqual extends OpBehavior {
  private translate: any;

  constructor(trans: any) {
    super(OpCode.CPUI_FLOAT_LESSEQUAL, false);
    this.translate = trans;
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    const format = this.translate?.getFloatFormat(sizein);
    if (format == null) {
      return super.evaluateBinary(sizeout, sizein, in1, in2);
    }
    return format.opLessEqual(in1, in2);
  }
}

/** CPUI_FLOAT_NAN behavior */
export class OpBehaviorFloatNan extends OpBehavior {
  private translate: any;

  constructor(trans: any) {
    super(OpCode.CPUI_FLOAT_NAN, true);
    this.translate = trans;
  }

  evaluateUnary(sizeout: number, sizein: number, in1: bigint): bigint {
    const format = this.translate?.getFloatFormat(sizein);
    if (format == null) {
      return super.evaluateUnary(sizeout, sizein, in1);
    }
    return format.opNan(in1);
  }
}

/** CPUI_FLOAT_ADD behavior */
export class OpBehaviorFloatAdd extends OpBehavior {
  private translate: any;

  constructor(trans: any) {
    super(OpCode.CPUI_FLOAT_ADD, false);
    this.translate = trans;
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    const format = this.translate?.getFloatFormat(sizein);
    if (format == null) {
      return super.evaluateBinary(sizeout, sizein, in1, in2);
    }
    return format.opAdd(in1, in2);
  }
}

/** CPUI_FLOAT_DIV behavior */
export class OpBehaviorFloatDiv extends OpBehavior {
  private translate: any;

  constructor(trans: any) {
    super(OpCode.CPUI_FLOAT_DIV, false);
    this.translate = trans;
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    const format = this.translate?.getFloatFormat(sizein);
    if (format == null) {
      return super.evaluateBinary(sizeout, sizein, in1, in2);
    }
    return format.opDiv(in1, in2);
  }
}

/** CPUI_FLOAT_MULT behavior */
export class OpBehaviorFloatMult extends OpBehavior {
  private translate: any;

  constructor(trans: any) {
    super(OpCode.CPUI_FLOAT_MULT, false);
    this.translate = trans;
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    const format = this.translate?.getFloatFormat(sizein);
    if (format == null) {
      return super.evaluateBinary(sizeout, sizein, in1, in2);
    }
    return format.opMult(in1, in2);
  }
}

/** CPUI_FLOAT_SUB behavior */
export class OpBehaviorFloatSub extends OpBehavior {
  private translate: any;

  constructor(trans: any) {
    super(OpCode.CPUI_FLOAT_SUB, false);
    this.translate = trans;
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    const format = this.translate?.getFloatFormat(sizein);
    if (format == null) {
      return super.evaluateBinary(sizeout, sizein, in1, in2);
    }
    return format.opSub(in1, in2);
  }
}

/** CPUI_FLOAT_NEG behavior */
export class OpBehaviorFloatNeg extends OpBehavior {
  private translate: any;

  constructor(trans: any) {
    super(OpCode.CPUI_FLOAT_NEG, true);
    this.translate = trans;
  }

  evaluateUnary(sizeout: number, sizein: number, in1: bigint): bigint {
    const format = this.translate?.getFloatFormat(sizein);
    if (format == null) {
      return super.evaluateUnary(sizeout, sizein, in1);
    }
    return format.opNeg(in1);
  }
}

/** CPUI_FLOAT_ABS behavior */
export class OpBehaviorFloatAbs extends OpBehavior {
  private translate: any;

  constructor(trans: any) {
    super(OpCode.CPUI_FLOAT_ABS, true);
    this.translate = trans;
  }

  evaluateUnary(sizeout: number, sizein: number, in1: bigint): bigint {
    const format = this.translate?.getFloatFormat(sizein);
    if (format == null) {
      return super.evaluateUnary(sizeout, sizein, in1);
    }
    return format.opAbs(in1);
  }
}

/** CPUI_FLOAT_SQRT behavior */
export class OpBehaviorFloatSqrt extends OpBehavior {
  private translate: any;

  constructor(trans: any) {
    super(OpCode.CPUI_FLOAT_SQRT, true);
    this.translate = trans;
  }

  evaluateUnary(sizeout: number, sizein: number, in1: bigint): bigint {
    const format = this.translate?.getFloatFormat(sizein);
    if (format == null) {
      return super.evaluateUnary(sizeout, sizein, in1);
    }
    return format.opSqrt(in1);
  }
}

/** CPUI_FLOAT_INT2FLOAT behavior */
export class OpBehaviorFloatInt2Float extends OpBehavior {
  private translate: any;

  constructor(trans: any) {
    super(OpCode.CPUI_FLOAT_INT2FLOAT, true);
    this.translate = trans;
  }

  evaluateUnary(sizeout: number, sizein: number, in1: bigint): bigint {
    const format = this.translate?.getFloatFormat(sizeout);
    if (format == null) {
      return super.evaluateUnary(sizeout, sizein, in1);
    }
    return format.opInt2Float(in1, sizein);
  }
}

/** CPUI_FLOAT_FLOAT2FLOAT behavior */
export class OpBehaviorFloatFloat2Float extends OpBehavior {
  private translate: any;

  constructor(trans: any) {
    super(OpCode.CPUI_FLOAT_FLOAT2FLOAT, true);
    this.translate = trans;
  }

  evaluateUnary(sizeout: number, sizein: number, in1: bigint): bigint {
    const formatout = this.translate?.getFloatFormat(sizeout);
    if (formatout == null) {
      return super.evaluateUnary(sizeout, sizein, in1);
    }
    const formatin = this.translate?.getFloatFormat(sizein);
    if (formatin == null) {
      return super.evaluateUnary(sizeout, sizein, in1);
    }
    return formatin.opFloat2Float(in1, formatout);
  }
}

/** CPUI_FLOAT_TRUNC behavior */
export class OpBehaviorFloatTrunc extends OpBehavior {
  private translate: any;

  constructor(trans: any) {
    super(OpCode.CPUI_FLOAT_TRUNC, true);
    this.translate = trans;
  }

  evaluateUnary(sizeout: number, sizein: number, in1: bigint): bigint {
    const format = this.translate?.getFloatFormat(sizein);
    if (format == null) {
      return super.evaluateUnary(sizeout, sizein, in1);
    }
    return format.opTrunc(in1, sizeout);
  }
}

/** CPUI_FLOAT_CEIL behavior */
export class OpBehaviorFloatCeil extends OpBehavior {
  private translate: any;

  constructor(trans: any) {
    super(OpCode.CPUI_FLOAT_CEIL, true);
    this.translate = trans;
  }

  evaluateUnary(sizeout: number, sizein: number, in1: bigint): bigint {
    const format = this.translate?.getFloatFormat(sizein);
    if (format == null) {
      return super.evaluateUnary(sizeout, sizein, in1);
    }
    return format.opCeil(in1);
  }
}

/** CPUI_FLOAT_FLOOR behavior */
export class OpBehaviorFloatFloor extends OpBehavior {
  private translate: any;

  constructor(trans: any) {
    super(OpCode.CPUI_FLOAT_FLOOR, true);
    this.translate = trans;
  }

  evaluateUnary(sizeout: number, sizein: number, in1: bigint): bigint {
    const format = this.translate?.getFloatFormat(sizein);
    if (format == null) {
      return super.evaluateUnary(sizeout, sizein, in1);
    }
    return format.opFloor(in1);
  }
}

/** CPUI_FLOAT_ROUND behavior */
export class OpBehaviorFloatRound extends OpBehavior {
  private translate: any;

  constructor(trans: any) {
    super(OpCode.CPUI_FLOAT_ROUND, true);
    this.translate = trans;
  }

  evaluateUnary(sizeout: number, sizein: number, in1: bigint): bigint {
    const format = this.translate?.getFloatFormat(sizein);
    if (format == null) {
      return super.evaluateUnary(sizeout, sizein, in1);
    }
    return format.opRound(in1);
  }
}

// ---------------------------------------------------------------------------
// Piece / Subpiece / Pointer behaviors
// ---------------------------------------------------------------------------

/** CPUI_PIECE behavior - Concatenate two values */
export class OpBehaviorPiece extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_PIECE, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    return (in1 << BigInt((sizeout - sizein) * 8)) | in2;
  }
}

/** CPUI_SUBPIECE behavior - Truncate / extract a sub-piece */
export class OpBehaviorSubpiece extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_SUBPIECE, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    // sizeof(uintb) == 8 in C++
    if (in2 >= 8n) return 0n;
    return (in1 >> (in2 * 8n)) & calc_mask(sizeout);
  }
}

/** CPUI_PTRADD behavior (ternary: base + index * element_size) */
export class OpBehaviorPtradd extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_PTRADD, false);
  }

  evaluateTernary(sizeout: number, sizein: number, in1: bigint, in2: bigint, in3: bigint): bigint {
    return (in1 + in2 * in3) & calc_mask(sizeout);
  }
}

/** CPUI_PTRSUB behavior */
export class OpBehaviorPtrsub extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_PTRSUB, false);
  }

  evaluateBinary(sizeout: number, sizein: number, in1: bigint, in2: bigint): bigint {
    return (in1 + in2) & calc_mask(sizeout);
  }
}

// ---------------------------------------------------------------------------
// Bit-counting behaviors
// ---------------------------------------------------------------------------

/** CPUI_POPCOUNT behavior - count the number of 1-bits */
export class OpBehaviorPopcount extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_POPCOUNT, true);
  }

  evaluateUnary(sizeout: number, sizein: number, in1: bigint): bigint {
    return BigInt(popcount(in1));
  }
}

/** CPUI_LZCOUNT behavior - count leading zeros */
export class OpBehaviorLzcount extends OpBehavior {
  constructor() {
    super(OpCode.CPUI_LZCOUNT, true);
  }

  evaluateUnary(sizeout: number, sizein: number, in1: bigint): bigint {
    // In C++: count_leading_zeros(in1) - 8*(sizeof(uintb) - sizein)
    // sizeof(uintb) == 8
    return BigInt(count_leading_zeros(in1) - 8 * (8 - sizein));
  }
}
