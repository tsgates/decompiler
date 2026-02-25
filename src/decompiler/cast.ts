/**
 * @file cast.ts
 * @description API and specific strategies for applying type casts.
 * Translated from Ghidra's cast.hh / cast.cc
 */

import type { int4, uint4, uintb } from '../core/types.js';
import { OpCode } from '../core/opcodes.js';
import { Datatype, type_metatype } from './type.js';
import { signbit_negative, uintb_negate, mostsigbit_set } from '../core/address.js';

// ---------------------------------------------------------------------------
// Forward type declarations for types not yet available
// ---------------------------------------------------------------------------

type PcodeOp = any;
type Varnode = any;
type TypeOp = any;
type TypeFactory = any;
type TypePointer = any;
type TypeCode = any;
type AddrSpace = any;
type FuncProto = any;
type Architecture = any;

// ---------------------------------------------------------------------------
// CastStrategy -- abstract base class
// ---------------------------------------------------------------------------

/**
 * A strategy for applying type casts.
 *
 * A *cast* operation in C or other languages masks a variety of possible
 * low-level conversions such as extensions, truncations, integer to
 * floating-point, etc.  On top of this, languages allow many of these types
 * of operations to be *implied* in the source code, with no explicit token
 * representing the conversion.
 *
 * This class is the API for making four kinds of decisions:
 *   - Do we need a cast operator for a given assignment
 *   - Does the given conversion operation need to be represented as a cast
 *   - Does the given extension or comparison match with the expected level of integer promotion
 *   - What data-type is produced by a particular integer arithmetic operation
 */
export abstract class CastStrategy {

  // ---- Types of integer promotion ----

  /** There is no integer promotion */
  static readonly NO_PROMOTION: int4 = -1;
  /** The type of integer promotion cannot be determined */
  static readonly UNKNOWN_PROMOTION: int4 = 0;
  /** The value is promoted using unsigned extension */
  static readonly UNSIGNED_EXTENSION: int4 = 1;
  /** The value is promoted using signed extension */
  static readonly SIGNED_EXTENSION: int4 = 2;
  /** The value is promoted using either signed or unsigned extension */
  static readonly EITHER_EXTENSION: int4 = 3;

  protected tlst: TypeFactory | null = null;
  protected promoteSize: int4 = 0;

  constructor() {}

  /** Establish the data-type factory */
  setTypeFactory(t: TypeFactory): void {
    this.tlst = t;
    this.promoteSize = this.tlst.getSizeOfInt();
  }

  // ---- Pure virtual methods (abstract) ----

  /**
   * Decide on integer promotion by examining just local properties of the
   * given Varnode.
   * @returns an IntPromotionCode (excluding NO_PROMOTION)
   */
  abstract localExtensionType(vn: Varnode, op: PcodeOp): int4;

  /**
   * Calculate the integer promotion code of a given Varnode.
   * Recursively examine the expression defining the Varnode as necessary.
   */
  abstract intPromotionType(vn: Varnode): int4;

  /**
   * Check if integer promotion forces a cast for the given comparison op
   * and slot.
   */
  abstract checkIntPromotionForCompare(op: PcodeOp, slot: int4): boolean;

  /**
   * Check if integer promotion forces a cast for the input to the given
   * extension (INT_ZEXT or INT_SEXT).
   */
  abstract checkIntPromotionForExtension(op: PcodeOp): boolean;

  /**
   * Is the given ZEXT/SEXT cast implied by the expression it is in?
   */
  abstract isExtensionCastImplied(op: PcodeOp, readOp: PcodeOp | null): boolean;

  /**
   * Does there need to be a visible cast between the given data-types?
   * Returns null if no cast is required, otherwise returns the data-type to
   * cast to (usually the expected data-type).
   */
  abstract castStandard(reqtype: Datatype, curtype: Datatype, care_uint_int: boolean, care_ptr_uint: boolean): Datatype | null;

  /**
   * What is the output data-type produced by the given integer arithmetic
   * operation?
   */
  abstract arithmeticOutputStandard(op: PcodeOp): Datatype;

  /**
   * Is truncating an input data-type, producing an output data-type,
   * considered a cast?
   */
  abstract isSubpieceCast(outtype: Datatype, intype: Datatype, offset: uint4): boolean;

  /**
   * Is the given data-type truncation considered a cast, given endianness
   * concerns?
   */
  abstract isSubpieceCastEndian(outtype: Datatype, intype: Datatype, offset: uint4, isbigend: boolean): boolean;

  /**
   * Is sign-extending an input data-type, producing an output data-type,
   * considered a cast?
   */
  abstract isSextCast(outtype: Datatype, intype: Datatype): boolean;

  /**
   * Is zero-extending an input data-type, producing an output data-type,
   * considered a cast?
   */
  abstract isZextCast(outtype: Datatype, intype: Datatype): boolean;

  // ---- Concrete methods ----

  /**
   * Check if a constant input should be explicitly labeled as an *unsigned*
   * token.  If this is true, the input Varnode is marked for printing as
   * explicitly unsigned.
   */
  markExplicitUnsigned(op: PcodeOp, slot: int4): boolean {
    const opcode: TypeOp = op.getOpcode();
    if (!opcode.inheritsSign()) return false;
    const inheritsFirstParamOnly: boolean = opcode.inheritsSignFirstParamOnly();
    if ((slot === 1) && inheritsFirstParamOnly) return false;
    const vn: Varnode = op.getIn(slot);
    if (!vn.isConstant()) return false;
    const dt: Datatype = vn.getHighTypeReadFacing(op);
    let meta: type_metatype = dt.getMetatype();
    if (meta !== type_metatype.TYPE_UINT && meta !== type_metatype.TYPE_UNKNOWN &&
        meta !== type_metatype.TYPE_PARTIALSTRUCT && meta !== type_metatype.TYPE_PARTIALUNION)
      return false;
    if (dt.isCharPrint()) return false;
    if (dt.isEnumType()) return false;
    if ((op.numInput() === 2) && !inheritsFirstParamOnly) {
      const firstvn: Varnode = op.getIn(1 - slot);
      meta = firstvn.getHighTypeReadFacing(op).getMetatype();
      if (meta === type_metatype.TYPE_UINT || meta === type_metatype.TYPE_UNKNOWN ||
          meta === type_metatype.TYPE_PARTIALSTRUCT || meta === type_metatype.TYPE_PARTIALUNION)
        return false;  // Other side of the operation will force the unsigned
    }
    // Check if type is going to get forced anyway
    const outvn: Varnode | null = op.getOut();
    if (outvn !== null) {
      if (outvn.isExplicit()) return false;
      const lone: PcodeOp | null = outvn.loneDescend();
      if (lone !== null) {
        if (!lone.getOpcode().inheritsSign()) return false;
      }
    }

    vn.setUnsignedPrint();
    return true;
  }

  /**
   * Check if a constant input should be explicitly labeled as a *long*
   * integer token.  If this is true, the input Varnode is marked for
   * printing as explicitly a larger integer (typically long).
   */
  markExplicitLongSize(op: PcodeOp, slot: int4): boolean {
    if (!op.getOpcode().isShiftOp()) return false;
    if (slot !== 0) return false;
    const vn: Varnode = op.getIn(slot);
    if (!vn.isConstant()) return false;
    if (vn.getSize() <= this.promoteSize) return false;
    const dt: Datatype = vn.getHigh().getType();
    const meta: type_metatype = dt.getMetatype();
    if (meta !== type_metatype.TYPE_UINT && meta !== type_metatype.TYPE_INT &&
        meta !== type_metatype.TYPE_UNKNOWN && meta !== type_metatype.TYPE_PARTIALSTRUCT &&
        meta !== type_metatype.TYPE_PARTIALUNION)
      return false;
    let off: uintb = vn.getOffset();
    if (meta === type_metatype.TYPE_INT && signbit_negative(off, vn.getSize())) {
      off = uintb_negate(off, vn.getSize());
      const bit: int4 = mostsigbit_set(off);
      if (bit >= this.promoteSize * 8 - 1) return false;
    }
    else {
      const bit: int4 = mostsigbit_set(off);
      if (bit >= this.promoteSize * 8) return false; // If integer is big enough, it naturally becomes a long
    }

    vn.setLongPrint();
    return true;
  }

  /**
   * For the given PcodeOp, does it matter if a constant operand is presented
   * as a character or integer?
   */
  caresAboutCharRepresentation(_vn: Varnode, _op: PcodeOp | null): boolean {
    return false;
  }
}

// ---------------------------------------------------------------------------
// CastStrategyC -- C language casting rules
// ---------------------------------------------------------------------------

/**
 * Casting strategies that are specific to the C language.
 */
export class CastStrategyC extends CastStrategy {

  localExtensionType(vn: Varnode, op: PcodeOp): int4 {
    const meta: type_metatype = vn.getHighTypeReadFacing(op).getMetatype();
    let natural: int4;
    if (meta === type_metatype.TYPE_UINT || meta === type_metatype.TYPE_BOOL ||
        meta === type_metatype.TYPE_UNKNOWN || meta === type_metatype.TYPE_PARTIALSTRUCT ||
        meta === type_metatype.TYPE_PARTIALUNION)
      natural = CastStrategy.UNSIGNED_EXTENSION;
    else if (meta === type_metatype.TYPE_INT)
      natural = CastStrategy.SIGNED_EXTENSION;
    else
      return CastStrategy.UNKNOWN_PROMOTION;

    if (vn.isConstant()) {
      if (!signbit_negative(vn.getOffset(), vn.getSize()))  // If the high-bit is zero
        return CastStrategy.EITHER_EXTENSION;               // Can be viewed as either extension
      return natural;
    }
    if (vn.isExplicit())
      return natural;
    if (!vn.isWritten())
      return CastStrategy.UNKNOWN_PROMOTION;
    const defOp: PcodeOp = vn.getDef();
    if (defOp.isBoolOutput())
      return CastStrategy.EITHER_EXTENSION;
    const opc: OpCode = defOp.code();
    if ((opc === OpCode.CPUI_CAST) || (opc === OpCode.CPUI_LOAD) || defOp.isCall())
      return natural;
    if (opc === OpCode.CPUI_INT_AND) {  // This is kind of recursing
      const tmpvn: Varnode = defOp.getIn(1);
      if (tmpvn.isConstant()) {
        if (!signbit_negative(tmpvn.getOffset(), tmpvn.getSize()))
          return CastStrategy.EITHER_EXTENSION;
        return natural;
      }
    }
    return CastStrategy.UNKNOWN_PROMOTION;
  }

  intPromotionType(vn: Varnode): int4 {
    let val: int4;
    if (vn.getSize() >= this.promoteSize)
      return CastStrategy.NO_PROMOTION;
    if (vn.isConstant())
      return this.localExtensionType(vn, vn.loneDescend());
    if (vn.isExplicit())
      return CastStrategy.NO_PROMOTION;
    if (!vn.isWritten()) return CastStrategy.UNKNOWN_PROMOTION;
    const op: PcodeOp = vn.getDef();
    let othervn: Varnode;
    switch (op.code() as OpCode) {
      case OpCode.CPUI_INT_AND:
        othervn = op.getIn(1);
        if ((this.localExtensionType(othervn, op) & CastStrategy.UNSIGNED_EXTENSION) !== 0)
          return CastStrategy.UNSIGNED_EXTENSION;
        othervn = op.getIn(0);
        if ((this.localExtensionType(othervn, op) & CastStrategy.UNSIGNED_EXTENSION) !== 0)
          return CastStrategy.UNSIGNED_EXTENSION; // If either side has zero extension, result has zero extension
        break;
      case OpCode.CPUI_INT_RIGHT:
        othervn = op.getIn(0);
        val = this.localExtensionType(othervn, op);
        if ((val & CastStrategy.UNSIGNED_EXTENSION) !== 0) // If the input provably zero extends
          return val;                                       // then the result is a zero extension (plus possibly a sign extension)
        break;
      case OpCode.CPUI_INT_SRIGHT:
        othervn = op.getIn(0);
        val = this.localExtensionType(othervn, op);
        if ((val & CastStrategy.SIGNED_EXTENSION) !== 0)   // If input can be construed as a sign-extension
          return val;                                       // then the result is a sign extension (plus possibly a zero extension)
        break;
      case OpCode.CPUI_INT_XOR:
      case OpCode.CPUI_INT_OR:
      case OpCode.CPUI_INT_DIV:
      case OpCode.CPUI_INT_REM:
        othervn = op.getIn(0);
        if ((this.localExtensionType(othervn, op) & CastStrategy.UNSIGNED_EXTENSION) === 0)
          return CastStrategy.UNKNOWN_PROMOTION;
        othervn = op.getIn(1);
        if ((this.localExtensionType(othervn, op) & CastStrategy.UNSIGNED_EXTENSION) === 0)
          return CastStrategy.UNKNOWN_PROMOTION;
        return CastStrategy.UNSIGNED_EXTENSION; // If both sides have zero extension, result has zero extension
      case OpCode.CPUI_INT_SDIV:
      case OpCode.CPUI_INT_SREM:
        othervn = op.getIn(0);
        if ((this.localExtensionType(othervn, op) & CastStrategy.SIGNED_EXTENSION) === 0)
          return CastStrategy.UNKNOWN_PROMOTION;
        othervn = op.getIn(1);
        if ((this.localExtensionType(othervn, op) & CastStrategy.SIGNED_EXTENSION) === 0)
          return CastStrategy.UNKNOWN_PROMOTION;
        return CastStrategy.SIGNED_EXTENSION; // If both sides have sign extension, result has sign extension
      case OpCode.CPUI_INT_NEGATE:
      case OpCode.CPUI_INT_2COMP:
        othervn = op.getIn(0);
        if ((this.localExtensionType(othervn, op) & CastStrategy.SIGNED_EXTENSION) !== 0)
          return CastStrategy.SIGNED_EXTENSION;
        break;
      case OpCode.CPUI_INT_ADD:
      case OpCode.CPUI_INT_SUB:
      case OpCode.CPUI_INT_LEFT:
      case OpCode.CPUI_INT_MULT:
        break;
      default:
        return CastStrategy.NO_PROMOTION; // No integer promotion at all
    }
    return CastStrategy.UNKNOWN_PROMOTION;
  }

  checkIntPromotionForCompare(op: PcodeOp, slot: int4): boolean {
    const vn: Varnode = op.getIn(slot);
    const exttype1: int4 = this.intPromotionType(vn);
    if (exttype1 === CastStrategy.NO_PROMOTION) return false;
    if (exttype1 === CastStrategy.UNKNOWN_PROMOTION) return true; // If there is promotion and we don't know type, we need a cast

    const exttype2: int4 = this.intPromotionType(op.getIn(1 - slot));
    if ((exttype1 & exttype2) !== 0) // If both sides share a common extension, then these bits aren't determining factor
      return false;
    if (exttype2 === CastStrategy.NO_PROMOTION) {
      // other side would not have integer promotion, but our side is forcing it
      // but both sides get extended in the same way
      return false;
    }
    return true;
  }

  checkIntPromotionForExtension(op: PcodeOp): boolean {
    const vn: Varnode = op.getIn(0);
    const exttype: int4 = this.intPromotionType(vn);
    if (exttype === CastStrategy.NO_PROMOTION) return false;
    if (exttype === CastStrategy.UNKNOWN_PROMOTION) return true; // If there is an extension and we don't know type, we need a cast

    // Test if the promotion extension matches the explicit extension
    if (((exttype & CastStrategy.UNSIGNED_EXTENSION) !== 0) && (op.code() === OpCode.CPUI_INT_ZEXT)) return false;
    if (((exttype & CastStrategy.SIGNED_EXTENSION) !== 0) && (op.code() === OpCode.CPUI_INT_SEXT)) return false;
    return true; // Otherwise we need a cast before we extend
  }

  isExtensionCastImplied(op: PcodeOp, readOp: PcodeOp | null): boolean {
    const outVn: Varnode = op.getOut();
    if (outVn.isExplicit()) {
      // empty -- matches the C++ code
    }
    else {
      if (readOp === null)
        return false;
      const metatype: type_metatype = outVn.getHighTypeReadFacing(readOp).getMetatype();
      let otherVn: Varnode;
      let slot: int4;
      switch (readOp.code() as OpCode) {
        case OpCode.CPUI_PTRADD:
          break;
        case OpCode.CPUI_INT_LEFT:
        case OpCode.CPUI_INT_RIGHT:
        case OpCode.CPUI_INT_SRIGHT:
        case OpCode.CPUI_INT_ADD:
        case OpCode.CPUI_INT_SUB:
        case OpCode.CPUI_INT_MULT:
        case OpCode.CPUI_INT_DIV:
        case OpCode.CPUI_INT_AND:
        case OpCode.CPUI_INT_OR:
        case OpCode.CPUI_INT_XOR:
        case OpCode.CPUI_INT_EQUAL:
        case OpCode.CPUI_INT_NOTEQUAL:
        case OpCode.CPUI_INT_LESS:
        case OpCode.CPUI_INT_LESSEQUAL:
        case OpCode.CPUI_INT_SLESS:
        case OpCode.CPUI_INT_SLESSEQUAL:
          slot = readOp.getSlot(outVn);
          otherVn = readOp.getIn(1 - slot);
          // Check if the expression involves an explicit variable of the right integer type
          if (otherVn.isConstant()) {
            // Integer tokens do not naturally indicate their size, and
            // integers that are bigger than the promotion size are NOT naturally extended.
            if (otherVn.getSize() > this.promoteSize) // So if the integer is bigger than the promotion size
              return false;                            // The extension cast on the other side must be explicit
          }
          else if (!otherVn.isExplicit())
            return false;
          if (otherVn.getHighTypeReadFacing(readOp).getMetatype() !== metatype)
            return false;
          break;
        default:
          return false;
      }
      return true; // Everything is integer promotion
    }
    return false;
  }

  castStandard(reqtype: Datatype, curtype: Datatype, care_uint_int: boolean, care_ptr_uint: boolean): Datatype | null {
    // Generic casting rules that apply for most ops
    if (curtype === reqtype) return null; // Types are equal, no cast required
    if (curtype.getMetatype() === type_metatype.TYPE_VOID)
      return reqtype; // If coming from "void" (as a dereferenced pointer) we need a cast
    let reqbase: Datatype = reqtype;
    let curbase: Datatype = curtype;
    let isptr = false;
    while ((reqbase.getMetatype() === type_metatype.TYPE_PTR) && (curbase.getMetatype() === type_metatype.TYPE_PTR)) {
      const reqptr: TypePointer = reqbase;
      const curptr: TypePointer = curbase;
      if (reqptr.getWordSize() !== curptr.getWordSize())
        return reqtype;
      if (reqptr.getSpace() !== curptr.getSpace()) {
        if (reqptr.getSpace() !== null && curptr.getSpace() !== null)
          return reqtype; // Pointers to different address spaces. We must cast
        // If one pointer doesn't have an address, assume a conversion to/from sub-type and don't need a cast
      }
      reqbase = reqptr.getPtrTo();
      curbase = curptr.getPtrTo();
      care_uint_int = true;
      isptr = true;
    }
    while (reqbase.getTypedef() !== null)
      reqbase = reqbase.getTypedef()!;
    while (curbase.getTypedef() !== null)
      curbase = curbase.getTypedef()!;
    if (curbase === reqbase) return null; // Different typedefs could point to the same type
    if (reqbase.getMetatype() === type_metatype.TYPE_VOID || curbase.getMetatype() === type_metatype.TYPE_VOID) {
      return null; // Don't cast to or from a void pointer
    }
    if (reqbase.getSize() !== curbase.getSize()) {
      if (reqbase.isVariableLength() && isptr && reqbase.hasSameVariableBase(curbase)) {
        return null; // Don't need a cast
      }
      return reqtype; // Otherwise, always cast change in size
    }
    switch (reqbase.getMetatype() as type_metatype) {
      case type_metatype.TYPE_UNKNOWN:
      case type_metatype.TYPE_PARTIALSTRUCT:  // As they are ultimately stripped, treat partials as undefined
      case type_metatype.TYPE_PARTIALUNION:
        return null;
      case type_metatype.TYPE_UINT: {
        if (!care_uint_int) {
          const meta: type_metatype = curbase.getMetatype();
          // Note: meta can be TYPE_UINT if curbase is typedef/enumerated
          if (meta === type_metatype.TYPE_UNKNOWN || meta === type_metatype.TYPE_INT ||
              meta === type_metatype.TYPE_UINT || meta === type_metatype.TYPE_BOOL ||
              meta === type_metatype.TYPE_PARTIALSTRUCT || meta === type_metatype.TYPE_PARTIALUNION)
            return null;
        }
        else {
          const meta: type_metatype = curbase.getMetatype();
          if ((meta === type_metatype.TYPE_UINT) || (meta === type_metatype.TYPE_BOOL)) // Can be TYPE_UINT for typedef/enumerated
            return null;
          if (isptr && (meta === type_metatype.TYPE_UNKNOWN || meta === type_metatype.TYPE_PARTIALSTRUCT ||
              meta === type_metatype.TYPE_PARTIALUNION))
            return null; // Don't cast pointers to unknown
        }
        if ((!care_ptr_uint) && (curbase.getMetatype() === type_metatype.TYPE_PTR))
          return null;
        break;
      }
      case type_metatype.TYPE_INT: {
        if (!care_uint_int) {
          const meta: type_metatype = curbase.getMetatype();
          // Note: meta can be TYPE_INT if curbase is an enumerated type
          if (meta === type_metatype.TYPE_UNKNOWN || meta === type_metatype.TYPE_INT ||
              meta === type_metatype.TYPE_UINT || meta === type_metatype.TYPE_BOOL ||
              meta === type_metatype.TYPE_PARTIALSTRUCT || meta === type_metatype.TYPE_PARTIALUNION)
            return null;
        }
        else {
          const meta: type_metatype = curbase.getMetatype();
          if ((meta === type_metatype.TYPE_INT) || (meta === type_metatype.TYPE_BOOL))
            return null; // Can be TYPE_INT for typedef/enumerated/char
          if (isptr && (meta === type_metatype.TYPE_UNKNOWN || meta === type_metatype.TYPE_PARTIALSTRUCT ||
              meta === type_metatype.TYPE_PARTIALUNION))
            return null; // Don't cast pointers to unknown
        }
        break;
      }
      case type_metatype.TYPE_CODE: {
        if (curbase.getMetatype() === type_metatype.TYPE_CODE) {
          // Don't cast between function pointer and generic code pointer
          if ((reqbase as TypeCode).getPrototype() === null)
            return null;
          if ((curbase as TypeCode).getPrototype() === null)
            return null;
        }
        break;
      }
      default:
        break;
    }

    return reqtype;
  }

  arithmeticOutputStandard(op: PcodeOp): Datatype {
    let res1: Datatype = op.getIn(0).getHighTypeReadFacing(op);
    if (res1.getMetatype() === type_metatype.TYPE_BOOL) // Treat boolean as if it is cast to an integer
      res1 = this.tlst!.getBase(res1.getSize(), type_metatype.TYPE_INT);
    let res2: Datatype;

    for (let i: int4 = 1; i < op.numInput(); ++i) {
      res2 = op.getIn(i).getHighTypeReadFacing(op);
      if (res2.getMetatype() === type_metatype.TYPE_BOOL) continue;
      if (0 > res2.typeOrder(res1))
        res1 = res2;
    }
    return res1;
  }

  isSubpieceCast(outtype: Datatype, intype: Datatype, offset: uint4): boolean {
    if (offset !== 0) return false;
    const inmeta: type_metatype = intype.getMetatype();
    if (inmeta !== type_metatype.TYPE_INT && inmeta !== type_metatype.TYPE_UINT &&
        inmeta !== type_metatype.TYPE_UNKNOWN && inmeta !== type_metatype.TYPE_PTR &&
        inmeta !== type_metatype.TYPE_PARTIALSTRUCT && inmeta !== type_metatype.TYPE_PARTIALUNION)
      return false;
    const outmeta: type_metatype = outtype.getMetatype();
    if (outmeta !== type_metatype.TYPE_INT && outmeta !== type_metatype.TYPE_UINT &&
        outmeta !== type_metatype.TYPE_UNKNOWN && outmeta !== type_metatype.TYPE_PTR &&
        outmeta !== type_metatype.TYPE_FLOAT)
      return false;
    if (inmeta === type_metatype.TYPE_PTR) {
      if (outmeta === type_metatype.TYPE_PTR) {
        if (outtype.getSize() < intype.getSize())
          return true; // Cast from far pointer to near pointer
      }
      if (outmeta !== type_metatype.TYPE_INT && outmeta !== type_metatype.TYPE_UINT)
        return false; // other casts don't make sense for pointers
    }
    return true;
  }

  isSubpieceCastEndian(outtype: Datatype, intype: Datatype, offset: uint4, isbigend: boolean): boolean {
    let tmpoff: uint4 = offset;
    if (isbigend)
      tmpoff = intype.getSize() - 1 - offset;
    return this.isSubpieceCast(outtype, intype, tmpoff);
  }

  isSextCast(outtype: Datatype, intype: Datatype): boolean {
    const metaout: type_metatype = outtype.getMetatype();
    if (metaout !== type_metatype.TYPE_UINT && metaout !== type_metatype.TYPE_INT)
      return false;
    const metain: type_metatype = intype.getMetatype();
    // Casting to larger storage always extends based on signedness of the input data-type
    // So the input must be SIGNED in order to treat SEXT as a cast
    if ((metain !== type_metatype.TYPE_INT) && (metain !== type_metatype.TYPE_BOOL))
      return false;
    return true;
  }

  isZextCast(outtype: Datatype, intype: Datatype): boolean {
    const metaout: type_metatype = outtype.getMetatype();
    if (metaout !== type_metatype.TYPE_UINT && metaout !== type_metatype.TYPE_INT)
      return false;
    const metain: type_metatype = intype.getMetatype();
    // Casting to larger storage always extends based on signedness of the input data-type
    // So the input must be UNSIGNED in order to treat ZEXT as a cast
    if ((metain !== type_metatype.TYPE_UINT) && (metain !== type_metatype.TYPE_BOOL))
      return false;
    return true;
  }
}

// ---------------------------------------------------------------------------
// CastStrategyJava -- Java language casting rules
// ---------------------------------------------------------------------------

/**
 * Casting strategies that are specific to the Java language.
 *
 * This is nearly identical to the strategy for C, but there is some change
 * to account for the way object references are encoded as pointer data-types
 * within the decompiler's data-type system.
 */
export class CastStrategyJava extends CastStrategyC {

  castStandard(reqtype: Datatype, curtype: Datatype, care_uint_int: boolean, _care_ptr_uint: boolean): Datatype | null {
    if (curtype === reqtype) return null; // Types are equal, no cast required
    const reqbase: Datatype = reqtype;
    const curbase: Datatype = curtype;
    if ((reqbase.getMetatype() === type_metatype.TYPE_PTR) || (curbase.getMetatype() === type_metatype.TYPE_PTR))
      return null; // There must be explicit cast op between objects, so assume no cast necessary

    if ((reqbase.getMetatype() === type_metatype.TYPE_VOID) || (curtype.getMetatype() === type_metatype.TYPE_VOID))
      return null; // Don't cast from or to VOID
    if (reqbase.getSize() !== curbase.getSize()) return reqtype; // Always cast change in size
    switch (reqbase.getMetatype() as type_metatype) {
      case type_metatype.TYPE_UNKNOWN:
      case type_metatype.TYPE_PARTIALSTRUCT:  // As they are ultimately stripped, treat partials as undefined
      case type_metatype.TYPE_PARTIALUNION:
        return null;
      case type_metatype.TYPE_UINT: {
        if (!care_uint_int) {
          const meta: type_metatype = curbase.getMetatype();
          // Note: meta can be TYPE_UINT if curbase is typedef/enumerated
          if (meta === type_metatype.TYPE_UNKNOWN || meta === type_metatype.TYPE_INT ||
              meta === type_metatype.TYPE_UINT || meta === type_metatype.TYPE_BOOL ||
              meta === type_metatype.TYPE_PARTIALSTRUCT || meta === type_metatype.TYPE_PARTIALUNION)
            return null;
        }
        else {
          const meta: type_metatype = curbase.getMetatype();
          if ((meta === type_metatype.TYPE_UINT) || (meta === type_metatype.TYPE_BOOL)) // Can be TYPE_UINT for typedef/enumerated
            return null;
        }
        break;
      }
      case type_metatype.TYPE_INT: {
        if (!care_uint_int) {
          const meta: type_metatype = curbase.getMetatype();
          // Note: meta can be TYPE_INT if curbase is an enumerated type
          if (meta === type_metatype.TYPE_UNKNOWN || meta === type_metatype.TYPE_INT ||
              meta === type_metatype.TYPE_UINT || meta === type_metatype.TYPE_BOOL ||
              meta === type_metatype.TYPE_PARTIALSTRUCT || meta === type_metatype.TYPE_PARTIALUNION)
            return null;
        }
        else {
          const meta: type_metatype = curbase.getMetatype();
          if ((meta === type_metatype.TYPE_INT) || (meta === type_metatype.TYPE_BOOL))
            return null; // Can be TYPE_INT for typedef/enumerated/char
        }
        break;
      }
      case type_metatype.TYPE_CODE: {
        if (curbase.getMetatype() === type_metatype.TYPE_CODE) {
          // Don't cast between function pointer and generic code pointer
          if ((reqbase as TypeCode).getPrototype() === null)
            return null;
          if ((curbase as TypeCode).getPrototype() === null)
            return null;
        }
        break;
      }
      default:
        break;
    }

    return reqtype;
  }

  isZextCast(outtype: Datatype, intype: Datatype): boolean {
    const outmeta: type_metatype = outtype.getMetatype();
    if ((outmeta !== type_metatype.TYPE_INT) && (outmeta !== type_metatype.TYPE_UINT) &&
        (outmeta !== type_metatype.TYPE_BOOL)) return false;
    const inmeta: type_metatype = intype.getMetatype();
    if ((inmeta !== type_metatype.TYPE_INT) && (inmeta !== type_metatype.TYPE_UINT) &&
        (inmeta !== type_metatype.TYPE_BOOL)) return false; // Non-integer types, print functional ZEXT
    if ((intype.getSize() === 2) && (!intype.isCharPrint())) return false; // cast is not zext for short
    if ((intype.getSize() === 1) && (inmeta === type_metatype.TYPE_INT)) return false; // cast is not zext for byte
    if (intype.getSize() >= 4) return false; // cast is not zext for int and long
    return true;
  }
}
