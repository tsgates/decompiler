/**
 * @file semantics.ts
 * @description SLEIGH semantic actions - the p-code constructor templates used to build
 * p-code from SLEIGH specifications.
 *
 * Translated from Ghidra's semantics.hh / semantics.cc.
 *
 * This module defines the template classes that represent p-code constructor trees:
 * ConstTpl, VarnodeTpl, OpTpl, HandleTpl, ConstructTpl, and the abstract PcodeBuilder.
 */

import type { int4, uint4, uintb } from '../core/types.js';
import { OpCode } from '../core/opcodes.js';
import { AddrSpace, spacetype } from '../core/space.js';
import { LowlevelError } from '../core/error.js';
import { UnimplError } from '../core/translate.js';

// Forward declarations for types from not-yet-written SLEIGH files
type ParserWalker = any;
type FixedHandle = any;
type Encoder = any;
type Decoder = any;

// ------------------------------------------------------------------
// Internal opcode remappings for pcode generation
// ------------------------------------------------------------------

/** BUILD pseudo-op: remapped from CPUI_MULTIEQUAL */
export const BUILD: OpCode = OpCode.CPUI_MULTIEQUAL;
/** DELAY_SLOT pseudo-op: remapped from CPUI_INDIRECT */
export const DELAY_SLOT: OpCode = OpCode.CPUI_INDIRECT;
/** CROSSBUILD pseudo-op: remapped from CPUI_PTRSUB */
export const CROSSBUILD: OpCode = OpCode.CPUI_PTRSUB;
/** MACROBUILD pseudo-op: remapped from CPUI_CAST */
export const MACROBUILD: OpCode = OpCode.CPUI_CAST;
/** LABELBUILD pseudo-op: remapped from CPUI_PTRADD */
export const LABELBUILD: OpCode = OpCode.CPUI_PTRADD;

// ------------------------------------------------------------------
// SLA element/attribute IDs (forward-declared stubs)
// ------------------------------------------------------------------

const sla = {
  ELEM_CONST_REAL: 1,
  ELEM_VARNODE_TPL: 2,
  ELEM_CONST_SPACEID: 3,
  ELEM_CONST_HANDLE: 4,
  ELEM_OP_TPL: 5,
  ELEM_NULL: 11,
  ELEM_CONSTRUCT_TPL: 21,
  ELEM_HANDLE_TPL: 30,
  ELEM_CONST_RELATIVE: 31,
  ELEM_CONST_START: 80,
  ELEM_CONST_NEXT: 81,
  ELEM_CONST_NEXT2: 82,
  ELEM_CONST_CURSPACE: 83,
  ELEM_CONST_CURSPACE_SIZE: 84,
  ELEM_CONST_FLOWREF: 85,
  ELEM_CONST_FLOWREF_SIZE: 86,
  ELEM_CONST_FLOWDEST: 87,
  ELEM_CONST_FLOWDEST_SIZE: 88,
  ATTRIB_VAL: 2,
  ATTRIB_S: 5,
  ATTRIB_PLUS: 28,
  ATTRIB_SPACE: 4,
  ATTRIB_CODE: 7,
  ATTRIB_SECTION: 54,
  ATTRIB_DELAY: 42,
  ATTRIB_LABELS: 55,
};

// ==================================================================
// ConstTpl
// ==================================================================

/** Constant template type */
export const enum const_type {
  real = 0,
  handle = 1,
  j_start = 2,
  j_next = 3,
  j_next2 = 4,
  j_curspace = 5,
  j_curspace_size = 6,
  spaceid = 7,
  j_relative = 8,
  j_flowref = 9,
  j_flowref_size = 10,
  j_flowdest = 11,
  j_flowdest_size = 12,
}

/** Which part of a handle to use as constant */
export const enum v_field {
  v_space = 0,
  v_offset = 1,
  v_size = 2,
  v_offset_plus = 3,
}

/**
 * A template for producing constant values during p-code generation.
 *
 * ConstTpl can represent a real constant, a reference to a handle field,
 * a placeholder for instruction addresses, or an address space id.
 */
export class ConstTpl {
  private type: const_type;
  // In C++ these were a union; in TS we keep both fields.
  private spaceid_value: AddrSpace | null;
  private handle_index: number;
  private value_real: bigint;
  private select: v_field;

  // --- Static constants for const_type (for external access) ---
  static readonly real = const_type.real;
  static readonly handle = const_type.handle;
  static readonly j_start = const_type.j_start;
  static readonly j_next = const_type.j_next;
  static readonly j_next2 = const_type.j_next2;
  static readonly j_curspace = const_type.j_curspace;
  static readonly j_curspace_size = const_type.j_curspace_size;
  static readonly spaceid = const_type.spaceid;
  static readonly j_relative = const_type.j_relative;
  static readonly j_flowref = const_type.j_flowref;
  static readonly j_flowref_size = const_type.j_flowref_size;
  static readonly j_flowdest = const_type.j_flowdest;
  static readonly j_flowdest_size = const_type.j_flowdest_size;

  // --- Static constants for v_field (for external access) ---
  static readonly v_space = v_field.v_space;
  static readonly v_offset = v_field.v_offset;
  static readonly v_size = v_field.v_size;
  static readonly v_offset_plus = v_field.v_offset_plus;

  constructor();
  constructor(op2: ConstTpl);
  constructor(tp: const_type, val: bigint);
  constructor(tp: const_type);
  constructor(sid: AddrSpace);
  constructor(tp: const_type, ht: number, vf: v_field);
  constructor(tp: const_type, ht: number, vf: v_field, plus: bigint);
  constructor(
    arg0?: const_type | ConstTpl | AddrSpace,
    arg1?: bigint | number,
    arg2?: v_field,
    arg3?: bigint,
  ) {
    this.type = const_type.real;
    this.spaceid_value = null;
    this.handle_index = 0;
    this.value_real = 0n;
    this.select = v_field.v_space;

    if (arg0 === undefined) {
      // Default constructor: ConstTpl()
      return;
    }

    if (arg0 instanceof ConstTpl) {
      // Copy constructor: ConstTpl(const ConstTpl &op2)
      this.type = arg0.type;
      this.spaceid_value = arg0.spaceid_value;
      this.handle_index = arg0.handle_index;
      this.value_real = arg0.value_real;
      this.select = arg0.select;
      return;
    }

    if (arg0 instanceof AddrSpace) {
      // ConstTpl(AddrSpace *sid)
      this.type = const_type.spaceid;
      this.spaceid_value = arg0;
      return;
    }

    // arg0 is const_type
    const tp = arg0 as const_type;

    if (arg1 === undefined) {
      // ConstTpl(const_type tp) - for relative jump constants and uniques
      this.type = tp;
      return;
    }

    if (arg2 === undefined) {
      // ConstTpl(const_type tp, uintb val) - for real constants
      this.type = tp;
      this.value_real = arg1 as bigint;
      this.handle_index = 0;
      this.select = v_field.v_space;
      return;
    }

    if (arg3 === undefined) {
      // ConstTpl(const_type tp, int4 ht, v_field vf) - for handle constant
      this.type = const_type.handle;
      this.handle_index = arg1 as number;
      this.select = arg2;
      this.value_real = 0n;
      return;
    }

    // ConstTpl(const_type tp, int4 ht, v_field vf, uintb plus)
    this.type = const_type.handle;
    this.handle_index = arg1 as number;
    this.select = arg2;
    this.value_real = arg3;
  }

  /** Copy all fields from another ConstTpl */
  copyFrom(op2: ConstTpl): void {
    this.type = op2.type;
    this.spaceid_value = op2.spaceid_value;
    this.handle_index = op2.handle_index;
    this.value_real = op2.value_real;
    this.select = op2.select;
  }

  isConstSpace(): boolean {
    if (this.type === const_type.spaceid)
      return this.spaceid_value!.getType() === spacetype.IPTR_CONSTANT;
    return false;
  }

  isUniqueSpace(): boolean {
    if (this.type === const_type.spaceid)
      return this.spaceid_value!.getType() === spacetype.IPTR_INTERNAL;
    return false;
  }

  equals(op2: ConstTpl): boolean {
    if (this.type !== op2.type) return false;
    switch (this.type) {
      case const_type.real:
        return this.value_real === op2.value_real;
      case const_type.handle:
        if (this.handle_index !== op2.handle_index) return false;
        if (this.select !== op2.select) return false;
        break;
      case const_type.spaceid:
        return this.spaceid_value === op2.spaceid_value;
      default:
        break;
    }
    return true;
  }

  lessThan(op2: ConstTpl): boolean {
    if (this.type !== op2.type) return this.type < op2.type;
    switch (this.type) {
      case const_type.real:
        return this.value_real < op2.value_real;
      case const_type.handle:
        if (this.handle_index !== op2.handle_index)
          return this.handle_index < op2.handle_index;
        if (this.select !== op2.select) return this.select < op2.select;
        break;
      case const_type.spaceid: {
        // Compare by identity - use index as proxy
        const thisIdx = this.spaceid_value ? this.spaceid_value.getIndex() : -1;
        const op2Idx = op2.spaceid_value ? op2.spaceid_value.getIndex() : -1;
        return thisIdx < op2Idx;
      }
      default:
        break;
    }
    return false;
  }

  getReal(): bigint {
    return this.value_real;
  }

  getSpace(): AddrSpace | null {
    return this.spaceid_value;
  }

  getHandleIndex(): number {
    return this.handle_index;
  }

  getType(): const_type {
    return this.type;
  }

  getSelect(): v_field {
    return this.select;
  }

  /**
   * Get the value of the ConstTpl in context.
   * If the property is dynamic this returns the property of the temporary storage.
   */
  fix(walker: ParserWalker): bigint {
    switch (this.type) {
      case const_type.j_start:
        return (walker as any).getAddr().getOffset();
      case const_type.j_next:
        return (walker as any).getNaddr().getOffset();
      case const_type.j_next2:
        return (walker as any).getN2addr().getOffset();
      case const_type.j_flowref:
        return (walker as any).getRefAddr().getOffset();
      case const_type.j_flowref_size:
        return BigInt((walker as any).getRefAddr().getAddrSize());
      case const_type.j_flowdest:
        return (walker as any).getDestAddr().getOffset();
      case const_type.j_flowdest_size:
        return BigInt((walker as any).getDestAddr().getAddrSize());
      case const_type.j_curspace_size:
        return BigInt((walker as any).getCurSpace().getAddrSize());
      case const_type.j_curspace:
        // In C++ this casts the space pointer to uintb; we return the index as proxy
        return BigInt((walker as any).getCurSpace().getIndex());
      case const_type.handle: {
        const hand: FixedHandle = (walker as any).getFixedHandle(this.handle_index);
        switch (this.select) {
          case v_field.v_space:
            if (hand.offset_space == null)
              return BigInt(hand.space.getIndex());
            return BigInt(hand.temp_space.getIndex());
          case v_field.v_offset:
            if (hand.offset_space == null)
              return hand.offset_offset;
            return hand.temp_offset;
          case v_field.v_size:
            return BigInt(hand.size);
          case v_field.v_offset_plus: {
            if (hand.space !== (walker as any).getConstSpace()) {
              // Not a constant - adjust offset by truncation amount
              if (hand.offset_space == null)
                return hand.offset_offset + (this.value_real & 0xffffn);
              return hand.temp_offset + (this.value_real & 0xffffn);
            } else {
              // Constant - return a shifted value
              let val: bigint;
              if (hand.offset_space == null)
                val = hand.offset_offset;
              else
                val = hand.temp_offset;
              val >>= 8n * (this.value_real >> 16n);
              return val;
            }
          }
        }
        break;
      }
      case const_type.j_relative:
      case const_type.real:
        return this.value_real;
      case const_type.spaceid:
        return BigInt(this.spaceid_value!.getIndex());
    }
    return 0n; // Should never reach here
  }

  /**
   * Get the value of the ConstTpl in context when we know it is a space.
   */
  fixSpace(walker: ParserWalker): AddrSpace {
    switch (this.type) {
      case const_type.j_curspace:
        return (walker as any).getCurSpace();
      case const_type.handle: {
        const hand: FixedHandle = (walker as any).getFixedHandle(this.handle_index);
        switch (this.select) {
          case v_field.v_space:
            if (hand.offset_space == null)
              return hand.space;
            return hand.temp_space;
          default:
            break;
        }
        break;
      }
      case const_type.spaceid:
        return this.spaceid_value!;
      case const_type.j_flowref:
        return (walker as any).getRefAddr().getSpace();
      default:
        break;
    }
    throw new LowlevelError('ConstTpl is not a spaceid as expected');
  }

  /**
   * Fill in the space portion of a FixedHandle, based on this ConstTpl.
   */
  fillinSpace(hand: FixedHandle, walker: ParserWalker): void {
    switch (this.type) {
      case const_type.j_curspace:
        hand.space = (walker as any).getCurSpace();
        return;
      case const_type.handle: {
        const otherhand: FixedHandle = (walker as any).getFixedHandle(this.handle_index);
        switch (this.select) {
          case v_field.v_space:
            hand.space = otherhand.space;
            return;
          default:
            break;
        }
        break;
      }
      case const_type.spaceid:
        hand.space = this.spaceid_value;
        return;
      default:
        break;
    }
    throw new LowlevelError('ConstTpl is not a spaceid as expected');
  }

  /**
   * Fill in the offset portion of a FixedHandle, based on this ConstTpl.
   * If the offset value is dynamic, indicate this in the handle.
   * We assume hand.space is already filled in.
   */
  fillinOffset(hand: FixedHandle, walker: ParserWalker): void {
    if (this.type === const_type.handle) {
      const otherhand: FixedHandle = (walker as any).getFixedHandle(this.handle_index);
      hand.offset_space = otherhand.offset_space;
      hand.offset_offset = otherhand.offset_offset;
      hand.offset_size = otherhand.offset_size;
      hand.temp_space = otherhand.temp_space;
      hand.temp_offset = otherhand.temp_offset;
    } else {
      hand.offset_space = null;
      hand.offset_offset = hand.space.wrapOffset(this.fix(walker));
    }
  }

  /**
   * Replace old handles with new handles during macro expansion.
   */
  transfer(params: HandleTpl[]): void {
    if (this.type !== const_type.handle) return;
    const newhandle = params[this.handle_index];

    switch (this.select) {
      case v_field.v_space:
        this.copyFrom(newhandle.getSpace());
        break;
      case v_field.v_offset:
        this.copyFrom(newhandle.getPtrOffset());
        break;
      case v_field.v_offset_plus: {
        const tmp = this.value_real;
        this.copyFrom(newhandle.getPtrOffset());
        // After copyFrom, type and select may have changed to any valid value
        if ((this.type as const_type) === const_type.real) {
          this.value_real += (tmp & 0xffffn);
        } else if ((this.type as const_type) === const_type.handle && (this.select as v_field) === v_field.v_offset) {
          this.select = v_field.v_offset_plus;
          this.value_real = tmp;
        } else {
          throw new LowlevelError('Cannot truncate macro input in this way');
        }
        break;
      }
      case v_field.v_size:
        this.copyFrom(newhandle.getSize());
        break;
    }
  }

  changeHandleIndex(handmap: number[]): void {
    if (this.type === const_type.handle)
      this.handle_index = handmap[this.handle_index];
  }

  isZero(): boolean {
    return this.type === const_type.real && this.value_real === 0n;
  }

  encode(encoder: Encoder): void {
    switch (this.type) {
      case const_type.real:
        (encoder as any).openElement(sla.ELEM_CONST_REAL);
        (encoder as any).writeUnsignedInteger(sla.ATTRIB_VAL, this.value_real);
        (encoder as any).closeElement(sla.ELEM_CONST_REAL);
        break;
      case const_type.handle:
        (encoder as any).openElement(sla.ELEM_CONST_HANDLE);
        (encoder as any).writeSignedInteger(sla.ATTRIB_VAL, this.handle_index);
        (encoder as any).writeSignedInteger(sla.ATTRIB_S, this.select);
        if (this.select === v_field.v_offset_plus)
          (encoder as any).writeUnsignedInteger(sla.ATTRIB_PLUS, this.value_real);
        (encoder as any).closeElement(sla.ELEM_CONST_HANDLE);
        break;
      case const_type.j_start:
        (encoder as any).openElement(sla.ELEM_CONST_START);
        (encoder as any).closeElement(sla.ELEM_CONST_START);
        break;
      case const_type.j_next:
        (encoder as any).openElement(sla.ELEM_CONST_NEXT);
        (encoder as any).closeElement(sla.ELEM_CONST_NEXT);
        break;
      case const_type.j_next2:
        (encoder as any).openElement(sla.ELEM_CONST_NEXT2);
        (encoder as any).closeElement(sla.ELEM_CONST_NEXT2);
        break;
      case const_type.j_curspace:
        (encoder as any).openElement(sla.ELEM_CONST_CURSPACE);
        (encoder as any).closeElement(sla.ELEM_CONST_CURSPACE);
        break;
      case const_type.j_curspace_size:
        (encoder as any).openElement(sla.ELEM_CONST_CURSPACE_SIZE);
        (encoder as any).closeElement(sla.ELEM_CONST_CURSPACE_SIZE);
        break;
      case const_type.spaceid:
        (encoder as any).openElement(sla.ELEM_CONST_SPACEID);
        (encoder as any).writeSpace(sla.ATTRIB_SPACE, this.spaceid_value);
        (encoder as any).closeElement(sla.ELEM_CONST_SPACEID);
        break;
      case const_type.j_relative:
        (encoder as any).openElement(sla.ELEM_CONST_RELATIVE);
        (encoder as any).writeUnsignedInteger(sla.ATTRIB_VAL, this.value_real);
        (encoder as any).closeElement(sla.ELEM_CONST_RELATIVE);
        break;
      case const_type.j_flowref:
        (encoder as any).openElement(sla.ELEM_CONST_FLOWREF);
        (encoder as any).closeElement(sla.ELEM_CONST_FLOWREF);
        break;
      case const_type.j_flowref_size:
        (encoder as any).openElement(sla.ELEM_CONST_FLOWREF_SIZE);
        (encoder as any).closeElement(sla.ELEM_CONST_FLOWREF_SIZE);
        break;
      case const_type.j_flowdest:
        (encoder as any).openElement(sla.ELEM_CONST_FLOWDEST);
        (encoder as any).closeElement(sla.ELEM_CONST_FLOWDEST);
        break;
      case const_type.j_flowdest_size:
        (encoder as any).openElement(sla.ELEM_CONST_FLOWDEST_SIZE);
        (encoder as any).closeElement(sla.ELEM_CONST_FLOWDEST_SIZE);
        break;
    }
  }

  decode(decoder: Decoder): void {
    const el: number = (decoder as any).openElement();
    if (el === sla.ELEM_CONST_REAL) {
      this.type = const_type.real;
      this.value_real = (decoder as any).readUnsignedInteger(sla.ATTRIB_VAL);
    } else if (el === sla.ELEM_CONST_HANDLE) {
      this.type = const_type.handle;
      this.handle_index = (decoder as any).readSignedInteger(sla.ATTRIB_VAL);
      const selectInt: number = (decoder as any).readSignedInteger(sla.ATTRIB_S);
      if (selectInt > v_field.v_offset_plus)
        throw new LowlevelError('Bad handle selector encoding');
      this.select = selectInt as v_field;
      if (this.select === v_field.v_offset_plus) {
        this.value_real = (decoder as any).readUnsignedInteger(sla.ATTRIB_PLUS);
      }
    } else if (el === sla.ELEM_CONST_START) {
      this.type = const_type.j_start;
    } else if (el === sla.ELEM_CONST_NEXT) {
      this.type = const_type.j_next;
    } else if (el === sla.ELEM_CONST_NEXT2) {
      this.type = const_type.j_next2;
    } else if (el === sla.ELEM_CONST_CURSPACE) {
      this.type = const_type.j_curspace;
    } else if (el === sla.ELEM_CONST_CURSPACE_SIZE) {
      this.type = const_type.j_curspace_size;
    } else if (el === sla.ELEM_CONST_SPACEID) {
      this.type = const_type.spaceid;
      this.spaceid_value = (decoder as any).readSpace(sla.ATTRIB_SPACE);
    } else if (el === sla.ELEM_CONST_RELATIVE) {
      this.type = const_type.j_relative;
      this.value_real = (decoder as any).readUnsignedInteger(sla.ATTRIB_VAL);
    } else if (el === sla.ELEM_CONST_FLOWREF) {
      this.type = const_type.j_flowref;
    } else if (el === sla.ELEM_CONST_FLOWREF_SIZE) {
      this.type = const_type.j_flowref_size;
    } else if (el === sla.ELEM_CONST_FLOWDEST) {
      this.type = const_type.j_flowdest;
    } else if (el === sla.ELEM_CONST_FLOWDEST_SIZE) {
      this.type = const_type.j_flowdest_size;
    } else {
      throw new LowlevelError('Bad constant type');
    }
    (decoder as any).closeElement(el);
  }
}

// ==================================================================
// VarnodeTpl
// ==================================================================

/**
 * A template for producing a Varnode during p-code generation.
 *
 * VarnodeTpl consists of three ConstTpl objects: space, offset, and size.
 * These are resolved at p-code generation time against the ParserWalker context
 * to produce actual Varnodes.
 */
export class VarnodeTpl {
  private space: ConstTpl;
  private offset: ConstTpl;
  private size: ConstTpl;
  private unnamed_flag: boolean;

  constructor();
  constructor(hand: number, zerosize: boolean);
  constructor(sp: ConstTpl, off: ConstTpl, sz: ConstTpl);
  constructor(vn: VarnodeTpl);
  constructor(
    arg0?: number | ConstTpl | VarnodeTpl,
    arg1?: boolean | ConstTpl,
    arg2?: ConstTpl,
  ) {
    this.space = new ConstTpl();
    this.offset = new ConstTpl();
    this.size = new ConstTpl();
    this.unnamed_flag = false;

    if (arg0 === undefined) {
      // Default constructor
      return;
    }

    if (arg0 instanceof VarnodeTpl) {
      // Copy constructor
      this.space = new ConstTpl(arg0.space);
      this.offset = new ConstTpl(arg0.offset);
      this.size = new ConstTpl(arg0.size);
      this.unnamed_flag = arg0.unnamed_flag;
      return;
    }

    if (arg0 instanceof ConstTpl) {
      // VarnodeTpl(sp, off, sz)
      this.space = new ConstTpl(arg0);
      this.offset = new ConstTpl(arg1 as ConstTpl);
      this.size = new ConstTpl(arg2 as ConstTpl);
      this.unnamed_flag = false;
      return;
    }

    // VarnodeTpl(hand: number, zerosize: boolean)
    const hand = arg0 as number;
    const zerosize = arg1 as boolean;
    this.space = new ConstTpl(const_type.handle, hand, v_field.v_space);
    this.offset = new ConstTpl(const_type.handle, hand, v_field.v_offset);
    this.size = new ConstTpl(const_type.handle, hand, v_field.v_size);
    if (zerosize)
      this.size = new ConstTpl(const_type.real, 0n);
    this.unnamed_flag = false;
  }

  getSpace(): ConstTpl {
    return this.space;
  }

  getOffset(): ConstTpl {
    return this.offset;
  }

  getSize(): ConstTpl {
    return this.size;
  }

  isDynamic(walker: ParserWalker): boolean {
    if (this.offset.getType() !== const_type.handle) return false;
    const hand: FixedHandle = (walker as any).getFixedHandle(this.offset.getHandleIndex());
    return hand.offset_space != null;
  }

  /**
   * Replace old handles with new handles during macro expansion.
   * Returns a positive number if truncation of a local temp occurred,
   * or -1 otherwise.
   */
  transfer(params: HandleTpl[]): number {
    let doesOffsetPlus = false;
    let handleIndex = 0;
    let plus = 0;
    if (
      this.offset.getType() === const_type.handle &&
      this.offset.getSelect() === v_field.v_offset_plus
    ) {
      handleIndex = this.offset.getHandleIndex();
      plus = Number(this.offset.getReal());
      doesOffsetPlus = true;
    }
    this.space.transfer(params);
    this.offset.transfer(params);
    this.size.transfer(params);
    if (doesOffsetPlus) {
      if (this.isLocalTemp())
        return plus; // A positive number indicates truncation of a local temp
      if (params[handleIndex].getSize().isZero())
        return plus; //    or a zerosize object
    }
    return -1;
  }

  isZeroSize(): boolean {
    return this.size.isZero();
  }

  equals(op2: VarnodeTpl): boolean {
    return (
      this.space.equals(op2.space) &&
      this.offset.equals(op2.offset) &&
      this.size.equals(op2.size)
    );
  }

  notEquals(op2: VarnodeTpl): boolean {
    return !this.equals(op2);
  }

  lessThan(op2: VarnodeTpl): boolean {
    if (!this.space.equals(op2.space)) return this.space.lessThan(op2.space);
    if (!this.offset.equals(op2.offset)) return this.offset.lessThan(op2.offset);
    if (!this.size.equals(op2.size)) return this.size.lessThan(op2.size);
    return false;
  }

  setOffset(constVal: bigint): void {
    this.offset = new ConstTpl(const_type.real, constVal);
  }

  setRelative(constVal: bigint): void {
    this.offset = new ConstTpl(const_type.j_relative, constVal);
  }

  setSize(sz: ConstTpl): void {
    this.size = sz;
  }

  isUnnamed(): boolean {
    return this.unnamed_flag;
  }

  setUnnamed(val: boolean): void {
    this.unnamed_flag = val;
  }

  isLocalTemp(): boolean {
    if (this.space.getType() !== const_type.spaceid) return false;
    if (this.space.getSpace()!.getType() !== spacetype.IPTR_INTERNAL) return false;
    return true;
  }

  isRelative(): boolean {
    return this.offset.getType() === const_type.j_relative;
  }

  changeHandleIndex(handmap: number[]): void {
    this.space.changeHandleIndex(handmap);
    this.offset.changeHandleIndex(handmap);
    this.size.changeHandleIndex(handmap);
  }

  /**
   * Adjust truncation parameters for this varnode template.
   * Returns true if truncation is in bounds.
   */
  adjustTruncation(sz: number, isbigendian: boolean): boolean {
    if (this.size.getType() !== const_type.real)
      return false;
    const numbytes = Number(this.size.getReal());
    const byteoffset = Number(this.offset.getReal());
    if (numbytes + byteoffset > sz) return false;

    // Encode the original truncation amount with the plus value
    let val: bigint = BigInt(byteoffset);
    val <<= 16n;
    if (isbigendian) {
      val |= BigInt(sz - (numbytes + byteoffset));
    } else {
      val |= BigInt(byteoffset);
    }

    this.offset = new ConstTpl(
      const_type.handle,
      this.offset.getHandleIndex(),
      v_field.v_offset_plus,
      val,
    );
    return true;
  }

  encode(encoder: Encoder): void {
    (encoder as any).openElement(sla.ELEM_VARNODE_TPL);
    this.space.encode(encoder);
    this.offset.encode(encoder);
    this.size.encode(encoder);
    (encoder as any).closeElement(sla.ELEM_VARNODE_TPL);
  }

  decode(decoder: Decoder): void {
    const el: number = (decoder as any).openElement(sla.ELEM_VARNODE_TPL);
    this.space.decode(decoder);
    this.offset.decode(decoder);
    this.size.decode(decoder);
    (decoder as any).closeElement(el);
  }
}

// ==================================================================
// HandleTpl
// ==================================================================

/**
 * A template for producing a Handle during p-code generation.
 *
 * HandleTpl represents the exported value of a constructor and can model
 * both direct and indirect (pointer-mediated) references.
 */
export class HandleTpl {
  private space: ConstTpl;
  private size: ConstTpl;
  private ptrspace: ConstTpl;
  private ptroffset: ConstTpl;
  private ptrsize: ConstTpl;
  private temp_space: ConstTpl;
  private temp_offset: ConstTpl;

  constructor();
  constructor(vn: VarnodeTpl);
  constructor(
    spc: ConstTpl,
    sz: ConstTpl,
    vn: VarnodeTpl,
    t_space: AddrSpace,
    t_offset: bigint,
  );
  constructor(
    arg0?: VarnodeTpl | ConstTpl,
    arg1?: ConstTpl,
    arg2?: VarnodeTpl,
    arg3?: AddrSpace,
    arg4?: bigint,
  ) {
    this.space = new ConstTpl();
    this.size = new ConstTpl();
    this.ptrspace = new ConstTpl();
    this.ptroffset = new ConstTpl();
    this.ptrsize = new ConstTpl();
    this.temp_space = new ConstTpl();
    this.temp_offset = new ConstTpl();

    if (arg0 === undefined) {
      // Default constructor
      return;
    }

    if (arg0 instanceof VarnodeTpl) {
      // HandleTpl(const VarnodeTpl *vn) - build handle which indicates given varnode
      const vn = arg0;
      this.space = new ConstTpl(vn.getSpace());
      this.size = new ConstTpl(vn.getSize());
      this.ptrspace = new ConstTpl(const_type.real, 0n);
      this.ptroffset = new ConstTpl(vn.getOffset());
      return;
    }

    // HandleTpl(spc, sz, vn, t_space, t_offset) - build handle to thing pointed at by vn
    const spc = arg0 as ConstTpl;
    const sz = arg1 as ConstTpl;
    const vn = arg2 as VarnodeTpl;
    const t_space = arg3 as AddrSpace;
    const t_offset = arg4 as bigint;
    this.space = new ConstTpl(spc);
    this.size = new ConstTpl(sz);
    this.ptrspace = new ConstTpl(vn.getSpace());
    this.ptroffset = new ConstTpl(vn.getOffset());
    this.ptrsize = new ConstTpl(vn.getSize());
    this.temp_space = new ConstTpl(t_space);
    this.temp_offset = new ConstTpl(const_type.real, t_offset);
  }

  getSpace(): ConstTpl {
    return this.space;
  }

  getPtrSpace(): ConstTpl {
    return this.ptrspace;
  }

  getPtrOffset(): ConstTpl {
    return this.ptroffset;
  }

  getPtrSize(): ConstTpl {
    return this.ptrsize;
  }

  getSize(): ConstTpl {
    return this.size;
  }

  getTempSpace(): ConstTpl {
    return this.temp_space;
  }

  getTempOffset(): ConstTpl {
    return this.temp_offset;
  }

  setSize(sz: ConstTpl): void {
    this.size = sz;
  }

  setPtrSize(sz: ConstTpl): void {
    this.ptrsize = sz;
  }

  setPtrOffset(val: bigint): void {
    this.ptroffset = new ConstTpl(const_type.real, val);
  }

  setTempOffset(val: bigint): void {
    this.temp_offset = new ConstTpl(const_type.real, val);
  }

  fix(hand: FixedHandle, walker: ParserWalker): void {
    if (this.ptrspace.getType() === const_type.real) {
      // The export is unstarred, but this doesn't mean the varnode
      // being exported isn't dynamic
      this.space.fillinSpace(hand, walker);
      hand.size = Number(this.size.fix(walker));
      this.ptroffset.fillinOffset(hand, walker);
    } else {
      hand.space = this.space.fixSpace(walker);
      hand.size = Number(this.size.fix(walker));
      hand.offset_offset = this.ptroffset.fix(walker);
      hand.offset_space = this.ptrspace.fixSpace(walker);
      if (hand.offset_space.getType() === spacetype.IPTR_CONSTANT) {
        // Handle could have been dynamic but wasn't
        hand.offset_space = null;
        hand.offset_offset = AddrSpace.addressToByte(
          hand.offset_offset,
          hand.space.getWordSize(),
        );
        hand.offset_offset = hand.space.wrapOffset(hand.offset_offset);
      } else {
        hand.offset_size = Number(this.ptrsize.fix(walker));
        hand.temp_space = this.temp_space.fixSpace(walker);
        hand.temp_offset = this.temp_offset.fix(walker);
      }
    }
  }

  changeHandleIndex(handmap: number[]): void {
    this.space.changeHandleIndex(handmap);
    this.size.changeHandleIndex(handmap);
    this.ptrspace.changeHandleIndex(handmap);
    this.ptroffset.changeHandleIndex(handmap);
    this.ptrsize.changeHandleIndex(handmap);
    this.temp_space.changeHandleIndex(handmap);
    this.temp_offset.changeHandleIndex(handmap);
  }

  encode(encoder: Encoder): void {
    (encoder as any).openElement(sla.ELEM_HANDLE_TPL);
    this.space.encode(encoder);
    this.size.encode(encoder);
    this.ptrspace.encode(encoder);
    this.ptroffset.encode(encoder);
    this.ptrsize.encode(encoder);
    this.temp_space.encode(encoder);
    this.temp_offset.encode(encoder);
    (encoder as any).closeElement(sla.ELEM_HANDLE_TPL);
  }

  decode(decoder: Decoder): void {
    const el: number = (decoder as any).openElement(sla.ELEM_HANDLE_TPL);
    this.space.decode(decoder);
    this.size.decode(decoder);
    this.ptrspace.decode(decoder);
    this.ptroffset.decode(decoder);
    this.ptrsize.decode(decoder);
    this.temp_space.decode(decoder);
    this.temp_offset.decode(decoder);
    (decoder as any).closeElement(el);
  }
}

// ==================================================================
// OpTpl
// ==================================================================

/**
 * A template for producing a single p-code operation during generation.
 *
 * An OpTpl owns its output and input VarnodeTpl objects.
 */
export class OpTpl {
  private output: VarnodeTpl | null;
  private opc: OpCode;
  private input: VarnodeTpl[];

  constructor();
  constructor(oc: OpCode);
  constructor(oc?: OpCode) {
    this.input = [];
    if (oc !== undefined) {
      this.opc = oc;
      this.output = null;
    } else {
      this.opc = OpCode.CPUI_COPY; // default
      this.output = null;
    }
  }

  getOut(): VarnodeTpl | null {
    return this.output;
  }

  numInput(): number {
    return this.input.length;
  }

  getIn(i: number): VarnodeTpl {
    return this.input[i];
  }

  getOpcode(): OpCode {
    return this.opc;
  }

  isZeroSize(): boolean {
    if (this.output !== null)
      if (this.output.isZeroSize()) return true;
    for (let i = 0; i < this.input.length; i++)
      if (this.input[i].isZeroSize()) return true;
    return false;
  }

  setOpcode(o: OpCode): void {
    this.opc = o;
  }

  setOutput(vt: VarnodeTpl | null): void {
    this.output = vt;
  }

  clearOutput(): void {
    // GC handles deletion
    this.output = null;
  }

  addInput(vt: VarnodeTpl): void {
    this.input.push(vt);
  }

  setInput(vt: VarnodeTpl, slot: number): void {
    this.input[slot] = vt;
  }

  removeInput(index: number): void {
    // Remove the indicated input (GC handles deletion)
    this.input.splice(index, 1);
  }

  changeHandleIndex(handmap: number[]): void {
    if (this.output !== null)
      this.output.changeHandleIndex(handmap);
    for (let i = 0; i < this.input.length; i++)
      this.input[i].changeHandleIndex(handmap);
  }

  encode(encoder: Encoder): void {
    (encoder as any).openElement(sla.ELEM_OP_TPL);
    (encoder as any).writeOpcode(sla.ATTRIB_CODE, this.opc);
    if (this.output === null) {
      (encoder as any).openElement(sla.ELEM_NULL);
      (encoder as any).closeElement(sla.ELEM_NULL);
    } else {
      this.output.encode(encoder);
    }
    for (let i = 0; i < this.input.length; i++)
      this.input[i].encode(encoder);
    (encoder as any).closeElement(sla.ELEM_OP_TPL);
  }

  decode(decoder: Decoder): void {
    const el: number = (decoder as any).openElement(sla.ELEM_OP_TPL);
    this.opc = (decoder as any).readOpcode(sla.ATTRIB_CODE);
    const subel: number = (decoder as any).peekElement();
    if (subel === sla.ELEM_NULL) {
      (decoder as any).openElement();
      (decoder as any).closeElement(subel);
      this.output = null;
    } else {
      this.output = new VarnodeTpl();
      this.output.decode(decoder);
    }
    while ((decoder as any).peekElement() !== 0) {
      const vn = new VarnodeTpl();
      vn.decode(decoder);
      this.input.push(vn);
    }
    (decoder as any).closeElement(el);
  }
}

// ==================================================================
// ConstructTpl
// ==================================================================

/**
 * A constructor template - the full p-code body of a SLEIGH constructor.
 *
 * A ConstructTpl contains a list of OpTpl objects and an optional result HandleTpl.
 */
export class ConstructTpl {
  protected delayslot: number;
  protected numlabels: number;
  protected vec: OpTpl[];
  protected result: HandleTpl | null;

  constructor() {
    this.delayslot = 0;
    this.numlabels = 0;
    this.vec = [];
    this.result = null;
  }

  protected setOpvec(opvec: OpTpl[]): void {
    this.vec = opvec;
  }

  protected setNumLabels(val: number): void {
    this.numlabels = val;
  }

  delaySlot(): number {
    return this.delayslot;
  }

  numLabels(): number {
    return this.numlabels;
  }

  getOpvec(): OpTpl[] {
    return this.vec;
  }

  getResult(): HandleTpl | null {
    return this.result;
  }

  addOp(ot: OpTpl): boolean {
    if (ot.getOpcode() === DELAY_SLOT) {
      if (this.delayslot !== 0)
        return false; // Cannot have multiple delay slots
      this.delayslot = Number(ot.getIn(0).getOffset().getReal());
    } else if (ot.getOpcode() === LABELBUILD) {
      this.numlabels += 1; // Count labels
    }
    this.vec.push(ot);
    return true;
  }

  addOpList(oplist: OpTpl[]): boolean {
    for (let i = 0; i < oplist.length; i++)
      if (!this.addOp(oplist[i]))
        return false;
    return true;
  }

  setResult(t: HandleTpl | null): void {
    this.result = t;
  }

  /**
   * Make sure there is a build statement for all subtable params.
   * Return 0 upon success, 1 if there is a duplicate BUILD, 2 if there is a build for a non-subtable.
   */
  fillinBuild(check: number[], const_space: AddrSpace): number {
    for (let i = 0; i < this.vec.length; i++) {
      const op = this.vec[i];
      if (op.getOpcode() === BUILD) {
        const index = Number(op.getIn(0).getOffset().getReal());
        if (check[index] !== 0)
          return check[index]; // Duplicate BUILD statement or non-subtable
        check[index] = 1; // Mark to avoid future duplicate build
      }
    }
    for (let i = 0; i < check.length; i++) {
      if (check[i] === 0) {
        // Didn't see a BUILD statement
        const op = new OpTpl(BUILD);
        const indvn = new VarnodeTpl(
          new ConstTpl(const_space),
          new ConstTpl(const_type.real, BigInt(i)),
          new ConstTpl(const_type.real, 4n),
        );
        op.addInput(indvn);
        this.vec.unshift(op);
      }
    }
    return 0;
  }

  buildOnly(): boolean {
    for (let i = 0; i < this.vec.length; i++) {
      if (this.vec[i].getOpcode() !== BUILD)
        return false;
    }
    return true;
  }

  changeHandleIndex(handmap: number[]): void {
    for (let i = 0; i < this.vec.length; i++) {
      const op = this.vec[i];
      if (op.getOpcode() === BUILD) {
        let index = Number(op.getIn(0).getOffset().getReal());
        index = handmap[index];
        op.getIn(0).setOffset(BigInt(index));
      } else {
        op.changeHandleIndex(handmap);
      }
    }
    if (this.result !== null)
      this.result.changeHandleIndex(handmap);
  }

  /** Set the VarnodeTpl input for a particular op (for optimization routines). */
  setInput(vn: VarnodeTpl, index: number, slot: number): void {
    const op = this.vec[index];
    op.setInput(vn, slot);
    // GC handles deletion of old vn
  }

  /** Set the VarnodeTpl output for a particular op (for optimization routines). */
  setOutput(vn: VarnodeTpl, index: number): void {
    const op = this.vec[index];
    op.setOutput(vn);
    // GC handles deletion of old vn
  }

  /** Delete a particular set of ops. */
  deleteOps(indices: number[]): void {
    for (let i = 0; i < indices.length; i++) {
      // GC handles deletion
      (this.vec as any)[indices[i]] = null;
    }
    // Compact the array
    let poscur = 0;
    for (let i = 0; i < this.vec.length; i++) {
      if (this.vec[i] !== null) {
        this.vec[poscur] = this.vec[i];
        poscur += 1;
      }
    }
    this.vec.length = poscur;
  }

  encode(encoder: Encoder, sectionid: number): void {
    (encoder as any).openElement(sla.ELEM_CONSTRUCT_TPL);
    if (sectionid >= 0)
      (encoder as any).writeSignedInteger(sla.ATTRIB_SECTION, sectionid);
    if (this.delayslot !== 0)
      (encoder as any).writeSignedInteger(sla.ATTRIB_DELAY, this.delayslot);
    if (this.numlabels !== 0)
      (encoder as any).writeSignedInteger(sla.ATTRIB_LABELS, this.numlabels);
    if (this.result !== null) {
      this.result.encode(encoder);
    } else {
      (encoder as any).openElement(sla.ELEM_NULL);
      (encoder as any).closeElement(sla.ELEM_NULL);
    }
    for (let i = 0; i < this.vec.length; i++)
      this.vec[i].encode(encoder);
    (encoder as any).closeElement(sla.ELEM_CONSTRUCT_TPL);
  }

  decode(decoder: Decoder): number {
    const el: number = (decoder as any).openElement(sla.ELEM_CONSTRUCT_TPL);
    let sectionid = -1;
    let attrib: number = (decoder as any).getNextAttributeId();
    while (attrib !== 0) {
      if (attrib === sla.ATTRIB_DELAY) {
        this.delayslot = (decoder as any).readSignedInteger();
      } else if (attrib === sla.ATTRIB_LABELS) {
        this.numlabels = (decoder as any).readSignedInteger();
      } else if (attrib === sla.ATTRIB_SECTION) {
        sectionid = (decoder as any).readSignedInteger();
      }
      attrib = (decoder as any).getNextAttributeId();
    }
    const subel: number = (decoder as any).peekElement();
    if (subel === sla.ELEM_NULL) {
      (decoder as any).openElement();
      (decoder as any).closeElement(subel);
      this.result = null;
    } else {
      this.result = new HandleTpl();
      this.result.decode(decoder);
    }
    while ((decoder as any).peekElement() !== 0) {
      const op = new OpTpl();
      op.decode(decoder);
      this.vec.push(op);
    }
    (decoder as any).closeElement(el);
    return sectionid;
  }
}

// ==================================================================
// PcodeBuilder (abstract)
// ==================================================================

/**
 * Abstract base class for SLEIGH-specific p-code generation.
 *
 * PcodeBuilder walks a ConstructTpl tree and dispatches each OpTpl
 * to the appropriate handler (build, delay slot, label, crossbuild, or dump).
 */
export abstract class PcodeBuilder {
  private labelbase: number;
  private labelcount: number;
  protected walker: ParserWalker | null;

  constructor(lbcnt: number) {
    this.labelbase = lbcnt;
    this.labelcount = lbcnt;
    this.walker = null;
  }

  getLabelBase(): number {
    return this.labelbase;
  }

  getCurrentWalker(): ParserWalker | null {
    return this.walker;
  }

  build(construct: ConstructTpl | null, secnum: number): void {
    if (construct === null)
      throw new UnimplError('', 0); // Pcode is not implemented for this constructor

    const oldbase = this.labelbase; // Recursively store old labelbase
    this.labelbase = this.labelcount; // Set the newbase
    this.labelcount += construct.numLabels(); // Add labels from this template

    const ops = construct.getOpvec();

    for (let i = 0; i < ops.length; i++) {
      const op = ops[i];
      switch (op.getOpcode()) {
        case BUILD:
          this.appendBuild(op, secnum);
          break;
        case DELAY_SLOT:
          this.delaySlot(op);
          break;
        case LABELBUILD:
          this.setLabel(op);
          break;
        case CROSSBUILD:
          this.appendCrossBuild(op, secnum);
          break;
        default:
          this.dump(op);
          break;
      }
    }
    this.labelbase = oldbase; // Restore old labelbase
  }

  protected abstract dump(op: OpTpl): void;
  abstract appendBuild(bld: OpTpl, secnum: number): void;
  abstract delaySlot(op: OpTpl): void;
  abstract setLabel(op: OpTpl): void;
  abstract appendCrossBuild(bld: OpTpl, secnum: number): void;
}
