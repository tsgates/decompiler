/**
 * @file address.ts
 * @description Classes for specifying addresses and other low-level constants.
 *
 * Translated from Ghidra's address.hh / address.cc.
 *
 * All addresses are absolute and there are no registers in CPUI. However,
 * all addresses are prefixed with an "immutable" pointer, which can
 * specify a separate RAM space, a register space, an i/o space etc. Thus
 * a translation from a real machine language will typically simulate registers
 * by placing them in their own space, separate from RAM. Indirection
 * (i.e. pointers) must be simulated through the LOAD and STORE ops.
 */

import type { AddrSpace, spacetype } from './space.js';
import { LowlevelError } from './error.js';
import type { Decoder } from './marshal.js';
import { AttributeId, ElementId, ATTRIB_NAME, ATTRIB_SPACE } from './marshal.js';
import { VarnodeData } from './pcoderaw.js';

const ATTRIB_FIRST = new AttributeId('first', 27);
const ATTRIB_LAST = new AttributeId('last', 28);
const ELEM_RANGE = new ElementId('range', 12);
const ELEM_RANGELIST = new ElementId('rangelist', 13);

// ---------------------------------------------------------------------------
// Sentinel objects for extremal address comparisons
// ---------------------------------------------------------------------------

/**
 * Sentinel AddrSpace used to represent the maximal (largest possible) address.
 * In C++ this is `(AddrSpace *) ~((uintp)0)`.  We use a dedicated object so
 * that identity comparison (`===`) works reliably.
 */
const MAXIMAL_SPACE_SENTINEL: AddrSpace = Object.freeze({
  __maximalSentinel: true,
}) as unknown as AddrSpace;

// ---------------------------------------------------------------------------
// Precalculated masks (uintbmasks)
// ---------------------------------------------------------------------------

/**
 * Precalculated byte-size masks.  `uintbmasks[n]` gives a mask covering
 * the least-significant `n` bytes (i.e. `n*8` bits), capped at 8 bytes.
 *
 * Index 0 is 0n, index 1 is 0xFFn, ..., index 8 is 0xFFFFFFFFFFFFFFFFn.
 */
export const uintbmasks: bigint[] = [
  0x0n,
  0xFFn,
  0xFFFFn,
  0xFFFFFFn,
  0xFFFFFFFFn,
  0xFFFFFFFFFFn,
  0xFFFFFFFFFFFFn,
  0xFFFFFFFFFFFFFFn,
  0xFFFFFFFFFFFFFFFFn,
];

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/**
 * Return a mask appropriate for masking off the first `size` bytes.
 * Sizes larger than 8 are clamped to 8.
 */
export function calc_mask(size: number): bigint {
  return uintbmasks[size < 8 ? (size >= 0 ? size : 0) : 8];
}

/** Largest unsigned integer value for a given byte size. */
export function calc_uint_max(size: number): bigint {
  return calc_mask(size);
}

/** Largest signed integer value for a given byte size. */
export function calc_int_max(size: number): bigint {
  return calc_mask(size) >> 1n;
}

/** Smallest (most negative) signed integer value for a given byte size. */
export function calc_int_min(size: number): bigint {
  return 1n << BigInt(size * 8 - 1);
}

/**
 * Perform a CPUI_INT_RIGHT (logical right shift) on the given value.
 * If the shift amount is >= 64 the result is 0n.
 */
export function pcode_right(val: bigint, sa: number): bigint {
  if (sa >= 64) return 0n;
  return val >> BigInt(sa);
}

/**
 * Perform a CPUI_INT_LEFT (logical left shift) on the given value.
 * If the shift amount is >= 64 the result is 0n.
 */
export function pcode_left(val: bigint, sa: number): bigint {
  if (sa >= 64) return 0n;
  return val << BigInt(sa);
}

/**
 * Calculate the smallest mask that covers the given value.
 * The mask covers either the least significant byte, uint16, uint32, or uint64,
 * whichever is smallest.
 */
export function minimalmask(val: bigint): bigint {
  if (val > 0xFFFFFFFFn) return ~0n & 0xFFFFFFFFFFFFFFFFn;
  if (val > 0xFFFFn) return 0xFFFFFFFFn;
  if (val > 0xFFn) return 0xFFFFn;
  return 0xFFn;
}

/**
 * Sign-extend `val` starting at bit position `bit` (0 = least significant).
 * All bits above position `bit` are set to match the bit at position `bit`.
 */
export function sign_extend(val: bigint, bit: number): bigint {
  // Emulate: int sa = 64 - (bit+1); val = (val << sa) >> sa;
  // We operate in signed 64-bit arithmetic.
  const sa = 64 - (bit + 1);
  if (sa < 0) return val;
  if (sa === 0) {
    // Full 64-bit value: interpret as signed
    if (val >= 0x8000000000000000n) {
      return val - 0x10000000000000000n;
    }
    return val;
  }
  // Shift left, then arithmetic shift right, all within 64-bit signed range
  let v = (val << BigInt(sa)) & 0xFFFFFFFFFFFFFFFFn;
  // Convert to signed for arithmetic shift right
  if (v >= 0x8000000000000000n) {
    v = v - 0x10000000000000000n; // make it negative
  }
  v = v >> BigInt(sa);
  return v;
}

/**
 * Zero-extend `val` starting at bit position `bit` (0 = least significant).
 * All bits above position `bit` are cleared.
 */
export function zero_extend(val: bigint, bit: number): bigint {
  const sa = 64 - (bit + 1);
  if (sa <= 0) return val & 0xFFFFFFFFFFFFFFFFn;
  return ((val << BigInt(sa)) & 0xFFFFFFFFFFFFFFFFn) >> BigInt(sa);
}

/**
 * Return true if the sign-bit is set for a value treated as a
 * constant of `size` bytes.
 */
export function signbit_negative(val: bigint, size: number): boolean {
  const mask = 0x80n << BigInt(8 * (size - 1));
  return (val & mask) !== 0n;
}

/**
 * Negate the sized value, keeping upper bytes zero.
 */
export function uintb_negate(val: bigint, size: number): bigint {
  return (~val) & calc_mask(size);
}

/**
 * Swap the least significant `size` bytes of `val`.
 */
export function byte_swap(val: bigint, size: number): bigint {
  let v = val;
  let res = 0n;
  for (let i = 0; i < size; i++) {
    res = (res << 8n) | (v & 0xFFn);
    v >>= 8n;
  }
  return res;
}

/**
 * Return the index of the least significant set bit, or -1 if val is 0.
 * Bit 0 is the least significant bit.
 */
export function leastsigbit_set(val: bigint): number {
  if (val === 0n) return -1;
  let v = val;
  let res = 0;
  let sz = 32; // 4 * sizeof(uintb=8)
  let mask = 0xFFFFFFFFFFFFFFFFn; // ~0n masked to 64 bits
  do {
    mask = mask >> BigInt(sz);
    if ((mask & v) === 0n) {
      res += sz;
      v >>= BigInt(sz);
    }
    sz >>= 1;
  } while (sz !== 0);
  return res;
}

/**
 * Return the index of the most significant set bit, or -1 if val is 0.
 * Bit 0 is the least significant bit.
 */
export function mostsigbit_set(val: bigint): number {
  if (val === 0n) return -1;
  let v = val & 0xFFFFFFFFFFFFFFFFn;
  let res = 63; // 8*sizeof(uintb)-1
  let sz = 32; // 4*sizeof(uintb)
  let mask = 0xFFFFFFFFFFFFFFFFn;
  do {
    mask = (mask << BigInt(sz)) & 0xFFFFFFFFFFFFFFFFn;
    if ((mask & v) === 0n) {
      res -= sz;
      v = (v << BigInt(sz)) & 0xFFFFFFFFFFFFFFFFn;
    }
    sz >>= 1;
  } while (sz !== 0);
  return res;
}

/**
 * Return the number of one bits (population count) in the given value.
 */
export function popcount(val: bigint): number {
  let v = val & 0xFFFFFFFFFFFFFFFFn;
  v = (v & 0x5555555555555555n) + ((v >> 1n) & 0x5555555555555555n);
  v = (v & 0x3333333333333333n) + ((v >> 2n) & 0x3333333333333333n);
  v = (v & 0x0F0F0F0F0F0F0F0Fn) + ((v >> 4n) & 0x0F0F0F0F0F0F0F0Fn);
  v = (v & 0x00FF00FF00FF00FFn) + ((v >> 8n) & 0x00FF00FF00FF00FFn);
  v = (v & 0x0000FFFF0000FFFFn) + ((v >> 16n) & 0x0000FFFF0000FFFFn);
  const res = Number(v & 0xFFn) + Number((v >> 32n) & 0xFFn);
  return res;
}

/**
 * Return the number of leading zero bits in a 64-bit value.
 */
export function count_leading_zeros(val: bigint): number {
  if (val === 0n) return 64;
  const v = val & 0xFFFFFFFFFFFFFFFFn;
  let mask = 0xFFFFFFFFFFFFFFFFn;
  let maskSize = 32;
  mask = (mask << BigInt(maskSize)) & 0xFFFFFFFFFFFFFFFFn;
  let bit = 0;

  do {
    if ((mask & v) === 0n) {
      bit += maskSize;
      maskSize >>= 1;
      mask = (mask | (mask >> BigInt(maskSize))) & 0xFFFFFFFFFFFFFFFFn;
    } else {
      maskSize >>= 1;
      mask = (mask << BigInt(maskSize)) & 0xFFFFFFFFFFFFFFFFn;
    }
  } while (maskSize !== 0);
  return bit;
}

/**
 * Return the smallest number of the form 2^n - 1 that is >= val.
 */
export function coveringmask(val: bigint): bigint {
  let res = val & 0xFFFFFFFFFFFFFFFFn;
  let sz = 1;
  while (sz < 64) {
    res = res | (res >> BigInt(sz));
    sz <<= 1;
  }
  return res;
}

/**
 * Scanning across the bits of `val` (treated as a `sz`-byte constant),
 * return the number of transitions (from 0->1 or 1->0).
 * If there are 2 or fewer transitions, this indicates a bit flag or mask.
 */
export function bit_transitions(val: bigint, sz: number): number {
  let v = val;
  let res = 0;
  let last = Number(v & 1n);
  for (let i = 1; i < 8 * sz; i++) {
    v >>= 1n;
    const cur = Number(v & 1n);
    if (cur !== last) {
      res += 1;
      last = cur;
    }
    if (v === 0n) break;
  }
  return res;
}

// ---------------------------------------------------------------------------
// Address class
// ---------------------------------------------------------------------------

/** Enum for specifying extremal addresses. */
export const enum MachExtreme {
  /** Smallest possible address */
  m_minimal = 0,
  /** Biggest possible address */
  m_maximal = 1,
}

/**
 * A low-level machine address for labelling bytes and data.
 *
 * All data that can be manipulated within the processor reverse engineering
 * model can be labelled with an Address. It is simply an address space
 * (AddrSpace) and an offset within that space.
 *
 * An Address represents an offset only, not an offset and length.
 */
export class Address {
  /** Pointer to our address space (null means invalid address) */
  base: AddrSpace | null;
  /** Offset (in bytes) */
  offset: bigint;

  /**
   * Construct an Address.
   * - No arguments: creates an invalid address.
   * - (MachExtreme): creates an extremal sentinel address.
   * - (AddrSpace, bigint): creates a normal address.
   * - (Address): copy constructor.
   */
  constructor();
  constructor(ex: MachExtreme);
  constructor(space: AddrSpace, offset: bigint);
  constructor(other: Address);
  constructor(
    arg0?: AddrSpace | Address | MachExtreme,
    arg1?: bigint,
  ) {
    if (arg0 === undefined) {
      // Invalid address
      this.base = null;
      this.offset = 0n;
    } else if (typeof arg0 === 'number') {
      // MachExtreme
      if (arg0 === MachExtreme.m_minimal) {
        this.base = null;
        this.offset = 0n;
      } else {
        // m_maximal
        this.base = MAXIMAL_SPACE_SENTINEL;
        this.offset = 0xFFFFFFFFFFFFFFFFn;
      }
    } else if (arg0 instanceof Address) {
      // Copy constructor
      this.base = arg0.base;
      this.offset = arg0.offset;
    } else if (arg1 === undefined && typeof (arg0 as any).getOffset === 'function' && typeof (arg0 as any).base !== 'undefined') {
      // Copy from pcoderaw.Address (not instanceof address.ts Address, but same shape)
      this.base = (arg0 as any).base;
      this.offset = (arg0 as any).offset;
    } else {
      // AddrSpace + offset
      this.base = arg0;
      this.offset = arg1!;
    }
  }

  /** Is the address invalid? */
  isInvalid(): boolean {
    return this.base === null;
  }

  /** Get the address space. Returns null if invalid. */
  getSpace(): AddrSpace | null {
    return this.base;
  }

  /** Get the address offset. */
  getOffset(): bigint {
    return this.offset;
  }

  /** Get the number of bytes in the address encoding. */
  getAddrSize(): number {
    return this.base!.getAddrSize();
  }

  /** Is data at this address big endian encoded? */
  isBigEndian(): boolean {
    return this.base!.isBigEndian();
  }

  /** Is this a constant value? */
  isConstant(): boolean {
    if (this.base === null || this.base === MAXIMAL_SPACE_SENTINEL) return false;
    if (typeof this.base.getType !== 'function') return false;
    return this.base.getType() === (0 as spacetype); // IPTR_CONSTANT
  }

  /** Is this a join value? */
  isJoin(): boolean {
    if (this.base === null || this.base === MAXIMAL_SPACE_SENTINEL) return false;
    if (typeof this.base.getType !== 'function') return false;
    return this.base.getType() === (6 as spacetype); // IPTR_JOIN
  }

  /** Get the shortcut character for the address space. */
  getShortcut(): string {
    return this.base!.getShortcut();
  }

  /**
   * Write a raw version of the address to a string.
   * Returns a short-hand / debug representation.
   */
  printRaw(): string {
    if (this.base === null) {
      return 'invalid_addr';
    }
    if (this.base === MAXIMAL_SPACE_SENTINEL) {
      return 'maximal_addr';
    }
    return this.base.printRaw(this.offset);
  }

  /** Convert to a human-readable string (equivalent of operator<< in C++). */
  toString(): string {
    return this.printRaw();
  }

  // ---- Assignment / copy ----

  /** Copy from another address (mutates this). */
  assign(op2: Address): this {
    this.base = op2.base;
    this.offset = op2.offset;
    return this;
  }

  /** Set the space and offset in place (avoids allocation). */
  set(space: AddrSpace | null, offset: bigint): this {
    this.base = space;
    this.offset = offset;
    return this;
  }

  /** Set to minimal sentinel in place. */
  setMinimal(): this {
    this.base = null;
    this.offset = 0n;
    return this;
  }

  /** Set to maximal sentinel in place. */
  setMaximal(): this {
    this.base = MAXIMAL_SPACE_SENTINEL;
    this.offset = 0xFFFFFFFFFFFFFFFFn;
    return this;
  }

  // ---- Comparison (instance methods) ----

  /** Check if two addresses are equal. */
  equals(op2: Address): boolean {
    return this.base === op2.base && this.offset === op2.offset;
  }

  /** Check if this address is strictly less than op2 in the natural ordering. */
  lessThan(op2: Address): boolean {
    if (this.base !== op2.base) {
      // null (minimal sentinel) sorts before everything
      if (this.base === null) return true;
      if (this.base === MAXIMAL_SPACE_SENTINEL) return false;
      if (op2.base === null) return false;
      if (op2.base === MAXIMAL_SPACE_SENTINEL) return true;
      const thisIdx = typeof this.base.getIndex === 'function' ? this.base.getIndex() : -1;
      const op2Idx = typeof op2.base.getIndex === 'function' ? op2.base.getIndex() : -1;
      return thisIdx < op2Idx;
    }
    if (this.offset !== op2.offset) return this.offset < op2.offset;
    return false;
  }

  /** Check if this address is less than or equal to op2. */
  lessEqual(op2: Address): boolean {
    if (this.base !== op2.base) {
      if (this.base === null) return true;
      if (this.base === MAXIMAL_SPACE_SENTINEL) return false;
      if (op2.base === null) return false;
      if (op2.base === MAXIMAL_SPACE_SENTINEL) return true;
      const thisIdx = typeof this.base.getIndex === 'function' ? this.base.getIndex() : -1;
      const op2Idx = typeof op2.base.getIndex === 'function' ? op2.base.getIndex() : -1;
      return thisIdx < op2Idx;
    }
    if (this.offset !== op2.offset) return this.offset < op2.offset;
    return true;
  }

  // ---- Arithmetic ----

  /**
   * Increment address by a number of bytes.
   * The addition takes into account the size of the address space
   * and wraps around if necessary.
   */
  add(off: bigint): Address {
    return new Address(this.base!, this.base!.wrapOffset(this.offset + BigInt(off)));
  }

  /**
   * Decrement address by a number of bytes.
   * The subtraction takes into account the size of the address space
   * and wraps around if necessary.
   */
  subtract(off: bigint): Address {
    return new Address(this.base!, this.base!.wrapOffset(this.offset - BigInt(off)));
  }

  // ---- Containment / overlap queries ----

  /**
   * Determine if (op2, sz2) contains (this, sz).
   * Returns true if the range [op2, op2+sz2) fully contains [this, this+sz).
   */
  containedBy(sz: number, op2: Address, sz2: number): boolean {
    if (this.base !== op2.base) return false;
    if (op2.offset > this.offset) return false;
    const off1 = this.offset + BigInt(sz - 1);
    const off2 = op2.offset + BigInt(sz2 - 1);
    return off2 >= off1;
  }

  /**
   * Return the endian-aware offset of (op2, sz2) within (this, sz), or -1.
   *
   * If (op2, sz2) is properly contained in (this, sz):
   * - For big endian (unless forceleft): return distance from the most significant end.
   * - For little endian (or forceleft): return distance from offset.
   */
  justifiedContain(
    sz: number,
    op2: Address,
    sz2: number,
    forceleft: boolean,
  ): number {
    if (this.base !== op2.base) return -1;
    if (op2.offset < this.offset) return -1;
    const off1 = this.offset + BigInt(sz - 1);
    const off2 = op2.offset + BigInt(sz2 - 1);
    if (off2 > off1) return -1;
    if (this.base!.isBigEndian() && !forceleft) {
      return Number(off1 - off2);
    }
    return Number(op2.offset - this.offset);
  }

  /**
   * Determine how (this + skip) falls within the range [op, op + size).
   *
   * Returns a non-negative integer indicating the position within the
   * interval, or -1 if there is no overlap.
   */
  overlap(skip: number, op: Address, size: number): number {
    if (this.base !== op.base) return -1;
    // Constants cannot overlap
    if (this.base!.getType() === (0 as spacetype)) return -1; // IPTR_CONSTANT

    const dist = this.base!.wrapOffset(
      this.offset + BigInt(skip) - op.offset,
    );
    if (dist >= BigInt(size)) return -1;
    return Number(dist);
  }

  /**
   * Like overlap, but a range in the join space can be considered
   * overlapped with its constituent pieces.
   */
  overlapJoin(skip: number, op: Address, size: number): number {
    return op.getSpace()!.overlapJoin(
      op.getOffset(),
      size,
      this.base!,
      this.offset,
      skip,
    );
  }

  /**
   * Does (this, sz) form a contiguous region with (loaddr, losz),
   * where `this` is the most significant piece?
   */
  isContiguous(sz: number, loaddr: Address, losz: number): boolean {
    if (this.base !== loaddr.base) return false;
    if (this.base!.isBigEndian()) {
      const nextoff = this.base!.wrapOffset(this.offset + BigInt(sz));
      return nextoff === loaddr.offset;
    } else {
      const nextoff = this.base!.wrapOffset(loaddr.offset + BigInt(losz));
      return nextoff === this.offset;
    }
  }

  /**
   * If this is (originally) a join address, reevaluate it in terms of its
   * new offset and size, changing the space and offset if necessary.
   */
  renormalize(size: number): void {
    if (this.base!.getType() === (6 as spacetype)) {
      // IPTR_JOIN
      this.base!.getManager()!.renormalizeJoinAddress(this, size);
    }
  }

  // ---- Static comparison functions ----

  /**
   * Three-way comparison. Returns -1, 0, or 1.
   */
  static compare(a: Address, b: Address): -1 | 0 | 1 {
    if (a.equals(b)) return 0;
    return a.lessThan(b) ? -1 : 1;
  }

  /** Factory: create an invalid address. */
  static invalid(): Address {
    return new Address();
  }

  static decode(decoder: Decoder): Address;
  static decode(decoder: Decoder, sizeRef: { val: number }): Address;
  static decode(decoder: Decoder, sizeRef?: { val: number }): Address {
    const vd = new VarnodeData();
    vd.decode(decoder);
    if (sizeRef !== undefined) {
      sizeRef.val = vd.size;
    }
    return new Address(vd.space as any as AddrSpace, vd.offset);
  }
}

// ---------------------------------------------------------------------------
// SeqNum class
// ---------------------------------------------------------------------------

/**
 * A class for uniquely labelling and comparing PcodeOps.
 *
 * Different PcodeOps generated by a single machine instruction can only be
 * labelled with a single Address. A SeqNum extends the address to include:
 *   - A fixed `time` field (uniq) set at creation time for uniqueness.
 *   - An `order` field for execution ordering within a basic block.
 */
export class SeqNum {
  /** Program counter at start of instruction */
  private pc: Address;
  /** Number to guarantee uniqueness */
  private uniq: number;
  /** Number for order comparisons within a block */
  private order: number;

  constructor();
  constructor(ex: MachExtreme);
  constructor(addr: Address, uniq: number);
  constructor(arg0?: Address | MachExtreme, arg1?: number) {
    if (arg0 === undefined) {
      // Invalid sequence number
      this.pc = new Address();
      this.uniq = 0;
      this.order = 0;
    } else if (typeof arg0 === 'number') {
      // MachExtreme
      this.pc = new Address(arg0);
      this.uniq = arg0 === MachExtreme.m_minimal ? 0 : 0xFFFFFFFF;
      this.order = 0;
    } else {
      // Address + uniq
      this.pc = new Address(arg0);
      this.uniq = arg1!;
      this.order = 0;
    }
  }

  /** Get the address portion. */
  getAddr(): Address {
    return this.pc;
  }

  /** Get the time (uniqueness) field. */
  getTime(): number {
    return this.uniq;
  }

  /** Get the order field. */
  getOrder(): number {
    return this.order;
  }

  /** Set the order field. */
  setOrder(ord: number): void {
    this.order = ord;
  }

  /** Compare two sequence numbers for equality (based on uniq). */
  equals(op2: SeqNum): boolean {
    return this.uniq === op2.uniq;
  }

  /**
   * Compare two sequence numbers with natural order.
   * First by address, then by uniq.
   */
  lessThan(op2: SeqNum): boolean {
    if (this.pc.equals(op2.pc)) {
      return this.uniq < op2.uniq;
    }
    return this.pc.lessThan(op2.pc);
  }

  /** Human readable representation: "addr:uniq" */
  toString(): string {
    return `${this.pc.printRaw()}:${this.uniq}`;
  }
}

// ---------------------------------------------------------------------------
// RangeProperties class
// ---------------------------------------------------------------------------

/**
 * A partially parsed description of a Range.
 * Allows <range> tags to be parsed when the address space does not yet exist.
 */
export class RangeProperties {
  spaceName: string = '';
  first: bigint = 0n;
  last: bigint = 0n;
  isRegister: boolean = false;
  seenLast: boolean = false;

  decode(decoder: Decoder): void {
    const elemId = decoder.openElement();
    for (;;) {
      const attribId = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_SPACE.getId()) {
        this.spaceName = decoder.readString();
      } else if (attribId === ATTRIB_FIRST.getId()) {
        this.first = decoder.readUnsignedInteger();
      } else if (attribId === ATTRIB_LAST.getId()) {
        this.last = decoder.readUnsignedInteger();
        this.seenLast = true;
      } else if (attribId === ATTRIB_NAME.getId()) {
        this.spaceName = decoder.readString();
        this.isRegister = true;
      }
    }
    decoder.closeElement(elemId);
  }
}

// ---------------------------------------------------------------------------
// Range class
// ---------------------------------------------------------------------------

/**
 * A contiguous range of bytes in some address space.
 */
export class Range {
  /** Space containing the range */
  spc!: AddrSpace;
  /** Offset of first byte in this Range */
  first!: bigint;
  /** Offset of last byte in this Range */
  last!: bigint;

  constructor();
  constructor(spc: AddrSpace, first: bigint, last: bigint);
  constructor(props: RangeProperties, manage: any);
  constructor(spcOrProps?: AddrSpace | RangeProperties, firstOrManage?: bigint | any, last?: bigint) {
    if (spcOrProps === undefined) {
      // No-arg constructor
    } else if (spcOrProps instanceof RangeProperties) {
      // RangeProperties + AddrSpaceManager constructor
      const props = spcOrProps;
      const manage = firstOrManage;
      if (props.isRegister) {
        const trans = manage.getDefaultCodeSpace().getTrans();
        const point = trans.getRegister(props.spaceName);
        this.spc = point.space as any as AddrSpace;
        this.first = point.offset;
        this.last = (this.first - 1n) + BigInt(point.size);
      } else {
        this.spc = manage.getSpaceByName(props.spaceName) as AddrSpace;
        if (this.spc === null || this.spc === undefined)
          throw new LowlevelError("Undefined space: " + props.spaceName);
        this.first = props.first;
        this.last = props.last;
        if (!props.seenLast) {
          this.last = (this.spc as any).getHighest();
        }
      }
    } else {
      // AddrSpace + first + last constructor
      this.spc = spcOrProps;
      this.first = firstOrManage as bigint;
      this.last = last!;
    }
  }

  /** Get the address space containing this Range. */
  getSpace(): AddrSpace {
    return this.spc;
  }

  /** Get the offset of the first byte. */
  getFirst(): bigint {
    return this.first;
  }

  /** Get the offset of the last byte. */
  getLast(): bigint {
    return this.last;
  }

  /** Get the address of the first byte. */
  getFirstAddr(): Address {
    return new Address(this.spc, this.first);
  }

  /** Get the address of the last byte. */
  getLastAddr(): Address {
    return new Address(this.spc, this.last);
  }

  /** Determine if the address is in this Range. */
  contains(addr: Address): boolean {
    if (this.spc !== addr.getSpace()) return false;
    if (this.first > addr.getOffset()) return false;
    if (this.last < addr.getOffset()) return false;
    return true;
  }

  /**
   * Sorting comparison for Ranges.
   * Compare based on address space index, then the starting offset.
   */
  lessThan(op2: Range): boolean {
    if (this.spc.getIndex() !== op2.spc.getIndex()) {
      return this.spc.getIndex() < op2.spc.getIndex();
    }
    return this.first < op2.first;
  }

  /** Print bounds: "spaceName: first-last" */
  printBounds(): string {
    return `${this.spc.getName()}: ${this.first.toString(16)}-${this.last.toString(16)}`;
  }

  decode(decoder: Decoder): void {
    const elemId = decoder.openElement();
    this.decodeFromAttributes(decoder);
    decoder.closeElement(elemId);
  }

  decodeFromAttributes(decoder: Decoder): void {
    this.spc = undefined as any;
    let seenLast = false;
    this.first = 0n;
    this.last = 0n;
    for (;;) {
      const attribId = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_SPACE.getId()) {
        this.spc = decoder.readSpace() as any as AddrSpace;
      } else if (attribId === ATTRIB_FIRST.getId()) {
        this.first = decoder.readUnsignedInteger();
      } else if (attribId === ATTRIB_LAST.getId()) {
        this.last = decoder.readUnsignedInteger();
        seenLast = true;
      } else if (attribId === ATTRIB_NAME.getId()) {
        const mgr: any = decoder.getAddrSpaceManager();
        const trans = mgr.getDefaultCodeSpace().getTrans();
        const point = trans.getRegister(decoder.readString());
        this.spc = point.space!;
        this.first = point.offset;
        this.last = (this.first - 1n) + BigInt(point.size);
        return;
      }
    }
    if (this.spc === undefined || this.spc === null) {
      throw new LowlevelError("No address space indicated in range tag");
    }
    if (!seenLast) {
      this.last = (this.spc as any).getHighest();
    }
  }
}

// ---------------------------------------------------------------------------
// RangeList class
// ---------------------------------------------------------------------------

/**
 * A disjoint set of Ranges, possibly across multiple address spaces.
 *
 * Maintains a sorted list of non-overlapping Range objects.
 * Ranges can be inserted and removed; overlapping/adjacent ranges are merged.
 *
 * Internally uses a sorted array. The sort key is (space index, first offset).
 */
export class RangeList {
  /** Sorted array of Range objects (by space index, then first offset). */
  private tree: Range[] = [];

  constructor();
  constructor(op2: RangeList);
  constructor(op2?: RangeList) {
    if (op2 !== undefined) {
      this.tree = op2.tree.map(
        (r) => new Range(r.spc, r.first, r.last),
      );
    }
  }

  /** Clear this container to empty. */
  clear(): void {
    this.tree.length = 0;
  }

  /** Return true if this container is empty. */
  empty(): boolean {
    return this.tree.length === 0;
  }

  /** Return the number of Range objects in the container. */
  numRanges(): number {
    return this.tree.length;
  }

  /** Get an iterator (array) of all ranges, for external iteration. */
  getRanges(): readonly Range[] {
    return this.tree;
  }

  /** Get the first contiguous range, or null if empty. */
  getFirstRange(): Range | null {
    if (this.tree.length === 0) return null;
    return this.tree[0];
  }

  /** Get the last contiguous range, or null if empty. */
  getLastRange(): Range | null {
    if (this.tree.length === 0) return null;
    return this.tree[this.tree.length - 1];
  }

  /**
   * Get the last Range viewing offsets as signed within the given space.
   * Offsets with their high-bit set come before offsets with a clear high-bit.
   */
  getLastSignedRange(spaceid: AddrSpace): Range | null {
    const midway = spaceid.getHighest() / 2n; // maximal signed value
    // Find the last range whose first <= midway in the given space
    let result: Range | null = null;

    // Search for positive ranges (first <= midway)
    for (let i = this.tree.length - 1; i >= 0; i--) {
      const r = this.tree[i];
      if (r.spc !== spaceid) continue;
      if (r.first <= midway) {
        result = r;
        break;
      }
    }

    if (result !== null) return result;

    // If no positive ranges found, search for biggest negative range
    for (let i = this.tree.length - 1; i >= 0; i--) {
      const r = this.tree[i];
      if (r.spc !== spaceid) continue;
      return r; // last range in the space
    }

    return null;
  }

  /**
   * Get the Range containing the given byte, or null.
   */
  getRange(spaceid: AddrSpace, offset: bigint): Range | null {
    if (this.tree.length === 0) return null;

    // Find the last range with range.first <= offset in the given space
    // Binary search: find upper_bound (first > offset), then step back
    const idx = this._upperBound(spaceid, offset);
    if (idx === 0) return null;
    const r = this.tree[idx - 1];
    if (r.spc !== spaceid) return null;
    if (r.last >= offset) return r;
    return null;
  }

  /**
   * Insert a range of addresses, merging overlapping/adjacent ranges.
   */
  insertRange(spc: AddrSpace, first: bigint, last: bigint): void {
    // Find all ranges that overlap or are adjacent to [first, last]
    let newFirst = first;
    let newLast = last;

    // Find iter1: first range whose last >= first in the same space
    const ub1 = this._upperBound(spc, first);
    let i1 = ub1;
    if (i1 > 0) {
      i1--;
      if (this.tree[i1].spc !== spc || this.tree[i1].last < first) {
        i1++;
      }
    }

    // Find iter2: first range whose first > last in the same space
    const i2 = this._upperBound(spc, last);

    // Merge with all overlapping ranges
    for (let i = i1; i < i2; i++) {
      if (this.tree[i].first < newFirst) newFirst = this.tree[i].first;
      if (this.tree[i].last > newLast) newLast = this.tree[i].last;
    }

    // Remove overlapping ranges and insert the merged range
    this.tree.splice(i1, i2 - i1, new Range(spc, newFirst, newLast));
  }

  /**
   * Remove a range of addresses, splitting/narrowing existing ranges as needed.
   */
  removeRange(spc: AddrSpace, first: bigint, last: bigint): void {
    if (this.tree.length === 0) return;

    // Find iter1: first range whose last >= first in the same space
    const ub1 = this._upperBound(spc, first);
    let i1 = ub1;
    if (i1 > 0) {
      i1--;
      if (this.tree[i1].spc !== spc || this.tree[i1].last < first) {
        i1++;
      }
    }

    // Find iter2: first range whose first > last
    const i2 = this._upperBound(spc, last);

    // Collect replacement ranges
    const replacements: Range[] = [];
    for (let i = i1; i < i2; i++) {
      const a = this.tree[i].first;
      const b = this.tree[i].last;
      if (a < first) {
        replacements.push(new Range(spc, a, first - 1n));
      }
      if (b > last) {
        replacements.push(new Range(spc, last + 1n, b));
      }
    }

    this.tree.splice(i1, i2 - i1, ...replacements);
  }

  /**
   * Merge another RangeList into this one.
   */
  merge(op2: RangeList): void {
    for (const range of op2.tree) {
      this.insertRange(range.spc, range.first, range.last);
    }
  }

  /**
   * Check whether the address range [addr, addr+size) is fully contained
   * in this RangeList.
   */
  inRange(addr: Address, size: number): boolean {
    if (addr.isInvalid()) return true; // Don't care about invalid
    if (this.tree.length === 0) return false;

    const spc = addr.getSpace()!;
    const offset = addr.getOffset();

    const idx = this._upperBound(spc, offset);
    if (idx === 0) return false;
    const r = this.tree[idx - 1];
    if (r.spc !== spc) return false;
    if (r.last >= offset + BigInt(size) - 1n) return true;
    return false;
  }

  /**
   * Return the size of the biggest contiguous sequence of addresses
   * in this RangeList which contain the given address.
   */
  longestFit(addr: Address, maxsize: bigint): bigint {
    if (addr.isInvalid()) return 0n;
    if (this.tree.length === 0) return 0n;

    const spc = addr.getSpace()!;
    let offset = addr.getOffset();

    const startIdx = this._upperBound(spc, offset);
    if (startIdx === 0) return 0n;

    let idx = startIdx - 1;
    let sizeres = 0n;

    if (this.tree[idx].last < offset) return 0n;

    while (idx < this.tree.length) {
      const r = this.tree[idx];
      if (r.spc !== spc) break;
      if (r.first > offset) break;
      sizeres += r.last + 1n - offset;
      offset = r.last + 1n;
      if (sizeres >= maxsize) break;
      idx++;
    }
    return sizeres;
  }

  /**
   * Print a description of all ranges.
   */
  printBounds(): string {
    if (this.tree.length === 0) return 'all';
    return this.tree.map((r) => r.printBounds()).join('\n');
  }

  decode(decoder: Decoder): void {
    const elemId = decoder.openElement();
    while (decoder.peekElement() !== 0) {
      const range = new Range();
      range.decode(decoder);
      this.insertRange(range.spc, range.first, range.last);
    }
    decoder.closeElement(elemId);
  }

  // ---- Private helpers ----

  /**
   * Binary search: find the index of the first Range in tree whose
   * (space index, first offset) is strictly greater than (spc, offset).
   * This emulates C++ `std::set::upper_bound`.
   */
  private _upperBound(spc: AddrSpace, offset: bigint): number {
    const spcIndex = typeof spc.getIndex === 'function' ? spc.getIndex() : (typeof (spc as any).index === 'number' ? (spc as any).index : -1);
    if (spcIndex < 0) return 0;
    let lo = 0;
    let hi = this.tree.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      const r = this.tree[mid];
      const rIndex = typeof r.spc.getIndex === 'function' ? r.spc.getIndex() : -2;
      if (rIndex < spcIndex || (rIndex === spcIndex && r.first <= offset)) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    return lo;
  }
}
