/**
 * @file pcoderaw.ts
 * @description Raw descriptions of varnodes and p-code ops, translated from pcoderaw.hh/cc
 */

import type { int4, uint4, uintb, uintm } from './types.js';
import { OpCode } from './opcodes.js';
import type { OpBehavior } from './opbehavior.js';
import { ATTRIB_NAME, ATTRIB_SPACE } from './marshal.js';
import type { Decoder } from './marshal.js';

// Forward declarations - these types will be properly imported later
// For now we use minimal interfaces
export interface AddrSpace {
  getIndex(): int4;
  getName(): string;
  getType(): int4;
}

/**
 * A low-level machine address (space + offset pair).
 * This is a simplified version used by pcoderaw; the full Address is in address.ts.
 */
export class Address {
  base: AddrSpace | null;
  offset: uintb;

  constructor(space?: AddrSpace | null, off?: uintb) {
    this.base = space ?? null;
    this.offset = off ?? 0n;
  }

  getSpace(): AddrSpace | null {
    return this.base;
  }

  getOffset(): uintb {
    return this.offset;
  }

  isInvalid(): boolean {
    return this.base === null;
  }

  /** Is this a constant value? */
  isConstant(): boolean {
    if (this.base === null) return false;
    return (this.base as any).getType() === 0; // IPTR_CONSTANT
  }

  /** Is this a join value? */
  isJoin(): boolean {
    if (this.base === null) return false;
    return (this.base as any).getType() === 6; // IPTR_JOIN
  }

  /** Add an offset to this address */
  add(off: bigint): Address {
    return new Address(this.base, this.offset + off);
  }

  /** Create an invalid address */
  static invalid(): Address {
    return new Address();
  }

  equals(other: Address): boolean {
    return this.base === other.base && this.offset === other.offset;
  }

  lessThan(other: Address): boolean {
    if (this.base !== other.base) {
      if (this.base === null) return true;
      if (other.base === null) return false;
      // Guard against sentinel objects that don't implement the full AddrSpace interface
      const thisIndex = typeof this.base.getIndex === 'function' ? this.base.getIndex() : -1;
      const otherIndex = typeof other.base.getIndex === 'function' ? other.base.getIndex() : -1;
      return thisIndex < otherIndex;
    }
    return this.offset < other.offset;
  }
}

/**
 * A class for uniquely labelling and comparing PcodeOps.
 */
export class SeqNum {
  pc: Address;
  uniq: uintm;
  order: uintm;

  constructor(addr?: Address, b?: uintm) {
    this.pc = addr ?? new Address();
    this.uniq = b ?? 0;
    this.order = 0;
  }

  getAddr(): Address {
    return this.pc;
  }

  getTime(): uintm {
    return this.uniq;
  }

  getOrder(): uintm {
    return this.order;
  }

  setOrder(ord: uintm): void {
    this.order = ord;
  }

  equals(other: SeqNum): boolean {
    return this.uniq === other.uniq;
  }

  lessThan(other: SeqNum): boolean {
    if (this.pc.equals(other.pc)) {
      return this.uniq < other.uniq;
    }
    return this.pc.lessThan(other.pc);
  }
}

/**
 * Data defining a specific memory location.
 *
 * Within the decompiler's model of a processor, any register,
 * memory location, or other variable can always be represented
 * as an address space, an offset within the space, and the
 * size of the sequence of bytes.
 */
export class VarnodeData {
  space: AddrSpace | null;
  offset: uintb;
  size: uint4;

  constructor(space?: AddrSpace | null, offset?: uintb, size?: uint4) {
    this.space = space ?? null;
    this.offset = offset ?? 0n;
    this.size = size ?? 0;
  }

  /** Get the location as an address */
  getAddr(): Address {
    return new Address(this.space, this.offset);
  }

  /**
   * VarnodeData can be sorted by space index, then offset, then size (BIG first).
   */
  lessThan(op2: VarnodeData): boolean {
    if (this.space !== op2.space) {
      return (this.space?.getIndex() ?? -1) < (op2.space?.getIndex() ?? -1);
    }
    if (this.offset !== op2.offset) return this.offset < op2.offset;
    return this.size > op2.size; // BIG sizes come first
  }

  /** Compare two VarnodeData for sorting. Returns -1, 0, or 1. */
  static compare(a: VarnodeData, b: VarnodeData): number {
    if (a.lessThan(b)) return -1;
    if (b.lessThan(a)) return 1;
    return 0;
  }

  equals(op2: VarnodeData): boolean {
    return this.space === op2.space &&
           this.offset === op2.offset &&
           this.size === op2.size;
  }

  notEquals(op2: VarnodeData): boolean {
    return !this.equals(op2);
  }

  /** Does this container contain another VarnodeData? */
  contains(op2: VarnodeData): boolean {
    if (this.space !== op2.space) return false;
    if (op2.offset < this.offset) return false;
    if (op2.offset + BigInt(op2.size) > this.offset + BigInt(this.size)) return false;
    return true;
  }

  /** Is this contiguous (as the most significant piece) with the given VarnodeData? */
  isContiguous(lo: VarnodeData): boolean {
    if (this.space !== lo.space) return false;
    return (lo.offset + BigInt(lo.size) === this.offset);
  }

  decode(decoder: Decoder): void {
    const elemId = decoder.openElement();
    this.decodeFromAttributes(decoder);
    decoder.closeElement(elemId);
  }

  decodeFromAttributes(decoder: Decoder): void {
    this.space = null;
    this.size = 0;
    for (;;) {
      const attribId = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_SPACE.getId()) {
        this.space = decoder.readSpace() as any;
        decoder.rewindAttributes();
        const sizeRef = { val: this.size };
        this.offset = (this.space as any).decodeAttributes_sized(decoder, sizeRef);
        this.size = sizeRef.val;
        break;
      } else if (attribId === ATTRIB_NAME.getId()) {
        const mgr: any = decoder.getAddrSpaceManager();
        const trans = mgr.getDefaultCodeSpace().getTrans();
        const point: VarnodeData = trans.getRegister(decoder.readString());
        this.space = point.space;
        this.offset = point.offset;
        this.size = point.size;
        break;
      }
    }
  }
}

/**
 * A low-level representation of a single pcode operation.
 *
 * This is just the minimum amount of data to represent a pcode operation:
 * an opcode, sequence number, optional output varnode, and input varnodes.
 */
export class PcodeOpRaw {
  private behave: OpBehavior | null = null;
  private seq: SeqNum = new SeqNum();
  private out: VarnodeData | null = null;
  private _in: VarnodeData[] = [];

  /** Set the opcode behavior for this op */
  setBehavior(be: OpBehavior): void {
    this.behave = be;
  }

  /** Retrieve the behavior for this op */
  getBehavior(): OpBehavior | null {
    return this.behave;
  }

  /** Get the opcode for this op */
  getOpcode(): OpCode {
    return this.behave!.getOpcode();
  }

  /** Set the sequence number */
  setSeqNum(a: Address, b: uintm): void {
    this.seq = new SeqNum(a, b);
  }

  /** Retrieve the sequence number */
  getSeqNum(): SeqNum {
    return this.seq;
  }

  /** Get address of this operation */
  getAddr(): Address {
    return this.seq.getAddr();
  }

  /** Set the output varnode */
  setOutput(o: VarnodeData | null): void {
    this.out = o;
  }

  /** Retrieve the output varnode */
  getOutput(): VarnodeData | null {
    return this.out;
  }

  /** Add an additional input varnode */
  addInput(i: VarnodeData): void {
    this._in.push(i);
  }

  /** Remove all input varnodes */
  clearInputs(): void {
    this._in.length = 0;
  }

  /** Get the number of input varnodes */
  numInput(): int4 {
    return this._in.length;
  }

  /** Get the i-th input varnode */
  getInput(i: int4): VarnodeData {
    return this._in[i];
  }
}
