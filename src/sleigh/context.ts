/**
 * @file context.ts
 * @description SLEIGH-specific context classes for instruction decoding.
 *
 * Translated from Ghidra's context.hh / context.cc.
 *
 * This module deals with context changes during SLEIGH instruction decoding,
 * including Token, FixedHandle, ConstructState, ParserContext, ParserWalker,
 * and ParserWalkerChange. This is separate from the core globalcontext.ts
 * which provides the general ContextDatabase infrastructure.
 */

import { Address } from '../core/address.js';
import { AddrSpace } from '../core/space.js';
import { ContextCache } from '../core/globalcontext.js';
import { LowlevelError } from '../core/error.js';
import { BadDataError } from '../core/translate.js';
import type { int4, uint4, uintb, uintm } from '../core/types.js';

// Forward declarations for types from not-yet-written SLEIGH files
type Constructor = any;
type TripleSymbol = any;
type OperandSymbol = any;
type SleighSymbol = any;
type Translate = any;

// ---------------------------------------------------------------------------
// SleighError
// ---------------------------------------------------------------------------

/**
 * An error specific to the SLEIGH subsystem.
 */
export class SleighError extends LowlevelError {
  constructor(s: string) {
    super(s);
    this.name = 'SleighError';
  }
}

// ---------------------------------------------------------------------------
// Token
// ---------------------------------------------------------------------------

/**
 * A multiple-byte sized chunk of pattern in a bitstream.
 */
export class Token {
  private name: string;
  private size: int4;       // Number of bytes in token
  private index: int4;      // Index of this token, for resolving offsets
  private bigendian: boolean;

  constructor(nm: string, sz: int4, be: boolean, ind: int4) {
    this.name = nm;
    this.size = sz;
    this.bigendian = be;
    this.index = ind;
  }

  getSize(): int4 {
    return this.size;
  }

  isBigEndian(): boolean {
    return this.bigendian;
  }

  getIndex(): int4 {
    return this.index;
  }

  getName(): string {
    return this.name;
  }
}

// ---------------------------------------------------------------------------
// FixedHandle
// ---------------------------------------------------------------------------

/**
 * A handle that is fully resolved.
 */
export class FixedHandle {
  space: AddrSpace | null = null;
  size: uint4 = 0;
  offset_space: AddrSpace | null = null;   // Either null or where dynamic offset is stored
  offset_offset: uintb = 0n;               // Either static offset or ptr offset
  offset_size: uint4 = 0;                  // Size of pointer
  temp_space: AddrSpace | null = null;     // Consistent temporary location for value
  temp_offset: uintb = 0n;
}

// ---------------------------------------------------------------------------
// ConstructState
// ---------------------------------------------------------------------------

/**
 * State associated with a single Constructor in the parse tree.
 */
export class ConstructState {
  ct: Constructor | null = null;
  hand: FixedHandle = new FixedHandle();
  resolve: (ConstructState | null)[] = [];
  parent: ConstructState | null = null;
  length: int4 = 0;        // Length of this instantiation of the constructor
  offset: uint4 = 0;       // Absolute offset (from start of instruction)
}

// ---------------------------------------------------------------------------
// ContextSet
// ---------------------------------------------------------------------------

/**
 * Instructions for setting a global context value.
 */
export class ContextSet {
  sym: TripleSymbol | null = null;         // Resolves to address where setting takes effect
  point: ConstructState | null = null;     // Point at which context set was made
  num: int4 = 0;                           // Number of context word affected
  mask: uintm = 0;                         // Bits within word affected
  value: uintm = 0;                        // New setting for bits
  flow: boolean = false;                   // Does the new context flow from its set point
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** sizeof(uintm) in C++ is 4 (uint32_t) */
const SIZEOF_UINTM = 4;

// SleighSymbol type enum value for operand_symbol
const SLEIGH_OPERAND_SYMBOL = 8; // operand_symbol in enum symbol_type

// ---------------------------------------------------------------------------
// ParserContext
// ---------------------------------------------------------------------------

/**
 * Context for parsing a single instruction.
 *
 * Holds state during SLEIGH instruction decoding, including the instruction
 * bytes buffer, local context array, commit list, and the tree of ConstructStates.
 */
export class ParserContext {
  // Possible states of the ParserContext
  static readonly uninitialized = 0;
  static readonly disassembly = 1;
  static readonly pcode = 2;

  // Fields accessible by ParserWalker/ParserWalkerChange (public with underscore prefix)
  _translate: Translate | null;
  _parsestate: int4;
  _const_space: AddrSpace | null = null;
  _buf: Uint8Array = new Uint8Array(16);   // Buffer of bytes in the instruction stream
  _context: number[] = [];                  // Local context (array of uint32 words)
  _contextsize: int4;                       // Number of entries in context array
  _contcache: ContextCache | null;          // Interface for getting/setting context
  _contextcommit: ContextSet[] = [];
  _addr: Address = new Address();           // Address of start of instruction
  _naddr: Address = new Address();          // Address of next instruction
  _n2addr: Address = new Address();         // Address of instruction after the next
  _calladdr: Address = new Address();       // For injections, address of the call being overridden
  _state: ConstructState[] = [];            // Current resolved instruction
  _base_state: ConstructState | null = null;
  _alloc: int4 = 0;                         // Number of ConstructState's allocated
  _delayslot: int4 = 0;                     // delayslot depth

  constructor(ccache: ContextCache | null, trans: Translate | null) {
    this._parsestate = ParserContext.uninitialized;
    this._contcache = ccache;
    this._translate = trans;
    if (ccache !== null) {
      this._contextsize = ccache.getDatabase().getContextSize();
      this._context = new Array(this._contextsize).fill(0);
    } else {
      this._contextsize = 0;
      this._context = [];
    }
  }

  getBuffer(): Uint8Array {
    return this._buf;
  }

  initialize(maxstate: int4, maxparam: int4, spc: AddrSpace): void {
    this._const_space = spc;
    this._state = [];
    for (let i = 0; i < maxstate; ++i) {
      const cs = new ConstructState();
      cs.resolve = new Array(maxparam).fill(null);
      this._state.push(cs);
    }
    this._state[0].parent = null;
    this._base_state = this._state[0];
  }

  getParserState(): int4 {
    return this._parsestate;
  }

  setParserState(st: int4): void {
    this._parsestate = st;
  }

  deallocateState(walker: ParserWalkerChange): void {
    this._alloc = 1;
    walker._context = this;
    walker.baseState();
  }

  allocateOperand(i: int4, walker: ParserWalkerChange): void {
    const opstate = this._state[this._alloc++];
    opstate.parent = walker._point;
    opstate.ct = null;
    walker._point!.resolve[i] = opstate;
    walker._breadcrumb[walker._depth++] += 1;
    walker._point = opstate;
    walker._breadcrumb[walker._depth] = 0;
  }

  setAddr(ad: Address): void {
    this._addr = ad;
    this._n2addr = new Address();
  }

  setNaddr(ad: Address): void {
    this._naddr = ad;
  }

  setCalladdr(ad: Address): void {
    this._calladdr = ad;
  }

  addCommit(sym: TripleSymbol, num: int4, mask: uintm, flow: boolean, point: ConstructState): void {
    const set = new ContextSet();
    set.sym = sym;
    set.point = point;
    set.num = num;
    set.mask = mask;
    set.value = this._context[num] & mask;
    set.flow = flow;
    this._contextcommit.push(set);
  }

  clearCommits(): void {
    this._contextcommit.length = 0;
  }

  applyCommits(): void {
    if (this._contextcommit.length === 0) return;
    const walker = new ParserWalker(this);
    walker.baseState();

    for (let idx = 0; idx < this._contextcommit.length; ++idx) {
      const cset = this._contextcommit[idx];
      const sym: TripleSymbol = cset.sym;
      let commitaddr: Address;
      if ((sym as SleighSymbol).getType() === SLEIGH_OPERAND_SYMBOL) {
        // The value for an OperandSymbol is probably already
        // calculated, we just need to find the right tree node of the state
        const i: int4 = (sym as OperandSymbol).getIndex();
        const h: FixedHandle = cset.point!.resolve[i]!.hand;
        commitaddr = new Address(h.space!, h.offset_offset);
      } else {
        const hand = new FixedHandle();
        (sym as any).getFixedHandle(hand, walker);
        commitaddr = new Address(hand.space!, hand.offset_offset);
      }
      if (commitaddr.isConstant()) {
        // If the symbol handed to globalset was a computed value, the getFixedHandle
        // calculation will return a value in the constant space. If this is the case,
        // we explicitly convert the offset into the current address space
        const newoff: uintb = AddrSpace.addressToByte(
          commitaddr.getOffset(),
          this._addr.getSpace()!.getWordSize()
        );
        commitaddr = new Address(this._addr.getSpace()!, newoff);
      }

      // Commit context change
      if (cset.flow) {
        // The context flows
        this._contcache!.setContext(commitaddr, cset.num, cset.mask, cset.value);
      } else {
        // Set the context so that it doesn't flow
        const nextaddr = commitaddr.add(1n);
        if (nextaddr.getOffset() < commitaddr.getOffset()) {
          this._contcache!.setContext(commitaddr, cset.num, cset.mask, cset.value);
        } else {
          this._contcache!.setContext(commitaddr, nextaddr, cset.num, cset.mask, cset.value);
        }
      }
    }
  }

  getAddr(): Address {
    return this._addr;
  }

  getNaddr(): Address {
    return this._naddr;
  }

  getN2addr(): Address {
    if (this._n2addr.isInvalid()) {
      if (this._translate === null || this._parsestate === ParserContext.uninitialized) {
        throw new LowlevelError('inst_next2 not available in this context');
      }
      const length: int4 = (this._translate as any).instructionLength(this._naddr);
      this._n2addr = this._naddr.add(BigInt(length));
    }
    return this._n2addr;
  }

  getDestAddr(): Address {
    return this._calladdr;
  }

  getRefAddr(): Address {
    return this._calladdr;
  }

  getCurSpace(): AddrSpace | null {
    return this._addr.getSpace();
  }

  getConstSpace(): AddrSpace | null {
    return this._const_space;
  }

  /**
   * Get bytes from the instruction stream into a number (assuming big endian format).
   *
   * @param byteoff - starting byte offset within the token
   * @param numbytes - number of bytes to read
   * @param off - absolute offset from start of instruction
   */
  getInstructionBytes(byteoff: int4, numbytes: int4, off: uint4): uintm {
    off += byteoff;
    if (off >= 16) {
      throw new BadDataError('Instruction is using more than 16 bytes');
    }
    let res = 0;
    for (let i = 0; i < numbytes; ++i) {
      res = ((res << 8) | this._buf[off + i]) >>> 0;
    }
    return res;
  }

  /**
   * Get bits from the instruction stream.
   */
  getInstructionBits(startbit: int4, size: int4, off: uint4): uintm {
    off += Math.floor(startbit / 8);
    if (off >= 16) {
      throw new BadDataError('Instruction is using more than 16 bytes');
    }
    startbit = startbit % 8;
    const bytesize = Math.floor((startbit + size - 1) / 8) + 1;
    let res = 0;
    for (let i = 0; i < bytesize; ++i) {
      res = ((res << 8) | this._buf[off + i]) >>> 0;
    }
    // Move starting bit to highest position: shift left by (8*(sizeof(uintm)-bytesize) + startbit)
    // sizeof(uintm) = 4
    const leftShift = 8 * (SIZEOF_UINTM - bytesize) + startbit;
    res = (res << leftShift) >>> 0;
    // Shift to bottom of uintm: shift right by (8*sizeof(uintm) - size)
    const rightShift = 8 * SIZEOF_UINTM - size;
    res = res >>> rightShift;
    return res;
  }

  /**
   * Get bytes from context into a number.
   */
  getContextBytes(bytestart: int4, size: int4): uintm {
    const intstart = Math.floor(bytestart / SIZEOF_UINTM);
    let res = this._context[intstart] >>> 0;
    const byteOffset = bytestart % SIZEOF_UINTM;
    const unusedBytes = SIZEOF_UINTM - size;
    res = (res << (byteOffset * 8)) >>> 0;
    res = res >>> (unusedBytes * 8);
    let remaining = size - SIZEOF_UINTM + byteOffset;
    if (remaining > 0 && (intstart + 1) < this._contextsize) {
      let res2 = this._context[intstart + 1] >>> 0;
      const unusedBytes2 = SIZEOF_UINTM - remaining;
      res2 = res2 >>> (unusedBytes2 * 8);
      res = (res | res2) >>> 0;
    }
    return res;
  }

  /**
   * Get bits from context.
   */
  getContextBits(startbit: int4, size: int4): uintm {
    const intstart = Math.floor(startbit / (8 * SIZEOF_UINTM));
    let res = this._context[intstart] >>> 0;  // Get uintm containing highest bit
    const bitOffset = startbit % (8 * SIZEOF_UINTM);
    const unusedBits = 8 * SIZEOF_UINTM - size;
    res = (res << bitOffset) >>> 0;   // Shift startbit to highest position
    res = res >>> unusedBits;
    let remaining = size - 8 * SIZEOF_UINTM + bitOffset;
    if (remaining > 0 && (intstart + 1) < this._contextsize) {
      let res2 = this._context[intstart + 1] >>> 0;
      const unusedBits2 = 8 * SIZEOF_UINTM - remaining;
      res2 = res2 >>> unusedBits2;
      res = (res | res2) >>> 0;
    }
    return res;
  }

  setContextWord(i: int4, val: uintm, mask: uintm): void {
    this._context[i] = ((this._context[i] & (~mask)) | (mask & val)) | 0;
  }

  loadContext(): void {
    this._contcache!.getContext(this._addr, this._context);
  }

  getLength(): int4 {
    return this._base_state!.length;
  }

  setDelaySlot(val: int4): void {
    this._delayslot = val;
  }

  getDelaySlot(): int4 {
    return this._delayslot;
  }
}

// ---------------------------------------------------------------------------
// ParserWalker
// ---------------------------------------------------------------------------

/**
 * A class for walking the ParserContext tree.
 */
export class ParserWalker {
  private _const_context: ParserContext;
  private _cross_context: ParserContext | null;
  _point: ConstructState | null = null;  // The current node being visited
  _depth: int4 = 0;                       // Depth of the current node
  _breadcrumb: number[] = new Array(32).fill(0); // Path of operands from root

  constructor(c: ParserContext, cross?: ParserContext) {
    this._const_context = c;
    this._cross_context = cross ?? null;
  }

  getParserContext(): ParserContext {
    return this._const_context;
  }

  baseState(): void {
    this._point = this._const_context._base_state;
    this._depth = 0;
    this._breadcrumb[0] = 0;
  }

  setOutOfBandState(
    ct: Constructor,
    index: int4,
    tempstate: ConstructState,
    otherwalker: ParserWalker
  ): void {
    // Initialize walker for future calls into getInstructionBytes
    // assuming ct is the current position in the walk
    let pt: ConstructState | null = otherwalker._point;
    let curdepth = otherwalker._depth;
    while (pt !== null && pt.ct !== ct) {
      if (curdepth <= 0) return;
      curdepth -= 1;
      pt = pt.parent;
    }
    if (pt === null) return;

    const sym: OperandSymbol = (ct as any).getOperand(index);
    const i: int4 = (sym as any).getOffsetBase();
    // if i<0, i.e. the offset of the operand is constructor relative
    // its possible that the branch corresponding to the operand
    // has not been constructed yet. Context expressions are
    // evaluated BEFORE the constructors branches are created.
    // So we have to construct the offset explicitly.
    if (i < 0) {
      tempstate.offset = pt.offset + (sym as any).getRelativeOffset();
    } else {
      tempstate.offset = pt.resolve[index]!.offset;
    }

    tempstate.ct = ct;
    tempstate.length = pt.length;
    this._point = tempstate;
    this._depth = 0;
    this._breadcrumb[0] = 0;
  }

  isState(): boolean {
    return this._point !== null;
  }

  pushOperand(i: int4): void {
    this._breadcrumb[this._depth++] = i + 1;
    this._point = this._point!.resolve[i]!;
    this._breadcrumb[this._depth] = 0;
  }

  popOperand(): void {
    this._point = this._point!.parent;
    this._depth -= 1;
  }

  getOffset(i: int4): uint4 {
    if (i < 0) return this._point!.offset;
    const op = this._point!.resolve[i]!;
    return op.offset + op.length;
  }

  getConstructor(): Constructor {
    return this._point!.ct;
  }

  getOperand(): int4 {
    return this._breadcrumb[this._depth];
  }

  getParentHandle(): FixedHandle {
    return this._point!.hand;
  }

  getFixedHandle(i: int4): FixedHandle {
    return this._point!.resolve[i]!.hand;
  }

  getCurSpace(): AddrSpace | null {
    return this._const_context.getCurSpace();
  }

  getConstSpace(): AddrSpace | null {
    return this._const_context.getConstSpace();
  }

  getAddr(): Address {
    if (this._cross_context !== null) {
      return this._cross_context.getAddr();
    }
    return this._const_context.getAddr();
  }

  getNaddr(): Address {
    if (this._cross_context !== null) {
      return this._cross_context.getNaddr();
    }
    return this._const_context.getNaddr();
  }

  getN2addr(): Address {
    if (this._cross_context !== null) {
      return this._cross_context.getN2addr();
    }
    return this._const_context.getN2addr();
  }

  getRefAddr(): Address {
    if (this._cross_context !== null) {
      return this._cross_context.getRefAddr();
    }
    return this._const_context.getRefAddr();
  }

  getDestAddr(): Address {
    if (this._cross_context !== null) {
      return this._cross_context.getDestAddr();
    }
    return this._const_context.getDestAddr();
  }

  getLength(): int4 {
    return this._const_context.getLength();
  }

  getInstructionBytes(byteoff: int4, numbytes: int4): uintm {
    return this._const_context.getInstructionBytes(byteoff, numbytes, this._point!.offset);
  }

  getContextBytes(byteoff: int4, numbytes: int4): uintm {
    return this._const_context.getContextBytes(byteoff, numbytes);
  }

  getInstructionBits(startbit: int4, size: int4): uintm {
    return this._const_context.getInstructionBits(startbit, size, this._point!.offset);
  }

  getContextBits(startbit: int4, size: int4): uintm {
    return this._const_context.getContextBits(startbit, size);
  }
}

// ---------------------------------------------------------------------------
// ParserWalkerChange
// ---------------------------------------------------------------------------

/**
 * Extension to walker that allows for on-the-fly modifications to the parse tree.
 */
export class ParserWalkerChange extends ParserWalker {
  _context: ParserContext;

  constructor(c: ParserContext) {
    super(c);
    this._context = c;
  }

  override getParserContext(): ParserContext {
    return this._context;
  }

  getPoint(): ConstructState | null {
    return this._point;
  }

  setOffset(off: uint4): void {
    this._point!.offset = off;
  }

  setConstructor(c: Constructor): void {
    this._point!.ct = c;
  }

  setCurrentLength(len: int4): void {
    this._point!.length = len;
  }

  /**
   * Calculate the length of the current constructor state
   * assuming all its operands are constructed.
   */
  calcCurrentLength(length: int4, numopers: int4): void {
    length += this._point!.offset; // Convert relative length to absolute length
    for (let i = 0; i < numopers; ++i) {
      const subpoint = this._point!.resolve[i]!;
      const sublength = subpoint.length + subpoint.offset;
      // Since subpoint.offset is an absolute offset
      // (relative to beginning of instruction), sublength
      // is absolute and must be compared to absolute length
      if (sublength > length) {
        length = sublength;
      }
    }
    this._point!.length = length - this._point!.offset; // Convert back to relative length
  }
}
