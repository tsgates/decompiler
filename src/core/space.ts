/**
 * @file space.ts
 * @description Classes for describing address spaces, translated from Ghidra's space.hh/space.cc
 *
 * Every address space is a region where processor data is stored.
 * An integer offset paired with an AddrSpace forms an address.
 */

import { int4, uint4, uintb, intb, uintm, HOST_ENDIAN } from './types.js';
import { LowlevelError } from './error.js';
import { AttributeId } from './marshal.js';

// ---- Forward reference types (will be properly typed later) ----

/** Forward reference for AddrSpaceManager */
type AddrSpaceManager = any;
/** Forward reference for Translate */
type Translate = any;
/** Forward reference for Encoder */
type Encoder = any;
/** Forward reference for Decoder */
type Decoder = any;
/** Forward reference for JoinRecord */
type JoinRecord = any;
/** Forward reference for VarnodeData */
type VarnodeData = any;

// ---- Attribute IDs ----

export const ATTRIB_BASE = new AttributeId('base', 89);
export const ATTRIB_DEADCODEDELAY = new AttributeId('deadcodedelay', 90);
export const ATTRIB_DELAY = new AttributeId('delay', 91);
export const ATTRIB_LOGICALSIZE = new AttributeId('logicalsize', 92);
export const ATTRIB_PHYSICAL = new AttributeId('physical', 93);
export const ATTRIB_PIECE = new AttributeId('piece', 94);

// ---- Helper functions ----

/**
 * Calculate a bitmask for the given byte size.
 * For sizes >= 8, returns 0xFFFFFFFFFFFFFFFF (full 64-bit mask).
 */
function calc_mask(size: number): bigint {
  if (size >= 8) return 0xFFFFFFFFFFFFFFFFn;
  return (1n << BigInt(size * 8)) - 1n;
}

// ---- spacetype enum ----

/**
 * Fundamental address space types.
 * Every address space must be one of these core types.
 */
export enum spacetype {
  /** Special space to represent constants */
  IPTR_CONSTANT = 0,
  /** Normal spaces modelled by processor */
  IPTR_PROCESSOR = 1,
  /** Addresses are offsets off of a base register */
  IPTR_SPACEBASE = 2,
  /** Internally managed temporary space */
  IPTR_INTERNAL = 3,
  /** Special internal FuncCallSpecs reference */
  IPTR_FSPEC = 4,
  /** Special internal PcodeOp reference */
  IPTR_IOP = 5,
  /** Special virtual space to represent split variables */
  IPTR_JOIN = 6,
}

// ---- AddrSpace class ----

/**
 * A region where processor data is stored.
 *
 * An AddrSpace (Address Space) is an arbitrary sequence of bytes where a processor can store data.
 * An integer offset paired with an AddrSpace forms the address of a byte.
 * The size of an AddrSpace indicates the number of bytes that can be separately addressed.
 *
 * Typical spaces include:
 *   - ram: Modeling the main processor address bus
 *   - register: Modeling a processor's registers
 *   - const: Constant address space for modeling constant values
 *   - unique: Temporary register pool
 */
export class AddrSpace {
  // ---- Flag constants ----

  /** Space is big endian if set, little endian otherwise */
  static readonly big_endian = 1;
  /** This space is heritaged */
  static readonly heritaged = 2;
  /** Dead-code analysis is done on this space */
  static readonly does_deadcode = 4;
  /** Space is specific to a particular loadimage */
  static readonly programspecific = 8;
  /** Justification within aligned word is opposite of endianness */
  static readonly reverse_justification = 16;
  /** Space attached to the formal stack pointer */
  static readonly formal_stackspace = 0x20;
  /** This space is an overlay of another space */
  static readonly overlay = 0x40;
  /** This is the base space for overlay space(s) */
  static readonly overlaybase = 0x80;
  /** Space is truncated from its original size, expect pointers larger than this size */
  static readonly truncated = 0x100;
  /** Has physical memory associated with it */
  static readonly hasphysical = 0x200;
  /** Quick check for the OtherSpace derived class */
  static readonly is_otherspace = 0x400;
  /** Does there exist near pointers into this space */
  static readonly has_nearpointers = 0x800;

  // ---- Private fields ----

  private _type: spacetype;
  private manage: AddrSpaceManager;
  private trans: Translate;
  private refcount: int4;
  private flags: uint4;
  private highest: uintb;
  private pointerLowerBound: uintb;
  private pointerUpperBound: uintb;
  private shortcut: string;

  // ---- Protected fields ----

  protected name: string;
  protected addressSize: uint4;
  protected wordsize: uint4;
  protected minimumPointerSize: int4;
  protected index: int4;
  protected delay: int4;
  protected deadcodedelay: int4;

  /**
   * Full constructor: initialize an address space with all basic attributes.
   * @param m - the space manager associated with the new space
   * @param t - the processor translator associated with the new space
   * @param tp - the type of the new space
   * @param nm - the name of the new space
   * @param bigEnd - true for big endian encoding
   * @param size - the (offset encoding) size of the new space in bytes
   * @param ws - the number of bytes in an addressable unit
   * @param ind - the integer identifier for the new space
   * @param fl - can be 0 or AddrSpace.hasphysical
   * @param dl - the number of rounds to delay heritage for the new space
   * @param dead - the number of rounds to delay before dead code removal
   */
  constructor(
    m: AddrSpaceManager,
    t: Translate,
    tp: spacetype,
    nm?: string,
    bigEnd?: boolean,
    size?: uint4,
    ws?: uint4,
    ind?: int4,
    fl?: uint4,
    dl?: int4,
    dead?: int4
  ) {
    this.manage = m;
    this.trans = t;
    this._type = tp;
    this.refcount = 0;

    if (nm !== undefined) {
      // Full constructor
      this.name = nm;
      this.addressSize = size!;
      this.wordsize = ws!;
      this.index = ind!;
      this.delay = dl!;
      this.deadcodedelay = dead!;
      this.minimumPointerSize = 0;
      this.shortcut = ' ';

      // Only allow hasphysical from fl
      this.flags = (fl! & AddrSpace.hasphysical);
      if (bigEnd!) {
        this.flags |= AddrSpace.big_endian;
      }
      // Always on unless explicitly turned off in derived constructor
      this.flags |= (AddrSpace.heritaged | AddrSpace.does_deadcode);

      this.highest = 0n;
      this.pointerLowerBound = 0n;
      this.pointerUpperBound = 0n;
      this.calcScaleMask();
    } else {
      // Partial constructor for decode
      this.name = '';
      this.addressSize = 0;
      this.wordsize = 1;
      this.index = 0;
      this.delay = 0;
      this.deadcodedelay = 0;
      this.minimumPointerSize = 0;
      this.shortcut = ' ';
      // Always on unless explicitly turned off in derived constructor
      this.flags = (AddrSpace.heritaged | AddrSpace.does_deadcode);
      this.highest = 0n;
      this.pointerLowerBound = 0n;
      this.pointerUpperBound = 0n;
      // big_endian will be set by attribute during decode
    }
  }

  // ---- Protected methods ----

  /**
   * Calculate highest, pointerLowerBound, and pointerUpperBound based on
   * addressSize and wordsize.
   */
  protected calcScaleMask(): void {
    this.highest = calc_mask(this.addressSize);  // Maximum address
    this.highest = this.highest * BigInt(this.wordsize) + BigInt(this.wordsize - 1);  // Maximum byte address
    this.pointerLowerBound = 0n;
    this.pointerUpperBound = this.highest;
    const bufferSize: bigint = (this.addressSize < 3) ? 0x100n : 0x1000n;
    this.pointerLowerBound += bufferSize;
    this.pointerUpperBound -= bufferSize;
  }

  /**
   * Set cached attribute flags.
   * @param fl - the set of attributes to set
   */
  protected setFlags(fl: uint4): void {
    this.flags |= fl;
  }

  /**
   * Clear cached attribute flags.
   * @param fl - the set of attributes to clear
   */
  protected clearFlags(fl: uint4): void {
    this.flags &= ~fl;
  }

  /**
   * Read attributes for this space from a decoder element.
   * The processor translator (trans) and type must already be filled in.
   * @param decoder - the stream decoder
   */
  protected decodeBasicAttributes(decoder: Decoder): void {
    this.deadcodedelay = -1;
    for (;;) {
      const attribId: uint4 = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_BASE.id) {
        this.name = decoder.readString();
      }
      // Note: In C++ source, ATTRIB_NAME is checked but not ATTRIB_BASE for name.
      // The C++ checks ATTRIB_NAME, ATTRIB_INDEX, ATTRIB_SIZE, ATTRIB_WORDSIZE, etc.
      // We replicate the exact logic from the C++ source:
      // if (attribId == ATTRIB_NAME) name = decoder.readString();
      // if (attribId == ATTRIB_INDEX) ...
      // For now, this is a decode stub that follows the C++ logic.
    }
  }

  /**
   * Truncate the logical form of the space.
   * Pointers may refer to the original size but the most significant bytes are ignored.
   * @param newsize - size (in bytes) of the truncated (logical) space
   */
  protected truncateSpace(newsize: uint4): void {
    this.setFlags(AddrSpace.truncated);
    this.addressSize = newsize;
    this.minimumPointerSize = newsize;
    this.calcScaleMask();
  }

  // ---- Public getters ----

  /** Get the name of this space */
  getName(): string {
    return this.name;
  }

  /** Get the space manager */
  getManager(): AddrSpaceManager {
    return this.manage;
  }

  /** Get the processor translator */
  getTrans(): Translate {
    return this.trans;
  }

  /** Get the type of space */
  getType(): spacetype {
    return this._type;
  }

  /** Get number of heritage passes being delayed */
  getDelay(): int4 {
    return this.delay;
  }

  /** Get number of passes before deadcode removal is allowed */
  getDeadcodeDelay(): int4 {
    return this.deadcodedelay;
  }

  /** Get the integer identifier */
  getIndex(): int4 {
    return this.index;
  }

  /** Get the addressable unit size (number of bytes in a word) */
  getWordSize(): uint4 {
    return this.wordsize;
  }

  /** Get the size of the space (number of bytes in an address) */
  getAddrSize(): uint4 {
    return this.addressSize;
  }

  /** Get the highest byte-scaled address */
  getHighest(): uintb {
    return this.highest;
  }

  /** Get lower bound for assuming an offset is a pointer */
  getPointerLowerBound(): uintb {
    return this.pointerLowerBound;
  }

  /** Get upper bound for assuming an offset is a pointer */
  getPointerUpperBound(): uintb {
    return this.pointerUpperBound;
  }

  /**
   * Get the minimum pointer size for this space.
   * A value of 0 means the size must match exactly.
   */
  getMinimumPtrSize(): int4 {
    return this.minimumPointerSize;
  }

  /**
   * Wrap an offset to fit into this address space.
   * Calculates off modulo the size of this address space.
   * @param off - the offset requested
   * @returns the wrapped offset
   */
  wrapOffset(off: uintb): uintb {
    if (off >= 0n && off <= this.highest) {
      return off;
    }
    // highest + 1 is the modulus (number of valid byte offsets)
    const mod: bigint = this.highest + 1n;
    if (mod === 0n) {
      // Full 64-bit space: everything wraps to itself
      return off & 0xFFFFFFFFFFFFFFFFn;
    }
    // Signed remainder
    let res: bigint = off % mod;
    if (res < 0n) {
      res += mod;
    }
    return res;
  }

  /** Get the shortcut character for printing */
  getShortcut(): string {
    return this.shortcut;
  }

  /**
   * Set the shortcut character.
   * This is used by AddrSpaceManager to assign unique shortcuts.
   */
  setShortcut(c: string): void {
    this.shortcut = c;
  }

  /** Return true if dataflow has been traced in this space */
  isHeritaged(): boolean {
    return (this.flags & AddrSpace.heritaged) !== 0;
  }

  /** Return true if dead code analysis should be done on this space */
  doesDeadcode(): boolean {
    return (this.flags & AddrSpace.does_deadcode) !== 0;
  }

  /** Return true if data is physically stored in this space */
  hasPhysical(): boolean {
    return (this.flags & AddrSpace.hasphysical) !== 0;
  }

  /** Return true if values in this space are big endian */
  isBigEndian(): boolean {
    return (this.flags & AddrSpace.big_endian) !== 0;
  }

  /** Return true if alignment justification does not match endianness */
  isReverseJustified(): boolean {
    return (this.flags & AddrSpace.reverse_justification) !== 0;
  }

  /** Return true if this is attached to the formal stack pointer */
  isFormalStackSpace(): boolean {
    return (this.flags & AddrSpace.formal_stackspace) !== 0;
  }

  /** Return true if this is an overlay space */
  isOverlay(): boolean {
    return (this.flags & AddrSpace.overlay) !== 0;
  }

  /** Return true if other spaces overlay this space */
  isOverlayBase(): boolean {
    return (this.flags & AddrSpace.overlaybase) !== 0;
  }

  /** Return true if this is the "other" address space */
  isOtherSpace(): boolean {
    return (this.flags & AddrSpace.is_otherspace) !== 0;
  }

  /** Return true if this space is truncated from its original size */
  isTruncated(): boolean {
    return (this.flags & AddrSpace.truncated) !== 0;
  }

  /** Return true if near (truncated) pointers into this space are possible */
  hasNearPointers(): boolean {
    return (this.flags & AddrSpace.has_nearpointers) !== 0;
  }

  /** Return true if this space is program-specific */
  isProgramSpecific(): boolean {
    return (this.flags & AddrSpace.programspecific) !== 0;
  }

  // ---- Virtual methods ----

  /**
   * Number of base registers associated with this space.
   * Non-zero for virtual spaces like the stack space.
   */
  numSpacebase(): int4 {
    return 0;
  }

  /**
   * Get a base register that creates this virtual space.
   * Throws if the register does not exist.
   */
  getSpacebase(_i: int4): VarnodeData {
    throw new LowlevelError(this.name + ' space is not virtual and has no associated base register');
  }

  /**
   * Return original spacebase register before truncation.
   */
  getSpacebaseFull(_i: int4): VarnodeData {
    throw new LowlevelError(this.name + ' has no truncated registers');
  }

  /**
   * Return true if a stack in this space grows negative (push decreases the pointer).
   */
  stackGrowsNegative(): boolean {
    return true;
  }

  /**
   * Return this space's containing space (if any).
   * For virtual spaces, returns the containing address space; otherwise null.
   */
  getContain(): AddrSpace | null {
    return null;
  }

  /**
   * Determine if a given point is contained in an address range in this address space.
   *
   * The point is specified as an address space and offset pair plus an additional number of bytes to "skip".
   * A non-negative value is returned if the point falls in the address range.
   * If the point falls on the first byte of the range, 0 is returned. For the second byte, 1 is returned, etc.
   * Otherwise -1 is returned.
   *
   * @param offset - starting offset of the address range within this space
   * @param size - size of the address range in bytes
   * @param pointSpace - address space of the given point
   * @param pointOff - offset of the given point
   * @param pointSkip - additional bytes to skip
   * @returns a non-negative value indicating where the point falls in the range, or -1
   */
  overlapJoin(offset: uintb, size: int4, pointSpace: AddrSpace, pointOff: uintb, pointSkip: int4): int4 {
    if (this !== pointSpace) return -1;
    const dist: uintb = this.wrapOffset(pointOff + BigInt(pointSkip) - offset);
    if (dist >= BigInt(size)) return -1;
    return Number(dist);
  }

  /**
   * Encode address attributes to a stream.
   * @param encoder - the stream encoder
   * @param offset - offset of the address
   * @param size - optional size of the memory location
   */
  encodeAttributes(encoder: Encoder, offset: uintb, size?: int4): void {
    encoder.writeSpace(ATTRIB_BASE, this);
    encoder.writeUnsignedInteger({ name: 'offset', id: 0 }, offset);
    if (size !== undefined) {
      encoder.writeSignedInteger({ name: 'size', id: 0 }, size);
    }
  }

  /**
   * Recover an offset and size from decoder attributes.
   * @param decoder - the stream decoder
   * @param sizeRef - object to receive the decoded size (sizeRef.val)
   * @returns the recovered offset
   */
  decodeAttributes_sized(decoder: Decoder, sizeRef: { val: uint4 }): uintb {
    let offset: uintb = 0n;
    let foundoffset = false;
    for (;;) {
      const attribId: uint4 = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === 16 /* ATTRIB_OFFSET */) {
        foundoffset = true;
        offset = decoder.readUnsignedInteger();
      } else if (attribId === 19 /* ATTRIB_SIZE */) {
        sizeRef.val = decoder.readSignedInteger();
      }
    }
    if (!foundoffset) {
      throw new LowlevelError('Address is missing offset');
    }
    return offset;
  }

  /**
   * Print an address offset as a hexadecimal string.
   * @param offset - the offset to be printed
   * @returns the formatted offset string
   */
  printOffset(offset: uintb): string {
    return '0x' + offset.toString(16);
  }

  /**
   * Print an address in this space as a string.
   * Takes into account the wordsize, adding a "+n" if the offset is not on-cut with wordsize.
   * @param offset - the offset to be printed
   * @returns the formatted address string
   */
  printRaw(offset: uintb): string {
    let sz = this.getAddrSize();
    if (sz > 4) {
      if ((offset >> 32n) === 0n) {
        sz = 4;
      } else if ((offset >> 48n) === 0n) {
        sz = 6;
      }
    }
    const byteAddr = AddrSpace.byteToAddress(offset, this.wordsize);
    let result = '0x' + byteAddr.toString(16).padStart(2 * sz, '0');
    if (this.wordsize > 1) {
      const cut = Number(offset % BigInt(this.wordsize));
      if (cut !== 0) {
        result += '+' + cut.toString();
      }
    }
    return result;
  }

  /**
   * Read in an address (and possible size) from a string.
   * @param s - the string to be parsed
   * @param sizeRef - object to receive the parsed size (sizeRef.val)
   * @returns the parsed offset
   */
  read(s: string, sizeRef: { val: int4 }): uintb {
    // Simplified read: parse hex offset
    const parsed = parseInt(s, 16);
    if (isNaN(parsed)) {
      throw new LowlevelError('Unable to parse address: ' + s);
    }
    const offset = AddrSpace.addressToByte(BigInt(parsed), this.wordsize);
    sizeRef.val = this.manage?.getDefaultSize?.() ?? this.addressSize;
    return offset;
  }

  /**
   * Recover the details of this space from a stream.
   * @param decoder - the stream decoder
   */
  decode(decoder: Decoder): void {
    const elemId: uint4 = decoder.openElement();
    this.decodeBasicAttributes(decoder);
    decoder.closeElement(elemId);
  }

  // ---- Refcount management (used by AddrSpaceManager) ----

  /** Increment the reference count */
  _incRefCount(): void {
    this.refcount++;
  }

  /** Decrement the reference count */
  _decRefCount(): void {
    this.refcount--;
  }

  /** Get the current reference count */
  _getRefCount(): int4 {
    return this.refcount;
  }

  // ---- Static methods ----

  /**
   * Scale from addressable units to byte units.
   * @param val - the offset in addressable units
   * @param ws - the number of bytes in the addressable word
   * @returns the byte-scaled offset
   */
  static addressToByte(val: uintb, ws: uint4): uintb {
    return val * BigInt(ws);
  }

  /**
   * Scale from byte units to addressable units.
   * @param val - the offset in bytes
   * @param ws - the number of bytes in the addressable word
   * @returns the address-scaled offset
   */
  static byteToAddress(val: uintb, ws: uint4): uintb {
    return val / BigInt(ws);
  }

  /**
   * Scale a signed value from addressable units to byte units.
   * @param val - the signed offset in addressable units
   * @param ws - the number of bytes in the addressable word
   * @returns the byte-scaled offset
   */
  static addressToByteInt(val: bigint, ws: uint4): bigint {
    const v = typeof val === 'bigint' ? val : BigInt(val);
    const w = typeof ws === 'bigint' ? ws : BigInt(ws || 1);
    return v * w;
  }

  /**
   * Scale a signed value from byte units to addressable units.
   * @param val - the signed offset in bytes
   * @param ws - the number of bytes in the addressable word
   * @returns the address-scaled offset
   */
  static byteToAddressInt(val: bigint, ws: uint4): bigint {
    return val / BigInt(ws);
  }

  /**
   * Compare two spaces by their index (for sorting).
   * @param a - the first space
   * @param b - the second space
   * @returns true if the first space should come before the second
   */
  static compareByIndex(a: AddrSpace, b: AddrSpace): boolean {
    return a.index < b.index;
  }
}

// ---- ConstantSpace ----

/**
 * Special AddrSpace for representing constants during analysis.
 *
 * The underlying RTL represents all data in terms of an Address (AddrSpace + offset).
 * To represent constants, there is a special constant address space where the offset
 * encodes the actual constant value. For example, (const, 4) represents the constant 4.
 */
export class ConstantSpace extends AddrSpace {
  static readonly NAME = 'const';
  static readonly INDEX = 0;

  /**
   * Construct the unique constant space.
   * By convention, the name is always "const" and the index is always 0.
   * @param m - the associated address space manager
   * @param t - the associated processor translator
   */
  constructor(m: AddrSpaceManager, t: Translate) {
    super(
      m, t,
      spacetype.IPTR_CONSTANT,
      ConstantSpace.NAME,
      false,
      8,      // sizeof(uintb) = 8 bytes for bigint
      1,      // wordsize
      ConstantSpace.INDEX,
      0,      // fl
      0,      // dl
      0       // dead
    );
    this.clearFlags(AddrSpace.heritaged | AddrSpace.does_deadcode | AddrSpace.big_endian);
    if ((HOST_ENDIAN as number) === 1) {  // Endianness always matches host
      this.setFlags(AddrSpace.big_endian);
    }
  }

  override overlapJoin(
    _offset: uintb, _size: int4, _pointSpace: AddrSpace, _pointOff: uintb, _pointSkip: int4
  ): int4 {
    return -1;
  }

  /**
   * Constants are always printed as hexadecimal values.
   */
  override printRaw(offset: uintb): string {
    return '0x' + offset.toString(16);
  }

  override decode(_decoder: Decoder): void {
    throw new LowlevelError('Should never decode the constant space');
  }
}

// ---- OtherSpace ----

/**
 * Special AddrSpace for special/user-defined address spaces.
 */
export class OtherSpace extends AddrSpace {
  static readonly NAME = 'OTHER';
  static readonly INDEX = 1;

  /**
   * Construct the OTHER space.
   * @param m - the associated address space manager
   * @param t - the associated processor translator
   * @param ind - the integer identifier (ignored; INDEX is always used)
   */
  constructor(m: AddrSpaceManager, t: Translate, ind?: int4) {
    if (ind !== undefined) {
      // Full constructor
      super(
        m, t,
        spacetype.IPTR_PROCESSOR,
        OtherSpace.NAME,
        false,
        8,      // sizeof(uintb)
        1,      // wordsize
        OtherSpace.INDEX,
        0,      // fl
        0,      // dl
        0       // dead
      );
    } else {
      // Partial constructor for decode
      super(m, t, spacetype.IPTR_PROCESSOR);
    }
    this.clearFlags(AddrSpace.heritaged | AddrSpace.does_deadcode);
    this.setFlags(AddrSpace.is_otherspace);
  }

  /**
   * Print addresses in the OTHER space as plain hex.
   */
  override printRaw(offset: uintb): string {
    return '0x' + offset.toString(16);
  }
}

// ---- UniqueSpace ----

/**
 * The pool of temporary storage registers.
 *
 * It is convenient both for modelling processor instructions in an RTL and for later
 * transforming of the RTL to have a pool of temporary registers that can hold data
 * but that are not a formal part of the state of the processor. The analysis engine
 * always creates exactly one of these spaces named "unique".
 */
export class UniqueSpace extends AddrSpace {
  static readonly NAME = 'unique';
  /** Fixed size (in bytes) for unique space offsets */
  static readonly SIZE: uint4 = 4;

  /**
   * Construct the unique space.
   * @param m - the associated address space manager
   * @param t - the associated processor translator
   * @param ind - the integer identifier
   * @param fl - attribute flags (currently unused)
   */
  constructor(m: AddrSpaceManager, t: Translate, ind?: int4, fl?: uint4) {
    if (ind !== undefined) {
      // Full constructor
      const isBigEnd: boolean = t?.isBigEndian?.() ?? false;
      super(
        m, t,
        spacetype.IPTR_INTERNAL,
        UniqueSpace.NAME,
        isBigEnd,
        UniqueSpace.SIZE,
        1,      // wordsize
        ind,
        fl ?? 0,
        0,      // dl
        0       // dead
      );
    } else {
      // Partial constructor for decode
      super(m, t, spacetype.IPTR_INTERNAL);
    }
    this.setFlags(AddrSpace.hasphysical);
  }
}

// ---- JoinSpace ----

/**
 * The pool of logically joined variables.
 *
 * Some logical variables are split across non-contiguous regions of memory. This space
 * creates a virtual place for these logical variables to exist. Any memory location within
 * this space is backed by 2 or more memory locations in other spaces that physically hold
 * the pieces of the logical value.
 */
export class JoinSpace extends AddrSpace {
  static readonly NAME = 'join';
  private static readonly MAX_PIECES = 64;

  /**
   * Construct the join space.
   * @param m - the associated address space manager
   * @param t - the associated processor translator
   * @param ind - the integer identifier
   */
  constructor(m: AddrSpaceManager, t: Translate, ind: int4) {
    const isBigEnd: boolean = t?.isBigEndian?.() ?? false;
    super(
      m, t,
      spacetype.IPTR_JOIN,
      JoinSpace.NAME,
      isBigEnd,
      4,      // sizeof(uintm) = 4 bytes
      1,      // wordsize
      ind,
      0,      // fl
      0,      // dl
      0       // dead
    );
    // This is a virtual space; never heritaged, but does dead-code analysis
    this.clearFlags(AddrSpace.heritaged);
  }

  override overlapJoin(
    _offset: uintb, _size: int4, _pointSpace: AddrSpace, _pointOff: uintb, _pointSkip: int4
  ): int4 {
    throw new LowlevelError('JoinSpace.overlapJoin not implemented');
  }

  override encodeAttributes(_encoder: Encoder, _offset: uintb, _size?: int4): void {
    throw new LowlevelError('JoinSpace.encodeAttributes not implemented');
  }

  override decodeAttributes_sized(decoder: Decoder, sizeRef: { val: uint4 }): uintb {
    const pieces: any[] = [];
    let sizesum = 0;
    let logicalsize = 0;
    for (;;) {
      const attribId: number = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_LOGICALSIZE.id) {
        logicalsize = Number(decoder.readUnsignedInteger());
        continue;
      }
      let aid = attribId;
      if (attribId === 159) // ATTRIB_UNKNOWN id
        aid = decoder.getIndexedAttributeId(ATTRIB_PIECE);
      if (aid < ATTRIB_PIECE.id)
        continue;
      const pos = aid - ATTRIB_PIECE.id;
      if (pos > JoinSpace.MAX_PIECES)
        continue;
      while (pieces.length <= pos)
        pieces.push({ space: null, offset: 0n, size: 0 });
      const attrVal: string = decoder.readString();
      const offpos = attrVal.indexOf(':');
      if (offpos < 0) {
        // Register name
        const tr = this.getTrans();
        const point = tr.getRegister(attrVal);
        pieces[pos] = { space: point.space, offset: point.offset, size: point.size };
      } else {
        const szpos = attrVal.indexOf(':', offpos + 1);
        if (szpos < 0)
          throw new LowlevelError('join address piece attribute is malformed');
        const spcname = attrVal.substring(0, offpos);
        pieces[pos].space = this.getManager().getSpaceByName(spcname);
        pieces[pos].offset = BigInt('0x' + attrVal.substring(offpos + 1, szpos));
        pieces[pos].size = parseInt(attrVal.substring(szpos + 1), 10);
      }
      sizesum += pieces[pos].size;
    }
    const rec = this.getManager().findAddJoin(pieces, logicalsize);
    sizeRef.val = rec.getUnified().size;
    return BigInt(rec.getUnified().offset);
  }

  override printRaw(_offset: uintb): string {
    throw new LowlevelError('JoinSpace.printRaw not implemented');
  }

  override read(_s: string, _sizeRef: { val: int4 }): uintb {
    throw new LowlevelError('JoinSpace.read not implemented');
  }

  override decode(_decoder: Decoder): void {
    throw new LowlevelError('Should never decode join space');
  }
}

// ---- OverlaySpace ----

/**
 * An overlay space.
 *
 * A different code and data layout that occupies the same memory as another address space.
 * Some compilers use this concept to increase the logical size of a program without
 * increasing its physical memory requirements. From the point of view of reverse engineering,
 * the different code and symbols are viewed as a logically distinct space.
 */
export class OverlaySpace extends AddrSpace {
  private baseSpace: AddrSpace | null;

  /**
   * Construct an overlay space (for use with decode).
   * @param m - the address space manager
   * @param t - the processor translator
   */
  constructor(m: AddrSpaceManager, t: Translate) {
    super(m, t, spacetype.IPTR_PROCESSOR);
    this.baseSpace = null;
    this.setFlags(AddrSpace.overlay);
  }

  /** Return the base space that this space overlays */
  override getContain(): AddrSpace | null {
    return this.baseSpace;
  }

  override decode(decoder: Decoder): void {
    const elemId: uint4 = decoder.openElement(/* ELEM_SPACE_OVERLAY */);
    this.name = decoder.readString(ATTRIB_BASE);
    this.index = decoder.readSignedInteger(/* ATTRIB_INDEX */);

    this.baseSpace = decoder.readSpace(ATTRIB_BASE);
    decoder.closeElement(elemId);

    this.addressSize = this.baseSpace!.getAddrSize();
    this.wordsize = this.baseSpace!.getWordSize();
    this.delay = this.baseSpace!.getDelay();
    this.deadcodedelay = this.baseSpace!.getDeadcodeDelay();
    this.calcScaleMask();

    if (this.baseSpace!.isBigEndian()) {
      this.setFlags(AddrSpace.big_endian);
    }
    if (this.baseSpace!.hasPhysical()) {
      this.setFlags(AddrSpace.hasphysical);
    }
  }
}
