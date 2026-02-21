/**
 * @file database_part1.ts
 * @description Symbol-related classes from the Ghidra decompiler's database.hh/cc,
 * translated from C++ to TypeScript.
 *
 * Contains: SymbolEntry, Symbol, FunctionSymbol, EquateSymbol, UnionFacetSymbol,
 * LabSymbol, ExternRefSymbol, MapIterator, and associated constants.
 */

import type { int4, uint4, int2, uint2, uintb } from '../core/types.js';
import { LowlevelError } from '../core/error.js';
import { Address, Range, RangeList, calc_mask, sign_extend } from '../core/address.js';
import { AddrSpace } from '../core/space.js';
import { SPACE_END_SENTINEL } from '../core/translate.js';
import { PartMap } from '../core/partmap.js';
import type { Writer } from '../util/writer.js';
import { StringWriter } from '../util/writer.js';
import {
  AttributeId,
  ElementId,
  Encoder,
  Decoder,
  ATTRIB_NAME,
  ATTRIB_ID,
  ATTRIB_FORMAT,
  ATTRIB_HIDDENRETPARM,
  ATTRIB_INDEX,
  ATTRIB_INDIRECTSTORAGE,
  ATTRIB_NAMELOCK,
  ATTRIB_READONLY,
  ATTRIB_THISPTR,
  ATTRIB_TYPELOCK,
  ATTRIB_TYPE,
  ATTRIB_VAL,
  ATTRIB_VALUE,
  ATTRIB_CONTENT,
  ELEM_SYMBOL,
  ELEM_VALUE,
  ELEM_VAL,
} from '../core/marshal.js';
import {
  Datatype,
  type_metatype,
  encodeIntegerFormat,
  decodeIntegerFormat,
  ATTRIB_LABEL,
} from './type.js';

// TypePointer and TypeFactory are not yet exported from type.ts
type TypePointer = any;
type TypeFactory = any;
import {
  Varnode,
  VN_TYPELOCK,
  VN_NAMELOCK,
  VN_READONLY,
  VN_VOLATIL,
  VN_EXTERNREF,
  VN_ADDRTIED,
  VN_INDIRECTSTORAGE,
  VN_HIDDENRETPARM,
  VN_PRECISLO,
  VN_PRECISHI,
} from './varnode.js';
import { SortedSet } from '../util/sorted-set.js';

// ---------------------------------------------------------------------------
// Forward type declarations
// ---------------------------------------------------------------------------

type Architecture = any;
type Funcdata = any;
type ProtoModel = any;
type FuncProto = any;

// ---------------------------------------------------------------------------
// AttributeId constants (from database.cc)
// ---------------------------------------------------------------------------

export const ATTRIB_CAT = new AttributeId("cat", 61);
export const ATTRIB_FIELD = new AttributeId("field", 62);
export const ATTRIB_MERGE = new AttributeId("merge", 63);
export const ATTRIB_SCOPEIDBYNAME = new AttributeId("scopeidbyname", 64);
export const ATTRIB_VOLATILE = new AttributeId("volatile", 65);

// ---------------------------------------------------------------------------
// ElementId constants (from database.cc)
// ---------------------------------------------------------------------------

export const ELEM_COLLISION = new ElementId("collision", 67);
export const ELEM_DB = new ElementId("db", 68);
export const ELEM_EQUATESYMBOL = new ElementId("equatesymbol", 69);
export const ELEM_EXTERNREFSYMBOL = new ElementId("externrefsymbol", 70);
export const ELEM_FACETSYMBOL = new ElementId("facetsymbol", 71);
export const ELEM_FUNCTIONSHELL = new ElementId("functionshell", 72);
export const ELEM_HASH = new ElementId("hash", 73);
export const ELEM_HOLE = new ElementId("hole", 74);
export const ELEM_LABELSYM = new ElementId("labelsym", 75);
export const ELEM_MAPSYM = new ElementId("mapsym", 76);
export const ELEM_PARENT = new ElementId("parent", 77);
export const ELEM_PROPERTY_CHANGEPOINT = new ElementId("property_changepoint", 78);
export const ELEM_RANGEEQUALSSYMBOLS = new ElementId("rangeequalssymbols", 79);
export const ELEM_SCOPE = new ElementId("scope", 80);
export const ELEM_SYMBOLLIST = new ElementId("symbollist", 81);

/** Externally defined ELEM_FUNCTION (from funcdata or prettyprint) */
const ELEM_FUNCTION = new ElementId("function", 100);

/** Rangelist element used in scope decoding */
const ELEM_RANGELIST = new ElementId("rangelist", 82);

// ---------------------------------------------------------------------------
// Helper: safely get space index (handles pcoderaw AddrSpace without getIndex)
// ---------------------------------------------------------------------------
function safeSpaceIndex(spc: any): number {
  if (spc === null || spc === undefined) return -1;
  if (typeof spc.getIndex === 'function') return spc.getIndex();
  if (typeof spc.index === 'number') return spc.index;
  return -1;
}

/** Safely get the maptable entry for a space, returns null if space is invalid */
function getMaptableEntry(maptable: any[], spc: any): any | null {
  const idx = safeSpaceIndex(spc);
  if (idx < 0 || idx >= maptable.length) return null;
  return maptable[idx] ?? null;
}

// ---------------------------------------------------------------------------
// DuplicateFunctionError
// ---------------------------------------------------------------------------

/**
 * Exception thrown when a function is added more than once to the database.
 * Stores the address of the function so a handler can recover the original symbol.
 */
export class DuplicateFunctionError extends LowlevelError {
  address: Address;
  functionName: string;

  constructor(addr: Address, nm: string) {
    super("Duplicate Function");
    this.address = addr;
    this.functionName = nm;
  }
}

// =========================================================================
// EntrySubsort
// =========================================================================

/**
 * Class for sub-sorting different SymbolEntry objects at the same address.
 * Built from the SymbolEntry uselimit object. Relevant portions of an Address
 * object are pulled out for smaller storage and quick comparisons.
 */
export class EntrySubsort {
  useindex: number;
  useoffset: bigint;

  constructor();
  constructor(addr: Address);
  constructor(val: boolean);
  constructor(op2: EntrySubsort);
  constructor(arg?: Address | boolean | EntrySubsort) {
    if (arg === undefined) {
      this.useindex = 0;
      this.useoffset = 0n;
    } else if (arg instanceof Address) {
      this.useindex = safeSpaceIndex(arg.getSpace());
      this.useoffset = arg.getOffset();
    } else if (arg instanceof EntrySubsort) {
      this.useindex = arg.useindex;
      this.useoffset = arg.useoffset;
    } else if (typeof arg === 'boolean') {
      if (arg) {
        this.useindex = 0xffff; // Greater than any real values
        this.useoffset = 0n;
      } else {
        this.useindex = 0;
        this.useoffset = 0n;
      }
    } else {
      this.useindex = 0;
      this.useoffset = 0n;
    }
  }

  /** Compare this with another sub-sort */
  lessThan(op2: EntrySubsort): boolean {
    if (this.useindex !== op2.useindex)
      return this.useindex < op2.useindex;
    return this.useoffset < op2.useoffset;
  }
}

// =========================================================================
// EntryInitData
// =========================================================================

/**
 * Initialization data for a SymbolEntry to facilitate a rangemap.
 * Contains all the raw pieces of a SymbolEntry for a (non-dynamic) Symbol
 * except the offset of the main address and the size.
 */
export class EntryInitData {
  space: AddrSpace;
  symbol: Symbol;
  extraflags: number;
  offset: number;
  uselimit: RangeList;

  constructor(sym: Symbol, exfl: number, spc: AddrSpace, off: number, ul: RangeList) {
    this.symbol = sym;
    this.extraflags = exfl;
    this.space = spc;
    this.offset = off;
    this.uselimit = new RangeList(ul);
  }
}

// =========================================================================
// SymbolEntry
// =========================================================================

/**
 * A storage location for a particular Symbol.
 *
 * Where a Symbol is stored, as a byte address and a size, is of particular
 * importance to the decompiler. This class encapsulates this storage meta-data.
 * A single Symbol split across multiple storage locations is supported by the
 * offset and size fields. The hash field supports dynamic storage, where a
 * Symbol is represented by a constant or a temporary register.
 */
export class SymbolEntry {
  /** Symbol object being mapped */
  symbol: Symbol;
  /** Varnode flags specific to this storage location */
  extraflags: number;
  /** Starting address of the storage location */
  addr: Address;
  /** A dynamic storage address (an alternative to addr for dynamic symbols) */
  hash: bigint;
  /** Offset into the Symbol that this covers */
  offset: number;
  /** Number of bytes consumed by this (piece of the) storage */
  size: number;
  /** Code address ranges where this storage is valid */
  uselimit: RangeList;

  /**
   * Construct a mapping for a Symbol without an address.
   * This SymbolEntry is unintegrated. An address or hash must be provided
   * either directly or via decode().
   */
  constructor(sym: Symbol);

  /**
   * Construct a dynamic SymbolEntry.
   * The main address field (addr) is set to invalid, and the hash becomes
   * the primary location information.
   */
  constructor(sym: Symbol, exfl: number, h: bigint, off: number, sz: number, rnglist: RangeList);

  /**
   * Fully initialize this from EntryInitData and boundary offsets (for rangemap).
   */
  constructor(data: EntryInitData, a: bigint, b: bigint);

  constructor(
    arg1: Symbol | EntryInitData,
    arg2?: number | bigint,
    arg3?: bigint,
    arg4?: number,
    arg5?: number,
    arg6?: RangeList,
  ) {
    if (arg1 instanceof EntryInitData) {
      // constructor(data: EntryInitData, a: bigint, b: bigint)
      const data = arg1;
      const a = arg2 as bigint;
      const b = arg3 as bigint;
      this.addr = new Address(data.space, a);
      this.size = Number(b - a) + 1;
      this.symbol = data.symbol;
      this.extraflags = data.extraflags;
      this.offset = data.offset;
      this.hash = 0n;
      this.uselimit = new RangeList(data.uselimit);
    } else if (arg2 !== undefined && typeof arg2 === 'number') {
      // constructor(sym, exfl, h, off, sz, rnglist)
      this.symbol = arg1 as Symbol;
      this.extraflags = arg2 as number;
      this.addr = new Address();
      this.hash = arg3 as bigint;
      this.offset = arg4 as number;
      this.size = arg5 as number;
      this.uselimit = new RangeList(arg6 as RangeList);
    } else {
      // constructor(sym)
      this.symbol = arg1 as Symbol;
      this.extraflags = 0;
      this.addr = new Address();
      this.hash = 0n;
      this.offset = 0;
      this.size = -1;
      this.uselimit = new RangeList();
    }
  }

  /** Is this a high or low piece of the whole Symbol */
  isPiece(): boolean {
    return (this.extraflags & (VN_PRECISLO | VN_PRECISHI)) !== 0;
  }

  /** Is storage dynamic */
  isDynamic(): boolean {
    return this.addr.isInvalid();
  }

  /** Is this storage invalid */
  isInvalid(): boolean {
    return this.addr.isInvalid() && this.hash === 0n;
  }

  /** Get all Varnode flags for this storage */
  getAllFlags(): number {
    return this.extraflags | this.symbol.getFlags();
  }

  /** Get offset of this within the Symbol */
  getOffset(): number {
    return this.offset;
  }

  /** Get the first offset of this storage location */
  getFirst(): bigint {
    return this.addr.getOffset();
  }

  /** Get the last offset of this storage location */
  getLast(): bigint {
    return this.addr.getOffset() + BigInt(this.size - 1);
  }

  /** Get the sub-sort object */
  getSubsort(): EntrySubsort {
    const res = new EntrySubsort();
    if ((this.symbol.getFlags() & Varnode.addrtied) === 0) {
      const range = this.uselimit.getFirstRange();
      if (range === null)
        throw new LowlevelError("Map entry with empty uselimit");
      res.useindex = safeSpaceIndex(range.getSpace());
      res.useoffset = range.getFirst();
    }
    return res;
  }

  /** Get the Symbol associated with this */
  getSymbol(): Symbol {
    return this.symbol;
  }

  /** Get the starting address of this storage */
  getAddr(): Address {
    return this.addr;
  }

  /** Get the hash used to identify this storage */
  getHash(): bigint {
    return this.hash;
  }

  /** Get the number of bytes consumed by this storage */
  getSize(): number {
    return this.size;
  }

  /**
   * Is this storage valid for the given code address.
   * This storage location may only hold the Symbol value for a limited
   * portion of the code.
   */
  inUse(usepoint: Address): boolean {
    if (this.isAddrTied()) return true; // Valid throughout scope
    if (usepoint.isInvalid()) return false;
    return this.uselimit.inRange(usepoint, 1);
  }

  /** Get the set of valid code addresses for this storage */
  getUseLimit(): RangeList {
    return this.uselimit;
  }

  /** Get the first code address where this storage is valid */
  getFirstUseAddress(): Address {
    const rng = this.uselimit.getFirstRange();
    if (rng === null)
      return new Address();
    return rng.getFirstAddr();
  }

  /** Set the range of code addresses where this is valid */
  setUseLimit(uselim: RangeList): void {
    this.uselimit = new RangeList(uselim);
  }

  /** Is this storage address tied */
  isAddrTied(): boolean {
    return (this.symbol.getFlags() & Varnode.addrtied) !== 0;
  }

  /**
   * Update a Varnode data-type from this.
   * If the Symbol associated with this is type-locked, change the given
   * Varnode's attached data-type to match the Symbol.
   */
  updateType(vn: any): boolean {
    if ((this.symbol.getFlags() & Varnode.typelock) !== 0) {
      const dt = this.getSizedType(vn.getAddr(), vn.getSize());
      if (dt !== null)
        return vn.updateType(dt, true, true);
    }
    return false;
  }

  /**
   * Get the data-type associated with (a piece of) this.
   * Return the data-type that matches the given size and address within this storage.
   * null is returned if there is no valid sub-type matching the size.
   */
  getSizedType(inaddr: Address, sz: number): Datatype | null {
    let off: number;
    if (this.isDynamic())
      off = this.offset;
    else
      off = Number(inaddr.getOffset() - this.addr.getOffset()) + this.offset;
    const cur = this.symbol.getType();
    return this.symbol.getScope().getArch().types.getExactPiece(cur, off, sz);
  }

  /**
   * Dump a description of this to a Writer.
   */
  printEntry(s: Writer): void {
    s.write(this.symbol.getName() + " : ");
    if (this.addr.isInvalid()) {
      s.write("<dynamic>");
    } else {
      s.write(this.addr.getShortcut());
      s.write(this.addr.printRaw());
    }
    s.write(':' + this.symbol.getType().getSize().toString());
    s.write(' ');
    const sw = new StringWriter();
    this.symbol.getType().printRaw(sw);
    s.write(sw.toString());
    s.write(" : ");
    s.write(this.uselimit.printBounds());
  }

  /**
   * Encode this to a stream.
   * Writes elements internal to the <mapsym> element associated with the Symbol.
   */
  encode(encoder: Encoder): void {
    if (this.isPiece()) return; // Don't save a piece
    if (this.addr.isInvalid()) {
      encoder.openElement(ELEM_HASH);
      encoder.writeUnsignedInteger(ATTRIB_VAL, this.hash);
      encoder.closeElement(ELEM_HASH);
    } else {
      this.addr.encode(encoder);
    }
    (this.uselimit as any).encode(encoder);
  }

  /**
   * Decode this from a stream.
   * Parse either an <addr> element for storage information or a <hash> element
   * if the symbol is dynamic. Then parse the uselimit describing the valid
   * range of code addresses.
   */
  decode(decoder: Decoder): void {
    const elemId = decoder.peekElement();
    if (elemId === ELEM_HASH.getId()) {
      decoder.openElement();
      this.hash = decoder.readUnsignedIntegerById(ATTRIB_VAL);
      this.addr = new Address();
      decoder.closeElement(elemId);
    } else {
      this.addr = Address.decode(decoder);
      this.hash = 0n;
    }
    (this.uselimit as any).decode(decoder);
  }
}

// =========================================================================
// Symbol
// =========================================================================

/**
 * The base class for a symbol in a symbol table or scope.
 *
 * At its most basic, a Symbol is a name and a data-type.
 * Practically a Symbol knows what Scope it is in, how it should be
 * displayed, and the symbol's category.
 */
export class Symbol {
  // --- Display (dispflag) properties ---
  static readonly force_hex = 1;
  static readonly force_dec = 2;
  static readonly force_oct = 3;
  static readonly force_bin = 4;
  static readonly force_char = 5;
  static readonly size_typelock = 8;
  static readonly isolate = 16;
  static readonly merge_problems = 32;
  static readonly is_this_ptr = 64;

  // --- Symbol categories ---
  static readonly no_category: int2 = -1;
  static readonly function_parameter: int2 = 0;
  static readonly equate: int2 = 1;
  static readonly union_facet: int2 = 2;
  static readonly fake_input: int2 = 3;

  /** Base of internal IDs */
  static ID_BASE: bigint = 0x4000000000000000n;

  // --- Protected fields ---
  /** The scope that owns this symbol */
  scope: Scope;
  /** The local name of the symbol */
  name: string;
  /** Name to use when displaying symbol in output */
  displayName: string;
  /** The symbol's data-type */
  type: Datatype | null;
  /** id to distinguish symbols with the same name */
  nameDedup: number;
  /** Varnode-like properties of the symbol */
  flags: number;
  /** Flags affecting the display of this symbol */
  dispflags: number;
  /** Special category (function_parameter, equate, etc.) */
  category: int2;
  /** Index within category */
  catindex: uint2;
  /** Unique id, 0=unassigned */
  symbolId: bigint;
  /** List of storage locations labeled with this Symbol */
  mapentry: SymbolEntry[];
  /** Scope associated with current depth resolution */
  depthScope: Scope | null;
  /** Number of namespace elements required to resolve symbol in current scope */
  depthResolution: number;
  /** Number of SymbolEntries that map to the whole Symbol */
  wholeCount: number;

  /**
   * Construct given a name and data-type.
   */
  constructor(sc: Scope, nm: string, ct: Datatype | null);
  /**
   * Construct for use with decode().
   */
  constructor(sc: Scope);
  constructor(sc: Scope, nm?: string, ct?: Datatype | null) {
    this.scope = sc;
    if (nm !== undefined) {
      this.name = nm;
      this.displayName = nm;
      this.type = ct ?? null;
    } else {
      this.name = '';
      this.displayName = '';
      this.type = null;
    }
    this.nameDedup = 0;
    this.flags = 0;
    this.dispflags = 0;
    this.category = Symbol.no_category;
    this.catindex = 0;
    this.symbolId = 0n;
    this.mapentry = [];
    this.wholeCount = 0;
    this.depthScope = null;
    this.depthResolution = 0;
  }

  /** Get the local name of the symbol */
  getName(): string { return this.name; }

  /** Get the name to display in output */
  getDisplayName(): string { return this.displayName; }

  /** Get the data-type */
  getType(): Datatype { return this.type!; }

  /** Get a unique id for the symbol */
  getId(): bigint { return this.symbolId; }

  /** Get the boolean properties of the Symbol */
  getFlags(): number { return this.flags; }

  /** Get the format to display the Symbol in */
  getDisplayFormat(): number { return this.dispflags & 7; }

  /** Get the Symbol category */
  getCategory(): int2 { return this.category; }

  /** Get the position of the Symbol within its category */
  getCategoryIndex(): uint2 { return this.catindex; }

  /** Is the Symbol type-locked */
  isTypeLocked(): boolean { return (this.flags & Varnode.typelock) !== 0; }

  /** Is the Symbol name-locked */
  isNameLocked(): boolean { return (this.flags & Varnode.namelock) !== 0; }

  /** Is the Symbol size type-locked */
  isSizeTypeLocked(): boolean { return (this.dispflags & Symbol.size_typelock) !== 0; }

  /** Is the Symbol volatile */
  isVolatile(): boolean { return (this.flags & Varnode.volatil) !== 0; }

  /** Is this the "this" pointer */
  isThisPointer(): boolean { return (this.dispflags & Symbol.is_this_ptr) !== 0; }

  /** Is storage really a pointer to the true Symbol */
  isIndirectStorage(): boolean { return (this.flags & Varnode.indirectstorage) !== 0; }

  /** Is this a reference to the function return value */
  isHiddenReturn(): boolean { return (this.flags & Varnode.hiddenretparm) !== 0; }

  /**
   * Does this have an undefined name.
   * The name for a Symbol can be unspecified. See ScopeInternal.buildUndefinedName
   */
  isNameUndefined(): boolean {
    return (this.name.length === 15) && (this.name.substring(0, 7) === "$$undef");
  }

  /** Does this have more than one entire mapping */
  isMultiEntry(): boolean { return this.wholeCount > 1; }

  /** Were some SymbolEntrys not merged */
  hasMergeProblems(): boolean { return (this.dispflags & Symbol.merge_problems) !== 0; }

  /** Mark that some SymbolEntrys could not be merged */
  setMergeProblems(): void { this.dispflags |= Symbol.merge_problems; }

  /** Return true if this is isolated from speculative merging */
  isIsolated(): boolean { return (this.dispflags & Symbol.isolate) !== 0; }

  /**
   * Set whether this Symbol should be speculatively merged.
   * If val is true, any Varnodes that map directly to this Symbol
   * will not be speculatively merged with other Varnodes.
   */
  setIsolated(val: boolean): void {
    if (val) {
      this.dispflags |= Symbol.isolate;
      this.flags |= Varnode.typelock;
      this.checkSizeTypeLock();
    } else {
      this.dispflags &= ~Symbol.isolate;
    }
  }

  /** Get the scope owning this Symbol */
  getScope(): Scope { return this.scope; }

  /**
   * Get the first entire mapping of the symbol.
   * Throws if there is no mapping.
   */
  getFirstWholeMap(): SymbolEntry {
    if (this.mapentry.length === 0)
      throw new LowlevelError("No mapping for symbol: " + this.name);
    return this.mapentry[0];
  }

  /**
   * Get first mapping of the symbol that contains the given Address.
   * This method may return a partial entry, where the SymbolEntry is only
   * holding part of the whole Symbol.
   */
  getMapEntry(addr: Address): SymbolEntry | null;
  /**
   * Return the i-th SymbolEntry for this Symbol.
   */
  getMapEntry(i: number): SymbolEntry;
  getMapEntry(arg: Address | number): SymbolEntry | null {
    if (typeof arg === 'number') {
      return this.mapentry[arg];
    }
    const addr = arg;
    for (let i = 0; i < this.mapentry.length; ++i) {
      const res = this.mapentry[i];
      const entryaddr = res.getAddr();
      if (addr.getSpace() !== entryaddr.getSpace()) continue;
      if (addr.getOffset() < entryaddr.getOffset()) continue;
      const diff = Number(addr.getOffset() - entryaddr.getOffset());
      if (diff >= res.getSize()) continue;
      return res;
    }
    return null;
  }

  /** Return the number of SymbolEntrys */
  numEntries(): number { return this.mapentry.length; }

  /**
   * Position of given SymbolEntry within this multi-entry Symbol.
   * Among all the SymbolEntrys that map this entire Symbol, calculate
   * the position of the given SymbolEntry within the list.
   * Returns -1 if it is not in the list.
   */
  getMapEntryPosition(entry: SymbolEntry): number {
    let pos = 0;
    for (let i = 0; i < this.mapentry.length; ++i) {
      const tmp = this.mapentry[i];
      if (tmp === entry)
        return pos;
      if (entry.getSize() === this.type!.getSize())
        pos += 1;
    }
    return -1;
  }

  /**
   * Get number of scope names needed to resolve this symbol.
   *
   * For a given context scope where this Symbol is used, determine how many elements of
   * the full namespace path need to be printed to correctly distinguish it.
   * A value of 0 means the base symbol name is visible and not overridden in the context scope.
   */
  getResolutionDepth(useScope: Scope | null): number {
    if (this.scope === useScope) return 0;
    if (useScope === null) {
      let point: Scope | null = this.scope;
      let count = 0;
      while (point !== null) {
        count += 1;
        point = point.getParent();
      }
      return count - 1; // Don't print global scope
    }
    if (this.depthScope === useScope)
      return this.depthResolution;
    this.depthScope = useScope;
    const distinguishScope = this.scope.findDistinguishingScope(useScope);
    this.depthResolution = 0;
    let distinguishName: string;
    let terminatingScope: Scope | null;
    if (distinguishScope === null) {
      // Symbol scope is ancestor of use scope
      distinguishName = this.name;
      terminatingScope = this.scope;
    } else {
      distinguishName = distinguishScope.getName();
      let currentScope: Scope | null = this.scope;
      while (currentScope !== distinguishScope) {
        this.depthResolution += 1;
        currentScope = currentScope!.getParent();
      }
      this.depthResolution += 1; // Also print the distinguishing scope name
      terminatingScope = distinguishScope.getParent();
    }
    if (useScope.isNameUsed(distinguishName, terminatingScope))
      this.depthResolution += 1; // Name was overridden, we need one more distinguishing name
    return this.depthResolution;
  }

  /**
   * Encode basic Symbol properties as attributes.
   */
  encodeHeader(encoder: Encoder): void {
    encoder.writeString(ATTRIB_NAME, this.name);
    encoder.writeUnsignedInteger(ATTRIB_ID, this.getId());
    if ((this.flags & Varnode.namelock) !== 0)
      encoder.writeBool(ATTRIB_NAMELOCK, true);
    if ((this.flags & Varnode.typelock) !== 0)
      encoder.writeBool(ATTRIB_TYPELOCK, true);
    if ((this.flags & Varnode.readonly) !== 0)
      encoder.writeBool(ATTRIB_READONLY, true);
    if ((this.flags & Varnode.volatil) !== 0)
      encoder.writeBool(ATTRIB_VOLATILE, true);
    if ((this.flags & Varnode.indirectstorage) !== 0)
      encoder.writeBool(ATTRIB_INDIRECTSTORAGE, true);
    if ((this.flags & Varnode.hiddenretparm) !== 0)
      encoder.writeBool(ATTRIB_HIDDENRETPARM, true);
    if ((this.dispflags & Symbol.isolate) !== 0)
      encoder.writeBool(ATTRIB_MERGE, false);
    if ((this.dispflags & Symbol.is_this_ptr) !== 0)
      encoder.writeBool(ATTRIB_THISPTR, true);
    const format = this.getDisplayFormat();
    if (format !== 0) {
      encoder.writeString(ATTRIB_FORMAT, decodeIntegerFormat(format));
    }
    encoder.writeSignedInteger(ATTRIB_CAT, this.category);
    if (this.category >= 0)
      encoder.writeUnsignedInteger(ATTRIB_INDEX, BigInt(this.catindex));
  }

  /**
   * Decode basic Symbol properties from a <symbol> element.
   */
  decodeHeader(decoder: Decoder): void {
    this.name = '';
    this.displayName = '';
    this.category = Symbol.no_category;
    this.symbolId = 0n;
    for (;;) {
      const attribId = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_CAT.getId()) {
        this.category = decoder.readSignedInteger() as int2;
      } else if (attribId === ATTRIB_FORMAT.getId()) {
        this.dispflags |= encodeIntegerFormat(decoder.readString());
      } else if (attribId === ATTRIB_HIDDENRETPARM.getId()) {
        if (decoder.readBool())
          this.flags |= Varnode.hiddenretparm;
      } else if (attribId === ATTRIB_ID.getId()) {
        this.symbolId = decoder.readUnsignedInteger();
        if ((this.symbolId >> 56n) === (Symbol.ID_BASE >> 56n))
          this.symbolId = 0n; // Don't keep old internal id's
      } else if (attribId === ATTRIB_INDIRECTSTORAGE.getId()) {
        if (decoder.readBool())
          this.flags |= Varnode.indirectstorage;
      } else if (attribId === ATTRIB_MERGE.getId()) {
        if (!decoder.readBool()) {
          this.dispflags |= Symbol.isolate;
          this.flags |= Varnode.typelock;
        }
      } else if (attribId === ATTRIB_NAME.getId()) {
        this.name = decoder.readString();
      } else if (attribId === ATTRIB_NAMELOCK.getId()) {
        if (decoder.readBool())
          this.flags |= Varnode.namelock;
      } else if (attribId === ATTRIB_READONLY.getId()) {
        if (decoder.readBool())
          this.flags |= Varnode.readonly;
      } else if (attribId === ATTRIB_TYPELOCK.getId()) {
        if (decoder.readBool())
          this.flags |= Varnode.typelock;
      } else if (attribId === ATTRIB_THISPTR.getId()) {
        if (decoder.readBool())
          this.dispflags |= Symbol.is_this_ptr;
      } else if (attribId === ATTRIB_VOLATILE.getId()) {
        if (decoder.readBool())
          this.flags |= Varnode.volatil;
      } else if (attribId === ATTRIB_LABEL.getId()) {
        this.displayName = decoder.readString();
      }
    }
    if (this.category === Symbol.function_parameter) {
      this.catindex = Number(decoder.readUnsignedIntegerById(ATTRIB_INDEX)) as uint2;
    } else {
      this.catindex = 0;
    }
    if (this.displayName.length === 0)
      this.displayName = this.name;
  }

  /**
   * Encode the data-type for the Symbol.
   */
  encodeBody(encoder: Encoder): void {
    this.type!.encodeRef(encoder);
  }

  /**
   * Decode the data-type for the Symbol from a <symbol> element.
   */
  decodeBody(decoder: Decoder): void {
    this.type = this.scope.getArch().types.decodeType(decoder);
    this.checkSizeTypeLock();
  }

  /**
   * Encode this Symbol to a stream.
   */
  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_SYMBOL);
    this.encodeHeader(encoder);
    this.encodeBody(encoder);
    encoder.closeElement(ELEM_SYMBOL);
  }

  /**
   * Decode this Symbol from a stream.
   */
  decode(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_SYMBOL);
    this.decodeHeader(decoder);
    this.decodeBody(decoder);
    decoder.closeElement(elemId);
  }

  /**
   * Get number of bytes consumed within the address->symbol map.
   * By default, this is the number of bytes consumed by the Symbol's data-type.
   */
  getBytesConsumed(): number {
    return this.type!.getSize();
  }

  // --- Protected helpers ---

  /** Set the display format for this Symbol */
  setDisplayFormat(val: number): void {
    this.dispflags &= ~7;
    this.dispflags |= val;
  }

  /**
   * Calculate if size_typelock property is on.
   * Examine the data-type to decide if the Symbol has the special property
   * called size_typelock, which indicates the size of the Symbol is locked,
   * but the data-type is not locked (and can float).
   */
  checkSizeTypeLock(): void {
    this.dispflags &= ~Symbol.size_typelock;
    if (this.isTypeLocked() && (this.type!.getMetatype() === type_metatype.TYPE_UNKNOWN))
      this.dispflags |= Symbol.size_typelock;
  }

  /** Toggle whether this is the "this" pointer for a class method */
  setThisPointer(val: boolean): void {
    if (val)
      this.dispflags |= Symbol.is_this_ptr;
    else
      this.dispflags &= ~Symbol.is_this_ptr;
  }
}

// =========================================================================
// FunctionSymbol
// =========================================================================

/**
 * A Symbol representing an executable function.
 *
 * This Symbol owns the Funcdata object for the function it represents. The formal
 * Symbol is thus associated with all the meta-data about the function.
 */
export class FunctionSymbol extends Symbol {
  /** The underlying meta-data object for the function */
  private fd: Funcdata | null;
  /** Minimum number of bytes to consume with the start address */
  private consumeSize: number;

  /**
   * Build the data-type associated with this Symbol.
   */
  private buildType(): void {
    const types: TypeFactory = this.scope.getArch().types;
    this.type = types.getTypeCode();
    this.flags |= Varnode.namelock | Varnode.typelock;
  }

  /**
   * Construct given the name.
   *
   * Build a function shell, made up of just the name of the function and
   * a placeholder data-type, without the underlying Funcdata object.
   * A SymbolEntry for a function has a small size starting at the entry address,
   * in order to deal with non-contiguous functions.
   */
  constructor(sc: Scope, nm: string, size: number);
  /** Constructor for use with decode */
  constructor(sc: Scope, size: number);
  constructor(sc: Scope, arg2: string | number, arg3?: number) {
    super(sc);
    this.fd = null;
    if (typeof arg2 === 'string') {
      // (sc, nm, size)
      this.consumeSize = arg3!;
      this.buildType();
      this.name = arg2;
      this.displayName = arg2;
    } else {
      // (sc, size)
      this.consumeSize = arg2;
      this.buildType();
    }
  }

  /**
   * Get the underlying Funcdata object.
   * Creates it on demand if not yet initialized.
   *
   * Note: In the C++ original this calls `new Funcdata(name, displayName, scope, entry->getAddr(), this)`.
   * Since Funcdata is forward-declared here, the actual construction is deferred to
   * a factory method that must be wired up when the Funcdata module is available.
   */
  getFunction(): Funcdata {
    if (this.fd !== null) return this.fd;
    const entry = this.getFirstWholeMap();
    this.fd = FunctionSymbol.createFuncdata(this.name, this.displayName, this.scope, entry.getAddr(), this);
    return this.fd;
  }

  /**
   * Factory function to create a Funcdata.
   * This must be assigned from outside once the Funcdata class is available.
   * Default implementation throws.
   */
  static createFuncdata: (nm: string, displayNm: string, sc: Scope, addr: Address, sym: FunctionSymbol) => Funcdata =
    (_nm, _displayNm, _sc, _addr, _sym) => {
      throw new LowlevelError("FunctionSymbol.createFuncdata not yet connected to Funcdata");
    };

  /** Encode this Symbol to a stream */
  override encode(encoder: Encoder): void {
    if (this.fd !== null) {
      this.fd.encode(encoder, this.symbolId, false); // Save the function itself
    } else {
      encoder.openElement(ELEM_FUNCTIONSHELL);
      encoder.writeString(ATTRIB_NAME, this.name);
      if (this.symbolId !== 0n)
        encoder.writeUnsignedInteger(ATTRIB_ID, this.symbolId);
      encoder.closeElement(ELEM_FUNCTIONSHELL);
    }
  }

  /** Decode this Symbol from a stream */
  override decode(decoder: Decoder): void {
    const elemId = decoder.peekElement();
    if (elemId === ELEM_FUNCTION.getId()) {
      this.fd = FunctionSymbol.createFuncdata("", "", this.scope, new Address(), this);
      try {
        this.symbolId = this.fd.decode(decoder);
      } catch (err: any) {
        if (err instanceof LowlevelError) {
          // Caused by a duplicate scope name. Preserve the address so we can find the original symbol
          throw new DuplicateFunctionError(this.fd.getAddress(), this.fd.getName());
        }
        throw err;
      }
      this.name = this.fd.getName();
      this.displayName = this.fd.getDisplayName();
      if (this.consumeSize < this.fd.getSize()) {
        if (this.fd.getSize() > 1 && this.fd.getSize() <= 8)
          this.consumeSize = this.fd.getSize();
      }
    } else {
      // functionshell
      decoder.openElement();
      this.symbolId = 0n;
      for (;;) {
        const attribId = decoder.getNextAttributeId();
        if (attribId === 0) break;
        if (attribId === ATTRIB_NAME.getId())
          this.name = decoder.readString();
        else if (attribId === ATTRIB_ID.getId()) {
          this.symbolId = decoder.readUnsignedInteger();
        } else if (attribId === ATTRIB_LABEL.getId()) {
          this.displayName = decoder.readString();
        }
      }
      decoder.closeElement(elemId);
    }
  }

  /** Get number of bytes consumed */
  override getBytesConsumed(): number {
    return this.consumeSize;
  }
}

// =========================================================================
// EquateSymbol
// =========================================================================

/**
 * A Symbol that holds equate information for a constant.
 *
 * This is a symbol that labels a constant. It can either replace the
 * constant's token with the symbol name, or it can force a conversion in
 * the emitted format of the constant.
 */
export class EquateSymbol extends Symbol {
  /** Value of the constant being equated */
  private value: bigint;

  /**
   * Create a symbol either to associate a name with a constant or to force
   * a display conversion.
   *
   * @param sc is the scope owning the new symbol
   * @param nm is the name of the equate (an empty string can be used for a convert)
   * @param format is the desired display conversion (0 for no conversion)
   * @param val is the constant value whose display is being altered
   */
  constructor(sc: Scope, nm: string, format: number, val: bigint);
  /** Constructor for use with decode */
  constructor(sc: Scope);
  constructor(sc: Scope, nm?: string, format?: number, val?: bigint) {
    if (nm !== undefined) {
      super(sc, nm, null);
      this.value = val!;
      this.category = Symbol.equate;
      this.type = sc.getArch().types.getBase(1, type_metatype.TYPE_UNKNOWN);
      this.dispflags |= format!;
    } else {
      super(sc);
      this.value = 0n;
      this.category = Symbol.equate;
    }
  }

  /** Get the constant value */
  getValue(): bigint { return this.value; }

  /**
   * Is the given value similar to this equate.
   *
   * An EquateSymbol should survive certain kinds of transforms during decompilation,
   * such as negation, twos-complementing, adding or subtracting 1.
   * Return true if the given value looks like a transform of this type relative
   * to the underlying value of this equate.
   */
  isValueClose(op2Value: bigint, size: number): boolean {
    if (this.value === op2Value) return true;
    const mask = calc_mask(size);
    const maskValue = this.value & mask;
    if (maskValue !== this.value) {
      // If '1' bits are getting masked off
      // Make sure only sign-extension is getting masked off
      if (this.value !== sign_extend(maskValue, size * 8))
        return false;
    }
    if (maskValue === (op2Value & mask)) return true;
    if (maskValue === (~op2Value & mask)) return true;
    if (maskValue === ((-op2Value) & mask)) return true;
    if (maskValue === ((op2Value + 1n) & mask)) return true;
    if (maskValue === ((op2Value - 1n) & mask)) return true;
    return false;
  }

  /** Encode this Symbol to a stream */
  override encode(encoder: Encoder): void {
    encoder.openElement(ELEM_EQUATESYMBOL);
    this.encodeHeader(encoder);
    encoder.openElement(ELEM_VALUE);
    encoder.writeUnsignedInteger(ATTRIB_CONTENT, this.value);
    encoder.closeElement(ELEM_VALUE);
    encoder.closeElement(ELEM_EQUATESYMBOL);
  }

  /** Decode this Symbol from a stream */
  override decode(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_EQUATESYMBOL);
    this.decodeHeader(decoder);

    const subId = decoder.openElementId(ELEM_VALUE);
    this.value = decoder.readUnsignedIntegerById(ATTRIB_CONTENT);
    decoder.closeElement(subId);

    const types: TypeFactory = this.scope.getArch().types;
    this.type = types.getBase(1, type_metatype.TYPE_UNKNOWN);
    decoder.closeElement(elemId);
  }
}

// =========================================================================
// UnionFacetSymbol
// =========================================================================

/**
 * A Symbol that forces a particular union field at a particular point in the
 * body of a function.
 *
 * This is an internal Symbol that users can create if they want to force a
 * particular interpretation of a union data-type. It attaches to data-flow
 * via the DynamicHash mechanism, which also allows it to attach to a specific
 * read or write of the target Varnode.
 */
export class UnionFacetSymbol extends Symbol {
  /** Particular field to associate with Symbol access */
  private fieldNum: number;

  /**
   * Constructor from components.
   * @param sc is the scope owning the new symbol
   * @param nm is the name of the symbol
   * @param unionDt is the union data-type being forced
   * @param fldNum is the particular field to force (-1 indicates the whole union)
   */
  constructor(sc: Scope, nm: string, unionDt: Datatype, fldNum: number);
  /** Constructor for decode */
  constructor(sc: Scope);
  constructor(sc: Scope, nm?: string, unionDt?: Datatype, fldNum?: number) {
    if (nm !== undefined) {
      super(sc, nm, unionDt!);
      this.fieldNum = fldNum!;
      this.category = Symbol.union_facet;
    } else {
      super(sc);
      this.fieldNum = -1;
      this.category = Symbol.union_facet;
    }
  }

  /** Get the particular field associated with this */
  getFieldNumber(): number { return this.fieldNum; }

  /** Encode this Symbol to a stream */
  override encode(encoder: Encoder): void {
    encoder.openElement(ELEM_FACETSYMBOL);
    this.encodeHeader(encoder);
    encoder.writeSignedInteger(ATTRIB_FIELD, this.fieldNum);
    this.encodeBody(encoder);
    encoder.closeElement(ELEM_FACETSYMBOL);
  }

  /** Decode this Symbol from a stream */
  override decode(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_FACETSYMBOL);
    this.decodeHeader(decoder);
    this.fieldNum = Number(decoder.readSignedIntegerById(ATTRIB_FIELD));

    this.decodeBody(decoder);
    decoder.closeElement(elemId);
    let testType: Datatype = this.type!;
    if (testType.getMetatype() === type_metatype.TYPE_PTR)
      testType = (testType as TypePointer).getPtrTo();
    if (testType.getMetatype() !== type_metatype.TYPE_UNION)
      throw new LowlevelError("<unionfacetsymbol> does not have a union type");
    if (this.fieldNum < -1 || this.fieldNum >= testType.numDepend())
      throw new LowlevelError("<unionfacetsymbol> field attribute is out of bounds");
  }
}

// =========================================================================
// LabSymbol
// =========================================================================

/**
 * A Symbol that labels code internal to a function.
 */
export class LabSymbol extends Symbol {
  /**
   * Build placeholder data-type.
   * Label symbols don't really have a data-type, so we just put a size 1 placeholder.
   */
  private buildType(): void {
    this.type = this.scope.getArch().types.getBase(1, type_metatype.TYPE_UNKNOWN);
  }

  /** Construct given name */
  constructor(sc: Scope, nm: string);
  /** Constructor for use with decode */
  constructor(sc: Scope);
  constructor(sc: Scope, nm?: string) {
    super(sc);
    if (nm !== undefined) {
      this.buildType();
      this.name = nm;
      this.displayName = nm;
    } else {
      this.buildType();
    }
  }

  /** Encode this Symbol to a stream */
  override encode(encoder: Encoder): void {
    encoder.openElement(ELEM_LABELSYM);
    this.encodeHeader(encoder); // We never set category
    encoder.closeElement(ELEM_LABELSYM);
  }

  /** Decode this Symbol from a stream */
  override decode(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_LABELSYM);
    this.decodeHeader(decoder);
    decoder.closeElement(elemId);
  }
}

// =========================================================================
// ExternRefSymbol
// =========================================================================

/**
 * A function Symbol referring to an external location.
 *
 * This Symbol is intended to label functions that have not been mapped directly into
 * the image being analyzed. It holds a level of indirection between the address the
 * image expects the symbol to be at and a placeholder address the system hangs
 * meta-data on.
 */
export class ExternRefSymbol extends Symbol {
  /** The placeholder address for meta-data */
  private refaddr: Address;

  /**
   * Create a name and data-type for the Symbol.
   * Build name, type, and flags based on the placeholder address.
   */
  private buildNameType(): void {
    const typegrp: TypeFactory = this.scope.getArch().types;
    let codeType = typegrp.getTypeCode();
    this.type = typegrp.getTypePointer(
      this.refaddr.getAddrSize(),
      codeType,
      this.refaddr.getSpace()!.getWordSize(),
    );
    if (this.name.length === 0) {
      // If a name was not already provided
      // Give the reference a unique name
      const sw = new StringWriter();
      sw.write(this.refaddr.getShortcut());
      sw.write(this.refaddr.printRaw());
      this.name = sw.toString();
      this.name += "_exref"; // Indicate this is an external reference variable
    }
    if (this.displayName.length === 0)
      this.displayName = this.name;
    this.flags |= Varnode.externref | Varnode.typelock;
  }

  /**
   * Construct given a placeholder address.
   * @param sc is the Scope containing the Symbol
   * @param ref is the placeholder address where the system will hold meta-data
   * @param nm is the name of the Symbol
   */
  constructor(sc: Scope, ref: Address, nm: string);
  /** For use with decode */
  constructor(sc: Scope);
  constructor(sc: Scope, ref?: Address, nm?: string) {
    if (ref !== undefined) {
      super(sc, nm!, null);
      this.refaddr = ref;
      this.buildNameType();
    } else {
      super(sc);
      this.refaddr = new Address();
    }
  }

  /** Return the placeholder address */
  getRefAddr(): Address { return this.refaddr; }

  /** Encode this Symbol to a stream */
  override encode(encoder: Encoder): void {
    encoder.openElement(ELEM_EXTERNREFSYMBOL);
    encoder.writeString(ATTRIB_NAME, this.name);
    this.refaddr.encode(encoder);
    encoder.closeElement(ELEM_EXTERNREFSYMBOL);
  }

  /** Decode this Symbol from a stream */
  override decode(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_EXTERNREFSYMBOL);
    this.name = '';
    this.displayName = '';
    for (;;) {
      const attribId = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_NAME.getId())
        this.name = decoder.readString();
      else if (attribId === ATTRIB_LABEL.getId())
        this.displayName = decoder.readString();
    }
    this.refaddr = Address.decode(decoder);
    decoder.closeElement(elemId);
    this.buildNameType();
  }
}

// =========================================================================
// SymbolCompareName
// =========================================================================

/**
 * Comparator for sorting Symbol objects by name.
 * Compare based on name. Use the deduplication id on the symbols if necessary.
 */
export function symbolCompareName(sym1: Symbol, sym2: Symbol): number {
  if (sym1.name < sym2.name) return -1;
  if (sym1.name > sym2.name) return 1;
  if (sym1.nameDedup < sym2.nameDedup) return -1;
  if (sym1.nameDedup > sym2.nameDedup) return 1;
  return 0;
}

// =========================================================================
// EntryMap (typedef for rangemap<SymbolEntry>)
// =========================================================================

/**
 * A simple representation of a rangemap of SymbolEntry objects within a single
 * address space. Stores SymbolEntry objects sorted by their starting offset.
 */
export class EntryMap {
  private entries: SymbolEntry[] = [];

  /** Return the number of entries */
  get length(): number { return this.entries.length; }

  /** Add a SymbolEntry to the map */
  addEntry(entry: SymbolEntry): SymbolEntry {
    this.entries.push(entry);
    // Keep sorted by first offset
    this.entries.sort((a, b) => {
      const aOff = a.getFirst();
      const bOff = b.getFirst();
      if (aOff < bOff) return -1;
      if (aOff > bOff) return 1;
      const aSub = a.getSubsort();
      const bSub = b.getSubsort();
      if (aSub.lessThan(bSub)) return -1;
      if (bSub.lessThan(aSub)) return 1;
      return 0;
    });
    return entry;
  }

  /** Iterator to the beginning of the list */
  begin_list(): number { return 0; }

  /** Iterator (index) past the end of the list */
  end_list(): number { return this.entries.length; }

  /** Get entry by index */
  getEntry(index: number): SymbolEntry { return this.entries[index]; }

  /** Get all entries as an array */
  getEntries(): SymbolEntry[] { return this.entries; }

  /** Alias for getEntries (C++ compatibility: list<SymbolEntry>::const_iterator) */
  getList(): SymbolEntry[] { return this.entries; }

  /** Remove a specific entry */
  removeEntry(entry: SymbolEntry): void {
    const idx = this.entries.indexOf(entry);
    if (idx >= 0) this.entries.splice(idx, 1);
  }

  /** Clear all entries */
  clear(): void { this.entries.length = 0; }

  /** Return the number of entries (used by part 2 code) */
  size(): number { return this.entries.length; }

  /** Insert a SymbolEntry (alias used by ScopeInternal), maintaining sorted order */
  insertEntry(entry: SymbolEntry): void {
    this.entries.push(entry);
    // Keep sorted by first offset, then subsort
    this.entries.sort((a, b) => {
      const aOff = a.getFirst();
      const bOff = b.getFirst();
      if (aOff < bOff) return -1;
      if (aOff > bOff) return 1;
      const aSub = a.getSubsort();
      const bSub = b.getSubsort();
      if (aSub.lessThan(bSub)) return -1;
      if (bSub.lessThan(aSub)) return 1;
      return 0;
    });
  }

  /** Erase (remove) a SymbolEntry (alias used by ScopeInternal) */
  eraseEntry(entry: SymbolEntry): void {
    const idx = this.entries.indexOf(entry);
    if (idx >= 0) this.entries.splice(idx, 1);
  }

  /** Find all entries whose range contains the given offset */
  findByOffset(offset: bigint): SymbolEntry[] {
    const result: SymbolEntry[] = [];
    for (const entry of this.entries) {
      if (entry.getFirst() <= offset && entry.getLast() >= offset) {
        result.push(entry);
      }
    }
    return result;
  }

  /** Find first entry whose range overlaps [first, last] */
  findOverlap(first: bigint, last: bigint): SymbolEntry | null {
    for (const entry of this.entries) {
      if (entry.getFirst() <= last && entry.getLast() >= first) {
        return entry;
      }
    }
    return null;
  }

  /** Get all entries as an array (alias used by part 2 MapIterator) */
  getAllEntries(): SymbolEntry[] { return this.entries; }
}

// =========================================================================
// MapIterator
// =========================================================================

/**
 * An iterator over SymbolEntry objects in multiple address spaces.
 *
 * Given an EntryMap (a rangemap of SymbolEntry objects in a single address space)
 * for each address space, iterate over all the SymbolEntry objects.
 */
export class MapIterator {
  /** The list of EntryMaps, one per address space */
  private map: (EntryMap | null)[] | null;
  /** Index of the current EntryMap being iterated */
  private curmap: number;
  /** Index of the current SymbolEntry within the current EntryMap */
  private curiter: number;

  /** Construct an uninitialized iterator */
  constructor();
  /**
   * Construct iterator at a specific position.
   * @param m is the list of EntryMaps
   * @param cm is the position of the iterator within the EntryMap list
   * @param ci is the position of the iterator within the specific EntryMap
   */
  constructor(m: (EntryMap | null)[], cm: number, ci: number);
  /** Copy constructor */
  constructor(op2: MapIterator);
  constructor(arg1?: (EntryMap | null)[] | MapIterator, arg2?: number, arg3?: number) {
    if (arg1 === undefined) {
      this.map = null;
      this.curmap = 0;
      this.curiter = 0;
    } else if (arg1 instanceof MapIterator) {
      this.map = arg1.map;
      this.curmap = arg1.curmap;
      this.curiter = arg1.curiter;
    } else {
      this.map = arg1;
      this.curmap = arg2!;
      this.curiter = arg3!;
    }
  }

  /** Return the SymbolEntry being pointed at */
  deref(): SymbolEntry {
    return this.map![this.curmap]!.getEntry(this.curiter);
  }

  /**
   * Pre-increment the iterator.
   * Advances to the next SymbolEntry, skipping over empty or null EntryMaps.
   */
  increment(): MapIterator {
    this.curiter += 1;
    while (this.curmap < this.map!.length &&
           (this.map![this.curmap] === null ||
            this.curiter >= this.map![this.curmap]!.end_list())) {
      do {
        this.curmap += 1;
      } while (this.curmap < this.map!.length && this.map![this.curmap] === null);
      if (this.curmap < this.map!.length)
        this.curiter = this.map![this.curmap]!.begin_list();
    }
    return this;
  }

  /**
   * Post-increment the iterator.
   * Returns a copy of the iterator before it was advanced.
   */
  postIncrement(): MapIterator {
    const tmp = new MapIterator(this);
    this.increment();
    return tmp;
  }

  /** Assignment from another MapIterator */
  assign(op2: MapIterator): MapIterator {
    this.map = op2.map;
    this.curmap = op2.curmap;
    this.curiter = op2.curiter;
    return this;
  }

  /** Equality comparison */
  equals(op2: MapIterator): boolean {
    if (this.curmap !== op2.curmap) return false;
    if (this.map !== null && this.curmap >= this.map.length) return true;
    return this.curiter === op2.curiter;
  }

  /** Inequality comparison */
  notEquals(op2: MapIterator): boolean {
    return !this.equals(op2);
  }
}

// ---------------------------------------------------------------------------
// Part 2: Scope, ScopeInternal, Database classes
// ---------------------------------------------------------------------------

type JoinRecord = any;
type VarnodeData = any;
type HighVariable = any;

// ---------------------------------------------------------------------------
// Varnode flag constants (mirrors varnode.ts exports)
// ---------------------------------------------------------------------------

const Varnode_mark             = 0x01;
const Varnode_constant         = 0x02;
const Varnode_annotation       = 0x04;
const Varnode_input            = 0x08;
const Varnode_written          = 0x10;
const Varnode_insert           = 0x20;
const Varnode_implied          = 0x40;
const Varnode_explict          = 0x80;
const Varnode_typelock         = 0x100;
const Varnode_namelock         = 0x200;
const Varnode_nolocalalias     = 0x400;
const Varnode_volatil          = 0x800;
const Varnode_externref        = 0x1000;
const Varnode_readonly         = 0x2000;
const Varnode_persist          = 0x4000;
const Varnode_addrtied         = 0x8000;
const Varnode_unaffected       = 0x10000;
const Varnode_spacebase        = 0x20000;
const Varnode_indirectonly     = 0x40000;
const Varnode_directwrite      = 0x80000;
const Varnode_addrforce        = 0x100000;
const Varnode_mapped           = 0x200000;
const Varnode_indirect_creation = 0x400000;
const Varnode_return_address   = 0x800000;
const Varnode_coverdirty       = 0x1000000;
const Varnode_precislo         = 0x2000000;
const Varnode_precishi         = 0x4000000;
const Varnode_indirectstorage  = 0x8000000;
const Varnode_hiddenretparm    = 0x10000000;
const Varnode_incidental_copy  = 0x20000000;

// Alias object to mirror C++ Varnode::flag usage
const VarnodeFlags = {
  mark: Varnode_mark,
  constant: Varnode_constant,
  annotation: Varnode_annotation,
  input: Varnode_input,
  written: Varnode_written,
  insert: Varnode_insert,
  implied: Varnode_implied,
  explict: Varnode_explict,
  typelock: Varnode_typelock,
  namelock: Varnode_namelock,
  nolocalalias: Varnode_nolocalalias,
  volatil: Varnode_volatil,
  externref: Varnode_externref,
  readonly: Varnode_readonly,
  persist: Varnode_persist,
  addrtied: Varnode_addrtied,
  unaffected: Varnode_unaffected,
  spacebase: Varnode_spacebase,
  indirectonly: Varnode_indirectonly,
  directwrite: Varnode_directwrite,
  addrforce: Varnode_addrforce,
  mapped: Varnode_mapped,
  indirect_creation: Varnode_indirect_creation,
  return_address: Varnode_return_address,
  coverdirty: Varnode_coverdirty,
  precislo: Varnode_precislo,
  precishi: Varnode_precishi,
  indirectstorage: Varnode_indirectstorage,
  hiddenretparm: Varnode_hiddenretparm,
  incidental_copy: Varnode_incidental_copy,
};

// ---------------------------------------------------------------------------
// ScopeMap: Map from bigint id to Scope
// ---------------------------------------------------------------------------

type ScopeMap = Map<bigint, Scope>;

// =========================================================================
// Scope  (abstract base class)
// =========================================================================

/**
 * A collection of Symbol objects within a single (namespace or functional) scope.
 *
 * This acts as a traditional Symbol container, allowing lookup by name, by storage
 * address, by symbol type, by containing range, or by overlapping range.
 *
 * A scope also supports the idea of ownership of memory -- for a Symbol in the scope,
 * the scope owns the storage memory within certain code locations. The global Scope
 * usually owns all memory in the ram address space.
 */
abstract class Scope {
  // ---- private fields ----
  private rangetree: any;         // RangeList: Range of data addresses owned by this scope
  private _parent: Scope | null;
  private owner: Scope;
  private children: ScopeMap;

  // ---- protected fields ----
  protected glb: Architecture;
  protected name: string;
  protected displayName: string;
  protected fd: Funcdata | null;
  protected uniqueId: bigint;

  // ------------------------------------------------------------------
  // Static methods for stack-based scope walking
  // ------------------------------------------------------------------

  /**
   * Hash a scope name combined with a parent scope id to produce a unique id.
   */
  static hashScopeName(baseId: bigint, nm: string): bigint {
    let reg1 = Number((baseId >> 32n) & 0xFFFFFFFFn);
    let reg2 = Number(baseId & 0xFFFFFFFFn);
    reg1 = crc_update(reg1, 0xa9);
    reg2 = crc_update(reg2, reg1 & 0xFF);
    for (let i = 0; i < nm.length; i++) {
      const val = nm.charCodeAt(i);
      reg1 = crc_update(reg1, val & 0xFF);
      reg2 = crc_update(reg2, reg1 & 0xFF);
    }
    return (BigInt(reg1 >>> 0) << 32n) | BigInt(reg2 >>> 0);
  }

  /**
   * Query for Symbols starting at a given address, walking up the scope hierarchy.
   * Returns the Scope owning the address, and passes back any matching SymbolEntry.
   */
  static stackAddr(
    scope1: Scope | null,
    scope2: Scope | null,
    addr: any,
    usepoint: any,
  ): { scope: Scope | null; entry: SymbolEntry | null } {
    if (addr.isConstant()) return { scope: null, entry: null };
    let cur = scope1;
    while (cur !== null && cur !== scope2) {
      const entry = cur.findAddr(addr, usepoint);
      if (entry !== null) {
        return { scope: cur, entry };
      }
      if (cur.inScope(addr, 1, usepoint)) {
        return { scope: cur, entry: null };
      }
      cur = cur.getParent();
    }
    return { scope: null, entry: null };
  }

  /**
   * Query for a Symbol containing a given range, walking up the scope hierarchy.
   */
  static stackContainer(
    scope1: Scope | null,
    scope2: Scope | null,
    addr: any,
    size: number,
    usepoint: any,
  ): { scope: Scope | null; entry: SymbolEntry | null } {
    if (addr.isConstant()) return { scope: null, entry: null };
    let cur = scope1;
    while (cur !== null && cur !== scope2) {
      const entry = cur.findContainer(addr, size, usepoint);
      if (entry !== null) {
        return { scope: cur, entry };
      }
      if (cur.inScope(addr, size, usepoint)) {
        return { scope: cur, entry: null };
      }
      cur = cur.getParent();
    }
    return { scope: null, entry: null };
  }

  /**
   * Query for a Symbol which most closely matches a given range, walking up the scope hierarchy.
   */
  static stackClosestFit(
    scope1: Scope | null,
    scope2: Scope | null,
    addr: any,
    size: number,
    usepoint: any,
  ): { scope: Scope | null; entry: SymbolEntry | null } {
    if (addr.isConstant()) return { scope: null, entry: null };
    let cur = scope1;
    while (cur !== null && cur !== scope2) {
      const entry = cur.findClosestFit(addr, size, usepoint);
      if (entry !== null) {
        return { scope: cur, entry };
      }
      if (cur.inScope(addr, size, usepoint)) {
        return { scope: cur, entry: null };
      }
      cur = cur.getParent();
    }
    return { scope: null, entry: null };
  }

  /**
   * Query for a function Symbol at the given address, walking up the scope hierarchy.
   */
  static stackFunction(
    scope1: Scope | null,
    scope2: Scope | null,
    addr: any,
  ): { scope: Scope | null; fd: Funcdata | null } {
    if (addr.isConstant()) return { scope: null, fd: null };
    let cur = scope1;
    while (cur !== null && cur !== scope2) {
      const fd = cur.findFunction(addr);
      if (fd !== null) {
        return { scope: cur, fd };
      }
      if (cur.inScope(addr, 1, new Address()))
        return { scope: cur, fd: null };
      cur = cur.getParent();
    }
    return { scope: null, fd: null };
  }

  /**
   * Query for an external reference Symbol, walking up the scope hierarchy.
   */
  static stackExternalRef(
    scope1: Scope | null,
    scope2: Scope | null,
    addr: any,
  ): { scope: Scope | null; sym: ExternRefSymbol | null } {
    if (addr.isConstant()) return { scope: null, sym: null };
    let cur = scope1;
    while (cur !== null && cur !== scope2) {
      const sym = cur.findExternalRef(addr);
      if (sym !== null) {
        return { scope: cur, sym };
      }
      // Don't do discovery for external refs (see C++ comment)
      cur = cur.getParent();
    }
    return { scope: null, sym: null };
  }

  /**
   * Query for a label Symbol at the given address, walking up the scope hierarchy.
   */
  static stackCodeLabel(
    scope1: Scope | null,
    scope2: Scope | null,
    addr: any,
  ): { scope: Scope | null; sym: LabSymbol | null } {
    if (addr.isConstant()) return { scope: null, sym: null };
    let cur = scope1;
    while (cur !== null && cur !== scope2) {
      const sym = cur.findCodeLabel(addr);
      if (sym !== null) {
        return { scope: cur, sym };
      }
      if (cur.inScope(addr, 1, new Address()))
        return { scope: cur, sym: null };
      cur = cur.getParent();
    }
    return { scope: null, sym: null };
  }

  // ------------------------------------------------------------------
  // Constructor / destructor
  // ------------------------------------------------------------------

  constructor(id: bigint, nm: string, g: Architecture, own: Scope | null) {
    this.uniqueId = id;
    this.name = nm;
    this.displayName = nm;
    this.glb = g;
    this._parent = null;
    this.fd = null;
    this.owner = own ?? (this as Scope);
    this.children = new Map();
    this.rangetree = new RangeList();
  }

  dispose(): void {
    for (const [, child] of this.children) {
      child.dispose();
    }
    this.children.clear();
  }

  // ------------------------------------------------------------------
  // Private helpers
  // ------------------------------------------------------------------

  private attachScope(child: Scope): void {
    child._parent = this;
    this.children.set(child.uniqueId, child);
  }

  private detachScope(id: bigint): void {
    const child = this.children.get(id);
    if (child !== undefined) {
      this.children.delete(id);
      child.dispose();
    }
  }

  // ------------------------------------------------------------------
  // Protected virtual methods (abstract or overridable)
  // ------------------------------------------------------------------

  protected abstract buildSubScope(id: bigint, nm: string): Scope;

  protected restrictScope(f: Funcdata): void {
    this.fd = f;
  }

  protected addRange(spc: AddrSpace, first: bigint, last: bigint): void {
    this.rangetree.insertRange(spc, first, last);
  }

  protected removeRange(spc: AddrSpace, first: bigint, last: bigint): void {
    this.rangetree.removeRange(spc, first, last);
  }

  protected abstract addSymbolInternal(sym: Symbol): void;

  protected abstract addMapInternal(
    sym: Symbol,
    exfl: number,
    addr: any,
    off: number,
    sz: number,
    uselim: any,
  ): SymbolEntry;

  protected abstract addDynamicMapInternal(
    sym: Symbol,
    exfl: number,
    hash: bigint,
    off: number,
    sz: number,
    uselim: any,
  ): SymbolEntry;

  /**
   * Integrate an unintegrated SymbolEntry into the range maps.
   * Handles join-address decomposition into pieces.
   */
  protected addMap(entry: SymbolEntry): SymbolEntry {
    // Set properties based on scope
    if (this.isGlobal()) {
      entry.symbol.flags |= Varnode_persist;
    } else if (entry.addr !== null && !entry.addr.isInvalid()) {
      const glbScope = this.glb.symboltab.getGlobalScope();
      const addr = new Address();
      if (glbScope.inScope(entry.addr, 1, addr)) {
        entry.symbol.flags |= Varnode_persist;
        entry.uselimit.clear();
      }
    }

    let res: SymbolEntry;
    const consumeSize = entry.symbol.getBytesConsumed();
    if (entry.addr === null || entry.addr.isInvalid()) {
      res = this.addDynamicMapInternal(
        entry.symbol, Varnode_mapped, entry.hash, 0, consumeSize, entry.uselimit,
      );
    } else {
      if (entry.uselimit.empty()) {
        entry.symbol.flags |= Varnode_addrtied;
        entry.symbol.flags |= this.glb.symboltab.getProperty(entry.addr);
      }
      res = this.addMapInternal(
        entry.symbol, Varnode_mapped, entry.addr, 0, consumeSize, entry.uselimit,
      );
      if (entry.addr.isJoin()) {
        const rec: JoinRecord = this.glb.findJoin(entry.addr.getOffset());
        const num = rec.numPieces();
        let off = 0;
        const bigendian = entry.addr.isBigEndian();
        for (let j = 0; j < num; j++) {
          const i = bigendian ? j : (num - 1 - j);
          const vdat: VarnodeData = rec.getPiece(i);
          let exfl: number;
          if (i === 0) {
            exfl = Varnode_precishi;
          } else if (i === num - 1) {
            exfl = Varnode_precislo;
          } else {
            exfl = Varnode_precislo | Varnode_precishi;
          }
          this.addMapInternal(
            entry.symbol, exfl, vdat.getAddr(), off, vdat.size, entry.uselimit,
          );
          off += vdat.size;
        }
      }
    }
    return res;
  }

  protected setSymbolId(sym: Symbol, id: bigint): void {
    sym.symbolId = id;
  }

  protected setDisplayName(nm: string): void {
    this.displayName = nm;
  }

  protected getRangeTree(): any {
    return this.rangetree;
  }

  // ------------------------------------------------------------------
  // Public abstract (virtual) methods
  // ------------------------------------------------------------------

  abstract begin(): MapIterator;
  abstract end(): MapIterator;
  abstract beginDynamic(): SymbolEntry[];
  abstract endDynamic(): SymbolEntry[];
  abstract clear(): void;
  abstract clearCategory(cat: number): void;
  abstract clearUnlocked(): void;
  abstract clearUnlockedCategory(cat: number): void;
  abstract adjustCaches(): void;

  /**
   * Query if the given range is owned by this Scope.
   */
  inScope(addr: any, size: number, usepoint: any): boolean {
    return this.rangetree.inRange(addr, size);
  }

  abstract removeSymbolMappings(symbol: Symbol): void;
  abstract removeSymbol(symbol: Symbol): void;
  abstract renameSymbol(sym: Symbol, newname: string): void;
  abstract retypeSymbol(sym: Symbol, ct: Datatype): void;
  abstract setAttribute(sym: Symbol, attr: number): void;
  abstract clearAttribute(sym: Symbol, attr: number): void;
  abstract setDisplayFormat(sym: Symbol, attr: number): void;

  abstract findAddr(addr: any, usepoint: any): SymbolEntry | null;
  abstract findContainer(addr: any, size: number, usepoint: any): SymbolEntry | null;
  abstract findClosestFit(addr: any, size: number, usepoint: any): SymbolEntry | null;
  abstract findFunction(addr: any): Funcdata | null;
  abstract findExternalRef(addr: any): ExternRefSymbol | null;
  abstract findCodeLabel(addr: any): LabSymbol | null;
  abstract findOverlap(addr: any, size: number): SymbolEntry | null;
  abstract findByName(nm: string): Symbol[];
  abstract isNameUsed(nm: string, op2: Scope | null): boolean;
  abstract resolveExternalRefFunction(sym: ExternRefSymbol): Funcdata | null;
  abstract buildVariableName(addr: any, pc: any, ct: Datatype, index: { val: number }, flags: number): string;
  abstract buildUndefinedName(): string;
  abstract makeNameUnique(nm: string): string;
  abstract encode(encoder: Encoder): void;
  abstract decode(decoder: Decoder): void;

  decodeWrappingAttributes(decoder: Decoder): void {
    // Default does nothing
  }

  abstract printEntries(s: Writer): void;
  abstract getCategorySize(cat: number): number;
  abstract getCategorySymbol(cat: number, ind: number): Symbol | null;
  abstract setCategory(sym: Symbol, cat: number, ind: number): void;

  // ------------------------------------------------------------------
  // Non-abstract public interface: addSymbol variants
  // ------------------------------------------------------------------

  /**
   * Add a new Symbol without mapping it to an address.
   */
  addSymbol(nm: string, ct: Datatype): Symbol;
  /**
   * Add a new Symbol with a single mapping (address + usepoint).
   */
  addSymbol(nm: string, ct: Datatype, addr: any, usepoint: any): SymbolEntry;
  addSymbol(nm: string, ct: Datatype, addr?: any, usepoint?: any): Symbol | SymbolEntry {
    if (addr !== undefined) {
      // Overload with address mapping
      if (ct.hasStripped()) ct = ct.getStripped()!;
      const sym = new Symbol(this.owner, nm, ct);
      this.addSymbolInternal(sym);
      return this.addMapPoint(sym, addr, usepoint);
    }
    // Overload without address
    const sym = new Symbol(this.owner, nm, ct);
    this.addSymbolInternal(sym);
    return sym;
  }

  // ------------------------------------------------------------------
  // Public non-virtual accessors
  // ------------------------------------------------------------------

  getName(): string { return this.name; }
  getDisplayName(): string { return this.displayName; }
  getId(): bigint { return this.uniqueId; }
  isGlobal(): boolean { return this.fd === null; }
  getArch(): Architecture { return this.glb; }
  getParent(): Scope | null { return this._parent; }
  childrenBegin(): IterableIterator<[bigint, Scope]> { return this.children.entries(); }
  childrenEnd(): void { /* iterator exhaustion signals end */ }

  // ------------------------------------------------------------------
  // Public query methods (walk scope hierarchy)
  // ------------------------------------------------------------------

  /**
   * Look up symbols by name, recursing into parent scopes.
   */
  queryByName(nm: string): Symbol[] {
    const res = this.findByName(nm);
    if (res.length > 0) return res;
    if (this._parent !== null) return this._parent.queryByName(nm);
    return [];
  }

  /**
   * Look up a function by name, recursing into parent scopes.
   */
  queryFunction(nm: string): Funcdata | null;
  queryFunction(addr: any): Funcdata | null;
  queryFunction(arg: any): Funcdata | null {
    if (typeof arg === 'string') {
      const symList = this.queryByName(arg);
      for (const sym of symList) {
        if (sym instanceof FunctionSymbol) {
          return sym.getFunction();
        }
      }
      return null;
    }
    // address overload
    const addr = arg;
    const basescope = this.glb.symboltab.mapScope(this, addr, new Address());
    const result = Scope.stackFunction(basescope, null, addr);
    return result.fd;
  }

  /**
   * Get Symbol with matching address within scope hierarchy.
   */
  queryByAddr(addr: any, usepoint: any): SymbolEntry | null {
    const basescope = this.glb.symboltab.mapScope(this, addr, usepoint);
    const result = Scope.stackAddr(basescope, null, addr, usepoint);
    return result.entry;
  }

  /**
   * Find the smallest containing Symbol within scope hierarchy.
   */
  queryContainer(addr: any, size: number, usepoint: any): SymbolEntry | null {
    const basescope = this.glb.symboltab.mapScope(this, addr, usepoint);
    const result = Scope.stackContainer(basescope, null, addr, size, usepoint);
    return result.entry;
  }

  /**
   * Find a Symbol or properties at the given address within scope hierarchy.
   */
  queryProperties(addr: any, size: number, usepoint: any): { entry: SymbolEntry | null; flags: number } {
    const basescope = this.glb.symboltab.mapScope(this, addr, usepoint);
    const result = Scope.stackContainer(basescope, null, addr, size, usepoint);
    let flags: number;
    if (result.entry !== null) {
      flags = result.entry.getAllFlags();
    } else if (result.scope !== null) {
      flags = Varnode_mapped | Varnode_addrtied;
      if (result.scope.isGlobal()) flags |= Varnode_persist;
      flags |= this.glb.symboltab.getProperty(addr);
    } else {
      flags = this.glb.symboltab.getProperty(addr);
    }
    return { entry: result.entry, flags };
  }

  /**
   * Look up a function thru an external reference.
   */
  queryExternalRefFunction(addr: any): Funcdata | null {
    const basescope = this.glb.symboltab.mapScope(this, addr, new Address());
    const result = Scope.stackExternalRef(basescope, null, addr);
    if (result.sym !== null && result.scope !== null) {
      return result.scope.resolveExternalRefFunction(result.sym);
    }
    return null;
  }

  /**
   * Look up a code label by address within scope hierarchy.
   */
  queryCodeLabel(addr: any): LabSymbol | null {
    const basescope = this.glb.symboltab.mapScope(this, addr, new Address());
    const result = Scope.stackCodeLabel(basescope, null, addr);
    return result.sym;
  }

  // ------------------------------------------------------------------
  // Scope resolution
  // ------------------------------------------------------------------

  /**
   * Find a child Scope of this by name.
   * @param nm - the child's name
   * @param strategy - true if hash of the name determines id
   */
  resolveScope(nm: string, strategy: boolean): Scope | null {
    if (strategy) {
      const key = Scope.hashScopeName(this.uniqueId, nm);
      const scope = this.children.get(key);
      if (scope === undefined) return null;
      if (scope.name === nm) return scope;
    } else if (nm.length > 0 && nm.charCodeAt(0) >= 48 && nm.charCodeAt(0) <= 57) {
      // Allow the string to directly specify the id
      const key = BigInt(nm);
      const scope = this.children.get(key);
      if (scope === undefined) return null;
      return scope;
    } else {
      for (const [, scope] of this.children) {
        if (scope.name === nm) return scope;
      }
    }
    return null;
  }

  /**
   * Discover which scope should own the given memory range.
   */
  discoverScope(addr: any, sz: number, usepoint: any): Scope | null {
    if (addr.isConstant()) return null;
    let basescope: Scope | null = this.glb.symboltab.mapScope(this, addr, usepoint);
    while (basescope !== null) {
      if (basescope.inScope(addr, sz, usepoint)) return basescope;
      basescope = basescope.getParent();
    }
    return null;
  }

  /**
   * Encode all contained scopes to a stream in post order.
   */
  encodeRecursive(encoder: Encoder, onlyGlobal: boolean): void {
    if (onlyGlobal && !this.isGlobal()) return;
    this.encode(encoder);
    for (const [, child] of this.children) {
      child.encodeRecursive(encoder, onlyGlobal);
    }
  }

  /**
   * Change the data-type of a size-locked Symbol.
   */
  overrideSizeLockType(sym: Symbol, ct: Datatype): void {
    if (sym.type!.getSize() === ct.getSize()) {
      if (!sym.isSizeTypeLocked()) {
        throw new Error("Overriding symbol that is not size locked");
      }
      sym.type = ct;
      return;
    }
    throw new Error("Overriding symbol with different type size");
  }

  /**
   * Clear a Symbol's size-locked data-type back to UNKNOWN.
   */
  resetSizeLockType(sym: Symbol): void {
    if (sym.type!.getMetatype() === type_metatype.TYPE_UNKNOWN) return;
    const size = sym.type!.getSize();
    sym.type = this.glb.types.getBase(size, type_metatype.TYPE_UNKNOWN);
  }

  /**
   * Toggle the given Symbol as the "this" pointer.
   */
  setThisPointer(sym: Symbol, val: boolean): void {
    sym.setThisPointer(val);
  }

  /**
   * Is this a sub-scope of the given Scope?
   */
  isSubScope(scp: Scope): boolean {
    let tmp: Scope | null = this;
    while (tmp !== null) {
      if (tmp === scp) return true;
      tmp = tmp._parent;
    }
    return false;
  }

  /**
   * Get the full namespace-qualified name of this Scope.
   */
  getFullName(): string {
    if (this._parent === null) return "";
    let fname = this.name;
    let scope = this._parent;
    while (scope !== null && scope._parent !== null) {
      fname = scope.name + "::" + fname;
      scope = scope._parent;
    }
    return fname;
  }

  /**
   * Get the ordered list of scopes from the global scope to this.
   */
  getScopePath(): Scope[] {
    let count = 0;
    let cur: Scope | null = this;
    while (cur !== null) {
      count++;
      cur = cur._parent;
    }
    const vec: Scope[] = new Array(count);
    cur = this;
    while (cur !== null) {
      count--;
      vec[count] = cur;
      cur = cur._parent;
    }
    return vec;
  }

  /**
   * Find first ancestor of this not shared by given scope.
   */
  findDistinguishingScope(op2: Scope): Scope | null {
    if (this === op2) return null;
    if (this._parent === op2) return this;
    if (op2._parent === this) return null;
    if (this._parent === op2._parent) return this;

    const thisPath = this.getScopePath();
    const op2Path = op2.getScopePath();
    const min = Math.min(thisPath.length, op2Path.length);
    for (let i = 0; i < min; i++) {
      if (thisPath[i] !== op2Path[i]) return thisPath[i];
    }
    if (min < thisPath.length) return thisPath[min];
    if (min < op2Path.length) return null;
    return this;
  }

  // ------------------------------------------------------------------
  // Public factory methods for Symbols
  // ------------------------------------------------------------------

  /**
   * Map a Symbol to a specific address.
   */
  addMapPoint(sym: Symbol, addr: any, usepoint: any): SymbolEntry {
    const entry = new SymbolEntry(sym);
    if (usepoint !== null && usepoint !== undefined && !usepoint.isInvalid()) {
      entry.uselimit.insertRange(usepoint.getSpace(), usepoint.getOffset(), usepoint.getOffset());
    }
    entry.addr = addr;
    return this.addMap(entry);
  }

  /**
   * Parse a mapped Symbol from a <mapsym> element.
   */
  addMapSym(decoder: Decoder): Symbol | null {
    const elemId = decoder.openElementId(ELEM_MAPSYM);
    const subId = decoder.peekElement();
    let sym: Symbol;

    if (subId === ELEM_SYMBOL.getId()) {
      sym = new Symbol(this.owner);
    } else if (subId === ELEM_EQUATESYMBOL.getId()) {
      sym = new EquateSymbol(this.owner);
    } else if (subId === ELEM_FUNCTION.getId() || subId === ELEM_FUNCTIONSHELL.getId()) {
      sym = new FunctionSymbol(this.owner, this.glb.min_funcsymbol_size);
    } else if (subId === ELEM_LABELSYM.getId()) {
      sym = new LabSymbol(this.owner);
    } else if (subId === ELEM_EXTERNREFSYMBOL.getId()) {
      sym = new ExternRefSymbol(this.owner);
    } else if (subId === ELEM_FACETSYMBOL.getId()) {
      sym = new UnionFacetSymbol(this.owner);
    } else {
      throw new Error("Unknown symbol type");
    }

    try {
      sym.decode(decoder);
    } catch (err) {
      throw err;
    }

    this.addSymbolInternal(sym);

    while (decoder.peekElement() !== 0) {
      const entry = new SymbolEntry(sym);
      entry.decode(decoder);
      if (entry.isInvalid()) {
        this.glb.printMessage("WARNING: Throwing out symbol with invalid mapping: " + sym.getName());
        this.removeSymbol(sym);
        decoder.closeElement(elemId);
        return null;
      }
      this.addMap(entry);
    }
    decoder.closeElement(elemId);
    return sym;
  }

  /**
   * Create a function Symbol at the given address.
   */
  addFunction(addr: any, nm: string): FunctionSymbol {
    const overlap = this.queryContainer(addr, 1, new Address());
    if (overlap !== null) {
      const errmsg = "WARNING: Function " + this.name + " overlaps object: " + overlap.getSymbol().getName();
      this.glb.printMessage(errmsg);
    }
    const sym = new FunctionSymbol(this.owner, nm, this.glb.min_funcsymbol_size);
    this.addSymbolInternal(sym);
    this.addMapPoint(sym, addr, new Address());
    return sym;
  }

  /**
   * Create an external reference at the given address.
   */
  addExternalRef(addr: any, refaddr: any, nm: string): ExternRefSymbol {
    const sym = new ExternRefSymbol(this.owner, refaddr, nm);
    this.addSymbolInternal(sym);
    const ret = this.addMapPoint(sym, addr, new Address());
    // Even if external ref is in readonly region, treat as not readonly
    ret.symbol.flags &= ~Varnode_readonly;
    return sym;
  }

  /**
   * Create a code label at the given address.
   */
  addCodeLabel(addr: any, nm: string): LabSymbol {
    const overlap = this.queryContainer(addr, 1, addr);
    if (overlap !== null) {
      const errmsg = "WARNING: Codelabel " + nm + " overlaps object: " + overlap.getSymbol().getName();
      this.glb.printMessage(errmsg);
    }
    const sym = new LabSymbol(this.owner, nm);
    this.addSymbolInternal(sym);
    this.addMapPoint(sym, addr, new Address());
    return sym;
  }

  /**
   * Create a dynamically mapped Symbol attached to specific data-flow.
   */
  addDynamicSymbol(nm: string, ct: Datatype, caddr: any, hash: bigint): Symbol {
    const sym = new Symbol(this.owner, nm, ct);
    this.addSymbolInternal(sym);
    const rnglist = new RangeList();
    if (caddr !== null && !caddr.isInvalid()) {
      rnglist.insertRange(caddr.getSpace(), caddr.getOffset(), caddr.getOffset());
    }
    this.addDynamicMapInternal(sym, Varnode_mapped, hash, 0, ct.getSize(), rnglist);
    return sym;
  }

  /**
   * Create a symbol that forces display conversion on a constant.
   */
  addEquateSymbol(nm: string, format: number, value: bigint, addr: any, hash: bigint): Symbol {
    const sym = new EquateSymbol(this.owner, nm, format, value);
    this.addSymbolInternal(sym);
    const rnglist = new RangeList();
    if (addr !== null && !addr.isInvalid()) {
      rnglist.insertRange(addr.getSpace(), addr.getOffset(), addr.getOffset());
    }
    this.addDynamicMapInternal(sym, Varnode_mapped, hash, 0, 1, rnglist);
    return sym;
  }

  /**
   * Create a symbol forcing a field interpretation for a union data-type.
   */
  addUnionFacetSymbol(nm: string, dt: Datatype, fieldNum: number, addr: any, hash: bigint): Symbol {
    const sym = new UnionFacetSymbol(this.owner, nm, dt, fieldNum);
    this.addSymbolInternal(sym);
    const rnglist = new RangeList();
    if (addr !== null && !addr.isInvalid()) {
      rnglist.insertRange(addr.getSpace(), addr.getOffset(), addr.getOffset());
    }
    this.addDynamicMapInternal(sym, Varnode_mapped, hash, 0, 1, rnglist);
    return sym;
  }

  /**
   * Create a default name for a Symbol based on context.
   */
  buildDefaultName(sym: Symbol, base: { val: number }, vn: Varnode | null): string {
    if (vn !== null && !vn.isConstant()) {
      let usepoint = new Address();
      if (!vn.isAddrTied() && this.fd !== null) {
        usepoint = vn.getUsePoint(this.fd);
      }
      if (!vn.hasHigh()) {
        return this.buildVariableName(vn.getAddr(), usepoint, sym.getType(), base, vn.getFlags());
      }
      const high = vn.getHigh();
      if (sym.getCategory() === Symbol.function_parameter || high.isInput()) {
        let index = -1;
        if (sym.getCategory() === Symbol.function_parameter)
          index = sym.getCategoryIndex() + 1;
        return this.buildVariableName(
          vn.getAddr(), usepoint, sym.getType(), { val: index },
          vn.getFlags() | Varnode_input,
        );
      }
      return this.buildVariableName(vn.getAddr(), usepoint, sym.getType(), base, vn.getFlags());
    }
    if (sym.numEntries() !== 0) {
      const entry = sym.getMapEntry(0);
      const addr = entry.getAddr();
      const usepoint = entry.getFirstUseAddress();
      let flags = (usepoint === null || usepoint.isInvalid()) ? Varnode_addrtied : 0;
      if (sym.getCategory() === Symbol.function_parameter) {
        flags |= Varnode_input;
        const index = sym.getCategoryIndex() + 1;
        return this.buildVariableName(addr, usepoint, sym.getType(), { val: index }, flags);
      }
      return this.buildVariableName(addr, usepoint, sym.getType(), base, flags);
    }
    return this.buildVariableName(new Address(), new Address(), sym.getType(), base, 0);
  }

  /**
   * Is the given memory range marked as read-only?
   */
  isReadOnly(addr: any, size: number, usepoint: any): boolean {
    const result = this.queryProperties(addr, size, usepoint);
    return (result.flags & Varnode_readonly) !== 0;
  }

  /**
   * Print a description of this Scope's owned memory ranges.
   */
  printBounds(s: Writer): void {
    this.rangetree.printBounds(s);
  }
}

// =========================================================================
// ScopeInternal  (concrete in-memory scope implementation)
// =========================================================================

/**
 * An in-memory implementation of the Scope interface.
 *
 * Implements a nametree (sorted set of Symbol objects) and a maptable
 * (array of EntryMap, one per address space) plus a list of dynamic entries.
 */
export class ScopeInternal extends Scope {
  protected nametree: SortedSet<Symbol>;
  protected maptable: Array<EntryMap | null>;
  protected category: Symbol[][];
  protected dynamicentry: SymbolEntry[];
  protected multiEntrySet: SortedSet<Symbol>;
  protected nextUniqueId: bigint;

  constructor(id: bigint, nm: string, g: Architecture);
  constructor(id: bigint, nm: string, g: Architecture, own: Scope);
  constructor(id: bigint, nm: string, g: Architecture, own?: Scope) {
    super(id, nm, g, own !== undefined ? own : null);
    this.nextUniqueId = 0n;
    this.nametree = new SortedSet<Symbol>(symbolCompareName);
    this.multiEntrySet = new SortedSet<Symbol>(symbolCompareName);
    this.category = [];
    this.dynamicentry = [];
    const numSpaces = g && g.numSpaces ? g.numSpaces() : 0;
    this.maptable = new Array(numSpaces).fill(null);
  }

  dispose(): void {
    for (let i = 0; i < this.maptable.length; i++) {
      this.maptable[i] = null;
    }
    // Symbols owned by nametree are garbage-collected
    this.nametree.clear();
    this.multiEntrySet.clear();
    super.dispose();
  }

  // ------------------------------------------------------------------
  // Protected overrides
  // ------------------------------------------------------------------

  protected buildSubScope(id: bigint, nm: string): Scope {
    return new ScopeInternal(id, nm, this.getArch());
  }

  protected addSymbolInternal(sym: Symbol): void {
    if (sym.symbolId === 0n) {
      sym.symbolId = Symbol.ID_BASE + ((this.getId() & 0xFFFFn) << 40n) + this.nextUniqueId;
      this.nextUniqueId += 1n;
    }
    if (sym.name.length === 0) {
      sym.name = this.buildUndefinedName();
      sym.displayName = sym.name;
    }
    if (sym.getType() === null) {
      throw new Error(sym.getName() + " symbol created with no type");
    }
    if (sym.getType().getSize() < 1) {
      throw new Error(sym.getName() + " symbol created with zero size type");
    }
    this.insertNameTree(sym);
    if (sym.category >= 0) {
      while (this.category.length <= sym.category) {
        this.category.push([]);
      }
      const list = this.category[sym.category];
      if (sym.category > 0) {
        sym.catindex = list.length;
      }
      while (list.length <= sym.catindex) {
        list.push(null as any);
      }
      list[sym.catindex] = sym;
    }
  }

  protected addMapInternal(
    sym: Symbol,
    exfl: number,
    addr: any,
    off: number,
    sz: number,
    uselim: any,
  ): SymbolEntry {
    const spc = addr.getSpace();
    const spcIndex = safeSpaceIndex(spc);
    if (spcIndex < 0) throw new LowlevelError("Cannot add symbol mapping with invalid space");
    let rangemap = this.maptable[spcIndex];
    if (rangemap === null) {
      rangemap = new EntryMap();
      this.maptable[spcIndex] = rangemap;
    }
    const entry = new SymbolEntry(sym, exfl, 0n, off, sz, uselim);
    entry.addr = addr;
    // Insert into the rangemap
    rangemap.insertEntry(entry);
    sym.mapentry.push(entry);
    if (sz === sym.type!.getSize()) {
      sym.wholeCount += 1;
      if (sym.wholeCount === 2) {
        this.multiEntrySet.insert(sym);
      }
    }
    return entry;
  }

  protected addDynamicMapInternal(
    sym: Symbol,
    exfl: number,
    hash: bigint,
    off: number,
    sz: number,
    uselim: any,
  ): SymbolEntry {
    const entry = new SymbolEntry(sym, exfl, hash, off, sz, uselim);
    this.dynamicentry.push(entry);
    sym.mapentry.push(entry);
    if (sz === sym.type!.getSize()) {
      sym.wholeCount += 1;
      if (sym.wholeCount === 2) {
        this.multiEntrySet.insert(sym);
      }
    }
    return entry;
  }

  // ------------------------------------------------------------------
  // Public overrides - iterators
  // ------------------------------------------------------------------

  begin(): MapIterator {
    // Find first non-null maptable entry with entries
    for (let i = 0; i < this.maptable.length; i++) {
      const rm = this.maptable[i];
      if (rm !== null && rm.size() > 0) {
        return new MapIterator(this.maptable, i, 0);
      }
    }
    return new MapIterator(this.maptable, this.maptable.length, 0);
  }

  end(): MapIterator {
    return new MapIterator(this.maptable, this.maptable.length, 0);
  }

  beginDynamic(): SymbolEntry[] {
    return this.dynamicentry;
  }

  endDynamic(): SymbolEntry[] {
    return this.dynamicentry;
  }

  // ------------------------------------------------------------------
  // clear / clearCategory / clearUnlocked
  // ------------------------------------------------------------------

  clear(): void {
    const syms: Symbol[] = [];
    for (const sym of this.nametree) {
      syms.push(sym);
    }
    for (const sym of syms) {
      this.removeSymbol(sym);
    }
    this.nextUniqueId = 0n;
  }

  categorySanity(): void {
    for (let i = 0; i < this.category.length; i++) {
      const num = this.category[i].length;
      if (num === 0) continue;
      let nullsymbol = false;
      for (let j = 0; j < num; j++) {
        if (this.category[i][j] === null) {
          nullsymbol = true;
          break;
        }
      }
      if (nullsymbol) {
        const list = [...this.category[i]];
        for (const sym of list) {
          if (sym === null) continue;
          this.setCategory(sym, Symbol.no_category, 0);
        }
      }
    }
  }

  clearCategory(cat: number): void {
    if (cat >= 0) {
      if (cat >= this.category.length) return;
      const sz = this.category[cat].length;
      for (let i = 0; i < sz; i++) {
        const sym = this.category[cat][i];
        if (sym !== null) this.removeSymbol(sym);
      }
    } else {
      const syms: Symbol[] = [];
      for (const sym of this.nametree) {
        if (sym.getCategory() >= 0) continue;
        syms.push(sym);
      }
      for (const sym of syms) {
        this.removeSymbol(sym);
      }
    }
  }

  clearUnlocked(): void {
    const syms: Symbol[] = [];
    for (const sym of this.nametree) {
      syms.push(sym);
    }
    for (const sym of syms) {
      if (sym.isTypeLocked()) {
        if (!sym.isNameLocked()) {
          if (!sym.isNameUndefined()) {
            this.renameSymbol(sym, this.buildUndefinedName());
          }
        }
        this.clearAttribute(sym, Varnode_nolocalalias);
        if (sym.isSizeTypeLocked()) {
          this.resetSizeLockType(sym);
        }
      } else if (sym.getCategory() === Symbol.equate) {
        continue; // Equates are treated as locked
      } else {
        this.removeSymbol(sym);
      }
    }
  }

  clearUnlockedCategory(cat: number): void {
    if (cat >= 0) {
      if (cat >= this.category.length) return;
      const sz = this.category[cat].length;
      for (let i = 0; i < sz; i++) {
        const sym = this.category[cat][i];
        if (sym === null) continue;
        if (sym.isTypeLocked()) {
          if (!sym.isNameLocked()) {
            if (!sym.isNameUndefined()) {
              this.renameSymbol(sym, this.buildUndefinedName());
            }
          }
          if (sym.isSizeTypeLocked()) {
            this.resetSizeLockType(sym);
          }
        } else {
          this.removeSymbol(sym);
        }
      }
    } else {
      const syms: Symbol[] = [];
      for (const sym of this.nametree) {
        syms.push(sym);
      }
      for (const sym of syms) {
        if (sym.getCategory() >= 0) continue;
        if (sym.isTypeLocked()) {
          if (!sym.isNameLocked()) {
            if (!sym.isNameUndefined()) {
              this.renameSymbol(sym, this.buildUndefinedName());
            }
          }
        } else {
          this.removeSymbol(sym);
        }
      }
    }
  }

  adjustCaches(): void {
    const numSpaces = this.getArch().numSpaces ? this.getArch().numSpaces() : 0;
    while (this.maptable.length < numSpaces) {
      this.maptable.push(null);
    }
  }

  // ------------------------------------------------------------------
  // Symbol/mapping removal
  // ------------------------------------------------------------------

  removeSymbolMappings(symbol: Symbol): void {
    if (symbol.wholeCount > 1) {
      this.multiEntrySet.eraseValue(symbol);
    }
    for (const entry of symbol.mapentry) {
      const spc = entry.getAddr() ? entry.getAddr().getSpace() : null;
      if (spc === null) {
        // Dynamic mapping
        const idx = this.dynamicentry.indexOf(entry);
        if (idx >= 0) this.dynamicentry.splice(idx, 1);
      } else {
        const rangemap = getMaptableEntry(this.maptable, spc);
        if (rangemap !== null) {
          rangemap.eraseEntry(entry);
        }
      }
    }
    symbol.wholeCount = 0;
    symbol.mapentry.length = 0;
  }

  removeSymbol(symbol: Symbol): void {
    if (symbol.category >= 0) {
      const list = this.category[symbol.category];
      if (list) {
        list[symbol.catindex] = null as any;
        while (list.length > 0 && list[list.length - 1] === null) {
          list.pop();
        }
      }
    }
    this.removeSymbolMappings(symbol);
    this.nametree.eraseValue(symbol);
  }

  renameSymbol(sym: Symbol, newname: string): void {
    this.nametree.eraseValue(sym);
    if (sym.wholeCount > 1)
      this.multiEntrySet.eraseValue(sym);
    sym.name = newname;
    sym.displayName = newname;
    this.insertNameTree(sym);
    if (sym.wholeCount > 1)
      this.multiEntrySet.insert(sym);
  }

  retypeSymbol(sym: Symbol, ct: Datatype): void {
    if (ct.hasStripped()) ct = ct.getStripped()!;
    if (sym.type!.getSize() === ct.getSize() || sym.mapentry.length === 0) {
      sym.type = ct;
      sym.checkSizeTypeLock();
      return;
    }
    if (sym.mapentry.length === 1) {
      const entry: SymbolEntry = sym.mapentry[0];
      if (entry.isAddrTied()) {
        const addr = entry.getAddr();
        const spc = addr.getSpace()!;
        const rangemap = getMaptableEntry(this.maptable, spc);
        if (rangemap !== null) {
          rangemap.eraseEntry(entry);
        }
        sym.mapentry.pop();
        sym.wholeCount = 0;
        sym.type = ct;
        sym.checkSizeTypeLock();
        this.addMapPoint(sym, addr, new Address());
        return;
      }
    }
    throw new Error("Unable to retype symbol: " + sym.name);
  }

  setAttribute(sym: Symbol, attr: number): void {
    attr &= (Varnode_typelock | Varnode_namelock | Varnode_readonly | Varnode_incidental_copy |
      Varnode_nolocalalias | Varnode_volatil | Varnode_indirectstorage | Varnode_hiddenretparm);
    sym.flags |= attr;
    sym.checkSizeTypeLock();
  }

  clearAttribute(sym: Symbol, attr: number): void {
    attr &= (Varnode_typelock | Varnode_namelock | Varnode_readonly | Varnode_incidental_copy |
      Varnode_nolocalalias | Varnode_volatil | Varnode_indirectstorage | Varnode_hiddenretparm);
    sym.flags &= ~attr;
    sym.checkSizeTypeLock();
  }

  setDisplayFormat(sym: Symbol, attr: number): void {
    sym.setDisplayFormat(attr);
  }

  // ------------------------------------------------------------------
  // Find operations (within this scope only)
  // ------------------------------------------------------------------

  findAddr(addr: any, usepoint: any): SymbolEntry | null {
    const spc = addr.getSpace();
    if (spc === null) return null;
    const rangemap = getMaptableEntry(this.maptable, spc);
    if (rangemap !== null) {
      const entries = rangemap.findByOffset(addr.getOffset());
      // Iterate from last to first (matching C++ reverse iteration)
      for (let i = entries.length - 1; i >= 0; i--) {
        const entry = entries[i];
        if (entry.getAddr().getOffset() === addr.getOffset()) {
          if (entry.inUse(usepoint)) {
            return entry;
          }
        }
      }
    }
    return null;
  }

  findContainer(addr: any, size: number, usepoint: any): SymbolEntry | null {
    let bestentry: SymbolEntry | null = null;
    const spc = addr.getSpace();
    if (spc === null) return null;
    const rangemap = getMaptableEntry(this.maptable, spc);
    if (rangemap !== null) {
      const entries = rangemap.findByOffset(addr.getOffset());
      let oldsize = -1;
      const end = addr.getOffset() + BigInt(size) - 1n;
      for (let i = entries.length - 1; i >= 0; i--) {
        const entry = entries[i];
        if (entry.getLast() >= end) {
          if (entry.getSize() < oldsize || oldsize === -1) {
            if (entry.inUse(usepoint)) {
              bestentry = entry;
              if (entry.getSize() === size) break;
              oldsize = entry.getSize();
            }
          }
        }
      }
    }
    return bestentry;
  }

  findClosestFit(addr: any, size: number, usepoint: any): SymbolEntry | null {
    let bestentry: SymbolEntry | null = null;
    const spc = addr.getSpace();
    if (spc === null) return null;
    const rangemap = getMaptableEntry(this.maptable, spc);
    if (rangemap !== null) {
      const entries = rangemap.findByOffset(addr.getOffset());
      let olddiff = -10000;
      for (let i = entries.length - 1; i >= 0; i--) {
        const entry = entries[i];
        if (entry.getLast() >= addr.getOffset()) {
          const newdiff = entry.getSize() - size;
          if ((olddiff < 0 && newdiff > olddiff) ||
            (olddiff >= 0 && newdiff >= 0 && newdiff < olddiff)) {
            if (entry.inUse(usepoint)) {
              bestentry = entry;
              if (newdiff === 0) break;
              olddiff = newdiff;
            }
          }
        }
      }
    }
    return bestentry;
  }

  findFunction(addr: any): Funcdata | null {
    const spc = addr.getSpace();
    if (spc === null) return null;
    const rangemap = getMaptableEntry(this.maptable, spc);
    if (rangemap !== null) {
      const entries = rangemap.findByOffset(addr.getOffset());
      for (const entry of entries) {
        if (entry.getAddr().getOffset() === addr.getOffset()) {
          const sym = entry.getSymbol();
          if (sym instanceof FunctionSymbol) {
            return sym.getFunction();
          }
        }
      }
    }
    return null;
  }

  findExternalRef(addr: any): ExternRefSymbol | null {
    const spc = addr.getSpace();
    if (spc === null) return null;
    const rangemap = getMaptableEntry(this.maptable, spc);
    if (rangemap !== null) {
      const entries = rangemap.findByOffset(addr.getOffset());
      for (const entry of entries) {
        if (entry.getAddr().getOffset() === addr.getOffset()) {
          const sym = entry.getSymbol();
          if (sym instanceof ExternRefSymbol) {
            return sym;
          }
        }
      }
    }
    return null;
  }

  findCodeLabel(addr: any): LabSymbol | null {
    const spc = addr.getSpace();
    if (spc === null) return null;
    const rangemap = getMaptableEntry(this.maptable, spc);
    if (rangemap !== null) {
      const entries = rangemap.findByOffset(addr.getOffset());
      for (let i = entries.length - 1; i >= 0; i--) {
        const entry = entries[i];
        if (entry.getAddr().getOffset() === addr.getOffset()) {
          if (entry.inUse(addr)) {
            const sym = entry.getSymbol();
            if (sym instanceof LabSymbol) return sym;
          }
        }
      }
    }
    return null;
  }

  findOverlap(addr: any, size: number): SymbolEntry | null {
    const spc = addr.getSpace();
    if (spc === null) return null;
    const rangemap = getMaptableEntry(this.maptable, spc);
    if (rangemap !== null) {
      return rangemap.findOverlap(addr.getOffset(), addr.getOffset() + BigInt(size) - 1n);
    }
    return null;
  }

  findByName(nm: string): Symbol[] {
    const res: Symbol[] = [];
    const iter = this.findFirstByName(nm);
    if (iter.isEnd) return res;
    let cur = iter.clone();
    while (!cur.isEnd) {
      const sym = cur.value;
      if (sym.name !== nm) break;
      res.push(sym);
      cur.next();
    }
    return res;
  }

  isNameUsed(nm: string, op2: Scope | null): boolean {
    const testSym = new Symbol(null as any, nm, null);
    const iter = this.nametree.lower_bound(testSym);
    if (!iter.isEnd) {
      if (iter.value.getName() === nm) return true;
    }
    const par = this.getParent();
    if (par === null || par === op2) return false;
    if (par.getParent() === null) return false; // Never recurse into global scope
    return par.isNameUsed(nm, op2);
  }

  resolveExternalRefFunction(sym: ExternRefSymbol): Funcdata | null {
    return this.queryFunction(sym.getRefAddr());
  }

  buildVariableName(addr: any, pc: any, ct: Datatype, index: { val: number }, flags: number): string {
    const sz = ct === null ? 1 : ct.getSize();
    let s = "";

    if ((flags & Varnode_unaffected) !== 0) {
      if ((flags & Varnode_return_address) !== 0) {
        s = "unaff_retaddr";
      } else {
        let unaffname = "";
        if (this.getArch().translate) {
          unaffname = this.getArch().translate.getRegisterName(addr.getSpace(), addr.getOffset(), sz);
        }
        if (unaffname.length === 0) {
          s = "unaff_" + addr.getOffset().toString(16).padStart(8, '0');
        } else {
          s = "unaff_" + unaffname;
        }
      }
    } else if ((flags & Varnode_persist) !== 0) {
      let spacename = "";
      if (this.getArch().translate) {
        spacename = this.getArch().translate.getRegisterName(addr.getSpace(), addr.getOffset(), sz);
      }
      if (spacename.length > 0) {
        s = spacename;
      } else {
        if (ct !== null) { const sw = new StringWriter(); ct.printNameBase(sw); s = sw.toString(); }
        let sname = addr.getSpace().getName();
        sname = sname.charAt(0).toUpperCase() + sname.slice(1);
        s += sname;
        const addrSize = addr.getAddrSize ? addr.getAddrSize() : 4;
        s += addr.getOffset().toString(16).padStart(2 * addrSize, '0');
      }
    } else if ((flags & Varnode_input) !== 0 && index.val < 0) {
      // Irregular input
      let regname = "";
      if (this.getArch().translate) {
        regname = this.getArch().translate.getRegisterName(addr.getSpace(), addr.getOffset(), sz);
      }
      if (regname.length === 0) {
        s = "in_" + addr.getSpace().getName() + "_" + addr.getOffset().toString(16).padStart(8, '0');
      } else {
        s = "in_" + regname;
      }
    } else if ((flags & Varnode_input) !== 0) {
      // Regular parameter
      s = "param_" + index.val.toString();
    } else if ((flags & Varnode_addrtied) !== 0) {
      if (ct !== null) { const sw = new StringWriter(); ct.printNameBase(sw); s = sw.toString(); }
      const spc = addr.getSpace();
      let spacename = spc.getName();
      spacename = spacename.charAt(0).toUpperCase() + spacename.slice(1);
      s += spacename;
      const addrSize = spc.getAddrSize();
      const off = AddrSpace.byteToAddress(addr.getOffset(), spc.getWordSize());
      const hexOff = (typeof off === 'bigint' ? off : BigInt(off)).toString(16).padStart(2 * addrSize, '0');
      s += hexOff;
    } else if ((flags & Varnode_indirect_creation) !== 0) {
      let regname = "";
      if (this.getArch().translate) {
        regname = this.getArch().translate.getRegisterName(addr.getSpace(), addr.getOffset(), sz);
      }
      s = "extraout_";
      if (regname.length > 0) {
        s += regname;
      } else {
        s += "var";
      }
    } else {
      // Some sort of local variable
      if (ct !== null) { const sw = new StringWriter(); ct.printNameBase(sw); s = sw.toString(); }
      s += "Var" + index.val.toString();
      index.val++;
      if (!this.findFirstByName(s).isEnd) {
        // If the name already exists, bump the index a few times
        for (let i = 0; i < 10; i++) {
          let s2 = "";
          if (ct !== null) { const sw = new StringWriter(); ct.printNameBase(sw); s2 = sw.toString(); }
          s2 += "Var" + index.val.toString();
          index.val++;
          if (this.findFirstByName(s2).isEnd) {
            return s2;
          }
        }
      }
    }
    return this.makeNameUnique(s);
  }

  buildUndefinedName(): string {
    // Generate a name of the form '$$undefXXXXXXXX'
    const testSym = new Symbol(null as any, "$$undefz", null);
    const iter = this.nametree.lower_bound(testSym);
    if (!iter.isEnd || this.nametree.size > 0) {
      // Go to the previous entry
      const prev = iter.clone();
      if (!iter.isEnd) {
        prev.prev();
      } else {
        // rbegin
        const rb = this.nametree.rbegin();
        if (!rb.isEnd) {
          const symname = rb.value.getName();
          if (symname.length === 15 && symname.substring(0, 7) === "$$undef") {
            const hexstr = symname.substring(7, 15);
            let uniq = parseInt(hexstr, 16);
            if (isNaN(uniq) || uniq === 0xFFFFFFFF) {
              throw new Error("Error creating undefined name");
            }
            uniq += 1;
            return "$$undef" + uniq.toString(16).padStart(8, '0');
          }
        }
      }
      if (!prev.isEnd) {
        const symname = prev.value.getName();
        if (symname.length === 15 && symname.substring(0, 7) === "$$undef") {
          const hexstr = symname.substring(7, 15);
          let uniq = parseInt(hexstr, 16);
          if (isNaN(uniq) || uniq === 0xFFFFFFFF) {
            throw new Error("Error creating undefined name");
          }
          uniq += 1;
          return "$$undef" + uniq.toString(16).padStart(8, '0');
        }
      }
    }
    return "$$undef00000000";
  }

  makeNameUnique(nm: string): string {
    const iter = this.findFirstByName(nm);
    if (iter.isEnd) return nm; // nm is already unique

    const boundsym = new Symbol(null as any, nm + "_x99999", null);
    boundsym.nameDedup = 0xFFFFFFFF;
    let iter2 = this.nametree.lower_bound(boundsym);
    let uniqid = 0xFFFFFFFF;

    do {
      uniqid = 0xFFFFFFFF;
      iter2.prev();
      if (iter.equals(iter2)) break;
      const bsym = iter2.value;
      const bname = bsym.getName();
      let isXForm = false;
      let digCount = 0;

      if (bname.length >= nm.length + 3 && bname[nm.length] === '_') {
        let i = nm.length + 1;
        if (bname[i] === 'x') {
          i++;
          isXForm = true;
        }
        uniqid = 0;
        for (; i < bname.length; i++) {
          const dig = bname[i];
          if (dig < '0' || dig > '9') {
            uniqid = 0xFFFFFFFF;
            break;
          }
          uniqid *= 10;
          uniqid += (dig.charCodeAt(0) - 48);
          digCount++;
        }
      }
      if (isXForm && digCount !== 5) uniqid = 0xFFFFFFFF;
      else if (!isXForm && digCount !== 2) uniqid = 0xFFFFFFFF;
    } while (uniqid === 0xFFFFFFFF);

    let resString: string;
    if (uniqid === 0xFFFFFFFF) {
      resString = nm + "_00";
    } else {
      uniqid += 1;
      if (uniqid < 100) {
        resString = nm + "_" + uniqid.toString().padStart(2, '0');
      } else {
        resString = nm + "_x" + uniqid.toString().padStart(5, '0');
      }
    }

    if (!this.findFirstByName(resString).isEnd) {
      throw new Error("Unable to uniquify name: " + resString);
    }
    return resString;
  }

  // ------------------------------------------------------------------
  // encode / decode
  // ------------------------------------------------------------------

  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_SCOPE);
    encoder.writeString(ATTRIB_NAME, this.name);
    encoder.writeUnsignedInteger(ATTRIB_ID, this.getId());
    if (this.getParent() !== null) {
      encoder.openElement(ELEM_PARENT);
      encoder.writeUnsignedInteger(ATTRIB_ID, this.getParent()!.getId());
      encoder.closeElement(ELEM_PARENT);
    }
    this.getRangeTree().encode(encoder);

    if (this.nametree.size > 0) {
      encoder.openElement(ELEM_SYMBOLLIST);
      for (const sym of this.nametree) {
        let symbolType = 0;
        if (sym.mapentry.length > 0) {
          const entry = sym.mapentry[0];
          if (entry.isDynamic()) {
            if (sym.getCategory() === Symbol.union_facet)
              continue; // Don't save override
            symbolType = (sym.getCategory() === Symbol.equate) ? 2 : 1;
          }
        }
        encoder.openElement(ELEM_MAPSYM);
        if (symbolType === 1) {
          encoder.writeString(ATTRIB_TYPE, "dynamic");
        } else if (symbolType === 2) {
          encoder.writeString(ATTRIB_TYPE, "equate");
        }
        sym.encode(encoder);
        for (const entry of sym.mapentry) {
          entry.encode(encoder);
        }
        encoder.closeElement(ELEM_MAPSYM);
      }
      encoder.closeElement(ELEM_SYMBOLLIST);
    }
    encoder.closeElement(ELEM_SCOPE);
  }

  decode(decoder: Decoder): void {
    let rangeequalssymbols = false;

    let subId = decoder.peekElement();
    if (subId === ELEM_PARENT.getId()) {
      decoder.skipElement();
      subId = decoder.peekElement();
    }
    if (subId === ELEM_RANGELIST.getId()) {
      const newrangetree = new RangeList();
      newrangetree.decode(decoder);
      this.getArch().symboltab.setRange(this, newrangetree);
    } else if (subId === ELEM_RANGEEQUALSSYMBOLS.getId()) {
      decoder.openElement();
      decoder.closeElement(subId);
      rangeequalssymbols = true;
    }

    subId = decoder.openElementId(ELEM_SYMBOLLIST);
    if (subId !== 0) {
      for (;;) {
        const symId = decoder.peekElement();
        if (symId === 0) break;
        if (symId === ELEM_MAPSYM.getId()) {
          const sym = this.addMapSym(decoder);
          if (rangeequalssymbols && sym !== null) {
            const e = sym.getFirstWholeMap();
            this.getArch().symboltab.addRange(
              this, e.getAddr().getSpace(), e.getFirst(), e.getLast(),
            );
          }
        } else if (symId === ELEM_HOLE.getId()) {
          this.decodeHole(decoder);
        } else if (symId === ELEM_COLLISION.getId()) {
          this.decodeCollision(decoder);
        } else {
          throw new Error("Unknown symbollist tag");
        }
      }
      decoder.closeElement(subId);
    }
    this.categorySanity();
  }

  printEntries(s: Writer): void {
    s.write("Scope " + this.name + "\n");
    for (let i = 0; i < this.maptable.length; i++) {
      const rangemap = this.maptable[i];
      if (rangemap === null) continue;
      const entries = rangemap.getAllEntries();
      for (const entry of entries) {
        entry.printEntry(s);
      }
    }
  }

  getCategorySize(cat: number): number {
    if (cat >= this.category.length || cat < 0) return 0;
    return this.category[cat].length;
  }

  getCategorySymbol(cat: number, ind: number): Symbol | null {
    if (cat >= this.category.length || cat < 0) return null;
    if (ind < 0 || ind >= this.category[cat].length) return null;
    return this.category[cat][ind];
  }

  setCategory(sym: Symbol, cat: number, ind: number): void {
    if (sym.category >= 0) {
      const list = this.category[sym.category];
      if (list) {
        list[sym.catindex] = null as any;
        while (list.length > 0 && list[list.length - 1] === null) {
          list.pop();
        }
      }
    }
    sym.category = cat;
    sym.catindex = ind;
    if (cat < 0) return;
    while (this.category.length <= sym.category) {
      this.category.push([]);
    }
    const list = this.category[sym.category];
    if (cat > 0) sym.catindex = list.length;
    while (list.length <= sym.catindex) {
      list.push(null as any);
    }
    list[sym.catindex] = sym;
  }

  /**
   * Assign a default name to any unnamed symbol.
   */
  assignDefaultNames(base: { val: number }): void {
    const testSym = new Symbol(null as any, "$$undef", null);
    let iter = this.nametree.upper_bound(testSym);
    const toRename: Symbol[] = [];
    while (!iter.isEnd) {
      const sym = iter.value;
      if (!sym.isNameUndefined()) break;
      toRename.push(sym);
      iter.next();
    }
    for (const sym of toRename) {
      const nm = this.buildDefaultName(sym, base, null);
      this.renameSymbol(sym, nm);
    }
  }

  beginMultiEntry(): IterableIterator<Symbol> {
    return this.multiEntrySet[globalThis.Symbol.iterator]();
  }

  endMultiEntry(): void { }

  // ------------------------------------------------------------------
  // Private decode helpers
  // ------------------------------------------------------------------

  private decodeHole(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_HOLE);
    let flags = 0;
    const range = new Range();
    range.decodeFromAttributes(decoder);
    decoder.rewindAttributes();
    for (;;) {
      const attribId = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_READONLY.getId() && decoder.readBool()) {
        flags |= Varnode_readonly;
      } else if (attribId === ATTRIB_VOLATILE.getId() && decoder.readBool()) {
        flags |= Varnode_volatil;
      }
    }
    if (flags !== 0) {
      this.getArch().symboltab.setPropertyRange(flags, range);
    }
    decoder.closeElement(elemId);
  }

  private decodeCollision(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_COLLISION);
    const nm = decoder.readStringById(ATTRIB_NAME);
    decoder.closeElement(elemId);
    const iter = this.findFirstByName(nm);
    if (iter.isEnd) {
      const ct = this.getArch().types.getBase(1, type_metatype.TYPE_INT);
      this.addSymbol(nm, ct);
    }
  }

  private insertNameTree(sym: Symbol): void {
    sym.nameDedup = 0;
    const [, inserted] = this.nametree.insert(sym);
    if (!inserted) {
      sym.nameDedup = 0xFFFFFFFF;
      const iter = this.nametree.upper_bound(sym);
      const prev = iter.clone().prev();
      if (!prev.isEnd) {
        sym.nameDedup = prev.value.nameDedup + 1;
      }
      const [, inserted2] = this.nametree.insert(sym);
      if (!inserted2) {
        throw new Error("Could not deduplicate symbol: " + sym.name);
      }
    }
  }

  private findFirstByName(nm: string): any {
    const testSym = new Symbol(null as any, nm, null);
    const iter = this.nametree.lower_bound(testSym);
    if (iter.isEnd) return iter;
    if (iter.value.getName() !== nm) return this.nametree.end();
    return iter;
  }
}

// =========================================================================
// ScopeMapper  (associates address ranges with Scopes)
// =========================================================================

/**
 * An Address range associated with the Scope that owns it.
 * Used in the Database's resolve map.
 */
class ScopeMapper {
  scope: Scope;
  first: any;  // Address
  last: any;   // Address

  constructor(scope: Scope, first: any, last: any) {
    this.scope = scope;
    this.first = first;
    this.last = last;
  }

  getFirst(): any { return this.first; }
  getLast(): any { return this.last; }
  getScope(): Scope { return this.scope; }
}

// =========================================================================
// Database  (manages the scope hierarchy)
// =========================================================================

/**
 * A manager for symbol scopes for a whole executable.
 *
 * This is the highest level container for anything related to Scope and Symbol
 * objects. It indirectly holds the Funcdata objects as well, through FunctionSymbol.
 * It acts as the formal symbol table for the decompiler.
 */
export class Database {
  private glb: Architecture;
  private globalscope: Scope | null;
  private resolvemap: ScopeMapper[];
  private idmap: ScopeMap;
  private flagbase: PartMap<Address, number>;
  private idByNameHash: boolean;

  constructor(g: Architecture, idByName: boolean) {
    this.glb = g;
    this.globalscope = null;
    this.resolvemap = [];
    this.idmap = new Map();
    this.idByNameHash = idByName;
    this.flagbase = new PartMap<Address, number>(
      0,
      (a: Address, b: Address) => {
        if (a.equals(b)) return 0;
        return a.lessThan(b) ? -1 : 1;
      }
    );
  }

  dispose(): void {
    if (this.globalscope !== null) {
      this.deleteScope(this.globalscope);
    }
  }

  // ------------------------------------------------------------------
  // Accessors
  // ------------------------------------------------------------------

  getArch(): Architecture { return this.glb; }
  getGlobalScope(): Scope | null { return this.globalscope; }

  /**
   * Get boolean properties at the given address.
   */
  getProperty(addr: Address): number {
    return this.flagbase.getValue(addr);
  }

  /**
   * Get the entire property map.
   */
  getProperties(): any { return this.flagbase; }

  /**
   * Replace the property map.
   */
  setProperties(newflags: any): void { this.flagbase = newflags; }

  // ------------------------------------------------------------------
  // Private helpers
  // ------------------------------------------------------------------

  /**
   * Clear the ownership ranges associated with a namespace Scope.
   */
  private clearResolve(scope: Scope): void {
    if (scope === this.globalscope) return;
    if (!scope.isGlobal()) return; // Does not apply to functional scopes (fd !== null means not global)
    // Actually the C++ checks (scope->fd != 0) which means it IS a function scope
    // For namespace scopes (isGlobal() is true), we remove from resolve map
    this.resolvemap = this.resolvemap.filter(m => m.scope !== scope);
  }

  /**
   * Recursively clear references in idmap and resolvemap.
   */
  private clearReferences(scope: Scope): void {
    for (const [, child] of scope.childrenBegin()) {
      this.clearReferences(child);
    }
    this.idmap.delete(scope.getId());
    this.clearResolve(scope);
  }

  /**
   * Add ownership ranges of the given namespace Scope to the map.
   */
  private fillResolve(scope: Scope): void {
    if (scope === this.globalscope) return;
    if (!scope.isGlobal()) return;
    // Iterate over scope ranges and add to resolvemap
    const rangetree = (scope as any).getRangeTree ? (scope as any).getRangeTree() : null;
    if (rangetree !== null) {
      const ranges = rangetree.getRanges ? rangetree.getRanges() : [];
      for (const rng of ranges) {
        this.resolvemap.push(
          new ScopeMapper(scope, rng.getFirstAddr(), rng.getLastAddr()),
        );
      }
    }
  }

  /**
   * Parse a <parent> element.
   */
  private parseParentTag(decoder: Decoder): Scope {
    const elemId = decoder.openElementId(ELEM_PARENT);
    const id = decoder.readUnsignedIntegerById(ATTRIB_ID);
    const res = this.resolveScope(id);
    if (res === null) {
      throw new Error("Could not find scope matching id");
    }
    decoder.closeElement(elemId);
    return res;
  }

  // ------------------------------------------------------------------
  // Public interface
  // ------------------------------------------------------------------

  /**
   * Let scopes adjust after configuration is finished.
   */
  adjustCaches(): void {
    for (const [, scope] of this.idmap) {
      scope.adjustCaches();
    }
  }

  /**
   * Register a new Scope.
   * If parent is null, the scope becomes the global scope.
   */
  attachScope(newscope: Scope, parent: Scope | null): void {
    if (parent === null) {
      if (this.globalscope !== null) {
        throw new Error("Multiple global scopes");
      }
      if (newscope.getName().length !== 0) {
        throw new Error("Global scope does not have empty name");
      }
      this.globalscope = newscope;
      this.idmap.set(this.globalscope.getId(), this.globalscope);
      return;
    }
    if (newscope.getName().length === 0) {
      throw new Error("Non-global scope has empty name");
    }
    if (this.idmap.has(newscope.getId())) {
      // In C++ the old scope would have been removed by the Funcdata destructor.
      // TypeScript has no destructors, so stale scopes can linger after errors.
      // Remove the stale scope so the new one can take its place.
      const oldscope = this.idmap.get(newscope.getId())!;
      this.deleteScope(oldscope);
    }
    this.idmap.set(newscope.getId(), newscope);
    (parent as any).attachScope(newscope);
  }

  /**
   * Delete the given Scope and all its sub-scopes.
   */
  deleteScope(scope: Scope): void {
    this.clearReferences(scope);
    if (this.globalscope === scope) {
      this.globalscope = null;
      scope.dispose();
    } else {
      const parent = scope.getParent();
      if (parent !== null) {
        (parent as any).detachScope(scope.getId());
      }
    }
  }

  /**
   * Delete all sub-scopes of the given Scope.
   */
  deleteSubScopes(scope: Scope): void {
    const childIds: bigint[] = [];
    for (const [id,] of scope.childrenBegin()) {
      childIds.push(id);
    }
    for (const id of childIds) {
      const children = new Map<bigint, Scope>();
      for (const [cid, child] of scope.childrenBegin()) {
        children.set(cid, child);
      }
      const child = children.get(id);
      if (child !== undefined) {
        this.clearReferences(child);
        (scope as any).detachScope(id);
      }
    }
  }

  /**
   * Clear unlocked Symbols owned by the given Scope, recursively.
   */
  clearUnlocked(scope: Scope): void {
    for (const [, child] of scope.childrenBegin()) {
      this.clearUnlocked(child);
    }
    scope.clearUnlocked();
  }

  /**
   * Set the ownership range for a Scope.
   */
  setRange(scope: Scope, rlist: any): void {
    this.clearResolve(scope);
    (scope as any).rangetree = rlist;
    this.fillResolve(scope);
  }

  /**
   * Add an address range to the ownership of a Scope.
   */
  addRange(scope: Scope, spc: AddrSpace, first: bigint, last: bigint): void {
    this.clearResolve(scope);
    (scope as any).addRange(spc, first, last);
    this.fillResolve(scope);
  }

  /**
   * Remove an address range from ownership of a Scope.
   */
  removeRange(scope: Scope, spc: AddrSpace, first: bigint, last: bigint): void {
    this.clearResolve(scope);
    (scope as any).removeRange(spc, first, last);
    this.fillResolve(scope);
  }

  /**
   * Look up a Scope by id.
   */
  resolveScope(id: bigint): Scope | null {
    return this.idmap.get(id) ?? null;
  }

  /**
   * Get the Scope and base name associated with a qualified symbol name.
   */
  resolveScopeFromSymbolName(
    fullname: string,
    delim: string,
    start: Scope | null,
  ): { scope: Scope | null; basename: string } {
    if (start === null) start = this.globalscope;
    let mark = 0;
    let endmark: number;
    for (;;) {
      endmark = fullname.indexOf(delim, mark);
      if (endmark === -1) break;
      if (endmark === 0) {
        start = this.globalscope;
      } else {
        const scopename = fullname.substring(mark, endmark);
        start = start!.resolveScope(scopename, this.idByNameHash);
        if (start === null) return { scope: null, basename: "" };
      }
      mark = endmark + delim.length;
    }
    return { scope: start, basename: fullname.substring(mark) };
  }

  /**
   * Find (and if not found create) a specific subscope.
   */
  findCreateScope(id: bigint, nm: string, parent: Scope | null): Scope {
    const res = this.resolveScope(id);
    if (res !== null) return res;
    const newScope = (this.globalscope as any).buildSubScope(id, nm);
    this.attachScope(newScope, parent);
    return newScope;
  }

  /**
   * Find and/or create Scopes associated with a qualified Symbol name.
   */
  findCreateScopeFromSymbolName(
    fullname: string,
    delim: string,
    start: Scope | null,
  ): { scope: Scope; basename: string } {
    if (start === null) start = this.globalscope;
    let mark = 0;
    let endmark: number;
    for (;;) {
      endmark = fullname.indexOf(delim, mark);
      if (endmark === -1) break;
      if (!this.idByNameHash) {
        throw new Error("Scope name hashes not allowed");
      }
      const scopename = fullname.substring(mark, endmark);
      const nameId = Scope.hashScopeName(start!.getId(), scopename);
      start = this.findCreateScope(nameId, scopename, start);
      mark = endmark + delim.length;
    }
    return { scope: start!, basename: fullname.substring(mark) };
  }

  /**
   * Determine the lowest-level Scope which might contain the given address as a Symbol.
   */
  mapScope(qpoint: Scope, addr: any, usepoint: any): Scope {
    if (this.resolvemap.length === 0) return qpoint;
    // Search resolvemap for the address
    for (const mapper of this.resolvemap) {
      const firstOff = mapper.first.getOffset();
      const lastOff = mapper.last.getOffset();
      const addrOff = addr.getOffset();
      if (addrOff >= firstOff && addrOff <= lastOff) {
        return mapper.scope;
      }
    }
    return qpoint;
  }

  /**
   * Compute the "open" end address for a range (one past the last address).
   * Handles the case where the range covers the end of an address space by
   * jumping to the beginning of the next space in order.
   * Returns null if the range extends to the end of the last address space.
   *
   * Matches C++ Range::getLastAddrOpen(const AddrSpaceManager *manage).
   */
  private getLastAddrOpen(range: Range): Address | null {
    const curspc = range.getSpace();
    const curlast = range.getLast();
    if (curlast === curspc.getHighest()) {
      const nextspc = this.glb.getNextSpaceInOrder(curspc);
      if (nextspc === null || nextspc === SPACE_END_SENTINEL) return null;
      return new Address(nextspc, 0n);
    }
    return new Address(curspc, curlast + 1n);
  }

  /**
   * Set boolean properties over a given memory range.
   */
  setPropertyRange(flags: number, range: Range): void {
    const addr1 = new Address(range.getSpace(), range.getFirst());
    const addr2 = this.getLastAddrOpen(range);
    this.flagbase.split(addr1);
    let endIdx: number;
    if (addr2 !== null) {
      this.flagbase.split(addr2);
      endIdx = this.flagbase.beginIndex(addr2);
    } else {
      endIdx = this.flagbase.endIndex();
    }
    // OR flags into all entries in [addr1, addr2)
    for (let idx = this.flagbase.beginIndex(addr1); idx < endIdx; idx++) {
      const oldVal = this.flagbase.getValueAt(idx);
      const key = this.flagbase.getKeyAt(idx);
      this.flagbase.splitAndSet(key, oldVal | flags);
    }
  }

  /**
   * Clear boolean properties over a given memory range.
   */
  clearPropertyRange(flags: number, range: Range): void {
    const addr1 = new Address(range.getSpace(), range.getFirst());
    const addr2 = this.getLastAddrOpen(range);
    this.flagbase.split(addr1);
    let endIdx: number;
    if (addr2 !== null) {
      this.flagbase.split(addr2);
      endIdx = this.flagbase.beginIndex(addr2);
    } else {
      endIdx = this.flagbase.endIndex();
    }
    // Clear flags from all entries in [addr1, addr2)
    for (let idx = this.flagbase.beginIndex(addr1); idx < endIdx; idx++) {
      const oldVal = this.flagbase.getValueAt(idx);
      const key = this.flagbase.getKeyAt(idx);
      this.flagbase.splitAndSet(key, oldVal & ~flags);
    }
  }

  /**
   * Encode the whole Database to a stream.
   */
  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_DB);
    if (this.idByNameHash) {
      encoder.writeBool(ATTRIB_SCOPEIDBYNAME, true);
    }
    // Save the property change points
    for (const [addr, val] of this.flagbase.entries()) {
      encoder.openElement(ELEM_PROPERTY_CHANGEPOINT);
      addr.getSpace()!.encodeAttributes(encoder, addr.getOffset());
      encoder.writeUnsignedInteger(ATTRIB_VAL, BigInt(val));
      encoder.closeElement(ELEM_PROPERTY_CHANGEPOINT);
    }
    if (this.globalscope !== null) {
      this.globalscope.encodeRecursive(encoder, true);
    }
    encoder.closeElement(ELEM_DB);
  }

  /**
   * Decode the whole database from a stream.
   */
  decode(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_DB);
    this.idByNameHash = false;
    for (;;) {
      const attribId = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_SCOPEIDBYNAME.getId()) {
        this.idByNameHash = decoder.readBool();
      }
    }

    // Read property change points
    for (;;) {
      const subId = decoder.peekElement();
      if (subId !== ELEM_PROPERTY_CHANGEPOINT.getId()) break;
      decoder.openElement();
      let val = 0;
      let spc: AddrSpace | null = null;
      let offset = 0n;
      for (;;) {
        const attribId = decoder.getNextAttributeId();
        if (attribId === 0) break;
        if (attribId === ATTRIB_VAL.getId()) {
          val = Number(decoder.readUnsignedInteger());
        } else if (attribId === AttributeId.find('space', 0) || attribId === AttributeId.find('base', 0)) {
          spc = decoder.readSpace() as any;
        } else {
          // Check for 'offset' attribute by name
          offset = decoder.readUnsignedInteger();
        }
      }
      decoder.closeElement(subId);
      if (spc !== null) {
        const addr = new Address(spc, offset);
        this.flagbase.splitAndSet(addr, val);
      }
    }

    // Read scopes
    for (;;) {
      const subId = decoder.openElement();
      if (subId !== ELEM_SCOPE.getId()) break;
      let name = "";
      let scopeDisplayName = "";
      let id = 0n;
      for (;;) {
        const attribId = decoder.getNextAttributeId();
        if (attribId === 0) break;
        if (attribId === ATTRIB_NAME.getId()) {
          name = decoder.readString();
        } else if (attribId === ATTRIB_ID.getId()) {
          id = decoder.readUnsignedInteger();
        } else if (attribId === ATTRIB_LABEL.getId()) {
          scopeDisplayName = decoder.readString();
        }
      }
      let parentScope: Scope | null = null;
      const parentId = decoder.peekElement();
      if (parentId === ELEM_PARENT.getId()) {
        parentScope = this.parseParentTag(decoder);
      }
      const newScope = this.findCreateScope(id, name, parentScope);
      if (scopeDisplayName.length > 0) {
        (newScope as any).setDisplayName(scopeDisplayName);
      }
      newScope.decode(decoder);
      decoder.closeElement(subId);
    }
    decoder.closeElement(elemId);
  }

  /**
   * Register and fill out a single Scope from an XML <scope> tag.
   */
  decodeScope(decoder: Decoder, newScope: Scope): void {
    const elemId = decoder.openElement();
    if (elemId === ELEM_SCOPE.getId()) {
      const parentScope = this.parseParentTag(decoder);
      this.attachScope(newScope, parentScope);
      newScope.decode(decoder);
    } else {
      newScope.decodeWrappingAttributes(decoder);
      const subId = decoder.openElementId(ELEM_SCOPE);
      const parentScope = this.parseParentTag(decoder);
      this.attachScope(newScope, parentScope);
      newScope.decode(decoder);
      decoder.closeElement(subId);
    }
    decoder.closeElement(elemId);
  }

  /**
   * Decode a namespace path and make sure each namespace exists.
   */
  decodeScopePath(decoder: Decoder): Scope {
    let curscope = this.getGlobalScope()!;
    const elemId = decoder.openElementId(ELEM_PARENT);
    let subId = decoder.openElement();
    decoder.closeElementSkipping(subId);  // Skip root scope element
    for (;;) {
      subId = decoder.openElement();
      if (subId !== ELEM_VAL.getId()) break;
      let scopeDisplayName = "";
      let scopeId = 0n;
      for (;;) {
        const attribId = decoder.getNextAttributeId();
        if (attribId === 0) break;
        if (attribId === ATTRIB_ID.getId()) {
          scopeId = decoder.readUnsignedInteger();
        } else if (attribId === ATTRIB_LABEL.getId()) {
          scopeDisplayName = decoder.readString();
        }
      }
      const name = decoder.readStringById(ATTRIB_CONTENT);
      if (scopeId === 0n) {
        throw new Error("Missing name and id in scope");
      }
      curscope = this.findCreateScope(scopeId, name, curscope);
      if (scopeDisplayName.length > 0) {
        (curscope as any).setDisplayName(scopeDisplayName);
      }
      decoder.closeElement(subId);
    }
    decoder.closeElement(elemId);
    return curscope;
  }
}

// =========================================================================
// Helper: CRC update (placeholder -- matches crc32.hh usage)
// =========================================================================

/**
 * Simple CRC update used for scope name hashing.
 * This is a placeholder for the actual crc_update from crc32.hh.
 */
function crc_update(reg: number, val: number): number {
  // Simplified CRC -- in a full implementation this uses a CRC32 lookup table
  reg = (reg ^ val) >>> 0;
  for (let i = 0; i < 8; i++) {
    if (reg & 1) {
      reg = ((reg >>> 1) ^ 0xEDB88320) >>> 0;
    } else {
      reg = (reg >>> 1) >>> 0;
    }
  }
  return reg >>> 0;
}

