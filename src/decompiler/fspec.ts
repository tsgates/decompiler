/**
 * @file fspec_part1.ts
 * @description Function prototype specification classes (Part 1).
 * Covers ParamEntry, ParamTrial, ParamActive, FspecSpace, ParameterPieces,
 * PrototypePieces, EffectRecord, and all ParamList hierarchy classes.
 * Translated from Ghidra's fspec.hh / fspec.cc
 */

import type { int4, uint4, uintb } from '../core/types.js';
import { HOST_ENDIAN } from '../core/types.js';
import { OpCode } from '../core/opcodes.js';
import { Address, Range, RangeList } from '../core/address.js';
import { AddrSpace, spacetype } from '../core/space.js';
import { AddrSpaceManager, JoinRecord, Translate } from '../core/translate.js';
import {
  Encoder, Decoder,
  AttributeId, ElementId,
  ATTRIB_ALIGN, ATTRIB_CONTENT, ATTRIB_CONSTRUCTOR, ATTRIB_DESTRUCTOR,
  ATTRIB_EXTRAPOP, ATTRIB_HIDDENRETPARM, ATTRIB_INDIRECTSTORAGE,
  ATTRIB_METATYPE, ATTRIB_MODEL, ATTRIB_NAME, ATTRIB_NAMELOCK,
  ATTRIB_OFFSET, ATTRIB_SIZE, ATTRIB_SPACE, ATTRIB_STORAGE,
  ATTRIB_THISPTR, ATTRIB_TYPELOCK,
  ELEM_INPUT, ELEM_OUTPUT, ELEM_RETURNADDRESS, ELEM_VOID,
} from '../core/marshal.js';
import { LowlevelError } from '../core/error.js';
import { VarnodeData } from '../core/pcoderaw.js';
import {
  Datatype, type_metatype,
  type_class, string2typeclass, metatype2typeclass,
  registerFuncProtoClass,
} from './type.js';
import { ELEM_PCODE, ELEM_INJECT } from './pcodeinject.js';
import { ELEM_ADDR } from './varnode.js';
import { ModelRule, SizeRestrictedFilter, ConvertToPointer } from './modelrules.js';
type TypeFactory = any;
import type { Writer } from '../util/writer.js';

// ---------------------------------------------------------------------------
// Module augmentations: add decode/encode stubs to core types for fspec usage
// These methods are part of the Ghidra C++ API but not yet on the TS classes.
// ---------------------------------------------------------------------------

declare module '../core/address.js' {
  interface Address {
    encode(encoder: Encoder): void;
  }
}

declare module '../core/space.js' {
  interface AddrSpace {
    encodeAttributes(encoder: Encoder, offset?: bigint): void;
  }
}

// ---------------------------------------------------------------------------
// Forward type declarations for not-yet-implemented modules
// ---------------------------------------------------------------------------

type Architecture = any;
type Funcdata = any;
type ScopeLocal = any;
type BlockBasic = any;
type FlowBlock = any;
type PcodeOp = any;
type Varnode = any;
type HighVariable = any;
type Symbol = any;
type SymbolEntry = any;
type Override = any;
type Scope = any;
type Varnode_t = any;

// Forward declarations for modelrules types not imported
type AssignAction = any;
type DatatypeFilter = any;

// AssignAction response codes
export const AssignActionCode = {
  success: 0,
  fail: 1,
  no_assignment: 2,
  hiddenret_ptrparam: 3,
  hiddenret_specialreg: 4,
  hiddenret_specialreg_void: 5,
} as const;

// ---------------------------------------------------------------------------
// AttributeId / ElementId constants defined in fspec.cc
// ---------------------------------------------------------------------------

const ATTRIB_FIRST                       = new AttributeId('first', 27);
export const ATTRIB_CUSTOM               = new AttributeId('custom', 114);
export const ATTRIB_DOTDOTDOT            = new AttributeId('dotdotdot', 115);
export const ATTRIB_EXTENSION            = new AttributeId('extension', 116);
export const ATTRIB_HASTHIS              = new AttributeId('hasthis', 117);
export const ATTRIB_INLINE               = new AttributeId('inline', 118);
export const ATTRIB_KILLEDBYCALL         = new AttributeId('killedbycall', 119);
export const ATTRIB_MAXSIZE              = new AttributeId('maxsize', 120);
export const ATTRIB_MINSIZE              = new AttributeId('minsize', 121);
export const ATTRIB_MODELLOCK            = new AttributeId('modellock', 122);
export const ATTRIB_NORETURN             = new AttributeId('noreturn', 123);
export const ATTRIB_POINTERMAX           = new AttributeId('pointermax', 124);
export const ATTRIB_SEPARATEFLOAT        = new AttributeId('separatefloat', 125);
export const ATTRIB_STACKSHIFT           = new AttributeId('stackshift', 126);
export const ATTRIB_STRATEGY             = new AttributeId('strategy', 127);
export const ATTRIB_THISBEFORERETPOINTER = new AttributeId('thisbeforeretpointer', 128);
export const ATTRIB_VOIDLOCK             = new AttributeId('voidlock', 129);

export const ELEM_GROUP             = new ElementId('group', 160);
export const ELEM_INTERNALLIST      = new ElementId('internallist', 161);
export const ELEM_KILLEDBYCALL      = new ElementId('killedbycall', 162);
export const ELEM_LIKELYTRASH       = new ElementId('likelytrash', 163);
export const ELEM_LOCALRANGE        = new ElementId('localrange', 164);
export const ELEM_MODEL             = new ElementId('model', 165);
export const ELEM_PARAM             = new ElementId('param', 166);
export const ELEM_PARAMRANGE        = new ElementId('paramrange', 167);
export const ELEM_PENTRY            = new ElementId('pentry', 168);
export const ELEM_PROTOTYPE         = new ElementId('prototype', 169);
export const ELEM_RESOLVEPROTOTYPE  = new ElementId('resolveprototype', 170);
export const ELEM_RETPARAM          = new ElementId('retparam', 171);
export const ELEM_RETURNSYM         = new ElementId('returnsym', 172);
export const ELEM_UNAFFECTED        = new ElementId('unaffected', 173);
export const ELEM_INTERNAL_STORAGE  = new ElementId('internal_storage', 286);
// Needed for decode but defined in modelrules
export const ELEM_RULE              = new ElementId('rule', 153);

// ---------------------------------------------------------------------------
// ParamUnassignedError
// ---------------------------------------------------------------------------

export class ParamUnassignedError extends LowlevelError {
  constructor(s: string) {
    super(s);
  }
}

// ---------------------------------------------------------------------------
// ParamEntry
// ---------------------------------------------------------------------------

/** Flags for ParamEntry */
export const ParamEntryFlags = {
  force_left_justify: 1,
  reverse_stack: 2,
  smallsize_zext: 4,
  smallsize_sext: 8,
  smallsize_inttype: 0x20,
  smallsize_floatext: 0x40,
  extracheck_high: 0x80,
  extracheck_low: 0x100,
  is_grouped: 0x200,
  overlapping: 0x400,
  first_storage: 0x800,
} as const;

/** Containment codes for ParamEntry */
export const ParamContainment = {
  no_containment: 0,
  contains_unjustified: 1,
  contains_justified: 2,
  contained_by: 3,
} as const;

/**
 * A contiguous range of memory that can be used to pass parameters.
 */
export class ParamEntry {
  // Static containment constants (mirroring enum)
  static readonly no_containment = ParamContainment.no_containment;
  static readonly contains_unjustified = ParamContainment.contains_unjustified;
  static readonly contains_justified = ParamContainment.contains_justified;
  static readonly contained_by = ParamContainment.contained_by;

  // Static flag constants
  static readonly force_left_justify = ParamEntryFlags.force_left_justify;
  static readonly reverse_stack = ParamEntryFlags.reverse_stack;
  static readonly smallsize_zext = ParamEntryFlags.smallsize_zext;
  static readonly smallsize_sext = ParamEntryFlags.smallsize_sext;
  static readonly smallsize_inttype = ParamEntryFlags.smallsize_inttype;
  static readonly smallsize_floatext = ParamEntryFlags.smallsize_floatext;
  static readonly extracheck_high = ParamEntryFlags.extracheck_high;
  static readonly extracheck_low = ParamEntryFlags.extracheck_low;
  static readonly is_grouped = ParamEntryFlags.is_grouped;
  static readonly overlapping = ParamEntryFlags.overlapping;
  static readonly first_storage = ParamEntryFlags.first_storage;

  private flags: uint4 = 0;
  private type: type_class = type_class.TYPECLASS_GENERAL;
  private groupSet: int4[] = [];
  private spaceid: AddrSpace | null = null;
  private addressbase: uintb = 0n;
  private size: int4 = 0;
  private minsize: int4 = 0;
  private alignment: int4 = 0;
  private numslots: int4 = 1;
  private joinrec: JoinRecord | null = null;

  constructor(grp: int4) {
    this.groupSet.push(grp);
  }

  /**
   * Find a ParamEntry matching the given storage Varnode.
   * Searches the list backward.
   */
  private static findEntryByStorage(entryList: ParamEntry[], vn: VarnodeData): ParamEntry | null {
    for (let i = entryList.length - 1; i >= 0; --i) {
      const entry = entryList[i];
      if (entry.spaceid === vn.space && entry.addressbase === vn.offset && entry.size === vn.size) {
        return entry;
      }
    }
    return null;
  }

  /**
   * Mark if this is the first ParamEntry in its storage class.
   */
  private resolveFirst(curList: ParamEntry[]): void {
    // curList includes this entry as the last element
    if (curList.length <= 1) {
      this.flags |= ParamEntry.first_storage;
      return;
    }
    const prev = curList[curList.length - 2];
    if (this.type !== prev.type) {
      this.flags |= ParamEntry.first_storage;
    }
  }

  /**
   * Make adjustments for a join ParamEntry.
   */
  private resolveJoin(curList: ParamEntry[]): void {
    if (this.spaceid!.getType() !== spacetype.IPTR_JOIN) {
      this.joinrec = null;
      return;
    }
    this.joinrec = this.spaceid!.getManager().findJoin(this.addressbase);
    this.groupSet = [];
    for (let i = 0; i < this.joinrec!.numPieces(); ++i) {
      const entry = ParamEntry.findEntryByStorage(curList, this.joinrec!.getPiece(i));
      if (entry !== null) {
        this.groupSet.push(...entry.groupSet);
        this.flags |= (i === 0) ? ParamEntry.extracheck_low : ParamEntry.extracheck_high;
      }
    }
    if (this.groupSet.length === 0)
      throw new LowlevelError('<pentry> join must overlap at least one previous entry');
    this.groupSet.sort((a, b) => a - b);
    this.flags |= ParamEntry.overlapping;
  }

  /**
   * Make adjustments for ParamEntry that overlaps others.
   */
  private resolveOverlap(curList: ParamEntry[]): void {
    if (this.joinrec !== null)
      return;
    const overlapSet: int4[] = [];
    const addr = new Address(this.spaceid!, this.addressbase);
    // curList includes this entry as the last element; check all entries before it
    for (let i = 0; i < curList.length - 1; ++i) {
      const entry = curList[i];
      if (!entry.intersects(addr, this.size)) continue;
      if (this.contains(entry)) {
        if (entry.isOverlap()) continue;
        overlapSet.push(...entry.groupSet);
        if (this.addressbase === entry.addressbase)
          this.flags |= this.spaceid!.isBigEndian() ? ParamEntry.extracheck_low : ParamEntry.extracheck_high;
        else
          this.flags |= this.spaceid!.isBigEndian() ? ParamEntry.extracheck_high : ParamEntry.extracheck_low;
      } else {
        throw new LowlevelError('Illegal overlap of <pentry> in compiler spec');
      }
    }
    if (overlapSet.length === 0) return;
    overlapSet.sort((a, b) => a - b);
    this.groupSet = overlapSet;
    this.flags |= ParamEntry.overlapping;
  }

  /**
   * Is the logical value left-justified within its container?
   */
  private isLeftJustified(): boolean {
    return ((this.flags & ParamEntry.force_left_justify) !== 0) || !this.spaceid!.isBigEndian();
  }

  getGroup(): int4 { return this.groupSet[0]; }
  getAllGroups(): int4[] { return this.groupSet; }

  groupOverlap(op2: ParamEntry): boolean {
    let i = 0;
    let j = 0;
    let valThis = this.groupSet[i];
    let valOther = op2.groupSet[j];
    while (valThis !== valOther) {
      if (valThis < valOther) {
        i += 1;
        if (i >= this.groupSet.length) return false;
        valThis = this.groupSet[i];
      } else {
        j += 1;
        if (j >= op2.groupSet.length) return false;
        valOther = op2.groupSet[j];
      }
    }
    return true;
  }

  getSize(): int4 { return this.size; }
  getMinSize(): int4 { return this.minsize; }
  getAlign(): int4 { return this.alignment; }
  getJoinRecord(): JoinRecord | null { return this.joinrec; }
  getType(): type_class { return this.type; }
  isExclusion(): boolean { return this.alignment === 0; }
  isReverseStack(): boolean { return (this.flags & ParamEntry.reverse_stack) !== 0; }
  isGrouped(): boolean { return (this.flags & ParamEntry.is_grouped) !== 0; }
  isOverlap(): boolean { return (this.flags & ParamEntry.overlapping) !== 0; }
  isFirstInClass(): boolean { return (this.flags & ParamEntry.first_storage) !== 0; }

  subsumesDefinition(op2: ParamEntry): boolean {
    if (this.type !== type_class.TYPECLASS_GENERAL && op2.type !== this.type) return false;
    if (this.spaceid !== op2.spaceid) return false;
    if (op2.addressbase < this.addressbase) return false;
    if ((op2.addressbase + BigInt(op2.size - 1)) > (this.addressbase + BigInt(this.size - 1))) return false;
    if (this.alignment !== op2.alignment) return false;
    return true;
  }

  containedBy(addr: Address, sz: int4): boolean {
    if (this.spaceid !== addr.getSpace()) return false;
    if (this.addressbase < addr.getOffset()) return false;
    const entryoff = this.addressbase + BigInt(this.size - 1);
    const rangeoff = addr.getOffset() + BigInt(sz - 1);
    return (entryoff <= rangeoff);
  }

  intersects(addr: Address, sz: int4): boolean {
    let rangeend: uintb;
    if (this.joinrec !== null) {
      rangeend = addr.getOffset() + BigInt(sz - 1);
      for (let i = 0; i < this.joinrec.numPieces(); ++i) {
        const vdata = this.joinrec.getPiece(i);
        if (addr.getSpace() !== vdata.space) continue;
        const vdataend = vdata.offset + BigInt(vdata.size - 1);
        if (addr.getOffset() < vdata.offset && rangeend < vdataend) continue;
        if (addr.getOffset() > vdata.offset && rangeend > vdataend) continue;
        return true;
      }
    }
    if (this.spaceid !== addr.getSpace()) return false;
    rangeend = addr.getOffset() + BigInt(sz - 1);
    const thisend = this.addressbase + BigInt(this.size - 1);
    if (addr.getOffset() < this.addressbase && rangeend < thisend) return false;
    if (addr.getOffset() > this.addressbase && rangeend > thisend) return false;
    return true;
  }

  justifiedContain(addr: Address, sz: int4): int4 {
    if (this.joinrec !== null) {
      let res = 0;
      for (let i = this.joinrec.numPieces() - 1; i >= 0; --i) {
        const vdata = this.joinrec.getPiece(i);
        const rawAddr = vdata.getAddr();
        const cur = new Address(rawAddr.getSpace() as any, rawAddr.getOffset()).justifiedContain(vdata.size, addr, sz, false);
        if (cur < 0)
          res += vdata.size;
        else {
          return res + cur;
        }
      }
      return -1;
    }
    if (this.alignment === 0) {
      const entry = new Address(this.spaceid!, this.addressbase);
      return entry.justifiedContain(this.size, addr, sz, (this.flags & ParamEntry.force_left_justify) !== 0);
    }
    if (this.spaceid !== addr.getSpace()) return -1;
    const startaddr = addr.getOffset();
    if (startaddr < this.addressbase) return -1;
    const endaddr = startaddr + BigInt(sz - 1);
    if (endaddr < startaddr) return -1;
    if (endaddr > (this.addressbase + BigInt(this.size - 1))) return -1;
    const relStart = startaddr - this.addressbase;
    const relEnd = endaddr - this.addressbase;
    if (!this.isLeftJustified()) {
      const res = Number((relEnd + 1n) % BigInt(this.alignment));
      if (res === 0) return 0;
      return this.alignment - res;
    }
    return Number(relStart % BigInt(this.alignment));
  }

  getContainer(addr: Address, sz: int4, res: VarnodeData): boolean {
    const endaddr = addr.add(BigInt(sz - 1));
    if (this.joinrec !== null) {
      for (let i = this.joinrec.numPieces() - 1; i >= 0; --i) {
        const vdata = this.joinrec.getPiece(i);
        if ((addr.overlap(0, vdata.getAddr() as any as Address, vdata.size) >= 0) &&
            (endaddr.overlap(0, vdata.getAddr() as any as Address, vdata.size) >= 0)) {
          res.space = vdata.space;
          res.offset = vdata.offset;
          res.size = vdata.size;
          return true;
        }
      }
      return false;
    }
    const entry = new Address(this.spaceid!, this.addressbase);
    if (addr.overlap(0, entry, this.size) < 0) return false;
    if (endaddr.overlap(0, entry, this.size) < 0) return false;
    if (this.alignment === 0) {
      res.space = this.spaceid!;
      res.offset = this.addressbase;
      res.size = this.size;
      return true;
    }
    const al = (addr.getOffset() - this.addressbase) % BigInt(this.alignment);
    res.space = this.spaceid!;
    res.offset = addr.getOffset() - al;
    res.size = Number(endaddr.getOffset() - res.offset) + 1;
    const al2 = res.size % this.alignment;
    if (al2 !== 0)
      res.size += (this.alignment - al2);
    return true;
  }

  contains(op2: ParamEntry): boolean {
    if (op2.joinrec !== null) return false;
    if (this.joinrec === null) {
      const addr = new Address(this.spaceid!, this.addressbase);
      return op2.containedBy(addr, this.size);
    }
    for (let i = 0; i < this.joinrec.numPieces(); ++i) {
      const vdata = this.joinrec.getPiece(i);
      const addr = vdata.getAddr() as any as Address;
      if (op2.containedBy(addr, vdata.size))
        return true;
    }
    return false;
  }

  assumedExtension(addr: Address, sz: int4, res: VarnodeData): OpCode {
    if ((this.flags & (ParamEntry.smallsize_zext | ParamEntry.smallsize_sext | ParamEntry.smallsize_inttype)) === 0)
      return OpCode.CPUI_COPY;
    if (this.alignment !== 0) {
      if (sz >= this.alignment) return OpCode.CPUI_COPY;
    } else if (sz >= this.size) {
      return OpCode.CPUI_COPY;
    }
    if (this.joinrec !== null) return OpCode.CPUI_COPY;
    if (this.justifiedContain(addr, sz) !== 0) return OpCode.CPUI_COPY;
    if (this.alignment === 0) {
      res.space = this.spaceid!;
      res.offset = this.addressbase;
      res.size = this.size;
    } else {
      res.space = this.spaceid!;
      const alignAdjust = Number((addr.getOffset() - this.addressbase) % BigInt(this.alignment));
      res.offset = addr.getOffset() - BigInt(alignAdjust);
      res.size = this.alignment;
    }
    if ((this.flags & ParamEntry.smallsize_zext) !== 0)
      return OpCode.CPUI_INT_ZEXT;
    if ((this.flags & ParamEntry.smallsize_inttype) !== 0)
      return OpCode.CPUI_PIECE;
    return OpCode.CPUI_INT_SEXT;
  }

  getSlot(addr: Address, skip: int4): int4 {
    let res = this.groupSet[0];
    if (this.alignment !== 0) {
      const diff = addr.getOffset() + BigInt(skip) - this.addressbase;
      const baseslot = Number(diff) / this.alignment | 0;
      if (this.isReverseStack())
        res += (this.numslots - 1) - baseslot;
      else
        res += baseslot;
    } else if (skip !== 0) {
      res = this.groupSet[this.groupSet.length - 1];
    }
    return res;
  }

  getSpace(): AddrSpace { return this.spaceid!; }
  getBase(): uintb { return this.addressbase; }

  /**
   * Calculate storage address assigned when allocating a parameter of given size.
   * (3-argument overload uses default right-justify based on endianness)
   */
  getAddrBySlot(slotnum: { val: int4 }, sz: int4, typeAlign: int4, justifyRight?: boolean): Address {
    if (justifyRight === undefined) {
      justifyRight = !this.isLeftJustified();
    }
    let res = Address.invalid();
    let spaceused: int4;
    if (sz < this.minsize) return res;
    if (this.alignment === 0) {
      if (slotnum.val !== 0) return res;
      if (sz > this.size) return res;
      res = new Address(this.spaceid!, this.addressbase);
      spaceused = this.size;
      if (((this.flags & ParamEntry.smallsize_floatext) !== 0) && (sz !== this.size)) {
        const manager = this.spaceid!.getManager();
        res = (manager as any).constructFloatExtensionAddress(res, this.size, sz);
        return res;
      }
    } else {
      if (typeAlign > this.alignment) {
        const tmp = (slotnum.val * this.alignment) % typeAlign;
        if (tmp !== 0)
          slotnum.val += (typeAlign - tmp) / this.alignment;
      }
      let slotsused = (sz / this.alignment) | 0;
      if ((sz % this.alignment) !== 0)
        slotsused += 1;
      if (slotnum.val + slotsused > this.numslots) return res;
      spaceused = slotsused * this.alignment;
      let index: int4;
      if (this.isReverseStack()) {
        index = this.numslots;
        index -= slotnum.val;
        index -= slotsused;
      } else {
        index = slotnum.val;
      }
      res = new Address(this.spaceid!, this.addressbase + BigInt(index * this.alignment));
      slotnum.val += slotsused;
    }
    if (justifyRight)
      res = res.add(BigInt(spaceused - sz));
    return res;
  }

  decode(decoder: Decoder, normalstack: boolean, grouped: boolean, curList: ParamEntry[]): void {
    this.flags = 0;
    this.type = type_class.TYPECLASS_GENERAL;
    this.size = -1;
    this.minsize = -1;
    this.alignment = 0;
    this.numslots = 1;

    const elemId = decoder.openElementId(ELEM_PENTRY);
    for (;;) {
      const attribId = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_MINSIZE.getId()) {
        this.minsize = decoder.readSignedInteger();
      } else if (attribId === ATTRIB_SIZE.getId()) {
        this.alignment = decoder.readSignedInteger();
      } else if (attribId === ATTRIB_ALIGN.getId()) {
        this.alignment = decoder.readSignedInteger();
      } else if (attribId === ATTRIB_MAXSIZE.getId()) {
        this.size = decoder.readSignedInteger();
      } else if (attribId === ATTRIB_STORAGE.getId() || attribId === ATTRIB_METATYPE.getId()) {
        this.type = string2typeclass(decoder.readString());
      } else if (attribId === ATTRIB_EXTENSION.getId()) {
        this.flags &= ~(ParamEntry.smallsize_zext | ParamEntry.smallsize_sext | ParamEntry.smallsize_inttype);
        const ext = decoder.readString();
        if (ext === 'sign')
          this.flags |= ParamEntry.smallsize_sext;
        else if (ext === 'zero')
          this.flags |= ParamEntry.smallsize_zext;
        else if (ext === 'inttype')
          this.flags |= ParamEntry.smallsize_inttype;
        else if (ext === 'float')
          this.flags |= ParamEntry.smallsize_floatext;
        else if (ext !== 'none')
          throw new LowlevelError('Bad extension attribute');
      } else {
        throw new LowlevelError('Unknown <pentry> attribute');
      }
    }
    if (this.size === -1 || this.minsize === -1)
      throw new LowlevelError('ParamEntry not fully specified');
    if (this.alignment === this.size)
      this.alignment = 0;
    const addr = Address.decode(decoder);
    decoder.closeElement(elemId);
    this.spaceid = addr.getSpace();
    this.addressbase = addr.getOffset();
    if (this.alignment !== 0) {
      this.numslots = (this.size / this.alignment) | 0;
    }
    if (this.spaceid!.isReverseJustified()) {
      if (this.spaceid!.isBigEndian())
        this.flags |= ParamEntry.force_left_justify;
      else
        throw new LowlevelError('No support for right justification in little endian encoding');
    }
    if (!normalstack) {
      this.flags |= ParamEntry.reverse_stack;
      if (this.alignment !== 0) {
        if ((this.size % this.alignment) !== 0)
          throw new LowlevelError('For positive stack growth, <pentry> size must match alignment');
      }
    }
    if (grouped)
      this.flags |= ParamEntry.is_grouped;
    this.resolveFirst(curList);
    this.resolveJoin(curList);
    this.resolveOverlap(curList);
  }

  isParamCheckHigh(): boolean { return (this.flags & ParamEntry.extracheck_high) !== 0; }
  isParamCheckLow(): boolean { return (this.flags & ParamEntry.extracheck_low) !== 0; }

  static orderWithinGroup(entry1: ParamEntry, entry2: ParamEntry): void {
    if (entry2.minsize > entry1.size || entry1.minsize > entry2.size)
      return;
    if (entry1.type !== entry2.type) {
      if (entry1.type === type_class.TYPECLASS_GENERAL) {
        throw new LowlevelError('<pentry> tags with a specific type must come before the general type');
      }
      return;
    }
    throw new LowlevelError('<pentry> tags within a group must be distinguished by size or type');
  }
}

// ---------------------------------------------------------------------------
// ParamEntryRange  (simplified -- no rangemap, use linear search)
// ---------------------------------------------------------------------------

/**
 * Helper for storing ParamEntry objects in an interval range (rangemap).
 * Simplified from the C++ rangemap template to use array-based searching.
 */
export class ParamEntryRange {
  first: uintb;
  last: uintb;
  position: int4;
  entry: ParamEntry;

  constructor(position: int4, entry: ParamEntry, first: uintb, last: uintb) {
    this.first = first;
    this.last = last;
    this.position = position;
    this.entry = entry;
  }

  getFirst(): uintb { return this.first; }
  getLast(): uintb { return this.last; }
  getParamEntry(): ParamEntry { return this.entry; }
}

/**
 * A map from offset to ParamEntry.
 * Simplified replacement for the C++ rangemap<ParamEntryRange>.
 */
export class ParamEntryResolver {
  private ranges: ParamEntryRange[] = [];

  insert(position: int4, entry: ParamEntry, first: uintb, last: uintb): void {
    this.ranges.push(new ParamEntryRange(position, entry, first, last));
  }

  /**
   * Find all ranges that contain the given offset.
   */
  find(offset: uintb): ParamEntryRange[] {
    const result: ParamEntryRange[] = [];
    for (const r of this.ranges) {
      if (offset >= r.first && offset <= r.last) {
        result.push(r);
      }
    }
    return result;
  }

  /**
   * Find all ranges that start at or after `startOff` up through `endOff`.
   */
  find_begin(startOff: uintb): ParamEntryRange[] {
    const result: ParamEntryRange[] = [];
    for (const r of this.ranges) {
      if (r.last >= startOff) {
        result.push(r);
      }
    }
    return result;
  }

  find_end(endOff: uintb): ParamEntryRange[] {
    const result: ParamEntryRange[] = [];
    for (const r of this.ranges) {
      if (r.first <= endOff) {
        result.push(r);
      }
    }
    return result;
  }

  /**
   * Find all ranges whose intervals overlap with [startOff, endOff].
   */
  find_range(startOff: uintb, endOff: uintb): ParamEntryRange[] {
    const result: ParamEntryRange[] = [];
    for (const r of this.ranges) {
      if (r.first <= endOff && r.last >= startOff) {
        result.push(r);
      }
    }
    return result;
  }

  isEmpty(): boolean { return this.ranges.length === 0; }
}

// ---------------------------------------------------------------------------
// ParamTrial
// ---------------------------------------------------------------------------

export const ParamTrialFlags = {
  checked: 1,
  used: 2,
  defnouse: 4,
  active: 8,
  unref: 0x10,
  killedbycall: 0x20,
  rem_formed: 0x40,
  indcreate_formed: 0x80,
  condexe_effect: 0x100,
  ancestor_realistic: 0x200,
  ancestor_solid: 0x400,
} as const;

/**
 * A register or memory range that may be used to pass a parameter or return value.
 */
export class ParamTrial {
  private flags: uint4;
  private addr: Address;
  private size: int4;
  private slot: int4;
  private entry: ParamEntry | null;
  private offset: int4;
  private fixedPosition: int4;

  constructor(ad: Address, sz: int4, sl: int4) {
    this.addr = ad;
    this.size = sz;
    this.slot = sl;
    this.flags = 0;
    this.entry = null;
    this.offset = -1;
    this.fixedPosition = -1;
  }

  getAddress(): Address { return this.addr; }
  getSize(): int4 { return this.size; }
  getSlot(): int4 { return this.slot; }
  setSlot(val: int4): void { this.slot = val; }
  getEntry(): ParamEntry | null { return this.entry; }
  getOffset(): int4 { return this.offset; }
  setEntry(ent: ParamEntry | null, off: int4): void { this.entry = ent; this.offset = off; }
  markUsed(): void { this.flags |= ParamTrialFlags.used; }
  markActive(): void { this.flags |= (ParamTrialFlags.active | ParamTrialFlags.checked); }
  markInactive(): void { this.flags &= ~ParamTrialFlags.active; this.flags |= ParamTrialFlags.checked; }
  markNoUse(): void {
    this.flags &= ~(ParamTrialFlags.active | ParamTrialFlags.used);
    this.flags |= (ParamTrialFlags.checked | ParamTrialFlags.defnouse);
  }
  markUnref(): void { this.flags |= (ParamTrialFlags.unref | ParamTrialFlags.checked); this.slot = -1; }
  markKilledByCall(): void { this.flags |= ParamTrialFlags.killedbycall; }
  isChecked(): boolean { return (this.flags & ParamTrialFlags.checked) !== 0; }
  isActive(): boolean { return (this.flags & ParamTrialFlags.active) !== 0; }
  isDefinitelyNotUsed(): boolean { return (this.flags & ParamTrialFlags.defnouse) !== 0; }
  isUsed(): boolean { return (this.flags & ParamTrialFlags.used) !== 0; }
  isUnref(): boolean { return (this.flags & ParamTrialFlags.unref) !== 0; }
  isKilledByCall(): boolean { return (this.flags & ParamTrialFlags.killedbycall) !== 0; }
  setRemFormed(): void { this.flags |= ParamTrialFlags.rem_formed; }
  isRemFormed(): boolean { return (this.flags & ParamTrialFlags.rem_formed) !== 0; }
  setIndCreateFormed(): void { this.flags |= ParamTrialFlags.indcreate_formed; }
  isIndCreateFormed(): boolean { return (this.flags & ParamTrialFlags.indcreate_formed) !== 0; }
  setCondExeEffect(): void { this.flags |= ParamTrialFlags.condexe_effect; }
  hasCondExeEffect(): boolean { return (this.flags & ParamTrialFlags.condexe_effect) !== 0; }
  setAncestorRealistic(): void { this.flags |= ParamTrialFlags.ancestor_realistic; }
  hasAncestorRealistic(): boolean { return (this.flags & ParamTrialFlags.ancestor_realistic) !== 0; }
  setAncestorSolid(): void { this.flags |= ParamTrialFlags.ancestor_solid; }
  hasAncestorSolid(): boolean { return (this.flags & ParamTrialFlags.ancestor_solid) !== 0; }
  slotGroup(): int4 { return this.entry!.getSlot(this.addr, this.size - 1); }
  setAddress(ad: Address, sz: int4): void { this.addr = ad; this.size = sz; }

  splitHi(sz: int4): ParamTrial {
    const res = new ParamTrial(this.addr, sz, this.slot);
    res.flags = this.flags;
    return res;
  }

  splitLo(sz: int4): ParamTrial {
    const newaddr = this.addr.add(BigInt(this.size - sz));
    const res = new ParamTrial(newaddr, sz, this.slot + 1);
    res.flags = this.flags;
    return res;
  }

  testShrink(newaddr: Address, sz: int4): boolean {
    let testaddr: Address;
    if (this.addr.isBigEndian())
      testaddr = this.addr.add(BigInt(this.size - sz));
    else
      testaddr = this.addr;
    if (!testaddr.equals(newaddr)) return false;
    if (this.entry !== null) return false;
    return true;
  }

  /**
   * Sort trials in formal parameter order.
   */
  compareTo(b: ParamTrial): number {
    if (this.entry === null) return 1;
    if (b.entry === null) return -1;
    const grpa = this.entry.getGroup();
    const grpb = b.entry.getGroup();
    if (grpa !== grpb) return grpa < grpb ? -1 : 1;
    if (this.entry !== b.entry) return 0;  // Arbitrary but consistent
    if (this.entry.isExclusion()) {
      if (this.offset !== b.offset) return this.offset < b.offset ? -1 : 1;
      return 0;
    }
    if (!this.addr.equals(b.addr)) {
      if (this.entry.isReverseStack())
        return b.addr.lessThan(this.addr) ? -1 : 1;
      else
        return this.addr.lessThan(b.addr) ? -1 : 1;
    }
    if (this.size !== b.size) return this.size < b.size ? -1 : 1;
    return 0;
  }

  setFixedPosition(pos: int4): void { this.fixedPosition = pos; }

  static fixedPositionCompare(a: ParamTrial, b: ParamTrial): number {
    if (a.fixedPosition === -1 && b.fixedPosition === -1) {
      return a.compareTo(b);
    }
    if (a.fixedPosition === -1) return 1;
    if (b.fixedPosition === -1) return -1;
    return a.fixedPosition < b.fixedPosition ? -1 : (a.fixedPosition > b.fixedPosition ? 1 : 0);
  }
}

// ---------------------------------------------------------------------------
// ParamActive
// ---------------------------------------------------------------------------

/**
 * Container class for ParamTrial objects.
 */
export class ParamActive {
  private trial: ParamTrial[] = [];
  private slotbase: int4;
  private stackplaceholder: int4;
  private numpasses: int4;
  private maxpass: int4;
  private isfullychecked: boolean;
  private needsfinalcheck: boolean;
  private recoversubcall: boolean;
  private joinReverse: boolean;

  constructor(recoversub: boolean) {
    this.slotbase = 1;
    this.stackplaceholder = -1;
    this.numpasses = 0;
    this.maxpass = 0;
    this.isfullychecked = false;
    this.needsfinalcheck = false;
    this.recoversubcall = recoversub;
    this.joinReverse = false;
  }

  clear(): void {
    this.trial = [];
    this.slotbase = 1;
    this.stackplaceholder = -1;
    this.numpasses = 0;
    this.isfullychecked = false;
    this.joinReverse = false;
  }

  registerTrial(addr: Address, sz: int4): void {
    this.trial.push(new ParamTrial(addr, sz, this.slotbase));
    if (addr.getSpace()!.getType() !== spacetype.IPTR_SPACEBASE)
      this.trial[this.trial.length - 1].markKilledByCall();
    this.slotbase += 1;
  }

  getNumTrials(): int4 { return this.trial.length; }
  getTrial(i: int4): ParamTrial { return this.trial[i]; }

  getTrialForInputVarnode(slot: int4): ParamTrial {
    slot -= ((this.stackplaceholder < 0) || (slot < this.stackplaceholder)) ? 1 : 2;
    return this.trial[slot];
  }

  whichTrial(addr: Address, sz: int4): int4 {
    for (let i = 0; i < this.trial.length; ++i) {
      if (addr.overlap(0, this.trial[i].getAddress(), this.trial[i].getSize()) >= 0) return i;
      if (sz <= 1) return -1;
      const endaddr = addr.add(BigInt(sz - 1));
      if (endaddr.overlap(0, this.trial[i].getAddress(), this.trial[i].getSize()) >= 0) return i;
    }
    return -1;
  }

  needsFinalCheck(): boolean { return this.needsfinalcheck; }
  markNeedsFinalCheck(): void { this.needsfinalcheck = true; }
  isJoinReverse(): boolean { return this.joinReverse; }
  setJoinReverse(): void { this.joinReverse = true; }
  isRecoverSubcall(): boolean { return this.recoversubcall; }
  isFullyChecked(): boolean { return this.isfullychecked; }
  markFullyChecked(): void { this.isfullychecked = true; }

  setPlaceholderSlot(): void {
    this.stackplaceholder = this.slotbase;
    this.slotbase += 1;
  }

  freePlaceholderSlot(): void {
    for (let i = 0; i < this.trial.length; ++i) {
      if (this.trial[i].getSlot() > this.stackplaceholder)
        this.trial[i].setSlot(this.trial[i].getSlot() - 1);
    }
    this.stackplaceholder = -2;
    this.slotbase -= 1;
    this.maxpass = 0;
  }

  getNumPasses(): int4 { return this.numpasses; }
  getMaxPass(): int4 { return this.maxpass; }
  setMaxPass(val: int4): void { this.maxpass = val; }
  finishPass(): void { this.numpasses += 1; }

  sortTrials(): void {
    this.trial.sort((a, b) => a.compareTo(b));
  }

  sortFixedPosition(): void {
    this.trial.sort(ParamTrial.fixedPositionCompare);
  }

  deleteUnusedTrials(): void {
    const newtrials: ParamTrial[] = [];
    let slot = 1;
    for (let i = 0; i < this.trial.length; ++i) {
      const curtrial = this.trial[i];
      if (curtrial.isUsed()) {
        curtrial.setSlot(slot);
        slot += 1;
        newtrials.push(curtrial);
      }
    }
    this.trial = newtrials;
  }

  splitTrial(i: int4, sz: int4): void {
    if (this.stackplaceholder >= 0)
      throw new LowlevelError('Cannot split parameter when the placeholder has not been recovered');
    const newtrials: ParamTrial[] = [];
    const slot = this.trial[i].getSlot();
    for (let j = 0; j < i; ++j) {
      newtrials.push(this.trial[j]);
      const oldslot = newtrials[newtrials.length - 1].getSlot();
      if (oldslot > slot)
        newtrials[newtrials.length - 1].setSlot(oldslot + 1);
    }
    newtrials.push(this.trial[i].splitHi(sz));
    newtrials.push(this.trial[i].splitLo(this.trial[i].getSize() - sz));
    for (let j = i + 1; j < this.trial.length; ++j) {
      newtrials.push(this.trial[j]);
      const oldslot = newtrials[newtrials.length - 1].getSlot();
      if (oldslot > slot)
        newtrials[newtrials.length - 1].setSlot(oldslot + 1);
    }
    this.slotbase += 1;
    this.trial = newtrials;
  }

  joinTrial(slot: int4, addr: Address, sz: int4): void {
    if (this.stackplaceholder >= 0)
      throw new LowlevelError('Cannot join parameters when the placeholder has not been removed');
    const newtrials: ParamTrial[] = [];
    let sizecheck = 0;
    for (let i = 0; i < this.trial.length; ++i) {
      const curtrial = this.trial[i];
      const curslot = curtrial.getSlot();
      if (curslot < slot) {
        newtrials.push(curtrial);
      } else if (curslot === slot) {
        sizecheck += curtrial.getSize();
        const joined = new ParamTrial(addr, sz, slot);
        joined.markUsed();
        joined.markActive();
        newtrials.push(joined);
      } else if (curslot === slot + 1) {
        sizecheck += curtrial.getSize();
      } else {
        newtrials.push(curtrial);
        newtrials[newtrials.length - 1].setSlot(curslot - 1);
      }
    }
    if (sizecheck !== sz)
      throw new LowlevelError('Size mismatch when joining parameters');
    this.slotbase -= 1;
    this.trial = newtrials;
  }

  getNumUsed(): int4 {
    let count: int4;
    for (count = 0; count < this.trial.length; ++count) {
      if (!this.trial[count].isUsed()) break;
    }
    return count;
  }

  testShrink(i: int4, addr: Address, sz: int4): boolean {
    return this.trial[i].testShrink(addr, sz);
  }

  shrink(i: int4, addr: Address, sz: int4): void {
    this.trial[i].setAddress(addr, sz);
  }
}

// ---------------------------------------------------------------------------
// FspecSpace
// ---------------------------------------------------------------------------

/**
 * A special space for encoding FuncCallSpecs.
 */
export class FspecSpace extends AddrSpace {
  static readonly NAME = 'fspec';

  constructor(m: AddrSpaceManager, t: Translate, ind: int4) {
    super(m, t, spacetype.IPTR_FSPEC, FspecSpace.NAME, false, 8, 1, ind, 0, 1, 1);
    this.clearFlags(AddrSpace.heritaged | AddrSpace.does_deadcode | AddrSpace.big_endian);
    if ((HOST_ENDIAN as number) === 1)
      this.setFlags(AddrSpace.big_endian);
  }

  encodeAttributes(encoder: Encoder, offset: uintb, size?: int4): void {
    // FspecSpace encoding is a special case -- this is a stub
    // In practice this is only used with FuncCallSpecs pointers, which are not applicable in TS
    encoder.writeString(ATTRIB_SPACE, 'fspec');
  }

  override printRaw(offset: uintb): string {
    return 'func_0x' + offset.toString(16);
  }

  decode(decoder: Decoder): void {
    throw new LowlevelError('Should never decode fspec space from stream');
  }
}

// ---------------------------------------------------------------------------
// ParameterPieces
// ---------------------------------------------------------------------------

/**
 * Basic elements of a parameter: address, data-type, properties.
 */
export class ParameterPieces {
  static readonly isthis = 1;
  static readonly hiddenretparm = 2;
  static readonly indirectstorage = 4;
  static readonly namelock = 8;
  static readonly typelock = 16;
  static readonly sizelock = 32;

  addr: Address = Address.invalid();
  type: Datatype | null = null;
  flags: uint4 = 0;

  swapMarkup(op: ParameterPieces): void {
    const tmpFlags = this.flags;
    const tmpType = this.type;
    this.flags = op.flags;
    this.type = op.type;
    op.flags = tmpFlags;
    op.type = tmpType;
  }

  assignAddressFromPieces(pieces: VarnodeData[], mostToLeast: boolean, glb: Architecture): void {
    if (!mostToLeast && pieces.length > 1) {
      const reverse: VarnodeData[] = [];
      for (let i = pieces.length - 1; i >= 0; --i)
        reverse.push(pieces[i]);
      pieces.length = 0;
      for (const v of reverse) pieces.push(v);
    }
    JoinRecord.mergeSequence(pieces, (glb as any).translate);
    if (pieces.length === 1) {
      const paddr = pieces[0];
      this.addr = new Address(paddr.space as any as AddrSpace, paddr.offset);
      return;
    }
    const joinRecord: JoinRecord = (glb as any).findAddJoin(pieces, 0);
    const jaddr = joinRecord.getUnified();
    this.addr = new Address(jaddr.space as any as AddrSpace, jaddr.offset);
  }
}

// ---------------------------------------------------------------------------
// PrototypePieces
// ---------------------------------------------------------------------------

/**
 * Raw components of a function prototype (obtained from parsing source code).
 */
export class PrototypePieces {
  model: ProtoModel | null = null;
  name: string = '';
  outtype: Datatype | null = null;
  intypes: Datatype[] = [];
  innames: string[] = [];
  firstVarArgSlot: int4 = -1;
}

// ---------------------------------------------------------------------------
// EffectRecord
// ---------------------------------------------------------------------------

/**
 * Description of the indirect effect a sub-function has on a memory range.
 */
export class EffectRecord {
  static readonly unaffected = 1;
  static readonly killedbycall = 2;
  static readonly return_address = 3;
  static readonly unknown_effect = 4;

  range: VarnodeData;
  type: uint4;

  constructor();
  constructor(addr: Address, size: int4);
  constructor(entry: ParamEntry, t: uint4);
  constructor(data: VarnodeData, t: uint4);
  constructor(addrOrEntryOrData?: Address | ParamEntry | VarnodeData, sizeOrType?: int4 | uint4) {
    this.range = new VarnodeData();
    this.type = EffectRecord.unknown_effect;
    if (addrOrEntryOrData === undefined) {
      return;
    }
    if (addrOrEntryOrData instanceof Address) {
      this.range.space = addrOrEntryOrData.getSpace();
      this.range.offset = addrOrEntryOrData.getOffset();
      this.range.size = sizeOrType as int4;
      this.type = EffectRecord.unknown_effect;
    } else if (addrOrEntryOrData instanceof ParamEntry) {
      this.range.space = addrOrEntryOrData.getSpace();
      this.range.offset = addrOrEntryOrData.getBase();
      this.range.size = addrOrEntryOrData.getSize();
      this.type = sizeOrType as uint4;
    } else if (addrOrEntryOrData instanceof VarnodeData) {
      this.range = new VarnodeData();
      this.range.space = addrOrEntryOrData.space;
      this.range.offset = addrOrEntryOrData.offset;
      this.range.size = addrOrEntryOrData.size;
      this.type = sizeOrType as uint4;
    }
  }

  static createCopy(op2: EffectRecord): EffectRecord {
    const r = new EffectRecord();
    r.range = new VarnodeData();
    r.range.space = op2.range.space;
    r.range.offset = op2.range.offset;
    r.range.size = op2.range.size;
    r.type = op2.type;
    return r;
  }

  getType(): uint4 { return this.type; }
  getAddress(): Address { return new Address(this.range.space as any as AddrSpace, this.range.offset); }
  getSize(): int4 { return this.range.size; }

  equals(op2: EffectRecord): boolean {
    if (!this.range.equals(op2.range)) return false;
    return this.type === op2.type;
  }

  notEquals(op2: EffectRecord): boolean {
    return !this.equals(op2);
  }

  encode(encoder: Encoder): void {
    const addr = new Address(this.range.space as any as AddrSpace, this.range.offset);
    if (this.type === EffectRecord.unaffected || this.type === EffectRecord.killedbycall ||
        this.type === EffectRecord.return_address) {
      (addr as any).encode(encoder, this.range.size);
    } else {
      throw new LowlevelError('Bad EffectRecord type');
    }
  }

  decodeRecord(grouptype: uint4, decoder: Decoder): void {
    this.type = grouptype;
    this.range.decode(decoder);
  }

  static compareByAddress(op1: EffectRecord, op2: EffectRecord): number {
    if (op1.range.space !== op2.range.space)
      return op1.range.space!.getIndex() < op2.range.space!.getIndex() ? -1 : 1;
    if (op1.range.offset !== op2.range.offset)
      return op1.range.offset < op2.range.offset ? -1 : 1;
    return 0;
  }
}

// ---------------------------------------------------------------------------
// ParamList (abstract base)
// ---------------------------------------------------------------------------

/**
 * A group of ParamEntry objects that form a complete set for passing
 * parameters in one direction (either input or output).
 */
export abstract class ParamList {
  static readonly p_standard = 0;
  static readonly p_standard_out = 1;
  static readonly p_register = 2;
  static readonly p_register_out = 3;
  static readonly p_merged = 4;

  abstract getType(): uint4;
  abstract assignMap(proto: PrototypePieces, typefactory: TypeFactory, res: ParameterPieces[]): void;
  abstract fillinMap(active: ParamActive): void;
  abstract checkJoin(hiaddr: Address, hisize: int4, loaddr: Address, losize: int4): boolean;
  abstract checkSplit(loc: Address, size: int4, splitpoint: int4): boolean;
  abstract characterizeAsParam(loc: Address, size: int4): int4;
  abstract possibleParam(loc: Address, size: int4): boolean;
  abstract possibleParamWithSlot(loc: Address, size: int4, slot: { val: int4 }, slotsize: { val: int4 }): boolean;
  abstract getBiggestContainedParam(loc: Address, size: int4, res: VarnodeData): boolean;
  abstract unjustifiedContainer(loc: Address, size: int4, res: VarnodeData): boolean;
  abstract assumedExtension(addr: Address, size: int4, res: VarnodeData): OpCode;
  abstract getSpacebase(): AddrSpace | null;
  abstract isThisBeforeRetPointer(): boolean;
  abstract getRangeList(spc: AddrSpace, res: RangeList): void;
  abstract getMaxDelay(): int4;
  abstract isAutoKilledByCall(): boolean;
  abstract decodeList(decoder: Decoder, effectlist: EffectRecord[], normalstack: boolean): void;
  abstract clone(): ParamList;
}

// ---------------------------------------------------------------------------
// ParamListStandard
// ---------------------------------------------------------------------------

/**
 * A standard model for parameters as an ordered list of storage resources.
 */
export class ParamListStandard extends ParamList {
  protected numgroup: int4 = 0;
  protected maxdelay: int4 = 0;
  protected thisbeforeret: boolean = false;
  protected autoKilledByCall_: boolean = false;
  protected resourceStart: int4[] = [];
  protected entry: ParamEntry[] = [];
  protected resolverMap: (ParamEntryResolver | null)[] = [];
  protected modelRules: any[] = [];  // ModelRule[]
  protected spacebase: AddrSpace | null = null;

  constructor();
  constructor(op2: ParamListStandard);
  constructor(op2?: ParamListStandard) {
    super();
    if (op2 !== undefined) {
      this.numgroup = op2.numgroup;
      // Deep copy entries
      this.entry = [];
      for (const e of op2.entry) {
        // ParamEntry is reference-shared in practice; for a proper deep copy
        // we would need clone, but here we share references as in the C++
        this.entry.push(e);
      }
      this.spacebase = op2.spacebase;
      this.maxdelay = op2.maxdelay;
      this.thisbeforeret = op2.thisbeforeret;
      this.autoKilledByCall_ = op2.autoKilledByCall_;
      this.resourceStart = [...op2.resourceStart];
      // ModelRules are forward-declared; copy references
      this.modelRules = [...op2.modelRules];
      this.populateResolver();
    }
  }

  getEntry(): ParamEntry[] { return this.entry; }

  isBigEndian(): boolean {
    return this.entry.length > 0 && this.entry[0].getSpace().isBigEndian();
  }

  extractTiles(tiles: ParamEntry[], type: type_class): void {
    for (const curEntry of this.entry) {
      if (!curEntry.isExclusion()) continue;
      if (curEntry.getType() !== type || curEntry.getAllGroups().length !== 1) continue;
      tiles.push(curEntry);
    }
  }

  getStackEntry(): ParamEntry | null {
    if (this.entry.length > 0) {
      const curEntry = this.entry[this.entry.length - 1];
      if (!curEntry.isExclusion() && curEntry.getSpace().getType() === spacetype.IPTR_SPACEBASE) {
        return curEntry;
      }
    }
    return null;
  }

  protected findEntry(loc: Address, size: int4, just: boolean): ParamEntry | null {
    const index = loc.getSpace()!.getIndex();
    if (index >= this.resolverMap.length) return null;
    const resolver = this.resolverMap[index];
    if (resolver === null) return null;
    const ranges = resolver.find(loc.getOffset());
    for (const r of ranges) {
      const testEntry = r.getParamEntry();
      if (testEntry.getMinSize() > size) continue;
      if (!just || testEntry.justifiedContain(loc, size) === 0)
        return testEntry;
    }
    return null;
  }

  protected selectUnreferenceEntry(grp: int4, prefType: type_class): ParamEntry | null {
    let bestScore = -1;
    let bestEntry: ParamEntry | null = null;
    for (const curEntry of this.entry) {
      if (curEntry.getGroup() !== grp) continue;
      let curScore: int4;
      if (curEntry.getType() === prefType)
        curScore = 2;
      else if (prefType === type_class.TYPECLASS_GENERAL)
        curScore = 1;
      else
        curScore = 0;
      if (curScore > bestScore) {
        bestScore = curScore;
        bestEntry = curEntry;
      }
    }
    return bestEntry;
  }

  protected buildTrialMap(active: ParamActive): void {
    const hitlist: (ParamEntry | null)[] = [];
    let floatCount = 0;
    let intCount = 0;

    for (let i = 0; i < active.getNumTrials(); ++i) {
      const paramtrial = active.getTrial(i);
      const entrySlot = this.findEntry(paramtrial.getAddress(), paramtrial.getSize(), true);
      if (entrySlot === null) {
        paramtrial.markNoUse();
      } else {
        paramtrial.setEntry(entrySlot, 0);
        if (paramtrial.isActive()) {
          if (entrySlot.getType() === type_class.TYPECLASS_FLOAT)
            floatCount += 1;
          else
            intCount += 1;
        }
        const grp = entrySlot.getGroup();
        while (hitlist.length <= grp)
          hitlist.push(null);
        if (hitlist[grp] === null)
          hitlist[grp] = entrySlot;
      }
    }

    for (let i = 0; i < hitlist.length; ++i) {
      let curentry = hitlist[i];
      if (curentry === null) {
        curentry = this.selectUnreferenceEntry(i,
          (floatCount > intCount) ? type_class.TYPECLASS_FLOAT : type_class.TYPECLASS_GENERAL);
        if (curentry === null) continue;
        const sz = curentry.isExclusion() ? curentry.getSize() : curentry.getAlign();
        const nextslot = { val: 0 };
        const addr = curentry.getAddrBySlot(nextslot, sz, 1);
        const trialpos = active.getNumTrials();
        active.registerTrial(addr, sz);
        const paramtrial = active.getTrial(trialpos);
        paramtrial.markUnref();
        paramtrial.setEntry(curentry, 0);
      } else if (!curentry.isExclusion()) {
        const slotlist: int4[] = [];
        for (let j = 0; j < active.getNumTrials(); ++j) {
          const paramtrial = active.getTrial(j);
          if (paramtrial.getEntry() !== curentry) continue;
          let slot = curentry.getSlot(paramtrial.getAddress(), 0) - curentry.getGroup();
          let endslot = curentry.getSlot(paramtrial.getAddress(), paramtrial.getSize() - 1) - curentry.getGroup();
          if (endslot < slot) {
            const tmp = slot;
            slot = endslot;
            endslot = tmp;
          }
          while (slotlist.length <= endslot) slotlist.push(0);
          while (slot <= endslot) {
            slotlist[slot] = 1;
            slot += 1;
          }
        }
        for (let j = 0; j < slotlist.length; ++j) {
          if (slotlist[j] === 0) {
            const nextslot = { val: j };
            const addr = curentry.getAddrBySlot(nextslot, curentry.getAlign(), 1);
            const trialpos = active.getNumTrials();
            active.registerTrial(addr, curentry.getAlign());
            const paramtrial = active.getTrial(trialpos);
            paramtrial.markUnref();
            paramtrial.setEntry(curentry, 0);
          }
        }
      }
    }
    active.sortTrials();
  }

  protected separateSections(active: ParamActive, trialStart: int4[]): void {
    const numtrials = active.getNumTrials();
    let currentTrial = 0;
    let nextGroup = this.resourceStart[1];
    let nextSection = 2;
    trialStart.push(currentTrial);
    for (; currentTrial < numtrials; ++currentTrial) {
      const curtrial = active.getTrial(currentTrial);
      if (curtrial.getEntry() === null) continue;
      if (curtrial.getEntry()!.getGroup() >= nextGroup) {
        if (nextSection > this.resourceStart.length)
          throw new LowlevelError('Missing next resource start');
        nextGroup = this.resourceStart[nextSection];
        nextSection += 1;
        trialStart.push(currentTrial);
      }
    }
    trialStart.push(numtrials);
  }

  protected static markGroupNoUse(active: ParamActive, activeTrial: int4, trialStart: int4): void {
    const numTrials = active.getNumTrials();
    const activeEntry = active.getTrial(activeTrial).getEntry()!;
    for (let i = trialStart; i < numTrials; ++i) {
      if (i === activeTrial) continue;
      const othertrial = active.getTrial(i);
      if (othertrial.isDefinitelyNotUsed()) continue;
      if (!othertrial.getEntry()!.groupOverlap(activeEntry)) break;
      othertrial.markNoUse();
    }
  }

  protected static markBestInactive(active: ParamActive, group: int4, groupStart: int4, prefType: type_class): void {
    const numTrials = active.getNumTrials();
    let bestTrial = -1;
    let bestScore = -1;
    for (let i = groupStart; i < numTrials; ++i) {
      const trial = active.getTrial(i);
      if (trial.isDefinitelyNotUsed()) continue;
      const entry = trial.getEntry()!;
      const grp = entry.getGroup();
      if (grp !== group) break;
      if (entry.getAllGroups().length > 1) continue;
      let score = 0;
      if (trial.hasAncestorRealistic()) {
        score += 5;
        if (trial.hasAncestorSolid())
          score += 5;
      }
      if (entry.getType() === prefType)
        score += 1;
      if (score > bestScore) {
        bestScore = score;
        bestTrial = i;
      }
    }
    if (bestTrial >= 0)
      ParamListStandard.markGroupNoUse(active, bestTrial, groupStart);
  }

  protected static forceExclusionGroup(active: ParamActive): void {
    const numTrials = active.getNumTrials();
    let curGroup = -1;
    let groupStart = -1;
    let inactiveCount = 0;
    for (let i = 0; i < numTrials; ++i) {
      const curtrial = active.getTrial(i);
      if (curtrial.isDefinitelyNotUsed() || !curtrial.getEntry()!.isExclusion())
        continue;
      const grp = curtrial.getEntry()!.getGroup();
      if (grp !== curGroup) {
        if (inactiveCount > 1)
          ParamListStandard.markBestInactive(active, curGroup, groupStart, type_class.TYPECLASS_GENERAL);
        curGroup = grp;
        groupStart = i;
        inactiveCount = 0;
      }
      if (curtrial.isActive()) {
        ParamListStandard.markGroupNoUse(active, i, groupStart);
      } else {
        inactiveCount += 1;
      }
    }
    if (inactiveCount > 1)
      ParamListStandard.markBestInactive(active, curGroup, groupStart, type_class.TYPECLASS_GENERAL);
  }

  protected static forceNoUse(active: ParamActive, start: int4, stop: int4): void {
    let seendefnouse = false;
    let curgroup = -1;
    let exclusion = false;
    let alldefnouse = false;
    for (let i = start; i < stop; ++i) {
      const curtrial = active.getTrial(i);
      if (curtrial.getEntry() === null) continue;
      const grp = curtrial.getEntry()!.getGroup();
      exclusion = curtrial.getEntry()!.isExclusion();
      if ((grp <= curgroup) && exclusion) {
        if (!curtrial.isDefinitelyNotUsed())
          alldefnouse = false;
      } else {
        if (alldefnouse)
          seendefnouse = true;
        alldefnouse = curtrial.isDefinitelyNotUsed();
        curgroup = grp;
      }
      if (seendefnouse)
        curtrial.markInactive();
    }
  }

  protected static forceInactiveChain(active: ParamActive, maxchain: int4, start: int4, stop: int4, groupstart: int4): void {
    let seenchain = false;
    let chainlength = 0;
    let max = -1;
    for (let i = start; i < stop; ++i) {
      const trial = active.getTrial(i);
      if (trial.isDefinitelyNotUsed()) continue;
      if (!trial.isActive()) {
        if (trial.isUnref() && active.isRecoverSubcall()) {
          if (trial.getAddress().getSpace()!.getType() === spacetype.IPTR_SPACEBASE)
            seenchain = true;
        }
        if (i === start) {
          chainlength += (trial.slotGroup() - groupstart + 1);
        } else {
          chainlength += trial.slotGroup() - active.getTrial(i - 1).slotGroup();
        }
        if (chainlength > maxchain)
          seenchain = true;
      } else {
        chainlength = 0;
        if (!seenchain)
          max = i;
      }
      if (seenchain)
        trial.markInactive();
    }
    for (let i = start; i <= max; ++i) {
      const trial = active.getTrial(i);
      if (trial.isDefinitelyNotUsed()) continue;
      if (!trial.isActive())
        trial.markActive();
    }
  }

  protected calcDelay(): void {
    this.maxdelay = 0;
    for (const e of this.entry) {
      const delay = e.getSpace().getDelay();
      if (delay > this.maxdelay)
        this.maxdelay = delay;
    }
  }

  protected addResolverRange(spc: AddrSpace, first: uintb, last: uintb, paramEntry: ParamEntry, position: int4): void {
    const index = spc.getIndex();
    while (this.resolverMap.length <= index) {
      this.resolverMap.push(null);
    }
    let resolver = this.resolverMap[index];
    if (resolver === null) {
      resolver = new ParamEntryResolver();
      this.resolverMap[index] = resolver;
    }
    resolver.insert(position, paramEntry, first, last);
  }

  protected populateResolver(): void {
    // Clear existing resolvers
    this.resolverMap = [];
    let position = 0;
    for (const paramEntry of this.entry) {
      const spc = paramEntry.getSpace();
      if (spc.getType() === spacetype.IPTR_JOIN) {
        const joinRec = paramEntry.getJoinRecord()!;
        for (let i = 0; i < joinRec.numPieces(); ++i) {
          const vData = joinRec.getPiece(i);
          const last = vData.offset + BigInt(vData.size - 1);
          this.addResolverRange(vData.space as any as AddrSpace, vData.offset, last, paramEntry, position);
          position += 1;
        }
      } else {
        const first = paramEntry.getBase();
        const last = first + BigInt(paramEntry.getSize() - 1);
        this.addResolverRange(spc, first, last, paramEntry, position);
        position += 1;
      }
    }
  }

  protected parsePentry(decoder: Decoder, effectlist: EffectRecord[],
                        groupid: int4, normalstack: boolean, splitFloat: boolean, grouped: boolean): void {
    let lastClass: type_class = type_class.TYPECLASS_CLASS4;
    if (this.entry.length > 0) {
      lastClass = this.entry[this.entry.length - 1].isGrouped()
        ? type_class.TYPECLASS_GENERAL
        : this.entry[this.entry.length - 1].getType();
    }
    const newEntry = new ParamEntry(groupid);
    this.entry.push(newEntry);
    newEntry.decode(decoder, normalstack, grouped, this.entry);
    if (splitFloat) {
      const currentClass = grouped ? type_class.TYPECLASS_GENERAL : newEntry.getType();
      if (lastClass !== currentClass) {
        if (lastClass < currentClass)
          throw new LowlevelError('parameter list entries must be ordered by storage class');
        this.resourceStart.push(groupid);
      }
    }
    const spc = newEntry.getSpace();
    if (spc.getType() === spacetype.IPTR_SPACEBASE)
      this.spacebase = spc;
    else if (this.autoKilledByCall_)
      effectlist.push(new EffectRecord(newEntry, EffectRecord.killedbycall));

    const maxgroup = newEntry.getAllGroups()[newEntry.getAllGroups().length - 1] + 1;
    if (maxgroup > this.numgroup)
      this.numgroup = maxgroup;
  }

  protected parseGroup(decoder: Decoder, effectlist: EffectRecord[],
                       groupid: int4, normalstack: boolean, splitFloat: boolean): void {
    const basegroup = this.numgroup;
    let previous1: ParamEntry | null = null;
    let previous2: ParamEntry | null = null;
    const elemId = decoder.openElementId(ELEM_GROUP);
    while (decoder.peekElement() !== 0) {
      this.parsePentry(decoder, effectlist, basegroup, normalstack, splitFloat, true);
      const pentry = this.entry[this.entry.length - 1];
      if (pentry.getSpace().getType() === spacetype.IPTR_JOIN)
        throw new LowlevelError('<pentry> in the join space not allowed in <group> tag');
      if (previous1 !== null) {
        ParamEntry.orderWithinGroup(previous1, pentry);
        if (previous2 !== null)
          ParamEntry.orderWithinGroup(previous2, pentry);
      }
      previous2 = previous1;
      previous1 = pentry;
    }
    decoder.closeElement(elemId);
  }

  assignAddressFallback(resource: type_class, tp: Datatype, matchExact: boolean,
                        status: int4[], param: ParameterPieces): uint4 {
    for (const curEntry of this.entry) {
      const grp = curEntry.getGroup();
      if (status[grp] < 0) continue;
      if (resource !== curEntry.getType()) {
        if (matchExact || curEntry.getType() !== type_class.TYPECLASS_GENERAL)
          continue;
      }
      const slotRef = { val: status[grp] };
      param.addr = curEntry.getAddrBySlot(slotRef, (tp as any).getAlignSize(), (tp as any).getAlignment());
      status[grp] = slotRef.val;
      if (param.addr.isInvalid()) continue;
      if (curEntry.isExclusion()) {
        const groupSet = curEntry.getAllGroups();
        for (let j = 0; j < groupSet.length; ++j)
          status[groupSet[j]] = -1;
      }
      param.type = tp;
      param.flags = 0;
      return AssignActionCode.success;
    }
    return AssignActionCode.fail;
  }

  assignAddress(dt: Datatype, proto: PrototypePieces, pos: int4, tlist: TypeFactory,
                status: int4[], res: ParameterPieces): uint4 {
    for (const rule of this.modelRules) {
      const responseCode = (rule as any).assignAddress(dt, proto, pos, tlist, status, res);
      if (responseCode !== AssignActionCode.fail)
        return responseCode;
    }
    const store = metatype2typeclass((dt as any).getMetatype());
    return this.assignAddressFallback(store, dt, false, status, res);
  }

  // ParamList interface

  getType(): uint4 { return ParamList.p_standard; }

  assignMap(proto: PrototypePieces, typefactory: TypeFactory, res: ParameterPieces[]): void {
    const status: int4[] = new Array(this.numgroup).fill(0);

    if (res.length === 2) {
      const dt = res[res.length - 1].type!;
      if ((res[res.length - 1].flags & ParameterPieces.hiddenretparm) !== 0) {
        if (this.assignAddressFallback(type_class.TYPECLASS_HIDDENRET, dt, false, status, res[res.length - 1]) === AssignActionCode.fail) {
          throw new ParamUnassignedError('Cannot assign parameter address for ' + (dt as any).getName());
        }
      } else {
        if (this.assignAddress(dt, proto, 0, typefactory, status, res[res.length - 1]) === AssignActionCode.fail) {
          throw new ParamUnassignedError('Cannot assign parameter address for ' + (dt as any).getName());
        }
      }
      res[res.length - 1].flags |= ParameterPieces.hiddenretparm;
    }
    for (let i = 0; i < proto.intypes.length; ++i) {
      const piece = new ParameterPieces();
      res.push(piece);
      const dt = proto.intypes[i];
      const responseCode = this.assignAddress(dt, proto, i, typefactory, status, piece);
      if (responseCode === AssignActionCode.fail || responseCode === AssignActionCode.no_assignment)
        throw new ParamUnassignedError('Cannot assign parameter address for ' + (dt as any).getName());
    }
  }

  fillinMap(active: ParamActive): void {
    if (active.getNumTrials() === 0) return;
    if (this.entry.length === 0)
      throw new LowlevelError('Cannot derive parameter storage for prototype model without parameter entries');

    this.buildTrialMap(active);
    ParamListStandard.forceExclusionGroup(active);
    const trialStart: int4[] = [];
    this.separateSections(active, trialStart);
    const numSection = trialStart.length - 1;
    for (let i = 0; i < numSection; ++i) {
      ParamListStandard.forceNoUse(active, trialStart[i], trialStart[i + 1]);
    }
    for (let i = 0; i < numSection; ++i) {
      ParamListStandard.forceInactiveChain(active, 2, trialStart[i], trialStart[i + 1], this.resourceStart[i]);
    }
    for (let i = 0; i < active.getNumTrials(); ++i) {
      const paramtrial = active.getTrial(i);
      if (paramtrial.isActive())
        paramtrial.markUsed();
    }
  }

  checkJoin(hiaddr: Address, hisize: int4, loaddr: Address, losize: int4): boolean {
    const entryHi = this.findEntry(hiaddr, hisize, true);
    if (entryHi === null) return false;
    const entryLo = this.findEntry(loaddr, losize, true);
    if (entryLo === null) return false;
    if (entryHi.getGroup() === entryLo.getGroup()) {
      if (entryHi.isExclusion() || entryLo.isExclusion()) return false;
      if (!hiaddr.isContiguous(hisize, loaddr, losize)) return false;
      if (Number((hiaddr.getOffset() - entryHi.getBase()) % BigInt(entryHi.getAlign())) !== 0) return false;
      if (Number((loaddr.getOffset() - entryLo.getBase()) % BigInt(entryLo.getAlign())) !== 0) return false;
      return true;
    } else {
      const sizesum = hisize + losize;
      for (const e of this.entry) {
        if (e.getSize() < sizesum) continue;
        if (e.justifiedContain(loaddr, losize) !== 0) continue;
        if (e.justifiedContain(hiaddr, hisize) !== losize) continue;
        return true;
      }
    }
    return false;
  }

  checkSplit(loc: Address, size: int4, splitpoint: int4): boolean {
    const loc2 = loc.add(BigInt(splitpoint));
    const size2 = size - splitpoint;
    let entryNum = this.findEntry(loc, splitpoint, true);
    if (entryNum === null) return false;
    entryNum = this.findEntry(loc2, size2, true);
    if (entryNum === null) return false;
    return true;
  }

  characterizeAsParam(loc: Address, size: int4): int4 {
    const index = loc.getSpace()!.getIndex();
    if (index >= this.resolverMap.length) return ParamEntry.no_containment;
    const resolver = this.resolverMap[index];
    if (resolver === null) return ParamEntry.no_containment;
    const ranges = resolver.find(loc.getOffset());
    let resContains = false;
    let resContainedBy = false;
    for (const r of ranges) {
      const testEntry = r.getParamEntry();
      const off = testEntry.justifiedContain(loc, size);
      if (off === 0) return ParamEntry.contains_justified;
      else if (off > 0) resContains = true;
      if (testEntry.isExclusion() && testEntry.containedBy(loc, size))
        resContainedBy = true;
    }
    if (resContains) return ParamEntry.contains_unjustified;
    if (resContainedBy) return ParamEntry.contained_by;
    // Check further ranges
    const endOff = loc.getOffset() + BigInt(size - 1);
    const furtherRanges = resolver.find_range(loc.getOffset(), endOff);
    for (const r of furtherRanges) {
      const testEntry = r.getParamEntry();
      if (testEntry.isExclusion() && testEntry.containedBy(loc, size)) {
        return ParamEntry.contained_by;
      }
    }
    return ParamEntry.no_containment;
  }

  possibleParam(loc: Address, size: int4): boolean {
    return this.findEntry(loc, size, true) !== null;
  }

  possibleParamWithSlot(loc: Address, size: int4, slot: { val: int4 }, slotsize: { val: int4 }): boolean {
    const entryNum = this.findEntry(loc, size, true);
    if (entryNum === null) return false;
    slot.val = entryNum.getSlot(loc, 0);
    if (entryNum.isExclusion()) {
      slotsize.val = entryNum.getAllGroups().length;
    } else {
      slotsize.val = (((size - 1) / entryNum.getAlign()) | 0) + 1;
    }
    return true;
  }

  getBiggestContainedParam(loc: Address, size: int4, res: VarnodeData): boolean {
    const index = loc.getSpace()!.getIndex();
    if (index >= this.resolverMap.length) return false;
    const resolver = this.resolverMap[index];
    if (resolver === null) return false;
    const endLoc = loc.add(BigInt(size - 1));
    if (endLoc.getOffset() < loc.getOffset()) return false;
    let maxEntry: ParamEntry | null = null;
    const ranges = resolver.find_range(loc.getOffset(), endLoc.getOffset());
    for (const r of ranges) {
      const testEntry = r.getParamEntry();
      if (testEntry.containedBy(loc, size)) {
        if (maxEntry === null)
          maxEntry = testEntry;
        else if (testEntry.getSize() > maxEntry.getSize())
          maxEntry = testEntry;
      }
    }
    if (maxEntry !== null) {
      if (!maxEntry.isExclusion()) return false;
      res.space = maxEntry.getSpace();
      res.offset = maxEntry.getBase();
      res.size = maxEntry.getSize();
      return true;
    }
    return false;
  }

  unjustifiedContainer(loc: Address, size: int4, res: VarnodeData): boolean {
    for (const e of this.entry) {
      if (e.getMinSize() > size) continue;
      const just = e.justifiedContain(loc, size);
      if (just < 0) continue;
      if (just === 0) return false;
      e.getContainer(loc, size, res);
      return true;
    }
    return false;
  }

  assumedExtension(addr: Address, size: int4, res: VarnodeData): OpCode {
    for (const e of this.entry) {
      if (e.getMinSize() > size) continue;
      const ext = e.assumedExtension(addr, size, res);
      if (ext !== OpCode.CPUI_COPY)
        return ext;
    }
    return OpCode.CPUI_COPY;
  }

  getSpacebase(): AddrSpace | null { return this.spacebase; }
  isThisBeforeRetPointer(): boolean { return this.thisbeforeret; }

  getRangeList(spc: AddrSpace, res: RangeList): void {
    for (const e of this.entry) {
      if (e.getSpace() !== spc) continue;
      const baseoff = e.getBase();
      const endoff = baseoff + BigInt(e.getSize() - 1);
      res.insertRange(spc, baseoff, endoff);
    }
  }

  getMaxDelay(): int4 { return this.maxdelay; }
  isAutoKilledByCall(): boolean { return this.autoKilledByCall_; }

  decodeList(decoder: Decoder, effectlist: EffectRecord[], normalstack: boolean): void {
    this.numgroup = 0;
    this.spacebase = null;
    let pointermax = 0;
    this.thisbeforeret = false;
    this.autoKilledByCall_ = false;
    let splitFloat = true;
    const elemId = decoder.openElement();
    for (;;) {
      const attribId = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_POINTERMAX.getId()) {
        pointermax = decoder.readSignedInteger();
      } else if (attribId === ATTRIB_THISBEFORERETPOINTER.getId()) {
        this.thisbeforeret = decoder.readBool();
      } else if (attribId === ATTRIB_KILLEDBYCALL.getId()) {
        this.autoKilledByCall_ = decoder.readBool();
      } else if (attribId === ATTRIB_SEPARATEFLOAT.getId()) {
        splitFloat = decoder.readBool();
      }
    }
    for (;;) {
      const subId = decoder.peekElement();
      if (subId === 0) break;
      if (subId === ELEM_PENTRY.getId()) {
        this.parsePentry(decoder, effectlist, this.numgroup, normalstack, splitFloat, false);
      } else if (subId === ELEM_GROUP.getId()) {
        this.parseGroup(decoder, effectlist, this.numgroup, normalstack, splitFloat);
      } else {
        break;
      }
    }
    for (;;) {
      const subId = decoder.peekElement();
      if (subId === 0) break;
      if (subId === ELEM_RULE.getId()) {
        const rule = new ModelRule();
        rule.decode(decoder, this);
        this.modelRules.push(rule);
      } else {
        throw new LowlevelError('<pentry> and <group> elements must come before any <rule>');
      }
    }
    decoder.closeElement(elemId);
    this.resourceStart.push(this.numgroup);
    this.calcDelay();
    this.populateResolver();
    if (pointermax > 0) {
      const sizeFilter = new SizeRestrictedFilter(pointermax + 1, 0);
      const convertAction = new ConvertToPointer(this);
      const rule = new ModelRule(sizeFilter, convertAction, this);
      this.modelRules.push(rule);
    }
  }

  clone(): ParamList {
    return new ParamListStandard(this);
  }
}

// ---------------------------------------------------------------------------
// ParamListStandardOut
// ---------------------------------------------------------------------------

/**
 * A standard model for returning output parameters from a function.
 */
export class ParamListStandardOut extends ParamListStandard {
  protected useFillinFallback: boolean = true;

  constructor();
  constructor(op2: ParamListStandardOut);
  constructor(op2?: ParamListStandardOut) {
    if (op2 !== undefined) {
      super(op2);
      this.useFillinFallback = op2.useFillinFallback;
    } else {
      super();
    }
  }

  private initialize(): void {
    this.useFillinFallback = true;
    for (const rule of this.modelRules) {
      if ((rule as any).canAffectFillinOutput()) {
        this.useFillinFallback = false;
        break;
      }
    }
    if (this.useFillinFallback)
      this.autoKilledByCall_ = true;
  }

  fillinMapFallback(active: ParamActive, firstOnly: boolean): void {
    let bestentry: ParamEntry | null = null;
    let bestcover = 0;
    let bestclass: type_class = type_class.TYPECLASS_PTR;

    for (const curentry of this.entry) {
      if (firstOnly && !curentry.isFirstInClass() && curentry.isExclusion() && curentry.getAllGroups().length === 1) {
        continue;
      }
      let putativematch = false;
      for (let j = 0; j < active.getNumTrials(); ++j) {
        const paramtrial = active.getTrial(j);
        if (paramtrial.isActive()) {
          const res = curentry.justifiedContain(paramtrial.getAddress(), paramtrial.getSize());
          if (res >= 0) {
            paramtrial.setEntry(curentry, res);
            putativematch = true;
          } else {
            paramtrial.setEntry(null, 0);
          }
        } else {
          paramtrial.setEntry(null, 0);
        }
      }
      if (!putativematch) continue;
      active.sortTrials();
      let offmatch = 0;
      let k: int4;
      for (k = 0; k < active.getNumTrials(); ++k) {
        const paramtrial = active.getTrial(k);
        if (paramtrial.getEntry() === null) continue;
        if (offmatch !== paramtrial.getOffset()) break;
        if (((offmatch === 0) && curentry.isParamCheckLow()) ||
            ((offmatch !== 0) && curentry.isParamCheckHigh())) {
          if (paramtrial.isRemFormed()) break;
          if (paramtrial.isIndCreateFormed()) break;
        }
        offmatch += paramtrial.getSize();
      }
      if (offmatch < curentry.getMinSize())
        k = 0;
      if ((k === active.getNumTrials()) && ((curentry.getType() < bestclass) || (offmatch > bestcover))) {
        bestentry = curentry;
        bestcover = offmatch;
        bestclass = curentry.getType();
      }
    }
    if (bestentry === null) {
      for (let i = 0; i < active.getNumTrials(); ++i)
        active.getTrial(i).markNoUse();
    } else {
      for (let i = 0; i < active.getNumTrials(); ++i) {
        const paramtrial = active.getTrial(i);
        if (paramtrial.isActive()) {
          const res = bestentry.justifiedContain(paramtrial.getAddress(), paramtrial.getSize());
          if (res >= 0) {
            paramtrial.markUsed();
            paramtrial.setEntry(bestentry, res);
          } else {
            paramtrial.markNoUse();
            paramtrial.setEntry(null, 0);
          }
        } else {
          paramtrial.markNoUse();
          paramtrial.setEntry(null, 0);
        }
      }
      active.sortTrials();
    }
  }

  getType(): uint4 { return ParamList.p_standard_out; }

  assignMap(proto: PrototypePieces, typefactory: TypeFactory, res: ParameterPieces[]): void {
    const status: int4[] = new Array(this.numgroup).fill(0);
    const piece = new ParameterPieces();
    res.push(piece);
    if ((proto.outtype as any).getMetatype() === type_metatype.TYPE_VOID) {
      piece.type = proto.outtype;
      piece.flags = 0;
      return;
    }
    let responseCode = this.assignAddress(proto.outtype!, proto, -1, typefactory, status, piece);

    if (responseCode === AssignActionCode.fail)
      responseCode = AssignActionCode.hiddenret_ptrparam;

    if (responseCode === AssignActionCode.hiddenret_ptrparam ||
        responseCode === AssignActionCode.hiddenret_specialreg ||
        responseCode === AssignActionCode.hiddenret_specialreg_void) {
      let spc = this.spacebase;
      if (spc === null)
        spc = (typefactory as any).getArch().getDefaultDataSpace();
      const pointersize: int4 = spc!.getAddrSize();
      const wordsize: int4 = spc!.getWordSize();
      const pointertp: Datatype = (typefactory as any).getTypePointer(pointersize, proto.outtype, wordsize);
      if (responseCode === AssignActionCode.hiddenret_specialreg_void) {
        piece.type = (typefactory as any).getTypeVoid();
      } else {
        piece.type = pointertp;
        if (this.assignAddress(pointertp, proto, -1, typefactory, status, piece) === AssignActionCode.fail) {
          throw new ParamUnassignedError('Cannot assign return value as a pointer');
        }
      }
      piece.flags = ParameterPieces.indirectstorage;

      const extraPiece = new ParameterPieces();
      res.push(extraPiece);
      extraPiece.type = pointertp;
      const isSpecial = (responseCode === AssignActionCode.hiddenret_specialreg ||
                         responseCode === AssignActionCode.hiddenret_specialreg_void);
      extraPiece.flags = isSpecial ? ParameterPieces.hiddenretparm : 0;
    }
  }

  fillinMap(active: ParamActive): void {
    if (active.getNumTrials() === 0) return;
    if (this.useFillinFallback) {
      this.fillinMapFallback(active, false);
      return;
    }
    for (let i = 0; i < active.getNumTrials(); ++i) {
      const trial = active.getTrial(i);
      trial.setEntry(null, 0);
      if (!trial.isActive()) continue;
      const entry = this.findEntry(trial.getAddress(), trial.getSize(), false);
      if (entry === null) {
        trial.markNoUse();
        continue;
      }
      const res = entry.justifiedContain(trial.getAddress(), trial.getSize());
      if ((trial.isRemFormed() || trial.isIndCreateFormed()) && !entry.isFirstInClass()) {
        trial.markNoUse();
        continue;
      }
      trial.setEntry(entry, res);
    }
    active.sortTrials();
    for (const rule of this.modelRules) {
      if ((rule as any).fillinOutputMap(active)) {
        for (let i = 0; i < active.getNumTrials(); ++i) {
          const trial = active.getTrial(i);
          if (trial.isActive()) {
            trial.markUsed();
          } else {
            trial.markNoUse();
            trial.setEntry(null, 0);
          }
        }
        return;
      }
    }
    this.fillinMapFallback(active, true);
  }

  possibleParam(loc: Address, size: int4): boolean {
    for (const e of this.entry) {
      if (e.justifiedContain(loc, size) >= 0)
        return true;
    }
    return false;
  }

  decodeList(decoder: Decoder, effectlist: EffectRecord[], normalstack: boolean): void {
    super.decodeList(decoder, effectlist, normalstack);
    this.initialize();
  }

  clone(): ParamList {
    return new ParamListStandardOut(this);
  }
}

// ---------------------------------------------------------------------------
// ParamListRegisterOut
// ---------------------------------------------------------------------------

/**
 * A model for passing back return values from a function.
 */
export class ParamListRegisterOut extends ParamListStandardOut {
  constructor();
  constructor(op2: ParamListRegisterOut);
  constructor(op2?: ParamListRegisterOut) {
    if (op2 !== undefined) {
      super(op2);
    } else {
      super();
    }
  }

  getType(): uint4 { return ParamList.p_register_out; }

  assignMap(proto: PrototypePieces, typefactory: TypeFactory, res: ParameterPieces[]): void {
    const status: int4[] = new Array(this.numgroup).fill(0);
    const piece = new ParameterPieces();
    res.push(piece);
    if ((proto.outtype as any).getMetatype() !== type_metatype.TYPE_VOID) {
      this.assignAddress(proto.outtype!, proto, -1, typefactory, status, piece);
      if (piece.addr.isInvalid())
        throw new ParamUnassignedError('Cannot assign parameter address for ' + (proto.outtype as any).getName());
    } else {
      piece.type = proto.outtype;
      piece.flags = 0;
    }
  }

  clone(): ParamList {
    return new ParamListRegisterOut(this);
  }
}

// ---------------------------------------------------------------------------
// ParamListRegister
// ---------------------------------------------------------------------------

/**
 * An unstructured model for passing input parameters to a function.
 */
export class ParamListRegister extends ParamListStandard {
  constructor();
  constructor(op2: ParamListRegister);
  constructor(op2?: ParamListRegister) {
    if (op2 !== undefined) {
      super(op2);
    } else {
      super();
    }
  }

  getType(): uint4 { return ParamList.p_register; }

  fillinMap(active: ParamActive): void {
    if (active.getNumTrials() === 0) return;
    for (let i = 0; i < active.getNumTrials(); ++i) {
      const paramtrial = active.getTrial(i);
      const entrySlot = this.findEntry(paramtrial.getAddress(), paramtrial.getSize(), true);
      if (entrySlot === null) {
        paramtrial.markNoUse();
      } else {
        paramtrial.setEntry(entrySlot, 0);
        if (paramtrial.isActive())
          paramtrial.markUsed();
      }
    }
    active.sortTrials();
  }

  clone(): ParamList {
    return new ParamListRegister(this);
  }
}

// ---------------------------------------------------------------------------
// ParamListMerged
// ---------------------------------------------------------------------------

/**
 * A union of other input parameter passing models.
 */
export class ParamListMerged extends ParamListStandard {
  constructor();
  constructor(op2: ParamListMerged);
  constructor(op2?: ParamListMerged) {
    if (op2 !== undefined) {
      super(op2);
    } else {
      super();
    }
  }

  foldIn(op2: ParamListStandard): void {
    if (this.entry.length === 0) {
      this.spacebase = op2.getSpacebase();
      this.entry = [...op2.getEntry()];
      return;
    }
    if ((this.spacebase !== op2.getSpacebase()) && (op2.getSpacebase() !== null))
      throw new LowlevelError('Cannot merge prototype models with different stacks');

    const op2entries = op2.getEntry();
    for (const opentry of op2entries) {
      let typeint = 0;
      let matchIndex = -1;
      for (let idx = 0; idx < this.entry.length; ++idx) {
        if (this.entry[idx].subsumesDefinition(opentry)) {
          typeint = 2;
          matchIndex = idx;
          break;
        }
        if (opentry.subsumesDefinition(this.entry[idx])) {
          typeint = 1;
          matchIndex = idx;
          break;
        }
      }
      if (typeint === 2) {
        if (this.entry[matchIndex].getMinSize() !== opentry.getMinSize())
          typeint = 0;
      } else if (typeint === 1) {
        if (this.entry[matchIndex].getMinSize() !== opentry.getMinSize())
          typeint = 0;
        else
          this.entry[matchIndex] = opentry;  // Replace with the containing entry
      }
      if (typeint === 0)
        this.entry.push(opentry);
    }
  }

  finalize(): void {
    this.populateResolver();
  }

  getType(): uint4 { return ParamList.p_merged; }

  assignMap(proto: PrototypePieces, typefactory: TypeFactory, res: ParameterPieces[]): void {
    throw new LowlevelError('Cannot assign prototype before model has been resolved');
  }

  fillinMap(active: ParamActive): void {
    throw new LowlevelError('Cannot determine prototype before model has been resolved');
  }

  clone(): ParamList {
    return new ParamListMerged(this);
  }
}
// ---------------------------------------------------------------------------
// Part 2: ProtoModel, ScoreProtoModel, ProtoModelMerged, ProtoParameter,
// ParameterBasic, ParameterSymbol, and ProtoStore.
// ---------------------------------------------------------------------------

/**
 * Compare two VarnodeData by (space index, offset, size), matching C++ operator<.
 */
function compareVarnodeData(a: VarnodeData, b: VarnodeData): number {
  const ai = a.space!.getIndex();
  const bi = b.space!.getIndex();
  if (ai !== bi) return ai < bi ? -1 : 1;
  if (a.offset !== b.offset) return a.offset < b.offset ? -1 : 1;
  if (a.size !== b.size) return a.size < b.size ? -1 : 1;
  return 0;
}

// ---------------------------------------------------------------------------
// ProtoParameter  (abstract base class)
// ---------------------------------------------------------------------------

/**
 * A function parameter viewed as a name, data-type, and storage address.
 *
 * This is the base class, with derived classes determining what is backing up
 * the information, whether it is a formal Symbol or just internal storage.
 * Both input parameters and return values can be represented with this object.
 */
export abstract class ProtoParameter {

  abstract getName(): string;
  abstract getType(): Datatype;
  abstract getAddress(): Address;
  abstract getSize(): number;
  abstract isTypeLocked(): boolean;
  abstract isNameLocked(): boolean;
  abstract isSizeTypeLocked(): boolean;
  abstract isThisPointer(): boolean;
  abstract isIndirectStorage(): boolean;
  abstract isHiddenReturn(): boolean;
  abstract isNameUndefined(): boolean;
  abstract setTypeLock(val: boolean): void;
  abstract setNameLock(val: boolean): void;
  abstract setThisPointer(val: boolean): void;

  /**
   * Change (override) the data-type of a size-locked parameter.
   */
  abstract overrideSizeLockType(ct: Datatype): void;

  /**
   * Clear this parameter's data-type preserving any size-lock.
   */
  abstract resetSizeLockType(factory: any /* TypeFactory */): void;

  abstract clone(): ProtoParameter;

  /**
   * Retrieve the formal Symbol associated with this parameter.
   * If there is no backing symbol an exception is thrown.
   */
  abstract getSymbol(): Symbol;

  /**
   * Compare storage location and data-type for equality.
   */
  equals(op2: ProtoParameter): boolean {
    if (!this.getAddress().equals(op2.getAddress())) return false;
    if (this.getType() !== op2.getType()) return false;
    return true;
  }

  /**
   * Compare storage location and data-type for inequality.
   */
  notEquals(op2: ProtoParameter): boolean {
    return !this.equals(op2);
  }
}

// ---------------------------------------------------------------------------
// ParameterBasic
// ---------------------------------------------------------------------------

/**
 * A stand-alone parameter with no backing symbol.
 *
 * Name, data-type, and storage location is stored internally to the object.
 * This is suitable for return values, function pointer prototypes, or functions
 * that have not been fully analyzed.
 */
export class ParameterBasic extends ProtoParameter {
  private name_: string;
  private addr: Address;
  private type_: Datatype;
  private flags: number;

  constructor(nm: string, ad: Address, tp: Datatype, fl: number);
  constructor(tp: Datatype);
  constructor(nmOrTp: string | Datatype, ad?: Address, tp?: Datatype, fl?: number) {
    super();
    if (typeof nmOrTp === 'string') {
      this.name_ = nmOrTp;
      this.addr = ad!;
      this.type_ = tp!;
      this.flags = fl!;
    } else {
      // Construct a void parameter
      this.name_ = '';
      this.addr = Address.invalid();
      this.type_ = nmOrTp;
      this.flags = 0;
    }
  }

  getName(): string { return this.name_; }
  getType(): Datatype { return this.type_; }
  getAddress(): Address { return this.addr; }
  getSize(): number { return (this.type_ as any).getSize(); }
  isTypeLocked(): boolean { return (this.flags & ParameterPieces.typelock) !== 0; }
  isNameLocked(): boolean { return (this.flags & ParameterPieces.namelock) !== 0; }
  isSizeTypeLocked(): boolean { return (this.flags & ParameterPieces.sizelock) !== 0; }
  isThisPointer(): boolean { return (this.flags & ParameterPieces.isthis) !== 0; }
  isIndirectStorage(): boolean { return (this.flags & ParameterPieces.indirectstorage) !== 0; }
  isHiddenReturn(): boolean { return (this.flags & ParameterPieces.hiddenretparm) !== 0; }
  isNameUndefined(): boolean { return this.name_.length === 0; }

  setTypeLock(val: boolean): void {
    if (val) {
      this.flags |= ParameterPieces.typelock;
      if ((this.type_ as any).getMetatype() === type_metatype.TYPE_UNKNOWN)
        this.flags |= ParameterPieces.sizelock;
    } else {
      this.flags &= ~(ParameterPieces.typelock | ParameterPieces.sizelock);
    }
  }

  setNameLock(val: boolean): void {
    if (val)
      this.flags |= ParameterPieces.namelock;
    else
      this.flags &= ~ParameterPieces.namelock;
  }

  setThisPointer(val: boolean): void {
    if (val)
      this.flags |= ParameterPieces.isthis;
    else
      this.flags &= ~ParameterPieces.isthis;
  }

  overrideSizeLockType(ct: Datatype): void {
    if ((this.type_ as any).getSize() === (ct as any).getSize()) {
      if (!this.isSizeTypeLocked())
        throw new LowlevelError('Overriding parameter that is not size locked');
      this.type_ = ct;
      return;
    }
    throw new LowlevelError('Overriding parameter with different type size');
  }

  resetSizeLockType(factory: any /* TypeFactory */): void {
    if ((this.type_ as any).getMetatype() === type_metatype.TYPE_UNKNOWN) return;
    const size: number = (this.type_ as any).getSize();
    this.type_ = factory.getBase(size, type_metatype.TYPE_UNKNOWN);
  }

  clone(): ProtoParameter {
    return new ParameterBasic(this.name_, this.addr, this.type_, this.flags);
  }

  getSymbol(): Symbol {
    throw new LowlevelError('Parameter is not a real symbol');
  }
}

// ---------------------------------------------------------------------------
// ParameterSymbol
// ---------------------------------------------------------------------------

/**
 * A parameter with a formal backing Symbol.
 *
 * Input parameters generally have a symbol associated with them.
 * This class holds a reference to the Symbol object and pulls the relevant
 * parameter information off of it.
 */
export class ParameterSymbol extends ProtoParameter {
  sym: Symbol | null;

  constructor() {
    super();
    this.sym = null;
  }

  /** Set the backing symbol (used by ProtoStoreSymbol). */
  setSymbol(s: Symbol): void {
    this.sym = s;
  }

  getName(): string {
    return (this.sym as any).getName();
  }

  getType(): Datatype {
    return (this.sym as any).getType();
  }

  getAddress(): Address {
    return (this.sym as any).getFirstWholeMap().getAddr();
  }

  getSize(): number {
    return (this.sym as any).getFirstWholeMap().getSize();
  }

  isTypeLocked(): boolean {
    return (this.sym as any).isTypeLocked();
  }

  isNameLocked(): boolean {
    return (this.sym as any).isNameLocked();
  }

  isSizeTypeLocked(): boolean {
    return (this.sym as any).isSizeTypeLocked();
  }

  isThisPointer(): boolean {
    return (this.sym as any).isThisPointer();
  }

  isIndirectStorage(): boolean {
    return (this.sym as any).isIndirectStorage();
  }

  isHiddenReturn(): boolean {
    return (this.sym as any).isHiddenReturn();
  }

  isNameUndefined(): boolean {
    return (this.sym as any).isNameUndefined();
  }

  setTypeLock(val: boolean): void {
    const scope: any = (this.sym as any).getScope();
    let attrs = 0x100; // Varnode::typelock
    if (!(this.sym as any).isNameUndefined())
      attrs |= 0x200; // Varnode::namelock
    if (val)
      scope.setAttribute(this.sym, attrs);
    else
      scope.clearAttribute(this.sym, attrs);
  }

  setNameLock(val: boolean): void {
    const scope: any = (this.sym as any).getScope();
    if (val)
      scope.setAttribute(this.sym, 0x200); // Varnode::namelock
    else
      scope.clearAttribute(this.sym, 0x200);
  }

  setThisPointer(val: boolean): void {
    const scope: any = (this.sym as any).getScope();
    scope.setThisPointer(this.sym, val);
  }

  overrideSizeLockType(ct: Datatype): void {
    (this.sym as any).getScope().overrideSizeLockType(this.sym, ct);
  }

  resetSizeLockType(factory: any /* TypeFactory */): void {
    (this.sym as any).getScope().resetSizeLockType(this.sym);
  }

  clone(): ProtoParameter {
    throw new LowlevelError('Should not be cloning ParameterSymbol');
  }

  getSymbol(): Symbol {
    return this.sym!;
  }
}

// ---------------------------------------------------------------------------
// ProtoModel
// ---------------------------------------------------------------------------

/**
 * A prototype model: a model for passing parameters between functions.
 *
 * This encompasses both input parameters and return values. It attempts to
 * describe the ABI, Application Binary Interface, of the processor or compiler.
 * Any number of function prototypes (FuncProto) can be implemented under a
 * prototype model, which represents a static rule set the compiler uses
 * to decide:
 *   - Storage locations for input parameters
 *   - Storage locations for return values
 *   - Expected side-effects of a function on other (non-parameter) registers and storage locations
 *   - Behavior of the stack and the stack pointer across function calls
 */
export class ProtoModel {
  static readonly extrapop_unknown = 0x8000;

  protected glb: Architecture;
  protected name_: string = '';
  protected extrapop: number = 0;
  protected input: ParamList | null = null;
  protected output: ParamList | null = null;
  protected compatModel: ProtoModel | null = null;
  protected effectlist: EffectRecord[] = [];
  protected likelytrash: VarnodeData[] = [];
  protected internalstorage: VarnodeData[] = [];
  protected injectUponEntry: number = -1;
  protected injectUponReturn: number = -1;
  protected localrange: RangeList = new RangeList();
  protected paramrange: RangeList = new RangeList();
  protected stackgrowsnegative: boolean = true;
  protected hasThis: boolean = false;
  protected isConstruct: boolean = false;
  protected isPrinted_: boolean = true;

  /**
   * Set the default stack range used for local variables.
   */
  private defaultLocalRange(): void {
    const spc: AddrSpace | null = (this.glb as any).getStackSpace();
    if (spc === null) return;
    let first: bigint;
    let last: bigint;

    if (this.stackgrowsnegative) {
      last = spc.getHighest();
      if (spc.getAddrSize() >= 4)
        first = last - 999999n;
      else if (spc.getAddrSize() >= 2)
        first = last - 9999n;
      else
        first = last - 99n;
      this.localrange.insertRange(spc, first, last);
    } else {
      first = 0n;
      if (spc.getAddrSize() >= 4)
        last = 999999n;
      else if (spc.getAddrSize() >= 2)
        last = 9999n;
      else
        last = 99n;
      this.localrange.insertRange(spc, first, last);
    }
  }

  /**
   * Set the default stack range used for input parameters.
   */
  private defaultParamRange(): void {
    const spc: AddrSpace | null = (this.glb as any).getStackSpace();
    if (spc === null) return;
    let first: bigint;
    let last: bigint;

    if (this.stackgrowsnegative) {
      first = 0n;
      if (spc.getAddrSize() >= 4)
        last = 511n;
      else if (spc.getAddrSize() >= 2)
        last = 255n;
      else
        last = 15n;
      this.paramrange.insertRange(spc, first, last);
    } else {
      last = spc.getHighest();
      if (spc.getAddrSize() >= 4)
        first = last - 511n;
      else if (spc.getAddrSize() >= 2)
        first = last - 255n;
      else
        first = last - 15n;
      this.paramrange.insertRange(spc, first, last);
    }
  }

  /**
   * Establish the main resource lists for input and output parameters.
   */
  private buildParamList(strategy: string): void {
    if (strategy === '' || strategy === 'standard') {
      this.input = new ParamListStandard();
      this.output = new ParamListStandardOut();
    } else if (strategy === 'register') {
      this.input = new ParamListRegister();
      this.output = new ParamListRegisterOut();
    } else {
      throw new LowlevelError('Unknown strategy type: ' + strategy);
    }
  }

  /**
   * Constructor for use with decode().
   */
  constructor(g: Architecture);
  /**
   * Copy constructor changing the name.
   */
  constructor(nm: string, op2: ProtoModel);
  constructor(gOrNm: Architecture | string, op2?: ProtoModel) {
    if (typeof gOrNm === 'string') {
      // Copy constructor: ProtoModel(nm, op2)
      const nm = gOrNm;
      const src = op2!;
      this.glb = src.glb;
      this.name_ = nm;
      this.isPrinted_ = true; // Don't inherit. Always print unless setPrintInDecl called explicitly
      this.extrapop = src.extrapop;
      if (src.input !== null)
        this.input = src.input.clone();
      else
        this.input = null;
      if (src.output !== null)
        this.output = src.output.clone();
      else
        this.output = null;

      this.effectlist = src.effectlist.map(e => EffectRecord.createCopy(e));
      this.likelytrash = src.likelytrash.map(v => {
        const vd = new VarnodeData();
        vd.space = v.space;
        vd.offset = v.offset;
        vd.size = v.size;
        return vd;
      });
      this.internalstorage = src.internalstorage.map(v => {
        const vd = new VarnodeData();
        vd.space = v.space;
        vd.offset = v.offset;
        vd.size = v.size;
        return vd;
      });

      this.injectUponEntry = src.injectUponEntry;
      this.injectUponReturn = src.injectUponReturn;
      this.localrange = src.localrange;
      this.paramrange = src.paramrange;
      this.stackgrowsnegative = src.stackgrowsnegative;
      this.hasThis = src.hasThis;
      this.isConstruct = src.isConstruct;
      if (nm === '__thiscall')
        this.hasThis = true;
      this.compatModel = src;
    } else {
      // Standard constructor: ProtoModel(g)
      this.glb = gOrNm;
      this.input = null;
      this.output = null;
      this.compatModel = null;
      this.extrapop = 0;
      this.injectUponEntry = -1;
      this.injectUponReturn = -1;
      this.stackgrowsnegative = true;
      this.hasThis = false;
      this.isConstruct = false;
      this.isPrinted_ = true;
      this.defaultLocalRange();
      this.defaultParamRange();
    }
  }

  getName(): string { return this.name_; }
  getArch(): Architecture { return this.glb; }
  getAliasParent(): ProtoModel | null { return this.compatModel; }
  getInput(): ParamList | null { return this.input; }
  getOutput(): ParamList | null { return this.output; }

  /**
   * Determine side-effect of this on the given memory range.
   */
  hasEffect(addr: Address, size: number): number {
    return ProtoModel.lookupEffect(this.effectlist, addr, size);
  }

  getExtraPop(): number { return this.extrapop; }
  setExtraPop(ep: number): void { this.extrapop = ep; }
  getInjectUponEntry(): number { return this.injectUponEntry; }
  getInjectUponReturn(): number { return this.injectUponReturn; }

  /**
   * Test whether one ProtoModel can be substituted for another during
   * FuncCallSpecs::deindirect. Currently this can only happen if one model
   * is a copy of the other except for the hasThis boolean property.
   */
  isCompatible(op2: ProtoModel): boolean {
    if (this === op2 || this.compatModel === op2 || op2.compatModel === this)
      return true;
    return false;
  }

  /**
   * Given a list of input trials, derive the most likely input prototype.
   * Trials are sorted and marked as used or not.
   */
  deriveInputMap(active: ParamActive): void {
    this.input!.fillinMap(active);
  }

  /**
   * Given a list of output trials, derive the most likely output prototype.
   * One trial (at most) is marked used and moved to the front of the list.
   */
  deriveOutputMap(active: ParamActive): void {
    this.output!.fillinMap(active);
  }

  /**
   * Calculate input and output storage locations given a function prototype.
   *
   * The data-types of the function prototype are passed in. Based on this model, a
   * location is selected for each (input and output) parameter and passed back to the
   * caller. The passed back storage locations are ordered with the output storage
   * as the first entry, followed by the input storage locations.
   *
   * If the model can't map the specific output prototype, the caller has the option of
   * whether an exception (ParamUnassignedError) is thrown.
   */
  assignParameterStorage(proto: PrototypePieces, res: ParameterPieces[], ignoreOutputError: boolean): void {
    if (ignoreOutputError) {
      try {
        this.output!.assignMap(proto, (this.glb as any).types, res);
      } catch (err) {
        if (err instanceof ParamUnassignedError) {
          res.length = 0;
          const piece = new ParameterPieces();
          res.push(piece);
          // leave address undefined
          piece.flags = 0;
          piece.type = (this.glb as any).types.getTypeVoid();
        } else {
          throw err;
        }
      }
    } else {
      this.output!.assignMap(proto, (this.glb as any).types, res);
    }
    this.input!.assignMap(proto, (this.glb as any).types, res);

    if (this.hasThis && res.length > 1) {
      let thisIndex = 1;
      if ((res[1].flags & ParameterPieces.hiddenretparm) !== 0 && res.length > 2) {
        if (this.input!.isThisBeforeRetPointer()) {
          // pointer has been bumped by auto-return-storage
          res[1].swapMarkup(res[2]); // must swap markup for slots 1 and 2
        } else {
          thisIndex = 2;
        }
      }
      res[thisIndex].flags |= ParameterPieces.isthis;
    }
  }

  /**
   * Check if the given two input storage locations can represent a single logical parameter.
   */
  checkInputJoin(hiaddr: Address, hisize: number, loaddr: Address, losize: number): boolean {
    return this.input!.checkJoin(hiaddr, hisize, loaddr, losize);
  }

  /**
   * Check if the given two output storage locations can represent a single logical return value.
   */
  checkOutputJoin(hiaddr: Address, hisize: number, loaddr: Address, losize: number): boolean {
    return this.output!.checkJoin(hiaddr, hisize, loaddr, losize);
  }

  /**
   * Check if it makes sense to split a single storage location into two input parameters.
   */
  checkInputSplit(loc: Address, size: number, splitpoint: number): boolean {
    return this.input!.checkSplit(loc, size, splitpoint);
  }

  getLocalRange(): RangeList { return this.localrange; }
  getParamRange(): RangeList { return this.paramrange; }

  getEffectList(): EffectRecord[] { return this.effectlist; }
  getLikelyTrash(): VarnodeData[] { return this.likelytrash; }
  getInternalStorage(): VarnodeData[] { return this.internalstorage; }

  /**
   * Characterize whether the given range overlaps parameter storage.
   */
  characterizeAsInputParam(loc: Address, size: number): number {
    return this.input!.characterizeAsParam(loc, size);
  }

  /**
   * Characterize whether the given range overlaps output storage.
   */
  characterizeAsOutput(loc: Address, size: number): number {
    return this.output!.characterizeAsParam(loc, size);
  }

  /** Does the given storage location make sense as an input parameter? */
  possibleInputParam(loc: Address, size: number): boolean {
    return this.input!.possibleParam(loc, size);
  }

  /** Does the given storage location make sense as a return value? */
  possibleOutputParam(loc: Address, size: number): boolean {
    return this.output!.possibleParam(loc, size);
  }

  /** Pass-back the slot and slot size for the given storage location as an input parameter. */
  possibleInputParamWithSlot(loc: Address, size: number, slot: { val: number }, slotsize: { val: number }): boolean {
    return this.input!.possibleParamWithSlot(loc, size, slot, slotsize);
  }

  /** Pass-back the slot and slot size for the given storage location as a return value. */
  possibleOutputParamWithSlot(loc: Address, size: number, slot: { val: number }, slotsize: { val: number }): boolean {
    return this.output!.possibleParamWithSlot(loc, size, slot, slotsize);
  }

  /** Check if the given storage location looks like an unjustified input parameter. */
  unjustifiedInputParam(loc: Address, size: number, res: VarnodeData): boolean {
    return this.input!.unjustifiedContainer(loc, size, res);
  }

  /** Get the type of extension and containing input parameter for the given storage. */
  assumedInputExtension(addr: Address, size: number, res: VarnodeData): OpCode {
    return this.input!.assumedExtension(addr, size, res);
  }

  /** Get the type of extension and containing return value location for the given storage. */
  assumedOutputExtension(addr: Address, size: number, res: VarnodeData): OpCode {
    return this.output!.assumedExtension(addr, size, res);
  }

  /** Pass-back the biggest input parameter contained within the given range. */
  getBiggestContainedInputParam(loc: Address, size: number, res: VarnodeData): boolean {
    return this.input!.getBiggestContainedParam(loc, size, res);
  }

  /** Pass-back the biggest possible output parameter contained within the given range. */
  getBiggestContainedOutput(loc: Address, size: number, res: VarnodeData): boolean {
    return this.output!.getBiggestContainedParam(loc, size, res);
  }

  /** Get the stack space associated with this model. */
  getSpacebase(): AddrSpace | null { return this.input!.getSpacebase(); }

  /** Return true if the stack grows toward smaller addresses. */
  isStackGrowsNegative(): boolean { return this.stackgrowsnegative; }

  /** Is this a model for (non-static) class methods? */
  hasThisPointer(): boolean { return this.hasThis; }

  /** Is this model for class constructors? */
  isConstructor(): boolean { return this.isConstruct; }

  /** Return true if name should be printed in function declarations. */
  printInDecl(): boolean { return this.isPrinted_; }

  /** Set whether this name should be printed in function declarations. */
  setPrintInDecl(val: boolean): void { this.isPrinted_ = val; }

  /** Return the maximum heritage delay across all possible input parameters. */
  getMaxInputDelay(): number { return this.input!.getMaxDelay(); }

  /** Return the maximum heritage delay across all possible return values. */
  getMaxOutputDelay(): number { return this.output!.getMaxDelay(); }

  /** Does this model automatically consider potential output locations as killed by call? */
  isAutoKilledByCall(): boolean { return this.output!.isAutoKilledByCall(); }

  /** Is this a merged prototype model? */
  isMerged(): boolean { return false; }

  /** Is this an unrecognized prototype model? */
  isUnknown(): boolean { return false; }

  /**
   * Parse details about this model from a <prototype> element.
   */
  decode(decoder: Decoder): void {
    let sawlocalrange = false;
    let sawparamrange = false;
    let sawretaddr = false;
    this.stackgrowsnegative = true;
    const stackspc: AddrSpace | null = (this.glb as any).getStackSpace();
    if (stackspc !== null)
      this.stackgrowsnegative = stackspc.stackGrowsNegative();
    let strategystring = '';
    this.localrange.clear();
    this.paramrange.clear();
    this.extrapop = -300;
    this.hasThis = false;
    this.isConstruct = false;
    this.isPrinted_ = true;
    this.effectlist = [];
    this.injectUponEntry = -1;
    this.injectUponReturn = -1;
    this.likelytrash = [];
    this.internalstorage = [];

    const elemId = decoder.openElementId(ELEM_PROTOTYPE);
    for (;;) {
      const attribId = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_NAME.getId()) {
        this.name_ = decoder.readString();
      } else if (attribId === ATTRIB_EXTRAPOP.getId()) {
        this.extrapop = decoder.readSignedIntegerExpectString('unknown', ProtoModel.extrapop_unknown);
      } else if (attribId === ATTRIB_STACKSHIFT.getId()) {
        // Allow this attribute for backward compatibility
        decoder.readSignedInteger(); // consume value
      } else if (attribId === ATTRIB_STRATEGY.getId()) {
        strategystring = decoder.readString();
      } else if (attribId === ATTRIB_HASTHIS.getId()) {
        this.hasThis = decoder.readBool();
      } else if (attribId === ATTRIB_CONSTRUCTOR.getId()) {
        this.isConstruct = decoder.readBool();
      } else {
        throw new LowlevelError('Unknown prototype attribute');
      }
    }
    if (this.name_ === '__thiscall')
      this.hasThis = true;
    if (this.extrapop === -300)
      throw new LowlevelError('Missing prototype attributes');

    this.buildParamList(strategystring);
    for (;;) {
      const subId = decoder.peekElement();
      if (subId === 0) break;
      if (subId === ELEM_INPUT.getId()) {
        this.input!.decodeList(decoder, this.effectlist, this.stackgrowsnegative);
        if (stackspc !== null) {
          this.input!.getRangeList(stackspc, this.paramrange);
          if (!this.paramrange.empty())
            sawparamrange = true;
        }
      } else if (subId === ELEM_OUTPUT.getId()) {
        this.output!.decodeList(decoder, this.effectlist, this.stackgrowsnegative);
      } else if (subId === ELEM_UNAFFECTED.getId()) {
        decoder.openElement();
        while (decoder.peekElement() !== 0) {
          const rec = new EffectRecord();
          rec.decodeRecord(EffectRecord.unaffected, decoder);
          this.effectlist.push(rec);
        }
        decoder.closeElement(subId);
      } else if (subId === ELEM_KILLEDBYCALL.getId()) {
        decoder.openElement();
        while (decoder.peekElement() !== 0) {
          const rec = new EffectRecord();
          rec.decodeRecord(EffectRecord.killedbycall, decoder);
          this.effectlist.push(rec);
        }
        decoder.closeElement(subId);
      } else if (subId === ELEM_RETURNADDRESS.getId()) {
        decoder.openElement();
        while (decoder.peekElement() !== 0) {
          const rec = new EffectRecord();
          rec.decodeRecord(EffectRecord.return_address, decoder);
          this.effectlist.push(rec);
        }
        decoder.closeElement(subId);
        sawretaddr = true;
      } else if (subId === ELEM_LOCALRANGE.getId()) {
        sawlocalrange = true;
        decoder.openElement();
        while (decoder.peekElement() !== 0) {
          const range = new Range(); range.decode(decoder);
          this.localrange.insertRange(range.getSpace(), range.getFirst(), range.getLast());
        }
        decoder.closeElement(subId);
      } else if (subId === ELEM_PARAMRANGE.getId()) {
        sawparamrange = true;
        decoder.openElement();
        while (decoder.peekElement() !== 0) {
          const range = new Range(); range.decode(decoder);
          this.paramrange.insertRange(range.getSpace(), range.getFirst(), range.getLast());
        }
        decoder.closeElement(subId);
      } else if (subId === ELEM_LIKELYTRASH.getId()) {
        decoder.openElement();
        while (decoder.peekElement() !== 0) {
          const vd = new VarnodeData();
          vd.decode(decoder);
          this.likelytrash.push(vd);
        }
        decoder.closeElement(subId);
      } else if (subId === ELEM_INTERNAL_STORAGE.getId()) {
        decoder.openElement();
        while (decoder.peekElement() !== 0) {
          const vd = new VarnodeData();
          vd.decode(decoder);
          this.internalstorage.push(vd);
        }
        decoder.closeElement(subId);
      } else if (subId === ELEM_PCODE.getId()) {
        const injectId: number = (this.glb as any).pcodeinjectlib.decodeInject(
          'Protomodel : ' + this.name_, this.name_,
          0 /* InjectPayload::CALLMECHANISM_TYPE */, decoder);
        const payload: any = (this.glb as any).pcodeinjectlib.getPayload(injectId);
        if (payload.getName().indexOf('uponentry') >= 0)
          this.injectUponEntry = injectId;
        else
          this.injectUponReturn = injectId;
      } else {
        throw new LowlevelError('Unknown element in prototype');
      }
    }
    decoder.closeElement(elemId);
    if (!sawretaddr && (this.glb as any).defaultReturnAddr !== undefined &&
        (this.glb as any).defaultReturnAddr.space !== null) {
      this.effectlist.push(
        new EffectRecord((this.glb as any).defaultReturnAddr as VarnodeData, EffectRecord.return_address));
    }
    this.effectlist.sort(EffectRecord.compareByAddress);
    this.likelytrash.sort((a, b) => compareVarnodeData(a, b));
    this.internalstorage.sort((a, b) => compareVarnodeData(a, b));
    if (!sawlocalrange)
      this.defaultLocalRange();
    if (!sawparamrange)
      this.defaultParamRange();
  }

  /**
   * Look up an effect from the given EffectRecord list.
   *
   * If a given memory range matches an EffectRecord, return the effect type.
   * Otherwise return EffectRecord.unknown_effect.
   */
  static lookupEffect(efflist: EffectRecord[], addr: Address, size: number): number {
    // Unique is always local to function
    if (addr.getSpace()!.getType() === spacetype.IPTR_INTERNAL)
      return EffectRecord.unaffected;

    const cur = new EffectRecord(addr, size);

    // upper_bound equivalent: find first element greater than cur
    let lo = 0;
    let hi = efflist.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (EffectRecord.compareByAddress(efflist[mid], cur) <= 0)
        lo = mid + 1;
      else
        hi = mid;
    }
    // lo is now pointing to first element greater than cur
    if (lo === 0) return EffectRecord.unknown_effect;
    lo -= 1;
    const hit = efflist[lo].getAddress();
    const sz = efflist[lo].getSize();
    if (sz === 0 && (hit.getSpace() === addr.getSpace()))
      return EffectRecord.unaffected;
    const where = addr.overlap(0, hit, sz);
    if (where >= 0 && (where + size) <= sz)
      return efflist[lo].getType();
    return EffectRecord.unknown_effect;
  }

  /**
   * Look up a particular EffectRecord from a given list by its Address and size.
   *
   * The index of the matching EffectRecord from the given list is returned. Only the first
   * listSize elements are examined, which must be sorted by Address.
   * If no matching range exists, a negative number is returned.
   *   -1 if the Address and size don't overlap any other EffectRecord
   *   -2 if there is overlap with another EffectRecord
   */
  static lookupRecord(efflist: EffectRecord[], listSize: number, addr: Address, size: number): number {
    if (listSize === 0) return -1;

    const cur = new EffectRecord(addr, size);

    // upper_bound on efflist[0..listSize)
    let lo = 0;
    let hi = listSize;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (EffectRecord.compareByAddress(efflist[mid], cur) <= 0)
        lo = mid + 1;
      else
        hi = mid;
    }
    // lo is now the upper_bound index
    if (lo === 0) {
      const closeAddr = efflist[0].getAddress();
      return (closeAddr.overlap(0, addr, size) < 0) ? -1 : -2;
    }
    lo -= 1;
    const closeAddr = efflist[lo].getAddress();
    const sz = efflist[lo].getSize();
    if (addr.equals(closeAddr) && size === sz)
      return lo;
    return (addr.overlap(0, closeAddr, sz) < 0) ? -1 : -2;
  }
}

// ---------------------------------------------------------------------------
// UnknownProtoModel
// ---------------------------------------------------------------------------

/**
 * An unrecognized prototype model.
 *
 * This kind of model is created for function prototypes that specify a model name
 * for which there is no matching object. A model is created for the name by cloning
 * behavior from a placeholder model, usually the default model.
 */
export class UnknownProtoModel extends ProtoModel {
  private placeholderModel: ProtoModel;

  constructor(nm: string, placeHold: ProtoModel) {
    super(nm, placeHold);
    this.placeholderModel = placeHold;
  }

  /** Retrieve the placeholder model. */
  getPlaceholderModel(): ProtoModel { return this.placeholderModel; }

  isUnknown(): boolean { return true; }
}

// ---------------------------------------------------------------------------
// ScoreProtoModel
// ---------------------------------------------------------------------------

/**
 * A record mapping trials to parameter entries in the prototype model.
 */
class PEntry {
  origIndex: number = 0;
  slot: number = 0;
  size: number = 0;
}

/**
 * Class for calculating "goodness of fit" of parameter trials against a prototype model.
 *
 * The class is instantiated with a prototype model (ProtoModel). A set of Varnode parameter trials
 * are registered by calling addParameter() for each trial. Then calling doScore() computes a score
 * that evaluates how well the set of registered trials fit the prototype model. A lower score
 * indicates a better fit.
 */
export class ScoreProtoModel {
  private isinputscore: boolean;
  private entry: PEntry[];
  private model: ProtoModel;
  private finalscore: number;
  private mismatch: number;

  constructor(isinput: boolean, mod: ProtoModel, numparam: number) {
    this.isinputscore = isinput;
    this.model = mod;
    this.entry = [];
    this.finalscore = -1;
    this.mismatch = 0;
  }

  /**
   * Register a trial to be scored.
   */
  addParameter(addr: Address, sz: number): void {
    const orig = this.entry.length;
    const slot: { val: number } = { val: 0 };
    const slotsize: { val: number } = { val: 0 };
    let isparam: boolean;
    if (this.isinputscore)
      isparam = this.model.possibleInputParamWithSlot(addr, sz, slot, slotsize);
    else
      isparam = this.model.possibleOutputParamWithSlot(addr, sz, slot, slotsize);
    if (isparam) {
      const pe = new PEntry();
      pe.origIndex = orig;
      pe.slot = slot.val;
      pe.size = slotsize.val;
      this.entry.push(pe);
    } else {
      this.mismatch += 1;
    }
  }

  /**
   * Compute the fitness score.
   */
  doScore(): void {
    // Sort entries by slot
    this.entry.sort((a, b) => a.slot - b.slot);

    let nextfree = 0;
    let basescore = 0;
    const penalty = [16, 10, 7, 5];
    const penaltyfinal = 3;
    const mismatchpenalty = 20;

    for (let i = 0; i < this.entry.length; ++i) {
      const p = this.entry[i];
      if (p.slot > nextfree) {
        // We have some kind of hole in our slot coverage
        while (nextfree < p.slot) {
          if (nextfree < 4)
            basescore += penalty[nextfree];
          else
            basescore += penaltyfinal;
          nextfree += 1;
        }
        nextfree += p.size;
      } else if (nextfree > p.slot) {
        // Some kind of slot duplication
        basescore += mismatchpenalty;
        if (p.slot + p.size > nextfree)
          nextfree = p.slot + p.size;
      } else {
        nextfree = p.slot + p.size;
      }
    }
    this.finalscore = basescore + mismatchpenalty * this.mismatch;
  }

  /** Get the fitness score. */
  getScore(): number { return this.finalscore; }

  /** Get the number of mismatched trials. */
  getNumMismatch(): number { return this.mismatch; }
}

// ---------------------------------------------------------------------------
// ProtoModelMerged
// ---------------------------------------------------------------------------

/**
 * A prototype model made by merging together other models.
 *
 * This model serves as a placeholder for multiple models, when the exact model
 * has not been immediately determined. At the time of active parameter recovery
 * the correct model is selected for the given set of trials
 * from among the constituent prototype models used to build this,
 * by calling the method selectModel().
 *
 * Up to this time, this serves as a merged form of the models so that all potential
 * parameter trials will be included in the analysis. The parameter recovery
 * for the output part of the model is currently limited, so the constituent models
 * must all share the same output model, and this part is not currently merged.
 */
export class ProtoModelMerged extends ProtoModel {
  private modellist: ProtoModel[] = [];

  constructor(g: Architecture) {
    super(g);
  }

  /**
   * Get the number of constituent models.
   */
  numModels(): number { return this.modellist.length; }

  /**
   * Get the i-th model.
   */
  getModel(i: number): ProtoModel { return this.modellist[i]; }

  /**
   * The EffectRecord lists are intersected. Anything in this that is not also
   * in the given EffectRecord list is removed.
   */
  private intersectEffects(efflist: EffectRecord[]): void {
    const newlist: EffectRecord[] = [];

    let i = 0;
    let j = 0;
    while (i < this.effectlist.length && j < efflist.length) {
      const eff1 = this.effectlist[i];
      const eff2 = efflist[j];

      const cmp = EffectRecord.compareByAddress(eff1, eff2);
      if (cmp < 0) {
        i += 1;
      } else if (cmp > 0) {
        j += 1;
      } else {
        if (eff1.equals(eff2))
          newlist.push(eff1);
        i += 1;
        j += 1;
      }
    }
    this.effectlist = newlist;
  }

  /**
   * The intersection of two containers of register Varnodes is calculated, and the
   * result is placed in the first container, replacing the original contents.
   * The containers must already be sorted.
   */
  private static intersectRegisters(regList1: VarnodeData[], regList2: VarnodeData[]): VarnodeData[] {
    const newlist: VarnodeData[] = [];

    let i = 0;
    let j = 0;
    while (i < regList1.length && j < regList2.length) {
      const trs1 = regList1[i];
      const trs2 = regList2[j];

      const cmp = VarnodeData.compare(trs1, trs2);
      if (cmp < 0)
        i += 1;
      else if (cmp > 0)
        j += 1;
      else {
        newlist.push(trs1);
        i += 1;
        j += 1;
      }
    }
    return newlist;
  }

  /**
   * Fold-in an additional prototype model.
   */
  foldIn(model: ProtoModel): void {
    if ((model as any).glb !== this.glb)
      throw new LowlevelError('Mismatched architecture');
    const inputType = model.getInput()!.getType();
    if (inputType !== ParamList.p_standard && inputType !== ParamList.p_register)
      throw new LowlevelError('Can only resolve between standard prototype models');

    if (this.input === null) {
      // First fold in
      this.input = new ParamListMerged();
      this.output = new ParamListStandardOut(model.getOutput()! as ParamListStandardOut);
      (this.input as ParamListMerged).foldIn(model.getInput()! as ParamListStandard);
      this.extrapop = model.getExtraPop();
      this.effectlist = model.getEffectList().map(e => EffectRecord.createCopy(e));
      this.injectUponEntry = model.getInjectUponEntry();
      this.injectUponReturn = model.getInjectUponReturn();
      this.likelytrash = [...model.getLikelyTrash()];
      this.localrange = model.getLocalRange();
      this.paramrange = model.getParamRange();
    } else {
      (this.input as ParamListMerged).foldIn(model.getInput()! as ParamListStandard);
      // We assume here that the output models are the same, but we don't check
      if (this.extrapop !== model.getExtraPop())
        this.extrapop = ProtoModel.extrapop_unknown;
      if (this.injectUponEntry !== model.getInjectUponEntry() ||
          this.injectUponReturn !== model.getInjectUponReturn())
        throw new LowlevelError('Cannot merge prototype models with different inject ids');
      this.intersectEffects(model.getEffectList());
      this.likelytrash = ProtoModelMerged.intersectRegisters(this.likelytrash, model.getLikelyTrash());
      this.internalstorage = ProtoModelMerged.intersectRegisters(this.internalstorage, model.getInternalStorage());
      // Take the union of the localrange and paramrange
      const modelLocalRange = model.getLocalRange();
      for (const r of modelLocalRange.getRanges()) {
        this.localrange.insertRange(r.getSpace(), r.getFirst(), r.getLast());
      }
      const modelParamRange = model.getParamRange();
      for (const r of modelParamRange.getRanges()) {
        this.paramrange.insertRange(r.getSpace(), r.getFirst(), r.getLast());
      }
    }
  }

  /**
   * Select the best model given a set of trials.
   *
   * The model that best matches the given set of input parameter trials is
   * returned. This method currently uses the ScoreProtoModel object to
   * score the different prototype models.
   */
  selectModel(active: ParamActive): ProtoModel {
    let bestscore = 500;
    let bestindex = -1;
    for (let i = 0; i < this.modellist.length; ++i) {
      const numtrials = active.getNumTrials();
      const scoremodel = new ScoreProtoModel(true, this.modellist[i], numtrials);
      for (let j = 0; j < numtrials; ++j) {
        const trial = active.getTrial(j);
        if (trial.isActive())
          scoremodel.addParameter(trial.getAddress(), trial.getSize());
      }
      scoremodel.doScore();
      const score = scoremodel.getScore();
      if (score < bestscore) {
        bestscore = score;
        bestindex = i;
        if (bestscore === 0)
          break; // Can't get any lower
      }
    }
    if (bestindex >= 0)
      return this.modellist[bestindex];
    throw new LowlevelError('No model matches : missing default');
  }

  isMerged(): boolean { return true; }

  /**
   * Restore this model from a <resolveprototype> element.
   */
  decode(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_RESOLVEPROTOTYPE);
    this.name_ = decoder.readStringById(ATTRIB_NAME);
    for (;;) {
      const subId = decoder.openElement();
      if (subId !== ELEM_MODEL.getId()) break;
      const modelName = decoder.readStringById(ATTRIB_NAME);
      const mymodel: ProtoModel | null = (this.glb as any).getModel(modelName);
      if (mymodel === null)
        throw new LowlevelError('Missing prototype model: ' + modelName);
      decoder.closeElement(subId);
      this.foldIn(mymodel);
      this.modellist.push(mymodel);
    }
    decoder.closeElement(elemId);
    (this.input as ParamListMerged).finalize();
  }
}

// ---------------------------------------------------------------------------
// ProtoStore  (abstract base class)
// ---------------------------------------------------------------------------

/**
 * A collection of parameter descriptions making up a function prototype.
 *
 * A unified interface for accessing descriptions of individual
 * parameters in a function prototype. Both input parameters and return values
 * are described.
 */
export abstract class ProtoStore {
  /**
   * Establish name, data-type, storage of a specific input parameter.
   */
  abstract setInput(i: number, nm: string, pieces: ParameterPieces): ProtoParameter;

  /**
   * Clear the input parameter at the specified slot.
   */
  abstract clearInput(i: number): void;

  abstract clearAllInputs(): void;
  abstract getNumInputs(): number;
  abstract getInput(i: number): ProtoParameter | null;

  /**
   * Establish the data-type and storage of the return value.
   */
  abstract setOutput(piece: ParameterPieces): ProtoParameter;

  abstract clearOutput(): void;
  abstract getOutput(): ProtoParameter | null;
  abstract clone(): ProtoStore;

  /**
   * Encode any parameters that are not backed by symbols to a stream.
   */
  abstract encode(encoder: Encoder): void;

  /**
   * Restore any internal parameter descriptions from a stream.
   */
  abstract decodeStore(decoder: Decoder, model: ProtoModel): void;
}
// ---------------------------------------------------------------------------
// Part 3: ProtoStoreSymbol, ProtoStoreInternal, FuncProto, FuncCallSpecs.
// ---------------------------------------------------------------------------

// Forward type declarations unique to Part 3
type AliasChecker = any;
type AncestorRealistic = any;
type InjectPayload = any;

// AncestorRealistic constructor reference for use in finalInputCheck.
// Set by funcdata.ts to break circular dependency.
let _AncestorRealisticCtor: (new () => { execute(op: any, slot: number, t: ParamTrial, allowFail: boolean): boolean }) | null = null;
export function registerAncestorRealisticCtor(ctor: any): void {
  _AncestorRealisticCtor = ctor;
}

// ---------------------------------------------------------------------------
// ProtoStoreSymbol
// ---------------------------------------------------------------------------

/**
 * A collection of parameter descriptions backed by Symbol information.
 * Input parameters are determined by symbols in a function Scope (category 0).
 */
export class ProtoStoreSymbol extends ProtoStore {
  private scope: Scope;
  private restricted_usepoint: any; // Address
  private inparam: (ProtoParameter | null)[] = [];
  private outparam: ProtoParameter | null = null;

  constructor(sc: Scope, usepoint: any) {
    super();
    this.scope = sc;
    this.restricted_usepoint = usepoint;
    const pieces = new ParameterPieces();
    pieces.type = (sc as any).getArch().types.getTypeVoid();
    pieces.flags = 0;
    this.outparam = new ParameterBasic('', pieces.addr, pieces.type!, pieces.flags);
  }

  /**
   * Fetch or allocate the ParameterSymbol for the indicated slot.
   */
  private getSymbolBacked(i: number): ParameterSymbol {
    while (this.inparam.length <= i)
      this.inparam.push(null);
    let res = this.inparam[i] instanceof ParameterSymbol ? this.inparam[i] as ParameterSymbol : null;
    if (res !== null) return res;
    // Discard old non-ParameterSymbol if present
    res = new ParameterSymbol();
    this.inparam[i] = res;
    return res;
  }

  setInput(i: number, nm: string, pieces: ParameterPieces): ProtoParameter {
    const res = this.getSymbolBacked(i);
    const scope = this.scope as any;
    res.sym = scope.getCategorySymbol(0 /* Symbol::function_parameter */, i);

    const isindirect = (pieces.flags & ParameterPieces.indirectstorage) !== 0;
    const ishidden = (pieces.flags & ParameterPieces.hiddenretparm) !== 0;
    const istypelock = (pieces.flags & ParameterPieces.typelock) !== 0;
    const isnamelock = (pieces.flags & ParameterPieces.namelock) !== 0;

    if (res.sym !== null) {
      const entry = (res.sym as any).getFirstWholeMap();
      if (!entry.getAddr().equals(pieces.addr) || entry.getSize() !== (pieces.type as any).getSize()) {
        scope.removeSymbol(res.sym);
        res.sym = null;
      }
    }

    if (res.sym === null) {
      let usepoint: any = Address.invalid();
      if (scope.discoverScope(pieces.addr, (pieces.type as any).getSize(), usepoint) === null)
        usepoint = this.restricted_usepoint;
      res.sym = scope.addSymbol(nm, pieces.type, pieces.addr, usepoint).getSymbol();
      scope.setCategory(res.sym, 0 /* Symbol::function_parameter */, i);
      if (isindirect || ishidden || istypelock || isnamelock) {
        let mirror = 0;
        if (isindirect) mirror |= 0x8000000; // Varnode::indirectstorage
        if (ishidden) mirror |= 0x10000000; // Varnode::hiddenretparm
        if (istypelock) mirror |= 0x100; // Varnode::typelock
        if (isnamelock) mirror |= 0x200; // Varnode::namelock
        scope.setAttribute(res.sym, mirror);
      }
      return res;
    }

    // Symbol already existed, update attributes
    if ((res.sym as any).isIndirectStorage() !== isindirect) {
      if (isindirect)
        scope.setAttribute(res.sym, 0x8000000);
      else
        scope.clearAttribute(res.sym, 0x8000000);
    }
    if ((res.sym as any).isHiddenReturn() !== ishidden) {
      if (ishidden)
        scope.setAttribute(res.sym, 0x10000000);
      else
        scope.clearAttribute(res.sym, 0x10000000);
    }
    if ((res.sym as any).isTypeLocked() !== istypelock) {
      if (istypelock)
        scope.setAttribute(res.sym, 0x100);
      else
        scope.clearAttribute(res.sym, 0x100);
    }
    if ((res.sym as any).isNameLocked() !== isnamelock) {
      if (isnamelock)
        scope.setAttribute(res.sym, 0x200);
      else
        scope.clearAttribute(res.sym, 0x200);
    }
    if (nm.length !== 0 && nm !== (res.sym as any).getName())
      scope.renameSymbol(res.sym, nm);
    if (pieces.type !== (res.sym as any).getType())
      scope.retypeSymbol(res.sym, pieces.type);
    return res;
  }

  clearInput(i: number): void {
    const scope = this.scope as any;
    let sym = scope.getCategorySymbol(0, i);
    if (sym !== null) {
      scope.setCategory(sym, -1 /* Symbol::no_category */, 0);
      scope.removeSymbol(sym);
    }
    const sz = scope.getCategorySize(0);
    for (let j = i + 1; j < sz; ++j) {
      sym = scope.getCategorySymbol(0, j);
      if (sym !== null)
        scope.setCategory(sym, 0, j - 1);
    }
  }

  clearAllInputs(): void {
    (this.scope as any).clearCategory(0);
  }

  getNumInputs(): number {
    return (this.scope as any).getCategorySize(0);
  }

  getInput(i: number): ProtoParameter | null {
    const sym = (this.scope as any).getCategorySymbol(0, i);
    if (sym === null) return null;
    const res = this.getSymbolBacked(i);
    res.sym = sym;
    return res;
  }

  setOutput(piece: ParameterPieces): ProtoParameter {
    this.outparam = new ParameterBasic('', piece.addr, piece.type!, piece.flags);
    return this.outparam;
  }

  clearOutput(): void {
    const pieces = new ParameterPieces();
    pieces.type = (this.scope as any).getArch().types.getTypeVoid();
    pieces.flags = 0;
    this.setOutput(pieces);
  }

  getOutput(): ProtoParameter {
    return this.outparam!;
  }

  clone(): ProtoStore {
    const res = new ProtoStoreSymbol(this.scope, this.restricted_usepoint);
    if (this.outparam !== null)
      res.outparam = this.outparam.clone();
    else
      res.outparam = null;
    return res;
  }

  encode(encoder: any): void {
    // Do not store anything explicitly for a symboltable backed store
  }

  decodeStore(decoder: Decoder, model: ProtoModel): void {
    throw new LowlevelError('Do not decode symbol-backed prototype through this interface');
  }
}

// ---------------------------------------------------------------------------
// ProtoStoreInternal
// ---------------------------------------------------------------------------

/**
 * A collection of parameter descriptions without backing symbols.
 * Parameter descriptions are stored internally.
 */
export class ProtoStoreInternal extends ProtoStore {
  private voidtype: Datatype;
  private inparam: (ProtoParameter | null)[] = [];
  private outparam: ProtoParameter | null = null;

  constructor(vt: Datatype) {
    super();
    this.voidtype = vt;
    const pieces = new ParameterPieces();
    pieces.type = this.voidtype;
    pieces.flags = 0;
    this.outparam = new ParameterBasic('', pieces.addr, pieces.type!, pieces.flags);
  }

  setInput(i: number, nm: string, pieces: ParameterPieces): ProtoParameter {
    while (this.inparam.length <= i)
      this.inparam.push(null);
    this.inparam[i] = new ParameterBasic(nm, pieces.addr, pieces.type!, pieces.flags);
    return this.inparam[i]!;
  }

  clearInput(i: number): void {
    const sz = this.inparam.length;
    if (i >= sz) return;
    this.inparam[i] = null;
    for (let j = i + 1; j < sz; ++j) {
      this.inparam[j - 1] = this.inparam[j];
      this.inparam[j] = null;
    }
    while (this.inparam.length > 0 && this.inparam[this.inparam.length - 1] === null)
      this.inparam.pop();
  }

  clearAllInputs(): void {
    this.inparam = [];
  }

  getNumInputs(): number {
    return this.inparam.length;
  }

  getInput(i: number): ProtoParameter | null {
    if (i >= this.inparam.length)
      return null;
    return this.inparam[i];
  }

  setOutput(piece: ParameterPieces): ProtoParameter {
    this.outparam = new ParameterBasic('', piece.addr, piece.type!, piece.flags);
    return this.outparam;
  }

  clearOutput(): void {
    this.outparam = new ParameterBasic(this.voidtype);
  }

  getOutput(): ProtoParameter {
    return this.outparam!;
  }

  clone(): ProtoStore {
    const res = new ProtoStoreInternal(this.voidtype);
    if (this.outparam !== null)
      res.outparam = this.outparam.clone();
    else
      res.outparam = null;
    for (let i = 0; i < this.inparam.length; ++i) {
      const param = this.inparam[i];
      res.inparam.push(param !== null ? param.clone() : null);
    }
    return res;
  }

  encode(encoder: any): void {
    encoder.openElement(ELEM_INTERNALLIST);
    if (this.outparam !== null) {
      encoder.openElement(ELEM_RETPARAM);
      if (this.outparam.isTypeLocked())
        encoder.writeBool(ATTRIB_TYPELOCK, true);
      this.outparam.getAddress().encode(encoder);
      (this.outparam.getType() as any).encodeRef(encoder);
      encoder.closeElement(ELEM_RETPARAM);
    } else {
      encoder.openElement(ELEM_RETPARAM);
      encoder.openElement(ELEM_ADDR);
      encoder.closeElement(ELEM_ADDR);
      encoder.openElement(ELEM_VOID);
      encoder.closeElement(ELEM_VOID);
      encoder.closeElement(ELEM_RETPARAM);
    }

    for (let i = 0; i < this.inparam.length; ++i) {
      const param = this.inparam[i]!;
      encoder.openElement(ELEM_PARAM);
      if (param.getName().length !== 0)
        encoder.writeString(ATTRIB_NAME, param.getName());
      if (param.isTypeLocked())
        encoder.writeBool(ATTRIB_TYPELOCK, true);
      if (param.isNameLocked())
        encoder.writeBool(ATTRIB_NAMELOCK, true);
      if (param.isThisPointer())
        encoder.writeBool(ATTRIB_THISPTR, true);
      if (param.isIndirectStorage())
        encoder.writeBool(ATTRIB_INDIRECTSTORAGE, true);
      if (param.isHiddenReturn())
        encoder.writeBool(ATTRIB_HIDDENRETPARM, true);
      param.getAddress().encode(encoder);
      (param.getType() as any).encodeRef(encoder);
      encoder.closeElement(ELEM_PARAM);
    }
    encoder.closeElement(ELEM_INTERNALLIST);
  }

  decodeStore(decoder: Decoder, model: ProtoModel): void {
    const glb = (model as any).getArch();
    const pieces: ParameterPieces[] = [];
    const proto = new PrototypePieces();
    proto.model = model;
    proto.firstVarArgSlot = -1;
    let addressesdetermined = true;

    // Push placeholder for output pieces
    const outPiece = new ParameterPieces();
    outPiece.type = this.outparam!.getType();
    outPiece.flags = 0;
    if (this.outparam!.isTypeLocked())
      outPiece.flags |= ParameterPieces.typelock;
    if (this.outparam!.isIndirectStorage())
      outPiece.flags |= ParameterPieces.indirectstorage;
    if (this.outparam!.getAddress().isInvalid())
      addressesdetermined = false;
    pieces.push(outPiece);

    const elemId = decoder.openElementId(ELEM_INTERNALLIST);
    const firstId = decoder.getNextAttributeId();
    if (firstId === ATTRIB_FIRST.getId()) {
      proto.firstVarArgSlot = decoder.readSignedInteger();
    }

    for (;;) {
      const subId = decoder.openElement();
      if (subId === 0) break;
      let name = '';
      let flags = 0;
      for (;;) {
        const attribId = decoder.getNextAttributeId();
        if (attribId === 0) break;
        if (attribId === ATTRIB_NAME.getId())
          name = decoder.readString();
        else if (attribId === ATTRIB_TYPELOCK.getId()) {
          if (decoder.readBool())
            flags |= ParameterPieces.typelock;
        }
        else if (attribId === ATTRIB_NAMELOCK.getId()) {
          if (decoder.readBool())
            flags |= ParameterPieces.namelock;
        }
        else if (attribId === ATTRIB_THISPTR.getId()) {
          if (decoder.readBool())
            flags |= ParameterPieces.isthis;
        }
        else if (attribId === ATTRIB_INDIRECTSTORAGE.getId()) {
          if (decoder.readBool())
            flags |= ParameterPieces.indirectstorage;
        }
        else if (attribId === ATTRIB_HIDDENRETPARM.getId()) {
          if (decoder.readBool())
            flags |= ParameterPieces.hiddenretparm;
        }
      }
      if ((flags & ParameterPieces.hiddenretparm) === 0)
        proto.innames.push(name);

      const curparam = new ParameterPieces();
      curparam.addr = Address.decode(decoder);
      curparam.type = glb.types.decodeType(decoder);
      curparam.flags = flags;
      if (curparam.addr.isInvalid())
        addressesdetermined = false;
      pieces.push(curparam);
      decoder.closeElement(subId);
    }
    decoder.closeElement(elemId);

    let curparam: ProtoParameter;
    if (!addressesdetermined) {
      proto.outtype = pieces[0].type;
      for (let i = 1; i < pieces.length; ++i)
        proto.intypes.push(pieces[i].type!);
      const addrPieces: ParameterPieces[] = [];
      (model as any).assignParameterStorage(proto, addrPieces, true);
      // Swap addrPieces and pieces
      const tmpPieces = pieces.splice(0);
      for (const p of addrPieces) pieces.push(p);
      let k = 0;
      for (let i = 0; i < pieces.length; ++i) {
        if ((pieces[i].flags & ParameterPieces.hiddenretparm) !== 0)
          continue; // Increment i but not k
        pieces[i].flags = tmpPieces[k].flags; // Use the original flags
        k = k + 1;
      }
      if (pieces[0].addr.isInvalid()) {
        pieces[0].flags &= ~ParameterPieces.typelock; // Treat as unlocked void
      }
      curparam = this.setOutput(pieces[0]);
      curparam.setTypeLock((pieces[0].flags & ParameterPieces.typelock) !== 0);
    }

    let j = 0;
    for (let i = 1; i < pieces.length; ++i) {
      if ((pieces[i].flags & ParameterPieces.hiddenretparm) !== 0) {
        curparam = this.setInput(i - 1, 'rethidden', pieces[i]);
        curparam.setTypeLock((pieces[0].flags & ParameterPieces.typelock) !== 0);
        continue; // increment i but not j
      }
      curparam = this.setInput(i - 1, proto.innames[j], pieces[i]);
      curparam.setTypeLock((pieces[i].flags & ParameterPieces.typelock) !== 0);
      curparam.setNameLock((pieces[i].flags & ParameterPieces.namelock) !== 0);
      j = j + 1;
    }
  }
}

// ---------------------------------------------------------------------------
// FuncProto
// ---------------------------------------------------------------------------

/**
 * A function prototype.
 * A description of the parameters and return value for a specific function.
 */
export class FuncProto {
  // Private enum flags
  private static readonly dotdotdot = 1;
  private static readonly voidinputlock = 2;
  private static readonly modellock = 4;
  private static readonly is_inline = 8;
  private static readonly no_return = 16;
  private static readonly paramshift_applied = 32;
  private static readonly error_inputparam = 64;
  private static readonly error_outputparam = 128;
  private static readonly custom_storage = 256;
  private static readonly is_constructor = 0x200;
  private static readonly is_destructor = 0x400;
  private static readonly has_thisptr = 0x800;
  private static readonly is_override = 0x1000;
  private static readonly auto_killedbycall = 0x2000;

  protected model: any | null = null;  // ProtoModel
  protected store: ProtoStore | null = null;
  protected extrapop: number = 0;
  protected flags: number = 0;
  protected effectlist: EffectRecord[] = [];
  protected likelytrash: VarnodeData[] = [];
  protected injectid: number = -1;
  protected returnBytesConsumed: number = 0;

  constructor() {
    this.model = null;
    this.store = null;
    this.flags = 0;
    this.injectid = -1;
    this.returnBytesConsumed = 0;
  }

  // --- Protected helpers ---

  protected updateThisPointer(): void {
    if (!(this.model as any).hasThisPointer()) return;
    const numInputs = this.store!.getNumInputs();
    if (numInputs === 0) return;
    let param = this.store!.getInput(0);
    if (param!.isHiddenReturn()) {
      if (numInputs < 2) return;
      param = this.store!.getInput(1);
    }
    param!.setThisPointer(true);
  }

  private encodeEffect(encoder: any): void {
    if (this.effectlist.length === 0) return;
    const unaffectedList: EffectRecord[] = [];
    const killedByCallList: EffectRecord[] = [];
    let retAddr: EffectRecord | null = null;
    for (const curRecord of this.effectlist) {
      const type = (this.model as any).hasEffect(curRecord.getAddress(), curRecord.getSize());
      if (type === curRecord.getType()) continue;
      if (curRecord.getType() === EffectRecord.unaffected)
        unaffectedList.push(curRecord);
      else if (curRecord.getType() === EffectRecord.killedbycall)
        killedByCallList.push(curRecord);
      else if (curRecord.getType() === EffectRecord.return_address)
        retAddr = curRecord;
    }
    if (unaffectedList.length > 0) {
      encoder.openElement(ELEM_UNAFFECTED);
      for (const rec of unaffectedList) rec.encode(encoder);
      encoder.closeElement(ELEM_UNAFFECTED);
    }
    if (killedByCallList.length > 0) {
      encoder.openElement(ELEM_KILLEDBYCALL);
      for (const rec of killedByCallList) rec.encode(encoder);
      encoder.closeElement(ELEM_KILLEDBYCALL);
    }
    if (retAddr !== null) {
      encoder.openElement(ELEM_RETURNADDRESS);
      retAddr.encode(encoder);
      encoder.closeElement(ELEM_RETURNADDRESS);
    }
  }

  private encodeLikelyTrash(encoder: any): void {
    if (this.likelytrash.length === 0) return;
    const modelTrash: VarnodeData[] = [];
    for (let iter = (this.model as any).trashBegin(); iter < (this.model as any).trashEnd(); ++iter) {
      // Collect model trash for binary_search simulation
    }
    encoder.openElement(ELEM_LIKELYTRASH);
    for (const cur of this.likelytrash) {
      // Check if it already exists in ProtoModel - skip if so
      let found = false;
      const mTrashBegin = (this.model as any).trashBeginArr?.() ?? [];
      for (const mt of mTrashBegin) {
        if (mt.space === cur.space && mt.offset === cur.offset && mt.size === cur.size) {
          found = true;
          break;
        }
      }
      if (found) continue;
      encoder.openElement(ELEM_ADDR);
      (cur.space as any).encodeAttributes(encoder, cur.offset, cur.size);
      encoder.closeElement(ELEM_ADDR);
    }
    encoder.closeElement(ELEM_LIKELYTRASH);
  }

  private decodeEffect(): void {
    if (this.effectlist.length === 0) return;
    const tmpList = this.effectlist.splice(0);
    for (let iter = (this.model as any).effectBegin(); iter !== (this.model as any).effectEnd();) {
      // Copy model effects - the model exposes effectBegin/effectEnd as iterators
      // In TypeScript, we'll use the array returned by getEffectList
      break;
    }
    // Copy all model effects
    const modelEffects: EffectRecord[] = (this.model as any).getEffectList?.() ?? [];
    for (const e of modelEffects) {
      this.effectlist.push(EffectRecord.createCopy(e));
    }
    let hasNew = false;
    const listSize = this.effectlist.length;
    for (const curRecord of tmpList) {
      const off = ProtoModel.lookupRecord(this.effectlist, listSize, curRecord.getAddress(), curRecord.getSize());
      if (off === -2)
        throw new LowlevelError('Partial overlap of prototype override with existing effects');
      else if (off >= 0) {
        this.effectlist[off] = curRecord;
      } else {
        this.effectlist.push(curRecord);
        hasNew = true;
      }
    }
    if (hasNew)
      this.effectlist.sort(EffectRecord.compareByAddress);
  }

  private decodeLikelyTrash(): void {
    if (this.likelytrash.length === 0) return;
    const tmpList = this.likelytrash.splice(0);
    const modelTrash: VarnodeData[] = (this.model as any).getLikelyTrashList?.() ?? [];
    for (const v of modelTrash)
      this.likelytrash.push(v);
    for (const v of tmpList) {
      let found = false;
      for (const mt of modelTrash) {
        if (mt.space === v.space && mt.offset === v.offset && mt.size === v.size) {
          found = true;
          break;
        }
      }
      if (!found)
        this.likelytrash.push(v);
    }
    this.likelytrash.sort((a, b) => VarnodeData.compare(a, b));
  }

  /**
   * Prepend the indicated number of input parameters to this.
   */
  protected paramShift(paramshift: number): void {
    if (this.model === null || this.store === null)
      throw new LowlevelError('Cannot parameter shift without a model');

    const proto = new PrototypePieces();
    proto.model = this.model;
    proto.firstVarArgSlot = -1;
    const typefactory = (this.model as any).getArch().types;

    if (this.isOutputLocked())
      proto.outtype = this.getOutputType();
    else
      proto.outtype = typefactory.getTypeVoid();

    const extra = typefactory.getBase(4, type_metatype.TYPE_UNKNOWN);
    for (let i = 0; i < paramshift; ++i) {
      proto.innames.push('');
      proto.intypes.push(extra);
    }

    if (this.isInputLocked()) {
      const num = this.numParams();
      for (let i = 0; i < num; ++i) {
        const param = this.getParam(i)!;
        proto.innames.push(param.getName());
        proto.intypes.push(param.getType());
      }
    } else {
      proto.firstVarArgSlot = paramshift;
    }

    const pieces: ParameterPieces[] = [];
    (this.model as any).assignParameterStorage(proto, pieces, false);

    this.store = new ProtoStoreInternal(typefactory.getTypeVoid());

    this.store.setOutput(pieces[0]);
    let j = 0;
    for (let i = 1; i < pieces.length; ++i) {
      if ((pieces[i].flags & ParameterPieces.hiddenretparm) !== 0) {
        this.store.setInput(i - 1, 'rethidden', pieces[i]);
        continue;
      }
      this.store.setInput(j, proto.innames[j], pieces[i]);
      j = j + 1;
    }
    this.setInputLock(true);
    this.setDotdotdot(proto.firstVarArgSlot >= 0);
  }

  protected isParamshiftApplied(): boolean {
    return (this.flags & FuncProto.paramshift_applied) !== 0;
  }

  protected setParamshiftApplied(val: boolean): void {
    this.flags = val ? (this.flags | FuncProto.paramshift_applied)
                     : (this.flags & ~FuncProto.paramshift_applied);
  }

  // --- Public API ---

  getArch(): Architecture { return (this.model as any).getArch(); }

  copy(op2: FuncProto): void {
    this.model = op2.model;
    this.extrapop = op2.extrapop;
    this.flags = op2.flags;
    if (op2.store !== null)
      this.store = op2.store.clone();
    else
      this.store = null;
    this.effectlist = op2.effectlist.slice();
    this.likelytrash = op2.likelytrash.slice();
    this.injectid = op2.injectid;
  }

  copyFlowEffects(op2: FuncProto): void {
    this.flags &= ~(FuncProto.is_inline | FuncProto.no_return);
    this.flags |= op2.flags & (FuncProto.is_inline | FuncProto.no_return);
    this.injectid = op2.injectid;
  }

  getPieces(pieces: PrototypePieces): void {
    pieces.model = this.model;
    if (this.store === null) return;
    pieces.outtype = this.store.getOutput()!.getType();
    const num = this.store.getNumInputs();
    for (let i = 0; i < num; ++i) {
      const param = this.store.getInput(i)!;
      pieces.intypes.push(param.getType());
      pieces.innames.push(param.getName());
    }
    pieces.firstVarArgSlot = this.isDotdotdot() ? num : -1;
  }

  setPieces(pieces: PrototypePieces): void {
    if (pieces.model !== null)
      this.setModel(pieces.model);
    this.updateAllTypes(pieces);
    this.setInputLock(true);
    this.setOutputLock(true);
    this.setModelLock(true);
  }

  setScope(s: Scope, startpoint: any): void {
    this.store = new ProtoStoreSymbol(s, startpoint);
    if (this.model === null)
      this.setModel((s as any).getArch().defaultfp);
  }

  setInternal(m: any, vt: Datatype): void {
    this.store = new ProtoStoreInternal(vt);
    if (this.model === null)
      this.setModel(m);
  }

  setModel(m: any): void {
    if (m !== null) {
      const expop = (m as any).getExtraPop();
      if (this.model === null || expop !== ProtoModel.extrapop_unknown)
        this.extrapop = expop;
      if ((m as any).hasThisPointer())
        this.flags |= FuncProto.has_thisptr;
      if ((m as any).isConstructor())
        this.flags |= FuncProto.is_constructor;
      if ((m as any).isAutoKilledByCall())
        this.flags |= FuncProto.auto_killedbycall;
      this.model = m;
    } else {
      this.model = m;
      this.extrapop = ProtoModel.extrapop_unknown;
    }
  }

  hasModel(): boolean { return this.model !== null; }
  hasMatchingModel(op2: any): boolean { return this.model === op2; }
  getModelName(): string { return (this.model as any).getName(); }
  getModelExtraPop(): number { return (this.model as any).getExtraPop(); }
  isModelUnknown(): boolean { return (this.model as any).isUnknown(); }
  printModelInDecl(): boolean { return (this.model as any).printInDecl(); }

  isInputLocked(): boolean {
    if ((this.flags & FuncProto.voidinputlock) !== 0) return true;
    if (this.numParams() === 0) return false;
    const param = this.getParam(0);
    if (param!.isTypeLocked()) return true;
    return false;
  }

  isOutputLocked(): boolean { return this.store!.getOutput()!.isTypeLocked(); }
  isModelLocked(): boolean { return (this.flags & FuncProto.modellock) !== 0; }
  hasCustomStorage(): boolean { return (this.flags & FuncProto.custom_storage) !== 0; }

  setInputLock(val: boolean): void {
    if (val)
      this.flags |= FuncProto.modellock;
    const num = this.numParams();
    if (num === 0) {
      this.flags = val ? (this.flags | FuncProto.voidinputlock) : (this.flags & ~FuncProto.voidinputlock);
      return;
    }
    for (let i = 0; i < num; ++i) {
      const param = this.getParam(i)!;
      param.setTypeLock(val);
      param.setNameLock(val);
    }
  }

  setOutputLock(val: boolean): void {
    if (val)
      this.flags |= FuncProto.modellock;
    this.store!.getOutput()!.setTypeLock(val);
  }

  setModelLock(val: boolean): void {
    this.flags = val ? (this.flags | FuncProto.modellock) : (this.flags & ~FuncProto.modellock);
  }

  isInline(): boolean { return (this.flags & FuncProto.is_inline) !== 0; }
  setInline(val: boolean): void {
    this.flags = val ? (this.flags | FuncProto.is_inline) : (this.flags & ~FuncProto.is_inline);
  }

  getInjectId(): number { return this.injectid; }
  getReturnBytesConsumed(): number { return this.returnBytesConsumed; }

  setReturnBytesConsumed(val: number): boolean {
    if (val === 0) return false;
    if (this.returnBytesConsumed === 0 || val < this.returnBytesConsumed) {
      this.returnBytesConsumed = val;
      return true;
    }
    return false;
  }

  isNoReturn(): boolean { return (this.flags & FuncProto.no_return) !== 0; }
  setNoReturn(val: boolean): void {
    this.flags = val ? (this.flags | FuncProto.no_return) : (this.flags & ~FuncProto.no_return);
  }

  hasThisPointer(): boolean { return (this.flags & FuncProto.has_thisptr) !== 0; }
  isConstructor(): boolean { return (this.flags & FuncProto.is_constructor) !== 0; }
  setConstructor(val: boolean): void {
    this.flags = val ? (this.flags | FuncProto.is_constructor) : (this.flags & ~FuncProto.is_constructor);
  }

  isDestructor(): boolean { return (this.flags & FuncProto.is_destructor) !== 0; }
  setDestructor(val: boolean): void {
    this.flags = val ? (this.flags | FuncProto.is_destructor) : (this.flags & ~FuncProto.is_destructor);
  }

  hasInputErrors(): boolean { return (this.flags & FuncProto.error_inputparam) !== 0; }
  hasOutputErrors(): boolean { return (this.flags & FuncProto.error_outputparam) !== 0; }
  setInputErrors(val: boolean): void {
    this.flags = val ? (this.flags | FuncProto.error_inputparam) : (this.flags & ~FuncProto.error_inputparam);
  }
  setOutputErrors(val: boolean): void {
    this.flags = val ? (this.flags | FuncProto.error_outputparam) : (this.flags & ~FuncProto.error_outputparam);
  }

  getExtraPop(): number { return this.extrapop; }
  setExtraPop(ep: number): void { this.extrapop = ep; }
  getInjectUponEntry(): number { return (this.model as any).getInjectUponEntry(); }
  getInjectUponReturn(): number { return (this.model as any).getInjectUponReturn(); }

  resolveExtraPop(): void {
    if (!this.isInputLocked()) return;
    const numparams = this.numParams();
    if (this.isDotdotdot()) {
      if (numparams !== 0)
        this.setExtraPop(4);
      return;
    }
    let expop = 4;
    for (let i = 0; i < numparams; ++i) {
      const param = this.getParam(i)!;
      const addr = param.getAddress();
      if (addr.getSpace()!.getType() !== spacetype.IPTR_SPACEBASE) continue;
      let cur = Number(addr.getOffset()) + param.getSize();
      cur = (cur + 3) & 0xffffffc;
      if (cur > expop) expop = cur;
    }
    this.setExtraPop(expop);
  }

  clearUnlockedInput(): void {
    if (this.isInputLocked()) return;
    this.store!.clearAllInputs();
  }

  clearUnlockedOutput(): void {
    const outparam = this.getOutput();
    if (outparam.isTypeLocked()) {
      if (outparam.isSizeTypeLocked()) {
        if (this.model !== null)
          outparam.resetSizeLockType(this.getArch().types);
      }
    } else {
      this.store!.clearOutput();
    }
    this.returnBytesConsumed = 0;
  }

  clearInput(): void {
    this.store!.clearAllInputs();
    this.flags &= ~FuncProto.voidinputlock;
  }

  setInjectId(id: number): void {
    if (id < 0)
      this.cancelInjectId();
    else {
      this.injectid = id;
      this.flags |= FuncProto.is_inline;
    }
  }

  cancelInjectId(): void {
    this.injectid = -1;
    this.flags &= ~FuncProto.is_inline;
  }

  resolveModel(active: ParamActive): void {
    if (this.model === null) return;
    if (!(this.model as any).isMerged()) return;
    const newmodel = (this.model as any).selectModel(active);
    this.setModel(newmodel);
  }

  deriveInputMap(active: ParamActive): void {
    (this.model as any).deriveInputMap(active);
  }

  deriveOutputMap(active: ParamActive): void {
    (this.model as any).deriveOutputMap(active);
  }

  checkInputJoin(hiaddr: any, hisz: number, loaddr: any, losz: number): boolean {
    return (this.model as any).checkInputJoin(hiaddr, hisz, loaddr, losz);
  }

  checkInputSplit(loc: any, size: number, splitpoint: number): boolean {
    return (this.model as any).checkInputSplit(loc, size, splitpoint);
  }

  updateInputTypes(data: Funcdata, triallist: Varnode[], activeinput: ParamActive): void {
    if (this.isInputLocked()) return;
    this.store!.clearAllInputs();
    let count = 0;
    const numtrials = activeinput.getNumTrials();
    for (let i = 0; i < numtrials; ++i) {
      const trial = activeinput.getTrial(i);
      if (trial.isUsed()) {
        const vn = triallist[trial.getSlot() - 1];
        if ((vn as any).isMark()) continue;
        const pieces = new ParameterPieces();
        if ((vn as any).isPersist()) {
          let sz = { value: 0 };
          pieces.addr = (data as any).findDisjointCover(vn, sz);
          if (sz.value === (vn as any).getSize())
            pieces.type = (vn as any).getHigh().getType();
          else
            pieces.type = (data as any).getArch().types.getBase(sz.value, type_metatype.TYPE_UNKNOWN);
          pieces.flags = 0;
        } else {
          pieces.addr = trial.getAddress();
          pieces.type = (vn as any).getHigh().getType();
          pieces.flags = 0;
        }
        this.store!.setInput(count, '', pieces);
        count += 1;
        (vn as any).setMark();
      }
    }
    for (let i = 0; i < triallist.length; ++i)
      (triallist[i] as any).clearMark();
    this.updateThisPointer();
  }

  updateInputNoTypes(data: Funcdata, triallist: Varnode[], activeinput: ParamActive): void {
    if (this.isInputLocked()) return;
    this.store!.clearAllInputs();
    let count = 0;
    const numtrials = activeinput.getNumTrials();
    const factory = (data as any).getArch().types;
    for (let i = 0; i < numtrials; ++i) {
      const trial = activeinput.getTrial(i);
      if (trial.isUsed()) {
        const vn = triallist[trial.getSlot() - 1];
        if ((vn as any).isMark()) continue;
        const pieces = new ParameterPieces();
        if ((vn as any).isPersist()) {
          let sz = { value: 0 };
          pieces.addr = (data as any).findDisjointCover(vn, sz);
          pieces.type = factory.getBase(sz.value, type_metatype.TYPE_UNKNOWN);
          pieces.flags = 0;
        } else {
          pieces.addr = trial.getAddress();
          pieces.type = factory.getBase((vn as any).getSize(), type_metatype.TYPE_UNKNOWN);
          pieces.flags = 0;
        }
        this.store!.setInput(count, '', pieces);
        count += 1;
        (vn as any).setMark();
      }
    }
    for (let i = 0; i < triallist.length; ++i)
      (triallist[i] as any).clearMark();
  }

  updateOutputTypes(triallist: Varnode[]): void {
    const outparm = this.getOutput();
    if (!outparm.isTypeLocked()) {
      if (triallist.length === 0) {
        this.store!.clearOutput();
        return;
      }
    } else if (outparm.isSizeTypeLocked()) {
      if (triallist.length === 0) return;
      if ((triallist[0] as any).getAddr().equals(outparm.getAddress()) &&
          (triallist[0] as any).getSize() === outparm.getSize())
        outparm.overrideSizeLockType((triallist[0] as any).getHigh().getType());
      return;
    } else {
      return; // Locked
    }
    if (triallist.length === 0) return;
    const pieces = new ParameterPieces();
    pieces.addr = (triallist[0] as any).getAddr();
    pieces.type = (triallist[0] as any).getHigh().getType();
    pieces.flags = 0;
    this.store!.setOutput(pieces);
  }

  updateOutputNoTypes(triallist: Varnode[], factory: TypeFactory): void {
    if (this.isOutputLocked()) return;
    if (triallist.length === 0) {
      this.store!.clearOutput();
      return;
    }
    const pieces = new ParameterPieces();
    pieces.type = (factory as any).getBase((triallist[0] as any).getSize(), type_metatype.TYPE_UNKNOWN);
    pieces.addr = (triallist[0] as any).getAddr();
    pieces.flags = 0;
    this.store!.setOutput(pieces);
  }

  updateAllTypes(proto: PrototypePieces): void {
    this.setModel(this.model);
    this.store!.clearAllInputs();
    this.store!.clearOutput();
    this.flags &= ~FuncProto.voidinputlock;
    this.setDotdotdot(proto.firstVarArgSlot >= 0);

    const pieces: ParameterPieces[] = [];
    try {
      (this.model as any).assignParameterStorage(proto, pieces, false);
      this.store!.setOutput(pieces[0]);
      let j = 0;
      for (let i = 1; i < pieces.length; ++i) {
        if ((pieces[i].flags & ParameterPieces.hiddenretparm) !== 0) {
          this.store!.setInput(i - 1, 'rethidden', pieces[i]);
          continue;
        }
        const nm = (j >= proto.innames.length) ? '' : proto.innames[j];
        this.store!.setInput(i - 1, nm, pieces[i]);
        j = j + 1;
      }
    } catch (err: any) {
      if (err instanceof ParamUnassignedError)
        this.flags |= FuncProto.error_inputparam;
      else
        throw err;
    }
    this.updateThisPointer();
  }

  getParam(i: number): ProtoParameter | null { return this.store!.getInput(i); }
  setParam(i: number, name: string, piece: ParameterPieces): void { this.store!.setInput(i, name, piece); }
  removeParam(i: number): void { this.store!.clearInput(i); }
  numParams(): number { return this.store!.getNumInputs(); }
  getOutput(): ProtoParameter { return this.store!.getOutput()!; }
  setOutput(piece: ParameterPieces): void { this.store!.setOutput(piece); }
  getOutputType(): Datatype { return this.store!.getOutput()!.getType(); }
  getLocalRange(): any { return (this.model as any).getLocalRange(); }
  getParamRange(): any { return (this.model as any).getParamRange(); }
  isStackGrowsNegative(): boolean { return (this.model as any).isStackGrowsNegative(); }

  isDotdotdot(): boolean { return (this.flags & FuncProto.dotdotdot) !== 0; }
  setDotdotdot(val: boolean): void {
    this.flags = val ? (this.flags | FuncProto.dotdotdot) : (this.flags & ~FuncProto.dotdotdot);
  }

  isOverride(): boolean { return (this.flags & FuncProto.is_override) !== 0; }
  setOverride(val: boolean): void {
    this.flags = val ? (this.flags | FuncProto.is_override) : (this.flags & ~FuncProto.is_override);
  }

  hasEffect(addr: any, size: number): number {
    if (this.effectlist.length === 0)
      return (this.model as any).hasEffect(addr, size);
    return ProtoModel.lookupEffect(this.effectlist, addr, size);
  }

  effectBegin(): EffectRecord[] {
    if (this.effectlist.length === 0)
      return (this.model as any).getEffectList?.() ?? [];
    return this.effectlist;
  }

  effectEnd(): number {
    if (this.effectlist.length === 0)
      return ((this.model as any).getEffectList?.() ?? []).length;
    return this.effectlist.length;
  }

  trashBegin(): VarnodeData[] {
    if (this.likelytrash.length === 0)
      return (this.model as any).getLikelyTrashList?.() ?? [];
    return this.likelytrash;
  }

  trashEnd(): number {
    if (this.likelytrash.length === 0)
      return ((this.model as any).getLikelyTrashList?.() ?? []).length;
    return this.likelytrash.length;
  }

  /** Get an iterable over the model's internal storage locations */
  getInternalIter(): VarnodeData[] {
    return this.model?.getInternalStorage?.() ?? [];
  }

  characterizeAsInputParam(addr: any, size: number): number {
    if (!this.isDotdotdot()) {
      if ((this.flags & FuncProto.voidinputlock) !== 0) return 0;
      const num = this.numParams();
      if (num > 0) {
        let locktest = false;
        let resContains = false;
        let resContainedBy = false;
        for (let i = 0; i < num; ++i) {
          const param = this.getParam(i)!;
          if (!param.isTypeLocked()) continue;
          locktest = true;
          const iaddr = param.getAddress();
          const off = iaddr.justifiedContain(param.getSize(), addr, size, false);
          if (off === 0)
            return ParamEntry.contains_justified;
          else if (off > 0)
            resContains = true;
          if (iaddr.containedBy(param.getSize(), addr, size))
            resContainedBy = true;
        }
        if (locktest) {
          if (resContains) return ParamEntry.contains_unjustified;
          if (resContainedBy) return ParamEntry.contained_by;
          return ParamEntry.no_containment;
        }
      }
    }
    return (this.model as any).characterizeAsInputParam(addr, size);
  }

  characterizeAsOutput(addr: any, size: number): number {
    if (this.isOutputLocked()) {
      const outparam = this.getOutput();
      if ((outparam.getType() as any).getMetatype() === type_metatype.TYPE_VOID)
        return ParamEntry.no_containment;
      const iaddr = outparam.getAddress();
      const off = iaddr.justifiedContain(outparam.getSize(), addr, size, false);
      if (off === 0) return ParamEntry.contains_justified;
      else if (off > 0) return ParamEntry.contains_unjustified;
      if (iaddr.containedBy(outparam.getSize(), addr, size))
        return ParamEntry.contained_by;
      return ParamEntry.no_containment;
    }
    return (this.model as any).characterizeAsOutput(addr, size);
  }

  possibleInputParam(addr: any, size: number): boolean {
    if (!this.isDotdotdot()) {
      if ((this.flags & FuncProto.voidinputlock) !== 0) return false;
      const num = this.numParams();
      if (num > 0) {
        let locktest = false;
        for (let i = 0; i < num; ++i) {
          const param = this.getParam(i)!;
          if (!param.isTypeLocked()) continue;
          locktest = true;
          const iaddr = param.getAddress();
          if (iaddr.justifiedContain(param.getSize(), addr, size, false) === 0)
            return true;
        }
        if (locktest) return false;
      }
    }
    return (this.model as any).possibleInputParam(addr, size);
  }

  possibleOutputParam(addr: any, size: number): boolean {
    if (this.isOutputLocked()) {
      const outparam = this.getOutput();
      if ((outparam.getType() as any).getMetatype() === type_metatype.TYPE_VOID)
        return false;
      const iaddr = outparam.getAddress();
      if (iaddr.justifiedContain(outparam.getSize(), addr, size, false) === 0)
        return true;
      return false;
    }
    return (this.model as any).possibleOutputParam(addr, size);
  }

  getMaxInputDelay(): number { return (this.model as any).getMaxInputDelay(); }
  getMaxOutputDelay(): number { return (this.model as any).getMaxOutputDelay(); }

  unjustifiedInputParam(addr: any, size: number, res: VarnodeData): boolean {
    if (!this.isDotdotdot()) {
      if ((this.flags & FuncProto.voidinputlock) !== 0) return false;
      const num = this.numParams();
      if (num > 0) {
        let locktest = false;
        for (let i = 0; i < num; ++i) {
          const param = this.getParam(i)!;
          if (!param.isTypeLocked()) continue;
          locktest = true;
          const iaddr = param.getAddress();
          const just = iaddr.justifiedContain(param.getSize(), addr, size, false);
          if (just === 0) return false;
          if (just > 0) {
            res.space = iaddr.getSpace();
            res.offset = iaddr.getOffset();
            res.size = param.getSize();
            return true;
          }
        }
        if (locktest) return false;
      }
    }
    return (this.model as any).unjustifiedInputParam(addr, size, res);
  }

  assumedInputExtension(addr: any, size: number, res: VarnodeData): number {
    return (this.model as any).assumedInputExtension(addr, size, res);
  }

  assumedOutputExtension(addr: any, size: number, res: VarnodeData): number {
    return (this.model as any).assumedOutputExtension(addr, size, res);
  }

  getBiggestContainedInputParam(loc: any, size: number, res: VarnodeData): boolean {
    if (!this.isDotdotdot()) {
      if ((this.flags & FuncProto.voidinputlock) !== 0) return false;
      const num = this.numParams();
      if (num > 0) {
        let locktest = false;
        res.size = 0;
        for (let i = 0; i < num; ++i) {
          const param = this.getParam(i)!;
          if (!param.isTypeLocked()) continue;
          locktest = true;
          const iaddr = param.getAddress();
          if (iaddr.containedBy(param.getSize(), loc, size)) {
            if (param.getSize() > res.size) {
              res.space = iaddr.getSpace();
              res.offset = iaddr.getOffset();
              res.size = param.getSize();
            }
          }
        }
        if (locktest)
          return (res.size === 0);
      }
    }
    return (this.model as any).getBiggestContainedInputParam(loc, size, res);
  }

  getBiggestContainedOutput(loc: any, size: number, res: VarnodeData): boolean {
    if (this.isOutputLocked()) {
      const outparam = this.getOutput();
      if ((outparam.getType() as any).getMetatype() === type_metatype.TYPE_VOID)
        return false;
      const iaddr = outparam.getAddress();
      if (iaddr.containedBy(outparam.getSize(), loc, size)) {
        res.space = iaddr.getSpace();
        res.offset = iaddr.getOffset();
        res.size = outparam.getSize();
        return true;
      }
      return false;
    }
    return (this.model as any).getBiggestContainedOutput(loc, size, res);
  }

  getThisPointerStorage(dt: Datatype): any {
    if (!(this.model as any).hasThisPointer())
      return Address.invalid();
    const proto = new PrototypePieces();
    proto.model = this.model;
    proto.firstVarArgSlot = -1;
    proto.outtype = this.getOutputType();
    proto.intypes.push(dt);
    const res: ParameterPieces[] = [];
    (this.model as any).assignParameterStorage(proto, res, true);
    for (let i = 1; i < res.length; ++i) {
      if ((res[i].flags & ParameterPieces.hiddenretparm) !== 0) continue;
      return res[i].addr;
    }
    return Address.invalid();
  }

  isCompatible(op2: FuncProto): boolean {
    if (!(this.model as any).isCompatible(op2.model)) return false;
    if (op2.isOutputLocked()) {
      if (this.isOutputLocked()) {
        const out1 = this.store!.getOutput()!;
        const out2 = op2.store!.getOutput()!;
        if (out1.notEquals(out2)) return false;
      }
    }
    if (this.extrapop !== ProtoModel.extrapop_unknown &&
        this.extrapop !== op2.extrapop) return false;
    if (this.isDotdotdot() !== op2.isDotdotdot()) {
      if (op2.isDotdotdot()) {
        if (this.isInputLocked()) return false;
      } else {
        return false;
      }
    }
    if (this.injectid !== op2.injectid) return false;
    if ((this.flags & (FuncProto.is_inline | FuncProto.no_return)) !==
        (op2.flags & (FuncProto.is_inline | FuncProto.no_return)))
      return false;
    if (this.effectlist.length !== op2.effectlist.length) return false;
    for (let i = 0; i < this.effectlist.length; ++i)
      if (this.effectlist[i].notEquals(op2.effectlist[i])) return false;
    if (this.likelytrash.length !== op2.likelytrash.length) return false;
    for (let i = 0; i < this.likelytrash.length; ++i)
      if (!this.likelytrash[i].equals(op2.likelytrash[i])) return false;
    return true;
  }

  printRaw(funcname: string, s: any): void {
    if (this.model !== null)
      s.write((this.model as any).getName() + ' ');
    else
      s.write('(no model) ');
    (this.getOutputType() as any).printRaw(s);
    s.write(' ' + funcname + '(');
    const num = this.numParams();
    for (let i = 0; i < num; ++i) {
      if (i !== 0) s.write(',');
      (this.getParam(i)!.getType() as any).printRaw(s);
    }
    if (this.isDotdotdot()) {
      if (num !== 0) s.write(',');
      s.write('...');
    }
    s.write(') extrapop=' + this.extrapop);
  }

  isAutoKilledByCall(): boolean {
    if ((this.flags & FuncProto.auto_killedbycall) !== 0)
      return true;
    if (this.isOutputLocked())
      return true;
    return false;
  }

  getComparableFlags(): number {
    return (this.flags & (FuncProto.dotdotdot | FuncProto.is_constructor | FuncProto.is_destructor | FuncProto.has_thisptr));
  }

  getSpacebase(): AddrSpace { return (this.model as any).getSpacebase(); }

  encode(encoder: any): void {
    encoder.openElement(ELEM_PROTOTYPE);
    encoder.writeString(ATTRIB_MODEL, (this.model as any).getName());
    if (this.extrapop === ProtoModel.extrapop_unknown)
      encoder.writeString(ATTRIB_EXTRAPOP, 'unknown');
    else
      encoder.writeSignedInteger(ATTRIB_EXTRAPOP, this.extrapop);
    if (this.isDotdotdot())
      encoder.writeBool(ATTRIB_DOTDOTDOT, true);
    if (this.isModelLocked())
      encoder.writeBool(ATTRIB_MODELLOCK, true);
    if ((this.flags & FuncProto.voidinputlock) !== 0)
      encoder.writeBool(ATTRIB_VOIDLOCK, true);
    if (this.isInline())
      encoder.writeBool(ATTRIB_INLINE, true);
    if (this.isNoReturn())
      encoder.writeBool(ATTRIB_NORETURN, true);
    if (this.hasCustomStorage())
      encoder.writeBool(ATTRIB_CUSTOM, true);
    if (this.isConstructor())
      encoder.writeBool(ATTRIB_CONSTRUCTOR, true);
    if (this.isDestructor())
      encoder.writeBool(ATTRIB_DESTRUCTOR, true);

    const outparam = this.store!.getOutput()!;
    encoder.openElement(ELEM_RETURNSYM);
    if (outparam.isTypeLocked())
      encoder.writeBool(ATTRIB_TYPELOCK, true);
    (outparam.getAddress() as any).encode(encoder, outparam.getSize());
    (outparam.getType() as any).encodeRef(encoder);
    encoder.closeElement(ELEM_RETURNSYM);

    this.encodeEffect(encoder);
    this.encodeLikelyTrash(encoder);

    if (this.injectid >= 0) {
      const glb = (this.model as any).getArch();
      encoder.openElement(ELEM_INJECT);
      encoder.writeString(ATTRIB_CONTENT, glb.pcodeinjectlib.getCallFixupName(this.injectid));
      encoder.closeElement(ELEM_INJECT);
    }
    this.store!.encode(encoder);
    encoder.closeElement(ELEM_PROTOTYPE);
  }

  decode(decoder: any, glb: Architecture): void {
    if (this.store === null)
      throw new LowlevelError('Prototype storage must be set before restoring FuncProto');

    let mod: any = null;
    let seenextrapop = false;
    let readextrapop = 0;
    this.flags = 0;
    this.injectid = -1;

    const elemId = decoder.openElement(ELEM_PROTOTYPE);
    for (;;) {
      const attribId = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_MODEL.getId()) {
        const modelname = decoder.readString();
        if (modelname.length === 0 || modelname === 'default')
          mod = (glb as any).defaultfp;
        else {
          mod = (glb as any).getModel(modelname);
          if (mod === null)
            mod = (glb as any).createUnknownModel(modelname);
        }
      }
      else if (attribId === ATTRIB_EXTRAPOP.getId()) {
        seenextrapop = true;
        readextrapop = decoder.readSignedIntegerExpectString('unknown', ProtoModel.extrapop_unknown);
      }
      else if (attribId === ATTRIB_MODELLOCK.getId()) {
        if (decoder.readBool()) this.flags |= FuncProto.modellock;
      }
      else if (attribId === ATTRIB_DOTDOTDOT.getId()) {
        if (decoder.readBool()) this.flags |= FuncProto.dotdotdot;
      }
      else if (attribId === ATTRIB_VOIDLOCK.getId()) {
        if (decoder.readBool()) this.flags |= FuncProto.voidinputlock;
      }
      else if (attribId === ATTRIB_INLINE.getId()) {
        if (decoder.readBool()) this.flags |= FuncProto.is_inline;
      }
      else if (attribId === ATTRIB_NORETURN.getId()) {
        if (decoder.readBool()) this.flags |= FuncProto.no_return;
      }
      else if (attribId === ATTRIB_CUSTOM.getId()) {
        if (decoder.readBool()) this.flags |= FuncProto.custom_storage;
      }
      else if (attribId === ATTRIB_CONSTRUCTOR.getId()) {
        if (decoder.readBool()) this.flags |= FuncProto.is_constructor;
      }
      else if (attribId === ATTRIB_DESTRUCTOR.getId()) {
        if (decoder.readBool()) this.flags |= FuncProto.is_destructor;
      }
    }
    if (mod !== null)
      this.setModel(mod);
    if (seenextrapop)
      this.extrapop = readextrapop;

    let subId = decoder.peekElement();
    if (subId !== 0) {
      const outpieces = new ParameterPieces();
      let outputlock = false;

      if (subId === ELEM_RETURNSYM.getId()) {
        decoder.openElement();
        for (;;) {
          const attribId = decoder.getNextAttributeId();
          if (attribId === 0) break;
          if (attribId === ATTRIB_TYPELOCK.getId())
            outputlock = decoder.readBool();
        }
        const tmpsize = { val: 0 };
        outpieces.addr = Address.decode(decoder, tmpsize);
        outpieces.type = (glb as any).types.decodeType(decoder);
        outpieces.flags = 0;
        decoder.closeElement(subId);
      }
      else if (subId === ELEM_ADDR.getId()) {
        const tmpsize = { val: 0 };
        outpieces.addr = Address.decode(decoder, tmpsize);
        outpieces.type = (glb as any).types.decodeType(decoder);
        outpieces.flags = 0;
      }
      else {
        throw new LowlevelError('Missing <returnsym> tag');
      }

      this.store!.setOutput(outpieces);
      this.store!.getOutput()!.setTypeLock(outputlock);
    } else {
      throw new LowlevelError('Missing <returnsym> tag');
    }

    if ((this.flags & FuncProto.voidinputlock) !== 0 || this.isOutputLocked())
      this.flags |= FuncProto.modellock;

    for (;;) {
      subId = decoder.peekElement();
      if (subId === 0) break;
      if (subId === ELEM_UNAFFECTED.getId()) {
        decoder.openElement();
        while (decoder.peekElement() !== 0) {
          const rec = new EffectRecord();
          rec.decodeRecord(EffectRecord.unaffected, decoder);
          this.effectlist.push(rec);
        }
        decoder.closeElement(subId);
      }
      else if (subId === ELEM_KILLEDBYCALL.getId()) {
        decoder.openElement();
        while (decoder.peekElement() !== 0) {
          const rec = new EffectRecord();
          rec.decodeRecord(EffectRecord.killedbycall, decoder);
          this.effectlist.push(rec);
        }
        decoder.closeElement(subId);
      }
      else if (subId === ELEM_RETURNADDRESS.getId()) {
        decoder.openElement();
        while (decoder.peekElement() !== 0) {
          const rec = new EffectRecord();
          rec.decodeRecord(EffectRecord.return_address, decoder);
          this.effectlist.push(rec);
        }
        decoder.closeElement(subId);
      }
      else if (subId === ELEM_LIKELYTRASH.getId()) {
        decoder.openElement();
        while (decoder.peekElement() !== 0) {
          const vd = new VarnodeData();
          vd.decode(decoder);
          this.likelytrash.push(vd);
        }
        decoder.closeElement(subId);
      }
      else if (subId === ELEM_INJECT.getId()) {
        decoder.openElement();
        const injectString = decoder.readStringById(ATTRIB_CONTENT);
        this.injectid = (glb as any).pcodeinjectlib.getPayloadId(0 /* InjectPayload::CALLFIXUP_TYPE */, injectString);
        this.flags |= FuncProto.is_inline;
        decoder.closeElement(subId);
      }
      else if (subId === ELEM_INTERNALLIST.getId()) {
        this.store!.decodeStore(decoder, this.model);
      }
    }
    decoder.closeElement(elemId);
    this.decodeEffect();
    this.decodeLikelyTrash();
    if (!this.isModelLocked()) {
      if (this.isInputLocked())
        this.flags |= FuncProto.modellock;
    }
    if (this.extrapop === ProtoModel.extrapop_unknown)
      this.resolveExtraPop();

    const outparam = this.store!.getOutput()!;
    if ((outparam.getType() as any).getMetatype() !== type_metatype.TYPE_VOID &&
        outparam.getAddress().isInvalid()) {
      throw new LowlevelError('<returnsym> tag must include a valid storage address');
    }
    this.updateThisPointer();
  }
}

// Register the real FuncProto constructor with type.ts to resolve circular dependency
registerFuncProtoClass(FuncProto);

// ---------------------------------------------------------------------------
// FuncCallSpecs
// ---------------------------------------------------------------------------

/**
 * A class for analyzing parameters to a sub-function call.
 * This can be viewed as a function prototype that evolves over the course of analysis.
 * It derives from FuncProto and includes facilities for analyzing data-flow
 * for parameter information.
 */
export class FuncCallSpecs extends FuncProto {
  static readonly offset_unknown = 0xBADBEEF;
  private static _nextId: number = 1;
  private static _registry: Map<number, FuncCallSpecs> = new Map();
  private _id: number;

  private op: PcodeOp;
  private name: string = '';
  private entryaddress: any; // Address
  private fd: Funcdata | null = null;
  private effective_extrapop: number;
  private stackoffset: bigint;
  private stackPlaceholderSlot: number;
  private paramshift: number;
  private matchCallCount: number = 1;
  private activeinput: ParamActive;
  private activeoutput: ParamActive;
  private inputConsume: number[] = [];
  private isinputactive: boolean;
  private isoutputactive: boolean;
  private isbadjumptable: boolean;
  private isstackoutputlock: boolean;

  getId(): number { return this._id; }

  constructor(call_op: PcodeOp) {
    super();
    this._id = FuncCallSpecs._nextId++;
    FuncCallSpecs._registry.set(this._id, this);
    this.activeinput = new ParamActive(true);
    this.activeoutput = new ParamActive(true);
    this.effective_extrapop = ProtoModel.extrapop_unknown;
    this.stackoffset = BigInt(FuncCallSpecs.offset_unknown);
    this.stackPlaceholderSlot = -1;
    this.paramshift = 0;
    this.op = call_op;
    this.fd = null;

    if ((call_op as any).code() === OpCode.CPUI_CALL) {
      this.entryaddress = (call_op as any).getIn(0).getAddr();
      if (this.entryaddress.getSpace().getType() === spacetype.IPTR_FSPEC) {
        const otherfc = FuncCallSpecs.getFspecFromConst(this.entryaddress);
        this.entryaddress = otherfc.entryaddress;
      }
    } else {
      this.entryaddress = Address.invalid();
    }

    this.isinputactive = false;
    this.isoutputactive = false;
    this.isbadjumptable = false;
    this.isstackoutputlock = false;
  }

  // --- Private helpers ---

  private getSpacebaseRelative(): Varnode | null {
    if (this.stackPlaceholderSlot < 0) return null;
    const tmpvn = (this.op as any).getIn(this.stackPlaceholderSlot);
    if (!(tmpvn as any).isSpacebasePlaceholder()) return null;
    if (!(tmpvn as any).isWritten()) return null;
    const loadop = (tmpvn as any).getDef();
    if ((loadop as any).code() !== OpCode.CPUI_LOAD) return null;
    return (loadop as any).getIn(1);
  }

  private buildParam(data: Funcdata, vn: Varnode | null, param: ProtoParameter, stackref: Varnode | null): Varnode {
    if (vn === null) {
      const spc = param.getAddress().getSpace();
      const off: bigint = param.getAddress().getOffset();
      const sz = param.getSize();
      return (data as any).opStackLoad(spc, off, sz, this.op, stackref, false);
    }
    if ((vn as any).getSize() === param.getSize()) return vn;
    const newop = (data as any).newOp(2, (this.op as any).getAddr());
    (data as any).opSetOpcode(newop, OpCode.CPUI_SUBPIECE);
    const newout = (data as any).newUniqueOut(param.getSize(), newop);
    let useVn = vn;
    if ((vn as any).isFree() && !(vn as any).isConstant() && !(vn as any).hasNoDescend())
      useVn = (data as any).newVarnode((vn as any).getSize(), (vn as any).getAddr());
    (data as any).opSetInput(newop, useVn, 0);
    (data as any).opSetInput(newop, (data as any).newConstant(4, 0n), 1);
    (data as any).opInsertBefore(newop, this.op);
    return newout;
  }

  private transferLockedInputParam(param: ProtoParameter): number {
    const numtrials = this.activeinput.getNumTrials();
    const startaddr = param.getAddress();
    const sz = param.getSize();
    const lastaddr = startaddr.add(BigInt(sz - 1));
    for (let i = 0; i < numtrials; ++i) {
      const curtrial = this.activeinput.getTrial(i);
      if (startaddr.lessThan(curtrial.getAddress())) continue;
      const trialend = curtrial.getAddress().add(BigInt(curtrial.getSize() - 1));
      if (trialend.lessThan(lastaddr)) continue;
      if (curtrial.isDefinitelyNotUsed()) return 0;
      return curtrial.getSlot();
    }
    if (startaddr.getSpace()!.getType() === spacetype.IPTR_SPACEBASE)
      return -1;
    return 0;
  }

  private transferLockedOutputParam(param: ProtoParameter, newoutput: Varnode[]): void {
    const paramAddr = new Address(param.getAddress());
    let vn = (this.op as any).getOut();
    if (vn !== null) {
      const vnAddr = new Address((vn as any).getAddr());
      if (paramAddr.justifiedContain(param.getSize(), vnAddr, (vn as any).getSize(), false) >= 0)
        newoutput.push(vn);
      else if (vnAddr.justifiedContain((vn as any).getSize(), paramAddr, param.getSize(), false) >= 0)
        newoutput.push(vn);
    }
    let indop = (this.op as any).previousOp();
    while (indop !== null && (indop as any).code() === OpCode.CPUI_INDIRECT) {
      if ((indop as any).isIndirectCreation()) {
        vn = (indop as any).getOut();
        const vnAddr2 = new Address((vn as any).getAddr());
        if (paramAddr.justifiedContain(param.getSize(), vnAddr2, (vn as any).getSize(), false) >= 0)
          newoutput.push(vn);
        else if (vnAddr2.justifiedContain((vn as any).getSize(), paramAddr, param.getSize(), false) >= 0)
          newoutput.push(vn);
      }
      indop = (indop as any).previousOp();
    }
  }

  private transferLockedInput(newinput: Varnode[], source: FuncProto): boolean {
    newinput.push((this.op as any).getIn(0));
    const numparams = source.numParams();
    let stackref: Varnode | null = null;
    for (let i = 0; i < numparams; ++i) {
      const reuse = this.transferLockedInputParam(source.getParam(i)!);
      if (reuse === 0) return false;
      if (reuse > 0)
        newinput.push((this.op as any).getIn(reuse));
      else {
        if (stackref === null)
          stackref = this.getSpacebaseRelative();
        if (stackref === null)
          return false;
        newinput.push(null as any);
      }
    }
    return true;
  }

  private transferLockedOutput(newoutput: Varnode[], source: FuncProto): boolean {
    const param = source.getOutput();
    if ((param.getType() as any).getMetatype() === type_metatype.TYPE_VOID)
      return true;
    this.transferLockedOutputParam(param, newoutput);
    return true;
  }

  private commitNewInputs(data: Funcdata, newinput: Varnode[]): void {
    if (!this.isInputLocked()) return;
    const stackref = this.getSpacebaseRelative();
    let placeholder: Varnode | null = null;
    if (this.stackPlaceholderSlot >= 0)
      placeholder = (this.op as any).getIn(this.stackPlaceholderSlot);
    let noplacehold = true;

    this.stackPlaceholderSlot = -1;
    const numPasses = this.activeinput.getNumPasses();
    this.activeinput.clear();

    const numparams = this.numParams();
    for (let i = 0; i < numparams; ++i) {
      const param = this.getParam(i)!;
      const vn = this.buildParam(data, newinput[1 + i], param, stackref);
      newinput[1 + i] = vn;
      this.activeinput.registerTrial(param.getAddress(), param.getSize());
      this.activeinput.getTrial(i).markActive();
      if (noplacehold && param.getAddress().getSpace()!.getType() === spacetype.IPTR_SPACEBASE) {
        (vn as any).setSpacebasePlaceholder();
        noplacehold = false;
        placeholder = null;
      }
    }
    if (placeholder !== null) {
      newinput.push(placeholder);
      this.setStackPlaceholderSlot(newinput.length - 1);
    }
    (data as any).opSetAllInput(this.op, newinput);
    if (!this.isDotdotdot())
      this.clearActiveInput();
    else {
      if (numPasses > 0)
        this.activeinput.finishPass();
    }
  }

  private commitNewOutputs(data: Funcdata, newoutput: Varnode[]): void {
    if (!this.isOutputLocked()) return;
    this.activeoutput.clear();

    if (newoutput.length > 0) {
      const param = this.getOutput();
      this.activeoutput.registerTrial(param.getAddress(), param.getSize());
      if (param.getSize() === 1 && (param.getType() as any).getMetatype() === type_metatype.TYPE_BOOL &&
          (data as any).isTypeRecoveryOn())
        (data as any).opMarkCalculatedBool(this.op);
      let exactMatch: Varnode | null = null;
      for (let i = 0; i < newoutput.length; ++i) {
        if ((newoutput[i] as any).getSize() === param.getSize()) {
          exactMatch = newoutput[i];
          break;
        }
      }
      let realOut: Varnode;
      let indOp: PcodeOp;
      if (exactMatch !== null) {
        indOp = (exactMatch as any).getDef();
        if (this.op !== indOp) {
          (data as any).opSetOutput(this.op, exactMatch);
          (data as any).opUnlink(indOp);
        }
        realOut = exactMatch;
      } else {
        (data as any).opUnsetOutput(this.op);
        realOut = (data as any).newVarnodeOut(param.getSize(), param.getAddress(), this.op);
      }

      for (let i = 0; i < newoutput.length; ++i) {
        const oldOut = newoutput[i];
        if (oldOut === exactMatch) continue;
        indOp = (oldOut as any).getDef();
        if (indOp === this.op)
          indOp = null as any;
        if ((oldOut as any).getSize() < param.getSize()) {
          if (indOp !== null) {
            (data as any).opUninsert(indOp);
            (data as any).opSetOpcode(indOp, OpCode.CPUI_SUBPIECE);
          } else {
            indOp = (data as any).newOp(2, (this.op as any).getAddr());
            (data as any).opSetOpcode(indOp, OpCode.CPUI_SUBPIECE);
            (data as any).opSetOutput(indOp, oldOut);
          }
          const overlap = (oldOut as any).overlapAddr((realOut as any).getAddr(), (realOut as any).getSize());
          (data as any).opSetInput(indOp, realOut, 0);
          (data as any).opSetInput(indOp, (data as any).newConstant(4, BigInt(overlap)), 1);
          (data as any).opInsertAfter(indOp, this.op);
        }
        else if (param.getSize() < (oldOut as any).getSize()) {
          const overlap = (oldOut as any).getAddr().justifiedContain(
            (oldOut as any).getSize(), param.getAddress(), param.getSize(), false);
          const vardata = new VarnodeData();
          const opc = this.assumedOutputExtension(param.getAddress(), param.getSize(), vardata);
          if (opc !== OpCode.CPUI_COPY && overlap === 0) {
            let extOpc = opc;
            if (opc === OpCode.CPUI_PIECE) {
              if ((param.getType() as any).getMetatype() === type_metatype.TYPE_INT)
                extOpc = OpCode.CPUI_INT_SEXT;
              else
                extOpc = OpCode.CPUI_INT_ZEXT;
            }
            if (indOp !== null) {
              (data as any).opUninsert(indOp);
              (data as any).opRemoveInput(indOp, 1);
              (data as any).opSetOpcode(indOp, extOpc);
              (data as any).opSetInput(indOp, realOut, 0);
              (data as any).opInsertAfter(indOp, this.op);
            } else {
              const extop = (data as any).newOp(1, (this.op as any).getAddr());
              (data as any).opSetOpcode(extop, extOpc);
              (data as any).opSetOutput(extop, oldOut);
              (data as any).opSetInput(extop, realOut, 0);
              (data as any).opInsertAfter(extop, this.op);
            }
          } else {
            if (indOp !== null)
              (data as any).opUnlink(indOp);
            const mostSigSize = (oldOut as any).getSize() - overlap - (realOut as any).getSize();
            let lastOp: PcodeOp = this.op;
            if (overlap !== 0) {
              let loAddr = (oldOut as any).getAddr();
              if (loAddr.isBigEndian())
                loAddr = loAddr.add((oldOut as any).getSize() - overlap);
              const newIndOp = (data as any).newIndirectCreation(this.op, loAddr, overlap, true);
              const concatOp = (data as any).newOp(2, (this.op as any).getAddr());
              (data as any).opSetOpcode(concatOp, OpCode.CPUI_PIECE);
              (data as any).opSetInput(concatOp, realOut, 0);
              (data as any).opSetInput(concatOp, (newIndOp as any).getOut(), 1);
              (data as any).opInsertAfter(concatOp, this.op);
              if (mostSigSize !== 0) {
                if (loAddr.isBigEndian())
                  (data as any).newVarnodeOut(overlap + (realOut as any).getSize(), (realOut as any).getAddr(), concatOp);
                else
                  (data as any).newVarnodeOut(overlap + (realOut as any).getSize(), loAddr, concatOp);
              }
              lastOp = concatOp;
            }
            if (mostSigSize !== 0) {
              let hiAddr = (oldOut as any).getAddr();
              if (!(hiAddr as any).isBigEndian())
                hiAddr = hiAddr.add((realOut as any).getSize() + overlap);
              const newIndOp = (data as any).newIndirectCreation(this.op, hiAddr, mostSigSize, true);
              const concatOp = (data as any).newOp(2, (this.op as any).getAddr());
              (data as any).opSetOpcode(concatOp, OpCode.CPUI_PIECE);
              (data as any).opSetInput(concatOp, (newIndOp as any).getOut(), 0);
              (data as any).opSetInput(concatOp, (lastOp as any).getOut(), 1);
              (data as any).opInsertAfter(concatOp, lastOp);
              lastOp = concatOp;
            }
            (data as any).opSetOutput(lastOp, oldOut);
          }
        }
      }
    }
    this.clearActiveOutput();
  }

  private collectOutputTrialVarnodes(trialvn: Varnode[]): void {
    if ((this.op as any).getOut() !== null)
      throw new LowlevelError('Output of call was determined prematurely');
    while (trialvn.length < this.activeoutput.getNumTrials())
      trialvn.push(null as any);
    let indop = (this.op as any).previousOp();
    while (indop !== null) {
      if ((indop as any).code() !== OpCode.CPUI_INDIRECT) break;
      if ((indop as any).isIndirectCreation()) {
        const vn = (indop as any).getOut();
        const index = this.activeoutput.whichTrial((vn as any).getAddr(), (vn as any).getSize());
        if (index >= 0) {
          trialvn[index] = vn;
          this.activeoutput.getTrial(index).setAddress((vn as any).getAddr(), (vn as any).getSize());
        }
      }
      indop = (indop as any).previousOp();
    }
  }

  private setStackPlaceholderSlot(slot: number): void {
    this.stackPlaceholderSlot = slot;
    if (this.isinputactive) this.activeinput.setPlaceholderSlot();
  }

  private clearStackPlaceholderSlot(): void {
    this.stackPlaceholderSlot = -1;
    if (this.isinputactive) this.activeinput.freePlaceholderSlot();
  }

  // --- Public API ---

  setAddress(addr: any): void { this.entryaddress = addr; }
  getOp(): PcodeOp { return this.op; }
  getFuncdata(): Funcdata | null { return this.fd; }

  setFuncdata(f: Funcdata): void {
    if (this.fd !== null)
      throw new LowlevelError('Setting call spec function multiple times');
    this.fd = f;
    if (this.fd !== null) {
      this.entryaddress = (this.fd as any).getAddress();
      if ((this.fd as any).getDisplayName().length !== 0)
        this.name = (this.fd as any).getDisplayName();
    }
  }

  cloneOp(newop: PcodeOp): FuncCallSpecs {
    const res = new FuncCallSpecs(newop);
    res.setFuncdata(this.fd!);
    res.effective_extrapop = this.effective_extrapop;
    res.stackoffset = this.stackoffset;
    res.paramshift = this.paramshift;
    res.isbadjumptable = this.isbadjumptable;
    res.copy(this);
    return res;
  }

  getName(): string { return this.name; }
  getEntryAddress(): any { return this.entryaddress; }
  setEffectiveExtraPop(epop: number): void { this.effective_extrapop = epop; }
  getEffectiveExtraPop(): number { return this.effective_extrapop; }
  getSpacebaseOffset(): bigint { return this.stackoffset; }
  setParamshift(val: number): void { this.paramshift = val; }
  getParamshift(): number { return this.paramshift; }
  getMatchCallCount(): number { return this.matchCallCount; }
  getStackPlaceholderSlot(): number { return this.stackPlaceholderSlot; }

  initActiveInput(): void {
    this.isinputactive = true;
    let maxdelay = this.getMaxInputDelay();
    if (maxdelay > 0) maxdelay = 3;
    this.activeinput.setMaxPass(maxdelay);
  }

  clearActiveInput(): void { this.isinputactive = false; }
  initActiveOutput(): void { this.isoutputactive = true; }
  clearActiveOutput(): void { this.isoutputactive = false; }
  isInputActive(): boolean { return this.isinputactive; }
  isOutputActive(): boolean { return this.isoutputactive; }
  setBadJumpTable(val: boolean): void { this.isbadjumptable = val; }
  isBadJumpTable(): boolean { return this.isbadjumptable; }
  setStackOutputLock(val: boolean): void { this.isstackoutputlock = val; }
  isStackOutputLock(): boolean { return this.isstackoutputlock; }
  getActiveInput(): ParamActive { return this.activeinput; }
  getActiveOutput(): ParamActive { return this.activeoutput; }

  checkInputJoinCall(slot1: number, ishislot: boolean, vn1: Varnode, vn2: Varnode): boolean {
    if (this.isInputActive()) return false;
    if (slot1 >= this.activeinput.getNumTrials()) return false;
    let hislot: ParamTrial, loslot: ParamTrial;
    if (ishislot) {
      hislot = this.activeinput.getTrialForInputVarnode(slot1);
      loslot = this.activeinput.getTrialForInputVarnode(slot1 + 1);
      if (hislot.getSize() !== (vn1 as any).getSize()) return false;
      if (loslot.getSize() !== (vn2 as any).getSize()) return false;
    } else {
      loslot = this.activeinput.getTrialForInputVarnode(slot1);
      hislot = this.activeinput.getTrialForInputVarnode(slot1 + 1);
      if (loslot.getSize() !== (vn1 as any).getSize()) return false;
      if (hislot.getSize() !== (vn2 as any).getSize()) return false;
    }
    return super.checkInputJoin(hislot.getAddress(), hislot.getSize(), loslot.getAddress(), loslot.getSize());
  }

  doInputJoin(slot1: number, ishislot: boolean): void {
    if (this.isInputLocked())
      throw new LowlevelError('Trying to join parameters on locked function prototype');

    const trial1 = this.activeinput.getTrialForInputVarnode(slot1);
    const trial2 = this.activeinput.getTrialForInputVarnode(slot1 + 1);

    const addr1 = trial1.getAddress();
    const addr2 = trial2.getAddress();
    const glb = this.getArch();
    let joinaddr: any;
    if (ishislot)
      joinaddr = (glb as any).constructJoinAddress((glb as any).translate, addr1, trial1.getSize(), addr2, trial2.getSize());
    else
      joinaddr = (glb as any).constructJoinAddress((glb as any).translate, addr2, trial2.getSize(), addr1, trial1.getSize());

    this.activeinput.joinTrial(slot1, joinaddr, trial1.getSize() + trial2.getSize());
  }

  lateRestriction(restrictedProto: FuncProto, newinput: Varnode[], newoutput: Varnode[]): boolean {
    if (!this.hasModel()) {
      this.copy(restrictedProto);
      return true;
    }
    if (!this.isCompatible(restrictedProto)) return false;
    if (restrictedProto.isDotdotdot() && !this.isinputactive) return false;

    if (restrictedProto.isInputLocked()) {
      if (!this.transferLockedInput(newinput, restrictedProto))
        return false;
    }
    if (restrictedProto.isOutputLocked()) {
      if (!this.transferLockedOutput(newoutput, restrictedProto))
        return false;
    }
    this.copy(restrictedProto);
    return true;
  }

  deindirect(data: Funcdata, newfd: Funcdata): void {
    this.entryaddress = (newfd as any).getAddress();
    this.name = (newfd as any).getDisplayName();
    this.fd = newfd;

    const vn = (data as any).newVarnodeCallSpecs(this);
    (data as any).opSetInput(this.op, vn, 0);
    (data as any).opSetOpcode(this.op, OpCode.CPUI_CALL);

    (data as any).getOverride().insertIndirectOverride((this.op as any).getAddr(), this.entryaddress);

    const newinput: Varnode[] = [];
    const newoutput: Varnode[] = [];
    const newproto: FuncProto = (newfd as any).getFuncProto();
    if (!newproto.isNoReturn() && !newproto.isInline()) {
      if (this.isOverride()) return;
      if (this.lateRestriction(newproto, newinput, newoutput)) {
        this.commitNewInputs(data, newinput);
        this.commitNewOutputs(data, newoutput);
        return;
      }
    }
    (data as any).setRestartPending(true);
  }

  forceSet(data: Funcdata, fp: FuncProto): void {
    const newinput: Varnode[] = [];
    const newoutput: Varnode[] = [];

    const newproto = new FuncProto();
    newproto.copy(fp);
    (data as any).getOverride().insertProtoOverride((this.op as any).getAddr(), newproto);
    if (this.lateRestriction(fp, newinput, newoutput)) {
      this.commitNewInputs(data, newinput);
      this.commitNewOutputs(data, newoutput);
    } else {
      (data as any).setRestartPending(true);
    }
    this.setInputLock(true);
    this.setInputErrors(fp.hasInputErrors());
    this.setOutputErrors(fp.hasOutputErrors());
  }

  insertPcode(data: Funcdata): void {
    const id = this.getInjectUponReturn();
    if (id < 0) return;
    const payload = (data as any).getArch().pcodeinjectlib.getPayload(id);
    const iter = (this.op as any).getBasicIter();
    // Advance iterator past the call
    (data as any).doLiveInject(payload, (this.op as any).getAddr(), (this.op as any).getParent(), iter);
  }

  createPlaceholder(data: Funcdata, spacebase: AddrSpace): void {
    const slot = (this.op as any).numInput();
    const loadval = (data as any).opStackLoad(spacebase, 0n, 1, this.op, null, false);
    (data as any).opInsertInput(this.op, loadval, slot);
    this.setStackPlaceholderSlot(slot);
    (loadval as any).setSpacebasePlaceholder();
  }

  resolveSpacebaseRelative(data: Funcdata, phvn: Varnode): void {
    const refvn = (phvn as any).getDef().getIn(0);
    const spacebase = (refvn as any).getSpace();
    if (spacebase.getType() !== spacetype.IPTR_SPACEBASE)
      (data as any).warningHeader('This function may have set the stack pointer');
    this.stackoffset = (refvn as any).getOffset();

    if (this.stackPlaceholderSlot >= 0) {
      if ((this.op as any).getIn(this.stackPlaceholderSlot) === phvn) {
        this.abortSpacebaseRelative(data);
        return;
      }
    }

    if (this.isInputLocked()) {
      const slot = (this.op as any).getSlot(phvn) - 1;
      if (slot >= this.numParams())
        throw new LowlevelError('Stack placeholder does not line up with locked parameter');
      const param = this.getParam(slot)!;
      const addr = param.getAddress();
      if (addr.getSpace() !== spacebase) {
        if (spacebase.getType() === spacetype.IPTR_SPACEBASE)
          throw new LowlevelError('Stack placeholder does not match locked space');
      }
      this.stackoffset -= BigInt(addr.getOffset());
      this.stackoffset = BigInt(spacebase.wrapOffset(this.stackoffset));
      return;
    }
    throw new LowlevelError('Unresolved stack placeholder');
  }

  abortSpacebaseRelative(data: Funcdata): void {
    if (this.stackPlaceholderSlot >= 0) {
      const vn = (this.op as any).getIn(this.stackPlaceholderSlot);
      (data as any).opRemoveInput(this.op, this.stackPlaceholderSlot);
      this.clearStackPlaceholderSlot();
      if ((vn as any).hasNoDescend() &&
          (vn as any).getSpace().getType() === spacetype.IPTR_INTERNAL &&
          (vn as any).isWritten())
        (data as any).opDestroy((vn as any).getDef());
    }
  }

  finalInputCheck(): void {
    if (_AncestorRealisticCtor === null) return;
    const ancestorReal = new _AncestorRealisticCtor();
    for (let i = 0; i < this.activeinput.getNumTrials(); ++i) {
      const trial = this.activeinput.getTrial(i);
      if (!trial.isActive()) continue;
      if (!trial.hasCondExeEffect()) continue;
      const slot = trial.getSlot();
      if (!ancestorReal.execute(this.op, slot, trial, false))
        trial.markNoUse();
    }
  }

  checkInputTrialUse(data: Funcdata, aliascheck: AliasChecker): void {
    if ((this.op as any).isDead())
      throw new LowlevelError('Function call in dead code');

    const maxancestor = (data as any).getArch().trim_recurse_max;
    let callee_pop = false;
    let expop = 0;
    if (this.hasModel()) {
      callee_pop = (this.getModelExtraPop() === ProtoModel.extrapop_unknown);
      if (callee_pop) {
        expop = this.getExtraPop();
        if (expop === ProtoModel.extrapop_unknown || expop <= 4)
          callee_pop = false;
      }
    }

    const ancestorReal = _AncestorRealisticCtor ? new _AncestorRealisticCtor() : null;
    for (let i = 0; i < this.activeinput.getNumTrials(); ++i) {
      const trial = this.activeinput.getTrial(i);
      if (trial.isChecked()) continue;
      const slot = trial.getSlot();
      const vn = (this.op as any).getIn(slot);
      if ((vn as any).getSpace().getType() === spacetype.IPTR_SPACEBASE) {
        if ((aliascheck as any).hasLocalAlias(vn))
          trial.markNoUse();
        else if (!(data as any).getFuncProto().getLocalRange().inRange((vn as any).getAddr(), 1))
          trial.markNoUse();
        else if (callee_pop) {
          if (Number(trial.getAddress().getOffset()) + (trial.getSize() - 1) < expop)
            trial.markActive();
          else
            trial.markNoUse();
        }
        else if (ancestorReal !== null && ancestorReal.execute(this.op, slot, trial, false)) {
          if ((data as any).ancestorOpUse(maxancestor, vn, this.op, trial, 0, 0))
            trial.markActive();
          else
            trial.markInactive();
        }
        else {
          trial.markNoUse();
        }
      } else {
        // Non-stack parameter trial check
        if (ancestorReal !== null && ancestorReal.execute(this.op, slot, trial, true)) {
          if ((data as any).ancestorOpUse(maxancestor, vn, this.op, trial, 0, 0)) {
            trial.markActive();
            if (trial.hasCondExeEffect())
              this.activeinput.markNeedsFinalCheck();
          }
          else
            trial.markInactive();
        }
        else if ((vn as any).isInput())
          trial.markInactive();
        else
          trial.markNoUse();
      }
      if (trial.isDefinitelyNotUsed())
        (data as any).opSetInput(this.op, (data as any).newConstant((vn as any).getSize(), 0n), slot);
    }
  }

  checkOutputTrialUse(data: Funcdata, trialvn: Varnode[]): void {
    this.collectOutputTrialVarnodes(trialvn);
    for (let i = 0; i < trialvn.length; ++i) {
      const curtrial = this.activeoutput.getTrial(i);
      if (curtrial.isChecked())
        throw new LowlevelError('Output trial has been checked prematurely');
      if (trialvn[i] !== null)
        curtrial.markActive();
      else
        curtrial.markInactive();
    }
  }

  buildInputFromTrials(data: Funcdata): void {
    const newparam: Varnode[] = [];
    newparam.push((this.op as any).getIn(0));

    if (this.isDotdotdot() && this.isInputLocked())
      this.activeinput.sortFixedPosition();

    for (let i = 0; i < this.activeinput.getNumTrials(); ++i) {
      const paramtrial = this.activeinput.getTrial(i);
      if (!paramtrial.isUsed()) continue;
      const sz = paramtrial.getSize();
      let isspacebase = false;
      const addr = paramtrial.getAddress();
      const spc = addr.getSpace()!;
      let off: bigint = addr.getOffset();
      if (spc.getType() === spacetype.IPTR_SPACEBASE) {
        isspacebase = true;
        off = BigInt(spc.wrapOffset(this.stackoffset + off));
      }
      let vn: Varnode;
      if (paramtrial.isUnref()) {
        vn = (data as any).newVarnode(sz, new Address(spc, off));
      } else {
        vn = (this.op as any).getIn(paramtrial.getSlot());
        if ((vn as any).getSize() > sz) {
          const newop = (data as any).newOp(2, (this.op as any).getAddr());
          let outvn: Varnode;
          if ((data as any).getArch().translate?.isBigEndian() ?? false)
            outvn = (data as any).newVarnodeOut(sz, (vn as any).getAddr().add(BigInt((vn as any).getSize() - sz)), newop);
          else
            outvn = (data as any).newVarnodeOut(sz, (vn as any).getAddr(), newop);
          (data as any).opSetOpcode(newop, OpCode.CPUI_SUBPIECE);
          (data as any).opSetInput(newop, vn, 0);
          (data as any).opSetInput(newop, (data as any).newConstant(1, 0n), 1);
          (data as any).opInsertBefore(newop, this.op);
          vn = outvn;
        }
      }
      newparam.push(vn);
      if (isspacebase)
        (data as any).getScopeLocal().markNotMapped(spc, off, sz, true);
    }
    (data as any).opSetAllInput(this.op, newparam);
    this.activeinput.deleteUnusedTrials();
  }

  static findPreexistingWhole(vn1: Varnode, vn2: Varnode): Varnode | null {
    const op1 = (vn1 as any).loneDescend();
    if (op1 === null) return null;
    const op2 = (vn2 as any).loneDescend();
    if (op2 === null) return null;
    if (op1 !== op2) return null;
    if ((op1 as any).code() !== OpCode.CPUI_PIECE) return null;
    return (op1 as any).getOut();
  }

  buildOutputFromTrials(data: Funcdata, trialvn: Varnode[]): void {
    let finaloutvn: Varnode;
    const finalvn: Varnode[] = [];

    for (let i = 0; i < this.activeoutput.getNumTrials(); ++i) {
      const curtrial = this.activeoutput.getTrial(i);
      if (!curtrial.isUsed()) break;
      const vn = trialvn[curtrial.getSlot() - 1];
      finalvn.push(vn);
    }
    this.activeoutput.deleteUnusedTrials();
    if (this.activeoutput.getNumTrials() === 0) return;

    const deletedops: PcodeOp[] = [];

    if (this.activeoutput.getNumTrials() === 1) {
      finaloutvn = finalvn[0];
      const indop = (finaloutvn as any).getDef();
      deletedops.push(indop);
      (data as any).opSetOutput(this.op, finaloutvn);
    }
    else if (this.activeoutput.getNumTrials() === 2) {
      let hivn: Varnode, lovn: Varnode;
      if (this.activeoutput.isJoinReverse()) {
        hivn = finalvn[0];
        lovn = finalvn[1];
      } else {
        hivn = finalvn[1];
        lovn = finalvn[0];
      }
      if ((data as any).isDoublePrecisOn()) {
        (lovn as any).setPrecisLo();
        (hivn as any).setPrecisHi();
      }
      deletedops.push((hivn as any).getDef());
      deletedops.push((lovn as any).getDef());
      finaloutvn = FuncCallSpecs.findPreexistingWhole(hivn, lovn);
      if (finaloutvn === null) {
        const joinaddr = (data as any).getArch().constructJoinAddress(
          (data as any).getArch().translate,
          (hivn as any).getAddr(), (hivn as any).getSize(),
          (lovn as any).getAddr(), (lovn as any).getSize());
        finaloutvn = (data as any).newVarnode((hivn as any).getSize() + (lovn as any).getSize(), joinaddr);
        (data as any).opSetOutput(this.op, finaloutvn);
        const sublo = (data as any).newOp(2, (this.op as any).getAddr());
        (data as any).opSetOpcode(sublo, OpCode.CPUI_SUBPIECE);
        (data as any).opSetInput(sublo, finaloutvn, 0);
        (data as any).opSetInput(sublo, (data as any).newConstant(4, 0n), 1);
        (data as any).opSetOutput(sublo, lovn);
        (data as any).opInsertAfter(sublo, this.op);
        const subhi = (data as any).newOp(2, (this.op as any).getAddr());
        (data as any).opSetOpcode(subhi, OpCode.CPUI_SUBPIECE);
        (data as any).opSetInput(subhi, finaloutvn, 0);
        (data as any).opSetInput(subhi, (data as any).newConstant(4, BigInt((lovn as any).getSize())), 1);
        (data as any).opSetOutput(subhi, hivn);
        (data as any).opInsertAfter(subhi, this.op);
      } else {
        deletedops.push((finaloutvn as any).getDef());
        (data as any).opSetOutput(this.op, finaloutvn);
      }
    }
    else {
      return;
    }

    for (const dop of deletedops) {
      const in0 = (dop as any).getIn(0);
      const in1 = (dop as any).getIn(1);
      (data as any).opDestroy(dop);
      if (in0 !== null)
        (data as any).deleteVarnode(in0);
      if (in1 !== null)
        (data as any).deleteVarnode(in1);
    }
  }

  getInputBytesConsumed(slot: number): number {
    if (slot >= this.inputConsume.length) return 0;
    return this.inputConsume[slot];
  }

  setInputBytesConsumed(slot: number, val: number): boolean {
    while (this.inputConsume.length <= slot)
      this.inputConsume.push(0);
    const oldVal = this.inputConsume[slot];
    if (oldVal === 0 || val < oldVal) {
      this.inputConsume[slot] = val;
      return true;
    }
    return false;
  }

  paramshiftModifyStart(): void {
    if (this.paramshift === 0) return;
    this.paramShift(this.paramshift);
  }

  paramshiftModifyStop(data: Funcdata): boolean {
    if (this.paramshift === 0) return false;
    if (this.isParamshiftApplied()) return false;
    this.setParamshiftApplied(true);
    if ((this.op as any).numInput() < this.paramshift + 1)
      throw new LowlevelError('Paramshift mechanism is confused');
    for (let i = 0; i < this.paramshift; ++i) {
      (data as any).opRemoveInput(this.op, 1);
      this.removeParam(0);
    }
    return true;
  }

  hasEffectTranslate(addr: any, size: number): number {
    const spc = addr.getSpace();
    if (spc.getType() !== spacetype.IPTR_SPACEBASE)
      return this.hasEffect(addr, size);
    if (this.stackoffset === BigInt(FuncCallSpecs.offset_unknown))
      return EffectRecord.unknown_effect;
    const newoff = BigInt(spc.wrapOffset(addr.getOffset() - this.stackoffset));
    return this.hasEffect(new Address(spc, newoff), size);
  }

  static getFspecFromConst(addr: any): FuncCallSpecs {
    const id = Number(addr.getOffset());
    const fc = FuncCallSpecs._registry.get(id);
    if (fc === undefined) throw new LowlevelError('Bad fspec reference: ' + id);
    return fc;
  }

  static compareByEntryAddress(a: FuncCallSpecs, b: FuncCallSpecs): number {
    if (a.entryaddress.lessThan(b.entryaddress)) return -1;
    if (b.entryaddress.lessThan(a.entryaddress)) return 1;
    return 0;
  }

  static countMatchingCalls(qlst: FuncCallSpecs[]): void {
    const copyList = qlst.slice();
    copyList.sort(FuncCallSpecs.compareByEntryAddress);
    let i: number;
    for (i = 0; i < copyList.length; ++i) {
      if (!copyList[i].entryaddress.isInvalid()) break;
      copyList[i].matchCallCount = 1;
    }
    if (i === copyList.length) return;
    let lastAddr = copyList[i].entryaddress;
    let lastChange = i;
    i++;
    let num: number;
    for (; i < copyList.length; ++i) {
      if (copyList[i].entryaddress.equals(lastAddr)) continue;
      num = i - lastChange;
      for (; lastChange < i; ++lastChange)
        copyList[lastChange].matchCallCount = num;
      lastAddr = copyList[i].entryaddress;
    }
    num = i - lastChange;
    for (; lastChange < i; ++lastChange)
      copyList[lastChange].matchCallCount = num;
  }
}
