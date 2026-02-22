/**
 * @file varnode.ts
 * @description The Varnode and VarnodeBank classes, translated from Ghidra's varnode.hh / varnode.cc
 *
 * A Varnode is the fundamental variable in the p-code language model. A Varnode
 * represents anything that holds data, including registers, stack locations,
 * global RAM locations, and constants. It is described by an Address and a size.
 *
 * VarnodeBank is a container for Varnode objects from a specific function,
 * maintaining dual sorted sets for efficient lookup by location and definition.
 */

import type { int4, uint4, uintb, uintm, int2, uint2 } from '../core/types.js';
import { LowlevelError } from '../core/error.js';
import { Address, MachExtreme, SeqNum, calc_mask, sign_extend, signbit_negative } from '../core/address.js';
import { AddrSpace, spacetype } from '../core/space.js';
import { _globalSpaceRegistry } from '../core/translate.js';
import { OpCode } from '../core/opcodes.js';
import { SortedSet, type SortedSetIterator } from '../util/sorted-set.js';
import type { Writer } from '../util/writer.js';
import { Cover } from './cover.js';
import {
  AttributeId,
  ElementId,
  Encoder,
  ATTRIB_REF,
  ATTRIB_TYPELOCK,
} from '../core/marshal.js';

// ---------------------------------------------------------------------------
// Forward type declarations
// ---------------------------------------------------------------------------

type PcodeOp = any;
type HighVariable = any;
type Funcdata = any;
type SymbolEntry = any;
type ValueSet = any;
type Merge = any;
type CloneBlockOps = any;
type EquateSymbol = any;
type Symbol = any;
type Datatype = any;
type AddrSpaceManager = any;
type Translate = any;

// ---------------------------------------------------------------------------
// Attribute and Element IDs defined in varnode.cc
// ---------------------------------------------------------------------------

export const ATTRIB_ADDRTIED = new AttributeId("addrtied", 30);
export const ATTRIB_GRP = new AttributeId("grp", 31);
export const ATTRIB_INPUT = new AttributeId("input", 32);
export const ATTRIB_PERSISTS = new AttributeId("persists", 33);
export const ATTRIB_UNAFF = new AttributeId("unaff", 34);

/** ATTRIB_VOLATILE is defined in database.cc with id 65 */
export const ATTRIB_VOLATILE = new AttributeId("volatile", 65);

/** ELEM_ADDR is defined in address.cc with id 11 */
export const ELEM_ADDR = new ElementId("addr", 11);

// ---------------------------------------------------------------------------
// Varnode flag enums (exported as plain numeric constants)
// ---------------------------------------------------------------------------

// varnode_flags
export const VN_MARK                = 0x01;
export const VN_CONSTANT            = 0x02;
export const VN_ANNOTATION          = 0x04;
export const VN_INPUT               = 0x08;
export const VN_WRITTEN             = 0x10;
export const VN_INSERT              = 0x20;
export const VN_IMPLIED             = 0x40;
export const VN_EXPLICIT            = 0x80;
export const VN_TYPELOCK            = 0x100;
export const VN_NAMELOCK            = 0x200;
export const VN_NOLOCALALIAS        = 0x400;
export const VN_VOLATIL             = 0x800;
export const VN_EXTERNREF           = 0x1000;
export const VN_READONLY            = 0x2000;
export const VN_PERSIST             = 0x4000;
export const VN_ADDRTIED            = 0x8000;
export const VN_UNAFFECTED          = 0x10000;
export const VN_SPACEBASE           = 0x20000;
export const VN_INDIRECTONLY        = 0x40000;
export const VN_DIRECTWRITE         = 0x80000;
export const VN_ADDRFORCE           = 0x100000;
export const VN_MAPPED              = 0x200000;
export const VN_INDIRECT_CREATION   = 0x400000;
export const VN_RETURN_ADDRESS      = 0x800000;
export const VN_COVERDIRTY          = 0x1000000;
export const VN_PRECISLO            = 0x2000000;
export const VN_PRECISHI            = 0x4000000;
export const VN_INDIRECTSTORAGE     = 0x8000000;
export const VN_HIDDENRETPARM       = 0x10000000;
export const VN_INCIDENTAL_COPY     = 0x20000000;
export const VN_AUTOLIVE_HOLD       = 0x40000000;
export const VN_PROTO_PARTIAL       = 0x80000000;

// addl_flags
export const VN_ACTIVEHERITAGE          = 0x01;
export const VN_WRITEMASK               = 0x02;
export const VN_VACCONSUME              = 0x04;
export const VN_LISCONSUME              = 0x08;
export const VN_PTRCHECK               = 0x10;
export const VN_PTRFLOW                = 0x20;
export const VN_UNSIGNEDPRINT           = 0x40;
export const VN_LONGPRINT              = 0x80;
export const VN_STACK_STORE            = 0x100;
export const VN_LOCKED_INPUT           = 0x200;
export const VN_SPACEBASE_PLACEHOLDER  = 0x400;
export const VN_STOP_UPPROPAGATION     = 0x800;
export const VN_HAS_IMPLIED_FIELD      = 0x1000;

// ---------------------------------------------------------------------------
// Varnode class
// ---------------------------------------------------------------------------

/**
 * A low-level variable or contiguous set of bytes described by an Address and a size.
 *
 * A Varnode is the fundamental variable in the p-code language model. A Varnode
 * represents anything that holds data, including registers, stack locations,
 * global RAM locations, and constants.
 */
export class Varnode {
  // Static flag aliases (mirrors C++ Varnode::mark, Varnode::constant, etc.)
  static readonly mark              = VN_MARK;
  static readonly constant          = VN_CONSTANT;
  static readonly annotation        = VN_ANNOTATION;
  static readonly input             = VN_INPUT;
  static readonly written           = VN_WRITTEN;
  static readonly insert            = VN_INSERT;
  static readonly implied           = VN_IMPLIED;
  static readonly explict           = VN_EXPLICIT;
  static readonly typelock          = VN_TYPELOCK;
  static readonly namelock          = VN_NAMELOCK;
  static readonly nolocalalias      = VN_NOLOCALALIAS;
  static readonly volatil           = VN_VOLATIL;
  static readonly externref         = VN_EXTERNREF;
  static readonly readonly          = VN_READONLY;
  static readonly persist           = VN_PERSIST;
  static readonly addrtied          = VN_ADDRTIED;
  static readonly unaffected        = VN_UNAFFECTED;
  static readonly spacebase         = VN_SPACEBASE;
  static readonly indirectonly      = VN_INDIRECTONLY;
  static readonly directwrite       = VN_DIRECTWRITE;
  static readonly addrforce         = VN_ADDRFORCE;
  static readonly mapped            = VN_MAPPED;
  static readonly indirect_creation = VN_INDIRECT_CREATION;
  static readonly return_address    = VN_RETURN_ADDRESS;
  static readonly coverdirty        = VN_COVERDIRTY;
  static readonly precislo          = VN_PRECISLO;
  static readonly precishi          = VN_PRECISHI;
  static readonly indirectstorage   = VN_INDIRECTSTORAGE;
  static readonly hiddenretparm     = VN_HIDDENRETPARM;
  static readonly incidental_copy   = VN_INCIDENTAL_COPY;
  static readonly autolive_hold     = VN_AUTOLIVE_HOLD;
  static readonly proto_partial     = VN_PROTO_PARTIAL;

  // addl_flags aliases
  static readonly activeheritage          = VN_ACTIVEHERITAGE;
  static readonly writemask               = VN_WRITEMASK;
  static readonly vacconsume              = VN_VACCONSUME;
  static readonly lisconsume              = VN_LISCONSUME;
  static readonly ptrcheck               = VN_PTRCHECK;
  static readonly ptrflow                = VN_PTRFLOW;
  static readonly unsignedprint           = VN_UNSIGNEDPRINT;
  static readonly longprint               = VN_LONGPRINT;
  static readonly stack_store             = VN_STACK_STORE;
  static readonly locked_input            = VN_LOCKED_INPUT;
  static readonly spacebase_placeholder   = VN_SPACEBASE_PLACEHOLDER;
  static readonly stop_uppropagation      = VN_STOP_UPPROPAGATION;
  static readonly has_implied_field       = VN_HAS_IMPLIED_FIELD;

  // ---- Private fields ----
  /** @internal */ public flags: number;
  /** @internal */ public size: number;
  /** @internal */ public create_index: number;
  /** @internal */ public mergegroup: number;
  /** @internal */ public addlflags: number;
  /** @internal */ public loc: Address;

  // Heritage fields
  /** @internal */ public def: PcodeOp | null;
  /** @internal */ public high: HighVariable | null;
  /** @internal */ public mapentry: SymbolEntry | null;
  /** @internal */ public type: Datatype | null;
  /** @internal */ public lociter: SortedSetIterator<Varnode> | null;
  /** @internal */ public defiter: SortedSetIterator<Varnode> | null;
  /** @internal */ public descend: PcodeOp[];
  /** @internal */ public cover: Cover | null;

  /** @internal Temporary data-type or ValueSet */
  public temp: { dataType: Datatype | null; valueSet: ValueSet | null };

  /** @internal Consumed bits mask */
  public consumed: bigint;
  /** @internal Known zero bits mask */
  public nzm: bigint;

  /**
   * Construct a free Varnode with possibly a Datatype attribute.
   * @param s is the size of the new Varnode
   * @param m is the starting storage Address
   * @param dt is the Datatype
   */
  constructor(s: number, m: Address, dt: Datatype | null) {
    this.loc = new Address(m);
    this.size = s;
    this.def = null;
    this.type = dt;
    // DEBUG: track unique varnodes created with TYPE_PARTIALUNION
    if (dt?.getMetatype() === 0 && m.getSpace()?.getName() === 'unique') {
      console.error(`[DBG ctor] UNIQUE created with PARTIALUNION: addr=${m.toString()} sz=${s}`);
      console.trace();
    }
    this.high = null;
    this.mapentry = null;
    this.consumed = 0xFFFFFFFFFFFFFFFFn;
    this.cover = null;
    this.mergegroup = 0;
    this.addlflags = 0;
    this.create_index = 0;
    this.lociter = null;
    this.defiter = null;
    this.descend = [];
    this.temp = { dataType: null, valueSet: null };
    this.nzm = 0xFFFFFFFFFFFFFFFFn;

    if (m.getSpace() === null) {
      this.flags = 0;
      return;
    }
    const tp: spacetype = m.getSpace()!.getType();
    if (tp === spacetype.IPTR_CONSTANT) {
      this.flags = Varnode.constant;
      this.nzm = m.getOffset();
    } else if (tp === spacetype.IPTR_FSPEC || tp === spacetype.IPTR_IOP) {
      this.flags = Varnode.annotation | Varnode.coverdirty;
      this.nzm = 0xFFFFFFFFFFFFFFFFn;
    } else {
      this.flags = Varnode.coverdirty;
      this.nzm = 0xFFFFFFFFFFFFFFFFn;
    }
  }

  // ---- Getters ----

  /** Get the storage Address */
  getAddr(): Address { return this.loc; }

  /** Get the AddrSpace storing this Varnode */
  getSpace(): AddrSpace | null { return this.loc.getSpace(); }

  /**
   * Get AddrSpace from this encoded constant Varnode.
   * In LOAD and STORE instructions, the particular address space being read/written
   * is encoded as a constant Varnode. The offset holds the space index.
   */
  getSpaceFromConst(): AddrSpace | null {
    // In C++, the offset stores a raw pointer to AddrSpace cast as uintp.
    // In TS, createConstFromSpace encodes the space index as the offset.
    // We look up the space from the global registry by index.
    const index = Number(this.loc.getOffset());
    return _globalSpaceRegistry.get(index) ?? null;
  }

  /** Get the offset (within its AddrSpace) where this is stored */
  getOffset(): bigint { return this.loc.getOffset(); }

  /** Get the number of bytes this Varnode stores */
  getSize(): number { return this.size; }

  /** Get the forced merge group of this Varnode */
  getMergeGroup(): number { return this.mergegroup; }

  /** Get the defining PcodeOp of this Varnode */
  getDef(): PcodeOp | null { return this.def; }

  /**
   * Check if this Varnode has a high-level variable assigned.
   */
  hasHigh(): boolean { return this.high !== null; }

  /**
   * Get the high-level variable associated with this Varnode.
   * Throws if not yet assigned.
   */
  getHigh(): HighVariable {
    if (this.high === null)
      throw new LowlevelError("Requesting non-existent high-level");
    return this.high;
  }

  /** Get symbol and scope information associated with this Varnode */
  getSymbolEntry(): SymbolEntry | null { return this.mapentry; }

  /** Get all the boolean attributes */
  getFlags(): number { return this.flags; }

  /** Get the Datatype associated with this Varnode */
  getType(): Datatype | null { return this.type; }

  /** Return the data-type of this when it is written to */
  getTypeDefFacing(): Datatype | null {
    if (this.type === null) return null;
    if (!this.type.needsResolution()) return this.type;
    return this.type.findResolve(this.def, -1);
  }

  /** Get the data-type of this when it is read by the given PcodeOp */
  getTypeReadFacing(op: PcodeOp): Datatype | null {
    if (this.type === null) return null;
    if (!this.type.needsResolution()) return this.type;
    return this.type.findResolve(op, op.getSlot(this));
  }

  /** Return the data-type of the HighVariable when this is written to */
  getHighTypeDefFacing(): Datatype | null {
    const ct = this.high.getType();
    if (!ct.needsResolution()) return ct;
    return ct.findResolve(this.def, -1);
  }

  /** Return data-type of the HighVariable when read by the given PcodeOp */
  getHighTypeReadFacing(op: PcodeOp): Datatype | null {
    const ct = this.high.getType();
    if (!ct.needsResolution()) return ct;
    return ct.findResolve(op, op.getSlot(this));
  }

  /** Set the temporary Datatype */
  setTempType(t: Datatype | null): void { this.temp.dataType = t; }

  /** Get the temporary Datatype (used during type propagation) */
  getTempType(): Datatype | null { return this.temp.dataType; }

  /** Set the temporary ValueSet record */
  setValueSet(v: ValueSet | null): void { this.temp.valueSet = v; }

  /** Get the temporary ValueSet record */
  getValueSet(): ValueSet | null { return this.temp.valueSet; }

  /** Get the creation index */
  getCreateIndex(): number { return this.create_index; }

  /** Get Varnode coverage information */
  getCover(): Cover | null {
    this.updateCover();
    return this.cover;
  }

  /** Get iterator to list of syntax tree descendants (reads) */
  beginDescend(): number { return 0; }

  /** Get the end index to list of descendants */
  endDescend(): number { return this.descend.length; }

  /** Get descendant at index i */
  getDescend(i: number): PcodeOp { return this.descend[i]; }

  /** Get array of all descendants (reads) of this varnode */
  getDescendants(): PcodeOp[] { return this.descend; }

  /** Get mask of consumed bits */
  getConsume(): bigint { return this.consumed; }

  /** Set the mask of consumed bits (used by dead-code algorithm) */
  setConsume(val: bigint): void { this.consumed = val; }

  /** Get marker used by dead-code algorithm */
  isConsumeList(): boolean { return (this.addlflags & Varnode.lisconsume) !== 0; }

  /** Get marker used by dead-code algorithm */
  isConsumeVacuous(): boolean { return (this.addlflags & Varnode.vacconsume) !== 0; }

  /** Set marker used by dead-code algorithm */
  setConsumeList(): void { this.addlflags |= Varnode.lisconsume; }

  /** Set marker used by dead-code algorithm */
  setConsumeVacuous(): void { this.addlflags |= Varnode.vacconsume; }

  /** Clear marker used by dead-code algorithm */
  clearConsumeList(): void { this.addlflags &= ~Varnode.lisconsume; }

  /** Clear marker used by dead-code algorithm */
  clearConsumeVacuous(): void { this.addlflags &= ~Varnode.vacconsume; }

  /**
   * Return unique reading PcodeOp, or null if there are zero or more than 1
   */
  loneDescend(): PcodeOp | null {
    if (this.descend.length === 0) return null;
    if (this.descend.length > 1) return null;
    return this.descend[0];
  }

  /**
   * Get Address when this Varnode first comes into scope.
   * @param fd is the Funcdata containing the tree
   * @return the first-use Address
   */
  getUsePoint(fd: Funcdata): Address {
    if (this.isWritten())
      return (this.def as PcodeOp).getAddr();
    return fd.getAddress().add(-1n);
  }

  /** Get the mask of bits within this that are known to be zero */
  getNZMask(): bigint { return this.nzm; }

  // ---- Boolean flag tests ----

  /** Is this an annotation? */
  isAnnotation(): boolean { return (this.flags & Varnode.annotation) !== 0; }

  /** Is this an implied variable? */
  isImplied(): boolean { return (this.flags & Varnode.implied) !== 0; }

  /** Is this an explicitly printed variable? */
  isExplicit(): boolean { return (this.flags & Varnode.explict) !== 0; }

  /** Is this a constant? */
  isConstant(): boolean { return (this.flags & Varnode.constant) !== 0; }

  /** Is this free, not in SSA form? */
  isFree(): boolean { return (this.flags & (Varnode.written | Varnode.input)) === 0; }

  /** Is this an SSA input node? */
  isInput(): boolean { return (this.flags & Varnode.input) !== 0; }

  /** Is this an abnormal input to the function? */
  isIllegalInput(): boolean { return (this.flags & (Varnode.input | Varnode.directwrite)) === Varnode.input; }

  /** Is this read only by INDIRECT operations? */
  isIndirectOnly(): boolean { return (this.flags & Varnode.indirectonly) !== 0; }

  /** Is this storage location mapped by the loader to an external location? */
  isExternalRef(): boolean { return (this.flags & Varnode.externref) !== 0; }

  /** Will this Varnode be replaced dynamically? */
  hasActionProperty(): boolean { return (this.flags & (Varnode.readonly | Varnode.volatil)) !== 0; }

  /** Is this a read-only storage location? */
  isReadOnly(): boolean { return (this.flags & Varnode.readonly) !== 0; }

  /** Is this a volatile storage location? */
  isVolatile(): boolean { return (this.flags & Varnode.volatil) !== 0; }

  /** Does this storage location persist beyond the end of the function? */
  isPersist(): boolean { return (this.flags & Varnode.persist) !== 0; }

  /** Is this value affected by a legitimate function input */
  isDirectWrite(): boolean { return (this.flags & Varnode.directwrite) !== 0; }

  /** Are all Varnodes at this storage location components of the same high-level variable? */
  isAddrTied(): boolean { return (this.flags & (Varnode.addrtied | Varnode.insert)) === (Varnode.addrtied | Varnode.insert); }

  /** Is this value forced into a particular storage location? */
  isAddrForce(): boolean { return (this.flags & Varnode.addrforce) !== 0; }

  /** Is this varnode exempt from dead-code removal? */
  isAutoLive(): boolean { return (this.flags & (Varnode.addrforce | Varnode.autolive_hold)) !== 0; }

  /** Is there a temporary hold on dead-code removal? */
  isAutoLiveHold(): boolean { return (this.flags & Varnode.autolive_hold) !== 0; }

  /** Is there or should be formal symbol information associated with this? */
  isMapped(): boolean { return (this.flags & Varnode.mapped) !== 0; }

  /** Is this a value that is supposed to be preserved across the function? */
  isUnaffected(): boolean { return (this.flags & Varnode.unaffected) !== 0; }

  /** Is this location used to store the base point for a virtual address space? */
  isSpacebase(): boolean { return (this.flags & Varnode.spacebase) !== 0; }

  /** Is this storage for a calls return address? */
  isReturnAddress(): boolean { return (this.flags & Varnode.return_address) !== 0; }

  /** Is this getting pieced together into a larger whole */
  isProtoPartial(): boolean { return (this.flags & Varnode.proto_partial) !== 0; }

  /** Has this been checked as a constant pointer to a mapped symbol? */
  isPtrCheck(): boolean { return (this.addlflags & Varnode.ptrcheck) !== 0; }

  /** Does this varnode flow to or from a known pointer */
  isPtrFlow(): boolean { return (this.addlflags & Varnode.ptrflow) !== 0; }

  /** Is this used specifically to track stackpointer values? */
  isSpacebasePlaceholder(): boolean { return (this.addlflags & Varnode.spacebase_placeholder) !== 0; }

  /** Are there (not) any local pointers that might affect this? */
  hasNoLocalAlias(): boolean { return (this.flags & Varnode.nolocalalias) !== 0; }

  /** Has this been visited by the current algorithm? */
  isMark(): boolean { return (this.flags & Varnode.mark) !== 0; }

  /** Is this currently being traced by the Heritage algorithm? */
  isActiveHeritage(): boolean { return (this.addlflags & Varnode.activeheritage) !== 0; }

  /** Was this originally produced by an explicit STORE */
  isStackStore(): boolean { return (this.addlflags & Varnode.stack_store) !== 0; }

  /** Is always an input, even if unused */
  isLockedInput(): boolean { return (this.addlflags & Varnode.locked_input) !== 0; }

  /** Is data-type propagation stopped */
  stopsUpPropagation(): boolean { return (this.addlflags & Varnode.stop_uppropagation) !== 0; }

  /** Does this have an implied field */
  hasImpliedField(): boolean { return (this.addlflags & Varnode.has_implied_field) !== 0; }

  /** Is this just a special placeholder representing INDIRECT creation? */
  isIndirectZero(): boolean {
    return (this.flags & (Varnode.indirect_creation | Varnode.constant)) === (Varnode.indirect_creation | Varnode.constant);
  }

  /** Is this Varnode created indirectly by a CALL operation? */
  isExtraOut(): boolean {
    return (this.flags & (Varnode.indirect_creation | Varnode.addrtied)) === Varnode.indirect_creation;
  }

  /** Is this the low portion of a double precision value? */
  isPrecisLo(): boolean { return (this.flags & Varnode.precislo) !== 0; }

  /** Is this the high portion of a double precision value? */
  isPrecisHi(): boolean { return (this.flags & Varnode.precishi) !== 0; }

  /** Does this varnode get copied as a side-effect */
  isIncidentalCopy(): boolean { return (this.flags & Varnode.incidental_copy) !== 0; }

  /** Is this (not) considered a true write location when calculating SSA form? */
  isWriteMask(): boolean { return (this.addlflags & Varnode.writemask) !== 0; }

  /** Must this be printed as unsigned */
  isUnsignedPrint(): boolean { return (this.addlflags & Varnode.unsignedprint) !== 0; }

  /** Must this be printed as a long token */
  isLongPrint(): boolean { return (this.addlflags & Varnode.longprint) !== 0; }

  /** Does this have a defining write operation? */
  isWritten(): boolean { return (this.flags & Varnode.written) !== 0; }

  /** Does this have Cover information? */
  hasCover(): boolean {
    return (this.flags & (Varnode.constant | Varnode.annotation | Varnode.insert)) === Varnode.insert;
  }

  /** Return true if nothing reads this Varnode */
  hasNoDescend(): boolean { return this.descend.length === 0; }

  /** Return true if this is a constant with the given value */
  constantMatch(val: bigint): boolean {
    if (!this.isConstant()) return false;
    return this.loc.getOffset() === val;
  }

  /** Is this linked into the SSA tree */
  isHeritageKnown(): boolean {
    return (this.flags & (Varnode.insert | Varnode.constant | Varnode.annotation)) !== 0;
  }

  /** Does this have a locked Datatype? */
  isTypeLock(): boolean { return (this.flags & Varnode.typelock) !== 0; }

  /** Does this have a locked name? */
  isNameLock(): boolean { return (this.flags & Varnode.namelock) !== 0; }

  // ---- Flag setters / clearers ----

  /** Mark this as currently being linked into the SSA tree */
  setActiveHeritage(): void { this.addlflags |= Varnode.activeheritage; }

  /** Mark this as not (actively) being linked into the SSA tree */
  clearActiveHeritage(): void { this.addlflags &= ~Varnode.activeheritage; }

  /** Mark this Varnode for breadcrumb algorithms */
  setMark(): void { this.flags |= Varnode.mark; }

  /** Clear the mark on this Varnode */
  clearMark(): void { this.flags &= ~Varnode.mark; }

  /** Mark this as directly affected by a legal input */
  setDirectWrite(): void { this.flags |= Varnode.directwrite; }

  /** Mark this as not directly affected by a legal input */
  clearDirectWrite(): void { this.flags &= ~Varnode.directwrite; }

  /** Mark as forcing a value into this particular storage location */
  setAddrForce(): void { this.setFlags(Varnode.addrforce); }

  /** Clear the forcing attribute */
  clearAddrForce(): void { this.clearFlags(Varnode.addrforce); }

  /** Mark this as an implied variable in the final C source */
  setImplied(): void { this.setFlags(Varnode.implied); }

  /** Clear the implied mark on this Varnode */
  clearImplied(): void { this.clearFlags(Varnode.implied); }

  /** Mark this as an explicit variable in the final C source */
  setExplicit(): void { this.setFlags(Varnode.explict); }

  /** Clear the explicit mark on this Varnode */
  clearExplicit(): void { this.clearFlags(Varnode.explict); }

  /** Mark as storage location for a return address */
  setReturnAddress(): void { this.flags |= Varnode.return_address; }

  /** Clear return address attribute */
  clearReturnAddress(): void { this.flags &= ~Varnode.return_address; }

  /** Set this as checked for a constant symbol reference */
  setPtrCheck(): void { this.addlflags |= Varnode.ptrcheck; }

  /** Clear the pointer check mark on this Varnode */
  clearPtrCheck(): void { this.addlflags &= ~Varnode.ptrcheck; }

  /** Set this as flowing to or from pointer */
  setPtrFlow(): void { this.addlflags |= Varnode.ptrflow; }

  /** Indicate that this varnode is not flowing to or from pointer */
  clearPtrFlow(): void { this.addlflags &= ~Varnode.ptrflow; }

  /** Mark this as a special Varnode for tracking stackpointer values */
  setSpacebasePlaceholder(): void { this.addlflags |= Varnode.spacebase_placeholder; }

  /** Clear the stackpointer tracking mark */
  clearSpacebasePlaceholder(): void { this.addlflags &= ~Varnode.spacebase_placeholder; }

  /** Mark this as the low portion of a double precision value */
  setPrecisLo(): void { this.setFlags(Varnode.precislo); }

  /** Clear the mark indicating a double precision portion */
  clearPrecisLo(): void { this.clearFlags(Varnode.precislo); }

  /** Mark this as the high portion of a double precision value */
  setPrecisHi(): void { this.setFlags(Varnode.precishi); }

  /** Clear the mark indicating a double precision portion */
  clearPrecisHi(): void { this.clearFlags(Varnode.precishi); }

  /** Mark this as not a true write when computing SSA form */
  setWriteMask(): void { this.addlflags |= Varnode.writemask; }

  /** Clear the mark indicating this is not a true write */
  clearWriteMask(): void { this.addlflags &= ~Varnode.writemask; }

  /** Place temporary hold on dead code removal */
  setAutoLiveHold(): void { this.flags |= Varnode.autolive_hold; }

  /** Clear temporary hold on dead code removal */
  clearAutoLiveHold(): void { this.flags &= ~Varnode.autolive_hold; }

  /** Mark this gets pieced into larger structure */
  setProtoPartial(): void { this.flags |= Varnode.proto_partial; }

  /** Clear mark indicating this gets pieced into larger structure */
  clearProtoPartial(): void { this.flags &= ~Varnode.proto_partial; }

  /** Force this to be printed as unsigned */
  setUnsignedPrint(): void { this.addlflags |= Varnode.unsignedprint; }

  /** Force this to be printed as a long token */
  setLongPrint(): void { this.addlflags |= Varnode.longprint; }

  /** Stop up-propagation thru this */
  setStopUpPropagation(): void { this.addlflags |= Varnode.stop_uppropagation; }

  /** Clear stop up-propagation thru this */
  clearStopUpPropagation(): void { this.addlflags &= ~Varnode.stop_uppropagation; }

  /** Mark this as having an implied field */
  setImpliedField(): void { this.addlflags |= Varnode.has_implied_field; }

  /** Mark as produced by explicit CPUI_STORE */
  setStackStore(): void { this.addlflags |= Varnode.stack_store; }

  /** Mark as existing input, even if unused */
  setLockedInput(): void { this.addlflags |= Varnode.locked_input; }

  /** Set the HighVariable owning this Varnode */
  setHigh(tv: HighVariable, mg: number): void {
    this.high = tv;
    this.mergegroup = mg;
  }

  /** @internal Mark Varnode as unaffected */
  setUnaffected(): void { this.setFlags(Varnode.unaffected); }

  /** @internal Mark Varnode as input */
  setInputFlag(): void { this.setFlags(Varnode.input | Varnode.coverdirty); }

  // ---- Internal methods (friend class access) ----

  /** @internal Set desired boolean attributes and update dirty bits */
  setFlags(fl: number): void {
    this.flags |= fl;
    if (this.high !== null) {
      this.high.flagsDirty();
      if ((fl & Varnode.coverdirty) !== 0)
        this.high.coverDirty();
    }
  }

  /** @internal Clear desired boolean attributes and update dirty bits */
  clearFlags(fl: number): void {
    this.flags &= ~fl;
    if (this.high !== null) {
      this.high.flagsDirty();
      if ((fl & Varnode.coverdirty) !== 0)
        this.high.coverDirty();
    }
  }

  /** @internal Clear any Symbol attached to this Varnode */
  clearSymbolLinks(): void {
    let foundEntry = false;
    for (let i = 0; i < this.high.numInstances(); ++i) {
      const vn: Varnode = this.high.getInstance(i);
      foundEntry = foundEntry || (vn.mapentry !== null);
      vn.mapentry = null;
      vn.clearFlags(Varnode.namelock | Varnode.typelock | Varnode.mapped);
    }
    if (foundEntry)
      this.high.symbolDirty();
  }

  /** @internal Directly change the defining PcodeOp and set appropriate dirty bits */
  setDef(op: PcodeOp | null): void {
    this.def = op;
    if (op === null) {
      this.setFlags(Varnode.coverdirty);
      this.clearFlags(Varnode.written);
    } else {
      this.setFlags(Varnode.coverdirty | Varnode.written);
    }
  }

  /**
   * @internal Set properties from the given Symbol to this Varnode.
   * @return true if any properties have changed
   */
  setSymbolProperties(entry: SymbolEntry): boolean {
    let res: boolean = entry.updateType(this);
    if (entry.getSymbol().isTypeLocked()) {
      if (this.mapentry !== entry) {
        this.mapentry = entry;
        if (this.high !== null)
          this.high.setSymbol(this);
        res = true;
      }
    }
    this.setFlags(entry.getAllFlags() & ~Varnode.typelock);
    return res;
  }

  /** @internal Attach a Symbol to this Varnode */
  setSymbolEntry(entry: SymbolEntry): void {
    this.mapentry = entry;
    let fl = Varnode.mapped;
    if (entry.getSymbol().isNameLocked())
      fl |= Varnode.namelock;
    this.setFlags(fl);
    if (this.high !== null)
      this.high.setSymbol(this);
  }

  /** @internal Attach a Symbol reference to this */
  setSymbolReference(entry: SymbolEntry, off: number): void {
    if (this.high !== null) {
      this.high.setSymbolReference(entry.getSymbol(), off);
    }
  }

  /** @internal Add a descendant (reading) PcodeOp to this Varnode's list */
  addDescend(op: PcodeOp): void {
    if (this.isFree() && (!this.isSpacebase())) {
      if (this.descend.length > 0)
        throw new LowlevelError("Free varnode has multiple descendants");
    }
    this.descend.push(op);
    this.setFlags(Varnode.coverdirty);
  }

  /** @internal Erase a descendant (reading) PcodeOp from this Varnode's list */
  eraseDescend(op: PcodeOp): void {
    const idx = this.descend.indexOf(op);
    if (idx >= 0) {
      this.descend.splice(idx, 1);
    }
    this.setFlags(Varnode.coverdirty);
  }

  /** @internal Clear all descendant (reading) PcodeOps */
  destroyDescend(): void {
    this.descend.length = 0;
  }

  /** @internal Rebuild variable cover based on where the Varnode is defined and read */
  updateCover(): void {
    if ((this.flags & Varnode.coverdirty) !== 0) {
      if (this.hasCover() && this.cover !== null)
        this.cover.rebuild(this);
      this.clearFlags(Varnode.coverdirty);
    }
  }

  /** @internal Delete the Cover object */
  clearCover(): void {
    this.cover = null;
  }

  /** @internal Initialize a new Cover and set dirty bit */
  calcCover(): void {
    if (this.hasCover()) {
      this.cover = new Cover();
      this.setFlags(Varnode.coverdirty);
    }
  }

  // ---- Set the Datatype ----

  /**
   * Set the Datatype if not locked.
   * @param ct is the Datatype to change to
   * @return true if the Datatype changed
   */
  updateType(ct: Datatype): boolean;
  /**
   * (Possibly) set the Datatype given various restrictions.
   * @param ct is the Datatype to change to
   * @param lock is true if the new Datatype should be locked
   * @param override is true if an old lock should be overridden
   * @return true if the Datatype or the lock setting was changed
   */
  updateType(ct: Datatype, lock: boolean, override: boolean): boolean;
  updateType(ct: Datatype, lock?: boolean, override?: boolean): boolean {
    if (lock === undefined) {
      // Single-arg version
      if (this.type === ct || this.isTypeLock()) return false;
      // DEBUG: track when unique varnodes get TYPE_PARTIALUNION
      if (ct.getMetatype() === 0 /* TYPE_PARTIALUNION */ && this.getAddr().getSpace()?.getName() === 'unique') {
        console.error(`[DBG vn.updateType] UNIQUE gets PARTIALUNION: addr=${this.getAddr().toString()} sz=${this.getSize()} old=${this.type?.getName()}(${this.type?.getMetatype()}) new=PARTIALUNION def=${this.isWritten() ? (this.def as any).getOpcode().getName() : 'N/A'}`);
        console.trace();
      }
      this.type = ct;
      if (this.high !== null)
        this.high.typeDirty();
      return true;
    }

    // Three-arg version
    if (ct.getMetatype() === 15 /* TYPE_UNKNOWN */)
      lock = false;

    if (this.isTypeLock() && (!override!)) return false;
    if ((this.type === ct) && (this.isTypeLock() === lock)) return false;
    // DEBUG: track when unique varnodes get TYPE_PARTIALUNION (3-arg)
    if (ct.getMetatype() === 0 /* TYPE_PARTIALUNION */ && this.getAddr().getSpace()?.getName() === 'unique') {
      console.error(`[DBG vn.updateType3] UNIQUE gets PARTIALUNION: addr=${this.getAddr().toString()} sz=${this.getSize()} lock=${lock} override=${override}`);
    }
    this.flags &= ~Varnode.typelock;
    if (lock)
      this.flags |= Varnode.typelock;
    this.type = ct;
    if (this.high !== null)
      this.high.typeDirty();
    return true;
  }

  /** Copy any symbol and type information from vn into this */
  copySymbol(vn: Varnode): void {
    // DEBUG: track when unique gets PARTIALUNION via copySymbol
    if (vn.type?.getMetatype() === 0 && this.getAddr().getSpace()?.getName() === 'unique') {
      console.error(`[DBG copySymbol] UNIQUE gets PARTIALUNION: addr=${this.getAddr().toString()} from=${vn.getAddr().toString()} vn.type=${vn.type?.getName()} vn.lock=${vn.isTypeLock()}`);
      console.trace();
    }
    this.type = vn.type;
    this.mapentry = vn.mapentry;
    this.flags &= ~(Varnode.typelock | Varnode.namelock);
    this.flags |= (Varnode.typelock | Varnode.namelock) & vn.flags;
    if (this.high !== null) {
      this.high.typeDirty();
      if (this.mapentry !== null)
        this.high.setSymbol(this);
    }
  }

  /** Copy symbol info from vn if constant value matches */
  copySymbolIfValid(vn: Varnode): void {
    const mapEntry = vn.getSymbolEntry();
    if (mapEntry === null) return;
    const sym: any = mapEntry.getSymbol();
    // dynamic_cast<EquateSymbol *> -- check if sym has isValueClose
    if (sym === null || typeof sym.isValueClose !== 'function') return;
    if (sym.isValueClose(this.loc.getOffset(), this.size)) {
      this.copySymbol(vn);
    }
  }

  // ---- Containment / overlap ----

  /**
   * Return info about the containment of op in this.
   *   -1 if op.loc starts before this
   *    0 if op is contained in this
   *    1 if op.start is contained in this
   *    2 if op.loc comes after this
   *    3 if op and this are in non-comparable spaces
   */
  contains(op: Varnode): number {
    if (this.loc.getSpace() !== op.loc.getSpace()) return 3;
    if (this.loc.getSpace()!.getType() === spacetype.IPTR_CONSTANT) return 3;
    const a = this.loc.getOffset();
    const b = op.loc.getOffset();
    if (b < a) return -1;
    if (b >= a + BigInt(this.size)) return 2;
    if (b + BigInt(op.size) > a + BigInt(this.size)) return 1;
    return 0;
  }

  /** Return true if the storage locations intersect */
  intersects(op: Varnode): boolean;
  /** Check intersection against an Address range */
  intersects(op2loc: Address, op2size: number): boolean;
  intersects(op: Varnode | Address, op2size?: number): boolean {
    if (op instanceof Varnode) {
      if (this.loc.getSpace() !== op.loc.getSpace()) return false;
      if (this.loc.getSpace()!.getType() === spacetype.IPTR_CONSTANT) return false;
      const a = this.loc.getOffset();
      const b = op.loc.getOffset();
      if (b < a) {
        if (a >= b + BigInt(op.size)) return false;
        return true;
      }
      if (b >= a + BigInt(this.size)) return false;
      return true;
    } else {
      const op2loc = op as Address;
      if (this.loc.getSpace() !== op2loc.getSpace()) return false;
      if (this.loc.getSpace()!.getType() === spacetype.IPTR_CONSTANT) return false;
      const a = this.loc.getOffset();
      const b = op2loc.getOffset();
      if (b < a) {
        if (a >= b + BigInt(op2size!)) return false;
        return true;
      }
      if (b >= a + BigInt(this.size)) return false;
      return true;
    }
  }

  /**
   * Return 0, 1, or 2 for "no overlap", "partial overlap", "identical storage"
   */
  characterizeOverlap(op: Varnode): number {
    if (this.loc.getSpace() !== op.loc.getSpace()) return 0;
    if (this.loc.getOffset() === op.loc.getOffset()) {
      return (this.size === op.size) ? 2 : 1;
    } else if (this.loc.getOffset() < op.loc.getOffset()) {
      const thisright = this.loc.getOffset() + BigInt(this.size - 1);
      return (thisright < op.loc.getOffset()) ? 0 : 1;
    } else {
      const opright = op.loc.getOffset() + BigInt(op.size - 1);
      return (opright < this.loc.getOffset()) ? 0 : 1;
    }
  }

  /**
   * Return relative point of overlap between two Varnodes.
   * This is the C++ Varnode::overlap(const Varnode &op) method.
   * Overloaded: also accepts (Address, number) to match C++ overlap(const Address &, int4).
   */
  overlap(op: Varnode): number;
  overlap(op2loc: Address, op2size: number): number;
  overlap(arg0: Varnode | Address, arg1?: number): number {
    if (arg0 instanceof Varnode) {
      return this.overlapVarnode(arg0);
    }
    return this.overlapAddr(arg0 as Address, arg1!);
  }

  /** Return relative point of overlap between two Varnodes */
  overlapVarnode(op: Varnode): number {
    if (!this.loc.isBigEndian()) {
      return this.loc.overlap(0, op.loc, op.size);
    } else {
      const over = this.loc.overlap(this.size - 1, op.loc, op.size);
      if (over !== -1)
        return op.size - 1 - over;
    }
    return -1;
  }

  /**
   * Return relative point of overlap, where the given Varnode may be in the join space.
   */
  overlapJoinVarnode(op: Varnode): number {
    if (!this.loc.isBigEndian()) {
      return this.loc.overlapJoin(0, op.loc, op.size);
    } else {
      const over = this.loc.overlapJoin(this.size - 1, op.loc, op.size);
      if (over !== -1)
        return op.size - 1 - over;
    }
    return -1;
  }

  /** Return relative point of overlap with Address range */
  overlapAddr(op2loc: Address, op2size: number): number {
    if (!this.loc.isBigEndian()) {
      return this.loc.overlap(0, op2loc, op2size);
    } else {
      const over = this.loc.overlap(this.size - 1, op2loc, op2size);
      if (over !== -1)
        return op2size - 1 - over;
    }
    return -1;
  }

  // ---- Print methods ----

  /** Print textual information about where this Varnode is in scope */
  printCover(writer: Writer): void {
    if (this.cover === null)
      throw new LowlevelError("No cover to print");
    if ((this.flags & Varnode.coverdirty) !== 0) {
      writer.write("Cover is dirty\n");
    } else {
      writer.write(this.cover.dump());
    }
  }

  /** Print boolean attribute information about this as keywords */
  printInfo(writer: Writer): void {
    if (this.type !== null)
      this.type.printRaw(writer);
    writer.write(" = ");
    this.printRaw(writer);
    if (this.isAddrTied()) writer.write(" tied");
    if (this.isMapped()) writer.write(" mapped");
    if (this.isPersist()) writer.write(" persistent");
    if (this.isTypeLock()) writer.write(" tlock");
    if (this.isNameLock()) writer.write(" nlock");
    if (this.isSpacebase()) writer.write(" base");
    if (this.isUnaffected()) writer.write(" unaff");
    if (this.isImplied()) writer.write(" implied");
    if (this.isAddrForce()) writer.write(" addrforce");
    if (this.isReadOnly()) writer.write(" readonly");
    writer.write(" (consumed=0x" + this.consumed.toString(16) + ")");
    writer.write(" (create=0x" + this.create_index.toString(16) + ")");
    writer.write("\n");
  }

  /**
   * Print a simple identifier for the Varnode.
   * Returns the expected size to facilitate printing of size modifiers.
   */
  printRawNoMarkup(writer: Writer): number {
    const spc: AddrSpace | null = this.loc.getSpace();
    if (spc === null) {
      writer.write("invalid");
      return 0;
    }
    const trans: Translate = spc.getTrans();
    let name: string = '';
    let expect: number;

    if (trans !== null && typeof trans.getRegisterName === 'function') {
      name = trans.getRegisterName(spc, this.loc.getOffset(), this.size);
    }

    if (name.length !== 0) {
      const point = trans.getRegister(name);
      const off = this.loc.getOffset() - point.offset;
      writer.write(name);
      expect = point.size;
      if (off !== 0n) {
        writer.write("+" + Number(off).toString());
      }
    } else {
      writer.write(this.loc.getShortcut());
      expect = (trans !== null && typeof trans.getDefaultSize === 'function') ? trans.getDefaultSize() : 0;
      writer.write(this.loc.printRaw());
    }
    return expect;
  }

  /**
   * Print a simple identifier plus additional info identifying Varnode with SSA form.
   */
  printRaw(writer: Writer): void {
    const expect = this.printRawNoMarkup(writer);

    if (expect !== this.size)
      writer.write(":" + this.size.toString());
    if ((this.flags & Varnode.input) !== 0)
      writer.write("(i)");
    if (this.isWritten())
      writer.write("(" + (this.def as PcodeOp).getSeqNum().toString() + ")");
    if ((this.flags & (Varnode.insert | Varnode.constant)) === 0) {
      writer.write("(free)");
      return;
    }
  }

  /** Recursively print a terse textual representation of the SSA tree */
  printRawHeritage(writer: Writer, depth: number): void {
    for (let i = 0; i < depth; ++i)
      writer.write(" ");

    if (this.isConstant()) {
      this.printRaw(writer);
      writer.write("\n");
      return;
    }
    this.printRaw(writer);
    writer.write(" ");
    if (this.def !== null)
      (this.def as PcodeOp).printRaw(writer);
    else
      this.printRaw(writer);

    if ((this.flags & Varnode.input) !== 0)
      writer.write(" Input");
    if ((this.flags & Varnode.constant) !== 0)
      writer.write(" Constant");
    if ((this.flags & Varnode.annotation) !== 0)
      writer.write(" Code");

    if (this.def !== null) {
      writer.write("\t\t" + (this.def as PcodeOp).getSeqNum().toString() + "\n");
      for (let i = 0; i < (this.def as PcodeOp).numInput(); ++i)
        (this.def as PcodeOp).getIn(i).printRawHeritage(writer, depth + 5);
    } else {
      writer.write("\n");
    }
  }

  /**
   * If this is a constant, or is extended from a constant,
   * the value (up to 128 bits) is passed back and true is returned.
   * @param val is a two-element bigint array that will hold the 128-bit value
   * @return true if a constant was recovered
   */
  isConstantExtended(val: bigint[]): boolean {
    if (this.isConstant()) {
      val[0] = this.getOffset();
      val[1] = 0n;
      return true;
    }
    if (!this.isWritten() || this.size <= 8) return false;
    if (this.size > 16) return false;
    const opc: OpCode = (this.def as PcodeOp).code();
    if (opc === OpCode.CPUI_INT_ZEXT) {
      const vn0: Varnode = (this.def as PcodeOp).getIn(0);
      if (vn0.isConstant()) {
        val[0] = vn0.getOffset();
        val[1] = 0n;
        return true;
      }
    } else if (opc === OpCode.CPUI_INT_SEXT) {
      const vn0: Varnode = (this.def as PcodeOp).getIn(0);
      if (vn0.isConstant()) {
        val[0] = vn0.getOffset();
        if (vn0.getSize() < 8)
          val[0] = sign_extend(val[0], vn0.getSize() * 8 - 1);
        val[1] = signbit_negative(val[0], 8) ? 0xFFFFFFFFFFFFFFFFn : 0n;
        return true;
      }
    } else if (opc === OpCode.CPUI_PIECE) {
      const vnlo: Varnode = (this.def as PcodeOp).getIn(1);
      if (vnlo.isConstant()) {
        val[0] = vnlo.getOffset();
        const vnhi: Varnode = (this.def as PcodeOp).getIn(0);
        if (vnhi.isConstant()) {
          val[1] = vnhi.getOffset();
          if (vnlo.getSize() === 8)
            return true;
          val[0] |= val[1] << BigInt(8 * vnlo.getSize());
          val[1] >>= BigInt(8 * (8 - vnlo.getSize()));
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Will this Varnode ultimately collapse to a constant?
   */
  isEventualConstant(maxBinary: number, maxLoad: number): boolean {
    let curVn: Varnode = this;
    while (!curVn.isConstant()) {
      if (!curVn.isWritten()) return false;
      const op: PcodeOp = curVn.getDef();
      switch (op.code()) {
        case OpCode.CPUI_LOAD:
          if (maxLoad === 0) return false;
          maxLoad -= 1;
          curVn = op.getIn(1);
          break;
        case OpCode.CPUI_INT_ADD:
        case OpCode.CPUI_INT_SUB:
        case OpCode.CPUI_INT_XOR:
        case OpCode.CPUI_INT_OR:
        case OpCode.CPUI_INT_AND:
          if (maxBinary === 0) return false;
          if (!op.getIn(0).isEventualConstant(maxBinary - 1, maxLoad))
            return false;
          return op.getIn(1).isEventualConstant(maxBinary - 1, maxLoad);
        case OpCode.CPUI_INT_ZEXT:
        case OpCode.CPUI_INT_SEXT:
        case OpCode.CPUI_COPY:
          curVn = op.getIn(0);
          break;
        case OpCode.CPUI_INT_LEFT:
        case OpCode.CPUI_INT_RIGHT:
        case OpCode.CPUI_INT_SRIGHT:
        case OpCode.CPUI_INT_MULT:
          if (!op.getIn(1).isConstant()) return false;
          curVn = op.getIn(0);
          break;
        default:
          return false;
      }
    }
    return true;
  }

  /**
   * Calculate type of Varnode based on local information.
   * @param blockupRef receives whether propagation should be blocked upward
   * @return the determined Datatype
   */
  getLocalType(blockupRef: { val: boolean }): Datatype {
    let ct: Datatype | null;
    let newct: Datatype | null;

    if (this.isTypeLock())
      return this.type;

    ct = null;
    if (this.def !== null) {
      ct = (this.def as PcodeOp).outputTypeLocal();
      if ((this.def as PcodeOp).stopsTypePropagation()) {
        blockupRef.val = true;
        return ct;
      }
    }

    for (let i = 0; i < this.descend.length; ++i) {
      const op = this.descend[i];
      const slot = op.getSlot(this);
      newct = op.inputTypeLocal(slot);

      if (ct === null)
        ct = newct;
      else {
        if (0 > newct.typeOrder(ct))
          ct = newct;
      }
    }
    if (ct === null)
      throw new LowlevelError("NULL local type");
    return ct;
  }

  /**
   * Does this Varnode hold a formal boolean value.
   */
  isBooleanValue(useAnnotation: boolean): boolean {
    if (this.isWritten()) return (this.def as PcodeOp).isCalculatedBool();
    if (!useAnnotation) return false;
    if ((this.flags & (Varnode.input | Varnode.typelock)) === (Varnode.input | Varnode.typelock)) {
      if (this.size === 1 && this.type !== null && this.type.getMetatype() === 11 /* TYPE_BOOL */)
        return true;
    }
    return false;
  }

  /**
   * Is this zero extended from something of the given size.
   */
  isZeroExtended(baseSize: number): boolean {
    if (baseSize >= this.size) return false;
    if (this.size > 8) {
      if (!this.isWritten()) return false;
      if ((this.def as PcodeOp).code() !== OpCode.CPUI_INT_ZEXT) return false;
      if ((this.def as PcodeOp).getIn(0).getSize() > baseSize) return false;
      return true;
    }
    const mask = this.nzm >> BigInt(8 * baseSize);
    return mask === 0n;
  }

  /** Are this and op2 copied from the same source? */
  copyShadow(op2: Varnode): boolean {
    if (this === op2) return true;
    let vn: Varnode = this;
    while (vn.isWritten() && vn.getDef().code() === OpCode.CPUI_COPY) {
      vn = vn.getDef().getIn(0);
      if (vn === op2) return true;
    }
    let op2cur: Varnode = op2;
    while (op2cur.isWritten() && op2cur.getDef().code() === OpCode.CPUI_COPY) {
      op2cur = op2cur.getDef().getIn(0);
      if (vn === op2cur) return true;
    }
    return false;
  }

  /**
   * Try to find a SUBPIECE operation producing the value in this from the given whole Varnode.
   */
  findSubpieceShadow(leastByte: number, whole: Varnode, recurse: number): boolean {
    let vn: Varnode = this;
    while (vn.isWritten() && vn.getDef().code() === OpCode.CPUI_COPY)
      vn = vn.getDef().getIn(0);
    if (!vn.isWritten()) {
      if (vn.isConstant()) {
        while (whole.isWritten() && whole.getDef().code() === OpCode.CPUI_COPY)
          whole = whole.getDef().getIn(0);
        if (!whole.isConstant()) return false;
        let off = whole.getOffset() >> BigInt(leastByte * 8);
        off &= calc_mask(vn.getSize());
        return off === vn.getOffset();
      }
      return false;
    }
    const opc = vn.getDef().code();
    if (opc === OpCode.CPUI_SUBPIECE) {
      let tmpvn: Varnode = vn.getDef().getIn(0);
      const off = Number(vn.getDef().getIn(1).getOffset());
      if (off !== leastByte || tmpvn.getSize() !== whole.getSize())
        return false;
      if (tmpvn === whole) return true;
      while (tmpvn.isWritten() && tmpvn.getDef().code() === OpCode.CPUI_COPY) {
        tmpvn = tmpvn.getDef().getIn(0);
        if (tmpvn === whole) return true;
      }
    } else if (opc === OpCode.CPUI_MULTIEQUAL) {
      recurse += 1;
      if (recurse > 1) return false;
      while (whole.isWritten() && whole.getDef().code() === OpCode.CPUI_COPY)
        whole = whole.getDef().getIn(0);
      if (!whole.isWritten()) return false;
      const bigOp = whole.getDef();
      if (bigOp.code() !== OpCode.CPUI_MULTIEQUAL) return false;
      const smallOp = vn.getDef();
      if (bigOp.getParent() !== smallOp.getParent()) return false;
      for (let i = 0; i < smallOp.numInput(); ++i) {
        if (!smallOp.getIn(i).findSubpieceShadow(leastByte, bigOp.getIn(i), recurse))
          return false;
      }
      return true;
    }
    return false;
  }

  /**
   * Try to find a PIECE operation that produces this from a given Varnode piece.
   */
  findPieceShadow(leastByte: number, piece: Varnode): boolean {
    let vn: Varnode = this;
    while (vn.isWritten() && vn.getDef().code() === OpCode.CPUI_COPY)
      vn = vn.getDef().getIn(0);
    if (!vn.isWritten()) return false;
    const opc = vn.getDef().code();
    if (opc === OpCode.CPUI_PIECE) {
      let tmpvn: Varnode = vn.getDef().getIn(1); // Least significant part
      if (leastByte >= tmpvn.getSize()) {
        leastByte -= tmpvn.getSize();
        tmpvn = vn.getDef().getIn(0);
      } else {
        if (piece.getSize() + leastByte > tmpvn.getSize()) return false;
      }
      if (leastByte === 0 && tmpvn.getSize() === piece.getSize()) {
        if (tmpvn === piece) return true;
        while (tmpvn.isWritten() && tmpvn.getDef().code() === OpCode.CPUI_COPY) {
          tmpvn = tmpvn.getDef().getIn(0);
          if (tmpvn === piece) return true;
        }
        return false;
      }
      return tmpvn.findPieceShadow(leastByte, piece);
    }
    return false;
  }

  /**
   * Is one of this or op2 a partial copy of the other?
   */
  partialCopyShadow(op2: Varnode, relOff: number): boolean {
    let vn: Varnode;

    if (this.size < op2.size) {
      vn = this;
    } else if (this.size > op2.size) {
      vn = op2;
      op2 = this;
      relOff = -relOff;
    } else {
      return false;
    }
    if (relOff < 0) return false;
    if (relOff + vn.getSize() > op2.getSize()) return false;

    const bigEndian = this.getSpace()!.isBigEndian();
    const leastByte = bigEndian ? (op2.getSize() - vn.getSize()) - relOff : relOff;
    if (vn.findSubpieceShadow(leastByte, op2, 0))
      return true;
    if (op2.findPieceShadow(leastByte, vn))
      return true;
    return false;
  }

  /**
   * Get structure/array/union that this is a piece of.
   * Return null if not applicable.
   */
  getStructuredType(): Datatype | null {
    let ct: Datatype;
    if (this.mapentry !== null)
      ct = this.mapentry.getSymbol().getType();
    else
      ct = this.type;
    if (ct !== null && ct.isPieceStructured())
      return ct;
    return null;
  }

  /**
   * Compare two Varnodes based on their term order.
   * Used in Term Rewriting strategies to order operands of commutative ops.
   * @return -1 if this comes before op, 1 if op before this, or 0
   */
  termOrder(op: Varnode): number {
    if (this.isConstant()) {
      if (!op.isConstant()) return 1;
    } else {
      if (op.isConstant()) return -1;
      let vn: Varnode = this;
      if (vn.isWritten() && vn.getDef().code() === OpCode.CPUI_INT_MULT)
        if (vn.getDef().getIn(1).isConstant())
          vn = vn.getDef().getIn(0);
      if (op.isWritten() && op.getDef().code() === OpCode.CPUI_INT_MULT)
        if (op.getDef().getIn(1).isConstant())
          op = op.getDef().getIn(0);

      if (vn.getAddr().lessThan(op.getAddr())) return -1;
      if (op.getAddr().lessThan(vn.getAddr())) return 1;
    }
    return 0;
  }

  /**
   * Encode a description of this to a stream.
   */
  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_ADDR);
    this.loc.getSpace()!.encodeAttributes(encoder, this.loc.getOffset(), this.size);
    encoder.writeUnsignedInteger(ATTRIB_REF, BigInt(this.getCreateIndex()));
    if (this.mergegroup !== 0)
      encoder.writeSignedInteger(ATTRIB_GRP, this.getMergeGroup());
    if (this.isPersist())
      encoder.writeBool(ATTRIB_PERSISTS, true);
    if (this.isAddrTied())
      encoder.writeBool(ATTRIB_ADDRTIED, true);
    if (this.isUnaffected())
      encoder.writeBool(ATTRIB_UNAFF, true);
    if (this.isInput())
      encoder.writeBool(ATTRIB_INPUT, true);
    if (this.isVolatile())
      encoder.writeBool(ATTRIB_VOLATILE, true);
    encoder.closeElement(ELEM_ADDR);
  }

  // ---- Comparison operators ----

  /** Comparison operator on Varnode */
  lessThan(op2: Varnode): boolean {
    if (!this.loc.equals(op2.loc)) return this.loc.lessThan(op2.loc);
    if (this.size !== op2.size) return this.size < op2.size;
    const f1 = this.flags & (Varnode.input | Varnode.written);
    const f2 = op2.flags & (Varnode.input | Varnode.written);
    if (f1 !== f2) return ((f1 - 1) >>> 0) < ((f2 - 1) >>> 0); // unsigned comparison with -1 trick
    if (f1 === Varnode.written)
      if (!(this.def as PcodeOp).getSeqNum().equals((op2.def as PcodeOp).getSeqNum()))
        return (this.def as PcodeOp).getSeqNum().lessThan((op2.def as PcodeOp).getSeqNum());
    return false;
  }

  /** Equality operator */
  equals(op2: Varnode): boolean {
    if (!this.loc.equals(op2.loc)) return false;
    if (this.size !== op2.size) return false;
    const f1 = this.flags & (Varnode.input | Varnode.written);
    const f2 = op2.flags & (Varnode.input | Varnode.written);
    if (f1 !== f2) return false;
    if (f1 === Varnode.written)
      if (!(this.def as PcodeOp).getSeqNum().equals((op2.def as PcodeOp).getSeqNum())) return false;
    return true;
  }

  /** Inequality operator */
  notEquals(op2: Varnode): boolean { return !this.equals(op2); }

  /** Compare Varnodes as pointers */
  static comparePointers(a: Varnode, b: Varnode): boolean { return a.lessThan(b); }

  /** Print raw info about a Varnode to writer (handles null) */
  static printRawStatic(writer: Writer, vn: Varnode | null): void {
    if (vn === null) {
      writer.write("<null>");
      return;
    }
    vn.printRaw(writer);
  }
}

// ---------------------------------------------------------------------------
// Comparison functions for SortedSet
// ---------------------------------------------------------------------------

/**
 * Compare by location then by definition.
 * Frees come last (via unsigned subtraction trick with -1).
 */
export function varnodeCompareLocDef(a: Varnode, b: Varnode): number {
  // Compare by address first
  if (!a.getAddr().equals(b.getAddr())) {
    return a.getAddr().lessThan(b.getAddr()) ? -1 : 1;
  }
  // Then by size
  if (a.getSize() !== b.getSize()) return a.getSize() - b.getSize();

  const f1 = a.getFlags() & (Varnode.input | Varnode.written);
  const f2 = b.getFlags() & (Varnode.input | Varnode.written);
  if (f1 !== f2) {
    // -1 forces free varnodes to come last (unsigned compare)
    return (((f1 - 1) >>> 0) < ((f2 - 1) >>> 0)) ? -1 : 1;
  }
  if (f1 === Varnode.written) {
    const seq1 = (a.getDef() as PcodeOp).getSeqNum();
    const seq2 = (b.getDef() as PcodeOp).getSeqNum();
    if (!seq1.equals(seq2)) {
      return seq1.lessThan(seq2) ? -1 : 1;
    }
  } else if (f1 === 0) {
    // Both are free, compare by create_index
    if (a.getCreateIndex() !== b.getCreateIndex())
      return a.getCreateIndex() < b.getCreateIndex() ? -1 : 1;
  }

  return 0;
}

/**
 * Compare by definition then by location.
 * Frees come last (via unsigned subtraction trick with -1).
 */
export function varnodeCompareDefLoc(a: Varnode, b: Varnode): number {
  const f1 = a.getFlags() & (Varnode.input | Varnode.written);
  const f2 = b.getFlags() & (Varnode.input | Varnode.written);
  if (f1 !== f2) {
    return (((f1 - 1) >>> 0) < ((f2 - 1) >>> 0)) ? -1 : 1;
  }
  if (f1 === Varnode.written) {
    const seq1 = (a.getDef() as PcodeOp).getSeqNum();
    const seq2 = (b.getDef() as PcodeOp).getSeqNum();
    if (!seq1.equals(seq2)) {
      return seq1.lessThan(seq2) ? -1 : 1;
    }
  }
  // Then by address
  if (!a.getAddr().equals(b.getAddr())) {
    return a.getAddr().lessThan(b.getAddr()) ? -1 : 1;
  }
  // Then by size
  if (a.getSize() !== b.getSize()) return a.getSize() - b.getSize();

  if (f1 === 0) {
    // Both are free
    if (a.getCreateIndex() !== b.getCreateIndex())
      return a.getCreateIndex() < b.getCreateIndex() ? -1 : 1;
  }

  return 0;
}

// ---------------------------------------------------------------------------
// VarnodeLocSet and VarnodeDefSet types
// ---------------------------------------------------------------------------

/** A set of Varnodes sorted by location (then by definition) */
export type VarnodeLocSet = SortedSet<Varnode>;

/** A set of Varnodes sorted by definition (then location) */
export type VarnodeDefSet = SortedSet<Varnode>;

// ---------------------------------------------------------------------------
// VarnodeBank class
// ---------------------------------------------------------------------------

/**
 * A container for Varnode objects from a specific function.
 *
 * The API allows the creation, deletion, search, and iteration of Varnode objects
 * from one function. The class maintains two orderings for efficiency:
 *   - Sorting based on storage location (loc)
 *   - Sorting based on point of definition (def)
 */
export class VarnodeBank {
  /** @internal */ private manage: AddrSpaceManager;
  /** @internal */ private uniq_space: AddrSpace;
  /** @internal */ private uniqbase: number;
  /** @internal */ private uniqid: number;
  /** @internal */ private create_index: number;
  /** @internal */ public loc_tree: VarnodeLocSet;
  /** @internal */ public def_tree: VarnodeDefSet;
  /** @internal */ private searchvn: Varnode;

  /**
   * Construct the container.
   * @param m is the underlying address space manager
   */
  constructor(m: AddrSpaceManager) {
    this.manage = m;
    this.searchvn = new Varnode(0, new Address(MachExtreme.m_minimal), null);
    this.searchvn.flags = Varnode.input; // searchvn is always an input varnode of size 0
    this.uniq_space = m.getUniqueSpace();
    // The C++ uses: uniq_space->getTrans()->getUniqueStart(Translate::ANALYSIS)
    // Translate::ANALYSIS is 0x10000000
    if (this.uniq_space !== null && typeof this.uniq_space.getTrans === 'function') {
      const trans = this.uniq_space.getTrans();
      if (trans !== null && typeof trans.getUniqueStart === 'function') {
        this.uniqbase = trans.getUniqueStart(0x10000000);
      } else {
        this.uniqbase = 0x10000000;
      }
    } else {
      this.uniqbase = 0x10000000;
    }
    this.uniqid = this.uniqbase;
    this.create_index = 0;
    this.loc_tree = new SortedSet<Varnode>(varnodeCompareLocDef);
    this.def_tree = new SortedSet<Varnode>(varnodeCompareDefLoc);
  }

  /** Clear out all Varnodes and reset counters */
  clear(): void {
    this.loc_tree.clear();
    this.def_tree.clear();
    this.uniqid = this.uniqbase;
    this.create_index = 0;
  }

  /** Get number of Varnodes this contains */
  numVarnodes(): number { return this.loc_tree.size; }

  /** Get the next creation index to be assigned */
  getCreateIndex(): number { return this.create_index; }

  /**
   * Create a free Varnode object.
   * @param s is the size of the Varnode in bytes
   * @param m is the starting address
   * @param ct is the data-type of the new varnode (must not be null)
   * @return the newly allocated Varnode object
   */
  create(s: number, m: Address, ct: Datatype): Varnode {
    const vn = new Varnode(s, m, ct);
    vn.create_index = this.create_index++;
    const [locIt] = this.loc_tree.insert(vn);
    vn.lociter = locIt;
    const [defIt] = this.def_tree.insert(vn);
    vn.defiter = defIt;
    return vn;
  }

  /**
   * Create a temporary varnode.
   * @param s is the size of the Varnode in bytes
   * @param ct is the data-type to assign (must not be null)
   */
  createUnique(s: number, ct: Datatype): Varnode {
    const addr = new Address(this.uniq_space, BigInt(this.uniqid));
    this.uniqid += s;
    return this.create(s, addr, ct);
  }

  /**
   * Remove a Varnode from the container.
   * @param vn is the Varnode to remove
   */
  destroy(vn: Varnode): void {
    if ((vn.getDef() !== null) || (!vn.hasNoDescend()))
      throw new LowlevelError("Deleting integrated varnode");

    if (vn.lociter !== null)
      this.loc_tree.erase(vn.lociter);
    if (vn.defiter !== null)
      this.def_tree.erase(vn.defiter);
    // GC handles the rest
  }

  /**
   * @internal Enter the Varnode into both sorted trees. Update iterators and flags.
   * @return the inserted object, which may not be the same as the input Varnode
   */
  private xref(vn: Varnode): Varnode {
    const [locIt, inserted] = this.loc_tree.insert(vn);

    if (!inserted) {
      // Set already contains this varnode
      const othervn = locIt.value;
      this.replace(vn, othervn);
      return othervn;
    }

    // New insertion
    vn.lociter = locIt;
    vn.setFlags(Varnode.insert);
    const [defIt] = this.def_tree.insert(vn);
    vn.defiter = defIt;
    return vn;
  }

  /**
   * Convert a Varnode to be free.
   * @param vn is the Varnode to modify
   */
  makeFree(vn: Varnode): void {
    if (vn.lociter !== null)
      this.loc_tree.erase(vn.lociter);
    if (vn.defiter !== null)
      this.def_tree.erase(vn.defiter);

    vn.setDef(null);
    vn.clearFlags(Varnode.insert | Varnode.input | Varnode.indirect_creation);

    const [locIt] = this.loc_tree.insert(vn);
    vn.lociter = locIt;
    const [defIt] = this.def_tree.insert(vn);
    vn.defiter = defIt;
  }

  /**
   * Replace every read of one Varnode with another.
   * @param oldvn is the old Varnode
   * @param newvn is the Varnode to replace it with
   */
  replace(oldvn: Varnode, newvn: Varnode): void {
    // Iterate over a copy since we're modifying the descend array
    const descendants = oldvn.descend.slice();
    for (const op of descendants) {
      if (op.output === newvn) continue;
      const i = op.getSlot(oldvn);
      const idx = oldvn.descend.indexOf(op);
      if (idx >= 0) oldvn.descend.splice(idx, 1);
      op.clearInput(i);
      newvn.addDescend(op);
      op.setInput(newvn, i);
    }
    oldvn.setFlags(Varnode.coverdirty);
    newvn.setFlags(Varnode.coverdirty);
  }

  /**
   * Mark a Varnode as an input to the function.
   * @param vn is the Varnode to mark
   * @return the modified Varnode (may be a different object)
   */
  setInput(vn: Varnode): Varnode {
    if (!vn.isFree())
      throw new LowlevelError("Making input out of varnode which is not free");
    if (vn.isConstant())
      throw new LowlevelError("Making input out of constant varnode");

    if (vn.lociter !== null)
      this.loc_tree.erase(vn.lociter);
    if (vn.defiter !== null)
      this.def_tree.erase(vn.defiter);

    vn.setInputFlag();
    return this.xref(vn);
  }

  /**
   * Change Varnode to be defined by the given PcodeOp.
   * @param vn is the Varnode to modify
   * @param op is the given PcodeOp
   * @return the modified Varnode (may be a different object)
   */
  setDef(vn: Varnode, op: PcodeOp): Varnode {
    if (!vn.isFree()) {
      const addr: Address = op.getAddr();
      throw new LowlevelError(
        "Defining varnode which is not free at " + addr.getShortcut() + addr.printRaw()
      );
    }
    if (vn.isConstant()) {
      const addr: Address = op.getAddr();
      throw new LowlevelError(
        "Assignment to constant at " + addr.getShortcut() + addr.printRaw()
      );
    }

    if (vn.lociter !== null)
      this.loc_tree.erase(vn.lociter);
    if (vn.defiter !== null)
      this.def_tree.erase(vn.defiter);

    vn.setDef(op);
    return this.xref(vn);
  }

  /**
   * Create a Varnode as the output of a PcodeOp.
   */
  createDef(s: number, m: Address, ct: Datatype, op: PcodeOp): Varnode {
    const vn = new Varnode(s, m, ct);
    vn.create_index = this.create_index++;
    vn.setDef(op);
    return this.xref(vn);
  }

  /**
   * Create a temporary Varnode as output of a PcodeOp.
   */
  createDefUnique(s: number, ct: Datatype, op: PcodeOp): Varnode {
    const addr = new Address(this.uniq_space, BigInt(this.uniqid));
    this.uniqid += s;
    return this.createDef(s, addr, ct, op);
  }

  /**
   * Find a Varnode given its (loc,size) and the address where it is defined.
   * @param s is the size
   * @param loc is the starting address
   * @param pc is the address where it is defined
   * @param uniq is the sequence number or 0xFFFFFFFF if not specified
   * @return the matching Varnode or null
   */
  find(s: number, loc: Address, pc: Address, uniq: number = 0xFFFFFFFF): Varnode | null {
    const iter = this.beginLocSizeAddrPcUniq(s, loc, pc, uniq);
    while (!iter.isEnd) {
      const vn = iter.value;
      if (vn.getSize() !== s) break;
      if (!vn.getAddr().equals(loc)) break;
      const op = vn.getDef();
      if (op !== null && op.getAddr().equals(pc)) {
        if (uniq === 0xFFFFFFFF || op.getTime() === uniq) return vn;
      }
      iter.next();
    }
    return null;
  }

  /**
   * Find an input Varnode given its size and address.
   */
  findInput(s: number, loc: Address): Varnode | null {
    const iter = this.beginLocSizeAddrFlag(s, loc, Varnode.input);
    if (!iter.isEnd) {
      const vn = iter.value;
      if (vn.isInput() && vn.getSize() === s && vn.getAddr().equals(loc))
        return vn;
    }
    return null;
  }

  /**
   * Find an input Varnode contained within this range.
   */
  findCoveredInput(s: number, loc: Address): Varnode | null {
    const highest = loc.getSpace()!.getHighest();
    const end = loc.getOffset() + BigInt(s) - 1n;

    let iter = this.beginDefFlagAddr(Varnode.input, loc);
    let enditer: SortedSetIterator<Varnode>;
    if (end === highest) {
      const tmp = new Address(loc.getSpace()!, highest);
      enditer = this.endDefFlagAddr(Varnode.input, tmp);
    } else {
      enditer = this.beginDefFlagAddr(Varnode.input, loc.add(BigInt(s)));
    }

    while (!iter.equals(enditer)) {
      const vn = iter.value;
      iter.next();
      if (vn.getOffset() + BigInt(vn.getSize()) - 1n <= end)
        return vn;
    }
    return null;
  }

  /**
   * Find an input Varnode covering a range.
   */
  findCoveringInput(s: number, loc: Address): Varnode | null {
    let iter = this.beginDefFlagAddr(Varnode.input, loc);
    if (!iter.isEnd) {
      let vn = iter.value;
      if (!vn.getAddr().equals(loc) && !iter.equals(this.def_tree.begin())) {
        iter.prev();
        vn = iter.value;
      }
      if (vn.isInput() && (vn.getSpace() === loc.getSpace()) &&
          (vn.getOffset() <= loc.getOffset()) &&
          (vn.getOffset() + BigInt(vn.getSize()) - 1n >= loc.getOffset() + BigInt(s) - 1n))
        return vn;
    }
    return null;
  }

  /**
   * Check for input Varnode that overlaps the given range.
   */
  hasInputIntersection(s: number, loc: Address): boolean {
    const iter = this.beginDefFlagAddr(Varnode.input, loc);
    if (!iter.isEnd) {
      const vn = iter.value;
      if (vn.isInput() && vn.intersects(loc, s))
        return true;
    }
    if (!iter.equals(this.def_tree.begin())) {
      const prevIter = iter.clone();
      prevIter.prev();
      const vn = prevIter.value;
      if (vn.isInput() && vn.intersects(loc, s))
        return true;
    }
    return false;
  }

  // ---- Location-sorted iterators ----

  /** Beginning of location list */
  beginLoc(): SortedSetIterator<Varnode> { return this.loc_tree.begin(); }

  /** End of location list */
  endLoc(): SortedSetIterator<Varnode> { return this.loc_tree.end(); }

  /** Beginning of Varnodes in given address space sorted by location */
  beginLocSpace(spaceid: AddrSpace): SortedSetIterator<Varnode> {
    this.searchvn.loc = new Address(spaceid, 0n);
    return this.loc_tree.lower_bound(this.searchvn);
  }

  /** Ending of Varnodes in given address space sorted by location */
  endLocSpace(spaceid: AddrSpace): SortedSetIterator<Varnode> {
    this.searchvn.loc = new Address(this.manage.getNextSpaceInOrder(spaceid), 0n);
    return this.loc_tree.lower_bound(this.searchvn);
  }

  /** Beginning of Varnodes starting at a given address sorted by location */
  beginLocAddr(addr: Address): SortedSetIterator<Varnode> {
    this.searchvn.loc = addr;
    return this.loc_tree.lower_bound(this.searchvn);
  }

  /** End of Varnodes starting at a given address sorted by location */
  endLocAddr(addr: Address): SortedSetIterator<Varnode> {
    if (addr.getOffset() === addr.getSpace()!.getHighest()) {
      const space = addr.getSpace()!;
      this.searchvn.loc = new Address(this.manage.getNextSpaceInOrder(space), 0n);
    } else {
      this.searchvn.loc = addr.add(1n);
    }
    return this.loc_tree.lower_bound(this.searchvn);
  }

  /** Beginning of Varnodes of given size and starting address sorted by location */
  beginLocSizeAddr(s: number, addr: Address): SortedSetIterator<Varnode> {
    this.searchvn.size = s;
    this.searchvn.loc = addr;
    const iter = this.loc_tree.lower_bound(this.searchvn);
    this.searchvn.size = 0;
    return iter;
  }

  /** End of Varnodes of given size and starting address sorted by location */
  endLocSizeAddr(s: number, addr: Address): SortedSetIterator<Varnode> {
    this.searchvn.size = s + 1;
    this.searchvn.loc = addr;
    const iter = this.loc_tree.lower_bound(this.searchvn);
    this.searchvn.size = 0;
    return iter;
  }

  /**
   * Beginning of Varnodes sorted by location, restricted by size, address, and flags.
   * @param s is the given size
   * @param addr is the given starting address
   * @param fl is the property restriction (Varnode.input, Varnode.written, or 0 for free)
   */
  beginLocSizeAddrFlag(s: number, addr: Address, fl: number): SortedSetIterator<Varnode> {
    if (fl === Varnode.input) {
      this.searchvn.size = s;
      this.searchvn.loc = addr;
      const iter = this.loc_tree.lower_bound(this.searchvn);
      this.searchvn.size = 0;
      return iter;
    }
    if (fl === Varnode.written) {
      // Create a minimal PcodeOp-like search key
      const searchop = { getSeqNum: () => new SeqNum(MachExtreme.m_minimal) };
      this.searchvn.size = s;
      this.searchvn.loc = addr;
      this.searchvn.flags = Varnode.written;
      this.searchvn.def = searchop;
      const iter = this.loc_tree.lower_bound(this.searchvn);
      this.searchvn.size = 0;
      this.searchvn.flags = Varnode.input;
      return iter;
    }

    // fl === 0: find free varnodes
    const searchop = { getSeqNum: () => new SeqNum(MachExtreme.m_maximal) };
    this.searchvn.size = s;
    this.searchvn.loc = addr;
    this.searchvn.flags = Varnode.written;
    this.searchvn.def = searchop;
    const iter = this.loc_tree.upper_bound(this.searchvn);
    this.searchvn.size = 0;
    this.searchvn.flags = Varnode.input;
    return iter;
  }

  /**
   * End of Varnodes sorted by location, restricted by size, address, and flags.
   */
  endLocSizeAddrFlag(s: number, addr: Address, fl: number): SortedSetIterator<Varnode> {
    this.searchvn.loc = addr;

    if (fl === Varnode.written) {
      this.searchvn.size = s;
      this.searchvn.flags = Varnode.written;
      const searchop = { getSeqNum: () => new SeqNum(MachExtreme.m_maximal) };
      this.searchvn.def = searchop;
      const iter = this.loc_tree.upper_bound(this.searchvn);
      this.searchvn.size = 0;
      this.searchvn.flags = Varnode.input;
      return iter;
    } else if (fl === Varnode.input) {
      this.searchvn.size = s;
      const iter = this.loc_tree.upper_bound(this.searchvn);
      this.searchvn.size = 0;
      return iter;
    }

    // fl === 0: end of free varnodes
    this.searchvn.size = s + 1;
    const iter = this.loc_tree.lower_bound(this.searchvn);
    this.searchvn.size = 0;
    return iter;
  }

  /**
   * Beginning of Varnodes sorted by location, restricted by size, address, pc, and uniq.
   */
  beginLocSizeAddrPcUniq(s: number, addr: Address, pc: Address, uniq: number): SortedSetIterator<Varnode> {
    this.searchvn.size = s;
    this.searchvn.loc = addr;
    this.searchvn.flags = Varnode.written;
    if (uniq === 0xFFFFFFFF) uniq = 0;
    const searchop = { getSeqNum: () => new SeqNum(pc, uniq) };
    this.searchvn.def = searchop;
    const iter = this.loc_tree.lower_bound(this.searchvn);
    this.searchvn.size = 0;
    this.searchvn.flags = Varnode.input;
    return iter;
  }

  /**
   * End of Varnodes sorted by location, restricted by size, address, pc, and uniq.
   */
  endLocSizeAddrPcUniq(s: number, addr: Address, pc: Address, uniq: number): SortedSetIterator<Varnode> {
    this.searchvn.size = s;
    this.searchvn.loc = addr;
    this.searchvn.flags = Varnode.written;
    const searchop = { getSeqNum: () => new SeqNum(pc, uniq) };
    this.searchvn.def = searchop;
    const iter = this.loc_tree.upper_bound(this.searchvn);
    this.searchvn.size = 0;
    this.searchvn.flags = Varnode.input;
    return iter;
  }

  /**
   * Given start, return maximal range of overlapping Varnodes.
   * @param iter is an iterator to the given start Varnode
   * @param bounds holds the array of iterators passed back
   * @return the union of Varnode flags across the range
   */
  overlapLoc(iter: SortedSetIterator<Varnode>, bounds: SortedSetIterator<Varnode>[]): number {
    let vn = iter.value;
    const spc = vn.getSpace();
    const off = vn.getOffset();
    let maxOff = off + BigInt(vn.getSize() - 1);
    let flags = vn.getFlags();
    bounds.push(iter.clone());
    let nextIter = this.endLocSizeAddrFlag(vn.getSize(), vn.getAddr(), Varnode.written);
    bounds.push(nextIter.clone());
    iter = nextIter;
    while (!iter.isEnd) {
      vn = iter.value;
      if (vn.getSpace() !== spc || vn.getOffset() > maxOff)
        break;
      if (vn.isFree()) {
        iter = this.endLocSizeAddrFlag(vn.getSize(), vn.getAddr(), 0);
        continue;
      }
      const endOff = vn.getOffset() + BigInt(vn.getSize() - 1);
      if (endOff > maxOff) maxOff = endOff;
      flags |= vn.getFlags();
      bounds.push(iter.clone());
      nextIter = this.endLocSizeAddrFlag(vn.getSize(), vn.getAddr(), Varnode.written);
      bounds.push(nextIter.clone());
      iter = nextIter;
    }
    bounds.push(iter.clone());
    return flags;
  }

  // ---- Definition-sorted iterators ----

  /** Beginning of Varnodes sorted by definition */
  beginDef(): SortedSetIterator<Varnode> { return this.def_tree.begin(); }

  /** End of Varnodes sorted by definition */
  endDef(): SortedSetIterator<Varnode> { return this.def_tree.end(); }

  /**
   * Beginning of varnodes with set definition property.
   * @param fl is Varnode.input, Varnode.written, or 0 for free
   */
  beginDefFlag(fl: number): SortedSetIterator<Varnode> {
    if (fl === Varnode.input) {
      return this.def_tree.begin();
    } else if (fl === Varnode.written) {
      this.searchvn.loc = new Address(MachExtreme.m_minimal);
      this.searchvn.flags = Varnode.written;
      const searchop = { getSeqNum: () => new SeqNum(MachExtreme.m_minimal) };
      this.searchvn.def = searchop;
      const iter = this.def_tree.lower_bound(this.searchvn);
      this.searchvn.flags = Varnode.input;
      return iter;
    }

    // Start of frees
    this.searchvn.loc = new Address(MachExtreme.m_maximal);
    this.searchvn.flags = Varnode.written;
    const searchop = { getSeqNum: () => new SeqNum(MachExtreme.m_maximal) };
    this.searchvn.def = searchop;
    const iter = this.def_tree.upper_bound(this.searchvn);
    this.searchvn.flags = Varnode.input;
    return iter;
  }

  /**
   * End of varnodes with set definition property.
   * @param fl is Varnode.input, Varnode.written, or 0 for free
   */
  endDefFlag(fl: number): SortedSetIterator<Varnode> {
    if (fl === Varnode.input) {
      // Highest input is lowest written
      this.searchvn.loc = new Address(MachExtreme.m_minimal);
      this.searchvn.flags = Varnode.written;
      const searchop = { getSeqNum: () => new SeqNum(MachExtreme.m_minimal) };
      this.searchvn.def = searchop;
      const iter = this.def_tree.lower_bound(this.searchvn);
      this.searchvn.flags = Varnode.input;
      return iter;
    } else if (fl === Varnode.written) {
      this.searchvn.loc = new Address(MachExtreme.m_maximal);
      this.searchvn.flags = Varnode.written;
      const searchop = { getSeqNum: () => new SeqNum(MachExtreme.m_maximal) };
      this.searchvn.def = searchop;
      const iter = this.def_tree.upper_bound(this.searchvn);
      this.searchvn.flags = Varnode.input;
      return iter;
    }
    return this.def_tree.end();
  }

  /**
   * Beginning of varnodes starting at a given address with a set definition property.
   * @param fl is the property restriction
   * @param addr is the given starting address
   */
  beginDefFlagAddr(fl: number, addr: Address): SortedSetIterator<Varnode> {
    if (fl === Varnode.written)
      throw new LowlevelError("Cannot get contiguous written AND addressed");
    if (fl === Varnode.input) {
      this.searchvn.loc = addr;
      return this.def_tree.lower_bound(this.searchvn);
    }

    // Free varnodes with given address
    this.searchvn.loc = addr;
    this.searchvn.flags = 0;
    const iter = this.def_tree.upper_bound(this.searchvn);
    this.searchvn.flags = Varnode.input;
    return iter;
  }

  /**
   * End of varnodes starting at a given address with a set definition property.
   * @param fl is the property restriction
   * @param addr is the given starting address
   */
  endDefFlagAddr(fl: number, addr: Address): SortedSetIterator<Varnode> {
    if (fl === Varnode.written)
      throw new LowlevelError("Cannot get contiguous written AND addressed");
    if (fl === Varnode.input) {
      this.searchvn.loc = addr;
      this.searchvn.size = 1000000;
      const iter = this.def_tree.lower_bound(this.searchvn);
      this.searchvn.size = 0;
      return iter;
    }

    // Free varnodes with given address
    this.searchvn.loc = addr;
    this.searchvn.size = 1000000;
    this.searchvn.flags = 0;
    const iter = this.def_tree.lower_bound(this.searchvn);
    this.searchvn.flags = Varnode.input;
    this.searchvn.size = 0;
    return iter;
  }

  // ---- Convenience iterables for coreaction/ruleaction ----

  /** Get all varnodes by location order as an array */
  getLocAll(): Varnode[] {
    const result: Varnode[] = [];
    const end = this.endLoc();
    for (let iter = this.beginLoc(); !iter.equals(end); iter.next()) {
      result.push(iter.get());
    }
    return result;
  }

  /** Get varnodes in a specific address space */
  getLocSpace(spc: AddrSpace): Varnode[] {
    const result: Varnode[] = [];
    const end = this.endLocSpace(spc);
    for (let iter = this.beginLocSpace(spc); !iter.equals(end); iter.next()) {
      result.push(iter.get());
    }
    return result;
  }

  /** Get varnodes at a specific size and address */
  getLocSizeAddr(s: number, addr: Address): Varnode[] {
    const result: Varnode[] = [];
    const end = this.endLocSizeAddr(s, addr);
    for (let iter = this.beginLocSizeAddr(s, addr); !iter.equals(end); iter.next()) {
      result.push(iter.get());
    }
    return result;
  }

  /** Get varnodes in an address range */
  getLocRange(addr: Address, endaddr: Address | null): Varnode[] {
    const result: Varnode[] = [];
    const startIter = this.beginLocAddr(addr);
    const endIter = endaddr !== null ? this.beginLocAddr(endaddr) : this.endLoc();
    for (let iter = startIter; !iter.equals(endIter); iter.next()) {
      result.push(iter.get());
    }
    return result;
  }

  /** Get varnodes by definition flag (input/written/free) */
  getDefFlag(fl: number): Varnode[] {
    const result: Varnode[] = [];
    const end = this.endDefFlag(fl);
    for (let iter = this.beginDefFlag(fl); !iter.equals(end); iter.next()) {
      result.push(iter.get());
    }
    return result;
  }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/**
 * Test if Varnodes are pieces of a whole.
 * Return true if vn1 contains the high part and vn2 the low part
 * of what was(is) a single value.
 * @param vn1 is the putative high Varnode
 * @param vn2 is the putative low Varnode
 * @return true if they are pieces of a whole
 */
export function contiguous_test(vn1: Varnode, vn2: Varnode): boolean {
  if (vn1.isInput() || vn2.isInput()) {
    return false;
  }
  if (!vn1.isWritten() || !vn2.isWritten()) return false;
  const op1: PcodeOp = vn1.getDef();
  const op2: PcodeOp = vn2.getDef();
  switch (op1.code()) {
    case OpCode.CPUI_SUBPIECE:
      if (op2.code() !== OpCode.CPUI_SUBPIECE) return false;
      {
        const vnwhole = op1.getIn(0);
        if (op2.getIn(0) !== vnwhole) return false;
        if (op2.getIn(1).getOffset() !== 0n) return false;
        if (op1.getIn(1).getOffset() !== BigInt(vn2.getSize())) return false;
      }
      return true;
    default:
      return false;
  }
}

/**
 * Retrieve the whole Varnode given pieces.
 * Assuming vn1,vn2 has passed the contiguous_test(), return
 * the Varnode containing the whole value.
 * @param data is the underlying function
 * @param vn1 is the high Varnode
 * @param vn2 is the low Varnode
 * @return the whole Varnode
 */
export function findContiguousWhole(data: Funcdata, vn1: Varnode, vn2: Varnode): Varnode | null {
  if (vn1.isWritten())
    if (vn1.getDef().code() === OpCode.CPUI_SUBPIECE)
      return vn1.getDef().getIn(0);
  return null;
}
