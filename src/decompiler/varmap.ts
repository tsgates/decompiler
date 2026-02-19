/**
 * @file varmap.ts
 * @description Classes for keeping track of local variables and reconstructing stack layout.
 *
 * Translated from Ghidra's varmap.hh / varmap.cc.
 */

import { Address, Range, RangeList, sign_extend, calc_mask } from '../core/address.js';
import { OpCode } from '../core/opcodes.js';
import { AddrSpace } from '../core/space.js';
import { LowlevelError } from '../core/error.js';
import { DynamicHash } from './dynamic.js';
import { StringWriter } from '../util/writer.js';
import { AttributeId, ElementId, Encoder, Decoder } from '../core/marshal.js';
import {
  Datatype,
  type_metatype,
} from './type.js';
import {
  SymbolEntry,
  Symbol,
  EntryMap,
  ScopeInternal,
} from './database.js';
import { Varnode } from './varnode.js';

// ---------------------------------------------------------------------------
// Forward type declarations for types from not-yet-written modules
// ---------------------------------------------------------------------------

type Funcdata = any;
type Architecture = any;
type TypeFactory = any;
type TypePointer = any;
type TypeArray = any;
type TypePartialStruct = any;
type TypePartialUnion = any;
type FuncProto = any;
type ProtoModel = any;
type LoadGuard = any;
type PcodeOp = any;
type HighVariable = any;
// ScopeInternal imported from database.ts
type SymbolNameTree = any;
type VarnodeLocSet = any;
type VarnodeDefSet = any;

// OpCode constants used in this file
const CPUI_COPY = OpCode.CPUI_COPY;
const CPUI_LOAD = OpCode.CPUI_LOAD;
const CPUI_STORE = OpCode.CPUI_STORE;
const CPUI_INDIRECT = OpCode.CPUI_INDIRECT;
const CPUI_MULTIEQUAL = OpCode.CPUI_MULTIEQUAL;
const CPUI_PIECE = OpCode.CPUI_PIECE;
const CPUI_SUBPIECE = OpCode.CPUI_SUBPIECE;
const CPUI_INT_ADD = OpCode.CPUI_INT_ADD;
const CPUI_INT_SUB = OpCode.CPUI_INT_SUB;
const CPUI_PTRADD = OpCode.CPUI_PTRADD;
const CPUI_PTRSUB = OpCode.CPUI_PTRSUB;
const CPUI_SEGMENTOP = OpCode.CPUI_SEGMENTOP;

// type_metatype constants used in this file
const TYPE_UNKNOWN = type_metatype.TYPE_UNKNOWN;
const TYPE_INT = type_metatype.TYPE_INT;
const TYPE_UINT = type_metatype.TYPE_UINT;
const TYPE_BOOL = type_metatype.TYPE_BOOL;
const TYPE_FLOAT = type_metatype.TYPE_FLOAT;
const TYPE_PTR = type_metatype.TYPE_PTR;
const TYPE_ARRAY = type_metatype.TYPE_ARRAY;
const TYPE_STRUCT = type_metatype.TYPE_STRUCT;
const TYPE_UNION = type_metatype.TYPE_UNION;
const TYPE_PARTIALSTRUCT = type_metatype.TYPE_PARTIALSTRUCT;
const TYPE_PARTIALUNION = type_metatype.TYPE_PARTIALUNION;

// ---------------------------------------------------------------------------
// Marshaling attributes / elements
// ---------------------------------------------------------------------------

export const ATTRIB_LOCK = new AttributeId("lock", 133);
export const ATTRIB_MAIN = new AttributeId("main", 134);

export const ELEM_LOCALDB = new ElementId("localdb", 228);

// ---------------------------------------------------------------------------
// NameRecommend
// ---------------------------------------------------------------------------

/**
 * A symbol name recommendation with its associated storage location.
 *
 * The name is associated with a static Address and use point in the code. Symbols
 * present at the end of function decompilation without a name can acquire this name
 * if their storage matches.
 */
export class NameRecommend {
  private addr: Address;
  private useaddr: Address;
  private _size: number;
  private _name: string;
  private _symbolId: bigint;

  constructor(ad: Address, use: Address, sz: number, nm: string, id: bigint) {
    this.addr = new Address(ad);
    this.useaddr = new Address(use);
    this._size = sz;
    this._name = nm;
    this._symbolId = id;
  }

  /** Get the storage address */
  getAddr(): Address { return this.addr; }

  /** Get the use point address */
  getUseAddr(): Address { return this.useaddr; }

  /** Get the optional size */
  getSize(): number { return this._size; }

  /** Get the recommended name */
  getName(): string { return this._name; }

  /** Get the original Symbol id */
  getSymbolId(): bigint { return this._symbolId; }
}

// ---------------------------------------------------------------------------
// DynamicRecommend
// ---------------------------------------------------------------------------

/**
 * A name recommendation for a particular dynamic storage location.
 *
 * A recommendation for a symbol name whose storage is dynamic. The storage
 * is identified using the DynamicHash mechanism and may or may not exist.
 */
export class DynamicRecommend {
  private usePoint: Address;
  private _hash: bigint;
  private _name: string;
  private _symbolId: bigint;

  constructor(addr: Address, h: bigint, nm: string, id: bigint) {
    this.usePoint = new Address(addr);
    this._hash = h;
    this._name = nm;
    this._symbolId = id;
  }

  /** Get the use point address */
  getAddress(): Address { return this.usePoint; }

  /** Get the dynamic hash */
  getHash(): bigint { return this._hash; }

  /** Get the recommended name */
  getName(): string { return this._name; }

  /** Get the original Symbol id */
  getSymbolId(): bigint { return this._symbolId; }
}

// ---------------------------------------------------------------------------
// TypeRecommend
// ---------------------------------------------------------------------------

/**
 * Data-type for a storage location when there is no Symbol (yet).
 *
 * Allow a data-type to be fed into a specific storage location. Currently
 * this only applies to input Varnodes.
 */
export class TypeRecommend {
  private addr: Address;
  private dataType: Datatype;

  constructor(ad: Address, dt: Datatype) {
    this.addr = new Address(ad);
    this.dataType = dt;
  }

  /** Get the storage address */
  getAddress(): Address { return this.addr; }

  /** Get the data-type */
  getType(): Datatype { return this.dataType; }
}

// ---------------------------------------------------------------------------
// RangeHint
// ---------------------------------------------------------------------------

/**
 * The basic categorization of the range.
 */
export enum RangeType {
  fixed = 0,      // A data-type with a fixed size
  open = 1,       // An array with a (possibly unknown) number of elements
  endpoint = 2,   // An (artificial) boundary to the range of bytes getting analyzed
}

/** Boolean properties for the range */
export const RANGEHINT_TYPELOCK = 1;
export const RANGEHINT_COPY_CONSTANT = 2;

/**
 * Partial data-type information mapped to a specific range of bytes.
 *
 * This object gives a hint about the data-type for a sequence of bytes
 * starting at a specific address offset (typically on the stack). It describes
 * where the data-type starts, what data-type it might be, and how far it extends
 * from the start point (possibly as an array).
 */
export class RangeHint {
  start: bigint = 0n;      // Starting offset of this range of bytes
  size: number = 0;        // Number of bytes in a single element of this range
  sstart: bigint = 0n;     // A signed version of the starting offset
  type: Datatype | null = null;  // Putative data-type for a single element of this range
  flags: number = 0;       // Additional boolean properties of this range
  rangeType: RangeType = RangeType.fixed;  // The type of range
  highind: number = 0;     // Minimum upper bound on the array index (if this is open)

  /** Uninitialized constructor */
  constructor();
  /** Initialized constructor */
  constructor(st: bigint, sz: number, sst: bigint, ct: Datatype, fl: number, rt: RangeType, hi: number);
  constructor(st?: bigint, sz?: number, sst?: bigint, ct?: Datatype, fl?: number, rt?: RangeType, hi?: number) {
    if (st !== undefined) {
      this.start = st;
      this.size = sz!;
      this.sstart = sst!;
      this.type = ct!;
      this.flags = fl!;
      this.rangeType = rt!;
      this.highind = hi!;
    }
  }

  /** Is the data-type for this range locked */
  isTypeLock(): boolean {
    return (this.flags & RANGEHINT_TYPELOCK) !== 0;
  }

  /**
   * Can another range be absorbed into this as a constant.
   *
   * This is assumed to be open. If this is a primitive integer or float, and if the other range
   * is just a constant being COPYed, return true, even if the constant is bigger.
   */
  isConstAbsorbable(b: RangeHint): boolean {
    if ((b.flags & RANGEHINT_COPY_CONSTANT) === 0)
      return false;
    if (b.isTypeLock())
      return false;
    if (b.size < this.size)
      return false;
    const meta = this.type!.getMetatype();
    if (meta !== TYPE_INT && meta !== TYPE_UINT && meta !== TYPE_BOOL && meta !== TYPE_FLOAT)
      return false;
    const bMeta = b.type!.getMetatype();
    if (bMeta !== TYPE_UNKNOWN && bMeta !== TYPE_INT && bMeta !== TYPE_UINT)
      return false;
    let end: bigint = this.sstart;
    if (this.highind > 0)
      end += BigInt(this.highind) * BigInt(this.type!.getAlignSize());
    else
      end += BigInt(this.size);
    if (b.sstart > end)
      return false;
    return true;
  }

  /**
   * Can the given intersecting RangeHint coexist with this at their given offsets.
   *
   * Determine if the data-type information in the two ranges line up
   * properly, in which case the union of the two ranges can exist without
   * destroying data-type information.
   */
  reconcile(b: RangeHint): boolean {
    let a: RangeHint = this;
    let bRef: RangeHint = b;
    if (a.type!.getAlignSize() < bRef.type!.getAlignSize()) {
      const tmp = bRef;
      bRef = a;
      a = tmp;
    }
    let mod: bigint = (bRef.sstart - a.sstart) % BigInt(a.type!.getAlignSize());
    if (mod < 0n)
      mod += BigInt(a.type!.getAlignSize());

    let sub: Datatype | null = a.type;
    while (sub !== null && sub.getAlignSize() > bRef.type!.getAlignSize()) {
      const result = { val: mod };
      sub = sub.getSubType(mod, result);
      mod = result.val;
    }

    if (sub !== null) {
      if (sub.getAlignSize() === bRef.type!.getAlignSize()) return true;
      // If we reach here, b overlaps multiple components of a
    }

    // If we reach here, component sizes do not match. Check for data-types we want to protect more
    if (bRef.rangeType === RangeType.open && bRef.isConstAbsorbable(a))
      return true;
    if (bRef.isTypeLock()) return false;
    const meta = a.type!.getMetatype();
    if (meta !== TYPE_STRUCT && meta !== TYPE_UNION) {
      if (meta !== TYPE_ARRAY || (a.type as any).getBase().getMetatype() !== TYPE_UNKNOWN)
        return false;
    }
    // For structures, unions, and arrays, test if b looks like a partial/combined data-type
    const bMeta = bRef.type!.getMetatype();
    if (bMeta === TYPE_UNKNOWN || bMeta === TYPE_INT || bMeta === TYPE_UINT) {
      return true;
    }
    return false;
  }

  /**
   * Return true if this or the given range contains the other.
   *
   * We assume this range starts at least as early as the given range
   * and that the two ranges intersect.
   */
  contain(b: RangeHint): boolean {
    if (this.sstart === b.sstart) return true;
    if (b.sstart + BigInt(b.size) - 1n <= this.sstart + BigInt(this.size) - 1n) return true;
    return false;
  }

  /**
   * Return true if this range's data-type is preferred over the other given range.
   *
   * A locked data-type is preferred over unlocked. A fixed size over open size.
   * Otherwise data-type ordering is used.
   */
  preferred(b: RangeHint, reconcileFlag: boolean): boolean {
    if (this.start !== b.start)
      return true;    // Something must occupy a.start to b.start
    // Prefer the locked type
    if (b.isTypeLock()) {
      if (!this.isTypeLock())
        return false;
    }
    else if (this.isTypeLock())
      return true;

    if (this.rangeType === RangeType.open && b.rangeType !== RangeType.open) {
      if (!reconcileFlag)
        return false;    // Throw out open range
      if (this.isConstAbsorbable(b))
        return true;
    }
    else if (b.rangeType === RangeType.open && this.rangeType !== RangeType.open) {
      if (!reconcileFlag)
        return true;     // Throw out open range
      if (b.isConstAbsorbable(this))
        return false;
    }
    else if (this.rangeType === RangeType.fixed && b.rangeType === RangeType.fixed) {
      if (this.size !== b.size && !reconcileFlag)
        return (this.size > b.size);
    }

    return (0 > this.type!.typeOrder(b.type!)); // Prefer the more specific
  }

  /**
   * Try to concatenate another RangeHint onto this.
   *
   * If this RangeHint is an array and the following RangeHint lines up, adjust this
   * so that it absorbs the other given RangeHint and return true.
   */
  attemptJoin(b: RangeHint): boolean {
    if (this.rangeType !== RangeType.open) return false;
    if (b.rangeType === RangeType.endpoint) return false;  // Don't merge with bounding range
    if (this.isConstAbsorbable(b)) {
      this.absorb(b);
      return true;
    }
    if (this.highind < 0) return false;
    let settype: Datatype = this.type!;
    if (settype.getAlignSize() !== b.type!.getAlignSize()) return false;
    if (settype !== b.type) {
      let aTestType: Datatype = this.type!;
      let bTestType: Datatype = b.type!;
      while (aTestType.getMetatype() === TYPE_PTR) {
        if (bTestType.getMetatype() !== TYPE_PTR)
          break;
        aTestType = (aTestType as any).getPtrTo();
        bTestType = (bTestType as any).getPtrTo();
      }
      if (aTestType.getMetatype() === TYPE_UNKNOWN)
        settype = b.type!;
      else if (bTestType.getMetatype() === TYPE_UNKNOWN) {
        // keep settype
      }
      else if (aTestType.getMetatype() === TYPE_INT && bTestType.getMetatype() === TYPE_UINT) {
        // keep settype
      }
      else if (aTestType.getMetatype() === TYPE_UINT && bTestType.getMetatype() === TYPE_INT) {
        // keep settype
      }
      else if (aTestType !== bTestType)  // If they are both not unknown, they must be the same
        return false;
    }
    if (this.isTypeLock()) return false;
    if (b.isTypeLock()) return false;
    let diffsz: bigint = b.sstart - this.sstart;
    if (diffsz % BigInt(settype.getAlignSize()) !== 0n) return false;
    diffsz = diffsz / BigInt(settype.getAlignSize());
    if (diffsz > BigInt(this.highind)) return false;
    this.type = settype;
    this.absorb(b);
    return true;
  }

  /**
   * Absorb the other RangeHint into this.
   *
   * Absorb details of the other RangeHint into this, except for the data-type. Inherit an open range
   * type and any indexing information.
   */
  absorb(b: RangeHint): void {
    if (b.rangeType === RangeType.open) {
      if (this.type!.getAlignSize() === b.type!.getAlignSize()) {
        this.rangeType = RangeType.open;
        if (0 <= b.highind) {
          let diffsz: bigint = b.sstart - this.sstart;
          diffsz = diffsz / BigInt(this.type!.getAlignSize());
          const trialhi: number = b.highind + Number(diffsz);
          if (this.highind < trialhi)
            this.highind = trialhi;
        }
      }
      else if (this.start === b.start) {
        const meta = this.type!.getMetatype();
        if (meta !== TYPE_STRUCT && meta !== TYPE_UNION)
          this.rangeType = RangeType.open;
      }
    }
    else if ((b.flags & RANGEHINT_COPY_CONSTANT) !== 0 && this.rangeType === RangeType.open) {
      const diffsz: bigint = b.sstart - this.sstart + BigInt(b.size);
      if (diffsz > BigInt(this.size)) {
        const trialhi: number = Number(diffsz / BigInt(this.type!.getAlignSize()));
        if (this.highind < trialhi)
          this.highind = trialhi;
      }
    }
    if ((this.flags & RANGEHINT_COPY_CONSTANT) !== 0 && (b.flags & RANGEHINT_COPY_CONSTANT) === 0) {
      this.flags ^= RANGEHINT_COPY_CONSTANT;
    }
  }

  /**
   * Try to form the union of this with another RangeHint.
   *
   * Given that this and the other RangeHint intersect, redefine this so that it
   * becomes the union of the two original ranges.
   */
  merge(b: RangeHint, space: AddrSpace, typeFactory: TypeFactory): boolean {
    let didReconcile: boolean;
    let resType: number;    // 0=this, 1=b, 2=confuse

    if (this.contain(b)) {
      didReconcile = this.reconcile(b);
      if (!didReconcile && this.start !== b.start)
        resType = 2;
      else
        resType = this.preferred(b, didReconcile) ? 0 : 1;
    }
    else {
      didReconcile = false;
      resType = this.isTypeLock() ? 0 : 2;
    }

    // Check for really problematic cases
    if (!didReconcile) {
      if (this.isTypeLock()) {
        if (b.isTypeLock())
          throw new LowlevelError("Overlapping forced variable types : " + this.type!.getName() + "   " + b.type!.getName());
        if (this.start !== b.start)
          return false;    // Discard b entirely
      }
    }

    if (resType === 0) {
      this.absorb(b);
    }
    else if (resType === 1) {
      const copyRange = new RangeHint(this.start, this.size, this.sstart, this.type!, this.flags, this.rangeType, this.highind);
      this.type = b.type;
      this.flags = b.flags;
      this.rangeType = b.rangeType;
      this.highind = b.highind;
      this.size = b.size;
      this.absorb(copyRange);
    }
    else if (resType === 2) {
      // Concede confusion about types, set unknown type rather than this or b's type
      this.flags = 0;
      this.rangeType = RangeType.fixed;
      const diff: number = Number(b.sstart - this.sstart);
      if (diff + b.size > this.size)
        this.size = diff + b.size;
      if (this.size !== 1 && this.size !== 2 && this.size !== 4 && this.size !== 8) {
        this.size = 1;
        this.rangeType = RangeType.open;
      }
      this.type = typeFactory.getBase(this.size, TYPE_UNKNOWN);
      this.flags = 0;
      this.highind = -1;
      return false;
    }
    return false;
  }

  /**
   * Order this with another RangeHint.
   *
   * Compare (signed) offset, size, RangeType, flags, and high index, in that order.
   * Datatype is not compared.
   */
  compare(op2: RangeHint): number {
    if (this.sstart !== op2.sstart)
      return (this.sstart < op2.sstart) ? -1 : 1;
    if (this.size !== op2.size)
      return (this.size < op2.size) ? -1 : 1;    // Small sizes come first
    if (this.rangeType !== op2.rangeType)
      return (this.rangeType < op2.rangeType) ? -1 : 1;
    if (this.flags !== op2.flags)
      return (this.flags < op2.flags) ? -1 : 1;
    if (this.highind !== op2.highind)
      return (this.highind < op2.highind) ? -1 : 1;
    return 0;
  }

  /** Compare two RangeHint pointers */
  static compareRanges(a: RangeHint, b: RangeHint): number {
    return a.compare(b);
  }
}

// ---------------------------------------------------------------------------
// AliasChecker
// ---------------------------------------------------------------------------

/**
 * A helper class holding a Varnode pointer reference and a possible index added to it.
 */
export class AddBase {
  base: any;    // Varnode
  index: any;   // Varnode or null

  constructor(b: any, i: any) {
    this.base = b;
    this.index = i;
  }
}

/**
 * A light-weight class for analyzing pointers and aliasing on the stack.
 *
 * The gather() method looks for pointer references into a specific AddressSpace
 * (usually the stack). Then hasLocalAlias() checks if a specific Varnode within
 * the AddressSpace is (possibly) aliased by one of the gathered pointer references.
 */
export class AliasChecker {
  private fd: Funcdata | null = null;
  private space: AddrSpace | null = null;
  private addBase_: AddBase[] = [];
  private alias_: bigint[] = [];
  private calculated: boolean = false;
  private localExtreme: bigint = 0n;
  private localBoundary: bigint = 0n;
  private aliasBoundary: bigint = 0n;
  private direction: number = 0;

  constructor() {
    this.fd = null;
    this.space = null;
    this.calculated = false;
  }

  /** Set up basic boundaries for the stack layout */
  private deriveBoundaries(proto: FuncProto): void {
    this.localExtreme = ~0n & 0xFFFFFFFFFFFFFFFFn;   // Default settings (equivalent to ~((uintb)0))
    this.localBoundary = 0x1000000n;
    if (this.direction === -1)
      this.localExtreme = this.localBoundary;

    if (proto.hasModel()) {
      const localrange: RangeList = proto.getLocalRange();
      const paramrange: RangeList = proto.getParamRange();

      const local: Range | null = localrange.getFirstRange();
      const param: Range | null = paramrange.getLastRange();
      if (local !== null && param !== null) {
        this.localBoundary = param.getLast();
        if (this.direction === -1) {
          this.localBoundary = paramrange.getFirstRange()!.getFirst();
          this.localExtreme = this.localBoundary;
        }
      }
    }
  }

  /**
   * Run through Varnodes looking for pointers into the stack.
   */
  private gatherInternal(): void {
    this.calculated = true;
    this.aliasBoundary = this.localExtreme;
    const spacebase = this.fd!.findSpacebaseInput(this.space);
    if (spacebase === null) return;  // No possible alias

    AliasChecker.gatherAdditiveBase(spacebase, this.addBase_);
    for (let i = 0; i < this.addBase_.length; i++) {
      let offset: bigint = AliasChecker.gatherOffset(this.addBase_[i].base);
      offset = AddrSpace.addressToByte(offset, this.space!.getWordSize()); // Convert to byte offset
      this.alias_.push(offset);
      if (this.direction === 1) {
        if (offset < this.localBoundary) continue;  // Parameter ref
      }
      else {
        if (offset > this.localBoundary) continue;  // Parameter ref
      }
      // Always consider anything AFTER a pointer reference as
      // aliased, regardless of the stack direction
      if (offset < this.aliasBoundary)
        this.aliasBoundary = offset;
    }
  }

  /**
   * Gather Varnodes that point on the stack.
   *
   * For the given function and address space, gather all Varnodes that are pointers into the
   * address space. The actual calculation can be deferred until the first time
   * hasLocalAlias() is called.
   */
  gather(f: Funcdata, spc: AddrSpace, defer: boolean): void {
    this.fd = f;
    this.space = spc;
    this.calculated = false;
    this.addBase_ = [];
    this.alias_ = [];
    this.direction = spc.stackGrowsNegative() ? 1 : -1;
    this.deriveBoundaries(this.fd.getFuncProto());
    if (!defer)
      this.gatherInternal();
  }

  /**
   * Return true if it looks like the given Varnode is aliased by a pointer.
   */
  hasLocalAlias(vn: any): boolean {
    if (vn === null) return false;
    if (!this.calculated)
      this.gatherInternal();
    if (vn.getSpace() !== this.space) return false;
    // For positive stack growth, this is not a good test because values being queued on the
    // stack to be passed to a subfunction always have offsets a little bit bigger than ALL
    // local variables on the stack
    if (this.direction === -1)
      return false;
    return (vn.getOffset() >= this.aliasBoundary);
  }

  /** Sort the alias starting offsets */
  sortAlias(): void {
    this.alias_.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  }

  /** Get the collection of pointer Varnodes */
  getAddBase(): AddBase[] { return this.addBase_; }

  /** Get the list of alias starting offsets */
  getAlias(): bigint[] { return this.alias_; }

  /**
   * Gather result Varnodes for all sums that the given starting Varnode is involved in.
   *
   * For every sum that involves startvn, collect the final result Varnode of the sum.
   * A sum is any expression involving only the additive operators
   * INT_ADD, INT_SUB, PTRADD, PTRSUB, and SEGMENTOP.
   */
  static gatherAdditiveBase(startvn: any, addbase: AddBase[]): void {
    const vnqueue: AddBase[] = [];
    let vn: any;
    let subvn: any;
    let indexvn: any;
    let othervn: any;
    let op: any;
    let nonadduse: boolean;
    let i = 0;

    vn = startvn;
    vn.setMark();
    vnqueue.push(new AddBase(vn, null));
    while (i < vnqueue.length) {
      vn = vnqueue[i].base;
      indexvn = vnqueue[i++].index;
      nonadduse = false;
      for (let d = 0; d < vn.descend.length; d++) {
        const op = vn.descend[d];
        switch (op.code()) {
          case CPUI_COPY:
            nonadduse = true;  // Treat COPY as both non-add use and part of ADD expression
            subvn = op.getOut();
            if (!subvn.isMark()) {
              subvn.setMark();
              vnqueue.push(new AddBase(subvn, indexvn));
            }
            break;
          case CPUI_INT_SUB:
            if (vn === op.getIn(1)) {   // Subtracting the pointer
              nonadduse = true;
              break;
            }
            othervn = op.getIn(1);
            if (!othervn.isConstant())
              indexvn = othervn;
            subvn = op.getOut();
            if (!subvn.isMark()) {
              subvn.setMark();
              vnqueue.push(new AddBase(subvn, indexvn));
            }
            break;
          case CPUI_INT_ADD:
          case CPUI_PTRADD:
            othervn = op.getIn(1);
            if (othervn === vn)
              othervn = op.getIn(0);
            if (!othervn.isConstant())
              indexvn = othervn;
            // fallthru
          case CPUI_PTRSUB:
          case CPUI_SEGMENTOP:
            subvn = op.getOut();
            if (!subvn.isMark()) {
              subvn.setMark();
              vnqueue.push(new AddBase(subvn, indexvn));
            }
            break;
          default:
            nonadduse = true;   // Used in non-additive expression
        }
      }
      if (nonadduse)
        addbase.push(new AddBase(vn, indexvn));
    }
    for (i = 0; i < vnqueue.length; i++)
      vnqueue[i].base.clearMark();
  }

  /**
   * If the given Varnode is a sum result, return the constant portion of this sum.
   *
   * Treat vn as the result of a series of ADD operations.
   * Examine all the constant terms of this sum and add them together.
   */
  static gatherOffset(vn: any): bigint {
    let retval: bigint;
    let othervn: any;

    if (vn.isConstant()) return vn.getOffset();
    const def = vn.getDef();
    if (def === null) return 0n;
    switch (def.code()) {
      case CPUI_COPY:
        retval = AliasChecker.gatherOffset(def.getIn(0));
        break;
      case CPUI_PTRSUB:
      case CPUI_INT_ADD:
        retval = AliasChecker.gatherOffset(def.getIn(0));
        retval += AliasChecker.gatherOffset(def.getIn(1));
        break;
      case CPUI_INT_SUB:
        retval = AliasChecker.gatherOffset(def.getIn(0));
        retval -= AliasChecker.gatherOffset(def.getIn(1));
        break;
      case CPUI_PTRADD:
        othervn = def.getIn(2);
        retval = AliasChecker.gatherOffset(def.getIn(0));
        if (def.getIn(1).isConstant())
          retval = retval + BigInt(def.getIn(1).getOffset()) * BigInt(othervn.getOffset());
        else if (othervn.getOffset() === 1n) {
          retval = retval + AliasChecker.gatherOffset(def.getIn(1));
        }
        break;
      case CPUI_SEGMENTOP:
        retval = AliasChecker.gatherOffset(def.getIn(2));
        break;
      default:
        retval = 0n;
    }
    return retval & calc_mask(vn.getSize());
  }
}

// ---------------------------------------------------------------------------
// MapState
// ---------------------------------------------------------------------------

/**
 * A container for hints about the data-type layout of an address space.
 *
 * A collection of data-type hints for the address space (as RangeHint objects) can
 * be collected from Varnodes, HighVariables or other sources, using the
 * gatherVarnodes(), gatherHighs(), and gatherOpen() methods. This class can then sort
 * and iterate through the RangeHint objects.
 */
export class MapState {
  private spaceid: AddrSpace;
  private range: RangeList;
  private maplist: RangeHint[] = [];
  private iterIndex: number = 0;
  private defaultType: Datatype;
  private checker: AliasChecker = new AliasChecker();

  /**
   * Constructor.
   * @param spc is the address space being analyzed
   * @param rn is the subset of ranges within the whole address space to analyze
   * @param pm is subset of ranges within the address space considered to be parameters
   * @param dt is the default data-type
   */
  constructor(spc: AddrSpace, rn: RangeList, pm: RangeList, dt: Datatype) {
    this.spaceid = spc;
    this.range = new RangeList(rn);
    this.defaultType = dt;
    const pmRanges = pm.getRanges();
    for (const r of pmRanges) {
      const pmSpc = r.getSpace();
      const first = r.getFirst();
      const last = r.getLast();
      this.range.removeRange(pmSpc, first, last);  // Clear possible input symbols
    }
  }

  /**
   * Add LoadGuard record as a hint to the collection.
   */
  private addGuard(guard: LoadGuard, opc: OpCode, typeFactory: TypeFactory): void {
    if (!guard.isValid(opc)) return;
    const step: number = guard.getStep();
    if (step === 0) return;    // No definitive sign of array access
    let ct: Datatype = guard.getOp().getIn(1).getTypeReadFacing(guard.getOp());
    if (ct.getMetatype() === TYPE_PTR) {
      ct = (ct as any).getPtrTo();
      while (ct.getMetatype() === TYPE_ARRAY)
        ct = (ct as any).getBase();
    }
    let outSize: number;
    if (opc === CPUI_STORE)
      outSize = guard.getOp().getIn(2).getSize();   // The Varnode being stored
    else
      outSize = guard.getOp().getOut().getSize();    // The Varnode being loaded
    if (outSize !== step) {
      if (outSize > step || (step % outSize) !== 0)
        return;
      step; // Since step is const we just use outSize below
    }
    let finalStep = step;
    if (outSize !== step) {
      finalStep = outSize;
    }
    if (ct.getAlignSize() !== finalStep) {
      if (finalStep > 8)
        return;
      ct = typeFactory.getBase(finalStep, TYPE_UNKNOWN);
    }
    if (guard.isRangeLocked()) {
      const minItems: number = Math.floor((Number(guard.getMaximum() - guard.getMinimum()) + 1) / finalStep);
      this.addRange(guard.getMinimum(), ct, 0, RangeType.open, minItems - 1);
    }
    else
      this.addRange(guard.getMinimum(), ct, 0, RangeType.open, 3);
  }

  /**
   * Add a hint to the collection.
   */
  private addRange(st: bigint, ct: Datatype | null, fl: number, rt: RangeType, hi: number): void {
    if (ct === null || ct.getSize() === 0)
      ct = this.defaultType;
    const sz: number = ct.getSize();
    if (!this.range.inRange(new Address(this.spaceid, st), sz))
      return;
    let sst: bigint = AddrSpace.byteToAddress(st, this.spaceid.getWordSize());
    sst = sign_extend(sst, this.spaceid.getAddrSize() * 8 - 1);
    sst = AddrSpace.addressToByte(sst, this.spaceid.getWordSize());
    const newRange = new RangeHint(st, sz, sst, ct, fl, rt, hi);
    this.maplist.push(newRange);
  }

  /**
   * Add a fixed reference to a specific data-type.
   *
   * If the data-type is an array, partial struct, or partial union, the reference may be added as open.
   */
  private addFixedType(start: bigint, ct: Datatype, flags: number, types: TypeFactory): void {
    if (ct.getMetatype() === TYPE_PARTIALSTRUCT) {
      const tps = ct as any;
      ct = tps.getParent();
      if (ct.getMetatype() === TYPE_STRUCT && tps.getOffset() === 0) {
        this.addRange(start, ct, 0, RangeType.open, -1);
      }
      else if (ct.getMetatype() === TYPE_ARRAY) {
        ct = (ct as any).getBase();
        if (ct.getMetatype() !== TYPE_UNKNOWN)
          this.addRange(start, ct, 0, RangeType.open, -1);
      }
      // If the Varnode is a constant COPY, generate a fixed reference as well
      if (flags !== 0) {
        ct = types.getBase(tps.getSize(), TYPE_UNKNOWN);
        this.addRange(start, ct, flags, RangeType.fixed, -1);
      }
    }
    else if (ct.getMetatype() === TYPE_PARTIALUNION) {
      const tpu = ct as any;
      if (tpu.getOffset() === 0) {
        ct = tpu.getParentUnion();
        this.addRange(start, ct, 0, RangeType.open, -1);
      }
    }
    else {
      this.addRange(start, ct, flags, RangeType.fixed, -1);
    }
  }

  /**
   * Decide on data-type for RangeHints at the same address.
   *
   * Assuming a sorted list, from among a sequence of RangeHints with the same start and size, select
   * the most specific data-type.
   */
  private reconcileDatatypes(): void {
    const newList: RangeHint[] = [];
    newList.length = 0;
    let startPos = 0;
    let startHint = this.maplist[0];
    let startDatatype: Datatype = startHint.type!;
    newList.push(startHint);
    let curPos = 1;
    while (curPos < this.maplist.length) {
      const curHint = this.maplist[curPos++];
      if (curHint.start === startHint.start && curHint.size === startHint.size && curHint.flags === startHint.flags) {
        const curDatatype = curHint.type!;
        if (curDatatype.typeOrder(startDatatype) < 0)
          startDatatype = curDatatype;
        if (curHint.compare(newList[newList.length - 1]) !== 0)
          newList.push(curHint);
        // else: RangeHint is on the heap (GC handles cleanup)
      }
      else {
        while (startPos < newList.length) {
          newList[startPos].type = startDatatype;
          startPos += 1;
        }
        startHint = curHint;
        startDatatype = startHint.type!;
        newList.push(startHint);
      }
    }
    while (startPos < newList.length) {
      newList[startPos].type = startDatatype;
      startPos += 1;
    }
    this.maplist = newList;
  }

  /**
   * Filter out INDIRECT, MULTIEQUAL, and PIECE operations that are just copying between the same
   * storage location. If there is another operation reading the Varnode, return true.
   */
  private static isReadActive(vn: any): boolean {
    for (let d = 0; d < vn.descend.length; d++) {
      const op = vn.descend[d];
      if (op.isMarker()) {
        if (!vn.getAddr().equals(op.getOut().getAddr()))
          return true;
      }
      else {
        const opc = op.code();
        if (opc === CPUI_PIECE) {
          let addr: Address = op.getOut().getAddr();
          const slot = addr.isBigEndian() ? 0 : 1;
          if (op.getIn(slot) !== vn) {
            addr = addr.add(BigInt(op.getIn(slot).getSize()));
          }
          if (!vn.getAddr().equals(addr))
            return true;
        }
        else if (opc === CPUI_SUBPIECE) {
          // Any data-type information comes from the output Varnode, so we ignore input
        }
        else {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Sort the collection and add a special terminating RangeHint.
   * @return true if the collection isn't empty (and iteration can begin)
   */
  initialize(): boolean {
    const lastrange = this.range.getLastSignedRange(this.spaceid);
    if (lastrange === null) return false;
    if (this.maplist.length === 0) return false;
    const high: bigint = this.spaceid.wrapOffset(lastrange.getLast() + 1n);
    let sst: bigint = AddrSpace.byteToAddress(high, this.spaceid.getWordSize());
    sst = sign_extend(sst, this.spaceid.getAddrSize() * 8 - 1);
    sst = AddrSpace.addressToByte(sst, this.spaceid.getWordSize());
    // Add extra range to bound any final open entry
    const termRange = new RangeHint(high, 1, sst, this.defaultType, 0, RangeType.endpoint, -2);
    this.maplist.push(termRange);

    // stable_sort equivalent
    this.maplist.sort((a, b) => RangeHint.compareRanges(a, b));
    this.reconcileDatatypes();
    this.iterIndex = 0;
    return true;
  }

  /** Sort the alias starting offsets */
  sortAlias(): void { this.checker.sortAlias(); }

  /** Get the list of alias starting offsets */
  getAlias(): bigint[] { return this.checker.getAlias(); }

  /**
   * Add Symbol information as hints to the collection.
   */
  gatherSymbols(rangemap: EntryMap | null): void {
    if (rangemap === null) return;
    const list = (rangemap as any).getList();
    for (const entry of list) {
      const sym = entry.getSymbol();
      if (sym === null) continue;
      const start: bigint = entry.getAddr().getOffset();
      const ct: Datatype = sym.getType();
      const flags: number = sym.isTypeLocked() ? RANGEHINT_TYPELOCK : 0;
      this.addRange(start, ct, flags, RangeType.fixed, -1);
    }
  }

  /**
   * Add stack Varnodes as hints to the collection.
   */
  gatherVarnodes(fd: Funcdata): void {
    const types: TypeFactory = fd.getArch().types;
    const riter = fd.beginLoc(this.spaceid);
    const iterend = fd.endLoc(this.spaceid);

    let vnIter = riter;
    while (!vnIter.equals(iterend)) {
      const vn = vnIter.get();
      vnIter.next();
      if (vn.isFree()) continue;
      if (!vn.isWritten()) {
        if (MapState.isReadActive(vn))
          this.addFixedType(vn.getOffset(), vn.getType(), 0, types);
        continue;
      }
      const op = vn.getDef();
      switch (op.code()) {
        case CPUI_INDIRECT:
        {
          const invn = op.getIn(0);
          if (!vn.getAddr().equals(invn.getAddr()) || MapState.isReadActive(vn)) {
            this.addFixedType(vn.getOffset(), vn.getType(), 0, types);
          }
          break;
        }
        case CPUI_MULTIEQUAL:
        {
          let i: number;
          for (i = 0; i < op.numInput(); ++i) {
            const invn = op.getIn(i);
            if (!vn.getAddr().equals(invn.getAddr()))
              break;
          }
          if (i !== op.numInput() || MapState.isReadActive(vn))
            this.addFixedType(vn.getOffset(), vn.getType(), 0, types);
          break;
        }
        case CPUI_PIECE:
        {
          // Treat PIECE as two COPYs
          let addr: Address = vn.getAddr();
          const slot = addr.isBigEndian() ? 0 : 1;
          const inFirst = op.getIn(slot);
          if (!inFirst.getAddr().equals(addr))
            this.addFixedType(addr.getOffset(), inFirst.getType(), 0, types);
          addr = addr.add(BigInt(inFirst.getSize()));
          const inSecond = op.getIn(1 - slot);
          if (!inSecond.getAddr().equals(addr))
            this.addFixedType(addr.getOffset(), inSecond.getType(), 0, types);
          if (MapState.isReadActive(vn))
            this.addFixedType(vn.getOffset(), vn.getType(), 0, types);
          break;
        }
        case CPUI_SUBPIECE:
        {
          let addr: Address = op.getIn(0).getAddr();
          let trunc: number;
          if (addr.isBigEndian()) {
            trunc = op.getIn(0).getSize() - vn.getSize() - Number(op.getIn(1).getOffset());
          }
          else {
            trunc = Number(op.getIn(1).getOffset());
          }
          addr = addr.add(BigInt(trunc));
          if (!addr.equals(vn.getAddr()) || MapState.isReadActive(vn)) {
            this.addFixedType(vn.getOffset(), vn.getType(), 0, types);
          }
          break;
        }
        case CPUI_COPY:
          this.addFixedType(vn.getOffset(), vn.getType(), op.getIn(0).isConstant() ? RANGEHINT_COPY_CONSTANT : 0, types);
          break;
        default:
          this.addFixedType(vn.getOffset(), vn.getType(), 0, types);
          break;
      }
    }
  }

  /**
   * Add pointer references as hints to the collection.
   *
   * For any Varnode that looks like a pointer into our address space, create an
   * open RangeHint.
   */
  gatherOpen(fd: Funcdata): void {
    this.checker.gather(fd, this.spaceid, false);

    const addbase = this.checker.getAddBase();
    const alias = this.checker.getAlias();

    for (let i = 0; i < addbase.length; i++) {
      const offset = alias[i];
      let ct: Datatype | null = addbase[i].base.getType();
      if (ct!.getMetatype() === TYPE_PTR) {
        ct = (ct as any).getPtrTo();
        while (ct!.getMetatype() === TYPE_ARRAY)
          ct = (ct as any).getBase();
      }
      else
        ct = null;   // Do unknown array
      let minItems: number;
      if (addbase[i].index !== null) {
        minItems = 3;   // If there is an index, assume it takes on at least the 4 values [0,3]
      }
      else {
        minItems = -1;
      }
      this.addRange(offset, ct, 0, RangeType.open, minItems);
    }

    const typeFactory: TypeFactory = fd.getArch().types;
    const loadGuard = fd.getLoadGuards();
    for (const guard of loadGuard)
      this.addGuard(guard, CPUI_LOAD, typeFactory);

    const storeGuard = fd.getStoreGuards();
    for (const guard of storeGuard)
      this.addGuard(guard, CPUI_STORE, typeFactory);
  }

  /** Get the current RangeHint in the collection */
  next(): RangeHint { return this.maplist[this.iterIndex]; }

  /** Advance the iterator, return true if another hint is available */
  getNext(): boolean {
    this.iterIndex++;
    if (this.iterIndex >= this.maplist.length) return false;
    return true;
  }
}

// ---------------------------------------------------------------------------
// ScopeLocal
// ---------------------------------------------------------------------------

/**
 * A Symbol scope for local variables of a particular function.
 *
 * This acts like any other variable Scope, but is associated with a specific function
 * and the address space where the function maps its local variables and parameters, typically
 * the stack space. This object in addition to managing the local Symbols, builds up information
 * about the stack address space: what portions of it are used for mapped local variables, what
 * portions are used for temporary storage (not mapped), and what portion is for parameters.
 */
export class ScopeLocal extends ScopeInternal {
  /** The Funcdata this scope is attached to */
  protected fd: Funcdata;

  // ScopeLocal-specific fields
  private space: AddrSpace;
  private nameRecommend_: NameRecommend[] = [];
  private dynRecommend_: DynamicRecommend[] = [];
  private typeRecommend_: TypeRecommend[] = [];
  private minParamOffset: bigint;
  private maxParamOffset: bigint;
  private stackGrowsNegative_: boolean;
  private rangeLocked_: boolean;
  private overlapProblems_: boolean;

  /**
   * Constructor.
   * @param id is the globally unique id associated with the function scope
   * @param spc is the (stack) address space associated with this function's local variables
   * @param fd is the function associated with these local variables
   * @param g is the Architecture
   */
  constructor(id: bigint, spc: AddrSpace, fd: Funcdata, g: Architecture) {
    super(id, fd.getName ? fd.getName() : "", g);
    this.fd = fd;
    this.space = spc;
    this.minParamOffset = ~0n & 0xFFFFFFFFFFFFFFFFn;
    this.maxParamOffset = 0n;
    this.rangeLocked_ = false;
    this.stackGrowsNegative_ = true;
    this.overlapProblems_ = false;
  }

  /** Get the associated (stack) address space */
  getSpaceId(): AddrSpace { return this.space; }

  /** Return true if restructure analysis discovered overlapping variables */
  hasOverlapProblems(): boolean { return this.overlapProblems_; }

  /**
   * Is this a storage location for unaffected registers.
   * @param vn is the Varnode storing an unaffected register
   * @return true if the Varnode can be used as unaffected storage
   */
  isUnaffectedStorage(vn: any): boolean { return (vn.getSpace() === this.space); }

  /**
   * Check if a given unmapped Varnode should be treated as unaliased.
   *
   * Currently we treat all unmapped Varnodes as not having an alias, unless the Varnode is on the stack
   * and the location is also used to pass parameters.
   */
  isUnmappedUnaliased(vn: any): boolean {
    if (vn.getSpace() !== this.space) return false;
    if (this.maxParamOffset < this.minParamOffset) return true;
    if (vn.getOffset() < this.minParamOffset || vn.getOffset() > this.maxParamOffset)
      return true;
    return false;
  }

  /**
   * Mark a specific address range as not mapped.
   *
   * The given range can no longer hold a mapped local variable. This indicates the range
   * is being used for temporary storage.
   */
  markNotMapped(spc: AddrSpace, first: bigint, sz: number, parameter: boolean): void {
    if (this.space !== spc) return;
    let last: bigint = first + BigInt(sz) - 1n;
    if (last < first)
      last = spc.getHighest();
    else if (last > spc.getHighest())
      last = spc.getHighest();
    if (parameter) {
      if (first < this.minParamOffset)
        this.minParamOffset = first;
      if (last > this.maxParamOffset)
        this.maxParamOffset = last;
    }
    const addr = new Address(this.space, first);
    // Remove any symbols under range
    let overlap: SymbolEntry | null = this.findOverlap(addr, sz);
    while (overlap !== null) {
      const sym = overlap.getSymbol();
      if ((sym.getFlags() & Varnode.typelock) !== 0) {
        if ((!parameter) || (sym.getCategory() !== Symbol.function_parameter))
          this.fd.warningHeader("Variable defined which should be unmapped: " + sym.getName());
        return;
      }
      else if (sym.getCategory() === Symbol.fake_input) {
        return;   // Inputs in the stack space should not be unmapped
      }
      this.removeSymbol(sym);
      overlap = this.findOverlap(addr, sz);
    }
    this.glb.symboltab.removeRange(this, this.space, first, last);
  }

  /**
   * Encode this scope to a stream.
   */
  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_LOCALDB);
    encoder.writeSpace(ATTRIB_MAIN, this.space);
    encoder.writeBool(ATTRIB_LOCK, this.rangeLocked_);
    super.encode(encoder);
    encoder.closeElement(ELEM_LOCALDB);
  }

  /**
   * Decode this scope from a stream.
   */
  decode(decoder: Decoder): void {
    super.decode(decoder);
    this.collectNameRecs();
  }

  /**
   * Decode wrapping attributes from a stream.
   */
  decodeWrappingAttributes(decoder: Decoder): void {
    this.rangeLocked_ = false;
    if (decoder.readBoolById(ATTRIB_LOCK))
      this.rangeLocked_ = true;
    this.space = decoder.readSpaceById(ATTRIB_MAIN) as any as AddrSpace;
  }

  /**
   * Build a variable name based on its address and context.
   */
  buildVariableName(addr: Address, pc: Address, ct: Datatype | null, index: { val: number }, flags: number): string {
    if (((flags & (Varnode.addrtied | Varnode.persist)) === Varnode.addrtied) &&
        addr.getSpace() === this.space) {
      if (this.fd.getFuncProto().getLocalRange().inRange(addr, 1)) {
        let start: bigint = AddrSpace.byteToAddress(addr.getOffset(), this.space.getWordSize());
        start = sign_extend(start, addr.getAddrSize() * 8 - 1);
        if (this.stackGrowsNegative_)
          start = -start;
        let s = '';
        if (ct !== null) {
          const sw = new StringWriter();
          ct.printNameBase(sw);
          s += sw.toString();
        }
        let spacename = addr.getSpace()!.getName();
        spacename = spacename.charAt(0).toUpperCase() + spacename.slice(1);
        s += spacename;
        if (start <= 0n) {
          s += 'X';    // Indicate local stack space allocated by caller
          start = -start;
        }
        else {
          if ((this.minParamOffset < this.maxParamOffset) &&
              (this.stackGrowsNegative_ ? (addr.getOffset() < this.minParamOffset) : (addr.getOffset() > this.maxParamOffset))) {
            s += 'Y';   // Indicate unusual region of stack
          }
        }
        s += '_' + start.toString(16);
        return this.makeNameUnique(s);
      }
    }
    return super.buildVariableName(addr, pc, ct!, index, flags);
  }

  /**
   * Reset the set of addresses that are considered mapped by the scope to the default.
   */
  resetLocalWindow(): void {
    this.stackGrowsNegative_ = this.fd.getFuncProto().isStackGrowsNegative();
    this.minParamOffset = ~0n & 0xFFFFFFFFFFFFFFFFn;
    this.maxParamOffset = 0n;

    if (this.rangeLocked_) return;

    const localRange: RangeList = this.fd.getFuncProto().getLocalRange();
    const paramrange: RangeList = this.fd.getFuncProto().getParamRange();

    const newrange = new RangeList();

    const localRanges = localRange.getRanges();
    for (const r of localRanges) {
      const spc = r.getSpace();
      const first = r.getFirst();
      const last = r.getLast();
      newrange.insertRange(spc, first, last);
    }
    const paramRanges = paramrange.getRanges();
    for (const r of paramRanges) {
      const spc = r.getSpace();
      const first = r.getFirst();
      const last = r.getLast();
      newrange.insertRange(spc, first, last);
    }
    this.glb.symboltab.setRange(this, newrange);
  }

  /**
   * Layout mapped symbols based on Varnode information.
   *
   * Define stack Symbols based on Varnodes.
   */
  restructureVarnode(aliasyes: boolean): void {
    this.clearUnlockedCategory(-1);
    const state = new MapState(this.space, this.getRangeTree(), this.fd.getFuncProto().getParamRange(),
      this.glb.types.getBase(1, TYPE_UNKNOWN));

    state.gatherVarnodes(this.fd);
    state.gatherOpen(this.fd);
    state.gatherSymbols(this.maptable[this.space.getIndex()]);
    this.overlapProblems_ = this.restructure(state);

    this.clearUnlockedCategory(Symbol.function_parameter);
    this.clearCategory(Symbol.fake_input);
    this.fakeInputSymbols();

    state.sortAlias();
    if (aliasyes) {
      this.markUnaliased(state.getAlias());
      this.checkUnaliasedReturn(state.getAlias());
    }
    if (state.getAlias().length > 0 && state.getAlias()[0] === 0n)
      this.annotateRawStackPtr();
  }

  /**
   * Change the primary mapping for the given Symbol to be a specific storage address and use point.
   */
  remapSymbol(sym: Symbol, addr: Address, usepoint: Address): SymbolEntry {
    let entry: SymbolEntry = sym.getFirstWholeMap();
    const size: number = entry.getSize();
    if (!entry.isDynamic()) {
      if (entry.getAddr().equals(addr)) {
        if (usepoint.isInvalid() && entry.getFirstUseAddress().isInvalid())
          return entry;
        if (entry.getFirstUseAddress().equals(usepoint))
          return entry;
      }
    }
    this.removeSymbolMappings(sym);
    const rnglist = new RangeList();
    if (!usepoint.isInvalid())
      rnglist.insertRange(usepoint.getSpace()!, usepoint.getOffset(), usepoint.getOffset());
    return this.addMapInternal(sym, Varnode.mapped, addr, 0, size, rnglist);
  }

  /**
   * Make the primary mapping for the given Symbol, dynamic.
   */
  remapSymbolDynamic(sym: Symbol, hash: bigint, usepoint: Address): SymbolEntry {
    let entry: SymbolEntry = sym.getFirstWholeMap();
    const size: number = entry.getSize();
    if (entry.isDynamic()) {
      if (entry.getHash() === hash && entry.getFirstUseAddress().equals(usepoint))
        return entry;
    }
    this.removeSymbolMappings(sym);
    const rnglist = new RangeList();
    if (!usepoint.isInvalid())
      rnglist.insertRange(usepoint.getSpace()!, usepoint.getOffset(), usepoint.getOffset());
    return this.addDynamicMapInternal(sym, Varnode.mapped, hash, 0, size, rnglist);
  }

  /**
   * Run through name recommendations, checking if any match unnamed symbols.
   */
  recoverNameRecommendationsForSymbols(): void {
    const param_usepoint = this.fd.getAddress().subtract(1n);
    for (const rec of this.nameRecommend_) {
      const addr = rec.getAddr();
      const usepoint = rec.getUseAddr();
      const size = rec.getSize();
      let sym: Symbol;
      let vn: any = null;
      if (usepoint.isInvalid()) {
        const entry: SymbolEntry | null = this.findOverlap(addr, size);
        if (entry === null) continue;
        if (!entry.getAddr().equals(addr))
          continue;
        sym = entry.getSymbol();
        if ((sym.getFlags() & Varnode.addrtied) === 0)
          continue;
        vn = this.fd.findLinkedVarnode(entry);
      }
      else {
        if (usepoint.equals(param_usepoint))
          vn = this.fd.findVarnodeInput(size, addr);
        else
          vn = this.fd.findVarnodeWritten(size, addr, usepoint);
        if (vn === null) continue;
        sym = vn.getHigh().getSymbol();
        if (sym === null) continue;
        if ((sym.getFlags() & Varnode.addrtied) !== 0)
          continue;
        const entry = sym.getFirstWholeMap();
        if (entry.getSize() !== size) continue;
      }
      if (!sym.isNameUndefined()) continue;
      this.renameSymbol(sym, this.makeNameUnique(rec.getName()));
      this.setSymbolId(sym, rec.getSymbolId());
      this.setAttribute(sym, Varnode.namelock);
      if (vn !== null) {
        this.fd.remapVarnode(vn, sym, usepoint);
      }
    }

    if (this.dynRecommend_.length === 0) return;

    const dhash = new DynamicHash();
    for (const dynEntry of this.dynRecommend_) {
      dhash.clear();
      const vn = dhash.findVarnode(this.fd, dynEntry.getAddress(), dynEntry.getHash());
      if (vn === null) continue;
      if (vn.isAnnotation()) continue;
      const sym = vn.getHigh().getSymbol();
      if (sym === null) continue;
      if (sym.getScope() !== this) continue;
      if (!sym.isNameUndefined()) continue;
      this.renameSymbol(sym, this.makeNameUnique(dynEntry.getName()));
      this.setAttribute(sym, Varnode.namelock);
      this.setSymbolId(sym, dynEntry.getSymbolId());
      this.fd.remapDynamicVarnode(vn, sym, dynEntry.getAddress(), dynEntry.getHash());
    }
  }

  /**
   * Try to apply recommended data-type information.
   */
  applyTypeRecommendations(): void {
    for (const rec of this.typeRecommend_) {
      const dt = rec.getType();
      const vn = this.fd.findVarnodeInput(dt.getSize(), rec.getAddress());
      if (vn !== null)
        vn.updateType(dt, true, false);
    }
  }

  /** Are there data-type recommendations */
  hasTypeRecommendations(): boolean { return this.typeRecommend_.length > 0; }

  /**
   * Add a new data-type recommendation.
   */
  addTypeRecommendation(addr: Address, dt: Datatype): void {
    this.typeRecommend_.push(new TypeRecommend(addr, dt));
  }

  // -----------------------------------------------------------------------
  // Private methods
  // -----------------------------------------------------------------------

  /**
   * Make the given RangeHint fit in the current Symbol map.
   */
  private adjustFit(a: RangeHint): boolean {
    if (a.size === 0) return false;
    if (a.isTypeLock()) return false;
    const addr = new Address(this.space, a.start);
    let maxsize: bigint = this.getRangeTree().longestFit(addr, BigInt(a.size));
    if (maxsize === 0n) return false;
    if (maxsize < BigInt(a.size)) {
      if (maxsize < BigInt(a.type!.getSize())) return false;
      a.size = Number(maxsize);
    }
    const entry = this.findOverlap(addr, a.size);
    if (entry === null)
      return true;
    if (entry.getAddr().lessEqual(addr)) {
      return false;
    }
    maxsize = entry.getAddr().getOffset() - a.start;
    if (maxsize < BigInt(a.type!.getSize())) return false;
    a.size = Number(maxsize);
    return true;
  }

  /**
   * Create a Symbol entry corresponding to the given (fitted) RangeHint.
   */
  private createEntry(a: RangeHint): void {
    const addr = new Address(this.space, a.start);
    const usepoint = new Address();
    let ct: Datatype = this.glb.types.concretize(a.type);
    const num = Math.floor(a.size / ct.getAlignSize());
    if (num > 1)
      ct = this.glb.types.getTypeArray(num, ct);
    this.addSymbol("", ct, addr, usepoint);
  }

  /**
   * Merge hints into a formal Symbol layout of the address space.
   */
  private restructure(state: MapState): boolean {
    let cur: RangeHint;
    let next: RangeHint;
    let overlapProblems = false;
    if (!state.initialize())
      return overlapProblems;

    const firstHint = state.next();
    cur = new RangeHint(firstHint.start, firstHint.size, firstHint.sstart, firstHint.type!, firstHint.flags, firstHint.rangeType, firstHint.highind);
    while (state.getNext()) {
      next = state.next();
      if (next.sstart < cur.sstart + BigInt(cur.size)) {
        if (cur.merge(next, this.space, this.glb.types))
          overlapProblems = true;
      }
      else {
        if (!cur.attemptJoin(next)) {
          if (cur.rangeType === RangeType.open)
            cur.size = Number(next.sstart - cur.sstart);
          if (this.adjustFit(cur))
            this.createEntry(cur);
          cur = new RangeHint(next.start, next.size, next.sstart, next.type!, next.flags, next.rangeType, next.highind);
        }
      }
    }
    // The last range is artificial so we don't build an entry for it
    return overlapProblems;
  }

  /**
   * Mark all local symbols for which there are no aliases.
   */
  private markUnaliased(alias: bigint[]): void {
    const rangemap: EntryMap | null = this.maptable[this.space.getIndex()];
    if (rangemap === null) return;
    const entryList = (rangemap as any).getList();

    const rangeRanges = this.getRangeTree().getRanges();
    let rangeIdx = 0;

    const alias_block_level: number = this.glb.alias_block_level;
    let aliason = false;
    let curalias: bigint = 0n;
    let i = 0;

    for (const entry of entryList) {
      const curoff: bigint = entry.getAddr().getOffset() + BigInt(entry.getSize()) - 1n;
      while ((i < alias.length) && (alias[i] <= curoff)) {
        aliason = true;
        curalias = alias[i++];
      }
      // Aliases shouldn't go thru unmapped regions of the local variables
      while (rangeIdx < rangeRanges.length) {
        const rng = rangeRanges[rangeIdx];
        if (rng.getSpace() === this.space) {
          if (rng.getFirst() > curalias && curoff >= rng.getFirst())
            aliason = false;
          if (rng.getLast() >= curoff) break;
          if (rng.getLast() > curalias)
            aliason = false;
        }
        rangeIdx++;
      }
      const symbol = entry.getSymbol();
      if (aliason && (curoff - curalias > 0xFFFFn)) aliason = false;
      if (!aliason) symbol.getScope().setAttribute(symbol, Varnode.nolocalalias);
      if (symbol.isTypeLocked() && alias_block_level !== 0) {
        if (alias_block_level === 3)
          aliason = false;
        else {
          const meta = symbol.getType().getMetatype();
          if (meta === TYPE_STRUCT)
            aliason = false;
          else if (meta === TYPE_ARRAY && alias_block_level > 1) aliason = false;
        }
      }
    }
  }

  /**
   * Make sure all stack inputs have an associated Symbol.
   */
  private fakeInputSymbols(): void {
    const lockedinputs: number = this.getCategorySize(Symbol.function_parameter);
    let iter = this.fd.beginDefFlags(Varnode.input);
    const enditer = this.fd.endDefFlags(Varnode.input);

    while (!iter.equals(enditer)) {
      let vn: Varnode = iter.get();
      iter.next();
      let locked = vn.isTypeLock();
      const addr = vn.getAddr();
      if (addr.getSpace() !== this.space) continue;
      if (!this.fd.getFuncProto().getParamRange().inRange(addr, 1)) continue;
      let endpoint: bigint = addr.getOffset() + BigInt(vn.getSize()) - 1n;
      while (!iter.equals(enditer)) {
        vn = iter.get();
        if (vn.getSpace() !== this.space) break;
        if (endpoint < vn.getOffset()) break;
        const newendpoint = vn.getOffset() + BigInt(vn.getSize()) - 1n;
        if (endpoint < newendpoint)
          endpoint = newendpoint;
        if (vn.isTypeLock())
          locked = true;
        iter.next();
      }
      if (!locked) {
        const usepoint = new Address();
        if (lockedinputs !== 0) {
          const qresult = this.queryProperties(vn.getAddr(), vn.getSize(), usepoint);
          if (qresult.entry !== null) {
            if (qresult.entry.getSymbol().getCategory() === Symbol.function_parameter)
              continue;
          }
        }
        const size = Number(endpoint - addr.getOffset()) + 1;
        const ct = this.fd.getArch().types.getBase(size, TYPE_UNKNOWN);
        try {
          const sym = this.addSymbol("", ct, addr, usepoint).getSymbol();
          this.setCategory(sym, Symbol.fake_input, -1);
        }
        catch (err: any) {
          this.fd.warningHeader(err.explain || err.message);
        }
      }
    }
  }

  /**
   * Convert the given symbol to a name recommendation.
   */
  private addRecommendName(sym: Symbol): void {
    const entry = sym.getFirstWholeMap();
    if (entry === null) return;
    if (entry.isDynamic()) {
      this.dynRecommend_.push(new DynamicRecommend(entry.getFirstUseAddress(), entry.getHash(), sym.getName(), sym.getId()));
    }
    else {
      let usepoint = new Address(null as any, 0n);
      if (!entry.getUseLimit().empty()) {
        const range = entry.getUseLimit().getFirstRange();
        if (range !== null)
          usepoint = new Address(range.getSpace(), range.getFirst());
      }
      this.nameRecommend_.push(new NameRecommend(entry.getAddr(), usepoint, entry.getSize(), sym.getName(), sym.getId()));
    }
    if (sym.getCategory() < 0)
      this.removeSymbol(sym);
  }

  /**
   * Collect names of unlocked Symbols on the stack.
   */
  private collectNameRecs(): void {
    this.nameRecommend_ = [];
    this.dynRecommend_ = [];

    const nametree = this.nametree;
    const symbols: Symbol[] = [];
    for (const sym of nametree) {
      symbols.push(sym);
    }
    for (const sym of symbols) {
      if (sym.isNameLocked() && (!sym.isTypeLocked())) {
        if (sym.isThisPointer()) {
          const dt = sym.getType();
          if (dt.getMetatype() === TYPE_PTR) {
            if ((dt as any).getPtrTo().getMetatype() === TYPE_STRUCT) {
              const entry = sym.getFirstWholeMap();
              this.addTypeRecommendation(entry.getAddr(), dt);
            }
          }
        }
        this.addRecommendName(sym);
      }
    }
  }

  /**
   * Generate placeholder PTRSUB off of stack pointer.
   */
  private annotateRawStackPtr(): void {
    if (!this.fd.hasTypeRecoveryStarted()) return;
    const spVn = this.fd.findSpacebaseInput(this.space);
    if (spVn === null) return;
    const refOps: any[] = [];
    for (let d = 0; d < spVn.descend.length; d++) {
      const op = spVn.descend[d];
      if (op.getEvalType() === 0 /* PcodeOp::special */ && !op.isCall()) continue;
      const opc = op.code();
      if (opc === CPUI_INT_ADD || opc === CPUI_PTRSUB || opc === CPUI_PTRADD)
        continue;
      refOps.push(op);
    }
    for (let i = 0; i < refOps.length; i++) {
      const op = refOps[i];
      const slot = op.getSlot(spVn);
      const ptrsub = this.fd.newOpBefore(op, CPUI_PTRSUB, spVn, this.fd.newConstant(spVn.getSize(), 0n));
      this.fd.opSetInput(op, ptrsub.getOut(), slot);
    }
  }

  /**
   * Determine if return storage is mapped.
   */
  private checkUnaliasedReturn(alias: bigint[]): void {
    const retOp = this.fd.getFirstReturnOp();
    if (retOp === null || retOp.numInput() < 2) return;
    const vn = retOp.getIn(1);
    if (vn.getSpace() !== this.space) return;
    // Find first alias >= vn offset using binary search
    let lo = 0;
    let hi = alias.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (alias[mid] < vn.getOffset()) lo = mid + 1;
      else hi = mid;
    }
    if (lo < alias.length) {
      if (alias[lo] <= (vn.getOffset() + BigInt(vn.getSize()) - 1n)) return;
    }
    this.markNotMapped(this.space, vn.getOffset(), vn.getSize(), false);
  }

  // -----------------------------------------------------------------------
  // Methods inherited from ScopeInternal / Scope
}
