/**
 * @file modelrules.ts
 * @description Rules governing mapping of data-type to address for prototype models.
 * Translated from Ghidra's modelrules.hh / modelrules.cc
 */

import type { int4, uint4 } from '../core/types.js';
import { Address } from '../core/address.js';
import { AddrSpace } from '../core/space.js';
import {
  Decoder,
  AttributeId,
  ElementId,
  ATTRIB_NAME,
  ATTRIB_INDEX,
  ATTRIB_ALIGN,
  ATTRIB_STORAGE,
  ATTRIB_STACKSPILL,
} from '../core/marshal.js';
import { LowlevelError, DecoderError } from '../core/error.js';
import { VarnodeData } from '../core/pcoderaw.js';
import {
  Datatype,
  TypeField,
  type_metatype,
  type_class,
  string2metatype,
  string2typeclass,
  metatype2typeclass,
} from './type.js';
import { ATTRIB_A, ATTRIB_B } from './cpool.js';

// ---------------------------------------------------------------------------
// Forward type declarations for not-yet-implemented modules
// ---------------------------------------------------------------------------

type Architecture = any;
type ParamEntry = any;
type ParamListStandard = any;
type ParamList = any;
type ProtoModel = any;
type PrototypePieces = any;
type ParameterPieces = any;
type ParamActive = any;
type ParamTrial = any;
type TypeFactory = any;
type TypeUnion = any;
type TypeStruct = any;
type TypeArray = any;

// ---------------------------------------------------------------------------
// AttributeId / ElementId constants defined in modelrules.cc
// ---------------------------------------------------------------------------

export const ATTRIB_SIZES           = new AttributeId('sizes', 151);
export const ATTRIB_MAX_PRIMITIVES  = new AttributeId('maxprimitives', 153);
export const ATTRIB_REVERSESIGNIF   = new AttributeId('reversesignif', 154);
export const ATTRIB_MATCHSIZE       = new AttributeId('matchsize', 155);
export const ATTRIB_AFTER_BYTES     = new AttributeId('afterbytes', 156);
export const ATTRIB_AFTER_STORAGE   = new AttributeId('afterstorage', 157);
export const ATTRIB_FILL_ALTERNATE  = new AttributeId('fillalternate', 158);

export const ELEM_DATATYPE          = new ElementId('datatype', 273);
export const ELEM_CONSUME           = new ElementId('consume', 274);
export const ELEM_CONSUME_EXTRA     = new ElementId('consume_extra', 275);
export const ELEM_CONVERT_TO_PTR    = new ElementId('convert_to_ptr', 276);
export const ELEM_GOTO_STACK        = new ElementId('goto_stack', 277);
export const ELEM_JOIN              = new ElementId('join', 278);
export const ELEM_DATATYPE_AT       = new ElementId('datatype_at', 279);
export const ELEM_POSITION          = new ElementId('position', 280);
export const ELEM_VARARGS           = new ElementId('varargs', 281);
export const ELEM_HIDDEN_RETURN     = new ElementId('hidden_return', 282);
export const ELEM_JOIN_PER_PRIMITIVE = new ElementId('join_per_primitive', 283);
export const ELEM_JOIN_DUAL_CLASS   = new ElementId('join_dual_class', 285);
export const ELEM_EXTRA_STACK       = new ElementId('extra_stack', 287);
export const ELEM_CONSUME_REMAINING = new ElementId('consume_remaining', 288);

// AttributeIds / ElementIds from other C++ files that are used in modelrules
// but may not yet be defined in the TS codebase.

const ATTRIB_MINSIZE        = new AttributeId('minsize', 121);
const ATTRIB_MAXSIZE        = new AttributeId('maxsize', 120);
const ATTRIB_FIRST          = new AttributeId('first', 27);
const ATTRIB_LAST           = new AttributeId('last', 28);
const ATTRIB_VOIDLOCK       = new AttributeId('voidlock', 129);
const ATTRIB_STRATEGY       = new AttributeId('strategy', 127);
const ATTRIB_REVERSEJUSTIFY = new AttributeId('reversejustify', 111);
const ELEM_RULE             = new ElementId('rule', 153);

// ---------------------------------------------------------------------------
// PrimitiveExtractor
// ---------------------------------------------------------------------------

/** Flags used by PrimitiveExtractor */
const PE_unknown_element = 1;
const PE_unaligned       = 2;
const PE_extra_space     = 4;
const PE_invalid         = 8;
const PE_union_invalid   = 16;

/**
 * A primitive data-type and its offset within the containing data-type.
 */
export class Primitive {
  dt: Datatype;
  offset: int4;

  constructor(d: Datatype, off: int4) {
    this.dt = d;
    this.offset = off;
  }
}

/**
 * Class for extracting primitive elements of a data-type.
 *
 * This recursively collects the formal primitive data-types of a composite data-type,
 * laying them out with their offsets in an array.  Other boolean properties are collected.
 */
export class PrimitiveExtractor {
  private primitives: Primitive[] = [];
  private flags: uint4;

  /**
   * Constructor.
   * @param dt is data-type to extract from
   * @param unionIllegal is true if unions encountered during extraction are considered illegal
   * @param offset is the starting offset to associate with the data-type
   * @param max is the maximum number of primitives to extract before giving up
   */
  constructor(dt: Datatype, unionIllegal: boolean, offset: int4, max: int4) {
    this.flags = unionIllegal ? PE_union_invalid : 0;
    if (!this.extract(dt, max, offset))
      this.flags |= PE_invalid;
  }

  /** Return the number of primitives extracted */
  size(): int4 { return this.primitives.length; }

  /** Get a particular primitive */
  get(i: int4): Primitive { return this.primitives[i]; }

  /** Return true if primitives were successfully extracted */
  isValid(): boolean { return (this.flags & PE_invalid) === 0; }

  /** Are there unknown elements */
  containsUnknown(): boolean { return (this.flags & PE_unknown_element) !== 0; }

  /** Are all elements aligned */
  isAligned(): boolean { return (this.flags & PE_unaligned) === 0; }

  /** Is there empty space that is not padding */
  containsHoles(): boolean { return (this.flags & PE_extra_space) !== 0; }

  /**
   * Check that a big Primitive properly overlaps smaller Primitives.
   */
  private checkOverlap(res: Primitive[], small: Primitive[], point: int4, big: Primitive): int4 {
    const endOff = big.offset + (big.dt as any).getAlignSize();
    const useSmall = (big.dt as any).getMetatype() === type_metatype.TYPE_FLOAT;
    while (point < small.length) {
      const curOff = small[point].offset;
      if (curOff >= endOff) break;
      const curEnd = curOff + (small[point].dt as any).getAlignSize();
      if (curEnd > endOff)
        return -1;
      if (useSmall)
        res.push(small[point]);
      point += 1;
    }
    if (!useSmall)
      res.push(big);
    return point;
  }

  /**
   * Overwrite first list with common refinement of first and second.
   */
  private commonRefinement(first: Primitive[], second: Primitive[]): boolean {
    let firstPoint = 0;
    let secondPoint = 0;
    const common: Primitive[] = [];
    while (firstPoint < first.length && secondPoint < second.length) {
      const firstElement = first[firstPoint];
      const secondElement = second[secondPoint];
      if (firstElement.offset < secondElement.offset &&
          firstElement.offset + (firstElement.dt as any).getAlignSize() <= secondElement.offset) {
        common.push(firstElement);
        firstPoint += 1;
        continue;
      }
      if (secondElement.offset < firstElement.offset &&
          secondElement.offset + (secondElement.dt as any).getAlignSize() <= firstElement.offset) {
        common.push(secondElement);
        secondPoint += 1;
        continue;
      }
      if ((firstElement.dt as any).getAlignSize() >= (secondElement.dt as any).getAlignSize()) {
        secondPoint = this.checkOverlap(common, second, secondPoint, firstElement);
        if (secondPoint < 0) return false;
        firstPoint += 1;
      }
      else {
        firstPoint = this.checkOverlap(common, first, firstPoint, secondElement);
        if (firstPoint < 0) return false;
        secondPoint += 1;
      }
    }
    while (firstPoint < first.length) {
      common.push(first[firstPoint]);
      firstPoint += 1;
    }
    while (secondPoint < second.length) {
      common.push(second[secondPoint]);
      secondPoint += 1;
    }
    // Replace first with the refinement
    first.length = 0;
    for (const p of common) first.push(p);
    return true;
  }

  /**
   * Form a primitive list for each field of the union. Then, if possible, form a common
   * refinement of all the primitive lists and add to the end of this extractor's list.
   */
  private handleUnion(dt: TypeUnion, max: int4, offset: int4): boolean {
    if ((this.flags & PE_union_invalid) !== 0)
      return false;
    const num: int4 = (dt as any).numDepend();
    if (num === 0)
      return false;
    const curField0: TypeField = (dt as any).getField(0);
    const common = new PrimitiveExtractor(curField0.type, false, offset + curField0.offset, max);
    if (!common.isValid())
      return false;
    for (let i = 1; i < num; ++i) {
      const curField: TypeField = (dt as any).getField(i);
      const next = new PrimitiveExtractor(curField.type, false, offset + curField.offset, max);
      if (!next.isValid())
        return false;
      if (!this.commonRefinement(common.primitives, next.primitives))
        return false;
    }
    if (this.primitives.length + common.primitives.length > max)
      return false;
    for (let i = 0; i < common.primitives.length; ++i)
      this.primitives.push(common.primitives[i]);
    return true;
  }

  /**
   * Extract list of primitives from given data-type.
   */
  private extract(dt: Datatype, max: int4, offset: int4): boolean {
    switch ((dt as any).getMetatype()) {
      case type_metatype.TYPE_UNKNOWN:
        this.flags |= PE_unknown_element;
        // fallthrough
      case type_metatype.TYPE_INT:
      case type_metatype.TYPE_UINT:
      case type_metatype.TYPE_BOOL:
      case type_metatype.TYPE_CODE:
      case type_metatype.TYPE_FLOAT:
      case type_metatype.TYPE_PTR:
      case type_metatype.TYPE_PTRREL:
        if (this.primitives.length >= max)
          return false;
        this.primitives.push(new Primitive(dt, offset));
        return true;
      case type_metatype.TYPE_ARRAY:
      {
        const numEls: int4 = (dt as any).numElements();
        const base: Datatype = (dt as any).getBase();
        for (let i = 0; i < numEls; ++i) {
          if (!this.extract(base, max, offset))
            return false;
          offset += (base as any).getAlignSize();
        }
        return true;
      }
      case type_metatype.TYPE_UNION:
        return this.handleUnion(dt as TypeUnion, max, offset);
      case type_metatype.TYPE_STRUCT:
        break;
      default:
        return false;
    }
    const structPtr = dt as TypeStruct;
    const fields: TypeField[] = (structPtr as any).beginField();
    let expectedOff = offset;
    for (let fi = 0; fi < fields.length; fi++) {
      const compDt: Datatype = fields[fi].type;
      const curOff = fields[fi].offset + offset;
      const align: int4 = (compDt as any).getAlignment();
      if (curOff % align !== 0)
        this.flags |= PE_unaligned;
      const rem = expectedOff % align;
      if (rem !== 0) {
        expectedOff += (align - rem);
      }
      if (expectedOff !== curOff) {
        this.flags |= PE_extra_space;
      }
      if (!this.extract(compDt, max, curOff))
        return false;
      expectedOff = curOff + (compDt as any).getAlignSize();
    }
    return true;
  }
}

// ---------------------------------------------------------------------------
// DatatypeFilter and subclasses
// ---------------------------------------------------------------------------

/**
 * A filter selecting a specific class of data-type.
 *
 * An instance is configured via the decode() method, then a test of whether
 * a data-type belongs to its class can be performed by calling the filter() method.
 */
export abstract class DatatypeFilter {
  /** Make a copy of this filter */
  abstract clone(): DatatypeFilter;

  /** Test whether the given data-type belongs to this filter's data-type class */
  abstract filter(dt: Datatype): boolean;

  /** Configure details of the data-type class being filtered from the given stream */
  abstract decode(decoder: Decoder): void;

  /** Instantiate a filter from the given stream */
  static decodeFilter(decoder: Decoder): DatatypeFilter {
    let filter: DatatypeFilter;
    const elemId: uint4 = decoder.openElementId(ELEM_DATATYPE);
    const nm: string = decoder.readStringById(ATTRIB_NAME);
    if (nm === 'any') {
      filter = new SizeRestrictedFilter();
    }
    else if (nm === 'homogeneous-float-aggregate') {
      filter = new HomogeneousAggregate(type_metatype.TYPE_FLOAT, 4, 0, 0);
    }
    else {
      const meta: type_metatype = string2metatype(nm);
      filter = new MetaTypeFilter(meta);
    }
    filter.decode(decoder);
    decoder.closeElement(elemId);
    return filter;
  }
}

/**
 * A base class for data-type filters that tests for either a range or an enumerated list of sizes.
 */
export class SizeRestrictedFilter extends DatatypeFilter {
  protected minSize: int4;
  protected maxSize: int4;
  protected sizes: Set<int4>;

  /** Constructor for use with decode() */
  constructor();
  /** Constructor with min/max bounds */
  constructor(min: int4, max: int4);
  /** Copy constructor */
  constructor(op2: SizeRestrictedFilter);
  constructor(arg1?: int4 | SizeRestrictedFilter, arg2?: int4) {
    super();
    if (arg1 === undefined) {
      this.minSize = 0;
      this.maxSize = 0;
      this.sizes = new Set();
    }
    else if (arg1 instanceof SizeRestrictedFilter) {
      this.minSize = arg1.minSize;
      this.maxSize = arg1.maxSize;
      this.sizes = new Set(arg1.sizes);
    }
    else {
      const min = arg1 as int4;
      const max = arg2 as int4;
      this.minSize = min;
      this.maxSize = max;
      this.sizes = new Set();
      if (this.maxSize === 0 && this.minSize >= 0) {
        this.maxSize = 0x7fffffff;
      }
    }
  }

  /**
   * Initialize filter from enumerated list of sizes.
   * Parse the given string as a comma or space separated list of decimal integers.
   */
  protected initFromSizeList(str: string): void {
    const parts = str.trim().split(/[\s,]+/);
    for (const part of parts) {
      if (part.length === 0) continue;
      const val = parseInt(part, 10);
      if (isNaN(val) || val <= 0)
        throw new DecoderError('Bad filter size');
      this.sizes.add(val);
    }
    if (this.sizes.size > 0) {
      let min = Number.MAX_SAFE_INTEGER;
      let max = 0;
      for (const s of this.sizes) {
        if (s < min) min = s;
        if (s > max) max = s;
      }
      this.minSize = min;
      this.maxSize = max;
    }
  }

  /** Enforce any size bounds on a given data-type */
  filterOnSize(dt: Datatype): boolean {
    if (this.maxSize === 0) return true;
    if (this.sizes.size > 0) {
      return this.sizes.has((dt as any).getSize());
    }
    return ((dt as any).getSize() >= this.minSize && (dt as any).getSize() <= this.maxSize);
  }

  clone(): DatatypeFilter { return new SizeRestrictedFilter(this); }

  filter(dt: Datatype): boolean { return this.filterOnSize(dt); }

  decode(decoder: Decoder): void {
    for (;;) {
      const attribId: uint4 = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_MINSIZE.getId()) {
        if (this.sizes.size > 0)
          throw new DecoderError('Mixing "sizes" with "minsize" and "maxsize"');
        this.minSize = Number(decoder.readUnsignedInteger());
      }
      else if (attribId === ATTRIB_MAXSIZE.getId()) {
        if (this.sizes.size > 0)
          throw new DecoderError('Mixing "sizes" with "minsize" and "maxsize"');
        this.maxSize = Number(decoder.readUnsignedInteger());
      }
      else if (attribId === ATTRIB_SIZES.getId()) {
        if (this.minSize !== 0 || this.maxSize !== 0)
          throw new DecoderError('Mixing "sizes" with "minsize" and "maxsize"');
        const sizeList: string = decoder.readString();
        this.initFromSizeList(sizeList);
      }
    }
    if (this.maxSize === 0 && this.minSize >= 0) {
      this.maxSize = 0x7fffffff;
    }
  }
}

/**
 * Filter on a single meta data-type.
 * Filters on TYPE_STRUCT or TYPE_FLOAT etc. Additional filtering on size can be configured.
 */
export class MetaTypeFilter extends SizeRestrictedFilter {
  protected metaType: type_metatype;

  /** Constructor for use with decode() */
  constructor(meta: type_metatype);
  /** Constructor with size bounds */
  constructor(meta: type_metatype, min: int4, max: int4);
  /** Copy constructor */
  constructor(op2: MetaTypeFilter);
  constructor(arg1: type_metatype | MetaTypeFilter, arg2?: int4, arg3?: int4) {
    if (arg1 instanceof MetaTypeFilter) {
      super(arg1 as SizeRestrictedFilter);
      this.metaType = arg1.metaType;
    }
    else if (arg2 !== undefined) {
      super(arg2, arg3!);
      this.metaType = arg1 as type_metatype;
    }
    else {
      super();
      this.metaType = arg1 as type_metatype;
    }
  }

  clone(): DatatypeFilter { return new MetaTypeFilter(this); }

  filter(dt: Datatype): boolean {
    if ((dt as any).getMetatype() !== this.metaType) return false;
    return this.filterOnSize(dt);
  }
}

/**
 * Filter on a homogeneous aggregate data-type.
 * All primitive data-types must be the same.
 */
export class HomogeneousAggregate extends SizeRestrictedFilter {
  private metaType: type_metatype;
  private maxPrimitives: int4;

  /** Constructor for use with decode() */
  constructor(meta: type_metatype);
  /** Constructor */
  constructor(meta: type_metatype, maxPrim: int4, minSize: int4, maxSize: int4);
  /** Copy constructor */
  constructor(op2: HomogeneousAggregate);
  constructor(arg1: type_metatype | HomogeneousAggregate, arg2?: int4, arg3?: int4, arg4?: int4) {
    if (arg1 instanceof HomogeneousAggregate) {
      super(arg1 as SizeRestrictedFilter);
      this.metaType = arg1.metaType;
      this.maxPrimitives = arg1.maxPrimitives;
    }
    else if (arg2 !== undefined) {
      super(arg3!, arg4!);
      this.metaType = arg1 as type_metatype;
      this.maxPrimitives = arg2;
    }
    else {
      super();
      this.metaType = arg1 as type_metatype;
      this.maxPrimitives = 4;
    }
  }

  clone(): DatatypeFilter { return new HomogeneousAggregate(this); }

  filter(dt: Datatype): boolean {
    const meta: type_metatype = (dt as any).getMetatype();
    if (meta !== type_metatype.TYPE_ARRAY && meta !== type_metatype.TYPE_STRUCT)
      return false;
    const primitives = new PrimitiveExtractor(dt, true, 0, this.maxPrimitives);
    if (!primitives.isValid() || primitives.size() === 0 || primitives.containsUnknown()
        || !primitives.isAligned() || primitives.containsHoles())
      return false;
    const base: Datatype = primitives.get(0).dt;
    if ((base as any).getMetatype() !== this.metaType)
      return false;
    for (let i = 1; i < primitives.size(); ++i) {
      if (primitives.get(i).dt !== base)
        return false;
    }
    return true;
  }

  decode(decoder: Decoder): void {
    super.decode(decoder);
    decoder.rewindAttributes();
    for (;;) {
      const attribId: uint4 = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_MAX_PRIMITIVES.getId()) {
        const xmlMaxPrim: uint4 = Number(decoder.readUnsignedInteger());
        if (xmlMaxPrim > 0) this.maxPrimitives = xmlMaxPrim;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// QualifierFilter and subclasses
// ---------------------------------------------------------------------------

/**
 * A filter on some aspect of a specific function prototype.
 */
export abstract class QualifierFilter {
  /** Make a copy of this qualifier */
  abstract clone(): QualifierFilter;

  /** Test whether the given function prototype meets this filter's criteria */
  abstract filter(proto: PrototypePieces, pos: int4): boolean;

  /** Configure details of the criteria being filtered from the given stream */
  decode(decoder: Decoder): void {}

  /** Try to instantiate a qualifier filter */
  static decodeFilter(decoder: Decoder): QualifierFilter | null {
    let filter: QualifierFilter;
    const elemId: uint4 = decoder.peekElement();
    if (elemId === ELEM_VARARGS.getId())
      filter = new VarargsFilter();
    else if (elemId === ELEM_POSITION.getId())
      filter = new PositionMatchFilter(-1);
    else if (elemId === ELEM_DATATYPE_AT.getId())
      filter = new DatatypeMatchFilter();
    else
      return null;
    filter.decode(decoder);
    return filter;
  }
}

/**
 * Logically AND multiple QualifierFilters together into a single filter.
 */
export class AndFilter extends QualifierFilter {
  private subQualifiers: QualifierFilter[];

  /** Construct from array of filters */
  constructor(filters: QualifierFilter[]) {
    super();
    this.subQualifiers = filters.slice();
    filters.length = 0;
  }

  clone(): QualifierFilter {
    const newFilters: QualifierFilter[] = [];
    for (let i = 0; i < this.subQualifiers.length; ++i)
      newFilters.push(this.subQualifiers[i].clone());
    return new AndFilter(newFilters);
  }

  filter(proto: PrototypePieces, pos: int4): boolean {
    for (let i = 0; i < this.subQualifiers.length; ++i) {
      if (!this.subQualifiers[i].filter(proto, pos))
        return false;
    }
    return true;
  }

  decode(decoder: Decoder): void {}
}

/**
 * A filter that selects a range of function parameters that are considered optional.
 */
export class VarargsFilter extends QualifierFilter {
  private firstPos: int4;
  private lastPos: int4;

  constructor();
  constructor(first: int4, last: int4);
  constructor(first?: int4, last?: int4) {
    super();
    if (first !== undefined) {
      this.firstPos = first;
      this.lastPos = last!;
    } else {
      // Use C++ INT_MIN/INT_MAX equivalent for int4
      this.firstPos = -0x80000000;
      this.lastPos = 0x7fffffff;
    }
  }

  clone(): QualifierFilter { return new VarargsFilter(this.firstPos, this.lastPos); }

  filter(proto: PrototypePieces, pos: int4): boolean {
    if ((proto as any).firstVarArgSlot < 0) return false;
    pos -= (proto as any).firstVarArgSlot;
    return (pos >= this.firstPos && pos <= this.lastPos);
  }

  decode(decoder: Decoder): void {
    const elemId: uint4 = decoder.openElementId(ELEM_VARARGS);
    for (;;) {
      const attribId: uint4 = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_FIRST.getId())
        this.firstPos = decoder.readSignedInteger();
      else if (attribId === ATTRIB_LAST.getId())
        this.lastPos = decoder.readSignedInteger();
    }
    decoder.closeElement(elemId);
  }
}

/**
 * Filter that selects for a particular parameter position.
 */
export class PositionMatchFilter extends QualifierFilter {
  private position: int4;

  constructor(pos: int4) {
    super();
    this.position = pos;
  }

  clone(): QualifierFilter { return new PositionMatchFilter(this.position); }

  filter(proto: PrototypePieces, pos: int4): boolean {
    return (pos === this.position);
  }

  decode(decoder: Decoder): void {
    const elemId: uint4 = decoder.openElementId(ELEM_POSITION);
    this.position = decoder.readSignedIntegerById(ATTRIB_INDEX);
    decoder.closeElement(elemId);
  }
}

/**
 * Check if the function signature has a specific data-type in a specific position.
 */
export class DatatypeMatchFilter extends QualifierFilter {
  private position: int4;
  private typeFilter: DatatypeFilter | null;

  constructor() {
    super();
    this.position = -1;
    this.typeFilter = null;
  }

  clone(): QualifierFilter {
    const res = new DatatypeMatchFilter();
    res.position = this.position;
    res.typeFilter = this.typeFilter!.clone();
    return res;
  }

  filter(proto: PrototypePieces, pos: int4): boolean {
    let dt: Datatype;
    if (this.position < 0)
      dt = (proto as any).outtype;
    else {
      if (this.position >= (proto as any).intypes.length)
        return false;
      dt = (proto as any).intypes[this.position];
    }
    return this.typeFilter!.filter(dt);
  }

  decode(decoder: Decoder): void {
    const elemId: uint4 = decoder.openElementId(ELEM_DATATYPE_AT);
    this.position = decoder.readSignedIntegerById(ATTRIB_INDEX);
    this.typeFilter = DatatypeFilter.decodeFilter(decoder);
    decoder.closeElement(elemId);
  }
}

// ---------------------------------------------------------------------------
// AssignAction and subclasses
// ---------------------------------------------------------------------------

/** Response codes for AssignAction */
export const AssignActionCode = {
  success: 0,
  fail: 1,
  no_assignment: 2,
  hiddenret_ptrparam: 3,
  hiddenret_specialreg: 4,
  hiddenret_specialreg_void: 5,
} as const;

/**
 * An action that assigns an Address to a function prototype parameter.
 */
export abstract class AssignAction {
  protected resource: ParamListStandard;
  fillinOutputActive: boolean;

  constructor(res: ParamListStandard) {
    this.resource = res;
    this.fillinOutputActive = false;
  }

  /** Return true if fillinOutputMap is active */
  canAffectFillinOutput(): boolean { return this.fillinOutputActive; }

  /** Make a copy of this action */
  abstract clone(newResource: ParamListStandard): AssignAction;

  /** Assign an address and other meta-data for a specific parameter or return storage */
  abstract assignAddress(dt: Datatype, proto: PrototypePieces, pos: int4, tlist: TypeFactory,
    status: int4[], res: ParameterPieces): uint4;

  /** Test if this action could produce return value storage matching the given set of trials */
  fillinOutputMap(active: ParamActive): boolean {
    return false;
  }

  /** Configure details from the stream */
  abstract decode(decoder: Decoder): void;

  /** Read the next model rule action element from the stream */
  static decodeAction(decoder: Decoder, res: ParamListStandard): AssignAction {
    let action: AssignAction;
    const elemId: uint4 = decoder.peekElement();
    if (elemId === ELEM_GOTO_STACK.getId())
      action = new GotoStack(res, 0);
    else if (elemId === ELEM_JOIN.getId())
      action = new MultiSlotAssign(res);
    else if (elemId === ELEM_CONSUME.getId())
      action = new ConsumeAs(type_class.TYPECLASS_GENERAL, res);
    else if (elemId === ELEM_CONVERT_TO_PTR.getId())
      action = new ConvertToPointer(res);
    else if (elemId === ELEM_HIDDEN_RETURN.getId())
      action = new HiddenReturnAssign(res, AssignActionCode.hiddenret_specialreg);
    else if (elemId === ELEM_JOIN_PER_PRIMITIVE.getId())
      action = new MultiMemberAssign(type_class.TYPECLASS_GENERAL, false, (res as any).isBigEndian(), res);
    else if (elemId === ELEM_JOIN_DUAL_CLASS.getId())
      action = new MultiSlotDualAssign(res);
    else
      throw new DecoderError('Expecting model rule action');
    action.decode(decoder);
    return action;
  }

  /** Read the next model rule precondition element from the stream */
  static decodePrecondition(decoder: Decoder, res: ParamListStandard): AssignAction | null {
    let action: AssignAction;
    const elemId: uint4 = decoder.peekElement();

    if (elemId === ELEM_CONSUME_EXTRA.getId()) {
      action = new ConsumeExtra(res);
    }
    else {
      return null;
    }

    action.decode(decoder);
    return action;
  }

  /** Read the next model rule sideeffect element from the stream */
  static decodeSideeffect(decoder: Decoder, res: ParamListStandard): AssignAction {
    let action: AssignAction;
    const elemId: uint4 = decoder.peekElement();

    if (elemId === ELEM_CONSUME_EXTRA.getId()) {
      action = new ConsumeExtra(res);
    }
    else if (elemId === ELEM_EXTRA_STACK.getId()) {
      action = new ExtraStack(res);
    }
    else if (elemId === ELEM_CONSUME_REMAINING.getId()) {
      action = new ConsumeRemaining(res);
    }
    else
      throw new DecoderError('Expecting model rule sideeffect');
    action.decode(decoder);
    return action;
  }

  /**
   * Truncate a tiling by a given number of bytes.
   * The extra bytes are considered padding and removed from one end of the tiling.
   */
  static justifyPieces(pieces: VarnodeData[], offset: int4, isBigEndian: boolean,
    consumeMostSig: boolean, justifyRight: boolean): void {
    const addOffset: boolean = (isBigEndian !== consumeMostSig) !== justifyRight;
    const pos: number = justifyRight ? 0 : pieces.length - 1;

    const vndata = pieces[pos];
    if (addOffset) {
      vndata.offset += BigInt(offset);
    }
    vndata.size -= offset;
  }
}

// ---------------------------------------------------------------------------
// GotoStack
// ---------------------------------------------------------------------------

/**
 * Action assigning a parameter Address from the next available stack location.
 */
export class GotoStack extends AssignAction {
  private stackEntry: ParamEntry | null;

  private initializeEntry(): void {
    this.stackEntry = (this.resource as any).getStackEntry();
    if (this.stackEntry === null)
      throw new LowlevelError('Cannot find matching <pentry> for action: goto_stack');
  }

  /** Constructor for use with decode */
  constructor(res: ParamListStandard, val: int4);
  /** Constructor */
  constructor(res: ParamListStandard);
  constructor(res: ParamListStandard, val?: int4) {
    super(res);
    this.stackEntry = null;
    this.fillinOutputActive = true;
    if (val === undefined) {
      this.initializeEntry();
    }
  }

  clone(newResource: ParamListStandard): AssignAction { return new GotoStack(newResource); }

  assignAddress(dt: Datatype, proto: PrototypePieces, pos: int4, tlst: TypeFactory,
    status: int4[], res: ParameterPieces): uint4 {
    const grp: int4 = (this.stackEntry as any).getGroup();
    (res as any).type = dt;
    const slotObj887 = { val: status[grp] };
    (res as any).addr = (this.stackEntry as any).getAddrBySlot(slotObj887, (dt as any).getSize(), (dt as any).getAlignment());
    status[grp] = slotObj887.val;
    (res as any).flags = 0;
    return AssignActionCode.success;
  }

  fillinOutputMap(active: ParamActive): boolean {
    let count = 0;
    for (let i = 0; i < (active as any).getNumTrials(); ++i) {
      const trial: ParamTrial = (active as any).getTrial(i);
      const entry: ParamEntry = (trial as any).getEntry();
      if (entry === null) break;
      if (entry !== this.stackEntry)
        return false;
      count += 1;
      if (count > 1)
        return false;
    }
    return (count === 1);
  }

  decode(decoder: Decoder): void {
    const elemId: uint4 = decoder.openElementId(ELEM_GOTO_STACK);
    decoder.closeElement(elemId);
    this.initializeEntry();
  }
}

// ---------------------------------------------------------------------------
// ConvertToPointer
// ---------------------------------------------------------------------------

/**
 * Action converting the parameter's data-type to a pointer, and assigning storage for the pointer.
 */
export class ConvertToPointer extends AssignAction {
  private space: AddrSpace | null;

  constructor(res: ParamListStandard) {
    super(res);
    this.space = (res as any).getSpacebase();
  }

  clone(newResource: ParamListStandard): AssignAction { return new ConvertToPointer(newResource); }

  assignAddress(dt: Datatype, proto: PrototypePieces, pos: int4, tlist: TypeFactory,
    status: int4[], res: ParameterPieces): uint4 {
    let spc: AddrSpace | null = this.space;
    if (spc === null)
      spc = (tlist as any).getArch().getDefaultDataSpace();
    const pointersize: int4 = (spc as any).getAddrSize();
    const wordsize: int4 = (spc as any).getWordSize();
    const pointertp: Datatype = (tlist as any).getTypePointer(pointersize, dt, wordsize);
    const responseCode: uint4 = (this.resource as any).assignAddress(pointertp, proto, pos, tlist, status, res);
    (res as any).flags = 4;   // ParameterPieces::indirectstorage
    return responseCode;
  }

  decode(decoder: Decoder): void {
    const elemId: uint4 = decoder.openElementId(ELEM_CONVERT_TO_PTR);
    decoder.closeElement(elemId);
  }
}

// ---------------------------------------------------------------------------
// MultiSlotAssign
// ---------------------------------------------------------------------------

/**
 * Consume multiple registers to pass a data-type.
 */
export class MultiSlotAssign extends AssignAction {
  private resourceType: type_class;
  private isBigEndian: boolean;
  private consumeFromStack: boolean;
  private consumeMostSig: boolean;
  private enforceAlignment: boolean;
  private justifyRight: boolean;
  private tiles: ParamEntry[];
  private stackEntry: ParamEntry | null;

  private initializeEntries(): void {
    this.tiles = [];
    (this.resource as any).extractTiles(this.tiles, this.resourceType);
    this.stackEntry = (this.resource as any).getStackEntry();
    if (this.tiles.length === 0)
      throw new LowlevelError('Could not find matching resources for action: join');
    if (this.consumeFromStack && this.stackEntry === null)
      throw new LowlevelError('Cannot find matching <pentry> for action: join');
  }

  /** Constructor for use with decode */
  constructor(res: ParamListStandard);
  /** Constructor */
  constructor(store: type_class, stack: boolean, mostSig: boolean, align: boolean, justRight: boolean, res: ParamListStandard);
  constructor(arg1: ParamListStandard | type_class, arg2?: boolean | undefined, arg3?: boolean, arg4?: boolean, arg5?: boolean, arg6?: ParamListStandard) {
    if (arg2 === undefined) {
      // Constructor for use with decode
      const res = arg1 as ParamListStandard;
      super(res);
      this.resourceType = type_class.TYPECLASS_GENERAL;
      this.isBigEndian = (res as any).isBigEndian();
      this.fillinOutputActive = true;
      const listType: uint4 = (res as any).getType();
      // ParamList::p_standard_out = 1, p_register_out = 3
      this.consumeFromStack = (listType !== 1 && listType !== 3);
      this.consumeMostSig = false;
      this.enforceAlignment = false;
      this.justifyRight = false;
      if (this.isBigEndian) {
        this.consumeMostSig = true;
        this.justifyRight = true;
      }
      this.stackEntry = null;
      this.tiles = [];
    }
    else {
      const store = arg1 as type_class;
      const stack = arg2 as boolean;
      const mostSig = arg3!;
      const align = arg4!;
      const justRight = arg5!;
      const res = arg6 as ParamListStandard;
      super(res);
      this.resourceType = store;
      this.isBigEndian = (res as any).isBigEndian();
      this.fillinOutputActive = true;
      this.consumeFromStack = stack;
      this.consumeMostSig = mostSig;
      this.enforceAlignment = align;
      this.justifyRight = justRight;
      this.stackEntry = null;
      this.tiles = [];
      this.initializeEntries();
    }
  }

  clone(newResource: ParamListStandard): AssignAction {
    return new MultiSlotAssign(this.resourceType, this.consumeFromStack, this.consumeMostSig,
      this.enforceAlignment, this.justifyRight, newResource);
  }

  assignAddress(dt: Datatype, proto: PrototypePieces, pos: int4, tlist: TypeFactory,
    status: int4[], res: ParameterPieces): uint4 {
    const tmpStatus: int4[] = status.slice();
    const pieces: VarnodeData[] = [];
    let sizeLeft: int4 = (dt as any).getSize();
    let align: int4 = (dt as any).getAlignment();
    let iter = 0;
    if (this.enforceAlignment) {
      let resourcesConsumed = 0;
      while (iter !== this.tiles.length) {
        const entry = this.tiles[iter];
        if (tmpStatus[(entry as any).getGroup()] === 0) {
          const regSize: int4 = (entry as any).getSize();
          if (align <= regSize || (resourcesConsumed % align) === 0)
            break;
          tmpStatus[(entry as any).getGroup()] = -1;
        }
        resourcesConsumed += (entry as any).getSize();
        ++iter;
      }
    }
    while (sizeLeft > 0 && iter !== this.tiles.length) {
      const entry = this.tiles[iter];
      ++iter;
      if (tmpStatus[(entry as any).getGroup()] !== 0)
        continue;
      const trialSize: int4 = (entry as any).getSize();
      const slotObj1057 = { val: tmpStatus[(entry as any).getGroup()] };
      const addr: Address = (entry as any).getAddrBySlot(slotObj1057, trialSize, align);
      tmpStatus[(entry as any).getGroup()] = -1;
      const vd = new VarnodeData(addr.getSpace(), addr.getOffset(), trialSize);
      pieces.push(vd);
      sizeLeft -= trialSize;
      align = 1;
    }
    if (sizeLeft > 0) {
      if (!this.consumeFromStack)
        return AssignActionCode.fail;
      const grp: int4 = (this.stackEntry as any).getGroup();
      const slotObj1069 = { val: tmpStatus[grp] };
      const addr: Address = (this.stackEntry as any).getAddrBySlot(slotObj1069, sizeLeft, align, this.justifyRight);
      tmpStatus[grp] = slotObj1069.val;
      if (addr.isInvalid())
        return AssignActionCode.fail;
      const vd = new VarnodeData(addr.getSpace(), addr.getOffset(), sizeLeft);
      pieces.push(vd);
    }
    else if (sizeLeft < 0) {
      if (this.resourceType === type_class.TYPECLASS_FLOAT && pieces.length === 1) {
        const manager = (tlist as any).getArch();
        const tmp = pieces[0];
        const addr: Address = (manager as any).constructFloatExtensionAddress(tmp.getAddr(), tmp.size, (dt as any).getSize());
        tmp.space = addr.getSpace();
        tmp.offset = addr.getOffset()!;
        tmp.size = (dt as any).getSize();
      }
      else {
        AssignAction.justifyPieces(pieces, -sizeLeft, this.isBigEndian, this.consumeMostSig, this.justifyRight);
      }
    }
    // Commit resource usage
    for (let i = 0; i < tmpStatus.length; i++) status[i] = tmpStatus[i];
    (res as any).flags = 0;
    (res as any).type = dt;
    (res as any).assignAddressFromPieces(pieces, this.consumeMostSig, (tlist as any).getArch());
    return AssignActionCode.success;
  }

  fillinOutputMap(active: ParamActive): boolean {
    let count = 0;
    let curGroup = -1;
    let partial = -1;
    for (let i = 0; i < (active as any).getNumTrials(); ++i) {
      const trial: ParamTrial = (active as any).getTrial(i);
      const entry: ParamEntry = (trial as any).getEntry();
      if (entry === null) break;
      if ((entry as any).getType() !== this.resourceType)
        return false;
      if (count === 0) {
        if (!(entry as any).isFirstInClass())
          return false;
      }
      else {
        if ((entry as any).getGroup() !== curGroup + 1)
          return false;
      }
      curGroup = (entry as any).getGroup();
      if ((trial as any).getSize() !== (entry as any).getSize()) {
        if (partial !== -1)
          return false;
        partial = i;
      }
      count += 1;
    }
    if (partial !== -1) {
      if (this.justifyRight) {
        if (partial !== 0) return false;
      }
      else {
        if (partial !== count - 1) return false;
      }
      const trial: ParamTrial = (active as any).getTrial(partial);
      if (this.justifyRight === this.consumeMostSig) {
        if ((trial as any).getOffset() !== 0)
          return false;
      }
      else {
        if ((trial as any).getOffset() + (trial as any).getSize() !== (trial as any).getEntry().getSize()) {
          return false;
        }
      }
    }
    if (count === 0) return false;
    if (this.consumeMostSig)
      (active as any).setJoinReverse();
    return true;
  }

  decode(decoder: Decoder): void {
    const elemId: uint4 = decoder.openElementId(ELEM_JOIN);
    for (;;) {
      const attribId: uint4 = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_REVERSEJUSTIFY.getId()) {
        if (decoder.readBool())
          this.justifyRight = !this.justifyRight;
      }
      else if (attribId === ATTRIB_REVERSESIGNIF.getId()) {
        if (decoder.readBool())
          this.consumeMostSig = !this.consumeMostSig;
      }
      else if (attribId === ATTRIB_STORAGE.getId()) {
        this.resourceType = string2typeclass(decoder.readString());
      }
      else if (attribId === ATTRIB_ALIGN.getId()) {
        this.enforceAlignment = decoder.readBool();
      }
      else if (attribId === ATTRIB_STACKSPILL.getId()) {
        this.consumeFromStack = decoder.readBool();
      }
    }
    decoder.closeElement(elemId);
    this.initializeEntries();
  }
}

// ---------------------------------------------------------------------------
// MultiMemberAssign
// ---------------------------------------------------------------------------

/**
 * Consume a register per primitive member of an aggregate data-type.
 */
export class MultiMemberAssign extends AssignAction {
  private resourceType: type_class;
  private consumeFromStack: boolean;
  private consumeMostSig: boolean;

  constructor(store: type_class, stack: boolean, mostSig: boolean, res: ParamListStandard) {
    super(res);
    this.resourceType = store;
    this.consumeFromStack = stack;
    this.consumeMostSig = mostSig;
    this.fillinOutputActive = true;
  }

  clone(newResource: ParamListStandard): AssignAction {
    return new MultiMemberAssign(this.resourceType, this.consumeFromStack, this.consumeMostSig, newResource);
  }

  assignAddress(dt: Datatype, proto: PrototypePieces, pos: int4, tlist: TypeFactory,
    status: int4[], res: ParameterPieces): uint4 {
    const tmpStatus: int4[] = status.slice();
    const pieces: VarnodeData[] = [];
    const primitives = new PrimitiveExtractor(dt, false, 0, 16);
    if (!primitives.isValid() || primitives.size() === 0 || primitives.containsUnknown()
        || !primitives.isAligned() || primitives.containsHoles())
      return AssignActionCode.fail;
    const param: ParameterPieces = {} as any;
    for (let i = 0; i < primitives.size(); ++i) {
      const curType: Datatype = primitives.get(i).dt;
      if ((this.resource as any).assignAddressFallback(this.resourceType, curType, !this.consumeFromStack, tmpStatus, param) === AssignActionCode.fail)
        return AssignActionCode.fail;
      const vd = new VarnodeData((param as any).addr.getSpace(), (param as any).addr.getOffset(), (curType as any).getSize());
      pieces.push(vd);
    }

    for (let i = 0; i < tmpStatus.length; i++) status[i] = tmpStatus[i];
    (res as any).flags = 0;
    (res as any).type = dt;
    (res as any).assignAddressFromPieces(pieces, this.consumeMostSig, (tlist as any).getArch());
    return AssignActionCode.success;
  }

  fillinOutputMap(active: ParamActive): boolean {
    let count = 0;
    let curGroup = -1;
    for (let i = 0; i < (active as any).getNumTrials(); ++i) {
      const trial: ParamTrial = (active as any).getTrial(i);
      const entry: ParamEntry = (trial as any).getEntry();
      if (entry === null) break;
      if ((entry as any).getType() !== this.resourceType)
        return false;
      if (count === 0) {
        if (!(entry as any).isFirstInClass())
          return false;
      }
      else {
        if ((entry as any).getGroup() !== curGroup + 1)
          return false;
      }
      curGroup = (entry as any).getGroup();
      if ((trial as any).getOffset() !== 0)
        return false;
      count += 1;
    }
    if (count === 0) return false;
    if (this.consumeMostSig)
      (active as any).setJoinReverse();
    return true;
  }

  decode(decoder: Decoder): void {
    const elemId: uint4 = decoder.openElementId(ELEM_JOIN_PER_PRIMITIVE);
    for (;;) {
      const attribId: uint4 = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_STORAGE.getId()) {
        this.resourceType = string2typeclass(decoder.readString());
      }
    }
    decoder.closeElement(elemId);
  }
}

// ---------------------------------------------------------------------------
// MultiSlotDualAssign
// ---------------------------------------------------------------------------

/**
 * Consume multiple registers from different storage classes to pass a data-type.
 */
export class MultiSlotDualAssign extends AssignAction {
  private baseType: type_class;
  private altType: type_class;
  private isBigEndian: boolean;
  private consumeFromStack: boolean;
  private consumeMostSig: boolean;
  private justifyRight: boolean;
  private fillAlternate: boolean;
  private tileSize!: int4;
  private baseTiles: ParamEntry[];
  private altTiles: ParamEntry[];
  private stackEntry: ParamEntry | null;

  private initializeEntries(): void {
    this.baseTiles = [];
    this.altTiles = [];
    (this.resource as any).extractTiles(this.baseTiles, this.baseType);
    (this.resource as any).extractTiles(this.altTiles, this.altType);
    this.stackEntry = (this.resource as any).getStackEntry();

    if (this.baseTiles.length === 0 || this.altTiles.length === 0)
      throw new LowlevelError('Could not find matching resources for action: join_dual_class');
    this.tileSize = (this.baseTiles[0] as any).getSize();
    if (this.tileSize !== (this.altTiles[0] as any).getSize())
      throw new LowlevelError('Storage class register sizes do not match for action: join_dual_class');
    if (this.consumeFromStack && this.stackEntry === null)
      throw new LowlevelError('Cannot find matching stack resource for action: join_dual_class');
  }

  /**
   * Get the index of the first unused ParamEntry in the given list.
   */
  private getFirstUnused(iter: int4, tiles: ParamEntry[], status: int4[]): int4 {
    for (; iter !== tiles.length; ++iter) {
      const entry = tiles[iter];
      if (status[(entry as any).getGroup()] !== 0)
        continue;
      return iter;
    }
    return tiles.length;
  }

  /**
   * Get the storage class to use for the specific section of the data-type.
   */
  private getTileClass(primitives: PrimitiveExtractor, off: int4, index: { val: int4 }): int4 {
    let res = 1;
    let count = 0;
    const endBoundary = off + this.tileSize;
    if (index.val >= primitives.size()) return -1;
    const firstPrimitive: Primitive = primitives.get(index.val);
    while (index.val < primitives.size()) {
      const element: Primitive = primitives.get(index.val);
      if (element.offset < off) return -1;
      if (element.offset >= endBoundary) break;
      if (element.offset + (element.dt as any).getSize() > endBoundary) return -1;
      count += 1;
      index.val += 1;
      const storage: type_class = metatype2typeclass((element.dt as any).getMetatype());
      if (storage !== this.altType)
        res = 0;
    }
    if (count === 0) return -1;
    if (this.fillAlternate) {
      if (count > 1)
        res = 0;
      if ((firstPrimitive.dt as any).getSize() !== this.tileSize)
        res = 0;
    }
    return res;
  }

  /** Constructor for use with decode */
  constructor(res: ParamListStandard);
  /** Constructor */
  constructor(baseStore: type_class, altStore: type_class, stack: boolean, mostSig: boolean,
    justRight: boolean, fillAlt: boolean, res: ParamListStandard);
  constructor(arg1: ParamListStandard | type_class, arg2?: type_class, arg3?: boolean, arg4?: boolean,
    arg5?: boolean, arg6?: boolean, arg7?: ParamListStandard) {
    if (arg2 === undefined) {
      const res = arg1 as ParamListStandard;
      super(res);
      this.isBigEndian = (res as any).isBigEndian();
      this.fillinOutputActive = true;
      this.baseType = type_class.TYPECLASS_GENERAL;
      this.altType = type_class.TYPECLASS_FLOAT;
      this.consumeFromStack = false;
      this.consumeMostSig = false;
      this.justifyRight = false;
      if (this.isBigEndian) {
        this.consumeMostSig = true;
        this.justifyRight = true;
      }
      this.fillAlternate = false;
      this.tileSize = 0;
      this.stackEntry = null;
      this.baseTiles = [];
      this.altTiles = [];
    }
    else {
      const baseStore = arg1 as type_class;
      const altStore = arg2;
      const stack = arg3!;
      const mostSig = arg4!;
      const justRight = arg5!;
      const fillAlt = arg6!;
      const res = arg7 as ParamListStandard;
      super(res);
      this.isBigEndian = (res as any).isBigEndian();
      this.fillinOutputActive = true;
      this.baseType = baseStore;
      this.altType = altStore;
      this.consumeFromStack = stack;
      this.consumeMostSig = mostSig;
      this.justifyRight = justRight;
      this.fillAlternate = fillAlt;
      this.stackEntry = null;
      this.baseTiles = [];
      this.altTiles = [];
      this.initializeEntries();
    }
  }

  clone(newResource: ParamListStandard): AssignAction {
    return new MultiSlotDualAssign(this.baseType, this.altType, this.consumeFromStack,
      this.consumeMostSig, this.justifyRight, this.fillAlternate, newResource);
  }

  assignAddress(dt: Datatype, proto: PrototypePieces, pos: int4, tlist: TypeFactory,
    status: int4[], res: ParameterPieces): uint4 {
    const primitives = new PrimitiveExtractor(dt, false, 0, 1024);
    if (!primitives.isValid() || primitives.size() === 0 || primitives.containsHoles())
      return AssignActionCode.fail;
    const primitiveIndex = { val: 0 };
    const tmpStatus: int4[] = status.slice();
    const pieces: VarnodeData[] = [];
    const typeSize: int4 = (dt as any).getSize();
    const align: int4 = (dt as any).getAlignment();
    let sizeLeft: int4 = typeSize;
    let iterBase = 0;
    let iterAlt = 0;
    while (sizeLeft > 0) {
      let entry: ParamEntry;
      const iterType = this.getTileClass(primitives, typeSize - sizeLeft, primitiveIndex);
      if (iterType < 0)
        return AssignActionCode.fail;
      if (iterType === 0) {
        iterBase = this.getFirstUnused(iterBase, this.baseTiles, tmpStatus);
        if (iterBase === this.baseTiles.length) {
          if (!this.consumeFromStack)
            return AssignActionCode.fail;
          break;
        }
        entry = this.baseTiles[iterBase];
      }
      else {
        iterAlt = this.getFirstUnused(iterAlt, this.altTiles, tmpStatus);
        if (iterAlt === this.altTiles.length) {
          if (!this.consumeFromStack)
            return AssignActionCode.fail;
          break;
        }
        entry = this.altTiles[iterAlt];
      }
      const trialSize: int4 = (entry as any).getSize();
      const slotObj1437 = { val: tmpStatus[(entry as any).getGroup()] };
      const addr: Address = (entry as any).getAddrBySlot(slotObj1437, trialSize, 1);
      tmpStatus[(entry as any).getGroup()] = -1;
      const vd = new VarnodeData(addr.getSpace(), addr.getOffset(), trialSize);
      pieces.push(vd);
      sizeLeft -= trialSize;
    }
    if (sizeLeft > 0) {
      if (!this.consumeFromStack)
        return AssignActionCode.fail;
      const grp: int4 = (this.stackEntry as any).getGroup();
      const slotObj1448 = { val: tmpStatus[grp] };
      const addr: Address = (this.stackEntry as any).getAddrBySlot(slotObj1448, sizeLeft, align, this.justifyRight);
      tmpStatus[grp] = slotObj1448.val;
      if (addr.isInvalid())
        return AssignActionCode.fail;
      const vd = new VarnodeData(addr.getSpace(), addr.getOffset(), sizeLeft);
      pieces.push(vd);
    }
    if (sizeLeft < 0) {
      AssignAction.justifyPieces(pieces, -sizeLeft, this.isBigEndian, this.consumeMostSig, this.justifyRight);
    }
    for (let i = 0; i < tmpStatus.length; i++) status[i] = tmpStatus[i];
    (res as any).flags = 0;
    (res as any).type = dt;
    (res as any).assignAddressFromPieces(pieces, this.consumeMostSig, (tlist as any).getArch());
    return AssignActionCode.success;
  }

  fillinOutputMap(active: ParamActive): boolean {
    let count = 0;
    let curGroup = -1;
    let partial = -1;
    let resourceType: type_class = type_class.TYPECLASS_GENERAL;
    for (let i = 0; i < (active as any).getNumTrials(); ++i) {
      const trial: ParamTrial = (active as any).getTrial(i);
      const entry: ParamEntry = (trial as any).getEntry();
      if (entry === null) break;
      if (count === 0) {
        resourceType = (entry as any).getType();
        if (resourceType !== this.baseType && resourceType !== this.altType)
          return false;
      }
      else if ((entry as any).getType() !== resourceType)
        return false;
      if (count === 0) {
        if (!(entry as any).isFirstInClass())
          return false;
      }
      else {
        if ((entry as any).getGroup() !== curGroup + 1)
          return false;
      }
      curGroup = (entry as any).getGroup();
      if ((trial as any).getSize() !== (entry as any).getSize()) {
        if (partial !== -1)
          return false;
        partial = i;
      }
      count += 1;
    }
    if (partial !== -1) {
      if (this.justifyRight) {
        if (partial !== 0) return false;
      }
      else {
        if (partial !== count - 1) return false;
      }
      const trial: ParamTrial = (active as any).getTrial(partial);
      if (this.justifyRight === this.consumeMostSig) {
        if ((trial as any).getOffset() !== 0)
          return false;
      }
      else {
        if ((trial as any).getOffset() + (trial as any).getSize() !== (trial as any).getEntry().getSize()) {
          return false;
        }
      }
    }
    if (count === 0) return false;
    if (this.consumeMostSig)
      (active as any).setJoinReverse();
    return true;
  }

  decode(decoder: Decoder): void {
    const elemId: uint4 = decoder.openElementId(ELEM_JOIN_DUAL_CLASS);
    for (;;) {
      const attribId: uint4 = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_REVERSEJUSTIFY.getId()) {
        if (decoder.readBool())
          this.justifyRight = !this.justifyRight;
      }
      else if (attribId === ATTRIB_REVERSESIGNIF.getId()) {
        if (decoder.readBool())
          this.consumeMostSig = !this.consumeMostSig;
      }
      else if (attribId === ATTRIB_STORAGE.getId() || attribId === ATTRIB_A.getId()) {
        this.baseType = string2typeclass(decoder.readString());
      }
      else if (attribId === ATTRIB_B.getId()) {
        this.altType = string2typeclass(decoder.readString());
      }
      else if (attribId === ATTRIB_STACKSPILL.getId()) {
        this.consumeFromStack = decoder.readBool();
      }
      else if (attribId === ATTRIB_FILL_ALTERNATE.getId()) {
        this.fillAlternate = decoder.readBool();
      }
    }
    decoder.closeElement(elemId);
    this.initializeEntries();
  }
}

// ---------------------------------------------------------------------------
// ConsumeAs
// ---------------------------------------------------------------------------

/**
 * Consume a parameter from a specific resource list.
 */
export class ConsumeAs extends AssignAction {
  private resourceType: type_class;

  constructor(store: type_class, res: ParamListStandard) {
    super(res);
    this.resourceType = store;
    this.fillinOutputActive = true;
  }

  clone(newResource: ParamListStandard): AssignAction {
    return new ConsumeAs(this.resourceType, newResource);
  }

  assignAddress(dt: Datatype, proto: PrototypePieces, pos: int4, tlist: TypeFactory,
    status: int4[], res: ParameterPieces): uint4 {
    return (this.resource as any).assignAddressFallback(this.resourceType, dt, true, status, res);
  }

  fillinOutputMap(active: ParamActive): boolean {
    let count = 0;
    for (let i = 0; i < (active as any).getNumTrials(); ++i) {
      const trial: ParamTrial = (active as any).getTrial(i);
      const entry: ParamEntry = (trial as any).getEntry();
      if (entry === null) break;
      if ((entry as any).getType() !== this.resourceType)
        return false;
      if (!(entry as any).isFirstInClass())
        return false;
      count += 1;
      if (count > 1)
        return false;
      if ((trial as any).getOffset() !== 0)
        return false;
    }
    return (count > 0);
  }

  decode(decoder: Decoder): void {
    const elemId: uint4 = decoder.openElementId(ELEM_CONSUME);
    this.resourceType = string2typeclass(decoder.readStringById(ATTRIB_STORAGE));
    decoder.closeElement(elemId);
  }
}

// ---------------------------------------------------------------------------
// HiddenReturnAssign
// ---------------------------------------------------------------------------

/**
 * Allocate the return value as an input parameter.
 */
export class HiddenReturnAssign extends AssignAction {
  private retCode: uint4;

  constructor(res: ParamListStandard, code: uint4) {
    super(res);
    this.retCode = code;
  }

  clone(newResource: ParamListStandard): AssignAction {
    return new HiddenReturnAssign(newResource, this.retCode);
  }

  assignAddress(dt: Datatype, proto: PrototypePieces, pos: int4, tlist: TypeFactory,
    status: int4[], res: ParameterPieces): uint4 {
    return this.retCode;
  }

  decode(decoder: Decoder): void {
    this.retCode = AssignActionCode.hiddenret_specialreg;
    const elemId: uint4 = decoder.openElementId(ELEM_HIDDEN_RETURN);
    for (;;) {
      const attribId: uint4 = decoder.getNextAttributeId();
      if (attribId === ATTRIB_VOIDLOCK.getId())
        this.retCode = AssignActionCode.hiddenret_specialreg_void;
      else if (attribId === ATTRIB_STRATEGY.getId()) {
        const strategyString: string = decoder.readString();
        if (strategyString === 'normalparam')
          this.retCode = AssignActionCode.hiddenret_ptrparam;
        else if (strategyString === 'special')
          this.retCode = AssignActionCode.hiddenret_specialreg;
        else
          throw new DecoderError('Bad <hidden_return> strategy: ' + strategyString);
      }
      else
        break;
    }
    decoder.closeElement(elemId);
  }
}

// ---------------------------------------------------------------------------
// ConsumeExtra
// ---------------------------------------------------------------------------

/**
 * Consume additional registers from an alternate resource list.
 */
export class ConsumeExtra extends AssignAction {
  private resourceType: type_class;
  private matchSize: boolean;
  private tiles: ParamEntry[];

  private initializeEntries(): void {
    this.tiles = [];
    (this.resource as any).extractTiles(this.tiles, this.resourceType);
    if (this.tiles.length === 0)
      throw new LowlevelError('Could not find matching resources for action: consume_extra');
  }

  /** Constructor for use with decode */
  constructor(res: ParamListStandard);
  /** Constructor */
  constructor(store: type_class, match: boolean, res: ParamListStandard);
  constructor(arg1: ParamListStandard | type_class, arg2?: boolean, arg3?: ParamListStandard) {
    if (arg2 === undefined) {
      const res = arg1 as ParamListStandard;
      super(res);
      this.resourceType = type_class.TYPECLASS_GENERAL;
      this.matchSize = true;
      this.tiles = [];
    }
    else {
      const store = arg1 as type_class;
      const match = arg2;
      const res = arg3 as ParamListStandard;
      super(res);
      this.resourceType = store;
      this.matchSize = match;
      this.tiles = [];
      this.initializeEntries();
    }
  }

  clone(newResource: ParamListStandard): AssignAction {
    return new ConsumeExtra(this.resourceType, this.matchSize, newResource);
  }

  assignAddress(dt: Datatype, proto: PrototypePieces, pos: int4, tlist: TypeFactory,
    status: int4[], res: ParameterPieces): uint4 {
    let iter = 0;
    let sizeLeft: int4 = (dt as any).getSize();
    while (sizeLeft > 0 && iter !== this.tiles.length) {
      const entry = this.tiles[iter];
      ++iter;
      if (status[(entry as any).getGroup()] !== 0)
        continue;
      status[(entry as any).getGroup()] = -1;
      sizeLeft -= (entry as any).getSize();
      if (!this.matchSize)
        break;
    }
    (res as any).type = dt;
    return AssignActionCode.success;
  }

  decode(decoder: Decoder): void {
    const elemId: uint4 = decoder.openElementId(ELEM_CONSUME_EXTRA);
    for (;;) {
      const attribId: uint4 = decoder.getNextAttributeId();
      if (attribId === 0) break;
      else if (attribId === ATTRIB_STORAGE.getId()) {
        this.resourceType = string2typeclass(decoder.readString());
      }
      else if (attribId === ATTRIB_MATCHSIZE.getId()) {
        this.matchSize = decoder.readBool();
      }
    }
    decoder.closeElement(elemId);
    this.initializeEntries();
  }
}

// ---------------------------------------------------------------------------
// ExtraStack
// ---------------------------------------------------------------------------

/**
 * Consume stack resources as a side-effect.
 */
export class ExtraStack extends AssignAction {
  private afterBytes: int4;
  private afterStorage: type_class;
  private stackEntry: ParamEntry | null;

  private initializeEntry(): void {
    this.stackEntry = (this.resource as any).getStackEntry();
    if (this.stackEntry === null)
      throw new LowlevelError('Cannot find matching <pentry> for action: extra_stack');
  }

  /** Constructor for use with decode */
  constructor(res: ParamListStandard);
  /** Constructor */
  constructor(storage: type_class, offset: int4, res: ParamListStandard);
  constructor(arg1: ParamListStandard | type_class, arg2?: int4, arg3?: ParamListStandard) {
    if (arg2 === undefined) {
      const res = arg1 as ParamListStandard;
      super(res);
      this.afterBytes = -1;
      this.afterStorage = type_class.TYPECLASS_GENERAL;
      this.stackEntry = null;
    }
    else {
      const storage = arg1 as type_class;
      const offset = arg2;
      const res = arg3 as ParamListStandard;
      super(res);
      this.afterStorage = storage;
      this.afterBytes = offset;
      this.stackEntry = null;
      this.initializeEntry();
    }
  }

  clone(newResource: ParamListStandard): AssignAction {
    return new ExtraStack(this.afterStorage, this.afterBytes, newResource);
  }

  assignAddress(dt: Datatype, proto: PrototypePieces, pos: int4, tlst: TypeFactory,
    status: int4[], res: ParameterPieces): uint4 {
    if ((res as any).addr.getSpace() === (this.stackEntry as any).getSpace()) {
      (res as any).type = dt;
      return AssignActionCode.success;
    }
    const grp: int4 = (this.stackEntry as any).getGroup();
    if (this.afterBytes > 0) {
      const entryList: any[] = (this.resource as any).getEntry();
      let bytesConsumed = 0;
      for (let i = 0; i < entryList.length; i++) {
        const entry = entryList[i];
        if ((entry as any).getGroup() === grp || (entry as any).getType() !== this.afterStorage) {
          continue;
        }
        if (status[(entry as any).getGroup()] !== 0) {
          bytesConsumed += (entry as any).getSize();
        }
      }
      if (bytesConsumed < this.afterBytes) {
        (res as any).type = dt;
        return AssignActionCode.success;
      }
    }
    const slotObj1799 = { val: status[grp] };
    (this.stackEntry as any).getAddrBySlot(slotObj1799, (dt as any).getSize(), (dt as any).getAlignment());
    status[grp] = slotObj1799.val;
    (res as any).type = dt;
    return AssignActionCode.success;
  }

  decode(decoder: Decoder): void {
    const elemId: uint4 = decoder.openElementId(ELEM_EXTRA_STACK);
    for (;;) {
      const attribId: uint4 = decoder.getNextAttributeId();
      if (attribId === 0) break;
      else if (attribId === ATTRIB_AFTER_BYTES.getId())
        this.afterBytes = Number(decoder.readUnsignedInteger());
      else if (attribId === ATTRIB_AFTER_STORAGE.getId())
        this.afterStorage = string2typeclass(decoder.readString());
    }
    decoder.closeElement(elemId);
    this.initializeEntry();
  }
}

// ---------------------------------------------------------------------------
// ConsumeRemaining
// ---------------------------------------------------------------------------

/**
 * Consume all the remaining registers from a given resource list.
 */
export class ConsumeRemaining extends AssignAction {
  private resourceType: type_class;
  private tiles: ParamEntry[];

  private initializeEntries(): void {
    this.tiles = [];
    (this.resource as any).extractTiles(this.tiles, this.resourceType);
    if (this.tiles.length === 0)
      throw new LowlevelError('Could not find matching resources for action: consume_remaining');
  }

  /** Constructor for use with decode */
  constructor(res: ParamListStandard);
  /** Constructor */
  constructor(store: type_class, res: ParamListStandard);
  constructor(arg1: ParamListStandard | type_class, arg2?: ParamListStandard) {
    if (arg2 === undefined) {
      const res = arg1 as ParamListStandard;
      super(res);
      this.resourceType = type_class.TYPECLASS_GENERAL;
      this.tiles = [];
    }
    else {
      const store = arg1 as type_class;
      const res = arg2;
      super(res);
      this.resourceType = store;
      this.tiles = [];
      this.initializeEntries();
    }
  }

  clone(newResource: ParamListStandard): AssignAction {
    return new ConsumeRemaining(this.resourceType, newResource);
  }

  assignAddress(dt: Datatype, proto: PrototypePieces, pos: int4, tlist: TypeFactory,
    status: int4[], res: ParameterPieces): uint4 {
    let iter = 0;
    while (iter !== this.tiles.length) {
      const entry = this.tiles[iter];
      ++iter;
      if (status[(entry as any).getGroup()] !== 0)
        continue;
      status[(entry as any).getGroup()] = -1;
    }
    (res as any).type = dt;
    return AssignActionCode.success;
  }

  decode(decoder: Decoder): void {
    const elemId: uint4 = decoder.openElementId(ELEM_CONSUME_REMAINING);
    this.resourceType = string2typeclass(decoder.readStringById(ATTRIB_STORAGE));
    decoder.closeElement(elemId);
    this.initializeEntries();
  }
}

// ---------------------------------------------------------------------------
// ModelRule
// ---------------------------------------------------------------------------

/**
 * A rule controlling how parameters are assigned addresses.
 */
export class ModelRule {
  private filter: DatatypeFilter | null;
  private qualifier: QualifierFilter | null;
  private assign: AssignAction | null;
  private preconditions: AssignAction[];
  private sideeffects: AssignAction[];

  /** Constructor for use with decode */
  constructor();
  /** Copy constructor */
  constructor(op2: ModelRule, res: ParamListStandard);
  /** Construct from components */
  constructor(typeFilter: DatatypeFilter, action: AssignAction, res: ParamListStandard);
  constructor(arg1?: ModelRule | DatatypeFilter, arg2?: ParamListStandard | AssignAction, arg3?: ParamListStandard) {
    if (arg1 === undefined) {
      this.filter = null;
      this.qualifier = null;
      this.assign = null;
      this.preconditions = [];
      this.sideeffects = [];
    }
    else if (arg1 instanceof ModelRule) {
      const op2 = arg1;
      const res = arg2 as ParamListStandard;
      this.filter = op2.filter !== null ? op2.filter.clone() : null;
      this.qualifier = op2.qualifier !== null ? op2.qualifier.clone() : null;
      this.assign = op2.assign !== null ? op2.assign.clone(res) : null;
      this.preconditions = [];
      for (let i = 0; i < op2.preconditions.length; ++i)
        this.preconditions.push(op2.preconditions[i].clone(res));
      this.sideeffects = [];
      for (let i = 0; i < op2.sideeffects.length; ++i)
        this.sideeffects.push(op2.sideeffects[i].clone(res));
    }
    else if (arg1 instanceof DatatypeFilter) {
      const typeFilter = arg1;
      const action = arg2 as AssignAction;
      const res = arg3 as ParamListStandard;
      this.filter = typeFilter.clone();
      this.qualifier = null;
      this.assign = action.clone(res);
      this.preconditions = [];
      this.sideeffects = [];
    }
    else {
      this.filter = null;
      this.qualifier = null;
      this.assign = null;
      this.preconditions = [];
      this.sideeffects = [];
    }
  }

  /** Assign an address for the parameter */
  assignAddress(dt: Datatype, proto: PrototypePieces, pos: int4, tlist: TypeFactory,
    status: int4[], res: ParameterPieces): uint4 {
    if (!this.filter!.filter(dt)) {
      return AssignActionCode.fail;
    }
    if (this.qualifier !== null && !this.qualifier.filter(proto, pos)) {
      return AssignActionCode.fail;
    }
    const tmpStatus: int4[] = status.slice();
    for (let i = 0; i < this.preconditions.length; ++i) {
      this.preconditions[i].assignAddress(dt, proto, pos, tlist, tmpStatus, res);
    }
    const response: uint4 = this.assign!.assignAddress(dt, proto, pos, tlist, tmpStatus, res);
    if (response !== AssignActionCode.fail) {
      for (let i = 0; i < tmpStatus.length; i++) status[i] = tmpStatus[i];
      for (let i = 0; i < this.sideeffects.length; ++i) {
        this.sideeffects[i].assignAddress(dt, proto, pos, tlist, status, res);
      }
    }
    return response;
  }

  /** Test and mark the trial(s) that can be valid return value */
  fillinOutputMap(active: ParamActive): boolean {
    return this.assign!.fillinOutputMap(active);
  }

  /** Return true if fillinOutputMap is active for this rule */
  canAffectFillinOutput(): boolean {
    return this.assign!.canAffectFillinOutput();
  }

  /** Decode this rule from stream */
  decode(decoder: Decoder, res: ParamListStandard): void {
    const qualifiers: QualifierFilter[] = [];
    const elemId: uint4 = decoder.openElementId(ELEM_RULE);
    this.filter = DatatypeFilter.decodeFilter(decoder);
    for (;;) {
      const qual = QualifierFilter.decodeFilter(decoder);
      if (qual === null)
        break;
      qualifiers.push(qual);
    }
    if (qualifiers.length === 0)
      this.qualifier = null;
    else if (qualifiers.length === 1) {
      this.qualifier = qualifiers[0];
      qualifiers.length = 0;
    }
    else {
      this.qualifier = new AndFilter(qualifiers);
    }
    for (;;) {
      const precond = AssignAction.decodePrecondition(decoder, res);
      if (precond === null)
        break;
      this.preconditions.push(precond);
    }
    this.assign = AssignAction.decodeAction(decoder, res);
    while (decoder.peekElement() !== 0) {
      this.sideeffects.push(AssignAction.decodeSideeffect(decoder, res));
    }

    decoder.closeElement(elemId);
  }
}
