/**
 * @file type.ts
 * @description Classes for describing and printing data-types, translated from type.hh/type.cc
 */

import { Writer } from '../util/writer.js';
import { LowlevelError } from '../core/error.js';
import {
  AttributeId,
  ElementId,
  Encoder,
  Decoder,
  ATTRIB_NAME,
  ATTRIB_METATYPE,
  ATTRIB_SIZE,
  ATTRIB_ID,
  ATTRIB_FORMAT,
  ATTRIB_OFFSET,
  ATTRIB_CONTENT,
  ATTRIB_WORDSIZE,
  ATTRIB_SPACE,
  ATTRIB_VALUE,
  ATTRIB_VAL,
  ELEM_VOID,
  ELEM_VAL,
  ELEM_OFF,
} from '../core/marshal.js';
import { Address, calc_mask, sign_extend, coveringmask } from '../core/address.js';
import { AddrSpace } from '../core/space.js';
import { SortedSet } from '../util/sorted-set.js';

// ---------------------------------------------------------------------------
// Forward type declarations for types not defined in this file
// ---------------------------------------------------------------------------

type Architecture = any;
type PcodeOp = any;
type Scope = any;
type Funcdata = any;
type PrototypePieces = any;

// These are used as both types and values (with `new`) but are not yet translated.
// We use `class` stubs so the name works both as a type and as a constructor at runtime.
// They will be replaced when the respective modules are translated.
class FuncProto { [key: string]: any; }

// Late-bound FuncProto constructor, populated by fspec.ts at import time
let _FuncProtoCtor: any = FuncProto;

/** Called by fspec.ts to register the real FuncProto constructor */
export function registerFuncProtoClass(ctor: any): void {
  _FuncProtoCtor = ctor;
}

// ScoreUnionFields and ResolvedUnion have a circular dependency with type.ts
// We use late-bound constructor references populated by unionresolve.ts at import time
let ScoreUnionFields: any = null;
let ResolvedUnion: any = null;

/** Called by unionresolve.ts to register the real constructors */
export function registerUnionResolveClasses(scoreUnionFieldsCtor: any, resolvedUnionCtor: any): void {
  ScoreUnionFields = scoreUnionFieldsCtor;
  ResolvedUnion = resolvedUnionCtor;
}

class StringWriter {
  private buf: string = '';
  write(s: string): void { this.buf += s; }
  toString(): string { return this.buf; }
}

// Opcode constants
import { OpCode } from '../core/opcodes.js';
const CPUI_COPY = OpCode.CPUI_COPY;
const CPUI_LOAD = OpCode.CPUI_LOAD;
const CPUI_STORE = OpCode.CPUI_STORE;
const CPUI_INDIRECT = OpCode.CPUI_INDIRECT;
const CPUI_SUBPIECE = OpCode.CPUI_SUBPIECE;

// ---------------------------------------------------------------------------
// DatatypeSet / DatatypeNameSet forward declarations
// ---------------------------------------------------------------------------

/** A set of data-types sorted by dependency comparison */
export type DatatypeSet = SortedSet<Datatype>;

/** A set of data-types sorted by name comparison */
export type DatatypeNameSet = SortedSet<Datatype>;

// =========================================================================
// Enums
// =========================================================================

/**
 * The core meta-types supported by the decompiler.
 * These are sizeless templates for the elements making up the type algebra.
 * Index is important for the Datatype.base2sub array.
 */
export enum type_metatype {
  TYPE_PARTIALUNION = 0,
  TYPE_PARTIALSTRUCT = 1,
  TYPE_PARTIALENUM = 2,
  TYPE_UNION = 3,
  TYPE_STRUCT = 4,
  TYPE_ENUM_INT = 5,
  TYPE_ENUM_UINT = 6,
  TYPE_ARRAY = 7,
  TYPE_PTRREL = 8,
  TYPE_PTR = 9,
  TYPE_FLOAT = 10,
  TYPE_CODE = 11,
  TYPE_BOOL = 12,
  TYPE_UINT = 13,
  TYPE_INT = 14,
  TYPE_UNKNOWN = 15,
  TYPE_SPACEBASE = 16,
  TYPE_VOID = 17,
}

/**
 * Specializations of the core meta-types.
 * Each enumeration is associated with a specific type_metatype.
 * Ordering is important: lower number = more specific data-type, affecting propagation.
 */
export enum sub_metatype {
  SUB_PARTIALUNION = 0,
  SUB_UNION = 1,
  SUB_STRUCT = 2,
  SUB_ARRAY = 3,
  SUB_PTR_STRUCT = 4,
  SUB_PTRREL = 5,
  SUB_PTR = 6,
  SUB_PTRREL_UNK = 7,
  SUB_FLOAT = 8,
  SUB_CODE = 9,
  SUB_BOOL = 10,
  SUB_UINT_UNICODE = 11,
  SUB_INT_UNICODE = 12,
  SUB_UINT_ENUM = 13,
  SUB_UINT_PARTIALENUM = 14,
  SUB_INT_ENUM = 15,
  SUB_UINT_PLAIN = 16,
  SUB_INT_PLAIN = 17,
  SUB_UINT_CHAR = 18,
  SUB_INT_CHAR = 19,
  SUB_PARTIALSTRUCT = 20,
  SUB_UNKNOWN = 21,
  SUB_SPACEBASE = 22,
  SUB_VOID = 23,
}

/**
 * Data-type classes for the purpose of assigning storage.
 */
export enum type_class {
  TYPECLASS_GENERAL = 0,
  TYPECLASS_FLOAT = 1,
  TYPECLASS_PTR = 2,
  TYPECLASS_HIDDENRET = 3,
  TYPECLASS_VECTOR = 4,
  TYPECLASS_CLASS1 = 100,
  TYPECLASS_CLASS2 = 101,
  TYPECLASS_CLASS3 = 102,
  TYPECLASS_CLASS4 = 103,
}

// =========================================================================
// AttributeId / ElementId constants defined in type.cc
// =========================================================================

export const ATTRIB_ALIGNMENT     = new AttributeId('alignment', 47);
export const ATTRIB_ARRAYSIZE     = new AttributeId('arraysize', 48);
export const ATTRIB_CHAR          = new AttributeId('char', 49);
export const ATTRIB_CORE          = new AttributeId('core', 50);
export const ATTRIB_INCOMPLETE    = new AttributeId('incomplete', 52);
export const ATTRIB_OPAQUESTRING  = new AttributeId('opaquestring', 56);
export const ATTRIB_SIGNED        = new AttributeId('signed', 57);
export const ATTRIB_STRUCTALIGN   = new AttributeId('structalign', 58);
export const ATTRIB_UTF           = new AttributeId('utf', 59);
export const ATTRIB_VARLENGTH     = new AttributeId('varlength', 60);
export const ATTRIB_LABEL         = new AttributeId('label', 61);

export const ELEM_CHAR_SIZE       = new ElementId('char_size', 39);
export const ELEM_CORETYPES       = new ElementId('coretypes', 41);
export const ELEM_DATA_ORGANIZATION = new ElementId('data_organization', 42);
export const ELEM_DEF             = new ElementId('def', 43);
export const ELEM_ENTRY           = new ElementId('entry', 47);
export const ELEM_ENUM            = new ElementId('enum', 48);
export const ELEM_FIELD           = new ElementId('field', 49);
export const ELEM_INTEGER_SIZE    = new ElementId('integer_size', 51);
export const ELEM_LONG_SIZE       = new ElementId('long_size', 54);
export const ELEM_POINTER_SIZE    = new ElementId('pointer_size', 57);
export const ELEM_SIZE_ALIGNMENT_MAP = new ElementId('size_alignment_map', 59);
export const ELEM_TYPE            = new ElementId('type', 60);
export const ELEM_TYPEGRP         = new ElementId('typegrp', 62);
export const ELEM_TYPEREF         = new ElementId('typeref', 63);
export const ELEM_WCHAR_SIZE      = new ElementId('wchar_size', 65);

// =========================================================================
// Datatype boolean property flags
// =========================================================================

export const DT_coretype           = 1;
export const DT_chartype           = 2;
export const DT_enumtype           = 4;
export const DT_poweroftwo         = 8;
export const DT_utf16              = 16;
export const DT_utf32              = 32;
export const DT_opaque_string      = 64;
export const DT_variable_length    = 128;
export const DT_has_stripped        = 0x100;
export const DT_is_ptrrel          = 0x200;
export const DT_type_incomplete    = 0x400;
export const DT_needs_resolution   = 0x800;
export const DT_force_format       = 0x7000;
export const DT_truncate_bigendian = 0x8000;
export const DT_pointer_to_array   = 0x10000;
export const DT_warning_issued     = 0x20000;

// =========================================================================
// base2sub mapping array
// =========================================================================

/**
 * The base propagation ordering associated with each meta-type.
 * Array elements correspond to the ordering of type_metatype (indexed by value).
 */
export const base2sub: sub_metatype[] = [
  sub_metatype.SUB_PARTIALUNION,    // TYPE_PARTIALUNION = 0
  sub_metatype.SUB_PARTIALSTRUCT,   // TYPE_PARTIALSTRUCT = 1
  sub_metatype.SUB_UINT_PARTIALENUM,// TYPE_PARTIALENUM = 2
  sub_metatype.SUB_UNION,           // TYPE_UNION = 3
  sub_metatype.SUB_STRUCT,          // TYPE_STRUCT = 4
  sub_metatype.SUB_INT_ENUM,        // TYPE_ENUM_INT = 5
  sub_metatype.SUB_UINT_ENUM,       // TYPE_ENUM_UINT = 6
  sub_metatype.SUB_ARRAY,           // TYPE_ARRAY = 7
  sub_metatype.SUB_PTRREL,          // TYPE_PTRREL = 8
  sub_metatype.SUB_PTR,             // TYPE_PTR = 9
  sub_metatype.SUB_FLOAT,           // TYPE_FLOAT = 10
  sub_metatype.SUB_CODE,            // TYPE_CODE = 11
  sub_metatype.SUB_BOOL,            // TYPE_BOOL = 12
  sub_metatype.SUB_UINT_PLAIN,      // TYPE_UINT = 13
  sub_metatype.SUB_INT_PLAIN,       // TYPE_INT = 14
  sub_metatype.SUB_UNKNOWN,         // TYPE_UNKNOWN = 15
  sub_metatype.SUB_SPACEBASE,       // TYPE_SPACEBASE = 16
  sub_metatype.SUB_VOID,            // TYPE_VOID = 17
];

// =========================================================================
// Utility functions
// =========================================================================

/**
 * Convert a type meta-type into the string name of the meta-type.
 */
export function metatype2string(metatype: type_metatype): string {
  switch (metatype) {
    case type_metatype.TYPE_VOID:           return 'void';
    case type_metatype.TYPE_PTR:            return 'ptr';
    case type_metatype.TYPE_PTRREL:         return 'ptrrel';
    case type_metatype.TYPE_ARRAY:          return 'array';
    case type_metatype.TYPE_PARTIALENUM:    return 'partenum';
    case type_metatype.TYPE_PARTIALSTRUCT:  return 'partstruct';
    case type_metatype.TYPE_PARTIALUNION:   return 'partunion';
    case type_metatype.TYPE_ENUM_INT:       return 'enum_int';
    case type_metatype.TYPE_ENUM_UINT:      return 'enum_uint';
    case type_metatype.TYPE_STRUCT:         return 'struct';
    case type_metatype.TYPE_UNION:          return 'union';
    case type_metatype.TYPE_SPACEBASE:      return 'spacebase';
    case type_metatype.TYPE_UNKNOWN:        return 'unknown';
    case type_metatype.TYPE_UINT:           return 'uint';
    case type_metatype.TYPE_INT:            return 'int';
    case type_metatype.TYPE_BOOL:           return 'bool';
    case type_metatype.TYPE_CODE:           return 'code';
    case type_metatype.TYPE_FLOAT:          return 'float';
    default:
      throw new LowlevelError('Unknown metatype');
  }
}

/**
 * Given a string description of a type meta-type, return the meta-type.
 */
export function string2metatype(metastring: string): type_metatype {
  switch (metastring[0]) {
    case 'p':
      if (metastring === 'ptr') return type_metatype.TYPE_PTR;
      if (metastring === 'ptrrel') return type_metatype.TYPE_PTRREL;
      if (metastring === 'partunion') return type_metatype.TYPE_PARTIALUNION;
      if (metastring === 'partstruct') return type_metatype.TYPE_PARTIALSTRUCT;
      if (metastring === 'partenum') return type_metatype.TYPE_PARTIALENUM;
      break;
    case 'a':
      if (metastring === 'array') return type_metatype.TYPE_ARRAY;
      break;
    case 'e':
      if (metastring === 'enum_int') return type_metatype.TYPE_ENUM_INT;
      if (metastring === 'enum_uint') return type_metatype.TYPE_ENUM_UINT;
      break;
    case 's':
      if (metastring === 'struct') return type_metatype.TYPE_STRUCT;
      if (metastring === 'spacebase') return type_metatype.TYPE_SPACEBASE;
      break;
    case 'u':
      if (metastring === 'unknown') return type_metatype.TYPE_UNKNOWN;
      if (metastring === 'uint') return type_metatype.TYPE_UINT;
      if (metastring === 'union') return type_metatype.TYPE_UNION;
      break;
    case 'i':
      if (metastring === 'int') return type_metatype.TYPE_INT;
      break;
    case 'f':
      if (metastring === 'float') return type_metatype.TYPE_FLOAT;
      break;
    case 'b':
      if (metastring === 'bool') return type_metatype.TYPE_BOOL;
      break;
    case 'c':
      if (metastring === 'code') return type_metatype.TYPE_CODE;
      break;
    case 'v':
      if (metastring === 'void') return type_metatype.TYPE_VOID;
      break;
    default:
      break;
  }
  throw new LowlevelError('Unknown metatype: ' + metastring);
}

/**
 * Given a description of a data-type class, return the type_class.
 */
export function string2typeclass(classstring: string): type_class {
  switch (classstring[0]) {
    case 'c':
      if (classstring === 'class1') return type_class.TYPECLASS_CLASS1;
      if (classstring === 'class2') return type_class.TYPECLASS_CLASS2;
      if (classstring === 'class3') return type_class.TYPECLASS_CLASS3;
      if (classstring === 'class4') return type_class.TYPECLASS_CLASS4;
      break;
    case 'g':
      if (classstring === 'general') return type_class.TYPECLASS_GENERAL;
      break;
    case 'h':
      if (classstring === 'hiddenret') return type_class.TYPECLASS_HIDDENRET;
      break;
    case 'f':
      if (classstring === 'float') return type_class.TYPECLASS_FLOAT;
      break;
    case 'p':
      if (classstring === 'ptr' || classstring === 'pointer') return type_class.TYPECLASS_PTR;
      break;
    case 'v':
      if (classstring === 'vector') return type_class.TYPECLASS_VECTOR;
      break;
    case 'u':
      if (classstring === 'unknown') return type_class.TYPECLASS_GENERAL;
      break;
  }
  throw new LowlevelError('Unknown data-type class: ' + classstring);
}

/**
 * Assign the basic storage class based on a metatype.
 *   TYPE_FLOAT -> TYPECLASS_FLOAT
 *   TYPE_PTR   -> TYPECLASS_PTR
 * Everything else returns the general purpose TYPECLASS_GENERAL.
 */
export function metatype2typeclass(meta: type_metatype): type_class {
  switch (meta) {
    case type_metatype.TYPE_FLOAT:
      return type_class.TYPECLASS_FLOAT;
    case type_metatype.TYPE_PTR:
      return type_class.TYPECLASS_PTR;
    default:
      break;
  }
  return type_class.TYPECLASS_GENERAL;
}

/**
 * Display an array of bytes as a hex dump at a given address.
 * Each line displays an address and 16 bytes in hexadecimal.
 */
export function print_data(s: Writer, buffer: Uint8Array | null, size: number, baseaddr: Address): void {
  if (buffer === null) {
    s.write('Address not present in binary image\n');
    return;
  }

  const addr = baseaddr.getOffset();
  const endaddr = addr + BigInt(size);
  let start = addr & ~0xFn;

  while (start < endaddr) {
    s.write(start.toString(16).padStart(8, '0') + ': ');
    for (let i = 0; i < 16; i++) {
      const cur = start + BigInt(i);
      if (cur < addr || cur >= endaddr) {
        s.write('   ');
      } else {
        const byteVal = buffer[Number(cur - addr)];
        s.write(byteVal.toString(16).padStart(2, '0') + ' ');
      }
    }
    s.write('  ');
    for (let i = 0; i < 16; i++) {
      const cur = start + BigInt(i);
      if (cur < addr || cur >= endaddr) {
        s.write(' ');
      } else {
        const byteVal = buffer[Number(cur - addr)];
        if (byteVal >= 0x20 && byteVal < 0x7F) {
          s.write(String.fromCharCode(byteVal));
        } else {
          s.write('.');
        }
      }
    }
    s.write('\n');
    start += 16n;
  }
}

/**
 * Encode an integer format string to a numeric value.
 *   "hex" -> 1, "dec" -> 2, "oct" -> 3, "bin" -> 4, "char" -> 5
 */
export function encodeIntegerFormat(val: string): number {
  if (val === 'hex') return 1;
  if (val === 'dec') return 2;
  if (val === 'oct') return 3;
  if (val === 'bin') return 4;
  if (val === 'char') return 5;
  throw new LowlevelError('Unrecognized integer format: ' + val);
}

/**
 * Decode a numeric integer format value to a string.
 *   1 -> "hex", 2 -> "dec", 3 -> "oct", 4 -> "bin", 5 -> "char"
 */
export function decodeIntegerFormat(val: number): string {
  switch (val) {
    case 1: return 'hex';
    case 2: return 'dec';
    case 3: return 'oct';
    case 4: return 'bin';
    case 5: return 'char';
  }
  throw new LowlevelError('Bad integer format encoding');
}

/**
 * Produce a data-type id by hashing the type name.
 * IDs produced this way will have their two high bits set
 * to distinguish them from other IDs.
 */
export function hashName(nm: string): bigint {
  let res = 123n;
  for (let i = 0; i < nm.length; i++) {
    res = ((res << 8n) | (res >> 56n)) & 0xFFFFFFFFFFFFFFFFn;
    res = (res + BigInt(nm.charCodeAt(i))) & 0xFFFFFFFFFFFFFFFFn;
    if ((res & 1n) === 0n) {
      res ^= 0xfeabfeabn;
    }
  }
  res |= 0xC000000000000000n;
  return res;
}

/**
 * Reversibly hash size into id. Allows IDs for variable length structures
 * to be uniquified based on size.
 */
export function hashSize(id: bigint, size: number): bigint {
  let sizeHash = BigInt(size);
  sizeHash = (sizeHash * 0x98251033aecbabafn) & 0xFFFFFFFFFFFFFFFFn;
  return (id ^ sizeHash) & 0xFFFFFFFFFFFFFFFFn;
}

// =========================================================================
// Datatype base class
// =========================================================================

/**
 * The base datatype class for the decompiler.
 *
 * Used for symbols, function prototypes, type propagation, etc.
 */
export abstract class Datatype {
  // --- Fields (public for TypeFactory friend access) ---
  /** @internal */ id: bigint;
  /** @internal */ size: number;
  /** @internal */ flags: number;
  /** @internal */ name: string;
  /** @internal */ displayName: string;
  /** @internal */ metatype: type_metatype;
  /** @internal */ submeta: sub_metatype;
  /** @internal */ typedefImm: Datatype | null;
  /** @internal */ alignment: number;
  /** @internal */ alignSize: number;

  /**
   * Construct the base data-type providing size, alignment, and meta-type.
   */
  constructor(s: number, align: number, m: type_metatype);
  /**
   * Construct the base data-type copying low-level properties of another.
   */
  constructor(op: Datatype);
  constructor(sOrOp: number | Datatype, align?: number, m?: type_metatype) {
    if (typeof sOrOp === 'number') {
      this.size = sOrOp;
      this.metatype = m!;
      this.submeta = base2sub[m!];
      this.flags = 0;
      this.id = 0n;
      this.typedefImm = null;
      this.alignment = align!;
      this.alignSize = sOrOp;
      this.name = '';
      this.displayName = '';
    } else {
      const op = sOrOp;
      this.size = op.size;
      this.name = op.name;
      this.displayName = op.displayName;
      this.metatype = op.metatype;
      this.submeta = op.submeta;
      this.flags = op.flags;
      this.id = op.id;
      this.typedefImm = op.typedefImm;
      this.alignment = op.alignment;
      this.alignSize = op.alignSize;
    }
  }

  // --- Boolean property accessors ---

  /** Is this a core data-type */
  isCoreType(): boolean { return (this.flags & DT_coretype) !== 0; }

  /** Does this print as a 'char' */
  isCharPrint(): boolean {
    return (this.flags & (DT_chartype | DT_utf16 | DT_utf32 | DT_opaque_string)) !== 0;
  }

  /** Is this an enumerated type */
  isEnumType(): boolean { return (this.flags & DT_enumtype) !== 0; }

  /** Does this print as an ASCII 'char' */
  isASCII(): boolean { return (this.flags & DT_chartype) !== 0; }

  /** Does this print as UTF16 'wchar' */
  isUTF16(): boolean { return (this.flags & DT_utf16) !== 0; }

  /** Does this print as UTF32 'wchar' */
  isUTF32(): boolean { return (this.flags & DT_utf32) !== 0; }

  /** Is this a variable length structure */
  isVariableLength(): boolean { return (this.flags & DT_variable_length) !== 0; }

  /**
   * Are these the same variable length data-type.
   * If this and the given data-type are both variable length and come from
   * the same base data-type, return true.
   */
  hasSameVariableBase(ct: Datatype): boolean {
    if (!this.isVariableLength()) return false;
    if (!ct.isVariableLength()) return false;
    const thisId = hashSize(this.id, this.size);
    const themId = hashSize(ct.id, ct.size);
    return thisId === themId;
  }

  /** Is this an opaquely encoded string */
  isOpaqueString(): boolean { return (this.flags & DT_opaque_string) !== 0; }

  /** Is this a pointer to an array */
  isPointerToArray(): boolean { return (this.flags & DT_pointer_to_array) !== 0; }

  /** Is this a TypePointerRel */
  isPointerRel(): boolean { return (this.flags & DT_is_ptrrel) !== 0; }

  /** Is this a non-ephemeral TypePointerRel */
  isFormalPointerRel(): boolean {
    return (this.flags & (DT_is_ptrrel | DT_has_stripped)) === DT_is_ptrrel;
  }

  /** Return true if this has a stripped form */
  hasStripped(): boolean { return (this.flags & DT_has_stripped) !== 0; }

  /** Is this an incompletely defined data-type */
  isIncomplete(): boolean { return (this.flags & DT_type_incomplete) !== 0; }

  /** Is this a union or a pointer to union */
  needsResolution(): boolean { return (this.flags & DT_needs_resolution) !== 0; }

  /** Has a warning been issued about this data-type */
  hasWarning(): boolean { return (this.flags & DT_warning_issued) !== 0; }

  /** Get properties pointers inherit */
  getInheritable(): number { return this.flags & DT_coretype; }

  /**
   * Get the display format for constants with this data-type.
   * Returns 0 if no format is forced, or 1=hex, 2=dec, 3=oct, 4=bin, 5=char.
   */
  getDisplayFormat(): number {
    return (this.flags & DT_force_format) >> 12;
  }

  /** Get the type meta-type */
  getMetatype(): type_metatype { return this.metatype; }

  /** Get the sub-metatype */
  getSubMeta(): sub_metatype { return this.submeta; }

  /** Get the type id */
  getId(): bigint { return this.id; }

  /**
   * Get the type id, without variable length size adjustment.
   * If the data-type is variable length, the working id has a contribution
   * based on the specific size. This removes that contribution, returning the base id.
   */
  getUnsizedId(): bigint {
    if ((this.flags & DT_variable_length) !== 0) {
      return hashSize(this.id, this.size);
    }
    return this.id;
  }

  /** Get the type size */
  getSize(): number { return this.size; }

  /** Get size rounded up to multiple of alignment */
  getAlignSize(): number { return this.alignSize; }

  /** Get the expected byte alignment */
  getAlignment(): number { return this.alignment; }

  /** Get the type name */
  getName(): string { return this.name; }

  /** Get string to use in display */
  getDisplayName(): string { return this.displayName; }

  /** Get the data-type immediately typedefed by this (or null) */
  getTypedef(): Datatype | null { return this.typedefImm; }

  // --- Virtual methods ---

  /** Print a description of the type to stream. Intended for debugging. */
  printRaw(s: Writer): void {
    if (this.name.length > 0) {
      s.write(this.name);
    } else {
      s.write('unkbyte' + this.size.toString());
    }
  }

  /**
   * Find an immediate subfield of this data-type.
   * Given a byte range within this data-type, determine the field it is contained in.
   * Returns the containing field or null if the range is not contained.
   */
  findTruncation(off: bigint, sz: number, op: PcodeOp, slot: number, newoff: { val: bigint }): TypeField | null {
    return null;
  }

  /**
   * Given an offset into this data-type, return the component data-type at that offset.
   * Also, pass back a "renormalized" offset suitable for recursive getSubType calls.
   * Returns null if there is no valid component data-type at the offset.
   */
  getSubType(off: bigint, newoff: { val: bigint }): Datatype | null {
    newoff.val = off;
    return null;
  }

  /**
   * Find the first component data-type that is (or contains) an array starting
   * after the given offset.
   */
  nearestArrayedComponentForward(off: bigint, newoff: { val: bigint }, elSize: { val: bigint }): Datatype | null {
    return null;
  }

  /**
   * Find the last component data-type that is (or contains) an array starting
   * before the given offset.
   */
  nearestArrayedComponentBackward(off: bigint, newoff: { val: bigint }, elSize: { val: bigint }): Datatype | null {
    return null;
  }

  /**
   * Get number of bytes at the given offset that are padding.
   * Returns the number of bytes of padding or 0.
   */
  getHoleSize(off: number): number { return 0; }

  /**
   * Get the number of component sub-types making up this data-type.
   */
  numDepend(): number { return 0; }

  /**
   * Get a specific component sub-type by index.
   */
  getDepend(index: number): Datatype | null { return null; }

  /**
   * Print (part of) the name of this data-type as short prefix for a label.
   * Used for building variable names to give indication of the variable's underlying data-type.
   */
  printNameBase(s: Writer): void {
    if (this.name.length > 0) {
      s.write(this.name[0]);
    }
  }

  /**
   * Order types for propagation.
   * Bigger types come earlier. More specific types come earlier.
   */
  compare(op: Datatype, level: number): number {
    if (this.submeta !== op.submeta) return (this.submeta < op.submeta) ? -1 : 1;
    if (this.size !== op.size) return op.size - this.size;
    return 0;
  }

  /**
   * Compare for storage in tree structure.
   * Sort data-types for the main TypeFactory container. The sort is based on
   * data-type structure so that an example data-type can be used to find the
   * equivalent object inside the factory.
   */
  compareDependency(op: Datatype): number {
    if (this.submeta !== op.submeta) return (this.submeta < op.submeta) ? -1 : 1;
    if (this.size !== op.size) return op.size - this.size;
    return 0;
  }

  /**
   * Encode a formal description of the data-type as a <type> element.
   * For composite data-types, the description goes down one level,
   * describing the component types only by reference.
   */
  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_TYPE);
    this.encodeBasic(this.metatype, -1, encoder);
    encoder.closeElement(ELEM_TYPE);
  }

  /**
   * Is this data-type suitable as input to a CPUI_PTRSUB op.
   * A CPUI_PTRSUB must act on a pointer data-type where the given offset addresses a component.
   */
  isPtrsubMatching(off: bigint, extra: bigint, multiplier: bigint): boolean {
    return false;
  }

  /**
   * Get a stripped version of this for formal use in formal declarations.
   * Some data-types are ephemeral and get replaced with a formal version.
   */
  getStripped(): Datatype | null {
    return null;
  }

  /**
   * Tailor data-type propagation based on Varnode use.
   * For unions, variables are transformed into a subtype depending on particular use.
   */
  resolveInFlow(op: PcodeOp, slot: number): Datatype {
    return this;
  }

  /**
   * Find a previously resolved sub-type.
   * This is the constant version of resolveInFlow.
   */
  findResolve(op: PcodeOp, slot: number): Datatype {
    return this;
  }

  /**
   * Find a resolution compatible with the given data-type.
   * If this data-type has an alternate form matching the given data-type, return its index.
   * Otherwise return -1.
   */
  findCompatibleResolve(ct: Datatype): number {
    return -1;
  }

  /**
   * Resolve which union field is being used for a given PcodeOp when a truncation is involved.
   */
  resolveTruncation(offset: bigint, op: PcodeOp, slot: number, newoff: { val: bigint }): TypeField | null {
    return null;
  }

  /**
   * Order this with op datatype.
   * Returns 0 if equal, negative if this is preferred, positive if op is preferred.
   */
  typeOrder(op: Datatype): number {
    if (this === op) return 0;
    return this.compare(op, 10);
  }

  /**
   * Order this with op, treating bool data-type as special.
   * Bool is ordered after all other data-types.
   * Returns -1, 0, or 1.
   */
  typeOrderBool(op: Datatype): number {
    if (this === op) return 0;
    if (this.metatype === type_metatype.TYPE_BOOL) return 1;  // Never prefer bool over other data-types
    if (op.metatype === type_metatype.TYPE_BOOL) return -1;
    return this.compare(op, 10);
  }

  /**
   * Encode a simple reference to this data-type as a <typeref> element,
   * including only the name and id.
   */
  encodeRef(encoder: Encoder): void {
    if (this.id !== 0n && this.metatype !== type_metatype.TYPE_VOID) {
      encoder.openElement(ELEM_TYPEREF);
      encoder.writeString(ATTRIB_NAME, this.name);
      if (this.isVariableLength()) {
        // For a type with a "variable length" base, emit the size independent version of the id
        encoder.writeUnsignedInteger(ATTRIB_ID, hashSize(this.id, this.size));
        encoder.writeSignedInteger(ATTRIB_SIZE, this.size);    // but also emit size of this instance
      } else {
        encoder.writeUnsignedInteger(ATTRIB_ID, this.id);
      }
      encoder.closeElement(ELEM_TYPEREF);
    } else {
      this.encode(encoder);
    }
  }

  /**
   * Does this data-type consist of separate pieces?
   * Generally a TYPE_STRUCT or TYPE_ARRAY should be represented with separate assignments.
   * Returns true if metatype <= TYPE_ARRAY.
   */
  isPieceStructured(): boolean {
    return this.metatype <= type_metatype.TYPE_ARRAY;
  }

  /**
   * Is this made up of a single primitive.
   * If this has no component data-types, return true.
   * If this has only a single primitive component filling the whole data-type, also return true.
   */
  isPrimitiveWhole(): boolean {
    if (!this.isPieceStructured()) return true;
    if (this.metatype === type_metatype.TYPE_ARRAY || this.metatype === type_metatype.TYPE_STRUCT) {
      if (this.numDepend() > 0) {
        const component = this.getDepend(0);
        if (component !== null && component.getSize() === this.getSize()) {
          return component.isPrimitiveWhole();
        }
      }
    }
    return false;
  }

  // --- Static methods ---

  /**
   * Encode an integer format string to a numeric value.
   */
  static encodeIntegerFormat(val: string): number {
    return encodeIntegerFormat(val);
  }

  /**
   * Decode a numeric integer format value to a string.
   */
  static decodeIntegerFormat(val: number): string {
    return decodeIntegerFormat(val);
  }

  /**
   * Produce a data-type id by hashing the type name.
   */
  static hashName(nm: string): bigint {
    return hashName(nm);
  }

  /**
   * Reversibly hash size into id.
   */
  static hashSize(id: bigint, size: number): bigint {
    return hashSize(id, size);
  }

  // --- Protected methods ---

  /**
   * Restore basic data-type properties (name, size, id, metatype, etc.) from a stream.
   * Properties are read from the attributes of the element.
   */
  /** @internal */ decodeBasic(decoder: Decoder): void {
    this.size = -1;
    this.metatype = type_metatype.TYPE_VOID;
    this.id = 0n;
    for (;;) {
      const attrib = decoder.getNextAttributeId();
      if (attrib === 0) break;
      if (attrib === ATTRIB_NAME.id) {
        this.name = decoder.readString();
      } else if (attrib === ATTRIB_SIZE.id) {
        this.size = decoder.readSignedInteger();
      } else if (attrib === ATTRIB_METATYPE.id) {
        this.metatype = string2metatype(decoder.readString());
      } else if (attrib === ATTRIB_CORE.id) {
        if (decoder.readBool()) {
          this.flags |= DT_coretype;
        }
      } else if (attrib === ATTRIB_ID.id) {
        this.id = decoder.readUnsignedInteger();
      } else if (attrib === ATTRIB_VARLENGTH.id) {
        if (decoder.readBool()) {
          this.flags |= DT_variable_length;
        }
      } else if (attrib === ATTRIB_ALIGNMENT.id) {
        this.alignment = decoder.readSignedInteger();
      } else if (attrib === ATTRIB_OPAQUESTRING.id) {
        if (decoder.readBool()) {
          this.flags |= DT_opaque_string;
        }
      } else if (attrib === ATTRIB_FORMAT.id) {
        const val = encodeIntegerFormat(decoder.readString());
        this.setDisplayFormat(val);
      } else if (attrib === ATTRIB_LABEL.id) {
        this.displayName = decoder.readString();
      } else if (attrib === ATTRIB_INCOMPLETE.id) {
        if (decoder.readBool()) {
          this.flags |= DT_type_incomplete;
        }
      }
    }
    if (this.size < 0) {
      throw new LowlevelError('Bad size for type ' + this.name);
    }
    this.alignSize = this.size;
    this.submeta = base2sub[this.metatype];
    if (this.id === 0n && this.name.length > 0) {
      // If there is a type name, there must be some kind of id
      this.id = hashName(this.name);
    }
    if (this.isVariableLength()) {
      // Id needs to be unique compared to another data-type with the same name
      this.id = hashSize(this.id, this.size);
    }
    if (this.displayName.length === 0) {
      this.displayName = this.name;
    }
  }

  /**
   * Encode basic data-type properties (name, size, id) as attributes.
   * This routine presumes the initial element is already written to the stream.
   */
  /** @internal */ encodeBasic(meta: type_metatype, align: number, encoder: Encoder): void {
    encoder.writeString(ATTRIB_NAME, this.name);
    const saveId = this.getUnsizedId();
    if (saveId !== 0n) {
      encoder.writeUnsignedInteger(ATTRIB_ID, saveId);
    }
    encoder.writeSignedInteger(ATTRIB_SIZE, this.size);
    const metastring = metatype2string(meta);
    encoder.writeString(ATTRIB_METATYPE, metastring);
    if (align > 0) {
      encoder.writeSignedInteger(ATTRIB_ALIGNMENT, align);
    }
    if ((this.flags & DT_coretype) !== 0) {
      encoder.writeBool(ATTRIB_CORE, true);
    }
    if (this.isVariableLength()) {
      encoder.writeBool(ATTRIB_VARLENGTH, true);
    }
    if ((this.flags & DT_opaque_string) !== 0) {
      encoder.writeBool(ATTRIB_OPAQUESTRING, true);
    }
    const format = this.getDisplayFormat();
    if (format !== 0) {
      encoder.writeString(ATTRIB_FORMAT, decodeIntegerFormat(format));
    }
  }

  /**
   * Encode this as a typedef element to a stream.
   * Called only if the typedefImm field is non-null.
   */
  /** @internal */ encodeTypedef(encoder: Encoder): void {
    encoder.openElement(ELEM_DEF);
    encoder.writeString(ATTRIB_NAME, this.name);
    encoder.writeUnsignedInteger(ATTRIB_ID, this.id);
    const format = this.getDisplayFormat();
    if (format !== 0) {
      encoder.writeString(ATTRIB_FORMAT, Datatype.decodeIntegerFormat(format));
    }
    this.typedefImm!.encodeRef(encoder);
    encoder.closeElement(ELEM_DEF);
  }

  /** Mark this data-type as completely defined */
  /** @internal */ markComplete(): void {
    this.flags &= ~DT_type_incomplete;
  }

  /**
   * Set a specific display format.
   * A value of zero clears any preexisting format.
   * Otherwise the value can be one of: 1=hex, 2=dec, 3=oct, 4=bin, 5=char.
   */
  /** @internal */ setDisplayFormat(format: number): void {
    this.flags &= ~DT_force_format;   // Clear preexisting
    this.flags |= (format << 12);
  }

  /** Clone the data-type */
  abstract clone(): Datatype;

  /**
   * Calculate aligned size, given size and alignment of data-type.
   * Returns size rounded up to be a multiple of align.
   */
  protected static calcAlignSize(sz: number, align: number): number {
    const mod = sz % align;
    if (mod !== 0) {
      return sz + (align - mod);
    }
    return sz;
  }
}

// =========================================================================
// TypeField
// =========================================================================

/**
 * A field within a structure or union.
 */
export class TypeField {
  ident: number;
  offset: number;
  name: string;
  type: Datatype;

  /**
   * Construct from components.
   */
  constructor(id: number, off: number, nm: string, ct: Datatype);
  /**
   * Restore this field from a stream.
   */
  constructor(decoder: Decoder, typegrp: TypeFactory);
  constructor(idOrDecoder: number | Decoder, offOrTypegrp: number | TypeFactory, nm?: string, ct?: Datatype) {
    if (typeof idOrDecoder === 'number') {
      this.ident = idOrDecoder;
      this.offset = offOrTypegrp as number;
      this.name = nm!;
      this.type = ct!;
    } else {
      const decoder = idOrDecoder as Decoder;
      const typegrp = offOrTypegrp as TypeFactory;
      this.ident = -1;
      this.offset = -1;
      this.name = '';
      this.type = null as any;

      const elemId = decoder.openElementId(ELEM_FIELD);
      for (;;) {
        const attrib = decoder.getNextAttributeId();
        if (attrib === 0) break;
        if (attrib === ATTRIB_NAME.id) {
          this.name = decoder.readString();
        } else if (attrib === ATTRIB_OFFSET.id) {
          this.offset = decoder.readSignedInteger();
        } else if (attrib === ATTRIB_ID.id) {
          this.ident = decoder.readSignedInteger();
        }
      }
      this.type = typegrp.decodeType(decoder);
      if (this.name.length === 0) {
        throw new LowlevelError('name attribute must not be empty in <field> tag');
      }
      if (this.offset < 0) {
        throw new LowlevelError('offset attribute invalid for <field> tag');
      }
      if (this.ident < 0) {
        this.ident = this.offset; // By default the id is the offset
      }
      decoder.closeElement(elemId);
    }
  }

  /** Compare based on offset */
  lessThan(op2: TypeField): boolean {
    return this.offset < op2.offset;
  }

  /**
   * Encode a formal description of this as a <field> element.
   */
  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_FIELD);
    encoder.writeString(ATTRIB_NAME, this.name);
    encoder.writeSignedInteger(ATTRIB_OFFSET, this.offset);
    if (this.ident !== this.offset) {
      encoder.writeSignedInteger(ATTRIB_ID, this.ident);
    }
    this.type.encodeRef(encoder);
    encoder.closeElement(ELEM_FIELD);
  }
}

// =========================================================================
// DatatypeCompare / DatatypeNameCompare (as functions)
// =========================================================================

/**
 * Compare two Datatype pointers for equivalence of their description.
 * First by compareDependency, then by id.
 */
export function DatatypeCompare(a: Datatype, b: Datatype): number {
  const res = a.compareDependency(b);
  if (res !== 0) return res;
  if (a.getId() < b.getId()) return -1;
  if (a.getId() > b.getId()) return 1;
  return 0;
}

/**
 * Compare two Datatype pointers: first by name, then by id.
 */
export function DatatypeNameCompare(a: Datatype, b: Datatype): number {
  const nameA = a.getName();
  const nameB = b.getName();
  if (nameA < nameB) return -1;
  if (nameA > nameB) return 1;
  if (a.getId() < b.getId()) return -1;
  if (a.getId() > b.getId()) return 1;
  return 0;
}

// =========================================================================
// TypeBase
// =========================================================================

/**
 * Base class for the fundamental atomic types.
 * Data-types with a name, size, and meta-type.
 */
export class TypeBase extends Datatype {
  /** Construct TypeBase copying properties from another data-type */
  constructor(op: TypeBase);
  /** Construct TypeBase from a size and meta-type */
  constructor(s: number, m: type_metatype);
  /** Construct TypeBase from a size, meta-type, and name */
  constructor(s: number, m: type_metatype, n: string);
  constructor(sOrOp: number | TypeBase, m?: type_metatype, n?: string) {
    if (typeof sOrOp !== 'number') {
      super(sOrOp);
    } else if (n !== undefined) {
      super(sOrOp, -1, m!);
      this.name = n;
      this.displayName = n;
    } else {
      super(sOrOp, -1, m!);
    }
  }

  clone(): Datatype {
    return new TypeBase(this);
  }
}

// =========================================================================
// TypeChar
// =========================================================================

/**
 * Base type for character data-types: i.e. char.
 * This is always presumed to be UTF-8 encoded.
 */
export class TypeChar extends TypeBase {
  /** Construct TypeChar copying properties from another data-type */
  constructor(op: TypeChar);
  /** Construct a char (always 1-byte) given a name */
  constructor(n: string);
  constructor(nOrOp: string | TypeChar) {
    if (typeof nOrOp === 'string') {
      super(1, type_metatype.TYPE_INT, nOrOp);
      this.flags |= DT_chartype;
      this.submeta = sub_metatype.SUB_INT_CHAR;
    } else {
      super(nOrOp);
      this.flags |= DT_chartype;
    }
  }

  clone(): Datatype {
    return new TypeChar(this);
  }

  encode(encoder: Encoder): void {
    if (this.typedefImm !== null) {
      this.encodeTypedef(encoder);
      return;
    }
    encoder.openElement(ELEM_TYPE);
    this.encodeBasic(this.metatype, -1, encoder);
    encoder.writeBool(ATTRIB_CHAR, true);
    encoder.closeElement(ELEM_TYPE);
  }

  /**
   * Restore this char data-type from a stream.
   */
  decode(decoder: Decoder, typegrp: TypeFactory): void {
    this.decodeBasic(decoder);
    this.submeta = (this.metatype === type_metatype.TYPE_INT) ? sub_metatype.SUB_INT_CHAR : sub_metatype.SUB_UINT_CHAR;
  }
}

// =========================================================================
// TypeUnicode
// =========================================================================

/**
 * The unicode data-type: i.e. wchar.
 * This supports encoding elements that are wider than 1 byte.
 */
export class TypeUnicode extends TypeBase {
  /** For use with decode */
  constructor();
  /** Construct from another TypeUnicode */
  constructor(op: TypeUnicode);
  /** Construct given name, size, meta-type */
  constructor(nm: string, sz: number, m: type_metatype);
  constructor(nmOrOp?: string | TypeUnicode, sz?: number, m?: type_metatype) {
    if (nmOrOp === undefined) {
      // Default constructor for use with decode
      super(0, type_metatype.TYPE_INT);
    } else if (typeof nmOrOp === 'string') {
      // Construct given name, size, meta-type
      super(sz!, m!, nmOrOp);
      this.setflags();
      this.submeta = (m === type_metatype.TYPE_INT) ? sub_metatype.SUB_INT_UNICODE : sub_metatype.SUB_UINT_UNICODE;
    } else {
      // Copy constructor
      super(nmOrOp);
    }
  }

  /**
   * Set unicode property flags based on size.
   * Select UTF8, UTF16, or UTF32.
   */
  private setflags(): void {
    if (this.size === 2) {
      this.flags |= DT_utf16;    // 16-bit UTF16 encoding
    } else if (this.size === 4) {
      this.flags |= DT_utf32;    // 32-bit UTF32 encoding
    } else if (this.size === 1) {
      this.flags |= DT_chartype; // Default to basic char (ultimately UTF8)
    }
  }

  clone(): Datatype {
    return new TypeUnicode(this);
  }

  encode(encoder: Encoder): void {
    if (this.typedefImm !== null) {
      this.encodeTypedef(encoder);
      return;
    }
    encoder.openElement(ELEM_TYPE);
    this.encodeBasic(this.metatype, -1, encoder);
    encoder.writeBool(ATTRIB_UTF, true);
    encoder.closeElement(ELEM_TYPE);
  }

  /**
   * Restore this unicode data-type from a stream.
   */
  decode(decoder: Decoder, typegrp: TypeFactory): void {
    this.decodeBasic(decoder);
    this.setflags();
    this.submeta = (this.metatype === type_metatype.TYPE_INT) ? sub_metatype.SUB_INT_UNICODE : sub_metatype.SUB_UINT_UNICODE;
  }
}

// =========================================================================
// TypeVoid
// =========================================================================

/**
 * Formal "void" data-type object.
 * A placeholder for "no data-type".
 * This should be the only object with meta-type set to TYPE_VOID.
 */
export class TypeVoid extends Datatype {
  /** Construct from another TypeVoid */
  constructor(op: TypeVoid);
  /** Constructor */
  constructor();
  constructor(op?: TypeVoid) {
    if (op !== undefined) {
      super(op);
      this.flags |= DT_coretype;
    } else {
      super(0, 1, type_metatype.TYPE_VOID);
      this.name = 'void';
      this.displayName = this.name;
      this.flags |= DT_coretype;
    }
  }

  clone(): Datatype {
    return new TypeVoid(this);
  }

  encode(encoder: Encoder): void {
    if (this.typedefImm !== null) {
      this.encodeTypedef(encoder);
      return;
    }
    encoder.openElement(ELEM_VOID);
    encoder.closeElement(ELEM_VOID);
  }

  /**
   * Restore the void data-type, with an id.
   */
  decode(decoder: Decoder, typegrp: TypeFactory): void {
    for (;;) {
      const attrib = decoder.getNextAttributeId();
      if (attrib === 0) break;
      if (attrib === ATTRIB_ID.id) {
        this.id = decoder.readUnsignedInteger();
      }
    }
  }
}


/// Datatype object representing a pointer
class TypePointer extends Datatype {
  protected ptrto: Datatype;            // Type being pointed to
  protected spaceid: AddrSpace | null;  // If non-null, the address space this is intended to point into
  protected truncate: TypePointer | null; // Truncated form of the pointer (if not null)
  protected wordsize: number;           // What size unit does the pointer address

  /// Test if an out-of-bounds offset makes sense as array slack
  private static testForArraySlack(dt: Datatype, off: bigint): boolean {
    let newoff: bigint;
    let elSize: bigint;
    if (dt.getMetatype() === type_metatype.TYPE_ARRAY)
      return true;
    let compType: Datatype | null;
    if (off < 0n) {
      const newoffRef = { val: 0n };
      const elSizeRef = { val: 0n };
      compType = dt.nearestArrayedComponentForward(off, newoffRef, elSizeRef);
    }
    else {
      const newoffRef = { val: 0n };
      const elSizeRef = { val: 0n };
      compType = dt.nearestArrayedComponentBackward(off, newoffRef, elSizeRef);
    }
    return (compType !== null);
  }

  /// Internal constructor for use with decode
  constructor();
  /// Construct from another TypePointer
  constructor(op: TypePointer);
  /// Construct from a size, pointed-to type, and wordsize
  constructor(s: number, pt: Datatype, ws: number);
  /// Construct from a pointed-to type and an address space attribute
  constructor(pt: Datatype, spc: AddrSpace);
  constructor(arg1?: any, arg2?: any, arg3?: any) {
    if (arg1 === undefined) {
      // Internal constructor for decode
      super(0, -1, type_metatype.TYPE_PTR);
      this.ptrto = null!;
      this.wordsize = 1;
      this.spaceid = null;
      this.truncate = null;
    }
    else if (arg1 instanceof TypePointer) {
      // Copy constructor
      super(arg1 as Datatype);
      const op = arg1;
      this.ptrto = op.ptrto;
      this.wordsize = op.wordsize;
      this.spaceid = op.spaceid;
      this.truncate = op.truncate;
    }
    else if (arg2 instanceof Datatype && typeof arg3 === 'number') {
      // Construct from size, pointed-to type, wordsize
      super(arg1, -1, type_metatype.TYPE_PTR);
      this.ptrto = arg2;
      this.flags = arg2.getInheritable();
      this.wordsize = arg3;
      this.spaceid = null;
      this.truncate = null;
      this.calcSubmeta();
    }
    else {
      // Construct from pointed-to type and address space
      const pt = arg1 as Datatype;
      const spc = arg2 as AddrSpace;
      super(spc.getAddrSize(), -1, type_metatype.TYPE_PTR);
      this.ptrto = pt;
      this.flags = pt.getInheritable();
      this.spaceid = spc;
      this.wordsize = spc.getWordSize();
      this.truncate = null;
      this.calcSubmeta();
    }
  }

  /// Get the pointed-to Datatype
  getPtrTo(): Datatype { return this.ptrto; }

  /// Get the size of the addressable unit being pointed to
  getWordSize(): number { return this.wordsize; }

  /// Get any address space associated with this pointer
  getSpace(): AddrSpace | null { return this.spaceid; }

  /// Pointers to structures may require a specific submeta
  protected calcSubmeta(): void {
    const ptrtoMeta = this.ptrto.getMetatype();
    if (ptrtoMeta === type_metatype.TYPE_STRUCT) {
      if (this.ptrto.numDepend() > 1 || this.ptrto.isIncomplete())
        this.submeta = sub_metatype.SUB_PTR_STRUCT;
      else
        this.submeta = sub_metatype.SUB_PTR;
    }
    else if (ptrtoMeta === type_metatype.TYPE_UNION) {
      this.submeta = sub_metatype.SUB_PTR_STRUCT;
    }
    else if (ptrtoMeta === type_metatype.TYPE_ARRAY) {
      this.flags |= DT_pointer_to_array;
    }
    if (this.ptrto.needsResolution() && ptrtoMeta !== type_metatype.TYPE_PTR)
      this.flags |= DT_needs_resolution;
  }

  /// If this pointer has a size of sizeOfAltPointer, a smaller (sizeOfPointer) pointer
  /// data-type is created and assigned to this as a subcomponent.
  /** @internal */ calcTruncate(typegrp: TypeFactory): void {
    if (this.truncate !== null || this.size !== typegrp.getSizeOfAltPointer())
      return;
    this.truncate = typegrp.resizePointer(this, typegrp.getSizeOfPointer());
    if (typegrp.getArch().getDefaultDataSpace().isBigEndian())
      this.flags |= DT_truncate_bigendian;
  }

  printRaw(s: Writer): void {
    this.ptrto.printRaw(s);
    s.write(' *');
    if (this.spaceid !== null) {
      s.write('(' + this.spaceid.getName() + ')');
    }
  }

  getSubType(off: bigint, newoff: { val: bigint }): Datatype | null {
    if (this.truncate !== null) {
      const min = ((this.flags & DT_truncate_bigendian) !== 0) ? BigInt(this.size - this.truncate.getSize()) : 0n;
      if (off >= min && off < min + BigInt(this.truncate.getSize())) {
        newoff.val = off - min;
        return this.truncate;
      }
    }
    return super.getSubType(off, newoff);
  }

  numDepend(): number { return 1; }

  getDepend(index: number): Datatype | null { return this.ptrto; }

  printNameBase(s: Writer): void { s.write('p'); this.ptrto.printNameBase(s); }

  compare(op: Datatype, level: number): number {
    let res = super.compare(op, level);
    if (res !== 0) return res;
    // Both must be pointers
    const tp = op as TypePointer;
    if (this.wordsize !== tp.wordsize) return (this.wordsize < tp.wordsize) ? -1 : 1;
    if (this.spaceid !== tp.spaceid) {
      if (this.spaceid === null) return 1;     // Pointers with address space come earlier
      if (tp.spaceid === null) return -1;
      return (this.spaceid.getIndex() < tp.spaceid.getIndex()) ? -1 : 1;
    }
    level -= 1;
    if (level < 0) {
      if (this.id === op.getId()) return 0;
      return (this.id < op.getId()) ? -1 : 1;
    }
    return this.ptrto.compare(tp.ptrto, level);
  }

  compareDependency(op: Datatype): number {
    if (this.submeta !== op.getSubMeta()) return (this.submeta < op.getSubMeta()) ? -1 : 1;
    const tp = op as TypePointer;
    if (this.ptrto !== tp.ptrto) return (this.ptrto < tp.ptrto) ? -1 : 1; // Compare absolute pointers (reference identity)
    if (this.wordsize !== tp.wordsize) return (this.wordsize < tp.wordsize) ? -1 : 1;
    if (this.spaceid !== tp.spaceid) {
      if (this.spaceid === null) return 1;
      if (tp.spaceid === null) return -1;
      return (this.spaceid.getIndex() < tp.spaceid.getIndex()) ? -1 : 1;
    }
    return (op.getSize() - this.size);
  }

  clone(): Datatype { return new TypePointer(this); }

  encode(encoder: Encoder): void {
    if (this.typedefImm !== null) {
      this.encodeTypedef(encoder);
      return;
    }
    encoder.openElement(ELEM_TYPE);
    this.encodeBasic(this.metatype, -1, encoder);
    if (this.wordsize !== 1)
      encoder.writeUnsignedInteger(ATTRIB_WORDSIZE, BigInt(this.wordsize));
    if (this.spaceid !== null)
      encoder.writeSpace(ATTRIB_SPACE, this.spaceid as any);
    this.ptrto.encodeRef(encoder);
    encoder.closeElement(ELEM_TYPE);
  }

  /// Restore this pointer data-type from a stream
  protected decode(decoder: Decoder, typegrp: TypeFactory): void {
    this.decodeBasic(decoder);
    decoder.rewindAttributes();
    for (;;) {
      const attrib = decoder.getNextAttributeId();
      if (attrib === 0) break;
      if (attrib === ATTRIB_WORDSIZE.id) {
        this.wordsize = Number(decoder.readUnsignedInteger());
      }
      else if (attrib === ATTRIB_SPACE.id) {
        this.spaceid = decoder.readSpace() as unknown as AddrSpace;
      }
    }
    this.ptrto = typegrp.decodeType(decoder);
    this.calcSubmeta();
    if (this.name.length === 0)       // Inherit only if no name
      this.flags |= this.ptrto.getInheritable();
    this.calcTruncate(typegrp);
  }

  /// Find a sub-type pointer given an offset into this
  downChain(off: { val: bigint }, par: { val: TypePointer | null }, parOff: { val: bigint }, allowArrayWrap: boolean, typegrp: TypeFactory): TypePointer | null {
    const ptrtoSize = this.ptrto.getAlignSize();
    if (off.val < 0n || off.val >= BigInt(ptrtoSize)) {  // Check if we are wrapping
      if (ptrtoSize !== 0 && !this.ptrto.isVariableLength()) {  // Check if pointed-to is wrappable
        if (!allowArrayWrap)
          return null;
        let signOff = sign_extend(off.val, this.size * 8 - 1);
        signOff = signOff % BigInt(ptrtoSize);
        if (signOff < 0n)
          signOff = signOff + BigInt(ptrtoSize);
        off.val = signOff;
        if (off.val === 0n)      // If we've wrapped and are now at zero
          return this;           // consider this going down one level
      }
    }

    if (this.ptrto.isEnumType()) {
      // Go "into" the enumeration
      const tmp = typegrp.getBase(1, type_metatype.TYPE_UINT);
      off.val = 0n;
      return typegrp.getTypePointer(this.size, tmp, this.wordsize);
    }
    const meta = this.ptrto.getMetatype();
    const isArray = (meta === type_metatype.TYPE_ARRAY);
    if (isArray || meta === type_metatype.TYPE_STRUCT) {
      par.val = this;
      parOff.val = off.val;
    }

    const newoffRef = { val: 0n };
    const pt = this.ptrto.getSubType(off.val, newoffRef);
    off.val = newoffRef.val;
    if (pt === null)
      return null;
    if (!isArray)
      return typegrp.getTypePointerStripArray(this.size, pt, this.wordsize);
    return typegrp.getTypePointer(this.size, pt, this.wordsize);
  }

  isPtrsubMatching(off: bigint, extra: bigint, multiplier: bigint): boolean {
    const meta = this.ptrto.getMetatype();
    if (meta === type_metatype.TYPE_SPACEBASE) {
      let newoff = AddrSpace.addressToByteInt(off, this.wordsize);
      const newoffRef = { val: 0n };
      const subType = this.ptrto.getSubType(newoff, newoffRef);
      newoff = newoffRef.val;
      if (subType === null || newoff !== 0n)
        return false;
      extra = AddrSpace.addressToByteInt(extra, this.wordsize);
      if (extra < 0n || extra >= BigInt(subType.getSize())) {
        if (!TypePointer.testForArraySlack(subType, extra))
          return false;
      }
    }
    else if (meta === type_metatype.TYPE_ARRAY) {
      if (off !== 0n)
        return false;
      multiplier = AddrSpace.addressToByteInt(multiplier, this.wordsize);
      if (multiplier >= BigInt(this.ptrto.getAlignSize()))
        return false;
    }
    else if (meta === type_metatype.TYPE_STRUCT) {
      const typesize = this.ptrto.getSize();
      multiplier = AddrSpace.addressToByteInt(multiplier, this.wordsize);
      if (multiplier >= BigInt(this.ptrto.getAlignSize()))
        return false;
      let newoff = AddrSpace.addressToByteInt(off, this.wordsize);
      extra = AddrSpace.addressToByteInt(extra, this.wordsize);
      const newoffRef = { val: 0n };
      const subType = this.ptrto.getSubType(newoff, newoffRef);
      newoff = newoffRef.val;
      if (subType !== null) {
        if (newoff !== 0n)
          return false;
        if (extra < 0n || extra >= BigInt(subType.getSize())) {
          if (!TypePointer.testForArraySlack(subType, extra))
            return false;
        }
      }
      else {
        extra += newoff;
        if ((extra < 0n || extra >= BigInt(typesize)) && (typesize !== 0))
          return false;
      }
    }
    else if (this.ptrto.getMetatype() === type_metatype.TYPE_UNION) {
      // A PTRSUB reaching here cannot be used for a union field resolution
      return false;
    }
    else
      return false;   // Not a pointer to a structured data-type
    return true;
  }

  resolveInFlow(op: PcodeOp, slot: number): Datatype {
    if (this.ptrto.getMetatype() === type_metatype.TYPE_UNION) {
      const fd = op.getParent().getFuncdata();
      const res = fd.getUnionField(this, op, slot);
      if (res !== null)
        return res.getDatatype();
      const scoreFields = new ScoreUnionFields(fd.getArch().types, this, op, slot);
      const bestResult = scoreFields.getResult();
      if (bestResult === null || bestResult === undefined) {
        const fallback = new ResolvedUnion(this);
        fd.setUnionField(this, op, slot, fallback);
        return this;
      }
      fd.setUnionField(this, op, slot, bestResult);
      return bestResult.getDatatype();
    }
    return this;
  }

  findResolve(op: PcodeOp, slot: number): Datatype {
    if (this.ptrto.getMetatype() === type_metatype.TYPE_UNION) {
      const fd = op.getParent().getFuncdata();
      const res = fd.getUnionField(this, op, slot);
      if (res !== null)
        return res.getDatatype();
      return this;
    }
    return this;
  }
}

/// Datatype object representing an array of elements
class TypeArray extends Datatype {
  protected arrayof: Datatype;    // type of which we have an array
  protected arraysize: number;    // Number of elements in the array

  /// Internal constructor for decode
  constructor();
  /// Construct from another TypeArray
  constructor(op: TypeArray);
  /// Construct given an array size and element data-type
  constructor(n: number, ao: Datatype);
  constructor(arg1?: any, arg2?: any) {
    if (arg1 === undefined) {
      // Internal constructor for decode
      super(0, -1, type_metatype.TYPE_ARRAY);
      this.arraysize = 0;
      this.arrayof = null!;
    }
    else if (arg1 instanceof TypeArray) {
      // Copy constructor
      super(arg1 as Datatype);
      this.arrayof = arg1.arrayof;
      this.arraysize = arg1.arraysize;
    }
    else {
      // Construct from array size and element data-type
      const n = arg1 as number;
      const ao = arg2 as Datatype;
      super(n * ao.getAlignSize(), ao.getAlignment(), type_metatype.TYPE_ARRAY);
      this.arraysize = n;
      this.arrayof = ao;
      // A varnode which is an array of size 1, should generally always be treated
      // as the element data-type
      if (n === 1)
        this.flags |= DT_needs_resolution;
    }
  }

  /// Get the element data-type
  getBase(): Datatype { return this.arrayof; }

  /// Get the number of elements
  numElements(): number { return this.arraysize; }

  /// Given some contiguous piece of the array, figure out which element overlaps
  /// the piece, and pass back the element index and the renormalized offset
  getSubEntry(off: number, sz: number, newoff: { val: number }, el: { val: number }): Datatype | null {
    const noff = off % this.arrayof.getAlignSize();
    const nel = Math.floor(off / this.arrayof.getAlignSize());
    if (noff + sz > this.arrayof.getAlignSize())  // Requesting parts of more than one element
      return null;
    newoff.val = noff;
    el.val = nel;
    return this.arrayof;
  }

  printRaw(s: Writer): void {
    this.arrayof.printRaw(s);
    s.write(' [' + this.arraysize.toString() + ']');
  }

  getSubType(off: bigint, newoff: { val: bigint }): Datatype | null {
    // Go down exactly one level, to type of element
    if (off >= BigInt(this.size))
      return super.getSubType(off, newoff);
    newoff.val = off % BigInt(this.arrayof.getAlignSize());
    return this.arrayof;
  }

  getHoleSize(off: number): number {
    const newOff = off % this.arrayof.getAlignSize();
    return this.arrayof.getHoleSize(newOff);
  }

  numDepend(): number { return 1; }

  getDepend(index: number): Datatype | null { return this.arrayof; }

  printNameBase(s: Writer): void { s.write('a'); this.arrayof.printNameBase(s); }

  compare(op: Datatype, level: number): number {
    let res = super.compare(op, level);
    if (res !== 0) return res;
    level -= 1;
    if (level < 0) {
      if (this.id === op.getId()) return 0;
      return (this.id < op.getId()) ? -1 : 1;
    }
    const ta = op as TypeArray;
    return this.arrayof.compare(ta.arrayof, level);
  }

  compareDependency(op: Datatype): number {
    if (this.submeta !== op.getSubMeta()) return (this.submeta < op.getSubMeta()) ? -1 : 1;
    const ta = op as TypeArray;
    if (this.arrayof !== ta.arrayof) return (this.arrayof < ta.arrayof) ? -1 : 1; // Compare absolute pointers
    return (op.getSize() - this.size);
  }

  clone(): Datatype { return new TypeArray(this); }

  encode(encoder: Encoder): void {
    if (this.typedefImm !== null) {
      this.encodeTypedef(encoder);
      return;
    }
    encoder.openElement(ELEM_TYPE);
    this.encodeBasic(this.metatype, -1, encoder);
    encoder.writeSignedInteger(ATTRIB_ARRAYSIZE, this.arraysize);
    this.arrayof.encodeRef(encoder);
    encoder.closeElement(ELEM_TYPE);
  }

  /// Restore this array from a stream
  protected decode(decoder: Decoder, typegrp: TypeFactory): void {
    this.decodeBasic(decoder);
    this.arraysize = -1;
    decoder.rewindAttributes();
    for (;;) {
      const attrib = decoder.getNextAttributeId();
      if (attrib === 0) break;
      if (attrib === ATTRIB_ARRAYSIZE.id) {
        this.arraysize = Number(decoder.readSignedInteger());
      }
    }
    this.arrayof = typegrp.decodeType(decoder);
    if ((this.arraysize <= 0) || (this.arraysize * this.arrayof.getAlignSize() !== this.size))
      throw new LowlevelError("Bad size for array of type " + this.arrayof.getName());
    this.alignment = this.arrayof.getAlignment();
    if (this.arraysize === 1)
      this.flags |= DT_needs_resolution;     // Array of size 1 needs special treatment
  }

  resolveInFlow(op: PcodeOp, slot: number): Datatype {
    const fd = op.getParent().getFuncdata();
    const res = fd.getUnionField(this, op, slot);
    if (res !== null)
      return res.getDatatype();

    const fieldNum = TypeStruct.scoreSingleComponent(this, op, slot);

    const compFill = new ResolvedUnion(this, fieldNum, fd.getArch().types);
    fd.setUnionField(this, op, slot, compFill);
    return compFill.getDatatype();
  }

  findResolve(op: PcodeOp, slot: number): Datatype {
    const fd = op.getParent().getFuncdata();
    const res = fd.getUnionField(this, op, slot);
    if (res !== null)
      return res.getDatatype();
    return this.arrayof;    // If not calculated before, assume referring to the element
  }

  findCompatibleResolve(ct: Datatype): number {
    if (ct.needsResolution() && !this.arrayof.needsResolution()) {
      if (ct.findCompatibleResolve(this.arrayof) >= 0)
        return 0;
    }
    if (this.arrayof === ct)
      return 0;
    return -1;
  }
}

/// An enumerated Datatype object: an integer with named values.
///
/// This supports combinations of the enumeration values (using logical OR and bit-wise complement)
/// by defining independent bit-fields.
class TypeEnum extends TypeBase {
  /// Class describing how a particular enumeration value is constructed using tokens
  static Representation = class Representation {
    matchname: string[];    // Name tokens that are ORed together
    complement: boolean;    // If true, bitwise complement value after ORing
    shiftAmount: number;    // Number of bits to left-shift final value
    constructor() {
      this.matchname = [];
      this.complement = false;
      this.shiftAmount = 0;
    }
  };

  protected namemap: Map<bigint, string>;   // Map from integer to name

  /// Establish the value -> name map
  protected setNameMap(nmap: Map<bigint, string>): void { this.namemap = new Map(nmap); }

  /// Construct from another TypeEnum
  constructor(op: TypeEnum);
  /// Construct from a size and meta-type (TYPE_ENUM_INT or TYPE_ENUM_UINT)
  constructor(s: number, m: type_metatype);
  /// Construct from a size, meta-type, and name
  constructor(s: number, m: type_metatype, nm: string);
  constructor(arg1: any, arg2?: any, arg3?: any) {
    if (arg1 instanceof TypeEnum) {
      // Copy constructor
      super(arg1);
      this.namemap = new Map(arg1.namemap);
    }
    else if (arg3 !== undefined) {
      // Construct from size, metatype, name
      super(arg1, arg2, arg3);
      this.flags |= DT_enumtype;
      this.metatype = (arg2 === type_metatype.TYPE_ENUM_INT) ? type_metatype.TYPE_INT : type_metatype.TYPE_UINT;
      this.namemap = new Map();
    }
    else {
      // Construct from size, metatype
      super(arg1, arg2);
      this.flags |= DT_enumtype;
      this.metatype = (arg2 === type_metatype.TYPE_ENUM_INT) ? type_metatype.TYPE_INT : type_metatype.TYPE_UINT;
      this.namemap = new Map();
    }
  }

  /// Beginning of name map iteration (returns iterator)
  beginEnum(): IterableIterator<[bigint, string]> { return this.namemap.entries(); }

  /// End of name map (for Map, use .size or iterate)
  endEnum(): IterableIterator<[bigint, string]> { return this.namemap.entries(); }

  /// Does this enumeration have a (single) name for the given value
  hasNamedValue(val: bigint): boolean {
    return this.namemap.has(val);
  }

  /// Recover the named representation
  getMatches(val: bigint, rep: InstanceType<typeof TypeEnum.Representation>): void {
    for (let count = 0; count < 2; ++count) {
      let allmatch = true;
      if (val === 0n) {     // Zero handled specially
        const name = this.namemap.get(val);
        if (name !== undefined)
          rep.matchname.push(name);
        else
          allmatch = false;
      }
      else {
        let bitsleft = val;
        let target = val;
        while (target !== 0n) {
          // Find named value that matches the largest number of most significant bits in bitsleft
          // We need to find the largest key <= target
          let bestKey: bigint | null = null;
          let bestName: string | null = null;
          for (const [k, v] of this.namemap) {
            if (k <= target) {
              if (bestKey === null || k > bestKey) {
                bestKey = k;
                bestName = v;
              }
            }
          }
          if (bestKey === null) break;  // All named values are greater than target

          const curval = bestKey;
          const diff = coveringmask(bitsleft ^ curval);
          if (diff >= bitsleft) break;   // Could not match most significant bit of bitsleft
          if ((curval & diff) === 0n) {
            // Found a named value that matches at least most significant bit of bitsleft
            rep.matchname.push(bestName!);
            bitsleft ^= curval;
            target = bitsleft;
          }
          else {
            // Not all the (one) bits of curval match into bitsleft, but we can restrict a further search.
            target = curval & ~diff;
          }
        }
        allmatch = (bitsleft === 0n);
      }
      if (allmatch) {         // If we have a complete representation
        rep.complement = (count === 1);
        return;
      }
      val = val ^ calc_mask(this.size);   // Switch value we are trying to represent (to complement)
      rep.matchname.length = 0;           // Clear out old attempt
    }
    // If we reach here, no representation was possible, matchname is empty
  }

  compare(op: Datatype, level: number): number {
    return this.compareDependency(op);
  }

  compareDependency(op: Datatype): number {
    let res = super.compareDependency(op);  // Compare as basic types first (TypeBase -> Datatype)
    if (res !== 0) return res;

    const te = op as TypeEnum;

    if (this.namemap.size !== te.namemap.size) {
      return (this.namemap.size < te.namemap.size) ? -1 : 1;
    }
    // Compare sorted entries
    const entries1 = Array.from(this.namemap.entries()).sort((a, b) => (a[0] < b[0]) ? -1 : (a[0] > b[0]) ? 1 : 0);
    const entries2 = Array.from(te.namemap.entries()).sort((a, b) => (a[0] < b[0]) ? -1 : (a[0] > b[0]) ? 1 : 0);
    for (let i = 0; i < entries1.length; i++) {
      if (entries1[i][0] !== entries2[i][0])
        return (entries1[i][0] < entries2[i][0]) ? -1 : 1;
      if (entries1[i][1] !== entries2[i][1])
        return (entries1[i][1] < entries2[i][1]) ? -1 : 1;
    }
    return 0;
  }

  clone(): Datatype { return new TypeEnum(this); }

  encode(encoder: Encoder): void {
    if (this.typedefImm !== null) {
      this.encodeTypedef(encoder);
      return;
    }
    encoder.openElement(ELEM_TYPE);
    this.encodeBasic(
      (this.metatype === type_metatype.TYPE_INT) ? type_metatype.TYPE_ENUM_INT : type_metatype.TYPE_ENUM_UINT,
      -1,
      encoder
    );
    for (const [val, nm] of this.namemap) {
      encoder.openElement(ELEM_VAL);
      encoder.writeString(ATTRIB_NAME, nm);
      encoder.writeUnsignedInteger(ATTRIB_VALUE, val);
      encoder.closeElement(ELEM_VAL);
    }
    encoder.closeElement(ELEM_TYPE);
  }

  /// Restore this enum data-type from a stream
  protected decodeEnum(decoder: Decoder, typegrp: TypeFactory): string {
    this.decodeBasic(decoder);
    this.metatype = (this.metatype === type_metatype.TYPE_ENUM_INT) ? type_metatype.TYPE_INT : type_metatype.TYPE_UINT;
    const nmap = new Map<bigint, string>();
    let warning = '';

    for (;;) {
      const childId = decoder.openElement();
      if (childId === 0) break;
      let val = 0n;
      let nm = '';
      for (;;) {
        const attrib = decoder.getNextAttributeId();
        if (attrib === 0) break;
        if (attrib === ATTRIB_VALUE.id) {
          const valsign = decoder.readSignedInteger();  // Value might be negative
          val = BigInt.asUintN(64, BigInt(valsign)) & calc_mask(this.size);
        }
        else if (attrib === ATTRIB_NAME.id)
          nm = decoder.readString();
      }
      if (nm.length === 0)
        throw new LowlevelError(this.name + ": TypeEnum field missing name attribute");
      if (nmap.has(val)) {
        if (warning.length === 0)
          warning = 'Enum "' + this.name + '": Some values do not have unique names';
      }
      else
        nmap.set(val, nm);
      decoder.closeElement(childId);
    }
    this.setNameMap(nmap);
    return warning;
  }

  /// Establish unique enumeration values for a TypeEnum.
  /// Fill in any values for any names that weren't explicitly assigned and check for duplicates.
  static assignValues(
    nmap: Map<bigint, string>,
    namelist: string[],
    vallist: bigint[],
    assignlist: boolean[],
    te: TypeEnum
  ): void {
    const mask = calc_mask(te.getSize());
    let maxval = 0n;
    for (let i = 0; i < namelist.length; ++i) {
      if (assignlist[i]) {    // Did the user explicitly set value
        let val = vallist[i];
        if (val > maxval)
          maxval = val;
        val = val & mask;
        if (nmap.has(val)) {
          throw new LowlevelError('Enum "' + te.name + '": "' + namelist[i] + '" is a duplicate value');
        }
        nmap.set(val, namelist[i]);
      }
    }
    for (let i = 0; i < namelist.length; ++i) {
      if (!assignlist[i]) {
        let val: bigint;
        do {
          maxval += 1n;
          val = maxval;
          val = val & mask;
        } while (nmap.has(val));
        nmap.set(val, namelist[i]);
      }
    }
  }
}

/// A composite Datatype object: A structure with component fields
export class TypeStruct extends Datatype {
  protected field: TypeField[];       // The list of fields

  /// Construct from another TypeStruct
  constructor(op: TypeStruct);
  /// Construct incomplete/empty TypeStruct
  constructor();
  constructor(arg1?: any) {
    if (arg1 instanceof TypeStruct) {
      super(arg1 as Datatype);
      this.field = [];
      this.setFields(arg1.field, arg1.size, arg1.alignment);
      this.alignSize = arg1.alignSize;
    }
    else {
      super(0, -1, type_metatype.TYPE_STRUCT);
      this.flags |= DT_type_incomplete;
      this.field = [];
    }
  }

  /// Beginning of fields
  beginField(): TypeField[] { return this.field; }

  /// Get a specific field by index
  getField(i: number): TypeField { return this.field[i]; }

  /// Establish fields for this
  protected setFields(fd: TypeField[], newSize: number, newAlign: number): void {
    this.field = fd.slice();  // Copy the array
    this.size = newSize;
    this.alignment = newAlign;
    if (this.field.length === 1) {            // A single field
      if (this.field[0].type.getSize() === this.size)  // that fills the whole structure
        this.flags |= DT_needs_resolution;       // needs special attention
    }
    this.alignSize = Datatype.calcAlignSize(this.size, this.alignment);
  }

  /// Get index into field list
  /// Find the proper subfield given an offset. Return the index of that field
  /// or -1 if the offset is not inside a field.
  protected getFieldIter(off: number): number {
    let min = 0;
    let max = this.field.length - 1;

    while (min <= max) {
      const mid = Math.floor((min + max) / 2);
      const curfield = this.field[mid];
      if (curfield.offset > off)
        max = mid - 1;
      else {       // curfield.offset <= off
        if ((curfield.offset + curfield.type.getSize()) > off)
          return mid;
        min = mid + 1;
      }
    }
    return -1;
  }

  /// Get index of last field before or equal to given offset
  protected getLowerBoundField(off: number): number {
    if (this.field.length === 0) return -1;
    let min = 0;
    let max = this.field.length - 1;

    while (min < max) {
      const mid = Math.floor((min + max + 1) / 2);
      if (this.field[mid].offset > off)
        max = mid - 1;
      else {       // curfield.offset <= off
        min = mid;
      }
    }
    if (min === max && this.field[min].offset <= off)
      return min;
    return -1;
  }

  findTruncation(off: bigint, sz: number, op: PcodeOp, slot: number, newoff: { val: bigint }): TypeField | null {
    const i = this.getFieldIter(Number(off));
    if (i < 0) return null;
    const curfield = this.field[i];
    const noff = Number(off) - curfield.offset;
    if (noff + sz > curfield.type.getSize())  // Requested piece spans more than one field
      return null;
    newoff.val = BigInt(noff);
    return curfield;
  }

  getSubType(off: bigint, newoff: { val: bigint }): Datatype | null {
    // Go down one level to field that contains offset
    const i = this.getFieldIter(Number(off));
    if (i < 0) return super.getSubType(off, newoff);
    const curfield = this.field[i];
    newoff.val = off - BigInt(curfield.offset);
    return curfield.type;
  }

  nearestArrayedComponentBackward(off: bigint, newoff: { val: bigint }, elSize: { val: bigint }): Datatype | null {
    const firstIndex = this.getLowerBoundField(Number(off));
    let i = firstIndex;
    while (i >= 0) {
      const subfield = this.field[i];
      const diff = off - BigInt(subfield.offset);
      if (diff > 128n) break;
      const subtype = subfield.type;
      if (subtype.getMetatype() === type_metatype.TYPE_ARRAY) {
        newoff.val = diff;
        elSize.val = BigInt((subtype as TypeArray).getBase().getAlignSize());
        return subtype;
      }
      else {
        const suboffRef = { val: 0n };
        const remain = (i === firstIndex) ? diff : BigInt(subtype.getSize() - 1);
        const res = subtype.nearestArrayedComponentBackward(remain, suboffRef, elSize);
        if (res !== null) {
          newoff.val = diff;
          return subtype;
        }
      }
      i -= 1;
    }
    return null;
  }

  nearestArrayedComponentForward(off: bigint, newoff: { val: bigint }, elSize: { val: bigint }): Datatype | null {
    let i = this.getLowerBoundField(Number(off));
    let remain: bigint;
    if (i < 0) {       // No component starting before off
      i += 1;           // First component starting after
      remain = 0n;
    }
    else {
      const subfield = this.field[i];
      remain = off - BigInt(subfield.offset);
      if (remain !== 0n && (subfield.type.getMetatype() !== type_metatype.TYPE_STRUCT || remain >= BigInt(subfield.type.getSize()))) {
        i += 1;         // Middle of non-structure that we must go forward from, skip over it
        remain = 0n;
      }
    }
    while (i < this.field.length) {
      const subfield = this.field[i];
      const diff = BigInt(subfield.offset) - off;   // The first struct field examined may have a negative diff
      if (diff > 128n) break;
      const subtype = subfield.type;
      if (subtype.getMetatype() === type_metatype.TYPE_ARRAY) {
        newoff.val = -diff;
        elSize.val = BigInt((subtype as TypeArray).getBase().getAlignSize());
        return subtype;
      }
      else {
        const suboffRef = { val: 0n };
        const res = subtype.nearestArrayedComponentForward(remain, suboffRef, elSize);
        if (res !== null) {
          const subdiff = diff + remain - suboffRef.val;
          if (subdiff > 128n)
            break;
          newoff.val = -diff;
          return subtype;
        }
      }
      i += 1;
      remain = 0n;
    }
    return null;
  }

  getHoleSize(off: number): number {
    let i = this.getLowerBoundField(off);
    if (i >= 0) {
      const curfield = this.field[i];
      const newOff = off - curfield.offset;
      if (newOff < curfield.type.getSize())
        return curfield.type.getHoleSize(newOff);
    }
    i += 1;                         // advance to first field following off
    if (i < this.field.length) {
      return this.field[i].offset - off;    // Distance to following field
    }
    return this.getSize() - off;            // Distance to end of structure
  }

  numDepend(): number { return this.field.length; }

  getDepend(index: number): Datatype | null { return this.field[index].type; }

  compare(op: Datatype, level: number): number {
    let res = super.compare(op, level);
    if (res !== 0) return res;
    const ts = op as TypeStruct;

    if (this.field.length !== ts.field.length) return (ts.field.length - this.field.length);
    // Test only the name and first level metatype first
    for (let i = 0; i < this.field.length; i++) {
      if (this.field[i].offset !== ts.field[i].offset)
        return (this.field[i].offset < ts.field[i].offset) ? -1 : 1;
      if (this.field[i].name !== ts.field[i].name)
        return (this.field[i].name < ts.field[i].name) ? -1 : 1;
      if (this.field[i].type.getMetatype() !== ts.field[i].type.getMetatype())
        return (this.field[i].type.getMetatype() < ts.field[i].type.getMetatype()) ? -1 : 1;
    }
    level -= 1;
    if (level < 0) {
      if (this.id === op.getId()) return 0;
      return (this.id < op.getId()) ? -1 : 1;
    }
    // If we are still equal, now go down deep into each field type
    for (let i = 0; i < this.field.length; i++) {
      if (this.field[i].type !== ts.field[i].type) {  // Short circuit recursive loops
        const c = this.field[i].type.compare(ts.field[i].type, level);
        if (c !== 0) return c;
      }
    }
    return 0;
  }

  compareDependency(op: Datatype): number {
    let res = super.compareDependency(op);
    if (res !== 0) return res;
    const ts = op as TypeStruct;

    if (this.field.length !== ts.field.length) return (ts.field.length - this.field.length);
    // Test only the name and first level metatype first
    for (let i = 0; i < this.field.length; i++) {
      if (this.field[i].offset !== ts.field[i].offset)
        return (this.field[i].offset < ts.field[i].offset) ? -1 : 1;
      if (this.field[i].name !== ts.field[i].name)
        return (this.field[i].name < ts.field[i].name) ? -1 : 1;
      const fld1 = this.field[i].type;
      const fld2 = ts.field[i].type;
      if (fld1 !== fld2)
        return (fld1 < fld2) ? -1 : 1;  // Compare the pointers directly (reference identity)
    }
    return 0;
  }

  clone(): Datatype { return new TypeStruct(this); }

  encode(encoder: Encoder): void {
    if (this.typedefImm !== null) {
      this.encodeTypedef(encoder);
      return;
    }
    encoder.openElement(ELEM_TYPE);
    this.encodeBasic(this.metatype, this.alignment, encoder);
    for (const f of this.field) {
      f.encode(encoder);
    }
    encoder.closeElement(ELEM_TYPE);
  }

  /// Read children of the structure element describing each field.
  protected decodeFields(decoder: Decoder, typegrp: TypeFactory): string {
    let calcAlign = 1;
    let calcSize = 0;
    let lastOff = -1;
    let warning = '';
    while (decoder.peekElement() !== 0) {
      this.field.push(new TypeField(decoder, typegrp));
      const curField = this.field[this.field.length - 1];
      if (curField.type === null || curField.type.getMetatype() === type_metatype.TYPE_VOID)
        throw new LowlevelError("Bad field data-type for structure: " + this.getName());
      if (curField.name.length === 0)
        throw new LowlevelError("Bad field name for structure: " + this.getName());
      if (curField.offset < lastOff)
        throw new LowlevelError("Fields are out of order");
      lastOff = curField.offset;
      if (curField.offset < calcSize) {
        if (warning.length === 0) {
          warning = 'Struct "' + this.name + '": ignoring overlapping field "' + curField.name + '"';
        }
        else {
          warning = 'Struct "' + this.name + '": ignoring multiple overlapping fields';
        }
        this.field.pop();       // Throw out the overlapping field
        continue;
      }
      calcSize = curField.offset + curField.type.getSize();
      if (calcSize > this.size) {
        throw new LowlevelError("Field " + curField.name + " does not fit in structure " + this.name);
      }
      const curAlign = curField.type.getAlignment();
      if (curAlign > calcAlign)
        calcAlign = curAlign;
    }
    if (this.size === 0)       // Old way to indicate an incomplete structure
      this.flags |= DT_type_incomplete;
    if (this.field.length > 0)
      this.markComplete();     // If we have fields, mark as complete
    if (this.field.length === 1) {            // A single field
      if (this.field[0].type.getSize() === this.size)  // that fills the whole structure
        this.flags |= DT_needs_resolution;       // needs special resolution
    }
    if (this.alignment < 1)
      this.alignment = calcAlign;
    this.alignSize = Datatype.calcAlignSize(this.size, this.alignment);
    return warning;
  }

  /// Determine best type fit for given PcodeOp use
  static scoreSingleComponent(parent: Datatype, op: PcodeOp, slot: number): number {
    if (op.code() === CPUI_COPY || op.code() === CPUI_INDIRECT) {
      let vn: any;
      if (slot === 0)
        vn = op.getOut();
      else
        vn = op.getIn(0);
      if (vn.isTypeLock() && vn.getType() === parent)
        return -1;    // COPY of the structure directly, use whole structure
    }
    else if ((op.code() === CPUI_LOAD && slot === -1) || (op.code() === CPUI_STORE && slot === 2)) {
      const vn = op.getIn(1);
      if (vn.isTypeLock()) {
        const ct = vn.getTypeReadFacing(op);
        if (ct.getMetatype() === type_metatype.TYPE_PTR && (ct as TypePointer).getPtrTo() === parent)
          return -1;    // LOAD or STORE of the structure directly, use whole structure
      }
    }
    else if (op.isCall()) {
      const fd = op.getParent().getFuncdata();
      const fc = fd.getCallSpecs(op);
      if (fc !== null) {
        let param: any = null;
        if (slot >= 1 && fc.isInputLocked())
          param = fc.getParam(slot - 1);
        else if (slot < 0 && fc.isOutputLocked())
          param = fc.getOutput();
        if (param !== null && param.getType() === parent)
          return -1;    // Function signature refers to parent directly, resolve to parent
      }
    }
    return 0;    // In all other cases resolve to the component
  }

  resolveInFlow(op: PcodeOp, slot: number): Datatype {
    const fd = op.getParent().getFuncdata();
    const res = fd.getUnionField(this, op, slot);
    if (res !== null)
      return res.getDatatype();

    const fieldNum = TypeStruct.scoreSingleComponent(this, op, slot);

    const compFill = new ResolvedUnion(this, fieldNum, fd.getArch().types);
    fd.setUnionField(this, op, slot, compFill);
    return compFill.getDatatype();
  }

  findResolve(op: PcodeOp, slot: number): Datatype {
    const fd = op.getParent().getFuncdata();
    const res = fd.getUnionField(this, op, slot);
    if (res !== null)
      return res.getDatatype();
    return this.field[0].type;    // If not calculated before, assume referring to field
  }

  findCompatibleResolve(ct: Datatype): number {
    const fieldType = this.field[0].type;
    if (ct.needsResolution() && !fieldType.needsResolution()) {
      if (ct.findCompatibleResolve(fieldType) >= 0)
        return 0;
    }
    if (fieldType === ct)
      return 0;
    return -1;
  }

  /// Assign field offsets
  static assignFieldOffsets(list: TypeField[], newSize: { val: number }, newAlign: { val: number }): void {
    let offset = 0;
    newAlign.val = 1;
    for (const f of list) {
      if (f.type.getMetatype() === type_metatype.TYPE_VOID)
        throw new LowlevelError("Illegal field data-type: void");
      if (f.offset !== -1) continue;
      const cursize = f.type.getAlignSize();
      let align = f.type.getAlignment();
      if (align > newAlign.val)
        newAlign.val = align;
      align -= 1;
      if (align > 0 && (offset & align) !== 0)
        offset = (offset - (offset & align) + (align + 1));
      f.offset = offset;
      f.ident = offset;
      offset += cursize;
    }
    newSize.val = Datatype.calcAlignSize(offset, newAlign.val);
  }
}

/// A collection of overlapping Datatype objects: A union of component fields
///
/// The individual components have field names, as with a structure, but for a union, the components all
/// share the same memory.
export class TypeUnion extends Datatype {
  protected field: TypeField[];       // The list of fields

  /// Construct from another TypeUnion
  constructor(op: TypeUnion);
  /// Construct incomplete TypeUnion
  constructor();
  constructor(arg1?: any) {
    if (arg1 instanceof TypeUnion) {
      super(arg1 as Datatype);
      this.field = [];
      this.setFields(arg1.field, arg1.size, arg1.alignment);
      this.alignSize = arg1.alignSize;
    }
    else {
      super(0, -1, type_metatype.TYPE_UNION);
      this.flags |= (DT_type_incomplete | DT_needs_resolution);
      this.field = [];
    }
  }

  /// Get the i-th field of the union
  getField(i: number): TypeField { return this.field[i]; }

  /// Establish fields for this
  protected setFields(fd: TypeField[], newSize: number, newAlign: number): void {
    this.field = fd.slice();  // Copy the array
    this.size = newSize;
    this.alignment = newAlign;
    this.alignSize = Datatype.calcAlignSize(this.size, this.alignment);
  }

  /// Restore fields from a stream
  protected decodeFields(decoder: Decoder, typegrp: TypeFactory): void {
    let calcAlign = 1;
    while (decoder.peekElement() !== 0) {
      this.field.push(new TypeField(decoder, typegrp));
      if (this.field[this.field.length - 1].offset + this.field[this.field.length - 1].type.getSize() > this.size) {
        throw new LowlevelError("Field " + this.field[this.field.length - 1].name + " does not fit in union " + this.name);
      }
      const curAlign = this.field[this.field.length - 1].type.getAlignment();
      if (curAlign > calcAlign)
        calcAlign = curAlign;
    }
    if (this.size === 0)       // Old way to indicate union is incomplete
      this.flags |= DT_type_incomplete;
    if (this.field.length > 0)
      this.markComplete();     // If we have fields, the union is complete
    if (this.alignment < 1)
      this.alignment = calcAlign;
    this.alignSize = Datatype.calcAlignSize(this.size, this.alignment);
  }

  findTruncation(offset: bigint, sz: number, op: PcodeOp, slot: number, newoff: { val: bigint }): TypeField | null {
    // No new scoring is done, but if a cached result is available, return it.
    const fd = op.getParent().getFuncdata();
    const res = fd.getUnionField(this, op, slot);
    if (res !== null && res.getFieldNum() >= 0) {
      const field = this.getField(res.getFieldNum());
      newoff.val = offset - BigInt(field.offset);
      if (Number(newoff.val) + sz > field.type.getSize())
        return null;    // Truncation spans more than one field
      return field;
    }
    return null;
  }

  numDepend(): number { return this.field.length; }

  getDepend(index: number): Datatype | null { return this.field[index].type; }

  compare(op: Datatype, level: number): number {
    let res = super.compare(op, level);
    if (res !== 0) return res;
    const tu = op as TypeUnion;

    if (this.field.length !== tu.field.length) return (tu.field.length - this.field.length);
    // Test only the name and first level metatype first
    for (let i = 0; i < this.field.length; i++) {
      if (this.field[i].name !== tu.field[i].name)
        return (this.field[i].name < tu.field[i].name) ? -1 : 1;
      if (this.field[i].type.getMetatype() !== tu.field[i].type.getMetatype())
        return (this.field[i].type.getMetatype() < tu.field[i].type.getMetatype()) ? -1 : 1;
    }
    level -= 1;
    if (level < 0) {
      if (this.id === op.getId()) return 0;
      return (this.id < op.getId()) ? -1 : 1;
    }
    // If we are still equal, now go down deep into each field type
    for (let i = 0; i < this.field.length; i++) {
      if (this.field[i].type !== tu.field[i].type) {  // Short circuit recursive loops
        const c = this.field[i].type.compare(tu.field[i].type, level);
        if (c !== 0) return c;
      }
    }
    return 0;
  }

  compareDependency(op: Datatype): number {
    let res = super.compareDependency(op);
    if (res !== 0) return res;
    const tu = op as TypeUnion;

    if (this.field.length !== tu.field.length) return (tu.field.length - this.field.length);
    for (let i = 0; i < this.field.length; i++) {
      if (this.field[i].name !== tu.field[i].name)
        return (this.field[i].name < tu.field[i].name) ? -1 : 1;
      const fld1 = this.field[i].type;
      const fld2 = tu.field[i].type;
      if (fld1 !== fld2)
        return (fld1 < fld2) ? -1 : 1;  // Compare the pointers directly (reference identity)
    }
    return 0;
  }

  clone(): Datatype { return new TypeUnion(this); }

  encode(encoder: Encoder): void {
    if (this.typedefImm !== null) {
      this.encodeTypedef(encoder);
      return;
    }
    encoder.openElement(ELEM_TYPE);
    this.encodeBasic(this.metatype, this.alignment, encoder);
    for (const f of this.field) {
      f.encode(encoder);
    }
    encoder.closeElement(ELEM_TYPE);
  }

  resolveInFlow(op: PcodeOp, slot: number): Datatype {
    const fd = op.getParent().getFuncdata();
    const res = fd.getUnionField(this, op, slot);
    if (res !== null)
      return res.getDatatype();
    const scoreFields = new ScoreUnionFields(fd.getArch().types, this, op, slot);
    const bestResult = scoreFields.getResult();
    if (bestResult === null || bestResult === undefined) {
      const fallback = new ResolvedUnion(this);
      fd.setUnionField(this, op, slot, fallback);
      return this;
    }
    fd.setUnionField(this, op, slot, bestResult);
    return bestResult.getDatatype();
  }

  findResolve(op: PcodeOp, slot: number): Datatype {
    const fd = op.getParent().getFuncdata();
    const res = fd.getUnionField(this, op, slot);
    if (res !== null)
      return res.getDatatype();
    return this;
  }

  resolveTruncation(offset: bigint, op: PcodeOp, slot: number, newoff: { val: bigint }): TypeField | null {
    const fd = op.getParent().getFuncdata();
    const res = fd.getUnionField(this, op, slot);
    if (res !== null) {
      if (res.getFieldNum() >= 0) {
        const field = this.getField(res.getFieldNum());
        newoff.val = offset - BigInt(field.offset);
        return field;
      }
    }
    else if (op.code() === CPUI_SUBPIECE && slot === 1) {  // The slot is artificial in this case
      const scoreFields = new ScoreUnionFields(fd.getArch().types, this, Number(offset), op);
      fd.setUnionField(this, op, slot, scoreFields.getResult());
      if (scoreFields.getResult().getFieldNum() >= 0) {
        newoff.val = 0n;
        return this.getField(scoreFields.getResult().getFieldNum());
      }
    }
    else {
      const scoreFields = new ScoreUnionFields(fd.getArch().types, this, Number(offset), op, slot);
      fd.setUnionField(this, op, slot, scoreFields.getResult());
      if (scoreFields.getResult().getFieldNum() >= 0) {
        const field = this.getField(scoreFields.getResult().getFieldNum());
        newoff.val = offset - BigInt(field.offset);
        return field;
      }
    }
    return null;
  }

  findCompatibleResolve(ct: Datatype): number {
    if (!ct.needsResolution()) {
      for (let i = 0; i < this.field.length; ++i) {
        if (this.field[i].type === ct && this.field[i].offset === 0)
          return i;
      }
    }
    else {
      for (let i = 0; i < this.field.length; ++i) {
        if (this.field[i].offset !== 0) continue;
        const fieldType = this.field[i].type;
        if (fieldType.getSize() !== ct.getSize()) continue;
        if (fieldType.needsResolution()) continue;
        if (ct.findCompatibleResolve(fieldType) >= 0)
          return i;
      }
    }
    return -1;
  }

  /// Assign field offsets (all fields at offset 0)
  static assignFieldOffsets(list: TypeField[], newSize: { val: number }, newAlign: { val: number }, tu: TypeUnion): void {
    newSize.val = 0;
    newAlign.val = 1;
    for (const f of list) {
      const ct = f.type;
      // Do some sanity checks on the field
      if (ct === null || ct.getMetatype() === type_metatype.TYPE_VOID)
        throw new LowlevelError("Bad field data-type for union: " + tu.getName());
      else if (f.name.length === 0)
        throw new LowlevelError("Bad field name for union: " + tu.getName());
      f.offset = 0;
      const end = ct.getSize();
      if (end > newSize.val)
        newSize.val = end;
      const curAlign = ct.getAlignment();
      if (curAlign > newAlign.val)
        newAlign.val = curAlign;
    }
  }
}

/// A data-type that holds part of a TypeEnum and possible additional padding
class TypePartialEnum extends TypeEnum {
  private stripped: Datatype;       // The undefined data-type to use if a formal data-type is required.
  private parent: TypeEnum;         // The enumeration data-type this is based on
  private offset: number;           // Byte offset within the parent enum where this starts

  /// Construct from another TypePartialEnum
  constructor(op: TypePartialEnum);
  /// Constructor
  constructor(par: TypeEnum, off: number, sz: number, strip: Datatype);
  constructor(arg1: any, arg2?: any, arg3?: any, arg4?: any) {
    if (arg1 instanceof TypePartialEnum) {
      super(arg1 as TypeEnum);
      this.stripped = arg1.stripped;
      this.parent = arg1.parent;
      this.offset = arg1.offset;
    }
    else {
      super(arg3, type_metatype.TYPE_PARTIALENUM);
      this.flags |= DT_has_stripped;
      this.stripped = arg4;
      this.parent = arg1;
      this.offset = arg2;
    }
  }

  /// Get the byte offset into the containing data-type
  getOffset(): number { return this.offset; }

  /// Get the enumeration containing this piece
  getParent(): Datatype { return this.parent; }

  printRaw(s: Writer): void {
    this.parent.printRaw(s);
    s.write('[off=' + this.offset.toString() + ',sz=' + this.size.toString() + ']');
  }

  hasNamedValue(val: bigint): boolean {
    val = val << BigInt(8 * this.offset);
    return this.parent.hasNamedValue(val);
  }

  getMatches(val: bigint, rep: InstanceType<typeof TypeEnum.Representation>): void {
    val = val << BigInt(8 * this.offset);
    rep.shiftAmount = this.offset * 8;
    this.parent.getMatches(val, rep);
  }

  compare(op: Datatype, level: number): number {
    let res = Datatype.prototype.compare.call(this, op, level);
    if (res !== 0) return res;
    // Both must be partial
    const tp = op as TypePartialEnum;
    if (this.offset !== tp.offset) return (this.offset < tp.offset) ? -1 : 1;
    level -= 1;
    if (level < 0) {
      if (this.id === op.getId()) return 0;
      return (this.id < op.getId()) ? -1 : 1;
    }
    return this.parent.compare(tp.parent, level);  // Compare the underlying enum
  }

  compareDependency(op: Datatype): number {
    if (this.submeta !== op.getSubMeta()) return (this.submeta < op.getSubMeta()) ? -1 : 1;
    const tp = op as TypePartialEnum;
    if (this.parent !== tp.parent) return (this.parent < tp.parent) ? -1 : 1;  // Compare absolute pointers
    if (this.offset !== tp.offset) return (this.offset < tp.offset) ? -1 : 1;
    return (op.getSize() - this.size);
  }

  clone(): Datatype { return new TypePartialEnum(this); }

  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_TYPE);
    this.encodeBasic(type_metatype.TYPE_PARTIALENUM, -1, encoder);
    encoder.writeSignedInteger(ATTRIB_OFFSET, this.offset);
    this.parent.encodeRef(encoder);
    encoder.closeElement(ELEM_TYPE);
  }

  getStripped(): Datatype | null { return this.stripped; }
}

/// A data-type that holds part of a TypeStruct or TypeArray
class TypePartialStruct extends Datatype {
  private stripped: Datatype;       // The undefined data-type to use if a formal data-type is required.
  private container: Datatype;      // Parent structure or array of which this is a part
  private offset: number;           // Byte offset within the parent where this starts

  /// Construct from another TypePartialStruct
  constructor(op: TypePartialStruct);
  /// Constructor
  constructor(contain: Datatype, off: number, sz: number, strip: Datatype);
  constructor(arg1: any, arg2?: any, arg3?: any, arg4?: any) {
    if (arg1 instanceof TypePartialStruct) {
      super(arg1 as Datatype);
      this.stripped = arg1.stripped;
      this.container = arg1.container;
      this.offset = arg1.offset;
    }
    else {
      super(arg3, 1, type_metatype.TYPE_PARTIALSTRUCT);
      this.flags |= DT_has_stripped;
      this.stripped = arg4;
      this.container = arg1;
      this.offset = arg2;
    }
  }

  /// Get the byte offset into the containing data-type
  getOffset(): number { return this.offset; }

  /// Get the data-type containing this piece
  getParent(): Datatype { return this.container; }

  /// Get (initial) component of array represented by this
  getComponentForPtr(): Datatype {
    if (this.container.getMetatype() === type_metatype.TYPE_ARRAY) {
      const eltype = (this.container as TypeArray).getBase();
      if (eltype.getMetatype() !== type_metatype.TYPE_UNKNOWN && (this.offset % eltype.getAlignSize()) === 0)
        return eltype;
    }
    return this.stripped;
  }

  printRaw(s: Writer): void {
    this.container.printRaw(s);
    s.write('[off=' + this.offset.toString() + ',sz=' + this.size.toString() + ']');
  }

  getSubType(off: bigint, newoff: { val: bigint }): Datatype | null {
    let sizeLeft = BigInt(this.size) - off;
    off = off + BigInt(this.offset);
    let ct: Datatype | null = this.container;
    do {
      const newoffRef = { val: 0n };
      ct = ct!.getSubType(off, newoffRef);
      if (ct === null)
        break;
      off = newoffRef.val;
      newoff.val = newoffRef.val;
      // Component can extend beyond range of this partial, in which case we go down another level
    } while (BigInt(ct.getSize()) - off > sizeLeft);
    return ct;
  }

  getHoleSize(off: number): number {
    const sizeLeft = this.size - off;
    off += this.offset;
    let res = this.container.getHoleSize(off);
    if (res > sizeLeft)
      res = sizeLeft;
    return res;
  }

  compare(op: Datatype, level: number): number {
    let res = super.compare(op, level);
    if (res !== 0) return res;
    // Both must be partial
    const tp = op as TypePartialStruct;
    if (this.offset !== tp.offset) return (this.offset < tp.offset) ? -1 : 1;
    level -= 1;
    if (level < 0) {
      if (this.id === op.getId()) return 0;
      return (this.id < op.getId()) ? -1 : 1;
    }
    return this.container.compare(tp.container, level);  // Compare the underlying container
  }

  compareDependency(op: Datatype): number {
    if (this.submeta !== op.getSubMeta()) return (this.submeta < op.getSubMeta()) ? -1 : 1;
    const tp = op as TypePartialStruct;
    if (this.container !== tp.container) return (this.container < tp.container) ? -1 : 1;  // Compare absolute pointers
    if (this.offset !== tp.offset) return (this.offset < tp.offset) ? -1 : 1;
    return (op.getSize() - this.size);
  }

  clone(): Datatype { return new TypePartialStruct(this); }

  getStripped(): Datatype | null { return this.stripped; }
}

/// An internal data-type for holding information about a variable's relative position within a union data-type
///
/// This is a data-type that can be assigned to a Varnode offset into a Symbol, where either the Symbol itself or
/// a sub-field is a TypeUnion. In these cases, we know the Varnode is properly contained within a TypeUnion,
/// but the lack of context prevents us from deciding which field of the TypeUnion applies (and possibly
/// the sub-field of the field).
class TypePartialUnion extends Datatype {
  protected stripped: Datatype;       // The undefined data-type to use if a formal data-type is required.
  protected container: TypeUnion;     // Union data-type containing this partial data-type
  protected offset: number;           // Offset (in bytes) into the container union

  /// Construct from another TypePartialUnion
  constructor(op: TypePartialUnion);
  /// Constructor
  constructor(contain: TypeUnion, off: number, sz: number, strip: Datatype);
  constructor(arg1: any, arg2?: any, arg3?: any, arg4?: any) {
    if (arg1 instanceof TypePartialUnion) {
      super(arg1 as Datatype);
      this.stripped = arg1.stripped;
      this.container = arg1.container;
      this.offset = arg1.offset;
    }
    else {
      super(arg3, 1, type_metatype.TYPE_PARTIALUNION);
      this.flags |= (DT_needs_resolution | DT_has_stripped);
      this.stripped = arg4;
      this.container = arg1;
      this.offset = arg2;
    }
  }

  /// Get the byte offset into the containing data-type
  getOffset(): number { return this.offset; }

  /// Get the union which this is part of
  getParentUnion(): TypeUnion { return this.container; }

  printRaw(s: Writer): void {
    this.container.printRaw(s);
    s.write('[off=' + this.offset.toString() + ',sz=' + this.size.toString() + ']');
  }

  findTruncation(off: bigint, sz: number, op: PcodeOp, slot: number, newoff: { val: bigint }): TypeField | null {
    return this.container.findTruncation(off + BigInt(this.offset), sz, op, slot, newoff);
  }

  numDepend(): number {
    return this.container.numDepend();
  }

  getDepend(index: number): Datatype | null {
    // Treat dependents as coming from the underlying union
    const res = this.container.getDepend(index);
    if (res !== null && res.getSize() !== this.size)  // But if the size doesn't match
      return this.stripped;          // Return the stripped data-type
    return res;
  }

  compare(op: Datatype, level: number): number {
    let res = super.compare(op, level);
    if (res !== 0) return res;
    // Both must be partial unions
    const tp = op as TypePartialUnion;
    if (this.offset !== tp.offset) return (this.offset < tp.offset) ? -1 : 1;
    level -= 1;
    if (level < 0) {
      if (this.id === op.getId()) return 0;
      return (this.id < op.getId()) ? -1 : 1;
    }
    return this.container.compare(tp.container, level);  // Compare the underlying union
  }

  compareDependency(op: Datatype): number {
    if (this.submeta !== op.getSubMeta()) return (this.submeta < op.getSubMeta()) ? -1 : 1;
    const tp = op as TypePartialUnion;
    if (this.container !== tp.container) return (this.container < tp.container) ? -1 : 1;  // Compare absolute pointers
    if (this.offset !== tp.offset) return (this.offset < tp.offset) ? -1 : 1;
    return (op.getSize() - this.size);
  }

  clone(): Datatype { return new TypePartialUnion(this); }

  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_TYPE);
    this.encodeBasic(this.metatype, -1, encoder);
    encoder.writeSignedInteger(ATTRIB_OFFSET, this.offset);
    this.container.encodeRef(encoder);
    encoder.closeElement(ELEM_TYPE);
  }

  getStripped(): Datatype | null { return this.stripped; }

  resolveInFlow(op: PcodeOp, slot: number): Datatype {
    let curType: Datatype | null = this.container;
    let curOff: bigint = BigInt(this.offset);
    while (curType !== null && curType.getSize() > this.size) {
      if (curType.getMetatype() === type_metatype.TYPE_UNION) {
        const newoffRef = { val: 0n };
        const field = curType.resolveTruncation(curOff, op, slot, newoffRef);
        curOff = newoffRef.val;
        curType = (field === null) ? null : field.type;
      }
      else {
        const newoffRef = { val: 0n };
        curType = curType.getSubType(curOff, newoffRef);
        curOff = newoffRef.val;
      }
    }
    if (curType !== null && curType.getSize() === this.size)
      return curType;
    return this.stripped;
  }

  findResolve(op: PcodeOp, slot: number): Datatype {
    let curType: Datatype | null = this.container;
    let curOff: bigint = BigInt(this.offset);
    while (curType !== null && curType.getSize() > this.size) {
      if (curType.getMetatype() === type_metatype.TYPE_UNION) {
        const newType = curType.findResolve(op, slot);
        curType = (newType === curType) ? null : newType;
      }
      else {
        const newoffRef = { val: 0n };
        curType = curType.getSubType(curOff, newoffRef);
        curOff = newoffRef.val;
      }
    }
    if (curType !== null && curType.getSize() === this.size)
      return curType;
    return this.stripped;
  }

  findCompatibleResolve(ct: Datatype): number {
    return this.container.findCompatibleResolve(ct);
  }

  resolveTruncation(off: bigint, op: PcodeOp, slot: number, newoff: { val: bigint }): TypeField | null {
    return this.container.resolveTruncation(off + BigInt(this.offset), op, slot, newoff);
  }
}

/// Relative pointer: A pointer with a fixed offset into a specific structure or other data-type
///
/// The other data-type, the container, is typically a TypeStruct or TypeArray. Even though this pointer
/// does not point directly to the start of the container, it is possible to access the container through this,
/// as the distance (the offset) to the start of the container is explicitly known.
export class TypePointerRel extends TypePointer {
  protected stripped: TypePointer | null;   // Same data-type with container info stripped
  protected parent: Datatype;               // Parent structure or array which this is pointing into
  protected offset: number;                 // Byte offset within the parent where this points to

  /// Internal constructor for decode
  constructor();
  /// Construct from another TypePointerRel
  constructor(op: TypePointerRel);
  /// Construct given a size, pointed-to type, parent, and offset
  constructor(sz: number, pt: Datatype, ws: number, par: Datatype, off: number);
  constructor(arg1?: any, arg2?: any, arg3?: any, arg4?: any, arg5?: any) {
    if (arg1 === undefined) {
      // Internal constructor for decode
      super();
      this.offset = 0;
      this.parent = null!;
      this.stripped = null;
      this.submeta = sub_metatype.SUB_PTRREL;
    }
    else if (arg1 instanceof TypePointerRel) {
      // Copy constructor
      super(arg1 as TypePointer);
      this.offset = arg1.offset;
      this.parent = arg1.parent;
      this.stripped = arg1.stripped;
    }
    else {
      // Construct from size, pointed-to type, wordsize, parent, offset
      super(arg1, arg2, arg3);
      this.parent = arg4;
      this.offset = arg5;
      this.stripped = null;
      this.flags |= DT_is_ptrrel;
      this.submeta = sub_metatype.SUB_PTRREL;
    }
  }

  /// Get the parent data-type to which this pointer is offset
  getParent(): Datatype { return this.parent; }

  /// Do we display given address offset as coming from the parent data-type
  evaluateThruParent(addrOff: bigint): boolean {
    let byteOff = AddrSpace.addressToByte(addrOff, this.wordsize);
    if (this.ptrto.getMetatype() === type_metatype.TYPE_STRUCT && byteOff < BigInt(this.ptrto.getSize()))
      return false;
    byteOff = (byteOff + BigInt(this.offset)) & calc_mask(this.size);
    return (byteOff < BigInt(this.parent.getSize()));
  }

  /// Get offset of this pointer relative to start of the containing data-type (in address units)
  getAddressOffset(): number { return Number(AddrSpace.byteToAddressInt(BigInt(this.offset), this.wordsize)); }

  /// Get offset of this pointer relative to start of the containing data-type (in byte units)
  getByteOffset(): number { return this.offset; }

  printRaw(s: Writer): void {
    this.ptrto.printRaw(s);
    s.write(' *+');
    s.write(this.offset.toString());
    s.write('[');
    this.parent.printRaw(s);
    s.write(']');
  }

  compare(op: Datatype, level: number): number {
    let res = super.compare(op, level);  // Compare as plain pointers first
    if (res !== 0) return res;
    // Both must be relative pointers
    const tp = op as TypePointerRel;
    // It's possible a formal relative pointer gets compared to its equivalent ephemeral version.
    // In which case, we prefer the formal version.
    if (this.stripped === null) {
      if (tp.stripped !== null)
        return -1;
    }
    else {
      if (tp.stripped === null)
        return 1;
    }
    return 0;
  }

  compareDependency(op: Datatype): number {
    if (this.submeta !== op.getSubMeta()) return (this.submeta < op.getSubMeta()) ? -1 : 1;
    const tp = op as TypePointerRel;
    if (this.ptrto !== tp.ptrto) return (this.ptrto < tp.ptrto) ? -1 : 1;  // Compare absolute pointers
    if (this.offset !== tp.offset) return (this.offset < tp.offset) ? -1 : 1;
    if (this.parent !== tp.parent) return (this.parent < tp.parent) ? -1 : 1;
    if (this.wordsize !== tp.wordsize) return (this.wordsize < tp.wordsize) ? -1 : 1;
    return (op.getSize() - this.size);
  }

  clone(): Datatype { return new TypePointerRel(this); }

  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_TYPE);
    this.encodeBasic(type_metatype.TYPE_PTRREL, -1, encoder);  // Override the metatype for encoding
    if (this.wordsize !== 1)
      encoder.writeUnsignedInteger(ATTRIB_WORDSIZE, BigInt(this.wordsize));
    this.ptrto.encode(encoder);
    this.parent.encodeRef(encoder);
    encoder.openElement(ELEM_OFF);
    encoder.writeSignedInteger(ATTRIB_CONTENT, this.offset);
    encoder.closeElement(ELEM_OFF);
    encoder.closeElement(ELEM_TYPE);
  }

  /// Restore this relative pointer data-type from a stream
  protected decode(decoder: Decoder, typegrp: TypeFactory): void {
    this.flags |= DT_is_ptrrel;
    this.decodeBasic(decoder);
    this.metatype = type_metatype.TYPE_PTR;    // Don't use TYPE_PTRREL internally
    decoder.rewindAttributes();
    for (;;) {
      const attrib = decoder.getNextAttributeId();
      if (attrib === 0) break;
      if (attrib === ATTRIB_WORDSIZE.id) {
        this.wordsize = Number(decoder.readUnsignedInteger());
      }
      else if (attrib === ATTRIB_SPACE.id) {
        this.spaceid = decoder.readSpace() as unknown as AddrSpace;
      }
    }
    this.ptrto = typegrp.decodeType(decoder);
    this.parent = typegrp.decodeType(decoder);
    const subId = decoder.openElementId(ELEM_OFF);
    this.offset = Number(decoder.readSignedIntegerById(ATTRIB_CONTENT));
    decoder.closeElement(subId);
    if (this.offset === 0)
      throw new LowlevelError('For metatype="ptrstruct", <off> tag must not be zero');
    this.submeta = sub_metatype.SUB_PTRREL;
    if (this.name.length === 0)       // If the data-type is not named
      this.markEphemeral(typegrp);    // it is considered ephemeral
  }

  /// Mark this pointer as ephemeral
  /** @internal */ markEphemeral(typegrp: TypeFactory): void {
    this.stripped = typegrp.getTypePointer(this.size, this.ptrto, this.wordsize);
    this.flags |= DT_has_stripped;
    // An ephemeral relative pointer that points to something unknown, propagates slightly
    // differently than a formal relative pointer
    if (this.ptrto.getMetatype() === type_metatype.TYPE_UNKNOWN)
      this.submeta = sub_metatype.SUB_PTRREL_UNK;
  }

  downChain(off: { val: bigint }, par: { val: TypePointer | null }, parOff: { val: bigint }, allowArrayWrap: boolean, typegrp: TypeFactory): TypePointer | null {
    const ptrtoMeta = this.ptrto.getMetatype();
    if (off.val >= 0n && off.val < BigInt(this.ptrto.getSize()) && (ptrtoMeta === type_metatype.TYPE_STRUCT || ptrtoMeta === type_metatype.TYPE_ARRAY)) {
      return super.downChain(off, par, parOff, allowArrayWrap, typegrp);
    }
    let relOff = (off.val + BigInt(this.offset)) & calc_mask(this.size);  // Convert off to be relative to the parent container
    if (relOff < 0n || relOff >= BigInt(this.parent.getSize()))
      return null;                    // Don't let pointer shift beyond original container

    const origPointer = typegrp.getTypePointer(this.size, this.parent, this.wordsize);
    off.val = relOff;
    if (relOff === 0n && this.offset !== 0)  // Recovering the start of the parent is still downchaining, even though the parent may be the container
      return origPointer;  // So we return the pointer to the parent and don't drill down to field at offset 0
    return origPointer.downChain(off, par, parOff, allowArrayWrap, typegrp);
  }

  isPtrsubMatching(off: bigint, extra: bigint, multiplier: bigint): boolean {
    if (this.stripped !== null)
      return super.isPtrsubMatching(off, extra, multiplier);
    // In C++, iOff is int4 (signed 32-bit) and addressToByteInt returns intb (signed).
    // BigInt values from the decompiler use unsigned representation, so we must
    // sign-extend before converting to Number to match C++ signed arithmetic.
    let offSigned = AddrSpace.addressToByteInt(off, this.wordsize);
    if (offSigned >= (1n << 63n)) offSigned -= (1n << 64n);
    let iOff = Number(offSigned);
    let extraSigned = AddrSpace.addressToByteInt(extra, this.wordsize);
    if (extraSigned >= (1n << 63n)) extraSigned -= (1n << 64n);
    const extraByte = Number(extraSigned);
    iOff += this.offset + extraByte;
    return (iOff >= 0 && iOff <= this.parent.getSize());
  }

  getStripped(): Datatype | null { return this.stripped; }

  /// Given a containing data-type and offset, find the "pointed to" data-type suitable for a TypePointerRel
  ///
  /// The biggest contained data-type that starts at the exact offset is returned. If the offset is negative
  /// or the is no data-type starting exactly there, an xunknown1 data-type is returned.
  static getPtrToFromParent(base: Datatype, off: number, typegrp: TypeFactory): Datatype {
    if (off > 0) {
      let curoff: bigint = BigInt(off);
      let curBase: Datatype | null = base;
      do {
        const newoffRef = { val: 0n };
        curBase = curBase!.getSubType(curoff, newoffRef);
        curoff = newoffRef.val;
      } while (curoff !== 0n && curBase !== null);
      if (curBase === null)
        curBase = typegrp.getBase(1, type_metatype.TYPE_UNKNOWN);
      return curBase;
    }
    else
      return typegrp.getBase(1, type_metatype.TYPE_UNKNOWN);
  }
}



// =========================================================================
// TypeCode
// =========================================================================

/**
 * Datatype object representing executable code.
 *
 * Sometimes, this holds the "function" being pointed to by a function pointer.
 */
class TypeCode extends Datatype {
  proto: FuncProto | null;
  factory: TypeFactory | null;

  /**
   * Construct an incomplete TypeCode.
   */
  constructor();
  /**
   * Construct from another TypeCode (copy constructor).
   */
  constructor(op: TypeCode);
  constructor(op?: TypeCode) {
    if (op !== undefined) {
      super(op);
      this.proto = null;
      this.factory = op.factory;
      if (op.proto !== null) {
        // In TS we store a reference to a copied proto
        this.proto = new _FuncProtoCtor();
        this.proto!.copy(op.proto);
      }
    } else {
      super(1, 1, type_metatype.TYPE_CODE);
      this.proto = null;
      this.factory = null;
      this.flags |= DT_type_incomplete;
    }
  }

  /**
   * Get the function prototype.
   */
  getPrototype(): FuncProto | null {
    return this.proto;
  }

  /**
   * Compare surface characteristics of two TypeCodes, not including the prototype.
   *   -1 or 1 if this and op are different in surface characteristics
   *    0 if they are exactly equal and have no parameters
   *    2 if they are equal on the surface, but additional comparisons must be made on parameters
   */
  compareBasic(op: TypeCode): number {
    if (this.proto === null) {
      if (op.proto === null) return 0;
      return 1;
    }
    if (op.proto === null)
      return -1;

    if (!this.proto.hasModel()) {
      if (op.proto.hasModel()) return 1;
    } else {
      if (!op.proto.hasModel()) return -1;
      const model1: string = this.proto.getModelName();
      const model2: string = op.proto.getModelName();
      if (model1 !== model2)
        return (model1 < model2) ? -1 : 1;
    }
    const nump: number = this.proto.numParams();
    const opnump: number = op.proto.numParams();
    if (nump !== opnump)
      return (opnump < nump) ? -1 : 1;
    const myflags: number = this.proto.getComparableFlags();
    const opflags: number = op.proto.getComparableFlags();
    if (myflags !== opflags)
      return (myflags < opflags) ? -1 : 1;

    return 2; // Carry on with comparison of parameters
  }

  override printRaw(s: Writer): void {
    if (this.name.length > 0)
      s.write(this.name);
    else
      s.write("funcptr");
    s.write("()");
  }

  override getSubType(off: bigint, newoff: { val: bigint }): Datatype | null {
    if (this.factory === null) return null;
    newoff.val = 0n;
    return this.factory.getBase(1, type_metatype.TYPE_CODE);
  }

  override compare(op: Datatype, level: number): number {
    let res = super.compare(op, level);
    if (res !== 0) return res;
    const tc = op as TypeCode;
    res = this.compareBasic(tc);
    if (res !== 2) return res;

    level -= 1;
    if (level < 0) {
      if (this.id === op.getId()) return 0;
      return (this.id < op.getId()) ? -1 : 1;
    }
    const nump = this.proto!.numParams();
    for (let i = 0; i < nump; ++i) {
      const param: Datatype = this.proto!.getParam(i).getType();
      const opparam: Datatype = tc.proto!.getParam(i).getType();
      const c = param.compare(opparam, level);
      if (c !== 0)
        return c;
    }
    const otype: Datatype | null = this.proto!.getOutputType();
    const opotype: Datatype | null = tc.proto!.getOutputType();
    if (otype === null) {
      if (opotype === null) return 0;
      return 1;
    }
    if (opotype === null) return -1;
    return otype.compare(opotype, level);
  }

  override compareDependency(op: Datatype): number {
    let res = super.compareDependency(op);
    if (res !== 0) return res;
    const tc = op as TypeCode;
    res = this.compareBasic(tc);
    if (res !== 2) return res;

    const nump = this.proto!.numParams();
    for (let i = 0; i < nump; ++i) {
      const param: Datatype = this.proto!.getParam(i).getType();
      const opparam: Datatype = tc.proto!.getParam(i).getType();
      if (param !== opparam)
        return (param < opparam) ? -1 : 1; // Compare references directly
    }
    const otype: Datatype | null = this.proto!.getOutputType();
    const opotype: Datatype | null = tc.proto!.getOutputType();
    if (otype === null) {
      if (opotype === null) return 0;
      return 1;
    }
    if (opotype === null) return -1;
    if (otype !== opotype)
      return (otype < opotype) ? -1 : 1;
    return 0;
  }

  override clone(): Datatype {
    return new TypeCode(this);
  }

  override encode(encoder: Encoder): void {
    if (this.typedefImm !== null) {
      this.encodeTypedef(encoder);
      return;
    }
    encoder.openElement(ELEM_TYPE);
    this.encodeBasic(this.metatype, -1, encoder);
    if (this.proto !== null)
      this.proto.encode(encoder);
    encoder.closeElement(ELEM_TYPE);
  }

  /**
   * Restore stub of data-type without the full prototype.
   */
  decodeStub(decoder: Decoder): void {
    if (decoder.peekElement() !== 0) {
      // Traditionally a <prototype> tag implies variable length, without a "varlength" attribute
      this.flags |= DT_variable_length;
    }
    this.decodeBasic(decoder);
  }

  /**
   * Restore any prototype description. A single child element indicates a full function prototype.
   */
  decodePrototype(decoder: Decoder, isConstructor: boolean, isDestructor: boolean, typegrp: TypeFactory): void {
    if (decoder.peekElement() !== 0) {
      const glb: Architecture = typegrp.getArch();
      this.factory = typegrp;
      this.proto = new _FuncProtoCtor();
      this.proto!.setInternal(glb.defaultfp, typegrp.getTypeVoid());
      this.proto!.decode(decoder, glb);
      this.proto!.setConstructor(isConstructor);
      this.proto!.setDestructor(isDestructor);
    }
    this.markComplete();
  }

  /**
   * Establish a function pointer from prototype pieces.
   */
  setPrototypePieces(tfact: TypeFactory, sig: PrototypePieces, voidtype: Datatype): void {
    this.factory = tfact;
    this.flags |= DT_variable_length;
    if (this.proto !== null)
      this.proto = null; // GC handles cleanup
    this.proto = new _FuncProtoCtor();
    this.proto!.setInternal(sig.model, voidtype);
    this.proto!.updateAllTypes(sig);
    this.proto!.setInputLock(true);
    this.proto!.setOutputLock(true);
  }

  /**
   * Set a particular function prototype on this. The prototype is copied in.
   */
  setPrototypeCopy(typegrp: TypeFactory, fp: FuncProto | null): void {
    if (this.proto !== null) {
      this.proto = null;
      this.factory = null;
    }
    if (fp !== null) {
      this.factory = typegrp;
      this.proto = new _FuncProtoCtor();
      this.proto!.copy(fp);
    }
  }
}

// =========================================================================
// TypeSpacebase
// =========================================================================

/**
 * Special Datatype object used to describe pointers that index into the symbol table.
 *
 * A TypeSpacebase treats a specific AddrSpace as "structure" that will get indexed into.
 * This facilitates type propagation from local symbols into the stack space and
 * from global symbols into the RAM space.
 */
class TypeSpacebase extends Datatype {
  spaceid: AddrSpace | null;
  localframe: Address;
  glb: Architecture;

  /**
   * Construct from another TypeSpacebase (copy constructor).
   */
  constructor(op: TypeSpacebase);
  /**
   * Constructor for use with decode.
   */
  constructor(g: Architecture);
  /**
   * Construct given an address space, scope, and architecture.
   */
  constructor(id: AddrSpace, frame: Address, g: Architecture);
  constructor(arg1: TypeSpacebase | Architecture | AddrSpace, arg2?: Address, arg3?: Architecture) {
    if (arg1 instanceof TypeSpacebase) {
      // Copy constructor
      super(arg1 as Datatype);
      this.spaceid = arg1.spaceid;
      this.localframe = arg1.localframe;
      this.glb = arg1.glb;
    } else if (arg2 === undefined) {
      // Constructor for decode: TypeSpacebase(Architecture)
      super(0, 1, type_metatype.TYPE_SPACEBASE);
      this.spaceid = null;
      this.localframe = new Address();
      this.glb = arg1 as Architecture;
    } else {
      // Construct given an address space, scope, and architecture
      super(0, 1, type_metatype.TYPE_SPACEBASE);
      this.spaceid = arg1 as AddrSpace;
      this.localframe = arg2;
      this.glb = arg3!;
    }
  }

  /**
   * Get the symbol table Scope indexed by this.
   * This data-type can index either a local or the global scope.
   */
  getMap(): Scope {
    let res: Scope = this.glb.symboltab.getGlobalScope();
    if (!this.localframe.isInvalid()) {
      const fd: Funcdata | null = res.queryFunction(this.localframe);
      if (fd !== null)
        res = fd.getScopeLocal();
    }
    return res;
  }

  /**
   * Return the Address being referred to by a specific offset relative to a pointer with this Datatype.
   */
  getAddress(off: bigint, sz: number, point: Address): Address {
    let fullEncoding: { val: bigint } = { val: 0n };
    // Currently a constant off of a global spacebase must be a full pointer encoding
    if (this.localframe.isInvalid())
      sz = -1; // Set size to -1 to guarantee that full encoding recovery isn't launched
    return this.glb.resolveConstant(this.spaceid!, off, sz, point, fullEncoding);
  }

  override getSubType(off: bigint, newoff: { val: bigint }): Datatype | null {
    const scope: Scope = this.getMap();
    const addrOff: bigint = AddrSpace.byteToAddress(off, this.spaceid!.getWordSize());
    const nullPoint = new Address();
    const fullEncoding: { val: bigint } = { val: 0n };
    const addr: Address = this.glb.resolveConstant(this.spaceid!, addrOff, -1, nullPoint, fullEncoding);
    let smallest: any = scope.queryContainer(addr, 1, nullPoint);

    if (smallest === null) {
      newoff.val = 0n;
      return this.glb.types.getBase(1, type_metatype.TYPE_UNKNOWN);
    }
    newoff.val = BigInt(addr.getOffset() - smallest.getAddr().getOffset()) + BigInt(smallest.getOffset());
    return smallest.getSymbol().getType();
  }

  override nearestArrayedComponentForward(off: bigint, newoff: { val: bigint }, elSize: { val: bigint }): Datatype | null {
    const scope: Scope = this.getMap();
    const addrOff: bigint = AddrSpace.byteToAddress(off, this.spaceid!.getWordSize());
    const nullPoint = new Address();
    const fullEncoding: { val: bigint } = { val: 0n };
    const addr: Address = this.glb.resolveConstant(this.spaceid!, addrOff, -1, nullPoint, fullEncoding);
    let smallest: any = scope.queryContainer(addr, 1, nullPoint);
    let nextAddr: Address;
    let symbolType: Datatype;
    if (smallest === null || smallest.getOffset() !== 0) {
      nextAddr = addr.add(32n);
    } else {
      symbolType = smallest.getSymbol().getType();
      if (symbolType.getMetatype() === type_metatype.TYPE_STRUCT) {
        const structOff: bigint = BigInt(addr.getOffset() - smallest.getAddr().getOffset());
        const dummyOff: { val: bigint } = { val: 0n };
        const res = symbolType.nearestArrayedComponentForward(structOff, dummyOff, elSize);
        if (res !== null) {
          newoff.val = structOff;
          return symbolType;
        }
      }
      const sz: bigint = AddrSpace.byteToAddressInt(BigInt(smallest.getSize()), this.spaceid!.getWordSize());
      nextAddr = smallest.getAddr().add(sz);
    }
    if (nextAddr!.getOffset() < addr.getOffset())
      return null; // Don't let the address wrap
    smallest = scope.queryContainer(nextAddr!, 1, nullPoint);
    if (smallest === null || smallest.getOffset() !== 0)
      return null;
    symbolType = smallest.getSymbol().getType();
    newoff.val = BigInt(addr.getOffset() - smallest.getAddr().getOffset());
    if (symbolType.getMetatype() === type_metatype.TYPE_ARRAY) {
      elSize.val = BigInt((symbolType as TypeArray).getBase()!.getAlignSize());
      return symbolType;
    }
    if (symbolType.getMetatype() === type_metatype.TYPE_STRUCT) {
      const dummyOff: { val: bigint } = { val: 0n };
      const res = symbolType.nearestArrayedComponentForward(0n, dummyOff, elSize);
      if (res !== null)
        return symbolType;
    }
    return null;
  }

  override nearestArrayedComponentBackward(off: bigint, newoff: { val: bigint }, elSize: { val: bigint }): Datatype | null {
    const subType = this.getSubType(off, newoff);
    if (subType === null)
      return null;
    if (subType.getMetatype() === type_metatype.TYPE_ARRAY) {
      elSize.val = BigInt((subType as TypeArray).getBase()!.getAlignSize());
      return subType;
    }
    if (subType.getMetatype() === type_metatype.TYPE_STRUCT) {
      const dummyOff: { val: bigint } = { val: 0n };
      const res = subType.nearestArrayedComponentBackward(newoff.val, dummyOff, elSize);
      if (res !== null)
        return subType;
    }
    return null;
  }

  override compare(op: Datatype, level: number): number {
    return this.compareDependency(op);
  }

  override compareDependency(op: Datatype): number {
    let res = super.compareDependency(op);
    if (res !== 0) return res;
    const tsb = op as TypeSpacebase;
    if (this.spaceid !== tsb.spaceid) return (this.spaceid! < tsb.spaceid!) ? -1 : 1;
    if (this.localframe.isInvalid()) return 0; // Global space base
    if (!this.localframe.equals(tsb.localframe)) return (this.localframe.lessThan(tsb.localframe)) ? -1 : 1;
    return 0;
  }

  override clone(): Datatype {
    return new TypeSpacebase(this);
  }

  override encode(encoder: Encoder): void {
    if (this.typedefImm !== null) {
      this.encodeTypedef(encoder);
      return;
    }
    encoder.openElement(ELEM_TYPE);
    this.encodeBasic(this.metatype, -1, encoder);
    encoder.writeSpace(ATTRIB_SPACE, this.spaceid! as any);
    (this.localframe as any).encode(encoder);
    encoder.closeElement(ELEM_TYPE);
  }

  /**
   * Restore this spacebase data-type from a stream.
   */
  decode(decoder: Decoder, typegrp: TypeFactory): void {
    this.decodeBasic(decoder);
    this.spaceid = decoder.readSpaceById(ATTRIB_SPACE) as unknown as AddrSpace;
    this.localframe = (Address as any).decode(decoder);
  }
}

// =========================================================================
// DatatypeWarning
// =========================================================================

/**
 * A data-type associated with a warning string.
 *
 * The warning should be presented to the user whenever the data-type is used.
 * A warning is typically issued for ill-formed data-types that have been
 * modified to facilitate decompiler analysis.
 */
class DatatypeWarning {
  dataType: Datatype;
  warning: string;

  constructor(dt: Datatype, warn: string) {
    this.dataType = dt;
    this.warning = warn;
  }

  getWarning(): string {
    return this.warning;
  }
}

// =========================================================================
// TypeFactory
// =========================================================================

/**
 * Container class for all Datatype objects in an Architecture.
 */
export class TypeFactory {
  private sizeOfInt: number;
  private sizeOfLong: number;
  private sizeOfChar: number;
  private sizeOfWChar: number;
  private sizeOfPointer: number;
  private sizeOfAltPointer: number;
  private enumsize: number;
  private enumtype: type_metatype;
  private alignMap: number[];
  private tree: SortedSet<Datatype>;
  private nametree: SortedSet<Datatype>;
  private typecache: (Datatype | null)[][];
  private typecache10: Datatype | null;
  private typecache16: Datatype | null;
  private type_nochar: Datatype | null;
  private charcache: (Datatype | null)[];
  private warnings: DatatypeWarning[];
  private incompleteTypedef: Datatype[];
  protected glb: Architecture;

  /**
   * Initialize an empty container.
   */
  constructor(g: Architecture) {
    this.glb = g;
    this.sizeOfInt = 0;
    this.sizeOfLong = 0;
    this.sizeOfChar = 0;
    this.sizeOfWChar = 0;
    this.sizeOfPointer = 0;
    this.sizeOfAltPointer = 0;
    this.enumsize = 0;
    this.enumtype = type_metatype.TYPE_ENUM_UINT;
    this.alignMap = [];
    this.tree = new SortedSet<Datatype>(DatatypeCompare);
    this.nametree = new SortedSet<Datatype>(DatatypeNameCompare);
    this.typecache = [];
    this.typecache10 = null;
    this.typecache16 = null;
    this.type_nochar = null;
    this.charcache = [];
    this.warnings = [];
    this.incompleteTypedef = [];
    this.clearCache();
  }

  // -- Cache management ---------------------------------------------------

  /**
   * Clear the matrix of commonly used atomic types.
   */
  private clearCache(): void {
    this.typecache = [];
    for (let i = 0; i < 9; ++i) {
      this.typecache[i] = [];
      for (let j = 0; j < 8; ++j)
        this.typecache[i][j] = null;
    }
    this.typecache10 = null;
    this.typecache16 = null;
    this.type_nochar = null;
    this.charcache = [];
    for (let i = 0; i < 5; ++i)
      this.charcache[i] = null;
  }

  /**
   * Set up default values for size of "int", structure alignment, and enums.
   */
  setupSizes(): void {
    if (this.sizeOfInt === 0) {
      this.sizeOfInt = 1; // Default if we can't find a better value
      const spc: AddrSpace | null = this.glb.getStackSpace();
      if (spc !== null) {
        const spdata = spc.getSpacebase(0);
        this.sizeOfInt = spdata.size;
        if (this.sizeOfInt > 4) // "int" is rarely bigger than 4 bytes
          this.sizeOfInt = 4;
      }
    }
    if (this.sizeOfLong === 0) {
      this.sizeOfLong = (this.sizeOfInt === 4) ? 8 : this.sizeOfInt;
    }
    if (this.sizeOfChar === 0)
      this.sizeOfChar = 1;
    if (this.sizeOfWChar === 0)
      this.sizeOfWChar = 2;
    if (this.sizeOfPointer === 0)
      this.sizeOfPointer = this.glb.getDefaultDataSpace().getAddrSize();
    const segOp: any = this.glb.getSegmentOp(this.glb.getDefaultDataSpace());
    if (segOp !== null && segOp.hasFarPointerSupport()) {
      this.sizeOfPointer = segOp.getInnerSize();
      this.sizeOfAltPointer = this.sizeOfPointer + segOp.getBaseSize();
    }
    if (this.alignMap.length === 0)
      this.setDefaultAlignmentMap();
    if (this.enumsize === 0) {
      this.enumsize = this.glb.getDefaultSize();
      this.enumtype = type_metatype.TYPE_ENUM_UINT;
    }
  }

  /**
   * Manually create a "base" core type.
   */
  setCoreType(name: string, size: number, meta: type_metatype, chartp: boolean): void {
    let ct: Datatype;
    if (chartp) {
      if (size === 1)
        ct = this.getTypeCharByName(name);
      else
        ct = this.getTypeUnicode(name, size, meta);
    } else if (meta === type_metatype.TYPE_CODE) {
      ct = this.getTypeCodeByName(name);
    } else if (meta === type_metatype.TYPE_VOID) {
      ct = this.getTypeVoid();
    } else {
      ct = this.getBaseNamed(size, meta, name);
    }
    ct.flags |= DT_coretype;
  }

  /**
   * Run through the list of "core" data-types and cache the most commonly
   * accessed ones for quick access.
   */
  cacheCoreTypes(): void {
    for (const ct of this.tree) {
      if (!ct.isCoreType()) continue;
      if (ct.getSize() > 8) {
        if (ct.getMetatype() === type_metatype.TYPE_FLOAT) {
          if (ct.getSize() === 10)
            this.typecache10 = ct;
          else if (ct.getSize() === 16)
            this.typecache16 = ct;
        }
        continue;
      }
      switch (ct.getMetatype()) {
        case type_metatype.TYPE_INT:
          if ((ct.getSize() === 1) && (!ct.isASCII()))
            this.type_nochar = ct;
          // fallthrough
        case type_metatype.TYPE_UINT:
          if (ct.isEnumType()) break; // Conceivably an enumeration
          if (ct.isCharPrint()) {
            if (ct.getSize() < 5)
              this.charcache[ct.getSize()] = ct;
            if (ct.isASCII()) {
              // Char is preferred over other int types
              this.typecache[ct.getSize()][ct.getMetatype() - type_metatype.TYPE_FLOAT] = ct;
            }
            // Other character types (UTF16,UTF32) are not preferred
            break;
          }
          // fallthrough
        case type_metatype.TYPE_VOID:
        case type_metatype.TYPE_UNKNOWN:
        case type_metatype.TYPE_BOOL:
        case type_metatype.TYPE_CODE:
        case type_metatype.TYPE_FLOAT:
        {
          const testct = this.typecache[ct.getSize()][ct.getMetatype() - type_metatype.TYPE_FLOAT];
          if (testct === null)
            this.typecache[ct.getSize()][ct.getMetatype() - type_metatype.TYPE_FLOAT] = ct;
          break;
        }
        default:
          break;
      }
    }
  }

  /**
   * Remove all Datatype objects owned by this TypeFactory.
   */
  clear(): void {
    this.tree.clear();
    this.nametree.clear();
    this.clearCache();
    this.warnings = [];
    this.incompleteTypedef = [];
  }

  /**
   * Delete anything that isn't a core type.
   */
  clearNoncore(): void {
    const toRemove: Datatype[] = [];
    for (const ct of this.tree) {
      if (!ct.isCoreType()) {
        toRemove.push(ct);
      }
    }
    for (const ct of toRemove) {
      this.nametree.eraseValue(ct);
      this.tree.eraseValue(ct);
    }
    this.warnings = [];
    this.incompleteTypedef = [];
  }

  /**
   * Return the alignment associated with a primitive data-type of the given size.
   */
  getAlignment(size: number): number {
    if (size >= this.alignMap.length) {
      if (this.alignMap.length === 0)
        throw new LowlevelError("TypeFactory alignment map not initialized");
      return this.alignMap[this.alignMap.length - 1];
    }
    return this.alignMap[size];
  }

  /**
   * Return the aligned size consistent with the sizeof operator in C.
   */
  getPrimitiveAlignSize(size: number): number {
    const align = this.getAlignment(size);
    const mod = size % align;
    if (mod !== 0)
      size += (align - mod);
    return size;
  }

  // -- Getters for architecture sizes ------------------------------------

  getSizeOfInt(): number { return this.sizeOfInt; }
  getSizeOfLong(): number { return this.sizeOfLong; }
  getSizeOfChar(): number { return this.sizeOfChar; }
  getSizeOfWChar(): number { return this.sizeOfWChar; }
  getSizeOfPointer(): number { return this.sizeOfPointer; }
  getSizeOfAltPointer(): number { return this.sizeOfAltPointer; }
  getArch(): Architecture { return this.glb; }

  // -- Search / Lookup ---------------------------------------------------

  /**
   * Looking just within this container, find a Datatype by name and/or id.
   */
  protected findByIdLocal(nm: string, id: bigint): Datatype | null {
    const ct = new TypeBase(1, type_metatype.TYPE_UNKNOWN, nm);
    if (id !== 0n) {
      // Search for an exact type
      ct.id = id;
      const iter = this.nametree.find(ct);
      if (iter.isEnd) return null;
      return iter.value;
    } else {
      // Allow for the fact that the name may not be unique
      ct.id = 0n;
      const iter = this.nametree.lower_bound(ct);
      if (iter.isEnd) return null;
      if (iter.value.getName() !== nm) return null;
      return iter.value;
    }
  }

  /**
   * Search by name and/or id. The id is expected to resolve uniquely.
   * Internally, different length instances of a variable length data-type are stored
   * as separate Datatype objects. A non-zero size can be given to distinguish these cases.
   */
  findById(n: string, id: bigint, sz: number): Datatype | null {
    if (sz > 0) {
      id = Datatype.hashSize(id, sz);
    }
    return this.findByIdLocal(n, id);
  }

  /**
   * Find type with given name. If there are more than one, return first.
   */
  findByName(n: string): Datatype | null {
    return this.findById(n, 0n, 0);
  }

  /**
   * Find data-type without reference to name, using the functional comparators.
   */
  private findNoName(ct: Datatype): Datatype | null {
    const iter = this.tree.find(ct);
    if (!iter.isEnd)
      return iter.value;
    return null;
  }

  /**
   * Internal method for finally inserting a new Datatype pointer.
   */
  private insert(newtype: Datatype): void {
    const [iter, inserted] = this.tree.insert(newtype);
    if (!inserted) {
      const s = new StringWriter();
      s.write("Shared type id: ");
      s.write(newtype.getId().toString(16));
      s.write("\n  ");
      newtype.printRaw(s);
      s.write(" : ");
      iter.value.printRaw(s);
      throw new LowlevelError(s.toString());
    }
    if (newtype.id !== 0n)
      this.nametree.insert(newtype);
  }

  /**
   * Use quickest method (name or id is possible) to locate the matching data-type.
   * If it's not currently in this container, clone the data-type and add it to the container.
   */
  findAdd(ct: Datatype): Datatype {
    let newtype: Datatype;
    let res: Datatype | null;

    if (ct.name.length !== 0) {
      if (ct.id === 0n)
        throw new LowlevelError("Datatype must have a valid id: " + ct.name);
      res = this.findByIdLocal(ct.name, ct.id);
      if (res !== null) {
        if (0 !== res.compareDependency(ct))
          throw new LowlevelError("Trying to alter definition of type: " + ct.name);
        return res;
      }
    } else {
      res = this.findNoName(ct);
      if (res !== null) return res;
    }

    newtype = ct.clone();
    if (newtype.alignment < 0) {
      newtype.alignSize = this.getPrimitiveAlignSize(newtype.size);
      newtype.alignment = this.getAlignment(newtype.alignSize);
    }
    this.insert(newtype);
    return newtype;
  }

  /**
   * This routine renames a Datatype object and fixes up cross-referencing.
   */
  setName(ct: Datatype, n: string): Datatype {
    if (ct.id !== 0n)
      this.nametree.eraseValue(ct);
    this.tree.eraseValue(ct);
    ct.name = n;
    ct.displayName = n;
    if (ct.id === 0n)
      ct.id = Datatype.hashName(n);
    this.tree.insert(ct);
    this.nametree.insert(ct);
    return ct;
  }

  /**
   * The display format for the data-type is changed based on the given format.
   */
  setDisplayFormat(ct: Datatype, format: number): void {
    ct.setDisplayFormat(format);
  }

  /**
   * Set fields on a TypeStruct, establishing its size, alignment, and other properties.
   */
  setFields(fd: TypeField[], ot: TypeStruct, newSize: number, newAlign: number, flags: number): void;
  /**
   * Set fields on a TypeUnion.
   */
  setFields(fd: TypeField[], ot: TypeUnion, newSize: number, newAlign: number, flags: number): void;
  setFields(fd: TypeField[], ot: TypeStruct | TypeUnion, newSize: number, newAlign: number, flags: number): void {
    if (!ot.isIncomplete())
      throw new LowlevelError("Can only set fields on an incomplete " + (ot instanceof TypeStruct ? "structure" : "union"));

    this.tree.eraseValue(ot);
    (ot as any).setFields(fd, newSize, newAlign);
    ot.flags &= ~DT_type_incomplete;
    if (ot instanceof TypeStruct) {
      ot.flags |= (flags & (DT_opaque_string | DT_variable_length | DT_type_incomplete));
      this.tree.insert(ot);
      this.recalcPointerSubmeta(ot, sub_metatype.SUB_PTR);
      this.recalcPointerSubmeta(ot, sub_metatype.SUB_PTR_STRUCT);
    } else {
      ot.flags |= (flags & (DT_variable_length | DT_type_incomplete));
      this.tree.insert(ot);
    }
  }

  /**
   * Set the prototype on a TypeCode. The given prototype is copied into the given code data-type.
   */
  setPrototype(fp: FuncProto | null, newCode: TypeCode, flags: number): void {
    if (!newCode.isIncomplete())
      throw new LowlevelError("Can only set prototype on incomplete data-type");
    this.tree.eraseValue(newCode);
    newCode.setPrototypeCopy(this, fp);
    newCode.flags &= ~DT_type_incomplete;
    newCode.flags |= (flags & (DT_variable_length | DT_type_incomplete));
    this.tree.insert(newCode);
  }

  /**
   * Set named values for an enumeration.
   */
  setEnumValues(nmap: Map<bigint, string>, te: TypeEnum): void {
    this.tree.eraseValue(te);
    (te as any).setNameMap(nmap);
    this.tree.insert(te);
  }

  /**
   * Establish unique enumeration values for a TypeEnum.
   * Fill in any values for names that weren't explicitly assigned and check for duplicates.
   */
  assignEnumValues(
    nmap: Map<bigint, string>,
    namelist: string[],
    vallist: bigint[],
    assignlist: boolean[],
    te: TypeEnum
  ): void {
    const mask: bigint = calc_mask(te.getSize());
    let maxval: bigint = 0n;

    // First pass: process explicitly assigned values
    for (let i = 0; i < namelist.length; ++i) {
      if (assignlist[i]) {
        let val = vallist[i];
        if (val > maxval)
          maxval = val;
        val &= mask;
        if (nmap.has(val)) {
          throw new LowlevelError('Enum "' + te.getName() + '": "' + namelist[i] + '" is a duplicate value');
        }
        nmap.set(val, namelist[i]);
      }
    }

    // Second pass: auto-assign values to unassigned names
    for (let i = 0; i < namelist.length; ++i) {
      if (!assignlist[i]) {
        let val: bigint;
        do {
          maxval += 1n;
          val = maxval & mask;
        } while (nmap.has(val));
        nmap.set(val, namelist[i]);
      }
    }
  }

  // -- Topological ordering -----------------------------------------------

  /**
   * Write out dependency list recursively.
   */
  private orderRecurse(deporder: Datatype[], mark: SortedSet<Datatype>, ct: Datatype): void {
    const [, inserted] = mark.insert(ct);
    if (!inserted) return; // Already inserted before
    if (ct.typedefImm !== null)
      this.orderRecurse(deporder, mark, ct.typedefImm);
    const size = ct.numDepend();
    for (let i = 0; i < size; ++i)
      this.orderRecurse(deporder, mark, ct.getDepend(i)!);
    deporder.push(ct);
  }

  /**
   * Place data-types in an order such that if the definition of data-type "a"
   * depends on the definition of data-type "b", then "b" occurs earlier in the order.
   */
  dependentOrder(deporder: Datatype[]): void {
    const mark = new SortedSet<Datatype>(DatatypeCompare);
    for (const ct of this.tree)
      this.orderRecurse(deporder, mark, ct);
  }

  // -- Type retrieval / creation ------------------------------------------

  /**
   * Get the "void" data-type. There should be exactly one instance.
   */
  getTypeVoid(): TypeVoid {
    let ct = this.typecache[0][type_metatype.TYPE_VOID - type_metatype.TYPE_FLOAT] as TypeVoid | null;
    if (ct !== null)
      return ct;
    const tv = new TypeVoid();
    tv.id = Datatype.hashName(tv.name);
    ct = tv.clone() as TypeVoid;
    this.tree.insert(ct);
    this.nametree.insert(ct);
    this.typecache[0][type_metatype.TYPE_VOID - type_metatype.TYPE_FLOAT] = ct;
    return ct;
  }

  /**
   * Create a 1-byte character data-type (assumed to use UTF8 encoding).
   * (Private helper used by setCoreType.)
   */
  private getTypeCharByName(n: string): TypeChar {
    const tc = new TypeChar(n);
    tc.id = Datatype.hashName(n);
    return this.findAdd(tc) as TypeChar;
  }

  /**
   * Create a multi-byte character data-type (using UTF16 or UTF32 encoding).
   */
  private getTypeUnicode(nm: string, sz: number, m: type_metatype): TypeUnicode {
    const tu = new TypeUnicode(nm, sz, m);
    tu.id = Datatype.hashName(nm);
    return this.findAdd(tu) as TypeUnicode;
  }

  /**
   * Get a "base" data-type, given its size and metatype.
   * If a 1-byte integer is requested, do NOT return a TypeChar.
   */
  getBaseNoChar(s: number, m: type_metatype): Datatype {
    if ((s === 1) && (m === type_metatype.TYPE_INT) && (this.type_nochar !== null))
      return this.type_nochar;
    return this.getBase(s, m);
  }

  /**
   * Get one of the "base" datatypes. Goes through a cache first.
   */
  getBase(s: number, m: type_metatype): Datatype {
    let ct: Datatype | null;
    if (s > 0 && s < 9) {
      if (m >= type_metatype.TYPE_FLOAT && m <= type_metatype.TYPE_VOID) {
        ct = this.typecache[s][m - type_metatype.TYPE_FLOAT];
        if (ct !== null)
          return ct;
      }
    } else if (m === type_metatype.TYPE_FLOAT) {
      if (s === 10)
        ct = this.typecache10;
      else if (s === 16)
        ct = this.typecache16;
      else
        ct = null;
      if (ct !== null)
        return ct;
    }
    if (s > this.glb.max_basetype_size) {
      // Create array of unknown bytes to match size
      ct = this.typecache[1][type_metatype.TYPE_UNKNOWN - type_metatype.TYPE_FLOAT];
      const arr = this.getTypeArray(s, ct!);
      return this.findAdd(arr);
    }
    const tmp = new TypeBase(s, m);
    return this.findAdd(tmp);
  }

  /**
   * Get or create a "base" type with a specified name and properties.
   */
  getBaseNamed(s: number, m: type_metatype, n: string): Datatype {
    const tmp = new TypeBase(s, m, n);
    tmp.id = Datatype.hashName(n);
    return this.findAdd(tmp);
  }

  /**
   * If a core character data-type of the given size exists, it is returned.
   * Otherwise an exception is thrown.
   */
  getTypeChar(s: number): Datatype {
    if (s < 5) {
      const res = this.charcache[s];
      if (res !== null)
        return res;
    }
    throw new LowlevelError("Request for unsupported character data-type");
  }

  /**
   * Retrieve or create the core "code" Datatype object.
   * This has no prototype attached to it and is appropriate for anonymous function pointers.
   */
  getTypeCode(): TypeCode {
    const ct = this.typecache[1][type_metatype.TYPE_CODE - type_metatype.TYPE_FLOAT];
    if (ct !== null)
      return ct as TypeCode;
    const tmp = new TypeCode(); // A generic code object
    tmp.markComplete();        // which is considered complete
    return this.findAdd(tmp) as TypeCode;
  }

  /**
   * Create a "function" or "executable" Datatype object with a name.
   * Used for anonymous function pointers with no prototype.
   */
  private getTypeCodeByName(nm: string): TypeCode {
    if (nm.length === 0) return this.getTypeCode();
    const tmp = new TypeCode();
    tmp.name = nm;
    tmp.displayName = nm;
    tmp.id = Datatype.hashName(nm);
    tmp.markComplete();
    return this.findAdd(tmp) as TypeCode;
  }

  /**
   * Create a TypeCode object and associate a specific function prototype with it.
   */
  getTypeCodeFromProto(proto: PrototypePieces): TypeCode {
    const tc = new TypeCode();
    tc.setPrototypePieces(this, proto, this.getTypeVoid());
    tc.markComplete();
    return this.findAdd(tc) as TypeCode;
  }

  /**
   * Search for pointers that match the given ptrto and sub-metatype and change it to
   * the current calculated sub-metatype.
   */
  private recalcPointerSubmeta(base: Datatype, sub: sub_metatype): void {
    const top = new TypePointer(1, base, 0);
    const curSub = top.submeta;
    if (curSub === sub) return; // Don't need to search for pointers with correct submeta
    top.submeta = sub; // Search on the incorrect submeta
    const iter = this.tree.lower_bound(top);
    const toFix: TypePointer[] = [];
    // Collect pointers that need fixing (can't modify tree while iterating)
    const iterClone = iter.clone();
    while (!iterClone.isEnd) {
      const dt = iterClone.value;
      if (dt.getMetatype() !== type_metatype.TYPE_PTR) break;
      const ptr = dt as TypePointer;
      if ((ptr as any).ptrto !== base) break;
      if (ptr.submeta === sub) {
        toFix.push(ptr);
      }
      iterClone.next();
    }
    for (const ptr of toFix) {
      this.tree.eraseValue(ptr);
      ptr.submeta = curSub;
      this.tree.insert(ptr);
    }
  }

  /**
   * Register a new data-type warning with this factory.
   */
  private insertWarning(dt: Datatype, warn: string): void {
    if (dt.getId() === 0n)
      throw new LowlevelError("Can only issue warnings for named data-types");
    dt.flags |= DT_warning_issued;
    this.warnings.push(new DatatypeWarning(dt, warn));
  }

  /**
   * Remove the warning associated with the given data-type.
   */
  private removeWarning(dt: Datatype): void {
    this.warnings = this.warnings.filter(w =>
      !(w.dataType.getId() === dt.getId() && w.dataType.getName() === dt.getName())
    );
  }

  /**
   * Redefine incomplete typedefs of data-types that are now complete.
   */
  private resolveIncompleteTypedefs(): void {
    const remaining: Datatype[] = [];
    for (const dt of this.incompleteTypedef) {
      const defedType = dt.getTypedef();
      if (defedType !== null && !defedType.isIncomplete()) {
        if (dt.getMetatype() === type_metatype.TYPE_STRUCT) {
          const prevStruct = dt as TypeStruct;
          const defedStruct = defedType as TypeStruct;
          this.setFields((defedStruct as any).field, prevStruct, defedStruct.size, defedStruct.alignment, defedStruct.flags);
        } else if (dt.getMetatype() === type_metatype.TYPE_UNION) {
          const prevUnion = dt as TypeUnion;
          const defedUnion = defedType as TypeUnion;
          this.setFields((defedUnion as any).field, prevUnion, defedUnion.size, defedUnion.alignment, defedUnion.flags);
        } else if (dt.getMetatype() === type_metatype.TYPE_CODE) {
          const prevCode = dt as TypeCode;
          const defedCode = defedType as TypeCode;
          this.setPrototype(defedCode.proto, prevCode, defedCode.flags);
        } else {
          remaining.push(dt);
        }
      } else {
        remaining.push(dt);
      }
    }
    this.incompleteTypedef = remaining;
  }

  /**
   * Find or create a data-type identical to the given data-type except for its name and id.
   * If the name and id already describe an incompatible data-type, an exception is thrown.
   */
  getTypedef(ct: Datatype, name: string, id: bigint, format: number): Datatype {
    id = BigInt(id);  // Ensure id is a true bigint (guards against numeric 0 vs 0n)
    if (id === 0n)
      id = Datatype.hashName(name);
    let res = this.findByIdLocal(name, id);
    if (res !== null) {
      if (ct !== res.getTypedef())
        throw new LowlevelError("Trying to create typedef of existing type: " + name);
      return res;
    }
    res = ct.clone();
    res.name = name;
    res.displayName = name;
    res.id = id;
    res.flags &= ~DT_coretype;
    res.typedefImm = ct;
    res.setDisplayFormat(format);
    this.insert(res);
    if (res.isIncomplete())
      this.incompleteTypedef.push(res);
    return res;
  }

  /**
   * Create a pointer, stripping an ARRAY level.
   * This creates a pointer to a given data-type. If the given data-type is an array,
   * the TYPE_ARRAY property is stripped off and a pointer to the array element data-type is returned.
   */
  getTypePointerStripArray(s: number, pt: Datatype, ws: number): TypePointer {
    if (pt.hasStripped())
      pt = pt.getStripped()!;
    if (pt.getMetatype() === type_metatype.TYPE_ARRAY)
      pt = (pt as TypeArray).getBase()!; // Strip the first ARRAY type
    const tmp = new TypePointer(s, pt, ws);
    const res = this.findAdd(tmp) as TypePointer;
    res.calcTruncate(this);
    return res;
  }

  /**
   * Construct an absolute pointer data-type.
   * Allows "pointer to array" to be constructed.
   */
  getTypePointer(s: number, pt: Datatype, ws: number): TypePointer;
  /**
   * Construct a named pointer data-type.
   */
  getTypePointer(s: number, pt: Datatype, ws: number, n: string): TypePointer;
  getTypePointer(s: number, pt: Datatype, ws: number, n?: string): TypePointer {
    if (pt.hasStripped())
      pt = pt.getStripped()!;
    const tmp = new TypePointer(s, pt, ws);
    if (n !== undefined) {
      tmp.name = n;
      tmp.displayName = n;
      tmp.id = Datatype.hashName(n);
    }
    const res = this.findAdd(tmp) as TypePointer;
    res.calcTruncate(this);
    return res;
  }

  /**
   * Construct an array data-type.
   */
  getTypeArray(as_: number, ao: Datatype): TypeArray {
    if (ao.hasStripped())
      ao = ao.getStripped()!;
    const tmp = new TypeArray(as_, ao);
    return this.findAdd(tmp) as TypeArray;
  }

  /**
   * Create an (empty) structure. The created structure will be incomplete and have no fields.
   */
  getTypeStruct(n: string): TypeStruct {
    const tmp = new TypeStruct();
    tmp.name = n;
    tmp.displayName = n;
    tmp.id = Datatype.hashName(n);
    return this.findAdd(tmp) as TypeStruct;
  }

  /**
   * Create a partial structure data-type.
   */
  getTypePartialStruct(contain: Datatype, off: number, sz: number): TypePartialStruct {
    const strip = this.getBase(sz, type_metatype.TYPE_UNKNOWN);
    const tps = new TypePartialStruct(contain, off, sz, strip);
    return this.findAdd(tps) as TypePartialStruct;
  }

  /**
   * Create an (empty) union. The created union will be incomplete and have no fields.
   */
  getTypeUnion(n: string): TypeUnion {
    const tmp = new TypeUnion();
    tmp.name = n;
    tmp.displayName = n;
    tmp.id = Datatype.hashName(n);
    return this.findAdd(tmp) as TypeUnion;
  }

  /**
   * Create a partial union data-type.
   */
  getTypePartialUnion(contain: TypeUnion, off: number, sz: number): TypePartialUnion {
    const strip = this.getBase(sz, type_metatype.TYPE_UNKNOWN);
    const tpu = new TypePartialUnion(contain, off, sz, strip);
    return this.findAdd(tpu) as TypePartialUnion;
  }

  /**
   * Create an (empty) enumeration. Named values must be added later.
   */
  getTypeEnum(n: string): TypeEnum {
    const tmp = new TypeEnum(this.enumsize, this.enumtype, n);
    tmp.id = Datatype.hashName(n);
    return this.findAdd(tmp) as TypeEnum;
  }

  /**
   * Create a partial enumeration data-type.
   */
  getTypePartialEnum(contain: TypeEnum, off: number, sz: number): TypePartialEnum {
    const strip = this.getBase(sz, type_metatype.TYPE_UNKNOWN);
    const tpe = new TypePartialEnum(contain, off, sz, strip);
    return this.findAdd(tpe) as TypePartialEnum;
  }

  /**
   * Create the special TypeSpacebase with an associated address space and scope.
   */
  getTypeSpacebase(id: AddrSpace, addr: Address): TypeSpacebase {
    const tsb = new TypeSpacebase(id, addr, this.glb);
    return this.findAdd(tsb) as TypeSpacebase;
  }

  /**
   * Find/create a pointer data-type that points at a known offset relative to a containing data-type.
   * The resulting data-type is unnamed and ephemeral.
   */
  getTypePointerRel(parentPtr: TypePointer, ptrTo: Datatype, off: number): TypePointerRel;
  /**
   * Build a named pointer offset into a larger container.
   */
  getTypePointerRel(sz: number, parent: Datatype, ptrTo: Datatype, ws: number, off: number, nm: string): TypePointerRel;
  getTypePointerRel(
    arg1: TypePointer | number,
    arg2: Datatype,
    arg3: Datatype | number,
    arg4?: number,
    arg5?: number,
    arg6?: string
  ): TypePointerRel {
    if (typeof arg1 !== 'number') {
      // getTypePointerRel(parentPtr, ptrTo, off)
      const parentPtr = arg1 as TypePointer;
      const ptrTo = arg2;
      const off = arg3 as number;
      const tp = new TypePointerRel(parentPtr.size, ptrTo, (parentPtr as any).wordsize, (parentPtr as any).ptrto, off);
      tp.markEphemeral(this);
      return this.findAdd(tp) as TypePointerRel;
    } else {
      // getTypePointerRel(sz, parent, ptrTo, ws, off, nm)
      const sz = arg1;
      const parent = arg2;
      const ptrTo = arg3 as Datatype;
      const ws = arg4!;
      const off = arg5!;
      const nm = arg6!;
      const tp = new TypePointerRel(sz, ptrTo, ws, parent, off);
      tp.name = nm;
      tp.displayName = nm;
      tp.id = Datatype.hashName(nm);
      return this.findAdd(tp) as TypePointerRel;
    }
  }

  /**
   * Build a named pointer with an address space attribute.
   */
  getTypePointerWithSpace(ptrTo: Datatype, spc: AddrSpace, nm: string): TypePointer {
    const tp = new TypePointer(ptrTo, spc);
    tp.name = nm;
    tp.displayName = nm;
    tp.id = Datatype.hashName(nm);
    const res = this.findAdd(tp) as TypePointer;
    res.calcTruncate(this);
    return res;
  }

  /**
   * Build a resized pointer based on the given pointer.
   * All the properties of the original pointer are preserved, except the size is changed.
   */
  resizePointer(ptr: TypePointer, newSize: number): TypePointer {
    let pt: Datatype = (ptr as any).ptrto;
    if (pt.hasStripped())
      pt = pt.getStripped()!;
    const tmp = new TypePointer(newSize, pt, (ptr as any).wordsize);
    return this.findAdd(tmp) as TypePointer;
  }

  /**
   * Drill down into nested data-types until we get to a data-type that exactly matches the
   * given offset and size, and return this data-type. Any union data-type encountered
   * terminates the process and a partial union data-type is constructed and returned.
   * Returns null if the range contains only a partial field or crosses field boundaries.
   */
  getExactPiece(ct: Datatype, offset: number, size: number): Datatype | null {
    let lastType: Datatype | null = null;
    let lastOff: bigint = 0n;
    let curOff: bigint = BigInt(offset);
    do {
      if (ct.getSize() < size + Number(curOff)) {
        break; // Range is beyond end of current data-type
      }
      if (ct.getSize() === size)
        return ct; // Perfect size match
      if (ct.getMetatype() === type_metatype.TYPE_UNION) {
        return this.getTypePartialUnion(ct as TypeUnion, Number(curOff), size);
      }
      lastType = ct;
      lastOff = curOff;
      const newoff: { val: bigint } = { val: 0n };
      const sub = ct.getSubType(curOff, newoff);
      ct = sub!;
      curOff = newoff.val;
    } while (ct !== null);
    if (lastType !== null) {
      // If we reach here, lastType is bigger than size
      if (lastType.getMetatype() === type_metatype.TYPE_STRUCT || lastType.getMetatype() === type_metatype.TYPE_ARRAY)
        return this.getTypePartialStruct(lastType, Number(lastOff), size);
      else if (lastType.isEnumType() && !lastType.hasStripped())
        return this.getTypePartialEnum(lastType as TypeEnum, Number(lastOff), size);
    }
    return null;
  }

  /**
   * Remove a data-type from this container.
   * Indirect references (via TypeArray, TypeStruct etc.) are not affected.
   */
  destroyType(ct: Datatype): void {
    if (ct.isCoreType())
      throw new LowlevelError("Cannot destroy core type");
    if (ct.hasWarning())
      this.removeWarning(ct);
    this.nametree.eraseValue(ct);
    this.tree.eraseValue(ct);
  }

  /**
   * Convert given data-type to concrete form.
   * The data-type propagation system can push around data-types that are partial or are
   * otherwise unrepresentable. This method substitutes those data-types with a concrete
   * data-type that is representable, or returns the same data-type if it is already concrete.
   */
  concretize(ct: Datatype): Datatype {
    const metatype = ct.getMetatype();
    if (metatype === type_metatype.TYPE_CODE) {
      if (ct.getSize() !== 1)
        throw new LowlevelError("Primitive code data-type that is not size 1");
      ct = this.getBase(1, type_metatype.TYPE_UNKNOWN);
    }
    return ct;
  }

  // -- Decode methods -----------------------------------------------------

  /**
   * Restore a Datatype object from an element: either <type>, <typeref>, or <void>.
   */
  decodeType(decoder: Decoder): Datatype {
    let ct: Datatype;
    const elemId = decoder.peekElement();
    if (ELEM_TYPEREF.getId() === elemId) {
      const openId = decoder.openElement();
      let newid: bigint = 0n;
      let size: number = -1;
      for (;;) {
        const attribId = decoder.getNextAttributeId();
        if (attribId === 0) break;
        if (attribId === ATTRIB_ID.getId()) {
          newid = BigInt(decoder.readUnsignedInteger());
        } else if (attribId === ATTRIB_SIZE.getId()) {
          size = decoder.readSignedInteger();
        }
      }
      const newname: string = decoder.readStringById(ATTRIB_NAME);
      if (newid === 0n)
        newid = Datatype.hashName(newname);
      ct = this.findById(newname, newid, size)!;
      if (ct === null)
        throw new LowlevelError("Unable to resolve type: " + newname);
      decoder.closeElement(openId);
      return ct;
    }
    return this.decodeTypeNoRef(decoder, false);
  }

  /**
   * Restore data-type from an element and extra "code" flags.
   * Kludge to get flags into code pointer types, when they can't come through the stream.
   */
  decodeTypeWithCodeFlags(decoder: Decoder, isConstructor: boolean, isDestructor: boolean): Datatype {
    const tp = new TypePointer();
    const elemId = decoder.openElement();
    tp.decodeBasic(decoder);
    if (tp.getMetatype() !== type_metatype.TYPE_PTR)
      throw new LowlevelError("Special type decode does not see pointer");
    for (;;) {
      const attribId = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_WORDSIZE.getId()) {
        (tp as any).wordsize = decoder.readUnsignedInteger();
      }
    }
    (tp as any).ptrto = this.decodeCode(decoder, isConstructor, isDestructor, false);
    decoder.closeElement(elemId);
    tp.calcTruncate(this);
    return this.findAdd(tp);
  }

  /**
   * Encode all data-types in dependency order to a stream.
   */
  encode(encoder: Encoder): void {
    const deporder: Datatype[] = [];
    this.dependentOrder(deporder);
    encoder.openElement(ELEM_TYPEGRP);
    for (const dt of deporder) {
      if (dt.getName().length === 0) continue; // Don't save anonymous types
      if (dt.isCoreType()) {
        const meta = dt.getMetatype();
        if (meta !== type_metatype.TYPE_PTR && meta !== type_metatype.TYPE_ARRAY &&
            meta !== type_metatype.TYPE_STRUCT && meta !== type_metatype.TYPE_UNION)
          continue; // Don't save it here
      }
      dt.encode(encoder);
    }
    encoder.closeElement(ELEM_TYPEGRP);
  }

  /**
   * Encode only core types to stream.
   */
  encodeCoreTypes(encoder: Encoder): void {
    encoder.openElement(ELEM_CORETYPES);
    for (const ct of this.tree) {
      if (!ct.isCoreType()) continue;
      const meta = ct.getMetatype();
      if (meta === type_metatype.TYPE_PTR || meta === type_metatype.TYPE_ARRAY ||
          meta === type_metatype.TYPE_STRUCT || meta === type_metatype.TYPE_UNION)
        continue;
      ct.encode(encoder);
    }
    encoder.closeElement(ELEM_CORETYPES);
  }

  /**
   * Decode a typedef element.
   */
  private decodeTypedef(decoder: Decoder): Datatype {
    let id: bigint = 0n;
    let nm: string = "";
    let format: number = 0;
    for (;;) {
      const attribId = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_ID.getId()) {
        id = BigInt(decoder.readUnsignedInteger());
      } else if (attribId === ATTRIB_NAME.getId()) {
        nm = decoder.readString();
      } else if (attribId === ATTRIB_FORMAT.getId()) {
        format = Datatype.encodeIntegerFormat(decoder.readString());
      }
    }
    if (id === 0n) {
      id = Datatype.hashName(nm);
    }
    const defedType: Datatype = this.decodeType(decoder);
    if (defedType.isVariableLength())
      id = Datatype.hashSize(id, defedType.size);
    if (defedType.getMetatype() === type_metatype.TYPE_STRUCT || defedType.getMetatype() === type_metatype.TYPE_UNION) {
      const prev = this.findByIdLocal(nm, id);
      if (prev !== null) {
        if (defedType !== prev.getTypedef())
          throw new LowlevelError("Trying to create typedef of existing type: " + prev.name);
        if (prev.getMetatype() === type_metatype.TYPE_STRUCT) {
          const prevStruct = prev as TypeStruct;
          const defedStruct = defedType as TypeStruct;
          if ((prevStruct as any).field.length !== (defedStruct as any).field.length)
            this.setFields((defedStruct as any).field, prevStruct, defedStruct.size, defedStruct.alignment, defedStruct.flags);
        } else {
          const prevUnion = prev as TypeUnion;
          const defedUnion = defedType as TypeUnion;
          if ((prevUnion as any).field.length !== (defedUnion as any).field.length)
            this.setFields((defedUnion as any).field, prevUnion, defedUnion.size, defedUnion.alignment, defedUnion.flags);
        }
        return prev;
      }
    }
    return this.getTypedef(defedType, nm, id, format);
  }

  /**
   * Restore an enumeration data-type from a stream.
   */
  private decodeEnum(decoder: Decoder, forcecore: boolean): Datatype {
    const te = new TypeEnum(1, type_metatype.TYPE_ENUM_INT); // metatype and size are replaced
    const warning: string = (te as any).decode(decoder, this);
    if (forcecore)
      te.flags |= DT_coretype;
    const res = this.findAdd(te);
    if (warning && warning.length > 0)
      this.insertWarning(res, warning);
    return res;
  }

  /**
   * Restore a structure data-type from a stream.
   * If necessary, create a stub object before parsing the field descriptions,
   * to deal with recursive definitions.
   */
  private decodeStruct(decoder: Decoder, forcecore: boolean): Datatype {
    const ts = new TypeStruct();
    ts.decodeBasic(decoder);
    if (forcecore)
      ts.flags |= DT_coretype;
    let ct: Datatype | null = this.findByIdLocal(ts.name, ts.id);
    if (ct === null) {
      ct = this.findAdd(ts); // Create stub to allow recursive definitions
    } else if (ct.getMetatype() !== type_metatype.TYPE_STRUCT) {
      throw new LowlevelError("Trying to redefine type: " + ts.name);
    }
    const warning: string = (ts as any).decodeFields(decoder, this);
    if (!ct.isIncomplete()) {
      // Structure of this name was already present
      if (0 !== ct.compareDependency(ts))
        throw new LowlevelError("Redefinition of structure: " + ts.name);
    } else {
      // If structure is a placeholder stub
      this.setFields((ts as any).field, ct as TypeStruct, ts.size, ts.alignment, ts.flags);
    }
    if (warning && warning.length > 0)
      this.insertWarning(ct, warning);
    this.resolveIncompleteTypedefs();
    return ct;
  }

  /**
   * Restore a union data-type from a stream.
   * If necessary, create a stub object before parsing the field descriptions.
   */
  private decodeUnion(decoder: Decoder, forcecore: boolean): Datatype {
    const tu = new TypeUnion();
    tu.decodeBasic(decoder);
    if (forcecore)
      tu.flags |= DT_coretype;
    let ct: Datatype | null = this.findByIdLocal(tu.name, tu.id);
    if (ct === null) {
      ct = this.findAdd(tu);
    } else if (ct.getMetatype() !== type_metatype.TYPE_UNION) {
      throw new LowlevelError("Trying to redefine type: " + tu.name);
    }
    (tu as any).decodeFields(decoder, this);
    if (!ct.isIncomplete()) {
      if (0 !== ct.compareDependency(tu))
        throw new LowlevelError("Redefinition of union: " + tu.name);
    } else {
      this.setFields((tu as any).field, ct as TypeUnion, tu.size, tu.alignment, tu.flags);
    }
    this.resolveIncompleteTypedefs();
    return ct;
  }

  /**
   * Restore a code data-type from a stream.
   * If necessary, create a stub object before parsing the prototype description.
   */
  private decodeCode(decoder: Decoder, isConstructor: boolean, isDestructor: boolean, forcecore: boolean): Datatype {
    const tc = new TypeCode();
    tc.decodeStub(decoder);
    if (tc.getMetatype() !== type_metatype.TYPE_CODE) {
      throw new LowlevelError("Expecting metatype=\"code\"");
    }
    if (forcecore)
      tc.flags |= DT_coretype;
    let ct: Datatype | null = this.findByIdLocal(tc.name, tc.id);
    if (ct === null) {
      ct = this.findAdd(tc);
    } else if (ct.getMetatype() !== type_metatype.TYPE_CODE) {
      throw new LowlevelError("Trying to redefine type: " + tc.name);
    }
    tc.decodePrototype(decoder, isConstructor, isDestructor, this);
    if (!ct.isIncomplete()) {
      if (0 !== ct.compareDependency(tc))
        throw new LowlevelError("Redefinition of code data-type: " + tc.name);
    } else {
      this.setPrototype(tc.proto, ct as TypeCode, tc.flags);
    }
    this.resolveIncompleteTypedefs();
    return ct;
  }

  /**
   * Restore a Datatype from a <type> element (not <typeref>).
   * The new Datatype is added to this container.
   */
  private decodeTypeNoRef(decoder: Decoder, forcecore: boolean): Datatype {
    let ct: Datatype;

    const elemId = decoder.openElement();
    if (elemId === ELEM_VOID.getId()) {
      ct = this.getTypeVoid(); // Automatically a coretype
      decoder.closeElement(elemId);
      return ct;
    }
    if (elemId === ELEM_DEF.getId()) {
      ct = this.decodeTypedef(decoder);
      decoder.closeElement(elemId);
      return ct;
    }
    const meta: type_metatype = string2metatype(decoder.readStringById(ATTRIB_METATYPE));
    switch (meta) {
      case type_metatype.TYPE_PTR:
      {
        const tp = new TypePointer();
        (tp as any).decode(decoder, this);
        if (forcecore)
          tp.flags |= DT_coretype;
        ct = this.findAdd(tp);
        break;
      }
      case type_metatype.TYPE_PTRREL:
      {
        const tp = new TypePointerRel();
        (tp as any).decode(decoder, this);
        if (forcecore)
          tp.flags |= DT_coretype;
        ct = this.findAdd(tp);
        break;
      }
      case type_metatype.TYPE_ARRAY:
      {
        const ta = new TypeArray();
        (ta as any).decode(decoder, this);
        if (forcecore)
          ta.flags |= DT_coretype;
        ct = this.findAdd(ta);
        break;
      }
      case type_metatype.TYPE_ENUM_INT:
      case type_metatype.TYPE_ENUM_UINT:
        ct = this.decodeEnum(decoder, forcecore);
        break;
      case type_metatype.TYPE_STRUCT:
        ct = this.decodeStruct(decoder, forcecore);
        break;
      case type_metatype.TYPE_UNION:
        ct = this.decodeUnion(decoder, forcecore);
        break;
      case type_metatype.TYPE_SPACEBASE:
      {
        const tsb = new TypeSpacebase(this.glb);
        tsb.decode(decoder, this);
        if (forcecore)
          tsb.flags |= DT_coretype;
        ct = this.findAdd(tsb);
        break;
      }
      case type_metatype.TYPE_CODE:
        ct = this.decodeCode(decoder, false, false, forcecore);
        break;
      case type_metatype.TYPE_VOID:
      {
        const voidType = new TypeVoid();
        (voidType as any).decode(decoder, this);
        ct = this.findAdd(voidType);
        break;
      }
      default:
      {
        // Check for char or utf attributes
        let foundCharOrUtf = false;
        for (;;) {
          const attribId = decoder.getNextAttributeId();
          if (attribId === 0) break;
          if (attribId === ATTRIB_CHAR.getId() && decoder.readBool()) {
            const tcChar = new TypeChar(decoder.readStringById(ATTRIB_NAME));
            decoder.rewindAttributes();
            (tcChar as any).decode(decoder, this);
            if (forcecore)
              tcChar.flags |= DT_coretype;
            ct = this.findAdd(tcChar);
            decoder.closeElement(elemId);
            return ct;
          } else if (attribId === ATTRIB_UTF.getId() && decoder.readBool()) {
            const tu = new TypeUnicode();
            decoder.rewindAttributes();
            (tu as any).decode(decoder, this);
            if (forcecore)
              tu.flags |= DT_coretype;
            ct = this.findAdd(tu);
            decoder.closeElement(elemId);
            return ct;
          }
        }
        // Default: TypeBase
        decoder.rewindAttributes();
        const tb = new TypeBase(0, type_metatype.TYPE_UNKNOWN);
        tb.decodeBasic(decoder);
        if (forcecore)
          tb.flags |= DT_coretype;
        ct = this.findAdd(tb);
        break;
      }
    }
    decoder.closeElement(elemId);
    return ct;
  }

  /**
   * Scan configuration parameters of the factory and parse elements
   * describing data-types into this container.
   */
  decode(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_TYPEGRP);
    while (decoder.peekElement() !== 0)
      this.decodeTypeNoRef(decoder, false);
    decoder.closeElement(elemId);
  }

  /**
   * Parse data-type elements into this container. This stream is presumed to contain
   * "core" datatypes and the cached matrix will be populated from this set.
   */
  decodeCoreTypes(decoder: Decoder): void {
    this.clear(); // Make sure this routine flushes

    const elemId = decoder.openElementId(ELEM_CORETYPES);
    while (decoder.peekElement() !== 0)
      this.decodeTypeNoRef(decoder, true);
    decoder.closeElement(elemId);
    this.cacheCoreTypes();
  }

  /**
   * Recover various sizes relevant to this container, such as
   * the default size of "int" and structure alignment, by parsing
   * a <data_organization> element.
   */
  decodeDataOrganization(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_DATA_ORGANIZATION);
    for (;;) {
      const subId = decoder.openElement();
      if (subId === 0) break;
      if (subId === ELEM_INTEGER_SIZE.getId()) {
        this.sizeOfInt = decoder.readSignedIntegerById(ATTRIB_VALUE);
      } else if (subId === ELEM_LONG_SIZE.getId()) {
        this.sizeOfLong = decoder.readSignedIntegerById(ATTRIB_VALUE);
      } else if (subId === ELEM_POINTER_SIZE.getId()) {
        this.sizeOfPointer = decoder.readSignedIntegerById(ATTRIB_VALUE);
      } else if (subId === ELEM_CHAR_SIZE.getId()) {
        this.sizeOfChar = decoder.readSignedIntegerById(ATTRIB_VALUE);
      } else if (subId === ELEM_WCHAR_SIZE.getId()) {
        this.sizeOfWChar = decoder.readSignedIntegerById(ATTRIB_VALUE);
      } else if (subId === ELEM_SIZE_ALIGNMENT_MAP.getId()) {
        this.decodeAlignmentMap(decoder);
      } else {
        decoder.closeElementSkipping(subId);
        continue;
      }
      decoder.closeElement(subId);
    }
    decoder.closeElement(elemId);
  }

  /**
   * Recover the map from data-type size to preferred alignment.
   */
  private decodeAlignmentMap(decoder: Decoder): void {
    this.alignMap = [];
    for (;;) {
      const mapId = decoder.openElement();
      if (mapId !== ELEM_ENTRY.getId()) break;
      const sz = decoder.readSignedIntegerById(ATTRIB_SIZE);
      const val = decoder.readSignedIntegerById(ATTRIB_ALIGNMENT);
      while (this.alignMap.length <= sz)
        this.alignMap.push(-1);
      this.alignMap[sz] = val;
      decoder.closeElement(mapId);
    }
    if (this.alignMap.length === 0)
      throw new LowlevelError("Alignment map empty");
    this.alignMap[0] = 1;
    let curAlign = 1;
    for (let sz = 1; sz < this.alignMap.length; ++sz) {
      const tmpAlign = this.alignMap[sz];
      if (tmpAlign === -1)
        this.alignMap[sz] = curAlign; // Copy alignment from nearest explicitly set value
      else
        curAlign = tmpAlign;
    }
  }

  /**
   * Set default alignment map, used if the compiler spec does not contain
   * a <size_alignment_map> element.
   */
  private setDefaultAlignmentMap(): void {
    this.alignMap = [1, 1, 2, 2, 4, 4, 4, 4, 8];
  }

  /**
   * Recover default enumeration properties (size and meta-type) from
   * an <enum> element.
   */
  parseEnumConfig(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_ENUM);
    this.enumsize = decoder.readSignedIntegerById(ATTRIB_SIZE);
    if (decoder.readBoolById(ATTRIB_SIGNED))
      this.enumtype = type_metatype.TYPE_ENUM_INT;
    else
      this.enumtype = type_metatype.TYPE_ENUM_UINT;
    decoder.closeElement(elemId);
  }

  // -- Warning iteration --------------------------------------------------

  beginWarnings(): IterableIterator<DatatypeWarning> {
    return this.warnings[Symbol.iterator]();
  }

  getWarnings(): DatatypeWarning[] {
    return this.warnings;
  }
}
