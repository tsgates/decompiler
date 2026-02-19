/**
 * @file cpool.ts
 * @description Definitions to support a constant pool for deferred compilation languages
 * (i.e. Java byte-code), translated from cpool.hh/cpool.cc
 */

import type { int4, uint4, uint1, uintb } from '../core/types.js';
import { LowlevelError } from '../core/error.js';
import {
  AttributeId,
  ElementId,
  Encoder,
  Decoder,
  ATTRIB_CONTENT,
  ATTRIB_CONSTRUCTOR,
  ATTRIB_DESTRUCTOR,
  ELEM_DATA,
  ELEM_VALUE,
} from '../core/marshal.js';
import { Datatype } from './type.js';

// ---------------------------------------------------------------------------
// Forward type declarations for types not defined in this file
// ---------------------------------------------------------------------------

type TypeFactory = any;

// ---------------------------------------------------------------------------
// Local AttributeId / ElementId constants
// ---------------------------------------------------------------------------

export const ATTRIB_A       = new AttributeId('a', 80);
export const ATTRIB_B       = new AttributeId('b', 81);
export const ATTRIB_LENGTH  = new AttributeId('length', 82);
export const ATTRIB_TAG     = new AttributeId('tag', 83);

export const ELEM_CONSTANTPOOL = new ElementId('constantpool', 109);
export const ELEM_CPOOLREC     = new ElementId('cpoolrec', 110);
export const ELEM_REF          = new ElementId('ref', 111);
export const ELEM_TOKEN        = new ElementId('token', 112);

// =========================================================================
// CPoolRecord
// =========================================================================

/**
 * A description of a byte-code object referenced by a constant.
 *
 * Byte-code languages can make use of objects that the system knows about
 * but which aren't fully embedded in the encoding of instructions that use them.
 * Instead the instruction refers to the object via a special encoded reference. This class
 * describes one object described by such a reference. In order to provide a concrete
 * interpretation of the instruction (i.e. a p-code translation), these objects generally
 * resolve to some sort of constant value (hence the term constant pool).
 */
export class CPoolRecord {
  // --- Generic constant pool tag types ---
  static readonly primitive       = 0;
  static readonly string_literal  = 1;
  static readonly class_reference = 2;
  static readonly pointer_method  = 3;
  static readonly pointer_field   = 4;
  static readonly array_length    = 5;
  static readonly instance_of     = 6;
  static readonly check_cast      = 7;

  // --- Flag bits ---
  static readonly is_constructor = 0x1;
  static readonly is_destructor  = 0x2;

  // --- Fields (package-private for ConstantPool access) ---
  tag: uint4 = 0;
  flags: uint4 = 0;
  token: string = '';
  value: uintb = 0n;
  type: Datatype | null = null;
  byteData: Uint8Array | null = null;
  byteDataLen: int4 = 0;

  /** Construct an empty record */
  constructor() {
    // defaults set above
  }

  /** Get the type of record */
  getTag(): uint4 { return this.tag; }

  /** Get name of method or data-type */
  getToken(): string { return this.token; }

  /** Get pointer to string literal data */
  getByteData(): Uint8Array | null { return this.byteData; }

  /** Number of bytes of string literal data */
  getByteDataLength(): int4 { return this.byteDataLen; }

  /** Get the data-type associated with this record */
  getType(): Datatype | null { return this.type; }

  /** Get the constant value associated with this record */
  getValue(): uintb { return this.value; }

  /** Is object a constructor method */
  isConstructor(): boolean { return (this.flags & CPoolRecord.is_constructor) !== 0; }

  /** Is object a destructor method */
  isDestructor(): boolean { return (this.flags & CPoolRecord.is_destructor) !== 0; }

  /**
   * Encode this record to a stream as a <cpoolrec> element.
   * @param encoder is the stream encoder
   */
  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_CPOOLREC);
    if (this.tag === CPoolRecord.pointer_method)
      encoder.writeString(ATTRIB_TAG, 'method');
    else if (this.tag === CPoolRecord.pointer_field)
      encoder.writeString(ATTRIB_TAG, 'field');
    else if (this.tag === CPoolRecord.instance_of)
      encoder.writeString(ATTRIB_TAG, 'instanceof');
    else if (this.tag === CPoolRecord.array_length)
      encoder.writeString(ATTRIB_TAG, 'arraylength');
    else if (this.tag === CPoolRecord.check_cast)
      encoder.writeString(ATTRIB_TAG, 'checkcast');
    else if (this.tag === CPoolRecord.string_literal)
      encoder.writeString(ATTRIB_TAG, 'string');
    else if (this.tag === CPoolRecord.class_reference)
      encoder.writeString(ATTRIB_TAG, 'classref');
    else
      encoder.writeString(ATTRIB_TAG, 'primitive');

    if (this.isConstructor())
      encoder.writeBool(ATTRIB_CONSTRUCTOR, true);
    if (this.isDestructor())
      encoder.writeBool(ATTRIB_DESTRUCTOR, true);

    if (this.tag === CPoolRecord.primitive) {
      encoder.openElement(ELEM_VALUE);
      encoder.writeUnsignedInteger(ATTRIB_CONTENT, this.value);
      encoder.closeElement(ELEM_VALUE);
    }

    if (this.byteData !== null) {
      encoder.openElement(ELEM_DATA);
      encoder.writeSignedInteger(ATTRIB_LENGTH, this.byteDataLen);
      let wrap = 0;
      let s = '';
      for (let i = 0; i < this.byteDataLen; ++i) {
        s += this.byteData[i].toString(16).padStart(2, '0') + ' ';
        wrap += 1;
        if (wrap > 15) {
          s += '\n';
          wrap = 0;
        }
      }
      encoder.writeString(ATTRIB_CONTENT, s);
      encoder.closeElement(ELEM_DATA);
    } else {
      encoder.openElement(ELEM_TOKEN);
      encoder.writeString(ATTRIB_CONTENT, this.token);
      encoder.closeElement(ELEM_TOKEN);
    }

    this.type!.encodeRef(encoder);
    encoder.closeElement(ELEM_CPOOLREC);
  }

  /**
   * Initialize this CPoolRecord from a <cpoolrec> element.
   * @param decoder is the stream decoder
   * @param typegrp is the TypeFactory used to resolve data-types
   */
  decode(decoder: Decoder, typegrp: TypeFactory): void {
    this.tag = CPoolRecord.primitive; // Default tag
    this.value = 0n;
    this.flags = 0;

    const elemId = decoder.openElementId(ELEM_CPOOLREC);

    for (;;) {
      const attribId = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_TAG.getId()) {
        const tagstring = decoder.readString();
        if (tagstring === 'method')
          this.tag = CPoolRecord.pointer_method;
        else if (tagstring === 'field')
          this.tag = CPoolRecord.pointer_field;
        else if (tagstring === 'instanceof')
          this.tag = CPoolRecord.instance_of;
        else if (tagstring === 'arraylength')
          this.tag = CPoolRecord.array_length;
        else if (tagstring === 'checkcast')
          this.tag = CPoolRecord.check_cast;
        else if (tagstring === 'string')
          this.tag = CPoolRecord.string_literal;
        else if (tagstring === 'classref')
          this.tag = CPoolRecord.class_reference;
      } else if (attribId === ATTRIB_CONSTRUCTOR.getId()) {
        if (decoder.readBool())
          this.flags |= CPoolRecord.is_constructor;
      } else if (attribId === ATTRIB_DESTRUCTOR.getId()) {
        if (decoder.readBool())
          this.flags |= CPoolRecord.is_destructor;
      }
    }

    if (this.tag === CPoolRecord.primitive) {
      // First child must be <value>
      const subId = decoder.openElementId(ELEM_VALUE);
      this.value = decoder.readUnsignedIntegerById(ATTRIB_CONTENT);
      decoder.closeElement(subId);
    }

    const subId = decoder.openElement();
    if (subId === ELEM_TOKEN.getId()) {
      this.token = decoder.readStringById(ATTRIB_CONTENT);
    } else {
      this.byteDataLen = decoder.readSignedIntegerById(ATTRIB_LENGTH);
      const hexStr = decoder.readStringById(ATTRIB_CONTENT);
      this.byteData = new Uint8Array(this.byteDataLen);
      // Parse hex pairs from the string
      const parts = hexStr.trim().split(/\s+/);
      for (let i = 0; i < this.byteDataLen; ++i) {
        this.byteData[i] = parseInt(parts[i], 16);
      }
    }
    decoder.closeElement(subId);

    if (this.tag === CPoolRecord.string_literal && this.byteData === null)
      throw new LowlevelError('Bad constant pool record: missing <data>');

    if (this.flags !== 0) {
      const isConstr = (this.flags & CPoolRecord.is_constructor) !== 0;
      const isDestr = (this.flags & CPoolRecord.is_destructor) !== 0;
      this.type = typegrp.decodeTypeWithCodeFlags(decoder, isConstr, isDestr);
    } else {
      this.type = typegrp.decodeType(decoder);
    }

    decoder.closeElement(elemId);
  }
}

// =========================================================================
// ConstantPool (abstract base)
// =========================================================================

/**
 * An interface to the pool of constant objects for byte-code languages.
 *
 * This is an abstract base class that acts as a container for CPoolRecords.
 * A reference (1 or more integer constants) maps to an individual CPoolRecord.
 */
export abstract class ConstantPool {
  /**
   * Allocate a new CPoolRecord object, given a reference to it.
   * The object will still need to be initialized but is already associated with the reference.
   * Any issue with allocation (like a duplicate reference) causes an exception.
   * @param refs is the reference of 1 or more identifying integers
   * @returns the new CPoolRecord
   */
  protected abstract createRecord(refs: uintb[]): CPoolRecord;

  /**
   * Retrieve a constant pool record (CPoolRecord) given a reference to it.
   * @param refs is the reference (made up of 1 or more identifying integers)
   * @returns the matching CPoolRecord or null if none matches the reference
   */
  abstract getRecord(refs: uintb[]): CPoolRecord | null;

  /**
   * Add a new constant pool record to this database.
   * Given the basic constituents of the record, type, name, and data-type, create
   * a new CPoolRecord object and associate it with the given reference.
   * @param refs is the reference (made up of 1 or more identifying integers)
   * @param tag is the type of record to create
   * @param tok is the name associated with the object
   * @param ct is the data-type associated with the object
   */
  putRecord(refs: uintb[], tag: uint4, tok: string, ct: Datatype): void {
    const newrec = this.createRecord(refs);
    newrec.tag = tag;
    newrec.token = tok;
    newrec.type = ct;
  }

  /**
   * Restore a CPoolRecord given a reference and a stream decoder.
   * A <cpoolrec> element initializes the new record which is immediately associated
   * with the reference.
   * @param refs is the reference (made up of 1 or more identifying integers)
   * @param decoder is the given stream decoder
   * @param typegrp is the TypeFactory used to resolve data-type references
   * @returns the newly allocated and initialized CPoolRecord
   */
  decodeRecord(refs: uintb[], decoder: Decoder, typegrp: TypeFactory): CPoolRecord {
    const newrec = this.createRecord(refs);
    newrec.decode(decoder, typegrp);
    return newrec;
  }

  /** Is the container empty of records */
  abstract empty(): boolean;

  /** Release any (local) resources */
  abstract clear(): void;

  /**
   * Encode all records in this container to a stream.
   * (If supported) A <constantpool> element is written containing <cpoolrec>
   * child elements for each CPoolRecord in the container.
   * @param encoder is the stream encoder
   */
  abstract encode(encoder: Encoder): void;

  /**
   * Restore constant pool records from the given stream decoder.
   * (If supported) The container is populated with CPoolRecords initialized
   * from a <constantpool> element.
   * @param decoder is the given stream decoder
   * @param typegrp is the TypeFactory used to resolve data-type references
   */
  abstract decode(decoder: Decoder, typegrp: TypeFactory): void;
}

// =========================================================================
// CheapSorter (helper for ConstantPoolInternal)
// =========================================================================

/**
 * A cheap (efficient) placeholder for a reference to a constant pool record.
 *
 * A reference can be an open-ended number of (1 or more) integers. In practice,
 * the most integers we see in a reference is two. So this is a slightly more
 * efficient container than an open-ended array.
 *
 * The field `a` is the first integer, the field `b` is the second integer, or zero
 * if there is no second integer. The references are ordered lexicographically.
 */
class CheapSorter {
  a: uintb;
  b: uintb;

  constructor(refs?: uintb[]) {
    if (refs !== undefined) {
      this.a = refs[0];
      this.b = refs.length > 1 ? refs[1] : 0n;
    } else {
      this.a = 0n;
      this.b = 0n;
    }
  }

  /** Generate a string key for use in a Map (lexicographic ordering) */
  toKey(): string {
    return `${this.a}:${this.b}`;
  }

  /** Lexicographic comparison: return negative if this < op2, 0 if equal, positive if this > op2 */
  compareTo(op2: CheapSorter): number {
    if (this.a !== op2.a) return this.a < op2.a ? -1 : 1;
    if (this.b !== op2.b) return this.b < op2.b ? -1 : 1;
    return 0;
  }

  /** Convert the reference back to a formal array of integers */
  apply(refs: uintb[]): void {
    refs.push(this.a);
    refs.push(this.b);
  }

  /** Encode the reference to a stream as a <ref> element */
  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_REF);
    encoder.writeUnsignedInteger(ATTRIB_A, this.a);
    encoder.writeUnsignedInteger(ATTRIB_B, this.b);
    encoder.closeElement(ELEM_REF);
  }

  /** Decode the reference from a stream <ref> element */
  decode(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_REF);
    this.a = decoder.readUnsignedIntegerById(ATTRIB_A);
    this.b = decoder.readUnsignedIntegerById(ATTRIB_B);
    decoder.closeElement(elemId);
  }
}

// =========================================================================
// ConstantPoolInternal
// =========================================================================

/**
 * An implementation of the ConstantPool interface storing records internally in RAM.
 *
 * The CPoolRecord objects are held directly in a map container. This class can be used
 * as a stand-alone ConstantPool that holds all its records in RAM. Or, it can act as
 * a local CPoolRecord cache for some other implementation.
 */
export class ConstantPoolInternal extends ConstantPool {
  /** A map from reference key to [sorter, record] pairs */
  private cpoolMap: Map<string, { sorter: CheapSorter; record: CPoolRecord }> = new Map();

  protected createRecord(refs: uintb[]): CPoolRecord {
    const sorter = new CheapSorter(refs);
    const key = sorter.toKey();
    if (this.cpoolMap.has(key)) {
      throw new LowlevelError(
        'Creating duplicate entry in constant pool: ' + this.cpoolMap.get(key)!.record.getToken()
      );
    }
    const record = new CPoolRecord();
    this.cpoolMap.set(key, { sorter, record });
    return record;
  }

  getRecord(refs: uintb[]): CPoolRecord | null {
    const sorter = new CheapSorter(refs);
    const key = sorter.toKey();
    const entry = this.cpoolMap.get(key);
    if (entry === undefined) return null;
    return entry.record;
  }

  empty(): boolean {
    return this.cpoolMap.size === 0;
  }

  clear(): void {
    this.cpoolMap.clear();
  }

  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_CONSTANTPOOL);
    for (const [, entry] of this.cpoolMap) {
      entry.sorter.encode(encoder);
      entry.record.encode(encoder);
    }
    encoder.closeElement(ELEM_CONSTANTPOOL);
  }

  decode(decoder: Decoder, typegrp: TypeFactory): void {
    const elemId = decoder.openElementId(ELEM_CONSTANTPOOL);
    while (decoder.peekElement() !== 0) {
      const sorter = new CheapSorter();
      sorter.decode(decoder);
      const refs: uintb[] = [];
      sorter.apply(refs);
      const newrec = this.createRecord(refs);
      newrec.decode(decoder, typegrp);
    }
    decoder.closeElement(elemId);
  }
}
