/**
 * @file marshal.ts
 * @description Infrastructure for marshaling data to/from streams, translated from marshal.hh/cc.
 *
 * Provides AttributeId/ElementId annotation classes, abstract Encoder/Decoder interfaces,
 * and concrete XML-based implementations (XmlEncode, XmlDecode).
 */

import { DecoderError, LowlevelError } from './error.js';
import { OpCode, get_opcode } from './opcodes.js';
import {
  xml_tree as xml_tree_impl,
  xml_escape as xml_escape_impl,
  Element as XmlElement,
  Document as XmlDocument,
} from './xml.js';

// Forward reference types -- full implementations will be provided by their respective modules.
// AddrSpace and AddrSpaceManager are not yet translated.
/** Forward-declared address space (full definition in space.ts) */
export type AddrSpace = {
  getName(): string;
  getIndex(): number;
  getType(): number;
  isFormalStackSpace(): boolean;
};

/** Forward-declared address space manager (full definition in translate.ts) */
export type AddrSpaceManager = {
  getSpaceByName(nm: string): AddrSpace | null;
  getSpace(idx: number): AddrSpace | null;
  getStackSpace(): AddrSpace;
  getJoinSpace(): AddrSpace;
};

// ---------------------------------------------------------------------------
// XML types -- re-exported from xml.ts
// ---------------------------------------------------------------------------

/** An XML element node in the DOM tree */
export type Element = XmlElement;

/** An in-memory XML document */
export type Document = XmlDocument;

/**
 * Parse an XML string into a Document.
 * Delegates to the real parser in xml.ts.
 */
export function xml_tree(input: string): Document {
  return xml_tree_impl(input);
}

/** Escape special XML characters in a string */
export function xml_escape(str: string): string {
  return xml_escape_impl(str);
}

/** Read an XML attribute value as a boolean (recognises "true", "1", "yes") */
function xml_readbool(attr: string): boolean {
  if (attr.length === 0) return false;
  const c = attr[0];
  return c === 't' || c === '1' || c === 'y';
}

// =========================================================================
// AttributeId
// =========================================================================

/** Lookup table from attribute name to id (scope 0 only) */
const lookupAttributeId = new Map<string, number>();

/**
 * An annotation for a data element to being transferred to/from a stream.
 *
 * Parallels the XML concept of an attribute on an element. An AttributeId describes
 * a particular piece of data associated with an ElementId. The defining characteristic
 * is its name, which is internally associated with an integer id.
 */
export class AttributeId {
  private static registrationList: AttributeId[] = [];
  private static initialized = false;

  readonly name: string;
  readonly id: number;

  constructor(nm: string, i: number, scope: number = 0) {
    this.name = nm;
    this.id = i;
    if (scope === 0) {
      if (AttributeId.initialized) {
        // Already initialized -- add directly to lookup map
        lookupAttributeId.set(nm, i);
      } else {
        AttributeId.registrationList.push(this);
      }
    }
  }

  /** Get the attribute's name */
  getName(): string { return this.name; }

  /** Get the attribute's id */
  getId(): number { return this.id; }

  /** Test equality with another AttributeId or raw id */
  equals(other: AttributeId | number): boolean {
    if (typeof other === 'number') return this.id === other;
    return this.id === other.id;
  }

  /**
   * Find the id associated with a specific attribute name.
   * Returns ATTRIB_UNKNOWN's id if not found.
   */
  static find(nm: string, scope: number): number {
    if (scope === 0) {
      const id = lookupAttributeId.get(nm);
      if (id !== undefined) return id;
    }
    return ATTRIB_UNKNOWN.id;
  }

  /** Populate the hashtable with all registered AttributeId objects */
  static initialize(): void {
    if (AttributeId.initialized) return;
    for (const attrib of AttributeId.registrationList) {
      lookupAttributeId.set(attrib.name, attrib.id);
    }
    AttributeId.registrationList.length = 0;
    AttributeId.initialized = true;
  }
}

// =========================================================================
// ElementId
// =========================================================================

/** Lookup table from element name to id (scope 0 only) */
const lookupElementId = new Map<string, number>();

/**
 * An annotation for a specific collection of hierarchical data.
 *
 * Parallels the XML concept of an element. An ElementId describes a collection of data,
 * where each piece is annotated by a specific AttributeId. Each ElementId can contain
 * zero or more child ElementId objects forming a hierarchy.
 */
export class ElementId {
  private static registrationList: ElementId[] = [];
  private static initialized = false;

  readonly name: string;
  readonly id: number;

  constructor(nm: string, i: number, scope: number = 0) {
    this.name = nm;
    this.id = i;
    if (scope === 0) {
      if (ElementId.initialized) {
        // Already initialized -- add directly to lookup map
        lookupElementId.set(nm, i);
      } else {
        ElementId.registrationList.push(this);
      }
    }
  }

  /** Get the element's name */
  getName(): string { return this.name; }

  /** Get the element's id */
  getId(): number { return this.id; }

  /** Test equality with another ElementId or raw id */
  equals(other: ElementId | number): boolean {
    if (typeof other === 'number') return this.id === other;
    return this.id === other.id;
  }

  /**
   * Find the id associated with a specific element name.
   * Returns ELEM_UNKNOWN's id if not found.
   */
  static find(nm: string, scope: number): number {
    if (scope === 0) {
      const id = lookupElementId.get(nm);
      if (id !== undefined) return id;
    }
    return ELEM_UNKNOWN.id;
  }

  /** Populate the hashtable with all registered ElementId objects */
  static initialize(): void {
    if (ElementId.initialized) return;
    for (const elem of ElementId.registrationList) {
      lookupElementId.set(elem.name, elem.id);
    }
    ElementId.registrationList.length = 0;
    ElementId.initialized = true;
  }
}

// =========================================================================
// Well-known AttributeId instances (from marshal.cc)
// =========================================================================

// Common attributes -- attributes with multiple uses
export const ATTRIB_CONTENT      = new AttributeId('XMLcontent', 1);
export const ATTRIB_ALIGN        = new AttributeId('align', 2);
export const ATTRIB_BIGENDIAN    = new AttributeId('bigendian', 3);
export const ATTRIB_CONSTRUCTOR  = new AttributeId('constructor', 4);
export const ATTRIB_DESTRUCTOR   = new AttributeId('destructor', 5);
export const ATTRIB_EXTRAPOP     = new AttributeId('extrapop', 6);
export const ATTRIB_FORMAT       = new AttributeId('format', 7);
export const ATTRIB_HIDDENRETPARM = new AttributeId('hiddenretparm', 8);
export const ATTRIB_ID           = new AttributeId('id', 9);
export const ATTRIB_INDEX        = new AttributeId('index', 10);
export const ATTRIB_INDIRECTSTORAGE = new AttributeId('indirectstorage', 11);
export const ATTRIB_METATYPE     = new AttributeId('metatype', 12);
export const ATTRIB_MODEL        = new AttributeId('model', 13);
export const ATTRIB_NAME         = new AttributeId('name', 14);
export const ATTRIB_NAMELOCK     = new AttributeId('namelock', 15);
export const ATTRIB_OFFSET       = new AttributeId('offset', 16);
export const ATTRIB_READONLY     = new AttributeId('readonly', 17);
export const ATTRIB_REF          = new AttributeId('ref', 18);
export const ATTRIB_SIZE         = new AttributeId('size', 19);
export const ATTRIB_SPACE        = new AttributeId('space', 20);
export const ATTRIB_THISPTR      = new AttributeId('thisptr', 21);
export const ATTRIB_TYPE         = new AttributeId('type', 22);
export const ATTRIB_TYPELOCK     = new AttributeId('typelock', 23);
export const ATTRIB_VAL          = new AttributeId('val', 24);
export const ATTRIB_VALUE        = new AttributeId('value', 25);
export const ATTRIB_WORDSIZE     = new AttributeId('wordsize', 26);
export const ATTRIB_STORAGE      = new AttributeId('storage', 149);
export const ATTRIB_STACKSPILL   = new AttributeId('stackspill', 150);

/** Special attribute for unrecognized names (id 159 serves as next open index) */
export const ATTRIB_UNKNOWN      = new AttributeId('XMLunknown', 159);

// =========================================================================
// Well-known ElementId instances (from marshal.cc)
// =========================================================================

export const ELEM_DATA           = new ElementId('data', 1);
export const ELEM_INPUT          = new ElementId('input', 2);
export const ELEM_OFF            = new ElementId('off', 3);
export const ELEM_OUTPUT         = new ElementId('output', 4);
export const ELEM_RETURNADDRESS  = new ElementId('returnaddress', 5);
export const ELEM_SYMBOL         = new ElementId('symbol', 6);
export const ELEM_TARGET         = new ElementId('target', 7);
export const ELEM_VAL            = new ElementId('val', 8);
export const ELEM_VALUE          = new ElementId('value', 9);
export const ELEM_VOID           = new ElementId('void', 10);

/** Special element for unrecognized names (id 289 serves as next open index) */
export const ELEM_UNKNOWN        = new ElementId('XMLunknown', 289);

// =========================================================================
// Encoder (abstract)
// =========================================================================

/**
 * A class for writing structured data to a stream.
 *
 * The resulting encoded data is structured similarly to an XML document. The document
 * contains a nested set of elements, with labels corresponding to the ElementId class.
 * A single element can hold zero or more attributes and zero or more child elements.
 */
export abstract class Encoder {
  /** Begin a new element in the encoding */
  abstract openElement(elemId: ElementId): void;

  /** End the current element in the encoding */
  abstract closeElement(elemId: ElementId): void;

  /** Write an annotated boolean value into the encoding */
  abstract writeBool(attribId: AttributeId, val: boolean): void;

  /** Write an annotated signed integer value into the encoding */
  abstract writeSignedInteger(attribId: AttributeId, val: number): void;

  /** Write an annotated unsigned integer value into the encoding */
  abstract writeUnsignedInteger(attribId: AttributeId, val: bigint): void;

  /** Write an annotated string into the encoding */
  abstract writeString(attribId: AttributeId, val: string): void;

  /** Write an annotated string, using an indexed attribute, into the encoding */
  abstract writeStringIndexed(attribId: AttributeId, index: number, val: string): void;

  /** Write an address space reference into the encoding */
  abstract writeSpace(attribId: AttributeId, spc: AddrSpace): void;
}

// =========================================================================
// Decoder (abstract)
// =========================================================================

/**
 * A class for reading structured data from a stream.
 *
 * All data is loosely structured as with an XML document. A document contains a nested
 * set of elements, with labels corresponding to the ElementId class.
 */
export abstract class Decoder {
  protected spcManager: AddrSpaceManager | null;

  constructor(spc: AddrSpaceManager | null) {
    this.spcManager = spc;
  }

  /** Get the manager used for address space decoding */
  getAddrSpaceManager(): AddrSpaceManager | null { return this.spcManager; }

  /** Prepare to decode a given stream */
  abstract ingestStream(s: string): void;

  /** Peek at the next child element of the current parent, without traversing in (opening) it */
  abstract peekElement(): number;

  /** Open (traverse into) the next child element of the current parent.
   *  If elemId is provided, dispatches to openElementId. */
  abstract openElement(elemId?: ElementId): number;

  /** Open (traverse into) the next child element, which must be of a specific type */
  abstract openElementId(elemId: ElementId): number;

  /** Close the current element */
  abstract closeElement(id: number): void;

  /** Close the current element, skipping any child elements that have not yet been parsed */
  abstract closeElementSkipping(id: number): void;

  /** Get the next attribute id for the current element (0 when done) */
  abstract getNextAttributeId(): number;

  /**
   * Get the id for the (current) attribute, assuming it is indexed.
   * If the attribute matches, return the indexed id, otherwise return ATTRIB_UNKNOWN's id.
   */
  abstract getIndexedAttributeId(attribId: AttributeId): number;

  /** Reset attribute traversal for the current element */
  abstract rewindAttributes(): void;

  /** Parse the current attribute as a boolean value.
   *  If attribId is provided, dispatches to readBoolById. */
  abstract readBool(attribId?: AttributeId): boolean;

  /** Find and parse a specific attribute in the current element as a boolean value */
  abstract readBoolById(attribId: AttributeId): boolean;

  /** Parse the current attribute as a signed integer value.
   *  If attribId is provided, dispatches to readSignedIntegerById. */
  abstract readSignedInteger(attribId?: AttributeId): number;

  /** Find and parse a specific attribute in the current element as a signed integer */
  abstract readSignedIntegerById(attribId: AttributeId): number;

  /**
   * Parse the current attribute as either a signed integer value or a string.
   * If the attribute matches the expected string, return expectval.
   */
  abstract readSignedIntegerExpectString(expect: string, expectval: number): number;

  /**
   * Find and parse a specific attribute as either a signed integer or a string.
   */
  abstract readSignedIntegerExpectStringById(attribId: AttributeId, expect: string, expectval: number): number;

  /** Parse the current attribute as an unsigned integer value.
   *  If attribId is provided, dispatches to readUnsignedIntegerById. */
  abstract readUnsignedInteger(attribId?: AttributeId): bigint;

  /** Find and parse a specific attribute in the current element as an unsigned integer */
  abstract readUnsignedIntegerById(attribId: AttributeId): bigint;

  /** Parse the current attribute as a string.
   *  If attribId is provided, dispatches to readStringById. */
  abstract readString(attribId?: AttributeId): string;

  /** Find the specific attribute in the current element and return it as a string */
  abstract readStringById(attribId: AttributeId): string;

  /** Parse the current attribute as an address space.
   *  If attribId is provided, dispatches to readSpaceById. */
  abstract readSpace(attribId?: AttributeId): AddrSpace;

  /** Find the specific attribute in the current element and return it as an address space */
  abstract readSpaceById(attribId: AttributeId): AddrSpace;

  /** Parse the current attribute as an OpCode value.
   *  If attribId is provided, dispatches to readOpcodeById. */
  abstract readOpcode(attribId?: AttributeId): OpCode;

  /** Find the specific attribute in the current element and return it as an OpCode */
  abstract readOpcodeById(attribId: AttributeId): OpCode;

  /** Skip parsing of the next element */
  skipElement(): void {
    const elemId = this.openElement();
    this.closeElementSkipping(elemId);
  }
}

// =========================================================================
// XmlEncode
// =========================================================================

const enum TagStatus {
  TAG_START = 0,     // Tag has been opened, attributes can be written
  TAG_CONTENT = 1,   // Opening tag and content have been written
  TAG_STOP = 2       // No tag is currently being written
}

const MAX_SPACES = 25;  // newline + 24 spaces
const SPACES = '\n' + ' '.repeat(24);

/**
 * An XML-based encoder.
 *
 * The underlying transfer encoding is an XML document. The encoder is initialized
 * with a string array buffer which will receive the XML output as calls are made.
 */
export class XmlEncode extends Encoder {
  private outParts: string[] = [];
  private tagStatus: TagStatus = TagStatus.TAG_STOP;
  private depth: number = 0;
  private doFormatting: boolean;

  constructor(doFormat: boolean = true) {
    super();
    this.doFormatting = doFormat;
  }

  private newLine(): void {
    if (!this.doFormatting) return;
    let numSpaces = this.depth * 2 + 1; // +1 for the leading newline char
    if (numSpaces > MAX_SPACES) {
      numSpaces = MAX_SPACES;
    }
    this.outParts.push(SPACES.substring(0, numSpaces));
  }

  openElement(elemId: ElementId): void {
    if (this.tagStatus === TagStatus.TAG_START) {
      this.outParts.push('>');
    } else {
      this.tagStatus = TagStatus.TAG_START;
    }
    this.newLine();
    this.outParts.push('<');
    this.outParts.push(elemId.getName());
    this.depth += 1;
  }

  closeElement(elemId: ElementId): void {
    this.depth -= 1;
    if (this.tagStatus === TagStatus.TAG_START) {
      this.outParts.push('/>');
      this.tagStatus = TagStatus.TAG_STOP;
      return;
    }
    if (this.tagStatus !== TagStatus.TAG_CONTENT) {
      this.newLine();
    } else {
      this.tagStatus = TagStatus.TAG_STOP;
    }
    this.outParts.push('</');
    this.outParts.push(elemId.getName());
    this.outParts.push('>');
  }

  writeBool(attribId: AttributeId, val: boolean): void {
    if (attribId.equals(ATTRIB_CONTENT)) {
      if (this.tagStatus === TagStatus.TAG_START) {
        this.outParts.push('>');
      }
      this.outParts.push(val ? 'true' : 'false');
      this.tagStatus = TagStatus.TAG_CONTENT;
      return;
    }
    // a_v_b equivalent
    this.outParts.push(' ');
    this.outParts.push(attribId.getName());
    this.outParts.push('="');
    this.outParts.push(val ? 'true' : 'false');
    this.outParts.push('"');
  }

  writeSignedInteger(attribId: AttributeId, val: number): void {
    if (attribId.equals(ATTRIB_CONTENT)) {
      if (this.tagStatus === TagStatus.TAG_START) {
        this.outParts.push('>');
      }
      this.outParts.push(val.toString(10));
      this.tagStatus = TagStatus.TAG_CONTENT;
      return;
    }
    // a_v_i equivalent
    this.outParts.push(' ');
    this.outParts.push(attribId.getName());
    this.outParts.push('="');
    this.outParts.push(val.toString(10));
    this.outParts.push('"');
  }

  writeUnsignedInteger(attribId: AttributeId, val: bigint): void {
    if (attribId.equals(ATTRIB_CONTENT)) {
      if (this.tagStatus === TagStatus.TAG_START) {
        this.outParts.push('>');
      }
      this.outParts.push('0x');
      this.outParts.push(val.toString(16));
      this.tagStatus = TagStatus.TAG_CONTENT;
      return;
    }
    // a_v_u equivalent
    this.outParts.push(' ');
    this.outParts.push(attribId.getName());
    this.outParts.push('="0x');
    this.outParts.push(val.toString(16));
    this.outParts.push('"');
  }

  writeString(attribId: AttributeId, val: string): void {
    if (attribId.equals(ATTRIB_CONTENT)) {
      if (this.tagStatus === TagStatus.TAG_START) {
        this.outParts.push('>');
      }
      this.outParts.push(xml_escape(val));
      this.tagStatus = TagStatus.TAG_CONTENT;
      return;
    }
    // a_v equivalent
    this.outParts.push(' ');
    this.outParts.push(attribId.getName());
    this.outParts.push('="');
    this.outParts.push(xml_escape(val));
    this.outParts.push('"');
  }

  writeStringIndexed(attribId: AttributeId, index: number, val: string): void {
    this.outParts.push(' ');
    this.outParts.push(attribId.getName());
    this.outParts.push((index + 1).toString(10));
    this.outParts.push('="');
    this.outParts.push(xml_escape(val));
    this.outParts.push('"');
  }

  writeSpace(attribId: AttributeId, spc: AddrSpace): void {
    if (attribId.equals(ATTRIB_CONTENT)) {
      if (this.tagStatus === TagStatus.TAG_START) {
        this.outParts.push('>');
      }
      this.outParts.push(xml_escape(spc.getName()));
      this.tagStatus = TagStatus.TAG_CONTENT;
      return;
    }
    // a_v equivalent
    this.outParts.push(' ');
    this.outParts.push(attribId.getName());
    this.outParts.push('="');
    this.outParts.push(xml_escape(spc.getName()));
    this.outParts.push('"');
  }

  /** Get the accumulated XML output as a string */
  toString(): string {
    return this.outParts.join('');
  }

  /** Clear the output buffer */
  clear(): void {
    this.outParts.length = 0;
    this.tagStatus = TagStatus.TAG_STOP;
    this.depth = 0;
  }
}

// =========================================================================
// XmlDecode
// =========================================================================

/**
 * An XML based decoder.
 *
 * The underlying transfer encoding is an XML document. The decoder can either be
 * initialized with an existing Element as the root of the data to transfer, or the
 * ingestStream() method can be invoked to read the XML document from an input string.
 */
export class XmlDecode extends Decoder {
  private document: Document | null;
  private rootElement: Element | null;
  private elStack: Element[] = [];
  private iterStack: number[] = [];   // index of next child for each open element
  private attributeIndex: number = -1;
  private scope: number;

  /**
   * Constructor with a preparsed root Element.
   */
  constructor(spc: AddrSpaceManager | null, root?: Element | null, sc?: number);
  constructor(spc: AddrSpaceManager | null, root?: Element | null, sc: number = 0) {
    super(spc);
    this.document = null;
    this.rootElement = root ?? null;
    this.attributeIndex = -1;
    this.scope = sc;
  }

  /** Get pointer to underlying XML element object */
  getCurrentXmlElement(): Element {
    return this.elStack[this.elStack.length - 1];
  }

  ingestStream(s: string): void {
    this.document = xml_tree(s);
    this.rootElement = this.document.getRoot();
  }

  /**
   * Ingest a pre-parsed Document directly (avoids re-parsing).
   */
  ingestDocument(doc: Document): void {
    this.document = doc;
    this.rootElement = doc.getRoot();
  }

  /**
   * Set the root element directly (for use with pre-parsed elements).
   */
  setRootElement(root: Element): void {
    this.rootElement = root;
  }

  peekElement(): number {
    let el: Element;
    if (this.elStack.length === 0) {
      if (this.rootElement === null) return 0;
      el = this.rootElement;
    } else {
      el = this.elStack[this.elStack.length - 1];
      const iterIdx = this.iterStack[this.iterStack.length - 1];
      const children = el.getChildren();
      if (iterIdx >= children.length) return 0;
      el = children[iterIdx];
    }
    return ElementId.find(el.getName(), this.scope);
  }

  openElement(elemId?: ElementId): number {
    if (elemId !== undefined && typeof elemId === 'object' && elemId !== null) {
      return this.openElementId(elemId);
    }
    let el: Element;
    if (this.elStack.length === 0) {
      if (this.rootElement === null) return 0;
      el = this.rootElement;
      this.rootElement = null;   // Only open once
    } else {
      const parent = this.elStack[this.elStack.length - 1];
      const iterIdx = this.iterStack[this.iterStack.length - 1];
      const children = parent.getChildren();
      if (iterIdx >= children.length) return 0;
      el = children[iterIdx];
      this.iterStack[this.iterStack.length - 1] = iterIdx + 1;
    }
    this.elStack.push(el);
    this.iterStack.push(0);
    this.attributeIndex = -1;
    return ElementId.find(el.getName(), this.scope);
  }

  openElementId(elemId: ElementId): number {
    let el: Element;
    if (this.elStack.length === 0) {
      if (this.rootElement === null) {
        throw new DecoderError('Expecting <' + elemId.getName() + '> but reached end of document');
      }
      el = this.rootElement;
      this.rootElement = null;   // Only open document once
    } else {
      const parent = this.elStack[this.elStack.length - 1];
      const iterIdx = this.iterStack[this.iterStack.length - 1];
      const children = parent.getChildren();
      if (iterIdx < children.length) {
        el = children[iterIdx];
        this.iterStack[this.iterStack.length - 1] = iterIdx + 1;
      } else {
        throw new DecoderError('Expecting <' + elemId.getName() + '> but no remaining children in current element');
      }
    }
    if (el.getName() !== elemId.getName()) {
      throw new DecoderError('Expecting <' + elemId.getName() + '> but got <' + el.getName() + '>');
    }
    this.elStack.push(el);
    this.iterStack.push(0);
    this.attributeIndex = -1;
    return elemId.getId();
  }

  closeElement(id: number): void {
    this.elStack.pop();
    this.iterStack.pop();
    this.attributeIndex = 1000;   // Cannot read any additional attributes
  }

  closeElementSkipping(id: number): void {
    this.elStack.pop();
    this.iterStack.pop();
    this.attributeIndex = 1000;
  }

  rewindAttributes(): void {
    this.attributeIndex = -1;
  }

  getNextAttributeId(): number {
    const el = this.elStack[this.elStack.length - 1];
    const nextIndex = this.attributeIndex + 1;
    if (nextIndex < el.getNumAttributes()) {
      this.attributeIndex = nextIndex;
      return AttributeId.find(el.getAttributeName(this.attributeIndex), this.scope);
    }
    return 0;
  }

  getIndexedAttributeId(attribId: AttributeId): number {
    const el = this.elStack[this.elStack.length - 1];
    if (this.attributeIndex < 0 || this.attributeIndex >= el.getNumAttributes()) {
      return ATTRIB_UNKNOWN.getId();
    }
    // For XML, the index is encoded directly in the attribute name
    const attribName = el.getAttributeName(this.attributeIndex);
    const baseName = attribId.getName();
    // Does the name start with the desired attribute base name?
    if (!attribName.startsWith(baseName)) {
      return ATTRIB_UNKNOWN.getId();
    }
    const remainder = attribName.substring(baseName.length);
    const val = parseInt(remainder, 10);
    if (isNaN(val) || val === 0) {
      throw new LowlevelError('Bad indexed attribute: ' + attribId.getName());
    }
    return attribId.getId() + (val - 1);
  }

  /**
   * Find the attribute index within the given element for the given name.
   * Throws DecoderError if not found.
   */
  private findMatchingAttribute(el: Element, attribName: string): number {
    for (let i = 0; i < el.getNumAttributes(); i++) {
      if (el.getAttributeName(i) === attribName) return i;
    }
    throw new DecoderError('Attribute missing: ' + attribName);
  }

  readBool(attribId?: AttributeId): boolean {
    if (attribId !== undefined && typeof attribId === 'object') {
      return this.readBoolById(attribId);
    }
    const el = this.elStack[this.elStack.length - 1];
    return xml_readbool(el.getAttributeValue(this.attributeIndex));
  }

  readBoolById(attribId: AttributeId): boolean {
    const el = this.elStack[this.elStack.length - 1];
    if (attribId.equals(ATTRIB_CONTENT)) {
      return xml_readbool(el.getContent());
    }
    const index = this.findMatchingAttribute(el, attribId.getName());
    return xml_readbool(el.getAttributeValue(index));
  }

  readSignedInteger(attribId?: AttributeId): number {
    if (attribId !== undefined && typeof attribId === 'object') {
      return this.readSignedIntegerById(attribId);
    }
    const el = this.elStack[this.elStack.length - 1];
    return parseIntAutoRadix(el.getAttributeValue(this.attributeIndex));
  }

  readSignedIntegerById(attribId: AttributeId): number {
    const el = this.elStack[this.elStack.length - 1];
    if (attribId.equals(ATTRIB_CONTENT)) {
      return parseIntAutoRadix(el.getContent());
    }
    const index = this.findMatchingAttribute(el, attribId.getName());
    return parseIntAutoRadix(el.getAttributeValue(index));
  }

  readSignedIntegerExpectString(expect: string, expectval: number): number {
    const el = this.elStack[this.elStack.length - 1];
    const value = el.getAttributeValue(this.attributeIndex);
    if (value === expect) return expectval;
    return parseIntAutoRadix(value);
  }

  readSignedIntegerExpectStringById(attribId: AttributeId, expect: string, expectval: number): number {
    const value = this.readStringById(attribId);
    if (value === expect) return expectval;
    return parseIntAutoRadix(value);
  }

  readUnsignedInteger(attribId?: AttributeId): bigint {
    if (attribId !== undefined && typeof attribId === 'object') {
      return this.readUnsignedIntegerById(attribId);
    }
    const el = this.elStack[this.elStack.length - 1];
    return parseUintAutoRadix(el.getAttributeValue(this.attributeIndex));
  }

  readUnsignedIntegerById(attribId: AttributeId): bigint {
    const el = this.elStack[this.elStack.length - 1];
    if (attribId.equals(ATTRIB_CONTENT)) {
      return parseUintAutoRadix(el.getContent());
    }
    const index = this.findMatchingAttribute(el, attribId.getName());
    return parseUintAutoRadix(el.getAttributeValue(index));
  }

  readString(attribId?: AttributeId): string {
    if (attribId !== undefined && typeof attribId === 'object') {
      return this.readStringById(attribId);
    }
    const el = this.elStack[this.elStack.length - 1];
    return el.getAttributeValue(this.attributeIndex);
  }

  readStringById(attribId: AttributeId): string {
    const el = this.elStack[this.elStack.length - 1];
    if (attribId.equals(ATTRIB_CONTENT)) {
      return el.getContent();
    }
    const index = this.findMatchingAttribute(el, attribId.getName());
    return el.getAttributeValue(index);
  }

  readSpace(attribId?: AttributeId): AddrSpace {
    if (attribId !== undefined && typeof attribId === 'object') {
      return this.readSpaceById(attribId);
    }
    const el = this.elStack[this.elStack.length - 1];
    const nm = el.getAttributeValue(this.attributeIndex);
    if (this.spcManager === null) {
      throw new DecoderError('No address space manager available');
    }
    const res = this.spcManager.getSpaceByName(nm);
    if (res === null) {
      throw new DecoderError('Unknown address space name: ' + nm);
    }
    return res;
  }

  readSpaceById(attribId: AttributeId): AddrSpace {
    const el = this.elStack[this.elStack.length - 1];
    let nm: string;
    if (attribId.equals(ATTRIB_CONTENT)) {
      nm = el.getContent();
    } else {
      const index = this.findMatchingAttribute(el, attribId.getName());
      nm = el.getAttributeValue(index);
    }
    if (this.spcManager === null) {
      throw new DecoderError('No address space manager available');
    }
    const res = this.spcManager.getSpaceByName(nm);
    if (res === null) {
      throw new DecoderError('Unknown address space name: ' + nm);
    }
    return res;
  }

  readOpcode(attribId?: AttributeId): OpCode {
    if (attribId !== undefined && typeof attribId === 'object') {
      return this.readOpcodeById(attribId);
    }
    const el = this.elStack[this.elStack.length - 1];
    const nm = el.getAttributeValue(this.attributeIndex);
    const opc = get_opcode(nm);
    if (opc === (0 as OpCode)) {
      throw new DecoderError('Bad opcode string: ' + nm);
    }
    return opc;
  }

  readOpcodeById(attribId: AttributeId): OpCode {
    const el = this.elStack[this.elStack.length - 1];
    const index = this.findMatchingAttribute(el, attribId.getName());
    const nm = el.getAttributeValue(index);
    const opc = get_opcode(nm);
    if (opc === (0 as OpCode)) {
      throw new DecoderError('Bad opcode string: ' + nm);
    }
    return opc;
  }
}

// =========================================================================
// PackedFormat constants
// =========================================================================

/** Protocol format constants for PackedEncode and PackedDecode classes */
const PackedFormat = {
  HEADER_MASK:          0xc0,  // Bits encoding the record type
  ELEMENT_START:        0x40,  // Header for an element start record
  ELEMENT_END:          0x80,  // Header for an element end record
  ATTRIBUTE:            0xc0,  // Header for an attribute record
  HEADEREXTEND_MASK:    0x20,  // Bit indicating the id extends into the next byte
  ELEMENTID_MASK:       0x1f,  // Bits encoding (part of) the id in the record header
  RAWDATA_MASK:         0x7f,  // Bits of raw data in follow-on bytes
  RAWDATA_BITSPERBYTE:  7,     // Number of bits used in a follow-on byte
  RAWDATA_MARKER:       0x80,  // The unused bit in follow-on bytes (always set to 1)
  TYPECODE_SHIFT:       4,     // Bit position of the type code in the type byte
  LENGTHCODE_MASK:      0x0f,  // Bits in the type byte forming the length code
  TYPECODE_BOOLEAN:             1,
  TYPECODE_SIGNEDINT_POSITIVE:  2,
  TYPECODE_SIGNEDINT_NEGATIVE:  3,
  TYPECODE_UNSIGNEDINT:         4,
  TYPECODE_ADDRESSSPACE:        5,
  TYPECODE_SPECIALSPACE:        6,
  TYPECODE_STRING:              7,
  SPECIALSPACE_STACK:     0,
  SPECIALSPACE_JOIN:      1,
  SPECIALSPACE_FSPEC:     2,
  SPECIALSPACE_IOP:       3,
  SPECIALSPACE_SPACEBASE: 4,
} as const;

/** Address space type constants matching C++ spacetype enum */
const IPTR_PROCESSOR = 1;
const IPTR_SPACEBASE = 2;
const IPTR_FSPEC = 4;
const IPTR_IOP = 5;
const IPTR_JOIN = 6;

// =========================================================================
// PackedEncode
// =========================================================================

/**
 * A byte-based encoder designed to marshal from the decompiler efficiently.
 *
 * The encoding format uses byte-level encoding as described in PackedFormat.
 * Element open/close markers and attribute headers encode a type and id in
 * the header bytes, followed by typed value data.
 */
export class PackedEncode extends Encoder {
  private outBytes: number[] = [];

  /** Write a header byte (element start, element end, or attribute) with the given id */
  private writeHeader(header: number, id: number): void {
    if (id > 0x1f) {
      header |= PackedFormat.HEADEREXTEND_MASK;
      header |= (id >> PackedFormat.RAWDATA_BITSPERBYTE);
      const extendByte = (id & PackedFormat.RAWDATA_MASK) | PackedFormat.RAWDATA_MARKER;
      this.outBytes.push(header & 0xff);
      this.outBytes.push(extendByte & 0xff);
    } else {
      header |= id;
      this.outBytes.push(header & 0xff);
    }
  }

  /** Write an integer value with the given type byte prefix */
  private writeInteger(typeByte: number, val: bigint): void {
    let lenCode: number;
    let sa: number;
    if (val === 0n) {
      lenCode = 0;
      sa = -1;
    } else if (val < 0x800000000n) {
      if (val < 0x200000n) {
        if (val < 0x80n) {
          lenCode = 1;
          sa = 0;
        } else if (val < 0x4000n) {
          lenCode = 2;
          sa = PackedFormat.RAWDATA_BITSPERBYTE;
        } else {
          lenCode = 3;
          sa = 2 * PackedFormat.RAWDATA_BITSPERBYTE;
        }
      } else if (val < 0x10000000n) {
        lenCode = 4;
        sa = 3 * PackedFormat.RAWDATA_BITSPERBYTE;
      } else {
        lenCode = 5;
        sa = 4 * PackedFormat.RAWDATA_BITSPERBYTE;
      }
    } else if (val < 0x2000000000000n) {
      if (val < 0x40000000000n) {
        lenCode = 6;
        sa = 5 * PackedFormat.RAWDATA_BITSPERBYTE;
      } else {
        lenCode = 7;
        sa = 6 * PackedFormat.RAWDATA_BITSPERBYTE;
      }
    } else {
      if (val < 0x100000000000000n) {
        lenCode = 8;
        sa = 7 * PackedFormat.RAWDATA_BITSPERBYTE;
      } else if (val < 0x8000000000000000n) {
        lenCode = 9;
        sa = 8 * PackedFormat.RAWDATA_BITSPERBYTE;
      } else {
        lenCode = 10;
        sa = 9 * PackedFormat.RAWDATA_BITSPERBYTE;
      }
    }
    typeByte |= lenCode;
    this.outBytes.push(typeByte & 0xff);
    for (; sa >= 0; sa -= PackedFormat.RAWDATA_BITSPERBYTE) {
      let piece = Number((val >> BigInt(sa)) & BigInt(PackedFormat.RAWDATA_MASK));
      piece |= PackedFormat.RAWDATA_MARKER;
      this.outBytes.push(piece & 0xff);
    }
  }

  openElement(elemId: ElementId): void {
    this.writeHeader(PackedFormat.ELEMENT_START, elemId.getId());
  }

  closeElement(elemId: ElementId): void {
    this.writeHeader(PackedFormat.ELEMENT_END, elemId.getId());
  }

  writeBool(attribId: AttributeId, val: boolean): void {
    this.writeHeader(PackedFormat.ATTRIBUTE, attribId.getId());
    const typeByte = val
      ? ((PackedFormat.TYPECODE_BOOLEAN << PackedFormat.TYPECODE_SHIFT) | 1)
      : (PackedFormat.TYPECODE_BOOLEAN << PackedFormat.TYPECODE_SHIFT);
    this.outBytes.push(typeByte & 0xff);
  }

  writeSignedInteger(attribId: AttributeId, val: number): void {
    this.writeHeader(PackedFormat.ATTRIBUTE, attribId.getId());
    let typeByte: number;
    let num: bigint;
    if (val < 0) {
      typeByte = (PackedFormat.TYPECODE_SIGNEDINT_NEGATIVE << PackedFormat.TYPECODE_SHIFT);
      num = BigInt(-val);
    } else {
      typeByte = (PackedFormat.TYPECODE_SIGNEDINT_POSITIVE << PackedFormat.TYPECODE_SHIFT);
      num = BigInt(val);
    }
    this.writeInteger(typeByte, num);
  }

  writeUnsignedInteger(attribId: AttributeId, val: bigint): void {
    this.writeHeader(PackedFormat.ATTRIBUTE, attribId.getId());
    this.writeInteger(PackedFormat.TYPECODE_UNSIGNEDINT << PackedFormat.TYPECODE_SHIFT, val);
  }

  writeString(attribId: AttributeId, val: string): void {
    const length = BigInt(val.length);
    this.writeHeader(PackedFormat.ATTRIBUTE, attribId.getId());
    this.writeInteger(PackedFormat.TYPECODE_STRING << PackedFormat.TYPECODE_SHIFT, length);
    // Write string bytes using latin1 encoding (one byte per char)
    for (let i = 0; i < val.length; i++) {
      this.outBytes.push(val.charCodeAt(i) & 0xff);
    }
  }

  writeStringIndexed(attribId: AttributeId, index: number, val: string): void {
    const length = BigInt(val.length);
    this.writeHeader(PackedFormat.ATTRIBUTE, attribId.getId() + index);
    this.writeInteger(PackedFormat.TYPECODE_STRING << PackedFormat.TYPECODE_SHIFT, length);
    for (let i = 0; i < val.length; i++) {
      this.outBytes.push(val.charCodeAt(i) & 0xff);
    }
  }

  writeSpace(attribId: AttributeId, spc: AddrSpace): void {
    this.writeHeader(PackedFormat.ATTRIBUTE, attribId.getId());
    const spcType = spc.getType();
    if (spcType === IPTR_FSPEC) {
      this.outBytes.push((PackedFormat.TYPECODE_SPECIALSPACE << PackedFormat.TYPECODE_SHIFT) | PackedFormat.SPECIALSPACE_FSPEC);
    } else if (spcType === IPTR_IOP) {
      this.outBytes.push((PackedFormat.TYPECODE_SPECIALSPACE << PackedFormat.TYPECODE_SHIFT) | PackedFormat.SPECIALSPACE_IOP);
    } else if (spcType === IPTR_JOIN) {
      this.outBytes.push((PackedFormat.TYPECODE_SPECIALSPACE << PackedFormat.TYPECODE_SHIFT) | PackedFormat.SPECIALSPACE_JOIN);
    } else if (spcType === IPTR_SPACEBASE) {
      if (spc.isFormalStackSpace()) {
        this.outBytes.push((PackedFormat.TYPECODE_SPECIALSPACE << PackedFormat.TYPECODE_SHIFT) | PackedFormat.SPECIALSPACE_STACK);
      } else {
        this.outBytes.push((PackedFormat.TYPECODE_SPECIALSPACE << PackedFormat.TYPECODE_SHIFT) | PackedFormat.SPECIALSPACE_SPACEBASE);
      }
    } else {
      const spcId = BigInt(spc.getIndex());
      this.writeInteger(PackedFormat.TYPECODE_ADDRESSSPACE << PackedFormat.TYPECODE_SHIFT, spcId);
    }
  }

  /**
   * Get the encoded output as a latin1 string.
   * Each byte in the output corresponds to one character.
   */
  toString(): string {
    return String.fromCharCode(...this.outBytes);
  }

  /** Get the encoded output as a Uint8Array */
  toBytes(): Uint8Array {
    return new Uint8Array(this.outBytes);
  }

  /** Clear the output buffer */
  clear(): void {
    this.outBytes.length = 0;
  }
}

// =========================================================================
// PackedDecode
// =========================================================================

/**
 * A byte-based decoder designed to marshal info to the decompiler efficiently.
 *
 * The decoder expects an encoding as described in PackedFormat. When ingested,
 * the stream bytes are held in a Uint8Array. During decoding, the object maintains
 * position offsets for the start and end of the current open element, and a
 * current position for attribute iteration.
 */
export class PackedDecode extends Decoder {
  private buf: Uint8Array = new Uint8Array(0);

  // Position tracking: simple integer offsets into this.buf
  private startPos: number = 0;   // Position at the start of the current open element's attributes
  private curPos: number = 0;     // Current position for attribute iteration (getNextAttributeId / read*)
  private endPos: number = 0;     // Position after all attributes (at child elements or element end)
  private attributeRead: boolean = true;  // Has the last attribute returned by getNextAttributeId been read

  constructor(spc: AddrSpaceManager | null) {
    super(spc);
  }

  /** Get the byte at the given position without advancing */
  private getByte(pos: number): number {
    return this.buf[pos];
  }

  /** Get the byte following the given position without advancing */
  private getBytePlus1(pos: number): number {
    const nextPos = pos + 1;
    if (nextPos >= this.buf.length) {
      throw new DecoderError('Unexpected end of stream');
    }
    return this.buf[nextPos];
  }

  /** Get the byte at the given position and return {value, newPos} with position advanced */
  private getNextByte(pos: number): { value: number; newPos: number } {
    if (pos >= this.buf.length) {
      throw new DecoderError('Unexpected end of stream');
    }
    return { value: this.buf[pos], newPos: pos + 1 };
  }

  /** Advance a position by the given number of bytes */
  private advancePosition(pos: number, skip: number): number {
    const newPos = pos + skip;
    if (newPos > this.buf.length) {
      throw new DecoderError('Unexpected end of stream');
    }
    return newPos;
  }

  /**
   * Read an integer from the given position, encoded as 7-bits per byte (MSB first).
   * Returns the integer value and the new position.
   */
  private readIntegerAt(pos: number, len: number): { value: number; newPos: number } {
    let res = 0;
    let p = pos;
    for (let i = 0; i < len; i++) {
      const b = this.getNextByte(p);
      p = b.newPos;
      res = (res * 128) + (b.value & PackedFormat.RAWDATA_MASK);
    }
    return { value: res, newPos: p };
  }

  /**
   * Read an integer from the given position as a bigint.
   * Used for unsigned 64-bit values that may exceed Number.MAX_SAFE_INTEGER.
   */
  private readIntegerBigAt(pos: number, len: number): { value: bigint; newPos: number } {
    let res = 0n;
    let p = pos;
    for (let i = 0; i < len; i++) {
      const b = this.getNextByte(p);
      p = b.newPos;
      res = (res << 7n) | BigInt(b.value & PackedFormat.RAWDATA_MASK);
    }
    return { value: res, newPos: p };
  }

  /** Read an integer from curPos and update curPos. Uses number (for lengths, signed ints). */
  private readIntegerFromCur(len: number): number {
    const r = this.readIntegerAt(this.curPos, len);
    this.curPos = r.newPos;
    return r.value;
  }

  /** Read a bigint integer from curPos and update curPos. */
  private readIntegerBigFromCur(len: number): bigint {
    const r = this.readIntegerBigAt(this.curPos, len);
    this.curPos = r.newPos;
    return r.value;
  }

  /** Extract the length code from a type byte */
  private readLengthCode(typeByte: number): number {
    return typeByte & PackedFormat.LENGTHCODE_MASK;
  }

  /**
   * Skip over the attribute at curPos (header + type byte + data).
   * curPos is advanced past the entire attribute.
   */
  private skipAttribute(): void {
    const h = this.getNextByte(this.curPos);
    this.curPos = h.newPos;
    const header1 = h.value;
    if ((header1 & PackedFormat.HEADEREXTEND_MASK) !== 0) {
      const ext = this.getNextByte(this.curPos);
      this.curPos = ext.newPos;
    }
    const tb = this.getNextByte(this.curPos);
    this.curPos = tb.newPos;
    const typeByte = tb.value;
    this.skipAttributeRemainingInternal(typeByte);
  }

  /**
   * Skip over the remaining data of an attribute after the header and type byte have been read.
   * typeByte is the type byte that was already consumed.
   */
  private skipAttributeRemainingInternal(typeByte: number): void {
    const attribType = typeByte >> PackedFormat.TYPECODE_SHIFT;
    if (attribType === PackedFormat.TYPECODE_BOOLEAN || attribType === PackedFormat.TYPECODE_SPECIALSPACE) {
      return; // no additional data
    }
    let length = this.readLengthCode(typeByte);
    if (attribType === PackedFormat.TYPECODE_STRING) {
      // For strings, the length code encodes the number of bytes for the string length integer
      length = this.readIntegerFromCur(length);
    }
    this.curPos = this.advancePosition(this.curPos, length);
  }

  /**
   * Find the attribute matching the given id in the current open element.
   * Resets curPos to startPos and scans through attributes until a match is found.
   * Throws DecoderError if not found.
   */
  private findMatchingAttribute(attribId: AttributeId): void {
    this.curPos = this.startPos;
    for (;;) {
      const header1 = this.getByte(this.curPos);
      if ((header1 & PackedFormat.HEADER_MASK) !== PackedFormat.ATTRIBUTE) break;
      let id = header1 & PackedFormat.ELEMENTID_MASK;
      if ((header1 & PackedFormat.HEADEREXTEND_MASK) !== 0) {
        id = (id << PackedFormat.RAWDATA_BITSPERBYTE) |
             (this.getBytePlus1(this.curPos) & PackedFormat.RAWDATA_MASK);
      }
      if (attribId.getId() === id) {
        return; // Found it
      }
      this.skipAttribute();
    }
    throw new DecoderError('Attribute ' + attribId.getName() + ' is not present');
  }

  ingestStream(s: string): void {
    // Convert latin1 string to byte array (each char is one byte)
    const len = s.length;
    // Allocate with one extra byte for the end-of-stream padding
    this.buf = new Uint8Array(len + 1);
    for (let i = 0; i < len; i++) {
      this.buf[i] = s.charCodeAt(i) & 0xff;
    }
    // Add ELEMENT_END marker as padding at the end
    this.buf[len] = PackedFormat.ELEMENT_END;
    this.endPos = 0;
    this.startPos = 0;
    this.curPos = 0;
    this.attributeRead = true;
  }

  /**
   * Ingest raw binary data directly, without string conversion.
   * This avoids the lossy TextDecoder('latin1') round-trip which uses Windows-1252
   * and corrupts bytes 0x80-0x9F.
   */
  ingestBytes(data: Uint8Array): void {
    this.buf = new Uint8Array(data.length + 1);
    this.buf.set(data);
    this.buf[data.length] = PackedFormat.ELEMENT_END;
    this.endPos = 0;
    this.startPos = 0;
    this.curPos = 0;
    this.attributeRead = true;
  }

  peekElement(): number {
    const header1 = this.getByte(this.endPos);
    if ((header1 & PackedFormat.HEADER_MASK) !== PackedFormat.ELEMENT_START) {
      return 0;
    }
    let id = header1 & PackedFormat.ELEMENTID_MASK;
    if ((header1 & PackedFormat.HEADEREXTEND_MASK) !== 0) {
      id = (id << PackedFormat.RAWDATA_BITSPERBYTE) |
           (this.getBytePlus1(this.endPos) & PackedFormat.RAWDATA_MASK);
    }
    return id;
  }

  openElement(elemId?: ElementId): number {
    if (elemId !== undefined && typeof elemId === 'object' && elemId !== null) {
      return this.openElementId(elemId);
    }
    const header1 = this.getByte(this.endPos);
    if ((header1 & PackedFormat.HEADER_MASK) !== PackedFormat.ELEMENT_START) {
      return 0;
    }
    // Consume the header byte
    const h = this.getNextByte(this.endPos);
    this.endPos = h.newPos;
    let id = header1 & PackedFormat.ELEMENTID_MASK;
    if ((header1 & PackedFormat.HEADEREXTEND_MASK) !== 0) {
      const ext = this.getNextByte(this.endPos);
      this.endPos = ext.newPos;
      id = (id << PackedFormat.RAWDATA_BITSPERBYTE) | (ext.value & PackedFormat.RAWDATA_MASK);
    }
    // startPos and curPos point to the first attribute (or element end/start)
    this.startPos = this.endPos;
    this.curPos = this.endPos;
    // Scan forward past all attributes to find endPos
    let nextHeader = this.getByte(this.curPos);
    while ((nextHeader & PackedFormat.HEADER_MASK) === PackedFormat.ATTRIBUTE) {
      this.skipAttribute();
      nextHeader = this.getByte(this.curPos);
    }
    this.endPos = this.curPos;
    this.curPos = this.startPos;
    this.attributeRead = true;
    return id;
  }

  openElementId(elemId: ElementId): number {
    const id = this.openElement();
    if (id !== elemId.getId()) {
      if (id === 0) {
        throw new DecoderError('Expecting <' + elemId.getName() + '> but did not scan an element');
      }
      throw new DecoderError('Expecting <' + elemId.getName() + '> but id did not match');
    }
    return id;
  }

  closeElement(id: number): void {
    const h = this.getNextByte(this.endPos);
    this.endPos = h.newPos;
    const header1 = h.value;
    if ((header1 & PackedFormat.HEADER_MASK) !== PackedFormat.ELEMENT_END) {
      throw new DecoderError('Expecting element close');
    }
    let closeId = header1 & PackedFormat.ELEMENTID_MASK;
    if ((header1 & PackedFormat.HEADEREXTEND_MASK) !== 0) {
      const ext = this.getNextByte(this.endPos);
      this.endPos = ext.newPos;
      closeId = (closeId << PackedFormat.RAWDATA_BITSPERBYTE) | (ext.value & PackedFormat.RAWDATA_MASK);
    }
    if (id !== closeId) {
      throw new DecoderError('Did not see expected closing element');
    }
  }

  closeElementSkipping(id: number): void {
    const idstack: number[] = [id];
    while (idstack.length > 0) {
      const headerByte = this.getByte(this.endPos) & PackedFormat.HEADER_MASK;
      if (headerByte === PackedFormat.ELEMENT_END) {
        this.closeElement(idstack[idstack.length - 1]);
        idstack.pop();
      } else if (headerByte === PackedFormat.ELEMENT_START) {
        idstack.push(this.openElement());
      } else {
        throw new DecoderError('Corrupt stream');
      }
    }
  }

  rewindAttributes(): void {
    this.curPos = this.startPos;
    this.attributeRead = true;
  }

  getNextAttributeId(): number {
    if (!this.attributeRead) {
      this.skipAttribute();
    }
    const header1 = this.getByte(this.curPos);
    if ((header1 & PackedFormat.HEADER_MASK) !== PackedFormat.ATTRIBUTE) {
      return 0;
    }
    let id = header1 & PackedFormat.ELEMENTID_MASK;
    if ((header1 & PackedFormat.HEADEREXTEND_MASK) !== 0) {
      id = (id << PackedFormat.RAWDATA_BITSPERBYTE) |
           (this.getBytePlus1(this.curPos) & PackedFormat.RAWDATA_MASK);
    }
    this.attributeRead = false;
    return id;
  }

  getIndexedAttributeId(_attribId: AttributeId): number {
    return ATTRIB_UNKNOWN.getId(); // PackedDecode never needs to reinterpret an attribute
  }

  readBool(attribId?: AttributeId): boolean {
    if (attribId !== undefined && typeof attribId === 'object') {
      return this.readBoolById(attribId);
    }
    // Consume attribute header
    const h = this.getNextByte(this.curPos);
    this.curPos = h.newPos;
    if ((h.value & PackedFormat.HEADEREXTEND_MASK) !== 0) {
      const ext = this.getNextByte(this.curPos);
      this.curPos = ext.newPos;
    }
    // Read type byte
    const tb = this.getNextByte(this.curPos);
    this.curPos = tb.newPos;
    const typeByte = tb.value;
    this.attributeRead = true;
    if ((typeByte >> PackedFormat.TYPECODE_SHIFT) !== PackedFormat.TYPECODE_BOOLEAN) {
      throw new DecoderError('Expecting boolean attribute');
    }
    return (typeByte & PackedFormat.LENGTHCODE_MASK) !== 0;
  }

  readBoolById(attribId: AttributeId): boolean {
    this.findMatchingAttribute(attribId);
    const res = this.readBool();
    this.curPos = this.startPos;
    return res;
  }

  readSignedInteger(attribId?: AttributeId): number {
    if (attribId !== undefined && typeof attribId === 'object') {
      return this.readSignedIntegerById(attribId);
    }
    // Consume attribute header
    const h = this.getNextByte(this.curPos);
    this.curPos = h.newPos;
    if ((h.value & PackedFormat.HEADEREXTEND_MASK) !== 0) {
      const ext = this.getNextByte(this.curPos);
      this.curPos = ext.newPos;
    }
    // Read type byte
    const tb = this.getNextByte(this.curPos);
    this.curPos = tb.newPos;
    const typeByte = tb.value;
    const typeCode = typeByte >> PackedFormat.TYPECODE_SHIFT;
    let res: number;
    if (typeCode === PackedFormat.TYPECODE_SIGNEDINT_POSITIVE) {
      res = this.readIntegerFromCur(this.readLengthCode(typeByte));
    } else if (typeCode === PackedFormat.TYPECODE_SIGNEDINT_NEGATIVE) {
      res = -this.readIntegerFromCur(this.readLengthCode(typeByte));
    } else {
      this.skipAttributeRemainingInternal(typeByte);
      this.attributeRead = true;
      throw new DecoderError('Expecting signed integer attribute');
    }
    this.attributeRead = true;
    return res;
  }

  readSignedIntegerById(attribId: AttributeId): number {
    this.findMatchingAttribute(attribId);
    const res = this.readSignedInteger();
    this.curPos = this.startPos;
    return res;
  }

  readSignedIntegerExpectString(expect: string, expectval: number): number {
    // Peek at the type to determine if it's a string or integer
    let tmpPos = this.curPos;
    const h = this.getNextByte(tmpPos);
    tmpPos = h.newPos;
    if ((h.value & PackedFormat.HEADEREXTEND_MASK) !== 0) {
      const ext = this.getNextByte(tmpPos);
      tmpPos = ext.newPos;
    }
    const tb = this.getNextByte(tmpPos);
    const typeByte = tb.value;
    const typeCode = typeByte >> PackedFormat.TYPECODE_SHIFT;
    if (typeCode === PackedFormat.TYPECODE_STRING) {
      const val = this.readString();
      if (val !== expect) {
        throw new DecoderError('Expecting string "' + expect + '" but read "' + val + '"');
      }
      return expectval;
    } else {
      return this.readSignedInteger();
    }
  }

  readSignedIntegerExpectStringById(attribId: AttributeId, expect: string, expectval: number): number {
    this.findMatchingAttribute(attribId);
    const res = this.readSignedIntegerExpectString(expect, expectval);
    this.curPos = this.startPos;
    return res;
  }

  readUnsignedInteger(attribId?: AttributeId): bigint {
    if (attribId !== undefined && typeof attribId === 'object') {
      return this.readUnsignedIntegerById(attribId);
    }
    // Consume attribute header
    const h = this.getNextByte(this.curPos);
    this.curPos = h.newPos;
    if ((h.value & PackedFormat.HEADEREXTEND_MASK) !== 0) {
      const ext = this.getNextByte(this.curPos);
      this.curPos = ext.newPos;
    }
    // Read type byte
    const tb = this.getNextByte(this.curPos);
    this.curPos = tb.newPos;
    const typeByte = tb.value;
    const typeCode = typeByte >> PackedFormat.TYPECODE_SHIFT;
    let res: bigint;
    if (typeCode === PackedFormat.TYPECODE_UNSIGNEDINT) {
      res = this.readIntegerBigFromCur(this.readLengthCode(typeByte));
    } else {
      this.skipAttributeRemainingInternal(typeByte);
      this.attributeRead = true;
      throw new DecoderError('Expecting unsigned integer attribute');
    }
    this.attributeRead = true;
    return res;
  }

  readUnsignedIntegerById(attribId: AttributeId): bigint {
    this.findMatchingAttribute(attribId);
    const res = this.readUnsignedInteger();
    this.curPos = this.startPos;
    return res;
  }

  readString(attribId?: AttributeId): string {
    if (attribId !== undefined && typeof attribId === 'object') {
      return this.readStringById(attribId);
    }
    // Consume attribute header
    const h = this.getNextByte(this.curPos);
    this.curPos = h.newPos;
    if ((h.value & PackedFormat.HEADEREXTEND_MASK) !== 0) {
      const ext = this.getNextByte(this.curPos);
      this.curPos = ext.newPos;
    }
    // Read type byte
    const tb = this.getNextByte(this.curPos);
    this.curPos = tb.newPos;
    const typeByte = tb.value;
    const typeCode = typeByte >> PackedFormat.TYPECODE_SHIFT;
    if (typeCode !== PackedFormat.TYPECODE_STRING) {
      this.skipAttributeRemainingInternal(typeByte);
      this.attributeRead = true;
      throw new DecoderError('Expecting string attribute');
    }
    const lengthCode = this.readLengthCode(typeByte);
    const strLen = this.readIntegerFromCur(lengthCode);
    this.attributeRead = true;
    // Read strLen bytes as latin1 characters
    let result = '';
    for (let i = 0; i < strLen; i++) {
      result += String.fromCharCode(this.buf[this.curPos + i]);
    }
    this.curPos = this.advancePosition(this.curPos, strLen);
    return result;
  }

  readStringById(attribId: AttributeId): string {
    this.findMatchingAttribute(attribId);
    const res = this.readString();
    this.curPos = this.startPos;
    return res;
  }

  readSpace(attribId?: AttributeId): AddrSpace {
    if (attribId !== undefined && typeof attribId === 'object') {
      return this.readSpaceById(attribId);
    }
    // Consume attribute header
    const h = this.getNextByte(this.curPos);
    this.curPos = h.newPos;
    if ((h.value & PackedFormat.HEADEREXTEND_MASK) !== 0) {
      const ext = this.getNextByte(this.curPos);
      this.curPos = ext.newPos;
    }
    // Read type byte
    const tb = this.getNextByte(this.curPos);
    this.curPos = tb.newPos;
    const typeByte = tb.value;
    const typeCode = typeByte >> PackedFormat.TYPECODE_SHIFT;
    let spc: AddrSpace | null;
    if (typeCode === PackedFormat.TYPECODE_ADDRESSSPACE) {
      const spcIdx = this.readIntegerFromCur(this.readLengthCode(typeByte));
      if (this.spcManager === null) {
        throw new DecoderError('No address space manager available');
      }
      spc = this.spcManager.getSpace(spcIdx);
      if (spc === null) {
        throw new DecoderError('Unknown address space index');
      }
    } else if (typeCode === PackedFormat.TYPECODE_SPECIALSPACE) {
      const specialCode = this.readLengthCode(typeByte);
      if (this.spcManager === null) {
        throw new DecoderError('No address space manager available');
      }
      if (specialCode === PackedFormat.SPECIALSPACE_STACK) {
        spc = this.spcManager.getStackSpace();
      } else if (specialCode === PackedFormat.SPECIALSPACE_JOIN) {
        spc = this.spcManager.getJoinSpace();
      } else {
        throw new DecoderError('Cannot marshal special address space');
      }
    } else {
      this.skipAttributeRemainingInternal(typeByte);
      this.attributeRead = true;
      throw new DecoderError('Expecting space attribute');
    }
    this.attributeRead = true;
    return spc;
  }

  readSpaceById(attribId: AttributeId): AddrSpace {
    this.findMatchingAttribute(attribId);
    const res = this.readSpace();
    this.curPos = this.startPos;
    return res;
  }

  readOpcode(attribId?: AttributeId): OpCode {
    if (attribId !== undefined && typeof attribId === 'object') {
      return this.readOpcodeById(attribId);
    }
    const val = this.readSignedInteger();
    if (val < 0 || val >= OpCode.CPUI_MAX) {
      throw new DecoderError('Bad encoded OpCode: ' + val);
    }
    return val as OpCode;
  }

  readOpcodeById(attribId: AttributeId): OpCode {
    this.findMatchingAttribute(attribId);
    const res = this.readOpcode();
    this.curPos = this.startPos;
    return res;
  }
}

// =========================================================================
// Utility: auto-radix integer parsing (mimics C++ ios unsetf dec|hex|oct)
// =========================================================================

/**
 * Parse an integer string that may be decimal, hex (0x prefix), or octal (0 prefix).
 * This mirrors the C++ behavior of unsetting ios::dec|hex|oct to enable auto-detection.
 */
function parseIntAutoRadix(s: string): number {
  s = s.trim();
  if (s.startsWith('0x') || s.startsWith('0X')) {
    return parseInt(s, 16);
  }
  if (s.startsWith('-0x') || s.startsWith('-0X')) {
    return -parseInt(s.substring(1), 16);
  }
  // Note: we do NOT parse leading-zero as octal to avoid common pitfalls.
  // The Ghidra codebase primarily uses 0x for hex and plain decimal.
  return parseInt(s, 10);
}

/**
 * Parse an unsigned integer string that may be decimal or hex (0x prefix).
 * Returns a bigint.
 */
function parseUintAutoRadix(s: string): bigint {
  s = s.trim();
  if (s.startsWith('0x') || s.startsWith('0X')) {
    return BigInt(s);
  }
  return BigInt(s);
}

// =========================================================================
// Initialize the lookup tables on module load
// =========================================================================

// All AttributeId and ElementId instances created above (at module scope) have
// been registered in their respective registration lists. Calling initialize()
// populates the lookup maps so that find() works correctly.
AttributeId.initialize();
ElementId.initialize();
