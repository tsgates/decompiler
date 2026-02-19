/**
 * @file xml.ts
 * @description Lightweight (and incomplete) XML parser for marshaling data to and from the decompiler.
 * Translated from Ghidra's xml.hh / xml.cc (which uses a yacc-based parser).
 * This is a hand-written recursive descent parser covering the subset of XML
 * that the decompiler actually uses.
 */

import * as fs from 'fs';
import { DecoderError } from './error.js';

// ---------------------------------------------------------------------------
// Attributes  (transient, used only during SAX parsing)
// ---------------------------------------------------------------------------

/**
 * The attributes for a single XML element.
 *
 * A container for name/value pairs (of strings) for the formal attributes,
 * as collected during parsing. This object is used to deliver attribute data
 * to the ContentHandler but is not part of the final DOM model.
 */
export class Attributes {
  private static readonly bogusUri = '';
  private readonly elementName: string;
  private readonly names: string[] = [];
  private readonly values: string[] = [];

  constructor(elementName: string) {
    this.elementName = elementName;
  }

  /** Get the namespace URI associated with this element (always empty). */
  getElemURI(): string {
    return Attributes.bogusUri;
  }

  /** Get the name of this element. */
  getElemName(): string {
    return this.elementName;
  }

  /** Add a formal attribute. */
  addAttribute(name: string, value: string): void {
    this.names.push(name);
    this.values.push(value);
  }

  // ---- SAX Attributes interface ----

  /** Get the number of attributes. */
  getLength(): number {
    return this.names.length;
  }

  /** Get the namespace URI of the i-th attribute (always empty). */
  getURI(_i: number): string {
    return Attributes.bogusUri;
  }

  /** Get the local name of the i-th attribute. */
  getLocalName(i: number): string {
    return this.names[i];
  }

  /** Get the qualified name of the i-th attribute. */
  getQName(i: number): string {
    return this.names[i];
  }

  /** Get the value of the i-th attribute. */
  getValue(i: number): string;
  /** Get the value of the attribute with the given qualified name. */
  getValue(qualifiedName: string): string;
  getValue(arg: number | string): string {
    if (typeof arg === 'number') {
      return this.values[arg];
    }
    for (let i = 0; i < this.names.length; ++i) {
      if (this.names[i] === arg) return this.values[i];
    }
    return '';
  }
}

// ---------------------------------------------------------------------------
// ContentHandler  (SAX-style interface)
// ---------------------------------------------------------------------------

/**
 * The SAX interface for parsing XML documents.
 *
 * This is the formal interface for handling the low-level string pieces of an
 * XML document as they are scanned by the parser.
 */
export interface ContentHandler {
  /** Start processing a new XML document. */
  startDocument(): void;

  /** End processing for the current XML document. */
  endDocument(): void;

  /**
   * Callback indicating a new XML element has started.
   * @param namespaceURI - namespace (always empty in this implementation)
   * @param localName - local name of the element
   * @param qualifiedName - fully qualified name (same as localName here)
   * @param atts - the parsed attributes
   */
  startElement(
    namespaceURI: string,
    localName: string,
    qualifiedName: string,
    atts: Attributes,
  ): void;

  /**
   * Callback indicating parsing of the current XML element is finished.
   * @param namespaceURI - namespace (always empty)
   * @param localName - local name of the element
   * @param qualifiedName - fully qualified name
   */
  endElement(
    namespaceURI: string,
    localName: string,
    qualifiedName: string,
  ): void;

  /**
   * Callback with raw characters to be inserted in the current XML element.
   * @param text - the character data
   * @param start - first character index
   * @param length - number of characters
   */
  characters(text: string, start: number, length: number): void;

  /**
   * Callback for handling an error condition during XML parsing.
   * @param errmsg - a message describing the error
   */
  setError(errmsg: string): void;
}

// ---------------------------------------------------------------------------
// Element  (DOM node)
// ---------------------------------------------------------------------------

/** A list of XML elements (child list). */
export type List = Element[];

/**
 * An XML element. A node in the DOM tree.
 *
 * This is the main node for the in-memory representation of the XML (DOM) tree.
 */
export class Element {
  private _name: string = '';
  private _content: string = '';
  private readonly _attr: string[] = [];
  private readonly _value: string[] = [];
  protected _parent: Element | null;
  protected _children: Element[] = [];

  constructor(parent: Element | null) {
    this._parent = parent;
  }

  /** Set the local name of the element. */
  setName(nm: string): void {
    this._name = nm;
  }

  /**
   * Append new character content to this element.
   * @param str - the character data
   * @param start - first character index
   * @param length - number of characters to append
   */
  addContent(str: string, start: number, length: number): void {
    this._content += str.substring(start, start + length);
  }

  /**
   * Add a new child Element to the model, with this as the parent.
   * @param child - the new child Element
   */
  addChild(child: Element): void {
    this._children.push(child);
  }

  /**
   * Add a new name/value attribute pair to this element.
   * @param nm - attribute name
   * @param vl - attribute value
   */
  addAttribute(nm: string, vl: string): void {
    this._attr.push(nm);
    this._value.push(vl);
  }

  /** Get the parent Element (or null for root/document). */
  getParent(): Element | null {
    return this._parent;
  }

  /** Get the local name of this element. */
  getName(): string {
    return this._name;
  }

  /** Get the list of child elements. */
  getChildren(): Element[] {
    return this._children;
  }

  /** Get the character content of this element. */
  getContent(): string {
    return this._content;
  }

  /**
   * Get an attribute value by name.
   *
   * Look up the value for the given attribute name and return it. Throws a
   * DecoderError if the attribute does not exist.
   * @param nm - attribute name
   * @returns the corresponding attribute value
   */
  getAttributeValue(nm: string): string;
  /**
   * Get the value of the i-th attribute.
   * @param i - attribute index
   * @returns the attribute value
   */
  getAttributeValue(i: number): string;
  getAttributeValue(arg: string | number): string {
    if (typeof arg === 'number') {
      return this._value[arg];
    }
    for (let i = 0; i < this._attr.length; ++i) {
      if (this._attr[i] === arg) return this._value[i];
    }
    throw new DecoderError('Unknown attribute: ' + arg);
  }

  /** Get the number of attributes for this element. */
  getNumAttributes(): number {
    return this._attr.length;
  }

  /** Get the name of the i-th attribute. */
  getAttributeName(i: number): string {
    return this._attr[i];
  }
}

// ---------------------------------------------------------------------------
// Document  (root of the DOM tree)
// ---------------------------------------------------------------------------

/**
 * A complete in-memory XML document.
 *
 * This is actually just an Element object itself, with the document's root
 * element as its only child, which owns all the child documents below it in
 * the DOM hierarchy.
 */
export class Document extends Element {
  constructor() {
    super(null);
  }

  /** Get the root Element of the document. */
  getRoot(): Element {
    return this._children[0];
  }
}

// ---------------------------------------------------------------------------
// TreeHandler  (SAX -> DOM builder)
// ---------------------------------------------------------------------------

/**
 * A SAX interface implementation for constructing an in-memory DOM model.
 *
 * This implementation builds a DOM model of the XML stream being parsed,
 * creating an Element object for each XML element tag in the stream.
 */
export class TreeHandler implements ContentHandler {
  private root: Element;
  private cur: Element;
  private _error: string = '';

  constructor(root: Element) {
    this.root = root;
    this.cur = root;
  }

  startDocument(): void {}

  endDocument(): void {}

  startElement(
    _namespaceURI: string,
    localName: string,
    _qualifiedName: string,
    atts: Attributes,
  ): void {
    const newel = new Element(this.cur);
    this.cur.addChild(newel);
    this.cur = newel;
    newel.setName(localName);
    for (let i = 0; i < atts.getLength(); ++i) {
      newel.addAttribute(atts.getLocalName(i), atts.getValue(i));
    }
  }

  endElement(
    _namespaceURI: string,
    _localName: string,
    _qualifiedName: string,
  ): void {
    const parent = this.cur.getParent();
    if (parent !== null) {
      this.cur = parent;
    }
  }

  characters(text: string, start: number, length: number): void {
    this.cur.addContent(text, start, length);
  }

  setError(errmsg: string): void {
    this._error = errmsg;
  }

  /** Get the current error message (empty string if none). */
  getError(): string {
    return this._error;
  }
}

// ---------------------------------------------------------------------------
// DocumentStorage
// ---------------------------------------------------------------------------

/**
 * A container for parsed XML documents.
 *
 * This holds multiple XML documents that have already been parsed. Documents
 * can be put in this container via parseDocument(). If they are explicitly
 * registered, specific XML Elements can be looked up by name via getTag().
 */
export class DocumentStorage {
  private doclist: Document[] = [];
  private tagmap: Map<string, Element> = new Map();

  /**
   * Parse an XML document from the given string.
   *
   * Parsing starts immediately, attempting to make an in-memory DOM tree.
   * A DecoderError is thrown for any parsing error.
   * @param input - the XML string to parse
   * @returns the in-memory DOM tree
   */
  parseDocument(input: string): Document {
    const doc = xml_tree(input);
    this.doclist.push(doc);
    return doc;
  }

  /**
   * Register the given XML Element object under its tag name.
   *
   * Only one Element can be stored per tag name.
   * @param el - the XML element to register
   */
  registerTag(el: Element): void {
    this.tagmap.set(el.getName(), el);
  }

  /**
   * Retrieve a registered XML Element by name.
   * @param nm - the XML tag name
   * @returns the matching registered Element or null
   */
  getTag(nm: string): Element | null {
    return this.tagmap.get(nm) ?? null;
  }

  /**
   * Open and parse an XML file from the filesystem.
   *
   * The file is read and its content is parsed into an in-memory DOM tree
   * which is added to the internal document list.
   * @param filename - the path to the XML file
   * @returns the parsed Document
   */
  openDocument(filename: string): Document {
    const content = fs.readFileSync(filename, 'utf-8');
    return this.parseDocument(content);
  }
}

// ---------------------------------------------------------------------------
// Recursive Descent XML Parser
// ---------------------------------------------------------------------------

/**
 * Internal parser state for the recursive descent XML parser.
 */
class XmlParser {
  private input: string;
  private pos: number = 0;
  private handler: ContentHandler;

  constructor(input: string, handler: ContentHandler) {
    this.input = input;
    this.handler = handler;
  }

  /** Run the parser. Returns 0 on success, non-zero on error. */
  parse(): number {
    try {
      this.handler.startDocument();
      this.skipWhitespace();
      // Skip XML declaration if present
      if (this.lookingAt('<?xml')) {
        this.parseXmlDeclaration();
      }
      this.skipWhitespace();
      // Parse the document body: one root element with possible
      // surrounding comments/whitespace
      this.parseContent();
      this.handler.endDocument();
      return 0;
    } catch (e) {
      if (e instanceof DecoderError) {
        this.handler.setError(e.explain);
        return 1;
      }
      if (e instanceof Error) {
        this.handler.setError(e.message);
        return 1;
      }
      this.handler.setError('Unknown parse error');
      return 1;
    }
  }

  // ---- Utility helpers ----

  /** Check if end of input has been reached. */
  private eof(): boolean {
    return this.pos >= this.input.length;
  }

  /** Peek at the current character without consuming. */
  private peek(): string {
    return this.input[this.pos];
  }

  /** Peek at a character at offset i from current position. */
  private peekAt(i: number): string {
    return this.input[this.pos + i];
  }

  /** Get the current character and advance. */
  private advance(): string {
    return this.input[this.pos++];
  }

  /** Check if the remaining input starts with the given string. */
  private lookingAt(s: string): boolean {
    return this.input.startsWith(s, this.pos);
  }

  /** Expect and consume the given string, or throw. */
  private expect(s: string): void {
    if (!this.lookingAt(s)) {
      this.error(`Expected '${s}'`);
    }
    this.pos += s.length;
  }

  /** Skip whitespace characters (space, tab, newline, carriage return). */
  private skipWhitespace(): void {
    while (!this.eof()) {
      const c = this.peek();
      if (c === ' ' || c === '\t' || c === '\n' || c === '\r') {
        this.pos++;
      } else {
        break;
      }
    }
  }

  /** Throw a DecoderError with context. */
  private error(msg: string): never {
    // Include a snippet of nearby text for context
    const contextStart = Math.max(0, this.pos - 20);
    const contextEnd = Math.min(this.input.length, this.pos + 20);
    const context = this.input.substring(contextStart, contextEnd);
    throw new DecoderError(`${msg} at position ${this.pos} near: "${context}"`);
  }

  // ---- Naming ----

  /** Check if a character is a valid XML name start character. */
  private isNameStartChar(c: string): boolean {
    const code = c.charCodeAt(0);
    // Letters, underscore, colon
    return (
      (code >= 0x41 && code <= 0x5a) || // A-Z
      (code >= 0x61 && code <= 0x7a) || // a-z
      code === 0x5f || // _
      code === 0x3a || // :
      code >= 0xc0 // extended unicode
    );
  }

  /** Check if a character is a valid XML name character. */
  private isNameChar(c: string): boolean {
    if (this.isNameStartChar(c)) return true;
    const code = c.charCodeAt(0);
    return (
      (code >= 0x30 && code <= 0x39) || // 0-9
      code === 0x2d || // -
      code === 0x2e // .
    );
  }

  /** Parse an XML name (element/attribute name). */
  private parseName(): string {
    if (this.eof() || !this.isNameStartChar(this.peek())) {
      this.error('Expected XML name');
    }
    const start = this.pos;
    while (!this.eof() && this.isNameChar(this.peek())) {
      this.pos++;
    }
    return this.input.substring(start, this.pos);
  }

  // ---- Entity and character references ----

  /**
   * Parse a reference (&...;) and return the replacement string.
   * Assumes the '&' has already been consumed.
   */
  private parseReference(): string {
    if (this.eof()) {
      this.error('Unexpected end of input in reference');
    }
    if (this.peek() === '#') {
      // Character reference: &#dd; or &#xhh;
      this.pos++; // consume '#'
      let codePoint: number;
      if (!this.eof() && this.peek() === 'x') {
        // Hexadecimal
        this.pos++; // consume 'x'
        const start = this.pos;
        while (!this.eof() && this.peek() !== ';') {
          this.pos++;
        }
        if (this.eof()) this.error('Unterminated character reference');
        codePoint = parseInt(this.input.substring(start, this.pos), 16);
      } else {
        // Decimal
        const start = this.pos;
        while (!this.eof() && this.peek() !== ';') {
          this.pos++;
        }
        if (this.eof()) this.error('Unterminated character reference');
        codePoint = parseInt(this.input.substring(start, this.pos), 10);
      }
      this.pos++; // consume ';'
      if (isNaN(codePoint)) {
        this.error('Invalid character reference');
      }
      return String.fromCodePoint(codePoint);
    } else {
      // Entity reference: &name;
      const start = this.pos;
      while (!this.eof() && this.peek() !== ';') {
        this.pos++;
      }
      if (this.eof()) this.error('Unterminated entity reference');
      const name = this.input.substring(start, this.pos);
      this.pos++; // consume ';'
      return convertEntityRef(name);
    }
  }

  // ---- Attribute value ----

  /** Parse an attribute value (quoted string with entity replacement). */
  private parseAttValue(): string {
    if (this.eof()) {
      this.error('Expected attribute value');
    }
    const quote = this.advance();
    if (quote !== '"' && quote !== "'") {
      this.error('Attribute value must be quoted');
    }
    let result = '';
    while (!this.eof() && this.peek() !== quote) {
      if (this.peek() === '&') {
        this.pos++; // consume '&'
        result += this.parseReference();
      } else {
        result += this.advance();
      }
    }
    if (this.eof()) {
      this.error('Unterminated attribute value');
    }
    this.pos++; // consume closing quote
    return result;
  }

  // ---- XML Declaration ----

  /** Parse <?xml ...?> declaration. */
  private parseXmlDeclaration(): void {
    this.expect('<?xml');
    // Scan until '?>'
    while (!this.eof()) {
      if (this.lookingAt('?>')) {
        this.pos += 2;
        return;
      }
      this.pos++;
    }
    this.error('Unterminated XML declaration');
  }

  // ---- Comments ----

  /** Parse <!-- ... --> comment. */
  private parseComment(): void {
    this.expect('<!--');
    while (!this.eof()) {
      if (this.lookingAt('-->')) {
        this.pos += 3;
        return;
      }
      this.pos++;
    }
    this.error('Unterminated comment');
  }

  // ---- CDATA ----

  /** Parse <![CDATA[ ... ]]> section. Returns the content text. */
  private parseCData(): string {
    this.expect('<![CDATA[');
    const start = this.pos;
    while (!this.eof()) {
      if (this.lookingAt(']]>')) {
        const text = this.input.substring(start, this.pos);
        this.pos += 3;
        return text;
      }
      this.pos++;
    }
    this.error('Unterminated CDATA section');
  }

  // ---- Elements ----

  /**
   * Parse element content (text, child elements, CDATA, comments, references).
   * This handles the mixed content between an open tag and its close tag,
   * as well as top-level content around the root element.
   */
  private parseContent(): void {
    while (!this.eof()) {
      if (this.lookingAt('</')) {
        // End tag -- caller will handle it
        return;
      }
      if (this.peek() === '<') {
        if (this.lookingAt('<!--')) {
          this.parseComment();
        } else if (this.lookingAt('<![CDATA[')) {
          const text = this.parseCData();
          if (text.length > 0) {
            this.handler.characters(text, 0, text.length);
          }
        } else if (this.lookingAt('<?')) {
          // Processing instruction -- skip it
          this.pos += 2;
          while (!this.eof() && !this.lookingAt('?>')) {
            this.pos++;
          }
          if (!this.eof()) this.pos += 2;
        } else {
          this.parseElement();
        }
      } else if (this.peek() === '&') {
        // Entity reference in content
        this.pos++; // consume '&'
        const replacement = this.parseReference();
        if (replacement.length > 0) {
          this.handler.characters(replacement, 0, replacement.length);
        }
      } else {
        // Character data
        this.parseCharData();
      }
    }
  }

  /**
   * Parse character data (text between tags).
   * Collects text up to the next '<' or '&'.
   */
  private parseCharData(): void {
    const start = this.pos;
    while (!this.eof() && this.peek() !== '<' && this.peek() !== '&') {
      this.pos++;
    }
    if (this.pos > start) {
      const text = this.input.substring(start, this.pos);
      // Following the C++ print_content behavior: check if the text is
      // entirely whitespace. If so, it is ignorable whitespace and we
      // still deliver it through characters() for the TreeHandler to
      // collect if it wants.
      this.handler.characters(text, 0, text.length);
    }
  }

  /**
   * Parse a complete element: open tag, content, close tag (or self-closing).
   */
  private parseElement(): void {
    this.expect('<');
    const name = this.parseName();

    // Parse attributes
    const atts = new Attributes(name);
    this.skipWhitespace();
    while (
      !this.eof() &&
      this.peek() !== '>' &&
      this.peek() !== '/' &&
      this.peek() !== '?'
    ) {
      const attrName = this.parseName();
      this.skipWhitespace();
      this.expect('=');
      this.skipWhitespace();
      const attrValue = this.parseAttValue();
      atts.addAttribute(attrName, attrValue);
      this.skipWhitespace();
    }

    if (this.eof()) {
      this.error('Unterminated element tag');
    }

    // Self-closing tag?
    if (this.lookingAt('/>')) {
      this.pos += 2;
      this.handler.startElement('', name, name, atts);
      this.handler.endElement('', name, name);
      return;
    }

    // Open tag
    this.expect('>');
    this.handler.startElement('', name, name, atts);

    // Parse content
    this.parseContent();

    // Close tag
    if (!this.lookingAt('</')) {
      this.error('Expected closing tag for <' + name + '>');
    }
    this.expect('</');
    this.skipWhitespace();
    const closeName = this.parseName();
    if (closeName !== name) {
      this.error(
        `Mismatched close tag: expected </${name}> but found </${closeName}>`,
      );
    }
    this.skipWhitespace();
    this.expect('>');
    this.handler.endElement('', name, name);
  }
}

// ---------------------------------------------------------------------------
// Module-level helper: entity conversion
// ---------------------------------------------------------------------------

/**
 * Convert an XML entity reference name to its replacement string.
 * @param ref - the entity name (without & and ;)
 * @returns the replacement character
 */
function convertEntityRef(ref: string): string {
  switch (ref) {
    case 'lt':
      return '<';
    case 'gt':
      return '>';
    case 'amp':
      return '&';
    case 'quot':
      return '"';
    case 'apos':
      return "'";
    default:
      throw new DecoderError('Unknown entity reference: &' + ref + ';');
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Start-up the XML parser given an input string and a handler.
 *
 * This runs the low-level XML parser.
 * @param input - the XML string to parse
 * @param handler - the ContentHandler that stores or processes the XML content events
 * @returns 0 if there is no error during parsing or a non-zero error condition
 */
export function xml_parse(input: string, handler: ContentHandler): number {
  const parser = new XmlParser(input, handler);
  return parser.parse();
}

/**
 * Parse the given XML string into an in-memory document.
 *
 * The string is parsed using the standard TreeHandler for producing an
 * in-memory DOM representation of the XML document.
 * @param input - the XML string to parse
 * @returns the in-memory XML document
 * @throws DecoderError if parsing fails
 */
export function xml_tree(input: string): Document {
  const doc = new Document();
  const handler = new TreeHandler(doc);
  if (xml_parse(input, handler) !== 0) {
    throw new DecoderError(handler.getError());
  }
  return doc;
}

/**
 * Escape characters with special XML meaning in the given string.
 *
 * Makes the following substitutions:
 *   - '<'  => "&lt;"
 *   - '>'  => "&gt;"
 *   - '&'  => "&amp;"
 *   - '"'  => "&quot;"
 *   - "'"  => "&apos;"
 *
 * @param str - the string to escape
 * @returns the escaped string
 */
export function xml_escape(str: string): string {
  let result = '';
  for (let i = 0; i < str.length; ++i) {
    const c = str[i];
    switch (c) {
      case '<':
        result += '&lt;';
        break;
      case '>':
        result += '&gt;';
        break;
      case '&':
        result += '&amp;';
        break;
      case '"':
        result += '&quot;';
        break;
      case "'":
        result += '&apos;';
        break;
      default:
        result += c;
        break;
    }
  }
  return result;
}

/**
 * Read an XML attribute value as a boolean.
 *
 * Recognizes "true", "yes", and "1" as true. Anything else (including
 * empty string) is returned as false.
 * @param attr - the attribute value string
 * @returns true or false
 */
export function xml_readbool(attr: string): boolean {
  if (attr.length === 0) return false;
  const firstc = attr[0];
  if (firstc === 't') return true;
  if (firstc === '1') return true;
  if (firstc === 'y') return true; // For backward compatibility
  return false;
}

// ---------------------------------------------------------------------------
// XML attribute writing helpers
// ---------------------------------------------------------------------------

/**
 * Produce an XML attribute name/value pair as a string.
 *
 * Returns ` attr="escaped_val"` (note the leading space).
 * @param attr - attribute name
 * @param val - attribute value (will be XML-escaped)
 * @returns the formatted attribute string
 */
export function a_v(attr: string, val: string): string {
  return ' ' + attr + '="' + xml_escape(val) + '"';
}

/**
 * Produce an XML attribute with a signed integer value (decimal).
 *
 * Returns ` attr="decimal_value"` (note the leading space).
 * @param attr - attribute name
 * @param val - signed integer value
 * @returns the formatted attribute string
 */
export function a_v_i(attr: string, val: bigint): string {
  return ' ' + attr + '="' + val.toString(10) + '"';
}

/**
 * Produce an XML attribute with an unsigned integer value (hexadecimal).
 *
 * Returns ` attr="0xhex_value"` (note the leading space).
 * @param attr - attribute name
 * @param val - unsigned integer value
 * @returns the formatted attribute string
 */
export function a_v_u(attr: string, val: bigint): string {
  return ' ' + attr + '="0x' + val.toString(16) + '"';
}

/**
 * Produce an XML attribute with a boolean value.
 *
 * Returns ` attr="true"` or ` attr="false"` (note the leading space).
 * @param attr - attribute name
 * @param val - boolean value
 * @returns the formatted attribute string
 */
export function a_v_b(attr: string, val: boolean): string {
  return ' ' + attr + '="' + (val ? 'true' : 'false') + '"';
}
