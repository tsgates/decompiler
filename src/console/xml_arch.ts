/**
 * @file xml_arch.ts
 * @description Extension to read executables based on an XML format.
 *
 * Translated from Ghidra's xml_arch.hh / xml_arch.cc
 */

import * as fs from 'fs';
import { ElementId } from '../core/marshal.js';
import { LowlevelError } from '../core/error.js';
import { DocumentStorage, Document, Element } from '../core/xml.js';
import { ArchitectureCapability, ATTRIB_ADJUSTVMA, Architecture } from '../decompiler/architecture.js';
import type { Writer } from '../decompiler/architecture.js';
import { LoadImageXml } from '../decompiler/loadimage.js';
import { SleighArchitecture } from './sleigh_arch.js';

// Forward type declarations for types only used as annotations
type Encoder = any;

// ---------------------------------------------------------------------------
// Element IDs
// ---------------------------------------------------------------------------

export const ELEM_XML_SAVEFILE = new ElementId('xml_savefile', 236);

// ---------------------------------------------------------------------------
// XmlArchitectureCapability
// ---------------------------------------------------------------------------

/**
 * Extension for building an XML format capable Architecture.
 *
 * This is registered as a singleton at module load time. It matches files
 * that begin with "<bi" (the start of a <binaryimage> tag) and XML documents
 * whose root tag is "xml_savefile".
 */
export class XmlArchitectureCapability extends ArchitectureCapability {
  /** The singleton instance */
  private static xmlArchitectureCapability: XmlArchitectureCapability;

  constructor() {
    super();
    this.name = 'xml';
  }

  /**
   * Build an XmlArchitecture from the given file.
   * @param filename - path to the XML executable file
   * @param target - language id string (if non-empty)
   * @param estream - output stream for error messages
   * @returns a new XmlArchitecture instance
   */
  buildArchitecture(filename: string, target: string, estream: Writer | null): Architecture {
    return new XmlArchitecture(filename, target, estream) as any;
  }

  /**
   * Check if a file starts with "<bi" (the beginning of a <binaryimage> tag).
   *
   * Reads the first few bytes of the file, skipping leading whitespace,
   * and checks for the sequence '<', 'b', 'i'.
   *
   * @param filename - path to the file to examine
   * @returns true if the file likely contains a <binaryimage> tag
   */
  isFileMatch(filename: string): boolean {
    let data: Buffer;
    try {
      // Only need to read a small amount to check the header
      const fd = fs.openSync(filename, 'r');
      const buf = Buffer.alloc(64);
      const bytesRead = fs.readSync(fd, buf, 0, 64, 0);
      fs.closeSync(fd);
      data = buf.subarray(0, bytesRead);
    } catch {
      return false;
    }

    // Skip leading whitespace (matching C++ stream >> ws behavior)
    let pos = 0;
    while (pos < data.length && (data[pos] === 0x20 || data[pos] === 0x09 ||
           data[pos] === 0x0A || data[pos] === 0x0D)) {
      pos++;
    }

    // Check for '<bi' (probably <binaryimage> tag)
    if (pos + 2 < data.length) {
      const val1 = data[pos];
      const val2 = data[pos + 1];
      const val3 = data[pos + 2];
      if (val1 === 0x3C /* '<' */ && val2 === 0x62 /* 'b' */ && val3 === 0x69 /* 'i' */) {
        return true;
      }
    }
    return false;
  }

  /**
   * Match an XML document with an "xml_savefile" root tag.
   * @param doc - the parsed XML document
   * @returns true if the root element is "xml_savefile"
   */
  isXmlMatch(doc: Document): boolean {
    return doc.getRoot().getName() === 'xml_savefile';
  }
}

// Register the singleton at module load time (mirrors C++ static initialization)
const xmlArchitectureCapability = new XmlArchitectureCapability();

// ---------------------------------------------------------------------------
// XmlArchitecture
// ---------------------------------------------------------------------------

/**
 * An Architecture that loads executables using an XML format.
 *
 * The image is loaded from an XML file containing a <binaryimage> element.
 * An optional adjustvma value shifts all addresses by a given amount.
 */
export class XmlArchitecture extends SleighArchitecture {
  /** The amount to adjust the virtual memory address */
  private adjustvma: number = 0;

  /**
   * @param fname - path to the XML executable file
   * @param targ - language id string
   * @param estream - output stream for error messages
   */
  constructor(fname: string, targ: string, estream: Writer | null) {
    super(fname, targ, estream ?? { write: (_s: string) => {} });
  }

  /**
   * Build the loader for the XML image.
   *
   * Collects spec files, finds or parses the <binaryimage> tag from the store,
   * and creates a LoadImageXml instance.
   *
   * @param store - document storage that may already contain a binaryimage tag
   */
  protected buildLoader(store: DocumentStorage): void {
    SleighArchitecture.collectSpecFiles(this.errorstream);

    let el: Element | null = store.getTag('binaryimage');
    if (el === null) {
      const doc: Document = store.openDocument(this.getFilename());
      store.registerTag(doc.getRoot());
      el = store.getTag('binaryimage');
    }
    if (el === null) {
      throw new LowlevelError('Could not find binaryimage tag');
    }
    this.loader = new LoadImageXml(this.getFilename(), el);
  }

  /**
   * Post-specification-file initialization.
   *
   * After the spec file is loaded, the loader is opened with the translator
   * and any VMA adjustment is applied.
   */
  protected postSpecFile(): void {
    super.postSpecFile();
    if (this.loader !== null) {
      (this.loader as LoadImageXml).open(this as any);
      if (this.adjustvma !== 0) {
        (this.loader as LoadImageXml).adjustVma(this.adjustvma);
      }
    }
  }

  /**
   * Encode this architecture to a stream.
   *
   * Wraps the state in an xml_savefile element with header and adjustvma
   * attribute, followed by the loader's encoded image, core types, and
   * the sleigh architecture state.
   *
   * @param encoder - the stream encoder
   */
  override encode(encoder: Encoder): void {
    encoder.openElement(ELEM_XML_SAVEFILE);
    this.encodeHeader(encoder);
    encoder.writeUnsignedInteger(ATTRIB_ADJUSTVMA, this.adjustvma);
    if (this.loader !== null) {
      (this.loader as any).encode(encoder); // Save the LoadImage
    }
    if (this.types !== null) {
      this.types.encodeCoreTypes(encoder);
    }
    // SleighArchitecture::encode(encoder) would save the rest of the state
    encoder.closeElement(ELEM_XML_SAVEFILE);
  }

  /**
   * Restore this architecture from an XML document store.
   *
   * Reads the xml_savefile tag, restores header attributes and the adjustvma
   * value, then registers binaryimage, specextensions, and coretypes child
   * elements before initializing the architecture.
   *
   * @param store - the document storage containing the xml_savefile tag
   */
  restoreXml(store: DocumentStorage): void {
    const el: Element | null = store.getTag('xml_savefile');
    if (el === null) {
      throw new LowlevelError('Could not find xml_savefile tag');
    }

    this.restoreXmlHeader(el);

    // Parse adjustvma (C++ uses istringstream with auto-base detection)
    let adjustStr: string;
    try {
      adjustStr = el.getAttributeValue('adjustvma');
    } catch {
      adjustStr = '0';
    }
    this.adjustvma = parseInt(adjustStr, 0) || 0;

    const list: Element[] = el.getChildren();
    let idx = 0;

    if (idx < list.length) {
      if (list[idx].getName() === 'binaryimage') {
        store.registerTag(list[idx]);
        idx++;
      }
    }
    if (idx < list.length) {
      if (list[idx].getName() === 'specextensions') {
        store.registerTag(list[idx]);
        idx++;
      }
    }
    if (idx < list.length) {
      if (list[idx].getName() === 'coretypes') {
        store.registerTag(list[idx]);
        idx++;
      }
    }

    this.init(store);

    if (idx < list.length) {
      store.registerTag(list[idx]);
    }
  }
}
