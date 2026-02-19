/**
 * @file raw_arch.ts
 * @description Bare bones capability for treating a file as a raw executable image.
 *
 * Translated from Ghidra's raw_arch.hh / raw_arch.cc
 */

import * as fs from 'fs';
import { ElementId } from '../core/marshal.js';
import { LowlevelError } from '../core/error.js';
import { ArchitectureCapability, ATTRIB_ADJUSTVMA } from '../decompiler/architecture.js';
import type { Writer } from '../decompiler/architecture.js';
import { RawLoadImage } from '../decompiler/loadimage.js';

// Forward type declarations for not-yet-wired modules
type Architecture = any;
type SleighArchitecture = any;
type DocumentStorage = any;
type Encoder = any;
type Document = any;
type Element = any;

// ---------------------------------------------------------------------------
// Element IDs
// ---------------------------------------------------------------------------

export const ELEM_RAW_SAVEFILE = new ElementId('raw_savefile', 237);

// ---------------------------------------------------------------------------
// RawBinaryArchitectureCapability
// ---------------------------------------------------------------------------

/**
 * Extension point for building an Architecture that reads in raw images.
 *
 * This is registered as a singleton at module load time. It matches any file
 * (since raw binary is the fallback format) and XML documents whose root tag
 * is "raw_savefile".
 */
export class RawBinaryArchitectureCapability extends ArchitectureCapability {
  /** The singleton instance */
  private static rawBinaryArchitectureCapability: RawBinaryArchitectureCapability;

  constructor() {
    super();
    this.name = 'raw';
  }

  /**
   * Build a RawBinaryArchitecture from the given file.
   * @param filename - path to the raw binary file
   * @param target - language id string (if non-empty)
   * @param estream - output stream for error messages
   * @returns a new RawBinaryArchitecture instance
   */
  buildArchitecture(filename: string, target: string, estream: Writer | null): Architecture {
    return new RawBinaryArchitecture(filename, target, estream);
  }

  /**
   * A raw binary file can always be opened -- this is the fallback capability.
   * @param filename - path to the file to examine
   * @returns true always
   */
  isFileMatch(filename: string): boolean {
    return true; // File can always be opened as raw binary
  }

  /**
   * Match an XML document with a "raw_savefile" root tag.
   * @param doc - the parsed XML document
   * @returns true if the root element is "raw_savefile"
   */
  isXmlMatch(doc: Document): boolean {
    return doc.getRoot().getName() === 'raw_savefile';
  }
}

// Register the singleton at module load time (mirrors C++ static initialization)
const rawBinaryArchitectureCapability = new RawBinaryArchitectureCapability();

// ---------------------------------------------------------------------------
// RawBinaryArchitecture
// ---------------------------------------------------------------------------

/**
 * Architecture that reads its binary as a raw file.
 *
 * The image is loaded from a flat binary file. An optional adjustvma value
 * shifts byte 0 of the file to a particular address.
 */
export class RawBinaryArchitecture {
  // SleighArchitecture fields (forward-declared base)
  protected filename: string;
  protected target: string;
  protected errorstream: Writer | null;
  protected archid: string = '';
  protected loader: RawLoadImage | null = null;
  protected types: any = null;
  protected translate: any = null;

  /** What address byte 0 of the raw file gets treated as */
  private adjustvma: number = 0;

  /**
   * @param fname - path to the raw binary file
   * @param targ - language id string
   * @param estream - output stream for error messages
   */
  constructor(fname: string, targ: string, estream: Writer | null) {
    this.filename = fname;
    this.target = targ;
    this.errorstream = estream;
  }

  /** Get the executable filename */
  getFilename(): string {
    return this.filename;
  }

  /** Get the language id of the active processor */
  getTarget(): string {
    return this.target;
  }

  /**
   * Build the loader for the raw binary image.
   *
   * Creates a RawLoadImage from the file, opens it (reads the raw bytes),
   * and applies any VMA adjustment.
   *
   * @param store - document storage (unused for raw images)
   */
  protected buildLoader(store: DocumentStorage): void {
    // collectSpecFiles(this.errorstream);  // TODO: wire up when SleighArchitecture is available

    const ldr = new RawLoadImage(this.getFilename());

    // In TypeScript, read the file and provide data via setData() instead of ldr.open()
    const data = fs.readFileSync(this.getFilename());
    ldr.setData(new Uint8Array(data));

    if (this.adjustvma !== 0) {
      ldr.adjustVma(this.adjustvma);
    }
    this.loader = ldr;
  }

  /**
   * Resolve the architecture.
   *
   * For raw images there is nothing to derive from the image itself --
   * we simply copy in the target that was passed in.
   */
  protected resolveArchitecture(): void {
    this.archid = this.getTarget();
    // SleighArchitecture.resolveArchitecture() would be called here in the C++ version
  }

  /**
   * Post-specification-file initialization.
   *
   * After the spec file is loaded, the loader's default code space is attached.
   */
  protected postSpecFile(): void {
    // Architecture.postSpecFile() -- cacheAddrSpaceProperties() would be called here
    if (this.loader !== null) {
      // Attach default code space to loader
      // this.loader.attachToSpace(this.getDefaultCodeSpace());
      // TODO: wire up when getDefaultCodeSpace is available from the base class
    }
  }

  /**
   * Encode basic attributes of the active executable.
   * @param encoder - the stream encoder
   */
  encodeHeader(encoder: Encoder): void {
    // Mirrors SleighArchitecture::encodeHeader
    const ATTRIB_NAME = { getId: () => 72 } as any; // placeholder
    const ATTRIB_TARGET = { getId: () => 73 } as any; // placeholder
    encoder.writeString(ATTRIB_NAME, this.filename);
    encoder.writeString(ATTRIB_TARGET, this.target);
  }

  /**
   * Restore from basic attributes of an executable.
   * @param el - the XML element to restore from
   */
  restoreXmlHeader(el: Element): void {
    this.filename = el.getAttributeValue('name');
    this.target = el.getAttributeValue('target');
  }

  /**
   * Encode this architecture to a stream.
   *
   * Wraps the state in a raw_savefile element with header and adjustvma attribute,
   * followed by core types and the sleigh architecture state.
   *
   * @param encoder - the stream encoder
   */
  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_RAW_SAVEFILE);
    this.encodeHeader(encoder);
    encoder.writeUnsignedInteger(ATTRIB_ADJUSTVMA, this.adjustvma);
    if (this.types !== null) {
      this.types.encodeCoreTypes(encoder);
    }
    // SleighArchitecture::encode(encoder) would be called here
    encoder.closeElement(ELEM_RAW_SAVEFILE);
  }

  /**
   * Restore this architecture from an XML document store.
   *
   * Reads the raw_savefile tag, restores header attributes and the adjustvma
   * value, then optionally registers coretypes and initializes the architecture.
   *
   * @param store - the document storage containing the raw_savefile tag
   */
  restoreXml(store: DocumentStorage): void {
    const el: Element | null = store.getTag('raw_savefile');
    if (el === null) {
      throw new LowlevelError('Could not find raw_savefile tag');
    }

    this.restoreXmlHeader(el);

    // Parse adjustvma (C++ uses istringstream with auto-base detection)
    const adjustStr: string = el.getAttributeValue('adjustvma');
    this.adjustvma = parseInt(adjustStr, 0) || 0;

    const list: Element[] = el.getChildren();
    let idx = 0;

    if (idx < list.length) {
      if (list[idx].getName() === 'coretypes') {
        store.registerTag(list[idx]);
        idx++;
      }
    }

    // init(store) -- Load the image and configure
    // this.init(store);  // TODO: wire up when Architecture.init() is available

    if (idx < list.length) {
      store.registerTag(list[idx]);
      // SleighArchitecture::restoreXml(store) would be called here
    }
  }
}
