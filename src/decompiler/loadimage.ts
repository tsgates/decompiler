/**
 * @file loadimage.ts
 * @description Classes and API for accessing a binary load image.
 *
 * Translated from Ghidra's loadimage.hh/loadimage.cc and loadimage_xml.hh/loadimage_xml.cc.
 */

import type { int4, uint4, uintb, uint1 } from '../core/types.js';
import { LowlevelError } from '../core/error.js';
import { Address, RangeList } from '../core/address.js';
import { AddrSpace } from '../core/space.js';
import {
  Encoder,
  Decoder,
  XmlDecode,
  AttributeId,
  ElementId,
  ATTRIB_CONTENT,
  ATTRIB_NAME,
  ATTRIB_READONLY,
  ATTRIB_SPACE,
  ELEM_SYMBOL,
} from '../core/marshal.js';
import type { Element } from '../core/xml.js';
import { SortedMap, SortedSet, SortedMapIterator } from '../util/sorted-set.js';

// Forward-declare types not yet available
type AddrSpaceManager = any;

// ---------------------------------------------------------------------------
// Attribute and Element IDs defined in loadimage_xml.cc
// ---------------------------------------------------------------------------

export const ATTRIB_ARCH = new AttributeId('arch', 135);

export const ELEM_BINARYIMAGE = new ElementId('binaryimage', 230);
export const ELEM_BYTECHUNK = new ElementId('bytechunk', 231);

// ---------------------------------------------------------------------------
// Address comparator for SortedMap / SortedSet usage
// ---------------------------------------------------------------------------

function addressCompare(a: Address, b: Address): number {
  return Address.compare(a, b);
}

// ---------------------------------------------------------------------------
// DataUnavailError
// ---------------------------------------------------------------------------

/**
 * Exception indicating data was not available.
 *
 * This exception is thrown when a request for load image data cannot be met,
 * usually because the requested address range is not in the image.
 */
export class DataUnavailError extends LowlevelError {
  constructor(s: string) {
    super(s);
    this.name = 'DataUnavailError';
  }
}

// ---------------------------------------------------------------------------
// LoadImageFunc
// ---------------------------------------------------------------------------

/**
 * A record indicating a function symbol.
 *
 * This is a lightweight object holding the Address and name of a function.
 */
export class LoadImageFunc {
  address: Address = new Address();
  name: string = '';
}

// ---------------------------------------------------------------------------
// LoadImageSection
// ---------------------------------------------------------------------------

/**
 * A record describing a section of bytes in the executable.
 *
 * A lightweight object specifying the location and size of the section
 * and basic properties.
 */
export class LoadImageSection {
  static readonly unalloc: number = 1;   // Not allocated in memory (debug info)
  static readonly noload: number = 2;    // uninitialized section
  static readonly code: number = 4;      // code only
  static readonly data: number = 8;      // data only
  static readonly readonly: number = 16; // read only section

  address: Address = new Address();
  size: bigint = 0n;
  flags: number = 0;
}

// ---------------------------------------------------------------------------
// LoadImage (abstract base)
// ---------------------------------------------------------------------------

/**
 * An interface into a particular binary executable image.
 *
 * This class provides the abstraction needed by the decompiler for the
 * numerous load file formats used to encode binary executables.
 */
export abstract class LoadImage {
  protected filename: string;

  constructor(f: string) {
    this.filename = f;
  }

  /** Get the name of the LoadImage */
  getFileName(): string {
    return this.filename;
  }

  /**
   * Get data from the LoadImage.
   *
   * Given a particular address range, this routine retrieves the exact byte
   * values that are stored at that address when the executable is loaded into
   * RAM. The caller must supply a pre-allocated Uint8Array where the returned
   * bytes should be stored. If the requested address range does not exist in
   * the image, a DataUnavailError is thrown.
   *
   * @param ptr - the buffer to fill with bytes
   * @param size - number of bytes to retrieve
   * @param addr - starting address
   */
  abstract loadFill(ptr: Uint8Array, size: number, addr: Address): void;

  /** Prepare to read symbols */
  openSymbols(): void {}

  /** Stop reading symbols */
  closeSymbols(): void {}

  /**
   * Get the next symbol record.
   * Returns true if there are more records to read.
   */
  getNextSymbol(record: LoadImageFunc): boolean {
    return false;
  }

  /** Prepare to read section info */
  openSectionInfo(): void {}

  /** Stop reading section info */
  closeSectionInfo(): void {}

  /**
   * Get info on the next section.
   * Returns true if there are more records to read.
   */
  getNextSection(sec: LoadImageSection): boolean {
    return false;
  }

  /** Return list of readonly address ranges */
  getReadonly(list: RangeList): void {}

  /** Get a string indicating the architecture type */
  abstract getArchType(): string;

  /**
   * Adjust load addresses with a global offset.
   * The offset passed to this method is added to the stored or default value
   * for any address queried in the image.
   */
  abstract adjustVma(adjust: number): void;

  /**
   * Load a chunk of image.
   *
   * This is a convenience method wrapped around the core loadFill() routine.
   * It automatically allocates a Uint8Array of the desired size, and then
   * fills it with load image data.
   *
   * @param size - the number of bytes to read from the image
   * @param addr - the address of the first byte being read
   * @returns a Uint8Array containing the desired bytes
   */
  load(size: number, addr: Address): Uint8Array {
    const buf = new Uint8Array(size);
    this.loadFill(buf, size, addr);
    return buf;
  }
}

// ---------------------------------------------------------------------------
// RawLoadImage
// ---------------------------------------------------------------------------

/**
 * A simple raw binary loadimage.
 *
 * Bytes from the image are read directly from a data buffer.
 * The address associated with each byte is determined by a single value,
 * the vma, which is the address of the first byte. No symbols or sections
 * are supported.
 */
export class RawLoadImage extends LoadImage {
  private vma: bigint = 0n;
  private data: Uint8Array | null = null;
  private filesize: bigint = 0n;
  private spaceid: AddrSpace | null = null;

  constructor(f: string) {
    super(f);
  }

  /** Attach the raw image to a particular address space */
  attachToSpace(id: AddrSpace): void {
    this.spaceid = id;
  }

  /**
   * Open the raw data for reading.
   * In the TypeScript translation, raw binary data must be set via setData()
   * since there is no direct filesystem access as in C++.
   */
  open(): void {
    if (this.data !== null) {
      throw new LowlevelError('loadimage is already open');
    }
    throw new LowlevelError('RawLoadImage.open() requires setData() in TypeScript');
  }

  /**
   * Provide the raw binary data directly.
   */
  setData(buf: Uint8Array): void {
    if (this.data !== null) {
      throw new LowlevelError('loadimage is already open');
    }
    this.data = buf;
    this.filesize = BigInt(buf.length);
  }

  getArchType(): string {
    return 'unknown';
  }

  adjustVma(adjust: number): void {
    const byteAdjust = AddrSpace.addressToByte(BigInt(adjust), this.spaceid!.getWordSize());
    this.vma += byteAdjust;
  }

  loadFill(ptr: Uint8Array, size: number, addr: Address): void {
    let curaddr: bigint = addr.getOffset();
    let offset: number = 0;
    let readsize: number;

    curaddr -= this.vma; // Get relative offset of first byte
    while (size > 0) {
      if (curaddr >= this.filesize) {
        if (offset === 0) break; // Initial address not within file
        ptr.fill(0, offset, offset + size); // Fill rest with 0
        return;
      }
      readsize = size;
      if (curaddr + BigInt(readsize) > this.filesize) {
        readsize = Number(this.filesize - curaddr);
      }
      // Copy from data buffer
      if (this.data !== null) {
        for (let i = 0; i < readsize; i++) {
          ptr[offset + i] = this.data[Number(curaddr) + i];
        }
      }
      offset += readsize;
      size -= readsize;
      curaddr += BigInt(readsize);
    }
    if (size > 0) {
      const shortcut = addr.getShortcut();
      const raw = addr.printRaw();
      throw new DataUnavailError(
        `Unable to load ${size} bytes at ${shortcut}${raw}`
      );
    }
  }
}

// ---------------------------------------------------------------------------
// LoadImageXml
// ---------------------------------------------------------------------------

/**
 * Implementation of the LoadImage interface using underlying data stored
 * in an XML format.
 *
 * The image data is stored in an XML file with a <binaryimage> root element.
 * The data is encoded in <bytechunk> and potentially <symbol> elements.
 */
export class LoadImageXml extends LoadImage {
  private rootel: Element | null;
  private archtype: string;
  private manage: AddrSpaceManager | null = null;
  private readonlyset: SortedSet<Address>;
  private chunk: SortedMap<Address, Uint8Array>;
  private addrtosymbol: SortedMap<Address, string>;
  private cursymbolIter: SortedMapIterator<Address, string> | null = null;

  /**
   * Constructor.
   * @param f - the path to the underlying XML file
   * @param el - the parsed form of the file (root Element)
   */
  constructor(f: string, el: Element) {
    super(f);
    this.rootel = el;
    this.readonlyset = new SortedSet<Address>(addressCompare);
    this.chunk = new SortedMap<Address, Uint8Array>(addressCompare);
    this.addrtosymbol = new SortedMap<Address, string>(addressCompare);

    // Extract architecture information
    if (el.getName() !== 'binaryimage') {
      throw new LowlevelError('Missing binaryimage tag in ' + this.filename);
    }
    this.archtype = el.getAttributeValue('arch');
  }

  /**
   * Read XML tags into the containers.
   * @param m - address space manager for looking up address spaces
   */
  open(m: AddrSpaceManager): void {
    this.manage = m;
    const sizeRef = { val: 0 as uint4 };

    // Read parsed xml file
    const decoder: Decoder = new XmlDecode(m, this.rootel);
    const elemId: number = decoder.openElementId(ELEM_BINARYIMAGE);
    for (;;) {
      const subId: number = decoder.openElement();
      if (subId === 0) break;
      if (subId === ELEM_SYMBOL.getId()) {
        const base = decoder.readSpaceById(ATTRIB_SPACE) as unknown as AddrSpace;
        const off: bigint = (base as any).decodeAttributes_sized(decoder, sizeRef);
        const addr = new Address(base, off);
        const nm: string = decoder.readStringById(ATTRIB_NAME);
        this.addrtosymbol.set(addr, nm);
      } else if (subId === ELEM_BYTECHUNK.getId()) {
        const base = decoder.readSpaceById(ATTRIB_SPACE) as unknown as AddrSpace;
        const off: bigint = (base as any).decodeAttributes_sized(decoder, sizeRef);
        const addr = new Address(base, off);
        const vec: number[] = [];

        decoder.rewindAttributes();
        for (;;) {
          const attribId: number = decoder.getNextAttributeId();
          if (attribId === 0) break;
          if (attribId === ATTRIB_READONLY.getId()) {
            if (decoder.readBool()) {
              this.readonlyset.insert(addr);
            }
          }
        }
        const content: string = decoder.readStringById(ATTRIB_CONTENT);
        // Parse hex string content
        const trimmed = content.replace(/\s+/g, '');
        for (let i = 0; i + 1 < trimmed.length; i += 2) {
          const byte = parseInt(trimmed.substring(i, i + 2), 16);
          if (!isNaN(byte)) {
            vec.push(byte);
          }
        }
        this.chunk.set(addr, new Uint8Array(vec));
      } else {
        throw new LowlevelError('Unknown LoadImageXml tag');
      }
      decoder.closeElement(subId);
    }
    decoder.closeElement(elemId);
    this.pad();
  }

  /** Clear out all the caches */
  clear(): void {
    this.archtype = '';
    this.manage = null;
    this.chunk.clear();
    this.addrtosymbol.clear();
    this.readonlyset.clear();
  }

  /**
   * Encode the image to a stream.
   * @param encoder - the stream encoder
   */
  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_BINARYIMAGE);
    encoder.writeString(ATTRIB_ARCH, this.archtype);

    for (const [addr, vec] of this.chunk.entries()) {
      if (vec.length === 0) continue;
      encoder.openElement(ELEM_BYTECHUNK);
      addr.getSpace()!.encodeAttributes(encoder, addr.getOffset());
      if (this.readonlyset.has(addr)) {
        encoder.writeBool(ATTRIB_READONLY, true);
      }
      let s = '\n';
      for (let i = 0; i < vec.length; i++) {
        s += vec[i].toString(16).padStart(2, '0');
        if (i % 20 === 19) {
          s += '\n';
        }
      }
      s += '\n';
      encoder.writeString(ATTRIB_CONTENT, s);
      encoder.closeElement(ELEM_BYTECHUNK);
    }

    for (const [addr, name] of this.addrtosymbol.entries()) {
      encoder.openElement(ELEM_SYMBOL);
      addr.getSpace()!.encodeAttributes(encoder, addr.getOffset());
      encoder.writeString(ATTRIB_NAME, name);
      encoder.closeElement(ELEM_SYMBOL);
    }
    encoder.closeElement(ELEM_BINARYIMAGE);
  }

  loadFill(ptr: Uint8Array, size: number, addr: Address): void {
    let curaddr = new Address(addr);
    let emptyhit = false;
    let ptrOffset = 0;

    // Find the last chunk whose address is <= curaddr
    let iter = this.chunk.upper_bound(curaddr); // First one greater than
    if (!iter.equals(this.chunk.begin())) {
      iter.prev(); // Last one less or equal
    }
    while (size > 0 && !iter.equals(this.chunk.end())) {
      const chnk: Uint8Array = iter.value;
      let chnksize: number = chnk.length;
      const chunkAddr: Address = iter.key;
      const over: number = curaddr.overlap(0, chunkAddr, chnksize);
      if (over !== -1) {
        if (chnksize - over > size) {
          chnksize = over + size;
        }
        for (let i = over; i < chnksize; i++) {
          ptr[ptrOffset++] = chnk[i];
        }
        size -= (chnksize - over);
        curaddr = curaddr.add(BigInt(chnksize - over));
        iter.next();
      } else {
        emptyhit = true;
        break;
      }
    }
    if (size > 0 || emptyhit) {
      throw new DataUnavailError(
        'Bytes at ' + curaddr.printRaw() + ' are not mapped'
      );
    }
  }

  openSymbols(): void {
    this.cursymbolIter = this.addrtosymbol.begin();
  }

  getNextSymbol(record: LoadImageFunc): boolean {
    if (this.cursymbolIter === null || this.cursymbolIter.equals(this.addrtosymbol.end())) {
      return false;
    }
    record.name = this.cursymbolIter.value;
    record.address = this.cursymbolIter.key;
    this.cursymbolIter.next();
    return true;
  }

  getReadonly(list: RangeList): void {
    for (const [addr, vec] of this.chunk.entries()) {
      if (this.readonlyset.has(addr)) {
        const start: bigint = addr.getOffset();
        const stop: bigint = start + BigInt(vec.length) - 1n;
        list.insertRange(addr.getSpace()!, start, stop);
      }
    }
  }

  getArchType(): string {
    return this.archtype;
  }

  adjustVma(adjust: number): void {
    const newchunk = new SortedMap<Address, Uint8Array>(addressCompare);
    const newsymbol = new SortedMap<Address, string>(addressCompare);

    for (const [addr, vec] of this.chunk.entries()) {
      const spc = addr.getSpace()!;
      const off = Number(AddrSpace.addressToByte(BigInt(adjust), spc.getWordSize()));
      const newaddr = addr.add(BigInt(off));
      newchunk.set(newaddr, vec);
    }
    this.chunk = newchunk;

    for (const [addr, name] of this.addrtosymbol.entries()) {
      const spc = addr.getSpace()!;
      const off = Number(AddrSpace.addressToByte(BigInt(adjust), spc.getWordSize()));
      const newaddr = addr.add(BigInt(off));
      newsymbol.set(newaddr, name);
    }
    this.addrtosymbol = newsymbol;
  }

  /**
   * Make sure every chunk is followed by at least 512 bytes of pad.
   * Also remove completely redundant chunks.
   */
  private pad(): void {
    // Search for completely redundant chunks
    if (this.chunk.empty) return;

    let lastiter = this.chunk.begin();
    let iter = lastiter.clone();
    iter.next();
    while (!iter.equals(this.chunk.end())) {
      if (lastiter.key.getSpace() === iter.key.getSpace()) {
        const end1: bigint = lastiter.key.getOffset() + BigInt(lastiter.value.length) - 1n;
        const end2: bigint = iter.key.getOffset() + BigInt(iter.value.length) - 1n;
        if (end1 >= end2) {
          iter = this.chunk.erase(iter);
          continue;
        }
      }
      lastiter = iter.clone();
      iter.next();
    }

    iter = this.chunk.begin();
    while (!iter.equals(this.chunk.end())) {
      const iterAddr = iter.key;
      const iterVec = iter.value;
      const endaddr: Address = iterAddr.add(BigInt(iterVec.length));
      if (endaddr.lessThan(iterAddr)) {
        iter.next();
        continue; // All the way to end of space
      }
      iter.next();
      let maxsize: number = 512;
      const endSpace = endaddr.getSpace()!;
      let room: bigint = endSpace.getHighest() - endaddr.getOffset() + 1n;
      if (BigInt(maxsize) > room) {
        maxsize = Number(room);
      }
      if (!iter.equals(this.chunk.end()) && iter.key.getSpace() === endSpace) {
        if (endaddr.getOffset() >= iter.key.getOffset()) continue;
        room = iter.key.getOffset() - endaddr.getOffset();
        if (BigInt(maxsize) > room) {
          maxsize = Number(room);
        }
      }
      const padArr = new Uint8Array(maxsize); // already zero-filled
      this.chunk.set(endaddr, padArr);
    }
  }
}
