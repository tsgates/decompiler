/**
 * @file stringmanage.ts
 * @description Classes for decoding and storing string data, translated from stringmanage.hh/stringmanage.cc
 */

import { Writer } from '../util/writer.js';
import { StringWriter } from '../util/writer.js';
import { LowlevelError } from '../core/error.js';
import { Address } from '../core/address.js';
import type { AddrSpace } from '../core/space.js';
import {
  AttributeId,
  ElementId,
  Encoder,
  Decoder,
  ATTRIB_CONTENT,
} from '../core/marshal.js';
import { Datatype } from './type.js';

// ---------------------------------------------------------------------------
// Forward type declarations for types not defined in this file
// ---------------------------------------------------------------------------

type Architecture = any;

// ---------------------------------------------------------------------------
// Marshaling attribute/element IDs
// ---------------------------------------------------------------------------

export const ATTRIB_TRUNC = new AttributeId('trunc', 69);

export const ELEM_BYTES = new ElementId('bytes', 83);
export const ELEM_STRING = new ElementId('string', 84);
export const ELEM_STRINGMANAGE = new ElementId('stringmanage', 85);

// ---------------------------------------------------------------------------
// CRC32 utility (translated from crc32.hh/crc32.cc)
// ---------------------------------------------------------------------------

/**
 * CRC32 lookup table, matching the polynomial used in Ghidra's crc32.cc
 */
const crc_table: number[] = (function () {
  const table: number[] = new Array(256);
  for (let i = 0; i < 256; i++) {
    let reg = i;
    for (let j = 0; j < 8; j++) {
      if (reg & 1) {
        reg = (reg >>> 1) ^ 0xEDB88320;
      } else {
        reg = reg >>> 1;
      }
    }
    table[i] = reg >>> 0;
  }
  return table;
})();

function crc_update(reg: number, val: number): number {
  return ((reg >>> 8) ^ crc_table[(reg ^ val) & 0xFF]) >>> 0;
}

// ---------------------------------------------------------------------------
// StringManager
// ---------------------------------------------------------------------------

/**
 * String data (a sequence of bytes) stored by StringManager.
 */
class StringData {
  /** true if the string is truncated */
  isTruncated: boolean = false;
  /** UTF8 encoded string data */
  byteData: number[] = [];
}

/**
 * Storage for decoding and storing strings associated with an address.
 *
 * Looks at data in the loadimage to determine if it represents a "string". Decodes the string for
 * presentation in the output. Stores the decoded string until its needed for presentation. Strings are
 * associated with their starting address in memory. An internal string (that is not in the loadimage) can
 * be registered with the manager and will be associated with a constant.
 */
export class StringManager {
  protected stringMap: Map<string, StringData> = new Map();
  /** Reverse map from key back to Address, so we can iterate with the original Address */
  protected stringAddrMap: Map<string, Address> = new Map();
  protected maximumChars: number;

  /**
   * Translate/copy unicode to UTF8.
   * Assume the buffer contains a null terminated unicode encoded string.
   * Write the characters out (as UTF8) to the writer.
   * @param s - the output writer
   * @param buffer - the given byte buffer
   * @param size - the number of bytes in the buffer
   * @param charsize - specifies the encoding (1=UTF8 2=UTF16 4=UTF32)
   * @param bigend - true if (UTF16 and UTF32) are big endian encoded
   * @returns true if the byte array contains valid unicode
   */
  protected writeUnicode(s: Writer, buffer: Uint8Array, size: number, charsize: number, bigend: boolean): boolean {
    let i = 0;
    let count = 0;
    let skip = charsize;
    while (i < size) {
      const result = StringManager.getCodepoint(buffer, i, charsize, bigend);
      if (result.codepoint < 0) return false;
      if (result.codepoint === 0) break; // Terminator
      skip = result.skip;
      StringManager.writeUtf8(s, result.codepoint);
      i += skip;
      count += 1;
      if (count >= this.maximumChars)
        break;
    }
    return true;
  }

  /**
   * Translate and assign raw string data to a StringData object.
   *
   * The string data is provided as raw bytes. The data is translated to UTF-8 and truncated
   * to the maximumChars allowed by the manager.
   * @param data - the StringData object to populate
   * @param buf - the raw byte array
   * @param size - the number of bytes in the array
   * @param charsize - the size of unicode encoding
   * @param numChars - the number of characters in the encoding as returned by checkCharacters()
   * @param bigend - true if UTF-16 and UTF-32 elements are big endian encoded
   */
  protected assignStringData(data: StringData, buf: Uint8Array, size: number, charsize: number, numChars: number, bigend: boolean): void {
    if (charsize === 1 && numChars < this.maximumChars) {
      data.byteData = [];
      data.byteData.length = 0;
      for (let i = 0; i < size; i++) {
        data.byteData.push(buf[i]);
      }
    } else {
      // We need to translate to UTF8 and/or truncate
      const sw = new StringWriter();
      if (!this.writeUnicode(sw, buf, size, charsize, bigend))
        return;
      const resString = sw.toString();
      data.byteData = [];
      for (let i = 0; i < resString.length; i++) {
        data.byteData.push(resString.charCodeAt(i));
      }
      data.byteData.push(0); // Make sure there is a null terminator
    }
    data.isTruncated = (numChars >= this.maximumChars);
  }

  /**
   * Calculate hash of a specific Address and contents of a byte array.
   *
   * Calculate a 32-bit CRC of the bytes and XOR into the upper part of the Address offset.
   * @param addr - the specific Address
   * @param buf - a pointer to the array of bytes
   * @param size - the number of bytes in the array
   * @returns the 64-bit hash
   */
  static calcInternalHash(addr: Address, buf: Uint8Array, size: number): bigint {
    let reg = 0x7b7c66a9;
    for (let i = 0; i < size; ++i) {
      reg = crc_update(reg, buf[i]);
    }
    let res = addr.getOffset();
    res = res ^ (BigInt(reg >>> 0) << 32n);
    return res;
  }

  /**
   * Constructor
   * @param max - the maximum number of characters to allow before truncating string
   */
  constructor(max: number) {
    this.maximumChars = max;
  }

  /** Clear out any cached strings */
  clear(): void {
    this.stringMap.clear();
    this.stringAddrMap.clear();
  }

  /**
   * Returns true if the data is some kind of complete string.
   * A given character data-type can be used as a hint for the encoding.
   * The string decoding can be cached internally.
   * @param addr - the given address
   * @param charType - the given character data-type
   * @returns true if the address represents string data
   */
  isString(addr: Address, charType: Datatype): boolean {
    const result = this.getStringData(addr, charType);
    return result.byteData.length > 0;
  }

  /**
   * Retrieve string data at the given address as a UTF8 byte array.
   *
   * If the address does not represent string data, a zero length array is returned. Otherwise,
   * the string data is fetched, converted to a UTF8 encoding, cached and returned.
   * @param addr - the given address
   * @param charType - a character data-type indicating the encoding
   * @returns object with byteData and isTruncated flag
   */
  getStringData(addr: Address, charType: Datatype): { byteData: number[]; isTruncated: boolean } {
    // Base class: pure virtual in C++. Subclasses override.
    return { byteData: [], isTruncated: false };
  }

  /**
   * Associate string data at a code address or other location that doesn't hold string data normally.
   *
   * The given byte buffer is decoded, and if it represents a legal string, a non-zero hash is returned,
   * constructed from an Address associated with the string and the string data itself. The registered string
   * can be retrieved via the getStringData() method using this hash as a constant Address. If the string is not
   * legal, 0 is returned.
   * @param addr - the address to associate with the string data
   * @param buf - the raw byte array encoding the string
   * @param size - the number of bytes in the array
   * @param charType - a character data-type indicating the encoding
   * @returns a hash associated with the string or 0n
   */
  registerInternalStringData(addr: Address, buf: Uint8Array, size: number, charType: Datatype): bigint {
    const charsize = charType.getSize();
    const numChars = StringManager.checkCharacters(buf, size, charsize, addr.isBigEndian());
    if (numChars < 0)
      return 0n; // Not a legal encoding
    const hash = StringManager.calcInternalHash(addr, buf, size);
    const constAddr = addr.getSpace()!.getManager()!.getConstant(hash);
    const key = constAddr.toString();
    let stringData = this.stringMap.get(key);
    if (!stringData) {
      stringData = new StringData();
      this.stringMap.set(key, stringData);
      this.stringAddrMap.set(key, constAddr);
    }
    stringData.byteData = [];
    stringData.isTruncated = false;
    this.assignStringData(stringData, buf, size, charsize, numChars, addr.isBigEndian());
    return hash;
  }

  /**
   * Encode <stringmanage> element, with <string> children.
   * @param encoder - the stream encoder
   */
  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_STRINGMANAGE);

    for (const [key, stringData] of this.stringMap) {
      encoder.openElement(ELEM_STRING);
      const addr = this.stringAddrMap.get(key)!;
      // Encode address: open <addr>, write space attributes, close
      this._encodeAddress(encoder, addr);
      encoder.openElement(ELEM_BYTES);
      encoder.writeBool(ATTRIB_TRUNC, stringData.isTruncated);
      let s = '\n';
      for (let i = 0; i < stringData.byteData.length; ++i) {
        s += stringData.byteData[i].toString(16).padStart(2, '0');
        if (i % 20 === 19)
          s += '\n  ';
      }
      s += '\n';
      encoder.writeString(ATTRIB_CONTENT, s);
      encoder.closeElement(ELEM_BYTES);
    }
    encoder.closeElement(ELEM_STRINGMANAGE);
  }

  /**
   * Encode an address element. This mirrors Address::encode from the C++ code.
   */
  private _encodeAddress(encoder: Encoder, addr: Address): void {
    // Use the same approach as C++ Address::encode:
    // encoder.openElement(ELEM_ADDR); base->encodeAttributes(encoder, offset); encoder.closeElement(ELEM_ADDR);
    const ELEM_ADDR = new ElementId('addr', 11);
    encoder.openElement(ELEM_ADDR);
    if (addr.getSpace() !== null) {
      addr.getSpace()!.encodeAttributes(encoder, addr.getOffset());
    }
    encoder.closeElement(ELEM_ADDR);
  }

  /**
   * Decode an address element. This mirrors Address::decode from the C++ code.
   */
  private static _decodeAddress(decoder: Decoder): Address {
    // VarnodeData::decode reads the <addr> element attributes (space + offset)
    const ELEM_ADDR = new ElementId('addr', 11);
    const elemId = decoder.openElement();
    const spcManager = decoder.getAddrSpaceManager();
    if (spcManager === null) {
      throw new LowlevelError('No address space manager for decoding');
    }
    // Read space attribute
    const ATTRIB_SPACE_LOCAL = new AttributeId('space', 10);
    const spaceName = decoder.readStringById(ATTRIB_SPACE_LOCAL);
    const space = spcManager.getSpaceByName(spaceName);
    if (space === null) {
      throw new LowlevelError(`Unknown address space: ${spaceName}`);
    }
    const ATTRIB_OFFSET_LOCAL = new AttributeId('offset', 12);
    const offset = decoder.readUnsignedIntegerById(ATTRIB_OFFSET_LOCAL);
    decoder.closeElement(elemId);
    return new Address(space as any as AddrSpace, offset);
  }

  /**
   * Parse a <stringmanage> element, with <string> children.
   * @param decoder - the stream decoder
   */
  decode(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_STRINGMANAGE);
    for (;;) {
      const subId = decoder.openElement();
      if (subId !== ELEM_STRING.getId()) break;
      const addr = StringManager._decodeAddress(decoder);
      const key = addr.toString();
      let stringData = this.stringMap.get(key);
      if (!stringData) {
        stringData = new StringData();
        this.stringMap.set(key, stringData);
        this.stringAddrMap.set(key, addr);
      }
      const subId2 = decoder.openElementId(ELEM_BYTES);
      stringData.isTruncated = decoder.readBoolById(ATTRIB_TRUNC);
      const hexStr = decoder.readStringById(ATTRIB_CONTENT);
      // Parse hex pairs from the string, skipping whitespace
      let pos = 0;
      while (pos < hexStr.length) {
        // Skip whitespace
        while (pos < hexStr.length && /\s/.test(hexStr[pos])) {
          pos++;
        }
        if (pos + 1 >= hexStr.length) break;
        const c1 = hexStr[pos];
        const c2 = hexStr[pos + 1];
        if (c1 === undefined || c2 === undefined) break;
        const val = parseInt(c1 + c2, 16);
        if (isNaN(val)) break;
        stringData.byteData.push(val);
        pos += 2;
      }
      decoder.closeElement(subId2);
      decoder.closeElement(subId);
    }
    decoder.closeElement(elemId);
  }

  /**
   * Check for a unicode string terminator.
   * @param buffer - the byte buffer
   * @param size - the number of bytes in the buffer
   * @param charsize - the presumed size (in bytes) of character elements
   * @returns true if a string terminator is found
   */
  static hasCharTerminator(buffer: Uint8Array, size: number, charsize: number): boolean {
    for (let i = 0; i < size; i += charsize) {
      let isTerminator = true;
      for (let j = 0; j < charsize; ++j) {
        if (buffer[i + j] !== 0) {
          isTerminator = false;
          break;
        }
      }
      if (isTerminator) return true;
    }
    return false;
  }

  /**
   * Pull the first two bytes from the byte array and combine them in the indicated endian order.
   * @param buf - the byte array
   * @param offset - offset into buf
   * @param bigend - true to request big endian encoding
   * @returns the decoded UTF16 element
   */
  static readUtf16(buf: Uint8Array, offset: number, bigend: boolean): number {
    let codepoint: number;
    if (bigend) {
      codepoint = buf[offset];
      codepoint = (codepoint << 8) | 0;
      codepoint += buf[offset + 1];
    } else {
      codepoint = buf[offset + 1];
      codepoint = (codepoint << 8) | 0;
      codepoint += buf[offset];
    }
    return codepoint;
  }

  /**
   * Encode the given unicode codepoint as UTF8 (1, 2, 3, or 4 bytes) and
   * write the bytes to the writer.
   * @param s - the output writer
   * @param codepoint - the unicode codepoint
   */
  static writeUtf8(s: Writer, codepoint: number): void {
    if (codepoint < 0)
      throw new LowlevelError('Negative unicode codepoint');
    if (codepoint < 128) {
      s.write(String.fromCharCode(codepoint));
      return;
    }
    // mostsigbit_set operates on bigint but codepoint is number.
    // We compute bits directly for a 32-bit number.
    const bits = 32 - Math.clz32(codepoint);
    if (bits > 21)
      throw new LowlevelError('Bad unicode codepoint');
    const bytes: number[] = [];
    let size: number;
    if (bits < 12) { // Encode with two bytes
      bytes[0] = 0xc0 | ((codepoint >> 6) & 0x1f);
      bytes[1] = 0x80 | (codepoint & 0x3f);
      size = 2;
    } else if (bits < 17) {
      bytes[0] = 0xe0 | ((codepoint >> 12) & 0xf);
      bytes[1] = 0x80 | ((codepoint >> 6) & 0x3f);
      bytes[2] = 0x80 | (codepoint & 0x3f);
      size = 3;
    } else {
      bytes[0] = 0xf0 | ((codepoint >> 18) & 7);
      bytes[1] = 0x80 | ((codepoint >> 12) & 0x3f);
      bytes[2] = 0x80 | ((codepoint >> 6) & 0x3f);
      bytes[3] = 0x80 | (codepoint & 0x3f);
      size = 4;
    }
    let str = '';
    for (let i = 0; i < size; i++) {
      str += String.fromCharCode(bytes[i]);
    }
    s.write(str);
  }

  /**
   * Make sure buffer has valid bounded set of unicode.
   *
   * Check that the given buffer contains valid unicode.
   * If the string is encoded in UTF8 or ASCII, we get (on average) a bit of check
   * per character. For UTF16, the surrogate reserved area gives at least some check.
   * @param buf - the byte array to check
   * @param size - the size of the buffer in bytes
   * @param charsize - the UTF encoding (1=UTF8, 2=UTF16, 4=UTF32)
   * @param bigend - true if the (UTF16 and UTF32) characters are big endian encoded
   * @returns the number of characters or -1 if there is an invalid encoding
   */
  static checkCharacters(buf: Uint8Array, size: number, charsize: number, bigend: boolean): number {
    if (buf === null || buf === undefined) return -1;
    let i = 0;
    let count = 0;
    let skip = charsize;
    while (i < size) {
      const result = StringManager.getCodepoint(buf, i, charsize, bigend);
      if (result.codepoint < 0) return -1;
      if (result.codepoint === 0) break;
      count += 1;
      skip = result.skip;
      i += skip;
    }
    return count;
  }

  /**
   * Extract next unicode codepoint from the buffer.
   * One or more bytes is consumed from the array, and the number of bytes used is passed back.
   * @param buf - the bytes in the character array
   * @param offset - starting offset into buf
   * @param charsize - 1 for UTF8, 2 for UTF16, or 4 for UTF32
   * @param bigend - true for big endian encoding of the UTF element
   * @returns object containing codepoint and skip (bytes consumed), codepoint is -1 on error
   */
  static getCodepoint(buf: Uint8Array, offset: number, charsize: number, bigend: boolean): { codepoint: number; skip: number } {
    let codepoint: number;
    let sk = 0;
    if (charsize === 2) { // UTF-16
      codepoint = StringManager.readUtf16(buf, offset, bigend);
      sk += 2;
      if ((codepoint >= 0xD800) && (codepoint <= 0xDBFF)) { // high surrogate
        const trail = StringManager.readUtf16(buf, offset + 2, bigend);
        sk += 2;
        if ((trail < 0xDC00) || (trail > 0xDFFF)) return { codepoint: -1, skip: sk }; // Bad trail
        codepoint = (codepoint << 10) + trail + (0x10000 - (0xD800 << 10) - 0xDC00);
      } else if ((codepoint >= 0xDC00) && (codepoint <= 0xDFFF)) {
        return { codepoint: -1, skip: sk }; // trail before high
      }
    } else if (charsize === 1) { // UTF-8
      const val = buf[offset];
      if ((val & 0x80) === 0) {
        codepoint = val;
        sk = 1;
      } else if ((val & 0xe0) === 0xc0) {
        const val2 = buf[offset + 1];
        sk = 2;
        if ((val2 & 0xc0) !== 0x80) return { codepoint: -1, skip: sk }; // Not a valid UTF8-encoding
        codepoint = ((val & 0x1f) << 6) | (val2 & 0x3f);
      } else if ((val & 0xf0) === 0xe0) {
        const val2 = buf[offset + 1];
        const val3 = buf[offset + 2];
        sk = 3;
        if (((val2 & 0xc0) !== 0x80) || ((val3 & 0xc0) !== 0x80)) return { codepoint: -1, skip: sk }; // invalid encoding
        codepoint = ((val & 0xf) << 12) | ((val2 & 0x3f) << 6) | (val3 & 0x3f);
      } else if ((val & 0xf8) === 0xf0) {
        const val2 = buf[offset + 1];
        const val3 = buf[offset + 2];
        const val4 = buf[offset + 3];
        sk = 4;
        if (((val2 & 0xc0) !== 0x80) || ((val3 & 0xc0) !== 0x80) || ((val4 & 0xc0) !== 0x80)) return { codepoint: -1, skip: sk }; // invalid encoding
        codepoint = ((val & 7) << 18) | ((val2 & 0x3f) << 12) | ((val3 & 0x3f) << 6) | (val4 & 0x3f);
      } else {
        return { codepoint: -1, skip: 0 };
      }
    } else if (charsize === 4) { // UTF-32
      sk = 4;
      if (bigend)
        codepoint = (buf[offset] << 24) + (buf[offset + 1] << 16) + (buf[offset + 2] << 8) + buf[offset + 3];
      else
        codepoint = (buf[offset + 3] << 24) + (buf[offset + 2] << 16) + (buf[offset + 1] << 8) + buf[offset];
    } else {
      return { codepoint: -1, skip: 0 };
    }
    if (codepoint! >= 0xd800) {
      if (codepoint! > 0x10ffff) // Bigger than maximum codepoint
        return { codepoint: -1, skip: sk };
      if (codepoint! <= 0xdfff)
        return { codepoint: -1, skip: sk }; // Reserved for surrogates, invalid codepoints
    }
    return { codepoint: codepoint!, skip: sk };
  }

  /**
   * Helper: get a StringData entry from the map by Address.
   */
  protected getStringDataByAddr(addr: Address): StringData | undefined {
    return this.stringMap.get(addr.toString());
  }

  /**
   * Helper: set a StringData entry in the map by Address.
   */
  protected setStringDataByAddr(addr: Address, data: StringData): void {
    const key = addr.toString();
    this.stringMap.set(key, data);
    this.stringAddrMap.set(key, addr);
  }
}

// ---------------------------------------------------------------------------
// StringManagerUnicode
// ---------------------------------------------------------------------------

/**
 * An implementation of StringManager that understands terminated unicode strings.
 *
 * This class understands UTF8, UTF16, and UTF32 encodings. It reports a string if it
 * sees a valid encoding that is null terminated.
 */
export class StringManagerUnicode extends StringManager {
  private glb: Architecture;
  private testBuffer: Uint8Array;

  /**
   * Constructor
   * @param g - the underlying architecture (and loadimage)
   * @param max - the maximum number of bytes to allow in a decoded string
   */
  constructor(g: Architecture, max: number) {
    super(max);
    this.glb = g;
    this.testBuffer = new Uint8Array(max);
  }

  /**
   * Retrieve string data at the given address as a UTF8 byte array.
   *
   * If the address does not represent string data, a zero length array is returned. Otherwise,
   * the string data is fetched, converted to a UTF8 encoding, cached and returned.
   * @param addr - the given address
   * @param charType - a character data-type indicating the encoding
   * @returns object with byteData and isTruncated flag
   */
  override getStringData(addr: Address, charType: Datatype): { byteData: number[]; isTruncated: boolean } {
    const existing = this.getStringDataByAddr(addr);
    if (existing !== undefined) {
      return { byteData: existing.byteData, isTruncated: existing.isTruncated };
    }

    const stringData = new StringData();
    stringData.isTruncated = false;
    this.setStringDataByAddr(addr, stringData);

    if (charType.isOpaqueString()) // Cannot currently test for an opaque encoding
      return { byteData: stringData.byteData, isTruncated: stringData.isTruncated }; // Return the empty buffer

    let curBufferSize = 0;
    const charsize = charType.getSize();
    let foundTerminator = false;

    try {
      do {
        let amount = 32; // Grab 32 bytes of image at a time
        let newBufferSize = curBufferSize + amount;
        if (newBufferSize > this.maximumChars) {
          newBufferSize = this.maximumChars;
          amount = newBufferSize - curBufferSize;
          if (amount === 0) {
            return { byteData: stringData.byteData, isTruncated: stringData.isTruncated }; // Could not find terminator
          }
        }
        this.glb.loader.loadFill(
          this.testBuffer.subarray(curBufferSize, curBufferSize + amount),
          amount,
          addr.add(BigInt(curBufferSize))
        );
        foundTerminator = StringManager.hasCharTerminator(
          this.testBuffer.subarray(curBufferSize, curBufferSize + amount),
          amount,
          charsize
        );
        curBufferSize = newBufferSize;
      } while (!foundTerminator);
    } catch (err: any) {
      // DataUnavailError equivalent
      return { byteData: stringData.byteData, isTruncated: stringData.isTruncated }; // Return the empty buffer
    }

    const numChars = StringManager.checkCharacters(this.testBuffer.subarray(0, curBufferSize), curBufferSize, charsize, addr.isBigEndian());
    if (numChars < 0)
      return { byteData: stringData.byteData, isTruncated: stringData.isTruncated }; // Return the empty buffer (invalid encoding)
    this.assignStringData(stringData, this.testBuffer.subarray(0, curBufferSize), curBufferSize, charsize, numChars, addr.isBigEndian());
    return { byteData: stringData.byteData, isTruncated: stringData.isTruncated };
  }
}
