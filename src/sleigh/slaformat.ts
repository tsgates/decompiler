/**
 * @file slaformat.ts
 * @description Encoding values for the SLA file format.
 *
 * Translated from Ghidra's slaformat.hh / slaformat.cc.
 * This module handles the .sla binary format -- reading pre-compiled SLEIGH specification files.
 * It defines format version numbers, element types, and the binary encoding for the SLEIGH format.
 */

import * as zlib from 'zlib';
import { LowlevelError } from '../core/error.js';
import {
  AttributeId,
  ElementId,
  PackedDecode,
  PackedEncode,
} from '../core/marshal.js';
import type { AddrSpaceManager } from '../core/marshal.js';

// =========================================================================
// Format constants
// =========================================================================

/** Grouping elements/attributes for SLA file format */
export const FORMAT_SCOPE: number = 1;

/** Current version of the .sla file */
export const FORMAT_VERSION: number = 4;

/** Minimum accepted SLEIGH spec version in the .sla data attributes */
export const MIN_SLEIGH_VERSION: number = 4;
/** Maximum accepted SLEIGH spec version in the .sla data attributes */
export const MAX_SLEIGH_VERSION: number = 30;

// =========================================================================
// SLA format AttributeId instances
// =========================================================================

// ATTRIB_CONTEXT = 1 is reserved
export const SLA_ATTRIB_VAL = new AttributeId('val', 2, FORMAT_SCOPE);
export const SLA_ATTRIB_ID = new AttributeId('id', 3, FORMAT_SCOPE);
export const SLA_ATTRIB_SPACE = new AttributeId('space', 4, FORMAT_SCOPE);
export const SLA_ATTRIB_S = new AttributeId('s', 5, FORMAT_SCOPE);
export const SLA_ATTRIB_OFF = new AttributeId('off', 6, FORMAT_SCOPE);
export const SLA_ATTRIB_CODE = new AttributeId('code', 7, FORMAT_SCOPE);
export const SLA_ATTRIB_MASK = new AttributeId('mask', 8, FORMAT_SCOPE);
export const SLA_ATTRIB_INDEX = new AttributeId('index', 9, FORMAT_SCOPE);
export const SLA_ATTRIB_NONZERO = new AttributeId('nonzero', 10, FORMAT_SCOPE);
export const SLA_ATTRIB_PIECE = new AttributeId('piece', 11, FORMAT_SCOPE);
export const SLA_ATTRIB_NAME = new AttributeId('name', 12, FORMAT_SCOPE);
export const SLA_ATTRIB_SCOPE = new AttributeId('scope', 13, FORMAT_SCOPE);
export const SLA_ATTRIB_STARTBIT = new AttributeId('startbit', 14, FORMAT_SCOPE);
export const SLA_ATTRIB_SIZE = new AttributeId('size', 15, FORMAT_SCOPE);
export const SLA_ATTRIB_TABLE = new AttributeId('table', 16, FORMAT_SCOPE);
export const SLA_ATTRIB_CT = new AttributeId('ct', 17, FORMAT_SCOPE);
export const SLA_ATTRIB_MINLEN = new AttributeId('minlen', 18, FORMAT_SCOPE);
export const SLA_ATTRIB_BASE = new AttributeId('base', 19, FORMAT_SCOPE);
export const SLA_ATTRIB_NUMBER = new AttributeId('number', 20, FORMAT_SCOPE);
export const SLA_ATTRIB_CONTEXT = new AttributeId('context', 21, FORMAT_SCOPE);
export const SLA_ATTRIB_PARENT = new AttributeId('parent', 22, FORMAT_SCOPE);
export const SLA_ATTRIB_SUBSYM = new AttributeId('subsym', 23, FORMAT_SCOPE);
export const SLA_ATTRIB_LINE = new AttributeId('line', 24, FORMAT_SCOPE);
export const SLA_ATTRIB_SOURCE = new AttributeId('source', 25, FORMAT_SCOPE);
export const SLA_ATTRIB_LENGTH = new AttributeId('length', 26, FORMAT_SCOPE);
export const SLA_ATTRIB_FIRST = new AttributeId('first', 27, FORMAT_SCOPE);
export const SLA_ATTRIB_PLUS = new AttributeId('plus', 28, FORMAT_SCOPE);
export const SLA_ATTRIB_SHIFT = new AttributeId('shift', 29, FORMAT_SCOPE);
export const SLA_ATTRIB_ENDBIT = new AttributeId('endbit', 30, FORMAT_SCOPE);
export const SLA_ATTRIB_SIGNBIT = new AttributeId('signbit', 31, FORMAT_SCOPE);
export const SLA_ATTRIB_ENDBYTE = new AttributeId('endbyte', 32, FORMAT_SCOPE);
export const SLA_ATTRIB_STARTBYTE = new AttributeId('startbyte', 33, FORMAT_SCOPE);

export const SLA_ATTRIB_VERSION = new AttributeId('version', 34, FORMAT_SCOPE);
export const SLA_ATTRIB_BIGENDIAN = new AttributeId('bigendian', 35, FORMAT_SCOPE);
export const SLA_ATTRIB_ALIGN = new AttributeId('align', 36, FORMAT_SCOPE);
export const SLA_ATTRIB_UNIQBASE = new AttributeId('uniqbase', 37, FORMAT_SCOPE);
export const SLA_ATTRIB_MAXDELAY = new AttributeId('maxdelay', 38, FORMAT_SCOPE);
export const SLA_ATTRIB_UNIQMASK = new AttributeId('uniqmask', 39, FORMAT_SCOPE);
export const SLA_ATTRIB_NUMSECTIONS = new AttributeId('numsections', 40, FORMAT_SCOPE);
export const SLA_ATTRIB_DEFAULTSPACE = new AttributeId('defaultspace', 41, FORMAT_SCOPE);
export const SLA_ATTRIB_DELAY = new AttributeId('delay', 42, FORMAT_SCOPE);
export const SLA_ATTRIB_WORDSIZE = new AttributeId('wordsize', 43, FORMAT_SCOPE);
export const SLA_ATTRIB_PHYSICAL = new AttributeId('physical', 44, FORMAT_SCOPE);
export const SLA_ATTRIB_SCOPESIZE = new AttributeId('scopesize', 45, FORMAT_SCOPE);
export const SLA_ATTRIB_SYMBOLSIZE = new AttributeId('symbolsize', 46, FORMAT_SCOPE);
export const SLA_ATTRIB_VARNODE = new AttributeId('varnode', 47, FORMAT_SCOPE);
export const SLA_ATTRIB_LOW = new AttributeId('low', 48, FORMAT_SCOPE);
export const SLA_ATTRIB_HIGH = new AttributeId('high', 49, FORMAT_SCOPE);
export const SLA_ATTRIB_FLOW = new AttributeId('flow', 50, FORMAT_SCOPE);
export const SLA_ATTRIB_CONTAIN = new AttributeId('contain', 51, FORMAT_SCOPE);
export const SLA_ATTRIB_I = new AttributeId('i', 52, FORMAT_SCOPE);
export const SLA_ATTRIB_NUMCT = new AttributeId('numct', 53, FORMAT_SCOPE);
export const SLA_ATTRIB_SECTION = new AttributeId('section', 54, FORMAT_SCOPE);
export const SLA_ATTRIB_LABELS = new AttributeId('labels', 55, FORMAT_SCOPE);

// =========================================================================
// SLA format ElementId instances
// =========================================================================

export const SLA_ELEM_CONST_REAL = new ElementId('const_real', 1, FORMAT_SCOPE);
export const SLA_ELEM_VARNODE_TPL = new ElementId('varnode_tpl', 2, FORMAT_SCOPE);
export const SLA_ELEM_CONST_SPACEID = new ElementId('const_spaceid', 3, FORMAT_SCOPE);
export const SLA_ELEM_CONST_HANDLE = new ElementId('const_handle', 4, FORMAT_SCOPE);
export const SLA_ELEM_OP_TPL = new ElementId('op_tpl', 5, FORMAT_SCOPE);
export const SLA_ELEM_MASK_WORD = new ElementId('mask_word', 6, FORMAT_SCOPE);
export const SLA_ELEM_PAT_BLOCK = new ElementId('pat_block', 7, FORMAT_SCOPE);
export const SLA_ELEM_PRINT = new ElementId('print', 8, FORMAT_SCOPE);
export const SLA_ELEM_PAIR = new ElementId('pair', 9, FORMAT_SCOPE);
export const SLA_ELEM_CONTEXT_PAT = new ElementId('context_pat', 10, FORMAT_SCOPE);
export const SLA_ELEM_NULL = new ElementId('null', 11, FORMAT_SCOPE);
export const SLA_ELEM_OPERAND_EXP = new ElementId('operand_exp', 12, FORMAT_SCOPE);
export const SLA_ELEM_OPERAND_SYM = new ElementId('operand_sym', 13, FORMAT_SCOPE);
export const SLA_ELEM_OPERAND_SYM_HEAD = new ElementId('operand_sym_head', 14, FORMAT_SCOPE);
export const SLA_ELEM_OPER = new ElementId('oper', 15, FORMAT_SCOPE);
export const SLA_ELEM_DECISION = new ElementId('decision', 16, FORMAT_SCOPE);
export const SLA_ELEM_OPPRINT = new ElementId('opprint', 17, FORMAT_SCOPE);
export const SLA_ELEM_INSTRUCT_PAT = new ElementId('instruct_pat', 18, FORMAT_SCOPE);
export const SLA_ELEM_COMBINE_PAT = new ElementId('combine_pat', 19, FORMAT_SCOPE);
export const SLA_ELEM_CONSTRUCTOR = new ElementId('constructor', 20, FORMAT_SCOPE);
export const SLA_ELEM_CONSTRUCT_TPL = new ElementId('construct_tpl', 21, FORMAT_SCOPE);
export const SLA_ELEM_SCOPE = new ElementId('scope', 22, FORMAT_SCOPE);
export const SLA_ELEM_VARNODE_SYM = new ElementId('varnode_sym', 23, FORMAT_SCOPE);
export const SLA_ELEM_VARNODE_SYM_HEAD = new ElementId('varnode_sym_head', 24, FORMAT_SCOPE);
export const SLA_ELEM_USEROP = new ElementId('userop', 25, FORMAT_SCOPE);
export const SLA_ELEM_USEROP_HEAD = new ElementId('userop_head', 26, FORMAT_SCOPE);
export const SLA_ELEM_TOKENFIELD = new ElementId('tokenfield', 27, FORMAT_SCOPE);
export const SLA_ELEM_VAR = new ElementId('var', 28, FORMAT_SCOPE);
export const SLA_ELEM_CONTEXTFIELD = new ElementId('contextfield', 29, FORMAT_SCOPE);
export const SLA_ELEM_HANDLE_TPL = new ElementId('handle_tpl', 30, FORMAT_SCOPE);
export const SLA_ELEM_CONST_RELATIVE = new ElementId('const_relative', 31, FORMAT_SCOPE);
export const SLA_ELEM_CONTEXT_OP = new ElementId('context_op', 32, FORMAT_SCOPE);

export const SLA_ELEM_SLEIGH = new ElementId('sleigh', 33, FORMAT_SCOPE);
export const SLA_ELEM_SPACES = new ElementId('spaces', 34, FORMAT_SCOPE);
export const SLA_ELEM_SOURCEFILES = new ElementId('sourcefiles', 35, FORMAT_SCOPE);
export const SLA_ELEM_SOURCEFILE = new ElementId('sourcefile', 36, FORMAT_SCOPE);
export const SLA_ELEM_SPACE = new ElementId('space', 37, FORMAT_SCOPE);
export const SLA_ELEM_SYMBOL_TABLE = new ElementId('symbol_table', 38, FORMAT_SCOPE);
export const SLA_ELEM_VALUE_SYM = new ElementId('value_sym', 39, FORMAT_SCOPE);
export const SLA_ELEM_VALUE_SYM_HEAD = new ElementId('value_sym_head', 40, FORMAT_SCOPE);
export const SLA_ELEM_CONTEXT_SYM = new ElementId('context_sym', 41, FORMAT_SCOPE);
export const SLA_ELEM_CONTEXT_SYM_HEAD = new ElementId('context_sym_head', 42, FORMAT_SCOPE);
export const SLA_ELEM_END_SYM = new ElementId('end_sym', 43, FORMAT_SCOPE);
export const SLA_ELEM_END_SYM_HEAD = new ElementId('end_sym_head', 44, FORMAT_SCOPE);
export const SLA_ELEM_SPACE_OTHER = new ElementId('space_other', 45, FORMAT_SCOPE);
export const SLA_ELEM_SPACE_UNIQUE = new ElementId('space_unique', 46, FORMAT_SCOPE);
export const SLA_ELEM_AND_EXP = new ElementId('and_exp', 47, FORMAT_SCOPE);
export const SLA_ELEM_DIV_EXP = new ElementId('div_exp', 48, FORMAT_SCOPE);
export const SLA_ELEM_LSHIFT_EXP = new ElementId('lshift_exp', 49, FORMAT_SCOPE);
export const SLA_ELEM_MINUS_EXP = new ElementId('minus_exp', 50, FORMAT_SCOPE);
export const SLA_ELEM_MULT_EXP = new ElementId('mult_exp', 51, FORMAT_SCOPE);
export const SLA_ELEM_NOT_EXP = new ElementId('not_exp', 52, FORMAT_SCOPE);
export const SLA_ELEM_OR_EXP = new ElementId('or_exp', 53, FORMAT_SCOPE);
export const SLA_ELEM_PLUS_EXP = new ElementId('plus_exp', 54, FORMAT_SCOPE);
export const SLA_ELEM_RSHIFT_EXP = new ElementId('rshift_exp', 55, FORMAT_SCOPE);
export const SLA_ELEM_SUB_EXP = new ElementId('sub_exp', 56, FORMAT_SCOPE);
export const SLA_ELEM_XOR_EXP = new ElementId('xor_exp', 57, FORMAT_SCOPE);
export const SLA_ELEM_INTB = new ElementId('intb', 58, FORMAT_SCOPE);
export const SLA_ELEM_END_EXP = new ElementId('end_exp', 59, FORMAT_SCOPE);
export const SLA_ELEM_NEXT2_EXP = new ElementId('next2_exp', 60, FORMAT_SCOPE);
export const SLA_ELEM_START_EXP = new ElementId('start_exp', 61, FORMAT_SCOPE);
export const SLA_ELEM_EPSILON_SYM = new ElementId('epsilon_sym', 62, FORMAT_SCOPE);
export const SLA_ELEM_EPSILON_SYM_HEAD = new ElementId('epsilon_sym_head', 63, FORMAT_SCOPE);
export const SLA_ELEM_NAME_SYM = new ElementId('name_sym', 64, FORMAT_SCOPE);
export const SLA_ELEM_NAME_SYM_HEAD = new ElementId('name_sym_head', 65, FORMAT_SCOPE);
export const SLA_ELEM_NAMETAB = new ElementId('nametab', 66, FORMAT_SCOPE);
export const SLA_ELEM_NEXT2_SYM = new ElementId('next2_sym', 67, FORMAT_SCOPE);
export const SLA_ELEM_NEXT2_SYM_HEAD = new ElementId('next2_sym_head', 68, FORMAT_SCOPE);
export const SLA_ELEM_START_SYM = new ElementId('start_sym', 69, FORMAT_SCOPE);
export const SLA_ELEM_START_SYM_HEAD = new ElementId('start_sym_head', 70, FORMAT_SCOPE);
export const SLA_ELEM_SUBTABLE_SYM = new ElementId('subtable_sym', 71, FORMAT_SCOPE);
export const SLA_ELEM_SUBTABLE_SYM_HEAD = new ElementId('subtable_sym_head', 72, FORMAT_SCOPE);
export const SLA_ELEM_VALUEMAP_SYM = new ElementId('valuemap_sym', 73, FORMAT_SCOPE);
export const SLA_ELEM_VALUEMAP_SYM_HEAD = new ElementId('valuemap_sym_head', 74, FORMAT_SCOPE);
export const SLA_ELEM_VALUETAB = new ElementId('valuetab', 75, FORMAT_SCOPE);
export const SLA_ELEM_VARLIST_SYM = new ElementId('varlist_sym', 76, FORMAT_SCOPE);
export const SLA_ELEM_VARLIST_SYM_HEAD = new ElementId('varlist_sym_head', 77, FORMAT_SCOPE);
export const SLA_ELEM_OR_PAT = new ElementId('or_pat', 78, FORMAT_SCOPE);
export const SLA_ELEM_COMMIT = new ElementId('commit', 79, FORMAT_SCOPE);
export const SLA_ELEM_CONST_START = new ElementId('const_start', 80, FORMAT_SCOPE);
export const SLA_ELEM_CONST_NEXT = new ElementId('const_next', 81, FORMAT_SCOPE);
export const SLA_ELEM_CONST_NEXT2 = new ElementId('const_next2', 82, FORMAT_SCOPE);
export const SLA_ELEM_CONST_CURSPACE = new ElementId('const_curspace', 83, FORMAT_SCOPE);
export const SLA_ELEM_CONST_CURSPACE_SIZE = new ElementId('const_curspace_size', 84, FORMAT_SCOPE);
export const SLA_ELEM_CONST_FLOWREF = new ElementId('const_flowref', 85, FORMAT_SCOPE);
export const SLA_ELEM_CONST_FLOWREF_SIZE = new ElementId('const_flowref_size', 86, FORMAT_SCOPE);
export const SLA_ELEM_CONST_FLOWDEST = new ElementId('const_flowdest', 87, FORMAT_SCOPE);
export const SLA_ELEM_CONST_FLOWDEST_SIZE = new ElementId('const_flowdest_size', 88, FORMAT_SCOPE);

// =========================================================================
// SLA header verification / writing
// =========================================================================

/**
 * Verify a .sla file header from the given byte data.
 *
 * The bytes of the header are read and verified against the required form and current version.
 * If the form matches, true is returned.
 * @param data - The raw bytes of the .sla file (at least the first 4 bytes)
 * @returns true if a valid header is present
 */
export function isSlaFormat(data: Uint8Array): boolean {
  if (data.length < 4) return false;
  // 's' = 0x73, 'l' = 0x6C, 'a' = 0x61
  if (data[0] !== 0x73 || data[1] !== 0x6C || data[2] !== 0x61) return false;
  if (data[3] !== FORMAT_VERSION) return false;
  return true;
}

/**
 * Write a .sla file header into a Uint8Array.
 *
 * A valid header, including the format version number, is returned.
 * @returns A 4-byte Uint8Array containing the header
 */
export function writeSlaHeader(): Uint8Array {
  const header = new Uint8Array(4);
  header[0] = 0x73; // 's'
  header[1] = 0x6C; // 'l'
  header[2] = 0x61; // 'a'
  header[3] = FORMAT_VERSION;
  return header;
}

// =========================================================================
// FormatEncode
// =========================================================================

/**
 * The encoder for the .sla file format.
 *
 * This provides the format header, does compression, and encodes the raw data elements/attributes.
 * In the TypeScript port, compression is not yet implemented; the encoder writes uncompressed
 * packed data preceded by the SLA header.
 */
export class FormatEncode extends PackedEncode {
  private outputChunks: Uint8Array[];

  /**
   * Initialize an encoder at a specific compression level.
   * @param level - The compression level (currently unused in the TS port)
   */
  constructor(level: number = 0) {
    super();
    void level; // Compression not yet implemented
    this.outputChunks = [];
  }

  /**
   * Flush any buffered bytes in the encoder.
   * Returns the complete .sla file contents as a Uint8Array (header + data).
   */
  flush(): Uint8Array {
    // Build output: header + all chunks
    const header = writeSlaHeader();
    const totalSize = header.length + this.outputChunks.reduce((s, c) => s + c.length, 0);
    const result = new Uint8Array(totalSize);
    result.set(header, 0);
    let offset = header.length;
    for (const chunk of this.outputChunks) {
      result.set(chunk, offset);
      offset += chunk.length;
    }
    return result;
  }
}

// =========================================================================
// FormatDecode
// =========================================================================

/**
 * The decoder for the .sla file format.
 *
 * This verifies the .sla file header, does decompression, and decodes the raw data
 * elements/attributes. In the TypeScript port, the input is expected to be the full
 * .sla file contents as a Uint8Array. Decompression uses the DecompressionStream API
 * when available, or accepts uncompressed data.
 */
export class FormatDecode extends PackedDecode {
  /** The size of the input buffer */
  private static readonly IN_BUFFER_SIZE: number = 4096;

  /**
   * Initialize the decoder.
   * @param spcManager - The (uninitialized) manager that will hold decoded address spaces
   */
  constructor(spcManager: AddrSpaceManager | null) {
    super(spcManager);
  }

  /**
   * Ingest a raw .sla file from a Uint8Array (synchronous).
   *
   * The header is verified, the payload is decompressed (zlib deflate), and the result
   * is fed into the PackedDecode parent for parsing.
   * @param data - The full .sla file contents
   */
  ingestStreamFromBytes(data: Uint8Array | Buffer): void {
    if (!isSlaFormat(data)) {
      throw new LowlevelError('Missing SLA format header');
    }
    const compressed = data.subarray(4);

    // Decompress using synchronous zlib
    let decompressed: Uint8Array;
    try {
      decompressed = new Uint8Array(decompressBytesSync(compressed));
    } catch {
      // If decompression fails, assume the data is not compressed
      decompressed = new Uint8Array(compressed);
    }

    // Use ingestBytes to avoid lossy TextDecoder('latin1') round-trip
    // TextDecoder('latin1') actually uses Windows-1252 which corrupts bytes 0x80-0x9F
    super.ingestBytes(decompressed);
  }

  /**
   * Ingest from a string.
   *
   * This override verifies the SLA header from the raw byte string, decompresses,
   * and feeds the result to PackedDecode.
   * @param s - The raw .sla data as a latin1 string
   */
  override ingestStream(s: string): void {
    // Convert string to bytes to check header
    const encoder = new TextEncoder();
    const bytes = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) {
      bytes[i] = s.charCodeAt(i) & 0xFF;
    }
    if (!isSlaFormat(bytes)) {
      throw new LowlevelError('Missing SLA format header');
    }
    // Pass the data after the 4-byte header to PackedDecode
    // Since compression requires async, for sync ingestStream we assume uncompressed data
    const payload = s.substring(4);
    super.ingestStream(payload);
  }
}

// =========================================================================
// Internal helpers
// =========================================================================

/**
 * Decompress zlib-compressed bytes synchronously.
 *
 * Uses Node.js zlib.inflateSync for synchronous decompression.
 */
function decompressBytesSync(compressed: Uint8Array): Buffer {
  return zlib.inflateSync(Buffer.from(compressed));
}
