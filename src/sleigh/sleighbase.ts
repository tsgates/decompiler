/**
 * @file sleighbase.ts
 * @description Base class for applications that process SLEIGH format specifications.
 *
 * Translated from Ghidra's sleighbase.hh / sleighbase.cc.
 *
 * SleighBase extends the Translate class with SLEIGH-specific infrastructure.
 * It manages symbol tables, source file info, and the overall SLEIGH architecture data.
 */

import type { int4, uint4, uintb, uintm } from '../core/types.js';
import {
  AddrSpace,
  ConstantSpace,
  OtherSpace,
  UniqueSpace,
  spacetype,
} from '../core/space.js';
import { VarnodeData } from '../core/pcoderaw.js';
import { Translate } from '../core/translate.js';
import { LowlevelError } from '../core/error.js';
import type { Encoder, Decoder } from '../core/marshal.js';
import { SleighError } from './context.js';
import { SymbolTable, SymbolScope } from './slghsymbol.js';
import {
  FORMAT_VERSION, MIN_SLEIGH_VERSION, MAX_SLEIGH_VERSION,
  SLA_ELEM_SLEIGH,
  SLA_ELEM_SPACES,
  SLA_ELEM_SPACE,
  SLA_ELEM_SPACE_UNIQUE,
  SLA_ELEM_SPACE_OTHER,
  SLA_ELEM_SOURCEFILES,
  SLA_ELEM_SOURCEFILE,
  SLA_ATTRIB_NAME,
  SLA_ATTRIB_INDEX,
  SLA_ATTRIB_VERSION,
  SLA_ATTRIB_BIGENDIAN,
  SLA_ATTRIB_ALIGN,
  SLA_ATTRIB_UNIQBASE,
  SLA_ATTRIB_MAXDELAY,
  SLA_ATTRIB_UNIQMASK,
  SLA_ATTRIB_NUMSECTIONS,
  SLA_ATTRIB_DEFAULTSPACE,
  SLA_ATTRIB_DELAY,
  SLA_ATTRIB_SIZE,
  SLA_ATTRIB_WORDSIZE,
  SLA_ATTRIB_PHYSICAL,
} from './slaformat.js';

// Forward declarations for types from not-yet-written files
type SleighSymbol = any;
type SubtableSymbol = any;
// SymbolTable and SymbolScope imported from slghsymbol.ts
type VarnodeSymbol = any;
type UserOpSymbol = any;
type ContextSymbol = any;
type ContextField = any;

// ---------------------------------------------------------------------------
// SourceFileIndexer
// ---------------------------------------------------------------------------

/**
 * Class for recording source file information for SLEIGH constructors.
 *
 * A SLEIGH specification may contain many source files. This class is
 * used to associate each constructor in a SLEIGH language to the source
 * file where it is defined. This information is useful when debugging
 * SLEIGH specifications. Sourcefiles are assigned a numeric index and
 * the mapping from indices to filenames is written to the generated .sla
 * file. For each constructor, the data written to the .sla file includes
 * the source file index.
 */
export class SourceFileIndexer {
  private leastUnusedIndex: int4 = 0;
  private indexToFile: Map<int4, string> = new Map();
  private fileToIndex: Map<string, int4> = new Map();

  constructor() {
    this.leastUnusedIndex = 0;
  }

  /**
   * Returns the index of the file. If the file is not in the index it is added.
   */
  index(filename: string): int4 {
    const existing = this.fileToIndex.get(filename);
    if (existing !== undefined) {
      return existing;
    }
    this.fileToIndex.set(filename, this.leastUnusedIndex);
    this.indexToFile.set(this.leastUnusedIndex, filename);
    return this.leastUnusedIndex++;
  }

  /**
   * Get the index of a file. Error if the file is not in the index.
   */
  getIndex(filename: string): int4 {
    return this.fileToIndex.get(filename) ?? 0;
  }

  /**
   * Get the filename corresponding to an index.
   */
  getFilename(index: int4): string {
    return this.indexToFile.get(index) ?? '';
  }

  /**
   * Decode a stored index mapping from a stream.
   */
  decode(decoder: Decoder): void {
    const el: uint4 = (decoder as any).openElement(SLA_ELEM_SOURCEFILES);
    while ((decoder as any).peekElement() === SLA_ELEM_SOURCEFILE.id) {
      const subel: int4 = (decoder as any).openElement();
      const filename: string = (decoder as any).readString(SLA_ATTRIB_NAME);
      const index: int4 = (decoder as any).readSignedInteger(SLA_ATTRIB_INDEX);
      (decoder as any).closeElement(subel);
      this.fileToIndex.set(filename, index);
      this.indexToFile.set(index, filename);
    }
    (decoder as any).closeElement(el);
  }

  /**
   * Encode the index mapping to stream.
   */
  encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_SOURCEFILES);
    for (let i = 0; i < this.leastUnusedIndex; ++i) {
      encoder.openElement(SLA_ELEM_SOURCEFILE);
      encoder.writeString(SLA_ATTRIB_NAME, this.indexToFile.get(i) ?? '');
      encoder.writeSignedInteger(SLA_ATTRIB_INDEX, i);
      encoder.closeElement(SLA_ELEM_SOURCEFILE);
    }
    encoder.closeElement(SLA_ELEM_SOURCEFILES);
  }
}

// ---------------------------------------------------------------------------
// VarnodeData comparison key for map usage
// ---------------------------------------------------------------------------

/**
 * Build a string key for a VarnodeData that preserves the C++ map ordering:
 * space index, then offset, then size (big sizes first).
 */
function varnodeDataKey(v: VarnodeData): string {
  const spaceIdx = v.space ? (v.space as any).getIndex() : -1;
  // Pad to ensure lexicographic == numeric ordering
  const idxStr = String(spaceIdx).padStart(10, '0');
  const offStr = v.offset.toString(16).padStart(16, '0');
  // Invert size so big sizes sort first (matches C++ operator<)
  const sizeStr = String(0xFFFFFFFF - v.size).padStart(10, '0');
  return `${idxStr}:${offStr}:${sizeStr}`;
}

// ---------------------------------------------------------------------------
// SleighBase
// ---------------------------------------------------------------------------

/**
 * Common core of classes that read or write SLEIGH specification files natively.
 *
 * This class represents what's in common across the SLEIGH infrastructure between:
 *   - Reading the various SLEIGH specification files
 *   - Building and writing out SLEIGH specification files
 */
export abstract class SleighBase extends Translate {
  /** Maximum size of a varnode in the unique space */
  static readonly MAX_UNIQUE_SIZE: uint4 = 256;

  private userop: string[] = [];
  /**
   * A map from VarnodeData in the register space to register names.
   * Sorted by (space index, offset, size desc) to match C++ map<VarnodeData, string>.
   */
  private varnode_xref: Map<string, { vn: VarnodeData; name: string }> = new Map();
  /** Sorted keys for varnode_xref, maintained for ordered iteration */
  private varnode_xref_keys: string[] = [];

  protected root: SubtableSymbol | null = null;
  protected symtab: SymbolTable = new SymbolTable();
  protected maxdelayslotbytes: uint4 = 0;
  protected unique_allocatemask: uint4 = 0;
  protected numSections: uint4 = 0;
  protected indexer: SourceFileIndexer = new SourceFileIndexer();

  constructor() {
    super();
    this.root = null;
    this.maxdelayslotbytes = 0;
    this.unique_allocatemask = 0;
    this.numSections = 0;
  }

  /** Return true if this is initialized */
  isInitialized(): boolean {
    return this.root !== null;
  }

  // ---- Virtual method overrides from Translate ----

  override getRegister(nm: string): VarnodeData {
    const sym: VarnodeSymbol = this.findSymbol(nm);
    if (sym === null || sym === undefined) {
      throw new SleighError('Unknown register name: ' + nm);
    }
    if ((sym as any).getType() !== SleighSymbolType.varnode_symbol) {
      throw new SleighError('Symbol is not a register: ' + nm);
    }
    return (sym as any).getFixedVarnode();
  }

  override getRegisterName(base: AddrSpace, off: uintb, size: int4): string {
    const sym = new VarnodeData(base as any, off, size);
    const key = varnodeDataKey(sym);

    // Find the first key greater than our key (upper_bound equivalent)
    const idx = this.upperBound(key);
    if (idx === 0) return '';

    // Step back one
    const prevKey = this.varnode_xref_keys[idx - 1];
    const prevEntry = this.varnode_xref.get(prevKey)!;
    const point = prevEntry.vn;
    if (point.space !== base) return '';
    const offbase: uintb = point.offset;
    if (point.offset + BigInt(point.size) >= off + BigInt(size)) {
      return prevEntry.name;
    }

    // Walk backwards through entries with the same offset
    let i = idx - 1;
    while (i > 0) {
      i--;
      const curKey = this.varnode_xref_keys[i];
      const curEntry = this.varnode_xref.get(curKey)!;
      const curPoint = curEntry.vn;
      if (curPoint.space !== base || curPoint.offset !== offbase) return '';
      if (curPoint.offset + BigInt(curPoint.size) >= off + BigInt(size)) {
        return curEntry.name;
      }
    }
    return '';
  }

  override getExactRegisterName(base: AddrSpace, off: uintb, size: int4): string {
    const sym = new VarnodeData(base as any, off, size);
    const key = varnodeDataKey(sym);
    const entry = this.varnode_xref.get(key);
    if (entry === undefined) return '';
    return entry.name;
  }

  override getAllRegisters(reglist: Map<string, VarnodeData>): void {
    for (const entry of this.varnode_xref.values()) {
      reglist.set(entry.name, entry.vn);
    }
  }

  override getUserOpNames(res: string[]): void {
    res.length = 0;
    for (const name of this.userop) {
      res.push(name);
    }
  }

  // ---- Symbol lookup convenience methods ----

  /** Find a specific SLEIGH symbol by name in the current scope */
  findSymbol(nm: string): SleighSymbol | null {
    return this.symtab.findSymbol(nm);
  }

  /** Find a specific SLEIGH symbol by id */
  findSymbolById(id: uintm): SleighSymbol | null {
    return this.symtab.findSymbol(id);
  }

  /** Find a specific global SLEIGH symbol by name */
  findGlobalSymbol(nm: string): SleighSymbol | null {
    return this.symtab.findGlobalSymbol(nm);
  }

  // ---- Protected methods ----

  /**
   * Register a context variable.
   *
   * Virtual method with empty default implementation (matching C++ Translate::registerContext).
   * Subclasses (e.g. Sleigh) override this to register with their ContextDatabase.
   *
   * @param _name is the name of the context variable
   * @param _sbit is the first bit of the variable in the packed state
   * @param _ebit is the last bit of the variable in the packed state
   */
  protected registerContext(_name: string, _sbit: int4, _ebit: int4): void {
    // Default empty implementation
  }

  /**
   * Build register map. Collect user-ops and context-fields.
   *
   * Assuming the symbol table is populated, iterate through the table collecting
   * registers (for the map), user-op names, and context fields.
   */
  protected buildXrefs(errorPairs: string[]): void {
    const glb: SymbolScope = this.symtab.getGlobalScope();
    const symbols: SleighSymbol[] = [...(glb as any)];

    for (const sym of symbols) {
      if ((sym as any).getType() === SleighSymbolType.varnode_symbol) {
        const vnSym = sym as VarnodeSymbol;
        const fixedVn: VarnodeData = (vnSym as any).getFixedVarnode();
        const name: string = (sym as any).getName();
        const key = varnodeDataKey(fixedVn);

        if (this.varnode_xref.has(key)) {
          // Duplicate
          errorPairs.push(name);
          errorPairs.push(this.varnode_xref.get(key)!.name);
        } else {
          this.varnode_xref.set(key, { vn: fixedVn, name });
          this.insertSortedKey(key);
        }
      } else if ((sym as any).getType() === SleighSymbolType.userop_symbol) {
        const index: int4 = (sym as any).getIndex();
        while (this.userop.length <= index) {
          this.userop.push('');
        }
        this.userop[index] = (sym as any).getName();
      } else if ((sym as any).getType() === SleighSymbolType.context_symbol) {
        const csym = sym as ContextSymbol;
        const field: ContextField = (csym as any).getPatternValue();
        const startbit: int4 = (field as any).getStartBit();
        const endbit: int4 = (field as any).getEndBit();
        this.registerContext((csym as any).getName(), startbit, endbit);
      }
    }
  }

  /**
   * Reregister context fields for a new executable.
   *
   * If this SleighBase is being reused with a new program, the context
   * variables need to be registered with the new program's database.
   */
  protected reregisterContext(): void {
    const glb: SymbolScope = this.symtab.getGlobalScope();
    const symbols: SleighSymbol[] = [...(glb as any)];

    for (const sym of symbols) {
      if ((sym as any).getType() === SleighSymbolType.context_symbol) {
        const csym = sym as ContextSymbol;
        const field: ContextField = (csym as any).getPatternValue();
        const startbit: int4 = (field as any).getStartBit();
        const endbit: int4 = (field as any).getEndBit();
        this.registerContext((csym as any).getName(), startbit, endbit);
      }
    }
  }

  /**
   * Add a space parsed from a .sla file.
   *
   * This is identical to the functionality of decodeSpace, but the AddrSpace information
   * is stored in the .sla file format.
   */
  protected decodeSlaSpace(decoder: Decoder, trans: Translate): AddrSpace {
    const elemId: uint4 = (decoder as any).openElement();
    let res: AddrSpace;
    let index: int4 = 0;
    let addressSize: int4 = 0;
    let delay: int4 = -1;
    let deadcodedelay: int4 = -1;
    let name: string = '';
    let wordsize: int4 = 1;
    let bigEnd: boolean = false;
    let flags: uint4 = 0;

    for (;;) {
      const attribId: uint4 = (decoder as any).getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === SLA_ATTRIB_NAME.id) {
        name = (decoder as any).readString();
      }
      if (attribId === SLA_ATTRIB_INDEX.id) {
        index = (decoder as any).readSignedInteger();
      } else if (attribId === SLA_ATTRIB_SIZE.id) {
        addressSize = (decoder as any).readSignedInteger();
      } else if (attribId === SLA_ATTRIB_WORDSIZE.id) {
        wordsize = (decoder as any).readSignedInteger();
      } else if (attribId === SLA_ATTRIB_BIGENDIAN.id) {
        bigEnd = (decoder as any).readBool();
      } else if (attribId === SLA_ATTRIB_DELAY.id) {
        delay = (decoder as any).readSignedInteger();
      } else if (attribId === SLA_ATTRIB_PHYSICAL.id) {
        if ((decoder as any).readBool()) {
          flags |= AddrSpace.hasphysical;
        }
      }
    }
    (decoder as any).closeElement(elemId);

    if (deadcodedelay === -1) {
      deadcodedelay = delay;
    }
    if (index === 0) {
      throw new LowlevelError('Expecting index attribute');
    }
    if (elemId === SLA_ELEM_SPACE_UNIQUE.id) {
      res = new UniqueSpace(this as any, trans, index, flags);
    } else if (elemId === SLA_ELEM_SPACE_OTHER.id) {
      res = new OtherSpace(this as any, trans, index);
    } else {
      if (addressSize === 0 || delay === -1 || name.length === 0) {
        throw new LowlevelError('Expecting size/delay/name attributes');
      }
      res = new AddrSpace(
        this as any,
        trans,
        spacetype.IPTR_PROCESSOR,
        name,
        bigEnd,
        addressSize,
        wordsize,
        index,
        flags,
        delay,
        deadcodedelay,
      );
    }

    return res;
  }

  /**
   * Restore address spaces from a .sla file.
   *
   * This is identical in functionality to decodeSpaces but the AddrSpace information
   * is stored in the .sla file format.
   */
  protected decodeSlaSpaces(decoder: Decoder, trans: Translate): void {
    // The first space should always be the constant space
    this.insertSpace(new ConstantSpace(this as any, trans));

    const elemId: uint4 = (decoder as any).openElement(SLA_ELEM_SPACES);
    const defname: string = (decoder as any).readString(SLA_ATTRIB_DEFAULTSPACE);
    while ((decoder as any).peekElement() !== 0) {
      const spc: AddrSpace = this.decodeSlaSpace(decoder, trans);
      this.insertSpace(spc);
    }
    (decoder as any).closeElement(elemId);
    const spc = this.getSpaceByName(defname);
    if (spc === null) {
      throw new LowlevelError("Bad 'defaultspace' attribute: " + defname);
    }
    this.setDefaultCodeSpace(spc.getIndex());
  }

  /**
   * Decode a SLEIGH specification from a stream.
   *
   * This parses the main <sleigh> tag (from a .sla file), which includes the description
   * of address spaces and the symbol table, with its associated decoding tables.
   */
  protected decodeSleigh(decoder: Decoder): void {
    this.maxdelayslotbytes = 0;
    this.unique_allocatemask = 0;
    this.numSections = 0;
    let version: int4 = 0;
    const el: uint4 = (decoder as any).openElement(SLA_ELEM_SLEIGH);
    let attrib: uint4 = (decoder as any).getNextAttributeId();
    while (attrib !== 0) {
      if (attrib === SLA_ATTRIB_BIGENDIAN.id) {
        this.setBigEndian((decoder as any).readBool());
      } else if (attrib === SLA_ATTRIB_ALIGN.id) {
        this.alignment = (decoder as any).readSignedInteger();
      } else if (attrib === SLA_ATTRIB_UNIQBASE.id) {
        this.setUniqueBase(Number((decoder as any).readUnsignedInteger()));
      } else if (attrib === SLA_ATTRIB_MAXDELAY.id) {
        this.maxdelayslotbytes = Number((decoder as any).readUnsignedInteger());
      } else if (attrib === SLA_ATTRIB_UNIQMASK.id) {
        this.unique_allocatemask = Number((decoder as any).readUnsignedInteger());
      } else if (attrib === SLA_ATTRIB_NUMSECTIONS.id) {
        this.numSections = Number((decoder as any).readUnsignedInteger());
      } else if (attrib === SLA_ATTRIB_VERSION.id) {
        version = (decoder as any).readSignedInteger();
      }
      attrib = (decoder as any).getNextAttributeId();
    }
    if (version < MIN_SLEIGH_VERSION || version > MAX_SLEIGH_VERSION) {
      throw new LowlevelError('.sla file has wrong format (version ' + version + ')');
    }
    this.indexer.decode(decoder);
    this.decodeSlaSpaces(decoder, this);
    this.symtab.decode(decoder, this);
    (decoder as any).closeElement(el);
    this.root = this.symtab.getGlobalScope().findSymbol('instruction');
    const errorPairs: string[] = [];
    this.buildXrefs(errorPairs);
    if (errorPairs.length > 0) {
      throw new SleighError('Duplicate register pairs');
    }
  }

  // ---- Public encode/decode methods ----

  /**
   * Write the details of given space in .sla format.
   */
  encodeSlaSpace(encoder: Encoder, spc: AddrSpace): void {
    if (spc.getType() === spacetype.IPTR_INTERNAL) {
      encoder.openElement(SLA_ELEM_SPACE_UNIQUE);
    } else if (spc.isOtherSpace()) {
      encoder.openElement(SLA_ELEM_SPACE_OTHER);
    } else {
      encoder.openElement(SLA_ELEM_SPACE);
    }
    encoder.writeString(SLA_ATTRIB_NAME, spc.getName());
    encoder.writeSignedInteger(SLA_ATTRIB_INDEX, spc.getIndex());
    encoder.writeBool(SLA_ATTRIB_BIGENDIAN, this.isBigEndian());
    encoder.writeSignedInteger(SLA_ATTRIB_DELAY, spc.getDelay());
    encoder.writeSignedInteger(SLA_ATTRIB_SIZE, spc.getAddrSize());
    if (spc.getWordSize() > 1) {
      encoder.writeSignedInteger(SLA_ATTRIB_WORDSIZE, spc.getWordSize());
    }
    encoder.writeBool(SLA_ATTRIB_PHYSICAL, spc.hasPhysical());
    if (spc.getType() === spacetype.IPTR_INTERNAL) {
      encoder.closeElement(SLA_ELEM_SPACE_UNIQUE);
    } else if (spc.isOtherSpace()) {
      encoder.closeElement(SLA_ELEM_SPACE_OTHER);
    } else {
      encoder.closeElement(SLA_ELEM_SPACE);
    }
  }

  /**
   * Write out the SLEIGH specification as a <sleigh> tag.
   *
   * This does the bulk of the work of creating a .sla file.
   */
  encodeSleigh(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_SLEIGH);
    encoder.writeSignedInteger(SLA_ATTRIB_VERSION, FORMAT_VERSION);
    encoder.writeBool(SLA_ATTRIB_BIGENDIAN, this.isBigEndian());
    encoder.writeSignedInteger(SLA_ATTRIB_ALIGN, this.alignment);
    encoder.writeUnsignedInteger(SLA_ATTRIB_UNIQBASE, BigInt(this.getUniqueBase()));
    if (this.maxdelayslotbytes > 0) {
      encoder.writeUnsignedInteger(SLA_ATTRIB_MAXDELAY, BigInt(this.maxdelayslotbytes));
    }
    if (this.unique_allocatemask !== 0) {
      encoder.writeUnsignedInteger(SLA_ATTRIB_UNIQMASK, BigInt(this.unique_allocatemask));
    }
    if (this.numSections !== 0) {
      encoder.writeUnsignedInteger(SLA_ATTRIB_NUMSECTIONS, BigInt(this.numSections));
    }
    this.indexer.encode(encoder);
    encoder.openElement(SLA_ELEM_SPACES);
    encoder.writeString(SLA_ATTRIB_DEFAULTSPACE, this.getDefaultCodeSpace()!.getName());
    for (let i = 0; i < this.numSpaces(); ++i) {
      const spc = this.getSpace(i);
      if (spc === null) continue;
      if (
        spc.getType() === spacetype.IPTR_CONSTANT ||
        spc.getType() === spacetype.IPTR_FSPEC ||
        spc.getType() === spacetype.IPTR_IOP ||
        spc.getType() === spacetype.IPTR_JOIN
      ) {
        continue;
      }
      this.encodeSlaSpace(encoder, spc);
    }
    encoder.closeElement(SLA_ELEM_SPACES);
    this.symtab.encode(encoder);
    encoder.closeElement(SLA_ELEM_SLEIGH);
  }

  // ---- Private helpers ----

  /**
   * Binary search for upper bound in sorted varnode_xref_keys.
   * Returns the index of the first key strictly greater than the given key.
   */
  private upperBound(key: string): int4 {
    let lo = 0;
    let hi = this.varnode_xref_keys.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (this.varnode_xref_keys[mid] <= key) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    return lo;
  }

  /**
   * Insert a key into the sorted varnode_xref_keys array.
   */
  private insertSortedKey(key: string): void {
    let lo = 0;
    let hi = this.varnode_xref_keys.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (this.varnode_xref_keys[mid] < key) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    this.varnode_xref_keys.splice(lo, 0, key);
  }
}

// ---------------------------------------------------------------------------
// SleighSymbol type enum (mirrors C++ SleighSymbol::symbol_type)
// ---------------------------------------------------------------------------

/**
 * Enum for SLEIGH symbol types.
 * Mirrors C++ SleighSymbol::symbol_type used in buildXrefs/reregisterContext.
 */
const enum SleighSymbolType {
  space_symbol = 0,
  token_symbol = 1,
  userop_symbol = 2,
  value_symbol = 3,
  valuemap_symbol = 4,
  name_symbol = 5,
  varnode_symbol = 6,
  varnodelist_symbol = 7,
  operand_symbol = 8,
  start_symbol = 9,
  end_symbol = 10,
  next2_symbol = 11,
  subtable_symbol = 12,
  macro_symbol = 13,
  section_symbol = 14,
  bitrange_symbol = 15,
  context_symbol = 16,
  epsilon_symbol = 17,
  label_symbol = 18,
  flowdest_symbol = 19,
  flowref_symbol = 20,
  dummy_symbol = 21,
}

// ---------------------------------------------------------------------------
// SymbolTableStub - minimal stub for the SymbolTable forward declaration
// ---------------------------------------------------------------------------

/**
 * A minimal stub for the SymbolTable class.
 * This will be replaced when slghsymbol.ts is fully translated.
 * The stub provides the minimal interface needed by SleighBase.
 */
class SymbolTableStub {
  private symbollist: any[] = [];
  private table: any[] = [];
  private curscope: any = null;

  findSymbol(nmOrId: string | uintm): any {
    if (typeof nmOrId === 'string') {
      return this.findSymbolInternal(this.curscope, nmOrId);
    }
    return this.symbollist[nmOrId as number] ?? null;
  }

  findGlobalSymbol(nm: string): any {
    if (this.table.length === 0) return null;
    return this.findSymbolInternal(this.table[0], nm);
  }

  getGlobalScope(): any {
    return this.table.length > 0 ? this.table[0] : null;
  }

  getCurrentScope(): any {
    return this.curscope;
  }

  encode(_encoder: Encoder): void {
    // Stub
  }

  decode(_decoder: Decoder, _trans: any): void {
    // Stub
  }

  private findSymbolInternal(_scope: any, _nm: string): any {
    return null;
  }
}
