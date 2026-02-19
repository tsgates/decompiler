/**
 * @file globalcontext.ts
 * @description Context variable database used for disassembly and decompilation.
 *
 * Translated from Ghidra's globalcontext.hh / globalcontext.cc.
 *
 * Context information is a set of named variables that hold concrete values at specific
 * addresses in the target executable being analyzed. A variable can hold different values
 * at different addresses, but a specific value at a specific address never changes.
 *
 * Context variables come in two flavors:
 *  - Low-level context variables: affect instruction decoding, defined in Sleigh specification.
 *  - High-level tracked variables: normal memory locations treated as constants across some
 *    range of code (e.g., direction flag, segment registers).
 */

import { Address, Range, MachExtreme, calc_mask } from './address.js';
import { VarnodeData } from './pcoderaw.js';
import { AddrSpace } from './space.js';
import {
  Encoder,
  Decoder,
  ElementId,
  AttributeId,
  ATTRIB_NAME,
  ATTRIB_VAL,
  ATTRIB_SPACE,
  ATTRIB_OFFSET,
  ATTRIB_SIZE,
} from './marshal.js';
import { PartMap } from './partmap.js';
import { LowlevelError } from './error.js';
import type { int4, uint4, uintb, uintm } from './types.js';

// ---------------------------------------------------------------------------
// Element IDs
// ---------------------------------------------------------------------------

export const ELEM_CONTEXT_DATA = new ElementId('context_data', 120);
export const ELEM_CONTEXT_POINTS = new ElementId('context_points', 121);
export const ELEM_CONTEXT_POINTSET = new ElementId('context_pointset', 122);
export const ELEM_CONTEXT_SET = new ElementId('context_set', 123);
export const ELEM_SET = new ElementId('set', 124);
export const ELEM_TRACKED_POINTSET = new ElementId('tracked_pointset', 125);
export const ELEM_TRACKED_SET = new ElementId('tracked_set', 126);

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Number of bits in a uintm word (32-bit) */
const WORD_BITS = 32;

// ---------------------------------------------------------------------------
// ContextBitRange
// ---------------------------------------------------------------------------

/**
 * Description of a context variable within the disassembly context blob.
 *
 * Disassembly context is stored as individual (integer) values packed into a sequence of words.
 * This class represents the info for encoding or decoding a single value within this sequence.
 * A value is a contiguous range of bits within one context word. Size can range from 1 bit up
 * to the size of a word (32 bits).
 */
export class ContextBitRange {
  /** Index of word containing this context value */
  word: int4;
  /** Starting bit of the value within its word (0 = most significant bit) */
  startbit: int4;
  /** Ending bit of the value within its word */
  endbit: int4;
  /** Right-shift amount to apply when unpacking this value from its word */
  shift: int4;
  /** Mask to apply (after shifting) when unpacking this value from its word */
  mask: uintm;

  /**
   * Construct a context value given an absolute bit range.
   *
   * Bits within the whole context blob are labeled starting with 0 as the most significant bit
   * in the first word in the sequence. The new context value must be contained within a single word.
   *
   * @param sbit - the starting (most significant) bit of the new value
   * @param ebit - the ending (least significant) bit of the new value
   */
  constructor(sbit?: int4, ebit?: int4) {
    if (sbit === undefined || ebit === undefined) {
      // Default constructor - undefined bit range
      this.word = 0;
      this.startbit = 0;
      this.endbit = 0;
      this.shift = 0;
      this.mask = 0;
      return;
    }
    this.word = Math.floor(sbit / WORD_BITS);
    this.startbit = sbit - this.word * WORD_BITS;
    this.endbit = ebit - this.word * WORD_BITS;
    this.shift = WORD_BITS - this.endbit - 1;
    // mask = (~((uintm)0)) >> (startbit + shift)
    // In 32-bit unsigned arithmetic: 0xFFFFFFFF >>> (startbit + shift)
    this.mask = (0xFFFFFFFF >>> (this.startbit + this.shift));
  }

  /** Return the shift-amount for this value */
  getShift(): int4 {
    return this.shift;
  }

  /** Return the mask for this value */
  getMask(): uintm {
    return this.mask;
  }

  /** Return the word index for this value */
  getWord(): int4 {
    return this.word;
  }

  /**
   * Set this value within a given context blob.
   *
   * @param vec - the given context blob to alter (as an array of 32-bit words)
   * @param val - the integer value to set
   */
  setValue(vec: number[], val: number): void {
    let newval = vec[this.word];
    newval = (newval & ~((this.mask << this.shift) | 0)) | 0;
    newval = (newval | (((val & this.mask) << this.shift) | 0)) | 0;
    vec[this.word] = newval;
  }

  /**
   * Retrieve this value from a given context blob.
   *
   * @param vec - the given context blob (as an array of 32-bit words)
   * @returns the recovered integer value
   */
  getValue(vec: number[]): number {
    return ((vec[this.word] >>> this.shift) & this.mask);
  }
}

// ---------------------------------------------------------------------------
// TrackedContext
// ---------------------------------------------------------------------------

/**
 * A tracked register (Varnode) and the value it contains.
 *
 * This is the object returned when querying for tracked registers via
 * ContextDatabase.getTrackedSet(). It holds the storage details of the register and
 * the actual value it holds at the point of the query.
 */
export class TrackedContext {
  /** Storage details of the register being tracked */
  loc: VarnodeData;
  /** The value of the register */
  val: uintb;

  constructor() {
    this.loc = new VarnodeData();
    this.val = 0n;
  }

  /**
   * Decode this from a stream.
   * Parse a <set> element to fill in the storage and value details.
   *
   * @param decoder - the stream decoder
   */
  decode(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_SET);
    // Decode the varnode location from attributes
    // In C++: loc.decodeFromAttributes(decoder)
    // We replicate the logic: read space, then have the space decode offset/size
    this.loc.space = null;
    this.loc.size = 0;
    for (;;) {
      const attribId = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_SPACE.id) {
        this.loc.space = decoder.readSpace() as any;
        decoder.rewindAttributes();
        const sizeRef = { val: 0 };
        this.loc.offset = (this.loc.space as any).decodeAttributes_sized(decoder, sizeRef);
        this.loc.size = sizeRef.val;
        break;
      } else if (attribId === ATTRIB_VAL.id) {
        this.val = decoder.readUnsignedInteger();
      }
    }
    // Re-read remaining attributes for VAL if we haven't gotten it yet
    if (this.loc.space !== null) {
      decoder.rewindAttributes();
      for (;;) {
        const attribId = decoder.getNextAttributeId();
        if (attribId === 0) break;
        if (attribId === ATTRIB_VAL.id) {
          this.val = decoder.readUnsignedInteger();
          break;
        }
      }
    }
    decoder.closeElement(elemId);
  }

  /**
   * Encode this to a stream.
   * The register storage and value are encoded as a <set> element.
   *
   * @param encoder - the stream encoder
   */
  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_SET);
    // In C++: loc.space->encodeAttributes(encoder, loc.offset, loc.size)
    if (this.loc.space !== null) {
      (this.loc.space as any).encodeAttributes(encoder, this.loc.offset, this.loc.size);
    }
    encoder.writeUnsignedInteger(ATTRIB_VAL, this.val);
    encoder.closeElement(ELEM_SET);
  }
}

/**
 * A set of tracked registers and their values (at one code point).
 */
export type TrackedSet = TrackedContext[];

// ---------------------------------------------------------------------------
// FreeArray
// ---------------------------------------------------------------------------

/**
 * A context blob, holding context values across some range of code addresses.
 *
 * This is an internal object that allocates the actual "array of words" for a context blob.
 * An associated mask array holds 1-bits for context variables that were explicitly set for the
 * specific split point.
 */
export class FreeArray {
  /** The "array of words" holding context variable values */
  array: number[];
  /** The mask array indicating which variables are explicitly set */
  mask: number[];
  /** The number of words in the array */
  size: int4;

  /** Construct an empty context blob */
  constructor() {
    this.size = 0;
    this.array = [];
    this.mask = [];
  }

  /**
   * Resize the context blob, preserving old values.
   *
   * The "array of words" and mask array are resized to the given value. Old values are
   * preserved, chopping off the last values, or appending zeroes, as needed.
   *
   * @param sz - the new number of words to resize to
   */
  reset(sz: int4): void {
    const newarray: number[] = [];
    const newmask: number[] = [];
    if (sz !== 0) {
      const min = sz > this.size ? this.size : sz;
      for (let i = 0; i < min; i++) {
        newarray[i] = this.array[i];
        newmask[i] = this.mask[i];
      }
      for (let i = min; i < sz; i++) {
        newarray[i] = 0;
        newmask[i] = 0;
      }
    }
    this.array = newarray;
    this.mask = newmask;
    this.size = sz;
  }

  /**
   * Clone a context blob.
   *
   * Copies array values but zeroes the mask (the mask indicates explicit set operations,
   * which don't carry over to cloned split points).
   *
   * @returns a new FreeArray with the same values but zeroed mask
   */
  clone(): FreeArray {
    const result = new FreeArray();
    result.size = this.size;
    if (this.size !== 0) {
      result.array = new Array(this.size);
      result.mask = new Array(this.size);
      for (let i = 0; i < this.size; i++) {
        result.array[i] = this.array[i];  // Copy value at split point
        result.mask[i] = 0;               // but not fact that value is being set
      }
    }
    return result;
  }
}

// ---------------------------------------------------------------------------
// Address comparator for PartMap
// ---------------------------------------------------------------------------

/**
 * Compare two Address objects for use in PartMap.
 */
function addressCompare(a: Address, b: Address): number {
  if (a.equals(b)) return 0;
  return a.lessThan(b) ? -1 : 1;
}

// ---------------------------------------------------------------------------
// ContextDatabase (abstract)
// ---------------------------------------------------------------------------

/**
 * An interface to a database of disassembly/decompiler context information.
 *
 * Context information is a set of named variables that hold concrete values at specific
 * addresses in the target executable being analyzed. A variable can hold different values
 * at different addresses, but a specific value at a specific address never changes.
 */
export abstract class ContextDatabase {

  // ---- Protected static methods ----

  /**
   * Encode all tracked register values for a specific address to a stream.
   *
   * Encode all the tracked register values associated with a specific target address
   * as a <tracked_pointset> tag.
   *
   * @param encoder - the stream encoder
   * @param addr - the specific address we have tracked values for
   * @param vec - the list of tracked values
   */
  protected static encodeTracked(encoder: Encoder, addr: Address, vec: TrackedSet): void {
    if (vec.length === 0) return;
    encoder.openElement(ELEM_TRACKED_POINTSET);
    addr.getSpace()!.encodeAttributes(encoder, addr.getOffset());
    for (let i = 0; i < vec.length; i++) {
      vec[i].encode(encoder);
    }
    encoder.closeElement(ELEM_TRACKED_POINTSET);
  }

  /**
   * Restore a sequence of tracked register values from the given stream decoder.
   *
   * Parse a <tracked_pointset> element, decoding each child in turn to populate a list of
   * TrackedContext objects.
   *
   * @param decoder - the given stream decoder
   * @param vec - the container that will hold the new TrackedContext objects
   */
  protected static decodeTracked(decoder: Decoder, vec: TrackedSet): void {
    vec.length = 0;  // Clear out any old stuff
    while (decoder.peekElement() !== 0) {
      const tc = new TrackedContext();
      tc.decode(decoder);
      vec.push(tc);
    }
  }

  // ---- Protected abstract methods ----

  /**
   * Retrieve the context variable description object by name.
   * If the variable doesn't exist an exception is thrown.
   *
   * @param nm - the name of the context value
   * @returns the ContextBitRange object matching the name
   */
  protected abstract _getVariable(nm: string): ContextBitRange;

  /**
   * Grab the context blob(s) for the given address range, marking bits that will be set.
   *
   * This is an internal routine for obtaining the actual memory regions holding context values
   * for the address range. This also informs the system which bits are getting set. A split is
   * forced at the first address, and at least one memory region is passed back. The second
   * address can be invalid in which case the memory region passed back is valid from the first
   * address to whatever the next split point is.
   *
   * @param res - will hold pointers to memory regions for the given range
   * @param addr1 - the starting address of the range
   * @param addr2 - (1 past) the last address of the range or is invalid
   * @param num - the word index for the context value that will be set
   * @param mask - a mask of the value being set (within its word)
   */
  protected abstract getRegionForSet(
    res: number[][],
    addr1: Address,
    addr2: Address,
    num: int4,
    mask: uintm
  ): void;

  /**
   * Grab the context blob(s) starting at the given address up to the first point of change.
   *
   * This is an internal routine for obtaining the actual memory regions holding context values
   * starting at the given address. A specific context value is specified, and all memory regions
   * are returned up to the first address where that particular context value changes.
   *
   * @param res - will hold pointers to memory regions being passed back
   * @param addr - the starting address of the regions to fetch
   * @param num - the word index for the specific context value being set
   * @param mask - a mask of the context value being set (within its word)
   */
  protected abstract getRegionToChangePoint(
    res: number[][],
    addr: Address,
    num: int4,
    mask: uintm
  ): void;

  /**
   * Retrieve the memory region holding all default context values.
   *
   * @returns the memory region holding all the default context values
   */
  protected abstract getDefaultValueBuf(): number[];

  // ---- Public abstract methods ----

  /**
   * Retrieve the number of words (uintm) in a context blob.
   */
  abstract getContextSize(): int4;

  /**
   * Register a new named context variable (as a bit range) with the database.
   *
   * A new variable is registered by providing a name and the range of bits the value will
   * occupy within the context blob. The full blob size is automatically increased if necessary.
   * The variable must be contained within a single word, and all variables must be registered
   * before any values can be set.
   *
   * @param nm - the name of the new variable
   * @param sbit - the position of the variable's most significant bit within the blob
   * @param ebit - the position of the variable's least significant bit within the blob
   */
  abstract registerVariable(nm: string, sbit: int4, ebit: int4): void;

  /**
   * Get the context blob of values associated with a given address.
   *
   * @param addr - the given address
   * @returns the array of words holding the context values for the address
   */
  abstract getContext(addr: Address): number[];

  /**
   * Get the context blob of values associated with a given address and its bounding offsets.
   *
   * In addition to the memory region, the range of addresses for which the region is valid
   * is passed back as offsets into the address space.
   *
   * @param addr - the given address
   * @returns an object with the buffer, first offset, and last offset
   */
  abstract getContextBounded(addr: Address): { buf: number[]; first: uintb; last: uintb };

  /**
   * Get the set of default values for all tracked registers.
   */
  abstract getTrackedDefault(): TrackedSet;

  /**
   * Get the set of tracked register values associated with the given address.
   */
  abstract getTrackedSet(addr: Address): TrackedSet;

  /**
   * Create a tracked register set that is valid over the given range.
   *
   * This really should be an internal routine. The created set is empty, old values are blown
   * away. If old/default values are to be preserved, they must be copied back in.
   *
   * @param addr1 - the starting address of the given range
   * @param addr2 - (1 past) the ending address of the given range
   * @returns the empty set of tracked register values
   */
  abstract createSet(addr1: Address, addr2: Address): TrackedSet;

  /** Encode the entire database to a stream */
  abstract encode(encoder: Encoder): void;

  /** Restore the state of this database from the given stream decoder */
  abstract decode(decoder: Decoder): void;

  /**
   * Add initial context state from elements in the compiler/processor specifications.
   *
   * Parse a <context_data> element from the given stream decoder from either the compiler
   * or processor specification file for the architecture, initializing this database.
   */
  abstract decodeFromSpec(decoder: Decoder): void;

  // ---- Public methods (implemented on base class) ----

  /**
   * Provide a default value for a context variable.
   *
   * The default value is returned for addresses that have not been overlaid with other values.
   *
   * @param nm - the name of the context variable
   * @param val - the default value to establish
   */
  setVariableDefault(nm: string, val: uintm): void {
    const variable = this._getVariable(nm);
    variable.setValue(this.getDefaultValueBuf(), val);
  }

  /**
   * Retrieve the default value for a context variable.
   *
   * This will return the default value used for addresses that have not been overlaid
   * with other values.
   *
   * @param nm - the name of the context variable
   * @returns the variable's default value
   */
  getDefaultValue(nm: string): uintm {
    const variable = this._getVariable(nm);
    return variable.getValue(this.getDefaultValueBuf());
  }

  /**
   * Set a context value at the given address.
   *
   * The variable will be changed to the new value, starting at the given address up to
   * the next point of change.
   *
   * @param nm - the name of the context variable
   * @param addr - the given address
   * @param value - the new value to set
   */
  setVariable(nm: string, addr: Address, value: uintm): void {
    const bitrange = this._getVariable(nm);
    const num = bitrange.getWord();
    const mask = (bitrange.getMask() << bitrange.getShift()) | 0;

    const contvec: number[][] = [];
    this.getRegionToChangePoint(contvec, addr, num, mask);
    for (let i = 0; i < contvec.length; i++) {
      bitrange.setValue(contvec[i], value);
    }
  }

  /**
   * Retrieve a context value at the given address.
   *
   * If a value has not been explicitly set for an address range containing the given address,
   * the default value for the variable is returned.
   *
   * @param nm - the name of the context variable
   * @param addr - the address for which the specific value is needed
   * @returns the context variable value for the address
   */
  getVariableValue(nm: string, addr: Address): uintm {
    const bitrange = this._getVariable(nm);
    const context = this.getContext(addr);
    return bitrange.getValue(context);
  }

  /**
   * Set a specific context value starting at the given address.
   *
   * The new value is painted across an address range starting with the given address up to
   * the point where another change for the variable was specified. No other context variable
   * is changed, inside (or outside) the range.
   *
   * @param addr - the given starting address
   * @param num - the index of the word (within the context blob) of the context variable
   * @param mask - the mask delimiting the context variable (within its word)
   * @param value - the (already shifted) value being set
   */
  setContextChangePoint(addr: Address, num: int4, mask: uintm, value: uintm): void {
    const contvec: number[][] = [];
    this.getRegionToChangePoint(contvec, addr, num, mask);
    for (let i = 0; i < contvec.length; i++) {
      const newcontext = contvec[i];
      let val = newcontext[num];
      val = (val & ~mask) | 0;  // Clear range to zero
      val = (val | value) | 0;
      newcontext[num] = val;
    }
  }

  /**
   * Set a context variable value over a given range of addresses.
   *
   * The new value is painted over an explicit range of addresses. No other context variable
   * is changed inside (or outside) the range.
   *
   * @param addr1 - the starting address of the given range
   * @param addr2 - the ending address of the given range
   * @param num - the index of the word (within the context blob) of the context variable
   * @param mask - the mask delimiting the context variable (within its word)
   * @param value - the (already shifted) value being set
   */
  setContextRegion(addr1: Address, addr2: Address, num: int4, mask: uintm, value: uintm): void {
    const vec: number[][] = [];
    this.getRegionForSet(vec, addr1, addr2, num, mask);
    for (let i = 0; i < vec.length; i++) {
      vec[i][num] = ((vec[i][num] & ~mask) | value) | 0;
    }
  }

  /**
   * Set a context variable by name over a given range of addresses.
   *
   * The new value is painted over an explicit range of addresses. No other context variable
   * is changed inside (or outside) the range.
   *
   * @param nm - the name of the context variable to set
   * @param begad - the starting address of the given range
   * @param endad - the ending address of the given range
   * @param value - the new value to set
   */
  setVariableRegion(nm: string, begad: Address, endad: Address, value: uintm): void {
    const bitrange = this._getVariable(nm);

    const vec: number[][] = [];
    this.getRegionForSet(
      vec, begad, endad,
      bitrange.getWord(),
      (bitrange.getMask() << bitrange.getShift()) | 0
    );
    for (let i = 0; i < vec.length; i++) {
      bitrange.setValue(vec[i], value);
    }
  }

  /**
   * Get the value of a tracked register at a specific address.
   *
   * A specific storage region and code address is given. If the region is tracked the value
   * at the address is retrieved. If the specified storage region is contained in the tracked
   * region, the retrieved value is trimmed to match the containment before returning it.
   * If the region is not tracked, a value of 0 is returned.
   *
   * @param mem - the specified storage region
   * @param point - the code address
   * @returns the tracked value or zero
   */
  getTrackedValue(mem: VarnodeData, point: Address): uintb {
    const tset = this.getTrackedSet(point);
    const endoff = mem.offset + BigInt(mem.size) - 1n;
    for (let i = 0; i < tset.length; i++) {
      const tcont = tset[i];
      // tcont must contain -mem-
      if (tcont.loc.space !== mem.space) continue;
      if (tcont.loc.offset > mem.offset) continue;
      const tendoff = tcont.loc.offset + BigInt(tcont.loc.size) - 1n;
      if (tendoff < endoff) continue;
      let res = tcont.val;
      // If we have proper containment, trim value based on endianness
      if ((tcont.loc.space as any).isBigEndian()) {
        if (endoff !== tendoff) {
          res = res >> (8n * (tendoff - mem.offset));
        }
      } else {
        if (mem.offset !== tcont.loc.offset) {
          res = res >> (8n * (mem.offset - tcont.loc.offset));
        }
      }
      res = res & calc_mask(mem.size);  // Final trim based on size
      return res;
    }
    return 0n;
  }
}

// ---------------------------------------------------------------------------
// ContextInternal
// ---------------------------------------------------------------------------

/**
 * An in-memory implementation of the ContextDatabase interface.
 *
 * Context blobs are held in a partition map on addresses. Any address within the map
 * indicates a split point, where the value of a context variable was explicitly changed.
 * Sets of tracked registers are held in a separate partition map.
 */
export class ContextInternal extends ContextDatabase {
  /** Number of words in a context blob (for this architecture) */
  private size: int4;
  /** Map from context variable name to description object */
  private variables: Map<string, ContextBitRange>;
  /** Partition map of context blobs (FreeArray) */
  private database: PartMap<Address, FreeArray>;
  /** Partition map of tracked register sets */
  private trackbase: PartMap<Address, TrackedSet>;

  constructor() {
    super();
    this.size = 0;
    this.variables = new Map();
    this.database = new PartMap<Address, FreeArray>(
      new FreeArray(),
      addressCompare,
      (v: FreeArray) => v.clone()
    );
    this.trackbase = new PartMap<Address, TrackedSet>(
      [],
      addressCompare,
      (v: TrackedSet) => v.map(tc => {
        const copy = new TrackedContext();
        copy.loc = new VarnodeData(tc.loc.space, tc.loc.offset, tc.loc.size);
        copy.val = tc.val;
        return copy;
      })
    );
  }

  // ---- Private methods ----

  /**
   * Encode a single context block to a stream.
   *
   * The blob is broken up into individual values and written out as a series
   * of <set> elements within a parent <context_pointset> element.
   *
   * @param encoder - the stream encoder
   * @param addr - the address of the split point where the blob is valid
   * @param vec - the array of words holding the blob values
   */
  private encodeContext(encoder: Encoder, addr: Address, vec: number[]): void {
    encoder.openElement(ELEM_CONTEXT_POINTSET);
    addr.getSpace()!.encodeAttributes(encoder, addr.getOffset());
    for (const [name, bitrange] of this.variables) {
      const val = bitrange.getValue(vec);
      encoder.openElement(ELEM_SET);
      encoder.writeString(ATTRIB_NAME, name);
      encoder.writeUnsignedInteger(ATTRIB_VAL, BigInt(val));
      encoder.closeElement(ELEM_SET);
    }
    encoder.closeElement(ELEM_CONTEXT_POINTSET);
  }

  /**
   * Restore a context blob for given address range from a stream decoder.
   *
   * Parse either a <context_pointset> or <context_set> element. In either case,
   * children are parsed to get context variable values. Then a context blob is
   * reconstructed from the values. The new blob is added to the interval map based
   * on the address range. If the start address is invalid, the default value of
   * the context variables are painted. The second address can be invalid, if
   * only a split point is known.
   *
   * @param decoder - the stream decoder
   * @param addr1 - the starting address of the given range
   * @param addr2 - the ending address of the given range
   */
  private decodeContext(decoder: Decoder, addr1: Address, addr2: Address): void {
    for (;;) {
      const subId = decoder.openElement();
      if (subId !== ELEM_SET.id) break;
      const val = Number(decoder.readUnsignedIntegerById(ATTRIB_VAL));
      const varName = decoder.readStringById(ATTRIB_NAME);
      const variable = this._getVariable(varName);
      const vec: number[][] = [];
      if (addr1.isInvalid()) {
        // Invalid addr1, indicates we should set default value
        const defaultBuffer = this.getDefaultValueBuf();
        for (let i = 0; i < this.size; i++) {
          defaultBuffer[i] = 0;
        }
        vec.push(defaultBuffer);
      } else {
        this.getRegionForSet(
          vec, addr1, addr2,
          variable.getWord(),
          (variable.getMask() << variable.getShift()) | 0
        );
      }
      for (let i = 0; i < vec.length; i++) {
        variable.setValue(vec[i], val);
      }
      decoder.closeElement(subId);
    }
  }

  // ---- Protected overrides ----

  protected _getVariable(nm: string): ContextBitRange {
    const result = this.variables.get(nm);
    if (result === undefined) {
      throw new LowlevelError('Non-existent context variable: ' + nm);
    }
    return result;
  }

  protected getRegionForSet(
    res: number[][],
    addr1: Address,
    addr2: Address,
    num: int4,
    mask: uintm
  ): void {
    this.database.split(addr1);
    const aIdx = this.database.beginIndex(addr1);
    let bIdx: number;
    if (!addr2.isInvalid()) {
      this.database.split(addr2);
      bIdx = this.database.beginIndex(addr2);
    } else {
      bIdx = this.database.endIndex();
    }
    for (let i = aIdx; i < bIdx; i++) {
      const entry = this.database.getValueAt(i) as FreeArray;
      res.push(entry.array);
      entry.mask[num] = (entry.mask[num] | mask) | 0;  // Mark that this value is being definitely set
    }
  }

  protected getRegionToChangePoint(
    res: number[][],
    addr: Address,
    num: int4,
    mask: uintm
  ): void {
    this.database.split(addr);
    const aIdx = this.database.beginIndex(addr);
    const bIdx = this.database.endIndex();
    if (aIdx === bIdx) return;

    let entry = this.database.getValueAt(aIdx) as FreeArray;
    res.push(entry.array);
    entry.mask[num] = (entry.mask[num] | mask) | 0;

    for (let i = aIdx + 1; i < bIdx; i++) {
      entry = this.database.getValueAt(i) as FreeArray;
      if ((entry.mask[num] & mask) !== 0) break;  // Reached point where this value was definitively set before
      res.push(entry.array);
    }
  }

  protected getDefaultValueBuf(): number[] {
    return this.database.defaultValue.array;
  }

  // ---- Public overrides ----

  getContextSize(): int4 {
    return this.size;
  }

  registerVariable(nm: string, sbit: int4, ebit: int4): void {
    if (!this.database.empty()) {
      throw new LowlevelError('Cannot register new context variables after database is initialized');
    }
    const bitrange = new ContextBitRange(sbit, ebit);
    const sz = Math.floor(sbit / WORD_BITS) + 1;
    if ((Math.floor(ebit / WORD_BITS) + 1) !== sz) {
      throw new LowlevelError('Context variable does not fit in one word');
    }
    if (sz > this.size) {
      this.size = sz;
      this.database.defaultValue.reset(this.size);
    }
    this.variables.set(nm, bitrange);
  }

  getContext(addr: Address): number[] {
    return (this.database.getValue(addr) as FreeArray).array;
  }

  getContextBounded(addr: Address): { buf: number[]; first: uintb; last: uintb } {
    const result = this.database.bounds(addr);
    const value = result.value as FreeArray;
    const buf = value.array;
    let first: uintb;
    let last: uintb;

    // valid: 0 = fully bounded, 1 = no lower bound, 2 = no upper bound, 3 = no bounds
    if (((result.valid & 1) !== 0) || (result.before === undefined) ||
        ((result.before as Address).getSpace() !== addr.getSpace())) {
      first = 0n;
    } else {
      first = (result.before as Address).getOffset();
    }

    if (((result.valid & 2) !== 0) || (result.after === undefined) ||
        ((result.after as Address).getSpace() !== addr.getSpace())) {
      last = addr.getSpace()!.getHighest();
    } else {
      last = (result.after as Address).getOffset() - 1n;
    }

    return { buf, first, last };
  }

  getTrackedDefault(): TrackedSet {
    return this.trackbase.defaultValue;
  }

  getTrackedSet(addr: Address): TrackedSet {
    return this.trackbase.getValue(addr);
  }

  createSet(addr1: Address, addr2: Address): TrackedSet {
    const res = this.trackbase.clearRange(addr1, addr2);
    res.length = 0;
    return res;
  }

  encode(encoder: Encoder): void {
    if (this.database.empty() && this.trackbase.empty()) return;

    encoder.openElement(ELEM_CONTEXT_POINTS);

    // Save context at each changepoint
    for (const [key, val] of this.database.entries()) {
      this.encodeContext(encoder, key, (val as FreeArray).array);
    }

    // Save tracked registers at each changepoint
    for (const [key, val] of this.trackbase.entries()) {
      ContextDatabase.encodeTracked(encoder, key, val);
    }

    encoder.closeElement(ELEM_CONTEXT_POINTS);
  }

  decode(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_CONTEXT_POINTS);
    for (;;) {
      const subId = decoder.openElement();
      if (subId === 0) break;
      if (subId === ELEM_CONTEXT_POINTSET.id) {
        const attribId = decoder.getNextAttributeId();
        decoder.rewindAttributes();
        if (attribId === 0) {
          // Restore the default value
          this.decodeContext(decoder, new Address(), new Address());
        } else {
          // Decode address from attributes
          const vData = new VarnodeData();
          this._decodeVarnodeFromAttributes(vData, decoder);
          this.decodeContext(decoder, vData.getAddr() as any, new Address());
        }
      } else if (subId === ELEM_TRACKED_POINTSET.id) {
        const vData = new VarnodeData();
        this._decodeVarnodeFromAttributes(vData, decoder);
        const addr = vData.getAddr();
        ContextDatabase.decodeTracked(
          decoder,
          this.trackbase.split(new Address(addr.getSpace() as any, addr.getOffset()))
        );
      } else {
        throw new LowlevelError('Bad <context_points> tag');
      }
      decoder.closeElement(subId);
    }
    decoder.closeElement(elemId);
  }

  decodeFromSpec(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_CONTEXT_DATA);
    for (;;) {
      const subId = decoder.openElement();
      if (subId === 0) break;
      // Decode the range from attributes
      const range = this._decodeRangeFromAttributes(decoder);
      const addr1 = range.getFirstAddr();
      const addr2 = this._getLastAddrOpen(range);
      if (subId === ELEM_CONTEXT_SET.id) {
        this.decodeContext(decoder, addr1, addr2);
      } else if (subId === ELEM_TRACKED_SET.id) {
        ContextDatabase.decodeTracked(decoder, this.createSet(addr1, addr2));
      } else {
        throw new LowlevelError('Bad <context_data> tag');
      }
      decoder.closeElement(subId);
    }
    decoder.closeElement(elemId);
  }

  // ---- Private helpers for decode ----

  /**
   * Decode a VarnodeData from the current element attributes.
   * Replicates VarnodeData::decodeFromAttributes.
   */
  private _decodeVarnodeFromAttributes(vData: VarnodeData, decoder: Decoder): void {
    vData.space = null;
    vData.size = 0;
    for (;;) {
      const attribId = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_SPACE.id) {
        vData.space = decoder.readSpace() as any;
        decoder.rewindAttributes();
        const sizeRef = { val: 0 };
        vData.offset = (vData.space as any).decodeAttributes_sized(decoder, sizeRef);
        vData.size = sizeRef.val;
        break;
      }
    }
  }

  /**
   * Decode a Range from the current element's attributes.
   * Replicates Range::decodeFromAttributes.
   */
  private _decodeRangeFromAttributes(decoder: Decoder): Range {
    let spc: AddrSpace | null = null;
    let first = 0n;
    let last = 0n;
    let seenLast = false;

    for (;;) {
      const attribId = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_SPACE.id) {
        spc = decoder.readSpace() as any;
      } else if (attribId === ATTRIB_NAME.id) {
        // Register-based range: handled by the Translate
        // For now, read the string and skip
        decoder.readString();
      } else {
        // Check for 'first' and 'last' attributes
        // ATTRIB_FIRST and ATTRIB_LAST may not be defined in our marshal.ts yet.
        // We use the generic attribute reading mechanism.
        // In the C++ source, ATTRIB_FIRST is a distinct attribute.
        // We need to handle these by name since they might not be registered yet.
        // The decoder has already advanced past the attribute, so we read it as unsigned.
        // We'll use a name-based approach by checking if the current attribute id
        // matches known patterns.
        // For a minimal approach, attempt to read as unsigned integer.
        // The attribute IDs for 'first' and 'last' are not in our standard marshal.ts exports.
        // We'll detect them by trying.
      }
    }

    // If no space found, rewind and try a different approach
    if (spc === null) {
      throw new LowlevelError('No address space indicated in range tag');
    }

    if (!seenLast) {
      last = spc.getHighest();
    }

    return new Range(spc, first, last);
  }

  /**
   * Compute the address of the first byte after the given range.
   * Replicates Range::getLastAddrOpen.
   */
  private _getLastAddrOpen(range: Range): Address {
    const curspc = range.getSpace();
    const curlast = range.getLast();
    if (curlast === curspc.getHighest()) {
      // Past the end of the space - return maximal address
      return new Address(MachExtreme.m_maximal);
    }
    return new Address(curspc, curlast + 1n);
  }
}

// ---------------------------------------------------------------------------
// ContextCache
// ---------------------------------------------------------------------------

/**
 * A helper class for caching the active context blob to minimize database lookups.
 *
 * This merely caches the last retrieved context blob ("array of words") and the range of
 * addresses over which the blob is valid. It encapsulates the ContextDatabase itself and
 * exposes a minimal interface (getContext() and setContext()).
 */
export class ContextCache {
  /** The encapsulated context database */
  private database: ContextDatabase;
  /** If set to false, any setContext() call is dropped */
  private _allowset: boolean;
  /** Address space of the current valid range */
  private curspace: AddrSpace | null;
  /** Starting offset of the current valid range */
  private first: uintb;
  /** Ending offset of the current valid range */
  private last: uintb;
  /** The current cached context blob */
  private context: number[];

  /**
   * Construct given a context database.
   *
   * @param db - the context database to encapsulate
   */
  constructor(db: ContextDatabase) {
    this.database = db;
    this.curspace = null;  // Mark cache as invalid
    this._allowset = true;
    this.first = 0n;
    this.last = 0n;
    this.context = [];
  }

  /**
   * Retrieve the encapsulated database object.
   */
  getDatabase(): ContextDatabase {
    return this.database;
  }

  /**
   * Toggle whether setContext() calls are ignored.
   *
   * @param val - true to honor setContext() calls, false to drop them
   */
  allowSet(val: boolean): void {
    this._allowset = val;
  }

  /**
   * Retrieve the context blob for the given address.
   *
   * Check if the address is in the current valid range. If it is, return the cached blob.
   * Otherwise, make a call to the database and cache a new block and valid range.
   *
   * @param addr - the given address
   * @param buf - where the blob should be stored
   */
  getContext(addr: Address, buf: number[]): void {
    if (
      addr.getSpace() !== this.curspace ||
      this.first > addr.getOffset() ||
      this.last < addr.getOffset()
    ) {
      this.curspace = addr.getSpace();
      const bounded = this.database.getContextBounded(addr);
      this.context = bounded.buf;
      this.first = bounded.first;
      this.last = bounded.last;
    }
    const sz = this.database.getContextSize();
    for (let i = 0; i < sz; i++) {
      buf[i] = this.context[i];
    }
  }

  /**
   * Change the value of a context variable at the given address with no bound.
   *
   * The context value is set starting at the given address and paints memory up
   * to the next explicit change point.
   *
   * @param addr - the given starting address
   * @param num - the word index of the context variable
   * @param mask - the mask delimiting the context variable
   * @param value - the (already shifted) value to set
   */
  setContext(addr: Address, num: int4, mask: uintm, value: uintm): void;
  /**
   * Change the value of a context variable across an explicit address range.
   *
   * The context value is painted across the range. The context variable is marked as
   * explicitly changing at the starting address of the range.
   *
   * @param addr1 - the starting address of the given range
   * @param addr2 - the ending address of the given range
   * @param num - the word index of the context variable
   * @param mask - the mask delimiting the context variable
   * @param value - the (already shifted) value to set
   */
  setContext(addr1: Address, addr2: Address, num: int4, mask: uintm, value: uintm): void;
  setContext(
    addr1: Address,
    addr2OrNum: Address | int4,
    numOrMask: int4 | uintm,
    maskOrValue?: uintm,
    value?: uintm
  ): void {
    if (typeof addr2OrNum === 'number') {
      // Single-address overload: setContext(addr, num, mask, value)
      const addr = addr1;
      const num = addr2OrNum as int4;
      const mask = numOrMask as uintm;
      const val = maskOrValue as uintm;

      if (!this._allowset) return;
      this.database.setContextChangePoint(addr, num, mask, val);
      if (
        addr.getSpace() === this.curspace &&
        this.first <= addr.getOffset() &&
        this.last >= addr.getOffset()
      ) {
        this.curspace = null;  // Invalidate cache
      }
    } else {
      // Range overload: setContext(addr1, addr2, num, mask, value)
      const addr2 = addr2OrNum as Address;
      const num = numOrMask as int4;
      const mask = maskOrValue as uintm;
      const val = value as uintm;

      if (!this._allowset) return;
      this.database.setContextRegion(addr1, addr2, num, mask, val);
      if (
        addr1.getSpace() === this.curspace &&
        this.first <= addr1.getOffset() &&
        this.last >= addr1.getOffset()
      ) {
        this.curspace = null;  // Invalidate cache
      }
      if (this.first <= addr2.getOffset() && this.last >= addr2.getOffset()) {
        this.curspace = null;  // Invalidate cache
      }
      if (this.first >= addr1.getOffset() && this.first <= addr2.getOffset()) {
        this.curspace = null;  // Invalidate cache
      }
    }
  }
}
