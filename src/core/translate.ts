/**
 * @file translate.ts
 * @description Core architecture management classes for disassembly and pcode generation.
 *
 * Translated from Ghidra's translate.hh / translate.cc.
 *
 * Provides classes for keeping track of spaces and registers (for a single architecture):
 * - AddrSpaceManager: Central manager for address spaces
 * - Translate: Base class for processor translators
 * - SpacebaseSpace: Virtual stack-like address space
 * - JoinRecord: Records how logical values are split across memory locations
 * - PcodeEmit / AssemblyEmit: Abstract classes for emitting pcode / disassembly
 * - AddressResolver: Abstract class for converting native constants to addresses
 * - TruncationTag: Describes how a space should be truncated
 * - Error classes: UnimplError, BadDataError
 */

import { Address, Range } from './address.js';
import {
  AddrSpace,
  ConstantSpace,
  OtherSpace,
  UniqueSpace,
  JoinSpace,
  OverlaySpace,
  spacetype,
} from './space.js';
import { VarnodeData, PcodeOpRaw } from './pcoderaw.js';
import { FloatFormat } from './float.js';
import { OpCode } from './opcodes.js';
import { LowlevelError } from './error.js';
import {
  Encoder,
  Decoder,
  AttributeId,
  ElementId,
  ATTRIB_NAME,
  ATTRIB_INDEX,
  ATTRIB_SIZE,
  ATTRIB_SPACE,
} from './marshal.js';
import type { int4, uint4, uintb, uintm } from './types.js';

// =========================================================================
// Global space registry for getSpaceFromConst
// =========================================================================
// In C++, space pointers are stored as integer offsets in constant varnodes.
// In TS, we encode the space index. This registry maps index -> AddrSpace
// so Varnode.getSpaceFromConst() can resolve the space without needing
// a direct reference to the AddrSpaceManager.
export const _globalSpaceRegistry: Map<int4, AddrSpace> = new Map();

// =========================================================================
// Attribute and Element IDs defined in translate.cc
// =========================================================================

export const ATTRIB_CODE = new AttributeId('code', 43);
export const ATTRIB_CONTAIN = new AttributeId('contain', 44);
export const ATTRIB_DEFAULTSPACE = new AttributeId('defaultspace', 45);
export const ATTRIB_UNIQBASE = new AttributeId('uniqbase', 46);

export const ELEM_OP = new ElementId('op', 27);
export const ELEM_SLEIGH = new ElementId('sleigh', 28);
export const ELEM_SPACE = new ElementId('space', 29);
export const ELEM_SPACEID = new ElementId('spaceid', 30);
export const ELEM_SPACES = new ElementId('spaces', 31);
export const ELEM_SPACE_BASE = new ElementId('space_base', 32);
export const ELEM_SPACE_OTHER = new ElementId('space_other', 33);
export const ELEM_SPACE_OVERLAY = new ElementId('space_overlay', 34);
export const ELEM_SPACE_UNIQUE = new ElementId('space_unique', 35);
export const ELEM_TRUNCATE_SPACE = new ElementId('truncate_space', 36);

// Re-export ELEM_VOID for use in decodeOp
import { ELEM_VOID } from './marshal.js';

// =========================================================================
// Error Classes
// =========================================================================

/**
 * Exception for encountering unimplemented pcode.
 *
 * This error is thrown when a particular machine instruction
 * cannot be translated into pcode. This particular error
 * means that the particular instruction being decoded was valid,
 * but the system doesn't know how to represent it in pcode.
 */
export class UnimplError extends LowlevelError {
  instruction_length: int4;

  /**
   * @param s is a more verbose description of the error
   * @param l is the length (in bytes) of the unimplemented instruction
   */
  constructor(s: string, l: int4) {
    super(s);
    this.name = 'UnimplError';
    this.instruction_length = l;
  }
}

/**
 * Exception for bad instruction data.
 *
 * This error is thrown when the system cannot decode data
 * for a particular instruction. This usually means that the
 * data is not really a machine instruction, but may indicate
 * that the system is unaware of the particular instruction.
 */
export class BadDataError extends LowlevelError {
  constructor(s: string) {
    super(s);
    this.name = 'BadDataError';
  }
}

// =========================================================================
// TruncationTag
// =========================================================================

/**
 * Object for describing how a space should be truncated.
 *
 * This can turn up in various configuration files and essentially acts
 * as a command to override the size of an address space as defined by the architecture.
 */
export class TruncationTag {
  private spaceName: string = '';
  private size: uint4 = 0;

  /** Restore this from a stream */
  decode(decoder: Decoder): void {
    const elemId: uint4 = decoder.openElement();
    this.spaceName = decoder.readStringById(ATTRIB_SPACE);
    this.size = Number(decoder.readUnsignedIntegerById(ATTRIB_SIZE));
    decoder.closeElement(elemId);
  }

  /** Get name of address space being truncated */
  getName(): string {
    return this.spaceName;
  }

  /** Size (of pointers) for new truncated space */
  getSize(): uint4 {
    return this.size;
  }
}

// =========================================================================
// PcodeEmit (abstract)
// =========================================================================

/**
 * Abstract class for emitting pcode to an application.
 *
 * Translation engines pass back the generated pcode for an
 * instruction to the application using this class.
 */
export abstract class PcodeEmit {
  /**
   * The main pcode emit method.
   *
   * A single pcode instruction is returned to the application via this method.
   * Particular applications override it to tailor how the operations are used.
   *
   * @param addr is the Address of the machine instruction
   * @param opc is the opcode of the particular pcode instruction
   * @param outvar if not null is data about the output varnode
   * @param vars is an array of VarnodeData for each input varnode
   * @param isize is the number of input varnodes
   */
  abstract dump(
    addr: Address,
    opc: OpCode,
    outvar: VarnodeData | null,
    vars: VarnodeData[],
    isize: int4,
  ): void;

  /**
   * Emit pcode directly from an <op> element.
   *
   * A convenience method for passing around p-code operations via stream.
   * A single p-code operation is parsed from an <op> element and
   * returned to the application via the dump method.
   *
   * @param addr is the address (of the instruction) to associate with the p-code op
   * @param decoder is the stream decoder
   */
  decodeOp(addr: Address, decoder: Decoder): void {
    const elemId: uint4 = decoder.openElement();
    const isize: int4 = decoder.readSignedIntegerById(ATTRIB_SIZE);

    const opcode: int4 = decoder.readSignedIntegerById(ATTRIB_CODE);
    let outvar: VarnodeData | null = null;

    const subId: uint4 = decoder.peekElement();
    if (subId === ELEM_VOID.id) {
      decoder.openElement();
      decoder.closeElement(subId);
      outvar = null;
    } else {
      outvar = new VarnodeData();
      // Decode output varnode from next element
      const outElemId = decoder.openElement();
      // Read space attribute, then use decodeAttributes on the space
      let foundSpace = false;
      for (;;) {
        const attribId = decoder.getNextAttributeId();
        if (attribId === 0) break;
        if (attribId === ATTRIB_SPACE.id) {
          outvar.space = decoder.readSpace() as any;
          decoder.rewindAttributes();
          const sizeRef = { val: 0 };
          outvar.offset = (outvar.space as any).decodeAttributes_sized(decoder, sizeRef);
          outvar.size = sizeRef.val;
          foundSpace = true;
          break;
        } else if (attribId === ATTRIB_NAME.id) {
          // Register reference
          const trans = (decoder.getAddrSpaceManager() as any).getDefaultCodeSpace().getTrans();
          const point = trans.getRegister(decoder.readString());
          outvar.space = point.space;
          outvar.offset = point.offset;
          outvar.size = point.size;
          foundSpace = true;
          break;
        }
      }
      decoder.closeElement(outElemId);
    }

    const invar: VarnodeData[] = [];
    for (let i = 0; i < isize; i++) {
      const peekId: uint4 = decoder.peekElement();
      if (peekId === ELEM_SPACEID.id) {
        decoder.openElement();
        const v = new VarnodeData();
        v.space = (decoder.getAddrSpaceManager() as any).getConstantSpace();
        const readSpc = decoder.readSpaceById(ATTRIB_NAME);
        v.offset = BigInt((readSpc as any).getIndex());
        v.size = 8; // sizeof(void*)
        decoder.closeElement(peekId);
        invar.push(v);
      } else {
        const v = new VarnodeData();
        const inElemId = decoder.openElement();
        let foundSpace = false;
        for (;;) {
          const attribId = decoder.getNextAttributeId();
          if (attribId === 0) break;
          if (attribId === ATTRIB_SPACE.id) {
            v.space = decoder.readSpace() as any;
            decoder.rewindAttributes();
            const sizeRef = { val: 0 };
            v.offset = (v.space as any).decodeAttributes_sized(decoder, sizeRef);
            v.size = sizeRef.val;
            foundSpace = true;
            break;
          } else if (attribId === ATTRIB_NAME.id) {
            const trans = (decoder.getAddrSpaceManager() as any).getDefaultCodeSpace().getTrans();
            const point = trans.getRegister(decoder.readString());
            v.space = point.space;
            v.offset = point.offset;
            v.size = point.size;
            foundSpace = true;
            break;
          }
        }
        decoder.closeElement(inElemId);
        invar.push(v);
      }
    }

    decoder.closeElement(elemId);
    this.dump(addr, opcode as OpCode, outvar, invar, isize);
  }
}

// =========================================================================
// AssemblyEmit (abstract)
// =========================================================================

/**
 * Abstract class for emitting disassembly to an application.
 *
 * Translation engines pass back the disassembly character data
 * for decoded machine instructions to an application using this class.
 */
export abstract class AssemblyEmit {
  /**
   * The main disassembly emitting method.
   *
   * The disassembly strings for a single machine instruction
   * are passed back to an application through this method.
   *
   * @param addr is the Address of the machine instruction
   * @param mnem is the decoded instruction mnemonic
   * @param body is the decoded body (or operands) of the instruction
   */
  abstract dump(addr: Address, mnem: string, body: string): void;
}

// =========================================================================
// AddressResolver (abstract)
// =========================================================================

/**
 * Abstract class for converting native constants to addresses.
 *
 * This class is used if there is a special calculation to get from a constant embedded
 * in the code being analyzed to the actual Address being referred to. This is used especially
 * in the case of a segmented architecture, where "near" pointers must be extended to a full address
 * with implied segment information.
 */
export abstract class AddressResolver {
  /**
   * The main resolver method.
   *
   * Given a native constant in a specific context, resolve what address is being referred to.
   *
   * @param val is constant to be resolved to an address
   * @param sz is the size of val in context (or -1)
   * @param point is the address at which this constant is being used
   * @param fullEncoding is used to hold the full pointer encoding if val is a partial encoding
   * @return the resolved Address
   */
  abstract resolve(
    val: uintb,
    sz: int4,
    point: Address,
    fullEncoding: { val: uintb },
  ): Address;
}

// =========================================================================
// SpacebaseSpace
// =========================================================================

/**
 * A virtual space (stack space).
 *
 * In a lot of analysis situations it is convenient to extend
 * the notion of an address space to mean bytes that are indexed
 * relative to some base register. The canonical example of this
 * is the stack space, which models the concept of local
 * variables stored on the stack.
 */
export class SpacebaseSpace extends AddrSpace {
  private contain!: AddrSpace | null;
  private hasbaseregister!: boolean;
  private isNegativeStack_!: boolean;
  private baseloc!: VarnodeData;
  private baseOrig!: VarnodeData;

  /**
   * Full constructor for a virtual space.
   * @param m is the manager for this program specific address space
   * @param t is associated processor translator
   * @param nm is the name of the space
   * @param ind is the integer identifier
   * @param sz is the size of the space
   * @param base is the containing space
   * @param dl is the heritage delay
   * @param isFormal is the formal stack space indicator
   */
  constructor(
    m: any,
    t: any,
    nm: string,
    ind: int4,
    sz: int4,
    base: AddrSpace,
    dl: int4,
    isFormal: boolean,
  );
  /**
   * Partial constructor for decode.
   * @param m is the associated address space manager
   * @param t is the associated processor translator
   */
  constructor(m: any, t: any);
  constructor(
    m: any,
    t: any,
    nm?: string,
    ind?: int4,
    sz?: int4,
    base?: AddrSpace,
    dl?: int4,
    isFormal?: boolean,
  ) {
    if (nm !== undefined) {
      // Full constructor
      const isBigEnd: boolean = t?.isBigEndian?.() ?? false;
      super(
        m,
        t,
        spacetype.IPTR_SPACEBASE,
        nm,
        isBigEnd,
        sz!,
        base!.getWordSize(),
        ind!,
        0,
        dl!,
        dl!,
      );
      this.contain = base!;
      this.hasbaseregister = false;
      this.isNegativeStack_ = true;
      this.baseloc = new VarnodeData();
      this.baseOrig = new VarnodeData();
      if (isFormal!) {
        this.setFlags(AddrSpace.formal_stackspace);
      }
    } else {
      // Partial constructor for decode
      super(m, t, spacetype.IPTR_SPACEBASE);
      this.contain = null;
      this.hasbaseregister = false;
      this.isNegativeStack_ = true;
      this.baseloc = new VarnodeData();
      this.baseOrig = new VarnodeData();
      this.setFlags(AddrSpace.programspecific);
    }
  }

  /**
   * Set the base register at time space is created.
   * This routine sets the base register associated with this virtual space.
   * It will throw an exception if something tries to set two (different) base registers.
   *
   * @param data is the location data for the base register
   * @param origSize is the size of the space covered by the register
   * @param stackGrowth is true if the stack grows in a negative direction
   */
  setBaseRegister(data: VarnodeData, origSize: int4, stackGrowth: boolean): void {
    if (this.hasbaseregister) {
      if (
        !this.baseloc.equals(data) ||
        this.isNegativeStack_ !== stackGrowth
      ) {
        throw new LowlevelError(
          'Attempt to assign more than one base register to space: ' +
            this.getName(),
        );
      }
    }
    this.hasbaseregister = true;
    this.isNegativeStack_ = stackGrowth;
    this.baseOrig = new VarnodeData(data.space, data.offset, data.size);
    this.baseloc = new VarnodeData(data.space, data.offset, data.size);
    if (origSize !== this.baseloc.size) {
      if ((this.baseloc.space as any).isBigEndian()) {
        this.baseloc.offset += BigInt(this.baseloc.size - origSize);
      }
      this.baseloc.size = origSize;
    }
  }

  override numSpacebase(): int4 {
    return this.hasbaseregister ? 1 : 0;
  }

  override getSpacebase(i: int4): VarnodeData {
    if (!this.hasbaseregister || i !== 0) {
      throw new LowlevelError(
        'No base register specified for space: ' + this.getName(),
      );
    }
    return this.baseloc;
  }

  override getSpacebaseFull(i: int4): VarnodeData {
    if (!this.hasbaseregister || i !== 0) {
      throw new LowlevelError(
        'No base register specified for space: ' + this.getName(),
      );
    }
    return this.baseOrig;
  }

  override stackGrowsNegative(): boolean {
    return this.isNegativeStack_;
  }

  override getContain(): AddrSpace | null {
    return this.contain;
  }

  override decode(decoder: Decoder): void {
    const elemId: uint4 = (decoder as any).openElement();
    (this as any).decodeBasicAttributes(decoder);
    this.contain = (decoder as any).readSpaceById(ATTRIB_CONTAIN);
    (decoder as any).closeElement(elemId);
  }
}

// =========================================================================
// JoinRecord
// =========================================================================

/**
 * A record describing how logical values are split.
 *
 * The decompiler can describe a logical value that is stored split across multiple
 * physical memory locations. This record describes such a split. The pieces must be listed
 * from most significant to least significant.
 */
export class JoinRecord {
  pieces: VarnodeData[] = [];
  unified: VarnodeData = new VarnodeData();

  /** Get number of pieces in this record */
  numPieces(): int4 {
    return this.pieces.length;
  }

  /** Does this record extend a float varnode */
  isFloatExtension(): boolean {
    return this.pieces.length === 1;
  }

  /** Get the i-th piece */
  getPiece(i: int4): VarnodeData {
    return this.pieces[i];
  }

  /** Get the Varnode whole */
  getUnified(): VarnodeData {
    return this.unified;
  }

  /**
   * Given offset in join space, get equivalent address of piece.
   *
   * The join space range maps to the underlying pieces in a natural endian aware way.
   * Given an offset in the range, figure out what address it is mapping to.
   * The particular piece is passed back as an index, and the Address is returned.
   *
   * @param offset is the offset within this range to map
   * @param posRef will hold the passed back piece index
   * @return the Address mapped to
   */
  getEquivalentAddress(
    offset: uintb,
    posRef: { val: int4 },
  ): Address {
    if (offset < this.unified.offset) {
      return new Address(); // offset comes before this range
    }
    let smallOff: int4 = Number(offset - this.unified.offset);
    let pos: int4;
    if ((this.pieces[0].space as any).isBigEndian()) {
      for (pos = 0; pos < this.pieces.length; ++pos) {
        const pieceSize: int4 = this.pieces[pos].size;
        if (smallOff < pieceSize) break;
        smallOff -= pieceSize;
      }
      if (pos === this.pieces.length) {
        return new Address(); // offset comes after this range
      }
    } else {
      for (pos = this.pieces.length - 1; pos >= 0; --pos) {
        const pieceSize: int4 = this.pieces[pos].size;
        if (smallOff < pieceSize) break;
        smallOff -= pieceSize;
      }
      if (pos < 0) {
        return new Address(); // offset comes after this range
      }
    }
    posRef.val = pos;
    return new Address(
      this.pieces[pos].space as any,
      this.pieces[pos].offset + BigInt(smallOff),
    );
  }

  /**
   * Compare records lexicographically by pieces.
   * Allows sorting on JoinRecords so that a collection of pieces can be quickly
   * mapped to its logical whole, specified with a join address.
   */
  lessThan(op2: JoinRecord): boolean {
    // Some joins may have same piece but different unified size (floating point)
    if (this.unified.size !== op2.unified.size) {
      return this.unified.size < op2.unified.size;
    }
    // Lexicographic sort on pieces
    let i = 0;
    for (;;) {
      if (this.pieces.length === i) {
        // If more pieces in op2, it is bigger (return true)
        // If same number, this==op2, return false
        return op2.pieces.length > i;
      }
      if (op2.pieces.length === i) return false;
      if (!this.pieces[i].equals(op2.pieces[i])) {
        return this.pieces[i].lessThan(op2.pieces[i]);
      }
      i += 1;
    }
  }

  /**
   * Merge any contiguous ranges in a sequence.
   *
   * Assuming the given list of VarnodeData go from most significant to least significant,
   * merge any contiguous elements in the list. Varnodes that are not in the stack address space
   * are only merged if the resulting byte range has a formal register name.
   *
   * @param seq is the given list of VarnodeData
   * @param trans is the language to use for register names
   */
  static mergeSequence(seq: VarnodeData[], trans: Translate): void {
    let i: int4 = 1;
    while (i < seq.length) {
      const hi = seq[i - 1];
      const lo = seq[i];
      if (hi.isContiguous(lo)) break;
      i += 1;
    }
    if (i >= seq.length) return;

    const res: VarnodeData[] = [];
    i = 1;
    res.push(
      new VarnodeData(seq[0].space, seq[0].offset, seq[0].size),
    );
    let lastIsInformal = false;
    while (i < seq.length) {
      const hi = res[res.length - 1];
      const lo = seq[i];
      if (hi.isContiguous(lo)) {
        hi.offset = (hi.space as any).isBigEndian()
          ? hi.offset
          : lo.offset;
        hi.size += lo.size;
        if ((hi.space as any).getType() !== spacetype.IPTR_SPACEBASE) {
          lastIsInformal =
            trans
              .getExactRegisterName(hi.space as any, hi.offset, hi.size)
              .length === 0;
        }
      } else {
        if (lastIsInformal) break;
        res.push(
          new VarnodeData(lo.space, lo.offset, lo.size),
        );
      }
      i += 1;
    }
    if (lastIsInformal) {
      // If the merge contains an informal register, throw it out and keep original
      return;
    }
    seq.length = 0;
    for (const v of res) {
      seq.push(v);
    }
  }
}

// =========================================================================
// Sentinel for getNextSpaceInOrder "past end"
// =========================================================================

const SPACE_END_SENTINEL: AddrSpace = Object.freeze({
  __spaceEndSentinel: true,
  getIndex(): number { return Number.MAX_SAFE_INTEGER; },
  getName(): string { return '__end__'; },
}) as unknown as AddrSpace;

// =========================================================================
// AddrSpaceManager
// =========================================================================

/**
 * A manager for different address spaces.
 *
 * Allows creation, lookup by name, lookup by shortcut, and iteration
 * over address spaces.
 */
export class AddrSpaceManager {
  private baselist: (AddrSpace | null)[] = [];
  private resolvelist: (AddressResolver | null)[] = [];
  private name2Space: Map<string, AddrSpace> = new Map();
  private shortcut2Space: Map<string, AddrSpace> = new Map();
  private constantspace: AddrSpace | null = null;
  private defaultcodespace: AddrSpace | null = null;
  private defaultdataspace: AddrSpace | null = null;
  private iopspace: AddrSpace | null = null;
  private fspecspace: AddrSpace | null = null;
  private joinspace: AddrSpace | null = null;
  private stackspace: AddrSpace | null = null;
  private uniqspace: AddrSpace | null = null;
  private joinallocate: uintb = 0n;
  /** Sorted set (by JoinRecord comparator) of join records */
  private splitset: JoinRecord[] = [];
  /** JoinRecords indexed by join address (in order of allocation) */
  private splitlist: JoinRecord[] = [];

  constructor() {
    // Initialize manager containing no address spaces
  }

  // ---- Protected methods ----

  /**
   * Add a space to the model based on a decoder element.
   *
   * The initialization of address spaces is the same across all
   * variants of the Translate object. This routine initializes
   * a single address space from a decoder element. It knows
   * which class derived from AddrSpace to instantiate based on
   * the ElementId.
   */
  protected decodeSpace(decoder: Decoder, trans: Translate): AddrSpace {
    const elemId: uint4 = decoder.peekElement();
    let res: AddrSpace;
    if (elemId === ELEM_SPACE_BASE.id) {
      res = new SpacebaseSpace(this as any, trans);
    } else if (elemId === ELEM_SPACE_UNIQUE.id) {
      res = new UniqueSpace(this as any, trans);
    } else if (elemId === ELEM_SPACE_OTHER.id) {
      res = new OtherSpace(this as any, trans);
    } else if (elemId === ELEM_SPACE_OVERLAY.id) {
      res = new OverlaySpace(this as any, trans);
    } else {
      res = new AddrSpace(this as any, trans, spacetype.IPTR_PROCESSOR);
    }

    res.decode(decoder);
    return res;
  }

  /**
   * Restore address spaces in the model from a stream.
   *
   * This routine initializes (almost) all the address spaces used
   * for a particular processor by using a <spaces> element,
   * which contains child elements for the specific address spaces.
   * This also instantiates the builtin constant space.
   */
  protected decodeSpaces(decoder: Decoder, trans: Translate): void {
    // The first space should always be the constant space
    this.insertSpace(new ConstantSpace(this as any, trans));

    const elemId: uint4 = decoder.openElement();
    const defname: string = decoder.readStringById(ATTRIB_DEFAULTSPACE);
    while (decoder.peekElement() !== 0) {
      const spc: AddrSpace = this.decodeSpace(decoder, trans);
      this.insertSpace(spc);
    }
    decoder.closeElement(elemId);
    const spc = this.getSpaceByName(defname);
    if (spc === null) {
      throw new LowlevelError("Bad 'defaultspace' attribute: " + defname);
    }
    this.setDefaultCodeSpace(spc.getIndex());
  }

  /**
   * Set the default address space (for code).
   * Once all the address spaces have been initialized, this routine
   * should be called once to establish the official default
   * space for the processor, via its index.
   */
  protected setDefaultCodeSpace(index: int4): void {
    if (this.defaultcodespace !== null) {
      throw new LowlevelError('Default space set multiple times');
    }
    if (
      this.baselist.length <= index ||
      this.baselist[index] === null
    ) {
      throw new LowlevelError('Bad index for default space');
    }
    this.defaultcodespace = this.baselist[index]!;
    this.defaultdataspace = this.defaultcodespace;
  }

  /**
   * Set the default address space for data.
   * If the architecture has different code and data spaces, this routine can be called
   * to set the data space after the code space has been set.
   */
  protected setDefaultDataSpace(index: int4): void {
    if (this.defaultcodespace === null) {
      throw new LowlevelError(
        'Default data space must be set after the code space',
      );
    }
    if (
      this.baselist.length <= index ||
      this.baselist[index] === null
    ) {
      throw new LowlevelError('Bad index for default data space');
    }
    this.defaultdataspace = this.baselist[index]!;
  }

  /**
   * Set reverse justified property on this space.
   *
   * For spaces with alignment restrictions, the address of a small variable must be justified
   * within a larger aligned memory word. Setting this property causes the decompiler
   * to use the opposite justification from what the endianness would suggest.
   */
  protected setReverseJustified(spc: AddrSpace): void {
    (spc as any).setFlags(AddrSpace.reverse_justification);
  }

  /**
   * Select a shortcut character for a new space.
   *
   * This routine makes use of the desired type of the new space
   * and info about shortcuts for spaces that already exist to
   * pick a unique and consistent character. This method also builds
   * up a map from shortcut to AddrSpace object.
   */
  protected assignShortcut(spc: AddrSpace): void {
    if (spc.getShortcut() !== ' ') {
      // If the shortcut is already assigned
      this.shortcut2Space.set(spc.getShortcut(), spc);
      return;
    }
    let shortcut: string;
    switch (spc.getType()) {
      case spacetype.IPTR_CONSTANT:
        shortcut = '#';
        break;
      case spacetype.IPTR_PROCESSOR:
        if (spc.getName() === 'register') {
          shortcut = '%';
        } else {
          shortcut = spc.getName()[0];
        }
        break;
      case spacetype.IPTR_SPACEBASE:
        shortcut = 's';
        break;
      case spacetype.IPTR_INTERNAL:
        shortcut = 'u';
        break;
      case spacetype.IPTR_FSPEC:
        shortcut = 'f';
        break;
      case spacetype.IPTR_JOIN:
        shortcut = 'j';
        break;
      case spacetype.IPTR_IOP:
        shortcut = 'i';
        break;
      default:
        shortcut = 'x';
        break;
    }

    if (shortcut >= 'A' && shortcut <= 'Z') {
      shortcut = String.fromCharCode(shortcut.charCodeAt(0) + 0x20);
    }

    let collisionCount = 0;
    while (this.shortcut2Space.has(shortcut)) {
      collisionCount += 1;
      if (collisionCount > 26) {
        // Could not find a unique shortcut, but we just re-use 'z'
        spc.setShortcut('z');
        return;
      }
      shortcut = String.fromCharCode(shortcut.charCodeAt(0) + 1);
      if (shortcut < 'a' || shortcut > 'z') {
        shortcut = 'a';
      }
    }
    this.shortcut2Space.set(shortcut, spc);
    spc.setShortcut(shortcut);
  }

  /**
   * Mark that given space can be accessed with near pointers.
   * @param spc is the AddrSpace to mark
   * @param size is the (minimum) size of a near pointer in bytes
   */
  protected markNearPointers(spc: AddrSpace, size: int4): void {
    (spc as any).setFlags(AddrSpace.has_nearpointers);
    const spcAny = spc as any;
    if (spcAny.minimumPointerSize === 0 && spcAny.addressSize !== size) {
      spcAny.minimumPointerSize = size;
    }
  }

  /**
   * Add a new address space to the model.
   *
   * This adds a previously instantiated address space (AddrSpace)
   * to the model for this processor. It checks a set of
   * indexing and naming conventions for the space and throws
   * an exception if the conventions are violated.
   */
  protected insertSpace(spc: AddrSpace): void {
    let nameTypeMismatch = false;
    let duplicateName = false;
    let duplicateId = false;
    const spcIndex = spc.getIndex();

    switch (spc.getType()) {
      case spacetype.IPTR_CONSTANT:
        if (spc.getName() !== ConstantSpace.NAME) nameTypeMismatch = true;
        if (spcIndex !== ConstantSpace.INDEX)
          throw new LowlevelError('const space must be assigned index 0');
        this.constantspace = spc;
        break;
      case spacetype.IPTR_INTERNAL:
        if (spc.getName() !== UniqueSpace.NAME) nameTypeMismatch = true;
        if (this.uniqspace !== null) duplicateName = true;
        this.uniqspace = spc;
        break;
      case spacetype.IPTR_FSPEC:
        if (spc.getName() !== 'fspec') nameTypeMismatch = true;
        if (this.fspecspace !== null) duplicateName = true;
        this.fspecspace = spc;
        break;
      case spacetype.IPTR_JOIN:
        if (spc.getName() !== JoinSpace.NAME) nameTypeMismatch = true;
        if (this.joinspace !== null) duplicateName = true;
        this.joinspace = spc;
        break;
      case spacetype.IPTR_IOP:
        if (spc.getName() !== 'iop') nameTypeMismatch = true;
        if (this.iopspace !== null) duplicateName = true;
        this.iopspace = spc;
        break;
      case spacetype.IPTR_SPACEBASE:
        if (spc.getName() === 'stack') {
          if (this.stackspace !== null) duplicateName = true;
          this.stackspace = spc;
        }
      // fallthrough
      case spacetype.IPTR_PROCESSOR:
        if (spc.isOverlay()) {
          // If this is a new overlay space, mark the base as being overlayed
          const contain = spc.getContain();
          if (contain !== null) {
            (contain as any).setFlags(AddrSpace.overlaybase);
          }
        } else if (spc.isOtherSpace()) {
          if (spcIndex !== OtherSpace.INDEX)
            throw new LowlevelError(
              'OTHER space must be assigned index 1',
            );
        }
        break;
    }

    if (this.baselist.length <= spcIndex) {
      // Resize baselist
      while (this.baselist.length <= spcIndex) {
        this.baselist.push(null);
      }
    }

    duplicateId = this.baselist[spcIndex] !== null;

    // Register in global registry for getSpaceFromConst
    _globalSpaceRegistry.set(spcIndex, spc);

    if (!nameTypeMismatch && !duplicateName && !duplicateId) {
      if (this.name2Space.has(spc.getName())) {
        duplicateName = true;
      } else {
        this.name2Space.set(spc.getName(), spc);
      }
    }

    if (nameTypeMismatch || duplicateName || duplicateId) {
      let errMsg = 'Space ' + spc.getName();
      if (nameTypeMismatch)
        errMsg = errMsg + ' was initialized with wrong type';
      if (duplicateName)
        errMsg = errMsg + ' was initialized more than once';
      if (duplicateId)
        errMsg =
          errMsg +
          ' was assigned as id duplicating: ' +
          this.baselist[spcIndex]!.getName();
      // In C++, if spc->refcount == 0, delete spc; We skip that in TS (GC handles it)
      throw new LowlevelError(errMsg);
    }
    this.baselist[spcIndex] = spc;
    spc._incRefCount();
    this.assignShortcut(spc);
  }

  /**
   * Copy spaces from another manager.
   *
   * Different managers may need to share the same spaces. This routine pulls in a reference
   * of every space in op2 in order to manage it from within this manager.
   */
  protected copySpaces(op2: AddrSpaceManager): void {
    for (let i = 0; i < op2.baselist.length; ++i) {
      const spc = op2.baselist[i];
      if (spc !== null) {
        this.insertSpace(spc);
      }
    }
    this.setDefaultCodeSpace(op2.getDefaultCodeSpace()!.getIndex());
    this.setDefaultDataSpace(op2.getDefaultDataSpace()!.getIndex());
  }

  /**
   * Perform the privileged act of associating a base register with an existing virtual space.
   *
   * @param basespace is the virtual space
   * @param ptrdata is the location data for the base register
   * @param truncSize is the size of the space covered by the base register
   * @param stackGrowth is true if the stack grows "normally" towards address 0
   */
  protected addSpacebasePointer(
    basespace: SpacebaseSpace,
    ptrdata: VarnodeData,
    truncSize: int4,
    stackGrowth: boolean,
  ): void {
    basespace.setBaseRegister(ptrdata, truncSize, stackGrowth);
  }

  /**
   * Provide a new specialized resolver for a specific AddrSpace.
   *
   * @param spc is the space to which the resolver is associated
   * @param rsolv is the new resolver object
   */
  protected insertResolver(
    spc: AddrSpace,
    rsolv: AddressResolver,
  ): void {
    const ind: int4 = spc.getIndex();
    while (this.resolvelist.length <= ind) {
      this.resolvelist.push(null);
    }
    // In C++, the old resolver is deleted. GC handles it in TS.
    this.resolvelist[ind] = rsolv;
  }

  /**
   * Set the range of addresses that can be inferred as pointers.
   *
   * This method establishes for a single address space, what range of constants are checked
   * as possible symbol starts, when it is not known a priori that a constant is a pointer.
   *
   * @param range is the range of values for a single address space
   */
  protected setInferPtrBounds(range: Range): void {
    // Access private fields via cast since C++ uses friend
    (range.getSpace() as any).pointerLowerBound = range.getFirst();
    (range.getSpace() as any).pointerUpperBound = range.getLast();
  }

  /**
   * Find JoinRecord for offset in the join space (internal, binary search).
   *
   * Given a specific offset into the join address space, recover the JoinRecord that
   * contains the offset, as a range in the join address space. If there is no existing
   * record, null is returned.
   */
  protected findJoinInternal(offset: uintb): JoinRecord | null {
    let min = 0;
    let max = this.splitlist.length - 1;
    while (min <= max) {
      const mid = (min + max) >>> 1;
      const rec = this.splitlist[mid];
      const val = rec.unified.offset;
      if (val + BigInt(rec.unified.size) <= offset) {
        min = mid + 1;
      } else if (val > offset) {
        max = mid - 1;
      } else {
        return rec;
      }
    }
    return null;
  }

  // ---- Public methods ----

  /**
   * Get size of addresses for the default space.
   * This space is usually the main RAM databus.
   */
  getDefaultSize(): int4 {
    return this.defaultcodespace!.getAddrSize();
  }

  /**
   * Get address space by name.
   * All address spaces have a unique name associated with them.
   */
  getSpaceByName(nm: string): AddrSpace | null {
    return this.name2Space.get(nm) ?? null;
  }

  /**
   * Get address space from its shortcut.
   * All address spaces have a unique shortcut (ASCII) character assigned to them.
   */
  getSpaceByShortcut(sc: string): AddrSpace | null {
    return this.shortcut2Space.get(sc) ?? null;
  }

  /** Get the internal pcode op space */
  getIopSpace(): AddrSpace | null {
    return this.iopspace;
  }

  /** Get the internal callspec space */
  getFspecSpace(): AddrSpace | null {
    return this.fspecspace;
  }

  /** Get the joining space */
  getJoinSpace(): AddrSpace | null {
    return this.joinspace;
  }

  /** Get the stack space for this processor */
  getStackSpace(): AddrSpace | null {
    return this.stackspace;
  }

  /** Get the temporary register space for this processor */
  getUniqueSpace(): AddrSpace | null {
    return this.uniqspace;
  }

  /** Get the default address space of this processor (for code) */
  getDefaultCodeSpace(): AddrSpace | null {
    return this.defaultcodespace;
  }

  /** Get the default address space where data is stored */
  getDefaultDataSpace(): AddrSpace | null {
    return this.defaultdataspace;
  }

  /** Get the constant space */
  getConstantSpace(): AddrSpace | null {
    return this.constantspace;
  }

  /**
   * Get a constant encoded as an Address.
   *
   * This routine encodes a specific value as a constant
   * address. The address space of the resulting Address
   * will be the constant space, and the offset will be the value.
   */
  getConstant(val: uintb): Address {
    return new Address(this.constantspace!, val);
  }

  /**
   * Create a constant address encoding an address space.
   *
   * This routine is used to encode a pointer to an address space
   * as a constant Address, for use in LOAD and STORE operations.
   * Since we cannot store a pointer as an integer like C++, we encode
   * the space's index as a bigint instead.
   */
  createConstFromSpace(spc: AddrSpace): Address {
    return new Address(this.constantspace!, BigInt(spc.getIndex()));
  }

  /**
   * Resolve a native constant into an Address.
   *
   * If there is a special resolver for the AddrSpace, this is invoked, otherwise
   * basic wordsize conversion and wrapping is performed.
   *
   * @param spc is the space to generate the address from
   * @param val is the constant encoding of the address
   * @param sz is the size of the constant encoding (or -1)
   * @param point is the context address
   * @param fullEncoding is used to pass back the recovered full encoding of the pointer
   * @return the formal Address associated with the encoding
   */
  resolveConstant(
    spc: AddrSpace,
    val: uintb,
    sz: int4,
    point: Address,
    fullEncoding: { val: uintb },
  ): Address {
    const ind: int4 = spc.getIndex();
    if (ind < this.resolvelist.length) {
      const resolve = this.resolvelist[ind];
      if (resolve !== null) {
        return resolve.resolve(val, sz, point, fullEncoding);
      }
    }
    fullEncoding.val = val;
    val = AddrSpace.addressToByte(val, spc.getWordSize());
    val = spc.wrapOffset(val);
    return new Address(spc, val);
  }

  /** Get the number of address spaces for this processor */
  numSpaces(): int4 {
    return this.baselist.length;
  }

  /**
   * Get an address space via its index.
   * This retrieves a specific address space via its formal index.
   */
  getSpace(i: int4): AddrSpace | null {
    if (i < 0 || i >= this.baselist.length) return null;
    return this.baselist[i];
  }

  /**
   * Get the next contiguous address space.
   *
   * Get the next space in the absolute order of addresses.
   * This ordering is determined by the AddrSpace index.
   * Use null for "before first". Returns SPACE_END_SENTINEL for past-end,
   * and null when called with the sentinel to indicate done.
   */
  getNextSpaceInOrder(spc: AddrSpace | null): AddrSpace | null {
    if (spc === null) {
      // Start: return first non-null space
      if (this.baselist.length > 0) {
        for (let i = 0; i < this.baselist.length; i++) {
          if (this.baselist[i] !== null) return this.baselist[i];
        }
      }
      return SPACE_END_SENTINEL;
    }
    if (spc === SPACE_END_SENTINEL) {
      return null;
    }
    let index = spc.getIndex() + 1;
    while (index < this.baselist.length) {
      const res = this.baselist[index];
      if (res !== null) return res;
      index += 1;
    }
    return SPACE_END_SENTINEL;
  }

  /**
   * Get (or create) JoinRecord for pieces.
   *
   * Given a list of memory locations, the pieces, either find a pre-existing JoinRecord or
   * create a JoinRecord that represents the logical joining of the pieces. The pieces must
   * be in order from most significant to least significant.
   *
   * @param pieces is the list of memory locations to be joined
   * @param logicalsize of a single piece join, or zero
   * @return a pointer to the JoinRecord
   */
  findAddJoin(pieces: VarnodeData[], logicalsize: uint4): JoinRecord {
    if (pieces.length === 0) {
      throw new LowlevelError('Cannot create a join without pieces');
    }
    if (pieces.length === 1 && logicalsize === 0) {
      throw new LowlevelError(
        'Cannot create a single piece join without a logical size',
      );
    }

    let totalsize: uint4;
    if (logicalsize !== 0) {
      if (pieces.length !== 1) {
        throw new LowlevelError(
          'Cannot specify logical size for multiple piece join',
        );
      }
      totalsize = logicalsize;
    } else {
      totalsize = 0;
      for (let i = 0; i < pieces.length; ++i) {
        totalsize += pieces[i].size;
      }
      if (totalsize === 0) {
        throw new LowlevelError('Cannot create a zero size join');
      }
    }

    // Build a test node for comparison
    const testnode = new JoinRecord();
    testnode.pieces = pieces.map(
      (p) => new VarnodeData(p.space, p.offset, p.size),
    );
    testnode.unified.size = totalsize;

    // Search in splitset
    for (const existing of this.splitset) {
      if (
        !existing.lessThan(testnode) &&
        !testnode.lessThan(existing)
      ) {
        // Found a match
        return existing;
      }
    }

    // Create a new join record
    const newjoin = new JoinRecord();
    newjoin.pieces = pieces.map(
      (p) => new VarnodeData(p.space, p.offset, p.size),
    );

    const roundsize: uint4 = (totalsize + 15) & ~0xf; // Next biggest multiple of 16

    newjoin.unified.space = this.joinspace as any;
    newjoin.unified.offset = this.joinallocate;
    this.joinallocate += BigInt(roundsize);
    newjoin.unified.size = totalsize;

    // Insert into splitset (sorted)
    this._insertIntoSplitset(newjoin);
    this.splitlist.push(newjoin);
    return this.splitlist[this.splitlist.length - 1];
  }

  /**
   * Insert a JoinRecord into the sorted splitset array.
   */
  private _insertIntoSplitset(rec: JoinRecord): void {
    // Binary search for insertion point
    let lo = 0;
    let hi = this.splitset.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (this.splitset[mid].lessThan(rec)) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    this.splitset.splice(lo, 0, rec);
  }

  /**
   * Find JoinRecord for offset in the join space.
   *
   * Given a specific offset into the join address space, recover the JoinRecord that
   * lists the pieces corresponding to that offset. The offset must originally have come from
   * a JoinRecord returned by findAddJoin, otherwise this method throws an exception.
   */
  findJoin(offset: uintb): JoinRecord {
    let min = 0;
    let max = this.splitlist.length - 1;
    while (min <= max) {
      const mid = (min + max) >>> 1;
      const rec = this.splitlist[mid];
      const val = rec.unified.offset;
      if (val === offset) return rec;
      if (val < offset) {
        min = mid + 1;
      } else {
        max = mid - 1;
      }
    }
    throw new LowlevelError('Unlinked join address');
  }

  /**
   * Set the deadcodedelay for a specific space.
   *
   * Set the number of passes for a specific AddrSpace before deadcode removal is allowed
   * for that space.
   *
   * @param spc is the AddrSpace to change
   * @param delaydelta is the number of rounds the delay should be set to
   */
  setDeadcodeDelay(spc: AddrSpace, delaydelta: int4): void {
    (spc as any).deadcodedelay = delaydelta;
  }

  /**
   * Mark the named space as truncated from its original size.
   * @param tag is a description of the space and how it should be truncated
   */
  truncateSpace(tag: TruncationTag): void {
    const spc = this.getSpaceByName(tag.getName());
    if (spc === null) {
      throw new LowlevelError(
        'Unknown space in <truncate_space> command: ' + tag.getName(),
      );
    }
    (spc as any).truncateSpace(tag.getSize());
  }

  /**
   * Build a logically lower precision storage location for a bigger floating point register.
   *
   * This handles the situation where we need to find a logical address to hold the lower
   * precision floating-point value that is stored in a bigger register.
   * If the logicalsize (precision) requested matches the realsize of the register
   * just return the real address. Otherwise construct a join address to hold the logical value.
   *
   * @param realaddr is the address of the real floating-point register
   * @param realsize is the size of the real floating-point register
   * @param logicalsize is the size (lower precision) of the logical value
   */
  constructFloatExtensionAddress(
    realaddr: Address,
    realsize: int4,
    logicalsize: int4,
  ): Address {
    if (logicalsize === realsize) return realaddr;
    const pieces: VarnodeData[] = [];
    pieces.push(
      new VarnodeData(
        realaddr.getSpace() as any,
        realaddr.getOffset(),
        realsize,
      ),
    );

    const join = this.findAddJoin(pieces, logicalsize);
    const unified = join.getUnified();
    return new Address(unified.space as any, unified.offset);
  }

  /**
   * Build a logical whole from register pairs.
   *
   * This handles the common case of trying to find a join address given a high location and a low
   * location. This may not return an address in the join address space. It checks for the case
   * where the two pieces are contiguous locations in a mappable space, in which case it just returns
   * the containing address.
   *
   * @param translate is the Translate object used to find registers
   * @param hiaddr is the address of the most significant piece to be joined
   * @param hisz is the size of the most significant piece
   * @param loaddr is the address of the least significant piece
   * @param losz is the size of the least significant piece
   * @return an address representing the start of the joined range
   */
  constructJoinAddress(
    translate: Translate,
    hiaddr: Address,
    hisz: int4,
    loaddr: Address,
    losz: int4,
  ): Address {
    const hitp = hiaddr.getSpace()!.getType();
    const lotp = loaddr.getSpace()!.getType();
    let usejoinspace = true;
    if (
      (hitp !== spacetype.IPTR_SPACEBASE &&
        hitp !== spacetype.IPTR_PROCESSOR) ||
      (lotp !== spacetype.IPTR_SPACEBASE &&
        lotp !== spacetype.IPTR_PROCESSOR)
    ) {
      throw new LowlevelError(
        'Trying to join inappropriate locations',
      );
    }
    if (
      hitp === spacetype.IPTR_SPACEBASE ||
      lotp === spacetype.IPTR_SPACEBASE ||
      hiaddr.getSpace() === this.getDefaultCodeSpace() ||
      loaddr.getSpace() === this.getDefaultCodeSpace()
    ) {
      usejoinspace = false;
    }
    if (hiaddr.isContiguous(hisz, loaddr, losz)) {
      // If we are contiguous
      if (!usejoinspace) {
        // and in a mappable space, just return the earliest address
        if (hiaddr.isBigEndian()) return hiaddr;
        return loaddr;
      } else {
        // If we are in a non-mappable (register) space, check for parent register
        if (hiaddr.isBigEndian()) {
          if (
            translate
              .getRegisterName(
                hiaddr.getSpace()!,
                hiaddr.getOffset(),
                hisz + losz,
              )
              .length !== 0
          ) {
            return hiaddr;
          }
        } else {
          if (
            translate
              .getRegisterName(
                loaddr.getSpace()!,
                loaddr.getOffset(),
                hisz + losz,
              )
              .length !== 0
          ) {
            return loaddr;
          }
        }
      }
    }
    // Otherwise construct a formal JoinRecord
    const pieces: VarnodeData[] = [];
    pieces.push(
      new VarnodeData(
        hiaddr.getSpace() as any,
        hiaddr.getOffset(),
        hisz,
      ),
    );
    pieces.push(
      new VarnodeData(
        loaddr.getSpace() as any,
        loaddr.getOffset(),
        losz,
      ),
    );
    const join = this.findAddJoin(pieces, 0);
    const unified = join.getUnified();
    return new Address(unified.space as any, unified.offset);
  }

  /**
   * Make sure a possibly offset join address has a proper JoinRecord.
   *
   * If an Address in the join AddressSpace is shifted from its original offset, it may no
   * longer have a valid JoinRecord. The shift or size change may even make the address of
   * one of the pieces a more natural representation. Given a new Address and size, this method
   * decides if there is a matching JoinRecord. If not it either constructs a new JoinRecord or
   * computes the address within the containing piece. The given Address is changed if necessary
   * either to the offset corresponding to the new JoinRecord or to a normal non-join Address.
   *
   * @param addr is the given Address (modified in place)
   * @param size is the size of the range in bytes
   */
  renormalizeJoinAddress(addr: Address, size: int4): void {
    const joinRecord = this.findJoinInternal(addr.getOffset());
    if (joinRecord === null) {
      throw new LowlevelError(
        'Join address not covered by a JoinRecord',
      );
    }
    if (
      addr.getOffset() === joinRecord.unified.offset &&
      size === joinRecord.unified.size
    ) {
      return; // JoinRecord matches perfectly, no change necessary
    }
    const pos1Ref = { val: 0 };
    const addr1 = joinRecord.getEquivalentAddress(
      addr.getOffset(),
      pos1Ref,
    );
    const pos1 = pos1Ref.val;

    const pos2Ref = { val: 0 };
    const addr2 = joinRecord.getEquivalentAddress(
      addr.getOffset() + BigInt(size - 1),
      pos2Ref,
    );
    const pos2 = pos2Ref.val;

    if (addr2.isInvalid()) {
      throw new LowlevelError('Join address range not covered');
    }
    if (pos1 === pos2) {
      addr.base = addr1.base;
      addr.offset = addr1.offset;
      return;
    }
    const newPieces: VarnodeData[] = [];
    const sizeTrunc1 = Number(
      addr1.getOffset() - joinRecord.pieces[pos1].offset,
    );
    const sizeTrunc2 =
      joinRecord.pieces[pos2].size -
      Number(
        addr2.getOffset() - joinRecord.pieces[pos2].offset,
      ) -
      1;

    if (pos2 < pos1) {
      // Little endian
      newPieces.push(
        new VarnodeData(
          joinRecord.pieces[pos2].space,
          joinRecord.pieces[pos2].offset,
          joinRecord.pieces[pos2].size,
        ),
      );
      let p = pos2 + 1;
      while (p <= pos1) {
        newPieces.push(
          new VarnodeData(
            joinRecord.pieces[p].space,
            joinRecord.pieces[p].offset,
            joinRecord.pieces[p].size,
          ),
        );
        p += 1;
      }
      newPieces[newPieces.length - 1].offset = addr1.getOffset();
      newPieces[newPieces.length - 1].size -= sizeTrunc1;
      newPieces[0].size -= sizeTrunc2;
    } else {
      // Big endian
      newPieces.push(
        new VarnodeData(
          joinRecord.pieces[pos1].space,
          joinRecord.pieces[pos1].offset,
          joinRecord.pieces[pos1].size,
        ),
      );
      let p = pos1 + 1;
      while (p <= pos2) {
        newPieces.push(
          new VarnodeData(
            joinRecord.pieces[p].space,
            joinRecord.pieces[p].offset,
            joinRecord.pieces[p].size,
          ),
        );
        p += 1;
      }
      newPieces[0].offset = addr1.getOffset();
      newPieces[0].size -= sizeTrunc1;
      newPieces[newPieces.length - 1].size -= sizeTrunc2;
    }
    const newJoinRecord = this.findAddJoin(newPieces, 0);
    addr.base = newJoinRecord.unified.space as any;
    addr.offset = newJoinRecord.unified.offset;
  }

  /**
   * Parse a string with just an address space name and a hex offset.
   *
   * The string must contain a hexadecimal offset. The offset may be optionally prepended with "0x".
   * The string may optionally start with the name of the address space to associate with the offset,
   * followed by ':' to separate it from the offset. If the name is not present, the default data
   * space is assumed.
   *
   * @param val is the string to parse
   * @return the parsed address
   */
  parseAddressSimple(val: string): Address {
    const col = val.indexOf(':');
    let spc: AddrSpace;
    let hexPart: string;
    if (col === -1) {
      spc = this.getDefaultDataSpace()!;
      hexPart = val;
    } else {
      const spcName = val.substring(0, col);
      const found = this.getSpaceByName(spcName);
      if (found === null) {
        throw new LowlevelError('Unknown address space: ' + spcName);
      }
      spc = found;
      hexPart = val.substring(col + 1);
    }
    // Strip optional 0x prefix
    if (
      hexPart.length >= 2 &&
      hexPart[0] === '0' &&
      (hexPart[1] === 'x' || hexPart[1] === 'X')
    ) {
      hexPart = hexPart.substring(2);
    }
    const off = BigInt('0x' + hexPart);
    return new Address(
      spc,
      AddrSpace.addressToByte(off, spc.getWordSize()),
    );
  }
}

// =========================================================================
// Translate
// =========================================================================

// Forward-declare DocumentStorage type for the initialize method
type DocumentStorage = any;

/**
 * The interface to a translation engine for a processor.
 *
 * This interface performs translations of instruction data
 * for a particular processor. It has two main functions:
 *   - Disassemble single machine instructions
 *   - Translate single machine instructions into pcode.
 *
 * It is also the repository for information about the exact
 * configuration of the reverse engineering model associated
 * with the processor.
 */
export abstract class Translate extends AddrSpaceManager {
  /** Tagged addresses in the unique address space */
  static readonly RUNTIME_BOOLEAN_INVERT = 0;
  static readonly RUNTIME_RETURN_LOCATION = 0x80;
  static readonly RUNTIME_BITRANGE_EA = 0x100;
  static readonly INJECT = 0x200;
  static readonly ANALYSIS = 0x10000000;

  private target_isbigendian: boolean = false;
  private unique_base: uint4 = 0;
  protected alignment: int4 = 1;
  protected floatformats: FloatFormat[] = [];

  constructor() {
    super();
    this.target_isbigendian = false;
    this.unique_base = 0;
    this.alignment = 1;
  }

  /**
   * Set general endianness to big if val is true.
   *
   * Although endianness is usually specified on the space, most languages set an endianness
   * across the entire processor.
   */
  protected setBigEndian(val: boolean): void {
    this.target_isbigendian = val;
  }

  /**
   * Set the base offset for new temporary registers.
   *
   * The unique address space, for allocating temporary registers,
   * is used for both registers needed by the pcode translation
   * engine and, later, by the simplification engine. This routine
   * sets the boundary of the portion of the space allocated
   * for the pcode engine, and sets the base offset where registers
   * created by the simplification process can start being allocated.
   */
  protected setUniqueBase(val: uint4): void {
    if (val > this.unique_base) this.unique_base = val;
  }

  /**
   * Is the processor big endian?
   *
   * Processors can usually be described as using a big endian
   * encoding or a little endian encoding. This routine returns
   * true if the processor globally uses big endian encoding.
   */
  isBigEndian(): boolean {
    return this.target_isbigendian;
  }

  /**
   * Get format for a particular floating point encoding.
   *
   * The pcode model for floating point encoding assumes that a
   * consistent encoding is used for all values of a given size.
   *
   * @param size is the size of the floating-point value in bytes
   * @return a pointer to the floating-point format, or null
   */
  getFloatFormat(size: int4): FloatFormat | null {
    for (const ff of this.floatformats) {
      if (ff.getSize() === size) return ff;
    }
    return null;
  }

  /**
   * Get the instruction alignment for the processor.
   *
   * If machine instructions need to have a specific alignment
   * for this processor, this routine returns it. A return
   * value of 4 means that the address of all instructions
   * must be a multiple of 4. If there is no specific alignment
   * requirement, this routine returns 1.
   */
  getAlignment(): int4 {
    return this.alignment;
  }

  /**
   * Get the base offset for new temporary registers.
   *
   * Return the first offset within the unique space after the range statically reserved by Translate.
   * This is generally the starting offset where dynamic temporary registers can start to be allocated.
   */
  getUniqueBase(): uint4 {
    return this.unique_base;
  }

  /**
   * Get a tagged address within the unique space.
   *
   * Regions of the unique space are reserved for specific uses.
   * We select the start of a specific region based on the given tag.
   *
   * @param layout is the given tag
   * @return the absolute offset into the unique space
   */
  getUniqueStart(layout: int4): uint4 {
    return layout !== Translate.ANALYSIS
      ? layout + this.unique_base
      : layout;
  }

  /**
   * If no explicit float formats, set up default formats.
   *
   * If no floating-point format objects were registered by the initialize method, this
   * method will fill in some suitable default formats. These defaults are based on
   * the 4-byte and 8-byte encoding specified by the IEEE 754 standard.
   */
  setDefaultFloatFormats(): void {
    if (this.floatformats.length === 0) {
      this.floatformats.push(new FloatFormat(4));
      this.floatformats.push(new FloatFormat(8));
    }
  }

  // ---- Abstract methods ----

  /**
   * Initialize the translator given configuration documents.
   * A translator gets initialized once, possibly using documents to configure it.
   */
  abstract initialize(store: DocumentStorage): void;

  /**
   * Get a register as VarnodeData given its name.
   * Retrieve the location and size of a register given its name.
   */
  abstract getRegister(nm: string): VarnodeData;

  /**
   * Get the name of the smallest containing register given a location and size.
   * Generic references to locations in a register space are translated into the
   * register name. If a containing register isn't found, an empty string is returned.
   */
  abstract getRegisterName(
    base: AddrSpace,
    off: uintb,
    size: int4,
  ): string;

  /**
   * Get the name of a register with an exact location and size.
   * If a register exists with the given location and size, return the name of the register.
   * Otherwise return the empty string.
   */
  abstract getExactRegisterName(
    base: AddrSpace,
    off: uintb,
    size: int4,
  ): string;

  /**
   * Get a list of all register names and the corresponding location.
   * Most processors have a list of named registers and possibly other memory locations
   * that are specific to it. This function populates a map from the location information
   * to the name, for every named location known by the translator.
   */
  abstract getAllRegisters(
    reglist: Map<string, VarnodeData>,
  ): void;

  /**
   * Get a list of all user-defined pcode ops.
   * The pcode model allows processors to define new pcode
   * instructions that are specific to that processor.
   */
  abstract getUserOpNames(res: string[]): void;

  /**
   * Get the length of a machine instruction.
   * This method decodes an instruction at a specific address
   * just enough to find the number of bytes it uses.
   */
  abstract instructionLength(baseaddr: Address): int4;

  /**
   * Transform a single machine instruction into pcode.
   * This is the main interface to the pcode translation engine.
   * The dump method in the emit object is invoked exactly once for each pcode operation.
   */
  abstract oneInstruction(emit: PcodeEmit, baseaddr: Address): int4;

  /**
   * Disassemble a single machine instruction.
   * This is the main interface to the disassembler for the processor.
   */
  abstract printAssembly(emit: AssemblyEmit, baseaddr: Address): int4;
}

// Re-export items that other modules will need
export { SPACE_END_SENTINEL };
