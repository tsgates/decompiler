/**
 * @file slghpattern.ts
 * @description SLEIGH matching patterns used during instruction decoding.
 *
 * Translated from Ghidra's slghpattern.hh / slghpattern.cc.
 *
 * This module defines PatternBlock (a mask/value pair viewed as two bitstreams)
 * and the Pattern class hierarchy: DisjointPattern, InstructionPattern,
 * ContextPattern, CombinePattern, and OrPattern.
 */

import type { int4, uint4, uintm } from '../core/types.js';
import {
  Encoder,
  Decoder,
  AttributeId,
  ElementId,
} from '../core/marshal.js';

// ---------------------------------------------------------------------------
// Forward declarations for types from not-yet-written SLEIGH modules
// ---------------------------------------------------------------------------

/** Forward-declared ParserWalker (full definition in context/sleigh module) */
type ParserWalker = any;

// ---------------------------------------------------------------------------
// SLA-format scoped AttributeId / ElementId constants
// ---------------------------------------------------------------------------

const SLA_FORMAT_SCOPE = 1;

const SLA_ATTRIB_VAL     = new AttributeId('val', 2, SLA_FORMAT_SCOPE);
const SLA_ATTRIB_OFF     = new AttributeId('off', 6, SLA_FORMAT_SCOPE);
const SLA_ATTRIB_MASK    = new AttributeId('mask', 8, SLA_FORMAT_SCOPE);
const SLA_ATTRIB_NONZERO = new AttributeId('nonzero', 10, SLA_FORMAT_SCOPE);

const SLA_ELEM_MASK_WORD    = new ElementId('mask_word', 6, SLA_FORMAT_SCOPE);
const SLA_ELEM_PAT_BLOCK    = new ElementId('pat_block', 7, SLA_FORMAT_SCOPE);
const SLA_ELEM_CONTEXT_PAT  = new ElementId('context_pat', 10, SLA_FORMAT_SCOPE);
const SLA_ELEM_INSTRUCT_PAT = new ElementId('instruct_pat', 18, SLA_FORMAT_SCOPE);
const SLA_ELEM_COMBINE_PAT  = new ElementId('combine_pat', 19, SLA_FORMAT_SCOPE);
const SLA_ELEM_OR_PAT       = new ElementId('or_pat', 78, SLA_FORMAT_SCOPE);

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** sizeof(uintm) in bytes -- uintm is a 32-bit unsigned integer */
const SIZEOF_UINTM = 4;

/** Number of bits in a uintm word */
const UINTM_BITS = SIZEOF_UINTM * 8; // 32

// ---------------------------------------------------------------------------
// PatternBlock
// ---------------------------------------------------------------------------

/**
 * A mask/value pair viewed as two bitstreams.
 *
 * The mask and value are stored as arrays of 32-bit unsigned integers (uintm).
 * An `offset` records the byte position of the first non-zero mask byte.
 *
 * Special sentinel values for `nonzerosize`:
 *  - 0  means "always true" (mask is all zeros)
 *  - -1 means "always false" (impossible pattern)
 */
export class PatternBlock {
  private offset: int4 = 0;
  private nonzerosize: int4 = 0;
  private maskvec: uintm[] = [];
  private valvec: uintm[] = [];

  // -- Constructors (use static factory methods) --

  private constructor() {}

  /**
   * Create a PatternBlock from offset, mask, and value (single uintm).
   */
  static fromMaskValue(off: int4, msk: uintm, val: uintm): PatternBlock {
    const pb = new PatternBlock();
    pb.offset = off;
    pb.maskvec.push(msk);
    pb.valvec.push(val);
    pb.nonzerosize = SIZEOF_UINTM; // assume all non-zero before normalization
    pb.normalize();
    return pb;
  }

  /**
   * Create an always-true or always-false PatternBlock.
   */
  static fromBool(tf: boolean): PatternBlock {
    const pb = new PatternBlock();
    pb.offset = 0;
    pb.nonzerosize = tf ? 0 : -1;
    return pb;
  }

  /**
   * Create a PatternBlock by ANDing two others together.
   */
  static fromAnd(a: PatternBlock, b: PatternBlock): PatternBlock {
    const res = a.intersect(b);
    return res;
  }

  /**
   * Create a PatternBlock by ANDing a list of blocks together.
   */
  static fromAndList(list: PatternBlock[]): PatternBlock {
    if (list.length === 0) {
      return PatternBlock.fromBool(true);
    }
    let res = list[0];
    for (let i = 1; i < list.length; ++i) {
      const next = res.intersect(list[i]);
      res = next;
    }
    return res;
  }

  // -- normalize --

  private normalize(): void {
    if (this.nonzerosize <= 0) {
      // always-true or always-false -- clear mask and value
      this.offset = 0;
      this.maskvec.length = 0;
      this.valvec.length = 0;
      return;
    }

    // Cut zeros from the beginning of the mask
    let startCut = 0;
    while (startCut < this.maskvec.length && this.maskvec[startCut] === 0) {
      startCut++;
      this.offset += SIZEOF_UINTM;
    }
    if (startCut > 0) {
      this.maskvec.splice(0, startCut);
      this.valvec.splice(0, startCut);
    }

    if (this.maskvec.length > 0) {
      // Cut off unaligned zeros from the beginning of mask
      let suboff = 0;
      let tmp = this.maskvec[0];
      while (tmp !== 0) {
        suboff += 1;
        tmp = (tmp >>> 8);
      }
      suboff = SIZEOF_UINTM - suboff;
      if (suboff !== 0) {
        this.offset += suboff;
        // Slide up maskvec by suboff bytes
        for (let i = 0; i < this.maskvec.length - 1; ++i) {
          tmp = (this.maskvec[i] << (suboff * 8)) >>> 0;
          tmp = (tmp | (this.maskvec[i + 1] >>> ((SIZEOF_UINTM - suboff) * 8))) >>> 0;
          this.maskvec[i] = tmp;
        }
        this.maskvec[this.maskvec.length - 1] = (this.maskvec[this.maskvec.length - 1] << (suboff * 8)) >>> 0;
        // Slide up valvec by suboff bytes
        for (let i = 0; i < this.valvec.length - 1; ++i) {
          tmp = (this.valvec[i] << (suboff * 8)) >>> 0;
          tmp = (tmp | (this.valvec[i + 1] >>> ((SIZEOF_UINTM - suboff) * 8))) >>> 0;
          this.valvec[i] = tmp;
        }
        this.valvec[this.valvec.length - 1] = (this.valvec[this.valvec.length - 1] << (suboff * 8)) >>> 0;
      }

      // Cut zeros from end of mask
      let endIdx = this.maskvec.length;
      while (endIdx > 0 && this.maskvec[endIdx - 1] === 0) {
        endIdx--;
      }
      if (endIdx < this.maskvec.length) {
        this.maskvec.length = endIdx;
        this.valvec.length = endIdx;
      }
    }

    if (this.maskvec.length === 0) {
      this.offset = 0;
      this.nonzerosize = 0; // always true
      return;
    }

    this.nonzerosize = this.maskvec.length * SIZEOF_UINTM;
    let tmp = this.maskvec[this.maskvec.length - 1]; // must be nonzero
    while ((tmp & 0xff) === 0) {
      this.nonzerosize -= 1;
      tmp = tmp >>> 8;
    }
  }

  // -- public API --

  /**
   * Return the common sub-pattern: a 1-bit in the result mask only where
   * both inputs have a 1-bit and the values agree.
   */
  commonSubPattern(b: PatternBlock): PatternBlock {
    const res = PatternBlock.fromBool(true);
    const maxlength = Math.max(this.getLength(), b.getLength());

    res.offset = 0;
    let off = 0;
    while (off < maxlength) {
      const mask1 = this.getMask(off * 8, UINTM_BITS);
      const val1 = this.getValue(off * 8, UINTM_BITS);
      const mask2 = b.getMask(off * 8, UINTM_BITS);
      const val2 = b.getValue(off * 8, UINTM_BITS);
      const resmask = ((mask1 & mask2) & ~(val1 ^ val2)) >>> 0;
      const resval = ((val1 & val2) & resmask) >>> 0;
      res.maskvec.push(resmask);
      res.valvec.push(resval);
      off += SIZEOF_UINTM;
    }
    res.nonzerosize = maxlength;
    res.normalize();
    return res;
  }

  /**
   * Construct the intersecting pattern.
   */
  intersect(b: PatternBlock): PatternBlock {
    if (this.alwaysFalse() || b.alwaysFalse()) {
      return PatternBlock.fromBool(false);
    }
    const res = PatternBlock.fromBool(true);
    const maxlength = Math.max(this.getLength(), b.getLength());

    res.offset = 0;
    let off = 0;
    while (off < maxlength) {
      const mask1 = this.getMask(off * 8, UINTM_BITS);
      const val1 = this.getValue(off * 8, UINTM_BITS);
      const mask2 = b.getMask(off * 8, UINTM_BITS);
      const val2 = b.getValue(off * 8, UINTM_BITS);
      const commonmask = (mask1 & mask2) >>> 0;
      if (((commonmask & val1) >>> 0) !== ((commonmask & val2) >>> 0)) {
        res.nonzerosize = -1; // impossible pattern
        res.normalize();
        return res;
      }
      const resmask = (mask1 | mask2) >>> 0;
      const resval = ((mask1 & val1) | (mask2 & val2)) >>> 0;
      res.maskvec.push(resmask);
      res.valvec.push(resval);
      off += SIZEOF_UINTM;
    }
    res.nonzerosize = maxlength;
    res.normalize();
    return res;
  }

  /**
   * Does every masked bit in this pattern match the corresponding masked bit in op2?
   */
  specializes(op2: PatternBlock): boolean {
    const length = 8 * op2.getLength();
    let sbit = 0;
    while (sbit < length) {
      let tmplength = length - sbit;
      if (tmplength > UINTM_BITS) tmplength = UINTM_BITS;
      const mask1 = this.getMask(sbit, tmplength);
      const value1 = this.getValue(sbit, tmplength);
      const mask2 = op2.getMask(sbit, tmplength);
      const value2 = op2.getValue(sbit, tmplength);
      if (((mask1 & mask2) >>> 0) !== mask2) return false;
      if (((value1 & mask2) >>> 0) !== ((value2 & mask2) >>> 0)) return false;
      sbit += tmplength;
    }
    return true;
  }

  /**
   * Do the mask and value match exactly?
   */
  identical(op2: PatternBlock): boolean {
    let length = 8 * op2.getLength();
    const tmplength2 = 8 * this.getLength();
    if (tmplength2 > length) length = tmplength2;
    let sbit = 0;
    while (sbit < length) {
      let tmplength = length - sbit;
      if (tmplength > UINTM_BITS) tmplength = UINTM_BITS;
      const mask1 = this.getMask(sbit, tmplength);
      const value1 = this.getValue(sbit, tmplength);
      const mask2 = op2.getMask(sbit, tmplength);
      const value2 = op2.getValue(sbit, tmplength);
      if (mask1 !== mask2) return false;
      if (((mask1 & value1) >>> 0) !== ((mask2 & value2) >>> 0)) return false;
      sbit += tmplength;
    }
    return true;
  }

  /**
   * Clone this PatternBlock.
   */
  clone(): PatternBlock {
    const res = PatternBlock.fromBool(true);
    res.offset = this.offset;
    res.nonzerosize = this.nonzerosize;
    res.maskvec = this.maskvec.slice();
    res.valvec = this.valvec.slice();
    return res;
  }

  /**
   * Shift the pattern by sa bytes.
   */
  shift(sa: int4): void {
    this.offset += sa;
    this.normalize();
  }

  /**
   * Get the total length in bytes (offset + nonzerosize).
   */
  getLength(): int4 {
    return this.offset + this.nonzerosize;
  }

  /**
   * Extract mask bits starting at startbit for size bits.
   */
  getMask(startbit: int4, size: int4): uintm {
    startbit -= 8 * this.offset;
    const wordnum1 = Math.floor(startbit / UINTM_BITS);
    const shift = ((startbit % UINTM_BITS) + UINTM_BITS) % UINTM_BITS;
    const wordnum2 = Math.floor((startbit + size - 1) / UINTM_BITS);
    let res: uintm;

    if (wordnum1 < 0 || wordnum1 >= this.maskvec.length) {
      res = 0;
    } else {
      res = this.maskvec[wordnum1];
    }

    res = (res << shift) >>> 0;
    if (wordnum1 !== wordnum2) {
      let tmp: uintm;
      if (wordnum2 < 0 || wordnum2 >= this.maskvec.length) {
        tmp = 0;
      } else {
        tmp = this.maskvec[wordnum2];
      }
      res = (res | (tmp >>> (UINTM_BITS - shift))) >>> 0;
    }
    res = res >>> (UINTM_BITS - size);
    return res;
  }

  /**
   * Extract value bits starting at startbit for size bits.
   */
  getValue(startbit: int4, size: int4): uintm {
    startbit -= 8 * this.offset;
    const wordnum1 = Math.floor(startbit / UINTM_BITS);
    const shift = ((startbit % UINTM_BITS) + UINTM_BITS) % UINTM_BITS;
    const wordnum2 = Math.floor((startbit + size - 1) / UINTM_BITS);
    let res: uintm;

    if (wordnum1 < 0 || wordnum1 >= this.valvec.length) {
      res = 0;
    } else {
      res = this.valvec[wordnum1];
    }
    res = (res << shift) >>> 0;
    if (wordnum1 !== wordnum2) {
      let tmp: uintm;
      if (wordnum2 < 0 || wordnum2 >= this.valvec.length) {
        tmp = 0;
      } else {
        tmp = this.valvec[wordnum2];
      }
      res = (res | (tmp >>> (UINTM_BITS - shift))) >>> 0;
    }
    res = res >>> (UINTM_BITS - size);
    return res;
  }

  /** Returns true if the pattern always matches (mask is all zeros). */
  alwaysTrue(): boolean {
    return this.nonzerosize === 0;
  }

  /** Returns true if the pattern can never match (impossible). */
  alwaysFalse(): boolean {
    return this.nonzerosize === -1;
  }

  /**
   * Check if this pattern matches the instruction bytes in the walker.
   */
  isInstructionMatch(walker: ParserWalker): boolean {
    if (this.nonzerosize <= 0) return this.nonzerosize === 0;
    let off = this.offset;
    for (let i = 0; i < this.maskvec.length; ++i) {
      const data: uintm = (walker as any).getInstructionBytes(off, SIZEOF_UINTM);
      if (((this.maskvec[i] & data) >>> 0) !== this.valvec[i]) return false;
      off += SIZEOF_UINTM;
    }
    return true;
  }

  /**
   * Check if this pattern matches the context bytes in the walker.
   */
  isContextMatch(walker: ParserWalker): boolean {
    if (this.nonzerosize <= 0) return this.nonzerosize === 0;
    let off = this.offset;
    for (let i = 0; i < this.maskvec.length; ++i) {
      const data: uintm = (walker as any).getContextBytes(off, SIZEOF_UINTM);
      if (((this.maskvec[i] & data) >>> 0) !== this.valvec[i]) return false;
      off += SIZEOF_UINTM;
    }
    return true;
  }

  /**
   * Encode this PatternBlock to the encoder.
   */
  encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_PAT_BLOCK);
    encoder.writeSignedInteger(SLA_ATTRIB_OFF, this.offset);
    encoder.writeSignedInteger(SLA_ATTRIB_NONZERO, this.nonzerosize);
    for (let i = 0; i < this.maskvec.length; ++i) {
      encoder.openElement(SLA_ELEM_MASK_WORD);
      encoder.writeUnsignedInteger(SLA_ATTRIB_MASK, BigInt(this.maskvec[i]) & 0xFFFFFFFFn);
      encoder.writeUnsignedInteger(SLA_ATTRIB_VAL, BigInt(this.valvec[i]) & 0xFFFFFFFFn);
      encoder.closeElement(SLA_ELEM_MASK_WORD);
    }
    encoder.closeElement(SLA_ELEM_PAT_BLOCK);
  }

  /**
   * Decode this PatternBlock from the decoder.
   */
  decode(decoder: Decoder): void {
    const el = decoder.openElementId(SLA_ELEM_PAT_BLOCK);
    this.offset = decoder.readSignedIntegerById(SLA_ATTRIB_OFF);
    this.nonzerosize = decoder.readSignedIntegerById(SLA_ATTRIB_NONZERO);
    while (decoder.peekElement() !== 0) {
      const subel = decoder.openElementId(SLA_ELEM_MASK_WORD);
      const mask = Number(decoder.readUnsignedIntegerById(SLA_ATTRIB_MASK)) >>> 0;
      const val = Number(decoder.readUnsignedIntegerById(SLA_ATTRIB_VAL)) >>> 0;
      this.maskvec.push(mask);
      this.valvec.push(val);
      decoder.closeElement(subel);
    }
    this.normalize();
    decoder.closeElement(el);
  }
}

// ---------------------------------------------------------------------------
// resolveIntersectBlock (module-level helper)
// ---------------------------------------------------------------------------

function resolveIntersectBlock(
  bl1: PatternBlock | null,
  bl2: PatternBlock | null,
  thisblock: PatternBlock | null,
): boolean {
  let inter: PatternBlock | null;
  let allocated = false;

  if (bl1 === null) {
    inter = bl2;
  } else if (bl2 === null) {
    inter = bl1;
  } else {
    allocated = true;
    inter = bl1.intersect(bl2);
  }
  if (inter === null) {
    return thisblock === null;
  } else if (thisblock === null) {
    return false;
  } else {
    return thisblock.identical(inter);
  }
}

// ---------------------------------------------------------------------------
// Pattern (abstract base)
// ---------------------------------------------------------------------------

/**
 * Abstract base class for all SLEIGH patterns.
 */
export abstract class Pattern {
  abstract simplifyClone(): Pattern;
  abstract shiftInstruction(sa: int4): void;
  abstract doOr(b: Pattern, sa: int4): Pattern;
  abstract doAnd(b: Pattern, sa: int4): Pattern;
  abstract commonSubPattern(b: Pattern, sa: int4): Pattern;
  abstract isMatch(walker: ParserWalker): boolean;
  abstract numDisjoint(): int4;
  abstract getDisjoint(i: int4): DisjointPattern | null;
  abstract alwaysTrue(): boolean;
  abstract alwaysFalse(): boolean;
  abstract alwaysInstructionTrue(): boolean;
  abstract encode(encoder: Encoder): void;
  abstract decode(decoder: Decoder): void;
}

// ---------------------------------------------------------------------------
// DisjointPattern (abstract, no ORs)
// ---------------------------------------------------------------------------

/**
 * A pattern with no ORs in it.
 */
export abstract class DisjointPattern extends Pattern {
  protected abstract getBlockByContext(context: boolean): PatternBlock | null;

  numDisjoint(): int4 {
    return 0;
  }

  getDisjoint(_i: int4): DisjointPattern | null {
    return null;
  }

  getMaskBits(startbit: int4, size: int4, context: boolean): uintm {
    const block = this.getBlockByContext(context);
    if (block !== null) return block.getMask(startbit, size);
    return 0;
  }

  getValueBits(startbit: int4, size: int4, context: boolean): uintm {
    const block = this.getBlockByContext(context);
    if (block !== null) return block.getValue(startbit, size);
    return 0;
  }

  getLength(context: boolean): int4 {
    const block = this.getBlockByContext(context);
    if (block !== null) return block.getLength();
    return 0;
  }

  specializes(op2: DisjointPattern): boolean {
    let a: PatternBlock | null;
    let b: PatternBlock | null;

    a = this.getBlockByContext(false);
    b = op2.getBlockByContext(false);
    if (b !== null && !b.alwaysTrue()) {
      if (a === null) return false;
      if (!a.specializes(b)) return false;
    }
    a = this.getBlockByContext(true);
    b = op2.getBlockByContext(true);
    if (b !== null && !b.alwaysTrue()) {
      if (a === null) return false;
      if (!a.specializes(b)) return false;
    }
    return true;
  }

  identical(op2: DisjointPattern): boolean {
    let a: PatternBlock | null;
    let b: PatternBlock | null;

    a = this.getBlockByContext(false);
    b = op2.getBlockByContext(false);
    if (b !== null) {
      if (a === null) {
        if (!b.alwaysTrue()) return false;
      } else if (!a.identical(b)) {
        return false;
      }
    } else {
      if (a !== null && !a.alwaysTrue()) return false;
    }

    a = this.getBlockByContext(true);
    b = op2.getBlockByContext(true);
    if (b !== null) {
      if (a === null) {
        if (!b.alwaysTrue()) return false;
      } else if (!a.identical(b)) {
        return false;
      }
    } else {
      if (a !== null && !a.alwaysTrue()) return false;
    }
    return true;
  }

  /**
   * Is this pattern equal to the intersection of op1 and op2?
   */
  resolvesIntersect(op1: DisjointPattern, op2: DisjointPattern): boolean {
    if (!resolveIntersectBlock(
      op1.getBlockByContext(false),
      op2.getBlockByContext(false),
      this.getBlockByContext(false),
    )) {
      return false;
    }
    return resolveIntersectBlock(
      op1.getBlockByContext(true),
      op2.getBlockByContext(true),
      this.getBlockByContext(true),
    );
  }

  /**
   * Factory: decode a DisjointPattern from a decoder.
   */
  static decodeDisjoint(decoder: Decoder): DisjointPattern {
    let res: DisjointPattern;
    const el = decoder.peekElement();
    if (el === SLA_ELEM_INSTRUCT_PAT.id) {
      res = new InstructionPattern();
    } else if (el === SLA_ELEM_CONTEXT_PAT.id) {
      res = new ContextPattern();
    } else {
      res = new CombinePattern();
    }
    res.decode(decoder);
    return res;
  }
}

// ---------------------------------------------------------------------------
// InstructionPattern
// ---------------------------------------------------------------------------

/**
 * Matches the instruction bitstream.
 */
export class InstructionPattern extends DisjointPattern {
  private maskvalue: PatternBlock | null;

  constructor();
  constructor(mv: PatternBlock);
  constructor(tf: boolean);
  constructor(arg?: PatternBlock | boolean) {
    super();
    if (arg === undefined) {
      this.maskvalue = null; // for use with decode
    } else if (typeof arg === 'boolean') {
      this.maskvalue = PatternBlock.fromBool(arg);
    } else {
      this.maskvalue = arg;
    }
  }

  protected getBlockByContext(context: boolean): PatternBlock | null {
    return context ? null : this.maskvalue;
  }

  /** Get the underlying PatternBlock (non-const version). */
  getBlock(): PatternBlock | null {
    return this.maskvalue;
  }

  simplifyClone(): Pattern {
    return new InstructionPattern(this.maskvalue!.clone());
  }

  shiftInstruction(sa: int4): void {
    this.maskvalue!.shift(sa);
  }

  doOr(b: Pattern, sa: int4): Pattern {
    if (b.numDisjoint() > 0) return b.doOr(this, -sa);

    if (b instanceof CombinePattern) return b.doOr(this, -sa);

    let res1: DisjointPattern;
    let res2: DisjointPattern;
    res1 = this.simplifyClone() as DisjointPattern;
    res2 = b.simplifyClone() as DisjointPattern;
    if (sa < 0) {
      res1.shiftInstruction(-sa);
    } else {
      res2.shiftInstruction(sa);
    }
    return new OrPattern(res1, res2);
  }

  doAnd(b: Pattern, sa: int4): Pattern {
    if (b.numDisjoint() > 0) return b.doAnd(this, -sa);

    if (b instanceof CombinePattern) return b.doAnd(this, -sa);

    if (b instanceof ContextPattern) {
      const newpat = this.simplifyClone() as InstructionPattern;
      if (sa < 0) newpat.shiftInstruction(-sa);
      return new CombinePattern(b.simplifyClone() as ContextPattern, newpat);
    }

    const b4 = b as InstructionPattern;
    let respattern: PatternBlock;
    if (sa < 0) {
      const a = this.maskvalue!.clone();
      a.shift(-sa);
      respattern = a.intersect(b4.maskvalue!);
    } else {
      const c = b4.maskvalue!.clone();
      c.shift(sa);
      respattern = this.maskvalue!.intersect(c);
    }
    return new InstructionPattern(respattern);
  }

  commonSubPattern(b: Pattern, sa: int4): Pattern {
    if (b.numDisjoint() > 0) return b.commonSubPattern(this, -sa);

    if (b instanceof CombinePattern) return b.commonSubPattern(this, -sa);

    if (b instanceof ContextPattern) {
      return new InstructionPattern(true);
    }

    const b4 = b as InstructionPattern;
    let respattern: PatternBlock;
    if (sa < 0) {
      const a = this.maskvalue!.clone();
      a.shift(-sa);
      respattern = a.commonSubPattern(b4.maskvalue!);
    } else {
      const c = b4.maskvalue!.clone();
      c.shift(sa);
      respattern = this.maskvalue!.commonSubPattern(c);
    }
    return new InstructionPattern(respattern);
  }

  isMatch(walker: ParserWalker): boolean {
    return this.maskvalue!.isInstructionMatch(walker);
  }

  alwaysTrue(): boolean {
    return this.maskvalue!.alwaysTrue();
  }

  alwaysFalse(): boolean {
    return this.maskvalue!.alwaysFalse();
  }

  alwaysInstructionTrue(): boolean {
    return this.maskvalue!.alwaysTrue();
  }

  encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_INSTRUCT_PAT);
    this.maskvalue!.encode(encoder);
    encoder.closeElement(SLA_ELEM_INSTRUCT_PAT);
  }

  decode(decoder: Decoder): void {
    const el = decoder.openElementId(SLA_ELEM_INSTRUCT_PAT);
    this.maskvalue = PatternBlock.fromBool(true);
    this.maskvalue.decode(decoder);
    decoder.closeElement(el);
  }
}

// ---------------------------------------------------------------------------
// ContextPattern
// ---------------------------------------------------------------------------

/**
 * Matches the context bitstream.
 */
export class ContextPattern extends DisjointPattern {
  private maskvalue: PatternBlock | null;

  constructor();
  constructor(mv: PatternBlock);
  constructor(arg?: PatternBlock) {
    super();
    if (arg === undefined) {
      this.maskvalue = null;
    } else {
      this.maskvalue = arg;
    }
  }

  protected getBlockByContext(context: boolean): PatternBlock | null {
    return context ? this.maskvalue : null;
  }

  /** Get the underlying PatternBlock (non-const version). */
  getBlock(): PatternBlock | null {
    return this.maskvalue;
  }

  simplifyClone(): Pattern {
    return new ContextPattern(this.maskvalue!.clone());
  }

  shiftInstruction(_sa: int4): void {
    // do nothing -- context is not shifted
  }

  doOr(b: Pattern, sa: int4): Pattern {
    if (!(b instanceof ContextPattern)) return b.doOr(this, -sa);

    return new OrPattern(
      this.simplifyClone() as DisjointPattern,
      b.simplifyClone() as DisjointPattern,
    );
  }

  doAnd(b: Pattern, sa: int4): Pattern {
    if (!(b instanceof ContextPattern)) return b.doAnd(this, -sa);

    const b2 = b as ContextPattern;
    const resblock = this.maskvalue!.intersect(b2.maskvalue!);
    return new ContextPattern(resblock);
  }

  commonSubPattern(b: Pattern, sa: int4): Pattern {
    if (!(b instanceof ContextPattern)) return b.commonSubPattern(this, -sa);

    const b2 = b as ContextPattern;
    const resblock = this.maskvalue!.commonSubPattern(b2.maskvalue!);
    return new ContextPattern(resblock);
  }

  isMatch(walker: ParserWalker): boolean {
    return this.maskvalue!.isContextMatch(walker);
  }

  alwaysTrue(): boolean {
    return this.maskvalue!.alwaysTrue();
  }

  alwaysFalse(): boolean {
    return this.maskvalue!.alwaysFalse();
  }

  alwaysInstructionTrue(): boolean {
    return true;
  }

  encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_CONTEXT_PAT);
    this.maskvalue!.encode(encoder);
    encoder.closeElement(SLA_ELEM_CONTEXT_PAT);
  }

  decode(decoder: Decoder): void {
    const el = decoder.openElementId(SLA_ELEM_CONTEXT_PAT);
    this.maskvalue = PatternBlock.fromBool(true);
    this.maskvalue.decode(decoder);
    decoder.closeElement(el);
  }
}

// ---------------------------------------------------------------------------
// CombinePattern
// ---------------------------------------------------------------------------

/**
 * A pattern with a context piece and an instruction piece.
 */
export class CombinePattern extends DisjointPattern {
  private context: ContextPattern | null;
  private instr: InstructionPattern | null;

  constructor();
  constructor(con: ContextPattern, ins: InstructionPattern);
  constructor(con?: ContextPattern, ins?: InstructionPattern) {
    super();
    this.context = con ?? null;
    this.instr = ins ?? null;
  }

  protected getBlockByContext(cont: boolean): PatternBlock | null {
    return cont ? this.context!.getBlock() : this.instr!.getBlock();
  }

  simplifyClone(): Pattern {
    if (this.context!.alwaysTrue()) return this.instr!.simplifyClone();
    if (this.instr!.alwaysTrue()) return this.context!.simplifyClone();
    if (this.context!.alwaysFalse() || this.instr!.alwaysFalse()) {
      return new InstructionPattern(false);
    }
    return new CombinePattern(
      this.context!.simplifyClone() as ContextPattern,
      this.instr!.simplifyClone() as InstructionPattern,
    );
  }

  shiftInstruction(sa: int4): void {
    this.instr!.shiftInstruction(sa);
  }

  isMatch(walker: ParserWalker): boolean {
    if (!this.instr!.isMatch(walker)) return false;
    if (!this.context!.isMatch(walker)) return false;
    return true;
  }

  alwaysTrue(): boolean {
    return this.context!.alwaysTrue() && this.instr!.alwaysTrue();
  }

  alwaysFalse(): boolean {
    return this.context!.alwaysFalse() || this.instr!.alwaysFalse();
  }

  alwaysInstructionTrue(): boolean {
    return this.instr!.alwaysInstructionTrue();
  }

  doAnd(b: Pattern, sa: int4): Pattern {
    if (b.numDisjoint() !== 0) return b.doAnd(this, -sa);

    if (b instanceof CombinePattern) {
      const b2 = b as CombinePattern;
      const c = this.context!.doAnd(b2.context!, 0) as ContextPattern;
      const i = this.instr!.doAnd(b2.instr!, sa) as InstructionPattern;
      return new CombinePattern(c, i);
    }

    if (b instanceof InstructionPattern) {
      const i = this.instr!.doAnd(b, sa) as InstructionPattern;
      return new CombinePattern(
        this.context!.simplifyClone() as ContextPattern,
        i,
      );
    }

    // Must be a ContextPattern
    const c = this.context!.doAnd(b, 0) as ContextPattern;
    const newpat = this.instr!.simplifyClone() as InstructionPattern;
    if (sa < 0) newpat.shiftInstruction(-sa);
    return new CombinePattern(c, newpat);
  }

  commonSubPattern(b: Pattern, sa: int4): Pattern {
    if (b.numDisjoint() !== 0) return b.commonSubPattern(this, -sa);

    if (b instanceof CombinePattern) {
      const b2 = b as CombinePattern;
      const c = this.context!.commonSubPattern(b2.context!, 0) as ContextPattern;
      const i = this.instr!.commonSubPattern(b2.instr!, sa) as InstructionPattern;
      return new CombinePattern(c, i);
    }

    if (b instanceof InstructionPattern) {
      return this.instr!.commonSubPattern(b, sa);
    }

    // Must be a ContextPattern
    return this.context!.commonSubPattern(b, 0);
  }

  doOr(b: Pattern, sa: int4): Pattern {
    if (b.numDisjoint() !== 0) return b.doOr(this, -sa);

    const res1 = this.simplifyClone() as DisjointPattern;
    const res2 = b.simplifyClone() as DisjointPattern;
    if (sa < 0) {
      res1.shiftInstruction(-sa);
    } else {
      res2.shiftInstruction(sa);
    }
    return new OrPattern(res1, res2);
  }

  encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_COMBINE_PAT);
    this.context!.encode(encoder);
    this.instr!.encode(encoder);
    encoder.closeElement(SLA_ELEM_COMBINE_PAT);
  }

  decode(decoder: Decoder): void {
    const el = decoder.openElementId(SLA_ELEM_COMBINE_PAT);
    this.context = new ContextPattern();
    this.context.decode(decoder);
    this.instr = new InstructionPattern();
    this.instr.decode(decoder);
    decoder.closeElement(el);
  }
}

// ---------------------------------------------------------------------------
// OrPattern
// ---------------------------------------------------------------------------

/**
 * A pattern that is the OR of multiple DisjointPatterns.
 */
export class OrPattern extends Pattern {
  private orlist: DisjointPattern[] = [];

  constructor();
  constructor(a: DisjointPattern, b: DisjointPattern);
  constructor(list: DisjointPattern[]);
  constructor(aOrList?: DisjointPattern | DisjointPattern[], b?: DisjointPattern) {
    super();
    if (aOrList === undefined) {
      // default -- for use with decode
    } else if (Array.isArray(aOrList)) {
      for (const item of aOrList) {
        this.orlist.push(item);
      }
    } else {
      this.orlist.push(aOrList);
      this.orlist.push(b!);
    }
  }

  simplifyClone(): Pattern {
    // Look for alwaysTrue -- if any branch is always true, result is always true
    for (const pat of this.orlist) {
      if (pat.alwaysTrue()) return new InstructionPattern(true);
    }

    // Look for alwaysFalse -- eliminate false branches
    const newlist: DisjointPattern[] = [];
    for (const pat of this.orlist) {
      if (!pat.alwaysFalse()) {
        newlist.push(pat.simplifyClone() as DisjointPattern);
      }
    }

    if (newlist.length === 0) return new InstructionPattern(false);
    if (newlist.length === 1) return newlist[0];
    return new OrPattern(newlist);
  }

  shiftInstruction(sa: int4): void {
    for (const pat of this.orlist) {
      pat.shiftInstruction(sa);
    }
  }

  isMatch(walker: ParserWalker): boolean {
    for (let i = 0; i < this.orlist.length; ++i) {
      if (this.orlist[i].isMatch(walker)) return true;
    }
    return false;
  }

  numDisjoint(): int4 {
    return this.orlist.length;
  }

  getDisjoint(i: int4): DisjointPattern {
    return this.orlist[i];
  }

  alwaysTrue(): boolean {
    for (const pat of this.orlist) {
      if (pat.alwaysTrue()) return true;
    }
    return false;
  }

  alwaysFalse(): boolean {
    for (const pat of this.orlist) {
      if (!pat.alwaysFalse()) return false;
    }
    return true;
  }

  alwaysInstructionTrue(): boolean {
    for (const pat of this.orlist) {
      if (!pat.alwaysInstructionTrue()) return false;
    }
    return true;
  }

  doAnd(b: Pattern, sa: int4): Pattern {
    const b2 = (b instanceof OrPattern) ? b as OrPattern : null;
    const newlist: DisjointPattern[] = [];

    if (b2 === null) {
      for (const pat of this.orlist) {
        const tmp = pat.doAnd(b, sa) as DisjointPattern;
        newlist.push(tmp);
      }
    } else {
      for (const pat of this.orlist) {
        for (const pat2 of b2.orlist) {
          const tmp = pat.doAnd(pat2, sa) as DisjointPattern;
          newlist.push(tmp);
        }
      }
    }
    return new OrPattern(newlist);
  }

  commonSubPattern(b: Pattern, sa: int4): Pattern {
    let idx = 0;
    let res: Pattern = this.orlist[idx].commonSubPattern(b, sa);
    idx++;

    const useSa = sa > 0 ? 0 : sa;
    while (idx < this.orlist.length) {
      const next = this.orlist[idx].commonSubPattern(res, useSa);
      res = next;
      idx++;
    }
    return res;
  }

  doOr(b: Pattern, sa: int4): Pattern {
    const b2 = (b instanceof OrPattern) ? b as OrPattern : null;
    const newlist: DisjointPattern[] = [];

    for (const pat of this.orlist) {
      newlist.push(pat.simplifyClone() as DisjointPattern);
    }
    if (sa < 0) {
      for (const pat of this.orlist) {
        pat.shiftInstruction(-sa);
      }
    }

    if (b2 === null) {
      newlist.push(b.simplifyClone() as DisjointPattern);
    } else {
      for (const pat of b2.orlist) {
        newlist.push(pat.simplifyClone() as DisjointPattern);
      }
    }
    if (sa > 0) {
      for (let i = 0; i < newlist.length; ++i) {
        newlist[i].shiftInstruction(sa);
      }
    }

    return new OrPattern(newlist);
  }

  encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_OR_PAT);
    for (let i = 0; i < this.orlist.length; ++i) {
      this.orlist[i].encode(encoder);
    }
    encoder.closeElement(SLA_ELEM_OR_PAT);
  }

  decode(decoder: Decoder): void {
    const el = decoder.openElementId(SLA_ELEM_OR_PAT);
    while (decoder.peekElement() !== 0) {
      const pat = DisjointPattern.decodeDisjoint(decoder);
      this.orlist.push(pat);
    }
    decoder.closeElement(el);
  }
}
