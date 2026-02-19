/**
 * @file slghpatexpress.ts
 * @description SLEIGH pattern expressions - the expression tree system used to compute
 * values from instruction bit patterns during decoding.
 *
 * Translated from Ghidra's slghpatexpress.hh / slghpatexpress.cc.
 *
 * Classes include:
 * - TokenPattern: A pattern tied to a list of tokens
 * - PatternExpression hierarchy: TokenField, ContextField, ConstantValue,
 *   StartInstructionValue, EndInstructionValue, Next2InstructionValue, OperandValue,
 *   BinaryExpression variants (Plus/Sub/Mult/LeftShift/RightShift/And/Or/Xor/Div),
 *   UnaryExpression variants (Minus/Not)
 * - PatternEquation hierarchy: OperandEquation, UnconstrainedEquation,
 *   ValExpressEquation (Equal/NotEqual/Less/LessEqual/Greater/GreaterEqual),
 *   EquationAnd, EquationOr, EquationCat, EquationLeftEllipsis, EquationRightEllipsis
 * - OperandResolve: Helper struct for resolving operand offsets
 */

import { AddrSpace } from '../core/space.js';
import {
  Encoder,
  Decoder,
  ElementId,
  AttributeId,
  ATTRIB_BIGENDIAN,
  ATTRIB_INDEX,
  ATTRIB_VAL,
} from '../core/marshal.js';
import type { int4, uint4, uintm, intb } from '../core/types.js';
import {
  SleighError,
  Token,
  ConstructState,
  ParserWalker,
  ParserContext,
} from './context.js';
import {
  SLA_ATTRIB_SIGNBIT,
  SLA_ATTRIB_STARTBIT,
  SLA_ATTRIB_ENDBIT,
  SLA_ATTRIB_STARTBYTE,
  SLA_ATTRIB_ENDBYTE,
  SLA_ATTRIB_SHIFT,
  SLA_ATTRIB_TABLE,
  SLA_ATTRIB_CT,
  SLA_ATTRIB_BIGENDIAN,
  SLA_ATTRIB_INDEX,
  SLA_ATTRIB_VAL,
  SLA_ELEM_TOKENFIELD,
  SLA_ELEM_CONTEXTFIELD,
  SLA_ELEM_OPERAND_EXP,
  SLA_ELEM_AND_EXP,
  SLA_ELEM_DIV_EXP,
  SLA_ELEM_LSHIFT_EXP,
  SLA_ELEM_MINUS_EXP,
  SLA_ELEM_MULT_EXP,
  SLA_ELEM_NOT_EXP,
  SLA_ELEM_OR_EXP,
  SLA_ELEM_PLUS_EXP,
  SLA_ELEM_RSHIFT_EXP,
  SLA_ELEM_SUB_EXP,
  SLA_ELEM_XOR_EXP,
  SLA_ELEM_INTB,
  SLA_ELEM_END_EXP,
  SLA_ELEM_NEXT2_EXP,
  SLA_ELEM_START_EXP,
} from './slaformat.js';

// Forward declarations for types from not-yet-written SLEIGH files
type Constructor = any;
type OperandSymbol = any;
type TripleSymbol = any;
type SubtableSymbol = any;
type SleighBase = any;
type Translate = any;

// Forward declarations for pattern types from not-yet-written slghpattern module
type Pattern = any;
type PatternBlock = any;
type InstructionPattern = any;
type ContextPattern = any;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** sizeof(uintm) in C++ is 4 (uint32_t) */
const SIZEOF_UINTM = 4;

// ---------------------------------------------------------------------------
// Bigint helper functions
// ---------------------------------------------------------------------------

/**
 * Sign-extend a bigint value based on a bit position.
 * Bit 0 is the least significant, so a value with bits 0..bit is extended.
 * Equivalent to C++: val = (val << sa) >> sa where sa = 64 - (bit+1)
 */
function sign_extend(val: bigint, bit: number): bigint {
  // BigInt has arbitrary precision, so shift-based sign extension doesn't work
  // (shifting a positive BigInt right always fills with 0).
  // Instead: mask to 64 bits, convert to signed, arithmetic shift, mask back.
  const sa = 64 - (bit + 1);
  if (sa <= 0) return val;
  const bsa = BigInt(sa);
  let v = (val << bsa) & 0xFFFFFFFFFFFFFFFFn;
  if (v >= 0x8000000000000000n) {
    v = v - 0x10000000000000000n; // convert to negative for arithmetic shift
  }
  v = v >> bsa;
  return v & 0xFFFFFFFFFFFFFFFFn;
}

/**
 * Zero-extend a bigint value based on a bit position.
 * Clears all bits above the given bit.
 * Equivalent to C++: (uintb(val) << sa) >> sa where sa = 64 - (bit+1)
 */
function zero_extend(val: bigint, bit: number): bigint {
  const numBits = bit + 1;
  if (numBits >= 64) return val & 0xFFFFFFFFFFFFFFFFn;
  const mask = (1n << BigInt(numBits)) - 1n;
  return val & mask;
}

/**
 * Swap bytes in a bigint value of the given byte size.
 * This is an in-place conceptual swap: reverses the byte order of the lowest `size` bytes.
 */
function byte_swap(val: bigint, size: number): bigint {
  let result = 0n;
  for (let i = 0; i < size; i++) {
    result = (result << 8n) | (val & 0xFFn);
    val >>= 8n;
  }
  return result;
}

// ---------------------------------------------------------------------------
// TokenPattern
// ---------------------------------------------------------------------------

/**
 * A pattern associated with a list of tokens.
 *
 * This class wraps a Pattern along with a list of Token objects that define
 * the instruction format. It supports AND, OR, and concatenation operations
 * on patterns, tracking left/right ellipses for variable-length instructions.
 */
export class TokenPattern {
  private pattern: Pattern | null;
  private toklist: Token[];
  private leftellipsis: boolean;
  private rightellipsis: boolean;

  /**
   * Build a mask/value PatternBlock within a single word.
   * The field is given by the bitrange [startbit, endbit] where bit 0 is MOST significant.
   */
  private static buildSingle(startbit: number, endbit: number, byteval: number): PatternBlock {
    let mask: number;
    let offset = 0;
    const size = endbit - startbit + 1;
    while (startbit >= 8) {
      offset += 1;
      startbit -= 8;
      endbit -= 8;
    }
    // ~0 << (32 - size), using unsigned 32-bit arithmetic
    mask = (~0 << (SIZEOF_UINTM * 8 - size)) >>> 0;
    byteval = ((byteval << (SIZEOF_UINTM * 8 - size)) & mask) >>> 0;
    mask = (mask >>> startbit) >>> 0;
    byteval = (byteval >>> startbit) >>> 0;
    // Create PatternBlock(offset, mask, byteval)
    return new (PatternBlockClass as any)(offset, mask, byteval);
  }

  /**
   * Build a pattern block given a big-endian contiguous range of bits and a value.
   */
  private static buildBigBlock(size: number, bitstart: number, bitend: number, value: bigint): PatternBlock {
    let startbit = 8 * size - 1 - bitend;
    let endbit = 8 * size - 1 - bitstart;

    let block: PatternBlock | null = null;
    while (endbit >= startbit) {
      const tmpstart = Math.max(endbit - (endbit & 7), startbit);
      const tmpblock = TokenPattern.buildSingle(tmpstart, endbit, Number(value & 0xFFFFFFFFn));
      if (block === null) {
        block = tmpblock;
      } else {
        const newblock = (block as any).intersect(tmpblock);
        block = newblock;
      }
      value >>= BigInt(endbit - tmpstart + 1);
      endbit = tmpstart - 1;
    }
    return block!;
  }

  /**
   * Build a pattern block given a little-endian contiguous range of bits and a value.
   */
  private static buildLittleBlock(size: number, bitstart: number, bitend: number, value: bigint): PatternBlock {
    let block: PatternBlock | null = null;

    // Convert bit range from little endian / LSB labelling to big endian / MSB labelling
    let startbitHigh = (bitstart >>> 3) * 8; // floor(bitstart/8) * 8
    let endbitHigh = (bitend >>> 3) * 8;     // floor(bitend/8) * 8
    const bitendLow = bitend % 8;
    const bitstartLow = bitstart % 8;

    if (startbitHigh === endbitHigh) {
      const newStart = startbitHigh + 7 - bitendLow;
      const newEnd = endbitHigh + 7 - bitstartLow;
      block = TokenPattern.buildSingle(newStart, newEnd, Number(value & 0xFFFFFFFFn));
    } else {
      block = TokenPattern.buildSingle(startbitHigh, startbitHigh + (7 - bitstartLow), Number(value & 0xFFFFFFFFn));
      value >>= BigInt(8 - bitstartLow);
      startbitHigh += 8;
      while (startbitHigh !== endbitHigh) {
        const tmpblock = TokenPattern.buildSingle(startbitHigh, startbitHigh + 7, Number(value & 0xFFFFFFFFn));
        if (block === null) {
          block = tmpblock;
        } else {
          const newblock = (block as any).intersect(tmpblock);
          block = newblock;
        }
        value >>= 8n;
        startbitHigh += 8;
      }
      const tmpblock = TokenPattern.buildSingle(endbitHigh + (7 - bitendLow), endbitHigh + 7, Number(value & 0xFFFFFFFFn));
      if (block === null) {
        block = tmpblock;
      } else {
        const newblock = (block as any).intersect(tmpblock);
        block = newblock;
      }
    }
    return block!;
  }

  /**
   * Use the token lists to decide how two patterns should be aligned relative to each other.
   * Returns how much tok2 needs to be shifted, and sets the resulting tokenlist and ellipses.
   */
  private resolveTokens(tok1: TokenPattern, tok2: TokenPattern): number {
    let reversedirection = false;
    this.leftellipsis = false;
    this.rightellipsis = false;
    let ressa = 0;
    const minsize = Math.min(tok1.toklist.length, tok2.toklist.length);

    if (minsize === 0) {
      if (tok1.toklist.length === 0 && !tok1.leftellipsis && !tok1.rightellipsis) {
        this.toklist = [...tok2.toklist];
        this.leftellipsis = tok2.leftellipsis;
        this.rightellipsis = tok2.rightellipsis;
        return 0;
      } else if (tok2.toklist.length === 0 && !tok2.leftellipsis && !tok2.rightellipsis) {
        this.toklist = [...tok1.toklist];
        this.leftellipsis = tok1.leftellipsis;
        this.rightellipsis = tok1.rightellipsis;
        return 0;
      }
    }

    if (tok1.leftellipsis) {
      reversedirection = true;
      if (tok2.rightellipsis) {
        throw new SleighError('Right/left ellipsis');
      } else if (tok2.leftellipsis) {
        this.leftellipsis = true;
      } else if (tok1.toklist.length !== minsize) {
        throw new SleighError(`Mismatched pattern sizes -- ${tok1.toklist.length} != ${minsize}`);
      } else if (tok1.toklist.length === tok2.toklist.length) {
        throw new SleighError("Pattern size cannot vary (missing '...'?)");
      }
    } else if (tok1.rightellipsis) {
      if (tok2.leftellipsis) {
        throw new SleighError('Left/right ellipsis');
      } else if (tok2.rightellipsis) {
        this.rightellipsis = true;
      } else if (tok1.toklist.length !== minsize) {
        throw new SleighError(`Mismatched pattern sizes -- ${tok1.toklist.length} != ${minsize}`);
      } else if (tok1.toklist.length === tok2.toklist.length) {
        throw new SleighError("Pattern size cannot vary (missing '...'?)");
      }
    } else {
      if (tok2.leftellipsis) {
        reversedirection = true;
        if (tok2.toklist.length !== minsize) {
          throw new SleighError(`Mismatched pattern sizes -- ${tok2.toklist.length} != ${minsize}`);
        } else if (tok1.toklist.length === tok2.toklist.length) {
          throw new SleighError("Pattern size cannot vary (missing '...'?)");
        }
      } else if (tok2.rightellipsis) {
        if (tok2.toklist.length !== minsize) {
          throw new SleighError(`Mismatched pattern sizes -- ${tok2.toklist.length} != ${minsize}`);
        } else if (tok1.toklist.length === tok2.toklist.length) {
          throw new SleighError("Pattern size cannot vary (missing '...'?)");
        }
      } else {
        if (tok2.toklist.length !== tok1.toklist.length) {
          throw new SleighError(`Mismatched pattern sizes -- ${tok2.toklist.length} != ${tok1.toklist.length}`);
        }
      }
    }

    if (reversedirection) {
      for (let i = 0; i < minsize; ++i) {
        if (tok1.toklist[tok1.toklist.length - 1 - i] !== tok2.toklist[tok2.toklist.length - 1 - i]) {
          throw new SleighError(
            `Mismatched tokens when combining patterns -- ${tok1.toklist[tok1.toklist.length - 1 - i]} != ${tok2.toklist[tok2.toklist.length - 1 - i]}`
          );
        }
      }
      if (tok1.toklist.length <= tok2.toklist.length) {
        for (let i = minsize; i < tok2.toklist.length; ++i) {
          ressa += tok2.toklist[tok2.toklist.length - 1 - i].getSize();
        }
      } else {
        for (let i = minsize; i < tok1.toklist.length; ++i) {
          ressa += tok1.toklist[tok1.toklist.length - 1 - i].getSize();
        }
      }
      if (tok1.toklist.length < tok2.toklist.length) {
        ressa = -ressa;
      }
    } else {
      for (let i = 0; i < minsize; ++i) {
        if (tok1.toklist[i] !== tok2.toklist[i]) {
          throw new SleighError(
            `Mismatched tokens when combining patterns -- ${tok1.toklist[i]} != ${tok2.toklist[i]}`
          );
        }
      }
    }

    // Save results
    if (tok1.toklist.length <= tok2.toklist.length) {
      this.toklist = [...tok2.toklist];
    } else {
      this.toklist = [...tok1.toklist];
    }
    return ressa;
  }

  // Private constructor helper for creating an empty shell with a given pattern
  private static fromPattern(pat: Pattern | null): TokenPattern {
    const tp = new TokenPattern();
    tp.pattern = pat;
    return tp;
  }

  /** Construct a TRUE pattern unassociated with a token */
  constructor();
  /** Construct a TRUE or FALSE pattern unassociated with a token */
  constructor(tf: boolean);
  /** Construct a TRUE pattern associated with a token */
  constructor(tok: Token);
  /** Construct an instruction pattern from a token, value, and bit range */
  constructor(tok: Token, value: bigint, bitstart: number, bitend: number);
  /** Construct a context pattern from a value and bit range */
  constructor(value: bigint, startbit: number, endbit: number);
  /** Copy constructor */
  constructor(tokpat: TokenPattern);
  constructor(
    arg0?: boolean | Token | bigint | TokenPattern,
    arg1?: bigint | number,
    arg2?: number,
    arg3?: number
  ) {
    this.pattern = null;
    this.toklist = [];
    this.leftellipsis = false;
    this.rightellipsis = false;

    if (arg0 === undefined) {
      // Default: TRUE pattern
      this.pattern = new InstructionPatternClass(true);
    } else if (typeof arg0 === 'boolean') {
      // TRUE or FALSE pattern
      this.pattern = new InstructionPatternClass(arg0);
    } else if (arg0 instanceof Token) {
      if (arg1 !== undefined && arg2 !== undefined && arg3 !== undefined) {
        // Token, value, bitstart, bitend
        const tok = arg0;
        const value = arg1 as bigint;
        const bitstart = arg2 as number;
        const bitend = arg3 as number;
        this.toklist.push(tok);
        let block: PatternBlock;
        if (tok.isBigEndian()) {
          block = TokenPattern.buildBigBlock(tok.getSize(), bitstart, bitend, value);
        } else {
          block = TokenPattern.buildLittleBlock(tok.getSize(), bitstart, bitend, value);
        }
        this.pattern = new InstructionPatternClass(block);
      } else {
        // Token only: TRUE pattern associated with token
        this.toklist.push(arg0);
        this.pattern = new InstructionPatternClass(true);
      }
    } else if (typeof arg0 === 'bigint') {
      // Context pattern: value, startbit, endbit
      const value = arg0;
      const startbit = arg1 as number;
      const endbit = arg2 as number;
      const size = ((endbit / 8) | 0) + 1;
      const block = TokenPattern.buildBigBlock(size, size * 8 - 1 - endbit, size * 8 - 1 - startbit, value);
      this.pattern = new ContextPatternClass(block);
    } else if (arg0 instanceof TokenPattern) {
      // Copy constructor
      this.pattern = (arg0.pattern as any).simplifyClone();
      this.toklist = [...arg0.toklist];
      this.leftellipsis = arg0.leftellipsis;
      this.rightellipsis = arg0.rightellipsis;
    }
  }

  /** Copy assignment */
  copyFrom(tokpat: TokenPattern): TokenPattern {
    this.pattern = (tokpat.pattern as any).simplifyClone();
    this.toklist = [...tokpat.toklist];
    this.leftellipsis = tokpat.leftellipsis;
    this.rightellipsis = tokpat.rightellipsis;
    return this;
  }

  setLeftEllipsis(val: boolean): void {
    this.leftellipsis = val;
  }

  setRightEllipsis(val: boolean): void {
    this.rightellipsis = val;
  }

  getLeftEllipsis(): boolean {
    return this.leftellipsis;
  }

  getRightEllipsis(): boolean {
    return this.rightellipsis;
  }

  /** Return this AND tokpat */
  doAnd(tokpat: TokenPattern): TokenPattern {
    const res = TokenPattern.fromPattern(null);
    const sa = res.resolveTokens(this, tokpat);
    res.pattern = (this.pattern as any).doAnd(tokpat.pattern, sa);
    return res;
  }

  /** Return this OR tokpat */
  doOr(tokpat: TokenPattern): TokenPattern {
    const res = TokenPattern.fromPattern(null);
    const sa = res.resolveTokens(this, tokpat);
    res.pattern = (this.pattern as any).doOr(tokpat.pattern, sa);
    return res;
  }

  /** Return concatenation of this and tokpat */
  doCat(tokpat: TokenPattern): TokenPattern {
    const res = TokenPattern.fromPattern(null);
    let sa: number;

    res.leftellipsis = this.leftellipsis;
    res.rightellipsis = this.rightellipsis;
    res.toklist = [...this.toklist];

    if (this.rightellipsis || tokpat.leftellipsis) {
      // Check for interior ellipsis
      if (this.rightellipsis) {
        if (!tokpat.alwaysInstructionTrue()) {
          throw new SleighError('Interior ellipsis in pattern');
        }
      }
      if (tokpat.leftellipsis) {
        if (!this.alwaysInstructionTrue()) {
          throw new SleighError('Interior ellipsis in pattern');
        }
        res.leftellipsis = true;
      }
      sa = -1;
    } else {
      sa = 0;
      for (const tok of this.toklist) {
        sa += tok.getSize();
      }
      for (const tok of tokpat.toklist) {
        res.toklist.push(tok);
      }
      res.rightellipsis = tokpat.rightellipsis;
    }

    if (res.rightellipsis && res.leftellipsis) {
      throw new SleighError('Double ellipsis in pattern');
    }

    if (sa < 0) {
      res.pattern = (this.pattern as any).doAnd(tokpat.pattern, 0);
    } else {
      res.pattern = (this.pattern as any).doAnd(tokpat.pattern, sa);
    }
    return res;
  }

  /** Construct a pattern that matches anything matching either this or tokpat */
  commonSubPattern(tokpat: TokenPattern): TokenPattern {
    const patres = TokenPattern.fromPattern(null);
    let reversedirection = false;

    if (this.leftellipsis || tokpat.leftellipsis) {
      if (this.rightellipsis || tokpat.rightellipsis) {
        throw new SleighError('Right/left ellipsis in commonSubPattern');
      }
      reversedirection = true;
    }

    patres.leftellipsis = this.leftellipsis || tokpat.leftellipsis;
    patres.rightellipsis = this.rightellipsis || tokpat.rightellipsis;
    let minnum = this.toklist.length;
    let maxnum = tokpat.toklist.length;
    if (maxnum < minnum) {
      const tmp = minnum;
      minnum = maxnum;
      maxnum = tmp;
    }

    let i: number;
    if (reversedirection) {
      for (i = 0; i < minnum; ++i) {
        const tok = this.toklist[this.toklist.length - 1 - i];
        if (tok === tokpat.toklist[tokpat.toklist.length - 1 - i]) {
          patres.toklist.unshift(tok);
        } else {
          break;
        }
      }
      if (i < maxnum) {
        patres.leftellipsis = true;
      }
    } else {
      for (i = 0; i < minnum; ++i) {
        const tok = this.toklist[i];
        if (tok === tokpat.toklist[i]) {
          patres.toklist.push(tok);
        } else {
          break;
        }
      }
      if (i < maxnum) {
        patres.rightellipsis = true;
      }
    }

    patres.pattern = (this.pattern as any).commonSubPattern(tokpat.pattern, 0);
    return patres;
  }

  getPattern(): Pattern {
    return this.pattern;
  }

  /** Add up length of concatenated tokens */
  getMinimumLength(): number {
    let length = 0;
    for (let i = 0; i < this.toklist.length; ++i) {
      length += this.toklist[i].getSize();
    }
    return length;
  }

  alwaysTrue(): boolean {
    return (this.pattern as any).alwaysTrue();
  }

  alwaysFalse(): boolean {
    return (this.pattern as any).alwaysFalse();
  }

  alwaysInstructionTrue(): boolean {
    return (this.pattern as any).alwaysInstructionTrue();
  }
}

// ---------------------------------------------------------------------------
// Module-level helper: getInstructionBytes
// ---------------------------------------------------------------------------

/**
 * Build a bigint from the instruction bytes.
 */
function getInstructionBytes(walker: ParserWalker, bytestart: number, byteend: number, bigendian: boolean): bigint {
  let res = 0n;
  let tmpsize = byteend - bytestart + 1;
  const size = tmpsize;

  while (tmpsize >= SIZEOF_UINTM) {
    const tmp = walker.getInstructionBytes(bytestart, SIZEOF_UINTM);
    res = (res << BigInt(8 * SIZEOF_UINTM)) | BigInt(tmp >>> 0);
    bytestart += SIZEOF_UINTM;
    tmpsize -= SIZEOF_UINTM;
  }
  if (tmpsize > 0) {
    const tmp = walker.getInstructionBytes(bytestart, tmpsize);
    res = (res << BigInt(8 * tmpsize)) | BigInt(tmp >>> 0);
  }
  if (!bigendian) {
    res = byte_swap(res, size);
  }
  return res;
}

/**
 * Build a bigint from the context bytes.
 */
function getContextBytes(walker: ParserWalker, bytestart: number, byteend: number): bigint {
  let res = 0n;
  let size = byteend - bytestart + 1;

  while (size >= SIZEOF_UINTM) {
    const tmp = walker.getContextBytes(bytestart, SIZEOF_UINTM);
    res = (res << BigInt(8 * SIZEOF_UINTM)) | BigInt(tmp >>> 0);
    bytestart += SIZEOF_UINTM;
    size = byteend - bytestart + 1;
  }
  if (size > 0) {
    const tmp = walker.getContextBytes(bytestart, size);
    res = (res << BigInt(8 * size)) | BigInt(tmp >>> 0);
  }
  return res;
}

// ---------------------------------------------------------------------------
// advance_combo helper
// ---------------------------------------------------------------------------

/**
 * Advance a combination vector (odometer-style). Returns false when all combinations exhausted.
 */
function advance_combo(val: bigint[], min: bigint[], max: bigint[]): boolean {
  let i = 0;
  while (i < val.length) {
    val[i] += 1n;
    if (val[i] <= max[i]) return true; // maximum is inclusive
    val[i] = min[i];
    i += 1;
  }
  return false;
}

/**
 * Build a composite TokenPattern from a lhs pattern value, a specific lhsval,
 * and a set of semantic values with their current combination values.
 */
function buildPattern(lhs: PatternValue, lhsval: bigint, semval: PatternValue[], val: bigint[]): TokenPattern {
  let respattern = lhs.genPattern(lhsval);
  for (let i = 0; i < semval.length; ++i) {
    respattern = respattern.doAnd(semval[i].genPattern(val[i]));
  }
  return respattern;
}

// ---------------------------------------------------------------------------
// PatternExpression (abstract base)
// ---------------------------------------------------------------------------

/**
 * Base class for all pattern expression tree nodes.
 * A PatternExpression computes a value from an instruction's bits during decoding.
 */
export abstract class PatternExpression {
  private refcount: number = 0;

  abstract getValue(walker: ParserWalker): bigint;
  abstract genMinPattern(ops: TokenPattern[]): TokenPattern;
  abstract listValues(list: PatternValue[]): void;
  abstract getMinMax(minlist: bigint[], maxlist: bigint[]): void;
  abstract getSubValue(replace: bigint[], listpos: { val: number }): bigint;
  abstract encode(encoder: Encoder): void;
  abstract decode(decoder: Decoder, trans: Translate): void;

  getSubValueFromList(replace: bigint[]): bigint {
    const listpos = { val: 0 };
    return this.getSubValue(replace, listpos);
  }

  layClaim(): void {
    this.refcount += 1;
  }

  static release(p: PatternExpression): void {
    p.refcount -= 1;
    // In TS we don't explicitly delete; GC handles it
  }

  static decodeExpression(decoder: Decoder, trans: Translate): PatternExpression | null {
    const el = decoder.peekElement();

    let res: PatternExpression;

    if (el === SLA_ELEM_TOKENFIELD.id) {
      res = new TokenField();
    } else if (el === SLA_ELEM_CONTEXTFIELD.id) {
      res = new ContextField();
    } else if (el === SLA_ELEM_INTB.id) {
      res = new ConstantValue();
    } else if (el === SLA_ELEM_OPERAND_EXP.id) {
      res = new OperandValue();
    } else if (el === SLA_ELEM_START_EXP.id) {
      res = new StartInstructionValue();
    } else if (el === SLA_ELEM_END_EXP.id) {
      res = new EndInstructionValue();
    } else if (el === SLA_ELEM_PLUS_EXP.id) {
      res = new PlusExpression();
    } else if (el === SLA_ELEM_SUB_EXP.id) {
      res = new SubExpression();
    } else if (el === SLA_ELEM_MULT_EXP.id) {
      res = new MultExpression();
    } else if (el === SLA_ELEM_LSHIFT_EXP.id) {
      res = new LeftShiftExpression();
    } else if (el === SLA_ELEM_RSHIFT_EXP.id) {
      res = new RightShiftExpression();
    } else if (el === SLA_ELEM_AND_EXP.id) {
      res = new AndExpression();
    } else if (el === SLA_ELEM_OR_EXP.id) {
      res = new OrExpression();
    } else if (el === SLA_ELEM_XOR_EXP.id) {
      res = new XorExpression();
    } else if (el === SLA_ELEM_DIV_EXP.id) {
      res = new DivExpression();
    } else if (el === SLA_ELEM_MINUS_EXP.id) {
      res = new MinusExpression();
    } else if (el === SLA_ELEM_NOT_EXP.id) {
      res = new NotExpression();
    } else if (el === SLA_ELEM_NEXT2_EXP.id) {
      res = new Next2InstructionValue();
    } else {
      return null;
    }

    res.decode(decoder, trans);
    return res;
  }
}

// ---------------------------------------------------------------------------
// PatternValue (abstract)
// ---------------------------------------------------------------------------

/**
 * A PatternExpression that represents a single value that can generate a pattern.
 */
export abstract class PatternValue extends PatternExpression {
  abstract genPattern(val: bigint): TokenPattern;
  abstract minValue(): bigint;
  abstract maxValue(): bigint;

  listValues(list: PatternValue[]): void {
    list.push(this);
  }

  getMinMax(minlist: bigint[], maxlist: bigint[]): void {
    minlist.push(this.minValue());
    maxlist.push(this.maxValue());
  }

  getSubValue(replace: bigint[], listpos: { val: number }): bigint {
    return replace[listpos.val++];
  }
}

// ---------------------------------------------------------------------------
// TokenField
// ---------------------------------------------------------------------------

/**
 * A PatternValue that extracts a field from an instruction token.
 */
export class TokenField extends PatternValue {
  private tok: Token | null = null;
  private bigendian: boolean = false;
  private signbit: boolean = false;
  private bitstart: number = 0;
  private bitend: number = 0;
  private bytestart: number = 0;
  private byteend: number = 0;
  private shift: number = 0;

  constructor();
  constructor(tk: Token, s: boolean, bstart: number, bend: number);
  constructor(tk?: Token, s?: boolean, bstart?: number, bend?: number) {
    super();
    if (tk !== undefined) {
      this.tok = tk;
      this.bigendian = tk.isBigEndian();
      this.signbit = s!;
      this.bitstart = bstart!;
      this.bitend = bend!;
      if (tk.isBigEndian()) {
        this.byteend = ((tk.getSize() * 8 - this.bitstart - 1) / 8) | 0;
        this.bytestart = ((tk.getSize() * 8 - this.bitend - 1) / 8) | 0;
      } else {
        this.bytestart = (this.bitstart / 8) | 0;
        this.byteend = (this.bitend / 8) | 0;
      }
      this.shift = this.bitstart % 8;
    }
  }

  getValue(walker: ParserWalker): bigint {
    let res = getInstructionBytes(walker, this.bytestart, this.byteend, this.bigendian);
    res >>= BigInt(this.shift);
    if (this.signbit) {
      res = sign_extend(res, this.bitend - this.bitstart);
    } else {
      res = zero_extend(res, this.bitend - this.bitstart);
    }
    return res;
  }

  genMinPattern(ops: TokenPattern[]): TokenPattern {
    return new TokenPattern(this.tok!);
  }

  genPattern(val: bigint): TokenPattern {
    return new TokenPattern(this.tok!, val, this.bitstart, this.bitend);
  }

  minValue(): bigint {
    return 0n;
  }

  maxValue(): bigint {
    return zero_extend(~0n, this.bitend - this.bitstart);
  }

  encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_TOKENFIELD);
    encoder.writeBool(SLA_ATTRIB_BIGENDIAN, this.bigendian);
    encoder.writeBool(SLA_ATTRIB_SIGNBIT, this.signbit);
    encoder.writeSignedInteger(SLA_ATTRIB_STARTBIT, this.bitstart);
    encoder.writeSignedInteger(SLA_ATTRIB_ENDBIT, this.bitend);
    encoder.writeSignedInteger(SLA_ATTRIB_STARTBYTE, this.bytestart);
    encoder.writeSignedInteger(SLA_ATTRIB_ENDBYTE, this.byteend);
    encoder.writeSignedInteger(SLA_ATTRIB_SHIFT, this.shift);
    encoder.closeElement(SLA_ELEM_TOKENFIELD);
  }

  decode(decoder: Decoder, trans: Translate): void {
    const el = decoder.openElementId(SLA_ELEM_TOKENFIELD);
    this.tok = null;
    this.bigendian = decoder.readBoolById(SLA_ATTRIB_BIGENDIAN);
    this.signbit = decoder.readBoolById(SLA_ATTRIB_SIGNBIT);
    this.bitstart = decoder.readSignedIntegerById(SLA_ATTRIB_STARTBIT);
    this.bitend = decoder.readSignedIntegerById(SLA_ATTRIB_ENDBIT);
    this.bytestart = decoder.readSignedIntegerById(SLA_ATTRIB_STARTBYTE);
    this.byteend = decoder.readSignedIntegerById(SLA_ATTRIB_ENDBYTE);
    this.shift = decoder.readSignedIntegerById(SLA_ATTRIB_SHIFT);
    decoder.closeElement(el);
  }
}

// ---------------------------------------------------------------------------
// ContextField
// ---------------------------------------------------------------------------

/**
 * A PatternValue that extracts a field from the context register.
 */
export class ContextField extends PatternValue {
  private startbit: number = 0;
  private endbit: number = 0;
  private startbyte: number = 0;
  private endbyte: number = 0;
  private shift: number = 0;
  private signbit: boolean = false;

  constructor();
  constructor(s: boolean, sbit: number, ebit: number);
  constructor(s?: boolean, sbit?: number, ebit?: number) {
    super();
    if (s !== undefined) {
      this.signbit = s;
      this.startbit = sbit!;
      this.endbit = ebit!;
      this.startbyte = (this.startbit / 8) | 0;
      this.endbyte = (this.endbit / 8) | 0;
      this.shift = 7 - (this.endbit % 8);
    }
  }

  getStartBit(): number {
    return this.startbit;
  }

  getEndBit(): number {
    return this.endbit;
  }

  getSignBit(): boolean {
    return this.signbit;
  }

  getValue(walker: ParserWalker): bigint {
    let res = getContextBytes(walker, this.startbyte, this.endbyte);
    res >>= BigInt(this.shift);
    if (this.signbit) {
      res = sign_extend(res, this.endbit - this.startbit);
    } else {
      res = zero_extend(res, this.endbit - this.startbit);
    }
    return res;
  }

  genMinPattern(ops: TokenPattern[]): TokenPattern {
    return new TokenPattern();
  }

  genPattern(val: bigint): TokenPattern {
    return new TokenPattern(val, this.startbit, this.endbit);
  }

  minValue(): bigint {
    return 0n;
  }

  maxValue(): bigint {
    return zero_extend(~0n, this.endbit - this.startbit);
  }

  encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_CONTEXTFIELD);
    encoder.writeBool(SLA_ATTRIB_SIGNBIT, this.signbit);
    encoder.writeSignedInteger(SLA_ATTRIB_STARTBIT, this.startbit);
    encoder.writeSignedInteger(SLA_ATTRIB_ENDBIT, this.endbit);
    encoder.writeSignedInteger(SLA_ATTRIB_STARTBYTE, this.startbyte);
    encoder.writeSignedInteger(SLA_ATTRIB_ENDBYTE, this.endbyte);
    encoder.writeSignedInteger(SLA_ATTRIB_SHIFT, this.shift);
    encoder.closeElement(SLA_ELEM_CONTEXTFIELD);
  }

  decode(decoder: Decoder, trans: Translate): void {
    const el = decoder.openElementId(SLA_ELEM_CONTEXTFIELD);
    this.signbit = decoder.readBoolById(SLA_ATTRIB_SIGNBIT);
    this.startbit = decoder.readSignedIntegerById(SLA_ATTRIB_STARTBIT);
    this.endbit = decoder.readSignedIntegerById(SLA_ATTRIB_ENDBIT);
    this.startbyte = decoder.readSignedIntegerById(SLA_ATTRIB_STARTBYTE);
    this.endbyte = decoder.readSignedIntegerById(SLA_ATTRIB_ENDBYTE);
    this.shift = decoder.readSignedIntegerById(SLA_ATTRIB_SHIFT);
    decoder.closeElement(el);
  }
}

// ---------------------------------------------------------------------------
// ConstantValue
// ---------------------------------------------------------------------------

/**
 * A PatternValue that holds a constant integer.
 */
export class ConstantValue extends PatternValue {
  private val: bigint = 0n;

  constructor();
  constructor(v: bigint);
  constructor(v?: bigint) {
    super();
    if (v !== undefined) {
      this.val = v;
    }
  }

  getValue(walker: ParserWalker): bigint {
    return this.val;
  }

  genMinPattern(ops: TokenPattern[]): TokenPattern {
    return new TokenPattern();
  }

  genPattern(v: bigint): TokenPattern {
    return new TokenPattern(this.val === v);
  }

  minValue(): bigint {
    return this.val;
  }

  maxValue(): bigint {
    return this.val;
  }

  encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_INTB);
    encoder.writeSignedInteger(SLA_ATTRIB_VAL, Number(this.val));
    encoder.closeElement(SLA_ELEM_INTB);
  }

  decode(decoder: Decoder, trans: Translate): void {
    const el = decoder.openElementId(SLA_ELEM_INTB);
    this.val = BigInt(decoder.readSignedIntegerById(SLA_ATTRIB_VAL));
    decoder.closeElement(el);
  }
}

// ---------------------------------------------------------------------------
// StartInstructionValue
// ---------------------------------------------------------------------------

/**
 * A PatternValue that returns the address of the start of the current instruction.
 */
export class StartInstructionValue extends PatternValue {
  getValue(walker: ParserWalker): bigint {
    const addr = walker.getAddr();
    return AddrSpace.byteToAddress(addr.getOffset(), addr.getSpace()!.getWordSize());
  }

  genMinPattern(ops: TokenPattern[]): TokenPattern {
    return new TokenPattern();
  }

  genPattern(val: bigint): TokenPattern {
    return new TokenPattern();
  }

  minValue(): bigint {
    return 0n;
  }

  maxValue(): bigint {
    return 0n;
  }

  encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_START_EXP);
    encoder.closeElement(SLA_ELEM_START_EXP);
  }

  decode(decoder: Decoder, trans: Translate): void {
    const el = decoder.openElementId(SLA_ELEM_START_EXP);
    decoder.closeElement(el);
  }
}

// ---------------------------------------------------------------------------
// EndInstructionValue
// ---------------------------------------------------------------------------

/**
 * A PatternValue that returns the address of the next instruction.
 */
export class EndInstructionValue extends PatternValue {
  getValue(walker: ParserWalker): bigint {
    const addr = walker.getNaddr();
    return AddrSpace.byteToAddress(addr.getOffset(), addr.getSpace()!.getWordSize());
  }

  genMinPattern(ops: TokenPattern[]): TokenPattern {
    return new TokenPattern();
  }

  genPattern(val: bigint): TokenPattern {
    return new TokenPattern();
  }

  minValue(): bigint {
    return 0n;
  }

  maxValue(): bigint {
    return 0n;
  }

  encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_END_EXP);
    encoder.closeElement(SLA_ELEM_END_EXP);
  }

  decode(decoder: Decoder, trans: Translate): void {
    const el = decoder.openElementId(SLA_ELEM_END_EXP);
    decoder.closeElement(el);
  }
}

// ---------------------------------------------------------------------------
// Next2InstructionValue
// ---------------------------------------------------------------------------

/**
 * A PatternValue that returns the address two instructions ahead.
 */
export class Next2InstructionValue extends PatternValue {
  getValue(walker: ParserWalker): bigint {
    const addr = walker.getN2addr();
    return AddrSpace.byteToAddress(addr.getOffset(), addr.getSpace()!.getWordSize());
  }

  genMinPattern(ops: TokenPattern[]): TokenPattern {
    return new TokenPattern();
  }

  genPattern(val: bigint): TokenPattern {
    return new TokenPattern();
  }

  minValue(): bigint {
    return 0n;
  }

  maxValue(): bigint {
    return 0n;
  }

  encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_NEXT2_EXP);
    encoder.closeElement(SLA_ELEM_NEXT2_EXP);
  }

  decode(decoder: Decoder, trans: Translate): void {
    const el = decoder.openElementId(SLA_ELEM_NEXT2_EXP);
    decoder.closeElement(el);
  }
}

// ---------------------------------------------------------------------------
// OperandValue
// ---------------------------------------------------------------------------

/**
 * A PatternValue that references an operand of a constructor.
 */
export class OperandValue extends PatternValue {
  private index: number = 0;
  private ct: Constructor | null = null;

  constructor();
  constructor(ind: number, c: Constructor);
  constructor(ind?: number, c?: Constructor) {
    super();
    if (ind !== undefined) {
      this.index = ind;
      this.ct = c!;
    }
  }

  changeIndex(newind: number): void {
    this.index = newind;
  }

  isConstructorRelative(): boolean {
    const sym: OperandSymbol = (this.ct as any).getOperand(this.index);
    return (sym as any).getOffsetBase() === -1;
  }

  getName(): string {
    const sym: OperandSymbol = (this.ct as any).getOperand(this.index);
    return (sym as any).getName();
  }

  genPattern(val: bigint): TokenPattern {
    throw new SleighError('Operand used in pattern expression');
  }

  genMinPattern(ops: TokenPattern[]): TokenPattern {
    return ops[this.index];
  }

  getValue(walker: ParserWalker): bigint {
    const sym: OperandSymbol = (this.ct as any).getOperand(this.index);
    let patexp: PatternExpression | null = (sym as any).getDefiningExpression();
    if (patexp === null) {
      const defsym: TripleSymbol | null = (sym as any).getDefiningSymbol();
      if (defsym !== null) {
        patexp = (defsym as any).getPatternExpression();
      }
      if (patexp === null) {
        return 0n;
      }
    }
    const tempstate = new ConstructState();
    const newwalker = new ParserWalker(walker.getParserContext());
    newwalker.setOutOfBandState(this.ct, this.index, tempstate, walker);
    const res = patexp.getValue(newwalker);
    return res;
  }

  override getSubValue(replace: bigint[], listpos: { val: number }): bigint {
    const sym: OperandSymbol = (this.ct as any).getOperand(this.index);
    return ((sym as any).getDefiningExpression() as PatternExpression).getSubValue(replace, listpos);
  }

  minValue(): bigint {
    throw new SleighError('Operand used in pattern expression');
  }

  maxValue(): bigint {
    throw new SleighError('Operand used in pattern expression');
  }

  encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_OPERAND_EXP);
    encoder.writeSignedInteger(SLA_ATTRIB_INDEX, this.index);
    encoder.writeUnsignedInteger(SLA_ATTRIB_TABLE, BigInt((this.ct as any).getParent().getId()));
    encoder.writeUnsignedInteger(SLA_ATTRIB_CT, BigInt((this.ct as any).getId()));
    encoder.closeElement(SLA_ELEM_OPERAND_EXP);
  }

  decode(decoder: Decoder, trans: Translate): void {
    const el = decoder.openElementId(SLA_ELEM_OPERAND_EXP);
    this.index = decoder.readSignedIntegerById(SLA_ATTRIB_INDEX);
    const tabid = Number(decoder.readUnsignedIntegerById(SLA_ATTRIB_TABLE));
    const ctid = Number(decoder.readUnsignedIntegerById(SLA_ATTRIB_CT));
    const sleigh: SleighBase = trans;
    const tab: SubtableSymbol = (sleigh as any).findSymbol(tabid);
    this.ct = (tab as any).getConstructor(ctid);
    decoder.closeElement(el);
  }
}

// ---------------------------------------------------------------------------
// BinaryExpression
// ---------------------------------------------------------------------------

/**
 * A PatternExpression with two operands (left and right).
 */
export class BinaryExpression extends PatternExpression {
  private left: PatternExpression | null = null;
  private right: PatternExpression | null = null;

  constructor();
  constructor(l: PatternExpression, r: PatternExpression);
  constructor(l?: PatternExpression, r?: PatternExpression) {
    super();
    if (l !== undefined) {
      this.left = l;
      l.layClaim();
      this.right = r!;
      r!.layClaim();
    }
  }

  protected dispose(): void {
    if (this.left !== null) PatternExpression.release(this.left);
    if (this.right !== null) PatternExpression.release(this.right);
  }

  getLeft(): PatternExpression {
    return this.left!;
  }

  getRight(): PatternExpression {
    return this.right!;
  }

  getValue(walker: ParserWalker): bigint {
    throw new SleighError('BinaryExpression.getValue not implemented');
  }

  genMinPattern(ops: TokenPattern[]): TokenPattern {
    return new TokenPattern();
  }

  listValues(list: PatternValue[]): void {
    this.left!.listValues(list);
    this.right!.listValues(list);
  }

  getMinMax(minlist: bigint[], maxlist: bigint[]): void {
    this.left!.getMinMax(minlist, maxlist);
    this.right!.getMinMax(minlist, maxlist);
  }

  getSubValue(replace: bigint[], listpos: { val: number }): bigint {
    throw new SleighError('BinaryExpression.getSubValue not implemented');
  }

  encode(encoder: Encoder): void {
    // Outer tag is generated by derived classes
    this.left!.encode(encoder);
    this.right!.encode(encoder);
  }

  decode(decoder: Decoder, trans: Translate): void {
    const el = decoder.openElement();
    this.left = PatternExpression.decodeExpression(decoder, trans)!;
    this.right = PatternExpression.decodeExpression(decoder, trans)!;
    this.left.layClaim();
    this.right.layClaim();
    decoder.closeElement(el);
  }
}

// ---------------------------------------------------------------------------
// UnaryExpression
// ---------------------------------------------------------------------------

/**
 * A PatternExpression with a single operand.
 */
export class UnaryExpression extends PatternExpression {
  private unary: PatternExpression | null = null;

  constructor();
  constructor(u: PatternExpression);
  constructor(u?: PatternExpression) {
    super();
    if (u !== undefined) {
      this.unary = u;
      u.layClaim();
    }
  }

  protected dispose(): void {
    if (this.unary !== null) PatternExpression.release(this.unary);
  }

  getUnary(): PatternExpression {
    return this.unary!;
  }

  getValue(walker: ParserWalker): bigint {
    throw new SleighError('UnaryExpression.getValue not implemented');
  }

  genMinPattern(ops: TokenPattern[]): TokenPattern {
    return new TokenPattern();
  }

  listValues(list: PatternValue[]): void {
    this.unary!.listValues(list);
  }

  getMinMax(minlist: bigint[], maxlist: bigint[]): void {
    this.unary!.getMinMax(minlist, maxlist);
  }

  getSubValue(replace: bigint[], listpos: { val: number }): bigint {
    throw new SleighError('UnaryExpression.getSubValue not implemented');
  }

  encode(encoder: Encoder): void {
    // Outer tag is generated by derived classes
    this.unary!.encode(encoder);
  }

  decode(decoder: Decoder, trans: Translate): void {
    const el = decoder.openElement();
    this.unary = PatternExpression.decodeExpression(decoder, trans)!;
    this.unary.layClaim();
    decoder.closeElement(el);
  }
}

// ---------------------------------------------------------------------------
// PlusExpression
// ---------------------------------------------------------------------------

export class PlusExpression extends BinaryExpression {
  constructor();
  constructor(l: PatternExpression, r: PatternExpression);
  constructor(l?: PatternExpression, r?: PatternExpression) {
    if (l !== undefined) {
      super(l, r!);
    } else {
      super();
    }
  }

  override getValue(walker: ParserWalker): bigint {
    return this.getLeft().getValue(walker) + this.getRight().getValue(walker);
  }

  override getSubValue(replace: bigint[], listpos: { val: number }): bigint {
    const leftval = this.getLeft().getSubValue(replace, listpos);
    const rightval = this.getRight().getSubValue(replace, listpos);
    return leftval + rightval;
  }

  override encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_PLUS_EXP);
    super.encode(encoder);
    encoder.closeElement(SLA_ELEM_PLUS_EXP);
  }
}

// ---------------------------------------------------------------------------
// SubExpression
// ---------------------------------------------------------------------------

export class SubExpression extends BinaryExpression {
  constructor();
  constructor(l: PatternExpression, r: PatternExpression);
  constructor(l?: PatternExpression, r?: PatternExpression) {
    if (l !== undefined) {
      super(l, r!);
    } else {
      super();
    }
  }

  override getValue(walker: ParserWalker): bigint {
    return this.getLeft().getValue(walker) - this.getRight().getValue(walker);
  }

  override getSubValue(replace: bigint[], listpos: { val: number }): bigint {
    const leftval = this.getLeft().getSubValue(replace, listpos);
    const rightval = this.getRight().getSubValue(replace, listpos);
    return leftval - rightval;
  }

  override encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_SUB_EXP);
    super.encode(encoder);
    encoder.closeElement(SLA_ELEM_SUB_EXP);
  }
}

// ---------------------------------------------------------------------------
// MultExpression
// ---------------------------------------------------------------------------

export class MultExpression extends BinaryExpression {
  constructor();
  constructor(l: PatternExpression, r: PatternExpression);
  constructor(l?: PatternExpression, r?: PatternExpression) {
    if (l !== undefined) {
      super(l, r!);
    } else {
      super();
    }
  }

  override getValue(walker: ParserWalker): bigint {
    return this.getLeft().getValue(walker) * this.getRight().getValue(walker);
  }

  override getSubValue(replace: bigint[], listpos: { val: number }): bigint {
    const leftval = this.getLeft().getSubValue(replace, listpos);
    const rightval = this.getRight().getSubValue(replace, listpos);
    return leftval * rightval;
  }

  override encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_MULT_EXP);
    super.encode(encoder);
    encoder.closeElement(SLA_ELEM_MULT_EXP);
  }
}

// ---------------------------------------------------------------------------
// LeftShiftExpression
// ---------------------------------------------------------------------------

export class LeftShiftExpression extends BinaryExpression {
  constructor();
  constructor(l: PatternExpression, r: PatternExpression);
  constructor(l?: PatternExpression, r?: PatternExpression) {
    if (l !== undefined) {
      super(l, r!);
    } else {
      super();
    }
  }

  override getValue(walker: ParserWalker): bigint {
    return this.getLeft().getValue(walker) << this.getRight().getValue(walker);
  }

  override getSubValue(replace: bigint[], listpos: { val: number }): bigint {
    const leftval = this.getLeft().getSubValue(replace, listpos);
    const rightval = this.getRight().getSubValue(replace, listpos);
    return leftval << rightval;
  }

  override encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_LSHIFT_EXP);
    super.encode(encoder);
    encoder.closeElement(SLA_ELEM_LSHIFT_EXP);
  }
}

// ---------------------------------------------------------------------------
// RightShiftExpression
// ---------------------------------------------------------------------------

export class RightShiftExpression extends BinaryExpression {
  constructor();
  constructor(l: PatternExpression, r: PatternExpression);
  constructor(l?: PatternExpression, r?: PatternExpression) {
    if (l !== undefined) {
      super(l, r!);
    } else {
      super();
    }
  }

  override getValue(walker: ParserWalker): bigint {
    return this.getLeft().getValue(walker) >> this.getRight().getValue(walker);
  }

  override getSubValue(replace: bigint[], listpos: { val: number }): bigint {
    const leftval = this.getLeft().getSubValue(replace, listpos);
    const rightval = this.getRight().getSubValue(replace, listpos);
    return leftval >> rightval;
  }

  override encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_RSHIFT_EXP);
    super.encode(encoder);
    encoder.closeElement(SLA_ELEM_RSHIFT_EXP);
  }
}

// ---------------------------------------------------------------------------
// AndExpression
// ---------------------------------------------------------------------------

export class AndExpression extends BinaryExpression {
  constructor();
  constructor(l: PatternExpression, r: PatternExpression);
  constructor(l?: PatternExpression, r?: PatternExpression) {
    if (l !== undefined) {
      super(l, r!);
    } else {
      super();
    }
  }

  override getValue(walker: ParserWalker): bigint {
    return this.getLeft().getValue(walker) & this.getRight().getValue(walker);
  }

  override getSubValue(replace: bigint[], listpos: { val: number }): bigint {
    const leftval = this.getLeft().getSubValue(replace, listpos);
    const rightval = this.getRight().getSubValue(replace, listpos);
    return leftval & rightval;
  }

  override encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_AND_EXP);
    super.encode(encoder);
    encoder.closeElement(SLA_ELEM_AND_EXP);
  }
}

// ---------------------------------------------------------------------------
// OrExpression
// ---------------------------------------------------------------------------

export class OrExpression extends BinaryExpression {
  constructor();
  constructor(l: PatternExpression, r: PatternExpression);
  constructor(l?: PatternExpression, r?: PatternExpression) {
    if (l !== undefined) {
      super(l, r!);
    } else {
      super();
    }
  }

  override getValue(walker: ParserWalker): bigint {
    return this.getLeft().getValue(walker) | this.getRight().getValue(walker);
  }

  override getSubValue(replace: bigint[], listpos: { val: number }): bigint {
    const leftval = this.getLeft().getSubValue(replace, listpos);
    const rightval = this.getRight().getSubValue(replace, listpos);
    return leftval | rightval;
  }

  override encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_OR_EXP);
    super.encode(encoder);
    encoder.closeElement(SLA_ELEM_OR_EXP);
  }
}

// ---------------------------------------------------------------------------
// XorExpression
// ---------------------------------------------------------------------------

export class XorExpression extends BinaryExpression {
  constructor();
  constructor(l: PatternExpression, r: PatternExpression);
  constructor(l?: PatternExpression, r?: PatternExpression) {
    if (l !== undefined) {
      super(l, r!);
    } else {
      super();
    }
  }

  override getValue(walker: ParserWalker): bigint {
    return this.getLeft().getValue(walker) ^ this.getRight().getValue(walker);
  }

  override getSubValue(replace: bigint[], listpos: { val: number }): bigint {
    const leftval = this.getLeft().getSubValue(replace, listpos);
    const rightval = this.getRight().getSubValue(replace, listpos);
    return leftval ^ rightval;
  }

  override encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_XOR_EXP);
    super.encode(encoder);
    encoder.closeElement(SLA_ELEM_XOR_EXP);
  }
}

// ---------------------------------------------------------------------------
// DivExpression
// ---------------------------------------------------------------------------

export class DivExpression extends BinaryExpression {
  constructor();
  constructor(l: PatternExpression, r: PatternExpression);
  constructor(l?: PatternExpression, r?: PatternExpression) {
    if (l !== undefined) {
      super(l, r!);
    } else {
      super();
    }
  }

  override getValue(walker: ParserWalker): bigint {
    return this.getLeft().getValue(walker) / this.getRight().getValue(walker);
  }

  override getSubValue(replace: bigint[], listpos: { val: number }): bigint {
    const leftval = this.getLeft().getSubValue(replace, listpos);
    const rightval = this.getRight().getSubValue(replace, listpos);
    return leftval / rightval;
  }

  override encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_DIV_EXP);
    super.encode(encoder);
    encoder.closeElement(SLA_ELEM_DIV_EXP);
  }
}

// ---------------------------------------------------------------------------
// MinusExpression
// ---------------------------------------------------------------------------

export class MinusExpression extends UnaryExpression {
  constructor();
  constructor(u: PatternExpression);
  constructor(u?: PatternExpression) {
    if (u !== undefined) {
      super(u);
    } else {
      super();
    }
  }

  override getValue(walker: ParserWalker): bigint {
    return -this.getUnary().getValue(walker);
  }

  override getSubValue(replace: bigint[], listpos: { val: number }): bigint {
    return -this.getUnary().getSubValue(replace, listpos);
  }

  override encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_MINUS_EXP);
    super.encode(encoder);
    encoder.closeElement(SLA_ELEM_MINUS_EXP);
  }
}

// ---------------------------------------------------------------------------
// NotExpression
// ---------------------------------------------------------------------------

export class NotExpression extends UnaryExpression {
  constructor();
  constructor(u: PatternExpression);
  constructor(u?: PatternExpression) {
    if (u !== undefined) {
      super(u);
    } else {
      super();
    }
  }

  override getValue(walker: ParserWalker): bigint {
    return ~this.getUnary().getValue(walker);
  }

  override getSubValue(replace: bigint[], listpos: { val: number }): bigint {
    return ~this.getUnary().getSubValue(replace, listpos);
  }

  override encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_NOT_EXP);
    super.encode(encoder);
    encoder.closeElement(SLA_ELEM_NOT_EXP);
  }
}

// ---------------------------------------------------------------------------
// OperandResolve
// ---------------------------------------------------------------------------

/**
 * Helper structure for resolving operand offsets during pattern equation processing.
 */
export class OperandResolve {
  operands: OperandSymbol[];
  base: number = -1;
  offset: number = 0;
  cur_rightmost: number = -1;
  size: number = 0;

  constructor(ops: OperandSymbol[]) {
    this.operands = ops;
  }
}

// ---------------------------------------------------------------------------
// PatternEquation (abstract base)
// ---------------------------------------------------------------------------

/**
 * Base class for pattern equations that produce TokenPatterns from operand patterns.
 */
export abstract class PatternEquation {
  private refcount: number = 0;
  protected resultpattern: TokenPattern = new TokenPattern();

  getTokenPattern(): TokenPattern {
    return this.resultpattern;
  }

  abstract genPattern(ops: TokenPattern[]): void;
  abstract resolveOperandLeft(state: OperandResolve): boolean;

  operandOrder(ct: Constructor, order: OperandSymbol[]): void {
    // Default: do nothing
  }

  layClaim(): void {
    this.refcount += 1;
  }

  static release(pateq: PatternEquation): void {
    pateq.refcount -= 1;
    // GC handles cleanup
  }
}

// ---------------------------------------------------------------------------
// OperandEquation
// ---------------------------------------------------------------------------

/**
 * An equation that defines an operand.
 */
export class OperandEquation extends PatternEquation {
  private index: number;

  constructor(ind: number) {
    super();
    this.index = ind;
  }

  genPattern(ops: TokenPattern[]): void {
    this.resultpattern = ops[this.index];
  }

  resolveOperandLeft(state: OperandResolve): boolean {
    const sym: OperandSymbol = state.operands[this.index];
    if ((sym as any).isOffsetIrrelevant()) {
      (sym as any).offsetbase = -1;
      (sym as any).reloffset = 0;
      return true;
    }
    if (state.base === -2) return false; // We have no base
    (sym as any).offsetbase = state.base;
    (sym as any).reloffset = state.offset;
    state.cur_rightmost = this.index;
    state.size = 0;
    return true;
  }

  override operandOrder(ct: Constructor, order: OperandSymbol[]): void {
    const sym: OperandSymbol = (ct as any).getOperand(this.index);
    if (!(sym as any).isMarked()) {
      order.push(sym);
      (sym as any).setMark();
    }
  }
}

// ---------------------------------------------------------------------------
// UnconstrainedEquation
// ---------------------------------------------------------------------------

/**
 * An unconstrained equation that just extracts token patterns from an expression.
 */
export class UnconstrainedEquation extends PatternEquation {
  private patex: PatternExpression;

  constructor(p: PatternExpression) {
    super();
    this.patex = p;
    p.layClaim();
  }

  genPattern(ops: TokenPattern[]): void {
    this.resultpattern = this.patex.genMinPattern(ops);
  }

  resolveOperandLeft(state: OperandResolve): boolean {
    state.cur_rightmost = -1;
    if (this.resultpattern.getLeftEllipsis() || this.resultpattern.getRightEllipsis()) {
      state.size = -1;
    } else {
      state.size = this.resultpattern.getMinimumLength();
    }
    return true;
  }
}

// ---------------------------------------------------------------------------
// ValExpressEquation
// ---------------------------------------------------------------------------

/**
 * An equation that compares a pattern value (lhs) against a pattern expression (rhs).
 */
export class ValExpressEquation extends PatternEquation {
  protected lhs: PatternValue;
  protected rhs: PatternExpression;

  constructor(l: PatternValue, r: PatternExpression) {
    super();
    this.lhs = l;
    l.layClaim();
    this.rhs = r;
    r.layClaim();
  }

  resolveOperandLeft(state: OperandResolve): boolean {
    state.cur_rightmost = -1;
    if (this.resultpattern.getLeftEllipsis() || this.resultpattern.getRightEllipsis()) {
      state.size = -1;
    } else {
      state.size = this.resultpattern.getMinimumLength();
    }
    return true;
  }

  genPattern(ops: TokenPattern[]): void {
    // Subclasses implement this
  }
}

// ---------------------------------------------------------------------------
// EqualEquation
// ---------------------------------------------------------------------------

export class EqualEquation extends ValExpressEquation {
  constructor(l: PatternValue, r: PatternExpression) {
    super(l, r);
  }

  override genPattern(ops: TokenPattern[]): void {
    const lhsmin = this.lhs.minValue();
    const lhsmax = this.lhs.maxValue();
    const semval: PatternValue[] = [];
    const min: bigint[] = [];
    const max: bigint[] = [];
    this.rhs.listValues(semval);
    this.rhs.getMinMax(min, max);
    const cur = [...min];
    let count = 0;

    do {
      const val = this.rhs.getSubValueFromList(cur);
      if (val >= lhsmin && val <= lhsmax) {
        if (count === 0) {
          this.resultpattern = buildPattern(this.lhs, val, semval, cur);
        } else {
          this.resultpattern = this.resultpattern.doOr(buildPattern(this.lhs, val, semval, cur));
        }
        count += 1;
      }
    } while (advance_combo(cur, min, max));

    if (count === 0) {
      throw new SleighError('Equal constraint is impossible to match');
    }
  }
}

// ---------------------------------------------------------------------------
// NotEqualEquation
// ---------------------------------------------------------------------------

export class NotEqualEquation extends ValExpressEquation {
  constructor(l: PatternValue, r: PatternExpression) {
    super(l, r);
  }

  override genPattern(ops: TokenPattern[]): void {
    const lhsmin = this.lhs.minValue();
    const lhsmax = this.lhs.maxValue();
    const semval: PatternValue[] = [];
    const min: bigint[] = [];
    const max: bigint[] = [];
    this.rhs.listValues(semval);
    this.rhs.getMinMax(min, max);
    const cur = [...min];
    let count = 0;

    do {
      const val = this.rhs.getSubValueFromList(cur);
      for (let lhsval = lhsmin; lhsval <= lhsmax; lhsval += 1n) {
        if (lhsval === val) continue;
        if (count === 0) {
          this.resultpattern = buildPattern(this.lhs, lhsval, semval, cur);
        } else {
          this.resultpattern = this.resultpattern.doOr(buildPattern(this.lhs, lhsval, semval, cur));
        }
        count += 1;
      }
    } while (advance_combo(cur, min, max));

    if (count === 0) {
      throw new SleighError('Notequal constraint is impossible to match');
    }
  }
}

// ---------------------------------------------------------------------------
// LessEquation
// ---------------------------------------------------------------------------

export class LessEquation extends ValExpressEquation {
  constructor(l: PatternValue, r: PatternExpression) {
    super(l, r);
  }

  override genPattern(ops: TokenPattern[]): void {
    const lhsmin = this.lhs.minValue();
    const lhsmax = this.lhs.maxValue();
    const semval: PatternValue[] = [];
    const min: bigint[] = [];
    const max: bigint[] = [];
    this.rhs.listValues(semval);
    this.rhs.getMinMax(min, max);
    const cur = [...min];
    let count = 0;

    do {
      const val = this.rhs.getSubValueFromList(cur);
      for (let lhsval = lhsmin; lhsval <= lhsmax; lhsval += 1n) {
        if (lhsval >= val) continue;
        if (count === 0) {
          this.resultpattern = buildPattern(this.lhs, lhsval, semval, cur);
        } else {
          this.resultpattern = this.resultpattern.doOr(buildPattern(this.lhs, lhsval, semval, cur));
        }
        count += 1;
      }
    } while (advance_combo(cur, min, max));

    if (count === 0) {
      throw new SleighError('Less than constraint is impossible to match');
    }
  }
}

// ---------------------------------------------------------------------------
// LessEqualEquation
// ---------------------------------------------------------------------------

export class LessEqualEquation extends ValExpressEquation {
  constructor(l: PatternValue, r: PatternExpression) {
    super(l, r);
  }

  override genPattern(ops: TokenPattern[]): void {
    const lhsmin = this.lhs.minValue();
    const lhsmax = this.lhs.maxValue();
    const semval: PatternValue[] = [];
    const min: bigint[] = [];
    const max: bigint[] = [];
    this.rhs.listValues(semval);
    this.rhs.getMinMax(min, max);
    const cur = [...min];
    let count = 0;

    do {
      const val = this.rhs.getSubValueFromList(cur);
      for (let lhsval = lhsmin; lhsval <= lhsmax; lhsval += 1n) {
        if (lhsval > val) continue;
        if (count === 0) {
          this.resultpattern = buildPattern(this.lhs, lhsval, semval, cur);
        } else {
          this.resultpattern = this.resultpattern.doOr(buildPattern(this.lhs, lhsval, semval, cur));
        }
        count += 1;
      }
    } while (advance_combo(cur, min, max));

    if (count === 0) {
      throw new SleighError('Less than or equal constraint is impossible to match');
    }
  }
}

// ---------------------------------------------------------------------------
// GreaterEquation
// ---------------------------------------------------------------------------

export class GreaterEquation extends ValExpressEquation {
  constructor(l: PatternValue, r: PatternExpression) {
    super(l, r);
  }

  override genPattern(ops: TokenPattern[]): void {
    const lhsmin = this.lhs.minValue();
    const lhsmax = this.lhs.maxValue();
    const semval: PatternValue[] = [];
    const min: bigint[] = [];
    const max: bigint[] = [];
    this.rhs.listValues(semval);
    this.rhs.getMinMax(min, max);
    const cur = [...min];
    let count = 0;

    do {
      const val = this.rhs.getSubValueFromList(cur);
      for (let lhsval = lhsmin; lhsval <= lhsmax; lhsval += 1n) {
        if (lhsval <= val) continue;
        if (count === 0) {
          this.resultpattern = buildPattern(this.lhs, lhsval, semval, cur);
        } else {
          this.resultpattern = this.resultpattern.doOr(buildPattern(this.lhs, lhsval, semval, cur));
        }
        count += 1;
      }
    } while (advance_combo(cur, min, max));

    if (count === 0) {
      throw new SleighError('Greater than constraint is impossible to match');
    }
  }
}

// ---------------------------------------------------------------------------
// GreaterEqualEquation
// ---------------------------------------------------------------------------

export class GreaterEqualEquation extends ValExpressEquation {
  constructor(l: PatternValue, r: PatternExpression) {
    super(l, r);
  }

  override genPattern(ops: TokenPattern[]): void {
    const lhsmin = this.lhs.minValue();
    const lhsmax = this.lhs.maxValue();
    const semval: PatternValue[] = [];
    const min: bigint[] = [];
    const max: bigint[] = [];
    this.rhs.listValues(semval);
    this.rhs.getMinMax(min, max);
    const cur = [...min];
    let count = 0;

    do {
      const val = this.rhs.getSubValueFromList(cur);
      for (let lhsval = lhsmin; lhsval <= lhsmax; lhsval += 1n) {
        if (lhsval < val) continue;
        if (count === 0) {
          this.resultpattern = buildPattern(this.lhs, lhsval, semval, cur);
        } else {
          this.resultpattern = this.resultpattern.doOr(buildPattern(this.lhs, lhsval, semval, cur));
        }
        count += 1;
      }
    } while (advance_combo(cur, min, max));

    if (count === 0) {
      throw new SleighError('Greater than or equal constraint is impossible to match');
    }
  }
}

// ---------------------------------------------------------------------------
// EquationAnd
// ---------------------------------------------------------------------------

/**
 * Pattern equations ANDed together.
 */
export class EquationAnd extends PatternEquation {
  private left: PatternEquation;
  private right: PatternEquation;

  constructor(l: PatternEquation, r: PatternEquation) {
    super();
    this.left = l;
    l.layClaim();
    this.right = r;
    r.layClaim();
  }

  genPattern(ops: TokenPattern[]): void {
    this.left.genPattern(ops);
    this.right.genPattern(ops);
    this.resultpattern = this.left.getTokenPattern().doAnd(this.right.getTokenPattern());
  }

  resolveOperandLeft(state: OperandResolve): boolean {
    let cur_rightmost = -1;
    let cur_size = -1;
    let res = this.right.resolveOperandLeft(state);
    if (!res) return false;
    if (state.cur_rightmost !== -1 && state.size !== -1) {
      cur_rightmost = state.cur_rightmost;
      cur_size = state.size;
    }
    res = this.left.resolveOperandLeft(state);
    if (!res) return false;
    if (state.cur_rightmost === -1 || state.size === -1) {
      state.cur_rightmost = cur_rightmost;
      state.size = cur_size;
    }
    return true;
  }

  override operandOrder(ct: Constructor, order: OperandSymbol[]): void {
    this.left.operandOrder(ct, order);
    this.right.operandOrder(ct, order);
  }
}

// ---------------------------------------------------------------------------
// EquationOr
// ---------------------------------------------------------------------------

/**
 * Pattern equations ORed together.
 */
export class EquationOr extends PatternEquation {
  private left: PatternEquation;
  private right: PatternEquation;

  constructor(l: PatternEquation, r: PatternEquation) {
    super();
    this.left = l;
    l.layClaim();
    this.right = r;
    r.layClaim();
  }

  genPattern(ops: TokenPattern[]): void {
    this.left.genPattern(ops);
    this.right.genPattern(ops);
    this.resultpattern = this.left.getTokenPattern().doOr(this.right.getTokenPattern());
  }

  resolveOperandLeft(state: OperandResolve): boolean {
    let cur_rightmost = -1;
    let cur_size = -1;
    let res = this.right.resolveOperandLeft(state);
    if (!res) return false;
    if (state.cur_rightmost !== -1 && state.size !== -1) {
      cur_rightmost = state.cur_rightmost;
      cur_size = state.size;
    }
    res = this.left.resolveOperandLeft(state);
    if (!res) return false;
    if (state.cur_rightmost === -1 || state.size === -1) {
      state.cur_rightmost = cur_rightmost;
      state.size = cur_size;
    }
    return true;
  }

  override operandOrder(ct: Constructor, order: OperandSymbol[]): void {
    this.left.operandOrder(ct, order);
    this.right.operandOrder(ct, order);
  }
}

// ---------------------------------------------------------------------------
// EquationCat
// ---------------------------------------------------------------------------

/**
 * Pattern equations concatenated.
 */
export class EquationCat extends PatternEquation {
  private left: PatternEquation;
  private right: PatternEquation;

  constructor(l: PatternEquation, r: PatternEquation) {
    super();
    this.left = l;
    l.layClaim();
    this.right = r;
    r.layClaim();
  }

  genPattern(ops: TokenPattern[]): void {
    this.left.genPattern(ops);
    this.right.genPattern(ops);
    this.resultpattern = this.left.getTokenPattern().doCat(this.right.getTokenPattern());
  }

  resolveOperandLeft(state: OperandResolve): boolean {
    let res = this.left.resolveOperandLeft(state);
    if (!res) return false;
    const cur_base = state.base;
    const cur_offset = state.offset;
    if (!this.left.getTokenPattern().getLeftEllipsis() && !this.left.getTokenPattern().getRightEllipsis()) {
      state.offset += this.left.getTokenPattern().getMinimumLength();
    } else if (state.cur_rightmost !== -1) {
      state.base = state.cur_rightmost;
      state.offset = state.size;
    } else if (state.size !== -1) {
      state.offset += state.size;
    } else {
      state.base = -2; // We have no anchor
    }
    const cur_rightmost = state.cur_rightmost;
    const cur_size = state.size;
    res = this.right.resolveOperandLeft(state);
    if (!res) return false;
    state.base = cur_base;
    state.offset = cur_offset;
    if (state.cur_rightmost === -1) {
      if (state.size !== -1 && cur_rightmost !== -1 && cur_size !== -1) {
        state.cur_rightmost = cur_rightmost;
        state.size += cur_size;
      }
    }
    return true;
  }

  override operandOrder(ct: Constructor, order: OperandSymbol[]): void {
    this.left.operandOrder(ct, order);
    this.right.operandOrder(ct, order);
  }
}

// ---------------------------------------------------------------------------
// EquationLeftEllipsis
// ---------------------------------------------------------------------------

/**
 * An equation preceded by ellipses.
 */
export class EquationLeftEllipsis extends PatternEquation {
  private eq: PatternEquation;

  constructor(e: PatternEquation) {
    super();
    this.eq = e;
    e.layClaim();
  }

  genPattern(ops: TokenPattern[]): void {
    this.eq.genPattern(ops);
    this.resultpattern = this.eq.getTokenPattern();
    this.resultpattern.setLeftEllipsis(true);
  }

  resolveOperandLeft(state: OperandResolve): boolean {
    const cur_base = state.base;
    state.base = -2;
    const res = this.eq.resolveOperandLeft(state);
    if (!res) return false;
    state.base = cur_base;
    return true;
  }

  override operandOrder(ct: Constructor, order: OperandSymbol[]): void {
    this.eq.operandOrder(ct, order);
  }
}

// ---------------------------------------------------------------------------
// EquationRightEllipsis
// ---------------------------------------------------------------------------

/**
 * An equation followed by ellipses.
 */
export class EquationRightEllipsis extends PatternEquation {
  private eq: PatternEquation;

  constructor(e: PatternEquation) {
    super();
    this.eq = e;
    e.layClaim();
  }

  genPattern(ops: TokenPattern[]): void {
    this.eq.genPattern(ops);
    this.resultpattern = this.eq.getTokenPattern();
    this.resultpattern.setRightEllipsis(true);
  }

  resolveOperandLeft(state: OperandResolve): boolean {
    const res = this.eq.resolveOperandLeft(state);
    if (!res) return false;
    state.size = -1; // Cannot predict size
    return true;
  }

  override operandOrder(ct: Constructor, order: OperandSymbol[]): void {
    this.eq.operandOrder(ct, order);
  }
}

// ---------------------------------------------------------------------------
// Late-binding pattern class references
// ---------------------------------------------------------------------------
// These are forward-declared types from slghpattern.ts which is not yet written.
// We use class stubs that get resolved at runtime via the setPatternClasses function.

let PatternBlockClass: any = null;
let InstructionPatternClass: any = null;
let ContextPatternClass: any = null;

/**
 * Register the actual pattern classes for use by TokenPattern.
 * This must be called before TokenPattern can be instantiated with pattern constructors.
 *
 * @param pb - The PatternBlock class
 * @param ip - The InstructionPattern class
 * @param cp - The ContextPattern class
 */
export function setPatternClasses(pb: any, ip: any, cp: any): void {
  PatternBlockClass = pb;
  InstructionPatternClass = ip;
  ContextPatternClass = cp;
}
