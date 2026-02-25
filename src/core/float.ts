/**
 * @file float.ts
 * @description Support for decoding different floating-point formats.
 *
 * Translated from Ghidra's float.hh / float.cc.
 * All values are encoded as bigint (uintb) and operations convert to/from
 * JavaScript's native double for computation.
 */

import { type int4, type uintb, type intb, uintbMask } from './types.js';

// ---------------------------------------------------------------------------
// Helper: DataView buffer used for bit-level float/double conversions
// ---------------------------------------------------------------------------

const _convBuf = new ArrayBuffer(8);
const _convView = new DataView(_convBuf);

// ---------------------------------------------------------------------------
// FloatClass enum
// ---------------------------------------------------------------------------

/** The various classes of floating-point encodings */
export enum FloatClass {
  normalized = 0,
  infinity = 1,
  zero = 2,
  nan = 3,
  denormalized = 4,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Equivalent of C++ `8 * sizeof(uintb)`.  uintb is a 64-bit type.
 */
const UINTB_BITS = 64;

/** Mask that keeps only the low 64 bits of a bigint. */
const UINTB_MASK = 0xFFFF_FFFF_FFFF_FFFFn;

/**
 * Sign-extend a bigint value from the given bit position.
 * Equivalent to the C++ inline `sign_extend(intb val, int4 bit)`.
 *
 * @param val  the value to sign-extend
 * @param bit  the index of the sign bit (0 = least significant)
 */
function signExtendBit(val: bigint, bit: int4): bigint {
  const sa = UINTB_BITS - (bit + 1);
  // Perform the shifts as signed 64-bit arithmetic.
  // Left-shift, then arithmetic right-shift to propagate the sign.
  val = (val << BigInt(sa)) & UINTB_MASK;
  // Treat as signed for right-shift: convert to signed 64-bit
  if (val & (1n << 63n)) {
    // Value is negative in 64-bit two's complement
    val = val | ~UINTB_MASK; // sign-extend to arbitrary precision
  }
  val = val >> BigInt(sa);
  return val;
}

/**
 * Count leading zeros of a 64-bit bigint value.
 */
function countLeadingZeros(val: bigint): int4 {
  val = val & UINTB_MASK;
  if (val === 0n) return UINTB_BITS;

  let bit = 0;
  let maskSize = 32;
  let mask = UINTB_MASK & (UINTB_MASK << BigInt(maskSize));

  do {
    if ((mask & val) === 0n) {
      bit += maskSize;
      maskSize >>= 1;
      mask |= (mask >> BigInt(maskSize));
    } else {
      maskSize >>= 1;
      mask &= (mask << BigInt(maskSize));
    }
  } while (maskSize > 0);

  return bit;
}

/**
 * Convert a JavaScript number (double) to its IEEE 754 64-bit representation as a bigint.
 */
function doubleToRawBits(x: number): bigint {
  _convView.setFloat64(0, x, false); // big-endian
  const hi = _convView.getUint32(0, false);
  const lo = _convView.getUint32(4, false);
  return (BigInt(hi) << 32n) | BigInt(lo);
}

/**
 * Convert a 64-bit IEEE 754 representation (bigint) back to a JavaScript number (double).
 */
function doubleFromRawBits(bits: bigint): number {
  bits = bits & UINTB_MASK;
  _convView.setUint32(0, Number((bits >> 32n) & 0xFFFF_FFFFn), false);
  _convView.setUint32(4, Number(bits & 0xFFFF_FFFFn), false);
  return _convView.getFloat64(0, false);
}

/**
 * Equivalent of C ldexp: value * 2^exp
 */
function ldexp(value: number, exp: number): number {
  // Handle edge cases
  if (value === 0 || !isFinite(value)) return value;
  // Use repeated multiplication to avoid overflow in Math.pow for large exponents
  while (exp > 1023) {
    value *= 8.98846567431158e+307; // 2^1023
    exp -= 1023;
  }
  while (exp < -1022) {
    value *= 2.2250738585072014e-308; // 2^-1022
    exp += 1022;
  }
  return value * Math.pow(2, exp);
}

/**
 * Equivalent of C frexp: decompose x into [frac, exp] where x = frac * 2^exp
 * and 0.5 <= |frac| < 1.0 (or frac is 0 for x==0).
 */
function frexp(x: number): { frac: number; exp: number } {
  if (x === 0 || !isFinite(x)) {
    return { frac: x, exp: 0 };
  }
  const bits = doubleToRawBits(x);
  let expBits = Number((bits >> 52n) & 0x7FFn);
  const sign = (bits >> 63n) & 1n;

  if (expBits === 0) {
    // Subnormal: normalize by multiplying by 2^64
    const scaled = x * 18446744073709551616; // 2^64
    const result = frexp(scaled);
    return { frac: result.frac, exp: result.exp - 64 };
  }

  const exp = expBits - 1022; // actual exponent: (expBits - 1023) + 1
  // Set exponent to -1 (biased: 1022) to get frac in [0.5, 1.0)
  const fracBits = (sign << 63n) | (0x3FEn << 52n) | (bits & 0x000F_FFFF_FFFF_FFFFn);
  const frac = doubleFromRawBits(fracBits);
  return { frac, exp };
}

// ---------------------------------------------------------------------------
// FloatFormat class
// ---------------------------------------------------------------------------

/**
 * Encoding information for a single floating-point format.
 *
 * This class supports manipulation of a single floating-point encoding.
 * An encoding can be converted to and from the host format and convenience
 * methods allow p-code floating-point operations to be performed on natively
 * encoded operands.  This follows the IEEE 754 standards.
 */
export class FloatFormat {
  private size: int4;
  private signbit_pos: int4;
  private frac_pos: int4;
  private frac_size: int4;
  private exp_pos: int4;
  private exp_size: int4;
  private bias: int4;
  private maxexponent: int4;
  private decimalMinPrecision: int4;
  private decimalMaxPrecision: int4;
  private jbitimplied: boolean;

  // -----------------------------------------------------------------------
  // Static private helpers
  // -----------------------------------------------------------------------

  /**
   * Create a double given sign, fractional (significand), and exponent.
   *
   * The significand is in the upper bits of a 64-bit bigint.
   */
  private static createFloat(sign: boolean, signif: uintb, exp: int4): number {
    signif = (signif >> 1n) & UINTB_MASK; // Throw away 1 bit of precision
    const precis = UINTB_BITS - 1; // 63
    let res = Number(signif);
    const expchange = exp - precis + 1;
    res = ldexp(res, expchange);
    if (sign) {
      res = res * -1.0;
    }
    return res;
  }

  /**
   * Extract the sign, fractional, and exponent from a given floating-point value.
   */
  private static extractExpSig(
    x: number,
  ): { type: FloatClass; sgn: boolean; signif: uintb; exp: int4 } {
    // Use the raw bit representation to detect sign, matching C++ std::signbit behavior.
    // This correctly detects the sign of -0, -Infinity, and -NaN.
    const rawBits = doubleToRawBits(x);
    const sgn = (rawBits & (1n << 63n)) !== 0n;
    if (x === 0.0) return { type: FloatClass.zero, sgn, signif: 0n, exp: 0 };
    if (isNaN(x)) return { type: FloatClass.nan, sgn, signif: 0n, exp: 0 };
    if (!isFinite(x)) return { type: FloatClass.infinity, sgn, signif: 0n, exp: 0 };
    if (sgn) x = -x;

    const { frac: norm0, exp: e0 } = frexp(x); // norm is between 1/2 and 1
    // norm between 2^62 and 2^63
    const norm = ldexp(norm0, UINTB_BITS - 1); // 63

    let signif: uintb = BigInt(Math.floor(norm)) & UINTB_MASK;
    signif = (signif << 1n) & UINTB_MASK;

    const exp = e0 - 1; // Consider normalization between 1 and 2
    return { type: FloatClass.normalized, sgn, signif, exp };
  }

  /**
   * Round a floating-point significand to the nearest even.
   *
   * Returns a tuple of [newSignif, didRoundUp].
   */
  private static roundToNearestEven(signif: uintb, lowbitpos: int4): { signif: uintb; rounded: boolean } {
    const lowbitmask = (lowbitpos < UINTB_BITS) ? (1n << BigInt(lowbitpos)) : 0n;
    const midbitmask = 1n << BigInt(lowbitpos - 1);
    const epsmask = (midbitmask - 1n) & UINTB_MASK;
    const odd = (signif & lowbitmask) !== 0n;
    if ((signif & midbitmask) !== 0n && ((signif & epsmask) !== 0n || odd)) {
      signif = (signif + midbitmask) & UINTB_MASK;
      return { signif, rounded: true };
    }
    return { signif, rounded: false };
  }

  // -----------------------------------------------------------------------
  // Private instance helpers
  // -----------------------------------------------------------------------

  /** Set the fractional part of an encoded value */
  private setFractionalCode(x: uintb, code: uintb): uintb {
    // Align with bottom of word, also drops bits of precision we don't have room for
    code = (code >> BigInt(UINTB_BITS - this.frac_size)) & UINTB_MASK;
    code = (code << BigInt(this.frac_pos)) & UINTB_MASK;
    x = (x | code) & UINTB_MASK;
    return x;
  }

  /** Set the sign bit of an encoded value */
  private setSign(x: uintb, sign: boolean): uintb {
    if (!sign) return x;
    const mask = 1n << BigInt(this.signbit_pos);
    x = (x | mask) & UINTB_MASK;
    return x;
  }

  /** Set the exponent of an encoded value */
  private setExponentCode(x: uintb, code: uintb): uintb {
    code = (code << BigInt(this.exp_pos)) & UINTB_MASK;
    x = (x | code) & UINTB_MASK;
    return x;
  }

  /** Get an encoded zero value */
  private getZeroEncoding(sgn: boolean): uintb {
    let res = 0n;
    res = this.setFractionalCode(res, 0n);
    res = this.setExponentCode(res, 0n);
    return this.setSign(res, sgn);
  }

  /** Get an encoded infinite value */
  private getInfinityEncoding(sgn: boolean): uintb {
    let res = 0n;
    res = this.setFractionalCode(res, 0n);
    res = this.setExponentCode(res, BigInt(this.maxexponent));
    return this.setSign(res, sgn);
  }

  /** Get an encoded NaN value */
  private getNaNEncoding(sgn: boolean): uintb {
    let res = 0n;
    const mask = 1n << BigInt(UINTB_BITS - 1); // Create "quiet" NaN
    res = this.setFractionalCode(res, mask);
    res = this.setExponentCode(res, BigInt(this.maxexponent));
    return this.setSign(res, sgn);
  }

  /** Calculate the decimal precision of this format */
  private calcPrecision(): void {
    this.decimalMinPrecision = Math.floor(this.frac_size * 0.30103);
    // Precision needed to guarantee IEEE 754 binary -> decimal -> binary round trip conversion
    this.decimalMaxPrecision = Math.ceil((this.frac_size + 1) * 0.30103) + 1;
  }

  // -----------------------------------------------------------------------
  // Constructor
  // -----------------------------------------------------------------------

  /**
   * Construct default IEEE 754 standard settings for a given encoding size.
   *
   * @param sz  the size of the encoding in bytes (4 for float, 8 for double)
   */
  constructor(sz: int4) {
    this.size = sz;
    // Initialize all fields with defaults that will be overwritten
    this.signbit_pos = 0;
    this.exp_pos = 0;
    this.exp_size = 0;
    this.frac_pos = 0;
    this.frac_size = 0;
    this.bias = 0;
    this.jbitimplied = true;
    this.maxexponent = 0;
    this.decimalMinPrecision = 0;
    this.decimalMaxPrecision = 0;

    if (sz === 4) {
      this.signbit_pos = 31;
      this.exp_pos = 23;
      this.exp_size = 8;
      this.frac_pos = 0;
      this.frac_size = 23;
      this.bias = 127;
      this.jbitimplied = true;
    } else if (sz === 8) {
      this.signbit_pos = 63;
      this.exp_pos = 52;
      this.exp_size = 11;
      this.frac_pos = 0;
      this.frac_size = 52;
      this.bias = 1023;
      this.jbitimplied = true;
    }

    this.maxexponent = (1 << this.exp_size) - 1;
    this.calcPrecision();
  }

  // -----------------------------------------------------------------------
  // Public accessors
  // -----------------------------------------------------------------------

  /** Get the size of the encoding in bytes */
  getSize(): int4 {
    return this.size;
  }

  // -----------------------------------------------------------------------
  // Extract helpers (public)
  // -----------------------------------------------------------------------

  /** Extract the fractional part of the encoding, aligned to the top of the word */
  extractFractionalCode(x: uintb): uintb {
    x = (x >> BigInt(this.frac_pos)) & UINTB_MASK;
    x = (x << BigInt(UINTB_BITS - this.frac_size)) & UINTB_MASK;
    return x;
  }

  /** Extract the sign bit from the encoding */
  extractSign(x: uintb): boolean {
    x = (x >> BigInt(this.signbit_pos)) & UINTB_MASK;
    return (x & 1n) !== 0n;
  }

  /** Extract the exponent from the encoding */
  extractExponentCode(x: uintb): int4 {
    x = (x >> BigInt(this.exp_pos)) & UINTB_MASK;
    let mask = 1n;
    mask = (mask << BigInt(this.exp_size)) - 1n;
    return Number(x & mask);
  }

  // -----------------------------------------------------------------------
  // Conversion methods
  // -----------------------------------------------------------------------

  /**
   * Convert an encoding into host's double.
   *
   * @param encoding  the encoded floating-point value
   * @returns an object with the double value and its FloatClass
   */
  getHostFloat(encoding: uintb): { value: number; type: FloatClass } {
    const sgn = this.extractSign(encoding);
    let frac = this.extractFractionalCode(encoding);
    const exp = this.extractExponentCode(encoding);
    let normal = true;

    if (exp === 0) {
      if (frac === 0n) {
        // Floating-point zero
        return { value: sgn ? -0.0 : +0.0, type: FloatClass.zero };
      }
      // Number is denormalized
      normal = false;
    } else if (exp === this.maxexponent) {
      if (frac === 0n) {
        // Floating-point infinity
        return { value: sgn ? -Infinity : Infinity, type: FloatClass.infinity };
      }
      // Not a Number
      return { value: sgn ? -NaN : NaN, type: FloatClass.nan };
    }

    const type = normal ? FloatClass.normalized : FloatClass.denormalized;

    // Get "true" exponent and fractional
    let trueExp = exp - this.bias;
    if (normal && this.jbitimplied) {
      frac = (frac >> 1n) & UINTB_MASK; // Make room for 1 jbit
      const highbit = 1n << BigInt(UINTB_BITS - 1);
      frac = (frac | highbit) & UINTB_MASK; // Stick bit in at top
    }
    return { value: FloatFormat.createFloat(sgn, frac, trueExp), type };
  }

  /**
   * Convert host's double into this encoding.
   *
   * @param host  the double value to convert
   * @returns the equivalent encoded value
   */
  getEncoding(host: number): uintb {
    const { type, sgn, signif: origSignif, exp: origExp } = FloatFormat.extractExpSig(host);

    if (type === FloatClass.zero)
      return this.getZeroEncoding(sgn);
    if (type === FloatClass.infinity)
      return this.getInfinityEncoding(sgn);
    if (type === FloatClass.nan)
      return this.getNaNEncoding(sgn);

    let signif = origSignif;
    let exp = origExp + this.bias;

    if (exp < -this.frac_size) {
      // Exponent is too small to represent
      return this.getZeroEncoding(sgn);
    }

    if (exp < 1) {
      // Must be denormalized
      const rtn = FloatFormat.roundToNearestEven(signif, UINTB_BITS - this.frac_size - exp);
      signif = rtn.signif;
      if (rtn.rounded) {
        if (((signif >> BigInt(UINTB_BITS - 1)) & 1n) === 0n) {
          signif = 1n << BigInt(UINTB_BITS - 1);
          exp += 1;
        }
      }
      let res = this.getZeroEncoding(sgn);
      return this.setFractionalCode(res, (signif >> BigInt(-exp)) & UINTB_MASK);
    }

    {
      const rtn = FloatFormat.roundToNearestEven(signif, UINTB_BITS - this.frac_size - 1);
      signif = rtn.signif;
      if (rtn.rounded) {
        if (((signif >> BigInt(UINTB_BITS - 1)) & 1n) === 0n) {
          signif = 1n << BigInt(UINTB_BITS - 1);
          exp += 1;
        }
      }
    }

    if (exp >= this.maxexponent) {
      // Exponent is too big to represent
      return this.getInfinityEncoding(sgn);
    }

    if (this.jbitimplied && exp !== 0) {
      signif = (signif << 1n) & UINTB_MASK; // Cut off top bit (which should be 1)
    }

    let res = 0n;
    res = this.setFractionalCode(res, signif);
    res = this.setExponentCode(res, BigInt(exp));
    return this.setSign(res, sgn);
  }

  /**
   * Convert between two different formats.
   *
   * @param encoding  the value in the other FloatFormat
   * @param formin    the other FloatFormat
   * @returns the equivalent value in this FloatFormat
   */
  convertEncoding(encoding: uintb, formin: FloatFormat): uintb {
    const sgn = formin.extractSign(encoding);
    let signif = formin.extractFractionalCode(encoding);
    let exp = formin.extractExponentCode(encoding);

    if (exp === formin.maxexponent) {
      // NaN or INFINITY encoding
      if (signif !== 0n) {
        return this.getNaNEncoding(sgn);
      } else {
        return this.getInfinityEncoding(sgn);
      }
    }

    if (exp === 0) {
      // incoming is subnormal
      if (signif === 0n) {
        return this.getZeroEncoding(sgn);
      }
      // normalize
      const lz = countLeadingZeros(signif);
      signif = (signif << BigInt(lz)) & UINTB_MASK;
      exp = -formin.bias - lz;
    } else {
      // incoming is normal
      exp -= formin.bias;
      if (this.jbitimplied) {
        signif = ((1n << BigInt(UINTB_BITS - 1)) | ((signif >> 1n) & UINTB_MASK)) & UINTB_MASK;
      }
    }

    exp += this.bias;

    if (exp < -this.frac_size) {
      // Exponent is too small to represent
      return this.getZeroEncoding(sgn);
    }

    if (exp < 1) {
      // Must be denormalized
      const rtn = FloatFormat.roundToNearestEven(signif, UINTB_BITS - this.frac_size - exp);
      signif = rtn.signif;
      if (rtn.rounded) {
        if (((signif >> BigInt(UINTB_BITS - 1)) & 1n) === 0n) {
          signif = 1n << BigInt(UINTB_BITS - 1);
          exp += 1;
        }
      }
      let res = this.getZeroEncoding(sgn);
      return this.setFractionalCode(res, (signif >> BigInt(-exp)) & UINTB_MASK);
    }

    {
      const rtn = FloatFormat.roundToNearestEven(signif, UINTB_BITS - this.frac_size - 1);
      signif = rtn.signif;
      if (rtn.rounded) {
        if (((signif >> BigInt(UINTB_BITS - 1)) & 1n) === 0n) {
          signif = 1n << BigInt(UINTB_BITS - 1);
          exp += 1;
        }
      }
    }

    if (exp >= this.maxexponent) {
      // Exponent is too big to represent
      return this.getInfinityEncoding(sgn);
    }

    if (this.jbitimplied && exp !== 0) {
      signif = (signif << 1n) & UINTB_MASK; // Cut off top bit (which should be 1)
    }

    let res = 0n;
    res = this.setFractionalCode(res, signif);
    res = this.setExponentCode(res, BigInt(exp));
    return this.setSign(res, sgn);
  }

  // -----------------------------------------------------------------------
  // Float operations - all take/return encoded values
  // -----------------------------------------------------------------------

  /** Equality comparison (==) */
  opEqual(a: uintb, b: uintb): uintb {
    const { value: val1 } = this.getHostFloat(a);
    const { value: val2 } = this.getHostFloat(b);
    return (val1 === val2) ? 1n : 0n;
  }

  /** Inequality comparison (!=) */
  opNotEqual(a: uintb, b: uintb): uintb {
    const { value: val1 } = this.getHostFloat(a);
    const { value: val2 } = this.getHostFloat(b);
    return (val1 !== val2) ? 1n : 0n;
  }

  /** Less-than comparison (<) */
  opLess(a: uintb, b: uintb): uintb {
    const { value: val1 } = this.getHostFloat(a);
    const { value: val2 } = this.getHostFloat(b);
    return (val1 < val2) ? 1n : 0n;
  }

  /** Less-than-or-equal comparison (<=) */
  opLessEqual(a: uintb, b: uintb): uintb {
    const { value: val1 } = this.getHostFloat(a);
    const { value: val2 } = this.getHostFloat(b);
    return (val1 <= val2) ? 1n : 0n;
  }

  /** Test if Not-a-Number (NaN) */
  opNan(a: uintb): uintb {
    const { type } = this.getHostFloat(a);
    return (type === FloatClass.nan) ? 1n : 0n;
  }

  /**
   * Force newly-created NaN results to negative NaN (matching x86/ARM hardware behavior).
   * When a non-NaN operation produces NaN (e.g., 0/0, Inf-Inf), x86/ARM hardware sets
   * the sign bit, producing 0xFFC00000. JavaScript canonicalizes NaN to positive
   * (0x7FC00000). We match the hardware behavior to stay consistent with the C++ decompiler.
   *
   * If either input was already NaN, the result is left unchanged (NaN propagation
   * preserves the input NaN's sign on hardware).
   */
  private forceNegativeNaN(result: uintb, val1: number, val2: number): uintb {
    if (isNaN(val1) || isNaN(val2)) return result; // Input was already NaN, don't modify
    // Check if result is NaN by examining the encoding
    const expCode = this.extractExponentCode(result);
    const fracCode = this.extractFractionalCode(result);
    if (expCode === this.maxexponent && fracCode !== 0n) {
      // Result is NaN - force sign bit on (negative NaN)
      result = result | (1n << BigInt(this.signbit_pos));
    }
    return result;
  }

  /** Addition (+) */
  opAdd(a: uintb, b: uintb): uintb {
    const { value: val1 } = this.getHostFloat(a);
    const { value: val2 } = this.getHostFloat(b);
    return this.forceNegativeNaN(this.getEncoding(val1 + val2), val1, val2);
  }

  /** Division (/) */
  opDiv(a: uintb, b: uintb): uintb {
    const { value: val1 } = this.getHostFloat(a);
    const { value: val2 } = this.getHostFloat(b);
    return this.forceNegativeNaN(this.getEncoding(val1 / val2), val1, val2);
  }

  /** Multiplication (*) */
  opMult(a: uintb, b: uintb): uintb {
    const { value: val1 } = this.getHostFloat(a);
    const { value: val2 } = this.getHostFloat(b);
    return this.forceNegativeNaN(this.getEncoding(val1 * val2), val1, val2);
  }

  /** Subtraction (-) */
  opSub(a: uintb, b: uintb): uintb {
    const { value: val1 } = this.getHostFloat(a);
    const { value: val2 } = this.getHostFloat(b);
    return this.forceNegativeNaN(this.getEncoding(val1 - val2), val1, val2);
  }

  /** Unary negate */
  opNeg(a: uintb): uintb {
    const { value: val } = this.getHostFloat(a);
    return this.getEncoding(-val);
  }

  /** Absolute value (abs) */
  opAbs(a: uintb): uintb {
    const { value: val } = this.getHostFloat(a);
    return this.getEncoding(Math.abs(val));
  }

  /** Square root (sqrt) */
  opSqrt(a: uintb): uintb {
    const { value: val } = this.getHostFloat(a);
    return this.getEncoding(Math.sqrt(val));
  }

  /**
   * Convert floating-point to integer (truncation toward zero).
   *
   * @param a        the encoded floating-point value
   * @param sizeout  the desired byte size of the output integer
   * @returns an integer encoding
   */
  opTrunc(a: uintb, sizeout: int4): uintb {
    const { value: val } = this.getHostFloat(a);
    let ival: bigint = BigInt(Math.trunc(val)); // Convert to integer (truncate toward zero)
    let res = ival & UINTB_MASK; // Convert to unsigned
    res = res & uintbMask(sizeout); // Truncate to proper size
    return res;
  }

  /** Ceiling (ceil) */
  opCeil(a: uintb): uintb {
    const { value: val } = this.getHostFloat(a);
    return this.getEncoding(Math.ceil(val));
  }

  /** Floor (floor) */
  opFloor(a: uintb): uintb {
    const { value: val } = this.getHostFloat(a);
    return this.getEncoding(Math.floor(val));
  }

  /** Round (round half away from zero) */
  opRound(a: uintb): uintb {
    const { value: val } = this.getHostFloat(a);
    return this.getEncoding(Math.round(val));
  }

  /**
   * Convert a signed integer to a floating-point encoding.
   *
   * @param a       the integer value (stored as uintb)
   * @param sizein  the number of bytes in the integer encoding
   * @returns the encoded floating-point value
   */
  opInt2Float(a: uintb, sizein: int4): uintb {
    // Sign-extend from bit position (8*sizein - 1)
    const ival = signExtendBit(a, 8 * sizein - 1);
    const val = Number(ival); // Convert integer to float
    return this.getEncoding(val);
  }

  /**
   * Convert between floating-point precisions.
   *
   * @param a          the encoded floating-point value in this format
   * @param outformat  the desired output FloatFormat
   * @returns the value encoded in the output format
   */
  opFloat2Float(a: uintb, outformat: FloatFormat): uintb {
    return outformat.convertEncoding(a, this);
  }

  // -----------------------------------------------------------------------
  // Decimal printing
  // -----------------------------------------------------------------------

  /**
   * Print a given value as a decimal string.
   *
   * The string is printed with the minimum number of digits to uniquely specify
   * the underlying binary value.  If forcesci is true, scientific notation is
   * always used.
   *
   * @param host      the value already converted to the host's double format
   * @param forcesci  if true, always use scientific notation
   * @returns the decimal representation as a string
   */
  printDecimal(host: number, forcesci: boolean): string {
    let res = '';
    for (let prec = this.decimalMinPrecision; ; ++prec) {
      let s: string;
      if (forcesci) {
        // Scientific notation: precision count excludes the first digit
        s = host.toExponential(prec - 1);
      } else {
        // Default notation: use toPrecision for minimal representation.
        // This behaves like C++ "default" float formatting, choosing between
        // fixed and scientific notation depending on the magnitude.
        s = host.toPrecision(prec);
      }

      // Normalize the exponent format to match C++ output:
      // JavaScript uses e+1 or e-7, C++ uses e+01 or e-07 for single digit exponents
      s = s.replace(/e([+-])(\d)$/, 'e$1' + '0$2');

      if (prec === this.decimalMaxPrecision) {
        res = s;
        break;
      }

      res = s;

      // Perform round-trip check
      let roundtrip: number;
      if (this.size <= 4) {
        // For float: parse and round to single precision via Float32Array
        const parsed = parseFloat(res);
        const f32 = new Float32Array(1);
        f32[0] = parsed;
        roundtrip = f32[0];
      } else {
        roundtrip = parseFloat(res);
      }

      if (roundtrip === host) {
        break;
      }
    }
    // C++ defaultfloat uses scientific notation when exponent < -4 or exponent >= precision
    // JavaScript toPrecision uses it when exponent < -6 or exponent >= precision
    // Convert to scientific notation for the gap: -6 <= exponent < -4
    if (!forcesci && !res.includes('e') && !res.includes('E')) {
      const absVal = Math.abs(host);
      if (absVal !== 0 && absVal < 1e-4) {
        // Count significant digits in current representation
        const match = res.match(/^-?0*\.?0*/);
        const leadingNonSig = match ? match[0].length : 0;
        const sigPart = res.slice(leadingNonSig).replace(/\.$/, '');
        const sigDigits = sigPart.length;
        res = host.toExponential(Math.max(sigDigits - 1, 0));
        res = res.replace(/e([+-])(\d)$/, 'e$10$2');
      }
    }
    // Strip trailing zeros (matching C++ defaultfloat / %g behavior)
    // Only strip when not using forced scientific notation
    if (!forcesci && res.includes('.')) {
      if (res.includes('e') || res.includes('E')) {
        // Scientific notation: strip trailing zeros before 'e'
        res = res.replace(/\.?0+(e)/i, '$1');
      } else {
        // Fixed notation: strip trailing zeros after decimal
        res = res.replace(/(\.\d*?)0+$/, '$1');
        if (res.endsWith('.'))
          res += '0';
      }
    }
    return res;
  }
}
