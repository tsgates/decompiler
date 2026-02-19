/**
 * @file testfloatemu.test.ts
 * @description Unit tests for FloatFormat, ported from Ghidra's testfloatemu.cc.
 *
 * Exercises encoding/decoding, arithmetic, comparison, special values,
 * conversion operations, and round-trip encoding.
 */

import { describe, it, expect } from 'vitest';
import { FloatFormat, FloatClass } from '../../src/core/float.js';

// ---------------------------------------------------------------------------
// Utility functions -- mirrors the C++ helpers
// ---------------------------------------------------------------------------

const _convBuf = new ArrayBuffer(8);
const _convView = new DataView(_convBuf);

/** Convert a 32-bit IEEE 754 encoding (bigint) to a JavaScript number (double via float). */
function floatFromRawBits(e: bigint): number {
  _convView.setUint32(0, Number(e & 0xFFFFFFFFn), false);
  return _convView.getFloat32(0, false);
}

/** Convert a JavaScript number (double) to 32-bit IEEE 754 encoding (bigint), going through float32. */
function floatToRawBits(f: number): bigint {
  _convView.setFloat32(0, f, false);
  return BigInt(_convView.getUint32(0, false)) & 0xFFFFFFFFn;
}

/** Convert a 64-bit IEEE 754 encoding (bigint) to a JavaScript number (double). */
function doubleFromRawBits(e: bigint): number {
  _convView.setUint32(0, Number((e >> 32n) & 0xFFFFFFFFn), false);
  _convView.setUint32(4, Number(e & 0xFFFFFFFFn), false);
  return _convView.getFloat64(0, false);
}

/** Convert a JavaScript number (double) to 64-bit IEEE 754 encoding (bigint). */
function doubleToRawBits(f: number): bigint {
  _convView.setFloat64(0, f, false);
  const hi = _convView.getUint32(0, false);
  const lo = _convView.getUint32(4, false);
  return (BigInt(hi) << 32n) | BigInt(lo);
}

// ---------------------------------------------------------------------------
// IEEE 754 single-precision special constants
// ---------------------------------------------------------------------------

// std::numeric_limits<float>::denorm_min()  = 0x00000001 as float32
const FLOAT_DENORM_MIN = floatFromRawBits(0x00000001n);
// std::numeric_limits<float>::min()         = 0x00800000 as float32  (smallest normal)
const FLOAT_MIN = floatFromRawBits(0x00800000n);
// std::numeric_limits<float>::max()         = 0x7f7fffff as float32
const FLOAT_MAX = floatFromRawBits(0x7F7FFFFFn);
// std::numeric_limits<float>::quiet_NaN()
const FLOAT_QNAN = NaN;
// std::numeric_limits<float>::infinity()
const FLOAT_INF = Infinity;

// std::numeric_limits<double>::denorm_min()
const DOUBLE_DENORM_MIN = doubleFromRawBits(0x0000000000000001n);
// std::numeric_limits<double>::min()
const DOUBLE_MIN = doubleFromRawBits(0x0010000000000000n);
// std::numeric_limits<double>::max()
const DOUBLE_MAX = doubleFromRawBits(0x7FEFFFFFFFFFFFFFn);

// ---------------------------------------------------------------------------
// Test value arrays (mirrors the C++ static vectors)
// ---------------------------------------------------------------------------

/**
 * Float test values.  Since JavaScript only has doubles, we store the 32-bit
 * IEEE 754 encodings and convert to double via floatFromRawBits so the
 * FloatFormat(4) operations can round-trip correctly.
 *
 * The C++ test uses native float variables; here we use the double
 * representation of those exact float bit patterns.
 */
const float_test_values: number[] = [
  -0.0,
  +0.0,
  -1.0,
  +1.0,

  floatFromRawBits(floatToRawBits(-1.234)),  // -1.234f
  floatFromRawBits(floatToRawBits(1.234)),   // +1.234f

  -FLOAT_DENORM_MIN,
  FLOAT_DENORM_MIN,

  // FLOAT_MIN - FLOAT_DENORM_MIN  (one step below smallest normal)
  floatFromRawBits(0x007FFFFFn),
  FLOAT_MIN,
  // FLOAT_MIN + FLOAT_DENORM_MIN  (one step above smallest normal)
  floatFromRawBits(0x00800001n),

  // -FLOAT_MIN + FLOAT_DENORM_MIN
  floatFromRawBits(0x807FFFFFn),
  -FLOAT_MIN,
  // -FLOAT_MIN - FLOAT_DENORM_MIN
  floatFromRawBits(0x80800001n),

  FLOAT_MAX,

  FLOAT_QNAN,

  -FLOAT_INF,
  FLOAT_INF,
];

const int_test_values: number[] = [
  0, -1, 1, 1234, -1234,
  -2147483648,   // std::numeric_limits<int>::min()  = -2^31
  2147483647,    // std::numeric_limits<int>::max()  = 2^31 - 1
];

// ---------------------------------------------------------------------------
// Helper: encode a float-precision value through FloatFormat(4)
//
// Since FloatFormat.getEncoding takes a JS double, but the C++ tests feed it
// a C float, we replicate the C++ behavior by taking our double-precision
// representation and letting getEncoding round to single.
// ---------------------------------------------------------------------------

function floatEncode(format: FloatFormat, f: number): bigint {
  return format.getEncoding(f);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('FloatFormat', () => {
  // =======================================================================
  // Encoding tests
  // =======================================================================

  describe('float encoding', () => {
    it('normal values', () => {
      const format = new FloatFormat(4);

      const f1 = floatFromRawBits(floatToRawBits(1.234));
      expect(format.getEncoding(f1)).toBe(floatToRawBits(1.234));

      const f2 = floatFromRawBits(floatToRawBits(-1.234));
      expect(format.getEncoding(f2)).toBe(floatToRawBits(-1.234));
    });

    it('NaN', () => {
      const format = new FloatFormat(4);

      // quiet NaN
      const nanEnc = format.getEncoding(NaN);
      // Must have exponent all-ones and non-zero fraction
      expect(nanEnc & 0x7F800000n).toBe(0x7F800000n);
      expect(nanEnc & 0x007FFFFFn).not.toBe(0n);

      // -NaN
      const negNanEnc = format.getEncoding(-NaN);
      expect(negNanEnc & 0x7F800000n).toBe(0x7F800000n);
      expect(negNanEnc & 0x007FFFFFn).not.toBe(0n);
    });

    it('subnormal', () => {
      const format = new FloatFormat(4);

      expect(format.getEncoding(FLOAT_DENORM_MIN)).toBe(0x00000001n);
      expect(format.getEncoding(-FLOAT_DENORM_MIN)).toBe(0x80000001n);
    });

    it('min normal', () => {
      const format = new FloatFormat(4);

      expect(format.getEncoding(FLOAT_MIN)).toBe(0x00800000n);
      expect(format.getEncoding(-FLOAT_MIN)).toBe(0x80800000n);
    });

    it('infinity', () => {
      const format = new FloatFormat(4);

      expect(format.getEncoding(Infinity)).toBe(0x7F800000n);
      expect(format.getEncoding(-Infinity)).toBe(0xFF800000n);
    });
  });

  describe('double encoding', () => {
    it('normal values', () => {
      const format = new FloatFormat(8);

      expect(format.getEncoding(1.234)).toBe(doubleToRawBits(1.234));
      expect(format.getEncoding(-1.234)).toBe(doubleToRawBits(-1.234));
    });

    it('NaN', () => {
      const format = new FloatFormat(8);

      const nanEnc = format.getEncoding(NaN);
      expect(nanEnc & 0x7FF0000000000000n).toBe(0x7FF0000000000000n);
      expect(nanEnc & 0x000FFFFFFFFFFFFFn).not.toBe(0n);

      const negNanEnc = format.getEncoding(-NaN);
      expect(negNanEnc & 0x7FF0000000000000n).toBe(0x7FF0000000000000n);
      expect(negNanEnc & 0x000FFFFFFFFFFFFFn).not.toBe(0n);
    });

    it('subnormal', () => {
      const format = new FloatFormat(8);

      expect(format.getEncoding(DOUBLE_DENORM_MIN)).toBe(0x0000000000000001n);
      expect(format.getEncoding(-DOUBLE_DENORM_MIN)).toBe(0x8000000000000001n);
    });

    it('min normal', () => {
      const format = new FloatFormat(8);

      expect(format.getEncoding(DOUBLE_MIN)).toBe(0x0010000000000000n);
      expect(format.getEncoding(-DOUBLE_MIN)).toBe(0x8010000000000000n);
    });

    it('infinity', () => {
      const format = new FloatFormat(8);

      expect(format.getEncoding(Infinity)).toBe(0x7FF0000000000000n);
      expect(format.getEncoding(-Infinity)).toBe(0xFFF0000000000000n);
    });
  });

  // =======================================================================
  // Decimal precision tests
  // =======================================================================

  describe('float decimal precision', () => {
    it('prints float values with correct precision', () => {
      const ff = new FloatFormat(4);

      const f0 = floatFromRawBits(0x34000001n);
      expect(ff.printDecimal(f0, false)).toBe('1.192093e-07');

      const f1 = floatFromRawBits(0x34800000n);
      expect(ff.printDecimal(f1, false)).toBe('2.3841858e-07');

      const f2 = floatFromRawBits(0x3eaaaaabn);
      expect(ff.printDecimal(f2, false)).toBe('0.33333334');

      const f3 = floatFromRawBits(0x3e800000n);
      // C++ default formatting strips trailing zeros
      expect(ff.printDecimal(f3, false)).toBe('0.25');

      const f4 = floatFromRawBits(0x3de3ee46n);
      expect(ff.printDecimal(f4, false)).toBe('0.111294314');
    });
  });

  describe('double decimal precision', () => {
    it('prints double values with correct precision', () => {
      const ff = new FloatFormat(8);

      const f0 = doubleFromRawBits(0x3fc5555555555555n);
      expect(ff.printDecimal(f0, false)).toBe('0.16666666666666666');

      const f1 = doubleFromRawBits(0x7fefffffffffffffn);
      // Note: JS parseFloat round-trip requires more digits for DBL_MAX than C++,
      // so the TS implementation returns the 17-digit form.
      expect(ff.printDecimal(f1, false)).toBe('1.7976931348623157e+308');

      const f2 = doubleFromRawBits(0x3fd555555c7dda4bn);
      // C++ default formatting strips trailing zeros
      expect(ff.printDecimal(f2, false)).toBe('0.33333334');

      const f3 = doubleFromRawBits(0x3fd0000000000000n);
      // C++ default formatting strips trailing zeros
      expect(ff.printDecimal(f3, false)).toBe('0.25');

      const f4 = doubleFromRawBits(0x3fb999999999999an);
      // C++ default formatting strips trailing zeros
      expect(ff.printDecimal(f4, false)).toBe('0.1');

      const f5 = doubleFromRawBits(0x3fbf7ced916872b0n);
      expect(ff.printDecimal(f5, true)).toBe('1.23000000000000e-01');
    });
  });

  // =======================================================================
  // Midpoint rounding test
  // =======================================================================

  describe('float midpoint rounding', () => {
    it('round-to-nearest-even at the midpoint', () => {
      const ff = new FloatFormat(4);

      // d0 - zeros in low 29 bits, round down
      // d1 - on the rounding midpoint with even integer part, round down
      // d2 - just above the midpoint, round up
      const d0 = doubleFromRawBits(0x4010000000000000n);
      const d1 = doubleFromRawBits(0x4010000010000000n);
      const d2 = doubleFromRawBits(0x4010000010000001n);

      // d3 - zeros in low 29 bits, round down
      // d4 - on the rounding midpoint with odd integer part, round up
      // d5 - just above the midpoint, round up
      const d3 = doubleFromRawBits(0x4010000020000000n);
      const d4 = doubleFromRawBits(0x4010000030000000n);
      const d5 = doubleFromRawBits(0x4010000030000001n);

      // C++ casts these doubles to float; replicate via Float32Array
      const f32 = new Float32Array(1);
      f32[0] = d0; const f0bits = floatToRawBits(f32[0]);
      f32[0] = d1; const f1bits = floatToRawBits(f32[0]);
      f32[0] = d2; const f2bits = floatToRawBits(f32[0]);
      f32[0] = d3; const f3bits = floatToRawBits(f32[0]);
      f32[0] = d4; const f4bits = floatToRawBits(f32[0]);
      f32[0] = d5; const f5bits = floatToRawBits(f32[0]);

      const e0 = ff.getEncoding(d0);
      const e1 = ff.getEncoding(d1);
      const e2 = ff.getEncoding(d2);
      const e3 = ff.getEncoding(d3);
      const e4 = ff.getEncoding(d4);
      const e5 = ff.getEncoding(d5);

      expect(e0).toBe(f0bits);
      expect(e1).toBe(f1bits);
      expect(e2).toBe(f2bits);
      expect(e3).toBe(f3bits);
      expect(e4).toBe(f4bits);
      expect(e5).toBe(f5bits);

      // Midpoint with even integer part rounds down (e0 == e1)
      expect(e0).toBe(e1);
      // Just above midpoint rounds up (e1 != e2)
      expect(e1).not.toBe(e2);

      // Midpoint with odd integer part rounds up (e3 != e4)
      expect(e3).not.toBe(e4);
      // Just above midpoint rounds to same as midpoint (e4 == e5)
      expect(e4).toBe(e5);
    });
  });

  // =======================================================================
  // Unary operations
  // =======================================================================

  describe('opNan', () => {
    it('detects NaN correctly for all test values', () => {
      const format = new FloatFormat(4);

      for (const f of float_test_values) {
        const trueResult = Number.isNaN(f) ? 1n : 0n;
        const encoding = format.getEncoding(f);
        const result = format.opNan(encoding);
        expect(result).toBe(trueResult);
      }
    });
  });

  describe('opNeg', () => {
    it('negates all test values', () => {
      const format = new FloatFormat(4);

      for (const f of float_test_values) {
        const trueResult = floatToRawBits(-f);
        const encoding = format.getEncoding(f);
        const result = format.opNeg(encoding);
        expect(result).toBe(trueResult);
      }
    });
  });

  describe('opAbs', () => {
    it('absolute value of all test values', () => {
      const format = new FloatFormat(4);

      for (const f of float_test_values) {
        const trueResult = floatToRawBits(Math.abs(f));
        const encoding = format.getEncoding(f);
        const result = format.opAbs(encoding);
        expect(result).toBe(trueResult);
      }
    });
  });

  describe('opSqrt', () => {
    it('square root of all test values', () => {
      const format = new FloatFormat(4);

      for (const f of float_test_values) {
        const trueResult = floatToRawBits(Math.fround(Math.sqrt(f)));
        const encoding = format.getEncoding(f);
        const result = format.opSqrt(encoding);
        expect(result).toBe(trueResult);
      }
    });
  });

  describe('opCeil', () => {
    it('ceiling of all test values', () => {
      const format = new FloatFormat(4);

      for (const f of float_test_values) {
        const trueResult = floatToRawBits(Math.fround(Math.ceil(f)));
        const encoding = format.getEncoding(f);
        const result = format.opCeil(encoding);
        expect(result).toBe(trueResult);
      }
    });
  });

  describe('opFloor', () => {
    it('floor of all test values', () => {
      const format = new FloatFormat(4);

      for (const f of float_test_values) {
        const trueResult = floatToRawBits(Math.fround(Math.floor(f)));
        const encoding = format.getEncoding(f);
        const result = format.opFloor(encoding);
        expect(result).toBe(trueResult);
      }
    });
  });

  describe('opRound', () => {
    it('round of all test values', () => {
      const format = new FloatFormat(4);

      for (const f of float_test_values) {
        const trueResult = floatToRawBits(Math.fround(Math.round(f)));
        const encoding = format.getEncoding(f);
        const result = format.opRound(encoding);
        expect(result).toBe(trueResult);
      }
    });
  });

  // =======================================================================
  // Int2Float
  // =======================================================================

  describe('opInt2Float (size 4)', () => {
    it('converts integers to float for all int test values', () => {
      const format = new FloatFormat(4);

      for (const i of int_test_values) {
        // C++: floatToRawBits((float)i)
        const trueResult = floatToRawBits(Math.fround(i));
        // The integer value must be passed as a bigint encoding (sign-extended fits in 32 bits)
        const ival = BigInt(i) & 0xFFFFFFFFn;
        const result = format.opInt2Float(ival, 4);
        expect(result).toBe(trueResult);
      }
    });
  });

  // =======================================================================
  // Float2Float  (float -> double)
  // =======================================================================

  describe('opFloat2Float (float to double)', () => {
    it('converts all float test values to double', () => {
      const format = new FloatFormat(4);
      const format8 = new FloatFormat(8);

      for (const f of float_test_values) {
        // C++: doubleToRawBits((double)f)
        // Since f is already a double representation of the float value,
        // the "true" double encoding is just doubleToRawBits(f).
        // But we need to match the C++ behavior where casting float to double
        // preserves the float-precision value exactly.
        const trueResult = doubleToRawBits(f);
        const encoding = format.getEncoding(f);
        const result = format.opFloat2Float(encoding, format8);
        expect(result).toBe(trueResult);
      }
    });
  });

  // =======================================================================
  // Trunc (float -> int)
  // =======================================================================

  describe('opTrunc (to int)', () => {
    it('truncates float to 32-bit integer for all test values', () => {
      const format = new FloatFormat(4);

      for (const f of float_test_values) {
        // Skip values that would cause undefined behavior (out of int32 range)
        const i64val = Math.trunc(f);
        if (i64val > 2147483647 || i64val < -2147483648) continue;
        // Also skip NaN (produces 0 in C++ but behavior is implementation-defined)
        if (Number.isNaN(f)) continue;

        // C++: ((uintb)(int32_t)f) & 0xffffffff
        const i32 = Math.trunc(f) | 0; // convert to int32 via bitwise OR
        const trueResult = BigInt(i32) & 0xFFFFFFFFn;
        const encoding = format.getEncoding(f);
        const result = format.opTrunc(encoding, 4);
        expect(result).toBe(trueResult);
      }
    });
  });

  // =======================================================================
  // Binary comparison operations
  // =======================================================================

  describe('opEqual', () => {
    it('equality comparison for all pairs of test values', () => {
      const format = new FloatFormat(4);

      for (const f1 of float_test_values) {
        const encoding1 = format.getEncoding(f1);
        for (const f2 of float_test_values) {
          const trueResult = (f1 === f2) ? 1n : 0n;
          const encoding2 = format.getEncoding(f2);
          const result = format.opEqual(encoding1, encoding2);
          expect(result).toBe(trueResult);
        }
      }
    });
  });

  describe('opNotEqual', () => {
    it('inequality comparison for all pairs of test values', () => {
      const format = new FloatFormat(4);

      for (const f1 of float_test_values) {
        const encoding1 = format.getEncoding(f1);
        for (const f2 of float_test_values) {
          const trueResult = (f1 !== f2) ? 1n : 0n;
          const encoding2 = format.getEncoding(f2);
          const result = format.opNotEqual(encoding1, encoding2);
          expect(result).toBe(trueResult);
        }
      }
    });
  });

  describe('opLess', () => {
    it('less-than comparison for all pairs of test values', () => {
      const format = new FloatFormat(4);

      for (const f1 of float_test_values) {
        const encoding1 = format.getEncoding(f1);
        for (const f2 of float_test_values) {
          const trueResult = (f1 < f2) ? 1n : 0n;
          const encoding2 = format.getEncoding(f2);
          const result = format.opLess(encoding1, encoding2);
          expect(result).toBe(trueResult);
        }
      }
    });
  });

  describe('opLessEqual', () => {
    it('less-than-or-equal comparison for all pairs of test values', () => {
      const format = new FloatFormat(4);

      for (const f1 of float_test_values) {
        const encoding1 = format.getEncoding(f1);
        for (const f2 of float_test_values) {
          const trueResult = (f1 <= f2) ? 1n : 0n;
          const encoding2 = format.getEncoding(f2);
          const result = format.opLessEqual(encoding1, encoding2);
          expect(result).toBe(trueResult);
        }
      }
    });
  });

  // =======================================================================
  // Binary arithmetic operations
  // =======================================================================

  describe('opAdd', () => {
    it('addition for all pairs of test values', () => {
      const format = new FloatFormat(4);

      for (const f1 of float_test_values) {
        const encoding1 = format.getEncoding(f1);
        for (const f2 of float_test_values) {
          const trueResult = floatToRawBits(Math.fround(f1 + f2));
          const encoding2 = format.getEncoding(f2);
          const result = format.opAdd(encoding1, encoding2);
          expect(result).toBe(trueResult);
        }
      }
    });
  });

  describe('opDiv', () => {
    it('division for all pairs of test values', () => {
      const format = new FloatFormat(4);

      for (const f1 of float_test_values) {
        const encoding1 = format.getEncoding(f1);
        for (const f2 of float_test_values) {
          const trueResult = floatToRawBits(Math.fround(f1 / f2));
          const encoding2 = format.getEncoding(f2);
          const result = format.opDiv(encoding1, encoding2);
          expect(result).toBe(trueResult);
        }
      }
    });
  });

  describe('opMult', () => {
    it('multiplication for all pairs of test values', () => {
      const format = new FloatFormat(4);

      for (const f1 of float_test_values) {
        const encoding1 = format.getEncoding(f1);
        for (const f2 of float_test_values) {
          const trueResult = floatToRawBits(Math.fround(f1 * f2));
          const encoding2 = format.getEncoding(f2);
          const result = format.opMult(encoding1, encoding2);
          expect(result).toBe(trueResult);
        }
      }
    });
  });

  describe('opSub', () => {
    it('subtraction for all pairs of test values', () => {
      const format = new FloatFormat(4);

      for (const f1 of float_test_values) {
        const encoding1 = format.getEncoding(f1);
        for (const f2 of float_test_values) {
          const trueResult = floatToRawBits(Math.fround(f1 - f2));
          const encoding2 = format.getEncoding(f2);
          const result = format.opSub(encoding1, encoding2);
          expect(result).toBe(trueResult);
        }
      }
    });
  });
});
