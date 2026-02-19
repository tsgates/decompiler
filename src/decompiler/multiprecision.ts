/**
 * @file multiprecision.ts
 * @description Multi-precision integer arithmetic, translated from multiprecision.hh / multiprecision.cc
 *
 * 128-bit integers are represented as arrays of 2 bigint values (64-bit words),
 * stored in little-endian order (index 0 = least significant word).
 */

import { LowlevelError } from '../core/error.js';
import { count_leading_zeros } from '../core/address.js';

// Masks for truncating to 64-bit and 32-bit unsigned values
const MASK64 = 0xFFFFFFFFFFFFFFFFn;
const MASK32 = 0xFFFFFFFFn;

/**
 * Multi-precision logical left shift by a constant amount.
 *
 * `inArr` and `outArr` arrays are specified and can point to the same storage.
 * @param num - the number of 64-bit words in the extended precision integers
 * @param inArr - the input value to shift
 * @param outArr - the container for the result
 * @param sa - the number of bits to shift
 */
function leftshift(num: number, inArr: bigint[], outArr: bigint[], sa: number): void {
  let inIndex: number = num - 1 - Math.floor(sa / 64);
  sa = sa % 64;
  let outIndex: number = num - 1;
  if (sa === 0) {
    for (; inIndex >= 0; --inIndex) {
      outArr[outIndex--] = inArr[inIndex];
    }
    for (; outIndex >= 0; --outIndex) {
      outArr[outIndex] = 0n;
    }
  } else {
    for (; inIndex > 0; --inIndex) {
      outArr[outIndex--] = ((inArr[inIndex] << BigInt(sa)) | (inArr[inIndex - 1] >> BigInt(64 - sa))) & MASK64;
    }
    outArr[outIndex--] = (inArr[0] << BigInt(sa)) & MASK64;
    for (; outIndex >= 0; --outIndex) {
      outArr[outIndex] = 0n;
    }
  }
}

/**
 * 128-bit INT_LEFT operation with constant shift amount.
 * @param inArr - the 128-bit input (as 2 64-bit words)
 * @param outArr - will hold the 128-bit result
 * @param sa - the number of bits to shift
 */
export function leftshift128(inArr: bigint[], outArr: bigint[], sa: number): void {
  leftshift(2, inArr, outArr, sa);
}

/**
 * Compare two multi-precision unsigned integers.
 *
 * -1, 0, or 1 is returned depending on if the first integer is less than, equal to, or greater than
 * the second integer.
 * @param num - the number of 64-bit words in the extended precision integers
 * @param in1 - the first integer to compare
 * @param in2 - the second integer to compare
 * @returns -1, 0, or 1
 */
function ucompare(num: number, in1: bigint[], in2: bigint[]): number {
  for (let i = num - 1; i >= 0; --i) {
    if (in1[i] !== in2[i])
      return (in1[i] < in2[i]) ? -1 : 1;
  }
  return 0;
}

/**
 * 128-bit INT_LESS operation.
 * @param in1 - the first 128-bit value (as 2 64-bit words) to compare
 * @param in2 - the second 128-bit value
 * @returns true if the first value is less than the second value
 */
export function uless128(in1: bigint[], in2: bigint[]): boolean {
  return ucompare(2, in1, in2) < 0;
}

/**
 * 128-bit INT_LESSEQUAL operation.
 * @param in1 - the first 128-bit value (as 2 64-bit words) to compare
 * @param in2 - the second 128-bit value
 * @returns true if the first value is less than or equal to the second value
 */
export function ulessequal128(in1: bigint[], in2: bigint[]): boolean {
  return ucompare(2, in1, in2) <= 0;
}

/**
 * Multi-precision add operation.
 * @param num - the number of 64-bit words in the extended precision integers
 * @param in1 - the first integer
 * @param in2 - the integer added to the first
 * @param out - where the add result is stored
 */
function add(num: number, in1: bigint[], in2: bigint[], out: bigint[]): void {
  let carry: bigint = 0n;
  for (let i = 0; i < num; ++i) {
    const tmp: bigint = (in2[i] + carry) & MASK64;
    const tmp2: bigint = (in1[i] + tmp) & MASK64;
    out[i] = tmp2;
    carry = (tmp < in2[i] || tmp2 < tmp) ? 1n : 0n;
  }
}

/**
 * 128-bit INT_ADD operation.
 * @param in1 - the first 128-bit value (as 2 64-bit words) to add
 * @param in2 - the second 128-bit value to add
 * @param out - will hold the 128-bit result
 */
export function add128(in1: bigint[], in2: bigint[], out: bigint[]): void {
  add(2, in1, in2, out);
}

/**
 * Multi-precision subtract operation.
 * @param num - the number of 64-bit words in the extended precision integers
 * @param in1 - the first integer
 * @param in2 - the integer subtracted from the first
 * @param out - where the subtraction result is stored
 */
function subtract(num: number, in1: bigint[], in2: bigint[], out: bigint[]): void {
  let borrow: bigint = 0n;
  for (let i = 0; i < num; ++i) {
    const tmp: bigint = (in2[i] + borrow) & MASK64;
    borrow = (tmp < in2[i] || in1[i] < tmp) ? 1n : 0n;
    out[i] = (in1[i] - tmp) & MASK64;
  }
}

/**
 * 128-bit INT_SUB operation.
 * @param in1 - the first 128-bit value (as 2 64-bit words)
 * @param in2 - the second 128-bit value to subtract
 * @param out - will hold the 128-bit result
 */
export function subtract128(in1: bigint[], in2: bigint[], out: bigint[]): void {
  subtract(2, in1, in2, out);
}

/**
 * Split an array of 64-bit words into an array of 32-bit words.
 *
 * The least significant half of each 64-bit word is put into the 32-bit word array first.
 * The index of the most significant non-zero 32-bit word is calculated and returned
 * as the effective size of the resulting array.
 * @param num - the number of 64-bit words to split
 * @param val - the array of 64-bit words (bigint)
 * @param res - the array that will hold the 32-bit words (number)
 * @returns the effective size of the 32-bit word array
 */
function split64_32(num: number, val: bigint[], res: number[]): number {
  let m: number = 0;
  for (let i = 0; i < num; ++i) {
    const hi: number = Number((val[i] >> 32n) & MASK32);
    const lo: number = Number(val[i] & MASK32);
    if (hi !== 0)
      m = i * 2 + 2;
    else if (lo !== 0)
      m = i * 2 + 1;
    res[i * 2] = lo;
    res[i * 2 + 1] = hi;
  }
  return m;
}

/**
 * Pack an array of 32-bit words into an array of 64-bit words.
 *
 * The 64-bit word array is padded out with zeroes if the specified size exceeds
 * the provided number of 32-bit words.
 * @param num - the number of 64-bit words in the resulting array
 * @param max - the number of 32-bit words to pack
 * @param out - the array of 64-bit words (bigint)
 * @param inArr - the array of 32-bit words (number)
 */
function pack32_64(num: number, max: number, out: bigint[], inArr: number[]): void {
  let j: number = num * 2 - 1;
  for (let i = num - 1; i >= 0; --i) {
    let val: bigint;
    val = (j < max) ? BigInt(inArr[j] >>> 0) : 0n;
    val = (val << 32n) & MASK64;
    j -= 1;
    if (j < max)
      val |= BigInt(inArr[j] >>> 0);
    j -= 1;
    out[i] = val;
  }
}

/**
 * Logical shift left for an extended integer in 32-bit word arrays.
 * @param arr - the array of 32-bit words
 * @param size - the number of words in the array
 * @param sa - the number of bits to shift
 */
function shift_left(arr: number[], size: number, sa: number): void {
  if (sa === 0) return;
  for (let i = size - 1; i > 0; --i)
    arr[i] = ((arr[i] << sa) | (arr[i - 1] >>> (32 - sa))) >>> 0;
  arr[0] = (arr[0] << sa) >>> 0;
}

/**
 * Logical shift right for an extended integer in 32-bit word arrays.
 * @param arr - the array of 32-bit words
 * @param size - the number of words in the array
 * @param sa - the number of bits to shift
 */
function shift_right(arr: number[], size: number, sa: number): void {
  if (sa === 0) return;
  for (let i = 0; i < size - 1; ++i)
    arr[i] = ((arr[i] >>> sa) | ((arr[i + 1] << (32 - sa)) >>> 0)) >>> 0;
  arr[size - 1] = arr[size - 1] >>> sa;
}

/**
 * Knuth's algorithm D, for integer division.
 *
 * The numerator and denominator, expressed in 32-bit digits, are provided.
 * The algorithm calculates the quotient and the remainder is left in the array
 * originally containing the numerator.
 * @param m - the number of 32-bit digits in the numerator
 * @param n - the number of 32-bit digits in the denominator
 * @param u - the numerator and will hold the remainder
 * @param v - the denominator
 * @param q - will hold the final quotient
 */
function knuth_algorithm_d(m: number, n: number, u: number[], v: number[], q: number[]): void {
  // count_leading_zeros operates on 64-bit bigint; v[n-1] is a 32-bit number.
  // In C++: count_leading_zeros(v[n-1]) - 8*(sizeof(uintb)-sizeof(uint4))
  // sizeof(uintb) = 8, sizeof(uint4) = 4, so the subtracted constant is 32.
  const s: number = count_leading_zeros(BigInt(v[n - 1] >>> 0)) - 32;
  shift_left(v, n, s);
  shift_left(u, m, s);

  for (let j = m - n - 1; j >= 0; --j) {
    // Use bigint for intermediate 64-bit arithmetic
    const tmp: bigint = ((BigInt(u[n + j] >>> 0) << 32n) + BigInt(u[n - 1 + j] >>> 0)) & MASK64;
    let qhat: bigint = tmp / BigInt(v[n - 1] >>> 0);
    let rhat: bigint = tmp % BigInt(v[n - 1] >>> 0);
    do {
      if (qhat <= MASK32 && qhat * BigInt(v[n - 2] >>> 0) <= ((rhat << 32n) + BigInt(u[n - 2 + j] >>> 0)))
        break;
      qhat -= 1n;
      rhat += BigInt(v[n - 1] >>> 0);
    } while (rhat <= MASK32);

    let carry: bigint = 0n;
    let t: bigint;
    for (let i = 0; i < n; ++i) {
      const prod: bigint = qhat * BigInt(v[i] >>> 0);
      // t is signed: u[i+j] - carry - (prod & 0xffffffff)
      // We need signed 64-bit arithmetic here
      t = BigInt(u[i + j] >>> 0) - carry - (prod & MASK32);
      u[i + j] = Number(t & MASK32);
      // carry = (prod >> 32) - (t >> 32), using signed shift for t
      carry = (prod >> 32n) - (BigInt.asIntN(64, t) >> 32n);
    }
    t = BigInt(u[j + n] >>> 0) - carry;
    u[j + n] = Number(t & MASK32);

    q[j] = Number(qhat & MASK32);
    if (BigInt.asIntN(64, t) < 0n) {
      q[j] = ((q[j] - 1) >>> 0);
      carry = 0n;
      for (let i = 0; i < n; ++i) {
        const sum: bigint = BigInt(u[i + j] >>> 0) + BigInt(v[i] >>> 0) + carry;
        u[i + j] = Number(sum & MASK32);
        carry = sum >> 32n;
      }
      u[j + n] = Number((BigInt(u[j + n] >>> 0) + carry) & MASK32);
    }
  }
  shift_right(u, m, s);
}

/**
 * 128-bit INT_DIV.
 * @param numer - holds the 2 64-bit words of the numerator
 * @param denom - holds the 2 words of the denominator
 * @param quotient_res - will hold the 2 words of the quotient
 * @param remainder_res - will hold the 2 words of the remainder
 */
export function udiv128(numer: bigint[], denom: bigint[], quotient_res: bigint[], remainder_res: bigint[]): void {
  if (numer[1] === 0n && denom[1] === 0n) {
    quotient_res[0] = numer[0] / denom[0];
    quotient_res[1] = 0n;
    remainder_res[0] = numer[0] % denom[0];
    remainder_res[1] = 0n;
    return;
  }
  const v: number[] = new Array<number>(4).fill(0);
  const u: number[] = new Array<number>(5).fill(0);  // One more entry for normalization overflow
  const q: number[] = new Array<number>(4).fill(0);
  const n: number = split64_32(2, denom, v);
  if (n === 0) {
    throw new LowlevelError("divide by 0");
  }
  const m_initial: number = split64_32(2, numer, u);
  if (m_initial < n || (n === m_initial && (u[n - 1] >>> 0) < (v[n - 1] >>> 0))) {
    // denominator is larger than the numerator, quotient is 0
    quotient_res[0] = 0n;
    quotient_res[1] = 0n;
    remainder_res[0] = numer[0];
    remainder_res[1] = numer[1];
    return;
  }
  u[m_initial] = 0;
  const m: number = m_initial + 1;  // Extend u array by 1 to account for normalization
  if (n === 1) {
    const d: number = v[0] >>> 0;
    let rem: number = 0;
    for (let i = m - 1; i >= 0; --i) {
      const tmp: bigint = ((BigInt(rem >>> 0) << 32n) + BigInt(u[i] >>> 0)) & MASK64;
      q[i] = Number(tmp / BigInt(d));
      u[i] = 0;
      rem = Number(tmp % BigInt(d));
    }
    u[0] = rem;  // Last carry is final remainder
  } else {
    knuth_algorithm_d(m, n, u, v, q);
  }
  pack32_64(2, m - n, quotient_res, q);
  pack32_64(2, m - 1, remainder_res, u);
}

/**
 * Set a 128-bit value (2 64-bit words) from a 64-bit value.
 * @param res - will hold the 128-bit value
 * @param val - the 64-bit value to set from
 */
export function set_u128(res: bigint[], val: bigint): void {
  res[0] = val;
  res[1] = 0n;
}
