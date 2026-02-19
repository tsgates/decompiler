/**
 * @file types.ts
 * @description Platform-specific type definitions translated from Ghidra's types.h
 *
 * C++ fixed-width integer types are mapped as follows:
 *   int1/uint1, int2/uint2, int4/uint4 → number (safe for 32-bit and below)
 *   int8/uint8, intb/uintb             → bigint (64-bit integers)
 *   uintp                              → number (pointer-sized, used as index)
 */

// ---- Small integer types (fit in JS number) ----

/** Signed 8-bit integer (C++ int1 / int8_t) */
export type int1 = number;
/** Unsigned 8-bit integer (C++ uint1 / uint8_t) */
export type uint1 = number;
/** Signed 16-bit integer (C++ int2 / int16_t) */
export type int2 = number;
/** Unsigned 16-bit integer (C++ uint2 / uint16_t) */
export type uint2 = number;
/** Signed 32-bit integer (C++ int4 / int32_t) */
export type int4 = number;
/** Unsigned 32-bit integer (C++ uint4 / uint32_t) */
export type uint4 = number;

// ---- Deprecated aliases (must be 32-bit) ----
/** @deprecated Use int4 */
export type intm = number;
/** @deprecated Use uint4 */
export type uintm = number;

// ---- Big integer types (64-bit, using BigInt) ----

/** Signed 64-bit integer (C++ int8 / int64_t) */
export type int8 = bigint;
/** Unsigned 64-bit integer (C++ uint8 / uint64_t) */
export type uint8 = bigint;

/** Signed big integer (C++ intb — currently 64-bit fixed precision) */
export type intb = bigint;
/** Unsigned big integer (C++ uintb — currently 64-bit fixed precision) */
export type uintb = bigint;

/** Pointer-sized unsigned integer (used as array index in TS) */
export type uintp = number;

// ---- Host endianness ----

/** Host byte order: 0 = little-endian (x86/x64), 1 = big-endian */
export const HOST_ENDIAN = 0;

// ---- Debug flags ----

/** Master debug switch (equivalent to CPUI_DEBUG) */
export let CPUI_DEBUG = false;
export let OPACTION_DEBUG = false;
export let PRETTY_DEBUG = false;
export let TYPEPROP_DEBUG = false;

/** Enable all debug flags */
export function enableDebug(): void {
  CPUI_DEBUG = true;
  OPACTION_DEBUG = true;
  PRETTY_DEBUG = true;
  TYPEPROP_DEBUG = true;
}

/** Disable all debug flags */
export function disableDebug(): void {
  CPUI_DEBUG = false;
  OPACTION_DEBUG = false;
  PRETTY_DEBUG = false;
  TYPEPROP_DEBUG = false;
}

// ---- BigInt utility constants ----

export const BIGINT_0 = 0n;
export const BIGINT_1 = 1n;

/** Mask for n-bit value: (1n << BigInt(n)) - 1n. Returns all 1s for the given bit width. */
export function uintbMask(byteSize: number): bigint {
  if (byteSize >= 8) return 0xFFFFFFFFFFFFFFFFn;
  return (1n << BigInt(byteSize * 8)) - 1n;
}

/** Sign-extend a value of the given byte size to a signed 64-bit bigint */
export function signExtend(val: bigint, byteSize: number): bigint {
  const bits = byteSize * 8;
  const mask = (1n << BigInt(bits)) - 1n;
  val = val & mask;
  const signBit = 1n << BigInt(bits - 1);
  if (val & signBit) {
    return val | (~mask);
  }
  return val;
}

/** Truncate a bigint to the given byte size (mask off upper bits) */
export function truncate(val: bigint, byteSize: number): bigint {
  if (byteSize >= 8) return val & 0xFFFFFFFFFFFFFFFFn;
  return val & ((1n << BigInt(byteSize * 8)) - 1n);
}
