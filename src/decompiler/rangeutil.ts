// rangeutil_part1.ts — Part 1 of 2
// Translation of Ghidra's rangeutil.hh / rangeutil.cc (first half)
// SPDX-License-Identifier: Apache-2.0

// ---------------------------------------------------------------------------
// Imports from existing modules
// ---------------------------------------------------------------------------
import { Address } from "../core/address.js";
import { OpCode, get_opname } from "../core/opcodes.js";
import { Varnode } from "./varnode.js";
import { PcodeOp } from "./op.js";

// ---------------------------------------------------------------------------
// Forward type declarations for types from not-yet-written modules
// ---------------------------------------------------------------------------
export type Funcdata = any;
export type SeqNum = any;
export type SymbolEntry = any;
export type FlowBlock = any;
export type BlockBasic = any;

// ---------------------------------------------------------------------------
// Utility helpers (mirroring Ghidra's address.hh helpers)
// ---------------------------------------------------------------------------

const uintbmasks: bigint[] = [
  0n,
  0xFFn,
  0xFFFFn,
  0xFFFFFFn,
  0xFFFFFFFFn,
  0xFFFFFFFFFFn,
  0xFFFFFFFFFFFFn,
  0xFFFFFFFFFFFFFFn,
  0xFFFFFFFFFFFFFFFFn,
];

/** Calculate a bit mask for a given byte size (1..8). */
export function calc_mask(size: number): bigint {
  return uintbmasks[size < 8 ? size : 8];
}

/** Sign-extend a value sitting in `sizein` bytes out to `sizeout` bytes. */
export function sign_extend_sizes(val: bigint, sizein: number, sizeout: number): bigint {
  const inMask = calc_mask(sizein);
  const signBit = (inMask >> 1n) + 1n;
  if ((val & signBit) !== 0n) {
    const outMask = calc_mask(sizeout);
    return (val | (outMask ^ inMask)) & outMask;
  }
  return val;
}

/** Sign-extend a value from bit position `bit` using BigInt arithmetic. */
export function sign_extend(val: bigint, bit: number): bigint {
  const mask = 1n << BigInt(bit);
  if ((val & mask) !== 0n) {
    // set all bits above `bit`
    return val | (~(mask - 1n));
  }
  return val;
}

/** Return the index of the least significant bit set, or -1 if val==0. */
export function leastsigbit_set(val: bigint): number {
  if (val === 0n) return -1;
  let i = 0;
  let v = val;
  while ((v & 1n) === 0n) { v >>= 1n; i++; }
  return i;
}

/** Return the index of the most significant bit set, or -1 if val==0. */
export function mostsigbit_set(val: bigint): number {
  if (val === 0n) return -1;
  let i = 0;
  let v = val;
  while (v > 1n) { v >>= 1n; i++; }
  return i;
}

/** Count leading zeros for a 64-bit value. */
export function count_leading_zeros(val: bigint): number {
  if (val === 0n) return 64;
  let n = 0;
  let v = val & 0xFFFFFFFFFFFFFFFFn;
  if ((v & 0xFFFFFFFF00000000n) === 0n) { n += 32; v <<= 32n; }
  if ((v & 0xFFFF000000000000n) === 0n) { n += 16; v <<= 16n; }
  if ((v & 0xFF00000000000000n) === 0n) { n += 8;  v <<= 8n; }
  if ((v & 0xF000000000000000n) === 0n) { n += 4;  v <<= 4n; }
  if ((v & 0xC000000000000000n) === 0n) { n += 2;  v <<= 2n; }
  if ((v & 0x8000000000000000n) === 0n) { n += 1; }
  return n;
}

/** Count the number of 0->1 and 1->0 bit transitions in a sized value. */
export function bit_transitions(val: bigint, sz: number): number {
  const totalBits = sz * 8;
  let count = 0;
  let prev = Number(val & 1n);
  for (let i = 1; i < totalBits; i++) {
    const cur = Number((val >> BigInt(i)) & 1n);
    if (cur !== prev) count++;
    prev = cur;
  }
  return count;
}

// BigInt mask to clamp to 64-bit unsigned
const MASK64 = 0xFFFFFFFFFFFFFFFFn;

/** Helper: clamp bigint to unsigned 64-bit range. */
function u64(v: bigint): bigint { return v & MASK64; }

// ---------------------------------------------------------------------------
// CircleRange
// ---------------------------------------------------------------------------

/**
 * A class for manipulating integer value ranges.
 *
 * The representation is a circular range (determined by a half-open interval
 * [left, right)), over the integers mod 2^n, where mask = 2^n - 1.
 * The range can support a step if some of the least significant bits of
 * the mask are set to zero.
 */
export class CircleRange {
  private left: bigint = 0n;
  private right: bigint = 0n;
  private mask: bigint = 0n;
  private isempty: boolean = true;
  private step: number = 1;

  // Map from raw overlaps to normalized overlap code
  private static readonly arrange: string =
    "gcgbegdagggggggeggggcgbggggggggcdfgggggggegdggggbgggfggggcgbegda";

  // ------- private helpers -------

  /** Normalize the representation of full sets. */
  private normalize(): void {
    if (this.left === this.right) {
      if (this.step !== 1)
        this.left = this.left % BigInt(this.step);
      else
        this.left = 0n;
      this.right = this.left;
    }
  }

  /** Set this to the complement of itself.  Only works if step is 1. */
  private complement(): void {
    if (this.isempty) {
      this.left = 0n;
      this.right = 0n;
      this.isempty = false;
      return;
    }
    if (this.left === this.right) {
      this.isempty = true;
      return;
    }
    const tmp = this.left;
    this.left = this.right;
    this.right = tmp;
  }

  /** Convert this to boolean.  Returns true if the range contains both 0 and 1. */
  private convertToBoolean(): boolean {
    if (this.isempty) return false;
    const containsZero = this.containsVal(0n);
    const containsOne = this.containsVal(1n);
    this.mask = 0xFFn;
    this.step = 1;
    if (containsZero && containsOne) {
      this.left = 0n;
      this.right = 2n;
      this.isempty = false;
      return true;
    } else if (containsZero) {
      this.left = 0n;
      this.right = 1n;
      this.isempty = false;
    } else if (containsOne) {
      this.left = 1n;
      this.right = 2n;
      this.isempty = false;
    } else {
      this.isempty = true;
    }
    return false;
  }

  /**
   * Recalculate range based on new stride.
   * Restrict a left/right specified range to a new stride, given the step and
   * remainder it needs to match.  This assumes the specified range is not empty.
   * Returns true if result is empty.
   */
  private static newStride(
    mask: bigint, step: number, oldStep: number, rem: number,
    ref: { left: bigint; right: bigint }
  ): boolean {
    const stepB = BigInt(step);
    const remB = BigInt(rem);
    if (oldStep !== 1) {
      const oldRem = Number(ref.left % BigInt(oldStep));
      if (oldRem !== (rem % oldStep))
        return true; // Step is completely off
    }
    const origOrder = ref.left < ref.right;
    const leftRem = Number(ref.left % stepB);
    const rightRem = Number(ref.right % stepB);
    if (leftRem > rem)
      ref.left += remB + stepB - BigInt(leftRem);
    else
      ref.left += remB - BigInt(leftRem);

    if (rightRem > rem)
      ref.right += remB + stepB - BigInt(rightRem);
    else
      ref.right += remB - BigInt(rightRem);

    ref.left &= mask;
    ref.right &= mask;

    const newOrder = ref.left < ref.right;
    if (origOrder !== newOrder)
      return true;
    return false; // not empty
  }

  /**
   * Make this range fit in a new domain.
   * Truncate any part of the range outside of the new domain.
   * Returns true if the truncated domain is empty.
   */
  private static newDomain(
    newMask: bigint, newStep: number,
    ref: { left: bigint; right: bigint }
  ): boolean {
    let rem: bigint;
    if (newStep !== 1)
      rem = ref.left % BigInt(newStep);
    else
      rem = 0n;
    if (ref.left > newMask) {
      if (ref.right > newMask) {
        if (ref.left < ref.right) return true;
        ref.left = rem;
        ref.right = rem;
        return false;
      }
      ref.left = rem;
    }
    if (ref.right > newMask) {
      ref.right = rem;
    }
    if (ref.left === ref.right) {
      ref.left = rem;
      ref.right = rem;
    }
    return false;
  }

  /**
   * Calculate overlap code.
   * Given 2 ranges, calculates the category code for the overlap.
   */
  private static encodeRangeOverlaps(
    op1left: bigint, op1right: bigint,
    op2left: bigint, op2right: bigint
  ): string {
    let val = (op1left <= op1right) ? 0x20 : 0;
    val |= (op1left <= op2left) ? 0x10 : 0;
    val |= (op1left <= op2right) ? 0x8 : 0;
    val |= (op1right <= op2left) ? 4 : 0;
    val |= (op1right <= op2right) ? 2 : 0;
    val |= (op2left <= op2right) ? 1 : 0;
    return CircleRange.arrange[val];
  }

  // ------- constructors (static factory methods) -------

  /** Construct an empty range (default). */
  constructor();
  /** Construct given specific boundaries. */
  constructor(lft: bigint, rgt: bigint, size: number, stp: number);
  /** Construct a boolean range. */
  constructor(val: boolean);
  /** Construct range with single value. */
  constructor(val: bigint, size: number);

  constructor(
    a?: bigint | boolean,
    b?: bigint | number,
    c?: number,
    d?: number
  ) {
    if (a === undefined) {
      // Default: empty range
      this.isempty = true;
      return;
    }
    if (typeof a === "boolean") {
      // Boolean constructor
      this.mask = 0xFFn;
      this.step = 1;
      this.left = a ? 1n : 0n;
      this.right = this.left + 1n;
      this.isempty = false;
      return;
    }
    // a is bigint
    if (c !== undefined && d !== undefined) {
      // (lft, rgt, size, stp)
      this.mask = calc_mask(c);
      this.step = d;
      this.left = a;
      this.right = b as bigint;
      this.isempty = false;
      return;
    }
    // (val, size)
    const size = b as number;
    this.mask = calc_mask(size);
    this.step = 1;
    this.left = a;
    this.right = (this.left + 1n) & this.mask;
    this.isempty = false;
  }

  // ------- public API -------

  /** Set directly to a specific range. */
  setRange(lft: bigint, rgt: bigint, size: number, stp: number): void;
  /** Set range with a single value. */
  setRange(val: bigint, size: number): void;

  setRange(a: bigint, b: bigint | number, c?: number, d?: number): void {
    if (c !== undefined && d !== undefined) {
      // (lft, rgt, size, step)
      this.mask = calc_mask(c);
      this.left = a;
      this.right = b as bigint;
      this.step = d;
      this.isempty = false;
    } else {
      // (val, size)
      const size = b as number;
      this.mask = calc_mask(size);
      this.step = 1;
      this.left = a;
      this.right = (this.left + 1n) & this.mask;
      this.isempty = false;
    }
  }

  /** Set a completely full range. */
  setFull(size: number): void {
    this.mask = calc_mask(size);
    this.step = 1;
    this.left = 0n;
    this.right = 0n;
    this.isempty = false;
  }

  /** Return true if this range is empty. */
  isEmpty(): boolean { return this.isempty; }

  /** Return true if this contains all possible values. */
  isFull(): boolean {
    return (!this.isempty) && (this.step === 1) && (this.left === this.right);
  }

  /** Return true if this contains a single value. */
  isSingle(): boolean {
    return (!this.isempty) && (this.right === ((this.left + BigInt(this.step)) & this.mask));
  }

  /** Get the left boundary of the range. */
  getMin(): bigint { return this.left; }

  /** Get the right-most integer contained in the range. */
  getMax(): bigint { return (this.right - BigInt(this.step)) & this.mask; }

  /** Get the right boundary of the range. */
  getEnd(): bigint { return this.right; }

  /** Get the mask. */
  getMask(): bigint { return this.mask; }

  /** Get the size of this range (number of integers contained). */
  getSize(): bigint {
    if (this.isempty) return 0n;
    const stepB = BigInt(this.step);
    let val: bigint;
    if (this.left < this.right) {
      val = (this.right - this.left) / stepB;
    } else {
      val = (this.mask - (this.left - this.right) + stepB) / stepB;
      if (val === 0n) {
        // Overflow: all uintb values are in the range
        val = this.mask;
        if (this.step > 1) {
          val = val / stepB;
          val += 1n;
        }
      }
    }
    return val;
  }

  /** Get the step for this range. */
  getStep(): number { return this.step; }

  /** Get maximum information content of range. */
  getMaxInfo(): number {
    const halfPoint = this.mask ^ (this.mask >> 1n);
    if (this.containsVal(halfPoint))
      return 64 - count_leading_zeros(halfPoint);
    let sizeLeft: number;
    let sizeRight: number;
    if ((halfPoint & this.left) === 0n)
      sizeLeft = count_leading_zeros(this.left);
    else
      sizeLeft = count_leading_zeros(~this.left & this.mask);
    if ((halfPoint & this.right) === 0n)
      sizeRight = count_leading_zeros(this.right);
    else
      sizeRight = count_leading_zeros(~this.right & this.mask);
    const size1 = 64 - (sizeRight < sizeLeft ? sizeRight : sizeLeft);
    return size1;
  }

  /** Equals operator. */
  equals(op2: CircleRange): boolean {
    if (this.isempty !== op2.isempty) return false;
    if (this.isempty) return true;
    return (
      this.left === op2.left &&
      this.right === op2.right &&
      this.mask === op2.mask &&
      this.step === op2.step
    );
  }

  /** Copy all fields from another CircleRange. */
  copyFrom(other: CircleRange): void {
    this.left = other.left;
    this.right = other.right;
    this.mask = other.mask;
    this.step = other.step;
    this.isempty = other.isempty;
  }

  /** Advance an integer within the range. Returns true if not at the end. */
  getNext(ref: { val: bigint }): boolean {
    ref.val = (ref.val + BigInt(this.step)) & this.mask;
    return ref.val !== this.right;
  }

  /** Check containment of another range in this. */
  containsRange(op2: CircleRange): boolean {
    if (this.isempty) return op2.isempty;
    if (op2.isempty) return true;
    if (this.step > op2.step) {
      if (!op2.isSingle()) return false;
    }
    if (this.left === this.right) return true;
    if (op2.left === op2.right) return false;
    if (this.left % BigInt(this.step) !== op2.left % BigInt(this.step)) return false;
    if (this.left === op2.left && this.right === op2.right) return true;

    const overlapCode = CircleRange.encodeRangeOverlaps(
      this.left, this.right, op2.left, op2.right
    );
    if (overlapCode === "c") return true;
    if (overlapCode === "b" && this.right === op2.right) return true;
    return false;
  }

  /** Check containment of a specific integer. */
  containsVal(val: bigint): boolean {
    if (this.isempty) return false;
    if (this.step !== 1) {
      if ((this.left % BigInt(this.step)) !== (val % BigInt(this.step)))
        return false;
    }
    if (this.left < this.right) {
      if (val < this.left) return false;
      if (this.right <= val) return false;
    } else if (this.right < this.left) {
      if (val < this.right) return true;
      if (val >= this.left) return true;
      return false;
    }
    return true;
  }

  // Convenience overload matching C++ `contains`
  contains(op2: CircleRange): boolean;
  contains(val: bigint): boolean;
  contains(arg: CircleRange | bigint): boolean {
    if (arg instanceof CircleRange) return this.containsRange(arg);
    return this.containsVal(arg);
  }

  /** Intersect this with another range.  Returns 0 if valid, 2 if two pieces. */
  intersect(op2: CircleRange): number {
    if (this.isempty) return 0;
    if (op2.isempty) {
      this.isempty = true;
      return 0;
    }
    const myRef = { left: this.left, right: this.right };
    const op2Ref = { left: op2.left, right: op2.right };
    let newStep: number;
    if (this.step < op2.step) {
      newStep = op2.step;
      const rem = Number(op2Ref.left % BigInt(newStep));
      if (CircleRange.newStride(this.mask, newStep, this.step, rem, myRef)) {
        this.isempty = true;
        return 0;
      }
    } else if (op2.step < this.step) {
      newStep = this.step;
      const rem = Number(myRef.left % BigInt(newStep));
      if (CircleRange.newStride(op2.mask, newStep, op2.step, rem, op2Ref)) {
        this.isempty = true;
        return 0;
      }
    } else {
      newStep = this.step;
    }
    const newMask = this.mask & op2.mask;
    if (this.mask !== newMask) {
      if (CircleRange.newDomain(newMask, newStep, myRef)) {
        this.isempty = true;
        return 0;
      }
    } else if (op2.mask !== newMask) {
      if (CircleRange.newDomain(newMask, newStep, op2Ref)) {
        this.isempty = true;
        return 0;
      }
    }

    let retval: number;
    if (myRef.left === myRef.right) {
      this.left = op2Ref.left;
      this.right = op2Ref.right;
      retval = 0;
    } else if (op2Ref.left === op2Ref.right) {
      this.left = myRef.left;
      this.right = myRef.right;
      retval = 0;
    } else {
      const overlapCode = CircleRange.encodeRangeOverlaps(
        myRef.left, myRef.right, op2Ref.left, op2Ref.right
      );
      switch (overlapCode) {
        case "a":
        case "f":
          this.isempty = true;
          retval = 0;
          break;
        case "b":
          this.left = op2Ref.left;
          this.right = myRef.right;
          if (this.left === this.right) this.isempty = true;
          retval = 0;
          break;
        case "c":
          this.left = op2Ref.left;
          this.right = op2Ref.right;
          retval = 0;
          break;
        case "d":
          this.left = myRef.left;
          this.right = myRef.right;
          retval = 0;
          break;
        case "e":
          this.left = myRef.left;
          this.right = op2Ref.right;
          if (this.left === this.right) this.isempty = true;
          retval = 0;
          break;
        case "g":
          if (myRef.left === op2Ref.right) {
            this.left = op2Ref.left;
            this.right = myRef.right;
            if (this.left === this.right) this.isempty = true;
            retval = 0;
          } else if (op2Ref.left === myRef.right) {
            this.left = myRef.left;
            this.right = op2Ref.right;
            if (this.left === this.right) this.isempty = true;
            retval = 0;
          } else {
            retval = 2;
          }
          break;
        default:
          retval = 2;
          break;
      }
    }
    if (retval !== 0) return retval;
    this.mask = newMask;
    this.step = newStep;
    return 0;
  }

  /**
   * Try to create a range given a value that is not necessarily a valid mask.
   * Returns true if the mask is valid and the range is set.
   */
  setNZMask(nzmask: bigint, size: number): boolean {
    const trans = bit_transitions(nzmask, size);
    if (trans > 2) return false;
    const hasstep = (nzmask & 1n) === 0n;
    if (!hasstep && trans === 2) return false;
    this.isempty = false;
    if (trans === 0) {
      this.mask = calc_mask(size);
      if (hasstep) {
        this.step = 1;
        this.left = 0n;
        this.right = 1n;
      } else {
        this.step = 1;
        this.left = 0n;
        this.right = 0n;
      }
      return true;
    }
    const shift = leastsigbit_set(nzmask);
    this.step = 1 << shift;
    this.mask = calc_mask(size);
    this.left = 0n;
    this.right = (nzmask + BigInt(this.step)) & this.mask;
    return true;
  }

  /**
   * Union two ranges.
   * Returns 0 if the result is valid, 2 if the union is two pieces.
   */
  circleUnion(op2: CircleRange): number {
    if (op2.isempty) return 0;
    if (this.isempty) {
      this.left = op2.left;
      this.right = op2.right;
      this.mask = op2.mask;
      this.step = op2.step;
      this.isempty = op2.isempty;
      return 0;
    }
    if (this.mask !== op2.mask) return 2;
    let aRight = this.right;
    let bRight = op2.right;
    let newStep = this.step;
    const stepB = BigInt(this.step);
    const op2StepB = BigInt(op2.step);
    if (this.step < op2.step) {
      if (this.isSingle()) {
        newStep = op2.step;
        aRight = (this.left + BigInt(newStep)) & this.mask;
      } else {
        return 2;
      }
    } else if (op2.step < this.step) {
      if (op2.isSingle()) {
        newStep = this.step;
        bRight = (op2.left + BigInt(newStep)) & this.mask;
      } else {
        return 2;
      }
    }
    const newStepB = BigInt(newStep);
    let rem: bigint;
    if (newStep !== 1) {
      rem = this.left % newStepB;
      if (rem !== (op2.left % newStepB))
        return 2;
    } else {
      rem = 0n;
    }
    if (this.left === aRight || op2.left === bRight) {
      this.left = rem;
      this.right = rem;
      this.step = newStep;
      return 0;
    }

    const overlapCode = CircleRange.encodeRangeOverlaps(this.left, aRight, op2.left, bRight);
    switch (overlapCode) {
      case "a":
      case "f":
        if (aRight === op2.left) {
          this.right = bRight;
          this.step = newStep;
          return 0;
        }
        if (this.left === bRight) {
          this.left = op2.left;
          this.right = aRight;
          this.step = newStep;
          return 0;
        }
        return 2;
      case "b":
        this.right = bRight;
        this.step = newStep;
        return 0;
      case "c":
        this.right = aRight;
        this.step = newStep;
        return 0;
      case "d":
        this.left = op2.left;
        this.right = bRight;
        this.step = newStep;
        return 0;
      case "e":
        this.left = op2.left;
        this.right = aRight;
        this.step = newStep;
        return 0;
      case "g":
        this.left = rem;
        this.right = rem;
        this.step = newStep;
        return 0;
    }
    return -1; // Never reached
  }

  /**
   * Construct minimal range that contains both this and another range.
   * Returns true if the container is everything (full).
   */
  minimalContainer(op2: CircleRange, maxStep: number): boolean {
    if (this.isSingle() && op2.isSingle()) {
      let min: bigint;
      let max: bigint;
      if (this.getMin() < op2.getMin()) {
        min = this.getMin();
        max = op2.getMin();
      } else {
        min = op2.getMin();
        max = this.getMin();
      }
      const diff = max - min;
      if (diff > 0n && diff <= BigInt(maxStep)) {
        if (leastsigbit_set(diff) === mostsigbit_set(diff)) {
          this.step = Number(diff);
          this.left = min;
          this.right = (max + BigInt(this.step)) & this.mask;
          return false;
        }
      }
    }

    let aRight = this.right - BigInt(this.step) + 1n;
    let bRight = op2.right - BigInt(op2.step) + 1n;
    this.step = 1;
    this.mask |= op2.mask;

    const overlapCode = CircleRange.encodeRangeOverlaps(this.left, aRight, op2.left, bRight);
    switch (overlapCode) {
      case "a": {
        const vacantSize1 = this.left + (this.mask - bRight) + 1n;
        const vacantSize2 = op2.left - aRight;
        if (vacantSize1 < vacantSize2) {
          this.left = op2.left;
          this.right = aRight;
        } else {
          this.right = bRight;
        }
        break;
      }
      case "f": {
        const vacantSize1 = op2.left + (this.mask - aRight) + 1n;
        const vacantSize2 = this.left - bRight;
        if (vacantSize1 < vacantSize2) {
          this.right = bRight;
        } else {
          this.left = op2.left;
          this.right = aRight;
        }
        break;
      }
      case "b":
        this.right = bRight;
        break;
      case "c":
        this.right = aRight;
        break;
      case "d":
        this.left = op2.left;
        this.right = bRight;
        break;
      case "e":
        this.left = op2.left;
        this.right = aRight;
        break;
      case "g":
        this.left = 0n;
        this.right = 0n;
        break;
    }
    this.normalize();
    return this.left === this.right;
  }

  /** Convert to complementary range.  Returns the original step size. */
  invert(): number {
    const res = this.step;
    this.step = 1;
    this.complement();
    return res;
  }

  /** Set a new step on this range. */
  setStride(newStep: number, rem: bigint): void {
    const iseverything = !this.isempty && this.left === this.right;
    if (newStep === this.step) return;
    let aRight = this.right - BigInt(this.step);
    this.step = newStep;
    const stepB = BigInt(this.step);
    if (this.step === 1) return;
    let curRem = this.left % stepB;
    this.left = (this.left - curRem) + rem;
    curRem = aRight % stepB;
    aRight = (aRight - curRem) + rem;
    this.right = aRight + stepB;
    if (!iseverything && this.left === this.right)
      this.isempty = true;
  }

  /**
   * Pull-back this through the given unary operator.
   * Returns true if a valid range is formed.
   */
  pullBackUnary(opc: OpCode, inSize: number, outSize: number): boolean {
    if (this.isempty) return true;
    const stepB = BigInt(this.step);
    switch (opc) {
      case OpCode.CPUI_BOOL_NEGATE:
        if (this.convertToBoolean()) break;
        this.left = this.left ^ 1n;
        this.right = this.left + 1n;
        break;
      case OpCode.CPUI_COPY:
        break;
      case OpCode.CPUI_INT_2COMP: {
        const val = (~this.left + 1n + stepB) & this.mask;
        this.left = (~this.right + 1n + stepB) & this.mask;
        this.right = val;
        break;
      }
      case OpCode.CPUI_INT_NEGATE: {
        const val = (~this.left + stepB) & this.mask;
        this.left = (~this.right + stepB) & this.mask;
        this.right = val;
        break;
      }
      case OpCode.CPUI_INT_ZEXT: {
        const inMask = calc_mask(inSize);
        const rem = this.left % stepB;
        const zextrange = new CircleRange();
        zextrange.left = rem;
        zextrange.right = inMask + 1n + rem;
        zextrange.mask = this.mask;
        zextrange.step = this.step;
        zextrange.isempty = false;
        if (0 !== this.intersect(zextrange))
          return false;
        this.left &= inMask;
        this.right &= inMask;
        this.mask &= inMask;
        break;
      }
      case OpCode.CPUI_INT_SEXT: {
        const inMask = calc_mask(inSize);
        const rem = this.left & stepB;
        const sextrange = new CircleRange();
        sextrange.left = inMask ^ (inMask >> 1n); // High order bit for (small) input space
        sextrange.left += rem;
        sextrange.right = sign_extend_sizes(sextrange.left, inSize, outSize);
        sextrange.mask = this.mask;
        sextrange.step = this.step;
        sextrange.isempty = false;
        if (sextrange.intersect(this) !== 0) {
          return false;
        } else {
          if (!sextrange.isEmpty()) {
            return false;
          } else {
            this.left &= inMask;
            this.right &= inMask;
            this.mask &= inMask;
          }
        }
        break;
      }
      default:
        return false;
    }
    return true;
  }

  /**
   * Pull-back this through binary operator.
   * Returns true if a valid range is formed.
   */
  pullBackBinary(opc: OpCode, val: bigint, slot: number, inSize: number, outSize: number): boolean {
    if (this.isempty) return true;

    let yescomplement: boolean;
    let bothTrueFalse: boolean;

    switch (opc) {
      case OpCode.CPUI_INT_EQUAL:
        bothTrueFalse = this.convertToBoolean();
        this.mask = calc_mask(inSize);
        if (bothTrueFalse) break;
        yescomplement = this.left === 0n;
        this.left = val;
        this.right = (val + 1n) & this.mask;
        if (yescomplement) this.complement();
        break;
      case OpCode.CPUI_INT_NOTEQUAL:
        bothTrueFalse = this.convertToBoolean();
        this.mask = calc_mask(inSize);
        if (bothTrueFalse) break;
        yescomplement = this.left === 0n;
        this.left = (val + 1n) & this.mask;
        this.right = val;
        if (yescomplement) this.complement();
        break;
      case OpCode.CPUI_INT_LESS:
        bothTrueFalse = this.convertToBoolean();
        this.mask = calc_mask(inSize);
        if (bothTrueFalse) break;
        yescomplement = this.left === 0n;
        if (slot === 0) {
          if (val === 0n) {
            this.isempty = true;
          } else {
            this.left = 0n;
            this.right = val;
          }
        } else {
          if (val === this.mask) {
            this.isempty = true;
          } else {
            this.left = (val + 1n) & this.mask;
            this.right = 0n;
          }
        }
        if (yescomplement) this.complement();
        break;
      case OpCode.CPUI_INT_LESSEQUAL:
        bothTrueFalse = this.convertToBoolean();
        this.mask = calc_mask(inSize);
        if (bothTrueFalse) break;
        yescomplement = this.left === 0n;
        if (slot === 0) {
          this.left = 0n;
          this.right = (val + 1n) & this.mask;
        } else {
          this.left = val;
          this.right = 0n;
        }
        if (yescomplement) this.complement();
        break;
      case OpCode.CPUI_INT_SLESS:
        bothTrueFalse = this.convertToBoolean();
        this.mask = calc_mask(inSize);
        if (bothTrueFalse) break;
        yescomplement = this.left === 0n;
        if (slot === 0) {
          if (val === (this.mask >> 1n) + 1n) {
            this.isempty = true;
          } else {
            this.left = (this.mask >> 1n) + 1n;
            this.right = val;
          }
        } else {
          if (val === this.mask >> 1n) {
            this.isempty = true;
          } else {
            this.left = (val + 1n) & this.mask;
            this.right = (this.mask >> 1n) + 1n;
          }
        }
        if (yescomplement) this.complement();
        break;
      case OpCode.CPUI_INT_SLESSEQUAL:
        bothTrueFalse = this.convertToBoolean();
        this.mask = calc_mask(inSize);
        if (bothTrueFalse) break;
        yescomplement = this.left === 0n;
        if (slot === 0) {
          this.left = (this.mask >> 1n) + 1n;
          this.right = (val + 1n) & this.mask;
        } else {
          this.left = val;
          this.right = (this.mask >> 1n) + 1n;
        }
        if (yescomplement) this.complement();
        break;
      case OpCode.CPUI_INT_CARRY:
        bothTrueFalse = this.convertToBoolean();
        this.mask = calc_mask(inSize);
        if (bothTrueFalse) break;
        yescomplement = this.left === 0n;
        if (val === 0n) {
          this.isempty = true;
        } else {
          this.left = ((this.mask - val) + 1n) & this.mask;
          this.right = 0n;
        }
        if (yescomplement) this.complement();
        break;
      case OpCode.CPUI_INT_ADD:
        this.left = (this.left - val) & this.mask;
        this.right = (this.right - val) & this.mask;
        break;
      case OpCode.CPUI_INT_SUB:
        if (slot === 0) {
          this.left = (this.left + val) & this.mask;
          this.right = (this.right + val) & this.mask;
        } else {
          this.left = (val - this.left) & this.mask;
          this.right = (val - this.right) & this.mask;
        }
        break;
      case OpCode.CPUI_INT_RIGHT: {
        if (this.step === 1) {
          const rightBound = (calc_mask(inSize) >> val) + 1n;
          if (
            ((this.left >= rightBound) && (this.right >= rightBound) && (this.left >= this.right)) ||
            ((this.left === 0n) && (this.right >= rightBound)) ||
            (this.left === this.right)
          ) {
            this.left = 0n;
            this.right = 0n;
          } else {
            if (this.left > rightBound) this.left = rightBound;
            if (this.right > rightBound) this.right = 0n;
            this.left = (this.left << val) & this.mask;
            this.right = (this.right << val) & this.mask;
            if (this.left === this.right) this.isempty = true;
          }
        } else {
          return false;
        }
        break;
      }
      case OpCode.CPUI_INT_SRIGHT: {
        if (this.step === 1) {
          const rightb = calc_mask(inSize);
          let leftb = rightb >> (val + 1n);
          const rightbNeg = leftb ^ rightb;
          leftb += 1n;
          if (
            ((this.left >= leftb) && (this.left <= rightbNeg) &&
             (this.right >= leftb) && (this.right <= rightbNeg) &&
             (this.left >= this.right)) ||
            (this.left === this.right)
          ) {
            this.left = 0n;
            this.right = 0n;
          } else {
            if ((this.left > leftb) && (this.left < rightbNeg)) this.left = leftb;
            if ((this.right > leftb) && (this.right < rightbNeg)) this.right = rightbNeg;
            this.left = (this.left << val) & this.mask;
            this.right = (this.right << val) & this.mask;
            if (this.left === this.right) this.isempty = true;
          }
        } else {
          return false;
        }
        break;
      }
      default:
        return false;
    }
    return true;
  }

  /**
   * Pull-back this range through given PcodeOp.
   * Returns the input Varnode or null.
   */
  pullBack(op: PcodeOp, constMarkup: { value: Varnode | null } | null, usenzmask: boolean): Varnode | null {
    let res: Varnode;

    if (op.numInput() === 1) {
      res = op.getIn(0)!;
      if (res.isConstant()) return null;
      if (!this.pullBackUnary(op.code(), res.getSize(), op.getOut()!.getSize()))
        return null;
    } else if (op.numInput() === 2) {
      let constvn: Varnode;
      let val: bigint;
      let slot = 0;
      res = op.getIn(slot)!;
      constvn = op.getIn(1 - slot)!;
      if (res.isConstant()) {
        slot = 1;
        constvn = res;
        res = op.getIn(slot)!;
        if (res.isConstant()) return null;
      } else if (!constvn.isConstant()) {
        return null;
      }
      val = constvn.getOffset();
      const opc = op.code();
      if (!this.pullBackBinary(opc, val, slot, res.getSize(), op.getOut()!.getSize())) {
        if (usenzmask && opc === OpCode.CPUI_SUBPIECE && val === 0n) {
          const msbset = mostsigbit_set(res.getNZMask());
          const msbBytes = Math.floor((msbset + 8) / 8);
          if (op.getOut()!.getSize() < msbBytes)
            return null;
          else {
            this.mask = calc_mask(res.getSize());
          }
        } else {
          return null;
        }
      }
      if (constvn.getSymbolEntry() !== null && constMarkup !== null)
        constMarkup.value = constvn;
    } else {
      return null;
    }

    if (usenzmask) {
      const nzrange = new CircleRange();
      if (!nzrange.setNZMask(res.getNZMask(), res.getSize()))
        return res;
      this.intersect(nzrange);
    }
    return res;
  }

  /**
   * Push-forward through given unary operator.
   * Returns true if the result is known and forms a range.
   */
  pushForwardUnary(opc: OpCode, in1: CircleRange, inSize: number, outSize: number): boolean {
    if (in1.isempty) {
      this.isempty = true;
      return true;
    }
    switch (opc) {
      case OpCode.CPUI_CAST:
      case OpCode.CPUI_COPY:
        this.left = in1.left;
        this.right = in1.right;
        this.mask = in1.mask;
        this.step = in1.step;
        this.isempty = in1.isempty;
        break;
      case OpCode.CPUI_INT_ZEXT:
        this.isempty = false;
        this.step = in1.step;
        this.mask = calc_mask(outSize);
        if (in1.left === in1.right) {
          this.left = in1.left % BigInt(in1.step);
          this.right = in1.mask + 1n + this.left;
        } else {
          this.left = in1.left;
          this.right = (in1.right - BigInt(in1.step)) & in1.mask;
          if (this.right < this.left) return false;
          this.right += BigInt(this.step);
        }
        break;
      case OpCode.CPUI_INT_SEXT:
        this.isempty = false;
        this.step = in1.step;
        this.mask = calc_mask(outSize);
        if (in1.left === in1.right) {
          const rem = in1.left % BigInt(in1.step);
          this.right = calc_mask(inSize) >> 1n;
          this.left = (calc_mask(outSize) ^ this.right) + rem;
          this.right = this.right + 1n + rem;
        } else {
          this.left = sign_extend_sizes(in1.left, inSize, outSize);
          this.right = sign_extend_sizes((in1.right - BigInt(in1.step)) & in1.mask, inSize, outSize);
          // Compare as signed
          const signedRight = sign_extend(this.right, 63);
          const signedLeft = sign_extend(this.left, 63);
          if (signedRight < signedLeft) return false;
          this.right = (this.right + BigInt(this.step)) & this.mask;
        }
        break;
      case OpCode.CPUI_INT_2COMP:
        this.isempty = false;
        this.step = in1.step;
        this.mask = in1.mask;
        this.right = (~in1.left + 1n + BigInt(this.step)) & this.mask;
        this.left = (~in1.right + 1n + BigInt(this.step)) & this.mask;
        this.normalize();
        break;
      case OpCode.CPUI_INT_NEGATE:
        this.isempty = false;
        this.step = in1.step;
        this.mask = in1.mask;
        this.left = (~in1.right + BigInt(this.step)) & this.mask;
        this.right = (~in1.left + BigInt(this.step)) & this.mask;
        this.normalize();
        break;
      case OpCode.CPUI_BOOL_NEGATE:
      case OpCode.CPUI_FLOAT_NAN:
        this.isempty = false;
        this.mask = 0xFFn;
        this.step = 1;
        this.left = 0n;
        this.right = 2n;
        break;
      default:
        return false;
    }
    return true;
  }

  /**
   * Push-forward through given binary operator.
   * Returns true if the result is known and forms a range.
   */
  pushForwardBinary(
    opc: OpCode, in1: CircleRange, in2: CircleRange,
    inSize: number, outSize: number, maxStep: number
  ): boolean {
    if (in1.isempty || in2.isempty) {
      this.isempty = true;
      return true;
    }
    switch (opc) {
      case OpCode.CPUI_PTRSUB:
      case OpCode.CPUI_INT_ADD:
        this.isempty = false;
        this.mask = in1.mask | in2.mask;
        if (in1.left === in1.right || in2.left === in2.right) {
          this.step = in1.step < in2.step ? in1.step : in2.step;
          this.left = (in1.left + in2.left) % BigInt(this.step);
          this.right = this.left;
        } else if (in2.isSingle()) {
          this.step = in1.step;
          this.left = (in1.left + in2.left) & this.mask;
          this.right = (in1.right + in2.left) & this.mask;
        } else if (in1.isSingle()) {
          this.step = in2.step;
          this.left = (in2.left + in1.left) & this.mask;
          this.right = (in2.right + in1.left) & this.mask;
        } else {
          this.step = in1.step < in2.step ? in1.step : in2.step;
          const stepB = BigInt(this.step);
          const in1StepB = BigInt(in1.step);
          const in2StepB = BigInt(in2.step);
          const size1 = in1.left < in1.right
            ? in1.right - in1.left
            : in1.mask - (in1.left - in1.right) + in1StepB;
          this.left = (in1.left + in2.left) & this.mask;
          this.right = (in1.right - in1StepB + in2.right - in2StepB + stepB) & this.mask;
          const sizenew = this.left < this.right
            ? this.right - this.left
            : this.mask - (this.left - this.right) + stepB;
          if (sizenew < size1) {
            this.right = this.left;
          }
          this.normalize();
        }
        break;
      case OpCode.CPUI_INT_MULT: {
        this.isempty = false;
        this.mask = in1.mask | in2.mask;
        let constVal: bigint;
        if (in1.isSingle()) {
          constVal = in1.getMin();
          this.step = in2.step;
        } else if (in2.isSingle()) {
          constVal = in2.getMin();
          this.step = in1.step;
        } else {
          return false;
        }
        let tmp = Number(constVal & 0xFFFFFFFFn);
        while (this.step < maxStep) {
          if ((tmp & 1) !== 0) break;
          this.step <<= 1;
          tmp >>= 1;
        }
        const wholeSize = 64 - count_leading_zeros(this.mask);
        if (in1.getMaxInfo() + in2.getMaxInfo() > wholeSize) {
          this.left = (in1.left * in2.left) % BigInt(this.step);
          this.right = this.left;
          this.normalize();
          return true;
        }
        if ((constVal & (this.mask ^ (this.mask >> 1n))) !== 0n) {
          this.left = ((in1.right - BigInt(in1.step)) * (in2.right - BigInt(in2.step))) & this.mask;
          this.right = (in1.left * in2.left + BigInt(this.step)) & this.mask;
        } else {
          this.left = (in1.left * in2.left) & this.mask;
          this.right = ((in1.right - BigInt(in1.step)) * (in2.right - BigInt(in2.step)) + BigInt(this.step)) & this.mask;
        }
        break;
      }
      case OpCode.CPUI_INT_LEFT: {
        if (!in2.isSingle()) return false;
        this.isempty = false;
        this.mask = in1.mask;
        this.step = in1.step;
        const sa = Number(in2.getMin());
        let tmp2 = sa;
        while (this.step < maxStep && tmp2 > 0) {
          this.step <<= 1;
          tmp2 -= 1;
        }
        const saB = BigInt(sa);
        this.left = (in1.left << saB) & this.mask;
        this.right = (in1.right << saB) & this.mask;
        const wholeSize = 64 - count_leading_zeros(this.mask);
        if (in1.getMaxInfo() + sa > wholeSize) {
          this.right = this.left;
          this.normalize();
          return true;
        }
        break;
      }
      case OpCode.CPUI_SUBPIECE: {
        if (!in2.isSingle()) return false;
        this.isempty = false;
        const sa = Number(in2.left) * 8;
        const saB = BigInt(sa);
        this.mask = calc_mask(outSize);
        this.step = sa === 0 ? in1.step : 1;
        const stepB = BigInt(this.step);
        const range = in1.left < in1.right
          ? in1.right - in1.left
          : in1.left - in1.right;
        if (range === 0n || ((range >> saB) > this.mask)) {
          this.left = 0n;
          this.right = 0n;
        } else {
          this.left = in1.left >> saB;
          this.right = ((in1.right - BigInt(in1.step)) >> saB) + stepB;
          this.left &= this.mask;
          this.right &= this.mask;
          this.normalize();
        }
        break;
      }
      case OpCode.CPUI_INT_RIGHT: {
        if (!in2.isSingle()) return false;
        this.isempty = false;
        const sa = Number(in2.left);
        const saB = BigInt(sa);
        this.mask = calc_mask(outSize);
        this.step = 1;
        if (in1.left < in1.right) {
          this.left = in1.left >> saB;
          this.right = ((in1.right - BigInt(in1.step)) >> saB) + 1n;
        } else {
          this.left = 0n;
          this.right = in1.mask >> saB;
        }
        if (this.left === this.right)
          this.right = (this.left + 1n) & this.mask;
        break;
      }
      case OpCode.CPUI_INT_SRIGHT: {
        if (!in2.isSingle()) return false;
        this.isempty = false;
        const sa = Number(in2.left);
        const saB = BigInt(sa);
        this.mask = calc_mask(outSize);
        this.step = 1;
        const bitPos = 8 * inSize - 1;
        let valLeft = sign_extend(in1.left, bitPos);
        let valRight = sign_extend(in1.right, bitPos);
        if (valLeft >= valRight) {
          valRight = this.mask >> 1n;       // Max positive
          valLeft = valRight + 1n;          // Min negative
          valLeft = sign_extend(valLeft, bitPos);
        }
        this.left = (valLeft >> saB) & this.mask;
        this.right = (((valRight - BigInt(in1.step)) >> saB) + 1n) & this.mask;
        if (this.left === this.right)
          this.right = (this.left + 1n) & this.mask;
        break;
      }
      case OpCode.CPUI_INT_EQUAL:
      case OpCode.CPUI_INT_NOTEQUAL:
      case OpCode.CPUI_INT_SLESS:
      case OpCode.CPUI_INT_SLESSEQUAL:
      case OpCode.CPUI_INT_LESS:
      case OpCode.CPUI_INT_LESSEQUAL:
      case OpCode.CPUI_INT_CARRY:
      case OpCode.CPUI_INT_SCARRY:
      case OpCode.CPUI_INT_SBORROW:
      case OpCode.CPUI_BOOL_XOR:
      case OpCode.CPUI_BOOL_AND:
      case OpCode.CPUI_BOOL_OR:
      case OpCode.CPUI_FLOAT_EQUAL:
      case OpCode.CPUI_FLOAT_NOTEQUAL:
      case OpCode.CPUI_FLOAT_LESS:
      case OpCode.CPUI_FLOAT_LESSEQUAL:
        this.isempty = false;
        this.mask = 0xFFn;
        this.step = 1;
        this.left = 0n;
        this.right = 2n;
        break;
      default:
        return false;
    }
    return true;
  }

  /**
   * Push-forward through given trinary operator (currently only CPUI_PTRADD).
   * Returns true if the result is known and forms a range.
   */
  pushForwardTrinary(
    opc: OpCode, in1: CircleRange, in2: CircleRange, in3: CircleRange,
    inSize: number, outSize: number, maxStep: number
  ): boolean {
    if (opc !== OpCode.CPUI_PTRADD) return false;
    const tmpRange = new CircleRange();
    if (!tmpRange.pushForwardBinary(OpCode.CPUI_INT_MULT, in2, in3, inSize, inSize, maxStep))
      return false;
    return this.pushForwardBinary(OpCode.CPUI_INT_ADD, in1, tmpRange, inSize, outSize, maxStep);
  }

  /**
   * Widen the unstable bound to match containing range.
   * @param op2 the containing range
   * @param leftIsStable true if we want to match right boundaries
   */
  widen(op2: CircleRange, leftIsStable: boolean): void {
    const stepB = BigInt(this.step);
    if (leftIsStable) {
      const lmod = this.left % stepB;
      const mod = op2.right % stepB;
      if (mod <= lmod)
        this.right = op2.right + (lmod - mod);
      else
        this.right = op2.right - (mod - lmod);
      this.right &= this.mask;
    } else {
      this.left = op2.left & this.mask;
    }
    this.normalize();
  }

  /**
   * Translate range to a comparison op.
   * Returns:
   *   0 on success,
   *   1 if all inputs must return true,
   *   2 if this is not possible,
   *   3 if no inputs must return true
   */
  translate2Op(result: { opc: OpCode; c: bigint; cslot: number }): number {
    if (this.isempty) return 3;
    if (this.step !== 1) return 2;
    if (this.right === ((this.left + 1n) & this.mask)) {
      result.opc = OpCode.CPUI_INT_EQUAL;
      result.cslot = 0;
      result.c = this.left;
      return 0;
    }
    if (this.left === ((this.right + 1n) & this.mask)) {
      result.opc = OpCode.CPUI_INT_NOTEQUAL;
      result.cslot = 0;
      result.c = this.right;
      return 0;
    }
    if (this.left === this.right) return 1;
    if (this.left === 0n) {
      result.opc = OpCode.CPUI_INT_LESS;
      result.cslot = 1;
      result.c = this.right;
      return 0;
    }
    if (this.right === 0n) {
      result.opc = OpCode.CPUI_INT_LESS;
      result.cslot = 0;
      result.c = (this.left - 1n) & this.mask;
      return 0;
    }
    if (this.left === (this.mask >> 1n) + 1n) {
      result.opc = OpCode.CPUI_INT_SLESS;
      result.cslot = 1;
      result.c = this.right;
      return 0;
    }
    if (this.right === (this.mask >> 1n) + 1n) {
      result.opc = OpCode.CPUI_INT_SLESS;
      result.cslot = 0;
      result.c = (this.left - 1n) & this.mask;
      return 0;
    }
    return 2;
  }

  /** Write a text representation of this to stream. */
  printRaw(s: { write(str: string): void }): void {
    if (this.isempty) {
      s.write("(empty)");
      return;
    }
    if (this.left === this.right) {
      s.write("(full");
      if (this.step !== 1)
        s.write("," + this.step.toString());
      s.write(")");
    } else if (this.right === ((this.left + 1n) & this.mask)) {
      s.write("[" + this.left.toString(16) + "]");
    } else {
      s.write("[" + this.left.toString(16) + "," + this.right.toString(16));
      if (this.step !== 1)
        s.write("," + this.step.toString());
      s.write(")");
    }
  }
}

// ---------------------------------------------------------------------------
// ValueSet
// ---------------------------------------------------------------------------

/**
 * A range of values attached to a Varnode within a data-flow subsystem.
 *
 * This class acts as both the set of values for the Varnode and as a node in a
 * sub-graph overlaying the full data-flow of the function containing the Varnode.
 */
export class ValueSet {
  static readonly MAX_STEP: number = 32;

  /** typeCode: 0=pure constant, 1=stack relative */
  typeCode: number = 0;
  /** Number of input parameters to defining operation */
  numParams: number = 0;
  /** Depth first numbering / widening count */
  count: number = 0;
  /** Op-code defining Varnode */
  opCode: OpCode = OpCode.CPUI_MAX;
  /** Set to true if left boundary of range didn't change (last iteration) */
  leftIsStable: boolean = false;
  /** Set to true if right boundary of range didn't change (last iteration) */
  rightIsStable: boolean = false;
  /** Varnode whose set this represents */
  vn: Varnode | null = null;
  /** Range of values or offsets in this set */
  range: CircleRange = new CircleRange();
  /** Any equations associated with this value set */
  equations: ValueSetEquation[] = [];
  /** If Varnode is a component head, pointer to corresponding Partition */
  partHead: PartitionNode | null = null;
  /** Next ValueSet to iterate */
  next: ValueSet | null = null;

  /** Does the indicated equation apply for the given input slot */
  doesEquationApply(num: number, slot: number): boolean {
    if (num < this.equations.length) {
      if (this.equations[num].slot === slot) {
        if (this.equations[num].typeCode === this.typeCode)
          return true;
      }
    }
    return false;
  }

  /** Mark value set as possibly containing any value */
  setFull(): void {
    if (this.vn !== null) {
      this.range.setFull(this.vn.getSize());
    }
    this.typeCode = 0;
  }

  /** Attach this to given Varnode and set initial values */
  setVarnode(v: Varnode, tCode: number): void {
    this.typeCode = tCode;
    this.vn = v;
    (v as any).setValueSet(this);
    if (this.typeCode !== 0) {
      this.opCode = OpCode.CPUI_MAX;
      this.numParams = 0;
      this.range.setRange(0n, v.getSize());
      this.leftIsStable = true;
      this.rightIsStable = true;
    } else if ((v as any).isWritten()) {
      const op: PcodeOp = (v as any).getDef();
      this.opCode = op.code();
      if (this.opCode === OpCode.CPUI_INDIRECT) {
        this.numParams = 1;
        this.opCode = OpCode.CPUI_COPY;
      } else {
        this.numParams = op.numInput();
      }
      this.leftIsStable = false;
      this.rightIsStable = false;
    } else if (v.isConstant()) {
      this.opCode = OpCode.CPUI_MAX;
      this.numParams = 0;
      this.range.setRange(v.getOffset(), v.getSize());
      this.leftIsStable = true;
      this.rightIsStable = true;
    } else {
      this.opCode = OpCode.CPUI_MAX;
      this.numParams = 0;
      this.typeCode = 0;
      this.range.setFull(v.getSize());
      this.leftIsStable = false;
      this.rightIsStable = false;
    }
  }

  /** Insert an equation restricting this value set */
  addEquation(slot: number, type: number, constraint: CircleRange): void {
    let i = 0;
    while (i < this.equations.length) {
      if (this.equations[i].slot > slot) break;
      i++;
    }
    this.equations.splice(i, 0, new ValueSetEquation(slot, type, constraint));
  }

  /** Add a widening landmark */
  addLandmark(type: number, constraint: CircleRange): void {
    this.addEquation(this.numParams, type, constraint);
  }

  /** Figure out if this value set is absolute or relative */
  computeTypeCode(): boolean {
    let relCount = 0;
    let lastTypeCode = 0;
    const op: PcodeOp = (this.vn as any).getDef();
    for (let i = 0; i < this.numParams; i++) {
      const valueSet: ValueSet | null = (op.getIn(i) as any).getValueSet();
      if (valueSet === null || valueSet === undefined) continue;
      if (valueSet.typeCode !== 0) {
        relCount += 1;
        lastTypeCode = valueSet.typeCode;
      }
    }
    if (relCount === 0) {
      this.typeCode = 0;
      return false;
    }
    switch (this.opCode) {
      case OpCode.CPUI_PTRSUB:
      case OpCode.CPUI_PTRADD:
      case OpCode.CPUI_INT_ADD:
      case OpCode.CPUI_INT_SUB:
        if (relCount === 1)
          this.typeCode = lastTypeCode;
        else
          return true;
        break;
      case OpCode.CPUI_CAST:
      case OpCode.CPUI_COPY:
      case OpCode.CPUI_INDIRECT:
      case OpCode.CPUI_MULTIEQUAL:
        this.typeCode = lastTypeCode;
        break;
      default:
        return true;
    }
    return false;
  }

  /** Regenerate this value set from operator inputs. Returns true if there was a change. */
  iterate(widener: Widener): boolean {
    if (this.vn === null || !(this.vn as any).isWritten()) return false;
    if (widener.checkFreeze(this)) return false;
    if (this.count === 0) {
      if (this.computeTypeCode()) {
        this.setFull();
        return true;
      }
    }
    this.count += 1;
    const res = new CircleRange();
    const op: PcodeOp = (this.vn as any).getDef();
    let eqPos = 0;

    if (this.opCode === OpCode.CPUI_MULTIEQUAL) {
      let pieces = 0;
      for (let i = 0; i < this.numParams; i++) {
        const inSet: ValueSet | null = (op.getIn(i) as any).getValueSet();
        if (inSet === null || inSet === undefined) {
          this.setFull();
          return true;
        }
        if (this.doesEquationApply(eqPos, i)) {
          const rangeCopy = new CircleRange(inSet.range.getMin(), inSet.range.getEnd(), 0, inSet.range.getStep());
          // deep copy via setRange
          rangeCopy.setRange(inSet.range.getMin(), inSet.range.getEnd(), 0, inSet.range.getStep());
          if (0 !== rangeCopy.intersect(this.equations[eqPos].range)) {
            // Use equation range directly (approximate)
            Object.assign(rangeCopy, this.equations[eqPos].range);
          }
          pieces = res.circleUnion(rangeCopy);
          eqPos += 1;
        } else {
          pieces = res.circleUnion(inSet.range);
        }
        if (pieces === 2) {
          if (res.minimalContainer(inSet.range, ValueSet.MAX_STEP))
            break;
        }
      }
      if (0 !== res.circleUnion(this.range)) {
        res.minimalContainer(this.range, ValueSet.MAX_STEP);
      }
      if (!this.range.isEmpty() && !res.isEmpty()) {
        this.leftIsStable = this.range.getMin() === res.getMin();
        this.rightIsStable = this.range.getEnd() === res.getEnd();
      }
    } else if (this.numParams === 1) {
      const inSet1: ValueSet | null = (op.getIn(0) as any).getValueSet();
      if (inSet1 === null || inSet1 === undefined) {
        this.setFull();
        return true;
      }
      if (this.doesEquationApply(eqPos, 0)) {
        const rangeCopy = new CircleRange();
        Object.assign(rangeCopy, inSet1.range);
        if (0 !== rangeCopy.intersect(this.equations[eqPos].range)) {
          Object.assign(rangeCopy, this.equations[eqPos].range);
        }
        if (!res.pushForwardUnary(this.opCode, rangeCopy, (inSet1.vn as any).getSize(), this.vn!.getSize())) {
          this.setFull();
          return true;
        }
        eqPos += 1;
      } else if (!res.pushForwardUnary(this.opCode, inSet1.range, (inSet1.vn as any).getSize(), this.vn!.getSize())) {
        this.setFull();
        return true;
      }
      this.leftIsStable = inSet1.leftIsStable;
      this.rightIsStable = inSet1.rightIsStable;
    } else if (this.numParams === 2) {
      const inSet1: ValueSet | null = (op.getIn(0) as any).getValueSet();
      const inSet2: ValueSet | null = (op.getIn(1) as any).getValueSet();
      if (inSet1 === null || inSet1 === undefined || inSet2 === null || inSet2 === undefined) {
        this.setFull();
        return true;
      }
      if (this.equations.length === 0) {
        if (!res.pushForwardBinary(
          this.opCode, inSet1.range, inSet2.range,
          (inSet1.vn as any).getSize(), this.vn!.getSize(), ValueSet.MAX_STEP
        )) {
          this.setFull();
          return true;
        }
      } else {
        const range1 = new CircleRange();
        Object.assign(range1, inSet1.range);
        const range2 = new CircleRange();
        Object.assign(range2, inSet2.range);
        if (this.doesEquationApply(eqPos, 0)) {
          if (0 !== range1.intersect(this.equations[eqPos].range))
            Object.assign(range1, this.equations[eqPos].range);
          eqPos += 1;
        }
        if (this.doesEquationApply(eqPos, 1)) {
          if (0 !== range2.intersect(this.equations[eqPos].range))
            Object.assign(range2, this.equations[eqPos].range);
        }
        if (!res.pushForwardBinary(
          this.opCode, range1, range2,
          (inSet1.vn as any).getSize(), this.vn!.getSize(), ValueSet.MAX_STEP
        )) {
          this.setFull();
          return true;
        }
      }
      this.leftIsStable = inSet1.leftIsStable && inSet2.leftIsStable;
      this.rightIsStable = inSet1.rightIsStable && inSet2.rightIsStable;
    } else if (this.numParams === 3) {
      const inSet1: ValueSet | null = (op.getIn(0) as any).getValueSet();
      const inSet2: ValueSet | null = (op.getIn(1) as any).getValueSet();
      const inSet3: ValueSet | null = (op.getIn(2) as any).getValueSet();
      if (inSet1 === null || inSet1 === undefined || inSet2 === null || inSet2 === undefined || inSet3 === null || inSet3 === undefined) {
        this.setFull();
        return true;
      }
      const range1 = new CircleRange();
      Object.assign(range1, inSet1.range);
      const range2 = new CircleRange();
      Object.assign(range2, inSet2.range);
      if (this.doesEquationApply(eqPos, 0)) {
        if (0 !== range1.intersect(this.equations[eqPos].range))
          Object.assign(range1, this.equations[eqPos].range);
        eqPos += 1;
      }
      if (this.doesEquationApply(eqPos, 1)) {
        if (0 !== range2.intersect(this.equations[eqPos].range))
          Object.assign(range2, this.equations[eqPos].range);
      }
      if (!res.pushForwardTrinary(
        this.opCode, range1, range2, inSet3.range,
        (inSet1.vn as any).getSize(), this.vn!.getSize(), ValueSet.MAX_STEP
      )) {
        this.setFull();
        return true;
      }
      this.leftIsStable = inSet1.leftIsStable && inSet2.leftIsStable;
      this.rightIsStable = inSet1.rightIsStable && inSet2.rightIsStable;
    } else {
      return false;
    }

    if (res.equals(this.range))
      return false;
    if (this.partHead !== null) {
      if (!widener.doWidening(this, this.range, res))
        this.setFull();
    } else {
      this.range = res;
    }
    return true;
  }

  /** Get the current iteration count */
  getCount(): number { return this.count; }

  /** Get any landmark range */
  getLandMark(): CircleRange | null {
    // Any equation can serve as a landmark.  We prefer the one restricting the
    // value of an input branch, as these usually give a tighter approximation
    // of the stable point.
    for (let i = 0; i < this.equations.length; i++) {
      if (this.equations[i].typeCode === this.typeCode)
        return this.equations[i].range;
    }
    return null;
  }

  /** Return '0' for normal constant, '1' for spacebase relative */
  getTypeCode(): number { return this.typeCode; }

  /** Get the Varnode attached to this ValueSet */
  getVarnode(): Varnode | null { return this.vn; }

  /** Get the actual range of values */
  getRange(): CircleRange { return this.range; }

  /** Return true if the left boundary hasn't been changing */
  isLeftStable(): boolean { return this.leftIsStable; }

  /** Return true if the right boundary hasn't been changing */
  isRightStable(): boolean { return this.rightIsStable; }

  /** Write a text description to the given stream */
  printRaw(s: { write(str: string): void }): void {
    if (this.vn === null)
      s.write("root");
    else
      (this.vn as any).printRaw(s);
    if (this.typeCode === 0)
      s.write(" absolute");
    else
      s.write(" stackptr");
    if (this.opCode === OpCode.CPUI_MAX) {
      if (this.vn !== null && this.vn.isConstant())
        s.write(" const");
      else
        s.write(" input");
    } else {
      s.write(" " + get_opname(this.opCode));
    }
    s.write(" ");
    this.range.printRaw(s);
  }
}

// ---------------------------------------------------------------------------
// ValueSet.Equation (inner class)
// ---------------------------------------------------------------------------

/**
 * An external equation that can be applied to a ValueSet.
 */
export class ValueSetEquation {
  slot: number;
  typeCode: number;
  range: CircleRange;

  constructor(s: number, tc: number, rng: CircleRange) {
    this.slot = s;
    this.typeCode = tc;
    this.range = rng;
  }
}

// ---------------------------------------------------------------------------
// PartitionNode
// ---------------------------------------------------------------------------

/**
 * A range of nodes (within the weak topological ordering) that are iterated together.
 */
export class PartitionNode {
  startNode: ValueSet | null = null;
  stopNode: ValueSet | null = null;
  isDirty: boolean = false;

  constructor() {}
}

// ---------------------------------------------------------------------------
// ValueSetRead
// ---------------------------------------------------------------------------

/**
 * A special form of ValueSet associated with the read point of a Varnode.
 */
export class ValueSetRead {
  typeCode: number = 0;
  slot: number = 0;
  op: PcodeOp | null = null;
  range: CircleRange = new CircleRange();
  equationConstraint: CircleRange = new CircleRange();
  equationTypeCode: number = 0;
  leftIsStable: boolean = false;
  rightIsStable: boolean = false;

  /** Establish read this value set corresponds to */
  setPcodeOp(o: PcodeOp, slt: number): void {
    this.typeCode = 0;
    this.op = o;
    this.slot = slt;
    this.equationTypeCode = -1;
  }

  /** Insert an equation restricting this value set */
  addEquation(slt: number, type: number, constraint: CircleRange): void {
    if (this.slot === slt) {
      this.equationTypeCode = type;
      this.equationConstraint = constraint;
    }
  }

  /** Return '0' for normal constant, '1' for spacebase relative */
  getTypeCode(): number { return this.typeCode; }

  /** Get the actual range of values */
  getRange(): CircleRange { return this.range; }

  /** Return true if the left boundary hasn't been changing */
  isLeftStable(): boolean { return this.leftIsStable; }

  /** Return true if the right boundary hasn't been changing */
  isRightStable(): boolean { return this.rightIsStable; }

  /** Compute this value set */
  compute(): void {
    if (this.op === null) return;
    const vn: Varnode = this.op.getIn(this.slot)!;
    const valueSet: ValueSet = (vn as any).getValueSet();
    this.typeCode = valueSet.getTypeCode();
    this.range = valueSet.getRange();
    this.leftIsStable = valueSet.isLeftStable();
    this.rightIsStable = valueSet.isRightStable();
    if (this.typeCode === this.equationTypeCode) {
      if (0 !== this.range.intersect(this.equationConstraint)) {
        this.range = this.equationConstraint;
      }
    }
  }

  /** Write a text description to the given stream */
  printRaw(s: { write(str: string): void }): void {
    if (this.op !== null) {
      s.write("Read: " + get_opname(this.op.code()));
      s.write("(" + (this.op as any).getSeqNum() + ")");
    }
    if (this.typeCode === 0)
      s.write(" absolute ");
    else
      s.write(" stackptr ");
    this.range.printRaw(s);
  }
}

// ---------------------------------------------------------------------------
// Widener (abstract base class)
// ---------------------------------------------------------------------------

/**
 * Class holding a particular widening strategy for the ValueSetSolver
 * iteration algorithm.
 */
export abstract class Widener {
  /**
   * Upon entering a fresh partition, determine how the given ValueSet count
   * should be reset.
   */
  abstract determineIterationReset(valueSet: ValueSet): number;

  /**
   * Check if the given value set has been frozen for the remainder of the
   * iteration process.
   */
  abstract checkFreeze(valueSet: ValueSet): boolean;

  /**
   * For an iteration that isn't stabilizing, attempt to widen the given ValueSet.
   * Change the given range based on its previous iteration so that it stabilizes
   * more rapidly on future iterations.
   * Returns true if widening succeeded.
   */
  abstract doWidening(valueSet: ValueSet, range: CircleRange, newRange: CircleRange): boolean;
}

// ---------------------------------------------------------------------------
// WidenerFull
// ---------------------------------------------------------------------------

/**
 * Class for doing normal widening.
 *
 * Widening is attempted at a specific iteration. If a landmark is available, it is
 * used to do a controlled widening, holding the stable range boundary constant.
 * Otherwise a full range is produced.
 */
export class WidenerFull extends Widener {
  private widenIteration: number;
  private fullIteration: number;

  constructor(wide?: number, full?: number) {
    super();
    this.widenIteration = wide !== undefined ? wide : 2;
    this.fullIteration = full !== undefined ? full : 5;
  }

  determineIterationReset(valueSet: ValueSet): number {
    if (valueSet.getCount() >= this.widenIteration)
      return this.widenIteration;
    return 0;
  }

  checkFreeze(valueSet: ValueSet): boolean {
    return valueSet.getRange().isFull();
  }

  doWidening(valueSet: ValueSet, range: CircleRange, newRange: CircleRange): boolean {
    if (valueSet.count < this.widenIteration) {
      Object.assign(range, newRange);
      return true;
    } else if (valueSet.count === this.widenIteration) {
      const landmark = valueSet.getLandMark();
      if (landmark !== null) {
        const leftIsStable = range.getMin() === newRange.getMin();
        Object.assign(range, newRange);
        if (landmark.contains(range)) {
          range.widen(landmark, leftIsStable);
          return true;
        } else {
          const constraint = new CircleRange();
          Object.assign(constraint, landmark);
          constraint.invert();
          if (constraint.contains(range)) {
            range.widen(constraint, leftIsStable);
            return true;
          }
        }
      }
    } else if (valueSet.count < this.fullIteration) {
      Object.assign(range, newRange);
      return true;
    }
    return false;
  }
}

// ---------------------------------------------------------------------------
// WidenerNone
// ---------------------------------------------------------------------------

/**
 * Class for freezing value sets at a specific iteration (to accelerate convergence).
 */
export class WidenerNone extends Widener {
  private freezeIteration: number;

  constructor() {
    super();
    this.freezeIteration = 3;
  }

  determineIterationReset(valueSet: ValueSet): number {
    return 0;
  }

  checkFreeze(valueSet: ValueSet): boolean {
    return valueSet.count >= this.freezeIteration;
  }

  doWidening(valueSet: ValueSet, range: CircleRange, newRange: CircleRange): boolean {
    Object.assign(range, newRange);
    return true;
  }
}

// ---------------------------------------------------------------------------
// ValueSetSolver
// ---------------------------------------------------------------------------

/**
 * Class that determines a ValueSet for each Varnode in a data-flow system.
 *
 * Uses value set analysis to calculate (an overestimation of) the range of values
 * that can reach each Varnode.
 */
export class ValueSetSolver {
  /** Storage for all the current value sets */
  private valueNodes: ValueSet[] = [];
  /** Additional, after iteration, add-on value sets */
  private readNodes: Map<string, ValueSetRead> = new Map();
  /** Value sets in iteration order */
  private orderPartition: PartitionNode = new PartitionNode();
  /** Storage for the Partitions establishing components */
  private recordStorage: PartitionNode[] = [];
  /** Values treated as inputs */
  private rootNodes: ValueSet[] = [];
  /** Stack used to generate the topological ordering */
  private nodeStack: ValueSet[] = [];
  /** (Global) depth first numbering for topological ordering */
  private depthFirstIndex: number = 0;
  /** Count of individual ValueSet iterations */
  private numIterations: number = 0;
  /** Maximum number of iterations before forcing termination */
  private maxIterations: number = 0;

  // ----- ValueSetEdge (inner helper) -----

  /** Create an edge iterator for a ValueSet node */
  private static createEdgeIterator(
    node: ValueSet,
    roots: ValueSet[]
  ): { rootEdges: ValueSet[] | null; rootPos: number; vn: Varnode | null; iterIdx: number } {
    const vn = node.getVarnode();
    if (vn === null) {
      // Simulated root
      return { rootEdges: roots, rootPos: 0, vn: null, iterIdx: 0 };
    }
    else {
      return { rootEdges: null, rootPos: 0, vn: vn, iterIdx: 0 };
    }
  }

  /** Get the next ValueSet from the edge iterator */
  private static edgeGetNext(
    edge: { rootEdges: ValueSet[] | null; rootPos: number; vn: Varnode | null; iterIdx: number }
  ): ValueSet | null {
    if (edge.vn === null) {
      // Simulated root
      if (edge.rootEdges !== null && edge.rootPos < edge.rootEdges.length) {
        const res = edge.rootEdges[edge.rootPos];
        edge.rootPos += 1;
        return res;
      }
      return null;
    }
    const descendants = (edge.vn as any).getDescendants();
    while (edge.iterIdx < descendants.length) {
      const op = descendants[edge.iterIdx];
      edge.iterIdx += 1;
      const outVn = op.getOut();
      if (outVn !== null && outVn.isMark()) {
        return (outVn as any).getValueSet();
      }
    }
    return null;
  }

  // ----- Partition helpers -----

  /** Prepend a vertex to a partition */
  private static partitionPrependVertex(vertex: ValueSet, part: PartitionNode): void {
    vertex.next = part.startNode;
    part.startNode = vertex;
    if (part.stopNode === null)
      part.stopNode = vertex;
  }

  /** Prepend full Partition to given Partition */
  private static partitionPrependPartition(head: PartitionNode, part: PartitionNode): void {
    if (head.stopNode !== null)
      head.stopNode.next = part.startNode;
    part.startNode = head.startNode;
    if (part.stopNode === null)
      part.stopNode = head.stopNode;
  }

  // ----- Private methods -----

  /** Allocate storage for a new ValueSet */
  private newValueSet(vn: Varnode, tCode: number): void {
    const vs = new ValueSet();
    this.valueNodes.push(vs);
    vs.setVarnode(vn, tCode);
  }

  /** Save a Partition to permanent storage */
  private partitionSurround(part: PartitionNode): void {
    this.recordStorage.push(new PartitionNode());
    const stored = this.recordStorage[this.recordStorage.length - 1];
    stored.startNode = part.startNode;
    stored.stopNode = part.stopNode;
    stored.isDirty = part.isDirty;
    part.startNode!.partHead = stored;
  }

  /** Generate a partition component given its head */
  private component(vertex: ValueSet, part: PartitionNode): void {
    const edgeIterator = ValueSetSolver.createEdgeIterator(vertex, this.rootNodes);
    let succ = ValueSetSolver.edgeGetNext(edgeIterator);
    while (succ !== null) {
      if (succ.count === 0)
        this.visit(succ, part);
      succ = ValueSetSolver.edgeGetNext(edgeIterator);
    }
    ValueSetSolver.partitionPrependVertex(vertex, part);
    this.partitionSurround(part);
  }

  /** Recursively walk the data-flow graph finding partitions */
  private visit(vertex: ValueSet, part: PartitionNode): number {
    this.nodeStack.push(vertex);
    this.depthFirstIndex += 1;
    vertex.count = this.depthFirstIndex;
    let head = this.depthFirstIndex;
    let loop = false;
    const edgeIterator = ValueSetSolver.createEdgeIterator(vertex, this.rootNodes);
    let succ = ValueSetSolver.edgeGetNext(edgeIterator);
    while (succ !== null) {
      let min: number;
      if (succ.count === 0)
        min = this.visit(succ, part);
      else
        min = succ.count;
      if (min <= head) {
        head = min;
        loop = true;
      }
      succ = ValueSetSolver.edgeGetNext(edgeIterator);
    }
    if (head === vertex.count) {
      vertex.count = 0x7fffffff;  // Set to "infinity"
      let element = this.nodeStack[this.nodeStack.length - 1];
      this.nodeStack.pop();
      if (loop) {
        while (element !== vertex) {
          element.count = 0;
          element = this.nodeStack[this.nodeStack.length - 1];
          this.nodeStack.pop();
        }
        const compPart = new PartitionNode();
        this.component(vertex, compPart);
        ValueSetSolver.partitionPrependPartition(compPart, part);
      }
      else {
        ValueSetSolver.partitionPrependVertex(vertex, part);
      }
    }
    return head;
  }

  /** Establish the recursive node ordering for iteratively solving the value set system */
  private establishTopologicalOrder(): void {
    for (const vs of this.valueNodes) {
      vs.count = 0;
      vs.next = null;
      vs.partHead = null;
    }
    const rootNode = new ValueSet();
    rootNode.vn = null;
    this.depthFirstIndex = 0;
    this.visit(rootNode, this.orderPartition);
    this.orderPartition.startNode = this.orderPartition.startNode!.next;  // Remove simulated root
  }

  /** Generate an equation given a true constraint */
  private generateTrueEquation(vn: Varnode | null, op: PcodeOp, slot: number, type: number, range: CircleRange): void {
    if (vn !== null)
      (vn as any).getValueSet().addEquation(slot, type, range);
    else {
      const key = (op as any).getSeqNum().toString();
      const readNode = this.readNodes.get(key);
      if (readNode !== undefined)
        readNode.addEquation(slot, type, range);
    }
  }

  /** Generate the complementary equation given a true constraint */
  private generateFalseEquation(vn: Varnode | null, op: PcodeOp, slot: number, type: number, range: CircleRange): void {
    const falseRange = new CircleRange();
    falseRange.copyFrom(range);
    falseRange.invert();
    if (vn !== null)
      (vn as any).getValueSet().addEquation(slot, type, falseRange);
    else {
      const key = (op as any).getSeqNum().toString();
      const readNode = this.readNodes.get(key);
      if (readNode !== undefined)
        readNode.addEquation(slot, type, falseRange);
    }
  }

  /** Look for PcodeOps where the given constraint range applies and instantiate an equation */
  private applyConstraints(vn: Varnode, type: number, range: CircleRange, cbranch: PcodeOp): void {
    const splitPoint = (cbranch as any).getParent();
    let trueBlock: FlowBlock;
    let falseBlock: FlowBlock;
    if ((cbranch as any).isBooleanFlip()) {
      trueBlock = splitPoint.getFalseOut();
      falseBlock = splitPoint.getTrueOut();
    }
    else {
      trueBlock = splitPoint.getTrueOut();
      falseBlock = splitPoint.getFalseOut();
    }
    const trueIsRestricted = trueBlock.restrictedByConditional(splitPoint);
    const falseIsRestricted = falseBlock.restrictedByConditional(splitPoint);

    if ((vn as any).isWritten()) {
      const vSet = (vn as any).getValueSet();
      if (vSet.opCode === OpCode.CPUI_MULTIEQUAL) {
        vSet.addLandmark(type, range);
      }
    }
    const descendants = (vn as any).getDescendants();
    for (const op of descendants) {
      let outVn: Varnode | null = null;
      if (!(op as any).isMark()) {
        outVn = op.getOut();
        if (outVn === null) continue;
        if (!(outVn as any).isMark()) continue;
      }
      let curBlock = (op as any).getParent();
      const slot = op.getSlot(vn);
      if (op.code() === OpCode.CPUI_MULTIEQUAL) {
        if (curBlock === trueBlock) {
          if (trueIsRestricted || trueBlock.getIn(slot) === splitPoint)
            this.generateTrueEquation(outVn, op, slot, type, range);
          continue;
        }
        else if (curBlock === falseBlock) {
          if (falseIsRestricted || falseBlock.getIn(slot) === splitPoint)
            this.generateFalseEquation(outVn, op, slot, type, range);
          continue;
        }
        else {
          curBlock = curBlock.getIn(slot);
        }
      }
      for (;;) {
        if (curBlock === trueBlock) {
          if (trueIsRestricted)
            this.generateTrueEquation(outVn, op, slot, type, range);
          break;
        }
        else if (curBlock === falseBlock) {
          if (falseIsRestricted)
            this.generateFalseEquation(outVn, op, slot, type, range);
          break;
        }
        else if (curBlock === splitPoint || curBlock === null)
          break;
        curBlock = curBlock.getImmedDom();
      }
    }
  }

  /** Generate constraints given a Varnode path */
  private constraintsFromPath(type: number, lift: CircleRange, startVn: Varnode, endVn: Varnode, cbranch: PcodeOp): void {
    let curVn: Varnode | null = startVn;
    while (curVn !== endVn) {
      curVn = lift.pullBack((curVn as any).getDef()!, null, false);
      if (curVn === null) return;
    }
    let curEnd: Varnode | null = endVn;
    for (;;) {
      this.applyConstraints(curEnd!, type, lift, cbranch);
      if (!(curEnd as any).isWritten()) break;
      const op: PcodeOp = (curEnd as any).getDef()!;
      if (op.isCall() || op.isMarker()) break;
      curEnd = lift.pullBack(op, null, false);
      if (curEnd === null) break;
      if (!(curEnd as any).isMark()) break;
    }
  }

  /** Generate constraints arising from the given branch */
  private constraintsFromCBranch(cbranch: PcodeOp): void {
    let vn = cbranch.getIn(1)!;  // Get Varnode deciding the condition
    while (!(vn as any).isMark()) {
      if (!(vn as any).isWritten()) break;
      const op = (vn as any).getDef()!;
      if (op.isCall() || op.isMarker())
        break;
      const num = op.numInput();
      if (num === 0 || num > 2) break;
      vn = op.getIn(0)!;
      if (num === 2) {
        if (vn.isConstant())
          vn = op.getIn(1)!;
        else if (!op.getIn(1)!.isConstant()) {
          // Both inputs are non-constant
          this.generateRelativeConstraint(op, cbranch);
          return;
        }
      }
    }
    if ((vn as any).isMark()) {
      const lift = new CircleRange(true);
      const startVn = cbranch.getIn(1)!;
      this.constraintsFromPath(0, lift, startVn, vn, cbranch);
    }
  }

  /** Generate constraints given a system of Varnodes */
  private generateConstraints(worklist: Varnode[], reads: PcodeOp[]): void {
    const blockList: FlowBlock[] = [];
    // Collect all blocks that contain a system op or dominate a container
    for (let i = 0; i < worklist.length; ++i) {
      const op = (worklist[i] as any).getDef();
      if (op === null) continue;
      let bl: FlowBlock | null = op.getParent();
      if (op.code() === OpCode.CPUI_MULTIEQUAL) {
        for (let j = 0; j < bl.sizeIn(); ++j) {
          let curBl: FlowBlock | null = bl.getIn(j);
          while (curBl !== null) {
            if (curBl.isMark()) break;
            curBl.setMark();
            blockList.push(curBl);
            curBl = curBl.getImmedDom();
          }
        }
      }
      else {
        while (bl !== null) {
          if (bl.isMark()) break;
          bl.setMark();
          blockList.push(bl);
          bl = bl.getImmedDom();
        }
      }
    }
    for (let i = 0; i < reads.length; ++i) {
      let bl: FlowBlock | null = (reads[i] as any).getParent();
      while (bl !== null) {
        if (bl.isMark()) break;
        bl.setMark();
        blockList.push(bl);
        bl = bl.getImmedDom();
      }
    }
    for (let i = 0; i < blockList.length; ++i)
      blockList[i].clearMark();

    const finalList: FlowBlock[] = [];
    // Go through input blocks to the previously calculated blocks
    for (let i = 0; i < blockList.length; ++i) {
      const bl = blockList[i];
      for (let j = 0; j < bl.sizeIn(); ++j) {
        const splitPoint = bl.getIn(j) as BlockBasic;
        if (splitPoint.isMark()) continue;
        if (splitPoint.sizeOut() !== 2) continue;
        const lastOp = splitPoint.lastOp();
        if (lastOp !== null && lastOp.code() === OpCode.CPUI_CBRANCH) {
          splitPoint.setMark();
          finalList.push(splitPoint);
          this.constraintsFromCBranch(lastOp);
        }
      }
    }
    for (let i = 0; i < finalList.length; ++i)
      finalList[i].clearMark();
  }

  /** Check if the given Varnode is a relative constant */
  private checkRelativeConstant(vn: Varnode): { found: boolean; typeCode: number; value: bigint } {
    let value = 0n;
    let curVn: Varnode | null = vn;
    for (;;) {
      if ((curVn as any).isMark()) {
        const valueSet = (curVn as any).getValueSet();
        if (valueSet.typeCode !== 0) {
          return { found: true, typeCode: valueSet.typeCode, value: value };
        }
      }
      if (!(curVn as any).isWritten()) return { found: false, typeCode: 0, value: 0n };
      const op: PcodeOp = (curVn as any).getDef()!;
      const opc = op.code();
      if (opc === OpCode.CPUI_COPY || opc === OpCode.CPUI_INDIRECT) {
        curVn = op.getIn(0);
      }
      else if (opc === OpCode.CPUI_INT_ADD || opc === OpCode.CPUI_PTRSUB) {
        const constVn = op.getIn(1)!;
        if (!constVn.isConstant())
          return { found: false, typeCode: 0, value: 0n };
        value = (value + constVn.getOffset()) & calc_mask(constVn.getSize());
        curVn = op.getIn(0);
      }
      else {
        return { found: false, typeCode: 0, value: 0n };
      }
    }
  }

  /** Try to find a relative constraint */
  private generateRelativeConstraint(compOp: PcodeOp, cbranch: PcodeOp): void {
    let opc = compOp.code();
    switch (opc) {
      case OpCode.CPUI_INT_LESS:
        opc = OpCode.CPUI_INT_SLESS;
        break;
      case OpCode.CPUI_INT_LESSEQUAL:
        opc = OpCode.CPUI_INT_SLESSEQUAL;
        break;
      case OpCode.CPUI_INT_SLESS:
      case OpCode.CPUI_INT_SLESSEQUAL:
      case OpCode.CPUI_INT_EQUAL:
      case OpCode.CPUI_INT_NOTEQUAL:
        break;
      default:
        return;
    }
    let typeCode: number;
    let value: bigint;
    let vn: Varnode;
    const inVn0 = compOp.getIn(0)!;
    const inVn1 = compOp.getIn(1)!;
    const lift = new CircleRange(true);

    const check0 = this.checkRelativeConstant(inVn0);
    if (check0.found) {
      typeCode = check0.typeCode;
      value = check0.value;
      vn = inVn1;
      if (!lift.pullBackBinary(opc, value, 1, vn.getSize(), 1))
        return;
    }
    else {
      const check1 = this.checkRelativeConstant(inVn1);
      if (check1.found) {
        typeCode = check1.typeCode;
        value = check1.value;
        vn = inVn0;
        if (!lift.pullBackBinary(opc, value, 0, vn.getSize(), 1))
          return;
      }
      else {
        return;  // Neither side looks like a relative constant
      }
    }

    let endVn: Varnode | null = vn;
    while (!(endVn as any).isMark()) {
      if (!(endVn as any).isWritten()) return;
      const op: PcodeOp = (endVn as any).getDef()!;
      const opcode = op.code();
      if (opcode === OpCode.CPUI_COPY || opcode === OpCode.CPUI_PTRSUB) {
        endVn = op.getIn(0);
      }
      else if (opcode === OpCode.CPUI_INT_ADD) {
        if (!op.getIn(1)!.isConstant())
          return;
        endVn = op.getIn(0);
      }
      else {
        return;
      }
    }
    this.constraintsFromPath(typeCode!, lift, vn, endVn!, cbranch);
  }

  // ----- Public methods -----

  /** Build value sets for a data-flow system */
  establishValueSets(sinks: Varnode[], reads: PcodeOp[], stackReg: Varnode | null, indirectAsCopy: boolean): void {
    const worklist: Varnode[] = [];
    let workPos = 0;
    if (stackReg !== null) {
      this.newValueSet(stackReg, 1);
      (stackReg as any).setMark();
      worklist.push(stackReg);
      workPos += 1;
      this.rootNodes.push((stackReg as any).getValueSet());
    }
    for (let i = 0; i < sinks.length; ++i) {
      const vn = sinks[i];
      this.newValueSet(vn, 0);
      (vn as any).setMark();
      worklist.push(vn);
    }
    while (workPos < worklist.length) {
      const vn = worklist[workPos];
      workPos += 1;
      if (!(vn as any).isWritten()) {
        if (vn.isConstant()) {
          if ((vn as any).isSpacebase() || (vn as any).loneDescend()!.numInput() === 1)
            this.rootNodes.push((vn as any).getValueSet());
        }
        else {
          this.rootNodes.push((vn as any).getValueSet());
        }
        continue;
      }
      const op = (vn as any).getDef()!;
      switch (op.code()) {
        case OpCode.CPUI_INDIRECT:
          if (indirectAsCopy || op.isIndirectStore()) {
            const inVn = op.getIn(0);
            if (!(inVn as any).isMark()) {
              this.newValueSet(inVn, 0);
              (inVn as any).setMark();
              worklist.push(inVn);
            }
          }
          else {
            (vn as any).getValueSet().setFull();
            this.rootNodes.push((vn as any).getValueSet());
          }
          break;
        case OpCode.CPUI_CALL:
        case OpCode.CPUI_CALLIND:
        case OpCode.CPUI_CALLOTHER:
        case OpCode.CPUI_LOAD:
        case OpCode.CPUI_NEW:
        case OpCode.CPUI_SEGMENTOP:
        case OpCode.CPUI_CPOOLREF:
        case OpCode.CPUI_FLOAT_ADD:
        case OpCode.CPUI_FLOAT_DIV:
        case OpCode.CPUI_FLOAT_MULT:
        case OpCode.CPUI_FLOAT_SUB:
        case OpCode.CPUI_FLOAT_NEG:
        case OpCode.CPUI_FLOAT_ABS:
        case OpCode.CPUI_FLOAT_SQRT:
        case OpCode.CPUI_FLOAT_INT2FLOAT:
        case OpCode.CPUI_FLOAT_FLOAT2FLOAT:
        case OpCode.CPUI_FLOAT_TRUNC:
        case OpCode.CPUI_FLOAT_CEIL:
        case OpCode.CPUI_FLOAT_FLOOR:
        case OpCode.CPUI_FLOAT_ROUND:
          (vn as any).getValueSet().setFull();
          this.rootNodes.push((vn as any).getValueSet());
          break;
        default:
          for (let i = 0; i < op.numInput(); ++i) {
            const inVn = op.getIn(i);
            if ((inVn as any).isMark() || (inVn as any).isAnnotation()) continue;
            this.newValueSet(inVn, 0);
            (inVn as any).setMark();
            worklist.push(inVn);
          }
          break;
      }
    }
    for (let i = 0; i < reads.length; ++i) {
      const op = reads[i];
      for (let slot = 0; slot < op.numInput(); ++slot) {
        const vn = op.getIn(slot);
        if ((vn as any).isMark()) {
          const vsRead = new ValueSetRead();
          vsRead.setPcodeOp(op, slot);
          this.readNodes.set((op as any).getSeqNum().toString(), vsRead);
          (op as any).setMark();
          break;   // Only 1 read allowed
        }
      }
    }
    this.generateConstraints(worklist, reads);
    for (let i = 0; i < reads.length; ++i)
      (reads[i] as any).clearMark();

    this.establishTopologicalOrder();
    for (let i = 0; i < worklist.length; ++i)
      (worklist[i] as any).clearMark();
  }

  /** Get the current number of iterations */
  getNumIterations(): number { return this.numIterations; }

  /** Iterate the ValueSet system until it stabilizes */
  solve(max: number, widener: Widener): void {
    this.maxIterations = max;
    this.numIterations = 0;
    for (const vs of this.valueNodes)
      vs.count = 0;

    const componentStack: PartitionNode[] = [];
    let curComponent: PartitionNode | null = null;
    let curSet: ValueSet | null = this.orderPartition.startNode;

    while (curSet !== null) {
      this.numIterations += 1;
      if (this.numIterations > this.maxIterations) break;
      if (curSet.partHead !== null && curSet.partHead !== curComponent) {
        componentStack.push(curSet.partHead);
        curComponent = curSet.partHead;
        curComponent.isDirty = false;
        // Reset component counter upon entry
        curComponent.startNode!.count = widener.determineIterationReset(curComponent.startNode!);
      }
      if (curComponent !== null) {
        if (curSet.iterate(widener))
          curComponent.isDirty = true;
        if (curComponent.stopNode !== curSet) {
          curSet = curSet.next;
        }
        else {
          for (;;) {
            if (curComponent!.isDirty) {
              curComponent!.isDirty = false;
              curSet = curComponent!.startNode;
              if (componentStack.length > 1) {
                componentStack[componentStack.length - 2].isDirty = true;
              }
              break;
            }

            componentStack.pop();
            if (componentStack.length === 0) {
              curComponent = null;
              curSet = curSet!.next;
              break;
            }
            curComponent = componentStack[componentStack.length - 1];
            if (curComponent.stopNode !== curSet) {
              curSet = curSet!.next;
              break;
            }
          }
        }
      }
      else {
        curSet.iterate(widener);
        curSet = curSet.next;
      }
    }
    // Calculate any follow-on value sets
    for (const [_key, readNode] of this.readNodes) {
      readNode.compute();
    }
  }

  /** Start of all ValueSets in the system */
  beginValueSets(): IterableIterator<ValueSet> {
    return this.valueNodes[Symbol.iterator]();
  }

  /** Iterator access over all ValueSets in the system */
  getValueSets(): ValueSet[] {
    return this.valueNodes;
  }

  /** Get all ValueSetReads */
  getValueSetReads(): Map<string, ValueSetRead> {
    return this.readNodes;
  }

  /** Get ValueSetRead by SeqNum */
  getValueSetRead(seq: any): ValueSetRead {
    return this.readNodes.get(seq.toString())!;
  }

  /** Dump value sets for debugging */
  dumpValueSets(s: { write(str: string): void }): void {
    for (const vs of this.valueNodes) {
      vs.printRaw(s);
      s.write("\n");
    }
    for (const [_key, readNode] of this.readNodes) {
      readNode.printRaw(s);
      s.write("\n");
    }
  }
}
// (Part 2 duplicate classes removed - merged into Part 1 above)
