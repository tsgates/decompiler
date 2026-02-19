/**
 * @file rangemap.ts
 * @description Interval map containers, translated from rangemap.hh
 *
 * This implements a generic interval/range map that maps non-overlapping
 * intervals to record objects. Records occupy ranges and can be inserted/removed.
 */

/**
 * A record type stored in the rangemap must implement this interface.
 */
export interface RangeMapRecord {
  /** Get the starting address of this record's range */
  getFirst(): bigint;
  /** Get the last address of this record's range */
  getLast(): bigint;
}

/**
 * A disjoint sub-range within a larger range in the interval map.
 */
export class AddrRange<T extends RangeMapRecord> {
  first: bigint;
  last: bigint;
  record: T;

  constructor(first: bigint, last: bigint, record: T) {
    this.first = first;
    this.last = last;
    this.record = record;
  }
}

/**
 * An interval map that maps non-overlapping ranges to record objects.
 *
 * This is a simplified version of the C++ rangemap template.
 * Records can be inserted and removed, and the map ensures
 * ranges don't overlap.
 *
 * @template T - Record type that must implement RangeMapRecord
 */
export class RangeMap<T extends RangeMapRecord> {
  private ranges: AddrRange<T>[] = [];

  /** Number of records */
  get size(): number {
    return this.ranges.length;
  }

  /** Check if the map is empty */
  empty(): boolean {
    return this.ranges.length === 0;
  }

  /** Clear all records */
  clear(): void {
    this.ranges.length = 0;
  }

  /** Find the index where a range starting at or after 'addr' would be */
  private lowerBound(addr: bigint): number {
    let lo = 0;
    let hi = this.ranges.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (this.ranges[mid].first < addr) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    return lo;
  }

  /**
   * Insert a record into the map.
   * The record's range must not overlap with existing records.
   * @returns the index where the record was inserted
   */
  insert(record: T): number {
    const first = record.getFirst();
    const last = record.getLast();
    const idx = this.lowerBound(first);
    const range = new AddrRange(first, last, record);
    this.ranges.splice(idx, 0, range);
    return idx;
  }

  /**
   * Remove the record at the given index.
   */
  erase(idx: number): void {
    this.ranges.splice(idx, 1);
  }

  /**
   * Find a range containing the given address.
   * @returns the index of the matching range, or -1 if not found
   */
  find(addr: bigint): number {
    // Binary search for the range that could contain addr
    let lo = 0;
    let hi = this.ranges.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (this.ranges[mid].last < addr) {
        lo = mid + 1;
      } else if (this.ranges[mid].first > addr) {
        hi = mid;
      } else {
        return mid; // addr is within this range
      }
    }
    return -1;
  }

  /**
   * Find the first range that starts at or after the given address.
   * @returns the index, or ranges.length if none found
   */
  findBegin(addr: bigint): number {
    return this.lowerBound(addr);
  }

  /**
   * Find ranges that overlap with [first, last].
   * @returns array of indices
   */
  findOverlap(first: bigint, last: bigint): number[] {
    const result: number[] = [];
    for (let i = 0; i < this.ranges.length; i++) {
      const r = this.ranges[i];
      if (r.first > last) break;
      if (r.last >= first) {
        result.push(i);
      }
    }
    return result;
  }

  /** Get the range at a specific index */
  getRange(idx: number): AddrRange<T> {
    return this.ranges[idx];
  }

  /** Get the record at a specific index */
  getRecord(idx: number): T {
    return this.ranges[idx].record;
  }

  /** Iterator over all ranges */
  *entries(): IterableIterator<AddrRange<T>> {
    for (const range of this.ranges) {
      yield range;
    }
  }

  /** Get the first range (if any) */
  getFirst(): AddrRange<T> | undefined {
    return this.ranges[0];
  }

  /** Get the last range (if any) */
  getLast(): AddrRange<T> | undefined {
    return this.ranges[this.ranges.length - 1];
  }
}
