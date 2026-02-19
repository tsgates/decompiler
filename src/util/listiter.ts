/// \file listiter.ts
/// \brief C++-style list iterator adapter for arrays

/// Wraps an array with C++ list iterator semantics: get(), next(), prev(), equals()
export class ListIter<T> implements Iterable<T> {
  private arr: T[];
  private idx: number;

  constructor(arr: T[], idx: number) {
    this.arr = arr;
    this.idx = idx;
  }

  get(): T { return this.arr[this.idx]; }
  /** Advance to next element (mutates in place, returns this) */
  next(): this { this.idx++; return this; }
  /** Retreat to previous element (mutates in place, returns this) */
  prev(): this { this.idx--; return this; }
  equals(other: ListIter<T>): boolean { return this.arr === other.arr && this.idx === other.idx; }
  get value(): T { return this.arr[this.idx]; }
  /** Return an independent copy of this iterator */
  clone(): ListIter<T> { return new ListIter(this.arr, this.idx); }
  isEnd(): boolean { return this.idx >= this.arr.length; }
  getIndex(): number { return this.idx; }

  /** Iterate from current position to end of array */
  *[Symbol.iterator](): IterableIterator<T> {
    for (let i = this.idx; i < this.arr.length; i++) {
      yield this.arr[i];
    }
  }
}
