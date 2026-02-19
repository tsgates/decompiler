/**
 * @file partmap.ts
 * @description A map from a linear space to value objects, translated from partmap.hh
 *
 * The partmap maps a linear space (with ordering) to value objects.
 * Split points partition the space into disjoint intervals, each
 * associated with a value. Points between split points inherit the
 * value of the previous split point (or the default value if there
 * is no earlier split point).
 */

/**
 * A map from a linear space to value objects.
 *
 * Let R be the linear space with an ordering, and let { a_i } be a finite set
 * of points in R. The a_i partition R into disjoint sets, each mapped to a value.
 *
 * @template L - the linear type (must support comparison)
 * @template V - the value type
 */
export class PartMap<L, V> {
  private database: Map<L, V> = new Map();
  private sortedKeys: L[] = [];
  private _defaultValue: V;
  private compare: (a: L, b: L) => number;
  private cloneFn: (v: V) => V;

  /**
   * @param defaultValue - the initial value for the entire linear space
   * @param compare - comparison function for L (negative = a < b, 0 = equal, positive = a > b)
   * @param clone - optional function to deep-copy values when splitting (default: identity)
   */
  constructor(defaultValue: V, compare: (a: L, b: L) => number, clone?: (v: V) => V) {
    this._defaultValue = defaultValue;
    this.compare = compare;
    this.cloneFn = clone ?? ((v: V) => v);
  }

  /** Get the default value object */
  get defaultValue(): V {
    return this._defaultValue;
  }

  /** Set the default value object */
  set defaultValue(val: V) {
    this._defaultValue = val;
  }

  /** Find the index for upper_bound (first element > pnt) */
  private upperBound(pnt: L): number {
    let lo = 0;
    let hi = this.sortedKeys.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (this.compare(this.sortedKeys[mid], pnt) <= 0) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    return lo;
  }

  /** Find the index for lower_bound (first element >= pnt) */
  private lowerBound(pnt: L): number {
    let lo = 0;
    let hi = this.sortedKeys.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (this.compare(this.sortedKeys[mid], pnt) < 0) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    return lo;
  }

  /** Insert a key into the sorted keys array at the correct position */
  private insertKey(key: L): void {
    const idx = this.lowerBound(key);
    if (idx < this.sortedKeys.length && this.compare(this.sortedKeys[idx], key) === 0) {
      return; // Already exists
    }
    this.sortedKeys.splice(idx, 0, key);
  }

  /**
   * Get the value object at a point.
   * Look up the first split point <= pnt and return its value.
   * If no such split point exists, return the default value.
   */
  getValue(pnt: L): V {
    const idx = this.upperBound(pnt);
    if (idx === 0) {
      return this._defaultValue;
    }
    return this.database.get(this.sortedKeys[idx - 1])!;
  }

  /**
   * Introduce a new split point.
   * If the point already exists, return its value.
   * Otherwise, create a new entry with a copy of the value that currently applies.
   */
  split(pnt: L): V {
    const idx = this.upperBound(pnt);
    if (idx > 0) {
      const prevKey = this.sortedKeys[idx - 1];
      if (this.compare(prevKey, pnt) === 0) {
        return this.database.get(prevKey)!;
      }
      const prevVal = this.database.get(prevKey)!;
      this.database.set(pnt, this.cloneFn(prevVal));
      this.insertKey(pnt);
      return this.database.get(pnt)!;
    }
    this.database.set(pnt, this.cloneFn(this._defaultValue));
    this.insertKey(pnt);
    return this.database.get(pnt)!;
  }

  /**
   * Set the value at a split point.
   * Introduces the split point if not present, then sets its value.
   */
  splitAndSet(pnt: L, val: V): void {
    this.split(pnt);
    this.database.set(pnt, val);
  }

  /**
   * Clear all split points in the range [pnt1, pnt2).
   * Split points are introduced at both boundaries, and everything
   * between is removed. Returns the value at pnt1.
   */
  clearRange(pnt1: L, pnt2: L): V {
    this.split(pnt1);
    this.split(pnt2);
    const begIdx = this.lowerBound(pnt1);
    const endIdx = this.lowerBound(pnt2);
    const val = this.database.get(this.sortedKeys[begIdx])!;
    // Remove all split points between begIdx+1 and endIdx (exclusive)
    for (let i = begIdx + 1; i < endIdx; i++) {
      this.database.delete(this.sortedKeys[i]);
    }
    this.sortedKeys.splice(begIdx + 1, endIdx - begIdx - 1);
    return val;
  }

  /**
   * Get the value and bounding range for a given point.
   * @returns { value, before?, after?, valid } where valid:
   *   0 = both bounds apply
   *   1 = no lower bound
   *   2 = no upper bound
   *   3 = no bounds at all
   */
  bounds(pnt: L): { value: V; before?: L; after?: L; valid: number } {
    if (this.database.size === 0) {
      return { value: this._defaultValue, valid: 3 };
    }

    const endIdx = this.upperBound(pnt);
    if (endIdx > 0) {
      const iterIdx = endIdx - 1;
      const before = this.sortedKeys[iterIdx];
      const value = this.database.get(before)!;
      if (endIdx === this.sortedKeys.length) {
        return { value, before, valid: 2 };
      }
      const after = this.sortedKeys[endIdx];
      return { value, before, after, valid: 0 };
    }
    const after = this.sortedKeys[endIdx];
    return { value: this._defaultValue, after, valid: 1 };
  }

  /** Iterate over all split points (in order) */
  *entries(): IterableIterator<[L, V]> {
    for (const key of this.sortedKeys) {
      yield [key, this.database.get(key)!];
    }
  }

  /** Iterate from a given point onward */
  *entriesFrom(pnt: L): IterableIterator<[L, V]> {
    const idx = this.lowerBound(pnt);
    for (let i = idx; i < this.sortedKeys.length; i++) {
      const key = this.sortedKeys[i];
      yield [key, this.database.get(key)!];
    }
  }

  /** Clear all split points */
  clear(): void {
    this.database.clear();
    this.sortedKeys.length = 0;
  }

  /** Return true if there are no split points */
  empty(): boolean {
    return this.database.size === 0;
  }

  /** Get the number of split points */
  get size(): number {
    return this.database.size;
  }

  // ---- Index-based access (for C++ iterator pattern compatibility) ----

  /** Get the index of the first entry >= pnt (or 0 if no pnt given) */
  beginIndex(pnt?: L): number {
    if (pnt === undefined) return 0;
    return this.lowerBound(pnt);
  }

  /** Get the end index (one past last) */
  endIndex(): number {
    return this.sortedKeys.length;
  }

  /** Get the key at a given index */
  getKeyAt(idx: number): L {
    return this.sortedKeys[idx];
  }

  /** Get the value at a given index */
  getValueAt(idx: number): V {
    return this.database.get(this.sortedKeys[idx])!;
  }

  /** Get [key, value] pair at a given index */
  getEntryAt(idx: number): [L, V] {
    const key = this.sortedKeys[idx];
    return [key, this.database.get(key)!];
  }
}
