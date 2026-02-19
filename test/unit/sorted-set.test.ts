/**
 * @file sorted-set.test.ts
 * @description Comprehensive tests for the red-black tree SortedSet and SortedMap.
 */

import { describe, it, expect } from 'vitest';
import { SortedSet, SortedMap } from '../../src/util/sorted-set.js';

const numcmp = (a: number, b: number) => a - b;

// ---------------------------------------------------------------------------
// SortedSet
// ---------------------------------------------------------------------------
describe('SortedSet', () => {
  // -- basic insertion & size --
  it('starts empty', () => {
    const s = new SortedSet<number>(numcmp);
    expect(s.size).toBe(0);
    expect(s.empty).toBe(true);
    expect(s.begin().isEnd).toBe(true);
  });

  it('inserts unique elements and rejects duplicates', () => {
    const s = new SortedSet<number>(numcmp);
    const [it1, ok1] = s.insert(5);
    expect(ok1).toBe(true);
    expect(it1.value).toBe(5);

    const [it2, ok2] = s.insert(5);
    expect(ok2).toBe(false);
    expect(it2.value).toBe(5);
    expect(s.size).toBe(1);
  });

  it('maintains sorted order for sequential inserts', () => {
    const s = new SortedSet<number>(numcmp);
    for (let i = 0; i < 20; i++) s.insert(i);
    expect([...s]).toEqual(Array.from({ length: 20 }, (_, i) => i));
  });

  it('maintains sorted order for reverse inserts', () => {
    const s = new SortedSet<number>(numcmp);
    for (let i = 19; i >= 0; i--) s.insert(i);
    expect([...s]).toEqual(Array.from({ length: 20 }, (_, i) => i));
  });

  it('maintains sorted order for random inserts', () => {
    const s = new SortedSet<number>(numcmp);
    const vals = [15, 3, 8, 20, 1, 12, 7, 19, 4, 17, 6, 11, 2, 16, 10, 14, 9, 5, 18, 13];
    for (const v of vals) s.insert(v);
    expect([...s]).toEqual(Array.from({ length: 20 }, (_, i) => i + 1));
  });

  // -- find, has --
  it('find returns end for missing elements', () => {
    const s = new SortedSet<number>(numcmp);
    s.insert(1);
    s.insert(3);
    expect(s.find(2).isEnd).toBe(true);
    expect(s.has(2)).toBe(false);
    expect(s.has(1)).toBe(true);
    expect(s.has(3)).toBe(true);
  });

  // -- lower_bound / upper_bound --
  it('lower_bound returns first >= value', () => {
    const s = new SortedSet<number>(numcmp);
    [10, 20, 30, 40, 50].forEach(v => s.insert(v));

    expect(s.lower_bound(25).value).toBe(30);
    expect(s.lower_bound(30).value).toBe(30);
    expect(s.lower_bound(5).value).toBe(10);
    expect(s.lower_bound(51).isEnd).toBe(true);
  });

  it('upper_bound returns first > value', () => {
    const s = new SortedSet<number>(numcmp);
    [10, 20, 30, 40, 50].forEach(v => s.insert(v));

    expect(s.upper_bound(30).value).toBe(40);
    expect(s.upper_bound(29).value).toBe(30);
    expect(s.upper_bound(50).isEnd).toBe(true);
    expect(s.upper_bound(4).value).toBe(10);
  });

  // -- iterators --
  it('begin/end iterate in order', () => {
    const s = new SortedSet<number>(numcmp);
    [3, 1, 2].forEach(v => s.insert(v));
    const vals: number[] = [];
    for (let it = s.begin(); !it.isEnd; it.next()) {
      vals.push(it.value);
    }
    expect(vals).toEqual([1, 2, 3]);
  });

  it('rbegin + prev iterates in reverse', () => {
    const s = new SortedSet<number>(numcmp);
    [3, 1, 4, 1, 5, 9].forEach(v => s.insert(v));
    const vals: number[] = [];
    const rb = s.rbegin();
    if (!rb.isEnd) {
      vals.push(rb.value);
      while (true) {
        rb.prev();
        if (rb.isEnd) break;
        // Check if we've gone past the beginning
        vals.push(rb.value);
        if (rb.equals(s.begin())) break;
      }
    }
    expect(vals).toEqual([9, 5, 4, 3, 1]);
  });

  it('end().prev() gives maximum', () => {
    const s = new SortedSet<number>(numcmp);
    [5, 2, 8].forEach(v => s.insert(v));
    const it = s.end();
    it.prev();
    expect(it.value).toBe(8);
  });

  it('iterator clone is independent', () => {
    const s = new SortedSet<number>(numcmp);
    [1, 2, 3].forEach(v => s.insert(v));
    const a = s.begin();
    const b = a.clone();
    expect(a.equals(b)).toBe(true);
    a.next();
    expect(a.value).toBe(2);
    expect(b.value).toBe(1);
    expect(a.equals(b)).toBe(false);
  });

  // -- erase --
  it('erases elements and returns correct next iterator', () => {
    const s = new SortedSet<number>(numcmp);
    [1, 2, 3, 4, 5].forEach(v => s.insert(v));

    // Erase 3, should return iterator to 4
    const it = s.find(3);
    const nxt = s.erase(it);
    expect(nxt.value).toBe(4);
    expect(s.size).toBe(4);
    expect(s.has(3)).toBe(false);
    expect([...s]).toEqual([1, 2, 4, 5]);
  });

  it('erases the last element and returns end()', () => {
    const s = new SortedSet<number>(numcmp);
    [1, 2, 3].forEach(v => s.insert(v));
    const nxt = s.erase(s.find(3));
    expect(nxt.isEnd).toBe(true);
    expect([...s]).toEqual([1, 2]);
  });

  it('erases all elements one by one', () => {
    const s = new SortedSet<number>(numcmp);
    [5, 3, 7, 1, 4, 6, 8].forEach(v => s.insert(v));

    let it = s.begin();
    while (!it.isEnd) {
      it = s.erase(it);
    }
    expect(s.size).toBe(0);
    expect(s.empty).toBe(true);
  });

  it('eraseValue removes by value', () => {
    const s = new SortedSet<number>(numcmp);
    [1, 2, 3].forEach(v => s.insert(v));
    expect(s.eraseValue(2)).toBe(true);
    expect(s.eraseValue(2)).toBe(false);
    expect([...s]).toEqual([1, 3]);
  });

  // -- clear --
  it('clear empties the set', () => {
    const s = new SortedSet<number>(numcmp);
    [1, 2, 3].forEach(v => s.insert(v));
    s.clear();
    expect(s.size).toBe(0);
    expect(s.begin().isEnd).toBe(true);
  });

  // -- iterator stability --
  it('iterators survive insertion of other elements', () => {
    const s = new SortedSet<number>(numcmp);
    s.insert(10);
    s.insert(30);
    const it = s.find(10);
    expect(it.value).toBe(10);

    // Insert elements around it
    s.insert(5);
    s.insert(20);
    s.insert(15);

    // it should still point to 10
    expect(it.value).toBe(10);
    // and next should be 15
    it.next();
    expect(it.value).toBe(15);
  });

  it('iterators survive deletion of other elements', () => {
    const s = new SortedSet<number>(numcmp);
    [10, 20, 30, 40, 50].forEach(v => s.insert(v));
    const it = s.find(30);

    s.eraseValue(10);
    s.eraseValue(50);

    // it still points to 30
    expect(it.value).toBe(30);
    it.prev();
    expect(it.value).toBe(20);
    it.next();
    it.next();
    expect(it.value).toBe(40);
  });

  // -- stress: large insertions + deletions --
  it('handles 1000 elements correctly', () => {
    const s = new SortedSet<number>(numcmp);
    const n = 1000;
    // Insert in shuffled order
    const arr = Array.from({ length: n }, (_, i) => i);
    // Fisher-Yates shuffle with deterministic seed
    let seed = 42;
    const rand = () => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed;
    };
    for (let i = arr.length - 1; i > 0; i--) {
      const j = rand() % (i + 1);
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    for (const v of arr) s.insert(v);
    expect(s.size).toBe(n);

    // Verify sorted order
    const sorted = [...s];
    for (let i = 0; i < n; i++) expect(sorted[i]).toBe(i);

    // Delete even numbers
    for (let i = 0; i < n; i += 2) s.eraseValue(i);
    expect(s.size).toBe(n / 2);

    const remaining = [...s];
    for (let i = 0; i < remaining.length; i++) {
      expect(remaining[i]).toBe(i * 2 + 1);
    }
  });

  // -- custom comparator (reverse) --
  it('works with reverse comparator', () => {
    const s = new SortedSet<number>((a, b) => b - a);
    [3, 1, 4, 1, 5, 9, 2, 6].forEach(v => s.insert(v));
    expect([...s]).toEqual([9, 6, 5, 4, 3, 2, 1]);
  });

  // -- string comparator --
  it('works with string comparator', () => {
    const s = new SortedSet<string>((a, b) => a < b ? -1 : a > b ? 1 : 0);
    ['banana', 'apple', 'cherry'].forEach(v => s.insert(v));
    expect([...s]).toEqual(['apple', 'banana', 'cherry']);
  });
});

// ---------------------------------------------------------------------------
// SortedMap
// ---------------------------------------------------------------------------
describe('SortedMap', () => {
  it('basic set/get/has/delete', () => {
    const m = new SortedMap<number, string>(numcmp);
    m.set(3, 'three');
    m.set(1, 'one');
    m.set(2, 'two');

    expect(m.size).toBe(3);
    expect(m.get(1)).toBe('one');
    expect(m.get(2)).toBe('two');
    expect(m.get(3)).toBe('three');
    expect(m.get(4)).toBeUndefined();

    expect(m.has(2)).toBe(true);
    expect(m.has(4)).toBe(false);

    expect(m.delete(2)).toBe(true);
    expect(m.delete(2)).toBe(false);
    expect(m.size).toBe(2);
    expect(m.get(2)).toBeUndefined();
  });

  it('set overwrites existing value', () => {
    const m = new SortedMap<number, string>(numcmp);
    m.set(1, 'first');
    m.set(1, 'second');
    expect(m.size).toBe(1);
    expect(m.get(1)).toBe('second');
  });

  it('insert does not overwrite', () => {
    const m = new SortedMap<number, string>(numcmp);
    const [, ok1] = m.insert(1, 'first');
    expect(ok1).toBe(true);
    const [it2, ok2] = m.insert(1, 'second');
    expect(ok2).toBe(false);
    expect(it2.value).toBe('first');
    expect(m.get(1)).toBe('first');
  });

  it('entries iterate in key order', () => {
    const m = new SortedMap<number, string>(numcmp);
    m.set(3, 'c');
    m.set(1, 'a');
    m.set(2, 'b');

    const entries = [...m.entries()];
    expect(entries).toEqual([[1, 'a'], [2, 'b'], [3, 'c']]);
  });

  it('keys and values iterate in order', () => {
    const m = new SortedMap<number, string>(numcmp);
    m.set(30, 'c');
    m.set(10, 'a');
    m.set(20, 'b');

    expect([...m.keys()]).toEqual([10, 20, 30]);
    expect([...m.values()]).toEqual(['a', 'b', 'c']);
  });

  it('for-of yields [key, value] pairs', () => {
    const m = new SortedMap<string, number>((a, b) => a < b ? -1 : a > b ? 1 : 0);
    m.set('b', 2);
    m.set('a', 1);

    const result: [string, number][] = [];
    for (const [k, v] of m) {
      result.push([k, v]);
    }
    expect(result).toEqual([['a', 1], ['b', 2]]);
  });

  it('lower_bound and upper_bound', () => {
    const m = new SortedMap<number, string>(numcmp);
    m.set(10, 'a');
    m.set(20, 'b');
    m.set(30, 'c');
    m.set(40, 'd');

    const lb = m.lower_bound(20);
    expect(lb.key).toBe(20);
    expect(lb.value).toBe('b');

    const ub = m.upper_bound(20);
    expect(ub.key).toBe(30);
    expect(ub.value).toBe('c');

    expect(m.lower_bound(25).key).toBe(30);
    expect(m.upper_bound(40).isEnd).toBe(true);
  });

  it('erase by iterator', () => {
    const m = new SortedMap<number, string>(numcmp);
    m.set(1, 'a');
    m.set(2, 'b');
    m.set(3, 'c');

    const it = m.find(2);
    const nxt = m.erase(it);
    expect(nxt.key).toBe(3);
    expect(m.size).toBe(2);
    expect([...m.keys()]).toEqual([1, 3]);
  });

  it('begin/end/rbegin iteration', () => {
    const m = new SortedMap<number, string>(numcmp);
    m.set(1, 'a');
    m.set(2, 'b');
    m.set(3, 'c');

    expect(m.begin().key).toBe(1);
    expect(m.rbegin().key).toBe(3);

    const vals: string[] = [];
    for (let it = m.begin(); !it.isEnd; it.next()) {
      vals.push(it.value);
    }
    expect(vals).toEqual(['a', 'b', 'c']);
  });

  it('map iterator value can be mutated', () => {
    const m = new SortedMap<number, string>(numcmp);
    m.set(1, 'old');
    const it = m.find(1);
    it.value = 'new';
    expect(m.get(1)).toBe('new');
  });

  it('clear empties the map', () => {
    const m = new SortedMap<number, string>(numcmp);
    m.set(1, 'a');
    m.set(2, 'b');
    m.clear();
    expect(m.size).toBe(0);
    expect(m.get(1)).toBeUndefined();
  });
});
