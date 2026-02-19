/**
 * @file sorted-set.ts
 * @description Red-black tree based SortedSet<T> and SortedMap<K,V> that replace
 * C++ std::set / std::map with custom comparators.
 *
 * Design goals:
 *   - O(log n) insert, delete, find, lower_bound, upper_bound
 *   - Stable iterators: insertions and deletions of *other* elements do not
 *     invalidate existing iterators (same guarantee as C++ std::set)
 *   - In-order forward and backward iteration
 *   - Generic over element type with a pluggable comparator
 *
 * The red-black tree invariants maintained:
 *   1. Every node is red or black.
 *   2. The root is black.
 *   3. Every leaf (NIL sentinel) is black.
 *   4. If a node is red, both children are black.
 *   5. Every simple path from a node to a descendant leaf has the same black-height.
 */

// ---------------------------------------------------------------------------
// Internal node types
// ---------------------------------------------------------------------------

const enum Color {
  RED = 0,
  BLACK = 1,
}

/**
 * Internal tree node.  The NIL sentinel is a distinguished node instance
 * shared by every tree; it is always black and its value is undefined.
 */
class RBNode<T> {
  color: Color;
  value: T;
  left: RBNode<T>;
  right: RBNode<T>;
  parent: RBNode<T>;

  constructor(value: T, color: Color, nil: RBNode<T>) {
    this.value = value;
    this.color = color;
    this.left = nil;
    this.right = nil;
    this.parent = nil;
  }
}

// ---------------------------------------------------------------------------
// SortedSetIterator
// ---------------------------------------------------------------------------

/**
 * Bidirectional iterator over a SortedSet, modeled after C++ std::set::iterator.
 *
 * An iterator either points to a real node or to the *end sentinel*.  Calling
 * `next()` on the last element yields the end sentinel; calling `prev()` on
 * the end sentinel yields the last element.
 *
 * Iterator stability: iterators remain valid across insertions and deletions
 * of *other* elements.  Erasing the element an iterator points to invalidates
 * that iterator (and only that iterator).
 */
export class SortedSetIterator<T> {
  /** @internal */ _node: RBNode<T>;
  /** @internal */ _nil: RBNode<T>;
  /** @internal */ _root: () => RBNode<T>;

  /** @internal */
  constructor(node: RBNode<T>, nil: RBNode<T>, root: () => RBNode<T>) {
    this._node = node;
    this._nil = nil;
    this._root = root;
  }

  /** The element this iterator points to.  Undefined behavior if `isEnd`. */
  get value(): T {
    return this._node.value;
  }

  /** True when this iterator is past-the-end (the end sentinel). */
  get isEnd(): boolean {
    return this._node === this._nil;
  }

  /**
   * Advance to the next element in sorted order (in-order successor).
   * If already at end, this is a no-op.
   * @returns this iterator (mutated) for chaining
   */
  next(): this {
    this._node = successor(this._node, this._nil, this._root);
    return this;
  }

  /**
   * Retreat to the previous element in sorted order (in-order predecessor).
   * If at the end sentinel, moves to the maximum element.
   * @returns this iterator (mutated) for chaining
   */
  prev(): this {
    this._node = predecessor(this._node, this._nil, this._root);
    return this;
  }

  /** Two iterators are equal iff they point to the same node. */
  equals(other: SortedSetIterator<T>): boolean {
    return this._node === other._node;
  }

  /** Get current element (alias for .value, for C++ iterator compatibility) */
  get(): T { return this._node.value; }

  /** Return an independent copy of this iterator. */
  clone(): SortedSetIterator<T> {
    return new SortedSetIterator<T>(this._node, this._nil, this._root);
  }
}

// ---------------------------------------------------------------------------
// Tree navigation helpers (work on nodes, not iterators)
// ---------------------------------------------------------------------------

/** In-order successor.  Returns nil when node is the maximum. */
function successor<T>(
  node: RBNode<T>,
  nil: RBNode<T>,
  root: () => RBNode<T>,
): RBNode<T> {
  if (node === nil) {
    // end().next() stays at end
    return nil;
  }
  if (node.right !== nil) {
    return subtreeMin(node.right, nil);
  }
  let p = node.parent;
  while (p !== nil && node === p.right) {
    node = p;
    p = p.parent;
  }
  // When p is nil we've walked past the root – that means node was the max.
  return p;
}

/** In-order predecessor.  When called on nil (end), returns the tree maximum. */
function predecessor<T>(
  node: RBNode<T>,
  nil: RBNode<T>,
  root: () => RBNode<T>,
): RBNode<T> {
  if (node === nil) {
    // end().prev() → maximum element
    const r = root();
    return r === nil ? nil : subtreeMax(r, nil);
  }
  if (node.left !== nil) {
    return subtreeMax(node.left, nil);
  }
  let p = node.parent;
  while (p !== nil && node === p.left) {
    node = p;
    p = p.parent;
  }
  return p;
}

function subtreeMin<T>(node: RBNode<T>, nil: RBNode<T>): RBNode<T> {
  while (node.left !== nil) {
    node = node.left;
  }
  return node;
}

function subtreeMax<T>(node: RBNode<T>, nil: RBNode<T>): RBNode<T> {
  while (node.right !== nil) {
    node = node.right;
  }
  return node;
}

// ---------------------------------------------------------------------------
// SortedSet<T>
// ---------------------------------------------------------------------------

/** Comparator function: negative ⇒ a < b, 0 ⇒ equal, positive ⇒ a > b. */
export type Comparator<T> = (a: T, b: T) => number;

/**
 * A sorted set backed by a red-black tree with a custom comparator.
 *
 * Semantics mirror C++ `std::set<T, Compare>`:
 *   - Unique elements (duplicates are rejected)
 *   - O(log n) insert / erase / find / lower_bound / upper_bound
 *   - Iterators are stable across mutations of *other* elements
 */
export class SortedSet<T> {
  /** @internal */ _nil: RBNode<T>;
  /** @internal */ _root: RBNode<T>;
  /** @internal */ _size: number;
  /** @internal */ _cmp: Comparator<T>;

  constructor(comparator: Comparator<T>) {
    // Sentinel NIL node — always black, parent/left/right point to itself.
    this._nil = new RBNode<T>(undefined as unknown as T, Color.BLACK, null!);
    this._nil.left = this._nil;
    this._nil.right = this._nil;
    this._nil.parent = this._nil;

    this._root = this._nil;
    this._size = 0;
    this._cmp = comparator;
  }

  // -- Capacity -----------------------------------------------------------

  /** Number of elements in the set. */
  get size(): number {
    return this._size;
  }

  /** True when the set contains no elements. */
  get empty(): boolean {
    return this._size === 0;
  }

  // -- Iterators ----------------------------------------------------------

  /** @internal helper to create an iterator */
  private _iter(node: RBNode<T>): SortedSetIterator<T> {
    return new SortedSetIterator<T>(node, this._nil, () => this._root);
  }

  /** Iterator to the minimum element, or `end()` if empty. */
  begin(): SortedSetIterator<T> {
    if (this._root === this._nil) return this.end();
    return this._iter(subtreeMin(this._root, this._nil));
  }

  /** Past-the-end sentinel iterator. */
  end(): SortedSetIterator<T> {
    return this._iter(this._nil);
  }

  /** Iterator to the maximum element, or `end()` if empty. */
  rbegin(): SortedSetIterator<T> {
    if (this._root === this._nil) return this.end();
    return this._iter(subtreeMax(this._root, this._nil));
  }

  // -- Lookup -------------------------------------------------------------

  /**
   * Iterator to the element equal to `value`, or `end()` if not found.
   * Equivalent to C++ `std::set::find`.
   */
  find(value: T): SortedSetIterator<T> {
    let node = this._root;
    const nil = this._nil;
    while (node !== nil) {
      const c = this._cmp(value, node.value);
      if (c < 0) {
        node = node.left;
      } else if (c > 0) {
        node = node.right;
      } else {
        return this._iter(node);
      }
    }
    return this.end();
  }

  /**
   * Iterator to the first element ≥ `value`, or `end()` if no such element.
   * Equivalent to C++ `std::set::lower_bound`.
   */
  lower_bound(value: T): SortedSetIterator<T> {
    let node = this._root;
    const nil = this._nil;
    let result: RBNode<T> = nil;
    while (node !== nil) {
      const c = this._cmp(value, node.value);
      if (c <= 0) {
        // node.value >= value — candidate
        result = node;
        node = node.left;
      } else {
        node = node.right;
      }
    }
    return this._iter(result);
  }

  /**
   * Iterator to the first element > `value`, or `end()` if no such element.
   * Equivalent to C++ `std::set::upper_bound`.
   */
  upper_bound(value: T): SortedSetIterator<T> {
    let node = this._root;
    const nil = this._nil;
    let result: RBNode<T> = nil;
    while (node !== nil) {
      const c = this._cmp(value, node.value);
      if (c < 0) {
        // node.value > value — candidate
        result = node;
        node = node.left;
      } else {
        node = node.right;
      }
    }
    return this._iter(result);
  }

  /**
   * Check whether the set contains an element equal to `value`.
   */
  has(value: T): boolean {
    return !this.find(value).isEnd;
  }

  // -- Modifiers ----------------------------------------------------------

  /**
   * Insert `value` into the set.
   * @returns A tuple `[iterator, inserted]` where `inserted` is true if the
   *          element was added (false means an equal element already existed).
   *          The iterator points to the (possibly pre-existing) element.
   */
  insert(value: T): [SortedSetIterator<T>, boolean] {
    const nil = this._nil;
    let parent: RBNode<T> = nil;
    let node: RBNode<T> = this._root;
    let cmp = 0;
    while (node !== nil) {
      parent = node;
      cmp = this._cmp(value, node.value);
      if (cmp < 0) {
        node = node.left;
      } else if (cmp > 0) {
        node = node.right;
      } else {
        // Duplicate – return existing
        return [this._iter(node), false];
      }
    }

    const z = new RBNode<T>(value, Color.RED, nil);
    z.parent = parent;
    if (parent === nil) {
      this._root = z;
    } else if (cmp < 0) {
      parent.left = z;
    } else {
      parent.right = z;
    }
    this._size++;
    this._insertFixup(z);
    return [this._iter(z), true];
  }

  /**
   * Erase the element at `it`.
   * @returns An iterator to the element that followed the erased one (like
   *          C++ `std::set::erase(iterator)`).
   */
  erase(it: SortedSetIterator<T>): SortedSetIterator<T> {
    const z = it._node;
    if (z === this._nil) {
      return this.end();
    }
    // Capture successor *before* we splice anything out.
    const nxt = successor(z, this._nil, () => this._root);
    this._deleteNode(z);
    this._size--;
    return this._iter(nxt);
  }

  /**
   * Erase the element equal to `value`, if present.
   * @returns true if an element was removed.
   */
  eraseValue(value: T): boolean {
    const it = this.find(value);
    if (it.isEnd) return false;
    this.erase(it);
    return true;
  }

  /** Remove all elements. */
  clear(): void {
    this._root = this._nil;
    this._size = 0;
  }

  // -- ES iteration -------------------------------------------------------

  /** Iterate values in sorted order (for-of support). */
  *[Symbol.iterator](): IterableIterator<T> {
    let node = this._root === this._nil ? this._nil : subtreeMin(this._root, this._nil);
    while (node !== this._nil) {
      yield node.value;
      node = successor(node, this._nil, () => this._root);
    }
  }

  // -- Red-black tree internals -------------------------------------------

  /** @internal */
  private _rotateLeft(x: RBNode<T>): void {
    const y = x.right;
    x.right = y.left;
    if (y.left !== this._nil) {
      y.left.parent = x;
    }
    y.parent = x.parent;
    if (x.parent === this._nil) {
      this._root = y;
    } else if (x === x.parent.left) {
      x.parent.left = y;
    } else {
      x.parent.right = y;
    }
    y.left = x;
    x.parent = y;
  }

  /** @internal */
  private _rotateRight(x: RBNode<T>): void {
    const y = x.left;
    x.left = y.right;
    if (y.right !== this._nil) {
      y.right.parent = x;
    }
    y.parent = x.parent;
    if (x.parent === this._nil) {
      this._root = y;
    } else if (x === x.parent.right) {
      x.parent.right = y;
    } else {
      x.parent.left = y;
    }
    y.right = x;
    x.parent = y;
  }

  /** @internal Restore red-black properties after insertion. */
  private _insertFixup(z: RBNode<T>): void {
    while (z.parent.color === Color.RED) {
      if (z.parent === z.parent.parent.left) {
        const y = z.parent.parent.right; // uncle
        if (y.color === Color.RED) {
          // Case 1: uncle is red
          z.parent.color = Color.BLACK;
          y.color = Color.BLACK;
          z.parent.parent.color = Color.RED;
          z = z.parent.parent;
        } else {
          if (z === z.parent.right) {
            // Case 2: z is right child → rotate to make it case 3
            z = z.parent;
            this._rotateLeft(z);
          }
          // Case 3: z is left child
          z.parent.color = Color.BLACK;
          z.parent.parent.color = Color.RED;
          this._rotateRight(z.parent.parent);
        }
      } else {
        // Symmetric: parent is a right child
        const y = z.parent.parent.left; // uncle
        if (y.color === Color.RED) {
          z.parent.color = Color.BLACK;
          y.color = Color.BLACK;
          z.parent.parent.color = Color.RED;
          z = z.parent.parent;
        } else {
          if (z === z.parent.left) {
            z = z.parent;
            this._rotateRight(z);
          }
          z.parent.color = Color.BLACK;
          z.parent.parent.color = Color.RED;
          this._rotateLeft(z.parent.parent);
        }
      }
    }
    this._root.color = Color.BLACK;
  }

  /**
   * @internal Replace subtree rooted at `u` with subtree rooted at `v`.
   * (Transplant from CLRS.)
   */
  private _transplant(u: RBNode<T>, v: RBNode<T>): void {
    if (u.parent === this._nil) {
      this._root = v;
    } else if (u === u.parent.left) {
      u.parent.left = v;
    } else {
      u.parent.right = v;
    }
    v.parent = u.parent;
  }

  /**
   * @internal Delete node z from the tree and fix up.
   *
   * This follows the CLRS algorithm.  We additionally handle iterator
   * stability: when we need to splice out the successor (y ≠ z), we move y's
   * value into z *and* repoint any external iterator that was sitting on y so
   * it now points to z.  However since we don't track external iterators, the
   * standard approach is acceptable: after `erase(it)`, `it` is invalidated.
   * The *returned* iterator is freshly constructed.
   *
   * To preserve iterator stability for *other* iterators we never move values
   * between nodes.  Instead we physically re-link y in z's position in the
   * tree (the "swap node links" approach).
   */
  private _deleteNode(z: RBNode<T>): void {
    const nil = this._nil;
    let y: RBNode<T>;
    let x: RBNode<T>;
    let yOrigColor: Color;

    if (z.left === nil || z.right === nil) {
      // z has at most one non-nil child.
      y = z;
      yOrigColor = y.color;
      x = z.left !== nil ? z.left : z.right;
      this._transplant(z, x);
    } else {
      // z has two children — find in-order successor y (minimum of right subtree).
      y = subtreeMin(z.right, nil);
      yOrigColor = y.color;
      x = y.right;

      if (y.parent === z) {
        // y is a direct child of z.  x (which might be nil) should parent to y
        // *after* we move y into z's position.
        x.parent = y;
      } else {
        // Detach y from its current position.
        this._transplant(y, y.right);
        y.right = z.right;
        y.right.parent = y;
      }

      // Put y in z's position.
      this._transplant(z, y);
      y.left = z.left;
      y.left.parent = y;
      y.color = z.color;
    }

    if (yOrigColor === Color.BLACK) {
      this._deleteFixup(x);
    }
  }

  /** @internal Restore red-black properties after deletion. */
  private _deleteFixup(x: RBNode<T>): void {
    while (x !== this._root && x.color === Color.BLACK) {
      if (x === x.parent.left) {
        let w = x.parent.right; // sibling
        if (w.color === Color.RED) {
          // Case 1
          w.color = Color.BLACK;
          x.parent.color = Color.RED;
          this._rotateLeft(x.parent);
          w = x.parent.right;
        }
        if (w.left.color === Color.BLACK && w.right.color === Color.BLACK) {
          // Case 2
          w.color = Color.RED;
          x = x.parent;
        } else {
          if (w.right.color === Color.BLACK) {
            // Case 3
            w.left.color = Color.BLACK;
            w.color = Color.RED;
            this._rotateRight(w);
            w = x.parent.right;
          }
          // Case 4
          w.color = x.parent.color;
          x.parent.color = Color.BLACK;
          w.right.color = Color.BLACK;
          this._rotateLeft(x.parent);
          x = this._root;
        }
      } else {
        // Symmetric
        let w = x.parent.left;
        if (w.color === Color.RED) {
          w.color = Color.BLACK;
          x.parent.color = Color.RED;
          this._rotateRight(x.parent);
          w = x.parent.left;
        }
        if (w.right.color === Color.BLACK && w.left.color === Color.BLACK) {
          w.color = Color.RED;
          x = x.parent;
        } else {
          if (w.left.color === Color.BLACK) {
            w.right.color = Color.BLACK;
            w.color = Color.RED;
            this._rotateLeft(w);
            w = x.parent.left;
          }
          w.color = x.parent.color;
          x.parent.color = Color.BLACK;
          w.left.color = Color.BLACK;
          this._rotateRight(x.parent);
          x = this._root;
        }
      }
    }
    x.color = Color.BLACK;
  }
}

// ---------------------------------------------------------------------------
// SortedMap<K, V>
// ---------------------------------------------------------------------------

/** Internal entry stored inside the SortedMap's backing SortedSet. */
interface MapEntry<K, V> {
  key: K;
  value: V;
}

/**
 * Iterator over a SortedMap, yielding `[key, value]` pairs in key order.
 */
export class SortedMapIterator<K, V> {
  /** @internal */
  _inner: SortedSetIterator<MapEntry<K, V>>;

  /** @internal */
  constructor(inner: SortedSetIterator<MapEntry<K, V>>) {
    this._inner = inner;
  }

  get key(): K {
    return this._inner.value.key;
  }

  get value(): V {
    return this._inner.value.value;
  }

  set value(v: V) {
    this._inner.value.value = v;
  }

  get isEnd(): boolean {
    return this._inner.isEnd;
  }

  next(): this {
    this._inner.next();
    return this;
  }

  prev(): this {
    this._inner.prev();
    return this;
  }

  equals(other: SortedMapIterator<K, V>): boolean {
    return this._inner.equals(other._inner);
  }

  clone(): SortedMapIterator<K, V> {
    return new SortedMapIterator<K, V>(this._inner.clone());
  }
}

/**
 * A sorted map backed by a red-black tree, keyed by a custom comparator.
 *
 * Semantics mirror C++ `std::map<K, V, Compare>`:
 *   - Unique keys
 *   - O(log n) get / set / delete / lower_bound / upper_bound
 *   - Stable iterators
 */
export class SortedMap<K, V> {
  /** @internal */
  private _set: SortedSet<MapEntry<K, V>>;
  /** @internal – reusable probe entry to avoid allocation in lookups. */
  private _probe: MapEntry<K, V>;

  constructor(comparator: Comparator<K>) {
    this._set = new SortedSet<MapEntry<K, V>>((a, b) => comparator(a.key, b.key));
    this._probe = { key: undefined as unknown as K, value: undefined as unknown as V };
  }

  // -- Capacity -----------------------------------------------------------

  get size(): number {
    return this._set.size;
  }

  get empty(): boolean {
    return this._set.empty;
  }

  // -- Iterators ----------------------------------------------------------

  private _wrap(it: SortedSetIterator<MapEntry<K, V>>): SortedMapIterator<K, V> {
    return new SortedMapIterator<K, V>(it);
  }

  begin(): SortedMapIterator<K, V> {
    return this._wrap(this._set.begin());
  }

  end(): SortedMapIterator<K, V> {
    return this._wrap(this._set.end());
  }

  rbegin(): SortedMapIterator<K, V> {
    return this._wrap(this._set.rbegin());
  }

  // -- Lookup -------------------------------------------------------------

  /** Get the value associated with `key`, or `undefined` if absent. */
  get(key: K): V | undefined {
    this._probe.key = key;
    const it = this._set.find(this._probe);
    return it.isEnd ? undefined : it.value.value;
  }

  /** Check whether a given key exists. */
  has(key: K): boolean {
    this._probe.key = key;
    return this._set.has(this._probe);
  }

  /**
   * Find the entry with the given key.
   * @returns A map iterator, or `end()` if not found.
   */
  find(key: K): SortedMapIterator<K, V> {
    this._probe.key = key;
    return this._wrap(this._set.find(this._probe));
  }

  /** Iterator to first entry with key ≥ `key`. */
  lower_bound(key: K): SortedMapIterator<K, V> {
    this._probe.key = key;
    return this._wrap(this._set.lower_bound(this._probe));
  }

  /** Iterator to first entry with key > `key`. */
  upper_bound(key: K): SortedMapIterator<K, V> {
    this._probe.key = key;
    return this._wrap(this._set.upper_bound(this._probe));
  }

  // -- Modifiers ----------------------------------------------------------

  /**
   * Insert or update a key-value pair.
   * If the key already exists, the value is overwritten.
   * @returns The map iterator pointing to the entry.
   */
  set(key: K, value: V): SortedMapIterator<K, V> {
    const entry: MapEntry<K, V> = { key, value };
    const [it, inserted] = this._set.insert(entry);
    if (!inserted) {
      // Key already present – update the value in place.
      it.value.value = value;
    }
    return this._wrap(it);
  }

  /**
   * Insert a key-value pair only if the key does not already exist.
   * @returns `[iterator, inserted]` — same semantics as C++ `std::map::insert`.
   */
  insert(key: K, value: V): [SortedMapIterator<K, V>, boolean] {
    const entry: MapEntry<K, V> = { key, value };
    const [it, inserted] = this._set.insert(entry);
    return [this._wrap(it), inserted];
  }

  /**
   * Delete the entry with the given key.
   * @returns true if the key existed and was removed.
   */
  delete(key: K): boolean {
    this._probe.key = key;
    return this._set.eraseValue(this._probe);
  }

  /**
   * Erase the entry at the given iterator.
   * @returns An iterator to the next entry.
   */
  erase(it: SortedMapIterator<K, V>): SortedMapIterator<K, V> {
    return this._wrap(this._set.erase(it._inner));
  }

  /** Remove all entries. */
  clear(): void {
    this._set.clear();
  }

  // -- ES iteration -------------------------------------------------------

  /** Iterate `[key, value]` pairs in key order. */
  *entries(): IterableIterator<[K, V]> {
    for (const entry of this._set) {
      yield [entry.key, entry.value];
    }
  }

  /** Iterate keys in order. */
  *keys(): IterableIterator<K> {
    for (const entry of this._set) {
      yield entry.key;
    }
  }

  /** Iterate values in key order. */
  *values(): IterableIterator<V> {
    for (const entry of this._set) {
      yield entry.value;
    }
  }

  /** for-of yields `[key, value]` pairs. */
  [Symbol.iterator](): IterableIterator<[K, V]> {
    return this.entries();
  }
}
