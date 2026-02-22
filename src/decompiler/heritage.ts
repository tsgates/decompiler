// heritage_part1.ts  — Ghidra heritage (SSA construction), Part 1
// Translated from heritage.hh + first ~1400 lines of heritage.cc

// ---- Imports from existing modules ----
import { Address, SeqNum, RangeList } from "../core/address.js";
import { AddrSpace, spacetype } from "../core/space.js";
import { OpCode } from "../core/opcodes.js";

// Const enum aliases for OpCode members
const CPUI_COPY = OpCode.CPUI_COPY;
const CPUI_SUBPIECE = OpCode.CPUI_SUBPIECE;
const CPUI_PIECE = OpCode.CPUI_PIECE;
const CPUI_MULTIEQUAL = OpCode.CPUI_MULTIEQUAL;
const CPUI_INDIRECT = OpCode.CPUI_INDIRECT;
const CPUI_LOAD = OpCode.CPUI_LOAD;
const CPUI_STORE = OpCode.CPUI_STORE;
const CPUI_CALL = OpCode.CPUI_CALL;
const CPUI_CALLIND = OpCode.CPUI_CALLIND;
const CPUI_CALLOTHER = OpCode.CPUI_CALLOTHER;
const CPUI_NEW = OpCode.CPUI_NEW;
const CPUI_INT_ADD = OpCode.CPUI_INT_ADD;
const CPUI_SEGMENTOP = OpCode.CPUI_SEGMENTOP;
const CPUI_RETURN = OpCode.CPUI_RETURN;
const CPUI_FLOAT_FLOAT2FLOAT = OpCode.CPUI_FLOAT_FLOAT2FLOAT;
import { Varnode, VarnodeBank } from "../decompiler/varnode.js";
import { PcodeOp } from "../decompiler/op.js";
import { PreferSplitManager } from "../decompiler/prefersplit.js";
import { AddrSpaceManager } from "../core/translate.js";

// ---- Forward type declarations for not-yet-translated modules ----
type Funcdata = any;
type FuncCallSpecs = any;
type FlowBlock = any;
type BlockBasic = any;
type JoinRecord = any;
type ValueSetRead = any;
type CircleRange = any;
// RangeList imported from address.js
type ValueSetSolver = any;
type WidenerNone = any;
import { WidenerFull } from './rangeutil.js';
type ParamActive = any;
type ParamEntry = any;
type VarnodeData = any;
type VarnodeLocSet = any;
type EffectRecord = any;
type FuncProto = any;

// ---- Constants mirrored from C++ enums / statics ----

/** spacetype enum value for stack-based spaces */
const IPTR_SPACEBASE = 2;
/** spacetype enum value for IOP references */
const IPTR_IOP = 4;

/** EffectRecord effect types */
const EffectRecord_unaffected = 1;
const EffectRecord_killedbycall = 2;
const EffectRecord_return_address = 3;
const EffectRecord_unknown_effect = 4;

/** ParamEntry containment codes */
const ParamEntry_no_containment = 0;
const ParamEntry_contains_justified = 2;
const ParamEntry_contained_by = 3;

/** PcodeOp flag for INDIRECT caused by STORE */
const PcodeOp_indirect_store = 0x80000000;

/** FuncCallSpecs "magic" unknown stack offset */
const FuncCallSpecs_offset_unknown = 0xBADBEEF;

// ---- VariableStack ----
// In C++ this is map<Address, vector<Varnode*>> using Address::operator< for comparison.
// In JS, Map uses reference identity for object keys, so we use a string key instead.
export type VariableStack = Map<string, Varnode[]>;

/** Convert an Address to a string key for use in VariableStack */
function addrKey(addr: Address): string {
  const spc = addr.getSpace();
  return spc === null ? `-1:${addr.getOffset()}` : `${spc.getIndex()}:${addr.getOffset()}`;
}

// ============================================================================
//  LocationMap
// ============================================================================

/** Label for extent of an address range that has been heritaged */
export interface SizePass {
  size: number;   // Size of the range (in bytes)
  pass: number;   // Pass when the range was heritaged
}

/**
 * Map object for keeping track of which address ranges have been heritaged.
 *
 * We keep track of a fairly fine-grained description of when each address range
 * was entered in SSA form, referred to as "heritaged" or, for Varnode objects,
 * no longer "free".  An address range is added using add(), which includes
 * the particular pass when it was entered.  The map can be queried using
 * findPass() that informs the caller whether the address has been heritaged and
 * if so in which pass.
 */
export class LocationMap {
  private themap: Map<Address, SizePass> = new Map();

  /**
   * Mark a new address as heritaged.
   *
   * Update disjoint cover making sure (addr, size) is contained in a single
   * element and return the key for that element.  The element's pass number is
   * set to be the smallest value of any previous intersecting element.
   * Additionally an intersect code is passed back:
   *   - 0 if the only intersection is with a range from the same pass
   *   - 1 if there is a partial intersection with something old
   *   - 2 if the range is contained in an old range
   *
   * @returns { key, intersect }
   */
  add(addr: Address, size: number, pass: number): { key: Address; intersect: number } {
    // Get sorted keys
    const keys = this.sortedKeys();
    // Find first key <= addr via lower_bound-like logic
    let idx = this.lowerBound(keys, addr);

    // Back up one if possible
    if (idx > 0) idx--;
    // If the entry before doesn't overlap, advance
    if (idx < keys.length) {
      const k = keys[idx];
      const sp = this.themap.get(k)!;
      if (addr.overlap(0, k, sp.size) === -1) {
        idx++;
      }
    }

    let where = 0;
    let intersect = 0;

    // Check if the current entry overlaps
    if (idx < keys.length) {
      const k = keys[idx];
      const sp = this.themap.get(k)!;
      where = addr.overlap(0, k, sp.size);
      if (where !== -1) {
        if (where + size <= sp.size) {
          intersect = (sp.pass < pass) ? 2 : 0;
          return { key: k, intersect };
        }
        addr = k;
        size = where + size;
        if (sp.pass < pass) {
          intersect = 1;
          pass = sp.pass;
        }
        this.themap.delete(k);
        keys.splice(idx, 1);
      }
    }

    // Merge with subsequent overlapping entries
    while (idx < keys.length) {
      const k = keys[idx];
      const sp = this.themap.get(k)!;
      where = k.overlap(0, addr, size);
      if (where === -1) break;
      if (where + sp.size > size) {
        size = where + sp.size;
      }
      if (sp.pass < pass) {
        intersect = 1;
        pass = sp.pass;
      }
      this.themap.delete(k);
      keys.splice(idx, 1);
    }

    const sp: SizePass = { size, pass };
    this.themap.set(addr, sp);
    return { key: addr, intersect };
  }

  /**
   * If the given address was heritaged, return the SizePass entry.
   * Returns undefined if the address is unheritaged.
   */
  find(addr: Address): { key: Address; value: SizePass } | undefined {
    const keys = this.sortedKeys();
    let idx = this.upperBound(keys, addr);
    if (idx === 0) return undefined;
    idx--;
    const k = keys[idx];
    const sp = this.themap.get(k)!;
    if (addr.overlap(0, k, sp.size) !== -1) {
      return { key: k, value: sp };
    }
    return undefined;
  }

  /**
   * Return the pass number when the given address was heritaged, or -1 if
   * it was not heritaged.
   */
  findPass(addr: Address): number {
    const keys = this.sortedKeys();
    let idx = this.upperBound(keys, addr);
    if (idx === 0) return -1;
    idx--;
    const k = keys[idx];
    const sp = this.themap.get(k)!;
    if (addr.overlap(0, k, sp.size) !== -1) {
      return sp.pass;
    }
    return -1;
  }

  erase(key: Address): void {
    this.themap.delete(key);
  }

  entries(): IterableIterator<[Address, SizePass]> {
    return this.themap.entries();
  }

  clear(): void {
    this.themap.clear();
  }

  // ---- internal helpers for ordered iteration ----
  private sortedKeys(): Address[] {
    return Array.from(this.themap.keys()).sort((a, b) => Address.compare(a, b));
  }

  /** Return index of first key >= addr */
  private lowerBound(keys: Address[], addr: Address): number {
    let lo = 0;
    let hi = keys.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (Address.compare(keys[mid], addr) < 0) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  }

  /** Return index of first key > addr */
  private upperBound(keys: Address[], addr: Address): number {
    let lo = 0;
    let hi = keys.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (Address.compare(keys[mid], addr) <= 0) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  }
}

// ============================================================================
//  MemRange
// ============================================================================

/** An address range to be processed */
export class MemRange {
  static readonly new_addresses = 1;
  static readonly old_addresses = 2;

  addr: Address;
  size: number;
  flags: number;

  constructor(addr: Address, size: number, flags: number) {
    this.addr = addr;
    this.size = size;
    this.flags = flags;
  }

  /** Does this range cover new addresses? */
  newAddresses(): boolean {
    return (this.flags & MemRange.new_addresses) !== 0;
  }

  /** Does this range cover old addresses? */
  oldAddresses(): boolean {
    return (this.flags & MemRange.old_addresses) !== 0;
  }

  /** Clear specific properties from the memory range */
  clearProperty(val: number): void {
    this.flags &= ~val;
  }
}

// ============================================================================
//  TaskList
// ============================================================================

/**
 * A list of address ranges that need to be converted to SSA form.
 *
 * The disjoint list of ranges are built up and processed in a single pass.
 * The container is fed a list of ranges that may be overlapping but are already
 * in address order.  It constructs a disjoint list by taking the union of
 * overlapping ranges.
 */
export class TaskList {
  private tasklist: MemRange[] = [];

  /**
   * Add a range to the list.  Addresses fed to this method must already be
   * sorted.  If the given range intersects the last range in the list the
   * last range is extended to cover it.  Otherwise the range is added as a
   * new element.
   */
  add(addr: Address, size: number, fl: number): void {
    if (this.tasklist.length > 0) {
      const entry = this.tasklist[this.tasklist.length - 1];
      const over = addr.overlap(0, entry.addr, entry.size);
      if (over >= 0) {
        const relsize = size + over;
        if (relsize > entry.size) entry.size = relsize;
        entry.flags |= fl;
        return;
      }
    }
    this.tasklist.push(new MemRange(addr, size, fl));
  }

  /**
   * Insert a disjoint range before the given index.
   * @returns the index of the newly inserted range
   */
  insert(pos: number, addr: Address, size: number, fl: number): number {
    this.tasklist.splice(pos, 0, new MemRange(addr, size, fl));
    return pos;
  }

  /** Remove a particular range by index */
  erase(idx: number): void {
    this.tasklist.splice(idx, 1);
  }

  /** Get the range at the given index */
  get(idx: number): MemRange {
    return this.tasklist[idx];
  }

  /** Number of ranges in the list */
  get length(): number {
    return this.tasklist.length;
  }

  /** Iterate over ranges */
  [Symbol.iterator](): IterableIterator<MemRange> {
    return this.tasklist[Symbol.iterator]();
  }

  /** Clear all ranges in the list */
  clear(): void {
    this.tasklist.length = 0;
  }
}

// ============================================================================
//  PriorityQueue
// ============================================================================

/**
 * Priority queue for the phi-node (MULTIEQUAL) placement algorithm.
 *
 * A work-list for basic blocks used during phi-node placement.  Implemented as
 * a set of stacks with an associated priority.  Blocks are placed in the queue
 * with an associated priority (or depth) using insert().  The current highest
 * priority block is retrieved with extract().
 */
export class PriorityQueue {
  private queue: FlowBlock[][] = [];
  private curdepth: number = -2;

  /** Reset to an empty queue */
  reset(maxdepth: number): void {
    if (this.curdepth === -1 && maxdepth === this.queue.length - 1) return;
    this.queue = [];
    for (let i = 0; i <= maxdepth; i++) {
      this.queue.push([]);
    }
    this.curdepth = -1;
  }

  /** Insert a block into the queue given its priority */
  insert(bl: FlowBlock, depth: number): void {
    this.queue[depth].push(bl);
    if (depth > this.curdepth) this.curdepth = depth;
  }

  /**
   * Retrieve the highest priority block.
   * Should not be called if the queue is empty.
   */
  extract(): FlowBlock {
    const res = this.queue[this.curdepth].pop()!;
    while (this.queue[this.curdepth].length === 0) {
      this.curdepth -= 1;
      if (this.curdepth < 0) break;
    }
    return res;
  }

  /** Return true if this queue is empty */
  empty(): boolean {
    return this.curdepth === -1;
  }
}

// ============================================================================
//  HeritageInfo
// ============================================================================

/**
 * Information about heritage passes performed for a specific address space.
 *
 * For a particular address space this keeps track of:
 *   - how long to delay heritage
 *   - how long to delay dead code removal
 *   - whether dead code has been removed (for this space)
 *   - have warnings been issued
 */
export class HeritageInfo {
  space: AddrSpace | null;
  delay: number;
  deadcodedelay: number;
  deadremoved: number;
  loadGuardSearch: boolean;
  warningissued: boolean;
  hasCallPlaceholders: boolean;

  constructor(spc: AddrSpace | null) {
    if (spc === null) {
      this.space = null;
      this.delay = 0;
      this.deadcodedelay = 0;
      this.hasCallPlaceholders = false;
    } else if (!spc.isHeritaged()) {
      this.space = null;
      this.delay = spc.getDelay();
      this.deadcodedelay = spc.getDeadcodeDelay();
      this.hasCallPlaceholders = false;
    } else {
      this.space = spc;
      this.delay = spc.getDelay();
      this.deadcodedelay = spc.getDeadcodeDelay();
      this.hasCallPlaceholders = (spc.getType() === IPTR_SPACEBASE);
    }
    this.deadremoved = 0;
    this.warningissued = false;
    this.loadGuardSearch = false;
  }

  /** Return true if heritage is performed on this space */
  isHeritaged(): boolean {
    return this.space !== null;
  }

  /** Reset the state */
  reset(): void {
    this.deadremoved = 0;
    if (this.space !== null) {
      this.hasCallPlaceholders = (this.space.getType() === IPTR_SPACEBASE);
    }
    this.warningissued = false;
    this.loadGuardSearch = false;
  }
}

// ============================================================================
//  LoadGuard
// ============================================================================

/**
 * Description of a LOAD operation that needs to be guarded.
 *
 * Heritage maintains a list of CPUI_LOAD ops that reference the stack
 * dynamically.  These can potentially alias stack Varnodes, so we maintain
 * what (possibly limited) information we know about the range of stack
 * addresses that can be referenced.
 */
export class LoadGuard {
  op!: PcodeOp;
  spc!: AddrSpace;
  pointerBase: bigint = 0n;
  minimumOffset: bigint = 0n;
  maximumOffset: bigint = 0n;
  step: number = 0;
  analysisState: number = 0;   // 0=unanalyzed, 1=analyzed(partial), 2=analyzed(full)

  /** Set a new unanalyzed LOAD guard that initially guards everything */
  set(o: PcodeOp, s: AddrSpace, off: bigint): void {
    this.op = o;
    this.spc = s;
    this.pointerBase = off;
    this.minimumOffset = 0n;
    this.maximumOffset = s.getHighest();
    this.step = 0;
    this.analysisState = 0;
  }

  /** Get the PcodeOp being guarded */
  getOp(): PcodeOp { return this.op; }

  /** Get minimum offset of the guarded range */
  getMinimum(): bigint { return this.minimumOffset; }

  /** Get maximum offset of the guarded range */
  getMaximum(): bigint { return this.maximumOffset; }

  /** Get the calculated step associated with the range (or 0) */
  getStep(): number { return this.step; }

  /** Does this guard apply to the given address */
  isGuarded(addr: Address): boolean {
    if (addr.getSpace() !== this.spc) return false;
    if (addr.getOffset() < this.minimumOffset) return false;
    if (addr.getOffset() > this.maximumOffset) return false;
    return true;
  }

  /** Return true if the range is fully determined */
  isRangeLocked(): boolean { return this.analysisState === 2; }

  /** Return true if the record still describes an active LOAD */
  isValid(opc: OpCode): boolean {
    return (!this.op.isDead() && this.op.code() === opc);
  }

  /**
   * Convert partial value set analysis into guard range.
   */
  establishRange(valueSet: ValueSetRead): void {
    const range: CircleRange = valueSet.getRange();
    const rangeSize: bigint = range.getSize();
    let size: bigint;
    if (range.isEmpty()) {
      this.minimumOffset = this.pointerBase;
      size = 0x1000n;
    } else if (range.isFull() || rangeSize > 0xffffffn) {
      this.minimumOffset = this.pointerBase;
      size = 0x1000n;
      this.analysisState = 1;
    } else {
      this.step = (rangeSize === 3n) ? range.getStep() : 0;
      size = 0x1000n;
      if (valueSet.isLeftStable()) {
        this.minimumOffset = range.getMin();
      } else if (valueSet.isRightStable()) {
        if (this.pointerBase < range.getEnd()) {
          this.minimumOffset = this.pointerBase;
          size = range.getEnd() - this.pointerBase;
        } else {
          this.minimumOffset = range.getMin();
          size = rangeSize * BigInt(range.getStep());
        }
      } else {
        this.minimumOffset = this.pointerBase;
      }
    }

    const max: bigint = this.spc.getHighest();
    if (this.minimumOffset > max) {
      this.minimumOffset = max;
      this.maximumOffset = this.minimumOffset;
    } else {
      const maxSize: bigint = (max - this.minimumOffset) + 1n;
      if (size > maxSize) size = maxSize;
      this.maximumOffset = this.minimumOffset + size - 1n;
    }
  }

  /**
   * Convert value set analysis to final guard range.
   */
  finalizeRange(valueSet: ValueSetRead): void {
    this.analysisState = 1;
    const range: CircleRange = valueSet.getRange();
    let rangeSize: bigint = range.getSize();
    if (rangeSize === 0x100n || rangeSize === 0x10000n) {
      if (this.step === 0) rangeSize = 0n;
    }
    if (rangeSize > 1n && rangeSize < 0xffffffn) {
      this.analysisState = 2;
      if (rangeSize > 2n) this.step = range.getStep();
      this.minimumOffset = range.getMin();
      this.maximumOffset = (range.getEnd() - 1n) & range.getMask();
      if (this.maximumOffset < this.minimumOffset) {
        this.maximumOffset = this.spc.getHighest();
        this.analysisState = 1;
      }
    }
    if (this.minimumOffset > this.spc.getHighest())
      this.minimumOffset = this.spc.getHighest();
    if (this.maximumOffset > this.spc.getHighest())
      this.maximumOffset = this.spc.getHighest();
  }
}

// ============================================================================
//  Heritage  — StackNode (inner helper)
// ============================================================================

/** Node for depth-first traversal of stack references */
interface StackNode {
  vn: Varnode;
  offset: bigint;
  traversals: number;
  iterIndex: number;           // index into vn's descend list, replaces C++ iterator
}

const StackNode_nonconstant_index = 1;
const StackNode_multiequal = 2;

function makeStackNode(vn: Varnode, offset: bigint, traversals: number): StackNode {
  return { vn, offset, traversals, iterIndex: 0 };
}

// ============================================================================
//  Heritage  — heritage_flags (inner enum)
// ============================================================================

const heritage_boundary_node = 1;
const heritage_mark_node = 2;
const heritage_merged_node = 4;

// ============================================================================
//  Heritage  class
// ============================================================================

/**
 * Manage the construction of Static Single Assignment (SSA) form.
 *
 * With a specific function (Funcdata), this class links the Varnode and
 * PcodeOp objects into the formal data-flow graph structure, SSA form.
 * The full structure can be built over multiple passes.
 */
export class Heritage {
  private fd: Funcdata;
  private globaldisjoint: LocationMap = new LocationMap();
  private disjoint: TaskList = new TaskList();
  private domchild: FlowBlock[][] = [];
  private augment: FlowBlock[][] = [];
  private flags: number[] = [];
  private depth: number[] = [];
  private maxdepth: number = -1;
  private pass: number = 0;

  private pq: PriorityQueue = new PriorityQueue();
  private merge: FlowBlock[] = [];
  private infolist: HeritageInfo[] = [];
  private loadGuard_list: LoadGuard[] = [];
  private storeGuard_list: LoadGuard[] = [];
  private loadCopyOps: PcodeOp[] = [];

  constructor(data: Funcdata) {
    this.fd = data;
    this.pass = 0;
    this.maxdepth = -1;
  }

  // ---- public accessors ----

  /** Get overall count of heritage passes */
  getPass(): number { return this.pass; }

  /** Get the pass number when the given address was heritaged (-1 if not) */
  heritagePass(addr: Address): number { return this.globaldisjoint.findPass(addr); }

  numHeritagePasses(spc: AddrSpace): number {
    const info = this.getInfo(spc);
    if (!info.isHeritaged()) return -1;
    return this.pass - info.delay;
  }

  /** Inform system of dead code removal in given space */
  seenDeadCode(spc: AddrSpace): void {
    const info = this.getInfo(spc);
    info.deadremoved += 1;
  }

  /** Get pass delay for heritaging the given space */
  getDeadCodeDelay(spc: AddrSpace): number {
    return this.getInfo(spc).deadcodedelay;
  }

  /** Set delay for a specific space */
  setDeadCodeDelay(spc: AddrSpace, delay: number): void {
    this.getInfo(spc).deadcodedelay = delay;
  }

  /** Return true if it is safe to remove dead code */
  deadRemovalAllowed(spc: AddrSpace): boolean {
    const info = this.getInfo(spc);
    return (this.pass > info.deadcodedelay);
  }

  deadRemovalAllowedSeen(spc: AddrSpace): boolean {
    const info = this.getInfo(spc);
    if (this.pass <= info.deadcodedelay) return false;
    info.deadremoved += 1;
    return true;
  }

  /** Force regeneration of basic block structures */
  forceRestructure(): void { this.maxdepth = -1; }

  /** Get list of LOAD ops that are guarded */
  getLoadGuards(): LoadGuard[] { return this.loadGuard_list; }

  /** Get list of STORE ops that are guarded */
  getStoreGuards(): LoadGuard[] { return this.storeGuard_list; }

  /** Get LoadGuard record associated with given PcodeOp */
  getStoreGuard(op: PcodeOp): LoadGuard | null {
    for (const guard of this.storeGuard_list) {
      if (guard.getOp() === op) return guard;
    }
    return null;
  }

  // ---- private helpers ----

  private getInfo(spc: AddrSpace): HeritageInfo {
    return this.infolist[spc.getIndex()];
  }

  private clearInfoList(): void {
    for (const info of this.infolist) {
      info.reset();
    }
  }

  /**
   * Remove deprecated CPUI_MULTIEQUAL, CPUI_INDIRECT, or CPUI_COPY ops,
   * preparing to re-heritage.
   */
  private removeRevisitedMarkers(remove: Varnode[], addr: Address, size: number): void {
    const info = this.getInfo(addr.getSpace()!);
    if (info.deadremoved > 0) {
      this.bumpDeadcodeDelay(addr.getSpace()!);
      if (!info.warningissued) {
        info.warningissued = true;
        const errmsg = "Heritage AFTER dead removal. Revisit: " + addr.printRaw();
        this.fd.warningHeader(errmsg);
      }
    }

    const newInputs: Varnode[] = [];
    for (let i = 0; i < remove.length; i++) {
      const vn = remove[i];
      const op: PcodeOp = vn.getDef();
      const bl: BlockBasic = op.getParent();
      let pos: number;

      if (op.code() === CPUI_INDIRECT) {
        const iopVn = op.getIn(1)!;
        const targetOp: PcodeOp = PcodeOp.getOpFromConst(iopVn.getAddr())!;
        if (targetOp.isDead())
          pos = op.getBasicIter();
        else
          pos = targetOp.getBasicIter();
        pos++;   // Insert SUBPIECE after target of INDIRECT
        vn.clearAddrForce();
      } else if (op.code() === CPUI_MULTIEQUAL) {
        pos = op.getBasicIter();
        pos++;
        while (pos < bl.endOp() && bl.getOp(pos).code() === CPUI_MULTIEQUAL) {
          pos++;
        }
      } else {
        // Remove return form COPY
        this.fd.opUnlink(op);
        continue;
      }

      const offset = vn.overlapAddr(addr, size);
      // C++ uses list iterators which remain stable after removal of other elements.
      // In TS we use array indices, so removing op shifts indices after opPos down by 1.
      const opPos = op.getBasicIter();
      this.fd.opUninsert(op);
      if (opPos < pos) pos--;  // Adjust for index shift after removal
      newInputs.length = 0;
      const big: Varnode = this.fd.newVarnode(size, addr);
      big.setActiveHeritage();
      newInputs.push(big);
      newInputs.push(this.fd.newConstant(4, offset));
      this.fd.opSetOpcode(op, CPUI_SUBPIECE);
      this.fd.opSetAllInput(op, newInputs);
      this.fd.opInsert(op, bl, pos);
      vn.setWriteMask();
    }
  }

  /**
   * Collect free reads, writes, and inputs in the given address range.
   * @returns the maximum size of a write
   */
  private collect(
    memrange: MemRange,
    read: Varnode[],
    write: Varnode[],
    input: Varnode[],
    remove: Varnode[]
  ): number {
    read.length = 0;
    write.length = 0;
    input.length = 0;
    remove.length = 0;

    const start: bigint = memrange.addr.getOffset();
    const endaddr: Address = memrange.addr.add(BigInt(memrange.size));

    let enditer: number;
    if (endaddr.getOffset() < start) {
      // Wraparound
      const tmp = new Address(endaddr.getSpace()!, endaddr.getSpace()!.getHighest());
      enditer = this.fd.endLoc(tmp);
    } else {
      enditer = this.fd.beginLoc(endaddr);
    }

    let maxsize = 0;
    for (let viter = this.fd.beginLoc(memrange.addr); !viter.equals(enditer); viter.next()) {
      const vn: Varnode = viter.get();
      if (!vn.isWriteMask()) {
        if (vn.isWritten()) {
          const op: PcodeOp = vn.getDef();
          if (op.isMarker() || op.isReturnCopy()) {
            if (vn.getSize() < memrange.size) {
              remove.push(vn);
              continue;
            }
            memrange.clearProperty(MemRange.new_addresses);
          }
          if (vn.getSize() > maxsize) maxsize = vn.getSize();
          write.push(vn);
        } else if (!vn.isHeritageKnown() && !vn.hasNoDescend()) {
          read.push(vn);
        } else if (vn.isInput()) {
          input.push(vn);
        }
      }
    }
    return maxsize;
  }

  /**
   * Determine if the address range is affected by the given call p-code op.
   */
  private callOpIndirectEffect(addr: Address, size: number, op: PcodeOp): boolean {
    if (op.code() === CPUI_CALL || op.code() === CPUI_CALLIND) {
      const fc: FuncCallSpecs = this.fd.getCallSpecs(op);
      if (fc === null) return true;
      return fc.hasEffectTranslate(addr, size) !== EffectRecord_unaffected;
    }
    // CALLOTHER, NEW — assume no effect
    return false;
  }

  /**
   * Normalize the size of a read Varnode, prior to heritage.
   * Creates a SUBPIECE to define the original (too-small) Varnode from a
   * new (correct-size) Varnode.
   */
  private normalizeReadSize(vn: Varnode, op: PcodeOp, addr: Address, size: number): Varnode {
    const newop: PcodeOp = this.fd.newOp(2, op.getAddr());
    this.fd.opSetOpcode(newop, CPUI_SUBPIECE);
    const vn1: Varnode = this.fd.newVarnode(size, addr);
    const overlap = vn.overlapAddr(addr, size);
    const vn2: Varnode = this.fd.newConstant(addr.getAddrSize(), BigInt(overlap));
    this.fd.opSetInput(newop, vn1, 0);
    this.fd.opSetInput(newop, vn2, 1);
    this.fd.opSetOutput(newop, vn);
    newop.getOut()!.setWriteMask();
    this.fd.opInsertBefore(newop, op);
    return vn1;
  }

  /**
   * Normalize the size of a written Varnode, prior to heritage.
   * Creates missing pieces in the range and concatenates everything
   * into a new Varnode of the correct size.
   */
  private normalizeWriteSize(vn: Varnode, addr: Address, size: number): Varnode {
    let mostvn: Varnode | null = null;
    const op: PcodeOp = vn.getDef();
    const overlap = vn.overlapAddr(addr, size);
    const mostsigsize = size - (overlap + vn.getSize());

    if (mostsigsize !== 0) {
      let pieceaddr: Address;
      if (addr.isBigEndian())
        pieceaddr = addr;
      else
        pieceaddr = addr.add(BigInt(overlap + vn.getSize()));
      if (op.isCall() && this.callOpIndirectEffect(pieceaddr, mostsigsize, op)) {
        const newop: PcodeOp = this.fd.newIndirectCreation(op, pieceaddr, mostsigsize, false);
        mostvn = newop.getOut()!;
      } else {
        const newop: PcodeOp = this.fd.newOp(2, op.getAddr());
        mostvn = this.fd.newVarnodeOut(mostsigsize, pieceaddr, newop);
        const big: Varnode = this.fd.newVarnode(size, addr);
        big.setActiveHeritage();
        this.fd.opSetOpcode(newop, CPUI_SUBPIECE);
        this.fd.opSetInput(newop, big, 0);
        this.fd.opSetInput(newop, this.fd.newConstant(addr.getAddrSize(), BigInt(overlap + vn.getSize())), 1);
        this.fd.opInsertBefore(newop, op);
      }
    }

    let leastvn: Varnode | null = null;
    if (overlap !== 0) {
      let pieceaddr: Address;
      if (addr.isBigEndian())
        pieceaddr = addr.add(BigInt(size - overlap));
      else
        pieceaddr = addr;
      if (op.isCall() && this.callOpIndirectEffect(pieceaddr, overlap, op)) {
        const newop: PcodeOp = this.fd.newIndirectCreation(op, pieceaddr, overlap, false);
        leastvn = newop.getOut();
      } else {
        const newop: PcodeOp = this.fd.newOp(2, op.getAddr());
        leastvn = this.fd.newVarnodeOut(overlap, pieceaddr, newop);
        const big: Varnode = this.fd.newVarnode(size, addr);
        big.setActiveHeritage();
        this.fd.opSetOpcode(newop, CPUI_SUBPIECE);
        this.fd.opSetInput(newop, big, 0);
        this.fd.opSetInput(newop, this.fd.newConstant(addr.getAddrSize(), 0n), 1);
        this.fd.opInsertBefore(newop, op);
      }
    }

    let midvn: Varnode;
    if (overlap !== 0) {
      const newop: PcodeOp = this.fd.newOp(2, op.getAddr());
      if (addr.isBigEndian())
        midvn = this.fd.newVarnodeOut(overlap + vn.getSize(), vn.getAddr(), newop);
      else
        midvn = this.fd.newVarnodeOut(overlap + vn.getSize(), addr, newop);
      this.fd.opSetOpcode(newop, CPUI_PIECE);
      this.fd.opSetInput(newop, vn, 0);       // Most significant part
      this.fd.opSetInput(newop, leastvn!, 1);  // Least sig
      this.fd.opInsertAfter(newop, op);
    } else {
      midvn = vn;
    }

    let bigout: Varnode;
    if (mostsigsize !== 0) {
      const newop: PcodeOp = this.fd.newOp(2, op.getAddr());
      bigout = this.fd.newVarnodeOut(size, addr, newop);
      this.fd.opSetOpcode(newop, CPUI_PIECE);
      this.fd.opSetInput(newop, mostvn!, 0);
      this.fd.opSetInput(newop, midvn, 1);
      this.fd.opInsertAfter(newop, midvn.getDef());
    } else {
      bigout = midvn;
    }

    vn.setWriteMask();
    return bigout;
  }

  /**
   * Concatenate a list of Varnodes together at the given location.
   * There must be at least 2 Varnodes in the list, in order from most to
   * least significant.
   */
  private concatPieces(vnlist: Varnode[], insertop: PcodeOp | null, finalvn: Varnode): Varnode {
    let preexist: Varnode = vnlist[0];
    const isbigendian: boolean = preexist.getAddr().isBigEndian();
    let opaddress: Address;
    let bl: BlockBasic;
    let insertiter: number;

    if (insertop === null) {
      bl = this.fd.getBasicBlocks().getStartBlock() as BlockBasic;
      insertiter = 0;  // beginOp() index
      opaddress = this.fd.getAddress();
    } else {
      bl = insertop.getParent();
      insertiter = insertop.getBasicIter();
      opaddress = insertop.getAddr();
    }

    for (let i = 1; i < vnlist.length; i++) {
      const vn: Varnode = vnlist[i];
      const newop: PcodeOp = this.fd.newOp(2, opaddress);
      this.fd.opSetOpcode(newop, CPUI_PIECE);
      let newvn: Varnode;
      if (i === vnlist.length - 1) {
        newvn = finalvn;
        this.fd.opSetOutput(newop, newvn);
      } else {
        newvn = this.fd.newUniqueOut(preexist.getSize() + vn.getSize(), newop);
      }
      if (isbigendian) {
        this.fd.opSetInput(newop, preexist, 0);
        this.fd.opSetInput(newop, vn, 1);
      } else {
        this.fd.opSetInput(newop, vn, 0);
        this.fd.opSetInput(newop, preexist, 1);
      }
      this.fd.opInsert(newop, bl, insertiter);
      insertiter++;  // Advance past inserted op (TS array index, unlike C++ list iterator, doesn't auto-track)
      preexist = newvn;
    }
    return preexist;
  }

  /**
   * Build a set of Varnode piece expressions at the given location.
   * Constructs a SUBPIECE op that defines each piece.
   */
  private splitPieces(
    vnlist: Varnode[],
    insertop: PcodeOp | null,
    addr: Address,
    size: number,
    startvn: Varnode
  ): void {
    let opaddress: Address;
    let baseoff: bigint;
    let bl: BlockBasic;
    let insertiter: number;

    const isbigendian: boolean = addr.isBigEndian();
    if (isbigendian)
      baseoff = addr.getOffset() + BigInt(size);
    else
      baseoff = addr.getOffset();

    if (insertop === null) {
      bl = this.fd.getBasicBlocks().getStartBlock() as BlockBasic;
      insertiter = 0;  // beginOp() index
      opaddress = this.fd.getAddress();
    } else {
      bl = insertop.getParent();
      insertiter = insertop.getBasicIter();
      insertiter++;   // Insert AFTER the write
      opaddress = insertop.getAddr();
    }

    for (let i = 0; i < vnlist.length; i++) {
      const vn: Varnode = vnlist[i];
      const newop: PcodeOp = this.fd.newOp(2, opaddress);
      this.fd.opSetOpcode(newop, CPUI_SUBPIECE);
      let diff: bigint;
      if (isbigendian)
        diff = baseoff - (vn.getOffset() + BigInt(vn.getSize()));
      else
        diff = vn.getOffset() - baseoff;
      this.fd.opSetInput(newop, startvn, 0);
      this.fd.opSetInput(newop, this.fd.newConstant(4, diff), 1);
      this.fd.opSetOutput(newop, vn);
      this.fd.opInsert(newop, bl, insertiter);
      insertiter++;  // Advance past inserted op (TS array index, unlike C++ list iterator, doesn't auto-track)
    }
  }

  /**
   * Find the last PcodeOps that write to specific addresses that flow to
   * specific sites.  Extends copySinks with artificial COPY/MULTIEQUALs
   * and populates forces with non-artificial boundary ops.
   */
  private findAddressForces(copySinks: PcodeOp[], forces: PcodeOp[]): void {
    // Mark the sinks
    for (let i = 0; i < copySinks.length; i++) {
      copySinks[i].setMark();
    }

    let pos = 0;
    while (pos < copySinks.length) {
      const op: PcodeOp = copySinks[pos];
      const addr: Address = op.getOut()!.getAddr();
      pos++;
      const maxIn = op.numInput();
      for (let i = 0; i < maxIn; i++) {
        const vn: Varnode = op.getIn(i)!;
        if (!vn.isWritten()) continue;
        if (vn.isAddrForce()) continue;
        const newOp: PcodeOp = vn.getDef();
        if (newOp.isMark()) continue;
        newOp.setMark();
        const opc: OpCode = newOp.code();
        let isArtificial = false;
        if (opc === CPUI_COPY || opc === CPUI_MULTIEQUAL) {
          isArtificial = true;
          const maxInNew = newOp.numInput();
          for (let j = 0; j < maxInNew; j++) {
            const inVn: Varnode = newOp.getIn(j)!;
            if (!addr.equals(inVn.getAddr())) {
              isArtificial = false;
              break;
            }
          }
        } else if (opc === CPUI_INDIRECT && newOp.isIndirectStore()) {
          const inVn: Varnode = newOp.getIn(0)!;
          if (addr.equals(inVn.getAddr())) isArtificial = true;
        }
        if (isArtificial)
          copySinks.push(newOp);
        else
          forces.push(newOp);
      }
    }
  }

  /**
   * Eliminate a COPY sink preserving its data-flow.
   */
  private propagateCopyAway(op: PcodeOp): void {
    let inVn: Varnode = op.getIn(0)!;
    while (inVn.isWritten()) {
      const nextOp: PcodeOp = inVn.getDef();
      if (nextOp.code() !== CPUI_COPY) break;
      const nextIn: Varnode = nextOp.getIn(0)!;
      if (!nextIn.getAddr().equals(inVn.getAddr())) break;
      inVn = nextIn;
    }
    this.fd.totalReplace(op.getOut()!, inVn);
    this.fd.opDestroy(op);
  }

  /**
   * Mark the boundary of artificial ops introduced by load guards.
   */
  private handleNewLoadCopies(): void {
    if (this.loadCopyOps.length === 0) return;
    const forces: PcodeOp[] = [];
    const copySinkSize = this.loadCopyOps.length;
    this.findAddressForces(this.loadCopyOps, forces);

    if (forces.length > 0) {
      const loadRanges: RangeList = new RangeList();
      for (const guard of this.loadGuard_list) {
        loadRanges.insertRange(guard.spc, guard.minimumOffset, guard.maximumOffset);
      }
      for (let i = 0; i < forces.length; i++) {
        const op: PcodeOp = forces[i];
        const vn: Varnode = op.getOut()!;
        if (loadRanges.inRange(vn.getAddr(), 1))
          vn.setAddrForce();
        op.clearMark();
      }
    }

    // Eliminate or propagate away original COPY sinks
    for (let i = 0; i < copySinkSize; i++) {
      this.propagateCopyAway(this.loadCopyOps[i]);
    }
    // Clear marks on remaining artificial COPYs
    for (let i = copySinkSize; i < this.loadCopyOps.length; i++) {
      this.loadCopyOps[i].clearMark();
    }
    this.loadCopyOps.length = 0;
  }

  /**
   * Make final determination of what range new LoadGuards are protecting.
   */
  private analyzeNewLoadGuards(): void {
    let nothingToDo = true;
    if (this.loadGuard_list.length > 0) {
      if (this.loadGuard_list[this.loadGuard_list.length - 1].analysisState === 0)
        nothingToDo = false;
    }
    if (this.storeGuard_list.length > 0) {
      if (this.storeGuard_list[this.storeGuard_list.length - 1].analysisState === 0)
        nothingToDo = false;
    }
    if (nothingToDo) return;

    const sinks: Varnode[] = [];
    const reads: PcodeOp[] = [];

    // Find new (unanalyzed) load guards
    let loadStartIdx = this.loadGuard_list.length;
    while (loadStartIdx > 0) {
      if (this.loadGuard_list[loadStartIdx - 1].analysisState !== 0) break;
      loadStartIdx--;
    }
    for (let i = loadStartIdx; i < this.loadGuard_list.length; i++) {
      reads.push(this.loadGuard_list[i].op);
      sinks.push(this.loadGuard_list[i].op.getIn(1)!);
    }

    // Find new (unanalyzed) store guards
    let storeStartIdx = this.storeGuard_list.length;
    while (storeStartIdx > 0) {
      if (this.storeGuard_list[storeStartIdx - 1].analysisState !== 0) break;
      storeStartIdx--;
    }
    for (let i = storeStartIdx; i < this.storeGuard_list.length; i++) {
      reads.push(this.storeGuard_list[i].op);
      sinks.push(this.storeGuard_list[i].op.getIn(1)!);
    }

    const stackSpc: AddrSpace | null = this.fd.getArch().getStackSpace();
    let stackReg: Varnode | null = null;
    if (stackSpc !== null && stackSpc.numSpacebase() > 0)
      stackReg = this.fd.findSpacebaseInput(stackSpc);

    const vsSolver: ValueSetSolver = new (this.fd.getArch().getValueSetSolverClass())();
    vsSolver.establishValueSets(sinks, reads, stackReg, false);
    const widener: WidenerNone = new (this.fd.getArch().getWidenerNoneClass())();
    vsSolver.solve(10000, widener);

    let runFullAnalysis = false;
    for (let i = loadStartIdx; i < this.loadGuard_list.length; i++) {
      const guard = this.loadGuard_list[i];
      guard.establishRange(vsSolver.getValueSetRead(guard.op.getSeqNum()));
      if (guard.analysisState === 0) runFullAnalysis = true;
    }
    for (let i = storeStartIdx; i < this.storeGuard_list.length; i++) {
      const guard = this.storeGuard_list[i];
      guard.establishRange(vsSolver.getValueSetRead(guard.op.getSeqNum()));
      if (guard.analysisState === 0) runFullAnalysis = true;
    }
    if (runFullAnalysis) {
      const fullWidener = new WidenerFull();
      vsSolver.solve(10000, fullWidener);
      for (let i = loadStartIdx; i < this.loadGuard_list.length; i++) {
        const guard = this.loadGuard_list[i];
        guard.finalizeRange(vsSolver.getValueSetRead(guard.op.getSeqNum()));
      }
      for (let i = storeStartIdx; i < this.storeGuard_list.length; i++) {
        const guard = this.storeGuard_list[i];
        guard.finalizeRange(vsSolver.getValueSetRead(guard.op.getSeqNum()));
      }
    }
  }

  /**
   * Generate a guard record given an indexed LOAD into a stack space.
   */
  private generateLoadGuard(node: StackNode, op: PcodeOp, spc: AddrSpace): void {
    if (!op.usesSpacebasePtr()) {
      const guard = new LoadGuard();
      guard.set(op, spc, node.offset);
      this.loadGuard_list.push(guard);
      this.fd.opMarkSpacebasePtr(op);
    }
  }

  /**
   * Generate a guard record given an indexed STORE to a stack space.
   */
  private generateStoreGuard(node: StackNode, op: PcodeOp, spc: AddrSpace): void {
    if (!op.usesSpacebasePtr()) {
      const guard = new LoadGuard();
      guard.set(op, spc, node.offset);
      this.storeGuard_list.push(guard);
      this.fd.opMarkSpacebasePtr(op);
    }
  }

  /**
   * Identify any CPUI_STORE ops that use a free pointer from a given address space.
   */
  private protectFreeStores(spc: AddrSpace, freeStores: PcodeOp[]): boolean {
    const iter = this.fd.beginOp(CPUI_STORE);
    const enditer = this.fd.endOp(CPUI_STORE);
    let hasNew = false;
    for (let i = iter; i < enditer; i++) {
      const op: PcodeOp = this.fd.getOp(i);
      if (op.isDead()) continue;
      let vn: Varnode = op.getIn(1)!;
      while (vn.isWritten()) {
        const defOp: PcodeOp = vn.getDef();
        const opc: OpCode = defOp.code();
        if (opc === CPUI_COPY)
          vn = defOp.getIn(0)!;
        else if (opc === CPUI_INT_ADD && defOp.getIn(1)!.isConstant())
          vn = defOp.getIn(0)!;
        else
          break;
      }
      if (vn.isFree() && vn.getSpace() === spc) {
        this.fd.opMarkSpacebasePtr(op);
        freeStores.push(op);
        hasNew = true;
      }
    }
    return hasNew;
  }

  /**
   * Trace input stack-pointer to any indexed loads.
   */
  private discoverIndexedStackPointers(
    spc: AddrSpace,
    freeStores: PcodeOp[],
    checkFreeStores: boolean
  ): boolean {
    const markedVn: Varnode[] = [];
    const path: StackNode[] = [];
    let unknownStackStorage = false;

    for (let i = 0; i < spc.numSpacebase(); i++) {
      const stackPointer = spc.getSpacebase(i);
      const spInput: Varnode | null = this.fd.findVarnodeInput(stackPointer.size, stackPointer.getAddr());
      if (spInput === null) continue;
      path.push(makeStackNode(spInput, 0n, 0));

      while (path.length > 0) {
        const curNode = path[path.length - 1];
        const descends = curNode.vn.descend;
        if (curNode.iterIndex >= descends.length) {
          path.pop();
          continue;
        }
        const op: PcodeOp = descends[curNode.iterIndex];
        curNode.iterIndex++;

        const outVn: Varnode | null = op.getOut();
        if (outVn !== null && outVn.isMark()) continue;

        switch (op.code()) {
          case CPUI_INT_ADD: {
            const otherVn: Varnode = op.getIn(1 - op.getSlot(curNode.vn))!;
            if (otherVn.isConstant()) {
              const newOffset: bigint = spc.wrapOffset(curNode.offset + otherVn.getOffset());
              const nextNode = makeStackNode(outVn!, newOffset, curNode.traversals);
              if (nextNode.iterIndex < outVn!.descend.length) {
                outVn!.setMark();
                path.push(nextNode);
                markedVn.push(outVn!);
              } else if (outVn!.getSpace()!.getType() === IPTR_SPACEBASE) {
                unknownStackStorage = true;
              }
            } else {
              const nextNode = makeStackNode(outVn!, curNode.offset,
                curNode.traversals | StackNode_nonconstant_index);
              if (nextNode.iterIndex < outVn!.descend.length) {
                outVn!.setMark();
                path.push(nextNode);
                markedVn.push(outVn!);
              } else if (outVn!.getSpace()!.getType() === IPTR_SPACEBASE) {
                unknownStackStorage = true;
              }
            }
            break;
          }
          case CPUI_SEGMENTOP: {
            if (op.getIn(2)! !== curNode.vn) break;
            // fall through to COPY/INDIRECT
          }
          // falls through
          case CPUI_INDIRECT:
          case CPUI_COPY: {
            const nextNode = makeStackNode(outVn!, curNode.offset, curNode.traversals);
            if (nextNode.iterIndex < outVn!.descend.length) {
              outVn!.setMark();
              path.push(nextNode);
              markedVn.push(outVn!);
            } else if (outVn!.getSpace()!.getType() === IPTR_SPACEBASE) {
              unknownStackStorage = true;
            }
            break;
          }
          case CPUI_MULTIEQUAL: {
            const nextNode = makeStackNode(outVn!, curNode.offset,
              curNode.traversals | StackNode_multiequal);
            if (nextNode.iterIndex < outVn!.descend.length) {
              outVn!.setMark();
              path.push(nextNode);
              markedVn.push(outVn!);
            } else if (outVn!.getSpace()!.getType() === IPTR_SPACEBASE) {
              unknownStackStorage = true;
            }
            break;
          }
          case CPUI_LOAD: {
            if (curNode.traversals !== 0) {
              this.generateLoadGuard(curNode, op, spc);
            }
            break;
          }
          case CPUI_STORE: {
            if (op.getIn(1) === curNode.vn) {
              if (curNode.traversals !== 0) {
                this.generateStoreGuard(curNode, op, spc);
              } else {
                this.fd.opMarkSpacebasePtr(op);
              }
            }
            break;
          }
          default:
            break;
        }
      }
    }

    for (let i = 0; i < markedVn.length; i++) {
      markedVn[i].clearMark();
    }
    if (unknownStackStorage && checkFreeStores)
      return this.protectFreeStores(spc, freeStores);
    return false;
  }

  /**
   * Revisit STOREs with free pointers now that a heritage pass has completed.
   */
  private reprocessFreeStores(spc: AddrSpace, freeStores: PcodeOp[]): void {
    for (let i = 0; i < freeStores.length; i++) {
      this.fd.opClearSpacebasePtr(freeStores[i]);
    }

    this.discoverIndexedStackPointers(spc, freeStores, false);

    for (let i = 0; i < freeStores.length; i++) {
      const op: PcodeOp = freeStores[i];
      if (op.usesSpacebasePtr()) continue;

      let indOp: PcodeOp | null = op.previousOp();
      while (indOp !== null) {
        if (indOp.code() !== CPUI_INDIRECT) break;
        const iopVn: Varnode = indOp.getIn(1)!;
        if (iopVn.getSpace()!.getType() !== IPTR_IOP) break;
        if (op !== PcodeOp.getOpFromConst(iopVn.getAddr())) break;
        const nextOp: PcodeOp | null = indOp.previousOp();
        if (indOp.getOut()!.getSpace() === spc) {
          this.fd.totalReplace(indOp.getOut()!, indOp.getIn(0)!);
          this.fd.opDestroy(indOp);
        }
        indOp = nextOp;
      }
    }
  }

  /**
   * Normalize p-code ops so that phi-node placement and renaming works.
   * Adds PIECE / SUBPIECE ops to make free Varnode sizes uniform, and
   * optionally adds INDIRECT ops for LOAD/STORE/CALL effects.
   */
  private guard(
    addr: Address,
    size: number,
    guardPerformed: boolean,
    read: Varnode[],
    write: Varnode[],
    inputvars: Varnode[]
  ): void {
    let vn: Varnode;
    for (let i = 0; i < read.length; i++) {
      vn = read[i];
      const descends = vn.descend;
      if (descends.length === 0) continue;  // removeRevisitedMarkers may have eliminated descendant
      if (descends.length > 1)
        throw new Error("Free varnode with multiple reads");
      const op: PcodeOp = descends[0];
      if (vn.getSize() < size)
        read[i] = vn = this.normalizeReadSize(vn, op, addr, size);
      vn.setActiveHeritage();
    }

    for (let i = 0; i < write.length; i++) {
      vn = write[i];
      if (vn.getSize() < size)
        write[i] = vn = this.normalizeWriteSize(vn, addr, size);
      vn.setActiveHeritage();
    }

    if (guardPerformed) {
      const qResult = this.fd.getScopeLocal().queryProperties(addr, size, new Address());
      const fl: number = qResult.flags;
      this.guardCalls(fl, addr, size, write);
      this.guardReturns(fl, addr, size, write);
      if (this.fd.getArch().highPtrPossible(addr, size)) {
        this.guardStores(addr, size, write);
        this.guardLoads(fl, addr, size, write);
      }
    }
  }

  // ---- Stubs for methods implemented in part 2 ----

  private clearStackPlaceholders(info: HeritageInfo): void {
    const numCalls: number = this.fd.numCalls();
    for (let i = 0; i < numCalls; ++i) {
      this.fd.getCallSpecs_byIndex(i).abortSpacebaseRelative(this.fd);
    }
    info.hasCallPlaceholders = false;
  }
  /**
   * Recursively split join-space varnodes to the next level.
   *
   * For each varnode in \b lastcombo, determine if it needs to be split further
   * to match the JoinRecord pieces. If a varnode's size matches a single piece,
   * push it with null partner. Otherwise create a mosthalf/leasthalf split.
   */
  private splitJoinLevel(lastcombo: Varnode[], nextlev: Varnode[], joinrec: JoinRecord): void {
    const numpieces: number = joinrec.numPieces();
    let recnum = 0;
    for (let i = 0; i < lastcombo.length; ++i) {
      const curvn: Varnode = lastcombo[i];
      if (curvn.getSize() === joinrec.getPiece(recnum).size) {
        nextlev.push(curvn);
        nextlev.push(null as any);  // null sentinel means "didn't get split"
        recnum += 1;
      } else {
        let sizeaccum = 0;
        let j: number;
        for (j = recnum; j < numpieces; ++j) {
          sizeaccum += joinrec.getPiece(j).size;
          if (sizeaccum === curvn.getSize()) {
            j += 1;
            break;
          }
        }
        const numinhalf: number = Math.floor((j - recnum) / 2); // Will be at least 1
        sizeaccum = 0;
        for (let k = 0; k < numinhalf; ++k)
          sizeaccum += joinrec.getPiece(recnum + k).size;
        let mosthalf: Varnode;
        let leasthalf: Varnode;
        if (numinhalf === 1) {
          const piece = joinrec.getPiece(recnum);
          mosthalf = this.fd.newVarnode(sizeaccum, new Address(piece.space as AddrSpace, piece.offset));
        } else {
          mosthalf = this.fd.newUnique(sizeaccum);
        }
        if ((j - recnum) === 2) {
          const vdata = joinrec.getPiece(recnum + 1);
          leasthalf = this.fd.newVarnode(vdata.size, new Address(vdata.space as AddrSpace, vdata.offset));
        } else {
          leasthalf = this.fd.newUnique(curvn.getSize() - sizeaccum);
        }
        nextlev.push(mosthalf);
        nextlev.push(leasthalf);
        recnum = j;
      }
    }
  }

  /**
   * Construct pieces for a join-space Varnode read by an operation.
   *
   * Given a splitting specification (JoinRecord) and a Varnode, build a
   * concatenation expression (out of PIECE operations) that constructs the
   * Varnode out of the specified Varnode pieces.
   */
  private splitJoinRead(vn: Varnode, joinrec: JoinRecord): void {
    let op: PcodeOp = vn.loneDescend()!; // vn isFree, so loneDescend must be non-null
    let isPrimitive = true;
    if (vn.isTypeLock()) {
      isPrimitive = vn.getType()!.isPrimitiveWhole();
    }

    let lastcombo: Varnode[] = [vn];
    let nextlev: Varnode[] = [];
    while (lastcombo.length < joinrec.numPieces()) {
      nextlev.length = 0;
      this.splitJoinLevel(lastcombo, nextlev, joinrec);

      for (let i = 0; i < lastcombo.length; ++i) {
        const curvn: Varnode = lastcombo[i];
        const mosthalf: Varnode = nextlev[2 * i];
        const leasthalf: Varnode | null = nextlev[2 * i + 1];
        if (leasthalf === null) continue; // Varnode didn't get split this level
        const concat: PcodeOp = this.fd.newOp(2, op.getAddr());
        this.fd.opSetOpcode(concat, CPUI_PIECE);
        this.fd.opSetOutput(concat, curvn);
        this.fd.opSetInput(concat, mosthalf, 0);
        this.fd.opSetInput(concat, leasthalf, 1);
        this.fd.opInsertBefore(concat, op);
        if (isPrimitive) {
          mosthalf.setPrecisHi();  // Set precision flags to trigger "double precision" rules
          leasthalf.setPrecisLo();
        } else {
          this.fd.opMarkNoCollapse(concat);
        }
        op = concat; // Keep op as the earliest op in the concatenation construction
      }

      lastcombo = [];
      for (let i = 0; i < nextlev.length; ++i) {
        const curvn: Varnode | null = nextlev[i];
        if (curvn !== null)
          lastcombo.push(curvn);
      }
    }
  }

  /**
   * Split a written join-space Varnode into specified pieces.
   *
   * Given a splitting specification (JoinRecord) and a Varnode, build a
   * series of expressions that construct the specified Varnode pieces
   * using SUBPIECE ops.
   */
  private splitJoinWrite(vn: Varnode, joinrec: JoinRecord): void {
    let op: PcodeOp | null = vn.getDef(); // vn cannot be free, either it has def, or it is input
    const bb = this.fd.getBasicBlocks().getBlock(0);
    let isPrimitive = true;
    if (vn.isTypeLock())
      isPrimitive = vn.getType()!.isPrimitiveWhole();

    let lastcombo: Varnode[] = [vn];
    let nextlev: Varnode[] = [];
    while (lastcombo.length < joinrec.numPieces()) {
      nextlev.length = 0;
      this.splitJoinLevel(lastcombo, nextlev, joinrec);
      for (let i = 0; i < lastcombo.length; ++i) {
        const curvn: Varnode = lastcombo[i];
        const mosthalf: Varnode = nextlev[2 * i];
        const leasthalf: Varnode | null = nextlev[2 * i + 1];
        if (leasthalf === null) continue; // Varnode didn't get split this level
        let split: PcodeOp;
        if (vn.isInput())
          split = this.fd.newOp(2, bb.getStart());
        else
          split = this.fd.newOp(2, op!.getAddr());
        this.fd.opSetOpcode(split, CPUI_SUBPIECE);
        this.fd.opSetOutput(split, mosthalf);
        this.fd.opSetInput(split, curvn, 0);
        this.fd.opSetInput(split, this.fd.newConstant(4, BigInt(leasthalf.getSize())), 1);
        if (op === null)
          this.fd.opInsertBegin(split, bb);
        else
          this.fd.opInsertAfter(split, op);
        op = split; // Keep op as the latest op in the split construction

        split = this.fd.newOp(2, op.getAddr());
        this.fd.opSetOpcode(split, CPUI_SUBPIECE);
        this.fd.opSetOutput(split, leasthalf);
        this.fd.opSetInput(split, curvn, 0);
        this.fd.opSetInput(split, this.fd.newConstant(4, 0n), 1);
        this.fd.opInsertAfter(split, op);
        if (isPrimitive) {
          mosthalf.setPrecisHi();  // Set precision flags to trigger "double precision" rules
          leasthalf.setPrecisLo();
        }
        op = split; // Keep op as the latest op in the split construction
      }

      lastcombo = [];
      for (let i = 0; i < nextlev.length; ++i) {
        const curvn: Varnode | null = nextlev[i];
        if (curvn !== null)
          lastcombo.push(curvn);
      }
    }
  }
  private floatExtensionRead(vn: Varnode, joinrec: JoinRecord): void {
    const op: PcodeOp = vn.loneDescend()!; // vn isFree, so loneDescend must be non-null
    const trunc: PcodeOp = this.fd.newOp(1, op.getAddr());
    const vdata = joinrec.getPiece(0); // Float extensions have exactly 1 piece
    const bigvn: Varnode = this.fd.newVarnode(vdata.size, vdata.space, vdata.offset);
    this.fd.opSetOpcode(trunc, CPUI_FLOAT_FLOAT2FLOAT);
    this.fd.opSetOutput(trunc, vn);
    this.fd.opSetInput(trunc, bigvn, 0);
    this.fd.opInsertBefore(trunc, op);
  }
  private floatExtensionWrite(vn: Varnode, joinrec: JoinRecord): void {
    const op: PcodeOp | null = vn.getDef();
    const bb = this.fd.getBasicBlocks().getBlock(0);
    let ext: PcodeOp;
    if (vn.isInput())
      ext = this.fd.newOp(1, bb.getStart());
    else
      ext = this.fd.newOp(1, op!.getAddr());
    const vdata = joinrec.getPiece(0); // Float extensions have exactly 1 piece
    this.fd.opSetOpcode(ext, CPUI_FLOAT_FLOAT2FLOAT);
    this.fd.newVarnodeOut(vdata.size, vdata.getAddr(), ext);
    this.fd.opSetInput(ext, vn, 0);
    if (op === null)
      this.fd.opInsertBegin(ext, bb);
    else
      this.fd.opInsertAfter(ext, op);
  }
  /**
   * Process any Varnodes in the join address space.
   *
   * For each Varnode in the join space, look up its JoinRecord and split
   * or extend it so that the individual pieces can be heritaged normally.
   */
  private processJoins(): void {
    const joinspace: AddrSpace = this.fd.getArch().getJoinSpace();
    let iter = this.fd.beginLoc(joinspace);
    const enditer = this.fd.endLoc(joinspace);

    while (!iter.equals(enditer)) {
      const vn: Varnode = iter.get();
      iter.next();
      if (vn.getSpace() !== joinspace) break; // New varnodes may get inserted before enditer
      let joinrec: JoinRecord;
      try {
        joinrec = this.fd.getArch().findJoin(vn.getOffset());
      } catch(e: any) {
        break;
      }
      const piecespace: AddrSpace = joinrec.getPiece(0).space;

      if (joinrec.getUnified().size !== vn.getSize())
        throw new Error("Joined varnode does not match size of record");
      if (vn.isFree()) {
        if (joinrec.isFloatExtension())
          this.floatExtensionRead(vn, joinrec);
        else
          this.splitJoinRead(vn, joinrec);
      }

      const info: HeritageInfo = this.getInfo(piecespace);
      if (this.pass !== info.delay) continue; // It is too soon to heritage this space

      if (joinrec.isFloatExtension())
        this.floatExtensionWrite(vn, joinrec);
      else
        this.splitJoinWrite(vn, joinrec); // Only do this once for a particular varnode
    }
  }

  /**
   * Build the augmented dominator tree.
   *
   * Assumes the dominator tree is already built and nodes are in DFS order.
   * Computes boundary nodes and the augmentation edges needed for efficient
   * phi-node placement using the iterative dominance frontier algorithm.
   */
  private buildADT(): void {
    const bblocks = this.fd.getBasicBlocks();
    const size: number = bblocks.getSize();
    const a: number[] = new Array(size);
    const b: number[] = new Array(size).fill(0);
    const t: number[] = new Array(size).fill(0);
    const z: number[] = new Array(size);
    const upstart: FlowBlock[] = [];
    const upend: FlowBlock[] = [];
    let x: FlowBlock, u: FlowBlock, v: FlowBlock;
    let i: number, j: number, k: number, l: number;

    this.augment = [];
    this.augment.length = size;
    for (i = 0; i < size; ++i) {
      this.augment[i] = [];
    }
    this.flags = [];
    this.flags.length = size;
    for (i = 0; i < size; ++i) {
      this.flags[i] = 0;
    }

    bblocks.buildDomTree(this.domchild);
    this.maxdepth = bblocks.buildDomDepth(this.depth);
    for (i = 0; i < size; ++i) {
      x = bblocks.getBlock(i);
      for (j = 0; j < this.domchild[i].length; ++j) {
        v = this.domchild[i][j];
        for (k = 0; k < v.sizeIn(); ++k) {
          u = v.getIn(k);
          if (u !== v.getImmedDom()) { // If u->v is an up-edge
            upstart.push(u);           // Store edge (in dfs order)
            upend.push(v);
            b[u.getIndex()] += 1;
            t[x.getIndex()] += 1;
          }
        }
      }
    }
    for (i = size - 1; i >= 0; --i) {
      k = 0;
      l = 0;
      for (j = 0; j < this.domchild[i].length; ++j) {
        k += a[this.domchild[i][j].getIndex()];
        l += z[this.domchild[i][j].getIndex()];
      }
      a[i] = b[i] - t[i] + k;
      z[i] = 1 + l;
      if ((this.domchild[i].length === 0) || (z[i] > a[i] + 1)) {
        this.flags[i] |= heritage_boundary_node; // Mark this node as a boundary node
        z[i] = 1;
      }
    }
    z[0] = -1;
    for (i = 1; i < size; ++i) {
      j = bblocks.getBlock(i).getImmedDom().getIndex();
      if ((this.flags[j] & heritage_boundary_node) !== 0) // If j is a boundary node
        z[i] = j;
      else
        z[i] = z[j];
    }
    for (i = 0; i < upstart.length; ++i) {
      v = upend[i];
      j = v.getImmedDom().getIndex();
      k = upstart[i].getIndex();
      while (j < k) { // while idom(v) properly dominates u
        this.augment[k].push(v);
        k = z[k];
      }
    }
  }

  /**
   * The heart of the phi-node placement algorithm.
   *
   * Recursively walk the dominance tree starting from a given block.
   * Calculate any children that are in the dominance frontier and add
   * them to the merge array.
   * @param qnode - the parent of the given block
   * @param vnode - the given block
   */
  private visitIncr(qnode: FlowBlock, vnode: FlowBlock): void {
    let i: number, j: number, k: number;
    let v: FlowBlock, child: FlowBlock;

    i = vnode.getIndex();
    j = qnode.getIndex();
    const aug: FlowBlock[] = this.augment[i];
    for (let idx = 0; idx < aug.length; ++idx) {
      v = aug[idx];
      if (v.getImmedDom().getIndex() < j) { // If idom(v) is strict ancestor of qnode
        k = v.getIndex();
        if ((this.flags[k] & heritage_merged_node) === 0) {
          this.merge.push(v);
          this.flags[k] |= heritage_merged_node;
        }
        if ((this.flags[k] & heritage_mark_node) === 0) { // If v is not marked
          this.flags[k] |= heritage_mark_node;             // then mark it
          this.pq.insert(v, this.depth[k]);                // insert it into the queue
        }
      } else {
        break;
      }
    }
    if ((this.flags[i] & heritage_boundary_node) === 0) { // If vnode is not a boundary node
      for (j = 0; j < this.domchild[i].length; ++j) {
        child = this.domchild[i][j];
        if ((this.flags[child.getIndex()] & heritage_mark_node) === 0) // If the child is not marked
          this.visitIncr(qnode, child);
      }
    }
  }

  /**
   * Calculate blocks that should contain MULTIEQUALs for one address range.
   *
   * This is the main entry point for the phi-node placement algorithm. It is
   * provided the normalized list of written Varnodes in this range.
   * All refinement and guarding must already be performed for the Varnodes, and
   * the dominance tree and its augmentation must already be computed.
   * After this executes, the merge array holds blocks that should contain
   * a MULTIEQUAL.
   * @param write - the list of written Varnodes
   */
  private calcMultiequals(write: Varnode[]): void {
    this.pq.reset(this.maxdepth);
    this.merge.length = 0;

    let i: number, j: number;
    let bl: FlowBlock;
    // Place write blocks into the pq
    for (i = 0; i < write.length; ++i) {
      bl = write[i].getDef().getParent(); // Get block where this write occurs
      j = bl.getIndex();
      if ((this.flags[j] & heritage_mark_node) !== 0) continue; // Already put in
      this.pq.insert(bl, this.depth[j]); // Insert input node into priority queue
      this.flags[j] |= heritage_mark_node; // mark input node
    }
    if ((this.flags[0] & heritage_mark_node) === 0) { // Make sure start node is in input
      this.pq.insert(this.fd.getBasicBlocks().getBlock(0), this.depth[0]);
      this.flags[0] |= heritage_mark_node;
    }

    while (!this.pq.empty()) {
      bl = this.pq.extract(); // Extract the next block
      this.visitIncr(bl, bl);
    }
    for (i = 0; i < this.flags.length; ++i)
      this.flags[i] &= ~(heritage_mark_node | heritage_merged_node); // Clear marks from nodes
  }

  // ---- Part 2: Full method implementations ----

  /**
   * Make sure existing inputs for the given range fill it entirely.
   *
   * The method is provided any Varnodes that overlap the range and are
   * already marked as input. If there are any holes in coverage, new
   * input Varnodes are created to cover them. A final unified Varnode
   * covering the whole range is built out of the pieces. In any event,
   * things are set up so the renaming algorithm sees only a single Varnode.
   * @param addr - first address in the given range
   * @param size - number of bytes in the range
   * @param input - pre-existing inputs, given in address order
   */
  guardInput(addr: Address, size: number, input: Varnode[]): void {
    if (input.length === 0) return;
    // If there is only one input and it fills everything
    // it will get linked in automatically
    if (input.length === 1 && input[0].getSize() === size) return;

    // Otherwise we need to make sure there are no holes
    let i = 0;
    let cur: bigint = addr.getOffset();
    const end: bigint = cur + BigInt(size);
    let vn: Varnode;
    const newinput: Varnode[] = [];

    // Make sure the input range is filled
    while (cur < end) {
      if (i < input.length) {
        vn = input[i];
        if (vn.getOffset() > cur) {
          const sz = Number(vn.getOffset() - cur);
          vn = this.fd.newVarnode(sz, new Address(addr.getSpace()!, cur));
          vn = this.fd.setInputVarnode(vn);
        } else {
          i += 1;
        }
      } else {
        const sz = Number(end - cur);
        vn = this.fd.newVarnode(sz, new Address(addr.getSpace()!, cur));
        vn = this.fd.setInputVarnode(vn);
      }
      newinput.push(vn);
      cur += BigInt(vn.getSize());
    }

    // Now we need to make sure that all the inputs get linked
    // together into a single input
    if (newinput.length === 1) return; // Will get linked in automatically
    for (let j = 0; j < newinput.length; ++j)
      newinput[j].setWriteMask();
    const newout: Varnode = this.fd.newVarnode(size, addr);
    this.concatPieces(newinput, null, newout).setActiveHeritage();
  }

  /**
   * Guard an address range that is larger than any single parameter.
   *
   * In this situation, an address range is being heritaged, but only a piece of
   * it can be a parameter for a given call. We have to construct a SUBPIECE that
   * pulls out the potential parameter.
   * @param fc - the call site potentially taking a parameter
   * @param addr - starting address of the range
   * @param transAddr - start of the same range from the callee's stack perspective
   * @param size - size of the range in bytes
   */
  guardCallOverlappingInput(fc: FuncCallSpecs, addr: Address, transAddr: Address, size: number): void {
    const vData: VarnodeData = {} as VarnodeData;

    if (fc.getBiggestContainedInputParam(transAddr, size, vData)) {
      const active: ParamActive = fc.getActiveInput();
      let truncAddr = new Address(vData.space, vData.offset);
      const diff: bigint = truncAddr.getOffset() - transAddr.getOffset();
      truncAddr = addr.add(diff);  // Convert truncated Address to caller's perspective
      if (active.whichTrial(truncAddr, size) < 0) { // If not already a trial
        const truncateAmount: number = addr.justifiedContain(size, truncAddr, vData.size, false);
        const op: PcodeOp = fc.getOp();
        const subpieceOp: PcodeOp = this.fd.newOp(2, op.getAddr());
        this.fd.opSetOpcode(subpieceOp, CPUI_SUBPIECE);
        const wholeVn: Varnode = this.fd.newVarnode(size, addr);
        wholeVn.setActiveHeritage();
        this.fd.opSetInput(subpieceOp, wholeVn, 0);
        this.fd.opSetInput(subpieceOp, this.fd.newConstant(4, BigInt(truncateAmount)), 1);
        const vn: Varnode = this.fd.newVarnodeOut(vData.size, truncAddr, subpieceOp);
        this.fd.opInsertBefore(subpieceOp, op);
        active.registerTrial(truncAddr, vData.size);
        this.fd.opInsertInput(op, vn, op.numInput());
      }
    }
  }

  /**
   * Insert created INDIRECT ops, to guard the output of a call.
   *
   * The potential return storage is an indirect creation at this stage, and the guarded range
   * properly contains the return storage.
   * @param callOp - the call causing the indirection
   * @param addr - starting address of the full range
   * @param size - size of the full range in bytes
   * @param retAddr - starting address of the return storage
   * @param retSize - size of the return storage in bytes
   * @param write - set of new written Varnodes
   */
  guardOutputOverlap(callOp: PcodeOp, addr: Address, size: number, retAddr: Address, retSize: number,
                     write: Varnode[]): void {
    const sizeFront: number = Number(retAddr.getOffset() - addr.getOffset());
    const sizeBack: number = size - retSize - sizeFront;
    const indOp: PcodeOp = this.fd.newIndirectCreation(callOp, retAddr, retSize, true);
    let vnCollect: Varnode = indOp.getOut()!;
    let insertPoint: PcodeOp = callOp;
    if (sizeFront !== 0) {
      const indOpFront: PcodeOp = this.fd.newIndirectCreation(indOp, addr, sizeFront, false);
      const newFront: Varnode = indOpFront.getOut()!;
      const concatFront: PcodeOp = this.fd.newOp(2, indOp.getAddr());
      const slotNew: number = retAddr.isBigEndian() ? 0 : 1;
      this.fd.opSetOpcode(concatFront, CPUI_PIECE);
      this.fd.opSetInput(concatFront, newFront, slotNew);
      this.fd.opSetInput(concatFront, vnCollect, 1 - slotNew);
      vnCollect = this.fd.newVarnodeOut(sizeFront + retSize, addr, concatFront);
      this.fd.opInsertAfter(concatFront, insertPoint);
      insertPoint = concatFront;
    }
    if (sizeBack !== 0) {
      const addrBack: Address = retAddr.add(BigInt(retSize));
      const indOpBack: PcodeOp = this.fd.newIndirectCreation(callOp, addrBack, sizeBack, false);
      const newBack: Varnode = indOpBack.getOut()!;
      const concatBack: PcodeOp = this.fd.newOp(2, indOp.getAddr());
      const slotNew: number = retAddr.isBigEndian() ? 1 : 0;
      this.fd.opSetOpcode(concatBack, CPUI_PIECE);
      this.fd.opSetInput(concatBack, newBack, slotNew);
      this.fd.opSetInput(concatBack, vnCollect, 1 - slotNew);
      vnCollect = this.fd.newVarnodeOut(size, addr, concatBack);
      this.fd.opInsertAfter(concatBack, insertPoint);
    }
    vnCollect.setActiveHeritage();
    write.push(vnCollect);
  }

  /**
   * Try to guard an address range that is larger than the possible output storage.
   * @param fc - the call site potentially returning a value
   * @param addr - starting address of the range
   * @param transAddr - starting address of the range relative to the callee
   * @param size - size of the range in bytes
   * @param write - set of new written Varnodes
   * @returns true if the INDIRECTs were created
   */
  tryOutputOverlapGuard(fc: FuncCallSpecs, addr: Address, transAddr: Address, size: number,
                        write: Varnode[]): boolean {
    const vData: VarnodeData = {} as VarnodeData;

    if (!fc.getBiggestContainedOutput(transAddr, size, vData))
      return false;
    const active: ParamActive = fc.getActiveOutput();
    let truncAddr = new Address(vData.space, vData.offset);
    const diff: bigint = truncAddr.getOffset() - transAddr.getOffset();
    truncAddr = addr.add(diff);  // Convert truncated Address to caller's perspective
    if (active.whichTrial(truncAddr, size) >= 0)
      return false;  // Trial already exists
    this.guardOutputOverlap(fc.getOp(), addr, size, truncAddr, vData.size, write);
    active.registerTrial(truncAddr, vData.size);
    return true;
  }

  /**
   * Guard a stack range that properly contains the return value storage for a call.
   *
   * The full range is assumed to have a related value before the call.
   * @param callOp - the call being guarded
   * @param addr - starting address of the stack range
   * @param size - number of bytes in the range
   * @param retAddr - starting address of the return storage
   * @param retSize - number of bytes of return storage
   * @param write - list of written Varnodes in the range (may be updated)
   */
  guardOutputOverlapStack(callOp: PcodeOp, addr: Address, size: number,
                          retAddr: Address, retSize: number, write: Varnode[]): void {
    const sizeFront: number = Number(retAddr.getOffset() - addr.getOffset());
    const sizeBack: number = size - retSize - sizeFront;
    let insertPoint: PcodeOp = callOp;
    let vnCollect: Varnode | null = callOp.getOut();
    if (vnCollect === null) {
      vnCollect = this.fd.newVarnodeOut(retSize, retAddr, callOp);
    }
    if (sizeFront !== 0) {
      const newInput: Varnode = this.fd.newVarnode(size, addr);
      newInput.setActiveHeritage();
      const subPiece: PcodeOp = this.fd.newOp(2, callOp.getAddr());
      this.fd.opSetOpcode(subPiece, CPUI_SUBPIECE);
      const truncateAmount: number = addr.justifiedContain(size, addr, sizeFront, false);
      this.fd.opSetInput(subPiece, this.fd.newConstant(4, BigInt(truncateAmount)), 1);
      this.fd.opSetInput(subPiece, newInput, 0);
      const indOpFront: PcodeOp = this.fd.newIndirectOp(callOp, addr, sizeFront, 0);
      this.fd.opSetOutput(subPiece, indOpFront.getIn(0)!);
      this.fd.opInsertBefore(subPiece, callOp);
      const newFront: Varnode = indOpFront.getOut()!;
      const concatFront: PcodeOp = this.fd.newOp(2, callOp.getAddr());
      const slotNew: number = retAddr.isBigEndian() ? 0 : 1;
      this.fd.opSetOpcode(concatFront, CPUI_PIECE);
      this.fd.opSetInput(concatFront, newFront, slotNew);
      this.fd.opSetInput(concatFront, vnCollect, 1 - slotNew);
      vnCollect = this.fd.newVarnodeOut(sizeFront + retSize, addr, concatFront);
      this.fd.opInsertAfter(concatFront, insertPoint);
      insertPoint = concatFront;
    }
    if (sizeBack !== 0) {
      const newInput: Varnode = this.fd.newVarnode(size, addr);
      newInput.setActiveHeritage();
      const addrBack: Address = retAddr.add(BigInt(retSize));
      const subPiece: PcodeOp = this.fd.newOp(2, callOp.getAddr());
      this.fd.opSetOpcode(subPiece, CPUI_SUBPIECE);
      const truncateAmount: number = addr.justifiedContain(size, addrBack, sizeBack, false);
      this.fd.opSetInput(subPiece, this.fd.newConstant(4, BigInt(truncateAmount)), 1);
      this.fd.opSetInput(subPiece, newInput, 0);
      const indOpBack: PcodeOp = this.fd.newIndirectOp(callOp, addrBack, sizeBack, 0);
      this.fd.opSetOutput(subPiece, indOpBack.getIn(0)!);
      this.fd.opInsertBefore(subPiece, callOp);
      const newBack: Varnode = indOpBack.getOut()!;
      const concatBack: PcodeOp = this.fd.newOp(2, callOp.getAddr());
      const slotNew: number = retAddr.isBigEndian() ? 1 : 0;
      this.fd.opSetOpcode(concatBack, CPUI_PIECE);
      this.fd.opSetInput(concatBack, newBack, slotNew);
      this.fd.opSetInput(concatBack, vnCollect, 1 - slotNew);
      vnCollect = this.fd.newVarnodeOut(size, addr, concatBack);
      this.fd.opInsertAfter(concatBack, insertPoint);
    }
    vnCollect!.setActiveHeritage();
    write.push(vnCollect!);
  }

  /**
   * Attempt to guard a stack range against a call that returns a value overlapping that range.
   *
   * @param fc - the call being guarded
   * @param addr - starting address of the range being guarded (relative to the caller's stack pointer)
   * @param transAddr - starting address of the range (relative to the callee's stack pointer)
   * @param size - number of bytes in the range
   * @param outputCharacter - indicates the type of containment between the guarded range and the return storage
   * @param write - list of written Varnodes in the range (may be updated)
   * @returns true if the range was successfully guarded
   */
  tryOutputStackGuard(fc: FuncCallSpecs, addr: Address, transAddr: Address, size: number,
                      outputCharacter: number, write: Varnode[]): boolean {
    const callOp: PcodeOp = fc.getOp();
    if (outputCharacter === ParamEntry_contained_by) {
      const vData: VarnodeData = {} as VarnodeData;

      if (!fc.getBiggestContainedOutput(transAddr, size, vData))
        return false;
      let truncAddr = new Address(vData.space, vData.offset);
      const diff: bigint = truncAddr.getOffset() - transAddr.getOffset();
      truncAddr = addr.add(diff);  // Convert truncated Address to caller's perspective
      this.guardOutputOverlapStack(callOp, addr, size, truncAddr, vData.size, write);
      return true;
    }
    // Reaching here, output exists and contains the heritage range
    let retAddr: Address = fc.getOutput().getAddress();
    const diff: bigint = addr.getOffset() - transAddr.getOffset();
    retAddr = retAddr.add(diff);  // Translate output address to caller perspective
    const retSize: number = fc.getOutput().getSize();
    let outvn: Varnode | null = callOp.getOut();
    let vnFinal: Varnode | null = null;
    if (outvn === null) {
      outvn = this.fd.newVarnodeOut(retSize, retAddr, callOp);
      vnFinal = outvn;
    }
    if (size < retSize) {
      const subPiece: PcodeOp = this.fd.newOp(2, callOp.getAddr());
      this.fd.opSetOpcode(subPiece, CPUI_SUBPIECE);
      const truncateAmount: number = retAddr.justifiedContain(retSize, addr, size, false);
      this.fd.opSetInput(subPiece, this.fd.newConstant(4, BigInt(truncateAmount)), 1);
      this.fd.opSetInput(subPiece, outvn, 0);
      vnFinal = this.fd.newVarnodeOut(size, addr, subPiece);
      this.fd.opInsertAfter(subPiece, callOp);
    }
    if (vnFinal !== null) {
      vnFinal.setActiveHeritage();
      write.push(vnFinal);
    }
    return true;
  }

  /**
   * Guard CALL/CALLIND ops in preparation for renaming algorithm.
   *
   * For the given address range, we decide what the data-flow effect is
   * across each call site in the function. If an effect is unknown, an
   * INDIRECT op is added, prepopulating data-flow through the call.
   * @param fl - boolean properties associated with the address range
   * @param addr - first address of given range
   * @param size - number of bytes in the range
   * @param write - list of written Varnodes in the range (may be updated)
   */
  guardCalls(fl: number, addr: Address, size: number, write: Varnode[]): void {
    let fc: FuncCallSpecs;
    let indop: PcodeOp;
    let effecttype: number;

    const holdind: boolean = (fl & Varnode.addrtied) !== 0;
    for (let i = 0; i < this.fd.numCalls(); ++i) {
      fc = this.fd.getCallSpecs_byIndex(i);
      if (fc.getOp().isAssignment()) {
        const vn: Varnode = fc.getOp().getOut();
        if (vn.getAddr().equals(addr) && vn.getSize() === size) continue;
      }
      const spc: AddrSpace = addr.getSpace()!;
      let off: bigint = addr.getOffset();
      let tryregister = true;
      if (spc.getType() === IPTR_SPACEBASE) {
        if (fc.getSpacebaseOffset() !== FuncCallSpecs_offset_unknown)
          off = spc.wrapOffset(off - fc.getSpacebaseOffset());
        else
          tryregister = false; // Do not attempt to register this stack loc as a trial
      }
      const transAddr = new Address(spc, off); // Address relative to callee's stack
      effecttype = fc.hasEffect(transAddr, size);
      let possibleoutput = false;
      if (fc.isOutputActive() && tryregister) {
        const active: ParamActive = fc.getActiveOutput();
        const outputCharacter: number = fc.characterizeAsOutput(transAddr, size);
        if (outputCharacter !== ParamEntry_no_containment) {
          if (effecttype !== EffectRecord_killedbycall && fc.isAutoKilledByCall())
            effecttype = EffectRecord_killedbycall;
          if (outputCharacter === ParamEntry_contained_by) {
            if (this.tryOutputOverlapGuard(fc, addr, transAddr, size, write))
              effecttype = EffectRecord_unaffected; // Range is handled, don't do additional guarding
          } else {
            if (active.whichTrial(transAddr, size) < 0) { // If not already a trial
              active.registerTrial(transAddr, size);
              possibleoutput = true;
            }
          }
        }
      } else if (fc.isStackOutputLock() && tryregister) {
        const outputCharacter: number = fc.characterizeAsOutput(transAddr, size);
        if (outputCharacter !== ParamEntry_no_containment) {
          effecttype = EffectRecord_unknown_effect;
          if (this.tryOutputStackGuard(fc, addr, transAddr, size, outputCharacter, write))
            effecttype = EffectRecord_unaffected; // Range is handled
        }
      }
      if (fc.isInputActive() && tryregister) {
        const inputCharacter: number = fc.characterizeAsInputParam(transAddr, size);
        if (inputCharacter === ParamEntry_contains_justified) { // Call could be using this range as an input parameter
          const active: ParamActive = fc.getActiveInput();
          if (active.whichTrial(transAddr, size) < 0) { // If not already a trial
            const op: PcodeOp = fc.getOp();
            active.registerTrial(transAddr, size);
            const vn: Varnode = this.fd.newVarnode(size, addr);
            vn.setActiveHeritage();
            this.fd.opInsertInput(op, vn, op.numInput());
          }
        } else if (inputCharacter === ParamEntry_contained_by) { // Call may be using part of this range as an input parameter
          this.guardCallOverlappingInput(fc, addr, transAddr, size);
        }
      }
      // We do not guard the call if the effect is "unaffected" or "reload"
      if (effecttype === EffectRecord_unknown_effect || effecttype === EffectRecord_return_address) {
        indop = this.fd.newIndirectOp(fc.getOp(), addr, size, 0);
        indop.getIn(0)!.setActiveHeritage();
        indop.getOut()!.setActiveHeritage();
        write.push(indop.getOut()!);
        if (holdind)
          indop.getOut()!.setAddrForce();
        if (effecttype === EffectRecord_return_address)
          indop.getOut()!.setReturnAddress();
      } else if (effecttype === EffectRecord_killedbycall) {
        indop = this.fd.newIndirectCreation(fc.getOp(), addr, size, possibleoutput);
        indop.getOut()!.setActiveHeritage();
        write.push(indop.getOut()!);
      }
    }
  }

  /**
   * Guard STORE ops in preparation for the renaming algorithm.
   *
   * Depending on the pointer, a STORE operation may affect data-flow across the
   * given address range. This method adds an INDIRECT op, prepopulating
   * data-flow across the STORE.
   * @param addr - first address of the given range
   * @param size - number of bytes in the given range
   * @param write - list of written Varnodes in the range (may be updated)
   */
  guardStores(addr: Address, size: number, write: Varnode[]): void {
    let op: PcodeOp;
    let indop: PcodeOp;
    const spc: AddrSpace = addr.getSpace()!;
    const container: AddrSpace | null = spc.getContain();

    const iterend = this.fd.endOp(CPUI_STORE);
    for (let iter = this.fd.beginOp(CPUI_STORE); !iter.equals(iterend); iter.next()) {
      op = iter.get();
      if (op.isDead()) continue;
      const storeSpace: AddrSpace = op.getIn(0)!.getSpaceFromConst()!;
      if ((container === storeSpace && op.usesSpacebasePtr()) ||
          (spc === storeSpace)) {
        indop = this.fd.newIndirectOp(op, addr, size, PcodeOp.indirect_store);
        indop.getIn(0)!.setActiveHeritage();
        indop.getOut()!.setActiveHeritage();
        write.push(indop.getOut()!);
      }
    }
  }

  /**
   * Guard LOAD ops in preparation for the renaming algorithm.
   *
   * The op must be in the loadGuard list, which means it may pull values from an indexed
   * range on the stack.
   * @param fl - boolean properties associated with the address
   * @param addr - first address of the given range
   * @param size - number of bytes in the given range
   * @param write - list of written Varnodes in the range (may be updated)
   */
  guardLoads(fl: number, addr: Address, size: number, write: Varnode[]): void {
    let copyop: PcodeOp;

    if ((fl & Varnode.addrtied) === 0) return; // If not address tied, don't consider for index alias
    let idx = 0;
    while (idx < this.loadGuard_list.length) {
      const guardRec: LoadGuard = this.loadGuard_list[idx];
      if (!guardRec.isValid(CPUI_LOAD)) {
        this.loadGuard_list.splice(idx, 1);
        continue;
      }
      ++idx;
      if (guardRec.spc !== addr.getSpace()) continue;
      if (addr.getOffset() < guardRec.minimumOffset) continue;
      if (addr.getOffset() > guardRec.maximumOffset) continue;
      copyop = this.fd.newOp(1, guardRec.op.getAddr());
      const vn: Varnode = this.fd.newVarnodeOut(size, addr, copyop);
      vn.setActiveHeritage();
      vn.setAddrForce();
      this.fd.opSetOpcode(copyop, CPUI_COPY);
      const invn: Varnode = this.fd.newVarnode(size, addr);
      invn.setActiveHeritage();
      this.fd.opSetInput(copyop, invn, 0);
      this.fd.opInsertBefore(copyop, guardRec.op);
      this.loadCopyOps.push(copyop);
    }
  }

  /**
   * Guard data-flow at RETURN ops, where range properly contains potential return storage.
   *
   * The RETURN ops need to take a new input because of the potential of a return value,
   * but the range is too big so it must be truncated to fit.
   * @param addr - starting address of the range
   * @param size - size of the range in bytes
   */
  guardReturnsOverlapping(addr: Address, size: number): void {
    const vData: VarnodeData = {} as VarnodeData;

    if (!this.fd.getFuncProto().getBiggestContainedOutput(addr, size, vData))
      return;
    const truncAddr = new Address(vData.space, vData.offset);
    const active: ParamActive = this.fd.getActiveOutput();
    active.registerTrial(truncAddr, vData.size);
    let offset: number = Number(vData.offset - addr.getOffset()); // Number of least significant bytes to truncate
    if (vData.space.isBigEndian())
      offset = (size - vData.size) - offset;
    const iterend = this.fd.endOp(CPUI_RETURN);
    for (let iter = this.fd.beginOp(CPUI_RETURN); !iter.equals(iterend); iter.next()) {
      const op: PcodeOp = iter.get();
      if (op.isDead()) continue;
      if (op.getHaltType() !== 0) continue; // Special halt points cannot take return values
      const invn: Varnode = this.fd.newVarnode(size, addr);
      const subOp: PcodeOp = this.fd.newOp(2, op.getAddr());
      this.fd.opSetOpcode(subOp, CPUI_SUBPIECE);
      this.fd.opSetInput(subOp, invn, 0);
      this.fd.opSetInput(subOp, this.fd.newConstant(4, BigInt(offset)), 1);
      this.fd.opInsertBefore(subOp, op);
      const retVal: Varnode = this.fd.newVarnodeOut(vData.size, truncAddr, subOp);
      invn.setActiveHeritage();
      this.fd.opInsertInput(op, retVal, op.numInput());
    }
  }

  /**
   * Guard global data-flow at RETURN ops in preparation for renaming.
   *
   * For the given global (persistent) address range, data-flow must persist up to
   * (beyond) the end of the function.
   * @param fl - boolean properties associated with the address range
   * @param addr - first address of the given range
   * @param size - number of bytes in the range
   * @param write - list of written Varnodes in the range (unused)
   */
  guardReturns(fl: number, addr: Address, size: number, write: Varnode[]): void {
    let op: PcodeOp;
    let copyop: PcodeOp;

    const active: ParamActive | null = this.fd.getActiveOutput();
    if (active !== null) {
      const outputCharacter: number = this.fd.getFuncProto().characterizeAsOutput(addr, size);
      if (outputCharacter === ParamEntry_contained_by)
        this.guardReturnsOverlapping(addr, size);
      else if (outputCharacter !== ParamEntry_no_containment) {
        active.registerTrial(addr, size);
        const iterend = this.fd.endOp(CPUI_RETURN);
        for (let iter = this.fd.beginOp(CPUI_RETURN); !iter.equals(iterend); iter.next()) {
          op = iter.get();
          if (op.isDead()) continue;
          if (op.getHaltType() !== 0) continue; // Special halt points cannot take return values
          const invn: Varnode = this.fd.newVarnode(size, addr);
          invn.setActiveHeritage();
          this.fd.opInsertInput(op, invn, op.numInput());
        }
      }
    }
    if ((fl & Varnode.persist) === 0) return;
    const iterend = this.fd.endOp(CPUI_RETURN);
    for (let iter = this.fd.beginOp(CPUI_RETURN); !iter.equals(iterend); iter.next()) {
      op = iter.get();
      if (op.isDead()) continue;
      copyop = this.fd.newOp(1, op.getAddr());
      const vn: Varnode = this.fd.newVarnodeOut(size, addr, copyop);
      vn.setAddrForce();
      vn.setActiveHeritage();
      this.fd.opSetOpcode(copyop, CPUI_COPY);
      this.fd.markReturnCopy(copyop);
      const invn: Varnode = this.fd.newVarnode(size, addr);
      invn.setActiveHeritage();
      this.fd.opSetInput(copyop, invn, 0);
      this.fd.opInsertBefore(copyop, op);
    }
  }

  /**
   * Build a refinement array given an address range and a list of Varnodes.
   *
   * The array is a preallocated array of ints, one for each byte in the address
   * range. Each Varnode in the given list has a 1 entered in the refinement
   * array, at the position corresponding to the starting address of the Varnode
   * and at the position corresponding to the address immediately following the Varnode.
   * @param refine - the refinement array
   * @param addr - starting address of the given range
   * @param vnlist - list of Varnodes to add to the array
   */
  static buildRefinement(refine: number[], addr: Address, vnlist: Varnode[]): void {
    for (let i = 0; i < vnlist.length; ++i) {
      const curaddr: Address = vnlist[i].getAddr();
      const sz: number = vnlist[i].getSize();
      const diff: number = Number(curaddr.getOffset() - addr.getOffset());
      refine[diff] = 1;
      refine[diff + sz] = 1;
    }
  }

  /**
   * Split up a Varnode by the given refinement.
   * @param vn - given Varnode to split
   * @param addr - starting address of the range described by the refinement
   * @param refine - the refinement array
   * @param split - will hold the new Varnode pieces
   */
  splitByRefinement(vn: Varnode, addr: Address, refine: number[], split: Varnode[]): void {
    let curaddr: Address = vn.getAddr();
    let sz: number = vn.getSize();
    const spc: AddrSpace = curaddr.getSpace()!;
    let diff: number = Number(spc.wrapOffset(curaddr.getOffset() - addr.getOffset()));
    let cutsz: number = refine[diff];
    if (sz <= cutsz) return; // Already refined
    split.push(this.fd.newVarnode(cutsz, curaddr));
    sz -= cutsz;
    while (sz > 0) {
      curaddr = curaddr.add(BigInt(cutsz));
      diff = Number(spc.wrapOffset(curaddr.getOffset() - addr.getOffset()));
      cutsz = refine[diff];
      if (cutsz > sz)
        cutsz = sz; // Final piece
      split.push(this.fd.newVarnode(cutsz, curaddr));
      sz -= cutsz;
    }
  }

  /**
   * Split up a free Varnode based on the given refinement.
   *
   * If the Varnode overlaps the refinement, it is replaced with 2 or more
   * covering Varnodes with boundaries that are on the refinement.
   * @param vn - given Varnode to split
   * @param addr - starting address of the address range being refined
   * @param refine - the refinement array
   * @param newvn - preallocated space for holding the array of Varnode pieces
   */
  refineRead(vn: Varnode, addr: Address, refine: number[], newvn: Varnode[]): void {
    newvn.length = 0;
    this.splitByRefinement(vn, addr, refine, newvn);
    if (newvn.length === 0) return;
    const replacevn: Varnode = this.fd.newUnique(vn.getSize());
    const op: PcodeOp = vn.loneDescend(); // Read is free so has 1 and only 1 descend
    const slot: number = op.getSlot(vn);
    this.concatPieces(newvn, op, replacevn);
    this.fd.opSetInput(op, replacevn, slot);
    if (vn.hasNoDescend())
      this.fd.deleteVarnode(vn);
    else
      throw new Error("Refining non-free varnode");
  }

  /**
   * Split up an output Varnode based on the given refinement.
   * @param vn - given Varnode to split
   * @param addr - starting address of the address range being refined
   * @param refine - the refinement array
   * @param newvn - preallocated space for holding the array of Varnode pieces
   */
  refineWrite(vn: Varnode, addr: Address, refine: number[], newvn: Varnode[]): void {
    newvn.length = 0;
    this.splitByRefinement(vn, addr, refine, newvn);
    if (newvn.length === 0) return;
    const replacevn: Varnode = this.fd.newUnique(vn.getSize());
    const def: PcodeOp = vn.getDef();
    this.fd.opSetOutput(def, replacevn);
    this.splitPieces(newvn, def, vn.getAddr(), vn.getSize(), replacevn);
    this.fd.totalReplace(vn, replacevn);
    this.fd.deleteVarnode(vn);
  }

  /**
   * Split up a known input Varnode based on the given refinement.
   * @param vn - given Varnode to split
   * @param addr - starting address of the address range being refined
   * @param refine - the refinement array
   * @param newvn - preallocated space for holding the array of Varnode pieces
   */
  refineInput(vn: Varnode, addr: Address, refine: number[], newvn: Varnode[]): void {
    newvn.length = 0;
    this.splitByRefinement(vn, addr, refine, newvn);
    if (newvn.length === 0) return;
    this.splitPieces(newvn, null, vn.getAddr(), vn.getSize(), vn);
    vn.setWriteMask();
  }

  /**
   * If we see 1-3 or 3-1 pieces in the partition, replace with a 4.
   * @param refine - the refinement array
   */
  remove13Refinement(refine: number[]): void {
    if (refine.length === 0) return;
    let pos = 0;
    let lastsize: number = refine[pos];
    let cursize: number;

    pos += lastsize;
    while (pos < refine.length) {
      cursize = refine[pos];
      if (cursize === 0) break;
      if ((lastsize === 1 && cursize === 3) || (lastsize === 3 && cursize === 1)) {
        refine[pos - lastsize] = 4;
        lastsize = 4;
        pos += cursize;
      } else {
        lastsize = cursize;
        pos += lastsize;
      }
    }
  }

  /**
   * Find the common refinement of all reads and writes in the address range.
   *
   * Split the reads and writes so they match the refinement.
   * @param memiter - points to the address range to be refined
   * @param readvars - all free Varnodes overlapping the address range
   * @param writevars - all written Varnodes overlapping the address range
   * @param inputvars - all known input Varnodes overlapping the address range
   * @returns iterator to the first new disjoint range, or end() if no refinement
   */
  refinement(memiter: number, readvars: Varnode[], writevars: Varnode[],
             inputvars: Varnode[]): number {
    const size: number = this.disjoint.get(memiter).size;
    if (size > 1024) return this.disjoint.length;
    const addr: Address = this.disjoint.get(memiter).addr;
    const refine: number[] = new Array<number>(size + 1).fill(0); // Add "fencepost" for size position
    Heritage.buildRefinement(refine, addr, readvars);
    Heritage.buildRefinement(refine, addr, writevars);
    Heritage.buildRefinement(refine, addr, inputvars);
    refine.pop(); // Remove the fencepost
    let lastpos = 0;
    for (let curpos = 1; curpos < size; ++curpos) { // Convert boundary points to partition sizes
      if (refine[curpos] !== 0) {
        refine[lastpos] = curpos - lastpos;
        lastpos = curpos;
      }
    }
    if (lastpos === 0) return this.disjoint.length; // No non-trivial refinements
    refine[lastpos] = size - lastpos;
    this.remove13Refinement(refine);
    const newvn: Varnode[] = [];
    for (let i = 0; i < readvars.length; ++i)
      this.refineRead(readvars[i], addr, refine, newvn);
    for (let i = 0; i < writevars.length; ++i)
      this.refineWrite(writevars[i], addr, refine, newvn);
    for (let i = 0; i < inputvars.length; ++i)
      this.refineInput(inputvars[i], addr, refine, newvn);

    // Alter the disjoint cover (both locally and globally) to reflect our refinement
    const flags: number = this.disjoint.get(memiter).flags;
    this.disjoint.erase(memiter);
    const giter = this.globaldisjoint.find(addr);
    const curPass: number = giter!.value.pass;
    this.globaldisjoint.erase(giter!.key);
    let cut = 0;
    let sz: number = refine[cut];
    let curAddr: Address = addr;
    const resiter: number = this.disjoint.insert(memiter, curAddr, sz, flags);
    this.globaldisjoint.add(curAddr, sz, curPass);
    cut += sz;
    curAddr = curAddr.add(BigInt(sz));
    while (cut < size) {
      sz = refine[cut];
      this.disjoint.insert(memiter, curAddr, sz, flags);
      this.globaldisjoint.add(curAddr, sz, curPass);
      cut += sz;
      curAddr = curAddr.add(BigInt(sz));
    }
    return resiter;
  }

  /**
   * The heart of the renaming algorithm.
   *
   * From the given block, recursively walk the dominance tree. At each
   * block, visit the PcodeOps in execution order looking for Varnodes that
   * need to be renamed.
   * @param bl - current basic block in the dominance tree walk
   * @param varstack - system of stacks, organized by address
   */
  renameRecurse(bl: BlockBasic, varstack: VariableStack): void {
    const writelist: Varnode[] = []; // List varnodes that are written in this block
    let subbl: BlockBasic;
    let op: PcodeOp;
    let multiop: PcodeOp;
    let vnout: Varnode | null;
    let vnin: Varnode;
    let vnnew: Varnode;
    let i: number;
    let slot: number;

    for (let oiter = bl.beginOp(); !oiter.equals(bl.endOp()); oiter.next()) {
      op = oiter.get();
      if (op.code() !== CPUI_MULTIEQUAL) {
        // First replace reads with top of stack
        for (slot = 0; slot < op.numInput(); ++slot) {
          vnin = op.getIn(slot)!;
          if (vnin.isHeritageKnown()) continue; // not free
          if (!vnin.isActiveHeritage()) continue; // Not being heritaged this round
          vnin.clearActiveHeritage();
          const rkey = addrKey(vnin.getAddr());
          let stack: Varnode[] | undefined = varstack.get(rkey);
          if (stack === undefined) {
            stack = [];
            varstack.set(rkey, stack);
          }
          if (stack.length === 0) {
            vnnew = this.fd.newVarnode(vnin.getSize(), vnin.getAddr());
            vnnew = this.fd.setInputVarnode(vnnew);
            stack.push(vnnew);
          } else {
            vnnew = stack[stack.length - 1];
          }
          // INDIRECTs and their op really happen AT SAME TIME
          if (vnnew.isWritten() && (vnnew.getDef().code() === CPUI_INDIRECT)) {
            if (PcodeOp.getOpFromConst(vnnew.getDef().getIn(1).getAddr()) === op) {
              if (stack.length === 1) {
                vnnew = this.fd.newVarnode(vnin.getSize(), vnin.getAddr());
                vnnew = this.fd.setInputVarnode(vnnew);
                stack.splice(0, 0, vnnew);
              } else {
                vnnew = stack[stack.length - 2];
              }
            }
          }
          this.fd.opSetInput(op, vnnew, slot);
          if (vnin.hasNoDescend())
            this.fd.deleteVarnode(vnin);
        }
      }
      // Then push writes onto stack
      vnout = op.getOut();
      if (vnout === null) continue;
      if (!vnout.isActiveHeritage()) continue; // Not a normalized write
      vnout.clearActiveHeritage();
      const wkey = addrKey(vnout.getAddr());
      let wstack: Varnode[] | undefined = varstack.get(wkey);
      if (wstack === undefined) {
        wstack = [];
        varstack.set(wkey, wstack);
      }
      wstack.push(vnout); // Push write onto stack
      writelist.push(vnout);
    }
    for (i = 0; i < bl.sizeOut(); ++i) {
      subbl = bl.getOut(i) as BlockBasic;
      slot = bl.getOutRevIndex(i);
      for (let suboiter = subbl.beginOp(); !suboiter.equals(subbl.endOp()); suboiter.next()) {
        multiop = suboiter.get();
        if (multiop.code() !== CPUI_MULTIEQUAL) break; // For each MULTIEQUAL
        vnin = multiop.getIn(slot)!;
        if (!vnin.isHeritageKnown()) {
          const mkey = addrKey(vnin.getAddr());
          let stack: Varnode[] | undefined = varstack.get(mkey);
          if (stack === undefined) {
            stack = [];
            varstack.set(mkey, stack);
          }
          if (stack.length === 0) {
            vnnew = this.fd.newVarnode(vnin.getSize(), vnin.getAddr());
            vnnew = this.fd.setInputVarnode(vnnew);
            stack.push(vnnew);
          } else {
            vnnew = stack[stack.length - 1];
          }
          this.fd.opSetInput(multiop, vnnew, slot);
          if (vnin.hasNoDescend())
            this.fd.deleteVarnode(vnin);
        }
      }
    }
    // Now we recurse to subtrees
    i = bl.getIndex();
    for (slot = 0; slot < this.domchild[i].length; ++slot)
      this.renameRecurse(this.domchild[i][slot] as BlockBasic, varstack);
    // Now we pop this block's writes off the stack
    for (i = 0; i < writelist.length; ++i) {
      vnout = writelist[i];
      const popStack = varstack.get(addrKey(vnout.getAddr()));
      if (popStack !== undefined)
        popStack.pop();
    }
  }

  /**
   * Increase the heritage delay for the given AddrSpace and request a restart.
   * @param spc - the given AddrSpace
   */
  bumpDeadcodeDelay(spc: AddrSpace): void {
    if (spc.getType() !== spacetype.IPTR_PROCESSOR && spc.getType() !== IPTR_SPACEBASE)
      return; // Not the right kind of space
    if (spc.getDelay() !== spc.getDeadcodeDelay())
      return; // there is already a global delay
    if (this.fd.getOverride().hasDeadcodeDelay(spc))
      return; // A delay has already been installed
    this.fd.getOverride().insertDeadcodeDelay(spc, spc.getDeadcodeDelay() + 1);
    this.fd.setRestartPending(true);
  }

  /**
   * Perform phi-node placement for the current set of address ranges.
   *
   * Main entry point for performing the phi-node placement algorithm.
   * Assumes disjoint is filled with all the free Varnodes to be heritaged.
   */
  placeMultiequals(): void {
    const readvars: Varnode[] = [];
    const writevars: Varnode[] = [];
    const inputvars: Varnode[] = [];
    const removevars: Varnode[] = [];

    for (let iter = 0; iter < this.disjoint.length; ++iter) {
      let max: number = this.collect(this.disjoint.get(iter), readvars, writevars, inputvars, removevars); // Collect reads/writes
      if (this.disjoint.get(iter).size > 4 && max < this.disjoint.get(iter).size) {
        const refiter: number = this.refinement(iter, readvars, writevars, inputvars);
        if (refiter < this.disjoint.length) {
          iter = refiter;
          this.collect(this.disjoint.get(iter), readvars, writevars, inputvars, removevars);
        }
      }
      const memrange: MemRange = this.disjoint.get(iter);
      const size: number = memrange.size;
      if (readvars.length === 0) {
        if (writevars.length === 0 && inputvars.length === 0) {
          continue;
        }
        if (memrange.addr.getSpace()!.getType() === spacetype.IPTR_INTERNAL || memrange.oldAddresses())
          continue;
      }
      if (removevars.length > 0)
        this.removeRevisitedMarkers(removevars, memrange.addr, size);
      this.guardInput(memrange.addr, size, inputvars);
      this.guard(memrange.addr, size, memrange.newAddresses(), readvars, writevars, inputvars);
      this.calcMultiequals(writevars); // Calculate where MULTIEQUALs go
      for (let i = 0; i < this.merge.length; ++i) {
        const mbl: BlockBasic = this.merge[i] as BlockBasic;
        const multiop: PcodeOp = this.fd.newOp(mbl.sizeIn(), mbl.getStart());
        const vnout: Varnode = this.fd.newVarnodeOut(size, memrange.addr, multiop);
        vnout.setActiveHeritage();
        this.fd.opSetOpcode(multiop, CPUI_MULTIEQUAL); // Create each MULTIEQUAL
        for (let j = 0; j < mbl.sizeIn(); ++j) {
          const vnin: Varnode = this.fd.newVarnode(size, memrange.addr);
          this.fd.opSetInput(multiop, vnin, j);
        }
        this.fd.opInsertBegin(multiop, mbl); // Insert at beginning of block
      }
    }
    this.merge.length = 0;
  }

  /**
   * Perform the renaming algorithm for the current set of address ranges.
   *
   * Phi-node placement must already have happened.
   */
  rename(): void {
    const varstack: VariableStack = new Map<string, Varnode[]>();
    this.renameRecurse(this.fd.getBasicBlocks().getBlock(0) as BlockBasic, varstack);
    this.disjoint.clear();
  }

  /**
   * Perform one pass of heritage.
   *
   * From any address space that is active for this pass, free Varnodes are collected
   * and then fully integrated into SSA form. Reads are connected to writes, inputs
   * are identified, and phi-nodes are placed.
   */
  heritage(): void {
    let info: HeritageInfo;
    let vn: Varnode;
    let needwarning: boolean;
    let warnvn: Varnode | null = null;
    let reprocessStackCount = 0;
    let stackSpace: AddrSpace | null = null;
    const freeStores: PcodeOp[] = [];
    const splitmanage: PreferSplitManager = new PreferSplitManager();
    if (this.maxdepth === -1) // Has a restructure been forced
      this.buildADT();

    this.processJoins();
    if (this.pass === 0) {
      splitmanage.init(this.fd, this.fd.getArch().splitrecords);
      splitmanage.split();
    }
    for (let i = 0; i < this.infolist.length; ++i) {
      info = this.infolist[i];

      if (!info.isHeritaged()) continue;
      if (this.pass < info.delay) continue; // It is too soon to heritage this space
      if (info.hasCallPlaceholders)
        this.clearStackPlaceholders(info);

      if (!info.loadGuardSearch) {
        info.loadGuardSearch = true;
        if (this.discoverIndexedStackPointers(info.space!, freeStores, true)) {
          reprocessStackCount += 1;
          stackSpace = info.space;
        }
      }
      needwarning = false;
      let iter = this.fd.beginLoc(info.space!);
      const enditer = this.fd.endLoc(info.space!);
      while (!iter.equals(enditer)) {
        vn = iter.get();
        iter.next();
        if (!vn.isWritten() && vn.hasNoDescend() && !vn.isUnaffected() && !vn.isInput())
          continue;
        if (vn.isWriteMask()) continue;
        const liter = this.globaldisjoint.add(vn.getAddr(), vn.getSize(), this.pass);
        const prev = liter.intersect;
        const literEntry = this.globaldisjoint.find(liter.key);
        const literSize = literEntry!.value.size;
        if (prev === 0) // All new location being heritaged, or intersecting with something new
          this.disjoint.add(liter.key, literSize, MemRange.new_addresses);
        else if (prev === 2) { // If completely contained in range from previous pass
          if (vn.isHeritageKnown()) continue; // Don't heritage if we don't have to
          if (vn.hasNoDescend()) continue;
          if (!needwarning && info.deadremoved > 0 && !this.fd.isJumptableRecoveryOn()) {
            needwarning = true;
            this.bumpDeadcodeDelay(vn.getSpace()!);
            warnvn = vn;
          }
          this.disjoint.add(liter.key, literSize, MemRange.old_addresses);
        } else { // Partially contained in old range, but may contain new stuff
          this.disjoint.add(liter.key, literSize,
                            MemRange.old_addresses | MemRange.new_addresses);
          if (!needwarning && info.deadremoved > 0 && !this.fd.isJumptableRecoveryOn()) {
            // TODO: We should check if this varnode is tiled by previously heritaged ranges
            if (vn.isHeritageKnown()) continue; // Assume that it is tiled and produced by merging
            needwarning = true;
            this.bumpDeadcodeDelay(vn.getSpace()!);
            warnvn = vn;
          }
        }
      }

      if (needwarning) {
        if (!info.warningissued) {
          info.warningissued = true;
          let errmsg = "Heritage AFTER dead removal. Example location: ";
          const _w = { result: '', write(s: string) { this.result += s; } };
          warnvn!.printRawNoMarkup(_w as any);
          errmsg += _w.result;
          if (!warnvn!.hasNoDescend()) {
            const warnop: PcodeOp = warnvn!.getDescend(warnvn!.beginDescend());
            errmsg += " : ";
            errmsg += warnop.getAddr().printRaw();
          }
          this.fd.warningHeader(errmsg);
        }
      }
    }
    this.placeMultiequals();
    this.rename();
    if (reprocessStackCount > 0)
      this.reprocessFreeStores(stackSpace!, freeStores);
    this.analyzeNewLoadGuards();
    this.handleNewLoadCopies();
    if (this.pass === 0)
      splitmanage.splitAdditional();
    this.pass += 1;
  }

  /**
   * Initialize information for each space.
   */
  buildInfoList(): void {
    if (this.infolist.length > 0) return;
    const manage: AddrSpaceManager = this.fd.getArch();
    for (let i = 0; i < manage.numSpaces(); ++i)
      this.infolist.push(new HeritageInfo(manage.getSpace(i)));
  }

  /**
   * Reset all analysis of heritage.
   */
  clear(): void {
    this.disjoint.clear();
    this.globaldisjoint.clear();
    this.domchild.length = 0;
    this.augment.length = 0;
    this.flags.length = 0;
    this.depth.length = 0;
    this.merge.length = 0;
    this.clearInfoList();
    this.loadGuard_list.length = 0;
    this.storeGuard_list.length = 0;
    this.maxdepth = -1;
    this.pass = 0;
  }
} // End of Heritage class
