/**
 * @file jumptable_part1.ts
 * @description Classes to support jump-tables and their recovery (Part 1).
 *
 * Translated from Ghidra's jumptable.hh / jumptable.cc
 * This file contains: LoadTable, EmulateFunction, JumpValues, JumpValuesRange,
 * JumpValuesRangeDefault, JumpModel, JumpModelTrivial, GuardRecord, PathMeld.
 */

import type { int4, uint4, uintb, uint8 } from '../core/types.js';
import { Address, count_leading_zeros, mostsigbit_set, calc_mask, coveringmask, minimalmask } from '../core/address.js';
import { AddrSpace } from '../core/space.js';
import { OpCode } from '../core/opcodes.js';
import { LowlevelError } from '../core/error.js';
import type { Encoder, Decoder } from '../core/marshal.js';
import { AttributeId, ElementId, ATTRIB_SIZE, ATTRIB_CONTENT } from '../core/marshal.js';

import { DataUnavailError } from './loadimage.js';
import { EmulatePcodeOp } from './emulateutil.js';
import { PcodeOpNode } from './expression.js';

// ---------------------------------------------------------------------------
// Forward-declare types not yet available
// ---------------------------------------------------------------------------

type Architecture = any;
type Funcdata = any;
type BlockBasic = any;
type PcodeOp = any;
type Varnode = any;

import { CircleRange } from './rangeutil.js';
import { MemoryImage } from './memstate.js';
import { VarnodeData } from '../core/pcoderaw.js';

// ---------------------------------------------------------------------------
// Marshaling attributes and elements
// ---------------------------------------------------------------------------

export const ATTRIB_LABEL = new AttributeId('label', 131);
export const ATTRIB_NUM = new AttributeId('num', 132);

export const ELEM_BASICOVERRIDE = new ElementId('basicoverride', 211);
export const ELEM_DEST = new ElementId('dest', 212);
export const ELEM_JUMPTABLE = new ElementId('jumptable', 213);
export const ELEM_LOADTABLE = new ElementId('loadtable', 214);
export const ELEM_NORMADDR = new ElementId('normaddr', 215);
export const ELEM_NORMHASH = new ElementId('normhash', 216);
export const ELEM_STARTVAL = new ElementId('startval', 217);

// ---------------------------------------------------------------------------
// JumptableThunkError
// ---------------------------------------------------------------------------

/**
 * Exception thrown for a thunk mechanism that looks like a jump-table.
 */
export class JumptableThunkError extends LowlevelError {
  constructor(s: string) {
    super(s);
    this.name = 'JumptableThunkError';
  }
}

// ---------------------------------------------------------------------------
// LoadTable
// ---------------------------------------------------------------------------

/**
 * A description where and how data was loaded from memory.
 *
 * This is a generic table description, giving the starting address
 * of the table, the size of an entry, and number of entries.
 */
export class LoadTable {
  /** Starting address of table */
  addr: Address;
  /** Size of table entry */
  size: int4;
  /** Number of entries in table */
  num: int4;

  /**
   * Construct a LoadTable.
   * @param ad - starting address (or undefined for decode usage)
   * @param sz - size of table entry
   * @param nm - number of entries (defaults to 1)
   */
  constructor(ad?: Address, sz?: int4, nm?: int4) {
    if (ad !== undefined && sz !== undefined) {
      this.addr = ad;
      this.size = sz;
      this.num = (nm !== undefined) ? nm : 1;
    } else {
      this.addr = new Address();
      this.size = 0;
      this.num = 0;
    }
  }

  /**
   * Compare this with another table by address.
   * @returns true if this comes before op2
   */
  lessThan(op2: LoadTable): boolean {
    return this.addr.lessThan(op2.addr);
  }

  /**
   * Encode a description of this as a \<loadtable\> element.
   */
  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_LOADTABLE);
    encoder.writeSignedInteger(ATTRIB_SIZE, this.size);
    encoder.writeSignedInteger(ATTRIB_NUM, this.num);
    (this.addr as any).encode(encoder);
    encoder.closeElement(ELEM_LOADTABLE);
  }

  /**
   * Decode this table from a \<loadtable\> element.
   */
  decode(decoder: Decoder): void {
    const elemId: uint4 = decoder.openElementId(ELEM_LOADTABLE);
    this.size = decoder.readSignedIntegerById(ATTRIB_SIZE);
    this.num = decoder.readSignedIntegerById(ATTRIB_NUM);
    this.addr = (Address as any).decode(decoder);
    decoder.closeElement(elemId);
  }

  /**
   * Collapse a sequence of table descriptions.
   *
   * Sort the entries and collapse any contiguous sequences into a single LoadTable entry.
   */
  static collapseTable(table: LoadTable[]): void {
    if (table.length === 0) return;

    // Test if the table is already sorted and contiguous entries
    let issorted = true;
    let num: int4 = table[0].num;
    const size: int4 = table[0].size;
    let nextaddr: Address = table[0].addr.add(BigInt(size));

    for (let i = 1; i < table.length; ++i) {
      if (table[i].addr.equals(nextaddr) && table[i].size === size) {
        num += table[i].num;
        nextaddr = table[i].addr.add(BigInt(table[i].size));
      } else {
        issorted = false;
        break;
      }
    }
    if (issorted) {
      // Table is sorted and contiguous. Truncate everything but the first entry
      table.length = 1;
      table[0].num = num;
      return;
    }

    table.sort((a, b) => a.lessThan(b) ? -1 : (b.lessThan(a) ? 1 : 0));

    let count = 1;
    let lastIdx = 0;
    nextaddr = table[0].addr.add(BigInt(table[0].size * table[0].num));
    for (let i = 1; i < table.length; ++i) {
      if (table[i].addr.equals(nextaddr) && table[i].size === table[lastIdx].size) {
        table[lastIdx].num += table[i].num;
        nextaddr = table[i].addr.add(BigInt(table[i].size * table[i].num));
      } else if (nextaddr.lessThan(table[i].addr) || table[i].size !== table[lastIdx].size) {
        // Starting a new table
        lastIdx++;
        table[lastIdx] = table[i];
        nextaddr = table[i].addr.add(BigInt(table[i].size * table[i].num));
        count += 1;
      }
    }
    table.length = count;
  }
}

// ---------------------------------------------------------------------------
// EmulateFunction
// ---------------------------------------------------------------------------

/**
 * A light-weight emulator to calculate switch targets from switch variables.
 *
 * We assume we only have to store memory state for individual Varnodes and that dynamic
 * LOADs are resolved from the LoadImage. BRANCH and CBRANCH emulation will fail, there can
 * only be one execution path, although there can be multiple data-flow paths.
 */
export class EmulateFunction extends EmulatePcodeOp {
  private fd: Funcdata;
  private varnodeMap: Map<Varnode, bigint>;
  private loadpoints: LoadTable[] | null;

  /**
   * Constructor.
   * @param f is the function to emulate within
   */
  constructor(f: Funcdata) {
    super((f as any).getArch());
    this.fd = f;
    this.varnodeMap = new Map();
    this.loadpoints = null;
  }

  /**
   * Set where/if we collect LOAD information.
   */
  setLoadCollect(val: LoadTable[] | null): void {
    this.loadpoints = val;
  }

  protected executeLoad(): void {
    if (this.loadpoints !== null) {
      const off: uintb = this.getVarnodeValue(this.currentOp!.getIn(1));
      const spc: AddrSpace = this.currentOp!.getIn(0).getSpaceFromConst();
      const byteOff: uintb = AddrSpace.addressToByte(off, spc.getWordSize());
      const sz: int4 = this.currentOp!.getOut().getSize();
      this.loadpoints.push(new LoadTable(new Address(spc, byteOff), sz));
    }
    super.executeLoad();
  }

  protected executeBranch(): void {
    throw new LowlevelError("Branch encountered emulating jumptable calculation");
  }

  protected executeBranchind(): void {
    throw new LowlevelError("Indirect branch encountered emulating jumptable calculation");
  }

  protected executeCall(): void {
    // Ignore calls, as presumably they have nothing to do with final address
    this.fallthruOp();
  }

  protected executeCallind(): void {
    // Ignore calls, as presumably they have nothing to do with final address
    this.fallthruOp();
  }

  protected executeCallother(): void {
    // Ignore callothers
    this.fallthruOp();
  }

  setExecuteAddress(addr: Address): void {
    if (!(addr.getSpace() as any).hasPhysical())
      throw new LowlevelError("Bad execute address");

    this.currentOp = (this.fd as any).target(addr);
    if (this.currentOp === null)
      throw new LowlevelError("Could not set execute address");
    this.currentBehave = this.currentOp!.getOpcode().getBehavior();
  }

  getVarnodeValue(vn: Varnode): uintb {
    // Get the value of a Varnode which is in a syntax tree
    // We can't just use the memory location as, within the tree,
    // this is just part of the label
    if ((vn as any).isConstant())
      return (vn as any).getOffset();
    const val = this.varnodeMap.get(vn);
    if (val !== undefined)
      return val;  // We have seen this varnode before

    return this.getLoadImageValue(
      (vn as any).getSpace(),
      (vn as any).getOffset(),
      (vn as any).getSize()
    );
  }

  setVarnodeValue(vn: Varnode, val: uintb): void {
    this.varnodeMap.set(vn, val);
  }

  protected fallthruOp(): void {
    this.lastOp = this.currentOp;  // Keep track of lastOp for MULTIEQUAL
    // Otherwise do nothing: outer loop is controlling execution flow
  }

  /**
   * Execute from a given starting point and value to the common end-point of the path set.
   *
   * Flow the given value through all paths in the path container to produce the
   * single output value.
   * @param val is the starting value
   * @param pathMeld is the set of paths to execute
   * @param startop is the starting PcodeOp within the path set
   * @param startvn is the Varnode holding the starting value
   * @returns the calculated value at the common end-point
   */
  emulatePath(val: uintb, pathMeld: PathMeld, startop: PcodeOp, startvn: Varnode): uintb {
    let i: uint4;
    for (i = 0; i < pathMeld.numOps(); ++i) {
      if (pathMeld.getOp(i) === startop) break;
    }
    if ((startop as any).code() === OpCode.CPUI_MULTIEQUAL) {
      // If we start on a MULTIEQUAL
      let j: int4;
      for (j = 0; j < (startop as any).numInput(); ++j) {
        // Is our startvn one of the branches
        if ((startop as any).getIn(j) === startvn) break;
      }
      if (j === (startop as any).numInput() || i === 0)
        // If not, we can't continue
        throw new LowlevelError("Cannot start jumptable emulation with unresolved MULTIEQUAL");
      // If the startvn was a branch of the MULTIEQUAL, emulate as if we just came from that branch
      startvn = (startop as any).getOut();  // So the output of the MULTIEQUAL is the new startvn
      i -= 1;  // Move to the next instruction to be executed
      startop = pathMeld.getOp(i);
    }
    if (i === pathMeld.numOps())
      throw new LowlevelError("Bad jumptable emulation");
    if (!(startvn as any).isConstant())
      this.setVarnodeValue(startvn, val);
    while (i > 0) {
      const curop: PcodeOp = pathMeld.getOp(i);
      --i;
      this.setCurrentOp(curop);
      try {
        this.executeCurrentOp();
      } catch (err: unknown) {
        if (err instanceof DataUnavailError) {
          throw new LowlevelError(
            "Could not emulate address calculation at " + (curop as any).getAddr().toString()
          );
        }
        throw err;
      }
    }
    const invn: Varnode = pathMeld.getOp(0).getIn(0);
    return this.getVarnodeValue(invn);
  }
}

// ---------------------------------------------------------------------------
// JumpValues (abstract base)
// ---------------------------------------------------------------------------

/**
 * An iterator over values a switch variable can take.
 *
 * This iterator is intended to provide the start value for emulation
 * of a jump-table model to obtain the associated jump-table destination.
 * Each value can be associated with a starting Varnode and PcodeOp in
 * the function being emulated, via getStartVarnode() and getStartOp().
 */
export abstract class JumpValues {
  /** Jump-table label reserved to indicate "no label" */
  static readonly NO_LABEL: uint8 = 0xBAD1ABE1BAD1ABE1n;

  /** Truncate the number of values to the given number */
  abstract truncate(nm: int4): void;

  /** Return the number of values the variables can take */
  abstract getSize(): uintb;

  /** Return true if the given value is in the set of possible values */
  abstract contains(val: uintb): boolean;

  /** Initialize this for iterating over the set of possible values. Returns true if there are any values. */
  abstract initializeForReading(): boolean;

  /** Advance the iterator, return true if there is another value */
  abstract next(): boolean;

  /** Get the current value */
  abstract getValue(): uintb;

  /** Get the Varnode associated with the current value */
  abstract getStartVarnode(): Varnode;

  /** Get the PcodeOp associated with the current value */
  abstract getStartOp(): PcodeOp;

  /** Return true if the current value can be reversed to get a label */
  abstract isReversible(): boolean;

  /** Clone this iterator */
  abstract clone(): JumpValues;
}

// ---------------------------------------------------------------------------
// JumpValuesRange
// ---------------------------------------------------------------------------

/**
 * Single entry switch variable that can take a range of values.
 */
export class JumpValuesRange extends JumpValues {
  protected range: CircleRange | null;
  protected normqvn: Varnode;
  protected startop: PcodeOp;
  protected curval: uintb;

  constructor() {
    super();
    this.range = null;
    this.normqvn = null;
    this.startop = null;
    this.curval = 0n;
  }

  /** Set the range of values explicitly */
  setRange(rng: CircleRange): void {
    this.range = rng;
  }

  /** Set the normalized switch Varnode explicitly */
  setStartVn(vn: Varnode): void {
    this.normqvn = vn;
  }

  /** Set the starting PcodeOp explicitly */
  setStartOp(op: PcodeOp): void {
    this.startop = op;
  }

  truncate(nm: int4): void {
    // The starting value for the range and the step is preserved.
    // The ending value is set so there are exactly the given number of elements in the range.
    const rangeSize: int4 = (64 - count_leading_zeros((this.range as any).getMask())) >> 3;
    const left: uintb = (this.range as any).getMin();
    const step: int4 = (this.range as any).getStep();
    const right: uintb = (left + BigInt(step) * BigInt(nm)) & (this.range as any).getMask();
    (this.range as any).setRange(left, right, rangeSize, step);
  }

  getSize(): uintb {
    return (this.range as any).getSize();
  }

  contains(val: uintb): boolean {
    return (this.range as any).contains(val);
  }

  initializeForReading(): boolean {
    if ((this.range as any).getSize() === 0n) return false;
    this.curval = (this.range as any).getMin();
    return true;
  }

  next(): boolean {
    // C++ getNext takes uintb& and modifies it in place.
    // We use a ref wrapper: { val: bigint }
    const ref = { val: this.curval };
    const result: boolean = (this.range as any).getNext(ref);
    this.curval = ref.val;
    return result;
  }

  getValue(): uintb {
    return this.curval;
  }

  getStartVarnode(): Varnode {
    return this.normqvn;
  }

  getStartOp(): PcodeOp {
    return this.startop;
  }

  isReversible(): boolean {
    return true;
  }

  clone(): JumpValues {
    const res = new JumpValuesRange();
    res.range = this.range;
    res.normqvn = this.normqvn;
    res.startop = this.startop;
    return res;
  }
}

// ---------------------------------------------------------------------------
// JumpValuesRangeDefault
// ---------------------------------------------------------------------------

/**
 * A jump-table starting range with two possible execution paths.
 *
 * This extends the basic JumpValuesRange having a single entry switch variable and
 * adds a second entry point that takes only a single value. This value comes last in the iteration.
 */
export class JumpValuesRangeDefault extends JumpValuesRange {
  private extravalue: uintb;
  private extravn: Varnode;
  private extraop: PcodeOp;
  private lastvalue: boolean;

  constructor() {
    super();
    this.extravalue = 0n;
    this.extravn = null;
    this.extraop = null;
    this.lastvalue = false;
  }

  /** Set the extra value explicitly */
  setExtraValue(val: uintb): void {
    this.extravalue = val;
  }

  /** Set the associated start Varnode */
  setDefaultVn(vn: Varnode): void {
    this.extravn = vn;
  }

  /** Set the associated start PcodeOp */
  setDefaultOp(op: PcodeOp): void {
    this.extraop = op;
  }

  getSize(): uintb {
    return (this.range as any).getSize() + 1n;
  }

  contains(val: uintb): boolean {
    if (this.extravalue === val) return true;
    return (this.range as any).contains(val);
  }

  initializeForReading(): boolean {
    if ((this.range as any).getSize() === 0n) {
      this.curval = this.extravalue;
      this.lastvalue = true;
    } else {
      this.curval = (this.range as any).getMin();
      this.lastvalue = false;
    }
    return true;
  }

  next(): boolean {
    if (this.lastvalue) return false;
    const ref = { val: this.curval };
    if ((this.range as any).getNext(ref)) {
      this.curval = ref.val;
      return true;
    }
    this.lastvalue = true;
    this.curval = this.extravalue;
    return true;
  }

  getStartVarnode(): Varnode {
    return this.lastvalue ? this.extravn : this.normqvn;
  }

  getStartOp(): PcodeOp {
    return this.lastvalue ? this.extraop : this.startop;
  }

  isReversible(): boolean {
    return !this.lastvalue;  // The extravalue is not reversible
  }

  clone(): JumpValues {
    const res = new JumpValuesRangeDefault();
    res.range = this.range;
    res.normqvn = this.normqvn;
    res.startop = this.startop;
    res.extravalue = this.extravalue;
    res.extravn = this.extravn;
    res.extraop = this.extraop;
    return res;
  }
}

// ---------------------------------------------------------------------------
// JumpModel (abstract base)
// ---------------------------------------------------------------------------

/**
 * A jump-table execution model.
 *
 * This class holds details of the model and recovers these details in various stages.
 * The model concepts include:
 *   - Address Table, the set of destination addresses the jump-table can produce.
 *   - Normalized Switch Variable, the Varnode with the most restricted set of values used
 *       by the model to produce the destination addresses.
 *   - Unnormalized Switch Variable, the Varnode being switched on, as seen in the decompiler output.
 *   - Case labels, switch variable values associated with specific destination addresses.
 *   - Guards, CBRANCH ops that enforce the normalized switch variable's value range.
 */
export abstract class JumpModel {
  protected jumptable: JumpTable;

  constructor(jt: JumpTable) {
    this.jumptable = jt;
  }

  /** Return true if this model was manually overridden */
  abstract isOverride(): boolean;

  /** Return the number of entries in the address table */
  abstract getTableSize(): int4;

  /**
   * Attempt to recover details of the model, given a specific BRANCHIND.
   * @param fd is the function containing the switch
   * @param indop is the given BRANCHIND
   * @param matchsize is the expected number of address table entries to recover, or 0 for no expectation
   * @param maxtablesize is maximum number of address table entries to allow in the model
   * @returns true if details of the model were successfully recovered
   */
  abstract recoverModel(fd: Funcdata, indop: PcodeOp, matchsize: uint4, maxtablesize: uint4): boolean;

  /**
   * Construct the explicit list of target addresses (the Address Table) from this model.
   */
  abstract buildAddresses(
    fd: Funcdata, indop: PcodeOp, addresstable: Address[],
    loadpoints: LoadTable[] | null, loadcounts: int4[] | null
  ): void;

  /**
   * Recover the unnormalized switch variable.
   */
  abstract findUnnormalized(maxaddsub: uint4, maxleftright: uint4, maxext: uint4): void;

  /**
   * Recover case labels associated with the Address table.
   */
  abstract buildLabels(fd: Funcdata, addresstable: Address[], label: bigint[], orig: JumpModel): void;

  /**
   * Do normalization of the given switch specific to this model.
   * @returns the Varnode holding the final unnormalized switch variable
   */
  abstract foldInNormalization(fd: Funcdata, indop: PcodeOp): Varnode;

  /**
   * Eliminate any guard code involved in computing the switch destination.
   * @returns true if a change was made to data-flow
   */
  abstract foldInGuards(fd: Funcdata, jump: JumpTable): boolean;

  /**
   * Perform a sanity check on recovered addresses.
   * @returns true if there are (at least some) reasonable addresses in the table
   */
  abstract sanityCheck(
    fd: Funcdata, indop: PcodeOp, addresstable: Address[],
    loadpoints: LoadTable[], loadcounts: int4[] | null
  ): boolean;

  /** Clone this model */
  abstract cloneModel(jt: JumpTable): JumpModel;

  /** Clear any non-permanent aspects of the model */
  clear(): void {}

  /** Encode this model to a stream */
  encode(encoder: Encoder): void {}

  /** Decode this model from a stream */
  decode(decoder: Decoder): void {}
}

// ---------------------------------------------------------------------------
// JumpModelTrivial
// ---------------------------------------------------------------------------

/**
 * A trivial jump-table model, where the BRANCHIND input Varnode is the switch variable.
 *
 * This class treats the input Varnode to the BRANCHIND as the switch variable, and recovers
 * its possible values from the existing block structure. This is used when the flow following
 * fork recovers destination addresses, but the switch normalization action is unable to recover
 * the model.
 */
export class JumpModelTrivial extends JumpModel {
  private size: uint4;

  constructor(jt: JumpTable) {
    super(jt);
    this.size = 0;
  }

  isOverride(): boolean {
    return false;
  }

  getTableSize(): int4 {
    return this.size;
  }

  recoverModel(fd: Funcdata, indop: PcodeOp, matchsize: uint4, _maxtablesize: uint4): boolean {
    this.size = (indop as any).getParent().sizeOut();
    return (this.size !== 0) && (this.size <= matchsize);
  }

  buildAddresses(
    fd: Funcdata, indop: PcodeOp, addresstable: Address[],
    _loadpoints: LoadTable[] | null, _loadcounts: int4[] | null
  ): void {
    addresstable.length = 0;
    const bl: BlockBasic = (indop as any).getParent();
    for (let i: int4 = 0; i < (bl as any).sizeOut(); ++i) {
      const outbl: BlockBasic = (bl as any).getOut(i);
      addresstable.push((outbl as any).getStart());
    }
  }

  findUnnormalized(_maxaddsub: uint4, _maxleftright: uint4, _maxext: uint4): void {
    // No normalization needed for the trivial model
  }

  buildLabels(
    _fd: Funcdata, addresstable: Address[], label: bigint[], _orig: JumpModel
  ): void {
    for (let i: uint4 = 0; i < addresstable.length; ++i) {
      label.push(addresstable[i].getOffset());  // Address itself is the label
    }
  }

  foldInNormalization(_fd: Funcdata, _indop: PcodeOp): Varnode {
    return null;
  }

  foldInGuards(_fd: Funcdata, _jump: JumpTable): boolean {
    return false;
  }

  sanityCheck(
    _fd: Funcdata, _indop: PcodeOp, _addresstable: Address[],
    _loadpoints: LoadTable[], _loadcounts: int4[] | null
  ): boolean {
    return true;
  }

  cloneModel(jt: JumpTable): JumpModel {
    const res = new JumpModelTrivial(jt);
    res.size = this.size;
    return res;
  }
}

// ---------------------------------------------------------------------------
// GuardRecord
// ---------------------------------------------------------------------------

/**
 * A (putative) switch variable Varnode and a constraint imposed by a CBRANCH.
 *
 * The record constrains a specific Varnode.  If the associated CBRANCH is followed
 * along the path that reaches the switch's BRANCHIND, then we have an explicit
 * description of the possible values the Varnode can hold.
 */
export class GuardRecord {
  private cbranch: PcodeOp;
  private readOp: PcodeOp;
  private vn: Varnode;
  private baseVn: Varnode;
  private indpath: int4;
  private bitsPreserved: int4;
  private range: CircleRange;
  private unrolled: boolean;

  /**
   * Constructor.
   * @param bOp is the CBRANCH guarding the switch
   * @param rOp is the PcodeOp immediately reading the Varnode
   * @param path is the specific branch to take from the CBRANCH to reach the switch
   * @param rng is the range of values causing the switch path to be taken
   * @param v is the Varnode holding the value controlling the CBRANCH
   * @param unr is true if the guard is duplicated across multiple blocks
   */
  constructor(bOp: PcodeOp, rOp: PcodeOp, path: int4, rng: CircleRange, v: Varnode, unr: boolean = false) {
    this.cbranch = bOp;
    this.readOp = rOp;
    this.indpath = path;
    // In C++, CircleRange is a value type copied on assignment.
    // In TypeScript, we must explicitly copy to avoid aliasing bugs
    // where later pullBack mutations corrupt earlier guards' ranges.
    this.range = new CircleRange();
    this.range.copyFrom(rng);
    this.vn = v;
    const bitsPreservedRef = { val: 0 };
    this.baseVn = GuardRecord.quasiCopy(v, bitsPreservedRef);
    this.bitsPreserved = bitsPreservedRef.val;
    this.unrolled = unr;
  }

  /** Is this guard duplicated across multiple blocks */
  isUnrolled(): boolean {
    return this.unrolled;
  }

  /** Get the CBRANCH associated with this guard */
  getBranch(): PcodeOp {
    return this.cbranch;
  }

  /** Get the PcodeOp immediately causing the restriction */
  getReadOp(): PcodeOp {
    return this.readOp;
  }

  /** Get the specific path index going towards the switch */
  getPath(): int4 {
    return this.indpath;
  }

  /** Get the range of values causing the switch path to be taken */
  getRange(): CircleRange {
    return this.range;
  }

  /** Mark this guard as unused */
  clear(): void {
    this.cbranch = null;
  }

  /**
   * Determine if this guard applies to the given Varnode.
   *
   * The guard applies if we know the given Varnode holds the same value as the Varnode
   * attached to the guard. Returns:
   *   - 0, if the two Varnodes do not clearly hold the same value.
   *   - 1, if the two Varnodes clearly hold the same value.
   *   - 2, if the two Varnodes clearly hold the same value, pending no writes between their defining op.
   */
  valueMatch(vn2: Varnode, baseVn2: Varnode, bitsPreserved2: int4): int4 {
    if (this.vn === vn2) return 1;  // Same varnode, same value
    let loadOp: PcodeOp;
    let loadOp2: PcodeOp;
    if (this.bitsPreserved === bitsPreserved2) {
      // Are the same number of bits being copied
      if (this.baseVn === baseVn2) return 1;  // Are bits being copied from same varnode
      loadOp = (this.baseVn as any).getDef();
      loadOp2 = (baseVn2 as any).getDef();
    } else {
      loadOp = (this.vn as any).getDef();
      loadOp2 = (vn2 as any).getDef();
    }
    if (loadOp === null) return 0;
    if (loadOp2 === null) return 0;
    if (GuardRecord.oneOffMatch(loadOp, loadOp2) === 1) return 1;
    if ((loadOp as any).code() !== OpCode.CPUI_LOAD) return 0;
    if ((loadOp2 as any).code() !== OpCode.CPUI_LOAD) return 0;
    if ((loadOp as any).getIn(0).getOffset() !== (loadOp2 as any).getIn(0).getOffset()) return 0;
    const ptr: Varnode = (loadOp as any).getIn(1);
    const ptr2: Varnode = (loadOp2 as any).getIn(1);
    if (ptr === ptr2) return 2;
    if (!(ptr as any).isWritten()) return 0;
    if (!(ptr2 as any).isWritten()) return 0;
    const addop: PcodeOp = (ptr as any).getDef();
    if ((addop as any).code() !== OpCode.CPUI_INT_ADD) return 0;
    const constvn: Varnode = (addop as any).getIn(1);
    if (!(constvn as any).isConstant()) return 0;
    const addop2: PcodeOp = (ptr2 as any).getDef();
    if ((addop2 as any).code() !== OpCode.CPUI_INT_ADD) return 0;
    const constvn2: Varnode = (addop2 as any).getIn(1);
    if (!(constvn2 as any).isConstant()) return 0;
    if ((addop as any).getIn(0) !== (addop2 as any).getIn(0)) return 0;
    if ((constvn as any).getOffset() !== (constvn2 as any).getOffset()) return 0;
    return 2;
  }

  /**
   * Return 1 if the two given PcodeOps produce exactly the same value, 0 if otherwise.
   *
   * We check up through only one level of PcodeOp calculation and only for certain binary ops
   * where the second parameter is a constant.
   */
  static oneOffMatch(op1: PcodeOp, op2: PcodeOp): int4 {
    if ((op1 as any).code() !== (op2 as any).code()) return 0;
    switch ((op1 as any).code()) {
      case OpCode.CPUI_INT_AND:
      case OpCode.CPUI_INT_ADD:
      case OpCode.CPUI_INT_XOR:
      case OpCode.CPUI_INT_OR:
      case OpCode.CPUI_INT_LEFT:
      case OpCode.CPUI_INT_RIGHT:
      case OpCode.CPUI_INT_SRIGHT:
      case OpCode.CPUI_INT_MULT:
      case OpCode.CPUI_SUBPIECE:
        if ((op2 as any).getIn(0) !== (op1 as any).getIn(0)) return 0;
        if (matchingConstants((op2 as any).getIn(1), (op1 as any).getIn(1)))
          return 1;
        break;
      default:
        break;
    }
    return 0;
  }

  /**
   * Compute the source of a quasi-COPY chain for the given Varnode.
   *
   * A value is a quasi-copy if a sequence of PcodeOps producing it always hold
   * the value as the least significant bits of their output Varnode, but the sequence
   * may put other non-zero values in the upper bits.
   * This method computes the earliest ancestor Varnode for which the given Varnode
   * can be viewed as a quasi-copy.
   * @param vn is the given Varnode
   * @param bitsPreservedRef will hold the number of least significant bits preserved by the sequence
   * @returns the earliest source of the quasi-copy, which may just be the given Varnode
   */
  static quasiCopy(vn: Varnode, bitsPreservedRef: { val: int4 }): Varnode {
    bitsPreservedRef.val = mostsigbit_set((vn as any).getNZMask()) + 1;
    if (bitsPreservedRef.val === 0) return vn;
    let mask: uintb = 1n << 1n;
    mask <<= BigInt(bitsPreservedRef.val - 1);
    mask -= 1n;
    let op: PcodeOp = (vn as any).getDef();
    let constVn: Varnode;
    while (op !== null) {
      switch ((op as any).code()) {
        case OpCode.CPUI_COPY:
          vn = (op as any).getIn(0);
          op = (vn as any).getDef();
          break;
        case OpCode.CPUI_INT_AND:
          constVn = (op as any).getIn(1);
          if ((constVn as any).isConstant() && (constVn as any).getOffset() === mask) {
            vn = (op as any).getIn(0);
            op = (vn as any).getDef();
          } else {
            op = null;
          }
          break;
        case OpCode.CPUI_INT_OR:
          constVn = (op as any).getIn(1);
          if ((constVn as any).isConstant() &&
              (((constVn as any).getOffset() | mask) === ((constVn as any).getOffset() ^ mask))) {
            vn = (op as any).getIn(0);
            op = (vn as any).getDef();
          } else {
            op = null;
          }
          break;
        case OpCode.CPUI_INT_SEXT:
        case OpCode.CPUI_INT_ZEXT:
          if ((op as any).getIn(0).getSize() * 8 >= bitsPreservedRef.val) {
            vn = (op as any).getIn(0);
            op = (vn as any).getDef();
          } else {
            op = null;
          }
          break;
        case OpCode.CPUI_PIECE:
          if ((op as any).getIn(1).getSize() * 8 >= bitsPreservedRef.val) {
            vn = (op as any).getIn(1);
            op = (vn as any).getDef();
          } else {
            op = null;
          }
          break;
        case OpCode.CPUI_SUBPIECE:
          constVn = (op as any).getIn(1);
          if ((constVn as any).isConstant() && (constVn as any).getOffset() === 0n) {
            vn = (op as any).getIn(0);
            op = (vn as any).getDef();
          } else {
            op = null;
          }
          break;
        default:
          op = null;
          break;
      }
    }
    return vn;
  }
}

// ---------------------------------------------------------------------------
// Helper: matching_constants (file-local)
// ---------------------------------------------------------------------------

/**
 * Check if the two given Varnodes are matching constants.
 */
function matchingConstants(vn1: Varnode, vn2: Varnode): boolean {
  if (!(vn1 as any).isConstant()) return false;
  if (!(vn2 as any).isConstant()) return false;
  if ((vn1 as any).getOffset() !== (vn2 as any).getOffset()) return false;
  return true;
}

// ---------------------------------------------------------------------------
// PathMeld
// ---------------------------------------------------------------------------

/**
 * A PcodeOp in the path set associated with the last Varnode in the intersection.
 *
 * This links a PcodeOp to the point where the flow path to it split from common path.
 */
class RootedOp {
  /** An op in the container */
  op: PcodeOp;
  /** The index, within commonVn, of the Varnode at the split point */
  rootVn: int4;

  constructor(o: PcodeOp, root: int4) {
    this.op = o;
    this.rootVn = root;
  }
}

/**
 * All paths from a (putative) switch variable to the CPUI_BRANCHIND.
 *
 * This is a container for intersecting paths during the construction of a
 * JumpModel.  It contains every PcodeOp from some starting Varnode through
 * all paths to a specific BRANCHIND.  The paths can split and rejoin. This also
 * keeps track of Varnodes that are present on all paths, as these are the
 * potential switch variables for the model.
 */
export class PathMeld {
  /** Varnodes in common with all paths */
  private commonVn: Varnode[];
  /** All the ops for the melded paths */
  private opMeld: RootedOp[];

  constructor() {
    this.commonVn = [];
    this.opMeld = [];
  }

  /**
   * Calculate intersection of a new Varnode path with the old path.
   *
   * The new path of Varnodes must all be marked. The old path, commonVn,
   * is replaced with the intersection.  A map is created from the index of each
   * Varnode in the old path with its index in the new path.  If the Varnode is
   * not in the intersection, its index is mapped to -1.
   */
  private internalIntersect(parentMap: int4[]): void {
    const newVn: Varnode[] = [];
    let lastIntersect: int4 = -1;
    for (let i: int4 = 0; i < this.commonVn.length; ++i) {
      const vn: Varnode = this.commonVn[i];
      if ((vn as any).isMark()) {
        // Look for previously marked varnode, so we know it is in both lists
        lastIntersect = newVn.length;
        parentMap.push(lastIntersect);
        newVn.push(vn);
        (vn as any).clearMark();
      } else {
        parentMap.push(-1);
      }
    }
    this.commonVn = newVn;
    lastIntersect = -1;
    for (let i: int4 = parentMap.length - 1; i >= 0; --i) {
      const val: int4 = parentMap[i];
      if (val === -1)
        parentMap[i] = lastIntersect;  // Fill in with next earliest that is in intersection
      else
        lastIntersect = val;
    }
  }

  /**
   * Meld in PcodeOps from a new path into this container.
   *
   * Execution order of the PcodeOps in the container is maintained.  Each PcodeOp, old or new,
   * has its split point from the common path recalculated.
   * @returns the index of the last (earliest) Varnode in the common path or -1
   */
  private meldOps(path: PcodeOpNode[], cutOff: int4, parentMap: int4[]): int4 {
    // First update opMeld.rootVn with new intersection information
    for (let i: int4 = 0; i < this.opMeld.length; ++i) {
      const pos: int4 = parentMap[this.opMeld[i].rootVn];
      if (pos === -1) {
        this.opMeld[i].op = null;  // Op split but did not rejoin
      } else {
        this.opMeld[i].rootVn = pos;  // New index
      }
    }

    // Do a merge sort, keeping ops in execution order
    const newMeld: RootedOp[] = [];
    let curRoot: int4 = -1;
    let meldPos: int4 = 0;
    let lastBlock: BlockBasic | null = null;
    for (let i: int4 = 0; i < cutOff; ++i) {
      const op: PcodeOp = path[i].op;
      let curOp: PcodeOp | null = null;
      while (meldPos < this.opMeld.length) {
        const trialOp: PcodeOp = this.opMeld[meldPos].op;
        if (trialOp === null) {
          meldPos += 1;
          continue;
        }
        if ((trialOp as any).getParent() !== (op as any).getParent()) {
          if ((op as any).getParent() === lastBlock) {
            curOp = null;  // op comes AFTER trialOp
            break;
          } else if ((trialOp as any).getParent() !== lastBlock) {
            // Both trialOp and op come from different blocks that are not the lastBlock
            const res: int4 = this.opMeld[meldPos].rootVn;
            // Found a new cut point
            this.opMeld = newMeld;
            return res;
          }
        } else if ((trialOp as any).getSeqNum().getOrder() <= (op as any).getSeqNum().getOrder()) {
          curOp = trialOp;  // op is equal to or comes later than trialOp
          break;
        }
        lastBlock = (trialOp as any).getParent();
        newMeld.push(this.opMeld[meldPos]);
        curRoot = this.opMeld[meldPos].rootVn;
        meldPos += 1;
      }
      if (curOp === op) {
        newMeld.push(this.opMeld[meldPos]);
        curRoot = this.opMeld[meldPos].rootVn;
        meldPos += 1;
      } else {
        newMeld.push(new RootedOp(op, curRoot));
      }
      lastBlock = (op as any).getParent();
    }
    this.opMeld = newMeld;
    return -1;
  }

  /**
   * Truncate all paths at the given new Varnode.
   *
   * The given Varnode is provided as an index into the current common Varnode list.
   * All Varnodes and PcodeOps involved in execution before this new cut point are removed.
   */
  private truncatePaths(cutPoint: int4): void {
    while (this.opMeld.length > 1) {
      if (this.opMeld[this.opMeld.length - 1].rootVn < cutPoint)
        break;  // If we see op using varnode earlier than cut point, keep it
      this.opMeld.pop();
    }
    this.commonVn.length = cutPoint;  // Since intersection is ordered, just resize to cutPoint
  }

  // ----- Public methods -----

  /**
   * Copy paths from another container.
   */
  setFromMeld(op2: PathMeld): void {
    this.commonVn = [...op2.commonVn];
    this.opMeld = [...op2.opMeld];
  }

  /**
   * Initialize this to be a single path.
   * @param path is the list of PcodeOpNode edges in the path (in reverse execution order)
   */
  setFromPath(path: PcodeOpNode[]): void {
    for (let i: int4 = 0; i < path.length; ++i) {
      const node: PcodeOpNode = path[i];
      const vn: Varnode = (node.op as any).getIn(node.slot);
      this.opMeld.push(new RootedOp(node.op, i));
      this.commonVn.push(vn);
    }
  }

  /**
   * Initialize this container to a single node "path".
   * @param op is the one PcodeOp in the path
   * @param vn is the one Varnode (input to the PcodeOp) in the path
   */
  setFromOpVn(op: PcodeOp, vn: Varnode): void {
    this.commonVn.push(vn);
    this.opMeld.push(new RootedOp(op, 0));
  }

  /**
   * Append a new set of paths to this set of paths.
   *
   * The new paths must all start at the common end-point of the paths in
   * this container.
   */
  append(op2: PathMeld): void {
    this.commonVn.unshift(...op2.commonVn);
    this.opMeld.unshift(...op2.opMeld);
    // Renumber all the rootVn refs to varnodes we have moved
    for (let i: int4 = op2.opMeld.length; i < this.opMeld.length; ++i) {
      this.opMeld[i].rootVn += op2.commonVn.length;
    }
  }

  /** Clear this to be an empty container */
  clear(): void {
    this.commonVn.length = 0;
    this.opMeld.length = 0;
  }

  /**
   * Meld a new path into this container.
   *
   * Add the new path, recalculating the set of Varnodes common to all paths.
   * Paths are trimmed to ensure that any path that splits from the common intersection
   * must eventually rejoin.
   * @param path is the new path of PcodeOpNode edges to meld, in reverse execution order
   */
  meld(path: PcodeOpNode[]): void {
    const parentMap: int4[] = [];

    for (let i: int4 = 0; i < path.length; ++i) {
      const node: PcodeOpNode = path[i];
      (node.op as any).getIn(node.slot).setMark();  // Mark varnodes in the new path
    }
    this.internalIntersect(parentMap);
    let cutOff: int4 = -1;

    // Calculate where the cutoff point is in the new path
    for (let i: int4 = 0; i < path.length; ++i) {
      const node: PcodeOpNode = path[i];
      const vn: Varnode = (node.op as any).getIn(node.slot);
      if (!(vn as any).isMark()) {
        // If mark already cleared, we know it is in intersection
        cutOff = i + 1;  // Cut-off must at least be past this vn
      } else {
        (vn as any).clearMark();
      }
    }
    const newCutoff: int4 = this.meldOps(path, cutOff, parentMap);
    if (newCutoff >= 0)
      this.truncatePaths(newCutoff);
    path.length = cutOff;
  }

  /**
   * Mark PcodeOps paths from the given start.
   *
   * The starting Varnode, common to all paths, is provided as an index.
   * All PcodeOps up to the final BRANCHIND are (un)marked.
   * @param val is true for marking, false for unmarking
   * @param startVarnode is the index of the starting PcodeOp
   */
  markPaths(val: boolean, startVarnode: int4): void {
    let startOp: int4;
    for (startOp = this.opMeld.length - 1; startOp >= 0; --startOp) {
      if (this.opMeld[startOp].rootVn === startVarnode)
        break;
    }
    if (startOp < 0) return;
    if (val) {
      for (let i: int4 = 0; i <= startOp; ++i)
        (this.opMeld[i].op as any).setMark();
    } else {
      for (let i: int4 = 0; i <= startOp; ++i)
        (this.opMeld[i].op as any).clearMark();
    }
  }

  /** Return the number of Varnodes common to all paths */
  numCommonVarnode(): int4 {
    return this.commonVn.length;
  }

  /** Return the number of PcodeOps across all paths */
  numOps(): int4 {
    return this.opMeld.length;
  }

  /** Get the i-th common Varnode */
  getVarnode(i: int4): Varnode {
    return this.commonVn[i];
  }

  /** Get the split-point for the i-th PcodeOp */
  getOpParent(i: int4): Varnode {
    return this.commonVn[this.opMeld[i].rootVn];
  }

  /** Get the i-th PcodeOp */
  getOp(i: int4): PcodeOp {
    return this.opMeld[i].op;
  }

  /**
   * Find earliest PcodeOp that has a specific common Varnode as input.
   * @param pos is the index of the Varnode
   * @returns the earliest PcodeOp using the Varnode
   */
  getEarliestOp(pos: int4): PcodeOp | null {
    for (let i: int4 = this.opMeld.length - 1; i >= 0; --i) {
      if (this.opMeld[i].rootVn === pos)
        return this.opMeld[i].op;
    }
    return null;
  }

  /**
   * Return true if a LOAD exists in the common path prior to the given point.
   * @param i is the given point in the path
   * @returns true if a LOAD is present
   */
  isLoadInPath(i: int4): boolean {
    while (i > 0) {
      i -= 1;
      const vn: Varnode = this.commonVn[i];
      if (!(vn as any).isWritten()) continue;
      if ((vn as any).getDef().code() === OpCode.CPUI_LOAD) return true;
    }
    return false;
  }

  /** Return true if this container holds no paths */
  empty(): boolean {
    return this.commonVn.length === 0;
  }
}
/**
 * @file jumptable_part2.ts
 * @description Jump-table recovery classes (Part 2): JumpBasic, JumpBasic2,
 * JumpBasicOverride, JumpAssisted, and JumpTable.
 *
 * Translated from Ghidra's jumptable.hh / jumptable.cc
 *
 * This file is intended to be concatenated after jumptable_part1.ts which
 * contains LoadTable, EmulateFunction, PathMeld, GuardRecord, JumpValues,
 * JumpValuesRange, JumpValuesRangeDefault, JumpModel, and JumpModelTrivial.
 */

// ---------------------------------------------------------------------------
// Additional forward-declare types for Part 2
// ---------------------------------------------------------------------------

type FlowBlock = any;
type FlowInfo = any;
type DynamicHash = any;
type UserPcodeOp = any;
type JumpAssistOp = any;
type ExecutablePcode = any;

// =========================================================================
// JumpBasic
// =========================================================================

/**
 * The basic switch model.
 *
 * This is the most common model:
 *   - A straight-line calculation from switch variable to BRANCHIND
 *   - The switch variable is bounded by one or more guards that branch around the BRANCHIND
 *   - The unnormalized switch variable is recovered from the normalized variable through
 *     some basic transforms
 */
class JumpBasic extends JumpModel {
  protected jrange: JumpValuesRange | null;
  protected pathMeld: PathMeld;
  protected selectguards: GuardRecord[];
  protected varnodeIndex: number;
  protected normalvn: any;   // Varnode
  protected switchvn: any;   // Varnode

  constructor(jt: JumpTable) {
    super(jt);
    this.jrange = null;
    this.pathMeld = new PathMeld();
    this.selectguards = [];
    this.varnodeIndex = 0;
    this.normalvn = null;
    this.switchvn = null;
  }

  getPathMeld(): PathMeld {
    return this.pathMeld;
  }

  getValueRange(): JumpValuesRange | null {
    return this.jrange;
  }

  // destructor logic not needed in TS; jrange would be GC'd

  isOverride(): boolean {
    return false;
  }

  cloneModel(jt: JumpTable): JumpModel {
    const res = new JumpBasic(jt);
    return res;
  }

  getTableSize(): number {
    if (this.jrange === null) return 0;
    return Number(this.jrange.getSize());
  }

  /**
   * Do we prune in here in our depth-first search for the normalized switch variable
   */
  static isprune(vn: any): boolean {
    if (!(vn as any).isWritten()) return true;
    const op = (vn as any).getDef();
    if ((op as any).isCall() || (op as any).isMarker()) return true;
    if ((op as any).numInput() === 0) return true;
    return false;
  }

  /**
   * Is it possible for the given Varnode to be a switch variable?
   */
  static ispoint(vn: any): boolean {
    if ((vn as any).isConstant()) return false;
    if ((vn as any).isAnnotation()) return false;
    if ((vn as any).isReadOnly()) return false;
    return true;
  }

  /**
   * Get the step/stride associated with the Varnode.
   * If the some of the least significant bits of the given Varnode are known to
   * be zero, translate this into a stride for the jumptable range.
   */
  static getStride(vn: any): number {
    let mask: bigint = (vn as any).getNZMask();
    if ((mask & 0x3fn) === 0n)
      return 32;
    let stride = 1;
    while ((mask & 1n) === 0n) {
      mask >>= 1n;
      stride <<= 1;
    }
    return stride;
  }

  /**
   * Back up the constant value in the output Varnode to the value in the input Varnode.
   * PcodeOps between the output and input Varnodes must be reversible.
   */
  static backup2Switch(fd: any, output: bigint, outvn: any, invn: any): bigint {
    let curvn = outvn;
    let op: any;
    let top: any;
    let slot: number;

    while (curvn !== invn) {
      op = (curvn as any).getDef();
      top = (op as any).getOpcode();
      for (slot = 0; slot < (op as any).numInput(); ++slot)
        if (!(op as any).getIn(slot).isConstant()) break;
      if ((op as any).getEvalType() === 0x10000) {
        // PcodeOp::binary (OP_binary = 0x10000)
        const addr = (op as any).getIn(1 - slot).getAddr();
        let otherval: bigint;
        if (!addr.isConstant()) {
          const mem = new MemoryImage(addr.getSpace(), 4, 1024, (fd as any).getArch().loader);
          otherval = mem.getValue(addr.getOffset(), (op as any).getIn(1 - slot).getSize());
        } else {
          otherval = addr.getOffset();
        }
        output = (top as any).recoverInputBinary(
          slot,
          (op as any).getOut().getSize(),
          output,
          (op as any).getIn(slot).getSize(),
          otherval
        );
        curvn = (op as any).getIn(slot);
      } else if ((op as any).getEvalType() === 0x8000) {
        // PcodeOp::unary (OP_unary = 0x8000)
        output = (top as any).recoverInputUnary(
          (op as any).getOut().getSize(),
          output,
          (op as any).getIn(slot).getSize()
        );
        curvn = (op as any).getIn(slot);
      } else {
        throw new LowlevelError("Bad switch normalization op");
      }
    }
    return output;
  }

  /**
   * If the Varnode has a restricted range due to masking via INT_AND, the maximum value
   * of this range is returned. Otherwise, 0 is returned.
   */
  static getMaxValue(vn: any): bigint {
    let maxValue: bigint = 0n;
    if (!(vn as any).isWritten()) return maxValue;
    const op = (vn as any).getDef();
    if ((op as any).code() === OpCode.CPUI_INT_AND) {
      const constvn = (op as any).getIn(1);
      if ((constvn as any).isConstant()) {
        maxValue = coveringmask((constvn as any).getOffset());
        maxValue = (maxValue + 1n) & calc_mask((vn as any).getSize());
      }
    } else if ((op as any).code() === OpCode.CPUI_MULTIEQUAL) {
      let i: number;
      for (i = 0; i < (op as any).numInput(); ++i) {
        const subvn = (op as any).getIn(i);
        if (!(subvn as any).isWritten()) break;
        const andOp = (subvn as any).getDef();
        if ((andOp as any).code() !== OpCode.CPUI_INT_AND) break;
        const constvn = (andOp as any).getIn(1);
        if (!(constvn as any).isConstant()) break;
        if (maxValue < (constvn as any).getOffset())
          maxValue = (constvn as any).getOffset();
      }
      if (i === (op as any).numInput()) {
        maxValue = coveringmask(maxValue);
        maxValue = (maxValue + 1n) & calc_mask((vn as any).getSize());
      } else {
        maxValue = 0n;
      }
    }
    return maxValue;
  }

  /**
   * Return true if all array elements are the same Varnode
   */
  static duplicateVarnodes(arr: any[]): boolean {
    const vn = arr[0];
    for (let i = 1; i < arr.length; ++i) {
      if (arr[i] !== vn) return false;
    }
    return true;
  }

  /**
   * Calculate the initial set of Varnodes that might be switch variables.
   */
  findDeterminingVarnodes(op: any, slot: number): void {
    const path: PcodeOpNode[] = [];
    let firstpoint = false;

    path.push(new PcodeOpNode(op, slot));

    do {
      const node = path[path.length - 1];
      const curvn = (node.op as any).getIn(node.slot);
      if (JumpBasic.isprune(curvn)) {
        if (JumpBasic.ispoint(curvn)) {
          if (!firstpoint) {
            this.pathMeld.setFromPath(path);
            firstpoint = true;
          } else {
            this.pathMeld.meld(path);
          }
        }

        path[path.length - 1].slot += 1;
        while (path[path.length - 1].slot >= (path[path.length - 1].op as any).numInput()) {
          path.pop();
          if (path.length === 0) break;
          path[path.length - 1].slot += 1;
        }
      } else {
        path.push(new PcodeOpNode((curvn as any).getDef(), 0));
      }
    } while (path.length > 1);

    if (this.pathMeld.empty()) {
      this.pathMeld.setFromOpVn(op, (op as any).getIn(slot));
    }
  }

  /**
   * Analyze CBRANCHs leading up to the given basic-block as a potential switch guard.
   */
  analyzeGuards(bl: any, pathout: number): void {
    let i: number, j: number, indpath: number;
    const maxbranch = 2;
    const maxpullback = 2;
    const usenzmask: boolean = !this.jumptable!.isPartial();

    this.selectguards = [];
    let prevbl: any;
    let vn: any;

    for (i = 0; i < maxbranch; ++i) {
      if ((pathout >= 0) && ((bl as any).sizeOut() === 2)) {
        prevbl = bl;
        bl = (prevbl as any).getOut(pathout);
        indpath = pathout;
        pathout = -1;
      } else {
        pathout = -1;
        for (;;) {
          if ((bl as any).sizeIn() !== 1) {
            if ((bl as any).sizeIn() > 1)
              this.checkUnrolledGuard(bl, maxpullback, usenzmask);
            return;
          }
          prevbl = (bl as any).getIn(0);
          if ((prevbl as any).sizeOut() !== 1) break;
          bl = prevbl;
        }
        indpath = (bl as any).getInRevIndex(0);
      }
      const cbranch = (prevbl as any).lastOp();
      if (cbranch === null || (cbranch as any).code() !== OpCode.CPUI_CBRANCH)
        break;
      if (i !== 0) {
        const otherbl = (prevbl as any).getOut(1 - indpath);
        const otherop = (otherbl as any).lastOp();
        if (otherop !== null && (otherop as any).code() === OpCode.CPUI_BRANCHIND) {
          if (otherop !== this.jumptable!.getIndirectOp())
            break;
        }
      }
      let toswitchval: boolean = (indpath === 1);
      if ((cbranch as any).isBooleanFlip())
        toswitchval = !toswitchval;
      bl = prevbl;
      vn = (cbranch as any).getIn(1);
      let rng = new CircleRange(toswitchval);

      const indpathstore = (prevbl as any).getFlipPath() ? 1 - indpath : indpath;
      this.selectguards.push(new GuardRecord(cbranch, cbranch, indpathstore, rng, vn));
      for (j = 0; j < maxpullback; ++j) {
        let markup: any = null;
        if (!(vn as any).isWritten()) break;
        const readOp = (vn as any).getDef();
        vn = rng.pullBack(readOp, markup, usenzmask);
        if (vn === null) {
          break;
        }
        if (rng.isEmpty()) {
          break;
        }
        this.selectguards.push(new GuardRecord(cbranch, readOp, indpathstore, rng, vn));
      }
    }
  }

  /**
   * Calculate the range of values in the given Varnode that direct control-flow to the switch.
   */
  calcRange(vn: any, rng: { value: CircleRange }): void {
    let stride = 1;
    if ((vn as any).isConstant()) {
      rng.value = new CircleRange((vn as any).getOffset(), (vn as any).getSize());
    } else if ((vn as any).isWritten() && (vn as any).getDef().isBoolOutput()) {
      rng.value = new CircleRange(0n, 2n, 1, 1);
    } else {
      const maxValue = JumpBasic.getMaxValue(vn);
      stride = JumpBasic.getStride(vn);
      rng.value = new CircleRange(0n, maxValue, (vn as any).getSize(), stride);
    }

    const bitsPreservedRef = { val: 0 };
    const baseVn = GuardRecord.quasiCopy(vn, bitsPreservedRef);
    for (const guard of this.selectguards) {
      const matchval = guard.valueMatch(vn, baseVn, bitsPreservedRef.val);
      if (matchval === 0) continue;
      if (rng.value.intersect(guard.getRange()) !== 0) continue;
    }

    if (rng.value.getSize() > 0x10000n) {
      const positive = new CircleRange(0n, (rng.value.getMask() >> 1n) + 1n, (vn as any).getSize(), stride);
      positive.intersect(rng.value);
      if (!positive.isEmpty())
        rng.value = positive;
    }
  }

  /**
   * Find the putative switch variable with the smallest range of values reaching the switch.
   */
  findSmallestNormal(matchsize: number): void {
    const rngRef: { value: CircleRange } = { value: new CircleRange() };

    this.varnodeIndex = 0;
    this.calcRange(this.pathMeld.getVarnode(0), rngRef);
    this.jrange!.setRange(rngRef.value);
    this.jrange!.setStartVn(this.pathMeld.getVarnode(0));
    this.jrange!.setStartOp(this.pathMeld.getOp(0));
    let maxsize: bigint = rngRef.value.getSize();

    for (let i = 1; i < this.pathMeld.numCommonVarnode(); ++i) {
      if (maxsize === BigInt(matchsize))
        return;
      this.calcRange(this.pathMeld.getVarnode(i), rngRef);
      const sz = rngRef.value.getSize();
      if (sz < maxsize) {
        if (sz !== 256n || (this.pathMeld.getVarnode(i) as any).getSize() !== 1 || this.pathMeld.isLoadInPath(i)) {
          this.varnodeIndex = i;
          maxsize = sz;
          this.jrange!.setRange(rngRef.value);
          this.jrange!.setStartVn(this.pathMeld.getVarnode(i));
          this.jrange!.setStartOp(this.pathMeld.getEarliestOp(i));
        }
      }
    }
  }

  /**
   * Do all the work necessary to recover the normalized switch variable.
   */
  findNormalized(fd: any, rootbl: any, pathout: number, matchsize: number, maxtablesize: number): void {
    this.analyzeGuards(rootbl, pathout);
    this.findSmallestNormal(matchsize);
    const sz = this.jrange!.getSize();
    if ((sz > BigInt(maxtablesize)) && (this.pathMeld.numCommonVarnode() === 1)) {
      const glb = (fd as any).getArch();
      const vn = this.pathMeld.getVarnode(0);
      if ((vn as any).isReadOnly()) {
        const mem = new MemoryImage((vn as any).getSpace(), 4, 16, glb.loader);
        const val = mem.getValue((vn as any).getOffset(), (vn as any).getSize());
        this.varnodeIndex = 0;
        this.jrange!.setRange(new CircleRange(val, (vn as any).getSize()));
        this.jrange!.setStartVn(vn);
        this.jrange!.setStartOp(this.pathMeld.getOp(0));
      }
    }
  }

  /**
   * Mark the guard CBRANCHs that are truly part of the model.
   */
  markFoldableGuards(): void {
    const vn = this.pathMeld.getVarnode(this.varnodeIndex);
    const bitsPreservedRef = { val: 0 };
    const baseVn = GuardRecord.quasiCopy(vn, bitsPreservedRef);
    for (let i = 0; i < this.selectguards.length; ++i) {
      const guardRecord = this.selectguards[i];
      if (guardRecord.valueMatch(vn, baseVn, bitsPreservedRef.val) === 0 || guardRecord.isUnrolled()) {
        guardRecord.clear();
      }
    }
  }

  /**
   * Mark (or unmark) all PcodeOps involved in the model.
   */
  markModel(val: boolean): void {
    this.pathMeld.markPaths(val, this.varnodeIndex);
    for (let i = 0; i < this.selectguards.length; ++i) {
      const op = this.selectguards[i].getBranch();
      if (op === null) continue;
      const readOp = this.selectguards[i].getReadOp();
      if (val)
        (readOp as any).setMark();
      else
        (readOp as any).clearMark();
    }
  }

  /**
   * Check if the given Varnode flows to anything other than this model.
   */
  flowsOnlyToModel(vn: any, trailOp: any): boolean {
    for (let i = (vn as any).beginDescend(); i < (vn as any).endDescend(); ++i) {
      const op = (vn as any).getDescend(i);
      if (op === trailOp) continue;
      if (!(op as any).isMark())
        return false;
    }
    return true;
  }

  /**
   * Check that all incoming blocks end with a CBRANCH.
   */
  checkCommonCbranch(varArray: any[], bl: any): boolean {
    let curBlock: any = (bl as any).getIn(0);
    let op = (curBlock as any).lastOp();
    if (op === null || (op as any).code() !== OpCode.CPUI_CBRANCH)
      return false;
    const outslot = (bl as any).getInRevIndex(0);
    const isOpFlip = (op as any).isBooleanFlip();
    varArray.push((op as any).getIn(1));
    for (let i = 1; i < (bl as any).sizeIn(); ++i) {
      curBlock = (bl as any).getIn(i);
      op = (curBlock as any).lastOp();
      if (op === null || (op as any).code() !== OpCode.CPUI_CBRANCH)
        return false;
      if ((op as any).isBooleanFlip() !== isOpFlip)
        return false;
      if (outslot !== (bl as any).getInRevIndex(i))
        return false;
      varArray.push((op as any).getIn(1));
    }
    return true;
  }

  /**
   * Check for a guard that has been unrolled across multiple blocks.
   */
  checkUnrolledGuard(bl: any, maxpullback: number, usenzmask: boolean): void {
    const varArray: any[] = [];
    if (!this.checkCommonCbranch(varArray, bl))
      return;
    const indpath = (bl as any).getInRevIndex(0);
    let toswitchval: boolean = (indpath === 1);
    const cbranch = ((bl as any).getIn(0) as any).lastOp();
    if ((cbranch as any).isBooleanFlip())
      toswitchval = !toswitchval;
    let rng = new CircleRange(toswitchval);
    const indpathstore = (bl as any).getIn(0).getFlipPath() ? 1 - indpath : indpath;
    let readOp: any = cbranch;
    for (let j = 0; j < maxpullback; ++j) {
      if (JumpBasic.duplicateVarnodes(varArray)) {
        this.selectguards.push(new GuardRecord(cbranch, readOp, indpathstore, rng, varArray[0], true));
      } else {
        const multiOp = (bl as any).findMultiequal(varArray);
        if (multiOp !== null) {
          this.selectguards.push(new GuardRecord(cbranch, readOp, indpathstore, rng, (multiOp as any).getOut(), true));
        }
      }
      let markup: any = null;
      let vn = varArray[0];
      if (!(vn as any).isWritten()) break;
      readOp = (vn as any).getDef();
      vn = rng.pullBack(readOp, markup, usenzmask);
      if (vn === null) break;
      if (rng.isEmpty()) break;
      if (!(bl as any).constructor.liftVerifyUnroll(varArray, (readOp as any).getSlot(vn))) break;
    }
  }

  /**
   * Eliminate the given guard to this switch.
   */
  protected foldInOneGuard(fd: any, guard: GuardRecord, jump: JumpTable): boolean {
    const cbranch = guard.getBranch();
    const cbranchblock = (cbranch as any).getParent();
    if ((cbranchblock as any).sizeOut() !== 2) return false;
    let indpath = guard.getPath();
    if ((cbranchblock as any).getFlipPath())
      indpath = 1 - indpath;
    const switchbl = (jump.getIndirectOp() as any).getParent();
    if ((cbranchblock as any).getOut(indpath) !== switchbl)
      return false;
    const guardtarget = (cbranchblock as any).getOut(1 - indpath);
    let pos: number;

    for (pos = 0; pos < (switchbl as any).sizeOut(); ++pos)
      if ((switchbl as any).getOut(pos) === guardtarget) break;
    if (jump.hasFoldedDefault() && jump.getDefaultBlock() !== pos)
      return false;

    if (!(switchbl as any).noInterveningStatement())
      return false;
    if (pos === (switchbl as any).sizeOut()) {
      jump.addBlockToSwitch(guardtarget, JumpValues.NO_LABEL);
      jump.setLastAsDefault();
      (fd as any).pushBranch(cbranchblock, 1 - indpath, switchbl);
    } else {
      const val: bigint = ((indpath === 0) !== (cbranch as any).isBooleanFlip()) ? 0n : 1n;
      (fd as any).opSetInput(cbranch, (fd as any).newConstant((cbranch as any).getIn(0).getSize(), val), 1);
      jump.setDefaultBlock(pos);
    }
    jump.setFoldedDefault();
    guard.clear();
    return true;
  }

  recoverModel(fd: any, indop: any, matchsize: number, maxtablesize: number): boolean {
    this.jrange = new JumpValuesRange();
    this.findDeterminingVarnodes(indop, 0);
    this.findNormalized(fd, (indop as any).getParent(), -1, matchsize, maxtablesize);
    if (this.jrange.getSize() > BigInt(maxtablesize))
      return false;
    this.markFoldableGuards();
    return true;
  }

  buildAddresses(fd: any, indop: any, addresstable: Address[], loadpoints: LoadTable[] | null, loadcounts: number[] | null): void {
    addresstable.length = 0;
    const emul = new EmulateFunction(fd);
    if (loadpoints !== null)
      emul.setLoadCollect(loadpoints);

    let mask: bigint = 0xFFFFFFFFFFFFFFFFn;
    const bit: number = (fd as any).getArch().funcptr_align;
    if (bit !== 0) {
      mask = (mask >> BigInt(bit)) << BigInt(bit);
    }
    const spc = (indop as any).getAddr().getSpace();
    let notdone = this.jrange!.initializeForReading();
    while (notdone) {
      const val = this.jrange!.getValue();
      let addr = emul.emulatePath(val, this.pathMeld, this.jrange!.getStartOp(), this.jrange!.getStartVarnode());
      addr = BigInt((spc as any).constructor.addressToByte(addr, (spc as any).getWordSize()));
      addr &= mask;
      addresstable.push(new Address(spc, addr));
      if (loadcounts !== null)
        loadcounts.push(loadpoints!.length);
      notdone = this.jrange!.next();
    }
  }

  findUnnormalized(maxaddsub: number, maxleftright: number, maxext: number): void {
    let i: number, j: number;

    i = this.varnodeIndex;
    this.normalvn = this.pathMeld.getVarnode(i++);
    this.switchvn = this.normalvn;
    this.markModel(true);

    let countaddsub = 0;
    let countext = 0;
    let normop: any = null;
    while (i < this.pathMeld.numCommonVarnode()) {
      if (!this.flowsOnlyToModel(this.switchvn, normop)) break;
      const testvn = this.pathMeld.getVarnode(i);
      if (!(this.switchvn as any).isWritten()) break;
      normop = (this.switchvn as any).getDef();
      for (j = 0; j < (normop as any).numInput(); ++j)
        if ((normop as any).getIn(j) === testvn) break;
      if (j === (normop as any).numInput()) break;
      switch ((normop as any).code()) {
        case OpCode.CPUI_INT_ADD:
        case OpCode.CPUI_INT_SUB:
          countaddsub += 1;
          if (countaddsub > maxaddsub) break;
          if (!(normop as any).getIn(1 - j).isConstant()) break;
          this.switchvn = testvn;
          break;
        case OpCode.CPUI_INT_ZEXT:
        case OpCode.CPUI_INT_SEXT:
          countext += 1;
          if (countext > maxext) break;
          this.switchvn = testvn;
          break;
        default:
          break;
      }
      if (this.switchvn !== testvn) break;
      i += 1;
    }
    this.markModel(false);
  }

  buildLabels(fd: any, addresstable: Address[], label: bigint[], orig: JumpModel): void {
    const origrange = (orig as JumpBasic).getValueRange()!;

    let notdone = origrange.initializeForReading();
    while (notdone) {
      const val = origrange.getValue();
      let needswarning = 0;
      if (origrange.isReversible()) {
        if (!this.jrange!.contains(val))
          needswarning = 1;
        try {
          var switchval = JumpBasic.backup2Switch(fd, val, this.normalvn, this.switchvn);
        } catch (err) {
          switchval = JumpValues.NO_LABEL;
          needswarning = 2;
        }
      } else {
        switchval = JumpValues.NO_LABEL;
      }
      if (needswarning === 1)
        (fd as any).warning("This code block may not be properly labeled as switch case", addresstable[label.length]);
      else if (needswarning === 2)
        (fd as any).warning("Calculation of case label failed", addresstable[label.length]);
      label.push(switchval);

      if (label.length >= addresstable.length) break;
      notdone = origrange.next();
    }

    while (label.length < addresstable.length) {
      (fd as any).warning("Bad switch case", addresstable[label.length]);
      label.push(JumpValues.NO_LABEL);
    }
  }

  foldInNormalization(fd: any, indop: any): any {
    (fd as any).opSetInput(indop, this.switchvn, 0);
    return this.switchvn;
  }

  foldInGuards(fd: any, jump: JumpTable): boolean {
    let change = false;
    for (let i = 0; i < this.selectguards.length; ++i) {
      const cbranch = this.selectguards[i].getBranch();
      if (cbranch === null) continue;
      if ((cbranch as any).isDead()) {
        this.selectguards[i].clear();
        continue;
      }
      if (this.foldInOneGuard(fd, this.selectguards[i], jump))
        change = true;
    }
    return change;
  }

  sanityCheck(fd: any, indop: any, addresstable: Address[], loadpoints: LoadTable[], loadcounts: number[] | null): boolean {
    let i: number;
    let diff: bigint;
    if (addresstable.length === 0) return true;
    const addr = addresstable[0];
    i = 0;
    if (addr.getOffset() !== 0n) {
      for (i = 1; i < addresstable.length; ++i) {
        if (addresstable[i].getOffset() === 0n) break;
        diff = (addr.getOffset() < addresstable[i].getOffset())
          ? (addresstable[i].getOffset() - addr.getOffset())
          : (addr.getOffset() - addresstable[i].getOffset());
        if (diff > 0xffffn) {
          const loadimage = (fd as any).getArch().loader;
          let dataavail = true;
          try {
            (loadimage as any).loadFill(new Uint8Array(4), 4, addresstable[i]);
          } catch (err) {
            dataavail = false;
          }
          if (!dataavail) break;
        }
      }
    }
    if (i === 0) return false;
    if (i !== addresstable.length) {
      addresstable.length = i;
      this.jrange!.truncate(i);
      if (loadcounts !== null) {
        loadpoints.length = loadcounts[i - 1];
      }
    }
    return true;
  }

  clone(jt: JumpTable): JumpModel {
    const res = new JumpBasic(jt);
    res.jrange = this.jrange!.clone() as JumpValuesRange;
    return res;
  }

  clear(): void {
    this.jrange = null;
    this.pathMeld.clear();
    this.selectguards = [];
    this.normalvn = null;
    this.switchvn = null;
  }
}

// =========================================================================
// JumpBasic2
// =========================================================================

/**
 * A basic jump-table model with an added default address path.
 *
 * This model expects two paths to the switch, 1 from a default value, 1 from
 * the other values that hit the switch.
 */
class JumpBasic2 extends JumpBasic {
  private extravn: any;   // Varnode
  private origPathMeld: PathMeld;

  constructor(jt: JumpTable) {
    super(jt);
    this.extravn = null;
    this.origPathMeld = new PathMeld();
  }

  cloneModel(jt: JumpTable): JumpModel {
    const res = new JumpBasic2(jt);
    return res;
  }

  /**
   * Pass in the prior PathMeld calculation.
   */
  initializeStart(pMeld: PathMeld): void {
    if (pMeld.empty()) {
      this.extravn = null;
      return;
    }
    this.extravn = pMeld.getVarnode(pMeld.numCommonVarnode() - 1);
    this.origPathMeld.setFromMeld(pMeld);
  }

  /**
   * Check if the block that defines the normalized switch variable dominates the switch block.
   */
  private checkNormalDominance(): boolean {
    if ((this.normalvn as any).isInput())
      return true;
    let defblock = (this.normalvn as any).getDef().getParent();
    let switchblock = this.pathMeld.getOp(0).getParent();
    while (switchblock !== null) {
      if (switchblock === defblock) return true;
      switchblock = (switchblock as any).getImmedDom();
    }
    return false;
  }

  protected foldInOneGuard(fd: any, guard: GuardRecord, jump: JumpTable): boolean {
    // If we recovered a switch in a loop, the guard is also the loop condition
    // If the guard is just deciding whether or not to use a default switch value,
    // the guard will disappear anyway because the normalization foldin will make all its blocks donothings
    jump.setLastAsDefault();
    guard.clear();
    return true;
  }

  recoverModel(fd: any, indop: any, matchsize: number, maxtablesize: number): boolean {
    let othervn: any = null;
    let copyop: any = null;
    let extravalue: bigint = 0n;
    const joinvn = this.extravn;
    if (joinvn === null) return false;
    if (!(joinvn as any).isWritten()) return false;
    const multiop = (joinvn as any).getDef();
    if ((multiop as any).code() !== OpCode.CPUI_MULTIEQUAL) return false;
    if ((multiop as any).numInput() !== 2) return false;

    let path: number;
    for (path = 0; path < 2; ++path) {
      const vn = (multiop as any).getIn(path);
      if (!(vn as any).isWritten()) continue;
      copyop = (vn as any).getDef();
      if ((copyop as any).code() !== OpCode.CPUI_COPY) continue;
      othervn = (copyop as any).getIn(0);
      if ((othervn as any).isConstant()) {
        extravalue = (othervn as any).getOffset();
        break;
      }
    }
    if (path === 2) return false;

    const rootbl = (multiop as any).getParent().getIn(1 - path);
    const pathout = (multiop as any).getParent().getInRevIndex(1 - path);
    const jdef = new JumpValuesRangeDefault();
    this.jrange = jdef;
    jdef.setExtraValue(extravalue);
    jdef.setDefaultVn(joinvn);
    jdef.setDefaultOp(this.origPathMeld.getOp(this.origPathMeld.numOps() - 1));

    this.findDeterminingVarnodes(multiop, 1 - path);
    this.findNormalized(fd, rootbl, pathout, matchsize, maxtablesize);
    if (this.jrange!.getSize() > BigInt(maxtablesize))
      return false;

    this.pathMeld.append(this.origPathMeld);
    this.varnodeIndex += this.origPathMeld.numCommonVarnode();
    return true;
  }

  findUnnormalized(maxaddsub: number, maxleftright: number, maxext: number): void {
    this.normalvn = this.pathMeld.getVarnode(this.varnodeIndex);
    if (this.checkNormalDominance()) {
      super.findUnnormalized(maxaddsub, maxleftright, maxext);
      return;
    }

    this.switchvn = this.extravn;
    const multiop = (this.extravn as any).getDef();
    if (((multiop as any).getIn(0) === this.normalvn) || ((multiop as any).getIn(1) === this.normalvn)) {
      this.normalvn = this.switchvn;
    } else {
      throw new LowlevelError("Backward normalization not implemented");
    }
  }

  clone(jt: JumpTable): JumpModel {
    const res = new JumpBasic2(jt);
    res.jrange = this.jrange!.clone() as JumpValuesRange;
    return res;
  }

  clear(): void {
    this.extravn = null;
    this.origPathMeld.clear();
    super.clear();
  }
}

// =========================================================================
// JumpBasicOverride
// =========================================================================

/**
 * A basic jump-table model incorporating manual override information.
 *
 * The list of potential target addresses produced by the BRANCHIND is not recovered
 * by this model, but must be provided explicitly via setAddresses().
 */
class JumpBasicOverride extends JumpBasic {
  private adset: Set<string>;          // Use stringified Address as key for dedup
  private adsetAddrs: Map<string, Address>;  // Map from string key to Address
  private values: bigint[];
  private addrtable: Address[];
  private startingvalue: bigint;
  private normaddress: Address;
  private hash: bigint;
  private istrivial: boolean;

  constructor(jt: JumpTable) {
    super(jt);
    this.adset = new Set<string>();
    this.adsetAddrs = new Map<string, Address>();
    this.values = [];
    this.addrtable = [];
    this.startingvalue = 0n;
    this.normaddress = new Address();
    this.hash = 0n;
    this.istrivial = false;
  }

  cloneModel(jt: JumpTable): JumpModel {
    const res = new JumpBasicOverride(jt);
    return res;
  }

  /**
   * Manually set the address table for this model (deduplicates via set).
   */
  setAddresses(adtable: Address[]): void {
    for (let i = 0; i < adtable.length; ++i) {
      const key = adtable[i].toString();
      this.adset.add(key);
      this.adsetAddrs.set(key, adtable[i]);
    }
  }

  /**
   * Set the normalized switch variable.
   */
  setNorm(addr: Address, h: bigint): void {
    this.normaddress = addr;
    this.hash = h;
  }

  /**
   * Set the starting value for the normalized range.
   */
  setStartingValue(val: bigint): void {
    this.startingvalue = val;
  }

  isOverride(): boolean {
    return true;
  }

  getTableSize(): number {
    return this.addrtable.length;
  }

  /**
   * Return the PcodeOp (within the PathMeld set) that takes the given Varnode as input.
   */
  private findStartOp(vn: any): number {
    const ops: any[] = [];
    for (let idx = (vn as any).beginDescend(); idx < (vn as any).endDescend(); ++idx) {
      const op = (vn as any).getDescend(idx);
      (op as any).setMark();
      ops.push(op);
    }
    let res = -1;
    for (let i = 0; i < this.pathMeld.numOps(); ++i) {
      if ((this.pathMeld.getOp(i) as any).isMark()) {
        res = i;
        break;
      }
    }
    for (const op of ops) {
      (op as any).clearMark();
    }
    return res;
  }

  /**
   * Test a given Varnode as a potential normalized switch variable.
   */
  private trialNorm(fd: any, trialvn: any, tolerance: number): number {
    const opi = this.findStartOp(trialvn);
    if (opi < 0) return -1;
    const startop = this.pathMeld.getOp(opi);

    if (this.values.length !== 0)
      return opi;

    const emul = new EmulateFunction(fd);
    const spc = (startop as any).getAddr().getSpace();
    let val = this.startingvalue;
    let addr: bigint;
    let total = 0;
    let miss = 0;
    const alreadyseen = new Set<string>();
    while (total < this.adset.size) {
      try {
        addr = emul.emulatePath(val, this.pathMeld, startop, trialvn);
      } catch (err) {
        addr = 0n;
        miss = tolerance;
      }
      addr = BigInt((spc as any).constructor.addressToByte(addr, (spc as any).getWordSize()));
      const newaddr = new Address(spc, addr);
      const key = newaddr.toString();
      if (this.adset.has(key)) {
        if (!alreadyseen.has(key)) {
          alreadyseen.add(key);
          total += 1;
        }
        this.values.push(val);
        this.addrtable.push(newaddr);
        if (this.values.length > this.adset.size + 100) break;
        miss = 0;
      } else {
        miss += 1;
        if (miss >= tolerance) break;
      }
      val += 1n;
    }
    if (total === this.adset.size)
      return opi;
    this.values = [];
    this.addrtable = [];
    return -1;
  }

  /**
   * Convert this to a trivial model.
   */
  private setupTrivial(): void {
    if (this.addrtable.length === 0) {
      for (const [key, addr] of this.adsetAddrs) {
        this.addrtable.push(addr);
      }
    }
    this.values = [];
    for (let i = 0; i < this.addrtable.length; ++i)
      this.values.push(this.addrtable[i].getOffset());
    this.varnodeIndex = 0;
    this.normalvn = this.pathMeld.getVarnode(0);
    this.istrivial = true;
  }

  /**
   * Find a potential normalized switch variable.
   */
  private findLikelyNorm(): any {
    let res: any = null;
    let op: any;
    let i: number;

    for (i = 0; i < this.pathMeld.numOps(); ++i) {
      op = this.pathMeld.getOp(i);
      if ((op as any).code() === OpCode.CPUI_LOAD) {
        res = this.pathMeld.getOpParent(i);
        break;
      }
    }
    if (res === null) return res;
    i += 1;
    while (i < this.pathMeld.numOps()) {
      op = this.pathMeld.getOp(i);
      if ((op as any).code() === OpCode.CPUI_INT_ADD) {
        res = this.pathMeld.getOpParent(i);
        break;
      }
      ++i;
    }
    i += 1;
    while (i < this.pathMeld.numOps()) {
      op = this.pathMeld.getOp(i);
      if ((op as any).code() === OpCode.CPUI_INT_MULT) {
        res = this.pathMeld.getOpParent(i);
        break;
      }
      ++i;
    }
    return res;
  }

  /**
   * Clear varnodes and ops that are specific to one instance of a function.
   */
  private clearCopySpecific(): void {
    this.selectguards = [];
    this.pathMeld.clear();
    this.normalvn = null;
    this.switchvn = null;
  }

  recoverModel(fd: any, indop: any, matchsize: number, maxtablesize: number): boolean {
    this.clearCopySpecific();
    this.findDeterminingVarnodes(indop, 0);
    if (!this.istrivial) {
      let trialvn: any = null;
      if (this.hash !== 0n) {
        const dyn: any = new (globalThis as any).DynamicHash();
        trialvn = (dyn as any).findVarnode(fd, this.normaddress, this.hash);
      }
      if ((trialvn === null) && (this.values.length === 0 || this.hash === 0n))
        trialvn = this.findLikelyNorm();

      if (trialvn !== null) {
        const opi = this.trialNorm(fd, trialvn, 10);
        if (opi >= 0) {
          this.varnodeIndex = opi;
          this.normalvn = trialvn;
          return true;
        }
      }
    }
    this.setupTrivial();
    return true;
  }

  buildAddresses(fd: any, indop: any, addresstable: Address[], loadpoints: LoadTable[] | null, loadcounts: number[] | null): void {
    // Addresses are already calculated, just copy them out
    addresstable.length = 0;
    for (const addr of this.addrtable) {
      addresstable.push(addr);
    }
  }

  buildLabels(fd: any, addresstable: Address[], label: bigint[], orig: JumpModel): void {
    for (let i = 0; i < this.values.length; ++i) {
      let addr: bigint;
      try {
        addr = JumpBasic.backup2Switch(fd, this.values[i], this.normalvn, this.switchvn);
      } catch (err) {
        addr = JumpValues.NO_LABEL;
      }
      label.push(addr);
      if (label.length >= addresstable.length) break;
    }

    while (label.length < addresstable.length) {
      (fd as any).warning("Bad switch case", addresstable[label.length]);
      label.push(JumpValues.NO_LABEL);
    }
  }

  foldInGuards(fd: any, jump: JumpTable): boolean {
    return false;
  }

  sanityCheck(fd: any, indop: any, addresstable: Address[], loadpoints: LoadTable[], loadcounts: number[] | null): boolean {
    return true;
  }

  clone(jt: JumpTable): JumpModel {
    const res = new JumpBasicOverride(jt);
    res.adset = new Set(this.adset);
    res.adsetAddrs = new Map(this.adsetAddrs);
    res.values = [...this.values];
    res.addrtable = [...this.addrtable];
    res.startingvalue = this.startingvalue;
    res.normaddress = this.normaddress;
    res.hash = this.hash;
    return res;
  }

  clear(): void {
    // adset, startingvalue, normaddress, hash are permanent
    this.values = [];
    this.addrtable = [];
    this.istrivial = false;
  }

  encode(encoder: any): void {
    encoder.openElement(ELEM_BASICOVERRIDE);
    for (const [key, addr] of this.adsetAddrs) {
      encoder.openElement(ELEM_DEST);
      const spc = addr.getSpace();
      const off = addr.getOffset();
      (spc as any).encodeAttributes(encoder, off);
      encoder.closeElement(ELEM_DEST);
    }
    if (this.hash !== 0n) {
      encoder.openElement(ELEM_NORMADDR);
      (this.normaddress.getSpace() as any).encodeAttributes(encoder, this.normaddress.getOffset());
      encoder.closeElement(ELEM_NORMADDR);
      encoder.openElement(ELEM_NORMHASH);
      encoder.writeUnsignedInteger(ATTRIB_CONTENT, this.hash);
      encoder.closeElement(ELEM_NORMHASH);
    }
    if (this.startingvalue !== 0n) {
      encoder.openElement(ELEM_STARTVAL);
      encoder.writeUnsignedInteger(ATTRIB_CONTENT, this.startingvalue);
      encoder.closeElement(ELEM_STARTVAL);
    }
    encoder.closeElement(ELEM_BASICOVERRIDE);
  }

  decode(decoder: any): void {
    const elemId = decoder.openElement(ELEM_BASICOVERRIDE);
    for (;;) {
      const subId = decoder.openElement();
      if (subId === 0) break;
      if (subId === ELEM_DEST.getId()) {
        const vData = new VarnodeData();
        vData.decodeFromAttributes(decoder);
        const rawAddr = vData.getAddr();
        const addr = new Address(rawAddr.getSpace() as any, rawAddr.getOffset());
        const key = addr.toString();
        this.adset.add(key);
        this.adsetAddrs.set(key, addr);
      } else if (subId === ELEM_NORMADDR.getId()) {
        const vData = new VarnodeData();
        vData.decodeFromAttributes(decoder);
        const rawAddr = vData.getAddr();
        this.normaddress = new Address(rawAddr.getSpace() as any, rawAddr.getOffset());
      } else if (subId === ELEM_NORMHASH.getId()) {
        this.hash = decoder.readUnsignedInteger(ATTRIB_CONTENT);
      } else if (subId === ELEM_STARTVAL.getId()) {
        this.startingvalue = decoder.readUnsignedInteger(ATTRIB_CONTENT);
      }
      decoder.closeElement(subId);
    }
    decoder.closeElement(elemId);
    if (this.adset.size === 0)
      throw new LowlevelError("Empty jumptable override");
  }
}

// =========================================================================
// JumpAssisted
// =========================================================================

/**
 * A jump-table model assisted by pseudo-op directives in the code.
 *
 * This model looks for a special "jumpassist" pseudo-op near the branch site,
 * which contains p-code models describing how to parse a jump-table for case
 * labels and addresses.
 */
class JumpAssisted extends JumpModel {
  private assistOp: any;     // PcodeOp
  private userop: any;       // JumpAssistOp
  private sizeIndices: number;
  private switchvn: any;     // Varnode

  constructor(jt: JumpTable) {
    super(jt);
    this.assistOp = null;
    this.userop = null;
    this.sizeIndices = 0;
    this.switchvn = null;
  }

  cloneModel(jt: JumpTable): JumpModel {
    const res = new JumpAssisted(jt);
    return res;
  }

  isOverride(): boolean {
    return false;
  }

  getTableSize(): number {
    return this.sizeIndices + 1;
  }

  recoverModel(fd: any, indop: any, matchsize: number, maxtablesize: number): boolean {
    const addrVn = (indop as any).getIn(0);
    if (!(addrVn as any).isWritten()) return false;
    this.assistOp = (addrVn as any).getDef();
    if (this.assistOp === null) return false;
    if ((this.assistOp as any).code() !== OpCode.CPUI_CALLOTHER) return false;
    if ((this.assistOp as any).numInput() < 3) return false;
    const index = Number((this.assistOp as any).getIn(0).getOffset());
    const tmpOp = (fd as any).getArch().userops.getOp(index);
    if ((tmpOp as any).getType() !== 7) // UserPcodeOp::jumpassist
      return false;
    this.userop = tmpOp;

    this.switchvn = (this.assistOp as any).getIn(1);
    for (let i = 2; i < (this.assistOp as any).numInput(); ++i)
      if (!(this.assistOp as any).getIn(i).isConstant())
        return false;
    if ((this.userop as any).getCalcSize() === -1)
      this.sizeIndices = Number((this.assistOp as any).getIn(2).getOffset());
    else {
      const pcodeScript = (fd as any).getArch().pcodeinjectlib.getPayload((this.userop as any).getCalcSize());
      const inputs: bigint[] = [];
      const numInputs = (this.assistOp as any).numInput() - 1;
      if ((pcodeScript as any).sizeInput() !== numInputs)
        throw new LowlevelError((this.userop as any).getName() + ": <size_pcode> has wrong number of parameters");
      for (let i = 0; i < numInputs; ++i)
        inputs.push((this.assistOp as any).getIn(i + 1).getOffset());
      this.sizeIndices = Number((pcodeScript as any).evaluate(inputs));
    }
    if (matchsize !== 0 && matchsize - 1 !== this.sizeIndices)
      return false;
    if (this.sizeIndices > maxtablesize)
      return false;

    return true;
  }

  buildAddresses(fd: any, indop: any, addresstable: Address[], loadpoints: LoadTable[] | null, loadcounts: number[] | null): void {
    if ((this.userop as any).getIndex2Addr() === -1)
      throw new LowlevelError("Final index2addr calculation outside of jumpassist");
    const pcodeScript = (fd as any).getArch().pcodeinjectlib.getPayload((this.userop as any).getIndex2Addr());
    addresstable.length = 0;

    const spc = (indop as any).getAddr().getSpace();
    const inputs: bigint[] = [];
    const numInputs = (this.assistOp as any).numInput() - 1;
    if ((pcodeScript as any).sizeInput() !== numInputs)
      throw new LowlevelError((this.userop as any).getName() + ": <addr_pcode> has wrong number of parameters");
    for (let i = 0; i < numInputs; ++i)
      inputs.push((this.assistOp as any).getIn(i + 1).getOffset());

    let mask: bigint = 0xFFFFFFFFFFFFFFFFn;
    const bit: number = (fd as any).getArch().funcptr_align;
    if (bit !== 0) {
      mask = (mask >> BigInt(bit)) << BigInt(bit);
    }
    for (let index = 0; index < this.sizeIndices; ++index) {
      inputs[0] = BigInt(index);
      let output: bigint = (pcodeScript as any).evaluate(inputs);
      output &= mask;
      addresstable.push(new Address(spc, output));
    }
    const defaultScript = (fd as any).getArch().pcodeinjectlib.getPayload((this.userop as any).getDefaultAddr());
    if ((defaultScript as any).sizeInput() !== numInputs)
      throw new LowlevelError((this.userop as any).getName() + ": <default_pcode> has wrong number of parameters");
    inputs[0] = 0n;
    const defaultAddress: bigint = (defaultScript as any).evaluate(inputs);
    addresstable.push(new Address(spc, defaultAddress));
  }

  findUnnormalized(maxaddsub: number, maxleftright: number, maxext: number): void {
    // Nothing to do for assisted model
  }

  buildLabels(fd: any, addresstable: Address[], label: bigint[], orig: JumpModel): void {
    if ((orig as JumpAssisted).sizeIndices !== this.sizeIndices)
      throw new LowlevelError("JumpAssisted table size changed during recovery");
    if ((this.userop as any).getIndex2Case() === -1) {
      for (let i = 0; i < this.sizeIndices; ++i)
        label.push(BigInt(i));
    } else {
      const pcodeScript = (fd as any).getArch().pcodeinjectlib.getPayload((this.userop as any).getIndex2Case());
      const inputs: bigint[] = [];
      const numInputs = (this.assistOp as any).numInput() - 1;
      if (numInputs !== (pcodeScript as any).sizeInput())
        throw new LowlevelError((this.userop as any).getName() + ": <case_pcode> has wrong number of parameters");
      for (let i = 0; i < numInputs; ++i)
        inputs.push((this.assistOp as any).getIn(i + 1).getOffset());

      for (let index = 0; index < this.sizeIndices; ++index) {
        inputs[0] = BigInt(index);
        const output: bigint = (pcodeScript as any).evaluate(inputs);
        label.push(output);
      }
    }
    label.push(JumpValues.NO_LABEL);
  }

  foldInNormalization(fd: any, indop: any): any {
    // Replace all outputs of jumpassist op with switchvn (including BRANCHIND)
    const outvn = (this.assistOp as any).getOut();
    // Collect descendants first since we are modifying the list during iteration
    const descendants: any[] = [];
    for (let idx = (outvn as any).beginDescend(); idx < (outvn as any).endDescend(); ++idx) {
      descendants.push((outvn as any).getDescend(idx));
    }
    for (const op of descendants) {
      (fd as any).opSetInput(op, this.switchvn, 0);
    }
    (fd as any).opDestroy(this.assistOp);
    return this.switchvn;
  }

  foldInGuards(fd: any, jump: JumpTable): boolean {
    const origVal = jump.getDefaultBlock();
    jump.setLastAsDefault();
    return (origVal !== jump.getDefaultBlock());
  }

  sanityCheck(fd: any, indop: any, addresstable: Address[], loadpoints: LoadTable[], loadcounts: number[] | null): boolean {
    return true;
  }

  clone(jt: JumpTable): JumpModel {
    const res = new JumpAssisted(jt);
    res.userop = this.userop;
    res.sizeIndices = this.sizeIndices;
    return res;
  }

  clear(): void {
    this.assistOp = null;
    this.switchvn = null;
  }
}

// =========================================================================
// JumpTable
// =========================================================================

/**
 * An address table index and its corresponding out-edge.
 */
class IndexPair {
  blockPosition: number;
  addressIndex: number;

  constructor(pos: number, index: number) {
    this.blockPosition = pos;
    this.addressIndex = index;
  }

  lessThan(op2: IndexPair): boolean {
    if (this.blockPosition !== op2.blockPosition)
      return (this.blockPosition < op2.blockPosition);
    return (this.addressIndex < op2.addressIndex);
  }

  static compareByPosition(op1: IndexPair, op2: IndexPair): boolean {
    return (op1.blockPosition < op2.blockPosition);
  }
}

/**
 * Recovery status for a specific JumpTable.
 */
const enum RecoveryMode {
  success = 0,
  fail_normal = 1,
  fail_thunk = 2,
  fail_return = 3,
  fail_callother = 4,
}

/**
 * A map from values to control-flow targets within a function.
 *
 * A JumpTable is attached to a specific CPUI_BRANCHIND and encapsulates all
 * the information necessary to model the indirect jump as a switch statement.
 */
export class JumpTable {
  private glb: any;                    // Architecture
  private jmodel: JumpModel | null;
  private origmodel: JumpModel | null;
  private addresstable: Address[];
  private block2addr: IndexPair[];
  private label: bigint[];
  private loadpoints: LoadTable[];
  private opaddress: Address;
  private indirect: any;               // PcodeOp
  private switchVarConsume: bigint;
  private _defaultBlock: number;
  private lastBlock: number;
  private _maxaddsub: number;
  private _maxleftright: number;
  private _maxext: number;
  private partialTable: boolean;
  private collectloads: boolean;
  private _defaultIsFolded: boolean;

  constructor(g: any, ad?: Address) {
    this.glb = g;
    this.opaddress = ad ?? new Address();
    this.jmodel = null;
    this.origmodel = null;
    this.indirect = null;
    this.switchVarConsume = 0xFFFFFFFFFFFFFFFFn;
    this._defaultBlock = -1;
    this.lastBlock = -1;
    this._maxaddsub = 1;
    this._maxleftright = 1;
    this._maxext = 1;
    this.partialTable = false;
    this.collectloads = false;
    this._defaultIsFolded = false;
    this.addresstable = [];
    this.block2addr = [];
    this.label = [];
    this.loadpoints = [];
  }

  /**
   * Copy constructor (partial clone of another jump-table).
   */
  static copyFrom(op2: JumpTable): JumpTable {
    const res = new JumpTable(op2.glb);
    res.opaddress = op2.opaddress;
    res.indirect = null;
    res.switchVarConsume = 0xFFFFFFFFFFFFFFFFn;
    res._defaultBlock = -1;
    res.lastBlock = op2.lastBlock;
    res._maxaddsub = op2._maxaddsub;
    res._maxleftright = op2._maxleftright;
    res._maxext = op2._maxext;
    res.partialTable = op2.partialTable;
    res.collectloads = op2.collectloads;
    res._defaultIsFolded = false;
    res.addresstable = [...op2.addresstable];
    res.loadpoints = [...op2.loadpoints];
    if (op2.jmodel !== null)
      res.jmodel = op2.jmodel.cloneModel(res);
    return res;
  }

  isRecovered(): boolean {
    return this.addresstable.length !== 0;
  }

  isLabelled(): boolean {
    return this.label.length !== 0;
  }

  isOverride(): boolean {
    if (this.jmodel === null) return false;
    return this.jmodel.isOverride();
  }

  isPartial(): boolean {
    return this.partialTable;
  }

  markComplete(): void {
    this.partialTable = false;
  }

  /**
   * Override the address table with pre-recovered addresses.
   * This is a TS-specific workaround for cases where the partial function
   * analysis cannot recover the full switch table. The model and other
   * state are preserved; only the address table is replaced.
   */
  overrideAddresses(addrs: Address[]): void {
    this.addresstable = [...addrs];
    this.partialTable = false;
  }

  numEntries(): number {
    return this.addresstable.length;
  }

  getSwitchVarConsume(): bigint {
    return this.switchVarConsume;
  }

  getDefaultBlock(): number {
    return this._defaultBlock;
  }

  getOpAddress(): Address {
    return this.opaddress;
  }

  getIndirectOp(): any {
    return this.indirect;
  }

  setIndirectOp(ind: any): void {
    this.opaddress = (ind as any).getAddr();
    this.indirect = ind;
  }

  setNormMax(maddsub: number, mleftright: number, mext: number): void {
    this._maxaddsub = maddsub;
    this._maxleftright = mleftright;
    this._maxext = mext;
  }

  /**
   * Force manual override information on this jump-table.
   */
  setOverride(addrtable: Address[], naddr: Address, h: bigint, sv: bigint): void {
    this.jmodel = null;

    const override = new JumpBasicOverride(this);
    this.jmodel = override;
    override.setAddresses(addrtable);
    override.setNorm(naddr, h);
    override.setStartingValue(sv);
  }

  /**
   * Return the number of address table entries that target the given basic-block.
   */
  numIndicesByBlock(bl: any): number {
    const pos = this.block2Position(bl);
    let count = 0;
    for (const pair of this.block2addr) {
      if (pair.blockPosition === pos) count++;
    }
    return count;
  }

  /**
   * Get the index of the i-th address table entry that corresponds to the given basic-block.
   */
  getIndexByBlock(bl: any, i: number): number {
    const pos = this.block2Position(bl);
    let count = 0;
    for (const pair of this.block2addr) {
      if (pair.blockPosition === pos) {
        if (count === i)
          return pair.addressIndex;
        count += 1;
      }
    }
    throw new LowlevelError("Could not get jumptable index for block");
  }

  getAddressByIndex(i: number): Address {
    return this.addresstable[i];
  }

  setLastAsDefault(): void {
    this._defaultBlock = this.lastBlock;
  }

  setDefaultBlock(bl: number): void {
    this._defaultBlock = bl;
  }

  setLoadCollect(val: boolean): void {
    this.collectloads = val;
  }

  setFoldedDefault(): void {
    this._defaultIsFolded = true;
  }

  hasFoldedDefault(): boolean {
    return this._defaultIsFolded;
  }

  /**
   * Force a given basic-block to be a switch destination.
   */
  addBlockToSwitch(bl: any, lab: bigint): void {
    this.addresstable.push((bl as any).getStart());
    this.lastBlock = (this.indirect as any).getParent().sizeOut();
    this.block2addr.push(new IndexPair(this.lastBlock, this.addresstable.length - 1));
    this.label.push(lab);
  }

  /**
   * Convert absolute addresses to block indices.
   */
  switchOver(flow: any): void {
    this.block2addr = [];
    const parent = (this.indirect as any).getParent();

    for (let i = 0; i < this.addresstable.length; ++i) {
      const addr = this.addresstable[i];
      let op: any;
      try {
        op = (flow as any).target(addr);
      } catch (e) {
        throw new LowlevelError("Jumptable destination not found");
      }
      if (op === null || op === undefined) {
        throw new LowlevelError("Jumptable destination not found");
      }
      const tmpbl = op.getParent();
      let pos: number;
      for (pos = 0; pos < (parent as any).sizeOut(); ++pos)
        if ((parent as any).getOut(pos) === tmpbl) break;
      if (pos === (parent as any).sizeOut())
        throw new LowlevelError("Jumptable destination not linked");
      this.block2addr.push(new IndexPair(pos, i));
    }
    if (this.block2addr.length === 0)
      throw new LowlevelError("No entries in jumptable address-to-block map");
    this.lastBlock = this.block2addr[this.block2addr.length - 1].blockPosition;
    this.block2addr.sort((a, b) => {
      if (a.blockPosition !== b.blockPosition) return a.blockPosition - b.blockPosition;
      return a.addressIndex - b.addressIndex;
    });

    this._defaultBlock = -1;
    let maxcount = 1;
    let idx = 0;
    while (idx < this.block2addr.length) {
      const curPos = this.block2addr[idx].blockPosition;
      let nextIdx = idx;
      let count = 0;
      while (nextIdx < this.block2addr.length && this.block2addr[nextIdx].blockPosition === curPos) {
        count += 1;
        nextIdx += 1;
      }
      idx = nextIdx;
      if (count > maxcount) {
        maxcount = count;
        this._defaultBlock = curPos;
      }
    }
  }

  getLabelByIndex(index: number): bigint {
    return this.label[index];
  }

  /**
   * Hide the normalization code for the switch.
   */
  foldInNormalization(fd: any): void {
    const switchvn = this.jmodel!.foldInNormalization(fd, this.indirect);
    if (switchvn !== null) {
      this.switchVarConsume = minimalmask((switchvn as any).getNZMask());
      if (this.switchVarConsume >= calc_mask((switchvn as any).getSize())) {
        if ((switchvn as any).isWritten()) {
          const op = (switchvn as any).getDef();
          if ((op as any).code() === OpCode.CPUI_INT_SEXT) {
            this.switchVarConsume = calc_mask((op as any).getIn(0).getSize());
          }
        }
      }
    }
  }

  /**
   * Hide any guard code for this switch.
   */
  foldInGuards(fd: any): boolean {
    return this.jmodel!.foldInGuards(fd, this);
  }

  // -- Private helpers --

  private saveModel(): void {
    this.origmodel = this.jmodel;
    this.jmodel = null;
  }

  private restoreSavedModel(): void {
    this.jmodel = this.origmodel;
    this.origmodel = null;
  }

  private clearSavedModel(): void {
    this.origmodel = null;
  }

  /**
   * Attempt recovery of the jump-table model.
   */
  private recoverModel(fd: any): void {
    if (this.jmodel !== null) {
      if (this.jmodel.isOverride()) {
        this.jmodel.recoverModel(fd, this.indirect, 0, this.glb.max_jumptable_size);
        return;
      }
      // Old attempt, remove
    }
    const vn = (this.indirect as any).getIn(0);
    if ((vn as any).isWritten()) {
      const op = (vn as any).getDef();
      if ((op as any).code() === OpCode.CPUI_CALLOTHER) {
        const jassisted = new JumpAssisted(this);
        this.jmodel = jassisted;
        if (this.jmodel.recoverModel(fd, this.indirect, this.addresstable.length, this.glb.max_jumptable_size))
          return;
      }
    }
    const jbasic = new JumpBasic(this);
    this.jmodel = jbasic;
    if (this.jmodel.recoverModel(fd, this.indirect, this.addresstable.length, this.glb.max_jumptable_size))
      return;
    this.jmodel = new JumpBasic2(this);
    (this.jmodel as JumpBasic2).initializeStart(jbasic.getPathMeld());
    if (this.jmodel.recoverModel(fd, this.indirect, this.addresstable.length, this.glb.max_jumptable_size))
      return;
    this.jmodel = null;
  }

  /**
   * Make exactly one case for each output edge of the switch block.
   */
  private trivialSwitchOver(): void {
    this.block2addr = [];
    const parent = (this.indirect as any).getParent();

    if ((parent as any).sizeOut() !== this.addresstable.length)
      throw new LowlevelError("Trivial addresstable and switch block size do not match");
    for (let i = 0; i < (parent as any).sizeOut(); ++i)
      this.block2addr.push(new IndexPair(i, i));
    this.lastBlock = (parent as any).sizeOut() - 1;
    this._defaultBlock = -1;
  }

  /**
   * Perform sanity check on recovered address targets.
   */
  private sanityCheck(fd: any, loadcounts: number[] | null): void {
    if (this.jmodel!.isOverride())
      return;
    const sz = this.addresstable.length;

    if (!JumpTable.isReachable(this.indirect))
      this.partialTable = true;
    if (this.addresstable.length === 1) {
      let isthunk = false;
      const addr = this.addresstable[0];
      if (addr.getOffset() === 0n)
        isthunk = true;
      else {
        const addr2 = (this.indirect as any).getAddr();
        const diff = (addr.getOffset() < addr2.getOffset())
          ? (addr2.getOffset() - addr.getOffset())
          : (addr.getOffset() - addr2.getOffset());
        if (diff > 0xffffn)
          isthunk = true;
      }
      if (isthunk) {
        throw new JumptableThunkError("Likely thunk");
      }
    }
    if (!this.jmodel!.sanityCheck(fd, this.indirect, this.addresstable, this.loadpoints, loadcounts)) {
      throw new LowlevelError("Jumptable at " + this.opaddress.toString() + " did not pass sanity check.");
    }
    if (sz !== this.addresstable.length)
      (fd as any).warning("Sanity check requires truncation of jumptable", this.opaddress);
  }

  /**
   * Convert a basic-block to an out-edge index from the switch.
   */
  private block2Position(bl: any): number {
    const parent = (this.indirect as any).getParent();
    let position: number;
    for (position = 0; position < (bl as any).sizeIn(); ++position)
      if ((bl as any).getIn(position) === parent) break;
    if (position === (bl as any).sizeIn())
      throw new LowlevelError("Requested block, not in jumptable");
    return (bl as any).getInRevIndex(position);
  }

  /**
   * Check if the given PcodeOp still seems reachable in its function.
   */
  static isReachable(op: any): boolean {
    let parent = (op as any).getParent();

    for (let i = 0; i < 2; ++i) {
      if ((parent as any).sizeIn() !== 1) return true;
      const bl = (parent as any).getIn(0);
      if ((bl as any).sizeOut() !== 2) continue;
      const cbranch = (bl as any).lastOp();
      if (cbranch === null || (cbranch as any).code() !== OpCode.CPUI_CBRANCH)
        continue;
      const vn = (cbranch as any).getIn(1);
      if (!(vn as any).isConstant()) continue;
      let trueslot = (cbranch as any).isBooleanFlip() ? 0 : 1;
      if ((vn as any).getOffset() === 0n)
        trueslot = 1 - trueslot;
      if ((bl as any).getOut(trueslot) !== parent)
        return false;
      parent = bl;
    }
    return true;
  }

  // -- Public high-level methods --

  /**
   * Recover the raw jump-table addresses (the address table).
   */
  recoverAddresses(fd: any): void {
    this.recoverModel(fd);
    if (this.jmodel === null) {
      throw new LowlevelError("Could not recover jumptable at " + this.opaddress.toString() + ". Too many branches");
    }
    if (this.jmodel.getTableSize() === 0) {
      throw new LowlevelError("Jumptable with 0 entries at " + this.opaddress.toString());
    }
    if (this.collectloads) {
      const loadcounts: number[] = [];
      this.jmodel.buildAddresses(fd, this.indirect, this.addresstable, this.loadpoints, loadcounts);
      this.sanityCheck(fd, loadcounts);
      LoadTable.collapseTable(this.loadpoints);
    } else {
      this.jmodel.buildAddresses(fd, this.indirect, this.addresstable, null, null);
      this.sanityCheck(fd, null);
    }
  }

  /**
   * Recover jump-table addresses keeping track of a possible previous stage.
   */
  recoverMultistage(fd: any): void {
    this.saveModel();

    const oldaddresstable = [...this.addresstable];
    this.addresstable = [];
    this.loadpoints = [];
    try {
      this.recoverAddresses(fd);
    } catch (err) {
      this.restoreSavedModel();
      this.addresstable = oldaddresstable;
      (fd as any).warning("Second-stage recovery error", (this.indirect as any).getAddr());
    }
    this.partialTable = false;
    this.clearSavedModel();
  }

  /**
   * Try to match JumpTable model to the existing function.
   */
  matchModel(fd: any): void {
    if (!this.isRecovered())
      throw new LowlevelError("Trying to recover jumptable labels without addresses");

    if (this.jmodel !== null) {
      if (!this.jmodel.isOverride())
        this.saveModel();
      else {
        this.clearSavedModel();
        (fd as any).warning("Switch is manually overridden", this.opaddress);
      }
    }
    this.recoverModel(fd);
    if (this.jmodel !== null && this.jmodel.getTableSize() !== this.addresstable.length) {
      if ((this.addresstable.length === 1) && (this.jmodel.getTableSize() > 1)) {
        // The jumptable was not fully recovered during flow analysis, try to issue a restart
        (fd as any).getOverride().insertMultistageJump(this.opaddress);
        (fd as any).setRestartPending(true);
        return;
      }
      (fd as any).warning("Could not find normalized switch variable to match jumptable", this.opaddress);
    }
  }

  /**
   * Recover the case labels for this jump-table.
   */
  recoverLabels(fd: any): void {
    if (this.jmodel !== null) {
      if (this.origmodel === null || this.origmodel.getTableSize() === 0) {
        this.jmodel.findUnnormalized(this._maxaddsub, this._maxleftright, this._maxext);
        this.jmodel.buildLabels(fd, this.addresstable, this.label, this.jmodel);
      } else {
        this.jmodel.findUnnormalized(this._maxaddsub, this._maxleftright, this._maxext);
        this.jmodel.buildLabels(fd, this.addresstable, this.label, this.origmodel!);
      }
    } else {
      this.jmodel = new JumpModelTrivial(this);
      this.jmodel.recoverModel(fd, this.indirect, this.addresstable.length, this.glb.max_jumptable_size);
      this.jmodel.buildAddresses(fd, this.indirect, this.addresstable, null, null);
      this.trivialSwitchOver();
      this.jmodel.buildLabels(fd, this.addresstable, this.label, this.origmodel!);
    }
    this.clearSavedModel();
  }

  /**
   * Check if this jump-table requires an additional recovery stage.
   */
  checkForMultistage(fd: any): boolean {
    if (this.addresstable.length !== 1) return false;
    if (this.partialTable) return false;
    if (this.indirect === null) return false;

    if ((fd as any).getOverride().queryMultistageJumptable((this.indirect as any).getAddr())) {
      this.partialTable = true;
      return true;
    }
    return false;
  }

  /**
   * Clear instance specific data for this jump-table.
   */
  clear(): void {
    this.clearSavedModel();
    if (this.jmodel!.isOverride())
      this.jmodel!.clear();
    else {
      this.jmodel = null;
    }
    this.addresstable = [];
    this.block2addr = [];
    this.lastBlock = -1;
    this.label = [];
    this.loadpoints = [];
    this.indirect = null;
    this.switchVarConsume = 0xFFFFFFFFFFFFFFFFn;
    this._defaultBlock = -1;
    this.partialTable = false;
  }

  /**
   * Encode this jump-table as a <jumptable> element.
   */
  encode(encoder: any): void {
    if (!this.isRecovered())
      throw new LowlevelError("Trying to save unrecovered jumptable");

    encoder.openElement(ELEM_JUMPTABLE);
    (this.opaddress as any).encode(encoder);
    for (let i = 0; i < this.addresstable.length; ++i) {
      encoder.openElement(ELEM_DEST);
      const spc = this.addresstable[i].getSpace();
      const off = this.addresstable[i].getOffset();
      if (spc !== null)
        (spc as any).encodeAttributes(encoder, off);
      if (i < this.label.length) {
        if (this.label[i] !== JumpValues.NO_LABEL)
          encoder.writeUnsignedInteger(ATTRIB_LABEL, this.label[i]);
      }
      encoder.closeElement(ELEM_DEST);
    }
    if (this.loadpoints.length !== 0) {
      for (let i = 0; i < this.loadpoints.length; ++i)
        this.loadpoints[i].encode(encoder);
    }
    if ((this.jmodel !== null) && (this.jmodel.isOverride()))
      this.jmodel.encode(encoder);
    encoder.closeElement(ELEM_JUMPTABLE);
  }

  /**
   * Decode this jump-table from a <jumptable> element.
   */
  decode(decoder: any): void {
    const elemId = decoder.openElement(ELEM_JUMPTABLE);
    this.opaddress = (Address as any).decode(decoder);
    let missedlabel = false;
    for (;;) {
      const subId = decoder.peekElement();
      if (subId === 0) break;
      if (subId === ELEM_DEST.getId()) {
        decoder.openElement();
        let foundlabel = false;
        for (;;) {
          const attribId = decoder.getNextAttributeId();
          if (attribId === 0) break;
          if (attribId === ATTRIB_LABEL.getId()) {
            if (missedlabel)
              throw new LowlevelError("Jumptable entries are missing labels");
            const lab: bigint = decoder.readUnsignedInteger();
            this.label.push(lab);
            foundlabel = true;
            break;
          }
        }
        if (!foundlabel)
          missedlabel = true;
        this.addresstable.push((Address as any).decode(decoder));
      } else if (subId === ELEM_LOADTABLE.getId()) {
        const lt = new LoadTable();
        lt.decode(decoder);
        this.loadpoints.push(lt);
      } else if (subId === ELEM_BASICOVERRIDE.getId()) {
        if (this.jmodel !== null)
          throw new LowlevelError("Duplicate jumptable override specs");
        this.jmodel = new JumpBasicOverride(this);
        this.jmodel.decode(decoder);
      }
    }
    decoder.closeElement(elemId);

    if (this.label.length !== 0) {
      while (this.label.length < this.addresstable.length)
        this.label.push(JumpValues.NO_LABEL);
    }
  }
}
