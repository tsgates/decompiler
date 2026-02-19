/**
 * @file dynamic.ts
 * @description Utilities for making references to dynamic variables: defined as
 * locations and constants that can only be identified by their context within the data-flow graph.
 *
 * Translated from Ghidra's dynamic.hh / dynamic.cc
 */

import { Address, SeqNum } from '../core/address.js';
import { OpCode } from '../core/opcodes.js';
import { crc_update } from './crc32.js';
import { Varnode } from './varnode.js';
import { PcodeOp } from './op.js';

// ---------------------------------------------------------------------------
// Forward type declarations for types from not-yet-written modules
// ---------------------------------------------------------------------------

type Funcdata = any;

// ---------------------------------------------------------------------------
// ToOpEdge
// ---------------------------------------------------------------------------

/**
 * An edge between a Varnode and a PcodeOp.
 *
 * A DynamicHash is defined on a sub-graph of the data-flow, and this defines an edge
 * in the sub-graph.  The edge can either be from an input Varnode to the PcodeOp
 * that reads it, or from a PcodeOp to the Varnode it defines.
 */
export class ToOpEdge {
  /** The PcodeOp defining the edge */
  private op: PcodeOp;
  /** Slot containing the input Varnode or -1 for the p-code op output */
  private slot: number;

  constructor(o: PcodeOp, s: number) {
    this.op = o;
    this.slot = s;
  }

  /** Get the PcodeOp defining the edge */
  getOp(): PcodeOp { return this.op; }

  /** Get the slot of the starting Varnode */
  getSlot(): number { return this.slot; }

  /**
   * Compare two edges based on PcodeOp.
   * These edges are sorted to provide consistency to the hash.
   * The sort is based on the PcodeOp sequence number first, then the Varnode slot.
   * @param op2 is the edge to compare this to
   * @return true if this should be ordered before the other edge
   */
  lessThan(op2: ToOpEdge): boolean {
    const addr1: Address = this.op.getSeqNum().getAddr();
    const addr2: Address = op2.op.getSeqNum().getAddr();
    if (!addr1.equals(addr2))
      return addr1.lessThan(addr2);
    const ord1: number = this.op.getSeqNum().getOrder();
    const ord2: number = op2.op.getSeqNum().getOrder();
    if (ord1 !== ord2)
      return ord1 < ord2;
    return this.slot < op2.slot;
  }

  /**
   * Hash this edge into an accumulator.
   *
   * The hash accumulates:
   *   - the Varnode slot
   *   - the address of the PcodeOp
   *   - the op-code of the PcodeOp
   *
   * The op-codes are translated so that the hash is invariant under
   * common variants.
   * @param reg is the incoming hash accumulator value
   * @return the accumulator value with this edge folded in
   */
  hash(reg: number): number {
    reg = crc_update(reg, this.slot);
    reg = crc_update(reg, DynamicHash.transtable[this.op.code()]);
    let val: bigint = this.op.getSeqNum().getAddr().getOffset();
    const sz: number = this.op.getSeqNum().getAddr().getAddrSize();
    for (let i = 0; i < sz; ++i) {
      reg = crc_update(reg, Number(val & 0xFFn)); // Hash in the address
      val >>= 8n;
    }
    return reg;
  }
}

// ---------------------------------------------------------------------------
// DynamicHash
// ---------------------------------------------------------------------------

/**
 * A hash utility to uniquely identify a temporary Varnode in data-flow.
 *
 * Most Varnodes can be identified within the data-flow graph by their storage address
 * and the address of the PcodeOp that defines them.  For temporary registers,
 * this does not work because the storage address is ephemeral. This class allows
 * Varnodes like temporary registers (and constants) to be robustly identified
 * by hashing details of the local data-flow.
 *
 * This class, when presented a Varnode via calcHash(), calculates a hash (getHash())
 * and an address (getAddress()) of the PcodeOp most closely associated with the Varnode,
 * either the defining op or the op directly reading the Varnode.
 * There are actually four hash variants that can be calculated, labeled 0, 1, 2, or 3,
 * which incrementally hash in a larger portion of data-flow.  The method uniqueHash() selects
 * the simplest variant that causes the hash to be unique for the Varnode, among all
 * the Varnodes that share the same address.
 *
 * The variant index is encoded in the hash, so the hash and the address are enough information
 * to uniquely identify the Varnode. This is what is stored in the symbol table for
 * a dynamic Symbol.
 */
export class DynamicHash {
  /** Number of Varnodes processed in the markvn list so far */
  private vnproc: number = 0;
  /** Number of PcodeOps processed in the markop list so far */
  private opproc: number = 0;
  /** Number of edges processed in the opedge list */
  private opedgeproc: number = 0;

  /** List of PcodeOps in the sub-graph being hashed */
  private markop: PcodeOp[] = [];
  /** List of Varnodes in the sub-graph being hashed */
  private markvn: Varnode[] = [];
  /** A staging area for Varnodes before formally adding to the sub-graph */
  private vnedge: Varnode[] = [];
  /** The edges in the sub-graph */
  private opedge: ToOpEdge[] = [];

  /** Address most closely associated with variable */
  private addrresult: Address = new Address();
  /** The calculated hash value */
  private hash: bigint = 0n;

  /**
   * Translation of op-codes to hash values.
   * Table for how to hash opcodes, lumps certain operators (i.e. ADD SUB PTRADD PTRSUB)
   * into one hash. Zero indicates the operator should be skipped.
   */
  static readonly transtable: number[] = [
    0,
    OpCode.CPUI_COPY, OpCode.CPUI_LOAD, OpCode.CPUI_STORE, OpCode.CPUI_BRANCH, OpCode.CPUI_CBRANCH, OpCode.CPUI_BRANCHIND,

    OpCode.CPUI_CALL, OpCode.CPUI_CALLIND, OpCode.CPUI_CALLOTHER, OpCode.CPUI_RETURN,

    OpCode.CPUI_INT_EQUAL, OpCode.CPUI_INT_EQUAL,         // NOT_EQUAL hashes same as EQUAL
    OpCode.CPUI_INT_SLESS, OpCode.CPUI_INT_SLESS,         // SLESSEQUAL hashes same as SLESS
    OpCode.CPUI_INT_LESS, OpCode.CPUI_INT_LESS,           // LESSEQUAL hashes same as LESS

    OpCode.CPUI_INT_ZEXT, OpCode.CPUI_INT_SEXT,
    OpCode.CPUI_INT_ADD, OpCode.CPUI_INT_ADD,             // SUB hashes same as ADD
    OpCode.CPUI_INT_CARRY, OpCode.CPUI_INT_SCARRY, OpCode.CPUI_INT_SBORROW,
    OpCode.CPUI_INT_2COMP, OpCode.CPUI_INT_NEGATE,

    OpCode.CPUI_INT_XOR, OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR, OpCode.CPUI_INT_MULT, // LEFT hashes same as MULT
    OpCode.CPUI_INT_RIGHT, OpCode.CPUI_INT_SRIGHT,
    OpCode.CPUI_INT_MULT, OpCode.CPUI_INT_DIV, OpCode.CPUI_INT_SDIV, OpCode.CPUI_INT_REM, OpCode.CPUI_INT_SREM,

    OpCode.CPUI_BOOL_NEGATE, OpCode.CPUI_BOOL_XOR, OpCode.CPUI_BOOL_AND, OpCode.CPUI_BOOL_OR,

    OpCode.CPUI_FLOAT_EQUAL, OpCode.CPUI_FLOAT_EQUAL,     // NOTEQUAL hashes same as EQUAL
    OpCode.CPUI_FLOAT_LESS, OpCode.CPUI_FLOAT_LESS,       // LESSEQUAL hashes same as LESS
    0,                                                      // Unused slot - skip
    OpCode.CPUI_FLOAT_NAN,

    OpCode.CPUI_FLOAT_ADD, OpCode.CPUI_FLOAT_DIV, OpCode.CPUI_FLOAT_MULT, OpCode.CPUI_FLOAT_ADD, // SUB hashes same as ADD
    OpCode.CPUI_FLOAT_NEG, OpCode.CPUI_FLOAT_ABS, OpCode.CPUI_FLOAT_SQRT,

    OpCode.CPUI_FLOAT_INT2FLOAT, OpCode.CPUI_FLOAT_FLOAT2FLOAT, OpCode.CPUI_FLOAT_TRUNC, OpCode.CPUI_FLOAT_CEIL, OpCode.CPUI_FLOAT_FLOOR,
    OpCode.CPUI_FLOAT_ROUND,

    OpCode.CPUI_MULTIEQUAL, OpCode.CPUI_INDIRECT, OpCode.CPUI_PIECE, OpCode.CPUI_SUBPIECE,

    0,                                                      // CAST is skipped
    OpCode.CPUI_INT_ADD, OpCode.CPUI_INT_ADD,              // PTRADD and PTRSUB hash same as INT_ADD
    OpCode.CPUI_SEGMENTOP, OpCode.CPUI_CPOOLREF, OpCode.CPUI_NEW, OpCode.CPUI_INSERT, OpCode.CPUI_EXTRACT,
    OpCode.CPUI_POPCOUNT, OpCode.CPUI_LZCOUNT
  ];

  /**
   * Add in the edge between the given Varnode and its defining PcodeOp.
   *
   * When building the edge, certain p-code ops (CAST) are effectively ignored so that
   * we get the same hash whether or not these ops are present.
   * @param vn is the given Varnode
   */
  private buildVnUp(vn: Varnode): void {
    let op: PcodeOp;
    for (;;) {
      if (!vn.isWritten()) return;
      op = vn.getDef()!;
      if (DynamicHash.transtable[op.code()] !== 0) break; // Do not ignore this operation
      vn = op.getIn(0)!;
    }
    this.opedge.push(new ToOpEdge(op, -1));
  }

  /**
   * Add in edges between the given Varnode and any PcodeOp that reads it.
   *
   * When building edges, certain p-code ops (CAST) are effectively ignored so that
   * we get the same hash whether or not these ops are present.
   * @param vn is the given Varnode
   */
  private buildVnDown(vn: Varnode): void {
    const insize: number = this.opedge.length;

    for (let iter = vn.beginDescend(); iter < vn.endDescend(); ++iter) {
      let op: PcodeOp | null = vn.getDescend(iter);
      let tmpvn: Varnode | null = vn;
      while (DynamicHash.transtable[op!.code()] === 0) {
        tmpvn = op!.getOut();
        if (tmpvn === null) {
          op = null;
          break;
        }
        op = tmpvn.loneDescend();
        if (op === null) break;
      }
      if (op === null) continue;
      const slot: number = op.getSlot(tmpvn!);
      this.opedge.push(new ToOpEdge(op, slot));
    }
    if (this.opedge.length - insize > 1) {
      // Sort only the newly added edges
      const newEdges = this.opedge.splice(insize);
      newEdges.sort((a, b) => a.lessThan(b) ? -1 : (b.lessThan(a) ? 1 : 0));
      this.opedge.push(...newEdges);
    }
  }

  /**
   * Move input Varnodes for the given PcodeOp into staging.
   * @param op is the given PcodeOp that's already in the sub-graph
   */
  private buildOpUp(op: PcodeOp): void {
    for (let i = 0; i < op.numInput(); ++i) {
      const vn: Varnode = op.getIn(i)!;
      this.vnedge.push(vn);
    }
  }

  /**
   * Move the output Varnode for the given PcodeOp into staging.
   * @param op is the given PcodeOp that's already in the sub-graph
   */
  private buildOpDown(op: PcodeOp): void {
    const vn: Varnode | null = op.getOut();
    if (vn === null) return;
    this.vnedge.push(vn);
  }

  /** Move staged Varnodes into the sub-graph and mark them */
  private gatherUnmarkedVn(): void {
    for (let i = 0; i < this.vnedge.length; ++i) {
      const vn: Varnode = this.vnedge[i];
      if (vn.isMark()) continue;
      this.markvn.push(vn);
      vn.setMark();
    }
    this.vnedge.length = 0;
  }

  /** Mark any new PcodeOps in the sub-graph */
  private gatherUnmarkedOp(): void {
    for (; this.opedgeproc < this.opedge.length; ++this.opedgeproc) {
      const op: PcodeOp = this.opedge[this.opedgeproc].getOp();
      if (op.isMark()) continue;
      this.markop.push(op);
      op.setMark();
    }
  }

  /**
   * Clean-up and piece together formal hash value.
   *
   * Assume all the elements of the hash have been calculated.  Calculate the internal 32-bit hash
   * based on these elements.  Construct the 64-bit hash by piecing together the 32-bit hash
   * together with the core opcode, slot, and method.
   * @param root is the Varnode to extract root characteristics from
   * @param method is the method used to compute the hash elements
   */
  private pieceTogetherHash(root: Varnode, method: number): void {
    for (let i = 0; i < this.markvn.length; ++i) // Clear our marks
      this.markvn[i].clearMark();
    for (let i = 0; i < this.markop.length; ++i)
      this.markop[i].clearMark();

    if (this.opedge.length === 0) {
      this.hash = 0n;
      this.addrresult = new Address();
      return;
    }

    let reg: number = 0x3ba0fe06; // Calculate the 32-bit hash

    // Hash in information about the root
    reg = crc_update(reg, root.getSize());
    if (root.isConstant()) {
      let val: bigint = root.getOffset();
      for (let i = 0; i < root.getSize(); ++i) {
        reg = crc_update(reg, Number(val & 0xFFn));
        val >>= 8n;
      }
    }

    for (let i = 0; i < this.opedge.length; ++i)
      reg = this.opedge[i].hash(reg);

    // Build the final 64-bit hash
    let op: PcodeOp | null = null;
    let slot: number = 0;
    let ct: number;
    let attachedop: boolean = true;
    for (ct = 0; ct < this.opedge.length; ++ct) { // Find op that is directly attached to root
      op = this.opedge[ct].getOp();
      slot = this.opedge[ct].getSlot();
      if ((slot < 0) && (op.getOut() === root)) break;
      if ((slot >= 0) && (op.getIn(slot) === root)) break;
    }
    if (ct === this.opedge.length) { // If everything attached to the root was a skip op
      op = this.opedge[0].getOp();   // Return op that is not attached directly
      slot = this.opedge[0].getSlot();
      attachedop = false;
    }

    // 15 bits unused
    let h: bigint = attachedop ? 0n : 1n;
    h <<= 4n;
    h |= BigInt(method);                                   // 4-bits
    h <<= 7n;
    h |= BigInt(DynamicHash.transtable[op!.code()]);       // 7-bits
    h <<= 5n;
    h |= BigInt(slot & 0x1f);                              // 5-bits

    h <<= 32n;
    h |= BigInt(reg >>> 0);                                // 32-bits for the neighborhood hash
    this.hash = h;
    this.addrresult = op!.getSeqNum().getAddr();
  }

  /**
   * Convert given PcodeOp to a non-skip op by following data-flow.
   *
   * For a DynamicHash on a PcodeOp, the op must not be a CAST or other skipped opcode.
   * Test if the given op is a skip op, and if so follow data-flow indicated by the
   * slot to another PcodeOp until we find one that isn't a skip op. Pass back the new PcodeOp
   * and slot. Pass back null if the data-flow path ends.
   * @param opRef is an object holding the op and slot to modify
   */
  private static moveOffSkip(opRef: { op: PcodeOp | null; slot: number }): void {
    while (opRef.op !== null && DynamicHash.transtable[opRef.op.code()] === 0) {
      if (opRef.slot >= 0) {
        const vn: Varnode | null = opRef.op.getOut();
        if (vn === null) {
          opRef.op = null;
          return;
        }
        opRef.op = vn.loneDescend();
        if (opRef.op === null) {
          return; // Indicate the end of the data-flow path
        }
        opRef.slot = opRef.op.getSlot(vn);
      } else {
        const vn: Varnode | null = opRef.op.getIn(0);
        if (vn === null || !vn.isWritten()) {
          opRef.op = null;
          return; // Indicate the end of the data-flow path
        }
        opRef.op = vn.getDef();
      }
    }
  }

  /**
   * Remove any duplicate Varnodes in given list.
   * Otherwise preserve the order of the list.
   * @param varlist is the given list of Varnodes to check
   */
  private static dedupVarnodes(varlist: Varnode[]): Varnode[] {
    if (varlist.length < 2) return [...varlist];
    const resList: Varnode[] = [];
    for (let i = 0; i < varlist.length; ++i) {
      const vn: Varnode = varlist[i];
      if (!vn.isMark()) {
        vn.setMark();
        resList.push(vn);
      }
    }
    for (let i = 0; i < resList.length; ++i)
      resList[i].clearMark();
    return resList;
  }

  /** Called for each additional hash (after the first) */
  clear(): void {
    this.markop.length = 0;
    this.markvn.length = 0;
    this.vnedge.length = 0;
    this.opedge.length = 0;
  }

  /**
   * Calculate the hash for a given PcodeOp, slot, and method.
   * @param op is the given PcodeOp
   * @param slot is the slot to encode
   * @param method is the hashing method to use: 4, 5, 6
   */
  calcHashOp(op: PcodeOp, slot: number, method: number): void {
    let root: Varnode | null;

    // slot may be from a hash unassociated with op
    // we need to check that slot indicates a valid Varnode
    if (slot < 0) {
      root = op.getOut();
      if (root === null) {
        this.hash = 0n;
        this.addrresult = new Address();
        return; // slot does not fit op
      }
    } else {
      if (slot >= op.numInput()) {
        this.hash = 0n;
        this.addrresult = new Address();
        return; // slot does not fit op
      }
      root = op.getIn(slot)!;
    }
    this.vnproc = 0;
    this.opproc = 0;
    this.opedgeproc = 0;

    this.opedge.push(new ToOpEdge(op, slot));
    switch (method) {
      case 4:
        break;
      case 5:
        this.gatherUnmarkedOp();
        for (; this.opproc < this.markop.length; ++this.opproc) {
          this.buildOpUp(this.markop[this.opproc]);
        }
        this.gatherUnmarkedVn();
        for (; this.vnproc < this.markvn.length; ++this.vnproc)
          this.buildVnUp(this.markvn[this.vnproc]);
        break;
      case 6:
        this.gatherUnmarkedOp();
        for (; this.opproc < this.markop.length; ++this.opproc) {
          this.buildOpDown(this.markop[this.opproc]);
        }
        this.gatherUnmarkedVn();
        for (; this.vnproc < this.markvn.length; ++this.vnproc)
          this.buildVnDown(this.markvn[this.vnproc]);
        break;
      default:
        break;
    }
    this.pieceTogetherHash(root!, method);
  }

  /**
   * Calculate the hash for given Varnode and method.
   *
   * A sub-graph is formed extending from the given Varnode as the root. The
   * method specifies how the sub-graph is extended. In particular:
   *  - Method 0 extends to just immediate p-code ops reading or writing root
   *  - Method 1 extends to one more level of inputs from method 0.
   *  - Method 2 extends to one more level of outputs from method 0.
   *  - Method 3 extends to inputs and outputs
   *
   * The resulting hash and address can be obtained after calling this method
   * through getHash() and getAddress().
   * @param root is the given root Varnode
   * @param method is the hashing method to use: 0, 1, 2, 3
   */
  calcHash(root: Varnode, method: number): void {
    this.vnproc = 0;
    this.opproc = 0;
    this.opedgeproc = 0;

    this.vnedge.push(root);
    this.gatherUnmarkedVn();
    for (let i = this.vnproc; i < this.markvn.length; ++i)
      this.buildVnUp(this.markvn[i]);
    for (; this.vnproc < this.markvn.length; ++this.vnproc)
      this.buildVnDown(this.markvn[this.vnproc]);

    switch (method) {
      case 0:
        break;
      case 1:
        this.gatherUnmarkedOp();
        for (; this.opproc < this.markop.length; ++this.opproc)
          this.buildOpUp(this.markop[this.opproc]);

        this.gatherUnmarkedVn();
        for (; this.vnproc < this.markvn.length; ++this.vnproc)
          this.buildVnUp(this.markvn[this.vnproc]);
        break;
      case 2:
        this.gatherUnmarkedOp();
        for (; this.opproc < this.markop.length; ++this.opproc)
          this.buildOpDown(this.markop[this.opproc]);

        this.gatherUnmarkedVn();
        for (; this.vnproc < this.markvn.length; ++this.vnproc)
          this.buildVnDown(this.markvn[this.vnproc]);
        break;
      case 3:
        this.gatherUnmarkedOp();
        for (; this.opproc < this.markop.length; ++this.opproc)
          this.buildOpUp(this.markop[this.opproc]);

        this.gatherUnmarkedVn();
        for (; this.vnproc < this.markvn.length; ++this.vnproc)
          this.buildVnDown(this.markvn[this.vnproc]);
        break;
      default:
        break;
    }
    this.pieceTogetherHash(root, method);
  }

  /**
   * Select a unique hash for the given Varnode.
   *
   * Collect the set of Varnodes at the same address as the given Varnode.
   * Starting with method 0, increment the method and calculate hashes
   * of the Varnodes until the given Varnode has a unique hash within the set.
   * The resulting hash and address can be obtained after calling this method
   * through getHash() and getAddress().
   *
   * In the rare situation that the last method still does not yield a unique hash,
   * the hash encodes:
   *   - the smallest number of hash collisions
   *   - the method that produced the smallest number of hash collisions
   *   - the position of the root within the collision list
   *
   * For most cases, this will still uniquely identify the root Varnode.
   * @param root is the given root Varnode
   * @param fd is the function (holding the data-flow graph)
   */
  uniqueHash(root: Varnode, fd: Funcdata): void {
    let vnlist: Varnode[] = [];
    let vnlist2: Varnode[] = [];
    let champion: Varnode[] = [];
    let method: number;
    let tmphash: bigint;
    let tmpaddr: Address;
    const maxduplicates: number = 8;

    for (method = 0; method < 4; ++method) {
      this.clear();
      this.calcHash(root, method);
      if (this.hash === 0n) return; // Can't get a good hash
      tmphash = this.hash;
      tmpaddr = this.addrresult;
      vnlist = [];
      vnlist2 = [];
      DynamicHash.gatherFirstLevelVars(vnlist, fd, tmpaddr, tmphash);
      for (let i = 0; i < vnlist.length; ++i) {
        const tmpvn: Varnode = vnlist[i];
        this.clear();
        this.calcHash(tmpvn, method);
        if (DynamicHash.getComparable(this.hash) === DynamicHash.getComparable(tmphash)) { // Hash collision
          vnlist2.push(tmpvn);
          if (vnlist2.length > maxduplicates) break;
        }
      }
      if (vnlist2.length <= maxduplicates) {
        if ((champion.length === 0) || (vnlist2.length < champion.length)) {
          champion = vnlist2;
          if (champion.length === 1) break; // Current hash is unique
        }
      }
    }
    if (champion.length === 0) {
      this.hash = 0n;
      this.addrresult = new Address(); // Couldn't find a unique hash
      return;
    }
    const total: number = champion.length - 1; // total is in range [0,maxduplicates-1]
    let pos: number;
    for (pos = 0; pos <= total; ++pos)
      if (champion[pos] === root) break;
    if (pos > total) {
      this.hash = 0n;
      this.addrresult = new Address();
      return;
    }
    this.hash = tmphash! | (BigInt(pos) << 49n); // Store three bits for position with list of duplicate hashes
    this.hash |= (BigInt(total) << 52n);          // Store three bits for total number of duplicate hashes
    this.addrresult = tmpaddr!;
  }

  /**
   * Select unique hash for given PcodeOp and slot.
   *
   * Different hash methods are cycled through until a hash is found that distinguishes
   * the given op from other PcodeOps at the same address. The final hash encoding and
   * address of the PcodeOp are built for retrieval using getHash() and getAddress().
   * @param op is the given PcodeOp
   * @param slot is the particular slot to encode in the hash
   * @param fd is the function containing the given PcodeOp
   */
  uniqueHashOp(op: PcodeOp, slot: number, fd: Funcdata): void {
    let oplist: PcodeOp[] = [];
    let oplist2: PcodeOp[] = [];
    let champion: PcodeOp[] = [];
    let method: number;
    let tmphash: bigint;
    let tmpaddr: Address;
    const maxduplicates: number = 8;

    const opRef: { op: PcodeOp | null; slot: number } = { op, slot };
    DynamicHash.moveOffSkip(opRef);
    if (opRef.op === null) {
      this.hash = 0n;
      this.addrresult = new Address(); // Hash cannot be calculated
      return;
    }
    op = opRef.op;
    slot = opRef.slot;

    DynamicHash.gatherOpsAtAddress(oplist, fd, op.getAddr());
    for (method = 4; method < 7; ++method) {
      this.clear();
      this.calcHashOp(op, slot, method);
      if (this.hash === 0n) return; // Can't get a good hash
      tmphash = this.hash;
      tmpaddr = this.addrresult;
      oplist2 = [];
      for (let i = 0; i < oplist.length; ++i) {
        const tmpop: PcodeOp = oplist[i];
        if (slot >= tmpop.numInput()) continue;
        this.clear();
        this.calcHashOp(tmpop, slot, method);
        if (DynamicHash.getComparable(this.hash) === DynamicHash.getComparable(tmphash)) { // Hash collision
          oplist2.push(tmpop);
          if (oplist2.length > maxduplicates)
            break;
        }
      }
      if (oplist2.length <= maxduplicates) {
        if ((champion.length === 0) || (oplist2.length < champion.length)) {
          champion = oplist2;
          if (champion.length === 1)
            break; // Current hash is unique
        }
      }
    }
    if (champion.length === 0) {
      this.hash = 0n;
      this.addrresult = new Address(); // Couldn't find a unique hash
      return;
    }
    const total: number = champion.length - 1; // total is in range [0,maxduplicates-1]
    let pos: number;
    for (pos = 0; pos <= total; ++pos)
      if (champion[pos] === op)
        break;
    if (pos > total) {
      this.hash = 0n;
      this.addrresult = new Address();
      return;
    }
    this.hash = tmphash! | (BigInt(pos) << 49n); // Store three bits for position with list of duplicate hashes
    this.hash |= (BigInt(total) << 52n);          // Store three bits for total number of duplicate hashes
    this.addrresult = tmpaddr!;
  }

  /**
   * Given an address and hash, find the unique matching Varnode.
   *
   * The method, number of collisions, and position are pulled out of the hash.
   * Hashes for the method are performed at Varnodes linked to the given address,
   * and the Varnode which matches the hash (and the position) is returned.
   * If the number of collisions for the hash does not match, this method
   * will not return a Varnode, even if the position looks valid.
   * @param fd is the function containing the data-flow
   * @param addr is the given address
   * @param h is the hash
   * @return the matching Varnode or null
   */
  findVarnode(fd: Funcdata, addr: Address, h: bigint): Varnode | null {
    const method: number = DynamicHash.getMethodFromHash(h);
    const total: number = DynamicHash.getTotalFromHash(h);
    const pos: number = DynamicHash.getPositionFromHash(h);
    h = DynamicHash.clearTotalPosition(h);
    const vnlist: Varnode[] = [];
    const vnlist2: Varnode[] = [];
    DynamicHash.gatherFirstLevelVars(vnlist, fd, addr, h);
    if (process.env.DEBUG_HASH === '1') {
      console.error(`findVarnode: addr=0x${addr.getOffset().toString(16)} method=${method} total=${total} h=0x${h.toString(16)} vnlist=${vnlist.length}`);
    }
    for (let i = 0; i < vnlist.length; ++i) {
      const tmpvn: Varnode = vnlist[i];
      this.clear();
      this.calcHash(tmpvn, method);
      if (process.env.DEBUG_HASH === '1') {
        console.error(`  vn[${i}] off=0x${tmpvn.getOffset().toString(16)} sz=${tmpvn.getSize()} hash=0x${this.hash.toString(16)} comp=${DynamicHash.getComparable(this.hash).toString(16)} tgt=${DynamicHash.getComparable(h).toString(16)} match=${DynamicHash.getComparable(this.hash) === DynamicHash.getComparable(h)}`);
      }
      if (DynamicHash.getComparable(this.hash) === DynamicHash.getComparable(h))
        vnlist2.push(tmpvn);
    }
    if (total !== vnlist2.length) return null;
    return vnlist2[pos];
  }

  /**
   * Given an address and hash, find the unique matching PcodeOp.
   *
   * The method, slot, number of collisions, and position are pulled out of the hash.
   * Hashes for the method are performed at PcodeOps linked to the given address,
   * and the PcodeOp which matches the hash (and the position) is returned.
   * If the number of collisions for the hash does not match, this method
   * will not return a PcodeOp, even if the position looks valid.
   * @param fd is the function containing the data-flow
   * @param addr is the given address
   * @param h is the hash
   * @return the matching PcodeOp or null
   */
  findOp(fd: Funcdata, addr: Address, h: bigint): PcodeOp | null {
    const method: number = DynamicHash.getMethodFromHash(h);
    const slot: number = DynamicHash.getSlotFromHash(h);
    const total: number = DynamicHash.getTotalFromHash(h);
    const pos: number = DynamicHash.getPositionFromHash(h);
    h = DynamicHash.clearTotalPosition(h);
    const oplist: PcodeOp[] = [];
    const oplist2: PcodeOp[] = [];
    DynamicHash.gatherOpsAtAddress(oplist, fd, addr);
    for (let i = 0; i < oplist.length; ++i) {
      const tmpop: PcodeOp = oplist[i];
      if (slot >= tmpop.numInput()) continue;
      this.clear();
      this.calcHashOp(tmpop, slot, method);
      if (DynamicHash.getComparable(this.hash) === DynamicHash.getComparable(h))
        oplist2.push(tmpop);
    }
    if (total !== oplist2.length)
      return null;
    return oplist2[pos];
  }

  /** Get the (current) hash */
  getHash(): bigint { return this.hash; }

  /** Get the (current) address */
  getAddress(): Address { return this.addrresult; }

  /**
   * Get the Varnodes immediately attached to PcodeOps at the given address.
   *
   * Varnodes can be either inputs or outputs to the PcodeOps. The op-code, slot, and
   * attachment boolean encoded in the hash are used to further filter the
   * PcodeOp and Varnode objects. Varnodes are passed back in sequence with a list container.
   * @param varlist is the container that will hold the matching Varnodes
   * @param fd is the function holding the data-flow
   * @param addr is the given address
   * @param h is the given hash
   */
  static gatherFirstLevelVars(varlist: Varnode[], fd: Funcdata, addr: Address, h: bigint): void {
    const opcVal: number = DynamicHash.getOpCodeFromHash(h);
    const slot: number = DynamicHash.getSlotFromHash(h);
    const isnotattached: boolean = DynamicHash.getIsNotAttached(h);
    const [iter, enditer] = fd.beginEndOp(addr);

    let cur = iter;
    while (!cur.equals(enditer)) {
      let op: PcodeOp = cur.get();
      cur = cur.next();
      if (op.isDead()) continue;
      if (DynamicHash.transtable[op.code()] !== opcVal) continue;
      if (slot < 0) {
        let vn: Varnode | null = op.getOut();
        if (vn !== null) {
          if (isnotattached) { // If original varnode was not attached to (this) op
            const desc: PcodeOp | null = vn.loneDescend();
            if (desc !== null) {
              if (DynamicHash.transtable[desc.code()] === 0) { // Check for skipped op
                vn = desc.getOut();
                if (vn === null) continue;
              }
            }
          }
          varlist.push(vn);
        }
      } else if (slot < op.numInput()) {
        let vn: Varnode | null = op.getIn(slot);
        if (vn !== null && isnotattached) {
          const defOp: PcodeOp | null = vn.getDef();
          if ((defOp !== null) && (DynamicHash.transtable[defOp.code()] === 0))
            vn = defOp.getIn(0);
        }
        if (vn !== null) {
          varlist.push(vn);
        }
      }
    }
    const deduped = DynamicHash.dedupVarnodes(varlist);
    varlist.length = 0;
    varlist.push(...deduped);
  }

  /**
   * Place all PcodeOps at the given address in the provided container.
   * @param opList is the container to hold the PcodeOps
   * @param fd is the function
   * @param addr is the given address
   */
  static gatherOpsAtAddress(opList: PcodeOp[], fd: Funcdata, addr: Address): void {
    const [iter, enditer] = fd.beginEndOp(addr);
    while (!iter.equals(enditer)) {
      const op: PcodeOp = iter.get();
      iter.next();
      if (op.isDead()) continue;
      opList.push(op);
    }
  }

  /**
   * Retrieve the encoded slot from a hash.
   * The hash encodes the input slot the root Varnode was attached to in its PcodeOp.
   * @param h is the hash value
   * @return the slot index or -1 if the Varnode was attached as output
   */
  static getSlotFromHash(h: bigint): number {
    let res: number = Number((h >> 32n) & 0x1Fn);
    if (res === 31)
      res = -1;
    return res;
  }

  /**
   * Retrieve the encoded method from a hash.
   * @param h is the hash value
   * @return the method: 0, 1, 2, 3
   */
  static getMethodFromHash(h: bigint): number {
    return Number((h >> 44n) & 0xFn);
  }

  /**
   * Retrieve the encoded op-code from a hash.
   * The hash encodes the op-code of the p-code op attached to the root Varnode.
   * @param h is the hash value
   * @return the op-code as an integer
   */
  static getOpCodeFromHash(h: bigint): number {
    return Number((h >> 37n) & 0x7Fn);
  }

  /**
   * Retrieve the encoded position from a hash.
   * The hash encodes the position of the root Varnode within the list of hash collisions.
   * @param h is the hash value
   * @return the position of the root
   */
  static getPositionFromHash(h: bigint): number {
    return Number((h >> 49n) & 7n);
  }

  /**
   * Retrieve the encoded collision total from a hash.
   * @param h is the hash value
   * @return the total number of collisions
   */
  static getTotalFromHash(h: bigint): number {
    return Number(((h >> 52n) & 7n) + 1n);
  }

  /**
   * Retrieve the attachment boolean from a hash.
   * The hash encodes whether or not the root was directly attached to its PcodeOp.
   * @param h is the hash value
   * @return true if the root was not attached
   */
  static getIsNotAttached(h: bigint): boolean {
    return ((h >> 48n) & 1n) !== 0n;
  }

  /**
   * Clear the collision total and position fields within a hash.
   * The position and total collisions fields are set by the uniqueness and
   * need to be cleared when comparing raw hashes.
   * @param h is the hash to modify
   * @return the modified hash
   */
  static clearTotalPosition(h: bigint): bigint {
    let val: bigint = 0x3Fn;
    val <<= 49n;
    val = ~val;
    h &= val;
    return h;
  }

  /**
   * Get only the formal hash for comparing.
   * @param h is the hash value
   * @return the lower 32 bits
   */
  static getComparable(h: bigint): number {
    return Number(h & 0xFFFFFFFFn);
  }
}
