/**
 * @file merge.ts
 * @description Utilities for merging low-level Varnodes into high-level variables.
 *
 * Faithfully translated from Ghidra's merge.hh / merge.cc.
 */

import { Address } from '../core/address.js';
import { OpCode } from '../core/opcodes.js';
import { Varnode } from './varnode.js';
import { PcodeOp, PieceNode } from './op.js';
import { HighVariable, VariableGroup, VariablePiece, HighIntersectTest } from './variable.js';
import { Cover, PcodeOpSet } from './cover.js';
import { PcodeOpNode } from './expression.js';
import { LowlevelError } from '../core/error.js';
import type { SortedSetIterator } from '../util/sorted-set.js';

// ---------------------------------------------------------------------------
// Forward type declarations for types from not-yet-written modules
// ---------------------------------------------------------------------------

type Funcdata = any;
type BlockBasic = any;
type FlowBlock = any;
type BlockGraph = any;
type Datatype = any;
type Symbol = any;
type SymbolEntry = any;
type AddrSpace = any;
type LoadGuard = any;
type ResolvedUnion = any;
// PieceNode imported from op.ts
type VarnodeLocSet = any;

// ---------------------------------------------------------------------------
// BlockVarnode
// ---------------------------------------------------------------------------

/**
 * Helper class associating a Varnode with the block where it is defined.
 *
 * This class explicitly stores a Varnode with the index of the BlockBasic that defines it.
 * If a Varnode does not have a defining PcodeOp it is assigned an index of 0.
 * This facilitates quicker sorting of Varnodes based on their defining block.
 */
export class BlockVarnode {
  private index: number = 0;
  private vn: Varnode | null = null;

  /** Set this as representing the given Varnode */
  set(v: Varnode): void {
    this.vn = v;
    const op = this.vn.getDef();
    if (op === null) {
      this.index = 0;
    } else {
      this.index = op.getParent().getIndex();
    }
  }

  /** Comparator: order by block index */
  lessThan(op2: BlockVarnode): boolean {
    return this.index < op2.index;
  }

  /** Get the Varnode represented by this */
  getVarnode(): Varnode {
    return this.vn!;
  }

  /** Get the Varnode's defining block index */
  getIndex(): number {
    return this.index;
  }

  /**
   * Find the first Varnode defined in the BlockBasic of the given index.
   *
   * A BlockVarnode is identified from a sorted list. The position of the first BlockVarnode
   * in this list that has the given BlockBasic index is returned.
   * @param blocknum is the index of the BlockBasic to search for
   * @param list is the sorted list of BlockVarnodes
   * @returns the index of the BlockVarnode within the list or -1 if no Varnode in the block is found
   */
  static findFront(blocknum: number, list: BlockVarnode[]): number {
    let min = 0;
    let max = list.length - 1;
    while (min < max) {
      const cur = (min + max) >>> 1;
      const curblock = list[cur].getIndex();
      if (curblock >= blocknum)
        max = cur;
      else
        min = cur + 1;
    }
    if (min > max) return -1;
    if (list[min].getIndex() !== blocknum) return -1;
    return min;
  }
}

// ---------------------------------------------------------------------------
// StackAffectingOps
// ---------------------------------------------------------------------------

/**
 * The set of CALL and STORE ops that might indirectly affect stack variables.
 *
 * Intersect tests between local address tied and non-address tied Varnodes need to check for
 * possible uses of aliases to the address tied Varnode.  This object is populated with the set of
 * PcodeOps through which any stack Varnode might be modified through an alias.  Given an intersection
 * of the Cover of an address tied Varnode and a PcodeOp in this set, affectsTest() can do
 * secondary testing of whether the Varnode is actually modified by the PcodeOp.
 */
export class StackAffectingOps extends PcodeOpSet {
  private data: Funcdata;

  constructor(fd: Funcdata) {
    super();
    this.data = fd;
  }

  populate(): void {
    for (let i = 0; i < this.data.numCalls(); ++i) {
      const op: PcodeOp = this.data.getCallSpecs_byIndex(i).getOp();
      this.addOp(op);
    }
    const storeGuard: LoadGuard[] = this.data.getStoreGuards();
    for (const guard of storeGuard) {
      if (guard.isValid(OpCode.CPUI_STORE))
        this.addOp(guard.getOp());
    }
    this.finalize();
  }

  affectsTest(op: PcodeOp, vn: Varnode): boolean {
    if (op.code() === OpCode.CPUI_STORE) {
      const loadGuard: LoadGuard | null = this.data.getStoreGuard(op);
      if (loadGuard === null)
        return true;
      return loadGuard.isGuarded(vn.getAddr());
    }
    // We could conceivably do secondary testing of CALL ops here
    return true;
  }
}

// ---------------------------------------------------------------------------
// Merge
// ---------------------------------------------------------------------------

/**
 * Class for merging low-level Varnodes into high-level HighVariables.
 *
 * As a node in Single Static Assignment (SSA) form, a Varnode has at most one defining
 * operation. To get a suitable notion of a single high-level variable (HighVariable) that
 * may be reassigned at multiple places in a single function, individual Varnode objects
 * can be merged into a HighVariable object. Varnode objects may be merged in this way
 * if there is no pairwise intersection between each Varnode's Cover, the ranges of code
 * where the Varnode holds its value.
 *
 * For a given function, this class attempts to merge Varnodes using various strategies
 * and keeps track of Cover intersections to facilitate the process.
 */
export class Merge {
  private data: Funcdata;
  private stackAffectingOps: StackAffectingOps;
  private testCache: HighIntersectTest;
  private copyTrims: PcodeOp[] = [];
  private protoPartial: PcodeOp[] = [];

  /** Construct given a specific function */
  constructor(fd: Funcdata) {
    this.data = fd;
    this.stackAffectingOps = new StackAffectingOps(fd);
    this.testCache = new HighIntersectTest(this.stackAffectingOps);
  }

  // --- Private static methods ---

  /**
   * Required tests to merge HighVariables that are not Cover related.
   *
   * This is designed to short circuit merge tests, when we know properties of the
   * two HighVariables preclude merging.
   * @param high_out is the first HighVariable to test
   * @param high_in is the second HighVariable to test
   * @returns true if tests pass and the HighVariables are not forbidden to merge
   */
  private static mergeTestRequired(high_out: HighVariable, high_in: HighVariable): boolean {
    if (high_in === high_out) return true; // Already merged

    if (high_in.isTypeLock())
      if (high_out.isTypeLock())
        if (high_in.getType() !== high_out.getType()) return false;

    if (high_out.isAddrTied()) {
      if (high_in.isAddrTied()) {
        if (!high_in.getTiedVarnode().getAddr().equals(high_out.getTiedVarnode().getAddr()))
          return false;
      }
    }

    if (high_in.isInput()) {
      if (high_out.isPersist()) return false;
      if (high_out.isAddrTied() && !high_in.isAddrTied()) return false;
    } else if (high_in.isExtraOut()) {
      return false;
    }
    if (high_out.isInput()) {
      if (high_in.isPersist()) return false;
      if (high_in.isAddrTied() && !high_out.isAddrTied()) return false;
    } else if (high_out.isExtraOut()) {
      return false;
    }

    if (high_in.isProtoPartial()) {
      if (high_out.isProtoPartial()) return false;
      if (high_out.isInput()) return false;
      if (high_out.isAddrTied()) return false;
      if (high_out.isPersist()) return false;
    }
    if (high_out.isProtoPartial()) {
      if (high_in.isInput()) return false;
      if (high_in.isAddrTied()) return false;
      if (high_in.isPersist()) return false;
    }

    if (high_in._piece !== null && high_out._piece !== null) {
      const groupIn: VariableGroup = high_in._piece!.getGroup();
      const groupOut: VariableGroup = high_out._piece!.getGroup();
      if (groupIn === groupOut)
        return false;
      // At least one of the pieces must represent its whole group
      if (high_in._piece!.getSize() !== groupIn.getSize() && high_out._piece!.getSize() !== groupOut.getSize())
        return false;
    }

    const symbolIn: Symbol | null = high_in.getSymbol();
    const symbolOut: Symbol | null = high_out.getSymbol();
    if (symbolIn !== null && symbolOut !== null) {
      if (symbolIn !== symbolOut)
        return false;
      if (high_in.getSymbolOffset() !== high_out.getSymbolOffset())
        return false;
    }
    return true;
  }

  /**
   * Adjacency tests for merging Varnodes that are input/output to the same p-code op.
   *
   * All the required tests (mergeTestRequired()) are performed, and then some additional tests
   * are performed. This does not perform any Cover tests.
   * @param high_out is the output HighVariable to test
   * @param high_in is the input HighVariable to test
   * @returns true if tests pass and the HighVariables are not forbidden to merge
   */
  private static mergeTestAdjacent(high_out: HighVariable, high_in: HighVariable): boolean {
    if (!Merge.mergeTestRequired(high_out, high_in)) return false;

    if (high_in.isNameLock() && high_out.isNameLock())
      return false;

    if (high_out.getType() !== high_in.getType())
      return false;

    if (high_out.isInput()) {
      const vn: Varnode = high_out.getInputVarnode();
      if (vn.isIllegalInput() && !vn.isIndirectOnly()) return false;
    }
    if (high_in.isInput()) {
      const vn: Varnode = high_in.getInputVarnode();
      if (vn.isIllegalInput() && !vn.isIndirectOnly()) return false;
    }
    let symbol: Symbol | null = high_in.getSymbol();
    if (symbol !== null)
      if (symbol.isIsolated())
        return false;
    symbol = high_out.getSymbol();
    if (symbol !== null)
      if (symbol.isIsolated())
        return false;

    // Currently don't allow speculative merging of variables that are in separate overlapping collections
    if (high_out._piece !== null && high_in._piece !== null)
      return false;
    return true;
  }

  /**
   * Speculative tests for merging HighVariables that are not Cover related.
   * @param high_out is the first HighVariable to test
   * @param high_in is the second HighVariable to test
   * @returns true if tests pass and the HighVariables are not forbidden to merge
   */
  private static mergeTestSpeculative(high_out: HighVariable, high_in: HighVariable): boolean {
    if (!Merge.mergeTestAdjacent(high_out, high_in)) return false;

    if (high_out.isPersist()) return false;
    if (high_in.isPersist()) return false;
    if (high_out.isInput()) return false;
    if (high_in.isInput()) return false;
    if (high_out.isAddrTied()) return false;
    if (high_in.isAddrTied()) return false;
    return true;
  }

  /**
   * Test if the given Varnode that must be merged, can be merged.
   * If it cannot be merged, throw an exception.
   * @param vn is the given Varnode
   */
  private static mergeTestMust(vn: Varnode): void {
    if (vn.hasCover() && !vn.isImplied())
      return;
    throw new LowlevelError("Cannot force merge of range");
  }

  /**
   * Test if the given Varnode can ever be merged.
   * Some Varnodes (constants, annotations, implied, spacebase) are never merged with another Varnode.
   * @param vn is the Varnode to test
   * @returns true if the Varnode is not forbidden from ever merging
   */
  private static mergeTestBasic(vn: Varnode | null): boolean {
    if (vn === null) return false;
    if (!vn.hasCover()) return false;
    if (vn.isImplied()) return false;
    if (vn.isProtoPartial()) return false;
    if (vn.isSpacebase()) return false;
    return true;
  }

  /**
   * Find instance Varnodes that are copied to from outside the given HighVariable.
   * @param high is the given HighVariable
   * @param singlelist will hold the resulting list of copied instances
   */
  private static findSingleCopy(high: HighVariable, singlelist: Varnode[]): void {
    for (let i = 0; i < high.numInstances(); ++i) {
      const vn: Varnode = high.getInstance(i);
      if (!vn.isWritten()) continue;
      const op: PcodeOp = vn.getDef()!;
      if (op.code() !== OpCode.CPUI_COPY) continue;
      if (op.getIn(0)!.getHigh() === high) continue;
      singlelist.push(vn);
    }
  }

  /**
   * Compare HighVariables by the blocks they cover.
   *
   * This comparator sorts, based on:
   *   - Index of the first block containing cover for the HighVariable
   *   - Address of the first instance
   *   - Address of the defining p-code op
   *   - Storage address
   * @param a is the first HighVariable to compare
   * @param b is the second HighVariable
   * @returns negative/0/positive for Array.sort
   */
  private static compareHighByBlock(a: HighVariable, b: HighVariable): number {
    const result: number = a.getCover().compareTo(b.getCover());
    if (result === 0) {
      const v1: Varnode = a.getInstance(0);
      const v2: Varnode = b.getInstance(0);

      if (v1.getAddr().equals(v2.getAddr())) {
        const def1: PcodeOp | null = v1.getDef();
        const def2: PcodeOp | null = v2.getDef();
        if (def1 === null) {
          return def2 !== null ? -1 : 0;
        } else if (def2 === null) {
          return 0;
        }
        if (def1.getAddr().lessThan(def2.getAddr())) return -1;
        if (def2.getAddr().lessThan(def1.getAddr())) return 1;
        return 0;
      }
      if (v1.getAddr().lessThan(v2.getAddr())) return -1;
      return 1;
    }
    return result < 0 ? -1 : 1;
  }

  /**
   * Compare COPY ops first by Varnode input, then by block containing the op.
   * @param op1 is the first PcodeOp being compared
   * @param op2 is the second PcodeOp being compared
   * @returns negative, 0, or positive for sort ordering
   */
  private static compareCopyByInVarnode(op1: PcodeOp, op2: PcodeOp): number {
    const inVn1: Varnode = op1.getIn(0)!;
    const inVn2: Varnode = op2.getIn(0)!;
    if (inVn1 !== inVn2) {
      return inVn1.getCreateIndex() - inVn2.getCreateIndex();
    }
    const index1: number = op1.getParent().getIndex();
    const index2: number = op2.getParent().getIndex();
    if (index1 !== index2)
      return index1 - index2;
    return op1.getSeqNum().getOrder() - op2.getSeqNum().getOrder();
  }

  /**
   * Determine if given Varnode is shadowed by another Varnode in the same HighVariable.
   * @param vn is the Varnode to check for shadowing
   * @returns true if vn is shadowed by another Varnode in its high-level variable
   */
  private static shadowedVarnode(vn: Varnode): boolean {
    const high: HighVariable = vn.getHigh();
    const num: number = high.numInstances();
    for (let i = 0; i < num; ++i) {
      const othervn: Varnode = high.getInstance(i);
      if (othervn === vn) continue;
      if (vn.getCover()!.intersect(othervn.getCover()!) === 2) return true;
    }
    return false;
  }

  /**
   * Find all the COPY ops into the given HighVariable.
   *
   * Collect all the COPYs whose output is the given HighVariable but
   * the input is from a different HighVariable. Returned COPYs are sorted
   * first by the input Varnode then by block order.
   * @param high is the given HighVariable
   * @param copyIns will hold the list of COPYs
   * @param filterTemps is true if COPYs must have a temporary output
   */
  private static findAllIntoCopies(high: HighVariable, copyIns: PcodeOp[], filterTemps: boolean): void {
    for (let i = 0; i < high.numInstances(); ++i) {
      const vn: Varnode = high.getInstance(i);
      if (!vn.isWritten()) continue;
      const op: PcodeOp = vn.getDef()!;
      if (op.code() !== OpCode.CPUI_COPY) continue;
      if (op.getIn(0)!.getHigh() === high) continue;
      if (filterTemps && op.getOut()!.getSpace()!.getType() !== 3 /* IPTR_INTERNAL */) continue;
      copyIns.push(op);
    }
    // Group COPYs based on the incoming Varnode then block order
    copyIns.sort(Merge.compareCopyByInVarnode);
  }

  // --- Private instance methods ---

  /**
   * Collect Varnode instances or pieces from a specific HighVariable that are inputs to a given PcodeOp.
   * @param high is the specific HighVariable through which to search for input instances
   * @param oplist will hold the PcodeOpNodes being passed back
   * @param op is the given PcodeOp
   */
  private collectInputs(high: HighVariable, oplist: PcodeOpNode[], op: PcodeOp | null): void {
    let group: VariableGroup | null = null;
    if (high._piece !== null)
      group = high._piece!.getGroup();
    for (;;) {
      for (let i = 0; i < op!.numInput(); ++i) {
        const vn: Varnode = op!.getIn(i)!;
        if (vn.isAnnotation()) continue;
        const testHigh: HighVariable = vn.getHigh();
        if (testHigh === high || (testHigh._piece !== null && testHigh._piece!.getGroup() === group)) {
          oplist.push(new PcodeOpNode(op, i));
        }
      }
      op = op!.previousOp();
      if (op === null || op.code() !== OpCode.CPUI_INDIRECT)
        break;
    }
  }

  /**
   * Allocate COPY PcodeOp designed to trim an overextended Cover.
   * @param inVn is the given input Varnode for the new COPY
   * @param addr is the address associated with the new COPY
   * @param trimOp is an exemplar PcodeOp whose read is being trimmed
   * @returns the newly allocated COPY
   */
  private allocateCopyTrim(inVn: Varnode, addr: Address, trimOp: PcodeOp): PcodeOp {
    const copyOp: PcodeOp = this.data.newOp(1, addr);
    this.data.opSetOpcode(copyOp, OpCode.CPUI_COPY);
    const ct: Datatype = inVn.getType();
    if (ct.needsResolution()) {
      if (inVn.isWritten()) {
        const fieldNum: number = this.data.inheritResolution(ct, copyOp, -1, inVn.getDef()!, -1);
        this.data.forceFacingType(ct, fieldNum, copyOp, 0);
      } else {
        const slot: number = trimOp.getSlot(inVn);
        const resUnion: ResolvedUnion | null = this.data.getUnionField(ct, trimOp, slot);
        const fieldNum: number = resUnion === null ? -1 : resUnion.getFieldNum();
        this.data.forceFacingType(ct, fieldNum, copyOp, 0);
      }
    }
    const outVn: Varnode = this.data.newUnique(inVn.getSize(), ct);
    this.data.opSetOutput(copyOp, outVn);
    this.data.opSetInput(copyOp, inVn, 0);
    this.copyTrims.push(copyOp);
    return copyOp;
  }

  /**
   * Snip off set of read p-code ops for a given Varnode.
   *
   * The data-flow for the given Varnode is truncated by creating a COPY p-code from the Varnode
   * into a new temporary Varnode, then replacing the Varnode reads for a specific set of
   * p-code ops with the temporary.
   * @param vn is the given Varnode
   * @param markedop is the specific set of PcodeOps reading the Varnode
   */
  private snipReads(vn: Varnode, markedop: PcodeOp[]): void {
    if (markedop.length === 0) return;

    let bl: BlockBasic;
    let pc: Address;
    let afterop: PcodeOp | null;

    if (vn.isInput()) {
      bl = this.data.getBasicBlocks().getBlock(0);
      pc = bl.getStart();
      afterop = null;
    } else {
      const defOp: PcodeOp = vn.getDef()!;
      bl = defOp.getParent();
      pc = defOp.getAddr();
      if (defOp.code() === OpCode.CPUI_INDIRECT) {
        afterop = PcodeOp.getOpFromConst(defOp.getIn(1)!.getAddr());
      } else {
        afterop = defOp;
      }
    }
    const copyop: PcodeOp = this.allocateCopyTrim(vn, pc, markedop[0]);
    if (afterop === null)
      this.data.opInsertBegin(copyop, bl);
    else
      this.data.opInsertAfter(copyop, afterop);

    for (const op of markedop) {
      const slot: number = op.getSlot(vn);
      this.data.opSetInput(op, copyop.getOut()!, slot);
    }
  }

  /**
   * Snip instances of the output of an INDIRECT that are also inputs to the underlying PcodeOp.
   * @param indop is the given INDIRECT op
   * @returns true if specific instances are snipped
   */
  private snipOutputInterference(indop: PcodeOp): boolean {
    const op: PcodeOp = PcodeOp.getOpFromConst(indop.getIn(1)!.getAddr())!;
    const correctable: PcodeOpNode[] = [];
    this.collectInputs(indop.getOut()!.getHigh(), correctable, op);
    if (correctable.length === 0)
      return false;

    correctable.sort((a: PcodeOpNode, b: PcodeOpNode): number => {
      // compareByHigh: group by HighVariable
      const ha = a.op!.getIn(a.slot)!.getHigh();
      const hb = b.op!.getIn(b.slot)!.getHigh();
      if (ha === hb) return 0;
      return ha < hb ? -1 : 1;
    });
    let snipop: PcodeOp | null = null;
    let curHigh: HighVariable | null = null;
    for (let i = 0; i < correctable.length; ++i) {
      const insertop: PcodeOp = correctable[i].op!;
      const slot: number = correctable[i].slot;
      const vn: Varnode = insertop.getIn(slot)!;
      if (vn.getHigh() !== curHigh) {
        snipop = this.allocateCopyTrim(vn, insertop.getAddr(), insertop);
        this.data.opInsertBefore(snipop, insertop);
        curHigh = vn.getHigh();
      }
      this.data.opSetInput(insertop, snipop!.getOut()!, slot);
    }
    return true;
  }

  /**
   * Eliminate intersections of given Varnode with other Varnodes in a list.
   * @param vn is the given Varnode
   * @param blocksort is the list of other Varnodes sorted by their defining basic block
   */
  private eliminateIntersect(vn: Varnode, blocksort: BlockVarnode[]): void {
    const markedop: PcodeOp[] = [];

    // beginDescend()/endDescend() return numeric indices in the TS Varnode class
    for (let oIdx = vn.beginDescend(); oIdx < vn.endDescend(); ++oIdx) {
      let shouldInsert = false;
      const single = new Cover();
      single.addDefPoint(vn);
      const op: PcodeOp = vn.getDescend(oIdx);
      single.addRefPoint(op, vn);

      for (const [blocknum] of single) {
        let slot: number = BlockVarnode.findFront(blocknum, blocksort);
        if (slot === -1) continue;
        while (slot < blocksort.length) {
          if (blocksort[slot].getIndex() !== blocknum)
            break;
          const vn2: Varnode = blocksort[slot].getVarnode();
          slot += 1;
          if (vn2 === vn) continue;
          const boundtype: number = single.containVarnodeDef(vn2);
          if (boundtype === 0) continue;
          const overlaptype: number = vn.characterizeOverlap(vn2);
          if (overlaptype === 0) continue;
          if (overlaptype === 1) {
            const off: number = Number(vn.getOffset() - vn2.getOffset());
            const shadow = vn.partialCopyShadow(vn2, off);
            if (shadow)
              continue;
          }
          if (boundtype === 2) {
            if (vn2.getDef() === null) {
              if (vn.getDef() === null) {
                if (vn < vn2) continue; // Arbitrary order for both inputs
              } else {
                continue;
              }
            } else {
              if (vn.getDef() !== null) {
                if (vn2.getDef()!.getSeqNum().getOrder() < vn.getDef()!.getSeqNum().getOrder())
                  continue;
              }
            }
          } else if (boundtype === 3) {
            if (!vn2.isAddrForce()) continue;
            if (!vn2.isWritten()) continue;
            const indop: PcodeOp = vn2.getDef()!;
            if (indop.code() !== OpCode.CPUI_INDIRECT) continue;
            if (op !== PcodeOp.getOpFromConst(indop.getIn(1)!.getAddr())) continue;
            if (overlaptype !== 1) {
              if (vn.copyShadow(indop.getIn(0)!)) continue;
            } else {
              const off: number = Number(vn.getOffset() - vn2.getOffset());
              if (vn.partialCopyShadow(indop.getIn(0)!, off)) continue;
            }
          }
          shouldInsert = true;
          break;
        }
        if (shouldInsert) break;
      }
      if (shouldInsert)
        markedop.push(op);
    }
    this.snipReads(vn, markedop);
  }

  /**
   * Make sure all Varnodes with the same storage address and size can be merged.
   * @param startiter is the beginning of the range of Varnodes with the same storage address
   * @param enditer is the end of the range
   */
  private unifyAddress(startiter: SortedSetIterator<Varnode>, enditer: SortedSetIterator<Varnode>): void {
    const isectlist: Varnode[] = [];
    const blocksort: BlockVarnode[] = [];

    const iter = startiter.clone();
    while (!iter.equals(enditer)) {
      const vn: Varnode = iter.get();
      iter.next();
      if (vn.isFree()) continue;
      isectlist.push(vn);
    }
    blocksort.length = isectlist.length;
    for (let i = 0; i < isectlist.length; ++i) {
      blocksort[i] = new BlockVarnode();
      blocksort[i].set(isectlist[i]);
    }
    blocksort.sort((a, b) => a.getIndex() - b.getIndex());

    for (let i = 0; i < isectlist.length; ++i)
      this.eliminateIntersect(isectlist[i], blocksort);
  }

  /** Trim the output HighVariable of the given PcodeOp so that its Cover is tiny */
  private trimOpOutput(op: PcodeOp): void {
    let afterop: PcodeOp;

    if (op.code() === OpCode.CPUI_INDIRECT)
      afterop = PcodeOp.getOpFromConst(op.getIn(1)!.getAddr())!;
    else
      afterop = op;
    const vn: Varnode = op.getOut()!;
    let ct: Datatype = vn.getType();
    const copyop: PcodeOp = this.data.newOp(1, op.getAddr());
    this.data.opSetOpcode(copyop, OpCode.CPUI_COPY);
    if (ct.needsResolution()) {
      const fieldNum: number = this.data.inheritResolution(ct, copyop, -1, op, -1);
      this.data.forceFacingType(ct, fieldNum, copyop, 0);
      if (ct.getMetatype() === 0 /* TYPE_PARTIALUNION */)
        ct = vn.getTypeDefFacing();
    }
    const uniq: Varnode = this.data.newUnique(vn.getSize(), ct);
    this.data.opSetOutput(op, uniq);
    this.data.opSetOutput(copyop, vn);
    this.data.opSetInput(copyop, uniq, 0);
    this.data.opInsertAfter(copyop, afterop);
  }

  /**
   * Trim the input HighVariable of the given PcodeOp so that its Cover is tiny.
   * @param op is the given PcodeOp
   * @param slot is the specified slot of the input Varnode to be trimmed
   */
  private trimOpInput(op: PcodeOp, slot: number): void {
    let pc: Address;

    if (op.code() === OpCode.CPUI_MULTIEQUAL) {
      const bb: BlockBasic = op.getParent().getIn(slot);
      pc = bb.getStop();
    } else {
      pc = op.getAddr();
    }
    const vn: Varnode = op.getIn(slot)!;
    const copyop: PcodeOp = this.allocateCopyTrim(vn, pc, op);
    this.data.opSetInput(op, copyop.getOut()!, slot);
    if (op.code() === OpCode.CPUI_MULTIEQUAL)
      this.data.opInsertEnd(copyop, op.getParent().getIn(slot));
    else
      this.data.opInsertBefore(copyop, op);
  }

  /**
   * Force the merge of a range of Varnodes with the same size and storage address.
   * @param startiter is the beginning of the range
   * @param enditer is the end of the range
   */
  private mergeRangeMust(startiter: SortedSetIterator<Varnode>, enditer: SortedSetIterator<Varnode>): void {
    const iter = startiter.clone();
    let vn: Varnode = iter.get();
    iter.next();
    Merge.mergeTestMust(vn);
    const high: HighVariable = vn.getHigh();
    while (!iter.equals(enditer)) {
      vn = iter.get();
      iter.next();
      if (vn.getHigh() === high) continue;
      Merge.mergeTestMust(vn);
      if (!this.mergePrivate(high, vn.getHigh(), false))
        throw new LowlevelError("Forced merge caused intersection");
    }
  }

  /**
   * Force the merge of all input and output Varnodes for the given PcodeOp.
   * @param op is the given PcodeOp
   */
  private mergeOp(op: PcodeOp): void {
    const testlist: HighVariable[] = [];
    const max: number = (op.code() === OpCode.CPUI_INDIRECT) ? 1 : op.numInput();
    const high_out: HighVariable = op.getOut()!.getHigh();

    for (let i = 0; i < max; ++i) {
      const high_in: HighVariable = op.getIn(i)!.getHigh();
      if (!Merge.mergeTestRequired(high_out, high_in)) {
        this.trimOpInput(op, i);
        continue;
      }
      for (let j = 0; j < i; ++j) {
        if (!Merge.mergeTestRequired(op.getIn(j)!.getHigh(), high_in)) {
          this.trimOpInput(op, i);
          break;
        }
      }
    }

    this.mergeTest(high_out, testlist);
    let i: number;
    for (i = 0; i < max; ++i)
      if (!this.mergeTest(op.getIn(i)!.getHigh(), testlist)) break;

    if (i !== max) {
      let nexttrim = 0;
      while (nexttrim < max) {
        this.trimOpInput(op, nexttrim);
        testlist.length = 0;
        this.mergeTest(high_out, testlist);
        let k: number;
        for (k = 0; k < max; ++k)
          if (!this.mergeTest(op.getIn(k)!.getHigh(), testlist)) break;
        if (k === max) break;
        nexttrim += 1;
      }
      if (nexttrim === max)
        this.trimOpOutput(op);
    }

    for (let m = 0; m < max; ++m) {
      if (!Merge.mergeTestRequired(op.getOut()!.getHigh(), op.getIn(m)!.getHigh()))
        throw new LowlevelError("Non-cover related merge restriction violated, despite trims");
      if (!this.mergePrivate(op.getOut()!.getHigh(), op.getIn(m)!.getHigh(), false)) {
        throw new LowlevelError("Unable to force merge of op at " + op.getSeqNum().toString());
      }
    }
  }

  /**
   * Force the merge of all input and output Varnodes to a given INDIRECT op.
   * @param indop is the given INDIRECT
   */
  private mergeIndirect(indop: PcodeOp): void {
    const outvn: Varnode = indop.getOut()!;
    if (!outvn.isAddrForce()) {
      this.mergeOp(indop);
      return;
    }

    const invn0: Varnode = indop.getIn(0)!;
    if (Merge.mergeTestRequired(outvn.getHigh(), invn0.getHigh())) {
      if (this.mergePrivate(invn0.getHigh(), outvn.getHigh(), false))
        return;
    }

    if (this.snipOutputInterference(indop)) {
      if (Merge.mergeTestRequired(outvn.getHigh(), invn0.getHigh())) {
        if (this.mergePrivate(invn0.getHigh(), outvn.getHigh(), false))
          return;
      }
    }

    const newop: PcodeOp = this.allocateCopyTrim(invn0, indop.getAddr(), indop);
    const entry: SymbolEntry | null = outvn.getSymbolEntry();
    if (entry !== null && entry.getSymbol().getType().needsResolution()) {
      this.data.inheritResolution(entry.getSymbol().getType(), newop, -1, indop, -1);
    }
    this.data.opSetInput(indop, newop.getOut()!, 0);
    this.data.opInsertBefore(newop, indop);
    if (!Merge.mergeTestRequired(outvn.getHigh(), indop.getIn(0)!.getHigh()) ||
        !this.mergePrivate(indop.getIn(0)!.getHigh(), outvn.getHigh(), false))
      throw new LowlevelError("Unable to merge address forced indirect");
  }

  /**
   * Speculatively merge all HighVariables in the given list as well as possible.
   * @param highvec is the list of HighVariables to merge
   */
  private mergeLinear(highvec: HighVariable[]): void {
    const highstack: HighVariable[] = [];

    if (highvec.length <= 1) return;
    for (const h of highvec)
      this.testCache.updateHigh(h);
    highvec.sort(Merge.compareHighByBlock);
    for (const high of highvec) {
      let found = false;
      for (const stackHigh of highstack) {
        if (Merge.mergeTestSpeculative(stackHigh, high)) {
          if (this.mergePrivate(stackHigh, high, true)) {
            found = true;
            break;
          }
        }
      }
      if (!found)
        highstack.push(high);
    }
  }

  /**
   * Perform low-level details of merging two HighVariables if possible.
   * @param high1 is the first HighVariable being merged
   * @param high2 is the second
   * @param isspeculative is true if the desired merge is speculative
   * @returns true if the merge was successful
   */
  private mergePrivate(high1: HighVariable, high2: HighVariable, isspeculative: boolean): boolean {
    if (high1 === high2) return true;
    if (this.testCache.intersection(high1, high2)) return false;

    high1.merge(high2, this.testCache, isspeculative);
    high1.updateCover();

    return true;
  }

  /**
   * Check if the given PcodeOp COPYs are redundant.
   * @param high is the HighVariable being assigned to
   * @param domOp is the first COPY
   * @param subOp is the second COPY
   * @returns true if the second COPY is redundant
   */
  private checkCopyPair(high: HighVariable, domOp: PcodeOp, subOp: PcodeOp): boolean {
    const domBlock: FlowBlock = domOp.getParent();
    const subBlock: FlowBlock = subOp.getParent();
    if (!domBlock.dominates(subBlock))
      return false;
    const range = new Cover();
    range.addDefPoint(domOp.getOut()!);
    range.addRefPoint(subOp, subOp.getIn(0)!);
    const inVn: Varnode = domOp.getIn(0)!;
    for (let i = 0; i < high.numInstances(); ++i) {
      const vn: Varnode = high.getInstance(i);
      if (!vn.isWritten()) continue;
      const op: PcodeOp = vn.getDef()!;
      if (op.code() === OpCode.CPUI_COPY) {
        if (op.getIn(0) === inVn) continue;
      }
      if (range.contain(op, 1)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Try to replace a set of COPYs from the same Varnode with a single dominant COPY.
   * @param high is the HighVariable being copied to
   * @param copy is the list of COPY ops into the HighVariable
   * @param pos is the index of the first COPY from the specific input Varnode
   * @param size is the number of COPYs (in sequence) from the same specific Varnode
   */
  private buildDominantCopy(high: HighVariable, copy: PcodeOp[], pos: number, size: number): void {
    const blockSet: FlowBlock[] = [];
    for (let i = 0; i < size; ++i)
      blockSet.push(copy[pos + i].getParent());
    const domBl: BlockBasic = (blockSet[0].constructor as any).findCommonBlock(blockSet);
    let domCopy: PcodeOp = copy[pos];
    const rootVn: Varnode = domCopy.getIn(0)!;
    let domVn: Varnode = domCopy.getOut()!;
    let domCopyIsNew: boolean;
    if (domBl === domCopy.getParent()) {
      domCopyIsNew = false;
    } else {
      domCopyIsNew = true;
      const oldCopy: PcodeOp = domCopy;
      domCopy = this.data.newOp(1, domBl.getStop());
      this.data.opSetOpcode(domCopy, OpCode.CPUI_COPY);
      let ct: Datatype = rootVn.getType();
      if (ct.needsResolution()) {
        const resUnion: ResolvedUnion | null = this.data.getUnionField(ct, oldCopy, 0);
        const fieldNum: number = resUnion === null ? -1 : resUnion.getFieldNum();
        this.data.forceFacingType(ct, fieldNum, domCopy, 0);
        this.data.forceFacingType(ct, fieldNum, domCopy, -1);
        if (ct.getMetatype() === 0 /* TYPE_PARTIALUNION */)
          ct = rootVn.getTypeReadFacing(oldCopy);
      }
      domVn = this.data.newUnique(rootVn.getSize(), ct);
      this.data.opSetOutput(domCopy, domVn);
      this.data.opSetInput(domCopy, rootVn, 0);
      this.data.opInsertEnd(domCopy, domBl);
    }

    // Cover created by removing all the COPYs from rootVn
    const bCover = new Cover();
    for (let i = 0; i < high.numInstances(); ++i) {
      const vn: Varnode = high.getInstance(i);
      if (vn.isWritten()) {
        const op: PcodeOp = vn.getDef()!;
        if (op.code() === OpCode.CPUI_COPY) {
          if (op.getIn(0)!.copyShadow(rootVn)) continue;
        }
      }
      bCover.merge(vn.getCover()!);
    }

    let count = size;
    for (let i = 0; i < size; ++i) {
      const op: PcodeOp = copy[pos + i];
      if (op === domCopy) continue;
      const outVn: Varnode = op.getOut()!;
      const aCover = new Cover();
      aCover.addDefPoint(domVn);
      for (let dIdx = outVn.beginDescend(); dIdx < outVn.endDescend(); ++dIdx)
        aCover.addRefPoint(outVn.getDescend(dIdx), outVn);
      if (bCover.intersect(aCover) > 1) {
        count -= 1;
        op.setMark();
      }
    }

    if (count <= 1) {
      for (let i = 0; i < size; ++i)
        copy[pos + i].setMark();
      count = 0;
      if (domCopyIsNew) {
        this.data.opDestroy(domCopy);
      }
    }

    // Replace all non-intersecting COPYs with read of dominating Varnode
    for (let i = 0; i < size; ++i) {
      const op: PcodeOp = copy[pos + i];
      if (op.isMark()) {
        op.clearMark();
      } else {
        const outVn: Varnode = op.getOut()!;
        if (outVn !== domVn) {
          outVn.getHigh().remove(outVn);
          this.data.totalReplace(outVn, domVn);
          this.data.opDestroy(op);
        }
      }
    }
    if (count > 0 && domCopyIsNew) {
      high.merge(domVn.getHigh(), null, true);
    }
  }

  /**
   * Search for and mark redundant COPY ops into the given high as non-printing.
   * @param high is the given HighVariable
   * @param copy is the list of COPYs coming from the same source HighVariable
   * @param pos is the starting index of a set of COPYs coming from the same Varnode
   * @param size is the number of Varnodes in the set coming from the same Varnode
   */
  private markRedundantCopies(high: HighVariable, copy: PcodeOp[], pos: number, size: number): void {
    for (let i = size - 1; i > 0; --i) {
      const subOp: PcodeOp = copy[pos + i];
      if (subOp.isDead()) continue;
      for (let j = i - 1; j >= 0; --j) {
        const domOp: PcodeOp = copy[pos + j];
        if (domOp.isDead()) continue;
        if (this.checkCopyPair(high, domOp, subOp)) {
          this.data.opMarkNonPrinting(subOp);
          break;
        }
      }
    }
  }

  /**
   * Try to replace COPYs into the given HighVariable with a single dominant COPY.
   * @param high is the given HighVariable
   */
  private processHighDominantCopy(high: HighVariable): void {
    const copyIns: PcodeOp[] = [];

    Merge.findAllIntoCopies(high, copyIns, true);
    if (copyIns.length < 2) return;
    let pos = 0;
    while (pos < copyIns.length) {
      const inVn: Varnode = copyIns[pos].getIn(0)!;
      let sz = 1;
      while (pos + sz < copyIns.length) {
        const nextVn: Varnode = copyIns[pos + sz].getIn(0)!;
        if (nextVn !== inVn) break;
        sz += 1;
      }
      if (sz > 1)
        this.buildDominantCopy(high, copyIns, pos, sz);
      pos += sz;
    }
  }

  /**
   * Mark COPY ops into the given HighVariable that are redundant.
   * @param high is the given HighVariable
   */
  processHighRedundantCopy(high: HighVariable): void {
    const copyIns: PcodeOp[] = [];

    Merge.findAllIntoCopies(high, copyIns, false);
    if (copyIns.length < 2) return;
    let pos = 0;
    while (pos < copyIns.length) {
      const inVn: Varnode = copyIns[pos].getIn(0)!;
      let sz = 1;
      while (pos + sz < copyIns.length) {
        const nextVn: Varnode = copyIns[pos + sz].getIn(0)!;
        if (nextVn !== inVn) break;
        sz += 1;
      }
      if (sz > 1) {
        this.markRedundantCopies(high, copyIns, pos, sz);
      }
      pos += sz;
    }
  }

  /**
   * Group the different nodes of a CONCAT tree into a VariableGroup.
   * @param vn is the root Varnode
   */
  private groupPartialRoot(vn: Varnode): void {
    const high: HighVariable = vn.getHigh();
    if (high.numInstances() !== 1) return;
    const pieces: PieceNode[] = [];

    let baseOffset = 0;
    const entry: SymbolEntry | null = vn.getSymbolEntry();
    if (entry !== null) {
      baseOffset = entry.getOffset();
    }

    PieceNode.gatherPieces(pieces, vn, vn.getDef()!, baseOffset, baseOffset);
    let throwOut = false;
    for (let i = 0; i < pieces.length; ++i) {
      const nodeVn: Varnode = pieces[i].getVarnode();
      if (!nodeVn.isProtoPartial() || nodeVn.getHigh().numInstances() !== 1) {
        throwOut = true;
        break;
      }
    }
    if (throwOut) {
      for (let i = 0; i < pieces.length; ++i)
        pieces[i].getVarnode().clearProtoPartial();
    } else {
      for (let i = 0; i < pieces.length; ++i) {
        const nodeVn: Varnode = pieces[i].getVarnode();
        nodeVn.getHigh().groupWith(pieces[i].getTypeOffset() - baseOffset, high);
      }
    }
  }

  // --- Public methods ---

  /** Clear any cached data from the last merge process */
  clear(): void {
    this.testCache.clear();
    this.copyTrims.length = 0;
    this.protoPartial.length = 0;
    this.stackAffectingOps.clear();
  }

  /**
   * Mark the given Varnode as implied.
   *
   * The covers of the immediate Varnodes involved in the expression are marked as dirty.
   * @param vn is the given Varnode being marked as implied
   */
  static markImplied(vn: Varnode): void {
    vn.setImplied();
    const op: PcodeOp = vn.getDef()!;
    for (let i = 0; i < op.numInput(); ++i) {
      const defvn: Varnode = op.getIn(i)!;
      if (!defvn.hasCover()) continue;
      defvn.setFlags(0x1000000 /* Varnode::coverdirty */);
    }
  }

  /**
   * Test if we can inflate the Cover of the given Varnode without incurring intersections.
   * @param a is the given Varnode to inflate
   * @param high is the HighVariable being propagated
   * @returns true if inflating the Varnode causes an intersection
   */
  inflateTest(a: Varnode, high: HighVariable): boolean {
    const ahigh: HighVariable = a.getHigh();

    this.testCache.updateHigh(high);
    const highCover: Cover = high._internalCover;

    for (let i = 0; i < ahigh.numInstances(); ++i) {
      const b: Varnode = ahigh.getInstance(i);
      if (b.copyShadow(a)) continue;
      if (2 === b.getCover()!.intersect(highCover)) {
        return true;
      }
    }
    const piece: VariablePiece | null = ahigh._piece;
    if (piece !== null) {
      piece.updateIntersections();
      for (let i = 0; i < piece.numIntersection(); ++i) {
        const otherPiece: VariablePiece = piece.getIntersection(i);
        const otherHigh: HighVariable = otherPiece.getHigh();
        const off: number = otherPiece.getOffset() - piece.getOffset();
        for (let j = 0; j < otherHigh.numInstances(); ++j) {
          const b: Varnode = otherHigh.getInstance(j);
          if (b.partialCopyShadow(a, off)) continue;
          if (2 === b.getCover()!.intersect(highCover))
            return true;
        }
      }
    }
    return false;
  }

  /**
   * Test for intersections between a given HighVariable and a list of other HighVariables.
   * @param high is the given HighVariable
   * @param tmplist is the list of HighVariables to test against
   * @returns true if there are no pairwise intersections
   */
  mergeTest(high: HighVariable, tmplist: HighVariable[]): boolean {
    if (!high.hasCover()) return false;

    for (let i = 0; i < tmplist.length; ++i) {
      const a: HighVariable = tmplist[i];
      if (this.testCache.intersection(a, high))
        return false;
    }
    tmplist.push(high);
    return true;
  }

  /**
   * Try to force merges of input to output for all p-code ops of a given type.
   * @param opc is the op-code type to merge
   */
  mergeOpcode(opc: OpCode): void {
    const bblocks: BlockGraph = this.data.getBasicBlocks();

    for (let i = 0; i < bblocks.getSize(); ++i) {
      const bl: BlockBasic = bblocks.getBlock(i);
      const endOp = bl.endOp();
      for (let iter = bl.beginOp(); !iter.equals(endOp); iter.next()) {
        const op: PcodeOp = iter.get();
        if (op.code() !== opc) continue;
        const vn1: Varnode | null = op.getOut();
        if (!Merge.mergeTestBasic(vn1)) continue;
        for (let j = 0; j < op.numInput(); ++j) {
          const vn2: Varnode | null = op.getIn(j);
          if (!Merge.mergeTestBasic(vn2)) continue;
          if (Merge.mergeTestRequired(vn1!.getHigh(), vn2!.getHigh()))
            this.mergePrivate(vn1!.getHigh(), vn2!.getHigh(), false);
        }
      }
    }
  }

  /**
   * Try to merge all HighVariables in the given range that have the same data-type.
   * @param startiter is the start of the given range of Varnodes
   * @param enditer is the end of the given range
   */
  mergeByDatatype(startiter: SortedSetIterator<Varnode>, enditer: SortedSetIterator<Varnode>): void {
    const highlist: HighVariable[] = [];

    const iter = startiter.clone();
    while (!iter.equals(enditer)) {
      const vn: Varnode = iter.get();
      iter.next();
      if (vn.isFree()) continue;
      const high: HighVariable = vn.getHigh();
      if (high.isMark()) continue;
      if (!Merge.mergeTestBasic(vn)) continue;
      high.setMark();
      highlist.push(high);
    }
    for (const h of highlist)
      h.clearMark();

    while (highlist.length > 0) {
      const highvec: HighVariable[] = [];
      const high: HighVariable = highlist[0];
      const ct: Datatype = high.getType();
      highvec.push(high);
      highlist.splice(0, 1);
      let idx = 0;
      while (idx < highlist.length) {
        const h: HighVariable = highlist[idx];
        if (ct === h.getType()) {
          highvec.push(h);
          highlist.splice(idx, 1);
        } else {
          ++idx;
        }
      }
      this.mergeLinear(highvec);
    }
  }

  /**
   * Force the merge of address tied Varnodes.
   *
   * For each set of address tied Varnodes with the same size and storage address, merge
   * them into a single HighVariable. The merges are forced, so any Cover intersections must
   * be resolved by altering data-flow.
   */
  mergeAddrTied(): void {
    let startiter: SortedSetIterator<Varnode> = this.data.beginLoc();
    const bounds: SortedSetIterator<Varnode>[] = [];
    while (!startiter.equals(this.data.endLoc())) {
      const spc: AddrSpace | null = startiter.get().getSpace();
      if (spc === null) {
        startiter.next();
        continue;
      }
      const type: number = spc.getType();
      if (type !== 1 /* IPTR_PROCESSOR */ && type !== 2 /* IPTR_SPACEBASE */) {
        startiter = this.data.endLoc(spc);
        continue;
      }
      const finaliter: SortedSetIterator<Varnode> = this.data.endLoc(spc);
      while (!startiter.equals(finaliter)) {
        const vn: Varnode = startiter.get();
        if (vn.isFree()) {
          startiter = this.data.endLocSizeAddrFlags(vn.getSize(), vn.getAddr(), 0);
          continue;
        }
        bounds.length = 0;
        const flags: number = this.data.overlapLoc(startiter, bounds);
        const max: number = bounds.length - 1;
        if ((flags & 0x8000 /* Varnode::addrtied */) !== 0) {
          this.unifyAddress(startiter, bounds[max]);
          for (let i = 0; i < max; i += 2) {
            this.mergeRangeMust(bounds[i], bounds[i + 1]);
          }
          if (max > 2) {
            const vn1: Varnode = bounds[0].get();
            for (let i = 2; i < max; i += 2) {
              const vn2: Varnode = bounds[i].get();
              const off: number = Number(vn2.getOffset() - vn1.getOffset());
              vn2.getHigh().groupWith(off, vn1.getHigh());
            }
          }
        }
        startiter = bounds[max];
      }
    }
  }

  /**
   * Force the merge of input and output Varnodes to MULTIEQUAL and INDIRECT ops.
   */
  mergeMarker(): void {
    const endAlive = this.data.endOpAlive();
    for (let iter = this.data.beginOpAlive(); !iter.equals(endAlive); iter.next()) {
      const op: PcodeOp = iter.get();
      if (!op.isMarker() || op.isIndirectCreation()) continue;
      if (op.code() === OpCode.CPUI_INDIRECT)
        this.mergeIndirect(op);
      else
        this.mergeOp(op);
    }
  }

  /**
   * Run through CONCAT tree roots and group each tree.
   */
  groupPartials(): void {
    for (let i = 0; i < this.protoPartial.length; ++i) {
      const op: PcodeOp = this.protoPartial[i];
      if (op.isDead()) continue;
      if (!op.isPartialRoot()) continue;
      this.groupPartialRoot(op.getOut()!);
    }
  }

  /**
   * Speculatively merge Varnodes that are input/output to the same p-code op.
   */
  mergeAdjacent(): void {
    const endAlive2 = this.data.endOpAlive();
    for (let oiter = this.data.beginOpAlive(); !oiter.equals(endAlive2); oiter.next()) {
      const op: PcodeOp = oiter.get();
      if (op.isCall()) continue;
      const vn1: Varnode | null = op.getOut();
      if (!Merge.mergeTestBasic(vn1)) continue;
      const high_out: HighVariable = vn1!.getHigh();
      const ct: Datatype = op.outputTypeLocal();
      for (let i = 0; i < op.numInput(); ++i) {
        if (ct !== op.inputTypeLocal(i)) continue;
        const vn2: Varnode | null = op.getIn(i);
        if (!Merge.mergeTestBasic(vn2)) continue;
        if (vn1!.getSize() !== vn2!.getSize()) continue;
        if (vn2!.getDef() === null && !vn2!.isInput()) continue;
        const high_in: HighVariable = vn2!.getHigh();
        if (!Merge.mergeTestAdjacent(high_out, high_in)) continue;

        if (!this.testCache.intersection(high_in, high_out))
          this.mergePrivate(high_out, high_in, true);
      }
    }
  }

  /**
   * Merge together Varnodes mapped to SymbolEntrys from the same Symbol.
   */
  mergeMultiEntry(): void {
    const multiIter = this.data.getScopeLocal().beginMultiEntry();
    let multiResult = multiIter.next();
    while (!multiResult.done) {
      const symbol = multiResult.value;
      const mergeList: Varnode[] = [];
      const numEntries: number = symbol.numEntries();
      let mergeCount = 0;
      let skipCount = 0;
      let conflictCount = 0;
      for (let i = 0; i < numEntries; ++i) {
        const prevSize: number = mergeList.length;
        const entry: SymbolEntry = symbol.getMapEntry(i);
        if (entry.getSize() !== symbol.getType().getSize())
          continue;
        this.data.findLinkedVarnodes(entry, mergeList);
        if (mergeList.length === prevSize)
          skipCount += 1;
      }
      if (mergeList.length === 0) {
        multiResult = multiIter.next();
        continue;
      }
      const high: HighVariable = mergeList[0].getHigh();
      this.testCache.updateHigh(high);
      for (let i = 0; i < mergeList.length; ++i) {
        const newHigh: HighVariable = mergeList[i].getHigh();
        if (newHigh === high) continue;
        this.testCache.updateHigh(newHigh);
        if (!Merge.mergeTestRequired(high, newHigh)) {
          symbol.setMergeProblems();
          newHigh.setUnmerged();
          conflictCount += 1;
          continue;
        }
        if (!this.mergePrivate(high, newHigh, false)) {
          symbol.setMergeProblems();
          newHigh.setUnmerged();
          conflictCount += 1;
          continue;
        }
        mergeCount += 1;
      }
      if (skipCount !== 0 || conflictCount !== 0) {
        let s = "Unable to";
        if (mergeCount !== 0)
          s += " fully";
        s += " merge symbol: " + symbol.getName();
        if (skipCount > 0)
          s += " -- Some instance varnodes not found.";
        if (conflictCount > 0)
          s += " -- Some merges are forbidden";
        this.data.warningHeader(s);
      }
      multiResult = multiIter.next();
    }
  }

  /**
   * Hide shadow Varnodes related to the given HighVariable by consolidating COPY chains.
   * @param high is the given HighVariable to search near
   * @returns true if a change was made to data-flow
   */
  hideShadows(high: HighVariable): boolean {
    const singlelist: (Varnode | null)[] = [];
    let res = false;

    Merge.findSingleCopy(high, singlelist as Varnode[]);
    if (singlelist.length <= 1) return false;
    for (let i = 0; i < singlelist.length - 1; ++i) {
      const vn1: Varnode | null = singlelist[i];
      if (vn1 === null) continue;
      for (let j = i + 1; j < singlelist.length; ++j) {
        const vn2: Varnode | null = singlelist[j];
        if (vn2 === null) continue;
        if (!vn1.copyShadow(vn2)) continue;
        if (vn2.getCover()!.containVarnodeDef(vn1) === 1) {
          this.data.opSetInput(vn1.getDef()!, vn2, 0);
          res = true;
          break;
        } else if (vn1.getCover()!.containVarnodeDef(vn2) === 1) {
          this.data.opSetInput(vn2.getDef()!, vn1, 0);
          singlelist[j] = null;
          res = true;
        }
      }
    }
    return res;
  }

  /**
   * Try to reduce/eliminate COPYs produced by the merge trimming process.
   */
  processCopyTrims(): void {
    const multiCopy: HighVariable[] = [];

    for (let i = 0; i < this.copyTrims.length; ++i) {
      const high: HighVariable = this.copyTrims[i].getOut()!.getHigh();
      if (!high.hasCopyIn1()) {
        multiCopy.push(high);
        high.setCopyIn1();
      } else {
        high.setCopyIn2();
      }
    }
    this.copyTrims.length = 0;
    for (let i = 0; i < multiCopy.length; ++i) {
      const high: HighVariable = multiCopy[i];
      if (high.hasCopyIn2())
        this.processHighDominantCopy(high);
      high.clearCopyIns();
    }
  }

  /**
   * Mark redundant/internal COPY PcodeOps.
   *
   * Run through all COPY, SUBPIECE, and PIECE operations and characterize those that are
   * internal (copy data between storage locations representing the same variable) or
   * redundant (perform the same copy as an earlier operation).
   */
  markInternalCopies(): void {
    const multiCopy: HighVariable[] = [];

    const endAlive3 = this.data.endOpAlive();
    for (let iter = this.data.beginOpAlive(); !iter.equals(endAlive3); iter.next()) {
      const op: PcodeOp = iter.get();
      switch (op.code()) {
        case OpCode.CPUI_COPY: {
          const v1: Varnode = op.getOut()!;
          const h1: HighVariable = v1.getHigh();
          if (h1 === op.getIn(0)!.getHigh()) {
            this.data.opMarkNonPrinting(op);
          } else {
            if (!h1.hasCopyIn1()) {
              h1.setCopyIn1();
              multiCopy.push(h1);
            } else {
              h1.setCopyIn2();
            }
            if (v1.hasNoDescend()) {
              if (Merge.shadowedVarnode(v1)) {
                this.data.opMarkNonPrinting(op);
              }
            }
          }
          break;
        }
        case OpCode.CPUI_PIECE: {
          const v1: Varnode = op.getOut()!;
          const v2: Varnode = op.getIn(0)!;
          const v3: Varnode = op.getIn(1)!;
          const p1: VariablePiece | null = v1.getHigh()._piece;
          const p2: VariablePiece | null = v2.getHigh()._piece;
          const p3: VariablePiece | null = v3.getHigh()._piece;
          if (p1 === null) break;
          if (p2 === null) break;
          if (p3 === null) break;
          if (p1.getGroup() !== p2.getGroup()) break;
          if (p1.getGroup() !== p3.getGroup()) break;
          if (v1.getSpace()!.isBigEndian()) {
            if (p2.getOffset() !== p1.getOffset()) break;
            if (p3.getOffset() !== p1.getOffset() + v2.getSize()) break;
          } else {
            if (p3.getOffset() !== p1.getOffset()) break;
            if (p2.getOffset() !== p1.getOffset() + v3.getSize()) break;
          }
          this.data.opMarkNonPrinting(op);
          if (v2.isImplied()) {
            v2.clearImplied();
            v2.setExplicit();
          }
          if (v3.isImplied()) {
            v3.clearImplied();
            v3.setExplicit();
          }
          break;
        }
        case OpCode.CPUI_SUBPIECE: {
          const v1: Varnode = op.getOut()!;
          const v2: Varnode = op.getIn(0)!;
          const p1: VariablePiece | null = v1.getHigh()._piece;
          const p2: VariablePiece | null = v2.getHigh()._piece;
          if (p1 === null) break;
          if (p2 === null) break;
          if (p1.getGroup() !== p2.getGroup()) break;
          const val: number = Number(op.getIn(1)!.getOffset());
          if (v1.getSpace()!.isBigEndian()) {
            if (p2.getOffset() + (v2.getSize() - v1.getSize() - val) !== p1.getOffset()) break;
          } else {
            if (p2.getOffset() + val !== p1.getOffset()) break;
          }
          this.data.opMarkNonPrinting(op);
          if (v2.isImplied()) {
            v2.clearImplied();
            v2.setExplicit();
          }
          break;
        }
        default:
          break;
      }
    }
    for (let i = 0; i < multiCopy.length; ++i) {
      const high: HighVariable = multiCopy[i];
      if (high.hasCopyIn2())
        this.data.getMerge().processHighRedundantCopy(high);
      high.clearCopyIns();
    }
  }

  /**
   * Register an unmapped CONCAT stack with the merge process.
   * @param vn is the given root Varnode
   */
  registerProtoPartialRoot(vn: Varnode): void {
    this.protoPartial.push(vn.getDef()!);
  }
}
