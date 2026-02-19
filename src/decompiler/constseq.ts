/**
 * @file constseq.ts
 * @description Classes for combining constants written to a contiguous region of memory.
 * Translated from Ghidra's constseq.hh / constseq.cc
 */

import { Address, calc_mask } from '../core/address.js';
import { OpCode } from '../core/opcodes.js';
import { AddrSpace, spacetype } from '../core/space.js';
import type { Datatype } from './type.js';
import { type_metatype } from './type.js';
import { ActionGroupList, Rule } from './action.js';

// ---------------------------------------------------------------------------
// Forward type declarations for types from not-yet-written modules
// ---------------------------------------------------------------------------

type Funcdata = any;
type PcodeOp = any;
type Varnode = any;
type BlockBasic = any;
type SymbolEntry = any;
type Architecture = any;
type TypeFactory = any;
type TypePointer = any;
type TypeArray = any;
type UserPcodeOp = any;
type VarnodeLocSet = any;
type SortedSetIterator<T> = any;

// ---------------------------------------------------------------------------
// WriteNode -- Helper class holding a data-flow edge and optionally a memory offset
// ---------------------------------------------------------------------------

/**
 * Helper class holding a data-flow edge and optionally a memory offset being COPYed into or from.
 */
export class WriteNode {
  /** Offset into the memory region */
  offset: bigint;
  /** PcodeOp moving into/outof memory region */
  op: PcodeOp;
  /** either input slot (>=0) or output (-1) */
  slot: number;

  constructor(off: bigint, o: PcodeOp, sl: number) {
    this.offset = off;
    this.op = o;
    this.slot = sl;
  }

  /**
   * Compare two nodes by their order within a basic block.
   */
  lessThan(node2: WriteNode): boolean {
    return this.op.getSeqNum().getOrder() < node2.op.getSeqNum().getOrder();
  }
}

// ---------------------------------------------------------------------------
// IndirectPair -- Helper class containing Varnode pairs that flow across a sequence of INDIRECTs
// ---------------------------------------------------------------------------

/**
 * Helper class containing Varnode pairs that flow across a sequence of INDIRECTs.
 */
class IndirectPair {
  /** Input to INDIRECTs */
  inVn: Varnode | null;
  /** Output of INDIRECTs */
  outVn: Varnode;

  constructor(inV: Varnode, outV: Varnode) {
    this.inVn = inV;
    this.outVn = outV;
  }

  /** Note that this is a duplicate of another pair */
  markDuplicate(): void {
    this.inVn = null;
  }

  /** Return true if this is marked as a duplicate */
  isDuplicate(): boolean {
    return this.inVn === null;
  }

  /** Compare pairs by output storage */
  static compareOutput(a: IndirectPair, b: IndirectPair): number {
    const vn1 = a.outVn;
    const vn2 = b.outVn;
    if (vn1.getSpace() !== vn2.getSpace()) {
      const idx1 = vn1.getSpace() !== null ? vn1.getSpace().getIndex() : -1;
      const idx2 = vn2.getSpace() !== null ? vn2.getSpace().getIndex() : -1;
      return idx1 < idx2 ? -1 : 1;
    }
    if (vn1.getOffset() !== vn2.getOffset()) {
      return vn1.getOffset() < vn2.getOffset() ? -1 : 1;
    }
    if (vn1.getSize() !== vn2.getSize()) {
      return vn1.getSize() < vn2.getSize() ? -1 : 1;
    }
    return 0;
  }
}

// ---------------------------------------------------------------------------
// ArraySequence
// ---------------------------------------------------------------------------

/**
 * A sequence of PcodeOps that move data in-to/out-of an array data-type.
 *
 * A container for a sequence of PcodeOps within a basic block where we are trying to determine if the sequence
 * can be replaced with a single memcpy style user-op.
 */
export class ArraySequence {
  /** Minimum number of sequential characters to trigger replacement with CALLOTHER */
  static readonly MINIMUM_SEQUENCE_LENGTH: number = 4;
  /** Maximum number of characters in replacement string */
  static readonly MAXIMUM_SEQUENCE_LENGTH: number = 0x20000;

  /** The function containing the sequence */
  protected data: Funcdata;
  /** The root PcodeOp */
  protected rootOp: PcodeOp;
  /** Element data-type */
  protected charType: Datatype;
  /** Basic block containing all the COPY/STORE ops */
  protected block: BlockBasic;
  /** Number of elements in the final sequence */
  protected numElements: number;
  /** COPY/STORE into the array memory region */
  protected moveOps: WriteNode[];
  /** Constants collected in a single array */
  protected byteArray: number[];

  /**
   * Constructor
   * @param fdata is the function containing the sequence
   * @param ct is the data-type of an element in the array
   * @param root is the PcodeOp to be interpreted as the root, copying the earliest element
   */
  constructor(fdata: Funcdata, ct: Datatype, root: PcodeOp) {
    this.data = fdata;
    this.rootOp = root;
    this.charType = ct;
    this.block = root.getParent();
    this.numElements = 0;
    this.moveOps = [];
    this.byteArray = [];
  }

  /** Return true if sequence is found */
  isValid(): boolean {
    return this.numElements !== 0;
  }

  /**
   * Check for interfering ops between the two given ops.
   * The output Varnodes themselves should be verified to only be read outside of the basic block.
   * So effectively only LOADs, STOREs, and CALLs can really interfere.
   * @param startOp is the starting op to check
   * @param endOp is the ending op
   * @returns true if there is no interference, false if there is possible interference
   */
  protected static interfereBetween(startOp: PcodeOp, endOp: PcodeOp): boolean {
    let cur: PcodeOp | null = startOp.nextOp();
    while (cur !== endOp) {
      if (cur.getEvalType() === 0x20000) {  // PcodeOp.special
        const opc: OpCode = cur.code();
        if (opc !== OpCode.CPUI_INDIRECT && opc !== OpCode.CPUI_CALLOTHER &&
          opc !== OpCode.CPUI_SEGMENTOP && opc !== OpCode.CPUI_CPOOLREF && opc !== OpCode.CPUI_NEW) {
          return false;
        }
      }
      cur = cur.nextOp();
    }
    return true;
  }

  /**
   * Find maximal set of ops containing the root with no interfering ops in between.
   * Sort the ops based on block order. Starting with the root op, walk backward until an interfering
   * gap is found or until the earliest op is reached. Similarly, walk forward until an interfering gap is found.
   * Truncate the op array to be this smaller set.
   * @returns true if a maximal set of ops is found containing at the least the minimum number required
   */
  protected checkInterference(): boolean {
    this.moveOps.sort((a, b) => a.lessThan(b) ? -1 : (b.lessThan(a) ? 1 : 0));
    let pos: number;
    for (pos = 0; pos < this.moveOps.length; ++pos) {
      if (this.moveOps[pos].op === this.rootOp) break;
    }
    if (pos === this.moveOps.length) return false;
    let curOp: PcodeOp = this.moveOps[pos].op;
    let startingPos: number;
    let endingPos: number;
    for (startingPos = pos - 1; startingPos >= 0; --startingPos) {
      const prevOp: PcodeOp = this.moveOps[startingPos].op;
      if (!ArraySequence.interfereBetween(prevOp, curOp))
        break;
      curOp = prevOp;
    }
    startingPos += 1;
    curOp = this.moveOps[pos].op;
    for (endingPos = pos + 1; endingPos < this.moveOps.length; ++endingPos) {
      const nextOp: PcodeOp = this.moveOps[endingPos].op;
      if (!ArraySequence.interfereBetween(curOp, nextOp))
        break;
      curOp = nextOp;
    }
    if (endingPos - startingPos < ArraySequence.MINIMUM_SEQUENCE_LENGTH)
      return false;
    if (startingPos > 0) {
      for (let i = startingPos; i < endingPos; ++i) {
        this.moveOps[i - startingPos] = this.moveOps[i];
      }
    }
    this.moveOps.length = endingPos - startingPos;
    return true;
  }

  /**
   * Put constant values from COPYs into a single byte array.
   * Create an array of bytes being written into the memory region.
   * Run through the ops and place their constant input (at given slot) into the array based on their
   * offset, relative to the given root offset.
   * @param sz is the maximum size of the byte array
   * @param slot is the slot to fetch input constants from
   * @param rootOff is the root offset
   * @param bigEndian is true if constant inputs have big endian encoding
   * @returns the number of characters in the contiguous region
   */
  protected formByteArray(sz: number, slot: number, rootOff: bigint, bigEndian: boolean): number {
    this.byteArray = new Array<number>(sz).fill(0);
    const used: number[] = new Array<number>(sz).fill(0);
    const elSize: number = this.charType.getSize();
    for (let i = 0; i < this.moveOps.length; ++i) {
      const bytePos: number = Number(this.moveOps[i].offset - rootOff);
      if (bytePos < 0 || bytePos + elSize > sz) continue;
      let val: bigint = this.moveOps[i].op.getIn(slot).getOffset();
      used[bytePos] = (val === 0n) ? 2 : 1;   // Mark byte as used, a 2 indicates a null terminator
      if (bigEndian) {
        for (let j = 0; j < elSize; ++j) {
          const b: number = Number((val >> BigInt((elSize - 1 - j) * 8)) & 0xFFn);
          this.byteArray[bytePos + j] = b;
        }
      } else {
        for (let j = 0; j < elSize; ++j) {
          this.byteArray[bytePos + j] = Number(val & 0xFFn);
          val >>= 8n;
        }
      }
    }
    const bigElSize: number = this.charType.getAlignSize();
    const maxEl: number = Math.floor(used.length / bigElSize);
    let count: number;
    for (count = 0; count < maxEl; count += 1) {
      const val: number = used[count * bigElSize];
      if (val !== 1) {      // Count number of characters not including null terminator
        if (val === 2)
          count += 1;       // Allow a single null terminator
        break;
      }
    }
    if (count < ArraySequence.MINIMUM_SEQUENCE_LENGTH)
      return 0;
    if (count !== this.moveOps.length) {
      const maxOff: bigint = rootOff + BigInt(count * bigElSize);
      const finalOps: WriteNode[] = [];
      for (let i = 0; i < this.moveOps.length; ++i) {
        if (this.moveOps[i].offset < maxOff)
          finalOps.push(this.moveOps[i]);
      }
      this.moveOps = finalOps;
    }
    return count;
  }

  /**
   * Pick either strncpy, wcsncpy, or memcpy function used to copy string.
   * Use the charType to select the appropriate string copying function. If a match to the charType
   * doesn't exist, use a built-in memcpy function. The id of the selected built-in function is returned.
   * @param index will hold the number of elements being copied (passed as { val: number })
   * @returns the id of the selected built-in function
   */
  protected selectStringCopyFunction(index: { val: number }): number {
    const types: TypeFactory = this.data.getArch().types;
    if (this.charType === types.getTypeChar(types.getSizeOfChar())) {
      index.val = this.numElements;
      return 0x10000004;  // UserPcodeOp.BUILTIN_STRNCPY
    } else if (this.charType === types.getTypeChar(types.getSizeOfWChar())) {
      index.val = this.numElements;
      return 0x10000005;  // UserPcodeOp.BUILTIN_WCSNCPY
    }
    index.val = this.numElements * this.charType.getAlignSize();
    return 0x10000003;    // UserPcodeOp.BUILTIN_MEMCPY
  }
}

// ---------------------------------------------------------------------------
// StringSequence
// ---------------------------------------------------------------------------

/**
 * A class for collecting sequences of COPY ops writing characters to the same string.
 *
 * Given a starting Address and a Symbol with a character array as a component, a class instance collects
 * a maximal set of COPY ops that can be treated as writing a single string into memory. Then, if the
 * transform() method is called, an explicit string is constructed, and the COPYs are replaced with a
 * strncpy or similar CALLOTHER that takes the string as its source input.
 */
export class StringSequence extends ArraySequence {
  /** Address within the memory region associated with the root PcodeOp */
  private rootAddr: Address;
  /** Starting address of the memory region */
  private startAddr: Address;
  /** Symbol at the root Address */
  private entry: SymbolEntry;

  /**
   * Constructor
   * @param fdata is the function containing the root COPY
   * @param ct is the specific data-type for which there should be an array
   * @param ent is the given Symbol
   * @param root is the COPY holding the constant
   * @param addr is the Address being COPYed into
   */
  constructor(fdata: Funcdata, ct: Datatype, ent: SymbolEntry, root: PcodeOp, addr: Address) {
    super(fdata, ct, root);
    this.rootAddr = new Address(addr);
    this.startAddr = new Address();
    this.entry = ent;
    if (this.entry.getAddr().getSpace() !== addr.getSpace())
      return;
    const off: bigint = this.rootAddr.getOffset() - BigInt(this.entry.getFirst());
    if (off >= BigInt(this.entry.getSize()))
      return;
    if (this.rootOp.getIn(0).getOffset() === 0n)
      return;
    let parentType: Datatype = this.entry.getSymbol().getType();
    let arrayType: Datatype | null = null;
    let lastOff: bigint = 0n;
    const newoff: { val: bigint } = { val: 0n };
    let curOff: bigint = off;
    do {
      if (parentType === ct)
        break;
      arrayType = parentType;
      lastOff = curOff;
      parentType = parentType.getSubType(curOff, newoff)!;
      curOff = newoff.val;
    } while (parentType !== null);
    if (parentType !== ct || arrayType === null || arrayType.getMetatype() !== type_metatype.TYPE_ARRAY)
      return;
    this.startAddr = this.rootAddr.subtract(lastOff);
    if (!this.collectCopyOps(arrayType.getSize()))
      return;
    if (!this.checkInterference())
      return;
    const arrSize: number = arrayType.getSize() - Number(this.rootAddr.getOffset() - this.startAddr.getOffset());
    this.numElements = this.formByteArray(arrSize, 0, this.rootAddr.getOffset(), this.rootAddr.isBigEndian());
  }

  /**
   * Collect ops COPYing constants into the memory region.
   * The COPYs must be in the same basic block.
   * If any COPY size does not match the copyType, return false.
   * @param size is the number of bytes in the memory region
   * @returns true to indicate legal COPY ops of constants were recovered
   */
  private collectCopyOps(size: number): boolean {
    const endAddr: Address = this.startAddr.add(BigInt(size - 1));
    let beginAddr: Address = new Address(this.startAddr);
    if (!this.startAddr.equals(this.rootAddr)) {
      beginAddr = this.rootAddr.subtract(BigInt(this.charType.getAlignSize()));
    }
    const iter: SortedSetIterator<Varnode> = this.data.beginLoc(beginAddr);
    const enditer: SortedSetIterator<Varnode> = this.data.endLoc(endAddr);
    let diff: bigint = this.rootAddr.getOffset() - this.startAddr.getOffset();
    while (!iter.equals(enditer)) {
      const vn: Varnode = iter.value;
      iter.next();
      if (!vn.isWritten()) continue;
      const op: PcodeOp = vn.getDef();
      if (op.code() !== OpCode.CPUI_COPY) continue;
      if (op.getParent() !== this.block) continue;
      if (!op.getIn(0).isConstant()) continue;
      if (vn.getSize() !== this.charType.getSize())
        return false;     // COPY is the wrong size (has yet to be split)
      const tmpDiff: bigint = vn.getOffset() - this.startAddr.getOffset();
      if (tmpDiff < diff) {
        if (tmpDiff + BigInt(this.charType.getAlignSize()) === diff)
          return false;   // COPY to previous element, rootVn is not the first in sequence
        continue;
      } else if (tmpDiff > diff) {
        if (tmpDiff - diff < BigInt(this.charType.getAlignSize()))
          continue;
        if (tmpDiff - diff > BigInt(this.charType.getAlignSize()))
          break;          // Gap in COPYs
        diff = tmpDiff;   // Advanced by one character
      }
      this.moveOps.push(new WriteNode(vn.getOffset(), op, -1));
    }
    return (this.moveOps.length >= ArraySequence.MINIMUM_SEQUENCE_LENGTH);
  }

  /**
   * Construct a Varnode, with data-type, that acts as a pointer (in)to the Symbol to the root Address.
   *
   * First, a PTRSUB is built from the base register to the Symbol. Then depending on its data-type, additional
   * PTRSUBs and PTRADDs are built to get from the start of the Symbol to the memory region holding the character data.
   * @param insertPoint is the point before which all new PTRSUBs and PTRADDs are inserted
   * @returns the Varnode holding the pointer to the memory region
   */
  private constructTypedPointer(insertPoint: PcodeOp): Varnode {
    let spacePtr: Varnode;
    const spc: AddrSpace = this.rootAddr.getSpace()!;
    const types: TypeFactory = this.data.getArch().types;
    if (spc.getType() === spacetype.IPTR_SPACEBASE)
      spacePtr = this.data.constructSpacebaseInput(spc);
    else
      spacePtr = this.data.constructConstSpacebase(spc);
    let baseType: Datatype = this.entry.getSymbol().getType();
    let ptrsub: PcodeOp = this.data.newOp(2, insertPoint.getAddr());
    this.data.opSetOpcode(ptrsub, OpCode.CPUI_PTRSUB);
    this.data.opSetInput(ptrsub, spacePtr, 0);
    let baseOff: bigint = AddrSpace.byteToAddress(BigInt(this.entry.getFirst()), spc.getWordSize());
    this.data.opSetInput(ptrsub, this.data.newConstant(spacePtr.getSize(), baseOff), 1);
    spacePtr = this.data.newUniqueOut(spacePtr.getSize(), ptrsub);
    this.data.opInsertBefore(ptrsub, insertPoint);
    let curType: TypePointer = types.getTypePointerStripArray(spacePtr.getSize(), baseType, spc.getWordSize());
    spacePtr.updateType(curType);
    let curOff: bigint = this.rootAddr.getOffset() - BigInt(this.entry.getFirst());
    const newoff: { val: bigint } = { val: 0n };
    while (baseType !== this.charType) {
      let elSize: number = -1;
      if (baseType.getMetatype() === type_metatype.TYPE_ARRAY)
        elSize = (baseType as TypeArray).getBase().getAlignSize();
      baseType = baseType.getSubType(curOff, newoff)!;
      const newOff = newoff.val;
      if (baseType === null) break;
      curOff -= newOff;
      baseOff = AddrSpace.byteToAddress(curOff, spc.getWordSize());
      if (elSize >= 0) {
        if (curOff === 0n) {    // Don't create a PTRADD( #0, ...)
          // spacePtr already has data-type with ARRAY stripped
          // baseType is already updated
          curOff = newOff;
          continue;
        }
        ptrsub = this.data.newOp(3, insertPoint.getAddr());
        this.data.opSetOpcode(ptrsub, OpCode.CPUI_PTRADD);
        const numEl: bigint = curOff / BigInt(elSize);
        this.data.opSetInput(ptrsub, this.data.newConstant(4, numEl), 1);
        this.data.opSetInput(ptrsub, this.data.newConstant(4, BigInt(elSize)), 2);
      } else {
        ptrsub = this.data.newOp(2, insertPoint.getAddr());
        this.data.opSetOpcode(ptrsub, OpCode.CPUI_PTRSUB);
        this.data.opSetInput(ptrsub, this.data.newConstant(spacePtr.getSize(), baseOff), 1);
      }
      this.data.opSetInput(ptrsub, spacePtr, 0);
      spacePtr = this.data.newUniqueOut(spacePtr.getSize(), ptrsub);
      this.data.opInsertBefore(ptrsub, insertPoint);
      curType = types.getTypePointerStripArray(spacePtr.getSize(), baseType, spc.getWordSize());
      spacePtr.updateType(curType);
      curOff = newOff;
    }
    if (curOff !== 0n) {
      const addOp: PcodeOp = this.data.newOp(2, insertPoint.getAddr());
      this.data.opSetOpcode(addOp, OpCode.CPUI_INT_ADD);
      this.data.opSetInput(addOp, spacePtr, 0);
      baseOff = AddrSpace.byteToAddress(curOff, spc.getWordSize());
      this.data.opSetInput(addOp, this.data.newConstant(spacePtr.getSize(), baseOff), 1);
      spacePtr = this.data.newUniqueOut(spacePtr.getSize(), addOp);
      this.data.opInsertBefore(addOp, insertPoint);
      curType = types.getTypePointer(spacePtr.getSize(), this.charType, spc.getWordSize());
      spacePtr.updateType(curType);
    }
    return spacePtr;
  }

  /**
   * Build the strncpy, wcsncpy, or memcpy function with string as input.
   *
   * A built-in user-op that copies string data is created. Its first (destination) parameter is constructed
   * as a pointer to the array holding the character data. The second (source) parameter is an internal string
   * constructed from the byteArray. The third parameter is the constant indicating the length of the string.
   * @returns the constructed PcodeOp representing the memcpy
   */
  private buildStringCopy(): PcodeOp | null {
    const insertPoint: PcodeOp = this.moveOps[0].op;   // Earliest COPY in the block
    const numBytes: number = this.moveOps.length * this.charType.getSize();
    const glb: Architecture = this.data.getArch();
    const types: TypeFactory = glb.types;
    const charPtrType: Datatype = types.getTypePointer(
      types.getSizeOfPointer(), this.charType, this.rootAddr.getSpace()!.getWordSize()
    );
    const srcPtr: Varnode | null = this.data.getInternalString(this.byteArray, numBytes, charPtrType, insertPoint);
    if (srcPtr === null)
      return null;
    const index: { val: number } = { val: 0 };
    const builtInId: number = this.selectStringCopyFunction(index);
    glb.userops.registerBuiltin(builtInId);
    const copyOp: PcodeOp = this.data.newOp(4, insertPoint.getAddr());
    this.data.opSetOpcode(copyOp, OpCode.CPUI_CALLOTHER);
    this.data.opSetInput(copyOp, this.data.newConstant(4, BigInt(builtInId)), 0);
    const destPtr: Varnode = this.constructTypedPointer(insertPoint);
    this.data.opSetInput(copyOp, destPtr, 1);
    this.data.opSetInput(copyOp, srcPtr, 2);
    const lenVn: Varnode = this.data.newConstant(4, BigInt(index.val));
    lenVn.updateType(copyOp.inputTypeLocal(3));
    this.data.opSetInput(copyOp, lenVn, 3);
    this.data.opInsertBefore(copyOp, insertPoint);
    return copyOp;
  }

  /**
   * Analyze output descendants of the given PcodeOp being removed.
   *
   * Record any points where the output is being read, for later replacement.
   * Keep track of CPUI_PIECE ops whose input is from a PcodeOp being removed, and if both inputs are
   * visited, remove the input points and add the CPUI_PIECE to the list of PcodeOps being removed.
   * @param curNode is the given PcodeOp being removed
   * @param xref are the set of CPUI_PIECE ops with one input visited
   * @param points is the set of input points whose PcodeOp is being removed
   * @param deadOps is the current collection of PcodeOps being removed
   */
  private static removeForward(
    curNode: WriteNode,
    xref: Map<PcodeOp, number>,
    points: WriteNode[],
    deadOps: WriteNode[]
  ): void {
    const vn: Varnode = curNode.op.getOut();
    const endIdx: number = vn.endDescend();
    for (let di = vn.beginDescend(); di < endIdx; ++di) {
      const op: PcodeOp = vn.getDescend(di);
      const existingIdx = xref.get(op);
      if (existingIdx !== undefined) {
        // We have seen the PIECE twice
        let off: bigint = points[existingIdx].offset;
        if (curNode.offset < off)
          off = curNode.offset;
        // Remove from points by marking as deleted (set op to null)
        points[existingIdx] = null!;  // Will be filtered later
        deadOps.push(new WriteNode(off, op, -1));
      } else {
        const slot: number = op.getSlot(vn);
        const idx = points.length;
        points.push(new WriteNode(curNode.offset, op, slot));
        if (op.code() === OpCode.CPUI_PIECE) {
          xref.set(op, idx);
        }
      }
    }
  }

  /**
   * Remove all the COPY ops from the basic block.
   *
   * The COPY ops are removed. Any descendants of the COPY output are redefined with an INDIRECT around
   * the CALLOTHER op. If the COPYs feed into a PIECE op (as part of a CONCAT stack), the PIECE is removed
   * as well, which may cascade into removal of other PIECE ops in the stack.
   * @param replaceOp is the CALLOTHER op creating the INDIRECT effect
   */
  private removeCopyOps(replaceOp: PcodeOp): void {
    const concatSet: Map<PcodeOp, number> = new Map();
    const points: WriteNode[] = [];
    const deadOps: WriteNode[] = [];
    for (let i = 0; i < this.moveOps.length; ++i) {
      StringSequence.removeForward(this.moveOps[i], concatSet, points, deadOps);
    }
    let pos = 0;
    while (pos < deadOps.length) {
      StringSequence.removeForward(deadOps[pos], concatSet, points, deadOps);
      pos += 1;
    }
    for (let i = 0; i < points.length; ++i) {
      const point = points[i];
      if (point === null) continue;   // Was removed during PIECE deduplication
      const op: PcodeOp = point.op;
      const vn: Varnode = op.getIn(point.slot);
      if (vn.getDef().code() !== OpCode.CPUI_INDIRECT) {
        const newIn: Varnode = this.data.newConstant(vn.getSize(), 0n);
        const indOp: PcodeOp = this.data.newOp(2, replaceOp.getAddr());
        this.data.opSetOpcode(indOp, OpCode.CPUI_INDIRECT);
        this.data.opSetInput(indOp, newIn, 0);
        this.data.opSetInput(indOp, this.data.newVarnodeIop(replaceOp), 1);
        this.data.opSetOutput(indOp, vn);
        this.data.markIndirectCreation(indOp, false);
        this.data.opInsertBefore(indOp, replaceOp);
      }
    }
    for (let i = 0; i < this.moveOps.length; ++i)
      this.data.opDestroy(this.moveOps[i].op);
    for (let i = 0; i < deadOps.length; ++i)
      this.data.opDestroy(deadOps[i].op);
  }

  /**
   * Transform COPYs into a single memcpy user-op.
   *
   * The transform can only fail if the byte array does not encode a valid string, in which case false is returned.
   * Otherwise, a CALLOTHER representing memcpy is constructed taking the string constant as its source pointer.
   * The original COPY ops are removed.
   * @returns true if the transform succeeded and the CALLOTHER is created
   */
  transform(): boolean {
    const memCpyOp: PcodeOp | null = this.buildStringCopy();
    if (memCpyOp === null)
      return false;
    this.removeCopyOps(memCpyOp);
    return true;
  }
}

// ---------------------------------------------------------------------------
// HeapSequence
// ---------------------------------------------------------------------------

/**
 * A sequence of STORE operations writing characters through the same string pointer.
 *
 * Given an initial STORE, a class instance collects a maximal set of STORE ops that can be treated as writing
 * a single string into memory. If the transform() method is called, an explicit string is constructed, and
 * the STOREs are replaced with a strncpy or similar CALLOTHER that takes the string as its source input.
 */
export class HeapSequence extends ArraySequence {
  /** Pointer that sequence is stored to */
  private basePointer: Varnode;
  /** Offset relative to pointer to root STORE */
  private baseOffset: bigint;
  /** Address space being STOREed to */
  private storeSpace: AddrSpace;
  /** Required multiplier for PTRADD ops */
  private ptrAddMult: number;
  /** non-constant Varnodes being added into pointer calculation */
  private nonConstAdds: Varnode[];

  /**
   * Constructor for the sequence of STORE ops.
   *
   * From a given STORE op, construct the sequence of STOREs off of the same root pointer.
   * The STOREs must be in the same basic block. They can be out of order but must fill out a contiguous
   * region of memory with a minimum number of character elements.
   * @param fdata is the function containing the sequence
   * @param ct is the character data-type being STOREd
   * @param root is the given (putative) initial STORE in the sequence
   */
  constructor(fdata: Funcdata, ct: Datatype, root: PcodeOp) {
    super(fdata, ct, root);
    this.basePointer = null!;
    this.baseOffset = 0n;
    this.storeSpace = root.getIn(0).getSpaceFromConst();
    this.ptrAddMult = Number(AddrSpace.byteToAddressInt(BigInt(this.charType.getAlignSize()), this.storeSpace.getWordSize()));
    this.nonConstAdds = [];
    this.findBasePointer(this.rootOp.getIn(1));
    if (!this.collectStoreOps())
      return;
    if (!this.checkInterference())
      return;
    const arrSize: number = this.moveOps.length * this.charType.getAlignSize();
    const bigEndian: boolean = this.storeSpace.isBigEndian();
    this.numElements = this.formByteArray(arrSize, 2, 0n, bigEndian);
  }

  /**
   * Find the base pointer for the sequence.
   * From a starting pointer, backtrack through PTRADDs and COPYs to a putative root Varnode pointer.
   * @param initPtr is pointer Varnode into the root STORE
   */
  private findBasePointer(initPtr: Varnode): void {
    this.basePointer = initPtr;
    while (this.basePointer.isWritten()) {
      const op: PcodeOp = this.basePointer.getDef();
      const opc: OpCode = op.code();
      if (opc === OpCode.CPUI_PTRADD) {
        const sz: bigint = op.getIn(2).getOffset();
        if (Number(sz) !== this.ptrAddMult) break;
      } else if (opc !== OpCode.CPUI_COPY) {
        break;
      }
      this.basePointer = op.getIn(0);
    }
  }

  /**
   * Find any duplicates of basePointer.
   *
   * Back-track from basePointer through PTRSUBs, PTRADDs, and INT_ADDs to an earlier root, keeping track
   * of any offsets. If an earlier root exists, trace forward, through ops trying to match the offsets.
   * @param duplist will hold the list of duplicate Varnodes (including basePointer)
   */
  private findDuplicateBases(duplist: Varnode[]): void {
    if (!this.basePointer.isWritten()) {
      duplist.push(this.basePointer);
      return;
    }
    let op: PcodeOp = this.basePointer.getDef();
    let opc: OpCode = op.code();
    if ((opc !== OpCode.CPUI_PTRSUB && opc !== OpCode.CPUI_INT_ADD && opc !== OpCode.CPUI_PTRADD) || !op.getIn(1).isConstant()) {
      duplist.push(this.basePointer);
      return;
    }
    let copyRoot: Varnode = this.basePointer;
    const offset: bigint[] = [];
    do {
      let off: bigint = op.getIn(1).getOffset();
      if (opc === OpCode.CPUI_PTRADD)
        off *= op.getIn(2).getOffset();
      offset.push(off);
      copyRoot = op.getIn(0);
      if (!copyRoot.isWritten()) break;
      op = copyRoot.getDef();
      opc = op.code();
      if ((opc as number) !== (OpCode.CPUI_PTRSUB as number) && (opc as number) !== (OpCode.CPUI_INT_ADD as number) && (opc as number) !== (OpCode.CPUI_PTRADD as number))
        break;
    } while (op.getIn(1).isConstant());

    duplist.push(copyRoot);
    let midlist: Varnode[] = [];
    for (let i = offset.length - 1; i >= 0; --i) {
      midlist = [...duplist];
      duplist.length = 0;
      for (let j = 0; j < midlist.length; ++j) {
        const vn: Varnode = midlist[j];
        const endIdx: number = vn.endDescend();
        for (let di = vn.beginDescend(); di < endIdx; ++di) {
          op = vn.getDescend(di);
          opc = op.code();
          if ((opc as number) !== (OpCode.CPUI_PTRSUB as number) && (opc as number) !== (OpCode.CPUI_INT_ADD as number) && (opc as number) !== (OpCode.CPUI_PTRADD as number))
            continue;
          if (op.getIn(0) !== vn || !op.getIn(1).isConstant())
            continue;
          let off: bigint = op.getIn(1).getOffset();
          if ((opc as number) === (OpCode.CPUI_PTRADD as number))
            off *= op.getIn(2).getOffset();
          if (off !== offset[i])
            continue;
          duplist.push(op.getOut());
        }
      }
    }
  }

  /**
   * Find STOREs with pointers derived from the basePointer and that are in the same
   * basic block as the root STORE. The root STORE is not included in the resulting set.
   * @param stores holds the collected STOREs
   */
  private findInitialStores(stores: PcodeOp[]): void {
    const ptradds: Varnode[] = [];
    this.findDuplicateBases(ptradds);
    let pos = 0;
    while (pos < ptradds.length) {
      const vn: Varnode = ptradds[pos];
      pos += 1;
      const endIdx: number = vn.endDescend();
      for (let di = vn.beginDescend(); di < endIdx; ++di) {
        const op: PcodeOp = vn.getDescend(di);
        const opc: OpCode = op.code();
        if (opc === OpCode.CPUI_PTRADD) {
          if (op.getIn(0) !== vn) continue;
          if (Number(op.getIn(2).getOffset()) !== this.ptrAddMult) continue;
          ptradds.push(op.getOut());
        } else if (opc === OpCode.CPUI_COPY) {
          ptradds.push(op.getOut());
        } else if (opc === OpCode.CPUI_STORE && op.getParent() === this.block && op !== this.rootOp) {
          if (op.getIn(1) !== vn) continue;
          stores.push(op);
        }
      }
    }
  }

  /**
   * Recursively walk an ADD tree from a given root, collecting offsets and non-constant elements.
   *
   * The constant offsets are returned as a final summed offset. Any non-constant Varnodes encountered are
   * passed back in a list.
   * @param vn is the given root of ADD tree
   * @param nonConst will hold the list of non-constant Varnodes in the tree
   * @param maxDepth is the maximum recursion depth
   * @returns the sum of all constant offsets
   */
  private static calcAddElements(vn: Varnode, nonConst: Varnode[], maxDepth: number): bigint {
    if (vn.isConstant())
      return vn.getOffset();
    if (!vn.isWritten() || vn.getDef().code() !== OpCode.CPUI_INT_ADD || maxDepth === 0) {
      nonConst.push(vn);
      return 0n;
    }
    let res: bigint = HeapSequence.calcAddElements(vn.getDef().getIn(0), nonConst, maxDepth - 1);
    res += HeapSequence.calcAddElements(vn.getDef().getIn(1), nonConst, maxDepth - 1);
    return res;
  }

  /**
   * Calculate the byte offset and any non-constant additive elements between the given Varnode and the basePointer.
   *
   * Walk backward from the given Varnode thru PTRADDs and COPYs, summing any offsets encountered.
   * @param vn is the given Varnode to trace back to the basePointer
   * @param nonConst will hold the list of non-constant Varnodes being passed back
   * @returns the sum of constant offsets on the path in byte units
   */
  private calcPtraddOffset(vn: Varnode, nonConst: Varnode[]): bigint {
    let res: bigint = 0n;
    while (vn.isWritten()) {
      const op: PcodeOp = vn.getDef();
      const opc: OpCode = op.code();
      if (opc === OpCode.CPUI_PTRADD) {
        const mult: bigint = op.getIn(2).getOffset();
        if (Number(mult) !== this.ptrAddMult)
          break;
        let off: bigint = HeapSequence.calcAddElements(op.getIn(1), nonConst, 3);
        off *= mult;
        res += off;
        vn = op.getIn(0);
      } else if (opc === OpCode.CPUI_COPY) {
        vn = op.getIn(0);
      } else {
        break;
      }
    }
    return AddrSpace.addressToByteInt(res, this.storeSpace.getWordSize());
  }

  /**
   * Determine if two sets of Varnodes are equal.
   *
   * The sets are passed in as arrays that are assumed sorted.
   * @param op1 is the first set
   * @param op2 is the second set
   * @returns true if and only if the sets are equal
   */
  private static setsEqual(op1: Varnode[], op2: Varnode[]): boolean {
    if (op1.length !== op2.length) return false;
    for (let i = 0; i < op1.length; ++i) {
      if (op1[i] !== op2[i]) return false;
    }
    return true;
  }

  /**
   * Test if a STORE value has the matching form for the sequence.
   * @param op is the STORE to test
   * @returns true if the value being STOREd has the right size and type
   */
  private testValue(op: PcodeOp): boolean {
    const vn: Varnode = op.getIn(2);
    if (!vn.isConstant())
      return false;
    if (vn.getSize() !== this.charType.getSize())
      return false;
    return true;
  }

  /**
   * Collect ops STOREing into a memory region from the same root pointer.
   *
   * Walk forward from the base pointer to all STORE ops from that pointer, keeping track of the offset.
   * @returns true if the minimum number of STOREs is collected
   */
  private collectStoreOps(): boolean {
    const initStores: PcodeOp[] = [];
    this.findInitialStores(initStores);
    if (initStores.length + 1 < ArraySequence.MINIMUM_SEQUENCE_LENGTH)
      return false;
    const maxSize: bigint = BigInt(ArraySequence.MAXIMUM_SEQUENCE_LENGTH * this.charType.getAlignSize());
    const wrapMask: bigint = calc_mask(this.storeSpace.getAddrSize());
    this.baseOffset = this.calcPtraddOffset(this.rootOp.getIn(1), this.nonConstAdds);
    const nonConstComp: Varnode[] = [];
    for (let i = 0; i < initStores.length; ++i) {
      const op: PcodeOp = initStores[i];
      nonConstComp.length = 0;
      const curOffset: bigint = this.calcPtraddOffset(op.getIn(1), nonConstComp);
      const diff: bigint = (curOffset - this.baseOffset) & wrapMask;
      if (HeapSequence.setsEqual(this.nonConstAdds, nonConstComp)) {
        if (diff >= maxSize)
          return false;       // Root is not the earliest STORE, or offsets span range larger than maxSize
        if (!this.testValue(op))
          return false;
        this.moveOps.push(new WriteNode(diff, op, -1));
      }
    }
    this.moveOps.push(new WriteNode(0n, this.rootOp, -1));

    return true;
  }

  /**
   * Build the strncpy, wcsncpy, or memcpy function with string as input.
   *
   * A built-in user-op that copies string data is created. Its first (destination) parameter is
   * the base pointer of the STOREs with the base offset added to it.
   * @returns the constructed PcodeOp representing the memcpy
   */
  private buildStringCopy(): PcodeOp | null {
    const insertPoint: PcodeOp = this.moveOps[0].op;   // Earliest STORE in the block
    const charPtrType: Datatype = this.rootOp.getIn(1).getTypeReadFacing(this.rootOp);
    const numBytes: number = this.numElements * this.charType.getSize();
    const glb: Architecture = this.data.getArch();
    const srcPtr: Varnode | null = this.data.getInternalString(this.byteArray, numBytes, charPtrType, insertPoint);
    if (srcPtr === null)
      return null;
    let destPtr: Varnode = this.basePointer;
    if (this.baseOffset !== 0n || this.nonConstAdds.length > 0) {
      let indexVn: Varnode | null = null;
      const intType: Datatype = glb.types.getBase(this.basePointer.getSize(), type_metatype.TYPE_INT);
      if (this.nonConstAdds.length > 0) {
        indexVn = this.nonConstAdds[0];
        for (let i = 1; i < this.nonConstAdds.length; ++i) {
          const addOp: PcodeOp = this.data.newOp(2, insertPoint.getAddr());
          this.data.opSetOpcode(addOp, OpCode.CPUI_INT_ADD);
          this.data.opSetInput(addOp, indexVn, 0);
          this.data.opSetInput(addOp, this.nonConstAdds[i], 1);
          indexVn = this.data.newUniqueOut(indexVn.getSize(), addOp);
          indexVn.updateType(intType);
          this.data.opInsertBefore(addOp, insertPoint);
        }
      }
      if (this.baseOffset !== 0n) {
        const numEl: bigint = this.baseOffset / BigInt(this.charType.getAlignSize());
        const cvn: Varnode = this.data.newConstant(this.basePointer.getSize(), numEl);
        cvn.updateType(intType);
        if (indexVn === null)
          indexVn = cvn;
        else {
          const addOp: PcodeOp = this.data.newOp(2, insertPoint.getAddr());
          this.data.opSetOpcode(addOp, OpCode.CPUI_INT_ADD);
          this.data.opSetInput(addOp, indexVn, 0);
          this.data.opSetInput(addOp, cvn, 1);
          indexVn = this.data.newUniqueOut(indexVn.getSize(), addOp);
          indexVn.updateType(intType);
          this.data.opInsertBefore(addOp, insertPoint);
        }
      }
      const ptrAdd: PcodeOp = this.data.newOp(3, insertPoint.getAddr());
      this.data.opSetOpcode(ptrAdd, OpCode.CPUI_PTRADD);
      destPtr = this.data.newUniqueOut(this.basePointer.getSize(), ptrAdd);
      this.data.opSetInput(ptrAdd, this.basePointer, 0);
      this.data.opSetInput(ptrAdd, indexVn!, 1);
      this.data.opSetInput(ptrAdd, this.data.newConstant(this.basePointer.getSize(), BigInt(this.charType.getAlignSize())), 2);
      destPtr.updateType(charPtrType);
      this.data.opInsertBefore(ptrAdd, insertPoint);
    }
    const index: { val: number } = { val: 0 };
    const builtInId: number = this.selectStringCopyFunction(index);
    glb.userops.registerBuiltin(builtInId);
    const copyOp: PcodeOp = this.data.newOp(4, insertPoint.getAddr());
    this.data.opSetOpcode(copyOp, OpCode.CPUI_CALLOTHER);
    this.data.opSetInput(copyOp, this.data.newConstant(4, BigInt(builtInId)), 0);
    this.data.opSetInput(copyOp, destPtr, 1);
    this.data.opSetInput(copyOp, srcPtr, 2);
    const lenVn: Varnode = this.data.newConstant(4, BigInt(index.val));
    lenVn.updateType(copyOp.inputTypeLocal(3));
    this.data.opSetInput(copyOp, lenVn, 3);
    this.data.opInsertBefore(copyOp, insertPoint);
    return copyOp;
  }

  /**
   * Gather INDIRECT ops attached to the final sequence STOREs and their input/output Varnode pairs.
   *
   * There may be chained INDIRECTs for a single storage location as it crosses multiple STORE ops. Only
   * the initial input and final output are gathered.
   * @param indirects will hold the INDIRECT ops attached to sequence STOREs
   * @param pairs will hold Varnode pairs
   */
  private gatherIndirectPairs(indirects: PcodeOp[], pairs: IndirectPair[]): void {
    for (let i = 0; i < this.moveOps.length; ++i) {
      let op: PcodeOp | null = this.moveOps[i].op.previousOp();
      while (op !== null) {
        if (op.code() !== OpCode.CPUI_INDIRECT) break;
        op.setMark();
        indirects.push(op);
        op = op.previousOp();
      }
    }
    for (let i = 0; i < indirects.length; ++i) {
      const op: PcodeOp = indirects[i];
      const outvn: Varnode = op.getOut();
      let hasUse = false;
      const endIdx: number = outvn.endDescend();
      for (let di = outvn.beginDescend(); di < endIdx; ++di) {
        const useOp: PcodeOp = outvn.getDescend(di);
        if (!useOp.isMark()) {    // Look for read of outvn that is not by another STORE INDIRECT
          hasUse = true;
          break;
        }
      }
      if (hasUse) {
        let invn: Varnode = op.getIn(0);
        while (invn.isWritten()) {
          const defOp: PcodeOp = invn.getDef();
          if (!defOp.isMark()) break;
          invn = defOp.getIn(0);
        }
        pairs.push(new IndirectPair(invn, outvn));
      }
    }
    for (let i = 0; i < indirects.length; ++i)
      indirects[i].clearMark();
  }

  /**
   * Find and eliminate duplicate INDIRECT pairs.
   *
   * Its possible that INDIRECTs collected from different effect ops may share
   * the same output storage. Find any output Varnodes that share storage and
   * replace all their reads with a single representative Varnode.
   * @param pairs is the list of INDIRECT pairs
   * @returns true if the deduplication succeeded
   */
  private deduplicatePairs(pairs: IndirectPair[]): boolean {
    if (pairs.length === 0) return true;
    const copy: IndirectPair[] = pairs.slice();
    copy.sort(IndirectPair.compareOutput);

    let head: IndirectPair = copy[0];
    let dupCount = 0;
    for (let i = 1; i < copy.length; ++i) {
      const vn: Varnode = copy[i].outVn;
      const overlap: number = head.outVn.characterizeOverlap(vn);
      if (overlap === 1)
        return false;       // Partial overlap
      if (overlap === 2) {
        if (copy[i].inVn !== head.inVn) {
          return false;     // Same storage coming from different sources
        }
        copy[i].markDuplicate();
        dupCount += 1;
      } else {
        head = copy[i];
      }
    }
    if (dupCount > 0) {
      head = copy[0];
      for (let i = 1; i < copy.length; ++i) {
        if (copy[i].isDuplicate()) {
          this.data.totalReplace(copy[i].outVn, head.outVn);
        } else {
          head = copy[i];
        }
      }
    }
    return true;
  }

  /**
   * Remove all STORE ops from the basic block.
   *
   * If the STORE pointer no longer has any other uses, remove the PTRADD producing it, recursively,
   * up to the base pointer. INDIRECT ops surrounding any STORE that is removed are replaced with
   * INDIRECTs around the user-op replacing the STOREs.
   * @param indirects are the list of INDIRECTs caused by the STOREs
   * @param indirectPairs are the flow pairs across the STOREs that need to be preserved
   * @param replaceOp is the user-op replacement for the STOREs
   */
  private removeStoreOps(indirects: PcodeOp[], indirectPairs: IndirectPair[], replaceOp: PcodeOp): void {
    const scratch: PcodeOp[] = [];
    for (let i = 0; i < indirectPairs.length; ++i) {
      this.data.opUnsetOutput(indirectPairs[i].outVn.getDef());
    }
    for (let i = 0; i < this.moveOps.length; ++i) {
      const op: PcodeOp = this.moveOps[i].op;
      this.data.opDestroyRecursive(op, scratch);
    }
    for (let i = 0; i < indirects.length; ++i) {
      this.data.opDestroy(indirects[i]);
    }
    for (let i = 0; i < indirectPairs.length; ++i) {
      if (indirectPairs[i].isDuplicate()) continue;
      const newInd: PcodeOp = this.data.newOp(2, replaceOp.getAddr());
      this.data.opSetOpcode(newInd, OpCode.CPUI_INDIRECT);
      this.data.opSetOutput(newInd, indirectPairs[i].outVn);
      this.data.opSetInput(newInd, indirectPairs[i].inVn, 0);
      this.data.opSetInput(newInd, this.data.newVarnodeIop(replaceOp), 1);
      this.data.opInsertBefore(newInd, replaceOp);
    }
  }

  /**
   * Transform STOREs into a single memcpy user-op.
   *
   * The user-op representing the string move is created and all the STORE ops are removed.
   * @returns true if STOREs are successfully converted to a user-op with a string representation
   */
  transform(): boolean {
    const indirects: PcodeOp[] = [];
    const indirectPairs: IndirectPair[] = [];
    this.gatherIndirectPairs(indirects, indirectPairs);
    if (!this.deduplicatePairs(indirectPairs))
      return false;
    const memCpyOp: PcodeOp | null = this.buildStringCopy();
    if (memCpyOp === null)
      return false;
    this.removeStoreOps(indirects, indirectPairs, memCpyOp);
    return true;
  }
}

// ---------------------------------------------------------------------------
// RuleStringCopy
// ---------------------------------------------------------------------------

/**
 * Replace a sequence of COPY ops moving single characters with a CALLOTHER copying a whole string.
 *
 * Given a root COPY of a constant character, search for other COPYs in the same basic block that form a sequence
 * of characters that can be interpreted as a single string. Replace the sequence of COPYs with a single
 * memcpy or wcsncpy user-op.
 */
export class RuleStringCopy extends Rule {
  constructor(g: string) {
    super(g, 0, "stringcopy");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleStringCopy(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_COPY);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (!op.getIn(0).isConstant()) return 0;
    const outvn: Varnode = op.getOut();
    const ct: Datatype = outvn.getType();
    if (!ct.isCharPrint()) return 0;
    if (ct.isOpaqueString()) return 0;
    if (!outvn.isAddrTied()) return 0;
    const entry: SymbolEntry | null = data.getScopeLocal().queryContainer(outvn.getAddr(), outvn.getSize(), op.getAddr());
    if (entry === null)
      return 0;
    const sequence = new StringSequence(data, ct, entry, op, outvn.getAddr());
    if (!sequence.isValid())
      return 0;
    if (!sequence.transform())
      return 0;
    return 1;
  }
}

// ---------------------------------------------------------------------------
// RuleStringStore
// ---------------------------------------------------------------------------

/**
 * Replace a sequence of STORE ops moving single characters with a CALLOTHER copying a whole string.
 *
 * Given a root STORE of a constant character, search for other STOREs in the same basic block off of the
 * same base pointer that form a sequence that can be interpreted as a single string. Replace
 * the STOREs with a single strncpy or wcsncpy user-op.
 */
export class RuleStringStore extends Rule {
  constructor(g: string) {
    super(g, 0, "stringstore");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleStringStore(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_STORE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (!op.getIn(2).isConstant()) return 0;
    const ptrvn: Varnode = op.getIn(1);
    let ct: Datatype = ptrvn.getTypeReadFacing(op);
    if (ct.getMetatype() !== type_metatype.TYPE_PTR) return 0;
    ct = (ct as any).getPtrTo();
    if (!ct.isCharPrint()) return 0;
    if (ct.isOpaqueString()) return 0;
    const sequence = new HeapSequence(data, ct, op);
    if (!sequence.isValid())
      return 0;
    if (!sequence.transform())
      return 0;
    return 1;
  }
}
