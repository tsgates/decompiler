/**
 * @file signature.ts
 * @description Classes for generating feature vectors representing individual functions.
 *
 * Translated from Ghidra's signature.hh / signature.cc
 */

import { Address } from '../core/address.js';
import { OpCode } from '../core/opcodes.js';
import {
  AttributeId,
  ElementId,
  Encoder,
  Decoder,
  ATTRIB_INDEX,
  ATTRIB_VAL,
  ATTRIB_SPACE,
  ATTRIB_OFFSET,
} from '../core/marshal.js';
import { LowlevelError } from '../core/error.js';
import { Varnode } from './varnode.js';
import { PcodeOp } from './op.js';
import { crc_update } from './crc32.js';

// ---------------------------------------------------------------------------
// Forward type declarations for types from not-yet-written modules
// ---------------------------------------------------------------------------

type Funcdata = any;
type BlockBasic = any;
type BlockGraph = any;
type FlowBlock = any;
type FuncCallSpecs = any;
type VarnodeLocSet = any;

// ---------------------------------------------------------------------------
// hashword type alias
// ---------------------------------------------------------------------------

/** Data-type for containing hash information (uint8 / 64-bit) */
export type hashword = bigint;

// ---------------------------------------------------------------------------
// Marshaling AttributeIds
// ---------------------------------------------------------------------------

export const ATTRIB_BADDATA = new AttributeId("baddata", 145);
export const ATTRIB_HASH = new AttributeId("hash", 146);
export const ATTRIB_UNIMPL = new AttributeId("unimpl", 147);

// ---------------------------------------------------------------------------
// Marshaling ElementIds
// ---------------------------------------------------------------------------

export const ELEM_BLOCKSIG = new ElementId("blocksig", 258);
export const ELEM_CALL = new ElementId("call", 259);
export const ELEM_GENSIG = new ElementId("gensig", 260);
export const ELEM_MAJOR = new ElementId("major", 261);
export const ELEM_MINOR = new ElementId("minor", 262);
export const ELEM_COPYSIG = new ElementId("copysig", 263);
export const ELEM_SETTINGS = new ElementId("settings", 264);
export const ELEM_SIG = new ElementId("sig", 265);
export const ELEM_SIGNATUREDESC = new ElementId("signaturedesc", 266);
export const ELEM_SIGNATURES = new ElementId("signatures", 267);
export const ELEM_SIGSETTINGS = new ElementId("sigsettings", 268);
export const ELEM_VARSIG = new ElementId("varsig", 269);

// ---------------------------------------------------------------------------
// BigInt masks and helpers
// ---------------------------------------------------------------------------

const MASK32 = 0xFFFFFFFFn;
const MASK64 = 0xFFFFFFFFFFFFFFFFn;

/** Mix two hashword values using CRC-based hashing */
function hash_mixin(val1: hashword, val2: hashword): hashword {
  let hashhi = Number((val1 >> 32n) & MASK32) >>> 0;
  let hashlo = Number(val1 & MASK32) >>> 0;
  let v2 = val2 & MASK64;
  for (let i = 0; i < 8; ++i) {
    const tmphi = hashhi;
    const tmplo = Number(v2 & 0xFFn);
    v2 = v2 >> 8n;
    hashhi = crc_update(hashhi, tmplo) >>> 0;
    hashlo = crc_update(hashlo, tmphi) >>> 0;
  }
  let res = BigInt(hashhi) << 32n;
  res |= BigInt(hashlo);
  return res & MASK64;
}

// ---------------------------------------------------------------------------
// Signature
// ---------------------------------------------------------------------------

/**
 * A feature describing some aspect of a function or other unit of code.
 *
 * The underlying representation is just a 32-bit hash of the information representing
 * the feature, but derived classes may contain other meta-data describing where and how the
 * feature was formed. Two features are generally unordered (they are either equal or not equal),
 * but an ordering is used internally to normalize the vector representation and accelerate comparison.
 */
export class Signature {
  private sig: number; // uint4

  constructor(h: hashword) {
    this.sig = Number(h & MASK32) >>> 0;
  }

  /** Get the underlying 32-bit hash of the feature */
  getHash(): number {
    return this.sig;
  }

  /** Print the feature hash and a brief description of this feature to the given stream */
  print(s: { write(s: string): void }): void {
    s.write('*');
    this.printOrigin(s);
    s.write(' = 0x' + this.sig.toString(16).padStart(8, '0') + '\n');
  }

  /** Compare two features. Returns -1, 0, or 1 */
  compare(op2: Signature): number {
    if (this.sig !== op2.sig)
      return (this.sig < op2.sig) ? -1 : 1;
    return 0;
  }

  /** Encode this feature to the given stream */
  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_GENSIG);
    encoder.writeUnsignedInteger(ATTRIB_HASH, BigInt(this.getHash()));
    encoder.closeElement(ELEM_GENSIG);
  }

  /** Restore this feature from the given stream */
  decode(decoder: Decoder): void {
    const elemId = decoder.openElement();
    this.sig = Number(decoder.readUnsignedInteger()) >>> 0;
    decoder.closeElement(elemId);
  }

  /** Print a brief description of this feature to the given stream */
  printOrigin(s: { write(s: string): void }): void {
    s.write('0x' + this.sig.toString(16).padStart(8, '0'));
  }

  /** Compare two Signature pointers via their underlying hash values */
  static comparePtr(a: Signature, b: Signature): number {
    if (a.sig < b.sig) return -1;
    if (a.sig > b.sig) return 1;
    return 0;
  }
}

// ---------------------------------------------------------------------------
// SignatureEntry
// ---------------------------------------------------------------------------

/** A path node for doing depth first traversals of data-flow informed by SignatureEntry */
interface DFSNode {
  entry: SignatureEntry;
  iter: number; // index into vn.descend[]
}

/**
 * A node for data-flow feature generation.
 *
 * A SignatureEntry is rooted at a specific Varnode in the data-flow of a function.
 * During feature generation it iteratively hashes information about the Varnode and its nearest
 * neighbors through the edges of the graph.
 */
export class SignatureEntry {
  // SignatureFlags
  private static readonly SIG_NODE_TERMINAL    = 0x1;
  private static readonly SIG_NODE_COMMUTATIVE = 0x2;
  private static readonly SIG_NODE_NOT_EMITTED = 0x4;
  private static readonly SIG_NODE_STANDALONE  = 0x8;
  private static readonly VISITED              = 0x10;
  private static readonly MARKER_ROOT          = 0x20;

  public vn: Varnode | null;
  private flags: number;
  public hash: [hashword, hashword]; // [current, previous]
  public op: PcodeOp | null;
  private startvn: number;
  private inSize: number;
  public index: number;
  public shadow: SignatureEntry | null;

  /** Get a hash encoding the OpCode of the effective defining PcodeOp */
  private getOpHash(modifiers: number): hashword {
    if (this.op === null) return 0n;
    const opc: OpCode = this.op.code();
    let ophash: hashword = BigInt(opc);
    // For constant pool operations, hash in the resolved tag type constant
    if (opc === OpCode.CPUI_CPOOLREF) {
      ophash = (ophash + 0xFEEDFACEn) ^ this.op.getIn(this.op.numInput() - 1)!.getOffset();
    }
    return ophash;
  }

  private isVisited(): boolean {
    return (this.flags & SignatureEntry.VISITED) !== 0;
  }

  private setVisited(): void {
    this.flags |= SignatureEntry.VISITED;
  }

  /** Get the number of input edges in the noise-reduced form of the data-flow graph */
  private markerSizeIn(): number {
    if ((this.flags & SignatureEntry.MARKER_ROOT) !== 0) return 1;
    return this.numInputs();
  }

  /**
   * Get a specific node coming into this in the noise-reduced form of the data-flow graph.
   * @param i is the index of the incoming node
   * @param vRoot is the virtual root of the noise-reduced form
   * @param sigMap is the map from a Varnode to its SignatureEntry overlay
   */
  private getMarkerIn(i: number, vRoot: SignatureEntry, sigMap: Map<number, SignatureEntry>): SignatureEntry {
    if ((this.flags & SignatureEntry.MARKER_ROOT) !== 0) return vRoot;
    return SignatureEntry.mapToEntry(this.op!.getIn(i + this.startvn)!, sigMap);
  }

  /** Calculate the hash for stand-alone COPY */
  private standaloneCopyHash(modifiers: number): void {
    let val: hashword = SignatureEntry.hashSize(this.vn!, modifiers);
    val ^= 0xAF29E23Bn;
    if (this.vn!.isPersist())
      val ^= 0x55055055n;
    const invn: Varnode = this.vn!.getDef()!.getIn(0)!;
    if (invn.isConstant()) {
      if ((modifiers & GraphSigManager.SIG_DONOTUSE_CONST) === 0)
        val ^= this.vn!.getOffset();
      else
        val ^= 0xA0A0A0A0n;
    } else if (invn.isPersist()) {
      val ^= 0xD7651EC3n;
    }
    this.hash[0] = val & MASK64;
    this.hash[1] = val & MASK64;
  }

  /** Determine if the given Varnode is a stand-alone COPY */
  static testStandaloneCopy(vn: Varnode): boolean {
    const op: PcodeOp = vn.getDef()!;
    const invn: Varnode = op.getIn(0)!;
    if (invn.isWritten())
      return false;
    if (invn.getAddr().equals(vn.getAddr()))
      return false;

    if (vn.isPersist() && op.code() === OpCode.CPUI_INDIRECT)
      return true;

    // Iterate over descendants
    const beginIdx = vn.beginDescend();
    const endIdx = vn.endDescend();
    if (beginIdx === endIdx)
      return true;
    const descOp: PcodeOp = vn.getDescend(beginIdx);
    if (beginIdx + 1 !== endIdx)
      return false;
    const opc: OpCode = descOp.code();
    if (vn.isPersist() && opc === OpCode.CPUI_INDIRECT) {
      return true;
    }
    // Account for COPY and INDIRECT placeholder conventions
    if (opc !== OpCode.CPUI_COPY && opc !== OpCode.CPUI_INDIRECT)
      return false;
    return descOp.getOut()!.hasNoDescend();
  }

  /** Construct from a Varnode */
  constructor(v: Varnode, modifiers: number);
  /** Construct a virtual node */
  constructor(ind: number);
  constructor(arg: Varnode | number, modifiers?: number) {
    this.hash = [0n, 0n];
    this.shadow = null;
    this.flags = 0;
    this.inSize = 0;
    this.index = -1;
    this.startvn = 0;

    if (typeof arg === 'number') {
      // Construct a virtual node
      this.vn = null;
      this.op = null;
      this.index = arg;
      return;
    }

    // Construct from a Varnode
    const v = arg;
    const mods = modifiers!;
    this.vn = v;
    this.op = v.getDef();

    // Decide on the effective defining op for the given varnode.
    if (this.op === null) {
      this.flags |= SignatureEntry.SIG_NODE_TERMINAL;
      return;
    }
    this.startvn = 0;
    this.inSize = this.op.numInput();
    switch (this.op.code()) {
      case OpCode.CPUI_COPY:
        if (SignatureEntry.testStandaloneCopy(v))
          this.flags |= SignatureEntry.SIG_NODE_STANDALONE;
        break;
      case OpCode.CPUI_INDIRECT:
        this.inSize -= 1;
        if (SignatureEntry.testStandaloneCopy(v))
          this.flags |= SignatureEntry.SIG_NODE_STANDALONE;
        break;
      case OpCode.CPUI_MULTIEQUAL:
        this.flags |= SignatureEntry.SIG_NODE_COMMUTATIVE;
        break;
      case OpCode.CPUI_CALL:
        this.startvn = 1;
        this.inSize -= 1;
        break;
      case OpCode.CPUI_CALLIND:
        this.startvn = 1;
        this.inSize -= 1;
        break;
      case OpCode.CPUI_CALLOTHER:
        this.startvn = 1;
        this.inSize -= 1;
        break;
      case OpCode.CPUI_STORE:
        this.startvn = 1;
        this.inSize -= 1;
        break;
      case OpCode.CPUI_LOAD:
        this.startvn = 1;
        this.inSize -= 1;
        break;
      case OpCode.CPUI_INT_LEFT:
      case OpCode.CPUI_INT_RIGHT:
      case OpCode.CPUI_INT_SRIGHT:
      case OpCode.CPUI_SUBPIECE:
        if (this.op.getIn(1)!.isConstant())
          this.inSize = 1;
        break;
      case OpCode.CPUI_CPOOLREF:
        this.inSize = 0;
        break;
      default:
        if (this.op.isCommutative())
          this.flags |= SignatureEntry.SIG_NODE_COMMUTATIVE;
        break;
    }
  }

  /** Return true if this node has no inputs */
  isTerminal(): boolean {
    return (this.flags & SignatureEntry.SIG_NODE_TERMINAL) !== 0;
  }

  /** Return true if this is not emitted as a feature */
  isNotEmitted(): boolean {
    return (this.flags & SignatureEntry.SIG_NODE_NOT_EMITTED) !== 0;
  }

  /** Return true if inputs to this are unordered */
  isCommutative(): boolean {
    return (this.flags & SignatureEntry.SIG_NODE_COMMUTATIVE) !== 0;
  }

  /** Return true if this is a stand-alone COPY */
  isStandaloneCopy(): boolean {
    return (this.flags & SignatureEntry.SIG_NODE_STANDALONE) !== 0;
  }

  /** Return the number of incoming edges to this node */
  numInputs(): number {
    return this.inSize;
  }

  /**
   * Get the i-th incoming node.
   * @param i is the index
   * @param sigMap is the map from Varnode to its SignatureEntry overlay
   */
  getIn(i: number, sigMap: Map<number, SignatureEntry>): SignatureEntry {
    return SignatureEntry.mapToEntryCollapse(this.op!.getIn(i + this.startvn)!, sigMap);
  }

  /**
   * Determine if this node shadows another.
   * A Varnode shadows another if it is defined by a COPY or INDIRECT op.
   */
  calculateShadow(sigMap: Map<number, SignatureEntry>): void {
    let shadowVn: Varnode = this.vn!;
    for (;;) {
      this.op = shadowVn.getDef();
      if (this.op === null)
        break;
      const opc: OpCode = this.op.code();
      if (opc !== OpCode.CPUI_COPY && opc !== OpCode.CPUI_INDIRECT && opc !== OpCode.CPUI_CAST)
        break;
      shadowVn = this.op.getIn(0)!;
    }
    if (shadowVn !== this.vn)
      this.shadow = SignatureEntry.mapToEntry(shadowVn, sigMap);
  }

  /**
   * Compute an initial hash based on local properties of the Varnode.
   */
  localHash(modifiers: number): void {
    let localhash: hashword;

    if (this.vn!.isAnnotation()) {
      localhash = 0xB7B7B7B7n;
      this.flags |= (SignatureEntry.SIG_NODE_NOT_EMITTED | SignatureEntry.SIG_NODE_TERMINAL);
      this.hash[0] = localhash;
      this.hash[1] = localhash;
      return;
    }
    if (this.shadow !== null) {
      this.flags |= SignatureEntry.SIG_NODE_NOT_EMITTED;
      if (this.isStandaloneCopy()) {
        this.standaloneCopyHash(modifiers);
      }
      return;
    }

    localhash = SignatureEntry.hashSize(this.vn!, modifiers);

    if (!this.vn!.isWritten())
      this.flags |= SignatureEntry.SIG_NODE_NOT_EMITTED;
    const ophash: hashword = this.getOpHash(modifiers);

    // Class of varnode
    if (this.vn!.isConstant()) {
      if ((modifiers & GraphSigManager.SIG_DONOTUSE_CONST) === 0)
        localhash ^= this.vn!.getOffset();
      else
        localhash ^= 0xA0A0A0A0n;
    }
    if ((modifiers & GraphSigManager.SIG_DONOTUSE_PERSIST) === 0) {
      if (this.vn!.isPersist() && this.vn!.isInput())
        localhash ^= 0x55055055n;
    }
    if (this.vn!.isInput())
      localhash ^= 0x10101n;
    if (ophash !== 0n) {
      localhash ^= ophash ^ (ophash << 9n) ^ (ophash << 18n);
    }

    this.hash[0] = localhash & MASK64;
    this.hash[1] = localhash & MASK64;
  }

  /** Store hash from previous iteration and prepare for next iteration */
  flip(): void {
    this.hash[1] = this.hash[0];
  }

  /** Hash info from other nodes into this */
  hashIn(neigh: SignatureEntry[]): void {
    let curhash: hashword = this.hash[1];
    if (this.isCommutative()) {
      let accum: hashword = 0n;
      for (let i = 0; i < neigh.length; ++i) {
        const entry = neigh[i];
        const tmphash = hash_mixin(curhash, entry.hash[1]);
        accum = (accum + tmphash) & MASK64;
      }
      curhash = hash_mixin(curhash, accum);
    } else {
      for (let i = 0; i < neigh.length; ++i) {
        const entry = neigh[i];
        curhash = hash_mixin(curhash, entry.hash[1]);
      }
    }
    this.hash[0] = curhash;
  }

  /** Get the underlying Varnode which this overlays */
  getVarnode(): Varnode | null {
    return this.vn;
  }

  /** Get the current hash value */
  getHash(): hashword {
    return this.hash[0];
  }

  /** Given a Varnode, find its SignatureEntry overlay */
  static mapToEntry(vn: Varnode, sigMap: Map<number, SignatureEntry>): SignatureEntry {
    return sigMap.get(vn.getCreateIndex())!;
  }

  /** Given a Varnode, find its SignatureEntry overlay, collapsing shadows */
  static mapToEntryCollapse(vn: Varnode, sigMap: Map<number, SignatureEntry>): SignatureEntry {
    const res = SignatureEntry.mapToEntry(vn, sigMap);
    if (res.shadow === null)
      return res;
    return res.shadow;
  }

  /**
   * Do a post-ordering of the modified noise graph.
   *
   * The noise graph is formed from the original graph by removing all non-marker edges.
   */
  private static noisePostOrder(
    rootlist: SignatureEntry[],
    postOrder: SignatureEntry[],
    sigMap: Map<number, SignatureEntry>
  ): void {
    const stack: DFSNode[] = [];
    for (let i = 0; i < rootlist.length; ++i) {
      const rootEntry = rootlist[i];
      stack.push({ entry: rootEntry, iter: rootEntry.vn!.beginDescend() });
      rootEntry.setVisited();
      while (stack.length > 0) {
        const top = stack[stack.length - 1];
        const entry = top.entry;
        const iterIdx = top.iter;
        if (iterIdx === entry.vn!.endDescend()) {
          stack.pop();
          entry.index = postOrder.length;
          postOrder.push(entry);
        } else {
          const op: PcodeOp = entry.vn!.getDescend(iterIdx);
          top.iter = iterIdx + 1;
          if (op.isMarker() || op.code() === OpCode.CPUI_COPY) {
            const childEntry = SignatureEntry.mapToEntry(op.getOut()!, sigMap);
            if (!childEntry.isVisited()) {
              childEntry.setVisited();
              stack.push({ entry: childEntry, iter: childEntry.vn!.beginDescend() });
            }
          }
        }
      }
    }
  }

  /**
   * Construct the dominator tree for the modified noise graph.
   */
  private static noiseDominator(
    postOrder: SignatureEntry[],
    sigMap: Map<number, SignatureEntry>
  ): void {
    const virtualRoot = postOrder[postOrder.length - 1];
    virtualRoot.shadow = virtualRoot;
    let changed = true;
    let new_idom: SignatureEntry | null = null;
    while (changed) {
      changed = false;
      for (let i = postOrder.length - 2; i >= 0; --i) {
        const b = postOrder[i];
        if (b.shadow !== postOrder[postOrder.length - 1]) {
          let j: number;
          const sizeIn = b.markerSizeIn();
          for (j = 0; j < sizeIn; ++j) {
            new_idom = b.getMarkerIn(j, virtualRoot, sigMap);
            if (new_idom.shadow !== null)
              break;
          }
          j += 1;
          for (; j < sizeIn; ++j) {
            const rho = b.getMarkerIn(j, virtualRoot, sigMap);
            if (rho.shadow !== null) {
              let finger1 = rho.index;
              let finger2 = new_idom!.index;
              while (finger1 !== finger2) {
                while (finger1 < finger2)
                  finger1 = postOrder[finger1].shadow!.index;
                while (finger2 < finger1)
                  finger2 = postOrder[finger2].shadow!.index;
              }
              new_idom = postOrder[finger1];
            }
          }
          if (b.shadow !== new_idom) {
            b.shadow = new_idom;
            changed = true;
          }
        }
      }
    }
  }

  /**
   * Remove noise from the data-flow graph by collapsing Varnodes that are indirect copies
   * of each other.
   */
  static removeNoise(sigMap: Map<number, SignatureEntry>): void {
    const rootlist: SignatureEntry[] = [];
    const postOrder: SignatureEntry[] = [];

    // Set up the virtual root
    for (const [, entry] of sigMap) {
      const vn = entry.vn!;
      if (vn.isInput() || vn.isConstant()) {
        rootlist.push(entry);
        entry.flags |= SignatureEntry.MARKER_ROOT;
      } else if (vn.isWritten()) {
        const op: PcodeOp = vn.getDef()!;
        if (!op.isMarker() && op.code() !== OpCode.CPUI_COPY) {
          rootlist.push(entry);
          entry.flags |= SignatureEntry.MARKER_ROOT;
        }
      }
    }

    SignatureEntry.noisePostOrder(rootlist, postOrder, sigMap);
    // Construct a virtual root with out edges to every node in rootlist
    const virtualRoot = new SignatureEntry(postOrder.length);
    postOrder.push(virtualRoot);
    for (let i = 0; i < rootlist.length; ++i)
      rootlist[i].shadow = virtualRoot;

    SignatureEntry.noiseDominator(postOrder, sigMap);
    postOrder.pop(); // Pop off virtual root

    // Calculate the shadow bases and set their shadow field to null
    for (let i = 0; i < postOrder.length; ++i) {
      const entry = postOrder[i];
      if (entry.shadow === virtualRoot)
        entry.shadow = null;
    }
    // Set the final shadow field by collapsing the dominator tree to the shadow bases
    for (let i = 0; i < postOrder.length; ++i) {
      let entry = postOrder[i];
      let base = entry;
      while (base.shadow !== null) {
        base = base.shadow;
      }
      while (entry.shadow !== null) {
        const tmp = entry;
        entry = entry.shadow;
        tmp.shadow = base;
      }
    }
  }

  /**
   * Calculate a hash describing the size of a given Varnode.
   *
   * The hash is computed from the size of the Varnode in bytes.
   * Depending on the signature settings, the hash incorporates the full value, or
   * it may truncate a value greater than 4.
   */
  static hashSize(vn: Varnode, modifiers: number): hashword {
    let val: hashword = BigInt(vn.getSize());
    if ((modifiers & GraphSigManager.SIG_COLLAPSE_SIZE) !== 0) {
      if (val > 4n)
        val = 4n;
    }
    return (val ^ (val << 7n) ^ (val << 14n) ^ (val << 21n)) & MASK64;
  }
}

// ---------------------------------------------------------------------------
// BlockSignatureEntry
// ---------------------------------------------------------------------------

/**
 * A node for control-flow feature generation.
 *
 * A BlockSignatureEntry is rooted at a specific basic block in the control-flow of a function.
 * During feature generation it iteratively hashes information about the basic block and its
 * nearest neighbors through the edges of the control-flow graph.
 */
export class BlockSignatureEntry {
  private bl: BlockBasic;
  private hash: [hashword, hashword];

  /** Construct from a basic block */
  constructor(b: BlockBasic) {
    this.bl = b;
    this.hash = [0n, 0n];
  }

  /** Compute an initial hash based on local properties of the basic block */
  localHash(modifiers: number): void {
    let localhash: hashword = BigInt(this.bl.sizeIn());
    localhash = localhash << 8n;
    localhash |= BigInt(this.bl.sizeOut());
    this.hash[0] = localhash & MASK64;
  }

  /** Store hash from previous iteration and prepare for next iteration */
  flip(): void {
    this.hash[1] = this.hash[0];
  }

  /** Hash info from other nodes into this */
  hashIn(neigh: BlockSignatureEntry[]): void {
    let curhash: hashword = this.hash[1];
    let accum: hashword = 0xBAFABACAn;
    for (let i = 0; i < neigh.length; ++i) {
      const entry = neigh[i];
      let tmphash = hash_mixin(curhash, entry.hash[1]);
      if (entry.bl.sizeOut() === 2) {
        if (this.bl.getInRevIndex(i) === 0)
          tmphash = hash_mixin(tmphash, 0x777n ^ 0x7ABC7ABCn);
        else
          tmphash = hash_mixin(tmphash, 0x777n);
      }
      accum = (accum + tmphash) & MASK64;
    }
    this.hash[0] = hash_mixin(curhash, accum);
  }

  /** Get the underlying basic block which this overlays */
  getBlock(): BlockBasic {
    return this.bl;
  }

  /** Get the current hash value */
  getHash(): hashword {
    return this.hash[0];
  }
}

// ---------------------------------------------------------------------------
// VarnodeSignature
// ---------------------------------------------------------------------------

/**
 * A feature representing a portion of the data-flow graph rooted at a particular Varnode.
 *
 * The feature recursively incorporates details about the Varnode, the PcodeOp that defined it and
 * its input Varnodes, up to a specific depth.
 */
export class VarnodeSignature extends Signature {
  private vn: Varnode;

  constructor(v: Varnode, h: hashword) {
    super(h);
    this.vn = v;
  }

  override encode(encoder: Encoder): void {
    encoder.openElement(ELEM_VARSIG);
    encoder.writeUnsignedInteger(ATTRIB_HASH, BigInt(this.getHash()));
    this.vn.encode(encoder);
    if (this.vn.isWritten())
      this.vn.getDef()!.encode(encoder);
    encoder.closeElement(ELEM_VARSIG);
  }

  override printOrigin(s: { write(s: string): void }): void {
    this.vn.printRaw(s);
  }
}

// ---------------------------------------------------------------------------
// BlockSignature
// ---------------------------------------------------------------------------

/**
 * A feature rooted in a basic block.
 *
 * There are two forms of a block feature.
 * Form 1 contains only local control-flow information about the basic block.
 * Form 2 is a feature that combines two operations that occur in sequence within the block.
 */
export class BlockSignature extends Signature {
  private bl: BlockBasic;
  private op1: PcodeOp | null;
  private op2: PcodeOp | null;

  constructor(b: BlockBasic, h: hashword, o1: PcodeOp | null, o2: PcodeOp | null) {
    super(h);
    this.bl = b;
    this.op1 = o1;
    this.op2 = o2;
  }

  override encode(encoder: Encoder): void {
    encoder.openElement(ELEM_BLOCKSIG);
    encoder.writeUnsignedInteger(ATTRIB_HASH, BigInt(this.getHash()));
    encoder.writeSignedInteger(ATTRIB_INDEX, this.bl.getIndex());
    this.bl.getStart().encode(encoder);
    if (this.op2 !== null)
      this.op2.encode(encoder);
    if (this.op1 !== null)
      this.op1.encode(encoder);
    encoder.closeElement(ELEM_BLOCKSIG);
  }

  override printOrigin(s: { write(s: string): void }): void {
    this.bl.printHeader(s);
  }
}

// ---------------------------------------------------------------------------
// CopySignature
// ---------------------------------------------------------------------------

/**
 * A feature representing 1 or more stand-alone copies in a basic block.
 *
 * A COPY operation is considered stand-alone if either a constant or a function input
 * is copied into a location that is then not read directly by the function.
 */
export class CopySignature extends Signature {
  private bl: BlockBasic;

  constructor(b: BlockBasic, h: hashword) {
    super(h);
    this.bl = b;
  }

  override encode(encoder: Encoder): void {
    encoder.openElement(ELEM_COPYSIG);
    encoder.writeUnsignedInteger(ATTRIB_HASH, BigInt(this.getHash()));
    encoder.writeSignedInteger(ATTRIB_INDEX, this.bl.getIndex());
    encoder.closeElement(ELEM_COPYSIG);
  }

  override printOrigin(s: { write(s: string): void }): void {
    s.write('Copies in ');
    this.bl.printHeader(s);
  }
}

// ---------------------------------------------------------------------------
// SigManager
// ---------------------------------------------------------------------------

/**
 * A container for collecting a set of features (a feature vector) for a single function.
 *
 * This manager handles:
 *   - Configuring details of the signature generation process
 *   - Establishing the function being signatured, via setCurrentFunction()
 *   - Generating the features, via generate()
 *   - Outputting the features, via encode() or print()
 */
export abstract class SigManager {
  private static settings: number = 0;

  private sigs: Signature[] = [];

  protected fd: Funcdata | null = null;

  /** Clear all current Signature/feature objects from this manager */
  private clearSignatures(): void {
    this.sigs.length = 0;
  }

  /** Add a new feature to the manager */
  protected addSignature(sig: Signature): void {
    this.sigs.push(sig);
  }

  constructor() {
    this.fd = null;
  }

  /** Clear all current Signature/feature resources */
  clear(): void {
    this.clearSignatures();
  }

  /** Read configuration information from a character stream */
  abstract initializeFromStream(s: string): void;

  /** Set the function used for (future) feature generation */
  setCurrentFunction(f: Funcdata): void {
    this.fd = f;
  }

  /** Generate all features for the current function */
  abstract generate(): void;

  /** Get the number of features currently generated */
  numSignatures(): number {
    return this.sigs.length;
  }

  /** Get the i-th Signature/feature */
  getSignature(i: number): Signature {
    return this.sigs[i];
  }

  /** Get the feature vector as a simple array of hashes */
  getSignatureVector(feature: number[]): void {
    feature.length = this.sigs.length;
    for (let i = 0; i < this.sigs.length; ++i)
      feature[i] = this.sigs[i].getHash();
    feature.sort((a, b) => (a >>> 0) - (b >>> 0));
  }

  /** Combine all feature hashes into one overall hash */
  getOverallHash(): hashword {
    const feature: number[] = [];
    this.getSignatureVector(feature);
    let pool: hashword = 0x12349876ABACABn;
    for (let i = 0; i < feature.length; ++i)
      pool = hash_mixin(pool, BigInt(feature[i]));
    return pool;
  }

  /** Sort all current features */
  sortByHash(): void {
    this.sigs.sort(Signature.comparePtr);
  }

  /** Print a brief description of all current features to a stream */
  print(s: { write(s: string): void }): void {
    for (const sig of this.sigs)
      sig.print(s);
  }

  /** Encode all current features to the given stream */
  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_SIGNATUREDESC);
    for (const sig of this.sigs)
      sig.encode(encoder);
    encoder.closeElement(ELEM_SIGNATUREDESC);
  }

  /** Get the settings currently being used for signature generation */
  static getSettings(): number {
    return SigManager.settings;
  }

  /** Establish settings to use for future signature generation */
  static setSettings(newvalue: number): void {
    SigManager.settings = newvalue;
  }
}

// ---------------------------------------------------------------------------
// GraphSigManager
// ---------------------------------------------------------------------------

/**
 * A manager for generating Signatures/features on function data-flow and control-flow.
 *
 * Features are extracted from the data-flow and control-flow graphs of the function.
 * The different feature types produced by this manager are:
 *   - VarnodeSignature
 *   - BlockSignature
 *   - CopySignature
 */
export class GraphSigManager extends SigManager {
  // Signature generation settings (Mods enum)
  static readonly SIG_COLLAPSE_SIZE     = 0x1;
  static readonly SIG_COLLAPSE_INDNOISE = 0x2;
  static readonly SIG_DONOTUSE_CONST    = 0x10;
  static readonly SIG_DONOTUSE_INPUT    = 0x20;
  static readonly SIG_DONOTUSE_PERSIST  = 0x40;

  private sigmods: number;
  private maxiter: number;
  private maxblockiter: number;
  private maxvarnode: number;
  private sigmap: Map<number, SignatureEntry> = new Map();
  private blockmap: Map<number, BlockSignatureEntry> = new Map();

  /** Do one iteration of hashing on the SignatureEntrys */
  private signatureIterate(): void {
    const neigh: SignatureEntry[] = [];
    this.flipVarnodes();
    for (const [, entry] of this.sigmap) {
      if (entry.isNotEmitted()) continue;
      if (entry.isTerminal()) continue;
      const num = entry.numInputs();
      neigh.length = 0;
      for (let j = 0; j < num; ++j) {
        const vnentry = entry.getIn(j, this.sigmap);
        neigh.push(vnentry);
      }
      entry.hashIn(neigh);
    }
  }

  /** Do one iteration of hashing on the BlockSignatureEntrys */
  private signatureBlockIterate(): void {
    const neigh: BlockSignatureEntry[] = [];
    this.flipBlocks();
    for (const [, entry] of this.blockmap) {
      const bl = entry.getBlock();
      neigh.length = 0;
      for (let i = 0; i < bl.sizeIn(); ++i) {
        const inbl: FlowBlock = bl.getIn(i);
        const inentry = this.blockmap.get(inbl.getIndex())!;
        neigh.push(inentry);
      }
      entry.hashIn(neigh);
    }
  }

  /** Generate the final feature for each Varnode from its SignatureEntry overlay */
  private collectVarnodeSigs(): void {
    for (const [, entry] of this.sigmap) {
      if (entry.isNotEmitted()) continue;
      const vsig = new VarnodeSignature(entry.getVarnode()!, entry.getHash());
      this.addSignature(vsig);
    }
  }

  /**
   * Generate the final feature(s) for each basic block from its BlockSignatureEntry overlay.
   */
  private collectBlockSigs(): void {
    for (const [, entry] of this.blockmap) {
      const bl = entry.getBlock();

      let lastop: PcodeOp | null = null;
      let lasthash: hashword = 0n;
      let callhash: hashword = 0n;
      let copyhash: hashword = 0n;
      let finalhash: hashword;

      // Iterate over ops in the basic block
      const opBegin = bl.beginOp();
      const opEnd = bl.endOp();
      for (let oiter = opBegin; oiter < opEnd; ++oiter) {
        const op: PcodeOp = bl.getOp(oiter);
        let startind = 0;
        let stopind = 0;
        let isCopyContinue = false;
        switch (op.code()) {
          case OpCode.CPUI_CALL:
            callhash = (callhash + 100001n) & MASK64;
            callhash = (callhash * 0x78ABBFn) & MASK64;
            startind = 1;
            stopind = op.numInput();
            break;
          case OpCode.CPUI_CALLIND:
            callhash = (callhash + 123451n) & MASK64;
            callhash = (callhash * 0x78ABBFn) & MASK64;
            startind = 1;
            stopind = op.numInput();
            break;
          case OpCode.CPUI_CALLOTHER:
            startind = 1;
            stopind = op.numInput();
            break;
          case OpCode.CPUI_STORE:
            startind = 1;
            stopind = op.numInput();
            break;
          case OpCode.CPUI_CBRANCH:
            startind = 1;
            stopind = 2;
            break;
          case OpCode.CPUI_BRANCHIND:
            startind = 0;
            stopind = 1;
            break;
          case OpCode.CPUI_RETURN:
            startind = 1;
            stopind = op.numInput();
            break;
          case OpCode.CPUI_INDIRECT:
          case OpCode.CPUI_COPY: {
            const outEntry = SignatureEntry.mapToEntry(op.getOut()!, this.sigmap);
            if (outEntry.isStandaloneCopy()) {
              copyhash = (copyhash + outEntry.getHash()) & MASK64;
            }
            isCopyContinue = true;
            break;
          }
          default:
            startind = 0;
            stopind = 0;
            break;
        }
        if (isCopyContinue) continue;

        const outvn: Varnode | null = op.getOut();
        if (stopind === 0 && (outvn === null || !outvn.hasNoDescend())) continue;

        let val: hashword;
        if (outvn !== null) {
          const outEntry = SignatureEntry.mapToEntry(outvn, this.sigmap);
          if (outEntry.isNotEmitted()) continue;
          val = outEntry.getHash();
        } else {
          val = BigInt(op.code() as number);
          val = (val ^ (val << 9n) ^ (val << 18n)) & MASK64;
          let accum: hashword = 0n;
          for (let i = startind; i < stopind; ++i) {
            const vn: Varnode = op.getIn(i)!;
            const tmphash = hash_mixin(val, SignatureEntry.mapToEntryCollapse(vn, this.sigmap).getHash());
            accum = (accum + tmphash) & MASK64;
          }
          val = (val ^ accum) & MASK64;
        }
        if (lastop === null)
          finalhash = hash_mixin(val, entry.getHash());
        else
          finalhash = hash_mixin(val, lasthash);
        const bsig = new BlockSignature(bl, finalhash, lastop, op);
        this.addSignature(bsig);
        lastop = op;
        lasthash = val;
      }
      finalhash = hash_mixin(entry.getHash(), 0x9B1C5Fn);
      if (callhash !== 0n)
        finalhash = hash_mixin(finalhash, callhash);
      this.addSignature(new BlockSignature(bl, finalhash, null, null));
      if (copyhash !== 0n) {
        copyhash = hash_mixin(copyhash, 0xA2DE3Cn);
        this.addSignature(new CopySignature(bl, copyhash));
      }
    }
  }

  /** Clear all SignatureEntry overlay objects */
  private varnodeClear(): void {
    this.sigmap.clear();
  }

  /** Clear all BlockSignatureEntry overlay objects */
  private blockClear(): void {
    this.blockmap.clear();
  }

  /** Initialize BlockSignatureEntry overlays for the current function */
  private initializeBlocks(): void {
    const blockgraph: BlockGraph = this.fd!.getBasicBlocks();
    for (let i = 0; i < blockgraph.getSize(); ++i) {
      const bl: BlockBasic = blockgraph.getBlock(i);
      const entry = new BlockSignatureEntry(bl);
      this.blockmap.set(bl.getIndex(), entry);
      entry.localHash(this.sigmods);
    }
  }

  /** Store off current Varnode hash values as previous hash values */
  private flipVarnodes(): void {
    for (const [, entry] of this.sigmap) {
      entry.flip();
    }
  }

  /** Store off current block hash values as previous hash values */
  private flipBlocks(): void {
    for (const [, entry] of this.blockmap) {
      entry.flip();
    }
  }

  /** Test for valid signature generation settings */
  static testSettings(val: number): boolean {
    if (val === 0) return false;
    let mask = GraphSigManager.SIG_COLLAPSE_SIZE | GraphSigManager.SIG_DONOTUSE_CONST |
      GraphSigManager.SIG_DONOTUSE_INPUT | GraphSigManager.SIG_DONOTUSE_PERSIST |
      GraphSigManager.SIG_COLLAPSE_INDNOISE;
    mask = (mask << 2) | 1;
    return ((val & ~mask) === 0);
  }

  constructor() {
    super();
    const setting = SigManager.getSettings();
    if (!GraphSigManager.testSettings(setting))
      throw new LowlevelError("Bad signature settings");
    this.sigmods = setting >> 2;
    this.maxiter = 3;
    this.maxblockiter = 1;
    this.maxvarnode = 0;
  }

  override clear(): void {
    this.varnodeClear();
    this.blockClear();
    super.clear();
  }

  /** Override the default iterations used for Varnode features */
  setMaxIteration(val: number): void {
    this.maxiter = val;
  }

  /** Override the default iterations used for block features */
  setMaxBlockIteration(val: number): void {
    this.maxblockiter = val;
  }

  /** Set a maximum threshold for Varnodes in a function */
  setMaxVarnode(val: number): void {
    this.maxvarnode = val;
  }

  override initializeFromStream(s: string): void {
    const trimmed = s.trim();
    if (trimmed.length > 0) {
      const parsed = parseInt(trimmed, 10);
      if (!isNaN(parsed) && parsed !== -1) {
        this.maxiter = parsed;
      }
    }
  }

  override setCurrentFunction(f: Funcdata): void {
    super.setCurrentFunction(f);

    const size: number = f.numVarnodes();
    if (this.maxvarnode !== 0 && size > this.maxvarnode)
      throw new LowlevelError(f.getName() + " exceeds size threshold for generating signatures");

    const endLoc = f.endLoc();
    for (let iter = f.beginLoc(); !iter.equals(endLoc); iter.next()) {
      const vn: Varnode = iter.get();
      const entry = new SignatureEntry(vn, this.sigmods);
      this.sigmap.set(vn.getCreateIndex(), entry);
    }

    if ((this.sigmods & GraphSigManager.SIG_COLLAPSE_INDNOISE) !== 0) {
      SignatureEntry.removeNoise(this.sigmap);
    } else {
      for (const [, entry] of this.sigmap)
        entry.calculateShadow(this.sigmap);
    }
    for (const [, entry] of this.sigmap) {
      entry.localHash(this.sigmods);
    }
  }

  override generate(): void {
    const minusone = this.maxiter - 1;
    const firsthalf = Math.floor(minusone / 2);
    const secondhalf = minusone - firsthalf;
    this.signatureIterate();
    for (let i = 0; i < firsthalf; ++i)
      this.signatureIterate();

    // Do the block signatures incorporating varnode sigs halfway through
    if (this.maxblockiter >= 0) {
      this.initializeBlocks();
      for (let i = 0; i < this.maxblockiter; ++i) {
        this.signatureBlockIterate();
      }
      this.collectBlockSigs();
      this.blockClear();
    }

    for (let i = 0; i < secondhalf; ++i)
      this.signatureIterate();

    this.collectVarnodeSigs();

    this.varnodeClear();
  }
}

// ---------------------------------------------------------------------------
// Top-level functions
// ---------------------------------------------------------------------------

/**
 * Generate features for a single function.
 *
 * Features are generated for the function and written to the encoder as a simple sequence of hash values.
 * No additional information about the features is written to the encoder.
 * The function must have been previously decompiled. If function decompilation failed due to either: flow
 * into bad data or unimplemented instructions, an error condition is encoded to the stream.
 */
export function simpleSignature(fd: Funcdata, encoder: Encoder): void {
  const sigmanager = new GraphSigManager();

  sigmanager.setCurrentFunction(fd);
  sigmanager.generate();
  const feature: number[] = [];
  sigmanager.getSignatureVector(feature);
  encoder.openElement(ELEM_SIGNATURES);
  if (fd.hasUnimplemented())
    encoder.writeBool(ATTRIB_UNIMPL, true);
  if (fd.hasBadData())
    encoder.writeBool(ATTRIB_BADDATA, true);
  for (let i = 0; i < feature.length; ++i) {
    encoder.openElement(ELEM_SIG);
    encoder.writeUnsignedInteger(ATTRIB_VAL, BigInt(feature[i]));
    encoder.closeElement(ELEM_SIG);
  }
  const numcalls: number = fd.numCalls();
  for (let i = 0; i < numcalls; ++i) {
    const fc: FuncCallSpecs = fd.getCallSpecs_byIndex(i);
    const addr: Address = fc.getEntryAddress();
    if (!addr.isInvalid()) {
      encoder.openElement(ELEM_CALL);
      encoder.writeSpace(ATTRIB_SPACE, addr.getSpace()!);
      encoder.writeUnsignedInteger(ATTRIB_OFFSET, addr.getOffset());
      encoder.closeElement(ELEM_CALL);
    }
  }
  encoder.closeElement(ELEM_SIGNATURES);
}

/**
 * Generate features (with debug info) for a single function.
 *
 * Features are generated for the function and a complete description of each feature is
 * written to the encoder. The function must have been previously decompiled.
 */
export function debugSignature(fd: Funcdata, encoder: Encoder): void {
  const sigmanager = new GraphSigManager();

  sigmanager.setCurrentFunction(fd);
  sigmanager.generate();
  sigmanager.sortByHash();
  sigmanager.encode(encoder);
}
