/**
 * @file block_part1.ts
 * @description Classes related to basic blocks and control-flow structuring.
 * Translated from Ghidra's block.hh / block.cc (Part 1: FlowBlock, BlockBasic, BlockCopy, BlockGoto)
 */

import type { int4, uint4, uintb } from '../core/types.js';
import { Address, Range, RangeList } from '../core/address.js';
import { AddrSpace, spacetype } from '../core/space.js';
import {
  Encoder,
  Decoder,
  ElementId,
  AttributeId,
  ATTRIB_INDEX,
  ATTRIB_TYPE,
  ELEM_TARGET,
} from '../core/marshal.js';
import { LowlevelError } from '../core/error.js';
import { OpCode } from '../core/opcodes.js';
import { ListIter } from '../util/listiter.js';

// ---------------------------------------------------------------------------
// Forward type declarations for not-yet-written modules
// ---------------------------------------------------------------------------

type Architecture = any;
type Funcdata = any;
type PcodeOp = any;
type Varnode = any;
type JumpTable = any;
type PrintLanguage = any;
type Override = any;
type Symbol = any;
type FlowInfo = any;
type BlockBasic = any;

// ---------------------------------------------------------------------------
// Writer interface (replaces C++ ostream)
// ---------------------------------------------------------------------------

interface Writer {
  write(s: string): void;
}

// ---------------------------------------------------------------------------
// Marshaling attribute/element IDs defined in block.hh/cc
// ---------------------------------------------------------------------------

export const ATTRIB_ALTINDEX = new AttributeId("altindex", 75);
export const ATTRIB_DEPTH   = new AttributeId("depth", 76);
export const ATTRIB_END     = new AttributeId("end", 77);
export const ATTRIB_OPCODE  = new AttributeId("opcode", 78);
export const ATTRIB_REV     = new AttributeId("rev", 79);

export const ELEM_BHEAD     = new ElementId("bhead", 102);
export const ELEM_BLOCK     = new ElementId("block", 103);
export const ELEM_BLOCKEDGE = new ElementId("blockedge", 104);
export const ELEM_EDGE      = new ElementId("edge", 105);

// ---------------------------------------------------------------------------
// BlockEdge -- a control-flow edge between blocks
// ---------------------------------------------------------------------------

/**
 * A control-flow edge between blocks (FlowBlock).
 *
 * The edge is owned by the source block and can have edge_flags labels applied to it.
 * The `point` indicates the FlowBlock at the other end from the source block.
 * NOTE: The control-flow direction of the edge can only be determined from context,
 * whether the edge is in the incoming or outgoing edge list.
 */
export class BlockEdge {
  label: uint4;               // Label of the edge
  point: FlowBlock;           // Other end of the edge
  reverse_index: int4;        // Index for edge coming other way

  constructor();
  constructor(pt: FlowBlock, lab: uint4, rev: int4);
  constructor(pt?: FlowBlock, lab?: uint4, rev?: int4) {
    this.label = lab ?? 0;
    this.point = pt as any;
    this.reverse_index = rev ?? 0;
  }

  /** Encode this edge to a stream */
  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_EDGE);
    encoder.writeSignedInteger(ATTRIB_END, this.point.getIndex());
    encoder.writeSignedInteger(ATTRIB_REV, this.reverse_index);
    encoder.closeElement(ELEM_EDGE);
  }

  /** Decode this edge from a stream */
  decode(decoder: Decoder, resolver: BlockMap): void {
    const elemId = decoder.openElementId(ELEM_EDGE);
    this.label = 0;
    const endIndex: int4 = decoder.readSignedIntegerById(ATTRIB_END);
    this.point = (resolver as any).findLevelBlock(endIndex);
    if (this.point == null) {
      throw new LowlevelError("Bad serialized edge in block graph");
    }
    this.reverse_index = decoder.readSignedIntegerById(ATTRIB_REV);
    decoder.closeElement(elemId);
  }
}

// ---------------------------------------------------------------------------
// FlowBlock -- abstract base class for control-flow blocks
// ---------------------------------------------------------------------------

/**
 * The possible block types
 */
export enum block_type {
  t_plain = 0,
  t_basic,
  t_graph,
  t_copy,
  t_goto,
  t_multigoto,
  t_ls,
  t_condition,
  t_if,
  t_whiledo,
  t_dowhile,
  t_switch,
  t_infloop,
}

/**
 * Boolean properties of blocks.
 *
 * The first four flags describe attributes of the blocks primary exiting edges.
 * The f_interior_* flags do not necessarily apply to these edges. They are used
 * with the block structure and hierarchy algorithms where unstructured jumps
 * are removed from the list of primary edges.
 */
export const enum block_flags {
  f_goto_goto        = 1,
  f_break_goto       = 2,
  f_continue_goto    = 4,
  f_switch_out       = 0x10,
  f_unstructured_targ = 0x20,
  f_mark             = 0x80,
  f_mark2            = 0x100,
  f_entry_point      = 0x200,
  f_interior_gotoout = 0x400,
  f_interior_gotoin  = 0x800,
  f_label_bumpup     = 0x1000,
  f_donothing_loop   = 0x2000,
  f_dead             = 0x4000,
  f_whiledo_overflow = 0x8000,
  f_flip_path        = 0x10000,
  f_joined_block     = 0x20000,
  f_duplicate_block  = 0x40000,
}

/**
 * Boolean properties on edges
 */
export const enum edge_flags {
  f_goto_edge          = 1,
  f_loop_edge          = 2,
  f_defaultswitch_edge = 4,
  f_irreducible        = 8,
  f_tree_edge          = 0x10,
  f_forward_edge       = 0x20,
  f_cross_edge         = 0x40,
  f_back_edge          = 0x80,
  f_loop_exit_edge     = 0x100,
}

/**
 * Description of a control-flow block containing PcodeOps.
 *
 * This is the base class for basic blocks (BlockBasic) and the
 * hierarchical description of structured code. At all levels,
 * these can be viewed as a block of code (PcodeOp objects) with
 * other blocks flowing into and out of it.
 */
export class FlowBlock {
  // --- private fields (accessible by friend class BlockGraph) ---
  flags: uint4;               // Collection of block_flags
  parent: FlowBlock | null;   // The parent block to which this belongs
  immed_dom: FlowBlock | null; // Immediate dominating block
  copymap: FlowBlock | null;  // Back reference to a BlockCopy of this
  index: int4;                // Reference index for this block (reverse post order)
  visitcount: int4;           // A count of visits of this node for various algorithms
  numdesc: int4;              // Number of descendants of this block in spanning tree (+1)
  intothis: BlockEdge[];      // Blocks which (can) fall into this block
  outofthis: BlockEdge[];     // Blocks into which this block (can) fall
                              // If there are two possible outputs as the
                              // result of a conditional branch, the first block
                              // in outofthis should be the result of the condition being false

  constructor() {
    this.flags = 0;
    this.index = 0;
    this.visitcount = 0;
    this.numdesc = 0;
    this.parent = null;
    this.immed_dom = null;
    this.copymap = null;
    this.intothis = [];
    this.outofthis = [];
  }

  // --- protected methods ---

  /** Set a boolean property */
  setFlag(fl: uint4): void {
    this.flags |= fl;
  }

  /** Clear a boolean property */
  clearFlag(fl: uint4): void {
    this.flags &= ~fl;
  }

  // --- private methods ---

  /** Update block references in edges with copy map */
  static replaceEdgeMap(vec: BlockEdge[]): void {
    for (let i = 0; i < vec.length; ++i) {
      vec[i].point = vec[i].point.getCopyMap()!;
    }
  }

  /** Add an edge coming into this */
  addInEdge(b: FlowBlock, lab: uint4): void {
    const ourrev: int4 = b.outofthis.length;
    const brev: int4 = this.intothis.length;
    this.intothis.push(new BlockEdge(b, lab, ourrev));
    b.outofthis.push(new BlockEdge(this, lab, brev));
  }

  /** Decode the next input edge from stream */
  decodeNextInEdge(decoder: Decoder, resolver: BlockMap): void {
    const inedge = new BlockEdge();
    this.intothis.push(inedge);
    inedge.decode(decoder, resolver);
    while (inedge.point.outofthis.length <= inedge.reverse_index) {
      inedge.point.outofthis.push(new BlockEdge());
    }
    const outedge = inedge.point.outofthis[inedge.reverse_index];
    outedge.label = 0;
    outedge.point = this;
    outedge.reverse_index = this.intothis.length - 1;
  }

  /** Delete the in half of an edge, correcting indices */
  halfDeleteInEdge(slot: int4): void {
    while (slot < this.intothis.length - 1) {
      const edge = this.intothis[slot];
      this.intothis[slot] = this.intothis[slot + 1];
      const edge2 = this.intothis[slot];
      // Correct the index coming the other way
      const edger = edge2.point.outofthis[edge2.reverse_index];
      edger.reverse_index -= 1;
      slot += 1;
    }
    this.intothis.pop();
  }

  /** Delete the out half of an edge, correcting indices */
  halfDeleteOutEdge(slot: int4): void {
    while (slot < this.outofthis.length - 1) {
      this.outofthis[slot] = this.outofthis[slot + 1];
      const edge2 = this.outofthis[slot];
      // Correct the index coming the other way
      const edger = edge2.point.intothis[edge2.reverse_index];
      edger.reverse_index -= 1;
      slot += 1;
    }
    this.outofthis.pop();
  }

  /** Remove an incoming edge */
  removeInEdge(slot: int4): void {
    const b = this.intothis[slot].point;
    const rev = this.intothis[slot].reverse_index;
    this.halfDeleteInEdge(slot);
    b.halfDeleteOutEdge(rev);
  }

  /** Remove an outgoing edge */
  removeOutEdge(slot: int4): void {
    const b = this.outofthis[slot].point;
    const rev = this.outofthis[slot].reverse_index;
    this.halfDeleteOutEdge(slot);
    b.halfDeleteInEdge(rev);
  }

  /** Make an incoming edge flow from a given block */
  replaceInEdge(num: int4, b: FlowBlock): void {
    const oldb = this.intothis[num].point;
    oldb.halfDeleteOutEdge(this.intothis[num].reverse_index);
    this.intothis[num].point = b;
    this.intothis[num].reverse_index = b.outofthis.length;
    b.outofthis.push(new BlockEdge(this, this.intothis[num].label, num));
  }

  /** Make an outgoing edge flow to a given block */
  replaceOutEdge(num: int4, b: FlowBlock): void {
    const oldb = this.outofthis[num].point;
    oldb.halfDeleteInEdge(this.outofthis[num].reverse_index);
    this.outofthis[num].point = b;
    this.outofthis[num].reverse_index = b.intothis.length;
    b.intothis.push(new BlockEdge(this, this.outofthis[num].label, num));
  }

  /** Remove this from flow between two blocks */
  replaceEdgesThru(inSlot: int4, outSlot: int4): void {
    const inb = this.intothis[inSlot].point;
    const inblock_outslot = this.intothis[inSlot].reverse_index;
    const outb = this.outofthis[outSlot].point;
    const outblock_inslot = this.outofthis[outSlot].reverse_index;
    inb.outofthis[inblock_outslot].point = outb;
    inb.outofthis[inblock_outslot].reverse_index = outblock_inslot;
    outb.intothis[outblock_inslot].point = inb;
    outb.intothis[outblock_inslot].reverse_index = inblock_outslot;
    this.halfDeleteInEdge(inSlot);
    this.halfDeleteOutEdge(outSlot);
  }

  /** Swap the first and second out edges */
  swapEdges(): void {
    const tmp = this.outofthis[0];
    this.outofthis[0] = this.outofthis[1];
    this.outofthis[1] = tmp;
    let bl = this.outofthis[0].point;
    bl.intothis[this.outofthis[0].reverse_index].reverse_index = 0;
    bl = this.outofthis[1].point;
    bl.intothis[this.outofthis[1].reverse_index].reverse_index = 1;
    this.flags ^= block_flags.f_flip_path;
  }

  /** Apply an out edge label */
  setOutEdgeFlag(i: int4, lab: uint4): void {
    const bbout = this.outofthis[i].point;
    this.outofthis[i].label |= lab;
    bbout.intothis[this.outofthis[i].reverse_index].label |= lab;
  }

  /** Remove an out edge label */
  clearOutEdgeFlag(i: int4, lab: uint4): void {
    const bbout = this.outofthis[i].point;
    this.outofthis[i].label &= ~lab;
    bbout.intothis[this.outofthis[i].reverse_index].label &= ~lab;
  }

  /** Eliminate duplicate in edges from given block */
  eliminateInDups(bl: FlowBlock): void {
    let indval: int4 = -1;
    let i = 0;
    while (i < this.intothis.length) {
      if (this.intothis[i].point === bl) {
        if (indval === -1) {
          indval = i;
          i += 1;
        } else {
          this.intothis[indval].label |= this.intothis[i].label;
          const rev = this.intothis[i].reverse_index;
          this.halfDeleteInEdge(i);
          bl.halfDeleteOutEdge(rev);
        }
      } else {
        i += 1;
      }
    }
  }

  /** Eliminate duplicate out edges to given block */
  eliminateOutDups(bl: FlowBlock): void {
    let indval: int4 = -1;
    let i = 0;
    while (i < this.outofthis.length) {
      if (this.outofthis[i].point === bl) {
        if (indval === -1) {
          indval = i;
          i += 1;
        } else {
          this.outofthis[indval].label |= this.outofthis[i].label;
          const rev = this.outofthis[i].reverse_index;
          this.halfDeleteOutEdge(i);
          bl.halfDeleteInEdge(rev);
        }
      } else {
        i += 1;
      }
    }
  }

  /** Find blocks that are at the end of multiple edges */
  static findDups(ref: BlockEdge[], duplist: FlowBlock[]): void {
    for (let i = 0; i < ref.length; ++i) {
      if ((ref[i].point.flags & block_flags.f_mark2) !== 0) continue;
      if ((ref[i].point.flags & block_flags.f_mark) !== 0) {
        duplist.push(ref[i].point);
        ref[i].point.flags |= block_flags.f_mark2;
      } else {
        ref[i].point.flags |= block_flags.f_mark;
      }
    }
    for (let i = 0; i < ref.length; ++i) {
      ref[i].point.flags &= ~(block_flags.f_mark | block_flags.f_mark2);
    }
  }

  /** Eliminate duplicate edges */
  dedup(): void {
    let duplist: FlowBlock[] = [];

    FlowBlock.findDups(this.intothis, duplist);
    for (let i = 0; i < duplist.length; ++i) {
      this.eliminateInDups(duplist[i]);
    }

    duplist = [];
    FlowBlock.findDups(this.outofthis, duplist);
    for (let i = 0; i < duplist.length; ++i) {
      this.eliminateOutDups(duplist[i]);
    }
  }

  /** Update references to other blocks using getCopyMap() */
  replaceUsingMap(): void {
    FlowBlock.replaceEdgeMap(this.intothis);
    FlowBlock.replaceEdgeMap(this.outofthis);
    if (this.immed_dom != null) {
      this.immed_dom = this.immed_dom.getCopyMap();
    }
  }

  // --- public accessor methods ---

  /** Get the index assigned to this block */
  getIndex(): int4 { return this.index; }

  /** Get the parent FlowBlock of this */
  getParent(): FlowBlock | null { return this.parent; }

  /** Get the immediate dominator FlowBlock */
  getImmedDom(): FlowBlock | null { return this.immed_dom; }

  /** Get the mapped FlowBlock */
  getCopyMap(): FlowBlock | null { return this.copymap; }

  /** Get the block_flags properties */
  getFlags(): uint4 { return this.flags; }

  // --- virtual methods ---

  /** Get the starting address of code in this FlowBlock */
  getStart(): Address { return new Address(); }

  /** Get the ending address of code in this FlowBlock */
  getStop(): Address { return new Address(); }

  /** Get the FlowBlock type of this */
  getType(): block_type { return block_type.t_plain; }

  /** Get the i-th component block */
  subBlock(i: int4): FlowBlock | null { return null; }

  /** Mark target blocks of any unstructured edges */
  markUnstructured(): void {}

  /** Let hierarchical blocks steal labels of their (first) components */
  markLabelBumpUp(bump: boolean): void {
    if (bump) {
      this.flags |= block_flags.f_label_bumpup;
    }
  }

  /** Mark unstructured edges that should be breaks */
  scopeBreak(curexit: int4, curloopexit: int4): void {}

  /** Print a simple description of this to stream */
  printHeader(s: Writer): void {
    s.write(this.index.toString());
    if (!this.getStart().isInvalid() && !this.getStop().isInvalid()) {
      s.write(' ' + this.getStart().toString() + '-' + this.getStop().toString());
    }
  }

  /** Print tree structure of any blocks owned by this */
  printTree(s: Writer, level: int4): void {
    for (let i = 0; i < level; ++i) {
      s.write("  ");
    }
    this.printHeader(s);
    s.write("\n");
  }

  /** Print raw instructions contained in this FlowBlock */
  printRaw(s: Writer): void {}

  /** If the out block is not the given next block, print an implied goto */
  printRawImpliedGoto(s: Writer, nextBlock: FlowBlock): void {}

  /** Emit the instructions in this FlowBlock as structured code */
  emit(lng: PrintLanguage): void {}

  /** Get the leaf block from which this block exits */
  getExitLeaf(): FlowBlock | null { return null; }

  /** Get the first PcodeOp executed by this FlowBlock */
  firstOp(): PcodeOp | null { return null; }

  /** Get the last PcodeOp executed by this FlowBlock */
  lastOp(): PcodeOp | null { return null; }

  /** Flip the condition computed by this */
  negateCondition(toporbottom: boolean): boolean {
    if (!toporbottom) return false;
    this.swapEdges();
    return false;
  }

  /** Rearrange this hierarchy to simplify boolean expressions */
  preferComplement(data: Funcdata): boolean {
    return false;
  }

  /** Get the leaf splitting block */
  getSplitPoint(): FlowBlock | null {
    return null;
  }

  /** Test normalizing the conditional branch in this */
  flipInPlaceTest(fliplist: PcodeOp[]): int4 {
    return 2;
  }

  /** Perform the flip to normalize conditional branch executed by this block */
  flipInPlaceExecute(): void {}

  /** Is this too complex to be a condition (BlockCondition) */
  isComplex(): boolean { return true; }

  /** Get the leaf FlowBlock that will execute after the given FlowBlock */
  nextFlowAfter(bl: FlowBlock): FlowBlock | null {
    return null;
  }

  /** Do any structure driven final transforms */
  finalTransform(data: Funcdata): void {}

  /** Make any final configurations necessary to emit the block */
  finalizePrinting(data: Funcdata): void {}

  /** Encode basic information as attributes */
  encodeHeader(encoder: Encoder): void {
    encoder.writeSignedInteger(ATTRIB_INDEX, this.index);
  }

  /** Decode basic information from element attributes */
  decodeHeader(decoder: Decoder): void {
    this.index = decoder.readSignedIntegerById(ATTRIB_INDEX);
  }

  /** Encode detail about this block and its components to a stream */
  encodeBody(encoder: Encoder): void {}

  /** Restore details about this FlowBlock from an element stream */
  decodeBody(decoder: Decoder): void {}

  /** Encode edge information to a stream */
  encodeEdges(encoder: Encoder): void {
    for (let i = 0; i < this.intothis.length; ++i) {
      this.intothis[i].encode(encoder);
    }
  }

  /** Decode edges from a stream */
  decodeEdges(decoder: Decoder, resolver: BlockMap): void {
    for (;;) {
      const subId: uint4 = decoder.peekElement();
      if (!ELEM_EDGE.equals(subId)) break;
      this.decodeNextInEdge(decoder, resolver);
    }
  }

  /** Encode this to a stream */
  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_BLOCK);
    this.encodeHeader(encoder);
    this.encodeBody(encoder);
    this.encodeEdges(encoder);
    encoder.closeElement(ELEM_BLOCK);
  }

  /** Decode this from a stream */
  decode(decoder: Decoder, resolver: BlockMap): void {
    const elemId: uint4 = decoder.openElementId(ELEM_BLOCK);
    this.decodeHeader(decoder);
    this.decodeBody(decoder);
    this.decodeEdges(decoder, resolver);
    decoder.closeElement(elemId);
  }

  /** Return next block to be executed in flow */
  nextInFlow(): FlowBlock | null {
    if (this.sizeOut() === 1) return this.getOut(0);
    if (this.sizeOut() === 2) {
      const op = this.lastOp();
      if (op == null) return null;
      if ((op as any).code() !== OpCode.CPUI_CBRANCH) return null;
      return (op as any).isFallthruTrue() ? this.getOut(1) : this.getOut(0);
    }
    return null;
  }

  /** Set the number of times this block has been visited */
  setVisitCount(i: int4): void { this.visitcount = i; }

  /** Get the count of visits */
  getVisitCount(): int4 { return this.visitcount; }

  /** Mark a goto branch */
  setGotoBranch(i: int4): void {
    if (i >= 0 && i < this.outofthis.length) {
      this.setOutEdgeFlag(i, edge_flags.f_goto_edge);
    } else {
      throw new LowlevelError("Could not find block edge to mark unstructured");
    }
    this.flags |= block_flags.f_interior_gotoout;
    this.outofthis[i].point.flags |= block_flags.f_interior_gotoin;
  }

  /** Mark an edge as the switch default */
  setDefaultSwitch(pos: int4): void {
    for (let i = 0; i < this.outofthis.length; ++i) {
      if (this.isDefaultBranch(i)) {
        this.clearOutEdgeFlag(i, edge_flags.f_defaultswitch_edge);
      }
    }
    this.setOutEdgeFlag(pos, edge_flags.f_defaultswitch_edge);
  }

  /** Return true if this block has been marked */
  isMark(): boolean { return (this.flags & block_flags.f_mark) !== 0; }

  /** Mark this block */
  setMark(): void { this.flags |= block_flags.f_mark; }

  /** Clear any mark on this block */
  clearMark(): void { this.flags &= ~block_flags.f_mark; }

  /** Label this as a do nothing loop */
  setDonothingLoop(): void { this.flags |= block_flags.f_donothing_loop; }

  /** Label this as dead */
  setDead(): void { this.flags |= block_flags.f_dead; }

  /** Return true if this uses a different label */
  hasSpecialLabel(): boolean {
    return (this.flags & (block_flags.f_joined_block | block_flags.f_duplicate_block)) !== 0;
  }

  /** Return true if this is a joined basic block */
  isJoined(): boolean { return (this.flags & block_flags.f_joined_block) !== 0; }

  /** Return true if this is a duplicated block */
  isDuplicated(): boolean { return (this.flags & block_flags.f_duplicate_block) !== 0; }

  /** Label the edge exiting this as a loop */
  setLoopExit(i: int4): void { this.setOutEdgeFlag(i, edge_flags.f_loop_exit_edge); }

  /** Clear the loop exit edge */
  clearLoopExit(i: int4): void { this.clearOutEdgeFlag(i, edge_flags.f_loop_exit_edge); }

  /** Label the back edge of a loop */
  setBackEdge(i: int4): void { this.setOutEdgeFlag(i, edge_flags.f_back_edge); }

  /** Have out edges been flipped */
  getFlipPath(): boolean { return (this.flags & block_flags.f_flip_path) !== 0; }

  /** Return true if non-fallthru jump flows into this */
  isJumpTarget(): boolean {
    for (let i = 0; i < this.intothis.length; ++i) {
      if (this.intothis[i].point.index !== this.index - 1) return true;
    }
    return false;
  }

  /** Get the false output FlowBlock */
  getFalseOut(): FlowBlock { return this.outofthis[0].point; }

  /** Get the true output FlowBlock */
  getTrueOut(): FlowBlock { return this.outofthis[1].point; }

  /** Get the i-th output FlowBlock */
  getOut(i: int4): FlowBlock { return this.outofthis[i].point; }

  /** Get the input index of the i-th output FlowBlock */
  getOutRevIndex(i: int4): int4 { return this.outofthis[i].reverse_index; }

  /** Get the i-th input FlowBlock */
  getIn(i: int4): FlowBlock { return this.intothis[i].point; }

  /** Get the output index of the i-th input FlowBlock */
  getInRevIndex(i: int4): int4 { return this.intothis[i].reverse_index; }

  /** Get the first leaf FlowBlock */
  getFrontLeaf(): FlowBlock | null {
    let bl: FlowBlock | null = this;
    while (bl!.getType() !== block_type.t_copy) {
      bl = bl!.subBlock(0);
      if (bl == null) return bl;
    }
    return bl;
  }

  /** How many getParent() calls from the leaf to this */
  calcDepth(leaf: FlowBlock): int4 {
    let depth = 0;
    let cur: FlowBlock | null = leaf;
    while (cur !== this) {
      if (cur == null) return -1;
      cur = cur.getParent();
      depth += 1;
    }
    return depth;
  }

  /** Does this block dominate the given block */
  dominates(sub: FlowBlock): boolean {
    let cur: FlowBlock | null = sub;
    while (cur != null && this.index <= cur.index) {
      if (cur === this) return true;
      cur = cur.getImmedDom();
    }
    return false;
  }

  /**
   * Check if the condition from the given block holds for this block.
   *
   * We assume the given block has 2 out-edges and that this block is immediately reached by
   * one of these two edges. We verify that the condition holds for this entire block.
   */
  restrictedByConditional(cond: FlowBlock): boolean {
    if (this.sizeIn() === 1) return true;
    if (this.getImmedDom() !== cond) return false;
    let seenCond = false;
    for (let i = 0; i < this.sizeIn(); ++i) {
      let inBlock: FlowBlock | null = this.getIn(i);
      if (inBlock === cond) {
        if (seenCond) return false;
        seenCond = true;
        continue;
      }
      while (inBlock !== this) {
        if (inBlock === cond) return false;
        inBlock = inBlock!.getImmedDom();
      }
    }
    return true;
  }

  /** Get the number of out edges */
  sizeOut(): int4 { return this.outofthis.length; }

  /** Get the number of in edges */
  sizeIn(): int4 { return this.intothis.length; }

  /** Is there a looping edge coming into this block */
  hasLoopIn(): boolean {
    for (let i = 0; i < this.intothis.length; ++i) {
      if ((this.intothis[i].label & edge_flags.f_loop_edge) !== 0) return true;
    }
    return false;
  }

  /** Is there a looping edge going out of this block */
  hasLoopOut(): boolean {
    for (let i = 0; i < this.outofthis.length; ++i) {
      if ((this.outofthis[i].label & edge_flags.f_loop_edge) !== 0) return true;
    }
    return false;
  }

  /** Is the i-th incoming edge a loop edge */
  isLoopIn(i: int4): boolean {
    return (this.intothis[i].label & edge_flags.f_loop_edge) !== 0;
  }

  /** Is the i-th outgoing edge a loop edge */
  isLoopOut(i: int4): boolean {
    return (this.outofthis[i].label & edge_flags.f_loop_edge) !== 0;
  }

  /** Get the incoming edge index for the given FlowBlock */
  getInIndex(bl: FlowBlock): int4 {
    for (let blocknum = 0; blocknum < this.intothis.length; ++blocknum) {
      if (this.intothis[blocknum].point === bl) return blocknum;
    }
    return -1;
  }

  /** Get the outgoing edge index for the given FlowBlock */
  getOutIndex(bl: FlowBlock): int4 {
    for (let blocknum = 0; blocknum < this.outofthis.length; ++blocknum) {
      if (this.outofthis[blocknum].point === bl) return blocknum;
    }
    return -1;
  }

  /** Is the i-th out edge the switch default edge */
  isDefaultBranch(i: int4): boolean {
    return (this.outofthis[i].label & edge_flags.f_defaultswitch_edge) !== 0;
  }

  /** Are labels for this printed by the parent */
  isLabelBumpUp(): boolean {
    return (this.flags & block_flags.f_label_bumpup) !== 0;
  }

  /** Is this the target of an unstructured goto */
  isUnstructuredTarget(): boolean {
    return (this.flags & block_flags.f_unstructured_targ) !== 0;
  }

  /** Is there an unstructured goto to this block's interior */
  isInteriorGotoTarget(): boolean {
    return (this.flags & block_flags.f_interior_gotoin) !== 0;
  }

  /** Is there an unstructured goto out of this block's interior */
  hasInteriorGoto(): boolean {
    return (this.flags & block_flags.f_interior_gotoout) !== 0;
  }

  /** Is the entry point of the function */
  isEntryPoint(): boolean {
    return (this.flags & block_flags.f_entry_point) !== 0;
  }

  /** Is this a switch block */
  isSwitchOut(): boolean {
    return (this.flags & block_flags.f_switch_out) !== 0;
  }

  /** Is this a do nothing block */
  isDonothingLoop(): boolean {
    return (this.flags & block_flags.f_donothing_loop) !== 0;
  }

  /** Is this block dead */
  isDead(): boolean {
    return (this.flags & block_flags.f_dead) !== 0;
  }

  /** Is the i-th incoming edge part of the spanning tree */
  isTreeEdgeIn(i: int4): boolean {
    return (this.intothis[i].label & edge_flags.f_tree_edge) !== 0;
  }

  /** Is the i-th incoming edge a back edge */
  isBackEdgeIn(i: int4): boolean {
    return (this.intothis[i].label & edge_flags.f_back_edge) !== 0;
  }

  /** Is the i-th outgoing edge a back edge */
  isBackEdgeOut(i: int4): boolean {
    return (this.outofthis[i].label & edge_flags.f_back_edge) !== 0;
  }

  /** Is the i-th outgoing edge an irreducible edge */
  isIrreducibleOut(i: int4): boolean {
    return (this.outofthis[i].label & edge_flags.f_irreducible) !== 0;
  }

  /** Is the i-th incoming edge an irreducible edge */
  isIrreducibleIn(i: int4): boolean {
    return (this.intothis[i].label & edge_flags.f_irreducible) !== 0;
  }

  /** Can this and the i-th output be merged into a BlockIf or BlockList */
  isDecisionOut(i: int4): boolean {
    return (this.outofthis[i].label & (edge_flags.f_irreducible | edge_flags.f_back_edge | edge_flags.f_goto_edge)) === 0;
  }

  /** Can this and the i-th input be merged into a BlockIf or BlockList */
  isDecisionIn(i: int4): boolean {
    return (this.intothis[i].label & (edge_flags.f_irreducible | edge_flags.f_back_edge | edge_flags.f_goto_edge)) === 0;
  }

  /** Is the i-th outgoing edge part of the DAG sub-graph */
  isLoopDAGOut(i: int4): boolean {
    return (this.outofthis[i].label & (edge_flags.f_irreducible | edge_flags.f_back_edge | edge_flags.f_loop_exit_edge | edge_flags.f_goto_edge)) === 0;
  }

  /** Is the i-th incoming edge part of the DAG sub-graph */
  isLoopDAGIn(i: int4): boolean {
    return (this.intothis[i].label & (edge_flags.f_irreducible | edge_flags.f_back_edge | edge_flags.f_loop_exit_edge | edge_flags.f_goto_edge)) === 0;
  }

  /** Is the i-th incoming edge unstructured */
  isGotoIn(i: int4): boolean {
    return (this.intothis[i].label & (edge_flags.f_irreducible | edge_flags.f_goto_edge)) !== 0;
  }

  /** Is the i-th outgoing edge unstructured */
  isGotoOut(i: int4): boolean {
    return (this.outofthis[i].label & (edge_flags.f_irreducible | edge_flags.f_goto_edge)) !== 0;
  }

  /** Get the JumpTable associated with this block */
  getJumptable(): JumpTable | null {
    let jt: JumpTable | null = null;
    if (!this.isSwitchOut()) return jt;
    const indop = this.lastOp();
    if (indop != null) {
      jt = (indop as any).getParent().getFuncdata().findJumpTable(indop);
    }
    return jt;
  }

  /** Print a short identifier for the block */
  printShortHeader(s: Writer): void {
    s.write("Block_" + this.index.toString());
    if (!this.getStart().isInvalid()) {
      s.write(':' + this.getStart().toString());
    }
  }

  /** Get the block_type associated with a name string */
  static nameToType(nm: string): block_type {
    let bt: block_type = block_type.t_plain;
    if (nm === "graph")
      bt = block_type.t_graph;
    else if (nm === "copy")
      bt = block_type.t_copy;
    return bt;
  }

  /** Get the name string associated with a block_type */
  static typeToName(bt: block_type): string {
    switch (bt) {
      case block_type.t_plain:     return "plain";
      case block_type.t_basic:     return "basic";
      case block_type.t_graph:     return "graph";
      case block_type.t_copy:      return "copy";
      case block_type.t_goto:      return "goto";
      case block_type.t_multigoto: return "multigoto";
      case block_type.t_ls:        return "list";
      case block_type.t_condition: return "condition";
      case block_type.t_if:        return "properif";
      case block_type.t_whiledo:   return "whiledo";
      case block_type.t_dowhile:   return "dowhile";
      case block_type.t_switch:    return "switch";
      case block_type.t_infloop:   return "infloop";
    }
    return "";
  }

  /** Compare FlowBlock by index */
  static compareBlockIndex(bl1: FlowBlock, bl2: FlowBlock): boolean {
    return bl1.getIndex() < bl2.getIndex();
  }

  /** Final FlowBlock comparison */
  static compareFinalOrder(bl1: FlowBlock, bl2: FlowBlock): boolean {
    if (bl1.getIndex() === 0) return true;
    if (bl2.getIndex() === 0) return false;
    const op1 = bl1.lastOp();
    const op2 = bl2.lastOp();

    if (op1 != null) {
      if (op2 != null) {
        if ((op1 as any).code() === OpCode.CPUI_RETURN && (op2 as any).code() !== OpCode.CPUI_RETURN)
          return false;
        else if ((op1 as any).code() !== OpCode.CPUI_RETURN && (op2 as any).code() === OpCode.CPUI_RETURN)
          return true;
      }
      if ((op1 as any).code() === OpCode.CPUI_RETURN) return false;
    } else if (op2 != null) {
      if ((op2 as any).code() === OpCode.CPUI_RETURN) return true;
    }
    return bl1.getIndex() < bl2.getIndex();
  }

  /** Find the common dominator of two FlowBlocks */
  static findCommonBlock(bl1: FlowBlock, bl2: FlowBlock): FlowBlock | null;
  static findCommonBlock(blockSet: FlowBlock[]): FlowBlock;
  static findCommonBlock(
    bl1OrSet: FlowBlock | FlowBlock[],
    bl2?: FlowBlock
  ): FlowBlock | null {
    if (Array.isArray(bl1OrSet)) {
      return FlowBlock._findCommonBlockMulti(bl1OrSet);
    }
    return FlowBlock._findCommonBlockPair(bl1OrSet, bl2!);
  }

  /** Find the common dominator of two FlowBlocks (pair version) */
  private static _findCommonBlockPair(bl1: FlowBlock, bl2: FlowBlock): FlowBlock | null {
    let common: FlowBlock | null = null;
    let b1: FlowBlock | null = bl1;
    let b2: FlowBlock | null = bl2;

    for (;;) {
      if (b2 == null) {
        while (b1 != null) {
          if (b1.isMark()) {
            common = b1;
            break;
          }
          b1 = b1.getImmedDom();
        }
        break;
      }
      if (b1 == null) {
        while (b2 != null) {
          if (b2.isMark()) {
            common = b2;
            break;
          }
          b2 = b2.getImmedDom();
        }
        break;
      }
      if (b1.isMark()) {
        common = b1;
        break;
      }
      b1.setMark();
      if (b2.isMark()) {
        common = b2;
        break;
      }
      b2.setMark();
      b1 = b1.getImmedDom();
      b2 = b2.getImmedDom();
    }
    // Clear our marks
    let c1: FlowBlock | null = bl1;
    while (c1 != null) {
      if (!c1.isMark()) break;
      c1.clearMark();
      c1 = c1.getImmedDom();
    }
    let c2: FlowBlock | null = bl2;
    while (c2 != null) {
      if (!c2.isMark()) break;
      c2.clearMark();
      c2 = c2.getImmedDom();
    }
    return common;
  }

  /** Find common dominator of multiple FlowBlocks */
  private static _findCommonBlockMulti(blockSet: FlowBlock[]): FlowBlock {
    const markedSet: FlowBlock[] = [];
    let bl: FlowBlock | null;
    let res = blockSet[0];
    let bestIndex = res.getIndex();
    bl = res;
    do {
      bl!.setMark();
      markedSet.push(bl!);
      bl = bl!.getImmedDom();
    } while (bl != null);
    for (let i = 1; i < blockSet.length; ++i) {
      if (bestIndex === 0) break;
      bl = blockSet[i];
      while (!bl!.isMark()) {
        bl!.setMark();
        markedSet.push(bl!);
        bl = bl!.getImmedDom();
      }
      if (bl!.getIndex() < bestIndex) {
        res = bl!;
        bestIndex = res.getIndex();
      }
    }
    for (let i = 0; i < markedSet.length; ++i) {
      markedSet[i].clearMark();
    }
    return res;
  }

  /**
   * Find conditional block that decides between the given control-flow edges.
   *
   * There must be a unique path from the conditional block through the first edge, and
   * a second unique path through the second edge. Otherwise null is returned.
   */
  static findCondition(
    bl1: FlowBlock,
    edge1: int4,
    bl2: FlowBlock,
    edge2: int4,
    slot1Out: { value: int4 }
  ): FlowBlock | null {
    let cond = bl1.getIn(edge1);
    while (cond.sizeOut() !== 2) {
      if (cond.sizeOut() !== 1) return null;
      bl1 = cond;
      edge1 = 0;
      cond = bl1.getIn(0);
    }

    while (cond !== bl2.getIn(edge2)) {
      bl2 = bl2.getIn(edge2);
      if (bl2.sizeOut() !== 1) return null;
      edge2 = 0;
    }
    slot1Out.value = bl1.getInRevIndex(edge1);
    return cond;
  }
}

// ---------------------------------------------------------------------------
// BlockBasicStub -- basic block for p-code operations
// ---------------------------------------------------------------------------

/**
 * A basic block for p-code operations.
 *
 * A basic block is a maximal sequence of p-code operations (PcodeOp) that,
 * within the context of a function, always execute starting with the first
 * operation in sequence through in order to the last operation. Any decision points
 * in the control flow of a function manifest as branching operations
 * (BRANCH, CBRANCH, BRANCHIND) that necessarily occur as the last operation
 * in a basic block.
 */
export class BlockBasicClass extends FlowBlock {
  op: PcodeOp[];               // The sequence of p-code operations (list in C++)
  data: Funcdata;               // The function of which this block is a part
  cover: RangeList;             // Original range of addresses covered by this basic block

  constructor(fd: Funcdata) {
    super();
    this.data = fd;
    this.op = [];
    this.cover = new RangeList();
  }

  /** Get the list of p-code operations in this block */
  getOpList(): PcodeOp[] { return this.op; }

  // --- private / friend methods ---

  /** Insert p-code operation at a given position (accepts index or ListIter) */
  insert(iterIdx: int4 | ListIter<PcodeOp>, inst: PcodeOp): void {
    const idx = typeof iterIdx === 'number' ? iterIdx : iterIdx.getIndex();
    (inst as any).setParent(this);
    this.op.splice(idx, 0, inst);
    // Update basiciter for the inserted op and all shifted ops
    (inst as any).setBasicIter(idx);
    for (let i = idx + 1; i < this.op.length; i++) {
      (this.op[i] as any).setBasicIter(i);
    }
    // Simplified ordering: assign sequential order
    // Full re-ordering handled by setOrder()
    if ((inst as any).isBranch()) {
      if ((inst as any).code() === OpCode.CPUI_BRANCHIND) {
        this.setFlag(block_flags.f_switch_out);
      }
    }
  }

  /** Set the initial address range of the block */
  setInitialRange(beg: Address, end: Address): void {
    this.cover.clear();
    this.cover.insertRange(beg.getSpace()!, beg.getOffset(), end.getOffset());
  }

  /** Copy address ranges from another basic block */
  copyRange(bb: BlockBasicClass): void {
    this.cover = new RangeList(bb.cover);
  }

  /** Merge address ranges from another basic block */
  mergeRange(bb: BlockBasicClass): void {
    this.cover.merge(bb.cover);
  }

  /** Reset the SeqNum.order field for all PcodeOp objects in this block */
  setOrder(): void {
    if (this.op.length === 0) return;
    const maxVal = 0xFFFFFFFF;
    const step = Math.floor(maxVal / this.op.length) - 1;
    let count = 0;
    for (let i = 0; i < this.op.length; ++i) {
      count += step;
      (this.op[i] as any).setOrder(count);
    }
  }

  /** Remove PcodeOp from this basic block */
  removeOp(inst: PcodeOp): void {
    const idx = this.op.indexOf(inst);
    if (idx >= 0) {
      this.op.splice(idx, 1);
      // Update basiciter for all shifted ops
      for (let i = idx; i < this.op.length; i++) {
        (this.op[i] as any).setBasicIter(i);
      }
    }
    (inst as any).setParent(null);
  }

  // --- public methods ---

  /** Return the underlying Funcdata object */
  getFuncdata(): Funcdata { return this.data; }

  /** Determine if the given address is contained in the original range */
  contains(addr: Address): boolean {
    return this.cover.inRange(addr, 1);
  }

  /** Get the address of the (original) first operation to execute */
  getEntryAddr(): Address {
    let range: Range | null;
    if (this.cover.numRanges() === 1) {
      range = this.cover.getFirstRange();
    } else {
      if (this.op.length === 0) return new Address();
      const addr: Address = (this.op[0] as any).getAddr();
      range = this.cover.getRange(addr.getSpace()!, addr.getOffset());
      if (range == null) {
        return (this.op[0] as any).getAddr();
      }
    }
    return range!.getFirstAddr();
  }

  override getStart(): Address {
    const range = this.cover.getFirstRange();
    if (range == null) return new Address();
    return range.getFirstAddr();
  }

  override getStop(): Address {
    const range = this.cover.getLastRange();
    if (range == null) return new Address();
    return range.getLastAddr();
  }

  override getType(): block_type { return block_type.t_basic; }

  override subBlock(i: int4): FlowBlock | null { return null; }

  override encodeBody(encoder: Encoder): void {
    (this.cover as any).encode(encoder);
  }

  override decodeBody(decoder: Decoder): void {
    (this.cover as any).decode(decoder);
  }

  override printHeader(s: Writer): void {
    s.write("Basic Block ");
    super.printHeader(s);
  }

  override printRaw(s: Writer): void {
    this.printHeader(s);
    s.write("\n");
    for (let i = 0; i < this.op.length; ++i) {
      const inst = this.op[i];
      s.write((inst as any).getSeqNum().toString() + ":\t");
      (inst as any).printRaw(s);
      s.write("\n");
    }
  }

  override printRawImpliedGoto(s: Writer, nextBlock: FlowBlock): void {
    if (this.sizeOut() !== 1) return;
    const outBlock = this.getOut(0);
    let resolvedNext: FlowBlock | null = nextBlock;
    if (resolvedNext.getType() !== block_type.t_basic) {
      resolvedNext = resolvedNext.getFrontLeaf();
      if (resolvedNext == null) return;
      resolvedNext = resolvedNext.subBlock(0);
    }
    if (this.getOut(0) === resolvedNext) return;
    if (this.op.length > 0 && (this.op[this.op.length - 1] as any).isBranch()) return;
    (this.getStop() as any).printRaw(s);
    s.write(":   \t[ goto ");
    outBlock.printShortHeader(s);
    s.write(" ]\n");
  }

  override emit(lng: PrintLanguage): void {
    (lng as any).emitBlockBasic(this);
  }

  override getExitLeaf(): FlowBlock | null { return this; }

  override firstOp(): PcodeOp | null {
    if (this.op.length === 0) return null;
    return this.op[0];
  }

  override lastOp(): PcodeOp | null {
    if (this.op.length === 0) return null;
    return this.op[this.op.length - 1];
  }

  override negateCondition(toporbottom: boolean): boolean {
    const lastop = this.op[this.op.length - 1];
    (lastop as any).flipFlag((lastop as any).constructor.boolean_flip ?? 0x20);
    (lastop as any).flipFlag((lastop as any).constructor.fallthru_true ?? 0x40);
    super.negateCondition(true);
    return true;
  }

  override getSplitPoint(): FlowBlock | null {
    if (this.sizeOut() !== 2) return null;
    return this;
  }

  override flipInPlaceTest(fliplist: PcodeOp[]): int4 {
    if (this.op.length === 0) return 2;
    const lastop = this.op[this.op.length - 1];
    if ((lastop as any).code() !== OpCode.CPUI_CBRANCH)
      return 2;
    return (this.data.constructor as any).opFlipInPlaceTest(lastop, fliplist);
  }

  override flipInPlaceExecute(): void {
    const lastop = this.op[this.op.length - 1];
    (lastop as any).flipFlag((lastop as any).constructor.fallthru_true ?? 0x40);
    super.negateCondition(true);
  }

  override isComplex(): boolean {
    let statement = 0;
    if (this.sizeOut() >= 2)
      statement = 1;
    const maxref: int4 = (this.data as any).getArch().max_implied_ref;
    for (let idx = 0; idx < this.op.length; ++idx) {
      const inst = this.op[idx];
      if ((inst as any).isMarker()) continue;
      const vn = (inst as any).getOut();
      if ((inst as any).isCall()) {
        statement += 1;
      } else if (vn == null) {
        if ((inst as any).isFlowBreak()) continue;
        statement += 1;
      } else {
        let yesstatement = false;
        if ((vn as any).hasNoDescend()) {
          yesstatement = true;
        } else if ((vn as any).isAddrTied()) {
          yesstatement = true;
        } else {
          let totalref = 0;
          const descEnd = (vn as any).endDescend();
          for (let dIter = (vn as any).beginDescend(); dIter < descEnd; dIter += 1) {
            const d_op = (vn as any).getDescend(dIter);
            if ((d_op as any).isMarker() || (d_op as any).getParent() !== this) {
              yesstatement = true;
              break;
            }
            totalref += 1;
            if (totalref > maxref) {
              yesstatement = true;
              break;
            }
          }
        }
        if (yesstatement)
          statement += 1;
      }
      if (statement > 2) return true;
    }
    return false;
  }

  /** Check if this block can be removed without introducing inconsistencies */
  unblockedMulti(outslot: int4): boolean {
    const blout = this.getOut(outslot) as any;
    const redundlist: FlowBlock[] = [];
    for (let i = 0; i < this.sizeIn(); ++i) {
      const bl = this.getIn(i);
      for (let j = 0; j < bl.sizeOut(); ++j) {
        if (bl.getOut(j) === blout) {
          redundlist.push(bl);
        }
      }
    }
    if (redundlist.length === 0) return true;
    for (let idx = 0; idx < blout.op.length; ++idx) {
      const multiop = blout.op[idx];
      if ((multiop as any).code() !== OpCode.CPUI_MULTIEQUAL) continue;
      for (let bIdx = 0; bIdx < redundlist.length; ++bIdx) {
        const bl = redundlist[bIdx];
        const vnredund = (multiop as any).getIn(blout.getInIndex(bl));
        let vnremove = (multiop as any).getIn(blout.getInIndex(this));
        if ((vnremove as any).isWritten()) {
          const othermulti = (vnremove as any).getDef();
          if ((othermulti as any).code() === OpCode.CPUI_MULTIEQUAL && (othermulti as any).getParent() === this) {
            vnremove = (othermulti as any).getIn(this.getInIndex(bl));
          }
        }
        if (vnremove !== vnredund) return false;
      }
    }
    return true;
  }

  /** Does this block contain only MULTIEQUAL and INDIRECT ops */
  hasOnlyMarkers(): boolean {
    for (let i = 0; i < this.op.length; ++i) {
      const bop = this.op[i];
      if ((bop as any).isMarker()) continue;
      if ((bop as any).isBranch()) continue;
      return false;
    }
    return true;
  }

  /** Should this block be removed */
  isDoNothing(): boolean {
    if (this.sizeOut() !== 1) return false;
    if (this.sizeIn() === 0) return false;
    for (let i = 0; i < this.sizeIn(); ++i) {
      const switchbl = this.getIn(i);
      if (!switchbl.isSwitchOut()) continue;
      if (switchbl.sizeOut() > 1) {
        if (this.getOut(0).sizeIn() > 1) {
          return false;
        }
      }
    }
    const lastop = this.lastOp();
    if (lastop != null && (lastop as any).code() === OpCode.CPUI_BRANCHIND)
      return false;
    return this.hasOnlyMarkers();
  }

  /** Return an iterator to the beginning of the PcodeOps */
  beginOp(): ListIter<PcodeOp> { return new ListIter(this.op, 0); }

  /** Return an iterator to the end of the PcodeOps */
  endOp(): ListIter<PcodeOp> { return new ListIter(this.op, this.op.length); }

  /** Return the PcodeOps as an iterable array */
  getOpIterator(): any[] { return [...this.op]; }

  /** Return true if block contains no operations */
  emptyOp(): boolean { return this.op.length === 0; }

  /** Check for values created in this block that flow outside the block */
  noInterveningStatement(): boolean {
    for (let idx = 0; idx < this.op.length; ++idx) {
      const bop = this.op[idx];
      if ((bop as any).isMarker()) continue;
      if ((bop as any).isBranch()) continue;
      if ((bop as any).getEvalType() === 0) {  // PcodeOp::special
        if ((bop as any).isCall()) return false;
        const opc = (bop as any).code();
        if (opc === OpCode.CPUI_STORE || opc === OpCode.CPUI_NEW) return false;
      } else {
        const opc = (bop as any).code();
        if (opc === OpCode.CPUI_COPY || opc === OpCode.CPUI_SUBPIECE) continue;
      }
      const outvn = (bop as any).getOut();
      if ((outvn as any).isAddrTied()) return false;
      const dEnd = (outvn as any).endDescend();
      for (let it = (outvn as any).beginDescend(); it < dEnd; it++) {
        if ((outvn as any).getDescend(it).getParent() !== this) return false;
      }
    }
    return true;
  }

  /** Find MULTIEQUAL with given inputs */
  findMultiequal(varArray: Varnode[]): PcodeOp | null {
    const vn = varArray[0];
    let op: PcodeOp | null = null;
    // Simplified: iterate over all ops in this block looking for MULTIEQUAL
    for (let i = 0; i < this.op.length; ++i) {
      const candidate = this.op[i];
      if ((candidate as any).code() === OpCode.CPUI_MULTIEQUAL) {
        // Check if first input matches
        if ((candidate as any).getIn(0) === vn) {
          op = candidate;
          break;
        }
      }
    }
    if (op == null) return null;
    for (let i = 0; i < (op as any).numInput(); ++i) {
      if ((op as any).getIn(i) !== varArray[i]) return null;
    }
    return op;
  }

  /** Get the earliest use/read of a Varnode in this basic block */
  earliestUse(vn: Varnode): PcodeOp | null {
    // Simplified: would iterate over vn's descendants
    return null;
  }

  /** Verify given Varnodes are defined with same PcodeOp */
  static liftVerifyUnroll(varArray: Varnode[], slot: int4): boolean {
    let vn = varArray[0];
    if (!(vn as any).isWritten()) return false;
    let op = (vn as any).getDef();
    const opc = (op as any).code();
    let cvn: Varnode | null;
    if ((op as any).numInput() === 2) {
      cvn = (op as any).getIn(1 - slot);
      if (!(cvn as any).isConstant()) return false;
    } else {
      cvn = null;
    }
    varArray[0] = (op as any).getIn(slot);
    for (let i = 1; i < varArray.length; ++i) {
      vn = varArray[i];
      if (!(vn as any).isWritten()) return false;
      op = (vn as any).getDef();
      if ((op as any).code() !== opc) return false;
      if (cvn != null) {
        const cvn2 = (op as any).getIn(1 - slot);
        if (!(cvn2 as any).isConstant()) return false;
        if ((cvn as any).getSize() !== (cvn2 as any).getSize()) return false;
        if ((cvn as any).getOffset() !== (cvn2 as any).getOffset()) return false;
      }
      varArray[i] = (op as any).getIn(slot);
    }
    return true;
  }
}

// ---------------------------------------------------------------------------
// BlockCopy -- mirrors a BlockBasic in the fixed control-flow graph
// ---------------------------------------------------------------------------

/**
 * This class is used to mirror the BlockBasic objects in the fixed control-flow graph for a function.
 *
 * The decompiler does control-flow structuring by making an initial copy of the control-flow graph,
 * then iteratively collapsing nodes (in the copy) into structured nodes. So an instance of this
 * class acts as the mirror of an original basic block within the copy of the graph.
 */
export class BlockCopy extends FlowBlock {
  private copy: FlowBlock;     // The block being mirrored by this (usually a BlockBasic)

  constructor(bl: FlowBlock) {
    super();
    this.copy = bl;
  }

  override subBlock(i: int4): FlowBlock | null { return this.copy; }

  override getType(): block_type { return block_type.t_copy; }

  override printHeader(s: Writer): void {
    s.write("Basic(copy) block ");
    super.printHeader(s);
  }

  override printTree(s: Writer, level: int4): void {
    this.copy.printTree(s, level);
  }

  override printRaw(s: Writer): void {
    this.copy.printRaw(s);
  }

  override printRawImpliedGoto(s: Writer, nextBlock: FlowBlock): void {
    this.copy.printRawImpliedGoto(s, nextBlock);
  }

  override emit(lng: PrintLanguage): void {
    (lng as any).emitBlockCopy(this);
  }

  override getExitLeaf(): FlowBlock | null { return this; }

  override firstOp(): PcodeOp | null { return this.copy.firstOp(); }

  override lastOp(): PcodeOp | null { return this.copy.lastOp(); }

  override negateCondition(toporbottom: boolean): boolean {
    const res = this.copy.negateCondition(true);
    super.negateCondition(toporbottom);
    return res;
  }

  override getSplitPoint(): FlowBlock | null {
    return this.copy.getSplitPoint();
  }

  override isComplex(): boolean {
    return this.copy.isComplex();
  }

  override encodeHeader(encoder: Encoder): void {
    super.encodeHeader(encoder);
    const altindex: int4 = this.copy.getIndex();
    encoder.writeSignedInteger(ATTRIB_ALTINDEX, altindex);
  }
}

// ---------------------------------------------------------------------------
// BlockGoto -- a block that terminates with an unstructured (goto) branch
// ---------------------------------------------------------------------------

/**
 * A block that terminates with an unstructured (goto) branch to another block.
 *
 * The goto must be an unconditional branch. The instance keeps track of the target block and
 * will emit the branch as some form of formal branch statement (goto, break, continue).
 * From the point of view of control-flow structuring, this block has no output edges.
 *
 * NOTE: This extends BlockGraph in the C++ source. Since BlockGraph is not yet translated in
 * this file, we extend FlowBlock and use forward-declared BlockGraph methods via `as any`.
 * The full hierarchy will be wired when BlockGraph is translated.
 */
export class BlockGoto extends FlowBlock {
  private gototarget: FlowBlock;   // The target block of the unstructured branch
  private gototype: uint4;         // The type of unstructured branch

  // BlockGraph members (needed since BlockGoto extends BlockGraph in C++,
  // but is declared before BlockGraph in this file)
  list: FlowBlock[] = [];

  addBlock(bl: FlowBlock): void {
    (bl as any).index = this.list.length;
    this.list.push(bl);
  }

  selfIdentify(): void {
    if (this.list.length === 0) return;
    for (let idx = 0; idx < this.list.length; ++idx) {
      const mybl = this.list[idx];
      let i = 0;
      while (i < mybl.sizeIn()) {
        const otherbl = mybl.getIn(i);
        if ((otherbl as any).parent === this) {
          i += 1;
        } else {
          for (let j = 0; j < otherbl.sizeOut(); ++j) {
            if (otherbl.getOut(j) === mybl) {
              otherbl.replaceOutEdge(j, this);
            }
          }
        }
      }
      i = 0;
      while (i < mybl.sizeOut()) {
        const otherbl = mybl.getOut(i);
        if ((otherbl as any).parent === this) {
          i += 1;
        } else {
          for (let j = 0; j < otherbl.sizeIn(); ++j) {
            if (otherbl.getIn(j) === mybl) {
              otherbl.replaceInEdge(j, this);
            }
          }
          if (mybl.isSwitchOut()) {
            this.setFlag(block_flags.f_switch_out);
          }
        }
      }
    }
    this.dedup();
  }

  constructor(bl: FlowBlock) {
    super();
    this.gototarget = bl;
    this.gototype = block_flags.f_goto_goto;
  }

  /** Get the target block of the goto */
  getGotoTarget(): FlowBlock { return this.gototarget; }

  /** Get the type of unstructured branch */
  getGotoType(): uint4 { return this.gototype; }

  /**
   * Should a formal goto statement be emitted.
   *
   * Under rare circumstances, the emitter can place the target block of the goto immediately
   * after this goto block. In this case, because the control-flow is essentially a fall-thru,
   * there should not be a formal goto statement emitted.
   */
  gotoPrints(): boolean {
    if (this.getParent() != null) {
      const nextbl = this.getParent()!.nextFlowAfter(this);
      const gotobl = this.getGotoTarget().getFrontLeaf();
      return gotobl !== nextbl;
    }
    return false;
  }

  override getType(): block_type { return block_type.t_goto; }

  override markUnstructured(): void {
    // BlockGraph::markUnstructured() -- recurse into children
    for (let i = 0; i < this.list.length; ++i) {
      this.list[i].markUnstructured();
    }
    if (this.gototype === block_flags.f_goto_goto) {
      if (this.gotoPrints()) {
        // markCopyBlock(gototarget, f_unstructured_targ)
        const leaf = this.gototarget.getFrontLeaf();
        if (leaf != null) {
          leaf.flags |= block_flags.f_unstructured_targ;
        }
      }
    }
  }

  override scopeBreak(curexit: int4, curloopexit: int4): void {
    if (this.list.length > 0) {
      this.list[0].scopeBreak(this.gototarget.getIndex(), curloopexit);
    }
    if (curloopexit === this.gototarget.getIndex()) {
      this.gototype = block_flags.f_break_goto;
    }
  }

  override printHeader(s: Writer): void {
    s.write("Plain goto block ");
    super.printHeader(s);
  }

  override printRaw(s: Writer): void {
    if (this.list.length > 0) {
      this.list[0].printRaw(s);
    }
  }

  override emit(lng: PrintLanguage): void {
    (lng as any).emitBlockGoto(this);
  }

  override getExitLeaf(): FlowBlock | null {
    if (this.list.length > 0) {
      return this.list[0].getExitLeaf();
    }
    return null;
  }

  override lastOp(): PcodeOp | null {
    if (this.list.length > 0) {
      return this.list[0].lastOp();
    }
    return null;
  }

  override nextFlowAfter(bl: FlowBlock): FlowBlock | null {
    return this.getGotoTarget().getFrontLeaf();
  }

  override encodeBody(encoder: Encoder): void {
    // BlockGraph::encodeBody
    super.encodeBody(encoder);
    encoder.openElement(ELEM_TARGET);
    const leaf = this.gototarget.getFrontLeaf();
    const depth: int4 = this.gototarget.calcDepth(leaf!);
    encoder.writeSignedInteger(ATTRIB_INDEX, leaf!.getIndex());
    encoder.writeSignedInteger(ATTRIB_DEPTH, depth);
    encoder.writeUnsignedInteger(ATTRIB_TYPE, BigInt(this.gototype));
    encoder.closeElement(ELEM_TARGET);
  }

  // --- BlockGraph helper: get the i-th component block ---
  getBlock(i: int4): FlowBlock { return this.list[i]; }

  /** Get the number of components */
  getSize(): int4 { return this.list.length; }
}
/**
 * @file block_part2.ts
 * @description Remaining block classes translated from Ghidra's block.hh / block.cc
 * (Part 2: BlockGraph, BlockMultiGoto, BlockList, BlockCondition, BlockIf,
 *  BlockWhileDo, BlockDoWhile, BlockInfLoop, BlockSwitch, BlockMap)
 *
 * DO NOT include any imports -- this file is concatenated after block_part1.ts
 */

// ---------------------------------------------------------------------------
// Forward type declarations for not-yet-written modules
// ---------------------------------------------------------------------------

type Datatype = any;
type HighVariable = any;

// ---------------------------------------------------------------------------
// PcodeOpNode helper (from expression.hh)
// ---------------------------------------------------------------------------

interface PcodeOpNode {
  op: any;      // PcodeOp
  slot: number;
}

function makePcodeOpNode(op: any, slot: number): PcodeOpNode {
  return { op, slot };
}

// ---------------------------------------------------------------------------
// BlockGraph -- a control-flow block built out of sub-components
// ---------------------------------------------------------------------------

/**
 * A control-flow block built out of sub-components.
 *
 * This is the core class for building a hierarchy of control-flow blocks.
 * A set of control-flow blocks can be grouped together and viewed as a single block,
 * with its own input and output blocks.
 * All the code structuring elements (BlockList, BlockIf, BlockWhileDo, etc.) derive from this.
 */
export class BlockGraph extends FlowBlock {
  protected list: FlowBlock[] = [];

  constructor() {
    super();
  }

  // --- private methods ---

  /** Add a component FlowBlock */
  addBlock(bl: FlowBlock): void {
    const min = bl.getIndex();
    if (this.list.length === 0) {
      (this as any).index = min;
    } else {
      if (min < this.getIndex()) {
        (this as any).index = min;
      }
    }
    (bl as any).parent = this;
    this.list.push(bl);
  }

  /** Force number of outputs */
  forceOutputNum(i: number): void {
    while (this.sizeOut() < i) {
      this.addInEdge(this, edge_flags.f_loop_edge | edge_flags.f_back_edge);
    }
  }

  /** Inherit our edges from the edges of our components */
  selfIdentify(): void {
    if (this.list.length === 0) return;
    for (let idx = 0; idx < this.list.length; ++idx) {
      const mybl = this.list[idx];
      let i = 0;
      while (i < mybl.sizeIn()) {
        const otherbl = mybl.getIn(i);
        if ((otherbl as any).parent === this) {
          i += 1;
        } else {
          for (let j = 0; j < otherbl.sizeOut(); ++j) {
            if (otherbl.getOut(j) === mybl) {
              otherbl.replaceOutEdge(j, this);
            }
          }
          // Don't increment i
        }
      }
      i = 0;
      while (i < mybl.sizeOut()) {
        const otherbl = mybl.getOut(i);
        if ((otherbl as any).parent === this) {
          i += 1;
        } else {
          for (let j = 0; j < otherbl.sizeIn(); ++j) {
            if (otherbl.getIn(j) === mybl) {
              otherbl.replaceInEdge(j, this);
            }
          }
          if (mybl.isSwitchOut()) {
            this.setFlag(block_flags.f_switch_out);
          }
        }
      }
    }
    this.dedup();
  }

  /** Move nodes from this into a new BlockGraph */
  identifyInternal(ident: BlockGraph, nodes: FlowBlock[]): void {
    for (let i = 0; i < nodes.length; ++i) {
      nodes[i].setMark();
      ident.addBlock(nodes[i]);
      (ident as any).flags |= (nodes[i].getFlags() & (block_flags.f_interior_gotoout | block_flags.f_interior_gotoin));
    }
    const newlist: FlowBlock[] = [];
    for (let i = 0; i < this.list.length; ++i) {
      if (!this.list[i].isMark()) {
        newlist.push(this.list[i]);
      } else {
        this.list[i].clearMark();
      }
    }
    this.list = newlist;
    ident.selfIdentify();
  }

  /** Clear a set of properties from all edges in the graph */
  clearEdgeFlags(fl: number): void {
    fl = ~fl;
    for (let j = 0; j < this.list.length; ++j) {
      const bl = this.list[j];
      for (let i = 0; i < bl.sizeIn(); ++i) {
        (bl as any).intothis[i].label &= fl;
      }
      for (let i = 0; i < bl.sizeOut(); ++i) {
        (bl as any).outofthis[i].label &= fl;
      }
    }
  }

  /** Create a single virtual root block given multiple entry points */
  static createVirtualRoot(rootlist: FlowBlock[]): FlowBlock {
    const newroot = new FlowBlock();
    for (let i = 0; i < rootlist.length; ++i) {
      rootlist[i].addInEdge(newroot, 0);
    }
    return newroot;
  }

  /**
   * Find a spanning tree (skipping irreducible edges).
   * Label pre and reverse-post orderings, tree, forward, cross, and back edges.
   * Calculate number of descendants. Put the blocks of the graph in reverse post order.
   */
  findSpanningTree(preorder: FlowBlock[], rootlist: FlowBlock[]): void {
    if (this.list.length === 0) return;
    const rpostorder: FlowBlock[] = new Array(this.list.length);
    const state: FlowBlock[] = [];
    const istate: number[] = [];
    let tmpbl: FlowBlock;
    let origrootpos: number;

    for (let i = 0; i < this.list.length; ++i) {
      tmpbl = this.list[i];
      (tmpbl as any).index = -1;
      (tmpbl as any).visitcount = -1;
      (tmpbl as any).copymap = tmpbl;
      if (tmpbl.sizeIn() === 0) {
        rootlist.push(tmpbl);
      }
    }
    if (rootlist.length > 1) {
      tmpbl = rootlist[rootlist.length - 1];
      rootlist[rootlist.length - 1] = rootlist[0];
      rootlist[0] = tmpbl;
    } else if (rootlist.length === 0) {
      rootlist.push(this.list[0]);
    }
    origrootpos = rootlist.length - 1;

    for (let repeat = 0; repeat < 2; ++repeat) {
      let extraroots = false;
      let rpostcount = this.list.length;
      let rootindex = 0;
      this.clearEdgeFlags(~0);

      while (preorder.length < this.list.length) {
        let startbl: FlowBlock | null = null;
        while (rootindex < rootlist.length) {
          startbl = rootlist[rootindex];
          rootindex += 1;
          if (startbl.getVisitCount() === -1) break;
          for (let i = rootindex; i < rootlist.length; ++i) {
            rootlist[i - 1] = rootlist[i];
          }
          rootlist.pop();
          rootindex -= 1;
          startbl = null;
        }
        if (startbl == null) {
          extraroots = true;
          for (let i = 0; i < this.list.length; ++i) {
            startbl = this.list[i];
            if (startbl.getVisitCount() === -1) break;
          }
          rootlist.push(startbl!);
          rootindex += 1;
        }

        state.push(startbl!);
        istate.push(0);
        startbl!.setVisitCount(preorder.length);
        preorder.push(startbl!);
        (startbl as any).numdesc = 1;

        while (state.length > 0) {
          const curbl = state[state.length - 1];
          if (curbl.sizeOut() <= istate[istate.length - 1]) {
            state.pop();
            istate.pop();
            rpostcount -= 1;
            (curbl as any).index = rpostcount;
            rpostorder[rpostcount] = curbl;
            if (state.length > 0) {
              (state[state.length - 1] as any).numdesc += (curbl as any).numdesc;
            }
          } else {
            const edgenum = istate[istate.length - 1];
            istate[istate.length - 1] += 1;
            if (curbl.isIrreducibleOut(edgenum)) continue;
            const childbl = curbl.getOut(edgenum);

            if (childbl.getVisitCount() === -1) {
              curbl.setOutEdgeFlag(edgenum, edge_flags.f_tree_edge);
              state.push(childbl);
              istate.push(0);
              childbl.setVisitCount(preorder.length);
              preorder.push(childbl);
              (childbl as any).numdesc = 1;
            } else if (childbl.getIndex() === -1) {
              curbl.setOutEdgeFlag(edgenum, edge_flags.f_back_edge | edge_flags.f_loop_edge);
            } else if (curbl.getVisitCount() < childbl.getVisitCount()) {
              curbl.setOutEdgeFlag(edgenum, edge_flags.f_forward_edge);
            } else {
              curbl.setOutEdgeFlag(edgenum, edge_flags.f_cross_edge);
            }
          }
        }
      }
      if (!extraroots) break;
      if (repeat === 1) {
        throw new LowlevelError("Could not generate spanning tree");
      }

      tmpbl = rootlist[rootlist.length - 1];
      rootlist[rootlist.length - 1] = rootlist[origrootpos];
      rootlist[origrootpos] = tmpbl;

      for (let i = 0; i < this.list.length; ++i) {
        tmpbl = this.list[i];
        (tmpbl as any).index = -1;
        (tmpbl as any).visitcount = -1;
        (tmpbl as any).copymap = tmpbl;
      }
      preorder.length = 0;
      state.length = 0;
      istate.length = 0;
    }

    if (rootlist.length > 1) {
      tmpbl = rootlist[rootlist.length - 1];
      rootlist[rootlist.length - 1] = rootlist[0];
      rootlist[0] = tmpbl;
    }

    this.list = rpostorder;
  }

  /**
   * Identify irreducible edges.
   * Returns true if the spanning tree needs to be rebuilt.
   */
  findIrreducible(preorder: FlowBlock[], irreduciblecount: { value: number }): boolean {
    const reachunder: FlowBlock[] = [];
    let needrebuild = false;
    let xi = preorder.length - 1;
    while (xi >= 0) {
      const x = preorder[xi];
      xi -= 1;
      const sizein = x.sizeIn();
      for (let i = 0; i < sizein; ++i) {
        if (!x.isBackEdgeIn(i)) continue;
        const y = x.getIn(i);
        if (y === x) continue;
        const yCopyMap = y.getCopyMap()!;
        reachunder.push(yCopyMap);
        yCopyMap.setMark();
      }
      let q = 0;
      while (q < reachunder.length) {
        const t = reachunder[q];
        q += 1;
        const sizein_t = t.sizeIn();
        for (let i = 0; i < sizein_t; ++i) {
          if (t.isIrreducibleIn(i)) continue;
          const y = t.getIn(i);
          const yprime = y.getCopyMap()!;
          if (
            x.getVisitCount() > yprime.getVisitCount() ||
            x.getVisitCount() + (x as any).numdesc <= yprime.getVisitCount()
          ) {
            irreduciblecount.value += 1;
            const edgeout = t.getInRevIndex(i);
            y.setOutEdgeFlag(edgeout, edge_flags.f_irreducible);
            if (t.isTreeEdgeIn(i)) {
              needrebuild = true;
            } else {
              y.clearOutEdgeFlag(edgeout, edge_flags.f_cross_edge | edge_flags.f_forward_edge);
            }
          } else if (!yprime.isMark() && yprime !== x) {
            reachunder.push(yprime);
            yprime.setMark();
          }
        }
      }
      for (let i = 0; i < reachunder.length; ++i) {
        const s = reachunder[i];
        s.clearMark();
        (s as any).copymap = x;
      }
      reachunder.length = 0;
    }
    return needrebuild;
  }

  /**
   * Make sure this has exactly 2 out edges and the first edge flows to the given FlowBlock.
   * Swap the edges if necessary.
   */
  forceFalseEdge(out0: FlowBlock): void {
    if (this.sizeOut() !== 2) {
      throw new LowlevelError("Can only preserve binary condition");
    }
    let target = out0;
    if (target.getParent() === this) {
      target = this;
    }
    if (this.getOut(0) !== target) {
      this.swapEdges();
    }
    if (this.getOut(0) !== target) {
      throw new LowlevelError("Unable to preserve condition");
    }
  }

  // --- protected methods ---

  /** Swap the positions of two component FlowBlocks */
  swapBlocks(i: number, j: number): void {
    const bl = this.list[i];
    this.list[i] = this.list[j];
    this.list[j] = bl;
  }

  /** Set properties on the first leaf FlowBlock */
  static markCopyBlock(bl: FlowBlock, fl: number): void {
    const leaf = bl.getFrontLeaf();
    if (leaf != null) {
      (leaf as any).flags |= fl;
    }
  }

  // --- public methods ---

  /** Clear all component FlowBlock objects */
  clear(): void {
    this.list.length = 0;
  }

  /** Get the list of component FlowBlock objects */
  getList(): FlowBlock[] {
    return this.list;
  }

  /** Get the number of components */
  getSize(): number {
    return this.list.length;
  }

  /** Get the i-th component */
  getBlock(i: number): FlowBlock {
    return this.list[i];
  }

  override getType(): block_type {
    return block_type.t_graph;
  }

  override subBlock(i: number): FlowBlock | null {
    return this.list[i];
  }

  override markUnstructured(): void {
    for (let i = 0; i < this.list.length; ++i) {
      this.list[i].markUnstructured();
    }
  }

  override markLabelBumpUp(bump: boolean): void {
    super.markLabelBumpUp(bump);
    if (this.list.length === 0) return;
    this.list[0].markLabelBumpUp(bump);
    for (let i = 1; i < this.list.length; ++i) {
      this.list[i].markLabelBumpUp(false);
    }
  }

  override scopeBreak(curexit: number, curloopexit: number): void {
    let idx = 0;
    while (idx < this.list.length) {
      const curbl = this.list[idx];
      idx += 1;
      let ind: number;
      if (idx === this.list.length) {
        ind = curexit;
      } else {
        ind = this.list[idx].getIndex();
      }
      curbl.scopeBreak(ind, curloopexit);
    }
  }

  override printTree(s: Writer, level: number): void {
    super.printTree(s, level);
    for (let i = 0; i < this.list.length; ++i) {
      this.list[i].printTree(s, level + 1);
    }
  }

  override printRaw(s: Writer): void {
    this.printHeader(s);
    s.write("\n");
    if (this.list.length === 0) return;
    let lastBl = this.list[0];
    lastBl.printRaw(s);
    for (let i = 1; i < this.list.length; ++i) {
      const curBl = this.list[i];
      lastBl.printRawImpliedGoto(s, curBl);
      curBl.printRaw(s);
      lastBl = curBl;
    }
  }

  override printRawImpliedGoto(s: Writer, nextBlock: FlowBlock): void {
    if (this.list.length === 0) return;
    this.list[this.list.length - 1].printRawImpliedGoto(s, nextBlock);
  }

  override emit(lng: PrintLanguage): void {
    (lng as any).emitBlockGraph(this);
  }

  override firstOp(): any | null {
    if (this.getSize() === 0) return null;
    return this.getBlock(0).firstOp();
  }

  override nextFlowAfter(bl: FlowBlock): FlowBlock | null {
    let nextbl: FlowBlock | null;
    let idx: number;
    for (idx = 0; idx < this.list.length; ++idx) {
      if (this.list[idx] === bl) break;
    }
    idx += 1;
    if (idx >= this.list.length) {
      if (this.getParent() == null) return null;
      return this.getParent()!.nextFlowAfter(this);
    }
    nextbl = this.list[idx];
    if (nextbl != null) {
      nextbl = nextbl.getFrontLeaf();
    }
    return nextbl;
  }

  override finalTransform(data: Funcdata): void {
    for (let i = 0; i < this.list.length; ++i) {
      this.list[i].finalTransform(data);
    }
  }

  override finalizePrinting(data: Funcdata): void {
    for (let i = 0; i < this.list.length; ++i) {
      this.list[i].finalizePrinting(data);
    }
  }

  override encodeBody(encoder: any): void {
    super.encodeBody(encoder);
    for (let i = 0; i < this.list.length; ++i) {
      const bl = this.list[i];
      encoder.openElement(ELEM_BHEAD);
      encoder.writeSignedInteger(ATTRIB_INDEX, bl.getIndex());
      const bt = bl.getType();
      let nm: string;
      if (bt === block_type.t_if) {
        const sz = (bl as BlockGraph).getSize();
        if (sz === 1) nm = "ifgoto";
        else if (sz === 2) nm = "properif";
        else nm = "ifelse";
      } else {
        nm = FlowBlock.typeToName(bt);
      }
      encoder.writeString(ATTRIB_TYPE, nm);
      encoder.closeElement(ELEM_BHEAD);
    }
    for (let i = 0; i < this.list.length; ++i) {
      this.list[i].encode(encoder);
    }
  }

  override decodeBody(decoder: any): void {
    const newresolver = new BlockMap();
    const tmplist: FlowBlock[] = [];

    for (;;) {
      const subId: number = decoder.peekElement();
      if (subId !== ELEM_BHEAD.getId()) break;
      decoder.openElement();
      const newindex: number = decoder.readSignedInteger(ATTRIB_INDEX);
      const bl = newresolver.createBlock(decoder.readString(ATTRIB_TYPE));
      (bl as any).index = newindex;
      tmplist.push(bl);
      decoder.closeElement(subId);
    }
    newresolver.sortList();

    for (let i = 0; i < tmplist.length; ++i) {
      const bl = tmplist[i];
      bl.decode(decoder, newresolver);
      this.addBlock(bl);
    }
  }

  /** Decode this BlockGraph from a stream */
  decodeGraph(decoder: any): void {
    const resolver = new BlockMap();
    super.decode(decoder, resolver as any);
  }

  /** Add a directed edge between component FlowBlocks */
  addEdge(begin: FlowBlock, end: FlowBlock): void {
    end.addInEdge(begin, 0);
  }

  /** Mark a given edge as a loop edge */
  addLoopEdge(begin: FlowBlock, outindex: number): void {
    begin.setOutEdgeFlag(outindex, edge_flags.f_loop_edge);
  }

  /** Remove an edge between component FlowBlocks */
  removeEdge(begin: FlowBlock, end: FlowBlock): void {
    for (let i = 0; i < end.sizeIn(); ++i) {
      if (end.getIn(i) === begin) {
        end.removeInEdge(i);
        return;
      }
    }
  }

  /** Switch an edge from one out FlowBlock to another */
  switchEdge(inbl: FlowBlock, outbefore: FlowBlock, outafter: FlowBlock): void {
    for (let i = 0; i < inbl.sizeOut(); ++i) {
      if (inbl.getOut(i) === outbefore) {
        inbl.replaceOutEdge(i, outafter);
      }
    }
  }

  /** Move indicated out edge to a new FlowBlock */
  moveOutEdge(blold: FlowBlock, slot: number, blnew: FlowBlock): void {
    const outbl = blold.getOut(slot);
    const i = blold.getOutRevIndex(slot);
    outbl.replaceInEdge(i, blnew);
  }

  /** Remove a FlowBlock from this BlockGraph */
  removeBlock(bl: FlowBlock): void {
    while (bl.sizeIn() > 0) {
      this.removeEdge(bl.getIn(0), bl);
    }
    while (bl.sizeOut() > 0) {
      this.removeEdge(bl, bl.getOut(0));
    }
    for (let i = 0; i < this.list.length; ++i) {
      if (this.list[i] === bl) {
        this.list.splice(i, 1);
        break;
      }
    }
  }

  /** Remove given FlowBlock preserving flow in this */
  removeFromFlow(bl: FlowBlock): void {
    let bbout: FlowBlock;
    let bbin: FlowBlock;
    while (bl.sizeOut() > 0) {
      bbout = bl.getOut(bl.sizeOut() - 1);
      bl.removeOutEdge(bl.sizeOut() - 1);
      while (bl.sizeIn() > 0) {
        bbin = bl.getIn(0);
        bbin.replaceOutEdge((bl as any).intothis[0].reverse_index, bbout);
      }
    }
  }

  /** Remove FlowBlock splitting flow between input and output edges */
  removeFromFlowSplit(bl: FlowBlock, flipflow: boolean): void {
    if (flipflow) {
      bl.replaceEdgesThru(0, 1);
    } else {
      bl.replaceEdgesThru(1, 1);
    }
    bl.replaceEdgesThru(0, 0);
  }

  /** Splice given FlowBlock together with its output */
  spliceBlock(bl: FlowBlock): void {
    let outbl: FlowBlock | null = null;
    if (bl.sizeOut() === 1) {
      outbl = bl.getOut(0);
      if (outbl.sizeIn() !== 1) {
        outbl = null;
      }
    }
    if (outbl == null) {
      throw new LowlevelError("Can only splice a block with 1 output to a block with 1 input");
    }
    const fl1 = bl.getFlags() & (block_flags.f_unstructured_targ | block_flags.f_entry_point);
    const fl2 = outbl.getFlags() & block_flags.f_switch_out;
    bl.removeOutEdge(0);
    const szout = outbl.sizeOut();
    for (let i = 0; i < szout; ++i) {
      this.moveOutEdge(outbl, 0, bl);
    }
    this.removeBlock(outbl);
    (bl as any).flags = fl1 | fl2;
  }

  /** Set the entry point FlowBlock for this graph */
  setStartBlock(bl: FlowBlock): void {
    if ((this.list[0].getFlags() & block_flags.f_entry_point) !== 0) {
      if (bl === this.list[0]) return;
      this.list[0].clearFlag(block_flags.f_entry_point);
    }
    let i: number;
    for (i = 0; i < this.list.length; ++i) {
      if (this.list[i] === bl) break;
    }
    for (let j = i; j > 0; --j) {
      this.list[j] = this.list[j - 1];
    }
    this.list[0] = bl;
    bl.setFlag(block_flags.f_entry_point);
  }

  /** Get the entry point FlowBlock */
  getStartBlock(): FlowBlock {
    if (this.list.length === 0 || (this.list[0].getFlags() & block_flags.f_entry_point) === 0) {
      throw new LowlevelError("No start block registered");
    }
    return this.list[0];
  }

  /** Build a new plain FlowBlock */
  newBlock(): FlowBlock {
    const ret = new FlowBlock();
    this.addBlock(ret);
    return ret;
  }

  /** Build a new BlockBasic (BlockBasicClass) */
  newBlockBasic(fd: Funcdata): BlockBasicClass {
    const ret = new BlockBasicClass(fd);
    this.addBlock(ret);
    return ret;
  }

  /** Build a new BlockCopy */
  newBlockCopy(bl: FlowBlock): BlockCopy {
    const ret = new BlockCopy(bl);
    (ret as any).intothis = (bl as any).intothis.map((e: BlockEdge) => new BlockEdge(e.point, e.label, e.reverse_index));
    (ret as any).outofthis = (bl as any).outofthis.map((e: BlockEdge) => new BlockEdge(e.point, e.label, e.reverse_index));
    (ret as any).immed_dom = (bl as any).immed_dom;
    (ret as any).index = bl.getIndex();
    (ret as any).numdesc = (bl as any).numdesc;
    (ret as any).flags |= bl.getFlags();
    if ((ret as any).outofthis.length > 2) {
      (ret as any).flags |= block_flags.f_switch_out;
    }
    this.addBlock(ret);
    return ret;
  }

  /** Build a new BlockGoto */
  newBlockGoto(bl: FlowBlock): BlockGoto {
    const ret = new BlockGoto(bl.getOut(0));
    const nodes: FlowBlock[] = [bl];
    this.identifyInternal(ret as any, nodes);
    this.addBlock(ret);
    // BlockGoto in part 1 extends FlowBlock (stub), so cast to access forceOutputNum
    while (ret.sizeOut() < 1) {
      ret.addInEdge(ret, edge_flags.f_loop_edge | edge_flags.f_back_edge);
    }
    this.removeEdge(ret, ret.getOut(0));
    return ret;
  }

  /** Build a new BlockMultiGoto */
  newBlockMultiGoto(bl: FlowBlock, outedge: number): BlockMultiGoto {
    let ret: BlockMultiGoto;
    const targetbl = bl.getOut(outedge);
    const isdefaultedge = bl.isDefaultBranch(outedge);
    if (bl.getType() === block_type.t_multigoto) {
      ret = bl as BlockMultiGoto;
      ret.addGotoEdge(targetbl);
      this.removeEdge(ret, targetbl);
      if (isdefaultedge) ret.setDefaultGoto();
    } else {
      ret = new BlockMultiGoto(bl);
      const origSizeOut = bl.sizeOut();
      const nodes: FlowBlock[] = [bl];
      this.identifyInternal(ret, nodes);
      this.addBlock(ret);
      ret.addGotoEdge(targetbl);
      if (targetbl !== bl) {
        if (ret.sizeOut() !== origSizeOut) {
          ret.forceOutputNum(ret.sizeOut() + 1);
        }
        this.removeEdge(ret, targetbl);
      }
      if (isdefaultedge) ret.setDefaultGoto();
    }
    return ret;
  }

  /** Build a new BlockList */
  newBlockList(nodes: FlowBlock[]): BlockList {
    let out0: FlowBlock | null = null;
    const outforce = nodes[nodes.length - 1].sizeOut();
    if (outforce === 2) {
      out0 = nodes[nodes.length - 1].getOut(0);
    }
    const ret = new BlockList();
    this.identifyInternal(ret, nodes);
    this.addBlock(ret);
    ret.forceOutputNum(outforce);
    if (ret.sizeOut() === 2) {
      ret.forceFalseEdge(out0!);
    }
    return ret;
  }

  /** Build a new BlockCondition */
  newBlockCondition(b1: FlowBlock, b2: FlowBlock): BlockCondition {
    const out0 = b2.getOut(0);
    const nodes: FlowBlock[] = [];
    const opc = (b1.getFalseOut() === b2) ? OpCode.CPUI_INT_OR : OpCode.CPUI_INT_AND;
    const ret = new BlockCondition(opc);
    nodes.push(b1);
    nodes.push(b2);
    this.identifyInternal(ret, nodes);
    this.addBlock(ret);
    ret.forceOutputNum(2);
    ret.forceFalseEdge(out0);
    return ret;
  }

  /** Build a new BlockIfGoto */
  newBlockIfGoto(cond: FlowBlock): BlockIf {
    if (!cond.isGotoOut(1)) {
      throw new LowlevelError("Building ifgoto where true branch is not the goto");
    }
    const out0 = cond.getOut(0);
    const nodes: FlowBlock[] = [];
    const ret = new BlockIf();
    ret.setGotoTarget(cond.getOut(1));
    nodes.push(cond);
    this.identifyInternal(ret, nodes);
    this.addBlock(ret);
    ret.forceOutputNum(2);
    ret.forceFalseEdge(out0);
    this.removeEdge(ret, ret.getTrueOut());
    return ret;
  }

  /** Build a new BlockIf */
  newBlockIf(cond: FlowBlock, tc: FlowBlock): BlockIf {
    const nodes: FlowBlock[] = [];
    const ret = new BlockIf();
    nodes.push(cond);
    nodes.push(tc);
    this.identifyInternal(ret, nodes);
    this.addBlock(ret);
    ret.forceOutputNum(1);
    return ret;
  }

  /** Build a new BlockIfElse */
  newBlockIfElse(cond: FlowBlock, tc: FlowBlock, fc: FlowBlock): BlockIf {
    const nodes: FlowBlock[] = [];
    const ret = new BlockIf();
    nodes.push(cond);
    nodes.push(tc);
    nodes.push(fc);
    this.identifyInternal(ret, nodes);
    this.addBlock(ret);
    ret.forceOutputNum(1);
    return ret;
  }

  /** Build a new BlockWhileDo */
  newBlockWhileDo(cond: FlowBlock, cl: FlowBlock): BlockWhileDo {
    const nodes: FlowBlock[] = [];
    const ret = new BlockWhileDo();
    nodes.push(cond);
    nodes.push(cl);
    this.identifyInternal(ret, nodes);
    this.addBlock(ret);
    ret.forceOutputNum(1);
    return ret;
  }

  /** Build a new BlockDoWhile */
  newBlockDoWhile(condcl: FlowBlock): BlockDoWhile {
    const nodes: FlowBlock[] = [];
    const ret = new BlockDoWhile();
    nodes.push(condcl);
    this.identifyInternal(ret, nodes);
    this.addBlock(ret);
    ret.forceOutputNum(1);
    return ret;
  }

  /** Build a new BlockInfLoop */
  newBlockInfLoop(body: FlowBlock): BlockInfLoop {
    const nodes: FlowBlock[] = [];
    const ret = new BlockInfLoop();
    nodes.push(body);
    this.identifyInternal(ret, nodes);
    this.addBlock(ret);
    return ret;
  }

  /** Build a new BlockSwitch */
  newBlockSwitch(cs: FlowBlock[], hasExit: boolean): BlockSwitch {
    const rootbl = cs[0];
    const ret = new BlockSwitch(rootbl);
    const leafbl = rootbl.getExitLeaf();
    if (leafbl == null || leafbl.getType() !== block_type.t_copy) {
      throw new LowlevelError("Could not get switch leaf");
    }
    ret.grabCaseBasic(leafbl.subBlock(0)!, cs);
    this.identifyInternal(ret, cs);
    this.addBlock(ret);
    if (hasExit) {
      ret.forceOutputNum(1);
    }
    ret.clearFlag(block_flags.f_switch_out);
    return ret;
  }

  /** Sort blocks using the final ordering */
  orderBlocks(): void {
    if (this.list.length !== 1) {
      this.list.sort((a, b) => {
        if (FlowBlock.compareFinalOrder(a, b)) return -1;
        if (FlowBlock.compareFinalOrder(b, a)) return 1;
        return 0;
      });
    }
  }

  /** Build a copy of a BlockGraph */
  buildCopy(graph: BlockGraph): void {
    const startsize = this.list.length;
    for (let i = 0; i < graph.list.length; ++i) {
      const copyblock = this.newBlockCopy(graph.list[i]);
      (graph.list[i] as any).copymap = copyblock;
    }
    for (let i = startsize; i < this.list.length; ++i) {
      this.list[i].replaceUsingMap();
    }
  }

  /** Clear the visit count in all node FlowBlocks */
  clearVisitCount(): void {
    for (let i = 0; i < this.list.length; ++i) {
      (this.list[i] as any).visitcount = 0;
    }
  }

  /** Calculate forward dominators */
  calcForwardDominator(rootlist: FlowBlock[]): void {
    if (this.list.length === 0) return;
    const numnodes = this.list.length - 1;
    const postorder: FlowBlock[] = new Array(this.list.length);
    for (let i = 0; i < this.list.length; ++i) {
      (this.list[i] as any).immed_dom = null;
      postorder[numnodes - i] = this.list[i];
    }
    let virtualroot: FlowBlock | null = null;
    if (rootlist.length > 1) {
      virtualroot = BlockGraph.createVirtualRoot(rootlist);
      postorder.push(virtualroot);
    }

    let b = postorder[postorder.length - 1];
    if (b.sizeIn() !== 0) {
      if (rootlist.length !== 1 || rootlist[0] !== b) {
        throw new LowlevelError("Problems finding root node of graph");
      }
      virtualroot = BlockGraph.createVirtualRoot(rootlist);
      postorder.push(virtualroot);
      b = virtualroot;
    }
    (b as any).immed_dom = b;
    for (let i = 0; i < b.sizeOut(); ++i) {
      (b.getOut(i) as any).immed_dom = b;
    }
    let changed = true;
    let new_idom: FlowBlock | null = null;
    while (changed) {
      changed = false;
      for (let i = postorder.length - 2; i >= 0; --i) {
        b = postorder[i];
        if ((b as any).immed_dom !== postorder[postorder.length - 1]) {
          let j: number;
          for (j = 0; j < b.sizeIn(); ++j) {
            new_idom = b.getIn(j);
            if (new_idom.getImmedDom() != null) break;
          }
          j += 1;
          for (; j < b.sizeIn(); ++j) {
            const rho = b.getIn(j);
            if (rho.getImmedDom() != null) {
              let finger1 = numnodes - rho.getIndex();
              let finger2 = numnodes - new_idom!.getIndex();
              while (finger1 !== finger2) {
                while (finger1 < finger2) {
                  finger1 = numnodes - postorder[finger1].getImmedDom()!.getIndex();
                }
                while (finger2 < finger1) {
                  finger2 = numnodes - postorder[finger2].getImmedDom()!.getIndex();
                }
              }
              new_idom = postorder[finger1];
            }
          }
          if ((b as any).immed_dom !== new_idom) {
            (b as any).immed_dom = new_idom;
            changed = true;
          }
        }
      }
    }
    if (virtualroot != null) {
      for (let i = 0; i < this.list.length; ++i) {
        if (postorder[i].getImmedDom() === virtualroot) {
          (postorder[i] as any).immed_dom = null;
        }
      }
      while (virtualroot.sizeOut() > 0) {
        virtualroot.removeOutEdge(virtualroot.sizeOut() - 1);
      }
      // virtualroot is garbage collected
    } else {
      (postorder[postorder.length - 1] as any).immed_dom = null;
    }
  }

  /** Build the dominator tree */
  buildDomTree(child: FlowBlock[][]): void {
    child.length = 0;
    for (let i = 0; i <= this.list.length; ++i) {
      child.push([]);
    }
    for (let i = 0; i < this.list.length; ++i) {
      const bl = this.list[i];
      if (bl.getImmedDom() != null) {
        child[bl.getImmedDom()!.getIndex()].push(bl);
      } else {
        child[this.list.length].push(bl);
      }
    }
  }

  /** Calculate dominator depths */
  buildDomDepth(depth: number[]): number {
    let max = 0;
    depth.length = this.list.length + 1;
    for (let i = 0; i < this.list.length; ++i) {
      const bl = this.list[i].getImmedDom();
      if (bl != null) {
        depth[i] = depth[bl.getIndex()] + 1;
      } else {
        depth[i] = 1;
      }
      if (max < depth[i]) max = depth[i];
    }
    depth[this.list.length] = 0;
    return max;
  }

  /** Collect nodes from a dominator sub-tree */
  buildDomSubTree(res: FlowBlock[], root: FlowBlock): void {
    const rootindex = root.getIndex();
    res.push(root);
    for (let i = rootindex + 1; i < this.list.length; ++i) {
      const bl = this.list[i];
      const dombl = bl.getImmedDom();
      if (dombl == null) break;
      if (dombl.getIndex() > rootindex) break;
      res.push(bl);
    }
  }

  /** Calculate loop edges */
  calcLoop(): void {
    if (this.list.length === 0) return;

    const path: FlowBlock[] = [];
    const state: number[] = [];

    path.push(this.list[0]);
    state.push(0);
    this.list[0].setFlag(block_flags.f_mark | block_flags.f_mark2);

    while (path.length > 0) {
      const bl = path[path.length - 1];
      const i = state[state.length - 1];
      if (i >= bl.sizeOut()) {
        bl.clearFlag(block_flags.f_mark2);
        path.pop();
        state.pop();
      } else {
        state[state.length - 1] += 1;
        if (bl.isLoopOut(i)) continue;
        const nextbl = bl.getOut(i);
        if ((nextbl.getFlags() & block_flags.f_mark2) !== 0) {
          this.addLoopEdge(bl, i);
        } else if ((nextbl.getFlags() & block_flags.f_mark) === 0) {
          nextbl.setFlag(block_flags.f_mark | block_flags.f_mark2);
          path.push(nextbl);
          state.push(0);
        }
      }
    }
    for (let i = 0; i < this.list.length; ++i) {
      this.list[i].clearFlag(block_flags.f_mark | block_flags.f_mark2);
    }
  }

  /** Collect reachable/unreachable FlowBlocks from a given start FlowBlock */
  collectReachable(res: FlowBlock[], bl: FlowBlock, un: boolean): void {
    bl.setMark();
    res.push(bl);
    let total = 0;
    while (total < res.length) {
      const blk = res[total++];
      for (let j = 0; j < blk.sizeOut(); ++j) {
        const blk2 = blk.getOut(j);
        if (blk2.isMark()) continue;
        blk2.setMark();
        res.push(blk2);
      }
    }
    if (un) {
      res.length = 0;
      for (let i = 0; i < this.list.length; ++i) {
        const blk = this.list[i];
        if (blk.isMark()) {
          blk.clearMark();
        } else {
          res.push(blk);
        }
      }
    } else {
      for (let i = 0; i < res.length; ++i) {
        res[i].clearMark();
      }
    }
  }

  /** Label loop edges */
  structureLoops(rootlist: FlowBlock[]): void {
    const preorder: FlowBlock[] = [];
    let needrebuild: boolean;
    const irreduciblecount = { value: 0 };

    do {
      needrebuild = false;
      this.findSpanningTree(preorder, rootlist);
      needrebuild = this.findIrreducible(preorder, irreduciblecount);
      if (needrebuild) {
        this.clearEdgeFlags(edge_flags.f_tree_edge | edge_flags.f_forward_edge | edge_flags.f_cross_edge | edge_flags.f_back_edge | edge_flags.f_loop_edge);
        preorder.length = 0;
        rootlist.length = 0;
      }
    } while (needrebuild);
    if (irreduciblecount.value > 0) {
      this.calcLoop();
    }
  }
}

// ---------------------------------------------------------------------------
// Now re-derive BlockGoto from BlockGraph (overriding the Part 1 stub)
// Part 1 had BlockGoto extending FlowBlock directly as a stub. This is the
// proper version, but since we cannot "re-open" a class, the Part 1 stub
// already has list[] and getBlock/getSize. Here we leave it as-is.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// BlockMultiGoto -- a block with multiple unstructured goto edges
// ---------------------------------------------------------------------------

/**
 * A block with multiple edges out, at least one of which is an unstructured (goto) branch.
 *
 * An instance of this class is used to mirror a basic block with multiple out edges at the point
 * where one of the edges can't be structured. The instance keeps track of this edge but otherwise
 * presents a view to the structuring algorithm as if the edge didn't exist.
 */
export class BlockMultiGoto extends BlockGraph {
  private gotoedges: FlowBlock[] = [];
  private defaultswitch: boolean = false;

  constructor(bl: FlowBlock) {
    super();
    this.defaultswitch = false;
  }

  /** Mark that this block holds an unstructured switch default */
  setDefaultGoto(): void {
    this.defaultswitch = true;
  }

  /** Does this block hold an unstructured switch default edge */
  hasDefaultGoto(): boolean {
    return this.defaultswitch;
  }

  /** Mark the edge from this to the given FlowBlock as unstructured */
  addGotoEdge(bl: FlowBlock): void {
    this.gotoedges.push(bl);
  }

  /** Get the number of unstructured edges */
  numGotos(): number {
    return this.gotoedges.length;
  }

  /** Get the target FlowBlock along the i-th unstructured edge */
  getGoto(i: number): FlowBlock {
    return this.gotoedges[i];
  }

  override getType(): block_type {
    return block_type.t_multigoto;
  }

  override scopeBreak(curexit: number, curloopexit: number): void {
    this.getBlock(0).scopeBreak(-1, curloopexit);
  }

  override printHeader(s: Writer): void {
    s.write("Multi goto block ");
    FlowBlock.prototype.printHeader.call(this, s);
  }

  override printRaw(s: Writer): void {
    this.getBlock(0).printRaw(s);
  }

  override emit(lng: PrintLanguage): void {
    this.getBlock(0).emit(lng);
  }

  override getExitLeaf(): FlowBlock | null {
    return this.getBlock(0).getExitLeaf();
  }

  override lastOp(): any | null {
    return this.getBlock(0).lastOp();
  }

  override nextFlowAfter(bl: FlowBlock): FlowBlock | null {
    return null;
  }

  override encodeBody(encoder: any): void {
    super.encodeBody(encoder);
    for (let i = 0; i < this.gotoedges.length; ++i) {
      const gototarget = this.gotoedges[i];
      const leaf = gototarget.getFrontLeaf();
      const depth = gototarget.calcDepth(leaf!);
      encoder.openElement(ELEM_TARGET);
      encoder.writeSignedInteger(ATTRIB_INDEX, leaf!.getIndex());
      encoder.writeSignedInteger(ATTRIB_DEPTH, depth);
      encoder.closeElement(ELEM_TARGET);
    }
  }
}

// ---------------------------------------------------------------------------
// BlockList -- a series of blocks that execute in sequence
// ---------------------------------------------------------------------------

/**
 * A series of blocks that execute in sequence.
 *
 * When structuring control-flow, an instance of this class represents blocks
 * that execute in sequence and fall-thru to each other. In general, the component
 * blocks may not be basic blocks and can have their own sub-structures.
 */
export class BlockList extends BlockGraph {
  constructor() {
    super();
  }

  override getType(): block_type {
    return block_type.t_ls;
  }

  override printHeader(s: Writer): void {
    s.write("List block ");
    FlowBlock.prototype.printHeader.call(this, s);
  }

  override emit(lng: PrintLanguage): void {
    (lng as any).emitBlockLs(this);
  }

  override getExitLeaf(): FlowBlock | null {
    if (this.getSize() === 0) return null;
    return this.getBlock(this.getSize() - 1).getExitLeaf();
  }

  override lastOp(): any | null {
    if (this.getSize() === 0) return null;
    return this.getBlock(this.getSize() - 1).lastOp();
  }

  override negateCondition(toporbottom: boolean): boolean {
    const bl = this.getBlock(this.getSize() - 1);
    const res = bl.negateCondition(false);
    FlowBlock.prototype.negateCondition.call(this, toporbottom);
    return res;
  }

  override getSplitPoint(): FlowBlock | null {
    if (this.getSize() === 0) return null;
    return this.getBlock(this.getSize() - 1).getSplitPoint();
  }
}

// ---------------------------------------------------------------------------
// BlockCondition -- two conditional blocks combined with AND/OR
// ---------------------------------------------------------------------------

/**
 * Two conditional blocks combined into one conditional using BOOL_AND or BOOL_OR.
 *
 * This class is used to construct full conditional expressions. An instance glues together
 * two components, each with two outgoing edges.
 */
export class BlockCondition extends BlockGraph {
  private opc: number;   // OpCode for the boolean operation

  constructor(c: number) {
    super();
    this.opc = c;
  }

  /** Get the boolean operation */
  getOpcode(): number {
    return this.opc;
  }

  override getType(): block_type {
    return block_type.t_condition;
  }

  override scopeBreak(curexit: number, curloopexit: number): void {
    this.getBlock(0).scopeBreak(-1, curloopexit);
    this.getBlock(1).scopeBreak(-1, curloopexit);
  }

  override printHeader(s: Writer): void {
    s.write("Condition block(");
    if (this.opc === OpCode.CPUI_BOOL_AND) {
      s.write("&&");
    } else {
      s.write("||");
    }
    s.write(") ");
    FlowBlock.prototype.printHeader.call(this, s);
  }

  override emit(lng: PrintLanguage): void {
    (lng as any).emitBlockCondition(this);
  }

  override negateCondition(toporbottom: boolean): boolean {
    const res1 = this.getBlock(0).negateCondition(false);
    const res2 = this.getBlock(1).negateCondition(false);
    this.opc = (this.opc === OpCode.CPUI_BOOL_AND) ? OpCode.CPUI_BOOL_OR : OpCode.CPUI_BOOL_AND;
    FlowBlock.prototype.negateCondition.call(this, toporbottom);
    return res1 || res2;
  }

  override getSplitPoint(): FlowBlock | null {
    return this;
  }

  override flipInPlaceTest(fliplist: any[]): number {
    const split1 = this.getBlock(0).getSplitPoint();
    if (split1 == null) return 2;
    const split2 = this.getBlock(1).getSplitPoint();
    if (split2 == null) return 2;
    const subtest1 = split1.flipInPlaceTest(fliplist);
    if (subtest1 === 2) return 2;
    const subtest2 = split2.flipInPlaceTest(fliplist);
    if (subtest2 === 2) return 2;
    return subtest1;
  }

  override flipInPlaceExecute(): void {
    this.opc = (this.opc === OpCode.CPUI_BOOL_AND) ? OpCode.CPUI_BOOL_OR : OpCode.CPUI_BOOL_AND;
    this.getBlock(0).getSplitPoint()!.flipInPlaceExecute();
    this.getBlock(1).getSplitPoint()!.flipInPlaceExecute();
  }

  override lastOp(): any | null {
    return this.getBlock(1).lastOp();
  }

  override isComplex(): boolean {
    return this.getBlock(0).isComplex();
  }

  override nextFlowAfter(bl: FlowBlock): FlowBlock | null {
    return null;
  }

  override encodeHeader(encoder: any): void {
    super.encodeHeader(encoder);
    const nm = get_opname(this.opc);
    encoder.writeString(ATTRIB_OPCODE, nm);
  }
}

/**
 * Helper: get opcode name string.
 * In the C++ codebase this comes from opcodes.cc; simplified here.
 */
function get_opname(opc: number): string {
  // Minimal mapping for the opcodes used in block conditions
  switch (opc) {
    case OpCode.CPUI_BOOL_AND: return "BOOL_AND";
    case OpCode.CPUI_BOOL_OR: return "BOOL_OR";
    case OpCode.CPUI_INT_AND: return "INT_AND";
    case OpCode.CPUI_INT_OR: return "INT_OR";
    default: return "UNKNOWN";
  }
}

// ---------------------------------------------------------------------------
// BlockIf -- a basic "if" block
// ---------------------------------------------------------------------------

/**
 * A basic "if" structure in code, with a expression for the condition, and
 * one or two bodies of the conditionally executed code.
 *
 * An instance has one, two, or three components. One component is always the conditional block.
 * If there is a second component, it is the block of code executed when the condition is true.
 * If there is a third component, it is the "else" block, executed when the condition is false.
 */
export class BlockIf extends BlockGraph {
  private gototype: number;
  private gototarget: FlowBlock | null;

  constructor() {
    super();
    this.gototype = block_flags.f_goto_goto;
    this.gototarget = null;
  }

  /** Mark the target of the unstructured edge */
  setGotoTarget(bl: FlowBlock): void {
    this.gototarget = bl;
  }

  /** Get the target of the unstructured edge */
  getGotoTarget(): FlowBlock | null {
    return this.gototarget;
  }

  /** Get the type of unstructured edge */
  getGotoType(): number {
    return this.gototype;
  }

  override getType(): block_type {
    return block_type.t_if;
  }

  override markUnstructured(): void {
    super.markUnstructured();
    if (this.gototarget != null && this.gototype === block_flags.f_goto_goto) {
      BlockGraph.markCopyBlock(this.gototarget, block_flags.f_unstructured_targ);
    }
  }

  override scopeBreak(curexit: number, curloopexit: number): void {
    this.getBlock(0).scopeBreak(-1, curloopexit);
    for (let i = 1; i < this.getSize(); ++i) {
      this.getBlock(i).scopeBreak(curexit, curloopexit);
    }
    if (this.gototarget != null && this.gototarget.getIndex() === curloopexit) {
      this.gototype = block_flags.f_break_goto;
    }
  }

  override printHeader(s: Writer): void {
    s.write("If block ");
    FlowBlock.prototype.printHeader.call(this, s);
  }

  override emit(lng: PrintLanguage): void {
    (lng as any).emitBlockIf(this);
  }

  override preferComplement(data: Funcdata): boolean {
    if (this.getSize() !== 3) return false;

    const split = this.getBlock(0).getSplitPoint();
    if (split == null) return false;
    const fliplist: any[] = [];
    if (0 !== split.flipInPlaceTest(fliplist)) return false;
    split.flipInPlaceExecute();
    (data as any).opFlipInPlaceExecute(fliplist);
    this.swapBlocks(1, 2);
    return true;
  }

  override getExitLeaf(): FlowBlock | null {
    if (this.getSize() === 1) {
      return this.getBlock(0).getExitLeaf();
    }
    return null;
  }

  override lastOp(): any | null {
    if (this.getSize() === 1) {
      return this.getBlock(0).lastOp();
    }
    return null;
  }

  override nextFlowAfter(bl: FlowBlock): FlowBlock | null {
    if (this.getBlock(0) === bl) return null;
    if (this.getParent() == null) return null;
    return this.getParent()!.nextFlowAfter(this);
  }

  override encodeBody(encoder: any): void {
    super.encodeBody(encoder);
    if (this.getSize() === 1) {
      const leaf = this.gototarget!.getFrontLeaf();
      const depth = this.gototarget!.calcDepth(leaf!);
      encoder.openElement(ELEM_TARGET);
      encoder.writeSignedInteger(ATTRIB_INDEX, leaf!.getIndex());
      encoder.writeSignedInteger(ATTRIB_DEPTH, depth);
      encoder.writeUnsignedInteger(ATTRIB_TYPE, this.gototype);
      encoder.closeElement(ELEM_TARGET);
    }
  }
}

// ---------------------------------------------------------------------------
// BlockWhileDo -- a loop where the condition is checked at the top
// ---------------------------------------------------------------------------

/**
 * A loop structure where the condition is checked at the top.
 *
 * This has exactly two components: one conditional block which evaluates when the
 * loop terminates, and one body block. Supports for-loop syntax if an iterator
 * op is provided.
 */
export class BlockWhileDo extends BlockGraph {
  private initializeOp: any;   // PcodeOp: statement used as for loop initializer
  private iterateOp: any;      // PcodeOp: statement used as for loop iterator
  private loopDef: any;        // PcodeOp: MULTIEQUAL merging loop variable

  constructor() {
    super();
    this.initializeOp = null;
    this.iterateOp = null;
    this.loopDef = null;
  }

  /** Get root of initialize statement or null */
  getInitializeOp(): any {
    return this.initializeOp;
  }

  /** Get root of iterate statement or null */
  getIterateOp(): any {
    return this.iterateOp;
  }

  /** Does this require overflow syntax */
  hasOverflowSyntax(): boolean {
    return (this.getFlags() & block_flags.f_whiledo_overflow) !== 0;
  }

  /** Set that this requires overflow syntax */
  setOverflowSyntax(): void {
    this.setFlag(block_flags.f_whiledo_overflow);
  }

  /**
   * Find a loop variable: tested by exit condition, has MULTIEQUAL in head block,
   * has a modification coming in from the tail block.
   */
  private findLoopVariable(cbranch: any, head: any, tail: any, lastOp: any): void {
    const vn = cbranch.getIn(1);
    if (!vn.isWritten()) return;
    let op = vn.getDef();
    const slot = tail.getOutRevIndex(0);

    const path: PcodeOpNode[] = new Array(4);
    let count = 0;
    if (op.isCall() || op.isMarker()) return;

    path[0] = { op: op, slot: 0 };
    while (count >= 0) {
      const curOp = path[count].op;
      const ind = path[count].slot++;
      if (ind >= curOp.numInput()) {
        count -= 1;
        continue;
      }
      const nextVn = curOp.getIn(ind);
      if (!nextVn.isWritten()) continue;
      const defOp = nextVn.getDef();
      if (defOp.code() === OpCode.CPUI_MULTIEQUAL) {
        if (defOp.getParent() !== head) continue;
        const itvn = defOp.getIn(slot);
        if (!itvn.isWritten()) continue;
        const possibleIterate = itvn.getDef();
        if (possibleIterate.getParent() === tail) {
          if (possibleIterate.isMarker()) continue;
          if (!possibleIterate.isMoveable(lastOp)) continue;
          this.loopDef = defOp;
          this.iterateOp = possibleIterate;
          return;
        }
      } else {
        if (count === 3) continue;
        if (defOp.isCall() || defOp.isMarker()) continue;
        count += 1;
        path[count] = { op: defOp, slot: 0 };
      }
    }
  }

  /**
   * Find the for-loop initializer op.
   * Returns the last PcodeOp in the initializer's block, or null.
   */
  private findInitializer(head: any, slot: number): any | null {
    if (head.sizeIn() !== 2) return null;
    slot = 1 - slot;
    const initVn = this.loopDef.getIn(slot);
    if (!initVn.isWritten()) return null;
    const res = initVn.getDef();
    if (res.isMarker()) return null;
    const initialBlock = res.getParent();
    if (initialBlock !== head.getIn(slot)) return null;
    let lastOp = initialBlock.lastOp();
    if (lastOp == null) return null;
    if (initialBlock.sizeOut() !== 1) return null;
    if (lastOp.isBranch()) {
      lastOp = lastOp.previousOp();
      if (lastOp == null) return null;
    }
    this.initializeOp = res;
    return lastOp;
  }

  /**
   * Test that given statement is terminal and explicit.
   * Returns the root PcodeOp if conditions are met, otherwise null.
   */
  private testTerminal(data: Funcdata, slot: number): any | null {
    const vn0 = this.loopDef.getIn(slot);
    if (!vn0.isWritten()) return null;
    const finalOp = vn0.getDef();
    const parentBlock = this.loopDef.getParent().getIn(slot);
    let resOp = finalOp;
    let vn = vn0;
    if (finalOp.code() === OpCode.CPUI_COPY && finalOp.notPrinted()) {
      vn = finalOp.getIn(0);
      if (!vn.isWritten()) return null;
      resOp = vn.getDef();
      if (resOp.getParent() !== parentBlock) return null;
    }
    if (!vn.isExplicit()) return null;
    if (resOp.notPrinted()) return null;

    let lastOp = finalOp.getParent().lastOp();
    if (lastOp.isBranch()) {
      lastOp = lastOp.previousOp();
    }
    if (!(data as any).moveRespectingCover(finalOp, lastOp)) return null;
    return resOp;
  }

  /**
   * Make sure the loop variable is involved as input in the iterator statement.
   */
  private testIterateForm(): boolean {
    const targetVn = this.loopDef.getOut();
    if (!targetVn.hasHigh()) return false;
    const high = targetVn.getHigh();

    const path: PcodeOpNode[] = [];
    path.push({ op: this.iterateOp, slot: 0 });
    while (path.length > 0) {
      const node = path[path.length - 1];
      if (node.op.numInput() <= node.slot) {
        path.pop();
        continue;
      }
      const vn = node.op.getIn(node.slot);
      node.slot += 1;
      if (vn.isAnnotation()) continue;
      if (vn.hasHigh() && vn.getHigh() === high) return true;
      if (vn.isExplicit()) continue;
      if (!vn.isWritten()) continue;
      path.push({ op: vn.getDef(), slot: 0 });
    }
    return false;
  }

  override getType(): block_type {
    return block_type.t_whiledo;
  }

  override markLabelBumpUp(bump: boolean): void {
    super.markLabelBumpUp(true);
    if (!bump) this.clearFlag(block_flags.f_label_bumpup);
  }

  override scopeBreak(curexit: number, curloopexit: number): void {
    this.getBlock(0).scopeBreak(-1, curexit);
    this.getBlock(1).scopeBreak(this.getBlock(0).getIndex(), curexit);
  }

  override printHeader(s: Writer): void {
    s.write("Whiledo block ");
    if (this.hasOverflowSyntax()) {
      s.write("(overflow) ");
    }
    FlowBlock.prototype.printHeader.call(this, s);
  }

  override emit(lng: PrintLanguage): void {
    (lng as any).emitBlockWhileDo(this);
  }

  override nextFlowAfter(bl: FlowBlock): FlowBlock | null {
    if (this.getBlock(0) === bl) return null;
    let nextbl: FlowBlock | null = this.getBlock(0);
    if (nextbl != null) nextbl = nextbl.getFrontLeaf();
    return nextbl;
  }

  override finalTransform(data: Funcdata): void {
    super.finalTransform(data);
    if (!(data as any).getArch().analyze_for_loops) return;
    if (this.hasOverflowSyntax()) return;
    const copyBl = this.getFrontLeaf();
    if (copyBl == null) return;
    const head = copyBl.subBlock(0);
    if (head == null || head.getType() !== block_type.t_basic) return;
    let lastOp = this.getBlock(1).lastOp();
    if (lastOp == null) return;
    const tail = (lastOp as any).getParent();
    if (tail.sizeOut() !== 1) return;
    if (tail.getOut(0) !== head) return;
    const cbranch = this.getBlock(0).lastOp();
    if (cbranch == null || (cbranch as any).code() !== OpCode.CPUI_CBRANCH) return;
    if ((lastOp as any).isBranch()) {
      lastOp = (lastOp as any).previousOp();
      if (lastOp == null) return;
    }

    this.findLoopVariable(cbranch, head, tail, lastOp);
    if (this.iterateOp == null) return;

    if (this.iterateOp !== lastOp) {
      (data as any).opUninsert(this.iterateOp);
      (data as any).opInsertAfter(this.iterateOp, lastOp);
    }

    lastOp = this.findInitializer(head, tail.getOutRevIndex(0));
    if (lastOp == null) return;
    if (!this.initializeOp.isMoveable(lastOp)) {
      this.initializeOp = null;
      return;
    }
    if (this.initializeOp !== lastOp) {
      (data as any).opUninsert(this.initializeOp);
      (data as any).opInsertAfter(this.initializeOp, lastOp);
    }
  }

  override finalizePrinting(data: Funcdata): void {
    super.finalizePrinting(data);
    if (this.iterateOp == null) return;
    const slot = this.iterateOp.getParent().getOutRevIndex(0);
    this.iterateOp = this.testTerminal(data, slot);
    if (this.iterateOp == null) return;
    if (!this.testIterateForm()) {
      this.iterateOp = null;
      return;
    }
    if (this.initializeOp == null) {
      this.findInitializer(this.loopDef.getParent(), slot);
    }
    if (this.initializeOp != null) {
      this.initializeOp = this.testTerminal(data, 1 - slot);
    }

    (data as any).opMarkNonPrinting(this.iterateOp);
    if (this.initializeOp != null) {
      (data as any).opMarkNonPrinting(this.initializeOp);
    }
  }
}

// ---------------------------------------------------------------------------
// BlockDoWhile -- a loop where the condition is checked at the bottom
// ---------------------------------------------------------------------------

/**
 * A loop structure where the condition is checked at the bottom.
 *
 * This has exactly one component with two outgoing edges: one edge flows to itself,
 * the other flows to the exit block. The BlockDoWhile instance has exactly one outgoing edge.
 */
export class BlockDoWhile extends BlockGraph {
  constructor() {
    super();
  }

  override getType(): block_type {
    return block_type.t_dowhile;
  }

  override markLabelBumpUp(bump: boolean): void {
    super.markLabelBumpUp(true);
    if (!bump) this.clearFlag(block_flags.f_label_bumpup);
  }

  override scopeBreak(curexit: number, curloopexit: number): void {
    this.getBlock(0).scopeBreak(-1, curexit);
  }

  override printHeader(s: Writer): void {
    s.write("Dowhile block ");
    FlowBlock.prototype.printHeader.call(this, s);
  }

  override emit(lng: PrintLanguage): void {
    (lng as any).emitBlockDoWhile(this);
  }

  override nextFlowAfter(bl: FlowBlock): FlowBlock | null {
    return null;
  }
}

// ---------------------------------------------------------------------------
// BlockInfLoop -- an infinite loop structure
// ---------------------------------------------------------------------------

/**
 * An infinite loop structure.
 *
 * This has exactly one component with one outgoing edge that flows into itself.
 * The BlockInfLoop instance has zero outgoing edges.
 */
export class BlockInfLoop extends BlockGraph {
  constructor() {
    super();
  }

  override getType(): block_type {
    return block_type.t_infloop;
  }

  override markLabelBumpUp(bump: boolean): void {
    super.markLabelBumpUp(true);
    if (!bump) this.clearFlag(block_flags.f_label_bumpup);
  }

  override scopeBreak(curexit: number, curloopexit: number): void {
    this.getBlock(0).scopeBreak(this.getBlock(0).getIndex(), curexit);
  }

  override printHeader(s: Writer): void {
    s.write("Infinite loop block ");
    FlowBlock.prototype.printHeader.call(this, s);
  }

  override emit(lng: PrintLanguage): void {
    (lng as any).emitBlockInfLoop(this);
  }

  override nextFlowAfter(bl: FlowBlock): FlowBlock | null {
    let nextbl: FlowBlock | null = this.getBlock(0);
    if (nextbl != null) nextbl = nextbl.getFrontLeaf();
    return nextbl;
  }
}

// ---------------------------------------------------------------------------
// BlockSwitch -- a structured switch construction
// ---------------------------------------------------------------------------

/**
 * A class for annotating and sorting the individual cases of the switch.
 */
interface CaseOrder {
  block: FlowBlock;             // The structured case block
  basicblock: FlowBlock;        // The first basic-block to execute within the case block
  label: bigint;                // The label for this case, as an untyped constant
  depth: number;                // How deep in a fall-thru chain we are
  chain: number;                // Who we immediately chain to, expressed as caseblocks index, -1 for no chaining
  outindex: number;             // Index coming out of switch to this case
  gototype: number;             // (If non-zero) What type of unstructured case is this?
  isexit: boolean;              // Does this case flow to the exit block
  isdefault: boolean;           // True if this is formal default case for the switch
}

function compareCaseOrder(a: CaseOrder, b: CaseOrder): number {
  if (a.label !== b.label) {
    return a.label < b.label ? -1 : 1;
  }
  return a.depth - b.depth;
}

/**
 * A structured switch construction.
 *
 * This always has at least one component, the first, that executes the switch statement
 * itself and has multiple outgoing edges. Each edge flows either to a formal exit block,
 * or to another case component. All additional components are case components.
 */
export class BlockSwitch extends BlockGraph {
  private jump: JumpTable;
  private caseblocks: CaseOrder[] = [];

  constructor(ind: FlowBlock) {
    super();
    this.jump = ind.getJumptable();
  }

  /**
   * Add a new case to this switch.
   */
  private addCase(switchbl: FlowBlock, bl: FlowBlock, gt: number): void {
    const basicbl = bl.getFrontLeaf()!.subBlock(0)!;
    const inindex = basicbl.getInIndex(switchbl);
    if (inindex === -1) {
      throw new LowlevelError("Case block has become detached from switch");
    }
    const curcase: CaseOrder = {
      block: bl,
      basicblock: basicbl,
      label: 0n,
      depth: 0,
      chain: -1,
      outindex: basicbl.getInRevIndex(inindex),
      gototype: gt,
      isexit: gt !== 0 ? false : (bl.sizeOut() === 1),
      isdefault: switchbl.isDefaultBranch(basicbl.getInRevIndex(inindex)),
    };
    this.caseblocks.push(curcase);
  }

  /**
   * Build annotated CaseOrder objects.
   * Work out flow between cases and if there are any unstructured cases.
   */
  grabCaseBasic(switchbl: FlowBlock, cs: FlowBlock[]): void {
    const casemap: number[] = new Array(switchbl.sizeOut()).fill(-1);
    this.caseblocks = [];
    for (let i = 1; i < cs.length; ++i) {
      const casebl = cs[i];
      this.addCase(switchbl, casebl, 0);
      casemap[this.caseblocks[i - 1].outindex] = i - 1;
    }
    // Fill in fallthru chaining
    for (let i = 0; i < this.caseblocks.length; ++i) {
      const curcase = this.caseblocks[i];
      const casebl = curcase.block;
      if (casebl.getType() === block_type.t_goto) {
        const targetbl = (casebl as BlockGoto).getGotoTarget();
        const basicbl = targetbl.getFrontLeaf()!.subBlock(0)!;
        const inindex = basicbl.getInIndex(switchbl);
        if (inindex === -1) continue;
        curcase.chain = casemap[basicbl.getInRevIndex(inindex)];
      }
    }

    if (cs[0].getType() === block_type.t_multigoto) {
      const gotoedgeblock = cs[0] as BlockMultiGoto;
      const numgoto = gotoedgeblock.numGotos();
      for (let i = 0; i < numgoto; ++i) {
        this.addCase(switchbl, gotoedgeblock.getGoto(i), block_flags.f_goto_goto);
      }
    }
  }

  /** Get the root switch component */
  getSwitchBlock(): FlowBlock {
    return this.getBlock(0);
  }

  /** Get the number of cases */
  getNumCaseBlocks(): number {
    return this.caseblocks.length;
  }

  /** Get the i-th case FlowBlock */
  getCaseBlock(i: number): FlowBlock {
    return this.caseblocks[i].block;
  }

  /** Get the number of labels associated with one case block */
  getNumLabels(i: number): number {
    return (this.jump as any).numIndicesByBlock(this.caseblocks[i].basicblock);
  }

  /** Get a specific label associated with a case block */
  getLabel(i: number, j: number): bigint {
    return (this.jump as any).getLabelByIndex(
      (this.jump as any).getIndexByBlock(this.caseblocks[i].basicblock, j)
    );
  }

  /** Is the i-th case the default case */
  isDefaultCase(i: number): boolean {
    return this.caseblocks[i].isdefault;
  }

  /** Get the edge type for the i-th case block */
  getCaseGotoType(i: number): number {
    return this.caseblocks[i].gototype;
  }

  /** Does the i-th case block exit the switch? */
  isExit(i: number): boolean {
    return this.caseblocks[i].isexit;
  }

  /** Get the data-type of the switch variable */
  getSwitchType(): Datatype {
    const op = (this.jump as any).getIndirectOp();
    return op.getIn(0).getHighTypeReadFacing(op);
  }

  override getType(): block_type {
    return block_type.t_switch;
  }

  override markUnstructured(): void {
    super.markUnstructured();
    for (let i = 0; i < this.caseblocks.length; ++i) {
      if (this.caseblocks[i].gototype === block_flags.f_goto_goto) {
        BlockGraph.markCopyBlock(this.caseblocks[i].block, block_flags.f_unstructured_targ);
      }
    }
  }

  override scopeBreak(curexit: number, curloopexit: number): void {
    this.getBlock(0).scopeBreak(-1, curexit);
    for (let i = 0; i < this.caseblocks.length; ++i) {
      const bl = this.caseblocks[i].block;
      if (this.caseblocks[i].gototype !== 0) {
        if (bl.getIndex() === curexit) {
          this.caseblocks[i].gototype = block_flags.f_break_goto;
        }
      } else {
        bl.scopeBreak(curexit, curexit);
      }
    }
  }

  override printHeader(s: Writer): void {
    s.write("Switch block ");
    FlowBlock.prototype.printHeader.call(this, s);
  }

  override emit(lng: PrintLanguage): void {
    (lng as any).emitBlockSwitch(this);
  }

  override nextFlowAfter(bl: FlowBlock): FlowBlock | null {
    if (this.getBlock(0) === bl) return null;
    if (bl.getType() !== block_type.t_goto) return null;
    let i: number;
    for (i = 0; i < this.caseblocks.length; ++i) {
      if (this.caseblocks[i].block === bl) break;
    }
    if (i === this.caseblocks.length) return null;
    i = i + 1;
    if (i < this.caseblocks.length) {
      return this.caseblocks[i].block.getFrontLeaf();
    }
    if (this.getParent() == null) return null;
    return this.getParent()!.nextFlowAfter(this);
  }

  override finalizePrinting(data: Funcdata): void {
    super.finalizePrinting(data);
    // Populate label and depth fields of CaseOrder objects
    for (let i = 0; i < this.caseblocks.length; ++i) {
      const curcase = this.caseblocks[i];
      let j = curcase.chain;
      while (j !== -1) {
        if (this.caseblocks[j].depth !== 0) break;
        this.caseblocks[j].depth = -1;
        j = this.caseblocks[j].chain;
      }
    }
    for (let i = 0; i < this.caseblocks.length; ++i) {
      const curcase = this.caseblocks[i];
      if ((this.jump as any).numIndicesByBlock(curcase.basicblock) > 0) {
        if (curcase.depth === 0) {
          const ind = (this.jump as any).getIndexByBlock(curcase.basicblock, 0);
          curcase.label = (this.jump as any).getLabelByIndex(ind);
          let j = curcase.chain;
          let depthcount = 1;
          while (j !== -1) {
            if (this.caseblocks[j].depth > 0) break;
            this.caseblocks[j].depth = depthcount++;
            this.caseblocks[j].label = curcase.label;
            j = this.caseblocks[j].chain;
          }
        }
      } else {
        curcase.label = 0n;
      }
    }
    // Sort the cases based on label
    this.caseblocks.sort(compareCaseOrder);
  }
}

// ---------------------------------------------------------------------------
// BlockMap -- helper for resolving cross-references during deserialization
// ---------------------------------------------------------------------------

/**
 * Helper class for resolving cross-references while deserializing BlockGraph objects.
 *
 * FlowBlock objects are serialized with their associated index value and edges are serialized
 * with the indices of the FlowBlock end-points. During deserialization, this class maintains a
 * list of FlowBlock objects sorted by index and then looks up the FlowBlock matching a given
 * index as edges specify them.
 */
export class BlockMap {
  private sortlist: FlowBlock[] = [];

  /** Construct a FlowBlock of the given type */
  private resolveBlock(bt: block_type): FlowBlock | null {
    switch (bt) {
      case block_type.t_plain:
        return new FlowBlock();
      case block_type.t_copy:
        return new BlockCopy(null as any);
      case block_type.t_graph:
        return new BlockGraph();
      default:
        break;
    }
    return null;
  }

  /**
   * Given a sorted list of FlowBlock objects, use binary search to find the one matching the given index.
   */
  static findBlock(list: FlowBlock[], ind: number): FlowBlock | null {
    let min = 0;
    let max = list.length - 1;
    while (min <= max) {
      const mid = Math.floor((min + max) / 2);
      const block = list[mid];
      if (block.getIndex() === ind) return block;
      if (block.getIndex() < ind) {
        min = mid + 1;
      } else {
        max = mid - 1;
      }
    }
    return null;
  }

  /** Sort the list of FlowBlock objects */
  sortList(): void {
    this.sortlist.sort((a, b) => a.getIndex() - b.getIndex());
  }

  /** Find the FlowBlock matching the given index */
  findLevelBlock(index: number): FlowBlock | null {
    return BlockMap.findBlock(this.sortlist, index);
  }

  /** Create a FlowBlock of the named type */
  createBlock(name: string): FlowBlock {
    const bt = FlowBlock.nameToType(name);
    const bl = this.resolveBlock(bt);
    if (bl == null) {
      throw new LowlevelError("Unable to resolve block type: " + name);
    }
    this.sortlist.push(bl);
    return bl;
  }
}
