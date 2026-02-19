// blockaction_part1.ts
// Translation of the first half of blockaction.hh and blockaction.cc from Ghidra decompiler
// Part 1 of 2

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------
import { FlowBlock, BlockGraph, BlockGoto, BlockIf, BlockMultiGoto, BlockWhileDo, block_type } from './block.js';
import { PcodeOp } from './op.js';
import { Action, ActionGroupList } from './action.js';
import { OpCode } from '../core/opcodes.js';

// ---------------------------------------------------------------------------
// Forward type declarations for modules not yet translated
// ---------------------------------------------------------------------------
type Funcdata = any;
type Varnode = any;
type BlockBasic = any;

/** PcodeOp opcodes referenced in this file */
const CPUI_CBRANCH = OpCode.CPUI_CBRANCH;
const CPUI_MULTIEQUAL = OpCode.CPUI_MULTIEQUAL;
const CPUI_COPY = OpCode.CPUI_COPY;
const CPUI_SUBPIECE = OpCode.CPUI_SUBPIECE;
const CPUI_RETURN = OpCode.CPUI_RETURN;

/** Forward declaration for functionalEqualityLevel */
declare function functionalEqualityLevel(
  vn1: Varnode,
  vn2: Varnode,
  res1: Varnode[],
  res2: Varnode[]
): number;

// ---------------------------------------------------------------------------
// FloatingEdge
// ---------------------------------------------------------------------------

/**
 * Class for holding an edge while the underlying graph is being manipulated.
 *
 * The original FlowBlock nodes that define the end-points of the edge may get
 * collapsed, but the edge may still exist between higher level components.
 * The edge can still be retrieved via the getCurrentEdge() method.
 */
export class FloatingEdge {
  private top: FlowBlock;   // Starting FlowBlock of the edge
  private bottom: FlowBlock; // Ending FlowBlock of the edge

  /** Construct given end points */
  constructor(t: FlowBlock, b: FlowBlock) {
    this.top = t;
    this.bottom = b;
  }

  /** Get the starting FlowBlock */
  getTop(): FlowBlock {
    return this.top;
  }

  /** Get the ending FlowBlock */
  getBottom(): FlowBlock {
    return this.bottom;
  }

  /**
   * Retrieve the current edge (as a top FlowBlock and the index of the outgoing edge).
   * If the end-points have been collapsed together, this returns null.
   * The top and bottom nodes of the edge are updated to FlowBlocks in the current collapsed graph.
   * @param outedge - object to receive the edge index { val: number }
   * @param graph - the containing BlockGraph
   * @returns the current top of the edge or null
   */
  getCurrentEdge(outedge: { val: number }, graph: FlowBlock): FlowBlock | null {
    while (this.top.getParent() !== graph) {
      this.top = this.top.getParent()!; // Move up through collapse hierarchy to current graph
    }
    while (this.bottom.getParent() !== graph) {
      this.bottom = this.bottom.getParent()!;
    }
    outedge.val = this.top.getOutIndex(this.bottom);
    if (outedge.val < 0) {
      return null; // Edge does not exist (any longer)
    }
    return this.top;
  }
}

// ---------------------------------------------------------------------------
// LoopBody
// ---------------------------------------------------------------------------

/**
 * A description of the body of a loop.
 *
 * Following Tarjan, assuming there are no irreducible edges, a loop body is defined
 * by the head (or entry-point) and 1 or more tails, which each have a back edge into
 * the head.
 */
export class LoopBody {
  private head: FlowBlock | null;                // head of the loop
  private tails: FlowBlock[];                    // (Possibly multiple) nodes with back edge returning to the head
  private depth: number;                         // Nested depth of this loop
  private uniquecount: number;                   // Total number of unique head and tail nodes
  private exitblock: FlowBlock | null;           // Official exit block from loop, or null
  private exitedges: FloatingEdge[];             // Edges that exit to the formal exit block
  private immed_container: LoopBody | null;      // Immediately containing loop body, or null

  /** Construct with a loop head */
  constructor(h: FlowBlock) {
    this.head = h;
    this.tails = [];
    this.depth = 0;
    this.uniquecount = 0;
    this.exitblock = null;
    this.exitedges = [];
    this.immed_container = null;
  }

  /** Return the head FlowBlock of the loop */
  getHead(): FlowBlock | null {
    return this.head;
  }

  /** Add a tail to the loop */
  addTail(bl: FlowBlock): void {
    this.tails.push(bl);
  }

  /** Get the exit FlowBlock or null */
  getExitBlock(): FlowBlock | null {
    return this.exitblock;
  }

  /**
   * Find blocks in containing loop that aren't in this.
   * Assuming this has all of its nodes marked, find all additional nodes that create the
   * body of the container loop. Mark these and put them in body list.
   */
  private extendToContainer(container: LoopBody, body: FlowBlock[]): void {
    let i = 0;
    if (!container.head!.isMark()) { // container head may already be in subloop, if not
      container.head!.setMark();     // add it to new body
      body.push(container.head!);
      i = 1; // make sure we don't traverse back from it
    }
    for (let j = 0; j < container.tails.length; ++j) {
      const tail = container.tails[j];
      if (!tail.isMark()) { // container tail may already be in subloop, if not
        tail.setMark();
        body.push(tail); // add to body, make sure we DO traverse back from it
      }
    }
    // -this- head is already marked, but hasn't been traversed
    if (this.head !== container.head) { // Unless the container has the same head, traverse the contained head
      const sizein = this.head!.sizeIn();
      for (let k = 0; k < sizein; ++k) {
        if (this.head!.isGotoIn(k)) continue; // Don't trace back through irreducible edges
        const bl = this.head!.getIn(k);
        if (bl.isMark()) continue; // Already in list
        bl.setMark();
        body.push(bl);
      }
    }

    while (i < body.length) {
      const curblock = body[i++];
      const sizein = curblock.sizeIn();
      for (let k = 0; k < sizein; ++k) {
        if (curblock.isGotoIn(k)) continue; // Don't trace back through irreducible edges
        const bl = curblock.getIn(k);
        if (bl.isMark()) continue; // Already in list
        bl.setMark();
        body.push(bl);
      }
    }
  }

  /**
   * Update loop body to current view.
   * This updates the head node to the FlowBlock in the current collapsed graph.
   * The tail nodes are also updated until one is found that has not collapsed into head.
   * This first updated tail is returned.  The loop may still exist as a head node with an
   * out edge back into itself, in which case head is returned as the active tail.
   * If the loop has been completely collapsed, null is returned.
   * @param graph - the containing control-flow structure
   * @returns the current loop tail or null
   */
  update(graph: FlowBlock): FlowBlock | null {
    while (this.head!.getParent() !== graph) {
      this.head = this.head!.getParent()!; // Move up through collapse hierarchy to current graph
    }
    let bottom: FlowBlock;
    for (let i = 0; i < this.tails.length; ++i) {
      bottom = this.tails[i];
      while (bottom.getParent() !== graph) {
        bottom = bottom.getParent()!;
      }
      this.tails[i] = bottom;
      if (bottom !== this.head) { // If the loop hasn't been fully collapsed yet
        return bottom;
      }
    }
    for (let i = this.head!.sizeOut() - 1; i >= 0; --i) {
      if (this.head!.getOut(i) === this.head) { // Check for head looping with itself
        return this.head;
      }
    }
    return null;
  }

  /**
   * Collect all FlowBlock nodes that reach a tail of the loop without going through head.
   * Put them in a list and mark them.
   * @param body will contain the body nodes
   */
  findBase(body: FlowBlock[]): void {
    this.head!.setMark();
    body.push(this.head!);
    for (let j = 0; j < this.tails.length; ++j) {
      const tail = this.tails[j];
      if (!tail.isMark()) {
        tail.setMark();
        body.push(tail);
      }
    }
    this.uniquecount = body.length; // Number of nodes that are either head or tail
    let i = 1;
    while (i < body.length) {
      const curblock = body[i++];
      const sizein = curblock.sizeIn();
      for (let k = 0; k < sizein; ++k) {
        if (curblock.isGotoIn(k)) continue; // Don't trace back through irreducible edges
        const bl = curblock.getIn(k);
        if (bl.isMark()) continue; // Already in list
        bl.setMark();
        body.push(bl);
      }
    }
  }

  /**
   * Extend the body of this loop to every FlowBlock that can be reached
   * only from head without hitting the exitblock.
   * Assume body has been filled out by findBase() and that all these blocks have their mark set.
   * @param body contains the current loop body and will be extended
   */
  extend(body: FlowBlock[]): void {
    const trial: FlowBlock[] = [];
    let i = 0;
    while (i < body.length) {
      const bl = body[i++];
      const sizeout = bl.sizeOut();
      for (let j = 0; j < sizeout; ++j) {
        if (bl.isGotoOut(j)) continue; // Don't extend through goto edge
        const curbl = bl.getOut(j);
        if (curbl.isMark()) continue;
        if (curbl === this.exitblock) continue;
        let count = curbl.getVisitCount();
        if (count === 0) {
          trial.push(curbl); // New possible extension
        }
        count += 1;
        curbl.setVisitCount(count);
        if (count === curbl.sizeIn()) {
          curbl.setMark();
          body.push(curbl);
        }
      }
    }
    for (let idx = 0; idx < trial.length; ++idx) {
      trial[idx].setVisitCount(0); // Make sure to clear the count
    }
  }

  /**
   * A structured loop is allowed at most one exit block: pick this block.
   * First build a set of trial exits, preferring from a tail, then from head,
   * then from the middle. If there is no containing loop, just return the first such exit we find.
   * @param body is the list of FlowBlock objects in the loop body, which we assume are marked.
   */
  findExit(body: FlowBlock[]): void {
    const trialexit: FlowBlock[] = [];

    for (let j = 0; j < this.tails.length; ++j) {
      const tail = this.tails[j];
      const sizeout = tail.sizeOut();

      for (let i = 0; i < sizeout; ++i) {
        if (tail.isGotoOut(i)) continue; // Don't use goto as exit edge
        const curbl = tail.getOut(i);
        if (!curbl.isMark()) {
          if (this.immed_container === null) {
            this.exitblock = curbl;
            return;
          }
          trialexit.push(curbl);
        }
      }
    }

    for (let i = 0; i < body.length; ++i) {
      const bl = body[i];
      if (i > 0 && i < this.uniquecount) continue; // Filter out tails (processed previously)
      const sizeout = bl.sizeOut();
      for (let j = 0; j < sizeout; ++j) {
        if (bl.isGotoOut(j)) continue; // Don't use goto as exit edge
        const curbl = bl.getOut(j);
        if (!curbl.isMark()) {
          if (this.immed_container === null) {
            this.exitblock = curbl;
            return;
          }
          trialexit.push(curbl);
        }
      }
    }

    this.exitblock = null; // Default exit is null, if no block meeting condition can be found
    if (trialexit.length === 0) return;

    // If there is a containing loop, force exitblock to be in the containing loop
    if (this.immed_container !== null) {
      const extension: FlowBlock[] = [];
      this.extendToContainer(this.immed_container, extension);
      for (let i = 0; i < trialexit.length; ++i) {
        const bl = trialexit[i];
        if (bl.isMark()) {
          this.exitblock = bl;
          break;
        }
      }
      LoopBody.clearMarks(extension);
    }
  }

  /**
   * The idea is if there is more than one tail for a loop, some tails are more "preferred" than others
   * and should have their exit edges preserved longer and be the target of the DAG path.
   * Currently we look for a single tail that has an outgoing edge to the exitblock and
   * make sure it is the first tail.
   */
  orderTails(): void {
    if (this.tails.length <= 1) return;
    if (this.exitblock === null) return;
    let prefindex: number;
    let trial: FlowBlock;
    for (prefindex = 0; prefindex < this.tails.length; ++prefindex) {
      trial = this.tails[prefindex];
      const sizeout = trial.sizeOut();
      let j: number;
      for (j = 0; j < sizeout; ++j) {
        if (trial.getOut(j) === this.exitblock) break;
      }
      if (j < sizeout) break;
    }
    if (prefindex >= this.tails.length) return;
    if (prefindex === 0) return;
    trial = this.tails[prefindex];
    this.tails[prefindex] = this.tails[0]; // Swap preferred tail into the first position
    this.tails[0] = trial;
  }

  /**
   * Label any edge that leaves the set of nodes in body.
   * Put the edges in priority for removal, middle exit at front, head exit, then tail exit.
   * We assume all the FlowBlock nodes in body have been marked.
   * @param body is the list of nodes in this loop body
   */
  labelExitEdges(body: FlowBlock[]): void {
    const toexitblock: FlowBlock[] = [];
    for (let i = this.uniquecount; i < body.length; ++i) { // For non-head/tail nodes of graph
      const curblock = body[i];
      const sizeout = curblock.sizeOut();
      for (let k = 0; k < sizeout; ++k) {
        if (curblock.isGotoOut(k)) continue; // Don't exit through goto edges
        const bl = curblock.getOut(k);
        if (bl === this.exitblock) {
          toexitblock.push(curblock);
          continue; // Postpone exit to exitblock
        }
        if (!bl.isMark()) {
          this.exitedges.push(new FloatingEdge(curblock, bl));
        }
      }
    }
    if (this.head !== null) {
      const sizeout = this.head.sizeOut();
      for (let k = 0; k < sizeout; ++k) {
        if (this.head.isGotoOut(k)) continue; // Don't exit through goto edges
        const bl = this.head.getOut(k);
        if (bl === this.exitblock) {
          toexitblock.push(this.head);
          continue; // Postpone exit to exitblock
        }
        if (!bl.isMark()) {
          this.exitedges.push(new FloatingEdge(this.head, bl));
        }
      }
    }
    for (let i = this.tails.length - 1; i >= 0; --i) { // Put exits from more preferred tails later
      const curblock = this.tails[i];
      if (curblock === this.head) continue;
      const sizeout = curblock.sizeOut();
      for (let k = 0; k < sizeout; ++k) {
        if (curblock.isGotoOut(k)) continue; // Don't exit through goto edges
        const bl = curblock.getOut(k);
        if (bl === this.exitblock) {
          toexitblock.push(curblock);
          continue; // Postpone exit to exitblock
        }
        if (!bl.isMark()) {
          this.exitedges.push(new FloatingEdge(curblock, bl));
        }
      }
    }
    for (let i = 0; i < toexitblock.length; ++i) { // Now we do exits to exitblock
      const bl = toexitblock[i];
      this.exitedges.push(new FloatingEdge(bl, this.exitblock!));
    }
  }

  /**
   * Record any loops that body contains.
   * Search for any loop contained by this and update its depth and immed_container field.
   * @param body is the set of FlowBlock nodes making up this loop
   * @param looporder is the list of known loops
   */
  labelContainments(body: FlowBlock[], looporder: LoopBody[]): void {
    const containlist: LoopBody[] = [];

    for (let i = 0; i < body.length; ++i) {
      const curblock = body[i];
      if (curblock !== this.head) {
        const subloop = LoopBody.find(curblock, looporder);
        if (subloop !== null) {
          containlist.push(subloop);
          subloop.depth += 1;
        }
      }
    }
    for (let i = 0; i < containlist.length; ++i) { // Keep track of the most immediate container
      const lb = containlist[i];
      if (lb.immed_container === null || lb.immed_container.depth < this.depth) {
        lb.immed_container = this;
      }
    }
  }

  /**
   * Add edges that exit from this loop body to the list of likely gotos,
   * giving them the proper priority.
   * @param likely will hold the exit edges in (reverse) priority order
   * @param graph is the containing control-flow graph
   */
  emitLikelyEdges(likely: FloatingEdge[], graph: FlowBlock): void {
    while (this.head!.getParent() !== graph) {
      this.head = this.head!.getParent()!;
    }
    if (this.exitblock !== null) {
      while (this.exitblock.getParent() !== graph) {
        this.exitblock = this.exitblock.getParent()!;
      }
    }
    for (let i = 0; i < this.tails.length; ++i) {
      let tail = this.tails[i];
      while (tail.getParent() !== graph) {
        tail = tail.getParent()!;
      }
      this.tails[i] = tail;
      if (tail === this.exitblock) { // If the exitblock was collapsed into the tail, we no longer really have an exit
        this.exitblock = null;
      }
    }

    let holdin: FlowBlock | null = null;
    let holdout: FlowBlock | null = null;

    for (let idx = 0; idx < this.exitedges.length; ++idx) {
      const edge = this.exitedges[idx];
      const outedgeRef = { val: 0 };
      const inbl = edge.getCurrentEdge(outedgeRef, graph);
      const isLast = (idx === this.exitedges.length - 1);
      if (inbl === null) continue;
      const outbl = inbl.getOut(outedgeRef.val);
      if (isLast) {
        if (outbl === this.exitblock) { // If this is the official exit edge
          holdin = inbl;               // Hold off putting the edge in list
          holdout = outbl;
          break;
        }
      }
      likely.push(new FloatingEdge(inbl, outbl));
    }
    for (let i = this.tails.length - 1; i >= 0; --i) { // Go in reverse order, to put out less preferred back-edges first
      if (holdin !== null && i === 0) {
        likely.push(new FloatingEdge(holdin, holdout!)); // Put in delayed exit, right before final backedge
      }
      const tail = this.tails[i];
      const sizeout = tail.sizeOut();
      for (let j = 0; j < sizeout; ++j) {
        const bl = tail.getOut(j);
        if (bl === this.head) { // If out edge to head (back-edge for this loop)
          likely.push(new FloatingEdge(tail, this.head!)); // emit it
        }
      }
    }
  }

  /**
   * Exit edges have their f_loop_exit_edge property set.
   * @param graph is the containing control-flow structure
   */
  setExitMarks(graph: FlowBlock): void {
    for (const edge of this.exitedges) {
      const outedgeRef = { val: 0 };
      const inloop = edge.getCurrentEdge(outedgeRef, graph);
      if (inloop !== null) {
        inloop.setLoopExit(outedgeRef.val);
      }
    }
  }

  /**
   * This clears the f_loop_exit_edge on any edge exiting this loop.
   * @param graph is the containing control-flow structure
   */
  clearExitMarks(graph: FlowBlock): void {
    for (const edge of this.exitedges) {
      const outedgeRef = { val: 0 };
      const inloop = edge.getCurrentEdge(outedgeRef, graph);
      if (inloop !== null) {
        inloop.clearLoopExit(outedgeRef.val);
      }
    }
  }

  /**
   * Order loop bodies by depth (deeper loops come first, for use in sort).
   */
  compareTo(op2: LoopBody): number {
    // operator< was: depth > op2.depth  (i.e. deeper loops sort first)
    if (this.depth > op2.depth) return -1;
    if (this.depth < op2.depth) return 1;
    return 0;
  }

  /**
   * Look for LoopBody records that share a head. Merge each tail
   * from one into the other. Set the merged LoopBody head to null,
   * for later clean up.
   * @param looporder is the list of LoopBody records
   */
  static mergeIdenticalHeads(looporder: LoopBody[]): void {
    let i = 0;
    let j = i + 1;

    let curbody = looporder[i];
    while (j < looporder.length) {
      const nextbody = looporder[j++];
      if (nextbody.head === curbody.head) {
        curbody.addTail(nextbody.tails[0]);
        nextbody.head = null; // Mark this LoopBody as subsumed
      } else {
        i += 1;
        looporder[i] = nextbody;
        curbody = nextbody;
      }
    }
    i += 1; // Total size of merged array
    looporder.length = i;
  }

  /**
   * Compare two loops based on the indices of the head and then the tail.
   * @returns true if the first LoopBody comes before the second
   */
  static compare_ends(a: LoopBody, b: LoopBody): number {
    const aindex = a.head!.getIndex();
    const bindex = b.head!.getIndex();
    if (aindex !== bindex) {
      return aindex < bindex ? -1 : 1;
    }
    const atailIndex = a.tails[0].getIndex(); // Only compare the first tail
    const btailIndex = b.tails[0].getIndex();
    if (atailIndex < btailIndex) return -1;
    if (atailIndex > btailIndex) return 1;
    return 0;
  }

  /**
   * Compare two loops based on the indices of the head.
   * @returns -1, 0, or 1 if the first is ordered before, the same, or after the second
   */
  static compare_head(a: LoopBody, looptop: FlowBlock): number {
    const aindex = a.head!.getIndex();
    const bindex = looptop.getIndex();
    if (aindex !== bindex) {
      return aindex < bindex ? -1 : 1;
    }
    return 0;
  }

  /**
   * Given the top FlowBlock of a loop, find corresponding LoopBody record from an ordered list.
   * This assumes mergeIdenticalHeads() has been run so that the head is uniquely identifying.
   * @param looptop is the top of the loop
   * @param looporder is the ordered list of LoopBody records
   * @returns the LoopBody or null if none found
   */
  static find(looptop: FlowBlock, looporder: LoopBody[]): LoopBody | null {
    let min = 0;
    let max = looporder.length - 1;
    while (min <= max) {
      const mid = (min + max) >>> 1;
      const comp = LoopBody.compare_head(looporder[mid], looptop);
      if (comp === 0) return looporder[mid];
      if (comp < 0) {
        min = mid + 1;
      } else {
        max = mid - 1;
      }
    }
    return null;
  }

  /** Clear the mark on all FlowBlock nodes in the body list */
  static clearMarks(body: FlowBlock[]): void {
    for (let i = 0; i < body.length; ++i) {
      body[i].clearMark();
    }
  }
}

// ---------------------------------------------------------------------------
// TraceDAG
// ---------------------------------------------------------------------------

/**
 * A trace of a single path out of a BranchPoint.
 *
 * Once a BranchPoint is retired with 1 outgoing edge, the multiple paths coming out of
 * the BranchPoint are considered a single path for the parent BlockTrace.
 */
class BlockTrace {
  static readonly f_active = 1;    // This BlockTrace is active
  static readonly f_terminal = 2;  // All paths from this point exit (without merging back to parent)

  flags: number;                     // Properties of the BlockTrace
  top: BranchPoint;                  // Parent BranchPoint for which this is a path
  pathout: number;                   // Index of the out-edge for this path (relative to the parent BranchPoint)
  bottom: FlowBlock | null;         // Current node being traversed along 1 path from decision point
  destnode: FlowBlock | null;       // Next FlowBlock node this BlockTrace will try to push into
  edgelump: number;                  // If >1, edge to destnode is "virtual" representing multiple edges coming together
  activeIndex: number;               // Position of this in the active trace list (index into array)
  derivedbp: BranchPoint | null;    // BranchPoint blocker this traces into

  /**
   * Construct given a parent BranchPoint and path index.
   * @param t is the parent BranchPoint
   * @param po is the index of the formal path out of the BranchPoint to this
   * @param eo is the edge index out of the BranchPoint's root FlowBlock
   */
  constructor(t: BranchPoint, po: number, eo: number);
  /**
   * Construct a root BlockTrace.
   * @param root is the virtual BranchPoint
   * @param po is the path out the BranchPoint to this
   * @param bl is the first FlowBlock along the path
   */
  constructor(t: BranchPoint, po: number, eoOrBl: number | FlowBlock);
  constructor(t: BranchPoint, po: number, eoOrBl: number | FlowBlock) {
    this.flags = 0;
    this.top = t;
    this.pathout = po;
    this.activeIndex = -1;
    this.derivedbp = null;
    if (typeof eoOrBl === 'number') {
      // First constructor: (BranchPoint, pathout, edge-out-index)
      this.bottom = t.top;
      this.destnode = this.bottom!.getOut(eoOrBl);
      this.edgelump = 1;
    } else {
      // Second constructor: (root BranchPoint, pathout, FlowBlock)
      this.bottom = null;
      this.destnode = eoOrBl;
      this.edgelump = 1;
    }
  }

  /** Return true if this is active */
  isActive(): boolean {
    return (this.flags & BlockTrace.f_active) !== 0;
  }

  /** Return true if this terminates */
  isTerminal(): boolean {
    return (this.flags & BlockTrace.f_terminal) !== 0;
  }
}

/**
 * A node in the control-flow graph with multiple outgoing edges in the DAG.
 * Ideally, all these paths eventually merge at the same node.
 */
class BranchPoint {
  parent: BranchPoint | null;  // The parent BranchPoint along which this is only one path
  pathout: number;             // Index (of the out edge from the parent) of the path along which this lies
  top: FlowBlock | null;      // FlowBlock that embodies the branch point
  paths: BlockTrace[];         // BlockTrace for each possible path out of this BranchPoint
  depth: number;               // Depth of BranchPoints from the root
  ismark: boolean;             // Possible mark

  /** Create the (unique) root branch point */
  constructor();
  /** Construct given a parent BlockTrace */
  constructor(parenttrace: BlockTrace);
  constructor(parenttrace?: BlockTrace) {
    this.paths = [];
    this.ismark = false;
    if (parenttrace === undefined) {
      // Root constructor
      this.parent = null;
      this.depth = 0;
      this.pathout = -1;
      this.top = null;
    } else {
      this.parent = parenttrace.top;
      this.depth = this.parent.depth + 1;
      this.pathout = parenttrace.pathout;
      this.top = parenttrace.destnode;
      this.createTraces();
    }
  }

  /** Given the BlockTrace objects, create traces for a new BranchPoint */
  private createTraces(): void {
    const sizeout = this.top!.sizeOut();
    for (let i = 0; i < sizeout; ++i) {
      if (!this.top!.isLoopDAGOut(i)) continue;
      this.paths.push(new BlockTrace(this, this.paths.length, i));
    }
  }

  /** Mark a path from this up to the root BranchPoint */
  markPath(): void {
    let cur: BranchPoint | null = this;
    do {
      cur.ismark = !cur.ismark;
      cur = cur.parent;
    } while (cur !== null);
  }

  /**
   * Calculate distance between two BranchPoints.
   * The distance is the number of edges from this up to the common
   * ancestor plus the number of edges down to the other BranchPoint.
   * We assume that this has had its path up to the root marked.
   * @param op2 is the other BranchPoint
   * @returns the distance
   */
  distance(op2: BranchPoint): number {
    // find the common ancestor
    let cur: BranchPoint | null = op2;
    do {
      if (cur!.ismark) { // Found the common ancestor
        return (this.depth - cur!.depth) + (op2.depth - cur!.depth);
      }
      cur = cur!.parent;
    } while (cur !== null);
    return this.depth + op2.depth + 1;
  }

  /**
   * Get the first FlowBlock along the i-th BlockTrace path.
   * @param i is the index of the path
   * @returns the first FlowBlock along the path
   */
  getPathStart(i: number): FlowBlock | null {
    let res = 0;
    const sizeout = this.top!.sizeOut();
    for (let j = 0; j < sizeout; ++j) {
      if (!this.top!.isLoopDAGOut(j)) continue;
      if (res === i) {
        return this.top!.getOut(j);
      }
      res += 1;
    }
    return null;
  }
}

/**
 * Record for scoring a BlockTrace for suitability as an unstructured branch.
 * This class holds various metrics about BlockTraces that are used to sort them.
 */
class BadEdgeScore {
  exitproto: FlowBlock | null = null; // Putative exit block for the BlockTrace
  trace: BlockTrace | null = null;    // The active BlockTrace being considered
  distance: number = -1;              // Minimum distance crossed by this and any other BlockTrace sharing same exit block
  terminal: number = 0;               // 1 if BlockTrace destination has no exit, 0 otherwise
  siblingedge: number = 0;            // Number of active BlockTraces with same BranchPoint and exit as this

  /**
   * Compare BadEdgeScore for unstructured suitability.
   * @returns true if this is LESS likely to be the bad edge than op2
   */
  compareFinal(op2: BadEdgeScore): boolean {
    if (this.siblingedge !== op2.siblingedge) {
      return op2.siblingedge < this.siblingedge; // A bigger sibling edge is less likely to be the bad edge
    }
    if (this.terminal !== op2.terminal) {
      return this.terminal < op2.terminal;
    }
    if (this.distance !== op2.distance) {
      return this.distance < op2.distance; // Less distance between branchpoints means less likely to be bad
    }
    return this.trace!.top.depth < op2.trace!.top.depth; // Less depth means less likely to be bad
  }

  /**
   * Comparator for grouping BlockTraces with the same exit block and parent BranchPoint.
   * @returns negative, zero, or positive for ordering
   */
  compareGrouping(op2: BadEdgeScore): number {
    const thisind = this.exitproto!.getIndex();
    const op2ind = op2.exitproto!.getIndex();
    if (thisind !== op2ind) {
      return thisind < op2ind ? -1 : 1;
    }
    const tmpbl1 = this.trace!.top.top;
    const idx1 = tmpbl1 !== null ? tmpbl1.getIndex() : -1;
    const tmpbl2 = op2.trace!.top.top;
    const idx2 = tmpbl2 !== null ? tmpbl2.getIndex() : -1;
    if (idx1 !== idx2) {
      return idx1 < idx2 ? -1 : 1;
    }
    const po1 = this.trace!.pathout;
    const po2 = op2.trace!.pathout;
    if (po1 !== po2) {
      return po1 < po2 ? -1 : 1;
    }
    return 0;
  }
}

/**
 * Algorithm for selecting unstructured edges based on Directed Acyclic Graphs (DAG).
 *
 * With the exception of the back edges in loops, structured code tends to form a DAG.
 * Within the DAG, all building blocks of structured code have a single node entry point
 * and (at most) one exit block. Given root points, this class traces edges with this kind of
 * structure.  Paths can recursively split at any point, starting a new active BranchPoint, but
 * the BranchPoint can't be retired until all paths emanating from its start either terminate
 * or come back together at the same FlowBlock node. Once a BranchPoint is retired, all the edges
 * traversed from the start FlowBlock to the end FlowBlock are likely structurable. After pushing
 * the traces as far as possible and retiring as much as possible, any active edge left
 * is a candidate for an unstructured branch.
 *
 * Ultimately this produces a list of likely gotos, which is used whenever the structuring
 * algorithm (ActionBlockStructure) gets stuck.
 *
 * The tracing can be restricted to a loopbody by setting the top FlowBlock of the loop as
 * the root, and the loop exit block as the finish block.  Additionally, any edges that
 * exit the loop should be marked using LoopBody.setExitMarks().
 */
export class TraceDAG {
  private likelygoto: FloatingEdge[];              // A reference to the list of likely goto edges being produced
  private rootlist: FlowBlock[];                   // List of root FlowBlocks to trace from
  private branchlist: BranchPoint[];               // Current set of BranchPoints that have been traced
  private activecount: number;                     // Number of active BlockTrace objects
  private missedactivecount: number;               // Current number of active BlockTraces that can't be pushed further
  private activetrace: BlockTrace[];               // The list of active BlockTrace objects
  private current_activeindex: number;             // The current active BlockTrace being pushed (index)
  private finishblock: FlowBlock | null;           // Designated exit block for the DAG (or null)

  /**
   * Prepare for a new trace using the provided storage for the likely unstructured
   * edges that will be discovered.
   * @param lg is the container for likely unstructured edges
   */
  constructor(lg: FloatingEdge[]) {
    this.likelygoto = lg;
    this.rootlist = [];
    this.branchlist = [];
    this.activecount = 0;
    this.missedactivecount = 0;
    this.activetrace = [];
    this.current_activeindex = 0;
    this.finishblock = null;
  }

  /** Add a root FlowBlock to the trace */
  addRoot(root: FlowBlock): void {
    this.rootlist.push(root);
  }

  /** Mark an exit point not to trace beyond */
  setFinishBlock(bl: FlowBlock): void {
    this.finishblock = bl;
  }

  /**
   * This adds the BlockTrace to the list of potential unstructured edges.
   * Then patch up the BranchPoint/BlockTrace/pathout hierarchy.
   */
  private removeTrace(trace: BlockTrace): void {
    // Record that we should now treat this edge like goto
    this.likelygoto.push(new FloatingEdge(trace.bottom!, trace.destnode!)); // Create goto record
    trace.destnode!.setVisitCount(trace.destnode!.getVisitCount() + trace.edgelump); // Ignore edge(s)

    const parentbp = trace.top;

    if (trace.bottom !== parentbp.top) { // If trace has moved past the root branch, we can treat trace as terminal
      trace.flags |= BlockTrace.f_terminal;
      trace.bottom = null;
      trace.destnode = null;
      trace.edgelump = 0;
      // Do NOT remove from active list
      return;
    }
    // Otherwise we need to actually remove the path from the BranchPoint as the root branch will be marked as a goto
    this.removeActive(trace); // The trace will no longer be active
    const size = parentbp.paths.length;
    for (let i = trace.pathout + 1; i < size; ++i) { // Move every trace above trace's pathout down one slot
      const movedtrace = parentbp.paths[i];
      movedtrace.pathout -= 1; // Correct the trace's pathout
      const derivedbp = movedtrace.derivedbp;
      if (derivedbp !== null) {
        derivedbp.pathout -= 1; // Correct any derived BranchPoint's pathout
      }
      parentbp.paths[i - 1] = movedtrace;
    }
    parentbp.paths.pop(); // Remove the vacated slot
    // In C++ the trace was deleted; in TS garbage collection handles it.
  }

  /**
   * Process a set of conflicting BlockTrace objects that go to the same exit point.
   * For each conflicting BlockTrace, calculate the minimum distance between it and any other BlockTrace.
   */
  private processExitConflict(scores: BadEdgeScore[], startIdx: number, endIdx: number): void {
    let si = startIdx;
    while (si < endIdx) {
      let ii = si + 1;
      const startbp = scores[si].trace!.top;
      if (ii < endIdx) {
        startbp.markPath(); // Mark path to root, so we can find common ancestors easily
        do {
          if (startbp === scores[ii].trace!.top) { // Edge coming from same BranchPoint
            scores[si].siblingedge += 1;
            scores[ii].siblingedge += 1;
          }
          const dist = startbp.distance(scores[ii].trace!.top);
          // Distance is symmetric with respect to the pair of traces,
          // Update minimum for both traces
          if (scores[si].distance === -1 || scores[si].distance > dist) {
            scores[si].distance = dist;
          }
          if (scores[ii].distance === -1 || scores[ii].distance > dist) {
            scores[ii].distance = dist;
          }
          ++ii;
        } while (ii < endIdx);
        startbp.markPath(); // Unmark the path
      }
      ++si;
    }
  }

  /**
   * Run through the list of active BlockTrace objects, annotate them using
   * the BadEdgeScore class, then select the BlockTrace which is the most likely
   * candidate for an unstructured edge.
   * @returns the BlockTrace corresponding to the unstructured edge
   */
  private selectBadEdge(): BlockTrace {
    const badedgelist: BadEdgeScore[] = [];
    for (const trace of this.activetrace) {
      if (trace.isTerminal()) continue;
      if (trace.top.top === null && trace.bottom === null) {
        continue; // Never remove virtual edges
      }
      const score = new BadEdgeScore();
      score.trace = trace;
      score.exitproto = trace.destnode;
      score.distance = -1;
      score.siblingedge = 0;
      score.terminal = (trace.destnode!.sizeOut() === 0) ? 1 : 0;
      badedgelist.push(score);
    }
    badedgelist.sort((a, b) => a.compareGrouping(b));

    let idx = 0;
    let startIdx = 0;
    let curbl = badedgelist[idx].exitproto;
    let samenodecount = 1;
    idx++;
    while (idx < badedgelist.length) { // Find traces to the same exitblock
      const score = badedgelist[idx];
      if (curbl === score.exitproto) {
        samenodecount += 1; // Count another trace to the same exit
        idx++;
      } else { // A new exit node
        if (samenodecount > 1) {
          this.processExitConflict(badedgelist, startIdx, idx);
        }
        curbl = score.exitproto;
        startIdx = idx;
        samenodecount = 1;
        idx++;
      }
    }
    if (samenodecount > 1) { // Process possible final group of traces exiting to same block
      this.processExitConflict(badedgelist, startIdx, idx);
    }

    let maxIdx = 0;
    for (let i = 1; i < badedgelist.length; ++i) {
      if (badedgelist[maxIdx].compareFinal(badedgelist[i])) {
        maxIdx = i;
      }
    }
    return badedgelist[maxIdx].trace!;
  }

  /** Move a BlockTrace into the active category */
  private insertActive(trace: BlockTrace): void {
    this.activetrace.push(trace);
    trace.activeIndex = this.activetrace.length - 1;
    trace.flags |= BlockTrace.f_active;
    this.activecount += 1;
  }

  /** Remove a BlockTrace from the active category */
  private removeActive(trace: BlockTrace): void {
    const idx = trace.activeIndex;
    // Swap with last element and pop for O(1) removal
    const lastIdx = this.activetrace.length - 1;
    if (idx !== lastIdx) {
      const swapped = this.activetrace[lastIdx];
      this.activetrace[idx] = swapped;
      swapped.activeIndex = idx;
    }
    this.activetrace.pop();
    trace.flags &= ~BlockTrace.f_active;
    this.activecount -= 1;
    // Adjust current_activeindex if needed
    if (this.current_activeindex > this.activetrace.length) {
      this.current_activeindex = 0;
    }
  }

  /**
   * Verify the given BlockTrace can push into the next FlowBlock (destnode).
   * A FlowBlock node can only be opened if all the incoming edges have been traced.
   * @param trace is the given BlockTrace to push
   * @returns true if the new node can be opened
   */
  private checkOpen(trace: BlockTrace): boolean {
    if (trace.isTerminal()) return false; // Already been opened
    let isroot = false;
    if (trace.top.depth === 0) {
      if (trace.bottom === null) {
        return true; // Artificial root can always open its first level (edge is not real edge)
      }
      isroot = true;
    }

    const bl = trace.destnode!;
    if (bl === this.finishblock && !isroot) {
      return false; // If there is a designated exit, only the root can open it
    }
    const ignore = trace.edgelump + bl.getVisitCount();
    let count = 0;
    for (let i = 0; i < bl.sizeIn(); ++i) {
      if (bl.isLoopDAGIn(i)) {
        count += 1;
        if (count > ignore) return false;
      }
    }
    return true;
  }

  /**
   * Given that a BlockTrace can be opened into its next FlowBlock node,
   * create a new BranchPoint at that node, and set up new sub-traces.
   * @param parent is the given BlockTrace to split
   * @returns the index (within the active list) of the new BlockTrace objects
   */
  private openBranch(parent: BlockTrace): number {
    const newbranch = new BranchPoint(parent);
    parent.derivedbp = newbranch;
    if (newbranch.paths.length === 0) { // No new traces, return immediately to parent trace
      // In C++ 'delete newbranch' -- GC handles it
      parent.derivedbp = null;
      parent.flags |= BlockTrace.f_terminal; // marking it as terminal
      parent.bottom = null;
      parent.destnode = null;
      parent.edgelump = 0;
      return parent.activeIndex;
    }
    this.removeActive(parent);
    this.branchlist.push(newbranch);
    for (let i = 0; i < newbranch.paths.length; ++i) {
      this.insertActive(newbranch.paths[i]);
    }
    return newbranch.paths[0].activeIndex;
  }

  /**
   * For the given BlockTrace, make sure all other sibling BlockTraces from its
   * BranchPoint parent either terminate or flow to the same FlowBlock node.
   * If so, return true and pass back that node as the exitblock.
   * @param trace is the given BlockTrace
   * @param exitblockRef - object to hold the passed back exit block { val: FlowBlock | null }
   * @returns true if the BlockTrace can be retired
   */
  private checkRetirement(trace: BlockTrace, exitblockRef: { val: FlowBlock | null }): boolean {
    if (trace.pathout !== 0) return false; // Only check if this is the first sibling
    const bp = trace.top;
    if (bp.depth === 0) { // Special conditions for retirement of root branch point
      for (let i = 0; i < bp.paths.length; ++i) {
        const curtrace = bp.paths[i];
        if (!curtrace.isActive()) return false;
        if (!curtrace.isTerminal()) return false; // All root paths must be terminal
      }
      return true;
    }
    let outblock: FlowBlock | null = null;
    for (let i = 0; i < bp.paths.length; ++i) {
      const curtrace = bp.paths[i];
      if (!curtrace.isActive()) return false;
      if (curtrace.isTerminal()) continue;
      if (outblock === curtrace.destnode) continue;
      if (outblock !== null) return false;
      outblock = curtrace.destnode;
    }
    exitblockRef.val = outblock;
    return true;
  }

  /**
   * Retire a BranchPoint, updating its parent BlockTrace.
   * Knowing a given BranchPoint can be retired, remove all its BlockTraces
   * from the active list, and update the BranchPoint's parent BlockTrace
   * as having reached the BlockTrace exit point.
   * @param bp is the given BranchPoint
   * @param exitblock is unique exit FlowBlock (calculated by checkRetirement())
   * @returns the index of the next active BlockTrace to examine
   */
  private retireBranch(bp: BranchPoint, exitblock: FlowBlock | null): number {
    let edgeout_bl: FlowBlock | null = null;
    let edgelump_sum = 0;

    for (let i = 0; i < bp.paths.length; ++i) {
      const curtrace = bp.paths[i];
      if (!curtrace.isTerminal()) {
        edgelump_sum += curtrace.edgelump;
        if (edgeout_bl === null) {
          edgeout_bl = curtrace.bottom;
        }
      }
      this.removeActive(curtrace); // Child traces are complete and no longer active
    }
    if (bp.depth === 0) { // If this is the root block
      return 0; // This is all there is to do
    }

    if (bp.parent !== null) {
      const parenttrace = bp.parent.paths[bp.pathout];
      parenttrace.derivedbp = null; // Derived branchpoint is gone
      if (edgeout_bl === null) { // If all traces were terminal
        parenttrace.flags |= BlockTrace.f_terminal;
        parenttrace.bottom = null;
        parenttrace.destnode = null;
        parenttrace.edgelump = 0;
      } else {
        parenttrace.bottom = edgeout_bl;
        parenttrace.destnode = exitblock;
        parenttrace.edgelump = edgelump_sum;
      }
      this.insertActive(parenttrace); // Parent trace gets re-activated
      return parenttrace.activeIndex;
    }
    return 0;
  }

  /**
   * The visitcount field is only modified in removeTrace() whenever we put an edge
   * in the likelygoto list.
   */
  private clearVisitCount(): void {
    for (const edge of this.likelygoto) {
      edge.getBottom().setVisitCount(0);
    }
  }

  /**
   * Given the registered root FlowBlocks, create the initial (virtual) BranchPoint
   * and an associated BlockTrace for each root FlowBlock.
   */
  initialize(): void {
    const rootBranch = new BranchPoint(); // Create a virtual BranchPoint for all entry points
    this.branchlist.push(rootBranch);

    for (let i = 0; i < this.rootlist.length; ++i) { // Find the entry points
      const newtrace = new BlockTrace(rootBranch, rootBranch.paths.length, this.rootlist[i] as any);
      rootBranch.paths.push(newtrace);
      this.insertActive(newtrace);
    }
  }

  /**
   * From the root BranchPoint, recursively push the trace. At any point where pushing
   * is no longer possible, select an appropriate edge to remove and add it to the
   * list of likely unstructured edges.  Then continue pushing the trace.
   */
  pushBranches(): void {
    const exitblockRef: { val: FlowBlock | null } = { val: null };

    this.current_activeindex = 0;
    this.missedactivecount = 0;
    while (this.activecount > 0) {
      if (this.current_activeindex >= this.activetrace.length) {
        this.current_activeindex = 0;
      }
      const curtrace = this.activetrace[this.current_activeindex];
      if (this.missedactivecount >= this.activecount) { // Could not push any trace further
        const badtrace = this.selectBadEdge(); // So we pick an edge to be unstructured
        this.removeTrace(badtrace); // destroy the trace
        this.current_activeindex = 0;
        this.missedactivecount = 0;
      } else if (this.checkRetirement(curtrace, exitblockRef)) {
        this.current_activeindex = this.retireBranch(curtrace.top, exitblockRef.val);
        this.missedactivecount = 0;
      } else if (this.checkOpen(curtrace)) {
        this.current_activeindex = this.openBranch(curtrace);
        this.missedactivecount = 0;
      } else {
        this.missedactivecount += 1;
        this.current_activeindex++;
      }
    }
    this.clearVisitCount();
  }
}

// ---------------------------------------------------------------------------
// CollapseStructure
// ---------------------------------------------------------------------------

/**
 * Build a code structure from a control-flow graph (BlockGraph).
 *
 * This class manages the main control-flow structuring algorithm for the decompiler.
 * In short:
 *    - Start with a control-flow graph of basic blocks.
 *    - Repeatedly apply:
 *       - Search for sub-graphs matching specific code structure elements.
 *       - Note the structure element and collapse the component nodes to a single node.
 *    - If the process gets stuck, remove appropriate edges, marking them as unstructured.
 */
export class CollapseStructure {
  private finaltrace: boolean;                   // Have we made a search for unstructured edges in the final DAG
  private likelylistfull: boolean;               // Have we generated a likely goto list for the current innermost loop
  private likelygoto: FloatingEdge[];            // The current likely goto list
  private likelyiterIndex: number;               // Iterator index to the next most likely goto edge
  private loopbody: LoopBody[];                  // The list of loop bodies for this control-flow graph
  private loopbodyiterIndex: number;             // Current (innermost) loop being structured (index)
  private graph: BlockGraph;                     // The control-flow graph
  private dataflow_changecount: number;          // Number of data-flow changes made during structuring

  /**
   * The initial BlockGraph should be a copy of the permanent control-flow graph.
   * In particular the FlowBlock nodes should be BlockCopy instances.
   * @param g is the (copy of the) control-flow graph
   */
  constructor(g: BlockGraph) {
    this.graph = g;
    this.dataflow_changecount = 0;
    this.finaltrace = false;
    this.likelylistfull = false;
    this.likelygoto = [];
    this.likelyiterIndex = 0;
    this.loopbody = [];
    this.loopbodyiterIndex = 0;
  }

  /** Get number of data-flow changes */
  getChangeCount(): number {
    return this.dataflow_changecount;
  }

  /**
   * Mark FlowBlocks only reachable from a given root.
   * For a given root FlowBlock, find all the FlowBlocks that can only be reached from it,
   * mark them and put them in a list.
   */
  private onlyReachableFromRoot(root: FlowBlock, body: FlowBlock[]): void {
    const trial: FlowBlock[] = [];
    let i = 0;
    root.setMark();
    body.push(root);
    while (i < body.length) {
      const bl = body[i++];
      const sizeout = bl.sizeOut();
      for (let j = 0; j < sizeout; ++j) {
        const curbl = bl.getOut(j);
        if (curbl.isMark()) continue;
        let count = curbl.getVisitCount();
        if (count === 0) {
          trial.push(curbl); // New possible extension
        }
        count += 1;
        curbl.setVisitCount(count);
        if (count === curbl.sizeIn()) {
          curbl.setMark();
          body.push(curbl);
        }
      }
    }
    for (let idx = 0; idx < trial.length; ++idx) {
      trial[idx].setVisitCount(0); // Make sure to clear the count
    }
  }

  /**
   * The FlowBlock objects in the body must all be marked.
   * @param body is the list of FlowBlock objects in the body
   * @returns the number of edges that were marked as unstructured
   */
  private markExitsAsGotos(body: FlowBlock[]): number {
    let changecount = 0;
    for (let i = 0; i < body.length; ++i) {
      const bl = body[i];
      const sizeout = bl.sizeOut();
      for (let j = 0; j < sizeout; ++j) {
        const curbl = bl.getOut(j);
        if (!curbl.isMark()) {
          bl.setGotoBranch(j); // mark edge as goto
          changecount += 1;
        }
      }
    }
    return changecount;
  }

  /**
   * Find distinct control-flow FlowBlock roots (having no incoming edges).
   * These delineate disjoint subsets of the control-flow graph, where a subset
   * is defined as the FlowBlock nodes that are only reachable from the root.
   * This method searches for one disjoint subset with cross-over edges,
   * edges from that subset into another.  The exiting edges for this subset are marked
   * as unstructured gotos and true is returned.
   * @returns true if any cross-over edges were found (and marked)
   */
  private clipExtraRoots(): boolean {
    for (let i = 1; i < this.graph.getSize(); ++i) { // Skip the canonical root
      const bl = this.graph.getBlock(i);
      if (bl.sizeIn() !== 0) continue;
      const body: FlowBlock[] = [];
      this.onlyReachableFromRoot(bl, body);
      const count = this.markExitsAsGotos(body);
      LoopBody.clearMarks(body);
      if (count !== 0) {
        return true;
      }
    }
    return false;
  }

  /**
   * Identify all the distinct loops in the graph (via their back-edge) and create a LoopBody record.
   * @param looporder is the container that will hold the LoopBody record for each loop
   */
  private labelLoops(looporder: LoopBody[]): void {
    for (let i = 0; i < this.graph.getSize(); ++i) {
      const bl = this.graph.getBlock(i);
      const sizein = bl.sizeIn();
      for (let j = 0; j < sizein; ++j) {
        if (bl.isBackEdgeIn(j)) { // back-edge coming in must be from the bottom of a loop
          const loopbottom = bl.getIn(j);
          const curbody = new LoopBody(bl);
          curbody.addTail(loopbottom);
          this.loopbody.push(curbody);
          looporder.push(curbody);
        }
      }
    }
    looporder.sort(LoopBody.compare_ends);
  }

  /**
   * Find the loop bodies, then:
   *   - Label all edges which exit their loops.
   *   - Generate a partial order on the loop bodies.
   */
  private orderLoopBodies(): void {
    const looporder: LoopBody[] = [];
    this.labelLoops(looporder);
    if (this.loopbody.length > 0) {
      const oldsize = looporder.length;
      LoopBody.mergeIdenticalHeads(looporder);
      if (oldsize !== looporder.length) { // If there was merging
        // Remove subsumed loop bodies (those with null head)
        this.loopbody = this.loopbody.filter(lb => lb.getHead() !== null);
      }
      for (const lb of this.loopbody) {
        const body: FlowBlock[] = [];
        lb.findBase(body);
        lb.labelContainments(body, looporder);
        LoopBody.clearMarks(body);
      }
      // Sort based on nesting depth (deepest come first); sorting is stable
      this.loopbody.sort((a, b) => a.compareTo(b));
      for (const lb of this.loopbody) {
        const body: FlowBlock[] = [];
        lb.findBase(body);
        lb.findExit(body);
        lb.orderTails();
        lb.extend(body);
        lb.labelExitEdges(body);
        LoopBody.clearMarks(body);
      }
    }
    this.likelylistfull = false;
    this.loopbodyiterIndex = 0;
  }

  /**
   * Find the current innermost loop, make sure its likely goto edges are calculated.
   * If there are no loops, make sure the likely goto edges are calculated for the final DAG.
   * @returns true if there are likely unstructured edges left to provide
   */
  private updateLoopBody(): boolean {
    if (this.finaltrace) { // If we've already performed trace on DAG with no likely goto edges
      return false;        // don't repeat the trace
    }
    let loopbottom: FlowBlock | null = null;
    let looptop: FlowBlock | null = null;
    while (this.loopbodyiterIndex < this.loopbody.length) { // Last innermost loop
      const curBody = this.loopbody[this.loopbodyiterIndex];
      loopbottom = curBody.update(this.graph as unknown as FlowBlock);
      if (loopbottom !== null) {
        looptop = curBody.getHead();
        if (loopbottom === looptop) { // Check for single node looping back to itself
          // If sizeout is 1 or 2, the loop would have collapsed, so the node is likely a switch.
          this.likelygoto.length = 0;
          this.likelygoto.push(new FloatingEdge(looptop!, looptop!)); // Mark the loop edge as a goto
          this.likelyiterIndex = 0;
          this.likelylistfull = true;
          return true;
        }
        if (!this.likelylistfull || this.likelyiterIndex < this.likelygoto.length) {
          break; // Loop still exists
        }
      }
      ++this.loopbodyiterIndex;
      this.likelylistfull = false; // Need to generate likely list for new loopbody (or no loopbody)
      loopbottom = null;
    }
    if (this.likelylistfull && this.likelyiterIndex < this.likelygoto.length) {
      return true;
    }

    // If we reach here, need to generate likely gotos for a new inner loop or DAG
    this.likelygoto.length = 0; // Clear out any old likely gotos from last inner loop
    const tracer = new TraceDAG(this.likelygoto);
    if (loopbottom !== null) {
      tracer.addRoot(looptop!); // Trace from the top of the loop
      tracer.setFinishBlock(loopbottom);
      this.loopbody[this.loopbodyiterIndex].setExitMarks(this.graph as unknown as FlowBlock); // Set the bounds of the TraceDAG
    } else {
      for (let i = 0; i < this.graph.getSize(); ++i) {
        const bl = this.graph.getBlock(i);
        if (bl.sizeIn() === 0) {
          tracer.addRoot(bl);
        }
      }
    }
    tracer.initialize();
    tracer.pushBranches();
    this.likelylistfull = true; // Mark likelygoto generation complete for current loop or DAG
    if (loopbottom !== null) {
      this.loopbody[this.loopbodyiterIndex].emitLikelyEdges(
        this.likelygoto,
        this.graph as unknown as FlowBlock
      );
      this.loopbody[this.loopbodyiterIndex].clearExitMarks(this.graph as unknown as FlowBlock);
    } else if (this.likelygoto.length === 0) {
      this.finaltrace = true; // No loops left and trace didn't find gotos
      return false;
    }
    this.likelyiterIndex = 0;
    return true;
  }

  /**
   * Pick an edge from among the likely goto list generated by a
   * trace of the current innermost loop. Given ongoing collapsing, this
   * may involve updating which loop is currently innermost and throwing
   * out potential edges whose endpoints have already been collapsed.
   * @returns the FlowBlock whose outgoing edge was marked unstructured or null
   */
  private selectGoto(): FlowBlock | null {
    while (this.updateLoopBody()) {
      while (this.likelyiterIndex < this.likelygoto.length) {
        const outedgeRef = { val: 0 };
        const startbl = this.likelygoto[this.likelyiterIndex].getCurrentEdge(
          outedgeRef,
          this.graph as unknown as FlowBlock
        );
        ++this.likelyiterIndex;
        if (startbl !== null) {
          startbl.setGotoBranch(outedgeRef.val); // Mark the selected branch as goto
          return startbl;
        }
      }
    }
    if (!this.clipExtraRoots()) {
      throw new Error('Could not finish collapsing block structure');
    }
    return null;
  }

  /**
   * Try to concatenate a straight sequence of blocks starting with the given FlowBlock.
   * All of the internal edges should be DAG (no exit, goto, or loopback).
   * The final edge can be an exit or loopback.
   */
  private ruleBlockCat(bl: FlowBlock): boolean {
    if (bl.sizeOut() !== 1) return false;
    if (bl.isSwitchOut()) return false;
    if (bl.sizeIn() === 1 && bl.getIn(0).sizeOut() === 1) return false; // Must be start of chain
    let outblock = bl.getOut(0);
    if (outblock === bl) return false; // No looping
    if (outblock.sizeIn() !== 1) return false; // Nothing else can hit outblock
    if (!bl.isDecisionOut(0)) return false; // Not a goto or a loopbottom
    if (outblock.isSwitchOut()) return false; // Switch must be resolved first

    const nodes: FlowBlock[] = [];
    nodes.push(bl);       // The first two blocks being concatenated
    nodes.push(outblock);

    while (outblock.sizeOut() === 1) {
      const outbl2 = outblock.getOut(0);
      if (outbl2 === bl) break; // No looping
      if (outbl2.sizeIn() !== 1) break; // Nothing else can hit outblock
      if (!outblock.isDecisionOut(0)) break; // Don't use loop bottom
      if (outbl2.isSwitchOut()) break; // Switch must be resolved first
      outblock = outbl2;
      nodes.push(outblock); // Extend the cat chain
    }

    this.graph.newBlockList(nodes); // Concatenate the nodes into a single block
    return true;
  }

  /**
   * Try to find an OR condition (finding ANDs by duality) starting with the given FlowBlock.
   * The top of the OR should not perform gotos, the edge to the orblock should not
   * be exit or loopback.
   */
  private ruleBlockOr(bl: FlowBlock): boolean {
    if (bl.sizeOut() !== 2) return false;
    if (bl.isGotoOut(0)) return false;
    if (bl.isGotoOut(1)) return false;
    if (bl.isSwitchOut()) return false;

    for (let i = 0; i < 2; ++i) {
      const orblock = bl.getOut(i); // False out is other part of OR
      if (orblock === bl) continue; // orblock cannot be same block
      if (orblock.sizeIn() !== 1) continue; // Nothing else can hit orblock
      if (orblock.sizeOut() !== 2) continue; // orblock must also be binary condition
      if (orblock.isInteriorGotoTarget()) continue; // No unstructured jumps into or
      if (orblock.isSwitchOut()) continue;
      if (bl.isBackEdgeOut(i)) continue; // Don't use loop branch to get to orblock
      if (orblock.isComplex()) continue;
      const clauseblock = bl.getOut(1 - i);
      if (clauseblock === bl) continue; // No looping
      if (clauseblock === orblock) continue;
      let j: number;
      for (j = 0; j < 2; ++j) {
        if (clauseblock !== orblock.getOut(j)) continue; // Clauses don't match
        break;
      }
      if (j === 2) continue;
      if (orblock.getOut(1 - j) === bl) continue; // No looping

      if (i === 1) { // orblock needs to be false out of bl
        if (bl.negateCondition(true)) {
          this.dataflow_changecount += 1;
        }
      }
      if (j === 0) { // clauseblock needs to be true out of orblock
        if (orblock.negateCondition(true)) {
          this.dataflow_changecount += 1;
        }
      }

      this.graph.newBlockCondition(bl, orblock);
      return true;
    }
    return false;
  }

  /**
   * Try to structure a proper if structure (with no else clause) starting from the given FlowBlock.
   * The edge to the clause should not be an exit or loopbottom.
   * The outgoing edges can be exit or loopbottom.
   */
  private ruleBlockProperIf(bl: FlowBlock): boolean {
    if (bl.sizeOut() !== 2) return false; // Must be binary condition
    if (bl.isSwitchOut()) return false;
    if (bl.getOut(0) === bl) return false; // No loops
    if (bl.getOut(1) === bl) return false;
    if (bl.isGotoOut(0)) return false; // Neither branch must be unstructured
    if (bl.isGotoOut(1)) return false;
    for (let i = 0; i < 2; ++i) {
      const clauseblock = bl.getOut(i);
      if (clauseblock.sizeIn() !== 1) continue; // Nothing else can hit clauseblock
      if (clauseblock.sizeOut() !== 1) continue; // Only one way out of clause
      if (clauseblock.isSwitchOut()) continue; // Don't use switch (possibly with goto edges)
      if (!bl.isDecisionOut(i)) continue; // Don't use loopbottom or exit
      if (clauseblock.isGotoOut(0)) continue; // No unstructured jumps out of clause
      const outblock = clauseblock.getOut(0);
      if (outblock !== bl.getOut(1 - i)) continue; // Path after clause must be the same

      if (i === 0) { // Clause must be true
        if (bl.negateCondition(true)) {
          this.dataflow_changecount += 1;
        }
      }

      this.graph.newBlockIf(bl, clauseblock);
      return true;
    }
    return false;
  }

  /**
   * Try to find an if/else structure starting with the given FlowBlock.
   * Edges into the clauses cannot be goto, exit, or loopback.
   * The returning edges can be exit or loopback.
   */
  private ruleBlockIfElse(bl: FlowBlock): boolean {
    if (bl.sizeOut() !== 2) return false; // Must be binary condition
    if (bl.isSwitchOut()) return false;
    if (!bl.isDecisionOut(0)) return false;
    if (!bl.isDecisionOut(1)) return false;

    const tc = bl.getTrueOut();
    const fc = bl.getFalseOut();
    if (tc.sizeIn() !== 1) return false; // Nothing else must hit true clause
    if (fc.sizeIn() !== 1) return false; // Nothing else must hit false clause

    if (tc.sizeOut() !== 1) return false; // Only one exit from clause
    if (fc.sizeOut() !== 1) return false; // Only one exit from clause
    const outblock = tc.getOut(0);
    if (outblock === bl) return false; // No loops
    if (outblock !== fc.getOut(0)) return false; // Clauses must exit to same place

    if (tc.isSwitchOut()) return false;
    if (fc.isSwitchOut()) return false;
    if (tc.isGotoOut(0)) return false;
    if (fc.isGotoOut(0)) return false;

    this.graph.newBlockIfElse(bl, tc, fc);
    return true;
  }

  /**
   * For the given FlowBlock, look for an outgoing edge marked as unstructured.
   * Create or update the BlockGoto or BlockMultiGoto structure.
   */
  private ruleBlockGoto(bl: FlowBlock): boolean {
    const sizeout = bl.sizeOut();
    for (let i = 0; i < sizeout; ++i) {
      if (bl.isGotoOut(i)) {
        if (bl.isSwitchOut()) {
          this.graph.newBlockMultiGoto(bl, i);
          return true;
        }
        if (sizeout === 2) {
          if (!bl.isGotoOut(1)) { // True branch must be goto
            if (bl.negateCondition(true)) {
              this.dataflow_changecount += 1;
            }
          }
          this.graph.newBlockIfGoto(bl);
          return true;
        }
        if (sizeout === 1) {
          this.graph.newBlockGoto(bl);
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Try to find an if structure, where the condition clause does not exit,
   * starting with the given FlowBlock.
   */
  private ruleBlockIfNoExit(bl: FlowBlock): boolean {
    if (bl.sizeOut() !== 2) return false; // Must be binary condition
    if (bl.isSwitchOut()) return false;
    if (bl.getOut(0) === bl) return false; // No loops
    if (bl.getOut(1) === bl) return false;
    if (bl.isGotoOut(0)) return false;
    if (bl.isGotoOut(1)) return false;
    for (let i = 0; i < 2; ++i) {
      const clauseblock = bl.getOut(i);
      if (clauseblock.sizeIn() !== 1) continue; // Nothing else must hit clause
      if (clauseblock.sizeOut() !== 0) continue; // Must be no way out of clause
      if (clauseblock.isSwitchOut()) continue;
      if (!bl.isDecisionOut(i)) continue;

      if (i === 0) { // clause must be true out of bl
        if (bl.negateCondition(true)) {
          this.dataflow_changecount += 1;
        }
      }
      this.graph.newBlockIf(bl, clauseblock);
      return true;
    }
    return false;
  }

  /**
   * Try to find a while/do structure, starting with a given FlowBlock.
   * Any break or continue must have already been collapsed as some form of goto.
   */
  private ruleBlockWhileDo(bl: FlowBlock): boolean {
    if (bl.sizeOut() !== 2) return false; // Must be binary condition
    if (bl.isSwitchOut()) return false;
    if (bl.getOut(0) === bl) return false; // No loops at this point
    if (bl.getOut(1) === bl) return false;
    if (bl.isInteriorGotoTarget()) return false;
    if (bl.isGotoOut(0)) return false;
    if (bl.isGotoOut(1)) return false;
    for (let i = 0; i < 2; ++i) {
      const clauseblock = bl.getOut(i);
      if (clauseblock.sizeIn() !== 1) continue; // Nothing else must hit clause
      if (clauseblock.sizeOut() !== 1) continue; // Only one way out of clause
      if (clauseblock.isSwitchOut()) continue;
      if (clauseblock.getOut(0) !== bl) continue; // Clause must loop back to bl

      const overflow = bl.isComplex(); // Check if we need to use overflow syntax
      if ((i === 0) !== overflow) { // clause must be true out of bl unless we use overflow syntax
        if (bl.negateCondition(true)) {
          this.dataflow_changecount += 1;
        }
      }
      const newbl: BlockWhileDo = this.graph.newBlockWhileDo(bl, clauseblock);
      if (overflow) {
        newbl.setOverflowSyntax();
      }
      return true;
    }
    return false;
  }

  /**
   * Try to find a do/while structure, starting with the given FlowBlock.
   * Any break and continue must have already been collapsed as some form of goto.
   */
  private ruleBlockDoWhile(bl: FlowBlock): boolean {
    if (bl.sizeOut() !== 2) return false; // Must be binary condition
    if (bl.isSwitchOut()) return false;
    if (bl.isGotoOut(0)) return false;
    if (bl.isGotoOut(1)) return false;
    for (let i = 0; i < 2; ++i) {
      if (bl.getOut(i) !== bl) continue; // Must loop back on itself
      if (i === 0) { // must loop on true condition
        if (bl.negateCondition(true)) {
          this.dataflow_changecount += 1;
        }
      }
      this.graph.newBlockDoWhile(bl);
      return true;
    }
    return false;
  }

  /**
   * Try to find a loop structure with no exits, starting at the given FlowBlock.
   */
  private ruleBlockInfLoop(bl: FlowBlock): boolean {
    if (bl.sizeOut() !== 1) return false; // Must only be one way out
    if (bl.isGotoOut(0)) return false;
    if (bl.getOut(0) !== bl) return false; // Must fall into itself
    this.graph.newBlockInfLoop(bl);
    return true;
  }

  /**
   * Check for switch edges that go straight to the exit block.
   *
   * Some switch forms have edges that effectively skip the body of the switch and go straight to the exit.
   * Many jumptable schemes have a default (i.e. if nothing else matches) edge.
   * If such skip edges exist, they are converted to gotos and false is returned.
   * @param switchbl is the entry FlowBlock for the switch
   * @param exitblock is the designated exit FlowBlock for the switch
   * @returns true if there are no skip edges
   */
  private checkSwitchSkips(switchbl: FlowBlock, exitblock: FlowBlock | null): boolean {
    if (exitblock === null) return true;

    const sizeout = switchbl.sizeOut();
    let defaultnottoexit = false;
    let anyskiptoexit = false;
    for (let edgenum = 0; edgenum < sizeout; ++edgenum) {
      if (switchbl.getOut(edgenum) === exitblock) {
        if (!switchbl.isDefaultBranch(edgenum)) {
          anyskiptoexit = true;
        }
      } else {
        if (switchbl.isDefaultBranch(edgenum)) {
          defaultnottoexit = true;
        }
      }
    }

    if (!anyskiptoexit) return true;

    if (!defaultnottoexit && switchbl.getType() === block_type.t_multigoto) {
      const multibl = switchbl as unknown as BlockMultiGoto;
      if (multibl.hasDefaultGoto()) {
        defaultnottoexit = true;
      }
    }
    if (!defaultnottoexit) return true;

    for (let edgenum = 0; edgenum < sizeout; ++edgenum) {
      if (switchbl.getOut(edgenum) === exitblock) {
        if (!switchbl.isDefaultBranch(edgenum)) {
          switchbl.setGotoBranch(edgenum);
        }
      }
    }
    return false;
  }

  /**
   * Try to find a switch structure, starting with the given FlowBlock.
   */
  private ruleBlockSwitch(bl: FlowBlock): boolean {
    if (!bl.isSwitchOut()) return false;
    let exitblock: FlowBlock | null = null;
    const sizeout = bl.sizeOut();

    // Find "obvious" exitblock: is sizeIn>1 or sizeOut>1
    for (let i = 0; i < sizeout; ++i) {
      const curbl = bl.getOut(i);
      if (curbl === bl) {
        exitblock = curbl; // Exit back to top of switch (loop)
        break;
      }
      if (curbl.sizeOut() > 1) {
        exitblock = curbl;
        break;
      }
      if (curbl.sizeIn() > 1) {
        exitblock = curbl;
        break;
      }
    }
    if (exitblock === null) {
      // If we reach here, every immediate block out of switch must have sizeIn==1 and sizeOut<=1
      for (let i = 0; i < sizeout; ++i) {
        const curbl = bl.getOut(i);
        if (curbl.isGotoIn(0)) return false; // In cannot be a goto
        if (curbl.isSwitchOut()) return false; // Must resolve nested switch first
        if (curbl.sizeOut() === 1) {
          if (curbl.isGotoOut(0)) return false; // Out cannot be goto
          if (exitblock !== null) {
            if (exitblock !== curbl.getOut(0)) return false;
          } else {
            exitblock = curbl.getOut(0);
          }
        }
      }
    } else { // From here we have a determined exitblock
      for (let i = 0; i < exitblock.sizeIn(); ++i) { // No in gotos to exitblock
        if (exitblock.isGotoIn(i)) return false;
      }
      for (let i = 0; i < exitblock.sizeOut(); ++i) { // No out gotos from exitblock
        if (exitblock.isGotoOut(i)) return false;
      }
      for (let i = 0; i < sizeout; ++i) {
        const curbl = bl.getOut(i);
        if (curbl === exitblock) continue; // The switch can go straight to the exit block
        if (curbl.sizeIn() > 1) return false; // A case can only have the switch fall into it
        if (curbl.isGotoIn(0)) return false; // In cannot be a goto
        if (curbl.sizeOut() > 1) return false; // There can be at most 1 exit from a case
        if (curbl.sizeOut() === 1) {
          if (curbl.isGotoOut(0)) return false; // Out cannot be goto
          if (curbl.getOut(0) !== exitblock) return false; // which must be to the exitblock
        }
        if (curbl.isSwitchOut()) return false; // Nested switch must be resolved first
      }
    }

    if (!this.checkSwitchSkips(bl, exitblock)) {
      return true; // We match, but have special condition that adds gotos
    }

    const cases: FlowBlock[] = [];
    cases.push(bl);
    for (let i = 0; i < sizeout; ++i) {
      const curbl = bl.getOut(i);
      if (curbl === exitblock) continue; // Don't include exit as a case
      cases.push(curbl);
    }
    this.graph.newBlockSwitch(cases, exitblock !== null);
    return true;
  }

  /**
   * Look for a switch case that falls thru to another switch case, starting
   * with the given switch FlowBlock.
   */
  private ruleCaseFallthru(bl: FlowBlock): boolean {
    if (!bl.isSwitchOut()) return false;
    const sizeout = bl.sizeOut();
    let nonfallthru = 0; // Count of exits that are not fallthru
    const fallthru: FlowBlock[] = [];

    for (let i = 0; i < sizeout; ++i) {
      const curbl = bl.getOut(i);
      if (curbl === bl) return false; // Cannot exit to itself
      if (curbl.sizeIn() > 2 || curbl.sizeOut() > 1) {
        nonfallthru += 1;
      } else if (curbl.sizeOut() === 1) {
        const target = curbl.getOut(0);
        if (target.sizeIn() === 2 && target.sizeOut() <= 1) {
          const inslot = curbl.getOutRevIndex(0);
          if (target.getIn(1 - inslot) === bl) {
            fallthru.push(curbl);
          }
        }
      }
      if (nonfallthru > 1) return false; // Can have at most 1 other exit block
    }
    if (fallthru.length === 0) return false; // No fall thru candidates

    // Mark the fallthru edges as gotos
    for (let i = 0; i < fallthru.length; ++i) {
      const curbl = fallthru[i];
      curbl.setGotoBranch(0);
    }

    return true;
  }

  /**
   * Collapse everything until no additional rules apply.
   * If handed a particular FlowBlock, try simplifying from that block first.
   * @param targetbl is the FlowBlock to start from or null
   * @returns the count of isolated FlowBlocks (with no incoming or outgoing edges)
   */
  private collapseInternal(targetbl: FlowBlock | null): number {
    let index: number;
    let change: boolean;
    let fullchange: boolean;
    let isolated_count: number;
    let bl: FlowBlock;

    do {
      do {
        change = false;
        index = 0;
        isolated_count = 0;
        while (index < this.graph.getSize()) {
          if (targetbl === null) {
            bl = this.graph.getBlock(index);
            index += 1;
          } else {
            bl = targetbl;       // Pick out targeted block
            change = true;       // but force a change so we still go through all blocks
            targetbl = null;     // Only target the block once
            index = this.graph.getSize();
          }
          if (bl.sizeIn() === 0 && bl.sizeOut() === 0) { // A completely collapsed block
            isolated_count += 1;
            continue; // This does not constitute a change
          }
          // Try each rule on the block
          if (this.ruleBlockGoto(bl)) {
            change = true;
            continue;
          }
          if (this.ruleBlockCat(bl)) {
            change = true;
            continue;
          }
          if (this.ruleBlockProperIf(bl)) {
            change = true;
            continue;
          }
          if (this.ruleBlockIfElse(bl)) {
            change = true;
            continue;
          }
          if (this.ruleBlockWhileDo(bl)) {
            change = true;
            continue;
          }
          if (this.ruleBlockDoWhile(bl)) {
            change = true;
            continue;
          }
          if (this.ruleBlockInfLoop(bl)) {
            change = true;
            continue;
          }
          if (this.ruleBlockSwitch(bl)) {
            change = true;
            continue;
          }
        }
      } while (change);
      // Applying IfNoExit rule too early can cause other (preferable) rules to miss
      // Only apply the rule if nothing else can apply
      fullchange = false;
      for (index = 0; index < this.graph.getSize(); ++index) {
        bl = this.graph.getBlock(index);
        if (this.ruleBlockIfNoExit(bl)) { // If no other change is possible but still blocks left, try ifnoexit
          fullchange = true;
          break;
        }
        if (this.ruleCaseFallthru(bl)) { // Check for fallthru cases in a switch
          fullchange = true;
          break;
        }
      }
    } while (fullchange);
    return isolated_count;
  }

  /** Simplify just the conditional AND/OR constructions. */
  private collapseConditions(): void {
    let change: boolean;
    do {
      change = false;
      for (let i = 0; i < this.graph.getSize(); ++i) {
        if (this.ruleBlockOr(this.graph.getBlock(i))) {
          change = true;
        }
      }
    } while (change);
  }

  /**
   * Collapse everything in the control-flow graph to isolated blocks with no inputs and outputs.
   */
  collapseAll(): void {
    this.finaltrace = false;
    this.graph.clearVisitCount();
    this.orderLoopBodies();

    this.collapseConditions();

    let isolated_count = this.collapseInternal(null);
    while (isolated_count < this.graph.getSize()) {
      const targetbl = this.selectGoto();
      isolated_count = this.collapseInternal(targetbl);
    }
  }
}

// ---------------------------------------------------------------------------
// ConditionalJoin
// ---------------------------------------------------------------------------

/**
 * A pair of Varnode objects that have been split (and should be merged).
 */
class MergePair {
  side1: Varnode; // Varnode coming from block1
  side2: Varnode; // Varnode coming from block2

  constructor(s1: Varnode, s2: Varnode) {
    this.side1 = s1;
    this.side2 = s2;
  }

  /** Generate a unique string key for use in Map */
  toKey(): string {
    return `${this.side1.getCreateIndex()}_${this.side2.getCreateIndex()}`;
  }

  /** Lexicographic comparator */
  compareTo(op2: MergePair): number {
    const s1 = this.side1.getCreateIndex();
    const s2 = op2.side1.getCreateIndex();
    if (s1 !== s2) return s1 < s2 ? -1 : 1;
    const t1 = this.side2.getCreateIndex();
    const t2 = op2.side2.getCreateIndex();
    if (t1 !== t2) return t1 < t2 ? -1 : 1;
    return 0;
  }
}

/**
 * Discover and eliminate split conditions.
 *
 * A split condition is when a conditional expression, resulting in a CBRANCH,
 * is duplicated across two blocks that would otherwise merge.
 * Instead of a single conditional in a merged block,
 * there are two copies of the conditional, two splitting blocks and no direct merge.
 */
export class ConditionalJoin {
  private data: Funcdata;                           // The function being analyzed
  private block1: BlockBasic | null = null;         // Side 1 of the (putative) split
  private block2: BlockBasic | null = null;         // Side 2 of the (putative) split
  private exita: BlockBasic | null = null;          // First (common) exit point
  private exitb: BlockBasic | null = null;          // Second (common) exit point
  private a_in1: number = 0;                        // In edge of exita coming from block1
  private a_in2: number = 0;                        // In edge of exita coming from block2
  private b_in1: number = 0;                        // In edge of exitb coming from block1
  private b_in2: number = 0;                        // In edge of exitb coming from block2
  private cbranch1: PcodeOp | null = null;          // CBRANCH at bottom of block1
  private cbranch2: PcodeOp | null = null;          // CBRANCH at bottom of block2
  private joinblock: BlockBasic | null = null;      // The new joined condition block
  private mergeneed: Map<string, { pair: MergePair; result: Varnode | null }> = new Map();

  /** Constructor */
  constructor(fd: Funcdata) {
    this.data = fd;
  }

  /**
   * Search for duplicate conditional expressions.
   * Given two conditional blocks, determine if the corresponding conditional
   * expressions are equivalent, up to Varnodes that need to be merged.
   * @returns true if there are matching conditions
   */
  private findDups(): boolean {
    this.cbranch1 = this.block1!.lastOp();
    if (this.cbranch1!.code() !== CPUI_CBRANCH) return false;
    this.cbranch2 = this.block2!.lastOp();
    if (this.cbranch2!.code() !== CPUI_CBRANCH) return false;

    if (this.cbranch1!.isBooleanFlip()) return false; // flip hasn't propagated through yet
    if (this.cbranch2!.isBooleanFlip()) return false;

    const vn1: Varnode = this.cbranch1!.getIn(1);
    const vn2: Varnode = this.cbranch2!.getIn(1);

    if (vn1 === vn2) return true;

    // Parallel RulePushMulti, so we know it will apply if we do the join
    if (!vn1.isWritten()) return false;
    if (!vn2.isWritten()) return false;
    if (vn1.isSpacebase()) return false;
    if (vn2.isSpacebase()) return false;
    const buf1: Varnode[] = [null, null];
    const buf2: Varnode[] = [null, null];
    const res = functionalEqualityLevel(vn1, vn2, buf1, buf2);
    if (res < 0) return false;
    if (res > 1) return false;
    const op1: PcodeOp = vn1.getDef();
    if (op1.code() === CPUI_SUBPIECE) return false;
    if (op1.code() === CPUI_COPY) return false;

    const mp = new MergePair(vn1, vn2);
    this.mergeneed.set(mp.toKey(), { pair: mp, result: null });
    return true;
  }

  /**
   * Look for additional Varnode pairs in an exit block that need to be merged.
   * Varnodes that are merged in the exit block flowing from block1 and block2
   * will need to be merged in the new joined block.  Add these pairs to the mergeneed map.
   */
  private checkExitBlock(exit: BlockBasic, in1: number, in2: number): void {
    const iter = exit.beginOp();
    const enditer = exit.endOp();
    for (const op of ConditionalJoin.iterateOps(exit)) {
      if (op.code() === CPUI_MULTIEQUAL) { // Anything merging from our two root blocks
        const vn1: Varnode = op.getIn(in1);
        const vn2: Varnode = op.getIn(in2);
        if (vn1 !== vn2) {
          const mp = new MergePair(vn1, vn2);
          this.mergeneed.set(mp.toKey(), { pair: mp, result: null });
        }
      } else if (op.code() !== CPUI_COPY) {
        break;
      }
    }
  }

  /**
   * Substitute new joined Varnode in the given exit block.
   * For any MULTIEQUAL in the exit, given two input slots, remove one Varnode,
   * and substitute the other Varnode from the corresponding Varnode in the mergeneed map.
   */
  private cutDownMultiequals(exit: BlockBasic, in1: number, in2: number): void {
    let lo: number;
    let hi: number;
    if (in1 > in2) {
      hi = in1;
      lo = in2;
    } else {
      hi = in2;
      lo = in1;
    }
    for (const op of ConditionalJoin.iterateOps(exit)) {
      if (op.code() === CPUI_MULTIEQUAL) {
        const vn1: Varnode = op.getIn(in1);
        const vn2: Varnode = op.getIn(in2);
        if (vn1 === vn2) {
          this.data.opRemoveInput(op, hi);
        } else {
          const mp = new MergePair(vn1, vn2);
          const entry = this.mergeneed.get(mp.toKey());
          const subvn = entry!.result;
          this.data.opRemoveInput(op, hi);
          this.data.opSetInput(op, subvn, lo);
        }
        if (op.numInput() === 1) {
          this.data.opUninsert(op);
          this.data.opSetOpcode(op, CPUI_COPY);
          this.data.opInsertBegin(op, exit);
        }
      } else if (op.code() !== CPUI_COPY) {
        break;
      }
    }
  }

  /**
   * Create a new Varnode and its defining MULTIEQUAL operation
   * for each MergePair in the map.
   */
  private setupMultiequals(): void {
    for (const [key, entry] of this.mergeneed) {
      if (entry.result !== null) continue;
      const vn1 = entry.pair.side1;
      const vn2 = entry.pair.side2;
      const multi = this.data.newOp(2, this.cbranch1!.getAddr());
      this.data.opSetOpcode(multi, CPUI_MULTIEQUAL);
      const outvn = this.data.newUniqueOut(vn1.getSize(), multi);
      this.data.opSetInput(multi, vn1, 0);
      this.data.opSetInput(multi, vn2, 1);
      entry.result = outvn;
      this.data.opInsertEnd(multi, this.joinblock);
    }
  }

  /**
   * Remove the other CBRANCH.
   * Move one of the duplicated CBRANCHs into the new joinblock.
   */
  private moveCbranch(): void {
    const vn1: Varnode = this.cbranch1!.getIn(1);
    const vn2: Varnode = this.cbranch2!.getIn(1);
    this.data.opUninsert(this.cbranch1!);
    this.data.opInsertEnd(this.cbranch1!, this.joinblock!);
    let vn: Varnode;
    if (vn1 !== vn2) {
      const mp = new MergePair(vn1, vn2);
      const entry = this.mergeneed.get(mp.toKey());
      vn = entry!.result;
    } else {
      vn = vn1;
    }
    this.data.opSetInput(this.cbranch1!, vn, 1);
    this.data.opDestroy(this.cbranch2!);
  }

  /** Test blocks for the merge condition */
  match(b1: BlockBasic, b2: BlockBasic): boolean {
    this.block1 = b1;
    this.block2 = b2;
    if (this.block2 === this.block1) return false;
    if (this.block1.sizeOut() !== 2) return false;
    if (this.block2.sizeOut() !== 2) return false;
    this.exita = this.block1.getOut(0) as BlockBasic;
    this.exitb = this.block1.getOut(1) as BlockBasic;
    if (this.exita === this.exitb) return false;
    if (this.block2.getOut(0) !== this.exita) return false;
    if (this.block2.getOut(1) !== this.exitb) return false;
    this.a_in2 = this.block2.getOutRevIndex(0);
    this.b_in2 = this.block2.getOutRevIndex(1);
    this.a_in1 = this.block1.getOutRevIndex(0);
    this.b_in1 = this.block1.getOutRevIndex(1);

    if (!this.findDups()) {
      this.clear();
      return false;
    }
    this.checkExitBlock(this.exita!, this.a_in1, this.a_in2);
    this.checkExitBlock(this.exitb!, this.b_in1, this.b_in2);
    return true;
  }

  /** Execute the merge */
  execute(): void {
    this.joinblock = this.data.nodeJoinCreateBlock(
      this.block1!, this.block2!, this.exita!, this.exitb!,
      (this.a_in1 > this.a_in2), (this.b_in1 > this.b_in2),
      this.cbranch1!.getAddr()
    );
    this.setupMultiequals();
    this.moveCbranch();
    this.cutDownMultiequals(this.exita!, this.a_in1, this.a_in2);
    this.cutDownMultiequals(this.exitb!, this.b_in1, this.b_in2);
  }

  /** Clear for a new test */
  clear(): void {
    this.mergeneed.clear();
  }

  /**
   * Helper to iterate over PcodeOps in a block.
   * This produces a snapshot so modification during iteration is safe.
   */
  private static iterateOps(block: BlockBasic): PcodeOp[] {
    const ops: PcodeOp[] = [];
    let iter = block.beginOp();
    const end = block.endOp();
    // Assume beginOp/endOp return iterable or array-like
    // In practice this would use the block's op list
    return ops;
  }
}

// ---------------------------------------------------------------------------
// Action subclasses
// ---------------------------------------------------------------------------

/**
 * Give each control-flow structure an opportunity to make a final transform.
 * This is currently used to set up for loops via BlockWhileDo.
 */
export class ActionStructureTransform extends Action {
  constructor(g: string) {
    super(0, 'structuretransform', g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionStructureTransform(this.getGroup());
  }

  apply(data: Funcdata): number {
    data.getStructure().finalTransform(data);
    return 0;
  }
}

/**
 * Flip conditional control-flow so that preferred comparison operators are used.
 */
export class ActionNormalizeBranches extends Action {
  constructor(g: string) {
    super(0, 'normalizebranches', g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionNormalizeBranches(this.getGroup());
  }

  apply(data: Funcdata): number {
    const graph: BlockGraph = data.getBasicBlocks();
    const fliplist: PcodeOp[] = [];

    for (let i = 0; i < graph.getSize(); ++i) {
      const bb: BlockBasic = graph.getBlock(i) as BlockBasic;
      if (bb.sizeOut() !== 2) continue;
      const cbranch: PcodeOp | null = bb.lastOp();
      if (cbranch === null) continue;
      if (cbranch.code() !== CPUI_CBRANCH) continue;
      fliplist.length = 0;
      if ((data.constructor as any).opFlipInPlaceTest(cbranch, fliplist) !== 0)
        continue;
      data.opFlipInPlaceExecute(fliplist);
      bb.flipInPlaceExecute();
      this.count += 1;
    }
    data.clearDeadOps();
    return 0;
  }
}

/**
 * Attempt to normalize symmetric block structures.
 */
export class ActionPreferComplement extends Action {
  constructor(g: string) {
    super(0, 'prefercomplement', g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionPreferComplement(this.getGroup());
  }

  apply(data: Funcdata): number {
    const graph: BlockGraph = data.getStructure();

    if (graph.getSize() === 0) return 0;
    const vec: BlockGraph[] = [];
    vec.push(graph);
    let pos: number = 0;

    while (pos < vec.length) {
      const curbl: BlockGraph = vec[pos];
      let bt: number;
      pos += 1;
      const sz: number = curbl.getSize();
      for (let i = 0; i < sz; ++i) {
        const childbl: FlowBlock = curbl.getBlock(i);
        bt = childbl.getType();
        if ((bt === block_type.t_copy) || (bt === block_type.t_basic))
          continue;
        vec.push(childbl as BlockGraph);
      }
      if (curbl.preferComplement(data))
        this.count += 1;
    }
    data.clearDeadOps();
    return 0;
  }
}

/**
 * Structure control-flow using standard high-level code constructs.
 */
export class ActionBlockStructure extends Action {
  constructor(g: string) {
    super(0, 'blockstructure', g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionBlockStructure(this.getGroup());
  }

  apply(data: Funcdata): number {
    const graph: BlockGraph = data.getStructure();

    // Check if already structured
    if (graph.getSize() !== 0) return 0;
    data.installSwitchDefaults();
    graph.buildCopy(data.getBasicBlocks());

    const collapse = new CollapseStructure(graph);
    collapse.collapseAll();
    this.count += collapse.getChangeCount();

    return 0;
  }
}

/**
 * Perform final organization of the control-flow structure.
 */
export class ActionFinalStructure extends Action {
  constructor(g: string) {
    super(0, 'finalstructure', g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionFinalStructure(this.getGroup());
  }

  apply(data: Funcdata): number {
    const graph: BlockGraph = data.getStructure();

    graph.orderBlocks();
    graph.finalizePrinting(data);
    graph.scopeBreak(-1, -1);
    graph.markUnstructured();
    graph.markLabelBumpUp(false);
    return 0;
  }
}

/**
 * Split the epilog code of the function.
 */
export class ActionReturnSplit extends Action {
  constructor(g: string) {
    super(0, 'returnsplit', g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionReturnSplit(this.getGroup());
  }

  /** Gather all blocks that have goto edge to a RETURN. */
  static gatherReturnGotos(parent: FlowBlock, vec: FlowBlock[]): void {
    let bl: FlowBlock | null;
    let ret: FlowBlock | null;

    for (let i = 0; i < parent.sizeIn(); ++i) {
      bl = parent.getIn(i).getCopyMap();
      while (bl !== null) {
        if (!bl.isMark()) {
          ret = null;
          if (bl.getType() === block_type.t_goto) {
            if ((bl as BlockGoto).gotoPrints())
              ret = (bl as BlockGoto).getGotoTarget();
          } else if (bl.getType() === block_type.t_if) {
            ret = (bl as BlockIf).getGotoTarget();
          }
          if (ret !== null) {
            while (ret!.getType() !== block_type.t_basic)
              ret = ret!.subBlock(0);
            if (ret === parent) {
              bl.setMark();
              vec.push(bl);
            }
          }
        }
        bl = bl.getParent();
      }
    }
  }

  /** Determine if a RETURN block can be split */
  static isSplittable(b: BlockBasic): boolean {
    let iter = b.beginOp();
    const endOp = b.endOp();
    while (!iter.equals(endOp)) {
      const op: PcodeOp = iter.get();
      iter.next();
      const opc: number = op.code();
      if (opc === CPUI_MULTIEQUAL) continue;
      if ((opc === CPUI_COPY) || (opc === CPUI_RETURN)) {
        let valid = true;
        for (let i = 0; i < op.numInput(); ++i) {
          if (op.getIn(i)!.isConstant()) continue;
          if (op.getIn(i)!.isAnnotation()) continue;
          if (op.getIn(i)!.isFree()) { valid = false; break; }
        }
        if (!valid) return false;
        continue;
      }
      return false;
    }
    return true;
  }

  apply(data: Funcdata): number {
    let op: PcodeOp;
    let parent: BlockBasic;
    let bl: FlowBlock | null;
    const splitedge: number[] = [];
    const retnode: BlockBasic[] = [];

    if (data.getStructure().getSize() === 0)
      return 0;
    const iterend = data.endOp(CPUI_RETURN);
    for (let iter = data.beginOp(CPUI_RETURN); !iter.equals(iterend); iter.next()) {
      op = iter.get();
      if (op.isDead()) continue;
      parent = op.getParent();
      if (parent.sizeIn() <= 1) continue;
      if (!ActionReturnSplit.isSplittable(parent)) continue;
      const gotoblocks: FlowBlock[] = [];
      ActionReturnSplit.gatherReturnGotos(parent, gotoblocks);
      if (gotoblocks.length === 0) continue;

      let splitcount: number = 0;
      for (let i = parent.sizeIn() - 1; i >= 0; --i) {
        bl = parent.getIn(i).getCopyMap();
        while (bl !== null) {
          if (bl.isMark()) {
            splitedge.push(i);
            retnode.push(parent);
            bl = null;
            splitcount += 1;
          } else {
            bl = bl.getParent();
          }
        }
      }

      for (let i = 0; i < gotoblocks.length; ++i)
        gotoblocks[i].clearMark();

      // Can't split ALL in edges
      if (parent.sizeIn() === splitcount) {
        splitedge.pop();
        retnode.pop();
      }
    }

    for (let i = 0; i < splitedge.length; ++i) {
      data.nodeSplit(retnode[i], splitedge[i]);
      this.count += 1;
    }
    return 0;
  }
}

/**
 * Look for conditional branch expressions that have been split and rejoin them.
 */
export class ActionNodeJoin extends Action {
  constructor(g: string) {
    super(0, 'nodejoin', g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionNodeJoin(this.getGroup());
  }

  apply(data: Funcdata): number {
    const graph: BlockGraph = data.getBasicBlocks();
    if (graph.getSize() === 0) return 0;

    const condjoin = new ConditionalJoin(data);

    for (let i = 0; i < graph.getSize(); ++i) {
      const bb: BlockBasic = graph.getBlock(i) as BlockBasic;
      if (bb.sizeOut() !== 2) continue;
      const out1: BlockBasic = bb.getOut(0) as BlockBasic;
      const out2: BlockBasic = bb.getOut(1) as BlockBasic;
      let inslot: number;
      let leastout: BlockBasic;
      if (out1.sizeIn() < out2.sizeIn()) {
        leastout = out1;
        inslot = bb.getOutRevIndex(0);
      } else {
        leastout = out2;
        inslot = bb.getOutRevIndex(1);
      }
      if (leastout.sizeIn() === 1) continue;

      for (let j = 0; j < leastout.sizeIn(); ++j) {
        if (j === inslot) continue;
        const bb2: BlockBasic = leastout.getIn(j) as BlockBasic;
        if (condjoin.match(bb, bb2)) {
          this.count += 1;
          condjoin.execute();
          condjoin.clear();
          break;
        }
      }
    }
    return 0;
  }
}
