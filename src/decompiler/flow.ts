/**
 * @file flow.ts
 * @description Utilities for following control-flow in p-code generated from machine instructions.
 *
 * Translated from Ghidra's flow.hh / flow.cc
 */

import { Address, SeqNum } from '../core/address.js';
import { OpCode } from '../core/opcodes.js';
import { LowlevelError, RecovError } from '../core/error.js';
import { UnimplError, BadDataError } from '../core/translate.js';
import { DataUnavailError } from './loadimage.js';
import { PcodeOp, PcodeOpBank } from './op.js';
import type { FlowBlock, BlockGraph } from './block.js';

type BlockBasic = any;

// ---------------------------------------------------------------------------
// Forward type declarations for types from not-yet-written modules
// ---------------------------------------------------------------------------

type Funcdata = any;
type Architecture = any;
type FuncCallSpecs = any;
import { PcodeEmitFd } from './funcdata.js';
type JumpTable = any;
type InjectPayload = any;
type InjectContext = any;
type Varnode = any;
type Override = any;
type FunctionSymbol = any;
type InjectedUserOp = any;
type UserPcodeOp = any;

// ---------------------------------------------------------------------------
// VisitStat -- helper describing bytes in a machine instruction and starting p-code op
// ---------------------------------------------------------------------------

/**
 * A helper structure describing the number of bytes in a machine instruction
 * and the starting p-code op.
 */
class VisitStat {
  /** Sequence number of first PcodeOp in the instruction (or INVALID if no p-code) */
  seqnum: SeqNum;
  /** Number of bytes in the instruction */
  size: number;

  constructor() {
    this.seqnum = new SeqNum();
    this.size = 0;
  }
}

// ---------------------------------------------------------------------------
// FlowInfo
// ---------------------------------------------------------------------------

/**
 * A class for generating the control-flow structure for a single function.
 *
 * Control-flow for the function is generated in two phases: the method generateOps() produces
 * all the raw p-code ops for the function, and the method generateBlocks() organizes the
 * p-code ops into basic blocks (PcodeBlockBasic).
 *
 * In generateOps(), p-code is generated for every machine instruction that is reachable starting
 * with the entry point address of the function. All possible flow is followed, trimming flow
 * at instructions that end with the formal RETURN p-code operation. CALL and CALLIND are treated
 * as fall-through operations, and flow is not followed into the sub-function.
 *
 * The class supports various options for handling corner cases during the flow following process,
 * including how to handle:
 *   - Flow out of range (specified by setRange())
 *   - Flow into unimplemented instructions
 *   - Flow into unaccessible data
 *   - Flow into previously traversed data at an off cut (reinterpreted data)
 *   - Flow that (seemingly) doesn't end, exceeding a threshold on the number of instructions
 *
 * In generateBlocks(), all previously generated PcodeOp instructions are assigned to a
 * PcodeBlockBasic. These objects define the formal basic block structure of the function.
 * Directed control-flow edges between the blocks are created at this time based on the
 * flow of p-code.
 */
export class FlowInfo {
  // ----- Public flag constants (enum) -----

  /** Ignore/truncate flow into addresses out of the specified range */
  static readonly ignore_outofbounds = 1;
  /** Treat unimplemented instructions as a NOP (no operation) */
  static readonly ignore_unimplemented = 2;
  /** Throw an exception for flow into addresses out of the specified range */
  static readonly error_outofbounds = 4;
  /** Throw an exception for flow into unimplemented instructions */
  static readonly error_unimplemented = 8;
  /** Throw an exception for flow into previously encountered data at a different cut */
  static readonly error_reinterpreted = 0x10;
  /** Throw an exception if too many instructions are encountered */
  static readonly error_toomanyinstructions = 0x20;
  /** Indicate we have encountered unimplemented instructions */
  static readonly unimplemented_present = 0x40;
  /** Indicate we have encountered flow into unaccessible data */
  static readonly baddata_present = 0x80;
  /** Indicate we have encountered flow out of the specified range */
  static readonly outofbounds_present = 0x100;
  /** Indicate we have encountered reinterpreted data */
  static readonly reinterpreted_present = 0x200;
  /** Indicate the maximum instruction threshold was reached */
  static readonly toomanyinstructions_present = 0x400;
  /** Indicate a CALL was converted to a BRANCH and some code may be unreachable */
  static readonly possible_unreachable = 0x1000;
  /** Indicate flow is being generated to in-line (a function) */
  static readonly flow_forinline = 0x2000;
  /** Indicate that any jump table recovery should record the table structure */
  static readonly record_jumploads = 0x4000;

  // ----- Private fields -----

  /** Owner of the function */
  private glb: Architecture;
  /** The function being flow-followed */
  private data: Funcdata;
  /** Container for generated p-code */
  private obank: PcodeOpBank;
  /** Container for the control-flow graph */
  private bblocks: BlockGraph;
  /** The list of discovered sub-function call sites */
  private qlst: FuncCallSpecs[];
  /** PcodeOp factory (configured to allocate into data and obank) */
  private emitter: PcodeEmitFd;
  /** Addresses which are permanently unprocessed */
  private unprocessed: Address[];
  /** Addresses to which there is flow */
  private addrlist: Address[];
  /** List of BRANCHIND ops (preparing for jump table recovery) */
  private tablelist: PcodeOp[];
  /** List of p-code ops that need injection */
  private injectlist: (PcodeOp | null)[];
  /** Map of machine instructions that have been visited so far */
  private visited: Map<string, VisitStat>;
  /** Source p-code op (Edges between basic blocks) */
  private block_edge1: PcodeOp[];
  /** Destination p-code op (Edges between basic blocks) */
  private block_edge2: PcodeOp[];
  /** Number of instructions flowed through */
  private insn_count: number;
  /** Maximum number of instructions */
  private insn_max: number;
  /** Start of range in which we are allowed to flow */
  private baddr: Address;
  /** End of range in which we are allowed to flow */
  private eaddr: Address;
  /** Start of actual function range */
  private minaddr: Address;
  /** End of actual function range */
  private maxaddr: Address;
  /** Does the function have registered flow override instructions */
  private flowoverride_present: boolean;
  /** Boolean options for flow following */
  private flags: number;
  /** First function in the in-lining chain */
  private inline_head: Funcdata | null;
  /** Active list of addresses for functions that are in-lined */
  private inline_recursion: Set<string> | null;
  /** Storage for addresses of functions that are in-lined */
  private inline_base: Set<string>;

  // ----- Private helper methods -----

  /** Are there possible unreachable ops */
  private hasPossibleUnreachable(): boolean {
    return (this.flags & FlowInfo.possible_unreachable) !== 0;
  }

  /** Mark that there may be unreachable ops */
  private setPossibleUnreachable(): void {
    this.flags |= FlowInfo.possible_unreachable;
  }

  /** Clear any discovered flow properties */
  private clearProperties(): void {
    this.flags &= ~(FlowInfo.unimplemented_present | FlowInfo.baddata_present | FlowInfo.outofbounds_present);
    this.insn_count = 0;
  }

  /** Has the given instruction (address) been seen in flow */
  private seenInstruction(addr: Address): boolean {
    return this.visited.has(FlowInfo.addrKey(addr));
  }

  /**
   * Generate a map key from an Address.
   * We use a string key composed of the space index and offset for Map lookups.
   */
  private static addrKey(addr: Address): string {
    const space = addr.getSpace();
    if (space === null || space === undefined) return 'invalid';
    const idx = typeof space.getIndex === 'function' ? space.getIndex() : (space as any).index ?? -1;
    return `${idx}:${addr.getOffset().toString(16)}`;
  }

  /**
   * Find fallthru pcode-op for given op.
   * For efficiency, this method assumes the given op can actually fall-thru.
   * @param op is the given PcodeOp
   * @returns the PcodeOp that fall-thru flow would reach (or null if there is no possible p-code op)
   */
  private fallthruOp(op: PcodeOp): PcodeOp | null {
    let iter = op.getInsertIter();
    iter++;
    if (iter < this.obank.endDead()) {
      const retop = this.obank.getDeadOp(iter);
      if (!retop.isInstructionStart()) { // If within same instruction
        return retop; // Then this is the fall thru
      }
    }
    // Find address of instruction containing this op
    const containingAddr = this.findContainingInstruction(op.getAddr());
    if (containingAddr === null) return null;
    const stat = this.visited.get(FlowInfo.addrKey(containingAddr))!;
    return this.target(containingAddr.add(BigInt(stat.size)));
  }

  /**
   * Find the instruction address that contains the given address (using visited map upper_bound logic).
   */
  private findContainingInstruction(addr: Address): Address | null {
    // Emulate C++ map::upper_bound then decrement
    let best: { addr: Address; stat: VisitStat } | null = null;
    for (const [key, stat] of this.visited) {
      const parts = key.split(':');
      if (parts[0] === 'invalid') continue;
      const visitAddr = this.reconstructAddr(key);
      if (visitAddr === null) continue;
      // We want the last entry whose address <= addr
      if (!visitAddr.lessThan(addr) && !visitAddr.equals(addr)) continue;
      if (best === null || best.addr.lessThan(visitAddr)) {
        best = { addr: visitAddr, stat };
      }
    }
    if (best === null) return null;
    // Check that addr falls within this instruction
    if (best.addr.add(BigInt(best.stat.size)).lessThan(addr) ||
        best.addr.add(BigInt(best.stat.size)).equals(addr)) {
      // addr is past the instruction
      if (addr.equals(best.addr.add(BigInt(best.stat.size)))) {
        // addr is exactly at the end of the instruction -- this is outside
      }
      return null;
    }
    return best.addr;
  }

  /**
   * Reconstruct an Address from a map key string.
   * The key has format "spaceIndex:offsetHex".
   * This is a helper for iteration over the visited map.
   */
  private reconstructAddr(key: string): Address | null {
    // We store the full address in a parallel structure for iteration
    // This is a simplification -- we rely on the visitedAddrs array
    return this.visitedAddrsMap.get(key) ?? null;
  }

  /** Parallel map from key string to actual Address objects for reconstruction */
  private visitedAddrsMap: Map<string, Address> = new Map();

  /**
   * Store a VisitStat in the visited map, also recording the Address for reverse lookup.
   */
  private visitedSet(addr: Address, stat: VisitStat): void {
    const key = FlowInfo.addrKey(addr);
    this.visited.set(key, stat);
    this.visitedAddrsMap.set(key, new Address(addr));
  }

  /**
   * Get a VisitStat from the visited map, creating it if necessary.
   */
  private visitedGetOrCreate(addr: Address): VisitStat {
    const key = FlowInfo.addrKey(addr);
    let stat = this.visited.get(key);
    if (stat === undefined) {
      stat = new VisitStat();
      this.visited.set(key, stat);
      this.visitedAddrsMap.set(key, new Address(addr));
    }
    return stat;
  }

  /**
   * Find a VisitStat in the visited map.
   */
  private visitedFind(addr: Address): VisitStat | undefined {
    return this.visited.get(FlowInfo.addrKey(addr));
  }

  /**
   * Get all visited entries sorted by address, for upper_bound-style operations.
   * Returns an array of [Address, VisitStat] sorted by address.
   */
  private getVisitedSorted(): Array<[Address, VisitStat]> {
    const entries: Array<[Address, VisitStat]> = [];
    for (const [key, stat] of this.visited) {
      const addr = this.visitedAddrsMap.get(key);
      if (addr) {
        entries.push([addr, stat]);
      }
    }
    entries.sort((a, b) => {
      if (a[0].equals(b[0])) return 0;
      return a[0].lessThan(b[0]) ? -1 : 1;
    });
    return entries;
  }

  /**
   * Perform upper_bound on visited map: find first entry with address strictly greater than addr.
   * Returns [index, sortedEntries] where index is the position of the upper_bound.
   */
  private visitedUpperBound(addr: Address): { index: number; entries: Array<[Address, VisitStat]> } {
    const entries = this.getVisitedSorted();
    // Binary search for first entry > addr
    let lo = 0;
    let hi = entries.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (entries[mid][0].lessThan(addr) || entries[mid][0].equals(addr)) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    return { index: lo, entries };
  }

  /**
   * Register a new (non fall-thru) flow target.
   * Check to see if the new target has been seen before. Otherwise
   * add it to the list of addresses that need to be processed.
   * Also check range bounds and update basic block information.
   * @param from is the PcodeOp issuing the branch
   * @param to is the target address of the branch
   */
  private newAddress(from: PcodeOp, to: Address): void {
    if (to.lessThan(this.baddr) || this.eaddr.lessThan(to)) {
      this.handleOutOfBounds(from.getAddr(), to);
      this.unprocessed.push(to);
      return;
    }

    if (this.seenInstruction(to)) { // If we have seen this address before
      const op = this.target(to);
      this.data.opMarkStartBasic(op);
      return;
    }
    this.addrlist.push(to);
  }

  /**
   * Delete any remaining ops at the end of the instruction
   * (because they have been predetermined to be dead).
   * @param oiter is the point within the raw p-code list where deletion should start
   */
  private deleteRemainingOps(oiter: number): void {
    // Collect ops to destroy first, since opDestroyRaw modifies deadlist via splice
    const toDestroy: PcodeOp[] = [];
    for (let i = oiter; i < this.obank.endDead(); i++) {
      toDestroy.push(this.obank.getDeadOp(i));
    }
    for (const op of toDestroy) {
      this.data.opDestroyRaw(op);
    }
  }

  /**
   * Analyze control-flow within p-code for a single instruction.
   *
   * Walk through the raw p-code (from the given iterator to the end of the list)
   * looking for control flow operations and add appropriate annotations.
   * @param oiter is the given iterator starting the list of p-code ops
   * @param startbasic holds whether the current op starts a basic block (modified in place)
   * @param fc if the p-code is generated from an injection, this holds the reference to the injecting sub-function
   * @returns [lastOp, startbasic, isfallthru]
   */
  private xrefControlFlow(
    oiter: number,
    startbasic: boolean,
    fc: FuncCallSpecs | null
  ): { lastOp: PcodeOp | null; startbasic: boolean; isfallthru: boolean } {
    let op: PcodeOp | null = null;
    let isfallthru = false;
    let maxtime = 0; // Deepest internal relative branch

    while (oiter < this.obank.endDead()) {
      op = this.obank.getDeadOp(oiter);
      oiter++;
      if (startbasic) {
        this.data.opMarkStartBasic(op);
        startbasic = false;
      }
      switch (op.code()) {
        case OpCode.CPUI_CBRANCH: {
          const destaddr: Address = op.getIn(0)!.getAddr();
          if (destaddr.isConstant()) {
            const fallThruAddr = new Address();
            const destop = this.findRelTarget(op, fallThruAddr);
            if (destop !== null) {
              this.data.opMarkStartBasic(destop); // Make sure the target op is a basic block start
              const newtime = destop.getTime();
              if (newtime > maxtime) maxtime = newtime;
            } else {
              isfallthru = true; // Relative branch is to end of instruction
            }
          } else {
            this.newAddress(op, destaddr); // Generate branch address
          }
          startbasic = true;
          break;
        }
        case OpCode.CPUI_BRANCH: {
          const destaddr: Address = op.getIn(0)!.getAddr();
          if (destaddr.isConstant()) {
            const fallThruAddr = new Address();
            const destop = this.findRelTarget(op, fallThruAddr);
            if (destop !== null) {
              this.data.opMarkStartBasic(destop); // Make sure the target op is a basic block start
              const newtime = destop.getTime();
              if (newtime > maxtime) maxtime = newtime;
            } else {
              isfallthru = true; // Relative branch is to end of instruction
            }
          } else {
            this.newAddress(op, destaddr); // Generate branch address
          }
          if (op.getTime() >= maxtime) {
            this.deleteRemainingOps(oiter);
            oiter = this.obank.endDead();
          }
          startbasic = true;
          break;
        }
        case OpCode.CPUI_BRANCHIND:
          this.tablelist.push(op); // Put off trying to recover the table
          if (op.getTime() >= maxtime) {
            this.deleteRemainingOps(oiter);
            oiter = this.obank.endDead();
          }
          startbasic = true;
          break;
        case OpCode.CPUI_RETURN:
          if (op.getTime() >= maxtime) {
            this.deleteRemainingOps(oiter);
            oiter = this.obank.endDead();
          }
          startbasic = true;
          break;
        case OpCode.CPUI_CALL:
          if (this.setupCallSpecs(op, fc)) {
            oiter--; // Backup one op, to pickup halt
          }
          break;
        case OpCode.CPUI_CALLIND:
          if (this.setupCallindSpecs(op, fc)) {
            oiter--; // Backup one op, to pickup halt
          }
          break;
        case OpCode.CPUI_CALLOTHER: {
          if (this.glb.userops.getOp(Number(op.getIn(0)!.getOffset())).getType() === 2 /* UserPcodeOp.injected */) {
            this.injectlist.push(op);
          }
          break;
        }
        default:
          break;
      }
    }
    if (isfallthru) {
      // We have seen an explicit relative branch to end of instruction
      startbasic = true; // So we know next instruction starts a basicblock
    } else {
      // If we haven't seen a relative branch, calculate fallthru by looking at last op
      if (op === null) {
        isfallthru = true; // No ops at all, mean a fallthru
      } else {
        switch (op.code()) {
          case OpCode.CPUI_BRANCH:
          case OpCode.CPUI_BRANCHIND:
          case OpCode.CPUI_RETURN:
            break; // If the last instruction is a branch, then no fallthru
          default:
            isfallthru = true; // otherwise it is a fallthru
            break;
        }
      }
    }
    return { lastOp: op, startbasic, isfallthru };
  }

  /**
   * Generate p-code for a single machine instruction and process discovered flow information.
   *
   * @param curaddr is the address of the instruction to process
   * @param startbasic indicates if the instruction starts a basic block
   * @returns [isfallthru, startbasic] -- whether the instruction falls thru and the updated startbasic
   */
  private processInstruction(curaddr: Address, startbasic: boolean): { isfallthru: boolean; startbasic: boolean } {
    let emptyflag: boolean;
    let isfallthru = true;
    let oiter: number;
    let step: number;
    let flowoverride: number;

    if (this.insn_count >= this.insn_max) {
      if ((this.flags & FlowInfo.error_toomanyinstructions) !== 0) {
        throw new LowlevelError("Flow exceeded maximum allowable instructions");
      } else {
        step = 1;
        this.artificialHalt(curaddr, PcodeOp.badinstruction);
        this.data.warning("Too many instructions -- Truncating flow here", curaddr);
        if (!this.hasTooManyInstructions()) {
          this.flags |= FlowInfo.toomanyinstructions_present;
          this.data.warningHeader("Exceeded maximum allowable instructions: Some flow is truncated");
        }
      }
    }
    this.insn_count += 1;

    if (this.obank.empty()) {
      emptyflag = true;
      oiter = 0;
    } else {
      emptyflag = false;
      oiter = this.obank.endDead() - 1;
    }
    if (this.flowoverride_present) {
      flowoverride = this.data.getOverride().getFlowOverride(curaddr);
    } else {
      flowoverride = 0; // Override::NONE
    }

    try {
      step = this.glb.translate.oneInstruction(this.emitter, curaddr); // Generate ops for instruction
    } catch (err: any) {
      if (err instanceof UnimplError) {
        if ((this.flags & FlowInfo.ignore_unimplemented) !== 0) {
          step = err.instruction_length;
          if (!this.hasUnimplemented()) {
            this.flags |= FlowInfo.unimplemented_present;
            this.data.warningHeader("Control flow ignored unimplemented instructions");
          }
        } else if ((this.flags & FlowInfo.error_unimplemented) !== 0) {
          throw err; // rethrow
        } else {
          // Add infinite loop instruction
          step = 1; // Pretend size 1
          this.artificialHalt(curaddr, PcodeOp.unimplemented);
          this.data.warning("Unimplemented instruction - Truncating control flow here", curaddr);
          if (!this.hasUnimplemented()) {
            this.flags |= FlowInfo.unimplemented_present;
            this.data.warningHeader("Control flow encountered unimplemented instructions");
          }
        }
      } else if (err instanceof BadDataError || err instanceof DataUnavailError) {
        if ((this.flags & FlowInfo.error_unimplemented) !== 0) {
          throw err; // rethrow
        } else {
          // Add infinite loop instruction
          step = 1; // Pretend size 1
          this.artificialHalt(curaddr, PcodeOp.badinstruction);
          this.data.warning("Bad instruction - Truncating control flow here", curaddr);
          if (!this.hasBadData()) {
            this.flags |= FlowInfo.baddata_present;
            this.data.warningHeader("Control flow encountered bad instruction data");
          }
        }
      } else {
        throw err;
      }
    }

    const stat = this.visitedGetOrCreate(curaddr); // Mark that we visited this instruction
    stat.size = step!; // Record size of instruction

    if (curaddr.lessThan(this.minaddr)) { // Update minimum and maximum address
      this.minaddr = new Address(curaddr);
    }
    if (this.maxaddr.lessThan(curaddr.add(BigInt(step!)))) { // Keep track of biggest and smallest address
      this.maxaddr = curaddr.add(BigInt(step!));
    }

    if (emptyflag) { // Make sure oiter points at first new op
      oiter = this.obank.beginDead();
    } else {
      oiter++;
    }

    if (oiter < this.obank.endDead()) {
      const firstOp = this.obank.getDeadOp(oiter);
      stat.seqnum = firstOp.getSeqNum();
      this.data.opMarkStartInstruction(firstOp); // Mark the first op in the instruction
      if (flowoverride !== 0 /* Override::NONE */) {
        this.data.overrideFlow(curaddr, flowoverride);
      }
      const result = this.xrefControlFlow(oiter, startbasic, null);
      startbasic = result.startbasic;
      isfallthru = result.isfallthru;
    }

    if (isfallthru) {
      this.addrlist.push(curaddr.add(BigInt(step!)));
    }
    return { isfallthru, startbasic };
  }

  /**
   * The address at the top of the addrlist stack that still needs processing is popped.
   * P-code is generated for instructions starting at this address until
   * one no longer has fall-thru flow (or some other error occurs).
   */
  private fallthru(): void {
    const bound = { addr: new Address() };

    if (!this.setFallthruBound(bound)) return;

    let curaddr: Address;
    let startbasic = true;
    let fallthruflag: boolean;

    for (;;) {
      curaddr = this.addrlist[this.addrlist.length - 1];
      this.addrlist.pop();
      const result = this.processInstruction(curaddr, startbasic);
      fallthruflag = result.isfallthru;
      startbasic = result.startbasic;
      if (!fallthruflag) break;
      if (this.addrlist.length === 0) break;
      const nextAddr = this.addrlist[this.addrlist.length - 1];
      if (!nextAddr.lessThan(bound.addr)) {
        // bound <= addrlist.back()
        if (bound.addr.equals(this.eaddr)) {
          this.handleOutOfBounds(this.eaddr, nextAddr);
          this.unprocessed.push(nextAddr);
          this.addrlist.pop();
          return;
        }
        if (bound.addr.equals(nextAddr)) { // Hit the bound exactly
          if (startbasic) {
            const op = this.target(nextAddr);
            this.data.opMarkStartBasic(op);
          }
          this.addrlist.pop();
          break;
        }
        if (!this.setFallthruBound(bound)) return; // Reset bound
      }
    }
  }

  /**
   * Generate the target PcodeOp for a relative branch.
   *
   * Assuming the given op is a relative branch, find the existing target PcodeOp if the
   * branch is properly internal, or return the fall-thru address in res (which may not have
   * PcodeOps generated for it yet) if the relative branch is really a branch to the next instruction.
   * Otherwise an exception is thrown.
   * @param op is the given branching p-code op
   * @param res is a reference to the fall-thru address being passed back
   * @returns the target PcodeOp or null if the fall-thru address is passed back instead
   */
  private findRelTarget(op: PcodeOp, res: Address): PcodeOp | null {
    const addr: Address = op.getIn(0)!.getAddr();
    const id = op.getTime() + Number(addr.getOffset());
    const seqnum = new SeqNum(op.getAddr(), id);
    let retop = this.obank.findOp(seqnum);
    if (retop !== null) { // Is this a "properly" internal branch
      return retop;
    }

    // Now we check if the relative branch is really to the next instruction
    const seqnum1 = new SeqNum(op.getAddr(), id - 1);
    retop = this.obank.findOp(seqnum1); // We go back one sequence number
    if (retop !== null) {
      // If the PcodeOp exists here then branch was indeed to next instruction
      const ub = this.visitedUpperBound(retop.getAddr());
      if (ub.index > 0) {
        const entry = ub.entries[ub.index - 1];
        const fallAddr = entry[0].add(BigInt(entry[1].size));
        if (op.getAddr().lessThan(fallAddr)) {
          res.assign(fallAddr);
          return null; // Indicate that res has the fallthru address
        }
      }
    }
    const errmsg =
      `Bad relative branch at instruction : (${op.getAddr().getSpace()!.getName()},${op.getAddr().printRaw()})`;
    throw new LowlevelError(errmsg);
  }

  /**
   * Add any remaining un-followed addresses to the unprocessed list.
   */
  private findUnprocessed(): void {
    for (const addr of this.addrlist) {
      if (this.seenInstruction(addr)) {
        const op = this.target(addr);
        this.data.opMarkStartBasic(op);
      } else {
        this.unprocessed.push(addr);
      }
    }
  }

  /** Get rid of duplicates in the unprocessed list (also sorts it). */
  private dedupUnprocessed(): void {
    if (this.unprocessed.length === 0) return;
    this.unprocessed.sort((a, b) => {
      if (a.equals(b)) return 0;
      return a.lessThan(b) ? -1 : 1;
    });
    const deduped: Address[] = [this.unprocessed[0]];
    for (let i = 1; i < this.unprocessed.length; i++) {
      if (!this.unprocessed[i].equals(deduped[deduped.length - 1])) {
        deduped.push(this.unprocessed[i]);
      }
    }
    this.unprocessed = deduped;
  }

  /**
   * Fill-in artificial HALT p-code for unprocessed addresses.
   * A special form of RETURN instruction is generated for every address in
   * the unprocessed list.
   */
  private fillinBranchStubs(): void {
    this.findUnprocessed();
    this.dedupUnprocessed();
    for (const addr of this.unprocessed) {
      const op = this.artificialHalt(addr, PcodeOp.missing);
      this.data.opMarkStartBasic(op);
      this.data.opMarkStartInstruction(op);
    }
  }

  /**
   * Collect edges between basic blocks as PcodeOp to PcodeOp pairs.
   * An edge is held as matching PcodeOp entries in block_edge1 and block_edge2.
   */
  private collectEdges(): void {
    let op: PcodeOp;
    let targ_op: PcodeOp;
    let jt: JumpTable;
    let nextstart: boolean;

    if (this.bblocks.getSize() !== 0) {
      throw new RecovError("Basic blocks already calculated\n");
    }

    // Snapshot the dead list since it may be modified during iteration
    const deadOps: PcodeOp[] = [];
    for (let i = this.obank.beginDead(); i < this.obank.endDead(); i++) {
      deadOps.push(this.obank.getDeadOp(i));
    }
    let iter = 0;
    const iterend = deadOps.length;
    while (iter < iterend) {
      op = deadOps[iter];
      iter++;
      if (iter === iterend) {
        nextstart = true;
      } else {
        nextstart = deadOps[iter].isBlockStart();
      }
      switch (op.code()) {
        case OpCode.CPUI_BRANCH:
          targ_op = this.branchTarget(op);
          this.block_edge1.push(op);
          this.block_edge2.push(targ_op);
          break;
        case OpCode.CPUI_BRANCHIND:
          jt = this.data.findJumpTable(op);
          if (jt === null) break;
          // If we are in this routine and there is no table
          // Then we must be doing partial flow analysis
          // so assume there are no branches out
          {
            const num = jt.numEntries();
            for (let i = 0; i < num; i++) {
              targ_op = this.target(jt.getAddressByIndex(i));
              if (targ_op.isMark()) continue; // Already a link between these blocks
              targ_op.setMark();
              this.block_edge1.push(op);
              this.block_edge2.push(targ_op);
            }
            // Clean up our marks
            let e1idx = this.block_edge1.length;
            let e2idx = this.block_edge2.length;
            while (e1idx > 0) {
              e1idx--;
              e2idx--;
              if (this.block_edge1[e1idx] === op) {
                this.block_edge2[e2idx].clearMark();
              } else {
                break;
              }
            }
          }
          break;
        case OpCode.CPUI_RETURN:
          break;
        case OpCode.CPUI_CBRANCH:
          targ_op = this.fallthruOp(op)!; // Put in fallthru edge
          this.block_edge1.push(op);
          this.block_edge2.push(targ_op);
          targ_op = this.branchTarget(op);
          this.block_edge1.push(op);
          this.block_edge2.push(targ_op);
          break;
        default:
          if (nextstart) { // Put in fallthru edge if new basic block
            targ_op = this.fallthruOp(op)!;
            this.block_edge1.push(op);
            this.block_edge2.push(targ_op);
          }
          break;
      }
    }
  }

  /**
   * Split raw p-code ops up into basic blocks.
   * PcodeOp objects are moved out of the PcodeOpBank dead list into their
   * assigned PcodeBlockBasic.
   */
  private splitBasic(): void {
    let op: PcodeOp;
    let cur: BlockBasic;

    // Snapshot the dead list since opInsert removes ops from it
    const deadOps: PcodeOp[] = [];
    for (let i = this.obank.beginDead(); i < this.obank.endDead(); i++) {
      deadOps.push(this.obank.getDeadOp(i));
    }
    if (deadOps.length === 0) return;

    op = deadOps[0];
    if (!op.isBlockStart()) {
      throw new LowlevelError("First op not marked as entry point");
    }
    cur = this.bblocks.newBlockBasic(this.data);
    this.data.opInsert(op, cur, cur.endOp());
    this.bblocks.setStartBlock(cur);
    let start = new Address(op.getAddr());
    let stop = new Address(start);
    for (let i = 1; i < deadOps.length; i++) {
      op = deadOps[i];
      if (op.isBlockStart()) {
        this.data.setBasicBlockRange(cur, start, stop);
        cur = this.bblocks.newBlockBasic(this.data); // Set up the next basic block
        start = new Address(op.getSeqNum().getAddr());
        stop = new Address(start);
      } else {
        const nextAddr = op.getAddr();
        if (stop.lessThan(nextAddr)) {
          stop = new Address(nextAddr);
        }
      }
      this.data.opInsert(op, cur, cur.endOp());
    }
    this.data.setBasicBlockRange(cur, start, stop);
  }

  /**
   * Generate edges between basic blocks.
   * Directed edges between the PcodeBlockBasic objects are created based on the
   * previously collected p-code op pairs in block_edge1 and block_edge2.
   */
  private connectBasic(): void {
    for (let i = 0; i < this.block_edge1.length; i++) {
      const op = this.block_edge1[i];
      const targ_op = this.block_edge2[i];
      const bs: BlockBasic = op.getParent();
      const targ_bs: BlockBasic = targ_op.getParent();
      this.bblocks.addEdge(bs, targ_bs);
    }
  }

  /**
   * Find end of the next unprocessed region.
   * From the address at the top of the addrlist stack, figure out how far we
   * could follow fall-thru instructions before hitting something we've already seen.
   * @param bound passes back the first address encountered that we have already seen
   * @returns false if the address has already been visited
   */
  private setFallthruBound(bound: { addr: Address }): boolean {
    const addr = this.addrlist[this.addrlist.length - 1];

    const ub = this.visitedUpperBound(addr);
    let idx = ub.index;
    const entries = ub.entries;

    if (idx > 0) {
      const prev = entries[idx - 1];
      if (addr.equals(prev[0])) { // If we have already visited this address
        const op = this.target(addr); // But make sure the address
        this.data.opMarkStartBasic(op); // starts a basic block
        this.addrlist.pop(); // Throw it away
        return false;
      }
      if (addr.lessThan(prev[0].add(BigInt(prev[1].size)))) {
        this.reinterpreted(addr);
      }
    }
    if (idx < entries.length) { // What's the maximum distance we can go
      bound.addr = new Address(entries[idx][0]);
    } else {
      bound.addr = new Address(this.eaddr);
    }
    return true;
  }

  /**
   * Generate warning message or throw exception for given flow that is out of bounds.
   * @param fromaddr is the source address of the flow (presumably in bounds)
   * @param toaddr is the given destination address that is out of bounds
   */
  private handleOutOfBounds(fromaddr: Address, toaddr: Address): void {
    if ((this.flags & FlowInfo.ignore_outofbounds) === 0) {
      let errmsg = "Function flow out of bounds: ";
      errmsg += fromaddr.getShortcut();
      errmsg += fromaddr.printRaw();
      errmsg += " flows to ";
      errmsg += toaddr.getShortcut();
      errmsg += toaddr.printRaw();
      if ((this.flags & FlowInfo.error_outofbounds) === 0) {
        this.data.warning(errmsg, toaddr);
        if (!this.hasOutOfBounds()) {
          this.flags |= FlowInfo.outofbounds_present;
          this.data.warningHeader("Function flows out of bounds");
        }
      } else {
        throw new LowlevelError(errmsg);
      }
    }
  }

  /**
   * Create an artificial halt p-code op.
   * An artificial halt is a special form of RETURN op.
   * @param addr is the target address for the new p-code op
   * @param flag is the desired type (badinstruction, unimplemented, missing, noreturn)
   * @returns the new p-code op
   */
  private artificialHalt(addr: Address, flag: number): PcodeOp {
    const haltop = this.data.newOp(1, addr);
    this.data.opSetOpcode(haltop, OpCode.CPUI_RETURN);
    this.data.opSetInput(haltop, this.data.newConstant(4, 1n), 0);
    if (flag !== 0) {
      this.data.opMarkHalt(haltop, flag); // What kind of halt
    }
    return haltop;
  }

  /**
   * Generate warning message or exception for a reinterpreted address.
   * A set of bytes is reinterpreted if there are at least two
   * different interpretations of the bytes as instructions.
   * @param addr is the address of a byte previously interpreted as (the interior of) an instruction
   */
  private reinterpreted(addr: Address): void {
    const ub = this.visitedUpperBound(addr);
    if (ub.index === 0) return; // Should never happen
    const addr2 = ub.entries[ub.index - 1][0];

    let s = `Instruction at (${addr.getSpace()!.getName()},${addr.printRaw()})`;
    s += ` overlaps instruction at (${addr2.getSpace()!.getName()},${addr2.printRaw()})\n`;

    if ((this.flags & FlowInfo.error_reinterpreted) !== 0) {
      throw new LowlevelError(s);
    }

    if ((this.flags & FlowInfo.reinterpreted_present) === 0) {
      this.flags |= FlowInfo.reinterpreted_present;
      this.data.warningHeader(s);
    }
  }

  /**
   * Check for modifications to flow at a call site given the recovered FuncCallSpecs.
   * The sub-function may be in-lined or never return.
   * @param fspecs is the given call site
   * @returns true if the sub-function never returns
   */
  private checkForFlowModification(fspecs: FuncCallSpecs): boolean {
    if (fspecs.isInline()) {
      this.injectlist.push(fspecs.getOp());
    }
    if (fspecs.isNoReturn()) {
      const op = fspecs.getOp();
      const haltop = this.artificialHalt(op.getAddr(), PcodeOp.noreturn);
      this.data.opDeadInsertAfter(haltop, op);
      if (!fspecs.isInline()) {
        this.data.warning("Subroutine does not return", op.getAddr());
      }
      return true;
    }
    return false;
  }

  /**
   * Try to recover the Funcdata object corresponding to a given call.
   * If there is an explicit target address for the given call site,
   * attempt to look up the function and adjust information in the FuncCallSpecs call site object.
   * @param fspecs is the call site object
   */
  private queryCall(fspecs: FuncCallSpecs): void {
    if (!fspecs.getEntryAddress().isInvalid()) { // If this is a direct call
      const otherfunc = this.data.getScopeLocal().getParent().queryFunction(fspecs.getEntryAddress());
      if (otherfunc !== null) {
        fspecs.setFuncdata(otherfunc); // Associate the symbol with the callsite
        if (!fspecs.hasModel() || otherfunc.getFuncProto().isInline()) {
          fspecs.copyFlowEffects(otherfunc.getFuncProto());
        }
      }
    }
  }

  /**
   * Set up the FuncCallSpecs object for a new call site.
   * @param op is the given CALL op
   * @param fc is non-null if injection is in progress and a cycle check needs to be made
   * @returns true if it is discovered the sub-function never returns
   */
  private setupCallSpecs(op: PcodeOp, fc: FuncCallSpecs | null): boolean {
    const res = new (FlowInfo as any)._FuncCallSpecsCtor(op);
    this.data.opSetInput(op, this.data.newVarnodeCallSpecs(res), 0);
    this.qlst.push(res);

    this.data.getOverride().applyPrototype(this.data, res);
    this.queryCall(res);
    if (fc !== null) { // If we are already in the midst of an injection
      if (fc.getEntryAddress().equals(res.getEntryAddress())) {
        res.cancelInjectId(); // Don't allow recursion
      }
    }
    return this.checkForFlowModification(res);
  }

  /**
   * Set up the FuncCallSpecs object for a new indirect call site.
   * @param op is the given CALLIND op
   * @param fc is non-null if injection is in progress and a cycle check needs to be made
   * @returns true if it is discovered the sub-function never returns
   */
  private setupCallindSpecs(op: PcodeOp, fc: FuncCallSpecs | null): boolean {
    const res = new (FlowInfo as any)._FuncCallSpecsCtor(op);
    this.qlst.push(res);

    this.data.getOverride().applyIndirect(this.data, res);
    if (fc !== null && fc.getEntryAddress().equals(res.getEntryAddress())) {
      res.setAddress(new Address()); // Cancel any indirect override
    }
    this.data.getOverride().applyPrototype(this.data, res);
    this.queryCall(res);

    if (!res.getEntryAddress().isInvalid()) { // If we are overridden to a direct call
      // Change indirect pcode call into a normal pcode call
      this.data.opSetOpcode(op, OpCode.CPUI_CALL); // Set normal opcode
      this.data.opSetInput(op, this.data.newVarnodeCallSpecs(res), 0);
    }
    return this.checkForFlowModification(res);
  }

  /**
   * Check for control-flow in a new injected p-code op.
   * If the given injected op is a CALL, CALLIND, or BRANCHIND,
   * we need to add references to it in other flow tables.
   * @param op is the given injected p-code op
   */
  private xrefInlinedBranch(op: PcodeOp): void {
    if (op.code() === OpCode.CPUI_CALL) {
      this.setupCallSpecs(op, null);
    } else if (op.code() === OpCode.CPUI_CALLIND) {
      this.setupCallindSpecs(op, null);
    } else if (op.code() === OpCode.CPUI_BRANCHIND) {
      const jt = this.data.linkJumpTable(op);
      if (jt === null) {
        this.tablelist.push(op); // Didn't recover a jumptable
      }
    }
  }

  /**
   * Inject the given payload into this flow.
   * The injected p-code replaces the given op, and control-flow information is updated.
   * @param payload is the specific injection payload
   * @param icontext is the specific context for the injection
   * @param op is the given p-code op being replaced by the payload
   * @param fc (if non-null) is information about the call site being in-lined
   */
  private doInjection(payload: InjectPayload, icontext: InjectContext, op: PcodeOp, fc: FuncCallSpecs | null): void {
    // Create marker at current end of the deadlist
    let iter = this.obank.endDead() - 1; // There must be at least one op

    payload.inject(icontext, this.emitter); // Do the injection

    const opStartBasic = op.isBlockStart();
    iter++; // Now points to first op in the injection
    if (iter >= this.obank.endDead()) {
      throw new LowlevelError("Empty injection: " + payload.getName());
    }
    const firstop = this.obank.getDeadOp(iter);
    const result = this.xrefControlFlow(iter, opStartBasic, fc);

    if (result.startbasic) { // If the inject code does NOT fall thru
      const opInsert = op.getInsertIter();
      const nextIdx = opInsert + 1;
      if (nextIdx < this.obank.endDead()) {
        this.data.opMarkStartBasic(this.obank.getDeadOp(nextIdx)); // as start of basic block
      }
    }

    if (payload.isIncidentalCopy()) {
      this.obank.markIncidentalCopy(firstop, result.lastOp!);
    }
    this.obank.moveSequenceDead(firstop, result.lastOp!, op); // Move the injection to right after the call

    this.updateTarget(op, firstop); // Replace -op- with -firstop- in the target map
    // Get rid of the original call
    this.data.opDestroyRaw(op);
  }

  /**
   * Perform injection for a given user-defined p-code op.
   * The op must already be established as a user defined op with an associated injection.
   * @param op is the given PcodeOp
   */
  private injectUserOp(op: PcodeOp): void {
    const userop: InjectedUserOp = this.glb.userops.getOp(Number(op.getIn(0)!.getOffset()));
    const payload = this.glb.pcodeinjectlib.getPayload(userop.getInjectId());
    const icontext = this.glb.pcodeinjectlib.getCachedContext();
    icontext.clear();
    icontext.baseaddr = op.getAddr();
    icontext.nextaddr = new Address(icontext.baseaddr);
    for (let i = 1; i < op.numInput(); i++) { // Skip the first operand containing the injectid
      const vn = op.getIn(i)!;
      icontext.inputlist.push({
        space: vn.getSpace(),
        offset: vn.getOffset(),
        size: vn.getSize(),
      });
    }
    const outvn = op.getOut();
    if (outvn !== null) {
      icontext.output.push({
        space: outvn.getSpace(),
        offset: outvn.getOffset(),
        size: outvn.getSize(),
      });
    }
    this.doInjection(payload, icontext, op, null);
  }

  /**
   * In-line the sub-function at the given call site.
   * P-code is generated for the sub-function and then woven into this flow at the call site.
   * @param fc is the given call site
   * @returns true if the in-lining is successful
   */
  private inlineSubFunction(fc: FuncCallSpecs): boolean {
    const fd = fc.getFuncdata();
    if (fd === null) return false;

    if (this.inline_head === null) {
      // This is the top level of inlining
      this.inline_head = this.data; // Set up head of inlining
      this.inline_recursion = this.inline_base;
    }
    this.inline_recursion!.add(FlowInfo.addrKey(this.data.getAddress())); // Insert current function
    if (this.inline_recursion!.has(FlowInfo.addrKey(fd.getAddress()))) {
      // This function has already been included with current inlining
      this.inline_head!.warning("Could not inline here", fc.getOp().getAddr());
      return false;
    }

    const res = this.data.inlineFlow(fd, this, fc.getOp());
    if (res < 0) {
      return false;
    } else if (res === 0) { // easy model
      // Remove inlined function from list so it can be inlined again, even if it also inlines
      this.inline_recursion!.delete(FlowInfo.addrKey(fd.getAddress()));
    } else if (res === 1) { // hard model
      // Add inlined function to recursion list, even if it contains no inlined calls,
      // to prevent parent from inlining it twice
      this.inline_recursion!.add(FlowInfo.addrKey(fd.getAddress()));
    }

    // Changing CALL to JUMP may make some original code unreachable
    this.setPossibleUnreachable();

    return true;
  }

  /**
   * Perform injection replacing the CALL at the given call site.
   * The call site must be previously marked with the injection id.
   * @param fc is the given call site
   * @returns true if the injection was successfully performed
   */
  private injectSubFunction(fc: FuncCallSpecs): boolean {
    const op = fc.getOp();

    // Inject to end of the deadlist
    const icontext = this.glb.pcodeinjectlib.getCachedContext();
    icontext.clear();
    icontext.baseaddr = op.getAddr();
    icontext.nextaddr = new Address(icontext.baseaddr);
    icontext.calladdr = fc.getEntryAddress();
    const payload = this.glb.pcodeinjectlib.getPayload(fc.getInjectId());
    this.doInjection(payload, icontext, op, fc);
    // If the injection fills in the -paramshift- field of the context
    // pass this information on to the callspec of the injected call, which must be last in the list
    if (payload.getParamShift() !== 0) {
      this.qlst[this.qlst.length - 1].setParamshift(payload.getParamShift());
    }

    return true; // Return true to indicate injection happened and callspec should be deleted
  }

  /**
   * Check if any of the calls this function makes are to already traced data-flow.
   * If so, we change the CALL to a BRANCH and issue a warning.
   * This situation is most likely due to a Position Independent Code construction.
   */
  private checkContainedCall(): void {
    let i = 0;
    while (i < this.qlst.length) {
      const fc = this.qlst[i];
      const fd = fc.getFuncdata();
      if (fd !== null) { i++; continue; }
      const op = fc.getOp();
      if (op.code() !== OpCode.CPUI_CALL) { i++; continue; }

      const addr: Address = fc.getEntryAddress();
      const ub = this.visitedUpperBound(addr);
      if (ub.index === 0) { i++; continue; }
      const prev = ub.entries[ub.index - 1];
      if (!addr.lessThan(prev[0].add(BigInt(prev[1].size))) &&
          !addr.equals(prev[0].add(BigInt(prev[1].size)).subtract(1n).add(1n))) {
        // Check: prev[0] + prev[1].size <= addr
        if (prev[0].add(BigInt(prev[1].size)).lessThan(addr) ||
            prev[0].add(BigInt(prev[1].size)).equals(addr)) {
          i++;
          continue;
        }
      }
      if (prev[0].equals(addr)) {
        let s = `Possible PIC construction at ${op.getAddr().printRaw()}: Changing call to branch`;
        this.data.warningHeader(s);
        this.data.opSetOpcode(op, OpCode.CPUI_BRANCH);
        // Make sure target of new goto starts a basic block
        const targ = this.target(addr);
        this.data.opMarkStartBasic(targ);
        // Make sure the following op starts a basic block
        const nextIdx = op.getInsertIter() + 1;
        if (nextIdx < this.obank.endDead()) {
          this.data.opMarkStartBasic(this.obank.getDeadOp(nextIdx));
        }
        // Restore original address
        this.data.opSetInput(op, this.data.newCodeRef(addr), 0);
        this.qlst.splice(i, 1); // Delete the call
        // fc is freed (garbage collected in TS)
        continue; // Don't increment i since we spliced
      } else {
        this.data.warning("Call to offcut address within same function", op.getAddr());
      }
      i++;
    }
  }

  /**
   * Look for changes in control-flow near indirect jumps that were discovered after the jumptable recovery.
   */
  private checkMultistageJumptables(): void {
    const num = this.data.numJumpTables();
    for (let i = 0; i < num; i++) {
      const jt = this.data.getJumpTable(i);
      if (jt.checkForMultistage(this.data)) {
        this.tablelist.push(jt.getIndirectOp());
      }
    }
  }

  /**
   * Recover jumptables for the current set of BRANCHIND ops using existing flow.
   * @param newTables will hold the list of recovered JumpTables
   * @param notreached will hold the list of BRANCHIND ops that could not be reached
   */
  private recoverJumpTables(newTables: JumpTable[], notreached: PcodeOp[]): void {
    const op = this.tablelist[0];
    let nm = `${this.data.getName()}@@jump@${op.getAddr().printRaw()}`;

    // Prepare partial Funcdata object for analysis if necessary.
    // In C++ this is a stack-allocated object whose destructor removes its scope
    // from the database.  In TypeScript we must use try/finally to mirror that RAII.
    const partial = new (FlowInfo as any)._FuncdataCtor(
      nm, nm, this.data.getScopeLocal().getParent(), this.data.getAddress(), null
    );

    try {
      for (let i = 0; i < this.tablelist.length; i++) {
        const tableOp = this.tablelist[i];
        const modeHolder = { mode: 0 };
        const jt = this.data.recoverJumpTable(partial, tableOp, this, modeHolder); // Recover it
        if (jt === null) { // Could not recover jumptable
          if (!this.isFlowForInline()) { // Unless this flow is being inlined for something else
            this.truncateIndirectJump(tableOp, modeHolder.mode); // Treat the indirect jump as a call
          }
        } else if (jt.isPartial()) {
          if (this.tablelist.length > 1 && !FlowInfo.isInArray(notreached, tableOp)) {
            // If the recovery is incomplete with current flow AND there is more flow to generate,
            // AND we haven't tried to recover this table before
            notreached.push(tableOp); // Save this op so we can try to recover the table again later
          } else {
            jt.markComplete(); // If we aren't revisiting, mark the table as complete
          }
        }
        newTables.push(jt);
      }
    } finally {
      // Mirror C++ stack-allocated Funcdata destructor: remove the partial scope
      // from the database so the id can be reused on retry.
      partial.destroy();
    }
  }

  /**
   * Remove the given call site from the list for this function.
   * @param fc is the given call site (which is freed by this method)
   */
  private deleteCallSpec(fc: FuncCallSpecs): void {
    let i: number;
    for (i = 0; i < this.qlst.length; i++) {
      if (this.qlst[i] === fc) break;
    }
    if (i === this.qlst.length) {
      throw new LowlevelError("Misplaced callspec");
    }
    // In TypeScript, the object will be garbage collected
    this.qlst.splice(i, 1);
  }

  /**
   * Convert an indirect jump to CALLIND or RETURN.
   * @param op is the BRANCHIND operation to convert
   * @param mode indicates the type of failure when trying to recover the jump table
   */
  private truncateIndirectJump(op: PcodeOp, mode: number): void {
    const fail_return = 3;
    const fail_thunk = 2;
    const fail_callother = 4;

    if (mode === fail_return) {
      this.data.opSetOpcode(op, OpCode.CPUI_RETURN); // Turn jump into return
      this.data.warning("Treating indirect jump as return", op.getAddr());
    } else {
      this.data.opSetOpcode(op, OpCode.CPUI_CALLIND); // Turn jump into call
      this.setupCallindSpecs(op, null);
      const fc = this.data.getCallSpecs(op);
      let returnType: number;
      let noParams: boolean;

      if (mode === fail_thunk) {
        returnType = 0;
        noParams = false;
      } else if (mode === fail_callother) {
        returnType = PcodeOp.noreturn;
        fc.setNoReturn(true);
        this.data.warning("Does not return", op.getAddr());
        noParams = true;
      } else {
        returnType = 0;
        noParams = false;
        fc.setBadJumpTable(true); // Consider using special name for switch variable
        this.data.warning("Treating indirect jump as call", op.getAddr());
      }
      if (noParams) {
        if (!fc.hasModel()) {
          fc.setInternal(this.glb.defaultfp, this.glb.types.getTypeVoid());
          fc.setInputLock(true);
          fc.setOutputLock(true);
        }
      }

      // Create an artificial return
      const truncop = this.artificialHalt(op.getAddr(), returnType);
      this.data.opDeadInsertAfter(truncop, op);
    }
  }

  /**
   * Test if the given p-code op is a member of an array.
   * @param array is the array of p-code ops to search
   * @param op is the given p-code op to search for
   * @returns true if the op is a member of the array
   */
  private static isInArray(array: PcodeOp[], op: PcodeOp): boolean {
    for (let i = 0; i < array.length; i++) {
      if (array[i] === op) return true;
    }
    return false;
  }

  // Static reference for external FuncCallSpecs constructor -- set at runtime to avoid circular deps
  static _FuncCallSpecsCtor: any = null;
  static _FuncdataCtor: any = null;

  // ----- Public methods -----

  /**
   * Constructor. Prepare for tracing flow for a new function.
   * @param d is the new function to trace
   * @param o is the internal p-code container for the function
   * @param b is the internal basic block container
   * @param q is the internal container of call sites
   */
  constructor(d: Funcdata, o: PcodeOpBank, b: BlockGraph, q: FuncCallSpecs[]);
  /**
   * Cloning constructor. Prepare a new flow cloned from an existing flow.
   * @param d is the new function that has been cloned
   * @param o is the internal p-code container for the function
   * @param b is the internal basic block container
   * @param q is the internal container of call sites
   * @param op2 is the existing flow
   */
  constructor(d: Funcdata, o: PcodeOpBank, b: BlockGraph, q: FuncCallSpecs[], op2: FlowInfo);
  constructor(d: Funcdata, o: PcodeOpBank, b: BlockGraph, q: FuncCallSpecs[], op2?: FlowInfo) {
    this.data = d;
    this.obank = o;
    this.bblocks = b;
    this.qlst = q;
    this.glb = d.getArch();
    this.emitter = new PcodeEmitFd();
    this.unprocessed = [];
    this.addrlist = [];
    this.tablelist = [];
    this.injectlist = [];
    this.visited = new Map();
    this.visitedAddrsMap = new Map();
    this.block_edge1 = [];
    this.block_edge2 = [];
    this.inline_base = new Set();

    if (op2 === undefined) {
      // Normal constructor
      this.baddr = new Address(d.getAddress().getSpace()!, 0n);
      this.eaddr = new Address(d.getAddress().getSpace()!, 0xFFFFFFFFFFFFFFFFn);
      this.minaddr = new Address(d.getAddress());
      this.maxaddr = new Address(d.getAddress());
      this.flags = 0;
      this.emitter.setFuncdata(d);
      this.inline_head = null;
      this.inline_recursion = null;
      this.insn_count = 0;
      this.insn_max = 0xFFFFFFFF; // ~((uint4)0)
      this.flowoverride_present = d.getOverride().hasFlowOverride();
    } else {
      // Cloning constructor
      this.baddr = new Address(op2.baddr);
      this.eaddr = new Address(op2.eaddr);
      this.minaddr = new Address(d.getAddress());
      this.maxaddr = new Address(d.getAddress());
      this.flags = op2.flags;
      this.emitter.setFuncdata(d);
      this.unprocessed = [...op2.unprocessed]; // Clone the flow address information
      this.addrlist = [...op2.addrlist];
      // Clone visited map
      for (const [key, stat] of op2.visited) {
        const cloneStat = new VisitStat();
        cloneStat.seqnum = new SeqNum(stat.seqnum.getAddr(), stat.seqnum.getTime());
        cloneStat.size = stat.size;
        this.visited.set(key, cloneStat);
      }
      for (const [key, addr] of op2.visitedAddrsMap) {
        this.visitedAddrsMap.set(key, new Address(addr));
      }
      // Ensure visitedAddrsMap is in sync with visited
      for (const [key, stat] of this.visited) {
        if (!this.visitedAddrsMap.has(key)) {
          this.visitedAddrsMap.set(key, stat.seqnum.getAddr());
        }
      }
      this.inline_head = op2.inline_head;
      if (this.inline_head !== null) {
        this.inline_base = new Set(op2.inline_base);
        this.inline_recursion = this.inline_base;
      } else {
        this.inline_recursion = null;
      }
      this.insn_count = op2.insn_count;
      this.insn_max = op2.insn_max;
      this.flowoverride_present = d.getOverride().hasFlowOverride();
    }
  }

  /** Establish the flow bounds */
  setRange(b: Address, e: Address): void {
    this.baddr = b;
    this.eaddr = e;
  }

  /** Set the maximum number of instructions */
  setMaximumInstructions(max: number): void {
    this.insn_max = max;
  }

  /** Enable a specific option */
  setFlags(val: number): void {
    this.flags |= val;
  }

  /** Disable a specific option */
  clearFlags(val: number): void {
    this.flags &= ~val;
  }

  /**
   * Return first p-code op for instruction at given address.
   * If the instruction generated no p-code, an attempt is made to fall-thru to the next instruction.
   * If no p-code op is ultimately found, an exception is thrown.
   * @param addr is the given address of the instruction
   * @returns the targetted p-code op
   */
  target(addr: Address): PcodeOp {
    let key = FlowInfo.addrKey(addr);
    let stat = this.visited.get(key);
    while (stat !== undefined) {
      const seq = stat.seqnum;
      if (!seq.getAddr().isInvalid()) {
        const retop = this.obank.findOp(seq);
        if (retop !== null) {
          return retop;
        }
        break;
      }
      // Visit fall thru address in case of no-op
      const origAddr = this.visitedAddrsMap.get(key);
      if (origAddr === undefined) break;
      const nextAddr = origAddr.add(BigInt(stat.size));
      key = FlowInfo.addrKey(nextAddr);
      stat = this.visited.get(key);
    }
    const errmsg = `Could not find op at target address: (${addr.getSpace()!.getName()},${addr.printRaw()})`;
    throw new LowlevelError(errmsg);
  }

  /**
   * Find the target referred to by a given BRANCH or CBRANCH.
   * The code reference passed as the first parameter to the branch
   * is examined, and the p-code op it refers to is returned.
   * @param op is the given branch op
   * @returns the targetted p-code op
   */
  branchTarget(op: PcodeOp): PcodeOp {
    const addr: Address = op.getIn(0)!.getAddr();
    if (addr.isConstant()) { // This is a relative sequence number
      const res = new Address();
      const retop = this.findRelTarget(op, res);
      if (retop !== null) return retop;
      return this.target(res);
    }
    return this.target(addr); // Otherwise a normal address target
  }

  /**
   * Update the branch target for an inlined p-code op.
   * Replace any reference to the op being inlined with the first op of the inlined sequence.
   * @param oldOp is the p-code op being inlined
   * @param newOp is the first p-code op in the inlined sequence
   */
  updateTarget(oldOp: PcodeOp, newOp: PcodeOp): void {
    const key = FlowInfo.addrKey(oldOp.getAddr());
    const stat = this.visited.get(key);
    if (stat !== undefined) { // Check if -oldOp- is a possible branch target
      const oldSeq = oldOp.getSeqNum();
      if (stat.seqnum.getAddr().equals(oldSeq.getAddr()) &&
          stat.seqnum.getTime() === oldSeq.getTime()) {
        // (if injection op is the first op for its address) change the seqnum to the newOp
        stat.seqnum = newOp.getSeqNum();
      }
    }
  }

  /** Generate raw control-flow from the function's base address */
  generateOps(): void {
    const notreached: PcodeOp[] = []; // indirect ops that are not reachable
    let notreachcnt = 0;
    this.clearProperties();
    this.addrlist.push(this.data.getAddress());
    while (this.addrlist.length > 0) { // Recovering as much as possible except jumptables
      this.fallthru();
    }
    if (this.hasInject()) {
      this.injectPcode();
    }
    do {
      while (this.tablelist.length > 0) { // For each jumptable found
        const newTables: JumpTable[] = [];
        this.recoverJumpTables(newTables, notreached);
        this.tablelist = [];
        for (let i = 0; i < newTables.length; i++) {
          const jt = newTables[i];
          if (jt === null) continue;

          const num = jt.numEntries();
          for (let j = 0; j < num; j++) {
            this.newAddress(jt.getIndirectOp(), jt.getAddressByIndex(j));
          }
          while (this.addrlist.length > 0) { // Try to fill in as much more as possible
            this.fallthru();
          }
        }
      }

      this.checkContainedCall(); // Check for PIC constructions
      this.checkMultistageJumptables();
      while (notreachcnt < notreached.length) {
        this.tablelist.push(notreached[notreachcnt]);
        notreachcnt += 1;
      }
      if (this.hasInject()) {
        this.injectPcode();
      }
    } while (this.tablelist.length > 0); // Inlining or multistage may have added new indirect branches
  }

  /** Generate basic blocks from the raw control-flow */
  generateBlocks(): void {
    this.fillinBranchStubs();
    this.collectEdges();
    this.splitBasic(); // Split ops up into basic blocks
    this.connectBasic(); // Generate edges between basic blocks
    if (this.bblocks.getSize() !== 0) {
      const startblock: FlowBlock = this.bblocks.getBlock(0);
      if (startblock.sizeIn() !== 0) { // Make sure the entry block has no incoming edges
        // If it does we create a new entry block that flows into the old entry block
        const newfront: BlockBasic = this.bblocks.newBlockBasic(this.data);
        this.bblocks.addEdge(newfront, startblock);
        this.bblocks.setStartBlock(newfront);
        this.data.setBasicBlockRange(newfront, this.data.getAddress(), this.data.getAddress());
      }
    }

    if (this.hasPossibleUnreachable()) {
      this.data.removeUnreachableBlocks(false, true);
    }
  }

  /**
   * For in-lining using the hard model, make sure some restrictions are met.
   * @param inlinefd is the function being in-lined into this flow
   * @param op is CALL instruction at the site of the in-line
   * @param retaddr holds the passed back return address
   * @returns true if all the hard model restrictions are met
   */
  testHardInlineRestrictions(inlinefd: Funcdata, op: PcodeOp, retaddr: Address): boolean {
    if (!inlinefd.getFuncProto().isNoReturn()) {
      const iterIdx = op.getInsertIter() + 1;
      if (iterIdx >= this.obank.endDead()) {
        this.inline_head!.warning("No fallthrough prevents inlining here", op.getAddr());
        return false;
      }
      const nextop = this.obank.getDeadOp(iterIdx);
      retaddr.assign(nextop.getAddr());
      if (op.getAddr().equals(retaddr)) {
        this.inline_head!.warning("Return address prevents inlining here", op.getAddr());
        return false;
      }
      // If the inlining "jumps back" this starts a new basic block
      this.data.opMarkStartBasic(nextop);
    }
    return true;
  }

  /**
   * Check if this flow matches the EZ in-lining model.
   * A function is in the EZ model if it is a straight-line leaf function.
   * @returns true if this flow contains no CALL or BRANCH ops
   */
  checkEZModel(): boolean {
    let iter = this.obank.beginDead();
    while (iter < this.obank.endDead()) {
      const op = this.obank.getDeadOp(iter);
      if (op.isCallOrBranch()) return false;
      iter++;
    }
    return true;
  }

  /**
   * Perform substitution on any op that requires injection.
   * Types of substitution include:
   *   - Sub-function in-lining
   *   - Sub-function injection
   *   - User defined op injection
   */
  injectPcode(): void {
    for (let i = 0; i < this.injectlist.length; i++) {
      const op = this.injectlist[i];
      if (op === null) continue;
      this.injectlist[i] = null; // Nullify entry, so we don't inject more than once
      if (op.code() === OpCode.CPUI_CALLOTHER) {
        this.injectUserOp(op);
      } else { // CPUI_CALL or CPUI_CALLIND
        const fc = (FlowInfo as any)._getFspecFromConst(op.getIn(0)!.getAddr());
        if (fc.isInline()) {
          if (fc.getInjectId() >= 0) {
            if (this.injectSubFunction(fc)) {
              this.data.warningHeader(
                "Function: " + fc.getName() + " replaced with injection: " +
                this.glb.pcodeinjectlib.getCallFixupName(fc.getInjectId())
              );
              this.deleteCallSpec(fc);
            }
          } else if (this.inlineSubFunction(fc)) {
            this.data.warningHeader("Inlined function: " + fc.getName());
            this.deleteCallSpec(fc);
          }
        }
      }
    }
    this.injectlist = [];
  }

  /**
   * Pull in-lining recursion information from another flow.
   * When preparing p-code for an in-lined function, the generation process needs
   * to be informed of in-lining that has already been performed.
   * @param op2 is the parent flow
   */
  forwardRecursion(op2: FlowInfo): void {
    this.inline_recursion = op2.inline_recursion;
    this.inline_head = op2.inline_head;
  }

  /**
   * Clone the given in-line flow into this flow using the hard model.
   * Individual PcodeOps from the Funcdata being in-lined are cloned into
   * the Funcdata for this flow, preserving their original address.
   * Any RETURN op is replaced with jump to first address following the call site.
   * @param inlineflow is the given in-line flow to clone
   * @param retaddr is the first address after the call site in this flow
   */
  inlineClone(inlineflow: FlowInfo, retaddr: Address): void {
    const deadBegin = inlineflow.data.beginOpDead();
    const deadEnd = inlineflow.data.endOpDead();
    for (let iter = deadBegin; iter < deadEnd; iter++) {
      const op = inlineflow.obank.getDeadOp(iter);
      let cloneop: PcodeOp;
      if (op.code() === OpCode.CPUI_RETURN && !retaddr.isInvalid()) {
        cloneop = this.data.newOp(1, op.getSeqNum());
        this.data.opSetOpcode(cloneop, OpCode.CPUI_BRANCH);
        const vn = this.data.newCodeRef(retaddr);
        this.data.opSetInput(cloneop, vn, 0);
      } else {
        cloneop = this.data.cloneOp(op, op.getSeqNum());
      }
      if (cloneop.isCallOrBranch()) {
        this.xrefInlinedBranch(cloneop);
      }
    }
    // Copy in the cross-referencing
    this.unprocessed.push(...inlineflow.unprocessed);
    this.addrlist.push(...inlineflow.addrlist);
    // Merge visited maps
    for (const [key, stat] of inlineflow.visited) {
      if (!this.visited.has(key)) {
        this.visited.set(key, stat);
      }
    }
    for (const [key, addr] of inlineflow.visitedAddrsMap) {
      if (!this.visitedAddrsMap.has(key)) {
        this.visitedAddrsMap.set(key, addr);
      }
    }
    // Ensure visitedAddrsMap is in sync with visited after merge
    for (const [key, stat] of this.visited) {
      if (!this.visitedAddrsMap.has(key)) {
        this.visitedAddrsMap.set(key, stat.seqnum.getAddr());
      }
    }
    // We don't copy inline_recursion or inline_head here
  }

  /**
   * Clone the given in-line flow into this flow using the EZ model.
   * Individual PcodeOps from the Funcdata being in-lined are cloned into
   * the Funcdata for this flow but are reassigned a new fixed address,
   * and the RETURN op is eliminated.
   * @param inlineflow is the given in-line flow to clone
   * @param calladdr is the fixed address assigned to the cloned PcodeOps
   */
  inlineEZClone(inlineflow: FlowInfo, calladdr: Address): void {
    const deadBegin = inlineflow.data.beginOpDead();
    const deadEnd = inlineflow.data.endOpDead();
    for (let iter = deadBegin; iter < deadEnd; iter++) {
      const op = inlineflow.obank.getDeadOp(iter);
      if (op.code() === OpCode.CPUI_RETURN) break;
      const myseq = new SeqNum(calladdr, op.getSeqNum().getTime());
      this.data.cloneOp(op, myseq);
    }
    // Because we are processing only straightline code and it is all getting assigned to one
    // address, we don't touch unprocessed, addrlist, or visited
  }

  /** Get the number of bytes covered by the flow */
  getSize(): number {
    return Number(this.maxaddr.getOffset() - this.minaddr.getOffset());
  }

  /** Does this flow have injections */
  hasInject(): boolean {
    return this.injectlist.length > 0;
  }

  /** Does this flow have unimplemented instructions */
  hasUnimplemented(): boolean {
    return (this.flags & FlowInfo.unimplemented_present) !== 0;
  }

  /** Does this flow reach inaccessible data */
  hasBadData(): boolean {
    return (this.flags & FlowInfo.baddata_present) !== 0;
  }

  /** Does this flow go out of bound */
  hasOutOfBounds(): boolean {
    return (this.flags & FlowInfo.outofbounds_present) !== 0;
  }

  /** Does this flow reinterpret bytes */
  hasReinterpreted(): boolean {
    return (this.flags & FlowInfo.reinterpreted_present) !== 0;
  }

  /** Does this flow have too many instructions */
  hasTooManyInstructions(): boolean {
    return (this.flags & FlowInfo.toomanyinstructions_present) !== 0;
  }

  /** Is this flow to be in-lined */
  isFlowForInline(): boolean {
    return (this.flags & FlowInfo.flow_forinline) !== 0;
  }

  /** Should jump table structure be recorded */
  doesJumpRecord(): boolean {
    return (this.flags & FlowInfo.record_jumploads) !== 0;
  }
}
