/**
 * @file condexe.ts
 * @description Classes for simplifying control-flow with shared conditional expressions.
 *
 * Translated from Ghidra's condexe.hh / condexe.cc
 */

import type { int4, uint4 } from '../core/types.js';
import { OpCode } from '../core/opcodes.js';
import { LowlevelError } from '../core/error.js';
import { BooleanExpressionMatch } from './expression.js';
import { FlowBlock, BlockBasicClass, BlockGraph } from './block.js';
import { Action, Rule, ActionGroupList } from './action.js';

// ---------------------------------------------------------------------------
// Forward type declarations for types from not-yet-written modules
// ---------------------------------------------------------------------------

type Funcdata = any;
type PcodeOp = any;
type Varnode = any;
type BlockBasic = any;
type Architecture = any;
type AddrSpace = any;

// ---------------------------------------------------------------------------
// ConditionalExecution
// ---------------------------------------------------------------------------

/**
 * A class for simplifying a series of conditionally executed statements.
 *
 * This class tries to perform transformations like the following:
 * ```
 *    if (a) {           if (a) {
 *       BODY1
 *    }          ==>       BODY1
 *    if (a) {             BODY2
 *       BODY2
 *    }                  }
 * ```
 * Other similar configurations where two CBRANCHs are based on
 * the same condition are handled. The main variation, referred to as a
 * "directsplit" in the code looks like:
 * ```
 *  if (a) {                      if (a && new_boolean()) {
 *     a = new_boolean();
 *  }                      ==>      BODY1
 *  if (a) {
 *     BODY1
 *  }                             }
 * ```
 * The value of 'a' doesn't need to be reevaluated if it is false.
 *
 * In the first scenario, there is a block where two flows come
 * together but don't need to, as the evaluation of the boolean
 * is redundant. This block is the iblock. The original
 * evaluation of the boolean occurs in initblock. There are
 * two paths from here to iblock, called the prea path and preb path,
 * either of which may contain additional 1in/1out blocks.
 * There are also two paths out of iblock, posta, and postb.
 * The ConditionalExecution class determines if the CBRANCH in
 * iblock is redundant by determining if the boolean value is
 * either the same as, or the complement of, the boolean value
 * in initblock. If the CBRANCH is redundant, iblock is
 * removed, linking prea to posta and preb to postb (or vice versa
 * depending on whether the booleans are complements of each other).
 * If iblock is to be removed, modifications to data-flow made
 * by iblock must be preserved. For MULTIEQUALs in iblock,
 * reads are examined to see if they came from the posta path,
 * or the postb path, then they are replaced by the MULTIEQUAL
 * slot corresponding to the matching prea or preb branch. If
 * posta and postb merge at an exitblock, the MULTIEQUAL must
 * be pushed into the exitblock and reads which can't be
 * attributed to the posta or postb path are replaced by the
 * exitblock MULTIEQUAL.
 *
 * In theory, other operations performed in iblock could be
 * pushed into exitblock if they are not read in the posta
 * or postb paths, but currently
 * non MULTIEQUAL operations in iblock terminate the action.
 *
 * In the second scenario, the boolean evaluated in initblock
 * remains unmodified along only one of the two paths out, prea
 * or preb. The boolean in iblock (modulo complementing) will
 * evaluate in the same way. We define posta as the path out of
 * iblock that will be followed by this unmodified path. The
 * transform that needs to be made is to have the unmodified path
 * out of initblock flow immediately into the posta path without
 * having to reevalute the condition in iblock. iblock is not
 * removed because flow from the "modified" path may also flow
 * into posta, depending on how the boolean was modified.
 * Adjustments to data-flow are similar to the first scenario but
 * slightly more complicated. The first block along the posta
 * path is referred to as the posta_block, this block will
 * have a new block flowing into it.
 */
export class ConditionalExecution {
  private fd: Funcdata;                        // Function being analyzed
  private cbranch: PcodeOp | null;             // CBRANCH in iblock
  private initblock: BlockBasic | null;        // The initial block computing the boolean value
  private iblock: BlockBasic | null;           // The block where flow is (unnecessarily) coming together
  private prea_inslot: int4;                   // iblock->In(prea_inslot) = pre a path
  private init2a_true: boolean;                // Does true branch (in terms of iblock) go to path pre a
  private iblock2posta_true: boolean;          // Does true branch go to path post a
  private camethruposta_slot: int4;            // init or pre slot to use, for data-flow thru post
  private posta_outslot: int4;                 // The out edge from iblock to posta
  private posta_block: BlockBasic | null;      // First block in posta path
  private postb_block: BlockBasic | null;      // First block in postb path
  private replacement: Map<int4, Varnode>;     // Map from block to replacement Varnode for (current) Varnode
  private pullback_arr: (Varnode | null)[];    // Outputs of ops that have been pulled back from iblock for (current) Varnode
  private heritageyes: boolean[];              // Boolean array indexed by address space indicating whether the space is heritaged

  /**
   * Calculate boolean array of all address spaces that have had a heritage pass run.
   *
   * Used to test if all the links out of the iblock have been calculated.
   */
  private buildHeritageArray(): void {
    this.heritageyes = [];
    const glb: Architecture = this.fd.getArch();
    const numSpaces: int4 = glb.numSpaces();
    this.heritageyes.length = numSpaces;
    for (let i = 0; i < numSpaces; ++i) {
      this.heritageyes[i] = false;
    }
    for (let i = 0; i < numSpaces; ++i) {
      const spc: AddrSpace = glb.getSpace(i);
      if (spc == null) continue;
      const index: int4 = spc.getIndex();
      if (!spc.isHeritaged()) continue;
      if (this.fd.numHeritagePasses(spc) > 0)
        this.heritageyes[index] = true;   // At least one pass has been performed on the space
    }
  }

  /**
   * Test the most basic requirements on iblock.
   *
   * The block must have 2 in edges and 2 out edges and a final CBRANCH op.
   * @returns true if iblock matches basic requirements
   */
  private testIBlock(): boolean {
    if (this.iblock!.sizeIn() !== 2) return false;
    if (this.iblock!.sizeOut() !== 2) return false;
    this.cbranch = this.iblock!.lastOp();
    if (this.cbranch == null) return false;
    if (this.cbranch.code() !== OpCode.CPUI_CBRANCH) return false;
    return true;
  }

  /**
   * Find initblock, based on iblock.
   * @returns true if configuration between initblock and iblock is correct
   */
  private findInitPre(): boolean {
    let tmp: FlowBlock = this.iblock!.getIn(this.prea_inslot);
    let last: FlowBlock = this.iblock!;
    while ((tmp.sizeOut() === 1) && (tmp.sizeIn() === 1)) {
      last = tmp;
      tmp = tmp.getIn(0);
    }
    if (tmp.sizeOut() !== 2) return false;
    this.initblock = tmp as BlockBasic;
    tmp = this.iblock!.getIn(1 - this.prea_inslot);
    while ((tmp.sizeOut() === 1) && (tmp.sizeIn() === 1))
      tmp = tmp.getIn(0);
    if (tmp !== this.initblock) return false;
    if (this.initblock === this.iblock) return false;

    this.init2a_true = (this.initblock!.getTrueOut() === last);

    return true;
  }

  /**
   * Verify that initblock and iblock branch on the same condition.
   *
   * The conditions must always have the same value or always have
   * complementary values.
   * @returns true if the conditions are correlated
   */
  private verifySameCondition(): boolean {
    const init_cbranch: PcodeOp = this.initblock!.lastOp();
    if (init_cbranch == null) return false;
    if (init_cbranch.code() !== OpCode.CPUI_CBRANCH) return false;

    const tester = new BooleanExpressionMatch();
    if (!tester.verifyCondition(this.cbranch, init_cbranch))
      return false;

    if (tester.getFlip())
      this.init2a_true = !this.init2a_true;
    return true;
  }

  /**
   * Can we move the MULTIEQUAL defining p-code of the given Varnode.
   *
   * The given Varnode is defined by a MULTIEQUAL in iblock which must be removed.
   * Test if this is possible/advisable given a specific p-code op that reads the Varnode.
   * @param vn is the given Varnode
   * @param op is the given PcodeOp reading the Varnode
   * @returns false if it is not possible to move the defining op (because of the given op)
   */
  private testMultiRead(vn: Varnode, op: PcodeOp): boolean {
    if (op.getParent() === this.iblock) {
      if (op.code() === OpCode.CPUI_COPY || op.code() === OpCode.CPUI_SUBPIECE)
        return true;    // If the COPY's output reads can be altered, then vn can be altered
      return false;
    }
    if (op.code() === OpCode.CPUI_RETURN) {
      if ((op.numInput() < 2) || (op.getIn(1) !== vn)) return false; // Only test for flow thru to return value
    }
    return true;
  }

  /**
   * Can we move the (non MULTIEQUAL) defining p-code of the given Varnode.
   *
   * The given Varnode is defined by an operation in iblock which must be removed.
   * Test if this is possible/advisable given a specific p-code op that reads the Varnode.
   * @param vn is the given Varnode
   * @param op is the given PcodeOp reading the Varnode
   * @returns false if it is not possible to move the defining op (because of the given op)
   */
  private testOpRead(vn: Varnode, op: PcodeOp): boolean {
    if (op.getParent() === this.iblock) return true;
    const writeOp: PcodeOp = vn.getDef();
    const opc: OpCode = writeOp.code();
    if (opc === OpCode.CPUI_COPY || opc === OpCode.CPUI_SUBPIECE || opc === OpCode.CPUI_INT_ADD || opc === OpCode.CPUI_PTRSUB) {
      if (opc === OpCode.CPUI_INT_ADD || opc === OpCode.CPUI_PTRSUB) {
        if (!writeOp.getIn(1).isConstant())
          return false;
      }
      const invn: Varnode = writeOp.getIn(0);
      if (invn.isWritten()) {
        const upop: PcodeOp = invn.getDef();
        if ((upop.getParent() === this.iblock) && (upop.code() !== OpCode.CPUI_MULTIEQUAL))
          return false;
      } else if (invn.isFree())
        return false;
      return true;
    }
    return false;
  }

  /**
   * Find previously constructed pull-back op.
   * @param inbranch is the iblock incoming branch to pullback through
   * @returns the output of the previous pullback op, or null
   */
  private findPullback(inbranch: int4): Varnode | null {
    while (this.pullback_arr.length <= inbranch)
      this.pullback_arr.push(null);
    return this.pullback_arr[inbranch];
  }

  /**
   * Pull-back PcodeOp out of the iblock.
   *
   * Create a duplicate PcodeOp outside the iblock. The first input to the PcodeOp can
   * be defined by a MULTIEQUAL in the iblock, in which case the duplicate's input will be
   * selected from the MULTIEQUAL input. Any other inputs must be constants.
   * @param op is the PcodeOp in the iblock being replaced
   * @param inbranch is the direction to pullback from
   * @returns the output Varnode of the new op
   */
  private pullbackOp(op: PcodeOp, inbranch: int4): Varnode {
    let invn: Varnode | null = this.findPullback(inbranch); // Look for pullback constructed for a previous read
    if (invn != null)
      return invn;
    invn = op.getIn(0);
    let bl: BlockBasic;
    if (invn.isWritten()) {
      const defOp: PcodeOp = invn.getDef();
      if (defOp.getParent() === this.iblock) {
        bl = this.iblock!.getIn(inbranch) as BlockBasic;
        invn = defOp.getIn(inbranch);      // defOp must be MULTIEQUAL
      } else {
        bl = this.iblock!.getImmedDom() as BlockBasic;
      }
    } else {
      bl = this.iblock!.getImmedDom() as BlockBasic;
    }
    const newOp: PcodeOp = this.fd.newOp(op.numInput(), op.getAddr());
    const origOutVn: Varnode = op.getOut();
    const outVn: Varnode = this.fd.newVarnodeOut(origOutVn.getSize(), origOutVn.getAddr(), newOp);
    this.fd.opSetOpcode(newOp, op.code());
    this.fd.opSetInput(newOp, invn, 0);
    for (let i = 1; i < op.numInput(); ++i)
      this.fd.opSetInput(newOp, op.getIn(i), i);
    this.fd.opInsertEnd(newOp, bl);
    this.pullback_arr[inbranch] = outVn;    // Cache pullback in case there are other reads
    return outVn;
  }

  /**
   * Create a MULTIEQUAL in the given block that will hold data-flow from the given PcodeOp.
   *
   * A new MULTIEQUAL is created whose inputs are the output of the given PcodeOp.
   * @param op is the PcodeOp whose output will get held
   * @param bl is the block that will contain the new MULTIEQUAL
   * @returns the output Varnode of the new MULTIEQUAL
   */
  private getNewMulti(op: PcodeOp, bl: BlockBasic): Varnode {
    const newop: PcodeOp = this.fd.newOp(bl.sizeIn(), bl.getStart());
    const outvn: Varnode = op.getOut();
    let newoutvn: Varnode;
    // Using the original outvn address may cause merge conflicts
    //  newoutvn = this.fd.newVarnodeOut(outvn.getSize(), outvn.getAddr(), newop);
    newoutvn = this.fd.newUniqueOut(outvn.getSize(), newop);
    this.fd.opSetOpcode(newop, OpCode.CPUI_MULTIEQUAL);

    // We create NEW references to outvn, these refs will get put
    // at the end of the dependency list and will get handled in
    // due course
    for (let i = 0; i < bl.sizeIn(); ++i)
      this.fd.opSetInput(newop, outvn, i);

    this.fd.opInsertBegin(newop, bl);
    return newoutvn;
  }

  /**
   * Resolve a read op coming through an arbitrary block.
   *
   * Given an op in the iblock and the basic block of another op that reads the output Varnode,
   * calculate the replacement Varnode for the read.
   * @param op is the given op in the iblock
   * @param bl is the basic block of the read
   * @returns the replacement Varnode
   */
  private resolveRead(op: PcodeOp, bl: BlockBasic): Varnode {
    let res: Varnode;
    if (bl.sizeIn() === 1) {
      // Since dominator is iblock, In(0) must be iblock
      // Figure what side of iblock we came through
      const slot: int4 = (bl.getInRevIndex(0) === this.posta_outslot) ? this.camethruposta_slot : 1 - this.camethruposta_slot;
      res = this.resolveIblockRead(op, slot);
    } else {
      res = this.getNewMulti(op, bl);
    }
    return res;
  }

  /**
   * Resolve a read op coming through the iblock.
   * @param op is the iblock op whose output is being read
   * @param inbranch is the known direction of the reading op
   * @returns the replacement Varnode to use for the read
   */
  private resolveIblockRead(op: PcodeOp, inbranch: int4): Varnode {
    if (op.code() === OpCode.CPUI_COPY) {
      const vn: Varnode = op.getIn(0);
      if (vn.isWritten()) {
        const defOp: PcodeOp = vn.getDef();
        if (defOp.code() === OpCode.CPUI_MULTIEQUAL && defOp.getParent() === this.iblock)
          op = defOp;
      } else {
        return vn;
      }
    }
    const opc: OpCode = op.code();
    if (opc === OpCode.CPUI_MULTIEQUAL)
      return op.getIn(inbranch);
    else if (opc === OpCode.CPUI_SUBPIECE || opc === OpCode.CPUI_INT_ADD || opc === OpCode.CPUI_PTRSUB) {
      return this.pullbackOp(op, inbranch);
    }
    throw new LowlevelError("Conditional execution: Illegal op in iblock");
  }

  /**
   * Get the replacement Varnode for the output of a MULTIEQUAL in the iblock, given the op reading it.
   *
   * @param op is the MULTIEQUAL from iblock
   * @param readop is the PcodeOp reading the output Varnode
   * @param slot is the input slot being read
   * @returns the Varnode to use as a replacement
   */
  private getMultiequalRead(op: PcodeOp, readop: PcodeOp, slot: int4): Varnode {
    const bl: BlockBasic = readop.getParent();
    const inbl: BlockBasic = bl.getIn(slot) as BlockBasic;
    if (inbl !== this.iblock)
      return this.getReplacementRead(op, inbl);
    const s: int4 = (bl.getInRevIndex(slot) === this.posta_outslot) ? this.camethruposta_slot : 1 - this.camethruposta_slot;
    return this.resolveIblockRead(op, s);
  }

  /**
   * Find a replacement Varnode for the output of the given PcodeOp that is read in the given block.
   *
   * The replacement Varnode must be valid for everything below (dominated) by the block.
   * If we can't find a replacement, create one (as a MULTIEQUAL) in the given
   * block (creating recursion through input blocks). Any new Varnode created is
   * cached in the replacement map so it can get picked up by other calls to this function
   * for different blocks.
   * @param op is the given PcodeOp whose output we must replace
   * @param bl is the given basic block (containing a read of the Varnode)
   * @returns the replacement Varnode
   */
  private getReplacementRead(op: PcodeOp, bl: BlockBasic): Varnode {
    const index: int4 = bl.getIndex();
    if (this.replacement.has(index))
      return this.replacement.get(index)!;
    let curbl: BlockBasic = bl;
    // Flow must eventually come through iblock
    while (curbl.getImmedDom() !== this.iblock) {
      curbl = curbl.getImmedDom() as BlockBasic;   // Get immediate dominator
      if (curbl == null)
        throw new LowlevelError("Conditional execution: Could not find dominator");
    }
    const curIndex: int4 = curbl.getIndex();
    if (this.replacement.has(curIndex)) {
      const val = this.replacement.get(curIndex)!;
      this.replacement.set(index, val);
      return val;
    }
    const res: Varnode = this.resolveRead(op, curbl);
    this.replacement.set(curIndex, res);
    if (curbl !== bl)
      this.replacement.set(index, res);
    return res;
  }

  /**
   * Replace the data-flow for the given PcodeOp in iblock.
   *
   * The data-flow for the given op is reproduced in the new control-flow configuration.
   * After completion of this method, the op can be removed.
   * @param op is the given PcodeOp
   */
  private doReplacement(op: PcodeOp): void {
    this.replacement.clear();
    this.pullback_arr = [];
    const vn: Varnode = op.getOut();
    let iter: int4 = vn.beginDescend();
    while (iter !== vn.endDescend()) {
      const readop: PcodeOp = vn.getDescend(iter);
      let slot: int4 = readop.getSlot(vn);
      const bl: BlockBasic = readop.getParent();
      let rvn: Varnode;
      if (bl === this.iblock) {
        this.fd.opUnsetInput(readop, slot);
      } else {
        if (readop.code() === OpCode.CPUI_MULTIEQUAL) {
          rvn = this.getMultiequalRead(op, readop, slot);
        } else if (readop.code() === OpCode.CPUI_RETURN) {
          // Cannot replace input of RETURN directly, create COPY to hold input
          const retvn: Varnode = readop.getIn(1);
          const newcopyop: PcodeOp = this.fd.newOp(1, readop.getAddr());
          this.fd.opSetOpcode(newcopyop, OpCode.CPUI_COPY);
          const outvn: Varnode = this.fd.newVarnodeOut(retvn.getSize(), retvn.getAddr(), newcopyop); // Preserve the CPUI_RETURN storage address
          this.fd.opSetInput(readop, outvn, 1);
          this.fd.opInsertBefore(newcopyop, readop);
          slot = 0;
          rvn = this.getReplacementRead(op, bl);
        } else {
          rvn = this.getReplacementRead(op, bl);
        }
        this.fd.opSetInput(readop, rvn, slot);
      }
      // The last descendant is now gone
      iter = vn.beginDescend();
    }
  }

  /**
   * Test if the given PcodeOp can be removed from iblock.
   * @param op is the PcodeOp within iblock to test
   * @returns true if it is removable
   */
  private testRemovability(op: PcodeOp): boolean {
    let readop: PcodeOp;
    let vn: Varnode;

    if (op.code() === OpCode.CPUI_MULTIEQUAL) {
      vn = op.getOut();
      for (let iter = vn.beginDescend(); iter !== vn.endDescend(); ++iter) {
        readop = vn.getDescend(iter);
        if (!this.testMultiRead(vn, readop))
          return false;
      }
    } else {
      if (op.isFlowBreak() || op.isCall()) return false;
      if ((op.code() === OpCode.CPUI_LOAD) || (op.code() === OpCode.CPUI_STORE))
        return false;
      if (op.code() === OpCode.CPUI_INDIRECT) return false;

      vn = op.getOut();
      if (vn != null) {
        if (vn.isAddrTied()) return false;
        let hasnodescend = true;
        for (let iter = vn.beginDescend(); iter !== vn.endDescend(); ++iter) {
          readop = vn.getDescend(iter);
          if (!this.testOpRead(vn, readop))
            return false;
          hasnodescend = false;
        }
        if (hasnodescend && (!this.heritageyes[vn.getSpace().getIndex()]))  // Check if heritage is performed for this varnode's space
          return false;
      }
    }
    return true;
  }

  /**
   * Verify that we have a removable iblock.
   *
   * The iblock has been fixed. Test all control-flow conditions, and test removability
   * of all ops in the iblock.
   * @returns true if the configuration can be modified
   */
  private verify(): boolean {
    this.prea_inslot = 0;
    this.posta_outslot = 0;

    if (!this.testIBlock()) return false;
    if (!this.findInitPre()) return false;
    if (!this.verifySameCondition()) return false;

    // Cache some useful values
    this.iblock2posta_true = (this.posta_outslot === 1);
    this.camethruposta_slot = (this.init2a_true === this.iblock2posta_true) ? this.prea_inslot : 1 - this.prea_inslot;
    this.posta_block = this.iblock!.getOut(this.posta_outslot) as BlockBasic;
    this.postb_block = this.iblock!.getOut(1 - this.posta_outslot) as BlockBasic;

    // Iterate ops in iblock, skip the branch at the end
    const ops = this.iblock!.op;
    let idx = ops.length;
    if (idx > 0)
      --idx;   // Skip branch
    while (idx > 0) {
      --idx;
      if (!this.testRemovability(ops[idx]))
        return false;
    }
    return true;
  }

  /**
   * Constructor. Set up for testing ConditionalExecution on multiple iblocks.
   * @param f is the function to do testing on
   */
  constructor(f: Funcdata) {
    this.fd = f;
    this.cbranch = null;
    this.initblock = null;
    this.iblock = null;
    this.prea_inslot = 0;
    this.init2a_true = false;
    this.iblock2posta_true = false;
    this.camethruposta_slot = 0;
    this.posta_outslot = 0;
    this.posta_block = null;
    this.postb_block = null;
    this.replacement = new Map<int4, Varnode>();
    this.pullback_arr = [];
    this.heritageyes = [];
    this.buildHeritageArray();   // Cache an array depending on the particular heritage pass
  }

  /**
   * Test for a modifiable configuration around the given block.
   *
   * The given block is tested as a possible iblock. If this configuration
   * works and is not a directsplit, true is returned.
   * If the configuration works as a directsplit, then recursively check that
   * its posta_block works as an iblock. If it does work, keep this
   * iblock, otherwise revert to the directsplit configuration. In either
   * case return true. Processing the directsplit first may prevent
   * posta_block from being an iblock.
   * @param ib is the trial iblock
   * @returns true if (some) configuration is recognized and can be modified
   */
  trial(ib: BlockBasic): boolean {
    this.iblock = ib;
    if (!this.verify()) return false;
    return true;
  }

  /**
   * Eliminate the unnecessary path join at iblock.
   *
   * We assume the last call to verify() returned true.
   */
  execute(): void {
    let op: PcodeOp;
    let notdone: boolean;

    const ops = this.iblock!.op;
    let idx = ops.length - 1;   // Remove ops in reverse order
    do {
      op = ops[idx];
      notdone = idx > 0;
      if (notdone)
        --idx;
      if (!op.isBranch())
        this.doReplacement(op);   // Remove all read refs of op
      this.fd.opDestroy(op);      // Then destroy op
    } while (notdone);
    this.fd.removeFromFlowSplit(this.iblock, (this.posta_outslot !== this.camethruposta_slot));
  }
}

// ---------------------------------------------------------------------------
// ActionConditionalExe
// ---------------------------------------------------------------------------

/**
 * Search for and remove various forms of redundant CBRANCH operations.
 *
 * This action wraps the analysis performed by ConditionalExecution to simplify control-flow
 * that repeatedly branches on the same (or slightly modified) boolean expression.
 */
export class ActionConditionalExe extends Action {

  /** Constructor */
  constructor(g: string) {
    super(0, "conditionalexe", g);
  }

  /** Clone this action if it belongs to the given group list */
  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionConditionalExe(this.getGroup());
  }

  /** Apply the action to the given function */
  apply(data: Funcdata): int4 {
    let changethisround: boolean;
    let numhits: int4 = 0;
    let i: int4;

    if (data.hasUnreachableBlocks())   // Conditional execution elimination logic may not work with unreachable blocks
      return 0;
    const condexe = new ConditionalExecution(data);
    const bblocks: BlockGraph = data.getBasicBlocks();

    do {
      changethisround = false;
      for (i = 0; i < bblocks.getSize(); ++i) {
        const bb: BlockBasic = bblocks.getBlock(i) as BlockBasic;
        if (condexe.trial(bb)) {
          condexe.execute();   // Adjust dataflow
          numhits += 1;
          changethisround = true;
        }
      }
    } while (changethisround);
    this.count += numhits;   // Number of changes
    return 0;
  }
}

// ---------------------------------------------------------------------------
// MultiPredicate (helper for RuleOrPredicate)
// ---------------------------------------------------------------------------

/**
 * A helper class to mark up predicated INT_OR expressions.
 */
class MultiPredicate {
  op: PcodeOp | null;                // Base MULTIEQUAL op
  zeroSlot: int4;                    // Input slot containing path that sets zero
  zeroBlock: FlowBlock | null;       // Final block in path that sets zero
  condBlock: FlowBlock | null;       // Conditional block determining if zero is set or not
  cbranch: PcodeOp | null;           // CBRANCH determining if zero is set
  otherVn: Varnode | null;           // Other (non-zero) Varnode getting set on other path
  zeroPathIsTrue: boolean;           // True if path to zero set is the true path out of condBlock

  constructor() {
    this.op = null;
    this.zeroSlot = 0;
    this.zeroBlock = null;
    this.condBlock = null;
    this.cbranch = null;
    this.otherVn = null;
    this.zeroPathIsTrue = false;
  }

  /**
   * Check if vn is produced by a 2-branch MULTIEQUAL, one side of which is a zero constant.
   *
   * @param vn is the given Varnode
   * @returns true if the expression producing vn matches the form
   */
  discoverZeroSlot(vn: Varnode): boolean {
    if (!vn.isWritten()) return false;
    this.op = vn.getDef();
    if (this.op.code() !== OpCode.CPUI_MULTIEQUAL) return false;
    if (this.op.numInput() !== 2) return false;
    for (this.zeroSlot = 0; this.zeroSlot < 2; ++this.zeroSlot) {
      const tmpvn: Varnode = this.op.getIn(this.zeroSlot);
      if (!tmpvn.isWritten()) continue;
      const copyop: PcodeOp = tmpvn.getDef();
      if (copyop.code() !== OpCode.CPUI_COPY) continue;    // Multiequal must have CPUI_COPY input
      const zerovn: Varnode = copyop.getIn(0);
      if (!zerovn.isConstant()) continue;
      if (zerovn.getOffset() !== 0n) continue;              // which copies #0
      this.otherVn = this.op.getIn(1 - this.zeroSlot);     // store off varnode from other path
      if (this.otherVn.isFree()) return false;
      return true;
    }
    return false;
  }

  /**
   * Find CBRANCH operation that determines whether zero is set or not.
   *
   * Assuming that op is a 2-branch MULTIEQUAL as per discoverZeroSlot(),
   * try to find a single CBRANCH whose two out edges correspond to the
   * in edges of the MULTIEQUAL. In this case, the boolean expression
   * controlling the CBRANCH is also controlling whether zero flows into
   * the MULTIEQUAL output Varnode.
   * @returns true if a single controlling CBRANCH is found
   */
  discoverCbranch(): boolean {
    const baseBlock: FlowBlock = this.op!.getParent();
    this.zeroBlock = baseBlock.getIn(this.zeroSlot);
    const otherBlock: FlowBlock = baseBlock.getIn(1 - this.zeroSlot);
    if (this.zeroBlock!.sizeOut() === 1) {
      if (this.zeroBlock!.sizeIn() !== 1) return false;
      this.condBlock = this.zeroBlock!.getIn(0);
    } else if (this.zeroBlock!.sizeOut() === 2) {
      this.condBlock = this.zeroBlock;
    } else {
      return false;
    }
    if (this.condBlock!.sizeOut() !== 2) return false;
    if (otherBlock.sizeOut() === 1) {
      if (otherBlock.sizeIn() !== 1) return false;
      if (this.condBlock !== otherBlock.getIn(0)) return false;
    } else if (otherBlock.sizeOut() === 2) {
      if (this.condBlock !== otherBlock) return false;
    } else {
      return false;
    }
    this.cbranch = this.condBlock!.lastOp();
    if (this.cbranch == null) return false;
    if (this.cbranch.code() !== OpCode.CPUI_CBRANCH) return false;
    return true;
  }

  /**
   * Does the condBlock true outgoing edge flow to the block that sets zero.
   *
   * The zeroPathIsTrue variable is set based on the current configuration.
   */
  discoverPathIsTrue(): void {
    if (this.condBlock!.getTrueOut() === this.zeroBlock)
      this.zeroPathIsTrue = true;
    else if (this.condBlock!.getFalseOut() === this.zeroBlock)
      this.zeroPathIsTrue = false;
    else {
      // condBlock must be zeroBlock
      this.zeroPathIsTrue = (this.condBlock!.getTrueOut() === this.op!.getParent());  // True if "true" path does not override zero set
    }
  }

  /**
   * Verify that CBRANCH boolean expression is either (vn == 0) or (vn != 0).
   *
   * Modify zeroPathIsTrue so that if it is true, then: A vn value equal to zero,
   * causes execution to flow to where the output of MULTIEQUAL is set to zero.
   * @param vn is the given Varnode
   * @returns true if the boolean expression has a matching form
   */
  discoverConditionalZero(vn: Varnode): boolean {
    const boolvn: Varnode = this.cbranch!.getIn(1);
    if (!boolvn.isWritten()) return false;
    const compareop: PcodeOp = boolvn.getDef();
    const opc: OpCode = compareop.code();
    if (opc === OpCode.CPUI_INT_NOTEQUAL)          // Verify that CBRANCH depends on INT_NOTEQUAL
      this.zeroPathIsTrue = !this.zeroPathIsTrue;
    else if (opc !== OpCode.CPUI_INT_EQUAL)         // or INT_EQUAL
      return false;
    const a1: Varnode = compareop.getIn(0);
    const a2: Varnode = compareop.getIn(1);
    let zerovn: Varnode;
    if (a1 === vn)           // Verify one side of compare is vn
      zerovn = a2;
    else if (a2 === vn)
      zerovn = a1;
    else
      return false;
    if (!zerovn.isConstant()) return false;
    if (zerovn.getOffset() !== 0n) return false;    // Verify we are comparing to zero
    if (this.cbranch!.isBooleanFlip())
      this.zeroPathIsTrue = !this.zeroPathIsTrue;
    return true;
  }
}

// ---------------------------------------------------------------------------
// RuleOrPredicate
// ---------------------------------------------------------------------------

/**
 * Simplify predication constructions involving the INT_OR operator.
 *
 * In this form of predication, two variables are set based on a condition and then ORed together.
 * Both variables may be set to zero, or to some other value, based on the condition
 * and the zero values are such that at least one of the variables is zero.
 * ```
 *     tmp1 = cond ? val1 : 0;
 *     tmp2 = cond ?  0 : val2;
 *     result = tmp1 | tmp2;
 * ```
 * The RuleOrPredicate simplifies this to
 * ```
 *     if (cond) result = val1; else result = val2;
 * ```
 * or to be precise
 * ```
 *     newtmp = val1 ? val2;                // Using a new MULTIEQUAL
 *     result = newtmp;
 * ```
 * In an alternate form we have
 * ```
 *     tmp1 = (val2 == 0) ? val1 : 0
 *     result = tmp1 | val2;
 * ```
 * again, one of val1 or val2 must be zero, so this gets replaced with
 * ```
 *     tmp1 = val1 ? val2
 *     result = tmp1
 * ```
 */
export class RuleOrPredicate extends Rule {

  /** Constructor */
  constructor(g: string) {
    super(g, 0, "orpredicate");
  }

  /** Clone this rule if it belongs to the given group list */
  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleOrPredicate(this.getGroup());
  }

  /** Get the list of opcodes this rule applies to */
  getOpList(oplist: uint4[]): void {
    oplist.push(OpCode.CPUI_INT_OR);
    oplist.push(OpCode.CPUI_INT_XOR);
  }

  /**
   * Check for the alternate form, tmp1 = (val2 == 0) ? val1 : 0.
   *
   * We know we have the basic form
   * ```
   *     tmp1 = cond ?  val1 : 0;
   *     result = tmp1 | other;
   * ```
   * So we just need to check that other plays the role of val2.
   * If we match the alternate form, perform the simplification.
   * @param vn is the candidate other Varnode
   * @param branch holds the basic form
   * @param op is the INT_OR p-code op
   * @param data is the function being analyzed
   * @returns 1 if the form was matched and simplified, 0 otherwise
   */
  private checkSingle(vn: Varnode, branch: MultiPredicate, op: PcodeOp, data: Funcdata): int4 {
    if (vn.isFree()) return 0;
    if (!branch.discoverCbranch()) return 0;
    if (branch.op!.getOut().loneDescend() !== op) return 0;  // Must only be one use of MULTIEQUAL, because we rewrite it
    branch.discoverPathIsTrue();
    if (!branch.discoverConditionalZero(vn)) return 0;
    if (branch.zeroPathIsTrue) return 0;       // true condition (vn == 0) must not go to zero set
    data.opSetInput(branch.op, vn, branch.zeroSlot);
    data.opRemoveInput(op, 1);
    data.opSetOpcode(op, OpCode.CPUI_COPY);
    data.opSetInput(op, branch.op!.getOut(), 0);
    return 1;
  }

  /**
   * Apply the rule to the given PcodeOp.
   * @param op is the INT_OR or INT_XOR op to check
   * @param data is the function being analyzed
   * @returns 1 if a simplification was performed, 0 otherwise
   */
  applyOp(op: PcodeOp, data: Funcdata): int4 {
    const branch0 = new MultiPredicate();
    const branch1 = new MultiPredicate();
    const test0: boolean = branch0.discoverZeroSlot(op.getIn(0));
    const test1: boolean = branch1.discoverZeroSlot(op.getIn(1));
    if ((!test0) && (!test1)) return 0;
    if (!test0)     // branch1 has MULTIEQUAL form, but branch0 does not
      return this.checkSingle(op.getIn(0), branch1, op, data);
    else if (!test1)  // branch0 has MULTIEQUAL form, but branch1 does not
      return this.checkSingle(op.getIn(1), branch0, op, data);
    if (!branch0.discoverCbranch()) return 0;
    if (!branch1.discoverCbranch()) return 0;
    if (branch0.condBlock === branch1.condBlock) {
      if (branch0.zeroBlock === branch1.zeroBlock) return 0;   // zero sets must be along different paths
    } else {
      // Make sure cbranches have shared condition and the different zero sets have complementary paths
      const condmarker = new BooleanExpressionMatch();
      if (!condmarker.verifyCondition(branch0.cbranch, branch1.cbranch)) return 0;
      if (condmarker.getMultiSlot() !== -1) return 0;
      branch0.discoverPathIsTrue();
      branch1.discoverPathIsTrue();
      let finalBool: boolean = branch0.zeroPathIsTrue === branch1.zeroPathIsTrue;
      if (condmarker.getFlip())
        finalBool = !finalBool;
      if (finalBool) return 0;   // One path hits both zero sets, they must be on different paths
    }
    const order: int4 = branch0.op!.compareOrder(branch1.op);
    if (order === 0) return 0;   // can this happen?
    let finalBlock: BlockBasic;
    let slot0SetsBranch0: boolean;   // True if non-zero setting of branch0 flows through slot0
    if (order < 0) {
      // branch1 happens after
      finalBlock = branch1.op!.getParent();
      slot0SetsBranch0 = branch1.zeroSlot === 0;
    } else {
      // branch0 happens after
      finalBlock = branch0.op!.getParent();
      slot0SetsBranch0 = branch0.zeroSlot === 1;
    }
    const newMulti: PcodeOp = data.newOp(2, finalBlock.getStart());
    data.opSetOpcode(newMulti, OpCode.CPUI_MULTIEQUAL);
    if (slot0SetsBranch0) {
      data.opSetInput(newMulti, branch0.otherVn, 0);
      data.opSetInput(newMulti, branch1.otherVn, 1);
    } else {
      data.opSetInput(newMulti, branch1.otherVn, 0);
      data.opSetInput(newMulti, branch0.otherVn, 1);
    }
    const newvn: Varnode = data.newUniqueOut(branch0.otherVn!.getSize(), newMulti);
    data.opInsertBegin(newMulti, finalBlock);
    data.opRemoveInput(op, 1);
    data.opSetInput(op, newvn, 0);
    data.opSetOpcode(op, OpCode.CPUI_COPY);
    return 1;
  }
}
