// coreaction_part1.ts
// Translation of Ghidra decompiler coreaction.hh (all declarations) and
// coreaction.cc lines 1–1900. Core decompilation actions independent of architecture.
//
// Licensed under the Apache License, Version 2.0

// =====================================================================
// Imports needed by parts 1, 2, and 3
// =====================================================================

import { Action, ActionGroupList, ActionGroup, ActionPool, ActionRestartGroup, ActionDatabase, Rule } from './action.js';
import { Funcdata, AncestorRealistic } from './funcdata.js';
import { Varnode } from './varnode.js';
import { PcodeOp, PieceNode } from './op.js';
import { OpCode } from '../core/opcodes.js';
import { Address, SeqNum, calc_mask, coveringmask, minimalmask, leastsigbit_set, bit_transitions, sign_extend } from '../core/address.js';
import { AddrSpace, spacetype } from '../core/space.js';
import { type_metatype, Datatype } from './type.js';
import { ParamActive as RealParamActive } from './fspec.js';
import { functionalEquality, functionalEqualityLevel } from './expression.js';
import { Merge as RealMerge } from './merge.js';
import { LowlevelError } from '../core/error.js';
import { ListIter } from '../util/listiter.js';
import { DynamicHash } from './dynamic.js';
import { LaneDescription } from './transform.js';
import { ResolvedUnion } from './unionresolve.js';
import { VarnodeData } from '../core/pcoderaw.js';

// =====================================================================
// Forward declarations / type aliases for types not yet available
// =====================================================================

// Forward-declared types used only as types
export type Architecture = any;
export type BlockBasic = BlockBasicClass;
export type BlockGraph = RealBlockGraph;
export type FuncProto = any;
export type ProtoParameter = any;
export type ParamTrial = any;
export type TrackedContext = any;
export type TrackedSet = any;
export type ScopeLocal = any;
export type Scope = any;
export type SymbolEntry = any;
export type Symbol = any;
export type HighVariable = any;
export type CastStrategy = any;
export type LanedRegister = any;
export type SegmentOp = any;
export type InjectPayload = any;
export type JumpTable = any;
export type IteratorSTL<T> = any;
export type TypeFactory = any;
export type TypePointer = any;
export type TypeArray = any;
export type TypeStruct = any;
export type TypeUnion = any;
export type TypeCode = any;
export type TypeSpacebase = any;
export type AddrSpaceManager = any;

// Forward-declared types also used as values (with new, or accessing statics)
// Use 'declare' blocks to merge type + value
const _any_cls: any = class {} as any;
const _any_obj: any = {} as any;
export type FlowBlock = RealFlowBlock; export const FlowBlock = RealFlowBlock;
export type FuncCallSpecs = RealFuncCallSpecs; export const FuncCallSpecs = RealFuncCallSpecs;
export type ProtoModel = RealProtoModel; export const ProtoModel = RealProtoModel;
const ParamActive = RealParamActive;
type ParamActive = RealParamActive;
export type EffectRecord = RealEffectRecord; export const EffectRecord = RealEffectRecord;
const Merge = RealMerge;
type Merge = RealMerge;
export type LaneDivide = RealLaneDivide; export const LaneDivide = RealLaneDivide;
// AliasChecker imported below
// AncestorRealistic imported below
// Action imports from blockaction.ts and condexe.ts
import { ActionBlockStructure, ActionPreferComplement, ActionStructureTransform, ActionNormalizeBranches, ActionReturnSplit, ActionNodeJoin, ActionFinalStructure } from './blockaction.js';
import { ActionConditionalExe } from './condexe.js';
import { AliasChecker } from './varmap.js';
import { FlowBlock as RealFlowBlock, BlockBasicClass, BlockGraph as RealBlockGraph } from './block.js';
import { FuncCallSpecs as RealFuncCallSpecs, ProtoModel as RealProtoModel, EffectRecord as RealEffectRecord } from './fspec.js';
import { LaneDivide as RealLaneDivide } from './subflow.js';

// Helper to iterate C++-style begin/end pairs
export function iteratorRange<T>(begin: Iterable<T>, _end?: any): Iterable<T> {
  return begin;
}

// PcodeOpNode: a (PcodeOp, slot) pair for tracking phi-node edges
export class PcodeOpNode {
  op: PcodeOp;
  slot: number;
  constructor(o: PcodeOp, s: number) { this.op = o; this.slot = s; }
  static compare(a: PcodeOpNode, b: PcodeOpNode): number {
    if (a.op !== b.op) return a.op.getSeqNum().getOrder() - b.op.getSeqNum().getOrder();
    return a.slot - b.slot;
  }
}

// Helper for binary search in sorted PcodeOpNode array
export function binarySearch(arr: PcodeOpNode[], target: PcodeOpNode): boolean {
  let lo = 0;
  let hi = arr.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const cmp = PcodeOpNode.compare(arr[mid], target);
    if (cmp < 0) lo = mid + 1;
    else if (cmp > 0) hi = mid - 1;
    else return true;
  }
  return false;
}

// =====================================================================
// Rule imports (used in universalAction in part 3)
// =====================================================================

import {
  RuleEarlyRemoval, RuleTermOrder, RuleSelectCse, RuleCollectTerms,
  RulePullsubMulti, RulePullsubIndirect, RulePushMulti,
  RuleSborrow, RuleScarry, RuleIntLessEqual,
  RuleTrivialArith, RuleTrivialBool, RuleTrivialShift,
  RuleSignShift, RuleTestSign, RuleIdentityEl,
  RuleOrMask, RuleAndMask, RuleOrConsume, RuleOrCollapse, RuleAndOrLump,
  RuleShiftBitops, RuleRightShiftAnd,
  RuleNotDistribute, RuleHighOrderAnd, RuleAndDistribute,
  RuleAndCommute, RuleAndPiece, RuleAndZext, RuleAndCompare,
  RuleDoubleSub, RuleDoubleShift, RuleDoubleArithShift,
  RuleConcatShift, RuleLeftRight, RuleShiftCompare,
  RuleShift2Mult, RuleShiftPiece,
  RuleMultiCollapse, RuleIndirectCollapse,
  Rule2Comp2Mult, RuleSub2Add, RuleCarryElim,
  RuleBxor2NotEqual, RuleLess2Zero, RuleLessEqual2Zero, RuleSLess2Zero,
  RuleEqual2Zero, RuleEqual2Constant, RuleThreeWayCompare,
  RuleXorCollapse, RuleAddMultCollapse,
  RuleCollapseConstants, RuleTransformCpool, RulePropagateCopy,
  RuleZextEliminate, RuleSlessToLess, RuleZextSless,
  RuleBitUndistribute, RuleBooleanUndistribute, RuleBooleanDedup,
  RuleBoolZext, RuleBooleanNegate, RuleLogic2Bool,
  RuleSubExtComm, RuleSubCommute,
  RuleConcatCommute, RuleConcatZext, RuleZextCommute, RuleZextShiftZext,
  RuleShiftAnd, RuleConcatZero, RuleConcatLeftShift,
  RuleSubZext, RuleSubCancel,
  RuleNegateIdentity, RuleSubNormal,
  RulePositiveDiv, RuleDivTermAdd, RuleDivTermAdd2, RuleDivOpt,
  RuleSignForm, RuleSignForm2, RuleSignDiv2, RuleDivChain,
  RuleSignNearMult, RuleModOpt,
  RuleSignMod2nOpt, RuleSignMod2nOpt2, RuleSignMod2Opt,
  RuleBoolNegate, RuleLessEqual, RuleLessNotEqual, RuleLessOne,
  RuleRangeMeld, RuleFloatRange,
  RulePiece2Zext, RulePiece2Sext,
  RulePopcountBoolXor, RuleXorSwap, RuleLzcountShiftBool,
  RuleFloatSign, RuleOrCompare,
  RulePtrFlow, RuleNegateNegate, RuleConditionalMove,
  RuleFuncPtrEncoding, RuleFloatCast, RuleIgnoreNan,
  RuleUnsigned2Float, RuleInt2FloatCollapse,
  RulePtraddUndo, RulePtrsubUndo, RuleSegment,
  RulePiecePathology,
  RulePushPtr, RuleStructOffset0, RulePtrArith,
  RuleLoadVarnode, RuleStoreVarnode,
  RuleMultNegOne, RuleAddUnsigned, Rule2Comp2Sub,
  RuleSubRight, RuleFloatSignCleanup, RuleExpandLoad,
  RulePtrsubCharConstant, RuleExtensionPush, RulePieceStructure,
} from './ruleaction.js';

import {
  RuleSubvarAnd, RuleSubvarSubpiece, RuleSubvarCompZero,
  RuleSubvarShift, RuleSubvarZext, RuleSubvarSext, RuleSplitFlow,
  RuleSplitCopy, RuleSplitLoad, RuleSplitStore,
  RuleDumptyHumpLate, RuleSubfloatConvert,
} from './subflow.js';

import { RuleDoubleIn, RuleDoubleOut, RuleDoubleLoad, RuleDoubleStore, SplitVarnode } from './double.js';
import { RuleStringCopy, RuleStringStore } from './constseq.js';
import { RuleOrPredicate } from './condexe.js';

// =====================================================================
// Minimal stubs for Rule subclasses not yet fully implemented
// =====================================================================

class RuleShiftSub extends Rule {
  constructor(g: string) { super(g, 0, "shiftsub"); }
  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleShiftSub(this.getGroup());
  }
  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_SUBPIECE);
  }
  applyOp(op: PcodeOp, data: Funcdata): number {
    if (!op.getIn(0)!.isWritten()) return 0;
    const shiftop: PcodeOp = op.getIn(0)!.getDef()!;
    if (shiftop.code() !== OpCode.CPUI_INT_LEFT) return 0;
    const sa: Varnode = shiftop.getIn(1)!;
    if (!sa.isConstant()) return 0;
    const n: number = Number(sa.getOffset());
    if ((n & 7) !== 0) return 0;       // Must shift by a multiple of 8 bits
    let c: number = Number(op.getIn(1)!.getOffset());
    const vn: Varnode = shiftop.getIn(0)!;
    if (vn.isFree()) return 0;
    const insize: number = vn.getSize();
    const outsize: number = op.getOut()!.getSize();
    c -= n / 8;
    if (c < 0 || c + outsize > insize)  // Check if this is a natural truncation
      return 0;
    data.opSetInput(op, vn, 0);
    data.opSetInput(op, data.newConstant(op.getIn(1)!.getSize(), BigInt(c)), 1);
    return 1;
  }
}

class RuleHumptyDumpty extends Rule {
  constructor(g: string) { super(g, 0, "humptydumpty"); }
  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleHumptyDumpty(this.getGroup());
  }
  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_PIECE);
  }
  applyOp(op: PcodeOp, data: Funcdata): number {
    // op is PIECE (put together)
    const vn1: Varnode = op.getIn(0)!;  // Most significant piece
    if (!vn1.isWritten()) return 0;
    const sub1: PcodeOp = vn1.getDef()!;
    if (sub1.code() !== OpCode.CPUI_SUBPIECE) return 0;
    const vn2: Varnode = op.getIn(1)!;  // Least significant piece
    if (!vn2.isWritten()) return 0;
    const sub2: PcodeOp = vn2.getDef()!;
    if (sub2.code() !== OpCode.CPUI_SUBPIECE) return 0;

    const root: Varnode = sub1.getIn(0)!;
    if (root !== sub2.getIn(0)!) return 0;  // Must be pieces of the same whole

    const pos1: bigint = sub1.getIn(1)!.getOffset();
    const pos2: bigint = sub2.getIn(1)!.getOffset();
    const size1: number = vn1.getSize();
    const size2: number = vn2.getSize();

    if (pos1 !== pos2 + BigInt(size2)) return 0;  // Pieces do not match up

    if (pos2 === 0n && (size1 + size2 === root.getSize())) {
      // Pieced together whole thing
      data.opRemoveInput(op, 1);
      data.opSetInput(op, root, 0);
      data.opSetOpcode(op, OpCode.CPUI_COPY);
    } else {
      // Pieced together a larger part of the whole
      data.opSetInput(op, root, 0);
      data.opSetInput(op, data.newConstant(sub2.getIn(1)!.getSize(), pos2), 1);
      data.opSetOpcode(op, OpCode.CPUI_SUBPIECE);
    }
    return 1;
  }
}

class RuleDumptyHump extends Rule {
  constructor(g: string) { super(g, 0, "dumptyhump"); }
  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleDumptyHump(this.getGroup());
  }
  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_SUBPIECE);
  }
  applyOp(op: PcodeOp, data: Funcdata): number {
    // If we append something to a varnode and then take a subpiece that
    // cuts off what we just appended, treat whole thing as COPY
    const base: Varnode = op.getIn(0)!;
    if (!base.isWritten()) return 0;
    const pieceop: PcodeOp = base.getDef()!;
    if (pieceop.code() !== OpCode.CPUI_PIECE) return 0;
    let offset: number = Number(op.getIn(1)!.getOffset());
    const outsize: number = op.getOut()!.getSize();

    const vn1: Varnode = pieceop.getIn(0)!;  // Most significant
    const vn2: Varnode = pieceop.getIn(1)!;  // Least significant

    let vn: Varnode;
    if (offset < vn2.getSize()) {  // Sub draws from vn2
      if (offset + outsize > vn2.getSize()) return 0;  // Also from vn1
      vn = vn2;
    } else {  // Sub draws from vn1
      vn = vn1;
      offset -= vn2.getSize();  // offset relative to vn1
    }

    if (vn.isFree() && !vn.isConstant()) return 0;
    if (offset === 0 && outsize === vn.getSize()) {
      // Eliminate SUB and CONCAT altogether
      data.opSetOpcode(op, OpCode.CPUI_COPY);
      data.opRemoveInput(op, 1);
      data.opSetInput(op, vn, 0);  // Skip over CONCAT
    } else {
      // Eliminate CONCAT and adjust SUB
      data.opSetInput(op, vn, 0);  // Skip over CONCAT
      data.opSetInput(op, data.newConstant(4, BigInt(offset)), 1);
    }
    return 1;
  }
}

class RuleHumptyOr extends Rule {
  constructor(g: string) { super(g, 0, "humptyor"); }
  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleHumptyOr(this.getGroup());
  }
}

class RuleSwitchSingle extends Rule {
  constructor(g: string) { super(g, 0, "switchsingle"); }
  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSwitchSingle(this.getGroup());
  }
}

class RuleCondNegate extends Rule {
  constructor(g: string) { super(g, 0, "condnegate"); }
  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleCondNegate(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(OpCode.CPUI_CBRANCH);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (!op.isBooleanFlip()) return 0;

    const vn: Varnode = op.getIn(1)!;
    const newop: PcodeOp = data.newOp(1, op.getAddr());
    data.opSetOpcode(newop, OpCode.CPUI_BOOL_NEGATE);
    const outvn: Varnode = data.newUniqueOut(1, newop);
    data.opSetInput(newop, vn, 0);
    data.opSetInput(op, outvn, 1);
    data.opInsertBefore(newop, op);
    data.opFlipCondition(op);  // Flip meaning of condition
    // NOTE fallthru block is still same status
    return 1;
  }
}


// =====================================================================
// Helper: ConstPoint interface and constructors (shared with part 3)
// =====================================================================

export interface ConstPoint {
  vn: Varnode;
  constVn: Varnode | null;
  value: bigint;
  constBlock: FlowBlock;
  inSlot: number;
  blockIsDom: boolean;
}

export function makeConstPointFromVn(v: Varnode, c: Varnode, bl: FlowBlock, slot: number, isDom: boolean): ConstPoint {
  return { vn: v, constVn: c, value: c.getOffset(), constBlock: bl, inSlot: slot, blockIsDom: isDom };
}

export function makeConstPointFromVal(v: Varnode, val: bigint, bl: FlowBlock, slot: number, isDom: boolean): ConstPoint {
  return { vn: v, constVn: null, value: val, constBlock: bl, inSlot: slot, blockIsDom: isDom };
}

// =====================================================================
// Helper: OpStackElement (shared with part 2 for ActionMarkExplicit)
// =====================================================================

export class OpStackElement {
  vn: Varnode;
  slot: number;
  slotback: number;

  constructor(v: Varnode) {
    this.vn = v;
    this.slot = 0;
    this.slotback = 0;
    if (v.isWritten()) {
      const opc: OpCode = v.getDef()!.code();
      if (opc === OpCode.CPUI_LOAD) {
        this.slot = 1;
        this.slotback = 2;
      } else if (opc === OpCode.CPUI_PTRADD)
        this.slotback = 1; // Don't traverse the multiplier slot
      else if (opc === OpCode.CPUI_SEGMENTOP) {
        this.slot = 2;
        this.slotback = 3;
      } else
        this.slotback = v.getDef()!.numInput();
    }
  }
}

// =====================================================================
// Helper: DescTreeElement (shared with part 2 for ActionMarkImplied)
// =====================================================================

export class DescTreeElement {
  vn: Varnode;
  desciter: IterableIterator<PcodeOp>;
  private _current: IteratorResult<PcodeOp>;

  constructor(v: Varnode) {
    this.vn = v;
    this.desciter = (v as any).descend[Symbol.iterator]();
    this._current = this.desciter.next();
  }

  get done(): boolean {
    return this._current.done === true;
  }

  advance(): PcodeOp {
    const val = this._current.value;
    this._current = this.desciter.next();
    return val;
  }
}

// =====================================================================
// Helper: OpRecommend interface (shared with part 2 for ActionNameVars)
// =====================================================================

export interface OpRecommend {
  ct: Datatype | null;
  namerec: string;
}

// =====================================================================
// Internal helpers: StackEqn and StackSolver
// =====================================================================

/** A stack equation: var1 - var2 = rhs */
interface StackEqn {
  var1: number;
  var2: number;
  rhs: number;
}

function stackEqnCompare(a: StackEqn, b: StackEqn): number {
  return a.var1 - b.var1;
}

/**
 * A class that solves for stack-pointer changes across unknown sub-functions.
 */
class StackSolver {
  private eqs: StackEqn[] = [];
  private guess: StackEqn[] = [];
  private vnlist: Varnode[] = [];
  private companion: number[] = [];
  private spacebase: Address = Address.invalid();
  private soln: number[] = [];
  private missedvariables: number = 0;

  /** Duplicate each equation, multiplying by -1 */
  private duplicate(): void {
    const size = this.eqs.length;
    for (let i = 0; i < size; ++i) {
      const eqn: StackEqn = {
        var1: this.eqs[i].var2,
        var2: this.eqs[i].var1,
        rhs: -this.eqs[i].rhs
      };
      this.eqs.push(eqn);
    }
    this.eqs.sort(stackEqnCompare);
  }

  /** Propagate solution for one variable to other variables */
  private propagate(varnum: number, val: number): void {
    if (this.soln[varnum] !== 65535) return;
    this.soln[varnum] = val;

    const workstack: number[] = [];
    workstack.push(varnum);

    while (workstack.length > 0) {
      varnum = workstack.pop()!;

      // Binary search for first equation with var1 == varnum
      let lo = 0;
      let hi = this.eqs.length;
      while (lo < hi) {
        const mid = (lo + hi) >>> 1;
        if (this.eqs[mid].var1 < varnum) lo = mid + 1;
        else hi = mid;
      }
      let top = lo;
      while (top < this.eqs.length && this.eqs[top].var1 === varnum) {
        const var2 = this.eqs[top].var2;
        if (this.soln[var2] === 65535) {
          this.soln[var2] = this.soln[varnum] - this.eqs[top].rhs;
          workstack.push(var2);
        }
        ++top;
      }
    }
  }

  /** Solve the system of equations */
  solve(): void {
    this.soln = new Array(this.vnlist.length).fill(65535);
    this.duplicate();

    this.propagate(0, 0); // We know one variable

    const size = this.guess.length;
    let lastcount = size + 2;
    let count: number;
    do {
      count = 0;
      for (let i = 0; i < size; ++i) {
        const var1 = this.guess[i].var1;
        const var2 = this.guess[i].var2;
        if (this.soln[var1] !== 65535 && this.soln[var2] === 65535)
          this.propagate(var2, this.soln[var1] - this.guess[i].rhs);
        else if (this.soln[var1] === 65535 && this.soln[var2] !== 65535)
          this.propagate(var1, this.soln[var2] + this.guess[i].rhs);
        else if (this.soln[var1] === 65535 && this.soln[var2] === 65535)
          count += 1;
      }
      if (count === lastcount) break;
      lastcount = count;
    } while (count > 0);
  }

  /** Build the system of equations */
  build(data: Funcdata, id: AddrSpace, spcbase: number): void {
    const spacebasedata: VarnodeData = id.getSpacebase(spcbase);
    this.spacebase = new Address(spacebasedata.space! as any, spacebasedata.offset);

    let begiter = data.beginLocSizeAddr(spacebasedata.size, this.spacebase);
    const enditer = data.endLocSizeAddr(spacebasedata.size, this.spacebase);

    while (!begiter.equals(enditer)) {
      const vn: Varnode = begiter.get();
      begiter.next();
      if (vn.isFree()) break;
      this.vnlist.push(vn);
      this.companion.push(-1);
    }
    this.missedvariables = 0;
    if (this.vnlist.length === 0) return;
    if (!this.vnlist[0].isInput())
      throw new LowlevelError("Input value of stackpointer is not used");

    for (let i = 1; i < this.vnlist.length; ++i) {
      const vn = this.vnlist[i];
      let othervn: Varnode;
      let constvn: Varnode;
      const op: PcodeOp = vn.getDef()!;
      const eqn: StackEqn = { var1: 0, var2: 0, rhs: 0 };

      if (op.code() === OpCode.CPUI_INT_ADD) {
        othervn = op.getIn(0)!;
        constvn = op.getIn(1)!;
        if (othervn.isConstant()) {
          constvn = othervn;
          othervn = op.getIn(1)!;
        }
        if (!constvn.isConstant()) { this.missedvariables += 1; continue; }
        if (!othervn.getAddr().equals(this.spacebase)) { this.missedvariables += 1; continue; }
        const idx = this.findVarIndex(othervn);
        eqn.var1 = i;
        eqn.var2 = idx;
        eqn.rhs = Number(constvn.getOffset());
        this.eqs.push({ ...eqn });
      }
      else if (op.code() === OpCode.CPUI_COPY) {
        othervn = op.getIn(0)!;
        if (!othervn.getAddr().equals(this.spacebase)) { this.missedvariables += 1; continue; }
        const idx = this.findVarIndex(othervn);
        eqn.var1 = i;
        eqn.var2 = idx;
        eqn.rhs = 0;
        this.eqs.push({ ...eqn });
      }
      else if (op.code() === OpCode.CPUI_INDIRECT) {
        othervn = op.getIn(0)!;
        if (!othervn.getAddr().equals(this.spacebase)) { this.missedvariables += 1; continue; }
        const idx = this.findVarIndex(othervn);
        eqn.var1 = i;
        eqn.var2 = idx;
        this.companion[i] = idx;
        const iopvn: Varnode = op.getIn(1)!;
        if (iopvn.getSpace() !== null && iopvn.getSpace()!.getType() === spacetype.IPTR_IOP) {
          const iop: PcodeOp | null = PcodeOp.getOpFromConst(iopvn.getAddr());
          if (iop !== null) {
            const fc: FuncCallSpecs | null = data.getCallSpecs(iop);
            if (fc !== null) {
              if (fc.getExtraPop() !== ProtoModel.extrapop_unknown) {
                eqn.rhs = fc.getExtraPop();
                this.eqs.push({ ...eqn });
                continue;
              }
            }
          }
        }
        eqn.rhs = 4; // Otherwise make a guess
        this.guess.push({ ...eqn });
      }
      else if (op.code() === OpCode.CPUI_MULTIEQUAL) {
        for (let j = 0; j < op.numInput(); ++j) {
          othervn = op.getIn(j)!;
          if (!othervn.getAddr().equals(this.spacebase)) { this.missedvariables += 1; continue; }
          const idx = this.findVarIndex(othervn);
          this.eqs.push({ var1: i, var2: idx, rhs: 0 });
        }
      }
      else if (op.code() === OpCode.CPUI_INT_AND) {
        othervn = op.getIn(0)!;
        constvn = op.getIn(1)!;
        if (othervn.isConstant()) {
          constvn = othervn;
          othervn = op.getIn(1)!;
        }
        if (!constvn.isConstant()) { this.missedvariables += 1; continue; }
        if (!othervn.getAddr().equals(this.spacebase)) { this.missedvariables += 1; continue; }
        const idx = this.findVarIndex(othervn);
        eqn.var1 = i;
        eqn.var2 = idx;
        eqn.rhs = 0; // Treat as a copy
        this.eqs.push({ ...eqn });
      }
      else {
        this.missedvariables += 1;
      }
    }
  }

  /** Find variable index via binary search (lower_bound) */
  private findVarIndex(vn: Varnode): number {
    let lo = 0;
    let hi = this.vnlist.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (Varnode.comparePointers(this.vnlist[mid], vn))
        lo = mid + 1;
      else
        hi = mid;
    }
    return lo;
  }

  getNumVariables(): number { return this.vnlist.length; }
  getVariable(i: number): Varnode { return this.vnlist[i]; }
  getCompanion(i: number): number { return this.companion[i]; }
  getSolution(i: number): number { return this.soln[i]; }
}

// =====================================================================
// PART 1: Action subclass declarations and implementations
// =====================================================================

// ---------------------
// ActionStart
// ---------------------

/** Gather raw p-code for a function. */
export class ActionStart extends Action {
  constructor(g: string) {
    super(0, "start", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionStart(this.getGroup());
  }

  apply(data: Funcdata): number {
    data.startProcessing();
    return 0;
  }
}

// ---------------------
// ActionStop
// ---------------------

/** Do any post-processing after decompilation. */
export class ActionStop extends Action {
  constructor(g: string) {
    super(0, "stop", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionStop(this.getGroup());
  }

  apply(data: Funcdata): number {
    data.stopProcessing();
    return 0;
  }
}

// ---------------------
// ActionStartCleanUp
// ---------------------

/** Start clean up after main transform phase. */
export class ActionStartCleanUp extends Action {
  constructor(g: string) {
    super(0, "startcleanup", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionStartCleanUp(this.getGroup());
  }

  apply(data: Funcdata): number {
    data.startCleanUp();
    return 0;
  }
}

// ---------------------
// ActionStartTypes
// ---------------------

/** Allow type recovery to start happening. */
export class ActionStartTypes extends Action {
  constructor(g: string) {
    super(0, "starttypes", g);
  }

  reset(data: Funcdata): void {
    data.setTypeRecovery(true);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionStartTypes(this.getGroup());
  }

  apply(data: Funcdata): number {
    if (data.startTypeRecovery())
      this.count += 1;
    return 0;
  }
}

// ---------------------
// ActionStackPtrFlow
// ---------------------

/** Analyze change to the stack pointer across sub-function calls. */
export class ActionStackPtrFlow extends Action {
  private stackspace: AddrSpace | null;
  private analysis_finished: boolean = false;

  constructor(g: string, ss: AddrSpace | null) {
    super(0, "stackptrflow", g);
    this.stackspace = ss;
  }

  reset(data: Funcdata): void {
    this.analysis_finished = false;
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionStackPtrFlow(this.getGroup(), this.stackspace);
  }

  /** Calculate stack-pointer change across undetermined sub-functions. */
  private static analyzeExtraPop(data: Funcdata, stackspace: AddrSpace, spcbase: number): void {
    let myfp: ProtoModel = data.getArch().evalfp_called;
    if (myfp === null)
      myfp = data.getArch().defaultfp;
    if (myfp.getExtraPop() !== ProtoModel.extrapop_unknown) return;

    const solver = new StackSolver();
    try {
      solver.build(data, stackspace, spcbase);
    } catch (err: any) {
      const msg = "Stack frame is not setup normally: " + (err.explain || err.message || String(err));
      data.warningHeader(msg);
      return;
    }
    if (solver.getNumVariables() === 0) return;
    solver.solve();

    const invn: Varnode = solver.getVariable(0);
    let warningprinted = false;

    for (let i = 1; i < solver.getNumVariables(); ++i) {
      const vn: Varnode = solver.getVariable(i);
      const soln: number = solver.getSolution(i);
      if (soln === 65535) {
        if (!warningprinted) {
          data.warningHeader("Unable to track spacebase fully for " + stackspace.getName());
          warningprinted = true;
        }
        continue;
      }
      const op: PcodeOp = vn.getDef()!;

      if (op.code() === OpCode.CPUI_INDIRECT) {
        const iopvn: Varnode = op.getIn(1)!;
        if (iopvn.getSpace() !== null && iopvn.getSpace()!.getType() === spacetype.IPTR_IOP) {
          const iop: PcodeOp | null = PcodeOp.getOpFromConst(iopvn.getAddr());
          if (iop !== null) {
            const fc: FuncCallSpecs | null = data.getCallSpecs(iop);
            if (fc !== null) {
              let soln2 = 0;
              const comp = solver.getCompanion(i);
              if (comp >= 0)
                soln2 = solver.getSolution(comp);
              fc.setEffectiveExtraPop(soln - soln2);
            }
          }
        }
      }
      const paramlist: Varnode[] = [];
      paramlist.push(invn);
      const sz = invn.getSize();
      paramlist.push(data.newConstant(sz, BigInt(soln) & calc_mask(sz)));
      data.opSetOpcode(op, OpCode.CPUI_INT_ADD);
      data.opSetAllInput(op, paramlist);
    }
  }

  /** Is the given Varnode defined as a pointer relative to the stack-pointer? */
  private static isStackRelative(spcbasein: Varnode, vn: Varnode, constval: { value: bigint }): boolean {
    if (spcbasein === vn) {
      constval.value = 0n;
      return true;
    }
    if (!vn.isWritten()) return false;
    const addop: PcodeOp = vn.getDef()!;
    if (addop.code() !== OpCode.CPUI_INT_ADD) return false;
    if (addop.getIn(0) !== spcbasein) return false;
    const constvn: Varnode = addop.getIn(1)!;
    if (!constvn.isConstant()) return false;
    constval.value = constvn.getOffset();
    return true;
  }

  /** Adjust the LOAD where the stack-pointer alias has been recovered. */
  private static adjustLoad(data: Funcdata, loadop: PcodeOp, storeop: PcodeOp): boolean {
    let vn: Varnode = storeop.getIn(2)!;
    if (vn.isConstant())
      vn = data.newConstant(vn.getSize(), vn.getOffset());
    else if (vn.isFree())
      return false;

    data.opRemoveInput(loadop, 1);
    data.opSetOpcode(loadop, OpCode.CPUI_COPY);
    data.opSetInput(loadop, vn, 0);
    return true;
  }

  /** Link LOAD to matching STORE of a constant. */
  private static repair(data: Funcdata, id: AddrSpace, spcbasein: Varnode, loadop: PcodeOp, constz: bigint): number {
    const loadsize: number = loadop.getOut()!.getSize();
    let curblock: BlockBasic = loadop.getParent();
    let begiter = curblock.beginOp();
    let iter = new ListIter<PcodeOp>(curblock.op, loadop.getBasicIter());
    for (;;) {
      if (iter.equals(begiter)) {
        if (curblock.sizeIn() !== 1) return 0;
        curblock = curblock.getIn(0) as BlockBasic;
        begiter = curblock.beginOp();
        iter = curblock.endOp();
        continue;
      } else {
        iter.prev();
      }
      const curop: PcodeOp = iter.get() as PcodeOp;
      if (curop.isCall()) return 0;
      if (curop.code() === OpCode.CPUI_STORE) {
        const ptrvn: Varnode = curop.getIn(1)!;
        const datavn: Varnode = curop.getIn(2)!;
        const constnew = { value: 0n };
        if (ActionStackPtrFlow.isStackRelative(spcbasein, ptrvn, constnew)) {
          if (constnew.value === constz && loadsize === datavn.getSize()) {
            if (ActionStackPtrFlow.adjustLoad(data, loadop, curop))
              return 1;
            return 0;
          } else if (constnew.value <= constz + BigInt(loadsize - 1) &&
            constnew.value + BigInt(datavn.getSize() - 1) >= constz)
            return 0;
        } else
          return 0;
      } else {
        const outvn: Varnode | null = curop.getOut();
        if (outvn !== null) {
          if (outvn.getSpace() === id) return 0;
        }
      }
    }
  }

  /** Find any stack pointer clogs and pass it on to the repair routines. */
  private static checkClog(data: Funcdata, id: AddrSpace, spcbase: number): number {
    const spacebasedata: VarnodeData = id.getSpacebase(spcbase);
    const spacebase = new Address(spacebasedata.space! as any, spacebasedata.offset);
    let clogcount = 0;

    let begiter = data.beginLocSizeAddr(spacebasedata.size, spacebase);
    const enditer = data.endLocSizeAddr(spacebasedata.size, spacebase);

    let spcbasein: Varnode;
    if (begiter.equals(enditer)) return clogcount;
    spcbasein = begiter.get(); begiter.next();
    if (!spcbasein.isInput()) return clogcount;

    while (!begiter.equals(enditer)) {
      const outvn: Varnode = begiter.get(); begiter.next();
      if (!outvn.isWritten()) continue;
      const addop: PcodeOp = outvn.getDef()!;
      if (addop.code() !== OpCode.CPUI_INT_ADD) continue;
      let y: Varnode = addop.getIn(1)!;
      if (!y.isWritten()) continue;
      let x: Varnode = addop.getIn(0)!;
      const constx = { value: 0n };
      if (!ActionStackPtrFlow.isStackRelative(spcbasein, x, constx)) {
        x = y;
        y = addop.getIn(0)!;
        if (!ActionStackPtrFlow.isStackRelative(spcbasein, x, constx)) continue;
      }
      let loadop: PcodeOp = y.getDef()!;
      if (loadop.code() === OpCode.CPUI_INT_MULT) {
        const constvn: Varnode = loadop.getIn(1)!;
        if (!constvn.isConstant()) continue;
        if (constvn.getOffset() !== calc_mask(constvn.getSize())) continue;
        y = loadop.getIn(0)!;
        if (!y.isWritten()) continue;
        loadop = y.getDef()!;
      }
      if (loadop.code() !== OpCode.CPUI_LOAD) continue;
      const ptrvn: Varnode = loadop.getIn(1)!;
      const constz = { value: 0n };
      if (!ActionStackPtrFlow.isStackRelative(spcbasein, ptrvn, constz)) continue;
      clogcount += ActionStackPtrFlow.repair(data, id, spcbasein, loadop, constz.value);
    }
    return clogcount;
  }

  apply(data: Funcdata): number {
    if (this.analysis_finished)
      return 0;
    if (this.stackspace === null) {
      this.analysis_finished = true;
      return 0;
    }
    const numchange = ActionStackPtrFlow.checkClog(data, this.stackspace, 0);
    if (numchange > 0) {
      this.count += 1;
    }
    if (numchange === 0) {
      ActionStackPtrFlow.analyzeExtraPop(data, this.stackspace, 0);
      this.analysis_finished = true;
    }
    return 0;
  }
}

// ---------------------
// ActionLaneDivide
// ---------------------

/** Find Varnodes with a vectorized lane scheme and attempt to split the lanes. */
export class ActionLaneDivide extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "lanedivide", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionLaneDivide(this.getGroup());
  }

  /** Examine ops using the given Varnode to determine possible lane sizes. */
  private collectLaneSizes(vn: Varnode, allowedLanes: LanedRegister, checkLanes: LanedRegister): void {
    let step = 0; // 0 = descendants, 1 = def, 2 = done
    const descIter = (vn as any).descend[Symbol.iterator]();
    let descResult = descIter.next();
    if (descResult.done) {
      step = 1;
    }
    while (step < 2) {
      let curSize: number;
      if (step === 0) {
        const op: PcodeOp = descResult.value;
        descResult = descIter.next();
        if (descResult.done) step = 1;
        if (op.code() !== OpCode.CPUI_SUBPIECE) continue;
        curSize = op.getOut()!.getSize();
      } else {
        step = 2;
        if (!vn.isWritten()) continue;
        const op: PcodeOp = vn.getDef()!;
        if (op.code() !== OpCode.CPUI_PIECE) continue;
        curSize = op.getIn(0)!.getSize();
        const tmpSize = op.getIn(1)!.getSize();
        if (tmpSize < curSize)
          curSize = tmpSize;
      }
      if (allowedLanes.allowedLane(curSize))
        checkLanes.addLaneSize(curSize);
    }
  }

  /** Search for a likely lane size and try to divide a single Varnode into these lanes. */
  private processVarnode(data: Funcdata, vn: Varnode, lanedRegister: LanedRegister, mode: number): boolean {
    const checkLanes: LanedRegister = new (lanedRegister.constructor as any)();
    const allowDowncast = (mode > 0);
    if (mode < 2)
      this.collectLaneSizes(vn, lanedRegister, checkLanes);
    else {
      let defaultSize = data.getArch().types.getSizeOfPointer();
      if (defaultSize !== 4)
        defaultSize = 8;
      checkLanes.addLaneSize(defaultSize);
    }
    for (const curSize of checkLanes) {
      const description: LaneDescription = new (LaneDescription as any)(lanedRegister.getWholeSize(), curSize);
      const laneDivide: LaneDivide = new (LaneDivide as any)(data, vn, description, allowDowncast);
      if (laneDivide.doTrace()) {
        laneDivide.apply();
        this.count += 1;
        return true;
      }
    }
    return false;
  }

  apply(data: Funcdata): number {
    data.setLanedRegGenerated();
    for (let mode = 0; mode < 3; ++mode) {
      let allStorageProcessed = true;
      for (const [vdata, lanedReg] of data.beginLaneAccess()) {
        const addr: Address = new Address((vdata as any).space, (vdata as any).offset);
        const sz: number = (vdata as any).size;
        let viter = data.beginLocSizeAddr(sz, addr);
        let venditer = data.endLocSizeAddr(sz, addr);
        let allVarnodesProcessed = true;
        while (!viter.equals(venditer)) {
          const vn: Varnode = viter.get(); viter.next();
          if (vn.hasNoDescend()) continue;
          if (this.processVarnode(data, vn, lanedReg, mode)) {
            viter = data.beginLocSizeAddr(sz, addr);
            venditer = data.endLocSizeAddr(sz, addr);
            allVarnodesProcessed = true;
          } else {
            allVarnodesProcessed = false;
          }
        }
        if (!allVarnodesProcessed)
          allStorageProcessed = false;
      }
      if (allStorageProcessed) break;
    }
    data.clearLanedAccessMap();
    return 0;
  }
}

// ---------------------
// ActionSegmentize
// ---------------------

/** Make sure pointers into segmented spaces have the correct form. */
export class ActionSegmentize extends Action {
  private localcount: number = 0;

  constructor(g: string) {
    super(0, "segmentize", g);
  }

  reset(data: Funcdata): void {
    this.localcount = 0;
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionSegmentize(this.getGroup());
  }

  apply(data: Funcdata): number {
    const numops: number = data.getArch().userops.numSegmentOps();
    if (numops === 0) return 0;
    if (this.localcount > 0) return 0;
    this.localcount = 1;

    const bindlist: (Varnode | null)[] = [null, null];

    for (let i = 0; i < numops; ++i) {
      const segdef: SegmentOp = data.getArch().userops.getSegmentOp(i);
      if (segdef === null) continue;
      const spc: AddrSpace = segdef.getSpace();

      const iter = data.beginOp(OpCode.CPUI_CALLOTHER);
      const enditer = data.endOp(OpCode.CPUI_CALLOTHER);
      const uindex: number = segdef.getIndex();
      for (const segroot of iteratorRange(iter, enditer)) {
        if (segroot.isDead()) continue;
        if (segroot.getIn(0)!.getOffset() !== BigInt(uindex)) continue;
        if (!segdef.unify(data, segroot, bindlist)) {
          const msg = "Segment op in wrong form at " + segroot.getAddr().toString();
          throw new LowlevelError(msg);
        }

        if (segdef.getNumVariableTerms() === 1)
          bindlist[0] = data.newConstant(4, 0n);
        data.opSetOpcode(segroot, OpCode.CPUI_SEGMENTOP);
        data.opSetInput(segroot, data.newVarnodeSpace(spc), 0);
        data.opSetInput(segroot, bindlist[0]!, 1);
        data.opSetInput(segroot, bindlist[1]!, 2);
        for (let j = segroot.numInput() - 1; j > 2; --j)
          data.opRemoveInput(segroot, j);
        this.count += 1;
      }
    }
    return 0;
  }
}

// ---------------------
// ActionForceGoto
// ---------------------

/** Apply any overridden forced gotos. */
export class ActionForceGoto extends Action {
  constructor(g: string) {
    super(0, "forcegoto", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionForceGoto(this.getGroup());
  }

  apply(data: Funcdata): number {
    data.getOverride().applyForceGoto(data);
    return 0;
  }
}

// ---------------------
// ActionConstbase
// ---------------------

/** Search for input Varnodes that have been officially provided constant values. */
export class ActionConstbase extends Action {
  constructor(g: string) {
    super(0, "constbase", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionConstbase(this.getGroup());
  }

  apply(data: Funcdata): number {
    if (data.getBasicBlocks().getSize() === 0) return 0;
    const bb: BlockBasic = data.getBasicBlocks().getBlock(0) as BlockBasic;

    const injectid: number = data.getFuncProto().getInjectUponEntry();
    if (injectid >= 0) {
      const payload: InjectPayload = data.getArch().pcodeinjectlib.getPayload(injectid);
      data.doLiveInject(payload, bb.getStart(), bb, bb.beginOp());
    }

    const trackset: TrackedSet = data.getArch().context.getTrackedSet(data.getAddress());

    for (let i = 0; i < trackset.length; ++i) {
      const ctx: TrackedContext = trackset[i];

      const addr = new Address(ctx.loc.space, ctx.loc.offset);
      const op: PcodeOp = data.newOp(1, bb.getStart());
      data.newVarnodeOut(ctx.loc.size, addr, op);
      const vnin: Varnode = data.newConstant(ctx.loc.size, ctx.val);
      data.opSetOpcode(op, OpCode.CPUI_COPY);
      data.opSetInput(op, vnin, 0);
      data.opInsertBegin(op, bb);
    }
    return 0;
  }
}

// ---------------------
// ActionMultiCse
// ---------------------

/** Perform Common Sub-expression Elimination on OpCode.CPUI_MULTIEQUAL ops. */
export class ActionMultiCse extends Action {
  constructor(g: string) {
    super(0, "multicse", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionMultiCse(this.getGroup());
  }

  /** Which of two outputs is preferred for substitution. */
  private static preferredOutput(out1: Varnode, out2: Varnode): boolean {
    // Prefer the output that is used in a OpCode.CPUI_RETURN
    for (const op of (out1 as any).descend) {
      if (op.code() === OpCode.CPUI_RETURN)
        return false;
    }
    for (const op of (out2 as any).descend) {
      if (op.code() === OpCode.CPUI_RETURN)
        return true;
    }
    // Prefer addrtied over register over unique
    if (!out1.isAddrTied()) {
      if (out2.isAddrTied())
        return true;
      else {
        if (out1.getSpace()!.getType() === spacetype.IPTR_INTERNAL) {
          if (out2.getSpace()!.getType() !== spacetype.IPTR_INTERNAL)
            return true;
        }
      }
    }
    return false;
  }

  /** Find any matching OpCode.CPUI_MULTIEQUAL that occurs before target that has in as an input. */
  private static findMatch(bl: BlockBasic, target: PcodeOp, inVn: Varnode): PcodeOp | null {
    for (const op of (bl as any).getOpIterator()) {
      if (op === target) break;
      const numinput: number = op.numInput();
      let i: number;
      for (i = 0; i < numinput; ++i) {
        let vn: Varnode = op.getIn(i);
        if (vn.isWritten() && vn.getDef()!.code() === OpCode.CPUI_COPY)
          vn = vn.getDef()!.getIn(0);
        if (vn === inVn) break;
      }
      if (i < numinput) {
        let j: number;
        const buf1: Varnode[] = [null as any, null as any];
        const buf2: Varnode[] = [null as any, null as any];
        for (j = 0; j < numinput; ++j) {
          let in1: Varnode = op.getIn(j);
          if (in1.isWritten() && in1.getDef()!.code() === OpCode.CPUI_COPY)
            in1 = in1.getDef()!.getIn(0);
          let in2: Varnode = target.getIn(j)!;
          if (in2.isWritten() && in2.getDef()!.code() === OpCode.CPUI_COPY)
            in2 = in2.getDef()!.getIn(0);
          if (in1 === in2) continue;
          if (0 !== functionalEqualityLevel(in1, in2, buf1, buf2))
            break;
        }
        if (j === numinput)
          return op;
      }
    }
    return null;
  }

  /** Search a block for equivalent OpCode.CPUI_MULTIEQUAL. */
  private processBlock(data: Funcdata, bl: BlockBasic): boolean {
    const vnlist: Varnode[] = [];
    let targetop: PcodeOp | null = null;
    let pairop: PcodeOp | null = null;

    for (const op of (bl as any).getOpIterator()) {
      const opc: OpCode = op.code();
      if (opc === OpCode.CPUI_COPY) continue;
      if (opc !== OpCode.CPUI_MULTIEQUAL) break;
      const vnpos = vnlist.length;
      const numinput: number = op.numInput();
      let i: number;
      for (i = 0; i < numinput; ++i) {
        let vn: Varnode = op.getIn(i);
        if (vn.isWritten() && vn.getDef()!.code() === OpCode.CPUI_COPY)
          vn = vn.getDef()!.getIn(0);
        vnlist.push(vn);
        if (vn.isMark()) {
          pairop = ActionMultiCse.findMatch(bl, op, vn);
          if (pairop !== null)
            break;
        }
      }
      if (i < numinput) {
        targetop = op;
        break;
      }
      for (let k = vnpos; k < vnlist.length; ++k)
        vnlist[k].setMark();
    }

    // Clear marks
    for (let k = 0; k < vnlist.length; ++k)
      vnlist[k].clearMark();

    if (targetop !== null && pairop !== null) {
      const out1: Varnode = pairop.getOut()!;
      const out2: Varnode = targetop.getOut()!;
      if (ActionMultiCse.preferredOutput(out1, out2)) {
        data.totalReplace(out1, out2);
        data.opDestroy(pairop);
      } else {
        data.totalReplace(out2, out1);
        data.opDestroy(targetop);
      }
      this.count += 1;
      return true;
    }
    return false;
  }

  apply(data: Funcdata): number {
    const bblocks: BlockGraph = data.getBasicBlocks();
    const sz: number = bblocks.getSize();
    for (let i = 0; i < sz; ++i) {
      const bl: BlockBasic = bblocks.getBlock(i) as BlockBasic;
      while (this.processBlock(data, bl)) {
        // keep processing
      }
    }
    return 0;
  }
}

// ---------------------
// ActionShadowVar
// ---------------------

/** Check for one OpCode.CPUI_MULTIEQUAL input set defining more than one Varnode. */
export class ActionShadowVar extends Action {
  constructor(g: string) {
    super(0, "shadowvar", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionShadowVar(this.getGroup());
  }

  apply(data: Funcdata): number {
    const bblocks: BlockGraph = data.getBasicBlocks();
    const oplist: PcodeOp[] = [];

    for (let i = 0; i < bblocks.getSize(); ++i) {
      const vnlist: Varnode[] = [];
      const bl: BlockBasic = bblocks.getBlock(i) as BlockBasic;
      const startoffset: bigint = bl.getStart().getOffset();

      for (const op of (bl as any).getOpIterator()) {
        if (op.getAddr().getOffset() !== startoffset) break;
        if (op.code() !== OpCode.CPUI_MULTIEQUAL) continue;
        const vn: Varnode = op.getIn(0);
        if (vn.isMark())
          oplist.push(op);
        else {
          vn.setMark();
          vnlist.push(vn);
        }
      }
      for (let j = 0; j < vnlist.length; ++j)
        vnlist[j].clearMark();
    }

    for (const op of oplist) {
      for (let op2 = op.previousOp(); op2 !== null; op2 = op2.previousOp()) {
        if (op2.code() !== OpCode.CPUI_MULTIEQUAL) continue;
        let i: number;
        for (i = 0; i < op.numInput(); ++i)
          if (op.getIn(i) !== op2.getIn(i)) break;
        if (i !== op.numInput()) continue;

        const plist: Varnode[] = [op2.getOut()!];
        data.opSetOpcode(op, OpCode.CPUI_COPY);
        data.opSetAllInput(op, plist);
        this.count += 1;
      }
    }
    return 0;
  }
}

// ---------------------
// ActionConstantPtr
// ---------------------

/** Check for constants, with pointer type, that correspond to global symbols. */
export class ActionConstantPtr extends Action {
  private localcount: number = 0;

  constructor(g: string) {
    super(0, "constantptr", g);
  }

  reset(data: Funcdata): void {
    this.localcount = 0;
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionConstantPtr(this.getGroup());
  }

  /** Search for address space annotations in the path of a pointer constant. */
  private static searchForSpaceAttribute(vn: Varnode, op: PcodeOp): AddrSpace | null {
    for (let i = 0; i < 3; ++i) {
      const dt: Datatype = vn.getType();
      if (dt.getMetatype() === type_metatype.TYPE_PTR) {
        const spc: AddrSpace | null = (dt as TypePointer).getSpace();
        if (spc !== null && spc.getAddrSize() === vn.getSize())
          return spc;
      }
      switch (op.code()) {
        case OpCode.CPUI_INT_ADD:
        case OpCode.CPUI_COPY:
        case OpCode.CPUI_INDIRECT:
        case OpCode.CPUI_MULTIEQUAL:
          vn = op.getOut()!;
          op = vn.loneDescend();
          break;
        case OpCode.CPUI_LOAD:
          return op.getIn(0)!.getSpaceFromConst();
        case OpCode.CPUI_STORE:
          if (op.getIn(1) === vn)
            return op.getIn(0)!.getSpaceFromConst();
          return null;
        default:
          return null;
      }
      if (op === null) break;
    }
    for (const descOp of (vn as any).descend) {
      const opc: OpCode = descOp.code();
      if (opc === OpCode.CPUI_LOAD)
        return descOp.getIn(0).getSpaceFromConst();
      else if (opc === OpCode.CPUI_STORE && descOp.getIn(1) === vn)
        return descOp.getIn(0).getSpaceFromConst();
    }
    return null;
  }

  /** Select the AddrSpace in which we infer the given constant is a pointer. */
  private static selectInferSpace(vn: Varnode, op: PcodeOp, spaceList: AddrSpace[]): AddrSpace | null {
    let resSpace: AddrSpace | null = null;
    if (vn.getType().getMetatype() === type_metatype.TYPE_PTR) {
      const spc: AddrSpace | null = (vn.getType() as TypePointer).getSpace();
      if (spc !== null && spc.getAddrSize() === vn.getSize())
        return spc;
    }
    for (let i = 0; i < spaceList.length; ++i) {
      const spc: AddrSpace = spaceList[i];
      const minSize: number = spc.getMinimumPtrSize();
      if (minSize === 0) {
        if (vn.getSize() !== spc.getAddrSize())
          continue;
      } else if (vn.getSize() < minSize)
        continue;
      if (resSpace !== null) {
        const searchSpc = ActionConstantPtr.searchForSpaceAttribute(vn, op);
        if (searchSpc !== null)
          resSpace = searchSpc;
        break;
      }
      resSpace = spc;
    }
    return resSpace;
  }

  /** Check if we need to try to infer a constant pointer from the input of the given COPY. */
  private static checkCopy(op: PcodeOp, data: Funcdata): boolean {
    const vn: Varnode = op.getOut()!;
    const retOp: PcodeOp | null = vn.loneDescend();
    if (retOp !== null && retOp.code() === OpCode.CPUI_RETURN && data.getFuncProto().isOutputLocked()) {
      const meta: type_metatype = data.getFuncProto().getOutput().getType().getMetatype();
      if (meta !== type_metatype.TYPE_PTR && meta !== type_metatype.TYPE_UNKNOWN) {
        return false;
      }
      return true;
    }
    return data.getArch().infer_pointers;
  }

  /** Determine if given Varnode might be a pointer constant. */
  private static isPointer(spc: AddrSpace, vn: Varnode, op: PcodeOp, slot: number,
    rampoint: { addr: Address }, fullEncoding: { val: bigint }, data: Funcdata): SymbolEntry | null {
    let needexacthit: boolean;
    const glb: Architecture = data.getArch();
    let outvn: Varnode;
    if (vn.getTypeReadFacing(op).getMetatype() === type_metatype.TYPE_PTR) {
      rampoint.addr = glb.resolveConstant(spc, vn.getOffset(), vn.getSize(), op.getAddr(), fullEncoding);
      needexacthit = false;
    } else {
      if (vn.isTypeLock()) return null;
      needexacthit = true;
      switch (op.code()) {
        case OpCode.CPUI_CALL:
        case OpCode.CPUI_CALLIND: {
          if (slot === 0) return null;
          const fc: FuncCallSpecs | null = data.getCallSpecs(op);
          if (fc !== null && fc.isInputLocked() && fc.numParams() > slot - 1) {
            const meta: type_metatype = fc.getParam(slot - 1)!.getType().getMetatype();
            if (meta !== type_metatype.TYPE_PTR && meta !== type_metatype.TYPE_UNKNOWN)
              return null;
          } else if (!glb.infer_pointers)
            return null;
          break;
        }
        case OpCode.CPUI_COPY:
          if (!ActionConstantPtr.checkCopy(op, data))
            return null;
          break;
        case OpCode.CPUI_PIECE:
        case OpCode.CPUI_INT_EQUAL:
        case OpCode.CPUI_INT_NOTEQUAL:
        case OpCode.CPUI_INT_LESS:
        case OpCode.CPUI_INT_LESSEQUAL:
          if (!glb.infer_pointers)
            return null;
          break;
        case OpCode.CPUI_INT_ADD:
          outvn = op.getOut()!;
          if (outvn.getTypeDefFacing().getMetatype() === type_metatype.TYPE_PTR) {
            if (op.getIn(1 - slot)!.getTypeReadFacing(op).getMetatype() === type_metatype.TYPE_PTR)
              return null;
            needexacthit = false;
          } else if (!glb.infer_pointers)
            return null;
          break;
        case OpCode.CPUI_STORE:
          if (slot !== 2)
            return null;
          break;
        default:
          return null;
      }
      if (spc.getPointerLowerBound() > vn.getOffset())
        return null;
      if (spc.getPointerUpperBound() < vn.getOffset())
        return null;
      if (bit_transitions(vn.getOffset(), vn.getSize()) < 3)
        return null;
      rampoint.addr = glb.resolveConstant(spc, vn.getOffset(), vn.getSize(), op.getAddr(), fullEncoding);
    }

    if (rampoint.addr.isInvalid()) return null;
    const entry: SymbolEntry | null = data.getScopeLocal()!.getParent()!.queryContainer(rampoint.addr, 1, Address.invalid());
    if (entry !== null) {
      const ptrType: Datatype = entry.getSymbol().getType();
      if (ptrType.getMetatype() === type_metatype.TYPE_ARRAY) {
        const ct: Datatype = (ptrType as TypeArray).getBase();
        if (ct.isCharPrint())
          needexacthit = false;
      }
      if (needexacthit && !entry.getAddr().equals(rampoint.addr))
        return null;
    }
    return entry;
  }

  apply(data: Funcdata): number {
    if (!data.hasTypeRecoveryStarted()) return 0;
    if (this.localcount >= 4) return 0;
    this.localcount += 1;

    const glb: Architecture = data.getArch();
    const cspc: AddrSpace = glb.getConstantSpace();

    let begiter = data.beginLocSpace(cspc);
    const enditer = data.endLocSpace(cspc);

    while (!begiter.equals(enditer)) {
      const vn: Varnode = begiter.get(); begiter.next();
      if (!vn.isConstant()) break;
      if (vn.getOffset() === 0n) continue;
      if (vn.isPtrCheck()) continue;
      if (vn.hasNoDescend()) continue;
      if (vn.isSpacebase()) continue;

      const op: PcodeOp | null = vn.loneDescend();
      if (op === null) continue;
      const rspc: AddrSpace | null = ActionConstantPtr.selectInferSpace(vn, op, glb.inferPtrSpaces);
      if (rspc === null) continue;
      const slot: number = op.getSlot(vn);
      const opc: OpCode = op.code();
      if (opc === OpCode.CPUI_INT_ADD) {
        if (op.getIn(1 - slot)!.isSpacebase()) continue;
      } else if (opc === OpCode.CPUI_PTRSUB || opc === OpCode.CPUI_PTRADD)
        continue;
      const rampoint = { addr: Address.invalid() };
      const fullEncoding = { val: 0n };
      const entry = ActionConstantPtr.isPointer(rspc, vn, op, slot, rampoint, fullEncoding, data);
      vn.setPtrCheck();
      if (entry !== null) {
        data.spacebaseConstant(op, slot, entry, rampoint.addr, fullEncoding.val, vn.getSize());
        if (opc === OpCode.CPUI_INT_ADD && slot === 1)
          data.opSwapInput(op, 0, 1);
        this.count += 1;
      }
    }
    return 0;
  }
}

// ---------------------
// ActionDeindirect
// ---------------------

/** Eliminate locally constant indirect calls. */
export class ActionDeindirect extends Action {
  constructor(g: string) {
    super(0, "deindirect", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionDeindirect(this.getGroup());
  }

  apply(data: Funcdata): number {
    for (let i = 0; i < data.numCalls(); ++i) {
      const fc: FuncCallSpecs = data.getCallSpecs_byIndex(i);
      const op: PcodeOp = fc.getOp();
      if (op.code() !== OpCode.CPUI_CALLIND) continue;
      let vn: Varnode = op.getIn(0)!;
      while (vn.isWritten() && vn.getDef()!.code() === OpCode.CPUI_COPY)
        vn = vn.getDef()!.getIn(0);
      if (vn.isPersist() && vn.isExternalRef()) {
        const newfd: Funcdata | null = data.getScopeLocal()!.getParent()!.queryExternalRefFunction(vn.getAddr());
        if (newfd !== null) {
          fc.deindirect(data, newfd);
          this.count += 1;
          continue;
        }
      } else if (vn.isConstant()) {
        const sp: AddrSpace = data.getAddress().getSpace()!;
        let offset: bigint = AddrSpace.addressToByte(vn.getOffset(), sp.getWordSize());
        const align: number = data.getArch().funcptr_align;
        if (align !== 0) {
          offset >>= BigInt(align);
          offset <<= BigInt(align);
        }
        const codeaddr = new Address(sp, offset);
        const newfd: Funcdata | null = data.getScopeLocal()!.getParent()!.queryFunction(codeaddr);
        if (newfd !== null) {
          fc.deindirect(data, newfd);
          this.count += 1;
          continue;
        }
      }
      if (data.hasTypeRecoveryStarted()) {
        const ct: Datatype = op.getIn(0)!.getTypeReadFacing(op);
        if (ct.getMetatype() === type_metatype.TYPE_PTR &&
          (ct as TypePointer).getPtrTo().getMetatype() === type_metatype.TYPE_CODE) {
          const tc: TypeCode = (ct as TypePointer).getPtrTo() as TypeCode;
          const fp: FuncProto | null = tc.getPrototype();
          if (fp !== null) {
            if (!fc.isInputLocked()) {
              fc.forceSet(data, fp);
              this.count += 1;
            }
          }
        }
      }
    }
    return 0;
  }
}

// ---------------------
// ActionVarnodeProps
// ---------------------

/** Transform based on Varnode properties, such as read-only and volatile. */
export class ActionVarnodeProps extends Action {
  constructor(g: string) {
    super(0, "varnodeprops", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionVarnodeProps(this.getGroup());
  }

  apply(data: Funcdata): number {
    const glb: Architecture = data.getArch();
    const cachereadonly: boolean = glb.readonlypropagate;
    const pass: number = data.getHeritagePass();

    for (const vn of (data as any).getLocIterator()) {
      if (vn.isAnnotation()) continue;
      const vnSize = vn.getSize();
      if (vn.isAutoLiveHold()) {
        if (pass > 0) {
          if (vn.isWritten()) {
            const loadOp: PcodeOp = vn.getDef()!;
            if (loadOp.code() === OpCode.CPUI_LOAD) {
              let ptr: Varnode = loadOp.getIn(1)!;
              if (ptr.isConstant() || ptr.isReadOnly())
                continue;
              if (ptr.isWritten()) {
                const copyOp: PcodeOp = ptr.getDef()!;
                if (copyOp.code() === OpCode.CPUI_COPY) {
                  ptr = copyOp.getIn(0)!;
                  if (ptr.isConstant() || ptr.isReadOnly())
                    continue;
                }
              }
            }
          }
          vn.clearAutoLiveHold();
          this.count += 1;
        }
      } else if (vn.hasActionProperty()) {
        if (cachereadonly && vn.isReadOnly()) {
          if (data.fillinReadOnly(vn))
            this.count += 1;
        } else if (vn.isVolatile())
          if (data.replaceVolatile(vn))
            this.count += 1;
      } else if ((BigInt(vn.getNZMask()) & BigInt(vn.getConsume())) === 0n && vnSize <= 8) {
        if (vn.isConstant()) continue;
        if (vn.isWritten()) {
          if (vn.getDef()!.code() === OpCode.CPUI_COPY) {
            if (vn.getDef()!.getIn(0).isConstant()) {
              if (vn.getDef()!.getIn(0).getOffset() === 0n)
                continue;
            }
          }
        }
        if (!vn.hasNoDescend()) {
          data.totalReplaceConstant(vn, 0n);
          this.count += 1;
        }
      }
    }
    return 0;
  }
}

// ---------------------
// ActionDirectWrite
// ---------------------

/** Mark Varnodes built out of legal parameters. */
export class ActionDirectWrite extends Action {
  private propagateIndirect: boolean;

  constructor(g: string, prop: boolean) {
    super(0, "directwrite", g);
    this.propagateIndirect = prop;
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionDirectWrite(this.getGroup(), this.propagateIndirect);
  }

  apply(data: Funcdata): number {
    const worklist: Varnode[] = [];

    // Collect legal inputs and other auto direct writes
    for (const vn of (data as any).getLocIterator()) {
      vn.clearDirectWrite();
      if (vn.isInput()) {
        if (vn.isPersist() || vn.isSpacebase()) {
          vn.setDirectWrite();
          worklist.push(vn);
        } else if (data.getFuncProto().possibleInputParam(vn.getAddr(), vn.getSize())) {
          vn.setDirectWrite();
          worklist.push(vn);
        }
      } else if (vn.isWritten()) {
        const op: PcodeOp = vn.getDef()!;
        if (!op.isMarker()) {
          if (vn.isPersist()) {
            vn.setDirectWrite();
            worklist.push(vn);
          } else if (op.code() === OpCode.CPUI_COPY) {
            if (vn.isStackStore()) {
              let invn: Varnode = op.getIn(0)!;
              if (invn.isWritten()) {
                const curop: PcodeOp = invn.getDef()!;
                if (curop.code() === OpCode.CPUI_COPY)
                  invn = curop.getIn(0)!;
              }
              if (invn.isWritten() && invn.getDef()!.isMarker()) {
                vn.setDirectWrite();
                worklist.push(vn);
              }
            }
          } else if (op.code() !== OpCode.CPUI_PIECE && op.code() !== OpCode.CPUI_SUBPIECE) {
            vn.setDirectWrite();
            worklist.push(vn);
          }
        } else if (!this.propagateIndirect && op.code() === OpCode.CPUI_INDIRECT) {
          const outvn: Varnode = op.getOut()!;
          if (!op.getIn(0)!.getAddr().equals(outvn.getAddr()))
            vn.setDirectWrite();
          else if (outvn.isPersist())
            vn.setDirectWrite();
        }
      } else if (vn.isConstant()) {
        if (!vn.isIndirectZero()) {
          vn.setDirectWrite();
          worklist.push(vn);
        }
      }
    }

    // Let legalness taint
    while (worklist.length > 0) {
      const vn: Varnode = worklist.pop()!;
      for (const op of (vn as any).descend) {
        if (!op.isAssignment()) continue;
        const dvn: Varnode = op.getOut()!;
        if (!dvn.isDirectWrite()) {
          dvn.setDirectWrite();
          if (this.propagateIndirect || op.code() !== OpCode.CPUI_INDIRECT || op.isIndirectStore())
            worklist.push(dvn);
        }
      }
    }
    return 0;
  }
}

// ---------------------
// ActionExtraPopSetup
// ---------------------

/** Define formal link between stack-pointer values before and after sub-function calls. */
export class ActionExtraPopSetup extends Action {
  private stackspace: AddrSpace | null;

  constructor(g: string, ss: AddrSpace | null) {
    super(Action.rule_onceperfunc, "extrapopsetup", g);
    this.stackspace = ss;
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionExtraPopSetup(this.getGroup(), this.stackspace);
  }

  apply(data: Funcdata): number {
    if (this.stackspace === null) return 0;
    const point: VarnodeData = this.stackspace.getSpacebase(0);
    const sb_addr = new Address(point.space! as any, point.offset);
    const sb_size: number = point.size;

    for (let i = 0; i < data.numCalls(); ++i) {
      const fc: FuncCallSpecs = data.getCallSpecs_byIndex(i);
      if (fc.getExtraPop() === 0) continue;
      const op: PcodeOp = data.newOp(2, fc.getOp().getAddr());
      data.newVarnodeOut(sb_size, sb_addr, op);
      data.opSetInput(op, data.newVarnode(sb_size, sb_addr), 0);
      if (fc.getExtraPop() !== ProtoModel.extrapop_unknown) {
        fc.setEffectiveExtraPop(fc.getExtraPop());
        data.opSetOpcode(op, OpCode.CPUI_INT_ADD);
        data.opSetInput(op, data.newConstant(sb_size, BigInt(fc.getExtraPop())), 1);
        data.opInsertAfter(op, fc.getOp());
      } else {
        data.opSetOpcode(op, OpCode.CPUI_INDIRECT);
        data.opSetInput(op, data.newVarnodeIop(fc.getOp()), 1);
        data.opInsertBefore(op, fc.getOp());
      }
    }
    return 0;
  }
}

// ---------------------
// ActionFuncLink
// ---------------------

/** Prepare for data-flow analysis of function parameters. */
export class ActionFuncLink extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "funclink", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionFuncLink(this.getGroup());
  }

  /** Set up the parameter recovery process for a single sub-function call. */
  static funcLinkInput(fc: FuncCallSpecs, data: Funcdata): void {
    const inputlocked: boolean = fc.isInputLocked();
    const varargs: boolean = fc.isDotdotdot();
    let spacebase: AddrSpace | null = fc.getSpacebase();
    const active: ParamActive = fc.getActiveInput();

    if (!inputlocked || varargs)
      fc.initActiveInput();
    if (inputlocked) {
      const op: PcodeOp = fc.getOp();
      const numparam: number = fc.numParams();
      let setplaceholder = varargs;
      for (let i = 0; i < numparam; ++i) {
        const param: ProtoParameter = fc.getParam(i);
        active.registerTrial(param.getAddress(), param.getSize());
        active.getTrial(i).markActive();
        if (varargs)
          active.getTrial(i).setFixedPosition(i);
        const spcType = param.getAddress().getSpace().getType();
        const off: bigint = param.getAddress().getOffset();
        const sz: number = param.getSize();
        if (spcType === spacetype.IPTR_SPACEBASE) {
          const loadval: Varnode = data.opStackLoad(param.getAddress().getSpace(), off, sz, op, null, false);
          data.opInsertInput(op, loadval, op.numInput());
          if (!setplaceholder) {
            setplaceholder = true;
            loadval.setSpacebasePlaceholder();
            spacebase = null;
          }
        } else
          data.opInsertInput(op, data.newVarnode(param.getSize(), param.getAddress()), op.numInput());
      }
    }
    if (spacebase !== null)
      fc.createPlaceholder(data, spacebase);
  }

  /** Set up the return value recovery process for a single sub-function call. */
  static funcLinkOutput(fc: FuncCallSpecs, data: Funcdata): void {
    const callop: PcodeOp = fc.getOp();
    if (callop.getOut() !== null) {
      if (callop.getOut()!.getSpace()!.getType() === spacetype.IPTR_INTERNAL) {
        const msg = "CALL op at " + callop.getAddr().toString() + " has an unexpected output varnode";
        throw new LowlevelError(msg);
      }
      data.opUnsetOutput(callop);
    }
    if (fc.isOutputLocked()) {
      const outparam: ProtoParameter = fc.getOutput();
      const outtype: Datatype = outparam.getType();
      if (outtype.getMetatype() !== type_metatype.TYPE_VOID) {
        const sz: number = outparam.getSize();
        if (sz === 1 && outtype.getMetatype() === type_metatype.TYPE_BOOL && data.isTypeRecoveryOn())
          data.opMarkCalculatedBool(callop);
        const addr: Address = outparam.getAddress();
        if (addr.getSpace()!.getType() === spacetype.IPTR_SPACEBASE) {
          fc.setStackOutputLock(true);
          return;
        }
        data.newVarnodeOut(sz, addr, callop);
        const vdata: VarnodeData = new VarnodeData();
        const res: OpCode = fc.assumedOutputExtension(addr, sz, vdata);
        let finalRes = res;
        if (res === OpCode.CPUI_PIECE) {
          if (outtype.getMetatype() === type_metatype.TYPE_INT)
            finalRes = OpCode.CPUI_INT_SEXT;
          else
            finalRes = OpCode.CPUI_INT_ZEXT;
        }
        if (finalRes !== OpCode.CPUI_COPY) {
          const extop: PcodeOp = data.newOp(1, callop.getAddr());
          data.newVarnodeOut(vdata.size, vdata.getAddr() as any, extop);
          const invn: Varnode = data.newVarnode(sz, addr);
          data.opSetInput(extop, invn, 0);
          data.opSetOpcode(extop, finalRes);
          data.opInsertAfter(extop, callop);
        }
      }
    } else
      fc.initActiveOutput();
  }

  apply(data: Funcdata): number {
    const size: number = data.numCalls();
    for (let i = 0; i < size; ++i) {
      ActionFuncLink.funcLinkInput(data.getCallSpecs_byIndex(i), data);
      ActionFuncLink.funcLinkOutput(data.getCallSpecs_byIndex(i), data);
    }
    return 0;
  }
}

// ---------------------
// ActionFuncLinkOutOnly
// ---------------------

/** Prepare for data-flow analysis of function parameters, when recovery isn't required. */
export class ActionFuncLinkOutOnly extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "funclink_outonly", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionFuncLinkOutOnly(this.getGroup());
  }

  apply(data: Funcdata): number {
    const size: number = data.numCalls();
    for (let i = 0; i < size; ++i)
      ActionFuncLink.funcLinkOutput(data.getCallSpecs_byIndex(i), data);
    return 0;
  }
}

// ---------------------
// ActionParamDouble
// ---------------------

/** Deal with situations that look like double precision parameters. */
export class ActionParamDouble extends Action {
  constructor(g: string) {
    super(0, "paramdouble", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionParamDouble(this.getGroup());
  }

  apply(data: Funcdata): number {
    for (let i = 0; i < data.numCalls(); ++i) {
      const fc: FuncCallSpecs = data.getCallSpecs_byIndex(i);
      const op: PcodeOp = fc.getOp();
      if (fc.isInputActive()) {
        const active: ParamActive = fc.getActiveInput();
        for (let j = 0; j < active.getNumTrials(); ++j) {
          const paramtrial: ParamTrial = active.getTrial(j);
          if (paramtrial.isChecked()) continue;
          if (paramtrial.isUnref()) continue;
          const spc: AddrSpace = paramtrial.getAddress().getSpace();
          if (spc.getType() !== spacetype.IPTR_SPACEBASE) continue;
          const slot: number = paramtrial.getSlot();
          const vn: Varnode = op.getIn(slot)!;
          if (!vn.isWritten()) continue;
          const concatop: PcodeOp = vn.getDef()!;
          if (concatop.code() !== OpCode.CPUI_PIECE) continue;
          if (!fc.hasModel()) continue;
          const mostvn: Varnode = concatop.getIn(0)!;
          const leastvn: Varnode = concatop.getIn(1)!;
          const splitsize: number = spc.isBigEndian() ? mostvn.getSize() : leastvn.getSize();
          if (fc.checkInputSplit(paramtrial.getAddress(), paramtrial.getSize(), splitsize)) {
            active.splitTrial(j, splitsize);
            if (spc.isBigEndian()) {
              data.opInsertInput(op, mostvn, slot);
              data.opSetInput(op, leastvn, slot + 1);
            } else {
              data.opInsertInput(op, leastvn, slot);
              data.opSetInput(op, mostvn, slot + 1);
            }
            this.count += 1;
            j -= 1; // Note we decrement j, so we can check nested CONCATs
          }
        }
      } else if (!fc.isInputLocked() && data.isDoublePrecisOn()) {
        let max: number = op.numInput() - 1;
        for (let j = 1; j < max; ++j) {
          const vn1: Varnode = op.getIn(j)!;
          const vn2: Varnode = op.getIn(j + 1)!;
          const whole: SplitVarnode = new (SplitVarnode as any)();
          let isslothi: boolean;
          if (whole.inHandHi(vn1)) {
            if (whole.getLo() !== vn2) continue;
            isslothi = true;
          } else if (whole.inHandLo(vn1)) {
            if (whole.getHi() !== vn2) continue;
            isslothi = false;
          } else
            continue;
          if (fc.checkInputJoinCall(j, isslothi, vn1, vn2)) {
            data.opSetInput(op, whole.getWhole()!, j);
            data.opRemoveInput(op, j + 1);
            fc.doInputJoin(j, isslothi);
            max = op.numInput() - 1;
            this.count += 1;
          }
        }
      }
    }

    const fp: FuncProto = data.getFuncProto();
    if (fp.isInputLocked() && data.isDoublePrecisOn()) {
      const lovec: Varnode[] = [];
      const hivec: Varnode[] = [];
      const minDoubleSize: number = data.getArch().getDefaultSize();
      const numparams: number = fp.numParams();
      for (let i = 0; i < numparams; ++i) {
        const param: ProtoParameter = fp.getParam(i);
        const tp: Datatype = param.getType();
        if (!tp.isPrimitiveWhole()) continue;
        const vn: Varnode | null = data.findVarnodeInput(tp.getSize(), param.getAddress());
        if (vn === null) continue;
        if (vn.getSize() < minDoubleSize) continue;
        const halfSize: number = vn.getSize() / 2;
        lovec.length = 0;
        hivec.length = 0;
        let otherUse = false;
        for (const subop of (vn as any).descend) {
          if (subop.code() !== OpCode.CPUI_SUBPIECE) continue;
          const outvn: Varnode = subop.getOut()!;
          if (outvn.getSize() !== halfSize) continue;
          if (subop.getIn(1).getOffset() === 0n)
            lovec.push(outvn);
          else if (subop.getIn(1).getOffset() === BigInt(halfSize))
            hivec.push(outvn);
          else {
            otherUse = true;
            break;
          }
        }
        if (!otherUse && lovec.length > 0 && hivec.length > 0) {
          for (let j = 0; j < lovec.length; ++j) {
            const piecevn: Varnode = lovec[j];
            if (!piecevn.isPrecisLo()) {
              piecevn.setPrecisLo();
              this.count += 1;
            }
          }
          for (let j = 0; j < hivec.length; ++j) {
            const piecevn: Varnode = hivec[j];
            if (!piecevn.isPrecisHi()) {
              piecevn.setPrecisHi();
              this.count += 1;
            }
          }
        }
      }
    }
    return 0;
  }
}

// ---------------------
// ActionActiveParam
// ---------------------

/** Determine active parameters to sub-functions. */
export class ActionActiveParam extends Action {
  constructor(g: string) {
    super(0, "activeparam", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionActiveParam(this.getGroup());
  }

  apply(data: Funcdata): number {
    const aliascheck: AliasChecker = new (AliasChecker as any)();
    aliascheck.gather(data, data.getArch().getStackSpace(), true);

    for (let i = 0; i < data.numCalls(); ++i) {
      const fc: FuncCallSpecs = data.getCallSpecs_byIndex(i);
      try {
        if (fc.isInputActive()) {
          const activeinput: ParamActive = fc.getActiveInput();
          const trimmable: boolean = (activeinput.getNumPasses() > 0 || fc.getOp().code() !== OpCode.CPUI_CALLIND);
          if (!activeinput.isFullyChecked())
            fc.checkInputTrialUse(data, aliascheck);
          activeinput.finishPass();
          if (activeinput.getNumPasses() > activeinput.getMaxPass())
            activeinput.markFullyChecked();
          else
            this.count += 1;
          if (trimmable && activeinput.isFullyChecked()) {
            if (activeinput.needsFinalCheck())
              fc.finalInputCheck();
            fc.resolveModel(activeinput);
            fc.deriveInputMap(activeinput);
            fc.buildInputFromTrials(data);
            fc.clearActiveInput();
            this.count += 1;
          }
        }
      } catch (err: any) {
        let s = "Error processing " + fc.getName();
        const op: PcodeOp | null = fc.getOp();
        if (op !== null)
          s += " called at " + op.getSeqNum().toString();
        s += ": " + (err.explain || err.message || String(err));
        throw new LowlevelError(s);
      }
    }
    return 0;
  }
}

// ---------------------
// ActionActiveReturn
// ---------------------

/** Determine which sub-functions have active output Varnodes. */
export class ActionActiveReturn extends Action {
  constructor(g: string) {
    super(0, "activereturn", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionActiveReturn(this.getGroup());
  }

  apply(data: Funcdata): number {
    for (let i = 0; i < data.numCalls(); ++i) {
      const fc: FuncCallSpecs = data.getCallSpecs_byIndex(i);
      if (fc.isOutputActive()) {
        const activeoutput: ParamActive = fc.getActiveOutput();
        const trialvn: Varnode[] = [];
        fc.checkOutputTrialUse(data, trialvn);
        fc.deriveOutputMap(activeoutput);
        fc.buildOutputFromTrials(data, trialvn);
        fc.clearActiveOutput();
        this.count += 1;
      }
    }
    return 0;
  }
}

// ---------------------
// ActionReturnRecovery
// ---------------------

/** Determine data-flow holding the return value of the function. */
export class ActionReturnRecovery extends Action {
  constructor(g: string) {
    super(0, "returnrecovery", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionReturnRecovery(this.getGroup());
  }

  /** Rewrite a OpCode.CPUI_RETURN op to reflect a recovered output parameter. */
  private static buildReturnOutput(active: ParamActive, retop: PcodeOp, data: Funcdata): void {
    const newparam: Varnode[] = [];

    newparam.push(retop.getIn(0)!);
    for (let i = 0; i < active.getNumTrials(); ++i) {
      const curtrial: ParamTrial = active.getTrial(i);
      if (!curtrial.isUsed()) break;
      if (curtrial.getSlot() >= retop.numInput()) break;
      newparam.push(retop.getIn(curtrial.getSlot())!);
    }
    if (newparam.length <= 2)
      data.opSetAllInput(retop, newparam);
    else if (newparam.length === 3) {
      const lovn: Varnode = newparam[1];
      const hivn: Varnode = newparam[2];
      const triallo: ParamTrial = active.getTrial(0);
      const trialhi: ParamTrial = active.getTrial(1);
      const joinaddr: Address = data.getArch().constructJoinAddress(
        data.getArch().translate,
        trialhi.getAddress(), trialhi.getSize(),
        triallo.getAddress(), triallo.getSize());
      const newop: PcodeOp = data.newOp(2, retop.getAddr());
      data.opSetOpcode(newop, OpCode.CPUI_PIECE);
      const newwhole: Varnode = data.newVarnodeOut(trialhi.getSize() + triallo.getSize(), joinaddr, newop);
      newwhole.setWriteMask();
      data.opInsertBefore(newop, retop);
      newparam.pop();
      newparam[newparam.length - 1] = newwhole;
      data.opSetAllInput(retop, newparam);
      data.opSetInput(newop, hivn, 0);
      data.opSetInput(newop, lovn, 1);
    } else {
      newparam.length = 0;
      newparam.push(retop.getIn(0)!);
      let offmatch = 0;
      let preexist: Varnode | null = null;
      for (let i = 0; i < active.getNumTrials(); ++i) {
        const curtrial: ParamTrial = active.getTrial(i);
        if (!curtrial.isUsed()) break;
        if (curtrial.getSlot() >= retop.numInput()) break;
        if (preexist === null) {
          preexist = retop.getIn(curtrial.getSlot());
          offmatch = curtrial.getOffset() + curtrial.getSize();
        } else if (offmatch === curtrial.getOffset()) {
          offmatch += curtrial.getSize();
          const vn: Varnode = retop.getIn(curtrial.getSlot())!;
          const newop: PcodeOp = data.newOp(2, retop.getAddr());
          data.opSetOpcode(newop, OpCode.CPUI_PIECE);
          let addr: Address = preexist.getAddr();
          if (vn.getAddr().getOffset() < addr.getOffset())
            addr = vn.getAddr();
          const newout: Varnode = data.newVarnodeOut(preexist.getSize() + vn.getSize(), addr, newop);
          newout.setWriteMask();
          data.opSetInput(newop, vn, 0);
          data.opSetInput(newop, preexist, 1);
          data.opInsertBefore(newop, retop);
          preexist = newout;
        } else
          break;
      }
      if (preexist !== null)
        newparam.push(preexist);
      data.opSetAllInput(retop, newparam);
    }
  }

  apply(data: Funcdata): number {
    const active: ParamActive | null = data.getActiveOutput();
    if (active !== null) {
      const maxancestor: number = data.getArch().trim_recurse_max;
      const ancestorReal: AncestorRealistic = new (AncestorRealistic as any)();
      for (const op of (data as any).getOpIter(OpCode.CPUI_RETURN)) {
        if (op.isDead()) continue;
        if (op.getHaltType() !== 0) continue;
        for (let i = 0; i < active.getNumTrials(); ++i) {
          const trial: ParamTrial = active.getTrial(i);
          if (trial.isChecked()) continue;
          const slot: number = trial.getSlot();
          const vn: Varnode = op.getIn(slot);
          if (ancestorReal.execute(op, slot, trial, false))
            if (data.ancestorOpUse(maxancestor, vn, op, trial, 0, 0))
              trial.markActive();
          this.count += 1;
        }
      }

      active.finishPass();
      if (active.getNumPasses() > active.getMaxPass())
        active.markFullyChecked();

      if (active.isFullyChecked()) {
        data.getFuncProto().deriveOutputMap(active);
        for (const op of (data as any).getOpIter(OpCode.CPUI_RETURN)) {
          if (op.isDead()) continue;
          if (op.getHaltType() !== 0) continue;
          ActionReturnRecovery.buildReturnOutput(active, op, data);
        }
        data.clearActiveOutput();
        this.count += 1;
      }
    }
    return 0;
  }
}

// Part 1 ActionRestrictLocal removed - see Part 2 below for full implementation

// =====================================================================
// Remaining inline Action subclasses from coreaction.hh that have
// trivial apply() bodies (not in coreaction.cc lines 1-1900)
// =====================================================================

/** Mark Varnode objects that hold stack-pointer values and set-up special data-type. */
export class ActionSpacebase extends Action {
  constructor(g: string) {
    super(0, "spacebase", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionSpacebase(this.getGroup());
  }

  apply(data: Funcdata): number {
    data.spacebase();
    return 0;
  }
}

/** Build Static Single Assignment (SSA) representation for function. */
export class ActionHeritage extends Action {
  constructor(g: string) {
    super(0, "heritage", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionHeritage(this.getGroup());
  }

  apply(data: Funcdata): number {
    data.opHeritage();
    return 0;
  }
}

/** Calculate the non-zero mask property on all Varnode objects. */
export class ActionNonzeroMask extends Action {
  constructor(g: string) {
    super(0, "nonzeromask", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionNonzeroMask(this.getGroup());
  }

  apply(data: Funcdata): number {
    data.calcNZMask();
    return 0;
  }
}

/** Assign initial high-level HighVariable objects to each Varnode. */
export class ActionAssignHigh extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "assignhigh", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionAssignHigh(this.getGroup());
  }

  apply(data: Funcdata): number {
    data.setHighLevel();
    return 0;
  }
}

/** Mark illegal Varnode inputs used only in OpCode.CPUI_INDIRECT ops. */
export class ActionMarkIndirectOnly extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "markindirectonly", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionMarkIndirectOnly(this.getGroup());
  }

  apply(data: Funcdata): number {
    data.markIndirectOnly();
    return 0;
  }
}

/** Make required Varnode merges as dictated by OpCode.CPUI_MULTIEQUAL, OpCode.CPUI_INDIRECT, and addrtied property. */
export class ActionMergeRequired extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "mergerequired", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionMergeRequired(this.getGroup());
  }

  apply(data: Funcdata): number {
    data.getMerge().mergeAddrTied();
    data.getMerge().groupPartials();
    data.getMerge().mergeMarker();
    return 0;
  }
}

/** Try to merge an op's input Varnode to its output, if they are at the same storage location. */
export class ActionMergeAdjacent extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "mergeadjacent", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionMergeAdjacent(this.getGroup());
  }

  apply(data: Funcdata): number {
    data.getMerge().mergeAdjacent();
    return 0;
  }
}

/** Try to merge the input and output Varnodes of a OpCode.CPUI_COPY op. */
export class ActionMergeCopy extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "mergecopy", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionMergeCopy(this.getGroup());
  }

  apply(data: Funcdata): number {
    data.getMerge().mergeOpcode(OpCode.CPUI_COPY);
    return 0;
  }
}

/** Try to merge Varnodes specified by Symbols with multiple SymbolEntrys. */
export class ActionMergeMultiEntry extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "mergemultientry", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionMergeMultiEntry(this.getGroup());
  }

  apply(data: Funcdata): number {
    data.getMerge().mergeMultiEntry();
    return 0;
  }
}

/** Try to merge Varnodes of the same type. */
export class ActionMergeType extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "mergetype", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionMergeType(this.getGroup());
  }

  apply(data: Funcdata): number {
    data.getMerge().mergeByDatatype(data.beginLoc(), data.endLoc());
    return 0;
  }
}

/** Replace COPYs from the same source with a single dominant COPY. */
export class ActionDominantCopy extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "dominantcopy", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionDominantCopy(this.getGroup());
  }

  apply(data: Funcdata): number {
    data.getMerge().processCopyTrims();
    return 0;
  }
}

/** Mark COPY operations between Varnodes representing the object as non-printing. */
export class ActionCopyMarker extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "copymarker", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionCopyMarker(this.getGroup());
  }

  apply(data: Funcdata): number {
    data.getMerge().markInternalCopies();
    return 0;
  }
}

/** Create symbols that map out the local stack-frame for the function. */
export class ActionMapGlobals extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "mapglobals", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionMapGlobals(this.getGroup());
  }

  apply(data: Funcdata): number {
    data.mapGlobals();
    return 0;
  }
}

// =====================================================================
// PART 2: Action class implementations (coreaction.cc lines ~1900-3800)
// =====================================================================

// ActionRestrictLocal
// -------------------

export class ActionRestrictLocal extends Action {
  constructor(g: string) {
    super(0, "restrictlocal", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionRestrictLocal(this.getGroup());
  }

  apply(data: Funcdata): number {
    let fc: FuncCallSpecs;
    let op: PcodeOp;
    let vn: Varnode;

    for (let i = 0; i < data.numCalls(); ++i) {
      fc = data.getCallSpecs_byIndex(i);
      op = fc.getOp();

      if (!fc.isInputLocked()) continue;
      if (fc.getSpacebaseOffset() === BigInt(FuncCallSpecs.offset_unknown)) continue;
      const numparam: number = fc.numParams();
      for (let j = 0; j < numparam; ++j) {
        const param: ProtoParameter = fc.getParam(j);
        const addr: Address = param.getAddress();
        if (addr.getSpace()!.getType() !== spacetype.IPTR_SPACEBASE) continue;
        const off: bigint = addr.getSpace()!.wrapOffset(fc.getSpacebaseOffset() + addr.getOffset());
        data.getScopeLocal()!.markNotMapped(addr.getSpace()!, off, param.getSize(), true);
      }
    }

    const eiter = data.getFuncProto().effectBegin();
    const endeiter = data.getFuncProto().effectEnd();
    for (const eff of iteratorRange(eiter, endeiter)) {  // Iterate through saved registers
      if (eff.getType() === EffectRecord.killedbycall) continue;  // Not saved
      vn = data.findVarnodeInput(eff.getSize(), eff.getAddress())!;
      if (vn !== null && vn.isUnaffected()) {
        // Mark storage locations for saved registers as not mapped
        // This should pickup unaffected, reload, and return_address effecttypes
        for (const iter of (vn as any).descend) {
          op = iter;
          if (op.code() !== OpCode.CPUI_COPY) continue;
          const outvn: Varnode = op.getOut()!;
          if (!data.getScopeLocal()!.isUnaffectedStorage(outvn))  // Is this where unaffected values get saved
            continue;
          data.getScopeLocal()!.markNotMapped(outvn.getSpace(), outvn.getOffset(), outvn.getSize(), false);
        }
      }
    }
    return 0;
  }
}

// ActionLikelyTrash
// -----------------

export class ActionLikelyTrash extends Action {
  constructor(g: string) {
    super(0, "likelytrash", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionLikelyTrash(this.getGroup());
  }

  /// Count the number of inputs to op which have their mark set
  private static countMarks(op: PcodeOp): number {
    let res: number = 0;
    for (let i = 0; i < op.numInput(); ++i) {
      let vn: Varnode = op.getIn(i)!;
      for (;;) {
        if (vn.isMark()) {
          res += 1;
          break;
        }
        if (!vn.isWritten()) break;
        const defOp: PcodeOp = vn.getDef()!;
        if (defOp === op) {  // We have looped all the way around
          res += 1;
          break;
        } else if (defOp.code() !== OpCode.CPUI_INDIRECT)  // Chain up through INDIRECTs
          break;
        vn = vn.getDef()!.getIn(0);
      }
    }
    return res;
  }

  /// Decide if the given Varnode only ever flows into OpCode.CPUI_INDIRECT.
  /// Return all the OpCode.CPUI_INDIRECT ops that the Varnode hits in a list.
  private static traceTrash(vn: Varnode, indlist: PcodeOp[]): boolean {
    const allroutes: PcodeOp[] = [];   // Keep track of merging ops (with more than 1 input)
    const markedlist: Varnode[] = [];   // All varnodes we have visited on paths from vn
    let outvn: Varnode;
    let val: bigint;
    let traced: number = 0;
    vn.setMark();
    markedlist.push(vn);
    let istrash: boolean = true;

    while (traced < markedlist.length) {
      const curvn: Varnode = markedlist[traced++];
      for (const op of (curvn as any).descend) {
        outvn = op.getOut()!;
        switch (op.code()) {
          case OpCode.CPUI_INDIRECT:
            if (outvn.isPersist())
              istrash = false;
            else if (op.isIndirectStore()) {
              if (!outvn.isMark()) {
                outvn.setMark();
                markedlist.push(outvn);
              }
            } else
              indlist.push(op);
            break;
          case OpCode.CPUI_SUBPIECE:
            if (outvn.isPersist())
              istrash = false;
            else {
              if (!outvn.isMark()) {
                outvn.setMark();
                markedlist.push(outvn);
              }
            }
            break;
          case OpCode.CPUI_MULTIEQUAL:
          case OpCode.CPUI_PIECE:
            if (outvn.isPersist())
              istrash = false;
            else {
              if (!op.isMark()) {
                op.setMark();
                allroutes.push(op);
              }
              const nummark: number = ActionLikelyTrash.countMarks(op);
              if (nummark === op.numInput()) {
                if (!outvn.isMark()) {
                  outvn.setMark();
                  markedlist.push(outvn);
                }
              }
            }
            break;
          case OpCode.CPUI_INT_AND:
            // If the AND is using only the topmost significant bytes then it is likely trash
            if (op.getIn(1).isConstant()) {
              val = op.getIn(1).getOffset();
              const mask: bigint = calc_mask(op.getIn(1).getSize());
              if (val === ((mask << 8n) & mask) || val === ((mask << 16n) & mask) || val === ((mask << 32n) & mask)) {
                indlist.push(op);
                break;
              }
            }
            istrash = false;
            break;
          default:
            istrash = false;
            break;
        }
        if (!istrash) break;
      }
      if (!istrash) break;
    }

    for (let i = 0; i < allroutes.length; ++i) {
      if (!allroutes[i].getOut()!.isMark())
        istrash = false;  // Didn't see all inputs
      allroutes[i].clearMark();
    }
    for (let i = 0; i < markedlist.length; ++i)
      markedlist[i].clearMark();

    return istrash;
  }

  apply(data: Funcdata): number {
    const indlist: PcodeOp[] = [];

    const iter = data.getFuncProto().trashBegin();
    const enditer = data.getFuncProto().trashEnd();
    for (const vdata of iteratorRange(iter, enditer)) {
      let vn: Varnode | null = data.findCoveredInput(vdata.size, vdata.getAddr() as any);
      if (vn === null) continue;
      if (vn.isTypeLock() || vn.isNameLock()) continue;
      indlist.length = 0;
      if (!ActionLikelyTrash.traceTrash(vn, indlist)) continue;

      for (let i = 0; i < indlist.length; ++i) {
        const op: PcodeOp = indlist[i];
        if (op.code() === OpCode.CPUI_INDIRECT) {
          // Truncate data-flow through INDIRECT, turning it into indirect creation
          data.opSetInput(op, data.newConstant(op.getOut()!.getSize(), 0n), 0);
          data.markIndirectCreation(op, false);
        } else if (op.code() === OpCode.CPUI_INT_AND) {
          data.opSetInput(op, data.newConstant(op.getIn(1)!.getSize(), 0n), 1);
        }
        this.count += 1;  // Indicate we made a change
      }
    }
    return 0;
  }
}

// ActionRestructureVarnode
// ------------------------

export class ActionRestructureVarnode extends Action {
  private numpass: number = 0;

  constructor(g: string) {
    super(0, "restructure_varnode", g);
  }

  reset(data: Funcdata): void {
    this.numpass = 0;
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionRestructureVarnode(this.getGroup());
  }

  /// Is the given Varnode a constant or a COPY of a constant
  private static isCopyConstant(vn: Varnode): boolean {
    if (vn.isConstant()) return true;
    if (!vn.isWritten()) return false;
    if (vn.getDef()!.code() !== OpCode.CPUI_COPY) return false;
    return vn.getDef()!.getIn(0).isConstant();
  }

  /// Return true if either the Varnode is a constant or if it is the not yet simplified
  /// COPY or INT_ADD of constants.
  private static isDelayedConstant(vn: Varnode): boolean {
    if (vn.isConstant()) return true;
    if (!vn.isWritten()) return false;
    const op: PcodeOp = vn.getDef()!;
    const opc: OpCode = op.code();
    if (opc === OpCode.CPUI_COPY)
      return op.getIn(0)!.isConstant();
    if (opc !== OpCode.CPUI_INT_ADD) return false;
    if (!ActionRestructureVarnode.isCopyConstant(op.getIn(1)!)) return false;
    if (!ActionRestructureVarnode.isCopyConstant(op.getIn(0)!)) return false;
    return true;
  }

  /// Test if the path to the given BRANCHIND originates from a constant but passes through INDIRECT operations.
  /// Mark the earliest INDIRECT operation as not collapsible.
  private static protectSwitchPathIndirects(op: PcodeOp): void {
    let lastIndirect: PcodeOp | null = null;
    let curVn: Varnode = op.getIn(0)!;
    while (curVn.isWritten()) {
      const curOp: PcodeOp = curVn.getDef()!;
      const evalType: number = curOp.getEvalType();
      if ((evalType & (PcodeOp.binary | PcodeOp.ternary)) !== 0) {
        if (curOp.numInput() > 1) {
          if (ActionRestructureVarnode.isDelayedConstant(curOp.getIn(1)!))
            curVn = curOp.getIn(0)!;
          else if (ActionRestructureVarnode.isDelayedConstant(curOp.getIn(0)!))
            curVn = curOp.getIn(1)!;
          else
            return;  // Multiple paths
        } else {
          curVn = curOp.getIn(0)!;
        }
      } else if ((evalType & PcodeOp.unary) !== 0)
        curVn = curOp.getIn(0)!;
      else if (curOp.code() === OpCode.CPUI_INDIRECT) {
        lastIndirect = curOp;
        curVn = curOp.getIn(0)!;
      } else if (curOp.code() === OpCode.CPUI_LOAD) {
        curVn = curOp.getIn(1)!;
      } else if (curOp.code() === OpCode.CPUI_MULTIEQUAL) {
        // Its possible there is a path from a constant that splits and rejoins.
        for (let i = 0; i < curOp.numInput(); ++i) {
          curVn = curOp.getIn(i)!;
          if (!curVn.isWritten()) continue;
          const inOp: PcodeOp = curVn.getDef()!;
          if (inOp.code() === OpCode.CPUI_INDIRECT) {
            inOp.setNoIndirectCollapse();
            break;
          }
        }
        return;  // In any case, we don't try to backtrack further
      } else
        return;
    }
    if (!curVn.isConstant()) return;
    // If we reach here, there is exactly one path, from a constant to a switch
    if (lastIndirect !== null)
      lastIndirect.setNoIndirectCollapse();
  }

  /// Run through BRANCHIND ops, treat them as switches and protect the data-flow path
  private static protectSwitchPaths(data: Funcdata): void {
    const bblocks: BlockGraph = data.getBasicBlocks();
    for (let i = 0; i < bblocks.getSize(); ++i) {
      const op: PcodeOp | null = bblocks.getBlock(i).lastOp();
      if (op === null) continue;
      if (op.code() !== OpCode.CPUI_BRANCHIND) continue;
      ActionRestructureVarnode.protectSwitchPathIndirects(op);
    }
  }

  apply(data: Funcdata): number {
    const l1: ScopeLocal = data.getScopeLocal();

    const aliasyes: boolean = (this.numpass !== 0);  // Alias calculations are not reliable on the first pass
    l1.restructureVarnode(aliasyes);
    if (data.syncVarnodesWithSymbols(l1, false, aliasyes))
      this.count += 1;

    if (data.isJumptableRecoveryOn())
      ActionRestructureVarnode.protectSwitchPaths(data);

    this.numpass += 1;
    return 0;
  }
}

// ActionMappedLocalSync
// ---------------------

export class ActionMappedLocalSync extends Action {
  constructor(g: string) {
    super(0, "mapped_local_sync", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionMappedLocalSync(this.getGroup());
  }

  apply(data: Funcdata): number {
    const l1: ScopeLocal = data.getScopeLocal();

    if (data.syncVarnodesWithSymbols(l1, true, true))
      this.count += 1;

    if (l1.hasOverlapProblems())
      data.warningHeader("Could not reconcile some variable overlaps");

    return 0;
  }
}

// ActionDefaultParams
// -------------------

export class ActionDefaultParams extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "defaultparams", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionDefaultParams(this.getGroup());
  }

  apply(data: Funcdata): number {
    let fc: FuncCallSpecs;
    let evalfp: ProtoModel | null = data.getArch().evalfp_called;  // Special model used when evaluating called funcs
    if (evalfp === null)  // If no special evaluation
      evalfp = data.getArch().defaultfp;  // Use the default model

    const size: number = data.numCalls();
    for (let i = 0; i < size; ++i) {
      fc = data.getCallSpecs_byIndex(i);
      if (!fc.hasModel()) {
        const otherfunc: Funcdata | null = fc.getFuncdata();

        if (otherfunc !== null) {
          fc.copy(otherfunc.getFuncProto());
          if (!fc.isModelLocked() && !fc.hasMatchingModel(evalfp!))
            fc.setModel(evalfp!);
        } else
          fc.setInternal(evalfp!, data.getArch().types.getTypeVoid());
      }
      fc.insertPcode(data);  // Insert any necessary pcode
    }
    return 0;  // Indicate success
  }
}

// ActionSetCasts
// --------------

export class ActionSetCasts extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "setcasts", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionSetCasts(this.getGroup());
  }

  /// Check if the data-type of the given value being used as a pointer makes sense.
  private static checkPointerIssues(op: PcodeOp, vn: Varnode, data: Funcdata): void {
    const ptrtype: Datatype = op.getIn(1)!.getHighTypeReadFacing(op);
    const valsize: number = vn.getSize();
    if (ptrtype.getMetatype() !== type_metatype.TYPE_PTR || (ptrtype as TypePointer).getPtrTo().getSize() !== valsize) {
      let name: string = op.getOpcode().getName();
      name = name.charAt(0).toUpperCase() + name.slice(1);
      data.warning(name + " size is inaccurate", op.getAddr());
    }
    if (ptrtype.getMetatype() === type_metatype.TYPE_PTR) {
      const spc: AddrSpace | null = (ptrtype as TypePointer).getSpace();
      if (spc !== null) {
        const opSpc: AddrSpace = op.getIn(0)!.getSpaceFromConst()!;
        if (opSpc !== spc && spc.getContain() !== opSpc) {
          let name: string = op.getOpcode().getName();
          name = name.charAt(0).toUpperCase() + name.slice(1);
          const s: string = `${name} refers to '${opSpc.getName()}' but pointer attribute is '${spc.getName()}'`;
          data.warning(s, op.getAddr());
        }
      }
    }
  }

  /// Test if the given cast conflict can be resolved by passing to the first structure/array field.
  private static testStructOffset0(reqtype: Datatype, curtype: Datatype, castStrategy: CastStrategy): boolean {
    if (curtype.getMetatype() !== type_metatype.TYPE_PTR) return false;
    const highPtrTo: Datatype = (curtype as TypePointer).getPtrTo();
    if (highPtrTo.getMetatype() === type_metatype.TYPE_STRUCT) {
      const highStruct: TypeStruct = highPtrTo as TypeStruct;
      if (highStruct.numDepend() === 0) return false;
      const fields = highStruct.beginField();
      if (fields[0].offset !== 0) return false;
      reqtype = (reqtype as TypePointer).getPtrTo();
      curtype = fields[0].type;
      if (reqtype.getMetatype() === type_metatype.TYPE_ARRAY)
        reqtype = (reqtype as TypeArray).getBase();
      if (curtype.getMetatype() === type_metatype.TYPE_ARRAY)
        curtype = (curtype as TypeArray).getBase();
    } else if (highPtrTo.getMetatype() === type_metatype.TYPE_ARRAY) {
      const highArray: TypeArray = highPtrTo as TypeArray;
      reqtype = (reqtype as TypePointer).getPtrTo();
      curtype = highArray.getBase();
    } else {
      return false;
    }
    if (reqtype.getMetatype() === type_metatype.TYPE_VOID) {
      return false;  // Don't induce PTRSUB for "void *"
    }
    return castStrategy.castStandard(reqtype, curtype, true, true) === null;
  }

  /// Try to adjust the input and output Varnodes to eliminate a CAST.
  private static tryResolutionAdjustment(op: PcodeOp, slot: number, data: Funcdata): boolean {
    const outvn: Varnode | null = op.getOut();
    if (outvn === null)
      return false;
    const outType: Datatype = outvn.getHigh().getType();
    const inType: Datatype = op.getIn(slot)!.getHigh().getType();
    if (!inType.needsResolution() && !outType.needsResolution()) return false;
    let inResolve: number = -1;
    let outResolve: number = -1;
    if (inType.needsResolution()) {
      inResolve = inType.findCompatibleResolve(outType);
      if (inResolve < 0) return false;
    }
    if (outType.needsResolution()) {
      if (inResolve >= 0)
        outResolve = outType.findCompatibleResolve(inType.getDepend(inResolve)!);
      else
        outResolve = outType.findCompatibleResolve(inType);
      if (outResolve < 0) return false;
    }

    const typegrp: TypeFactory = data.getArch().types;
    if (inType.needsResolution()) {
      const resolve: ResolvedUnion = new ResolvedUnion(inType, inResolve, typegrp);
      if (!data.setUnionField(inType, op, slot, resolve))
        return false;
    }
    if (outType.needsResolution()) {
      const resolve: ResolvedUnion = new ResolvedUnion(outType, outResolve, typegrp);
      if (!data.setUnionField(outType, op, -1, resolve))
        return false;
    }
    return true;
  }

  /// Test if two data-types are operation identical.
  private static isOpIdentical(ct1: Datatype, ct2: Datatype): boolean {
    while (ct1.getMetatype() === type_metatype.TYPE_PTR && ct2.getMetatype() === type_metatype.TYPE_PTR) {
      ct1 = (ct1 as TypePointer).getPtrTo();
      ct2 = (ct2 as TypePointer).getPtrTo();
    }
    while (ct1.getTypedef() !== null)
      ct1 = ct1.getTypedef()!;
    while (ct2.getTypedef() !== null)
      ct2 = ct2.getTypedef()!;
    return ct1 === ct2;
  }

  /// If the given op reads a pointer to a union, insert the OpCode.CPUI_PTRSUB that resolves the union.
  private static resolveUnion(op: PcodeOp, slot: number, data: Funcdata, castStrategy: CastStrategy): number {
    const vn: Varnode = op.getIn(slot)!;
    if (vn.isAnnotation()) return 0;
    let dt: Datatype = vn.getHigh().getType();
    if (!dt.needsResolution())
      return 0;
    if (dt !== vn.getType())
      dt.resolveInFlow(op, slot);  // Last chance to resolve data-type based on flow
    const resUnion: ResolvedUnion | null = data.getUnionField(dt, op, slot);
    if (resUnion !== null && resUnion.getFieldNum() >= 0) {
      if (dt.getMetatype() === type_metatype.TYPE_PTR) {
        // Test if a cast is still needed even after resolution
        const reqtype: Datatype = vn.getTypeReadFacing(op);
        if (castStrategy.castStandard(reqtype, resUnion.getDatatype(), true, true) !== null)
          return 0;  // If cast still needed, don't do the resolve
        // Insert specific placeholder indicating which field is accessed
        const ptrsub: PcodeOp = ActionSetCasts.insertPtrsubZero(op, slot, reqtype, data);
        data.setUnionField(dt, ptrsub, -1, resUnion);  // Attach the resolution to the PTRSUB
      } else if (vn.isImplied()) {
        if (vn.isWritten()) {
          // If the writefacing and readfacing resolutions for vn (an implied variable) are the same,
          // the resolutions are unnecessary and we treat the vn as if it had the field data-type
          const writeRes: ResolvedUnion | null = data.getUnionField(dt, vn.getDef()!, -1);
          if (writeRes !== null && writeRes.getFieldNum() === resUnion.getFieldNum())
            return 0;  // Don't print implied fields for vn
        }
        vn.setImpliedField();
      }
      return 1;
    }
    return 0;
  }

  /// Insert cast to output Varnode type after given PcodeOp if it is necessary.
  private static castOutput(op: PcodeOp, data: Funcdata, castStrategy: CastStrategy): number {
    let outct: Datatype;
    let ct: Datatype | null;
    let tokenct: Datatype;
    let vn: Varnode;
    let outvn: Varnode;
    let newop: PcodeOp;
    let outHighType: Datatype;
    let force: boolean = false;

    tokenct = op.getOpcode().getOutputToken(op, castStrategy);
    outvn = op.getOut()!;
    outHighType = outvn.getHigh().getType();
    if (tokenct === outHighType) {
      if (tokenct.needsResolution()) {
        // operation copies directly to outvn AS a union
        const resolve: ResolvedUnion = new ResolvedUnion(tokenct);  // Force the varnode to resolve to the parent data-type
        data.setUnionField(tokenct, op, -1, resolve);
      }
      // Short circuit more sophisticated casting tests. If they are the same type, there is no cast
      return 0;
    }
    let outHighResolve: Datatype = outHighType;
    if (outHighType.needsResolution()) {
      if (outHighType !== outvn.getType())
        outHighType.resolveInFlow(op, -1);  // Last chance to resolve data-type based on flow
      outHighResolve = outHighType.findResolve(op, -1);  // Finish fetching DefFacing data-type
    }
    if (outvn.isImplied()) {
      // implied varnode must have parse type
      if (outvn.isTypeLock()) {
        const outOp: PcodeOp | null = outvn.loneDescend();
        // The Varnode input to a OpCode.CPUI_RETURN is marked as implied but
        // casting should act as if it were explicit
        if (outOp === null || outOp.code() !== OpCode.CPUI_RETURN) {
          force = !ActionSetCasts.isOpIdentical(outHighResolve, tokenct);
        }
      } else if (outHighResolve.getMetatype() !== type_metatype.TYPE_PTR) {
        // If implied varnode has an atomic (non-pointer) type
        outvn.updateType(tokenct);  // Ignore it in favor of the token type
        outHighResolve = outvn.getHighTypeDefFacing();
      } else if (tokenct.getMetatype() === type_metatype.TYPE_PTR) {
        // If the token is a pointer AND implied varnode is pointer
        outct = (outHighResolve as TypePointer).getPtrTo();
        const meta: type_metatype = outct.getMetatype();
        // Preserve implied pointer if it points to a composite
        if (meta !== type_metatype.TYPE_ARRAY && meta !== type_metatype.TYPE_STRUCT && meta !== type_metatype.TYPE_UNION) {
          outvn.updateType(tokenct);  // Otherwise ignore it in favor of the token type
          outHighResolve = outvn.getHighTypeDefFacing();
        }
      }
    }
    let opc: OpCode = OpCode.CPUI_CAST;
    if (!force) {
      outct = outHighResolve;  // Type of result
      if (outct.getMetatype() === type_metatype.TYPE_PTR && ActionSetCasts.testStructOffset0(outct, tokenct, castStrategy)) {
        opc = OpCode.CPUI_PTRSUB;
      } else {
        ct = castStrategy.castStandard(outct, tokenct, false, true);
        if (ct === null) return 0;
      }
    }
    // Generate the cast op
    vn = data.newUnique(outvn.getSize());
    vn.updateType(tokenct);
    vn.setImplied();
    newop = data.newOp(opc !== OpCode.CPUI_CAST ? 2 : 1, op.getAddr());
    data.opSetOpcode(newop, opc);
    data.opSetOutput(newop, outvn);
    data.opSetInput(newop, vn, 0);
    if (opc !== OpCode.CPUI_CAST) {
      data.opSetInput(newop, data.newConstant(4, 0n), 1);
    }
    data.opSetOutput(op, vn);
    data.opInsertAfter(newop, op);  // Cast comes AFTER this operation
    if (tokenct.needsResolution())
      data.forceFacingType(tokenct, -1, newop, 0);
    if (outHighType.needsResolution())
      data.inheritResolution(outHighType, newop, -1, op, -1);  // Inherit write resolution

    return 1;
  }

  /// Insert a PTRSUB with offset 0 that accesses a field of the given data-type.
  private static insertPtrsubZero(op: PcodeOp, slot: number, ct: Datatype, data: Funcdata): PcodeOp {
    const vn: Varnode = op.getIn(slot)!;
    const newop: PcodeOp = data.newOp(2, op.getAddr());
    const vnout: Varnode = data.newUniqueOut(vn.getSize(), newop);
    vnout.updateType(ct);
    vnout.setImplied();
    data.opSetOpcode(newop, OpCode.CPUI_PTRSUB);
    data.opSetInput(newop, vn, 0);
    data.opSetInput(newop, data.newConstant(4, 0n), 1);
    data.opSetInput(op, vnout, slot);
    data.opInsertBefore(newop, op);
    return newop;
  }

  /// Insert cast to produce the input Varnode to a given PcodeOp if necessary.
  private static castInput(op: PcodeOp, slot: number, data: Funcdata, castStrategy: CastStrategy): number {
    let ct: Datatype | null;
    let vn: Varnode;
    let vnout: Varnode;
    let vnin: Varnode;
    let newop: PcodeOp;

    ct = op.getOpcode().getInputCast(op, slot, castStrategy);  // Input type expected by this operation
    if (ct === null) {
      const resUnsigned: boolean = castStrategy.markExplicitUnsigned(op, slot);
      const resSized: boolean = castStrategy.markExplicitLongSize(op, slot);
      if (resUnsigned || resSized)
        return 1;
      return 0;
    }

    vnin = vn = op.getIn(slot)!;
    // Check to make sure we don't have a double cast
    if (vn.isWritten() && vn.getDef()!.code() === OpCode.CPUI_CAST) {
      if (vn.isImplied()) {
        if (vn.loneDescend() === op) {
          vn.updateType(ct);
          if (vn.getType() === ct)
            return 1;
        }
        vnin = vn.getDef()!.getIn(0);  // Cast directly from input of previous cast
        if (ct === vnin.getType()) {  // If the earlier data-type is what the input expects
          data.opSetInput(op, vnin, slot);  // Just use the earlier Varnode
          return 1;
        }
      }
    } else if (vn.isConstant()) {
      vn.updateType(ct);
      if (vn.getType() === ct)
        return 1;
    } else if (ct.getMetatype() === type_metatype.TYPE_PTR && ActionSetCasts.testStructOffset0(ct, vn.getHighTypeReadFacing(op), castStrategy)) {
      // Insert a PTRSUB(vn,#0) instead of a CAST
      newop = ActionSetCasts.insertPtrsubZero(op, slot, ct, data);
      if (vn.getHigh().getType().needsResolution())
        data.inheritResolution(vn.getHigh().getType(), newop, 0, op, slot);
      return 1;
    } else if (ActionSetCasts.tryResolutionAdjustment(op, slot, data)) {
      return 1;
    }
    newop = data.newOp(1, op.getAddr());
    vnout = data.newUniqueOut(vnin.getSize(), newop);
    vnout.updateType(ct);
    vnout.setImplied();
    data.opSetOpcode(newop, OpCode.CPUI_CAST);
    data.opSetInput(newop, vnin, 0);
    data.opSetInput(op, vnout, slot);
    data.opInsertBefore(newop, op);  // Cast comes AFTER operation
    if (ct.needsResolution()) {
      data.forceFacingType(ct, -1, newop, -1);
    }
    if (vn.getHigh().getType().needsResolution()) {
      data.inheritResolution(vn.getHigh().getType(), newop, 0, op, slot);
    }
    return 1;
  }

  apply(data: Funcdata): number {
    let op: PcodeOp;

    data.startCastPhase();
    const castStrategy: CastStrategy = data.getArch().print.getCastStrategy();
    // We follow data flow, doing basic blocks in dominance order
    // Doing operations in basic block order
    const basicblocks: BlockGraph = data.getBasicBlocks();
    for (let j = 0; j < basicblocks.getSize(); ++j) {
      const bb: BlockBasic = basicblocks.getBlock(j) as BlockBasic;
      for (const iter of (bb as any).getOpIterator()) {
        op = iter;
        if (op.notPrinted()) continue;
        const opc: OpCode = op.code();
        if (opc === OpCode.CPUI_CAST) continue;
        if (opc === OpCode.CPUI_PTRADD) {  // Check for PTRADD that no longer fits its pointer
          const sz: number = Number(op.getIn(2)!.getOffset());
          const ct: Datatype = op.getIn(0)!.getHighTypeReadFacing(op);
          if (ct.getMetatype() !== type_metatype.TYPE_PTR ||
            (ct as TypePointer).getPtrTo().getAlignSize() !== Number(AddrSpace.addressToByteInt(BigInt(sz), (ct as TypePointer).getWordSize())))
            data.opUndoPtradd(op, true);
        } else if (opc === OpCode.CPUI_PTRSUB) {  // Check for PTRSUB that no longer fits pointer
          if (!op.getIn(0)!.getTypeReadFacing(op).isPtrsubMatching(op.getIn(1)!.getOffset(), 0, 0)) {
            if (op.getIn(1)!.getOffset() === 0n) {
              data.opRemoveInput(op, 1);
              data.opSetOpcode(op, OpCode.CPUI_COPY);
            } else
              data.opSetOpcode(op, OpCode.CPUI_INT_ADD);
          }
        }
        // Do input casts first, as output may depend on input
        for (let i = 0; i < op.numInput(); ++i) {
          this.count += ActionSetCasts.resolveUnion(op, i, data, castStrategy);
          this.count += ActionSetCasts.castInput(op, i, data, castStrategy);
        }
        if (opc === OpCode.CPUI_LOAD) {
          ActionSetCasts.checkPointerIssues(op, op.getOut()!, data);
        } else if (opc === OpCode.CPUI_STORE) {
          ActionSetCasts.checkPointerIssues(op, op.getIn(2)!, data);
        }
        const vn: Varnode | null = op.getOut();
        if (vn === null) continue;
        this.count += ActionSetCasts.castOutput(op, data, castStrategy);
      }
    }
    return 0;  // Indicate full completion
  }
}

// ActionNameVars
// --------------

export class ActionNameVars extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "namevars", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionNameVars(this.getGroup());
  }

  /// Name the Varnode which seems to be the putative switch variable for an
  /// unrecovered jump-table with a special name.
  private static lookForBadJumpTables(data: Funcdata): void {
    const numfunc: number = data.numCalls();
    const localmap: ScopeLocal = data.getScopeLocal();
    for (let i = 0; i < numfunc; ++i) {
      const fc: FuncCallSpecs = data.getCallSpecs_byIndex(i);
      if (fc.isBadJumpTable()) {
        const op: PcodeOp = fc.getOp();
        let vn: Varnode = op.getIn(0)!;
        if (vn.isImplied() && vn.isWritten()) {  // Skip any cast into the function
          const castop: PcodeOp = vn.getDef()!;
          if (castop.code() === OpCode.CPUI_CAST)
            vn = castop.getIn(0)!;
        }
        if (vn.isFree()) continue;
        const sym: Symbol | null = vn.getHigh().getSymbol();
        if (sym === null) continue;
        if (sym.isNameLocked()) continue;  // Override any unlocked name
        if (sym.getScope() !== localmap) continue;  // Only name this in the local scope
        const newname: string = "UNRECOVERED_JUMPTABLE";
        sym.getScope().renameSymbol(sym, localmap.makeNameUnique(newname));
      }
    }
  }

  /// Add a recommendation to the database based on a particular sub-function parameter.
  private static makeRec(param: ProtoParameter, vn: Varnode, recmap: Map<HighVariable, OpRecommend>): void {
    if (!param.isNameLocked()) return;
    if (param.isNameUndefined()) return;
    if (vn.getSize() !== param.getSize()) return;
    let ct: Datatype | null = param.getType();
    if (vn.isImplied() && vn.isWritten()) {  // Skip any cast into the function
      const castop: PcodeOp = vn.getDef()!;
      if (castop.code() === OpCode.CPUI_CAST) {
        vn = castop.getIn(0)!;
        ct = null;  // Indicate that this is a less preferred name
      }
    }
    const high: HighVariable = vn.getHigh();
    if (high.isAddrTied()) return;  // Don't propagate parameter name to address tied variable
    if (param.getName().substring(0, 6) === "param_") return;

    const existing = recmap.get(high);
    if (existing !== undefined) {  // We have seen this varnode before
      if (ct === null) return;  // Cannot override with null (casted) type
      const oldtype: Datatype | null = existing.ct;
      if (oldtype !== null) {
        if (oldtype.typeOrder(ct) <= 0) return;  // oldtype is more specified
      }
      existing.ct = ct;
      existing.namerec = param.getName();
    } else {
      const oprec: OpRecommend = {
        ct: ct,
        namerec: param.getName()
      };
      recmap.set(high, oprec);
    }
  }

  /// Collect potential variable names from sub-function parameters.
  private static lookForFuncParamNames(data: Funcdata, varlist: Varnode[]): void {
    const numfunc: number = data.numCalls();
    if (numfunc === 0) return;

    const recmap: Map<HighVariable, OpRecommend> = new Map();

    const localmap: ScopeLocal = data.getScopeLocal();
    for (let i = 0; i < numfunc; ++i) {  // Run through all calls to functions
      const fc: FuncCallSpecs = data.getCallSpecs_byIndex(i);
      if (!fc.isInputLocked()) continue;
      const op: PcodeOp = fc.getOp();
      let numparam: number = fc.numParams();
      if (numparam >= op.numInput())
        numparam = op.numInput() - 1;
      for (let j = 0; j < numparam; ++j) {
        const param: ProtoParameter = fc.getParam(j);  // Looking for a parameter
        const vn: Varnode = op.getIn(j + 1)!;
        ActionNameVars.makeRec(param, vn, recmap);
      }
    }
    if (recmap.size === 0) return;

    for (let i = 0; i < varlist.length; ++i) {  // Do the actual naming in the original (address based) order
      const vn: Varnode = varlist[i];
      if (vn.isFree()) continue;
      if (vn.isInput()) continue;  // Don't override unaffected or input naming strategy
      const high: HighVariable = vn.getHigh();
      if (high.getNumMergeClasses() > 1) continue;  // Don't inherit a name if speculatively merged
      const sym: Symbol | null = high.getSymbol();
      if (sym === null) continue;
      if (!sym.isNameUndefined()) continue;
      const rec = recmap.get(high);
      if (rec !== undefined) {
        sym.getScope().renameSymbol(sym, localmap.makeNameUnique(rec.namerec));
      }
    }
  }

  /// Link symbols associated with a given spacebase Varnode.
  private static linkSpacebaseSymbol(vn: Varnode, data: Funcdata, namerec: Varnode[]): void {
    if (!vn.isConstant() && !vn.isInput()) return;
    for (const op of (vn as any).descend) {
      if (op.code() !== OpCode.CPUI_PTRSUB) continue;
      const offVn: Varnode = op.getIn(1);
      const sym: Symbol | null = data.linkSymbolReference(offVn);
      if (sym !== null && sym.isNameUndefined())
        namerec.push(offVn);
    }
  }

  /// Link formal Symbols to their HighVariable representative in the given Function.
  private static linkSymbols(data: Funcdata, namerec: Varnode[]): void {
    const manage: AddrSpaceManager = data.getArch();
    const constSpace: AddrSpace = manage.getConstantSpace();
    for (const curvn of (data as any).getLocIterator(constSpace)) {
      if (curvn.getSymbolEntry() !== null)
        data.linkSymbol(curvn);  // Special equate symbol
      else if (curvn.isSpacebase())
        ActionNameVars.linkSpacebaseSymbol(curvn, data, namerec);
    }

    const typeFactory: TypeFactory = data.getArch().types;
    for (let i = 0; i < manage.numSpaces(); ++i) {  // Build a list of nameable highs
      const spc: AddrSpace | null = manage.getSpace(i);
      if (spc === null) continue;
      if (spc === constSpace) continue;
      for (const curvn of (data as any).getLocIterator(spc)) {
        if (curvn.isFree()) {
          continue;
        }
        if (curvn.isSpacebase())
          ActionNameVars.linkSpacebaseSymbol(curvn, data, namerec);
        const vn: Varnode = curvn.getHigh().getNameRepresentative();
        if (vn !== curvn) continue;  // Hit each high only once
        const high: HighVariable = vn.getHigh();
        if (!high.hasName()) continue;
        const sym: Symbol | null = data.linkSymbol(vn);
        if (sym !== null) {  // Can we associate high with a nameable symbol
          if (sym.isNameUndefined() && high.getSymbolOffset() < 0)
            namerec.push(vn);  // Add if no name, and we have a high representing the whole
          if (sym.isSizeTypeLocked()) {
            if (vn.getSize() === sym.getType().getSize())
              sym.getScope().overrideSizeLockType(sym, high.getType());
          }
          if (vn.isAddrTied() && !sym.getScope().isGlobal())
            high.finalizeDatatype(typeFactory);
        }
      }
    }
  }

  apply(data: Funcdata): number {
    const namerec: Varnode[] = [];

    ActionNameVars.linkSymbols(data, namerec);
    data.getScopeLocal()!.recoverNameRecommendationsForSymbols();  // Make sure recommended names hit before subfunc
    ActionNameVars.lookForBadJumpTables(data);
    ActionNameVars.lookForFuncParamNames(data, namerec);

    const base = { val: 1 };
    for (let i = 0; i < namerec.length; ++i) {
      const vn: Varnode = namerec[i];
      const sym: Symbol | null = vn.getHigh().getSymbol();
      if (sym !== null && sym.isNameUndefined()) {
        const scope: Scope = sym.getScope();
        const newname: string = scope.buildDefaultName(sym, base, vn);
        scope.renameSymbol(sym, newname);
      }
    }
    data.getScopeLocal()!.assignDefaultNames(base);
    return 0;
  }
}

// ActionMarkExplicit
// ------------------

export class ActionMarkExplicit extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "markexplicit", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionMarkExplicit(this.getGroup());
  }

  /// Make initial determination if a Varnode should be explicit.
  /// If the given Varnode is defined by OpCode.CPUI_NEW, return -2 indicating it should be explicit
  /// and that it needs special printing.
  private static baseExplicit(vn: Varnode, maxref: number): number {
    const def: PcodeOp | null = vn.getDef();
    if (def === null) return -1;
    if (def.isMarker()) return -1;
    if (def.isCall()) {
      if (def.code() === OpCode.CPUI_NEW && def.numInput() === 1)
        return -2;  // Explicit, but may need special printing
      return -1;
    }
    const high: HighVariable | null = vn.getHigh();
    if (high !== null && high.numInstances() > 1) return -1;  // Must not be merged at all
    if (vn.isAddrTied()) {  // We need to see addrtied as explicit because pointers may reference it
      if (def.code() === OpCode.CPUI_SUBPIECE) {
        const vin: Varnode = def.getIn(0)!;
        if (vin.isAddrTied()) {
          if ((vn as any).overlapJoinVarnode(vin) === Number(def.getIn(1)!.getOffset()))
            return -1;  // Should be explicit, will be a copymarker and not printed
        }
      }
      const useOp: PcodeOp | null = vn.loneDescend();
      if (useOp === null) return -1;
      if (useOp.code() === OpCode.CPUI_INT_ZEXT) {
        const vnout: Varnode = useOp.getOut()!;
        if (!vnout.isAddrTied() || 0 !== vnout.contains(vn))
          return -1;
      } else if (useOp.code() === OpCode.CPUI_PIECE) {
        const rootVn: Varnode = PieceNode.findRoot(vn);
        if (vn === rootVn) return -1;
        if (rootVn.getDef()!.isPartialRoot()) {
          return -1;
        }
      } else {
        return -1;
      }
    } else if (vn.isMapped()) {
      return -1;
    } else if (vn.isProtoPartial()) {
      return -1;
    } else if (def.code() === OpCode.CPUI_PIECE && def.getIn(0)!.isProtoPartial()) {
      return -1;
    }
    if (vn.hasNoDescend()) return -1;  // Must have at least one descendant

    if (def.code() === OpCode.CPUI_PTRSUB) {  // A dereference
      const basevn: Varnode = def.getIn(0)!;
      if (basevn.isSpacebase()) {  // of a spacebase
        if (basevn.isConstant() || basevn.isInput())
          maxref = 1000000;  // Should always be implicit, so remove limit on max references
      }
    }
    let desccount: number = 0;
    for (const op of (vn as any).descend) {
      if (op.isMarker()) return -1;
      desccount += 1;
      if (desccount > maxref) return -1;  // Must not exceed max descendants
    }

    return desccount;
  }

  /// Look for certain situations where one Varnode with multiple descendants has one descendant who also has
  /// multiple descendants.  Mark the top Varnode as explicit.
  private static multipleInteraction(multlist: Varnode[]): number {
    const purgelist: Varnode[] = [];

    for (let i = 0; i < multlist.length; ++i) {
      const vn: Varnode = multlist[i];  // All elements in this list should have a defining op
      const op: PcodeOp = vn.getDef()!;
      const opc: OpCode = op.code();
      if (op.isBoolOutput() || opc === OpCode.CPUI_INT_ZEXT || opc === OpCode.CPUI_INT_SEXT || opc === OpCode.CPUI_PTRADD) {
        let maxparam: number = 2;
        if (op.numInput() < maxparam)
          maxparam = op.numInput();
        let topvn: Varnode | null = null;
        for (let j = 0; j < maxparam; ++j) {
          topvn = op.getIn(j);
          if (topvn!.isMark()) {  // We have a "multiple" interaction between topvn and vn
            let topopc: OpCode = OpCode.CPUI_COPY;
            if (topvn!.isWritten()) {
              if (topvn!.getDef()!.isBoolOutput())
                continue;  // Try not to make boolean outputs explicit
              topopc = topvn!.getDef()!.code();
            }
            if (opc === OpCode.CPUI_PTRADD) {
              if (topopc === OpCode.CPUI_PTRADD)
                purgelist.push(topvn!);
            } else
              purgelist.push(topvn!);
          }
        }
      }
    }

    for (let i = 0; i < purgelist.length; ++i) {
      const vn: Varnode = purgelist[i];
      vn.setExplicit();
      vn.clearImplied();
      vn.clearMark();
    }
    return purgelist.length;
  }

  /// Count the number of terms in the expression making up vn. If
  /// there are more than max terms, mark vn as explicit.
  private static processMultiplier(vn: Varnode, max: number): void {
    const opstack: OpStackElement[] = [];
    let vncur: Varnode;
    let finalcount: number = 0;

    opstack.push(new OpStackElement(vn));
    do {
      vncur = opstack[opstack.length - 1].vn;
      const isaterm: boolean = vncur.isExplicit() || !vncur.isWritten();
      if (isaterm || opstack[opstack.length - 1].slotback <= opstack[opstack.length - 1].slot) {  // Trimming condition
        if (isaterm) {
          if (!vncur.isSpacebase())  // Don't count space base
            finalcount += 1;
        }
        if (finalcount > max) {
          vn.setExplicit();  // Make this variable explicit
          vn.clearImplied();
          return;
        }
        opstack.pop();
      } else {
        const op: PcodeOp = vncur.getDef()!;
        const newvn: Varnode = op.getIn(opstack[opstack.length - 1].slot++)!;
        if (newvn.isMark()) {  // If an ancestor is marked (also possible implied with multiple descendants)
          vn.setExplicit();  // then automatically consider this to be explicit
          vn.clearImplied();
        }
        opstack.push(new OpStackElement(newvn));
      }
    } while (opstack.length > 0);
  }

  /// Assume vn is produced via a OpCode.CPUI_NEW operation. If it is immediately fed to a constructor,
  /// set special printing flags on the Varnode.
  private static checkNewToConstructor(data: Funcdata, vn: Varnode): void {
    const op: PcodeOp = vn.getDef()!;
    const bb: BlockBasic = op.getParent();
    let firstuse: PcodeOp | null = null;
    for (const curop of (vn as any).descend) {
      if (curop.getParent() !== bb) continue;
      if (firstuse === null)
        firstuse = curop;
      else if (curop.getSeqNum().getOrder() < firstuse.getSeqNum().getOrder())
        firstuse = curop;
      else if (curop.code() === OpCode.CPUI_CALLIND) {
        const ptr: Varnode = curop.getIn(0);
        if (ptr.isWritten()) {
          if (ptr.getDef() === firstuse)
            firstuse = curop;
        }
      }
    }
    if (firstuse === null) return;

    if (!firstuse.isCall()) return;
    if (firstuse.getOut() !== null) return;
    if (firstuse.numInput() < 2) return;  // Must have at least 1 parameter (plus destination varnode)
    if (firstuse.getIn(1) !== vn) return;  // First parameter must result of new
    data.opMarkSpecialPrint(firstuse);  // Mark call to print the new operator as well
    data.opMarkNonPrinting(op);  // Don't print the new operator as stand-alone operation
  }

  apply(data: Funcdata): number {
    const multlist: Varnode[] = [];  // implied varnodes with >1 descendants
    let maxref: number;

    maxref = data.getArch().max_implied_ref;
    const enditer = data.beginDefFlags(0);  // Cut out free varnodes
    for (let viter = data.beginDef(); !viter.equals(enditer); viter.next()) {
      const vn: Varnode = viter.get();
      const desccount: number = ActionMarkExplicit.baseExplicit(vn, maxref);
      if (desccount < 0) {
        vn.setExplicit();
        this.count += 1;
        if (desccount < -1)
          ActionMarkExplicit.checkNewToConstructor(data, vn);
      } else if (desccount > 1) {  // Keep track of possible implieds with more than one descendant
        vn.setMark();
        multlist.push(vn);
      }
    }

    this.count += ActionMarkExplicit.multipleInteraction(multlist);
    const maxdup: number = data.getArch().max_term_duplication;
    for (let i = 0; i < multlist.length; ++i) {
      const vn: Varnode = multlist[i];
      if (vn.isMark())  // Mark may have been cleared by multipleInteraction
        ActionMarkExplicit.processMultiplier(vn, maxdup);
    }
    for (let i = 0; i < multlist.length; ++i)
      multlist[i].clearMark();
    return 0;
  }
}

// ActionMarkImplied
// -----------------

export class ActionMarkImplied extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "markimplied", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionMarkImplied(this.getGroup());
  }

  /// Return false only if one Varnode is obtained by adding non-zero thing to another Varnode.
  private static isPossibleAliasStep(vn1: Varnode, vn2: Varnode): boolean {
    const vars: Varnode[] = [vn1, vn2];
    for (let i = 0; i < 2; ++i) {
      const vncur: Varnode = vars[i];
      if (!vncur.isWritten()) continue;
      const op: PcodeOp = vncur.getDef()!;
      const opc: OpCode = op.code();
      if (opc !== OpCode.CPUI_INT_ADD && opc !== OpCode.CPUI_PTRSUB && opc !== OpCode.CPUI_PTRADD && opc !== OpCode.CPUI_INT_XOR) continue;
      if (vars[1 - i] !== op.getIn(0)) continue;
      if (op.getIn(1)!.isConstant()) return false;
    }
    return true;
  }

  /// Return false only if we can guarantee two Varnodes have different values.
  private static isPossibleAlias(vn1: Varnode, vn2: Varnode, depth: number): boolean {
    if (vn1 === vn2) return true;  // Definite alias
    if (!vn1.isWritten() || !vn2.isWritten()) {
      if (vn1.isConstant() && vn2.isConstant())
        return vn1.getOffset() === vn2.getOffset();
      return ActionMarkImplied.isPossibleAliasStep(vn1, vn2);
    }

    if (!ActionMarkImplied.isPossibleAliasStep(vn1, vn2))
      return false;
    let cvn1: Varnode;
    let cvn2: Varnode;
    const op1: PcodeOp = vn1.getDef()!;
    const op2: PcodeOp = vn2.getDef()!;
    let opc1: OpCode = op1.code();
    let opc2: OpCode = op2.code();
    let mult1: number = 1;
    let mult2: number = 1;
    if (opc1 === OpCode.CPUI_PTRSUB)
      opc1 = OpCode.CPUI_INT_ADD;
    else if (opc1 === OpCode.CPUI_PTRADD) {
      opc1 = OpCode.CPUI_INT_ADD;
      mult1 = Number(op1.getIn(2)!.getOffset());
    }
    if (opc2 === OpCode.CPUI_PTRSUB)
      opc2 = OpCode.CPUI_INT_ADD;
    else if (opc2 === OpCode.CPUI_PTRADD) {
      opc2 = OpCode.CPUI_INT_ADD;
      mult2 = Number(op2.getIn(2)!.getOffset());
    }
    if (opc1 !== opc2) return true;
    if (depth === 0) return true;  // Couldn't find absolute difference
    depth -= 1;
    switch (opc1) {
      case OpCode.CPUI_COPY:
      case OpCode.CPUI_INT_ZEXT:
      case OpCode.CPUI_INT_SEXT:
      case OpCode.CPUI_INT_2COMP:
      case OpCode.CPUI_INT_NEGATE:
        return ActionMarkImplied.isPossibleAlias(op1.getIn(0)!, op2.getIn(0)!, depth);
      case OpCode.CPUI_INT_ADD:
        cvn1 = op1.getIn(1)!;
        cvn2 = op2.getIn(1)!;
        if (cvn1.isConstant() && cvn2.isConstant()) {
          const val1: bigint = BigInt(mult1) * cvn1.getOffset();
          const val2: bigint = BigInt(mult2) * cvn2.getOffset();
          if (val1 === val2)
            return ActionMarkImplied.isPossibleAlias(op1.getIn(0)!, op2.getIn(0)!, depth);
          return !functionalEquality(op1.getIn(0), op2.getIn(0));
        }
        if (mult1 !== mult2) return true;
        if (functionalEquality(op1.getIn(0), op2.getIn(0)))
          return ActionMarkImplied.isPossibleAlias(op1.getIn(1)!, op2.getIn(1)!, depth);
        if (functionalEquality(op1.getIn(1), op2.getIn(1)))
          return ActionMarkImplied.isPossibleAlias(op1.getIn(0)!, op2.getIn(0)!, depth);
        if (functionalEquality(op1.getIn(0), op2.getIn(1)))
          return ActionMarkImplied.isPossibleAlias(op1.getIn(1)!, op2.getIn(0)!, depth);
        if (functionalEquality(op1.getIn(1), op2.getIn(0)))
          return ActionMarkImplied.isPossibleAlias(op1.getIn(0)!, op2.getIn(1)!, depth);
        break;
      default:
        break;
    }
    return true;
  }

  /// Check for Cover violation if Varnode is implied.
  private static checkImpliedCover(data: Funcdata, vn: Varnode): boolean {
    let op: PcodeOp;
    let storeop: PcodeOp;
    let callop: PcodeOp;
    let defvn: Varnode;

    op = vn.getDef()!;
    if (op.code() === OpCode.CPUI_LOAD) {  // Check for loads crossing stores
      for (const storeop of (data as any).getOpIterator(OpCode.CPUI_STORE)) {
        if (storeop.isDead()) continue;
        if (vn.getCover()!.contain(storeop, 2)) {
          if (storeop.getIn(0)!.getOffset() === op.getIn(0)!.getOffset()) {
            if (ActionMarkImplied.isPossibleAlias(storeop.getIn(1)!, op.getIn(1)!, 2)) return false;
          }
        }
      }
    }
    if (op.isCall() || op.code() === OpCode.CPUI_LOAD) {  // loads crossing calls
      for (let i = 0; i < data.numCalls(); ++i) {
        callop = data.getCallSpecs_byIndex(i).getOp();
        if (vn.getCover()!.contain(callop, 2)) return false;
      }
    }
    for (let i = 0; i < op.numInput(); ++i) {
      defvn = op.getIn(i)!;
      if (defvn.isConstant()) continue;
      if (data.getMerge().inflateTest(defvn, vn.getHigh()))  // Test for intersection
        return false;
    }
    return true;
  }

  apply(data: Funcdata): number {
    let vn: Varnode;
    let vncur: Varnode;
    let outvn: Varnode | null;
    const varstack: DescTreeElement[] = [];  // Depth first varnode traversal stack

    const locEnd = data.endLoc();
    for (let viter = data.beginLoc(); !viter.equals(locEnd); viter.next()) {
      vn = viter.get();
      if (vn.isFree()) continue;
      if (vn.isExplicit()) continue;
      if (vn.isImplied()) continue;
      varstack.push(new DescTreeElement(vn));
      do {
        const top = varstack[varstack.length - 1];
        vncur = top.vn;
        if (top.done) {
          // All descendants are traced first, try to make vncur implied
          this.count += 1;  // Will be marked either explicit or implied
          if (!ActionMarkImplied.checkImpliedCover(data, vncur))  // Can this variable be implied
            vncur.setExplicit();  // if not, mark explicit
          else {
            Merge.markImplied(vncur);
          }
          varstack.pop();
        } else {
          outvn = top.advance().getOut();
          if (outvn !== null) {
            if (!outvn.isExplicit() && !outvn.isImplied())
              varstack.push(new DescTreeElement(outvn));
          }
        }
      } while (varstack.length > 0);
    }

    return 0;
  }
}

// Part 2 duplicates removed - see Part 3 below for full implementations
// PART 3 of coreaction.cc translation (lines ~3457–5741)
// Covers: ActionUnreachable, ActionDoNothing, ActionRedundBranch, ActionDeterminedBranch,
//         ActionDeadCode (pushConsumed, propagateConsumed, neverConsumed, markConsumedParameters,
//         gatherConsumedReturn, lastChanceLoad, apply),
//         ActionConditionalConst, ActionSwitchNorm, ActionNormalizeSetup,
//         ActionPrototypeTypes, ActionInputPrototype, ActionOutputPrototype,
//         ActionUnjustifiedParams, ActionHideShadow, ActionDynamicMapping,
//         ActionDynamicSymbols, ActionPrototypeWarnings, ActionInternalStorage,
//         ActionInferTypes (buildLocaltypes, writeBack, propagateTypeEdge, propagateOneType,
//         propagateRef, propagateSpacebaseRef, canonicalReturnOp, propagateAcrossReturns, apply),
//         PropagationState,
//         ActionDatabase.buildDefaultGroups, ActionDatabase.universalAction

// =====================================================================
// ActionUnreachable
// =====================================================================

export class ActionUnreachable extends Action {
  constructor(g: string) {
    super(0, "unreachable", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionUnreachable(this.getGroup());
  }

  apply(data: Funcdata): number {
    // Detect unreachable blocks and remove
    if (data.removeUnreachableBlocks(true, false))
      this.count += 1;	// Deleting at least one block

    return 0;
  }
}

// =====================================================================
// ActionDoNothing
// =====================================================================

export class ActionDoNothing extends Action {
  constructor(g: string) {
    super(Action.rule_repeatapply, "donothing", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionDoNothing(this.getGroup());
  }

  apply(data: Funcdata): number {
    // Remove blocks that do nothing
    const graph: BlockGraph = data.getBasicBlocks();

    for (let i = 0; i < graph.getSize(); ++i) {
      const bb: BlockBasic = graph.getBlock(i) as BlockBasic;
      if (bb.isDoNothing()) {
        if ((bb.sizeOut() === 1) && (bb.getOut(0) === bb)) { // Infinite loop
          if (!bb.isDonothingLoop()) {
            bb.setDonothingLoop();
            data.warning("Do nothing block with infinite loop", bb.getStart());
          }
        }
        else if (bb.unblockedMulti(0)) {
          data.removeDoNothingBlock(bb);
          this.count += 1;
          return 0;
        }
      }
    }
    return 0;
  }
}

// =====================================================================
// ActionRedundBranch
// =====================================================================

export class ActionRedundBranch extends Action {
  constructor(g: string) {
    super(0, "redundbranch", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionRedundBranch(this.getGroup());
  }

  apply(data: Funcdata): number {
    // Remove redundant branches, i.e. a OpCode.CPUI_CBRANCH that falls thru and branches to the same place
    const graph: BlockGraph = data.getBasicBlocks();

    for (let i = 0; i < graph.getSize(); ++i) {
      const bb: BlockBasic = graph.getBlock(i) as BlockBasic;
      if (bb.sizeOut() === 0) continue;
      const bl: FlowBlock = bb.getOut(0);
      if (bb.sizeOut() === 1) {
        if ((bl.sizeIn() === 1) && (!bl.isEntryPoint()) && (!bb.isSwitchOut())) {
          // Do not splice block coming from single exit switch as this prevents possible second stage recovery
          data.spliceBlockBasic(bb);
          this.count += 1;
          // This will remove one block, so reset i
          i = -1;
        }
        continue;
      }
      let j: number;
      for (j = 1; j < bb.sizeOut(); ++j) // Are all exits to the same block? (bl)
        if (bb.getOut(j) !== bl) break;
      if (j !== bb.sizeOut()) continue;

      data.removeBranch(bb, 1);	// Remove the branch instruction
      this.count += 1;
    }
    return 0;			// Indicate full rule was applied
  }
}

// =====================================================================
// ActionDeterminedBranch
// =====================================================================

export class ActionDeterminedBranch extends Action {
  constructor(g: string) {
    super(0, "determinedbranch", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionDeterminedBranch(this.getGroup());
  }

  apply(data: Funcdata): number {
    const graph: BlockGraph = data.getBasicBlocks();

    for (let i = 0; i < graph.getSize(); ++i) {
      const bb: BlockBasic = graph.getBlock(i) as BlockBasic;
      const cbranch: PcodeOp | null = bb.lastOp();
      if (cbranch === null || cbranch.code() !== OpCode.CPUI_CBRANCH) continue;
      if (!cbranch.getIn(1)!.isConstant()) continue;
      const val: bigint = cbranch.getIn(1)!.getOffset();
      const num: number = ((val !== 0n) !== cbranch.isBooleanFlip()) ? 0 : 1;
      data.removeBranch(bb, num);
      this.count += 1;
    }
    return 0;
  }
}

// =====================================================================
// ActionDeadCode
// =====================================================================

export class ActionDeadCode extends Action {
  constructor(g: string) {
    super(0, "deadcode", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionDeadCode(this.getGroup());
  }

  /// Given a new consume value to push to a Varnode, determine if this changes
  /// the Varnodes consume value and whether to push the Varnode onto the work-list.
  private static pushConsumed(val: bigint, vn: Varnode, worklist: Varnode[]): void {
    let newval: bigint = (val | vn.getConsume()) & calc_mask(vn.getSize());
    if ((newval === vn.getConsume()) && vn.isConsumeVacuous()) return;
    vn.setConsumeVacuous();
    if (!vn.isConsumeList()) {	// Check if already in list
      vn.setConsumeList();	// Mark as in the list
      if (vn.isWritten())
        worklist.push(vn);	// add to list
    }
    vn.setConsume(newval);
  }

  /// Propagate the consumed value for one Varnode
  private static propagateConsumed(worklist: Varnode[]): void {
    const vn: Varnode = worklist.pop()!;
    const outc: bigint = vn.getConsume();
    vn.clearConsumeList();

    const op: PcodeOp = vn.getDef()!;	// Assume vn is written

    let sz: number;
    let a: bigint;
    let b: bigint;

    switch (op.code()) {
      case OpCode.CPUI_INT_MULT:
        b = coveringmask(outc);
        if (op.getIn(1)!.isConstant()) {
          const leastSet: number = leastsigbit_set(op.getIn(1)!.getOffset());
          if (leastSet >= 0) {
            a = calc_mask(vn.getSize()) >> BigInt(leastSet);
            a &= b;
          }
          else
            a = 0n;
        }
        else
          a = b;
        ActionDeadCode.pushConsumed(a, op.getIn(0)!, worklist);
        ActionDeadCode.pushConsumed(b, op.getIn(1)!, worklist);
        break;
      case OpCode.CPUI_INT_ADD:
      case OpCode.CPUI_INT_SUB:
        a = coveringmask(outc);	// Make sure value is filled out as a contiguous mask
        ActionDeadCode.pushConsumed(a, op.getIn(0)!, worklist);
        ActionDeadCode.pushConsumed(a, op.getIn(1)!, worklist);
        break;
      case OpCode.CPUI_SUBPIECE:
        sz = Number(op.getIn(1)!.getOffset());
        if (sz >= 8)	// If we are truncating beyond the precision of the consume field (sizeof(uintb)==8)
          a = 0n;	// this tells us nothing about consuming bits within the field
        else
          a = outc << BigInt(sz * 8);
        if ((a === 0n) && (outc !== 0n) && (op.getIn(0)!.getSize() > 8)) {
          // If the consumed mask is zero because
          // it isn't big enough to cover the whole varnode and
          // there are still upper bits that are consumed
          a = 0xFFFFFFFFFFFFFFFFn;
          a = a ^ (a >> 1n);	// Set the highest bit possible in the mask to indicate some consumption
        }
        b = (outc === 0n) ? 0n : 0xFFFFFFFFFFFFFFFFn;
        ActionDeadCode.pushConsumed(a, op.getIn(0)!, worklist);
        ActionDeadCode.pushConsumed(b, op.getIn(1)!, worklist);
        break;
      case OpCode.CPUI_PIECE:
        sz = op.getIn(1)!.getSize();
        if (vn.getSize() > 8) {	// If the concatenation goes beyond the consume precision
          if (sz >= 8) {
            a = 0xFFFFFFFFFFFFFFFFn;	// Assume the bits not in the consume field are consumed
            b = outc;
          }
          else {
            a = (outc >> BigInt(sz * 8)) ^ ((0xFFFFFFFFFFFFFFFFn) << BigInt(8 * (8 - sz)));
            b = outc ^ (a << BigInt(sz * 8));
          }
        }
        else {
          a = outc >> BigInt(sz * 8);
          b = outc ^ (a << BigInt(sz * 8));
        }
        ActionDeadCode.pushConsumed(a, op.getIn(0)!, worklist);
        ActionDeadCode.pushConsumed(b, op.getIn(1)!, worklist);
        break;
      case OpCode.CPUI_INDIRECT:
        ActionDeadCode.pushConsumed(outc, op.getIn(0)!, worklist);
        if (op.getIn(1)!.getSpace() !== null && op.getIn(1)!.getSpace()!.getType() === spacetype.IPTR_IOP) {
          const indop: PcodeOp | null = PcodeOp.getOpFromConst(op.getIn(1)!.getAddr());
          if (indop !== null && !indop.isDead()) {
            if (indop.code() === OpCode.CPUI_COPY) {
              if (indop.getOut()!.characterizeOverlap(op.getOut()!) > 0) {
                ActionDeadCode.pushConsumed(0xFFFFFFFFFFFFFFFFn, indop.getOut()!, worklist);	// Mark the copy as consumed
                indop.setIndirectSource();
              }
              // If we reach here, there isn't a true block of INDIRECT (RuleIndirectCollapse will convert it to COPY)
            }
            else
              indop.setIndirectSource();
          }
        }
        break;
      case OpCode.CPUI_COPY:
      case OpCode.CPUI_INT_NEGATE:
        ActionDeadCode.pushConsumed(outc, op.getIn(0)!, worklist);
        break;
      case OpCode.CPUI_INT_XOR:
      case OpCode.CPUI_INT_OR:
        ActionDeadCode.pushConsumed(outc, op.getIn(0)!, worklist);
        ActionDeadCode.pushConsumed(outc, op.getIn(1)!, worklist);
        break;
      case OpCode.CPUI_INT_AND:
        if (op.getIn(1)!.isConstant()) {
          const val: bigint = op.getIn(1)!.getOffset();
          ActionDeadCode.pushConsumed(outc & val, op.getIn(0)!, worklist);
          ActionDeadCode.pushConsumed(outc, op.getIn(1)!, worklist);
        }
        else {
          ActionDeadCode.pushConsumed(outc, op.getIn(0)!, worklist);
          ActionDeadCode.pushConsumed(outc, op.getIn(1)!, worklist);
        }
        break;
      case OpCode.CPUI_MULTIEQUAL:
        for (let i = 0; i < op.numInput(); ++i)
          ActionDeadCode.pushConsumed(outc, op.getIn(i)!, worklist);
        break;
      case OpCode.CPUI_INT_ZEXT:
        ActionDeadCode.pushConsumed(outc, op.getIn(0)!, worklist);
        break;
      case OpCode.CPUI_INT_SEXT:
        b = calc_mask(op.getIn(0)!.getSize());
        a = outc & b;
        if (outc > b)
          a |= (b ^ (b >> 1n));	// Make sure signbit is marked used
        ActionDeadCode.pushConsumed(a, op.getIn(0)!, worklist);
        break;
      case OpCode.CPUI_INT_LEFT:
        if (op.getIn(1)!.isConstant()) {
          sz = vn.getSize();
          const sa: number = Number(op.getIn(1)!.getOffset());
          if (sz > 8) {	// If there exist bits beyond the precision of the consume field
            if (sa >= 8 * 8)
              a = 0xFFFFFFFFFFFFFFFFn;	// Make sure we assume one bits where we shift in unrepresented bits
            else
              a = (outc >> BigInt(sa)) ^ ((0xFFFFFFFFFFFFFFFFn) << BigInt(8 * 8 - sa));
            const bitCount = 8 * sz - sa;
            if (bitCount < 8 * 8) {
              let mask: bigint = 0xFFFFFFFFFFFFFFFFn;
              mask = mask << BigInt(bitCount);
              a = a & ~mask;	// Make sure high bits that are left shifted out are not marked consumed
            }
          }
          else
            a = outc >> BigInt(sa);	// Most cases just do this
          b = (outc === 0n) ? 0n : 0xFFFFFFFFFFFFFFFFn;
          ActionDeadCode.pushConsumed(a, op.getIn(0)!, worklist);
          ActionDeadCode.pushConsumed(b, op.getIn(1)!, worklist);
        }
        else {
          a = (outc === 0n) ? 0n : 0xFFFFFFFFFFFFFFFFn;
          ActionDeadCode.pushConsumed(a, op.getIn(0)!, worklist);
          ActionDeadCode.pushConsumed(a, op.getIn(1)!, worklist);
        }
        break;
      case OpCode.CPUI_INT_RIGHT:
        if (op.getIn(1)!.isConstant()) {
          const sa: number = Number(op.getIn(1)!.getOffset());
          if (sa >= 8 * 8)	// If the shift is beyond the precision of the consume field
            a = 0n;		// We know nothing about the low order consumption of the input bits
          else
            a = outc << BigInt(sa);	// Most cases just do this
          b = (outc === 0n) ? 0n : 0xFFFFFFFFFFFFFFFFn;
          ActionDeadCode.pushConsumed(a, op.getIn(0)!, worklist);
          ActionDeadCode.pushConsumed(b, op.getIn(1)!, worklist);
        }
        else {
          a = (outc === 0n) ? 0n : 0xFFFFFFFFFFFFFFFFn;
          ActionDeadCode.pushConsumed(a, op.getIn(0)!, worklist);
          ActionDeadCode.pushConsumed(a, op.getIn(1)!, worklist);
        }
        break;
      case OpCode.CPUI_INT_LESS:
      case OpCode.CPUI_INT_LESSEQUAL:
      case OpCode.CPUI_INT_EQUAL:
      case OpCode.CPUI_INT_NOTEQUAL:
        if (outc === 0n)
          a = 0n;
        else			// Anywhere we know is zero, is not getting "consumed"
          a = op.getIn(0)!.getNZMask() | op.getIn(1)!.getNZMask();
        ActionDeadCode.pushConsumed(a, op.getIn(0)!, worklist);
        ActionDeadCode.pushConsumed(a, op.getIn(1)!, worklist);
        break;
      case OpCode.CPUI_INSERT:
        if (op.numInput() >= 4) {
          a = 1n;
          a = a << op.getIn(3)!.getOffset();
          a -= 1n;	// Insert mask
          ActionDeadCode.pushConsumed(a, op.getIn(1)!, worklist);
          a = a << op.getIn(2)!.getOffset();
          ActionDeadCode.pushConsumed(outc & ~a, op.getIn(0)!, worklist);
          b = (outc === 0n) ? 0n : 0xFFFFFFFFFFFFFFFFn;
          ActionDeadCode.pushConsumed(b, op.getIn(2)!, worklist);
          ActionDeadCode.pushConsumed(b, op.getIn(3)!, worklist);
        }
        break;
      case OpCode.CPUI_EXTRACT:
        if (op.numInput() >= 3) {
          a = 1n;
          a = a << op.getIn(2)!.getOffset();
          a -= 1n;	// Extract mask
          a &= outc;	// Consumed bits of mask
          a = a << op.getIn(1)!.getOffset();
          ActionDeadCode.pushConsumed(a, op.getIn(0)!, worklist);
          b = (outc === 0n) ? 0n : 0xFFFFFFFFFFFFFFFFn;
          ActionDeadCode.pushConsumed(b, op.getIn(1)!, worklist);
          ActionDeadCode.pushConsumed(b, op.getIn(2)!, worklist);
        }
        break;
      case OpCode.CPUI_POPCOUNT:
      case OpCode.CPUI_LZCOUNT:
        a = BigInt(16 * op.getIn(0)!.getSize() - 1);	// Mask for possible bits that could be set
        a &= outc;					// Of the bits that could be set, which are consumed
        b = (a === 0n) ? 0n : 0xFFFFFFFFFFFFFFFFn;		// if any consumed, treat all input bits as consumed
        ActionDeadCode.pushConsumed(b, op.getIn(0)!, worklist);
        break;
      case OpCode.CPUI_CALL:
      case OpCode.CPUI_CALLIND:
        break;		// Call output doesn't indicate consumption of inputs
      case OpCode.CPUI_FLOAT_INT2FLOAT:
        a = 0n;
        if (outc !== 0n)
          a = coveringmask(op.getIn(0)!.getNZMask());
        ActionDeadCode.pushConsumed(a, op.getIn(0)!, worklist);
        break;
      default:
        a = (outc === 0n) ? 0n : 0xFFFFFFFFFFFFFFFFn; // all or nothing
        for (let i = 0; i < op.numInput(); ++i)
          ActionDeadCode.pushConsumed(a, op.getIn(i)!, worklist);
        break;
    }
  }

  /// Deal with unconsumed Varnodes
  private static neverConsumed(vn: Varnode, data: Funcdata): boolean {
    if (vn.getSize() > 8) return false;	// Not enough precision to really tell (sizeof(uintb))
    let op: PcodeOp;
    const descends: PcodeOp[] = [];
    for (const desc of (vn as any).descend) {
      descends.push(desc);
    }
    for (const desc of descends) {
      op = desc;
      const slot: number = op.getSlot(vn);
      // Replace vn with 0 wherever it is read
      // We don't worry about putting a constant in a marker
      // because if vn is not consumed and is input to a marker
      // then the output is also not consumed and the marker
      // op is about to be deleted anyway
      data.opSetInput(op, data.newConstant(vn.getSize(), 0n), slot);
    }
    op = vn.getDef()!;
    if (op.isCall())
      data.opUnsetOutput(op);	// For calls just get rid of output
    else
      data.opDestroy(op);	// Otherwise completely remove the op
    return true;
  }

  /// Determine how the given sub-function parameters are consumed
  private static markConsumedParameters(fc: FuncCallSpecs, worklist: Varnode[]): void {
    const callOp: PcodeOp = fc.getOp();
    ActionDeadCode.pushConsumed(0xFFFFFFFFFFFFFFFFn, callOp.getIn(0)!, worklist);	// In all cases the first operand is fully consumed
    if (fc.isInputLocked() || fc.isInputActive()) {	// If the prototype is locked in, or in active recovery
      for (let i = 1; i < callOp.numInput(); ++i)
        ActionDeadCode.pushConsumed(0xFFFFFFFFFFFFFFFFn, callOp.getIn(i)!, worklist);	// Treat all parameters as fully consumed
      return;
    }
    for (let i = 1; i < callOp.numInput(); ++i) {
      const vn: Varnode = callOp.getIn(i)!;
      let consumeVal: bigint;
      if (vn.isAutoLive())
        consumeVal = 0xFFFFFFFFFFFFFFFFn;
      else
        consumeVal = minimalmask(vn.getNZMask());
      const bytesConsumed: number = fc.getInputBytesConsumed(i);
      if (bytesConsumed !== 0)
        consumeVal &= calc_mask(bytesConsumed);
      ActionDeadCode.pushConsumed(consumeVal, vn, worklist);
    }
  }

  /// Determine how the return values for the given function are consumed
  private static gatherConsumedReturn(data: Funcdata): bigint {
    if (data.getFuncProto().isOutputLocked() || data.getActiveOutput() !== null)
      return 0xFFFFFFFFFFFFFFFFn;
    let consumeVal: bigint = 0n;
    for (const returnOp of (data as any).getOpIter(OpCode.CPUI_RETURN)) {
      if (returnOp.isDead()) continue;
      if (returnOp.numInput() > 1) {
        const vn: Varnode = returnOp.getIn(1);
        consumeVal |= minimalmask(vn.getNZMask());
      }
    }
    const val: number = data.getFuncProto().getReturnBytesConsumed();
    if (val !== 0) {
      consumeVal &= calc_mask(val);
    }
    return consumeVal;
  }

  /// Check if there are any unconsumed LOADs that may be from volatile addresses.
  private static lastChanceLoad(data: Funcdata, worklist: Varnode[]): boolean {
    if (data.getHeritagePass() > 1) return false;
    if (data.isJumptableRecoveryOn()) return false;
    let res = false;
    for (const op of (data as any).getOpIter(OpCode.CPUI_LOAD)) {
      if (op.isDead()) continue;
      const vn: Varnode = op.getOut()!;
      if (vn.isConsumeVacuous()) continue;
      if (op.getIn(1).isEventualConstant(3, 1)) {
        ActionDeadCode.pushConsumed(0xFFFFFFFFFFFFFFFFn, vn, worklist);
        vn.setAutoLiveHold();
        res = true;
      }
    }
    return res;
  }

  apply(data: Funcdata): number {
    let i: number;
    let op: PcodeOp;
    let vn: Varnode;
    let returnConsume: bigint;
    const worklist: Varnode[] = [];
    const manage: AddrSpaceManager = data.getArch();
    let spc: AddrSpace | null;

    // Clear consume flags
    for (const v of (data as any).getLocIter()) {
      vn = v;
      vn.clearConsumeList();
      vn.clearConsumeVacuous();
      vn.setConsume(0n);
      if (vn.isAddrForce() && (!vn.isDirectWrite()))
        vn.clearAddrForce();
    }

    // Set pre-live registers
    for (i = 0; i < manage.numSpaces(); ++i) {
      spc = manage.getSpace(i);
      if (spc === null || !spc.doesDeadcode()) continue;
      if (data.deadRemovalAllowed(spc)) continue;	// Mark consumed if we have NOT heritaged
      for (const v of (data as any).getLocIter(spc)) {
        vn = v;
        ActionDeadCode.pushConsumed(0xFFFFFFFFFFFFFFFFn, vn, worklist);
      }
    }

    returnConsume = ActionDeadCode.gatherConsumedReturn(data);
    for (const opAlive of (data as any).getOpAliveIter()) {
      op = opAlive;

      op.clearIndirectSource();
      if (op.isCall()) {
        // Postpone setting consumption on CALL and CALLIND inputs
        if (op.isCallWithoutSpec()) {
          for (i = 0; i < op.numInput(); ++i)
            ActionDeadCode.pushConsumed(0xFFFFFFFFFFFFFFFFn, op.getIn(i)!, worklist);
        }
        if (!op.isAssignment())
          continue;
        if (op.holdOutput())
          ActionDeadCode.pushConsumed(0xFFFFFFFFFFFFFFFFn, op.getOut()!, worklist);
      }
      else if (!op.isAssignment()) {
        const opc: OpCode = op.code();
        if (opc === OpCode.CPUI_RETURN) {
          ActionDeadCode.pushConsumed(0xFFFFFFFFFFFFFFFFn, op.getIn(0)!, worklist);
          for (i = 1; i < op.numInput(); ++i)
            ActionDeadCode.pushConsumed(returnConsume, op.getIn(i)!, worklist);
        }
        else if (opc === OpCode.CPUI_BRANCHIND) {
          const jt: JumpTable | null = data.findJumpTable(op);
          let mask: bigint;
          if (jt !== null)
            mask = jt.getSwitchVarConsume();
          else
            mask = 0xFFFFFFFFFFFFFFFFn;
          ActionDeadCode.pushConsumed(mask, op.getIn(0)!, worklist);
        }
        else {
          for (i = 0; i < op.numInput(); ++i)
            ActionDeadCode.pushConsumed(0xFFFFFFFFFFFFFFFFn, op.getIn(i)!, worklist);
        }
        // Postpone setting consumption on RETURN input
        continue;
      }
      else {
        for (i = 0; i < op.numInput(); ++i) {
          vn = op.getIn(i)!;
          if (vn.isAutoLive())
            ActionDeadCode.pushConsumed(0xFFFFFFFFFFFFFFFFn, vn, worklist);
        }
      }
      vn = op.getOut()!;
      if (vn.isAutoLive())
        ActionDeadCode.pushConsumed(0xFFFFFFFFFFFFFFFFn, vn, worklist);
    }

    // Mark consumption of call parameters
    for (i = 0; i < data.numCalls(); ++i)
      ActionDeadCode.markConsumedParameters(data.getCallSpecs_byIndex(i), worklist);

    // Propagate the consume flags
    while (worklist.length > 0)
      ActionDeadCode.propagateConsumed(worklist);

    if (ActionDeadCode.lastChanceLoad(data, worklist)) {
      while (worklist.length > 0)
        ActionDeadCode.propagateConsumed(worklist);
    }

    for (i = 0; i < manage.numSpaces(); ++i) {
      spc = manage.getSpace(i);
      if (spc === null || !spc.doesDeadcode()) continue;
      if (!data.deadRemovalAllowed(spc)) continue;	// Don't eliminate if we haven't heritaged
      const varnodes: Varnode[] = [];
      for (const v of (data as any).getLocIter(spc)) {
        varnodes.push(v);
      }
      let changecount = 0;
      for (const curVn of varnodes) {
        vn = curVn;
        if (!vn.isWritten()) continue;
        const vacflag: boolean = vn.isConsumeVacuous();
        vn.clearConsumeList();
        vn.clearConsumeVacuous();
        if (!vacflag) {		// Not even vacuously consumed
          op = vn.getDef()!;
          changecount += 1;
          if (op.isCall())
            data.opUnsetOutput(op);	// For calls just get rid of output
          else
            data.opDestroy(op);	// Otherwise completely remove the op
        }
        else {
          // Check for values that are never used, but bang around for a while
          if (vn.getConsume() === 0n) {
            if (ActionDeadCode.neverConsumed(vn, data))
              changecount += 1;
          }
        }
      }
      if (changecount !== 0)
        data.seenDeadcode(spc);	// Record that we have seen dead code for this space
    }
    data.clearDeadVarnodes();
    data.clearDeadOps();
    return 0;
  }
}

// =====================================================================
// ActionConditionalConst
// =====================================================================

export class ActionConditionalConst extends Action {
  constructor(g: string) {
    super(0, "condconst", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionConditionalConst(this.getGroup());
  }

  /// Clear all marks on the given list of PcodeOps
  private static clearMarks(opList: PcodeOp[]): void {
    for (let i = 0; i < opList.length; ++i)
      opList[i].clearMark();
  }

  /// Collect COPY, INDIRECT, and MULTIEQUAL ops reachable from the given Varnode, without going thru excised edges
  private static collectReachable(vn: Varnode, phiNodeEdges: PcodeOpNode[], reachable: PcodeOp[]): void {
    phiNodeEdges.sort((a, b) => PcodeOpNode.compare(a, b));
    let count = 0;
    if (vn.isWritten()) {
      const op: PcodeOp = vn.getDef()!;
      if (op.code() === OpCode.CPUI_MULTIEQUAL) {
        // Consider defining MULTIEQUAL to be "reachable"
        op.setMark();
        reachable.push(op);
      }
    }
    for (;;) {
      for (const op of (vn as any).descend) {
        if (op.isMark()) continue;
        const opc: OpCode = op.code();
        if (opc === OpCode.CPUI_MULTIEQUAL) {
          const tmpOp: PcodeOpNode = new PcodeOpNode(op, 0);
          let found = false;
          for (tmpOp.slot = 0; tmpOp.slot < op.numInput(); ++tmpOp.slot) {
            if (op.getIn(tmpOp.slot) !== vn) continue;	// Find incoming slot for current Varnode
            // Don't count as flow if coming thru excised edge
            if (!binarySearch(phiNodeEdges, tmpOp)) {
              found = true;
              break;
            }
          }
          if (!found) continue;	// Was the MULTIEQUAL reached
        }
        else if (opc !== OpCode.CPUI_COPY && opc !== OpCode.CPUI_INDIRECT)
          continue;
        reachable.push(op);
        op.setMark();
      }
      if (count >= reachable.length) break;
      vn = reachable[count].getOut()!;
      count += 1;
    }
  }

  /// Does the output of the given op reunite with the alternate flow
  private static flowToAlternatePath(op: PcodeOp): boolean {
    if (op.isMark()) return true;
    const markSet: Varnode[] = [];
    let vn: Varnode = op.getOut()!;
    markSet.push(vn);
    vn.setMark();
    let count = 0;
    let foundPath = false;
    while (count < markSet.length) {
      vn = markSet[count];
      count += 1;
      for (const nextOp of (vn as any).descend) {
        const opc: OpCode = nextOp.code();
        if (opc === OpCode.CPUI_MULTIEQUAL) {
          if (nextOp.isMark()) {
            foundPath = true;
            break;
          }
        }
        else if (opc !== OpCode.CPUI_COPY && opc !== OpCode.CPUI_INDIRECT)
          continue;
        const outVn: Varnode = nextOp.getOut()!;
        if (outVn.isMark()) continue;
        outVn.setMark();
        markSet.push(outVn);
      }
      if (foundPath) break;
    }
    for (let i = 0; i < markSet.length; ++i)
      markSet[i].clearMark();
    return foundPath;
  }

  /// Test if flow from a specific edge is disjoint from other edges
  private static flowTogether(edges: PcodeOpNode[], i: number, result: number[]): boolean {
    const reachable: PcodeOp[] = [];
    const excise: PcodeOpNode[] = [];	// No edge excised
    ActionConditionalConst.collectReachable(edges[i].op.getOut()!, excise, reachable);
    let res = false;
    for (let j = 0; j < edges.length; ++j) {
      if (i === j) continue;
      if (result[j] === 0) continue;	// Check for disconnected path
      if (edges[j].op.isMark()) {
        result[i] = 2;			// Disconnected paths, which flow together
        result[j] = 2;
        res = true;
      }
    }
    ActionConditionalConst.clearMarks(reachable);
    return res;
  }

  /// Place a COPY of a constant at the end of a basic block
  private static placeCopy(op: PcodeOp, bl: BlockBasic, constVn: Varnode, data: Funcdata): Varnode {
    const lastOp: PcodeOp | null = bl.lastOp();
    let iter: IteratorSTL<PcodeOp>;
    let addr: Address;
    if (lastOp === null) {
      iter = bl.endOp();
      addr = op.getAddr();
    }
    else if (lastOp.isBranch()) {
      iter = lastOp.getBasicIter();	// Insert before any branch
      addr = lastOp.getAddr();
    }
    else {
      iter = bl.endOp();
      addr = lastOp.getAddr();
    }
    const copyOp: PcodeOp = data.newOp(1, addr);
    data.opSetOpcode(copyOp, OpCode.CPUI_COPY);
    const outVn: Varnode = data.newUniqueOut(constVn.getSize(), copyOp);
    data.opSetInput(copyOp, constVn, 0);
    data.opInsert(copyOp, bl, iter);
    return outVn;
  }

  /// Place a single COPY assignment shared by multiple MULTIEQUALs
  private static placeMultipleConstants(phiNodeEdges: PcodeOpNode[], marks: number[],
                                        constVn: Varnode, data: Funcdata): void {
    const blocks: FlowBlock[] = [];
    let op: PcodeOp | null = null;
    for (let i = 0; i < phiNodeEdges.length; ++i) {
      if (marks[i] !== 2) continue;	// Check that the MULTIEQUAL is marked as flowing together
      op = phiNodeEdges[i].op;
      let bl: FlowBlock = op.getParent();
      bl = bl.getIn(phiNodeEdges[i].slot);
      blocks.push(bl);
    }
    const rootBlock: BlockBasic = FlowBlock.findCommonBlock(blocks) as BlockBasic;
    const outVn: Varnode = ActionConditionalConst.placeCopy(op!, rootBlock, constVn, data);
    for (let i = 0; i < phiNodeEdges.length; ++i) {
      if (marks[i] !== 2) continue;
      data.opSetInput(phiNodeEdges[i].op, outVn, phiNodeEdges[i].slot);
    }
  }

  /// Try to push the constant at the front point through to the output of the given PcodeOp
  private static pushConstant(points: ConstPoint[], op: PcodeOp): void {
    if ((op.getEvalType() & PcodeOp.special) !== 0) return;
    if (op.getOpcode().isFloatingPointOp()) return;
    const outvn: Varnode = op.getOut()!;
    if (outvn.getSize() > 8) return;	// sizeof(uintb)
    const vn: Varnode = points[0].vn;
    const slot: number = op.getSlot(vn);
    const inArr: bigint[] = [0n, 0n, 0n];
    for (let i = 0; i < op.numInput(); ++i) {
      if (i === slot)
        inArr[i] = points[0].value;
      else {
        const inVn: Varnode = op.getIn(i)!;
        if (inVn.getSize() > 8) return;	// sizeof(uintb)
        if (inVn.isConstant())
          inArr[i] = op.getIn(i)!.getOffset();
        else
          return;		// Not all inputs are constant
      }
    }
    const result = op.executeSimple(inArr);
    if (result.evalError)
      return;
    points.push(makeConstPointFromVal(outvn, result.result, points[0].constBlock, points[0].inSlot, points[0].blockIsDom));
  }

  /// Replace MULTIEQUAL edges with constant if there is no alternate flow
  private handlePhiNodes(varVn: Varnode, constVn: Varnode, phiNodeEdges: PcodeOpNode[], data: Funcdata): void {
    const alternateFlow: PcodeOp[] = [];
    const results: number[] = new Array(phiNodeEdges.length).fill(0);
    ActionConditionalConst.collectReachable(varVn, phiNodeEdges, alternateFlow);
    let alternate = 0;
    for (let i = 0; i < phiNodeEdges.length; ++i) {
      if (!ActionConditionalConst.flowToAlternatePath(phiNodeEdges[i].op)) {
        results[i] = 1;	// Mark as disconnecting
        alternate += 1;
      }
    }
    ActionConditionalConst.clearMarks(alternateFlow);

    let hasFlowTogether = false;
    if (alternate > 1) {
      // If we reach here, multiple MULTIEQUAL are disjoint from the non-constant flow
      for (let i = 0; i < results.length; ++i) {
        if (results[i] === 0) continue;	// Is this a disconnected path
        if (ActionConditionalConst.flowTogether(phiNodeEdges, i, results))	// Check if the disconnected paths flow together
          hasFlowTogether = true;
      }
    }
    // Build sorted index array for COPY placement: sort by MULTIEQUAL output address
    // to ensure deterministic emit order matching C++ (which depends on descend-list order
    // that may differ from TS due to implementation differences in list vs array containers)
    const indices: number[] = [];
    for (let i = 0; i < phiNodeEdges.length; ++i) {
      if (results[i] === 1) indices.push(i);
    }
    indices.sort((a, b) => {
      const addrA = phiNodeEdges[a].op.getOut()!.getAddr();
      const addrB = phiNodeEdges[b].op.getOut()!.getAddr();
      if (!addrA.equals(addrB)) return addrA.lessThan(addrB) ? -1 : 1;
      return phiNodeEdges[a].slot - phiNodeEdges[b].slot;
    });
    // Add COPY assignment for each edge that has its own disconnected path going forward
    for (const i of indices) {
      const op: PcodeOp = phiNodeEdges[i].op;
      const slot: number = phiNodeEdges[i].slot;
      const bl: BlockBasic = op.getParent().getIn(slot) as BlockBasic;
      const outVn: Varnode = ActionConditionalConst.placeCopy(op, bl, constVn, data);
      data.opSetInput(op, outVn, slot);
      this.count += 1;
    }
    if (hasFlowTogether) {
      ActionConditionalConst.placeMultipleConstants(phiNodeEdges, results, constVn, data);	// Add COPY assignment for edges that flow together
      this.count += 1;
    }
  }

  /// Test if we can reach the given Varnode via a path other than through the immediate edge
  private testAlternatePath(vn: Varnode, op: PcodeOp, slot: number, depth: number): boolean {
    for (let i = 0; i < op.numInput(); ++i) {
      if (i === slot) continue;
      const inVn: Varnode = op.getIn(i)!;
      if (inVn === vn) return true;
      if (inVn.isWritten()) {
        const curOp: PcodeOp = inVn.getDef()!;
        const opc: OpCode = curOp.code();
        if (opc === OpCode.CPUI_INT_ADD || opc === OpCode.CPUI_PTRSUB || opc === OpCode.CPUI_PTRADD) {
          if (curOp.getIn(0) === vn || curOp.getIn(1) === vn)
            return true;
        }
        else if (opc === OpCode.CPUI_MULTIEQUAL) {
          if (depth === 0) continue;
          if (this.testAlternatePath(vn, curOp, -1, depth - 1))
            return true;
        }
      }
    }
    return false;
  }

  /// At each ConstPoint, replace reads of the Varnode down the constant path with a constant Varnode
  private propagateConstant(points: ConstPoint[], useMultiequal: boolean, data: Funcdata): void {
    const phiNodeEdges: PcodeOpNode[] = [];
    while (points.length > 0) {
      const point: ConstPoint = points[0];
      const varVn: Varnode = point.vn;
      let constVn: Varnode | null = point.constVn;
      const constBlock: FlowBlock = point.constBlock;
      const descends: PcodeOp[] = [];
      for (const desc of (varVn as any).descend) {
        descends.push(desc);
      }
      // Deduplicate: each op listed once
      const uniqueOps: PcodeOp[] = [...new Set(descends)];
      for (const op of uniqueOps) {
        const opc: OpCode = op.code();
        if (opc === OpCode.CPUI_INDIRECT)			// Don't propagate constant into these
          continue;
        else if (opc === OpCode.CPUI_MULTIEQUAL) {
          if (!useMultiequal)
            continue;
          if (varVn.isAddrTied() && varVn.getAddr().equals(op.getOut()!.getAddr()))
            continue;
          const bl: FlowBlock = op.getParent();
          if (bl === constBlock) {	// The immediate edge from the conditional block, coming into a MULTIEQUAL
            if (op.getIn(point.inSlot) === varVn) {
              // Its possible the compiler still intends the constant value to be the same variable
              // Test for conditions when this is likely so we don't unnecessarily create a new variable
              if (point.value > 1n) continue;
              if (op.getOut()!.isAddrTied()) continue;
              if (this.testAlternatePath(varVn, op, point.inSlot, 2)) continue;
              phiNodeEdges.push(new PcodeOpNode(op, point.inSlot));
            }
          }
          else if (point.blockIsDom) {
            for (let slot = 0; slot < op.numInput(); ++slot) {
              if (op.getIn(slot) === varVn) {
                if (constBlock.dominates(bl.getIn(slot))) {
                  phiNodeEdges.push(new PcodeOpNode(op, slot));
                }
              }
            }
          }
          continue;
        }
        else if (opc === OpCode.CPUI_COPY) {	// Don't propagate into COPY unless...
          const followOp: PcodeOp | null = op.getOut()!.loneDescend();
          if (followOp === null) continue;
          if (followOp.isMarker()) continue;
          if (followOp.code() === OpCode.CPUI_COPY) continue;
          // ...unless COPY is into something more interesting
        }
        if (!point.blockIsDom) continue;
        if (constBlock.dominates(op.getParent())) {
          if (constVn === null)
            constVn = data.newConstant(varVn.getSize(), point.value);
          if (opc === OpCode.CPUI_RETURN) {
            // OpCode.CPUI_RETURN ops can't directly take constants as inputs
            const copyBeforeRet: PcodeOp = data.newOp(1, op.getAddr());
            data.opSetOpcode(copyBeforeRet, OpCode.CPUI_COPY);
            data.opSetInput(copyBeforeRet, constVn, 0);
            data.newVarnodeOut(varVn.getSize(), varVn.getAddr(), copyBeforeRet);
            data.opSetInput(op, copyBeforeRet.getOut()!, 1);
            data.opInsertBefore(copyBeforeRet, op);
          }
          else {
            const slot: number = op.getSlot(varVn);
            data.opSetInput(op, constVn, slot);	// Replace ref with constant!
          }
          this.count += 1;			// We made a change
        }
        else {
          ActionConditionalConst.pushConstant(points, op);
        }
      }
      if (phiNodeEdges.length > 0) {
        if (constVn === null)
          constVn = data.newConstant(varVn.getSize(), point.value);
        this.handlePhiNodes(varVn, constVn, phiNodeEdges, data);
        phiNodeEdges.length = 0;
      }
      points.shift();
    }
  }

  /// Find a Varnode being compared to a constant creating the given CBRANCH boolean
  private static findConstCompare(points: ConstPoint[], boolVn: Varnode, bl: FlowBlock,
                                  blockDom: boolean[], flipEdge: boolean): void {
    if (!boolVn.isWritten()) return;
    let compOp: PcodeOp = boolVn.getDef()!;
    let opc: OpCode = compOp.code();
    if (opc === OpCode.CPUI_BOOL_NEGATE) {
      flipEdge = !flipEdge;
      boolVn = compOp.getIn(0)!;
      if (!boolVn.isWritten()) return;
      compOp = boolVn.getDef()!;
      opc = compOp.code();
    }
    let constEdge: number;	// Out edge where value is constant
    if (opc === OpCode.CPUI_INT_EQUAL)
      constEdge = 1;
    else if (opc === OpCode.CPUI_INT_NOTEQUAL)
      constEdge = 0;
    else
      return;
    // Find the variable and verify that it is compared to a constant
    let varVn: Varnode = compOp.getIn(0)!;
    let constVn: Varnode = compOp.getIn(1)!;
    if (!constVn.isConstant()) {
      if (!varVn.isConstant())
        return;
      const tmp = constVn;
      constVn = varVn;
      varVn = tmp;
    }
    if (varVn.loneDescend() !== null) return;
    if (flipEdge)
      constEdge = 1 - constEdge;
    points.push(makeConstPointFromVn(varVn, constVn, bl.getOut(constEdge), bl.getOutRevIndex(constEdge), blockDom[constEdge]));
  }

  apply(data: Funcdata): number {
    let useMultiequal = true;
    const stackSpace: AddrSpace | null = data.getArch().getStackSpace();
    if (stackSpace !== null) {
      // Determining if conditional constants should apply to MULTIEQUAL operations may require
      // flow calculations.
      const numPasses: number = data.numHeritagePasses(stackSpace);
      if (numPasses <= 0)	// If the stack hasn't been heritaged yet
        useMultiequal = false;	// Don't propagate into MULTIEQUAL
    }
    const blockGraph: BlockGraph = data.getBasicBlocks();
    const blockDom: boolean[] = [false, false];
    const points: ConstPoint[] = [];
    for (let i = 0; i < blockGraph.getSize(); ++i) {
      const bl: FlowBlock = blockGraph.getBlock(i);
      const cBranch: PcodeOp | null = bl.lastOp();
      if (cBranch === null || cBranch.code() !== OpCode.CPUI_CBRANCH) continue;
      const boolVn: Varnode = cBranch.getIn(1)!;
      blockDom[0] = bl.getOut(0).restrictedByConditional(bl);	// Make sure boolean constant holds down false branch
      blockDom[1] = bl.getOut(1).restrictedByConditional(bl);
      const flipEdge: boolean = cBranch.isBooleanFlip();
      if (boolVn.loneDescend() === null) {	// If the boolean is read more than once
        // Search for implied constants, bool=0 down false branch, bool=1 down true branch
        points.push(makeConstPointFromVal(boolVn, flipEdge ? 1n : 0n, bl.getFalseOut(), bl.getOutRevIndex(0), blockDom[0]));
        points.push(makeConstPointFromVal(boolVn, flipEdge ? 0n : 1n, bl.getTrueOut(), bl.getOutRevIndex(1), blockDom[1]));
      }
      ActionConditionalConst.findConstCompare(points, boolVn, bl, blockDom, flipEdge);
      this.propagateConstant(points, useMultiequal, data);
    }
    return 0;
  }
}

// =====================================================================
// ActionSwitchNorm
// =====================================================================

export class ActionSwitchNorm extends Action {
  constructor(g: string) {
    super(0, "switchnorm", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionSwitchNorm(this.getGroup());
  }

  apply(data: Funcdata): number {
    for (let i = 0; i < data.numJumpTables(); ++i) {
      const jt: JumpTable = data.getJumpTable(i);
      if (!jt.isLabelled()) {
        jt.matchModel(data);
        jt.recoverLabels(data);	// Recover case statement labels
        jt.foldInNormalization(data);
        this.count += 1;
      }
      if (jt.foldInGuards(data)) {
        data.getStructure().clear();	// Make sure we redo structure
        this.count += 1;
      }
    }
    return 0;
  }
}

// =====================================================================
// ActionNormalizeSetup
// =====================================================================

export class ActionNormalizeSetup extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "normalizesetup", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionNormalizeSetup(this.getGroup());
  }

  apply(data: Funcdata): number {
    const fp: FuncProto = data.getFuncProto();
    fp.clearInput();
    fp.setModelLock(false);	// This will cause the model to get reevaluated
    fp.setOutputLock(false);

    // FIXME: This should probably save and restore symbols, model, and state
    //   If we are calculating normalized trees in console mode, this currently eliminates locks
    //   that may be needed by other normalizing calculations
    return 0;
  }
}

// =====================================================================
// ActionPrototypeTypes
// =====================================================================

export class ActionPrototypeTypes extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "prototypetypes", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionPrototypeTypes(this.getGroup());
  }

  /// Extend Varnode inputs to match prototype model.
  extendInput(data: Funcdata, invn: Varnode, param: ProtoParameter, topbl: BlockBasic): void {
    const vdata: VarnodeData = new VarnodeData();
    let res: OpCode = data.getFuncProto().assumedInputExtension(invn.getAddr(), invn.getSize(), vdata);
    if (res === OpCode.CPUI_COPY) return;	// no extension
    if (res === OpCode.CPUI_PIECE) {	// Do an extension based on type of parameter
      if (param.getType().getMetatype() === type_metatype.TYPE_INT)
        res = OpCode.CPUI_INT_SEXT;
      else
        res = OpCode.CPUI_INT_ZEXT;
    }
    const op: PcodeOp = data.newOp(1, topbl.getStart());
    data.newVarnodeOut(vdata.size, vdata.getAddr() as any, op);
    data.opSetOpcode(op, res);
    data.opSetInput(op, invn, 0);
    data.opInsertBegin(op, topbl);
  }

  apply(data: Funcdata): number {
    // Set the evaluation prototype if we are not already locked
    let evalfp: ProtoModel | null = data.getArch().evalfp_current;
    if (evalfp === null)
      evalfp = data.getArch().defaultfp;
    if ((!data.getFuncProto().isModelLocked()) && !data.getFuncProto().hasMatchingModel(evalfp))
      data.getFuncProto().setModel(evalfp);
    if (data.getFuncProto().hasThisPointer())
      data.prepareThisPointer();

    // Strip the indirect register from all RETURN ops
    // (Because we don't want to see this compiler
    // mechanism in the high-level C output)
    for (const op of (data as any).getOpIter(OpCode.CPUI_RETURN)) {
      if (op.isDead()) continue;
      if (!op.getIn(0).isConstant()) {
        const vn: Varnode = data.newConstant(op.getIn(0).getSize(), 0n);
        data.opSetInput(op, vn, 0);
      }
    }

    if (data.getFuncProto().isOutputLocked()) {
      const outparam: ProtoParameter = data.getFuncProto().getOutput();
      if (outparam.getType().getMetatype() !== type_metatype.TYPE_VOID) {
        for (const op of (data as any).getOpIter(OpCode.CPUI_RETURN)) {
          if (op.isDead()) continue;
          if (op.getHaltType() !== 0) continue;
          const vn: Varnode = data.newVarnode(outparam.getSize(), outparam.getAddress());
          data.opInsertInput(op, vn, op.numInput());
          vn.updateType(outparam.getType(), true, true);
        }
      }
    }
    else
      data.initActiveOutput();	// Initiate gathering potential return values

    const spc: AddrSpace = data.getArch().getDefaultCodeSpace();
    if (spc.isTruncated()) {
      // For truncated spaces we need a zext op, from the truncated stack pointer
      // into the full stack pointer
      const stackspc: AddrSpace | null = data.getArch().getStackSpace();
      let topbl: BlockBasic | null = null;
      if (data.getBasicBlocks().getSize() > 0)
        topbl = data.getBasicBlocks().getBlock(0) as BlockBasic;
      if (stackspc !== null && topbl !== null) {
        for (let i = 0; i < stackspc.numSpacebase(); ++i) {
          const fullReg: VarnodeData = stackspc.getSpacebaseFull(i);
          const truncReg: VarnodeData = stackspc.getSpacebase(i);
          let invn: Varnode = data.newVarnode(truncReg.size, truncReg.getAddr() as any);
          invn = data.setInputVarnode(invn);
          const extop: PcodeOp = data.newOp(1, topbl.getStart());
          data.newVarnodeOut(fullReg.size, fullReg.getAddr() as any, extop);
          data.opSetOpcode(extop, OpCode.CPUI_INT_ZEXT);
          data.opSetInput(extop, invn, 0);
          data.opInsertBegin(extop, topbl);
        }
      }
    }

    // Force locked inputs to exist as varnodes
    if (data.getFuncProto().isInputLocked()) {
      const ptr_size: number = spc.isTruncated() ? spc.getAddrSize() : 0;	// Check if we need to do pointer trimming
      let topbl: BlockBasic | null = null;
      if (data.getBasicBlocks().getSize() > 0)
        topbl = data.getBasicBlocks().getBlock(0) as BlockBasic;

      const numparams: number = data.getFuncProto().numParams();
      for (let i = 0; i < numparams; ++i) {
        const param: ProtoParameter = data.getFuncProto().getParam(i);
        let vn: Varnode = data.newVarnode(param.getSize(), param.getAddress());
        vn = data.setInputVarnode(vn);
        vn.setLockedInput();
        if (topbl !== null)
          this.extendInput(data, vn, param, topbl);
        if (ptr_size > 0) {
          const ct: Datatype = param.getType();
          if ((ct.getMetatype() === type_metatype.TYPE_PTR) && (ct.getSize() === ptr_size))
            vn.setPtrFlow();
        }
      }
    }
    return 0;
  }
}

// =====================================================================
// ActionInputPrototype
// =====================================================================

export class ActionInputPrototype extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "inputprototype", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionInputPrototype(this.getGroup());
  }

  apply(data: Funcdata): number {
    const triallist: Varnode[] = [];
    const active: ParamActive = new ParamActive(false);
    let vn: Varnode;

    data.getScopeLocal()!.clearCategory(3);  // Symbol.fake_input = 3
    data.getFuncProto().clearUnlockedInput();
    if (!data.getFuncProto().isInputLocked()) {
      for (const v of (data as any).getDefIter(Varnode.input)) {
        vn = v;
        if (data.getFuncProto().possibleInputParam(vn.getAddr(), vn.getSize())) {
          const slot: number = active.getNumTrials();
          active.registerTrial(vn.getAddr(), vn.getSize());
          if (!vn.hasNoDescend())
            active.getTrial(slot).markActive();	// Mark as active if it has descendants
          triallist.push(vn);
        }
      }
      data.getFuncProto().resolveModel(active);
      data.getFuncProto().deriveInputMap(active);	// Derive the correct prototype from trials
      // Create any unreferenced input varnodes
      for (let i = 0; i < active.getNumTrials(); ++i) {
        const paramtrial: ParamTrial = active.getTrial(i);
        if (paramtrial.isUnref() && paramtrial.isUsed()) {
          if (data.hasInputIntersection(paramtrial.getSize(), paramtrial.getAddress())) {
            // There is something in the way of the unreferenced parameter, don't create it
            paramtrial.markNoUse();
          }
          else {
            vn = data.newVarnode(paramtrial.getSize(), paramtrial.getAddress());
            vn = data.setInputVarnode(vn);
            const slot: number = triallist.length;
            triallist.push(vn);
            paramtrial.setSlot(slot + 1);
          }
        }
      }
      if (data.isHighOn())
        data.getFuncProto().updateInputTypes(data, triallist, active);
      else
        data.getFuncProto().updateInputNoTypes(data, triallist, active);
    }
    data.clearDeadVarnodes();
    return 0;
  }
}

// =====================================================================
// ActionOutputPrototype
// =====================================================================

export class ActionOutputPrototype extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "outputprototype", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionOutputPrototype(this.getGroup());
  }

  apply(data: Funcdata): number {
    const outparam: ProtoParameter = data.getFuncProto().getOutput();
    if ((!outparam.isTypeLocked()) || outparam.isSizeTypeLocked()) {
      const op: PcodeOp | null = data.getFirstReturnOp();
      const vnlist: Varnode[] = [];
      if (op !== null) {
        for (let i = 1; i < op.numInput(); ++i)
          vnlist.push(op.getIn(i)!);
      }
      if (data.isHighOn())
        data.getFuncProto().updateOutputTypes(vnlist);
      else
        data.getFuncProto().updateOutputNoTypes(vnlist, data.getArch().types);
    }
    return 0;
  }
}

// =====================================================================
// ActionUnjustifiedParams
// =====================================================================

export class ActionUnjustifiedParams extends Action {
  constructor(g: string) {
    super(0, "unjustparams", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionUnjustifiedParams(this.getGroup());
  }

  apply(data: Funcdata): number {
    const proto: FuncProto = data.getFuncProto();

    let iter = data.beginDefFlags(Varnode.input);
    let enditer = data.endDefFlags(Varnode.input);

    while (!iter.equals(enditer)) {
      const vn: Varnode = iter.get(); iter.next();
      const vdata: VarnodeData = new VarnodeData();
      if (!proto.unjustifiedInputParam(vn.getAddr(), vn.getSize(), vdata)) continue;

      let newcontainer: boolean;
      do {
        newcontainer = false;
        let overlaps = false;
        // Search backwards through input varnodes for overlaps
        const inputEnd = data.endDefFlags(Varnode.input);
        for (let it = data.beginDefFlags(Varnode.input); !it.equals(inputEnd); it.next()) {
          const prevVn: Varnode = it.get();
          if (prevVn === vn) break;
          if (prevVn.getSpace() !== vdata.space) continue;
          const offset: bigint = prevVn.getOffset() + BigInt(prevVn.getSize() - 1);	// Last offset in varnode
          if ((offset >= vdata.offset) && (prevVn.getOffset() < vdata.offset)) {	// If there is overlap that extends size
            overlaps = true;
            const endpoint: bigint = vdata.offset + BigInt(vdata.size);
            vdata.offset = prevVn.getOffset();
            vdata.size = Number(endpoint - vdata.offset);
          }
        }
        if (!overlaps) break;	// Found no additional overlaps, go with current justified container
        // If there were overlaps, container may no longer be justified
        newcontainer = proto.unjustifiedInputParam(new Address(vdata.getAddr() as any), vdata.size, vdata);
      } while (newcontainer);

      data.adjustInputVarnodes(new Address(vdata.getAddr() as any), vdata.size);
      // Reset iterator because of additions and deletions
      iter = data.beginDefFlagsAddr(Varnode.input, new Address(vdata.getAddr() as any));
      enditer = data.endDefFlags(Varnode.input);
      this.count += 1;
    }
    return 0;
  }
}

// =====================================================================
// ActionHideShadow
// =====================================================================

export class ActionHideShadow extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "hideshadow", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionHideShadow(this.getGroup());
  }

  apply(data: Funcdata): number {
    let high: HighVariable;

    for (const vn of (data as any).getDefIter(Varnode.written)) {
      high = vn.getHigh();
      if (high.isMark()) continue;
      if (data.getMerge().hideShadows(high))
        this.count += 1;
      high.setMark();
    }
    for (const vn of (data as any).getDefIter(Varnode.written)) {
      high = vn.getHigh();
      high.clearMark();
    }
    return 0;
  }
}

// =====================================================================
// ActionDynamicMapping
// =====================================================================

export class ActionDynamicMapping extends Action {
  constructor(g: string) {
    super(0, "dynamicmapping", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionDynamicMapping(this.getGroup());
  }

  apply(data: Funcdata): number {
    const localmap: ScopeLocal = data.getScopeLocal();
    const dhash: DynamicHash = new DynamicHash();
    for (const entry of localmap.beginDynamic()) {
      if (data.attemptDynamicMapping(entry, dhash))
        this.count += 1;
    }
    return 0;
  }
}

// =====================================================================
// ActionDynamicSymbols
// =====================================================================

export class ActionDynamicSymbols extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "dynamicsymbols", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionDynamicSymbols(this.getGroup());
  }

  apply(data: Funcdata): number {
    const localmap: ScopeLocal = data.getScopeLocal();
    const dhash: DynamicHash = new DynamicHash();
    for (const entry of localmap.beginDynamic()) {
      if (data.attemptDynamicMappingLate(entry, dhash))
        this.count += 1;
    }
    return 0;
  }
}

// =====================================================================
// ActionPrototypeWarnings
// =====================================================================

export class ActionPrototypeWarnings extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "prototypewarnings", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionPrototypeWarnings(this.getGroup());
  }

  apply(data: Funcdata): number {
    const overridemessages: string[] = [];
    data.getOverride().generateOverrideMessages(overridemessages, data.getArch());
    for (let i = 0; i < overridemessages.length; ++i)
      data.warningHeader(overridemessages[i]);

    const ourproto: FuncProto = data.getFuncProto();
    if (ourproto.hasInputErrors()) {
      data.warningHeader("Cannot assign parameter locations for this function: Prototype may be inaccurate");
    }
    if (ourproto.hasOutputErrors()) {
      data.warningHeader("Cannot assign location of return value for this function: Return value may be inaccurate");
    }
    if (ourproto.isModelUnknown()) {
      let s = "Unknown calling convention";
      if (ourproto.printModelInDecl())
        s += ": " + ourproto.getModelName();
      if (!ourproto.hasCustomStorage() && (ourproto.isInputLocked() || ourproto.isOutputLocked()))
        s += " -- yet parameter storage is locked";
      data.warningHeader(s);
    }
    const numcalls: number = data.numCalls();
    for (let i = 0; i < numcalls; ++i) {
      const fc: FuncCallSpecs = data.getCallSpecs_byIndex(i);
      const fd: Funcdata | null = fc.getFuncdata();
      if (fc.hasInputErrors()) {
        let s = "Cannot assign parameter location for function ";
        if (fd !== null)
          s += fd.getName();
        else
          s += "<indirect>";
        s += ": Prototype may be inaccurate";
        data.warning(s, fc.getEntryAddress());
      }
      if (fc.hasOutputErrors()) {
        let s = "Cannot assign location of return value for function ";
        if (fd !== null)
          s += fd.getName();
        else
          s += "<indirect>";
        s += ": Return value may be inaccurate";
        data.warning(s, fc.getEntryAddress());
      }
    }
    return 0;
  }
}

// =====================================================================
// ActionInternalStorage
// =====================================================================

export class ActionInternalStorage extends Action {
  constructor(g: string) {
    super(Action.rule_onceperfunc, "internalstorage", g);
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionInternalStorage(this.getGroup());
  }

  apply(data: Funcdata): number {
    const proto: FuncProto = data.getFuncProto();
    for (const vd of (proto as any).getInternalIter()) {
      const addr: Address = vd.getAddr();
      const sz: number = vd.size;

      for (const vn of (data as any).getLocIter(sz, addr)) {
        for (const op of (vn as any).descend) {
          if (op.code() === OpCode.CPUI_STORE) {
            if (vn.isEventualConstant(3, 0)) {
              op.setStoreUnmapped();
            }
          }
        }
      }
    }
    return 0;
  }
}

// =====================================================================
// PropagationState
// =====================================================================

export class PropagationState {
  vn: Varnode;
  iterIdx: number;
  op: PcodeOp | null;
  inslot: number;
  slot: number;

  constructor(v: Varnode) {
    this.vn = v;
    this.iterIdx = 0;
    if (this.iterIdx < v.descend.length) {
      this.op = v.descend[this.iterIdx];
      this.iterIdx++;
      if (this.op!.getOut() !== null)
        this.slot = -1;
      else
        this.slot = 0;
      this.inslot = this.op!.getSlot(v);
    }
    else {
      this.op = v.getDef()!;
      this.inslot = -1;
      this.slot = 0;
    }
  }

  /// Advance to the next propagation edge
  step(): void {
    this.slot += 1;
    if (this.slot < this.op!.numInput())
      return;
    if (this.iterIdx < this.vn.descend.length) {
      this.op = this.vn.descend[this.iterIdx];
      this.iterIdx++;
      if (this.op!.getOut() !== null)
        this.slot = -1;
      else
        this.slot = 0;
      this.inslot = this.op!.getSlot(this.vn);
      return;
    }
    if (this.inslot === -1)
      this.op = null;
    else
      this.op = this.vn.getDef()!;
    this.inslot = -1;
    this.slot = 0;
  }

  /// Return true if there are edges left to iterate
  valid(): boolean {
    return this.op !== null;
  }
}

// =====================================================================
// ActionInferTypes
// =====================================================================

export class ActionInferTypes extends Action {
  private localcount: number = 0;

  constructor(g: string) {
    super(0, "infertypes", g);
  }

  reset(data: Funcdata): void {
    this.localcount = 0;
  }

  clone(grouplist: ActionGroupList): Action | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new ActionInferTypes(this.getGroup());
  }

  /// Collect local data-type information on each Varnode inferred from the PcodeOps that read and write to it.
  private static buildLocaltypes(data: Funcdata): void {
    let ct: Datatype;
    let vn: Varnode;
    const typegrp: TypeFactory = data.getArch().types;

    for (const v of (data as any).getLocIter()) {
      vn = v;
      if (vn.isAnnotation()) continue;
      if ((!vn.isWritten()) && (vn.hasNoDescend())) continue;
      let needsBlock = false;
      const entry: SymbolEntry | null = vn.getSymbolEntry();
      if (entry !== null && !vn.isTypeLock() && entry.getSymbol().isTypeLocked()) {
        const curOff: number = (Number(vn.getAddr().getOffset() - entry.getAddr().getOffset())) + entry.getOffset();
        ct = typegrp.getExactPiece(entry.getSymbol().getType(), curOff, vn.getSize())!;
        if (ct === null || ct.getMetatype() === type_metatype.TYPE_UNKNOWN) {	// If we can't resolve, or resolve to UNKNOWN
          const blockupRef1: { val: boolean } = { val: false };
          ct = vn.getLocalType(blockupRef1);
          needsBlock = blockupRef1.val;
        }
      }
      else {
        const blockupRef2: { val: boolean } = { val: false };
        ct = vn.getLocalType(blockupRef2);
        needsBlock = blockupRef2.val;
      }
      if (needsBlock)
        vn.setStopUpPropagation();
      vn.setTempType(ct);
    }
  }

  /// For each Varnode copy the temporary data-type to the permanent field, taking into account previous locks.
  private static writeBack(data: Funcdata): boolean {
    let change = false;
    let ct: Datatype;
    let vn: Varnode;

    for (const v of (data as any).getLocIter()) {
      vn = v;
      if (vn.isAnnotation()) continue;
      if ((!vn.isWritten()) && (vn.hasNoDescend())) continue;
      ct = vn.getTempType();
      if (vn.updateType(ct))
        change = true;
    }
    return change;
  }

  /// Attempt to propagate a data-type across a single PcodeOp edge
  private static propagateTypeEdge(typegrp: TypeFactory, op: PcodeOp, inslot: number, outslot: number): boolean {
    let invn: Varnode;
    let outvn: Varnode;

    invn = (inslot === -1) ? op.getOut()! : op.getIn(inslot)!;

    // (debug removed)
    let alttype: Datatype = invn.getTempType();
    if (alttype.needsResolution()) {
      // Always give incoming data-type a chance to resolve, even if it would not otherwise propagate
      alttype = alttype.resolveInFlow(op, inslot);
    }
    if (inslot === outslot) return false;	// don't backtrack
    if (outslot < 0)
      outvn = op.getOut()!;
    else {
      outvn = op.getIn(outslot)!;
      if (outvn.isAnnotation()) return false;
    }
    if (outvn.isTypeLock()) {
      return false;	// Can't propagate through typelock
    }
    if (outvn.stopsUpPropagation() && outslot >= 0) return false;	// Propagation is blocked

    if (alttype.getMetatype() === type_metatype.TYPE_BOOL) {	// Only propagate boolean
      if (outvn.getNZMask() > 1n)		// If we know output can only take boolean values
        return false;
    }

    const newtype: Datatype | null = op.getOpcode().propagateType(alttype, op, invn, outvn, inslot, outslot);

    if (newtype === null)
      return false;

    if (0 > newtype.typeOrder(outvn.getTempType())) {
      outvn.setTempType(newtype);
      return !outvn.isMark();
    }
    return false;
  }

  /// Propagate a data-type starting from one Varnode across the function
  private static propagateOneType(typegrp: TypeFactory, vn: Varnode): void {
    let ptr: PropagationState;
    const state: PropagationState[] = [];

    state.push(new PropagationState(vn));
    vn.setMark();

    while (state.length > 0) {
      ptr = state[state.length - 1];
      if (!ptr.valid()) {	// If we are out of edges to traverse
        ptr.vn.clearMark();
        state.pop();
      }
      else {
        if (ActionInferTypes.propagateTypeEdge(typegrp, ptr.op!, ptr.inslot, ptr.slot)) {
          vn = (ptr.slot === -1) ? ptr.op!.getOut()! : ptr.op!.getIn(ptr.slot)!;
          ptr.step();	// Make sure to step before push
          state.push(new PropagationState(vn));
          vn.setMark();
        }
        else
          ptr.step();
      }
    }
  }

  /// Try to propagate a pointer data-type to known aliases.
  private static propagateRef(data: Funcdata, vn: Varnode, addr: Address): void {
    let ct: Datatype = vn.getTempType();
    if (ct.getMetatype() !== type_metatype.TYPE_PTR) return;
    ct = (ct as TypePointer).getPtrTo();
    if (ct.getMetatype() === type_metatype.TYPE_SPACEBASE) return;
    if (ct.getMetatype() === type_metatype.TYPE_UNKNOWN) return;	// Don't bother propagating this
    const off: bigint = addr.getOffset();
    const typegrp: TypeFactory = data.getArch().types;
    const endaddr: Address = addr.add(BigInt(ct.getSize()));
    let lastoff: bigint = 0n;
    let lastsize: number = ct.getSize();
    let lastct: Datatype | null = ct;
    for (const curvn of (data as any).getLocIterRange(addr, endaddr.getOffset() < off ? null : endaddr)) {
      if (curvn.isAnnotation()) continue;
      if ((!curvn.isWritten()) && curvn.hasNoDescend()) continue;
      if (curvn.isTypeLock()) continue;
      if (curvn.getSymbolEntry() !== null) continue;
      const curoff: bigint = curvn.getOffset() - off;
      const cursize: number = curvn.getSize();
      if (curoff + BigInt(cursize) > BigInt(ct.getSize())) continue;
      if ((cursize !== lastsize) || (curoff !== lastoff)) {
        lastoff = curoff;
        lastsize = cursize;
        lastct = typegrp.getExactPiece(ct, Number(curoff), cursize);
      }
      if (lastct === null) continue;

      // Try to propagate the reference type into a varnode that is pointed to by that reference
      if (0 > lastct.typeOrder(curvn.getTempType())) {
        curvn.setTempType(lastct);
        ActionInferTypes.propagateOneType(typegrp, curvn);	// Try to propagate the new type as far as possible
      }
    }
  }

  /// Search for pointers and propagate its data-type to known aliases
  private static propagateSpacebaseRef(data: Funcdata, spcvn: Varnode): void {
    let spctype: Datatype = spcvn.getType();	// This is an absolute property of the varnode, so not temptype
    if (spctype.getMetatype() !== type_metatype.TYPE_PTR) return;
    spctype = (spctype as TypePointer).getPtrTo();
    if (spctype.getMetatype() !== type_metatype.TYPE_SPACEBASE) return;
    const sbtype: TypeSpacebase = spctype as TypeSpacebase;
    let addr: Address;

    for (const op of (spcvn as any).descend) {
      let vn: Varnode;
      switch (op.code()) {
        case OpCode.CPUI_COPY:
          vn = op.getIn(0);
          addr = sbtype.getAddress(0n, vn.getSize(), op.getAddr());
          ActionInferTypes.propagateRef(data, op.getOut()!, addr);
          break;
        case OpCode.CPUI_INT_ADD:
        case OpCode.CPUI_PTRSUB:
          vn = op.getIn(1);
          if (vn.isConstant()) {
            addr = sbtype.getAddress(vn.getOffset(), vn.getSize(), op.getAddr());
            ActionInferTypes.propagateRef(data, op.getOut()!, addr);
          }
          break;
        case OpCode.CPUI_PTRADD:
          vn = op.getIn(1);
          if (vn.isConstant()) {
            const off: bigint = vn.getOffset() * op.getIn(2).getOffset();
            addr = sbtype.getAddress(off, vn.getSize(), op.getAddr());
            ActionInferTypes.propagateRef(data, op.getOut()!, addr);
          }
          break;
        default:
          break;
      }
    }
  }

  /// Return the OpCode.CPUI_RETURN op with the most specialized data-type
  private static canonicalReturnOp(data: Funcdata): PcodeOp | null {
    let res: PcodeOp | null = null;
    let bestdt: Datatype | null = null;
    for (const retop of (data as any).getOpIter(OpCode.CPUI_RETURN)) {
      if (retop.isDead()) continue;
      if (retop.getHaltType() !== 0) continue;
      if (retop.numInput() > 1) {
        const vn: Varnode = retop.getIn(1);
        const ct: Datatype = vn.getTempType();
        if (bestdt === null) {
          res = retop;
          bestdt = ct;
        }
        else if (ct.typeOrder(bestdt) < 0) {
          res = retop;
          bestdt = ct;
        }
      }
    }
    return res;
  }

  /// Give data-types a chance to propagate between OpCode.CPUI_RETURN operations.
  private static propagateAcrossReturns(data: Funcdata): void {
    if (data.getFuncProto().isOutputLocked()) return;
    const op: PcodeOp | null = ActionInferTypes.canonicalReturnOp(data);
    if (op === null) return;
    const typegrp: TypeFactory = data.getArch().types;
    const baseVn: Varnode = op.getIn(1)!;
    const ct: Datatype = baseVn.getTempType();
    const baseSize: number = baseVn.getSize();
    const isBool: boolean = ct.getMetatype() === type_metatype.TYPE_BOOL;
    for (const retop of (data as any).getOpIter(OpCode.CPUI_RETURN)) {
      if (retop === op) continue;
      if (retop.isDead()) continue;
      if (retop.getHaltType() !== 0) continue;
      if (retop.numInput() > 1) {
        const vn: Varnode = retop.getIn(1);
        if (vn.getSize() !== baseSize) continue;
        if (isBool && vn.getNZMask() > 1n) continue;	// Don't propagate bool if value is not necessarily 0 or 1
        if (vn.getTempType() === ct) continue;		// Already propagated
        vn.setTempType(ct);
        ActionInferTypes.propagateOneType(typegrp, vn);
      }
    }
  }

  apply(data: Funcdata): number {
    // Make sure spacebase is accurate or bases could get typed and then ptrarithed
    if (!data.hasTypeRecoveryStarted()) return 0;
    const typegrp: TypeFactory = data.getArch().types;
    let vn: Varnode;

    if (this.localcount >= 7) {	// This constant arrived at empirically
      if (this.localcount === 7) {
        data.warningHeader("Type propagation algorithm not settling");
        data.setTypeRecoveryExceeded();
        this.localcount += 1;
      }
      return 0;
    }
    data.getScopeLocal()!.applyTypeRecommendations();
    ActionInferTypes.buildLocaltypes(data);	// Set up initial types (based on local info)
    for (const v of (data as any).getLocIter()) {
      vn = v;
      if (vn.isAnnotation()) continue;
      if ((!vn.isWritten()) && (vn.hasNoDescend())) continue;
      ActionInferTypes.propagateOneType(typegrp, vn);
    }
    ActionInferTypes.propagateAcrossReturns(data);
    const spcid: AddrSpace = data.getScopeLocal()!.getSpaceId();
    const spcvn: Varnode | null = data.findSpacebaseInput(spcid);
    if (spcvn !== null)
      ActionInferTypes.propagateSpacebaseRef(data, spcvn);
    if (ActionInferTypes.writeBack(data)) {
      // count += 1;	// Do not consider this a data-flow change
      this.localcount += 1;
    }
    return 0;
  }
}

// =====================================================================
// ActionDatabase: buildDefaultGroups and universalAction
// =====================================================================

export function buildDefaultGroups(db: ActionDatabase): void {
  if ((db as any).isDefaultGroups) return;
  (db as any).groupmap.clear();
  const members: string[] = [
    "base", "protorecovery", "protorecovery_a", "deindirect", "localrecovery",
    "deadcode", "typerecovery", "stackptrflow",
    "blockrecovery", "stackvars", "deadcontrolflow", "switchnorm",
    "cleanup", "splitcopy", "splitpointer", "merge", "dynamic", "casts", "analysis",
    "fixateglobals", "fixateproto", "constsequence",
    "segment", "returnsplit", "nodejoin", "doubleload", "doubleprecis",
    "unreachable", "subvar", "floatprecision",
    "conditionalexe"
  ];
  db.setGroup("decompile", members);

  const jumptab: string[] = [
    "base", "noproto", "localrecovery", "deadcode", "stackptrflow",
    "stackvars", "analysis", "segment", "subvar", "normalizebranches", "conditionalexe"
  ];
  db.setGroup("jumptable", jumptab);

  const normali: string[] = [
    "base", "protorecovery", "protorecovery_b", "deindirect", "localrecovery",
    "deadcode", "stackptrflow", "normalanalysis",
    "stackvars", "deadcontrolflow", "analysis", "fixateproto", "nodejoin",
    "unreachable", "subvar", "floatprecision", "normalizebranches",
    "conditionalexe"
  ];
  db.setGroup("normalize", normali);

  const paramid: string[] = [
    "base", "protorecovery", "protorecovery_b", "deindirect", "localrecovery",
    "deadcode", "typerecovery", "stackptrflow", "siganalysis",
    "stackvars", "deadcontrolflow", "analysis", "fixateproto",
    "unreachable", "subvar", "floatprecision",
    "conditionalexe"
  ];
  db.setGroup("paramid", paramid);

  const regmemb: string[] = ["base", "analysis", "subvar"];
  db.setGroup("register", regmemb);

  const firstmem: string[] = ["base"];
  db.setGroup("firstpass", firstmem);
  (db as any).isDefaultGroups = true;
}

/// Construct the universal Action that contains all possible components
export function universalAction(conf: Architecture, db: ActionDatabase): void {
  const stackspace: AddrSpace | null = conf.getStackSpace();

  const act: ActionGroup = new ActionRestartGroup(Action.rule_onceperfunc, "universal", 1);
  (db as any).registerAction(ActionDatabase.universalname, act);

  act.addAction(new ActionStart("base"));
  act.addAction(new ActionConstbase("base"));
  act.addAction(new ActionNormalizeSetup("normalanalysis"));
  act.addAction(new ActionDefaultParams("base"));
  act.addAction(new ActionExtraPopSetup("base", stackspace));
  act.addAction(new ActionPrototypeTypes("protorecovery"));
  act.addAction(new ActionFuncLink("protorecovery"));
  act.addAction(new ActionFuncLinkOutOnly("noproto"));
  {
    const actfullloop: ActionGroup = new ActionGroup(Action.rule_repeatapply, "fullloop");
    {
      const actmainloop: ActionGroup = new ActionGroup(Action.rule_repeatapply, "mainloop");
      actmainloop.addAction(new ActionUnreachable("base"));
      actmainloop.addAction(new ActionVarnodeProps("base"));
      actmainloop.addAction(new ActionHeritage("base"));
      actmainloop.addAction(new ActionParamDouble("protorecovery"));
      actmainloop.addAction(new ActionSegmentize("base"));
      actmainloop.addAction(new ActionInternalStorage("base"));
      actmainloop.addAction(new ActionForceGoto("blockrecovery"));
      actmainloop.addAction(new ActionDirectWrite("protorecovery_a", true));
      actmainloop.addAction(new ActionDirectWrite("protorecovery_b", false));
      actmainloop.addAction(new ActionActiveParam("protorecovery"));
      actmainloop.addAction(new ActionReturnRecovery("protorecovery"));
      actmainloop.addAction(new ActionRestrictLocal("localrecovery"));	// Do before dead code removed
      actmainloop.addAction(new ActionDeadCode("deadcode"));
      actmainloop.addAction(new ActionDynamicMapping("dynamic"));	// Must come before restructurevarnode and infertypes
      actmainloop.addAction(new ActionRestructureVarnode("localrecovery"));
      actmainloop.addAction(new ActionSpacebase("base"));	// Must come before infertypes and nonzeromask
      actmainloop.addAction(new ActionNonzeroMask("analysis"));
      actmainloop.addAction(new ActionInferTypes("typerecovery"));
      const actstackstall: ActionGroup = new ActionGroup(Action.rule_repeatapply, "stackstall");
      {
        const actprop: ActionPool = new ActionPool(Action.rule_repeatapply, "oppool1");
        actprop.addRule(new RuleEarlyRemoval("deadcode"));
        actprop.addRule(new RuleTermOrder("analysis"));
        actprop.addRule(new RuleSelectCse("analysis"));
        actprop.addRule(new RuleCollectTerms("analysis"));
        actprop.addRule(new RulePullsubMulti("analysis"));
        actprop.addRule(new RulePullsubIndirect("analysis"));
        actprop.addRule(new RulePushMulti("nodejoin"));
        actprop.addRule(new RuleSborrow("analysis"));
        actprop.addRule(new RuleScarry("analysis"));
        actprop.addRule(new RuleIntLessEqual("analysis"));
        actprop.addRule(new RuleTrivialArith("analysis"));
        actprop.addRule(new RuleTrivialBool("analysis"));
        actprop.addRule(new RuleTrivialShift("analysis"));
        actprop.addRule(new RuleSignShift("analysis"));
        actprop.addRule(new RuleTestSign("analysis"));
        actprop.addRule(new RuleIdentityEl("analysis"));
        actprop.addRule(new RuleOrMask("analysis"));
        actprop.addRule(new RuleAndMask("analysis"));
        actprop.addRule(new RuleOrConsume("analysis"));
        actprop.addRule(new RuleOrCollapse("analysis"));
        actprop.addRule(new RuleAndOrLump("analysis"));
        actprop.addRule(new RuleShiftBitops("analysis"));
        actprop.addRule(new RuleRightShiftAnd("analysis"));
        actprop.addRule(new RuleNotDistribute("analysis"));
        actprop.addRule(new RuleHighOrderAnd("analysis"));
        actprop.addRule(new RuleAndDistribute("analysis"));
        actprop.addRule(new RuleAndCommute("analysis"));
        actprop.addRule(new RuleAndPiece("analysis"));
        actprop.addRule(new RuleAndZext("analysis"));
        actprop.addRule(new RuleAndCompare("analysis"));
        actprop.addRule(new RuleDoubleSub("analysis"));
        actprop.addRule(new RuleDoubleShift("analysis"));
        actprop.addRule(new RuleDoubleArithShift("analysis"));
        actprop.addRule(new RuleConcatShift("analysis"));
        actprop.addRule(new RuleLeftRight("analysis"));
        actprop.addRule(new RuleShiftCompare("analysis"));
        actprop.addRule(new RuleShift2Mult("analysis"));
        actprop.addRule(new RuleShiftPiece("analysis"));
        actprop.addRule(new RuleMultiCollapse("analysis"));
        actprop.addRule(new RuleIndirectCollapse("analysis"));
        actprop.addRule(new Rule2Comp2Mult("analysis"));
        actprop.addRule(new RuleSub2Add("analysis"));
        actprop.addRule(new RuleCarryElim("analysis"));
        actprop.addRule(new RuleBxor2NotEqual("analysis"));
        actprop.addRule(new RuleLess2Zero("analysis"));
        actprop.addRule(new RuleLessEqual2Zero("analysis"));
        actprop.addRule(new RuleSLess2Zero("analysis"));
        actprop.addRule(new RuleEqual2Zero("analysis"));
        actprop.addRule(new RuleEqual2Constant("analysis"));
        actprop.addRule(new RuleThreeWayCompare("analysis"));
        actprop.addRule(new RuleXorCollapse("analysis"));
        actprop.addRule(new RuleAddMultCollapse("analysis"));
        actprop.addRule(new RuleCollapseConstants("analysis"));
        actprop.addRule(new RuleTransformCpool("analysis"));
        actprop.addRule(new RulePropagateCopy("analysis"));
        actprop.addRule(new RuleZextEliminate("analysis"));
        actprop.addRule(new RuleSlessToLess("analysis"));
        actprop.addRule(new RuleZextSless("analysis"));
        actprop.addRule(new RuleBitUndistribute("analysis"));
        actprop.addRule(new RuleBooleanUndistribute("analysis"));
        actprop.addRule(new RuleBooleanDedup("analysis"));
        actprop.addRule(new RuleBoolZext("analysis"));
        actprop.addRule(new RuleBooleanNegate("analysis"));
        actprop.addRule(new RuleLogic2Bool("analysis"));
        actprop.addRule(new RuleSubExtComm("analysis"));
        actprop.addRule(new RuleSubCommute("analysis"));
        actprop.addRule(new RuleConcatCommute("analysis"));
        actprop.addRule(new RuleConcatZext("analysis"));
        actprop.addRule(new RuleZextCommute("analysis"));
        actprop.addRule(new RuleZextShiftZext("analysis"));
        actprop.addRule(new RuleShiftAnd("analysis"));
        actprop.addRule(new RuleConcatZero("analysis"));
        actprop.addRule(new RuleConcatLeftShift("analysis"));
        actprop.addRule(new RuleSubZext("analysis"));
        actprop.addRule(new RuleSubCancel("analysis"));
        actprop.addRule(new RuleShiftSub("analysis"));
        actprop.addRule(new RuleHumptyDumpty("analysis"));
        actprop.addRule(new RuleDumptyHump("analysis"));
        actprop.addRule(new RuleHumptyOr("analysis"));
        actprop.addRule(new RuleNegateIdentity("analysis"));
        actprop.addRule(new RuleSubNormal("analysis"));
        actprop.addRule(new RulePositiveDiv("analysis"));
        actprop.addRule(new RuleDivTermAdd("analysis"));
        actprop.addRule(new RuleDivTermAdd2("analysis"));
        actprop.addRule(new RuleDivOpt("analysis"));
        actprop.addRule(new RuleSignForm("analysis"));
        actprop.addRule(new RuleSignForm2("analysis"));
        actprop.addRule(new RuleSignDiv2("analysis"));
        actprop.addRule(new RuleDivChain("analysis"));
        actprop.addRule(new RuleSignNearMult("analysis"));
        actprop.addRule(new RuleModOpt("analysis"));
        actprop.addRule(new RuleSignMod2nOpt("analysis"));
        actprop.addRule(new RuleSignMod2nOpt2("analysis"));
        actprop.addRule(new RuleSignMod2Opt("analysis"));
        actprop.addRule(new RuleSwitchSingle("analysis"));
        actprop.addRule(new RuleCondNegate("analysis"));
        actprop.addRule(new RuleBoolNegate("analysis"));
        actprop.addRule(new RuleLessEqual("analysis"));
        actprop.addRule(new RuleLessNotEqual("analysis"));
        actprop.addRule(new RuleLessOne("analysis"));
        actprop.addRule(new RuleRangeMeld("analysis"));
        actprop.addRule(new RuleFloatRange("analysis"));
        actprop.addRule(new RulePiece2Zext("analysis"));
        actprop.addRule(new RulePiece2Sext("analysis"));
        actprop.addRule(new RulePopcountBoolXor("analysis"));
        actprop.addRule(new RuleXorSwap("analysis"));
        actprop.addRule(new RuleLzcountShiftBool("analysis"));
        actprop.addRule(new RuleFloatSign("analysis"));
        actprop.addRule(new RuleOrCompare("analysis"));
        actprop.addRule(new RuleSubvarAnd("subvar"));
        actprop.addRule(new RuleSubvarSubpiece("subvar"));
        actprop.addRule(new RuleSplitFlow("subvar"));
        actprop.addRule(new RulePtrFlow("subvar", conf));
        actprop.addRule(new RuleSubvarCompZero("subvar"));
        actprop.addRule(new RuleSubvarShift("subvar"));
        actprop.addRule(new RuleSubvarZext("subvar"));
        actprop.addRule(new RuleSubvarSext("subvar"));
        actprop.addRule(new RuleNegateNegate("analysis"));
        actprop.addRule(new RuleConditionalMove("conditionalexe"));
        actprop.addRule(new RuleOrPredicate("conditionalexe"));
        actprop.addRule(new RuleFuncPtrEncoding("analysis"));
        actprop.addRule(new RuleSubfloatConvert("floatprecision"));
        actprop.addRule(new RuleFloatCast("floatprecision"));
        actprop.addRule(new RuleIgnoreNan("floatprecision"));
        actprop.addRule(new RuleUnsigned2Float("analysis"));
        actprop.addRule(new RuleInt2FloatCollapse("analysis"));
        actprop.addRule(new RulePtraddUndo("typerecovery"));
        actprop.addRule(new RulePtrsubUndo("typerecovery"));
        actprop.addRule(new RuleSegment("segment"));
        actprop.addRule(new RulePiecePathology("protorecovery"));

        actprop.addRule(new RuleDoubleLoad("doubleload"));
        actprop.addRule(new RuleDoubleStore("doubleprecis"));
        actprop.addRule(new RuleDoubleIn("doubleprecis"));
        actprop.addRule(new RuleDoubleOut("doubleprecis"));
        for (const rule of conf.extra_pool_rules)
          actprop.addRule(rule);	// Add CPU specific rules
        conf.extra_pool_rules.length = 0;	// Rules are now absorbed into universal

        actstackstall.addAction(actprop);
      }
      actstackstall.addAction(new ActionLaneDivide("base"));
      actstackstall.addAction(new ActionMultiCse("analysis"));
      actstackstall.addAction(new ActionShadowVar("analysis"));
      actstackstall.addAction(new ActionDeindirect("deindirect"));
      actstackstall.addAction(new ActionStackPtrFlow("stackptrflow", stackspace));
      actmainloop.addAction(actstackstall);
      actmainloop.addAction(new ActionRedundBranch("deadcontrolflow"));	// dead code removal
      actmainloop.addAction(new ActionBlockStructure("blockrecovery"));
      actmainloop.addAction(new ActionConstantPtr("typerecovery"));
      {
        const actprop2: ActionPool = new ActionPool(Action.rule_repeatapply, "oppool2");

        actprop2.addRule(new RulePushPtr("typerecovery"));
        actprop2.addRule(new RuleStructOffset0("typerecovery"));
        actprop2.addRule(new RulePtrArith("typerecovery"));
        actprop2.addRule(new RuleLoadVarnode("stackvars"));
        actprop2.addRule(new RuleStoreVarnode("stackvars"));

        actmainloop.addAction(actprop2);
      }
      actmainloop.addAction(new ActionDeterminedBranch("unreachable"));
      actmainloop.addAction(new ActionUnreachable("unreachable"));
      actmainloop.addAction(new ActionNodeJoin("nodejoin"));
      actmainloop.addAction(new ActionConditionalExe("conditionalexe"));
      actmainloop.addAction(new ActionConditionalConst("analysis"));

      actfullloop.addAction(actmainloop);
    }
    actfullloop.addAction(new ActionLikelyTrash("protorecovery"));
    actfullloop.addAction(new ActionDirectWrite("protorecovery_a", true));
    actfullloop.addAction(new ActionDirectWrite("protorecovery_b", false));
    actfullloop.addAction(new ActionDeadCode("deadcode"));
    actfullloop.addAction(new ActionDoNothing("deadcontrolflow"));
    actfullloop.addAction(new ActionSwitchNorm("switchnorm"));
    actfullloop.addAction(new ActionReturnSplit("returnsplit"));
    actfullloop.addAction(new ActionUnjustifiedParams("protorecovery"));
    actfullloop.addAction(new ActionStartTypes("typerecovery"));
    actfullloop.addAction(new ActionActiveReturn("protorecovery"));

    act.addAction(actfullloop);
  }
  act.addAction(new ActionMappedLocalSync("localrecovery"));
  act.addAction(new ActionStartCleanUp("cleanup"));
  {
    const actcleanup: ActionPool = new ActionPool(Action.rule_repeatapply, "cleanup");

    actcleanup.addRule(new RuleMultNegOne("cleanup"));
    actcleanup.addRule(new RuleAddUnsigned("cleanup"));
    actcleanup.addRule(new Rule2Comp2Sub("cleanup"));
    actcleanup.addRule(new RuleDumptyHumpLate("cleanup"));
    actcleanup.addRule(new RuleSubRight("cleanup"));
    actcleanup.addRule(new RuleFloatSignCleanup("cleanup"));
    actcleanup.addRule(new RuleExpandLoad("cleanup"));
    actcleanup.addRule(new RulePtrsubCharConstant("cleanup"));
    actcleanup.addRule(new RuleExtensionPush("cleanup"));
    actcleanup.addRule(new RulePieceStructure("cleanup"));
    actcleanup.addRule(new RuleSplitCopy("splitcopy"));
    actcleanup.addRule(new RuleSplitLoad("splitpointer"));
    actcleanup.addRule(new RuleSplitStore("splitpointer"));
    actcleanup.addRule(new RuleStringCopy("constsequence"));
    actcleanup.addRule(new RuleStringStore("constsequence"));

    act.addAction(actcleanup);
  }

  act.addAction(new ActionPreferComplement("blockrecovery"));
  act.addAction(new ActionStructureTransform("blockrecovery"));
  act.addAction(new ActionNormalizeBranches("normalizebranches"));
  act.addAction(new ActionAssignHigh("merge"));
  act.addAction(new ActionMergeRequired("merge"));
  act.addAction(new ActionMarkExplicit("merge"));
  act.addAction(new ActionMarkImplied("merge"));	// This must come BEFORE general merging
  act.addAction(new ActionMergeMultiEntry("merge"));
  act.addAction(new ActionMergeCopy("merge"));
  act.addAction(new ActionDominantCopy("merge"));
  act.addAction(new ActionDynamicSymbols("dynamic"));
  act.addAction(new ActionMarkIndirectOnly("merge"));	// Must come after required merges but before speculative
  act.addAction(new ActionMergeAdjacent("merge"));
  act.addAction(new ActionMergeType("merge"));
  act.addAction(new ActionHideShadow("merge"));
  act.addAction(new ActionCopyMarker("merge"));
  act.addAction(new ActionOutputPrototype("localrecovery"));
  act.addAction(new ActionInputPrototype("fixateproto"));
  act.addAction(new ActionMapGlobals("fixateglobals"));
  act.addAction(new ActionDynamicSymbols("dynamic"));
  act.addAction(new ActionNameVars("merge"));
  act.addAction(new ActionSetCasts("casts"));
  act.addAction(new ActionFinalStructure("blockrecovery"));
  act.addAction(new ActionPrototypeWarnings("protorecovery"));
  act.addAction(new ActionStop("base"));
}

// Wire up ActionDatabase methods
ActionDatabase.prototype.universalAction = function(glb: Architecture): void {
  universalAction(glb, this);
};
(ActionDatabase.prototype as any).buildDefaultGroups = function(): void {
  buildDefaultGroups(this);
};
