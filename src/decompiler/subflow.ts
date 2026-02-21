// subflow_part1.ts
// Translation of subflow.hh and the first ~2000 lines of subflow.cc
// from the Ghidra decompiler C++ source into TypeScript.
//
// Licensed under the Apache License, Version 2.0

// ---------------------------------------------------------------------------
// Imports from existing modules
// ---------------------------------------------------------------------------
import { Address } from "../core/address.js";
import { OpCode } from "../core/opcodes.js";
import { Varnode } from "../decompiler/varnode.js";
import { PcodeOp } from "../decompiler/op.js";
import { TransformManager, TransformVar, TransformOp, LaneDescription } from "../decompiler/transform.js";
import { Rule, ActionGroupList } from "./action.js";

// ---------------------------------------------------------------------------
// Forward type declarations for types not yet translated
// ---------------------------------------------------------------------------
type Funcdata = any;
type FuncCallSpecs = any;
type Datatype = any;
type TypeFactory = any;
type TypePointer = any;
type TypePartialStruct = any;
type TypeArray = any;
type TypePointerRel = any;
type FloatFormat = any;
type AddrSpace = any;
type Architecture = any;
type type_metatype = any;

// Forward-declared helper stubs for static-like methods on types used as values
function AddrSpace_addressToByteInt(off: number, wordSize: number): number { return off * wordSize; }
function AddrSpace_byteToAddressInt(off: number, wordSize: number): number { return Math.floor(off / (wordSize || 1)); }
const OptionSplitDatatypes = { option_struct: 1, option_array: 2 } as any;

// ---------------------------------------------------------------------------
// Forward declarations for enums / metatypes used
// ---------------------------------------------------------------------------
// type_metatype enumeration values used in the code
export const TYPE_PARTIALSTRUCT = 1;
export const TYPE_STRUCT = 4;
export const TYPE_UNION = 3;
export const TYPE_ARRAY = 7;
export const TYPE_PTR = 9;
export const TYPE_FLOAT = 10;
export const TYPE_BOOL = 12;
export const TYPE_UINT = 13;
export const TYPE_INT = 14;
export const TYPE_UNKNOWN = 15;

// ---------------------------------------------------------------------------
// Utility function declarations (assumed provided by core modules)
// ---------------------------------------------------------------------------

/** Calculate a bitmask for a given byte size */
export function calc_mask(size: number): bigint {
  if (size <= 0) return 0n;
  if (size >= 8) return 0xFFFFFFFFFFFFFFFFn;
  return (1n << BigInt(size * 8)) - 1n;
}

/** Return the index of the least significant bit set, or -1 if val is 0 */
export function leastsigbit_set(val: bigint): number {
  if (val === 0n) return -1;
  let i = 0;
  while ((val & 1n) === 0n) {
    val >>= 1n;
    i++;
  }
  return i;
}

/** Return the index of the most significant bit set, or -1 if val is 0 */
export function mostsigbit_set(val: bigint): number {
  if (val === 0n) return -1;
  let i = 0;
  while (val > 1n) {
    val >>= 1n;
    i++;
  }
  return i;
}

/** Sign-extend a value from sizein bytes to sizeout bytes */
export function sign_extend(input: bigint, sizein: number, sizeout: number): bigint {
  const bitsin = sizein * 8;
  const bitsout = sizeout * 8;
  const signbit = 1n << BigInt(bitsin - 1);
  const maskin = calc_mask(sizein);
  const maskout = calc_mask(sizeout);
  let val = input & maskin;
  if ((val & signbit) !== 0n) {
    // sign bit is set, fill upper bits with 1s
    val = val | (maskout ^ maskin);
  }
  return val & maskout;
}

// ---------------------------------------------------------------------------
// CPUI OpCode constants (a subset used in subflow)
// Assumed available from OpCode import; redeclared here for clarity.
// ---------------------------------------------------------------------------
export const CPUI_COPY = OpCode.CPUI_COPY;
export const CPUI_MULTIEQUAL = OpCode.CPUI_MULTIEQUAL;
export const CPUI_INDIRECT = OpCode.CPUI_INDIRECT;
export const CPUI_INT_NEGATE = OpCode.CPUI_INT_NEGATE;
export const CPUI_INT_XOR = OpCode.CPUI_INT_XOR;
export const CPUI_INT_AND = OpCode.CPUI_INT_AND;
export const CPUI_INT_OR = OpCode.CPUI_INT_OR;
export const CPUI_INT_ZEXT = OpCode.CPUI_INT_ZEXT;
export const CPUI_INT_SEXT = OpCode.CPUI_INT_SEXT;
export const CPUI_INT_ADD = OpCode.CPUI_INT_ADD;
export const CPUI_INT_LEFT = OpCode.CPUI_INT_LEFT;
export const CPUI_INT_RIGHT = OpCode.CPUI_INT_RIGHT;
export const CPUI_INT_SRIGHT = OpCode.CPUI_INT_SRIGHT;
export const CPUI_INT_MULT = OpCode.CPUI_INT_MULT;
export const CPUI_INT_DIV = OpCode.CPUI_INT_DIV;
export const CPUI_INT_REM = OpCode.CPUI_INT_REM;
export const CPUI_INT_EQUAL = OpCode.CPUI_INT_EQUAL;
export const CPUI_INT_NOTEQUAL = OpCode.CPUI_INT_NOTEQUAL;
export const CPUI_INT_LESS = OpCode.CPUI_INT_LESS;
export const CPUI_INT_LESSEQUAL = OpCode.CPUI_INT_LESSEQUAL;
export const CPUI_INT_SLESS = OpCode.CPUI_INT_SLESS;
export const CPUI_INT_SLESSEQUAL = OpCode.CPUI_INT_SLESSEQUAL;
export const CPUI_INT_CARRY = OpCode.CPUI_INT_CARRY;
export const CPUI_INT_SCARRY = OpCode.CPUI_INT_SCARRY;
export const CPUI_INT_SBORROW = OpCode.CPUI_INT_SBORROW;
export const CPUI_BOOL_NEGATE = OpCode.CPUI_BOOL_NEGATE;
export const CPUI_BOOL_AND = OpCode.CPUI_BOOL_AND;
export const CPUI_BOOL_OR = OpCode.CPUI_BOOL_OR;
export const CPUI_BOOL_XOR = OpCode.CPUI_BOOL_XOR;
export const CPUI_FLOAT_EQUAL = OpCode.CPUI_FLOAT_EQUAL;
export const CPUI_FLOAT_NOTEQUAL = OpCode.CPUI_FLOAT_NOTEQUAL;
export const CPUI_FLOAT_LESSEQUAL = OpCode.CPUI_FLOAT_LESSEQUAL;
export const CPUI_FLOAT_NAN = OpCode.CPUI_FLOAT_NAN;
export const CPUI_FLOAT_INT2FLOAT = OpCode.CPUI_FLOAT_INT2FLOAT;
export const CPUI_FLOAT_FLOAT2FLOAT = OpCode.CPUI_FLOAT_FLOAT2FLOAT;
export const CPUI_SUBPIECE = OpCode.CPUI_SUBPIECE;
export const CPUI_PIECE = OpCode.CPUI_PIECE;
export const CPUI_CALL = OpCode.CPUI_CALL;
export const CPUI_CALLIND = OpCode.CPUI_CALLIND;
export const CPUI_RETURN = OpCode.CPUI_RETURN;
export const CPUI_BRANCHIND = OpCode.CPUI_BRANCHIND;
export const CPUI_CBRANCH = OpCode.CPUI_CBRANCH;
export const CPUI_LOAD = OpCode.CPUI_LOAD;
export const CPUI_STORE = OpCode.CPUI_STORE;
export const CPUI_PTRSUB = OpCode.CPUI_PTRSUB;
export const CPUI_PTRADD = OpCode.CPUI_PTRADD;
export const CPUI_FLOAT_LESS = OpCode.CPUI_FLOAT_LESS;
export const CPUI_FLOAT_ADD = OpCode.CPUI_FLOAT_ADD;
export const CPUI_FLOAT_DIV = OpCode.CPUI_FLOAT_DIV;
export const CPUI_FLOAT_MULT = OpCode.CPUI_FLOAT_MULT;
export const CPUI_FLOAT_SUB = OpCode.CPUI_FLOAT_SUB;
export const CPUI_FLOAT_NEG = OpCode.CPUI_FLOAT_NEG;
export const CPUI_FLOAT_ABS = OpCode.CPUI_FLOAT_ABS;
export const CPUI_FLOAT_SQRT = OpCode.CPUI_FLOAT_SQRT;
export const CPUI_FLOAT_TRUNC = OpCode.CPUI_FLOAT_TRUNC;
export const CPUI_FLOAT_CEIL = OpCode.CPUI_FLOAT_CEIL;
export const CPUI_FLOAT_FLOOR = OpCode.CPUI_FLOAT_FLOOR;
export const CPUI_FLOAT_ROUND = OpCode.CPUI_FLOAT_ROUND;

// Size of bigint in "bytes" for mask precision (analogous to sizeof(uintb) == 8)
const SIZEOF_UINTB = 8;

// Forward declaration for TypeOpFloatInt2Float utility
function preferredZextSize(inSize: number): number {
  // Mirrors TypeOpFloatInt2Float::preferredZextSize logic
  if (inSize <= 4) return 4;
  return 8;
}

// ============================================================================
// Class declarations from subflow.hh
// ============================================================================

// ---------------------------------------------------------------------------
// SubvariableFlow inner classes
// ---------------------------------------------------------------------------

/** Placeholder node for Varnode holding a smaller logical value */
class ReplaceVarnode {
  vn: Varnode | null = null;          // Varnode being shrunk
  replacement: Varnode | null = null; // The new smaller Varnode
  mask: bigint = 0n;                  // Bits making up the logical sub-variable
  val: bigint = 0n;                   // Value of constant (when vn==null)
  def: ReplaceOp | null = null;       // Defining op for new Varnode
}

/** Placeholder node for PcodeOp operating on smaller logical values */
class ReplaceOp {
  op: PcodeOp | null = null;              // op getting paralleled
  replacement: PcodeOp | null = null;     // The new op
  opc: OpCode = CPUI_COPY;               // Opcode of the new op
  numparams: number = 0;                  // Number of parameters in (new) op
  output: ReplaceVarnode | null = null;   // Varnode output
  input: (ReplaceVarnode | null)[] = [];  // Varnode inputs
}

/** The possible types of patches on ops being performed */
export enum PatchType {
  copy_patch = 0,           // Turn op into a COPY of the logical value
  compare_patch = 1,        // Turn compare op inputs into logical values
  parameter_patch = 2,      // Convert a CALL/CALLIND/RETURN/BRANCHIND parameter into logical value
  extension_patch = 3,      // Convert op into something that copies/extends logical value, adding zero bits
  push_patch = 4,           // Convert an operator output to the logical value
  int2float_patch = 5,      // Zero extend logical value into FLOAT_INT2FLOAT operator
}

/** Operation with a new logical value as (part of) input, but output Varnode is unchanged */
class PatchRecord {
  type: PatchType = PatchType.copy_patch;    // The type of this patch
  patchOp: PcodeOp | null = null;           // Op being affected
  in1: ReplaceVarnode | null = null;         // The logical variable input
  in2: ReplaceVarnode | null = null;         // (optional second parameter)
  slot: number = 0;                          // slot being affected or other parameter
}

// ---------------------------------------------------------------------------
// SubvariableFlow
// ---------------------------------------------------------------------------

/**
 * Class for shrinking big Varnodes carrying smaller logical values.
 *
 * Given a root within the syntax tree and dimensions of a logical variable,
 * this class traces the flow of this logical variable through its containing
 * Varnodes. It then creates a subgraph of this flow, where there is a
 * correspondence between nodes in the subgraph and nodes in the original graph
 * containing the logical variable. When doReplacement is called, this subgraph
 * is duplicated as a new separate piece within the syntax tree.
 */
export class SubvariableFlow {
  private flowsize: number = 0;           // Size of the logical data-flow in bytes
  private bitsize: number = 0;            // Number of bits in logical variable
  private returnsTraversed: boolean = false; // Have we tried to flow logical value across CPUI_RETURNs
  private aggressive: boolean = false;    // Do we "know" initial seed point must be a sub variable
  private sextrestrictions: boolean = false; // Check for logical variables that are always sign extended
  private fd: Funcdata | null = null;     // Containing function
  private varmap: Map<Varnode, ReplaceVarnode> = new Map(); // Map from original Varnodes to subgraph nodes
  private newvarlist: ReplaceVarnode[] = [];   // Storage for subgraph variable nodes
  private oplist: ReplaceOp[] = [];            // Storage for subgraph op nodes
  private patchlist: PatchRecord[] = [];       // Operations getting patched (but with no flow thru)
  private worklist: ReplaceVarnode[] = [];     // Subgraph variable nodes still needing to be traced
  private pullcount: number = 0;               // Number of instructions pulling out the logical value

  // -------------------------------------------------------------------------
  // Static helpers
  // -------------------------------------------------------------------------

  /**
   * Return slot of constant if INT_OR op sets all bits in mask, otherwise -1
   */
  private static doesOrSet(orop: PcodeOp, mask: bigint): number {
    const index = orop.getIn(1)!.isConstant() ? 1 : 0;
    if (!orop.getIn(index)!.isConstant()) return -1;
    const orval: bigint = orop.getIn(index)!.getOffset();
    if ((mask & (~orval)) === 0n) // Are all masked bits one
      return index;
    return -1;
  }

  /**
   * Return slot of constant if INT_AND op clears all bits in mask, otherwise -1
   */
  private static doesAndClear(andop: PcodeOp, mask: bigint): number {
    const index = andop.getIn(1)!.isConstant() ? 1 : 0;
    if (!andop.getIn(index)!.isConstant()) return -1;
    const andval: bigint = andop.getIn(index)!.getOffset();
    if ((mask & andval) === 0n) // Are all masked bits zero
      return index;
    return -1;
  }

  // -------------------------------------------------------------------------
  // Private methods
  // -------------------------------------------------------------------------

  /**
   * Calculate address of replacement Varnode for given subgraph variable node
   */
  private getReplacementAddress(rvn: ReplaceVarnode): Address {
    let addr: Address = rvn.vn!.getAddr();
    const sa: number = leastsigbit_set(rvn.mask) / 8; // Number of bytes value is shifted into container
    if (addr.isBigEndian())
      addr = addr.add(BigInt(rvn.vn!.getSize() - this.flowsize - sa));
    else
      addr = addr.add(BigInt(sa));
    addr.renormalize(this.flowsize);
    return addr;
  }

  /**
   * Add the given Varnode as a new node in the logical subgraph.
   *
   * A new ReplaceVarnode object is created, representing the given Varnode within
   * the logical subgraph, and returned. If an object representing the Varnode already
   * exists it is returned. A mask describing the subset of bits within the Varnode
   * representing the logical value is also passed in.
   *
   * @returns [ReplaceVarnode | null, inworklist: boolean]
   */
  private setReplacement(vn: Varnode, mask: bigint): [ReplaceVarnode | null, boolean] {
    let res: ReplaceVarnode;
    if (vn.isMark()) {
      // Already seen before
      const existing = this.varmap.get(vn);
      if (existing === undefined) return [null, false];
      res = existing;
      if (res.mask !== mask)
        return [null, false];
      return [res, false];
    }

    if (vn.isConstant()) {
      if (this.sextrestrictions) {
        // Check that vn is a sign extension
        const cval: bigint = vn.getOffset();
        const smallval: bigint = cval & mask; // From its logical size
        const sextval: bigint = sign_extend(smallval, this.flowsize, vn.getSize());
        if (sextval !== cval)
          return [null, false];
      }
      return [this.addConstant(null, mask, 0, vn), false];
    }

    if (vn.isFree())
      return [null, false]; // Abort

    if (vn.isAddrForce() && (vn.getSize() !== this.flowsize))
      return [null, false];

    if (this.sextrestrictions) {
      if (vn.getSize() !== this.flowsize) {
        if ((!this.aggressive) && vn.isInput()) return [null, false];
        if (vn.isPersist()) return [null, false];
      }
      if (vn.isTypeLock() && vn.getType().getMetatype() !== TYPE_PARTIALSTRUCT) {
        if (vn.getType().getSize() !== this.flowsize)
          return [null, false];
      }
    } else {
      if (this.bitsize >= 8) {
        // Not a flag
        if ((!this.aggressive) && ((vn.getConsume() & ~mask) !== 0n))
          return [null, false];
        if (vn.isTypeLock() && vn.getType().getMetatype() !== TYPE_PARTIALSTRUCT) {
          const sz: number = vn.getType().getSize();
          if (sz !== this.flowsize)
            return [null, false];
        }
      }

      if (vn.isInput()) {
        if (this.bitsize < 8) return [null, false]; // Don't create input flag
        if ((mask & 1n) === 0n) return [null, false]; // Don't create unique input
      }
    }

    res = new ReplaceVarnode();
    this.varmap.set(vn, res);
    vn.setMark();
    res.vn = vn;
    res.replacement = null;
    res.mask = mask;
    res.def = null;
    let inworklist = true;
    // Check if vn already represents the logical variable being traced
    if (vn.getSize() === this.flowsize) {
      if (mask === calc_mask(this.flowsize)) {
        inworklist = false;
        res.replacement = vn;
      } else if (mask === 1n) {
        if (vn.isWritten() && vn.getDef()!.isBoolOutput()) {
          inworklist = false;
          res.replacement = vn;
        }
      }
    }
    return [res, inworklist];
  }

  /**
   * Create a logical subgraph operator node given its output variable node.
   */
  private createOp(opc: OpCode, numparam: number, outrvn: ReplaceVarnode): ReplaceOp {
    if (outrvn.def !== null)
      return outrvn.def;
    const rop = new ReplaceOp();
    this.oplist.push(rop);
    outrvn.def = rop;
    rop.op = outrvn.vn!.getDef();
    rop.numparams = numparam;
    rop.opc = opc;
    rop.output = outrvn;
    return rop;
  }

  /**
   * Create a logical subgraph operator node given one of its input variable nodes.
   */
  private createOpDown(opc: OpCode, numparam: number, op: PcodeOp, inrvn: ReplaceVarnode, slot: number): ReplaceOp {
    const rop = new ReplaceOp();
    this.oplist.push(rop);
    rop.op = op;
    rop.opc = opc;
    rop.numparams = numparam;
    rop.output = null;
    while (rop.input.length <= slot)
      rop.input.push(null);
    rop.input[slot] = inrvn;
    return rop;
  }

  /**
   * Determine if the given subgraph variable can act as a parameter to the given CALL op.
   */
  private tryCallPull(op: PcodeOp, rvn: ReplaceVarnode, slot: number): boolean {
    if (slot === 0) return false;
    if (!this.aggressive) {
      if ((rvn.vn!.getConsume() & ~rvn.mask) !== 0n)
        return false;
    }
    const fc: FuncCallSpecs = this.fd!.getCallSpecs(op);
    if (fc === null) return false;
    if (fc.isInputActive()) return false;
    if (fc.isInputLocked() && (!fc.isDotdotdot())) return false;

    const pr = new PatchRecord();
    pr.type = PatchType.parameter_patch;
    pr.patchOp = op;
    pr.in1 = rvn;
    pr.slot = slot;
    this.patchlist.push(pr);
    this.pullcount += 1;
    return true;
  }

  /**
   * Determine if the given subgraph variable can act as return value for the given RETURN op.
   */
  private tryReturnPull(op: PcodeOp, rvn: ReplaceVarnode, slot: number): boolean {
    if (slot === 0) return false;
    if (this.fd!.getFuncProto().isOutputLocked()) return false;
    if (!this.aggressive) {
      if ((rvn.vn!.getConsume() & ~rvn.mask) !== 0n)
        return false;
    }

    if (!this.returnsTraversed) {
      const iter = this.fd!.beginOp(CPUI_RETURN);
      const enditer = this.fd!.endOp(CPUI_RETURN);
      for (const retop of this.iterateOps(iter, enditer)) {
        if (retop.getHaltType() !== 0) continue; // Artificial halt
        const retvn: Varnode = retop.getIn(slot)!;
        const [rep, inworklist] = this.setReplacement(retvn, rvn.mask);
        if (rep === null)
          return false;
        if (inworklist)
          this.worklist.push(rep);
        else if (retvn.isConstant() && retop !== op) {
          // Trace won't revisit this RETURN, so we need to generate patch now
          const pr = new PatchRecord();
          pr.type = PatchType.parameter_patch;
          pr.patchOp = retop;
          pr.in1 = rep;
          pr.slot = slot;
          this.patchlist.push(pr);
          this.pullcount += 1;
        }
      }
      this.returnsTraversed = true;
    }
    const pr = new PatchRecord();
    pr.type = PatchType.parameter_patch;
    pr.patchOp = op;
    pr.in1 = rvn;
    pr.slot = slot;
    this.patchlist.push(pr);
    this.pullcount += 1;
    return true;
  }

  /**
   * Helper to iterate over a C++ list-style iterator range.
   * In the TS translation, we assume beginOp/endOp return iterables or arrays.
   */
  private iterateOps(iter: any, enditer: any): PcodeOp[] {
    // If the Funcdata provides an array or iterable, use it directly.
    // This is a compatibility shim for the C++ list<PcodeOp *>::const_iterator pattern.
    if (Array.isArray(iter)) return iter;
    const result: PcodeOp[] = [];
    const current = iter.clone ? iter.clone() : iter;
    while (!current.equals(enditer)) {
      result.push(current.value);
      current.next();
    }
    return result;
  }

  /**
   * Determine if the given subgraph variable can act as a created value for the given INDIRECT op.
   */
  private tryCallReturnPush(op: PcodeOp, rvn: ReplaceVarnode): boolean {
    if (!this.aggressive) {
      if ((rvn.vn!.getConsume() & ~rvn.mask) !== 0n)
        return false;
    }
    if ((rvn.mask & 1n) === 0n) return false;
    if (this.bitsize < 8) return false;
    const fc: FuncCallSpecs = this.fd!.getCallSpecs(op);
    if (fc === null) return false;
    if (fc.isOutputLocked()) return false;
    if (fc.isOutputActive()) return false;

    this.addPush(op, rvn);
    return true;
  }

  /**
   * Determine if the subgraph variable can act as a switch variable for the given BRANCHIND.
   */
  private trySwitchPull(op: PcodeOp, rvn: ReplaceVarnode): boolean {
    if ((rvn.mask & 1n) === 0n) return false;
    if ((rvn.vn!.getConsume() & ~rvn.mask) !== 0n)
      return false;
    const pr = new PatchRecord();
    pr.type = PatchType.parameter_patch;
    pr.patchOp = op;
    pr.in1 = rvn;
    pr.slot = 0;
    this.patchlist.push(pr);
    this.pullcount += 1;
    return true;
  }

  /**
   * Determine if the subgraph variable flows naturally into a terminal FLOAT_INT2FLOAT operation.
   */
  private tryInt2FloatPull(op: PcodeOp, rvn: ReplaceVarnode): boolean {
    if ((rvn.mask & 1n) === 0n) return false;
    if ((rvn.vn!.getNZMask() & ~rvn.mask) !== 0n)
      return false;
    if (rvn.vn!.getSize() === this.flowsize)
      return false;
    let pullModification = true;
    if (rvn.vn!.isWritten() && rvn.vn!.getDef()!.code() === CPUI_INT_ZEXT) {
      if (rvn.vn!.getSize() === preferredZextSize(this.flowsize)) {
        if (rvn.vn!.loneDescend() === op) {
          pullModification = false;
        }
      }
    }
    const pr = new PatchRecord();
    pr.type = PatchType.int2float_patch;
    pr.patchOp = op;
    pr.in1 = rvn;
    this.patchlist.push(pr);
    if (pullModification)
      this.pullcount += 1;
    return true;
  }

  /**
   * Trace the logical data-flow forward for the given subgraph variable.
   */
  private traceForward(rvn: ReplaceVarnode): boolean {
    let rop: ReplaceOp;
    let op: PcodeOp;
    let outvn: Varnode;
    let slot: number;
    let sa: number;
    let newmask: bigint;
    let booldir: boolean;
    let dcount = 0;
    let hcount = 0;
    let callcount = 0;

    const descendants = rvn.vn!.descend;
    for (let idx = 0; idx < descendants.length; idx++) {
      op = descendants[idx];
      outvn = op.getOut()!;
      if (outvn !== null && outvn.isMark() && !op.isCall())
        continue;
      dcount += 1;
      slot = op.getSlot(rvn.vn!);
      switch (op.code()) {
        case CPUI_COPY:
        case CPUI_MULTIEQUAL:
        case CPUI_INT_NEGATE:
        case CPUI_INT_XOR:
          rop = this.createOpDown(op.code(), op.numInput(), op, rvn, slot);
          if (!this.createLink(rop, rvn.mask, -1, outvn)) return false;
          hcount += 1;
          break;
        case CPUI_INT_OR:
          if (SubvariableFlow.doesOrSet(op, rvn.mask) !== -1) break;
          rop = this.createOpDown(CPUI_INT_OR, 2, op, rvn, slot);
          if (!this.createLink(rop, rvn.mask, -1, outvn)) return false;
          hcount += 1;
          break;
        case CPUI_INT_AND:
          if (op.getIn(1)!.isConstant() && op.getIn(1)!.getOffset() === rvn.mask) {
            if ((outvn.getSize() === this.flowsize) && ((rvn.mask & 1n) !== 0n)) {
              this.addTerminalPatch(op, rvn);
              hcount += 1;
              break;
            }
            // Is the small variable getting zero padded into something that is fully consumed
            if ((!this.aggressive) && ((outvn.getConsume() & rvn.mask) !== outvn.getConsume())) {
              this.addExtensionPatch(rvn, op, -1);
              hcount += 1;
              break;
            }
          }
          if (SubvariableFlow.doesAndClear(op, rvn.mask) !== -1) break;
          rop = this.createOpDown(CPUI_INT_AND, 2, op, rvn, slot);
          if (!this.createLink(rop, rvn.mask, -1, outvn)) return false;
          hcount += 1;
          break;
        case CPUI_INT_ZEXT:
        case CPUI_INT_SEXT:
          rop = this.createOpDown(CPUI_COPY, 1, op, rvn, 0);
          if (!this.createLink(rop, rvn.mask, -1, outvn)) return false;
          hcount += 1;
          break;
        case CPUI_INT_MULT:
          if ((rvn.mask & 1n) === 0n)
            return false;
          sa = leastsigbit_set(op.getIn(1 - slot)!.getNZMask());
          sa &= ~7; // Should be nearest multiple of 8
          if (this.bitsize + sa > 8 * rvn.vn!.getSize()) return false;
          rop = this.createOpDown(CPUI_INT_MULT, 2, op, rvn, slot);
          if (!this.createLink(rop, rvn.mask << BigInt(sa), -1, outvn)) return false;
          hcount += 1;
          break;
        case CPUI_INT_DIV:
        case CPUI_INT_REM:
          if ((rvn.mask & 1n) === 0n) return false;
          if ((this.bitsize & 7) !== 0) return false;
          if (!op.getIn(0)!.isZeroExtended(this.flowsize)) return false;
          if (!op.getIn(1)!.isZeroExtended(this.flowsize)) return false;
          rop = this.createOpDown(op.code(), 2, op, rvn, slot);
          if (!this.createLink(rop, rvn.mask, -1, outvn)) return false;
          hcount += 1;
          break;
        case CPUI_INT_ADD:
          if ((rvn.mask & 1n) === 0n)
            return false;
          rop = this.createOpDown(CPUI_INT_ADD, 2, op, rvn, slot);
          if (!this.createLink(rop, rvn.mask, -1, outvn)) return false;
          hcount += 1;
          break;
        case CPUI_INT_LEFT:
          if (slot === 1) {
            if ((rvn.mask & 1n) === 0n) return false;
            if (this.bitsize < 8) return false;
            this.addTerminalPatchSameOp(op, rvn, slot);
            hcount += 1;
            break;
          }
          if (!op.getIn(1)!.isConstant()) return false;
          sa = Number(op.getIn(1)!.getOffset());
          if (sa >= SIZEOF_UINTB * 8) return false;
          newmask = (rvn.mask << BigInt(sa)) & calc_mask(outvn.getSize());
          if (newmask === 0n) break;
          if (rvn.mask !== (newmask >> BigInt(sa))) return false;
          // Is the small variable getting zero padded into something that is consumed beyond the variable
          if (((rvn.mask & 1n) !== 0n) && (sa + this.bitsize === 8 * outvn.getSize())
              && ((outvn.getConsume() & ~newmask) !== 0n)) {
            this.addExtensionPatch(rvn, op, sa);
            hcount += 1;
            break;
          }
          rop = this.createOpDown(CPUI_COPY, 1, op, rvn, 0);
          if (!this.createLink(rop, newmask, -1, outvn)) return false;
          hcount += 1;
          break;
        case CPUI_INT_RIGHT:
        case CPUI_INT_SRIGHT:
          if (slot === 1) {
            if ((rvn.mask & 1n) === 0n) return false;
            if (this.bitsize < 8) return false;
            this.addTerminalPatchSameOp(op, rvn, slot);
            hcount += 1;
            break;
          }
          if (!op.getIn(1)!.isConstant()) return false;
          sa = Number(op.getIn(1)!.getOffset());
          if (sa >= SIZEOF_UINTB * 8)
            newmask = 0n;
          else
            newmask = rvn.mask >> BigInt(sa);
          if (newmask === 0n) {
            if (op.code() === CPUI_INT_RIGHT) break;
            return false;
          }
          if (rvn.mask !== (newmask << BigInt(sa))) return false;
          if ((outvn.getSize() === this.flowsize) && ((newmask & 1n) === 1n) &&
              (op.getIn(0)!.getNZMask() === rvn.mask)) {
            this.addTerminalPatch(op, rvn);
            hcount += 1;
            break;
          }
          // Is the small variable getting zero padded into something that is consumed beyond the variable
          if (((newmask & 1n) === 1n) && (sa + this.bitsize === 8 * outvn.getSize())
              && ((outvn.getConsume() & ~newmask) !== 0n)) {
            this.addExtensionPatch(rvn, op, 0);
            hcount += 1;
            break;
          }
          rop = this.createOpDown(CPUI_COPY, 1, op, rvn, 0);
          if (!this.createLink(rop, newmask, -1, outvn)) return false;
          hcount += 1;
          break;
        case CPUI_SUBPIECE:
          sa = Number(op.getIn(1)!.getOffset()) * 8;
          if (sa >= SIZEOF_UINTB * 8) break;
          newmask = (rvn.mask >> BigInt(sa)) & calc_mask(outvn.getSize());
          if (newmask === 0n) break;
          if (rvn.mask !== (newmask << BigInt(sa))) {
            if (this.flowsize > ((sa / 8) + outvn.getSize()) && (rvn.mask & 1n) !== 0n) {
              this.addTerminalPatchSameOp(op, rvn, 0);
              hcount += 1;
              break;
            }
            return false;
          }
          if (((newmask & 1n) !== 0n) && (outvn.getSize() === this.flowsize)) {
            this.addTerminalPatch(op, rvn);
            hcount += 1;
            break;
          }
          rop = this.createOpDown(CPUI_COPY, 1, op, rvn, 0);
          if (!this.createLink(rop, newmask, -1, outvn)) return false;
          hcount += 1;
          break;
        case CPUI_PIECE:
          if (rvn.vn === op.getIn(0)!)
            newmask = rvn.mask << BigInt(8 * op.getIn(1)!.getSize());
          else
            newmask = rvn.mask;
          rop = this.createOpDown(CPUI_COPY, 1, op, rvn, 0);
          if (!this.createLink(rop, newmask, -1, outvn)) return false;
          hcount += 1;
          break;
        case CPUI_INT_LESS:
        case CPUI_INT_LESSEQUAL:
          outvn = op.getIn(1 - slot)!; // The OTHER side of the comparison
          if ((!this.aggressive) && (((rvn.vn!.getNZMask() | rvn.mask) !== rvn.mask)))
            return false;
          if (outvn.isConstant()) {
            if ((rvn.mask | outvn.getOffset()) !== rvn.mask)
              return false;
          } else {
            if ((!this.aggressive) && (((rvn.mask | outvn.getNZMask()) !== rvn.mask)))
              return false;
          }
          if (!this.createCompareBridge(op, rvn, slot, outvn))
            return false;
          hcount += 1;
          break;
        case CPUI_INT_NOTEQUAL:
        case CPUI_INT_EQUAL:
          outvn = op.getIn(1 - slot)!; // The OTHER side of the comparison
          if (this.bitsize !== 1) {
            if ((!this.aggressive) && (((rvn.vn!.getNZMask() | rvn.mask) !== rvn.mask)))
              return false;
            if (outvn.isConstant()) {
              if ((rvn.mask | outvn.getOffset()) !== rvn.mask)
                return false;
            } else {
              if ((!this.aggressive) && (((rvn.mask | outvn.getNZMask()) !== rvn.mask)))
                return false;
            }
            if (!this.createCompareBridge(op, rvn, slot, outvn))
              return false;
          } else {
            // Movement of boolean variables
            if (!outvn.isConstant()) return false;
            newmask = rvn.vn!.getNZMask();
            if (newmask !== rvn.mask) return false;
            if (op.getIn(1 - slot)!.getOffset() === 0n)
              booldir = true;
            else if (op.getIn(1 - slot)!.getOffset() === newmask)
              booldir = false;
            else
              return false;
            if (op.code() === CPUI_INT_EQUAL)
              booldir = !booldir;
            if (booldir)
              this.addTerminalPatch(op, rvn);
            else {
              rop = this.createOpDown(CPUI_BOOL_NEGATE, 1, op, rvn, 0);
              this.createNewOut(rop, 1n);
              this.addTerminalPatch(op, rop.output!);
            }
          }
          hcount += 1;
          break;
        case CPUI_CALL:
        case CPUI_CALLIND:
          callcount += 1;
          if (callcount > 1)
            slot = op.getRepeatSlot(rvn.vn!, slot, idx);
          if (!this.tryCallPull(op, rvn, slot)) return false;
          hcount += 1;
          break;
        case CPUI_RETURN:
          if (!this.tryReturnPull(op, rvn, slot)) return false;
          hcount += 1;
          break;
        case CPUI_BRANCHIND:
          if (!this.trySwitchPull(op, rvn)) return false;
          hcount += 1;
          break;
        case CPUI_BOOL_NEGATE:
        case CPUI_BOOL_AND:
        case CPUI_BOOL_OR:
        case CPUI_BOOL_XOR:
          if (this.bitsize !== 1) return false;
          if (rvn.mask !== 1n) return false;
          this.addBooleanPatch(op, rvn, slot);
          break;
        case CPUI_FLOAT_INT2FLOAT:
          if (!this.tryInt2FloatPull(op, rvn)) return false;
          hcount += 1;
          break;
        case CPUI_CBRANCH:
          if ((this.bitsize !== 1) || (slot !== 1)) return false;
          if (rvn.mask !== 1n) return false;
          this.addBooleanPatch(op, rvn, 1);
          hcount += 1;
          break;
        default:
          return false;
      }
    }
    if (dcount !== hcount) {
      if (rvn.vn!.isInput()) return false;
    }
    return true;
  }

  /**
   * Trace the logical data-flow backward for the given subgraph variable.
   */
  private traceBackward(rvn: ReplaceVarnode): boolean {
    const op: PcodeOp | null = rvn.vn!.getDef();
    if (op === null) return true; // If vn is input
    let sa: number;
    let newmask: bigint;
    let rop: ReplaceOp;

    switch (op.code()) {
      case CPUI_COPY:
      case CPUI_MULTIEQUAL:
      case CPUI_INT_NEGATE:
      case CPUI_INT_XOR:
        rop = this.createOp(op.code(), op.numInput(), rvn);
        for (let i = 0; i < op.numInput(); ++i)
          if (!this.createLink(rop, rvn.mask, i, op.getIn(i)!))
            return false;
        return true;
      case CPUI_INT_AND:
        sa = SubvariableFlow.doesAndClear(op, rvn.mask);
        if (sa !== -1) {
          rop = this.createOp(CPUI_COPY, 1, rvn);
          this.addConstant(rop, rvn.mask, 0, op.getIn(sa)!);
        } else {
          rop = this.createOp(CPUI_INT_AND, 2, rvn);
          if (!this.createLink(rop, rvn.mask, 0, op.getIn(0)!)) return false;
          if (!this.createLink(rop, rvn.mask, 1, op.getIn(1)!)) return false;
        }
        return true;
      case CPUI_INT_OR:
        sa = SubvariableFlow.doesOrSet(op, rvn.mask);
        if (sa !== -1) {
          rop = this.createOp(CPUI_COPY, 1, rvn);
          this.addConstant(rop, rvn.mask, 0, op.getIn(sa)!);
        } else {
          rop = this.createOp(CPUI_INT_OR, 2, rvn);
          if (!this.createLink(rop, rvn.mask, 0, op.getIn(0)!)) return false;
          if (!this.createLink(rop, rvn.mask, 1, op.getIn(1)!)) return false;
        }
        return true;
      case CPUI_INT_ZEXT:
      case CPUI_INT_SEXT:
        if ((rvn.mask & calc_mask(op.getIn(0)!.getSize())) !== rvn.mask) {
          if ((rvn.mask & 1n) !== 0n && this.flowsize > op.getIn(0)!.getSize()) {
            this.addPush(op, rvn);
            return true;
          }
          break;
        }
        rop = this.createOp(CPUI_COPY, 1, rvn);
        if (!this.createLink(rop, rvn.mask, 0, op.getIn(0)!)) return false;
        return true;
      case CPUI_INT_ADD:
        if ((rvn.mask & 1n) === 0n)
          break;
        if (rvn.mask === 1n)
          rop = this.createOp(CPUI_INT_XOR, 2, rvn); // Single bit add
        else
          rop = this.createOp(CPUI_INT_ADD, 2, rvn);
        if (!this.createLink(rop, rvn.mask, 0, op.getIn(0)!)) return false;
        if (!this.createLink(rop, rvn.mask, 1, op.getIn(1)!)) return false;
        return true;
      case CPUI_INT_LEFT:
        if (!op.getIn(1)!.isConstant()) break;
        sa = Number(op.getIn(1)!.getOffset());
        if (sa >= SIZEOF_UINTB * 8)
          newmask = 0n;
        else
          newmask = rvn.mask >> BigInt(sa);
        if (newmask === 0n) {
          rop = this.createOp(CPUI_COPY, 1, rvn);
          this.addNewConstant(rop, 0, 0n);
          return true;
        }
        if ((newmask << BigInt(sa)) === rvn.mask) {
          rop = this.createOp(CPUI_COPY, 1, rvn);
          if (!this.createLink(rop, newmask, 0, op.getIn(0)!)) return false;
          return true;
        }
        if ((rvn.mask & 1n) === 0n) return false;
        rop = this.createOp(CPUI_INT_LEFT, 2, rvn);
        if (!this.createLink(rop, rvn.mask, 0, op.getIn(0)!)) return false;
        this.addConstant(rop, calc_mask(op.getIn(1)!.getSize()), 1, op.getIn(1)!);
        return true;
      case CPUI_INT_RIGHT:
        if (!op.getIn(1)!.isConstant()) break;
        sa = Number(op.getIn(1)!.getOffset());
        if (sa >= SIZEOF_UINTB * 8)
          break;
        newmask = (rvn.mask << BigInt(sa)) & calc_mask(op.getIn(0)!.getSize());
        if (newmask === 0n) {
          rop = this.createOp(CPUI_COPY, 1, rvn);
          this.addNewConstant(rop, 0, 0n);
          return true;
        }
        if ((newmask >> BigInt(sa)) !== rvn.mask)
          break;
        rop = this.createOp(CPUI_COPY, 1, rvn);
        if (!this.createLink(rop, newmask, 0, op.getIn(0)!)) return false;
        return true;
      case CPUI_INT_SRIGHT:
        if (!op.getIn(1)!.isConstant()) break;
        sa = Number(op.getIn(1)!.getOffset());
        if (sa >= SIZEOF_UINTB * 8)
          break;
        newmask = (rvn.mask << BigInt(sa)) & calc_mask(op.getIn(0)!.getSize());
        if ((newmask >> BigInt(sa)) !== rvn.mask)
          break;
        rop = this.createOp(CPUI_COPY, 1, rvn);
        if (!this.createLink(rop, newmask, 0, op.getIn(0)!)) return false;
        return true;
      case CPUI_INT_MULT: {
        sa = leastsigbit_set(rvn.mask);
        if (sa !== 0) {
          const sa2 = leastsigbit_set(op.getIn(1)!.getNZMask());
          if (sa2 < sa) return false;
          newmask = rvn.mask >> BigInt(sa);
          rop = this.createOp(CPUI_INT_MULT, 2, rvn);
          if (!this.createLink(rop, newmask, 0, op.getIn(0)!)) return false;
          if (!this.createLink(rop, rvn.mask, 1, op.getIn(1)!)) return false;
        } else {
          if (rvn.mask === 1n)
            rop = this.createOp(CPUI_INT_AND, 2, rvn); // Single bit multiply
          else
            rop = this.createOp(CPUI_INT_MULT, 2, rvn);
          if (!this.createLink(rop, rvn.mask, 0, op.getIn(0)!)) return false;
          if (!this.createLink(rop, rvn.mask, 1, op.getIn(1)!)) return false;
        }
        return true;
      }
      case CPUI_INT_DIV:
      case CPUI_INT_REM:
        if ((rvn.mask & 1n) === 0n) return false;
        if ((this.bitsize & 7) !== 0) return false;
        if (!op.getIn(0)!.isZeroExtended(this.flowsize)) return false;
        if (!op.getIn(1)!.isZeroExtended(this.flowsize)) return false;
        rop = this.createOp(op.code(), 2, rvn);
        if (!this.createLink(rop, rvn.mask, 0, op.getIn(0)!)) return false;
        if (!this.createLink(rop, rvn.mask, 1, op.getIn(1)!)) return false;
        return true;
      case CPUI_SUBPIECE:
        sa = Number(op.getIn(1)!.getOffset()) * 8;
        newmask = rvn.mask << BigInt(sa);
        rop = this.createOp(CPUI_COPY, 1, rvn);
        if (!this.createLink(rop, newmask, 0, op.getIn(0)!)) return false;
        return true;
      case CPUI_PIECE:
        if ((rvn.mask & calc_mask(op.getIn(1)!.getSize())) === rvn.mask) {
          rop = this.createOp(CPUI_COPY, 1, rvn);
          if (!this.createLink(rop, rvn.mask, 0, op.getIn(1)!)) return false;
          return true;
        }
        sa = op.getIn(1)!.getSize() * 8;
        newmask = rvn.mask >> BigInt(sa);
        if ((newmask << BigInt(sa)) === rvn.mask) {
          rop = this.createOp(CPUI_COPY, 1, rvn);
          if (!this.createLink(rop, newmask, 0, op.getIn(0)!)) return false;
          return true;
        }
        break;
      case CPUI_CALL:
      case CPUI_CALLIND:
        if (this.tryCallReturnPush(op, rvn))
          return true;
        break;
      case CPUI_INT_EQUAL:
      case CPUI_INT_NOTEQUAL:
      case CPUI_INT_SLESS:
      case CPUI_INT_SLESSEQUAL:
      case CPUI_INT_LESS:
      case CPUI_INT_LESSEQUAL:
      case CPUI_INT_CARRY:
      case CPUI_INT_SCARRY:
      case CPUI_INT_SBORROW:
      case CPUI_BOOL_NEGATE:
      case CPUI_BOOL_XOR:
      case CPUI_BOOL_AND:
      case CPUI_BOOL_OR:
      case CPUI_FLOAT_EQUAL:
      case CPUI_FLOAT_NOTEQUAL:
      case CPUI_FLOAT_LESSEQUAL:
      case CPUI_FLOAT_NAN:
        // Mask won't be 1, because setReplacement takes care of it
        if ((rvn.mask & 1n) === 1n) break; // Not normal variable flow
        // Variable is filled with zero
        rop = this.createOp(CPUI_COPY, 1, rvn);
        this.addNewConstant(rop, 0, 0n);
        return true;
      default:
        break;
    }

    return false;
  }

  /**
   * Trace logical data-flow forward assuming sign-extensions.
   */
  private traceForwardSext(rvn: ReplaceVarnode): boolean {
    let rop: ReplaceOp;
    let op: PcodeOp;
    let outvn: Varnode;
    let slot: number;
    let dcount = 0;
    let hcount = 0;
    let callcount = 0;

    const descendants = rvn.vn!.descend;
    for (let idx = 0; idx < descendants.length; idx++) {
      op = descendants[idx];
      outvn = op.getOut()!;
      if (outvn !== null && outvn.isMark() && !op.isCall())
        continue;
      dcount += 1;
      slot = op.getSlot(rvn.vn!);
      switch (op.code()) {
        case CPUI_COPY:
        case CPUI_MULTIEQUAL:
        case CPUI_INT_NEGATE:
        case CPUI_INT_XOR:
        case CPUI_INT_OR:
        case CPUI_INT_AND:
          rop = this.createOpDown(op.code(), op.numInput(), op, rvn, slot);
          if (!this.createLink(rop, rvn.mask, -1, outvn)) return false;
          hcount += 1;
          break;
        case CPUI_INT_SEXT:
          rop = this.createOpDown(CPUI_COPY, 1, op, rvn, 0);
          if (!this.createLink(rop, rvn.mask, -1, outvn)) return false;
          hcount += 1;
          break;
        case CPUI_INT_SRIGHT:
          if (!op.getIn(1)!.isConstant()) return false;
          rop = this.createOpDown(CPUI_INT_SRIGHT, 2, op, rvn, 0);
          if (!this.createLink(rop, rvn.mask, -1, outvn)) return false;
          this.addConstant(rop, calc_mask(op.getIn(1)!.getSize()), 1, op.getIn(1)!);
          hcount += 1;
          break;
        case CPUI_SUBPIECE:
          if (op.getIn(1)!.getOffset() !== 0n) return false;
          if (outvn.getSize() > this.flowsize) return false;
          if (outvn.getSize() === this.flowsize)
            this.addTerminalPatch(op, rvn);
          else
            this.addTerminalPatchSameOp(op, rvn, 0);
          hcount += 1;
          break;
        case CPUI_INT_LESS:
        case CPUI_INT_LESSEQUAL:
        case CPUI_INT_SLESS:
        case CPUI_INT_SLESSEQUAL:
        case CPUI_INT_EQUAL:
        case CPUI_INT_NOTEQUAL:
          outvn = op.getIn(1 - slot)!;
          if (!this.createCompareBridge(op, rvn, slot, outvn)) return false;
          hcount += 1;
          break;
        case CPUI_CALL:
        case CPUI_CALLIND:
          callcount += 1;
          if (callcount > 1)
            slot = op.getRepeatSlot(rvn.vn!, slot, idx);
          if (!this.tryCallPull(op, rvn, slot)) return false;
          hcount += 1;
          break;
        case CPUI_RETURN:
          if (!this.tryReturnPull(op, rvn, slot)) return false;
          hcount += 1;
          break;
        case CPUI_BRANCHIND:
          if (!this.trySwitchPull(op, rvn)) return false;
          hcount += 1;
          break;
        default:
          return false;
      }
    }
    if (dcount !== hcount) {
      if (rvn.vn!.isInput()) return false;
    }
    return true;
  }

  /**
   * Trace logical data-flow backward assuming sign-extensions.
   */
  private traceBackwardSext(rvn: ReplaceVarnode): boolean {
    const op: PcodeOp | null = rvn.vn!.getDef();
    if (op === null) return true; // If vn is input
    let rop: ReplaceOp;

    switch (op.code()) {
      case CPUI_COPY:
      case CPUI_MULTIEQUAL:
      case CPUI_INT_NEGATE:
      case CPUI_INT_XOR:
      case CPUI_INT_AND:
      case CPUI_INT_OR:
        rop = this.createOp(op.code(), op.numInput(), rvn);
        for (let i = 0; i < op.numInput(); ++i)
          if (!this.createLink(rop, rvn.mask, i, op.getIn(i)!))
            return false;
        return true;
      case CPUI_INT_ZEXT:
        if (op.getIn(0)!.getSize() < this.flowsize) {
          this.addPush(op, rvn);
          return true;
        }
        break;
      case CPUI_INT_SEXT:
        if (this.flowsize !== op.getIn(0)!.getSize()) return false;
        rop = this.createOp(CPUI_COPY, 1, rvn);
        if (!this.createLink(rop, rvn.mask, 0, op.getIn(0)!)) return false;
        return true;
      case CPUI_INT_SRIGHT:
        if (!op.getIn(1)!.isConstant()) return false;
        rop = this.createOp(CPUI_INT_SRIGHT, 2, rvn);
        if (!this.createLink(rop, rvn.mask, 0, op.getIn(0)!)) return false;
        if (rop.input.length === 1)
          this.addConstant(rop, calc_mask(op.getIn(1)!.getSize()), 1, op.getIn(1)!);
        return true;
      case CPUI_CALL:
      case CPUI_CALLIND:
        if (this.tryCallReturnPush(op, rvn))
          return true;
        break;
      default:
        break;
    }
    return false;
  }

  /**
   * Add a new variable to the logical subgraph as an input to the given operation.
   */
  private createLink(rop: ReplaceOp | null, mask: bigint, slot: number, vn: Varnode): boolean {
    const [rep, inworklist] = this.setReplacement(vn, mask);
    if (rep === null) return false;

    if (rop !== null) {
      if (slot === -1) {
        rop.output = rep;
        rep.def = rop;
      } else {
        while (rop.input.length <= slot)
          rop.input.push(null);
        rop.input[slot] = rep;
      }
    }

    if (inworklist)
      this.worklist.push(rep);
    return true;
  }

  /**
   * Extend the logical subgraph through a given comparison operator if possible.
   */
  private createCompareBridge(op: PcodeOp, inrvn: ReplaceVarnode, slot: number, othervn: Varnode): boolean {
    const [rep, inworklist] = this.setReplacement(othervn, inrvn.mask);
    if (rep === null) return false;

    if (slot === 0)
      this.addComparePatch(inrvn, rep, op);
    else
      this.addComparePatch(rep, inrvn, op);

    if (inworklist)
      this.worklist.push(rep);
    return true;
  }

  /**
   * Add a constant variable node to the logical subgraph.
   */
  private addConstant(rop: ReplaceOp | null, mask: bigint, slot: number, constvn: Varnode): ReplaceVarnode {
    const res = new ReplaceVarnode();
    this.newvarlist.push(res);
    res.vn = constvn;
    res.replacement = null;
    res.mask = mask;

    // Calculate the actual constant value
    const sa: number = leastsigbit_set(mask);
    res.val = sa >= 0 ? (mask & constvn.getOffset()) >> BigInt(sa) : 0n;
    res.def = null;
    if (rop !== null) {
      while (rop.input.length <= slot)
        rop.input.push(null);
      rop.input[slot] = res;
    }
    return res;
  }

  /**
   * Add a new constant variable node as an input to a logical operation.
   * The constant is new and isn't associated with a constant in the original graph.
   */
  private addNewConstant(rop: ReplaceOp | null, slot: number, val: bigint): ReplaceVarnode {
    const res = new ReplaceVarnode();
    this.newvarlist.push(res);
    res.vn = null;
    res.replacement = null;
    res.mask = 0n;
    res.val = val;
    res.def = null;
    if (rop !== null) {
      while (rop.input.length <= slot)
        rop.input.push(null);
      rop.input[slot] = res;
    }
    return res;
  }

  /**
   * Create a new, non-shadowing, subgraph variable node as an operation output.
   */
  private createNewOut(rop: ReplaceOp, mask: bigint): void {
    const res = new ReplaceVarnode();
    this.newvarlist.push(res);
    res.vn = null;
    res.replacement = null;
    res.mask = mask;

    rop.output = res;
    res.def = rop;
  }

  /**
   * Mark an operation where original data-flow is being pushed into a subgraph variable.
   */
  private addPush(pushOp: PcodeOp, rvn: ReplaceVarnode): void {
    const pr = new PatchRecord();
    pr.type = PatchType.push_patch;
    pr.patchOp = pushOp;
    pr.in1 = rvn;
    this.patchlist.unshift(pr); // Push to the front of the patch list
  }

  /**
   * Mark an operation where a subgraph variable is naturally copied into the original data-flow.
   * The original PcodeOp will be converted to a COPY.
   */
  private addTerminalPatch(pullop: PcodeOp, rvn: ReplaceVarnode): void {
    const pr = new PatchRecord();
    pr.type = PatchType.copy_patch;
    pr.patchOp = pullop;
    pr.in1 = rvn;
    this.patchlist.push(pr);
    this.pullcount += 1;
  }

  /**
   * Mark an operation where a subgraph variable is naturally pulled into the original data-flow.
   * The opcode of the operation will not change.
   */
  private addTerminalPatchSameOp(pullop: PcodeOp, rvn: ReplaceVarnode, slot: number): void {
    const pr = new PatchRecord();
    pr.type = PatchType.parameter_patch;
    pr.patchOp = pullop;
    pr.in1 = rvn;
    pr.slot = slot;
    this.patchlist.push(pr);
    this.pullcount += 1;
  }

  /**
   * Mark a subgraph bit variable flowing into an operation taking a boolean input.
   */
  private addBooleanPatch(pullop: PcodeOp, rvn: ReplaceVarnode, slot: number): void {
    const pr = new PatchRecord();
    pr.type = PatchType.parameter_patch;
    pr.patchOp = pullop;
    pr.in1 = rvn;
    pr.slot = slot;
    this.patchlist.push(pr);
    // this is not a true modification
  }

  /**
   * Mark a subgraph variable flowing to an operation that extends it by padding with zero bits.
   */
  private addExtensionPatch(rvn: ReplaceVarnode, pushop: PcodeOp, sa: number): void {
    const pr = new PatchRecord();
    pr.type = PatchType.extension_patch;
    pr.in1 = rvn;
    pr.patchOp = pushop;
    if (sa === -1)
      sa = leastsigbit_set(rvn.mask);
    pr.slot = sa;
    this.patchlist.push(pr);
    // This is not a true modification because the output is still the expanded size
  }

  /**
   * Mark subgraph variables flowing into a comparison operation.
   */
  private addComparePatch(in1: ReplaceVarnode, in2: ReplaceVarnode, op: PcodeOp): void {
    const pr = new PatchRecord();
    pr.type = PatchType.compare_patch;
    pr.patchOp = op;
    pr.in1 = in1;
    pr.in2 = in2;
    this.patchlist.push(pr);
    this.pullcount += 1;
  }

  /**
   * Replace an input Varnode in the subgraph with a temporary register.
   */
  private replaceInput(rvn: ReplaceVarnode): void {
    let newvn: Varnode = this.fd!.newUnique(rvn.vn!.getSize());
    newvn = this.fd!.setInputVarnode(newvn);
    this.fd!.totalReplace(rvn.vn!, newvn);
    this.fd!.deleteVarnode(rvn.vn!);
    rvn.vn = newvn;
  }

  /**
   * Decide if we use the same memory range of the original Varnode for the logical replacement.
   */
  private useSameAddress(rvn: ReplaceVarnode): boolean {
    if (rvn.vn!.isInput()) return true;
    if (rvn.vn!.isAddrTied()) return false;
    if ((rvn.mask & 1n) === 0n) return false; // Not aligned
    if (this.bitsize >= 8) return true;
    if (this.aggressive) return true;
    let bitmask = 1;
    bitmask = (bitmask << this.bitsize) - 1;
    let mask: bigint = rvn.vn!.getConsume();
    mask |= BigInt(bitmask);
    if (mask === rvn.mask) return true;
    return false;
  }

  /**
   * Build the logical Varnode which will replace its original containing Varnode.
   */
  private getReplaceVarnode(rvn: ReplaceVarnode): Varnode {
    if (rvn.replacement !== null)
      return rvn.replacement!;
    if (rvn.vn === null) {
      if (rvn.def === null)
        return this.fd!.newConstant(this.flowsize, rvn.val);
      rvn.replacement = this.fd!.newUnique(this.flowsize);
      return rvn.replacement!;
    }
    if (rvn.vn.isConstant()) {
      const newVn: Varnode = this.fd!.newConstant(this.flowsize, rvn.val);
      newVn.copySymbolIfValid(rvn.vn);
      return newVn;
    }

    const isinput: boolean = rvn.vn.isInput();
    if (this.useSameAddress(rvn)) {
      const addr: Address = this.getReplacementAddress(rvn);
      if (isinput)
        this.replaceInput(rvn);
      rvn.replacement = this.fd!.newVarnode(this.flowsize, addr);
    } else {
      rvn.replacement = this.fd!.newUnique(this.flowsize);
    }
    if (isinput)
      rvn.replacement = this.fd!.setInputVarnode(rvn.replacement);
    return rvn.replacement!;
  }

  /**
   * Process the next node in the worklist.
   */
  private processNextWork(): boolean {
    const rvn: ReplaceVarnode = this.worklist[this.worklist.length - 1];
    this.worklist.pop();

    if (this.sextrestrictions) {
      if (!this.traceBackwardSext(rvn)) return false;
      return this.traceForwardSext(rvn);
    }
    if (!this.traceBackward(rvn)) return false;
    return this.traceForward(rvn);
  }

  // -------------------------------------------------------------------------
  // Public interface
  // -------------------------------------------------------------------------

  /**
   * Constructor.
   * @param f is the function to attempt the subvariable transform on
   * @param root is a starting Varnode containing a smaller logical value
   * @param mask is a mask where 1 bits indicate the position of the logical value within the root Varnode
   * @param aggr is true if we should use aggressive (less restrictive) tests during the trace
   * @param sext is true if we should assume sign extensions from the logical value into its container
   * @param big is true if we look for subvariable flow for big (8-byte) logical values
   */
  constructor(f: Funcdata, root: Varnode, mask: bigint, aggr: boolean, sext: boolean, big: boolean) {
    this.fd = f;
    this.returnsTraversed = false;
    if (mask === 0n) {
      this.fd = null;
      return;
    }
    this.aggressive = aggr;
    this.sextrestrictions = sext;
    this.bitsize = (mostsigbit_set(mask) - leastsigbit_set(mask)) + 1;
    if (this.bitsize <= 8)
      this.flowsize = 1;
    else if (this.bitsize <= 16)
      this.flowsize = 2;
    else if (this.bitsize <= 24)
      this.flowsize = 3;
    else if (this.bitsize <= 32)
      this.flowsize = 4;
    else if (this.bitsize <= 64) {
      if (!big) {
        this.fd = null;
        return;
      }
      this.flowsize = 8;
    } else {
      this.fd = null;
      return;
    }
    this.createLink(null, mask, 0, root);
  }

  /**
   * Trace logical value through data-flow, constructing transform.
   * @returns true if a full transform has been constructed
   */
  public doTrace(): boolean {
    this.pullcount = 0;
    let retval = false;
    if (this.fd !== null) {
      retval = true;
      while (this.worklist.length > 0) {
        if (!this.processNextWork()) {
          retval = false;
          break;
        }
      }
    }

    // Clear marks
    for (const [vn, _rvn] of this.varmap) {
      vn.clearMark();
    }

    if (!retval) return false;
    if (this.pullcount === 0) return false;
    return true;
  }

  /**
   * Perform the discovered transform, making logical values explicit.
   */
  public doReplacement(): void {
    let piterIdx = 0;

    // Do up front processing of the call return patches, which will be at the front of the list
    for (piterIdx = 0; piterIdx < this.patchlist.length; piterIdx++) {
      const patch = this.patchlist[piterIdx];
      if (patch.type !== PatchType.push_patch) break;
      const pushOp: PcodeOp = patch.patchOp!;
      const newVn: Varnode = this.getReplaceVarnode(patch.in1!);
      const oldVn: Varnode = pushOp.getOut()!;
      this.fd!.opSetOutput(pushOp, newVn);

      // Create placeholder defining op for old Varnode, until dead code cleans it up
      const newZext: PcodeOp = this.fd!.newOp(1, pushOp.getAddr());
      this.fd!.opSetOpcode(newZext, CPUI_INT_ZEXT);
      this.fd!.opSetInput(newZext, newVn, 0);
      this.fd!.opSetOutput(newZext, oldVn);
      this.fd!.opInsertAfter(newZext, pushOp);
    }

    // Define all the outputs first
    for (const rop of this.oplist) {
      const newop: PcodeOp = this.fd!.newOp(rop.numparams, rop.op!.getAddr());
      rop.replacement = newop;
      this.fd!.opSetOpcode(newop, rop.opc);
      const rout: ReplaceVarnode = rop.output!;
      this.fd!.opSetOutput(newop, this.getReplaceVarnode(rout));
      this.fd!.opInsertAfter(newop, rop.op!);
    }

    // Set all the inputs
    for (const rop of this.oplist) {
      const newop: PcodeOp = rop.replacement!;
      for (let i = 0; i < rop.input.length; ++i)
        this.fd!.opSetInput(newop, this.getReplaceVarnode(rop.input[i]!), i);
    }

    // These are operations that carry flow from the small variable into an existing
    // variable of the correct size
    for (; piterIdx < this.patchlist.length; piterIdx++) {
      const patch = this.patchlist[piterIdx];
      const pullop: PcodeOp = patch.patchOp!;
      switch (patch.type) {
        case PatchType.copy_patch:
          while (pullop.numInput() > 1)
            this.fd!.opRemoveInput(pullop, pullop.numInput() - 1);
          this.fd!.opSetInput(pullop, this.getReplaceVarnode(patch.in1!), 0);
          this.fd!.opSetOpcode(pullop, CPUI_COPY);
          break;
        case PatchType.compare_patch:
          this.fd!.opSetInput(pullop, this.getReplaceVarnode(patch.in1!), 0);
          this.fd!.opSetInput(pullop, this.getReplaceVarnode(patch.in2!), 1);
          break;
        case PatchType.parameter_patch:
          this.fd!.opSetInput(pullop, this.getReplaceVarnode(patch.in1!), patch.slot);
          break;
        case PatchType.extension_patch: {
          const sa: number = patch.slot;
          const invec: Varnode[] = [];
          const inVn: Varnode = this.getReplaceVarnode(patch.in1!);
          const outSize: number = pullop.getOut()!.getSize();
          if (sa === 0) {
            invec.push(inVn);
            const opc: OpCode = (inVn.getSize() === outSize) ? CPUI_COPY : CPUI_INT_ZEXT;
            this.fd!.opSetOpcode(pullop, opc);
            this.fd!.opSetAllInput(pullop, invec);
          } else {
            if (inVn.getSize() !== outSize) {
              const zextop: PcodeOp = this.fd!.newOp(1, pullop.getAddr());
              this.fd!.opSetOpcode(zextop, CPUI_INT_ZEXT);
              const zextout: Varnode = this.fd!.newUniqueOut(outSize, zextop);
              this.fd!.opSetInput(zextop, inVn, 0);
              this.fd!.opInsertBefore(zextop, pullop);
              invec.push(zextout);
            } else {
              invec.push(inVn);
            }
            invec.push(this.fd!.newConstant(4, BigInt(sa)));
            this.fd!.opSetAllInput(pullop, invec);
            this.fd!.opSetOpcode(pullop, CPUI_INT_LEFT);
          }
          break;
        }
        case PatchType.push_patch:
          break; // Shouldn't see these here, handled earlier
        case PatchType.int2float_patch: {
          const zextOp: PcodeOp = this.fd!.newOp(1, pullop.getAddr());
          this.fd!.opSetOpcode(zextOp, CPUI_INT_ZEXT);
          const invn: Varnode = this.getReplaceVarnode(patch.in1!);
          this.fd!.opSetInput(zextOp, invn, 0);
          const sizeout: number = preferredZextSize(invn.getSize());
          const outvn: Varnode = this.fd!.newUniqueOut(sizeout, zextOp);
          this.fd!.opInsertBefore(zextOp, pullop);
          this.fd!.opSetInput(pullop, outvn, 0);
          break;
        }
      }
    }
  }
}

// ============================================================================
// Rule classes that use SubvariableFlow
// ============================================================================

/** Perform SubVariableFlow analysis triggered by INT_AND */
export class RuleSubvarAnd extends Rule {
  constructor(g: string) {
    super(g, 0, "subvar_and");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSubvarAnd(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(CPUI_INT_AND);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (!op.getIn(1)!.isConstant()) return 0;
    const vn: Varnode = op.getIn(0)!;
    const outvn: Varnode = op.getOut()!;
    if (outvn.getConsume() !== op.getIn(1)!.getOffset()) return 0;
    if ((outvn.getConsume() & 1n) === 0n) return 0;
    let cmask: bigint;
    if (outvn.getConsume() === 1n)
      cmask = 1n;
    else {
      cmask = calc_mask(vn.getSize());
      cmask >>= 8n;
      while (cmask !== 0n) {
        if (cmask === outvn.getConsume()) break;
        cmask >>= 8n;
      }
    }
    if (cmask === 0n) return 0;
    if (op.getOut()!.hasNoDescend()) return 0;
    const subflow = new SubvariableFlow(data, vn, cmask, false, false, false);
    if (!subflow.doTrace()) return 0;
    subflow.doReplacement();
    return 1;
  }
}

/** Perform SubVariableFlow analysis triggered by SUBPIECE */
export class RuleSubvarSubpiece extends Rule {
  constructor(g: string) {
    super(g, 0, "subvar_subpiece");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSubvarSubpiece(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(CPUI_SUBPIECE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const vn: Varnode = op.getIn(0)!;
    const outvn: Varnode = op.getOut()!;
    const flowsize: number = outvn.getSize();
    const sa: number = Number(op.getIn(1)!.getOffset());
    if (flowsize + sa > SIZEOF_UINTB) // Mask must fit in precision
      return 0;
    let mask: bigint = calc_mask(flowsize);
    mask <<= BigInt(8 * sa);
    let aggressive: boolean = outvn.isPtrFlow();
    if (!aggressive) {
      if ((vn.getConsume() & mask) !== vn.getConsume()) return 0;
      if (op.getOut()!.hasNoDescend()) return 0;
    }
    let big = false;
    if (flowsize >= 8 && vn.isInput()) {
      if (vn.loneDescend() === op)
        big = true;
    }
    const subflow = new SubvariableFlow(data, vn, mask, aggressive, false, big);
    if (!subflow.doTrace()) return 0;
    subflow.doReplacement();
    return 1;
  }
}

/**
 * Perform SubvariableFlow analysis triggered by testing of a single bit.
 *
 * Given a comparison (INT_EQUAL or INT_NOTEQUAL) to a constant,
 * check that input has only 1 bit that can possibly be non-zero
 * and that the constant is testing this.
 */
export class RuleSubvarCompZero extends Rule {
  constructor(g: string) {
    super(g, 0, "subvar_compzero");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSubvarCompZero(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(CPUI_INT_NOTEQUAL);
    oplist.push(CPUI_INT_EQUAL);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    if (!op.getIn(1)!.isConstant()) return 0;
    const vn: Varnode = op.getIn(0)!;
    let mask: bigint = vn.getNZMask();
    const bitnum: number = leastsigbit_set(mask);
    if (bitnum === -1) return 0;
    if ((mask >> BigInt(bitnum)) !== 1n) return 0; // Check if only one bit active

    // Check if the active bit is getting tested
    if ((op.getIn(1)!.getOffset() !== mask) &&
        (op.getIn(1)!.getOffset() !== 0n))
      return 0;

    if (op.getOut()!.hasNoDescend()) return 0;
    // We do a basic check that the stream from which it looks like
    // the bit is getting pulled is not fully consumed
    if (vn.isWritten()) {
      const andop: PcodeOp = vn.getDef()!;
      if (andop.numInput() === 0) return 0;
      const vn0: Varnode = andop.getIn(0)!;
      switch (andop.code()) {
        case CPUI_INT_AND:
        case CPUI_INT_OR:
        case CPUI_INT_RIGHT: {
          if (vn0.isConstant()) return 0;
          const mask0: bigint = vn0.getConsume() & vn0.getNZMask();
          const wholemask: bigint = calc_mask(vn0.getSize()) & mask0;
          if ((wholemask & 0xFFn) === 0xFFn) return 0;
          if ((wholemask & 0xFF00n) === 0xFF00n) return 0;
          break;
        }
        default:
          break;
      }
    }

    const subflow = new SubvariableFlow(data, vn, mask, false, false, false);
    if (!subflow.doTrace()) {
      return 0;
    }
    subflow.doReplacement();
    return 1;
  }
}

/** Perform SubvariableFlow analysis triggered by INT_RIGHT */
export class RuleSubvarShift extends Rule {
  constructor(g: string) {
    super(g, 0, "subvar_shift");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSubvarShift(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(CPUI_INT_RIGHT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const vn: Varnode = op.getIn(0)!;
    if (vn.getSize() !== 1) return 0;
    if (!op.getIn(1)!.isConstant()) return 0;
    const sa: number = Number(op.getIn(1)!.getOffset());
    let mask: bigint = vn.getNZMask();
    if ((mask >> BigInt(sa)) !== 1n) return 0; // Pulling out a single bit
    mask = ((mask >> BigInt(sa)) << BigInt(sa));
    if (op.getOut()!.hasNoDescend()) return 0;

    const subflow = new SubvariableFlow(data, vn, mask, false, false, false);
    if (!subflow.doTrace()) return 0;
    subflow.doReplacement();
    return 1;
  }
}

/** Perform SubvariableFlow analysis triggered by INT_ZEXT */
export class RuleSubvarZext extends Rule {
  constructor(g: string) {
    super(g, 0, "subvar_zext");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSubvarZext(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(CPUI_INT_ZEXT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const vn: Varnode = op.getOut()!;
    const invn: Varnode = op.getIn(0)!;
    const mask: bigint = calc_mask(invn.getSize());

    const subflow = new SubvariableFlow(data, vn, mask, invn.isPtrFlow(), false, false);
    if (!subflow.doTrace()) return 0;
    subflow.doReplacement();
    return 1;
  }
}

/** Perform SubvariableFlow analysis triggered by INT_SEXT */
export class RuleSubvarSext extends Rule {
  private isaggressive: boolean = false;

  constructor(g: string) {
    super(g, 0, "subvar_sext");
    this.isaggressive = false;
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSubvarSext(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(CPUI_INT_SEXT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const vn: Varnode = op.getOut()!;
    const invn: Varnode = op.getIn(0)!;
    const mask: bigint = calc_mask(invn.getSize());

    const subflow = new SubvariableFlow(data, vn, mask, this.isaggressive, true, false);
    if (!subflow.doTrace()) return 0;
    subflow.doReplacement();
    return 1;
  }

  reset(data: Funcdata): void {
    this.isaggressive = data.getArch().aggressive_ext_trim;
  }
}

// ============================================================================
// SplitFlow class
// ============================================================================

/**
 * Class for splitting up Varnodes that hold 2 logical variables.
 *
 * Starting from a root Varnode provided to the constructor, this class looks
 * for data-flow that consistently holds 2 logical values in a single Varnode.
 * If doTrace() returns true, a consistent view has been created and invoking
 * apply() will split all Varnodes and PcodeOps involved in the data-flow into
 * their logical pieces.
 */
export class SplitFlow extends TransformManager {
  private laneDescription: any;              // Description of how to split Varnodes
  private worklist: TransformVar[][] = [];   // Pending work list of Varnodes to push the split through

  /**
   * Find or build the placeholder objects for a Varnode that needs to be split.
   */
  private setReplacement(vn: Varnode): TransformVar[] | null {
    let res: TransformVar[];
    if (vn.isMark()) {
      // Already seen before
      res = this.getSplit(vn, this.laneDescription);
      return res;
    }

    if (vn.isTypeLock() && vn.getType().getMetatype() !== TYPE_PARTIALSTRUCT)
      return null;
    if (vn.isInput())
      return null;
    if (vn.isFree() && (!vn.isConstant()))
      return null;

    res = this.newSplit(vn, this.laneDescription);
    vn.setMark();
    if (!vn.isConstant())
      this.worklist.push(res);

    return res;
  }

  /**
   * Split given op into its lanes.
   */
  private addOp(op: PcodeOp, rvn: TransformVar[], slot: number): boolean {
    let outvn: TransformVar[];
    if (slot === -1)
      outvn = rvn;
    else {
      outvn = this.setReplacement(op.getOut()!)!;
      if (outvn === null)
        return false;
    }

    if (outvn[0].getDef() !== null)
      return true; // Already traversed

    const loOp: TransformOp = this.newOpReplace(op.numInput(), op.code(), op);
    const hiOp: TransformOp = this.newOpReplace(op.numInput(), op.code(), op);
    let numParam: number = op.numInput();
    if (op.code() === CPUI_INDIRECT) {
      this.opSetInput(loOp, this.newIop(op.getIn(1)!), 1);
      this.opSetInput(hiOp, this.newIop(op.getIn(1)!), 1);
      loOp.inheritIndirect(op);
      hiOp.inheritIndirect(op);
      numParam = 1;
    }
    for (let i = 0; i < numParam; ++i) {
      let invn: TransformVar[];
      if (i === slot)
        invn = rvn;
      else {
        invn = this.setReplacement(op.getIn(i)!)!;
        if (invn === null)
          return false;
      }
      this.opSetInput(loOp, invn[0], i);    // Low piece with low op
      this.opSetInput(hiOp, invn[1], i);    // High piece with high op
    }
    this.opSetOutput(loOp, outvn[0]);
    this.opSetOutput(hiOp, outvn[1]);
    return true;
  }

  /**
   * Try to trace the pair of logical values, forward, through ops that read them.
   */
  private traceForward(rvn: TransformVar[]): boolean {
    const origvn: Varnode = rvn[0].getOriginal()!;
    for (let idx = 0; idx < origvn.descend.length; idx++) {
      const op: PcodeOp = origvn.descend[idx];
      const outvn: Varnode | null = op.getOut()!;
      if (outvn !== null && outvn.isMark())
        continue;
      switch (op.code()) {
        case CPUI_COPY:
        case CPUI_MULTIEQUAL:
        case CPUI_INDIRECT:
        case CPUI_INT_AND:
        case CPUI_INT_OR:
        case CPUI_INT_XOR:
          if (!this.addOp(op, rvn, op.getSlot(origvn)))
            return false;
          break;
        case CPUI_SUBPIECE: {
          if (outvn!.isPrecisLo() || outvn!.isPrecisHi())
            return false;
          const val: bigint = op.getIn(1)!.getOffset();
          if ((val === 0n) && (outvn!.getSize() === this.laneDescription.getSize(0))) {
            const rop: TransformOp = this.newPreexistingOp(1, CPUI_COPY, op);
            this.opSetInput(rop, rvn[0], 0);
          } else if ((val === BigInt(this.laneDescription.getSize(0))) &&
                     (outvn!.getSize() === this.laneDescription.getSize(1))) {
            const rop: TransformOp = this.newPreexistingOp(1, CPUI_COPY, op);
            this.opSetInput(rop, rvn[1], 0);
          } else {
            return false;
          }
          break;
        }
        case CPUI_INT_LEFT: {
          const tmpvn: Varnode = op.getIn(1)!;
          if (!tmpvn.isConstant())
            return false;
          const val: bigint = tmpvn.getOffset();
          if (val < BigInt(this.laneDescription.getSize(1) * 8))
            return false;
          const rop: TransformOp = this.newPreexistingOp(2, CPUI_INT_LEFT, op);
          const zextrop: TransformOp = this.newOp(1, CPUI_INT_ZEXT, rop);
          this.opSetInput(zextrop, rvn[0], 0);
          this.opSetOutput(zextrop, this.newUnique(this.laneDescription.getWholeSize()));
          this.opSetInput(rop, zextrop.getOut()!, 0);
          this.opSetInput(rop, this.newConstant(op.getIn(1)!.getSize(), 0, op.getIn(1)!.getOffset()), 1);
          break;
        }
        case CPUI_INT_SRIGHT:
        case CPUI_INT_RIGHT: {
          const tmpvn: Varnode = op.getIn(1)!;
          if (!tmpvn.isConstant())
            return false;
          const val: bigint = tmpvn.getOffset();
          if (val < BigInt(this.laneDescription.getSize(0) * 8))
            return false;
          const extOpCode: OpCode = (op.code() === CPUI_INT_RIGHT) ? CPUI_INT_ZEXT : CPUI_INT_SEXT;
          if (val === BigInt(this.laneDescription.getSize(0) * 8)) {
            const rop: TransformOp = this.newPreexistingOp(1, extOpCode, op);
            this.opSetInput(rop, rvn[1], 0);
          } else {
            const remainShift: bigint = val - BigInt(this.laneDescription.getSize(0) * 8);
            const rop: TransformOp = this.newPreexistingOp(2, op.code(), op);
            const extrop: TransformOp = this.newOp(1, extOpCode, rop);
            this.opSetInput(extrop, rvn[1], 0);
            this.opSetOutput(extrop, this.newUnique(this.laneDescription.getWholeSize()));
            this.opSetInput(rop, extrop.getOut()!, 0);
            this.opSetInput(rop, this.newConstant(op.getIn(1)!.getSize(), 0, remainShift), 1);
          }
          break;
        }
        default:
          return false;
      }
    }
    return true;
  }

  /**
   * Try to trace the pair of logical values, backward, through the defining op.
   */
  private traceBackward(rvn: TransformVar[]): boolean {
    const op: PcodeOp | null = rvn[0].getOriginal()!.getDef();
    if (op === null) return true; // If vn is input

    switch (op.code()) {
      case CPUI_COPY:
      case CPUI_MULTIEQUAL:
      case CPUI_INT_AND:
      case CPUI_INT_OR:
      case CPUI_INT_XOR:
      case CPUI_INDIRECT:
        if (!this.addOp(op, rvn, -1))
          return false;
        break;
      case CPUI_PIECE: {
        if (op.getIn(0)!.getSize() !== this.laneDescription.getSize(1))
          return false;
        if (op.getIn(1)!.getSize() !== this.laneDescription.getSize(0))
          return false;
        const loOp: TransformOp = this.newOpReplace(1, CPUI_COPY, op);
        const hiOp: TransformOp = this.newOpReplace(1, CPUI_COPY, op);
        this.opSetInput(loOp, this.getPreexistingVarnode(op.getIn(1)!), 0);
        this.opSetOutput(loOp, rvn[0]);     // Least sig -> low
        this.opSetInput(hiOp, this.getPreexistingVarnode(op.getIn(0)!), 0);
        this.opSetOutput(hiOp, rvn[1]); // Most sig -> high
        break;
      }
      case CPUI_INT_ZEXT: {
        if (op.getIn(0)!.getSize() !== this.laneDescription.getSize(0))
          return false;
        if (op.getOut()!.getSize() !== this.laneDescription.getWholeSize())
          return false;
        const loOp: TransformOp = this.newOpReplace(1, CPUI_COPY, op);
        const hiOp: TransformOp = this.newOpReplace(1, CPUI_COPY, op);
        this.opSetInput(loOp, this.getPreexistingVarnode(op.getIn(0)!), 0);
        this.opSetOutput(loOp, rvn[0]);     // ZEXT input -> low
        this.opSetInput(hiOp, this.newConstant(this.laneDescription.getSize(1), 0, 0n), 0);
        this.opSetOutput(hiOp, rvn[1]); // zero -> high
        break;
      }
      case CPUI_INT_LEFT: {
        const cvn: Varnode = op.getIn(1)!;
        if (!cvn.isConstant()) return false;
        if (cvn.getOffset() !== BigInt(this.laneDescription.getSize(0) * 8)) return false;
        let invn: Varnode = op.getIn(0)!;
        if (!invn.isWritten()) return false;
        const zextOp: PcodeOp = invn.getDef()!;
        if (zextOp.code() !== CPUI_INT_ZEXT) return false;
        invn = zextOp.getIn(0)!;
        if (invn.getSize() !== this.laneDescription.getSize(1)) return false;
        if (invn.isFree()) return false;
        const loOp: TransformOp = this.newOpReplace(1, CPUI_COPY, op);
        const hiOp: TransformOp = this.newOpReplace(1, CPUI_COPY, op);
        this.opSetInput(loOp, this.newConstant(this.laneDescription.getSize(0), 0, 0n), 0);
        this.opSetOutput(loOp, rvn[0]);     // zero -> low
        this.opSetInput(hiOp, this.getPreexistingVarnode(invn), 0);
        this.opSetOutput(hiOp, rvn[1]); // invn -> high
        break;
      }
      default:
        return false;
    }
    return true;
  }

  /**
   * Process the next logical value on the worklist.
   */
  private processNextWork(): boolean {
    const rvn: TransformVar[] = this.worklist[this.worklist.length - 1];
    this.worklist.pop();

    if (!this.traceBackward(rvn)) return false;
    return this.traceForward(rvn);
  }

  /**
   * Constructor.
   * @param f is the function
   * @param root is the Varnode to split
   * @param lowSize is the size of the low piece in bytes
   */
  constructor(f: Funcdata, root: Varnode, lowSize: number) {
    super(f);
    // LaneDescription(wholeSize, lowSize, highSize)
    this.laneDescription = {
      getSize: (i: number) => (i === 0) ? lowSize : root.getSize() - lowSize,
      getWholeSize: () => root.getSize(),
      getNumLanes: () => 2,
      getPosition: (i: number) => (i === 0) ? 0 : lowSize,
    };
    this.setReplacement(root);
  }

  /**
   * Trace split through data-flow, constructing transform.
   * @returns true if a full transform has been constructed that can perform the split
   */
  public doTrace(): boolean {
    if (this.worklist.length === 0)
      return false;
    let retval = true;
    while (this.worklist.length > 0) {
      if (!this.processNextWork()) {
        retval = false;
        break;
      }
    }

    this.clearVarnodeMarks();
    if (!retval) return false;
    return true;
  }
}

// ============================================================================
// RuleSplitFlow
// ============================================================================

/**
 * Try to detect and split artificially joined Varnodes.
 *
 * Look for SUBPIECE coming from a PIECE that has come through INDIRECTs and/or MULTIEQUAL.
 * Then check if the input to SUBPIECE can be viewed as two independent pieces.
 * If so, split the pieces into independent data-flows.
 */
export class RuleSplitFlow extends Rule {
  constructor(g: string) {
    super(g, 0, "splitflow");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSplitFlow(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(CPUI_SUBPIECE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const loSize: number = Number(op.getIn(1)!.getOffset());
    if (loSize === 0)
      return 0;
    const vn: Varnode = op.getIn(0)!;
    if (!vn.isWritten())
      return 0;
    if (vn.isPrecisLo() || vn.isPrecisHi())
      return 0;
    if (op.getOut()!.getSize() + loSize !== vn.getSize())
      return 0;
    let concatOp: PcodeOp | null = null;
    let multiOp: PcodeOp = vn.getDef()!;
    while (multiOp.code() === CPUI_INDIRECT) {
      const tmpvn: Varnode = multiOp.getIn(0)!;
      if (!tmpvn.isWritten()) return 0;
      multiOp = tmpvn.getDef()!;
    }
    if (multiOp.code() === CPUI_PIECE) {
      if (vn.getDef() !== multiOp)
        concatOp = multiOp;
    } else if (multiOp.code() === CPUI_MULTIEQUAL) {
      for (let i = 0; i < multiOp.numInput(); ++i) {
        const invn: Varnode = multiOp.getIn(i)!;
        if (!invn.isWritten()) continue;
        const tmpOp: PcodeOp = invn.getDef()!;
        if (tmpOp.code() === CPUI_PIECE) {
          concatOp = tmpOp;
          break;
        }
      }
    }
    if (concatOp === null)
      return 0;
    if (concatOp.getIn(1)!.getSize() !== loSize)
      return 0;
    const splitFlow = new SplitFlow(data, vn, loSize);
    if (!splitFlow.doTrace()) return 0;
    splitFlow.apply();
    return 1;
  }
}

// --- SplitDatatype::RootPointer ---

class RootPointer {
  loadStore!: PcodeOp;
  ptrType!: TypePointer;
  firstPointer!: Varnode;
  pointer!: Varnode;
  baseOffset: number = 0;

  // RootPointer.backUpPointer
  backUpPointer(impliedBase: Datatype | null): boolean {
    if (!this.pointer.isWritten())
      return false;
    let off: number;
    const addOp: PcodeOp = this.pointer.getDef()!;
    const opc: OpCode = addOp.code();
    if (opc === CPUI_PTRSUB || opc === CPUI_INT_ADD || opc === CPUI_PTRADD) {
      const cvn: Varnode = addOp.getIn(1)!;
      if (!cvn.isConstant())
        return false;
      off = Number(BigInt.asIntN(32, cvn.getOffset()));
    }
    else if (opc === CPUI_COPY)
      off = 0;
    else {
      return false;
    }
    const tmpPointer: Varnode = addOp.getIn(0)!;
    const ct: Datatype = tmpPointer.getTypeReadFacing(addOp);
    if (ct.getMetatype() !== TYPE_PTR)
      return false;
    const parent: Datatype = (ct as TypePointer).getPtrTo();
    const meta: type_metatype = parent.getMetatype();
    if (meta !== TYPE_STRUCT && meta !== TYPE_ARRAY) {
      if ((opc !== CPUI_PTRADD && opc !== CPUI_COPY) || parent !== impliedBase)
        return false;
    }
    this.ptrType = ct as TypePointer;
    if (opc === CPUI_PTRADD)
      off *= Number(BigInt.asIntN(32, addOp.getIn(2)!.getOffset()));
    off = AddrSpace_addressToByteInt(off, this.ptrType.getWordSize());
    this.baseOffset += off;
    this.pointer = tmpPointer;
    return true;
  }

  // RootPointer.find
  find(op: PcodeOp, valueType: Datatype): boolean {
    let impliedBase: Datatype | null = null;
    if (valueType.getMetatype() === TYPE_PARTIALSTRUCT)		// Strip off partial to get containing struct or array
      valueType = (valueType as TypePartialStruct).getParent();
    if (valueType.getMetatype() === TYPE_ARRAY) {		// If the data-type is an array
      valueType = (valueType as TypeArray).getBase();
      impliedBase = valueType;				// we allow an implied array (pointer to element) as a match
    }
    this.loadStore = op;
    this.baseOffset = 0;
    this.firstPointer = this.pointer = op.getIn(1)!;
    const ct: Datatype = this.pointer.getTypeReadFacing(op);
    if (ct.getMetatype() !== TYPE_PTR)
      return false;
    this.ptrType = ct as TypePointer;
    if (this.ptrType.getPtrTo() !== valueType) {
      if (impliedBase !== null)
        return false;
      if (!this.backUpPointer(impliedBase))
        return false;
      if (this.ptrType.getPtrTo() !== valueType)
        return false;
    }
    // The required pointer is found.  We try to back up to pointers to containing structures or arrays
    for (let i = 0; i < 3; ++i) {
      if (this.pointer.isAddrTied() || this.pointer.loneDescend() === null) break;
      if (!this.backUpPointer(impliedBase))
        break;
    }
    return true;
  }

  // RootPointer.duplicateToTemp
  duplicateToTemp(data: Funcdata, followOp: PcodeOp): void {
    const newRoot: Varnode = data.buildCopyTemp(this.pointer, followOp);
    newRoot.updateType(this.ptrType);
    this.pointer = newRoot;
  }

  // RootPointer.freePointerChain
  freePointerChain(data: Funcdata): void {
    while (this.firstPointer !== this.pointer && !this.firstPointer.isAddrTied() && this.firstPointer.hasNoDescend()) {
      const tmpOp: PcodeOp = this.firstPointer.getDef()!;
      this.firstPointer = tmpOp.getIn(0)!;
      data.opDestroy(tmpOp);
    }
  }
}

// --- SplitDatatype::Component ---

class Component {
  inType: Datatype;
  outType: Datatype;
  offset: number;

  constructor(inT: Datatype, outT: Datatype, off: number) {
    this.inType = inT;
    this.outType = outT;
    this.offset = off;
  }
}

// --- SplitDatatype ---

class SplitDatatype {
  private data: Funcdata;
  private types: TypeFactory;
  private dataTypePieces: Component[] = [];
  private splitStructures: boolean;
  private splitArrays: boolean;
  private isLoadStore: boolean;

  constructor(func: Funcdata) {
    this.data = func;
    const glb: Architecture = func.getArch();
    this.types = glb.types;
    this.splitStructures = (glb.split_datatype_config & OptionSplitDatatypes.option_struct) !== 0;
    this.splitArrays = (glb.split_datatype_config & OptionSplitDatatypes.option_array) !== 0;
    this.isLoadStore = false;
  }

  // SplitDatatype.getComponent
  private getComponent(ct: Datatype, offset: number, isHole: { value: boolean }): Datatype | null {
    isHole.value = false;
    let curType: Datatype | null = ct;
    let curOff: bigint = BigInt(offset);
    do {
      const newoffRef = { val: curOff };
      curType = curType!.getSubType(curOff, newoffRef);
      curOff = newoffRef.val;
      if (curType === null) {
        let hole: number = ct.getHoleSize(offset);
        if (hole > 0) {
          if (hole > 8)
            hole = 8;
          isHole.value = true;
          return this.types.getBase(hole, TYPE_UNKNOWN);
        }
        return curType;
      }
    } while (curOff !== 0n || curType.getMetatype() === TYPE_ARRAY);
    return curType;
  }

  // SplitDatatype.categorizeDatatype
  private categorizeDatatype(ct: Datatype): number {
    let subType: Datatype;
    switch (ct.getMetatype()) {
      case TYPE_ARRAY:
        if (!this.splitArrays) break;
        subType = (ct as TypeArray).getBase();
        if (subType.getMetatype() !== TYPE_UNKNOWN || subType.getSize() !== 1)
          return 1;
        else
          return 2;	// unknown1 array does not need splitting and acts as (large) primitive
      case TYPE_PARTIALSTRUCT:
        subType = (ct as TypePartialStruct).getParent();
        if (subType.getMetatype() === TYPE_ARRAY) {
          if (!this.splitArrays) break;
          subType = (subType as TypeArray).getBase();
          if (subType.getMetatype() !== TYPE_UNKNOWN || subType.getSize() !== 1)
            return 1;
          else
            return 2;	// unknown1 array does not need splitting and acts as (large) primitive
        }
        else if (subType.getMetatype() === TYPE_STRUCT) {
          if (!this.splitStructures) break;
          return 0;
        }
        break;
      case TYPE_STRUCT:
        if (!this.splitStructures) break;
        if (ct.numDepend() > 1)
          return 0;
        break;
      case TYPE_INT:
      case TYPE_UINT:
      case TYPE_UNKNOWN:
        return 2;
      default:
        break;
    }
    return -1;
  }

  // SplitDatatype.testDatatypeCompatibility
  private testDatatypeCompatibility(inBase: Datatype, outBase: Datatype, inConstant: boolean): boolean {
    const inCategory: number = this.categorizeDatatype(inBase);
    if (inCategory < 0)
      return false;
    const outCategory: number = this.categorizeDatatype(outBase);
    if (outCategory < 0)
      return false;
    if (outCategory === 2 && inCategory === 2)
      return false;
    if (!inConstant && inBase === outBase && inBase.getMetatype() === TYPE_STRUCT)
      return false;	// Don't split a whole structure unless it is getting initialized from a constant
    if (this.isLoadStore && outCategory === 2 && inCategory === 1)
      return false;	// Don't split array pointer writing into primitive
    if (this.isLoadStore && inCategory === 2 && !inConstant && outCategory === 1)
      return false;	// Don't split primitive into an array pointer
    if (this.isLoadStore && inCategory === 1 && outCategory === 1 && !inConstant)
      return false;	// Don't split copies between arrays
    const inHole: { value: boolean } = { value: false };
    const outHole: { value: boolean } = { value: false };
    let curOff: number = 0;
    let sizeLeft: number = inBase.getSize();
    if (inCategory === 2) {		// If input is primitive
      while (sizeLeft > 0) {
        const curOut: Datatype | null = this.getComponent(outBase, curOff, outHole);
        if (curOut === null) return false;
        // Throw away primitive data-type if it is a constant
        const curIn: Datatype = inConstant ? curOut : this.types.getBase(curOut.getSize(), TYPE_UNKNOWN);
        this.dataTypePieces.push(new Component(curIn, curOut, curOff));
        sizeLeft -= curOut.getSize();
        curOff += curOut.getSize();
        if (outHole.value) {
          if (this.dataTypePieces.length === 1)
            return false;		// Initial offset into structure is at a hole
          if (sizeLeft === 0 && this.dataTypePieces.length === 2)
            return false;		// Two pieces, one is a hole.  Likely padding.
        }
      }
    }
    else if (outCategory === 2) {		// If output is primitive
      while (sizeLeft > 0) {
        const curIn: Datatype | null = this.getComponent(inBase, curOff, inHole);
        if (curIn === null) return false;
        const curOut: Datatype = this.types.getBase(curIn.getSize(), TYPE_UNKNOWN);
        this.dataTypePieces.push(new Component(curIn, curOut, curOff));
        sizeLeft -= curIn.getSize();
        curOff += curIn.getSize();
        if (inHole.value) {
          if (this.dataTypePieces.length === 1)
            return false;		// Initial offset into structure is at a hole
          if (sizeLeft === 0 && this.dataTypePieces.length === 2)
            return false;		// Two pieces, one is a hole.  Likely padding.
        }
      }
    }
    else {	// Both in and out data-types have components
      while (sizeLeft > 0) {
        let curIn: Datatype | null = this.getComponent(inBase, curOff, inHole);
        if (curIn === null) return false;
        let curOut: Datatype | null = this.getComponent(outBase, curOff, outHole);
        if (curOut === null) return false;
        while (curIn!.getSize() !== curOut!.getSize()) {
          if (curIn!.getSize() > curOut!.getSize()) {
            if (inHole.value)
              curIn = this.types.getBase(curOut!.getSize(), TYPE_UNKNOWN);
            else
              curIn = this.getComponent(curIn!, 0, inHole);
            if (curIn === null) return false;
          }
          else {
            if (outHole.value)
              curOut = this.types.getBase(curIn!.getSize(), TYPE_UNKNOWN);
            else
              curOut = this.getComponent(curOut!, 0, outHole);
            if (curOut === null) return false;
          }
        }
        this.dataTypePieces.push(new Component(curIn!, curOut!, curOff));
        sizeLeft -= curIn!.getSize();
        curOff += curIn!.getSize();
      }
    }
    return this.dataTypePieces.length > 1;
  }

  // SplitDatatype.testCopyConstraints
  private testCopyConstraints(copyOp: PcodeOp): boolean {
    const inVn: Varnode = copyOp.getIn(0)!;
    if (inVn.isInput() && !inVn.isReadOnly()) {
      return false;
    }
    if (inVn.isAddrTied()) {
      const outVn: Varnode = copyOp.getOut()!;
      if (outVn.isAddrTied() && outVn.getAddr().equals(inVn.getAddr())) {
        return false;
      }
    }
    else if (inVn.isWritten() && inVn.getDef()!.code() === CPUI_LOAD) {
      if (inVn.loneDescend() === copyOp) {
        return false;		// This situation is handled by splitLoad()
      }
    }
    return true;
  }

  // SplitDatatype.generateConstants
  private generateConstants(vn: Varnode, inVarnodes: Varnode[]): boolean {
    if (vn.loneDescend() === null) return false;
    if (!vn.isWritten()) return false;
    const op: PcodeOp = vn.getDef()!;
    const opc: OpCode = op.code();
    if (opc === CPUI_INT_ZEXT) {
      if (!op.getIn(0)!.isConstant()) return false;
    }
    else if (opc === CPUI_PIECE) {
      if (!op.getIn(0)!.isConstant() || !op.getIn(1)!.isConstant())
        return false;
    }
    else
      return false;
    let lo: bigint;
    let hi: bigint;
    let losize: number;
    const fullsize: number = vn.getSize();
    const isBigEndian: boolean = vn.getSpace()!.isBigEndian();
    if (opc === CPUI_INT_ZEXT) {
      hi = 0n;
      lo = op.getIn(0)!.getOffset();
      losize = op.getIn(0)!.getSize();
    }
    else {
      hi = op.getIn(0)!.getOffset();
      lo = op.getIn(1)!.getOffset();
      losize = op.getIn(1)!.getSize();
    }
    for (let i = 0; i < this.dataTypePieces.length; ++i) {
      const dt: Datatype = this.dataTypePieces[i].inType;
      if (dt.getSize() > 8) {	// sizeof(uintb)
        inVarnodes.length = 0;
        return false;
      }
      let sa: number;
      if (isBigEndian)
        sa = fullsize - (this.dataTypePieces[i].offset + dt.getSize());
      else
        sa = this.dataTypePieces[i].offset;
      let val: bigint;
      if (sa >= losize)
        val = hi >> BigInt(sa - losize);
      else {
        val = lo >> BigInt(sa * 8);
        if (sa + dt.getSize() > losize)
          val |= hi << BigInt((losize - sa) * 8);
      }
      val &= calc_mask(dt.getSize());
      const outVn: Varnode = this.data.newConstant(dt.getSize(), val);
      inVarnodes.push(outVn);
      outVn.updateType(dt);
    }
    this.data.opDestroy(op);
    return true;
  }

  // SplitDatatype.buildInConstants
  private buildInConstants(rootVn: Varnode, inVarnodes: Varnode[], bigEndian: boolean): void {
    const baseVal: bigint = rootVn.getOffset();
    for (let i = 0; i < this.dataTypePieces.length; ++i) {
      const dt: Datatype = this.dataTypePieces[i].inType;
      let off: number = this.dataTypePieces[i].offset;
      if (bigEndian)
        off = rootVn.getSize() - off - dt.getSize();
      const val: bigint = (baseVal >> BigInt(8 * off)) & calc_mask(dt.getSize());
      const outVn: Varnode = this.data.newConstant(dt.getSize(), val);
      inVarnodes.push(outVn);
      outVn.updateType(dt);
    }
  }

  // SplitDatatype.buildInSubpieces
  private buildInSubpieces(rootVn: Varnode, followOp: PcodeOp, inVarnodes: Varnode[]): void {
    if (this.generateConstants(rootVn, inVarnodes))
      return;
    const baseAddr: Address = rootVn.getAddr();
    for (let i = 0; i < this.dataTypePieces.length; ++i) {
      const dt: Datatype = this.dataTypePieces[i].inType;
      let off: number = this.dataTypePieces[i].offset;
      let addr: Address = baseAddr.add(BigInt(off));
      addr.renormalize(dt.getSize());
      if (addr.isBigEndian())
        off = rootVn.getSize() - off - dt.getSize();
      const subpiece: PcodeOp = this.data.newOp(2, followOp.getAddr());
      this.data.opSetOpcode(subpiece, CPUI_SUBPIECE);
      this.data.opSetInput(subpiece, rootVn, 0);
      this.data.opSetInput(subpiece, this.data.newConstant(4, BigInt(off)), 1);
      const outVn: Varnode = this.data.newVarnodeOut(dt.getSize(), addr, subpiece);
      inVarnodes.push(outVn);
      outVn.updateType(dt);
      this.data.opInsertBefore(subpiece, followOp);
    }
  }

  // SplitDatatype.buildOutVarnodes
  private buildOutVarnodes(rootVn: Varnode, outVarnodes: Varnode[]): void {
    const baseAddr: Address = rootVn.getAddr();
    for (let i = 0; i < this.dataTypePieces.length; ++i) {
      const dt: Datatype = this.dataTypePieces[i].outType;
      const off: number = this.dataTypePieces[i].offset;
      let addr: Address = baseAddr.add(BigInt(off));
      addr.renormalize(dt.getSize());
      const outVn: Varnode = this.data.newVarnode(dt.getSize(), addr, dt);
      outVarnodes.push(outVn);
    }
  }

  // SplitDatatype.buildOutConcats
  private buildOutConcats(rootVn: Varnode, previousOp: PcodeOp, outVarnodes: Varnode[]): void {
    if (rootVn.hasNoDescend())
      return;				// Don't need to produce concatenation if its unused
    const baseAddr: Address = rootVn.getAddr();
    let vn: Varnode;
    let concatOp: PcodeOp;
    let preOp: PcodeOp = previousOp;
    const addressTied: boolean = rootVn.isAddrTied();
    // We are creating a CONCAT stack, mark varnodes appropriately
    for (let i = 0; i < outVarnodes.length; ++i) {
      if (!addressTied)
        outVarnodes[i].setProtoPartial();
    }
    if (baseAddr.isBigEndian()) {
      vn = outVarnodes[0];
      for (let i = 1; ; ++i) {				// Traverse most to least significant
        concatOp = this.data.newOp(2, previousOp.getAddr());
        this.data.opSetOpcode(concatOp, CPUI_PIECE);
        this.data.opSetInput(concatOp, vn, 0);			// Most significant
        this.data.opSetInput(concatOp, outVarnodes[i], 1);	// Least significant
        this.data.opInsertAfter(concatOp, preOp);
        if (i + 1 >= outVarnodes.length) break;
        preOp = concatOp;
        const sz: number = vn.getSize() + outVarnodes[i].getSize();
        let addr: Address = baseAddr;
        addr.renormalize(sz);
        vn = this.data.newVarnodeOut(sz, addr, concatOp);
        if (!addressTied)
          vn.setProtoPartial();
      }
    }
    else {
      vn = outVarnodes[outVarnodes.length - 1];
      for (let i = outVarnodes.length - 2; ; --i) {		// Traverse most to least significant
        concatOp = this.data.newOp(2, previousOp.getAddr());
        this.data.opSetOpcode(concatOp, CPUI_PIECE);
        this.data.opSetInput(concatOp, vn, 0);			// Most significant
        this.data.opSetInput(concatOp, outVarnodes[i], 1);	// Least significant
        this.data.opInsertAfter(concatOp, preOp);
        if (i <= 0) break;
        preOp = concatOp;
        const sz: number = vn.getSize() + outVarnodes[i].getSize();
        let addr: Address = outVarnodes[i].getAddr();
        addr.renormalize(sz);
        vn = this.data.newVarnodeOut(sz, addr, concatOp);
        if (!addressTied)
          vn.setProtoPartial();
      }
    }
    concatOp!.setPartialRoot();
    this.data.opSetOutput(concatOp!, rootVn);
    if (!addressTied)
      this.data.getMerge().registerProtoPartialRoot(rootVn);
  }

  // SplitDatatype.buildPointers
  private buildPointers(
    rootVn: Varnode, ptrType: TypePointer, baseOffset: number,
    followOp: PcodeOp, ptrVarnodes: Varnode[], isInput: boolean
  ): void {
    const baseType: Datatype = ptrType.getPtrTo();
    for (let i = 0; i < this.dataTypePieces.length; ++i) {
      const matchType: Datatype = isInput ? this.dataTypePieces[i].inType : this.dataTypePieces[i].outType;
      let curOff: bigint = BigInt(baseOffset + this.dataTypePieces[i].offset);
      let tmpType: Datatype = baseType;
      let inPtr: Varnode = rootVn;
      do {
        let newOff: bigint;
        let newOp: PcodeOp;
        let newType: Datatype | null;
        if (curOff < 0n || curOff >= BigInt(tmpType.getSize())) {	// An offset not within the data-type indicates an array
          newType = tmpType;			// The new data-type will be the same as current data-type
          newOff = curOff % BigInt(tmpType.getSize());	// But new offset will be old offset modulo data-type size
          newOff = (newOff < 0n) ? (newOff + BigInt(tmpType.getSize())) : newOff;
        }
        else {
          const outOff: { value: bigint } = { value: 0n };
          newType = tmpType.getSubType(curOff, outOff);
          newOff = outOff.value;
          if (newType === null) {
            // Null should only be returned for a hole in a structure, in which case use precomputed data-type
            newType = matchType;
            newOff = 0n;
          }
        }
        if (tmpType === newType || tmpType.getMetatype() === TYPE_ARRAY) {
          let finalOffset: bigint = curOff - newOff;
          const sz: number = newType.getSize();		// Element size in bytes
          finalOffset = finalOffset / BigInt(sz);		// Number of elements
          // Convert to unsigned representation for the pointer size (matching C++ implicit int8->uintb cast)
          finalOffset = BigInt.asUintN(inPtr.getSize() * 8, finalOffset);
          const szAddr: number = AddrSpace_byteToAddressInt(sz, ptrType.getWordSize());
          newOp = this.data.newOp(3, followOp.getAddr());
          this.data.opSetOpcode(newOp, CPUI_PTRADD);
          this.data.opSetInput(newOp, inPtr, 0);
          const indexVn: Varnode = this.data.newConstant(inPtr.getSize(), finalOffset);
          this.data.opSetInput(newOp, indexVn, 1);
          this.data.opSetInput(newOp, this.data.newConstant(inPtr.getSize(), BigInt(szAddr)), 2);
          const indexType: Datatype = this.types.getBase(indexVn.getSize(), TYPE_INT);
          indexVn.updateType(indexType);
        }
        else {
          let finalOffset: bigint = BigInt(AddrSpace_byteToAddressInt(Number(curOff - newOff), ptrType.getWordSize()));
          // Convert to unsigned representation for the pointer size (matching C++ implicit int8->uintb cast)
          finalOffset = BigInt.asUintN(inPtr.getSize() * 8, finalOffset);
          newOp = this.data.newOp(2, followOp.getAddr());
          this.data.opSetOpcode(newOp, CPUI_PTRSUB);
          this.data.opSetInput(newOp, inPtr, 0);
          this.data.opSetInput(newOp, this.data.newConstant(inPtr.getSize(), finalOffset), 1);
        }
        inPtr = this.data.newUniqueOut(inPtr.getSize(), newOp);
        const tmpPtr: Datatype = this.types.getTypePointerStripArray(ptrType.getSize(), newType, ptrType.getWordSize());
        inPtr.updateType(tmpPtr);
        this.data.opInsertBefore(newOp, followOp);
        tmpType = newType;
        curOff = newOff;
      } while (tmpType.getSize() > matchType.getSize());
      ptrVarnodes.push(inPtr);
    }
  }

  // SplitDatatype.isArithmeticInput (static)
  static isArithmeticInput(vn: Varnode): boolean {
    for (let it = vn.beginDescend(); it < vn.endDescend(); it++) {
      const op: PcodeOp = vn.getDescend(it);
      if (op.getOpcode().isArithmeticOp())
        return true;
    }
    return false;
  }

  // SplitDatatype.isArithmeticOutput (static)
  static isArithmeticOutput(vn: Varnode): boolean {
    if (!vn.isWritten())
      return false;
    return vn.getDef()!.getOpcode().isArithmeticOp();
  }

  // SplitDatatype.splitCopy
  splitCopy(copyOp: PcodeOp, inType: Datatype, outType: Datatype): boolean {
    if (!this.testCopyConstraints(copyOp))
      return false;
    const inVn: Varnode = copyOp.getIn(0)!;
    // Detect if input is effectively a constant (true constant, or PIECE/ZEXT of constants)
    let inConstant: boolean = inVn.isConstant();
    if (!inConstant && inVn.isWritten()) {
      const defOp: PcodeOp = inVn.getDef()!;
      const defOpc = defOp.code();
      if (defOpc === CPUI_PIECE) {
        if (defOp.getIn(0)!.isConstant() && defOp.getIn(1)!.isConstant())
          inConstant = true;
      } else if (defOpc === CPUI_INT_ZEXT) {
        if (defOp.getIn(0)!.isConstant())
          inConstant = true;
      }
    }
    if (!this.testDatatypeCompatibility(inType, outType, inConstant))
      return false;
    if (SplitDatatype.isArithmeticOutput(inVn))		// Sanity check on input
      return false;
    const outVn: Varnode = copyOp.getOut()!;
    if (SplitDatatype.isArithmeticInput(outVn))	// Sanity check on output
      return false;
    const inVarnodes: Varnode[] = [];
    const outVarnodes: Varnode[] = [];
    if (inVn.isConstant())
      this.buildInConstants(inVn, inVarnodes, outVn.getSpace()!.isBigEndian());
    else
      this.buildInSubpieces(inVn, copyOp, inVarnodes);
    this.buildOutVarnodes(outVn, outVarnodes);
    this.buildOutConcats(outVn, copyOp, outVarnodes);
    for (let i = 0; i < inVarnodes.length; ++i) {
      const newCopyOp: PcodeOp = this.data.newOp(1, copyOp.getAddr());
      this.data.opSetOpcode(newCopyOp, CPUI_COPY);
      this.data.opSetInput(newCopyOp, inVarnodes[i], 0);
      this.data.opSetOutput(newCopyOp, outVarnodes[i]);
      this.data.opInsertBefore(newCopyOp, copyOp);
    }
    this.data.opDestroy(copyOp);
    return true;
  }

  // SplitDatatype.splitLoad
  splitLoad(loadOp: PcodeOp, inType: Datatype): boolean {
    this.isLoadStore = true;
    let outVn: Varnode = loadOp.getOut()!;
    let copyOp: PcodeOp | null = null;
    if (!outVn.isAddrTied())
      copyOp = outVn.loneDescend();
    if (copyOp !== null) {
      const opc: OpCode = copyOp.code();
      if (opc === CPUI_STORE) return false;	// Handled by RuleSplitStore
      if (opc !== CPUI_COPY)
        copyOp = null;
    }
    if (copyOp !== null)
      outVn = copyOp.getOut()!;
    const outType: Datatype = outVn.getTypeDefFacing();
    if (!this.testDatatypeCompatibility(inType, outType, false))
      return false;
    if (SplitDatatype.isArithmeticInput(outVn))			// Sanity check on output
      return false;
    const root = new RootPointer();
    if (!root.find(loadOp, inType))
      return false;
    const ptrVarnodes: Varnode[] = [];
    const outVarnodes: Varnode[] = [];
    const insertPoint: PcodeOp = (copyOp === null) ? loadOp : copyOp;
    this.buildPointers(root.pointer, root.ptrType, root.baseOffset, loadOp, ptrVarnodes, true);
    this.buildOutVarnodes(outVn, outVarnodes);
    this.buildOutConcats(outVn, insertPoint, outVarnodes);
    const spc: AddrSpace = loadOp.getIn(0)!.getSpaceFromConst();
    for (let i = 0; i < ptrVarnodes.length; ++i) {
      const newLoadOp: PcodeOp = this.data.newOp(2, insertPoint.getAddr());
      this.data.opSetOpcode(newLoadOp, CPUI_LOAD);
      this.data.opSetInput(newLoadOp, this.data.newVarnodeSpace(spc), 0);
      this.data.opSetInput(newLoadOp, ptrVarnodes[i], 1);
      this.data.opSetOutput(newLoadOp, outVarnodes[i]);
      this.data.opInsertBefore(newLoadOp, insertPoint);
    }
    if (copyOp !== null)
      this.data.opDestroy(copyOp);
    this.data.opDestroy(loadOp);
    root.freePointerChain(this.data);
    return true;
  }

  // SplitDatatype.splitStore
  splitStore(storeOp: PcodeOp, outType: Datatype): boolean {
    this.isLoadStore = true;
    const inVn: Varnode = storeOp.getIn(2)!;
    let loadOp: PcodeOp | null = null;
    let inType: Datatype | null = null;
    if (inVn.isWritten() && inVn.getDef()!.code() === CPUI_LOAD && inVn.loneDescend() === storeOp) {
      loadOp = inVn.getDef()!;
      inType = SplitDatatype.getValueDatatype(loadOp!, inVn.getSize(), this.data.getArch().types);
      if (inType === null)
        loadOp = null;
    }
    if (inType === null) {
      inType = inVn.getTypeReadFacing(storeOp);
    }
    if (!this.testDatatypeCompatibility(inType!, outType, inVn.isConstant())) {
      if (loadOp !== null) {
        // If not compatible while considering the LOAD, check again, but without the LOAD
        loadOp = null;
        inType = inVn.getTypeReadFacing(storeOp);
        this.dataTypePieces.length = 0;
        if (!this.testDatatypeCompatibility(inType, outType, inVn.isConstant()))
          return false;
      }
      else
        return false;
    }

    if (SplitDatatype.isArithmeticOutput(inVn)) {		// Sanity check
      return false;
    }

    const storeRoot = new RootPointer();
    if (!storeRoot.find(storeOp, outType)) {
      return false;
    }

    const loadRoot = new RootPointer();
    if (loadOp !== null) {
      if (!loadRoot.find(loadOp, inType!))
        return false;
    }

    const storeSpace: AddrSpace = storeOp.getIn(0)!.getSpaceFromConst();
    const inVarnodes: Varnode[] = [];
    if (inVn.isConstant())
      this.buildInConstants(inVn, inVarnodes, storeSpace.isBigEndian());
    else if (loadOp !== null) {
      const loadPtrs: Varnode[] = [];
      this.buildPointers(loadRoot.pointer, loadRoot.ptrType, loadRoot.baseOffset, loadOp, loadPtrs, true);
      const loadSpace: AddrSpace = loadOp.getIn(0)!.getSpaceFromConst();
      for (let i = 0; i < loadPtrs.length; ++i) {
        const newLoadOp: PcodeOp = this.data.newOp(2, loadOp.getAddr());
        this.data.opSetOpcode(newLoadOp, CPUI_LOAD);
        this.data.opSetInput(newLoadOp, this.data.newVarnodeSpace(loadSpace), 0);
        this.data.opSetInput(newLoadOp, loadPtrs[i], 1);
        const dt: Datatype = this.dataTypePieces[i].inType;
        const vn: Varnode = this.data.newUniqueOut(dt.getSize(), newLoadOp);
        vn.updateType(dt);
        inVarnodes.push(vn);
        this.data.opInsertBefore(newLoadOp, loadOp);
      }
    }
    else
      this.buildInSubpieces(inVn, storeOp, inVarnodes);

    const storePtrs: Varnode[] = [];
    if (storeRoot.pointer.isAddrTied())
      storeRoot.duplicateToTemp(this.data, storeOp);
    this.buildPointers(storeRoot.pointer, storeRoot.ptrType, storeRoot.baseOffset, storeOp, storePtrs, false);
    // Preserve original STORE object, so that INDIRECT references are still valid
    // but convert it into the first of the smaller STOREs
    this.data.opSetInput(storeOp, storePtrs[0], 1);
    this.data.opSetInput(storeOp, inVarnodes[0], 2);
    let lastStore: PcodeOp = storeOp;
    for (let i = 1; i < storePtrs.length; ++i) {
      const newStoreOp: PcodeOp = this.data.newOp(3, storeOp.getAddr());
      this.data.opSetOpcode(newStoreOp, CPUI_STORE);
      this.data.opSetInput(newStoreOp, this.data.newVarnodeSpace(storeSpace), 0);
      this.data.opSetInput(newStoreOp, storePtrs[i], 1);
      this.data.opSetInput(newStoreOp, inVarnodes[i], 2);
      this.data.opInsertAfter(newStoreOp, lastStore);
      lastStore = newStoreOp;
    }

    if (loadOp !== null) {
      this.data.opDestroy(loadOp);
      loadRoot.freePointerChain(this.data);
    }
    storeRoot.freePointerChain(this.data);
    return true;
  }

  // SplitDatatype.getValueDatatype (static)
  static getValueDatatype(loadStore: PcodeOp, size: number, tlst: TypeFactory): Datatype | null {
    let resType: Datatype;
    const ptrType: Datatype = loadStore.getIn(1)!.getTypeReadFacing(loadStore);
    if (ptrType.getMetatype() !== TYPE_PTR)
      return null;
    let baseOffset: number;
    if (ptrType.isPointerRel()) {
      const ptrRel = ptrType as TypePointerRel;
      resType = ptrRel.getParent();
      baseOffset = ptrRel.getByteOffset();
    }
    else {
      resType = (ptrType as TypePointer).getPtrTo();
      baseOffset = 0;
    }
    const metain: type_metatype = resType.getMetatype();
    if (resType.getAlignSize() < size) {
      if (metain === TYPE_INT || metain === TYPE_UINT || metain === TYPE_BOOL || metain === TYPE_FLOAT || metain === TYPE_PTR) {
        if ((size % resType.getAlignSize()) === 0) {
          const numEl: number = Math.floor(size / resType.getAlignSize());
          return tlst.getTypeArray(numEl, resType);
        }
      }
    }
    else if (metain === TYPE_STRUCT || metain === TYPE_ARRAY) {
      return tlst.getExactPiece(resType, baseOffset, size);
    }
    return null;
  }
}

// --- RuleSplitCopy ---

export class RuleSplitCopy extends Rule {
  constructor(g: string) {
    super(g, 0, "splitcopy");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSplitCopy(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(CPUI_COPY);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const inType: Datatype = op.getIn(0)!.getTypeReadFacing(op);
    const outType: Datatype = op.getOut()!.getTypeDefFacing();
    const metain: type_metatype = inType.getMetatype();
    const metaout: type_metatype = outType.getMetatype();
    if (metain !== TYPE_PARTIALSTRUCT && metaout !== TYPE_PARTIALSTRUCT &&
        metain !== TYPE_ARRAY && metaout !== TYPE_ARRAY &&
        metain !== TYPE_STRUCT && metaout !== TYPE_STRUCT)
      return 0;
    const splitter = new SplitDatatype(data);
    if (splitter.splitCopy(op, inType, outType))
      return 1;
    return 0;
  }
}

// --- RuleSplitLoad ---

export class RuleSplitLoad extends Rule {
  constructor(g: string) {
    super(g, 0, "splitload");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSplitLoad(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(CPUI_LOAD);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const inType: Datatype | null = SplitDatatype.getValueDatatype(op, op.getOut()!.getSize(), data.getArch().types);
    if (inType === null)
      return 0;
    const metain: type_metatype = inType.getMetatype();
    if (metain !== TYPE_STRUCT && metain !== TYPE_ARRAY && metain !== TYPE_PARTIALSTRUCT)
      return 0;
    const splitter = new SplitDatatype(data);
    if (splitter.splitLoad(op, inType))
      return 1;
    return 0;
  }
}

// --- RuleSplitStore ---

export class RuleSplitStore extends Rule {
  constructor(g: string) {
    super(g, 0, "splitstore");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSplitStore(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(CPUI_STORE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const outType: Datatype | null = SplitDatatype.getValueDatatype(op, op.getIn(2)!.getSize(), data.getArch().types);
    if (outType === null)
      return 0;
    const metain: type_metatype = outType.getMetatype();
    if (metain !== TYPE_STRUCT && metain !== TYPE_ARRAY && metain !== TYPE_PARTIALSTRUCT)
      return 0;
    const splitter = new SplitDatatype(data);
    if (splitter.splitStore(op, outType))
      return 1;
    return 0;
  }
}

// --- RuleDumptyHumpLate ---

export class RuleDumptyHumpLate extends Rule {
  constructor(g: string) {
    super(g, 0, "dumptyhumplate");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleDumptyHumpLate(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(CPUI_SUBPIECE);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    let vn: Varnode = op.getIn(0)!;
    if (!vn.isWritten()) return 0;
    let pieceOp: PcodeOp = vn.getDef()!;
    if (pieceOp.code() !== CPUI_PIECE) return 0;
    const out: Varnode = op.getOut()!;
    const outSize: number = out.getSize();
    let trunc: number = Number(op.getIn(1)!.getOffset());
    for (;;) {
      // Try to backtrack thru PIECE to the component vn is being truncated from
      let trialVn: Varnode = pieceOp.getIn(1)!;	// Assume the least significant component
      let trialTrunc: number = trunc;
      if (trunc >= trialVn.getSize()) {	// Test for truncation from the most significant part
        trialTrunc -= trialVn.getSize();		// How much is truncated
        trialVn = pieceOp.getIn(0)!;
      }
      if (outSize + trialTrunc > trialVn.getSize())
        break;				// vn crosses both components
      vn = trialVn;				// Commit to this component
      trunc = trialTrunc;
      if (vn.getSize() === outSize)
        break;				// Found matching component
      if (!vn.isWritten())
        break;
      pieceOp = vn.getDef()!;
      if (pieceOp.code() !== CPUI_PIECE)
        break;
    }
    if (vn === op.getIn(0)!)
      return 0;				// Didn't backtrack thru any PIECE
    if (vn.isWritten() && vn.getDef()!.code() === CPUI_COPY)
      vn = vn.getDef()!.getIn(0);
    let removeOp: PcodeOp;
    if (outSize !== vn.getSize()) {	// Component does not match size exactly. Preserve SUBPIECE.
      removeOp = op.getIn(0)!.getDef()!;
      if (Number(op.getIn(1)!.getOffset()) !== trunc)
        data.opSetInput(op, data.newConstant(4, BigInt(trunc)), 1);
      data.opSetInput(op, vn, 0);
    }
    else if (out.isAutoLive()) {		// Exact match but output address fixed. Change SUBPIECE to COPY.
      removeOp = op.getIn(0)!.getDef()!;
      data.opRemoveInput(op, 1);
      data.opSetOpcode(op, CPUI_COPY);
      data.opSetInput(op, vn, 0);
    }
    else {				// Exact match. Completely replace output with component.
      removeOp = op;
      data.totalReplace(out, vn);
    }
    if (removeOp.getOut()!.hasNoDescend() && !removeOp.getOut()!.isAutoLive()) {
      const scratch: PcodeOp[] = [];
      data.opDestroyRecursive(removeOp, scratch);
    }
    return 1;
  }
}

// --- SubfloatFlow ---

class SubfloatFlow extends TransformManager {
  private precision: number;
  private terminatorCount: number = 0;
  private format: FloatFormat | null;
  private worklist: TransformVar[] = [];
  private maxPrecisionMap: Map<PcodeOp, number> = new Map();

  // SubfloatFlow::State (internal helper)
  // Represented as an inline object rather than a separate class

  // SubfloatFlow.maxPrecision
  private maxPrecisionCalc(vn: Varnode): number {
    if (!vn.isWritten())
      return vn.getSize();
    const op: PcodeOp = vn.getDef()!;
    switch (op.code()) {
      case CPUI_MULTIEQUAL:
      case CPUI_FLOAT_NEG:
      case CPUI_FLOAT_ABS:
      case CPUI_FLOAT_SQRT:
      case CPUI_FLOAT_CEIL:
      case CPUI_FLOAT_FLOOR:
      case CPUI_FLOAT_ROUND:
      case CPUI_COPY:
        break;
      case CPUI_FLOAT_ADD:
      case CPUI_FLOAT_SUB:
      case CPUI_FLOAT_MULT:
      case CPUI_FLOAT_DIV:
        return 0;			// Delay checking other binary ops
      case CPUI_FLOAT_FLOAT2FLOAT:
      case CPUI_FLOAT_INT2FLOAT:	// Treat integer as having precision matching its size
        if (op.getIn(0)!.getSize() > vn.getSize())
          return vn.getSize();
        return op.getIn(0)!.getSize();
      default:
        return vn.getSize();
    }

    const cached = this.maxPrecisionMap.get(op);
    if (cached !== undefined) {
      return cached;
    }

    interface State {
      op: PcodeOp;
      slot: number;
      maxPrecision: number;
    }
    const opStack: State[] = [];
    opStack.push({ op: op, slot: 0, maxPrecision: 0 });
    op.setMark();
    let max: number = 0;
    while (opStack.length > 0) {
      const state: State = opStack[opStack.length - 1];
      if (state.slot >= state.op.numInput()) {
        max = state.maxPrecision;
        state.op.clearMark();
        this.maxPrecisionMap.set(state.op, state.maxPrecision);
        opStack.pop();
        if (opStack.length > 0) {
          const top = opStack[opStack.length - 1];
          top.maxPrecision = (top.maxPrecision < max) ? max : top.maxPrecision;
        }
        continue;
      }
      const nextVn: Varnode = state.op.getIn(state.slot)!;
      state.slot += 1;
      if (!nextVn.isWritten()) {
        state.maxPrecision = (state.maxPrecision < nextVn.getSize()) ? nextVn.getSize() : state.maxPrecision;
        continue;
      }
      const nextOp: PcodeOp = nextVn.getDef()!;
      if (nextOp.isMark()) {
        continue;			// Truncate the cycle edge
      }
      switch (nextOp.code()) {
        case CPUI_MULTIEQUAL:
        case CPUI_FLOAT_NEG:
        case CPUI_FLOAT_ABS:
        case CPUI_FLOAT_SQRT:
        case CPUI_FLOAT_CEIL:
        case CPUI_FLOAT_FLOOR:
        case CPUI_FLOAT_ROUND:
        case CPUI_COPY:
        {
          const cachedVal = this.maxPrecisionMap.get(nextOp);
          if (cachedVal !== undefined) {
            // Seen the op before, incorporate its cached precision information
            state.maxPrecision = (state.maxPrecision < cachedVal) ? cachedVal : state.maxPrecision;
            break;
          }
          nextOp.setMark();
          opStack.push({ op: nextOp, slot: 0, maxPrecision: 0 });	// Recursively push into the new op
          break;
        }
        case CPUI_FLOAT_ADD:
        case CPUI_FLOAT_SUB:
        case CPUI_FLOAT_MULT:
        case CPUI_FLOAT_DIV:
          break;
        case CPUI_FLOAT_FLOAT2FLOAT:
        case CPUI_FLOAT_INT2FLOAT:		// Treat integer as having precision matching its size
        {
          let inPrec: number;
          if (nextOp.getIn(0)!.getSize() > nextVn.getSize())
            inPrec = nextVn.getSize();
          else
            inPrec = nextOp.getIn(0)!.getSize();
          state.maxPrecision = (state.maxPrecision < inPrec) ? inPrec : state.maxPrecision;
          break;
        }
        default:
          state.maxPrecision = (state.maxPrecision < nextVn.getSize()) ? nextVn.getSize() : state.maxPrecision;
          break;
      }
    }
    return max;
  }

  // SubfloatFlow.exceedsPrecision
  private exceedsPrecision(op: PcodeOp): boolean {
    const val1: number = this.maxPrecisionCalc(op.getIn(0)!);
    const val2: number = this.maxPrecisionCalc(op.getIn(1)!);
    const min: number = (val1 < val2) ? val1 : val2;
    return (min > this.precision);
  }

  // SubfloatFlow.setReplacement
  private setReplacement(vn: Varnode): TransformVar | null {
    if (vn.isMark())		// Already seen before
      return this.getPiece(vn, this.precision * 8, 0);

    if (vn.isConstant()) {
      const form2: FloatFormat | null = this.getFunction().getArch().translate.getFloatFormat(vn.getSize());
      if (form2 === null)
        return null;	// Unsupported constant format
      // Return the converted form of the constant
      return this.newConstant(this.precision, 0, this.format!.convertEncoding(vn.getOffset(), form2));
    }

    if (vn.isFree())
      return null; // Abort

    if (vn.isAddrForce() && (vn.getSize() !== this.precision))
      return null;

    if (vn.isTypeLock() && vn.getType().getMetatype() !== TYPE_PARTIALSTRUCT) {
      const sz: number = vn.getType().getSize();
      if (sz !== this.precision)
        return null;
    }

    if (vn.isInput()) {		// Must be careful with inputs
      if (vn.getSize() !== this.precision) return null;
    }

    vn.setMark();
    let res: TransformVar;
    // Check if vn already represents the logical variable being traced
    if (vn.getSize() === this.precision)
      res = this.newPreexistingVarnode(vn);
    else {
      res = this.newPiece(vn, this.precision * 8, 0);
      this.worklist.push(res);
    }
    return res;
  }

  // SubfloatFlow.traceForward
  private traceForward(rvn: TransformVar): boolean {
    const vn: Varnode = rvn.getOriginal()!;
    const enditer = vn.endDescend();
    for (let it = vn.beginDescend(); it < enditer; it++) {
      const op: PcodeOp = vn.getDescend(it);
      const outvn: Varnode | null = op.getOut()!;
      if ((outvn !== null) && (outvn.isMark()))
        continue;
      switch (op.code()) {
        case CPUI_FLOAT_ADD:
        case CPUI_FLOAT_SUB:
        case CPUI_FLOAT_MULT:
        case CPUI_FLOAT_DIV:
          if (this.exceedsPrecision(op))
            return false;
          // fall through
        case CPUI_MULTIEQUAL:
        case CPUI_COPY:
        case CPUI_FLOAT_CEIL:
        case CPUI_FLOAT_FLOOR:
        case CPUI_FLOAT_ROUND:
        case CPUI_FLOAT_NEG:
        case CPUI_FLOAT_ABS:
        case CPUI_FLOAT_SQRT:
        {
          const rop: TransformOp = this.newOpReplace(op.numInput(), op.code(), op);
          const outrvn: TransformVar | null = this.setReplacement(outvn!);
          if (outrvn === null) return false;
          this.opSetInput(rop, rvn, op.getSlot(vn));
          this.opSetOutput(rop, outrvn);
          break;
        }
        case CPUI_FLOAT_FLOAT2FLOAT:
        {
          if (outvn!.getSize() < this.precision)
            return false;
          const rop: TransformOp = this.newPreexistingOp(
            1,
            (outvn!.getSize() === this.precision) ? CPUI_COPY : CPUI_FLOAT_FLOAT2FLOAT,
            op
          );
          this.opSetInput(rop, rvn, 0);
          this.terminatorCount += 1;
          break;
        }
        case CPUI_FLOAT_EQUAL:
        case CPUI_FLOAT_NOTEQUAL:
        case CPUI_FLOAT_LESS:
        case CPUI_FLOAT_LESSEQUAL:
        {
          if (this.exceedsPrecision(op))
            return false;
          let slot: number = op.getSlot(vn);
          const rvn2: TransformVar | null = this.setReplacement(op.getIn(1 - slot)!);
          if (rvn2 === null) return false;
          if (rvn === rvn2) {
            // Need to handle repeat slot case
            // In C++ this uses iterator arithmetic; approximate here
            slot = op.getRepeatSlot(vn, slot, it);
          }
          if (TransformManager.preexistingGuard(slot, rvn2)) {
            const rop: TransformOp = this.newPreexistingOp(2, op.code(), op);
            this.opSetInput(rop, rvn, slot);
            this.opSetInput(rop, rvn2, 1 - slot);
            this.terminatorCount += 1;
          }
          break;
        }
        case CPUI_FLOAT_TRUNC:
        case CPUI_FLOAT_NAN:
        {
          const rop: TransformOp = this.newPreexistingOp(1, op.code(), op);
          this.opSetInput(rop, rvn, 0);
          this.terminatorCount += 1;
          break;
        }
        default:
          return false;
      }
    }
    return true;
  }

  // SubfloatFlow.traceBackward
  private traceBackward(rvn: TransformVar): boolean {
    const op: PcodeOp | null = rvn.getOriginal()!.getDef();
    if (op === null) return true; // If vn is input

    switch (op.code()) {
      case CPUI_FLOAT_ADD:
      case CPUI_FLOAT_SUB:
      case CPUI_FLOAT_MULT:
      case CPUI_FLOAT_DIV:
        if (this.exceedsPrecision(op))
          return false;
        // fallthru
      case CPUI_COPY:
      case CPUI_FLOAT_CEIL:
      case CPUI_FLOAT_FLOOR:
      case CPUI_FLOAT_ROUND:
      case CPUI_FLOAT_NEG:
      case CPUI_FLOAT_ABS:
      case CPUI_FLOAT_SQRT:
      case CPUI_MULTIEQUAL:
      {
        let rop: TransformOp | null = rvn.getDef();
        if (rop === null) {
          rop = this.newOpReplace(op.numInput(), op.code(), op);
          this.opSetOutput(rop, rvn);
        }
        for (let i = 0; i < op.numInput(); ++i) {
          let newvar: TransformVar | null = rop.getIn(i);
          if (newvar === null) {
            newvar = this.setReplacement(op.getIn(i)!);
            if (newvar === null)
              return false;
            this.opSetInput(rop, newvar, i);
          }
        }
        return true;
      }
      case CPUI_FLOAT_INT2FLOAT:
      {
        const vn: Varnode = op.getIn(0)!;
        if (!vn.isConstant() && vn.isFree())
          return false;
        const rop: TransformOp = this.newOpReplace(1, CPUI_FLOAT_INT2FLOAT, op);
        this.opSetOutput(rop, rvn);
        const newvar: TransformVar = this.getPreexistingVarnode(vn);
        this.opSetInput(rop, newvar, 0);
        return true;
      }
      case CPUI_FLOAT_FLOAT2FLOAT:
      {
        const vn: Varnode = op.getIn(0)!;
        let newvar: TransformVar | null;
        let opc: OpCode;
        if (vn.isConstant()) {
          opc = CPUI_COPY;
          if (vn.getSize() === this.precision)
            newvar = this.newConstant(this.precision, 0, vn.getOffset());
          else {
            newvar = this.setReplacement(vn);	// Convert constant to precision size
            if (newvar === null)
              return false;			// Unsupported float format
          }
        }
        else {
          if (vn.isFree()) return false;
          opc = (vn.getSize() === this.precision) ? CPUI_COPY : CPUI_FLOAT_FLOAT2FLOAT;
          newvar = this.getPreexistingVarnode(vn);
        }
        const rop: TransformOp = this.newOpReplace(1, opc, op);
        this.opSetOutput(rop, rvn);
        this.opSetInput(rop, newvar!, 0);
        return true;
      }
      default:
        break;			// Everything else we abort
    }

    return false;
  }

  // SubfloatFlow.processNextWork
  private processNextWork(): boolean {
    const rvn: TransformVar = this.worklist[this.worklist.length - 1];
    this.worklist.pop();

    if (!this.traceBackward(rvn)) return false;
    return this.traceForward(rvn);
  }

  // SubfloatFlow constructor
  constructor(f: Funcdata, root: Varnode, prec: number) {
    super(f);
    this.precision = prec;
    this.format = f.getArch().translate.getFloatFormat(prec);
    if (this.format === null)
      return;
    this.setReplacement(root);
  }

  // SubfloatFlow.preserveAddress
  preserveAddress(vn: Varnode, bitSize: number, lsbOffset: number): boolean {
    return vn.isInput();		// Only try to preserve address for input varnodes
  }

  // SubfloatFlow.doTrace
  doTrace(): boolean {
    if (this.format === null)
      return false;
    this.terminatorCount = 0;	// Have seen no terminators
    let retval: boolean = true;
    while (this.worklist.length > 0) {
      if (!this.processNextWork()) {
        retval = false;
        break;
      }
    }

    this.clearVarnodeMarks();

    if (!retval) return false;
    if (this.terminatorCount === 0) return false;	// Must see at least 1 terminator
    return true;
  }
}

// --- RuleSubfloatConvert ---

export class RuleSubfloatConvert extends Rule {
  constructor(g: string) {
    super(g, 0, "subfloat_convert");
  }

  clone(grouplist: ActionGroupList): Rule | null {
    if (!grouplist.contains(this.getGroup())) return null;
    return new RuleSubfloatConvert(this.getGroup());
  }

  getOpList(oplist: number[]): void {
    oplist.push(CPUI_FLOAT_FLOAT2FLOAT);
  }

  applyOp(op: PcodeOp, data: Funcdata): number {
    const invn: Varnode = op.getIn(0)!;
    const outvn: Varnode = op.getOut()!;
    const insize: number = invn.getSize();
    const outsize: number = outvn.getSize();
    if (outsize > insize) {
      const subflow = new SubfloatFlow(data, outvn, insize);
      if (!subflow.doTrace()) return 0;
      subflow.apply();
    }
    else {
      const subflow = new SubfloatFlow(data, invn, outsize);
      if (!subflow.doTrace()) return 0;
      subflow.apply();
    }
    return 1;
  }
}

// --- LaneDivide ---

export class LaneDivide extends TransformManager {
  private description: LaneDescription;
  private workList: WorkNode[] = [];
  private allowSubpieceTerminator: boolean;

  // LaneDivide.setReplacement
  private setReplacement(vn: Varnode, numLanes: number, skipLanes: number): TransformVar[] | null {
    if (vn.isMark())		// Already seen before
      return this.getSplit(vn, this.description, numLanes, skipLanes);

    if (vn.isConstant()) {
      return this.newSplit(vn, this.description, numLanes, skipLanes);
    }

    if (vn.isTypeLock()) {
      const meta: type_metatype = vn.getType().getMetatype();
      if (meta > TYPE_ARRAY)
        return null;		// Don't split a primitive type
      if (meta === TYPE_STRUCT || meta === TYPE_UNION)
        return null;
    }

    vn.setMark();
    const res: TransformVar[] = this.newSplit(vn, this.description, numLanes, skipLanes);
    if (!vn.isFree()) {
      this.workList.push({ lanes: res, numLanes: numLanes, skipLanes: skipLanes });
    }
    return res;
  }

  // LaneDivide.buildUnaryOp
  private buildUnaryOp(opc: OpCode, op: PcodeOp, inVars: TransformVar[], outVars: TransformVar[], numLanes: number): void {
    for (let i = 0; i < numLanes; ++i) {
      const rop: TransformOp = this.newOpReplace(1, opc, op);
      this.opSetOutput(rop, outVars[i]);
      this.opSetInput(rop, inVars[i], 0);
    }
  }

  // LaneDivide.buildBinaryOp
  private buildBinaryOp(opc: OpCode, op: PcodeOp, in0Vars: TransformVar[], in1Vars: TransformVar[],
                         outVars: TransformVar[], numLanes: number): void {
    for (let i = 0; i < numLanes; ++i) {
      const rop: TransformOp = this.newOpReplace(2, opc, op);
      this.opSetOutput(rop, outVars[i]);
      this.opSetInput(rop, in0Vars[i], 0);
      this.opSetInput(rop, in1Vars[i], 1);
    }
  }

  // LaneDivide.buildPiece
  private buildPiece(op: PcodeOp, outVars: TransformVar[], numLanes: number, skipLanes: number): boolean {
    let highLanes: number, highSkip: number;
    let lowLanes: number, lowSkip: number;
    const highVn: Varnode = op.getIn(0)!;
    const lowVn: Varnode = op.getIn(1)!;

    const highRes = this.description.restriction(numLanes, skipLanes, lowVn.getSize(), highVn.getSize());
    if (!highRes.result)
      return false;
    highLanes = highRes.resNumLanes;
    highSkip = highRes.resSkipLanes;
    const lowRes = this.description.restriction(numLanes, skipLanes, 0, lowVn.getSize());
    if (!lowRes.result)
      return false;
    lowLanes = lowRes.resNumLanes;
    lowSkip = lowRes.resSkipLanes;
    if (highLanes === 1) {
      const highRvn: TransformVar = this.getPreexistingVarnode(highVn);
      const rop: TransformOp = this.newOpReplace(1, CPUI_COPY, op);
      this.opSetInput(rop, highRvn, 0);
      this.opSetOutput(rop, outVars[numLanes - 1]);
    }
    else {	// Multi-lane high
      const highRvn: TransformVar[] | null = this.setReplacement(highVn, highLanes, highSkip);
      if (highRvn === null) return false;
      const outHighStart: number = numLanes - highLanes;
      for (let i = 0; i < highLanes; ++i) {
        const rop: TransformOp = this.newOpReplace(1, CPUI_COPY, op);
        this.opSetInput(rop, highRvn[i], 0);
        this.opSetOutput(rop, outVars[outHighStart + i]);
      }
    }
    if (lowLanes === 1) {
      const lowRvn: TransformVar = this.getPreexistingVarnode(lowVn);
      const rop: TransformOp = this.newOpReplace(1, CPUI_COPY, op);
      this.opSetInput(rop, lowRvn, 0);
      this.opSetOutput(rop, outVars[0]);
    }
    else {	// Multi-lane low
      const lowRvn: TransformVar[] | null = this.setReplacement(lowVn, lowLanes, lowSkip);
      if (lowRvn === null) return false;
      for (let i = 0; i < lowLanes; ++i) {
        const rop: TransformOp = this.newOpReplace(1, CPUI_COPY, op);
        this.opSetInput(rop, lowRvn[i], 0);
        this.opSetOutput(rop, outVars[i]);
      }
    }
    return true;
  }

  // LaneDivide.buildMultiequal
  private buildMultiequal(op: PcodeOp, outVars: TransformVar[], numLanes: number, skipLanes: number): boolean {
    const inVarSets: TransformVar[][] = [];
    const numInput: number = op.numInput();
    for (let i = 0; i < numInput; ++i) {
      const inVn: TransformVar[] | null = this.setReplacement(op.getIn(i)!, numLanes, skipLanes);
      if (inVn === null) return false;
      inVarSets.push(inVn);
    }
    for (let i = 0; i < numLanes; ++i) {
      const rop: TransformOp = this.newOpReplace(numInput, CPUI_MULTIEQUAL, op);
      this.opSetOutput(rop, outVars[i]);
      for (let j = 0; j < numInput; ++j)
        this.opSetInput(rop, inVarSets[j][i], j);
    }
    return true;
  }

  // LaneDivide.buildIndirect
  private buildIndirect(op: PcodeOp, outVars: TransformVar[], numLanes: number, skipLanes: number): boolean {
    const inVn: TransformVar[] | null = this.setReplacement(op.getIn(0)!, numLanes, skipLanes);
    if (inVn === null) return false;
    for (let i = 0; i < numLanes; ++i) {
      const rop: TransformOp = this.newOpReplace(2, CPUI_INDIRECT, op);
      this.opSetOutput(rop, outVars[i]);
      this.opSetInput(rop, inVn[i], 0);
      this.opSetInput(rop, this.newIop(op.getIn(1)!), 1);
      rop.inheritIndirect(op);
    }
    return true;
  }

  // LaneDivide.buildStore
  private buildStore(op: PcodeOp, numLanes: number, skipLanes: number): boolean {
    const inVars: TransformVar[] | null = this.setReplacement(op.getIn(2)!, numLanes, skipLanes);
    if (inVars === null) return false;
    const spaceConst: bigint = op.getIn(0)!.getOffset();
    const spaceConstSize: number = op.getIn(0)!.getSize();
    const spc: AddrSpace = op.getIn(0)!.getSpaceFromConst();	// Address space being stored to
    const origPtr: Varnode = op.getIn(1)!;
    if (origPtr.isFree()) {
      if (!origPtr.isConstant()) return false;
    }
    const basePtr: TransformVar = this.getPreexistingVarnode(origPtr);
    const ptrSize: number = origPtr.getSize();
    // Order lanes by pointer offset
    let bytePos: bigint = 0n;	// Smallest pointer offset
    for (let count = 0; count < numLanes; ++count) {
      const i: number = spc.isBigEndian() ? numLanes - 1 - count : count;
      const ropStore: TransformOp = this.newOpReplace(3, CPUI_STORE, op);

      // Construct the pointer
      let ptrVn: TransformVar;
      if (bytePos === 0n)
        ptrVn = basePtr;
      else {
        ptrVn = this.newUnique(ptrSize);
        const addOp: TransformOp = this.newOp(2, CPUI_INT_ADD, ropStore);
        this.opSetOutput(addOp, ptrVn);
        this.opSetInput(addOp, basePtr, 0);
        this.opSetInput(addOp, this.newConstant(ptrSize, 0, bytePos), 1);
      }

      this.opSetInput(ropStore, this.newConstant(spaceConstSize, 0, spaceConst), 0);
      this.opSetInput(ropStore, ptrVn, 1);
      this.opSetInput(ropStore, inVars[i], 2);
      bytePos += BigInt(this.description.getSize(skipLanes + i));
    }
    return true;
  }

  // LaneDivide.buildLoad
  private buildLoad(op: PcodeOp, outVars: TransformVar[], numLanes: number, skipLanes: number): boolean {
    const spaceConst: bigint = op.getIn(0)!.getOffset();
    const spaceConstSize: number = op.getIn(0)!.getSize();
    const spc: AddrSpace = op.getIn(0)!.getSpaceFromConst();	// Address space being loaded from
    const origPtr: Varnode = op.getIn(1)!;
    if (origPtr.isFree()) {
      if (!origPtr.isConstant()) return false;
    }
    const basePtr: TransformVar = this.getPreexistingVarnode(origPtr);
    const ptrSize: number = origPtr.getSize();
    // Order lanes by pointer offset
    let bytePos: bigint = 0n;	// Smallest pointer offset
    for (let count = 0; count < numLanes; ++count) {
      const ropLoad: TransformOp = this.newOpReplace(2, CPUI_LOAD, op);
      const i: number = spc.isBigEndian() ? numLanes - 1 - count : count;

      // Construct the pointer
      let ptrVn: TransformVar;
      if (bytePos === 0n)
        ptrVn = basePtr;
      else {
        ptrVn = this.newUnique(ptrSize);
        const addOp: TransformOp = this.newOp(2, CPUI_INT_ADD, ropLoad);
        this.opSetOutput(addOp, ptrVn);
        this.opSetInput(addOp, basePtr, 0);
        this.opSetInput(addOp, this.newConstant(ptrSize, 0, bytePos), 1);
      }

      this.opSetInput(ropLoad, this.newConstant(spaceConstSize, 0, spaceConst), 0);
      this.opSetInput(ropLoad, ptrVn, 1);
      this.opSetOutput(ropLoad, outVars[i]);
      bytePos += BigInt(this.description.getSize(skipLanes + i));
    }
    return true;
  }

  // LaneDivide.buildRightShift
  private buildRightShift(op: PcodeOp, outVars: TransformVar[], numLanes: number, skipLanes: number): boolean {
    if (!op.getIn(1)!.isConstant()) return false;
    let shiftSize: number = Number(op.getIn(1)!.getOffset());
    if ((shiftSize & 7) !== 0) return false;		// Not a multiple of 8
    shiftSize = Math.floor(shiftSize / 8);
    const startPos: number = shiftSize + this.description.getPosition(skipLanes);
    const startLane: number = this.description.getBoundary(startPos);
    if (startLane < 0) return false;		// Shift does not end on a lane boundary
    let srcLane: number = startLane;
    let destLane: number = skipLanes;
    while (srcLane - skipLanes < numLanes) {
      if (this.description.getSize(srcLane) !== this.description.getSize(destLane)) return false;
      srcLane += 1;
      destLane += 1;
    }
    const inVars: TransformVar[] | null = this.setReplacement(op.getIn(0)!, numLanes, skipLanes);
    if (inVars === null) return false;
    this.buildUnaryOp(CPUI_COPY, op, inVars.slice(startLane - skipLanes), outVars, numLanes - (startLane - skipLanes));

    for (let zeroLane = numLanes - (startLane - skipLanes); zeroLane < numLanes; ++zeroLane) {
      const rop: TransformOp = this.newOpReplace(1, CPUI_COPY, op);
      this.opSetOutput(rop, outVars[zeroLane]);
      this.opSetInput(rop, this.newConstant(this.description.getSize(zeroLane), 0, 0n), 0);
    }
    return true;
  }

  // LaneDivide.buildLeftShift
  private buildLeftShift(op: PcodeOp, outVars: TransformVar[], numLanes: number, skipLanes: number): boolean {
    if (!op.getIn(1)!.isConstant()) return false;
    let shiftSize: number = Number(op.getIn(1)!.getOffset());
    if ((shiftSize & 7) !== 0) return false;		// Not a multiple of 8
    shiftSize = Math.floor(shiftSize / 8);
    const startPos: number = shiftSize + this.description.getPosition(skipLanes);
    const startLane: number = this.description.getBoundary(startPos);
    if (startLane < 0) return false;		// Shift does not end on a lane boundary
    let destLane: number = startLane;
    let srcLane: number = skipLanes;
    while (destLane - skipLanes < numLanes) {
      if (this.description.getSize(srcLane) !== this.description.getSize(destLane)) return false;
      srcLane += 1;
      destLane += 1;
    }
    const inVars: TransformVar[] | null = this.setReplacement(op.getIn(0)!, numLanes, skipLanes);
    if (inVars === null) return false;
    for (let zeroLane = 0; zeroLane < (startLane - skipLanes); ++zeroLane) {
      const rop: TransformOp = this.newOpReplace(1, CPUI_COPY, op);
      this.opSetOutput(rop, outVars[zeroLane]);
      this.opSetInput(rop, this.newConstant(this.description.getSize(zeroLane), 0, 0n), 0);
    }
    this.buildUnaryOp(CPUI_COPY, op, inVars, outVars.slice(startLane - skipLanes), numLanes - (startLane - skipLanes));
    return true;
  }

  // LaneDivide.buildZext
  private buildZext(op: PcodeOp, outVars: TransformVar[], numLanes: number, skipLanes: number): boolean {
    const invn: Varnode = op.getIn(0)!;
    const inRes = this.description.restriction(numLanes, skipLanes, 0, invn.getSize());
    if (!inRes.result) {
      return false;
    }
    const inLanes = inRes.resNumLanes;
    const inSkip = inRes.resSkipLanes;
    // inSkip should always come back as equal to skipLanes
    if (inLanes === 1) {
      const rop: TransformOp = this.newOpReplace(1, CPUI_COPY, op);
      const inVar: TransformVar = this.getPreexistingVarnode(invn);
      this.opSetInput(rop, inVar, 0);
      this.opSetOutput(rop, outVars[0]);
    }
    else {
      const inRvn: TransformVar[] | null = this.setReplacement(invn, inLanes, inSkip);
      if (inRvn === null) return false;
      for (let i = 0; i < inLanes; ++i) {
        const rop: TransformOp = this.newOpReplace(1, CPUI_COPY, op);
        this.opSetInput(rop, inRvn[i], 0);
        this.opSetOutput(rop, outVars[i]);
      }
    }
    for (let i = 0; i < numLanes - inLanes; ++i) {			// Write 0 constants to remaining lanes
      const rop: TransformOp = this.newOpReplace(1, CPUI_COPY, op);
      this.opSetInput(rop, this.newConstant(this.description.getSize(skipLanes + inLanes + i), 0, 0n), 0);
      this.opSetOutput(rop, outVars[inLanes + i]);
    }
    return true;
  }

  // LaneDivide.traceForward
  private traceForward(rvn: TransformVar[], numLanes: number, skipLanes: number): boolean {
    const origvn: Varnode = rvn[0].getOriginal()!;
    const enditer = origvn.endDescend();
    for (let it = origvn.beginDescend(); it < enditer; it++) {
      const op: PcodeOp = origvn.getDescend(it);
      const outvn: Varnode | null = op.getOut()!;
      if ((outvn !== null) && (outvn.isMark()))
        continue;
      switch (op.code()) {
        case CPUI_SUBPIECE:
        {
          const bytePos: number = Number(op.getIn(1)!.getOffset());
          const outRes = this.description.restriction(numLanes, skipLanes, bytePos, outvn!.getSize());
          if (!outRes.result) {
            if (this.allowSubpieceTerminator) {
              const laneIndex: number = this.description.getBoundary(bytePos);
              if (laneIndex < 0 || laneIndex >= this.description.getNumLanes())	// Does piece start on lane boundary?
                return false;
              if (this.description.getSize(laneIndex) <= outvn!.getSize())		// Is the piece smaller than a lane?
                return false;
              // Treat SUBPIECE as terminating
              const rop: TransformOp = this.newPreexistingOp(2, CPUI_SUBPIECE, op);
              this.opSetInput(rop, rvn[laneIndex - skipLanes], 0);
              this.opSetInput(rop, this.newConstant(4, 0, 0n), 1);
              break;
            }
            return false;
          }
          const outLanes = outRes.resNumLanes;
          const outSkip = outRes.resSkipLanes;
          if (outLanes === 1) {
            const rop: TransformOp = this.newPreexistingOp(1, CPUI_COPY, op);
            this.opSetInput(rop, rvn[outSkip - skipLanes], 0);
          }
          else {
            const outRvn: TransformVar[] | null = this.setReplacement(outvn!, outLanes, outSkip);
            if (outRvn === null) return false;
            // Don't create the placeholder ops, let traceBackward make them
          }
          break;
        }
        case CPUI_PIECE:
        {
          const bytePos: number = (op.getIn(0)! === origvn) ? op.getIn(1)!.getSize() : 0;
          const outRes = { numLanes: 0, skipLanes: 0 };
          const _extRes = this.description.extension(numLanes, skipLanes, bytePos, outvn!.getSize());
          if (!_extRes.result)
            return false;
          const outRvn: TransformVar[] | null = this.setReplacement(outvn!, _extRes.resNumLanes, _extRes.resSkipLanes);
          if (outRvn === null) return false;
          // Don't create the placeholder ops, let traceBackward make them
          break;
        }
        case CPUI_COPY:
        case CPUI_INT_NEGATE:
        case CPUI_INT_AND:
        case CPUI_INT_OR:
        case CPUI_INT_XOR:
        case CPUI_MULTIEQUAL:
        case CPUI_INDIRECT:
        {
          const outRvn: TransformVar[] | null = this.setReplacement(outvn!, numLanes, skipLanes);
          if (outRvn === null) return false;
          // Don't create the placeholder ops, let traceBackward make them
          break;
        }
        case CPUI_INT_RIGHT:
        {
          if (!op.getIn(1)!.isConstant()) return false;	// Trace must come through op->getIn(0)
          const outRvn: TransformVar[] | null = this.setReplacement(outvn!, numLanes, skipLanes);
          if (outRvn === null) return false;
          // Don't create the placeholder ops, let traceBackward make them
          break;
        }
        case CPUI_STORE:
          if (op.getIn(2) !== origvn) return false;	// Can only propagate through value being stored
          if (!this.buildStore(op, numLanes, skipLanes))
            return false;
          break;
        default:
          return false;
      }
    }
    return true;
  }

  // LaneDivide.traceBackward
  private traceBackward(rvn: TransformVar[], numLanes: number, skipLanes: number): boolean {
    const op: PcodeOp | null = rvn[0].getOriginal()!.getDef();
    if (op === null) return true; // If vn is input

    switch (op.code()) {
      case CPUI_INT_NEGATE:
      case CPUI_COPY:
      {
        const inVars: TransformVar[] | null = this.setReplacement(op.getIn(0)!, numLanes, skipLanes);
        if (inVars === null) return false;
        this.buildUnaryOp(op.code(), op, inVars, rvn, numLanes);
        break;
      }
      case CPUI_INT_AND:
      case CPUI_INT_OR:
      case CPUI_INT_XOR:
      {
        const in0Vars: TransformVar[] | null = this.setReplacement(op.getIn(0)!, numLanes, skipLanes);
        if (in0Vars === null) return false;
        const in1Vars: TransformVar[] | null = this.setReplacement(op.getIn(1)!, numLanes, skipLanes);
        if (in1Vars === null) return false;
        this.buildBinaryOp(op.code(), op, in0Vars, in1Vars, rvn, numLanes);
        break;
      }
      case CPUI_MULTIEQUAL:
        if (!this.buildMultiequal(op, rvn, numLanes, skipLanes))
          return false;
        break;
      case CPUI_INDIRECT:
        if (!this.buildIndirect(op, rvn, numLanes, skipLanes))
          return false;
        break;
      case CPUI_SUBPIECE:
      {
        const inVn: Varnode = op.getIn(0)!;
        const bytePos: number = Number(op.getIn(1)!.getOffset());
        const inRes = this.description.extension(numLanes, skipLanes, bytePos, inVn.getSize());
        if (!inRes.result)
          return false;
        const inLanes = inRes.resNumLanes;
        const inSkip = inRes.resSkipLanes;
        const inVars: TransformVar[] | null = this.setReplacement(inVn, inLanes, inSkip);
        if (inVars === null) return false;
        this.buildUnaryOp(CPUI_COPY, op, inVars.slice(skipLanes - inSkip), rvn, numLanes);

        break;
      }
      case CPUI_PIECE:
        if (!this.buildPiece(op, rvn, numLanes, skipLanes))
          return false;
        break;
      case CPUI_LOAD:
        if (!this.buildLoad(op, rvn, numLanes, skipLanes))
          return false;
        break;
      case CPUI_INT_RIGHT:
        if (!this.buildRightShift(op, rvn, numLanes, skipLanes))
          return false;
        break;
      case CPUI_INT_LEFT:
        if (!this.buildLeftShift(op, rvn, numLanes, skipLanes))
          return false;
        break;
      case CPUI_INT_ZEXT:
        if (!this.buildZext(op, rvn, numLanes, skipLanes))
          return false;
        break;
      default:
        return false;
    }
    return true;
  }

  // LaneDivide.processNextWork
  private processNextWork(): boolean {
    const work: WorkNode = this.workList[this.workList.length - 1];
    const rvn: TransformVar[] = work.lanes;
    const numLanes: number = work.numLanes;
    const skipLanes: number = work.skipLanes;

    this.workList.pop();

    if (!this.traceBackward(rvn, numLanes, skipLanes)) return false;
    return this.traceForward(rvn, numLanes, skipLanes);
  }

  // LaneDivide constructor
  constructor(f: Funcdata, root: Varnode, desc: LaneDescription, allowDowncast: boolean) {
    super(f);
    this.description = desc;
    this.allowSubpieceTerminator = allowDowncast;
    this.setReplacement(root, desc.getNumLanes(), 0);
  }

  // LaneDivide.doTrace
  doTrace(): boolean {
    if (this.workList.length === 0)
      return false;		// Nothing to do
    let retval: boolean = true;
    while (this.workList.length > 0) {	// Process the work list until its done
      if (!this.processNextWork()) {
        retval = false;
        break;
      }
    }

    this.clearVarnodeMarks();
    if (!retval) return false;
    return true;
  }
}

// --- WorkNode interface for LaneDivide ---

interface WorkNode {
  lanes: TransformVar[];
  numLanes: number;
  skipLanes: number;
}
