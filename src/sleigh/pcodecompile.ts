/**
 * @file pcodecompile.ts
 * @description P-code compilation infrastructure used by SLEIGH.
 *
 * Translated from Ghidra's pcodecompile.hh / pcodecompile.cc.
 *
 * PcodeCompile takes semantic expressions (VarnodeTpl, OpTpl, etc.) and
 * produces ConstructTpl objects. ExprTree represents a flattened expression
 * tree of p-code operations, and Location tracks source file positions.
 */

import type { int4, uint4, uintb } from '../core/types.js';
import { OpCode } from '../core/opcodes.js';
import { AddrSpace } from '../core/space.js';
import {
  ConstTpl,
  VarnodeTpl,
  OpTpl,
  ConstructTpl,
  LABELBUILD,
} from './semantics.js';
import { SleighError } from './context.js';
import type { const_type, v_field } from './semantics.js';

// Forward declarations for types from not-yet-written files
type SleighSymbol = any;
type LabelSymbol = any;
type VarnodeSymbol = any;
type UserOpSymbol = any;
type SpecificSymbol = any;

// ==================================================================
// Location
// ==================================================================

/**
 * A location in a source file, used for error reporting during SLEIGH compilation.
 */
export class Location {
  private filename: string;
  private lineno: int4;

  constructor();
  constructor(fname: string, line: int4);
  constructor(fname?: string, line?: int4) {
    this.filename = fname ?? '';
    this.lineno = line ?? 0;
  }

  getFilename(): string {
    return this.filename;
  }

  getLineno(): int4 {
    return this.lineno;
  }

  format(): string {
    return `${this.filename}:${this.lineno}`;
  }
}

// ==================================================================
// StarQuality
// ==================================================================

/**
 * Qualification for a dereferenced pointer in SLEIGH.
 * Holds the space constant and the size of the pointed-to object.
 */
export class StarQuality {
  id: ConstTpl = new ConstTpl();
  size: uint4 = 0;
}

// ==================================================================
// ExprTree
// ==================================================================

/**
 * A flattened expression tree of p-code operations.
 *
 * ExprTree holds a list of OpTpl operations that make up the expression,
 * and a VarnodeTpl representing the output. If the last op has an output,
 * outvn is a COPY of that varnode.
 */
export class ExprTree {
  /** Flattened ops making up the expression */
  ops: OpTpl[] | null;
  /** Output varnode of the expression */
  outvn: VarnodeTpl | null;

  constructor();
  constructor(vn: VarnodeTpl);
  constructor(op: OpTpl);
  constructor(arg?: VarnodeTpl | OpTpl) {
    if (arg === undefined) {
      // Default constructor
      this.ops = null;
      this.outvn = null;
      return;
    }

    if (arg instanceof VarnodeTpl) {
      // ExprTree(VarnodeTpl *vn)
      this.outvn = arg;
      this.ops = [];
      return;
    }

    // ExprTree(OpTpl *op)
    const op = arg;
    this.ops = [];
    this.ops.push(op);
    if (op.getOut() !== null) {
      this.outvn = new VarnodeTpl(op.getOut()!);
    } else {
      this.outvn = null;
    }
  }

  /**
   * Force the output of the expression to be newout.
   * If the original output is named, this requires an extra COPY op.
   */
  setOutput(newout: VarnodeTpl): void {
    if (this.outvn === null) {
      throw new SleighError('Expression has no output');
    }
    if (this.outvn.isUnnamed()) {
      // outvn was unnamed - reuse the last op's output slot
      const op = this.ops![this.ops!.length - 1];
      op.clearOutput();
      op.setOutput(newout);
    } else {
      // Need an extra COPY op
      const op = new OpTpl(OpCode.CPUI_COPY);
      op.addInput(this.outvn);
      op.setOutput(newout);
      this.ops!.push(op);
    }
    this.outvn = new VarnodeTpl(newout);
  }

  getOut(): VarnodeTpl | null {
    return this.outvn;
  }

  getSize(): ConstTpl {
    return this.outvn!.getSize();
  }

  /**
   * Create op expression with an entire list of expression inputs.
   * Collects ops from all param expressions, adds their outputs as inputs to op,
   * then appends op at the end.
   */
  static appendParams(op: OpTpl, param: ExprTree[]): OpTpl[] {
    const res: OpTpl[] = [];

    for (let i = 0; i < param.length; ++i) {
      // Collect all ops from this param expression
      res.push(...param[i].ops!);
      param[i].ops!.length = 0;
      op.addInput(param[i].outvn!);
      param[i].outvn = null;
      // param[i] would be deleted in C++; GC handles it here
    }
    res.push(op);
    // param array would be deleted in C++; GC handles it here
    return res;
  }

  /**
   * Grab the op vector and discard the output expression.
   */
  static toVector(expr: ExprTree): OpTpl[] {
    const res = expr.ops!;
    expr.ops = null;
    // expr would be deleted in C++; GC handles it here
    return res;
  }
}

// ==================================================================
// PcodeCompile
// ==================================================================

/**
 * Abstract base class for compiling p-code from SLEIGH semantic expressions.
 *
 * PcodeCompile provides the infrastructure for building p-code instruction
 * templates (ConstructTpl) from SLEIGH semantic actions. It creates
 * ExprTree objects from operations and varnodes, manages temporary variables,
 * labels, and performs size propagation.
 */
export abstract class PcodeCompile {
  private defaultspace: AddrSpace | null;
  private constantspace: AddrSpace | null;
  private uniqspace: AddrSpace | null;
  private local_labelcount: uint4;
  private enforceLocalKey: boolean;

  protected abstract allocateTemp(): uint4;
  protected abstract addSymbol(sym: SleighSymbol): void;

  constructor() {
    this.defaultspace = null;
    this.constantspace = null;
    this.uniqspace = null;
    this.local_labelcount = 0;
    this.enforceLocalKey = false;
  }

  abstract getLocation(sym: SleighSymbol): Location | null;
  abstract reportError(loc: Location | null, msg: string): void;
  abstract reportWarning(loc: Location | null, msg: string): void;

  resetLabelCount(): void {
    this.local_labelcount = 0;
  }

  setDefaultSpace(spc: AddrSpace): void {
    this.defaultspace = spc;
  }

  setConstantSpace(spc: AddrSpace): void {
    this.constantspace = spc;
  }

  setUniqueSpace(spc: AddrSpace): void {
    this.uniqspace = spc;
  }

  setEnforceLocalKey(val: boolean): void {
    this.enforceLocalKey = val;
  }

  getDefaultSpace(): AddrSpace | null {
    return this.defaultspace;
  }

  getConstantSpace(): AddrSpace | null {
    return this.constantspace;
  }

  // ------------------------------------------------------------------
  // Build helpers
  // ------------------------------------------------------------------

  /** Build a temporary variable (with zero size). */
  buildTemporary(): VarnodeTpl {
    const res = new VarnodeTpl(
      new ConstTpl(this.uniqspace!),
      new ConstTpl(ConstTpl.real, BigInt(this.allocateTemp())),
      new ConstTpl(ConstTpl.real, 0n),
    );
    res.setUnnamed(true);
    return res;
  }

  /** Create a label symbol. */
  defineLabel(name: string): LabelSymbol {
    const labsym = { _name: name, _index: this.local_labelcount++, _isplaced: false, _refcount: 0,
      getName(): string { return this._name; },
      getIndex(): number { return this._index; },
      isPlaced(): boolean { return this._isplaced; },
      setPlaced(): void { this._isplaced = true; },
      incrementRefCount(): void { this._refcount += 1; },
      getRefCount(): number { return this._refcount; },
    };
    this.addSymbol(labsym as any);
    return labsym;
  }

  /** Create placeholder OpTpl for a label. */
  placeLabel(labsym: LabelSymbol): OpTpl[] {
    if ((labsym as any).isPlaced()) {
      this.reportError(
        this.getLocation(labsym),
        "Label '" + (labsym as any).getName() + "' is placed more than once",
      );
    }
    (labsym as any).setPlaced();
    const res: OpTpl[] = [];
    const op = new OpTpl(LABELBUILD);
    const idvn = new VarnodeTpl(
      new ConstTpl(this.constantspace!),
      new ConstTpl(ConstTpl.real, BigInt((labsym as any).getIndex())),
      new ConstTpl(ConstTpl.real, 4n),
    );
    op.addInput(idvn);
    res.push(op);
    return res;
  }

  /**
   * Assign a new named output to an expression.
   */
  newOutput(usesLocalKey: boolean, rhs: ExprTree, varname: string, size: uint4 = 0): OpTpl[] {
    const tmpvn = this.buildTemporary();
    if (size !== 0) {
      tmpvn.setSize(new ConstTpl(ConstTpl.real, BigInt(size)));
    } else if (
      rhs.getSize().getType() === (ConstTpl.real as const_type) &&
      rhs.getSize().getReal() !== 0n
    ) {
      tmpvn.setSize(rhs.getSize());
    }
    rhs.setOutput(tmpvn);
    // Create new VarnodeSymbol - forward-declared, create as plain object
    const sym = {
      _name: varname,
      getName(): string { return this._name; },
    };
    this.addSymbol(sym as any);
    if (!usesLocalKey && this.enforceLocalKey) {
      this.reportError(
        this.getLocation(sym as any),
        "Must use 'local' keyword to define symbol '" + varname + "'",
      );
    }
    return ExprTree.toVector(rhs);
  }

  /**
   * Create a new temporary symbol without generating any pcode.
   */
  newLocalDefinition(varname: string, size: uint4 = 0): void {
    const sym = {
      _name: varname,
      getName(): string { return this._name; },
    };
    this.addSymbol(sym as any);
  }

  // ------------------------------------------------------------------
  // Expression creation (unary)
  // ------------------------------------------------------------------

  /** Create a new expression with a unary operation. */
  createOp(opc: OpCode, vn: ExprTree): ExprTree;
  /** Create a new expression with a binary operation. */
  createOp(opc: OpCode, vn1: ExprTree, vn2: ExprTree): ExprTree;
  createOp(opc: OpCode, vn1: ExprTree, vn2?: ExprTree): ExprTree {
    if (vn2 === undefined) {
      // Unary case
      const outvn = this.buildTemporary();
      const op = new OpTpl(opc);
      op.addInput(vn1.outvn!);
      op.setOutput(outvn);
      vn1.ops!.push(op);
      vn1.outvn = new VarnodeTpl(outvn);
      return vn1;
    }

    // Binary case
    const outvn = this.buildTemporary();
    vn1.ops!.push(...vn2.ops!);
    vn2.ops!.length = 0;
    const op = new OpTpl(opc);
    op.addInput(vn1.outvn!);
    op.addInput(vn2.outvn!);
    vn2.outvn = null;
    op.setOutput(outvn);
    vn1.ops!.push(op);
    vn1.outvn = new VarnodeTpl(outvn);
    // vn2 deleted in C++; GC handles
    return vn1;
  }

  /** Create an op with explicit output and two inputs. */
  createOpOut(outvn: VarnodeTpl, opc: OpCode, vn1: ExprTree, vn2: ExprTree): ExprTree {
    vn1.ops!.push(...vn2.ops!);
    vn2.ops!.length = 0;
    const op = new OpTpl(opc);
    op.addInput(vn1.outvn!);
    op.addInput(vn2.outvn!);
    vn2.outvn = null;
    op.setOutput(outvn);
    vn1.ops!.push(op);
    vn1.outvn = new VarnodeTpl(outvn);
    // vn2 deleted in C++; GC handles
    return vn1;
  }

  /** Create an op with explicit output and one input. */
  createOpOutUnary(outvn: VarnodeTpl, opc: OpCode, vn: ExprTree): ExprTree {
    const op = new OpTpl(opc);
    op.addInput(vn.outvn!);
    op.setOutput(outvn);
    vn.ops!.push(op);
    vn.outvn = new VarnodeTpl(outvn);
    return vn;
  }

  // ------------------------------------------------------------------
  // No-output operations
  // ------------------------------------------------------------------

  /** Create operation with no output (unary). */
  createOpNoOut(opc: OpCode, vn: ExprTree): OpTpl[];
  /** Create operation with no output (binary). */
  createOpNoOut(opc: OpCode, vn1: ExprTree, vn2: ExprTree): OpTpl[];
  createOpNoOut(opc: OpCode, vn1: ExprTree, vn2?: ExprTree): OpTpl[] {
    if (vn2 === undefined) {
      // Unary no-output
      const op = new OpTpl(opc);
      op.addInput(vn1.outvn!);
      vn1.outvn = null;
      const res = vn1.ops!;
      vn1.ops = null;
      // vn1 deleted in C++; GC handles
      res.push(op);
      return res;
    }

    // Binary no-output
    const res = vn1.ops!;
    vn1.ops = null;
    res.push(...vn2.ops!);
    vn2.ops!.length = 0;
    const op = new OpTpl(opc);
    op.addInput(vn1.outvn!);
    vn1.outvn = null;
    op.addInput(vn2.outvn!);
    vn2.outvn = null;
    res.push(op);
    // vn1, vn2 deleted in C++; GC handles
    return res;
  }

  /** Create an operation with a single constant input and no output. */
  createOpConst(opc: OpCode, val: uintb): OpTpl[] {
    const vn = new VarnodeTpl(
      new ConstTpl(this.constantspace!),
      new ConstTpl(ConstTpl.real, val),
      new ConstTpl(ConstTpl.real, 4n),
    );
    const res: OpTpl[] = [];
    const op = new OpTpl(opc);
    op.addInput(vn);
    res.push(op);
    return res;
  }

  // ------------------------------------------------------------------
  // Load / Store
  // ------------------------------------------------------------------

  /** Create a load expression. */
  createLoad(qual: StarQuality, ptr: ExprTree): ExprTree {
    const outvn = this.buildTemporary();
    const op = new OpTpl(OpCode.CPUI_LOAD);
    const spcvn = new VarnodeTpl(
      new ConstTpl(this.constantspace!),
      qual.id,
      new ConstTpl(ConstTpl.real, 8n),
    );
    op.addInput(spcvn);
    op.addInput(ptr.outvn!);
    op.setOutput(outvn);
    ptr.ops!.push(op);
    if (qual.size > 0) {
      PcodeCompile.force_size(outvn, new ConstTpl(ConstTpl.real, BigInt(qual.size)), ptr.ops!);
    }
    ptr.outvn = new VarnodeTpl(outvn);
    // qual deleted in C++; GC handles
    return ptr;
  }

  /** Create a store operation. */
  createStore(qual: StarQuality, ptr: ExprTree, val: ExprTree): OpTpl[] {
    const res = ptr.ops!;
    ptr.ops = null;
    res.push(...val.ops!);
    val.ops!.length = 0;
    const op = new OpTpl(OpCode.CPUI_STORE);
    const spcvn = new VarnodeTpl(
      new ConstTpl(this.constantspace!),
      qual.id,
      new ConstTpl(ConstTpl.real, 8n),
    );
    op.addInput(spcvn);
    op.addInput(ptr.outvn!);
    op.addInput(val.outvn!);
    res.push(op);
    PcodeCompile.force_size(val.outvn!, new ConstTpl(ConstTpl.real, BigInt(qual.size)), res);
    ptr.outvn = null;
    val.outvn = null;
    // ptr, val, qual deleted in C++; GC handles
    return res;
  }

  // ------------------------------------------------------------------
  // User-defined operations
  // ------------------------------------------------------------------

  /** Create user-defined pcode op with output. */
  createUserOp(sym: UserOpSymbol, param: ExprTree[]): ExprTree {
    const outvn = this.buildTemporary();
    const res = new ExprTree();
    res.ops = this.createUserOpNoOut(sym, param);
    res.ops[res.ops.length - 1].setOutput(outvn);
    res.outvn = new VarnodeTpl(outvn);
    return res;
  }

  /** Create user-defined pcode op without output. */
  createUserOpNoOut(sym: UserOpSymbol, param: ExprTree[]): OpTpl[] {
    const op = new OpTpl(OpCode.CPUI_CALLOTHER);
    const vn = new VarnodeTpl(
      new ConstTpl(this.constantspace!),
      new ConstTpl(ConstTpl.real, BigInt((sym as any).getIndex())),
      new ConstTpl(ConstTpl.real, 4n),
    );
    op.addInput(vn);
    return ExprTree.appendParams(op, param);
  }

  /** Create a variadic operation expression. */
  createVariadic(opc: OpCode, param: ExprTree[]): ExprTree {
    const outvn = this.buildTemporary();
    const res = new ExprTree();
    const op = new OpTpl(opc);
    res.ops = ExprTree.appendParams(op, param);
    res.ops[res.ops.length - 1].setOutput(outvn);
    res.outvn = new VarnodeTpl(outvn);
    return res;
  }

  /**
   * Append an operation that combines the output of res with a constant.
   */
  appendOp(opc: OpCode, res: ExprTree, constval: uintb, constsz: int4): void {
    const op = new OpTpl(opc);
    const constvn = new VarnodeTpl(
      new ConstTpl(this.constantspace!),
      new ConstTpl(ConstTpl.real, constval),
      new ConstTpl(ConstTpl.real, BigInt(constsz)),
    );
    const outvn = this.buildTemporary();
    op.addInput(res.outvn!);
    op.addInput(constvn);
    op.setOutput(outvn);
    res.ops!.push(op);
    res.outvn = new VarnodeTpl(outvn);
  }

  // ------------------------------------------------------------------
  // Bit range operations
  // ------------------------------------------------------------------

  /**
   * Build a truncated form of basevn that matches the bitrange [bitoffset, numbits]
   * if possible using just ConstTpl mechanics, otherwise return null.
   */
  buildTruncatedVarnode(basevn: VarnodeTpl, bitoffset: uint4, numbits: uint4): VarnodeTpl | null {
    const byteoffset: uint4 = (bitoffset / 8) >>> 0; // Convert to byte units (integer division)
    const numbytes: uint4 = (numbits / 8) >>> 0;
    let fullsz: uintb = 0n;
    if (basevn.getSize().getType() === (ConstTpl.real as const_type)) {
      fullsz = basevn.getSize().getReal();
      if (fullsz === 0n) return null;
      if (byteoffset + numbytes > Number(fullsz)) {
        throw new SleighError('Requested bit range out of bounds');
      }
    }

    if ((bitoffset % 8) !== 0) return null;
    if ((numbits % 8) !== 0) return null;

    const offset_type = basevn.getOffset().getType();
    if (offset_type !== (ConstTpl.real as const_type) && offset_type !== (ConstTpl.handle as const_type)) {
      return null;
    }

    let specialoff: ConstTpl;
    if (offset_type === (ConstTpl.handle as const_type)) {
      // Little endian adjustment; big endian deferred until consistency check
      specialoff = new ConstTpl(
        ConstTpl.handle,
        basevn.getOffset().getHandleIndex(),
        ConstTpl.v_offset_plus as v_field,
        BigInt(byteoffset),
      );
    } else {
      if (basevn.getSize().getType() !== (ConstTpl.real as const_type)) {
        throw new SleighError('Could not construct requested bit range');
      }
      let plus: uintb;
      if (this.defaultspace!.isBigEndian()) {
        plus = fullsz - BigInt(byteoffset + numbytes);
      } else {
        plus = BigInt(byteoffset);
      }
      specialoff = new ConstTpl(ConstTpl.real, basevn.getOffset().getReal() + plus);
    }
    const res = new VarnodeTpl(
      basevn.getSpace(),
      specialoff,
      new ConstTpl(ConstTpl.real, BigInt(numbytes)),
    );
    return res;
  }

  /**
   * Create an expression assigning the rhs to a bitrange within a varnode.
   */
  assignBitRange(vn: VarnodeTpl, bitoffset: uint4, numbits: uint4, rhs: ExprTree): OpTpl[] {
    let errmsg = '';
    if (numbits === 0) {
      errmsg = 'Size of bitrange is zero';
    }
    const smallsize: uint4 = ((numbits + 7) / 8) >>> 0;
    const shiftneeded: boolean = bitoffset !== 0;
    let zextneeded = true;
    let mask: uintb = 2n;
    mask = ~(((mask << BigInt(numbits - 1)) - 1n) << BigInt(bitoffset));

    if (vn.getSize().getType() === (ConstTpl.real as const_type)) {
      let symsize: uint4 = Number(vn.getSize().getReal());
      if (symsize > 0) {
        zextneeded = symsize > smallsize;
      }
      symsize *= 8;
      if (bitoffset >= symsize || bitoffset + numbits > symsize) {
        errmsg = 'Assigned bitrange is bad';
      } else if (bitoffset === 0 && numbits === symsize) {
        errmsg = 'Assigning to bitrange is superfluous';
      }
    }

    if (errmsg.length > 0) {
      this.reportError(null, errmsg);
      // Passthru old expression
      const resops = rhs.ops!;
      rhs.ops = null;
      // rhs, vn deleted in C++; GC handles
      return resops;
    }

    // We know the size of the input
    PcodeCompile.force_size(rhs.outvn!, new ConstTpl(ConstTpl.real, BigInt(smallsize)), rhs.ops!);

    let res: ExprTree;
    let finalout = this.buildTruncatedVarnode(vn, bitoffset, numbits);
    if (finalout !== null) {
      // Don't keep the original Varnode object (deleted in C++)
      res = this.createOpOutUnary(finalout, OpCode.CPUI_COPY, rhs);
    } else {
      if (bitoffset + numbits > 64) {
        errmsg = 'Assigned bitrange extends past first 64 bits';
      }
      res = new ExprTree(vn);
      this.appendOp(OpCode.CPUI_INT_AND, res, mask, 0);
      if (zextneeded) {
        this.createOp(OpCode.CPUI_INT_ZEXT, rhs);
      }
      if (shiftneeded) {
        this.appendOp(OpCode.CPUI_INT_LEFT, rhs, BigInt(bitoffset), 4);
      }

      finalout = new VarnodeTpl(vn);
      res = this.createOpOut(finalout, OpCode.CPUI_INT_OR, res, rhs);
    }
    if (errmsg.length > 0) {
      this.reportError(null, errmsg);
    }
    const resops = res.ops!;
    res.ops = null;
    // res deleted in C++; GC handles
    return resops;
  }

  /**
   * Create an expression computing the indicated bitrange of sym.
   * The result is truncated to the smallest byte size that can contain
   * the indicated number of bits, with the desired bits shifted to the right.
   */
  createBitRange(sym: SpecificSymbol, bitoffset: uint4, numbits: uint4): ExprTree {
    let errmsg = '';
    if (numbits === 0) {
      errmsg = 'Size of bitrange is zero';
    }
    const vn: VarnodeTpl = (sym as any).getVarnode();
    const finalsize: uint4 = ((numbits + 7) / 8) >>> 0;
    let truncshift: uint4 = 0;
    let maskneeded: boolean = (numbits % 8) !== 0;
    let truncneeded = true;

    // Special case where we can set the size without invoking a truncation operator
    if (
      errmsg.length === 0 &&
      bitoffset === 0 &&
      !maskneeded
    ) {
      if (
        vn.getSpace().getType() === (ConstTpl.handle as const_type) &&
        vn.isZeroSize()
      ) {
        vn.setSize(new ConstTpl(ConstTpl.real, BigInt(finalsize)));
        const res = new ExprTree(vn);
        return res;
      }
    }

    if (errmsg.length === 0) {
      const truncvn = this.buildTruncatedVarnode(vn, bitoffset, numbits);
      if (truncvn !== null) {
        const res = new ExprTree(truncvn);
        // vn deleted in C++; GC handles
        return res;
      }
    }

    if (vn.getSize().getType() === (ConstTpl.real as const_type)) {
      let insize: uint4 = Number(vn.getSize().getReal());
      if (insize > 0) {
        truncneeded = finalsize < insize;
        insize *= 8;
        if (bitoffset >= insize || bitoffset + numbits > insize) {
          errmsg = 'Bitrange is bad';
        }
        if (maskneeded && bitoffset + numbits === insize) {
          maskneeded = false;
        }
      }
    }

    let mask: uintb = 2n;
    mask = (mask << BigInt(numbits - 1)) - 1n;

    if (truncneeded && (bitoffset % 8) === 0) {
      truncshift = (bitoffset / 8) >>> 0;
      bitoffset = 0;
    }

    if (bitoffset === 0 && !truncneeded && !maskneeded) {
      errmsg = 'Superfluous bitrange';
    }

    if (maskneeded && finalsize > 8) {
      errmsg =
        'Illegal masked bitrange producing varnode larger than 64 bits: ' +
        (sym as any).getName();
    }

    const res = new ExprTree(vn);

    if (errmsg.length > 0) {
      this.reportError(this.getLocation(sym), errmsg);
      return res;
    }

    if (bitoffset !== 0) {
      this.appendOp(OpCode.CPUI_INT_RIGHT, res, BigInt(bitoffset), 4);
    }
    if (truncneeded) {
      this.appendOp(OpCode.CPUI_SUBPIECE, res, BigInt(truncshift), 4);
    }
    if (maskneeded) {
      this.appendOp(OpCode.CPUI_INT_AND, res, mask, finalsize);
    }
    PcodeCompile.force_size(res.outvn!, new ConstTpl(ConstTpl.real, BigInt(finalsize)), res.ops!);
    return res;
  }

  /**
   * Produce a constant varnode that is the offset portion of var,
   * treated as an address.
   */
  addressOf(varTpl: VarnodeTpl, size: uint4): VarnodeTpl {
    if (size === 0) {
      if (varTpl.getSpace().getType() === (ConstTpl.spaceid as const_type)) {
        const spc = varTpl.getSpace().getSpace()!;
        size = spc.getAddrSize();
      }
    }
    let res: VarnodeTpl;
    if (
      varTpl.getOffset().getType() === (ConstTpl.real as const_type) &&
      varTpl.getSpace().getType() === (ConstTpl.spaceid as const_type)
    ) {
      const spc = varTpl.getSpace().getSpace()!;
      const off = AddrSpace.byteToAddress(varTpl.getOffset().getReal(), spc.getWordSize());
      res = new VarnodeTpl(
        new ConstTpl(this.constantspace!),
        new ConstTpl(ConstTpl.real, off),
        new ConstTpl(ConstTpl.real, BigInt(size)),
      );
    } else {
      res = new VarnodeTpl(
        new ConstTpl(this.constantspace!),
        varTpl.getOffset(),
        new ConstTpl(ConstTpl.real, BigInt(size)),
      );
    }
    // var deleted in C++; GC handles
    return res;
  }

  // ------------------------------------------------------------------
  // Static size-propagation methods
  // ------------------------------------------------------------------

  /**
   * Force a size onto a varnode template and propagate it through
   * all ops that reference the same local temporary.
   */
  static force_size(vt: VarnodeTpl, size: ConstTpl, ops: OpTpl[]): void {
    if (
      vt.getSize().getType() !== (ConstTpl.real as const_type) ||
      vt.getSize().getReal() !== 0n
    ) {
      return; // Size already exists
    }

    vt.setSize(size);
    if (!vt.isLocalTemp()) return;

    // Propagate size to uses of the same local temporary
    for (let i = 0; i < ops.length; ++i) {
      const op = ops[i];
      const vn = op.getOut();
      if (vn !== null && vn.isLocalTemp()) {
        if (vn.getOffset().equals(vt.getOffset())) {
          if (
            size.getType() === (ConstTpl.real as const_type) &&
            vn.getSize().getType() === (ConstTpl.real as const_type) &&
            vn.getSize().getReal() !== 0n &&
            vn.getSize().getReal() !== size.getReal()
          ) {
            throw new SleighError('Localtemp size mismatch');
          }
          vn.setSize(size);
        }
      }
      for (let j = 0; j < op.numInput(); ++j) {
        const invn = op.getIn(j);
        if (invn.isLocalTemp() && invn.getOffset().equals(vt.getOffset())) {
          if (
            size.getType() === (ConstTpl.real as const_type) &&
            invn.getSize().getType() === (ConstTpl.real as const_type) &&
            invn.getSize().getReal() !== 0n &&
            invn.getSize().getReal() !== size.getReal()
          ) {
            throw new SleighError('Localtemp size mismatch');
          }
          invn.setSize(size);
        }
      }
    }
  }

  /**
   * Find something to fill in a zero-size varnode.
   * j is the slot we are trying to fill (-1 = output).
   * Don't check output for non-zero if inputonly is true.
   */
  static matchSize(j: int4, op: OpTpl, inputonly: boolean, ops: OpTpl[]): void {
    let match: VarnodeTpl | null = null;

    const vt = j === -1 ? op.getOut()! : op.getIn(j);
    if (!inputonly) {
      if (op.getOut() !== null) {
        if (!op.getOut()!.isZeroSize()) {
          match = op.getOut()!;
        }
      }
    }
    const inputsize = op.numInput();
    for (let i = 0; i < inputsize; ++i) {
      if (match !== null) break;
      if (op.getIn(i).isZeroSize()) continue;
      match = op.getIn(i);
    }
    if (match !== null) {
      PcodeCompile.force_size(vt, match.getSize(), ops);
    }
  }

  /** Try to get rid of zero-size varnodes in op. */
  static fillinZero(op: OpTpl, ops: OpTpl[]): void {
    let inputsize: int4;
    let i: int4;

    switch (op.getOpcode()) {
      // Instructions where all inputs and output are same size
      case OpCode.CPUI_COPY:
      case OpCode.CPUI_INT_ADD:
      case OpCode.CPUI_INT_SUB:
      case OpCode.CPUI_INT_2COMP:
      case OpCode.CPUI_INT_NEGATE:
      case OpCode.CPUI_INT_XOR:
      case OpCode.CPUI_INT_AND:
      case OpCode.CPUI_INT_OR:
      case OpCode.CPUI_INT_MULT:
      case OpCode.CPUI_INT_DIV:
      case OpCode.CPUI_INT_SDIV:
      case OpCode.CPUI_INT_REM:
      case OpCode.CPUI_INT_SREM:
      case OpCode.CPUI_FLOAT_ADD:
      case OpCode.CPUI_FLOAT_DIV:
      case OpCode.CPUI_FLOAT_MULT:
      case OpCode.CPUI_FLOAT_SUB:
      case OpCode.CPUI_FLOAT_NEG:
      case OpCode.CPUI_FLOAT_ABS:
      case OpCode.CPUI_FLOAT_SQRT:
      case OpCode.CPUI_FLOAT_CEIL:
      case OpCode.CPUI_FLOAT_FLOOR:
      case OpCode.CPUI_FLOAT_ROUND:
        if (op.getOut() !== null && op.getOut()!.isZeroSize()) {
          PcodeCompile.matchSize(-1, op, false, ops);
        }
        inputsize = op.numInput();
        for (i = 0; i < inputsize; ++i) {
          if (op.getIn(i).isZeroSize()) {
            PcodeCompile.matchSize(i, op, false, ops);
          }
        }
        break;

      // Instructions with bool output
      case OpCode.CPUI_INT_EQUAL:
      case OpCode.CPUI_INT_NOTEQUAL:
      case OpCode.CPUI_INT_SLESS:
      case OpCode.CPUI_INT_SLESSEQUAL:
      case OpCode.CPUI_INT_LESS:
      case OpCode.CPUI_INT_LESSEQUAL:
      case OpCode.CPUI_INT_CARRY:
      case OpCode.CPUI_INT_SCARRY:
      case OpCode.CPUI_INT_SBORROW:
      case OpCode.CPUI_FLOAT_EQUAL:
      case OpCode.CPUI_FLOAT_NOTEQUAL:
      case OpCode.CPUI_FLOAT_LESS:
      case OpCode.CPUI_FLOAT_LESSEQUAL:
      case OpCode.CPUI_FLOAT_NAN:
      case OpCode.CPUI_BOOL_NEGATE:
      case OpCode.CPUI_BOOL_XOR:
      case OpCode.CPUI_BOOL_AND:
      case OpCode.CPUI_BOOL_OR:
        if (op.getOut()!.isZeroSize()) {
          PcodeCompile.force_size(op.getOut()!, new ConstTpl(ConstTpl.real, 1n), ops);
        }
        inputsize = op.numInput();
        for (i = 0; i < inputsize; ++i) {
          if (op.getIn(i).isZeroSize()) {
            PcodeCompile.matchSize(i, op, true, ops);
          }
        }
        break;

      // Shift ops: shift amount doesn't necessarily match size,
      // but if no size is specified, assume same size
      case OpCode.CPUI_INT_LEFT:
      case OpCode.CPUI_INT_RIGHT:
      case OpCode.CPUI_INT_SRIGHT:
        if (op.getOut()!.isZeroSize()) {
          if (!op.getIn(0).isZeroSize()) {
            PcodeCompile.force_size(op.getOut()!, op.getIn(0).getSize(), ops);
          }
        } else if (op.getIn(0).isZeroSize()) {
          PcodeCompile.force_size(op.getIn(0), op.getOut()!.getSize(), ops);
        }
      // fallthrough to subpiece constant check
      // eslint-disable-next-line no-fallthrough
      case OpCode.CPUI_SUBPIECE:
        if (op.getIn(1).isZeroSize()) {
          PcodeCompile.force_size(op.getIn(1), new ConstTpl(ConstTpl.real, 4n), ops);
        }
        break;

      case OpCode.CPUI_CPOOLREF:
        if (op.getOut()!.isZeroSize() && !op.getIn(0).isZeroSize()) {
          PcodeCompile.force_size(op.getOut()!, op.getIn(0).getSize(), ops);
        }
        if (op.getIn(0).isZeroSize() && !op.getOut()!.isZeroSize()) {
          PcodeCompile.force_size(op.getIn(0), op.getOut()!.getSize(), ops);
        }
        for (i = 1; i < op.numInput(); ++i) {
          if (op.getIn(i).isZeroSize()) {
            // sizeof(uintb) = 8 in the C++ code
            PcodeCompile.force_size(op.getIn(i), new ConstTpl(ConstTpl.real, 8n), ops);
          }
        }
        break;

      default:
        break;
    }
  }

  /**
   * Fill in size for varnodes with size 0.
   * Returns true if all zero-size varnodes were resolved, false otherwise.
   */
  static propagateSize(ct: ConstructTpl): boolean {
    let zerovec: OpTpl[] = [];
    let zerovec2: OpTpl[];
    let lastsize: int4;

    const opvec = ct.getOpvec();
    for (let i = 0; i < opvec.length; ++i) {
      if (opvec[i].isZeroSize()) {
        PcodeCompile.fillinZero(opvec[i], opvec);
        if (opvec[i].isZeroSize()) {
          zerovec.push(opvec[i]);
        }
      }
    }
    lastsize = zerovec.length + 1;
    while (zerovec.length < lastsize) {
      lastsize = zerovec.length;
      zerovec2 = [];
      for (let i = 0; i < zerovec.length; ++i) {
        PcodeCompile.fillinZero(zerovec[i], opvec);
        if (zerovec[i].isZeroSize()) {
          zerovec2.push(zerovec[i]);
        }
      }
      zerovec = zerovec2;
    }
    if (lastsize !== 0) return false;
    return true;
  }
}
