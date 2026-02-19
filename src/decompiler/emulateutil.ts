/**
 * @file emulateutil.ts
 * @description (Lightweight) emulation interface for executing PcodeOp objects within a syntax tree
 * or for executing snippets defined with PcodeOpRaw objects.
 *
 * Translated from Ghidra's emulateutil.hh / emulateutil.cc
 */

import type { int4, uint4, uintb } from '../core/types.js';
import { HOST_ENDIAN } from '../core/types.js';
import { Address, byte_swap, calc_mask } from '../core/address.js';
import { AddrSpace, spacetype } from '../core/space.js';
import { OpCode, get_opname } from '../core/opcodes.js';
import { LowlevelError } from '../core/error.js';
import { VarnodeData, PcodeOpRaw } from '../core/pcoderaw.js';
import type { OpBehavior } from '../core/opbehavior.js';
import type { PcodeEmit } from '../core/translate.js';

// ---------------------------------------------------------------------------
// Forward-declare types not yet available
// ---------------------------------------------------------------------------

type Funcdata = any;
type PcodeOp = any;
type Varnode = any;
type Architecture = any;
type FlowBlock = any;
type SegmentOp = any;
type LoadImage = any;
type MemoryState = any;
type PcodeEmitCache = any;

// ---------------------------------------------------------------------------
// Emulate (base class)
// ---------------------------------------------------------------------------

/**
 * A pcode-based emulator interface.
 *
 * The interface expects that the underlying emulation engine operates on individual pcode
 * operations as its atomic operation. The interface allows execution stepping through
 * individual pcode operations.
 */
export abstract class Emulate {
  protected emu_halted: boolean;
  protected currentBehave: OpBehavior | null;

  constructor() {
    this.emu_halted = true;
    this.currentBehave = null;
  }

  /** Set the halt state of the emulator */
  setHalt(val: boolean): void {
    this.emu_halted = val;
  }

  /** Get the halt state of the emulator */
  getHalt(): boolean {
    return this.emu_halted;
  }

  /** Set the address of the next instruction to emulate */
  abstract setExecuteAddress(addr: Address): void;

  /** Get the address of the current instruction being executed */
  abstract getExecuteAddress(): Address;

  /** Execute a unary arithmetic/logical operation */
  protected abstract executeUnary(): void;

  /** Execute a binary arithmetic/logical operation */
  protected abstract executeBinary(): void;

  /** Standard behavior for a p-code LOAD */
  protected abstract executeLoad(): void;

  /** Standard behavior for a p-code STORE */
  protected abstract executeStore(): void;

  /** Standard behavior for a BRANCH */
  protected abstract executeBranch(): void;

  /** Check if the conditional of a CBRANCH is true */
  protected abstract executeCbranch(): boolean;

  /** Standard behavior for a BRANCHIND */
  protected abstract executeBranchind(): void;

  /** Standard behavior for a p-code CALL */
  protected abstract executeCall(): void;

  /** Standard behavior for a CALLIND */
  protected abstract executeCallind(): void;

  /** Standard behavior for a user-defined p-code op */
  protected abstract executeCallother(): void;

  /** Standard behavior for a MULTIEQUAL (phi-node) */
  protected abstract executeMultiequal(): void;

  /** Standard behavior for an INDIRECT op */
  protected abstract executeIndirect(): void;

  /** Behavior for a SEGMENTOP */
  protected abstract executeSegmentOp(): void;

  /** Standard behavior for a CPOOLREF (constant pool reference) op */
  protected abstract executeCpoolRef(): void;

  /** Standard behavior for (low-level) NEW op */
  protected abstract executeNew(): void;

  /** Standard p-code fall-thru semantics */
  protected abstract fallthruOp(): void;

  /** Do a single pcode op step */
  executeCurrentOp(): void {
    if (this.currentBehave === null) {
      // Presumably a NO-OP
      this.fallthruOp();
      return;
    }

    const opc: OpCode = this.currentBehave.getOpcode();
    if (this.currentBehave.isSpecial()) {
      switch (opc) {
        case OpCode.CPUI_LOAD:
          this.executeLoad();
          this.fallthruOp();
          break;
        case OpCode.CPUI_STORE:
          this.executeStore();
          this.fallthruOp();
          break;
        case OpCode.CPUI_BRANCH:
          this.executeBranch();
          break;
        case OpCode.CPUI_CBRANCH: {
          const condition = this.executeCbranch();
          if (condition) {
            this.executeBranch();
          } else {
            this.fallthruOp();
          }
          break;
        }
        case OpCode.CPUI_BRANCHIND:
          this.executeBranchind();
          break;
        case OpCode.CPUI_CALL:
          this.executeCall();
          break;
        case OpCode.CPUI_CALLIND:
          this.executeCallind();
          break;
        case OpCode.CPUI_CALLOTHER:
          this.executeCallother();
          break;
        case OpCode.CPUI_RETURN:
          this.executeBranchind();
          break;
        case OpCode.CPUI_MULTIEQUAL:
          this.executeMultiequal();
          this.fallthruOp();
          break;
        case OpCode.CPUI_INDIRECT:
          this.executeIndirect();
          this.fallthruOp();
          break;
        case OpCode.CPUI_SEGMENTOP:
          this.executeSegmentOp();
          this.fallthruOp();
          break;
        case OpCode.CPUI_CPOOLREF:
          this.executeCpoolRef();
          this.fallthruOp();
          break;
        case OpCode.CPUI_NEW:
          this.executeNew();
          this.fallthruOp();
          break;
        default:
          throw new LowlevelError("Bad special op");
      }
    } else if (this.currentBehave.isUnary()) {
      this.executeUnary();
      this.fallthruOp();
    } else {
      this.executeBinary();
      this.fallthruOp();
    }
  }
}

// ---------------------------------------------------------------------------
// EmulatePcodeOp
// ---------------------------------------------------------------------------

/**
 * Emulation based on (existing) PcodeOps and Varnodes.
 *
 * This is still an abstract class. It does most of the work of emulating
 * p-code using PcodeOp and Varnode objects (as opposed to PcodeOpRaw and VarnodeData).
 * This class leaves implementation of control-flow to the derived class. This class
 * implements most operations by going through new virtual methods:
 *    - getVarnodeValue()
 *    - setVarnodeValue()
 *    - getLoadImageValue()
 *
 * The default executeLoad() implementation pulls values from the underlying LoadImage
 * object. The following p-code ops are provided null implementations, as some tasks
 * don't need hard emulation of them:
 *   - STORE
 *   - CPOOLREF
 *   - NEW
 */
export abstract class EmulatePcodeOp extends Emulate {
  protected glb: Architecture;
  protected currentOp: PcodeOp | null;
  protected lastOp: PcodeOp | null;

  /**
   * Constructor
   * @param g is the Architecture providing the LoadImage
   */
  constructor(g: Architecture) {
    super();
    this.glb = g;
    this.currentOp = null;
    this.lastOp = null;
  }

  /**
   * Pull a value from the load-image given a specific address.
   *
   * A contiguous chunk of memory is pulled from the load-image and returned as a
   * constant value, respecting the endianness of the address space. The default implementation
   * of this method pulls the value directly from the LoadImage object.
   *
   * @param spc is the address space to pull the value from
   * @param offset is the starting address offset (from within the space) to pull the value from
   * @param sz is the number of bytes to pull from memory
   * @returns indicated bytes arranged as a constant value
   */
  protected getLoadImageValue(spc: AddrSpace, offset: uintb, sz: int4): uintb {
    const loadimage: LoadImage = this.glb.loader;
    const buf = new Uint8Array(8);
    loadimage.loadFill(buf, 8, new Address(spc, offset));

    // Read as a 64-bit value from the buffer
    let res: bigint = 0n;
    if (((HOST_ENDIAN as number) === 1) !== spc.isBigEndian()) {
      // Need to byte-swap
      for (let i = 7; i >= 0; i--) {
        res = (res << 8n) | BigInt(buf[i]);
      }
      res = byte_swap(res, 8);
    } else {
      for (let i = 7; i >= 0; i--) {
        res = (res << 8n) | BigInt(buf[i]);
      }
    }

    if (spc.isBigEndian() && (sz < 8)) {
      res = res >> BigInt((8 - sz) * 8);
    } else {
      res = res & calc_mask(sz);
    }
    return res;
  }

  protected executeUnary(): void {
    const in1: uintb = this.getVarnodeValue(this.currentOp!.getIn(0));
    const out: uintb = this.currentBehave!.evaluateUnary(
      this.currentOp!.getOut().getSize(),
      this.currentOp!.getIn(0).getSize(),
      in1
    );
    this.setVarnodeValue(this.currentOp!.getOut(), out);
  }

  protected executeBinary(): void {
    const in1: uintb = this.getVarnodeValue(this.currentOp!.getIn(0));
    const in2: uintb = this.getVarnodeValue(this.currentOp!.getIn(1));
    const out: uintb = this.currentBehave!.evaluateBinary(
      this.currentOp!.getOut().getSize(),
      this.currentOp!.getIn(0).getSize(),
      in1,
      in2
    );
    this.setVarnodeValue(this.currentOp!.getOut(), out);
  }

  protected executeLoad(): void {
    const off: uintb = this.getVarnodeValue(this.currentOp!.getIn(1));
    const spc: AddrSpace = this.currentOp!.getIn(0).getSpaceFromConst();
    const byteOff: uintb = AddrSpace.addressToByte(off, spc.getWordSize());
    const sz: int4 = this.currentOp!.getOut().getSize();
    const res: uintb = this.getLoadImageValue(spc, byteOff, sz);
    this.setVarnodeValue(this.currentOp!.getOut(), res);
  }

  protected executeStore(): void {
    // There is currently nowhere to store anything since the memstate is null
  }

  protected executeCbranch(): boolean {
    const cond: uintb = this.getVarnodeValue(this.currentOp!.getIn(1));
    // We must take into account the booleanflip bit with pcode from the syntax tree
    return ((cond !== 0n) !== this.currentOp!.isBooleanFlip());
  }

  protected executeMultiequal(): void {
    let i: int4;
    const bl: FlowBlock = this.currentOp!.getParent();
    const lastBl: FlowBlock = this.lastOp!.getParent();

    for (i = 0; i < bl.sizeIn(); ++i) {
      if (bl.getIn(i) === lastBl) break;
    }
    if (i === bl.sizeIn()) {
      throw new LowlevelError("Could not execute MULTIEQUAL");
    }
    const val: uintb = this.getVarnodeValue(this.currentOp!.getIn(i));
    this.setVarnodeValue(this.currentOp!.getOut(), val);
  }

  protected executeIndirect(): void {
    // We could probably safely ignore this in the
    // context we are using it (jumptable recovery)
    // But we go ahead and assume it is equivalent to copy
    const val: uintb = this.getVarnodeValue(this.currentOp!.getIn(0));
    this.setVarnodeValue(this.currentOp!.getOut(), val);
  }

  protected executeSegmentOp(): void {
    const segdef: SegmentOp = this.glb.userops.getSegmentOp(
      this.currentOp!.getIn(0).getSpaceFromConst().getIndex()
    );
    if (segdef === null) {
      throw new LowlevelError("Segment operand missing definition");
    }

    const in1: uintb = this.getVarnodeValue(this.currentOp!.getIn(1));
    const in2: uintb = this.getVarnodeValue(this.currentOp!.getIn(2));
    const bindlist: uintb[] = [];
    bindlist.push(in1);
    bindlist.push(in2);
    const res: uintb = segdef.execute(bindlist);
    this.setVarnodeValue(this.currentOp!.getOut(), res);
  }

  protected executeCpoolRef(): void {
    // Ignore references to constant pool
  }

  protected executeNew(): void {
    // Ignore new operations
  }

  /**
   * Establish the current PcodeOp being emulated.
   * @param op is the PcodeOp that will next be executed via executeCurrentOp()
   */
  setCurrentOp(op: PcodeOp): void {
    this.currentOp = op;
    this.currentBehave = op.getOpcode().getBehavior();
  }

  getExecuteAddress(): Address {
    return this.currentOp!.getAddr() as any as Address;
  }

  /**
   * Given a specific Varnode, set the given value for it in the current machine state.
   *
   * This is the placeholder internal operation for setting a Varnode value during emulation.
   * The value is stored using the Varnode as the address and storage size.
   * @param vn is the specific Varnode
   * @param val is the constant value to store
   */
  abstract setVarnodeValue(vn: Varnode, val: uintb): void;

  /**
   * Given a specific Varnode, retrieve the current value for it from the machine state.
   *
   * This is the placeholder internal operation for obtaining a Varnode value during emulation.
   * The value is loaded using the Varnode as the address and storage size.
   * @param vn is the specific Varnode
   * @returns the corresponding value from the machine state
   */
  abstract getVarnodeValue(vn: Varnode): uintb;
}

// ---------------------------------------------------------------------------
// EmulateSnippet
// ---------------------------------------------------------------------------

/**
 * Emulate a snippet of PcodeOps out of a functional context.
 *
 * Emulation is performed on a short sequence (snippet) of PcodeOpRaw objects.
 * Control-flow emulation is limited to this snippet; BRANCH and CBRANCH operations
 * can happen using p-code relative branching. Executing BRANCHIND, CALL, CALLIND,
 * CALLOTHER, STORE, MULTIEQUAL, INDIRECT, SEGMENTOP, CPOOLOP, and NEW
 * ops is treated as illegal and an exception is thrown.
 * Expressions can only use temporary registers or read from the LoadImage.
 *
 * The set of PcodeOpRaw objects in the snippet is provided by emitting p-code to the object
 * returned by buildEmitter(). This is designed for one-time initialization of this
 * class, which can be repeatedly used by calling resetMemory() between executions.
 */
export class EmulateSnippet extends Emulate {
  private glb: Architecture;
  private opList: PcodeOpRaw[];
  private varList: VarnodeData[];
  private tempValues: Map<bigint, bigint>;
  private currentOp: PcodeOpRaw | null;
  private pos: int4;

  /**
   * Constructor
   * @param g is the Architecture providing the LoadImage
   */
  constructor(g: Architecture) {
    super();
    this.glb = g;
    this.opList = [];
    this.varList = [];
    this.tempValues = new Map();
    this.pos = 0;
    this.currentOp = null;
  }

  /**
   * Destructor - clean up allocated ops and varnodes.
   * In TypeScript, GC handles this, but we clear the arrays for consistency.
   */
  dispose(): void {
    this.opList.length = 0;
    this.varList.length = 0;
  }

  setExecuteAddress(_addr: Address): void {
    this.setCurrentOp(0);
  }

  getExecuteAddress(): Address {
    return this.currentOp!.getAddr() as any as Address;
  }

  /** Get the underlying Architecture */
  getArch(): Architecture {
    return this.glb;
  }

  /**
   * Reset the emulation snippet.
   * Reset the memory state, and set the first p-code op as current.
   */
  resetMemory(): void {
    this.tempValues.clear();
    this.setCurrentOp(0);
    this.emu_halted = false;
  }

  /**
   * Provide the caller with an emitter for building the p-code snippet.
   *
   * Any p-code produced by the PcodeEmit, when triggered by the caller, becomes
   * part of the snippet that will get emulated by this. The caller should
   * free the PcodeEmit object immediately after use.
   *
   * @param inst is the opcode to behavior map the emitter will use
   * @param uniqReserve is the starting offset within the unique address space for any temporary registers
   * @returns the newly constructed emitter
   */
  buildEmitter(inst: OpBehavior[], uniqReserve: uintb): PcodeEmit {
    // PcodeEmitCache is forward-declared; this follows the C++ pattern
    return new (PcodeEmitCacheRef())(this.opList, this.varList, inst, uniqReserve) as PcodeEmit;
  }

  /**
   * Check for p-code that is deemed illegal for a snippet.
   *
   * This method facilitates enforcement of the formal rules for snippet code.
   *   - Branches must use p-code relative addressing.
   *   - Snippets can only read/write from temporary registers
   *   - Snippets cannot use BRANCHIND, CALL, CALLIND, CALLOTHER, STORE, SEGMENTOP, CPOOLREF,
   *              NEW, MULTIEQUAL, or INDIRECT
   *
   * @returns true if the current snippet is legal
   */
  checkForLegalCode(): boolean {
    for (let i = 0; i < this.opList.length; ++i) {
      const op: PcodeOpRaw = this.opList[i];
      let vn: VarnodeData | null;
      const opc: OpCode = op.getOpcode();
      if (
        opc === OpCode.CPUI_BRANCHIND || opc === OpCode.CPUI_CALL ||
        opc === OpCode.CPUI_CALLIND || opc === OpCode.CPUI_CALLOTHER ||
        opc === OpCode.CPUI_STORE || opc === OpCode.CPUI_SEGMENTOP ||
        opc === OpCode.CPUI_CPOOLREF || opc === OpCode.CPUI_NEW ||
        opc === OpCode.CPUI_MULTIEQUAL || opc === OpCode.CPUI_INDIRECT
      ) {
        return false;
      }
      if (opc === OpCode.CPUI_BRANCH) {
        vn = op.getInput(0);
        if ((vn.space as any).getType() !== spacetype.IPTR_CONSTANT) {
          // Only relative branching allowed
          return false;
        }
      }
      vn = op.getOutput();
      if (vn !== null) {
        if ((vn.space as any).getType() !== spacetype.IPTR_INTERNAL) {
          return false; // Can only write to temporaries
        }
      }
      for (let j = 0; j < op.numInput(); ++j) {
        vn = op.getInput(j);
        if ((vn.space as any).getType() === spacetype.IPTR_PROCESSOR) {
          return false; // Cannot read from normal registers
        }
      }
    }
    return true;
  }

  /**
   * Set the current executing p-code op by index.
   *
   * The i-th p-code op in the snippet sequence is set as the currently executing op.
   * @param i is the index
   */
  setCurrentOp(i: int4): void {
    this.pos = i;
    this.currentOp = this.opList[i];
    this.currentBehave = this.currentOp.getBehavior();
  }

  /**
   * Set a temporary register value in the machine state.
   *
   * The temporary Varnode's storage offset is used as key into the machine state map.
   * @param offset is the temporary storage offset
   * @param val is the value to put into the machine state
   */
  setVarnodeValue(offset: uintb, val: uintb): void {
    this.tempValues.set(offset, val);
  }

  /**
   * Retrieve the value of a Varnode from the current machine state.
   *
   * If the Varnode is a temporary register, the storage offset is used to look up
   * the value from the machine state cache. If the Varnode represents a RAM location,
   * the value is pulled directly out of the load-image.
   * If the value does not exist, a "Read before write" exception is thrown.
   *
   * @param vn is the Varnode to read
   * @returns the retrieved value
   */
  getVarnodeValue(vn: VarnodeData): uintb {
    const spc: AddrSpace = vn.space as any as AddrSpace;
    if (spc.getType() === spacetype.IPTR_CONSTANT) {
      return vn.offset;
    }
    if (spc.getType() === spacetype.IPTR_INTERNAL) {
      const val = this.tempValues.get(vn.offset);
      if (val !== undefined) {
        return val; // We have seen this varnode before
      }
      throw new LowlevelError("Read before write in snippet emulation");
    }

    return this.getLoadImageValue(vn.space as any as AddrSpace, vn.offset, vn.size);
  }

  /**
   * Retrieve a temporary register value directly.
   *
   * This allows the user to obtain the final value of the snippet calculation, without
   * having to have the Varnode object in hand.
   *
   * @param offset is the offset of the temporary register to retrieve
   * @returns the calculated value or 0n if the register was never written
   */
  getTempValue(offset: uintb): uintb {
    const val = this.tempValues.get(offset);
    if (val === undefined) {
      return 0n;
    }
    return val;
  }

  // ---------------------------------------------------------------------------
  // Private / protected implementation methods
  // ---------------------------------------------------------------------------

  /**
   * Pull a value from the load-image given a specific address.
   */
  private getLoadImageValue(spc: AddrSpace, offset: uintb, sz: int4): uintb {
    const loadimage: LoadImage = this.glb.loader;
    const buf = new Uint8Array(8);
    loadimage.loadFill(buf, 8, new Address(spc, offset));

    // Read as a 64-bit value from the buffer
    let res: bigint = 0n;
    if (((HOST_ENDIAN as number) === 1) !== spc.isBigEndian()) {
      for (let i = 7; i >= 0; i--) {
        res = (res << 8n) | BigInt(buf[i]);
      }
      res = byte_swap(res, 8);
    } else {
      for (let i = 7; i >= 0; i--) {
        res = (res << 8n) | BigInt(buf[i]);
      }
    }

    if (spc.isBigEndian() && (sz < 8)) {
      res = res >> BigInt((8 - sz) * 8);
    } else {
      res = res & calc_mask(sz);
    }
    return res;
  }

  protected executeUnary(): void {
    const in1: uintb = this.getVarnodeValue(this.currentOp!.getInput(0));
    const out: uintb = this.currentBehave!.evaluateUnary(
      this.currentOp!.getOutput()!.size,
      this.currentOp!.getInput(0).size,
      in1
    );
    this.setVarnodeValue(this.currentOp!.getOutput()!.offset, out);
  }

  protected executeBinary(): void {
    const in1: uintb = this.getVarnodeValue(this.currentOp!.getInput(0));
    const in2: uintb = this.getVarnodeValue(this.currentOp!.getInput(1));
    const out: uintb = this.currentBehave!.evaluateBinary(
      this.currentOp!.getOutput()!.size,
      this.currentOp!.getInput(0).size,
      in1,
      in2
    );
    this.setVarnodeValue(this.currentOp!.getOutput()!.offset, out);
  }

  protected executeLoad(): void {
    const off: uintb = this.getVarnodeValue(this.currentOp!.getInput(1));
    const spc: AddrSpace = this.currentOp!.getInput(0).space as any as AddrSpace;
    const byteOff: uintb = AddrSpace.addressToByte(off, spc.getWordSize());
    const sz: int4 = this.currentOp!.getOutput()!.size;
    const res: uintb = this.getLoadImageValue(spc, byteOff, sz);
    this.setVarnodeValue(this.currentOp!.getOutput()!.offset, res);
  }

  protected executeStore(): void {
    throw new LowlevelError(
      "Illegal p-code operation in snippet: " + get_opname(this.currentOp!.getOpcode())
    );
  }

  protected executeBranch(): void {
    const vn: VarnodeData = this.currentOp!.getInput(0);
    if ((vn.space as any).getType() !== spacetype.IPTR_CONSTANT) {
      throw new LowlevelError("Tried to emulate absolute branch in snippet code");
    }
    const rel: int4 = Number(vn.offset);
    this.pos += rel;
    if (this.pos < 0 || this.pos > this.opList.length) {
      throw new LowlevelError("Relative branch out of bounds in snippet code");
    }
    if (this.pos === this.opList.length) {
      this.emu_halted = true;
      return;
    }
    this.setCurrentOp(this.pos);
  }

  protected executeCbranch(): boolean {
    const cond: uintb = this.getVarnodeValue(this.currentOp!.getInput(1));
    // We must take into account the booleanflip bit with pcode from the syntax tree
    return (cond !== 0n);
  }

  protected executeBranchind(): void {
    throw new LowlevelError(
      "Illegal p-code operation in snippet: " + get_opname(this.currentOp!.getOpcode())
    );
  }

  protected executeCall(): void {
    throw new LowlevelError(
      "Illegal p-code operation in snippet: " + get_opname(this.currentOp!.getOpcode())
    );
  }

  protected executeCallind(): void {
    throw new LowlevelError(
      "Illegal p-code operation in snippet: " + get_opname(this.currentOp!.getOpcode())
    );
  }

  protected executeCallother(): void {
    throw new LowlevelError(
      "Illegal p-code operation in snippet: " + get_opname(this.currentOp!.getOpcode())
    );
  }

  protected executeMultiequal(): void {
    throw new LowlevelError(
      "Illegal p-code operation in snippet: " + get_opname(this.currentOp!.getOpcode())
    );
  }

  protected executeIndirect(): void {
    throw new LowlevelError(
      "Illegal p-code operation in snippet: " + get_opname(this.currentOp!.getOpcode())
    );
  }

  protected executeSegmentOp(): void {
    throw new LowlevelError(
      "Illegal p-code operation in snippet: " + get_opname(this.currentOp!.getOpcode())
    );
  }

  protected executeCpoolRef(): void {
    throw new LowlevelError(
      "Illegal p-code operation in snippet: " + get_opname(this.currentOp!.getOpcode())
    );
  }

  protected executeNew(): void {
    throw new LowlevelError(
      "Illegal p-code operation in snippet: " + get_opname(this.currentOp!.getOpcode())
    );
  }

  protected fallthruOp(): void {
    this.pos += 1;
    if (this.pos === this.opList.length) {
      this.emu_halted = true;
      return;
    }
    this.setCurrentOp(this.pos);
  }
}

// ---------------------------------------------------------------------------
// PcodeEmitCache reference (lazy to avoid circular dependency)
// ---------------------------------------------------------------------------

/**
 * Lazy reference to PcodeEmitCache. Returns a constructor function.
 * Since PcodeEmitCache may not yet exist, we return a placeholder that
 * just constructs an object with the correct interface.
 */
function PcodeEmitCacheRef(): any {
  // Forward reference - PcodeEmitCache should be provided by emulate.ts
  // For now, provide a minimal implementation that matches the C++ interface
  return class PcodeEmitCacheImpl {
    private opcache: PcodeOpRaw[];
    private varcache: VarnodeData[];
    private inst: OpBehavior[];
    private uniq: number;

    constructor(
      ocache: PcodeOpRaw[],
      vcache: VarnodeData[],
      _inst: OpBehavior[],
      uniqReserve: bigint,
    ) {
      this.opcache = ocache;
      this.varcache = vcache;
      this.inst = _inst;
      this.uniq = Number(uniqReserve);
    }

    dump(
      _addr: Address,
      opc: OpCode,
      outvar: VarnodeData | null,
      vars: VarnodeData[],
      isize: number,
    ): void {
      const op = new PcodeOpRaw();
      op.setBehavior(this.inst[opc]);
      op.setSeqNum(_addr, this.opcache.length);

      const createVarnode = (v: VarnodeData): VarnodeData => {
        const vn = new VarnodeData(v.space, v.offset, v.size);
        this.varcache.push(vn);
        return vn;
      };

      if (outvar !== null) {
        const outvn = createVarnode(outvar);
        op.setOutput(outvn);
      }
      for (let j = 0; j < isize; ++j) {
        const invn = createVarnode(vars[j]);
        op.addInput(invn);
      }
      this.opcache.push(op);
    }
  };
}
