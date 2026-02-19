/**
 * @file emulate.ts
 * @description Classes for emulating p-code, translated from Ghidra's emulate.hh / emulate.cc
 */

import type { int4, uint4, uintb, uintm } from '../core/types.js';
import { LowlevelError } from '../core/error.js';
import { Address } from '../core/address.js';
import { AddrSpace } from '../core/space.js';
import { OpCode } from '../core/opcodes.js';
import { OpBehavior } from '../core/opbehavior.js';
import {
  VarnodeData,
  PcodeOpRaw,
  Address as PcodeRawAddress,
} from '../core/pcoderaw.js';
import { PcodeEmit, Translate } from '../core/translate.js';

// Forward-declare types not yet available
type MemoryState = any;

/**
 * Convert a pcoderaw Address (from VarnodeData.getAddr() or PcodeOpRaw.getAddr())
 * to the main Address type.
 */
function toAddress(raw: PcodeRawAddress): Address {
  return new Address(raw.base as any as AddrSpace, raw.offset);
}

/**
 * Emulate VarnodeData.getSpaceFromConst().
 * In C++ this casts the offset field to an AddrSpace pointer.
 * In the TS translation, the space is encoded in the varnode's space field
 * (for LOAD/STORE the first input is a constant whose offset encodes a space index).
 * We rely on the MemoryState / caller to resolve this; here we use the space field directly.
 */
function getSpaceFromConst(vn: VarnodeData): AddrSpace {
  return (vn as any).getSpaceFromConst?.() ?? (vn.space as any);
}

// ---------------------------------------------------------------------------
// BreakTable (abstract)
// ---------------------------------------------------------------------------

/**
 * A collection of breakpoints for the emulator.
 *
 * A BreakTable keeps track of an arbitrary number of breakpoints for an emulator.
 * Breakpoints are either associated with a particular user-defined pcode op,
 * or with a specific machine address (as in a standard debugger). Through the BreakTable
 * object, an emulator can invoke breakpoints through the two methods
 *   - doPcodeOpBreak()
 *   - doAddressBreak()
 *
 * depending on the type of breakpoint they currently want to invoke
 */
export abstract class BreakTable {
  /**
   * Associate a particular emulator with breakpoints in this table.
   *
   * Breakpoints may need access to the context in which they are invoked. This
   * routine provides the context for all breakpoints in the table.
   * @param emu is the Emulate context
   */
  abstract setEmulate(emu: Emulate): void;

  /**
   * Invoke any breakpoints associated with this particular pcodeop.
   *
   * Within the table, the first breakpoint which is designed to work with this particular
   * kind of pcode operation is invoked. If there was a breakpoint and it was designed
   * to replace the action of the pcode op, then true is returned.
   * @param curop is the instance of a pcode op to test for breakpoints
   * @returns true if the action of the pcode op is performed by the breakpoint
   */
  abstract doPcodeOpBreak(curop: PcodeOpRaw): boolean;

  /**
   * Invoke any breakpoints associated with this machine address.
   *
   * Within the table, the first breakpoint which is designed to work with at this address
   * is invoked. If there was a breakpoint, and if it was designed to replace
   * the action of the machine instruction, then true is returned.
   * @param addr is address to test for breakpoints
   * @returns true if the machine instruction has been replaced by a breakpoint
   */
  abstract doAddressBreak(addr: Address): boolean;
}

// ---------------------------------------------------------------------------
// BreakCallBack
// ---------------------------------------------------------------------------

/**
 * A breakpoint object.
 *
 * This is a base class for breakpoint objects in an emulator. The breakpoints are implemented
 * as callback method, which is overridden for the particular behavior needed by the emulator.
 * Each derived class must override either
 *   - pcodeCallback()
 *   - addressCallback()
 *
 * depending on whether the breakpoint is tailored for a particular pcode op or for
 * a machine address.
 */
export class BreakCallBack {
  /** The emulator currently associated with this breakpoint */
  protected emulate: Emulate | null;

  /** Generic breakpoint constructor */
  constructor() {
    this.emulate = null;
  }

  /**
   * Call back method for pcode based breakpoints.
   *
   * This routine is invoked during emulation, if this breakpoint has somehow been associated with
   * this kind of pcode op. The callback can perform any operation on the emulator context it wants.
   * It then returns true if these actions are intended to replace the action of the pcode op itself.
   * Or it returns false if the pcode op should still have its normal effect on the emulator context.
   * @param op is the particular pcode operation where the break occurs.
   * @returns true if the normal pcode op action should not occur
   */
  pcodeCallback(op: PcodeOpRaw): boolean {
    return true;
  }

  /**
   * Call back method for address based breakpoints.
   *
   * This routine is invoked during emulation, if this breakpoint has somehow been associated with
   * this address. The callback can perform any operation on the emulator context it wants. It then
   * returns true if these actions are intended to replace the action of the entire machine
   * instruction at this address. Or it returns false if the machine instruction should still be
   * executed normally.
   * @param addr is the address where the break has occurred
   * @returns true if the machine instruction should not be executed
   */
  addressCallback(addr: Address): boolean {
    return true;
  }

  /**
   * Associate a particular emulator with this breakpoint.
   * Breakpoints can be associated with one emulator at a time.
   * @param emu is the emulator to associate this breakpoint with
   */
  setEmulate(emu: Emulate): void {
    this.emulate = emu;
  }
}

// ---------------------------------------------------------------------------
// BreakTableCallBack
// ---------------------------------------------------------------------------

/**
 * A basic instantiation of a breakpoint table.
 *
 * This object allows breakpoints to registered in the table via either
 *   - registerPcodeCallback()  or
 *   - registerAddressCallback()
 *
 * Breakpoints are stored in map containers, and the core BreakTable methods
 * are implemented to search in these containers.
 */
export class BreakTableCallBack extends BreakTable {
  /** The emulator associated with this table */
  private emulate: Emulate | null;
  /** The translator */
  private trans: Translate;
  /** A container of address based breakpoints */
  private addresscallback: Map<string, BreakCallBack> = new Map();
  /** A container of pcode based breakpoints */
  private pcodecallback: Map<bigint, BreakCallBack> = new Map();

  /**
   * Basic breaktable constructor.
   *
   * The break table needs a translator object so user-defined pcode ops can be registered against
   * by name.
   * @param t is the translator object
   */
  constructor(t: Translate) {
    super();
    this.emulate = null;
    this.trans = t;
  }

  /**
   * Register a pcode based breakpoint.
   *
   * Any time the emulator is about to execute a user-defined pcode op with the given name,
   * the indicated breakpoint is invoked first. The break table does not assume responsibility
   * for freeing the breakpoint object.
   * @param nm is the name of the user-defined pcode op
   * @param func is the breakpoint object to associate with the pcode op
   */
  registerPcodeCallback(nm: string, func: BreakCallBack): void {
    func.setEmulate(this.emulate!);
    const userops: string[] = [];
    this.trans.getUserOpNames(userops);
    for (let i = 0; i < userops.length; ++i) {
      if (userops[i] === nm) {
        this.pcodecallback.set(BigInt(i), func);
        return;
      }
    }
    throw new LowlevelError('Bad userop name: ' + nm);
  }

  /**
   * Register an address based breakpoint.
   *
   * Any time the emulator is about to execute (the pcode translation of) a particular machine
   * instruction at this address, the indicated breakpoint is invoked first. The break table
   * does not assume responsibility for freeing the breakpoint object.
   * @param addr is the address associated with the breakpoint
   * @param func is the breakpoint being registered
   */
  registerAddressCallback(addr: Address, func: BreakCallBack): void {
    func.setEmulate(this.emulate!);
    const key = BreakTableCallBack.addressKey(addr);
    this.addresscallback.set(key, func);
  }

  /**
   * Associate an emulator with all breakpoints in the table.
   *
   * This routine invokes the setEmulate method on each breakpoint currently in the table.
   * @param emu is the emulator to be associated with the breakpoints
   */
  setEmulate(emu: Emulate): void {
    this.emulate = emu;
    for (const [, cb] of this.addresscallback) {
      cb.setEmulate(emu);
    }
    for (const [, cb] of this.pcodecallback) {
      cb.setEmulate(emu);
    }
  }

  /**
   * Invoke any breakpoints for the given pcode op.
   *
   * This routine examines the pcode-op based container for any breakpoints associated with the
   * given op. If one is found, its pcodeCallback method is invoked.
   * @param curop is pcode op being checked for breakpoints
   * @returns true if the breakpoint exists and returns true, otherwise return false
   */
  doPcodeOpBreak(curop: PcodeOpRaw): boolean {
    const val: bigint = curop.getInput(0).offset;
    const cb = this.pcodecallback.get(val);
    if (cb === undefined) return false;
    return cb.pcodeCallback(curop);
  }

  /**
   * Invoke any breakpoints for the given address.
   *
   * This routine examines the address based container for any breakpoints associated with the
   * given address. If one is found, its addressCallback method is invoked.
   * @param addr is the address being checked for breakpoints
   * @returns true if the breakpoint exists and returns true, otherwise return false
   */
  doAddressBreak(addr: Address): boolean {
    const key = BreakTableCallBack.addressKey(addr);
    const cb = this.addresscallback.get(key);
    if (cb === undefined) return false;
    return cb.addressCallback(addr);
  }

  /**
   * Create a string key from an Address for use in the address callback map.
   * Since we cannot use Address objects directly as Map keys, we create a unique
   * string representation combining the space index and offset.
   */
  private static addressKey(addr: Address): string {
    const spc = addr.getSpace();
    const idx = spc !== null ? spc.getIndex() : -1;
    return `${idx}:${addr.getOffset()}`;
  }
}

// ---------------------------------------------------------------------------
// Emulate (abstract)
// ---------------------------------------------------------------------------

/**
 * A pcode-based emulator interface.
 *
 * The interface expects that the underlying emulation engine operates on individual pcode
 * operations as its atomic operation. The interface allows execution stepping through
 * individual pcode operations. The interface allows
 * querying of the current pcode op, the current machine address, and the rest of the
 * machine state.
 */
export abstract class Emulate {
  /** Set to true if the emulator is halted */
  protected emu_halted: boolean;
  /** Behavior of the next op to execute */
  protected currentBehave: OpBehavior | null;

  /** Generic emulator constructor */
  constructor() {
    this.emu_halted = true;
    this.currentBehave = null;
  }

  /**
   * Set the halt state of the emulator.
   *
   * Applications and breakpoints can use this method and its companion getHalt() to
   * terminate and restart the main emulator loop as needed. The emulator itself makes no use
   * of this routine or the associated state variable emu_halted.
   * @param val is what the halt state of the emulator should be set to
   */
  setHalt(val: boolean): void {
    this.emu_halted = val;
  }

  /**
   * Get the halt state of the emulator.
   *
   * Applications and breakpoints can use this method and its companion setHalt() to
   * terminate and restart the main emulator loop as needed. The emulator itself makes no use
   * of this routine or the associated state variable emu_halted.
   * @returns true if the emulator is in a "halted" state.
   */
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

  /**
   * Standard behavior for a BRANCH.
   *
   * This routine performs a standard p-code BRANCH operation on the memory state.
   * This same routine is used for CBRANCH operations if the condition
   * has evaluated to true.
   */
  protected abstract executeBranch(): void;

  /**
   * Check if the conditional of a CBRANCH is true.
   *
   * This routine only checks if the condition for a p-code CBRANCH is true.
   * It does not perform the actual branch.
   * @returns the boolean state indicated by the condition
   */
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

  /**
   * Do a single pcode op step.
   *
   * This method executes a single pcode operation, the current one (returned by getCurrentOp()).
   * The MemoryState of the emulator is queried and changed as needed to accomplish this.
   */
  executeCurrentOp(): void {
    if (this.currentBehave === null) {
      // Presumably a NO-OP
      this.fallthruOp();
      return;
    }
    if (this.currentBehave.isSpecial()) {
      switch (this.currentBehave.getOpcode()) {
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
        case OpCode.CPUI_CBRANCH:
          if (this.executeCbranch())
            this.executeBranch();
          else
            this.fallthruOp();
          break;
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
          throw new LowlevelError('Bad special op');
      }
    } else if (this.currentBehave.isUnary()) {
      // Unary operation
      this.executeUnary();
      this.fallthruOp();
    } else {
      // Binary operation
      this.executeBinary();
      this.fallthruOp(); // All binary ops are fallthrus
    }
  }
}

// ---------------------------------------------------------------------------
// EmulateMemory (abstract)
// ---------------------------------------------------------------------------

/**
 * An abstract Emulate class using a MemoryState object as the backing machine state.
 *
 * Most p-code operations are implemented using the MemoryState to fetch and store
 * values. Control-flow is implemented partially in that setExecuteAddress() is called
 * to indicate which instruction is being executed. The derived class must provide
 *   - fallthruOp()
 *   - setExecuteAddress()
 *   - getExecuteAddress()
 *
 * The following p-code operations are stubbed out and will throw an exception:
 * CALLOTHER, MULTIEQUAL, INDIRECT, CPOOLREF, SEGMENTOP, and NEW.
 * Of course the derived class can override these.
 */
export abstract class EmulateMemory extends Emulate {
  /** The memory state of the emulator */
  protected memstate: MemoryState;
  /** Current op to execute */
  protected currentOp: PcodeOpRaw | null;

  /** Construct given a memory state */
  constructor(mem: MemoryState) {
    super();
    this.memstate = mem;
    this.currentOp = null;
  }

  /** Get the emulator's memory state */
  getMemoryState(): MemoryState {
    return this.memstate;
  }

  protected executeUnary(): void {
    const in1: bigint = this.memstate.getValue(this.currentOp!.getInput(0));
    const out: bigint = this.currentBehave!.evaluateUnary(
      this.currentOp!.getOutput()!.size,
      this.currentOp!.getInput(0).size,
      in1
    );
    this.memstate.setValue(this.currentOp!.getOutput()!, out);
  }

  protected executeBinary(): void {
    const in1: bigint = this.memstate.getValue(this.currentOp!.getInput(0));
    const in2: bigint = this.memstate.getValue(this.currentOp!.getInput(1));
    const out: bigint = this.currentBehave!.evaluateBinary(
      this.currentOp!.getOutput()!.size,
      this.currentOp!.getInput(0).size,
      in1,
      in2
    );
    this.memstate.setValue(this.currentOp!.getOutput()!, out);
  }

  protected executeLoad(): void {
    let off: bigint = this.memstate.getValue(this.currentOp!.getInput(1));
    const spc: AddrSpace = getSpaceFromConst(this.currentOp!.getInput(0));

    off = AddrSpace.addressToByte(off, spc.getWordSize());
    const res: bigint = this.memstate.getValue(spc, off, this.currentOp!.getOutput()!.size);
    this.memstate.setValue(this.currentOp!.getOutput()!, res);
  }

  protected executeStore(): void {
    const val: bigint = this.memstate.getValue(this.currentOp!.getInput(2)); // Value being stored
    let off: bigint = this.memstate.getValue(this.currentOp!.getInput(1)); // Offset to store at
    const spc: AddrSpace = getSpaceFromConst(this.currentOp!.getInput(0)); // Space to store in

    off = AddrSpace.addressToByte(off, spc.getWordSize());
    this.memstate.setValue(spc, off, this.currentOp!.getInput(2).size, val);
  }

  protected executeBranch(): void {
    this.setExecuteAddress(toAddress(this.currentOp!.getInput(0).getAddr()));
  }

  protected executeCbranch(): boolean {
    const cond: bigint = this.memstate.getValue(this.currentOp!.getInput(1));
    return (cond !== 0n);
  }

  protected executeBranchind(): void {
    const off: bigint = this.memstate.getValue(this.currentOp!.getInput(0));
    const rawAddr = this.currentOp!.getAddr();
    this.setExecuteAddress(new Address(rawAddr.getSpace() as any as AddrSpace, off));
  }

  protected executeCall(): void {
    this.setExecuteAddress(toAddress(this.currentOp!.getInput(0).getAddr()));
  }

  protected executeCallind(): void {
    const off: bigint = this.memstate.getValue(this.currentOp!.getInput(0));
    const rawAddr = this.currentOp!.getAddr();
    this.setExecuteAddress(new Address(rawAddr.getSpace() as any as AddrSpace, off));
  }

  protected executeCallother(): void {
    throw new LowlevelError('CALLOTHER emulation not currently supported');
  }

  protected executeMultiequal(): void {
    throw new LowlevelError('MULTIEQUAL appearing in unheritaged code?');
  }

  protected executeIndirect(): void {
    throw new LowlevelError('INDIRECT appearing in unheritaged code?');
  }

  protected executeSegmentOp(): void {
    throw new LowlevelError('SEGMENTOP emulation not currently supported');
  }

  protected executeCpoolRef(): void {
    throw new LowlevelError('Cannot currently emulate cpool operator');
  }

  protected executeNew(): void {
    throw new LowlevelError('Cannot currently emulate new operator');
  }
}

// ---------------------------------------------------------------------------
// PcodeEmitCache
// ---------------------------------------------------------------------------

/**
 * P-code emitter that dumps its raw Varnodes and PcodeOps to an in memory cache.
 *
 * This is used for emulation when full Varnode and PcodeOp objects aren't needed.
 */
export class PcodeEmitCache extends PcodeEmit {
  /** The cache of current p-code ops */
  private opcache: PcodeOpRaw[];
  /** The cache of current varnodes */
  private varcache: VarnodeData[];
  /** Array of behaviors for translating OpCode */
  private inst: (OpBehavior | null)[];
  /** Starting offset for defining temporaries in unique space */
  private uniq: number;

  /**
   * Constructor.
   *
   * Provide the emitter with the containers that will hold the cached p-code ops and varnodes.
   * @param ocache is the container for cached PcodeOpRaw
   * @param vcache is the container for cached VarnodeData
   * @param behaviors is the map of OpBehavior
   * @param uniqReserve is the starting offset for temporaries in the unique space
   */
  constructor(
    ocache: PcodeOpRaw[],
    vcache: VarnodeData[],
    behaviors: (OpBehavior | null)[],
    uniqReserve: bigint
  ) {
    super();
    this.opcache = ocache;
    this.varcache = vcache;
    this.inst = behaviors;
    this.uniq = Number(uniqReserve);
  }

  /**
   * Clone and cache a raw VarnodeData.
   *
   * Create an internal copy of the VarnodeData and cache it.
   * @param v is the incoming VarnodeData being dumped
   * @returns the cloned VarnodeData
   */
  private createVarnode(v: VarnodeData): VarnodeData {
    const res = new VarnodeData(v.space, v.offset, v.size);
    this.varcache.push(res);
    return res;
  }

  dump(
    addr: Address,
    opc: OpCode,
    outvar: VarnodeData | null,
    vars: VarnodeData[],
    isize: int4
  ): void {
    const op = new PcodeOpRaw();
    op.setSeqNum(addr, this.uniq);
    this.opcache.push(op);
    op.setBehavior(this.inst[opc]!);
    this.uniq += 1;
    if (outvar !== null) {
      const outvn = this.createVarnode(outvar);
      op.setOutput(outvn);
    }
    for (let i = 0; i < isize; ++i) {
      const invn = this.createVarnode(vars[i]);
      op.addInput(invn);
    }
  }
}

// ---------------------------------------------------------------------------
// EmulatePcodeCache
// ---------------------------------------------------------------------------

/**
 * A SLEIGH based implementation of the Emulate interface.
 *
 * This implementation uses a Translate object to translate machine instructions into
 * pcode and caches pcode ops for later use by the emulator. The pcode is cached as soon
 * as the execution address is set, either explicitly, or via branches and fallthrus. There
 * are additional methods for inspecting the pcode ops in the current instruction as a sequence.
 */
export class EmulatePcodeCache extends EmulateMemory {
  /** The SLEIGH translator */
  private trans: Translate;
  /** The cache of current p-code ops */
  private opcache: PcodeOpRaw[] = [];
  /** The cache of current varnodes */
  private varcache: VarnodeData[] = [];
  /** Map from OpCode to OpBehavior */
  private inst: (OpBehavior | null)[];
  /** The table of breakpoints */
  private breaktable: BreakTable;
  /** Address of current instruction being executed */
  private current_address: Address;
  /** true if next pcode op is start of instruction */
  private instruction_start: boolean = false;
  /** Index of current pcode op within machine instruction */
  private current_op: int4 = 0;
  /** Length of current instruction in bytes */
  private instruction_length: int4 = 0;

  /**
   * Pcode cache emulator constructor.
   * @param t is the SLEIGH translator
   * @param s is the MemoryState the emulator should manipulate
   * @param b is the table of breakpoints the emulator should invoke
   */
  constructor(t: Translate, s: MemoryState, b: BreakTable) {
    super(s);
    this.trans = t;
    this.inst = OpBehavior.registerInstructions(t);
    this.breaktable = b;
    this.breaktable.setEmulate(this);
    this.current_address = new Address();
  }

  /**
   * Clear the p-code cache.
   *
   * Free all the VarnodeData and PcodeOpRaw objects and clear the cache.
   */
  private clearCache(): void {
    this.opcache.length = 0;
    this.varcache.length = 0;
  }

  /**
   * Cache pcode for instruction at given address.
   *
   * This is a private routine which does the work of translating a machine instruction
   * into pcode, putting it into the cache, and setting up the iterators.
   * @param addr is the address of the instruction to translate
   */
  private createInstruction(addr: Address): void {
    this.clearCache();
    const emit = new PcodeEmitCache(this.opcache, this.varcache, this.inst, 0n);
    this.instruction_length = this.trans.oneInstruction(emit, addr);
    this.current_op = 0;
    this.instruction_start = true;
  }

  /**
   * Set-up currentOp and currentBehave.
   */
  private establishOp(): void {
    if (this.current_op < this.opcache.length) {
      this.currentOp = this.opcache[this.current_op];
      this.currentBehave = this.currentOp!.getBehavior();
      return;
    }
    this.currentOp = null;
    this.currentBehave = null;
  }

  /**
   * Execute fallthru semantics for the pcode cache.
   *
   * Update the iterator into the current pcode cache, and if necessary, generate
   * the pcode for the fallthru instruction and reset the iterator.
   */
  protected fallthruOp(): void {
    this.instruction_start = false;
    this.current_op += 1;
    if (this.current_op >= this.opcache.length) {
      this.current_address = this.current_address.add(BigInt(this.instruction_length));
      this.createInstruction(this.current_address);
    }
    this.establishOp();
  }

  /**
   * Execute branch (including relative branches).
   *
   * Since the full instruction is cached, we can do relative branches properly.
   */
  protected executeBranch(): void {
    const destaddr: Address = toAddress(this.currentOp!.getInput(0).getAddr());
    if (destaddr.isConstant()) {
      let id: number = Number(destaddr.getOffset());
      id = id + this.current_op;
      this.current_op = id;
      if (this.current_op === this.opcache.length) {
        this.fallthruOp();
      } else if (this.current_op < 0 || this.current_op >= this.opcache.length) {
        throw new LowlevelError('Bad intra-instruction branch');
      } else {
        this.establishOp();
      }
    } else {
      this.setExecuteAddress(destaddr);
    }
  }

  /**
   * Execute breakpoint for this user-defined op.
   *
   * Look for a breakpoint for the given user-defined op and invoke it.
   * If it doesn't exist, or doesn't replace the action, throw an exception.
   */
  protected executeCallother(): void {
    if (!this.breaktable.doPcodeOpBreak(this.currentOp!))
      throw new LowlevelError('Userop not hooked');
    this.fallthruOp();
  }

  /**
   * Return true if we are at an instruction start.
   *
   * Since the emulator can single step through individual pcode operations, the machine state
   * may be halted in the middle of a single machine instruction, unlike conventional debuggers.
   * This routine can be used to determine if execution is actually at the beginning of a machine
   * instruction.
   * @returns true if the next pcode operation is at the start of the instruction translation
   */
  isInstructionStart(): boolean {
    return this.instruction_start;
  }

  /**
   * Return number of pcode ops in translation of current instruction.
   *
   * A typical machine instruction translates into a sequence of pcode ops.
   * @returns the number of ops in the sequence
   */
  numCurrentOps(): int4 {
    return this.opcache.length;
  }

  /**
   * Get the index of current pcode op within current instruction.
   *
   * This routine can be used to determine where, within the sequence of ops in the translation
   * of the entire machine instruction, the currently executing op is.
   * @returns the index of the current (next) pcode op.
   */
  getCurrentOpIndex(): int4 {
    return this.current_op;
  }

  /**
   * Get pcode op in current instruction translation by index.
   *
   * This routine can be used to examine ops other than the currently executing op in the
   * machine instruction's translation sequence.
   * @param i is the desired op index
   * @returns the pcode op at the indicated index
   */
  getOpByIndex(i: int4): PcodeOpRaw {
    return this.opcache[i];
  }

  /**
   * Set current execution address.
   *
   * Set the current execution address and cache the pcode translation of the machine instruction
   * at that address.
   * @param addr is the address where execution should continue
   */
  setExecuteAddress(addr: Address): void {
    this.current_address = new Address(addr); // Copy addr BEFORE calling createInstruction
                                               // as it calls clear and may delete addr
    this.createInstruction(this.current_address);
    this.establishOp();
  }

  /**
   * Get current execution address.
   * @returns the currently executing machine address
   */
  getExecuteAddress(): Address {
    return this.current_address;
  }

  /**
   * Execute (the rest of) a single machine instruction.
   *
   * This routine executes an entire machine instruction at once, as a conventional debugger step
   * function would do. If execution is at the start of an instruction, the breakpoints are checked
   * and invoked as needed for the current address. If this routine is invoked while execution is
   * in the middle of a machine instruction, execution is continued until the current instruction
   * completes.
   */
  executeInstruction(): void {
    if (this.instruction_start) {
      if (this.breaktable.doAddressBreak(this.current_address))
        return;
    }
    do {
      this.executeCurrentOp();
    } while (!this.instruction_start);
  }
}
