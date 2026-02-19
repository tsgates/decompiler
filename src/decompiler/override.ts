/**
 * @file override.ts
 * @description A system for sending override commands to the decompiler.
 *
 * Translated from Ghidra's override.hh / override.cc
 */

import { Address } from '../core/address.js';
import { AddrSpace } from '../core/space.js';
import { ATTRIB_DELAY } from '../core/space.js';
import {
  Encoder,
  Decoder,
  ElementId,
  AttributeId,
  ATTRIB_SPACE,
  ATTRIB_TYPE,
} from '../core/marshal.js';
import { LowlevelError } from '../core/error.js';

// Cast the plain-object attribute from space.ts to AttributeId for type compatibility
const ATTRIB_DELAY_ID = ATTRIB_DELAY as unknown as AttributeId;

// Forward type declarations for types from not-yet-written modules
type Architecture = any;
type Funcdata = any;
type FuncCallSpecs = any;
type FuncProto = any;

// ---- Element IDs specific to override ----

export const ELEM_DEADCODEDELAY = new ElementId('deadcodedelay', 218);
export const ELEM_FLOW = new ElementId('flow', 219);
export const ELEM_FORCEGOTO = new ElementId('forcegoto', 220);
export const ELEM_INDIRECTOVERRIDE = new ElementId('indirectoverride', 221);
export const ELEM_MULTISTAGEJUMP = new ElementId('multistagejump', 222);
export const ELEM_OVERRIDE = new ElementId('override', 223);
export const ELEM_PROTOOVERRIDE = new ElementId('protooverride', 224);

/**
 * A container of commands that override the decompiler's default behavior for a single function.
 *
 * Information about a particular function that can be overridden includes:
 *   - sub-functions:  How they are called and where they call to
 *   - jumptables:     Mark indirect jumps that need multistage analysis
 *   - deadcode:       Details about how dead code is eliminated
 *   - data-flow:      Override the interpretation of specific branch instructions
 *
 * Commands exist independently of the main data-flow, control-flow, and symbol structures
 * and survive decompilation restart. A few analyses, mid transformation, insert a new command
 * to fix a problem that was discovered too late and then force a restart via Funcdata.setRestartPending()
 *
 * The class accepts new commands via the insert* methods. The decompiler applies them by
 * calling the apply* or get* methods.
 */
export class Override {
  /** No override */
  static readonly NONE = 0;
  /** Replace primary CALL or RETURN with suitable BRANCH operation */
  static readonly BRANCH = 1;
  /** Replace primary BRANCH or RETURN with suitable CALL operation */
  static readonly CALL = 2;
  /** Replace primary BRANCH or RETURN with suitable CALL/RETURN operation */
  static readonly CALL_RETURN = 3;
  /** Replace primary BRANCH or CALL with a suitable RETURN operation */
  static readonly RETURN = 4;

  /** Force goto on jump at targetpc to destpc */
  private forcegoto: Map<string, [Address, Address]> = new Map();
  /** Delay count indexed by address space */
  private deadcodedelay: number[] = [];
  /** Override indirect at call-point into direct to addr */
  private indirectover: Map<string, [Address, Address]> = new Map();
  /** Override prototype at call-point */
  private protoover: Map<string, [Address, FuncProto]> = new Map();
  /** Addresses of indirect jumps that need multistage recovery */
  private multistagejump: Address[] = [];
  /** Override the CALL <-> BRANCH */
  private flowoverride: Map<string, [Address, number]> = new Map();

  /** Destructor equivalent: clear all overrides */
  dispose(): void {
    this.clear();
  }

  /** Clear the entire set of overrides */
  private clear(): void {
    // In TypeScript, no manual memory management needed for FuncProto objects.
    // Just clear all collections.
    this.forcegoto.clear();
    this.deadcodedelay = [];
    this.indirectover.clear();
    this.protoover.clear();
    this.multistagejump = [];
    this.flowoverride.clear();
  }

  /**
   * Generate warning message related to a dead code delay.
   *
   * This is triggered by the insertDeadcodeDelay() command on a specific address space.
   * @param index - the index of the address space
   * @param glb - the Architecture object
   * @returns the generated message
   */
  private static generateDeadcodeDelayMessage(index: number, glb: Architecture): string {
    const spc: AddrSpace = glb.getSpace(index);
    const res = 'Restarted to delay deadcode elimination for space: ' + spc.getName();
    return res;
  }

  /**
   * Force a specific branch instruction to be an unstructured goto.
   *
   * The command is specified as the address of the branch instruction and
   * the destination address of the branch. The decompiler will automatically
   * mark this as unstructured when trying to structure the control-flow.
   * @param targetpc - the address of the branch instruction
   * @param destpc - the destination address of the branch
   */
  insertForceGoto(targetpc: Address, destpc: Address): void {
    this.forcegoto.set(Override.addrKey(targetpc), [targetpc, destpc]);
  }

  /**
   * Override the number of passes that are executed before dead-code elimination starts.
   *
   * Every address space has an assigned delay (which may be zero) before a PcodeOp
   * involving a Varnode in that address space can be eliminated. This command allows the
   * delay for a specific address space to be increased so that new Varnode accesses can be discovered.
   * @param spc - the address space to modify
   * @param delay - the size of the delay (in passes)
   */
  insertDeadcodeDelay(spc: AddrSpace, delay: number): void {
    while (this.deadcodedelay.length <= spc.getIndex()) {
      this.deadcodedelay.push(-1);
    }
    this.deadcodedelay[spc.getIndex()] = delay;
  }

  /**
   * Check if a delay override is already installed for an address space.
   * @param spc - the address space
   * @returns true if an override has already been installed
   */
  hasDeadcodeDelay(spc: AddrSpace): boolean {
    const index: number = spc.getIndex();
    if (index >= this.deadcodedelay.length) return false;
    const val: number = this.deadcodedelay[index];
    if (val === -1) return false;
    return val !== spc.getDeadcodeDelay();
  }

  /**
   * Override an indirect call turning it into a direct call.
   *
   * The command consists of the address of the indirect call instruction and
   * the target address of the direct call.
   * @param callpoint - the address of the indirect call
   * @param directcall - the target address of the direct call
   */
  insertIndirectOverride(callpoint: Address, directcall: Address): void {
    this.indirectover.set(Override.addrKey(callpoint), [callpoint, directcall]);
  }

  /**
   * Override the assumed function prototype at a specific call site.
   *
   * The exact input and output storage locations are overridden for a
   * specific call instruction (direct or indirect).
   * @param callpoint - the address of the call instruction
   * @param p - the overriding function prototype
   */
  insertProtoOverride(callpoint: Address, p: FuncProto): void {
    // No need to explicitly delete pre-existing override in TS (GC handles it)
    p.setOverride(true);  // Mark this as an override
    this.protoover.set(Override.addrKey(callpoint), [callpoint, p]);  // Take ownership of the object
  }

  /**
   * Flag an indirect jump for multistage analysis.
   * @param addr - the address of the indirect jump
   */
  insertMultistageJump(addr: Address): void {
    this.multistagejump.push(addr);
  }

  /**
   * Mark a branch instruction with a different flow type.
   *
   * Change the interpretation of a BRANCH, CALL, or RETURN.
   * @param addr - the address of the branch instruction
   * @param type - the type of flow that should be forced
   */
  insertFlowOverride(addr: Address, type: number): void {
    this.flowoverride.set(Override.addrKey(addr), [addr, type]);
  }

  /**
   * Look for and apply a function prototype override.
   *
   * Given a call point, look for a prototype override and copy
   * the call specification in.
   * @param data - the (calling) function
   * @param fspecs - a reference to the call specification
   */
  applyPrototype(data: Funcdata, fspecs: FuncCallSpecs): void {
    if (this.protoover.size !== 0) {
      const key = Override.addrKey(fspecs.getOp().getAddr());
      const entry = this.protoover.get(key);
      if (entry !== undefined) {
        fspecs.copy(entry[1]);
      }
    }
  }

  /**
   * Look for and apply destination overrides of indirect calls.
   *
   * Given an indirect call, look for any overrides, then copy in
   * the overriding target address of the direct call.
   * @param data - the (calling) function
   * @param fspecs - a reference to the call specification
   */
  applyIndirect(data: Funcdata, fspecs: FuncCallSpecs): void {
    if (this.indirectover.size !== 0) {
      const key = Override.addrKey(fspecs.getOp().getAddr());
      const entry = this.indirectover.get(key);
      if (entry !== undefined) {
        fspecs.setAddress(entry[1]);
      }
    }
  }

  /**
   * Check for a multistage marker for a specific indirect jump.
   *
   * Given the address of an indirect jump, look for the multistage command.
   * @param addr - the address of the indirect jump
   * @returns true if multistage analysis is flagged for this address
   */
  queryMultistageJumptable(addr: Address): boolean {
    for (let i = 0; i < this.multistagejump.length; ++i) {
      if (this.multistagejump[i].equals(addr))
        return true;
    }
    return false;
  }

  /**
   * Push all the force-goto overrides into the function.
   * @param data - the function
   */
  applyForceGoto(data: Funcdata): void {
    for (const [_key, [targetpc, destpc]] of this.forcegoto) {
      data.forceGoto(targetpc, destpc);
    }
  }

  /**
   * Apply any dead-code delay overrides.
   *
   * Look for delays of each address space and apply them to the Heritage object.
   * @param data - the function
   */
  applyDeadCodeDelay(data: Funcdata): void {
    const glb: Architecture = data.getArch();
    for (let i = 0; i < this.deadcodedelay.length; ++i) {
      const delay: number = this.deadcodedelay[i];
      if (delay < 0) continue;
      const spc: AddrSpace = glb.getSpace(i);
      data.setDeadCodeDelay(spc, delay);
    }
  }

  /** Are there any flow overrides */
  hasFlowOverride(): boolean {
    return this.flowoverride.size !== 0;
  }

  /**
   * Return the particular flow override at a given address.
   * @param addr - the address of a branch instruction
   * @returns the override type
   */
  getFlowOverride(addr: Address): number {
    const key = Override.addrKey(addr);
    const entry = this.flowoverride.get(key);
    if (entry === undefined) return Override.NONE;
    return entry[1];
  }

  /**
   * Dump a description of the overrides to stream.
   *
   * Give a description of each override, one per line, that is suitable for debug.
   * @param s - the output stream
   * @param glb - the Architecture
   */
  printRaw(s: { write(str: string): void }, glb: Architecture): void {
    for (const [_key, [targetpc, destpc]] of this.forcegoto) {
      s.write('force goto at ' + targetpc.toString() + ' jumping to ' + destpc.toString() + '\n');
    }

    for (let i = 0; i < this.deadcodedelay.length; ++i) {
      if (this.deadcodedelay[i] < 0) continue;
      const spc: AddrSpace = glb.getSpace(i);
      s.write('dead code delay on ' + spc.getName() + ' set to ' + this.deadcodedelay[i].toString() + '\n');
    }

    for (const [_key, [callpoint, directcall]] of this.indirectover) {
      s.write('override indirect at ' + callpoint.toString() + ' to call directly to ' + directcall.toString() + '\n');
    }

    for (const [_key, [callpoint, proto]] of this.protoover) {
      s.write('override prototype at ' + callpoint.toString() + ' to ');
      proto.printRaw('func', s);
      s.write('\n');
    }
  }

  /**
   * Create warning messages that describe current overrides.
   *
   * Messages are designed to be displayed in the function header comment.
   * @param messagelist - will hold the generated list of messages
   * @param glb - the Architecture
   */
  generateOverrideMessages(messagelist: string[], glb: Architecture): void {
    // Generate deadcode delay messages
    for (let i = 0; i < this.deadcodedelay.length; ++i) {
      if (this.deadcodedelay[i] >= 0) {
        messagelist.push(Override.generateDeadcodeDelayMessage(i, glb));
      }
    }
  }

  /**
   * Encode the override commands to a stream.
   *
   * All the commands are written as children of a root <override> element.
   * @param encoder - the stream encoder
   * @param glb - the Architecture
   */
  encode(encoder: Encoder, glb: Architecture): void {
    if (this.forcegoto.size === 0 && this.deadcodedelay.length === 0 &&
        this.indirectover.size === 0 && this.protoover.size === 0 &&
        this.multistagejump.length === 0 && this.flowoverride.size === 0) {
      return;
    }
    encoder.openElement(ELEM_OVERRIDE);

    for (const [_key, [targetpc, destpc]] of this.forcegoto) {
      encoder.openElement(ELEM_FORCEGOTO);
      targetpc.encode(encoder);
      destpc.encode(encoder);
      encoder.closeElement(ELEM_FORCEGOTO);
    }

    for (let i = 0; i < this.deadcodedelay.length; ++i) {
      if (this.deadcodedelay[i] < 0) continue;
      const spc: AddrSpace = glb.getSpace(i);
      encoder.openElement(ELEM_DEADCODEDELAY);
      encoder.writeSpace(ATTRIB_SPACE, spc);
      encoder.writeSignedInteger(ATTRIB_DELAY_ID, this.deadcodedelay[i]);
      encoder.closeElement(ELEM_DEADCODEDELAY);
    }

    for (const [_key, [callpoint, directcall]] of this.indirectover) {
      encoder.openElement(ELEM_INDIRECTOVERRIDE);
      callpoint.encode(encoder);
      directcall.encode(encoder);
      encoder.closeElement(ELEM_INDIRECTOVERRIDE);
    }

    for (const [_key, [callpoint, proto]] of this.protoover) {
      encoder.openElement(ELEM_PROTOOVERRIDE);
      callpoint.encode(encoder);
      proto.encode(encoder);
      encoder.closeElement(ELEM_PROTOOVERRIDE);
    }

    for (let i = 0; i < this.multistagejump.length; ++i) {
      encoder.openElement(ELEM_MULTISTAGEJUMP);
      this.multistagejump[i].encode(encoder);
      encoder.closeElement(ELEM_MULTISTAGEJUMP);
    }

    for (const [_key, [addr, type]] of this.flowoverride) {
      encoder.openElement(ELEM_FLOW);
      encoder.writeString(ATTRIB_TYPE, Override.typeToString(type));
      addr.encode(encoder);
      encoder.closeElement(ELEM_FLOW);
    }

    encoder.closeElement(ELEM_OVERRIDE);
  }

  /**
   * Parse an <override> element containing override commands.
   * @param decoder - the stream decoder
   * @param glb - the Architecture
   */
  decode(decoder: Decoder, glb: Architecture): void {
    const elemId: number = decoder.openElementId(ELEM_OVERRIDE);
    for (;;) {
      const subId: number = decoder.openElement();
      if (subId === 0) break;
      if (subId === ELEM_INDIRECTOVERRIDE.id) {
        const callpoint: Address = Address.decode(decoder);
        const directcall: Address = Address.decode(decoder);
        this.insertIndirectOverride(callpoint, directcall);
      }
      else if (subId === ELEM_PROTOOVERRIDE.id) {
        const callpoint: Address = Address.decode(decoder);
        const fp: FuncProto = new (Override._FuncProtoClass as any)();
        fp.setInternal(glb.defaultfp, glb.types.getTypeVoid());
        fp.decode(decoder, glb);
        this.insertProtoOverride(callpoint, fp);
      }
      else if (subId === ELEM_FORCEGOTO.id) {
        const targetpc: Address = Address.decode(decoder);
        const destpc: Address = Address.decode(decoder);
        this.insertForceGoto(targetpc, destpc);
      }
      else if (subId === ELEM_DEADCODEDELAY.id) {
        const delay: number = decoder.readSignedIntegerById(ATTRIB_DELAY_ID);
        const spc: AddrSpace = decoder.readSpaceById(ATTRIB_SPACE) as any as AddrSpace;
        if (delay < 0) {
          throw new LowlevelError('Bad deadcodedelay tag');
        }
        this.insertDeadcodeDelay(spc, delay);
      }
      else if (subId === ELEM_MULTISTAGEJUMP.id) {
        const callpoint: Address = Address.decode(decoder);
        this.insertMultistageJump(callpoint);
      }
      else if (subId === ELEM_FLOW.id) {
        const type: number = Override.stringToType(decoder.readStringById(ATTRIB_TYPE));
        const addr: Address = Address.decode(decoder);
        if (type === Override.NONE || addr.isInvalid()) {
          throw new LowlevelError('Bad flowoverride tag');
        }
        this.insertFlowOverride(addr, type);
      }
      decoder.closeElement(subId);
    }
    decoder.closeElement(elemId);
  }

  /**
   * Convert a flow override type to a string.
   * @param tp - the override type
   * @returns the corresponding name string
   */
  static typeToString(tp: number): string {
    if (tp === Override.BRANCH) return 'branch';
    if (tp === Override.CALL) return 'call';
    if (tp === Override.CALL_RETURN) return 'callreturn';
    if (tp === Override.RETURN) return 'return';
    return 'none';
  }

  /**
   * Convert a string to a flow override type.
   * @param nm - the override name
   * @returns the override enumeration type
   */
  static stringToType(nm: string): number {
    if (nm === 'branch') return Override.BRANCH;
    else if (nm === 'call') return Override.CALL;
    else if (nm === 'callreturn') return Override.CALL_RETURN;
    else if (nm === 'return') return Override.RETURN;
    return Override.NONE;
  }

  // ---- Internal helpers ----

  /**
   * Generate a stable string key from an Address for use in Map lookups.
   * This emulates the C++ std::map<Address,...> ordering by producing a unique
   * string from the address space index and offset.
   */
  private static addrKey(addr: Address): string {
    const space = addr.getSpace();
    if (space === null) return 'null:0';
    return space.getIndex().toString() + ':' + addr.getOffset().toString();
  }

  /**
   * Injectable FuncProto constructor reference. Because FuncProto comes from
   * fspec.ts (a forward-declared module), set this to the actual class at
   * module-initialization time to allow `new` in decode().
   *
   * Usage:  Override._FuncProtoClass = FuncProto;
   */
  static _FuncProtoClass: any = null;
}
