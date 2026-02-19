/**
 * @file userop.ts
 * @description Classes for more detailed definitions of user defined p-code operations.
 * Translated from Ghidra's userop.hh / userop.cc
 */

import type { int4, uint4, uintb } from '../core/types.js';
import { LowlevelError } from '../core/error.js';
import { OpCode } from '../core/opcodes.js';
import { Address } from '../core/address.js';
import type { AddrSpace } from '../core/space.js';
import { VarnodeData } from '../core/pcoderaw.js';
import {
  AttributeId,
  ElementId,
  Encoder,
  Decoder,
  ATTRIB_FORMAT,
  ATTRIB_NAME,
  ATTRIB_SPACE,
} from '../core/marshal.js';
import {
  InjectPayload,
  ELEM_ADDR_PCODE,
  ELEM_CASE_PCODE,
  ELEM_DEFAULT_PCODE,
  ELEM_PCODE,
  ELEM_SIZE_PCODE,
} from './pcodeinject.js';
import type { Datatype } from './type.js';

// ---------------------------------------------------------------------------
// Forward type declarations for not-yet-written modules
// ---------------------------------------------------------------------------

type Architecture = any;
type PcodeOp = any;
type Varnode = any;
type Funcdata = any;
type SymbolEntry = any;
type ExecutablePcode = any;

// ---------------------------------------------------------------------------
// Marshaling Attribute / Element IDs
// ---------------------------------------------------------------------------

export const ATTRIB_FARPOINTER = new AttributeId('farpointer', 85);
export const ATTRIB_INPUTOP    = new AttributeId('inputop', 86);
export const ATTRIB_OUTPUTOP   = new AttributeId('outputop', 87);
export const ATTRIB_USEROP     = new AttributeId('userop', 88);

export const ELEM_CONSTRESOLVE = new ElementId('constresolve', 127);
export const ELEM_JUMPASSIST   = new ElementId('jumpassist', 128);
export const ELEM_SEGMENTOP    = new ElementId('segmentop', 129);

// ---------------------------------------------------------------------------
// UserPcodeOp
// ---------------------------------------------------------------------------

/**
 * The base class for a detailed definition of a user-defined p-code operation.
 *
 * Within the raw p-code framework, the CALLOTHER opcode represents a user defined
 * operation. At this level, the operation is just a placeholder for inputs and outputs
 * to some black-box procedure. The first input parameter (index 0) must be a constant
 * id associated with the particular procedure. Classes derived off of this base class
 * provide a more specialized definition of an operation/procedure.
 */
export abstract class UserPcodeOp {
  /** Enumeration of different boolean properties that can be assigned to a CALLOTHER */
  static readonly annotation_assignment = 1;
  static readonly no_operator = 2;
  static readonly display_string = 4;

  /** User-op class encoded as an enum */
  static readonly unspecialized = 1;
  static readonly injected = 2;
  static readonly volatile_read = 3;
  static readonly volatile_write = 4;
  static readonly segment = 5;
  static readonly jumpassist = 6;
  static readonly string_data = 7;
  static readonly datatype = 8;

  /** Built-in id for the InternalStringOp */
  static readonly BUILTIN_STRINGDATA: uint4 = 0x10000000;
  /** Built-in id for VolatileReadOp */
  static readonly BUILTIN_VOLATILE_READ: uint4 = 0x10000001;
  /** Built-in id for VolatileWriteOp */
  static readonly BUILTIN_VOLATILE_WRITE: uint4 = 0x10000002;
  /** Built-in id for memcpy */
  static readonly BUILTIN_MEMCPY: uint4 = 0x10000003;
  /** Built-in id for strcpy */
  static readonly BUILTIN_STRNCPY: uint4 = 0x10000004;
  /** Built-in id for wcsncpy */
  static readonly BUILTIN_WCSNCPY: uint4 = 0x10000005;

  protected name: string;
  protected glb: Architecture;
  protected type: uint4;
  protected useropindex: int4;
  protected flags: uint4;

  constructor(nm: string, g: Architecture, tp: uint4, ind: int4) {
    this.name = nm;
    this.glb = g;
    this.type = tp;
    this.useropindex = ind;
    this.flags = 0;
  }

  /** Get the low-level name of the p-code op */
  getName(): string {
    return this.name;
  }

  /** Get the encoded class type */
  getType(): uint4 {
    return this.type;
  }

  /** Get the constant id of the op */
  getIndex(): int4 {
    return this.useropindex;
  }

  /** Get display type (0=functional) */
  getDisplay(): uint4 {
    return this.flags & (UserPcodeOp.annotation_assignment | UserPcodeOp.no_operator | UserPcodeOp.display_string);
  }

  /**
   * Get the symbol representing this operation in decompiled code.
   * @param op is the operation (in context) where a symbol is needed
   * @returns the symbol as a string
   */
  getOperatorName(op: PcodeOp): string {
    return this.name;
  }

  /**
   * Return the output data-type of the user-op if specified.
   * @param op is the instantiation of the user-op
   * @returns the data-type or null to indicate the data-type is unspecified
   */
  getOutputLocal(op: PcodeOp): Datatype | null {
    return null;
  }

  /**
   * Return the input data-type to the user-op in the given slot.
   * @param op is the instantiation of the user-op
   * @param slot is the given input slot
   * @returns the data-type or null to indicate the data-type is unspecified
   */
  getInputLocal(op: PcodeOp, slot: int4): Datatype | null {
    return null;
  }

  /**
   * Assign a size to an annotation input to this userop.
   * @param vn is the annotation Varnode
   * @param op is the specific PcodeOp instance of this userop
   */
  extractAnnotationSize(vn: Varnode, op: PcodeOp): int4 {
    throw new LowlevelError("Unexpected annotation input for CALLOTHER " + this.name);
  }

  /**
   * Restore the detailed description from a stream element.
   * @param decoder is the stream decoder
   */
  abstract decode(decoder: Decoder): void;
}

// ---------------------------------------------------------------------------
// UnspecializedPcodeOp
// ---------------------------------------------------------------------------

/**
 * A user defined p-code op with no specialization.
 *
 * This class is used by the manager for CALLOTHER indices that have not been
 * mapped to a specialization.
 */
export class UnspecializedPcodeOp extends UserPcodeOp {
  constructor(nm: string, g: Architecture, ind: int4) {
    super(nm, g, UserPcodeOp.unspecialized, ind);
  }

  decode(_decoder: Decoder): void {
    // No additional decoding needed
  }
}

// ---------------------------------------------------------------------------
// DatatypeUserOp
// ---------------------------------------------------------------------------

/**
 * Generic user defined operation that provides input/output data-types.
 *
 * The CALLOTHER acts a source of data-type information within data-flow.
 */
export class DatatypeUserOp extends UserPcodeOp {
  private outType: Datatype | null;
  private inTypes: Datatype[] = [];

  constructor(
    nm: string,
    g: Architecture,
    ind: int4,
    out: Datatype | null,
    in0: Datatype | null = null,
    in1: Datatype | null = null,
    in2: Datatype | null = null,
    in3: Datatype | null = null
  ) {
    super(nm, g, UserPcodeOp.datatype, ind);
    this.outType = out;
    if (in0 !== null) this.inTypes.push(in0);
    if (in1 !== null) this.inTypes.push(in1);
    if (in2 !== null) this.inTypes.push(in2);
    if (in3 !== null) this.inTypes.push(in3);
  }

  override getOutputLocal(_op: PcodeOp): Datatype | null {
    return this.outType;
  }

  override getInputLocal(_op: PcodeOp, slot: int4): Datatype | null {
    slot -= 1;
    if (slot >= 0 && slot < this.inTypes.length) {
      return this.inTypes[slot];
    }
    return null;
  }

  decode(_decoder: Decoder): void {
    // No additional decoding needed
  }
}

// ---------------------------------------------------------------------------
// InjectedUserOp
// ---------------------------------------------------------------------------

/**
 * A user defined operation that is injected with other p-code.
 *
 * The system can configure user defined p-code ops as a hook point within the
 * control-flow where other p-code is injected during analysis. This class maps
 * the raw CALLOTHER p-code op, via its constant id, to its injection object.
 */
export class InjectedUserOp extends UserPcodeOp {
  private injectid: uint4;

  constructor(nm: string, g: Architecture, ind: int4, injid: int4) {
    super(nm, g, UserPcodeOp.injected, ind);
    this.injectid = injid;
  }

  /** Get the id of the injection object */
  getInjectId(): uint4 {
    return this.injectid;
  }

  decode(decoder: Decoder): void {
    this.injectid = (this.glb as any).pcodeinjectlib.decodeInject(
      "userop", "", InjectPayload.CALLOTHERFIXUP_TYPE, decoder
    );
    this.name = (this.glb as any).pcodeinjectlib.getCallOtherTarget(this.injectid);
    const base: UserPcodeOp | null = (this.glb as any).userops.getOp(this.name);
    // This tag overrides the base functionality of a userop
    // so the core userop name and index may already be defined
    if (base === null) {
      throw new LowlevelError("Unknown userop name in <callotherfixup>: " + this.name);
    }
    if (!(base instanceof UnspecializedPcodeOp)) {
      // Make sure the userop isn't used for some other purpose
      throw new LowlevelError("<callotherfixup> overloads userop with another purpose: " + this.name);
    }
    this.useropindex = base.getIndex(); // Get the index from the core userop
  }
}

// ---------------------------------------------------------------------------
// VolatileOp
// ---------------------------------------------------------------------------

/**
 * A base class for operations that access volatile memory.
 *
 * The decompiler models volatile memory by converting any direct read or write of
 * the memory to a function that accesses the memory.
 */
export abstract class VolatileOp extends UserPcodeOp {
  /**
   * Append a suffix to a string encoding a specific size.
   * @param base is the string to append the suffix to
   * @param size is the size to encode expressed as the number of bytes
   * @returns the appended string
   */
  protected static appendSize(base: string, size: int4): string {
    if (size === 1) return base + "_1";
    if (size === 2) return base + "_2";
    if (size === 4) return base + "_4";
    if (size === 8) return base + "_8";
    return base + '_' + size.toString();
  }

  constructor(nm: string, g: Architecture, tp: uint4, ind: int4) {
    super(nm, g, tp, ind);
  }

  /** Currently volatile ops only need their name */
  decode(_decoder: Decoder): void {
    // No additional decoding needed
  }
}

// ---------------------------------------------------------------------------
// VolatileReadOp
// ---------------------------------------------------------------------------

/**
 * An operation that reads from volatile memory.
 *
 * This CALLOTHER p-code operation takes as its input parameter, after the constant id,
 * a reference Varnode to the memory being read. The output returned by this operation
 * is the actual value read from memory.
 */
export class VolatileReadOp extends VolatileOp {
  constructor(nm: string, g: Architecture, functional: boolean) {
    super(nm, g, UserPcodeOp.volatile_read, UserPcodeOp.BUILTIN_VOLATILE_READ);
    this.flags = functional ? 0 : UserPcodeOp.no_operator;
  }

  override getOperatorName(op: PcodeOp): string {
    if ((op as any).getOut() === null) return this.name;
    return VolatileOp.appendSize(this.name, (op as any).getOut().getSize());
  }

  override getOutputLocal(op: PcodeOp): Datatype | null {
    if (!(op as any).doesSpecialPropagation()) return null;
    const addr: Address = (op as any).getIn(1).getAddr(); // Address of volatile memory
    const size: int4 = (op as any).getOut().getSize();     // Size of memory being read
    const result = (this.glb as any).symboltab.getGlobalScope()
      .queryProperties(addr, size, (op as any).getAddr());
    if (result.entry !== null) {
      return result.entry.getSizedType(addr, size);
    }
    return null;
  }

  override extractAnnotationSize(vn: Varnode, op: PcodeOp): int4 {
    const outvn = (op as any).getOut();
    if (outvn !== null) {
      return (op as any).getOut().getSize(); // Get size from output of read function
    }
    return 1;
  }
}

// ---------------------------------------------------------------------------
// VolatileWriteOp
// ---------------------------------------------------------------------------

/**
 * An operation that writes to volatile memory.
 *
 * This CALLOTHER p-code operation takes as its input parameters:
 *   - Constant id
 *   - Reference Varnode to the memory being written
 *   - The Varnode value being written to the memory
 */
export class VolatileWriteOp extends VolatileOp {
  constructor(nm: string, g: Architecture, functional: boolean) {
    super(nm, g, UserPcodeOp.volatile_write, UserPcodeOp.BUILTIN_VOLATILE_WRITE);
    this.flags = functional ? 0 : UserPcodeOp.annotation_assignment;
  }

  override getOperatorName(op: PcodeOp): string {
    if ((op as any).numInput() < 3) return this.name;
    return VolatileOp.appendSize(this.name, (op as any).getIn(2).getSize());
  }

  override getInputLocal(op: PcodeOp, slot: int4): Datatype | null {
    if (!(op as any).doesSpecialPropagation() || slot !== 2) return null;
    const addr: Address = (op as any).getIn(1).getAddr(); // Address of volatile memory
    const size: int4 = (op as any).getIn(2).getSize();     // Size of memory being written
    const result = (this.glb as any).symboltab.getGlobalScope()
      .queryProperties(addr, size, (op as any).getAddr());
    if (result.entry !== null) {
      return result.entry.getSizedType(addr, size);
    }
    return null;
  }

  override extractAnnotationSize(vn: Varnode, op: PcodeOp): int4 {
    return (op as any).getIn(2).getSize(); // Get size from the 3rd parameter of write function
  }
}

// ---------------------------------------------------------------------------
// TermPatternOp
// ---------------------------------------------------------------------------

/**
 * A user defined p-code op that has a dynamically defined procedure.
 *
 * The behavior of this op on constant inputs can be dynamically defined.
 * This class defines a unify() method that picks out the input varnodes to the
 * operation, given the root PcodeOp.
 */
export abstract class TermPatternOp extends UserPcodeOp {
  constructor(nm: string, g: Architecture, tp: uint4, ind: int4) {
    super(nm, g, tp, ind);
  }

  /** Get the number of input Varnodes expected */
  abstract getNumVariableTerms(): int4;

  /**
   * Gather the formal input Varnode objects given the root PcodeOp.
   * @param data is the function being analyzed
   * @param op is the root operation
   * @param bindlist will hold the ordered list of input Varnodes
   * @returns true if the requisite inputs were found
   */
  abstract unify(data: Funcdata, op: PcodeOp, bindlist: Varnode[]): boolean;

  /**
   * Compute the output value of this operation, given constant inputs.
   * @param input is the ordered list of constant inputs
   * @returns the resulting value as a constant
   */
  abstract execute(input: uintb[]): uintb;

  decode(_decoder: Decoder): void {
    // Subclasses override as needed
  }
}

// ---------------------------------------------------------------------------
// SegmentOp
// ---------------------------------------------------------------------------

/**
 * The segmented address operator.
 *
 * This op is a placeholder for address mappings involving segments.
 * The output of the operator is always a full low-level pointer.
 * The operator takes two inputs: the base or segment and the high-level near pointer.
 */
export class SegmentOp extends TermPatternOp {
  private spc: AddrSpace | null = null;
  private injectId: int4 = -1;
  private baseinsize: int4 = 0;
  private innerinsize: int4 = 0;
  private supportsfarpointer: boolean = false;
  private constresolve: VarnodeData;

  constructor(nm: string, g: Architecture, ind: int4) {
    super(nm, g, UserPcodeOp.segment, ind);
    this.constresolve = new VarnodeData(null, 0n, 0);
  }

  /** Get the address space being pointed to */
  getSpace(): AddrSpace | null {
    return this.spc;
  }

  /** Return true, if this op supports far pointers */
  hasFarPointerSupport(): boolean {
    return this.supportsfarpointer;
  }

  /** Get size in bytes of the base/segment value */
  getBaseSize(): int4 {
    return this.baseinsize;
  }

  /** Get size in bytes of the near value */
  getInnerSize(): int4 {
    return this.innerinsize;
  }

  /** Get the default register for resolving indirect segments */
  getResolve(): VarnodeData {
    return this.constresolve;
  }

  override getNumVariableTerms(): int4 {
    if (this.baseinsize !== 0) return 2;
    return 1;
  }

  override unify(data: Funcdata, op: PcodeOp, bindlist: Varnode[]): boolean {
    let basevn: Varnode;
    let innervn: Varnode;

    // Segmenting is done by a user defined p-code op, so this is what we look for
    if ((op as any).code() !== OpCode.CPUI_CALLOTHER) return false;
    if ((op as any).getIn(0).getOffset() !== BigInt(this.useropindex)) return false;
    if ((op as any).numInput() !== 3) return false;
    innervn = (op as any).getIn(1);
    if (this.baseinsize !== 0) {
      basevn = (op as any).getIn(1);
      innervn = (op as any).getIn(2);
      if ((basevn as any).isConstant()) {
        basevn = (data as any).newConstant(this.baseinsize, (basevn as any).getOffset());
      }
      bindlist[0] = basevn;
    } else {
      bindlist[0] = null;
    }
    if ((innervn as any).isConstant()) {
      innervn = (data as any).newConstant(this.innerinsize, (innervn as any).getOffset());
    }
    bindlist[1] = innervn;
    return true;
  }

  override execute(input: uintb[]): uintb {
    const pcodeScript: ExecutablePcode = (this.glb as any).pcodeinjectlib.getPayload(this.injectId);
    return (pcodeScript as any).evaluate(input);
  }

  override decode(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_SEGMENTOP);
    this.spc = null;
    this.injectId = -1;
    this.baseinsize = 0;
    this.innerinsize = 0;
    this.supportsfarpointer = false;
    this.name = "segment"; // Default name, might be overridden by userop attribute
    for (;;) {
      const attribId = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_SPACE.id) {
        this.spc = decoder.readSpace() as unknown as AddrSpace;
      } else if (attribId === ATTRIB_FARPOINTER.id) {
        this.supportsfarpointer = true;
      } else if (attribId === ATTRIB_USEROP.id) {
        // Based on existing sleigh op
        this.name = decoder.readString();
      }
    }
    if (this.spc === null) {
      throw new LowlevelError("<segmentop> expecting space attribute");
    }
    const otherop: UserPcodeOp | null = (this.glb as any).userops.getOp(this.name);
    if (otherop === null) {
      throw new LowlevelError("<segmentop> unknown userop " + this.name);
    }
    this.useropindex = otherop.getIndex();
    if (!(otherop instanceof UnspecializedPcodeOp)) {
      throw new LowlevelError("Redefining userop " + this.name);
    }

    for (;;) {
      const subId = decoder.peekElement();
      if (subId === 0) break;
      if (subId === ELEM_CONSTRESOLVE.id) {
        decoder.openElement();
        if (decoder.peekElement() !== 0) {
          // Decode VarnodeData from <addr> child element
          // C++ calls Address::decode(decoder, sz) which internally decodes a VarnodeData
          const vn = new VarnodeData();
          (vn as any).decode(decoder);
          this.constresolve.space = vn.space;
          this.constresolve.offset = vn.offset;
          this.constresolve.size = vn.size;
        }
        decoder.closeElement(subId);
      } else if (subId === ELEM_PCODE.id) {
        const nm = this.name + "_pcode";
        const source = "cspec";
        this.injectId = (this.glb as any).pcodeinjectlib.decodeInject(
          source, nm, InjectPayload.EXECUTABLEPCODE_TYPE, decoder
        );
      }
    }
    decoder.closeElement(elemId);
    if (this.injectId < 0) {
      throw new LowlevelError("Missing <pcode> child in <segmentop> tag");
    }
    const payload: InjectPayload = (this.glb as any).pcodeinjectlib.getPayload(this.injectId);
    if (payload.sizeOutput() !== 1) {
      throw new LowlevelError("<pcode> child of <segmentop> tag must declare one <output>");
    }
    if (payload.sizeInput() === 1) {
      this.innerinsize = payload.getInput(0).getSize();
    } else if (payload.sizeInput() === 2) {
      this.baseinsize = payload.getInput(0).getSize();
      this.innerinsize = payload.getInput(1).getSize();
    } else {
      throw new LowlevelError("<pcode> child of <segmentop> tag must declare one or two <input> tags");
    }
  }
}

// ---------------------------------------------------------------------------
// JumpAssistOp
// ---------------------------------------------------------------------------

/**
 * A user defined p-code op for assisting the recovery of jump tables.
 *
 * An instance of this class refers to p-code script(s) that describe how to parse
 * the jump table from the load image.
 */
export class JumpAssistOp extends UserPcodeOp {
  private index2case: int4;
  private index2addr: int4;
  private defaultaddr: int4;
  private calcsize: int4;

  constructor(g: Architecture) {
    super("", g, UserPcodeOp.jumpassist, 0);
    this.index2case = -1;
    this.index2addr = -1;
    this.defaultaddr = -1;
    this.calcsize = -1;
  }

  /** Get the injection id for index2case */
  getIndex2Case(): int4 {
    return this.index2case;
  }

  /** Get the injection id for index2addr */
  getIndex2Addr(): int4 {
    return this.index2addr;
  }

  /** Get the injection id for defaultaddr */
  getDefaultAddr(): int4 {
    return this.defaultaddr;
  }

  /** Get the injection id for calcsize */
  getCalcSize(): int4 {
    return this.calcsize;
  }

  decode(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_JUMPASSIST);
    this.name = decoder.readStringById(ATTRIB_NAME);
    this.index2case = -1; // Mark as not present until we see a tag
    this.index2addr = -1;
    this.defaultaddr = -1;
    this.calcsize = -1;
    for (;;) {
      const subId = decoder.peekElement();
      if (subId === 0) break;
      if (subId === ELEM_CASE_PCODE.id) {
        if (this.index2case !== -1) {
          throw new LowlevelError("Too many <case_pcode> tags");
        }
        this.index2case = (this.glb as any).pcodeinjectlib.decodeInject(
          "jumpassistop", this.name + "_index2case",
          InjectPayload.EXECUTABLEPCODE_TYPE, decoder
        );
      } else if (subId === ELEM_ADDR_PCODE.id) {
        if (this.index2addr !== -1) {
          throw new LowlevelError("Too many <addr_pcode> tags");
        }
        this.index2addr = (this.glb as any).pcodeinjectlib.decodeInject(
          "jumpassistop", this.name + "_index2addr",
          InjectPayload.EXECUTABLEPCODE_TYPE, decoder
        );
      } else if (subId === ELEM_DEFAULT_PCODE.id) {
        if (this.defaultaddr !== -1) {
          throw new LowlevelError("Too many <default_pcode> tags");
        }
        this.defaultaddr = (this.glb as any).pcodeinjectlib.decodeInject(
          "jumpassistop", this.name + "_defaultaddr",
          InjectPayload.EXECUTABLEPCODE_TYPE, decoder
        );
      } else if (subId === ELEM_SIZE_PCODE.id) {
        if (this.calcsize !== -1) {
          throw new LowlevelError("Too many <size_pcode> tags");
        }
        this.calcsize = (this.glb as any).pcodeinjectlib.decodeInject(
          "jumpassistop", this.name + "_calcsize",
          InjectPayload.EXECUTABLEPCODE_TYPE, decoder
        );
      }
    }
    decoder.closeElement(elemId);

    if (this.index2addr === -1) {
      throw new LowlevelError("userop: " + this.name + " is missing <addr_pcode>");
    }
    if (this.defaultaddr === -1) {
      throw new LowlevelError("userop: " + this.name + " is missing <default_pcode>");
    }
    const base: UserPcodeOp | null = (this.glb as any).userops.getOp(this.name);
    // This tag overrides the base functionality of a userop
    // so the core userop name and index may already be defined
    if (base === null) {
      throw new LowlevelError("Unknown userop name in <jumpassist>: " + this.name);
    }
    if (!(base instanceof UnspecializedPcodeOp)) {
      // Make sure the userop isn't used for some other purpose
      throw new LowlevelError("<jumpassist> overloads userop with another purpose: " + this.name);
    }
    this.useropindex = base.getIndex(); // Get the index from the core userop
  }
}

// ---------------------------------------------------------------------------
// InternalStringOp
// ---------------------------------------------------------------------------

/**
 * An op that displays as an internal string.
 *
 * The user op takes no input parameters. In the decompiler output, it displays as a
 * quoted string. The string is associated with the address assigned to the user op
 * and is pulled from StringManager as internal.
 */
export class InternalStringOp extends UserPcodeOp {
  constructor(g: Architecture) {
    super("stringdata", g, UserPcodeOp.string_data, UserPcodeOp.BUILTIN_STRINGDATA);
    this.flags |= UserPcodeOp.display_string;
  }

  override getOutputLocal(op: PcodeOp): Datatype | null {
    return (op as any).getOut().getType();
  }

  decode(_decoder: Decoder): void {
    // No additional decoding needed
  }
}

// ---------------------------------------------------------------------------
// UserOpManage
// ---------------------------------------------------------------------------

/**
 * Manager/container for description objects (UserPcodeOp) of user defined p-code ops.
 *
 * The description objects are referenced by the CALLOTHER constant id, (or by name
 * during initialization). During initialize(), every user defined p-code op presented
 * by the Architecture is assigned a default UnspecializedPcodeOp description.
 */
export class UserOpManage {
  private glb: Architecture | null = null;
  private useroplist: (UserPcodeOp | null)[] = [];
  private builtinmap: Map<uint4, UserPcodeOp> = new Map();
  private useropmap: Map<string, UserPcodeOp> = new Map();
  private segmentop: (SegmentOp | null)[] = [];

  constructor() {
    this.glb = null;
  }

  /**
   * Insert a new UserPcodeOp description object in the map(s).
   *
   * Add the description to the mapping by index and the mapping by name. Make some basic
   * sanity checks for conflicting values and duplicate operations.
   */
  private registerOp(op: UserPcodeOp): void {
    const ind = op.getIndex();
    if (ind < 0) throw new LowlevelError("UserOp not assigned an index");

    const existing = this.useropmap.get(op.getName());
    if (existing !== undefined) {
      if (existing.getIndex() !== ind) {
        throw new LowlevelError("Conflicting indices for userop name " + op.getName());
      }
    }

    while (this.useroplist.length <= ind) {
      this.useroplist.push(null);
    }
    if (this.useroplist[ind] !== null) {
      if (this.useroplist[ind]!.getName() !== op.getName()) {
        throw new LowlevelError(
          "User op " + op.getName() + " has same index as " + this.useroplist[ind]!.getName()
        );
      }
      // We assume this registration customizes an existing userop
      // Delete the old spec (in TS, just replace the reference)
    }
    this.useroplist[ind] = op;        // Index crossref
    this.useropmap.set(op.getName(), op); // Name crossref

    if (op instanceof SegmentOp) {
      const s_op = op as SegmentOp;
      const index = s_op.getSpace()!.getIndex();

      while (this.segmentop.length <= index) {
        this.segmentop.push(null);
      }

      if (this.segmentop[index] !== null) {
        throw new LowlevelError("Multiple segmentops defined for same space");
      }
      this.segmentop[index] = s_op;
      return;
    }
  }

  /**
   * Initialize description objects for all user defined ops.
   *
   * Every user defined p-code op is initially assigned an UnspecializedPcodeOp description,
   * which may get overridden later.
   * @param g is the Architecture from which to draw user defined operations
   */
  initialize(g: Architecture): void {
    this.glb = g;
    const basicops: string[] = [];
    (g as any).translate.getUserOpNames(basicops);
    for (let i = 0; i < basicops.length; ++i) {
      if (basicops[i].length === 0) continue;
      const userop = new UnspecializedPcodeOp(basicops[i], this.glb, i);
      this.registerOp(userop);
    }
  }

  /** Number of segment operations supported */
  numSegmentOps(): int4 {
    return this.segmentop.length;
  }

  /**
   * Retrieve a user-op description object by index.
   * @param i is the index
   * @returns the indicated user-op description, or null
   */
  getOp(i: uint4): UserPcodeOp | null;
  /**
   * Retrieve description by name.
   * @param nm is the low-level operation name
   * @returns the matching description object or null
   */
  getOp(nm: string): UserPcodeOp | null;
  getOp(arg: uint4 | string): UserPcodeOp | null {
    if (typeof arg === 'number') {
      if (arg < this.useroplist.length) {
        return this.useroplist[arg];
      }
      const entry = this.builtinmap.get(arg);
      if (entry === undefined) return null;
      return entry;
    }
    // string overload
    const entry = this.useropmap.get(arg);
    if (entry === undefined) return null;
    return entry;
  }

  /**
   * Make sure an active record exists for the given built-in op.
   *
   * Retrieve a built-in user-op given its id.  If user-op record does not already exist,
   * instantiate a default form of the record.
   * @param i is the index associated
   * @returns the matching user-op record
   */
  registerBuiltin(i: uint4): UserPcodeOp {
    const existing = this.builtinmap.get(i);
    if (existing !== undefined) return existing;

    let res: UserPcodeOp;
    switch (i) {
      case UserPcodeOp.BUILTIN_STRINGDATA:
        res = new InternalStringOp(this.glb);
        break;
      case UserPcodeOp.BUILTIN_VOLATILE_READ:
        res = new VolatileReadOp("read_volatile", this.glb, false);
        break;
      case UserPcodeOp.BUILTIN_VOLATILE_WRITE:
        res = new VolatileWriteOp("write_volatile", this.glb, false);
        break;
      case UserPcodeOp.BUILTIN_MEMCPY: {
        const ptrSize: int4 = (this.glb as any).types.getSizeOfPointer();
        const wordSize: int4 = (this.glb as any).getDefaultDataSpace().getWordSize();
        const vType: Datatype = (this.glb as any).types.getTypeVoid();
        const ptrType: Datatype = (this.glb as any).types.getTypePointer(ptrSize, vType, wordSize);
        const intType: Datatype = (this.glb as any).types.getBase(4, 14 /* TYPE_INT */);
        res = new DatatypeUserOp("builtin_memcpy", this.glb, UserPcodeOp.BUILTIN_MEMCPY,
          ptrType, ptrType, ptrType, intType);
        break;
      }
      case UserPcodeOp.BUILTIN_STRNCPY: {
        // Copy "char" elements
        const ptrSize: int4 = (this.glb as any).types.getSizeOfPointer();
        const wordSize: int4 = (this.glb as any).getDefaultDataSpace().getWordSize();
        const cType: Datatype = (this.glb as any).types.getTypeChar((this.glb as any).types.getSizeOfChar());
        const ptrType: Datatype = (this.glb as any).types.getTypePointer(ptrSize, cType, wordSize);
        const intType: Datatype = (this.glb as any).types.getBase(4, 14 /* TYPE_INT */);
        res = new DatatypeUserOp("builtin_strncpy", this.glb, UserPcodeOp.BUILTIN_STRNCPY,
          ptrType, ptrType, ptrType, intType);
        break;
      }
      case UserPcodeOp.BUILTIN_WCSNCPY: {
        // Copy "wchar_t" elements
        const ptrSize: int4 = (this.glb as any).types.getSizeOfPointer();
        const wordSize: int4 = (this.glb as any).getDefaultDataSpace().getWordSize();
        const cType: Datatype = (this.glb as any).types.getTypeChar((this.glb as any).types.getSizeOfWChar());
        const ptrType: Datatype = (this.glb as any).types.getTypePointer(ptrSize, cType, wordSize);
        const intType: Datatype = (this.glb as any).types.getBase(4, 14 /* TYPE_INT */);
        res = new DatatypeUserOp("builtin_wcsncpy", this.glb, UserPcodeOp.BUILTIN_WCSNCPY,
          ptrType, ptrType, ptrType, intType);
        break;
      }
      default:
        throw new LowlevelError("Bad built-in userop id");
    }
    this.builtinmap.set(i, res);
    return res;
  }

  /**
   * Retrieve a segment-op description object by index.
   * @param i is the index
   * @returns the indicated segment-op description
   */
  getSegmentOp(i: int4): SegmentOp | null {
    if (i >= this.segmentop.length) return null;
    return this.segmentop[i];
  }

  /**
   * Create a SegmentOp description object based on the element and register it with this manager.
   * @param decoder is the stream decoder
   * @param glb is the owning Architecture
   */
  decodeSegmentOp(decoder: Decoder, glb: Architecture): void {
    const s_op = new SegmentOp("", glb, this.useroplist.length);
    try {
      s_op.decode(decoder);
      this.registerOp(s_op);
    } catch (err) {
      throw err;
    }
  }

  /**
   * Create either a VolatileReadOp or VolatileWriteOp description object based on
   * the element and register it with this manager.
   * @param decoder is the stream decoder
   * @param glb is the owning Architecture
   */
  decodeVolatile(decoder: Decoder, glb: Architecture): void {
    let readOpName = "";
    let writeOpName = "";
    let functionalDisplay = false;
    for (;;) {
      const attribId = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_INPUTOP.id) {
        readOpName = decoder.readString();
      } else if (attribId === ATTRIB_OUTPUTOP.id) {
        writeOpName = decoder.readString();
      } else if (attribId === ATTRIB_FORMAT.id) {
        const format = decoder.readString();
        if (format === "functional") {
          functionalDisplay = true;
        }
      }
    }
    if (readOpName.length === 0 || writeOpName.length === 0) {
      throw new LowlevelError("Missing inputop/outputop attributes in <volatile> element");
    }
    if (this.builtinmap.has(UserPcodeOp.BUILTIN_VOLATILE_READ)) {
      throw new LowlevelError("read_volatile user-op registered more than once");
    }
    if (this.builtinmap.has(UserPcodeOp.BUILTIN_VOLATILE_WRITE)) {
      throw new LowlevelError("write_volatile user-op registered more than once");
    }
    const vr_op = new VolatileReadOp(readOpName, glb, functionalDisplay);
    this.builtinmap.set(UserPcodeOp.BUILTIN_VOLATILE_READ, vr_op);
    const vw_op = new VolatileWriteOp(writeOpName, glb, functionalDisplay);
    this.builtinmap.set(UserPcodeOp.BUILTIN_VOLATILE_WRITE, vw_op);
  }

  /**
   * Create an InjectedUserOp description object based on the element
   * and register it with this manager.
   * @param decoder is the stream decoder
   * @param glb is the owning Architecture
   */
  decodeCallOtherFixup(decoder: Decoder, glb: Architecture): void {
    const op = new InjectedUserOp("", glb, 0, 0);
    try {
      op.decode(decoder);
      this.registerOp(op);
    } catch (err) {
      throw err;
    }
  }

  /**
   * Create a JumpAssistOp description object based on the element
   * and register it with this manager.
   * @param decoder is the stream decoder
   * @param glb is the owning Architecture
   */
  decodeJumpAssist(decoder: Decoder, glb: Architecture): void {
    const op = new JumpAssistOp(glb);
    try {
      op.decode(decoder);
      this.registerOp(op);
    } catch (err) {
      throw err;
    }
  }

  /**
   * Manually install an InjectedUserOp given just names of the user defined op and the p-code snippet.
   *
   * An alternate way to attach a call-fixup to user defined p-code ops, without using XML. The
   * p-code to inject is presented as a raw string to be handed to the p-code parser.
   * @param useropname is the name of the user defined op
   * @param outname is the name of the output variable in the snippet
   * @param inname is the list of input variable names in the snippet
   * @param snippet is the raw p-code source snippet
   * @param glb is the owning Architecture
   */
  manualCallOtherFixup(
    useropname: string,
    outname: string,
    inname: string[],
    snippet: string,
    glb: Architecture
  ): void {
    const userop = this.getOp(useropname);
    if (userop === null) {
      throw new LowlevelError("Unknown userop: " + useropname);
    }
    if (!(userop instanceof UnspecializedPcodeOp)) {
      throw new LowlevelError("Cannot fixup userop: " + useropname);
    }

    const injectid: int4 = (glb as any).pcodeinjectlib.manualCallOtherFixup(
      useropname, outname, inname, snippet
    );
    const op = new InjectedUserOp(useropname, glb, userop.getIndex(), injectid);
    try {
      this.registerOp(op);
    } catch (err) {
      throw err;
    }
  }
}
