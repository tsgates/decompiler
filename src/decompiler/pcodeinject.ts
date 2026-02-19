/**
 * @file pcodeinject.ts
 * @description Classes for managing p-code injection, translated from Ghidra's pcodeinject.hh/cc
 */

import type { int4, uint4, uintb } from '../core/types.js';
import { LowlevelError } from '../core/error.js';
import { Address } from '../core/address.js';
import type { AddrSpace } from '../core/space.js';
import { VarnodeData } from '../core/pcoderaw.js';
import { PcodeEmit } from '../core/translate.js';
import type { Writer } from '../util/writer.js';
import {
  AttributeId,
  ElementId,
  Encoder,
  Decoder,
  ATTRIB_NAME,
  ATTRIB_SIZE,
  ELEM_INPUT,
  ELEM_OUTPUT,
} from '../core/marshal.js';
import type { OpBehavior } from '../core/opbehavior.js';

// ---------------------------------------------------------------------------
// Forward type declarations
// ---------------------------------------------------------------------------

/** Forward-declared Architecture (full definition not yet available) */
type Architecture = any;

/** Forward-declared EmulateSnippet (full definition in emulateutil.ts) */
type EmulateSnippet = any;

// ---------------------------------------------------------------------------
// Marshaling Attribute IDs
// ---------------------------------------------------------------------------

export const ATTRIB_DYNAMIC         = new AttributeId('dynamic', 70);
export const ATTRIB_INCIDENTALCOPY  = new AttributeId('incidentalcopy', 71);
export const ATTRIB_INJECT          = new AttributeId('inject', 72);
export const ATTRIB_PARAMSHIFT      = new AttributeId('paramshift', 73);
export const ATTRIB_TARGETOP        = new AttributeId('targetop', 74);

// ---------------------------------------------------------------------------
// Marshaling Element IDs
// ---------------------------------------------------------------------------

export const ELEM_ADDR_PCODE        = new ElementId('addr_pcode', 89);
export const ELEM_BODY              = new ElementId('body', 90);
export const ELEM_CALLFIXUP         = new ElementId('callfixup', 91);
export const ELEM_CALLOTHERFIXUP    = new ElementId('callotherfixup', 92);
export const ELEM_CASE_PCODE        = new ElementId('case_pcode', 93);
export const ELEM_CONTEXT           = new ElementId('context', 94);
export const ELEM_DEFAULT_PCODE     = new ElementId('default_pcode', 95);
export const ELEM_INJECT            = new ElementId('inject', 96);
export const ELEM_INJECTDEBUG       = new ElementId('injectdebug', 97);
export const ELEM_INST              = new ElementId('inst', 98);
export const ELEM_PAYLOAD           = new ElementId('payload', 99);
export const ELEM_PCODE             = new ElementId('pcode', 100);
export const ELEM_SIZE_PCODE        = new ElementId('size_pcode', 101);

// ---------------------------------------------------------------------------
// InjectParameter
// ---------------------------------------------------------------------------

/**
 * An input or output parameter to a p-code injection payload.
 *
 * Within the chunk of p-code being injected, this is a placeholder for Varnodes
 * that serve as inputs or outputs to the chunk, which are filled-in in the context
 * of the injection. For instance, for a call-fixup that injects a user-defined
 * p-code op, the input Varnodes would be substituted with the actual input Varnodes
 * to the user-defined op.
 */
export class InjectParameter {
  name: string;
  index: int4;
  size: uint4;

  constructor(nm: string, sz: uint4) {
    this.name = nm;
    this.index = 0;
    this.size = sz;
  }

  /** Get the parameter name */
  getName(): string {
    return this.name;
  }

  /** Get the assigned index */
  getIndex(): int4 {
    return this.index;
  }

  /** Get the size of the parameter in bytes */
  getSize(): uint4 {
    return this.size;
  }
}

// ---------------------------------------------------------------------------
// InjectContext
// ---------------------------------------------------------------------------

/**
 * Context needed to emit a p-code injection as a full set of p-code operations.
 *
 * P-code injection works by passing a pre-built template of p-code operations (ConstructTpl)
 * to an emitter (PcodeEmit), which makes the final resolution of SLEIGH concepts like
 * inst_next to concrete Varnodes.
 */
export abstract class InjectContext {
  glb: Architecture;
  baseaddr: Address = new Address();
  nextaddr: Address = new Address();
  calladdr: Address = new Address();
  inputlist: VarnodeData[] = [];
  output: VarnodeData[] = [];

  constructor(g: Architecture) {
    this.glb = g;
  }

  /** Release resources (from last injection) */
  clear(): void {
    this.inputlist.length = 0;
    this.output.length = 0;
  }

  /**
   * Encode this context to a stream as a \<context\> element.
   * @param encoder is the stream encoder
   */
  abstract encode(encoder: Encoder): void;
}

// ---------------------------------------------------------------------------
// InjectPayload
// ---------------------------------------------------------------------------

/**
 * An active container for a set of p-code operations that can be injected into data-flow.
 *
 * This is an abstract base class. Derived classes manage details of how the p-code
 * is stored. The methods provide access to the input/output parameter information,
 * and the main injection is performed with inject().
 */
export abstract class InjectPayload {
  static readonly CALLFIXUP_TYPE = 1;
  static readonly CALLOTHERFIXUP_TYPE = 2;
  static readonly CALLMECHANISM_TYPE = 3;
  static readonly EXECUTABLEPCODE_TYPE = 4;

  protected name: string;
  protected type: int4;
  protected dynamic: boolean;
  protected incidentalCopy: boolean;
  protected paramshift: int4;
  protected inputlist: InjectParameter[];
  protected output: InjectParameter[];

  constructor(nm: string, tp: int4) {
    this.name = nm;
    this.type = tp;
    this.paramshift = 0;
    this.dynamic = false;
    this.incidentalCopy = false;
    this.inputlist = [];
    this.output = [];
  }

  /**
   * Parse an \<input\> or \<output\> element describing an injection parameter.
   * @param decoder is the stream decoder
   * @returns a tuple [name, size]
   */
  protected static decodeParameter(decoder: Decoder): { name: string; size: uint4 } {
    let name = '';
    let size: uint4 = 0;
    const elemId: uint4 = decoder.openElement();
    for (;;) {
      const attribId: uint4 = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_NAME.id) {
        name = decoder.readString();
      } else if (attribId === ATTRIB_SIZE.id) {
        size = Number(decoder.readUnsignedInteger());
      }
    }
    decoder.closeElement(elemId);
    if (name.length === 0) {
      throw new LowlevelError('Missing inject parameter name');
    }
    return { name, size };
  }

  /** Assign an index to parameters */
  protected orderParameters(): void {
    let id: int4 = 0;
    for (let i = 0; i < this.inputlist.length; ++i) {
      this.inputlist[i].index = id;
      id += 1;
    }
    for (let i = 0; i < this.output.length; ++i) {
      this.output[i].index = id;
      id += 1;
    }
  }

  /** Parse the attributes of the current \<pcode\> tag */
  protected decodePayloadAttributes(decoder: Decoder): void {
    this.paramshift = 0;
    this.dynamic = false;
    for (;;) {
      const attribId: uint4 = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_PARAMSHIFT.id) {
        this.paramshift = decoder.readSignedInteger();
      } else if (attribId === ATTRIB_DYNAMIC.id) {
        this.dynamic = decoder.readBool();
      } else if (attribId === ATTRIB_INCIDENTALCOPY.id) {
        this.incidentalCopy = decoder.readBool();
      } else if (attribId === ATTRIB_INJECT.id) {
        const uponType: string = decoder.readString();
        if (uponType === 'uponentry') {
          this.name = this.name + '@@inject_uponentry';
        } else {
          this.name = this.name + '@@inject_uponreturn';
        }
      }
    }
  }

  /**
   * Parse any \<input\> or \<output\> children of current \<pcode\> tag.
   * Elements are processed until the first child that isn't an \<input\> or
   * \<output\> tag is encountered. The \<pcode\> element must be current and
   * already opened.
   */
  protected decodePayloadParams(decoder: Decoder): void {
    for (;;) {
      const subId: uint4 = decoder.peekElement();
      if (subId === ELEM_INPUT.id) {
        const { name: paramName, size } = InjectPayload.decodeParameter(decoder);
        this.inputlist.push(new InjectParameter(paramName, size));
      } else if (subId === ELEM_OUTPUT.id) {
        const { name: paramName, size } = InjectPayload.decodeParameter(decoder);
        this.output.push(new InjectParameter(paramName, size));
      } else {
        break;
      }
    }
    this.orderParameters();
  }

  /** Get the number of parameters shifted */
  getParamShift(): int4 {
    return this.paramshift;
  }

  /** Return true if p-code in the injection is generated dynamically */
  isDynamic(): boolean {
    return this.dynamic;
  }

  /** Return true if any injected COPY is considered incidental */
  isIncidentalCopy(): boolean {
    return this.incidentalCopy;
  }

  /** Return the number of input parameters */
  sizeInput(): int4 {
    return this.inputlist.length;
  }

  /** Return the number of output parameters */
  sizeOutput(): int4 {
    return this.output.length;
  }

  /** Get the i-th input parameter */
  getInput(i: int4): InjectParameter {
    return this.inputlist[i];
  }

  /** Get the i-th output parameter */
  getOutput(i: int4): InjectParameter {
    return this.output[i];
  }

  /**
   * Perform the injection of this payload into data-flow.
   *
   * P-code operations representing this payload are copied into the
   * controlling analysis context. The provided PcodeEmit object dictates exactly
   * where the PcodeOp and Varnode objects are inserted and to what container.
   * An InjectContext object specifies how placeholder elements become concrete Varnodes
   * in the appropriate context.
   * @param context is the provided InjectContext object
   * @param emit is the provided PcodeEmit object
   */
  abstract inject(context: InjectContext, emit: PcodeEmit): void;

  /** Decode this payload from a stream */
  abstract decode(decoder: Decoder): void;

  /** Print the p-code ops of the injection to a stream (for debugging) */
  abstract printTemplate(s: Writer): void;

  /** Return the name of the injection */
  getName(): string {
    return this.name;
  }

  /** Return the type of injection (CALLFIXUP_TYPE, CALLOTHERFIXUP_TYPE, etc.) */
  getType(): int4 {
    return this.type;
  }

  /** Return a string describing the source of the injection (.cspec, prototype model, etc.) */
  abstract getSource(): string;
}

// ---------------------------------------------------------------------------
// ExecutablePcode
// ---------------------------------------------------------------------------

/**
 * A snippet of p-code that can be executed outside of normal analysis.
 *
 * Essentially a p-code script. The p-code contained in this snippet needs to be
 * processor agnostic, so any register Varnodes must be temporary (out of the unique space)
 * and any control-flow operations must be contained within the snippet (p-code relative addressing).
 * Input and output to the snippet/script is provided by standard injection parameters.
 * The class contains, as a field, a stripped down emulator to run the script and
 * a convenience method evaluate() to feed in concrete values to the input parameters
 * and return a value from a single output parameter.
 */
export class ExecutablePcode extends InjectPayload {
  private glb: Architecture;
  private source: string;
  private built: boolean;
  private emulator: EmulateSnippet;
  private inputList_: bigint[];
  private outputList: bigint[];
  private emitter: PcodeEmit | null;

  constructor(g: Architecture, src: string, nm: string) {
    super(nm, InjectPayload.EXECUTABLEPCODE_TYPE);
    this.glb = g;
    this.emitter = null;
    this.source = src;
    this.built = false;
    // EmulateSnippet is constructed from the Architecture (forward-declared as any)
    this.emulator = null;
    this.inputList_ = [];
    this.outputList = [];
  }

  getSource(): string {
    return this.source;
  }

  /** Initialize the Emulate object with the snippet p-code */
  private build(): void {
    if (this.built) return;
    const icontext: InjectContext = this.glb.pcodeinjectlib.getCachedContext();
    icontext.clear();
    let uniqReserve: bigint = 0x10n;  // Temporary register space reserved for inputs and output
    const codeSpace: AddrSpace = this.glb.getDefaultCodeSpace();
    const uniqSpace: AddrSpace = this.glb.getUniqueSpace();
    icontext.baseaddr = new Address(codeSpace, 0x1000n);  // Fake address
    icontext.nextaddr = icontext.baseaddr;
    for (let i = 0; i < this.sizeInput(); ++i) {
      const param: InjectParameter = this.getInput(i);
      const vd = new VarnodeData();
      vd.space = uniqSpace;
      vd.offset = uniqReserve;
      vd.size = param.getSize();
      icontext.inputlist.push(vd);
      this.inputList_.push(uniqReserve);
      uniqReserve += 0x20n;
    }
    for (let i = 0; i < this.sizeOutput(); ++i) {
      const param: InjectParameter = this.getOutput(i);
      const vd = new VarnodeData();
      vd.space = uniqSpace;
      vd.offset = uniqReserve;
      vd.size = param.getSize();
      icontext.output.push(vd);
      this.outputList.push(uniqReserve);
      uniqReserve += 0x20n;
    }
    this.emitter = this.emulator.buildEmitter(
      this.glb.pcodeinjectlib.getBehaviors(),
      uniqReserve
    );
    this.inject(icontext, this.emitter!);
    this.emitter = null;
    if (!this.emulator.checkForLegalCode()) {
      throw new LowlevelError('Illegal p-code in executable snippet');
    }
    this.built = true;
  }

  /**
   * Evaluate the snippet on the given inputs.
   *
   * The caller provides a list of concrete values that are assigned to the
   * input parameters. The number of values and input parameters must match,
   * and values are assigned in order. This method assumes there is
   * exactly 1 relevant output parameter. Once the snippet is executed the
   * value of this parameter is read from the emulator state and returned.
   * @param input is the ordered list of input values to feed to this script
   * @returns the value of the output parameter after script execution
   */
  evaluate(input: bigint[]): bigint {
    this.build();
    this.emulator.resetMemory();
    if (input.length !== this.inputList_.length) {
      throw new LowlevelError('Wrong number of input parameters to executable snippet');
    }
    if (this.outputList.length === 0) {
      throw new LowlevelError('No registered outputs to executable snippet');
    }
    for (let i = 0; i < input.length; ++i) {
      this.emulator.setVarnodeValue(this.inputList_[i], input[i]);
    }
    while (!this.emulator.getHalt()) {
      this.emulator.executeCurrentOp();
    }
    return this.emulator.getTempValue(this.outputList[0]);
  }

  // InjectPayload abstract implementations
  inject(_context: InjectContext, _emit: PcodeEmit): void {
    throw new LowlevelError('ExecutablePcode::inject not directly implemented');
  }

  decode(_decoder: Decoder): void {
    throw new LowlevelError('ExecutablePcode::decode not directly implemented');
  }

  printTemplate(_s: Writer): void {
    throw new LowlevelError('ExecutablePcode::printTemplate not directly implemented');
  }
}

// ---------------------------------------------------------------------------
// PcodeInjectLibrary
// ---------------------------------------------------------------------------

/**
 * A collection of p-code injection payloads.
 *
 * This is a container of InjectPayload objects that can be applied for a
 * specific Architecture. Payloads can be read in via stream (decodeInject()) and manually
 * via manualCallFixup() and manualCallOtherFixup(). Each payload is assigned an integer id
 * when it is read in, and getPayload() fetches the payload during analysis. The library
 * also associates the formal names of payloads with the id. Payloads of different types,
 * CALLFIXUP_TYPE, CALLOTHERFIXUP_TYPE, etc., are stored in separate namespaces.
 *
 * This is an abstract base class. The derived classes determine the type of storage used
 * by the payloads. The library also provides a reusable InjectContext object to match
 * the payloads, which can be obtained via getCachedContext().
 */
export abstract class PcodeInjectLibrary {
  protected glb: Architecture;
  protected tempbase: uint4;
  protected injection: InjectPayload[];
  protected callFixupMap: Map<string, int4>;
  protected callOtherFixupMap: Map<string, int4>;
  protected callMechFixupMap: Map<string, int4>;
  protected scriptMap: Map<string, int4>;
  protected callFixupNames: string[];
  protected callOtherTarget: string[];
  protected callMechTarget: string[];
  protected scriptNames: string[];

  constructor(g: Architecture, tmpbase: uint4) {
    this.glb = g;
    this.tempbase = tmpbase;
    this.injection = [];
    this.callFixupMap = new Map<string, int4>();
    this.callOtherFixupMap = new Map<string, int4>();
    this.callMechFixupMap = new Map<string, int4>();
    this.scriptMap = new Map<string, int4>();
    this.callFixupNames = [];
    this.callOtherTarget = [];
    this.callMechTarget = [];
    this.scriptNames = [];
  }

  /** Destructor equivalent -- cleanup injections (no-op in TS due to GC) */
  dispose(): void {
    // In C++ this deletes each InjectPayload*. In TS, GC handles this.
    this.injection.length = 0;
  }

  /** Get the (current) offset for building temporary registers */
  getUniqueBase(): uint4 {
    return this.tempbase;
  }

  /**
   * Map name and type to the payload id.
   *
   * The given name is looked up in a symbol table depending on the given type.
   * @param type is the payload type
   * @param nm is the formal name of the payload
   * @returns the payload id or -1 if there is no matching payload
   */
  getPayloadId(type: int4, nm: string): int4 {
    let val: int4 | undefined;
    if (type === InjectPayload.CALLFIXUP_TYPE) {
      val = this.callFixupMap.get(nm);
      if (val === undefined) return -1;
    } else if (type === InjectPayload.CALLOTHERFIXUP_TYPE) {
      val = this.callOtherFixupMap.get(nm);
      if (val === undefined) return -1;
    } else if (type === InjectPayload.CALLMECHANISM_TYPE) {
      val = this.callMechFixupMap.get(nm);
      if (val === undefined) return -1;
    } else {
      val = this.scriptMap.get(nm);
      if (val === undefined) return -1;
    }
    return val;
  }

  /** Get the InjectPayload by id */
  getPayload(id: int4): InjectPayload {
    return this.injection[id];
  }

  /**
   * Get the call-fixup name associated with an id.
   * @param injectid is an integer id of a call-fixup payload
   * @returns the name of the payload or the empty string
   */
  getCallFixupName(injectid: int4): string {
    if (injectid < 0 || injectid >= this.callFixupNames.length) return '';
    return this.callFixupNames[injectid];
  }

  /**
   * Get the callother-fixup name associated with an id.
   * @param injectid is an integer id of a callother-fixup payload
   * @returns the name of the payload or the empty string
   */
  getCallOtherTarget(injectid: int4): string {
    if (injectid < 0 || injectid >= this.callOtherTarget.length) return '';
    return this.callOtherTarget[injectid];
  }

  /**
   * Get the call mechanism name associated with an id.
   * @param injectid is an integer id of a call mechanism payload
   * @returns the name of the payload or the empty string
   */
  getCallMechanismName(injectid: int4): string {
    if (injectid < 0 || injectid >= this.callMechTarget.length) return '';
    return this.callMechTarget[injectid];
  }

  /**
   * Parse and register an injection payload from a stream element.
   *
   * The element is one of: \<pcode\>, \<callfixup\> \<callotherfixup\>, etc.
   * The InjectPayload is allocated and then initialized using the element.
   * Then the InjectPayload is finalized with the library.
   * @param src is a string describing the source of the payload being decoded
   * @param nm is the name of the payload
   * @param tp is the type of the payload (CALLFIXUP_TYPE, EXECUTABLEPCODE_TYPE, etc.)
   * @param decoder is the stream decoder
   * @returns the id of the newly registered payload
   */
  decodeInject(src: string, nm: string, tp: int4, decoder: Decoder): int4 {
    const injectid: int4 = this.allocateInject(src, nm, tp);
    this.getPayload(injectid).decode(decoder);
    this.registerInject(injectid);
    return injectid;
  }

  /**
   * A method for parsing p-code generated externally for use in debugging.
   *
   * Instantiate a special InjectPayloadDynamic object initialized with an
   * \<injectdebug\> element. Within the library, this replaces the original InjectPayload,
   * allowing its p-code to be replayed for debugging purposes.
   * @param _decoder is the stream decoder
   */
  decodeDebug(_decoder: Decoder): void {
    // Default implementation is empty (matches C++)
  }

  /**
   * Map a call-fixup name to a payload id.
   * @param fixupName is the formal name of the call-fixup
   * @param injectid is the integer id
   */
  protected registerCallFixup(fixupName: string, injectid: int4): void {
    if (this.callFixupMap.has(fixupName)) {
      throw new LowlevelError('Duplicate <callfixup>: ' + fixupName);
    }
    this.callFixupMap.set(fixupName, injectid);
    while (this.callFixupNames.length <= injectid) {
      this.callFixupNames.push('');
    }
    this.callFixupNames[injectid] = fixupName;
  }

  /**
   * Map a callother-fixup name to a payload id.
   * @param fixupName is the formal name of the callother-fixup
   * @param injectid is the integer id
   */
  protected registerCallOtherFixup(fixupName: string, injectid: int4): void {
    if (this.callOtherFixupMap.has(fixupName)) {
      throw new LowlevelError('Duplicate <callotherfixup>: ' + fixupName);
    }
    this.callOtherFixupMap.set(fixupName, injectid);
    while (this.callOtherTarget.length <= injectid) {
      this.callOtherTarget.push('');
    }
    this.callOtherTarget[injectid] = fixupName;
  }

  /**
   * Map a call mechanism name to a payload id.
   * @param fixupName is the formal name of the call mechanism
   * @param injectid is the integer id
   */
  protected registerCallMechanism(fixupName: string, injectid: int4): void {
    if (this.callMechFixupMap.has(fixupName)) {
      throw new LowlevelError('Duplicate <callmechanism>: ' + fixupName);
    }
    this.callMechFixupMap.set(fixupName, injectid);
    while (this.callMechTarget.length <= injectid) {
      this.callMechTarget.push('');
    }
    this.callMechTarget[injectid] = fixupName;
  }

  /**
   * Map a p-code script name to a payload id.
   * @param scriptName is the formal name of the p-code script
   * @param injectid is the integer id
   */
  protected registerExeScript(scriptName: string, injectid: int4): void {
    if (this.scriptMap.has(scriptName)) {
      throw new LowlevelError('Duplicate <script>: ' + scriptName);
    }
    this.scriptMap.set(scriptName, injectid);
    while (this.scriptNames.length <= injectid) {
      this.scriptNames.push('');
    }
    this.scriptNames[injectid] = scriptName;
  }

  /**
   * Allocate a new InjectPayload object.
   *
   * This acts as an InjectPayload factory. The formal name and type of the payload are given,
   * this library allocates a new object that fits with its storage scheme and returns the id.
   * @param sourceName is a string describing the source of the new payload
   * @param name is the formal name of the payload
   * @param type is the formal type (CALLFIXUP_TYPE, CALLOTHERFIXUP_TYPE, etc.) of the payload
   * @returns the id associated with the new InjectPayload object
   */
  protected abstract allocateInject(sourceName: string, name: string, type: int4): int4;

  /**
   * Finalize a payload within the library, once the payload is initialized.
   *
   * This provides the derived class the opportunity to add the payload name to the
   * symbol tables or do anything else it needs to once the InjectPayload object
   * has been fully initialized.
   * @param injectid is the id of the InjectPayload to finalize
   */
  protected abstract registerInject(injectid: int4): void;

  /**
   * Manually add a call-fixup payload given a compilable snippet of p-code source.
   *
   * The snippet is compiled immediately to produce the payload.
   * @param name is the formal name of the new payload
   * @param snippetstring is the compilable snippet of p-code source
   * @returns the id of the new payload
   */
  abstract manualCallFixup(name: string, snippetstring: string): int4;

  /**
   * Manually add a callother-fixup payload given a compilable snippet of p-code source.
   *
   * The snippet is compiled immediately to produce the payload. Symbol names for
   * input and output parameters must be provided to the compiler.
   * @param name is the formal name of the new payload
   * @param outname is the name of the output symbol
   * @param inname is the ordered list of input symbol names
   * @param snippet is the compilable snippet of p-code source
   * @returns the id of the new payload
   */
  abstract manualCallOtherFixup(
    name: string,
    outname: string,
    inname: string[],
    snippet: string,
  ): int4;

  /**
   * Retrieve a reusable context object for this library.
   *
   * The object returned by this method gets passed to the payload inject() method.
   * The clear() method must be called between uses.
   * @returns the cached context object
   */
  abstract getCachedContext(): InjectContext;

  /**
   * Get the array of op-code behaviors for initializing an emulator.
   *
   * Behaviors are pulled from the underlying architecture in order to initialize
   * the Emulate object which services the p-code script payloads.
   * @returns the array of OpBehavior objects indexed by op-code
   */
  abstract getBehaviors(): OpBehavior[];
}
