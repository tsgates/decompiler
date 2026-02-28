/**
 * @file architecture.ts
 * @description Architecture and associated classes that help manage a single processor
 * architecture and load image.
 *
 * Translated from Ghidra's architecture.hh / architecture.cc
 */

import type { int4, uint4, uintb } from '../core/types.js';
import { LowlevelError, ParseError } from '../core/error.js';
import { Address, Range, RangeList, RangeProperties } from '../core/address.js';
// Side-effect import: patches ActionDatabase.prototype with universalAction/buildDefaultGroups
import './coreaction.js';
import { AddrSpace, spacetype } from '../core/space.js';
import {
  AddrSpaceManager,
  Translate,
  SpacebaseSpace,
  AddressResolver,
} from '../core/translate.js';
import {
  Decoder,
  Encoder,
  AttributeId,
  ElementId,
  ATTRIB_ALIGN,
  ATTRIB_NAME,
  ATTRIB_SPACE,
  ATTRIB_TYPE,
} from '../core/marshal.js';
import { VarnodeData } from '../core/pcoderaw.js';
import { ContextDatabase } from '../core/globalcontext.js';
import { CapabilityPoint } from '../core/capability.js';
import type { Datatype } from '../decompiler/type.js';
import { TypeFactory } from '../decompiler/type.js';
import { Database, ScopeInternal } from '../decompiler/database.js';
import { TypeOp } from '../decompiler/typeop.js';
import { XmlDecode } from '../core/marshal.js';
import { FspecSpace } from '../decompiler/fspec.js';
import { IopSpace } from '../decompiler/op.js';
import { JoinSpace } from '../core/space.js';
import { Override } from '../decompiler/override.js';

// Forward declarations for types only used as type annotations
type Scope = any;

// Attributes not exported from marshal.js - define locally
const ATTRIB_DELAY = new AttributeId("delay", 200);
const ATTRIB_VOLATILE = new AttributeId("volatile", 201);
import {
  ProtoModel,
  UnknownProtoModel,
  ProtoModelMerged,
  PrototypePieces,
  FuncProto,
} from '../decompiler/fspec.js';
import { UserOpManage } from '../decompiler/userop.js';
import { OptionDatabase } from '../decompiler/options.js';
import { LoadImage } from '../decompiler/loadimage.js';
import { PcodeInjectLibrary } from '../decompiler/pcodeinject.js';
import { CommentDatabase } from '../decompiler/comment.js';
import { ConstantPool } from '../decompiler/cpool.js';
import { StringManager } from '../decompiler/stringmanage.js';
import { PrintLanguage, PrintLanguageCapability } from '../decompiler/printlanguage.js';
import { PrintCCapability } from '../decompiler/printc.js';
import { PreferSplitRecord, PreferSplitManager } from '../decompiler/prefersplit.js';
import { Action, ActionDatabase } from '../decompiler/action.js';
import { ValueSetSolver, WidenerNone } from '../decompiler/rangeutil.js';

// ---------------------------------------------------------------------------
// Forward type declarations for types from not-yet-written modules
// ---------------------------------------------------------------------------

/** Forward-declared Funcdata */
type Funcdata = any;
/** Forward-declared OpBehavior */
type OpBehavior = any;
/** Forward-declared Rule */
type Rule = any;
/** Forward-declared SegmentOp */
type SegmentOp = any;
/** Forward-declared LanedRegister */
type LanedRegister = any;
// PrintLanguageCapability imported above from printlanguage.js
/** Forward-declared Document */
type Document = any;
/** Forward-declared DocumentStorage */
type DocumentStorage = any;
/** Forward-declared Element */
type Element = any;
/** Forward-declared LoadImageFunc */
type LoadImageFunc = any;
// RangeProperties imported from ../core/address.js
/** Forward-declared InjectPayload */
type InjectPayload = any;
/** Forward-declared OtherSpace */
type OtherSpace = any;
/** Forward-declared Comment */
type Comment = any;
/** Forward-declared Varnode */
type Varnode = any;
/** Forward-declared FlowInfo */
type FlowInfo = any;
/** Forward-declared OptionSplitDatatypes */
type OptionSplitDatatypes = any;

// TypeOp, XmlDecode, ScopeInternal, Override, FspecSpace, IopSpace, JoinSpace
// are now imported above

// ---------------------------------------------------------------------------
// Writer interface (replaces C++ ostream)
// ---------------------------------------------------------------------------

/** Minimal output stream interface replacing C++ ostream */
export interface Writer {
  write(s: string): void;
}

// ---------------------------------------------------------------------------
// Marshaling Attribute IDs
// ---------------------------------------------------------------------------

export const ATTRIB_ADDRESS = new AttributeId("address", 148);
export const ATTRIB_ADJUSTVMA = new AttributeId("adjustvma", 103);
export const ATTRIB_ENABLE = new AttributeId("enable", 104);
export const ATTRIB_GROUP = new AttributeId("group", 105);
export const ATTRIB_GROWTH = new AttributeId("growth", 106);
export const ATTRIB_KEY = new AttributeId("key", 107);
export const ATTRIB_LOADERSYMBOLS = new AttributeId("loadersymbols", 108);
export const ATTRIB_PARENT = new AttributeId("parent", 109);
export const ATTRIB_REGISTER = new AttributeId("register", 110);
export const ATTRIB_REVERSEJUSTIFY = new AttributeId("reversejustify", 111);
export const ATTRIB_SIGNEXT = new AttributeId("signext", 112);
export const ATTRIB_STYLE = new AttributeId("style", 113);

// ---------------------------------------------------------------------------
// Marshaling Element IDs
// ---------------------------------------------------------------------------

export const ELEM_ADDRESS_SHIFT_AMOUNT = new ElementId("address_shift_amount", 130);
export const ELEM_AGGRESSIVETRIM = new ElementId("aggressivetrim", 131);
export const ELEM_COMPILER_SPEC = new ElementId("compiler_spec", 132);
export const ELEM_DATA_SPACE = new ElementId("data_space", 133);
export const ELEM_DEFAULT_MEMORY_BLOCKS = new ElementId("default_memory_blocks", 134);
export const ELEM_DEFAULT_PROTO = new ElementId("default_proto", 135);
export const ELEM_DEFAULT_SYMBOLS = new ElementId("default_symbols", 136);
export const ELEM_EVAL_CALLED_PROTOTYPE = new ElementId("eval_called_prototype", 137);
export const ELEM_EVAL_CURRENT_PROTOTYPE = new ElementId("eval_current_prototype", 138);
export const ELEM_EXPERIMENTAL_RULES = new ElementId("experimental_rules", 139);
export const ELEM_FLOWOVERRIDELIST = new ElementId("flowoverridelist", 140);
export const ELEM_FUNCPTR = new ElementId("funcptr", 141);
export const ELEM_GLOBAL = new ElementId("global", 142);
export const ELEM_INCIDENTALCOPY = new ElementId("incidentalcopy", 143);
export const ELEM_INFERPTRBOUNDS = new ElementId("inferptrbounds", 144);
export const ELEM_MODELALIAS = new ElementId("modelalias", 145);
export const ELEM_NOHIGHPTR = new ElementId("nohighptr", 146);
export const ELEM_PROCESSOR_SPEC = new ElementId("processor_spec", 147);
export const ELEM_PROGRAMCOUNTER = new ElementId("programcounter", 148);
export const ELEM_PROPERTIES = new ElementId("properties", 149);
export const ELEM_PROPERTY = new ElementId("property", 150);
export const ELEM_READONLY = new ElementId("readonly", 151);
export const ELEM_REGISTER = new ElementId("register", 300);
export const ELEM_REGISTER_DATA = new ElementId("register_data", 152);
export const ELEM_RULE = new ElementId("rule", 153);
export const ELEM_SAVE_STATE = new ElementId("save_state", 154);
export const ELEM_SEGMENTED_ADDRESS = new ElementId("segmented_address", 155);
export const ELEM_SPACEBASE = new ElementId("spacebase", 156);
export const ELEM_SPECEXTENSIONS = new ElementId("specextensions", 157);
export const ELEM_STACKPOINTER = new ElementId("stackpointer", 158);
export const ELEM_VOLATILE = new ElementId("volatile", 159);

// ---------------------------------------------------------------------------
// External element IDs needed for restoreXml, referenced from other modules
// ---------------------------------------------------------------------------

// These are forward references to elements defined in other modules.
// In practice, they must be imported from their respective modules.
const ELEM_TYPEGRP = new ElementId("typegrp", 62);       // from type.ts
const ELEM_DB = new ElementId("db", 68);                  // from database.ts
const ELEM_CONTEXT_POINTS = new ElementId("context_points", 121); // from globalcontext.ts
const ELEM_COMMENTDB = new ElementId("commentdb", 87);    // from comment.ts
const ELEM_STRINGMANAGE = new ElementId("stringmanage", 85); // from stringmanage.ts
const ELEM_CONSTANTPOOL = new ElementId("constantpool", 109); // from cpool.ts
const ELEM_OPTIONSLIST = new ElementId("optionslist", 201); // from options.ts
const ELEM_INJECTDEBUG = new ElementId("injectdebug", 97); // from pcodeinject.ts
const ELEM_FLOW = new ElementId("flow", 219);              // from flow
const ELEM_PROTOTYPE = new ElementId("prototype", 169);    // from fspec.ts
const ELEM_RESOLVEPROTOTYPE = new ElementId("resolveprototype", 170); // from fspec.ts
const ELEM_CONTEXT_DATA = new ElementId("context_data", 120); // from globalcontext.ts
const ELEM_JUMPASSIST = new ElementId("jumpassist", 128);  // from userop.ts
const ELEM_SEGMENTOP = new ElementId("segmentop", 129);    // from userop.ts
const ELEM_DATA_ORGANIZATION = new ElementId("data_organization", 42); // from type.ts
const ELEM_ENUM = new ElementId("enum", 48);              // from type.ts
const ELEM_CALLFIXUP = new ElementId("callfixup", 91);    // from pcodeinject.ts
const ELEM_CALLOTHERFIXUP = new ElementId("callotherfixup", 92); // from pcodeinject.ts
const ELEM_DEADCODEDELAY = new ElementId("deadcodedelay", 218);
const ELEM_PREFERSPLIT = new ElementId("prefersplit", 225);
const ELEM_RETURNADDRESS = new ElementId("returnaddress", 5);

// FlowInfo flag constants
const FlowInfo_error_toomanyinstructions = 0x20;

// InjectPayload type constants
const InjectPayload_CALLFIXUP_TYPE = 1;

// OptionSplitDatatypes flag constants
const OptionSplitDatatypes_option_struct = 1;
const OptionSplitDatatypes_option_array = 2;
const OptionSplitDatatypes_option_pointer = 4;

// Varnode property flags (must match values in database.ts)
const Varnode_readonly = 0x2000;
const Varnode_volatil = 0x800;
const Varnode_incidental_copy = 0x20000000;

// Comment type flags (must match values in comment.ts)
const Comment_warning = 16;
const Comment_warningheader = 32;

// ATTRIB_VECTOR_LANE_SIZES
const ATTRIB_VECTOR_LANE_SIZES = new AttributeId("vector_lane_sizes", 0);

// OtherSpace NAME constant
const OtherSpace_NAME = "OTHER";

// ---------------------------------------------------------------------------
// Helper: calc_mask
// ---------------------------------------------------------------------------

function calc_mask(size: number): bigint {
  if (size >= 8) return 0xFFFFFFFFFFFFFFFFn;
  return (1n << BigInt(size * 8)) - 1n;
}

// ---------------------------------------------------------------------------
// ArchitectureCapability
// ---------------------------------------------------------------------------

/**
 * Abstract extension point for building Architecture objects.
 *
 * Decompilation hinges on initially recognizing the format of code then
 * bootstrapping into discovering the processor etc. This is the base class
 * for the different extensions that perform this process. Each extension
 * implements the buildArchitecture() method as the formal entry point
 * for the bootstrapping process.
 */
export abstract class ArchitectureCapability extends CapabilityPoint {
  private static readonly majorversion: number = 6;
  private static readonly minorversion: number = 1;
  private static thelist: ArchitectureCapability[] = [];

  protected name: string = "";

  /** Get the capability identifier */
  getName(): string {
    return this.name;
  }

  /** Do specialized initialization */
  initialize(): void {
    ArchitectureCapability.thelist.push(this);
  }

  /**
   * Build an Architecture given a raw file or data.
   * @param filename is the path to the executable file to examine
   * @param target if non-empty is a language id string
   * @param estream is an output stream for error messages
   * @returns a new Architecture object
   */
  abstract buildArchitecture(filename: string, target: string, estream: Writer | null): Architecture;

  /**
   * Determine if this extension can handle this file.
   * @param filename is the name of the file to examine
   * @returns true if this extension is suitable for analyzing the file
   */
  abstract isFileMatch(filename: string): boolean;

  /**
   * Determine if this extension can handle this XML document.
   * @param doc is the parsed XML document
   * @returns true if this extension understands the XML
   */
  abstract isXmlMatch(doc: Document): boolean;

  /**
   * Find an extension to process a file.
   * @param filename is the path to the file
   * @returns an ArchitectureCapability that can handle it or null
   */
  static findCapabilityByFile(filename: string): ArchitectureCapability | null {
    for (let i = 0; i < ArchitectureCapability.thelist.length; ++i) {
      const capa = ArchitectureCapability.thelist[i];
      if (capa.isFileMatch(filename))
        return capa;
    }
    return null;
  }

  /**
   * Find an extension to process an XML document.
   * @param doc is the parsed XML document
   * @returns an ArchitectureCapability that can handle it or null
   */
  static findCapabilityByDocument(doc: Document): ArchitectureCapability | null {
    for (let i = 0; i < ArchitectureCapability.thelist.length; ++i) {
      const capa = ArchitectureCapability.thelist[i];
      if (capa.isXmlMatch(doc))
        return capa;
    }
    return null;
  }

  /**
   * Get a capability by name.
   * @param name is the name to match
   * @returns the ArchitectureCapability or null if no match is found
   */
  static getCapability(name: string): ArchitectureCapability | null {
    for (let i = 0; i < ArchitectureCapability.thelist.length; ++i) {
      const res = ArchitectureCapability.thelist[i];
      if (res.getName() === name)
        return res;
    }
    return null;
  }

  /**
   * Sort extensions.
   * Modify order that extensions are searched, to effect which gets a chance
   * to run first. Right now all we need to do is make sure the raw
   * architecture comes last.
   */
  static sortCapabilities(): void {
    const thelist = ArchitectureCapability.thelist;
    let i: number;
    for (i = 0; i < thelist.length; ++i) {
      if (thelist[i].getName() === "raw") break;
    }
    if (i === thelist.length) return;
    const capa = thelist[i];
    for (let j = i + 1; j < thelist.length; ++j)
      thelist[j - 1] = thelist[j];
    thelist[thelist.length - 1] = capa;
  }

  /** Get major decompiler version */
  static getMajorVersion(): number {
    return ArchitectureCapability.majorversion;
  }

  /** Get minor decompiler version */
  static getMinorVersion(): number {
    return ArchitectureCapability.minorversion;
  }
}

// ---------------------------------------------------------------------------
// Architecture
// ---------------------------------------------------------------------------

/**
 * Manager for all the major decompiler subsystems.
 *
 * An instantiation is tailored to a specific LoadImage,
 * processor, and compiler spec. This class is the owner of
 * the LoadImage, Translate, symbols (Database), PrintLanguage, etc.
 * This class also holds numerous configuration parameters for the analysis process.
 */
export abstract class Architecture extends AddrSpaceManager {
  // ID string uniquely describing this architecture
  archid: string = "";

  // Configuration data
  trim_recurse_max: number = 5;
  max_implied_ref: number = 2;
  max_term_duplication: number = 2;
  max_basetype_size: number = 10;
  min_funcsymbol_size: number = 1;
  max_jumptable_size: number = 1024;
  aggressive_ext_trim: boolean = false;
  readonlypropagate: boolean = false;
  infer_pointers: boolean = true;
  analyze_for_loops: boolean = true;
  nan_ignore_all: boolean = false;
  nan_ignore_compare: boolean = true;
  inferPtrSpaces: AddrSpace[] = [];
  funcptr_align: number = 0;
  flowoptions: number = 0;
  max_instructions: number = 100000;
  alias_block_level: number = 2;
  split_datatype_config: number = 0;
  extra_pool_rules: Rule[] = [];
  enhancedDisplay: boolean = false;

  // Sub-components
  symboltab: any | null = null;
  context: ContextDatabase | null = null;
  protoModels: Map<string, ProtoModel> = new Map();
  defaultfp: ProtoModel | null = null;
  defaultReturnAddr: VarnodeData;
  evalfp_current: ProtoModel | null = null;
  evalfp_called: ProtoModel | null = null;
  types: TypeFactory | null = null;
  translate: Translate | null = null;
  loader: LoadImage | null = null;
  pcodeinjectlib: PcodeInjectLibrary | null = null;
  nohighptr: RangeList;
  commentdb: CommentDatabase | null = null;
  stringManager: StringManager | null = null;
  cpool: ConstantPool | null = null;
  print: PrintLanguage | null = null;
  printlist: PrintLanguage[] = [];
  options: OptionDatabase | null = null;
  inst: (any | null)[] = [];
  userops: UserOpManage;
  splitrecords: PreferSplitRecord[] = [];
  lanerecords: LanedRegister[] = [];
  allacts: ActionDatabase;
  loadersymbols_parsed: boolean = false;

  /**
   * Construct an uninitialized Architecture.
   * Set most sub-components to null pointers. Provide reasonable defaults
   * for the configurable options.
   */
  constructor() {
    super();
    this.resetDefaultsInternal();
    this.min_funcsymbol_size = 1;
    this.aggressive_ext_trim = false;
    this.funcptr_align = 0;
    this.defaultfp = null;
    this.defaultReturnAddr = new VarnodeData();
    this.defaultReturnAddr.space = null;
    this.evalfp_current = null;
    this.evalfp_called = null;
    this.types = null;
    this.translate = null;
    this.loader = null;
    this.pcodeinjectlib = null;
    this.commentdb = null;
    this.stringManager = null;
    this.cpool = null;
    this.symboltab = null;
    this.context = null;
    this.nohighptr = new RangeList();
    this.userops = new UserOpManage();
    this.allacts = new ActionDatabase();
    // Ensure PrintC capability is registered
    PrintCCapability.register();
    this.print = PrintLanguageCapability.getDefault().buildLanguage(this as any);
    this.printlist = [this.print];
    this.options = new OptionDatabase(this as any);
    this.loadersymbols_parsed = false;
  }

  /**
   * Load the image and configure architecture.
   * @param store is the XML document store
   */
  init(store: DocumentStorage): void {
    this.buildLoader(store);
    this.resolveArchitecture();
    this.buildSpecFile(store);
    this.buildContext(store);
    this.buildTypegrp(store);
    this.buildCommentDB(store);
    this.buildStringManager(store);
    this.buildConstantPool(store);
    this.buildDatabase(store);
    this.restoreFromSpec(store);
    this.buildCoreTypes(store);
    if (this.print !== null) {
      this.print.initializeFromArchitecture();
    }
    if (this.symboltab !== null) {
      this.symboltab.adjustCaches();
    }
    this.buildSymbols(store);
    this.postSpecFile();
    this.buildInstructions(store);
    this.fillinReadOnlyFromLoader();
  }

  /** Reset default values for options specific to Architecture */
  resetDefaultsInternal(): void {
    this.trim_recurse_max = 5;
    this.max_implied_ref = 2;
    this.max_term_duplication = 2;
    this.max_basetype_size = 10;
    this.flowoptions = FlowInfo_error_toomanyinstructions;
    this.max_instructions = 100000;
    this.infer_pointers = true;
    this.analyze_for_loops = true;
    this.readonlypropagate = false;
    this.nan_ignore_all = false;
    this.nan_ignore_compare = true;
    this.alias_block_level = 2;
    this.split_datatype_config = OptionSplitDatatypes_option_struct
      | OptionSplitDatatypes_option_array
      | OptionSplitDatatypes_option_pointer;
    this.max_jumptable_size = 1024;
  }

  /**
   * Reset default values for options owned by this.
   * Reset options that can be modified by the OptionDatabase. This includes
   * options specific to this class and options under PrintLanguage and ActionDatabase.
   */
  resetDefaults(): void {
    this.resetDefaultsInternal();
    this.allacts.resetDefaults();
    for (let i = 0; i < this.printlist.length; ++i)
      this.printlist[i].resetDefaults();
  }

  /**
   * Get a specific PrototypeModel by name.
   * @param nm is the name
   * @returns the matching model or null
   */
  getModel(nm: string): ProtoModel | null {
    const result = this.protoModels.get(nm);
    if (result === undefined)
      return null;
    return result;
  }

  /**
   * Does this Architecture have a specific PrototypeModel?
   * @param nm is the name of the model
   * @returns true if this Architecture supports a model with that name
   */
  hasModel(nm: string): boolean {
    return this.protoModels.has(nm);
  }

  /**
   * Create a model for an unrecognized name.
   * A new UnknownProtoModel, which clones its behavior from the default model,
   * is created and associated with the unrecognized name.
   * @param modelName is the unrecognized name
   * @returns the new unknown prototype model
   */
  createUnknownModel(modelName: string): ProtoModel {
    const model = new UnknownProtoModel(modelName, this.defaultfp!);
    this.protoModels.set(modelName, model);
    if (modelName === "unknown")
      model.setPrintInDecl(false);
    return model;
  }

  /**
   * Get the class/constructor for ValueSetSolver.
   * In C++ this is a virtual factory method. Here we return the default solver class.
   */
  getValueSetSolverClass(): new () => ValueSetSolver {
    return ValueSetSolver;
  }

  /**
   * Get the class/constructor for WidenerNone.
   * In C++ this is a virtual factory method. Here we return the default widener class.
   */
  getWidenerNoneClass(): new () => WidenerNone {
    return WidenerNone;
  }

  /**
   * Are pointers possible to the given location?
   * @param loc is the starting address of the range
   * @param size is the size of the range in bytes
   * @returns true if pointers are possible
   */
  highPtrPossible(loc: Address, size: number): boolean {
    if (loc.getSpace()!.getType() === spacetype.IPTR_INTERNAL) return false;
    return !this.nohighptr.inRange(loc, size);
  }

  /**
   * Get space associated with a spacebase register.
   * @param loc is the location of the spacebase register
   * @param size is the size of the register in bytes
   * @returns a pointer to the address space
   */
  getSpaceBySpacebase(loc: Address, size: number): AddrSpace {
    const sz = this.numSpaces();
    for (let i = 0; i < sz; ++i) {
      const id = this.getSpace(i);
      if (id === null) continue;
      const numspace = id.numSpacebase();
      for (let j = 0; j < numspace; ++j) {
        const point = id.getSpacebase(j);
        if (point.size !== size) continue;
        if (point.space !== loc.getSpace()) continue;
        if (point.offset !== loc.getOffset()) continue;
        return id;
      }
    }
    throw new LowlevelError("Unable to find entry for spacebase register");
  }

  /**
   * Get LanedRegister associated with storage.
   * @param loc is the starting address of the storage location
   * @param size is the size of the storage in bytes
   * @returns the matching LanedRegister record or null
   */
  getLanedRegister(loc: Address, size: number): LanedRegister | null {
    let min = 0;
    let max = this.lanerecords.length - 1;
    while (min <= max) {
      const mid = Math.floor((min + max) / 2);
      const sz = this.lanerecords[mid].getWholeSize();
      if (sz < size)
        min = mid + 1;
      else if (size < sz)
        max = mid - 1;
      else
        return this.lanerecords[mid];
    }
    return null;
  }

  /**
   * Get the minimum size of a laned register in bytes.
   * @returns the size in bytes of the smallest laned register or -1
   */
  getMinimumLanedRegisterSize(): number {
    if (this.lanerecords.length === 0)
      return -1;
    return this.lanerecords[0].getWholeSize();
  }

  /**
   * Set the default PrototypeModel.
   * @param model is the ProtoModel object to make the default
   */
  setDefaultModel(model: ProtoModel): void {
    if (this.defaultfp !== null)
      this.defaultfp.setPrintInDecl(true);
    model.setPrintInDecl(false);
    this.defaultfp = model;
  }

  /**
   * Clear analysis specific to a function.
   * @param fd is the function to clear
   */
  clearAnalysis(fd: Funcdata): void {
    fd.clear();
    this.commentdb!.clearType(fd.getAddress(), Comment_warning | Comment_warningheader);
  }

  /**
   * Read any symbols from loader into database.
   * @param delim is the delimiter separating namespaces from symbol base names
   */
  readLoaderSymbols(delim: string): void {
    if (this.loadersymbols_parsed) return;
    this.loader!.openSymbols();
    this.loadersymbols_parsed = true;
    const record: LoadImageFunc = {} as any;
    while (this.loader!.getNextSymbol(record)) {
      const result = this.symboltab!.findCreateScopeFromSymbolName(record.name, delim, null);
      result.scope.addFunction(record.address, result.basename);
    }
    this.loader!.closeSymbols();
  }

  /**
   * Enable enhanced display: standard C type names and Ghidra GUI-style globals.
   */
  applyEnhancedDisplay(): void {
    this.enhancedDisplay = true;
    if (this.types) this.types.applyEnhancedDisplayNames();
    if (this.print) {
      (this.print as any).setShowAddresses(true);
      (this.print as any).setNULLPrinting(true);
      (this.print as any).setInplaceOps(true);
    }
  }

  /**
   * Provide a list of OpBehavior objects.
   * @param behave is the list to be populated
   */
  collectBehaviors(behave: (OpBehavior | null)[]): void {
    behave.length = this.inst.length;
    for (let i = 0; i < behave.length; ++i)
      behave[i] = null;
    for (let i = 0; i < this.inst.length; ++i) {
      const op = this.inst[i];
      if (op === null) continue;
      behave[i] = op.getBehavior();
    }
  }

  /**
   * Retrieve the segment op for the given space if any.
   * @param spc is the address space to check
   * @returns the SegmentOp object or null
   */
  getSegmentOp(spc: AddrSpace): SegmentOp | null {
    if (spc.getIndex() >= this.userops.numSegmentOps()) return null;
    const segdef = this.userops.getSegmentOp(spc.getIndex());
    if (segdef === null) return null;
    if (segdef.getResolve().space !== null)
      return segdef;
    return null;
  }

  /**
   * Set the prototype for a particular function.
   * @param pieces holds the raw prototype information and the symbol name
   */
  setPrototype(pieces: PrototypePieces): void {
    const resolved = this.symboltab!.resolveScopeFromSymbolName(pieces.name, "::", null);
    if (resolved.scope === null)
      throw new ParseError("Unknown namespace: " + pieces.name);
    const fd = resolved.scope.queryFunction(resolved.basename);
    if (fd === null)
      throw new ParseError("Unknown function name: " + pieces.name);

    fd.getFuncProto().setPieces(pieces);
  }

  /**
   * Establish a particular output language.
   * @param nm is the name of the language
   */
  setPrintLanguage(nm: string): void {
    for (let i = 0; i < this.printlist.length; ++i) {
      if (this.printlist[i].getName() === nm) {
        this.print = this.printlist[i];
        this.print!.adjustTypeOperators();
        return;
      }
    }
    // In C++: PrintLanguageCapability *capa = PrintLanguageCapability::findCapability(nm);
    // This is a simplified version; full capability lookup would be needed
    throw new LowlevelError("Unknown print language: " + nm);
  }

  /**
   * Set all IPTR_PROCESSOR and IPTR_SPACEBASE spaces to be global.
   */
  globalify(): void {
    const scope = this.symboltab!.getGlobalScope();
    const nm = this.numSpaces();

    for (let i = 0; i < nm; ++i) {
      const spc = this.getSpace(i);
      if (spc === null) continue;
      if ((spc.getType() !== spacetype.IPTR_PROCESSOR) && (spc.getType() !== spacetype.IPTR_SPACEBASE)) continue;
      this.symboltab!.addRange(scope, spc, 0n, spc.getHighest());
    }
  }

  /**
   * Decode flow overrides from a stream.
   * @param decoder is the stream decoder
   */
  decodeFlowOverride(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_FLOWOVERRIDELIST);
    for (;;) {
      const subId = decoder.openElement();
      if (subId !== ELEM_FLOW.id) break;
      const flowType = decoder.readStringById(ATTRIB_TYPE);
      const funcaddr = Address.decode(decoder);
      const overaddr = Address.decode(decoder);
      const fd = this.symboltab!.getGlobalScope().queryFunction(funcaddr);
      if (fd !== null)
        fd.getOverride().insertFlowOverride(overaddr, (Override as any).stringToType(flowType));
      decoder.closeElement(subId);
    }
    decoder.closeElement(elemId);
  }

  /**
   * Get a string describing this architecture.
   * @returns the description
   */
  getDescription(): string {
    return this.archid;
  }

  /**
   * Print an error message to console.
   * @param message is the error message
   */
  abstract printMessage(message: string): void;

  /**
   * Encode this architecture to a stream.
   * @param encoder is the stream encoder
   */
  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_SAVE_STATE);
    encoder.writeBool(ATTRIB_LOADERSYMBOLS, this.loadersymbols_parsed);
    this.types!.encode(encoder);
    this.symboltab!.encode(encoder);
    this.context!.encode(encoder);
    this.commentdb!.encode(encoder);
    this.stringManager!.encode(encoder);
    if (!this.cpool!.empty())
      this.cpool!.encode(encoder);
    encoder.closeElement(ELEM_SAVE_STATE);
  }

  /**
   * Restore the Architecture state from XML documents.
   * @param store is document store containing the parsed root tag
   */
  restoreXml(store: DocumentStorage): void {
    const el = store.getTag(ELEM_SAVE_STATE.getName());
    if (el === null)
      throw new LowlevelError("Could not find save_state tag");
    const decoder: any = new (XmlDecode as any)(this, el);
    const elemId = decoder.openElementId(ELEM_SAVE_STATE);
    this.loadersymbols_parsed = false;
    for (;;) {
      const attribId = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_LOADERSYMBOLS.id)
        this.loadersymbols_parsed = decoder.readBool();
    }

    for (;;) {
      const subId = decoder.peekElement();
      if (subId === 0) break;
      if (subId === ELEM_TYPEGRP.id)
        this.types!.decode(decoder);
      else if (subId === ELEM_DB.id)
        this.symboltab!.decode(decoder);
      else if (subId === ELEM_CONTEXT_POINTS.id)
        this.context!.decode(decoder);
      else if (subId === ELEM_COMMENTDB.id)
        this.commentdb!.decode(decoder);
      else if (subId === ELEM_STRINGMANAGE.id)
        this.stringManager!.decode(decoder);
      else if (subId === ELEM_CONSTANTPOOL.id)
        this.cpool!.decode(decoder, this.types!);
      else if (subId === ELEM_OPTIONSLIST.id)
        this.options!.decode(decoder);
      else if (subId === ELEM_FLOWOVERRIDELIST.id)
        this.decodeFlowOverride(decoder);
      else if (subId === ELEM_INJECTDEBUG.id)
        this.pcodeinjectlib!.decodeDebug(decoder);
      else
        throw new LowlevelError("XML error restoring architecture");
    }
    decoder.closeElement(elemId);
  }

  /**
   * Pick a default name for a function.
   * @param addr is the address of the function
   * @returns the constructed name
   */
  nameFunction(addr: Address): string {
    let defname = "func_";
    const raw = addr.printRaw();
    defname += this.enhancedDisplay ? raw.replace(/^0x/, '') : raw;
    return defname;
  }

  // -----------------------------------------------------------------------
  // Protected methods
  // -----------------------------------------------------------------------

  /**
   * Create a new address space associated with a pointer register.
   * @param basespace is the address space underlying the stack
   * @param nm is the name of the new space
   * @param ptrdata is the register location acting as a pointer into the new space
   * @param truncSize is the (possibly truncated) size of the register
   * @param isreversejustified is true if small variables are justified opposite of endianness
   * @param stackGrowth is true if stack grows in the negative direction
   * @param isFormal is the indicator for the formal stack space
   */
  protected addSpacebase(
    basespace: AddrSpace,
    nm: string,
    ptrdata: VarnodeData,
    truncSize: number,
    isreversejustified: boolean,
    stackGrowth: boolean,
    isFormal: boolean
  ): void {
    const ind = this.numSpaces();
    const spc = new SpacebaseSpace(
      this as any,
      this.translate!,
      nm,
      ind,
      truncSize,
      basespace,
      (ptrdata.space as any).getDelay() + 1,
      isFormal
    );
    if (isreversejustified)
      this.setReverseJustified(spc);
    this.insertSpace(spc);
    this.addSpacebasePointer(spc, ptrdata, truncSize, stackGrowth);
  }

  /**
   * Add a new region where pointers do not exist.
   * @param rng is the new range with no aliases to be added
   */
  protected addNoHighPtr(rng: Range): void {
    this.nohighptr.insertRange(rng.getSpace(), rng.getFirst(), rng.getLast());
  }

  // -----------------------------------------------------------------------
  // Factory methods (abstract, to be implemented by subclasses)
  // -----------------------------------------------------------------------

  /**
   * Build the database and global scope for this executable.
   * @param store is the storage for any configuration data
   * @returns the global Scope object
   */
  protected buildDatabase(store: DocumentStorage): Scope {
    this.symboltab = new Database(this as any, true);
    const globscope = new (ScopeInternal as any)(0n, "", this);
    this.symboltab.attachScope(globscope, null);
    return globscope;
  }

  /** Build the Translator object */
  protected abstract buildTranslator(store: DocumentStorage): Translate;

  /** Build the LoadImage object and load the executable image */
  protected abstract buildLoader(store: DocumentStorage): void;

  /** Build the injection library */
  protected abstract buildPcodeInjectLibrary(): PcodeInjectLibrary;

  /** Build the data-type factory/container */
  protected abstract buildTypegrp(store: DocumentStorage): void;

  /** Add core primitive data-types */
  protected abstract buildCoreTypes(store: DocumentStorage): void;

  /** Build the comment database */
  protected abstract buildCommentDB(store: DocumentStorage): void;

  /** Build the string manager */
  protected abstract buildStringManager(store: DocumentStorage): void;

  /** Build the constant pool */
  protected abstract buildConstantPool(store: DocumentStorage): void;

  /**
   * Register the p-code operations.
   * @param store may hold configuration information
   */
  protected buildInstructions(store: DocumentStorage): void {
    TypeOp.registerInstructions(this.inst, this.types!, this.translate!);
  }

  /**
   * Build the Action framework.
   * @param store may hold configuration information
   */
  protected buildAction(store: DocumentStorage): void {
    this.parseExtraRules(store);
    this.allacts.universalAction(this as any);
    this.allacts.resetDefaults();
  }

  /** Build the Context database */
  protected abstract buildContext(store: DocumentStorage): void;

  /** Build any symbols from spec files */
  protected abstract buildSymbols(store: DocumentStorage): void;

  /** Load any relevant specification files */
  protected abstract buildSpecFile(store: DocumentStorage): void;

  /** Modify address spaces as required by this Architecture */
  protected abstract modifySpaces(trans: Translate): void;

  /** Let components initialize after Translate is built */
  protected postSpecFile(): void {
    this.cacheAddrSpaceProperties();
  }

  /** Figure out the processor and compiler of the target executable */
  protected abstract resolveArchitecture(): void;

  /**
   * Fully initialize the Translate object.
   * @param store will hold parsed configuration information
   */
  protected restoreFromSpec(store: DocumentStorage): void {
    const newtrans = this.buildTranslator(store);
    newtrans.initialize(store);
    this.translate = newtrans;
    this.modifySpaces(newtrans);
    this.copySpaces(newtrans);
    this.insertSpace(new (FspecSpace as any)(this, this.translate, this.numSpaces()));
    this.insertSpace(new (IopSpace as any)(this, this.translate, this.numSpaces()));
    this.insertSpace(new (JoinSpace as any)(this, this.translate, this.numSpaces()));
    this.userops.initialize(this as any);
    if (this.translate.getAlignment() <= 8)
      this.min_funcsymbol_size = this.translate.getAlignment();
    this.pcodeinjectlib = this.buildPcodeInjectLibrary();
    this.parseProcessorConfig(store);
    newtrans.setDefaultFloatFormats();
    this.parseCompilerConfig(store);
    this.buildAction(store);
  }

  /** Load info about read-only sections */
  protected fillinReadOnlyFromLoader(): void {
    const rangelist = new RangeList();
    this.loader!.getReadonly(rangelist);
    for (const rng of rangelist.getRanges()) {
      this.symboltab!.setPropertyRange(Varnode_readonly, rng);
    }
  }

  /** Set up segment resolvers */
  protected initializeSegments(): void {
    const sz = this.userops.numSegmentOps();
    for (let i = 0; i < sz; ++i) {
      const sop = this.userops.getSegmentOp(i);
      if (sop === null) continue;
      const rsolv = new SegmentedResolver(this, sop.getSpace()!, sop);
      this.insertResolver(sop.getSpace()!, rsolv);
    }
  }

  /**
   * Calculate some frequently used space properties and cache them.
   */
  protected cacheAddrSpaceProperties(): void {
    const copyList: AddrSpace[] = [...this.inferPtrSpaces];
    copyList.push(this.getDefaultCodeSpace()!);
    copyList.push(this.getDefaultDataSpace()!);
    this.inferPtrSpaces = [];
    copyList.sort((a, b) => a.getIndex() - b.getIndex());
    let lastSpace: AddrSpace | null = null;
    for (let i = 0; i < copyList.length; ++i) {
      const spc = copyList[i];
      if (spc === lastSpace) continue;
      lastSpace = spc;
      if (spc.getDelay() === 0) continue;
      if (spc.getType() === spacetype.IPTR_SPACEBASE) continue;
      if (spc.isOtherSpace()) continue;
      if (spc.isOverlay()) continue;
      this.inferPtrSpaces.push(spc);
    }

    let defPos = -1;
    for (let i = 0; i < this.inferPtrSpaces.length; ++i) {
      const spc = this.inferPtrSpaces[i];
      if (spc === this.getDefaultDataSpace())
        defPos = i;
      const segOp = this.getSegmentOp(spc);
      if (segOp !== null) {
        const val = segOp.getInnerSize();
        this.markNearPointers(spc, val);
      }
    }
    if (defPos > 0) {
      const tmp = this.inferPtrSpaces[0];
      this.inferPtrSpaces[0] = this.inferPtrSpaces[defPos];
      this.inferPtrSpaces[defPos] = tmp;
    }
  }

  /**
   * Clone the named ProtoModel, attaching it to another name.
   * @param aliasName is the new name to assign
   * @param parentName is the name of the parent model
   */
  protected createModelAlias(aliasName: string, parentName: string): void {
    const model = this.protoModels.get(parentName);
    if (model === undefined)
      throw new LowlevelError("Requesting non-existent prototype model: " + parentName);
    if (model.isMerged())
      throw new LowlevelError("Cannot make alias of merged model: " + parentName);
    if (model.getAliasParent() !== null)
      throw new LowlevelError("Cannot make alias of an alias: " + parentName);
    if (this.protoModels.has(aliasName))
      throw new LowlevelError("Duplicate ProtoModel name: " + aliasName);
    this.protoModels.set(aliasName, new ProtoModel(aliasName, model));
  }

  /**
   * Apply processor specific configuration.
   * @param store is the document store holding the tag
   */
  protected parseProcessorConfig(store: DocumentStorage): void {
    const el = store.getTag("processor_spec");
    if (el === null)
      throw new LowlevelError("No processor configuration tag found");
    const decoder: any = new (XmlDecode as any)(this, el);

    const elemId = decoder.openElementId(ELEM_PROCESSOR_SPEC);
    for (;;) {
      const subId = decoder.peekElement();
      if (subId === 0) break;
      if (subId === ELEM_PROGRAMCOUNTER.id) {
        decoder.openElement();
        decoder.closeElementSkipping(subId);
      }
      else if (subId === ELEM_VOLATILE.id)
        this.decodeVolatile(decoder);
      else if (subId === ELEM_INCIDENTALCOPY.id)
        this.decodeIncidentalCopy(decoder);
      else if (subId === ELEM_CONTEXT_DATA.id)
        this.context!.decodeFromSpec(decoder);
      else if (subId === ELEM_JUMPASSIST.id)
        this.userops.decodeJumpAssist(decoder, this as any);
      else if (subId === ELEM_SEGMENTOP.id)
        this.userops.decodeSegmentOp(decoder, this as any);
      else if (subId === ELEM_REGISTER_DATA.id)
        this.decodeRegisterData(decoder);
      else if (subId === ELEM_DATA_SPACE.id) {
        const innerElemId = decoder.openElement();
        const spc = decoder.readSpaceById(ATTRIB_SPACE);
        decoder.closeElement(innerElemId);
        this.setDefaultDataSpace(spc.getIndex());
      }
      else if (subId === ELEM_INFERPTRBOUNDS.id)
        this.decodeInferPtrBounds(decoder);
      else if (subId === ELEM_SEGMENTED_ADDRESS.id) {
        decoder.openElement();
        decoder.closeElementSkipping(subId);
      }
      else if (subId === ELEM_DEFAULT_SYMBOLS.id) {
        decoder.openElement();
        store.registerTag(decoder.getCurrentXmlElement());
        decoder.closeElementSkipping(subId);
      }
      else if (subId === ELEM_DEFAULT_MEMORY_BLOCKS.id) {
        decoder.openElement();
        decoder.closeElementSkipping(subId);
      }
      else if (subId === ELEM_ADDRESS_SHIFT_AMOUNT.id) {
        decoder.openElement();
        decoder.closeElementSkipping(subId);
      }
      else if (subId === ELEM_PROPERTIES.id) {
        decoder.openElement();
        decoder.closeElementSkipping(subId);
      }
      else
        throw new LowlevelError("Unknown element in <processor_spec>");
    }
    decoder.closeElement(elemId);
  }

  /**
   * Apply compiler specific configuration.
   * @param store is the document store holding the tag
   */
  protected parseCompilerConfig(store: DocumentStorage): void {
    const globalRanges: RangeProperties[] = [];
    const el = store.getTag("compiler_spec");
    if (el === null)
      throw new LowlevelError("No compiler configuration tag found");
    const decoder: any = new (XmlDecode as any)(this, el);

    const elemId = decoder.openElementId(ELEM_COMPILER_SPEC);
    for (;;) {
      const subId = decoder.peekElement();
      if (subId === 0) break;
      if (subId === ELEM_DEFAULT_PROTO.id)
        this.decodeDefaultProto(decoder);
      else if (subId === ELEM_PROTOTYPE.id)
        this.decodeProto(decoder);
      else if (subId === ELEM_STACKPOINTER.id)
        this.decodeStackPointer(decoder);
      else if (subId === ELEM_RETURNADDRESS.id)
        this.decodeReturnAddress(decoder);
      else if (subId === ELEM_SPACEBASE.id)
        this.decodeSpacebase(decoder);
      else if (subId === ELEM_NOHIGHPTR.id)
        this.decodeNoHighPtr(decoder);
      else if (subId === ELEM_PREFERSPLIT.id)
        this.decodePreferSplit(decoder);
      else if (subId === ELEM_AGGRESSIVETRIM.id)
        this.decodeAggressiveTrim(decoder);
      else if (subId === ELEM_DATA_ORGANIZATION.id)
        this.types!.decodeDataOrganization(decoder);
      else if (subId === ELEM_ENUM.id)
        this.types!.parseEnumConfig(decoder);
      else if (subId === ELEM_GLOBAL.id)
        this.decodeGlobal(decoder, globalRanges);
      else if (subId === ELEM_SEGMENTOP.id)
        this.userops.decodeSegmentOp(decoder, this as any);
      else if (subId === ELEM_READONLY.id)
        this.decodeReadOnly(decoder);
      else if (subId === ELEM_CONTEXT_DATA.id)
        this.context!.decodeFromSpec(decoder);
      else if (subId === ELEM_RESOLVEPROTOTYPE.id)
        this.decodeProto(decoder);
      else if (subId === ELEM_EVAL_CALLED_PROTOTYPE.id)
        this.decodeProtoEval(decoder);
      else if (subId === ELEM_EVAL_CURRENT_PROTOTYPE.id)
        this.decodeProtoEval(decoder);
      else if (subId === ELEM_CALLFIXUP.id) {
        this.pcodeinjectlib!.decodeInject(
          this.archid + " : compiler spec", "", InjectPayload_CALLFIXUP_TYPE, decoder
        );
      }
      else if (subId === ELEM_CALLOTHERFIXUP.id)
        this.userops.decodeCallOtherFixup(decoder, this as any);
      else if (subId === ELEM_FUNCPTR.id)
        this.decodeFuncPtrAlign(decoder);
      else if (subId === ELEM_DEADCODEDELAY.id)
        this.decodeDeadcodeDelay(decoder);
      else if (subId === ELEM_INFERPTRBOUNDS.id)
        this.decodeInferPtrBounds(decoder);
      else if (subId === ELEM_MODELALIAS.id) {
        const innerElemId = decoder.openElement();
        const aliasName = decoder.readStringById(ATTRIB_NAME);
        const parentName = decoder.readStringById(ATTRIB_PARENT);
        decoder.closeElement(innerElemId);
        this.createModelAlias(aliasName, parentName);
      }
    }
    decoder.closeElement(elemId);

    const extEl = store.getTag("specextensions");
    if (extEl !== null) {
      const decoderExt: any = new (XmlDecode as any)(this, extEl);
      const extElemId = decoderExt.openElement(ELEM_SPECEXTENSIONS);
      for (;;) {
        const subId = decoderExt.peekElement();
        if (subId === 0) break;
        if (subId === ELEM_PROTOTYPE.id)
          this.decodeProto(decoderExt);
        else if (subId === ELEM_CALLFIXUP.id) {
          this.pcodeinjectlib!.decodeInject(
            this.archid + " : compiler spec", "", InjectPayload_CALLFIXUP_TYPE, decoder
          );
        }
        else if (subId === ELEM_CALLOTHERFIXUP.id)
          this.userops.decodeCallOtherFixup(decoder, this as any);
        else if (subId === ELEM_GLOBAL.id)
          this.decodeGlobal(decoder, globalRanges);
      }
      decoderExt.closeElement(extElemId);
    }

    // <global> tags instantiate the base symbol table
    for (let i = 0; i < globalRanges.length; ++i)
      this.addToGlobalScope(globalRanges[i]);

    this.addOtherSpace();

    if (this.defaultfp === null) {
      if (this.protoModels.size > 0) {
        const firstValue = this.protoModels.values().next().value;
        this.setDefaultModel(firstValue!);
      }
      else
        throw new LowlevelError("No default prototype specified");
    }
    // We must have a __thiscall calling convention
    if (!this.protoModels.has("__thiscall")) {
      this.createModelAlias("__thiscall", this.defaultfp!.getName());
    }
    this.initializeSegments();
    PreferSplitManager.initialize(this.splitrecords);
    this.types!.setupSizes();
  }

  /**
   * Apply any Rule tags.
   * @param store is the document store containing the tag
   */
  protected parseExtraRules(store: DocumentStorage): void {
    const expertag = store.getTag("experimental_rules");
    if (expertag !== null) {
      const decoder: any = new (XmlDecode as any)(this, expertag);
      const elemId = decoder.openElementId(ELEM_EXPERIMENTAL_RULES);
      while (decoder.peekElement() !== 0)
        this.decodeDynamicRule(decoder);
      decoder.closeElement(elemId);
    }
  }

  /**
   * Apply details of a dynamic Rule object.
   * @param decoder is the stream decoder
   */
  protected decodeDynamicRule(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_RULE);
    let rulename = "";
    let groupname = "";
    let enabled = false;
    for (;;) {
      const attribId = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_NAME.id)
        rulename = decoder.readString();
      else if (attribId === ATTRIB_GROUP.id)
        groupname = decoder.readString();
      else if (attribId === ATTRIB_ENABLE.id)
        enabled = decoder.readBool();
      else
        throw new LowlevelError("Dynamic rule tag contains illegal attribute");
    }
    if (rulename.length === 0)
      throw new LowlevelError("Dynamic rule has no name");
    if (groupname.length === 0)
      throw new LowlevelError("Dynamic rule has no group");
    if (!enabled) {
      decoder.closeElement(elemId);
      return;
    }
    // Dynamic rules are not enabled in this build
    throw new LowlevelError("Dynamic rules have not been enabled for this decompiler");
  }

  /**
   * Parse a proto-type model from a stream.
   * @param decoder is the stream decoder
   * @returns the new ProtoModel object
   */
  protected decodeProto(decoder: Decoder): ProtoModel {
    let res: ProtoModel;
    const elemId = decoder.peekElement();
    if (elemId === ELEM_PROTOTYPE.id)
      res = new ProtoModel(this as any);
    else if (elemId === ELEM_RESOLVEPROTOTYPE.id)
      res = new ProtoModelMerged(this as any);
    else
      throw new LowlevelError("Expecting <prototype> or <resolveprototype> tag");

    res.decode(decoder);

    const other = this.getModel(res.getName());
    if (other !== null) {
      const errMsg = "Duplicate ProtoModel name: " + res.getName();
      throw new LowlevelError(errMsg);
    }
    this.protoModels.set(res.getName(), res);
    return res;
  }

  /**
   * Apply prototype evaluation configuration.
   * @param decoder is the stream decoder
   */
  protected decodeProtoEval(decoder: Decoder): void {
    const elemId = decoder.openElement();
    const modelName = decoder.readStringById(ATTRIB_NAME);
    const res = this.getModel(modelName);
    if (res === null)
      throw new LowlevelError("Unknown prototype model name: " + modelName);

    if (elemId === ELEM_EVAL_CALLED_PROTOTYPE.id) {
      if (this.evalfp_called !== null)
        throw new LowlevelError("Duplicate <eval_called_prototype> tag");
      this.evalfp_called = res;
    }
    else {
      if (this.evalfp_current !== null)
        throw new LowlevelError("Duplicate <eval_current_prototype> tag");
      this.evalfp_current = res;
    }
    decoder.closeElement(elemId);
  }

  /**
   * Apply default prototype model configuration.
   * @param decoder is the stream decoder
   */
  protected decodeDefaultProto(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_DEFAULT_PROTO);
    while (decoder.peekElement() !== 0) {
      if (this.defaultfp !== null)
        throw new LowlevelError("More than one default prototype model");
      const model = this.decodeProto(decoder);
      this.setDefaultModel(model);
    }
    decoder.closeElement(elemId);
  }

  /**
   * Parse information about global ranges.
   * @param decoder is the stream decoder
   * @param rangeProps is where the partially parsed ranges are stored
   */
  protected decodeGlobal(decoder: Decoder, rangeProps: RangeProperties[]): void {
    const elemId = decoder.openElementId(ELEM_GLOBAL);
    while (decoder.peekElement() !== 0) {
      const prop = new RangeProperties();
      prop.decode(decoder);
      rangeProps.push(prop);
    }
    decoder.closeElement(elemId);
  }

  /**
   * Add a memory range to the set of addresses considered global.
   * @param props is information about a specific range
   */
  protected addToGlobalScope(props: RangeProperties): void {
    const scope = this.symboltab!.getGlobalScope();
    const range = new (Range as any)(props, this) as Range;
    const spc = range.getSpace();
    this.inferPtrSpaces.push(spc);
    this.symboltab!.addRange(scope, spc, range.getFirst(), range.getLast());
    if (range.getSpace().isOverlayBase()) {
      const num = this.numSpaces();
      for (let i = 0; i < num; ++i) {
        const ospc = this.getSpace(i);
        if (ospc === null || !ospc.isOverlay()) continue;
        if (ospc.getContain() !== range.getSpace()) continue;
        this.symboltab!.addRange(scope, ospc, range.getFirst(), range.getLast());
      }
    }
  }

  /**
   * Add OTHER space and all of its overlays to the symboltab.
   */
  protected addOtherSpace(): void {
    const scope = this.symboltab!.getGlobalScope();
    const otherSpace = this.getSpaceByName(OtherSpace_NAME);
    this.symboltab!.addRange(scope, otherSpace!, 0n, otherSpace!.getHighest());
    if (otherSpace!.isOverlayBase()) {
      const num = this.numSpaces();
      for (let i = 0; i < num; ++i) {
        const ospc = this.getSpace(i);
        if (ospc === null || !ospc.isOverlay()) continue;
        if (ospc.getContain() !== otherSpace) continue;
        this.symboltab!.addRange(scope, ospc, 0n, otherSpace!.getHighest());
      }
    }
  }

  /**
   * Apply read-only region configuration.
   * @param decoder is the stream decoder
   */
  protected decodeReadOnly(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_READONLY);
    while (decoder.peekElement() !== 0) {
      const range = new Range();
      (range as any).decode(decoder);
      this.symboltab!.setPropertyRange(Varnode_readonly, range);
    }
    decoder.closeElement(elemId);
  }

  /**
   * Apply volatile region configuration.
   * @param decoder is the stream decoder
   */
  protected decodeVolatile(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_VOLATILE);
    this.userops.decodeVolatile(decoder, this as any);
    while (decoder.peekElement() !== 0) {
      const range = new Range();
      (range as any).decode(decoder);
      this.symboltab!.setPropertyRange(Varnode_volatil, range);
    }
    decoder.closeElement(elemId);
  }

  /**
   * Apply return address configuration.
   * @param decoder is the stream decoder
   */
  protected decodeReturnAddress(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_RETURNADDRESS);
    const subId = decoder.peekElement();
    if (subId !== 0) {
      if (this.defaultReturnAddr.space !== null)
        throw new LowlevelError("Multiple <returnaddress> tags in .cspec");
      this.defaultReturnAddr.decode(decoder);
    }
    decoder.closeElement(elemId);
  }

  /**
   * Apply incidental copy configuration.
   * @param decoder is the stream decoder
   */
  protected decodeIncidentalCopy(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_INCIDENTALCOPY);
    while (decoder.peekElement() !== 0) {
      const vdata = new VarnodeData();
      (vdata as any).decode(decoder);
      const range = new Range(vdata.space! as any as AddrSpace, vdata.offset, vdata.offset + BigInt(vdata.size) - 1n);
      this.symboltab!.setPropertyRange(Varnode_incidental_copy, range);
    }
    decoder.closeElement(elemId);
  }

  /**
   * Read specific register properties.
   * @param decoder is the stream decoder
   */
  protected decodeRegisterData(decoder: Decoder): void {
    const maskList: number[] = [];

    const elemId = decoder.openElementId(ELEM_REGISTER_DATA);
    while (decoder.peekElement() !== 0) {
      const subId = decoder.openElementId(ELEM_REGISTER);
      let isVolatile = false;
      let laneSizes = "";
      for (;;) {
        const attribId = decoder.getNextAttributeId();
        if (attribId === 0) break;
        if (attribId === ATTRIB_VECTOR_LANE_SIZES.id) {
          laneSizes = decoder.readString();
        }
        else if (attribId === ATTRIB_VOLATILE.id) {
          isVolatile = decoder.readBool();
        }
      }
      if (laneSizes.length > 0 || isVolatile) {
        decoder.rewindAttributes();
        const storage = new VarnodeData();
        storage.space = null;
        (storage as any).decodeFromAttributes(decoder);
        if (laneSizes.length > 0) {
          const lanedRegister: any = { parseSizes: () => {}, getWholeSize: () => 0, getSizeBitMask: () => 0 };
          lanedRegister.parseSizes(storage.size, laneSizes);
          const sizeIndex = lanedRegister.getWholeSize();
          while (maskList.length <= sizeIndex)
            maskList.push(0);
          maskList[sizeIndex] |= lanedRegister.getSizeBitMask();
        }
        if (isVolatile) {
          const range = new Range(storage.space! as any as AddrSpace, storage.offset, storage.offset + BigInt(storage.size) - 1n);
          this.symboltab!.setPropertyRange(Varnode_volatil, range);
        }
      }
      decoder.closeElement(subId);
    }
    decoder.closeElement(elemId);
    this.lanerecords = [];
    for (let i = 0; i < maskList.length; ++i) {
      if (maskList[i] === 0) continue;
      // LanedRegister constructor: new LanedRegister(i, maskList[i])
      this.lanerecords.push({ wholeSize: i, sizeBitMask: maskList[i], getWholeSize: () => i });
    }
  }

  /**
   * Create a stack space and a stack-pointer register from a \<stackpointer> element.
   * @param decoder is the stream decoder
   */
  protected decodeStackPointer(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_STACKPOINTER);

    let registerName = "";
    let stackGrowth = true;
    let isreversejustify = false;
    let basespace: AddrSpace | null = null;
    for (;;) {
      const attribId = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_REVERSEJUSTIFY.id)
        isreversejustify = decoder.readBool();
      else if (attribId === ATTRIB_GROWTH.id)
        stackGrowth = decoder.readString() === "negative";
      else if (attribId === ATTRIB_SPACE.id)
        basespace = decoder.readSpace() as any as AddrSpace;
      else if (attribId === ATTRIB_REGISTER.id)
        registerName = decoder.readString();
    }

    if (basespace === null)
      throw new LowlevelError(ELEM_STACKPOINTER.getName() + " element missing \"space\" attribute");

    const point = this.translate!.getRegister(registerName);
    decoder.closeElement(elemId);

    let truncSize = point.size;
    if (basespace.isTruncated() && (point.size > basespace.getAddrSize())) {
      truncSize = basespace.getAddrSize();
    }

    this.addSpacebase(basespace, "stack", point, truncSize, isreversejustify, stackGrowth, true);
  }

  /**
   * Apply dead-code delay configuration.
   * @param decoder is the stream decoder
   */
  protected decodeDeadcodeDelay(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_DEADCODEDELAY);
    const spc = decoder.readSpaceById(ATTRIB_SPACE) as any as AddrSpace;
    const delay = decoder.readSignedIntegerById(ATTRIB_DELAY);
    if (delay >= 0)
      this.setDeadcodeDelay(spc, delay);
    else
      throw new LowlevelError("Bad <deadcodedelay> tag");
    decoder.closeElement(elemId);
  }

  /**
   * Apply pointer inference bounds.
   * @param decoder is the stream decoder
   */
  protected decodeInferPtrBounds(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_INFERPTRBOUNDS);
    while (decoder.peekElement() !== 0) {
      const range = new Range();
      (range as any).decode(decoder);
      this.setInferPtrBounds(range);
    }
    decoder.closeElement(elemId);
  }

  /**
   * Apply function pointer alignment configuration.
   * @param decoder is the stream decoder
   */
  protected decodeFuncPtrAlign(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_FUNCPTR);
    let align = decoder.readSignedIntegerById(ATTRIB_ALIGN);
    decoder.closeElement(elemId);

    if (align === 0) {
      this.funcptr_align = 0;
      return;
    }
    let bits = 0;
    while ((align & 1) === 0) {
      bits += 1;
      align >>= 1;
    }
    this.funcptr_align = bits;
  }

  /**
   * Create an additional indexed space.
   * @param decoder is the stream decoder
   */
  protected decodeSpacebase(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_SPACEBASE);
    const nameString = decoder.readStringById(ATTRIB_NAME);
    const registerName = decoder.readStringById(ATTRIB_REGISTER);
    const basespace = decoder.readSpaceById(ATTRIB_SPACE) as any as AddrSpace;
    decoder.closeElement(elemId);
    const point = this.translate!.getRegister(registerName);
    this.addSpacebase(basespace, nameString, point, point.size, false, false, false);
  }

  /**
   * Apply memory alias configuration.
   * @param decoder is the stream decoder
   */
  protected decodeNoHighPtr(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_NOHIGHPTR);
    while (decoder.peekElement() !== 0) {
      const range = new Range();
      (range as any).decode(decoder);
      this.addNoHighPtr(range);
    }
    decoder.closeElement(elemId);
  }

  /**
   * Designate registers to be split.
   * @param decoder is the stream decoder
   */
  protected decodePreferSplit(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_PREFERSPLIT);
    const style = decoder.readStringById(ATTRIB_STYLE);
    if (style !== "inhalf")
      throw new LowlevelError("Unknown prefersplit style: " + style);

    while (decoder.peekElement() !== 0) {
      const record = new PreferSplitRecord();
      record.storage.decode(decoder);
      record.splitoffset = Math.floor(record.storage.size / 2);
      this.splitrecords.push(record);
    }
    decoder.closeElement(elemId);
  }

  /**
   * Designate how to trim extension p-code ops.
   * @param decoder is the stream decoder
   */
  protected decodeAggressiveTrim(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_AGGRESSIVETRIM);
    for (;;) {
      const attribId = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_SIGNEXT.id) {
        this.aggressive_ext_trim = decoder.readBool();
      }
    }
    decoder.closeElement(elemId);
  }
}

// ---------------------------------------------------------------------------
// SegmentedResolver
// ---------------------------------------------------------------------------

/**
 * A resolver for segmented architectures.
 *
 * When the decompiler is attempting to resolve embedded constants as pointers,
 * this class tries to recover segment info for near pointers by looking up
 * tracked registers in context.
 */
export class SegmentedResolver extends AddressResolver {
  private glb: Architecture;
  private spc: AddrSpace;
  private segop: SegmentOp;

  /**
   * Construct a segmented resolver.
   * @param g is the owning Architecture
   * @param sp is the segmented space
   * @param sop is the segment operator
   */
  constructor(g: Architecture, sp: AddrSpace, sop: SegmentOp) {
    super();
    this.glb = g;
    this.spc = sp;
    this.segop = sop;
  }

  resolve(val: uintb, sz: int4, point: Address, fullEncoding: { val: uintb }): Address {
    const innersz = this.segop.getInnerSize();
    if (sz >= 0 && sz <= innersz) {
      // Value is a "near" pointer
      if (this.segop.getResolve().space !== null) {
        const base = this.glb.context!.getTrackedValue(this.segop.getResolve(), point);
        fullEncoding.val = (base << BigInt(8 * innersz)) + (val & calc_mask(innersz));
        const seginput: bigint[] = [base, val];
        const newval = this.segop.execute(seginput);
        return new Address(this.spc, AddrSpace.addressToByte(newval, this.spc.getWordSize()));
      }
    }
    else {
      // For anything else, consider it a "far" pointer
      fullEncoding.val = val;
      const outersz = this.segop.getBaseSize();
      const base = (val >> BigInt(8 * innersz)) & calc_mask(outersz);
      const innerval = val & calc_mask(innersz);
      const seginput: bigint[] = [base, innerval];
      const newval = this.segop.execute(seginput);
      return new Address(this.spc, AddrSpace.addressToByte(newval, this.spc.getWordSize()));
    }
    // Return invalid address
    fullEncoding.val = 0n;
    return new Address();
  }
}
