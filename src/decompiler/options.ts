/**
 * @file options.ts
 * @description Classes for processing architecture configuration options.
 * Translated from Ghidra's options.hh / options.cc
 */

import type { int4, uint4 } from '../core/types.js';
import {
  ElementId,
  AttributeId,
  ATTRIB_CONTENT,
} from '../core/marshal.js';
import type { Decoder } from '../core/marshal.js';
import { ParseError, LowlevelError, RecovError } from '../core/error.js';

// ---------------------------------------------------------------------------
// Forward type declarations for not-yet-written modules
// ---------------------------------------------------------------------------

type Architecture = any;
type Funcdata = any;
type ProtoModel = any;
type PrintC = any;
type PrintLanguage = any;
type Action = any;
type Comment = any;
type FlowInfo = any;
type Emit = any;

// ---------------------------------------------------------------------------
// FlowInfo flag constants (from flow.hh)
// ---------------------------------------------------------------------------

const FlowInfoFlags = {
  ignore_unimplemented: 2,
  error_unimplemented: 8,
  error_reinterpreted: 0x10,
  error_toomanyinstructions: 0x20,
  record_jumploads: 0x4000,
} as const;

// ---------------------------------------------------------------------------
// ProtoModel constant (from fspec.hh)
// ---------------------------------------------------------------------------

const EXTRAPOP_UNKNOWN = 0x8000;

// ---------------------------------------------------------------------------
// Emit brace_style constants (from prettyprint.hh)
// ---------------------------------------------------------------------------

const BraceStyle = {
  same_line: 0,
  next_line: 1,
  skip_line: 2,
} as const;

// ---------------------------------------------------------------------------
// PrintLanguage namespace_strategy constants (from printlanguage.hh)
// ---------------------------------------------------------------------------

const NamespaceStrategy = {
  MINIMAL_NAMESPACES: 0,
  NO_NAMESPACES: 1,
  ALL_NAMESPACES: 2,
} as const;

// ---------------------------------------------------------------------------
// ElementId constants (from options.cc)
// ---------------------------------------------------------------------------

export const ELEM_ALIASBLOCK               = new ElementId("aliasblock", 174);
export const ELEM_ALLOWCONTEXTSET          = new ElementId("allowcontextset", 175);
export const ELEM_ANALYZEFORLOOPS          = new ElementId("analyzeforloops", 176);
export const ELEM_COMMENTHEADER            = new ElementId("commentheader", 177);
export const ELEM_COMMENTINDENT            = new ElementId("commentindent", 178);
export const ELEM_COMMENTINSTRUCTION       = new ElementId("commentinstruction", 179);
export const ELEM_COMMENTSTYLE             = new ElementId("commentstyle", 180);
export const ELEM_CONVENTIONPRINTING       = new ElementId("conventionprinting", 181);
export const ELEM_CURRENTACTION            = new ElementId("currentaction", 182);
export const ELEM_DEFAULTPROTOTYPE         = new ElementId("defaultprototype", 183);
export const ELEM_ERRORREINTERPRETED       = new ElementId("errorreinterpreted", 184);
export const ELEM_ERRORTOOMANYINSTRUCTIONS = new ElementId("errortoomanyinstructions", 185);
export const ELEM_ERRORUNIMPLEMENTED       = new ElementId("errorunimplemented", 186);
export const ELEM_EXTRAPOP                 = new ElementId("extrapop", 187);
export const ELEM_IGNOREUNIMPLEMENTED      = new ElementId("ignoreunimplemented", 188);
export const ELEM_INDENTINCREMENT          = new ElementId("indentincrement", 189);
export const ELEM_INFERCONSTPTR            = new ElementId("inferconstptr", 190);
export const ELEM_INLINE                   = new ElementId("inline", 191);
export const ELEM_INPLACEOPS               = new ElementId("inplaceops", 192);
export const ELEM_INTEGERFORMAT            = new ElementId("integerformat", 193);
export const ELEM_JUMPLOAD                 = new ElementId("jumpload", 194);
export const ELEM_MAXINSTRUCTION           = new ElementId("maxinstruction", 195);
export const ELEM_MAXLINEWIDTH             = new ElementId("maxlinewidth", 196);
export const ELEM_NAMESPACESTRATEGY        = new ElementId("namespacestrategy", 197);
export const ELEM_NOCASTPRINTING           = new ElementId("nocastprinting", 198);
export const ELEM_NORETURN                 = new ElementId("noreturn", 199);
export const ELEM_NULLPRINTING             = new ElementId("nullprinting", 200);
export const ELEM_OPTIONSLIST              = new ElementId("optionslist", 201);
export const ELEM_PARAM1                   = new ElementId("param1", 202);
export const ELEM_PARAM2                   = new ElementId("param2", 203);
export const ELEM_PARAM3                   = new ElementId("param3", 204);
export const ELEM_PROTOEVAL                = new ElementId("protoeval", 205);
export const ELEM_SETACTION                = new ElementId("setaction", 206);
export const ELEM_SETLANGUAGE              = new ElementId("setlanguage", 207);
export const ELEM_SPLITDATATYPE            = new ElementId("splitdatatype", 270);
export const ELEM_STRUCTALIGN              = new ElementId("structalign", 208);
export const ELEM_TOGGLERULE              = new ElementId("togglerule", 209);
export const ELEM_WARNING                  = new ElementId("warning", 210);
export const ELEM_JUMPTABLEMAX             = new ElementId("jumptablemax", 271);
export const ELEM_NANIGNORE                = new ElementId("nanignore", 272);
export const ELEM_BRACEFORMAT              = new ElementId("braceformat", 284);

// ---------------------------------------------------------------------------
// Utility: parse an integer from a string, allowing hex/oct/dec prefixes
// ---------------------------------------------------------------------------

/**
 * Parse an integer from a string, supporting optional 0x (hex) and 0 (octal) prefixes.
 * Returns NaN if parsing fails.
 */
function parseIntAuto(s: string): number {
  s = s.trim();
  if (s.length === 0) return NaN;
  if (s.startsWith("0x") || s.startsWith("0X")) {
    return parseInt(s, 16);
  }
  if (s.startsWith("0") && s.length > 1 && !s.startsWith("0.")) {
    return parseInt(s, 8);
  }
  return parseInt(s, 10);
}

// ---------------------------------------------------------------------------
// ArchOption - base class
// ---------------------------------------------------------------------------

/**
 * Base class for options classes that affect the configuration of the Architecture object.
 *
 * Each class instance affects configuration through its apply() method, which is handed the
 * Architecture object to be configured along with string based parameters. The apply() methods
 * are run once during initialization of the Architecture object.
 */
export abstract class ArchOption {
  protected name: string = "";

  /** Return the name of the option */
  getName(): string {
    return this.name;
  }

  /**
   * Apply a particular configuration option to the Architecture.
   *
   * This method is overloaded by the different Option classes to provide possible configuration
   * of different parts of the Architecture. The user can provide up to three optional parameters
   * to tailor a specific type of configuration. The method returns a confirmation/failure message
   * as feedback.
   * @param glb - the Architecture being configured
   * @param p1 - the first optional configuration string
   * @param p2 - the second optional configuration string
   * @param p3 - the third optional configuration string
   * @returns a confirmation/failure message
   */
  abstract apply(glb: Architecture, p1: string, p2: string, p3: string): string;

  /**
   * Parse an "on" or "off" string.
   * If the parameter is "on" return true, if "off" return false.
   * An empty string defaults to true. Any other value causes an exception.
   * @param p - the parameter
   * @returns the parsed boolean value
   */
  static onOrOff(p: string): boolean {
    if (p.length === 0)
      return true;
    if (p === "on")
      return true;
    if (p === "off")
      return false;
    throw new ParseError("Must specify toggle value, on/off");
  }
}

// ---------------------------------------------------------------------------
// OptionDatabase
// ---------------------------------------------------------------------------

/**
 * A Dispatcher for possible ArchOption commands.
 *
 * An option command is a specific request by a user to change the configuration options
 * for an Architecture. This class takes care of dispatching the command to the proper ArchOption
 * derived class, which does the work of actually modifying the configuration. The command is issued
 * either through the set() method directly, or via an element handed to the decode() method.
 * The decode() method expects an \<optionslist\> element with one or more children. The child names
 * match the registered name of the option and have up to three child elements, \<param1\>, \<param2\> and \<param3\>,
 * whose content is provided as the optional parameters to command.
 */
export class OptionDatabase {
  private glb: Architecture;
  private optionmap: Map<uint4, ArchOption> = new Map();

  /**
   * Map from ArchOption name to its class instance.
   * @param option - the new ArchOption instance
   */
  private registerOption(option: ArchOption): void {
    const id: uint4 = ElementId.find(option.getName(), 0);
    this.optionmap.set(id, option);
  }

  /**
   * Construct given the owning Architecture.
   * Register all possible ArchOption objects with this database and set-up the parsing map.
   * @param g - the Architecture owning this database
   */
  constructor(g: Architecture) {
    this.glb = g;
    this.registerOption(new OptionExtraPop());
    this.registerOption(new OptionReadOnly());
    this.registerOption(new OptionIgnoreUnimplemented());
    this.registerOption(new OptionErrorUnimplemented());
    this.registerOption(new OptionErrorReinterpreted());
    this.registerOption(new OptionErrorTooManyInstructions());
    this.registerOption(new OptionDefaultPrototype());
    this.registerOption(new OptionInferConstPtr());
    this.registerOption(new OptionForLoops());
    this.registerOption(new OptionInline());
    this.registerOption(new OptionNoReturn());
    this.registerOption(new OptionProtoEval());
    this.registerOption(new OptionWarning());
    this.registerOption(new OptionNullPrinting());
    this.registerOption(new OptionInPlaceOps());
    this.registerOption(new OptionConventionPrinting());
    this.registerOption(new OptionNoCastPrinting());
    this.registerOption(new OptionMaxLineWidth());
    this.registerOption(new OptionIndentIncrement());
    this.registerOption(new OptionCommentIndent());
    this.registerOption(new OptionCommentStyle());
    this.registerOption(new OptionCommentHeader());
    this.registerOption(new OptionCommentInstruction());
    this.registerOption(new OptionIntegerFormat());
    this.registerOption(new OptionBraceFormat());
    this.registerOption(new OptionCurrentAction());
    this.registerOption(new OptionAllowContextSet());
    this.registerOption(new OptionSetAction());
    this.registerOption(new OptionSetLanguage());
    this.registerOption(new OptionJumpTableMax());
    this.registerOption(new OptionJumpLoad());
    this.registerOption(new OptionToggleRule());
    this.registerOption(new OptionAliasBlock());
    this.registerOption(new OptionMaxInstruction());
    this.registerOption(new OptionNamespaceStrategy());
    this.registerOption(new OptionSplitDatatypes());
    this.registerOption(new OptionNanIgnore());
  }

  /**
   * Issue an option command.
   * Perform an option command directly, given its id and optional parameters.
   * @param nameId - the id of the option
   * @param p1 - the first optional parameter
   * @param p2 - the second optional parameter
   * @param p3 - the third optional parameter
   * @returns the confirmation/failure message after trying to apply the option
   */
  set(nameId: uint4, p1: string = "", p2: string = "", p3: string = ""): string {
    const opt = this.optionmap.get(nameId);
    if (opt === undefined)
      throw new ParseError("Unknown option");
    return opt.apply(this.glb, p1, p2, p3);
  }

  /**
   * Parse and execute a single option element.
   * Scan the name and optional parameters and call method set().
   * @param decoder - the stream decoder
   */
  decodeOne(decoder: Decoder): void {
    let p1 = "";
    let p2 = "";
    let p3 = "";

    const elemId: uint4 = decoder.openElement();
    let subId: uint4 = decoder.openElement();
    if (subId === ELEM_PARAM1.getId()) {
      p1 = decoder.readStringById(ATTRIB_CONTENT);
      decoder.closeElement(subId);
      subId = decoder.openElement();
      if (subId === ELEM_PARAM2.getId()) {
        p2 = decoder.readStringById(ATTRIB_CONTENT);
        decoder.closeElement(subId);
        subId = decoder.openElement();
        if (subId === ELEM_PARAM3.getId()) {
          p3 = decoder.readStringById(ATTRIB_CONTENT);
          decoder.closeElement(subId);
        }
      }
    }
    else if (subId === 0) {
      p1 = decoder.readStringById(ATTRIB_CONTENT);  // If no children, content is param 1
    }
    decoder.closeElement(elemId);
    this.set(elemId, p1, p2, p3);
  }

  /**
   * Execute a series of option commands parsed from a stream.
   * Parse an \<optionslist\> element, treating each child as an option command.
   * @param decoder - the stream decoder
   */
  decode(decoder: Decoder): void {
    const elemId: uint4 = (decoder as any).openElement(ELEM_OPTIONSLIST);

    while (decoder.peekElement() !== 0)
      this.decodeOne(decoder);
    decoder.closeElement(elemId);
  }
}

// ---------------------------------------------------------------------------
// Concrete ArchOption subclasses
// ---------------------------------------------------------------------------

/**
 * Set the extrapop parameter used by the (default) prototype model.
 *
 * The extrapop for a function is the number of bytes popped from the stack that
 * a calling function can assume when this function is called.
 *
 * The first parameter is the integer value to use as the extrapop, or the special
 * value "unknown" which triggers the extrapop recovery analysis.
 *
 * The second parameter, if present, indicates a specific function to modify. Otherwise,
 * the default prototype model is modified.
 */
export class OptionExtraPop extends ArchOption {
  constructor() {
    super();
    this.name = "extrapop";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    let expop: int4 = -300;
    let res: string;
    if (p1 === "unknown")
      expop = EXTRAPOP_UNKNOWN;
    else {
      expop = parseIntAuto(p1);
    }
    if (isNaN(expop) || expop === -300)
      throw new ParseError("Bad extrapop adjustment parameter");
    if (p2.length !== 0) {
      const fd = (glb as any).symboltab.getGlobalScope().queryFunction(p2);
      if (fd == null)
        throw new RecovError("Unknown function name: " + p2);
      (fd as any).getFuncProto().setExtraPop(expop);
      res = "ExtraPop set for function " + p2;
    }
    else {
      (glb as any).defaultfp.setExtraPop(expop);
      if ((glb as any).evalfp_current != null)
        (glb as any).evalfp_current.setExtraPop(expop);
      if ((glb as any).evalfp_called != null)
        (glb as any).evalfp_called.setExtraPop(expop);
      res = "Global extrapop set";
    }
    return res;
  }
}

/**
 * Toggle whether read-only memory locations have their value propagated.
 *
 * Setting this to "on", causes the decompiler to treat read-only memory locations as
 * constants that can be propagated.
 */
export class OptionReadOnly extends ArchOption {
  constructor() {
    super();
    this.name = "readonly";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    if (p1.length === 0)
      throw new ParseError("Read-only option must be set \"on\" or \"off\"");
    (glb as any).readonlypropagate = ArchOption.onOrOff(p1);
    if ((glb as any).readonlypropagate)
      return "Read-only memory locations now propagate as constants";
    return "Read-only memory locations now do not propagate";
  }
}

/**
 * Set the default prototype model for analyzing unknown functions.
 *
 * The first parameter must give the name of a registered prototype model.
 */
export class OptionDefaultPrototype extends ArchOption {
  constructor() {
    super();
    this.name = "defaultprototype";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    const model = (glb as any).getModel(p1);
    if (model == null)
      throw new LowlevelError("Unknown prototype model :" + p1);
    (glb as any).setDefaultModel(model);
    return "Set default prototype to " + p1;
  }
}

/**
 * Toggle whether the decompiler attempts to infer constant pointers.
 *
 * Setting the first parameter to "on" causes the decompiler to check if unknown
 * constants look like a reference to a known symbol's location.
 */
export class OptionInferConstPtr extends ArchOption {
  constructor() {
    super();
    this.name = "inferconstptr";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    const val: boolean = ArchOption.onOrOff(p1);

    let res: string;
    if (val) {
      res = "Constant pointers are now inferred";
      (glb as any).infer_pointers = true;
    }
    else {
      res = "Constant pointers must now be set explicitly";
      (glb as any).infer_pointers = false;
    }
    return res;
  }
}

/**
 * Toggle whether the decompiler attempts to recover for-loop variables.
 *
 * Setting the first parameter to "on" causes the decompiler to search for a suitable loop variable
 * controlling iteration of a while-do block.
 */
export class OptionForLoops extends ArchOption {
  constructor() {
    super();
    this.name = "analyzeforloops";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    (glb as any).analyze_for_loops = ArchOption.onOrOff(p1);

    const res: string = "Recovery of for-loops is " + p1;
    return res;
  }
}

/**
 * Mark/unmark a specific function as inline.
 *
 * The first parameter gives the symbol name of a function. The second parameter is
 * "true" to set the inline property, "false" to clear.
 */
export class OptionInline extends ArchOption {
  constructor() {
    super();
    this.name = "inline";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    const infd = (glb as any).symboltab.getGlobalScope().queryFunction(p1);
    if (infd == null)
      throw new RecovError("Unknown function name: " + p1);
    let val: boolean;
    if (p2.length === 0)
      val = true;
    else
      val = (p2 === "true");
    (infd as any).getFuncProto().setInline(val);
    const prop: string = val ? "true" : "false";
    const res: string = "Inline property for function " + p1 + " = " + prop;
    return res;
  }
}

/**
 * Mark/unmark a specific function with the noreturn property.
 *
 * The first parameter is the symbol name of the function. The second parameter
 * is "true" to enable the noreturn property, "false" to disable.
 */
export class OptionNoReturn extends ArchOption {
  constructor() {
    super();
    this.name = "noreturn";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    const infd = (glb as any).symboltab.getGlobalScope().queryFunction(p1);
    if (infd == null)
      throw new RecovError("Unknown function name: " + p1);
    let val: boolean;
    if (p2.length === 0)
      val = true;
    else
      val = (p2 === "true");
    (infd as any).getFuncProto().setNoReturn(val);
    const prop: string = val ? "true" : "false";
    const res: string = "No return property for function " + p1 + " = " + prop;
    return res;
  }
}

/**
 * Toggle whether a warning should be issued if a specific action/rule is applied.
 *
 * The first parameter gives the name of the Action or RuleAction. The second parameter
 * is "on" to turn on warnings, "off" to turn them off.
 */
export class OptionWarning extends ArchOption {
  constructor() {
    super();
    this.name = "warning";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    if (p1.length === 0)
      throw new ParseError("No action/rule specified");
    let val: boolean;
    if (p2.length === 0)
      val = true;
    else
      val = ArchOption.onOrOff(p2);
    const res2: boolean = (glb as any).allacts.getCurrent().setWarning(val, p1);
    if (!res2)
      throw new RecovError("Bad action/rule specifier: " + p1);
    const prop: string = val ? "on" : "off";
    return "Warnings for " + p1 + " turned " + prop;
  }
}

/**
 * Toggle whether null pointers should be printed as the string "NULL".
 */
export class OptionNullPrinting extends ArchOption {
  constructor() {
    super();
    this.name = "nullprinting";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    const val: boolean = ArchOption.onOrOff(p1);
    if ((glb as any).print.getName() !== "c-language")
      return "Only c-language accepts the null printing option";
    const lng = (glb as any).print;
    (lng as any).setNULLPrinting(val);
    const prop: string = val ? "on" : "off";
    return "Null printing turned " + prop;
  }
}

/**
 * Toggle whether in-place operators (+=, *=, &=, etc.) are emitted by the decompiler.
 */
export class OptionInPlaceOps extends ArchOption {
  constructor() {
    super();
    this.name = "inplaceops";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    const val: boolean = ArchOption.onOrOff(p1);
    if ((glb as any).print.getName() !== "c-language")
      return "Can only set inplace operators for C language";
    const lng = (glb as any).print;
    (lng as any).setInplaceOps(val);
    const prop: string = val ? "on" : "off";
    return "Inplace operators turned " + prop;
  }
}

/**
 * Toggle whether the calling convention is printed when emitting function prototypes.
 */
export class OptionConventionPrinting extends ArchOption {
  constructor() {
    super();
    this.name = "conventionprinting";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    const val: boolean = ArchOption.onOrOff(p1);
    if ((glb as any).print.getName() !== "c-language")
      return "Can only set convention printing for C language";
    const lng = (glb as any).print;
    (lng as any).setConvention(val);
    const prop: string = val ? "on" : "off";
    return "Convention printing turned " + prop;
  }
}

/**
 * Toggle whether cast syntax is emitted by the decompiler or stripped.
 */
export class OptionNoCastPrinting extends ArchOption {
  constructor() {
    super();
    this.name = "nocastprinting";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    const val: boolean = ArchOption.onOrOff(p1);
    const lng = (glb as any).print;
    if (lng == null)
      return "Can only set no cast printing for C language";
    (lng as any).setNoCastPrinting(val);
    const prop: string = val ? "on" : "off";
    return "No cast printing turned " + prop;
  }
}

/**
 * Toggle whether implied extensions (ZEXT or SEXT) are printed.
 */
export class OptionHideExtensions extends ArchOption {
  constructor() {
    super();
    this.name = "hideextensions";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    const val: boolean = ArchOption.onOrOff(p1);
    const lng = (glb as any).print;
    if (lng == null)
      return "Can only toggle extension hiding for C language";
    (lng as any).setHideImpliedExts(val);
    const prop: string = val ? "on" : "off";
    return "Implied extension hiding turned " + prop;
  }
}

/**
 * Set the maximum number of characters per decompiled line.
 *
 * The first parameter is an integer value passed to the pretty printer as the maximum
 * number of characters to emit in a single line before wrapping.
 */
export class OptionMaxLineWidth extends ArchOption {
  constructor() {
    super();
    this.name = "maxlinewidth";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    const val: int4 = parseIntAuto(p1);
    if (isNaN(val) || val === -1)
      throw new ParseError("Must specify integer linewidth");
    (glb as any).print.setMaxLineSize(val);
    return "Maximum line width set to " + p1;
  }
}

/**
 * Set the number of characters to indent per nested scope.
 *
 * The first parameter is the integer value specifying how many characters to indent.
 */
export class OptionIndentIncrement extends ArchOption {
  constructor() {
    super();
    this.name = "indentincrement";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    const val: int4 = parseIntAuto(p1);
    if (isNaN(val) || val === -1)
      throw new ParseError("Must specify integer increment");
    (glb as any).print.setIndentIncrement(val);
    return "Characters per indent level set to " + p1;
  }
}

/**
 * How many characters to indent comment lines.
 *
 * The first parameter gives the integer value. Comment lines are indented this much independent
 * of the associated code's nesting depth.
 */
export class OptionCommentIndent extends ArchOption {
  constructor() {
    super();
    this.name = "commentindent";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    const val: int4 = parseIntAuto(p1);
    if (isNaN(val) || val === -1)
      throw new ParseError("Must specify integer comment indent");
    (glb as any).print.setLineCommentIndent(val);
    return "Comment indent set to " + p1;
  }
}

/**
 * Set the style of comment emitted by the decompiler.
 *
 * The first parameter is either "c", "cplusplus", a string starting with "/*", or a string starting with "//"
 */
export class OptionCommentStyle extends ArchOption {
  constructor() {
    super();
    this.name = "commentstyle";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    (glb as any).print.setCommentStyle(p1);
    return "Comment style set to " + p1;
  }
}

/**
 * Toggle whether different comment types are emitted by the decompiler in the header for a function.
 *
 * The first parameter specifies the comment type: "header" and "warningheader"
 * The second parameter is the toggle value "on" or "off".
 */
export class OptionCommentHeader extends ArchOption {
  constructor() {
    super();
    this.name = "commentheader";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    const toggle: boolean = ArchOption.onOrOff(p2);
    let flags: uint4 = (glb as any).print.getHeaderComment();
    const val: uint4 = (glb as any).print.constructor.encodeCommentType
      ? (glb as any).print.constructor.encodeCommentType(p1)
      : Comment_encodeCommentType(p1);
    if (toggle)
      flags |= val;
    else
      flags &= ~val;
    (glb as any).print.setHeaderComment(flags);
    const prop: string = toggle ? "on" : "off";
    return "Header comment type " + p1 + " turned " + prop;
  }
}

/**
 * Toggle whether different comment types are emitted by the decompiler in the body of a function.
 *
 * The first parameter specifies the comment type: "warning", "user1", "user2", etc.
 * The second parameter is the toggle value "on" or "off".
 */
export class OptionCommentInstruction extends ArchOption {
  constructor() {
    super();
    this.name = "commentinstruction";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    const toggle: boolean = ArchOption.onOrOff(p2);
    let flags: uint4 = (glb as any).print.getInstructionComment();
    const val: uint4 = (glb as any).print.constructor.encodeCommentType
      ? (glb as any).print.constructor.encodeCommentType(p1)
      : Comment_encodeCommentType(p1);
    if (toggle)
      flags |= val;
    else
      flags &= ~val;
    (glb as any).print.setInstructionComment(flags);
    const prop: string = toggle ? "on" : "off";
    return "Instruction comment type " + p1 + " turned " + prop;
  }
}

/**
 * Fallback for Comment::encodeCommentType when the Comment class is not yet available.
 * Maps comment type name to flag bit.
 */
function Comment_encodeCommentType(name: string): uint4 {
  if (name === "user1") return 1;
  if (name === "user2") return 2;
  if (name === "user3") return 4;
  if (name === "header") return 0x10;
  if (name === "warning") return 0x20;
  if (name === "warningheader") return 0x40;
  throw new LowlevelError("Unknown comment type: " + name);
}

/**
 * Set the formatting strategy used by the decompiler to emit integers.
 *
 * The first parameter is the strategy name: "hex", "dec", or "best"
 */
export class OptionIntegerFormat extends ArchOption {
  constructor() {
    super();
    this.name = "integerformat";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    (glb as any).print.setIntegerFormat(p1);
    return "Integer format set to " + p1;
  }
}

/**
 * Set the brace formatting strategy for various types of code block.
 *
 * The first parameter is the type of code block: "function", "ifelse", "loop", "switch"
 * The second parameter is the strategy name: "same", "next", "skip"
 */
export class OptionBraceFormat extends ArchOption {
  constructor() {
    super();
    this.name = "braceformat";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    const lng = (glb as any).print;
    if (lng == null)
      return "Can only set brace formatting for C language";
    let style: number;
    if (p2 === "same")
      style = BraceStyle.same_line;
    else if (p2 === "next")
      style = BraceStyle.next_line;
    else if (p2 === "skip")
      style = BraceStyle.skip_line;
    else
      throw new ParseError("Unknown brace style: " + p2);
    if (p1 === "function")
      (lng as any).setBraceFormatFunction(style);
    else if (p1 === "ifelse")
      (lng as any).setBraceFormatIfElse(style);
    else if (p1 === "loop")
      (lng as any).setBraceFormatLoop(style);
    else if (p1 === "switch")
      (lng as any).setBraceFormatSwitch(style);
    else
      throw new ParseError("Unknown brace format category: " + p1);
    return "Brace formatting for " + p1 + " set to " + p2;
  }
}

/**
 * Establish a new root Action for the decompiler.
 *
 * The first parameter specifies the name of the root Action. If a second parameter
 * is given, it specifies the name of a new root Action, which is created by copying the
 * Action specified with the first parameter. In this case, the current root Action is
 * set to the new copy, which can then be modified.
 */
export class OptionSetAction extends ArchOption {
  constructor() {
    super();
    this.name = "setaction";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    if (p1.length === 0)
      throw new ParseError("Must specify preexisting action");

    if (p2.length !== 0) {
      (glb as any).allacts.cloneGroup(p1, p2);
      (glb as any).allacts.setCurrent(p2);
      return "Created " + p2 + " by cloning " + p1 + " and made it current";
    }
    (glb as any).allacts.setCurrent(p1);
    return "Set current action to " + p1;
  }
}

/**
 * Toggle a sub-group of actions within a root Action.
 *
 * If two parameters are given, the first indicates the name of the sub-group, and the second is
 * the toggle value, "on" or "off". The change is applied to the current root Action.
 *
 * If three parameters are given, the first indicates the root Action (which will be set as current)
 * to modify. The second and third parameters give the name of the sub-group and the toggle value.
 */
export class OptionCurrentAction extends ArchOption {
  constructor() {
    super();
    this.name = "currentaction";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    if (p1.length === 0 || p2.length === 0)
      throw new ParseError("Must specify subaction, on/off");
    let val: boolean;
    let res: string = "Toggled ";

    if (p3.length !== 0) {
      (glb as any).allacts.setCurrent(p1);
      val = ArchOption.onOrOff(p3);
      (glb as any).allacts.toggleAction(p1, p2, val);
      res += p2 + " in action " + p1;
    }
    else {
      val = ArchOption.onOrOff(p2);
      (glb as any).allacts.toggleAction((glb as any).allacts.getCurrentName(), p1, val);
      res += p1 + " in action " + (glb as any).allacts.getCurrentName();
    }

    return res;
  }
}

/**
 * Toggle whether the disassembly engine is allowed to modify context.
 *
 * If the first parameter is "on", disassembly can make changes to context.
 */
export class OptionAllowContextSet extends ArchOption {
  constructor() {
    super();
    this.name = "allowcontextset";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    const val: boolean = ArchOption.onOrOff(p1);

    const prop: string = val ? "on" : "off";
    const res: string = "Toggled allowcontextset to " + prop;
    (glb as any).translate.allowContextSet(val);

    return res;
  }
}

/**
 * Toggle whether unimplemented instructions are treated as a no-operation.
 *
 * If the first parameter is "on", unimplemented instructions are ignored, otherwise
 * they are treated as an artificial halt in the control flow.
 */
export class OptionIgnoreUnimplemented extends ArchOption {
  constructor() {
    super();
    this.name = "ignoreunimplemented";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    const val: boolean = ArchOption.onOrOff(p1);

    let res: string;
    if (val) {
      res = "Unimplemented instructions are now ignored (treated as nop)";
      (glb as any).flowoptions |= FlowInfoFlags.ignore_unimplemented;
    }
    else {
      res = "Unimplemented instructions now generate warnings";
      (glb as any).flowoptions &= ~(FlowInfoFlags.ignore_unimplemented as uint4);
    }

    return res;
  }
}

/**
 * Toggle whether unimplemented instructions are treated as a fatal error.
 *
 * If the first parameter is "on", decompilation of functions with unimplemented instructions
 * will terminate with a fatal error message. Otherwise, warning comments will be generated.
 */
export class OptionErrorUnimplemented extends ArchOption {
  constructor() {
    super();
    this.name = "errorunimplemented";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    const val: boolean = ArchOption.onOrOff(p1);

    let res: string;
    if (val) {
      res = "Unimplemented instructions are now a fatal error";
      (glb as any).flowoptions |= FlowInfoFlags.error_unimplemented;
    }
    else {
      res = "Unimplemented instructions now NOT a fatal error";
      (glb as any).flowoptions &= ~(FlowInfoFlags.error_unimplemented as uint4);
    }

    return res;
  }
}

/**
 * Toggle whether off-cut reinterpretation of an instruction is a fatal error.
 *
 * If the first parameter is "on", interpreting the same code bytes at two or more different
 * cuts, during disassembly, is considered a fatal error.
 */
export class OptionErrorReinterpreted extends ArchOption {
  constructor() {
    super();
    this.name = "errorreinterpreted";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    const val: boolean = ArchOption.onOrOff(p1);

    let res: string;
    if (val) {
      res = "Instruction reinterpretation is now a fatal error";
      (glb as any).flowoptions |= FlowInfoFlags.error_reinterpreted;
    }
    else {
      res = "Instruction reinterpretation is now NOT a fatal error";
      (glb as any).flowoptions &= ~(FlowInfoFlags.error_reinterpreted as uint4);
    }

    return res;
  }
}

/**
 * Toggle whether too many instructions in one function body is considered a fatal error.
 *
 * If the first parameter is "on" and the number of instructions in a single function body exceeds
 * the threshold, then decompilation will halt for that function with a fatal error. Otherwise,
 * artificial halts are generated to prevent control-flow into further instructions.
 */
export class OptionErrorTooManyInstructions extends ArchOption {
  constructor() {
    super();
    this.name = "errortoomanyinstructions";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    const val: boolean = ArchOption.onOrOff(p1);

    let res: string;
    if (val) {
      res = "Too many instructions are now a fatal error";
      (glb as any).flowoptions |= FlowInfoFlags.error_toomanyinstructions;
    }
    else {
      res = "Too many instructions are now NOT a fatal error";
      (glb as any).flowoptions &= ~(FlowInfoFlags.error_toomanyinstructions as uint4);
    }

    return res;
  }
}

/**
 * Set the prototype model to use when evaluating the parameters of the current function.
 *
 * The first parameter gives the name of the prototype model. The string "default" can be given
 * to refer to the format default model for the architecture. The specified model is used to
 * evaluate parameters of the function actively being decompiled, which may be distinct from the
 * model used to evaluate sub-functions.
 */
export class OptionProtoEval extends ArchOption {
  constructor() {
    super();
    this.name = "protoeval";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    let model: any = null;

    if (p1.length === 0)
      throw new ParseError("Must specify prototype model");

    if (p1 === "default")
      model = (glb as any).defaultfp;
    else {
      model = (glb as any).getModel(p1);
      if (model == null)
        throw new ParseError("Unknown prototype model: " + p1);
    }
    const res: string = "Set current evaluation to " + p1;
    (glb as any).evalfp_current = model;
    return res;
  }
}

/**
 * Set the current language emitted by the decompiler.
 *
 * The first parameter specifies the name of the language to emit: "c-language", "java-language", etc.
 */
export class OptionSetLanguage extends ArchOption {
  constructor() {
    super();
    this.name = "setlanguage";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    (glb as any).setPrintLanguage(p1);
    const res: string = "Decompiler produces " + p1;
    return res;
  }
}

/**
 * Set the maximum number of entries that can be recovered for a single jump table.
 *
 * This option is an unsigned integer value used during analysis of jump tables. It serves as a
 * sanity check that the recovered number of entries for a jump table is reasonable and
 * also acts as a resource limit on the number of destination addresses that analysis will attempt
 * to follow from a single indirect jump.
 */
export class OptionJumpTableMax extends ArchOption {
  constructor() {
    super();
    this.name = "jumptablemax";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    const val: uint4 = parseIntAuto(p1);
    if (isNaN(val) || val === 0)
      throw new ParseError("Must specify integer maximum");
    (glb as any).max_jumptable_size = val;
    return "Maximum jumptable size set to " + p1;
  }
}

/**
 * Toggle whether the decompiler should try to recover the table used to evaluate a switch.
 *
 * If the first parameter is "on", the decompiler will record the memory locations with constant values
 * that were accessed as part of the jump-table so that they can be formally labeled.
 */
export class OptionJumpLoad extends ArchOption {
  constructor() {
    super();
    this.name = "jumpload";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    const val: boolean = ArchOption.onOrOff(p1);

    let res: string;
    if (val) {
      res = "Jumptable analysis will record loads required to calculate jump address";
      (glb as any).flowoptions |= FlowInfoFlags.record_jumploads;
    }
    else {
      res = "Jumptable analysis will NOT record loads";
      (glb as any).flowoptions &= ~(FlowInfoFlags.record_jumploads as uint4);
    }
    return res;
  }
}

/**
 * Toggle whether a specific Rule is applied in the current Action.
 *
 * The first parameter must be a name path describing the unique Rule instance
 * to be toggled. The second parameter is "on" to enable the Rule, "off" to disable.
 */
export class OptionToggleRule extends ArchOption {
  constructor() {
    super();
    this.name = "togglerule";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    if (p1.length === 0)
      throw new ParseError("Must specify rule path");
    if (p2.length === 0)
      throw new ParseError("Must specify on/off");
    const val: boolean = ArchOption.onOrOff(p2);

    const root = (glb as any).allacts.getCurrent();
    if (root == null)
      throw new LowlevelError("Missing current action");
    let res: string;
    if (!val) {
      if ((root as any).disableRule(p1))
        res = "Successfully disabled";
      else
        res = "Failed to disable";
      res += " rule";
    }
    else {
      if ((root as any).enableRule(p1))
        res = "Successfully enabled";
      else
        res = "Failed to enable";
      res += " rule";
    }
    return res;
  }
}

/**
 * Set how locked data-types on the stack affect alias heuristics.
 *
 * Stack analysis uses the following simple heuristic: a pointer is unlikely to reference (alias)
 * a stack location if there is a locked data-type between the pointer base and the location.
 * This option determines what kind of locked data-types block aliases in this way.
 *   - none - no data-types will block an alias
 *   - struct - only structure data-types will block an alias
 *   - array - array data-types (and structure data-types) will block an alias
 *   - all - all locked data-types will block an alias
 */
export class OptionAliasBlock extends ArchOption {
  constructor() {
    super();
    this.name = "aliasblock";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    if (p1.length === 0)
      throw new ParseError("Must specify alias block level");
    const oldVal: int4 = (glb as any).alias_block_level;
    if (p1 === "none")
      (glb as any).alias_block_level = 0;
    else if (p1 === "struct")
      (glb as any).alias_block_level = 1;
    else if (p1 === "array")
      (glb as any).alias_block_level = 2;  // The default. Let structs and arrays block aliases
    else if (p1 === "all")
      (glb as any).alias_block_level = 3;
    else
      throw new ParseError("Unknown alias block level: " + p1);
    if (oldVal === (glb as any).alias_block_level)
      return "Alias block level unchanged";
    return "Alias block level set to " + p1;
  }
}

/**
 * Maximum number of instructions that can be processed in a single function.
 *
 * The first parameter is an integer specifying the maximum.
 */
export class OptionMaxInstruction extends ArchOption {
  constructor() {
    super();
    this.name = "maxinstruction";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    if (p1.length === 0)
      throw new ParseError("Must specify number of instructions");

    const newMax: int4 = parseIntAuto(p1);
    if (isNaN(newMax) || newMax < 0)
      throw new ParseError("Bad maxinstruction parameter");
    (glb as any).max_instructions = newMax;
    return "Maximum instructions per function set";
  }
}

/**
 * How should namespace tokens be displayed.
 *
 * The first parameter gives the strategy identifier, mapping to PrintLanguage::namespace_strategy.
 */
export class OptionNamespaceStrategy extends ArchOption {
  constructor() {
    super();
    this.name = "namespacestrategy";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    let strategy: number;
    if (p1 === "minimal")
      strategy = NamespaceStrategy.MINIMAL_NAMESPACES;
    else if (p1 === "all")
      strategy = NamespaceStrategy.ALL_NAMESPACES;
    else if (p1 === "none")
      strategy = NamespaceStrategy.NO_NAMESPACES;
    else
      throw new ParseError("Must specify a valid strategy");
    (glb as any).print.setNamespaceStrategy(strategy);
    return "Namespace strategy set";
  }
}

/**
 * Control which data-type assignments are split into multiple COPY/LOAD/STORE operations.
 *
 * Any combination of the three options can be given:
 *   - "struct"  = Divide structure data-types into separate field assignments
 *   - "array"   = Divide array data-types into separate element assignments
 *   - "pointer" = Divide assignments, via LOAD/STORE, through pointers
 */
export class OptionSplitDatatypes extends ArchOption {
  static readonly option_struct  = 1;   // Split combined structure fields
  static readonly option_array   = 2;   // Split combined array elements
  static readonly option_pointer = 4;   // Split combined LOAD and STORE operations

  /**
   * Translate option string to a configuration bit.
   * @param val - the option string
   * @returns the corresponding configuration bit
   */
  static getOptionBit(val: string): uint4 {
    if (val.length === 0) return 0;
    if (val === "struct") return OptionSplitDatatypes.option_struct;
    if (val === "array") return OptionSplitDatatypes.option_array;
    if (val === "pointer") return OptionSplitDatatypes.option_pointer;
    throw new LowlevelError("Unknown data-type split option: " + val);
  }

  constructor() {
    super();
    this.name = "splitdatatype";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    const oldConfig: uint4 = (glb as any).split_datatype_config;
    (glb as any).split_datatype_config = OptionSplitDatatypes.getOptionBit(p1);
    (glb as any).split_datatype_config |= OptionSplitDatatypes.getOptionBit(p2);
    (glb as any).split_datatype_config |= OptionSplitDatatypes.getOptionBit(p3);

    if (((glb as any).split_datatype_config & (OptionSplitDatatypes.option_struct | OptionSplitDatatypes.option_array)) === 0) {
      (glb as any).allacts.toggleAction((glb as any).allacts.getCurrentName(), "splitcopy", false);
      (glb as any).allacts.toggleAction((glb as any).allacts.getCurrentName(), "splitpointer", false);
    }
    else {
      const pointers: boolean = ((glb as any).split_datatype_config & OptionSplitDatatypes.option_pointer) !== 0;
      (glb as any).allacts.toggleAction((glb as any).allacts.getCurrentName(), "splitcopy", true);
      (glb as any).allacts.toggleAction((glb as any).allacts.getCurrentName(), "splitpointer", pointers);
    }

    if (oldConfig === (glb as any).split_datatype_config)
      return "Split data-type configuration unchanged";
    return "Split data-type configuration set";
  }
}

/**
 * Which Not a Number (NaN) operations should be ignored.
 *
 * The option controls which p-code NaN operations are replaced with a false constant, assuming
 * the input is a valid floating-point value.
 *   - "none"    = No operations are replaced
 *   - "compare" = Replace NaN operations associated with floating-point comparisons
 *   - "all"     = Replace all NaN operations
 */
export class OptionNanIgnore extends ArchOption {
  constructor() {
    super();
    this.name = "nanignore";
  }

  apply(glb: Architecture, p1: string, p2: string, p3: string): string {
    const oldIgnoreAll: boolean = (glb as any).nan_ignore_all;
    const oldIgnoreCompare: boolean = (glb as any).nan_ignore_compare;

    if (p1 === "none") {           // Don't ignore any NaN operation
      (glb as any).nan_ignore_all = false;
      (glb as any).nan_ignore_compare = false;
    }
    else if (p1 === "compare") {   // Ignore only NaN operations protecting floating-point comparisons
      (glb as any).nan_ignore_all = false;
      (glb as any).nan_ignore_compare = true;
    }
    else if (p1 === "all") {       // Ignore all NaN operations
      (glb as any).nan_ignore_all = true;
      (glb as any).nan_ignore_compare = true;
    }
    else {
      throw new LowlevelError("Unknown nanignore option: " + p1);
    }
    const root = (glb as any).allacts.getCurrent();
    if (!(glb as any).nan_ignore_all && !(glb as any).nan_ignore_compare) {
      (root as any).disableRule("ignorenan");
    }
    else {
      (root as any).enableRule("ignorenan");
    }
    if (oldIgnoreAll === (glb as any).nan_ignore_all && oldIgnoreCompare === (glb as any).nan_ignore_compare)
      return "NaN ignore configuration unchanged";
    return "Nan ignore configuration set to: " + p1;
  }
}
