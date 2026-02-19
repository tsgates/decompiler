/**
 * @file printc.ts
 * @description Classes to support the C-language back-end of the decompiler.
 *
 * Faithful translation of Ghidra's printc.hh / printc.cc.
 */

import type { int4, uint4, uintb } from '../core/types.js';
import { LowlevelError } from '../core/error.js';
import { FloatClass } from '../core/float.js';
import { Address, calc_mask, sign_extend } from '../core/address.js';
import { OpCode } from '../core/opcodes.js';
import { spacetype } from '../core/space.js';
import { CastStrategyC } from './cast.js';
import { CommentSorter } from './comment.js';
import {
  Emit,
  EmitMarkup,
  brace_style,
  PendPrint,
  syntax_highlight,
  type Writer,
} from './prettyprint.js';
import {
  PrintLanguage,
  PrintLanguageCapability,
  OpToken,
  tokentype,
  ReversePolish,
  Atom,
  tagtype,
  modifiers,
  namespace_strategy,
} from './printlanguage.js';
import { type_metatype } from './type.js';

// =========================================================================
// Forward type declarations for types not yet translated
// =========================================================================

type Architecture = any;
type Datatype = any;
type TypePointer = any;
type TypeArray = any;
type TypeCode = any;
type TypeBase = any;
type TypeEnum = any;
type TypeStruct = any;
type TypeUnion = any;
type TypePointerRel = any;
type TypeSpacebase = any;
type TypeField = any;
type Varnode = any;
type PcodeOp = any;
type Funcdata = any;
type FuncProto = any;
type FuncCallSpecs = any;
type ProtoParameter = any;
type Symbol = any;
type EquateSymbol = any;
type Scope = any;
type HighVariable = any;
type SymbolEntry = any;
type FlowBlock = any;
type BlockBasic = any;
type BlockGraph = any;
type BlockList = any;
type BlockCopy = any;
type BlockGoto = any;
type BlockIf = any;
type BlockCondition = any;
type BlockWhileDo = any;
type BlockDoWhile = any;
type BlockInfLoop = any;
type BlockSwitch = any;
type TypeFactory = any;
type UserPcodeOp = any;
type CPoolRecord = any;
type FloatFormat = any;
type ResolvedUnion = any;
type AddrSpace = any;
type JumpTable = any;
type Comment = any;
type TypeOpFloatInt2Float = any;

// =========================================================================
// PartialSymbolEntry -- helper for unraveling nested field references
// =========================================================================

/**
 * A structure for pushing nested fields to the RPN stack.
 *
 * Links the data-type, field name, field object, and token together.
 */
export interface PartialSymbolEntry {
  token: OpToken;
  field: TypeField | null;
  parent: Datatype;
  offset: bigint;
  size: number;
  hilite: number; // EmitMarkup.syntax_highlight
}

// =========================================================================
// PrintCCapability -- factory/singleton
// =========================================================================

/**
 * Factory and static initializer for the "c-language" back-end to the decompiler.
 *
 * The singleton adds itself to the list of possible back-end languages for the decompiler
 * and it acts as a factory for producing the PrintC object for emitting C-language tokens.
 */
export class PrintCCapability extends PrintLanguageCapability {
  private static printCCapability: PrintCCapability = new PrintCCapability();

  private constructor() {
    super();
    this.name = "c-language";
    this.isdefault = true;
  }

  buildLanguage(glb: Architecture): PrintLanguage {
    return new PrintC(glb, this.name);
  }

  /** Register the singleton so it becomes discoverable. */
  static register(): void {
    PrintCCapability.printCCapability.initialize();
  }
}

// =========================================================================
// PendingBrace -- pending print commands for opening brace
// =========================================================================

/**
 * Set of print commands for displaying an open brace '{' and setting a new indent level.
 *
 * These are the print commands sent to the emitter prior to printing an else block.
 * The open brace can be canceled if the block decides it wants to use "else if" syntax.
 */
export class PendingBrace extends PendPrint {
  private indentId: number;
  private style: brace_style;

  constructor(s: brace_style) {
    super();
    this.indentId = -1;
    this.style = s;
  }

  getIndentId(): number { return this.indentId; }

  callback(emit: Emit): void {
    this.indentId = (emit as any).openBraceIndent("{", this.style);
  }
}

// =========================================================================
// Helper: isValueFlexible (file-scoped utility from printc.cc)
// =========================================================================

function isValueFlexible(vn: Varnode): boolean {
  if (vn.isImplied() && vn.isWritten()) {
    const def = vn.getDef();
    let opc: number = def.code();
    if (opc === OpCode.CPUI_COPY) {
      const invn = def.getIn(0);
      if (!invn.isImplied() || !invn.isWritten())
        return false;
      opc = invn.getDef().code();
    }
    if (opc === OpCode.CPUI_PTRSUB) return true;
    if (opc === OpCode.CPUI_PTRADD) return true;
  }
  return false;
}

// =========================================================================
// PrintC -- the C-language token emitter
// =========================================================================

/**
 * The C-language specific rules for emitting expressions, statements,
 * function prototypes, variable declarations, if/else structures,
 * loop structures, etc.
 */
export class PrintC extends PrintLanguage {

  // -----------------------------------------------------------------------
  // Static OpToken instances
  // -----------------------------------------------------------------------

  //                                      print1  print2  stage prec  assoc   type                         space bump negate
  protected static hidden            = new OpToken("",    "",   1,    70,  false, tokentype.hiddenfunction,  0,    0,   null);
  protected static scope             = new OpToken("::",  "",   2,    70,  true,  tokentype.binary,          0,    0,   null);
  protected static object_member     = new OpToken(".",   "",   2,    66,  true,  tokentype.binary,          0,    0,   null);
  protected static pointer_member    = new OpToken("->",  "",   2,    66,  true,  tokentype.binary,          0,    0,   null);
  protected static subscript         = new OpToken("[",   "]",  2,    66,  false, tokentype.postsurround,    0,    0,   null);
  protected static function_call     = new OpToken("(",   ")",  2,    66,  false, tokentype.postsurround,    0,    10,  null);
  protected static bitwise_not       = new OpToken("~",   "",   1,    62,  false, tokentype.unary_prefix,    0,    0,   null);
  protected static boolean_not       = new OpToken("!",   "",   1,    62,  false, tokentype.unary_prefix,    0,    0,   null);
  protected static unary_minus       = new OpToken("-",   "",   1,    62,  false, tokentype.unary_prefix,    0,    0,   null);
  protected static unary_plus        = new OpToken("+",   "",   1,    62,  false, tokentype.unary_prefix,    0,    0,   null);
  protected static addressof         = new OpToken("&",   "",   1,    62,  false, tokentype.unary_prefix,    0,    0,   null);
  protected static dereference       = new OpToken("*",   "",   1,    62,  false, tokentype.unary_prefix,    0,    0,   null);
  protected static typecast          = new OpToken("(",   ")",  2,    62,  false, tokentype.presurround,     0,    0,   null);
  protected static multiply          = new OpToken("*",   "",   2,    54,  true,  tokentype.binary,          1,    0,   null);
  protected static divide            = new OpToken("/",   "",   2,    54,  false, tokentype.binary,          1,    0,   null);
  protected static modulo            = new OpToken("%",   "",   2,    54,  false, tokentype.binary,          1,    0,   null);
  protected static binary_plus       = new OpToken("+",   "",   2,    50,  true,  tokentype.binary,          1,    0,   null);
  protected static binary_minus      = new OpToken("-",   "",   2,    50,  false, tokentype.binary,          1,    0,   null);
  protected static shift_left        = new OpToken("<<",  "",   2,    46,  false, tokentype.binary,          1,    0,   null);
  protected static shift_right       = new OpToken(">>",  "",   2,    46,  false, tokentype.binary,          1,    0,   null);
  protected static shift_sright      = new OpToken(">>",  "",   2,    46,  false, tokentype.binary,          1,    0,   null);
  protected static less_than         = new OpToken("<",   "",   2,    42,  false, tokentype.binary,          1,    0,   null);
  protected static less_equal        = new OpToken("<=",  "",   2,    42,  false, tokentype.binary,          1,    0,   null);
  protected static greater_than      = new OpToken(">",   "",   2,    42,  false, tokentype.binary,          1,    0,   null);
  protected static greater_equal     = new OpToken(">=",  "",   2,    42,  false, tokentype.binary,          1,    0,   null);
  protected static equal             = new OpToken("==",  "",   2,    38,  false, tokentype.binary,          1,    0,   null);
  protected static not_equal         = new OpToken("!=",  "",   2,    38,  false, tokentype.binary,          1,    0,   null);
  protected static bitwise_and       = new OpToken("&",   "",   2,    34,  true,  tokentype.binary,          1,    0,   null);
  protected static bitwise_xor       = new OpToken("^",   "",   2,    30,  true,  tokentype.binary,          1,    0,   null);
  protected static bitwise_or        = new OpToken("|",   "",   2,    26,  true,  tokentype.binary,          1,    0,   null);
  protected static boolean_and       = new OpToken("&&",  "",   2,    22,  false, tokentype.binary,          1,    0,   null);
  protected static boolean_xor       = new OpToken("^^",  "",   2,    20,  false, tokentype.binary,          1,    0,   null);
  protected static boolean_or        = new OpToken("||",  "",   2,    18,  false, tokentype.binary,          1,    0,   null);
  protected static assignment        = new OpToken("=",   "",   2,    14,  false, tokentype.binary,          1,    5,   null);
  protected static comma             = new OpToken(",",   "",   2,    2,   true,  tokentype.binary,          0,    0,   null);
  protected static new_op            = new OpToken("",    "",   2,    62,  false, tokentype.space,           1,    0,   null);

  // In-place assignment operators
  protected static multequal         = new OpToken("*=",  "",   2,    14,  false, tokentype.binary,          1,    5,   null);
  protected static divequal          = new OpToken("/=",  "",   2,    14,  false, tokentype.binary,          1,    5,   null);
  protected static remequal          = new OpToken("%=",  "",   2,    14,  false, tokentype.binary,          1,    5,   null);
  protected static plusequal         = new OpToken("+=",  "",   2,    14,  false, tokentype.binary,          1,    5,   null);
  protected static minusequal        = new OpToken("-=",  "",   2,    14,  false, tokentype.binary,          1,    5,   null);
  protected static leftequal         = new OpToken("<<=", "",   2,    14,  false, tokentype.binary,          1,    5,   null);
  protected static rightequal        = new OpToken(">>=", "",   2,    14,  false, tokentype.binary,          1,    5,   null);
  protected static andequal          = new OpToken("&=",  "",   2,    14,  false, tokentype.binary,          1,    5,   null);
  protected static orequal           = new OpToken("|=",  "",   2,    14,  false, tokentype.binary,          1,    5,   null);
  protected static xorequal          = new OpToken("^=",  "",   2,    14,  false, tokentype.binary,          1,    5,   null);

  // Type expression operators
  protected static type_expr_space   = new OpToken("",    "",   2,    10,  false, tokentype.space,           1,    0,   null);
  protected static type_expr_nospace = new OpToken("",    "",   2,    10,  false, tokentype.space,           0,    0,   null);
  protected static ptr_expr          = new OpToken("*",   "",   1,    62,  false, tokentype.unary_prefix,    0,    0,   null);
  protected static array_expr        = new OpToken("[",   "]",  2,    66,  false, tokentype.postsurround,    1,    0,   null);
  protected static enum_cat          = new OpToken("|",   "",   2,    26,  true,  tokentype.binary,          0,    0,   null);

  // -----------------------------------------------------------------------
  // Static string constants
  // -----------------------------------------------------------------------

  static readonly EMPTY_STRING        = "";
  static readonly OPEN_CURLY          = "{";
  static readonly CLOSE_CURLY         = "}";
  static readonly SEMICOLON           = ";";
  static readonly COLON               = ":";
  static readonly EQUALSIGN           = "=";
  static readonly COMMA               = ",";
  static readonly DOTDOTDOT           = "...";
  static readonly KEYWORD_VOID        = "void";
  static readonly KEYWORD_TRUE        = "true";
  static readonly KEYWORD_FALSE       = "false";
  static readonly KEYWORD_IF          = "if";
  static readonly KEYWORD_ELSE        = "else";
  static readonly KEYWORD_DO          = "do";
  static readonly KEYWORD_WHILE       = "while";
  static readonly KEYWORD_FOR         = "for";
  static readonly KEYWORD_GOTO        = "goto";
  static readonly KEYWORD_BREAK       = "break";
  static readonly KEYWORD_CONTINUE    = "continue";
  static readonly KEYWORD_CASE        = "case";
  static readonly KEYWORD_SWITCH      = "switch";
  static readonly KEYWORD_DEFAULT     = "default";
  static readonly KEYWORD_RETURN      = "return";
  static readonly KEYWORD_NEW         = "new";
  static readonly typePointerRelToken = "ADJ";

  // -----------------------------------------------------------------------
  // Protected option fields
  // -----------------------------------------------------------------------

  protected option_NULL: boolean = false;
  protected option_inplace_ops: boolean = false;
  protected option_convention: boolean = true;
  protected option_nocasts: boolean = false;
  protected option_unplaced: boolean = false;
  protected option_hide_exts: boolean = true;
  protected option_brace_func: brace_style = brace_style.skip_line;
  protected option_brace_ifelse: brace_style = brace_style.same_line;
  protected option_brace_loop: brace_style = brace_style.same_line;
  protected option_brace_switch: brace_style = brace_style.same_line;
  protected nullToken: string = "NULL";
  protected sizeSuffix: string = "L";

  // -----------------------------------------------------------------------
  // CommentSorter
  // -----------------------------------------------------------------------

  protected commsorter: CommentSorter = new CommentSorter();

  // -----------------------------------------------------------------------
  // Constructor
  // -----------------------------------------------------------------------

  constructor(g: Architecture, nm: string = "c-language") {
    super(g, nm);
    this.nullToken = "NULL";

    // Set the negate (flip) tokens
    PrintC.less_than.negate = PrintC.greater_equal;
    PrintC.less_equal.negate = PrintC.greater_than;
    PrintC.greater_than.negate = PrintC.less_equal;
    PrintC.greater_equal.negate = PrintC.less_than;
    PrintC.equal.negate = PrintC.not_equal;
    PrintC.not_equal.negate = PrintC.equal;

    this.castStrategy = new CastStrategyC();
    this.resetDefaultsPrintC();
  }

  // -----------------------------------------------------------------------
  // Protected helper: resetDefaultsPrintC
  // -----------------------------------------------------------------------

  protected resetDefaultsPrintC(): void {
    this.option_convention = true;
    this.option_hide_exts = true;
    this.option_inplace_ops = false;
    this.option_nocasts = false;
    this.option_NULL = false;
    this.option_unplaced = false;
    this.option_brace_func = brace_style.skip_line;
    this.option_brace_ifelse = brace_style.same_line;
    this.option_brace_loop = brace_style.same_line;
    this.option_brace_switch = brace_style.same_line;
    this.setCStyleComments();
  }

  // -----------------------------------------------------------------------
  // Public setters
  // -----------------------------------------------------------------------

  setNULLPrinting(val: boolean): void { this.option_NULL = val; }
  setInplaceOps(val: boolean): void { this.option_inplace_ops = val; }
  setConvention(val: boolean): void { this.option_convention = val; }
  setNoCastPrinting(val: boolean): void { this.option_nocasts = val; }
  setCStyleComments(): void { this.setCommentDelimeter("/* ", " */", false); }
  setCPlusPlusStyleComments(): void { this.setCommentDelimeter("// ", "", true); }
  setDisplayUnplaced(val: boolean): void { this.option_unplaced = val; }
  setHideImpliedExts(val: boolean): void { this.option_hide_exts = val; }
  setBraceFormatFunction(style: brace_style): void { this.option_brace_func = style; }
  setBraceFormatIfElse(style: brace_style): void { this.option_brace_ifelse = style; }
  setBraceFormatLoop(style: brace_style): void { this.option_brace_loop = style; }
  setBraceFormatSwitch(style: brace_style): void { this.option_brace_switch = style; }

  // -----------------------------------------------------------------------
  // buildTypeStack
  // -----------------------------------------------------------------------

  protected buildTypeStack(ct: Datatype, typestack: Datatype[]): void {
    for (;;) {
      typestack.push(ct);
      if (ct.getName().length !== 0)  // This can be a base type
        break;
      if (ct.getMetatype() === type_metatype.TYPE_PTR)
        ct = ct.getPtrTo();
      else if (ct.getMetatype() === type_metatype.TYPE_ARRAY)
        ct = ct.getBase();
      else if (ct.getMetatype() === type_metatype.TYPE_CODE) {
        const proto: FuncProto = ct.getPrototype();
        if (proto !== null && proto !== undefined)
          ct = proto.getOutputType();
        else
          ct = this.glb.types.getTypeVoid();
      } else
        break;  // Some other anonymous type
    }
  }

  // -----------------------------------------------------------------------
  // pushPrototypeInputs
  // -----------------------------------------------------------------------

  protected pushPrototypeInputs(proto: FuncProto): void {
    const sz: number = proto.numParams();

    if (sz === 0 && !proto.isDotdotdot()) {
      this.pushAtom(new Atom(PrintC.KEYWORD_VOID, tagtype.syntax, syntax_highlight.keyword_color));
    } else {
      for (let i = 0; i < sz - 1; ++i)
        this.pushOp(PrintC.comma, null as any);
      if (proto.isDotdotdot() && sz !== 0)
        this.pushOp(PrintC.comma, null as any);
      for (let i = 0; i < sz; ++i) {
        const param: ProtoParameter = proto.getParam(i);
        this.pushTypeStart(param.getType(), true);
        this.pushAtom(new Atom(PrintC.EMPTY_STRING, tagtype.blanktoken, syntax_highlight.no_color));
        this.pushTypeEnd(param.getType());
      }
      if (proto.isDotdotdot()) {
        if (sz !== 0)
          this.pushAtom(new Atom(PrintC.DOTDOTDOT, tagtype.syntax, syntax_highlight.no_color));
        else {
          this.pushAtom(new Atom(PrintC.EMPTY_STRING, tagtype.blanktoken, syntax_highlight.no_color));
        }
      }
    }
  }

  // -----------------------------------------------------------------------
  // pushSymbolScope
  // -----------------------------------------------------------------------

  protected pushSymbolScope(symbol: Symbol): void {
    let scopedepth: number;
    if (this.namespc_strategy === namespace_strategy.MINIMAL_NAMESPACES)
      scopedepth = symbol.getResolutionDepth(this.curscope);
    else if (this.namespc_strategy === namespace_strategy.ALL_NAMESPACES) {
      if (symbol.getScope() === this.curscope)
        scopedepth = 0;
      else
        scopedepth = symbol.getResolutionDepth(null);
    } else
      scopedepth = 0;

    if (scopedepth !== 0) {
      const scopeList: Scope[] = [];
      let point: Scope = symbol.getScope();
      for (let i = 0; i < scopedepth; ++i) {
        scopeList.push(point);
        point = point.getParent();
        this.pushOp(PrintC.scope, null as any);
      }
      for (let i = scopedepth - 1; i >= 0; --i) {
        this.pushAtom(new Atom(scopeList[i].getDisplayName(), tagtype.syntax,
          syntax_highlight.global_color, null as any, null as any));
      }
    }
  }

  // -----------------------------------------------------------------------
  // emitSymbolScope
  // -----------------------------------------------------------------------

  protected emitSymbolScope(symbol: Symbol): void {
    let scopedepth: number;
    if (this.namespc_strategy === namespace_strategy.MINIMAL_NAMESPACES)
      scopedepth = symbol.getResolutionDepth(this.curscope);
    else if (this.namespc_strategy === namespace_strategy.ALL_NAMESPACES) {
      if (symbol.getScope() === this.curscope)
        scopedepth = 0;
      else
        scopedepth = symbol.getResolutionDepth(null);
    } else
      scopedepth = 0;

    if (scopedepth !== 0) {
      const scopeList: Scope[] = [];
      let point: Scope = symbol.getScope();
      for (let i = 0; i < scopedepth; ++i) {
        scopeList.push(point);
        point = point.getParent();
      }
      for (let i = scopedepth - 1; i >= 0; --i) {
        this.emit.print(scopeList[i].getDisplayName(), syntax_highlight.global_color);
        this.emit.print(PrintC.scope.print1, syntax_highlight.no_color);
      }
    }
  }

  // -----------------------------------------------------------------------
  // pushTypeStart
  // -----------------------------------------------------------------------

  protected pushTypeStart(ct: Datatype, noident: boolean): void {
    const typestack: Datatype[] = [];
    this.buildTypeStack(ct, typestack);

    ct = typestack[typestack.length - 1];  // The base type
    let tok: OpToken;

    if (noident && typestack.length === 1)
      tok = PrintC.type_expr_nospace;
    else
      tok = PrintC.type_expr_space;

    if (ct.getName().length === 0) {
      const nm = this.genericTypeName(ct);
      this.pushOp(tok, null as any);
      this.pushAtom(new Atom(nm, tagtype.typetoken, syntax_highlight.type_color, ct));
    } else {
      this.pushOp(tok, null as any);
      this.pushAtom(new Atom(ct.getDisplayName(), tagtype.typetoken, syntax_highlight.type_color, ct));
    }
    for (let i = typestack.length - 2; i >= 0; --i) {
      ct = typestack[i];
      if (ct.getMetatype() === type_metatype.TYPE_PTR)
        this.pushOp(PrintC.ptr_expr, null as any);
      else if (ct.getMetatype() === type_metatype.TYPE_ARRAY)
        this.pushOp(PrintC.array_expr, null as any);
      else if (ct.getMetatype() === type_metatype.TYPE_CODE)
        this.pushOp(PrintC.function_call, null as any);
      else {
        this.clear();
        throw new LowlevelError("Bad type expression");
      }
    }
  }

  // -----------------------------------------------------------------------
  // pushTypeEnd
  // -----------------------------------------------------------------------

  protected pushTypeEnd(ct: Datatype): void {
    this.pushMod();
    this.setMod(modifiers.force_dec);

    for (;;) {
      if (ct.getName().length !== 0)
        break;
      if (ct.getMetatype() === type_metatype.TYPE_PTR)
        ct = ct.getPtrTo();
      else if (ct.getMetatype() === type_metatype.TYPE_ARRAY) {
        const ctarray = ct;
        ct = ctarray.getBase();
        this.push_integer(BigInt(ctarray.numElements()), 4, false, tagtype.syntax, null, null);
      } else if (ct.getMetatype() === type_metatype.TYPE_CODE) {
        const proto: FuncProto = ct.getPrototype();
        if (proto !== null && proto !== undefined) {
          this.pushPrototypeInputs(proto);
          ct = proto.getOutputType();
        } else
          this.pushAtom(new Atom(PrintC.EMPTY_STRING, tagtype.blanktoken, syntax_highlight.no_color));
      } else
        break;
    }

    this.popMod();
  }

  // -----------------------------------------------------------------------
  // checkArrayDeref
  // -----------------------------------------------------------------------

  protected checkArrayDeref(vn: Varnode): boolean {
    if (!vn.isImplied()) return false;
    if (!vn.isWritten()) return false;
    let op: PcodeOp = vn.getDef();
    if (op.code() === OpCode.CPUI_SEGMENTOP) {
      vn = op.getIn(2);
      if (!vn.isImplied()) return false;
      if (!vn.isWritten()) return false;
      op = vn.getDef();
    }
    if (op.code() !== OpCode.CPUI_PTRSUB && op.code() !== OpCode.CPUI_PTRADD) return false;
    return true;
  }

  // -----------------------------------------------------------------------
  // checkAddressOfCast
  // -----------------------------------------------------------------------

  protected checkAddressOfCast(op: PcodeOp): boolean {
    const dt0: Datatype = op.getOut().getHighTypeDefFacing();
    const vnin: Varnode = op.getIn(0);
    const dt1: Datatype = vnin.getHighTypeReadFacing(op);
    if (dt0.getMetatype() !== type_metatype.TYPE_PTR || dt1.getMetatype() !== type_metatype.TYPE_PTR)
      return false;
    let base0: Datatype = dt0.getPtrTo();
    let base1: Datatype = dt1.getPtrTo();
    if (base0.getMetatype() !== type_metatype.TYPE_ARRAY)
      return false;
    const arraySize: number = base0.getSize();
    base0 = base0.getBase();
    while (base0.getTypedef() !== null && base0.getTypedef() !== undefined)
      base0 = base0.getTypedef();
    while (base1.getTypedef() !== null && base1.getTypedef() !== undefined)
      base1 = base1.getTypedef();
    if (base0 !== base1)
      return false;
    let symbolType: Datatype = null;
    if (vnin.getSymbolEntry() !== null && vnin.getHigh().getSymbolOffset() === -1) {
      symbolType = vnin.getSymbolEntry().getSymbol().getType();
    } else if (vnin.isWritten()) {
      const ptrsub: PcodeOp = vnin.getDef();
      if (ptrsub.code() === OpCode.CPUI_PTRSUB) {
        let rootType: Datatype = ptrsub.getIn(0).getHighTypeReadFacing(ptrsub);
        if (rootType.getMetatype() === type_metatype.TYPE_PTR) {
          rootType = rootType.getPtrTo();
          const off: bigint = ptrsub.getIn(1).getOffset();
          const offOut = { value: 0n };
          symbolType = rootType.getSubType(off, offOut);
          if (offOut.value !== 0n)
            return false;
        }
      }
    }
    if (symbolType === null)
      return false;
    if (symbolType.getMetatype() !== type_metatype.TYPE_ARRAY || symbolType.getSize() !== arraySize)
      return false;
    return true;
  }

  // -----------------------------------------------------------------------
  // opFunc
  // -----------------------------------------------------------------------

  protected opFunc(op: PcodeOp): void {
    this.pushOp(PrintC.function_call, op);
    const nm: string = op.getOpcode().getOperatorName(op);
    this.pushAtom(new Atom(nm, tagtype.optoken, syntax_highlight.no_color, op));
    if (op.numInput() > 0) {
      for (let i = 0; i < op.numInput() - 1; ++i)
        this.pushOp(PrintC.comma, op);
      for (let i = op.numInput() - 1; i >= 0; --i)
        this.pushVn(op.getIn(i), op, this.mods);
    } else
      this.pushAtom(new Atom(PrintC.EMPTY_STRING, tagtype.blanktoken, syntax_highlight.no_color));
  }

  // -----------------------------------------------------------------------
  // opTypeCast
  // -----------------------------------------------------------------------

  protected opTypeCast(op: PcodeOp): void {
    const dt: Datatype = op.getOut().getHighTypeDefFacing();
    if (dt.isPointerToArray()) {
      if (this.checkAddressOfCast(op)) {
        this.pushOp(PrintC.addressof, op);
        this.pushVn(op.getIn(0), op, this.mods);
        return;
      }
    }
    if (!this.option_nocasts) {
      this.pushOp(PrintC.typecast, op);
      this.pushType(dt);
    }
    this.pushVn(op.getIn(0), op, this.mods);
  }

  // -----------------------------------------------------------------------
  // opHiddenFunc
  // -----------------------------------------------------------------------

  protected opHiddenFunc(op: PcodeOp): void {
    this.pushOp(PrintC.hidden, op);
    this.pushVn(op.getIn(0), op, this.mods);
  }

  // -----------------------------------------------------------------------
  // printCharHexEscape (static)
  // -----------------------------------------------------------------------

  protected static printCharHexEscape(s: Writer, val: number): void {
    if (val < 256) {
      s.write("\\x" + (val & 0xff).toString(16).padStart(2, '0'));
    } else if (val < 65536) {
      s.write("\\x" + (val & 0xffff).toString(16).padStart(4, '0'));
    } else {
      s.write("\\x" + (val & 0xffffffff).toString(16).padStart(8, '0'));
    }
  }

  // -----------------------------------------------------------------------
  // getHiddenThisSlot
  // -----------------------------------------------------------------------

  protected getHiddenThisSlot(op: PcodeOp, fc: FuncCallSpecs): number {
    // Simplified: in practice returns -1 for C (no hidden this)
    if (fc === null) return -1;
    if (!fc.hasThisPointer()) return -1;
    const numIn = op.numInput();
    if (numIn < 2) return -1;
    return fc.getThisPointerSlot(op);
  }

  // -----------------------------------------------------------------------
  // pushTypePointerRel (inline in header)
  // -----------------------------------------------------------------------

  protected pushTypePointerRel(op: PcodeOp): void {
    this.pushOp(PrintC.function_call, op);
    this.pushAtom(new Atom(PrintC.typePointerRelToken, tagtype.optoken, syntax_highlight.funcname_color, op));
  }

  // -----------------------------------------------------------------------
  // PcodeOp emission methods (from printc.cc lines 1-1425)
  // -----------------------------------------------------------------------

  opCopy(op: PcodeOp): void {
    this.pushVn(op.getIn(0), op, this.mods);
  }

  opLoad(op: PcodeOp): void {
    const usearray: boolean = this.checkArrayDeref(op.getIn(1));
    let m: number = this.mods;
    if (usearray && !this.isSet(modifiers.force_pointer))
      m |= modifiers.print_load_value;
    else {
      this.pushOp(PrintC.dereference, op);
    }
    this.pushVn(op.getIn(1), op, m);
  }

  opStore(op: PcodeOp): void {
    let m: number = this.mods;
    this.pushOp(PrintC.assignment, op);
    const usearray: boolean = this.checkArrayDeref(op.getIn(1));
    if (usearray && !this.isSet(modifiers.force_pointer))
      m |= modifiers.print_store_value;
    else {
      this.pushOp(PrintC.dereference, op);
    }
    // implied vn's pushed on in reverse order for efficiency
    this.pushVn(op.getIn(2), op, this.mods);
    this.pushVn(op.getIn(1), op, m);
  }

  opBranch(op: PcodeOp): void {
    if (this.isSet(modifiers.flat)) {
      this.emit.tagOp(PrintC.KEYWORD_GOTO, syntax_highlight.keyword_color, op);
      this.emit.spaces(1);
      this.pushVn(op.getIn(0), op, this.mods);
    }
  }

  opCbranch(op: PcodeOp): void {
    const yesif: boolean = this.isSet(modifiers.flat);
    const yesparen: boolean = !this.isSet(modifiers.comma_separate);
    let booleanflip: boolean = op.isBooleanFlip();
    let m: number = this.mods;

    if (yesif) {
      this.emit.tagOp(PrintC.KEYWORD_IF, syntax_highlight.keyword_color, op);
      this.emit.spaces(1);
      if (op.isFallthruTrue()) {
        booleanflip = !booleanflip;
        m |= modifiers.falsebranch;
      }
    }
    let id: number;
    if (yesparen)
      id = this.emit.openParen(PrintLanguage.OPEN_PAREN);
    else
      id = this.emit.openGroup();
    if (booleanflip) {
      if (this.checkPrintNegation(op.getIn(1))) {
        m |= modifiers.negatetoken;
        booleanflip = false;
      }
    }
    if (booleanflip)
      this.pushOp(PrintC.boolean_not, op);
    this.pushVn(op.getIn(1), op, m);
    this.recurse();
    if (yesparen)
      this.emit.closeParen(PrintLanguage.CLOSE_PAREN, id);
    else
      this.emit.closeGroup(id);

    if (yesif) {
      this.emit.spaces(1);
      this.emit.print(PrintC.KEYWORD_GOTO, syntax_highlight.keyword_color);
      this.emit.spaces(1);
      this.pushVn(op.getIn(0), op, this.mods);
    }
  }

  opBranchind(op: PcodeOp): void {
    this.emit.tagOp(PrintC.KEYWORD_SWITCH, syntax_highlight.keyword_color, op);
    const id: number = this.emit.openParen(PrintLanguage.OPEN_PAREN);
    this.pushVn(op.getIn(0), op, this.mods);
    this.recurse();
    this.emit.closeParen(PrintLanguage.CLOSE_PAREN, id);
  }

  opCall(op: PcodeOp): void {
    this.pushOp(PrintC.function_call, op);
    const callpoint: Varnode = op.getIn(0);
    let fc: FuncCallSpecs;
    if (callpoint.getSpace().getType() === spacetype.IPTR_FSPEC) {
      fc = (callpoint.getAddr() as any).getFspecFromConst
        ? (callpoint.getAddr() as any).getFspecFromConst()
        : (callpoint as any).getFspecFromConst
          ? (callpoint as any).getFspecFromConst()
          : (() => { // FuncCallSpecs.getFspecFromConst(callpoint.getAddr())
            // Use the global FuncCallSpecs approach
            return (op as any).getParent().getFuncdata().getCallSpecs(op);
          })();
      // Simplified: treat fc as available
      if (fc !== null && fc !== undefined) {
        if (fc.getName().length === 0) {
          const nm: string = this.genericFunctionName(fc.getEntryAddress());
          this.pushAtom(new Atom(nm, tagtype.functoken, syntax_highlight.funcname_color, op, null as any));
        } else {
          const fd: Funcdata = fc.getFuncdata();
          if (fd !== null && fd !== undefined)
            this.pushSymbolScope(fd.getSymbol());
          this.pushAtom(new Atom(fc.getName(), tagtype.functoken, syntax_highlight.funcname_color, op, null as any));
        }
      } else {
        this.clear();
        throw new LowlevelError("Missing function callspec");
      }
    } else {
      this.clear();
      throw new LowlevelError("Missing function callspec");
    }

    const skip: number = -1;
    let count: number = op.numInput() - 1;
    count -= (skip < 0) ? 0 : 1;
    if (count > 0) {
      for (let i = 0; i < count - 1; ++i)
        this.pushOp(PrintC.comma, op);
      for (let i = op.numInput() - 1; i >= 1; --i) {
        if (i === skip) continue;
        this.pushVn(op.getIn(i), op, this.mods);
      }
    } else
      this.pushAtom(new Atom(PrintC.EMPTY_STRING, tagtype.blanktoken, syntax_highlight.no_color));
  }

  opCallind(op: PcodeOp): void {
    this.pushOp(PrintC.function_call, op);
    this.pushOp(PrintC.dereference, op);
    const fd: Funcdata = op.getParent().getFuncdata();
    const fc: FuncCallSpecs = fd.getCallSpecs(op);
    if (fc === null || fc === undefined)
      throw new LowlevelError("Missing indirect function callspec");
    const skip: number = this.getHiddenThisSlot(op, fc);
    let count: number = op.numInput() - 1;
    count -= (skip < 0) ? 0 : 1;
    if (count > 1) {
      this.pushVn(op.getIn(0), op, this.mods);
      for (let i = 0; i < count - 1; ++i)
        this.pushOp(PrintC.comma, op);
      for (let i = op.numInput() - 1; i >= 1; --i) {
        if (i === skip) continue;
        this.pushVn(op.getIn(i), op, this.mods);
      }
    } else if (count === 1) {
      if (skip === 1)
        this.pushVn(op.getIn(2), op, this.mods);
      else
        this.pushVn(op.getIn(1), op, this.mods);
      this.pushVn(op.getIn(0), op, this.mods);
    } else {
      this.pushVn(op.getIn(0), op, this.mods);
      this.pushAtom(new Atom(PrintC.EMPTY_STRING, tagtype.blanktoken, syntax_highlight.no_color));
    }
  }

  opCallother(op: PcodeOp): void {
    const userop: UserPcodeOp | null = this.glb.userops.getOp(Number(op.getIn(0).getOffset()));
    if (userop === null) {
      // Fallback: emit using functional syntax with the opcode name
      const nm: string = op.getOpcode().getOperatorName(op);
      this.pushOp(PrintC.function_call, op);
      this.pushAtom(new Atom(nm, tagtype.optoken, syntax_highlight.funcname_color, op));
      if (op.numInput() > 1) {
        for (let i = 1; i < op.numInput() - 1; ++i)
          this.pushOp(PrintC.comma, op);
        for (let i = op.numInput() - 1; i >= 1; --i)
          this.pushVn(op.getIn(i), op, this.mods);
      } else
        this.pushAtom(new Atom(PrintC.EMPTY_STRING, tagtype.blanktoken, syntax_highlight.no_color));
      return;
    }
    const display: number = userop.getDisplay();
    if (display === 0) {
      // Emit using functional syntax
      const nm: string = op.getOpcode().getOperatorName(op);
      this.pushOp(PrintC.function_call, op);
      this.pushAtom(new Atom(nm, tagtype.optoken, syntax_highlight.funcname_color, op));
      if (op.numInput() > 1) {
        for (let i = 1; i < op.numInput() - 1; ++i)
          this.pushOp(PrintC.comma, op);
        for (let i = op.numInput() - 1; i >= 1; --i)
          this.pushVn(op.getIn(i), op, this.mods);
      } else
        this.pushAtom(new Atom(PrintC.EMPTY_STRING, tagtype.blanktoken, syntax_highlight.no_color));
    } else if (display === 1) {
      // annotation_assignment
      this.pushOp(PrintC.assignment, op);
      this.pushVn(op.getIn(2), op, this.mods);
      this.pushVn(op.getIn(1), op, this.mods);
    } else if (display === 2) {
      // no_operator
      this.pushVn(op.getIn(1), op, this.mods);
    } else if (display === 3) {
      // display_string
      const vn: Varnode = op.getOut();
      let ct: Datatype = vn.getType();
      let str: string;
      if (ct.getMetatype() === type_metatype.TYPE_PTR) {
        ct = ct.getPtrTo();
        // Simplified: try to print character constant
        str = '"badstring"';
      } else {
        str = '"badstring"';
      }
      this.pushAtom(new Atom(str, tagtype.vartoken, syntax_highlight.const_color, op, vn));
    }
  }

  opConstructor(op: PcodeOp, withNew: boolean): void {
    let dt: Datatype;
    if (withNew) {
      const newop: PcodeOp = op.getIn(1).getDef();
      const outvn: Varnode = newop.getOut();
      this.pushOp(PrintC.new_op, newop);
      this.pushAtom(new Atom(PrintC.KEYWORD_NEW, tagtype.optoken, syntax_highlight.keyword_color, newop, outvn));
      dt = outvn.getTypeDefFacing();
    } else {
      const thisvn: Varnode = op.getIn(1);
      dt = thisvn.getType();
    }
    if (dt.getMetatype() === type_metatype.TYPE_PTR) {
      dt = dt.getPtrTo();
    }
    const nm: string = dt.getDisplayName();
    this.pushOp(PrintC.function_call, op);
    this.pushAtom(new Atom(nm, tagtype.optoken, syntax_highlight.funcname_color, op));
    if (op.numInput() > 3) {
      for (let i = 2; i < op.numInput() - 1; ++i)
        this.pushOp(PrintC.comma, op);
      for (let i = op.numInput() - 1; i >= 2; --i)
        this.pushVn(op.getIn(i), op, this.mods);
    } else if (op.numInput() === 3) {
      this.pushVn(op.getIn(2), op, this.mods);
    } else {
      this.pushAtom(new Atom(PrintC.EMPTY_STRING, tagtype.blanktoken, syntax_highlight.no_color));
    }
  }

  opReturn(op: PcodeOp): void {
    let nm: string;
    const haltType: number = op.getHaltType();
    // The most common cases: default (0) is plain return
    if (haltType === 0) {
      this.emit.tagOp(PrintC.KEYWORD_RETURN, syntax_highlight.keyword_color, op);
      if (op.numInput() > 1) {
        this.emit.spaces(1);
        this.pushVn(op.getIn(1), op, this.mods);
      }
      return;
    }
    // PcodeOp::noreturn = 1, PcodeOp::halt = 4
    if (haltType === 1 || haltType === 4)
      nm = "halt";
    else if (haltType === 2)  // badinstruction
      nm = "halt_baddata";
    else if (haltType === 3)  // unimplemented
      nm = "halt_unimplemented";
    else if (haltType === 5)  // missing
      nm = "halt_missing";
    else
      nm = "halt";

    this.pushOp(PrintC.function_call, op);
    this.pushAtom(new Atom(nm, tagtype.optoken, syntax_highlight.funcname_color, op));
    this.pushAtom(new Atom(PrintC.EMPTY_STRING, tagtype.blanktoken, syntax_highlight.no_color));
  }

  opIntZext(op: PcodeOp, readOp: PcodeOp | null): void {
    if (this.castStrategy!.isZextCast(op.getOut().getHighTypeDefFacing(), op.getIn(0).getHighTypeReadFacing(op))) {
      if (this.option_hide_exts && this.castStrategy!.isExtensionCastImplied(op, readOp))
        this.opHiddenFunc(op);
      else
        this.opTypeCast(op);
    } else
      this.opFunc(op);
  }

  opIntSext(op: PcodeOp, readOp: PcodeOp | null): void {
    if (this.castStrategy!.isSextCast(op.getOut().getHighTypeDefFacing(), op.getIn(0).getHighTypeReadFacing(op))) {
      if (this.option_hide_exts && this.castStrategy!.isExtensionCastImplied(op, readOp))
        this.opHiddenFunc(op);
      else
        this.opTypeCast(op);
    } else
      this.opFunc(op);
  }

  opBoolNegate(op: PcodeOp): void {
    if (this.isSet(modifiers.negatetoken)) {
      this.unsetMod(modifiers.negatetoken);
      this.pushVn(op.getIn(0), op, this.mods);
    } else if (this.checkPrintNegation(op.getIn(0))) {
      this.pushVn(op.getIn(0), op, this.mods | modifiers.negatetoken);
    } else {
      this.pushOp(PrintC.boolean_not, op);
      this.pushVn(op.getIn(0), op, this.mods);
    }
  }

  opFloatInt2Float(op: PcodeOp): void {
    // TypeOpFloatInt2Float::absorbZext(op) -- simplified
    let vn0: Varnode = op.getIn(0);
    // Check for absorbed zext
    if (vn0.isWritten()) {
      const defOp = vn0.getDef();
      if (defOp.code() === OpCode.CPUI_INT_ZEXT) {
        // absorbZext logic: check if the zext can be absorbed
        // Simplified: just use the direct input
      }
    }
    const dt: Datatype = op.getOut().getHighTypeDefFacing();
    if (!this.option_nocasts) {
      this.pushOp(PrintC.typecast, op);
      this.pushType(dt);
    }
    this.pushVn(vn0, op, this.mods);
  }

  opSubpiece(op: PcodeOp): void {
    if (op.doesSpecialPrinting()) {
      const vn: Varnode = op.getIn(0);
      const ct: Datatype = vn.getHighTypeReadFacing(op);
      if (ct.isPieceStructured()) {
        let byteOff: bigint = BigInt(op.getIn(1).getOffset()) as any;
        // computeByteOffsetForComposite simplified
        const sym: Symbol = vn.getHigh().getSymbol();
        if (sym !== null && sym !== undefined && vn.isExplicit()) {
          const sz: number = op.getOut().getSize();
          let suboff: number = vn.getHigh().getSymbolOffset();
          if (suboff > 0)
            byteOff += BigInt(suboff);
          const slot: number = ct.needsResolution() ? 1 : 0;
          this.pushPartialSymbol(sym, Number(byteOff), sz, op.getOut(), op, slot, true);
          return;
        }
        const offResult = { value: 0n };
        const field: TypeField = ct.findTruncation(byteOff, op.getOut().getSize(), op, 1, offResult);
        if (field !== null && field !== undefined && offResult.value === 0n) {
          this.pushOp(PrintC.object_member, op);
          this.pushVn(vn, op, this.mods);
          this.pushAtom(new Atom(field.name, tagtype.fieldtoken, syntax_highlight.no_color, ct, field.ident ?? 0, op));
          return;
        }
        // Fall thru to functional printing
      }
    }
    if (this.castStrategy!.isSubpieceCast(
      op.getOut().getHighTypeDefFacing(),
      op.getIn(0).getHighTypeReadFacing(op),
      op.getIn(1).getOffset()))
      this.opTypeCast(op);
    else
      this.opFunc(op);
  }

  opPtradd(op: PcodeOp): void {
    const printval: boolean = this.isSet(modifiers.print_load_value | modifiers.print_store_value);
    const m: number = this.mods & ~(modifiers.print_load_value | modifiers.print_store_value);
    if (printval)
      this.pushOp(PrintC.subscript, op);
    else
      this.pushOp(PrintC.binary_plus, op);
    this.pushVn(op.getIn(1), op, m);
    this.pushVn(op.getIn(0), op, m);
  }

  opPtrsub(op: PcodeOp): void {
    let ptype: TypePointer;
    let ptrel: TypePointerRel;
    let ct: Datatype;
    const in0: Varnode = op.getIn(0);
    const in1const: bigint = op.getIn(1).getOffset();
    ptype = in0.getHighTypeReadFacing(op);
    if (ptype.getMetatype() !== type_metatype.TYPE_PTR) {
      this.clear();
      throw new LowlevelError("PTRSUB off of non-pointer type");
    }
    if (ptype.isFormalPointerRel && ptype.isFormalPointerRel() &&
      ptype.evaluateThruParent && ptype.evaluateThruParent(in1const)) {
      ptrel = ptype;
      ct = ptrel.getParent();
    } else {
      ptrel = null as any;
      ct = ptype.getPtrTo();
    }
    const m: number = this.mods & ~(modifiers.print_load_value | modifiers.print_store_value);
    const valueon_initial: boolean = (this.mods & (modifiers.print_load_value | modifiers.print_store_value)) !== 0;
    let valueon = valueon_initial;
    const flex: boolean = isValueFlexible(in0);

    if (ct.getMetatype() === type_metatype.TYPE_STRUCT || ct.getMetatype() === type_metatype.TYPE_UNION) {
      let suboff: bigint = in1const;
      if (ptrel !== null && ptrel !== undefined && ptrel.getAddressOffset) {
        suboff = suboff + BigInt(ptrel.getAddressOffset());
        suboff = suboff & calc_mask(ptype.getSize());
        if (suboff === 0n) {
          this.pushTypePointerRel(op);
          if (flex)
            this.pushVn(in0, op, m | modifiers.print_load_value);
          else
            this.pushVn(in0, op, m);
          return;
        }
      }
      // Convert to byte offset
      if (ptype.getWordSize && ptype.getWordSize() > 1)
        suboff = suboff * BigInt(ptype.getWordSize());

      let fieldname: string;
      let fieldtype: Datatype;
      let fieldid: number;

      if (ct.getMetatype() === type_metatype.TYPE_UNION) {
        if (suboff !== 0n)
          throw new LowlevelError("PTRSUB accesses union with non-zero offset");
        const fd: Funcdata = op.getParent().getFuncdata();
        const resUnion: ResolvedUnion = fd.getUnionField(ptype, op, -1);
        if (resUnion === null || resUnion === undefined || resUnion.getFieldNum() < 0)
          throw new LowlevelError("PTRSUB for union that does not resolve to a field");
        const fld: TypeField = ct.getField(resUnion.getFieldNum());
        fieldid = fld.ident ?? 0;
        fieldname = fld.name;
        fieldtype = fld.type;
      } else {
        // TYPE_STRUCT
        const newoffResult = { value: 0n };
        const fld: TypeField = ct.findTruncation(suboff, 0, op, 0, newoffResult);
        if (fld === null || fld === undefined) {
          if (ct.getSize() <= Number(suboff) || Number(suboff) < 0) {
            this.clear();
            throw new LowlevelError("PTRSUB out of bounds into struct");
          }
          fieldname = "field_0x" + Number(suboff).toString(16);
          fieldtype = null;
          fieldid = Number(suboff);
        } else {
          fieldname = fld.name;
          fieldtype = fld.type;
          fieldid = fld.ident ?? 0;
        }
      }

      let arrayvalue = false;
      if (fieldtype !== null && fieldtype !== undefined && fieldtype.getMetatype() === type_metatype.TYPE_ARRAY) {
        arrayvalue = valueon;
        valueon = true;
      }

      if (!valueon) {
        if (flex) {
          this.pushOp(PrintC.addressof, op);
          this.pushOp(PrintC.object_member, op);
          if (ptrel !== null && ptrel !== undefined && ptrel.getAddressOffset)
            this.pushTypePointerRel(op);
          this.pushVn(in0, op, m | modifiers.print_load_value);
          this.pushAtom(new Atom(fieldname, tagtype.fieldtoken, syntax_highlight.no_color, ct, fieldid, op));
        } else {
          this.pushOp(PrintC.addressof, op);
          this.pushOp(PrintC.pointer_member, op);
          if (ptrel !== null && ptrel !== undefined && ptrel.getAddressOffset)
            this.pushTypePointerRel(op);
          this.pushVn(in0, op, m);
          this.pushAtom(new Atom(fieldname, tagtype.fieldtoken, syntax_highlight.no_color, ct, fieldid, op));
        }
      } else {
        if (arrayvalue)
          this.pushOp(PrintC.subscript, op);
        if (flex) {
          this.pushOp(PrintC.object_member, op);
          if (ptrel !== null && ptrel !== undefined && ptrel.getAddressOffset)
            this.pushTypePointerRel(op);
          this.pushVn(in0, op, m | modifiers.print_load_value);
          this.pushAtom(new Atom(fieldname, tagtype.fieldtoken, syntax_highlight.no_color, ct, fieldid, op));
        } else {
          this.pushOp(PrintC.pointer_member, op);
          if (ptrel !== null && ptrel !== undefined && ptrel.getAddressOffset)
            this.pushTypePointerRel(op);
          this.pushVn(in0, op, m);
          this.pushAtom(new Atom(fieldname, tagtype.fieldtoken, syntax_highlight.no_color, ct, fieldid, op));
        }
        if (arrayvalue)
          this.push_integer(0n, 4, false, tagtype.syntax, null, op);
      }
    } else if (ct.getMetatype() === type_metatype.TYPE_SPACEBASE) {
      const high: HighVariable = op.getIn(1).getHigh();
      const symbol: Symbol = high.getSymbol();
      let arrayvalue = false;
      if (symbol !== null && symbol !== undefined) {
        ct = symbol.getType();
        if (ct.getMetatype() === type_metatype.TYPE_ARRAY) {
          arrayvalue = valueon;
          valueon = true;
        } else if (ct.getMetatype() === type_metatype.TYPE_CODE)
          valueon = true;
      }
      if (!valueon) {
        this.pushOp(PrintC.addressof, op);
      } else {
        if (arrayvalue)
          this.pushOp(PrintC.subscript, op);
      }
      if (symbol === null || symbol === undefined) {
        const sb = ct;
        const addr: Address = sb.getAddress(in1const, in0.getSize(), op.getAddr());
        this.pushUnnamedLocation(addr, null, op);
      } else {
        const off: number = high.getSymbolOffset();
        if (off === 0)
          this.pushSymbol(symbol, null, op);
        else {
          this.pushPartialSymbol(symbol, off, 0, null, op, -1, false);
        }
      }
      if (arrayvalue)
        this.push_integer(0n, 4, false, tagtype.syntax, null, op);
    } else if (ct.getMetatype() === type_metatype.TYPE_ARRAY) {
      if (in1const !== 0n) {
        this.clear();
        throw new LowlevelError("PTRSUB with non-zero offset into array type");
      }
      if (!valueon) {
        if (flex) {
          if (ptrel !== null && ptrel !== undefined && ptrel.getAddressOffset)
            this.pushTypePointerRel(op);
          this.pushVn(in0, op, m | modifiers.print_load_value);
        } else {
          this.pushOp(PrintC.dereference, op);
          if (ptrel !== null && ptrel !== undefined && ptrel.getAddressOffset)
            this.pushTypePointerRel(op);
          this.pushVn(in0, op, m);
        }
      } else {
        if (flex) {
          this.pushOp(PrintC.subscript, op);
          if (ptrel !== null && ptrel !== undefined && ptrel.getAddressOffset)
            this.pushTypePointerRel(op);
          this.pushVn(in0, op, m | modifiers.print_load_value);
          this.push_integer(0n, 4, false, tagtype.syntax, null, op);
        } else {
          this.pushOp(PrintC.subscript, op);
          this.pushOp(PrintC.dereference, op);
          if (ptrel !== null && ptrel !== undefined && ptrel.getAddressOffset)
            this.pushTypePointerRel(op);
          this.pushVn(in0, op, m);
          this.push_integer(0n, 4, false, tagtype.syntax, null, op);
        }
      }
    } else {
      this.clear();
      throw new LowlevelError("PTRSUB off of non structured pointer type");
    }
  }

  opSegmentOp(op: PcodeOp): void {
    this.pushVn(op.getIn(2), op, this.mods);
  }

  opCpoolRefOp(op: PcodeOp): void {
    const outvn: Varnode = op.getOut();
    const vn0: Varnode = op.getIn(0);
    const refs: bigint[] = [];
    for (let i = 1; i < op.numInput(); ++i)
      refs.push(op.getIn(i).getOffset());
    const rec: CPoolRecord = this.glb.cpool.getRecord(refs);
    if (rec === null || rec === undefined) {
      this.pushAtom(new Atom("UNKNOWNREF", tagtype.syntax, syntax_highlight.const_color, op, outvn));
    } else {
      const tag = rec.getTag();
      // CPoolRecord tag values: string_literal=0, class_reference=1, instance_of=2, primitive=3, pointer_method=4, pointer_field=5, array_length=6, check_cast=7
      if (tag === 0) {
        // string_literal
        let len: number = rec.getByteDataLength();
        if (len > 2048) len = 2048;
        let str = '"';
        // Simplified character escaping
        str += "...";
        str += '"';
        this.pushAtom(new Atom(str, tagtype.vartoken, syntax_highlight.const_color, op, outvn));
      } else if (tag === 1) {
        // class_reference
        this.pushAtom(new Atom(rec.getToken(), tagtype.vartoken, syntax_highlight.type_color, op, outvn));
      } else if (tag === 2) {
        // instance_of
        let dt: Datatype = rec.getType();
        while (dt.getMetatype() === type_metatype.TYPE_PTR)
          dt = dt.getPtrTo();
        this.pushOp(PrintC.function_call, op);
        this.pushAtom(new Atom(rec.getToken(), tagtype.functoken, syntax_highlight.funcname_color, op, outvn));
        this.pushOp(PrintC.comma, null as any);
        this.pushVn(vn0, op, this.mods);
        this.pushAtom(new Atom(dt.getDisplayName(), tagtype.syntax, syntax_highlight.type_color, op, outvn));
      } else {
        // primitive, pointer_method, pointer_field, array_length, check_cast, default
        let ct: Datatype = rec.getType();
        let color: number = syntax_highlight.var_color;
        if (ct.getMetatype() === type_metatype.TYPE_PTR) {
          ct = ct.getPtrTo();
          if (ct.getMetatype() === type_metatype.TYPE_CODE)
            color = syntax_highlight.funcname_color;
        }
        if (vn0.isConstant()) {
          this.pushAtom(new Atom(rec.getToken(), tagtype.vartoken, color, op, outvn));
        } else {
          this.pushOp(PrintC.pointer_member, op);
          this.pushVn(vn0, op, this.mods);
          this.pushAtom(new Atom(rec.getToken(), tagtype.syntax, color, op, outvn));
        }
      }
    }
  }

  opNewOp(op: PcodeOp): void {
    const outvn: Varnode = op.getOut();
    const vn0: Varnode = op.getIn(0);
    if (op.numInput() === 2) {
      const vn1: Varnode = op.getIn(1);
      if (!vn0.isConstant()) {
        // Array allocation form
        this.pushOp(PrintC.new_op, op);
        this.pushAtom(new Atom(PrintC.KEYWORD_NEW, tagtype.optoken, syntax_highlight.keyword_color, op, outvn));
        let nm: string;
        if (outvn === null || outvn === undefined) {
          nm = "<unused>";
        } else {
          let dt: Datatype = outvn.getTypeDefFacing();
          while (dt.getMetatype() === type_metatype.TYPE_PTR)
            dt = dt.getPtrTo();
          nm = dt.getDisplayName();
        }
        this.pushOp(PrintC.subscript, op);
        this.pushAtom(new Atom(nm, tagtype.optoken, syntax_highlight.type_color, op));
        this.pushVn(vn1, op, this.mods);
        return;
      }
    }
    this.pushOp(PrintC.function_call, op);
    this.pushAtom(new Atom(PrintC.KEYWORD_NEW, tagtype.optoken, syntax_highlight.keyword_color, op, outvn));
    this.pushVn(vn0, op, this.mods);
  }

  opInsertOp(op: PcodeOp): void {
    this.opFunc(op);
  }

  opExtractOp(op: PcodeOp): void {
    this.opFunc(op);
  }

  // -----------------------------------------------------------------------
  // push_integer
  // -----------------------------------------------------------------------

  protected push_integer(val: uintb, sz: number, sign: boolean, tag: tagtype,
    vn: Varnode | null, op: PcodeOp | null): void {
    let print_negsign: boolean;
    let force_unsigned_token = false;
    let force_sized_token = false;
    let displayFormat: number = 0;

    if (vn !== null && vn !== undefined && !vn.isAnnotation()) {
      const high: HighVariable = vn.getHigh();
      const sym: Symbol = high.getSymbol();
      if (sym !== null && sym !== undefined) {
        if (sym.isNameLocked() && sym.getCategory() === 1) {
          // Symbol::equate = 1
          if (this.pushEquate(val, sz, sym, vn, op))
            return;
        }
        displayFormat = sym.getDisplayFormat();
      }
      force_unsigned_token = vn.isUnsignedPrint();
      force_sized_token = vn.isLongPrint();
      if (displayFormat === 0)
        displayFormat = high.getType().getDisplayFormat();
    }

    // Symbol::force_char = 5
    if (sign && displayFormat !== 5) {
      const mask: bigint = calc_mask(sz);
      const flip: bigint = val ^ mask;
      print_negsign = flip < val;
      if (print_negsign)
        val = flip + 1n;
      force_unsigned_token = false;
    } else {
      print_negsign = false;
    }

    // Determine display format
    // Symbol::force_hex=1, force_dec=2, force_oct=3, force_char=5, force_bin=4
    if (displayFormat !== 0) {
      // Format is forced by the Symbol
    } else if ((this.mods & modifiers.force_hex) !== 0) {
      displayFormat = 1; // force_hex
    } else if (val <= 10n || (this.mods & modifiers.force_dec) !== 0) {
      displayFormat = 2; // force_dec
    } else {
      displayFormat = (PrintLanguage.mostNaturalBase(val) === 16) ? 1 : 2;
    }

    let t = "";
    if (print_negsign)
      t += '-';
    if (displayFormat === 1) {
      // force_hex
      t += "0x" + val.toString(16);
    } else if (displayFormat === 2) {
      // force_dec
      t += val.toString(10);
    } else if (displayFormat === 3) {
      // force_oct
      t += "0" + val.toString(8);
    } else if (displayFormat === 5) {
      // force_char
      if (this.doEmitWideCharPrefix() && sz > 1)
        t += 'L';
      t += "'";
      if (sz === 1 && Number(val) >= 0x80)
        t += "\\x" + (Number(val) & 0xff).toString(16).padStart(2, '0');
      else {
        // printUnicode simplified
        const ch = Number(val);
        if (ch >= 0x20 && ch < 0x7f && ch !== 0x27 && ch !== 0x5c)
          t += String.fromCharCode(ch);
        else
          t += "\\x" + (ch & 0xff).toString(16).padStart(2, '0');
      }
      t += "'";
    } else {
      // force_bin
      t += "0b";
      // Format binary
      const writer: Writer = { write(s: string) { t += s; } };
      PrintLanguage.formatBinary(writer, val);
    }
    if (force_unsigned_token)
      t += 'U';
    if (force_sized_token)
      t += this.sizeSuffix;

    this.pushAtom(new Atom(t, tag, syntax_highlight.const_color, op as any, vn, val));
  }

  // -----------------------------------------------------------------------
  // push_float
  // -----------------------------------------------------------------------

  protected push_float(val: uintb, sz: number, tag: tagtype, vn: Varnode | null, op: PcodeOp | null): void {
    let token: string;

    const format: FloatFormat = this.glb.translate.getFloatFormat(sz);
    if (format === null || format === undefined) {
      token = "FLOAT_UNKNOWN";
    } else {
      const hostResult = format.getHostFloat(val);
      const floatval: number = hostResult.value;
      const floatType = hostResult.type;
      // FloatFormat::infinity=1, nan=2
      if (floatType === FloatClass.infinity) {
        if (format.extractSign(val))
          token = "-INFINITY";
        else
          token = "INFINITY";
      } else if (floatType === FloatClass.nan) {
        if (format.extractSign(val))
          token = "-NAN";
        else
          token = "NAN";
      } else {
        if ((this.mods & modifiers.force_scinote) !== 0) {
          token = format.printDecimal(floatval, true);
        } else {
          token = format.printDecimal(floatval, false);
          let looksLikeFloat = false;
          for (let i = 0; i < token.length; ++i) {
            const c = token[i];
            if (c === '.' || c === 'e') {
              looksLikeFloat = true;
              break;
            }
          }
          if (!looksLikeFloat) {
            token += ".0";
          }
        }
      }
    }
    this.pushAtom(new Atom(token, tag, syntax_highlight.const_color, op as any, vn, val));
  }

  // -----------------------------------------------------------------------
  // Simple one-liner op methods (from the header)
  // -----------------------------------------------------------------------

  opIntEqual(op: PcodeOp): void { this.opBinary(PrintC.equal, op); }
  opIntNotEqual(op: PcodeOp): void { this.opBinary(PrintC.not_equal, op); }
  opIntSless(op: PcodeOp): void { this.opBinary(PrintC.less_than, op); }
  opIntSlessEqual(op: PcodeOp): void { this.opBinary(PrintC.less_equal, op); }
  opIntLess(op: PcodeOp): void { this.opBinary(PrintC.less_than, op); }
  opIntLessEqual(op: PcodeOp): void { this.opBinary(PrintC.less_equal, op); }
  opIntAdd(op: PcodeOp): void { this.opBinary(PrintC.binary_plus, op); }
  opIntSub(op: PcodeOp): void { this.opBinary(PrintC.binary_minus, op); }
  opIntCarry(op: PcodeOp): void { this.opFunc(op); }
  opIntScarry(op: PcodeOp): void { this.opFunc(op); }
  opIntSborrow(op: PcodeOp): void { this.opFunc(op); }
  opInt2Comp(op: PcodeOp): void { this.opUnary(PrintC.unary_minus, op); }
  opIntNegate(op: PcodeOp): void { this.opUnary(PrintC.bitwise_not, op); }
  opIntXor(op: PcodeOp): void { this.opBinary(PrintC.bitwise_xor, op); }
  opIntAnd(op: PcodeOp): void { this.opBinary(PrintC.bitwise_and, op); }
  opIntOr(op: PcodeOp): void { this.opBinary(PrintC.bitwise_or, op); }
  opIntLeft(op: PcodeOp): void { this.opBinary(PrintC.shift_left, op); }
  opIntRight(op: PcodeOp): void { this.opBinary(PrintC.shift_right, op); }
  opIntSright(op: PcodeOp): void { this.opBinary(PrintC.shift_sright, op); }
  opIntMult(op: PcodeOp): void { this.opBinary(PrintC.multiply, op); }
  opIntDiv(op: PcodeOp): void { this.opBinary(PrintC.divide, op); }
  opIntSdiv(op: PcodeOp): void { this.opBinary(PrintC.divide, op); }
  opIntRem(op: PcodeOp): void { this.opBinary(PrintC.modulo, op); }
  opIntSrem(op: PcodeOp): void { this.opBinary(PrintC.modulo, op); }
  opBoolXor(op: PcodeOp): void { this.opBinary(PrintC.boolean_xor, op); }
  opBoolAnd(op: PcodeOp): void { this.opBinary(PrintC.boolean_and, op); }
  opBoolOr(op: PcodeOp): void { this.opBinary(PrintC.boolean_or, op); }
  opFloatEqual(op: PcodeOp): void { this.opBinary(PrintC.equal, op); }
  opFloatNotEqual(op: PcodeOp): void { this.opBinary(PrintC.not_equal, op); }
  opFloatLess(op: PcodeOp): void { this.opBinary(PrintC.less_than, op); }
  opFloatLessEqual(op: PcodeOp): void { this.opBinary(PrintC.less_equal, op); }
  opFloatNan(op: PcodeOp): void { this.opFunc(op); }
  opFloatAdd(op: PcodeOp): void { this.opBinary(PrintC.binary_plus, op); }
  opFloatDiv(op: PcodeOp): void { this.opBinary(PrintC.divide, op); }
  opFloatMult(op: PcodeOp): void { this.opBinary(PrintC.multiply, op); }
  opFloatSub(op: PcodeOp): void { this.opBinary(PrintC.binary_minus, op); }
  opFloatNeg(op: PcodeOp): void { this.opUnary(PrintC.unary_minus, op); }
  opFloatAbs(op: PcodeOp): void { this.opFunc(op); }
  opFloatSqrt(op: PcodeOp): void { this.opFunc(op); }
  opFloatFloat2Float(op: PcodeOp): void { this.opTypeCast(op); }
  opFloatTrunc(op: PcodeOp): void { this.opTypeCast(op); }
  opFloatCeil(op: PcodeOp): void { this.opFunc(op); }
  opFloatFloor(op: PcodeOp): void { this.opFunc(op); }
  opFloatRound(op: PcodeOp): void { this.opFunc(op); }
  opMultiequal(_op: PcodeOp): void { /* empty */ }
  opIndirect(_op: PcodeOp): void { /* empty */ }
  opPiece(op: PcodeOp): void { this.opFunc(op); }
  opCast(op: PcodeOp): void { this.opTypeCast(op); }
  opPopcountOp(op: PcodeOp): void { this.opFunc(op); }
  opLzcountOp(op: PcodeOp): void { this.opFunc(op); }

  // -----------------------------------------------------------------------
  // Remaining virtual methods
  // -----------------------------------------------------------------------

  protected printUnicode(s: Writer, onechar: number): void {
    if (PrintLanguage.unicodeNeedsEscape(onechar)) {
      switch (onechar) {
        case 0: s.write("\\0"); return;
        case 7: s.write("\\a"); return;
        case 8: s.write("\\b"); return;
        case 9: s.write("\\t"); return;
        case 10: s.write("\\n"); return;
        case 11: s.write("\\v"); return;
        case 12: s.write("\\f"); return;
        case 13: s.write("\\r"); return;
        case 0x22: s.write('\\"'); return;
        case 0x27: s.write("\\'"); return;
        case 92: s.write("\\\\"); return;
        default:
          PrintC.printCharHexEscape(s, onechar);
          return;
      }
    }
    s.write(String.fromCodePoint(onechar));
  }

  protected pushType(ct: Datatype): void {
    this.pushTypeStart(ct, true);
    this.pushAtom(new Atom(PrintC.EMPTY_STRING, tagtype.blanktoken, syntax_highlight.no_color));
    this.pushTypeEnd(ct);
  }

  protected genericFunctionName(addr: Address): string {
    return "func_" + addr.getOffset().toString(16);
  }

  protected genericTypeName(ct: Datatype): string {
    let prefix: string;
    switch (ct.getMetatype()) {
      case type_metatype.TYPE_INT:
        prefix = "unkint"; break;
      case type_metatype.TYPE_UINT:
        prefix = "unkuint"; break;
      case type_metatype.TYPE_UNKNOWN:
        prefix = "unkbyte"; break;
      case type_metatype.TYPE_SPACEBASE:
        return "BADSPACEBASE";
      case type_metatype.TYPE_FLOAT:
        prefix = "unkfloat"; break;
      default:
        return "BADTYPE";
    }
    return prefix + ct.getSize().toString();
  }

  protected pushConstant(val: uintb, ct: Datatype, tag: tagtype, vn: Varnode | null, op: PcodeOp | null): void {
    let subtype: Datatype;
    switch (ct.getMetatype()) {
      case type_metatype.TYPE_UINT:
        if (ct.isCharPrint())
          this.pushCharConstant(val, ct, tag, vn, op);
        else if (ct.isEnumType())
          this.pushEnumConstant(val, ct, tag, vn, op);
        else
          this.push_integer(val, ct.getSize(), false, tag, vn, op);
        return;
      case type_metatype.TYPE_INT:
        if (ct.isCharPrint())
          this.pushCharConstant(val, ct, tag, vn, op);
        else if (ct.isEnumType())
          this.pushEnumConstant(val, ct, tag, vn, op);
        else
          this.push_integer(val, ct.getSize(), true, tag, vn, op);
        return;
      case type_metatype.TYPE_UNKNOWN:
        this.push_integer(val, ct.getSize(), false, tag, vn, op);
        return;
      case type_metatype.TYPE_BOOL:
        this.pushBoolConstant(val, ct, tag, vn, op);
        return;
      case type_metatype.TYPE_VOID:
        this.clear();
        throw new LowlevelError("Cannot have a constant of type void");
      case type_metatype.TYPE_PTR:
      case type_metatype.TYPE_PTRREL:
        if (this.option_NULL && val === 0n) {
          this.pushAtom(new Atom(this.nullToken, tagtype.vartoken, syntax_highlight.var_color, op as any, vn));
          return;
        }
        subtype = ct.getPtrTo();
        if (subtype.isCharPrint()) {
          if (this.pushPtrCharConstant(val, ct, vn, op))
            return;
        } else if (subtype.getMetatype() === type_metatype.TYPE_CODE) {
          if (this.pushPtrCodeConstant(val, ct, vn, op))
            return;
        }
        break;
      case type_metatype.TYPE_FLOAT:
        this.push_float(val, ct.getSize(), tag, vn, op);
        return;
      case type_metatype.TYPE_SPACEBASE:
      case type_metatype.TYPE_CODE:
      case type_metatype.TYPE_ARRAY:
      case type_metatype.TYPE_STRUCT:
      case type_metatype.TYPE_UNION:
        break;
      default:
        break;
    }
    // Default printing
    if (!this.option_nocasts) {
      this.pushOp(PrintC.typecast, op);
      this.pushType(ct);
    }
    this.pushMod();
    if (!this.isSet(modifiers.force_dec))
      this.setMod(modifiers.force_hex);
    this.push_integer(val, ct.getSize(), false, tag, vn, op);
    this.popMod();
  }

  protected pushEquate(val: uintb, sz: number, sym: EquateSymbol, vn: Varnode | null, op: PcodeOp | null): boolean {
    const mask: bigint = calc_mask(sz);
    const baseval: bigint = sym.getValue();
    let modval: bigint = baseval & mask;
    if (modval !== baseval) {
      // If 1-bits are getting masked, make sure we only mask sign extension bits
      if (sign_extend(modval, sz * 8 - 1) !== baseval)
        return false;
    }
    if (modval === val) {
      this.pushSymbol(sym, vn, op);
      return true;
    }
    modval = (~baseval) & mask;
    if (modval === val) {
      this.pushOp(PrintC.bitwise_not, null as any);
      this.pushSymbol(sym, vn, op);
      return true;
    }
    modval = (-baseval) & mask;
    if (modval === val) {
      this.pushOp(PrintC.unary_minus, null as any);
      this.pushSymbol(sym, vn, op);
      return true;
    }
    modval = (baseval + 1n) & mask;
    if (modval === val) {
      this.pushOp(PrintC.binary_plus, null as any);
      this.pushSymbol(sym, vn, op);
      this.push_integer(1n, sz, false, tagtype.syntax, null, null);
      return true;
    }
    modval = (baseval - 1n) & mask;
    if (modval === val) {
      this.pushOp(PrintC.binary_minus, null as any);
      this.pushSymbol(sym, vn, op);
      this.push_integer(1n, sz, false, tagtype.syntax, null, null);
      return true;
    }
    return false;
  }

  protected pushAnnotation(vn: Varnode, op: PcodeOp): void {
    const symScope: Scope = op.getParent().getFuncdata().getScopeLocal();
    let size: number = 0;
    if (op.code() === OpCode.CPUI_CALLOTHER) {
      const userind: number = Number(op.getIn(0).getOffset());
      size = this.glb.userops.getOp(userind).extractAnnotationSize(vn, op);
    }
    let entry: SymbolEntry;
    if (size !== 0) {
      entry = symScope.queryContainer(vn.getAddr(), size, op.getAddr());
    } else {
      entry = symScope.queryContainer(vn.getAddr(), 1, op.getAddr());
      if (entry !== null && entry !== undefined)
        size = entry.getSize();
      else
        size = vn.getSize();
    }

    if (entry !== null && entry !== undefined) {
      if (entry.getSize() === size)
        this.pushSymbol(entry.getSymbol(), vn, op);
      else {
        const symboloff: number = Number(vn.getOffset() - entry.getFirst());
        this.pushPartialSymbol(entry.getSymbol(), symboloff, size, vn, op, -1, false);
      }
    } else {
      let regname: string = this.glb.translate.getRegisterName(vn.getSpace(), vn.getOffset(), size);
      if (!regname || regname.length === 0) {
        const spc: AddrSpace = vn.getSpace();
        let spacename: string = spc.getName();
        spacename = spacename[0].toUpperCase() + spacename.slice(1);
        const addrVal = spc.byteToAddress ? spc.byteToAddress(vn.getOffset(), spc.getWordSize()) : vn.getOffset();
        regname = spacename + Number(addrVal).toString(16).padStart(2 * spc.getAddrSize(), '0');
      }
      this.pushAtom(new Atom(regname, tagtype.vartoken, syntax_highlight.special_color, op, vn));
    }
  }

  protected pushSymbol(sym: Symbol, vn: Varnode, op: PcodeOp): void {
    let tokenColor: number;
    if (sym.isVolatile())
      tokenColor = syntax_highlight.special_color;
    else if (sym.getScope().isGlobal())
      tokenColor = syntax_highlight.global_color;
    else if (sym.getCategory() === 0) // Symbol::function_parameter = 0
      tokenColor = syntax_highlight.param_color;
    else if (sym.getCategory() === 1) // Symbol::equate = 1
      tokenColor = syntax_highlight.const_color;
    else
      tokenColor = syntax_highlight.var_color;

    this.pushSymbolScope(sym);
    if (sym.hasMergeProblems() && vn !== null && vn !== undefined) {
      const high: HighVariable = vn.getHigh();
      if (high.isUnmerged()) {
        let s: string = sym.getDisplayName();
        const entry: SymbolEntry = high.getSymbolEntry();
        if (entry !== null && entry !== undefined) {
          s += '$' + entry.getSymbol().getMapEntryPosition(entry).toString();
        } else {
          s += '$$';
        }
        this.pushAtom(new Atom(s, tagtype.vartoken, tokenColor, op, vn));
        return;
      }
    }
    this.pushAtom(new Atom(sym.getDisplayName(), tagtype.vartoken, tokenColor, op, vn));
  }

  protected pushUnnamedLocation(addr: Address, vn: Varnode, op: PcodeOp): void {
    const spc = addr.getSpace();
    let s: string = spc !== null && typeof spc.getName === 'function' ? spc.getName() : 'unknown';
    s += addr.getOffset().toString(16);
    this.pushAtom(new Atom(s, tagtype.vartoken, syntax_highlight.var_color, op, vn));
  }

  protected pushPartialSymbol(sym: Symbol, off: number, sz: number,
    vn: Varnode, op: PcodeOp, slot: number, allowCast: boolean): void {
    // We need to print "bottom up" in order to get parentheses right
    const stack: PartialSymbolEntry[] = [];
    let finalcast: Datatype = null as any;

    let ct: Datatype = sym.getType();

    while (ct !== null && ct !== undefined) {
      if (off === 0) {
        if (sz === 0 || (sz === ct.getSize() && (!ct.needsResolution() || ct.getMetatype() === type_metatype.TYPE_PTR)))
          break;
      }
      let succeeded = false;
      if (ct.getMetatype() === type_metatype.TYPE_STRUCT) {
        if (ct.needsResolution() && ct.getSize() === sz) {
          const outtype: Datatype = ct.findResolve(op, slot);
          if (outtype === ct)
            break;
        }
        const newoffResult = { value: 0 };
        const field: TypeField = ct.findTruncation(BigInt(off), sz, op, slot, newoffResult);
        if (field !== null && field !== undefined) {
          off = Number(newoffResult.value);
          const entry: PartialSymbolEntry = {
            token: PrintC.object_member,
            field: field,
            parent: ct,
            offset: 0n,
            size: 0,
            hilite: syntax_highlight.no_color,
          };
          stack.push(entry);
          ct = field.type;
          succeeded = true;
        }
      } else if (ct.getMetatype() === type_metatype.TYPE_ARRAY) {
        const offOut = { value: 0 };
        const elOut = { value: 0 };
        const arrayof: Datatype = ct.getSubEntry(off, sz, offOut, elOut);
        if (arrayof !== null && arrayof !== undefined) {
          off = offOut.value;
          const entry: PartialSymbolEntry = {
            token: PrintC.subscript,
            field: null,
            parent: ct,
            offset: BigInt(elOut.value),
            size: 0,
            hilite: syntax_highlight.const_color,
          };
          stack.push(entry);
          ct = arrayof;
          succeeded = true;
        }
      } else if (ct.getMetatype() === type_metatype.TYPE_UNION) {
        const newoffResult = { value: 0 };
        const field: TypeField = ct.findTruncation(BigInt(off), sz, op, slot, newoffResult);
        if (field !== null && field !== undefined) {
          off = Number(newoffResult.value);
          const entry: PartialSymbolEntry = {
            token: PrintC.object_member,
            field: field,
            parent: ct,
            offset: 0n,
            size: 0,
            hilite: syntax_highlight.no_color,
          };
          stack.push(entry);
          ct = field.type;
          succeeded = true;
        } else if (ct.getSize() === sz)
          break;
      } else if (allowCast) {
        const outtype: Datatype = vn.getHigh().getType();
        let spc: AddrSpace = sym.getFirstWholeMap()?.getAddr()?.getSpace();
        if (spc === null || spc === undefined)
          spc = vn.getSpace();
        if (this.castStrategy!.isSubpieceCastEndian(outtype, ct, off, spc.isBigEndian())) {
          finalcast = outtype;
          ct = null as any;
          succeeded = true;
        }
      }
      if (!succeeded) {
        if (sz === 0)
          sz = ct.getSize() - off;
        const entry: PartialSymbolEntry = {
          token: PrintC.object_member,
          field: null,
          parent: ct,
          offset: BigInt(off),
          size: sz,
          hilite: syntax_highlight.no_color,
        };
        stack.push(entry);
        ct = null as any;
      }
    }

    if (finalcast !== null && finalcast !== undefined && !this.option_nocasts) {
      this.pushOp(PrintC.typecast, op);
      this.pushType(finalcast);
    }
    // Push these on the RPN stack in reverse order
    for (let i = stack.length - 1; i >= 0; --i)
      this.pushOp(stack[i].token, op);
    this.pushSymbol(sym, vn, op);
    for (let i = 0; i < stack.length; ++i) {
      const entry = stack[i];
      if (entry.field === null || entry.field === undefined) {
        if (entry.size <= 0)
          this.push_integer(entry.offset, entry.size, (entry.offset < 0n), tagtype.syntax, null, op);
        else {
          const fieldName: string = this.unnamedField(Number(entry.offset), entry.size);
          this.pushAtom(new Atom(fieldName, tagtype.syntax, entry.hilite, op as any));
        }
      } else {
        this.pushAtom(new Atom(entry.field.name, tagtype.fieldtoken, stack[i].hilite, stack[i].parent, entry.field.ident ?? 0, op));
      }
    }
  }

  protected pushMismatchSymbol(sym: Symbol, off: number, sz: number,
    vn: Varnode, op: PcodeOp): void {
    if (off === 0) {
      // The most common situation: user sees a reference to a variable and forces a symbol
      // but guesses the type (or size) incorrectly.
      // Prepend an underscore to indicate a close but not quite match.
      const nm: string = '_' + sym.getDisplayName();
      this.pushAtom(new Atom(nm, tagtype.vartoken, syntax_highlight.var_color, op, vn));
    } else {
      this.pushUnnamedLocation(vn.getAddr(), vn, op);
    }
  }

  protected pushImpliedField(vn: Varnode, op: PcodeOp): void {
    let proceed = false;
    const parent: Datatype = vn.getHigh().getType();
    let field: TypeField = null as any;
    if (parent.needsResolution() && parent.getMetatype() !== type_metatype.TYPE_PTR) {
      const fd: Funcdata = op.getParent().getFuncdata();
      const slot: number = op.getSlot(vn);
      const res: ResolvedUnion = fd.getUnionField(parent, op, slot);
      if (res !== null && res !== undefined && res.getFieldNum() >= 0) {
        if (parent.getMetatype() === type_metatype.TYPE_STRUCT && res.getFieldNum() === 0) {
          field = parent.getField(0);
          proceed = true;
        } else if (parent.getMetatype() === type_metatype.TYPE_UNION) {
          field = parent.getField(res.getFieldNum());
          proceed = true;
        }
      }
    }

    const defOp: PcodeOp = vn.getDef();
    if (!proceed) {
      // Just push original op
      defOp.getOpcode().push(this, defOp, op);
      return;
    }
    this.pushOp(PrintC.object_member, op);
    defOp.getOpcode().push(this, defOp, op);
    this.pushAtom(new Atom(field.name, tagtype.fieldtoken, syntax_highlight.no_color, parent, field.ident ?? 0, op));
  }

  protected pushBoolConstant(val: uintb, ct: TypeBase, tag: tagtype, vn: Varnode | null, op: PcodeOp | null): void {
    if (val !== 0n)
      this.pushAtom(new Atom(PrintC.KEYWORD_TRUE, tag, syntax_highlight.const_color, op as any, vn, val));
    else
      this.pushAtom(new Atom(PrintC.KEYWORD_FALSE, tag, syntax_highlight.const_color, op as any, vn, val));
  }

  protected pushCharConstant(val: uintb, ct: Datatype, tag: tagtype, vn: Varnode | null, op: PcodeOp | null): void {
    let displayFormat: number = 0;
    const isSigned: boolean = (ct.getMetatype() === type_metatype.TYPE_INT);
    if (vn !== null && vn !== undefined && !vn.isAnnotation()) {
      const high: HighVariable = vn.getHigh();
      const sym: Symbol = high.getSymbol();
      if (sym !== null && sym !== undefined) {
        if (sym.isNameLocked() && sym.getCategory() === 1) {
          if (this.pushEquate(val, vn.getSize(), sym, vn, op))
            return;
        }
        displayFormat = sym.getDisplayFormat();
      }
      if (displayFormat === 0)
        displayFormat = high.getType().getDisplayFormat();
    }
    // Symbol::force_char = 5
    if (displayFormat !== 0 && displayFormat !== 5) {
      if (!this.castStrategy!.caresAboutCharRepresentation(vn, op)) {
        this.push_integer(val, ct.getSize(), isSigned, tag, vn, op);
        return;
      }
    }
    if (ct.getSize() === 1 && val >= 0x80n) {
      // For byte characters, encoding is assumed to be ASCII, UTF-8, or some other
      // code-page that extends ASCII. At 0x80 and above, we cannot treat the value as a
      // unicode code-point.
      if (displayFormat !== 1 && displayFormat !== 5) { // force_hex=1, force_char=5
        this.push_integer(val, 1, isSigned, tag, vn, op);
        return;
      }
      displayFormat = 1; // force_hex, Fallthru but force a hex representation
    }
    let t = "";
    // From here we assume, the constant value is a direct unicode code-point.
    if (this.doEmitWideCharPrefix() && ct.getSize() > 1)
      t += 'L';
    t += "'";
    if (displayFormat === 1) { // force_hex
      const writer: Writer = { write(s: string) { t += s; } };
      PrintC.printCharHexEscape(writer, Number(val));
    } else {
      const writer: Writer = { write(s: string) { t += s; } };
      this.printUnicode(writer, Number(val));
    }
    t += "'";
    this.pushAtom(new Atom(t, tag, syntax_highlight.const_color, op as any, vn, val));
  }

  protected pushEnumConstant(val: uintb, ct: TypeEnum, tag: tagtype, vn: Varnode | null, op: PcodeOp | null): void {
    const rep: any = { matchname: [], complement: false, shiftAmount: 0 };
    ct.getMatches(val, rep);
    if (rep.matchname && rep.matchname.length > 0) {
      if (rep.shiftAmount !== 0)
        this.pushOp(PrintC.shift_right, op);
      if (rep.complement)
        this.pushOp(PrintC.bitwise_not, op);
      for (let i = rep.matchname.length - 1; i > 0; --i)
        this.pushOp(PrintC.enum_cat, op);
      for (let i = 0; i < rep.matchname.length; ++i)
        this.pushAtom(new Atom(rep.matchname[i], tag, syntax_highlight.const_color, op as any, vn, val));
      if (rep.shiftAmount !== 0)
        this.push_integer(BigInt(rep.shiftAmount), 4, false, tag, vn, op);
    } else {
      this.push_integer(val, ct.getSize(), false, tag, vn, op);
    }
  }

  protected pushPtrCharConstant(val: uintb, ct: TypePointer, vn: Varnode | null, op: PcodeOp | null): boolean {
    if (val === 0n) return false;
    const spc: AddrSpace = this.glb.getDefaultDataSpace();
    let fullEncoding: bigint = 0n;
    let point: Address = new Address();
    if (op !== null && op !== undefined)
      point = op.getAddr();
    const fullEncodingOut = { value: fullEncoding };
    const stringaddr: Address = this.glb.resolveConstant(spc, val, ct.getSize(), point, fullEncodingOut);
    if (stringaddr.isInvalid()) return false;
    if (!this.glb.symboltab.getGlobalScope().isReadOnly(stringaddr, 1, new Address()))
      return false;

    let str = "";
    const writer: Writer = { write(s: string) { str += s; } };
    const subct: Datatype = ct.getPtrTo();
    if (!this.printCharacterConstant(writer, stringaddr, subct))
      return false;

    this.pushAtom(new Atom(str, tagtype.vartoken, syntax_highlight.const_color, op as any, vn));
    return true;
  }

  protected pushPtrCodeConstant(val: uintb, ct: TypePointer, vn: Varnode | null, op: PcodeOp | null): boolean {
    const spc: AddrSpace = this.glb.getDefaultCodeSpace();
    let byteVal: bigint = val;
    if (spc.addressToByte) {
      byteVal = spc.addressToByte(val, spc.getWordSize());
    } else if (spc.getWordSize() > 1) {
      byteVal = val * BigInt(spc.getWordSize());
    }
    const fd: Funcdata = this.glb.symboltab.getGlobalScope().queryFunction(new Address(spc, byteVal));
    if (fd !== null && fd !== undefined) {
      this.pushAtom(new Atom(fd.getDisplayName(), tagtype.functoken, syntax_highlight.funcname_color, op as any, fd));
      return true;
    }
    return false;
  }

  protected doEmitWideCharPrefix(): boolean {
    return true;
  }

  protected printCharacterConstant(s: Writer, addr: Address, charType: Datatype): boolean {
    const manager = this.glb.stringManager;
    if (manager === null || manager === undefined) return false;

    // Retrieve UTF8 version of string
    let isTrunc = false;
    const truncOut = { value: isTrunc };
    const buffer: Uint8Array = manager.getStringData(addr, charType, truncOut);
    isTrunc = truncOut.value;
    if (!buffer || buffer.length === 0)
      return false;
    if (this.doEmitWideCharPrefix() && charType.getSize() > 1 && !charType.isOpaqueString())
      s.write('L');
    s.write('"');
    this.escapeCharacterData(s, buffer, buffer.length, 1, this.glb.translate?.isBigEndian() ?? false);
    if (isTrunc)
      s.write('..." /* TRUNCATED STRING LITERAL */');
    else
      s.write('"');

    return true;
  }

  // -----------------------------------------------------------------------
  // emitExpression and related methods (stubs)
  // -----------------------------------------------------------------------

  protected emitExpression(op: PcodeOp): void {
    let outvn: Varnode = op.getOut();
    if (outvn !== null && outvn !== undefined) {
      if (this.option_inplace_ops && this.emitInplaceOp(op)) return;
      this.pushOp(PrintC.assignment, op);
      this.pushSymbolDetail(outvn, op, false);
    } else if (op.doesSpecialPrinting()) {
      // Printing of constructor syntax
      const newop: PcodeOp = op.getIn(1).getDef();
      outvn = newop.getOut();
      this.pushOp(PrintC.assignment, newop);
      this.pushSymbolDetail(outvn, newop, false);
      this.opConstructor(op, true);
      this.recurse();
      return;
    }
    op.getOpcode().push(this, op, null as any);
    this.recurse();
  }

  protected emitVarDecl(sym: Symbol): void {
    const id: number = this.emit.beginVarDecl(sym);
    this.pushTypeStart(sym.getType(), false);
    this.pushSymbol(sym, null as any, null as any);
    this.pushTypeEnd(sym.getType());
    this.recurse();
    this.emit.endVarDecl(id);
  }

  protected emitVarDeclStatement(sym: Symbol): void {
    this.emit.tagLine();
    this.emitVarDecl(sym);
    this.emit.print(PrintC.SEMICOLON);
  }

  protected emitScopeVarDecls(symScope: Scope, cat: number): boolean {
    let notempty = false;

    if (cat >= 0) {
      const sz: number = symScope.getCategorySize(cat);
      for (let i = 0; i < sz; ++i) {
        const sym: Symbol = symScope.getCategorySymbol(cat, i);
        if (sym.getName().length === 0) continue;
        if (sym.isNameUndefined()) continue;
        notempty = true;
        this.emitVarDeclStatement(sym);
      }
      return notempty;
    }
    // Iterate over mapped entries
    const enditer = symScope.end();
    for (let cur = symScope.begin(); !cur.equals(enditer); cur = cur.increment()) {
      const entry: SymbolEntry = cur.deref();
      if (entry.isPiece()) continue;
      const sym: Symbol = entry.getSymbol();
      if (sym.getCategory() !== cat) continue;
      if (sym.getName().length === 0) continue;
      if (sym.isFunctionSymbol && sym.isFunctionSymbol()) continue;
      if (sym.isLabSymbol && sym.isLabSymbol()) continue;
      if (sym.isMultiEntry()) {
        if (sym.getFirstWholeMap() !== entry)
          continue;
      }
      notempty = true;
      this.emitVarDeclStatement(sym);
    }
    // Iterate over dynamic entries
    if (symScope.beginDynamic) {
      const dynEntries: SymbolEntry[] = symScope.beginDynamic();
      for (const entry of dynEntries) {
        if (entry.isPiece()) continue;
        const sym: Symbol = entry.getSymbol();
        if (sym.getCategory() !== cat) continue;
        if (sym.getName().length === 0) continue;
        if (sym.isFunctionSymbol && sym.isFunctionSymbol()) continue;
        if (sym.isLabSymbol && sym.isLabSymbol()) continue;
        if (sym.isMultiEntry()) {
          if (sym.getFirstWholeMap() !== entry)
            continue;
        }
        notempty = true;
        this.emitVarDeclStatement(sym);
      }
    }
    return notempty;
  }

  protected emitFunctionDeclaration(fd: Funcdata): void {
    const proto: FuncProto = fd.getFuncProto();
    const id: number = this.emit.beginFuncProto();
    this.emitPrototypeOutput(proto, fd);
    this.emit.spaces(1);
    if (this.option_convention) {
      if (fd.getFuncProto().printModelInDecl()) {
        const highlight: number = fd.getFuncProto().isModelUnknown() ? syntax_highlight.error_color : syntax_highlight.keyword_color;
        this.emit.print(fd.getFuncProto().getModelName(), highlight);
        this.emit.spaces(1);
      }
    }
    const id1: number = this.emit.openGroup();
    this.emitSymbolScope(fd.getSymbol());
    this.emit.tagFuncName(fd.getDisplayName(), syntax_highlight.funcname_color, fd, null as any);

    this.emit.spaces(PrintC.function_call.spacing, PrintC.function_call.bump);
    const id2: number = this.emit.openParen(PrintLanguage.OPEN_PAREN);
    this.emit.spaces(0, PrintC.function_call.bump);
    this.pushScope(fd.getScopeLocal());
    this.emitPrototypeInputs(proto);
    this.emit.closeParen(PrintLanguage.CLOSE_PAREN, id2);
    this.emit.closeGroup(id1);

    this.emit.endFuncProto(id);
  }

  protected checkPrintNegation(vn: Varnode): boolean {
    if (!vn.isImplied()) return false;
    if (!vn.isWritten()) return false;
    const defOp = vn.getDef();
    const opc: number = defOp.code();
    if (opc === OpCode.CPUI_INT_EQUAL || opc === OpCode.CPUI_INT_NOTEQUAL ||
      opc === OpCode.CPUI_INT_SLESS || opc === OpCode.CPUI_INT_SLESSEQUAL ||
      opc === OpCode.CPUI_INT_LESS || opc === OpCode.CPUI_INT_LESSEQUAL ||
      opc === OpCode.CPUI_FLOAT_EQUAL || opc === OpCode.CPUI_FLOAT_NOTEQUAL ||
      opc === OpCode.CPUI_FLOAT_LESS || opc === OpCode.CPUI_FLOAT_LESSEQUAL ||
      opc === OpCode.CPUI_BOOL_NEGATE)
      return true;
    return false;
  }

  protected emitStructDefinition(ct: TypeStruct): void {
    if (ct.getName().length === 0) {
      this.clear();
      throw new LowlevelError("Trying to save unnamed structure");
    }

    this.emit.tagLine();
    this.emit.print("typedef struct", syntax_highlight.keyword_color);
    const id: number = this.emit.openBraceIndent(PrintC.OPEN_CURLY, brace_style.same_line);
    this.emit.tagLine();
    let iter = ct.beginField();
    const endIter = ct.endField();
    while (iter !== endIter) {
      const fld = ct.derefField(iter);
      this.pushTypeStart(fld.type, false);
      this.pushAtom(new Atom(fld.name, tagtype.syntax, syntax_highlight.var_color));
      this.pushTypeEnd(fld.type);
      iter = ct.nextField(iter);
      if (iter !== endIter) {
        this.emit.print(PrintC.COMMA);
        this.emit.tagLine();
      }
    }
    this.emit.closeBraceIndent(PrintC.CLOSE_CURLY, id);
    this.emit.spaces(1);
    this.emit.print(ct.getDisplayName());
    this.emit.print(PrintC.SEMICOLON);
  }

  protected emitEnumDefinition(ct: TypeEnum): void {
    if (ct.getName().length === 0) {
      this.clear();
      throw new LowlevelError("Trying to save unnamed enumeration");
    }

    this.pushMod();
    const sign: boolean = (ct.getMetatype() === type_metatype.TYPE_INT);
    this.emit.tagLine();
    this.emit.print("typedef enum", syntax_highlight.keyword_color);
    const id: number = this.emit.openBraceIndent(PrintC.OPEN_CURLY, brace_style.same_line);
    this.emit.tagLine();
    let iter = ct.beginEnum();
    const endIter = ct.endEnum();
    while (iter !== endIter) {
      const entry = ct.derefEnum(iter);
      this.emit.print(entry[1], syntax_highlight.const_color);
      this.emit.spaces(1);
      this.emit.print(PrintC.EQUALSIGN, syntax_highlight.no_color);
      this.emit.spaces(1);
      this.push_integer(entry[0], ct.getSize(), sign, tagtype.syntax, null, null);
      this.recurse();
      this.emit.print(PrintC.SEMICOLON);
      iter = ct.nextEnum(iter);
      if (iter !== endIter)
        this.emit.tagLine();
    }
    this.popMod();
    this.emit.closeBraceIndent(PrintC.CLOSE_CURLY, id);
    this.emit.spaces(1);
    this.emit.print(ct.getDisplayName());
    this.emit.print(PrintC.SEMICOLON);
  }

  protected emitPrototypeOutput(proto: FuncProto, fd: Funcdata): void {
    let op: PcodeOp = null as any;
    let vn: Varnode = null as any;

    if (fd !== null && fd !== undefined) {
      op = fd.getFirstReturnOp();
      if (op !== null && op !== undefined && op.numInput() < 2)
        op = null as any;
    }

    const outtype: Datatype = proto.getOutputType();
    if (outtype.getMetatype() !== type_metatype.TYPE_VOID && op !== null && op !== undefined)
      vn = op.getIn(1);

    const id: number = this.emit.beginReturnType(vn);
    this.pushType(outtype);
    this.recurse();
    this.emit.endReturnType(id);
  }

  protected emitPrototypeInputs(proto: FuncProto): void {
    const sz: number = proto.numParams();

    if (sz === 0)
      this.emit.print(PrintC.KEYWORD_VOID, syntax_highlight.keyword_color);
    else {
      let printComma = false;
      for (let i = 0; i < sz; ++i) {
        if (printComma)
          this.emit.print(PrintC.COMMA);
        const param: ProtoParameter = proto.getParam(i);
        if (this.isSet(modifiers.hide_thisparam) && param.isThisPointer())
          continue;
        const sym: Symbol = param.getSymbol();
        printComma = true;
        if (sym !== null && sym !== undefined)
          this.emitVarDecl(sym);
        else {
          this.pushTypeStart(param.getType(), true);
          this.pushAtom(new Atom(PrintC.EMPTY_STRING, tagtype.blanktoken, syntax_highlight.no_color));
          this.pushTypeEnd(param.getType());
          this.recurse();
        }
      }
    }
    if (proto.isDotdotdot()) {
      if (sz !== 0)
        this.emit.print(PrintC.COMMA);
      this.emit.print(PrintC.DOTDOTDOT);
    }
  }

  protected emitGlobalVarDeclsRecursive(symScope: Scope): void {
    if (!symScope.isGlobal()) return;
    this.emitScopeVarDecls(symScope, -1); // Symbol::no_category = -1
    for (const [, child] of symScope.childrenBegin()) {
      this.emitGlobalVarDeclsRecursive(child);
    }
  }

  protected emitLocalVarDecls(fd: Funcdata): void {
    let notempty = false;

    // Symbol::no_category = -1
    if (this.emitScopeVarDecls(fd.getScopeLocal(), -1))
      notempty = true;
    for (const [, child] of fd.getScopeLocal().childrenBegin()) {
      if (this.emitScopeVarDecls(child, -1))
        notempty = true;
    }

    if (notempty)
      this.emit.tagLine();
  }

  protected emitStatement(inst: PcodeOp): void {
    const id: number = this.emit.beginStatement(inst);
    this.emitExpression(inst);
    this.emit.endStatement(id);
    if (!this.isSet(modifiers.comma_separate))
      this.emit.print(PrintC.SEMICOLON);
  }

  protected emitInplaceOp(op: PcodeOp): boolean {
    let tok: OpToken;
    switch (op.code()) {
      case OpCode.CPUI_INT_MULT:
        tok = PrintC.multequal; break;
      case OpCode.CPUI_INT_DIV:
      case OpCode.CPUI_INT_SDIV:
        tok = PrintC.divequal; break;
      case OpCode.CPUI_INT_REM:
      case OpCode.CPUI_INT_SREM:
        tok = PrintC.remequal; break;
      case OpCode.CPUI_INT_ADD:
        tok = PrintC.plusequal; break;
      case OpCode.CPUI_INT_SUB:
        tok = PrintC.minusequal; break;
      case OpCode.CPUI_INT_LEFT:
        tok = PrintC.leftequal; break;
      case OpCode.CPUI_INT_RIGHT:
      case OpCode.CPUI_INT_SRIGHT:
        tok = PrintC.rightequal; break;
      case OpCode.CPUI_INT_AND:
        tok = PrintC.andequal; break;
      case OpCode.CPUI_INT_OR:
        tok = PrintC.orequal; break;
      case OpCode.CPUI_INT_XOR:
        tok = PrintC.xorequal; break;
      default:
        return false;
    }
    const vn: Varnode = op.getIn(0);
    if (op.getOut().getHigh() !== vn.getHigh()) return false;
    this.pushOp(tok, op);
    this.pushVnExplicit(vn, op);
    this.pushVn(op.getIn(1), op, this.mods);
    this.recurse();
    return true;
  }

  protected emitGotoStatement(bl: FlowBlock, exp_bl: FlowBlock, type: number): void {
    const id: number = this.emit.beginStatement(bl.lastOp());
    // FlowBlock::f_break_goto=2, f_continue_goto=4, f_goto_goto=1
    switch (type) {
      case 2: // f_break_goto
        this.emit.print(PrintC.KEYWORD_BREAK, syntax_highlight.keyword_color);
        break;
      case 4: // f_continue_goto
        this.emit.print(PrintC.KEYWORD_CONTINUE, syntax_highlight.keyword_color);
        break;
      case 1: // f_goto_goto
        this.emit.print(PrintC.KEYWORD_GOTO, syntax_highlight.keyword_color);
        this.emit.spaces(1);
        this.emitLabel(exp_bl);
        break;
    }
    this.emit.print(PrintC.SEMICOLON);
    this.emit.endStatement(id);
  }

  protected emitSwitchCase(casenum: number, switchbl: BlockSwitch): void {
    const ct: Datatype = switchbl.getSwitchType();
    const op: PcodeOp = switchbl.getCaseBlock(casenum).firstOp();

    if (switchbl.isDefaultCase(casenum)) {
      const val: bigint = switchbl.getLabel(casenum, 0);
      this.emit.tagLine();
      this.emit.tagCaseLabel(PrintC.KEYWORD_DEFAULT, syntax_highlight.keyword_color, op, val);
      this.emit.print(PrintC.COLON);
    } else {
      const num: number = switchbl.getNumLabels(casenum);
      for (let i = 0; i < num; ++i) {
        const val: bigint = switchbl.getLabel(casenum, i);
        this.emit.tagLine();
        this.emit.print(PrintC.KEYWORD_CASE, syntax_highlight.keyword_color);
        this.emit.spaces(1);
        this.pushConstant(val, ct, tagtype.casetoken, null as any, op);
        this.recurse();
        this.emit.print(PrintC.COLON);
      }
    }
  }

  protected emitLabel(bl: FlowBlock): void {
    bl = bl.getFrontLeaf();
    if (bl === null || bl === undefined) return;
    const bb: BlockBasic = bl.subBlock(0);
    const addr: Address = bb.getEntryAddr();
    const spc: AddrSpace = addr.getSpace()!;
    const off: bigint = addr.getOffset();
    if (!bb.hasSpecialLabel()) {
      // block_type.t_basic = 1
      if (bb.getType() === 1) {
        const symScope: Scope = bb.getFuncdata().getScopeLocal();
        const sym: Symbol = symScope.queryCodeLabel(addr);
        if (sym !== null && sym !== undefined) {
          this.emit.tagLabel(sym.getDisplayName(), syntax_highlight.no_color, spc, off);
          return;
        }
      }
    }
    let lb: string;
    if (bb.isJoined())
      lb = "joined_";
    else if (bb.isDuplicated())
      lb = "dup_";
    else
      lb = "code_";
    lb += addr.getShortcut();
    lb += addr.getOffset().toString(16);
    this.emit.tagLabel(lb, syntax_highlight.no_color, spc, off);
  }

  protected emitLabelStatement(bl: FlowBlock): void {
    if (this.isSet(modifiers.only_branch)) return;

    if (this.isSet(modifiers.flat)) {
      if (!bl.isJumpTarget()) return;
    } else {
      if (!bl.isUnstructuredTarget()) return;
      // block_type.t_copy = 3
      if (bl.getType() !== 3) return;
    }
    this.emit.tagLineWithIndent(0);
    this.emitLabel(bl);
    this.emit.print(PrintC.COLON);
  }

  protected emitAnyLabelStatement(bl: FlowBlock): void {
    if (bl.isLabelBumpUp()) return;
    bl = bl.getFrontLeaf();
    if (bl === null || bl === undefined) return;
    this.emitLabelStatement(bl);
  }

  protected emitCommentGroup(inst: PcodeOp): void {
    this.commsorter.setupOpList(inst);
    while (this.commsorter.hasNext()) {
      const comm: Comment = this.commsorter.getNext();
      if (comm.isEmitted()) continue;
      if ((this.instr_comment_type & comm.getType()) === 0) continue;
      this.emitLineComment(-1, comm);
    }
  }

  protected emitCommentBlockTree(bl: FlowBlock): void {
    if (bl === null || bl === undefined) return;
    let btype: number = bl.getType();
    // block_type.t_copy = 3
    if (btype === 3) {
      bl = bl.subBlock(0);
      btype = bl.getType();
    }
    // block_type.t_plain = 0
    if (btype === 0) return;
    // block_type.t_basic = 1
    if (bl.getType() !== 1) {
      const rootbl = bl;
      const size: number = rootbl.getSize();
      for (let i = 0; i < size; ++i) {
        this.emitCommentBlockTree(rootbl.subBlock(i));
      }
      return;
    }
    this.commsorter.setupBlockList(bl);
    this.emitCommentGroup(null as any);
  }

  protected emitCommentFuncHeader(fd: Funcdata): void {
    let extralinebreak = false;
    // CommentSorter::header_basic = 0
    this.commsorter.setupHeader(0);
    while (this.commsorter.hasNext()) {
      const comm: Comment = this.commsorter.getNext();
      if (comm.isEmitted()) continue;
      if ((this.head_comment_type & comm.getType()) === 0) continue;
      this.emitLineComment(0, comm);
      extralinebreak = true;
    }
    if (this.option_unplaced) {
      if (extralinebreak)
        this.emit.tagLine();
      extralinebreak = false;
      // CommentSorter::header_unplaced = 1
      this.commsorter.setupHeader(1);
      while (this.commsorter.hasNext()) {
        const comm: Comment = this.commsorter.getNext();
        if (comm.isEmitted()) continue;
        if (!extralinebreak) {
          // Emit a warning label
          const label: any = {
            isEmitted: () => false,
            getType: () => 0x8, // Comment::warningheader
            getText: () => "Comments that could not be placed in the function body:",
          };
          this.emitLineComment(0, label);
          extralinebreak = true;
        }
        this.emitLineComment(1, comm);
      }
    }
    if (this.option_nocasts) {
      if (extralinebreak)
        this.emit.tagLine();
      const comm: any = {
        isEmitted: () => false,
        getType: () => 0x8, // Comment::warningheader
        getText: () => "DISPLAY WARNING: Type casts are NOT being printed",
      };
      this.emitLineComment(0, comm);
      extralinebreak = true;
    }
    if (extralinebreak)
      this.emit.tagLine();
  }

  protected emitForLoop(bl: BlockWhileDo): void {
    let op: PcodeOp;

    this.pushMod();
    this.unsetMod(modifiers.no_branch | modifiers.only_branch);
    this.emitAnyLabelStatement(bl);
    const condBlock: FlowBlock = bl.getBlock(0);
    this.emitCommentBlockTree(condBlock);
    this.emit.tagLine();
    op = condBlock.lastOp();
    this.emit.tagOp(PrintC.KEYWORD_FOR, syntax_highlight.keyword_color, op);
    this.emit.spaces(1);
    const id1: number = this.emit.openParen(PrintLanguage.OPEN_PAREN);
    this.pushMod();
    this.setMod(modifiers.comma_separate);
    op = bl.getInitializeOp();
    if (op !== null && op !== undefined) {
      const id3: number = this.emit.beginStatement(op);
      this.emitExpression(op);
      this.emit.endStatement(id3);
    }
    this.emit.print(PrintC.SEMICOLON);
    this.emit.spaces(1);
    condBlock.emit(this);
    this.emit.print(PrintC.SEMICOLON);
    this.emit.spaces(1);
    op = bl.getIterateOp();
    const id4: number = this.emit.beginStatement(op);
    this.emitExpression(op);
    this.emit.endStatement(id4);
    this.popMod();
    this.emit.closeParen(PrintLanguage.CLOSE_PAREN, id1);
    const indent: number = this.emit.openBraceIndent(PrintC.OPEN_CURLY, this.option_brace_loop);
    this.setMod(modifiers.no_branch);
    const id2: number = this.emit.beginBlock(bl.getBlock(1));
    bl.getBlock(1).emit(this);
    this.emit.endBlock(id2);
    this.emit.closeBraceIndent(PrintC.CLOSE_CURLY, indent);
    this.popMod();
  }

  // -----------------------------------------------------------------------
  // Public virtual method overrides
  // -----------------------------------------------------------------------

  resetDefaults(): void {
    super.resetDefaults();
    this.resetDefaultsPrintC();
  }

  initializeFromArchitecture(): void {
    this.castStrategy!.setTypeFactory(this.glb.types);
    if (this.glb.types.getSizeOfLong() === this.glb.types.getSizeOfInt())
      this.sizeSuffix = "LL";
    else
      this.sizeSuffix = "L";
  }

  adjustTypeOperators(): void {
    PrintC.scope.print1 = "::";
    PrintC.shift_right.print1 = ">>";
    // TypeOp::selectJavaOperators(glb->inst, false) -- not called for C
  }

  setCommentStyle(nm: string): void {
    if (nm === "c" || (nm.length >= 2 && nm[0] === '/' && nm[1] === '*'))
      this.setCStyleComments();
    else if (nm === "cplusplus" || (nm.length >= 2 && nm[0] === '/' && nm[1] === '/'))
      this.setCPlusPlusStyleComments();
    else
      throw new LowlevelError('Unknown comment style. Use "c" or "cplusplus"');
  }

  docTypeDefinitions(typegrp: TypeFactory): void {
    const deporder: Datatype[] = [];
    typegrp.dependentOrder(deporder);
    for (let i = 0; i < deporder.length; ++i) {
      if (deporder[i].isCoreType()) continue;
      this.emitTypeDefinition(deporder[i]);
    }
  }

  docAllGlobals(): void {
    const id: number = this.emit.beginDocument();
    this.emitGlobalVarDeclsRecursive(this.glb.symboltab.getGlobalScope());
    this.emit.tagLine();
    this.emit.endDocument(id);
    this.emit.flush();
  }

  docSingleGlobal(sym: Symbol): void {
    const id: number = this.emit.beginDocument();
    this.emitVarDeclStatement(sym);
    this.emit.tagLine();
    this.emit.endDocument(id);
    this.emit.flush();
  }

  docFunction(fd: Funcdata): void {
    const modsave: number = this.mods;
    if (!fd.isProcStarted())
      throw new LowlevelError("Function not decompiled");
    if (!this.isSet(modifiers.flat) && fd.hasNoStructBlocks())
      throw new LowlevelError("Function not fully decompiled. No structure present.");
    try {
      this.commsorter.setupFunctionList(this.instr_comment_type | this.head_comment_type, fd, fd.getArch().commentdb, this.option_unplaced);
      const id1: number = this.emit.beginFunction(fd);
      this.emitCommentFuncHeader(fd);
      this.emit.tagLine();
      this.emitFunctionDeclaration(fd);   // Causes us to enter function's scope
      const id: number = this.emit.openBraceIndent(PrintC.OPEN_CURLY, this.option_brace_func);
      this.emitLocalVarDecls(fd);
      if (this.isSet(modifiers.flat))
        this.emitBlockGraph(fd.getBasicBlocks());
      else
        this.emitBlockGraph(fd.getStructure());
      this.popScope();                   // Exit function's scope
      this.emit.closeBraceIndent(PrintC.CLOSE_CURLY, id);
      this.emit.tagLine();
      this.emit.endFunction(id1);
      this.emit.flush();
      this.mods = modsave;
    } catch (err) {
      this.clear();
      throw err;
    }
  }

  // -----------------------------------------------------------------------
  // Block emission methods
  // -----------------------------------------------------------------------

  emitBlockBasic(bb: BlockBasic): void {
    let inst: PcodeOp;
    let separator: boolean;

    this.commsorter.setupBlockList(bb);
    this.emitLabelStatement(bb);
    if (this.isSet(modifiers.only_branch)) {
      inst = bb.lastOp();
      if (inst.isBranch())
        this.emitExpression(inst);
    } else {
      separator = false;
      const enditer = bb.endOp();
      for (let cur = bb.beginOp(); !cur.equals(enditer); cur.next()) {
        inst = cur.get();
        if (inst.notPrinted()) continue;
        if (inst.isBranch()) {
          if (this.isSet(modifiers.no_branch)) continue;
          if (inst.code() === OpCode.CPUI_BRANCH) continue;
        }
        const vn: Varnode = inst.getOut();
        if (vn !== null && vn !== undefined && vn.isImplied())
          continue;
        if (separator) {
          if (this.isSet(modifiers.comma_separate)) {
            this.emit.print(PrintC.COMMA);
            this.emit.spaces(1);
          } else {
            this.emitCommentGroup(inst);
            this.emit.tagLine();
          }
        } else if (!this.isSet(modifiers.comma_separate)) {
          this.emitCommentGroup(inst);
          this.emit.tagLine();
        }
        this.emitStatement(inst);
        separator = true;
      }
      // If printing flat structure and there is no longer a normal fallthru, print a goto
      if (this.isSet(modifiers.flat) && this.isSet(modifiers.nofallthru)) {
        inst = bb.lastOp();
        this.emit.tagLine();
        const id: number = this.emit.beginStatement(inst);
        this.emit.print(PrintC.KEYWORD_GOTO, syntax_highlight.keyword_color);
        this.emit.spaces(1);
        if (bb.sizeOut() === 2) {
          if (inst.isFallthruTrue())
            this.emitLabel(bb.getOut(1));
          else
            this.emitLabel(bb.getOut(0));
        } else
          this.emitLabel(bb.getOut(0));
        this.emit.print(PrintC.SEMICOLON);
        this.emit.endStatement(id);
      }
      this.emitCommentGroup(null as any); // Any remaining comments
    }
  }

  emitBlockGraph(bl: BlockGraph): void {
    const list: FlowBlock[] = bl.getList();
    for (let i = 0; i < list.length; ++i) {
      const id: number = this.emit.beginBlock(list[i]);
      list[i].emit(this);
      this.emit.endBlock(id);
    }
  }

  emitBlockCopy(bl: BlockCopy): void {
    this.emitAnyLabelStatement(bl);
    bl.subBlock(0).emit(this);
  }

  emitBlockGoto(bl: BlockGoto): void {
    this.pushMod();
    this.setMod(modifiers.no_branch);
    bl.getBlock(0).emit(this);
    this.popMod();
    // Make sure we don't print goto if it is the next block to be printed
    if (bl.gotoPrints()) {
      this.emit.tagLine();
      this.emitGotoStatement(bl.getBlock(0), bl.getGotoTarget(), bl.getGotoType());
    }
  }

  emitBlockLs(bl: BlockList): void {
    let subbl: FlowBlock;

    if (this.isSet(modifiers.only_branch)) {
      subbl = bl.getBlock(bl.getSize() - 1);
      subbl.emit(this);
      return;
    }

    if (bl.getSize() === 0) return;
    let i = 0;
    subbl = bl.getBlock(i++);
    let id1: number = this.emit.beginBlock(subbl);
    if (i === bl.getSize()) {
      subbl.emit(this);
      this.emit.endBlock(id1);
      return;
    }
    this.pushMod();
    if (!this.isSet(modifiers.flat))
      this.setMod(modifiers.no_branch);
    if (bl.getBlock(i) !== subbl.nextInFlow()) {
      this.pushMod();
      this.setMod(modifiers.nofallthru);
      subbl.emit(this);
      this.popMod();
    } else {
      subbl.emit(this);
    }
    this.emit.endBlock(id1);

    while (i < bl.getSize() - 1) {
      subbl = bl.getBlock(i++);
      const id2: number = this.emit.beginBlock(subbl);
      if (bl.getBlock(i) !== subbl.nextInFlow()) {
        this.pushMod();
        this.setMod(modifiers.nofallthru);
        subbl.emit(this);
        this.popMod();
      } else {
        subbl.emit(this);
      }
      this.emit.endBlock(id2);
    }
    this.popMod();
    subbl = bl.getBlock(i);
    const id3: number = this.emit.beginBlock(subbl);
    subbl.emit(this);
    this.emit.endBlock(id3);
  }

  emitBlockCondition(bl: BlockCondition): void {
    if (this.isSet(modifiers.no_branch)) {
      const id: number = this.emit.beginBlock(bl.getBlock(0));
      bl.getBlock(0).emit(this);
      this.emit.endBlock(id);
      return;
    }
    if (this.isSet(modifiers.only_branch) || this.isSet(modifiers.comma_separate)) {
      const id: number = this.emit.openParen(PrintLanguage.OPEN_PAREN);
      bl.getBlock(0).emit(this);
      this.pushMod();
      this.unsetMod(modifiers.only_branch);
      this.setMod(modifiers.comma_separate);

      // Set up OpToken so it is emitted as if on the stack
      const pol = new ReversePolish();
      pol.op = null as any;
      pol.visited = 1;
      if (bl.getOpcode() === OpCode.CPUI_BOOL_AND)
        pol.tok = PrintC.boolean_and;
      else
        pol.tok = PrintC.boolean_or;
      this.emitOp(pol);

      const id2: number = this.emit.openParen(PrintLanguage.OPEN_PAREN);
      bl.getBlock(1).emit(this);
      this.emit.closeParen(PrintLanguage.CLOSE_PAREN, id2);
      this.popMod();
      this.emit.closeParen(PrintLanguage.CLOSE_PAREN, id);
    }
  }

  emitBlockIf(bl: BlockIf): void {
    let op: PcodeOp;
    const pendingBrace = new PendingBrace(this.option_brace_ifelse);

    if (this.isSet(modifiers.pending_brace))
      this.emit.setPendingPrint(pendingBrace);

    this.pushMod();
    this.unsetMod(modifiers.no_branch | modifiers.only_branch | modifiers.pending_brace);

    this.pushMod();
    this.setMod(modifiers.no_branch);
    const condBlock: FlowBlock = bl.getBlock(0);
    condBlock.emit(this);
    this.popMod();
    this.emitCommentBlockTree(condBlock);

    if (this.emit.hasPendingPrint(pendingBrace)) {
      this.emit.cancelPendingPrint();
      this.emit.spaces(1);
    } else {
      this.emit.tagLine();
    }

    op = condBlock.lastOp();
    this.emit.tagOp(PrintC.KEYWORD_IF, syntax_highlight.keyword_color, op);
    this.emit.spaces(1);
    this.pushMod();
    this.setMod(modifiers.only_branch);
    condBlock.emit(this);
    this.popMod();
    if (bl.getGotoTarget() !== null && bl.getGotoTarget() !== undefined) {
      this.emit.spaces(1);
      this.emitGotoStatement(condBlock, bl.getGotoTarget(), bl.getGotoType());
    } else {
      this.setMod(modifiers.no_branch);
      const id: number = this.emit.openBraceIndent(PrintC.OPEN_CURLY, this.option_brace_ifelse);
      const id1: number = this.emit.beginBlock(bl.getBlock(1));
      bl.getBlock(1).emit(this);
      this.emit.endBlock(id1);
      this.emit.closeBraceIndent(PrintC.CLOSE_CURLY, id);
      if (bl.getSize() === 3) {
        this.emit.tagLine();
        this.emit.print(PrintC.KEYWORD_ELSE, syntax_highlight.keyword_color);
        const elseBlock: FlowBlock = bl.getBlock(2);
        // block_type.t_if = 6 (check via FlowBlock)
        if (elseBlock.getType() === 8) { // block_type.t_if = 8
          // Attempt to merge the "else" and "if" syntax
          this.setMod(modifiers.pending_brace);
          const id2: number = this.emit.beginBlock(elseBlock);
          elseBlock.emit(this);
          this.emit.endBlock(id2);
        } else {
          const id2: number = this.emit.openBraceIndent(PrintC.OPEN_CURLY, this.option_brace_ifelse);
          const id3: number = this.emit.beginBlock(elseBlock);
          elseBlock.emit(this);
          this.emit.endBlock(id3);
          this.emit.closeBraceIndent(PrintC.CLOSE_CURLY, id2);
        }
      }
    }
    this.popMod();
    if (pendingBrace.getIndentId() >= 0) {
      this.emit.closeBraceIndent(PrintC.CLOSE_CURLY, pendingBrace.getIndentId());
    }
  }

  emitBlockWhileDo(bl: BlockWhileDo): void {
    let op: PcodeOp;
    let indent: number;

    if (bl.getIterateOp() !== null && bl.getIterateOp() !== undefined) {
      this.emitForLoop(bl);
      return;
    }
    this.pushMod();
    this.unsetMod(modifiers.no_branch | modifiers.only_branch);
    this.emitAnyLabelStatement(bl);
    const condBlock: FlowBlock = bl.getBlock(0);
    op = condBlock.lastOp();
    if (bl.hasOverflowSyntax()) {
      this.emit.tagLine();
      this.emit.tagOp(PrintC.KEYWORD_WHILE, syntax_highlight.keyword_color, op);
      const id1: number = this.emit.openParen(PrintLanguage.OPEN_PAREN);
      this.emit.spaces(1);
      this.emit.print(PrintC.KEYWORD_TRUE, syntax_highlight.const_color);
      this.emit.spaces(1);
      this.emit.closeParen(PrintLanguage.CLOSE_PAREN, id1);
      indent = this.emit.openBraceIndent(PrintC.OPEN_CURLY, this.option_brace_loop);
      this.pushMod();
      this.setMod(modifiers.no_branch);
      condBlock.emit(this);
      this.popMod();
      this.emitCommentBlockTree(condBlock);
      this.emit.tagLine();
      this.emit.tagOp(PrintC.KEYWORD_IF, syntax_highlight.keyword_color, op);
      this.emit.spaces(1);
      this.pushMod();
      this.setMod(modifiers.only_branch);
      condBlock.emit(this);
      this.popMod();
      this.emit.spaces(1);
      this.emitGotoStatement(condBlock, null as any, 2); // f_break_goto = 2
    } else {
      this.emitCommentBlockTree(condBlock);
      this.emit.tagLine();
      this.emit.tagOp(PrintC.KEYWORD_WHILE, syntax_highlight.keyword_color, op);
      this.emit.spaces(1);
      const id1: number = this.emit.openParen(PrintLanguage.OPEN_PAREN);
      this.pushMod();
      this.setMod(modifiers.comma_separate);
      condBlock.emit(this);
      this.popMod();
      this.emit.closeParen(PrintLanguage.CLOSE_PAREN, id1);
      indent = this.emit.openBraceIndent(PrintC.OPEN_CURLY, this.option_brace_loop);
    }
    this.setMod(modifiers.no_branch);
    const id2: number = this.emit.beginBlock(bl.getBlock(1));
    bl.getBlock(1).emit(this);
    this.emit.endBlock(id2);
    this.emit.closeBraceIndent(PrintC.CLOSE_CURLY, indent);
    this.popMod();
  }

  emitBlockDoWhile(bl: BlockDoWhile): void {
    let op: PcodeOp;

    this.pushMod();
    this.unsetMod(modifiers.no_branch | modifiers.only_branch);
    this.emitAnyLabelStatement(bl);
    this.emit.tagLine();
    this.emit.print(PrintC.KEYWORD_DO, syntax_highlight.keyword_color);
    const id: number = this.emit.openBraceIndent(PrintC.OPEN_CURLY, this.option_brace_loop);
    this.pushMod();
    const id2: number = this.emit.beginBlock(bl.getBlock(0));
    this.setMod(modifiers.no_branch);
    bl.getBlock(0).emit(this);
    this.emit.endBlock(id2);
    this.popMod();
    this.emit.closeBraceIndent(PrintC.CLOSE_CURLY, id);
    this.emit.spaces(1);
    op = bl.getBlock(0).lastOp();
    this.emit.tagOp(PrintC.KEYWORD_WHILE, syntax_highlight.keyword_color, op);
    this.emit.spaces(1);
    this.setMod(modifiers.only_branch);
    bl.getBlock(0).emit(this);
    this.emit.print(PrintC.SEMICOLON);
    this.popMod();
  }

  emitBlockInfLoop(bl: BlockInfLoop): void {
    let op: PcodeOp;

    this.pushMod();
    this.unsetMod(modifiers.no_branch | modifiers.only_branch);
    this.emitAnyLabelStatement(bl);
    this.emit.tagLine();
    this.emit.print(PrintC.KEYWORD_DO, syntax_highlight.keyword_color);
    const id: number = this.emit.openBraceIndent(PrintC.OPEN_CURLY, this.option_brace_loop);
    const id1: number = this.emit.beginBlock(bl.getBlock(0));
    bl.getBlock(0).emit(this);
    this.emit.endBlock(id1);
    this.emit.closeBraceIndent(PrintC.CLOSE_CURLY, id);
    this.emit.spaces(1);
    op = bl.getBlock(0).lastOp();
    this.emit.tagOp(PrintC.KEYWORD_WHILE, syntax_highlight.keyword_color, op);
    const id2: number = this.emit.openParen(PrintLanguage.OPEN_PAREN);
    this.emit.spaces(1);
    this.emit.print(PrintC.KEYWORD_TRUE, syntax_highlight.const_color);
    this.emit.spaces(1);
    this.emit.closeParen(PrintLanguage.CLOSE_PAREN, id2);
    this.emit.print(PrintC.SEMICOLON);
    this.popMod();
  }

  emitBlockSwitch(bl: BlockSwitch): void {
    let bl2: FlowBlock;

    this.pushMod();
    this.unsetMod(modifiers.no_branch | modifiers.only_branch);
    this.pushMod();
    this.setMod(modifiers.no_branch);
    bl.getSwitchBlock().emit(this);
    this.popMod();
    this.emit.tagLine();
    this.pushMod();
    this.setMod(modifiers.only_branch | modifiers.comma_separate);
    bl.getSwitchBlock().emit(this);
    this.popMod();
    this.emit.openBrace(PrintC.OPEN_CURLY, this.option_brace_switch);

    for (let i = 0; i < bl.getNumCaseBlocks(); ++i) {
      this.emitSwitchCase(i, bl);
      const id: number = this.emit.startIndent();
      if (bl.getCaseGotoType(i) !== 0) {
        this.emit.tagLine();
        this.emitGotoStatement(bl.getBlock(0), bl.getCaseBlock(i), bl.getCaseGotoType(i));
      } else {
        bl2 = bl.getCaseBlock(i);
        const id2: number = this.emit.beginBlock(bl2);
        bl2.emit(this);
        if (bl.isExit(i) && i !== bl.getNumCaseBlocks() - 1) {
          this.emit.tagLine();
          this.emitGotoStatement(bl2, null as any, 2); // f_break_goto = 2
        }
        this.emit.endBlock(id2);
      }
      this.emit.stopIndent(id);
    }
    this.emit.tagLine();
    this.emit.print(PrintC.CLOSE_CURLY);
    this.popMod();
  }

  // -----------------------------------------------------------------------
  // emitTypeDefinition (stub)
  // -----------------------------------------------------------------------

  protected emitTypeDefinition(ct: Datatype): void {
    if (ct.getMetatype() === type_metatype.TYPE_STRUCT)
      this.emitStructDefinition(ct);
    else if (ct.isEnumType())
      this.emitEnumDefinition(ct);
    else {
      this.clear();
      throw new LowlevelError("Unsupported typedef");
    }
  }
} // End class PrintC
