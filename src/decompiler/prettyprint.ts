/**
 * @file prettyprint.ts
 * @description Routines for emitting high-level (C) language syntax in a well formatted way.
 *
 * Faithful line-by-line translation of Ghidra's prettyprint.hh / prettyprint.cc.
 */

import type { int4, uintb } from '../core/types.js';
import { PRETTY_DEBUG } from '../core/types.js';
import { LowlevelError } from '../core/error.js';
import {
  AttributeId,
  ElementId,
  Encoder,
  ATTRIB_CONTENT,
  ATTRIB_ID,
  ATTRIB_NAME,
  ATTRIB_SPACE,
  type AddrSpace,
} from '../core/marshal.js';

// =========================================================================
// Forward type declarations (use type X = any for now)
// =========================================================================

export type Datatype = any;
export type Varnode = any;
export type PcodeOp = any;
export type FlowBlock = any;
export type Funcdata = any;
export type Symbol = any;
export type HighVariable = any;

// =========================================================================
// Writer interface (replaces C++ ostream)
// =========================================================================

/**
 * Writer interface replacing C++ ostream.
 */
export interface Writer {
  write(s: string): void;
}

// =========================================================================
// Marshaling attribute/element ids specific to prettyprint
// =========================================================================

export const ATTRIB_BLOCKREF = new AttributeId("blockref", 35);
export const ATTRIB_CLOSE    = new AttributeId("close", 36);
export const ATTRIB_COLOR    = new AttributeId("color", 37);
export const ATTRIB_INDENT   = new AttributeId("indent", 38);
export const ATTRIB_OFF      = new AttributeId("off", 39);
export const ATTRIB_OPEN     = new AttributeId("open", 40);
export const ATTRIB_OPREF    = new AttributeId("opref", 41);
export const ATTRIB_VARREF   = new AttributeId("varref", 42);
export const ATTRIB_SYMREF   = new AttributeId("symref", 43);

export const ELEM_BREAK          = new ElementId("break", 17);
export const ELEM_CLANG_DOCUMENT = new ElementId("clang_document", 18);
export const ELEM_FUNCNAME       = new ElementId("funcname", 19);
export const ELEM_FUNCPROTO      = new ElementId("funcproto", 20);
export const ELEM_LABEL          = new ElementId("label", 21);
export const ELEM_RETURN_TYPE    = new ElementId("return_type", 22);
export const ELEM_STATEMENT      = new ElementId("statement", 23);
export const ELEM_SYNTAX         = new ElementId("syntax", 24);
export const ELEM_VARDECL        = new ElementId("vardecl", 25);
export const ELEM_VARIABLE       = new ElementId("variable", 26);

// Additional ElementIds used in EmitMarkup that aren't in prettyprint.hh
// but are referenced in prettyprint.cc
export const ELEM_FUNCTION  = new ElementId("function", 100);
export const ELEM_BLOCK     = new ElementId("block", 101);
export const ELEM_OP        = new ElementId("op", 102);
export const ELEM_TYPE      = new ElementId("type", 103);
export const ELEM_FIELD     = new ElementId("field", 104);
export const ELEM_COMMENT   = new ElementId("comment", 105);
export const ELEM_PP_VALUE  = new ElementId("value", 106);

// =========================================================================
// syntax_highlight enum
// =========================================================================

/**
 * Possible types of syntax highlighting.
 * Values must match constants in ClangToken.
 */
export enum syntax_highlight {
  keyword_color = 0,   ///< Keyword in the high-level language
  comment_color = 1,   ///< Comments
  type_color = 2,      ///< Data-type identifiers
  funcname_color = 3,  ///< Function identifiers
  var_color = 4,       ///< Local variable identifiers
  const_color = 5,     ///< Constant values
  param_color = 6,     ///< Function parameters
  global_color = 7,    ///< Global variable identifiers
  no_color = 8,        ///< Un-highlighted
  error_color = 9,     ///< Indicates a warning or error state
  special_color = 10,  ///< A token with special/highlighted meaning
}

// =========================================================================
// brace_style enum
// =========================================================================

/**
 * Different brace formatting styles
 */
export enum brace_style {
  same_line = 0,  ///< Opening brace on the same line as if/do/while/for/switch
  next_line = 1,  ///< Opening brace is on next line
  skip_line = 2,  ///< Opening brace is two lines down
}

// =========================================================================
// printclass enum (for TokenSplit)
// =========================================================================

/**
 * An enumeration denoting the general class of a token
 */
export enum printclass {
  begin = 0,          ///< A token that starts a printing group
  end = 1,            ///< A token that ends a printing group
  tokenstring = 2,    ///< A token representing actual content
  tokenbreak = 3,     ///< White space (where line breaks can be inserted)
  begin_indent = 4,   ///< Start of a new nesting level
  end_indent = 5,     ///< End of a nesting level
  begin_comment = 6,  ///< Start of a comment block
  end_comment = 7,    ///< End of a comment block
  ignore = 8,         ///< Mark-up that doesn't affect pretty printing
}

// =========================================================================
// tag_type enum (for TokenSplit)
// =========================================================================

/**
 * The exhaustive list of possible token types
 */
export enum tag_type {
  docu_b = 0,   ///< Start of a document
  docu_e = 1,   ///< End of a document
  func_b = 2,   ///< Start of a function body
  func_e = 3,   ///< End of a function body
  bloc_b = 4,   ///< Start of a control-flow section
  bloc_e = 5,   ///< End of a control-flow section
  rtyp_b = 6,   ///< Start of a return type declaration
  rtyp_e = 7,   ///< End of a return type declaration
  vard_b = 8,   ///< Start of a variable declaration
  vard_e = 9,   ///< End of a variable declaration
  stat_b = 10,  ///< Start of a statement
  stat_e = 11,  ///< End of a statement
  prot_b = 12,  ///< Start of a function prototype
  prot_e = 13,  ///< End of a function prototype
  vari_t = 14,  ///< A variable identifier
  op_t = 15,    ///< An operator
  fnam_t = 16,  ///< A function identifier
  type_t = 17,  ///< A data-type identifier
  field_t = 18, ///< A field name for a structured data-type
  comm_t = 19,  ///< Part of a comment block
  label_t = 20, ///< A code label
  case_t = 21,  ///< A case label
  synt_t = 22,  ///< Other unspecified syntax
  opar_t = 23,  ///< Open parenthesis
  cpar_t = 24,  ///< Close parenthesis
  oinv_t = 25,  ///< Start of an arbitrary (invisible) grouping
  cinv_t = 26,  ///< End of an arbitrary (invisible) grouping
  spac_t = 27,  ///< White space
  bump_t = 28,  ///< Required line break
  line_t = 29,  ///< Required line break with one-time indent level
}

// =========================================================================
// PendPrint — callback class for pending print commands
// =========================================================================

/**
 * Helper class for sending cancelable print commands to an emitter.
 *
 * The PendPrint is issued as a placeholder for commands to the emitter using its
 * setPendingPrint() method. The callback() method is overridden to tailor the exact
 * sequence of print commands. The print commands will be executed prior to the next
 * tagLine() call to the emitter, unless the PendPrint is cancelled.
 */
export abstract class PendPrint {
  abstract callback(emit: Emit): void;
}

// =========================================================================
// Emit — abstract base class
// =========================================================================

/**
 * Interface for emitting the Decompiler's formal output: source code.
 *
 * There are two basic functions being implemented through this interface:
 *
 * Markup: allows recording of the natural grouping of the high-level tokens
 * and directly links the nodes of the abstract syntax tree to the emitted tokens.
 *
 * Pretty printing: Line breaks and additional white space characters are
 * inserted within the emitted source code to enforce a maximum number of characters
 * per line while minimizing breaks in important groups of syntax.
 */
export abstract class Emit {
  static readonly EMPTY_STRING: string = "";

  protected indentlevel: int4;       ///< Current indent level (in fixed width characters)
  protected parenlevel: int4;        ///< Current depth of parentheses
  protected indentincrement!: int4;  ///< Change in indentlevel per level of nesting (set by resetDefaultsInternal)
  protected pendPrintCb: PendPrint | null; ///< Pending print callback

  protected resetDefaultsInternal(): void {
    this.indentincrement = 2;
  }

  protected emitPending(): void {
    if (this.pendPrintCb !== null) {
      const tmp = this.pendPrintCb;
      this.pendPrintCb = null;   // Clear pending before callback
      tmp.callback(this);
    }
  }

  constructor() {
    this.indentlevel = 0;
    this.parenlevel = 0;
    this.pendPrintCb = null;
    this.resetDefaultsInternal();
  }

  // --- Abstract methods ---

  abstract beginDocument(): int4;
  abstract endDocument(id: int4): void;
  abstract beginFunction(fd: Funcdata | null): int4;
  abstract endFunction(id: int4): void;
  abstract beginBlock(bl: FlowBlock | null): int4;
  abstract endBlock(id: int4): void;

  abstract tagLine(): void;
  abstract tagLineWithIndent(indent: int4): void;

  abstract beginReturnType(vn: Varnode | null): int4;
  abstract endReturnType(id: int4): void;
  abstract beginVarDecl(sym: Symbol | null): int4;
  abstract endVarDecl(id: int4): void;
  abstract beginStatement(op: PcodeOp | null): int4;
  abstract endStatement(id: int4): void;
  abstract beginFuncProto(): int4;
  abstract endFuncProto(id: int4): void;

  abstract tagVariable(name: string, hl: syntax_highlight, vn: Varnode | null, op: PcodeOp | null): void;
  abstract tagOp(name: string, hl: syntax_highlight, op: PcodeOp | null): void;
  abstract tagFuncName(name: string, hl: syntax_highlight, fd: Funcdata | null, op: PcodeOp | null): void;
  abstract tagType(name: string, hl: syntax_highlight, ct: Datatype | null): void;
  abstract tagField(name: string, hl: syntax_highlight, ct: Datatype | null, off: int4, op: PcodeOp | null): void;
  abstract tagComment(name: string, hl: syntax_highlight, spc: AddrSpace, off: uintb): void;
  abstract tagLabel(name: string, hl: syntax_highlight, spc: AddrSpace, off: uintb): void;
  abstract tagCaseLabel(name: string, hl: syntax_highlight, op: PcodeOp | null, value: uintb): void;

  abstract print(data: string, hl?: syntax_highlight): void;
  abstract openParen(paren: string, id?: int4): int4;
  abstract closeParen(paren: string, id: int4): void;

  abstract setOutputStream(t: Writer | null): void;
  abstract getOutputStream(): Writer | null;
  abstract emitsMarkup(): boolean;

  // --- Virtual methods with default implementations ---

  openGroup(): int4 { return 0; }
  closeGroup(_id: int4): void {}

  clear(): void {
    this.parenlevel = 0;
    this.indentlevel = 0;
    this.pendPrintCb = null;
  }

  setMarkup(_val: boolean): void {}
  setPackedOutput(_val: boolean): void {}

  spaces(num: int4, bump: int4 = 0): void {
    const spacearray = ["", " ", "  ", "   ", "    ", "     ", "      ", "       ",
      "        ", "         ", "          "];
    if (num <= 10) {
      this.print(spacearray[num]);
    } else {
      let spc = "";
      for (let i = 0; i < num; ++i)
        spc += ' ';
      this.print(spc);
    }
  }

  startIndent(): int4 { this.indentlevel += this.indentincrement; return 0; }
  stopIndent(_id: int4): void { this.indentlevel -= this.indentincrement; }

  startComment(): int4 { return 0; }
  stopComment(_id: int4): void {}

  flush(): void {}
  setMaxLineSize(_mls: int4): void {}
  getMaxLineSize(): int4 { return -1; }
  setCommentFill(_fill: string): void {}

  resetDefaults(): void { this.resetDefaultsInternal(); }

  getParenLevel(): int4 { return this.parenlevel; }
  getIndentIncrement(): int4 { return this.indentincrement; }
  setIndentIncrement(val: int4): void { this.indentincrement = val; }

  setPendingPrint(pend: PendPrint): void { this.pendPrintCb = pend; }
  cancelPendingPrint(): void { this.pendPrintCb = null; }
  hasPendingPrint(pend: PendPrint): boolean { return (this.pendPrintCb === pend); }

  /**
   * Emit an opening brace given a specific format and add an indent level.
   */
  openBraceIndent(brace: string, style: brace_style): int4 {
    if (style === brace_style.same_line) {
      this.spaces(1);
    } else if (style === brace_style.skip_line) {
      this.tagLine();
      this.tagLine();
    } else {
      this.tagLine();
    }
    const id = this.startIndent();
    this.print(brace);
    return id;
  }

  /**
   * Emit an opening brace given a specific format.
   * The indent level is not increased.
   */
  openBrace(brace: string, style: brace_style): void {
    if (style === brace_style.same_line) {
      this.spaces(1);
    } else if (style === brace_style.skip_line) {
      this.tagLine();
      this.tagLine();
    } else {
      this.tagLine();
    }
    this.print(brace);
  }

  /**
   * Emit a closing brace and remove an indent level.
   */
  closeBraceIndent(brace: string, id: int4): void {
    this.stopIndent(id);
    this.tagLine();
    this.print(brace);
  }
}

// =========================================================================
// EmitMarkup — emitter that associates markup with individual tokens
// =========================================================================

/**
 * Emitter that associates markup with individual tokens.
 *
 * Variable and operation tokens are associated with their corresponding Varnode or PcodeOp object in
 * the data-flow graph of the decompiled function.
 */
export class EmitMarkup extends Emit {
  protected s: Writer | null;
  protected encoder: Encoder | null;

  constructor() {
    super();
    this.s = null;
    this.encoder = null;
  }

  beginDocument(): int4 {
    this.encoder!.openElement(ELEM_CLANG_DOCUMENT);
    return 0;
  }

  endDocument(_id: int4): void {
    this.encoder!.closeElement(ELEM_CLANG_DOCUMENT);
  }

  beginFunction(_fd: Funcdata | null): int4 {
    this.encoder!.openElement(ELEM_FUNCTION);
    return 0;
  }

  endFunction(_id: int4): void {
    this.encoder!.closeElement(ELEM_FUNCTION);
  }

  beginBlock(bl: FlowBlock | null): int4 {
    this.encoder!.openElement(ELEM_BLOCK);
    this.encoder!.writeSignedInteger(ATTRIB_BLOCKREF, bl!.getIndex());
    return 0;
  }

  endBlock(_id: int4): void {
    this.encoder!.closeElement(ELEM_BLOCK);
  }

  tagLine(): void {
    this.emitPending();
    this.encoder!.openElement(ELEM_BREAK);
    this.encoder!.writeSignedInteger(ATTRIB_INDENT, this.indentlevel);
    this.encoder!.closeElement(ELEM_BREAK);
  }

  tagLineWithIndent(indent: int4): void {
    this.emitPending();
    this.encoder!.openElement(ELEM_BREAK);
    this.encoder!.writeSignedInteger(ATTRIB_INDENT, indent);
    this.encoder!.closeElement(ELEM_BREAK);
  }

  beginReturnType(vn: Varnode | null): int4 {
    this.encoder!.openElement(ELEM_RETURN_TYPE);
    if (vn !== null)
      this.encoder!.writeUnsignedInteger(ATTRIB_VARREF, BigInt(vn.getCreateIndex()));
    return 0;
  }

  endReturnType(_id: int4): void {
    this.encoder!.closeElement(ELEM_RETURN_TYPE);
  }

  beginVarDecl(sym: Symbol | null): int4 {
    this.encoder!.openElement(ELEM_VARDECL);
    this.encoder!.writeUnsignedInteger(ATTRIB_SYMREF, BigInt(sym!.getId()));
    return 0;
  }

  endVarDecl(_id: int4): void {
    this.encoder!.closeElement(ELEM_VARDECL);
  }

  beginStatement(op: PcodeOp | null): int4 {
    this.encoder!.openElement(ELEM_STATEMENT);
    if (op !== null)
      this.encoder!.writeUnsignedInteger(ATTRIB_OPREF, BigInt(op.getTime()));
    return 0;
  }

  endStatement(_id: int4): void {
    this.encoder!.closeElement(ELEM_STATEMENT);
  }

  beginFuncProto(): int4 {
    this.encoder!.openElement(ELEM_FUNCPROTO);
    return 0;
  }

  endFuncProto(_id: int4): void {
    this.encoder!.closeElement(ELEM_FUNCPROTO);
  }

  tagVariable(name: string, hl: syntax_highlight, vn: Varnode | null, op: PcodeOp | null): void {
    this.encoder!.openElement(ELEM_VARIABLE);
    if (hl !== syntax_highlight.no_color)
      this.encoder!.writeUnsignedInteger(ATTRIB_COLOR, BigInt(hl));
    if (vn !== null)
      this.encoder!.writeUnsignedInteger(ATTRIB_VARREF, BigInt(vn.getCreateIndex()));
    if (op !== null)
      this.encoder!.writeUnsignedInteger(ATTRIB_OPREF, BigInt(op.getTime()));
    this.encoder!.writeString(ATTRIB_CONTENT, name);
    this.encoder!.closeElement(ELEM_VARIABLE);
  }

  tagOp(name: string, hl: syntax_highlight, op: PcodeOp | null): void {
    this.encoder!.openElement(ELEM_OP);
    if (hl !== syntax_highlight.no_color)
      this.encoder!.writeUnsignedInteger(ATTRIB_COLOR, BigInt(hl));
    if (op !== null)
      this.encoder!.writeUnsignedInteger(ATTRIB_OPREF, BigInt(op.getTime()));
    this.encoder!.writeString(ATTRIB_CONTENT, name);
    this.encoder!.closeElement(ELEM_OP);
  }

  tagFuncName(name: string, hl: syntax_highlight, _fd: Funcdata | null, op: PcodeOp | null): void {
    this.encoder!.openElement(ELEM_FUNCNAME);
    if (hl !== syntax_highlight.no_color)
      this.encoder!.writeUnsignedInteger(ATTRIB_COLOR, BigInt(hl));
    if (op !== null)
      this.encoder!.writeUnsignedInteger(ATTRIB_OPREF, BigInt(op.getTime()));
    this.encoder!.writeString(ATTRIB_CONTENT, name);
    this.encoder!.closeElement(ELEM_FUNCNAME);
  }

  tagType(name: string, hl: syntax_highlight, ct: Datatype | null): void {
    this.encoder!.openElement(ELEM_TYPE);
    if (hl !== syntax_highlight.no_color)
      this.encoder!.writeUnsignedInteger(ATTRIB_COLOR, BigInt(hl));
    const typeId: bigint = ct!.getUnsizedId();
    if (typeId !== 0n) {
      this.encoder!.writeUnsignedInteger(ATTRIB_ID, typeId);
    }
    this.encoder!.writeString(ATTRIB_CONTENT, name);
    this.encoder!.closeElement(ELEM_TYPE);
  }

  tagField(name: string, hl: syntax_highlight, ct: Datatype | null, o: int4, op: PcodeOp | null): void {
    this.encoder!.openElement(ELEM_FIELD);
    if (hl !== syntax_highlight.no_color)
      this.encoder!.writeUnsignedInteger(ATTRIB_COLOR, BigInt(hl));
    if (ct !== null) {
      this.encoder!.writeString(ATTRIB_NAME, ct.getName());
      const typeId: bigint = ct.getUnsizedId();
      if (typeId !== 0n) {
        this.encoder!.writeUnsignedInteger(ATTRIB_ID, typeId);
      }
      this.encoder!.writeSignedInteger(ATTRIB_OFF, o);
      if (op !== null)
        this.encoder!.writeUnsignedInteger(ATTRIB_OPREF, BigInt(op.getTime()));
    }
    this.encoder!.writeString(ATTRIB_CONTENT, name);
    this.encoder!.closeElement(ELEM_FIELD);
  }

  tagComment(name: string, hl: syntax_highlight, spc: AddrSpace, off: uintb): void {
    this.encoder!.openElement(ELEM_COMMENT);
    if (hl !== syntax_highlight.no_color)
      this.encoder!.writeUnsignedInteger(ATTRIB_COLOR, BigInt(hl));
    this.encoder!.writeSpace(ATTRIB_SPACE, spc);
    this.encoder!.writeUnsignedInteger(ATTRIB_OFF, off);
    this.encoder!.writeString(ATTRIB_CONTENT, name);
    this.encoder!.closeElement(ELEM_COMMENT);
  }

  tagLabel(name: string, hl: syntax_highlight, spc: AddrSpace, off: uintb): void {
    this.encoder!.openElement(ELEM_LABEL);
    if (hl !== syntax_highlight.no_color)
      this.encoder!.writeUnsignedInteger(ATTRIB_COLOR, BigInt(hl));
    this.encoder!.writeSpace(ATTRIB_SPACE, spc);
    this.encoder!.writeUnsignedInteger(ATTRIB_OFF, off);
    this.encoder!.writeString(ATTRIB_CONTENT, name);
    this.encoder!.closeElement(ELEM_LABEL);
  }

  tagCaseLabel(name: string, hl: syntax_highlight, op: PcodeOp | null, value: uintb): void {
    this.encoder!.openElement(ELEM_PP_VALUE);
    if (hl !== syntax_highlight.no_color)
      this.encoder!.writeUnsignedInteger(ATTRIB_COLOR, BigInt(hl));
    this.encoder!.writeUnsignedInteger(ATTRIB_OFF, value);
    if (op !== null)
      this.encoder!.writeUnsignedInteger(ATTRIB_OPREF, BigInt(op.getTime()));
    this.encoder!.writeString(ATTRIB_CONTENT, name);
    this.encoder!.closeElement(ELEM_PP_VALUE);
  }

  print(data: string, hl: syntax_highlight = syntax_highlight.no_color): void {
    this.encoder!.openElement(ELEM_SYNTAX);
    if (hl !== syntax_highlight.no_color)
      this.encoder!.writeUnsignedInteger(ATTRIB_COLOR, BigInt(hl));
    this.encoder!.writeString(ATTRIB_CONTENT, data);
    this.encoder!.closeElement(ELEM_SYNTAX);
  }

  openParen(paren: string, id: int4 = 0): int4 {
    this.encoder!.openElement(ELEM_SYNTAX);
    this.encoder!.writeSignedInteger(ATTRIB_OPEN, id);
    this.encoder!.writeString(ATTRIB_CONTENT, paren);
    this.encoder!.closeElement(ELEM_SYNTAX);
    this.parenlevel += 1;
    return 0;
  }

  closeParen(paren: string, id: int4): void {
    this.encoder!.openElement(ELEM_SYNTAX);
    this.encoder!.writeSignedInteger(ATTRIB_CLOSE, id);
    this.encoder!.writeString(ATTRIB_CONTENT, paren);
    this.encoder!.closeElement(ELEM_SYNTAX);
    this.parenlevel -= 1;
  }

  setOutputStream(t: Writer | null): void {
    this.s = t;
    if (t !== null) {
      // By default create a PackedEncode; we can't import it directly without
      // circular deps, so we use the encoder factory pattern here.
      // For now, encoder must be set separately or via setPackedOutput/setMarkup.
      // The C++ code does: encoder = new PackedEncode(*s);
      // We leave encoder as-is since the caller is expected to set it.
    }
  }

  getOutputStream(): Writer | null { return this.s; }

  setEncoder(enc: Encoder): void {
    this.encoder = enc;
  }

  getEncoder(): Encoder | null {
    return this.encoder;
  }

  setPackedOutput(_val: boolean): void {
    // In the C++ code this switches between PackedEncode and XmlEncode.
    // The caller should set the encoder directly via setEncoder().
  }

  emitsMarkup(): boolean { return true; }
}

// =========================================================================
// EmitNoMarkup — trivial emitter with no markup
// =========================================================================

/**
 * A trivial emitter that outputs syntax straight to the stream.
 *
 * This emitter does neither pretty printing nor markup. It dumps any tokens
 * straight to the final output stream. It can be used as the low-level back-end
 * for EmitPrettyPrint.
 */
export class EmitNoMarkup extends Emit {
  private s: Writer | null;

  constructor() {
    super();
    this.s = null;
  }

  beginDocument(): int4 { return 0; }
  endDocument(_id: int4): void {}
  beginFunction(_fd: Funcdata | null): int4 { return 0; }
  endFunction(_id: int4): void {}
  beginBlock(_bl: FlowBlock | null): int4 { return 0; }
  endBlock(_id: int4): void {}

  tagLine(): void {
    this.s!.write("\n");
    for (let i = this.indentlevel; i > 0; --i) this.s!.write(" ");
  }

  tagLineWithIndent(indent: int4): void {
    this.s!.write("\n");
    for (let i = indent; i > 0; --i) this.s!.write(" ");
  }

  beginReturnType(_vn: Varnode | null): int4 { return 0; }
  endReturnType(_id: int4): void {}
  beginVarDecl(_sym: Symbol | null): int4 { return 0; }
  endVarDecl(_id: int4): void {}
  beginStatement(_op: PcodeOp | null): int4 { return 0; }
  endStatement(_id: int4): void {}
  beginFuncProto(): int4 { return 0; }
  endFuncProto(_id: int4): void {}

  tagVariable(name: string, _hl: syntax_highlight, _vn: Varnode | null, _op: PcodeOp | null): void {
    this.s!.write(name);
  }

  tagOp(name: string, _hl: syntax_highlight, _op: PcodeOp | null): void {
    this.s!.write(name);
  }

  tagFuncName(name: string, _hl: syntax_highlight, _fd: Funcdata | null, _op: PcodeOp | null): void {
    this.s!.write(name);
  }

  tagType(name: string, _hl: syntax_highlight, _ct: Datatype | null): void {
    this.s!.write(name);
  }

  tagField(name: string, _hl: syntax_highlight, _ct: Datatype | null, _off: int4, _op: PcodeOp | null): void {
    this.s!.write(name);
  }

  tagComment(name: string, _hl: syntax_highlight, _spc: AddrSpace, _off: uintb): void {
    this.s!.write(name);
  }

  tagLabel(name: string, _hl: syntax_highlight, _spc: AddrSpace, _off: uintb): void {
    this.s!.write(name);
  }

  tagCaseLabel(name: string, _hl: syntax_highlight, _op: PcodeOp | null, _value: uintb): void {
    this.s!.write(name);
  }

  print(data: string, _hl: syntax_highlight = syntax_highlight.no_color): void {
    this.s!.write(data);
  }

  openParen(paren: string, id: int4 = 0): int4 {
    this.s!.write(paren);
    this.parenlevel += 1;
    return id;
  }

  closeParen(paren: string, _id: int4): void {
    this.s!.write(paren);
    this.parenlevel -= 1;
  }

  setOutputStream(t: Writer | null): void { this.s = t; }
  getOutputStream(): Writer | null { return this.s; }
  emitsMarkup(): boolean { return false; }
}

// =========================================================================
// TokenSplit — token/command object in the pretty printing stream
// =========================================================================

/**
 * A token/command object in the pretty printing stream.
 *
 * The pretty printing algorithm (see EmitPrettyPrint) works on the stream of
 * tokens, constituting the content actually being output, plus additional
 * embedded commands made up begin/end or open/close pairs that delimit the
 * (hierarchy of) groups of tokens that should be printed as a unit.
 */
export class TokenSplit {
  private tagtype: tag_type = tag_type.docu_b;
  private delimtype: printclass = printclass.begin;
  private tok: string = "";
  private hl: syntax_highlight = syntax_highlight.no_color;

  // Additional markup elements for token
  private op: PcodeOp | null = null;

  // Union-like fields (ptr_second in C++)
  private ptr_second_vn: Varnode | null = null;
  private ptr_second_bl: FlowBlock | null = null;
  private ptr_second_fd: Funcdata | null = null;
  private ptr_second_ct: Datatype | null = null;
  private ptr_second_spc: AddrSpace | null = null;
  private ptr_second_symbol: Symbol | null = null;

  private off: uintb = 0n;
  private indentbump: int4 = 0;
  private numspaces: int4 = 0;
  private _size: int4 = 0;
  private count: int4 = 0;

  private static countbase: int4 = 0;

  constructor() {}

  // -- begin/end commands --

  beginDocument(): int4 {
    this.tagtype = tag_type.docu_b;
    this.delimtype = printclass.begin;
    this._size = 0;
    this.count = TokenSplit.countbase++;
    return this.count;
  }

  endDocument(id: int4): void {
    this.tagtype = tag_type.docu_e;
    this.delimtype = printclass.end;
    this._size = 0;
    this.count = id;
  }

  beginFunction(f: Funcdata | null): int4 {
    this.tagtype = tag_type.func_b;
    this.delimtype = printclass.begin;
    this._size = 0;
    this.ptr_second_fd = f;
    this.count = TokenSplit.countbase++;
    return this.count;
  }

  endFunction(id: int4): void {
    this.tagtype = tag_type.func_e;
    this.delimtype = printclass.end;
    this._size = 0;
    this.count = id;
  }

  beginBlock(b: FlowBlock | null): int4 {
    this.tagtype = tag_type.bloc_b;
    this.delimtype = printclass.ignore;
    this.ptr_second_bl = b;
    this.count = TokenSplit.countbase++;
    return this.count;
  }

  endBlock(id: int4): void {
    this.tagtype = tag_type.bloc_e;
    this.delimtype = printclass.ignore;
    this.count = id;
  }

  beginReturnType(v: Varnode | null): int4 {
    this.tagtype = tag_type.rtyp_b;
    this.delimtype = printclass.begin;
    this.ptr_second_vn = v;
    this.count = TokenSplit.countbase++;
    return this.count;
  }

  endReturnType(id: int4): void {
    this.tagtype = tag_type.rtyp_e;
    this.delimtype = printclass.end;
    this.count = id;
  }

  beginVarDecl(sym: Symbol | null): int4 {
    this.tagtype = tag_type.vard_b;
    this.delimtype = printclass.begin;
    this.ptr_second_symbol = sym;
    this.count = TokenSplit.countbase++;
    return this.count;
  }

  endVarDecl(id: int4): void {
    this.tagtype = tag_type.vard_e;
    this.delimtype = printclass.end;
    this.count = id;
  }

  beginStatement(o: PcodeOp | null): int4 {
    this.tagtype = tag_type.stat_b;
    this.delimtype = printclass.begin;
    this.op = o;
    this.count = TokenSplit.countbase++;
    return this.count;
  }

  endStatement(id: int4): void {
    this.tagtype = tag_type.stat_e;
    this.delimtype = printclass.end;
    this.count = id;
  }

  beginFuncProto(): int4 {
    this.tagtype = tag_type.prot_b;
    this.delimtype = printclass.begin;
    this.count = TokenSplit.countbase++;
    return this.count;
  }

  endFuncProto(id: int4): void {
    this.tagtype = tag_type.prot_e;
    this.delimtype = printclass.end;
    this.count = id;
  }

  // -- tag tokens --

  tagVariable(name: string, h: syntax_highlight, v: Varnode | null, o: PcodeOp | null): void {
    this.tok = name;
    this._size = this.tok.length;
    this.tagtype = tag_type.vari_t;
    this.delimtype = printclass.tokenstring;
    this.hl = h;
    this.ptr_second_vn = v;
    this.op = o;
  }

  tagOp(name: string, h: syntax_highlight, o: PcodeOp | null): void {
    this.tok = name;
    this._size = this.tok.length;
    this.tagtype = tag_type.op_t;
    this.delimtype = printclass.tokenstring;
    this.hl = h;
    this.op = o;
  }

  tagFuncName(name: string, h: syntax_highlight, f: Funcdata | null, o: PcodeOp | null): void {
    this.tok = name;
    this._size = this.tok.length;
    this.tagtype = tag_type.fnam_t;
    this.delimtype = printclass.tokenstring;
    this.hl = h;
    this.ptr_second_fd = f;
    this.op = o;
  }

  tagType(name: string, h: syntax_highlight, ct: Datatype | null): void {
    this.tok = name;
    this._size = this.tok.length;
    this.tagtype = tag_type.type_t;
    this.delimtype = printclass.tokenstring;
    this.hl = h;
    this.ptr_second_ct = ct;
  }

  tagField(name: string, h: syntax_highlight, ct: Datatype | null, o: int4, inOp: PcodeOp | null): void {
    this.tok = name;
    this._size = this.tok.length;
    this.tagtype = tag_type.field_t;
    this.delimtype = printclass.tokenstring;
    this.hl = h;
    this.ptr_second_ct = ct;
    this.off = BigInt(o);
    this.op = inOp;
  }

  tagComment(name: string, h: syntax_highlight, s: AddrSpace, o: uintb): void {
    this.tok = name;
    this._size = this.tok.length;
    this.ptr_second_spc = s;
    this.off = o;
    this.tagtype = tag_type.comm_t;
    this.delimtype = printclass.tokenstring;
    this.hl = h;
  }

  tagLabel(name: string, h: syntax_highlight, s: AddrSpace, o: uintb): void {
    this.tok = name;
    this._size = this.tok.length;
    this.ptr_second_spc = s;
    this.off = o;
    this.tagtype = tag_type.label_t;
    this.delimtype = printclass.tokenstring;
    this.hl = h;
  }

  tagCaseLabel(name: string, h: syntax_highlight, inOp: PcodeOp | null, intValue: uintb): void {
    this.tok = name;
    this._size = this.tok.length;
    this.op = inOp;
    this.off = intValue;
    this.tagtype = tag_type.case_t;
    this.delimtype = printclass.tokenstring;
    this.hl = h;
  }

  printToken(data: string, h: syntax_highlight): void {
    this.tok = data;
    this._size = this.tok.length;
    this.tagtype = tag_type.synt_t;
    this.delimtype = printclass.tokenstring;
    this.hl = h;
  }

  openParen(paren: string, id: int4): void {
    this.tok = paren;
    this._size = 1;
    this.tagtype = tag_type.opar_t;
    this.delimtype = printclass.tokenstring;
    this.count = id;
  }

  closeParen(paren: string, id: int4): void {
    this.tok = paren;
    this._size = 1;
    this.tagtype = tag_type.cpar_t;
    this.delimtype = printclass.tokenstring;
    this.count = id;
  }

  openGroup(): int4 {
    this.tagtype = tag_type.oinv_t;
    this.delimtype = printclass.begin;
    this.count = TokenSplit.countbase++;
    return this.count;
  }

  closeGroup(id: int4): void {
    this.tagtype = tag_type.cinv_t;
    this.delimtype = printclass.end;
    this.count = id;
  }

  startIndent(bump: int4): int4 {
    this.tagtype = tag_type.bump_t;
    this.delimtype = printclass.begin_indent;
    this.indentbump = bump;
    this._size = 0;
    this.count = TokenSplit.countbase++;
    return this.count;
  }

  stopIndent(id: int4): void {
    this.tagtype = tag_type.bump_t;
    this.delimtype = printclass.end_indent;
    this._size = 0;
    this.count = id;
  }

  startComment(): int4 {
    this.tagtype = tag_type.oinv_t;
    this.delimtype = printclass.begin_comment;
    this.count = TokenSplit.countbase++;
    return this.count;
  }

  stopComment(id: int4): void {
    this.tagtype = tag_type.cinv_t;
    this.delimtype = printclass.end_comment;
    this.count = id;
  }

  spaces(num: int4, bump: int4): void {
    this.tagtype = tag_type.spac_t;
    this.delimtype = printclass.tokenbreak;
    this.numspaces = num;
    this.indentbump = bump;
  }

  tagLine(): void {
    this.tagtype = tag_type.bump_t;
    this.delimtype = printclass.tokenbreak;
    this.numspaces = 999999;
    this.indentbump = 0;
  }

  tagLineWithIndent(indent: int4): void {
    this.tagtype = tag_type.line_t;
    this.delimtype = printclass.tokenbreak;
    this.numspaces = 999999;
    this.indentbump = indent;
  }

  /**
   * Send this token to emitter.
   */
  printToEmit(emit: Emit): void {
    switch (this.tagtype) {
      case tag_type.docu_b:  // beginDocument
        emit.beginDocument();
        break;
      case tag_type.docu_e:  // endDocument
        emit.endDocument(this.count);
        break;
      case tag_type.func_b:  // beginFunction
        emit.beginFunction(this.ptr_second_fd);
        break;
      case tag_type.func_e:  // endFunction
        emit.endFunction(this.count);
        break;
      case tag_type.bloc_b:  // beginBlock
        emit.beginBlock(this.ptr_second_bl);
        break;
      case tag_type.bloc_e:  // endBlock
        emit.endBlock(this.count);
        break;
      case tag_type.rtyp_b:  // beginReturnType
        emit.beginReturnType(this.ptr_second_vn);
        break;
      case tag_type.rtyp_e:  // endReturnType
        emit.endReturnType(this.count);
        break;
      case tag_type.vard_b:  // beginVarDecl
        emit.beginVarDecl(this.ptr_second_symbol);
        break;
      case tag_type.vard_e:  // endVarDecl
        emit.endVarDecl(this.count);
        break;
      case tag_type.stat_b:  // beginStatement
        emit.beginStatement(this.op);
        break;
      case tag_type.stat_e:  // endStatement
        emit.endStatement(this.count);
        break;
      case tag_type.prot_b:  // beginFuncProto
        emit.beginFuncProto();
        break;
      case tag_type.prot_e:  // endFuncProto
        emit.endFuncProto(this.count);
        break;
      case tag_type.vari_t:  // tagVariable
        emit.tagVariable(this.tok, this.hl, this.ptr_second_vn, this.op);
        break;
      case tag_type.op_t:    // tagOp
        emit.tagOp(this.tok, this.hl, this.op);
        break;
      case tag_type.fnam_t:  // tagFuncName
        emit.tagFuncName(this.tok, this.hl, this.ptr_second_fd, this.op);
        break;
      case tag_type.type_t:  // tagType
        emit.tagType(this.tok, this.hl, this.ptr_second_ct);
        break;
      case tag_type.field_t: // tagField
        emit.tagField(this.tok, this.hl, this.ptr_second_ct, Number(this.off), this.op);
        break;
      case tag_type.comm_t:  // tagComment
        emit.tagComment(this.tok, this.hl, this.ptr_second_spc!, this.off);
        break;
      case tag_type.label_t: // tagLabel
        emit.tagLabel(this.tok, this.hl, this.ptr_second_spc!, this.off);
        break;
      case tag_type.case_t:  // tagCaseLabel
        emit.tagCaseLabel(this.tok, this.hl, this.op, this.off);
        break;
      case tag_type.synt_t:  // print
        emit.print(this.tok, this.hl);
        break;
      case tag_type.opar_t:  // openParen
        emit.openParen(this.tok, this.count);
        break;
      case tag_type.cpar_t:  // closeParen
        emit.closeParen(this.tok, this.count);
        break;
      case tag_type.oinv_t:  // Invisible open
        break;
      case tag_type.cinv_t:  // Invisible close
        break;
      case tag_type.spac_t:  // Spaces
        emit.spaces(this.numspaces);
        break;
      case tag_type.line_t:  // tagLine
      case tag_type.bump_t:
        throw new LowlevelError("Should never get called");
    }
  }

  getIndentBump(): int4 { return this.indentbump; }
  getNumSpaces(): int4 { return this.numspaces; }
  getSize(): int4 { return this._size; }
  setSize(sz: int4): void { this._size = sz; }
  getClass(): printclass { return this.delimtype; }
  getTag(): tag_type { return this.tagtype; }

  // Debug support
  getCount(): int4 { return this.count; }

  printDebug(): string {
    const names: Record<tag_type, string> = {
      [tag_type.docu_b]: "docu_b",
      [tag_type.docu_e]: "docu_e",
      [tag_type.func_b]: "func_b",
      [tag_type.func_e]: "func_e",
      [tag_type.bloc_b]: "bloc_b",
      [tag_type.bloc_e]: "bloc_e",
      [tag_type.rtyp_b]: "rtyp_b",
      [tag_type.rtyp_e]: "rtyp_e",
      [tag_type.vard_b]: "vard_b",
      [tag_type.vard_e]: "vard_e",
      [tag_type.stat_b]: "stat_b",
      [tag_type.stat_e]: "stat_e",
      [tag_type.prot_b]: "prot_b",
      [tag_type.prot_e]: "prot_e",
      [tag_type.vari_t]: "vari_t",
      [tag_type.op_t]: "op_t",
      [tag_type.fnam_t]: "fnam_t",
      [tag_type.type_t]: "type_t",
      [tag_type.field_t]: "field_t",
      [tag_type.comm_t]: "comm_t",
      [tag_type.label_t]: "label_t",
      [tag_type.case_t]: "case_t",
      [tag_type.synt_t]: "synt_t",
      [tag_type.opar_t]: "opar_t",
      [tag_type.cpar_t]: "cpar_t",
      [tag_type.oinv_t]: "oinv_t",
      [tag_type.cinv_t]: "cinv_t",
      [tag_type.spac_t]: "spac_t",
      [tag_type.line_t]: "line_t",
      [tag_type.bump_t]: "bump_t",
    };
    return names[this.tagtype] || "unknown";
  }
}

// =========================================================================
// circularqueue<T> — generic circular buffer
// =========================================================================

/**
 * A circular buffer template.
 *
 * A circular buffer implementation that can act as a stack: push(), pop().
 * Or it can act as a queue: push(), popbottom(). The size of the buffer can be expanded
 * on the fly using expand(). Objects can also be looked up via an integer reference.
 */
export class circularqueue<T> {
  private cache: T[];
  private left: int4;
  private right: int4;
  private max: int4;
  private factory: () => T;

  /**
   * Construct queue of a given size.
   * @param sz maximum number of objects the queue will hold
   * @param factory function to create default instances of T
   */
  constructor(sz: int4, factory: () => T) {
    this.max = sz;
    this.left = 1;
    this.right = 0;
    this.factory = factory;
    this.cache = new Array<T>(sz);
    for (let i = 0; i < sz; i++) {
      this.cache[i] = factory();
    }
  }

  /**
   * Establish a new maximum queue size.
   * This destroys the old queue and reallocates.
   */
  setMax(sz: int4): void {
    if (this.max !== sz) {
      this.max = sz;
      this.cache = new Array<T>(sz);
      for (let i = 0; i < sz; i++) {
        this.cache[i] = this.factory();
      }
    }
    this.left = 1;   // This operation empties queue
    this.right = 0;
  }

  /** Get the maximum queue size */
  getMax(): int4 { return this.max; }

  /**
   * Expand the (maximum) size of the queue.
   * Objects currently in the queue are preserved. This routine invalidates
   * references referring to objects currently in the queue, although the references
   * can be systematically adjusted to be valid again.
   */
  expand(amount: int4): void {
    const newcache = new Array<T>(this.max + amount);
    for (let k = 0; k < this.max + amount; k++) {
      newcache[k] = this.factory();
    }

    let i = this.left;
    let j = 0;

    // Assume there is at least one element in queue
    while (i !== this.right) {
      newcache[j++] = this.cache[i];
      i = (i + 1) % this.max;
    }
    newcache[j] = this.cache[i]; // Copy rightmost

    this.left = 0;
    this.right = j;

    this.cache = newcache;
    this.max += amount;
  }

  /** Clear the queue */
  clear(): void { this.left = 1; this.right = 0; }

  /** Is the queue empty */
  empty(): boolean { return (this.left === (this.right + 1) % this.max); }

  /** Get a reference to the last object on the queue/stack */
  topref(): int4 { return this.right; }

  /** Get a reference to the first object on the queue/stack */
  bottomref(): int4 { return this.left; }

  /** Retrieve an object by its reference */
  ref(r: int4): T { return this.cache[r]; }

  /** Set an object by its reference */
  setRef(r: int4, val: T): void { this.cache[r] = val; }

  /** Get the last object on the queue/stack */
  top(): T { return this.cache[this.right]; }

  /** Get the first object on the queue/stack */
  bottom(): T { return this.cache[this.left]; }

  /** Push a new object onto the queue/stack, return it */
  push(): T {
    this.right = (this.right + 1) % this.max;
    return this.cache[this.right];
  }

  /** Pop the (last) object on the stack, return it */
  pop(): T {
    const tmp = this.right;
    this.right = (this.right + this.max - 1) % this.max;
    return this.cache[tmp];
  }

  /** Get the (next) object in the queue (pop from bottom) */
  popbottom(): T {
    const tmp = this.left;
    this.left = (this.left + 1) % this.max;
    return this.cache[tmp];
  }
}

// =========================================================================
// EmitPrettyPrint — Oppen's pretty printing algorithm
// =========================================================================

/**
 * A generic source code pretty printer.
 *
 * This pretty printer is based on the standard Derek C. Oppen pretty printing
 * algorithm. It allows configurable indenting, spacing, and line breaks that enhances
 * the readability of the high-level language output.
 */
export class EmitPrettyPrint extends Emit {
  private checkid: int4[] = [];  // Debug only
  private lowlevel: Emit;
  private indentstack: int4[];
  private spaceremain: int4;
  private maxlinesize: int4;
  private leftotal: int4;
  private rightotal: int4;
  private needbreak: boolean;
  private commentmode: boolean;
  private commentfill: string;
  private scanqueue: circularqueue<int4>;
  private tokqueue: circularqueue<TokenSplit>;

  constructor() {
    super();
    this.scanqueue = new circularqueue<int4>(3 * 100, () => 0);
    this.tokqueue = new circularqueue<TokenSplit>(3 * 100, () => new TokenSplit());
    this.lowlevel = new EmitNoMarkup(); // Do not emit xml by default
    this.indentstack = [];
    this.maxlinesize = 0;
    this.spaceremain = 0;
    this.leftotal = 0;
    this.rightotal = 0;
    this.needbreak = false;
    this.commentmode = false;
    this.commentfill = "";
    this.resetDefaultsPrettyPrint();
    this.spaceremain = this.maxlinesize;
  }

  private resetDefaultsPrettyPrint(): void {
    this.setMaxLineSize(100);
  }

  /**
   * Expand the stream buffer.
   * Increase the number of tokens that can be in the queue simultaneously.
   */
  private expand(): void {
    const max = this.tokqueue.getMax();
    const left = this.tokqueue.bottomref();
    this.tokqueue.expand(200);
    // Expanding puts the leftmost element at reference 0
    // So we need to adjust references
    for (let i = 0; i < max; ++i) {
      const oldVal = this.scanqueue.ref(i);
      this.scanqueue.setRef(i, (oldVal + max - left) % max);
    }
    // The number of elements in scanqueue is always less than
    // or equal to the number of elements in tokqueue, so
    // if we keep scanqueue and tokqueue with the same max
    // we don't need to check for scanqueue overflow
    this.scanqueue.expand(200);
  }

  /**
   * (Permanently) adjust the current set of indent levels to guarantee a minimum
   * amount of space and issue a line break.
   */
  private overflow(): void {
    const half = Math.floor(this.maxlinesize / 2);
    for (let i = this.indentstack.length - 1; i >= 0; --i) {
      if (this.indentstack[i] < half)
        this.indentstack[i] = half;
      else
        break;
    }
    let newspaceremain: int4;
    if (this.indentstack.length > 0)
      newspaceremain = this.indentstack[this.indentstack.length - 1];
    else
      newspaceremain = this.maxlinesize;
    if (newspaceremain === this.spaceremain)
      return;   // Line breaking doesn't give us any additional space
    if (this.commentmode && (newspaceremain === this.spaceremain + this.commentfill.length))
      return;   // Line breaking doesn't give us any additional space
    this.spaceremain = newspaceremain;
    this.lowlevel.tagLineWithIndent(this.maxlinesize - this.spaceremain);
    if (this.commentmode && (this.commentfill.length !== 0)) {
      this.lowlevel.print(this.commentfill, syntax_highlight.comment_color);
      this.spaceremain -= this.commentfill.length;
    }
  }

  /**
   * Output the given token to the low-level emitter.
   */
  private printToken(tok: TokenSplit): void {
    let val = 0;

    switch (tok.getClass()) {
      case printclass.ignore:
        tok.printToEmit(this.lowlevel); // Markup or other that doesn't use space
        break;
      case printclass.begin_indent:
        val = this.indentstack[this.indentstack.length - 1] - tok.getIndentBump();
        this.indentstack.push(val);
        if (PRETTY_DEBUG) {
          this.checkid.push(tok.getCount());
        }
        break;
      case printclass.begin_comment:
        this.commentmode = true;
        // fallthru, treat as a group begin
        // falls through
      case printclass.begin:
        tok.printToEmit(this.lowlevel);
        this.indentstack.push(this.spaceremain);
        if (PRETTY_DEBUG) {
          this.checkid.push(tok.getCount());
        }
        break;
      case printclass.end_indent:
        if (this.indentstack.length === 0)
          throw new LowlevelError("indent error");
        if (PRETTY_DEBUG) {
          if (this.checkid.length === 0 || (this.checkid[this.checkid.length - 1] !== tok.getCount()))
            throw new LowlevelError("mismatch1");
          this.checkid.pop();
          if (this.indentstack.length === 0)
            throw new LowlevelError("Empty indent stack");
        }
        this.indentstack.pop();
        break;
      case printclass.end_comment:
        this.commentmode = false;
        // fallthru, treat as a group end
        // falls through
      case printclass.end:
        tok.printToEmit(this.lowlevel);
        if (PRETTY_DEBUG) {
          if (this.checkid.length === 0 || (this.checkid[this.checkid.length - 1] !== tok.getCount()))
            throw new LowlevelError("mismatch2");
          this.checkid.pop();
          if (this.indentstack.length === 0)
            throw new LowlevelError("indent error");
        }
        this.indentstack.pop();
        break;
      case printclass.tokenstring:
        if (tok.getSize() > this.spaceremain)
          this.overflow();
        tok.printToEmit(this.lowlevel);
        this.spaceremain -= tok.getSize();
        break;
      case printclass.tokenbreak:
        if (tok.getSize() > this.spaceremain) {
          if (tok.getTag() === tag_type.line_t) {
            // Absolute indent
            this.spaceremain = this.maxlinesize - tok.getIndentBump();
          } else {
            // relative indent
            val = this.indentstack[this.indentstack.length - 1] - tok.getIndentBump();
            // If creating a line break doesn't save that much
            // don't do the line break
            if ((tok.getNumSpaces() <= this.spaceremain) &&
                (val - this.spaceremain < 10)) {
              this.lowlevel.spaces(tok.getNumSpaces());
              this.spaceremain -= tok.getNumSpaces();
              return;
            }
            this.indentstack[this.indentstack.length - 1] = val;
            this.spaceremain = val;
          }
          this.lowlevel.tagLineWithIndent(this.maxlinesize - this.spaceremain);
          if (this.commentmode && (this.commentfill.length !== 0)) {
            this.lowlevel.print(this.commentfill, syntax_highlight.comment_color);
            this.spaceremain -= this.commentfill.length;
          }
        } else {
          this.lowlevel.spaces(tok.getNumSpaces());
          this.spaceremain -= tok.getNumSpaces();
        }
        break;
    }
  }

  /**
   * Emit tokens that have been fully committed.
   */
  private advanceleft(): void {
    let l = this.tokqueue.bottom().getSize();
    while (l >= 0) {
      const tok = this.tokqueue.bottom();
      this.printToken(tok);
      switch (tok.getClass()) {
        case printclass.tokenbreak:
          this.leftotal += tok.getNumSpaces();
          break;
        case printclass.tokenstring:
          this.leftotal += l;
          break;
        default:
          break;
      }
      this.tokqueue.popbottom();
      if (this.tokqueue.empty()) break;
      l = this.tokqueue.bottom().getSize();
    }
  }

  /**
   * Process a new token. This is the heart of the pretty printing algorithm.
   */
  private scan(): void {
    if (this.tokqueue.empty())   // If we managed to overflow queue
      this.expand();             // Expand it
    // Delay creating reference until after the possible expansion
    const tok = this.tokqueue.top();
    switch (tok.getClass()) {
      case printclass.begin_comment:
      case printclass.begin:
        if (this.scanqueue.empty()) {
          this.leftotal = this.rightotal = 1;
        }
        tok.setSize(-this.rightotal);
        this.scanqueue.push();
        this.scanqueue.setRef(this.scanqueue.topref(), this.tokqueue.topref());
        break;
      case printclass.end_comment:
      case printclass.end:
        tok.setSize(0);
        if (!this.scanqueue.empty()) {
          const ref = this.tokqueue.ref(this.scanqueue.pop());
          ref.setSize(ref.getSize() + this.rightotal);
          if ((ref.getClass() === printclass.tokenbreak) && (!this.scanqueue.empty())) {
            const ref2 = this.tokqueue.ref(this.scanqueue.pop());
            ref2.setSize(ref2.getSize() + this.rightotal);
          }
          if (this.scanqueue.empty())
            this.advanceleft();
        }
        break;
      case printclass.tokenbreak:
        if (this.scanqueue.empty()) {
          this.leftotal = this.rightotal = 1;
        } else {
          const ref = this.tokqueue.ref(this.scanqueue.top());
          if (ref.getClass() === printclass.tokenbreak) {
            this.scanqueue.pop();
            ref.setSize(ref.getSize() + this.rightotal);
          }
        }
        tok.setSize(-this.rightotal);
        this.scanqueue.push();
        this.scanqueue.setRef(this.scanqueue.topref(), this.tokqueue.topref());
        this.rightotal += tok.getNumSpaces();
        break;
      case printclass.begin_indent:
      case printclass.end_indent:
      case printclass.ignore:
        tok.setSize(0);
        break;
      case printclass.tokenstring:
        if (!this.scanqueue.empty()) {
          this.rightotal += tok.getSize();
          while (this.rightotal - this.leftotal > this.spaceremain) {
            const ref = this.tokqueue.ref(this.scanqueue.popbottom());
            ref.setSize(999999);
            this.advanceleft();
            if (this.scanqueue.empty()) break;
          }
        }
        break;
    }
  }

  /**
   * Make sure there is whitespace after the last content token before a start token.
   */
  private checkstart(): void {
    if (this.needbreak) {
      const tok = this.tokqueue.push();
      tok.spaces(0, 0);
      this.scan();
    }
    this.needbreak = false;
  }

  /**
   * Make sure there is whitespace after the last content token before a content token.
   */
  private checkstring(): void {
    if (this.needbreak) {
      const tok = this.tokqueue.push();
      tok.spaces(0, 0);
      this.scan();
    }
    this.needbreak = true;
  }

  /**
   * Make sure there is content before an end token.
   */
  private checkend(): void {
    if (!this.needbreak) {
      const tok = this.tokqueue.push();
      tok.printToken(Emit.EMPTY_STRING, syntax_highlight.no_color); // Add a blank string
      this.scan();
    }
    this.needbreak = true;
  }

  /**
   * Make sure there is content before a line break token.
   */
  private checkbreak(): void {
    if (!this.needbreak) {
      const tok = this.tokqueue.push();
      tok.printToken(Emit.EMPTY_STRING, syntax_highlight.no_color); // Add a blank string
      this.scan();
    }
    this.needbreak = false;
  }

  // --- Public API ---

  beginDocument(): int4 {
    this.checkstart();
    const tok = this.tokqueue.push();
    const id = tok.beginDocument();
    this.scan();
    return id;
  }

  endDocument(id: int4): void {
    this.checkend();
    const tok = this.tokqueue.push();
    tok.endDocument(id);
    this.scan();
  }

  beginFunction(fd: Funcdata | null): int4 {
    if (PRETTY_DEBUG) {
      if (!this.tokqueue.empty())
        throw new LowlevelError("Starting with non-empty token queue");
    }
    this.checkstart();
    const tok = this.tokqueue.push();
    const id = tok.beginFunction(fd);
    this.scan();
    return id;
  }

  endFunction(id: int4): void {
    this.checkend();
    const tok = this.tokqueue.push();
    tok.endFunction(id);
    this.scan();
  }

  beginBlock(bl: FlowBlock | null): int4 {
    const tok = this.tokqueue.push();
    const id = tok.beginBlock(bl);
    this.scan();
    return id;
  }

  endBlock(id: int4): void {
    const tok = this.tokqueue.push();
    tok.endBlock(id);
    this.scan();
  }

  tagLine(): void {
    this.emitPending();
    this.checkbreak();
    const tok = this.tokqueue.push();
    tok.tagLine();
    this.scan();
  }

  tagLineWithIndent(indent: int4): void {
    this.emitPending();
    this.checkbreak();
    const tok = this.tokqueue.push();
    tok.tagLineWithIndent(indent);
    this.scan();
  }

  beginReturnType(vn: Varnode | null): int4 {
    this.checkstart();
    const tok = this.tokqueue.push();
    const id = tok.beginReturnType(vn);
    this.scan();
    return id;
  }

  endReturnType(id: int4): void {
    this.checkend();
    const tok = this.tokqueue.push();
    tok.endReturnType(id);
    this.scan();
  }

  beginVarDecl(sym: Symbol | null): int4 {
    this.checkstart();
    const tok = this.tokqueue.push();
    const id = tok.beginVarDecl(sym);
    this.scan();
    return id;
  }

  endVarDecl(id: int4): void {
    this.checkend();
    const tok = this.tokqueue.push();
    tok.endVarDecl(id);
    this.scan();
  }

  beginStatement(op: PcodeOp | null): int4 {
    this.checkstart();
    const tok = this.tokqueue.push();
    const id = tok.beginStatement(op);
    this.scan();
    return id;
  }

  endStatement(id: int4): void {
    this.checkend();
    const tok = this.tokqueue.push();
    tok.endStatement(id);
    this.scan();
  }

  beginFuncProto(): int4 {
    this.checkstart();
    const tok = this.tokqueue.push();
    const id = tok.beginFuncProto();
    this.scan();
    return id;
  }

  endFuncProto(id: int4): void {
    this.checkend();
    const tok = this.tokqueue.push();
    tok.endFuncProto(id);
    this.scan();
  }

  tagVariable(name: string, hl: syntax_highlight, vn: Varnode | null, op: PcodeOp | null): void {
    this.checkstring();
    const tok = this.tokqueue.push();
    tok.tagVariable(name, hl, vn, op);
    this.scan();
  }

  tagOp(name: string, hl: syntax_highlight, op: PcodeOp | null): void {
    this.checkstring();
    const tok = this.tokqueue.push();
    tok.tagOp(name, hl, op);
    this.scan();
  }

  tagFuncName(name: string, hl: syntax_highlight, fd: Funcdata | null, op: PcodeOp | null): void {
    this.checkstring();
    const tok = this.tokqueue.push();
    tok.tagFuncName(name, hl, fd, op);
    this.scan();
  }

  tagType(name: string, hl: syntax_highlight, ct: Datatype | null): void {
    this.checkstring();
    const tok = this.tokqueue.push();
    tok.tagType(name, hl, ct);
    this.scan();
  }

  tagField(name: string, hl: syntax_highlight, ct: Datatype | null, o: int4, op: PcodeOp | null): void {
    this.checkstring();
    const tok = this.tokqueue.push();
    tok.tagField(name, hl, ct, o, op);
    this.scan();
  }

  tagComment(name: string, hl: syntax_highlight, spc: AddrSpace, off: uintb): void {
    this.checkstring();
    const tok = this.tokqueue.push();
    tok.tagComment(name, hl, spc, off);
    this.scan();
  }

  tagLabel(name: string, hl: syntax_highlight, spc: AddrSpace, off: uintb): void {
    this.checkstring();
    const tok = this.tokqueue.push();
    tok.tagLabel(name, hl, spc, off);
    this.scan();
  }

  tagCaseLabel(name: string, hl: syntax_highlight, op: PcodeOp | null, value: uintb): void {
    this.checkstring();
    const tok = this.tokqueue.push();
    tok.tagCaseLabel(name, hl, op, value);
    this.scan();
  }

  print(data: string, hl: syntax_highlight = syntax_highlight.no_color): void {
    this.checkstring();
    const tok = this.tokqueue.push();
    tok.printToken(data, hl);
    this.scan();
  }

  openParen(paren: string, id: int4 = 0): int4 {
    id = this.openGroup();     // Open paren automatically opens group
    const tok = this.tokqueue.push();
    tok.openParen(paren, id);
    this.scan();
    this.needbreak = true;
    return id;
  }

  closeParen(paren: string, id: int4): void {
    this.checkstring();
    const tok = this.tokqueue.push();
    tok.closeParen(paren, id);
    this.scan();
    this.closeGroup(id);
  }

  openGroup(): int4 {
    this.checkstart();
    const tok = this.tokqueue.push();
    const id = tok.openGroup();
    this.scan();
    return id;
  }

  closeGroup(id: int4): void {
    this.checkend();
    const tok = this.tokqueue.push();
    tok.closeGroup(id);
    this.scan();
  }

  startComment(): int4 {
    this.checkstart();
    const tok = this.tokqueue.push();
    const id = tok.startComment();
    this.scan();
    return id;
  }

  stopComment(id: int4): void {
    this.checkend();
    const tok = this.tokqueue.push();
    tok.stopComment(id);
    this.scan();
  }

  clear(): void {
    super.clear();
    this.lowlevel.clear();
    this.indentstack.length = 0;
    this.scanqueue.clear();
    this.tokqueue.clear();
    this.leftotal = 1;
    this.rightotal = 1;
    this.needbreak = false;
    this.commentmode = false;
    this.spaceremain = this.maxlinesize;
  }

  spaces(num: int4, bump: int4 = 0): void {
    this.checkbreak();
    const tok = this.tokqueue.push();
    tok.spaces(num, bump);
    this.scan();
  }

  startIndent(): int4 {
    const tok = this.tokqueue.push();
    const id = tok.startIndent(this.indentincrement);
    this.scan();
    return id;
  }

  stopIndent(id: int4): void {
    const tok = this.tokqueue.push();
    tok.stopIndent(id);
    this.scan();
  }

  flush(): void {
    while (!this.tokqueue.empty()) {
      const tok = this.tokqueue.popbottom();
      if (tok.getSize() < 0)
        throw new LowlevelError("Cannot flush pretty printer. Missing group end");
      this.printToken(tok);
    }
    this.needbreak = false;
    if (PRETTY_DEBUG) {
      if (!this.scanqueue.empty())
        throw new LowlevelError("prettyprint scanqueue did not flush");
      if (this.indentstack.length > 0)
        throw new LowlevelError("prettyprint indentstack did not flush");
    }
    this.lowlevel.flush();
  }

  setMarkup(val: boolean): void {
    const t = this.lowlevel.getOutputStream();
    if (val)
      this.lowlevel = new EmitMarkup();
    else
      this.lowlevel = new EmitNoMarkup();
    this.lowlevel.setOutputStream(t);
  }

  setMaxLineSize(val: int4): void {
    if ((val < 20) || (val > 10000))
      throw new LowlevelError("Bad maximum line size");
    this.maxlinesize = val;
    this.scanqueue.setMax(3 * val);
    this.tokqueue.setMax(3 * val);
    this.spaceremain = this.maxlinesize;
    this.clear();
  }

  getMaxLineSize(): int4 { return this.maxlinesize; }

  setCommentFill(fill: string): void { this.commentfill = fill; }

  setOutputStream(t: Writer | null): void { this.lowlevel.setOutputStream(t); }
  getOutputStream(): Writer | null { return this.lowlevel.getOutputStream(); }
  setPackedOutput(val: boolean): void { this.lowlevel.setPackedOutput(val); }
  emitsMarkup(): boolean { return this.lowlevel.emitsMarkup(); }

  resetDefaults(): void {
    this.lowlevel.resetDefaults();
    this.resetDefaultsInternal();
    this.resetDefaultsPrettyPrint();
  }
}
