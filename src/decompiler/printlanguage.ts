/**
 * @file printlanguage.ts
 * @description Classes for printing tokens in a high-level language.
 *
 * Faithful translation of Ghidra's printlanguage.hh / printlanguage.cc.
 */

import type { int4, uint4, uint1, uintb } from '../core/types.js';
import { LowlevelError } from '../core/error.js';
import { Address, mostsigbit_set } from '../core/address.js';
import { CastStrategy } from './cast.js';
import {
  Emit,
  EmitMarkup,
  EmitPrettyPrint,
  syntax_highlight,
  type Writer,
} from './prettyprint.js';

// =========================================================================
// Forward type declarations (types not yet available from other modules)
// =========================================================================

type Architecture = any;
type Scope = any;
type Symbol = any;
type EquateSymbol = any;
type Varnode = any;
type PcodeOp = any;
type HighVariable = any;
type Funcdata = any;
type Datatype = any;
type TypeFactory = any;
type Comment = any;
type AddrSpace = any;
type ResolvedUnion = any;

type BlockGraph = any;
type BlockBasic = any;
type BlockList = any;
type BlockCopy = any;
type BlockGoto = any;
type BlockIf = any;
type BlockCondition = any;
type BlockWhileDo = any;
type BlockDoWhile = any;
type BlockInfLoop = any;
type BlockSwitch = any;

// =========================================================================
// OpToken -- operator token for high-level language
// =========================================================================

/**
 * The possible types of operator token.
 */
export enum tokentype {
  binary = 0,           ///< Binary operator form (printed between its inputs)
  unary_prefix = 1,     ///< Unary operator form (printed before its input)
  postsurround = 2,     ///< Function or array operator form
  presurround = 3,      ///< Modifier form (like a cast operation)
  space = 4,            ///< No explicitly printed token
  hiddenfunction = 5,   ///< Operation that isn't explicitly printed
}

/**
 * A token representing an operator in the high-level language.
 *
 * The token knows how to print itself and other syntax information like
 * precedence level and associativity within the language, desired spacing,
 * and how operator groups its input expressions. Note that an operator has
 * a broader meaning than just p-code operators in this context.
 */
export class OpToken {
  print1: string;           ///< Printing characters for the token
  print2: string;           ///< (terminating) characters for the token
  stage: int4;              ///< Additional elements consumed from the RPN stack when emitting this token
  precedence: int4;         ///< Precedence level of this token (higher binds more tightly)
  associative: boolean;     ///< True if the operator is associative
  type: tokentype;          ///< The basic token type
  spacing: int4;            ///< Spaces to print around operator
  bump: int4;               ///< Spaces to indent if we break here
  negate: OpToken | null;   ///< The token representing the negation of this token

  constructor(
    print1: string = "",
    print2: string = "",
    stage: int4 = 0,
    precedence: int4 = 0,
    associative: boolean = false,
    type: tokentype = tokentype.binary,
    spacing: int4 = 0,
    bump: int4 = 0,
    negate: OpToken | null = null
  ) {
    this.print1 = print1;
    this.print2 = print2;
    this.stage = stage;
    this.precedence = precedence;
    this.associative = associative;
    this.type = type;
    this.spacing = spacing;
    this.bump = bump;
    this.negate = negate;
  }
}

// =========================================================================
// PrintLanguageCapability -- factory/registry pattern
// =========================================================================

/**
 * Base class for high-level language capabilities.
 *
 * This class is overridden to introduce a new high-level language back-end
 * to the system. A static singleton is instantiated to automatically
 * register the new capability with the system. A static array keeps track of
 * all the registered capabilities.
 *
 * The singleton is registered with a name, which the user can use to select the language, and
 * it acts as a factory for the main language printing class for the capability,
 * which must be derived from PrintLanguage. The factory method for the capability to override
 * is buildLanguage().
 */
export abstract class PrintLanguageCapability {
  /** The static array of registered high-level languages */
  private static thelist: PrintLanguageCapability[] = [];

  /** Unique identifier for language capability */
  protected name: string = "";

  /** Set to true to treat this as the default language */
  protected isdefault: boolean = false;

  /** Get the high-level language name */
  getName(): string { return this.name; }

  /** Register this capability */
  initialize(): void {
    if (this.isdefault)
      PrintLanguageCapability.thelist.unshift(this);  // Default goes at beginning
    else
      PrintLanguageCapability.thelist.push(this);
  }

  /**
   * Build the main PrintLanguage object corresponding to this capability.
   *
   * An Architecture will call this once. All decompiling from this Architecture
   * will use this same emitter.
   * @param glb is the Architecture that will own the new emitter
   * @returns the instantiated PrintLanguage emitter
   */
  abstract buildLanguage(glb: Architecture): PrintLanguage;

  /**
   * Retrieve the default language capability.
   * This retrieves the capability with its isdefault field set or the first capability registered.
   * @returns the default language capability
   */
  static getDefault(): PrintLanguageCapability {
    if (PrintLanguageCapability.thelist.length === 0)
      throw new LowlevelError("No print languages registered");
    return PrintLanguageCapability.thelist[0];
  }

  /**
   * Find a language capability by name.
   * @param name is the language name to search for
   * @returns the matching language capability or null
   */
  static findCapability(name: string): PrintLanguageCapability | null {
    for (let i = 0; i < PrintLanguageCapability.thelist.length; ++i) {
      const plc = PrintLanguageCapability.thelist[i];
      if (plc.getName() === name)
        return plc;
    }
    return null;
  }
}

// =========================================================================
// PrintLanguage -- enums and inner types
// =========================================================================

/**
 * Possible context sensitive modifiers to how tokens get emitted.
 */
export const enum modifiers {
  force_hex        = 0x1,
  force_dec        = 0x2,
  bestfit          = 0x4,
  force_scinote    = 0x8,
  force_pointer    = 0x10,
  print_load_value = 0x20,
  print_store_value = 0x40,
  no_branch        = 0x80,
  only_branch      = 0x100,
  comma_separate   = 0x200,
  flat             = 0x400,
  falsebranch      = 0x800,
  nofallthru       = 0x1000,
  negatetoken      = 0x2000,
  hide_thisparam   = 0x4000,
  pending_brace    = 0x8000,
}

/**
 * Possible types of Atom.
 */
export enum tagtype {
  syntax = 0,       ///< Emit atom as syntax
  vartoken = 1,     ///< Emit atom as variable
  functoken = 2,    ///< Emit atom as function name
  optoken = 3,      ///< Emit atom as operator
  typetoken = 4,    ///< Emit atom as data-type
  fieldtoken = 5,   ///< Emit atom as structure field
  casetoken = 6,    ///< Emit atom as a case label
  blanktoken = 7,   ///< For anonymous types
}

/**
 * Strategies for displaying namespace tokens.
 */
export enum namespace_strategy {
  MINIMAL_NAMESPACES = 0,   ///< (default) Print just enough namespace info to fully resolve symbol
  NO_NAMESPACES = 1,        ///< Never print namespace information
  ALL_NAMESPACES = 2,       ///< Always print all namespace information
}

// =========================================================================
// ReversePolish -- an entry on the RPN stack
// =========================================================================

/**
 * An entry on the reverse polish notation (RPN) stack.
 */
export class ReversePolish {
  tok: OpToken | null = null;   ///< The operator token
  visited: int4 = 0;            ///< The current stage of printing for the operator
  paren: boolean = false;       ///< True if parentheses are required
  op: PcodeOp | null = null;    ///< The PcodeOp associated with the operator token
  id: int4 = 0;                 ///< The id of the token group which this belongs to
  id2: int4 = 0;                ///< The id of the token group this surrounds (for surround operator tokens)
}

// =========================================================================
// NodePending -- a pending data-flow node
// =========================================================================

/**
 * A pending data-flow node; waiting to be placed on the reverse polish notation stack.
 *
 * This holds an implied Varnode in the data-flow graph, which prints as the expression producing
 * the value in the Varnode.
 */
export class NodePending {
  vn: Varnode;          ///< The implied Varnode
  op: PcodeOp;          ///< The single operator consuming value from the implied Varnode
  vnmod: uint4;         ///< Printing modifications to enforce on the expression

  constructor(v: Varnode, o: PcodeOp, m: uint4) {
    this.vn = v;
    this.op = o;
    this.vnmod = m;
  }
}

// =========================================================================
// Atom -- a single non-operator token
// =========================================================================

/**
 * A single non-operator token emitted by the decompiler.
 *
 * These play the role of variable tokens on the RPN stack with the operator tokens.
 * The term "variable" has a broader meaning than just a Varnode. An Atom can also be a data-type
 * name, a function name, or a structure field etc.
 *
 * The C++ union `ptr_second` is replaced by separate optional fields.
 */
export class Atom {
  name: string;                              ///< The actual printed characters of the token
  type: tagtype;                             ///< The type of Atom
  highlight: syntax_highlight;               ///< The type of highlighting to use when emitting the token
  op: PcodeOp | null;                        ///< A p-code operation associated with the token

  // Union replacement: separate optional fields for ptr_second
  vn?: Varnode;                              ///< A Varnode associated with the token
  fd?: Funcdata;                             ///< A function associated with the token
  ct?: Datatype;                             ///< A type associated with the token
  intValue?: uintb;                          ///< An integer value associated with the token

  offset: int4;                              ///< The offset (within the parent structure) for a field token

  /** Construct a token with no associated data-flow annotations */
  constructor(nm: string, t: tagtype, hl: syntax_highlight);
  /** Construct a token for a data-type name */
  constructor(nm: string, t: tagtype, hl: syntax_highlight, c: Datatype);
  /** Construct a token for a field name */
  constructor(nm: string, t: tagtype, hl: syntax_highlight, c: Datatype, off: int4, o: PcodeOp);
  /** Construct a token with an associated PcodeOp */
  constructor(nm: string, t: tagtype, hl: syntax_highlight, o: PcodeOp);
  /** Construct a token with an associated PcodeOp and Varnode */
  constructor(nm: string, t: tagtype, hl: syntax_highlight, o: PcodeOp, v: Varnode);
  /** Construct a token for a function name */
  constructor(nm: string, t: tagtype, hl: syntax_highlight, o: PcodeOp, f: Funcdata);
  /** Construct a token with an associated PcodeOp, Varnode, and constant value */
  constructor(nm: string, t: tagtype, hl: syntax_highlight, o: PcodeOp, v: Varnode, intVal: uintb);
  constructor(
    nm: string,
    t: tagtype,
    hl: syntax_highlight,
    arg4?: any,
    arg5?: any,
    arg6?: any
  ) {
    this.name = nm;
    this.type = t;
    this.highlight = hl;
    this.op = null;
    this.offset = 0;

    if (arg4 === undefined) {
      // No extra args: token with no associated data-flow annotations
      return;
    }

    if (arg5 === undefined && arg6 === undefined) {
      // One extra arg: either a Datatype (for typetoken) or a PcodeOp
      // Distinguish by checking the tagtype; ct is used for typetoken/fieldtoken
      if (t === tagtype.typetoken || t === tagtype.fieldtoken) {
        this.ct = arg4;
      } else {
        this.op = arg4;
      }
      return;
    }

    if (arg6 !== undefined && typeof arg6 !== 'bigint') {
      // Six args, last is PcodeOp: this is field construction (nm, t, hl, ct, off, op)
      this.ct = arg4;
      this.offset = arg5 as int4;
      this.op = arg6;
      return;
    }

    // arg4 is PcodeOp, arg5 is Varnode/Funcdata, arg6 is optional intValue
    this.op = arg4;

    if (arg6 !== undefined) {
      // Seven-arg form: (nm, t, hl, op, vn, intValue)
      if (t === tagtype.casetoken) {
        this.intValue = arg6 as uintb;
      } else {
        this.vn = arg5;
      }
      return;
    }

    // Five-arg forms: PcodeOp + (Varnode or Funcdata)
    if (t === tagtype.functoken) {
      this.fd = arg5;
    } else {
      this.vn = arg5;
    }
  }
}

// =========================================================================
// PrintLanguage -- the base class API for emitting a high-level language
// =========================================================================

/**
 * The base class API for emitting a high-level language.
 *
 * Instances of this object are responsible for converting a function's
 * (transformed) data-flow graph into the final stream of tokens of a high-level
 * source code language.
 */
export abstract class PrintLanguage {
  static readonly OPEN_PAREN: string = "(";
  static readonly CLOSE_PAREN: string = ")";

  // Re-export enums as static members for compatibility
  static readonly force_hex        = modifiers.force_hex;
  static readonly force_dec        = modifiers.force_dec;
  static readonly bestfit          = modifiers.bestfit;
  static readonly force_scinote    = modifiers.force_scinote;
  static readonly force_pointer    = modifiers.force_pointer;
  static readonly print_load_value = modifiers.print_load_value;
  static readonly print_store_value = modifiers.print_store_value;
  static readonly no_branch        = modifiers.no_branch;
  static readonly only_branch      = modifiers.only_branch;
  static readonly comma_separate   = modifiers.comma_separate;
  static readonly flat             = modifiers.flat;
  static readonly falsebranch      = modifiers.falsebranch;
  static readonly nofallthru       = modifiers.nofallthru;
  static readonly negatetoken      = modifiers.negatetoken;
  static readonly hide_thisparam   = modifiers.hide_thisparam;
  static readonly pending_brace    = modifiers.pending_brace;

  // -- Private fields --
  private _name: string;                         ///< The name of the high-level language
  private modstack: uint4[];                     ///< Printing modification stack
  private scopestack: Scope[];                   ///< The symbol scope stack
  private revpol: ReversePolish[];               ///< The Reverse Polish Notation (RPN) token stack
  private nodepend: NodePending[];               ///< Data-flow nodes waiting to be pushed onto the RPN stack
  private _pending: int4;                        ///< Number of data-flow nodes waiting to be pushed
  private line_commentindent: int4;              ///< Number of characters a comment line should be indented
  private commentstart: string;                  ///< Delimiter characters for the start of a comment
  private commentend: string;                    ///< Delimiter characters (if any) for the end of a comment

  // -- Protected fields --
  /** @internal */ glb: Architecture;            ///< The Architecture owning the language emitter
  /** @internal */ curscope: Scope | null;       ///< The current symbol scope
  /** @internal */ castStrategy: CastStrategy | null;  ///< The strategy for emitting explicit cast operations
  /** @internal */ emit: Emit;                   ///< The low-level token emitter
  /** @internal */ mods: uint4;                  ///< Currently active printing modifications
  /** @internal */ instr_comment_type: uint4;    ///< Type of instruction comments to display
  /** @internal */ head_comment_type: uint4;     ///< Type of header comments to display
  /** @internal */ namespc_strategy: namespace_strategy; ///< How should namespace tokens be displayed

  // ---- Debug helpers ----
  /** Return true if the RPN stack is empty (debug only) */
  protected isStackEmpty(): boolean { return (this.nodepend.length === 0 && this.revpol.length === 0); }
  /** Return true if the printing modification stack is empty (debug only) */
  protected isModStackEmpty(): boolean { return this.modstack.length === 0; }

  // ---- Protected helper methods ----

  /** Is the given printing modification active */
  protected isSet(m: uint4): boolean { return ((this.mods & m) !== 0); }

  /** Push a new symbol scope */
  protected pushScope(sc: Scope): void { this.scopestack.push(sc); this.curscope = sc; }

  /** Pop to the previous symbol scope */
  protected popScope(): void {
    this.scopestack.pop();
    if (this.scopestack.length === 0)
      this.curscope = null;
    else
      this.curscope = this.scopestack[this.scopestack.length - 1];
  }

  /** Push current printing modifications to the stack */
  protected pushMod(): void { this.modstack.push(this.mods); }

  /** Pop to the previous printing modifications */
  protected popMod(): void {
    this.mods = this.modstack[this.modstack.length - 1];
    this.modstack.pop();
  }

  /** Activate the given printing modification */
  protected setMod(m: uint4): void { this.mods |= m; }

  /** Deactivate the given printing modification */
  protected unsetMod(m: uint4): void { this.mods &= ~m; }

  /**
   * Push an operator token onto the RPN stack.
   *
   * This generally will recursively push an entire expression onto the RPN stack,
   * up to Varnode objects marked as explicit, and will decide token order
   * and parenthesis placement.
   */
  protected pushOp(tok: OpToken, op: PcodeOp): void {
    if (this._pending < this.nodepend.length)   // Pending varnode pushes before op
      this.recurse();                            // So we must recurse

    let paren: boolean;
    let id: int4;

    if (this.revpol.length === 0) {
      paren = false;
      id = this.emit.openGroup();
    } else {
      this.emitOp(this.revpol[this.revpol.length - 1]);
      paren = this.parentheses(tok);
      if (paren)
        id = this.emit.openParen(PrintLanguage.OPEN_PAREN);
      else
        id = this.emit.openGroup();
    }

    const entry = new ReversePolish();
    entry.tok = tok;
    entry.visited = 0;
    entry.paren = paren;
    entry.op = op;
    entry.id = id;
    this.revpol.push(entry);
  }

  /**
   * Push a variable token onto the RPN stack.
   *
   * Push a single token (an Atom) onto the RPN stack. This may trigger some amount
   * of the RPN stack to get emitted, depending on what was pushed previously.
   */
  protected pushAtom(atom: Atom): void {
    if (this._pending < this.nodepend.length)   // pending varnodes before atom
      this.recurse();                            // So we must recurse

    if (this.revpol.length === 0)
      this.emitAtom(atom);
    else {
      this.emitOp(this.revpol[this.revpol.length - 1]);
      this.emitAtom(atom);
      do {
        const back = this.revpol[this.revpol.length - 1];
        back.visited += 1;
        if (back.visited === back.tok!.stage) {
          this.emitOp(back);
          if (back.paren)
            this.emit.closeParen(PrintLanguage.CLOSE_PAREN, back.id);
          else
            this.emit.closeGroup(back.id);
          this.revpol.pop();
        } else {
          break;
        }
      } while (this.revpol.length > 0);
    }
  }

  /**
   * Push an expression rooted at a Varnode onto the RPN stack.
   *
   * For a given implied Varnode, the entire expression producing it is
   * recursively pushed onto the RPN stack.
   *
   * When calling this method multiple times to push Varnode inputs for a
   * single p-code op, the inputs must be pushed in reverse order.
   */
  protected pushVn(vn: Varnode, op: PcodeOp, m: uint4): void {
    this.nodepend.push(new NodePending(vn, op, m));
  }

  /**
   * Push an explicit variable onto the RPN stack.
   *
   * This method pushes a given Varnode as a leaf of the current expression.
   * It decides how the Varnode should get emitted, as a symbol, constant, etc.,
   * and then pushes the resulting leaf Atom onto the stack.
   */
  protected pushVnExplicit(vn: Varnode, op: PcodeOp): void {
    if (vn.isAnnotation()) {
      this.pushAnnotation(vn, op);
      return;
    }
    if (vn.isConstant()) {
      this.pushConstant(vn.getOffset(), vn.getHighTypeReadFacing(op), tagtype.vartoken, vn, op);
      return;
    }
    this.pushSymbolDetail(vn, op, true);
  }

  /**
   * Push symbol name with adornments matching given Varnode.
   *
   * We know that the given Varnode matches part of a single Symbol.
   * Push a set of tokens that represents the Varnode, which may require
   * extracting subfields or casting to get the correct value.
   */
  protected pushSymbolDetail(vn: Varnode, op: PcodeOp, isRead: boolean): void {
    const high: HighVariable = vn.getHigh();
    const sym: Symbol | null = high.getSymbol();
    if (sym === null) {
      this.pushUnnamedLocation(high.getNameRepresentative().getAddr(), vn, op);
    } else {
      let symboloff: int4 = high.getSymbolOffset();
      if (symboloff === -1) {
        if (!sym.getType().needsResolution()) {
          this.pushSymbol(sym, vn, op);
          return;
        }
        symboloff = 0;
      }
      if (symboloff + vn.getSize() <= sym.getType().getSize()) {
        const inslot: int4 = isRead ? op.getSlot(vn) : -1;
        this.pushPartialSymbol(sym, symboloff, vn.getSize(), vn, op, inslot, isRead);
      } else {
        this.pushMismatchSymbol(sym, symboloff, vn.getSize(), vn, op);
      }
    }
  }

  /**
   * Determine if the given token should be emitted in its own parenthetic expression.
   *
   * The token at the top of the stack is being emitted. Check if its input expression,
   * ending with the given operator token, needs to be surrounded by parentheses.
   */
  protected parentheses(op2: OpToken): boolean {
    const top = this.revpol[this.revpol.length - 1];
    const topToken = top.tok!;
    const stage = top.visited;
    switch (topToken.type) {
      case tokentype.space:
      case tokentype.binary:
        if (topToken.precedence > op2.precedence) return true;
        if (topToken.precedence < op2.precedence) return false;
        if (topToken.associative && (topToken === op2)) return false;
        if ((op2.type === tokentype.postsurround) && (stage === 0)) return false;
        return true;
      case tokentype.unary_prefix:
        if (topToken.precedence > op2.precedence) return true;
        if (topToken.precedence < op2.precedence) return false;
        if ((op2.type === tokentype.unary_prefix) || (op2.type === tokentype.presurround)) return false;
        return true;
      case tokentype.postsurround:
        if (stage === 1) return false;  // Inside the surround
        if (topToken.precedence > op2.precedence) return true;
        if (topToken.precedence < op2.precedence) return false;
        if ((op2.type === tokentype.postsurround) || (op2.type === tokentype.binary)) return false;
        return true;
      case tokentype.presurround:
        if (stage === 0) return false;  // Inside the surround
        if (topToken.precedence > op2.precedence) return true;
        if (topToken.precedence < op2.precedence) return false;
        if ((op2.type === tokentype.unary_prefix) || (op2.type === tokentype.presurround)) return false;
        return true;
      case tokentype.hiddenfunction:
        if ((stage === 0) && (this.revpol.length > 1)) {
          const prevToken = this.revpol[this.revpol.length - 2].tok!;
          if (prevToken.type !== tokentype.binary && prevToken.type !== tokentype.unary_prefix)
            return false;
          if (prevToken.precedence < op2.precedence) return false;
        }
        return true;
    }
    return true;
  }

  /**
   * Send an operator token from the RPN to the emitter.
   *
   * An OpToken directly from the RPN is sent to the low-level emitter,
   * resolving any final spacing or parentheses.
   */
  protected emitOp(entry: ReversePolish): void {
    const tok = entry.tok!;
    switch (tok.type) {
      case tokentype.binary:
        if (entry.visited !== 1) return;
        this.emit.spaces(tok.spacing, tok.bump);
        this.emit.tagOp(tok.print1, syntax_highlight.no_color, entry.op);
        this.emit.spaces(tok.spacing, tok.bump);
        break;
      case tokentype.unary_prefix:
        if (entry.visited !== 0) return;
        this.emit.tagOp(tok.print1, syntax_highlight.no_color, entry.op);
        this.emit.spaces(tok.spacing, tok.bump);
        break;
      case tokentype.postsurround:
        if (entry.visited === 0) return;
        if (entry.visited === 1) {  // Front surround token
          this.emit.spaces(tok.spacing, tok.bump);
          entry.id2 = this.emit.openParen(tok.print1);
          this.emit.spaces(0, tok.bump);
        } else {                     // Back surround token
          this.emit.closeParen(tok.print2, entry.id2);
        }
        break;
      case tokentype.presurround:
        if (entry.visited === 2) return;
        if (entry.visited === 0) {  // Front surround token
          entry.id2 = this.emit.openParen(tok.print1);
        } else {                     // Back surround token
          this.emit.closeParen(tok.print2, entry.id2);
          this.emit.spaces(tok.spacing, tok.bump);
        }
        break;
      case tokentype.space:         // Like binary but just a space between
        if (entry.visited !== 1) return;
        this.emit.spaces(tok.spacing, tok.bump);
        break;
      case tokentype.hiddenfunction:
        return;                     // Never directly prints anything
    }
  }

  /**
   * Send a variable token from the RPN to the emitter.
   *
   * Send the given Atom to the low-level emitter, marking it up according to its type.
   */
  protected emitAtom(atom: Atom): void {
    switch (atom.type) {
      case tagtype.syntax:
        this.emit.print(atom.name, atom.highlight);
        break;
      case tagtype.vartoken:
        this.emit.tagVariable(atom.name, atom.highlight, atom.vn ?? null, atom.op);
        break;
      case tagtype.functoken:
        this.emit.tagFuncName(atom.name, atom.highlight, atom.fd ?? null, atom.op);
        break;
      case tagtype.optoken:
        this.emit.tagOp(atom.name, atom.highlight, atom.op);
        break;
      case tagtype.typetoken:
        this.emit.tagType(atom.name, atom.highlight, atom.ct ?? null);
        break;
      case tagtype.fieldtoken:
        this.emit.tagField(atom.name, atom.highlight, atom.ct ?? null, atom.offset, atom.op);
        break;
      case tagtype.casetoken:
        this.emit.tagCaseLabel(atom.name, atom.highlight, atom.op, atom.intValue ?? 0n);
        break;
      case tagtype.blanktoken:
        break;  // Print nothing
    }
  }

  /**
   * Determine if the given codepoint needs to be escaped.
   *
   * Separate unicode characters that can be clearly emitted in a source code string
   * (letters, numbers, punctuation, symbols) from characters that are better represented
   * in source code with an escape sequence.
   */
  static unicodeNeedsEscape(codepoint: int4): boolean {
    if (codepoint < 0x20) {          // C0 Control characters
      return true;
    }
    if (codepoint < 0x7F) {          // Printable ASCII
      switch (codepoint) {
        case 92:                       // back-slash
        case 0x22:                     // '"'
        case 0x27:                     // "'"
          return true;
      }
      return false;
    }
    if (codepoint < 0x100) {
      if (codepoint > 0xa0) {         // Printable codepoints A1-FF
        return false;
      }
      return true;                    // Delete + C1 Control characters
    }
    if (codepoint >= 0x2fa20) {       // Up to last currently defined language
      return true;
    }
    if (codepoint < 0x2000) {
      if (codepoint >= 0x180b && codepoint <= 0x180e) {
        return true;                  // Mongolian separators
      }
      if (codepoint === 0x61c) {
        return true;                  // arabic letter mark
      }
      if (codepoint === 0x1680) {
        return true;                  // ogham space mark
      }
      return false;
    }
    if (codepoint < 0x3000) {
      if (codepoint < 0x2010) {
        return true;                  // white space and separators
      }
      if (codepoint >= 0x2028 && codepoint <= 0x202f) {
        return true;                  // white space and separators
      }
      if (codepoint === 0x205f || codepoint === 0x2060) {
        return true;                  // white space and word joiner
      }
      if (codepoint >= 0x2066 && codepoint <= 0x206f) {
        return true;                  // bidirectional markers
      }
      return false;
    }
    if (codepoint < 0xe000) {
      if (codepoint === 0x3000) {
        return true;                  // ideographic space
      }
      if (codepoint >= 0xd7fc) {     // D7FC-D7FF unassigned, D800-DFFF surrogates
        return true;
      }
      return false;
    }
    if (codepoint < 0xf900) {
      return true;                    // private use
    }
    if (codepoint >= 0xfe00 && codepoint <= 0xfe0f) {
      return true;                    // variation selectors
    }
    if (codepoint === 0xfeff) {
      return true;                    // zero width non-breaking space
    }
    if (codepoint >= 0xfff0 && codepoint <= 0xffff) {
      if ((codepoint === 0xfffc || codepoint === 0xfffd))
        return false;
      return true;                    // interlinear specials
    }
    return false;
  }

  /**
   * Emit a byte buffer to the stream as unicode characters.
   *
   * Characters are emitted until we reach a terminator character or count bytes is consumed.
   * @param s is the output stream (Writer)
   * @param buf is the byte buffer
   * @param count is the maximum number of bytes to consume
   * @param charsize is 1 for UTF8, 2 for UTF16, or 4 for UTF32
   * @param bigend is true for a big endian encoding of UTF elements
   * @returns true if we reach a terminator character
   */
  protected escapeCharacterData(s: Writer, buf: Uint8Array, count: int4, charsize: int4, bigend: boolean): boolean {
    let i = 0;
    const skip = charsize;
    let codepoint = 0;
    while (i < count) {
      // In the C++ code this calls StringManager::getCodepoint.
      // We use a simplified inline version here. The actual implementation would call
      // StringManager.getCodepoint, but we avoid importing it to reduce coupling.
      // For now, handle the simple single-byte case:
      if (charsize === 1) {
        codepoint = buf[i];
      } else if (charsize === 2) {
        if (bigend)
          codepoint = (buf[i] << 8) | buf[i + 1];
        else
          codepoint = buf[i] | (buf[i + 1] << 8);
      } else {
        if (bigend)
          codepoint = (buf[i] << 24) | (buf[i + 1] << 16) | (buf[i + 2] << 8) | buf[i + 3];
        else
          codepoint = buf[i] | (buf[i + 1] << 8) | (buf[i + 2] << 16) | (buf[i + 3] << 24);
      }
      if (codepoint === 0 || codepoint === -1) break;
      this.printUnicode(s, codepoint);
      i += skip;
    }
    return (codepoint === 0);
  }

  /**
   * Emit from the RPN stack as much as possible.
   *
   * Any complete sub-expressions that are still on the RPN will get emitted.
   */
  protected recurse(): void {
    const modsave = this.mods;
    let lastPending = this._pending;             // Already claimed
    this._pending = this.nodepend.length;        // Lay claim to the rest
    while (lastPending < this._pending) {
      const back = this.nodepend[this.nodepend.length - 1];
      const vn = back.vn;
      const op = back.op;
      this.mods = back.vnmod;
      this.nodepend.pop();
      this._pending -= 1;
      if (vn.isImplied()) {
        if (vn.hasImpliedField()) {
          this.pushImpliedField(vn, op);
        } else {
          const defOp = vn.getDef();
          defOp.getOpcode().push(this, defOp, op);
        }
      } else {
        this.pushVnExplicit(vn, op);
      }
      this._pending = this.nodepend.length;
    }
    this.mods = modsave;
  }

  /**
   * Push a binary operator onto the RPN stack.
   *
   * Push an operator onto the stack that has a normal binary format.
   * Both of its input expressions are also pushed.
   */
  protected opBinary(tok: OpToken, op: PcodeOp): void {
    if (this.isSet(modifiers.negatetoken)) {
      const negated = tok.negate;
      if (negated === null)
        throw new LowlevelError("Could not find fliptoken");
      tok = negated;
      this.unsetMod(modifiers.negatetoken);
    }
    this.pushOp(tok, op);
    // implied vn's pushed on in reverse order for efficiency
    this.pushVn(op.getIn(1), op, this.mods);
    this.pushVn(op.getIn(0), op, this.mods);
  }

  /**
   * Push a unary operator onto the RPN stack.
   *
   * Push an operator onto the stack that has a normal unary format.
   * Its input expression is also pushed.
   */
  protected opUnary(tok: OpToken, op: PcodeOp): void {
    this.pushOp(tok, op);
    // implied vn's pushed on in reverse order for efficiency
    this.pushVn(op.getIn(0), op, this.mods);
  }

  /** Get the number of pending nodes yet to be put on the RPN stack */
  protected getPending(): int4 { return this._pending; }

  /** Reset options to default for PrintLanguage */
  protected resetDefaultsInternal(): void {
    this.mods = 0;
    // Comment.header = 8, Comment.warningheader = 32
    this.head_comment_type = 8 | 32;
    this.line_commentindent = 20;
    this.namespc_strategy = namespace_strategy.MINIMAL_NAMESPACES;
    // Comment.user2 = 2, Comment.warning = 16
    this.instr_comment_type = 2 | 16;
  }

  // ---- Abstract protected methods (pure virtual in C++) ----

  /**
   * Print a single unicode character as a character constant for the high-level language.
   *
   * For most languages, this prints the character surrounded by single quotes.
   */
  protected abstract printUnicode(s: Writer, onechar: int4): void;

  /**
   * Push a data-type name onto the RPN expression stack.
   *
   * The data-type is generally emitted as if for a cast.
   */
  protected abstract pushType(ct: Datatype): void;

  /**
   * Push a constant onto the RPN stack.
   *
   * The value is ultimately emitted based on its data-type and other associated mark-up.
   */
  protected abstract pushConstant(val: uintb, ct: Datatype, tag: tagtype, vn: Varnode | null, op: PcodeOp | null): void;

  /**
   * Push a constant marked up by an EquateSymbol onto the RPN stack.
   *
   * The equate may substitute a name or force a conversion for the constant.
   */
  protected abstract pushEquate(val: uintb, sz: int4, sym: EquateSymbol, vn: Varnode | null, op: PcodeOp | null): boolean;

  /**
   * Push an address which is not in the normal data-flow.
   *
   * The given Varnode is treated as an address, which may or may not have a symbol name.
   */
  protected abstract pushAnnotation(vn: Varnode, op: PcodeOp): void;

  /**
   * Push a specific Symbol onto the RPN stack.
   */
  protected abstract pushSymbol(sym: Symbol, vn: Varnode, op: PcodeOp): void;

  /**
   * Push an address as a substitute for a Symbol onto the RPN stack.
   *
   * If there is no Symbol or other name source for an explicit variable,
   * this method is used to print something to represent the variable based on its storage address.
   */
  protected abstract pushUnnamedLocation(addr: Address, vn: Varnode, op: PcodeOp): void;

  /**
   * Push a variable that represents only part of a symbol onto the RPN stack.
   */
  protected abstract pushPartialSymbol(sym: Symbol, off: int4, sz: int4,
    vn: Varnode, op: PcodeOp, slot: int4, allowCast: boolean): void;

  /**
   * Push an identifier for a variable that mismatches with its Symbol.
   */
  protected abstract pushMismatchSymbol(sym: Symbol, off: int4, sz: int4,
    vn: Varnode, op: PcodeOp): void;

  /**
   * Push the implied field of a given Varnode as an object member extraction operation.
   */
  protected abstract pushImpliedField(vn: Varnode, op: PcodeOp): void;

  /**
   * Emit a comment line.
   *
   * The comment will get emitted as a single line using the high-level language's
   * delimiters with the given indent level.
   */
  protected emitLineComment(indent: int4, comm: Comment): void {
    const text: string = comm.getText();
    const spc: AddrSpace = comm.getAddr().getSpace();
    const off: uintb = comm.getAddr().getOffset();
    if (indent < 0)
      indent = this.line_commentindent;  // User specified default indent
    this.emit.tagLineWithIndent(indent);
    const id: int4 = this.emit.startComment();
    // The comment delimeters should not be printed as
    // comment tags, so that they won't get filled
    this.emit.tagComment(this.commentstart, syntax_highlight.comment_color, spc, off);
    let pos = 0;
    while (pos < text.length) {
      let tok: string = text[pos++];
      if ((tok === ' ') || (tok === '\t')) {
        let count = 1;
        while (pos < text.length) {
          tok = text[pos];
          if ((tok !== ' ') && (tok !== '\t')) break;
          count += 1;
          pos += 1;
        }
        this.emit.spaces(count);
      } else if (tok === '\n') {
        this.emit.tagLine();
      } else if (tok === '\r') {
        // skip
      } else if (tok === '{' && pos < text.length && text[pos] === '@') {
        // Comment annotation
        let count = 1;
        while (pos < text.length) {
          tok = text[pos];
          count += 1;
          pos += 1;
          if (tok === '}') break;    // Search for brace ending the annotation
        }
        // Treat annotation as one token
        const annote = text.substring(pos - count, pos);
        this.emit.tagComment(annote, syntax_highlight.comment_color, spc, off);
      } else {
        let count = 1;
        while (pos < text.length) {
          tok = text[pos];
          if (tok === ' ' || tok === '\t' || tok === '\n' || tok === '\r') break;
          count += 1;
          pos += 1;
        }
        const sub = text.substring(pos - count, pos);
        this.emit.tagComment(sub, syntax_highlight.comment_color, spc, off);
      }
    }
    if (this.commentend.length !== 0)
      this.emit.tagComment(this.commentend, syntax_highlight.comment_color, spc, off);
    this.emit.stopComment(id);
    comm.setEmitted(true);
  }

  /** Emit a variable declaration */
  protected abstract emitVarDecl(sym: Symbol): void;

  /** Emit a variable declaration statement */
  protected abstract emitVarDeclStatement(sym: Symbol): void;

  /**
   * Emit all the variable declarations for a given scope.
   * A subset of all variables can be declared by specifying a category,
   * 0 for parameters, -1 for everything.
   */
  protected abstract emitScopeVarDecls(symScope: Scope, cat: int4): boolean;

  /**
   * Emit a full expression.
   * This can be an assignment statement, if the given PcodeOp has an output Varnode,
   * or it can be a statement with no left-hand side.
   */
  protected abstract emitExpression(op: PcodeOp): void;

  /** Emit a function declaration */
  protected abstract emitFunctionDeclaration(fd: Funcdata): void;

  /**
   * Check whether a given boolean Varnode can be printed in negated form.
   */
  protected abstract checkPrintNegation(vn: Varnode): boolean;

  // ---- Public methods ----

  /**
   * Constructor.
   * @param g is the Architecture that owns and will use this PrintLanguage
   * @param nm is the formal name of the language
   */
  constructor(g: Architecture, nm: string) {
    this.glb = g;
    this.castStrategy = null;
    this._name = nm;
    this.curscope = null;
    this.emit = new EmitPrettyPrint();
    this._pending = 0;
    this.line_commentindent = 20;
    this.commentstart = "";
    this.commentend = "";
    this.modstack = [];
    this.scopestack = [];
    this.revpol = [];
    this.nodepend = [];
    this.mods = 0;
    this.instr_comment_type = 0;
    this.head_comment_type = 0;
    this.namespc_strategy = namespace_strategy.MINIMAL_NAMESPACES;
    this.resetDefaultsInternal();
  }

  /** Get the language name */
  getName(): string { return this._name; }

  /** Get the casting strategy for the language */
  getCastStrategy(): CastStrategy | null { return this.castStrategy; }

  /** Get the output stream being emitted to */
  getOutputStream(): Writer | null { return this.emit.getOutputStream(); }

  /** Set the output stream to emit to */
  setOutputStream(t: Writer | null): void { this.emit.setOutputStream(t); }

  /** Set the maximum number of characters per line */
  setMaxLineSize(mls: int4): void { this.emit.setMaxLineSize(mls); }

  /** Set the number of characters to indent per level of code nesting */
  setIndentIncrement(inc: int4): void { this.emit.setIndentIncrement(inc); }

  /**
   * Set the number of characters to indent comment lines.
   * @param val is the number of characters
   */
  setLineCommentIndent(val: int4): void {
    if ((val < 0) || (val >= this.emit.getMaxLineSize()))
      throw new LowlevelError("Bad comment indent value");
    this.line_commentindent = val;
  }

  /**
   * Establish comment delimiters for the language.
   *
   * By default, comments are indicated in the high-level language by preceding
   * them with a specific sequence of delimiter characters, and optionally
   * by ending the comment with another set of delimiter characters.
   * @param start is the initial sequence of characters delimiting a comment
   * @param stop if not empty is the sequence delimiting the end of the comment
   * @param usecommentfill is true if the delimiter needs to be emitted after every line break
   */
  setCommentDelimeter(start: string, stop: string, usecommentfill: boolean): void {
    this.commentstart = start;
    this.commentend = stop;
    if (usecommentfill) {
      this.emit.setCommentFill(start);
    } else {
      let spaces = "";
      for (let i = 0; i < start.length; ++i)
        spaces += ' ';
      this.emit.setCommentFill(spaces);
    }
  }

  /** Get the type of comments suitable within the body of a function */
  getInstructionComment(): uint4 { return this.instr_comment_type; }

  /** Set the type of comments suitable within the body of a function */
  setInstructionComment(val: uint4): void { this.instr_comment_type = val; }

  /** Set how namespace tokens are displayed */
  setNamespaceStrategy(strat: namespace_strategy): void { this.namespc_strategy = strat; }

  /** Get the type of comments suitable for a function header */
  getHeaderComment(): uint4 { return this.head_comment_type; }

  /** Set the type of comments suitable for a function header */
  setHeaderComment(val: uint4): void { this.head_comment_type = val; }

  /** Does the low-level emitter emit markup */
  emitsMarkup(): boolean { return this.emit.emitsMarkup(); }

  /** Turn on/off mark-up in emitted output */
  setMarkup(val: boolean): void { this.emit.setMarkup(val); }

  /**
   * Turn on/off packed output.
   *
   * Select packed or unpacked (XML) output, if the emitter supports it.
   */
  setPackedOutput(val: boolean): void {
    this.emit.setPackedOutput(val);
  }

  /**
   * Set whether nesting code structure should be emitted.
   *
   * Emitting formal code structuring can be turned off, causing all control-flow
   * to be represented as goto statements and labels.
   */
  setFlat(val: boolean): void {
    if (val)
      this.mods |= modifiers.flat;
    else
      this.mods &= ~modifiers.flat;
  }

  // ---- Abstract public methods ----

  /** Initialize architecture specific aspects of printer */
  abstract initializeFromArchitecture(): void;

  /** Set basic data-type information for p-code operators */
  abstract adjustTypeOperators(): void;

  /**
   * Set printing options to their default value.
   */
  resetDefaults(): void {
    this.emit.resetDefaults();
    this.resetDefaultsInternal();
  }

  /**
   * Clear the RPN stack and the low-level emitter.
   */
  clear(): void {
    this.emit.clear();
    if (this.modstack.length > 0) {
      this.mods = this.modstack[0];
      this.modstack.length = 0;
    }
    this.scopestack.length = 0;
    this.curscope = null;
    this.revpol.length = 0;
    this._pending = 0;
    this.nodepend.length = 0;
  }

  /**
   * Set the default integer format.
   *
   * This determines how integers are displayed by default. Possible
   * values are "hex" and "dec" to force a given format, or "best" can
   * be used to let the decompiler select what it thinks best for each individual integer.
   * @param nm is "hex", "dec", or "best"
   */
  setIntegerFormat(nm: string): void {
    let mod: uint4;
    if (nm.startsWith("hex"))
      mod = modifiers.force_hex;
    else if (nm.startsWith("dec"))
      mod = modifiers.force_dec;
    else if (nm.startsWith("best"))
      mod = 0;
    else
      throw new LowlevelError("Unknown integer format option: " + nm);
    this.mods &= ~(modifiers.force_hex | modifiers.force_dec);  // Turn off any pre-existing force
    this.mods |= mod;                                           // Set any new force
  }

  /** Set the way comments are displayed in decompiler output */
  abstract setCommentStyle(nm: string): void;

  /** Emit definitions of data-types */
  abstract docTypeDefinitions(typegrp: TypeFactory): void;

  /** Emit declarations of global variables */
  abstract docAllGlobals(): void;

  /** Emit the declaration for a single (global) Symbol */
  abstract docSingleGlobal(sym: Symbol): void;

  /** Emit the declaration (and body) of a function */
  abstract docFunction(fd: Funcdata): void;

  // ---- Block emission (abstract) ----

  abstract emitBlockBasic(bb: BlockBasic): void;
  abstract emitBlockGraph(bl: BlockGraph): void;
  abstract emitBlockCopy(bl: BlockCopy): void;
  abstract emitBlockGoto(bl: BlockGoto): void;
  abstract emitBlockLs(bl: BlockList): void;
  abstract emitBlockCondition(bl: BlockCondition): void;
  abstract emitBlockIf(bl: BlockIf): void;
  abstract emitBlockWhileDo(bl: BlockWhileDo): void;
  abstract emitBlockDoWhile(bl: BlockDoWhile): void;
  abstract emitBlockInfLoop(bl: BlockInfLoop): void;
  abstract emitBlockSwitch(bl: BlockSwitch): void;

  // ---- PcodeOp emission (abstract) ----

  abstract opCopy(op: PcodeOp): void;
  abstract opLoad(op: PcodeOp): void;
  abstract opStore(op: PcodeOp): void;
  abstract opBranch(op: PcodeOp): void;
  abstract opCbranch(op: PcodeOp): void;
  abstract opBranchind(op: PcodeOp): void;
  abstract opCall(op: PcodeOp): void;
  abstract opCallind(op: PcodeOp): void;
  abstract opCallother(op: PcodeOp): void;
  abstract opConstructor(op: PcodeOp, withNew: boolean): void;
  abstract opReturn(op: PcodeOp): void;
  abstract opIntEqual(op: PcodeOp): void;
  abstract opIntNotEqual(op: PcodeOp): void;
  abstract opIntSless(op: PcodeOp): void;
  abstract opIntSlessEqual(op: PcodeOp): void;
  abstract opIntLess(op: PcodeOp): void;
  abstract opIntLessEqual(op: PcodeOp): void;
  abstract opIntZext(op: PcodeOp, readOp: PcodeOp | null): void;
  abstract opIntSext(op: PcodeOp, readOp: PcodeOp | null): void;
  abstract opIntAdd(op: PcodeOp): void;
  abstract opIntSub(op: PcodeOp): void;
  abstract opIntCarry(op: PcodeOp): void;
  abstract opIntScarry(op: PcodeOp): void;
  abstract opIntSborrow(op: PcodeOp): void;
  abstract opInt2Comp(op: PcodeOp): void;
  abstract opIntNegate(op: PcodeOp): void;
  abstract opIntXor(op: PcodeOp): void;
  abstract opIntAnd(op: PcodeOp): void;
  abstract opIntOr(op: PcodeOp): void;
  abstract opIntLeft(op: PcodeOp): void;
  abstract opIntRight(op: PcodeOp): void;
  abstract opIntSright(op: PcodeOp): void;
  abstract opIntMult(op: PcodeOp): void;
  abstract opIntDiv(op: PcodeOp): void;
  abstract opIntSdiv(op: PcodeOp): void;
  abstract opIntRem(op: PcodeOp): void;
  abstract opIntSrem(op: PcodeOp): void;
  abstract opBoolNegate(op: PcodeOp): void;
  abstract opBoolXor(op: PcodeOp): void;
  abstract opBoolAnd(op: PcodeOp): void;
  abstract opBoolOr(op: PcodeOp): void;
  abstract opFloatEqual(op: PcodeOp): void;
  abstract opFloatNotEqual(op: PcodeOp): void;
  abstract opFloatLess(op: PcodeOp): void;
  abstract opFloatLessEqual(op: PcodeOp): void;
  abstract opFloatNan(op: PcodeOp): void;
  abstract opFloatAdd(op: PcodeOp): void;
  abstract opFloatDiv(op: PcodeOp): void;
  abstract opFloatMult(op: PcodeOp): void;
  abstract opFloatSub(op: PcodeOp): void;
  abstract opFloatNeg(op: PcodeOp): void;
  abstract opFloatAbs(op: PcodeOp): void;
  abstract opFloatSqrt(op: PcodeOp): void;
  abstract opFloatInt2Float(op: PcodeOp): void;
  abstract opFloatFloat2Float(op: PcodeOp): void;
  abstract opFloatTrunc(op: PcodeOp): void;
  abstract opFloatCeil(op: PcodeOp): void;
  abstract opFloatFloor(op: PcodeOp): void;
  abstract opFloatRound(op: PcodeOp): void;
  abstract opMultiequal(op: PcodeOp): void;
  abstract opIndirect(op: PcodeOp): void;
  abstract opPiece(op: PcodeOp): void;
  abstract opSubpiece(op: PcodeOp): void;
  abstract opCast(op: PcodeOp): void;
  abstract opPtradd(op: PcodeOp): void;
  abstract opPtrsub(op: PcodeOp): void;
  abstract opSegmentOp(op: PcodeOp): void;
  abstract opCpoolRefOp(op: PcodeOp): void;
  abstract opNewOp(op: PcodeOp): void;
  abstract opInsertOp(op: PcodeOp): void;
  abstract opExtractOp(op: PcodeOp): void;
  abstract opPopcountOp(op: PcodeOp): void;
  abstract opLzcountOp(op: PcodeOp): void;

  /**
   * Generate an artificial field name.
   *
   * This is used if a value is extracted from a structured data-type, but the natural name
   * is not available. An artificial name is generated given just the offset into the data-type
   * and the size in bytes.
   * @param off is the byte offset into the data-type
   * @param size is the number of bytes in the extracted value
   * @returns a string describing the artificial field
   */
  unnamedField(off: int4, size: int4): string {
    return `_${off}_${size}_`;
  }

  // ---- Static utility methods ----

  /**
   * Determine the most natural base for an integer.
   *
   * Count '0' and '9' digits base 10. Count '0' and 'f' digits base 16.
   * The highest count is the preferred base.
   * @param val is the given integer
   * @returns 10 for decimal or 16 for hexadecimal
   */
  static mostNaturalBase(val: uintb): int4 {
    let countdec = 0;       // Count 0's and 9's

    let tmp = val;
    let dig: bigint;
    let setdig: bigint;
    if (tmp === 0n) return 10;
    setdig = tmp % 10n;
    if ((setdig === 0n) || (setdig === 9n)) {
      countdec += 1;
      tmp = tmp / 10n;
      while (tmp !== 0n) {
        dig = tmp % 10n;
        if (dig === setdig)
          countdec += 1;
        else
          break;
        tmp = tmp / 10n;
      }
    }
    switch (countdec) {
      case 0:
        return 16;
      case 1:
        if ((tmp > 1n) || (setdig === 9n)) return 16;
        break;
      case 2:
        if (tmp > 10n) return 16;
        break;
      case 3:
      case 4:
        if (tmp > 100n) return 16;
        break;
      default:
        if (tmp > 1000n) return 16;
        break;
    }

    let counthex = 0;       // Count 0's and f's

    tmp = val;
    setdig = tmp & 0xfn;
    if ((setdig === 0n) || (setdig === 0xfn)) {
      counthex += 1;
      tmp >>= 4n;
      while (tmp !== 0n) {
        dig = tmp & 0xfn;
        if (dig === setdig)
          counthex += 1;
        else
          break;
        tmp >>= 4n;
      }
    }

    return (countdec > counthex) ? 10 : 16;
  }

  /**
   * Print a number in binary form.
   *
   * Print a string of '0' and '1' characters representing the given value.
   * @param s is the output stream (Writer)
   * @param val is the given value
   */
  static formatBinary(s: Writer, val: uintb): void {
    let pos = mostsigbit_set(val);
    if (pos < 0) {
      s.write('0');
      return;
    } else if (pos <= 7) {
      pos = 7;
    } else if (pos <= 15) {
      pos = 15;
    } else if (pos <= 31) {
      pos = 31;
    } else {
      pos = 63;
    }
    let mask = 1n;
    mask <<= BigInt(pos);
    while (mask !== 0n) {
      if ((mask & val) !== 0n)
        s.write('1');
      else
        s.write('0');
      mask >>= 1n;
    }
  }
}
