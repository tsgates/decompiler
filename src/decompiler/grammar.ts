/**
 * @file grammar_part1.ts
 * @description C type grammar parser for Ghidra decompiler (Part 1 of 2).
 *
 * Translated from:
 *   - grammar.hh
 *   - grammar.y  (yacc grammar)
 *   - grammar.cc (generated parser + hand-written lexer/helpers)
 *
 * This is a hand-written recursive descent parser that replaces the
 * original Bison/LALR(1) parser.  Part 1 contains:
 *   - Token types, TypeDeclarator, GrammarLexer (tokenizer)
 *   - GrammarParser class declaration with all fields
 *   - Parser methods for: declarations, type specifiers, declarators,
 *     pointer declarators, abstract declarators
 *
 * Part 2 (grammar_part2.ts) will contain:
 *   - struct/union/enum specifiers
 *   - top-level parse entry points (parseFile, parseStream, parse_type, etc.)
 *   - CParse helper/allocation methods
 */

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

import { Datatype, TypeStruct, TypeUnion } from '../decompiler/type.js';
import { type_metatype } from '../decompiler/type.js';

// ---------------------------------------------------------------------------
// Forward type declarations
// ---------------------------------------------------------------------------

type Architecture = any;
type ProtoModel = any;
type PrototypePieces = any;

// ---------------------------------------------------------------------------
// Error classes
// ---------------------------------------------------------------------------

export class ParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ParseError';
  }
}

export class LowlevelError extends Error {
  explain: string;
  constructor(message: string) {
    super(message);
    this.name = 'LowlevelError';
    this.explain = message;
  }
}

// ---------------------------------------------------------------------------
// GrammarToken — token types and values
// ---------------------------------------------------------------------------

/** Token type constants */
export enum TokenType {
  // Single-character punctuation tokens are represented by their char code
  openparen    = 0x28,  // '('
  closeparen   = 0x29,  // ')'
  star         = 0x2a,  // '*'
  comma        = 0x2c,  // ','
  semicolon    = 0x3b,  // ';'
  equals       = 0x3d,  // '='
  openbracket  = 0x5b,  // '['
  closebracket = 0x5d,  // ']'
  openbrace    = 0x7b,  // '{'
  closebrace   = 0x7d,  // '}'

  // Multi-character / classified tokens
  badtoken     = 0x100,
  endoffile    = 0x101,
  dotdotdot    = 0x102,
  integer      = 0x103,
  charconstant = 0x104,
  identifier   = 0x105,
  stringval    = 0x106,
}

/**
 * High-level token kinds returned by the CParse lexer (after keyword
 * classification).  These correspond to the yacc %token declarations.
 */
export enum HighToken {
  DOTDOTDOT              = 258,
  BADTOKEN               = 259,
  STRUCT                 = 260,
  UNION                  = 261,
  ENUM                   = 262,
  DECLARATION_RESULT     = 263,
  PARAM_RESULT           = 264,
  NUMBER                 = 265,
  IDENTIFIER             = 266,
  STORAGE_CLASS_SPECIFIER = 267,
  TYPE_QUALIFIER         = 268,
  FUNCTION_SPECIFIER     = 269,
  TYPE_NAME              = 270,
  EOF_TOKEN              = -1,
}

// ---------------------------------------------------------------------------
// GrammarToken
// ---------------------------------------------------------------------------

export class GrammarToken {
  type: number = 0;
  integerValue: bigint = 0n;
  stringValue: string | null = null;
  lineno: number = -1;
  colno: number = -1;
  filenum: number = -1;

  /** Set a simple (no-value) token */
  set(tp: number): void {
    this.type = tp;
    this.integerValue = 0n;
    this.stringValue = null;
  }

  /** Set a token that carries a value extracted from the buffer */
  setWithValue(tp: number, text: string): void {
    this.type = tp;
    switch (tp) {
      case TokenType.integer: {
        // Parse integer supporting 0x hex prefix, 0 octal prefix, etc.
        const trimmed = text.trim();
        if (trimmed.startsWith('0x') || trimmed.startsWith('0X')) {
          this.integerValue = BigInt(trimmed);
        } else if (trimmed.startsWith('0') && trimmed.length > 1 && !trimmed.includes('8') && !trimmed.includes('9')) {
          // Octal
          this.integerValue = BigInt('0o' + trimmed.substring(1));
        } else {
          this.integerValue = BigInt(trimmed);
        }
        break;
      }
      case TokenType.identifier:
      case TokenType.stringval:
        this.stringValue = text;
        break;
      case TokenType.charconstant:
        if (text.length === 1) {
          this.integerValue = BigInt(text.charCodeAt(0));
        } else {
          // Backslash escape
          switch (text.charAt(1)) {
            case 'n': this.integerValue = 10n; break;
            case '0': this.integerValue = 0n;  break;
            case 'a': this.integerValue = 7n;  break;
            case 'b': this.integerValue = 8n;  break;
            case 't': this.integerValue = 9n;  break;
            case 'v': this.integerValue = 11n; break;
            case 'f': this.integerValue = 12n; break;
            case 'r': this.integerValue = 13n; break;
            default:
              this.integerValue = BigInt(text.charCodeAt(1));
              break;
          }
        }
        break;
      default:
        throw new LowlevelError('Bad internal grammar token set');
    }
  }

  setPosition(file: number, line: number, col: number): void {
    this.filenum = file;
    this.lineno = line;
    this.colno = col;
  }

  getType(): number { return this.type; }
  getInteger(): bigint { return this.integerValue; }
  getString(): string | null { return this.stringValue; }
  getLineNo(): number { return this.lineno; }
  getColNo(): number { return this.colno; }
  getFileNum(): number { return this.filenum; }
}

// ---------------------------------------------------------------------------
// GrammarLexer — finite-state tokeniser
// ---------------------------------------------------------------------------

const enum LexState {
  start,
  slash,
  dot1,
  dot2,
  dot3,
  punctuation,
  endofline_comment,
  c_comment,
  doublequote,
  doublequoteend,
  singlequote,
  singlequoteend,
  singlebackslash,
  number,
  identifier,
}

/**
 * Character-level lexer.  Reads from a string (representing a pushed
 * "file" or stream) and emits `GrammarToken` instances.
 */
export class GrammarLexer {
  private filenamemap: Map<number, string> = new Map();
  private streammap: Map<number, string> = new Map();   // maps filenum → full source text
  private streampos: Map<number, number> = new Map();    // maps filenum → current read position
  private filestack: number[] = [];
  private buffersize: number;
  private buffer: string = '';
  private bufstart: number = 0;
  private bufend: number = 0;
  private curlineno: number = 0;
  private input: string = '';
  private inputPos: number = 0;
  private _endoffile: boolean = true;
  private state: LexState = LexState.start;
  private _error: string = '';

  constructor(maxbuffer: number) {
    this.buffersize = maxbuffer;
  }

  clear(): void {
    this.filenamemap.clear();
    this.streammap.clear();
    this.streampos.clear();
    this.filestack = [];
    this.buffer = '';
    this.bufstart = 0;
    this.bufend = 0;
    this.curlineno = 0;
    this.state = LexState.start;
    this.input = '';
    this.inputPos = 0;
    this._endoffile = true;
    this._error = '';
  }

  getError(): string { return this._error; }
  private setError(err: string): void { this._error = err; }

  pushFile(filename: string, text: string): void {
    const filenum = this.filenamemap.size;
    this.filenamemap.set(filenum, filename);
    this.streammap.set(filenum, text);
    this.streampos.set(filenum, 0);
    this.filestack.push(filenum);
    this.input = text;
    this.inputPos = 0;
    this._endoffile = false;
  }

  popFile(): void {
    this.filestack.pop();
    if (this.filestack.length === 0) {
      this._endoffile = true;
      return;
    }
    const filenum = this.filestack[this.filestack.length - 1];
    this.input = this.streammap.get(filenum)!;
    this.inputPos = this.streampos.get(filenum)!;
  }

  writeLocation(s: { write(s: string): void }, line: number, filenum: number): void {
    s.write(` at line ${line}`);
    const fname = this.filenamemap.get(filenum);
    if (fname !== undefined) {
      s.write(` in ${fname}`);
    }
  }

  writeTokenLocation(s: { write(s: string): void }, line: number, colno: number): void {
    if (line !== this.curlineno) return;
    s.write(this.buffer.substring(0, this.bufend));
    s.write('\n');
    for (let i = 0; i < colno; ++i) s.write(' ');
    s.write('^--\n');
  }

  private bumpLine(): void {
    this.curlineno += 1;
    this.bufstart = 0;
    this.bufend = 0;
    this.buffer = '';
  }

  /**
   * Core finite-state machine.  Given a lookahead character, advance
   * the state and return a resolved token type (nonzero) or 0 if
   * the character was consumed without completing a token.
   */
  private moveState(lookahead: string): number {
    let ch = lookahead;
    let newline = false;
    const code = ch.charCodeAt(0);

    // Normalise whitespace / control chars
    if (code < 32) {
      if (code === 9 || code === 11 || code === 12 || code === 13) {
        ch = ' ';
      } else if (code === 10) {
        newline = true;
        ch = ' ';
      } else {
        this.setError('Illegal character');
        return TokenType.badtoken;
      }
    } else if (code >= 127) {
      this.setError('Illegal character');
      return TokenType.badtoken;
    }

    let res = 0;
    let syntaxerror = false;

    switch (this.state) {
      case LexState.start:
        switch (ch) {
          case '/':
            this.state = LexState.slash;
            break;
          case '.':
            this.state = LexState.dot1;
            break;
          case '*': case ',': case '(': case ')':
          case '[': case ']': case '{': case '}':
          case ';': case '=':
            this.state = LexState.punctuation;
            this.bufstart = this.bufend - 1;
            break;
          case '-':
          case '0': case '1': case '2': case '3': case '4':
          case '5': case '6': case '7': case '8': case '9':
            this.state = LexState.number;
            this.bufstart = this.bufend - 1;
            break;
          case ' ':
            break;   // Ignore whitespace in start state
          case '"':
            this.state = LexState.doublequote;
            this.bufstart = this.bufend - 1;
            break;
          case "'":
            this.state = LexState.singlequote;
            break;
          default:
            if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch === '_') {
              this.state = LexState.identifier;
              this.bufstart = this.bufend - 1;
            } else {
              this.setError('Illegal character');
              return TokenType.badtoken;
            }
            break;
        }
        break;

      case LexState.slash:
        if (ch === '*')
          this.state = LexState.c_comment;
        else if (ch === '/')
          this.state = LexState.endofline_comment;
        else
          syntaxerror = true;
        break;

      case LexState.dot1:
        if (ch === '.') this.state = LexState.dot2;
        else syntaxerror = true;
        break;

      case LexState.dot2:
        if (ch === '.') this.state = LexState.dot3;
        else syntaxerror = true;
        break;

      case LexState.dot3:
        this.state = LexState.start;
        res = TokenType.dotdotdot;
        break;

      case LexState.punctuation:
        this.state = LexState.start;
        res = this.buffer.charCodeAt(this.bufstart);
        break;

      case LexState.endofline_comment:
        if (newline) this.state = LexState.start;
        break;

      case LexState.c_comment:
        if (ch === '/') {
          if (this.bufend > 1 && this.buffer.charAt(this.bufend - 2) === '*')
            this.state = LexState.start;
        }
        break;

      case LexState.doublequote:
        if (ch === '"')
          this.state = LexState.doublequoteend;
        break;

      case LexState.doublequoteend:
        this.state = LexState.start;
        res = TokenType.stringval;
        break;

      case LexState.singlequote:
        if (ch === '\\')
          this.state = LexState.singlebackslash;
        else if (ch === "'")
          this.state = LexState.singlequoteend;
        break;

      case LexState.singlequoteend:
        this.state = LexState.start;
        res = TokenType.charconstant;
        break;

      case LexState.singlebackslash:
        this.state = LexState.singlequote;
        break;

      case LexState.number:
        if (ch === 'x') {
          if ((this.bufend - this.bufstart) !== 2 || this.buffer.charAt(this.bufstart) !== '0')
            syntaxerror = true;
        } else if ((ch >= '0' && ch <= '9') ||
                   (ch >= 'A' && ch <= 'Z') ||
                   (ch >= 'a' && ch <= 'z') ||
                   ch === '_') {
          // still in number
        } else {
          this.state = LexState.start;
          res = TokenType.integer;
        }
        break;

      case LexState.identifier:
        if ((ch >= '0' && ch <= '9') ||
            (ch >= 'A' && ch <= 'Z') ||
            (ch >= 'a' && ch <= 'z') ||
            ch === '_' || ch === ':') {
          // still in identifier
        } else {
          this.state = LexState.start;
          res = TokenType.identifier;
        }
        break;
    }

    if (syntaxerror) {
      this.setError('Syntax error');
      return TokenType.badtoken;
    }
    if (newline) this.bumpLine();
    return res;
  }

  private establishToken(token: GrammarToken, val: number): void {
    if (val < TokenType.integer) {
      token.set(val);
    } else {
      const text = this.buffer.substring(this.bufstart, this.bufend - 1);
      token.setWithValue(val, text);
    }
    token.setPosition(
      this.filestack[this.filestack.length - 1],
      this.curlineno,
      this.bufstart,
    );
  }

  /** Read the next character from the current input stream, or null on EOF */
  private readChar(): string | null {
    if (this.inputPos >= this.input.length) return null;
    const ch = this.input.charAt(this.inputPos);
    this.inputPos++;
    // Save position back for potential popFile
    const filenum = this.filestack[this.filestack.length - 1];
    this.streampos.set(filenum, this.inputPos);
    return ch;
  }

  /** Get the next token from the input stream */
  getNextToken(token: GrammarToken): void {
    let tok: number = TokenType.badtoken;
    let firsttimethru = true;

    if (this._endoffile) {
      token.set(TokenType.endoffile);
      return;
    }

    do {
      let nextchar: string;
      if (!firsttimethru || this.bufend === 0) {
        if (this.bufend >= this.buffersize) {
          this.setError('Line too long');
          tok = TokenType.badtoken;
          break;
        }
        const ch = this.readChar();
        if (ch === null) {
          this._endoffile = true;
          break;
        }
        nextchar = ch;
        this.buffer += nextchar;
        this.bufend++;
      } else {
        nextchar = this.buffer.charAt(this.bufend - 1);
      }
      tok = this.moveState(nextchar);
      firsttimethru = false;
    } while (tok === 0);

    if (this._endoffile) {
      // Simulate a trailing space to resolve the final token
      this.buffer += ' ';
      this.bufend++;
      tok = this.moveState(' ');
      if (tok === 0 && this.state !== LexState.start && this.state !== LexState.endofline_comment) {
        this.setError('Incomplete token');
        tok = TokenType.badtoken;
      }
    }

    this.establishToken(token, tok);
  }
}

// ---------------------------------------------------------------------------
// TypeModifier hierarchy
// ---------------------------------------------------------------------------

export const enum ModifierType {
  pointer_mod  = 0,
  array_mod    = 1,
  function_mod = 2,
  struct_mod   = 3,
  enum_mod     = 4,
}

export abstract class TypeModifier {
  abstract getType(): ModifierType;
  abstract isValid(): boolean;
  abstract modType(base: Datatype | null, decl: TypeDeclarator, glb: Architecture): Datatype;
}

export class PointerModifier extends TypeModifier {
  private flags: number;

  constructor(fl: number) {
    super();
    this.flags = fl;
  }

  getType(): ModifierType { return ModifierType.pointer_mod; }
  isValid(): boolean { return true; }

  modType(base: Datatype | null, _decl: TypeDeclarator, glb: Architecture): Datatype {
    const addrsize: number = glb.getDefaultDataSpace().getAddrSize();
    const wordsize: number = glb.getDefaultDataSpace().getWordSize();
    return glb.types.getTypePointer(addrsize, base!, wordsize);
  }
}

export class ArrayModifier extends TypeModifier {
  private flags: number;
  private arraysize: number;

  constructor(fl: number, as: number) {
    super();
    this.flags = fl;
    this.arraysize = as;
  }

  getType(): ModifierType { return ModifierType.array_mod; }
  isValid(): boolean { return this.arraysize > 0; }

  modType(base: Datatype | null, _decl: TypeDeclarator, glb: Architecture): Datatype {
    return glb.types.getTypeArray(this.arraysize, base!);
  }
}

export class FunctionModifier extends TypeModifier {
  private paramlist: (TypeDeclarator | null)[];
  private _dotdotdot: boolean;

  constructor(p: (TypeDeclarator | null)[], dtdtdt: boolean) {
    super();
    this.paramlist = [...p];
    // If single parameter is void with no modifiers, treat as empty param list
    if (this.paramlist.length === 1) {
      const decl = this.paramlist[0];
      if (decl !== null && decl.numModifiers() === 0) {
        const ct = decl.getBaseType();
        if (ct !== null && ct.getMetatype() === type_metatype.TYPE_VOID) {
          this.paramlist = [];
        }
      }
    }
    this._dotdotdot = dtdtdt;
  }

  getType(): ModifierType { return ModifierType.function_mod; }

  isValid(): boolean {
    for (const decl of this.paramlist) {
      if (decl === null) continue;
      if (!decl.isValid()) return false;
      if (decl.numModifiers() === 0) {
        const ct = decl.getBaseType();
        if (ct !== null && ct.getMetatype() === type_metatype.TYPE_VOID)
          return false;  // Extra void type
      }
    }
    return true;
  }

  getInTypes(glb: Architecture): Datatype[] {
    const intypes: Datatype[] = [];
    for (const decl of this.paramlist) {
      if (decl !== null) {
        intypes.push(decl.buildType(glb));
      }
    }
    return intypes;
  }

  getInNames(): string[] {
    const innames: string[] = [];
    for (const decl of this.paramlist) {
      if (decl !== null) {
        innames.push(decl.getIdentifier());
      }
    }
    return innames;
  }

  isDotdotdot(): boolean { return this._dotdotdot; }

  modType(base: Datatype | null, decl: TypeDeclarator, glb: Architecture): Datatype {
    const proto: any = {};

    if (base === null) {
      proto.outtype = glb.types.getTypeVoid();
    } else {
      proto.outtype = base;
    }

    // Varargs encoded as extra null pointer in paramlist
    proto.firstVarArgSlot = -1;
    if (this.paramlist.length > 0 && this.paramlist[this.paramlist.length - 1] === null) {
      proto.firstVarArgSlot = this.paramlist.length - 1;
    }

    proto.intypes = this.getInTypes(glb);
    proto.model = decl.getModel(glb);
    return glb.types.getTypeCode(proto);
  }
}

// ---------------------------------------------------------------------------
// Enumerator — a single constant in an enum definition
// ---------------------------------------------------------------------------

export class Enumerator {
  enumconstant: string;
  constantassigned: boolean;
  value: bigint;

  constructor(nm: string, val?: bigint) {
    this.enumconstant = nm;
    if (val !== undefined) {
      this.constantassigned = true;
      this.value = val;
    } else {
      this.constantassigned = false;
      this.value = 0n;
    }
  }
}

// ---------------------------------------------------------------------------
// TypeSpecifiers — accumulated declaration specifiers
// ---------------------------------------------------------------------------

export class TypeSpecifiers {
  type_specifier: Datatype | null = null;
  function_specifier: string = '';
  flags: number = 0;
}

// ---------------------------------------------------------------------------
// TypeDeclarator — a declarator with modifiers and a base type
// ---------------------------------------------------------------------------

export class TypeDeclarator {
  /** @internal */ mods: TypeModifier[] = [];
  /** @internal */ basetype: Datatype | null = null;
  /** @internal */ ident: string = '';
  /** @internal */ model: string = '';     // name of calling convention model
  /** @internal */ flags: number = 0;

  constructor(nm?: string) {
    if (nm !== undefined) {
      this.ident = nm;
    }
  }

  getBaseType(): Datatype | null { return this.basetype; }
  numModifiers(): number { return this.mods.length; }
  getIdentifier(): string { return this.ident; }

  getModel(glb: Architecture): ProtoModel | null {
    let protomodel: ProtoModel | null = null;
    if (this.model.length !== 0) {
      protomodel = glb.getModel(this.model);
    }
    if (protomodel === null) {
      protomodel = glb.defaultfp;
    }
    return protomodel;
  }

  getPrototype(pieces: PrototypePieces, glb: Architecture): boolean {
    let mod: TypeModifier | null = null;
    if (this.mods.length > 0) {
      mod = this.mods[0];
    }
    if (mod === null || mod.getType() !== ModifierType.function_mod)
      return false;
    const fmod = mod as FunctionModifier;

    pieces.model = this.getModel(glb);
    pieces.name = this.ident;
    pieces.intypes = fmod.getInTypes(glb);
    pieces.innames = fmod.getInNames();
    pieces.firstVarArgSlot = fmod.isDotdotdot() ? pieces.intypes.length : -1;

    // Construct the output type
    let outtype: Datatype | null = this.basetype;
    for (let i = this.mods.length - 1; i > 0; --i) {
      outtype = this.mods[i].modType(outtype, this, glb);
    }
    pieces.outtype = outtype;
    return true;
  }

  hasProperty(mask: number): boolean { return (this.flags & mask) !== 0; }

  buildType(glb: Architecture): Datatype {
    let restype: Datatype | null = this.basetype;
    for (let i = this.mods.length - 1; i >= 0; --i) {
      restype = this.mods[i].modType(restype, this, glb);
    }
    return restype!;
  }

  isValid(): boolean {
    if (this.basetype === null) return false;

    let count = 0;
    if ((this.flags & CParse.f_typedef) !== 0)  count++;
    if ((this.flags & CParse.f_extern) !== 0)   count++;
    if ((this.flags & CParse.f_static) !== 0)   count++;
    if ((this.flags & CParse.f_auto) !== 0)     count++;
    if ((this.flags & CParse.f_register) !== 0) count++;
    if (count > 1) throw new ParseError('Multiple storage specifiers');

    count = 0;
    if ((this.flags & CParse.f_const) !== 0)    count++;
    if ((this.flags & CParse.f_restrict) !== 0) count++;
    if ((this.flags & CParse.f_volatile) !== 0) count++;
    if (count > 1) throw new ParseError('Multiple type qualifiers');

    for (const mod of this.mods) {
      if (!mod.isValid()) return false;
    }
    return true;
  }
}

// ---------------------------------------------------------------------------
// CParse — the main recursive-descent parser
// ---------------------------------------------------------------------------

export class CParse {
  // Storage-class / qualifier / specifier flag constants
  static readonly f_typedef  = 1;
  static readonly f_extern   = 2;
  static readonly f_static   = 4;
  static readonly f_auto     = 8;
  static readonly f_register = 16;
  static readonly f_const    = 32;
  static readonly f_restrict = 64;
  static readonly f_volatile = 128;
  static readonly f_inline   = 256;
  static readonly f_struct   = 512;
  static readonly f_union    = 1024;
  static readonly f_enum     = 2048;

  // Document type constants
  static readonly doc_declaration            = 0;
  static readonly doc_parameter_declaration  = 1;

  // --- Fields ---
  private glb: Architecture;
  private keywords: Map<string, number> = new Map();
  private lexer: GrammarLexer;
  private lineno: number = -1;
  private colno: number = -1;
  private filenum: number = -1;

  private lastdecls: TypeDeclarator[] | null = null;
  private firsttoken: number = -1;
  private lasterror: string = '';

  // --- Current token look-ahead state ---
  private currentToken: number = 0;       // HighToken value of current token
  private tokenString: string | null = null;   // string payload (for IDENTIFIER etc.)
  private tokenNumber: bigint = 0n;       // numeric payload (for NUMBER)
  private tokenType: Datatype | null = null;   // type payload (for TYPE_NAME)

  // Internal yacc-like lval used during lexing
  private yylval: {
    flags: number;
    dec: TypeDeclarator | null;
    declist: TypeDeclarator[] | null;
    spec: TypeSpecifiers | null;
    ptrspec: number[] | null;
    type: Datatype | null;
    enumer: Enumerator | null;
    vecenum: Enumerator[] | null;
    str: string | null;
    i: bigint;
  } = {
    flags: 0,
    dec: null,
    declist: null,
    spec: null,
    ptrspec: null,
    type: null,
    enumer: null,
    vecenum: null,
    str: null,
    i: 0n,
  };

  constructor(g: Architecture, maxbuf: number) {
    this.glb = g;
    this.lexer = new GrammarLexer(maxbuf);
    this.keywords.set('typedef',  CParse.f_typedef);
    this.keywords.set('extern',   CParse.f_extern);
    this.keywords.set('static',   CParse.f_static);
    this.keywords.set('auto',     CParse.f_auto);
    this.keywords.set('register', CParse.f_register);
    this.keywords.set('const',    CParse.f_const);
    this.keywords.set('restrict', CParse.f_restrict);
    this.keywords.set('volatile', CParse.f_volatile);
    this.keywords.set('inline',   CParse.f_inline);
    this.keywords.set('struct',   CParse.f_struct);
    this.keywords.set('union',    CParse.f_union);
    this.keywords.set('enum',     CParse.f_enum);
  }

  clear(): void {
    this.lasterror = '';
    this.lastdecls = null;
    this.lexer.clear();
    this.firsttoken = -1;
  }

  getError(): string { return this.lasterror; }

  setResultDeclarations(val: TypeDeclarator[]): void { this.lastdecls = val; }
  getResultDeclarations(): TypeDeclarator[] | null { return this.lastdecls; }

  // =========================================================================
  // Error handling
  // =========================================================================

  private setError(msg: string): void {
    let s = msg;
    const parts: string[] = [msg];
    // Build location string
    const loc = { buf: '' as string, write(str: string) { this.buf += str; } };
    this.lexer.writeLocation(loc, this.lineno, this.filenum);
    parts.push(loc.buf);
    parts.push('\n');
    const tok = { buf: '' as string, write(str: string) { this.buf += str; } };
    this.lexer.writeTokenLocation(tok, this.lineno, this.colno);
    parts.push(tok.buf);
    this.lasterror = parts.join('');
  }

  // =========================================================================
  // Keyword / identifier classification (corresponds to lookupIdentifier)
  // =========================================================================

  private lookupIdentifier(nm: string): number {
    const kw = this.keywords.get(nm);
    if (kw !== undefined) {
      switch (kw) {
        case CParse.f_typedef:
        case CParse.f_extern:
        case CParse.f_static:
        case CParse.f_auto:
        case CParse.f_register:
          return HighToken.STORAGE_CLASS_SPECIFIER;
        case CParse.f_const:
        case CParse.f_restrict:
        case CParse.f_volatile:
          return HighToken.TYPE_QUALIFIER;
        case CParse.f_inline:
          return HighToken.FUNCTION_SPECIFIER;
        case CParse.f_struct:
          return HighToken.STRUCT;
        case CParse.f_union:
          return HighToken.UNION;
        case CParse.f_enum:
          return HighToken.ENUM;
      }
    }
    const tp: Datatype | null = this.glb.types.findByName(nm);
    if (tp !== null && tp !== undefined) {
      this.yylval.type = tp;
      return HighToken.TYPE_NAME;
    }
    if (this.glb.hasModel && this.glb.hasModel(nm))
      return HighToken.FUNCTION_SPECIFIER;
    return HighToken.IDENTIFIER;
  }

  // =========================================================================
  // Low-level lex() — reads one classified token
  // =========================================================================

  private lex(): number {
    if (this.firsttoken !== -1) {
      const retval = this.firsttoken;
      this.firsttoken = -1;
      return retval;
    }
    if (this.lasterror.length !== 0) return HighToken.BADTOKEN;

    const tok = new GrammarToken();
    this.lexer.getNextToken(tok);
    this.lineno = tok.getLineNo();
    this.colno = tok.getColNo();
    this.filenum = tok.getFileNum();

    switch (tok.getType()) {
      case TokenType.integer:
      case TokenType.charconstant:
        this.yylval.i = tok.getInteger();
        return HighToken.NUMBER;
      case TokenType.identifier: {
        this.yylval.str = tok.getString();
        return this.lookupIdentifier(this.yylval.str!);
      }
      case TokenType.stringval:
        this.setError('Illegal string constant');
        return HighToken.BADTOKEN;
      case TokenType.dotdotdot:
        return HighToken.DOTDOTDOT;
      case TokenType.badtoken:
        this.setError(this.lexer.getError());
        return HighToken.BADTOKEN;
      case TokenType.endoffile:
        return HighToken.EOF_TOKEN;
      default:
        return tok.getType();
    }
  }

  // =========================================================================
  // Advance / match helpers for recursive descent
  // =========================================================================

  /** Advance to the next token, storing payloads in instance fields */
  private advance(): void {
    this.currentToken = this.lex();
    // Copy payloads from yylval based on token type
    switch (this.currentToken) {
      case HighToken.NUMBER:
        this.tokenNumber = this.yylval.i;
        break;
      case HighToken.IDENTIFIER:
      case HighToken.STORAGE_CLASS_SPECIFIER:
      case HighToken.TYPE_QUALIFIER:
      case HighToken.FUNCTION_SPECIFIER:
        this.tokenString = this.yylval.str;
        break;
      case HighToken.TYPE_NAME:
        this.tokenType = this.yylval.type;
        break;
    }
  }

  /** Check whether the current token matches `expected` */
  private check(expected: number): boolean {
    return this.currentToken === expected;
  }

  /** Consume the current token if it matches, and advance.  Returns true on match. */
  private match(expected: number): boolean {
    if (this.currentToken === expected) {
      this.advance();
      return true;
    }
    return false;
  }

  /** Require the current token to be `expected`; throw on mismatch */
  private expect(expected: number): void {
    if (!this.match(expected)) {
      this.setError('Syntax error');
      throw new ParseError(this.lasterror);
    }
  }

  // =========================================================================
  // CParse helper/builder methods (translated from grammar.cc)
  // =========================================================================

  convertFlag(str: string): number {
    const kw = this.keywords.get(str);
    if (kw !== undefined) return kw;
    this.setError('Unknown qualifier');
    return 0;
  }

  newSpecifier(): TypeSpecifiers {
    return new TypeSpecifiers();
  }

  addSpecifier(spec: TypeSpecifiers, str: string): TypeSpecifiers {
    const flag = this.convertFlag(str);
    spec.flags |= flag;
    return spec;
  }

  addTypeSpecifier(spec: TypeSpecifiers, tp: Datatype): TypeSpecifiers {
    if (spec.type_specifier !== null) {
      this.setError('Multiple type specifiers');
    }
    spec.type_specifier = tp;
    return spec;
  }

  addFuncSpecifier(spec: TypeSpecifiers, str: string): TypeSpecifiers {
    const kw = this.keywords.get(str);
    if (kw !== undefined) {
      spec.flags |= kw;
    } else {
      if (spec.function_specifier.length !== 0)
        this.setError('Multiple parameter models');
      spec.function_specifier = str;
    }
    return spec;
  }

  mergeSpecDec(spec: TypeSpecifiers, dec?: TypeDeclarator): TypeDeclarator {
    if (dec === undefined) {
      dec = new TypeDeclarator();
    }
    dec.basetype = spec.type_specifier;
    dec.model = spec.function_specifier;
    dec.flags |= spec.flags;
    return dec;
  }

  mergeSpecDecVec(spec: TypeSpecifiers, declist?: TypeDeclarator[]): TypeDeclarator[] {
    if (declist === undefined) {
      declist = [];
      const dec = new TypeDeclarator();
      declist.push(dec);
    }
    for (const dec of declist) {
      this.mergeSpecDec(spec, dec);
    }
    return declist;
  }

  mergePointer(ptr: number[], dec: TypeDeclarator): TypeDeclarator {
    for (const fl of ptr) {
      const newmod = new PointerModifier(fl);
      dec.mods.push(newmod);
    }
    return dec;
  }

  newDeclarator(str?: string): TypeDeclarator {
    if (str !== undefined) {
      return new TypeDeclarator(str);
    }
    return new TypeDeclarator();
  }

  newArray(dec: TypeDeclarator, flags: number, num: bigint): TypeDeclarator {
    const newmod = new ArrayModifier(flags, Number(num));
    dec.mods.push(newmod);
    return dec;
  }

  newFunc(dec: TypeDeclarator, declist: (TypeDeclarator | null)[]): TypeDeclarator {
    let dotdotdot = false;
    if (declist.length > 0) {
      if (declist[declist.length - 1] === null) {
        dotdotdot = true;
        declist.pop();
      }
    }
    const newmod = new FunctionModifier(declist, dotdotdot);
    dec.mods.push(newmod);
    return dec;
  }

  newStruct(ident: string, declist: TypeDeclarator[]): Datatype | null {
    const res = this.glb.types.getTypeStruct(ident);
    const sublist: any[] = [];

    for (const decl of declist) {
      if (!decl.isValid()) {
        this.setError('Invalid structure declarator');
        this.glb.types.destroyType(res);
        return null;
      }
      sublist.push({
        offset: -1,
        ordinal: -1,
        name: decl.getIdentifier(),
        type: decl.buildType(this.glb),
      });
    }

    try {
      const newSize = { val: 0 };
      const newAlign = { val: 0 };
      TypeStruct.assignFieldOffsets(sublist, newSize, newAlign);
      this.glb.types.setFields(sublist, res, newSize.val, newAlign.val, 0);
    } catch (err: any) {
      this.setError(err.explain || err.message);
      this.glb.types.destroyType(res);
      return null;
    }
    return res;
  }

  oldStruct(ident: string): Datatype | null {
    const res = this.glb.types.findByName(ident);
    if (res === null || res === undefined || res.getMetatype() !== type_metatype.TYPE_STRUCT) {
      this.setError('Identifier does not represent a struct as required');
      return null;
    }
    return res;
  }

  newUnion(ident: string, declist: TypeDeclarator[]): Datatype | null {
    const res = this.glb.types.getTypeUnion(ident);
    const sublist: any[] = [];

    for (let i = 0; i < declist.length; ++i) {
      const decl = declist[i];
      if (!decl.isValid()) {
        this.setError('Invalid union declarator');
        this.glb.types.destroyType(res);
        return null;
      }
      sublist.push({
        offset: 0,
        ordinal: i,
        name: decl.getIdentifier(),
        type: decl.buildType(this.glb),
      });
    }

    try {
      const newSize = { val: 0 };
      const newAlign = { val: 0 };
      TypeUnion.assignFieldOffsets(sublist, newSize, newAlign, res);
      this.glb.types.setFields(sublist, res, newSize.val, newAlign.val, 0);
    } catch (err: any) {
      this.setError(err.explain || err.message);
      this.glb.types.destroyType(res);
      return null;
    }
    return res;
  }

  oldUnion(ident: string): Datatype | null {
    const res = this.glb.types.findByName(ident);
    if (res === null || res === undefined || res.getMetatype() !== type_metatype.TYPE_UNION) {
      this.setError('Identifier does not represent a union as required');
      return null;
    }
    return res;
  }

  newEnumerator(ident: string, val?: bigint): Enumerator {
    if (val !== undefined) {
      return new Enumerator(ident, val);
    }
    return new Enumerator(ident);
  }

  newEnum(ident: string, vecenum: Enumerator[]): Datatype | null {
    const res = this.glb.types.getTypeEnum(ident);
    const namelist: string[] = [];
    const vallist: bigint[] = [];
    const assignlist: boolean[] = [];

    for (const enumer of vecenum) {
      namelist.push(enumer.enumconstant);
      vallist.push(enumer.value);
      assignlist.push(enumer.constantassigned);
    }

    try {
      const namemap = new Map<bigint, string>();
      // TypeEnum.assignValues populates namemap
      this.glb.types.assignEnumValues(namemap, namelist, vallist, assignlist, res);
      this.glb.types.setEnumValues(namemap, res);
    } catch (err: any) {
      this.setError(err.explain || err.message);
      this.glb.types.destroyType(res);
      return null;
    }
    return res;
  }

  oldEnum(ident: string): Datatype | null {
    const res = this.glb.types.findByName(ident);
    if (res === null || res === undefined || !res.isEnumType()) {
      this.setError('Identifier does not represent an enum as required');
      return null;
    }
    return res;
  }

  // =========================================================================
  //  FIRST-set helpers
  //
  //  These predicates determine which tokens can start various grammar
  //  non-terminals.  They are essential for the recursive-descent parser to
  //  decide which alternative to take in each production.
  // =========================================================================

  /** Can the current token start a declaration_specifiers? */
  private isDeclarationSpecifierStart(): boolean {
    switch (this.currentToken) {
      case HighToken.STORAGE_CLASS_SPECIFIER:
      case HighToken.TYPE_QUALIFIER:
      case HighToken.FUNCTION_SPECIFIER:
      case HighToken.TYPE_NAME:
      case HighToken.STRUCT:
      case HighToken.UNION:
      case HighToken.ENUM:
        return true;
      default:
        return false;
    }
  }

  /** Can the current token start a type_specifier? */
  private isTypeSpecifierStart(): boolean {
    switch (this.currentToken) {
      case HighToken.TYPE_NAME:
      case HighToken.STRUCT:
      case HighToken.UNION:
      case HighToken.ENUM:
        return true;
      default:
        return false;
    }
  }

  /** Can the current token start a specifier_qualifier (subset of decl spec)? */
  private isSpecifierQualifierStart(): boolean {
    switch (this.currentToken) {
      case HighToken.TYPE_QUALIFIER:
      case HighToken.TYPE_NAME:
      case HighToken.STRUCT:
      case HighToken.UNION:
      case HighToken.ENUM:
        return true;
      default:
        return false;
    }
  }

  /** Can the current token start a declarator? */
  private isDeclaratorStart(): boolean {
    return this.currentToken === HighToken.IDENTIFIER ||
           this.currentToken === TokenType.openparen ||
           this.currentToken === TokenType.star;
  }

  /** Can the current token start a direct_declarator? */
  private isDirectDeclaratorStart(): boolean {
    return this.currentToken === HighToken.IDENTIFIER ||
           this.currentToken === TokenType.openparen;
  }

  /** Can the current token start an abstract_declarator? */
  private isAbstractDeclaratorStart(): boolean {
    return this.currentToken === TokenType.star ||
           this.currentToken === TokenType.openparen ||
           this.currentToken === TokenType.openbracket;
  }

  /** Can the current token start a direct_abstract_declarator? */
  private isDirectAbstractDeclaratorStart(): boolean {
    return this.currentToken === TokenType.openparen ||
           this.currentToken === TokenType.openbracket;
  }

  // =========================================================================
  //  PARSER — Recursive descent methods
  //
  //  Grammar (from grammar.y), rewritten to eliminate left-recursion and
  //  factor left-common prefixes where needed.
  // =========================================================================

  // -----------------------------------------------------------------------
  //  document
  //    : DECLARATION_RESULT declaration
  //    | PARAM_RESULT parameter_declaration
  //  ;
  // -----------------------------------------------------------------------
  private parseDocument(): boolean {
    this.advance();  // prime the look-ahead

    if (this.match(HighToken.DECLARATION_RESULT)) {
      const decl = this.parseDeclaration();
      if (decl === null) return false;
      this.setResultDeclarations(decl);
      return true;
    }
    if (this.match(HighToken.PARAM_RESULT)) {
      const dec = this.parseParameterDeclaration();
      if (dec === null) return false;
      const res: TypeDeclarator[] = [];
      res.push(dec);
      this.setResultDeclarations(res);
      return true;
    }
    this.setError('Syntax error');
    return false;
  }

  // -----------------------------------------------------------------------
  //  declaration
  //    : declaration_specifiers ';'
  //    | declaration_specifiers init_declarator_list ';'
  //  ;
  // -----------------------------------------------------------------------
  private parseDeclaration(): TypeDeclarator[] | null {
    const spec = this.parseDeclarationSpecifiers();
    if (spec === null) return null;

    if (this.match(TokenType.semicolon)) {
      // declaration_specifiers ';'
      return this.mergeSpecDecVec(spec);
    }

    // declaration_specifiers init_declarator_list ';'
    const declist = this.parseInitDeclaratorList();
    if (declist === null) return null;
    this.expect(TokenType.semicolon);
    return this.mergeSpecDecVec(spec, declist);
  }

  // -----------------------------------------------------------------------
  //  declaration_specifiers
  //    : (STORAGE_CLASS_SPECIFIER | type_specifier | TYPE_QUALIFIER
  //       | FUNCTION_SPECIFIER)+
  //
  //  The original yacc grammar is right-recursive (each specifier
  //  followed by optional declaration_specifiers).  In a recursive
  //  descent parser we use a simple loop.
  // -----------------------------------------------------------------------
  private parseDeclarationSpecifiers(): TypeSpecifiers | null {
    if (!this.isDeclarationSpecifierStart()) {
      this.setError('Syntax error');
      return null;
    }

    const spec = this.newSpecifier();

    while (this.isDeclarationSpecifierStart()) {
      switch (this.currentToken) {
        case HighToken.STORAGE_CLASS_SPECIFIER: {
          const str = this.tokenString!;
          this.advance();
          this.addSpecifier(spec, str);
          break;
        }
        case HighToken.TYPE_QUALIFIER: {
          const str = this.tokenString!;
          this.advance();
          this.addSpecifier(spec, str);
          break;
        }
        case HighToken.FUNCTION_SPECIFIER: {
          const str = this.tokenString!;
          this.advance();
          this.addFuncSpecifier(spec, str);
          break;
        }
        case HighToken.TYPE_NAME:
        case HighToken.STRUCT:
        case HighToken.UNION:
        case HighToken.ENUM: {
          const tp = this.parseTypeSpecifier();
          if (tp === null) return null;
          this.addTypeSpecifier(spec, tp);
          break;
        }
        default:
          // Should not reach here due to isDeclarationSpecifierStart guard
          break;
      }
    }
    return spec;
  }

  // -----------------------------------------------------------------------
  //  type_specifier
  //    : TYPE_NAME
  //    | struct_or_union_specifier
  //    | enum_specifier
  //  ;
  // -----------------------------------------------------------------------
  private parseTypeSpecifier(): Datatype | null {
    switch (this.currentToken) {
      case HighToken.TYPE_NAME: {
        const tp = this.tokenType!;
        this.advance();
        return tp;
      }
      case HighToken.STRUCT:
      case HighToken.UNION:
        return this.parseStructOrUnionSpecifier();
      case HighToken.ENUM:
        return this.parseEnumSpecifier();
      default:
        this.setError('Syntax error');
        return null;
    }
  }

  // -----------------------------------------------------------------------
  //  struct_or_union_specifier
  //    : STRUCT '{' struct_declaration_list '}'
  //    | STRUCT IDENTIFIER '{' struct_declaration_list '}'
  //    | STRUCT IDENTIFIER
  //    | UNION '{' struct_declaration_list '}'
  //    | UNION IDENTIFIER '{' struct_declaration_list '}'
  //    | UNION IDENTIFIER
  //  ;
  // -----------------------------------------------------------------------
  private parseStructOrUnionSpecifier(): Datatype | null {
    const isStruct = this.currentToken === HighToken.STRUCT;
    this.advance();  // consume STRUCT or UNION

    let ident: string | null = null;

    if (this.currentToken === HighToken.IDENTIFIER) {
      ident = this.tokenString!;
      this.advance();
    }

    if (this.match(TokenType.openbrace)) {
      // '{' struct_declaration_list '}'
      const declist = this.parseStructDeclarationList();
      if (declist === null) return null;
      this.expect(TokenType.closebrace);
      if (isStruct)
        return this.newStruct(ident ?? '', declist);
      else
        return this.newUnion(ident ?? '', declist);
    }

    // Just a tag reference: STRUCT IDENTIFIER  or  UNION IDENTIFIER
    if (ident === null) {
      this.setError('Syntax error');
      return null;
    }
    if (isStruct)
      return this.oldStruct(ident);
    else
      return this.oldUnion(ident);
  }

  // -----------------------------------------------------------------------
  //  struct_declaration_list
  //    : struct_declaration+
  //  ;
  //  struct_declaration
  //    : specifier_qualifier_list struct_declarator_list ';'
  //  ;
  // -----------------------------------------------------------------------
  private parseStructDeclarationList(): TypeDeclarator[] | null {
    const result: TypeDeclarator[] = [];

    do {
      const decls = this.parseStructDeclaration();
      if (decls === null) return null;
      for (const d of decls) result.push(d);
    } while (this.isSpecifierQualifierStart());

    return result;
  }

  private parseStructDeclaration(): TypeDeclarator[] | null {
    const spec = this.parseSpecifierQualifierList();
    if (spec === null) return null;
    const declist = this.parseStructDeclaratorList();
    if (declist === null) return null;
    this.expect(TokenType.semicolon);
    return this.mergeSpecDecVec(spec, declist);
  }

  // -----------------------------------------------------------------------
  //  specifier_qualifier_list
  //    : (type_specifier | TYPE_QUALIFIER)+
  //  ;
  // -----------------------------------------------------------------------
  private parseSpecifierQualifierList(): TypeSpecifiers | null {
    if (!this.isSpecifierQualifierStart()) {
      this.setError('Syntax error');
      return null;
    }

    const spec = this.newSpecifier();

    while (this.isSpecifierQualifierStart()) {
      if (this.currentToken === HighToken.TYPE_QUALIFIER) {
        const str = this.tokenString!;
        this.advance();
        this.addSpecifier(spec, str);
      } else {
        // type_specifier
        const tp = this.parseTypeSpecifier();
        if (tp === null) return null;
        this.addTypeSpecifier(spec, tp);
      }
    }
    return spec;
  }

  // -----------------------------------------------------------------------
  //  struct_declarator_list
  //    : struct_declarator (',' struct_declarator)*
  //  ;
  //  struct_declarator
  //    : declarator
  //  ;
  // -----------------------------------------------------------------------
  private parseStructDeclaratorList(): TypeDeclarator[] | null {
    const result: TypeDeclarator[] = [];

    const first = this.parseDeclarator();
    if (first === null) return null;
    result.push(first);

    while (this.match(TokenType.comma)) {
      const dec = this.parseDeclarator();
      if (dec === null) return null;
      result.push(dec);
    }
    return result;
  }

  // -----------------------------------------------------------------------
  //  enum_specifier
  //    : ENUM IDENTIFIER '{' enumerator_list ','? '}'
  //    | ENUM '{' enumerator_list ','? '}'
  //    | ENUM IDENTIFIER
  //  ;
  // -----------------------------------------------------------------------
  private parseEnumSpecifier(): Datatype | null {
    this.expect(HighToken.ENUM);   // already checked by caller; consume it

    let ident: string | null = null;

    if (this.currentToken === HighToken.IDENTIFIER) {
      ident = this.tokenString!;
      this.advance();
    }

    if (this.match(TokenType.openbrace)) {
      const vecenum = this.parseEnumeratorList();
      if (vecenum === null) return null;
      // optional trailing comma
      this.match(TokenType.comma);
      this.expect(TokenType.closebrace);
      return this.newEnum(ident ?? '', vecenum);
    }

    // Just a tag reference: ENUM IDENTIFIER
    if (ident === null) {
      this.setError('Syntax error');
      return null;
    }
    return this.oldEnum(ident);
  }

  // -----------------------------------------------------------------------
  //  enumerator_list
  //    : enumerator (',' enumerator)*
  //  ;
  //  enumerator
  //    : IDENTIFIER
  //    | IDENTIFIER '=' NUMBER
  //  ;
  // -----------------------------------------------------------------------
  private parseEnumeratorList(): Enumerator[] | null {
    const result: Enumerator[] = [];

    const first = this.parseEnumerator();
    if (first === null) return null;
    result.push(first);

    while (this.currentToken === TokenType.comma) {
      // Peek ahead: if the next token after ',' is '}', this is a trailing
      // comma (allowed by the grammar), so don't consume.
      // We need to be careful: we can only peek by trying to match.
      // Save state and tentatively consume comma.
      // Actually, the grammar allows trailing comma followed by '}'.
      // We handle it by checking if IDENTIFIER follows the comma.
      // If not, break out (the comma is trailing and handled by caller).

      // Look-ahead: if current is comma, check whether it's followed by
      // an enumerator (IDENTIFIER) or closing brace.
      // Since we use single-token look-ahead we peek via a simple check:
      // the caller (parseEnumSpecifier) will try match(comma) after us.
      // For the `enumerator_list ',' enumerator` rule, the comma must
      // be followed by IDENTIFIER.  We'll save the comma and see.
      //
      // Strategy: consume comma.  If next token is IDENTIFIER, parse
      // enumerator.  Otherwise, we've consumed a trailing comma —
      // that's fine since our caller also tries match(comma).
      // But wait — the caller checks match(comma) AFTER we return.
      // So we must NOT consume a trailing comma ourselves.  Instead
      // we should only consume comma if IDENTIFIER follows.

      // To avoid ambiguity, we use a two-step approach:
      // peek at comma => if next is IDENTIFIER, consume comma + parse enumerator
      // else break.  But we only have single look-ahead.
      // So we break here and let caller handle trailing comma.
      // This works because the loop condition checks currentToken == comma,
      // and inside we first consume the comma, then check for IDENTIFIER.

      this.advance();  // consume ','

      // If the next token is an IDENTIFIER, parse an enumerator
      if ((this.currentToken as number) === (HighToken.IDENTIFIER as number)) {
        const e = this.parseEnumerator();
        if (e === null) return null;
        result.push(e);
      } else {
        // Trailing comma — the '}' (or whatever follows) will be
        // handled by caller
        break;
      }
    }
    return result;
  }

  private parseEnumerator(): Enumerator | null {
    if ((this.currentToken as number) !== (HighToken.IDENTIFIER as number)) {
      this.setError('Syntax error');
      return null;
    }
    const ident = this.tokenString!;
    this.advance();

    if (this.match(TokenType.equals)) {
      // IDENTIFIER '=' NUMBER
      if ((this.currentToken as number) !== (HighToken.NUMBER as number)) {
        this.setError('Syntax error');
        return null;
      }
      const val = this.tokenNumber;
      this.advance();
      return this.newEnumerator(ident, val);
    }
    return this.newEnumerator(ident);
  }

  // -----------------------------------------------------------------------
  //  init_declarator_list
  //    : init_declarator (',' init_declarator)*
  //  ;
  //  init_declarator
  //    : declarator
  //  ;
  // -----------------------------------------------------------------------
  private parseInitDeclaratorList(): TypeDeclarator[] | null {
    const result: TypeDeclarator[] = [];

    const first = this.parseDeclarator();
    if (first === null) return null;
    result.push(first);

    while (this.match(TokenType.comma)) {
      const dec = this.parseDeclarator();
      if (dec === null) return null;
      result.push(dec);
    }
    return result;
  }

  // -----------------------------------------------------------------------
  //  declarator
  //    : direct_declarator
  //    | pointer direct_declarator
  //  ;
  // -----------------------------------------------------------------------
  private parseDeclarator(): TypeDeclarator | null {
    if (this.currentToken === TokenType.star) {
      // pointer direct_declarator
      const ptr = this.parsePointer();
      if (ptr === null) return null;
      const dec = this.parseDirectDeclarator();
      if (dec === null) return null;
      return this.mergePointer(ptr, dec);
    }
    return this.parseDirectDeclarator();
  }

  // -----------------------------------------------------------------------
  //  direct_declarator
  //    : IDENTIFIER direct_declarator_suffix*
  //    | '(' declarator ')' direct_declarator_suffix*
  //  ;
  //  direct_declarator_suffix
  //    : '[' type_qualifier_list assignment_expression ']'
  //    | '[' assignment_expression ']'
  //    | '(' parameter_type_list ')'
  //  ;
  //
  //  The original yacc grammar is left-recursive; we convert to
  //  right-recursive with a suffix loop.
  // -----------------------------------------------------------------------
  private parseDirectDeclarator(): TypeDeclarator | null {
    let dec: TypeDeclarator | null = null;

    if (this.currentToken === HighToken.IDENTIFIER) {
      const str = this.tokenString!;
      this.advance();
      dec = this.newDeclarator(str);
    } else if (this.match(TokenType.openparen)) {
      dec = this.parseDeclarator();
      if (dec === null) return null;
      this.expect(TokenType.closeparen);
    } else {
      this.setError('Syntax error');
      return null;
    }

    // Suffix loop
    return this.parseDirectDeclaratorSuffix(dec);
  }

  /** Parse zero or more direct-declarator suffixes (array, function call) */
  private parseDirectDeclaratorSuffix(dec: TypeDeclarator): TypeDeclarator | null {
    while (true) {
      if (this.match(TokenType.openbracket)) {
        // '[' ... ']'
        let flags: number = 0;
        if (this.currentToken === HighToken.TYPE_QUALIFIER) {
          flags = this.parseTypeQualifierList();
        }
        const num = this.parseAssignmentExpression();
        if (num === null) return null;
        this.expect(TokenType.closebracket);
        dec = this.newArray(dec, flags, num);
      } else if (this.match(TokenType.openparen)) {
        // '(' parameter_type_list ')'
        const paramlist = this.parseParameterTypeList();
        if (paramlist === null) return null;
        this.expect(TokenType.closeparen);
        dec = this.newFunc(dec, paramlist);
      } else {
        break;
      }
    }
    return dec;
  }

  // -----------------------------------------------------------------------
  //  pointer
  //    : '*' type_qualifier_list? pointer?
  //
  //  Produces a list of flag values (one per '*'), outermost first.
  //  In the yacc grammar the list is built in reverse (push_back), so
  //  the *last* element corresponds to the outermost pointer.  We
  //  replicate that order.
  // -----------------------------------------------------------------------
  private parsePointer(): number[] | null {
    const result: number[] = [];

    while (this.match(TokenType.star)) {
      let flags: number = 0;
      if (this.currentToken === HighToken.TYPE_QUALIFIER) {
        flags = this.parseTypeQualifierList();
      }
      // Push with outermost-last order (matching yacc push_back semantics)
      result.push(flags);
    }

    // Reverse so that the outermost pointer is at the end, matching
    // the yacc grammar's recursive build order:
    //   '*'                 => [0]
    //   '*' qual            => [qual]
    //   '*' pointer         => pointer ++ [0]
    //   '*' qual pointer    => pointer ++ [qual]
    // Actually looking more carefully: the yacc rules are:
    //   '*'                   => new; push_back(0)            → [0]
    //   '*' type_qualifier_list => new; push_back($2)         → [$2]
    //   '*' pointer           => $2; push_back(0)             → [...$2, 0]
    //   '*' type_qualifier_list pointer => $3; push_back($2)  → [...$3, $2]
    //
    // So the OUTERMOST '*' is pushed LAST.  When we scan left-to-right
    // in the loop above, the first '*' we see is the outermost, and we
    // push it first.  We need to reverse to match the yacc order.
    result.reverse();

    if (result.length === 0) {
      this.setError('Syntax error');
      return null;
    }
    return result;
  }

  // -----------------------------------------------------------------------
  //  type_qualifier_list
  //    : TYPE_QUALIFIER+
  //  ;
  // -----------------------------------------------------------------------
  private parseTypeQualifierList(): number {
    let flags: number = 0;
    while (this.currentToken === HighToken.TYPE_QUALIFIER) {
      const str = this.tokenString!;
      this.advance();
      flags |= this.convertFlag(str);
    }
    return flags;
  }

  // -----------------------------------------------------------------------
  //  parameter_type_list
  //    : parameter_list
  //    | parameter_list ',' DOTDOTDOT
  //  ;
  //  parameter_list
  //    : parameter_declaration (',' parameter_declaration)*
  //  ;
  // -----------------------------------------------------------------------
  private parseParameterTypeList(): (TypeDeclarator | null)[] | null {
    const result: (TypeDeclarator | null)[] = [];

    const first = this.parseParameterDeclaration();
    if (first === null) return null;
    result.push(first);

    while (this.currentToken === TokenType.comma) {
      this.advance();  // consume ','

      if (this.match(HighToken.DOTDOTDOT)) {
        // varargs
        result.push(null);
        break;
      }

      const dec = this.parseParameterDeclaration();
      if (dec === null) return null;
      result.push(dec);
    }
    return result;
  }

  // -----------------------------------------------------------------------
  //  parameter_declaration
  //    : declaration_specifiers declarator
  //    | declaration_specifiers abstract_declarator
  //    | declaration_specifiers
  //  ;
  //
  //  Distinguishing between declarator and abstract_declarator at the
  //  point where both can start with '(' or '*' is tricky.  We use the
  //  following approach:
  //    - If we see '*', try parseDeclarator (which handles pointer + direct).
  //      If the direct_declarator starts with IDENTIFIER, that's a
  //      concrete declarator.  If it starts with '(' we try declarator
  //      first; on failure fall back to abstract.
  //    - Actually, the simplest correct approach: try declarator first.
  //      If it succeeds, use it.  Otherwise backtrack and try abstract.
  //
  //  Since full backtracking is expensive, we instead observe:
  //    - declarator MUST contain an IDENTIFIER somewhere (it always ends
  //      up at IDENTIFIER in direct_declarator).
  //    - abstract_declarator does NOT contain an IDENTIFIER.
  //
  //  Strategy: after parsing declaration_specifiers, check:
  //    - currentToken == IDENTIFIER => surely a (concrete) declarator
  //    - currentToken == '*' => could be either; parse pointer, then
  //      decide based on what follows
  //    - currentToken == '(' => could be either; need deeper look
  //    - currentToken == '[' => abstract_declarator
  //    - otherwise => bare declaration_specifiers
  // -----------------------------------------------------------------------
  private parseParameterDeclaration(): TypeDeclarator | null {
    const spec = this.parseDeclarationSpecifiers();
    if (spec === null) return null;

    if (this.isDeclaratorStart()) {
      // Could be declarator or abstract_declarator.
      // We try to parse a general declarator-or-abstract.
      const dec = this.parseDeclaratorOrAbstract();
      if (dec === null) return null;
      return this.mergeSpecDec(spec, dec);
    }

    // Bare declaration_specifiers (e.g. just "int")
    return this.mergeSpecDec(spec);
  }

  // -----------------------------------------------------------------------
  //  Combined declarator-or-abstract parser.
  //
  //  Both declarator and abstract_declarator can start with '*' or '('.
  //  The key difference: a concrete declarator eventually reaches an
  //  IDENTIFIER in a direct_declarator; an abstract one never does.
  //
  //  Strategy:
  //    pointer? ( direct_declarator | direct_abstract_declarator | nothing )
  //
  //  After consuming any pointer prefix, if IDENTIFIER follows it must
  //  be a concrete direct_declarator.  If '(' follows, it could be
  //  either a grouped declarator "( declarator )" or a grouped abstract
  //  "( abstract_declarator )" or a function-call suffix
  //  "( parameter_type_list )".  We disambiguate by checking what's
  //  inside the parens.
  // -----------------------------------------------------------------------
  private parseDeclaratorOrAbstract(): TypeDeclarator | null {
    let ptr: number[] | null = null;

    if (this.currentToken === TokenType.star) {
      ptr = this.parsePointer();
      if (ptr === null) return null;
    }

    let dec: TypeDeclarator | null = null;

    if (this.currentToken === HighToken.IDENTIFIER) {
      // Definitely a concrete direct_declarator
      dec = this.parseDirectDeclarator();
    } else if (this.currentToken === TokenType.openparen ||
               this.currentToken === TokenType.openbracket) {
      // Could be direct_abstract_declarator or direct_declarator.
      // If '(' follows, the content decides:
      //   - '(' declarator ')' vs '(' abstract_declarator ')' vs '(' param_type_list ')'
      //
      // For '(' we use the following heuristic:
      //   If inside the parens we see declaration_specifiers first, it's a
      //   parameter_type_list (so this is an abstract func call suffix).
      //   If we see '*' or IDENTIFIER first, it's likely a grouped
      //   declarator/abstract.
      //
      // We implement this by trying parseDirectAbstractDeclarator which
      // handles all the abstract cases.  However, if the user wrote a
      // concrete declarator inside parens, e.g. "int (*foo)", we need
      // to handle that too.
      //
      // Simplification: if we have a pointer prefix and no IDENTIFIER
      // follows, it's an abstract declarator.  If no pointer prefix and
      // we see '(', we must look deeper.

      if (this.currentToken === TokenType.openbracket) {
        // '[' can only start direct_abstract_declarator
        dec = this.parseDirectAbstractDeclarator();
      } else {
        // '(' — try to determine if this is:
        //   (a) grouped declarator:  '(' pointer? IDENTIFIER ... ')'
        //   (b) grouped abstract:    '(' abstract_declarator ')'
        //   (c) function params:     '(' parameter_type_list ')'
        //
        // For a parameter_declaration context, '(' followed by
        // declaration_specifier_start tokens means function params
        // (abstract suffix).  '(' followed by '*' or IDENTIFIER
        // means grouped declarator/abstract.

        // Save state for potential backtrack isn't trivial with a
        // stream-based lexer.  Instead, we peek:
        // If '(' is followed by '*', it's a grouped pointer declarator
        //   (could be concrete or abstract).
        // If '(' is followed by IDENTIFIER, it could be either a
        //   grouped concrete declarator or the start of parameter types.
        //   But in parameter_declaration we already have declaration_specifiers,
        //   so '(' IDENTIFIER would be a grouped concrete declarator only if
        //   IDENTIFIER is not a type name.  Actually, it's ambiguous.
        //
        // Practical approach: try concrete declarator first (which includes
        // abstract as a subset if we allow empty identifier).

        // Actually, the cleanest approach for this particular grammar:
        // parse it as an abstract declarator (which can also contain a
        // grouped sub-declarator).  Since this is called from
        // parameter_declaration, both concrete and abstract are valid.

        dec = this.parseAbstractOrConcreteInParens();
      }
    } else if (ptr !== null) {
      // pointer with nothing after — abstract declarator that's just a pointer
      dec = this.newDeclarator();
    }

    if (ptr !== null && dec !== null) {
      return this.mergePointer(ptr, dec);
    }
    if (dec !== null) return dec;
    if (ptr !== null) {
      // Pointer-only abstract declarator
      dec = this.newDeclarator();
      return this.mergePointer(ptr, dec);
    }
    this.setError('Syntax error');
    return null;
  }

  /**
   * Handle the ambiguous '(' case when parsing declarator-or-abstract.
   * Called when currentToken == '('.
   * Returns a TypeDeclarator (possibly with an identifier if concrete).
   */
  private parseAbstractOrConcreteInParens(): TypeDeclarator | null {
    // Check what follows '('.
    // If the token after '(' is a declaration_specifier start, this is
    // a function parameter list (direct_abstract_declarator suffix).
    // Otherwise it's a grouped declarator/abstract.

    // We are at '(' — consume it
    this.advance();  // consume '('

    // If we see a declaration_specifier start, this is a function call:
    //   '(' parameter_type_list ')'
    // That forms a direct_abstract_declarator but needs a "base" declarator.
    // In the abstract grammar: direct_abstract_declarator : '(' abstract ')'
    //                          | dAD '(' param_type_list ')'
    // The first form (grouped abstract) wouldn't start with decl specs.
    // So if decl specs follow, this must be an implicit function:
    //   e.g.  void (int, float)  — an unnamed function type.
    //
    // But if DOTDOTDOT or ')' follows '(', it's also function params.

    if (this.isDeclarationSpecifierStart() ||
        this.currentToken === HighToken.DOTDOTDOT ||
        this.currentToken === TokenType.closeparen) {
      // Function parameter list
      // We need a "base" declarator — create an anonymous one
      let dec = this.newDeclarator();

      // Parse parameter_type_list (could be empty if ')' is next)
      let paramlist: (TypeDeclarator | null)[];
      if (this.currentToken === TokenType.closeparen) {
        paramlist = [];
      } else {
        const pl = this.parseParameterTypeList();
        if (pl === null) return null;
        paramlist = pl;
      }
      this.expect(TokenType.closeparen);
      dec = this.newFunc(dec, paramlist);

      // Continue with more suffixes
      return this.parseDirectAbstractDeclaratorSuffix(dec);
    }

    // Otherwise, it's a grouped (abstract_declarator) or (declarator)
    // Parse recursively
    const inner = this.parseDeclaratorOrAbstract();
    if (inner === null) return null;
    this.expect(TokenType.closeparen);

    // Continue parsing direct_declarator / direct_abstract_declarator suffixes
    return this.parseDirectDeclaratorSuffix(inner);
  }

  // -----------------------------------------------------------------------
  //  abstract_declarator
  //    : pointer
  //    | direct_abstract_declarator
  //    | pointer direct_abstract_declarator
  //  ;
  // -----------------------------------------------------------------------
  private parseAbstractDeclarator(): TypeDeclarator | null {
    let ptr: number[] | null = null;

    if (this.currentToken === TokenType.star) {
      ptr = this.parsePointer();
      if (ptr === null) return null;
    }

    let dec: TypeDeclarator | null = null;

    if (this.isDirectAbstractDeclaratorStart()) {
      dec = this.parseDirectAbstractDeclarator();
      if (dec === null) return null;
    }

    if (ptr !== null) {
      if (dec === null) {
        dec = this.newDeclarator();
      }
      return this.mergePointer(ptr, dec);
    }
    if (dec !== null) return dec;

    this.setError('Syntax error');
    return null;
  }

  // -----------------------------------------------------------------------
  //  direct_abstract_declarator
  //    : '(' abstract_declarator ')'  suffix*
  //    | suffix+
  //  ;
  //  suffix
  //    : '[' assignment_expression ']'
  //    | '(' parameter_type_list ')'
  //  ;
  // -----------------------------------------------------------------------
  private parseDirectAbstractDeclarator(): TypeDeclarator | null {
    let dec: TypeDeclarator | null = null;

    if ((this.currentToken as number) === (TokenType.openparen as number)) {
      // Could be '(' abstract_declarator ')' or function suffix
      // Disambiguate: if what follows '(' is declaration_specifiers or
      // ')' or DOTDOTDOT, it's a function call (suffix on an implicit base).
      // Otherwise it's a grouped abstract declarator.

      // Actually, for direct_abstract_declarator, the grammar says:
      //   '(' abstract_declarator ')'
      // An abstract_declarator starts with '*', '(' or '['.
      // A parameter_type_list starts with declaration_specifiers.
      // So if after '(' we see a decl spec start, it's function params.

      // Peek inside
      this.advance();  // consume '('

      if (this.isDeclarationSpecifierStart() ||
          (this.currentToken as number) === (HighToken.DOTDOTDOT as number) ||
          (this.currentToken as number) === (TokenType.closeparen as number)) {
        // Function parameter list on implicit base
        dec = this.newDeclarator();
        let paramlist: (TypeDeclarator | null)[];
        if ((this.currentToken as number) === (TokenType.closeparen as number)) {
          paramlist = [];
        } else {
          const pl = this.parseParameterTypeList();
          if (pl === null) return null;
          paramlist = pl;
        }
        this.expect(TokenType.closeparen);
        dec = this.newFunc(dec, paramlist);
      } else {
        // Grouped abstract declarator
        dec = this.parseAbstractDeclarator();
        if (dec === null) return null;
        this.expect(TokenType.closeparen);
      }
    } else if (this.currentToken === TokenType.openbracket) {
      // Array suffix on implicit base
      dec = this.newDeclarator();
      this.advance();  // consume '['
      const num = this.parseAssignmentExpression();
      if (num === null) return null;
      this.expect(TokenType.closebracket);
      dec = this.newArray(dec, 0, num);
    } else {
      this.setError('Syntax error');
      return null;
    }

    // Parse further suffixes
    return this.parseDirectAbstractDeclaratorSuffix(dec);
  }

  /** Parse zero or more direct_abstract_declarator suffixes */
  private parseDirectAbstractDeclaratorSuffix(dec: TypeDeclarator): TypeDeclarator | null {
    while (true) {
      if (this.match(TokenType.openbracket)) {
        const num = this.parseAssignmentExpression();
        if (num === null) return null;
        this.expect(TokenType.closebracket);
        dec = this.newArray(dec, 0, num);
      } else if (this.match(TokenType.openparen)) {
        let paramlist: (TypeDeclarator | null)[];
        if (this.currentToken === TokenType.closeparen) {
          paramlist = [];
        } else {
          const pl = this.parseParameterTypeList();
          if (pl === null) return null;
          paramlist = pl;
        }
        this.expect(TokenType.closeparen);
        dec = this.newFunc(dec, paramlist);
      } else {
        break;
      }
    }
    return dec;
  }

  // -----------------------------------------------------------------------
  //  assignment_expression
  //    : NUMBER
  //  ;
  // -----------------------------------------------------------------------
  private parseAssignmentExpression(): bigint | null {
    if (this.currentToken !== HighToken.NUMBER) {
      this.setError('Syntax error');
      return null;
    }
    const val = this.tokenNumber;
    this.advance();
    return val;
  }

  // =========================================================================
  //  Top-level parse entry points
  // =========================================================================

  private runParse(doctype: number): boolean {
    switch (doctype) {
      case CParse.doc_declaration:
        this.firsttoken = HighToken.DECLARATION_RESULT;
        break;
      case CParse.doc_parameter_declaration:
        this.firsttoken = HighToken.PARAM_RESULT;
        break;
      default:
        throw new LowlevelError('Bad document type');
    }

    try {
      const res = this.parseDocument();
      if (!res) {
        if (this.lasterror.length === 0) {
          this.setError('Syntax error');
        }
        return false;
      }
      return true;
    } catch (e) {
      if (e instanceof ParseError) {
        if (this.lasterror.length === 0) {
          this.lasterror = e.message;
        }
        return false;
      }
      throw e;
    }
  }

  /**
   * Parse a string of C type declarations.
   * @param text   The source text to parse
   * @param doctype  CParse.doc_declaration or CParse.doc_parameter_declaration
   * @returns true if parse succeeded with no errors
   */
  parseStream(text: string, doctype: number): boolean {
    this.clear();
    this.lexer.pushFile('stream', text);
    return this.runParse(doctype);
  }

  /**
   * Parse from a named source (the text content is provided directly).
   * @param filename  Logical filename for error messages
   * @param text      The source text
   * @param doctype   Document type
   * @returns true on success
   */
  parseFile(filename: string, text: string, doctype: number): boolean {
    this.clear();
    this.lexer.pushFile(filename, text);
    return this.runParse(doctype);
  }
}

// ---------------------------------------------------------------------------
// Top-level convenience functions (correspond to parse_type, parse_C, etc.)
// ---------------------------------------------------------------------------

/**
 * Parse a single C type declaration from a string and return its Datatype
 * and the declared name (if any).
 */
export function parse_type(
  s: string,
  glb: Architecture,
): { type: Datatype; name: string } {
  const parser = new CParse(glb, 4096);

  if (!parser.parseStream(s, CParse.doc_parameter_declaration))
    throw new ParseError(parser.getError());

  const decls = parser.getResultDeclarations();
  if (decls === null || decls.length === 0)
    throw new ParseError('Did not parse a datatype');
  if (decls.length > 1)
    throw new ParseError('Parsed multiple declarations');

  const decl = decls[0];
  if (!decl.isValid())
    throw new ParseError('Parsed type is invalid');

  return {
    type: decl.buildType(glb),
    name: decl.getIdentifier(),
  };
}

/**
 * Parse a function prototype from a C declaration string.
 */
export function parse_protopieces(
  s: string,
  glb: Architecture,
): PrototypePieces {
  const parser = new CParse(glb, 4096);

  if (!parser.parseStream(s, CParse.doc_declaration))
    throw new ParseError(parser.getError());

  const decls = parser.getResultDeclarations();
  if (decls === null || decls.length === 0)
    throw new ParseError('Did not parse a datatype');
  if (decls.length > 1)
    throw new ParseError('Parsed multiple declarations');

  const decl = decls[0];
  if (!decl.isValid())
    throw new ParseError('Parsed type is invalid');

  const pieces: any = {};
  if (!decl.getPrototype(pieces, glb))
    throw new ParseError('Did not parse a prototype');
  return pieces;
}

/**
 * Parse a C declaration and load the resulting type data into the
 * Architecture's type system.
 */
export function parse_C(glb: Architecture, s: string): void {
  const parser = new CParse(glb, 4096);

  if (!parser.parseStream(s, CParse.doc_declaration))
    throw new ParseError(parser.getError());

  const decls = parser.getResultDeclarations();
  if (decls === null || decls.length === 0)
    throw new ParseError('Did not parse a datatype');
  if (decls.length > 1)
    throw new ParseError('Parsed multiple declarations');

  const decl = decls[0];
  if (!decl.isValid())
    throw new ParseError('Parsed type is invalid');

  if (decl.hasProperty(CParse.f_extern)) {
    const pieces: any = {};
    if (!decl.getPrototype(pieces, glb))
      throw new ParseError('Did not parse prototype as expected');
    glb.setPrototype(pieces);
  } else if (decl.hasProperty(CParse.f_typedef)) {
    const ct = decl.buildType(glb);
    if (decl.getIdentifier().length === 0)
      throw new ParseError('Missing identifier for typedef');
    if (ct.getMetatype() === type_metatype.TYPE_STRUCT) {
      glb.types.setName(ct, decl.getIdentifier());
    } else {
      glb.types.getTypedef(ct, decl.getIdentifier(), 0n, 0);
    }
  } else if (decl.getBaseType()!.getMetatype() === type_metatype.TYPE_STRUCT) {
    // Parsed a struct — treat as typedef
  } else if (decl.getBaseType()!.getMetatype() === type_metatype.TYPE_UNION) {
    // Parsed a union — treat as typedef
  } else if (decl.getBaseType()!.isEnumType()) {
    // Parsed an enum — treat as typedef
  } else {
    throw new LowlevelError('Not sure what to do with this type');
  }
}
// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/**
 * Parse a string up to the next C separator character.
 * Returns the parsed name token.
 *
 * Equivalent to Ghidra's parse_toseparator().
 */
export function parse_toseparator(input: string, pos: number): { name: string; newPos: number } {
  let name = '';

  // Skip whitespace
  while (pos < input.length && /\s/.test(input[pos])) {
    pos++;
  }

  while (pos < input.length) {
    const ch = input[pos];
    if (/[a-zA-Z0-9_]/.test(ch)) {
      name += ch;
      pos++;
    } else {
      break;
    }
  }

  return { name, newPos: pos };
}
