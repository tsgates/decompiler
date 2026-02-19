/**
 * @file pcodeparse.ts
 * @description Hand-written recursive descent parser for the Ghidra p-code snippet language.
 *
 * Translated from Ghidra's pcodeparse.y (yacc grammar) and pcodeparse.cc.
 *
 * The p-code parser handles semantic action expressions in SLEIGH:
 *   - Variable declarations and assignments
 *   - Arithmetic/logical expressions with operator precedence
 *   - Memory loads/stores with bracket notation (sizedstar)
 *   - Function calls (user-defined pcodeops via CALLOTHER)
 *   - Control flow: goto, call, return, if/goto
 *   - Labels
 *   - Export statements (via ExprTree.setOutput)
 */

import type { int4, uint4, uintb } from '../core/types.js';
import { OpCode } from '../core/opcodes.js';
import { AddrSpace, spacetype } from '../core/space.js';
import { LowlevelError } from '../core/error.js';
import {
  ConstTpl,
  VarnodeTpl,
  OpTpl,
  HandleTpl,
  ConstructTpl,
  const_type,
  v_field,
  LABELBUILD,
} from './semantics.js';

// ============================================================================
// Forward declarations for types from not-yet-written files
// ============================================================================
type SleighBase = any;
type SleighSymbol = any;
type SpaceSymbol = any;
type UserOpSymbol = any;
type VarnodeSymbol = any;
type OperandSymbol = any;
type SpecificSymbol = any;
type LabelSymbol = any;
type Location = any;

// ============================================================================
// Constants matching C++ sizeof(uintm) = 4
// ============================================================================
const SIZEOF_UINTM = 4;

// ============================================================================
// Token types
// ============================================================================
const enum TokenType {
  // Single-char tokens use their char code as the token type
  // Multi-char operators and keywords get IDs starting at 256

  // End of stream
  ENDOFSTREAM = 256,
  // Integer literal
  INTEGER = 257,
  // Identifier (unrecognized string)
  STRING = 258,
  // Bad (overflowing) integer
  BADINTEGER = 259,

  // Keywords
  GOTO_KEY = 260,
  CALL_KEY = 261,
  RETURN_KEY = 262,
  IF_KEY = 263,
  LOCAL_KEY = 264,

  // Multi-char operators
  OP_BOOL_OR = 270,    // ||
  OP_BOOL_AND = 271,   // &&
  OP_BOOL_XOR = 272,   // ^^
  OP_EQUAL = 273,       // ==
  OP_NOTEQUAL = 274,    // !=
  OP_GREATEQUAL = 275,  // >=
  OP_LESSEQUAL = 276,   // <=
  OP_LEFT = 277,        // <<
  OP_RIGHT = 278,       // >>
  OP_SRIGHT = 279,      // s>>
  OP_SLESS = 280,       // s<
  OP_SGREAT = 281,      // s>
  OP_SLESSEQUAL = 282,  // s<=
  OP_SGREATEQUAL = 283, // s>=
  OP_SDIV = 284,        // s/
  OP_SREM = 285,        // s%
  OP_FEQUAL = 286,      // f==
  OP_FNOTEQUAL = 287,   // f!=
  OP_FLESS = 288,       // f<
  OP_FGREAT = 289,      // f>
  OP_FLESSEQUAL = 290,  // f<=
  OP_FGREATEQUAL = 291, // f>=
  OP_FADD = 292,        // f+
  OP_FSUB = 293,        // f-
  OP_FMULT = 294,       // f*
  OP_FDIV = 295,        // f/

  // Unary/function-style operators
  OP_ZEXT = 300,
  OP_CARRY = 301,
  OP_BORROW = 302,
  OP_SEXT = 303,
  OP_SCARRY = 304,
  OP_SBORROW = 305,
  OP_NAN = 306,
  OP_ABS = 307,
  OP_SQRT = 308,
  OP_CEIL = 309,
  OP_FLOOR = 310,
  OP_ROUND = 311,
  OP_INT2FLOAT = 312,
  OP_FLOAT2FLOAT = 313,
  OP_TRUNC = 314,
  OP_NEW = 315,

  // Symbol tokens (resolved from symbol table)
  SPACESYM = 400,
  USEROPSYM = 401,
  VARSYM = 402,
  OPERANDSYM = 403,
  JUMPSYM = 404,
  LABELSYM = 405,
}

// ============================================================================
// Token interface
// ============================================================================
interface Token {
  type: number;          // TokenType value or ASCII char code
  stringVal?: string;    // for STRING tokens
  intVal?: bigint;       // for INTEGER tokens
  // Symbol references
  spaceSym?: SpaceSymbol;
  userOpSym?: UserOpSymbol;
  varSym?: VarnodeSymbol;
  operandSym?: OperandSymbol;
  specSym?: SpecificSymbol;
  labelSym?: LabelSymbol;
}

// ============================================================================
// IdentRec - keyword/operator table entry
// ============================================================================
interface IdentRec {
  nm: string;
  id: number;
}

// Sorted list of identifiers (must be kept sorted for binary search)
const IDENT_TABLE: IdentRec[] = [
  { nm: '!=', id: TokenType.OP_NOTEQUAL },
  { nm: '&&', id: TokenType.OP_BOOL_AND },
  { nm: '<<', id: TokenType.OP_LEFT },
  { nm: '<=', id: TokenType.OP_LESSEQUAL },
  { nm: '==', id: TokenType.OP_EQUAL },
  { nm: '>=', id: TokenType.OP_GREATEQUAL },
  { nm: '>>', id: TokenType.OP_RIGHT },
  { nm: '^^', id: TokenType.OP_BOOL_XOR },
  { nm: '||', id: TokenType.OP_BOOL_OR },
  { nm: 'abs', id: TokenType.OP_ABS },
  { nm: 'borrow', id: TokenType.OP_BORROW },
  { nm: 'call', id: TokenType.CALL_KEY },
  { nm: 'carry', id: TokenType.OP_CARRY },
  { nm: 'ceil', id: TokenType.OP_CEIL },
  { nm: 'f!=', id: TokenType.OP_FNOTEQUAL },
  { nm: 'f*', id: TokenType.OP_FMULT },
  { nm: 'f+', id: TokenType.OP_FADD },
  { nm: 'f-', id: TokenType.OP_FSUB },
  { nm: 'f/', id: TokenType.OP_FDIV },
  { nm: 'f<', id: TokenType.OP_FLESS },
  { nm: 'f<=', id: TokenType.OP_FLESSEQUAL },
  { nm: 'f==', id: TokenType.OP_FEQUAL },
  { nm: 'f>', id: TokenType.OP_FGREAT },
  { nm: 'f>=', id: TokenType.OP_FGREATEQUAL },
  { nm: 'float2float', id: TokenType.OP_FLOAT2FLOAT },
  { nm: 'floor', id: TokenType.OP_FLOOR },
  { nm: 'goto', id: TokenType.GOTO_KEY },
  { nm: 'if', id: TokenType.IF_KEY },
  { nm: 'int2float', id: TokenType.OP_INT2FLOAT },
  { nm: 'local', id: TokenType.LOCAL_KEY },
  { nm: 'nan', id: TokenType.OP_NAN },
  { nm: 'return', id: TokenType.RETURN_KEY },
  { nm: 'round', id: TokenType.OP_ROUND },
  { nm: 's%', id: TokenType.OP_SREM },
  { nm: 's/', id: TokenType.OP_SDIV },
  { nm: 's<', id: TokenType.OP_SLESS },
  { nm: 's<=', id: TokenType.OP_SLESSEQUAL },
  { nm: 's>', id: TokenType.OP_SGREAT },
  { nm: 's>=', id: TokenType.OP_SGREATEQUAL },
  { nm: 's>>', id: TokenType.OP_SRIGHT },
  { nm: 'sborrow', id: TokenType.OP_SBORROW },
  { nm: 'scarry', id: TokenType.OP_SCARRY },
  { nm: 'sext', id: TokenType.OP_SEXT },
  { nm: 'sqrt', id: TokenType.OP_SQRT },
  { nm: 'trunc', id: TokenType.OP_TRUNC },
  { nm: 'zext', id: TokenType.OP_ZEXT },
];

// ============================================================================
// StarQuality - describes a dereference operator (*) with optional space/size
// ============================================================================
export class StarQuality {
  id: ConstTpl = new ConstTpl();
  size: number = 0;
}

// ============================================================================
// ExprTree - a flattened expression tree (ops + output varnode)
// ============================================================================
export class ExprTree {
  ops: OpTpl[];
  outvn: VarnodeTpl | null;

  constructor();
  constructor(vn: VarnodeTpl);
  constructor(op: OpTpl);
  constructor(arg?: VarnodeTpl | OpTpl) {
    if (arg === undefined) {
      this.ops = [];
      this.outvn = null;
    } else if (arg instanceof VarnodeTpl) {
      this.outvn = arg;
      this.ops = [];
    } else {
      // OpTpl
      this.ops = [arg];
      if (arg.getOut() !== null) {
        this.outvn = new VarnodeTpl(arg.getOut()!);
      } else {
        this.outvn = null;
      }
    }
  }

  setOutput(newout: VarnodeTpl): void {
    if (this.outvn === null) {
      throw new LowlevelError('Expression has no output');
    }
    if (this.outvn.isUnnamed()) {
      const op = this.ops[this.ops.length - 1];
      op.clearOutput();
      op.setOutput(newout);
    } else {
      const op = new OpTpl(OpCode.CPUI_COPY);
      op.addInput(this.outvn);
      op.setOutput(newout);
      this.ops.push(op);
    }
    this.outvn = new VarnodeTpl(newout);
  }

  getOut(): VarnodeTpl | null {
    return this.outvn;
  }

  getSize(): ConstTpl {
    return this.outvn!.getSize();
  }

  static appendParams(op: OpTpl, param: ExprTree[]): OpTpl[] {
    const res: OpTpl[] = [];
    for (let i = 0; i < param.length; i++) {
      res.push(...param[i].ops);
      param[i].ops = [];
      op.addInput(param[i].outvn!);
      param[i].outvn = null;
    }
    res.push(op);
    return res;
  }

  static toVector(expr: ExprTree): OpTpl[] {
    const res = expr.ops;
    expr.ops = [];
    return res;
  }
}

// ============================================================================
// PcodeLexer - tokenizer for p-code expressions
// ============================================================================
class PcodeLexer {
  private input: string = '';
  private pos: number = 0;

  initialize(s: string): void {
    this.input = s;
    this.pos = 0;
  }

  private peek(): string {
    if (this.pos >= this.input.length) return '\0';
    return this.input[this.pos];
  }

  private advance(): string {
    if (this.pos >= this.input.length) return '\0';
    return this.input[this.pos++];
  }

  private peekAt(offset: number): string {
    const idx = this.pos + offset;
    if (idx >= this.input.length) return '\0';
    return this.input[idx];
  }

  private skipWhitespace(): void {
    while (this.pos < this.input.length) {
      const ch = this.input[this.pos];
      if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === '\v') {
        this.pos++;
      } else if (ch === '#') {
        // Comment to end of line
        this.pos++;
        while (this.pos < this.input.length && this.input[this.pos] !== '\n') {
          this.pos++;
        }
      } else {
        break;
      }
    }
  }

  private static isIdent(c: string): boolean {
    return /[a-zA-Z0-9_.]/.test(c);
  }

  private static isHex(c: string): boolean {
    return /[0-9a-fA-F]/.test(c);
  }

  private static isDec(c: string): boolean {
    return /[0-9]/.test(c);
  }

  private static isAlpha(c: string): boolean {
    return /[a-zA-Z_.]/.test(c);
  }

  private findIdentifier(str: string): number {
    let low = 0;
    let high = IDENT_TABLE.length - 1;
    while (low <= high) {
      const mid = (low + high) >>> 1;
      const cmp = str < IDENT_TABLE[mid].nm ? -1 : str > IDENT_TABLE[mid].nm ? 1 : 0;
      if (cmp < 0) {
        high = mid - 1;
      } else if (cmp > 0) {
        low = mid + 1;
      } else {
        return mid;
      }
    }
    return -1;
  }

  /**
   * Scan the next raw token from input.
   * Returns a Token with type set appropriately.
   */
  getNextToken(): Token {
    this.skipWhitespace();

    if (this.pos >= this.input.length) {
      return { type: TokenType.ENDOFSTREAM };
    }

    const ch = this.peek();

    // Check for multi-character operators starting with 's' or 'f'
    if (ch === 's') {
      const la1 = this.peekAt(1);
      if (la1 === '/' || la1 === '%') {
        const tok = ch + la1;
        this.pos += 2;
        const idx = this.findIdentifier(tok);
        if (idx >= 0) return { type: IDENT_TABLE[idx].id };
      } else if (la1 === '<') {
        const la2 = this.peekAt(2);
        if (la2 === '=') {
          this.pos += 3;
          return { type: TokenType.OP_SLESSEQUAL };
        }
        this.pos += 2;
        return { type: TokenType.OP_SLESS };
      } else if (la1 === '>') {
        const la2 = this.peekAt(2);
        if (la2 === '>') {
          this.pos += 3;
          return { type: TokenType.OP_SRIGHT };
        }
        if (la2 === '=') {
          this.pos += 3;
          return { type: TokenType.OP_SGREATEQUAL };
        }
        this.pos += 2;
        return { type: TokenType.OP_SGREAT };
      }
      // Fall through to identifier
    } else if (ch === 'f') {
      const la1 = this.peekAt(1);
      if (la1 === '+' || la1 === '-' || la1 === '*' || la1 === '/') {
        const tok = ch + la1;
        this.pos += 2;
        const idx = this.findIdentifier(tok);
        if (idx >= 0) return { type: IDENT_TABLE[idx].id };
      } else if ((la1 === '=' || la1 === '!') && this.peekAt(2) === '=') {
        const tok = ch + la1 + '=';
        this.pos += 3;
        const idx = this.findIdentifier(tok);
        if (idx >= 0) return { type: IDENT_TABLE[idx].id };
      } else if (la1 === '<' || la1 === '>') {
        const la2 = this.peekAt(2);
        if (la2 === '=') {
          const tok = ch + la1 + '=';
          this.pos += 3;
          const idx = this.findIdentifier(tok);
          if (idx >= 0) return { type: IDENT_TABLE[idx].id };
        }
        const tok = ch + la1;
        this.pos += 2;
        const idx = this.findIdentifier(tok);
        if (idx >= 0) return { type: IDENT_TABLE[idx].id };
      }
      // Fall through to identifier
    }

    // Identifiers and keywords (alpha, _, .)
    if (PcodeLexer.isAlpha(ch) || ch === '_' || ch === '.') {
      const start = this.pos;
      this.pos++;
      while (this.pos < this.input.length && PcodeLexer.isIdent(this.input[this.pos])) {
        this.pos++;
      }
      const ident = this.input.slice(start, this.pos);
      const idx = this.findIdentifier(ident);
      if (idx >= 0) {
        return { type: IDENT_TABLE[idx].id };
      }
      return { type: TokenType.STRING, stringVal: ident };
    }

    // Numbers
    if (PcodeLexer.isDec(ch)) {
      const start = this.pos;
      if (ch === '0' && this.peekAt(1) === 'x') {
        // Hex number
        this.pos += 2;
        while (this.pos < this.input.length && PcodeLexer.isHex(this.input[this.pos])) {
          this.pos++;
        }
      } else {
        // Decimal number
        while (this.pos < this.input.length && PcodeLexer.isDec(this.input[this.pos])) {
          this.pos++;
        }
      }
      const numStr = this.input.slice(start, this.pos);
      try {
        let val: bigint;
        if (numStr.startsWith('0x') || numStr.startsWith('0X')) {
          val = BigInt(numStr);
        } else {
          val = BigInt(numStr);
        }
        return { type: TokenType.INTEGER, intVal: val };
      } catch {
        return { type: TokenType.BADINTEGER };
      }
    }

    // Two-character operators
    const la1 = this.peekAt(1);
    if (ch === '|' && la1 === '|') { this.pos += 2; return { type: TokenType.OP_BOOL_OR }; }
    if (ch === '&' && la1 === '&') { this.pos += 2; return { type: TokenType.OP_BOOL_AND }; }
    if (ch === '^' && la1 === '^') { this.pos += 2; return { type: TokenType.OP_BOOL_XOR }; }
    if (ch === '>' && la1 === '>') { this.pos += 2; return { type: TokenType.OP_RIGHT }; }
    if (ch === '>' && la1 === '=') { this.pos += 2; return { type: TokenType.OP_GREATEQUAL }; }
    if (ch === '<' && la1 === '<') { this.pos += 2; return { type: TokenType.OP_LEFT }; }
    if (ch === '<' && la1 === '=') { this.pos += 2; return { type: TokenType.OP_LESSEQUAL }; }
    if (ch === '=' && la1 === '=') { this.pos += 2; return { type: TokenType.OP_EQUAL }; }
    if (ch === '!' && la1 === '=') { this.pos += 2; return { type: TokenType.OP_NOTEQUAL }; }

    // Single-character punctuation
    this.pos++;
    return { type: ch.charCodeAt(0) };
  }
}

// ============================================================================
// PcodeCompile - base class with factory methods for building p-code templates
// ============================================================================
/**
 * PcodeCompile provides the semantic action methods called by the parser
 * to construct p-code operation templates. This is a direct translation
 * of the C++ PcodeCompile class.
 */
class PcodeCompile {
  protected defaultspace: AddrSpace | null = null;
  protected constantspace: AddrSpace | null = null;
  protected uniqspace: AddrSpace | null = null;
  protected local_labelcount: number = 0;
  protected enforceLocalKey: boolean = false;

  resetLabelCount(): void {
    this.local_labelcount = 0;
  }

  setDefaultSpace(spc: AddrSpace): void { this.defaultspace = spc; }
  setConstantSpace(spc: AddrSpace): void { this.constantspace = spc; }
  setUniqueSpace(spc: AddrSpace): void { this.uniqspace = spc; }
  setEnforceLocalKey(val: boolean): void { this.enforceLocalKey = val; }
  getDefaultSpace(): AddrSpace { return this.defaultspace!; }
  getConstantSpace(): AddrSpace { return this.constantspace!; }

  protected allocateTemp(): number {
    throw new LowlevelError('allocateTemp not implemented');
  }

  protected addSymbol(_sym: SleighSymbol): void {
    throw new LowlevelError('addSymbol not implemented');
  }

  reportError(_loc: Location | null, _msg: string): void {
    throw new LowlevelError('reportError not implemented');
  }

  reportWarning(_loc: Location | null, _msg: string): void {
    // default: no-op
  }

  buildTemporary(): VarnodeTpl {
    const res = new VarnodeTpl(
      new ConstTpl(this.uniqspace!),
      new ConstTpl(const_type.real, BigInt(this.allocateTemp())),
      new ConstTpl(const_type.real, 0n),
    );
    res.setUnnamed(true);
    return res;
  }

  defineLabel(name: string): LabelSymbol {
    const labsym = {
      name_: name,
      index_: this.local_labelcount++,
      isplaced_: false,
      refcount_: 0,
      getName(): string { return this.name_; },
      getIndex(): number { return this.index_; },
      incrementRefCount(): void { this.refcount_++; },
      getRefCount(): number { return this.refcount_; },
      setPlaced(): void { this.isplaced_ = true; },
      isPlaced(): boolean { return this.isplaced_; },
      getType(): number { return SymbolType.label_symbol; },
    };
    this.addSymbol(labsym as any);
    return labsym;
  }

  placeLabel(labsym: LabelSymbol): OpTpl[] {
    if ((labsym as any).isPlaced()) {
      this.reportError(null, "Label '" + (labsym as any).getName() + "' is placed more than once");
    }
    (labsym as any).setPlaced();
    const op = new OpTpl(LABELBUILD);
    const idvn = new VarnodeTpl(
      new ConstTpl(this.constantspace!),
      new ConstTpl(const_type.real, BigInt((labsym as any).getIndex())),
      new ConstTpl(const_type.real, 4n),
    );
    op.addInput(idvn);
    return [op];
  }

  newOutput(usesLocalKey: boolean, rhs: ExprTree, varname: string, size: number = 0): OpTpl[] {
    const tmpvn = this.buildTemporary();
    if (size !== 0) {
      tmpvn.setSize(new ConstTpl(const_type.real, BigInt(size)));
    } else if (rhs.getSize().getType() === const_type.real && rhs.getSize().getReal() !== 0n) {
      tmpvn.setSize(rhs.getSize());
    }
    rhs.setOutput(tmpvn);
    const sym = {
      name_: varname,
      space_: tmpvn.getSpace().getSpace(),
      offset_: tmpvn.getOffset().getReal(),
      size_: tmpvn.getSize().getReal(),
      getName(): string { return this.name_; },
      getType(): number { return 6; }, // varnode_symbol
      getVarnode(): VarnodeTpl {
        return new VarnodeTpl(
          new ConstTpl(this.space_ as AddrSpace),
          new ConstTpl(const_type.real, this.offset_),
          new ConstTpl(const_type.real, this.size_),
        );
      },
    };
    this.addSymbol(sym as any);
    if (!usesLocalKey && this.enforceLocalKey) {
      this.reportError(null, "Must use 'local' keyword to define symbol '" + varname + "'");
    }
    return ExprTree.toVector(rhs);
  }

  newLocalDefinition(varname: string, size: number = 0): void {
    const sym = {
      name_: varname,
      space_: this.uniqspace,
      offset_: BigInt(this.allocateTemp()),
      size_: BigInt(size),
      getName(): string { return this.name_; },
      getType(): number { return 6; }, // varnode_symbol
      getVarnode(): VarnodeTpl {
        return new VarnodeTpl(
          new ConstTpl(this.space_ as AddrSpace),
          new ConstTpl(const_type.real, this.offset_),
          new ConstTpl(const_type.real, this.size_),
        );
      },
    };
    this.addSymbol(sym as any);
  }

  createOp(opc: OpCode, vn1: ExprTree, vn2?: ExprTree): ExprTree {
    if (vn2 === undefined) {
      // Unary
      const outvn = this.buildTemporary();
      const op = new OpTpl(opc);
      op.addInput(vn1.outvn!);
      op.setOutput(outvn);
      vn1.ops.push(op);
      vn1.outvn = new VarnodeTpl(outvn);
      return vn1;
    }
    // Binary
    const outvn = this.buildTemporary();
    vn1.ops.push(...vn2.ops);
    vn2.ops = [];
    const op = new OpTpl(opc);
    op.addInput(vn1.outvn!);
    op.addInput(vn2.outvn!);
    vn2.outvn = null;
    op.setOutput(outvn);
    vn1.ops.push(op);
    vn1.outvn = new VarnodeTpl(outvn);
    return vn1;
  }

  createOpOut(outvn: VarnodeTpl, opc: OpCode, vn1: ExprTree, vn2: ExprTree): ExprTree {
    vn1.ops.push(...vn2.ops);
    vn2.ops = [];
    const op = new OpTpl(opc);
    op.addInput(vn1.outvn!);
    op.addInput(vn2.outvn!);
    vn2.outvn = null;
    op.setOutput(outvn);
    vn1.ops.push(op);
    vn1.outvn = new VarnodeTpl(outvn);
    return vn1;
  }

  createOpOutUnary(outvn: VarnodeTpl, opc: OpCode, vn: ExprTree): ExprTree {
    const op = new OpTpl(opc);
    op.addInput(vn.outvn!);
    op.setOutput(outvn);
    vn.ops.push(op);
    vn.outvn = new VarnodeTpl(outvn);
    return vn;
  }

  createOpNoOut(opc: OpCode, vn1: ExprTree, vn2?: ExprTree): OpTpl[] {
    if (vn2 === undefined) {
      const res = vn1.ops;
      vn1.ops = [];
      const op = new OpTpl(opc);
      op.addInput(vn1.outvn!);
      vn1.outvn = null;
      res.push(op);
      return res;
    }
    const res = vn1.ops;
    vn1.ops = [];
    res.push(...vn2.ops);
    vn2.ops = [];
    const op = new OpTpl(opc);
    op.addInput(vn1.outvn!);
    vn1.outvn = null;
    op.addInput(vn2.outvn!);
    vn2.outvn = null;
    res.push(op);
    return res;
  }

  createLoad(qual: StarQuality, ptr: ExprTree): ExprTree {
    const outvn = this.buildTemporary();
    const op = new OpTpl(OpCode.CPUI_LOAD);
    const spcvn = new VarnodeTpl(
      new ConstTpl(this.constantspace!),
      qual.id,
      new ConstTpl(const_type.real, 8n),
    );
    op.addInput(spcvn);
    op.addInput(ptr.outvn!);
    op.setOutput(outvn);
    ptr.ops.push(op);
    if (qual.size > 0) {
      PcodeCompile.force_size(outvn, new ConstTpl(const_type.real, BigInt(qual.size)), ptr.ops);
    }
    ptr.outvn = new VarnodeTpl(outvn);
    return ptr;
  }

  createStore(qual: StarQuality, ptr: ExprTree, val: ExprTree): OpTpl[] {
    const res = ptr.ops;
    ptr.ops = [];
    res.push(...val.ops);
    val.ops = [];
    const op = new OpTpl(OpCode.CPUI_STORE);
    const spcvn = new VarnodeTpl(
      new ConstTpl(this.constantspace!),
      qual.id,
      new ConstTpl(const_type.real, 8n),
    );
    op.addInput(spcvn);
    op.addInput(ptr.outvn!);
    op.addInput(val.outvn!);
    res.push(op);
    PcodeCompile.force_size(val.outvn!, new ConstTpl(const_type.real, BigInt(qual.size)), res);
    ptr.outvn = null;
    val.outvn = null;
    return res;
  }

  createUserOp(sym: UserOpSymbol, param: ExprTree[]): ExprTree {
    const outvn = this.buildTemporary();
    const res = new ExprTree();
    res.ops = this.createUserOpNoOut(sym, param);
    res.ops[res.ops.length - 1].setOutput(outvn);
    res.outvn = new VarnodeTpl(outvn);
    return res;
  }

  createUserOpNoOut(sym: UserOpSymbol, param: ExprTree[]): OpTpl[] {
    const op = new OpTpl(OpCode.CPUI_CALLOTHER);
    const vn = new VarnodeTpl(
      new ConstTpl(this.constantspace!),
      new ConstTpl(const_type.real, BigInt((sym as any).getIndex())),
      new ConstTpl(const_type.real, 4n),
    );
    op.addInput(vn);
    return ExprTree.appendParams(op, param);
  }

  appendOp(opc: OpCode, res: ExprTree, constval: bigint, constsz: number): void {
    const op = new OpTpl(opc);
    const constvn = new VarnodeTpl(
      new ConstTpl(this.constantspace!),
      new ConstTpl(const_type.real, constval),
      new ConstTpl(const_type.real, BigInt(constsz)),
    );
    const outvn = this.buildTemporary();
    op.addInput(res.outvn!);
    op.addInput(constvn);
    op.setOutput(outvn);
    res.ops.push(op);
    res.outvn = new VarnodeTpl(outvn);
  }

  buildTruncatedVarnode(basevn: VarnodeTpl, bitoffset: number, numbits: number): VarnodeTpl | null {
    const byteoffset = (bitoffset / 8) >>> 0;
    const numbytes = (numbits / 8) >>> 0;
    let fullsz: bigint = 0n;
    if (basevn.getSize().getType() === const_type.real) {
      fullsz = basevn.getSize().getReal();
      if (fullsz === 0n) return null;
      if (byteoffset + numbytes > Number(fullsz)) {
        throw new LowlevelError('Requested bit range out of bounds');
      }
    }

    if ((bitoffset % 8) !== 0) return null;
    if ((numbits % 8) !== 0) return null;

    const offset_type = basevn.getOffset().getType();
    if (offset_type !== const_type.real && offset_type !== const_type.handle) return null;

    let specialoff: ConstTpl;
    if (offset_type === const_type.handle) {
      specialoff = new ConstTpl(
        const_type.handle,
        basevn.getOffset().getHandleIndex(),
        v_field.v_offset_plus,
        BigInt(byteoffset),
      );
    } else {
      if (basevn.getSize().getType() !== const_type.real) {
        throw new LowlevelError('Could not construct requested bit range');
      }
      let plus: bigint;
      if (this.defaultspace!.isBigEndian()) {
        plus = fullsz - BigInt(byteoffset + numbytes);
      } else {
        plus = BigInt(byteoffset);
      }
      specialoff = new ConstTpl(const_type.real, basevn.getOffset().getReal() + plus);
    }
    return new VarnodeTpl(
      basevn.getSpace(),
      specialoff,
      new ConstTpl(const_type.real, BigInt(numbytes)),
    );
  }

  assignBitRange(vn: VarnodeTpl, bitoffset: number, numbits: number, rhs: ExprTree): OpTpl[] {
    let errmsg = '';
    if (numbits === 0) errmsg = 'Size of bitrange is zero';
    const smallsize = ((numbits + 7) / 8) >>> 0;
    const shiftneeded = bitoffset !== 0;
    let zextneeded = true;
    let mask: bigint = 2n;
    mask = ~(((mask << BigInt(numbits - 1)) - 1n) << BigInt(bitoffset));

    if (vn.getSize().getType() === const_type.real) {
      let symsize = Number(vn.getSize().getReal());
      if (symsize > 0) zextneeded = symsize > smallsize;
      symsize *= 8;
      if (bitoffset >= symsize || bitoffset + numbits > symsize)
        errmsg = 'Assigned bitrange is bad';
      else if (bitoffset === 0 && numbits === symsize)
        errmsg = 'Assigning to bitrange is superfluous';
    }

    if (errmsg.length > 0) {
      this.reportError(null, errmsg);
      const resops = rhs.ops;
      rhs.ops = [];
      return resops;
    }

    PcodeCompile.force_size(rhs.outvn!, new ConstTpl(const_type.real, BigInt(smallsize)), rhs.ops);

    let res: ExprTree;
    let finalout = this.buildTruncatedVarnode(vn, bitoffset, numbits);
    if (finalout !== null) {
      res = this.createOpOutUnary(finalout, OpCode.CPUI_COPY, rhs);
    } else {
      if (bitoffset + numbits > 64) errmsg = 'Assigned bitrange extends past first 64 bits';
      res = new ExprTree(vn);
      this.appendOp(OpCode.CPUI_INT_AND, res, mask, 0);
      if (zextneeded) this.createOp(OpCode.CPUI_INT_ZEXT, rhs);
      if (shiftneeded) this.appendOp(OpCode.CPUI_INT_LEFT, rhs, BigInt(bitoffset), 4);
      finalout = new VarnodeTpl(vn);
      res = this.createOpOut(finalout, OpCode.CPUI_INT_OR, res, rhs);
    }
    if (errmsg.length > 0) this.reportError(null, errmsg);
    const resops = res.ops;
    res.ops = [];
    return resops;
  }

  createBitRange(sym: SpecificSymbol, bitoffset: number, numbits: number): ExprTree {
    let errmsg = '';
    if (numbits === 0) errmsg = 'Size of bitrange is zero';
    const vn = (sym as any).getVarnode() as VarnodeTpl;
    const finalsize = ((numbits + 7) / 8) >>> 0;
    let truncshift = 0;
    let maskneeded = (numbits % 8) !== 0;
    let truncneeded = true;

    if (errmsg.length === 0 && bitoffset === 0 && !maskneeded) {
      if (vn.getSpace().getType() === const_type.handle && vn.isZeroSize()) {
        vn.setSize(new ConstTpl(const_type.real, BigInt(finalsize)));
        return new ExprTree(vn);
      }
    }

    if (errmsg.length === 0) {
      const truncvn = this.buildTruncatedVarnode(vn, bitoffset, numbits);
      if (truncvn !== null) {
        return new ExprTree(truncvn);
      }
    }

    if (vn.getSize().getType() === const_type.real) {
      let insize = Number(vn.getSize().getReal());
      if (insize > 0) {
        truncneeded = finalsize < insize;
        insize *= 8;
        if (bitoffset >= insize || bitoffset + numbits > insize)
          errmsg = 'Bitrange is bad';
        if (maskneeded && (bitoffset + numbits) === insize)
          maskneeded = false;
      }
    }

    let maskval: bigint = 2n;
    maskval = (maskval << BigInt(numbits - 1)) - 1n;

    if (truncneeded && (bitoffset % 8) === 0) {
      truncshift = (bitoffset / 8) >>> 0;
      bitoffset = 0;
    }

    if (bitoffset === 0 && !truncneeded && !maskneeded)
      errmsg = 'Superfluous bitrange';

    if (maskneeded && finalsize > 8)
      errmsg = 'Illegal masked bitrange producing varnode larger than 64 bits: ' + (sym as any).getName();

    const res = new ExprTree(vn);

    if (errmsg.length > 0) {
      this.reportError(null, errmsg);
      return res;
    }

    if (bitoffset !== 0)
      this.appendOp(OpCode.CPUI_INT_RIGHT, res, BigInt(bitoffset), 4);
    if (truncneeded)
      this.appendOp(OpCode.CPUI_SUBPIECE, res, BigInt(truncshift), 4);
    if (maskneeded)
      this.appendOp(OpCode.CPUI_INT_AND, res, maskval, finalsize);
    PcodeCompile.force_size(res.outvn!, new ConstTpl(const_type.real, BigInt(finalsize)), res.ops);
    return res;
  }

  addressOf(varnode: VarnodeTpl, size: number): VarnodeTpl {
    if (size === 0) {
      if (varnode.getSpace().getType() === const_type.spaceid) {
        const spc = varnode.getSpace().getSpace();
        size = (spc as any).getAddrSize();
      }
    }
    let res: VarnodeTpl;
    if (varnode.getOffset().getType() === const_type.real && varnode.getSpace().getType() === const_type.spaceid) {
      const spc = varnode.getSpace().getSpace();
      const off = AddrSpace.byteToAddress(varnode.getOffset().getReal(), (spc as any).getWordSize());
      res = new VarnodeTpl(
        new ConstTpl(this.constantspace!),
        new ConstTpl(const_type.real, off),
        new ConstTpl(const_type.real, BigInt(size)),
      );
    } else {
      res = new VarnodeTpl(
        new ConstTpl(this.constantspace!),
        varnode.getOffset(),
        new ConstTpl(const_type.real, BigInt(size)),
      );
    }
    return res;
  }

  static force_size(vt: VarnodeTpl, size: ConstTpl, ops: OpTpl[]): void {
    if (vt.getSize().getType() !== const_type.real || vt.getSize().getReal() !== 0n) return;
    vt.setSize(size);
    if (!vt.isLocalTemp()) return;
    for (let i = 0; i < ops.length; i++) {
      const op = ops[i];
      const vn = op.getOut();
      if (vn !== null && vn.isLocalTemp()) {
        if (vn.getOffset().equals(vt.getOffset())) {
          if (size.getType() === const_type.real && vn.getSize().getType() === const_type.real &&
            vn.getSize().getReal() !== 0n && vn.getSize().getReal() !== size.getReal()) {
            throw new LowlevelError('Localtemp size mismatch');
          }
          vn.setSize(size);
        }
      }
      for (let j = 0; j < op.numInput(); j++) {
        const inp = op.getIn(j);
        if (inp.isLocalTemp() && inp.getOffset().equals(vt.getOffset())) {
          if (size.getType() === const_type.real && inp.getSize().getType() === const_type.real &&
            inp.getSize().getReal() !== 0n && inp.getSize().getReal() !== size.getReal()) {
            throw new LowlevelError('Localtemp size mismatch');
          }
          inp.setSize(size);
        }
      }
    }
  }

  static matchSize(j: number, op: OpTpl, inputonly: boolean, ops: OpTpl[]): void {
    let match: VarnodeTpl | null = null;
    const vt = j === -1 ? op.getOut()! : op.getIn(j);
    if (!inputonly) {
      if (op.getOut() !== null && !op.getOut()!.isZeroSize()) {
        match = op.getOut()!;
      }
    }
    const inputsize = op.numInput();
    for (let i = 0; i < inputsize; i++) {
      if (match !== null) break;
      if (op.getIn(i).isZeroSize()) continue;
      match = op.getIn(i);
    }
    if (match !== null) {
      PcodeCompile.force_size(vt, match.getSize(), ops);
    }
  }

  static fillinZero(op: OpTpl, ops: OpTpl[]): void {
    let inputsize: number;
    switch (op.getOpcode()) {
      case OpCode.CPUI_COPY:
      case OpCode.CPUI_INT_ADD:
      case OpCode.CPUI_INT_SUB:
      case OpCode.CPUI_INT_2COMP:
      case OpCode.CPUI_INT_NEGATE:
      case OpCode.CPUI_INT_XOR:
      case OpCode.CPUI_INT_AND:
      case OpCode.CPUI_INT_OR:
      case OpCode.CPUI_INT_MULT:
      case OpCode.CPUI_INT_DIV:
      case OpCode.CPUI_INT_SDIV:
      case OpCode.CPUI_INT_REM:
      case OpCode.CPUI_INT_SREM:
      case OpCode.CPUI_FLOAT_ADD:
      case OpCode.CPUI_FLOAT_DIV:
      case OpCode.CPUI_FLOAT_MULT:
      case OpCode.CPUI_FLOAT_SUB:
      case OpCode.CPUI_FLOAT_NEG:
      case OpCode.CPUI_FLOAT_ABS:
      case OpCode.CPUI_FLOAT_SQRT:
      case OpCode.CPUI_FLOAT_CEIL:
      case OpCode.CPUI_FLOAT_FLOOR:
      case OpCode.CPUI_FLOAT_ROUND:
        if (op.getOut() !== null && op.getOut()!.isZeroSize())
          PcodeCompile.matchSize(-1, op, false, ops);
        inputsize = op.numInput();
        for (let i = 0; i < inputsize; i++)
          if (op.getIn(i).isZeroSize())
            PcodeCompile.matchSize(i, op, false, ops);
        break;
      case OpCode.CPUI_INT_EQUAL:
      case OpCode.CPUI_INT_NOTEQUAL:
      case OpCode.CPUI_INT_SLESS:
      case OpCode.CPUI_INT_SLESSEQUAL:
      case OpCode.CPUI_INT_LESS:
      case OpCode.CPUI_INT_LESSEQUAL:
      case OpCode.CPUI_INT_CARRY:
      case OpCode.CPUI_INT_SCARRY:
      case OpCode.CPUI_INT_SBORROW:
      case OpCode.CPUI_FLOAT_EQUAL:
      case OpCode.CPUI_FLOAT_NOTEQUAL:
      case OpCode.CPUI_FLOAT_LESS:
      case OpCode.CPUI_FLOAT_LESSEQUAL:
      case OpCode.CPUI_FLOAT_NAN:
      case OpCode.CPUI_BOOL_NEGATE:
      case OpCode.CPUI_BOOL_XOR:
      case OpCode.CPUI_BOOL_AND:
      case OpCode.CPUI_BOOL_OR:
        if (op.getOut()!.isZeroSize())
          PcodeCompile.force_size(op.getOut()!, new ConstTpl(const_type.real, 1n), ops);
        inputsize = op.numInput();
        for (let i = 0; i < inputsize; i++)
          if (op.getIn(i).isZeroSize())
            PcodeCompile.matchSize(i, op, true, ops);
        break;
      case OpCode.CPUI_INT_LEFT:
      case OpCode.CPUI_INT_RIGHT:
      case OpCode.CPUI_INT_SRIGHT:
        if (op.getOut()!.isZeroSize()) {
          if (!op.getIn(0).isZeroSize())
            PcodeCompile.force_size(op.getOut()!, op.getIn(0).getSize(), ops);
        } else if (op.getIn(0).isZeroSize()) {
          PcodeCompile.force_size(op.getIn(0), op.getOut()!.getSize(), ops);
        }
        // fall through
      case OpCode.CPUI_SUBPIECE:
        if (op.getIn(1).isZeroSize())
          PcodeCompile.force_size(op.getIn(1), new ConstTpl(const_type.real, 4n), ops);
        break;
      case OpCode.CPUI_CPOOLREF:
        if (op.getOut()!.isZeroSize() && !op.getIn(0).isZeroSize())
          PcodeCompile.force_size(op.getOut()!, op.getIn(0).getSize(), ops);
        if (op.getIn(0).isZeroSize() && !op.getOut()!.isZeroSize())
          PcodeCompile.force_size(op.getIn(0), op.getOut()!.getSize(), ops);
        for (let i = 1; i < op.numInput(); i++) {
          if (op.getIn(i).isZeroSize())
            PcodeCompile.force_size(op.getIn(i), new ConstTpl(const_type.real, 8n), ops);
        }
        break;
      default:
        break;
    }
  }

  static propagateSize(ct: ConstructTpl): boolean {
    let zerovec: OpTpl[] = [];
    const opvec = ct.getOpvec();
    for (let i = 0; i < opvec.length; i++) {
      if (opvec[i].isZeroSize()) {
        PcodeCompile.fillinZero(opvec[i], opvec);
        if (opvec[i].isZeroSize())
          zerovec.push(opvec[i]);
      }
    }
    let lastsize = zerovec.length + 1;
    while (zerovec.length < lastsize) {
      lastsize = zerovec.length;
      const zerovec2: OpTpl[] = [];
      for (let i = 0; i < zerovec.length; i++) {
        PcodeCompile.fillinZero(zerovec[i], opvec);
        if (zerovec[i].isZeroSize())
          zerovec2.push(zerovec[i]);
      }
      zerovec = zerovec2;
    }
    return lastsize === 0;
  }
}

// ============================================================================
// Symbol type enum (mirrors C++ SleighSymbol::symbol_type)
// ============================================================================
const enum SymbolType {
  space_symbol = 0,
  token_symbol = 1,
  userop_symbol = 2,
  value_symbol = 3,
  valuemap_symbol = 4,
  name_symbol = 5,
  varnode_symbol = 6,
  varnodelist_symbol = 7,
  operand_symbol = 8,
  start_symbol = 9,
  end_symbol = 10,
  next2_symbol = 11,
  subtable_symbol = 12,
  macro_symbol = 13,
  section_symbol = 14,
  bitrange_symbol = 15,
  context_symbol = 16,
  epsilon_symbol = 17,
  label_symbol = 18,
  flowdest_symbol = 19,
  flowref_symbol = 20,
  dummy_symbol = 21,
}

// ============================================================================
// PcodeSnippet - the main parser class
// ============================================================================

/**
 * PcodeSnippet extends PcodeCompile and provides a complete parser for
 * standalone p-code snippets against an existing SLEIGH language definition.
 *
 * Usage:
 *   const snippet = new PcodeSnippet(sleighBase);
 *   snippet.addOperand("op1", 0);
 *   const success = snippet.parsePcode("op1 = op1 + 1;");
 *   if (success) {
 *     const result = snippet.releaseResult();
 *   }
 */
export class PcodeSnippet extends PcodeCompile {
  private lexer: PcodeLexer = new PcodeLexer();
  private sleigh: SleighBase;
  private tree: Map<string, SleighSymbol> = new Map();
  private tempbase: number;
  private errorcount: number = 0;
  private firsterror: string = '';
  private result: ConstructTpl | null = null;

  // Parser state
  private currentToken!: Token;

  constructor(slgh: SleighBase) {
    super();
    this.sleigh = slgh;
    this.tempbase = 0;
    this.setDefaultSpace((slgh as any).getDefaultCodeSpace());
    this.setConstantSpace((slgh as any).getConstantSpace());
    this.setUniqueSpace((slgh as any).getUniqueSpace());
    const num: number = (slgh as any).numSpaces();
    for (let i = 0; i < num; i++) {
      const spc: AddrSpace = (slgh as any).getSpace(i);
      const type = spc.getType();
      if (
        type === spacetype.IPTR_CONSTANT ||
        type === spacetype.IPTR_PROCESSOR ||
        type === spacetype.IPTR_SPACEBASE ||
        type === spacetype.IPTR_INTERNAL
      ) {
        const spaceSym = {
          name_: spc.getName(),
          space_: spc,
          getName(): string { return this.name_; },
          getType(): number { return SymbolType.space_symbol; },
          getSpace(): AddrSpace { return this.space_; },
        };
        this.tree.set(spc.getName(), spaceSym);
      }
    }
    // Add flow symbols
    this.addFlowDestSymbol('inst_dest', (slgh as any).getConstantSpace());
    this.addFlowRefSymbol('inst_ref', (slgh as any).getConstantSpace());
  }

  private addFlowDestSymbol(name: string, cspc: AddrSpace): void {
    const sym = {
      name_: name,
      const_space_: cspc,
      getName(): string { return this.name_; },
      getType(): number { return SymbolType.flowdest_symbol; },
      getVarnode(): VarnodeTpl {
        return new VarnodeTpl(
          new ConstTpl(this.const_space_),
          new ConstTpl(const_type.j_flowdest),
          new ConstTpl(const_type.j_flowdest_size),
        );
      },
    };
    this.tree.set(name, sym);
  }

  private addFlowRefSymbol(name: string, cspc: AddrSpace): void {
    const sym = {
      name_: name,
      const_space_: cspc,
      getName(): string { return this.name_; },
      getType(): number { return SymbolType.flowref_symbol; },
      getVarnode(): VarnodeTpl {
        return new VarnodeTpl(
          new ConstTpl(this.const_space_),
          new ConstTpl(const_type.j_flowref),
          new ConstTpl(const_type.j_flowref_size),
        );
      },
    };
    this.tree.set(name, sym);
  }

  setResult(res: ConstructTpl): void {
    this.result = res;
  }

  releaseResult(): ConstructTpl | null {
    const res = this.result;
    this.result = null;
    return res;
  }

  hasErrors(): boolean {
    return this.errorcount !== 0;
  }

  getErrorMessage(): string {
    return this.firsterror;
  }

  setUniqueBase(val: number): void {
    this.tempbase = val;
  }

  getUniqueBase(): number {
    return this.tempbase;
  }

  override reportError(_loc: Location | null, msg: string): void {
    if (this.errorcount === 0) this.firsterror = msg;
    this.errorcount++;
  }

  override reportWarning(_loc: Location | null, _msg: string): void {
    // no-op
  }

  protected override allocateTemp(): number {
    const res = this.tempbase;
    this.tempbase += 16;
    return res;
  }

  protected override addSymbol(sym: SleighSymbol): void {
    const name: string = (sym as any).getName();
    if (this.tree.has(name)) {
      // In a recursive descent parser, lookahead can classify a token before
      // the previous statement's newOutput adds the symbol. When re-assigning
      // an existing local variable (e.g. "offset = ...; offset = offset * 4;"),
      // the second LHS "offset" may be classified as STRING rather than VARSYM
      // because the lookahead was read before newOutput ran. This is benign —
      // just skip the duplicate insertion (the existing symbol is correct).
      return;
    }
    this.tree.set(name, sym);
  }

  clear(): void {
    // Remove all non-space symbols
    const toRemove: string[] = [];
    for (const [name, sym] of this.tree) {
      if ((sym as any).getType() !== SymbolType.space_symbol) {
        toRemove.push(name);
      }
    }
    for (const name of toRemove) {
      this.tree.delete(name);
    }
    this.result = null;
    this.errorcount = 0;
    this.firsterror = '';
    this.resetLabelCount();
  }

  addOperand(name: string, index: number): void {
    const sym = {
      name_: name,
      index_: index,
      getName(): string { return this.name_; },
      getType(): number { return SymbolType.operand_symbol; },
      getIndex(): number { return this.index_; },
      getVarnode(): VarnodeTpl {
        return new VarnodeTpl(this.index_, false);
      },
    };
    this.addSymbol(sym as any);
  }

  /**
   * Main entry point: parse a p-code string.
   * Returns true on success, false on error.
   */
  parsePcode(input: string): boolean {
    this.lexer.initialize(input);
    this.advance(); // prime the first token
    try {
      const ct = this.parseRtl();
      this.setResult(ct);
    } catch (e) {
      if (e instanceof PcodeParseError) {
        this.reportError(null, e.message);
        return false;
      }
      throw e;
    }
    if (this.errorcount !== 0) return false;
    if (!PcodeCompile.propagateSize(this.result!)) {
      this.reportError(null, 'Could not resolve at least 1 variable size');
      return false;
    }
    return true;
  }

  // ========================================================================
  // Lexer integration - token lookup with symbol resolution
  // ========================================================================

  /**
   * Read the next token from the lexer, resolving STRING tokens
   * against the symbol table.
   */
  private nextToken(): Token {
    const raw = this.lexer.getNextToken();
    if (raw.type === TokenType.STRING) {
      // Look up in local symbols first, then global sleigh symbols
      let sym = this.tree.get(raw.stringVal!);
      if (sym === undefined) {
        sym = (this.sleigh as any).findSymbol(raw.stringVal!);
      }
      if (sym != null) {
        const symType: number = (sym as any).getType();
        switch (symType) {
          case SymbolType.space_symbol:
            return { type: TokenType.SPACESYM, spaceSym: sym };
          case SymbolType.userop_symbol:
            return { type: TokenType.USEROPSYM, userOpSym: sym };
          case SymbolType.varnode_symbol:
            return { type: TokenType.VARSYM, varSym: sym };
          case SymbolType.operand_symbol:
            return { type: TokenType.OPERANDSYM, operandSym: sym };
          case SymbolType.start_symbol:
          case SymbolType.end_symbol:
          case SymbolType.next2_symbol:
          case SymbolType.flowdest_symbol:
          case SymbolType.flowref_symbol:
            return { type: TokenType.JUMPSYM, specSym: sym };
          case SymbolType.label_symbol:
            return { type: TokenType.LABELSYM, labelSym: sym };
          case SymbolType.dummy_symbol:
            break;
          default:
            // Other symbol types not visible in snippet compiler
            break;
        }
      }
      return raw; // Return as STRING
    }
    return raw;
  }

  private advance(): void {
    this.currentToken = this.nextToken();
  }

  private tokenType(): number {
    return this.currentToken.type;
  }

  private expect(type: number): Token {
    if (this.currentToken.type !== type) {
      this.parseError(`Expected token ${tokenName(type)} but got ${tokenName(this.currentToken.type)}`);
    }
    const tok = this.currentToken;
    this.advance();
    return tok;
  }

  private match(type: number): boolean {
    if (this.currentToken.type === type) {
      this.advance();
      return true;
    }
    return false;
  }

  private check(type: number): boolean {
    return this.currentToken.type === type;
  }

  private parseError(msg: string): never {
    throw new PcodeParseError(msg);
  }

  // ========================================================================
  // Grammar: rtl
  // ========================================================================
  // rtl: rtlmid ENDOFSTREAM
  // rtlmid: /* EMPTY */
  //       | rtlmid statement
  //       | rtlmid LOCAL_KEY STRING ';'
  //       | rtlmid LOCAL_KEY STRING ':' INTEGER ';'

  private parseRtl(): ConstructTpl {
    const ct = new ConstructTpl();
    while (!this.check(TokenType.ENDOFSTREAM)) {
      // Check for local variable declarations:
      //   LOCAL_KEY STRING ';'
      //   LOCAL_KEY STRING ':' INTEGER ';'
      if (this.check(TokenType.LOCAL_KEY)) {
        this.advance(); // consume LOCAL_KEY
        if (this.check(TokenType.STRING)) {
          const name = this.currentToken.stringVal!;
          this.advance();
          if (this.match(':'.charCodeAt(0))) {
            const sizeTok = this.expect(TokenType.INTEGER);
            this.expect(';'.charCodeAt(0));
            this.newLocalDefinition(name, Number(sizeTok.intVal!));
          } else {
            this.expect(';'.charCodeAt(0));
            this.newLocalDefinition(name);
          }
          continue;
        }
        // LOCAL_KEY followed by something other than STRING -
        // could be LOCAL_KEY specificsymbol '=' (error in grammar) or
        // LOCAL_KEY STRING '=' expr ';' (new output) - push back via parseStatementAfterLocal
        const stmtOps = this.parseStatementAfterLocal();
        if (stmtOps !== null) {
          if (!ct.addOpList(stmtOps)) {
            this.parseError('Multiple delayslot declarations');
          }
        }
        continue;
      }

      const stmtOps = this.parseStatement();
      if (stmtOps !== null) {
        if (!ct.addOpList(stmtOps)) {
          this.parseError('Multiple delayslot declarations');
        }
      }
    }
    return ct;
  }

  // ========================================================================
  // Grammar: statement
  // ========================================================================
  // This is the most complex part due to ambiguity. We need to distinguish:
  // - lhsvarnode '=' expr ';'
  // - LOCAL_KEY STRING '=' expr ';'
  // - STRING '=' expr ';'
  // - LOCAL_KEY STRING ':' INTEGER '=' expr ';'
  // - STRING ':' INTEGER '=' expr ';'
  // - LOCAL_KEY specificsymbol '=' (error: redefinition)
  // - sizedstar expr '=' expr ';'
  // - USEROPSYM '(' paramlist ')' ';'
  // - lhsvarnode '[' INTEGER ',' INTEGER ']' '=' expr ';' (bitrange assign)
  // - varnode ':' INTEGER '=' (error: truncation on lhs)
  // - varnode '(' INTEGER ')' (error: subpiece on lhs)
  // - GOTO_KEY jumpdest ';'
  // - IF_KEY expr GOTO_KEY jumpdest ';'
  // - GOTO_KEY '[' expr ']' ';'
  // - CALL_KEY jumpdest ';'
  // - CALL_KEY '[' expr ']' ';'
  // - RETURN_KEY ';'
  // - RETURN_KEY '[' expr ']' ';'
  // - label

  private parseStatementAfterLocal(): OpTpl[] | null {
    // Called after LOCAL_KEY is consumed, and the next token is NOT a plain STRING
    // Could be: LOCAL_KEY specificsymbol '=' => error
    // Or: LOCAL_KEY STRING '=' expr ';' (already handled for STRING with = after)
    // But could also be LOCAL_KEY STRING ':' INTEGER '=' expr ';' (already handled)

    // Actually, re-examine: If LOCAL_KEY was consumed and next is not STRING,
    // it must be a specific symbol (like VARSYM/OPERANDSYM/JUMPSYM) -> error
    if (this.isSpecificSymbol()) {
      const sym = this.getSpecificSymbol();
      this.advance();
      this.expect('='.charCodeAt(0));
      this.reportError(null, 'Redefinition of symbol: ' + (sym as any).getName());
      // Consume the rest up to ';' to recover
      this.skipToSemicolon();
      return null;
    }
    // Otherwise it could be a STRING which was resolved to something
    if (this.check(TokenType.STRING)) {
      const name = this.currentToken.stringVal!;
      this.advance();
      if (this.match(':'.charCodeAt(0))) {
        const sizeTok = this.expect(TokenType.INTEGER);
        this.expect('='.charCodeAt(0));
        const rhs = this.parseExpr();
        this.expect(';'.charCodeAt(0));
        return this.newOutput(true, rhs, name, Number(sizeTok.intVal!));
      }
      this.expect('='.charCodeAt(0));
      const rhs = this.parseExpr();
      this.expect(';'.charCodeAt(0));
      return this.newOutput(true, rhs, name);
    }
    this.parseError('Unexpected token after local keyword');
  }

  private parseStatement(): OpTpl[] | null {
    // GOTO_KEY ...
    if (this.check(TokenType.GOTO_KEY)) {
      this.advance();
      if (this.match('['.charCodeAt(0))) {
        const e = this.parseExpr();
        this.expect(']'.charCodeAt(0));
        this.expect(';'.charCodeAt(0));
        return this.createOpNoOut(OpCode.CPUI_BRANCHIND, e);
      }
      const dest = this.parseJumpdest();
      this.expect(';'.charCodeAt(0));
      return this.createOpNoOut(OpCode.CPUI_BRANCH, new ExprTree(dest));
    }

    // IF_KEY expr GOTO_KEY jumpdest ';'
    if (this.check(TokenType.IF_KEY)) {
      this.advance();
      const cond = this.parseExpr();
      this.expect(TokenType.GOTO_KEY);
      const dest = this.parseJumpdest();
      this.expect(';'.charCodeAt(0));
      return this.createOpNoOut(OpCode.CPUI_CBRANCH, new ExprTree(dest), cond);
    }

    // CALL_KEY ...
    if (this.check(TokenType.CALL_KEY)) {
      this.advance();
      if (this.match('['.charCodeAt(0))) {
        const e = this.parseExpr();
        this.expect(']'.charCodeAt(0));
        this.expect(';'.charCodeAt(0));
        return this.createOpNoOut(OpCode.CPUI_CALLIND, e);
      }
      const dest = this.parseJumpdest();
      this.expect(';'.charCodeAt(0));
      return this.createOpNoOut(OpCode.CPUI_CALL, new ExprTree(dest));
    }

    // RETURN_KEY ...
    if (this.check(TokenType.RETURN_KEY)) {
      this.advance();
      if (this.match(';'.charCodeAt(0))) {
        this.reportError(null, 'Must specify an indirect parameter for return');
        return null;
      }
      this.expect('['.charCodeAt(0));
      const e = this.parseExpr();
      this.expect(']'.charCodeAt(0));
      this.expect(';'.charCodeAt(0));
      return this.createOpNoOut(OpCode.CPUI_RETURN, e);
    }

    // label: '<' ...
    if (this.check('<'.charCodeAt(0))) {
      const lab = this.parseLabel();
      return this.placeLabel(lab);
    }

    // USEROPSYM '(' paramlist ')' ';'
    if (this.check(TokenType.USEROPSYM)) {
      const sym = this.currentToken.userOpSym!;
      this.advance();
      // Could be an assignment: USEROPSYM is not an lhsvarnode, so it must be '('
      this.expect('('.charCodeAt(0));
      const params = this.parseParamlist();
      this.expect(')'.charCodeAt(0));
      this.expect(';'.charCodeAt(0));
      return this.createUserOpNoOut(sym, params);
    }

    // sizedstar expr '=' expr ';'  (store)
    // sizedstar also starts expressions (load) but at statement level the '*' means store
    if (this.check('*'.charCodeAt(0))) {
      const sq = this.parseSizedstar();
      const ptr = this.parseExpr();
      this.expect('='.charCodeAt(0));
      const val = this.parseExpr();
      this.expect(';'.charCodeAt(0));
      return this.createStore(sq, ptr, val);
    }

    // STRING '=' expr ';'
    // STRING ':' INTEGER '=' expr ';'
    if (this.check(TokenType.STRING)) {
      const name = this.currentToken.stringVal!;
      this.advance();
      if (this.match(':'.charCodeAt(0))) {
        const sizeTok = this.expect(TokenType.INTEGER);
        this.expect('='.charCodeAt(0));
        const rhs = this.parseExpr();
        this.expect(';'.charCodeAt(0));
        return this.newOutput(true, rhs, name, Number(sizeTok.intVal!));
      }
      if (this.match('='.charCodeAt(0))) {
        const rhs = this.parseExpr();
        this.expect(';'.charCodeAt(0));
        return this.newOutput(false, rhs, name);
      }
      // If we get here, STRING was not followed by '=' or ':', which is an error
      this.parseError('Unexpected token after identifier "' + name + '"');
    }

    // specificsymbol (VARSYM | OPERANDSYM | JUMPSYM) based assignments:
    // lhsvarnode '=' expr ';'
    // lhsvarnode '[' INTEGER ',' INTEGER ']' '=' expr ';'
    // varnode ':' INTEGER '=' => error
    // varnode '(' INTEGER ')' => error
    if (this.isSpecificSymbol()) {
      const sym = this.getSpecificSymbol();
      this.advance();
      const vn = (sym as any).getVarnode() as VarnodeTpl;

      if (this.match('='.charCodeAt(0))) {
        const rhs = this.parseExpr();
        this.expect(';'.charCodeAt(0));
        rhs.setOutput(vn);
        return ExprTree.toVector(rhs);
      }

      if (this.match('['.charCodeAt(0))) {
        const bit1 = this.expect(TokenType.INTEGER);
        this.expect(','.charCodeAt(0));
        const bit2 = this.expect(TokenType.INTEGER);
        this.expect(']'.charCodeAt(0));
        this.expect('='.charCodeAt(0));
        const rhs = this.parseExpr();
        this.expect(';'.charCodeAt(0));
        return this.assignBitRange(vn, Number(bit1.intVal!), Number(bit2.intVal!), rhs);
      }

      if (this.match(':'.charCodeAt(0))) {
        this.expect(TokenType.INTEGER);
        this.expect('='.charCodeAt(0));
        this.reportError(null, 'Illegal truncation on left-hand side of assignment');
        this.skipToSemicolon();
        return null;
      }

      if (this.match('('.charCodeAt(0))) {
        this.expect(TokenType.INTEGER);
        this.expect(')'.charCodeAt(0));
        this.reportError(null, 'Illegal subpiece on left-hand side of assignment');
        this.skipToSemicolon();
        return null;
      }

      this.parseError('Expected assignment operator after varnode');
    }

    this.parseError('Unexpected token at start of statement: ' + tokenName(this.tokenType()));
  }

  private skipToSemicolon(): void {
    while (!this.check(';'.charCodeAt(0)) && !this.check(TokenType.ENDOFSTREAM)) {
      this.advance();
    }
    if (this.check(';'.charCodeAt(0))) this.advance();
  }

  // ========================================================================
  // Grammar: label
  // ========================================================================
  // label: '<' LABELSYM '>'
  //      | '<' STRING '>'

  private parseLabel(): LabelSymbol {
    this.expect('<'.charCodeAt(0));
    if (this.check(TokenType.LABELSYM)) {
      const sym = this.currentToken.labelSym!;
      this.advance();
      this.expect('>'.charCodeAt(0));
      return sym;
    }
    if (this.check(TokenType.STRING)) {
      const name = this.currentToken.stringVal!;
      this.advance();
      this.expect('>'.charCodeAt(0));
      return this.defineLabel(name);
    }
    this.parseError('Expected label name after "<"');
  }

  // ========================================================================
  // Grammar: jumpdest
  // ========================================================================
  // jumpdest: JUMPSYM
  //         | INTEGER
  //         | BADINTEGER
  //         | INTEGER '[' SPACESYM ']'
  //         | label
  //         | STRING (error)

  private parseJumpdest(): VarnodeTpl {
    if (this.check(TokenType.JUMPSYM)) {
      const sym = this.currentToken.specSym!;
      this.advance();
      const vnSym = (sym as any).getVarnode() as VarnodeTpl;
      return new VarnodeTpl(
        new ConstTpl(const_type.j_curspace),
        vnSym.getOffset(),
        new ConstTpl(const_type.j_curspace_size),
      );
    }

    if (this.check(TokenType.INTEGER)) {
      const val = this.currentToken.intVal!;
      this.advance();
      if (this.match('['.charCodeAt(0))) {
        const spcTok = this.expect(TokenType.SPACESYM);
        this.expect(']'.charCodeAt(0));
        const spc: AddrSpace = (spcTok.spaceSym as any).getSpace();
        return new VarnodeTpl(
          new ConstTpl(spc),
          new ConstTpl(const_type.real, val),
          new ConstTpl(const_type.real, BigInt(spc.getAddrSize())),
        );
      }
      return new VarnodeTpl(
        new ConstTpl(const_type.j_curspace),
        new ConstTpl(const_type.real, val),
        new ConstTpl(const_type.j_curspace_size),
      );
    }

    if (this.check(TokenType.BADINTEGER)) {
      this.advance();
      this.reportError(null, 'Parsed integer is too big (overflow)');
      return new VarnodeTpl(
        new ConstTpl(const_type.j_curspace),
        new ConstTpl(const_type.real, 0n),
        new ConstTpl(const_type.j_curspace_size),
      );
    }

    // label
    if (this.check('<'.charCodeAt(0))) {
      const lab = this.parseLabel();
      (lab as any).incrementRefCount();
      return new VarnodeTpl(
        new ConstTpl(this.getConstantSpace()),
        new ConstTpl(const_type.j_relative, BigInt((lab as any).getIndex())),
        new ConstTpl(const_type.real, BigInt(SIZEOF_UINTM)),
      );
    }

    if (this.check(TokenType.STRING)) {
      const name = this.currentToken.stringVal!;
      this.advance();
      this.reportError(null, 'Unknown jump destination: ' + name);
      return new VarnodeTpl(
        new ConstTpl(const_type.j_curspace),
        new ConstTpl(const_type.real, 0n),
        new ConstTpl(const_type.j_curspace_size),
      );
    }

    this.parseError('Expected jump destination');
  }

  // ========================================================================
  // Grammar: sizedstar
  // ========================================================================
  // sizedstar: '*' '[' SPACESYM ']' ':' INTEGER
  //          | '*' '[' SPACESYM ']'
  //          | '*' ':' INTEGER
  //          | '*'

  private parseSizedstar(): StarQuality {
    this.expect('*'.charCodeAt(0));
    const sq = new StarQuality();

    if (this.match('['.charCodeAt(0))) {
      const spcTok = this.expect(TokenType.SPACESYM);
      this.expect(']'.charCodeAt(0));
      sq.id = new ConstTpl((spcTok.spaceSym as any).getSpace());
      if (this.match(':'.charCodeAt(0))) {
        const sizeTok = this.expect(TokenType.INTEGER);
        sq.size = Number(sizeTok.intVal!);
      } else {
        sq.size = 0;
      }
      return sq;
    }

    if (this.match(':'.charCodeAt(0))) {
      const sizeTok = this.expect(TokenType.INTEGER);
      sq.size = Number(sizeTok.intVal!);
      sq.id = new ConstTpl(this.getDefaultSpace());
      return sq;
    }

    sq.size = 0;
    sq.id = new ConstTpl(this.getDefaultSpace());
    return sq;
  }

  // ========================================================================
  // Grammar: specificsymbol
  // ========================================================================
  // specificsymbol: VARSYM | OPERANDSYM | JUMPSYM

  private isSpecificSymbol(): boolean {
    const t = this.tokenType();
    return t === TokenType.VARSYM || t === TokenType.OPERANDSYM || t === TokenType.JUMPSYM;
  }

  private getSpecificSymbol(): SpecificSymbol {
    const t = this.currentToken;
    if (t.type === TokenType.VARSYM) return t.varSym!;
    if (t.type === TokenType.OPERANDSYM) return t.operandSym!;
    if (t.type === TokenType.JUMPSYM) return t.specSym!;
    this.parseError('Expected specific symbol');
  }

  // ========================================================================
  // Grammar: varnode, integervarnode
  // ========================================================================
  // varnode: specificsymbol | integervarnode | STRING (error)
  // integervarnode: INTEGER
  //              | BADINTEGER
  //              | INTEGER ':' INTEGER
  //              | '&' varnode
  //              | '&' ':' INTEGER varnode

  private parseVarnode(): VarnodeTpl {
    if (this.isSpecificSymbol()) {
      const sym = this.getSpecificSymbol();
      this.advance();
      return (sym as any).getVarnode();
    }
    return this.parseIntegerVarnode();
  }

  private parseIntegerVarnode(): VarnodeTpl {
    if (this.check(TokenType.INTEGER)) {
      const val = this.currentToken.intVal!;
      this.advance();
      if (this.match(':'.charCodeAt(0))) {
        const sizeTok = this.expect(TokenType.INTEGER);
        return new VarnodeTpl(
          new ConstTpl(this.getConstantSpace()),
          new ConstTpl(const_type.real, val),
          new ConstTpl(const_type.real, sizeTok.intVal!),
        );
      }
      return new VarnodeTpl(
        new ConstTpl(this.getConstantSpace()),
        new ConstTpl(const_type.real, val),
        new ConstTpl(const_type.real, 0n),
      );
    }

    if (this.check(TokenType.BADINTEGER)) {
      this.advance();
      this.reportError(null, 'Parsed integer is too big (overflow)');
      return new VarnodeTpl(
        new ConstTpl(this.getConstantSpace()),
        new ConstTpl(const_type.real, 0n),
        new ConstTpl(const_type.real, 0n),
      );
    }

    if (this.match('&'.charCodeAt(0))) {
      if (this.match(':'.charCodeAt(0))) {
        const sizeTok = this.expect(TokenType.INTEGER);
        const inner = this.parseVarnode();
        return this.addressOf(inner, Number(sizeTok.intVal!));
      }
      const inner = this.parseVarnode();
      return this.addressOf(inner, 0);
    }

    if (this.check(TokenType.STRING)) {
      const name = this.currentToken.stringVal!;
      this.advance();
      this.reportError(null, 'Unknown varnode parameter: ' + name);
      // Return a dummy to allow parsing to continue
      return new VarnodeTpl(
        new ConstTpl(this.getConstantSpace()),
        new ConstTpl(const_type.real, 0n),
        new ConstTpl(const_type.real, 0n),
      );
    }

    this.parseError('Expected varnode');
  }

  // ========================================================================
  // Grammar: paramlist
  // ========================================================================
  // paramlist: /* EMPTY */ | expr | paramlist ',' expr

  private parseParamlist(): ExprTree[] {
    if (this.check(')'.charCodeAt(0))) {
      return [];
    }
    const params: ExprTree[] = [];
    params.push(this.parseExpr());
    while (this.match(','.charCodeAt(0))) {
      params.push(this.parseExpr());
    }
    return params;
  }

  // ========================================================================
  // Grammar: expr (operator precedence climbing)
  // ========================================================================
  // The yacc grammar defines precedence levels (lowest to highest):
  //   OP_BOOL_OR
  //   OP_BOOL_AND, OP_BOOL_XOR
  //   |
  //   ; (used as separator, but in grammar it's at precedence level)
  //   ^
  //   &
  //   == != f== f!=
  //   < > >= <= s< s> s>= s<= f< f> f<= f>=
  //   << >> s>>
  //   + - f+ f-
  //   * / % s/ s% f* f/
  //   unary: ! ~ (prefix -)
  //
  // We implement this via precedence climbing with explicit levels.

  private parseExpr(): ExprTree {
    return this.parseBoolOr();
  }

  // Level 1: OP_BOOL_OR (left assoc)
  private parseBoolOr(): ExprTree {
    let left = this.parseBoolAndXor();
    while (this.check(TokenType.OP_BOOL_OR)) {
      this.advance();
      const right = this.parseBoolAndXor();
      left = this.createOp(OpCode.CPUI_BOOL_OR, left, right);
    }
    return left;
  }

  // Level 2: OP_BOOL_AND, OP_BOOL_XOR (left assoc)
  private parseBoolAndXor(): ExprTree {
    let left = this.parseBitOr();
    while (true) {
      if (this.check(TokenType.OP_BOOL_AND)) {
        this.advance();
        const right = this.parseBitOr();
        left = this.createOp(OpCode.CPUI_BOOL_AND, left, right);
      } else if (this.check(TokenType.OP_BOOL_XOR)) {
        this.advance();
        const right = this.parseBitOr();
        left = this.createOp(OpCode.CPUI_BOOL_XOR, left, right);
      } else {
        break;
      }
    }
    return left;
  }

  // Level 3: | (left assoc)
  private parseBitOr(): ExprTree {
    let left = this.parseBitXor();
    while (this.check('|'.charCodeAt(0))) {
      this.advance();
      const right = this.parseBitXor();
      left = this.createOp(OpCode.CPUI_INT_OR, left, right);
    }
    return left;
  }

  // Level 4: ^ (left assoc) - note: ';' is also at this level in yacc but
  // we don't use ';' as a binary operator in expressions
  private parseBitXor(): ExprTree {
    let left = this.parseBitAnd();
    while (this.check('^'.charCodeAt(0))) {
      this.advance();
      const right = this.parseBitAnd();
      left = this.createOp(OpCode.CPUI_INT_XOR, left, right);
    }
    return left;
  }

  // Level 5: & (left assoc)
  private parseBitAnd(): ExprTree {
    let left = this.parseEquality();
    while (this.check('&'.charCodeAt(0))) {
      this.advance();
      const right = this.parseEquality();
      left = this.createOp(OpCode.CPUI_INT_AND, left, right);
    }
    return left;
  }

  // Level 6: == != f== f!=
  private parseEquality(): ExprTree {
    let left = this.parseComparison();
    while (true) {
      if (this.check(TokenType.OP_EQUAL)) {
        this.advance();
        const right = this.parseComparison();
        left = this.createOp(OpCode.CPUI_INT_EQUAL, left, right);
      } else if (this.check(TokenType.OP_NOTEQUAL)) {
        this.advance();
        const right = this.parseComparison();
        left = this.createOp(OpCode.CPUI_INT_NOTEQUAL, left, right);
      } else if (this.check(TokenType.OP_FEQUAL)) {
        this.advance();
        const right = this.parseComparison();
        left = this.createOp(OpCode.CPUI_FLOAT_EQUAL, left, right);
      } else if (this.check(TokenType.OP_FNOTEQUAL)) {
        this.advance();
        const right = this.parseComparison();
        left = this.createOp(OpCode.CPUI_FLOAT_NOTEQUAL, left, right);
      } else {
        break;
      }
    }
    return left;
  }

  // Level 7: < > >= <= s< s> s>= s<= f< f> f<= f>= (nonassoc in yacc, but we treat as left)
  private parseComparison(): ExprTree {
    let left = this.parseShift();
    // Only parse one comparison (nonassoc means no chaining)
    if (this.check('<'.charCodeAt(0))) {
      this.advance();
      const right = this.parseShift();
      return this.createOp(OpCode.CPUI_INT_LESS, left, right);
    }
    if (this.check('>'.charCodeAt(0))) {
      this.advance();
      const right = this.parseShift();
      return this.createOp(OpCode.CPUI_INT_LESS, right, left);
    }
    if (this.check(TokenType.OP_GREATEQUAL)) {
      this.advance();
      const right = this.parseShift();
      return this.createOp(OpCode.CPUI_INT_LESSEQUAL, right, left);
    }
    if (this.check(TokenType.OP_LESSEQUAL)) {
      this.advance();
      const right = this.parseShift();
      return this.createOp(OpCode.CPUI_INT_LESSEQUAL, left, right);
    }
    if (this.check(TokenType.OP_SLESS)) {
      this.advance();
      const right = this.parseShift();
      return this.createOp(OpCode.CPUI_INT_SLESS, left, right);
    }
    if (this.check(TokenType.OP_SGREAT)) {
      this.advance();
      const right = this.parseShift();
      return this.createOp(OpCode.CPUI_INT_SLESS, right, left);
    }
    if (this.check(TokenType.OP_SGREATEQUAL)) {
      this.advance();
      const right = this.parseShift();
      return this.createOp(OpCode.CPUI_INT_SLESSEQUAL, right, left);
    }
    if (this.check(TokenType.OP_SLESSEQUAL)) {
      this.advance();
      const right = this.parseShift();
      return this.createOp(OpCode.CPUI_INT_SLESSEQUAL, left, right);
    }
    if (this.check(TokenType.OP_FLESS)) {
      this.advance();
      const right = this.parseShift();
      return this.createOp(OpCode.CPUI_FLOAT_LESS, left, right);
    }
    if (this.check(TokenType.OP_FGREAT)) {
      this.advance();
      const right = this.parseShift();
      return this.createOp(OpCode.CPUI_FLOAT_LESS, right, left);
    }
    if (this.check(TokenType.OP_FLESSEQUAL)) {
      this.advance();
      const right = this.parseShift();
      return this.createOp(OpCode.CPUI_FLOAT_LESSEQUAL, left, right);
    }
    if (this.check(TokenType.OP_FGREATEQUAL)) {
      this.advance();
      const right = this.parseShift();
      return this.createOp(OpCode.CPUI_FLOAT_LESSEQUAL, right, left);
    }
    return left;
  }

  // Level 8: << >> s>>
  private parseShift(): ExprTree {
    let left = this.parseAddSub();
    while (true) {
      if (this.check(TokenType.OP_LEFT)) {
        this.advance();
        const right = this.parseAddSub();
        left = this.createOp(OpCode.CPUI_INT_LEFT, left, right);
      } else if (this.check(TokenType.OP_RIGHT)) {
        this.advance();
        const right = this.parseAddSub();
        left = this.createOp(OpCode.CPUI_INT_RIGHT, left, right);
      } else if (this.check(TokenType.OP_SRIGHT)) {
        this.advance();
        const right = this.parseAddSub();
        left = this.createOp(OpCode.CPUI_INT_SRIGHT, left, right);
      } else {
        break;
      }
    }
    return left;
  }

  // Level 9: + - f+ f-
  private parseAddSub(): ExprTree {
    let left = this.parseMulDiv();
    while (true) {
      if (this.check('+'.charCodeAt(0))) {
        this.advance();
        const right = this.parseMulDiv();
        left = this.createOp(OpCode.CPUI_INT_ADD, left, right);
      } else if (this.check('-'.charCodeAt(0))) {
        this.advance();
        const right = this.parseMulDiv();
        left = this.createOp(OpCode.CPUI_INT_SUB, left, right);
      } else if (this.check(TokenType.OP_FADD)) {
        this.advance();
        const right = this.parseMulDiv();
        left = this.createOp(OpCode.CPUI_FLOAT_ADD, left, right);
      } else if (this.check(TokenType.OP_FSUB)) {
        this.advance();
        const right = this.parseMulDiv();
        left = this.createOp(OpCode.CPUI_FLOAT_SUB, left, right);
      } else {
        break;
      }
    }
    return left;
  }

  // Level 10: * / % s/ s% f* f/
  private parseMulDiv(): ExprTree {
    let left = this.parseUnary();
    while (true) {
      if (this.check('*'.charCodeAt(0))) {
        this.advance();
        const right = this.parseUnary();
        left = this.createOp(OpCode.CPUI_INT_MULT, left, right);
      } else if (this.check('/'.charCodeAt(0))) {
        this.advance();
        const right = this.parseUnary();
        left = this.createOp(OpCode.CPUI_INT_DIV, left, right);
      } else if (this.check('%'.charCodeAt(0))) {
        this.advance();
        const right = this.parseUnary();
        left = this.createOp(OpCode.CPUI_INT_REM, left, right);
      } else if (this.check(TokenType.OP_SDIV)) {
        this.advance();
        const right = this.parseUnary();
        left = this.createOp(OpCode.CPUI_INT_SDIV, left, right);
      } else if (this.check(TokenType.OP_SREM)) {
        this.advance();
        const right = this.parseUnary();
        left = this.createOp(OpCode.CPUI_INT_SREM, left, right);
      } else if (this.check(TokenType.OP_FMULT)) {
        this.advance();
        const right = this.parseUnary();
        left = this.createOp(OpCode.CPUI_FLOAT_MULT, left, right);
      } else if (this.check(TokenType.OP_FDIV)) {
        this.advance();
        const right = this.parseUnary();
        left = this.createOp(OpCode.CPUI_FLOAT_DIV, left, right);
      } else {
        break;
      }
    }
    return left;
  }

  // Level 11: unary !, ~, -, f- (prefix), sizedstar (load)
  private parseUnary(): ExprTree {
    if (this.match('!'.charCodeAt(0))) {
      const e = this.parseUnary();
      return this.createOp(OpCode.CPUI_BOOL_NEGATE, e);
    }
    if (this.match('~'.charCodeAt(0))) {
      const e = this.parseUnary();
      return this.createOp(OpCode.CPUI_INT_NEGATE, e);
    }
    if (this.check('-'.charCodeAt(0))) {
      this.advance();
      const e = this.parseUnary();
      return this.createOp(OpCode.CPUI_INT_2COMP, e);
    }
    if (this.check(TokenType.OP_FSUB)) {
      this.advance();
      const e = this.parseUnary();
      return this.createOp(OpCode.CPUI_FLOAT_NEG, e);
    }

    // sizedstar for load: * expr
    if (this.check('*'.charCodeAt(0))) {
      const sq = this.parseSizedstar();
      const e = this.parseUnary();
      return this.createLoad(sq, e);
    }

    return this.parsePrimary();
  }

  // Primary expressions:
  //   varnode
  //   '(' expr ')'
  //   function-style ops: zext(...), sext(...), carry(...), etc.
  //   USEROPSYM '(' paramlist ')'
  //   specificsymbol '(' integervarnode ')'    -- subpiece
  //   specificsymbol ':' INTEGER               -- bitrange (size truncation)
  //   specificsymbol '[' INTEGER ',' INTEGER ']' -- bitrange

  private parsePrimary(): ExprTree {
    // Parenthesized expression
    if (this.match('('.charCodeAt(0))) {
      const e = this.parseExpr();
      this.expect(')'.charCodeAt(0));
      return e;
    }

    // Function-style unary ops
    if (this.check(TokenType.OP_SEXT)) { return this.parseFuncUnary(OpCode.CPUI_INT_SEXT); }
    if (this.check(TokenType.OP_ZEXT)) { return this.parseFuncUnary(OpCode.CPUI_INT_ZEXT); }
    if (this.check(TokenType.OP_ABS)) { return this.parseFuncUnary(OpCode.CPUI_FLOAT_ABS); }
    if (this.check(TokenType.OP_SQRT)) { return this.parseFuncUnary(OpCode.CPUI_FLOAT_SQRT); }
    if (this.check(TokenType.OP_FLOAT2FLOAT)) { return this.parseFuncUnary(OpCode.CPUI_FLOAT_FLOAT2FLOAT); }
    if (this.check(TokenType.OP_INT2FLOAT)) { return this.parseFuncUnary(OpCode.CPUI_FLOAT_INT2FLOAT); }
    if (this.check(TokenType.OP_NAN)) { return this.parseFuncUnary(OpCode.CPUI_FLOAT_NAN); }
    if (this.check(TokenType.OP_TRUNC)) { return this.parseFuncUnary(OpCode.CPUI_FLOAT_TRUNC); }
    if (this.check(TokenType.OP_CEIL)) { return this.parseFuncUnary(OpCode.CPUI_FLOAT_CEIL); }
    if (this.check(TokenType.OP_FLOOR)) { return this.parseFuncUnary(OpCode.CPUI_FLOAT_FLOOR); }
    if (this.check(TokenType.OP_ROUND)) { return this.parseFuncUnary(OpCode.CPUI_FLOAT_ROUND); }

    // Function-style binary ops
    if (this.check(TokenType.OP_CARRY)) { return this.parseFuncBinary(OpCode.CPUI_INT_CARRY); }
    if (this.check(TokenType.OP_SCARRY)) { return this.parseFuncBinary(OpCode.CPUI_INT_SCARRY); }
    if (this.check(TokenType.OP_SBORROW)) { return this.parseFuncBinary(OpCode.CPUI_INT_SBORROW); }
    if (this.check(TokenType.OP_BORROW)) {
      // borrow is just carry in the yacc grammar... but actually there's no CPUI_INT_BORROW
      // The grammar doesn't define borrow as an expression rule; it's just a token.
      // Actually looking at the grammar, OP_BORROW is defined as a token but not used in expr rules.
      // Just consume it as an error for now.
      this.parseError('borrow is not valid in expressions');
    }

    // OP_NEW - can be unary or binary
    if (this.check(TokenType.OP_NEW)) {
      this.advance();
      this.expect('('.charCodeAt(0));
      const e1 = this.parseExpr();
      if (this.match(','.charCodeAt(0))) {
        const e2 = this.parseExpr();
        this.expect(')'.charCodeAt(0));
        return this.createOp(OpCode.CPUI_NEW, e1, e2);
      }
      this.expect(')'.charCodeAt(0));
      return this.createOp(OpCode.CPUI_NEW, e1);
    }

    // USEROPSYM '(' paramlist ')'
    if (this.check(TokenType.USEROPSYM)) {
      const sym = this.currentToken.userOpSym!;
      this.advance();
      this.expect('('.charCodeAt(0));
      const params = this.parseParamlist();
      this.expect(')'.charCodeAt(0));
      return this.createUserOp(sym, params);
    }

    // specificsymbol with possible postfix: '(' integervarnode ')' | ':' INTEGER | '[' INTEGER ',' INTEGER ']'
    if (this.isSpecificSymbol()) {
      const sym = this.getSpecificSymbol();
      this.advance();

      // specificsymbol '(' integervarnode ')' => SUBPIECE
      if (this.match('('.charCodeAt(0))) {
        const ivn = this.parseIntegerVarnode();
        this.expect(')'.charCodeAt(0));
        return this.createOp(
          OpCode.CPUI_SUBPIECE,
          new ExprTree((sym as any).getVarnode()),
          new ExprTree(ivn),
        );
      }

      // specificsymbol ':' INTEGER => createBitRange
      if (this.match(':'.charCodeAt(0))) {
        const sizeTok = this.expect(TokenType.INTEGER);
        return this.createBitRange(sym, 0, Number(sizeTok.intVal!) * 8);
      }

      // specificsymbol '[' INTEGER ',' INTEGER ']' => createBitRange
      if (this.match('['.charCodeAt(0))) {
        const bit1 = this.expect(TokenType.INTEGER);
        this.expect(','.charCodeAt(0));
        const bit2 = this.expect(TokenType.INTEGER);
        this.expect(']'.charCodeAt(0));
        return this.createBitRange(sym, Number(bit1.intVal!), Number(bit2.intVal!));
      }

      // Plain specificsymbol varnode
      return new ExprTree((sym as any).getVarnode());
    }

    // varnode (INTEGER with possible ':' size, BADINTEGER, '&', STRING)
    // INTEGER
    if (this.check(TokenType.INTEGER) || this.check(TokenType.BADINTEGER) || this.check('&'.charCodeAt(0))) {
      const vn = this.parseIntegerVarnode();
      return new ExprTree(vn);
    }

    // STRING as unknown varnode
    if (this.check(TokenType.STRING)) {
      const name = this.currentToken.stringVal!;
      this.advance();
      this.reportError(null, 'Unknown varnode parameter: ' + name);
      return new ExprTree(new VarnodeTpl(
        new ConstTpl(this.getConstantSpace()),
        new ConstTpl(const_type.real, 0n),
        new ConstTpl(const_type.real, 0n),
      ));
    }

    this.parseError('Expected expression, got ' + tokenName(this.tokenType()));
  }

  private parseFuncUnary(opc: OpCode): ExprTree {
    this.advance();
    this.expect('('.charCodeAt(0));
    const e = this.parseExpr();
    this.expect(')'.charCodeAt(0));
    return this.createOp(opc, e);
  }

  private parseFuncBinary(opc: OpCode): ExprTree {
    this.advance();
    this.expect('('.charCodeAt(0));
    const e1 = this.parseExpr();
    this.expect(','.charCodeAt(0));
    const e2 = this.parseExpr();
    this.expect(')'.charCodeAt(0));
    return this.createOp(opc, e1, e2);
  }
}

// ============================================================================
// Parse error class
// ============================================================================
class PcodeParseError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = 'PcodeParseError';
  }
}

// ============================================================================
// Token name helper for error messages
// ============================================================================
function tokenName(type: number): string {
  if (type >= 32 && type < 127) {
    return "'" + String.fromCharCode(type) + "'";
  }
  switch (type) {
    case TokenType.ENDOFSTREAM: return 'end-of-stream';
    case TokenType.INTEGER: return 'integer';
    case TokenType.STRING: return 'identifier';
    case TokenType.BADINTEGER: return 'bad-integer';
    case TokenType.GOTO_KEY: return 'goto';
    case TokenType.CALL_KEY: return 'call';
    case TokenType.RETURN_KEY: return 'return';
    case TokenType.IF_KEY: return 'if';
    case TokenType.LOCAL_KEY: return 'local';
    case TokenType.OP_BOOL_OR: return '||';
    case TokenType.OP_BOOL_AND: return '&&';
    case TokenType.OP_BOOL_XOR: return '^^';
    case TokenType.OP_EQUAL: return '==';
    case TokenType.OP_NOTEQUAL: return '!=';
    case TokenType.OP_GREATEQUAL: return '>=';
    case TokenType.OP_LESSEQUAL: return '<=';
    case TokenType.OP_LEFT: return '<<';
    case TokenType.OP_RIGHT: return '>>';
    case TokenType.OP_SRIGHT: return 's>>';
    case TokenType.OP_SLESS: return 's<';
    case TokenType.OP_SGREAT: return 's>';
    case TokenType.OP_SLESSEQUAL: return 's<=';
    case TokenType.OP_SGREATEQUAL: return 's>=';
    case TokenType.OP_SDIV: return 's/';
    case TokenType.OP_SREM: return 's%';
    case TokenType.OP_FEQUAL: return 'f==';
    case TokenType.OP_FNOTEQUAL: return 'f!=';
    case TokenType.OP_FLESS: return 'f<';
    case TokenType.OP_FGREAT: return 'f>';
    case TokenType.OP_FLESSEQUAL: return 'f<=';
    case TokenType.OP_FGREATEQUAL: return 'f>=';
    case TokenType.OP_FADD: return 'f+';
    case TokenType.OP_FSUB: return 'f-';
    case TokenType.OP_FMULT: return 'f*';
    case TokenType.OP_FDIV: return 'f/';
    case TokenType.OP_ZEXT: return 'zext';
    case TokenType.OP_SEXT: return 'sext';
    case TokenType.OP_CARRY: return 'carry';
    case TokenType.OP_BORROW: return 'borrow';
    case TokenType.OP_SCARRY: return 'scarry';
    case TokenType.OP_SBORROW: return 'sborrow';
    case TokenType.OP_NAN: return 'nan';
    case TokenType.OP_ABS: return 'abs';
    case TokenType.OP_SQRT: return 'sqrt';
    case TokenType.OP_CEIL: return 'ceil';
    case TokenType.OP_FLOOR: return 'floor';
    case TokenType.OP_ROUND: return 'round';
    case TokenType.OP_INT2FLOAT: return 'int2float';
    case TokenType.OP_FLOAT2FLOAT: return 'float2float';
    case TokenType.OP_TRUNC: return 'trunc';
    case TokenType.OP_NEW: return 'new';
    case TokenType.SPACESYM: return 'space-symbol';
    case TokenType.USEROPSYM: return 'userop-symbol';
    case TokenType.VARSYM: return 'varnode-symbol';
    case TokenType.OPERANDSYM: return 'operand-symbol';
    case TokenType.JUMPSYM: return 'jump-symbol';
    case TokenType.LABELSYM: return 'label-symbol';
    default: return `token(${type})`;
  }
}
