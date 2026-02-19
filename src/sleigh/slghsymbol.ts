import type { int4, uint4, uintb, uintm, intb } from '../core/types.js';
import { AddrSpace, spacetype } from '../core/space.js';
import { Address } from '../core/address.js';
import { LowlevelError, DecoderError } from '../core/error.js';
import { VarnodeData } from '../core/pcoderaw.js';
import { BadDataError } from '../core/translate.js';
import type { Encoder, Decoder } from '../core/marshal.js';
import type { Writer } from '../util/writer.js';

import {
  ConstTpl, VarnodeTpl, HandleTpl, ConstructTpl,
} from './semantics.js';
import {
  PatternExpression, PatternValue, PatternEquation,
  TokenPattern, OperandValue, ConstantValue,
  StartInstructionValue, EndInstructionValue, Next2InstructionValue,
  ContextField, OperandResolve,
} from './slghpatexpress.js';
import { DisjointPattern, Pattern } from './slghpattern.js';
import {
  SleighError, Token, ParserWalker, ParserWalkerChange,
  ParserContext, FixedHandle, ConstructState,
} from './context.js';

import {
  SLA_ELEM_SYMBOL_TABLE, SLA_ELEM_SCOPE, SLA_ELEM_USEROP, SLA_ELEM_USEROP_HEAD,
  SLA_ELEM_EPSILON_SYM, SLA_ELEM_EPSILON_SYM_HEAD,
  SLA_ELEM_VALUE_SYM, SLA_ELEM_VALUE_SYM_HEAD,
  SLA_ELEM_VALUEMAP_SYM, SLA_ELEM_VALUEMAP_SYM_HEAD,
  SLA_ELEM_NAME_SYM, SLA_ELEM_NAME_SYM_HEAD,
  SLA_ELEM_VARNODE_SYM, SLA_ELEM_VARNODE_SYM_HEAD,
  SLA_ELEM_CONTEXT_SYM, SLA_ELEM_CONTEXT_SYM_HEAD,
  SLA_ELEM_VARLIST_SYM, SLA_ELEM_VARLIST_SYM_HEAD,
  SLA_ELEM_OPERAND_SYM, SLA_ELEM_OPERAND_SYM_HEAD,
  SLA_ELEM_START_SYM, SLA_ELEM_START_SYM_HEAD,
  SLA_ELEM_END_SYM, SLA_ELEM_END_SYM_HEAD,
  SLA_ELEM_NEXT2_SYM, SLA_ELEM_NEXT2_SYM_HEAD,
  SLA_ELEM_SUBTABLE_SYM, SLA_ELEM_SUBTABLE_SYM_HEAD,
  SLA_ELEM_CONSTRUCTOR, SLA_ELEM_DECISION, SLA_ELEM_PAIR,
  SLA_ELEM_CONTEXT_OP, SLA_ELEM_COMMIT,
  SLA_ELEM_OPER, SLA_ELEM_OPPRINT, SLA_ELEM_PRINT,
  SLA_ELEM_VALUETAB, SLA_ELEM_NAMETAB, SLA_ELEM_VAR, SLA_ELEM_NULL,
  SLA_ATTRIB_NAME, SLA_ATTRIB_ID, SLA_ATTRIB_SCOPE, SLA_ATTRIB_SCOPESIZE,
  SLA_ATTRIB_SYMBOLSIZE, SLA_ATTRIB_PARENT, SLA_ATTRIB_INDEX,
  SLA_ATTRIB_SPACE, SLA_ATTRIB_OFF, SLA_ATTRIB_SIZE,
  SLA_ATTRIB_VARNODE, SLA_ATTRIB_LOW, SLA_ATTRIB_HIGH, SLA_ATTRIB_FLOW,
  SLA_ATTRIB_SUBSYM, SLA_ATTRIB_BASE, SLA_ATTRIB_MINLEN,
  SLA_ATTRIB_CODE, SLA_ATTRIB_VAL, SLA_ATTRIB_FIRST,
  SLA_ATTRIB_LENGTH, SLA_ATTRIB_SOURCE, SLA_ATTRIB_LINE,
  SLA_ATTRIB_PIECE, SLA_ATTRIB_I, SLA_ATTRIB_SHIFT, SLA_ATTRIB_MASK,
  SLA_ATTRIB_NUMBER, SLA_ATTRIB_CONTEXT, SLA_ATTRIB_STARTBIT,
  SLA_ATTRIB_NUMCT,
} from './slaformat.js';

// Forward type declarations for not-yet-wired modules
type SleighBase = any;

const SIZEOF_UINTM = 4;

// =========================================================================
// SymbolType enum
// =========================================================================

export const enum SymbolType {
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

// =========================================================================
// calc_maskword helper
// =========================================================================

function calc_maskword(sbit: number, ebit: number): { num: number; shift: number; mask: number } {
  const wordBits = 8 * SIZEOF_UINTM; // 32
  const num = Math.floor(sbit / wordBits);
  if (num !== Math.floor(ebit / wordBits))
    throw new SleighError('Context field not contained within one machine int');
  sbit -= num * wordBits;
  ebit -= num * wordBits;
  const shift = wordBits - ebit - 1;
  let mask = (0xFFFFFFFF >>> (sbit + shift));
  mask = (mask << shift) >>> 0;
  return { num, shift, mask: mask | 0 };
}

// =========================================================================
// SleighSymbol
// =========================================================================

export class SleighSymbol {
  private _name: string = '';
  public id: number = 0;       // Unique id across all symbols (public for SymbolTable friend access)
  public scopeid: number = 0;  // Unique id of scope

  constructor(nm?: string) {
    if (nm !== undefined) {
      this._name = nm;
      this.id = 0;
    }
  }

  getName(): string { return this._name; }
  getId(): number { return this.id; }
  getType(): SymbolType { return SymbolType.dummy_symbol; }

  encodeHeader(encoder: Encoder): void {
    encoder.writeString(SLA_ATTRIB_NAME, this._name);
    encoder.writeUnsignedInteger(SLA_ATTRIB_ID, BigInt(this.id));
    encoder.writeUnsignedInteger(SLA_ATTRIB_SCOPE, BigInt(this.scopeid));
  }

  decodeHeader(decoder: Decoder): void {
    const el = decoder.openElement();
    this._name = decoder.readStringById(SLA_ATTRIB_NAME);
    this.id = Number(decoder.readUnsignedIntegerById(SLA_ATTRIB_ID));
    this.scopeid = Number(decoder.readUnsignedIntegerById(SLA_ATTRIB_SCOPE));
    decoder.closeElement(el);
  }

  encode(encoder: Encoder): void {
    throw new LowlevelError('Symbol ' + this._name + ' cannot be encoded to stream directly');
  }

  decode(decoder: Decoder, trans: SleighBase): void {
    throw new LowlevelError('Symbol ' + this._name + ' cannot be decoded from stream directly');
  }
}

// =========================================================================
// SymbolScope
// =========================================================================

export class SymbolScope {
  private parent: SymbolScope | null;
  public tree: Map<string, SleighSymbol> = new Map();
  public id: number;

  constructor(p: SymbolScope | null, i: number) {
    this.parent = p;
    this.id = i;
  }

  getParent(): SymbolScope | null { return this.parent; }
  getId(): number { return this.id; }

  addSymbol(a: SleighSymbol): SleighSymbol {
    const existing = this.tree.get(a.getName());
    if (existing !== undefined) return existing;
    this.tree.set(a.getName(), a);
    return a;
  }

  findSymbol(nm: string): SleighSymbol | null {
    return this.tree.get(nm) ?? null;
  }

  removeSymbol(a: SleighSymbol): void {
    this.tree.delete(a.getName());
  }

  [Symbol.iterator](): IterableIterator<SleighSymbol> {
    return this.tree.values();
  }
}

// =========================================================================
// SymbolTable
// =========================================================================

export class SymbolTable {
  private symbollist: (SleighSymbol | null)[] = [];
  private table: (SymbolScope | null)[] = [];
  private curscope: SymbolScope | null = null;

  getCurrentScope(): SymbolScope | null { return this.curscope; }
  getGlobalScope(): SymbolScope { return this.table[0]!; }
  setCurrentScope(scope: SymbolScope): void { this.curscope = scope; }

  addScope(): void {
    this.curscope = new SymbolScope(this.curscope, this.table.length);
    this.table.push(this.curscope);
  }

  popScope(): void {
    if (this.curscope !== null)
      this.curscope = this.curscope.getParent();
  }

  private skipScope(i: number): SymbolScope {
    let res = this.curscope!;
    while (i > 0) {
      if (res.getParent() === null) return res;
      res = res.getParent()!;
      --i;
    }
    return res;
  }

  addGlobalSymbol(a: SleighSymbol): void {
    a.id = this.symbollist.length;
    this.symbollist.push(a);
    const scope = this.getGlobalScope();
    a.scopeid = scope.getId();
    const res = scope.addSymbol(a);
    if (res !== a)
      throw new SleighError("Duplicate symbol name '" + a.getName() + "'");
  }

  addSymbol(a: SleighSymbol): void {
    a.id = this.symbollist.length;
    this.symbollist.push(a);
    a.scopeid = this.curscope!.getId();
    const res = this.curscope!.addSymbol(a);
    if (res !== a)
      throw new SleighError('Duplicate symbol name: ' + a.getName());
  }

  private findSymbolInternal(scope: SymbolScope | null, nm: string): SleighSymbol | null {
    while (scope !== null) {
      const res = scope.findSymbol(nm);
      if (res !== null) return res;
      scope = scope.getParent();
    }
    return null;
  }

  findSymbol(nm: string): SleighSymbol | null;
  findSymbol(nm: string, skip: number): SleighSymbol | null;
  findSymbol(id: number): SleighSymbol | null;
  findSymbol(arg0: string | number, skip?: number): SleighSymbol | null {
    if (typeof arg0 === 'number') {
      return this.symbollist[arg0] ?? null;
    }
    if (skip !== undefined) {
      return this.findSymbolInternal(this.skipScope(skip), arg0);
    }
    return this.findSymbolInternal(this.curscope, arg0);
  }

  findGlobalSymbol(nm: string): SleighSymbol | null {
    return this.findSymbolInternal(this.table[0]!, nm);
  }

  replaceSymbol(a: SleighSymbol, b: SleighSymbol): void {
    for (let i = this.table.length - 1; i >= 0; --i) {
      const scope = this.table[i];
      if (scope === null) continue;
      const sym = scope.findSymbol(a.getName());
      if (sym === a) {
        scope.removeSymbol(a);
        b.id = a.id;
        b.scopeid = a.scopeid;
        this.symbollist[b.id] = b;
        scope.addSymbol(b);
        return;
      }
    }
  }

  encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_SYMBOL_TABLE);
    encoder.writeSignedInteger(SLA_ATTRIB_SCOPESIZE, this.table.length);
    encoder.writeSignedInteger(SLA_ATTRIB_SYMBOLSIZE, this.symbollist.length);
    for (let i = 0; i < this.table.length; ++i) {
      encoder.openElement(SLA_ELEM_SCOPE);
      encoder.writeUnsignedInteger(SLA_ATTRIB_ID, BigInt(this.table[i]!.getId()));
      if (this.table[i]!.getParent() === null)
        encoder.writeUnsignedInteger(SLA_ATTRIB_PARENT, 0n);
      else
        encoder.writeUnsignedInteger(SLA_ATTRIB_PARENT, BigInt(this.table[i]!.getParent()!.getId()));
      encoder.closeElement(SLA_ELEM_SCOPE);
    }
    for (let i = 0; i < this.symbollist.length; ++i)
      this.symbollist[i]!.encodeHeader(encoder);
    for (let i = 0; i < this.symbollist.length; ++i)
      this.symbollist[i]!.encode(encoder);
    encoder.closeElement(SLA_ELEM_SYMBOL_TABLE);
  }

  decode(decoder: Decoder, trans: SleighBase): void {
    const el = decoder.openElementId(SLA_ELEM_SYMBOL_TABLE);
    const scopesize = decoder.readSignedIntegerById(SLA_ATTRIB_SCOPESIZE);
    const symbolsize = decoder.readSignedIntegerById(SLA_ATTRIB_SYMBOLSIZE);
    this.table = new Array(scopesize).fill(null);
    this.symbollist = new Array(symbolsize).fill(null);
    for (let i = 0; i < scopesize; ++i) {
      const subel = decoder.openElementId(SLA_ELEM_SCOPE);
      const id = Number(decoder.readUnsignedIntegerById(SLA_ATTRIB_ID));
      const parent = Number(decoder.readUnsignedIntegerById(SLA_ATTRIB_PARENT));
      const parscope = (parent === id) ? null : this.table[parent];
      this.table[id] = new SymbolScope(parscope, id);
      decoder.closeElement(subel);
    }
    this.curscope = this.table[0]!;
    for (let i = 0; i < symbolsize; ++i)
      this.decodeSymbolHeader(decoder);
    while (decoder.peekElement() !== 0) {
      decoder.openElement();
      const id = Number(decoder.readUnsignedIntegerById(SLA_ATTRIB_ID));
      const sym = this.findSymbol(id)!;
      sym.decode(decoder, trans);
    }
    decoder.closeElement(el);
  }

  decodeSymbolHeader(decoder: Decoder): void {
    let sym: SleighSymbol;
    const el = decoder.peekElement();
    if (el === SLA_ELEM_USEROP_HEAD.id)
      sym = new UserOpSymbol();
    else if (el === SLA_ELEM_EPSILON_SYM_HEAD.id)
      sym = new EpsilonSymbol();
    else if (el === SLA_ELEM_VALUE_SYM_HEAD.id)
      sym = new ValueSymbol();
    else if (el === SLA_ELEM_VALUEMAP_SYM_HEAD.id)
      sym = new ValueMapSymbol();
    else if (el === SLA_ELEM_NAME_SYM_HEAD.id)
      sym = new NameSymbol();
    else if (el === SLA_ELEM_VARNODE_SYM_HEAD.id)
      sym = new VarnodeSymbol();
    else if (el === SLA_ELEM_CONTEXT_SYM_HEAD.id)
      sym = new ContextSymbol();
    else if (el === SLA_ELEM_VARLIST_SYM_HEAD.id)
      sym = new VarnodeListSymbol();
    else if (el === SLA_ELEM_OPERAND_SYM_HEAD.id)
      sym = new OperandSymbol();
    else if (el === SLA_ELEM_START_SYM_HEAD.id)
      sym = new StartSymbol();
    else if (el === SLA_ELEM_END_SYM_HEAD.id)
      sym = new EndSymbol();
    else if (el === SLA_ELEM_NEXT2_SYM_HEAD.id)
      sym = new Next2Symbol();
    else if (el === SLA_ELEM_SUBTABLE_SYM_HEAD.id)
      sym = new SubtableSymbol();
    else
      throw new SleighError('Bad symbol xml');
    sym.decodeHeader(decoder);
    this.symbollist[sym.id] = sym;
    this.table[sym.scopeid]!.addSymbol(sym);
  }

  purge(): void {
    for (let i = 0; i < this.symbollist.length; ++i) {
      const sym = this.symbollist[i];
      if (sym === null) continue;
      if (sym.scopeid !== 0) {
        if (sym.getType() === SymbolType.operand_symbol) continue;
      } else {
        switch (sym.getType()) {
          case SymbolType.space_symbol:
          case SymbolType.token_symbol:
          case SymbolType.epsilon_symbol:
          case SymbolType.section_symbol:
          case SymbolType.bitrange_symbol:
            break;
          case SymbolType.macro_symbol: {
            const macro = sym as MacroSymbol;
            for (let j = 0; j < macro.getNumOperands(); ++j) {
              const opersym = macro.getOperand(j);
              this.table[opersym.scopeid]!.removeSymbol(opersym);
              this.symbollist[opersym.id] = null;
            }
            break;
          }
          case SymbolType.subtable_symbol: {
            const subsym = sym as SubtableSymbol;
            if (subsym.getPattern() !== null) continue;
            for (let j = 0; j < subsym.getNumConstructors(); ++j) {
              const con = subsym.getConstructor(j);
              for (let k = 0; k < con.getNumOperands(); ++k) {
                const oper = con.getOperand(k);
                this.table[oper.scopeid]!.removeSymbol(oper);
                this.symbollist[oper.id] = null;
              }
            }
            break;
          }
          default:
            continue;
        }
      }
      this.table[sym.scopeid]!.removeSymbol(sym);
      this.symbollist[i] = null;
    }
    for (let i = 1; i < this.table.length; ++i) {
      if (this.table[i] !== null && this.table[i]!.tree.size === 0) {
        this.table[i] = null;
      }
    }
    this.renumber();
  }

  private renumber(): void {
    const newtable: SymbolScope[] = [];
    const newsymbol: SleighSymbol[] = [];
    for (let i = 0; i < this.table.length; ++i) {
      const scope = this.table[i];
      if (scope !== null) {
        scope.id = newtable.length;
        newtable.push(scope);
      }
    }
    for (let i = 0; i < this.symbollist.length; ++i) {
      const sym = this.symbollist[i];
      if (sym !== null) {
        sym.scopeid = (this.table[sym.scopeid] as SymbolScope).id;
        sym.id = newsymbol.length;
        newsymbol.push(sym);
      }
    }
    this.table = newtable;
    this.symbollist = newsymbol;
  }
}

// =========================================================================
// SpaceSymbol
// =========================================================================

export class SpaceSymbol extends SleighSymbol {
  private space: AddrSpace;

  constructor(spc: AddrSpace) {
    super(spc.getName());
    this.space = spc;
  }

  getSpace(): AddrSpace { return this.space; }
  override getType(): SymbolType { return SymbolType.space_symbol; }
}

// =========================================================================
// TokenSymbol
// =========================================================================

export class TokenSymbol extends SleighSymbol {
  private tok: Token;

  constructor(t: Token) {
    super(t.getName());
    this.tok = t;
  }

  getToken(): Token { return this.tok; }
  override getType(): SymbolType { return SymbolType.token_symbol; }
}

// =========================================================================
// SectionSymbol
// =========================================================================

export class SectionSymbol extends SleighSymbol {
  private templateid: number;
  private define_count: number = 0;
  private ref_count: number = 0;

  constructor(nm: string, id: number) {
    super(nm);
    this.templateid = id;
  }

  getTemplateId(): number { return this.templateid; }
  incrementDefineCount(): void { this.define_count += 1; }
  incrementRefCount(): void { this.ref_count += 1; }
  getDefineCount(): number { return this.define_count; }
  getRefCount(): number { return this.ref_count; }
  override getType(): SymbolType { return SymbolType.section_symbol; }
}

// =========================================================================
// UserOpSymbol
// =========================================================================

export class UserOpSymbol extends SleighSymbol {
  private index: number = 0;

  constructor(nm?: string) {
    super(nm);
  }

  setIndex(ind: number): void { this.index = ind; }
  getIndex(): number { return this.index; }
  override getType(): SymbolType { return SymbolType.userop_symbol; }

  override encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_USEROP);
    encoder.writeUnsignedInteger(SLA_ATTRIB_ID, BigInt(this.getId()));
    encoder.writeSignedInteger(SLA_ATTRIB_INDEX, this.index);
    encoder.closeElement(SLA_ELEM_USEROP);
  }

  override encodeHeader(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_USEROP_HEAD);
    super.encodeHeader(encoder);
    encoder.closeElement(SLA_ELEM_USEROP_HEAD);
  }

  override decode(decoder: Decoder, trans: SleighBase): void {
    this.index = decoder.readSignedIntegerById(SLA_ATTRIB_INDEX);
    decoder.closeElement(SLA_ELEM_USEROP.id);
  }
}

// =========================================================================
// TripleSymbol (abstract)
// =========================================================================

export abstract class TripleSymbol extends SleighSymbol {
  constructor(nm?: string) {
    super(nm);
  }

  resolve(walker: ParserWalker): Constructor | null { return null; }
  abstract getPatternExpression(): PatternExpression;
  abstract getFixedHandle(hand: FixedHandle, walker: ParserWalker): void;
  getSize(): number { return 0; }
  abstract print(s: Writer, walker: ParserWalker): void;
  collectLocalValues(results: bigint[]): void {}
}

// =========================================================================
// FamilySymbol (abstract)
// =========================================================================

export abstract class FamilySymbol extends TripleSymbol {
  constructor(nm?: string) {
    super(nm);
  }

  abstract getPatternValue(): PatternValue;
}

// =========================================================================
// SpecificSymbol (abstract)
// =========================================================================

export abstract class SpecificSymbol extends TripleSymbol {
  constructor(nm?: string) {
    super(nm);
  }

  abstract getVarnode(): VarnodeTpl;
}

// =========================================================================
// PatternlessSymbol
// =========================================================================

export class PatternlessSymbol extends SpecificSymbol {
  protected patexp: ConstantValue;

  constructor(nm?: string) {
    super(nm);
    this.patexp = new ConstantValue(0n);
    this.patexp.layClaim();
  }

  override getPatternExpression(): PatternExpression { return this.patexp; }

  getFixedHandle(_hand: FixedHandle, _walker: ParserWalker): void {
    throw new LowlevelError('PatternlessSymbol.getFixedHandle not implemented');
  }

  print(_s: Writer, _walker: ParserWalker): void {
    throw new LowlevelError('PatternlessSymbol.print not implemented');
  }

  getVarnode(): VarnodeTpl {
    throw new LowlevelError('PatternlessSymbol.getVarnode not implemented');
  }
}

// =========================================================================
// EpsilonSymbol
// =========================================================================

export class EpsilonSymbol extends PatternlessSymbol {
  private const_space: AddrSpace | null = null;

  constructor();
  constructor(nm: string, spc: AddrSpace);
  constructor(nm?: string, spc?: AddrSpace) {
    super(nm);
    if (spc !== undefined)
      this.const_space = spc;
  }

  override getFixedHandle(hand: FixedHandle, walker: ParserWalker): void {
    hand.space = this.const_space;
    hand.offset_space = null;
    hand.offset_offset = 0n;
    hand.size = 0;
  }

  override print(s: Writer, walker: ParserWalker): void {
    s.write('0');
  }

  override getType(): SymbolType { return SymbolType.epsilon_symbol; }

  override getVarnode(): VarnodeTpl {
    return new VarnodeTpl(
      new ConstTpl(this.const_space!),
      new ConstTpl(ConstTpl.real, 0n),
      new ConstTpl(ConstTpl.real, 0n)
    );
  }

  override encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_EPSILON_SYM);
    encoder.writeUnsignedInteger(SLA_ATTRIB_ID, BigInt(this.getId()));
    encoder.closeElement(SLA_ELEM_EPSILON_SYM);
  }

  override encodeHeader(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_EPSILON_SYM_HEAD);
    super.encodeHeader(encoder);
    encoder.closeElement(SLA_ELEM_EPSILON_SYM_HEAD);
  }

  override decode(decoder: Decoder, trans: SleighBase): void {
    this.const_space = trans.getConstantSpace();
    decoder.closeElement(SLA_ELEM_EPSILON_SYM.id);
  }
}

// =========================================================================
// ValueSymbol
// =========================================================================

export class ValueSymbol extends FamilySymbol {
  protected patval: PatternValue | null = null;

  constructor();
  constructor(nm: string, pv: PatternValue);
  constructor(nm?: string, pv?: PatternValue) {
    super(nm);
    if (pv !== undefined) {
      this.patval = pv;
      pv.layClaim();
    }
  }

  override getPatternValue(): PatternValue { return this.patval!; }
  override getPatternExpression(): PatternExpression { return this.patval!; }

  override getFixedHandle(hand: FixedHandle, walker: ParserWalker): void {
    hand.space = walker.getConstSpace();
    hand.offset_space = null;
    hand.offset_offset = BigInt(this.patval!.getValue(walker)) & 0xFFFFFFFFFFFFFFFFn;
    hand.size = 0;
  }

  override print(s: Writer, walker: ParserWalker): void {
    const val: bigint = this.patval!.getValue(walker);
    if (val >= 0n)
      s.write('0x' + val.toString(16));
    else
      s.write('-0x' + (-val).toString(16));
  }

  override getType(): SymbolType { return SymbolType.value_symbol; }

  override encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_VALUE_SYM);
    encoder.writeUnsignedInteger(SLA_ATTRIB_ID, BigInt(this.getId()));
    this.patval!.encode(encoder);
    encoder.closeElement(SLA_ELEM_VALUE_SYM);
  }

  override encodeHeader(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_VALUE_SYM_HEAD);
    super.encodeHeader(encoder);
    encoder.closeElement(SLA_ELEM_VALUE_SYM_HEAD);
  }

  override decode(decoder: Decoder, trans: SleighBase): void {
    this.patval = PatternExpression.decodeExpression(decoder, trans) as PatternValue;
    this.patval.layClaim();
    decoder.closeElement(SLA_ELEM_VALUE_SYM.id);
  }

  // Abstract stubs from SpecificSymbol not applicable here
  getVarnode(): VarnodeTpl {
    throw new SleighError('Cannot get varnode from FamilySymbol');
  }
}

// =========================================================================
// ValueMapSymbol
// =========================================================================

export class ValueMapSymbol extends ValueSymbol {
  private valuetable: bigint[] = [];
  private tableisfilled: boolean = false;

  constructor();
  constructor(nm: string, pv: PatternValue, vt: bigint[]);
  constructor(nm?: string, pv?: PatternValue, vt?: bigint[]) {
    super(nm!, pv!);
    if (vt !== undefined) {
      this.valuetable = [...vt];
      this.checkTableFill();
    }
  }

  private checkTableFill(): void {
    const min = this.patval!.minValue();
    const max = this.patval!.maxValue();
    this.tableisfilled = (min >= 0n) && (max < BigInt(this.valuetable.length));
    for (let i = 0; i < this.valuetable.length; ++i) {
      if (this.valuetable[i] === 0xBADBEEFn)
        this.tableisfilled = false;
    }
  }

  override resolve(walker: ParserWalker): Constructor | null {
    if (!this.tableisfilled) {
      const ind = this.patval!.getValue(walker);
      if (ind >= BigInt(this.valuetable.length) || ind < 0n || this.valuetable[Number(ind)] === 0xBADBEEFn) {
        const addr = walker.getAddr();
        throw new BadDataError(addr.getShortcut() + addr.printRaw() + ': No corresponding entry in valuetable');
      }
    }
    return null;
  }

  override getFixedHandle(hand: FixedHandle, walker: ParserWalker): void {
    const ind = Number(this.patval!.getValue(walker));
    hand.space = walker.getConstSpace();
    hand.offset_space = null;
    hand.offset_offset = BigInt(this.valuetable[ind]) & 0xFFFFFFFFFFFFFFFFn;
    hand.size = 0;
  }

  override print(s: Writer, walker: ParserWalker): void {
    const ind = Number(this.patval!.getValue(walker));
    const val = this.valuetable[ind];
    if (val >= 0n)
      s.write('0x' + val.toString(16));
    else
      s.write('-0x' + (-val).toString(16));
  }

  override getType(): SymbolType { return SymbolType.valuemap_symbol; }

  override encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_VALUEMAP_SYM);
    encoder.writeUnsignedInteger(SLA_ATTRIB_ID, BigInt(this.getId()));
    this.patval!.encode(encoder);
    for (let i = 0; i < this.valuetable.length; ++i) {
      encoder.openElement(SLA_ELEM_VALUETAB);
      encoder.writeSignedInteger(SLA_ATTRIB_VAL, Number(this.valuetable[i]));
      encoder.closeElement(SLA_ELEM_VALUETAB);
    }
    encoder.closeElement(SLA_ELEM_VALUEMAP_SYM);
  }

  override encodeHeader(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_VALUEMAP_SYM_HEAD);
    SleighSymbol.prototype.encodeHeader.call(this, encoder);
    encoder.closeElement(SLA_ELEM_VALUEMAP_SYM_HEAD);
  }

  override decode(decoder: Decoder, trans: SleighBase): void {
    this.patval = PatternExpression.decodeExpression(decoder, trans) as PatternValue;
    this.patval.layClaim();
    while (decoder.peekElement() !== 0) {
      const subel = decoder.openElement();
      const val = BigInt(decoder.readSignedIntegerById(SLA_ATTRIB_VAL));
      this.valuetable.push(val);
      decoder.closeElement(subel);
    }
    decoder.closeElement(SLA_ELEM_VALUEMAP_SYM.id);
    this.checkTableFill();
  }
}

// =========================================================================
// NameSymbol
// =========================================================================

export class NameSymbol extends ValueSymbol {
  private nametable: string[] = [];
  private tableisfilled: boolean = false;

  constructor();
  constructor(nm: string, pv: PatternValue, nt: string[]);
  constructor(nm?: string, pv?: PatternValue, nt?: string[]) {
    super(nm!, pv!);
    if (nt !== undefined) {
      this.nametable = [...nt];
      this.checkTableFill();
    }
  }

  private checkTableFill(): void {
    const min = this.patval!.minValue();
    const max = this.patval!.maxValue();
    this.tableisfilled = (min >= 0n) && (max < BigInt(this.nametable.length));
    for (let i = 0; i < this.nametable.length; ++i) {
      if (this.nametable[i] === '_' || this.nametable[i] === '\t') {
        this.nametable[i] = '\t';
        this.tableisfilled = false;
      }
    }
  }

  override resolve(walker: ParserWalker): Constructor | null {
    if (!this.tableisfilled) {
      const ind = this.patval!.getValue(walker);
      if (ind >= BigInt(this.nametable.length) || ind < 0n ||
          (this.nametable[Number(ind)].length === 1 && this.nametable[Number(ind)][0] === '\t')) {
        const addr = walker.getAddr();
        throw new BadDataError(addr.getShortcut() + addr.printRaw() + ': No corresponding entry in nametable');
      }
    }
    return null;
  }

  override print(s: Writer, walker: ParserWalker): void {
    const ind = Number(this.patval!.getValue(walker));
    s.write(this.nametable[ind]);
  }

  override getType(): SymbolType { return SymbolType.name_symbol; }

  override encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_NAME_SYM);
    encoder.writeUnsignedInteger(SLA_ATTRIB_ID, BigInt(this.getId()));
    this.patval!.encode(encoder);
    for (let i = 0; i < this.nametable.length; ++i) {
      encoder.openElement(SLA_ELEM_NAMETAB);
      if (this.nametable[i] !== '\t') {
        encoder.writeString(SLA_ATTRIB_NAME, this.nametable[i]);
      }
      encoder.closeElement(SLA_ELEM_NAMETAB);
    }
    encoder.closeElement(SLA_ELEM_NAME_SYM);
  }

  override encodeHeader(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_NAME_SYM_HEAD);
    SleighSymbol.prototype.encodeHeader.call(this, encoder);
    encoder.closeElement(SLA_ELEM_NAME_SYM_HEAD);
  }

  override decode(decoder: Decoder, trans: SleighBase): void {
    this.patval = PatternExpression.decodeExpression(decoder, trans) as PatternValue;
    this.patval.layClaim();
    while (decoder.peekElement() !== 0) {
      const subel = decoder.openElement();
      if (decoder.getNextAttributeId() === SLA_ATTRIB_NAME.id)
        this.nametable.push(decoder.readString());
      else
        this.nametable.push('\t');
      decoder.closeElement(subel);
    }
    decoder.closeElement(SLA_ELEM_NAME_SYM.id);
    this.checkTableFill();
  }
}

// =========================================================================
// VarnodeSymbol
// =========================================================================

export class VarnodeSymbol extends PatternlessSymbol {
  private fix: VarnodeData = new VarnodeData();
  private context_bits: boolean = false;

  constructor();
  constructor(nm: string, base: AddrSpace, offset: bigint, size: number);
  constructor(nm?: string, base?: AddrSpace, offset?: bigint, size?: number) {
    super(nm);
    if (base !== undefined) {
      this.fix.space = base;
      this.fix.offset = offset!;
      this.fix.size = size!;
      this.context_bits = false;
    }
  }

  markAsContext(): void { this.context_bits = true; }
  getFixedVarnode(): VarnodeData { return this.fix; }

  override getVarnode(): VarnodeTpl {
    return new VarnodeTpl(
      new ConstTpl(this.fix.space! as any as AddrSpace),
      new ConstTpl(ConstTpl.real, this.fix.offset),
      new ConstTpl(ConstTpl.real, BigInt(this.fix.size))
    );
  }

  override getFixedHandle(hand: FixedHandle, walker: ParserWalker): void {
    hand.space = this.fix.space as any;
    hand.offset_space = null;
    hand.offset_offset = this.fix.offset;
    hand.size = this.fix.size;
  }

  override getSize(): number { return this.fix.size; }

  override print(s: Writer, walker: ParserWalker): void {
    s.write(this.getName());
  }

  override collectLocalValues(results: bigint[]): void {
    if ((this.fix.space as any).getType() === spacetype.IPTR_INTERNAL)
      results.push(this.fix.offset);
  }

  override getType(): SymbolType { return SymbolType.varnode_symbol; }

  override encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_VARNODE_SYM);
    encoder.writeUnsignedInteger(SLA_ATTRIB_ID, BigInt(this.getId()));
    encoder.writeSpace(SLA_ATTRIB_SPACE, this.fix.space! as any as AddrSpace);
    encoder.writeUnsignedInteger(SLA_ATTRIB_OFF, this.fix.offset);
    encoder.writeSignedInteger(SLA_ATTRIB_SIZE, this.fix.size);
    encoder.closeElement(SLA_ELEM_VARNODE_SYM);
  }

  override encodeHeader(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_VARNODE_SYM_HEAD);
    super.encodeHeader(encoder);
    encoder.closeElement(SLA_ELEM_VARNODE_SYM_HEAD);
  }

  override decode(decoder: Decoder, trans: SleighBase): void {
    this.fix.space = decoder.readSpaceById(SLA_ATTRIB_SPACE);
    this.fix.offset = decoder.readUnsignedIntegerById(SLA_ATTRIB_OFF);
    this.fix.size = decoder.readSignedIntegerById(SLA_ATTRIB_SIZE);
    decoder.closeElement(SLA_ELEM_VARNODE_SYM.id);
  }
}

// =========================================================================
// BitrangeSymbol
// =========================================================================

export class BitrangeSymbol extends SleighSymbol {
  private varsym: VarnodeSymbol | null = null;
  private bitoffset: number = 0;
  private numbits_val: number = 0;

  constructor();
  constructor(nm: string, sym: VarnodeSymbol, bitoff: number, num: number);
  constructor(nm?: string, sym?: VarnodeSymbol, bitoff?: number, num?: number) {
    super(nm);
    if (sym !== undefined) {
      this.varsym = sym;
      this.bitoffset = bitoff!;
      this.numbits_val = num!;
    }
  }

  getParentSymbol(): VarnodeSymbol { return this.varsym!; }
  getBitOffset(): number { return this.bitoffset; }
  numBits(): number { return this.numbits_val; }
  override getType(): SymbolType { return SymbolType.bitrange_symbol; }
}

// =========================================================================
// ContextSymbol
// =========================================================================

export class ContextSymbol extends ValueSymbol {
  private vn: VarnodeSymbol | null = null;
  private low: number = 0;
  private high: number = 0;
  private _flow: boolean = false;

  constructor();
  constructor(nm: string, pate: ContextField, v: VarnodeSymbol, l: number, h: number, fl: boolean);
  constructor(nm?: string, pate?: ContextField, v?: VarnodeSymbol, l?: number, h?: number, fl?: boolean) {
    super(nm!, pate as any);
    if (v !== undefined) {
      this.vn = v;
      this.low = l!;
      this.high = h!;
      this._flow = fl!;
    }
  }

  getVarnodeSym(): VarnodeSymbol { return this.vn!; }
  getLow(): number { return this.low; }
  getHigh(): number { return this.high; }
  getFlow(): boolean { return this._flow; }
  override getType(): SymbolType { return SymbolType.context_symbol; }

  override encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_CONTEXT_SYM);
    encoder.writeUnsignedInteger(SLA_ATTRIB_ID, BigInt(this.getId()));
    encoder.writeUnsignedInteger(SLA_ATTRIB_VARNODE, BigInt(this.vn!.getId()));
    encoder.writeSignedInteger(SLA_ATTRIB_LOW, this.low);
    encoder.writeSignedInteger(SLA_ATTRIB_HIGH, this.high);
    encoder.writeBool(SLA_ATTRIB_FLOW, this._flow);
    this.patval!.encode(encoder);
    encoder.closeElement(SLA_ELEM_CONTEXT_SYM);
  }

  override encodeHeader(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_CONTEXT_SYM_HEAD);
    SleighSymbol.prototype.encodeHeader.call(this, encoder);
    encoder.closeElement(SLA_ELEM_CONTEXT_SYM_HEAD);
  }

  override decode(decoder: Decoder, trans: SleighBase): void {
    this._flow = false;
    let highMissing = true;
    let lowMissing = true;
    let attrib = decoder.getNextAttributeId();
    while (attrib !== 0) {
      if (attrib === SLA_ATTRIB_VARNODE.id) {
        const id = Number(decoder.readUnsignedInteger());
        this.vn = trans.findSymbolById(id) as VarnodeSymbol;
      } else if (attrib === SLA_ATTRIB_LOW.id) {
        this.low = decoder.readSignedInteger();
        lowMissing = false;
      } else if (attrib === SLA_ATTRIB_HIGH.id) {
        this.high = decoder.readSignedInteger();
        highMissing = false;
      } else if (attrib === SLA_ATTRIB_FLOW.id) {
        this._flow = decoder.readBool();
      }
      attrib = decoder.getNextAttributeId();
    }
    if (lowMissing || highMissing) {
      throw new DecoderError('Missing high/low attributes');
    }
    this.patval = PatternExpression.decodeExpression(decoder, trans) as PatternValue;
    this.patval.layClaim();
    decoder.closeElement(SLA_ELEM_CONTEXT_SYM.id);
  }
}

// =========================================================================
// VarnodeListSymbol
// =========================================================================

export class VarnodeListSymbol extends ValueSymbol {
  private varnode_table: (VarnodeSymbol | null)[] = [];
  private tableisfilled: boolean = false;

  constructor();
  constructor(nm: string, pv: PatternValue, vt: SleighSymbol[]);
  constructor(nm?: string, pv?: PatternValue, vt?: SleighSymbol[]) {
    super(nm!, pv!);
    if (vt !== undefined) {
      for (let i = 0; i < vt.length; ++i)
        this.varnode_table.push(vt[i] as VarnodeSymbol | null);
      this.checkTableFill();
    }
  }

  private checkTableFill(): void {
    const min = this.patval!.minValue();
    const max = this.patval!.maxValue();
    this.tableisfilled = (min >= 0n) && (max < BigInt(this.varnode_table.length));
    for (let i = 0; i < this.varnode_table.length; ++i) {
      if (this.varnode_table[i] === null)
        this.tableisfilled = false;
    }
  }

  override resolve(walker: ParserWalker): Constructor | null {
    if (!this.tableisfilled) {
      const ind = this.patval!.getValue(walker);
      if (ind < 0n || ind >= BigInt(this.varnode_table.length) || this.varnode_table[Number(ind)] === null) {
        const addr = walker.getAddr();
        throw new BadDataError(addr.getShortcut() + addr.printRaw() + ': No corresponding entry in varnode list');
      }
    }
    return null;
  }

  override getFixedHandle(hand: FixedHandle, walker: ParserWalker): void {
    const ind = Number(this.patval!.getValue(walker));
    const fix = this.varnode_table[ind]!.getFixedVarnode();
    hand.space = fix.space as any;
    hand.offset_space = null;
    hand.offset_offset = fix.offset;
    hand.size = fix.size;
  }

  override getSize(): number {
    for (let i = 0; i < this.varnode_table.length; ++i) {
      const vnsym = this.varnode_table[i];
      if (vnsym !== null)
        return vnsym.getSize();
    }
    throw new SleighError('No register attached to: ' + this.getName());
  }

  override print(s: Writer, walker: ParserWalker): void {
    const ind = Number(this.patval!.getValue(walker));
    if (ind >= this.varnode_table.length)
      throw new SleighError('Value out of range for varnode table');
    s.write(this.varnode_table[ind]!.getName());
  }

  override getType(): SymbolType { return SymbolType.varnodelist_symbol; }

  override encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_VARLIST_SYM);
    encoder.writeUnsignedInteger(SLA_ATTRIB_ID, BigInt(this.getId()));
    this.patval!.encode(encoder);
    for (let i = 0; i < this.varnode_table.length; ++i) {
      if (this.varnode_table[i] === null) {
        encoder.openElement(SLA_ELEM_NULL);
        encoder.closeElement(SLA_ELEM_NULL);
      } else {
        encoder.openElement(SLA_ELEM_VAR);
        encoder.writeUnsignedInteger(SLA_ATTRIB_ID, BigInt(this.varnode_table[i]!.getId()));
        encoder.closeElement(SLA_ELEM_VAR);
      }
    }
    encoder.closeElement(SLA_ELEM_VARLIST_SYM);
  }

  override encodeHeader(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_VARLIST_SYM_HEAD);
    SleighSymbol.prototype.encodeHeader.call(this, encoder);
    encoder.closeElement(SLA_ELEM_VARLIST_SYM_HEAD);
  }

  override decode(decoder: Decoder, trans: SleighBase): void {
    this.patval = PatternExpression.decodeExpression(decoder, trans) as PatternValue;
    this.patval.layClaim();
    while (decoder.peekElement() !== 0) {
      const subel = decoder.openElement();
      if (subel === SLA_ELEM_VAR.id) {
        const id = Number(decoder.readUnsignedIntegerById(SLA_ATTRIB_ID));
        this.varnode_table.push(trans.findSymbolById(id) as VarnodeSymbol);
      } else {
        this.varnode_table.push(null);
      }
      decoder.closeElement(subel);
    }
    decoder.closeElement(SLA_ELEM_VARLIST_SYM.id);
    this.checkTableFill();
  }
}

// =========================================================================
// OperandSymbol
// =========================================================================

export class OperandSymbol extends SpecificSymbol {
  static readonly code_address = 1;
  static readonly offset_irrel = 2;
  static readonly variable_len = 4;
  static readonly marked = 8;

  public reloffset: number = 0;
  public offsetbase: number = -1;
  public minimumlength: number = 0;
  public hand: number = 0;
  public localexp: OperandValue | null = null;
  private triple: TripleSymbol | null = null;
  private defexp: PatternExpression | null = null;
  private flags: number = 0;

  constructor();
  constructor(nm: string, index: number, ct: Constructor);
  constructor(nm?: string, index?: number, ct?: Constructor) {
    super(nm);
    if (index !== undefined && ct !== undefined) {
      this.flags = 0;
      this.hand = index;
      this.localexp = new OperandValue(index, ct);
      this.localexp.layClaim();
      this.defexp = null;
      this.triple = null;
    }
  }

  private setVariableLength(): void { this.flags |= OperandSymbol.variable_len; }
  isVariableLength(): boolean { return (this.flags & OperandSymbol.variable_len) !== 0; }

  getRelativeOffset(): number { return this.reloffset; }
  getOffsetBase(): number { return this.offsetbase; }
  getMinimumLength(): number { return this.minimumlength; }
  getDefiningExpression(): PatternExpression | null { return this.defexp; }
  getDefiningSymbol(): TripleSymbol | null { return this.triple; }
  getIndex(): number { return this.hand; }

  defineOperandExpr(pe: PatternExpression): void {
    if (this.defexp !== null || this.triple !== null)
      throw new SleighError('Redefining operand');
    this.defexp = pe;
    this.defexp.layClaim();
  }

  defineOperandSym(tri: TripleSymbol): void {
    if (this.defexp !== null || this.triple !== null)
      throw new SleighError('Redefining operand');
    this.triple = tri;
  }

  setCodeAddress(): void { this.flags |= OperandSymbol.code_address; }
  isCodeAddress(): boolean { return (this.flags & OperandSymbol.code_address) !== 0; }
  setOffsetIrrelevant(): void { this.flags |= OperandSymbol.offset_irrel; }
  isOffsetIrrelevant(): boolean { return (this.flags & OperandSymbol.offset_irrel) !== 0; }
  setMark(): void { this.flags |= OperandSymbol.marked; }
  clearMark(): void { this.flags &= ~OperandSymbol.marked; }
  isMarked(): boolean { return (this.flags & OperandSymbol.marked) !== 0; }

  override getVarnode(): VarnodeTpl {
    if (this.defexp !== null)
      return new VarnodeTpl(this.hand, true);
    if (this.triple !== null && (this.triple instanceof SpecificSymbol)) {
      return (this.triple as SpecificSymbol).getVarnode();
    }
    if (this.triple !== null &&
        (this.triple.getType() === SymbolType.valuemap_symbol || this.triple.getType() === SymbolType.name_symbol))
      return new VarnodeTpl(this.hand, true);
    return new VarnodeTpl(this.hand, false);
  }

  override getPatternExpression(): PatternExpression { return this.localexp!; }

  override getFixedHandle(hand: FixedHandle, walker: ParserWalker): void {
    const hnd = walker.getFixedHandle(this.hand);
    hand.space = hnd.space;
    hand.size = hnd.size;
    hand.offset_space = hnd.offset_space;
    hand.offset_offset = hnd.offset_offset;
    hand.offset_size = hnd.offset_size;
    hand.temp_space = hnd.temp_space;
    hand.temp_offset = hnd.temp_offset;
  }

  override getSize(): number {
    if (this.triple !== null)
      return this.triple.getSize();
    return 0;
  }

  override print(s: Writer, walker: ParserWalker): void {
    walker.pushOperand(this.getIndex());
    if (this.triple !== null) {
      if (this.triple.getType() === SymbolType.subtable_symbol)
        walker.getConstructor().print(s, walker);
      else
        this.triple.print(s, walker);
    } else {
      const val: bigint = this.defexp!.getValue(walker);
      if (val >= 0n)
        s.write('0x' + val.toString(16));
      else
        s.write('-0x' + (-val).toString(16));
    }
    walker.popOperand();
  }

  override collectLocalValues(results: bigint[]): void {
    if (this.triple !== null)
      this.triple.collectLocalValues(results);
  }

  override getType(): SymbolType { return SymbolType.operand_symbol; }

  override encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_OPERAND_SYM);
    encoder.writeUnsignedInteger(SLA_ATTRIB_ID, BigInt(this.getId()));
    if (this.triple !== null)
      encoder.writeUnsignedInteger(SLA_ATTRIB_SUBSYM, BigInt(this.triple.getId()));
    encoder.writeSignedInteger(SLA_ATTRIB_OFF, this.reloffset);
    encoder.writeSignedInteger(SLA_ATTRIB_BASE, this.offsetbase);
    encoder.writeSignedInteger(SLA_ATTRIB_MINLEN, this.minimumlength);
    if (this.isCodeAddress())
      encoder.writeBool(SLA_ATTRIB_CODE, true);
    encoder.writeSignedInteger(SLA_ATTRIB_INDEX, this.hand);
    this.localexp!.encode(encoder);
    if (this.defexp !== null)
      this.defexp.encode(encoder);
    encoder.closeElement(SLA_ELEM_OPERAND_SYM);
  }

  override encodeHeader(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_OPERAND_SYM_HEAD);
    super.encodeHeader(encoder);
    encoder.closeElement(SLA_ELEM_OPERAND_SYM_HEAD);
  }

  override decode(decoder: Decoder, trans: SleighBase): void {
    this.defexp = null;
    this.triple = null;
    this.flags = 0;
    let attrib = decoder.getNextAttributeId();
    while (attrib !== 0) {
      attrib = decoder.getNextAttributeId();
      if (attrib === SLA_ATTRIB_INDEX.id)
        this.hand = decoder.readSignedInteger();
      else if (attrib === SLA_ATTRIB_OFF.id)
        this.reloffset = decoder.readSignedInteger();
      else if (attrib === SLA_ATTRIB_BASE.id)
        this.offsetbase = decoder.readSignedInteger();
      else if (attrib === SLA_ATTRIB_MINLEN.id)
        this.minimumlength = decoder.readSignedInteger();
      else if (attrib === SLA_ATTRIB_SUBSYM.id) {
        const id = Number(decoder.readUnsignedInteger());
        this.triple = trans.findSymbolById(id) as TripleSymbol;
      } else if (attrib === SLA_ATTRIB_CODE.id) {
        if (decoder.readBool())
          this.flags |= OperandSymbol.code_address;
      }
    }
    this.localexp = PatternExpression.decodeExpression(decoder, trans) as OperandValue;
    this.localexp.layClaim();
    if (decoder.peekElement() !== 0) {
      this.defexp = PatternExpression.decodeExpression(decoder, trans)!;
      this.defexp.layClaim();
    }
    decoder.closeElement(SLA_ELEM_OPERAND_SYM.id);
  }
}

// =========================================================================
// StartSymbol
// =========================================================================

export class StartSymbol extends SpecificSymbol {
  private const_space: AddrSpace | null = null;
  private patexp: PatternExpression | null = null;

  constructor();
  constructor(nm: string, cspc: AddrSpace);
  constructor(nm?: string, cspc?: AddrSpace) {
    super(nm);
    if (cspc !== undefined) {
      this.const_space = cspc;
      this.patexp = new StartInstructionValue();
      this.patexp.layClaim();
    }
  }

  override getVarnode(): VarnodeTpl {
    const spc = new ConstTpl(this.const_space!);
    const off = new ConstTpl(ConstTpl.j_start);
    const sz_zero = new ConstTpl();
    return new VarnodeTpl(spc, off, sz_zero);
  }

  override getPatternExpression(): PatternExpression { return this.patexp!; }

  override getFixedHandle(hand: FixedHandle, walker: ParserWalker): void {
    hand.space = walker.getCurSpace();
    hand.offset_space = null;
    hand.offset_offset = walker.getAddr().getOffset();
    hand.size = hand.space!.getAddrSize();
  }

  override print(s: Writer, walker: ParserWalker): void {
    const val = walker.getAddr().getOffset();
    s.write('0x' + val.toString(16));
  }

  override getType(): SymbolType { return SymbolType.start_symbol; }

  override encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_START_SYM);
    encoder.writeUnsignedInteger(SLA_ATTRIB_ID, BigInt(this.getId()));
    encoder.closeElement(SLA_ELEM_START_SYM);
  }

  override encodeHeader(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_START_SYM_HEAD);
    super.encodeHeader(encoder);
    encoder.closeElement(SLA_ELEM_START_SYM_HEAD);
  }

  override decode(decoder: Decoder, trans: SleighBase): void {
    this.const_space = trans.getConstantSpace();
    this.patexp = new StartInstructionValue();
    this.patexp.layClaim();
    decoder.closeElement(SLA_ELEM_START_SYM.id);
  }
}

// =========================================================================
// EndSymbol
// =========================================================================

export class EndSymbol extends SpecificSymbol {
  private const_space: AddrSpace | null = null;
  private patexp: PatternExpression | null = null;

  constructor();
  constructor(nm: string, cspc: AddrSpace);
  constructor(nm?: string, cspc?: AddrSpace) {
    super(nm);
    if (cspc !== undefined) {
      this.const_space = cspc;
      this.patexp = new EndInstructionValue();
      this.patexp.layClaim();
    }
  }

  override getVarnode(): VarnodeTpl {
    const spc = new ConstTpl(this.const_space!);
    const off = new ConstTpl(ConstTpl.j_next);
    const sz_zero = new ConstTpl();
    return new VarnodeTpl(spc, off, sz_zero);
  }

  override getPatternExpression(): PatternExpression { return this.patexp!; }

  override getFixedHandle(hand: FixedHandle, walker: ParserWalker): void {
    hand.space = walker.getCurSpace();
    hand.offset_space = null;
    hand.offset_offset = walker.getNaddr().getOffset();
    hand.size = hand.space!.getAddrSize();
  }

  override print(s: Writer, walker: ParserWalker): void {
    const val = walker.getNaddr().getOffset();
    s.write('0x' + val.toString(16));
  }

  override getType(): SymbolType { return SymbolType.end_symbol; }

  override encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_END_SYM);
    encoder.writeUnsignedInteger(SLA_ATTRIB_ID, BigInt(this.getId()));
    encoder.closeElement(SLA_ELEM_END_SYM);
  }

  override encodeHeader(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_END_SYM_HEAD);
    super.encodeHeader(encoder);
    encoder.closeElement(SLA_ELEM_END_SYM_HEAD);
  }

  override decode(decoder: Decoder, trans: SleighBase): void {
    this.const_space = trans.getConstantSpace();
    this.patexp = new EndInstructionValue();
    this.patexp.layClaim();
    decoder.closeElement(SLA_ELEM_END_SYM.id);
  }
}

// =========================================================================
// Next2Symbol
// =========================================================================

export class Next2Symbol extends SpecificSymbol {
  private const_space: AddrSpace | null = null;
  private patexp: PatternExpression | null = null;

  constructor();
  constructor(nm: string, cspc: AddrSpace);
  constructor(nm?: string, cspc?: AddrSpace) {
    super(nm);
    if (cspc !== undefined) {
      this.const_space = cspc;
      this.patexp = new Next2InstructionValue();
      this.patexp.layClaim();
    }
  }

  override getVarnode(): VarnodeTpl {
    const spc = new ConstTpl(this.const_space!);
    const off = new ConstTpl(ConstTpl.j_next2);
    const sz_zero = new ConstTpl();
    return new VarnodeTpl(spc, off, sz_zero);
  }

  override getPatternExpression(): PatternExpression { return this.patexp!; }

  override getFixedHandle(hand: FixedHandle, walker: ParserWalker): void {
    hand.space = walker.getCurSpace();
    hand.offset_space = null;
    hand.offset_offset = walker.getN2addr().getOffset();
    hand.size = hand.space!.getAddrSize();
  }

  override print(s: Writer, walker: ParserWalker): void {
    const val = walker.getN2addr().getOffset();
    s.write('0x' + val.toString(16));
  }

  override getType(): SymbolType { return SymbolType.next2_symbol; }

  override encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_NEXT2_SYM);
    encoder.writeUnsignedInteger(SLA_ATTRIB_ID, BigInt(this.getId()));
    encoder.closeElement(SLA_ELEM_NEXT2_SYM);
  }

  override encodeHeader(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_NEXT2_SYM_HEAD);
    super.encodeHeader(encoder);
    encoder.closeElement(SLA_ELEM_NEXT2_SYM_HEAD);
  }

  override decode(decoder: Decoder, trans: SleighBase): void {
    this.const_space = trans.getConstantSpace();
    this.patexp = new Next2InstructionValue();
    this.patexp.layClaim();
    decoder.closeElement(SLA_ELEM_NEXT2_SYM.id);
  }
}

// =========================================================================
// FlowDestSymbol
// =========================================================================

export class FlowDestSymbol extends SpecificSymbol {
  private const_space: AddrSpace | null = null;

  constructor();
  constructor(nm: string, cspc: AddrSpace);
  constructor(nm?: string, cspc?: AddrSpace) {
    super(nm);
    if (cspc !== undefined)
      this.const_space = cspc;
  }

  override getVarnode(): VarnodeTpl {
    const spc = new ConstTpl(this.const_space!);
    const off = new ConstTpl(ConstTpl.j_flowdest);
    const sz_zero = new ConstTpl();
    return new VarnodeTpl(spc, off, sz_zero);
  }

  override getPatternExpression(): PatternExpression {
    throw new SleighError('Cannot use symbol in pattern');
  }

  override getFixedHandle(hand: FixedHandle, walker: ParserWalker): void {
    const refAddr = walker.getDestAddr();
    hand.space = this.const_space;
    hand.offset_space = null;
    hand.offset_offset = refAddr.getOffset();
    hand.size = refAddr.getAddrSize();
  }

  override print(s: Writer, walker: ParserWalker): void {
    const val = walker.getDestAddr().getOffset();
    s.write('0x' + val.toString(16));
  }

  override getType(): SymbolType { return SymbolType.flowdest_symbol; }
}

// =========================================================================
// FlowRefSymbol
// =========================================================================

export class FlowRefSymbol extends SpecificSymbol {
  private const_space: AddrSpace | null = null;

  constructor();
  constructor(nm: string, cspc: AddrSpace);
  constructor(nm?: string, cspc?: AddrSpace) {
    super(nm);
    if (cspc !== undefined)
      this.const_space = cspc;
  }

  override getVarnode(): VarnodeTpl {
    const spc = new ConstTpl(this.const_space!);
    const off = new ConstTpl(ConstTpl.j_flowref);
    const sz_zero = new ConstTpl();
    return new VarnodeTpl(spc, off, sz_zero);
  }

  override getPatternExpression(): PatternExpression {
    throw new SleighError('Cannot use symbol in pattern');
  }

  override getFixedHandle(hand: FixedHandle, walker: ParserWalker): void {
    const refAddr = walker.getRefAddr();
    hand.space = this.const_space;
    hand.offset_space = null;
    hand.offset_offset = refAddr.getOffset();
    hand.size = refAddr.getAddrSize();
  }

  override print(s: Writer, walker: ParserWalker): void {
    const val = walker.getRefAddr().getOffset();
    s.write('0x' + val.toString(16));
  }

  override getType(): SymbolType { return SymbolType.flowref_symbol; }
}

// =========================================================================
// ContextChange (abstract)
// =========================================================================

export abstract class ContextChange {
  abstract validate(): void;
  abstract encode(encoder: Encoder): void;
  abstract decode(decoder: Decoder, trans: SleighBase): void;
  abstract apply(walker: ParserWalkerChange): void;
  abstract clone(): ContextChange;
}

// =========================================================================
// ContextOp
// =========================================================================

export class ContextOp extends ContextChange {
  private patexp: PatternExpression | null = null;
  private num: number = 0;
  private mask: number = 0;
  private shift: number = 0;

  constructor();
  constructor(startbit: number, endbit: number, pe: PatternExpression);
  constructor(startbit?: number, endbit?: number, pe?: PatternExpression) {
    super();
    if (startbit !== undefined && endbit !== undefined && pe !== undefined) {
      const r = calc_maskword(startbit, endbit);
      this.num = r.num;
      this.shift = r.shift;
      this.mask = r.mask;
      this.patexp = pe;
      this.patexp.layClaim();
    }
  }

  validate(): void {
    const values: PatternValue[] = [];
    this.patexp!.listValues(values);
    for (let i = 0; i < values.length; ++i) {
      if (values[i] instanceof OperandValue) {
        const val = values[i] as OperandValue;
        if (!val.isConstructorRelative())
          throw new SleighError(val.getName() + ': cannot be used in context expression');
      }
    }
  }

  encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_CONTEXT_OP);
    encoder.writeSignedInteger(SLA_ATTRIB_I, this.num);
    encoder.writeSignedInteger(SLA_ATTRIB_SHIFT, this.shift);
    encoder.writeUnsignedInteger(SLA_ATTRIB_MASK, BigInt(this.mask >>> 0));
    this.patexp!.encode(encoder);
    encoder.closeElement(SLA_ELEM_CONTEXT_OP);
  }

  decode(decoder: Decoder, trans: SleighBase): void {
    const el = decoder.openElementId(SLA_ELEM_CONTEXT_OP);
    this.num = decoder.readSignedIntegerById(SLA_ATTRIB_I);
    this.shift = decoder.readSignedIntegerById(SLA_ATTRIB_SHIFT);
    this.mask = Number(decoder.readUnsignedIntegerById(SLA_ATTRIB_MASK)) | 0;
    this.patexp = PatternExpression.decodeExpression(decoder, trans)!;
    this.patexp.layClaim();
    decoder.closeElement(el);
  }

  apply(walker: ParserWalkerChange): void {
    let val = Number(this.patexp!.getValue(walker)) & 0xFFFFFFFF;
    val = (val << this.shift) | 0;
    walker.getParserContext().setContextWord(this.num, val, this.mask);
  }

  clone(): ContextChange {
    const res = new ContextOp();
    res.patexp = this.patexp;
    res.patexp!.layClaim();
    res.mask = this.mask;
    res.num = this.num;
    res.shift = this.shift;
    return res;
  }
}

// =========================================================================
// ContextCommit
// =========================================================================

export class ContextCommit extends ContextChange {
  private sym: TripleSymbol | null = null;
  private num: number = 0;
  private mask: number = 0;
  private _flow: boolean = false;

  constructor();
  constructor(s: TripleSymbol, sbit: number, ebit: number, fl: boolean);
  constructor(s?: TripleSymbol, sbit?: number, ebit?: number, fl?: boolean) {
    super();
    if (s !== undefined) {
      this.sym = s;
      this._flow = fl!;
      const r = calc_maskword(sbit!, ebit!);
      this.num = r.num;
      this.mask = r.mask;
    }
  }

  validate(): void {}

  encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_COMMIT);
    encoder.writeUnsignedInteger(SLA_ATTRIB_ID, BigInt(this.sym!.getId()));
    encoder.writeSignedInteger(SLA_ATTRIB_NUMBER, this.num);
    encoder.writeUnsignedInteger(SLA_ATTRIB_MASK, BigInt(this.mask >>> 0));
    encoder.writeBool(SLA_ATTRIB_FLOW, this._flow);
    encoder.closeElement(SLA_ELEM_COMMIT);
  }

  decode(decoder: Decoder, trans: SleighBase): void {
    const el = decoder.openElementId(SLA_ELEM_COMMIT);
    const id = Number(decoder.readUnsignedIntegerById(SLA_ATTRIB_ID));
    this.sym = trans.findSymbolById(id) as TripleSymbol;
    this.num = decoder.readSignedIntegerById(SLA_ATTRIB_NUMBER);
    this.mask = Number(decoder.readUnsignedIntegerById(SLA_ATTRIB_MASK)) | 0;
    this._flow = decoder.readBoolById(SLA_ATTRIB_FLOW);
    decoder.closeElement(el);
  }

  apply(walker: ParserWalkerChange): void {
    walker.getParserContext().addCommit(this.sym!, this.num, this.mask, this._flow, walker.getPoint()!);
  }

  clone(): ContextChange {
    const res = new ContextCommit();
    res.sym = this.sym;
    res._flow = this._flow;
    res.mask = this.mask;
    res.num = this.num;
    return res;
  }
}

// =========================================================================
// Constructor (NOT a symbol)
// =========================================================================

export class Constructor {
  private pattern: TokenPattern | null = null;
  private parent: SubtableSymbol | null = null;
  private pateq: PatternEquation | null = null;
  private operands: OperandSymbol[] = [];
  private printpiece: string[] = [];
  private context: ContextChange[] = [];
  private templ: ConstructTpl | null = null;
  private namedtempl: (ConstructTpl | null)[] = [];
  private minimumlength: number = 0;
  private _id: number = 0;
  private firstwhitespace: number = -1;
  private flowthruindex: number = -1;
  private lineno: number = 0;
  private src_index: number = 0;
  private inerror: boolean = false;

  constructor();
  constructor(p: SubtableSymbol);
  constructor(p?: SubtableSymbol) {
    this.pattern = null;
    this.pateq = null;
    this.templ = null;
    this.firstwhitespace = -1;
    this.flowthruindex = -1;
    this.inerror = false;
    if (p !== undefined)
      this.parent = p;
    else
      this.parent = null;
  }

  getPattern(): TokenPattern | null { return this.pattern; }
  setMinimumLength(l: number): void { this.minimumlength = l; }
  getMinimumLength(): number { return this.minimumlength; }
  setId(i: number): void { this._id = i; }
  getId(): number { return this._id; }
  setLineno(ln: number): void { this.lineno = ln; }
  getLineno(): number { return this.lineno; }
  setSrcIndex(index: number): void { this.src_index = index; }
  getSrcIndex(): number { return this.src_index; }
  addContext(vec: ContextChange[]): void { this.context = vec; }
  getParent(): SubtableSymbol { return this.parent!; }
  getNumOperands(): number { return this.operands.length; }
  getOperand(i: number): OperandSymbol { return this.operands[i]; }
  getPatternEquation(): PatternEquation | null { return this.pateq; }
  getTempl(): ConstructTpl | null { return this.templ; }
  setMainSection(tpl: ConstructTpl): void { this.templ = tpl; }
  getNumSections(): number { return this.namedtempl.length; }

  getNamedTempl(secnum: number): ConstructTpl | null {
    if (secnum < this.namedtempl.length)
      return this.namedtempl[secnum];
    return null;
  }

  setNamedSection(tpl: ConstructTpl, id: number): void {
    while (this.namedtempl.length <= id)
      this.namedtempl.push(null);
    this.namedtempl[id] = tpl;
  }

  addInvisibleOperand(sym: OperandSymbol): void {
    this.operands.push(sym);
  }

  addOperand(sym: OperandSymbol): void {
    let operstring = '\n' + String.fromCharCode('A'.charCodeAt(0) + this.operands.length);
    this.operands.push(sym);
    this.printpiece.push(operstring);
  }

  addSyntax(syn: string): void {
    if (syn.length === 0) return;
    let hasNonSpace = false;
    for (let i = 0; i < syn.length; ++i) {
      if (syn[i] !== ' ') { hasNonSpace = true; break; }
    }
    const syntrim = hasNonSpace ? syn : ' ';
    if (this.firstwhitespace === -1 && syntrim === ' ')
      this.firstwhitespace = this.printpiece.length;
    if (this.printpiece.length === 0) {
      this.printpiece.push(syntrim);
    } else if (this.printpiece[this.printpiece.length - 1] === ' ' && syntrim === ' ') {
      // Don't add more whitespace
    } else if (this.printpiece[this.printpiece.length - 1][0] === '\n' ||
               this.printpiece[this.printpiece.length - 1] === ' ' || syntrim === ' ') {
      this.printpiece.push(syntrim);
    } else {
      this.printpiece[this.printpiece.length - 1] += syntrim;
    }
  }

  addEquation(pe: PatternEquation): void {
    this.pateq = pe;
    pe.layClaim();
  }

  removeTrailingSpace(): void {
    if (this.printpiece.length > 0 && this.printpiece[this.printpiece.length - 1] === ' ')
      this.printpiece.pop();
  }

  print(s: Writer, walker: ParserWalker): void {
    for (let i = 0; i < this.printpiece.length; ++i) {
      if (this.printpiece[i][0] === '\n') {
        const index = this.printpiece[i].charCodeAt(1) - 'A'.charCodeAt(0);
        this.operands[index].print(s, walker);
      } else {
        s.write(this.printpiece[i]);
      }
    }
  }

  printMnemonic(s: Writer, walker: ParserWalker): void {
    if (this.flowthruindex !== -1) {
      const sym = this.operands[this.flowthruindex].getDefiningSymbol();
      if (sym !== null && sym instanceof SubtableSymbol) {
        walker.pushOperand(this.flowthruindex);
        walker.getConstructor().printMnemonic(s, walker);
        walker.popOperand();
        return;
      }
    }
    const endind = (this.firstwhitespace === -1) ? this.printpiece.length : this.firstwhitespace;
    for (let i = 0; i < endind; ++i) {
      if (this.printpiece[i][0] === '\n') {
        const index = this.printpiece[i].charCodeAt(1) - 'A'.charCodeAt(0);
        this.operands[index].print(s, walker);
      } else {
        s.write(this.printpiece[i]);
      }
    }
  }

  printBody(s: Writer, walker: ParserWalker): void {
    if (this.flowthruindex !== -1) {
      const sym = this.operands[this.flowthruindex].getDefiningSymbol();
      if (sym !== null && sym instanceof SubtableSymbol) {
        walker.pushOperand(this.flowthruindex);
        walker.getConstructor().printBody(s, walker);
        walker.popOperand();
        return;
      }
    }
    if (this.firstwhitespace === -1) return;
    for (let i = this.firstwhitespace + 1; i < this.printpiece.length; ++i) {
      if (this.printpiece[i][0] === '\n') {
        const index = this.printpiece[i].charCodeAt(1) - 'A'.charCodeAt(0);
        this.operands[index].print(s, walker);
      } else {
        s.write(this.printpiece[i]);
      }
    }
  }

  applyContext(walker: ParserWalkerChange): void {
    for (let i = 0; i < this.context.length; ++i)
      this.context[i].apply(walker);
  }

  markSubtableOperands(check: number[]): void {
    check.length = this.operands.length;
    for (let i = 0; i < this.operands.length; ++i) {
      const sym = this.operands[i].getDefiningSymbol();
      if (sym !== null && sym.getType() === SymbolType.subtable_symbol)
        check[i] = 0;
      else
        check[i] = 2;
    }
  }

  collectLocalExports(results: bigint[]): void {
    if (this.templ === null) return;
    const handle = this.templ.getResult();
    if (handle === null) return;
    if (handle.getSpace().isConstSpace()) return;
    if (handle.getPtrSpace().getType() !== ConstTpl.real) {
      if (handle.getTempSpace().isUniqueSpace())
        results.push(handle.getTempOffset().getReal());
      return;
    }
    if (handle.getSpace().isUniqueSpace()) {
      results.push(handle.getPtrOffset().getReal());
      return;
    }
    if (handle.getSpace().getType() === ConstTpl.handle) {
      const handleIndex = handle.getSpace().getHandleIndex();
      const opSym = this.getOperand(handleIndex);
      opSym.collectLocalValues(results);
    }
  }

  setError(val: boolean): void { this.inerror = val; }
  isError(): boolean { return this.inerror; }

  isRecursive(): boolean {
    for (let i = 0; i < this.operands.length; ++i) {
      const sym = this.operands[i].getDefiningSymbol();
      if (sym === this.parent) return true;
    }
    return false;
  }

  printInfo(s: Writer): void {
    s.write('table "' + this.parent!.getName());
    s.write('" constructor starting at line ' + this.lineno);
  }

  orderOperands(): void {
    const patternorder: OperandSymbol[] = [];
    const newops: OperandSymbol[] = [];

    this.pateq!.operandOrder(this, patternorder);
    for (let i = 0; i < this.operands.length; ++i) {
      const sym = this.operands[i];
      if (!sym.isMarked()) {
        patternorder.push(sym);
        sym.setMark();
      }
    }
    let lastsize: number;
    do {
      lastsize = newops.length;
      for (let i = 0; i < patternorder.length; ++i) {
        const sym = patternorder[i];
        if (!sym.isMarked()) continue;
        if (sym.isOffsetIrrelevant()) continue;
        if (sym.offsetbase === -1 || !this.operands[sym.offsetbase].isMarked()) {
          newops.push(sym);
          sym.clearMark();
        }
      }
    } while (newops.length !== lastsize);
    for (let i = 0; i < patternorder.length; ++i) {
      const sym = patternorder[i];
      if (sym.isOffsetIrrelevant()) {
        newops.push(sym);
        sym.clearMark();
      }
    }
    if (newops.length !== this.operands.length)
      throw new SleighError('Circular offset dependency between operands');

    for (let i = 0; i < newops.length; ++i) {
      newops[i].hand = i;
      newops[i].localexp!.changeIndex(i);
    }
    const handmap: number[] = [];
    for (let i = 0; i < this.operands.length; ++i)
      handmap.push(this.operands[i].hand);

    for (let i = 0; i < newops.length; ++i) {
      const sym = newops[i];
      if (sym.offsetbase === -1) continue;
      sym.offsetbase = handmap[sym.offsetbase];
    }

    if (this.templ !== null)
      this.templ.changeHandleIndex(handmap);
    for (let i = 0; i < this.namedtempl.length; ++i) {
      const ntempl = this.namedtempl[i];
      if (ntempl !== null)
        ntempl.changeHandleIndex(handmap);
    }

    for (let i = 0; i < this.printpiece.length; ++i) {
      if (this.printpiece[i][0] === '\n') {
        let index = this.printpiece[i].charCodeAt(1) - 'A'.charCodeAt(0);
        index = handmap[index];
        this.printpiece[i] = '\n' + String.fromCharCode('A'.charCodeAt(0) + index);
      }
    }
    this.operands = newops;
  }

  buildPattern(s: Writer): TokenPattern {
    if (this.pattern !== null) return this.pattern;

    this.pattern = new TokenPattern();
    const oppattern: TokenPattern[] = [];
    let recursion = false;

    for (let i = 0; i < this.operands.length; ++i) {
      const sym = this.operands[i];
      const triple = sym.getDefiningSymbol();
      const defexp = sym.getDefiningExpression();
      if (triple !== null) {
        if (triple instanceof SubtableSymbol) {
          const subsym = triple as SubtableSymbol;
          if (subsym.isBeingBuilt()) {
            if (recursion) throw new SleighError('Illegal recursion');
            recursion = true;
            oppattern.push(new TokenPattern());
          } else {
            oppattern.push(subsym.buildPattern(s));
          }
        } else {
          oppattern.push(triple.getPatternExpression().genMinPattern(oppattern));
        }
      } else if (defexp !== null) {
        oppattern.push(defexp.genMinPattern(oppattern));
      } else {
        throw new SleighError(sym.getName() + ': operand is undefined');
      }
      const sympat = oppattern[oppattern.length - 1];
      sym.minimumlength = sympat.getMinimumLength();
      if (sympat.getLeftEllipsis() || sympat.getRightEllipsis())
        (sym as any).setVariableLength();
    }

    if (this.pateq === null)
      throw new SleighError('Missing equation');

    this.pateq.genPattern(oppattern);
    this.pattern = this.pateq.getTokenPattern();
    if (this.pattern.alwaysFalse())
      throw new SleighError('Impossible pattern');
    if (recursion)
      this.pattern.setRightEllipsis(true);
    this.minimumlength = this.pattern.getMinimumLength();

    const resolve = new OperandResolve(this.operands);
    if (!this.pateq.resolveOperandLeft(resolve))
      throw new SleighError('Unable to resolve operand offsets');

    for (let i = 0; i < this.operands.length; ++i) {
      const sym = this.operands[i];
      if (sym.isOffsetIrrelevant()) {
        sym.offsetbase = -1;
        sym.reloffset = 0;
        continue;
      }
      let base = sym.offsetbase;
      let offset = sym.reloffset;
      while (base >= 0) {
        const bsym = this.operands[base];
        if (bsym.isVariableLength()) break;
        base = bsym.offsetbase;
        offset += bsym.getMinimumLength();
        offset += bsym.reloffset;
        if (base < 0) {
          this.operands[i].offsetbase = base;
          this.operands[i].reloffset = offset;
        }
      }
    }

    for (let i = 0; i < this.context.length; ++i)
      this.context[i].validate();

    this.orderOperands();
    return this.pattern;
  }

  encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_CONSTRUCTOR);
    encoder.writeUnsignedInteger(SLA_ATTRIB_PARENT, BigInt(this.parent!.getId()));
    encoder.writeSignedInteger(SLA_ATTRIB_FIRST, this.firstwhitespace);
    encoder.writeSignedInteger(SLA_ATTRIB_LENGTH, this.minimumlength);
    encoder.writeSignedInteger(SLA_ATTRIB_SOURCE, this.src_index);
    encoder.writeSignedInteger(SLA_ATTRIB_LINE, this.lineno);
    for (let i = 0; i < this.operands.length; ++i) {
      encoder.openElement(SLA_ELEM_OPER);
      encoder.writeUnsignedInteger(SLA_ATTRIB_ID, BigInt(this.operands[i].getId()));
      encoder.closeElement(SLA_ELEM_OPER);
    }
    for (let i = 0; i < this.printpiece.length; ++i) {
      if (this.printpiece[i][0] === '\n') {
        const index = this.printpiece[i].charCodeAt(1) - 'A'.charCodeAt(0);
        encoder.openElement(SLA_ELEM_OPPRINT);
        encoder.writeSignedInteger(SLA_ATTRIB_ID, index);
        encoder.closeElement(SLA_ELEM_OPPRINT);
      } else {
        encoder.openElement(SLA_ELEM_PRINT);
        encoder.writeString(SLA_ATTRIB_PIECE, this.printpiece[i]);
        encoder.closeElement(SLA_ELEM_PRINT);
      }
    }
    for (let i = 0; i < this.context.length; ++i)
      this.context[i].encode(encoder);
    if (this.templ !== null)
      this.templ.encode(encoder, -1);
    for (let i = 0; i < this.namedtempl.length; ++i) {
      if (this.namedtempl[i] === null) continue;
      this.namedtempl[i]!.encode(encoder, i);
    }
    encoder.closeElement(SLA_ELEM_CONSTRUCTOR);
  }

  decode(decoder: Decoder, trans: SleighBase): void {
    const el = decoder.openElementId(SLA_ELEM_CONSTRUCTOR);
    const pid = Number(decoder.readUnsignedIntegerById(SLA_ATTRIB_PARENT));
    this.parent = trans.findSymbolById(pid) as SubtableSymbol;
    this.firstwhitespace = decoder.readSignedIntegerById(SLA_ATTRIB_FIRST);
    this.minimumlength = decoder.readSignedIntegerById(SLA_ATTRIB_LENGTH);
    this.src_index = decoder.readSignedIntegerById(SLA_ATTRIB_SOURCE);
    this.lineno = decoder.readSignedIntegerById(SLA_ATTRIB_LINE);
    let subel = decoder.peekElement();
    while (subel !== 0) {
      if (subel === SLA_ELEM_OPER.id) {
        decoder.openElement();
        const oid = Number(decoder.readUnsignedIntegerById(SLA_ATTRIB_ID));
        const sym = trans.findSymbolById(oid) as OperandSymbol;
        this.operands.push(sym);
        decoder.closeElement(subel);
      } else if (subel === SLA_ELEM_PRINT.id) {
        decoder.openElement();
        this.printpiece.push(decoder.readStringById(SLA_ATTRIB_PIECE));
        decoder.closeElement(subel);
      } else if (subel === SLA_ELEM_OPPRINT.id) {
        decoder.openElement();
        const index = decoder.readSignedIntegerById(SLA_ATTRIB_ID);
        const operstring = '\n' + String.fromCharCode('A'.charCodeAt(0) + index);
        this.printpiece.push(operstring);
        decoder.closeElement(subel);
      } else if (subel === SLA_ELEM_CONTEXT_OP.id) {
        const c_op = new ContextOp();
        c_op.decode(decoder, trans);
        this.context.push(c_op);
      } else if (subel === SLA_ELEM_COMMIT.id) {
        const c_op = new ContextCommit();
        c_op.decode(decoder, trans);
        this.context.push(c_op);
      } else {
        const cur = new ConstructTpl();
        const sectionid = cur.decode(decoder);
        if (sectionid < 0) {
          if (this.templ !== null)
            throw new LowlevelError('Duplicate main section');
          this.templ = cur;
        } else {
          while (this.namedtempl.length <= sectionid)
            this.namedtempl.push(null);
          if (this.namedtempl[sectionid] !== null)
            throw new LowlevelError('Duplicate named section');
          this.namedtempl[sectionid] = cur;
        }
      }
      subel = decoder.peekElement();
    }
    this.pattern = null;
    if (this.printpiece.length === 1 && this.printpiece[0][0] === '\n')
      this.flowthruindex = this.printpiece[0].charCodeAt(1) - 'A'.charCodeAt(0);
    else
      this.flowthruindex = -1;
    decoder.closeElement(el);
  }
}

// =========================================================================
// DecisionProperties
// =========================================================================

export class DecisionProperties {
  private identerrors: [Constructor, Constructor][] = [];
  private conflicterrors: [Constructor, Constructor][] = [];

  identicalPattern(a: Constructor, b: Constructor): void {
    if (!a.isError() && !b.isError()) {
      a.setError(true);
      b.setError(true);
      this.identerrors.push([a, b]);
    }
  }

  conflictingPattern(a: Constructor, b: Constructor): void {
    if (!a.isError() && !b.isError()) {
      a.setError(true);
      b.setError(true);
      this.conflicterrors.push([a, b]);
    }
  }

  getIdentErrors(): [Constructor, Constructor][] { return this.identerrors; }
  getConflictErrors(): [Constructor, Constructor][] { return this.conflicterrors; }
}

// =========================================================================
// DecisionNode
// =========================================================================

export class DecisionNode {
  private list: [DisjointPattern, Constructor][] = [];
  private children: DecisionNode[] = [];
  public num: number = 0;
  private contextdecision: boolean = false;
  private startbit: number = 0;
  private bitsize: number = 0;
  private parent: DecisionNode | null = null;

  constructor();
  constructor(p: DecisionNode | null);
  constructor(p?: DecisionNode | null) {
    if (p !== undefined) {
      this.parent = p;
      this.num = 0;
      this.startbit = 0;
      this.bitsize = 0;
      this.contextdecision = false;
    }
  }

  resolve(walker: ParserWalker): Constructor {
    if (this.bitsize === 0) {
      for (let i = 0; i < this.list.length; ++i) {
        if (this.list[i][0].isMatch(walker))
          return this.list[i][1];
      }
      const addr = walker.getAddr();
      throw new BadDataError(addr.getShortcut() + addr.printRaw() + ': Unable to resolve constructor');
    }
    let val: number;
    if (this.contextdecision)
      val = walker.getContextBits(this.startbit, this.bitsize);
    else
      val = walker.getInstructionBits(this.startbit, this.bitsize);
    return this.children[val].resolve(walker);
  }

  addConstructorPair(pat: DisjointPattern, ct: Constructor): void {
    const clone = pat.simplifyClone() as DisjointPattern;
    this.list.push([clone, ct]);
    this.num += 1;
  }

  private getMaximumLength(context: boolean): number {
    let max = 0;
    for (let i = 0; i < this.list.length; ++i) {
      const val = this.list[i][0].getLength(context);
      if (val > max) max = val;
    }
    return max;
  }

  private getNumFixed(low: number, size: number, context: boolean): number {
    let count = 0;
    let m = (size === 8 * SIZEOF_UINTM) ? 0 : (1 << size);
    m = (m - 1) >>> 0;
    for (let i = 0; i < this.list.length; ++i) {
      const mask = this.list[i][0].getMaskBits(low, size, context);
      if (((mask & m) >>> 0) === m) count += 1;
    }
    return count;
  }

  private getScore(low: number, size: number, context: boolean): number {
    const numBins = 1 << size;
    let m = ((1 << size) - 1) >>> 0;
    let total = 0;
    const count = new Array(numBins).fill(0);
    for (let i = 0; i < this.list.length; ++i) {
      const mask = this.list[i][0].getMaskBits(low, size, context);
      if (((mask & m) >>> 0) !== m) continue;
      const val = this.list[i][0].getValueBits(low, size, context);
      total += 1;
      count[val] += 1;
    }
    if (total <= 0) return -1.0;
    let sc = 0.0;
    for (let i = 0; i < numBins; ++i) {
      if (count[i] <= 0) continue;
      if (count[i] >= this.list.length) return -1.0;
      const p = count[i] / total;
      sc -= p * Math.log(p);
    }
    return sc / Math.log(2.0);
  }

  private chooseOptimalField(): void {
    let score = 0.0;
    let maxfixed = 1;
    let context = true;
    do {
      const maxlength = 8 * this.getMaximumLength(context);
      for (let sbit = 0; sbit < maxlength; ++sbit) {
        const numfixed = this.getNumFixed(sbit, 1, context);
        if (numfixed < maxfixed) continue;
        const sc = this.getScore(sbit, 1, context);
        if (numfixed > maxfixed && sc > 0.0) {
          score = sc;
          maxfixed = numfixed;
          this.startbit = sbit;
          this.bitsize = 1;
          this.contextdecision = context;
          continue;
        }
        if (sc > score) {
          score = sc;
          this.startbit = sbit;
          this.bitsize = 1;
          this.contextdecision = context;
        }
      }
      context = !context;
    } while (!context);

    context = true;
    do {
      const maxlength = 8 * this.getMaximumLength(context);
      for (let size = 2; size <= 8; ++size) {
        for (let sbit = 0; sbit < maxlength - size + 1; ++sbit) {
          if (this.getNumFixed(sbit, size, context) < maxfixed) continue;
          const sc = this.getScore(sbit, size, context);
          if (sc > score) {
            score = sc;
            this.startbit = sbit;
            this.bitsize = size;
            this.contextdecision = context;
          }
        }
      }
      context = !context;
    } while (!context);
    if (score <= 0.0)
      this.bitsize = 0;
  }

  private consistentValues(bins: number[], pat: DisjointPattern): void {
    let m = (this.bitsize === 8 * SIZEOF_UINTM) ? 0 : (1 << this.bitsize);
    m = (m - 1) >>> 0;
    const commonMask = (m & pat.getMaskBits(this.startbit, this.bitsize, this.contextdecision)) >>> 0;
    const commonValue = (commonMask & pat.getValueBits(this.startbit, this.bitsize, this.contextdecision)) >>> 0;
    const dontCareMask = (m ^ commonMask) >>> 0;
    for (let i = 0; i <= dontCareMask; ++i) {
      if (((i & dontCareMask) >>> 0) !== i) continue;
      bins.push((commonValue | i) >>> 0);
    }
  }

  split(props: DecisionProperties): void {
    if (this.list.length <= 1) {
      this.bitsize = 0;
      return;
    }
    this.chooseOptimalField();
    if (this.bitsize === 0) {
      this.orderPatterns(props);
      return;
    }
    if (this.parent !== null && this.list.length >= this.parent.num)
      throw new LowlevelError('Child has as many Patterns as parent');

    const numChildren = 1 << this.bitsize;
    for (let i = 0; i < numChildren; ++i)
      this.children.push(new DecisionNode(this));
    for (let i = 0; i < this.list.length; ++i) {
      const vals: number[] = [];
      this.consistentValues(vals, this.list[i][0]);
      for (let j = 0; j < vals.length; ++j)
        this.children[vals[j]].addConstructorPair(this.list[i][0], this.list[i][1]);
    }
    this.list.length = 0;
    for (let i = 0; i < numChildren; ++i)
      this.children[i].split(props);
  }

  orderPatterns(props: DecisionProperties): void {
    const newlist = [...this.list];
    const conflictlist: [DisjointPattern, Constructor][] = [];

    for (let i = 0; i < this.list.length; ++i) {
      for (let j = 0; j < i; ++j) {
        if (this.list[i][0].identical(this.list[j][0]))
          props.identicalPattern(this.list[i][1], this.list[j][1]);
      }
    }

    for (let i = 0; i < this.list.length; ++i) {
      let j: number;
      for (j = 0; j < i; ++j) {
        const ipat = newlist[i][0];
        const jpat = this.list[j][0];
        if (ipat.specializes(jpat))
          break;
        if (!jpat.specializes(ipat)) {
          const iconst = newlist[i][1];
          const jconst = this.list[j][1];
          if (iconst !== jconst) {
            conflictlist.push([ipat, iconst]);
            conflictlist.push([jpat, jconst]);
          }
        }
      }
      for (let k = i - 1; k >= j; --k)
        this.list[k + 1] = this.list[k];
      this.list[j] = newlist[i];
    }

    for (let i = 0; i < conflictlist.length; i += 2) {
      const pat1 = conflictlist[i][0];
      const const1 = conflictlist[i][1];
      const pat2 = conflictlist[i + 1][0];
      const const2 = conflictlist[i + 1][1];
      let resolved = false;
      for (let j = 0; j < this.list.length; ++j) {
        const tpat = this.list[j][0];
        const tconst = this.list[j][1];
        if (tpat === pat1 && tconst === const1) break;
        if (tpat === pat2 && tconst === const2) break;
        if (tpat.resolvesIntersect(pat1, pat2)) {
          resolved = true;
          break;
        }
      }
      if (!resolved)
        props.conflictingPattern(const1, const2);
    }
  }

  encode(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_DECISION);
    encoder.writeSignedInteger(SLA_ATTRIB_NUMBER, this.num);
    encoder.writeBool(SLA_ATTRIB_CONTEXT, this.contextdecision);
    encoder.writeSignedInteger(SLA_ATTRIB_STARTBIT, this.startbit);
    encoder.writeSignedInteger(SLA_ATTRIB_SIZE, this.bitsize);
    for (let i = 0; i < this.list.length; ++i) {
      encoder.openElement(SLA_ELEM_PAIR);
      encoder.writeSignedInteger(SLA_ATTRIB_ID, this.list[i][1].getId());
      this.list[i][0].encode(encoder);
      encoder.closeElement(SLA_ELEM_PAIR);
    }
    for (let i = 0; i < this.children.length; ++i)
      this.children[i].encode(encoder);
    encoder.closeElement(SLA_ELEM_DECISION);
  }

  decode(decoder: Decoder, par: DecisionNode | null, sub: SubtableSymbol): void {
    const el = decoder.openElementId(SLA_ELEM_DECISION);
    this.parent = par;
    this.num = decoder.readSignedIntegerById(SLA_ATTRIB_NUMBER);
    this.contextdecision = decoder.readBoolById(SLA_ATTRIB_CONTEXT);
    this.startbit = decoder.readSignedIntegerById(SLA_ATTRIB_STARTBIT);
    this.bitsize = decoder.readSignedIntegerById(SLA_ATTRIB_SIZE);
    let subel = decoder.peekElement();
    while (subel !== 0) {
      if (subel === SLA_ELEM_PAIR.id) {
        decoder.openElement();
        const id = decoder.readSignedIntegerById(SLA_ATTRIB_ID);
        const ct = sub.getConstructor(id);
        const pat = DisjointPattern.decodeDisjoint(decoder);
        this.list.push([pat, ct]);
        decoder.closeElement(subel);
      } else if (subel === SLA_ELEM_DECISION.id) {
        const subnode = new DecisionNode();
        subnode.decode(decoder, this, sub);
        this.children.push(subnode);
      }
      subel = decoder.peekElement();
    }
    decoder.closeElement(el);
  }
}

// =========================================================================
// SubtableSymbol
// =========================================================================

export class SubtableSymbol extends TripleSymbol {
  private pattern: TokenPattern | null = null;
  private beingbuilt: boolean = false;
  private errors: boolean = false;
  private construct: Constructor[] = [];
  private decisiontree: DecisionNode | null = null;

  constructor();
  constructor(nm: string);
  constructor(nm?: string) {
    super(nm);
    if (nm !== undefined) {
      this.beingbuilt = false;
      this.pattern = null;
      this.decisiontree = null;
      this.errors = false;
    }
  }

  isBeingBuilt(): boolean { return this.beingbuilt; }
  isError(): boolean { return this.errors; }
  addConstructor(ct: Constructor): void { ct.setId(this.construct.length); this.construct.push(ct); }
  getPattern(): TokenPattern | null { return this.pattern; }
  getNumConstructors(): number { return this.construct.length; }
  getConstructor(id: number): Constructor { return this.construct[id]; }
  override getSize(): number { return -1; }

  override resolve(walker: ParserWalker): Constructor | null {
    return this.decisiontree!.resolve(walker);
  }

  override getPatternExpression(): PatternExpression {
    throw new SleighError('Cannot use subtable in expression');
  }

  override getFixedHandle(hand: FixedHandle, walker: ParserWalker): void {
    throw new SleighError('Cannot use subtable in expression');
  }

  override print(s: Writer, walker: ParserWalker): void {
    throw new SleighError('Cannot use subtable in expression');
  }

  override collectLocalValues(results: bigint[]): void {
    for (let i = 0; i < this.construct.length; ++i)
      this.construct[i].collectLocalExports(results);
  }

  override getType(): SymbolType { return SymbolType.subtable_symbol; }

  buildDecisionTree(props: DecisionProperties): void {
    if (this.pattern === null) return;
    this.decisiontree = new DecisionNode(null);
    for (let i = 0; i < this.construct.length; ++i) {
      const pat = this.construct[i].getPattern()!.getPattern();
      if (pat.numDisjoint() === 0)
        this.decisiontree.addConstructorPair(pat as DisjointPattern, this.construct[i]);
      else
        for (let j = 0; j < pat.numDisjoint(); ++j)
          this.decisiontree.addConstructorPair(pat.getDisjoint(j)!, this.construct[i]);
    }
    this.decisiontree.split(props);
  }

  buildPattern(s: Writer): TokenPattern {
    if (this.pattern !== null) return this.pattern;

    this.errors = false;
    this.beingbuilt = true;
    this.pattern = new TokenPattern();
    if (this.construct.length === 0) {
      s.write('Error: There are no constructors in table: ' + this.getName() + '\n');
      this.errors = true;
      return this.pattern;
    }
    try {
      this.construct[0].buildPattern(s);
    } catch (err: any) {
      s.write('Error: ' + (err.explain || err.message) + ': for ');
      this.construct[0].printInfo(s);
      s.write('\n');
      this.errors = true;
    }
    this.pattern = this.construct[0].getPattern()!;
    for (let i = 1; i < this.construct.length; ++i) {
      try {
        this.construct[i].buildPattern(s);
      } catch (err: any) {
        s.write('Error: ' + (err.explain || err.message) + ': for ');
        this.construct[i].printInfo(s);
        s.write('\n');
        this.errors = true;
      }
      this.pattern = this.construct[i].getPattern()!.commonSubPattern(this.pattern);
    }
    this.beingbuilt = false;
    return this.pattern;
  }

  override encode(encoder: Encoder): void {
    if (this.decisiontree === null) return;
    encoder.openElement(SLA_ELEM_SUBTABLE_SYM);
    encoder.writeUnsignedInteger(SLA_ATTRIB_ID, BigInt(this.getId()));
    encoder.writeSignedInteger(SLA_ATTRIB_NUMCT, this.construct.length);
    for (let i = 0; i < this.construct.length; ++i)
      this.construct[i].encode(encoder);
    this.decisiontree.encode(encoder);
    encoder.closeElement(SLA_ELEM_SUBTABLE_SYM);
  }

  override encodeHeader(encoder: Encoder): void {
    encoder.openElement(SLA_ELEM_SUBTABLE_SYM_HEAD);
    super.encodeHeader(encoder);
    encoder.closeElement(SLA_ELEM_SUBTABLE_SYM_HEAD);
  }

  override decode(decoder: Decoder, trans: SleighBase): void {
    const numct = decoder.readSignedIntegerById(SLA_ATTRIB_NUMCT);
    this.construct = [];
    this.construct.length = 0;
    let subel = decoder.peekElement();
    while (subel !== 0) {
      if (subel === SLA_ELEM_CONSTRUCTOR.id) {
        const ct = new Constructor();
        this.addConstructor(ct);
        ct.decode(decoder, trans);
      } else if (subel === SLA_ELEM_DECISION.id) {
        this.decisiontree = new DecisionNode();
        this.decisiontree.decode(decoder, null, this);
      }
      subel = decoder.peekElement();
    }
    this.pattern = null;
    this.beingbuilt = false;
    this.errors = false;
    decoder.closeElement(SLA_ELEM_SUBTABLE_SYM.id);
  }
}

// =========================================================================
// MacroSymbol
// =========================================================================

export class MacroSymbol extends SleighSymbol {
  private index: number;
  private construct_tpl: ConstructTpl | null = null;
  private operands: OperandSymbol[] = [];

  constructor(nm: string, i: number) {
    super(nm);
    this.index = i;
  }

  getIndex(): number { return this.index; }
  setConstruct(ct: ConstructTpl): void { this.construct_tpl = ct; }
  getConstruct(): ConstructTpl | null { return this.construct_tpl; }
  addOperand(sym: OperandSymbol): void { this.operands.push(sym); }
  getNumOperands(): number { return this.operands.length; }
  getOperand(i: number): OperandSymbol { return this.operands[i]; }
  override getType(): SymbolType { return SymbolType.macro_symbol; }
}

// =========================================================================
// LabelSymbol
// =========================================================================

export class LabelSymbol extends SleighSymbol {
  private index: number;
  private _isplaced: boolean = false;
  private refcount: number = 0;

  constructor(nm: string, i: number) {
    super(nm);
    this.index = i;
  }

  getIndex(): number { return this.index; }
  incrementRefCount(): void { this.refcount += 1; }
  getRefCount(): number { return this.refcount; }
  setPlaced(): void { this._isplaced = true; }
  isPlaced(): boolean { return this._isplaced; }
  override getType(): SymbolType { return SymbolType.label_symbol; }
}
