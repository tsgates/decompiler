import type { int4, uint4, uintb, uintm } from '../core/types.js';
import { OpCode } from '../core/opcodes.js';
import { AddrSpace } from '../core/space.js';
import { Address } from '../core/address.js';
import { calc_mask, coveringmask } from '../core/address.js';
import { LowlevelError } from '../core/error.js';
import { Translate, UnimplError, PcodeEmit, AssemblyEmit } from '../core/translate.js';
import { VarnodeData } from '../core/pcoderaw.js';
import { ContextCache, ContextDatabase } from '../core/globalcontext.js';
import { ConstTpl, VarnodeTpl, OpTpl, HandleTpl, ConstructTpl, PcodeBuilder } from './semantics.js';
import { ParserContext, ParserWalker, ParserWalkerChange, FixedHandle } from './context.js';
import { SleighBase } from './sleighbase.js';
import { FormatDecode } from './slaformat.js';
import { Writer, StringWriter } from '../util/writer.js';
import * as fs from 'fs';

type LoadImage = any;
type DocumentStorage = any;
type Element = any;
type SubtableSymbol = any;
type TripleSymbol = any;
type OperandSymbol = any;
type Constructor = any;
type PatternExpression = any;

// SleighSymbol type constants
const subtable_symbol = 12;

export interface RelativeRecord {
  dataptr: VarnodeData;
  calling_index: bigint;
}

export interface PcodeData {
  opc: OpCode;
  outvar: VarnodeData | null;
  invar: VarnodeData[];
  isize: number;
}

export class PcodeCacher {
  private issued: PcodeData[] = [];
  private label_refs: RelativeRecord[] = [];
  private labels: bigint[] = [];

  allocateVarnodes(size: number): VarnodeData[] {
    const arr: VarnodeData[] = new Array(size);
    for (let i = 0; i < size; i++) {
      arr[i] = new VarnodeData();
    }
    return arr;
  }

  allocateInstruction(): PcodeData {
    const res: PcodeData = {
      opc: OpCode.CPUI_COPY,
      outvar: null,
      invar: [],
      isize: 0,
    };
    this.issued.push(res);
    return res;
  }

  addLabelRef(ptr: VarnodeData): void {
    this.label_refs.push({
      dataptr: ptr,
      calling_index: BigInt(this.issued.length),
    });
  }

  addLabel(id: number): void {
    while (this.labels.length <= id)
      this.labels.push(0xbadbeefn);
    this.labels[id] = BigInt(this.issued.length);
  }

  clear(): void {
    this.issued.length = 0;
    this.label_refs.length = 0;
    this.labels.length = 0;
  }

  resolveRelatives(): void {
    for (const rec of this.label_refs) {
      const ptr = rec.dataptr;
      const id = Number(ptr.offset);
      if (id >= this.labels.length || this.labels[id] === 0xbadbeefn)
        throw new LowlevelError('Reference to non-existant sleigh label');
      let res = this.labels[id] - rec.calling_index;
      res &= calc_mask(ptr.size);
      ptr.offset = res;
    }
  }

  emit(addr: Address, emt: PcodeEmit): void {
    for (const op of this.issued) {
      emt.dump(addr, op.opc, op.outvar, op.invar, op.isize);
    }
  }
}

export class DisassemblyCache {
  private translate: Translate;
  private contextcache: ContextCache;
  private constspace: AddrSpace;
  private minimumreuse: number = 0;
  private mask: number = 0;
  private list: ParserContext[] = [];
  private nextfree: number = 0;
  private hashtable: (ParserContext | null)[] = [];

  constructor(trans: Translate, ccache: ContextCache, cspace: AddrSpace, cachesize: number, windowsize: number) {
    this.translate = trans;
    this.contextcache = ccache;
    this.constspace = cspace;
    this.initialize(cachesize, windowsize);
  }

  private initialize(min: number, hashsize: number): void {
    this.minimumreuse = min;
    this.mask = hashsize - 1;
    const masktest = coveringmask(BigInt(this.mask));
    if (masktest !== BigInt(this.mask))
      throw new LowlevelError('Bad windowsize for disassembly cache');
    this.list = [];
    this.nextfree = 0;
    this.hashtable = [];
    for (let i = 0; i < min; i++) {
      const pos = new ParserContext(this.contextcache, this.translate);
      pos.initialize(75, 20, this.constspace);
      this.list.push(pos);
    }
    const pos = this.list[0];
    for (let i = 0; i < hashsize; i++) {
      this.hashtable.push(pos);
    }
  }

  getParserContext(addr: Address): ParserContext {
    const hashindex = Number(addr.getOffset()) & this.mask;
    let res = this.hashtable[hashindex]!;
    if (res.getAddr().equals(addr))
      return res;
    res = this.list[this.nextfree];
    this.nextfree += 1;
    if (this.nextfree >= this.minimumreuse)
      this.nextfree = 0;
    res.setAddr(addr);
    res.setParserState(ParserContext.uninitialized);
    this.hashtable[hashindex] = res;
    return res;
  }
}

export class SleighBuilder extends PcodeBuilder {
  private const_space: AddrSpace;
  private uniq_space: AddrSpace;
  private uniquemask: bigint;
  private uniqueoffset: bigint;
  private discache: DisassemblyCache;
  private cache: PcodeCacher;

  constructor(
    w: ParserWalker,
    dcache: DisassemblyCache,
    pc: PcodeCacher,
    cspc: AddrSpace,
    uspc: AddrSpace,
    umask: number,
  ) {
    super(0);
    this.walker = w;
    this.discache = dcache;
    this.cache = pc;
    this.const_space = cspc;
    this.uniq_space = uspc;
    this.uniquemask = BigInt(umask);
    this.uniqueoffset = (w.getAddr().getOffset() & this.uniquemask) << 8n;
  }

  private setUniqueOffset(addr: Address): void {
    this.uniqueoffset = (addr.getOffset() & this.uniquemask) << 8n;
  }

  private generateLocation(vntpl: VarnodeTpl, vn: VarnodeData): void {
    vn.space = vntpl.getSpace().fixSpace(this.walker!);
    vn.size = Number(vntpl.getSize().fix(this.walker!));
    if (vn.space === this.const_space) {
      vn.offset = vntpl.getOffset().fix(this.walker!) & calc_mask(vn.size);
    } else if (vn.space === this.uniq_space) {
      vn.offset = vntpl.getOffset().fix(this.walker!);
      vn.offset |= this.uniqueoffset;
    } else {
      vn.offset = (vn.space as any).wrapOffset(vntpl.getOffset().fix(this.walker!));
    }
  }

  private generatePointer(vntpl: VarnodeTpl, vn: VarnodeData): AddrSpace {
    const hand: FixedHandle = (this.walker as any).getFixedHandle(vntpl.getOffset().getHandleIndex());
    vn.space = hand.offset_space;
    vn.size = hand.offset_size;
    if (vn.space === this.const_space) {
      vn.offset = hand.offset_offset & calc_mask(vn.size);
    } else if (vn.space === this.uniq_space) {
      vn.offset = hand.offset_offset | this.uniqueoffset;
    } else {
      vn.offset = (vn.space as any).wrapOffset(hand.offset_offset);
    }
    return hand.space!;
  }

  private generatePointerAdd(op: PcodeData, vntpl: VarnodeTpl): void {
    const offsetPlus = vntpl.getOffset().getReal() & 0xffffn;
    if (offsetPlus === 0n) return;

    const nextop = this.cache.allocateInstruction();
    nextop.opc = op.opc;
    nextop.invar = op.invar;
    nextop.isize = op.isize;
    nextop.outvar = op.outvar;

    op.isize = 2;
    op.opc = OpCode.CPUI_INT_ADD;
    const newparams = this.cache.allocateVarnodes(2);
    op.invar = newparams;
    newparams[0].space = nextop.invar[1].space;
    newparams[0].offset = nextop.invar[1].offset;
    newparams[0].size = nextop.invar[1].size;
    newparams[1].space = this.const_space;
    newparams[1].offset = offsetPlus;
    newparams[1].size = newparams[0].size;

    // Output of ADD is input to the original op - create a new VarnodeData for it
    const outvn = new VarnodeData();
    outvn.space = this.uniq_space;
    outvn.offset = BigInt(this.uniq_space.getTrans()!.getUniqueStart(Translate.RUNTIME_BITRANGE_EA));
    outvn.size = newparams[0].size;
    op.outvar = outvn;
    // The original op's second input (the pointer) now refers to this output
    nextop.invar[1] = outvn;
  }

  protected dump(op: OpTpl): void {
    let thisop: PcodeData;
    let vn: VarnodeTpl;
    let outvn: VarnodeTpl | null;
    const isize = op.numInput();

    const invars = this.cache.allocateVarnodes(isize);
    for (let i = 0; i < isize; i++) {
      vn = op.getIn(i);
      if (vn.isDynamic(this.walker!)) {
        this.generateLocation(vn, invars[i]);
        const load_op = this.cache.allocateInstruction();
        load_op.opc = OpCode.CPUI_LOAD;
        load_op.outvar = invars[i];
        load_op.isize = 2;
        const loadvars = this.cache.allocateVarnodes(2);
        load_op.invar = loadvars;
        const spc = this.generatePointer(vn, loadvars[1]);
        loadvars[0].space = this.const_space;
        loadvars[0].offset = BigInt(spc.getIndex());
        loadvars[0].size = 8;
        if (vn.getOffset().getSelect() === ConstTpl.v_offset_plus)
          this.generatePointerAdd(load_op, vn);
      } else {
        this.generateLocation(vn, invars[i]);
      }
    }
    if (isize > 0 && op.getIn(0).isRelative()) {
      invars[0].offset += BigInt(this.getLabelBase());
      this.cache.addLabelRef(invars[0]);
    }
    thisop = this.cache.allocateInstruction();
    thisop.opc = op.getOpcode();
    thisop.invar = invars;
    thisop.isize = isize;
    outvn = op.getOut();
    if (outvn !== null) {
      if (outvn.isDynamic(this.walker!)) {
        const storevars = this.cache.allocateVarnodes(3);
        this.generateLocation(outvn, storevars[2]);
        thisop.outvar = storevars[2];
        const store_op = this.cache.allocateInstruction();
        store_op.opc = OpCode.CPUI_STORE;
        store_op.isize = 3;
        store_op.invar = storevars;
        const spc = this.generatePointer(outvn, storevars[1]);
        storevars[0].space = this.const_space;
        storevars[0].offset = BigInt(spc.getIndex());
        storevars[0].size = 8;
        if (outvn.getOffset().getSelect() === ConstTpl.v_offset_plus)
          this.generatePointerAdd(store_op, outvn);
      } else {
        const outvars = this.cache.allocateVarnodes(1);
        thisop.outvar = outvars[0];
        this.generateLocation(outvn, outvars[0]);
      }
    }
  }

  private buildEmpty(ct: Constructor, secnum: number): void {
    const numops: number = ct.getNumOperands();
    for (let i = 0; i < numops; i++) {
      const sym: SubtableSymbol = ct.getOperand(i).getDefiningSymbol();
      if (sym == null) continue;
      if (sym.getType() !== subtable_symbol) continue;
      (this.walker as any).pushOperand(i);
      const construct: ConstructTpl | null = (this.walker as any).getConstructor().getNamedTempl(secnum);
      if (construct == null)
        this.buildEmpty((this.walker as any).getConstructor(), secnum);
      else
        this.build(construct, secnum);
      (this.walker as any).popOperand();
    }
  }

  appendBuild(bld: OpTpl, secnum: number): void {
    const index = Number(bld.getIn(0).getOffset().getReal());
    const sym: SubtableSymbol = (this.walker as any).getConstructor().getOperand(index).getDefiningSymbol();
    if (sym == null || sym.getType() !== subtable_symbol) return;

    (this.walker as any).pushOperand(index);
    const ct: Constructor = (this.walker as any).getConstructor();
    if (secnum >= 0) {
      const construct: ConstructTpl | null = ct.getNamedTempl(secnum);
      if (construct == null)
        this.buildEmpty(ct, secnum);
      else
        this.build(construct, secnum);
    } else {
      const construct: ConstructTpl = ct.getTempl();
      this.build(construct, -1);
    }
    (this.walker as any).popOperand();
  }

  delaySlot(op: OpTpl): void {
    const tmp = this.walker!;
    const olduniqueoffset = this.uniqueoffset;

    const baseaddr: Address = tmp.getAddr();
    let fallOffset = tmp.getLength();
    const delaySlotByteCnt = tmp.getParserContext().getDelaySlot();
    let bytecount = 0;
    do {
      const newaddr = baseaddr.add(BigInt(fallOffset));
      this.setUniqueOffset(newaddr);
      const pos = this.discache.getParserContext(newaddr);
      if (pos.getParserState() !== ParserContext.pcode)
        throw new LowlevelError('Could not obtain cached delay slot instruction');
      const len = pos.getLength();
      const newwalker = new ParserWalker(pos);
      this.walker = newwalker;
      newwalker.baseState();
      this.build(newwalker.getConstructor().getTempl(), -1);
      fallOffset += len;
      bytecount += len;
    } while (bytecount < delaySlotByteCnt);
    this.walker = tmp;
    this.uniqueoffset = olduniqueoffset;
  }

  setLabel(op: OpTpl): void {
    this.cache.addLabel(Number(op.getIn(0).getOffset().getReal()) + this.getLabelBase());
  }

  appendCrossBuild(bld: OpTpl, secnum: number): void {
    if (secnum >= 0)
      throw new LowlevelError('CROSSBUILD directive within a named section');
    secnum = Number(bld.getIn(1).getOffset().getReal());
    const vn: VarnodeTpl = bld.getIn(0);
    const spc: AddrSpace = vn.getSpace().fixSpace(this.walker!);
    const addr: bigint = spc.wrapOffset(vn.getOffset().fix(this.walker!));

    const tmp = this.walker!;
    const olduniqueoffset = this.uniqueoffset;

    const newaddr = new Address(spc, addr);
    this.setUniqueOffset(newaddr);
    const pos = this.discache.getParserContext(newaddr);
    if (pos.getParserState() !== ParserContext.pcode)
      throw new LowlevelError('Could not obtain cached crossbuild instruction');

    const newwalker = new ParserWalker(pos, tmp.getParserContext());
    this.walker = newwalker;

    newwalker.baseState();
    const ct: Constructor = newwalker.getConstructor();
    const construct: ConstructTpl | null = ct.getNamedTempl(secnum);
    if (construct == null)
      this.buildEmpty(ct, secnum);
    else
      this.build(construct, secnum);
    this.walker = tmp;
    this.uniqueoffset = olduniqueoffset;
  }
}

export class Sleigh extends SleighBase {
  private loader: LoadImage;
  private context_db: ContextDatabase;
  private cache_ctx: ContextCache;
  private discache: DisassemblyCache | null = null;
  private pcode_cache: PcodeCacher = new PcodeCacher();

  constructor(ld: LoadImage, c_db: ContextDatabase) {
    super();
    this.loader = ld;
    this.context_db = c_db;
    this.cache_ctx = new ContextCache(c_db);
  }

  private clearForDelete(): void {
    // JS GC handles memory, but we null out refs
    this.discache = null;
  }

  reset(ld: LoadImage, c_db: ContextDatabase): void {
    this.clearForDelete();
    this.pcode_cache.clear();
    this.loader = ld;
    this.context_db = c_db;
    this.cache_ctx = new ContextCache(c_db);
    this.discache = null;
  }

  initialize(store: DocumentStorage): void {
    if (!this.isInitialized()) {
      const el: Element | null = store.getTag('sleigh');
      if (el == null)
        throw new LowlevelError('Could not find sleigh tag');
      const slafile: string = el.getContent().trim();
      // Read the binary .sla file and feed it to FormatDecode
      const slaData = fs.readFileSync(slafile);
      const decoder = new FormatDecode(this as any);
      decoder.ingestStreamFromBytes(slaData);
      this.decodeSleigh(decoder);
    } else {
      this.reregisterContext();
    }
    let parser_cachesize = 2;
    let parser_windowsize = 32;
    if (this.maxdelayslotbytes > 1 || this.unique_allocatemask !== 0) {
      parser_cachesize = 8;
      parser_windowsize = 256;
    }
    this.discache = new DisassemblyCache(
      this as any,
      this.cache_ctx,
      this.getConstantSpace()!,
      parser_cachesize,
      parser_windowsize,
    );
  }

  protected obtainContext(addr: Address, state: number): ParserContext {
    const pos = this.discache!.getParserContext(addr);
    const curstate = pos.getParserState();
    if (curstate >= state) return pos;
    if (curstate === ParserContext.uninitialized) {
      this.resolve(pos);
      if (state === ParserContext.disassembly) return pos;
    }
    this.resolveHandles(pos);
    return pos;
  }

  protected resolve(pos: ParserContext): void {
    this.loader.loadFill(pos.getBuffer(), 16, pos.getAddr());
    const walker = new ParserWalkerChange(pos);
    pos.deallocateState(walker);
    let ct: Constructor;
    let subct: Constructor | null;
    let off: number;
    let oper: number;
    let numoper: number;

    pos.setDelaySlot(0);
    walker.setOffset(0);
    pos.clearCommits();
    pos.loadContext();
    ct = (this as any).root.resolve(walker);
    walker.setConstructor(ct);
    ct.applyContext(walker);
    while (walker.isState()) {
      ct = walker.getConstructor();
      oper = walker.getOperand();
      numoper = ct.getNumOperands();
      while (oper < numoper) {
        const sym: OperandSymbol = ct.getOperand(oper);
        off = walker.getOffset(sym.getOffsetBase()) + sym.getRelativeOffset();
        pos.allocateOperand(oper, walker);
        walker.setOffset(off);
        const tsym: TripleSymbol | null = sym.getDefiningSymbol();
        if (tsym != null) {
          subct = tsym.resolve(walker);
          if (subct != null) {
            walker.setConstructor(subct);
            subct.applyContext(walker);
            break;
          }
        }
        walker.setCurrentLength(sym.getMinimumLength());
        walker.popOperand();
        oper += 1;
      }
      if (oper >= numoper) {
        walker.calcCurrentLength(ct.getMinimumLength(), numoper);
        walker.popOperand();
        const templ: ConstructTpl | null = ct.getTempl();
        if (templ != null && templ.delaySlot() > 0)
          pos.setDelaySlot(templ.delaySlot());
      }
    }
    pos.setNaddr(pos.getAddr().add(BigInt(pos.getLength())));
    pos.setParserState(ParserContext.disassembly);
  }

  protected resolveHandles(pos: ParserContext): void {
    let triple: TripleSymbol | null;
    let ct: Constructor;
    let oper: number;
    let numoper: number;

    const walker = new ParserWalker(pos);
    walker.baseState();
    while (walker.isState()) {
      ct = walker.getConstructor();
      oper = walker.getOperand();
      numoper = ct.getNumOperands();
      while (oper < numoper) {
        const sym: OperandSymbol = ct.getOperand(oper);
        walker.pushOperand(oper);
        triple = sym.getDefiningSymbol();
        if (triple != null) {
          if (triple.getType() === subtable_symbol)
            break;
          else
            triple.getFixedHandle(walker.getParentHandle(), walker);
        } else {
          const patexp: PatternExpression = sym.getDefiningExpression();
          const res: bigint = patexp.getValue(walker);
          const hand: FixedHandle = walker.getParentHandle();
          hand.space = pos.getConstSpace();
          hand.offset_space = null;
          hand.offset_offset = res;
          hand.size = 0;
        }
        walker.popOperand();
        oper += 1;
      }
      if (oper >= numoper) {
        const templ: ConstructTpl | null = ct.getTempl();
        if (templ != null) {
          const res: HandleTpl | null = templ.getResult();
          if (res != null)
            res.fix(walker.getParentHandle(), walker);
        }
        walker.popOperand();
      }
    }
    pos.setParserState(ParserContext.pcode);
  }

  instructionLength(baseaddr: Address): number {
    const pos = this.obtainContext(baseaddr, ParserContext.disassembly);
    return pos.getLength();
  }

  oneInstruction(emit: PcodeEmit, baseaddr: Address): number {
    let fallOffset: number;
    if (this.alignment !== 1) {
      if (Number(baseaddr.getOffset() % BigInt(this.alignment)) !== 0) {
        throw new UnimplError('Instruction address not aligned: ' + baseaddr.toString(), 0);
      }
    }

    const pos = this.obtainContext(baseaddr, ParserContext.pcode);
    pos.applyCommits();
    fallOffset = pos.getLength();

    if (pos.getDelaySlot() > 0) {
      let bytecount = 0;
      do {
        const delaypos = this.obtainContext(pos.getAddr().add(BigInt(fallOffset)), ParserContext.pcode);
        delaypos.applyCommits();
        const len = delaypos.getLength();
        fallOffset += len;
        bytecount += len;
      } while (bytecount < pos.getDelaySlot());
      pos.setNaddr(pos.getAddr().add(BigInt(fallOffset)));
    }
    const walker = new ParserWalker(pos);
    walker.baseState();
    this.pcode_cache.clear();
    const builder = new SleighBuilder(
      walker,
      this.discache!,
      this.pcode_cache,
      this.getConstantSpace()!,
      this.getUniqueSpace()!,
      this.unique_allocatemask,
    );
    try {
      builder.build(walker.getConstructor().getTempl(), -1);
      this.pcode_cache.resolveRelatives();
      this.pcode_cache.emit(baseaddr, emit);
    } catch (err) {
      if (err instanceof UnimplError) {
        const sw = new StringWriter();
        sw.write('Instruction not implemented in pcode:\n ');
        const cur = builder.getCurrentWalker()!;
        cur.baseState();
        const ct: Constructor = cur.getConstructor();
        sw.write(cur.getAddr().printRaw());
        sw.write(': ');
        const mnemSw = new StringWriter();
        ct.printMnemonic(mnemSw, cur);
        sw.write(mnemSw.toString());
        sw.write('  ');
        const bodySw = new StringWriter();
        ct.printBody(bodySw, cur);
        sw.write(bodySw.toString());
        (err as any).explain = sw.toString();
        err.instruction_length = fallOffset;
        throw err;
      }
      throw err;
    }
    return fallOffset;
  }

  printAssembly(emit: AssemblyEmit, baseaddr: Address): number {
    const pos = this.obtainContext(baseaddr, ParserContext.disassembly);
    const walker = new ParserWalker(pos);
    walker.baseState();

    const ct: Constructor = walker.getConstructor();
    const mnemSw = new StringWriter();
    ct.printMnemonic(mnemSw, walker);
    const bodySw = new StringWriter();
    ct.printBody(bodySw, walker);
    emit.dump(baseaddr, mnemSw.toString(), bodySw.toString());
    return pos.getLength();
  }

  registerContext(name: string, sbit: number, ebit: number): void {
    this.context_db.registerVariable(name, sbit, ebit);
  }

  setContextDefault(name: string, val: number): void {
    this.context_db.setVariableDefault(name, val);
  }

  allowContextSet(val: boolean): void {
    this.cache_ctx.allowSet(val);
  }
}
