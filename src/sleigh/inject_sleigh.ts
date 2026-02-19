import type { int4, uint4 } from '../core/types.js';
import { LowlevelError, DecoderError } from '../core/error.js';
import { Address } from '../core/address.js';
import type { AddrSpace } from '../core/space.js';
import { VarnodeData } from '../core/pcoderaw.js';
import { Translate, PcodeEmit } from '../core/translate.js';
import { PcodeCacher, SleighBuilder } from './sleigh.js';
import {
  Encoder,
  Decoder,
  XmlEncode,
  XmlDecode,
  ATTRIB_CONTENT,
  ATTRIB_NAME,
  ATTRIB_SPACE,
  ATTRIB_TYPE,
  ELEM_TARGET,
} from '../core/marshal.js';
import { xml_tree, Document as XmlDocument } from '../core/xml.js';
import { ConstructTpl } from './semantics.js';
import { ParserContext, ParserWalkerChange } from './context.js';
import { SleighBase } from './sleighbase.js';
import { PcodeSnippet } from './pcodeparse.js';
import type { Writer } from '../util/writer.js';
import {
  InjectPayload,
  InjectContext,
  InjectParameter,
  PcodeInjectLibrary,
  ExecutablePcode,
  ATTRIB_TARGETOP,
  ELEM_BODY,
  ELEM_PCODE,
  ELEM_CALLFIXUP,
  ELEM_CALLOTHERFIXUP,
  ELEM_CASE_PCODE,
  ELEM_ADDR_PCODE,
  ELEM_DEFAULT_PCODE,
  ELEM_SIZE_PCODE,
  ELEM_INJECTDEBUG,
  ELEM_INJECT,
  ELEM_INST,
  ELEM_PAYLOAD,
} from '../decompiler/pcodeinject.js';

type Architecture = any;
type OpBehavior = any;

function decodeAddress(decoder: Decoder): Address {
  const elemId = decoder.openElement();
  let space: AddrSpace | null = null;
  let offset = 0n;
  for (;;) {
    const attribId = decoder.getNextAttributeId();
    if (attribId === 0) break;
    if (attribId === ATTRIB_SPACE.id) {
      space = decoder.readSpace() as AddrSpace;
      decoder.rewindAttributes();
      const sizeRef = { val: 0 };
      offset = (space as any).decodeAttributes_sized(decoder, sizeRef);
      break;
    }
  }
  decoder.closeElement(elemId);
  if (space === null) return new Address();
  return new Address(space, offset);
}

export class InjectContextSleigh extends InjectContext {
  cacher: PcodeCacher;
  pos: ParserContext | null;

  constructor(g?: Architecture) {
    super(g);
    this.pos = null;
    this.cacher = new PcodeCacher();
  }

  encode(_encoder: Encoder): void {}
}

export class InjectPayloadSleigh extends InjectPayload {
  tpl: ConstructTpl | null;
  parsestring: string;
  private source: string;

  constructor(src: string, nm: string, tp: int4) {
    super(nm, tp);
    this.source = src;
    this.tpl = null;
    this.paramshift = 0;
    this.parsestring = '';
  }

  inject(context: InjectContext, emit: PcodeEmit): void {
    const con = context as InjectContextSleigh;
    con.cacher.clear();
    con.pos!.setAddr(con.baseaddr);
    con.pos!.setNaddr(con.nextaddr);
    con.pos!.setCalladdr(con.calladdr);
    const walker = new ParserWalkerChange(con.pos!);
    con.pos!.deallocateState(walker);
    InjectPayloadSleigh.setupParameters(con, walker, this.inputlist, this.output, this.source);
    const glb = con.glb;
    const builder = new SleighBuilder(
      walker, null as any, con.cacher, glb.getConstantSpace(), glb.getUniqueSpace(), 0
    );
    builder.build(this.tpl, -1);
    con.cacher.resolveRelatives();
    con.cacher.emit(con.baseaddr, emit);
  }

  protected decodeBody(decoder: Decoder): void {
    const elemId = decoder.openElement();
    if (elemId === ELEM_BODY.id) {
      this.parsestring = decoder.readStringById(ATTRIB_CONTENT);
      decoder.closeElement(elemId);
    }
    if (this.parsestring.length === 0 && !this.isDynamic())
      throw new LowlevelError('Missing <body> subtag in <pcode>: ' + this.getSource());
  }

  decode(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_PCODE);
    this.decodePayloadAttributes(decoder);
    this.decodePayloadParams(decoder);
    this.decodeBody(decoder);
    decoder.closeElement(elemId);
  }

  printTemplate(s: Writer): void {
    const encoder = new XmlEncode();
    this.tpl!.encode(encoder, -1);
    s.write(encoder.toString());
  }

  getSource(): string {
    return this.source;
  }

  static checkParameterRestrictions(
    con: InjectContextSleigh,
    inputlist: InjectParameter[],
    output: InjectParameter[],
    source: string
  ): void {
    if (inputlist.length !== con.inputlist.length)
      throw new LowlevelError(
        'Injection parameter list has different number of parameters than p-code operation: ' + source
      );
    for (let i = 0; i < inputlist.length; ++i) {
      const sz = inputlist[i].getSize();
      if (sz !== 0 && sz !== con.inputlist[i].size)
        throw new LowlevelError(
          'P-code input parameter size does not match injection specification: ' + source
        );
    }
    if (output.length !== con.output.length)
      throw new LowlevelError(
        'Injection output does not match output of p-code operation: ' + source
      );
    for (let i = 0; i < output.length; ++i) {
      const sz = output[i].getSize();
      if (sz !== 0 && sz !== con.output[i].size)
        throw new LowlevelError(
          'P-code output size does not match injection specification: ' + source
        );
    }
  }

  static setupParameters(
    con: InjectContextSleigh,
    walker: ParserWalkerChange,
    inputlist: InjectParameter[],
    output: InjectParameter[],
    source: string
  ): void {
    InjectPayloadSleigh.checkParameterRestrictions(con, inputlist, output, source);
    const pos = walker.getParserContext();
    for (let i = 0; i < inputlist.length; ++i) {
      pos.allocateOperand(inputlist[i].getIndex(), walker);
      const data = con.inputlist[i];
      const hand = walker.getParentHandle();
      hand.space = data.space as any;
      hand.offset_offset = data.offset;
      hand.size = data.size;
      hand.offset_space = null;
      walker.popOperand();
    }
    for (let i = 0; i < output.length; ++i) {
      pos.allocateOperand(output[i].getIndex(), walker);
      const data = con.output[i];
      const hand = walker.getParentHandle();
      hand.space = data.space as any;
      hand.offset_offset = data.offset;
      hand.size = data.size;
      hand.offset_space = null;
      walker.popOperand();
    }
  }
}

export class InjectPayloadCallfixup extends InjectPayloadSleigh {
  targetSymbolNames: string[] = [];

  constructor(sourceName: string) {
    super(sourceName, 'unknown', InjectPayload.CALLFIXUP_TYPE);
  }

  override decode(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_CALLFIXUP);
    this.name = decoder.readStringById(ATTRIB_NAME);
    let pcodeSubtag = false;
    for (;;) {
      const subId = decoder.openElement();
      if (subId === 0) break;
      if (subId === ELEM_PCODE.id) {
        this.decodePayloadAttributes(decoder);
        this.decodePayloadParams(decoder);
        this.decodeBody(decoder);
        pcodeSubtag = true;
      } else if (subId === ELEM_TARGET.id) {
        this.targetSymbolNames.push(decoder.readStringById(ATTRIB_NAME));
      }
      decoder.closeElement(subId);
    }
    decoder.closeElement(elemId);
    if (!pcodeSubtag)
      throw new LowlevelError('<callfixup> is missing <pcode> subtag: ' + this.name);
  }
}

export class InjectPayloadCallother extends InjectPayloadSleigh {
  constructor(sourceName: string) {
    super(sourceName, 'unknown', InjectPayload.CALLOTHERFIXUP_TYPE);
  }

  override decode(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_CALLOTHERFIXUP);
    this.name = decoder.readStringById(ATTRIB_TARGETOP);
    const subId = decoder.openElement();
    if (subId !== ELEM_PCODE.id)
      throw new LowlevelError('<callotherfixup> does not contain a <pcode> tag');
    this.decodePayloadAttributes(decoder);
    this.decodePayloadParams(decoder);
    this.decodeBody(decoder);
    decoder.closeElement(subId);
    decoder.closeElement(elemId);
  }
}

export class ExecutablePcodeSleigh extends ExecutablePcode {
  parsestring: string = '';
  tpl: ConstructTpl | null = null;

  constructor(g: Architecture, src: string, nm: string) {
    super(g, src, nm);
    this.tpl = null;
  }

  override inject(context: InjectContext, emit: PcodeEmit): void {
    const con = context as InjectContextSleigh;
    con.cacher.clear();
    con.pos!.setAddr(con.baseaddr);
    con.pos!.setNaddr(con.nextaddr);
    con.pos!.setCalladdr(con.calladdr);
    const walker = new ParserWalkerChange(con.pos!);
    con.pos!.deallocateState(walker);
    InjectPayloadSleigh.setupParameters(con, walker, this.inputlist, this.output, this.getSource());
    const glb = con.glb;
    const builder = new SleighBuilder(
      walker, null as any, con.cacher, glb.getConstantSpace(), glb.getUniqueSpace(), 0
    );
    builder.build(this.tpl, -1);
    con.cacher.resolveRelatives();
    con.cacher.emit(con.baseaddr, emit);
  }

  override decode(decoder: Decoder): void {
    const elemId = decoder.openElement();
    if (
      elemId !== ELEM_PCODE.id &&
      elemId !== ELEM_CASE_PCODE.id &&
      elemId !== ELEM_ADDR_PCODE.id &&
      elemId !== ELEM_DEFAULT_PCODE.id &&
      elemId !== ELEM_SIZE_PCODE.id
    )
      throw new DecoderError(
        'Expecting <pcode>, <case_pcode>, <addr_pcode>, <default_pcode>, or <size_pcode>'
      );
    this.decodePayloadAttributes(decoder);
    this.decodePayloadParams(decoder);
    const subId = decoder.openElementId(ELEM_BODY);
    this.parsestring = decoder.readStringById(ATTRIB_CONTENT);
    decoder.closeElement(subId);
    decoder.closeElement(elemId);
  }

  override printTemplate(s: Writer): void {
    const encoder = new XmlEncode();
    this.tpl!.encode(encoder, -1);
    s.write(encoder.toString());
  }
}

export class InjectPayloadDynamic extends InjectPayload {
  private glb: Architecture;
  private addrMap: Map<string, XmlDocument> = new Map();

  constructor(g: Architecture, base: InjectPayload) {
    super(base.getName(), base.getType());
    this.glb = g;
    this.dynamic = true;
    this.incidentalCopy = base.isIncidentalCopy();
    this.paramshift = base.getParamShift();
    for (let i = 0; i < base.sizeInput(); ++i)
      this.inputlist.push(base.getInput(i));
    for (let i = 0; i < base.sizeOutput(); ++i)
      this.output.push(base.getOutput(i));
  }

  decodeEntry(decoder: Decoder): void {
    const addr = decodeAddress(decoder);
    const subId = decoder.openElementId(ELEM_PAYLOAD);
    const content = decoder.readStringById(ATTRIB_CONTENT);
    try {
      const doc = xml_tree(content);
      const key = addr.toString();
      this.addrMap.set(key, doc);
    } catch {
      throw new LowlevelError('Error decoding dynamic payload');
    }
    decoder.closeElement(subId);
  }

  inject(context: InjectContext, emit: PcodeEmit): void {
    const key = context.baseaddr.toString();
    const doc = this.addrMap.get(key);
    if (doc === undefined)
      throw new LowlevelError('Missing dynamic inject');
    const el = doc.getRoot();
    const xmlDecoder = new XmlDecode(this.glb.translate, el);
    const rootId = xmlDecoder.openElementId(ELEM_INST);
    const addr = decodeAddress(xmlDecoder);
    while (xmlDecoder.peekElement() !== 0)
      emit.decodeOp(addr, xmlDecoder);
    xmlDecoder.closeElement(rootId);
  }

  decode(_decoder: Decoder): void {
    throw new LowlevelError('decode not supported for InjectPayloadDynamic');
  }

  printTemplate(s: Writer): void {
    s.write('dynamic');
  }

  getSource(): string {
    return 'dynamic';
  }
}

export class PcodeInjectLibrarySleigh extends PcodeInjectLibrary {
  private slgh: SleighBase | null;
  private inst: OpBehavior[] = [];
  private contextCache: InjectContextSleigh;

  constructor(g: Architecture) {
    super(g, (g.translate as Translate).getUniqueStart(Translate.INJECT));
    this.slgh = g.translate as SleighBase;
    this.contextCache = new InjectContextSleigh(g);
    this.contextCache.glb = g;
  }

  private forceDebugDynamic(injectid: int4): InjectPayloadDynamic {
    const oldPayload = this.injection[injectid];
    const newPayload = new InjectPayloadDynamic(this.glb, oldPayload);
    this.injection[injectid] = newPayload;
    return newPayload;
  }

  private parseInject(payload: InjectPayload): void {
    if (payload.isDynamic()) return;
    if (this.slgh === null) {
      this.slgh = this.glb.translate as SleighBase;
      if (this.slgh === null)
        throw new LowlevelError('Registering pcode snippet before language is instantiated');
    }
    if (this.contextCache.pos === null) {
      this.contextCache.pos = new ParserContext(null, null);
      this.contextCache.pos.initialize(8, 8, (this.slgh as any).getConstantSpace());
    }
    const compiler = new PcodeSnippet(this.slgh);
    for (let i = 0; i < payload.sizeInput(); ++i) {
      const param = payload.getInput(i);
      compiler.addOperand(param.getName(), param.getIndex());
    }
    for (let i = 0; i < payload.sizeOutput(); ++i) {
      const param = payload.getOutput(i);
      compiler.addOperand(param.getName(), param.getIndex());
    }
    if (payload.getType() === InjectPayload.EXECUTABLEPCODE_TYPE) {
      compiler.setUniqueBase(0x2000);
      const sleighpayload = payload as ExecutablePcodeSleigh;
      if (!compiler.parsePcode(sleighpayload.parsestring))
        throw new LowlevelError(
          payload.getSource() + ': Unable to compile pcode: ' + compiler.getErrorMessage()
        );
      sleighpayload.tpl = compiler.releaseResult();
      sleighpayload.parsestring = '';
    } else {
      compiler.setUniqueBase(this.tempbase);
      const sleighpayload = payload as InjectPayloadSleigh;
      if (!compiler.parsePcode(sleighpayload.parsestring))
        throw new LowlevelError(
          payload.getSource() + ': Unable to compile pcode: ' + compiler.getErrorMessage()
        );
      this.tempbase = compiler.getUniqueBase();
      sleighpayload.tpl = compiler.releaseResult();
      sleighpayload.parsestring = '';
    }
  }

  protected allocateInject(sourceName: string, name: string, type: int4): int4 {
    const injectid = this.injection.length;
    if (type === InjectPayload.CALLFIXUP_TYPE)
      this.injection.push(new InjectPayloadCallfixup(sourceName));
    else if (type === InjectPayload.CALLOTHERFIXUP_TYPE)
      this.injection.push(new InjectPayloadCallother(sourceName));
    else if (type === InjectPayload.EXECUTABLEPCODE_TYPE)
      this.injection.push(new ExecutablePcodeSleigh(this.glb, sourceName, name));
    else
      this.injection.push(new InjectPayloadSleigh(sourceName, name, type));
    return injectid;
  }

  protected registerInject(injectid: int4): void {
    let payload = this.injection[injectid];
    if (payload.isDynamic()) {
      const sub = new InjectPayloadDynamic(this.glb, payload);
      payload = sub;
      this.injection[injectid] = payload;
    }
    switch (payload.getType()) {
      case InjectPayload.CALLFIXUP_TYPE:
        this.registerCallFixup(payload.getName(), injectid);
        this.parseInject(payload);
        break;
      case InjectPayload.CALLOTHERFIXUP_TYPE:
        this.registerCallOtherFixup(payload.getName(), injectid);
        this.parseInject(payload);
        break;
      case InjectPayload.CALLMECHANISM_TYPE:
        this.registerCallMechanism(payload.getName(), injectid);
        this.parseInject(payload);
        break;
      case InjectPayload.EXECUTABLEPCODE_TYPE:
        this.registerExeScript(payload.getName(), injectid);
        this.parseInject(payload);
        break;
      default:
        throw new LowlevelError('Unknown p-code inject type');
    }
  }

  decodeDebug(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_INJECTDEBUG);
    for (;;) {
      const subId = decoder.openElement();
      if (subId !== ELEM_INJECT.id) break;
      const name = decoder.readStringById(ATTRIB_NAME);
      const type = decoder.readSignedIntegerById(ATTRIB_TYPE);
      const id = this.getPayloadId(type, name);
      let payload = this.getPayload(id);
      let dynPayload: InjectPayloadDynamic;
      if (payload instanceof InjectPayloadDynamic) {
        dynPayload = payload as InjectPayloadDynamic;
      } else {
        dynPayload = this.forceDebugDynamic(id);
      }
      dynPayload.decodeEntry(decoder);
      decoder.closeElement(subId);
    }
    decoder.closeElement(elemId);
  }

  getBehaviors(): OpBehavior[] {
    if (this.inst.length === 0)
      this.glb.collectBehaviors(this.inst);
    return this.inst;
  }

  manualCallFixup(name: string, snippetstring: string): int4 {
    const sourceName = '(manual callfixup name="' + name + '")';
    const injectid = this.allocateInject(sourceName, name, InjectPayload.CALLFIXUP_TYPE);
    const payload = this.getPayload(injectid) as InjectPayloadSleigh;
    payload.parsestring = snippetstring;
    this.registerInject(injectid);
    return injectid;
  }

  manualCallOtherFixup(name: string, outname: string, inname: string[], snippet: string): int4 {
    const sourceName = '<manual callotherfixup name="' + name + '")';
    const injectid = this.allocateInject(sourceName, name, InjectPayload.CALLOTHERFIXUP_TYPE);
    const payload = this.getPayload(injectid) as InjectPayloadSleigh;
    const payloadAny = payload as any;
    for (let i = 0; i < inname.length; ++i)
      payloadAny.inputlist.push(new InjectParameter(inname[i], 0));
    if (outname.length !== 0)
      payloadAny.output.push(new InjectParameter(outname, 0));
    payloadAny.orderParameters();
    payload.parsestring = snippet;
    this.registerInject(injectid);
    return injectid;
  }

  getCachedContext(): InjectContext {
    return this.contextCache;
  }
}
