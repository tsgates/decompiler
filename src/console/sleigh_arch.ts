/**
 * @file sleigh_arch.ts
 * @description Architecture objects that use a Translate object derived from Sleigh.
 *
 * Translated from Ghidra's sleigh_arch.hh / sleigh_arch.cc
 */

import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

import { AttributeId, ElementId, XmlDecode, ATTRIB_CONTENT, ATTRIB_ID, ATTRIB_NAME, ATTRIB_SIZE } from '../core/marshal.js';
import { LowlevelError, DecoderError } from '../core/error.js';
import { FileManage } from '../core/filemanage.js';
import { DocumentStorage, Element } from '../core/xml.js';
import { Translate } from '../core/translate.js';
import { ContextInternal } from '../core/globalcontext.js';
import { Writer, StringWriter } from '../util/writer.js';
import { SleighError } from '../sleigh/context.js';
import { Sleigh } from '../sleigh/sleigh.js';
import { PcodeInjectLibrarySleigh } from '../sleigh/inject_sleigh.js';
import { Architecture } from '../decompiler/architecture.js';
import { TypeFactory } from '../decompiler/type.js';
import { CommentDatabaseInternal } from '../decompiler/comment.js';
import { StringManagerUnicode } from '../decompiler/stringmanage.js';
import { ConstantPoolInternal } from '../decompiler/cpool.js';
import { PcodeInjectLibrary } from '../decompiler/pcodeinject.js';

// -------------------------------------------------------------------------
// Forward type declarations for types only used as annotations
// -------------------------------------------------------------------------

type Decoder = any;
type Encoder = any;
type TruncationTag = any;

// -------------------------------------------------------------------------
// Marshaling Attribute IDs (sleigh_arch-specific)
// -------------------------------------------------------------------------

export const ATTRIB_DEPRECATED = new AttributeId("deprecated", 136);
export const ATTRIB_ENDIAN = new AttributeId("endian", 137);
export const ATTRIB_PROCESSOR = new AttributeId("processor", 138);
export const ATTRIB_PROCESSORSPEC = new AttributeId("processorspec", 139);
export const ATTRIB_SLAFILE = new AttributeId("slafile", 140);
export const ATTRIB_SPEC = new AttributeId("spec", 141);
export const ATTRIB_TARGET = new AttributeId("target", 142);
export const ATTRIB_VARIANT = new AttributeId("variant", 143);
export const ATTRIB_VERSION = new AttributeId("version", 144);

// -------------------------------------------------------------------------
// Marshaling Element IDs (sleigh_arch-specific)
// -------------------------------------------------------------------------

export const ELEM_COMPILER = new ElementId("compiler", 232);
export const ELEM_DESCRIPTION = new ElementId("description", 233);
export const ELEM_LANGUAGE = new ElementId("language", 234);
export const ELEM_LANGUAGE_DEFINITIONS = new ElementId("language_definitions", 235);

// Forward reference to ELEM_TRUNCATE_SPACE (defined in translate module)
const ELEM_TRUNCATE_SPACE = new ElementId("truncate_space", 0, 1);

// -------------------------------------------------------------------------
// Module-level state (formerly static members of SleighArchitecture)
// -------------------------------------------------------------------------

/** Map from language index to instantiated translators */
const translators: Map<number, any> = new Map();

/** List of languages we know about */
let description: LanguageDescription[] = [];

/** Known directories that contain .ldefs files */
export const specpaths: FileManage = new FileManage();

// =========================================================================
// CompilerTag
// =========================================================================

/**
 * Contents of a <compiler> tag in a .ldefs file.
 *
 * This class describes a compiler specification file as referenced by the
 * Sleigh language subsystem.
 */
export class CompilerTag {
  private name: string = "";
  private spec: string = "";
  private id: string = "";

  constructor() {}

  /** Restore the record from a decoder stream */
  decode(decoder: Decoder): void {
    const elemId: number = decoder.openElementId(ELEM_COMPILER);
    this.name = decoder.readStringById(ATTRIB_NAME);
    this.spec = decoder.readStringById(ATTRIB_SPEC);
    this.id = decoder.readStringById(ATTRIB_ID);
    decoder.closeElement(elemId);
  }

  /** Get the human readable name of the spec */
  getName(): string { return this.name; }

  /** Get the file-name */
  getSpec(): string { return this.spec; }

  /** Get the string used as part of language id */
  getId(): string { return this.id; }
}

// =========================================================================
// LanguageDescription
// =========================================================================

/**
 * Contents of the <language> tag in a .ldefs file.
 *
 * This class contains meta-data describing a single processor and the set
 * of files used to analyze it. Ghidra requires a compiled SLEIGH specification
 * file (.sla), a processor specification file (.pspec), and a compiler
 * specification file (.cspec) in order to support disassembly/decompilation
 * of a processor. This class supports a single processor, as described by a
 * single SLEIGH file and processor spec. Multiple compiler specifications
 * can be given for the single processor.
 */
export class LanguageDescription {
  private processor: string = "";
  private isbigendian: boolean = false;
  private size: number = 0;
  private variant: string = "";
  private version: string = "";
  private slafile: string = "";
  private processorspec: string = "";
  private id: string = "";
  private descriptionStr: string = "";
  private deprecated: boolean = false;
  private compilers: CompilerTag[] = [];
  private truncations: TruncationTag[] = [];

  constructor() {}

  /** Parse this description from a decoder stream */
  decode(decoder: Decoder): void {
    const elemId: number = decoder.openElementId(ELEM_LANGUAGE);
    this.processor = decoder.readStringById(ATTRIB_PROCESSOR);
    this.isbigendian = (decoder.readStringById(ATTRIB_ENDIAN) === "big");
    this.size = decoder.readSignedIntegerById(ATTRIB_SIZE);
    this.variant = decoder.readStringById(ATTRIB_VARIANT);
    this.version = decoder.readStringById(ATTRIB_VERSION);
    this.slafile = decoder.readStringById(ATTRIB_SLAFILE);
    this.processorspec = decoder.readStringById(ATTRIB_PROCESSORSPEC);
    this.id = decoder.readStringById(ATTRIB_ID);
    this.deprecated = false;
    for (;;) {
      const attribId: number = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_DEPRECATED.getId())
        this.deprecated = decoder.readBool();
    }
    for (;;) {
      const subId: number = decoder.peekElement();
      if (subId === 0) break;
      if (subId === ELEM_DESCRIPTION.getId()) {
        decoder.openElement();
        this.descriptionStr = decoder.readStringById(ATTRIB_CONTENT);
        decoder.closeElement(subId);
      } else if (subId === ELEM_COMPILER.getId()) {
        const tag = new CompilerTag();
        tag.decode(decoder);
        this.compilers.push(tag);
      } else if (subId === ELEM_TRUNCATE_SPACE.getId()) {
        // TruncationTag not yet wired - skip
        decoder.openElement();
        decoder.closeElementSkipping(subId);
      } else {
        // Ignore other child elements
        decoder.openElement();
        decoder.closeElementSkipping(subId);
      }
    }
    decoder.closeElement(elemId);
  }

  /** Get the name of the processor */
  getProcessor(): string { return this.processor; }

  /** Return true if the processor is big-endian */
  isBigEndian(): boolean { return this.isbigendian; }

  /** Get the size of the address bus */
  getSize(): number { return this.size; }

  /** Get the processor variant */
  getVariant(): string { return this.variant; }

  /** Get the processor version */
  getVersion(): string { return this.version; }

  /** Get filename of the SLEIGH specification */
  getSlaFile(): string { return this.slafile; }

  /** Get the filename of the processor specification */
  getProcessorSpec(): string { return this.processorspec; }

  /** Get the language id string associated with this processor */
  getId(): string { return this.id; }

  /** Get a description of the processor */
  getDescription(): string { return this.descriptionStr; }

  /** Return true if this specification is deprecated */
  isDeprecated(): boolean { return this.deprecated; }

  /**
   * Get compiler specification of the given name.
   * Pick out the CompilerTag associated with the desired compiler id string.
   * Falls back to "default" id, then first compiler.
   */
  getCompiler(nm: string): CompilerTag {
    let defaultind: number = -1;
    for (let i = 0; i < this.compilers.length; ++i) {
      if (this.compilers[i].getId() === nm)
        return this.compilers[i];
      if (this.compilers[i].getId() === "default")
        defaultind = i;
    }
    if (defaultind !== -1)
      return this.compilers[defaultind];
    return this.compilers[0];
  }

  /** Get the number of compiler records */
  numCompilers(): number { return this.compilers.length; }

  /** Get the i-th compiler record */
  getCompilerByIndex(i: number): CompilerTag { return this.compilers[i]; }

  /** Get the number of truncation records */
  numTruncations(): number { return this.truncations.length; }

  /** Get the i-th truncation record */
  getTruncation(i: number): TruncationTag { return this.truncations[i]; }
}

// =========================================================================
// SleighArchitecture
// =========================================================================

/**
 * Read a SLEIGH .ldefs file.
 *
 * Any <language> tags are added to the LanguageDescription array.
 * @param specfile - the filename of the .ldefs file
 * @param errs - a Writer for printing error messages
 */
function loadLanguageDescription(specfile: string, errs: Writer): void {
  let content: string;
  try {
    content = fs.readFileSync(specfile, 'utf-8');
  } catch {
    return;
  }

  let decoder: Decoder;
  try {
    decoder = new XmlDecode(null);
    decoder.ingestStream(content);
  } catch (err: any) {
    errs.write("WARNING: Unable to parse sleigh specfile: " + specfile);
    return;
  }

  try {
    const elemId: number = decoder.openElementId(ELEM_LANGUAGE_DEFINITIONS);
    for (;;) {
      const subId: number = decoder.peekElement();
      if (subId === 0) break;
      if (subId === ELEM_LANGUAGE.getId()) {
        const lang = new LanguageDescription();
        lang.decode(decoder);
        description.push(lang);
      } else {
        decoder.openElement();
        decoder.closeElementSkipping(subId);
      }
    }
    decoder.closeElement(elemId);
  } catch (err: any) {
    errs.write("WARNING: Unable to parse sleigh specfile: " + specfile);
  }
}

/**
 * An Architecture that uses the decompiler's native SLEIGH translation engine.
 *
 * Any Architecture derived from this knows how to natively read in:
 *   - a compiled SLEIGH specification (.sla)
 *   - a processor specification file (.pspec), and
 *   - a compiler specification file (.cspec)
 *
 * Generally a language id (i.e. x86:LE:64:default) is provided, then this
 * object is able to automatically load in configuration and construct the
 * Translate object.
 */
export class SleighArchitecture extends Architecture {
  /** Index (within LanguageDescription array) of the active language */
  protected languageindex: number = -1;

  /** Name of active load-image file */
  protected filename: string;

  /** The language id of the active load-image */
  protected target: string;

  /** Error stream associated with this SleighArchitecture */
  protected errorstream: Writer;

  /**
   * Construct given executable file.
   * @param fname - the filename of the given executable image
   * @param targ - the optional language id or other target information
   * @param estream - a Writer for writing error messages
   */
  constructor(fname: string, targ: string, estream: Writer) {
    super();
    this.filename = fname;
    this.target = targ;
    this.errorstream = estream;
  }

  /** Get the executable filename */
  getFilename(): string { return this.filename; }

  /** Get the language id of the active processor */
  getTarget(): string { return this.target; }

  /**
   * Test if last Translate object can be reused.
   * If the current languageindex matches an entry in the translators map,
   * try to reuse the previous Sleigh object.
   */
  private isTranslateReused(): boolean {
    return translators.has(this.languageindex);
  }

  /**
   * Build a sleigh translator.
   * Creates or reuses a Sleigh from the translators map.
   */
  protected buildTranslator(store: DocumentStorage): Translate {
    const existing = translators.get(this.languageindex);
    if (existing !== undefined) {
      existing.reset(this.loader, this.context);
      return existing;
    }
    const sleigh = new Sleigh(this.loader!, this.context!);
    translators.set(this.languageindex, sleigh);
    return sleigh;
  }

  /** Build the pcode injector based on sleigh */
  protected buildPcodeInjectLibrary(): PcodeInjectLibrary {
    return new PcodeInjectLibrarySleigh(this as any);
  }

  /** Initialize the type factory */
  protected buildTypegrp(store: DocumentStorage): void {
    this.types = new TypeFactory(this as any);
  }

  /**
   * Set up core data types.
   * If a "coretypes" tag exists in the store, decode it.
   * Otherwise set up default core types.
   */
  protected buildCoreTypes(store: DocumentStorage): void {
    const el = store.getTag('coretypes');
    if (el !== null) {
      const decoder = new XmlDecode(this as any, el);
      this.types!.decodeCoreTypes(decoder);
    } else {
      this.types!.setCoreType('void', 1, 17 /* TYPE_VOID */, false);
      this.types!.setCoreType('bool', 1, 12 /* TYPE_BOOL */, false);
      this.types!.setCoreType('uint1', 1, 13 /* TYPE_UINT */, false);
      this.types!.setCoreType('uint2', 2, 13, false);
      this.types!.setCoreType('uint4', 4, 13, false);
      this.types!.setCoreType('uint8', 8, 13, false);
      this.types!.setCoreType('int1', 1, 14 /* TYPE_INT */, false);
      this.types!.setCoreType('int2', 2, 14, false);
      this.types!.setCoreType('int4', 4, 14, false);
      this.types!.setCoreType('int8', 8, 14, false);
      this.types!.setCoreType('float4', 4, 10 /* TYPE_FLOAT */, false);
      this.types!.setCoreType('float8', 8, 10, false);
      this.types!.setCoreType('float10', 10, 10, false);
      this.types!.setCoreType('float16', 16, 10, false);
      this.types!.setCoreType('xunknown1', 1, 15 /* TYPE_UNKNOWN */, false);
      this.types!.setCoreType('xunknown2', 2, 15, false);
      this.types!.setCoreType('xunknown4', 4, 15, false);
      this.types!.setCoreType('xunknown8', 8, 15, false);
      this.types!.setCoreType('code', 1, 11 /* TYPE_CODE */, false);
      this.types!.setCoreType('char', 1, 14 /* TYPE_INT */, true);
      this.types!.setCoreType('wchar2', 2, 14, true);
      this.types!.setCoreType('wchar4', 4, 14, true);
    }
    this.types!.cacheCoreTypes();
  }

  /** Set up the comment database */
  protected buildCommentDB(store: DocumentStorage): void {
    this.commentdb = new CommentDatabaseInternal();
  }

  /** Set up the string manager */
  protected buildStringManager(store: DocumentStorage): void {
    this.stringManager = new StringManagerUnicode(this as any, 2048);
  }

  /** Set up the constant pool */
  protected buildConstantPool(store: DocumentStorage): void {
    this.cpool = new ConstantPoolInternal();
  }

  /** Set up the context database */
  protected buildContext(store: DocumentStorage): void {
    this.context = new ContextInternal();
  }

  /**
   * Parse default symbols from the store.
   * Reads <default_symbols> tag from the store (set during parseProcessorConfig).
   */
  protected buildSymbols(store: DocumentStorage): void {
    const el = store.getTag('default_symbols');
    if (el === null) return;
    const decoder = new XmlDecode(this as any, el);
    const elemId = decoder.openElement();
    while (decoder.peekElement() !== 0) {
      // Each child is a symbol entry; skip for now
      const subId = decoder.openElement();
      decoder.closeElementSkipping(subId);
    }
    decoder.closeElement(elemId);
  }

  /**
   * Resolve the architecture from the archid / target.
   * Matches the archid to known language descriptions.
   */
  protected resolveArchitecture(): void {
    if (this.archid.length === 0) {
      if (this.target.length === 0 || this.target === "default") {
        if (this.loader !== null && typeof this.loader.getArchType === 'function') {
          this.archid = this.loader.getArchType();
        }
      } else {
        this.archid = this.target;
      }
    }
    if (this.archid.startsWith("binary-"))
      this.archid = this.archid.substring(7);
    else if (this.archid.startsWith("default-"))
      this.archid = this.archid.substring(8);

    this.archid = SleighArchitecture.normalizeArchitecture(this.archid);
    const lastColon = this.archid.lastIndexOf(':');
    const baseid = this.archid.substring(0, lastColon);
    this.languageindex = -1;
    for (let i = 0; i < description.length; ++i) {
      if (description[i].getId() === baseid) {
        this.languageindex = i;
        if (description[i].isDeprecated())
          this.printMessage("WARNING: Language " + baseid + " is deprecated");
        break;
      }
    }

    if (this.languageindex === -1)
      throw new LowlevelError("No sleigh specification for " + baseid);
  }

  /**
   * Build the specification files.
   * Given a specific language, make sure relevant spec files are loaded.
   * Parses .pspec, .cspec, and .sla files and registers their root tags in the store.
   */
  protected buildSpecFile(store: DocumentStorage): void {
    const languageReuse = this.isTranslateReused();
    const language = description[this.languageindex];
    const lastColon = this.archid.lastIndexOf(':');
    const compiler = this.archid.substring(lastColon + 1);
    const compilertag = language.getCompiler(compiler);

    const processorfile = specpaths.findFile(language.getProcessorSpec());
    const compilerfile = specpaths.findFile(compilertag.getSpec());
    let slafile = "";
    if (!languageReuse) {
      slafile = specpaths.findFile(language.getSlaFile());
      if (slafile.length === 0)
        throw new SleighError("Could not find .sla file for " + this.archid);
    }

    try {
      if (processorfile.length === 0)
        throw new SleighError("Could not find processor spec: " + language.getProcessorSpec());
      const doc = store.openDocument(processorfile);
      store.registerTag(doc.getRoot());
    } catch (err: any) {
      if (err instanceof SleighError) throw err;
      throw new SleighError("Error reading processor specification: " + processorfile + "\n " + (err.explain || err.message));
    }

    try {
      if (compilerfile.length === 0)
        throw new SleighError("Could not find compiler spec: " + compilertag.getSpec());
      const doc = store.openDocument(compilerfile);
      store.registerTag(doc.getRoot());
    } catch (err: any) {
      if (err instanceof SleighError) throw err;
      throw new SleighError("Error reading compiler specification: " + compilerfile + "\n " + (err.explain || err.message));
    }

    if (!languageReuse && slafile.length > 0) {
      // Wrap the sla filename in a <sleigh> tag so Sleigh::initialize() can find it
      const slaXml = "<sleigh>" + slafile + "</sleigh>";
      const doc = store.parseDocument(slaXml);
      store.registerTag(doc.getRoot());
    }
  }

  /**
   * Build the LoadImage object. Must be overridden by subclasses.
   */
  protected buildLoader(store: DocumentStorage): void {
    throw new LowlevelError("SleighArchitecture.buildLoader must be overridden");
  }

  /**
   * Apply truncation tags to the Translate object.
   */
  protected modifySpaces(trans: Translate): void {
    const language = description[this.languageindex];
    for (let i = 0; i < language.numTruncations(); ++i) {
      if (trans !== null && typeof trans.truncateSpace === 'function') {
        trans.truncateSpace(language.getTruncation(i));
      }
    }
  }

  /** Print a message to the error stream */
  printMessage(message: string): void {
    this.errorstream.write(message + "\n");
  }

  /** Destructor equivalent -- detach the translate pointer */
  dispose(): void {
    this.translate = null;
  }

  /** Get a description of this architecture */
  getDescription(): string {
    return description[this.languageindex].getDescription();
  }

  /**
   * Encode basic attributes of the active executable.
   * @param encoder - the stream encoder
   */
  encodeHeader(encoder: Encoder): void {
    encoder.writeString(ATTRIB_NAME, this.filename);
    encoder.writeString(ATTRIB_TARGET, this.target);
  }

  /**
   * Restore from basic attributes of an executable.
   * @param el - the root XML element
   */
  restoreXmlHeader(el: Element): void {
    this.filename = el.getAttributeValue("name");
    this.target = el.getAttributeValue("target");
  }

  // -----------------------------------------------------------------------
  // Static methods
  // -----------------------------------------------------------------------

  /**
   * Try to recover a language id processor field.
   * Given an architecture target string try to recover an appropriate
   * processor name for use in a normalized language id.
   */
  static normalizeProcessor(nm: string): string {
    if (nm.indexOf("386") !== -1)
      return "x86";
    return nm;
  }

  /**
   * Try to recover a language id endianness field.
   * Given an architecture target string try to recover an appropriate
   * endianness string for use in a normalized language id.
   */
  static normalizeEndian(nm: string): string {
    if (nm.indexOf("big") !== -1)
      return "BE";
    if (nm.indexOf("little") !== -1)
      return "LE";
    return nm;
  }

  /**
   * Try to recover a language id size field.
   * Given an architecture target string try to recover an appropriate
   * size string for use in a normalized language id.
   */
  static normalizeSize(nm: string): string {
    let res = nm;
    let pos = res.indexOf("bit");
    if (pos !== -1)
      res = res.substring(0, pos) + res.substring(pos + 3);
    pos = res.indexOf('-');
    if (pos !== -1)
      res = res.substring(0, pos) + res.substring(pos + 1);
    return res;
  }

  /**
   * Try to normalize the target string into a valid language id.
   * In general the target string must already look like a language id,
   * but it can drop the compiler field and be a little sloppier in its format.
   */
  static normalizeArchitecture(nm: string): string {
    const pos: number[] = [];
    let curpos = 0;
    for (let i = 0; i < 4; ++i) {
      curpos = nm.indexOf(':', curpos + 1);
      if (curpos === -1) break;
      pos.push(curpos);
    }
    if (pos.length !== 3 && pos.length !== 4)
      throw new LowlevelError("Architecture string does not look like sleigh id: " + nm);

    let processor = nm.substring(0, pos[0]);
    let endian = nm.substring(pos[0] + 1, pos[1]);
    let size = nm.substring(pos[1] + 1, pos[2]);
    let variant: string;
    let compile: string;

    if (pos.length === 4) {
      variant = nm.substring(pos[2] + 1, pos[3]);
      compile = nm.substring(pos[3] + 1);
    } else {
      variant = nm.substring(pos[2] + 1);
      compile = "default";
    }

    processor = SleighArchitecture.normalizeProcessor(processor);
    endian = SleighArchitecture.normalizeEndian(endian);
    size = SleighArchitecture.normalizeSize(size);
    return processor + ':' + endian + ':' + size + ':' + variant + ':' + compile;
  }

  /**
   * Scan directories for SLEIGH specification files.
   *
   * This assumes a standard "Ghidra/Processors/x/data/languages" layout.
   * It scans for all matching directories and prepares for reading .ldefs files.
   * @param rootpath - the root path of the Ghidra installation
   */
  static scanForSleighDirectories(rootpath: string): void {
    const ghidradir: string[] = [];
    const procdir: string[] = [];
    const procdir2: string[] = [];
    const languagesubdirs: string[] = [];

    scanDirectoryRecursiveForDir(ghidradir, "Ghidra", rootpath, 2);
    for (let i = 0; i < ghidradir.length; ++i) {
      scanDirectoryRecursiveForDir(procdir, "Processors", ghidradir[i], 1);
      scanDirectoryRecursiveForDir(procdir, "contrib", ghidradir[i], 1);
    }
    if (procdir.length !== 0) {
      for (let i = 0; i < procdir.length; ++i) {
        const entries = directoryListAll(procdir[i]);
        for (const e of entries) procdir2.push(e);
      }

      const datadirs: string[] = [];
      for (let i = 0; i < procdir2.length; ++i)
        scanDirectoryRecursiveForDir(datadirs, "data", procdir2[i], 1);

      const languagedirs: string[] = [];
      for (let i = 0; i < datadirs.length; ++i)
        scanDirectoryRecursiveForDir(languagedirs, "languages", datadirs[i], 1);

      for (let i = 0; i < languagedirs.length; ++i)
        languagesubdirs.push(languagedirs[i]);

      // In the old version we have to go down one more level to get to the ldefs
      for (let i = 0; i < languagedirs.length; ++i) {
        const entries = directoryListAll(languagedirs[i]);
        for (const e of entries) languagesubdirs.push(e);
      }
    }
    // If we haven't matched this directory structure, just use the rootpath
    // as the directory containing the ldef
    if (languagesubdirs.length === 0)
      languagesubdirs.push(rootpath);

    for (let i = 0; i < languagesubdirs.length; ++i)
      specpaths.addDir2Path(languagesubdirs[i]);
  }

  /**
   * Scan for bundled spec files shipped with this package.
   * Looks in sleigh/specfiles/ relative to the project root.
   * Each subdirectory (x86, AARCH64, ARM, ...) is added as a spec path.
   */
  static scanForBundledSpecs(): void {
    const thisFile = fileURLToPath(import.meta.url);
    const bundledRoot = path.resolve(path.dirname(thisFile), '../../sleigh/specfiles');
    if (!fs.existsSync(bundledRoot)) return;
    try {
      const entries = fs.readdirSync(bundledRoot, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory()) {
          specpaths.addDir2Path(path.join(bundledRoot, entry.name));
        }
      }
    } catch {
      // bundled specfiles not available
    }
  }

  /**
   * Gather specification files in normal locations.
   * This is run once when spinning up the decompiler.
   * Look for the root .ldefs files within the normal directories and parse them.
   * @param errs - a Writer for writing error messages
   */
  static collectSpecFiles(errs: Writer): void {
    if (description.length !== 0) return; // Have we already collected before

    const testspecs = specpaths.matchList(".ldefs", true);
    for (let i = 0; i < testspecs.length; ++i)
      loadLanguageDescription(testspecs[i], errs);
  }

  /**
   * Parse all .ldef files and return the list of all LanguageDescription objects.
   * If there are any parse errors in the .ldef files, an exception is thrown.
   */
  static getDescriptions(): LanguageDescription[] {
    const s = new StringWriter();
    SleighArchitecture.collectSpecFiles(s);
    const errStr = s.toString();
    if (errStr.length > 0)
      throw new LowlevelError(errStr);
    return description;
  }

  /**
   * Shutdown all Translate objects and free global resources.
   */
  static shutdown(): void {
    translators.clear();
    // description.length = 0; // In C++, static vector is destroyed by the normal exit handler
  }
}

// =========================================================================
// Internal helper functions for directory scanning
// =========================================================================

/**
 * Recursively scan a directory for subdirectories matching a given name.
 *
 * Unlike FileManage.scanDirectoryRecursive (which matches file names),
 * this function matches directory names -- needed by scanForSleighDirectories
 * to locate Ghidra/Processors/x/data/languages paths.
 *
 * @param res - array to push matching directory paths into
 * @param matchname - the directory name to look for
 * @param rootpath - the root directory to scan
 * @param maxdepth - maximum recursion depth
 */
function scanDirectoryRecursiveForDir(
  res: string[],
  matchname: string,
  rootpath: string,
  maxdepth: number
): void {
  if (maxdepth <= 0) return;
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(rootpath, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.name.startsWith('.')) continue;
    const full = path.join(rootpath, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === matchname) {
        res.push(full);
      } else {
        scanDirectoryRecursiveForDir(res, matchname, full, maxdepth - 1);
      }
    }
  }
}

/**
 * List all entries (files and directories) in a given directory.
 * Skips dot-files/directories.
 *
 * @param dirname - the directory to list
 * @returns array of full paths
 */
function directoryListAll(dirname: string): string[] {
  const res: string[] = [];
  try {
    const entries = fs.readdirSync(dirname);
    for (const entry of entries) {
      if (entry.startsWith('.')) continue;
      res.push(path.join(dirname, entry));
    }
  } catch {
    // Directory doesn't exist or can't be read
  }
  return res;
}
