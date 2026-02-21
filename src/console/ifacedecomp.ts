/**
 * @file ifacedecomp.ts
 * @description Console interface commands for the decompiler engine.
 *
 * Translated from Ghidra's ifacedecomp.hh / ifacedecomp.cc
 *
 * PART 1 of 2:
 *   - IfaceDecompCapability, IfaceDecompData, IfaceAssemblyEmit
 *   - IfaceDecompCommand base class with iteration helpers
 *   - First batch of command classes (IfcComment through IfcPrintRaw)
 */

import {
  IfaceCapability,
  IfaceCommand,
  IfaceData,
  IfaceStatus,
  IfaceParseError,
  IfaceExecutionError,
  InputStream,
  IfcQuit,
  IfcHistory,
  IfcOpenfile,
  IfcOpenfileAppend,
  IfcClosefile,
  IfcEcho,
} from './interface.js';

import { Writer } from '../util/writer.js';

// ---------------------------------------------------------------------------
// Forward type declarations for decompiler types not yet wired
// ---------------------------------------------------------------------------

type Architecture = any;
type Funcdata = any;
type CallGraph = any;
type CallGraphNode = any;
type Scope = any;
type Symbol = any;
type FunctionSymbol = any;
type Varnode = any;
type HighVariable = any;
type PcodeOp = any;
import { Address, SeqNum, Range } from '../core/address.js';
import { AddrSpace } from '../core/space.js';
import { OpCode } from '../core/opcodes.js';
import { ElementId } from '../core/marshal.js';
import { FuncProto } from '../decompiler/fspec.js';
import { TypePointerRel, type_metatype } from '../decompiler/type.js';
type Datatype = any;
type TypeFactory = any;
type DocumentStorage = any;
type Document = any;
type Element = any;
type Encoder = any;
type Decoder = any;
type FunctionTestCollection = any;
type ProtoModel = any;
type Action = any;
type LoadImage = any;
type AssemblyEmit = any;
type ScopeMap = any;
type MapIterator = any;
type VarnodeLocSet = any;
type ParameterPieces = any;
type TrackedSet = any;
type TrackedContext = any;
type ParamIDAnalysis = any;
type FuncCallSpecs = any;
type SymbolEntry = any;

// ---------------------------------------------------------------------------
// Forward-declared utility functions (stubs - to be wired when modules exist)
// ---------------------------------------------------------------------------

/**
 * Parse a machine address from an input stream.
 * Stub -- actual implementation lives in the grammar/type-parsing module.
 */
function parse_machaddr(s: InputStream, sizeRef: { val: number }, types: any, ignorecolon: boolean = false): Address {
  let token: string = '';
  let b: AddrSpace | null = null;
  let size: number = -1;
  let tok: string;
  const manage = types.getArch();

  s.skipWhitespace();
  tok = s.peek();

  if (tok === '[') {
    // Bracketed address: [spacename, offset] or [spacename, offset, size]
    s.getChar(); // consume '['

    // parse_toseparator: scan base address token (space name)
    token = '';
    s.skipWhitespace();
    while (true) {
      const ch = s.peek();
      if (ch === '' || ch === ',' || ch === ']' || ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') break;
      token += s.getChar();
    }

    b = manage.getSpaceByName(token);
    if (b === null) {
      throw new ParseError('Bad address base');
    }

    s.skipWhitespace();
    tok = s.getChar();
    if (tok !== ',') {
      throw new ParseError("Missing ',' in address");
    }

    // parse_toseparator: get the offset portion
    token = '';
    s.skipWhitespace();
    while (true) {
      const ch = s.peek();
      if (ch === '' || ch === ',' || ch === ']' || ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') break;
      token += s.getChar();
    }

    s.skipWhitespace();
    tok = s.getChar();
    if (tok === ',') {
      // Optional size specifier - read digits manually (don't use readToken which would consume ']')
      s.skipWhitespace();
      let sizeStr = '';
      while (s.peek() !== '' && /[0-9]/.test(s.peek())) {
        sizeStr += s.getChar();
      }
      size = parseInt(sizeStr, 10);
      s.skipWhitespace();
      tok = s.getChar();
    }
    if (tok !== ']') {
      throw new ParseError("Missing ']' in address");
    }
  } else if (tok === '{') {
    // Join space address
    b = manage.getJoinSpace();
    s.getChar(); // consume '{'
    token = '';
    tok = s.getChar();
    while (tok !== '' && tok !== '}') {
      token += tok;
      tok = s.getChar();
    }
  } else {
    // Simple (shortcut-prefixed) address or hex address starting with '0'
    if (tok === '0') {
      b = manage.getDefaultCodeSpace();
    } else {
      b = manage.getSpaceByShortcut(tok);
      s.getChar(); // consume the shortcut character
    }
    if (b === null) {
      const rest = s.readToken();
      throw new ParseError('Bad address: ' + tok + rest);
    }
    token = '';
    s.skipWhitespace();
    tok = s.peek();
    if (ignorecolon) {
      while (tok !== '' && (/[a-zA-Z0-9]/.test(tok) || tok === '_' || tok === '+')) {
        token += s.getChar();
        tok = s.peek();
      }
    } else {
      while (tok !== '' && (/[a-zA-Z0-9]/.test(tok) || tok === '_' || tok === '+' || tok === ':')) {
        token += s.getChar();
        tok = s.peek();
      }
    }
  }

  // Address::read equivalent: parse the token through the space's read method
  const overSizeRef = { val: -1 };
  let offset: bigint;
  try {
    offset = b!.read(token, overSizeRef);
  } catch (_e) {
    throw new ParseError('Bad machine address');
  }
  if (overSizeRef.val === -1) {
    throw new ParseError('Bad machine address');
  }
  sizeRef.val = (size === -1) ? overSizeRef.val : size;
  return new Address(b!, offset);
}

/**
 * Parse a C type declaration from an input stream.
 * Stub -- actual implementation lives in the grammar/type-parsing module.
 */
function parse_type(s: InputStream, nameRef: { val: string }, conf: Architecture): any {
  const text = s.readRest();
  const result = grammar_parse_type(text, conf);
  nameRef.val = result.name;
  return result.type;
}

/**
 * Parse a varnode specification from an input stream.
 * Stub -- actual implementation lives in the grammar module.
 */
function parse_varnode(
  s: InputStream,
  sizeRef: { val: number },
  pcRef: { val: any },
  uqRef: { val: number },
  types: any
): Address {
  const loc = parse_machaddr(s, sizeRef, types);
  s.skipWhitespace();
  let tok = s.getChar();
  if (tok !== '(')
    throw new ParseError("Missing '('");
  s.skipWhitespace();
  pcRef.val = new Address(); // pc starts out as invalid
  let ch = s.peek();
  if (ch === 'i') {
    s.getChar(); // consume 'i'
  } else if (ch !== ':') {
    const discardRef = { val: 0 };
    pcRef.val = parse_machaddr(s, discardRef, types, true);
  }
  s.skipWhitespace();
  if (s.peek() === ':') {
    s.getChar(); // consume ':'
    s.skipWhitespace();
    let uqTok = '';
    while (s.peek() !== '' && /[a-fA-F0-9]/.test(s.peek())) {
      uqTok += s.getChar();
    }
    uqRef.val = parseInt(uqTok, 16); // Assume uniq is in hex
  } else {
    uqRef.val = 0xFFFFFFFF; // ~0 for uint32
  }
  s.skipWhitespace();
  tok = s.getChar();
  if (tok !== ')')
    throw new ParseError("Missing ')'");
  return loc;
}

/**
 * Parse a C syntax string using the architecture's parser.
 * Stub -- actual implementation lives in the grammar module.
 */
import { parse_C as grammar_parse_C, parse_type as grammar_parse_type, parse_protopieces as grammar_parse_protopieces, ParseError, parse_toseparator } from '../decompiler/grammar.js';
import { encodeIntegerFormat } from '../decompiler/type.js';
function parse_C(conf: Architecture, input: string | InputStream): void {
  const s = typeof input === 'string' ? input : input.toString();
  grammar_parse_C(conf, s);
}

/**
 * Print raw binary data in hex dump format.
 * Stub -- actual implementation lives in a utility module.
 */
function print_data(_w: Writer, _buffer: Uint8Array, _size: number, _offset: any): void {
  throw new IfaceExecutionError('print_data not yet wired');
}

// ---------------------------------------------------------------------------
// IfaceDecompData
// ---------------------------------------------------------------------------

/**
 * Common data shared by decompiler commands.
 *
 * Holds references to the current function, architecture, call-graph, and
 * test collection that are shared across all decompiler console commands.
 */
export class IfaceDecompData extends IfaceData {
  /** Current function active in the console */
  fd: Funcdata | null = null;

  /** Current architecture/program active in the console */
  conf: Architecture | null = null;

  /** Call-graph information for the program */
  cgraph: CallGraph | null = null;

  /** Executable environment from a datatest */
  testCollection: FunctionTestCollection | null = null;

  constructor() {
    super();
  }

  /** Allocate (or re-allocate) the call-graph object. */
  allocateCallGraph(): void {
    this.cgraph = null; // Release old graph
    // In a full wiring: this.cgraph = new CallGraph(this.conf);
    // For now, leave as a no-op placeholder until CallGraph is wired.
    throw new IfaceExecutionError('CallGraph not yet wired');
  }

  /**
   * Clear references to the current function.
   *
   * Called if a command throws a low-level error.  It clears any analysis on
   * the function, sets the current function to null, and issues a warning.
   * @param w - the writer to output the warning to
   */
  abortFunction(w: Writer): void {
    if (this.fd === null) return;
    w.write('Unable to proceed with function: ' + this.fd.getName() + '\n');
    this.conf.clearAnalysis(this.fd);
    // Mirror C++ destructor: remove the function's local scope from the
    // database so the id can be reused if the function is re-analysed.
    this.fd.dispose();
    this.fd = null;
  }

  /** Free all resources for the current architecture/program. */
  clearArchitecture(): void {
    // In C++ this calls `delete conf` which cascades through the
    // Architecture destructor, tearing down the Database and all scopes.
    // We mirror that by calling dispose() on the database if available.
    if (this.conf !== null && this.conf.symboltab) {
      try {
        this.conf.symboltab.dispose();
      } catch (_e) {
        // Best-effort cleanup
      }
    }
    this.conf = null;
    this.fd = null;
  }

  /**
   * Generate raw p-code for the current function.
   *
   * Follow flow from the entry point of the function and generate the raw
   * p-code ops for all instructions, up to return instructions.  If a size
   * in bytes is provided, it bounds the memory region where flow can be
   * followed.  Otherwise, a zero size allows unbounded flow tracing.
   *
   * @param w - output writer for reporting function details or errors
   * @param size - if non-zero, the maximum number of bytes to disassemble
   */
  followFlow(w: Writer, size: number): void {
    try {
      if (size === 0) {
        const space = this.fd.getAddress().getSpace();
        const baddr = new Address(space, 0n);
        const eaddr = new Address(space, space.getHighest());
        this.fd.followFlow(baddr, eaddr);
      } else {
        const addr = this.fd.getAddress();
        this.fd.followFlow(addr, addr.add(BigInt(size)));
      }
      w.write('Function ' + this.fd.getName() + ': ');
      // addr.printRaw(w);
      w.write(this.fd.getAddress().toString());
      w.write('\n');
    } catch (err: any) {
      w.write('Function ' + this.fd.getName() + ': ' + (err.explain ?? err.message) + '\n');
    }
  }

  /**
   * Read a varnode specification from the given stream.
   *
   * The Varnode is selected from the current function.  It is specified as a
   * storage location with info about its defining p-code in parentheses.
   *
   * @param s - the input stream to read from
   * @returns the Varnode object
   */
  readVarnode(s: InputStream): Varnode {
    if (this.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }

    const sizeRef = { val: 0 };
    const pcRef = { val: null as any };
    const uqRef = { val: ~0 >>> 0 };
    const loc: Address = parse_varnode(s, sizeRef, pcRef, uqRef, this.conf.types);
    const defsize = sizeRef.val;
    const pc: Address = pcRef.val;
    const uq: number = uqRef.val;
    let vn: Varnode | null = null;

    if (loc.getSpace()!.getType() === 0 /* IPTR_CONSTANT */) {
      if (pc === null || pc.isInvalid() || uq === (~0 >>> 0)) {
        throw new IfaceParseError('Missing p-code sequence number');
      }
      const seq = new SeqNum(pc, uq);
      const op: PcodeOp = this.fd.findOp(seq);
      if (op !== null) {
        for (let i = 0; i < op.numInput(); ++i) {
          const tmpvn = op.getIn(i);
          if (tmpvn.getAddr().equals(loc)) {
            vn = tmpvn;
            break;
          }
        }
      }
    } else if ((pc === null || pc.isInvalid()) && uq === (~0 >>> 0)) {
      vn = this.fd.findVarnodeInput(defsize, loc);
    } else if (pc !== null && !pc.isInvalid() && uq !== (~0 >>> 0)) {
      vn = this.fd.findVarnodeWritten(defsize, loc, pc, uq);
    } else {
      const iter = this.fd.beginLoc(defsize, loc);
      const enditer = this.fd.endLoc(defsize, loc);
      while (iter !== enditer) {
        vn = iter.next();
        if (vn.isFree()) continue;
        if (vn.isWritten()) {
          if (pc !== null && !pc.isInvalid() && vn.getDef().getAddr().equals(pc)) break;
          if (uq !== (~0 >>> 0) && vn.getDef().getTime() === uq) break;
        }
      }
    }

    if (vn === null) {
      throw new IfaceExecutionError('Requested varnode does not exist');
    }
    return vn;
  }

  /**
   * Find symbols matching the given name in the current scope.
   *
   * Scope is either the current function scope if a function is active,
   * otherwise the global scope.
   *
   * @param name - the symbol name, either absolute or partial
   * @returns array of matching symbols
   */
  readSymbol(name: string): Symbol[] {
    const res: Symbol[] = [];
    let scope: Scope = (this.fd === null)
      ? this.conf.symboltab.getGlobalScope()
      : this.fd.getScopeLocal();
    const resolved = this.conf.symboltab.resolveScopeFromSymbolName(name, '::', scope);
    if (resolved.scope === null) {
      throw new IfaceParseError('Bad namespace for symbol: ' + name);
    }
    const found = resolved.scope.queryByName(resolved.basename);
    for (const sym of found) {
      res.push(sym);
    }
    return res;
  }
}

// ---------------------------------------------------------------------------
// IfaceAssemblyEmit
// ---------------------------------------------------------------------------

/**
 * Disassembly emitter that prints to a console stream.
 *
 * An instruction is printed to a stream simply, as an address followed by
 * the mnemonic and then column-aligned operands.
 */
export class IfaceAssemblyEmit {
  private mnemonicpad: number;
  private w: Writer;

  constructor(w: Writer, mp: number) {
    this.w = w;
    this.mnemonicpad = mp;
  }

  /** Emit a single disassembled instruction line. */
  dump(addr: Address, mnem: string, body: string): void {
    // addr.printRaw(this.w)
    this.w.write(addr.toString());
    this.w.write(': ' + mnem);
    for (let i = mnem.length; i < this.mnemonicpad; ++i) {
      this.w.write(' ');
    }
    this.w.write(body + '\n');
  }
}

// ---------------------------------------------------------------------------
// IfaceDecompCommand
// ---------------------------------------------------------------------------

/**
 * Root class for all decompiler-specific commands.
 *
 * Commands share the data object IfaceDecompData and are capable of
 * iterating over all functions in the program/architecture.
 */
export abstract class IfaceDecompCommand extends IfaceCommand {
  protected status!: IfaceStatus;
  protected dcp!: IfaceDecompData;

  setData(root: IfaceStatus, data: IfaceData | null): void {
    this.status = root;
    this.dcp = data as IfaceDecompData;
  }

  getModule(): string {
    return 'decompile';
  }

  createData(): IfaceData | null {
    return new IfaceDecompData();
  }

  /**
   * Perform the per-function aspect of this command.
   * Subclasses override this to operate on each function during iteration.
   */
  iterationCallback(_fd: Funcdata): void {
    // default: do nothing
  }

  /**
   * Iterate recursively over all functions in the given scope and its children.
   */
  protected iterateScopesRecursive(scope: Scope): void {
    if (!scope.isGlobal()) return;
    this.iterateFunctionsAddrOrderInScope(scope);
    for (const [, child] of scope.childrenBegin()) {
      this.iterateScopesRecursive(child);
    }
  }

  /**
   * Iterate over every function in the given scope, calling iterationCallback().
   */
  protected iterateFunctionsAddrOrderInScope(scope: Scope): void {
    const miter = scope.begin();
    const menditer = scope.end();
    let current = miter;
    while (current !== menditer) {
      const sym = current.getSymbol();
      current = current.next();
      // In C++ this is a dynamic_cast<FunctionSymbol*>
      if (sym !== null && typeof sym.getFunction === 'function') {
        this.iterationCallback(sym.getFunction());
      }
    }
  }

  /**
   * Iterate command over all functions in all scopes (depth-first, address order).
   */
  iterateFunctionsAddrOrder(): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No architecture loaded');
    }
    this.iterateScopesRecursive(this.dcp.conf.symboltab.getGlobalScope());
  }

  /**
   * Iterate command over all functions in a call-graph leaf-first traversal.
   *
   * Child functions are traversed before their parents.
   */
  iterateFunctionsLeafOrder(): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No architecture loaded');
    }
    if (this.dcp.cgraph === null) {
      throw new IfaceExecutionError('No callgraph present');
    }

    let node: CallGraphNode | null = this.dcp.cgraph.initLeafWalk();
    while (node !== null) {
      if (node.getName().length === 0) {
        node = this.dcp.cgraph.nextLeaf(node);
        continue; // Skip if has no name
      }
      const fd: Funcdata | null = node.getFuncdata();
      if (fd !== null) {
        this.iterationCallback(fd);
      }
      node = this.dcp.cgraph.nextLeaf(node);
    }
  }
}

// ===========================================================================
// First batch of command classes
// ===========================================================================

// ---------------------------------------------------------------------------
// IfcComment
// ---------------------------------------------------------------------------

/**
 * A comment within a command script: `% A comment in a script`
 *
 * This command does nothing but attaches to comment tokens (#, %, //)
 * allowing comment lines in a script file.
 */
export class IfcComment extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    // Do nothing
  }
}

// ---------------------------------------------------------------------------
// IfcOption
// ---------------------------------------------------------------------------

/**
 * Adjust a decompiler option: `option <optionname> [<param1>] [<param2>] [<param3>]`
 *
 * Passes command-line parameters to an ArchOption object registered with
 * the current architecture's OptionDatabase.
 */
export class IfcOption extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No load image present');
    }

    const optname = s.readToken();
    if (optname.length === 0) {
      throw new IfaceParseError('Missing option name');
    }

    let p1 = '';
    let p2 = '';
    let p3 = '';
    if (!s.eof()) {
      p1 = s.readToken();
      if (!s.eof()) {
        p2 = s.readToken();
        if (!s.eof()) {
          p3 = s.readToken();
          if (!s.eof()) {
            throw new IfaceParseError('Too many option parameters');
          }
        }
      }
    }

    try {
      const res: string = this.dcp.conf.options.set(ElementId.find(optname, 0), p1, p2, p3);
      this.status.optr.write(res + '\n');
    } catch (err: any) {
      this.status.optr.write((err.explain ?? err.message) + '\n');
      throw new IfaceParseError('Bad option');
    }
  }
}

// ---------------------------------------------------------------------------
// IfcParseFile
// ---------------------------------------------------------------------------

/**
 * Parse a file with C declarations: `parse file <filename>`
 *
 * The file must contain C syntax data-type and function declarations.
 */
export class IfcParseFile extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No load image present');
    }

    const filename = s.readToken();
    if (filename.length === 0) {
      throw new IfaceParseError('Missing filename');
    }

    let content: string;
    try {
      // In a browser/node environment, read the file
      const fs = require('fs');
      content = fs.readFileSync(filename, 'utf-8');
    } catch (_e) {
      throw new IfaceExecutionError('Unable to open file: ' + filename);
    }

    try {
      parse_C(this.dcp.conf, content);
    } catch (err: any) {
      this.status.optr.write('Error in C syntax: ' + (err.explain ?? err.message) + '\n');
      if (err.stack) this.status.optr.write(err.stack + '\n');
      throw new IfaceExecutionError('Bad C syntax');
    }
  }
}

// ---------------------------------------------------------------------------
// IfcParseLine
// ---------------------------------------------------------------------------

/**
 * Parse a line of C syntax: `parse line ...`
 *
 * The line can contain a declaration of a data-type or function prototype.
 */
export class IfcParseLine extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No load image present');
    }

    if (s.eof()) {
      throw new IfaceParseError('No input');
    }

    const rest = s.readRest();
    try {
      parse_C(this.dcp.conf, rest);
    } catch (err: any) {
      this.status.optr.write('Error in C syntax: ' + (err.explain ?? err.message) + '\n');
      if (err.stack) this.status.optr.write(err.stack + '\n');
      throw new IfaceExecutionError('Bad C syntax');
    }
  }
}

// ---------------------------------------------------------------------------
// IfcAdjustVma
// ---------------------------------------------------------------------------

/**
 * Change the base address of the load image: `adjust vma 0xabcd0123`
 *
 * The provided parameter is added to the current base address of the image.
 */
export class IfcAdjustVma extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No load image present');
    }

    const tok = s.readToken();
    if (tok.length === 0) {
      throw new IfaceParseError('No adjustment parameter');
    }
    const adjust = parseInt(tok, 0); // Let the string determine base (0x prefix etc.)
    if (adjust === 0 || isNaN(adjust)) {
      throw new IfaceParseError('No adjustment parameter');
    }
    this.dcp.conf.loader.adjustVma(adjust);
  }
}

// ---------------------------------------------------------------------------
// IfcFuncload
// ---------------------------------------------------------------------------

/**
 * Make a specific function current: `load function <functionname>`
 *
 * The name must be a fully qualified symbol with "::" separating namespaces.
 */
export class IfcFuncload extends IfaceDecompCommand {
  execute(s: InputStream): void {
    const funcname = s.readToken();

    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No image loaded');
    }

    const resolved = this.dcp.conf.symboltab.resolveScopeFromSymbolName(
      funcname, '::', null
    );
    if (resolved.scope === null) {
      throw new IfaceExecutionError('Bad namespace: ' + funcname);
    }
    this.dcp.fd = resolved.scope.queryFunction(resolved.basename);
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('Unknown function name: ' + funcname);
    }

    if (!this.dcp.fd.hasNoCode()) {
      this.dcp.followFlow(this.status.optr, 0);
    }
  }
}

// ---------------------------------------------------------------------------
// IfcAddrrangeLoad
// ---------------------------------------------------------------------------

/**
 * Create a new function at an address: `load addr <address> [<funcname>]`
 *
 * A new function is created at the provided address.  If a name is provided,
 * it becomes the function symbol; otherwise a default name is generated.
 */
export class IfcAddrrangeLoad extends IfaceDecompCommand {
  execute(s: InputStream): void {
    const sizeRef = { val: 0 };
    const offset: Address = parse_machaddr(s, sizeRef, this.dcp.conf.types);
    let size = sizeRef.val;

    if (size <= offset.getAddrSize()) {
      size = 0;
    }
    if (this.dcp.conf.loader === null) {
      throw new IfaceExecutionError('No binary loaded');
    }

    let name = s.readToken();
    if (name.length === 0) {
      const nameRef = { val: '' };
      this.dcp.conf.nameFunction(offset, nameRef);
      name = nameRef.val;
    }
    this.dcp.fd = this.dcp.conf.symboltab.getGlobalScope()
      .addFunction(offset, name).getFunction();
    this.dcp.followFlow(this.status.optr, size);
  }
}

// ---------------------------------------------------------------------------
// IfcCleararch
// ---------------------------------------------------------------------------

/**
 * Clear the current architecture/program: `clear architecture`
 */
export class IfcCleararch extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    this.dcp.clearArchitecture();
  }
}

// ---------------------------------------------------------------------------
// IfcReadSymbols
// ---------------------------------------------------------------------------

/**
 * Read in symbols from the load image: `read symbols`
 */
export class IfcReadSymbols extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No load image present');
    }
    if (this.dcp.conf.loader === null) {
      throw new IfaceExecutionError('No binary loaded');
    }
    this.dcp.conf.readLoaderSymbols('::');
  }
}

// ---------------------------------------------------------------------------
// IfcMapaddress
// ---------------------------------------------------------------------------

/**
 * Map a new symbol into the program: `map address <address> <typedeclaration>`
 *
 * Create a new variable in the current scope.
 */
export class IfcMapaddress extends IfaceDecompCommand {
  execute(s: InputStream): void {
    const sizeRef = { val: 0 };
    const addr: Address = parse_machaddr(s, sizeRef, this.dcp.conf.types);

    const nameRef = { val: '' };
    const ct: Datatype = parse_type(s, nameRef, this.dcp.conf);
    const name = nameRef.val;

    if (this.dcp.fd !== null) {
      const sym: Symbol = this.dcp.fd.getScopeLocal()
        .addSymbol(name, ct, addr, null).getSymbol();
      sym.getScope().setAttribute(sym, 0x200 | 0x100); // Varnode::namelock | Varnode::typelock
    } else {
      let flags = 0x200 | 0x100; // Varnode::namelock | Varnode::typelock
      flags |= this.dcp.conf.symboltab.getProperty(addr);
      const findResult = this.dcp.conf.symboltab.findCreateScopeFromSymbolName(
        name, '::', null
      );
      const scope: Scope = findResult.scope;
      const sym: Symbol = scope.addSymbol(findResult.basename, ct, addr, null).getSymbol();
      sym.getScope().setAttribute(sym, flags);
      if (scope.getParent() !== null) {
        const e: SymbolEntry = sym.getFirstWholeMap();
        this.dcp.conf.symboltab.addRange(
          scope, e.getAddr().getSpace(), e.getFirst(), e.getLast()
        );
      }
    }
  }
}

// ---------------------------------------------------------------------------
// IfcMaphash
// ---------------------------------------------------------------------------

/**
 * Add a dynamic symbol to the current function:
 * `map hash <address> <hash> <typedeclaration>`
 */
export class IfcMaphash extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function loaded');
    }

    const sizeRef = { val: 0 };
    const addr: Address = parse_machaddr(s, sizeRef, this.dcp.conf.types);

    const hashTok = s.readToken();
    const hash = BigInt(hashTok.startsWith('0x') ? hashTok : '0x' + hashTok);

    const nameRef = { val: '' };
    const ct: Datatype = parse_type(s, nameRef, this.dcp.conf);

    const sym: Symbol = this.dcp.fd.getScopeLocal()
      .addDynamicSymbol(nameRef.val, ct, addr, hash);
    sym.getScope().setAttribute(sym, 0x200 | 0x100); // Varnode::namelock | Varnode::typelock
  }
}

// ---------------------------------------------------------------------------
// IfcMapParam
// ---------------------------------------------------------------------------

/**
 * Map a parameter symbol for the current function:
 * `map param #i <address> <typedeclaration>`
 */
export class IfcMapParam extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function loaded');
    }

    const iTok = s.readToken();
    const i = parseInt(iTok, 10);

    const sizeRef = { val: 0 };
    const addr: Address = parse_machaddr(s, sizeRef, this.dcp.conf.types);

    const nameRef = { val: '' };
    const type: Datatype = parse_type(s, nameRef, this.dcp.conf);

    const piece: any = {
      addr: addr,
      type: type,
      flags: 16 | 8, // ParameterPieces::typelock | ParameterPieces::namelock
    };

    this.dcp.fd.getFuncProto().setParam(i, nameRef.val, piece);
  }
}

// ---------------------------------------------------------------------------
// IfcMapReturn
// ---------------------------------------------------------------------------

/**
 * Map the return storage for the current function:
 * `map return <address> <typedeclaration>`
 */
export class IfcMapReturn extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function loaded');
    }

    const sizeRef = { val: 0 };
    const addr: Address = parse_machaddr(s, sizeRef, this.dcp.conf.types);

    const nameRef = { val: '' };
    const type: Datatype = parse_type(s, nameRef, this.dcp.conf);

    const piece: any = {
      addr: addr,
      type: type,
      flags: 16, // ParameterPieces::typelock
    };

    this.dcp.fd.getFuncProto().setOutput(piece);
  }
}

// ---------------------------------------------------------------------------
// IfcMapfunction
// ---------------------------------------------------------------------------

/**
 * Create a new function: `map function <address> [<functionname>] [nocode]`
 */
export class IfcMapfunction extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.conf === null || this.dcp.conf.loader === null) {
      throw new IfaceExecutionError('No binary loaded');
    }

    const sizeRef = { val: 0 };
    const addr: Address = parse_machaddr(s, sizeRef, this.dcp.conf.types);

    let name = s.readToken();
    if (name.length === 0) {
      const nameRef = { val: '' };
      this.dcp.conf.nameFunction(addr, nameRef);
      name = nameRef.val;
    }

    const findResult = this.dcp.conf.symboltab.findCreateScopeFromSymbolName(
      name, '::', null
    );
    this.dcp.fd = findResult.scope.addFunction(addr, findResult.basename).getFunction();

    const nocode = s.readToken();
    if (nocode === 'nocode') {
      this.dcp.fd.setNoCode(true);
    }
  }
}

// ---------------------------------------------------------------------------
// IfcMapexternalref
// ---------------------------------------------------------------------------

/**
 * Create an external ref symbol: `map externalref <address> <refaddress> [<name>]`
 */
export class IfcMapexternalref extends IfaceDecompCommand {
  execute(s: InputStream): void {
    const sizeRef1 = { val: 0 };
    const addr1: Address = parse_machaddr(s, sizeRef1, this.dcp.conf.types);

    const sizeRef2 = { val: 0 };
    const addr2: Address = parse_machaddr(s, sizeRef2, this.dcp.conf.types);

    const name = s.readToken();
    this.dcp.conf.symboltab.getGlobalScope().addExternalRef(addr1, addr2, name);
  }
}

// ---------------------------------------------------------------------------
// IfcMaplabel
// ---------------------------------------------------------------------------

/**
 * Create a code label: `map label <name> <address>`
 */
export class IfcMaplabel extends IfaceDecompCommand {
  execute(s: InputStream): void {
    const name = s.readToken();
    if (name.length === 0) {
      throw new IfaceParseError('Need label name and address');
    }

    const sizeRef = { val: 0 };
    const addr: Address = parse_machaddr(s, sizeRef, this.dcp.conf.types);

    let scope: Scope;
    if (this.dcp.fd !== null) {
      scope = this.dcp.fd.getScopeLocal();
    } else {
      scope = this.dcp.conf.symboltab.getGlobalScope();
    }

    const sym: Symbol = scope.addCodeLabel(addr, name);
    scope.setAttribute(sym, 0x200 | 0x100); // Varnode::namelock | Varnode::typelock
  }
}

// ---------------------------------------------------------------------------
// IfcMapconvert
// ---------------------------------------------------------------------------

/**
 * Create a convert directive: `map convert <format> <value> <address> <hash>`
 *
 * Causes a targeted constant value to be displayed with the specified integer format.
 */
export class IfcMapconvert extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function loaded');
    }

    const formatName = s.readToken();
    let format = 0;
    if (formatName === 'hex') format = 1;       // Symbol.force_hex
    else if (formatName === 'dec') format = 2;   // Symbol.force_dec
    else if (formatName === 'oct') format = 3;   // Symbol.force_oct
    else if (formatName === 'bin') format = 4;   // Symbol.force_bin
    else if (formatName === 'char') format = 5;  // Symbol.force_char
    else throw new IfaceParseError('Bad convert format');

    const valueTok = s.readToken();
    const value = BigInt(valueTok.startsWith('0x') ? valueTok : '0x' + valueTok);

    const sizeRef = { val: 0 };
    const addr: Address = parse_machaddr(s, sizeRef, this.dcp.conf.types);

    const hashTok = s.readToken();
    const hash = BigInt(hashTok.startsWith('0x') ? hashTok : '0x' + hashTok);

    this.dcp.fd.getScopeLocal().addEquateSymbol('', format, value, addr, hash);
  }
}

// ---------------------------------------------------------------------------
// IfcMapunionfacet
// ---------------------------------------------------------------------------

/**
 * Create a union field forcing directive:
 * `map facet <union> <fieldnum> <address> <hash>`
 */
export class IfcMapunionfacet extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function loaded');
    }

    const unionName = s.readToken();
    const ct: Datatype = this.dcp.conf.types.findByName(unionName);
    if (ct === null || ct.getMetatype() !== 3 /* TYPE_UNION */) {
      throw new IfaceParseError('Bad union data-type: ' + unionName);
    }

    const fieldNumTok = s.readToken();
    const fieldNum = parseInt(fieldNumTok, 10);
    if (fieldNum < -1 || fieldNum >= ct.numDepend()) {
      throw new IfaceParseError('Bad field index');
    }

    const sizeRef = { val: 0 };
    const addr: Address = parse_machaddr(s, sizeRef, this.dcp.conf.types);

    const hashTok = s.readToken();
    const hash = BigInt(hashTok.startsWith('0x') ? hashTok : '0x' + hashTok);

    const symName = 'unionfacet' + (fieldNum + 1).toString() + '_' +
      addr.getOffset().toString(16);
    const sym: Symbol = this.dcp.fd.getScopeLocal()
      .addUnionFacetSymbol(symName, ct, fieldNum, addr, hash);
    this.dcp.fd.getScopeLocal().setAttribute(sym, 0x100 | 0x200); // Varnode::typelock | Varnode::namelock
  }
}

// ---------------------------------------------------------------------------
// IfcPrintdisasm
// ---------------------------------------------------------------------------

/**
 * Print disassembly of a memory range: `disassemble [<address1> <address2>]`
 *
 * If no addresses are provided, disassembly for the current function is displayed.
 */
export class IfcPrintdisasm extends IfaceDecompCommand {
  execute(s: InputStream): void {
    let glb: Architecture;
    let addr: Address;
    let size: number;

    if (s.eof()) {
      if (this.dcp.fd === null) {
        throw new IfaceExecutionError('No function selected');
      }
      this.status.fileoptr.write('Assembly listing for ' + this.dcp.fd.getName() + '\n');
      addr = this.dcp.fd.getAddress();
      size = this.dcp.fd.getSize();
      glb = this.dcp.fd.getArch();
    } else {
      const sizeRef1 = { val: 0 };
      addr = parse_machaddr(s, sizeRef1, this.dcp.conf.types);

      const sizeRef2 = { val: 0 };
      const offset2: Address = parse_machaddr(s, sizeRef2, this.dcp.conf.types);
      size = Number(offset2.getOffset() - addr.getOffset());
      glb = this.dcp.conf;
    }

    const assem = new IfaceAssemblyEmit(this.status.fileoptr, 10);
    while (size > 0) {
      const sz: number = glb.translate.printAssembly(assem, addr);
      addr = addr.add(BigInt(sz));
      size -= sz;
    }
  }
}

// ---------------------------------------------------------------------------
// IfcDump
// ---------------------------------------------------------------------------

/**
 * Display bytes in the load image: `dump <address+size>`
 */
export class IfcDump extends IfaceDecompCommand {
  execute(s: InputStream): void {
    const sizeRef = { val: 0 };
    const offset: Address = parse_machaddr(s, sizeRef, this.dcp.conf.types);
    const size = sizeRef.val;

    const buffer: Uint8Array = this.dcp.conf.loader.load(size, offset);
    print_data(this.status.fileoptr, buffer, size, offset);
  }
}

// ---------------------------------------------------------------------------
// IfcDumpbinary
// ---------------------------------------------------------------------------

/**
 * Dump memory to file: `binary <address+size> <filename>`
 */
export class IfcDumpbinary extends IfaceDecompCommand {
  execute(s: InputStream): void {
    const sizeRef = { val: 0 };
    const offset: Address = parse_machaddr(s, sizeRef, this.dcp.conf.types);
    const size = sizeRef.val;

    const filename = s.readToken();
    if (filename.length === 0) {
      throw new IfaceParseError('Missing file name for binary dump');
    }

    const buffer: Uint8Array = this.dcp.conf.loader.load(size, offset);

    try {
      const fs = require('fs');
      fs.writeFileSync(filename, buffer);
    } catch (_e) {
      throw new IfaceExecutionError('Unable to open file ' + filename);
    }
  }
}

// ---------------------------------------------------------------------------
// IfcDecompile
// ---------------------------------------------------------------------------

/**
 * Decompile the current function: `decompile`
 *
 * Decompilation is started for the current function.  Any previous analysis
 * is cleared first.  The process respects active break points.
 */
export class IfcDecompile extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }

    if (this.dcp.fd.hasNoCode()) {
      this.status.optr.write('No code for ' + this.dcp.fd.getName() + '\n');
      return;
    }

    if (this.dcp.fd.isProcStarted()) {
      this.status.optr.write('Clearing old decompilation\n');
      this.dcp.conf.clearAnalysis(this.dcp.fd);
    }

    this.status.optr.write('Decompiling ' + this.dcp.fd.getName() + '\n');
    this.dcp.conf.allacts.getCurrent().reset(this.dcp.fd);
    const res: number = this.dcp.conf.allacts.getCurrent().perform(this.dcp.fd);
    if (res < 0) {
      this.status.optr.write('Break at ');
      this.dcp.conf.allacts.getCurrent().printState(this.status.optr);
    } else {
      let msg = 'Decompilation complete';
      if (res === 0) {
        msg += ' (no change)';
      }
      this.status.optr.write(msg);
    }
    this.status.optr.write('\n');
  }
}

// ---------------------------------------------------------------------------
// IfcPrintCFlat
// ---------------------------------------------------------------------------

/**
 * Print current function without control-flow: `print C flat`
 */
export class IfcPrintCFlat extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }

    this.dcp.conf.print.setOutputStream(this.status.fileoptr);
    this.dcp.conf.print.setFlat(true);
    this.dcp.conf.print.docFunction(this.dcp.fd);
    this.dcp.conf.print.setFlat(false);
  }
}

// ---------------------------------------------------------------------------
// IfcPrintCGlobals
// ---------------------------------------------------------------------------

/**
 * Print declarations for any known global variables: `print C globals`
 */
export class IfcPrintCGlobals extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No load image present');
    }

    this.dcp.conf.print.setOutputStream(this.status.fileoptr);
    this.dcp.conf.print.docAllGlobals();
  }
}

// ---------------------------------------------------------------------------
// IfcPrintCTypes
// ---------------------------------------------------------------------------

/**
 * Print any known type definitions: `print C types`
 */
export class IfcPrintCTypes extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No load image present');
    }

    if (this.dcp.conf.types !== null) {
      this.dcp.conf.print.setOutputStream(this.status.fileoptr);
      this.dcp.conf.print.docTypeDefinitions(this.dcp.conf.types);
    }
  }
}

// ---------------------------------------------------------------------------
// IfcPrintCXml
// ---------------------------------------------------------------------------

/**
 * Print the current function with C syntax and XML markup: `print C xml`
 */
export class IfcPrintCXml extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }

    this.dcp.conf.print.setOutputStream(this.status.fileoptr);
    this.dcp.conf.print.setMarkup(true);
    this.dcp.conf.print.setPackedOutput(false);
    this.dcp.conf.print.docFunction(this.dcp.fd);
    this.status.fileoptr.write('\n');
    this.dcp.conf.print.setMarkup(false);
  }
}

// ---------------------------------------------------------------------------
// IfcPrintCStruct
// ---------------------------------------------------------------------------

/**
 * Print the current function using C syntax: `print C`
 */
export class IfcPrintCStruct extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }

    this.dcp.conf.print.setOutputStream(this.status.fileoptr);
    this.dcp.conf.print.docFunction(this.dcp.fd);
  }
}

// ---------------------------------------------------------------------------
// IfcPrintLanguage
// ---------------------------------------------------------------------------

/**
 * Print current output using a specific language: `print language <langname>`
 *
 * The current function must already be decompiled.
 */
export class IfcPrintLanguage extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }

    if (s.eof()) {
      throw new IfaceParseError('No print language specified');
    }
    let langroot = s.readToken();
    langroot = langroot + '-language';

    const curlangname: string = this.dcp.conf.print.getName();
    this.dcp.conf.setPrintLanguage(langroot);
    this.dcp.conf.print.setOutputStream(this.status.fileoptr);
    this.dcp.conf.print.docFunction(this.dcp.fd);
    this.dcp.conf.setPrintLanguage(curlangname); // Reset to original language
  }
}

// ---------------------------------------------------------------------------
// IfcPrintRaw
// ---------------------------------------------------------------------------

/**
 * Print the raw p-code for the current function: `print raw`
 *
 * Each p-code op is printed to the console, labeled with the address of its
 * original instruction and any output and input varnodes.
 */
export class IfcPrintRaw extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }

    this.dcp.fd.printRaw(this.status.fileoptr);
  }
}

// ---------------------------------------------------------------------------
// Graph-related commands (stubs)
// ---------------------------------------------------------------------------

/**
 * Stub: Display the data-flow graph of the current function: `graph dataflow`
 */
export class IfcGraphDataflow extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    throw new IfaceExecutionError('Graph commands not yet wired');
  }
}

/**
 * Stub: Display the control-flow graph of the current function: `graph controlflow`
 */
export class IfcGraphControlflow extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    throw new IfaceExecutionError('Graph commands not yet wired');
  }
}

/**
 * Stub: Display the dominator tree of the current function: `graph dom`
 */
export class IfcGraphDom extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    throw new IfaceExecutionError('Graph commands not yet wired');
  }
}

// ---------------------------------------------------------------------------
// CallGraph-related commands (stubs)
// ---------------------------------------------------------------------------

/**
 * Stub: Dump the call-graph: `callgraph dump`
 */
export class IfcCallGraphDump extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    throw new IfaceExecutionError('CallGraph commands not yet wired');
  }
}

/**
 * Stub: Build the call-graph: `callgraph build`
 */
export class IfcCallGraphBuild extends IfaceDecompCommand {
  protected quick: boolean = false;

  execute(_s: InputStream): void {
    throw new IfaceExecutionError('CallGraph commands not yet wired');
  }

  iterationCallback(_fd: Funcdata): void {
    // stub
  }
}

/**
 * Stub: Build the call-graph quickly: `callgraph build quick`
 */
export class IfcCallGraphBuildQuick extends IfcCallGraphBuild {
  execute(_s: InputStream): void {
    throw new IfaceExecutionError('CallGraph commands not yet wired');
  }
}

/**
 * Stub: Load a call-graph from file: `callgraph load`
 */
export class IfcCallGraphLoad extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    throw new IfaceExecutionError('CallGraph commands not yet wired');
  }
}

/**
 * Stub: List call-graph information: `callgraph list`
 */
export class IfcCallGraphList extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    throw new IfaceExecutionError('CallGraph commands not yet wired');
  }

  iterationCallback(_fd: Funcdata): void {
    // stub
  }
}

// ---------------------------------------------------------------------------
// IfcSource (placed here as declared in .hh among the first commands)
// ---------------------------------------------------------------------------

/**
 * Execute a command script: `source <filename>`
 *
 * Pushes the file onto the script stack for subsequent command processing.
 */
export class IfcSource extends IfaceDecompCommand {
  execute(s: InputStream): void {
    const filename = s.readToken();
    if (filename.length === 0) {
      throw new IfaceParseError('Filename missing');
    }
    this.status.pushScript(filename, filename + '> ');
  }
}

// ---------------------------------------------------------------------------
// IfaceDecompCapability
// ---------------------------------------------------------------------------

/**
 * Interface capability point for all decompiler commands.
 *
 * Singleton that registers all decompiler console commands with an IfaceStatus.
 */
export class IfaceDecompCapability extends IfaceCapability {
  private static instance: IfaceDecompCapability = new IfaceDecompCapability();

  private constructor() {
    super();
    this.name = 'decomp';
  }

  /** Get the singleton instance. */
  static getInstance(): IfaceDecompCapability {
    return IfaceDecompCapability.instance;
  }

  registerCommands(status: IfaceStatus): void {
    // Comment tokens
    status.registerCom(new IfcComment(), '//');
    status.registerCom(new IfcComment(), '#');
    status.registerCom(new IfcComment(), '%');

    // Base commands (from interface.ts)
    status.registerCom(new IfcQuit(), 'quit');
    status.registerCom(new IfcHistory(), 'history');
    status.registerCom(new IfcOpenfile(), 'openfile', 'write');
    status.registerCom(new IfcOpenfileAppend(), 'openfile', 'append');
    status.registerCom(new IfcClosefile(), 'closefile');
    status.registerCom(new IfcEcho(), 'echo');

    // Decompiler commands
    status.registerCom(new IfcSource(), 'source');
    status.registerCom(new IfcOption(), 'option');
    status.registerCom(new IfcParseFile(), 'parse', 'file');
    status.registerCom(new IfcParseLine(), 'parse', 'line');
    status.registerCom(new IfcAdjustVma(), 'adjust', 'vma');
    status.registerCom(new IfcFuncload(), 'load', 'function');
    status.registerCom(new IfcAddrrangeLoad(), 'load', 'addr');
    status.registerCom(new IfcReadSymbols(), 'read', 'symbols');
    status.registerCom(new IfcCleararch(), 'clear', 'architecture');
    status.registerCom(new IfcMapaddress(), 'map', 'address');
    status.registerCom(new IfcMaphash(), 'map', 'hash');
    status.registerCom(new IfcMapParam(), 'map', 'param');
    status.registerCom(new IfcMapReturn(), 'map', 'return');
    status.registerCom(new IfcMapfunction(), 'map', 'function');
    status.registerCom(new IfcMapexternalref(), 'map', 'externalref');
    status.registerCom(new IfcMaplabel(), 'map', 'label');
    status.registerCom(new IfcMapconvert(), 'map', 'convert');
    status.registerCom(new IfcMapunionfacet(), 'map', 'unionfacet');
    status.registerCom(new IfcPrintdisasm(), 'disassemble');
    status.registerCom(new IfcDecompile(), 'decompile');
    status.registerCom(new IfcDump(), 'dump');
    status.registerCom(new IfcDumpbinary(), 'binary');
    status.registerCom(new IfcPrintLanguage(), 'print', 'language');
    status.registerCom(new IfcPrintCStruct(), 'print', 'C');
    status.registerCom(new IfcPrintCFlat(), 'print', 'C', 'flat');
    status.registerCom(new IfcPrintCGlobals(), 'print', 'C', 'globals');
    status.registerCom(new IfcPrintCTypes(), 'print', 'C', 'types');
    status.registerCom(new IfcPrintCXml(), 'print', 'C', 'xml');
    status.registerCom(new IfcPrintRaw(), 'print', 'raw');

    // Graph commands (stubs)
    status.registerCom(new IfcGraphDataflow(), 'graph', 'dataflow');
    status.registerCom(new IfcGraphControlflow(), 'graph', 'controlflow');
    status.registerCom(new IfcGraphDom(), 'graph', 'dom');

    // CallGraph commands (stubs)
    status.registerCom(new IfcCallGraphBuild(), 'callgraph', 'build');
    status.registerCom(new IfcCallGraphBuildQuick(), 'callgraph', 'build', 'quick');
    status.registerCom(new IfcCallGraphDump(), 'callgraph', 'dump');
    status.registerCom(new IfcCallGraphLoad(), 'callgraph', 'load');
    status.registerCom(new IfcCallGraphList(), 'callgraph', 'list');

    // Part 2 commands
    status.registerCom(new IfcForcegoto(), 'force', 'goto');
    status.registerCom(new IfcForceFormat(), 'force', 'varnode');
    status.registerCom(new IfcForceDatatypeFormat(), 'force', 'datatype');
    status.registerCom(new IfcProtooverride(), 'override', 'prototype');
    status.registerCom(new IfcJumpOverride(), 'override', 'jumptable');
    status.registerCom(new IfcFlowOverride(), 'override', 'flow');
    status.registerCom(new IfcDeadcodedelay(), 'deadcode', 'delay');
    status.registerCom(new IfcGlobalAdd(), 'global', 'add');
    status.registerCom(new IfcGlobalRemove(), 'global', 'remove');
    status.registerCom(new IfcGlobalify(), 'global', 'spaces');
    status.registerCom(new IfcGlobalRegisters(), 'global', 'registers');
    status.registerCom(new IfcPrintParamMeasures(), 'print', 'parammeasures');
    status.registerCom(new IfcProduceC(), 'produce', 'C');
    status.registerCom(new IfcProducePrototypes(), 'produce', 'prototypes');
    status.registerCom(new IfcPrintInputs(), 'print', 'inputs');
    status.registerCom(new IfcPrintInputsAll(), 'print', 'inputs', 'all');
    status.registerCom(new IfcListaction(), 'list', 'action');
    status.registerCom(new IfcListOverride(), 'list', 'override');
    status.registerCom(new IfcListprototypes(), 'list', 'prototypes');
    status.registerCom(new IfcSetcontextrange(), 'set', 'context');
    status.registerCom(new IfcSettrackedrange(), 'set', 'track');
    status.registerCom(new IfcBreakstart(), 'break', 'start');
    status.registerCom(new IfcBreakaction(), 'break', 'action');
    status.registerCom(new IfcPrintSpaces(), 'print', 'spaces');
    status.registerCom(new IfcPrintHigh(), 'print', 'high');
    status.registerCom(new IfcPrintTree(), 'print', 'tree', 'varnode');
    status.registerCom(new IfcPrintBlocktree(), 'print', 'tree', 'block');
    status.registerCom(new IfcPrintLocalrange(), 'print', 'localrange');
    status.registerCom(new IfcPrintMap(), 'print', 'map');
    status.registerCom(new IfcPrintVarnode(), 'print', 'varnode');
    status.registerCom(new IfcPrintCover(), 'print', 'cover', 'high');
    status.registerCom(new IfcVarnodeCover(), 'print', 'cover', 'varnode');
    status.registerCom(new IfcVarnodehighCover(), 'print', 'cover', 'varnodehigh');
    status.registerCom(new IfcPrintExtrapop(), 'print', 'extrapop');
    status.registerCom(new IfcPrintActionstats(), 'print', 'actionstats');
    status.registerCom(new IfcResetActionstats(), 'reset', 'actionstats');
    status.registerCom(new IfcCountPcode(), 'count', 'pcode');
    status.registerCom(new IfcTypeVarnode(), 'type', 'varnode');
    status.registerCom(new IfcNameVarnode(), 'name', 'varnode');
    status.registerCom(new IfcRename(), 'rename');
    status.registerCom(new IfcRetype(), 'retype');
    status.registerCom(new IfcRemove(), 'remove');
    status.registerCom(new IfcIsolate(), 'isolate');
    status.registerCom(new IfcLockPrototype(), 'prototype', 'lock');
    status.registerCom(new IfcUnlockPrototype(), 'prototype', 'unlock');
    status.registerCom(new IfcCommentInstr(), 'comment', 'instruction');
    status.registerCom(new IfcDuplicateHash(), 'duplicate', 'hash');
    status.registerCom(new IfcCallFixup(), 'fixup', 'call');
    status.registerCom(new IfcCallOtherFixup(), 'fixup', 'callother');
    status.registerCom(new IfcFixupApply(), 'fixup', 'apply');
    status.registerCom(new IfcVolatile(), 'volatile');
    status.registerCom(new IfcReadonly(), 'readonly');
    status.registerCom(new IfcPointerSetting(), 'pointer', 'setting');
    status.registerCom(new IfcPreferSplit(), 'prefersplit');
    status.registerCom(new IfcStructureBlocks(), 'structure', 'blocks');
    status.registerCom(new IfcAnalyzeRange(), 'analyze', 'range');
    status.registerCom(new IfcLoadTestFile(), 'load', 'test', 'file');
    status.registerCom(new IfcListTestCommands(), 'list', 'test', 'commands');
    status.registerCom(new IfcExecuteTestCommand(), 'execute', 'test', 'command');
    status.registerCom(new IfcContinue(), 'continue');
  }
}

// ===========================================================================
// PART 2: Remaining command classes
// ===========================================================================

// ---------------------------------------------------------------------------
// IfcListaction
// ---------------------------------------------------------------------------

/**
 * List all current actions and rules for the decompiler: `list action`
 */
export class IfcListaction extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('Decompile action not loaded');
    }
    this.dcp.conf.allacts.getCurrent().print(this.status.fileoptr, 0, 0);
  }
}

// ---------------------------------------------------------------------------
// IfcListOverride
// ---------------------------------------------------------------------------

/**
 * Display any overrides for the current function: `list override`
 *
 * Overrides include:
 *   - Forced gotos
 *   - Dead code delays
 *   - Indirect call overrides
 *   - Indirect prototype overrides
 */
export class IfcListOverride extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }
    this.status.optr.write('Function: ' + this.dcp.fd.getName() + '\n');
    this.dcp.fd.getOverride().printRaw(this.status.optr, this.dcp.conf);
  }
}

// ---------------------------------------------------------------------------
// IfcListprototypes
// ---------------------------------------------------------------------------

/**
 * List known prototype models: `list prototypes`
 *
 * All prototype models are listed with markup indicating the
 * default, the evaluation model for the active function, and
 * the evaluation model for called functions.
 */
export class IfcListprototypes extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No load image present');
    }

    const models: Map<string, any> = this.dcp.conf.protoModels;
    for (const [, model] of models) {
      this.status.optr.write(model.getName());
      if (model === this.dcp.conf.defaultfp) {
        this.status.optr.write(' default');
      } else if (model === this.dcp.conf.evalfp_called) {
        this.status.optr.write(' eval called');
      } else if (model === this.dcp.conf.evalfp_current) {
        this.status.optr.write(' eval current');
      }
      this.status.optr.write('\n');
    }
  }
}

// ---------------------------------------------------------------------------
// IfcSetcontextrange
// ---------------------------------------------------------------------------

/**
 * Set a context variable: `set context <name> <value> [<startaddress> <endaddress>]`
 *
 * The named context variable is set to the provided value.
 * If a start and end address is provided, the context variable is set over this range,
 * otherwise the value is set as a default.
 */
export class IfcSetcontextrange extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No load image present');
    }

    const name = s.readToken();
    if (name.length === 0) {
      throw new IfaceParseError('Missing context variable name');
    }

    const valueTok = s.readToken();
    if (valueTok.length === 0) {
      throw new IfaceParseError('Missing context value');
    }
    const value = parseInt(valueTok, 0);

    if (s.eof()) {
      // No range indicates default value
      this.dcp.conf.context.setVariableDefault(name, value);
      return;
    }

    // Otherwise parse the range
    const sizeRef1 = { val: 0 };
    const addr1: Address = parse_machaddr(s, sizeRef1, this.dcp.conf.types);
    const sizeRef2 = { val: 0 };
    const addr2: Address = parse_machaddr(s, sizeRef2, this.dcp.conf.types);

    if (addr1.isInvalid() || addr2.isInvalid()) {
      throw new IfaceParseError('Invalid address range');
    }
    if (addr2 <= addr1) {
      throw new IfaceParseError('Bad address range');
    }

    this.dcp.conf.context.setVariableRegion(name, addr1, addr2, value);
  }
}

// ---------------------------------------------------------------------------
// IfcSettrackedrange
// ---------------------------------------------------------------------------

/**
 * Set the value of a register: `set track <name> <value> [<startaddress> <endaddress>]`
 *
 * The value for the register is picked up by the decompiler for functions in the tracked range.
 * The register is specified by name.  A specific range can be provided, otherwise the value is
 * treated as a default.
 */
export class IfcSettrackedrange extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No load image present');
    }

    const name = s.readToken();
    if (name.length === 0) {
      throw new IfaceParseError('Missing tracked register name');
    }

    const valueTok = s.readToken();
    if (valueTok.length === 0) {
      throw new IfaceParseError('Missing context value');
    }
    const value = BigInt(valueTok.startsWith('0x') ? valueTok : parseInt(valueTok, 0).toString());

    if (s.eof()) {
      // No range indicates default value
      const track: any[] = this.dcp.conf.context.getTrackedDefault();
      track.push({ loc: this.dcp.conf.translate.getRegister(name), val: value });
      return;
    }

    const sizeRef1 = { val: 0 };
    const addr1: Address = parse_machaddr(s, sizeRef1, this.dcp.conf.types);
    const sizeRef2 = { val: 0 };
    const addr2: Address = parse_machaddr(s, sizeRef2, this.dcp.conf.types);

    if (addr1.isInvalid() || addr2.isInvalid()) {
      throw new IfaceParseError('Invalid address range');
    }
    if (addr2 <= addr1) {
      throw new IfaceParseError('Bad address range');
    }

    const track: any[] = this.dcp.conf.context.createSet(addr1, addr2);
    const def: any[] = this.dcp.conf.context.getTrackedDefault();
    // Start with default as base (copy entries)
    for (const entry of def) {
      track.push(entry);
    }
    track.push({ loc: this.dcp.conf.translate.getRegister(name), val: value });
  }
}

// ---------------------------------------------------------------------------
// IfcBreakaction
// ---------------------------------------------------------------------------

/**
 * Set a breakpoint when a Rule or Action executes: `break action <actionname>`
 *
 * The break point can be on either an Action or Rule.  The name can specify
 * partial path information to distinguish the Action/Rule.  The breakpoint causes
 * the decompilation process to stop and return control to the console immediately
 * after the Action or Rule has executed, but only if there was an active transformation
 * to the function.
 */
export class IfcBreakaction extends IfaceDecompCommand {
  execute(s: InputStream): void {
    const specify = s.readToken();
    if (specify.length === 0) {
      throw new IfaceExecutionError('No action/rule specified');
    }

    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('Decompile action not loaded');
    }

    // Action.break_action
    const res: boolean = this.dcp.conf.allacts.getCurrent().setBreakPoint(0x04, specify);
    if (!res) {
      throw new IfaceExecutionError('Bad action/rule specifier: ' + specify);
    }
  }
}

// ---------------------------------------------------------------------------
// IfcBreakstart
// ---------------------------------------------------------------------------

/**
 * Set a break point at the start of an Action: `break start <actionname>`
 *
 * The break point can be on either an Action or a Rule.  The name can specify
 * partial path information to distinguish the Action/Rule.  The breakpoint causes
 * the decompilation process to stop and return control to the console just before
 * the Action/Rule would have executed.
 */
export class IfcBreakstart extends IfaceDecompCommand {
  execute(s: InputStream): void {
    const specify = s.readToken();
    if (specify.length === 0) {
      throw new IfaceExecutionError('No action/rule specified');
    }

    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('Decompile action not loaded');
    }

    // Action.break_start
    const res: boolean = this.dcp.conf.allacts.getCurrent().setBreakPoint(0x08, specify);
    if (!res) {
      throw new IfaceExecutionError('Bad action/rule specifier: ' + specify);
    }
  }
}

// ---------------------------------------------------------------------------
// IfcPrintTree
// ---------------------------------------------------------------------------

/**
 * Print all Varnodes in the current function: `print tree varnode`
 *
 * Information about every Varnode in the data-flow graph for the function is displayed.
 */
export class IfcPrintTree extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }
    this.dcp.fd.printVarnodeTree(this.status.fileoptr);
  }
}

// ---------------------------------------------------------------------------
// IfcPrintBlocktree
// ---------------------------------------------------------------------------

/**
 * Print a description of the current function's control-flow: `print tree block`
 *
 * The recovered control-flow structure is displayed as a hierarchical list of blocks,
 * showing the nesting and code ranges covered by the blocks.
 */
export class IfcPrintBlocktree extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }
    this.dcp.fd.printBlockTree(this.status.fileoptr);
  }
}

// ---------------------------------------------------------------------------
// IfcPrintSpaces
// ---------------------------------------------------------------------------

/**
 * Print all address spaces: `print spaces`
 *
 * Information about every address space in the architecture/program is written
 * to the console.
 */
export class IfcPrintSpaces extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No load image present');
    }

    const manage = this.dcp.conf;
    const num: number = manage.numSpaces();
    for (let i = 0; i < num; ++i) {
      const spc: AddrSpace = manage.getSpace(i);
      if (spc === null) continue;
      let line = spc.getIndex().toString() + " : '" + spc.getShortcut() + "' " + spc.getName();
      const type = spc.getType();
      if (type === 0 /* IPTR_CONSTANT */) {
        line += ' constant ';
      } else if (type === 1 /* IPTR_PROCESSOR */) {
        line += ' processor';
      } else if (type === 2 /* IPTR_SPACEBASE */) {
        line += ' spacebase';
      } else if (type === 3 /* IPTR_INTERNAL */) {
        line += ' internal ';
      } else {
        line += ' special  ';
      }
      if (spc.isBigEndian()) {
        line += ' big  ';
      } else {
        line += ' small';
      }
      line += ' addrsize=' + spc.getAddrSize() + ' wordsize=' + spc.getWordSize();
      line += ' delay=' + spc.getDelay();
      this.status.fileoptr.write(line + '\n');
    }
  }
}

// ---------------------------------------------------------------------------
// IfcPrintHigh
// ---------------------------------------------------------------------------

/**
 * Display all Varnodes in a HighVariable: `print high <name>`
 *
 * A HighVariable associated with the current function is specified by name.
 * Information about every Varnode merged into the variable is displayed.
 */
export class IfcPrintHigh extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }

    const varname = s.readToken();
    if (varname.length === 0) {
      throw new IfaceParseError('Missing variable name');
    }

    const high: HighVariable = this.dcp.fd.findHigh(varname);
    if (high === null) {
      throw new IfaceExecutionError('Unknown variable name: ' + varname);
    }
    high.printInfo(this.status.optr);
  }
}

// ---------------------------------------------------------------------------
// IfcPrintParamMeasures
// ---------------------------------------------------------------------------

/**
 * Perform parameter-id analysis on the current function: `print parammeasures`
 */
export class IfcPrintParamMeasures extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }

    const pidanalysis: ParamIDAnalysis = new (Function.prototype.bind.call(
      Object, null
    ))();
    // In full wiring: pidanalysis = new ParamIDAnalysis(this.dcp.fd, false);
    // For now, delegate to the architecture's param analysis
    throw new IfaceExecutionError('ParamIDAnalysis not yet wired');
  }
}

// ---------------------------------------------------------------------------
// IfcRename
// ---------------------------------------------------------------------------

/**
 * Rename a variable: `rename <oldname> <newname>`
 *
 * Change the name of a symbol.  The provided name is searched for starting
 * in the scope of the current function.
 */
export class IfcRename extends IfaceDecompCommand {
  execute(s: InputStream): void {
    const oldname = s.readToken();
    if (oldname.length === 0) {
      throw new IfaceParseError('Missing old symbol name');
    }
    const newname = s.readToken();
    if (newname.length === 0) {
      throw new IfaceParseError('Missing new name');
    }

    const symList: Symbol[] = this.dcp.readSymbol(oldname);
    if (symList.length === 0) {
      throw new IfaceExecutionError('No symbol named: ' + oldname);
    }
    if (symList.length > 1) {
      throw new IfaceExecutionError('More than one symbol named: ' + oldname);
    }
    const sym: Symbol = symList[0];

    // Symbol::function_parameter
    if (sym.getCategory() === 0) {
      this.dcp.fd.getFuncProto().setInputLock(true);
    }
    sym.getScope().renameSymbol(sym, newname);
    sym.getScope().setAttribute(sym, 0x200 | 0x100); // Varnode::namelock | Varnode::typelock
  }
}

// ---------------------------------------------------------------------------
// IfcRetype
// ---------------------------------------------------------------------------

/**
 * Change the data-type of a symbol: `retype <symbolname> <typedeclaration>`
 *
 * The symbol is searched for by name starting in the current function's scope.
 * If the type declaration includes a new name for the variable, the
 * variable is renamed as well.
 */
export class IfcRetype extends IfaceDecompCommand {
  execute(s: InputStream): void {
    const name = s.readToken();
    if (name.length === 0) {
      throw new IfaceParseError('Must specify name of symbol');
    }

    const newNameRef = { val: '' };
    const ct: Datatype = parse_type(s, newNameRef, this.dcp.conf);

    const symList: Symbol[] = this.dcp.readSymbol(name);
    if (symList.length === 0) {
      throw new IfaceExecutionError('No symbol named: ' + name);
    }
    if (symList.length > 1) {
      throw new IfaceExecutionError('More than one symbol named : ' + name);
    }
    const sym: Symbol = symList[0];

    // Symbol::function_parameter
    if (sym.getCategory() === 0) {
      this.dcp.fd.getFuncProto().setInputLock(true);
    }
    sym.getScope().retypeSymbol(sym, ct);
    sym.getScope().setAttribute(sym, 0x100); // Varnode::typelock
    if (newNameRef.val.length !== 0 && newNameRef.val !== name) {
      sym.getScope().renameSymbol(sym, newNameRef.val);
      sym.getScope().setAttribute(sym, 0x200); // Varnode::namelock
    }
  }
}

// ---------------------------------------------------------------------------
// IfcRemove
// ---------------------------------------------------------------------------

/**
 * Remove a symbol by name: `remove <symbolname>`
 *
 * The symbol is searched for starting in the current function's scope.
 * The resulting symbol is removed completely from the symbol table.
 */
export class IfcRemove extends IfaceDecompCommand {
  execute(s: InputStream): void {
    const name = s.readToken();
    if (name.length === 0) {
      throw new IfaceParseError('Missing symbol name');
    }

    const symList: Symbol[] = this.dcp.readSymbol(name);
    if (symList.length === 0) {
      throw new IfaceExecutionError('No symbol named: ' + name);
    }
    if (symList.length > 1) {
      throw new IfaceExecutionError('More than one symbol named: ' + name);
    }
    symList[0].getScope().removeSymbol(symList[0]);
  }
}

// ---------------------------------------------------------------------------
// IfcIsolate
// ---------------------------------------------------------------------------

/**
 * Mark a symbol as isolated from speculative merging: `isolate <name>`
 */
export class IfcIsolate extends IfaceDecompCommand {
  execute(s: InputStream): void {
    const symbolName = s.readToken();
    if (symbolName.length === 0) {
      throw new IfaceParseError('Missing symbol name');
    }

    const symList: Symbol[] = this.dcp.readSymbol(symbolName);
    if (symList.length === 0) {
      throw new IfaceExecutionError('No symbol named: ' + symbolName);
    }
    if (symList.length > 1) {
      throw new IfaceExecutionError('More than one symbol named: ' + symbolName);
    }
    symList[0].setIsolated(true);
  }
}

// ---------------------------------------------------------------------------
// IfcPrintVarnode
// ---------------------------------------------------------------------------

/**
 * Print information about a Varnode: `print varnode <varnode>`
 *
 * Attributes of the indicated Varnode from the current function are printed
 * to the console.  If the Varnode belongs to a HighVariable, information about
 * it and all its Varnodes are printed as well.
 */
export class IfcPrintVarnode extends IfaceDecompCommand {
  execute(s: InputStream): void {
    const vn: Varnode = this.dcp.readVarnode(s);
    if (vn.isAnnotation() || !this.dcp.fd.isHighOn()) {
      vn.printInfo(this.status.optr);
    } else {
      vn.getHigh().printInfo(this.status.optr);
    }
  }
}

// ---------------------------------------------------------------------------
// IfcPrintCover
// ---------------------------------------------------------------------------

/**
 * Print cover info about a HighVariable: `print cover high <name>`
 *
 * A HighVariable is specified by its symbol name in the current function's scope.
 * Information about the code ranges where the HighVariable is in scope is printed.
 */
export class IfcPrintCover extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }

    const name = s.readToken();
    if (name.length === 0) {
      throw new IfaceParseError('Missing variable name');
    }
    const high: HighVariable = this.dcp.fd.findHigh(name);
    if (high === null) {
      throw new IfaceExecutionError('Unable to find variable: ' + name);
    }
    high.printCover(this.status.optr);
  }
}

// ---------------------------------------------------------------------------
// IfcVarnodehighCover
// ---------------------------------------------------------------------------

/**
 * Print cover info about a HighVariable: `print cover varnodehigh <varnode>`
 *
 * The HighVariable is selected by specifying one of its Varnodes.
 * Information about the code ranges where the HighVariable is in scope is printed.
 */
export class IfcVarnodehighCover extends IfaceDecompCommand {
  execute(s: InputStream): void {
    const vn: Varnode = this.dcp.readVarnode(s);
    if (vn === null) {
      throw new IfaceParseError('Unknown varnode');
    }
    if (vn.getHigh() !== null) {
      vn.getHigh().printCover(this.status.optr);
    } else {
      this.status.optr.write('Unmerged\n');
    }
  }
}

// ---------------------------------------------------------------------------
// IfcPrintExtrapop
// ---------------------------------------------------------------------------

/**
 * Print change to stack pointer for called function: `print extrapop [<functionname>]`
 *
 * For the selected function, the extra amount each called function changes the stack pointer
 * (over popping the return value) is printed to console.
 */
export class IfcPrintExtrapop extends IfaceDecompCommand {
  execute(s: InputStream): void {
    const name = s.readToken();

    if (name.length === 0) {
      if (this.dcp.fd !== null) {
        const num: number = this.dcp.fd.numCalls();
        for (let i = 0; i < num; ++i) {
          const fc: FuncCallSpecs = this.dcp.fd.getCallSpecs_byIndex(i);
          let line = 'ExtraPop for ' + fc.getName() + '(' + fc.getOp().getAddr().toString() + ') ';
          const expop: number = fc.getEffectiveExtraPop();
          if (expop === 0x7fffffff) { // ProtoModel::extrapop_unknown
            line += 'unknown';
          } else {
            line += expop.toString();
          }
          line += '(';
          const expop2: number = fc.getExtraPop();
          if (expop2 === 0x7fffffff) {
            line += 'unknown';
          } else {
            line += expop2.toString();
          }
          line += ')';
          this.status.optr.write(line + '\n');
        }
      } else {
        const expop: number = this.dcp.conf.defaultfp.getExtraPop();
        let line = 'Default extra pop = ';
        if (expop === 0x7fffffff) {
          line += 'unknown';
        } else {
          line += expop.toString();
        }
        this.status.optr.write(line + '\n');
      }
    } else {
      const fd: Funcdata = this.dcp.conf.symboltab.getGlobalScope().queryFunction(name);
      if (fd === null) {
        throw new IfaceExecutionError('Unknown function: ' + name);
      }
      const expop: number = fd.getFuncProto().getExtraPop();
      let line = 'ExtraPop for function ' + name + ' is ';
      if (expop === 0x7fffffff) {
        line += 'unknown';
      } else {
        line += expop.toString();
      }
      this.status.optr.write(line + '\n');

      if (this.dcp.fd !== null) {
        const num: number = this.dcp.fd.numCalls();
        for (let i = 0; i < num; ++i) {
          const fc: FuncCallSpecs = this.dcp.fd.getCallSpecs_byIndex(i);
          if (fc.getName() === fd.getName()) {
            const ep: number = fc.getEffectiveExtraPop();
            let msg = 'For this function, extrapop = ';
            if (ep === 0x7fffffff) {
              msg += 'unknown';
            } else {
              msg += ep.toString();
            }
            msg += '(';
            const ep2: number = fc.getExtraPop();
            if (ep2 === 0x7fffffff) {
              msg += 'unknown';
            } else {
              msg += ep2.toString();
            }
            msg += ')';
            this.status.optr.write(msg + '\n');
          }
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// IfcVarnodeCover
// ---------------------------------------------------------------------------

/**
 * Print cover information about a Varnode: `print cover varnode <varnode>`
 *
 * Information about code ranges where the single Varnode is in scope are printed.
 */
export class IfcVarnodeCover extends IfaceDecompCommand {
  execute(s: InputStream): void {
    const vn: Varnode = this.dcp.readVarnode(s);
    if (vn === null) {
      throw new IfaceParseError('Unknown varnode');
    }
    vn.printCover(this.status.optr);
  }
}

// ---------------------------------------------------------------------------
// IfcNameVarnode
// ---------------------------------------------------------------------------

/**
 * Attach a named symbol to a specific Varnode: `name varnode <varnode> <name>`
 *
 * A new local symbol is created for the current function, and
 * is attached to the specified Varnode. The current function must be decompiled
 * again to see the effects.  The new symbol is name-locked with the specified
 * name, but the data-type of the symbol is allowed to float.
 */
export class IfcNameVarnode extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }

    const sizeRef = { val: 0 };
    const pcRef = { val: null as any };
    const uqRef = { val: ~0 >>> 0 };
    const loc: Address = parse_varnode(s, sizeRef, pcRef, uqRef, this.dcp.conf.types);
    const size = sizeRef.val;
    const pc: Address = pcRef.val;

    const token = s.readToken();
    if (token.length === 0) {
      throw new IfaceParseError('Must specify name');
    }

    // TYPE_UNKNOWN = 15 in Ghidra
    const ct: Datatype = this.dcp.conf.types.getBase(size, 15);

    this.dcp.conf.clearAnalysis(this.dcp.fd); // Make sure varnodes are cleared

    let scope: Scope = this.dcp.fd.getScopeLocal().discoverScope(loc, size, pc);
    if (scope === null) {
      scope = this.dcp.fd.getScopeLocal();
    }
    const sym: Symbol = scope.addSymbol(token, ct, loc, pc).getSymbol();
    scope.setAttribute(sym, 0x200); // Varnode::namelock

    this.status.fileoptr.write('Successfully added ' + token);
    this.status.fileoptr.write(' to scope ' + scope.getFullName() + '\n');
  }
}

// ---------------------------------------------------------------------------
// IfcTypeVarnode
// ---------------------------------------------------------------------------

/**
 * Attach a typed symbol to a specific Varnode: `type varnode <varnode> <typedeclaration>`
 *
 * A new local symbol is created for the current function, and
 * is attached to the specified Varnode. The current function must be decompiled
 * again to see the effects.
 */
export class IfcTypeVarnode extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }

    const sizeRef = { val: 0 };
    const pcRef = { val: null as any };
    const uqRef = { val: ~0 >>> 0 };
    const loc: Address = parse_varnode(s, sizeRef, pcRef, uqRef, this.dcp.conf.types);
    const size = sizeRef.val;
    const pc: Address = pcRef.val;

    const nameRef = { val: '' };
    const ct: Datatype = parse_type(s, nameRef, this.dcp.conf);

    this.dcp.conf.clearAnalysis(this.dcp.fd); // Make sure varnodes are cleared

    let scope: Scope = this.dcp.fd.getScopeLocal().discoverScope(loc, size, pc);
    if (scope === null) {
      scope = this.dcp.fd.getScopeLocal();
    }
    const sym: Symbol = scope.addSymbol(nameRef.val, ct, loc, pc).getSymbol();
    scope.setAttribute(sym, 0x100); // Varnode::typelock
    sym.setIsolated(true);
    if (nameRef.val.length > 0) {
      scope.setAttribute(sym, 0x200); // Varnode::namelock
    }

    this.status.fileoptr.write('Successfully added ' + sym.getName());
    this.status.fileoptr.write(' to scope ' + scope.getFullName() + '\n');
  }
}

// ---------------------------------------------------------------------------
// IfcForceFormat
// ---------------------------------------------------------------------------

/**
 * Mark a constant to be printed in a specific format: `force varnode <varnode> [hex|dec|oct|bin|char]`
 *
 * A constant Varnode in the current function is marked so that it is forced
 * to print in one of the formats: hex, dec, oct, bin, char.
 */
export class IfcForceFormat extends IfaceDecompCommand {
  execute(s: InputStream): void {
    const vn: Varnode = this.dcp.readVarnode(s);
    if (!vn.isConstant()) {
      throw new IfaceExecutionError('Can only force format on a constant');
    }
    const mt = vn.getType().getMetatype();
    if (mt !== type_metatype.TYPE_INT && mt !== type_metatype.TYPE_UINT && mt !== type_metatype.TYPE_UNKNOWN) {
      throw new IfaceExecutionError('Can only force format on integer type constant');
    }
    this.dcp.fd.buildDynamicSymbol(vn);
    const sym: Symbol = vn.getHigh().getSymbol();
    if (sym === null) {
      throw new IfaceExecutionError('Unable to create symbol');
    }
    const formatString = s.readToken();
    const format: number = encodeIntegerFormat(formatString);
    sym.getScope().setDisplayFormat(sym, format);
    sym.getScope().setAttribute(sym, 0x100); // Varnode::typelock
    this.status.optr.write('Successfully forced format display\n');
  }
}

// ---------------------------------------------------------------------------
// IfcForceDatatypeFormat
// ---------------------------------------------------------------------------

/**
 * Mark constants of a data-type to be printed in a specific format:
 * `force datatype <datatype> [hex|dec|oct|bin|char]`
 *
 * A display format attribute is set on the indicated data-type.
 */
export class IfcForceDatatypeFormat extends IfaceDecompCommand {
  execute(s: InputStream): void {
    const typeName = s.readToken();
    if (typeName.length === 0) {
      throw new IfaceParseError('Missing data-type name');
    }

    const dt: Datatype = this.dcp.conf.types.findByName(typeName);
    if (dt === null) {
      throw new IfaceExecutionError('Unknown data-type: ' + typeName);
    }

    const formatString = s.readToken();
    const format: number = encodeIntegerFormat(formatString);
    this.dcp.conf.types.setDisplayFormat(dt, format);
    this.status.optr.write('Successfully forced data-type display\n');
  }
}

// ---------------------------------------------------------------------------
// IfcForcegoto
// ---------------------------------------------------------------------------

/**
 * Force a branch to be an unstructured goto: `force goto <branchaddr> <targetaddr>`
 *
 * Create an override that forces the decompiler to treat the specified branch
 * as unstructured. The branch will be modeled as a goto statement.
 */
export class IfcForcegoto extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }

    const sizeRef1 = { val: 0 };
    const target: Address = parse_machaddr(s, sizeRef1, this.dcp.conf.types);
    const sizeRef2 = { val: 0 };
    const dest: Address = parse_machaddr(s, sizeRef2, this.dcp.conf.types);
    this.dcp.fd.getOverride().insertForceGoto(target, dest);
  }
}

// ---------------------------------------------------------------------------
// IfcProtooverride
// ---------------------------------------------------------------------------

/**
 * Override the prototype of a called function: `override prototype <address> <declaration>`
 *
 * Force a specified prototype declaration on a called function when decompiling
 * the current function. The current function must be decompiled again to see the effect.
 */
export class IfcProtooverride extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }

    const sizeRef = { val: 0 };
    const callpoint: Address = parse_machaddr(s, sizeRef, this.dcp.conf.types);

    let i: number;
    const numCalls = this.dcp.fd.numCalls();
    for (i = 0; i < numCalls; ++i) {
      if (this.dcp.fd.getCallSpecs_byIndex(i).getOp().getAddr().equals(callpoint)) break;
    }
    if (i === numCalls) {
      throw new IfaceExecutionError('No call is made at this address');
    }

    const text = s.readRest();
    const pieces = grammar_parse_protopieces(text, this.dcp.conf);
    const newproto = new FuncProto();
    newproto.setInternal(pieces.model, this.dcp.conf.types.getTypeVoid());
    newproto.setPieces(pieces);
    this.dcp.fd.getOverride().insertProtoOverride(callpoint, newproto);
    this.dcp.fd.clear();
  }
}

// ---------------------------------------------------------------------------
// IfcJumpOverride
// ---------------------------------------------------------------------------

/**
 * Provide an overriding jump-table for an indirect branch: `override jumptable ...`
 *
 * The command expects the address of an indirect branch in the current function,
 * followed by the keyword "table" then a list of possible target addresses.
 */
export class IfcJumpOverride extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }

    const sizeRef = { val: 0 };
    const jmpaddr: Address = parse_machaddr(s, sizeRef, this.dcp.conf.types);
    const jt: any = this.dcp.fd.installJumpTable(jmpaddr);
    const adtable: Address[] = [];
    let sv: bigint = BigInt(0);
    let h: bigint = BigInt(0);
    let naddr: Address | null = null;

    let token = s.readToken();
    if (token === 'startval') {
      const svTok = s.readToken();
      sv = BigInt(svTok.startsWith('0x') ? svTok : parseInt(svTok, 0).toString());
      token = s.readToken();
    }
    if (token === 'table') {
      while (!s.eof()) {
        const addrSizeRef = { val: 0 };
        const addr: Address = parse_machaddr(s, addrSizeRef, this.dcp.conf.types);
        adtable.push(addr);
      }
    }
    if (adtable.length === 0) {
      throw new IfaceExecutionError('Missing jumptable address entries');
    }
    jt.setOverride(adtable, naddr, h, sv);
    this.status.optr.write('Successfully installed jumptable override\n');
  }
}

// ---------------------------------------------------------------------------
// IfcFlowOverride
// ---------------------------------------------------------------------------

/**
 * Create a control-flow override: `override flow <address> branch|call|callreturn|return`
 *
 * Change the nature of the control-flow at the specified address.
 */
export class IfcFlowOverride extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }

    const sizeRef = { val: 0 };
    const addr: Address = parse_machaddr(s, sizeRef, this.dcp.conf.types);
    const token = s.readToken();
    if (token.length === 0) {
      throw new IfaceParseError('Missing override type');
    }
    // Override.stringToType maps strings to type constants
    const type: number = this.dcp.fd.getOverride().constructor.stringToType
      ? this.dcp.fd.getOverride().constructor.stringToType(token)
      : 0;
    if (type === 0) {
      throw new IfaceParseError('Bad override type');
    }

    this.dcp.fd.getOverride().insertFlowOverride(addr, type);
    this.status.optr.write('Successfully added override\n');
  }
}

// ---------------------------------------------------------------------------
// IfcDeadcodedelay
// ---------------------------------------------------------------------------

/**
 * Change when dead code elimination starts: `deadcode delay <name> <delay>`
 *
 * An address space is selected by name, along with a pass number.
 * Dead code elimination for Varnodes in that address space is changed to start
 * during that pass.
 */
export class IfcDeadcodedelay extends IfaceDecompCommand {
  execute(s: InputStream): void {
    const name = s.readToken();
    const delayTok = s.readToken();
    const delay = parseInt(delayTok, 10);

    const spc: AddrSpace = this.dcp.conf.getSpaceByName(name);
    if (spc === null) {
      throw new IfaceParseError('Bad space: ' + name);
    }
    if (isNaN(delay) || delay === -1) {
      throw new IfaceParseError('Need delay integer');
    }
    if (this.dcp.fd !== null) {
      this.dcp.fd.getOverride().insertDeadcodeDelay(spc, delay);
      this.status.optr.write('Successfully overrided deadcode delay for single function\n');
    } else {
      this.dcp.conf.setDeadcodeDelay(spc, delay);
      this.status.optr.write('Successfully overrided deadcode delay for all functions\n');
    }
  }
}

// ---------------------------------------------------------------------------
// IfcGlobalAdd
// ---------------------------------------------------------------------------

/**
 * Add a memory range as discoverable global variables: `global add <address+size>`
 *
 * The decompiler will treat Varnodes stored in the new memory range as persistent
 * global variables.
 */
export class IfcGlobalAdd extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No image loaded');
    }

    const sizeRef = { val: 0 };
    const addr: Address = parse_machaddr(s, sizeRef, this.dcp.conf.types);
    const size = sizeRef.val;
    const first: bigint = addr.getOffset();
    const last: bigint = first + BigInt(size - 1);

    const scope: Scope = this.dcp.conf.symboltab.getGlobalScope();
    this.dcp.conf.symboltab.addRange(scope, addr.getSpace(), first, last);
  }
}

// ---------------------------------------------------------------------------
// IfcGlobalRemove
// ---------------------------------------------------------------------------

/**
 * Remove a memory range from discoverable global variables: `global remove <address+size>`
 */
export class IfcGlobalRemove extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No image loaded');
    }

    const sizeRef = { val: 0 };
    const addr: Address = parse_machaddr(s, sizeRef, this.dcp.conf.types);
    const size = sizeRef.val;
    const first: bigint = addr.getOffset();
    const last: bigint = first + BigInt(size - 1);

    const scope: Scope = this.dcp.conf.symboltab.getGlobalScope();
    this.dcp.conf.symboltab.removeRange(scope, addr.getSpace(), first, last);
  }
}

// ---------------------------------------------------------------------------
// IfcGlobalify
// ---------------------------------------------------------------------------

/**
 * Treat all normal memory as discoverable global variables: `global spaces`
 *
 * This has the drastic effect that the decompiler will treat all registers and stack
 * locations as global variables.
 */
export class IfcGlobalify extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No load image present');
    }
    this.dcp.conf.globalify();
    this.status.optr.write('Successfully made all registers/memory locations global\n');
  }
}

// ---------------------------------------------------------------------------
// IfcGlobalRegisters
// ---------------------------------------------------------------------------

/**
 * Name global registers: `global registers`
 *
 * Name any global symbol stored in a register with the name of the register.
 */
export class IfcGlobalRegisters extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No load image present');
    }

    const reglist: Map<any, string> = new Map();
    this.dcp.conf.translate.getAllRegisters(reglist);
    let spc: AddrSpace | null = null;
    let lastoff: bigint = BigInt(0);
    const globalscope: Scope = this.dcp.conf.symboltab.getGlobalScope();
    let count = 0;

    for (const [dat, regName] of reglist) {
      if (dat.space === spc) {
        if (dat.offset <= lastoff) continue; // Nested register def
      }
      spc = dat.space;
      lastoff = dat.offset + BigInt(dat.size - 1);
      const addr = { getSpace: () => spc, getOffset: () => dat.offset };
      let flags = 0;
      globalscope.queryProperties(addr, dat.size, null, { val: flags });
      if ((flags & 0x4000) !== 0) { // Varnode.persist = 0x4000
        const ct: Datatype = this.dcp.conf.types.getBase(dat.size, type_metatype.TYPE_UINT);
        globalscope.addSymbol(regName, ct, addr, null);
        count += 1;
      }
    }
    if (count === 0) {
      this.status.optr.write('No global registers\n');
    } else {
      this.status.optr.write('Successfully made a global symbol for ' + count + ' registers\n');
    }
  }
}

// ---------------------------------------------------------------------------
// IfcPrintInputs
// ---------------------------------------------------------------------------

/**
 * Print info about the current function's input Varnodes: `print inputs`
 */
export class IfcPrintInputs extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }
    IfcPrintInputs.print(this.dcp.fd, this.status.fileoptr);
  }

  /**
   * Check for non-trivial use of given Varnode.
   * The use is non-trivial if it can be traced to any p-code operation except
   * a COPY, CAST, INDIRECT, or MULTIEQUAL.
   */
  static nonTrivialUse(vn: Varnode): boolean {
    const vnlist: Varnode[] = [];
    let res = false;
    vnlist.push(vn);
    let proc = 0;
    while (proc < vnlist.length) {
      const tmpvn: Varnode = vnlist[proc];
      proc += 1;
      const enditer = tmpvn.endDescend();
      for (let it = 0; it < enditer; it++) {
        const op: PcodeOp = tmpvn.getDescend(it);
        const opc = op.code();
        if (opc === OpCode.CPUI_COPY || opc === OpCode.CPUI_CAST || opc === OpCode.CPUI_INDIRECT || opc === OpCode.CPUI_MULTIEQUAL) {
          const outvn: Varnode = op.getOut();
          if (!outvn.isMark()) {
            outvn.setMark();
            vnlist.push(outvn);
          }
        } else {
          res = true;
          break;
        }
      }
    }
    for (let i = 0; i < vnlist.length; ++i) {
      vnlist[i].clearMark();
    }
    return res;
  }

  /**
   * Check if a Varnode is restored to its original input value.
   * Look for any value flowing into the Varnode coming from anything
   * other than an input Varnode with the same storage.
   */
  static checkRestore(vn: Varnode): number {
    const vnlist: Varnode[] = [];
    let res = 0;
    vnlist.push(vn);
    let proc = 0;
    while (proc < vnlist.length) {
      const tmpvn: Varnode = vnlist[proc];
      proc += 1;
      if (tmpvn.isInput()) {
        if (tmpvn.getSize() !== vn.getSize() || !tmpvn.getAddr().equals(vn.getAddr())) {
          res = 1;
          break;
        }
      } else if (!tmpvn.isWritten()) {
        res = 1;
        break;
      } else {
        const op: PcodeOp = tmpvn.getDef();
        const opc = op.code();
        if (opc === OpCode.CPUI_COPY || opc === OpCode.CPUI_CAST) {
          const inv: Varnode = op.getIn(0);
          if (!inv.isMark()) {
            inv.setMark();
            vnlist.push(inv);
          }
        }
        else if (opc === OpCode.CPUI_INDIRECT) {
          const inv: Varnode = op.getIn(0);
          if (!inv.isMark()) {
            inv.setMark();
            vnlist.push(inv);
          }
        }
        else if (opc === OpCode.CPUI_MULTIEQUAL) {
          for (let i = 0; i < op.numInput(); ++i) {
            const inv: Varnode = op.getIn(i);
            if (!inv.isMark()) {
              inv.setMark();
              vnlist.push(inv);
            }
          }
        } else {
          res = 1;
          break;
        }
      }
    }
    for (let i = 0; i < vnlist.length; ++i) {
      vnlist[i].clearMark();
    }
    return res;
  }

  /**
   * Check if storage is restored.
   * For the given storage location, check that it is restored
   * from its original input value.
   */
  static findRestore(vn: Varnode, fd: Funcdata): boolean {
    const iter = fd.beginLoc(vn.getAddr());
    const enditer = fd.endLoc(vn.getAddr());
    let count = 0;
    let current = iter;
    while (current !== enditer) {
      const cvn: Varnode = current.value();
      current = current.next();
      if (!cvn.hasNoDescend()) continue;
      if (!cvn.isWritten()) continue;
      const op: PcodeOp = cvn.getDef();
      if (op.code() === OpCode.CPUI_INDIRECT) continue;
      const res: number = IfcPrintInputs.checkRestore(cvn);
      if (res !== 0) return false;
      count += 1;
    }
    return count > 0;
  }

  /**
   * Print information about function inputs.
   * For each input Varnode, print information about the Varnode,
   * any explicit symbol it represents, and info about how the value is used.
   */
  static print(fd: Funcdata, w: Writer): void {
    w.write('Function: ' + fd.getName() + '\n');
    const VN_INPUT = 0x08; // Varnode.input flag
    const iter = fd.beginDef(VN_INPUT);
    const enditer = fd.endDef(VN_INPUT);
    let current = iter;
    while (current !== enditer) {
      const vn: Varnode = current.value();
      current = current.next();
      vn.printRaw(w);
      if (fd.isHighOn()) {
        const sym: Symbol = vn.getHigh().getSymbol();
        if (sym !== null) {
          w.write('    ' + sym.getName());
        }
      }
      const findres: boolean = IfcPrintInputs.findRestore(vn, fd);
      const nontriv: boolean = IfcPrintInputs.nonTrivialUse(vn);
      if (findres && !nontriv) {
        w.write('     restored');
      } else if (nontriv) {
        w.write('     nontriv');
      }
      w.write('\n');
    }
  }
}

// ---------------------------------------------------------------------------
// IfcPrintInputsAll
// ---------------------------------------------------------------------------

/**
 * Print info about input Varnodes for all functions: `print inputs all`
 *
 * Each function is decompiled, and info about its input Varnodes are printed.
 */
export class IfcPrintInputsAll extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No load image present');
    }
    this.iterateFunctionsAddrOrder();
  }

  iterationCallback(fd: Funcdata): void {
    if (fd.hasNoCode()) {
      this.status.optr.write('No code for ' + fd.getName() + '\n');
      return;
    }
    try {
      this.dcp.conf.clearAnalysis(fd);
      this.dcp.conf.allacts.getCurrent().reset(fd);
      this.dcp.conf.allacts.getCurrent().perform(fd);
      IfcPrintInputs.print(fd, this.status.fileoptr);
    } catch (err: any) {
      this.status.optr.write('Skipping ' + fd.getName() + ': ' + (err.explain ?? err.message) + '\n');
    }
    this.dcp.conf.clearAnalysis(fd);
  }
}

// ---------------------------------------------------------------------------
// IfcLockPrototype
// ---------------------------------------------------------------------------

/**
 * Lock in the current function's prototype: `prototype lock`
 *
 * Lock in the existing formal parameter names and data-types for any future
 * decompilation.  Both input parameters and the return value are locked.
 */
export class IfcLockPrototype extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }
    this.dcp.fd.getFuncProto().setInputLock(true);
    this.dcp.fd.getFuncProto().setOutputLock(true);
  }
}

// ---------------------------------------------------------------------------
// IfcUnlockPrototype
// ---------------------------------------------------------------------------

/**
 * Unlock the current function's prototype: `prototype unlock`
 *
 * Unlock all input parameters and the return value, so future decompilation
 * is not constrained with their data-type or name.
 */
export class IfcUnlockPrototype extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }
    this.dcp.fd.getFuncProto().setInputLock(false);
    this.dcp.fd.getFuncProto().setOutputLock(false);
  }
}

// ---------------------------------------------------------------------------
// IfcPrintLocalrange
// ---------------------------------------------------------------------------

/**
 * Print range of locals on the stack: `print localrange`
 */
export class IfcPrintLocalrange extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }
    this.dcp.fd.printLocalRange(this.status.optr);
  }
}

// ---------------------------------------------------------------------------
// IfcPrintMap
// ---------------------------------------------------------------------------

/**
 * Print info about a scope/namespace: `print map <name>`
 *
 * Prints information about the discoverable memory ranges for the scope,
 * and prints a description of every symbol in the scope.
 */
export class IfcPrintMap extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No load image');
    }

    const name = s.readToken();
    let scope: Scope;

    if (name.length !== 0 || this.dcp.fd === null) {
      const fullname = name + '::a'; // Add fake variable name
      const resolved = this.dcp.conf.symboltab.resolveScopeFromSymbolName(fullname, '::', null);
      scope = resolved.scope;
    } else {
      scope = this.dcp.fd.getScopeLocal();
    }

    if (scope === null) {
      throw new IfaceExecutionError('No map named: ' + name);
    }

    this.status.fileoptr.write(scope.getFullName() + '\n');
    scope.printBounds(this.status.fileoptr);
    scope.printEntries(this.status.fileoptr);
  }
}

// ---------------------------------------------------------------------------
// IfcProduceC
// ---------------------------------------------------------------------------

/**
 * Write decompilation for all functions to a file: `produce C <filename>`
 *
 * Iterate over all functions in the program.  For each function, decompilation is
 * performed and output is appended to the file.
 */
export class IfcProduceC extends IfaceDecompCommand {
  execute(s: InputStream): void {
    const name = s.readToken();
    if (name.length === 0) {
      throw new IfaceParseError('Need file name to write to');
    }

    // In a full wiring this would open a file and set the print stream.
    // For now, we use the architecture's print output directly.
    const fs = require('fs');
    const fd = fs.openSync(name, 'w');
    const fileWriter: Writer = {
      write(data: string): void {
        fs.writeSync(fd, data);
      },
    } as Writer;
    this.dcp.conf.print.setOutputStream(fileWriter);

    this.iterateFunctionsAddrOrder();

    fs.closeSync(fd);
  }

  iterationCallback(fd: Funcdata): void {
    if (fd.hasNoCode()) {
      this.status.optr.write('No code for ' + fd.getName() + '\n');
      return;
    }
    try {
      this.dcp.conf.clearAnalysis(fd);
      this.dcp.conf.allacts.getCurrent().reset(fd);
      const startTime = Date.now();
      this.dcp.conf.allacts.getCurrent().perform(fd);
      const endTime = Date.now();
      const duration = endTime - startTime;
      this.status.optr.write('Decompiled ' + fd.getName());
      this.status.optr.write('(' + fd.getSize() + ')');
      this.status.optr.write(' time=' + duration + ' ms\n');
      this.dcp.conf.print.docFunction(fd);
    } catch (err: any) {
      this.status.optr.write('Skipping ' + fd.getName() + ': ' + (err.explain ?? err.message) + '\n');
    }
    this.dcp.conf.clearAnalysis(fd);
  }
}

// ---------------------------------------------------------------------------
// IfcProducePrototypes
// ---------------------------------------------------------------------------

/**
 * Determine the prototype model for all functions: `produce prototypes`
 *
 * Functions are walked in leaf order.
 */
export class IfcProducePrototypes extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No load image');
    }
    if (this.dcp.cgraph === null) {
      throw new IfaceExecutionError('Callgraph has not been built');
    }
    if (this.dcp.conf.evalfp_current === null) {
      this.status.optr.write('Always using default prototype\n');
      return;
    }

    if (!this.dcp.conf.evalfp_current.isMerged()) {
      this.status.optr.write('Always using prototype ' + this.dcp.conf.evalfp_current.getName() + '\n');
      return;
    }
    const model = this.dcp.conf.evalfp_current;
    this.status.optr.write('Trying to distinguish between prototypes:\n');
    for (let i = 0; i < model.numModels(); ++i) {
      this.status.optr.write('  ' + model.getModel(i).getName() + '\n');
    }

    this.iterateFunctionsLeafOrder();
  }

  iterationCallback(fd: Funcdata): void {
    this.status.optr.write(fd.getName() + ' ');
    if (fd.hasNoCode()) {
      this.status.optr.write('has no code\n');
      return;
    }
    if (fd.getFuncProto().isInputLocked()) {
      this.status.optr.write('has locked prototype\n');
      return;
    }
    try {
      this.dcp.conf.clearAnalysis(fd);
      this.dcp.conf.allacts.getCurrent().reset(fd);
      const startTime = Date.now();
      this.dcp.conf.allacts.getCurrent().perform(fd);
      const duration = Date.now() - startTime;
      this.status.optr.write('proto=' + fd.getFuncProto().getModelName());
      fd.getFuncProto().setModelLock(true);
      this.status.optr.write(' time=' + duration + ' ms\n');
    } catch (err: any) {
      this.status.optr.write('Skipping ' + fd.getName() + ': ' + (err.explain ?? err.message) + '\n');
    }
    this.dcp.conf.clearAnalysis(fd);
  }
}

// ---------------------------------------------------------------------------
// IfcContinue
// ---------------------------------------------------------------------------

/**
 * Continue decompilation after a break point: `continue`
 *
 * This command assumes decompilation has been started and has hit a break point.
 */
export class IfcContinue extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('Decompile action not loaded');
    }
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }

    // Action::status_start = 0, Action::status_end = 4
    if (this.dcp.conf.allacts.getCurrent().getStatus() === 0) {
      throw new IfaceExecutionError('Decompilation has not been started');
    }
    if (this.dcp.conf.allacts.getCurrent().getStatus() === 4) {
      throw new IfaceExecutionError('Decompilation is already complete');
    }

    const res: number = this.dcp.conf.allacts.getCurrent().perform(this.dcp.fd);
    if (res < 0) {
      this.status.optr.write('Break at ');
      this.dcp.conf.allacts.getCurrent().printState(this.status.optr);
    } else {
      let msg = 'Decompilation complete';
      if (res === 0) {
        msg += ' (no change)';
      }
      this.status.optr.write(msg);
    }
    this.status.optr.write('\n');
  }
}

// ---------------------------------------------------------------------------
// IfcCommentInstr
// ---------------------------------------------------------------------------

/**
 * Attach a comment to an address: `comment <address> comment text...`
 *
 * Add a comment to the database, suitable for integration into decompiler output
 * for the current function.
 */
export class IfcCommentInstr extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('Decompile action not loaded');
    }
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }

    const sizeRef = { val: 0 };
    const addr: Address = parse_machaddr(s, sizeRef, this.dcp.conf.types);

    const comment = s.readRest();
    const type: number = this.dcp.conf.print.getInstructionComment();
    this.dcp.conf.commentdb.addComment(type, this.dcp.fd.getAddress(), addr, comment);
  }
}

// ---------------------------------------------------------------------------
// IfcDuplicateHash
// ---------------------------------------------------------------------------

/**
 * Check for duplicate hashes in functions: `duplicate hash`
 *
 * All functions in the architecture/program are decompiled, and for each
 * a check is made for Varnode pairs with identical hash values.
 */
export class IfcDuplicateHash extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    this.iterateFunctionsAddrOrder();
  }

  /**
   * Check for duplicate hashes in given function.
   * For each duplicate discovered, a message is written to the provided writer.
   */
  static check(fd: Funcdata, w: Writer): void {
    // DynamicHash is used for finding duplicate hash values.
    // This is a complex analysis delegated to the architecture layer.
    const iter = fd.beginLoc();
    const enditer = fd.endLoc();
    let current = iter;
    while (current !== enditer) {
      const vn: Varnode = current.value();
      current = current.next();
      if (vn.isAnnotation()) continue;
      if (vn.isConstant()) {
        const op: PcodeOp = vn.loneDescend();
        if (op !== null) {
          const slot: number = op.getSlot(vn);
          if (slot === 0) {
            const opc = op.code();
            if (opc === OpCode.CPUI_LOAD || opc === OpCode.CPUI_STORE || opc === OpCode.CPUI_RETURN) continue;
          }
        }
      } else if (vn.getSpace().getType() !== 3 /* IPTR_INTERNAL */) {
        continue;
      } else if (vn.isImplied()) {
        continue;
      }
      // DynamicHash::uniqueHash(vn, fd) etc. -- delegate to architecture
      // Stub: full duplicate-hash checking requires DynamicHash wiring
    }
  }

  iterationCallback(fd: Funcdata): void {
    if (fd.hasNoCode()) {
      this.status.optr.write('No code for ' + fd.getName() + '\n');
      return;
    }
    try {
      this.dcp.conf.clearAnalysis(fd);
      this.dcp.conf.allacts.getCurrent().reset(fd);
      const startTime = Date.now();
      this.dcp.conf.allacts.getCurrent().perform(fd);
      const duration = Date.now() - startTime;
      this.status.optr.write('Decompiled ' + fd.getName());
      this.status.optr.write('(' + fd.getSize() + ')');
      this.status.optr.write(' time=' + duration + ' ms\n');
      IfcDuplicateHash.check(fd, this.status.optr);
    } catch (err: any) {
      this.status.optr.write('Skipping ' + fd.getName() + ': ' + (err.explain ?? err.message) + '\n');
    }
    this.dcp.conf.clearAnalysis(fd);
  }
}

// ---------------------------------------------------------------------------
// IfcCallFixup
// ---------------------------------------------------------------------------

/**
 * Add a new call fix-up to the program: `fixup call ...`
 *
 * Create a new call fixup-up for the architecture/program, suitable for
 * replacing called functions.  The fix-up is specified as a function-style declarator.
 */
export class IfcCallFixup extends IfaceDecompCommand {
  /**
   * Scan a single-line p-code snippet declaration from the given stream.
   *
   * A declarator is scanned first, providing a name to associate with the snippet, as well
   * as potential names of the formal output Varnode and input Varnodes.
   * The body of the snippet is then surrounded by '{' and '}'.
   */
  static readPcodeSnippet(
    s: InputStream,
    nameRef: { val: string },
    outnameRef: { val: string },
    inname: string[],
    pcodeRef: { val: string }
  ): void {
    outnameRef.val = s.readToken();
    nameRef.val = s.readToken(); // reads up to separator
    const bracket1 = s.readToken();
    if (outnameRef.val === 'void') {
      outnameRef.val = '';
    }
    if (bracket1 !== '(') {
      throw new IfaceParseError("Missing '('");
    }
    let bracket = bracket1;
    while (bracket !== ')') {
      const param = s.readToken();
      bracket = s.readToken();
      if (param.length !== 0) {
        inname.push(param);
      }
    }
    const openBrace = s.readToken();
    if (openBrace !== '{') {
      throw new IfaceParseError("Missing '{'");
    }
    // Read until '}' -- consume remaining and strip trailing '}'
    const rest = s.readRest();
    const closeIdx = rest.indexOf('}');
    if (closeIdx < 0) {
      pcodeRef.val = rest;
    } else {
      pcodeRef.val = rest.substring(0, closeIdx);
    }
  }

  execute(s: InputStream): void {
    const nameRef = { val: '' };
    const outnameRef = { val: '' };
    const pcodeRef = { val: '' };
    const inname: string[] = [];

    IfcCallFixup.readPcodeSnippet(s, nameRef, outnameRef, inname, pcodeRef);
    let id = -1;
    try {
      id = this.dcp.conf.pcodeinjectlib.manualCallFixup(nameRef.val, pcodeRef.val);
    } catch (err: any) {
      this.status.optr.write('Error compiling pcode: ' + (err.explain ?? err.message) + '\n');
      return;
    }
    const payload: any = this.dcp.conf.pcodeinjectlib.getPayload(id);
    payload.printTemplate(this.status.optr);
  }
}

// ---------------------------------------------------------------------------
// IfcCallOtherFixup
// ---------------------------------------------------------------------------

/**
 * Add a new callother fix-up to the program: `fixup callother ...`
 *
 * The new fix-up is suitable for replacing specific user-defined (CALLOTHER)
 * p-code operations.
 */
export class IfcCallOtherFixup extends IfaceDecompCommand {
  execute(s: InputStream): void {
    const useropnameRef = { val: '' };
    const outnameRef = { val: '' };
    const pcodeRef = { val: '' };
    const inname: string[] = [];

    IfcCallFixup.readPcodeSnippet(s, useropnameRef, outnameRef, inname, pcodeRef);
    this.dcp.conf.userops.manualCallOtherFixup(
      useropnameRef.val, outnameRef.val, inname, pcodeRef.val, this.dcp.conf
    );

    this.status.optr.write('Successfully registered callotherfixup\n');
  }
}

// ---------------------------------------------------------------------------
// IfcFixupApply
// ---------------------------------------------------------------------------

/**
 * Apply a call-fixup to a particular function: `fixup apply <fixup> <function>`
 *
 * The call-fixup and function are named from the command-line. If they both exist,
 * the fixup is set on the function's prototype.
 */
export class IfcFixupApply extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No load image present');
    }

    const fixupName = s.readToken();
    if (fixupName.length === 0) {
      throw new IfaceParseError('Missing fixup name');
    }
    const funcName = s.readToken();
    if (funcName.length === 0) {
      throw new IfaceParseError('Missing function name');
    }

    // InjectPayload::CALLFIXUP_TYPE = 1
    const injectid: number = this.dcp.conf.pcodeinjectlib.getPayloadId(1, fixupName);
    if (injectid < 0) {
      throw new IfaceExecutionError('Unknown fixup: ' + fixupName);
    }

    const resolved = this.dcp.conf.symboltab.resolveScopeFromSymbolName(
      funcName, '::', null
    );
    if (resolved.scope === null) {
      throw new IfaceExecutionError('Bad namespace: ' + funcName);
    }
    const fd: Funcdata = resolved.scope.queryFunction(resolved.basename);
    if (fd === null) {
      throw new IfaceExecutionError('Unknown function name: ' + funcName);
    }

    fd.getFuncProto().setInjectId(injectid);
    this.status.optr.write('Successfully applied callfixup\n');
  }
}

// ---------------------------------------------------------------------------
// IfcCountPcode
// ---------------------------------------------------------------------------

/**
 * Count p-code in the current function: `count pcode`
 *
 * The count is based on the number of existing p-code operations in
 * the current function.
 */
export class IfcCountPcode extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('Image not loaded');
    }
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }

    let count = 0;
    const iter = this.dcp.fd.beginOpAlive();
    const enditer = this.dcp.fd.endOpAlive();
    let current = iter;
    while (current !== enditer) {
      count += 1;
      current = current.next();
    }
    this.status.optr.write('Count - pcode = ' + count + '\n');
  }
}

// ---------------------------------------------------------------------------
// IfcPrintActionstats
// ---------------------------------------------------------------------------

/**
 * Print transform statistics for the decompiler engine: `print actionstats`
 *
 * Counts for each Action and Rule are displayed.
 */
export class IfcPrintActionstats extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('Image not loaded');
    }
    if (this.dcp.conf.allacts.getCurrent() === null) {
      throw new IfaceExecutionError('No action set');
    }
    this.dcp.conf.allacts.getCurrent().printStatistics(this.status.fileoptr);
  }
}

// ---------------------------------------------------------------------------
// IfcResetActionstats
// ---------------------------------------------------------------------------

/**
 * Reset transform statistics for the decompiler engine: `reset actionstats`
 *
 * Counts for each Action and Rule are reset to zero.
 */
export class IfcResetActionstats extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('Image not loaded');
    }
    if (this.dcp.conf.allacts.getCurrent() === null) {
      throw new IfaceExecutionError('No action set');
    }
    this.dcp.conf.allacts.getCurrent().resetStats();
  }
}

// ---------------------------------------------------------------------------
// IfcVolatile
// ---------------------------------------------------------------------------

/**
 * Mark a memory range as volatile: `volatile <address+size>`
 *
 * The memory range provided on the command-line is marked as volatile.
 */
export class IfcVolatile extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No load image present');
    }

    const sizeRef = { val: 0 };
    const addr: Address = parse_machaddr(s, sizeRef, this.dcp.conf.types);
    const size = sizeRef.val;
    if (size === 0) {
      throw new IfaceExecutionError('Must specify a size');
    }

    const range = new Range(addr.getSpace()!, addr.getOffset(), addr.getOffset() + BigInt(size - 1));
    // Varnode::volatil = 0x800
    this.dcp.conf.symboltab.setPropertyRange(0x800, range);
    this.status.optr.write('Successfully marked range as volatile\n');
  }
}

// ---------------------------------------------------------------------------
// IfcReadonly
// ---------------------------------------------------------------------------

/**
 * Mark a memory range as read-only: `readonly <address+size>`
 *
 * The memory range is marked as read-only, allowing the decompiler to propagate
 * values pulled from the LoadImage as constants.
 */
export class IfcReadonly extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No load image present');
    }

    const sizeRef = { val: 0 };
    const addr: Address = parse_machaddr(s, sizeRef, this.dcp.conf.types);
    const size = sizeRef.val;
    if (size === 0) {
      throw new IfaceExecutionError('Must specify a size');
    }

    const range = new Range(addr.getSpace()!, addr.getOffset(), addr.getOffset() + BigInt(size - 1));
    // Varnode::readonly = 0x2000
    this.dcp.conf.symboltab.setPropertyRange(0x2000, range);
    this.status.optr.write('Successfully marked range as readonly\n');
  }
}

// ---------------------------------------------------------------------------
// IfcPointerSetting
// ---------------------------------------------------------------------------

/**
 * Create a pointer with additional settings: `pointer setting <name> <basetype> offset <val>`
 *
 * Alternately: `pointer setting <name> <basetype> space <spacename>`
 */
export class IfcPointerSetting extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No load image present');
    }

    const typeName = s.readToken();
    if (typeName.length === 0) {
      throw new IfaceParseError('Missing name');
    }
    const baseType = s.readToken();
    if (baseType.length === 0) {
      throw new IfaceParseError('Missing base-type');
    }
    const setting = s.readToken();
    if (setting.length === 0) {
      throw new IfaceParseError('Missing setting');
    }

    if (setting === 'offset') {
      const offTok = s.readToken();
      const off = offTok.startsWith('0x') ? parseInt(offTok, 16) : parseInt(offTok, 10);
      if (off <= 0) {
        throw new IfaceParseError('Missing offset');
      }
      const bt: Datatype = this.dcp.conf.types.findByName(baseType);
      if (bt === null || bt.getMetatype() !== 4) { // TYPE_STRUCT = 4
        throw new IfaceParseError('Base-type must be a structure');
      }
      const ptrto: Datatype = TypePointerRel.getPtrToFromParent(bt, off, this.dcp.conf.types);
      const spc: AddrSpace = this.dcp.conf.getDefaultDataSpace();
      this.dcp.conf.types.getTypePointerRel(
        spc.getAddrSize(), bt, ptrto, spc.getWordSize(), off, typeName
      );
    } else if (setting === 'space') {
      const spaceName = s.readToken();
      if (spaceName.length === 0) {
        throw new IfaceParseError('Missing name of address space');
      }
      const ptrTo: Datatype = this.dcp.conf.types.findByName(baseType);
      if (ptrTo === null) {
        throw new IfaceParseError('Unknown base data-type: ' + baseType);
      }
      const spc: AddrSpace = this.dcp.conf.getSpaceByName(spaceName);
      if (spc === null) {
        throw new IfaceParseError('Unknown space: ' + spaceName);
      }
      this.dcp.conf.types.getTypePointerWithSpace(ptrTo, spc, typeName);
    } else {
      throw new IfaceParseError('Unknown pointer setting: ' + setting);
    }
    this.status.optr.write('Successfully created pointer: ' + typeName + '\n');
  }
}

// ---------------------------------------------------------------------------
// IfcPreferSplit
// ---------------------------------------------------------------------------

/**
 * Mark a storage location to be split: `prefersplit <address+size> <splitsize>`
 *
 * The storage location is marked for splitting in any future decompilation.
 */
export class IfcPreferSplit extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No load image present');
    }

    const sizeRef = { val: 0 };
    const addr: Address = parse_machaddr(s, sizeRef, this.dcp.conf.types);
    const size = sizeRef.val;
    if (size === 0) {
      throw new IfaceExecutionError('Must specify a size');
    }

    const splitTok = s.readToken();
    if (splitTok.length === 0) {
      throw new IfaceParseError('Missing split offset');
    }
    const split = parseInt(splitTok, 10);
    if (split === -1 || isNaN(split)) {
      throw new IfaceParseError('Bad split offset');
    }

    this.dcp.conf.splitrecords.push({
      storage: {
        space: addr.getSpace(),
        offset: addr.getOffset(),
        size: size,
      },
      splitoffset: split,
    });

    this.status.optr.write('Successfully added split record\n');
  }
}

// ---------------------------------------------------------------------------
// IfcStructureBlocks
// ---------------------------------------------------------------------------

/**
 * Structure an external control-flow graph: `structure blocks <infile> <outfile>`
 *
 * The control-flow graph is read in from XML file, structuring is performed, and the
 * result is written out to a separate XML file.
 */
export class IfcStructureBlocks extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('No load image present');
    }

    const infile = s.readToken();
    const outfile = s.readToken();

    if (infile.length === 0) {
      throw new IfaceParseError('Missing input file');
    }
    if (outfile.length === 0) {
      throw new IfaceParseError('Missing output file');
    }

    // Structure blocks involves parsing XML, building block graphs,
    // running CollapseStructure, etc.  Delegate to architecture.
    throw new IfaceExecutionError('StructureBlocks not yet wired');
  }
}

// ---------------------------------------------------------------------------
// IfcAnalyzeRange
// ---------------------------------------------------------------------------

/**
 * Run value-set analysis on the current function: `analyze range full|partial <varnode>`
 *
 * The analysis targets a single varnode as specified on the command-line and is based on
 * the existing data-flow graph for the current function.
 */
export class IfcAnalyzeRange extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.conf === null) {
      throw new IfaceExecutionError('Image not loaded');
    }
    if (this.dcp.fd === null) {
      throw new IfaceExecutionError('No function selected');
    }

    const token = s.readToken();
    let useFullWidener: boolean;
    if (token === 'full') {
      useFullWidener = true;
    } else if (token === 'partial') {
      useFullWidener = false;
    } else {
      throw new IfaceParseError('Must specify "full" or "partial" widening');
    }

    const vn: Varnode = this.dcp.readVarnode(s);
    // Value-set analysis involves ValueSetSolver, wideners, etc.
    // Delegate to architecture's analysis framework.
    throw new IfaceExecutionError('ValueSetSolver not yet wired');
  }
}

// ---------------------------------------------------------------------------
// IfcLoadTestFile
// ---------------------------------------------------------------------------

/**
 * Load a datatest environment file: `load test <filename>`
 *
 * The program and associated script from a decompiler test file is loaded.
 */
export class IfcLoadTestFile extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.conf !== null) {
      throw new IfaceExecutionError('Load image already present');
    }

    const filename = s.readToken();
    if (filename.length === 0) {
      throw new IfaceParseError('Missing test filename');
    }

    // Use dynamic import to avoid circular dependency with testfunction.ts
    // (testfunction.ts imports mainloop from this module)
    const { FunctionTestCollection } = require('./testfunction.js');
    this.dcp.testCollection = new FunctionTestCollection(this.status);
    this.dcp.testCollection.loadTest(filename);
  }
}

// ---------------------------------------------------------------------------
// IfcListTestCommands
// ---------------------------------------------------------------------------

/**
 * List all the script commands in the current test: `list test commands`
 */
export class IfcListTestCommands extends IfaceDecompCommand {
  execute(_s: InputStream): void {
    if (this.dcp.testCollection === null) {
      throw new IfaceExecutionError('No test file is loaded');
    }
    for (let i = 0; i < this.dcp.testCollection.numCommands(); ++i) {
      this.status.optr.write(' ' + (i + 1) + ': ' + this.dcp.testCollection.getCommand(i) + '\n');
    }
  }
}

// ---------------------------------------------------------------------------
// IfcExecuteTestCommand
// ---------------------------------------------------------------------------

/**
 * Execute a specified range of the test script: `execute test command <#>-<#>`
 */
export class IfcExecuteTestCommand extends IfaceDecompCommand {
  execute(s: InputStream): void {
    if (this.dcp.testCollection === null) {
      throw new IfaceExecutionError('No test file is loaded');
    }

    const firstTok = s.readToken();
    let first = parseInt(firstTok, 10) - 1;
    if (first < 0 || first > this.dcp.testCollection.numCommands()) {
      throw new IfaceExecutionError('Command index out of bounds');
    }

    let last = first;
    if (!s.eof()) {
      const hyphen = s.readToken();
      if (hyphen !== '-') {
        throw new IfaceExecutionError('Missing hyphenated command range');
      }
      const lastTok = s.readToken();
      last = parseInt(lastTok, 10) - 1;
      if (last < 0 || last < first || last > this.dcp.testCollection.numCommands()) {
        throw new IfaceExecutionError('Command index out of bounds');
      }
    }

    let combined = '';
    for (let i = first; i <= last; ++i) {
      combined += this.dcp.testCollection.getCommand(i) + '\n';
    }
    this.status.pushScript(combined, 'test> ');
  }
}

// ===========================================================================
// Free functions: execute() and mainloop()
// ===========================================================================

/**
 * Execute one command and handle any exceptions.
 *
 * Error messages are printed to the console.  For low-level errors,
 * the current function is reset to null.
 *
 * @param status - the console interface
 * @param dcp - the shared program data
 */
export function execute(status: IfaceStatus, dcp: IfaceDecompData): void {
  try {
    status.runCommand();
    return;
  } catch (err: any) {
    if (err instanceof IfaceParseError) {
      status.optr.write('Command parsing error: ' + (err.explain ?? err.message) + '\n');
    } else if (err instanceof IfaceExecutionError) {
      status.optr.write('Execution error: ' + (err.explain ?? err.message) + '\n');
    } else if (err.constructor && err.constructor.name === 'ParseError') {
      status.optr.write('Parse ERROR: ' + (err.explain ?? err.message) + '\n');
    } else if (err.constructor && err.constructor.name === 'RecovError') {
      status.optr.write('Function ERROR: ' + (err.explain ?? err.message) + '\n');
    } else if (err.constructor && err.constructor.name === 'LowlevelError') {
      status.optr.write('Low-level ERROR: ' + (err.explain ?? err.message) + '\n');
      dcp.abortFunction(status.optr);
    } else if (err.constructor && err.constructor.name === 'DecoderError') {
      status.optr.write('Decoding ERROR: ' + (err.explain ?? err.message) + '\n');
      dcp.abortFunction(status.optr);
    } else {
      status.optr.write('ERROR: ' + (err.explain ?? err.message) + '\n');
      if (err.stack) status.optr.write(err.stack.split('\n').slice(0, 15).join('\n') + '\n');
    }
  }
  status.evaluateError();
}

/**
 * Execute commands as they become available.
 *
 * Execution loops until either the done field in the console is set
 * or if all streams have ended.  This handles popping script states pushed
 * on by the IfcSource command.
 *
 * @param status - the console interface
 */
export function mainloop(status: IfaceStatus): void {
  const dcp = status.getData('decompile') as IfaceDecompData;
  for (;;) {
    while (!status.isStreamFinished()) {
      status.writePrompt();
      // flush is a no-op for our Writer interface
      if (typeof (status.optr as any).flush === 'function') {
        (status.optr as any).flush();
      }
      execute(status, dcp);
    }
    if (status.done) break;
    if (status.getNumInputStreamSize() === 0) break;
    status.popScript();
  }
}
