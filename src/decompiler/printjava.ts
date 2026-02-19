/**
 * @file printjava.ts
 * @description Classes supporting the java-language back-end to the decompiler.
 *
 * Translated from Ghidra's printjava.hh / printjava.cc
 */

import type { int4, uint4, uintb } from '../core/types.js';
import type { Writer } from '../util/writer.js';
import { StringWriter } from '../util/writer.js';
import { LowlevelError } from '../core/error.js';
import { OpCode } from '../core/opcodes.js';
import { type_metatype } from './type.js';
import { syntax_highlight } from './prettyprint.js';
import { StringManager } from './stringmanage.js';
import { CPoolRecord } from './cpool.js';

// ---------------------------------------------------------------------------
// Forward type declarations for types not yet available
// ---------------------------------------------------------------------------

type Architecture = any;
type Datatype = any;
type TypePointer = any;
type Varnode = any;
type PcodeOp = any;
type Funcdata = any;
type Scope = any;
type FuncCallSpecs = any;
type CastStrategy = any;
type CastStrategyJava = any;
type Emit = any;
type TypeOp = any;
type PrintLanguage = any;

// ---------------------------------------------------------------------------
// OpToken interface (matching C++ OpToken struct)
// ---------------------------------------------------------------------------

/**
 * Possible types of operator token
 */
enum tokentype {
  binary = 0,
  unary_prefix = 1,
  postsurround = 2,
  presurround = 3,
  space = 4,
  hiddenfunction = 5,
}

interface OpToken {
  print1: string;
  print2: string;
  stage: int4;
  precedence: int4;
  associative: boolean;
  type: tokentype;
  spacing: int4;
  bump: int4;
  negate: OpToken | null;
}

// ---------------------------------------------------------------------------
// Atom interface (matching C++ PrintLanguage::Atom)
// ---------------------------------------------------------------------------

/**
 * Possible types of Atom
 */
enum tagtype {
  syntax = 0,
  vartoken = 1,
  functoken = 2,
  optoken = 3,
  typetoken = 4,
  fieldtoken = 5,
  casetoken = 6,
  blanktoken = 7,
}

interface Atom {
  name: string;
  type: tagtype;
  highlight: syntax_highlight;
  op?: PcodeOp | null;
  ptr_second?: {
    vn?: Varnode | null;
    fd?: Funcdata | null;
    ct?: Datatype | null;
    intValue?: uintb;
  };
  offset?: int4;
}

function makeAtom(
  name: string,
  type: tagtype,
  highlight: syntax_highlight,
  ctOrOp?: any,
  vnOrFd?: any,
  intValue?: uintb,
): Atom {
  const a: Atom = { name, type, highlight };
  if (ctOrOp !== undefined) {
    if (type === tagtype.typetoken) {
      a.ptr_second = { ct: ctOrOp };
    } else {
      a.op = ctOrOp;
      if (vnOrFd !== undefined) {
        if (type === tagtype.functoken) {
          a.ptr_second = { fd: vnOrFd };
        } else if (type === tagtype.casetoken) {
          a.ptr_second = { intValue };
        } else {
          a.ptr_second = { vn: vnOrFd };
        }
      }
    }
  }
  return a;
}

// ---------------------------------------------------------------------------
// PrintLanguage modifiers (matching C++ PrintLanguage::modifiers)
// ---------------------------------------------------------------------------

const force_hex         = 1;
const force_dec         = 2;
const bestfit           = 4;
const force_scinote     = 8;
const force_pointer     = 0x10;
const print_load_value  = 0x20;
const print_store_value = 0x40;
const no_branch         = 0x80;
const only_branch       = 0x100;
const comma_separate    = 0x200;
const flat              = 0x400;
const falsebranch       = 0x800;
const nofallthru        = 0x1000;
const negatetoken       = 0x2000;
const hide_thisparam    = 0x4000;
const pending_brace     = 0x8000;

// ---------------------------------------------------------------------------
// PrintLanguageCapability -- base class stub
// ---------------------------------------------------------------------------

/**
 * Base class for high-level language capabilities.
 *
 * This is a minimal stub since printlanguage.ts does not yet exist.
 * Subclasses override buildLanguage() to produce a specific PrintLanguage.
 */
export abstract class PrintLanguageCapability {
  protected name: string = '';
  protected isdefault: boolean = false;

  getName(): string { return this.name; }

  initialize(): void {
    // Register with the global list of capabilities
  }

  abstract buildLanguage(glb: Architecture): PrintLanguage;
}

// ---------------------------------------------------------------------------
// PrintC -- base class stub
// ---------------------------------------------------------------------------

/**
 * Minimal stub for PrintC (from printc.ts, which does not yet exist).
 *
 * This provides the fields and methods that PrintJava references.
 * When printc.ts is fully translated, PrintJava should extend the real PrintC.
 */
class PrintC {
  // Static OpTokens referenced by PrintJava
  protected static scope: OpToken = {
    print1: '::', print2: '', stage: 1, precedence: 2, associative: false,
    type: tokentype.binary, spacing: 0, bump: 0, negate: null
  };
  protected static object_member: OpToken = {
    print1: '.', print2: '', stage: 1, precedence: 2, associative: false,
    type: tokentype.binary, spacing: 0, bump: 0, negate: null
  };
  protected static subscript: OpToken = {
    print1: '[', print2: ']', stage: 1, precedence: 2, associative: false,
    type: tokentype.postsurround, spacing: 0, bump: 0, negate: null
  };
  protected static function_call: OpToken = {
    print1: '(', print2: ')', stage: 0, precedence: 2, associative: false,
    type: tokentype.postsurround, spacing: 0, bump: 0, negate: null
  };
  protected static assignment: OpToken = {
    print1: '=', print2: '', stage: 1, precedence: 22, associative: false,
    type: tokentype.binary, spacing: 1, bump: 0, negate: null
  };
  protected static comma: OpToken = {
    print1: ',', print2: '', stage: 1, precedence: 24, associative: true,
    type: tokentype.binary, spacing: 0, bump: 0, negate: null
  };
  protected static shift_right: OpToken = {
    print1: '>>', print2: '', stage: 1, precedence: 11, associative: false,
    type: tokentype.binary, spacing: 1, bump: 0, negate: null
  };
  protected static type_expr_space: OpToken = {
    print1: '', print2: '', stage: 1, precedence: 10, associative: false,
    type: tokentype.space, spacing: 1, bump: 0, negate: null
  };
  protected static type_expr_nospace: OpToken = {
    print1: '', print2: '', stage: 1, precedence: 10, associative: false,
    type: tokentype.space, spacing: 0, bump: 0, negate: null
  };

  // Static string constants
  static readonly EMPTY_STRING: string = '';

  // Instance fields referenced by PrintJava
  protected glb: Architecture;
  protected curscope: Scope | null = null;
  protected castStrategy: CastStrategy | null = null;
  protected emit: Emit | null = null;
  protected mods: uint4 = 0;
  protected nullToken: string = 'NULL';
  protected option_NULL: boolean = false;
  protected option_convention: boolean = true;
  protected option_inplace_ops: boolean = false;
  protected option_nocasts: boolean = false;
  protected option_unplaced: boolean = false;
  protected option_hide_exts: boolean = false;

  constructor(glb: Architecture, _nm: string) {
    this.glb = glb;
  }

  // Methods referenced by PrintJava
  resetDefaults(): void {
    // Reset to C defaults (stub)
  }

  docFunction(_fd: Funcdata): void {
    // Full implementation in printc.ts (stub)
  }

  pushScope(sc: Scope): void {
    this.curscope = sc;
  }

  popScope(): void {
    this.curscope = null;
  }

  pushOp(_tok: OpToken, _op: PcodeOp | null): void {
    // Stub
  }

  pushAtom(_atom: Atom): void {
    // Stub
  }

  pushVn(_vn: Varnode, _op: PcodeOp | null, _m: uint4): void {
    // Stub
  }

  push_integer(
    _val: uintb, _sz: int4, _sign: boolean, _tag: tagtype,
    _vn: Varnode | null, _op: PcodeOp | null
  ): void {
    // Stub
  }

  getHiddenThisSlot(_op: PcodeOp, _fc: FuncCallSpecs): int4 {
    return -1; // Stub
  }

  genericTypeName(_ct: Datatype): string {
    return 'unknown_t'; // Stub
  }

  static unicodeNeedsEscape(codepoint: int4): boolean {
    if (codepoint < 0x20) return true;
    if (codepoint === 0x7f) return true;
    if (codepoint >= 0x80) return true;
    return false;
  }

  escapeCharacterData(
    _s: Writer, _buf: Uint8Array | null, _count: int4,
    _charsize: int4, _bigend: boolean
  ): boolean {
    return false; // Stub
  }

  adjustTypeOperators(): void {
    // Stub for C defaults
  }
}

// =========================================================================
// PrintJavaCapability
// =========================================================================

/**
 * Factory and static initializer for the "java-language" back-end to the decompiler.
 *
 * The singleton adds itself to the list of possible back-end languages for the decompiler
 * and it acts as a factory for producing the PrintJava object for emitting java-language tokens.
 */
export class PrintJavaCapability extends PrintLanguageCapability {
  /** The singleton instance */
  static readonly printJavaCapability: PrintJavaCapability = new PrintJavaCapability();

  /** Singleton constructor */
  private constructor() {
    super();
    this.name = 'java-language';
    this.isdefault = false;
  }

  buildLanguage(glb: Architecture): PrintJava {
    return new PrintJava(glb, this.name);
  }
}

// =========================================================================
// PrintJava
// =========================================================================

/**
 * The java-language token emitter.
 *
 * This builds heavily on the c-language PrintC emitter.  Most operator tokens, the format of
 * function prototypes, and code structuring are shared.  Specifics of the java constant pool are
 * handled through the overloaded opCpoolRefOp().
 *
 * Java data-types are mapped into the decompiler's data-type system in a specific way.
 * The primitives int, long, short, byte, boolean, float, and double all map directly.
 * The char primitive is treated as a 2 byte unsigned integer.
 * A TypeStruct object holds the field layout for a java class, then java objects get mapped as:
 *   - Class reference = pointer to TYPE_UINT
 *   - Array of int, long, short, or byte = pointer to TYPE_INT
 *   - Array of float or double = pointer to TYPE_FLOAT
 *   - Array of boolean = pointer to TYPE_BOOL
 *   - Array of class objects = pointer to TYPE_PTR
 *
 * There are some adjustments to the printing of data-types and LOAD/STORE expressions
 * to account for this mapping.
 */
export class PrintJava extends PrintC {
  /** The "instanceof" keyword operator token */
  private static instanceof_op: OpToken = {
    print1: 'instanceof', print2: '', stage: 2, precedence: 60,
    associative: true, type: tokentype.binary, spacing: 1, bump: 0, negate: null
  };

  /**
   * Does the given data-type reference a java array?
   *
   * References to java array objects where the underlying element is a java primitive look like:
   *   - Pointer to int
   *   - Pointer to bool
   *   - Pointer to float
   *
   * An array of java class objects is represented as a pointer to pointer data-type.
   * @param ct the given data-type
   * @returns true if the data-type references a java array object
   */
  private static isArrayType(ct: Datatype): boolean {
    if (ct.getMetatype() !== type_metatype.TYPE_PTR)  // Java arrays are always Ghidra pointer types
      return false;
    ct = (ct as TypePointer).getPtrTo();
    switch (ct.getMetatype() as type_metatype) {
      case type_metatype.TYPE_UINT:     // Pointer to unsigned is placeholder for class reference, not an array
        if (ct.isCharPrint())
          return true;
        break;
      case type_metatype.TYPE_INT:
      case type_metatype.TYPE_BOOL:
      case type_metatype.TYPE_FLOAT:   // Pointer to primitive type is an array
      case type_metatype.TYPE_PTR:     // Pointer to class reference is an array
        return true;
      default:
        break;
    }
    return false;
  }

  /**
   * Do we need '[0]' syntax?
   *
   * Assuming the given Varnode is a dereferenced pointer, determine whether
   * it needs to be represented using '[0]' syntax.
   * @param vn the given Varnode
   * @returns true if '[0]' syntax is required
   */
  private static needZeroArray(vn: Varnode): boolean {
    if (!PrintJava.isArrayType(vn.getType()))
      return false;
    if (vn.isExplicit()) return true;
    if (!vn.isWritten()) return true;
    const opc: OpCode = vn.getDef().code();
    if ((opc === OpCode.CPUI_PTRADD) || (opc === OpCode.CPUI_PTRSUB) || (opc === OpCode.CPUI_CPOOLREF))
      return false;
    return true;
  }

  /** Set options that are specific to Java */
  private resetDefaultsPrintJava(): void {
    this.option_NULL = true;          // Automatically use 'null' token
    this.option_convention = false;   // Automatically hide convention name
    this.mods |= hide_thisparam;      // turn on hiding of 'this' parameter
  }

  /**
   * Print a single unicode character as a character constant for the high-level language.
   * Java uses a similar encoding to C for common escape sequences but
   * uses \\uXXXX for generic unicode escapes.
   */
  protected printUnicode(s: Writer, onechar: int4): void {
    if (PrintC.unicodeNeedsEscape(onechar)) {
      switch (onechar) {          // Special escape characters
        case 0:
          s.write('\\0');
          return;
        case 8:
          s.write('\\b');
          return;
        case 9:
          s.write('\\t');
          return;
        case 10:
          s.write('\\n');
          return;
        case 12:
          s.write('\\f');
          return;
        case 13:
          s.write('\\r');
          return;
        case 92:
          s.write('\\\\');
          return;
        case 0x22: // '"'
          s.write('\\"');
          return;
        case 0x27: // "'"
          s.write("\\'");
          return;
      }
      // Generic unicode escape
      if (onechar < 65536) {
        s.write('\\ux' + onechar.toString(16).padStart(4, '0'));
      } else {
        s.write('\\ux' + onechar.toString(16).padStart(8, '0'));
      }
      return;
    }
    StringManager.writeUtf8(s, onechar);   // Emit normally
  }

  /** Construct the Java language emitter */
  constructor(glb: Architecture, nm: string = 'java-language') {
    super(glb, nm);
    this.resetDefaultsPrintJava();
    this.nullToken = 'null';        // Java standard lower-case 'null'

    // In C++: delete castStrategy; castStrategy = new CastStrategyJava();
    // We import CastStrategyJava from cast.ts if available.
    // For now, we do a dynamic import approach using the cast module.
    this.castStrategy = null;
    try {
      // CastStrategyJava is exported from cast.ts
      // We avoid a circular import by using a lazy approach
      const castMod = require('./cast.js');
      if (castMod && castMod.CastStrategyJava) {
        this.castStrategy = new castMod.CastStrategyJava();
      }
    } catch {
      // cast module not available; castStrategy remains null
    }
  }

  resetDefaults(): void {
    super.resetDefaults();
    this.resetDefaultsPrintJava();
  }

  /**
   * Emit a function declaration.
   * Always assume we are in the scope of the parent class.
   */
  docFunction(fd: Funcdata): void {
    let singletonFunction = false;
    if (this.curscope === null) {
      singletonFunction = true;
      // Always assume we are in the scope of the parent class
      this.pushScope(fd.getScopeLocal().getParent());
    }
    super.docFunction(fd);
    if (singletonFunction)
      this.popScope();
  }

  /**
   * Print a data-type up to the identifier, store off array sizes
   * for printing after the identifier. Find the root type (the one with an identifier)
   * and the count number of wrapping arrays.
   * @param ct the given data-type
   * @param noident true if no identifier will be pushed with this declaration
   */
  pushTypeStart(ct: Datatype, noident: boolean): void {
    let arrayCount: int4 = 0;
    for (;;) {
      if (ct.getMetatype() === type_metatype.TYPE_PTR) {
        if (PrintJava.isArrayType(ct))
          arrayCount += 1;
        ct = (ct as TypePointer).getPtrTo();
      } else if (ct.getName().length !== 0) {
        break;
      } else {
        ct = this.glb.types.getTypeVoid();
        break;
      }
    }
    let tok: OpToken;

    if (noident)
      tok = PrintC.type_expr_nospace;
    else
      tok = PrintC.type_expr_space;

    this.pushOp(tok, null);
    for (let i: int4 = 0; i < arrayCount; ++i)
      this.pushOp(PrintC.subscript, null);

    if (ct.getName().length === 0) {    // Check for anonymous type
      // We could support a struct or enum declaration here
      const nm: string = this.genericTypeName(ct);
      this.pushAtom(makeAtom(nm, tagtype.typetoken, syntax_highlight.type_color, ct));
    } else {
      this.pushAtom(makeAtom(ct.getDisplayName(), tagtype.typetoken, syntax_highlight.type_color, ct));
    }
    for (let i: int4 = 0; i < arrayCount; ++i)
      this.pushAtom(makeAtom(PrintC.EMPTY_STRING, tagtype.blanktoken, syntax_highlight.no_color));  // Fill in the blank array index
  }

  /** Push the tail end of a data-type declaration. In Java this is a no-op. */
  pushTypeEnd(_ct: Datatype): void {
    // This routine doesn't have to do anything
  }

  /** Whether to emit a wide character prefix. Java does not use one. */
  doEmitWideCharPrefix(): boolean {
    return false;
  }

  /**
   * Adjust operator tokens for Java-specific conventions.
   * The scope operator becomes '.', and the right shift operator becomes '>>>'.
   */
  adjustTypeOperators(): void {
    PrintC.scope.print1 = '.';
    PrintC.shift_right.print1 = '>>>';
    TypeOpSelectJava(this.glb.inst, true);
  }

  /**
   * Emit a LOAD operation.
   * If the pointer dereference needs '[0]' syntax, wrap with a subscript operator.
   */
  opLoad(op: PcodeOp): void {
    const m: uint4 = this.mods | print_load_value;
    const printArrayRef: boolean = PrintJava.needZeroArray(op.getIn(1));
    if (printArrayRef)
      this.pushOp(PrintC.subscript, op);
    this.pushVn(op.getIn(1), op, m);
    if (printArrayRef)
      this.push_integer(0n, 4, false, tagtype.syntax, null, op);
  }

  /**
   * Emit a STORE operation.
   * If the pointer dereference needs '[0]' syntax, wrap with a subscript operator.
   */
  opStore(op: PcodeOp): void {
    const m: uint4 = this.mods | print_store_value;   // Inform sub-tree that we are storing
    this.pushOp(PrintC.assignment, op);                // This is an assignment
    if (PrintJava.needZeroArray(op.getIn(1))) {
      this.pushOp(PrintC.subscript, op);
      this.pushVn(op.getIn(1), op, m);
      this.push_integer(0n, 4, false, tagtype.syntax, null, op);
      this.pushVn(op.getIn(2), op, this.mods);
    } else {
      // implied vn's pushed on in reverse order for efficiency
      // see PrintLanguage::pushVnImplied
      this.pushVn(op.getIn(2), op, this.mods);
      this.pushVn(op.getIn(1), op, m);
    }
  }

  /** Emit an indirect function call. */
  opCallind(op: PcodeOp): void {
    this.pushOp(PrintC.function_call, op);
    const fd: Funcdata = op.getParent().getFuncdata();
    const fc: FuncCallSpecs = fd.getCallSpecs(op);
    if (fc === null)
      throw new LowlevelError('Missing indirect function callspec');
    const skip: int4 = this.getHiddenThisSlot(op, fc);
    let count: int4 = op.numInput() - 1;
    count -= (skip < 0) ? 0 : 1;
    if (count > 1) {    // Multiple parameters
      this.pushVn(op.getIn(0), op, this.mods);
      for (let i: int4 = 0; i < count - 1; ++i)
        this.pushOp(PrintC.comma, op);
      // implied vn's pushed on in reverse order for efficiency
      // see PrintLanguage::pushVnImplied
      for (let i: int4 = op.numInput() - 1; i >= 1; --i) {
        if (i === skip) continue;
        this.pushVn(op.getIn(i), op, this.mods);
      }
    } else if (count === 1) {  // One parameter
      if (skip === 1)
        this.pushVn(op.getIn(2), op, this.mods);
      else
        this.pushVn(op.getIn(1), op, this.mods);
      this.pushVn(op.getIn(0), op, this.mods);
    } else {                   // A void function
      this.pushVn(op.getIn(0), op, this.mods);
      this.pushAtom(makeAtom(PrintC.EMPTY_STRING, tagtype.blanktoken, syntax_highlight.no_color));
    }
  }

  /** Emit a constant pool reference operation. */
  opCpoolRefOp(op: PcodeOp): void {
    const outvn: Varnode = op.getOut();
    const vn0: Varnode = op.getIn(0);
    const refs: uintb[] = [];
    for (let i: int4 = 1; i < op.numInput(); ++i)
      refs.push(op.getIn(i).getOffset());
    const rec: CPoolRecord | null = this.glb.cpool.getRecord(refs);
    if (rec === null) {
      this.pushAtom(makeAtom('UNKNOWNREF', tagtype.syntax, syntax_highlight.const_color, op, outvn));
    } else {
      switch (rec.getTag()) {
        case CPoolRecord.string_literal:
        {
          const sw = new StringWriter();
          let len: int4 = rec.getByteDataLength();
          if (len > 2048)
            len = 2048;
          sw.write('"');
          this.escapeCharacterData(sw, rec.getByteData(), len, 1, false);
          if (len === rec.getByteDataLength())
            sw.write('"');
          else {
            sw.write('..."');
          }
          this.pushAtom(makeAtom(sw.toString(), tagtype.vartoken, syntax_highlight.const_color, op, outvn));
          break;
        }
        case CPoolRecord.class_reference:
          this.pushAtom(makeAtom(rec.getToken(), tagtype.vartoken, syntax_highlight.type_color, op, outvn));
          break;
        case CPoolRecord.instance_of:
        {
          let dt: Datatype = rec.getType();
          while (dt.getMetatype() === type_metatype.TYPE_PTR) {
            dt = (dt as TypePointer).getPtrTo();
          }
          this.pushOp(PrintJava.instanceof_op, op);
          this.pushVn(vn0, op, this.mods);
          this.pushAtom(makeAtom(dt.getDisplayName(), tagtype.syntax, syntax_highlight.type_color, op, outvn));
          break;
        }
        case CPoolRecord.primitive:       // Should be eliminated
        case CPoolRecord.pointer_method:
        case CPoolRecord.pointer_field:
        case CPoolRecord.array_length:
        case CPoolRecord.check_cast:
        default:
        {
          let ct: Datatype = rec.getType();
          let color: syntax_highlight = syntax_highlight.var_color;
          if (ct.getMetatype() === type_metatype.TYPE_PTR) {
            ct = (ct as TypePointer).getPtrTo();
            if (ct.getMetatype() === type_metatype.TYPE_CODE)
              color = syntax_highlight.funcname_color;
          }
          if (vn0.isConstant()) {    // If this is NOT relative to an object reference
            this.pushAtom(makeAtom(rec.getToken(), tagtype.vartoken, color, op, outvn));
          } else {
            this.pushOp(PrintC.object_member, op);
            this.pushVn(vn0, op, this.mods);
            this.pushAtom(makeAtom(rec.getToken(), tagtype.syntax, color, op, outvn));
          }
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Helper: call TypeOp.selectJavaOperators
// ---------------------------------------------------------------------------

/**
 * Wrapper that calls TypeOp.selectJavaOperators.
 * We import TypeOp dynamically to avoid potential circular imports.
 */
function TypeOpSelectJava(inst: (TypeOp | null)[], val: boolean): void {
  try {
    const typeOpMod = require('./typeop.js');
    if (typeOpMod && typeOpMod.TypeOp && typeOpMod.TypeOp.selectJavaOperators) {
      typeOpMod.TypeOp.selectJavaOperators(inst, val);
    }
  } catch {
    // typeop module not available
  }
}
