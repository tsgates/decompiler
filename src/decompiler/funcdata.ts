/// \file funcdata.ts
/// \brief Utilities for processing data structures associated with a single function
/// Translated from Ghidra's funcdata.hh and funcdata.cc

// ============================================================
// Imports
// ============================================================

import { Address, SeqNum } from '../core/address.js';
import { AddrSpace, spacetype } from '../core/space.js';
import { OpCode, get_booleanflip } from '../core/opcodes.js';
import { VarnodeData } from '../core/pcoderaw.js';
import { calc_mask, calc_int_min, calc_int_max, calc_uint_max } from '../core/address.js';
import { SortedSetIterator } from '../util/sorted-set.js';
import {
  Varnode,
  VarnodeBank,
  VarnodeLocSet,
  VarnodeDefSet,
} from '../decompiler/varnode.js';
import {
  PcodeOp,
  PcodeOpBank,
  PieceNode,
} from '../decompiler/op.js';
import {
  FlowBlock,
  BlockGraph,
} from '../decompiler/block.js';
import { Datatype, type_metatype } from '../decompiler/type.js';
import { FuncProto, FuncCallSpecs, ParamTrial, ParamActive, ProtoModel, EffectRecord } from '../decompiler/fspec.js';
import {
  Symbol,
  FunctionSymbol,
  SymbolEntry,
} from '../decompiler/database.js';
import { HighVariable } from '../decompiler/variable.js';
import { Cover } from '../decompiler/cover.js';
import { Override } from '../decompiler/override.js';
import { Heritage, LoadGuard } from '../decompiler/heritage.js';
import { Merge } from '../decompiler/merge.js';
import { DynamicHash } from '../decompiler/dynamic.js';
import { ResolveEdge, ResolvedUnion } from '../decompiler/unionresolve.js';
import { UserPcodeOp } from '../decompiler/userop.js';
import { Encoder, Decoder, ElementId, AttributeId, ATTRIB_NAME, ATTRIB_SIZE, ATTRIB_ID, ATTRIB_INDEX } from '../core/marshal.js';
import { Comment } from '../decompiler/comment.js';
import { FlowInfo } from '../decompiler/flow.js';
import { LowlevelError, RecovError } from '../core/error.js';
import { PcodeOpNode, TraverseNode, functionalEqualityLevel } from '../decompiler/expression.js';

// Wire up FlowInfo's forward declaration stubs (moved to end of file after Funcdata class definition)
FlowInfo._FuncCallSpecsCtor = FuncCallSpecs;

// ============================================================
// Forward declarations / type aliases for non-exported or missing types
// ============================================================

type Architecture = any;
// Pure type aliases (not used as values/constructors)
type LanedRegister = any;
type InjectPayload = any;
type InjectContext = any;
type ostream = { write(s: string): void };
type IteratorPosition = any;
type PcodeOpTreeIterator = IterableIterator<PcodeOp>;
type VarnodeLocSetIterator = IterableIterator<Varnode>;
type TypeSpacebase = any;
type PcodeOpTree = any;
type BlockBasic = any;
type TypeFactory = any;
type TypePointer = any;
type DatatypeWarning = any;
type ProtoParameter = any;
type Scope = any;
type ScopeMap = any;
type Database = any;
type UnionFacetSymbol = any;
import { PcodeEmit } from '../core/translate.js';

// Classes/constructors that need both type and value identity
import { ScopeLocal as ScopeLocalImpl } from './varmap.js';
type ScopeLocal = any;
const ScopeLocal = ScopeLocalImpl;
import { JumpTable, JumptableThunkError } from './jumptable.js';
// PcodeOpNode imported from expression.ts
// PieceNode imported from op.js
// TraverseNode imported from expression.ts
// EffectRecord imported from fspec.ts
declare class PcodeOpEvalType { [k: string]: any; static unspecialized: number; static volatile_read: number; static volatile_write: number; static segment: number; }
// UserPcodeOp imported from userop.js

// functionalEqualityLevel imported from expression.js
// get_booleanflip imported from opcodes.js

// ============================================================
// JumpTableRecoveryMode enum
// ============================================================

enum JumpTableRecoveryMode {
  success = 0,
  fail_normal = 1,
  fail_return = 2,
  fail_thunk = 3,
  fail_callother = 4,
}

// ============================================================
// Marshaling attributes and elements
// ============================================================

export const ATTRIB_NOCODE = new AttributeId('nocode', 200);

export const ELEM_AST = new ElementId('ast', 200);
export const ELEM_FUNCTION = new ElementId('function', 201);
export const ELEM_HIGHLIST = new ElementId('highlist', 202);
export const ELEM_JUMPTABLELIST = new ElementId('jumptablelist', 203);
export const ELEM_VARNODES = new ElementId('varnodes', 204);
export const ELEM_BLOCK = new ElementId('block', 205);
export const ELEM_BLOCKEDGE = new ElementId('blockedge', 206);
export const ELEM_LOCALDB = new ElementId('localdb', 207);
export const ELEM_OVERRIDE = new ElementId('override', 208);
export const ELEM_PROTOTYPE = new ElementId('prototype', 209);

export const ATTRIB_LABEL = new AttributeId('label', 204);
export { ATTRIB_NAME, ATTRIB_SIZE, ATTRIB_ID, ATTRIB_INDEX };

// ============================================================
// Constants for address space types
// ============================================================

const IPTR_FSPEC = spacetype.IPTR_FSPEC;
const IPTR_IOP = spacetype.IPTR_IOP;

// ============================================================
// Type alias for C++ ostream equivalent
// ============================================================

type OStream = { write(s: string): void };

// Import and re-export ListIter from utility module
import { ListIter } from '../util/listiter.js';
export { ListIter } from '../util/listiter.js';

// ============================================================
// PcodeEmitFd class
// ============================================================

/// A p-code emitter for building PcodeOp objects.
/// The emitter is attached to a specific Funcdata object. Any p-code generated
/// (by FlowInfo typically) will be instantiated as PcodeOp and Varnode objects
/// and placed in the Funcdata dead list.
export class PcodeEmitFd extends PcodeEmit {
  private fd: Funcdata | null = null;

  setFuncdata(f: Funcdata): void {
    this.fd = f;
  }

  dump(addr: Address, opc: OpCode, outvar: VarnodeData | null, vars: VarnodeData[], isize: number): void {
    const fd = this.fd!;
    let op: PcodeOp;

    if (outvar !== null) {
      const oaddr = new Address(outvar.space as any, outvar.offset);
      op = fd.newOp(isize, addr);
      fd.newVarnodeOut(outvar.size, oaddr, op);
    } else {
      op = fd.newOp(isize, addr);
    }
    fd.opSetOpcode(op, opc);
    let i = 0;
    if (op.isCodeRef()) {
      // First input parameter is a code reference
      const addrcode = new Address(vars[0].space as any, vars[0].offset);
      fd.opSetInput(op, fd.newCodeRef(addrcode), 0);
      i += 1;
    }
    for (; i < isize; ++i) {
      const vn = fd.newVarnode(vars[i].size, new Address(vars[i].space as any, vars[i].offset));
      fd.opSetInput(op, vn, i);
    }
  }
}

// ============================================================
// Funcdata class
// ============================================================

/// Container for data structures associated with a single function.
///
/// This class holds the primary data structures for decompiling a function.
/// In particular it holds control-flow, data-flow, and prototype information,
/// plus class instances to help with constructing SSA form, structure
/// control-flow, recover jump-tables, recover parameters, and merge Varnodes.
export class Funcdata {
  // ---- Private enum-like flags ----
  private static readonly highlevel_on       = 1;
  private static readonly blocks_generated   = 2;
  private static readonly blocks_unreachable = 4;
  private static readonly processing_started = 8;
  private static readonly processing_complete = 0x10;
  private static readonly typerecovery_on    = 0x20;
  private static readonly typerecovery_start = 0x40;
  private static readonly no_code            = 0x80;
  private static readonly jumptablerecovery_on   = 0x100;
  private static readonly jumptablerecovery_dont = 0x200;
  private static readonly restart_pending        = 0x400;
  private static readonly unimplemented_present  = 0x800;
  private static readonly baddata_present        = 0x1000;
  private static readonly double_precis_on       = 0x2000;
  private static readonly typerecovery_exceeded  = 0x4000;

  // ---- Fields (properties) ----
  private flags: number;                      ///< Boolean properties associated with this function
  private clean_up_index: number;             ///< Creation index of first Varnode created after start of cleanup
  private high_level_index: number;           ///< Creation index of first Varnode created after HighVariables are created
  private cast_phase_index: number;           ///< Creation index of first Varnode created after ActionSetCasts
  private minLanedSize: number;               ///< Minimum Varnode size to check as LanedRegister
  private size: number;                       ///< Number of bytes of binary data in function body
  private glb: Architecture;                  ///< Global configuration data
  private functionSymbol: FunctionSymbol | null; ///< The symbol representing this function
  private name: string;                       ///< Name of function
  private displayName: string;                ///< Name to display in output
  private baseaddr: Address;                  ///< Starting code address of binary data
  private funcp: FuncProto;                   ///< Prototype of this function
  private localmap: ScopeLocal | null;        ///< Local variables (symbols in the function scope)

  private qlst: FuncCallSpecs[];              ///< List of calls this function makes
  private jumpvec: JumpTable[];               ///< List of jump-tables for this function

  private vbank: VarnodeBank;                 ///< Container of Varnode objects for this function
  private obank: PcodeOpBank;                 ///< Container of PcodeOp objects for this function
  private bblocks: BlockGraph;                ///< Unstructured basic blocks
  private sblocks: BlockGraph;                ///< Structured block hierarchy (on top of basic blocks)
  private heritage: Heritage;                 ///< Manager for maintaining SSA form
  private covermerge: Merge;                  ///< Variable range intersection algorithms
  private activeoutput: ParamActive | null;   ///< Data for assessing which parameters are passed to this function
  private localoverride: Override;            ///< Overrides of data-flow, prototypes, etc. that are local to this function
  private lanedMap: Map<string, LanedRegister>; ///< Current storage locations which may be laned registers (keyed by VarnodeData key)
  private unionMap: Map<string, ResolvedUnion>; ///< A map from data-flow edges to the resolved field of TypeUnion being accessed

  // ============================================================
  // Constructor
  // ============================================================

  /// \param nm is the (base) name of the function, as a formal symbol
  /// \param disp is the name used when displaying the function name in output
  /// \param scope is Symbol scope associated with the function
  /// \param addr is the entry address for the function
  /// \param sym is the symbol representing the function
  /// \param sz is the number of bytes (of code) in the function body
  constructor(nm: string, disp: string, scope: Scope, addr: Address, sym: FunctionSymbol | null, sz: number = 0) {
    this.baseaddr = addr;
    this.funcp = new FuncProto();
    this.vbank = new VarnodeBank(scope.getArch());
    this.heritage = new Heritage(this);
    this.covermerge = new Merge(this);
    this.obank = new PcodeOpBank();
    this.bblocks = new BlockGraph();
    this.sblocks = new BlockGraph();
    this.localoverride = new Override();
    this.lanedMap = new Map<string, LanedRegister>();
    this.unionMap = new Map<string, ResolvedUnion>();
    this.qlst = [];
    this.jumpvec = [];

    this.functionSymbol = sym;
    this.flags = 0;
    this.clean_up_index = 0;
    this.high_level_index = 0;
    this.cast_phase_index = 0;
    this.glb = scope.getArch();
    this.minLanedSize = this.glb.getMinimumLanedRegisterSize();
    this.name = nm;
    this.displayName = disp;

    this.size = sz;
    const stackid: AddrSpace = this.glb.getStackSpace();
    if (nm.length === 0) {
      this.localmap = null;   // Filled in by decode
    } else {
      let id: bigint;
      if (sym !== null) {
        id = sym.getId();
      } else {
        // Missing a symbol, build unique id based on address
        id = BigInt(0x57AB12CD);
        id = (id << 32n) | (addr.getOffset() & 0xffffffffn);
      }
      const newMap = new ScopeLocal(id, stackid, this, this.glb);
      this.glb.symboltab.attachScope(newMap, scope);   // This may throw and delete newMap
      this.localmap = newMap;
      this.funcp.setScope(this.localmap, this.baseaddr.add(-1n));
      this.localmap!.resetLocalWindow();
    }
    this.activeoutput = null;
  }

  // ============================================================
  // Destructor
  // ============================================================

  /// Destructor - clean up owned resources.
  /// Mirrors the C++ ~Funcdata() destructor: removes the local scope from the
  /// database so that the scope id can be reused if the function is re-analysed.
  destroy(): void {
    if (this.localmap !== null && this.glb !== null) {
      this.glb.symboltab.deleteScope(this.localmap);
      this.localmap = null;
    }
    this.clearCallSpecs();
    for (let i = 0; i < this.jumpvec.length; ++i) {
      // delete jumpvec[i]
    }
    this.jumpvec = [];
    this.glb = null;
  }

  /// Alias for destroy() -- mirrors C++ destructor cleanup.
  /// TypeScript has no automatic destructors, so callers must invoke this
  /// explicitly in finally blocks or error-recovery paths.
  dispose(): void {
    this.destroy();
  }

  // ============================================================
  // Simple accessors (inline in .hh)
  // ============================================================

  /// Get the function's local symbol name
  getName(): string { return this.name; }

  /// Get the name to display in output
  getDisplayName(): string { return this.displayName; }

  /// Get the entry point address
  getAddress(): Address { return this.baseaddr; }

  /// Get the function body size in bytes
  getSize(): number { return this.size; }

  /// Get the program/architecture owning this function
  getArch(): Architecture { return this.glb; }

  /// Return the symbol associated with this function
  getSymbol(): FunctionSymbol | null { return this.functionSymbol; }

  /// Are high-level variables assigned to Varnodes
  isHighOn(): boolean { return (this.flags & Funcdata.highlevel_on) !== 0; }

  /// Has processing of the function started
  isProcStarted(): boolean { return (this.flags & Funcdata.processing_started) !== 0; }

  /// Is processing of the function complete
  isProcComplete(): boolean { return (this.flags & Funcdata.processing_complete) !== 0; }

  /// Did this function exhibit unreachable code
  hasUnreachableBlocks(): boolean { return (this.flags & Funcdata.blocks_unreachable) !== 0; }

  /// Will data-type analysis be performed
  isTypeRecoveryOn(): boolean { return (this.flags & Funcdata.typerecovery_on) !== 0; }

  /// Has data-type recovery processes started
  hasTypeRecoveryStarted(): boolean { return (this.flags & Funcdata.typerecovery_start) !== 0; }

  /// Has maximum propagation passes been reached
  isTypeRecoveryExceeded(): boolean { return (this.flags & Funcdata.typerecovery_exceeded) !== 0; }

  /// Return true if this function has no code body
  hasNoCode(): boolean { return (this.flags & Funcdata.no_code) !== 0; }

  /// Toggle whether this has a body
  setNoCode(val: boolean): void {
    if (val) this.flags |= Funcdata.no_code;
    else this.flags &= ~Funcdata.no_code;
  }

  /// Mark that laned registers have been collected
  setLanedRegGenerated(): void { this.minLanedSize = 1000000; }

  /// Toggle whether this is being used for jump-table recovery
  setJumptableRecovery(val: boolean): void {
    if (val) this.flags &= ~Funcdata.jumptablerecovery_dont;
    else this.flags |= Funcdata.jumptablerecovery_dont;
  }

  /// Is this used for jump-table recovery
  isJumptableRecoveryOn(): boolean { return (this.flags & Funcdata.jumptablerecovery_on) !== 0; }

  /// Toggle whether double precision analysis is used
  setDoublePrecisRecovery(val: boolean): void {
    if (val) this.flags |= Funcdata.double_precis_on;
    else this.flags &= ~Funcdata.double_precis_on;
  }

  /// Is double precision analysis enabled
  isDoublePrecisOn(): boolean { return (this.flags & Funcdata.double_precis_on) !== 0; }

  /// Return true if no block structuring was performed
  hasNoStructBlocks(): boolean { return this.sblocks.getSize() === 0; }

  /// Toggle whether data-type recovery will be performed on this function
  setTypeRecovery(val: boolean): void {
    this.flags = val ? (this.flags | Funcdata.typerecovery_on) : (this.flags & ~Funcdata.typerecovery_on);
  }

  /// Mark propagation passes have reached maximum
  setTypeRecoveryExceeded(): void { this.flags |= Funcdata.typerecovery_exceeded; }

  /// Start the cast insertion phase
  startCastPhase(): void { this.cast_phase_index = this.vbank.getCreateIndex(); }

  /// Get creation index at the start of cast insertion
  getCastPhaseIndex(): number { return this.cast_phase_index; }

  /// Get creation index at the start of HighVariable creation
  getHighLevelIndex(): number { return this.high_level_index; }

  /// Start clean-up phase
  startCleanUp(): void { this.clean_up_index = this.vbank.getCreateIndex(); }

  /// Get creation index at the start of clean-up phase
  getCleanUpIndex(): number { return this.clean_up_index; }

  /// Get the Override object for this function
  getOverride(): Override { return this.localoverride; }

  /// Toggle whether analysis needs to be restarted for this function
  setRestartPending(val: boolean): void {
    this.flags = val ? (this.flags | Funcdata.restart_pending) : (this.flags & ~Funcdata.restart_pending);
  }

  /// Does this function need to restart its analysis
  hasRestartPending(): boolean { return (this.flags & Funcdata.restart_pending) !== 0; }

  /// Does this function have instructions marked as unimplemented
  hasUnimplemented(): boolean { return (this.flags & Funcdata.unimplemented_present) !== 0; }

  /// Does this function flow into bad data
  hasBadData(): boolean { return (this.flags & Funcdata.baddata_present) !== 0; }

  /// Get overall count of heritage passes
  getHeritagePass(): number { return this.heritage.getPass(); }

  /// Get the number of heritage passes performed for the given address space
  numHeritagePasses(spc: AddrSpace): number { return this.heritage.numHeritagePasses(spc); }

  /// Mark that dead Varnodes have been seen in a specific address space
  seenDeadcode(spc: AddrSpace): void { this.heritage.seenDeadCode(spc); }

  /// Set a delay before removing dead code for a specific address space
  setDeadCodeDelay(spc: AddrSpace, delay: number): void { this.heritage.setDeadCodeDelay(spc, delay); }

  /// Check if dead code removal is allowed for a specific address space
  deadRemovalAllowed(spc: AddrSpace): boolean { return this.heritage.deadRemovalAllowed(spc); }

  /// Check if dead Varnodes have been removed for a specific address space
  deadRemovalAllowedSeen(spc: AddrSpace): boolean { return this.heritage.deadRemovalAllowedSeen(spc); }

  /// Check if a specific Varnode has been linked in fully to the syntax tree (SSA)
  isHeritaged(vn: Varnode): boolean { return this.heritage.heritagePass(vn.getAddr()) >= 0; }

  /// Get the list of guarded LOADs
  getLoadGuards(): LoadGuard[] { return this.heritage.getLoadGuards(); }

  /// Get the list of guarded STOREs
  getStoreGuards(): LoadGuard[] { return this.heritage.getStoreGuards(); }

  /// Get LoadGuard associated with STORE op
  getStoreGuard(op: PcodeOp): LoadGuard | null { return this.heritage.getStoreGuard(op); }

  // ---- Function prototype and call specification routines ----

  /// Get the number of calls made by this function
  numCalls(): number { return this.qlst.length; }

  /// Get the i-th call specification
  getCallSpecs_byIndex(i: number): FuncCallSpecs { return this.qlst[i]; }

  /// Get the call specification associated with a CALL op
  getCallSpecs(op: PcodeOp): FuncCallSpecs | null {
    const vn = op.getIn(0)!;
    if (vn.getSpace()!.getType() === IPTR_FSPEC) {
      return FuncCallSpecs.getFspecFromConst(vn.getAddr());
    }
    for (let i = 0; i < this.qlst.length; ++i) {
      if (this.qlst[i].getOp() === op) return this.qlst[i];
    }
    return null;
  }

  /// Recover and return the extrapop for this function
  fillinExtrapop(): number {
    if (this.hasNoCode()) {
      return this.funcp.getExtraPop();
    }
    if (this.funcp.getExtraPop() !== ProtoModel.extrapop_unknown) {
      return this.funcp.getExtraPop();
    }

    const iter = this.beginOp(OpCode.CPUI_RETURN);
    const result = (iter as any).next();
    if (result.done) return 0;  // If no return statements, answer is irrelevant

    const retop = result.value;
    const buffer = new Uint8Array(4);
    this.glb.loader.loadFill(buffer, 4, retop.getAddr());

    // We are assuming x86 code here
    let extrapop = 4;   // The default case
    if (buffer[0] === 0xc2) {
      extrapop = buffer[2];
      extrapop <<= 8;
      extrapop += buffer[1];
      extrapop += 4;     // extra 4 for the return address
    }
    this.funcp.setExtraPop(extrapop);
    return extrapop;
  }

  // ---- Varnode routines ----

  /// Get the total number of Varnodes
  numVarnodes(): number { return this.vbank.numVarnodes(); }

  /// Create a new Varnode given an address space and offset
  newVarnodeFromSpace(s: number, base: AddrSpace, off: bigint): Varnode {
    return (this.vbank as any).create(s, new Address(base, off));
  }

  /// Find the first input Varnode covered by the given range
  findCoveredInput(s: number, loc: Address): Varnode | null { return this.vbank.findCoveredInput(s, loc); }

  /// Find the input Varnode that contains the given range
  findCoveringInput(s: number, loc: Address): Varnode | null { return this.vbank.findCoveringInput(s, loc); }

  /// Check if an input Varnode exists that overlaps the given range
  hasInputIntersection(s: number, loc: Address): boolean { return this.vbank.hasInputIntersection(s, loc); }

  /// Find the input Varnode with the given size and storage address
  findVarnodeInput(s: number, loc: Address): Varnode | null { return this.vbank.findInput(s, loc); }

  /// Find a defined Varnode via its storage address and its definition address
  findVarnodeWritten(s: number, loc: Address, pc: Address, uniq: number = ~0 >>> 0): Varnode | null {
    return this.vbank.find(s, loc, pc, uniq);
  }

  /// Start of Varnodes sorted by storage (overloaded: no args, AddrSpace, Address, or size+Address)
  beginLoc(): SortedSetIterator<Varnode>;
  beginLoc(spaceid: AddrSpace): SortedSetIterator<Varnode>;
  beginLoc(addr: Address): SortedSetIterator<Varnode>;
  beginLoc(s: number, addr: Address): SortedSetIterator<Varnode>;
  beginLoc(arg1?: any, arg2?: any): SortedSetIterator<Varnode> {
    if (arg1 === undefined) return this.vbank.beginLoc();
    if (typeof arg1 === 'number') return this.vbank.beginLocSizeAddr(arg1, arg2);
    if (arg1 instanceof Address) return this.vbank.beginLocAddr(arg1);
    return this.vbank.beginLocSpace(arg1); // AddrSpace
  }

  /// End of Varnodes sorted by storage (overloaded: no args, AddrSpace, Address, or size+Address)
  endLoc(): SortedSetIterator<Varnode>;
  endLoc(spaceid: AddrSpace): SortedSetIterator<Varnode>;
  endLoc(addr: Address): SortedSetIterator<Varnode>;
  endLoc(s: number, addr: Address): SortedSetIterator<Varnode>;
  endLoc(arg1?: any, arg2?: any): SortedSetIterator<Varnode> {
    if (arg1 === undefined) return this.vbank.endLoc();
    if (typeof arg1 === 'number') return this.vbank.endLocSizeAddr(arg1, arg2);
    if (arg1 instanceof Address) return this.vbank.endLocAddr(arg1);
    return this.vbank.endLocSpace(arg1); // AddrSpace
  }

  /// Start of Varnodes stored in a given address space
  beginLocSpace(spaceid: AddrSpace): SortedSetIterator<Varnode> { return this.vbank.beginLocSpace(spaceid); }

  /// End of Varnodes stored in a given address space
  endLocSpace(spaceid: AddrSpace): SortedSetIterator<Varnode> { return this.vbank.endLocSpace(spaceid); }

  /// Start of Varnodes at a storage address
  beginLocAddr(addr: Address): SortedSetIterator<Varnode> { return this.vbank.beginLocAddr(addr); }

  /// End of Varnodes at a storage address
  endLocAddr(addr: Address): SortedSetIterator<Varnode> { return this.vbank.endLocAddr(addr); }

  /// Start of Varnodes with given storage (size + addr)
  beginLocSizeAddr(s: number, addr: Address): SortedSetIterator<Varnode> { return this.vbank.beginLocSizeAddr(s, addr); }

  /// End of Varnodes with given storage (size + addr)
  endLocSizeAddr(s: number, addr: Address): SortedSetIterator<Varnode> { return this.vbank.endLocSizeAddr(s, addr); }

  /// Start of Varnodes matching storage and properties
  beginLocSizeAddrFlags(s: number, addr: Address, fl: number): SortedSetIterator<Varnode> {
    return this.vbank.beginLocSizeAddrFlag(s, addr, fl);
  }

  /// End of Varnodes matching storage and properties
  endLocSizeAddrFlags(s: number, addr: Address, fl: number): SortedSetIterator<Varnode> {
    return this.vbank.endLocSizeAddrFlag(s, addr, fl);
  }

  /// Start of Varnodes matching storage and definition address
  beginLocSizeAddrPC(s: number, addr: Address, pc: Address, uniq: number = ~0 >>> 0): SortedSetIterator<Varnode> {
    return this.vbank.beginLocSizeAddrPcUniq(s, addr, pc, uniq);
  }

  /// End of Varnodes matching storage and definition address
  endLocSizeAddrPC(s: number, addr: Address, pc: Address, uniq: number = ~0 >>> 0): SortedSetIterator<Varnode> {
    return this.vbank.endLocSizeAddrPcUniq(s, addr, pc, uniq);
  }

  /// Given start, return maximal range of overlapping Varnodes
  overlapLoc(iter: IterableIterator<Varnode>, bounds: IterableIterator<Varnode>[]): number {
    return (this.vbank as any).overlapLoc(iter, bounds);
  }

  /// Start of all Varnodes sorted by definition address
  beginDef(): SortedSetIterator<Varnode> { return this.vbank.beginDef(); }

  /// End of all Varnodes sorted by definition address
  endDef(): SortedSetIterator<Varnode> { return this.vbank.endDef(); }

  /// Start of Varnodes with a given definition property
  beginDefFlags(fl: number): SortedSetIterator<Varnode> { return this.vbank.beginDefFlag(fl); }

  /// End of Varnodes with a given definition property
  endDefFlags(fl: number): SortedSetIterator<Varnode> { return this.vbank.endDefFlag(fl); }

  /// Start of (input or free) Varnodes at a given storage address
  beginDefFlagsAddr(fl: number, addr: Address): SortedSetIterator<Varnode> {
    return this.vbank.beginDefFlagAddr(fl, addr);
  }

  /// End of (input or free) Varnodes at a given storage address
  endDefFlagsAddr(fl: number, addr: Address): SortedSetIterator<Varnode> {
    return this.vbank.endDefFlagAddr(fl, addr);
  }

  /// Beginning iterator over laned accesses
  beginLaneAccess(): IterableIterator<[string, LanedRegister]> { return this.lanedMap.entries(); }

  /// Ending iterator over laned accesses
  endLaneAccess(): IterableIterator<[string, LanedRegister]> { return this.lanedMap.entries(); }

  /// Clear records from the laned access list
  clearLanedAccessMap(): void { this.lanedMap.clear(); }

  // ---- Scope / prototype accessors ----

  /// Get the local function scope
  getScopeLocal(): ScopeLocal | null { return this.localmap; }

  /// Get the function's prototype object
  getFuncProto(): FuncProto { return this.funcp; }

  /// Clear any analysis of the function's return prototype
  clearActiveOutput(): void {
    this.activeoutput = null;
  }

  /// Get the return prototype recovery object
  getActiveOutput(): ParamActive | null { return this.activeoutput; }

  /// Get the Merge object for this function
  getMerge(): Merge { return this.covermerge; }

  // ---- PcodeOp routines (inline accessors) ----

  /// Clear any dead PcodeOps
  clearDeadOps(): void { this.obank.destroyDead(); }

  // ---- PcodeOp iteration (inline accessors) ----

  /// Get begin and end iterators for alive ops at a given address.
  /// Returns [begin, end] from the same filtered array so equals() works correctly.
  beginEndOp(addr: Address): [ListIter<PcodeOp>, ListIter<PcodeOp>] {
    const list = this.obank.getAliveList();
    const filtered: PcodeOp[] = [];
    const targetOff = addr.getOffset();
    const targetSpc = addr.getSpace();
    for (let i = 0; i < list.length; i++) {
      if (list[i].getAddr().getOffset() === targetOff &&
          list[i].getAddr().getSpace() === targetSpc) {
        filtered.push(list[i]);
      }
    }
    return [new ListIter(filtered, 0), new ListIter(filtered, filtered.length)];
  }

  /// Start of PcodeOp objects with the given op-code, or at/after given address
  beginOp(opcOrAddr: OpCode | Address): ListIter<PcodeOp> {
    if (typeof opcOrAddr === 'object' && opcOrAddr !== null && typeof (opcOrAddr as any).getOffset === 'function') {
      // Address overload: find first alive op at or after this address
      const addr = opcOrAddr as Address;
      const list = this.obank.getAliveList();
      for (let i = 0; i < list.length; i++) {
        if (list[i].getAddr().getOffset() >= addr.getOffset()) {
          return new ListIter(list, i);
        }
      }
      return new ListIter(list, list.length);
    }
    const list = this.obank.getCodeList(opcOrAddr as OpCode);
    return new ListIter(list, 0);
  }

  /// End of PcodeOp objects with the given op-code, or strictly after given address
  endOp(opcOrAddr: OpCode | Address): ListIter<PcodeOp> {
    if (typeof opcOrAddr === 'object' && opcOrAddr !== null && typeof (opcOrAddr as any).getOffset === 'function') {
      // Address overload: find first alive op strictly after this address
      const addr = opcOrAddr as Address;
      const list = this.obank.getAliveList();
      for (let i = 0; i < list.length; i++) {
        if (list[i].getAddr().getOffset() > addr.getOffset()) {
          return new ListIter(list, i);
        }
      }
      return new ListIter(list, list.length);
    }
    const list = this.obank.getCodeList(opcOrAddr as OpCode);
    return new ListIter(list, list.length);
  }

  /// Start of PcodeOp objects in the alive list
  beginOpAlive(): ListIter<PcodeOp> {
    const list = this.obank.getAliveList();
    return new ListIter(list, 0);
  }

  /// End of PcodeOp objects in the alive list
  endOpAlive(): ListIter<PcodeOp> {
    const list = this.obank.getAliveList();
    return new ListIter(list, list.length);
  }

  /// Start of PcodeOp objects in the dead list
  beginOpDead(): ListIter<PcodeOp> {
    const list = this.obank.getDeadList();
    return new ListIter(list, 0);
  }

  /// End of PcodeOp objects in the dead list
  endOpDead(): ListIter<PcodeOp> {
    const list = this.obank.getDeadList();
    return new ListIter(list, list.length);
  }

  /// Start of all (alive) PcodeOp objects sorted by sequence number
  beginOpAll(): ListIter<PcodeOp> {
    const list = this.obank.getAliveList();
    return new ListIter(list, 0);
  }

  /// End of all (alive) PcodeOp objects sorted by sequence number
  endOpAll(): ListIter<PcodeOp> {
    const list = this.obank.getAliveList();
    return new ListIter(list, list.length);
  }

  /// Get an iterable of PcodeOp objects matching the given op-code
  getOpIter(opc: OpCode): PcodeOp[] { return this.obank.getCodeList(opc); }

  /// Get an iterable of all alive PcodeOp objects
  getOpAliveIter(): PcodeOp[] { return this.obank.getAliveList(); }

  /// Get an iterable of PcodeOp objects matching the given op-code (alias for getOpIter)
  getOpIterator(opc: OpCode): PcodeOp[] { return this.obank.getCodeList(opc); }

  /// Iterate all varnodes by location order
  getLocIter(): Iterable<Varnode>;
  /// Iterate varnodes in a specific address space
  getLocIter(spc: any): Iterable<Varnode>;
  /// Iterate varnodes at a specific size and address
  getLocIter(sz: number, addr: Address): Iterable<Varnode>;
  getLocIter(spcOrSz?: any, addr?: Address): Iterable<Varnode> {
    if (spcOrSz === undefined) {
      return this.vbank.getLocAll();
    }
    if (addr !== undefined) {
      // getLocIter(size, addr)
      return this.vbank.getLocSizeAddr(spcOrSz as number, addr);
    }
    // getLocIter(space)
    return this.vbank.getLocSpace(spcOrSz);
  }

  /// Iterate varnodes by location (alias)
  getLocIterator(): Iterable<Varnode> { return this.vbank.getLocAll(); }

  /// Iterate varnodes in a range
  getLocIterRange(addr: Address, endaddr: Address | null): Iterable<Varnode> {
    return this.vbank.getLocRange(addr, endaddr);
  }

  /// Iterate varnodes by definition flags
  getDefIter(fl: number): Iterable<Varnode> {
    return this.vbank.getDefFlag(fl);
  }

  /// Iterate varnodes by definition flags in a range
  getDefIterRange(fl: number): Iterable<Varnode> {
    return this.vbank.getDefFlag(fl);
  }

  /// Start of all (alive) PcodeOp objects attached to a specific Address
  beginOpAddr(addr: Address): IterableIterator<[SeqNum, PcodeOp]> { return (this.obank as any).beginAtAddr(addr); }

  /// End of all (alive) PcodeOp objects attached to a specific Address
  endOpAddr(addr: Address): IterableIterator<[SeqNum, PcodeOp]> { return (this.obank as any).endAtAddr(addr); }

  // ---- Jump-table routines (inline accessors) ----

  /// Get the number of jump-tables for this function
  numJumpTables(): number { return this.jumpvec.length; }

  /// Get the i-th jump-table
  getJumpTable(i: number): JumpTable { return this.jumpvec[i]; }

  // ---- Block routines (inline accessors) ----

  /// Get the current control-flow structuring hierarchy
  getStructure(): BlockGraph { return this.sblocks; }

  /// Get the basic blocks container
  getBasicBlocks(): BlockGraph { return this.bblocks; }

  /// Set the initial ownership range for the given basic block
  setBasicBlockRange(bb: BlockBasic, beg: Address, end: Address): void {
    bb.setInitialRange(beg, end);
  }

  // ============================================================
  // Methods from funcdata.cc
  // ============================================================

  /// Clear out old disassembly
  clear(): void {
    this.flags &= ~(Funcdata.highlevel_on | Funcdata.blocks_generated |
      Funcdata.processing_started | Funcdata.typerecovery_start |
      Funcdata.typerecovery_on | Funcdata.double_precis_on |
      Funcdata.restart_pending);
    this.clean_up_index = 0;
    this.high_level_index = 0;
    this.cast_phase_index = 0;
    this.minLanedSize = this.glb.getMinimumLanedRegisterSize();

    this.localmap!.clearUnlocked();
    this.localmap!.resetLocalWindow();

    this.clearActiveOutput();
    this.funcp.clearUnlockedOutput();
    this.unionMap.clear();
    this.clearBlocks();
    this.obank.clear();
    this.vbank.clear();
    this.clearCallSpecs();
    this.clearJumpTables();
    // Do not clear overrides
    this.heritage.clear();
    this.covermerge.clear();
  }

  /// Add a warning comment in the function body.
  /// The comment is added to the global database, indexed via its placement address and
  /// the entry address of the function.
  warning(txt: string, ad: Address): void {
    let msg: string;
    if ((this.flags & Funcdata.jumptablerecovery_on) !== 0) {
      msg = 'WARNING (jumptable): ';
    } else {
      msg = 'WARNING: ';
    }
    msg += txt;
    this.glb.commentdb.addCommentNoDuplicate(Comment.warning, this.baseaddr, ad, msg);
  }

  /// Add a warning comment as part of the function header.
  /// The warning will be emitted as part of the block comment printed right before the prototype.
  warningHeader(txt: string): void {
    let msg: string;
    if ((this.flags & Funcdata.jumptablerecovery_on) !== 0) {
      msg = 'WARNING (jumptable): ';
    } else {
      msg = 'WARNING: ';
    }
    msg += txt;
    this.glb.commentdb.addCommentNoDuplicate(Comment.warningheader, this.baseaddr, this.baseaddr, msg);
  }

  /// Start processing for this function.
  /// This routine does basic set-up for analyzing the function. In particular, it
  /// generates the raw p-code, builds basic blocks, and generates the call specification objects.
  startProcessing(): void {
    if ((this.flags & Funcdata.processing_started) !== 0) {
      throw new Error('Function processing already started');
    }
    this.flags |= Funcdata.processing_started;

    if (this.funcp.isInline()) {
      this.warningHeader('This is an inlined function');
    }
    this.localmap!.clearUnlocked();
    this.funcp.clearUnlockedOutput();
    const spc = this.baseaddr.getSpace()!;
    const baddr = new Address(spc, 0n);
    const eaddr = new Address(spc, spc.getHighest());
    this.followFlow(baddr, eaddr);
    this.structureReset();
    this.sortCallSpecs();    // Must come after structure reset
    this.heritage.buildInfoList();
    this.localoverride.applyDeadCodeDelay(this);
  }

  /// Mark that processing has completed for this function
  stopProcessing(): void {
    this.flags |= Funcdata.processing_complete;
    this.obank.destroyDead();   // Free up anything in the dead list
    if (!this.isJumptableRecoveryOn()) {
      this.issueDatatypeWarnings();
    }
  }

  /// Mark that data-type analysis has started.
  /// Returns true if this is the first call (i.e., recovery was not already started).
  startTypeRecovery(): boolean {
    if ((this.flags & Funcdata.typerecovery_start) !== 0) return false;
    this.flags |= Funcdata.typerecovery_start;
    return true;
  }

  /// Print raw p-code op descriptions to a stream.
  /// PcodeOps are grouped into their basic blocks, and within a block, ops are displayed
  /// sequentially.
  printRaw(s: OStream): void {
    if (this.bblocks.getSize() === 0) {
      if (this.obank.empty()) {
        throw new Error('No operations to print');
      }
      s.write('Raw operations: \n');
      for (const [seqnum, op] of (this.obank as any).iterAll()) {
        s.write(seqnum.toString() + ':\t');
        op.printRaw(s);
        s.write('\n');
      }
    } else {
      this.bblocks.printRaw(s);
    }
  }

  /// Mark registers that map to a virtual address space.
  /// This routine searches for and marks Varnode objects, like stack-pointer registers,
  /// that are used as a base address for a virtual address space.
  spacebase(): void {
    for (let j = 0; j < this.glb.numSpaces(); ++j) {
      const spc = this.glb.getSpace(j);
      if (spc === null) continue;
      const numspace = spc.numSpacebase();
      for (let i = 0; i < numspace; ++i) {
        const point: VarnodeData = spc.getSpacebase(i);
        const ct = this.glb.types.getTypeSpacebase(spc, this.getAddress());
        const ptr = this.glb.types.getTypePointer(point.size, ct, spc.getWordSize());

        const iter = this.vbank.beginLocSizeAddr(point.size, new Address(point.space as any, point.offset));
        const enditer = this.vbank.endLocSizeAddr(point.size, new Address(point.space as any, point.offset));
        // Iterate between iter and enditer - collect into array to avoid mutation during iteration
        const vnList: Varnode[] = [];
        for (let it = iter; !it.equals(enditer); it.next()) {
          vnList.push(it.get());
        }
        for (const vn of vnList) {
          if (vn.isFree()) continue;
          if (vn.isSpacebase()) {
            // This has already been marked spacebase.
            // We have given it a chance for descendants to be eliminated naturally,
            // now force a split if it still has multiple descendants.
            const op = vn.getDef();
            if (op !== null && op.code() === OpCode.CPUI_INT_ADD) {
              this.splitUses(vn);
            }
          } else {
            vn.setFlags(Varnode.spacebase);
            if (vn.isInput()) {
              vn.updateType(ptr, true, true);
            }
          }
        }
      }
    }
  }

  /// Construct a new spacebase register for a given address space.
  /// Given an address space, like stack, that is known to have a base register
  /// pointing to it, construct a Varnode representing that register.
  newSpacebasePtr(id: AddrSpace): Varnode {
    const point: VarnodeData = id.getSpacebase(0);
    const vn = this.newVarnode(point.size, new Address(point.space as any, point.offset));
    return vn;
  }

  /// Find the unique Varnode that holds the input value of the base register
  /// for the given address space.
  findSpacebaseInput(id: AddrSpace): Varnode | null {
    const point: VarnodeData = id.getSpacebase(0);
    const vn = this.vbank.findInput(point.size, new Address(point.space as any, point.offset));
    return vn;
  }

  /// If it doesn't exist, create an input Varnode of the base register corresponding to
  /// the given address space.
  constructSpacebaseInput(id: AddrSpace): Varnode {
    let spacePtr = this.findSpacebaseInput(id);
    if (spacePtr !== null) {
      return spacePtr;
    }
    if (id.numSpacebase() === 0) {
      throw new Error('Unable to construct pointer into space: ' + id.getName());
    }
    const point: VarnodeData = id.getSpacebase(0);
    const ct = this.glb.types.getTypeSpacebase(id, this.getAddress());
    const ptr = this.glb.types.getTypePointer(point.size, ct, id.getWordSize());
    spacePtr = this.newVarnode(point.size, point.getAddr() as any as Address, ptr);
    spacePtr = this.setInputVarnode(spacePtr);
    spacePtr.setFlags(Varnode.spacebase);
    spacePtr.updateType(ptr, true, true);
    return spacePtr;
  }

  /// Create a constant representing the base of the given global address space.
  /// The constant will have the TypeSpacebase data-type set.
  constructConstSpacebase(id: AddrSpace): Varnode {
    const ct = this.glb.types.getTypeSpacebase(id, new Address());
    const ptr = this.glb.types.getTypePointer(id.getAddrSize(), ct, id.getWordSize());
    const spacePtr = this.newConstant(id.getAddrSize(), 0n);
    spacePtr.updateType(ptr, true, true);
    spacePtr.setFlags(Varnode.spacebase);
    return spacePtr;
  }

  /// Convert a constant pointer into a ram OpCode.CPUI_PTRSUB.
  ///
  /// A constant known to be a pointer into an address space like ram is converted
  /// into a Varnode defined by OpCode.CPUI_PTRSUB, which triggers a Symbol lookup at points
  /// during analysis.
  spacebaseConstant(
    op: PcodeOp, slot: number, entry: SymbolEntry,
    rampoint: Address, origval: bigint, origsize: number
  ): void {
    const sz = rampoint.getAddrSize();
    const spaceid = rampoint.getSpace();
    let sb_type: Datatype = this.glb.types.getTypeSpacebase(spaceid!, new Address());
    sb_type = this.glb.types.getTypePointer(sz, sb_type, spaceid!.getWordSize());

    let outvn: Varnode;
    let newconst: Varnode;

    const extra: bigint = AddrSpace.byteToAddress(
      rampoint.getOffset() - entry.getAddr().getOffset(),
      rampoint.getSpace()!.getWordSize()
    );

    let addOp: PcodeOp | null = null;
    let extraOp: PcodeOp | null = null;
    let zextOp: PcodeOp | null = null;
    let subOp: PcodeOp | null = null;
    let isCopy = false;

    if (op.code() === OpCode.CPUI_COPY) {
      isCopy = true;
      if (sz < origsize) {
        zextOp = op;
      } else {
        op.insertInput(1);
        if (origsize < sz) {
          subOp = op;
        } else if (extra !== 0n) {
          extraOp = op;
        } else {
          addOp = op;
        }
      }
    }

    const spacebase_vn = this.newConstant(sz, 0n);
    spacebase_vn.updateType(sb_type, true, true);
    spacebase_vn.setFlags(Varnode.spacebase);

    if (addOp === null) {
      addOp = this.newOp(2, op.getAddr());
      this.opSetOpcode(addOp, OpCode.CPUI_PTRSUB);
      this.newUniqueOut(sz, addOp);
      this.opInsertBefore(addOp, op);
    } else {
      this.opSetOpcode(addOp, OpCode.CPUI_PTRSUB);
    }

    outvn = addOp.getOut()!;
    const newconstoff: bigint = origval - extra;
    newconst = this.newConstant(sz, newconstoff);
    newconst.setPtrCheck();

    if (spaceid!.isTruncated()) {
      addOp.setPtrFlow();
    }

    this.opSetInput(addOp, spacebase_vn, 0);
    this.opSetInput(addOp, newconst, 1);

    const sym = entry.getSymbol();
    const entrytype = sym.getType();
    const ptrentrytype = this.glb.types.getTypePointerStripArray(sz, entrytype, spaceid!.getWordSize());
    let typelock = sym.isTypeLocked();
    if (typelock && entrytype.getMetatype() === type_metatype.TYPE_UNKNOWN) {
      typelock = false;
    }
    outvn.updateType(ptrentrytype, typelock, false);

    if (extra !== 0n) {
      if (extraOp === null) {
        extraOp = this.newOp(2, op.getAddr());
        this.opSetOpcode(extraOp, OpCode.CPUI_INT_ADD);
        this.newUniqueOut(sz, extraOp);
        this.opInsertBefore(extraOp, op);
      } else {
        this.opSetOpcode(extraOp, OpCode.CPUI_INT_ADD);
      }
      const extconst = this.newConstant(sz, extra);
      extconst.setPtrCheck();
      this.opSetInput(extraOp, outvn, 0);
      this.opSetInput(extraOp, extconst, 1);
      outvn = extraOp.getOut()!;
    }

    if (sz < origsize) {
      // The new constant is smaller than the original varnode, so we extend it
      if (zextOp === null) {
        zextOp = this.newOp(1, op.getAddr());
        this.opSetOpcode(zextOp, OpCode.CPUI_INT_ZEXT);
        this.newUniqueOut(origsize, zextOp);
        this.opInsertBefore(zextOp, op);
      } else {
        this.opSetOpcode(zextOp, OpCode.CPUI_INT_ZEXT);
      }
      this.opSetInput(zextOp, outvn, 0);
      outvn = zextOp.getOut()!;
    } else if (origsize < sz) {
      // The new constant is bigger than the original varnode, truncate it
      if (subOp === null) {
        subOp = this.newOp(2, op.getAddr());
        this.opSetOpcode(subOp, OpCode.CPUI_SUBPIECE);
        this.newUniqueOut(origsize, subOp);
        this.opInsertBefore(subOp, op);
      } else {
        this.opSetOpcode(subOp, OpCode.CPUI_SUBPIECE);
      }
      this.opSetInput(subOp, outvn, 0);
      this.opSetInput(subOp, this.newConstant(4, 0n), 1);
      outvn = subOp.getOut()!;
    }

    if (!isCopy) {
      this.opSetInput(op, outvn, slot);
    }
  }

  /// Remove all call specifications
  private clearCallSpecs(): void {
    // In C++ each FuncCallSpecs is deleted; here we just clear the array.
    this.qlst = [];
  }

  /// Add warning headers for any data-types that have been modified
  private issueDatatypeWarnings(): void {
    for (const w of this.glb.types.getWarnings()) {
      this.warningHeader(w.getWarning());
    }
  }

  /// Compare call specification objects by call site address
  static compareCallspecs(a: FuncCallSpecs, b: FuncCallSpecs): number {
    const opA = a.getOp();
    const opB = b.getOp();
    if (opA === null || opA === undefined) return (opB === null || opB === undefined) ? 0 : -1;
    if (opB === null || opB === undefined) return 1;
    const parentA = opA.getParent();
    const parentB = opB.getParent();
    if (parentA === null || parentA === undefined) return (parentB === null || parentB === undefined) ? 0 : -1;
    if (parentB === null || parentB === undefined) return 1;
    const ind1 = parentA.getIndex();
    const ind2 = parentB.getIndex();
    if (ind1 !== ind2) return ind1 < ind2 ? -1 : 1;
    const ord1 = opA.getSeqNum().getOrder();
    const ord2 = opB.getSeqNum().getOrder();
    return ord1 < ord2 ? -1 : (ord1 > ord2 ? 1 : 0);
  }

  /// Sort calls using a dominance based order.
  /// Calls are put in dominance order so that earlier calls get evaluated first.
  private sortCallSpecs(): void {
    this.qlst.sort(Funcdata.compareCallspecs);
  }

  /// Remove the specification for a particular call.
  /// This is used internally if a CALL is removed (because it is unreachable).
  private deleteCallSpecs(op: PcodeOp): void {
    for (let i = 0; i < this.qlst.length; ++i) {
      if (this.qlst[i].getOp() === op) {
        this.qlst.splice(i, 1);
        return;
      }
    }
  }

  /// Print a description of all Varnodes to a stream
  printVarnodeTree(s: OStream): void {
    for (let it = this.vbank.beginDef(); !it.equals(this.vbank.endDef()); it.next()) {
      it.get().printInfo(s);
    }
  }

  /// Print description of memory ranges associated with local scopes
  printLocalRange(s: OStream): void {
    this.localmap!.printBounds(s);
    for (const [key, scope] of this.localmap!.iterChildren()) {
      scope.printBounds(s);
    }
  }

  /// Parse a <jumptablelist> element and build a JumpTable object for
  /// each <jumptable> child element.
  decodeJumpTable(decoder: Decoder): void {
    const elemId = (decoder as any).openElement(ELEM_JUMPTABLELIST);
    while (decoder.peekElement() !== 0) {
      const jt = new JumpTable(this.glb);
      jt.decode(decoder);
      this.jumpvec.push(jt);
    }
    decoder.closeElement(elemId);
  }

  /// Encode a description of jump-tables to stream
  encodeJumpTable(encoder: Encoder): void {
    if (this.jumpvec.length === 0) return;
    encoder.openElement(ELEM_JUMPTABLELIST);
    for (const jt of this.jumpvec) {
      jt.encode(encoder);
    }
    encoder.closeElement(ELEM_JUMPTABLELIST);
  }

  /// Encode descriptions for a set of Varnodes to a stream.
  /// Individual elements are written in sequence for Varnodes in a given set.
  private static encodeVarnode(
    encoder: Encoder,
    iter: IterableIterator<Varnode>,
    enditer: IterableIterator<Varnode>
  ): void {
    for (const vn of { [globalThis.Symbol.iterator]: () => iter } as any) {
      vn.encode(encoder);
    }
  }

  /// Encode a description of all HighVariables to stream.
  /// Produces a single <highlist> element with a <high> child for each
  /// high-level variable currently associated with this function.
  encodeHigh(encoder: Encoder): void {
    if (!this.isHighOn()) return;
    encoder.openElement(ELEM_HIGHLIST);
    const seen = new Set<HighVariable>();
    for (let it = this.vbank.beginLoc(); !it.equals(this.vbank.endLoc()); it.next()) {
      const vn = it.get();
      if (vn.isAnnotation()) continue;
      if (!vn.hasHigh()) continue;
      const high = vn.getHigh();
      if (seen.has(high)) continue;
      seen.add(high);
      high.encode(encoder);
    }
    encoder.closeElement(ELEM_HIGHLIST);
  }

  /// Encode a description of the p-code tree to stream.
  /// A single <ast> element is produced with children describing Varnodes, PcodeOps,
  /// and basic blocks making up this function's current syntax tree.
  encodeTree(encoder: Encoder): void {
    encoder.openElement(ELEM_AST);
    encoder.openElement(ELEM_VARNODES);
    for (let i = 0; i < this.glb.numSpaces(); ++i) {
      const base: AddrSpace | null = this.glb.getSpace(i);
      if (base === null || base.getType() === IPTR_IOP) continue;
      const iter = this.vbank.beginLocSpace(base);
      const enditer = this.vbank.endLocSpace(base);
      Funcdata.encodeVarnode(encoder, iter as any, enditer as any);
    }
    encoder.closeElement(ELEM_VARNODES);

    for (let i = 0; i < this.bblocks.getSize(); ++i) {
      const bs = this.bblocks.getBlock(i) as BlockBasic;
      encoder.openElement(ELEM_BLOCK);
      encoder.writeSignedInteger(ATTRIB_INDEX, bs.getIndex());
      bs.encodeBody(encoder);
      for (const op of bs.iterOps()) {
        op.encode(encoder);
      }
      encoder.closeElement(ELEM_BLOCK);
    }

    for (let i = 0; i < this.bblocks.getSize(); ++i) {
      const bs = this.bblocks.getBlock(i) as BlockBasic;
      if (bs.sizeIn() === 0) continue;
      encoder.openElement(ELEM_BLOCKEDGE);
      encoder.writeSignedInteger(ATTRIB_INDEX, bs.getIndex());
      bs.encodeEdges(encoder);
      encoder.closeElement(ELEM_BLOCKEDGE);
    }
    encoder.closeElement(ELEM_AST);
  }

  /// Encode a description of this function to stream.
  /// A description of this function is written to the stream, including name, address,
  /// prototype, symbol, jump-table, and override information.
  encode(encoder: Encoder, id: bigint, savetree: boolean): void {
    encoder.openElement(ELEM_FUNCTION);
    if (id !== 0n) {
      encoder.writeUnsignedInteger(ATTRIB_ID, id);
    }
    encoder.writeString(ATTRIB_NAME, this.name);
    encoder.writeSignedInteger(ATTRIB_SIZE, this.size);
    if (this.hasNoCode()) {
      encoder.writeBool(ATTRIB_NOCODE, true);
    }
    this.baseaddr.encode(encoder);

    if (!this.hasNoCode()) {
      this.localmap!.encodeRecursive(encoder, false);
    }

    if (savetree) {
      this.encodeTree(encoder);
      this.encodeHigh(encoder);
    }
    this.encodeJumpTable(encoder);
    this.funcp.encode(encoder);
    this.localoverride.encode(encoder, this.glb);
    encoder.closeElement(ELEM_FUNCTION);
  }

  /// Restore the state of this function from a stream.
  /// Parse a <function> element, recovering the name, address, prototype, symbol,
  /// jump-table, and override information for this function.
  decode(decoder: Decoder): bigint {
    this.name = '';
    this.size = -1;
    let id: bigint = 0n;
    const stackid: AddrSpace = this.glb.getStackSpace();
    const elemId = (decoder as any).openElement(ELEM_FUNCTION);

    for (;;) {
      const attribId = decoder.getNextAttributeId();
      if (attribId === 0) break;
      if (attribId === ATTRIB_NAME.getId()) {
        this.name = decoder.readString();
      } else if (attribId === ATTRIB_SIZE.getId()) {
        this.size = decoder.readSignedInteger();
      } else if (attribId === ATTRIB_ID.getId()) {
        id = decoder.readUnsignedInteger();
      } else if (attribId === ATTRIB_NOCODE.getId()) {
        if (decoder.readBool()) {
          this.flags |= Funcdata.no_code;
        }
      } else if (attribId === ATTRIB_LABEL.getId()) {
        this.displayName = decoder.readString();
      }
    }

    if (this.name.length === 0) {
      throw new Error('Missing function name');
    }
    if (this.displayName.length === 0) {
      this.displayName = this.name;
    }
    if (this.size === -1) {
      throw new Error('Missing function size');
    }

    this.baseaddr = Address.decode(decoder);

    for (;;) {
      const subId = decoder.peekElement();
      if (subId === 0) break;
      if ((subId as any) === ELEM_LOCALDB) {
        if (this.localmap !== null) {
          throw new Error('Pre-existing local scope when restoring: ' + this.name);
        }
        const newMap = new ScopeLocal(id, stackid, this, this.glb);
        this.glb.symboltab.decodeScope(decoder, newMap);
        this.localmap = newMap;
      } else if ((subId as any) === ELEM_OVERRIDE) {
        this.localoverride.decode(decoder, this.glb);
      } else if ((subId as any) === ELEM_PROTOTYPE) {
        if (this.localmap === null) {
          const newMap = new ScopeLocal(id, stackid, this, this.glb);
          const scope: Scope = this.glb.symboltab.getGlobalScope();
          this.glb.symboltab.attachScope(newMap, scope);
          this.localmap = newMap;
        }
        this.funcp.setScope(this.localmap, this.baseaddr.add(-1n));
        this.funcp.decode(decoder, this.glb);
      } else if ((subId as any) === ELEM_JUMPTABLELIST) {
        this.decodeJumpTable(decoder);
      }
    }

    decoder.closeElement(elemId);

    if (this.localmap === null) {
      // Seen neither <localdb> or <prototype>
      // This is a function shell, so we provide default locals
      const newMap = new ScopeLocal(id, stackid, this, this.glb);
      const scope: Scope = this.glb.symboltab.getGlobalScope();
      this.glb.symboltab.attachScope(newMap, scope);
      this.localmap = newMap;
      this.funcp.setScope(this.localmap, this.baseaddr.add(-1n));
    }
    this.localmap!.resetLocalWindow();
    return id;
  }

  /// Inject p-code from a payload into this live function.
  /// Raw PcodeOps are generated from the payload within a given basic block at a specific
  /// position in this function.
  doLiveInject(payload: InjectPayload, addr: Address, bl: BlockBasic, pos: IterableIterator<PcodeOp>): void {
    const emitter = new PcodeEmitFd();
    const context: InjectContext = this.glb.pcodeinjectlib.getCachedContext();

    emitter.setFuncdata(this);
    context.clear();
    context.baseaddr = addr;
    context.nextaddr = addr;

    const deadBefore = this.obank.getDeadList().slice();   // snapshot of dead ops before injection
    payload.inject(context, emitter);

    // Find newly injected ops (those in dead list that were not there before)
    const deadAfter = this.obank.getDeadList();
    const startIndex = deadBefore.length;
    for (let i = startIndex; i < deadAfter.length; ++i) {
      const op = deadAfter[i];
      if (op.isCallOrBranch()) {
        throw new Error('Illegal branching injection');
      }
      this.opInsert(op, bl, pos);
    }
  }

  /// Get the resolved union field associated with the given edge.
  /// If there is no field associated with the edge, null is returned.
  getUnionField(parent: Datatype, op: PcodeOp, slot: number): ResolvedUnion | null {
    const edge = new ResolveEdge(parent, op, slot);
    const key = (edge as any).toKey();
    const result = this.unionMap.get(key);
    if (result !== undefined) return result;
    return null;
  }

  /// Associate a union field with the given edge.
  /// If there was a previous association, it is overwritten unless it was locked.
  /// Returns true unless there was a locked association.
  setUnionField(parent: Datatype, op: PcodeOp, slot: number, resolve: ResolvedUnion): boolean {
    const edge = new ResolveEdge(parent, op, slot);
    const key = (edge as any).toKey();
    const existing = this.unionMap.get(key);
    if (existing !== undefined) {
      if (existing.isLocked()) {
        return false;
      }
      this.unionMap.set(key, resolve);
    } else {
      this.unionMap.set(key, resolve);
    }

    if (op.code() === OpCode.CPUI_MULTIEQUAL && slot >= 0) {
      // Copy resolution to any other input slots holding the same Varnode
      const vn = op.getIn(slot);
      for (let i = 0; i < op.numInput(); ++i) {
        if (i === slot) continue;
        if (op.getIn(i) !== vn) continue;
        const dupedge = new ResolveEdge(parent, op, i);
        const dupkey = (dupedge as any).toKey();
        const dupExisting = this.unionMap.get(dupkey);
        if (dupExisting !== undefined) {
          if (!dupExisting.isLocked()) {
            this.unionMap.set(dupkey, resolve);
          }
        } else {
          this.unionMap.set(dupkey, resolve);
        }
      }
    }
    return true;
  }

  /// Force a specific union field resolution for the given edge.
  /// The parent data-type is taken directly from the given Varnode.
  forceFacingType(parent: Datatype, fieldNum: number, op: PcodeOp, slot: number): void {
    let baseType: Datatype = parent;
    if (baseType.getMetatype() === type_metatype.TYPE_PTR) {
      baseType = (baseType as TypePointer).getPtrTo();
    }
    if (parent.isPointerRel()) {
      parent = this.glb.types.getTypePointer(
        parent.getSize(), baseType, (parent as TypePointer).getWordSize()
      );
    }
    const resolve = new ResolvedUnion(parent, fieldNum, this.glb.types);
    this.setUnionField(parent, op, slot, resolve);
  }

  /// Copy a read/write facing resolution for a specific data-type from one PcodeOp to another.
  inheritResolution(parent: Datatype, op: PcodeOp, slot: number, oldOp: PcodeOp, oldSlot: number): number {
    const edge = new ResolveEdge(parent, oldOp, oldSlot);
    const key = (edge as any).toKey();
    const existing = this.unionMap.get(key);
    if (existing === undefined) return -1;
    this.setUnionField(parent, op, slot, existing);
    return existing.getFieldNum();
  }

  newOpSeq(inputs: number, sq: SeqNum): PcodeOp {
    return (this.obank as any).createSeq(inputs, sq);
  }

  // =====================================================================
  // funcdata_block.cc — Funcdata methods pertaining directly to blocks
  // =====================================================================

  /// A description of each block in the current structure hierarchy is
  /// printed to stream.
  printBlockTree(s: ostream): void {
    if (this.sblocks.getSize() !== 0) {
      this.sblocks.printTree(s, 0);
    }
  }

  clearBlocks(): void {
    this.bblocks.clear();
    this.sblocks.clear();
  }

  /// Any override information is preserved.
  clearJumpTables(): void {
    const remain: JumpTable[] = [];

    for (const jt of this.jumpvec) {
      if (jt.isOverride()) {
        jt.clear();           // Clear out any derived data
        remain.push(jt);      // Keep the override itself
      }
      // else: original C++ deletes jt; in TS we just let GC handle it
    }

    this.jumpvec = remain;
  }

  /// The JumpTable object is freed, and the associated BRANCHIND is no longer
  /// marked as a switch point.
  removeJumpTable(jt: JumpTable): void {
    const remain: JumpTable[] = [];

    for (const jtEntry of this.jumpvec) {
      if (jtEntry !== jt) {
        remain.push(jtEntry);
      }
    }
    const op: PcodeOp | null = jt.getIndirectOp();
    // In C++ jt is deleted here; TS relies on GC
    if (op !== null) {
      op.getParent()!.clearFlag((FlowBlock as any).f_switch_out);
    }
    this.jumpvec = remain;
  }

  /// Assuming the given basic block is being removed, force any Varnode
  /// defined by a MULTIEQUAL in the block to be defined in the output
  /// block instead.
  pushMultiequals(bb: BlockBasic): void {
    let outblock: BlockBasic;
    let origop: PcodeOp;
    let replaceop: PcodeOp;
    let origvn: Varnode;
    let replacevn: Varnode;

    if (bb.sizeOut() === 0) return;
    if (bb.sizeOut() > 1) {
      this.warningHeader("push_multiequal on block with multiple outputs");
    }
    outblock = bb.getOut(0) as BlockBasic;
    const outblock_ind: number = bb.getOutRevIndex(0);

    for (const iterOp of bb.op) {
      origop = iterOp;
      if (origop.code() !== OpCode.CPUI_MULTIEQUAL) continue;
      origvn = origop.getOut()!;
      if (origvn.hasNoDescend()) continue;
      let needreplace = false;
      let neednewunique = false;
      for (const op of [...origvn.descend]) {
        if ((op.code() === OpCode.CPUI_MULTIEQUAL) && (op.getParent() === outblock)) {
          let deadEdge = true;
          for (let i = 0; i < op.numInput(); ++i) {
            if (i === outblock_ind) continue;
            if (op.getIn(i) === origvn) {
              deadEdge = false;
              break;
            }
          }
          if (deadEdge) {
            if (origvn.getAddr().equals(op.getOut()!.getAddr()) && origvn.isAddrTied()) {
              neednewunique = true;
            }
            continue;
          }
        }
        needreplace = true;
        break;
      }
      if (!needreplace) continue;

      // Construct artificial MULTIEQUAL
      const branches: Varnode[] = [];
      if (neednewunique) {
        replacevn = this.newUnique(origvn.getSize());
      } else {
        replacevn = this.newVarnode(origvn.getSize(), origvn.getAddr());
      }
      for (let i = 0; i < outblock.sizeIn(); ++i) {
        if (outblock.getIn(i) === bb) {
          branches.push(origvn);
        } else {
          branches.push(replacevn);
        }
      }
      replaceop = this.newOp(branches.length, outblock.getStart());
      this.opSetOpcode(replaceop, OpCode.CPUI_MULTIEQUAL);
      this.opSetOutput(replaceop, replacevn);
      this.opSetAllInput(replaceop, branches);
      this.opInsertBegin(replaceop, outblock);

      // Replace obsolete origvn with replacevn
      const descendants: PcodeOp[] = [...origvn.descend];
      for (const op of descendants) {
        for (let i = 0; i < op.numInput(); ++i) {
          if (op.getIn(i) !== origvn) continue;
          if (i === outblock_ind && op.getParent() === outblock && op.code() === OpCode.CPUI_MULTIEQUAL) {
            continue;
          }
          this.opSetInput(op, replacevn, i);
          break;
        }
      }
    }
  }

  /// If the MULTIEQUAL has no inputs, presumably the basic block is
  /// unreachable, so we treat the p-code op as a COPY from a new input
  /// Varnode.  If there is 1 input, the MULTIEQUAL is transformed directly
  /// into a COPY.
  opZeroMulti(op: PcodeOp): void {
    if (op.numInput() === 0) {
      this.opInsertInput(op, this.newVarnode(op.getOut()!.getSize(), op.getOut()!.getAddr()), 0);
      this.setInputVarnode(op.getIn(0)!);
      this.opSetOpcode(op, OpCode.CPUI_COPY);
    } else if (op.numInput() === 1) {
      this.opSetOpcode(op, OpCode.CPUI_COPY);
    }
  }

  /// Remove an outgoing branch of the given basic block.
  /// MULTIEQUAL p-code ops (in other blocks) that take inputs from
  /// the outgoing branch are patched appropriately.
  branchRemoveInternal(bb: BlockBasic, num: number): void {
    let bbout: BlockBasic;
    let op: PcodeOp;
    let blocknum: number;

    if (bb.sizeOut() === 2) {
      // If there is no decision left, remove the branch instruction
      this.opDestroy(bb.lastOp()!);
    }

    bbout = bb.getOut(num) as BlockBasic;
    blocknum = bbout.getInIndex(bb);
    this.bblocks.removeEdge(bb, bbout);

    for (let oiter = bbout.beginOp(); !oiter.equals(bbout.endOp()); oiter.next()) {
      op = oiter.get() as PcodeOp;
      if (op.code() !== OpCode.CPUI_MULTIEQUAL) continue;
      this.opRemoveInput(op, blocknum);
      this.opZeroMulti(op);
    }
  }

  /// The edge is removed from control-flow and affected MULTIEQUAL ops
  /// are adjusted.
  removeBranch(bb: BlockBasic, num: number): void {
    this.branchRemoveInternal(bb, num);
    this.structureReset();
  }

  /// Check if given Varnode has any descendants in a dead block.
  /// Remove an active basic block from the function.
  /// PcodeOps in the block are deleted.  Data-flow and control-flow
  /// are otherwise patched up.
  blockRemoveInternal(bb: BlockBasic, unreachable: boolean): void {
    let bbout: BlockBasic;
    let deadvn: Varnode;
    let op: PcodeOp;
    let deadop: PcodeOp;
    let i: number;
    let j: number;
    let blocknum: number;
    let desc_warning: boolean;

    op = bb.lastOp()!;
    if (op !== null && op.code() === OpCode.CPUI_BRANCHIND) {
      const jt: JumpTable | null = this.findJumpTable(op);
      if (jt !== null) {
        this.removeJumpTable(jt);
      }
    }
    if (!unreachable) {
      this.pushMultiequals(bb);   // Make sure data flow is preserved

      for (i = 0; i < bb.sizeOut(); ++i) {
        bbout = bb.getOut(i) as BlockBasic;
        if (bbout.isDead()) continue;
        blocknum = bbout.getInIndex(bb);
        for (const iterOp of bbout.op) {
          op = iterOp;
          if (op.code() !== OpCode.CPUI_MULTIEQUAL) continue;
          deadvn = op.getIn(blocknum)!;
          this.opRemoveInput(op, blocknum);
          deadop = deadvn.getDef()!;
          if (deadvn.isWritten() && deadop.code() === OpCode.CPUI_MULTIEQUAL && deadop.getParent() === bb) {
            // Append new branches
            for (j = 0; j < bb.sizeIn(); ++j) {
              this.opInsertInput(op, deadop.getIn(j)!, op.numInput());
            }
          } else {
            for (j = 0; j < bb.sizeIn(); ++j) {
              this.opInsertInput(op, deadvn, op.numInput());
            }
          }
          this.opZeroMulti(op);
        }
      }
    }
    this.bblocks.removeFromFlow(bb);

    desc_warning = false;
    const ops: PcodeOp[] = Array.from(bb.op);
    for (const iterOp of ops) {
      op = iterOp;
      if (op.isAssignment()) {
        deadvn = op.getOut()!;
        if (unreachable) {
          const undef: boolean = this.descend2Undef(deadvn);
          if (undef && !desc_warning) {
            this.warningHeader("Creating undefined varnodes in (possibly) reachable block");
            desc_warning = true;
          }
        }
        if (Funcdata.descendantsOutside(deadvn)) {
          throw new LowlevelError("Deleting op with descendants\n");
        }
      }
      if (op.isCall()) {
        this.deleteCallSpecs(op);
      }
      this.opDestroy(op);
    }
    this.bblocks.removeBlock(bb);
  }

  /// The block must contain only marker operations (MULTIEQUAL) and
  /// possibly a single unconditional branch operation.
  removeDoNothingBlock(bb: BlockBasic): void {
    if (bb.sizeOut() > 1) {
      throw new LowlevelError("Cannot delete a reachable block unless it has 1 out or less");
    }

    bb.setDead();
    this.blockRemoveInternal(bb, false);
    this.structureReset();
  }

  /// Remove any unreachable basic blocks.
  /// A quick check for unreachable blocks can optionally be made.
  removeUnreachableBlocks(issuewarning: boolean, checkexistence: boolean): boolean {
    const list: FlowBlock[] = [];
    let i: number;

    if (checkexistence) {
      for (i = 0; i < this.bblocks.getSize(); ++i) {
        const blk: FlowBlock = this.bblocks.getBlock(i);
        if (blk.isEntryPoint()) continue;
        if (blk.getImmedDom() === null) break;
      }
      if (i === this.bblocks.getSize()) return false;
    } else if (!this.hasUnreachableBlocks()) {
      return false;
    }

    // There must be at least one unreachable block if we reach here
    for (i = 0; i < this.bblocks.getSize(); ++i) {
      if (this.bblocks.getBlock(i).isEntryPoint()) break;
    }
    this.bblocks.collectReachable(list, this.bblocks.getBlock(i), true);

    for (i = 0; i < list.length; ++i) {
      list[i].setDead();
      if (issuewarning) {
        const bb = list[i] as BlockBasic;
        const msg =
          "Removing unreachable block (" +
          bb.getStart().getSpace().getName() +
          "," +
          bb.getStart().printRaw() +
          ")";
        this.warningHeader(msg);
      }
    }
    for (i = 0; i < list.length; ++i) {
      const bb = list[i] as BlockBasic;
      while (bb.sizeOut() > 0) {
        this.branchRemoveInternal(bb, 0);
      }
    }
    for (i = 0; i < list.length; ++i) {
      const bb = list[i] as BlockBasic;
      this.blockRemoveInternal(bb, true);
    }
    this.structureReset();
    return true;
  }

  /// Move a control-flow edge from one block to another.
  /// This is intended for eliminating switch guard artifacts.
  pushBranch(bb: BlockBasic, slot: number, bbnew: BlockBasic): void {
    const cbranch: PcodeOp = bb.lastOp()!;
    if (cbranch.code() !== OpCode.CPUI_CBRANCH || bb.sizeOut() !== 2) {
      throw new LowlevelError("Cannot push non-conditional edge");
    }
    const indop: PcodeOp = bbnew.lastOp()!;
    if (indop.code() !== OpCode.CPUI_BRANCHIND) {
      throw new LowlevelError("Can only push branch into indirect jump");
    }

    // Turn the conditional branch into a branch
    this.opRemoveInput(cbranch, 1);
    this.opSetOpcode(cbranch, OpCode.CPUI_BRANCH);
    this.bblocks.moveOutEdge(bb, slot, bbnew);
    this.structureReset();
  }

  /// Look up the jump-table object with the matching PcodeOp address,
  /// then attach the given PcodeOp to it.
  linkJumpTable(op: PcodeOp): JumpTable | null {
    for (const jt of this.jumpvec) {
      if (jt.getOpAddress().equals(op.getAddr())) {
        jt.setIndirectOp(op);
        return jt;
      }
    }
    return null;
  }

  /// Look up the jump-table object with the matching PcodeOp address.
  findJumpTable(op: PcodeOp): JumpTable | null {
    for (const jt of this.jumpvec) {
      if (jt.getOpAddress().equals(op.getAddr())) return jt;
    }
    return null;
  }

  /// The given address must have a BRANCHIND op attached to it.
  /// This is suitable for installing an override and must be called
  /// before flow has been traced.
  installJumpTable(addr: Address): JumpTable {
    if (this.isProcStarted()) {
      throw new LowlevelError("Cannot install jumptable if flow is already traced");
    }
    for (let i = 0; i < this.jumpvec.length; ++i) {
      const jt: JumpTable = this.jumpvec[i];
      if (jt.getOpAddress().equals(addr)) {
        throw new LowlevelError("Trying to install over existing jumptable");
      }
    }
    const newjt = new JumpTable(this.glb, addr);
    this.jumpvec.push(newjt);
    return newjt;
  }

  /// Recover a jump-table for a given BRANCHIND using existing flow
  /// information.
  stageJumpTable(partial: Funcdata, jt: JumpTable, op: PcodeOp, flow: FlowInfo): JumpTableRecoveryMode {
    if (!partial.isJumptableRecoveryOn()) {
      partial.flags |= Funcdata.jumptablerecovery_on;
      partial.truncatedFlow(this, flow);

      const oldactname: string = this.glb.allacts.getCurrentName();
      try {
        this.glb.allacts.setCurrent("jumptable");
        this.glb.allacts.getCurrent().reset(partial);
        this.glb.allacts.getCurrent().perform(partial);
        this.glb.allacts.setCurrent(oldactname);
      } catch (err) {
        this.glb.allacts.setCurrent(oldactname);
        if (err instanceof LowlevelError) {
          this.warning(err.explain, op.getAddr());
          return JumpTableRecoveryMode.fail_normal;
        }
        throw err;
      }
    }
    const partop: PcodeOp | null = partial.findOp(op.getSeqNum());

    if (partop === null || partop.code() !== OpCode.CPUI_BRANCHIND || !partop.getAddr().equals(op.getAddr())) {
      throw new LowlevelError("Error recovering jumptable: Bad partial clone");
    }
    if (partop.isDead()) {
      return JumpTableRecoveryMode.success;
    }

    // Test if the branch target is copied from the return address
    if (this.testForReturnAddress(partop.getIn(0)!)) {
      return JumpTableRecoveryMode.fail_return;
    }

    try {
      jt.setLoadCollect(flow.doesJumpRecord());
      jt.setIndirectOp(partop);
      if (jt.isPartial()) {
        jt.recoverMultistage(partial);
      } else {
        jt.recoverAddresses(partial);
      }
    } catch (err) {
      if (err instanceof JumptableThunkError) {
        return JumpTableRecoveryMode.fail_thunk;
      }
      if (err instanceof LowlevelError) {
        this.warning(err.explain, op.getAddr());
        return JumpTableRecoveryMode.fail_normal;
      }
      throw err;
    }
    return JumpTableRecoveryMode.success;
  }

  /// Backtrack from the BRANCHIND, looking for ops that might affect
  /// the destination.  If a CALLOTHER, which is not injected/inlined in
  /// some way, is in the flow path, we know the jump-table analysis
  /// will fail and the failure mode is returned.
  earlyJumpTableFail(op: PcodeOp): JumpTableRecoveryMode {
    let vn: Varnode = op.getIn(0)!;
    let iter: number = op.getInsertIter();
    const startiter: number = 0; // beginOpDead equivalent
    let countMax: number = 8;

    // Walk backwards through the dead list
    const deadOps = this.obank.getDeadList();
    let idx = deadOps.indexOf(op);
    if (idx < 0) return JumpTableRecoveryMode.success;

    while (idx > 0) {
      if (vn.getSize() === 1) return JumpTableRecoveryMode.success;
      countMax -= 1;
      if (countMax < 0) return JumpTableRecoveryMode.success;
      --idx;
      op = deadOps[idx];
      const outvn: Varnode | null = op.getOut();
      let outhit = false;
      if (outvn !== null) {
        outhit = vn.intersects(outvn);
      }
      if (op.getEvalType() === PcodeOp.special) {
        if (op.isCall()) {
          const opc: OpCode = op.code();
          if (opc === OpCode.CPUI_CALLOTHER) {
            const id: number = Number(op.getIn(0)!.getOffset());
            const userOpType: number = this.glb.userops.getOp(id).getType();
            if (userOpType === UserPcodeOp.injected)
              return JumpTableRecoveryMode.success;
            if (userOpType === UserPcodeOp.jumpassist)
              return JumpTableRecoveryMode.success;
            if (userOpType === UserPcodeOp.segment)
              return JumpTableRecoveryMode.success;
            if (outhit)
              return JumpTableRecoveryMode.fail_callother;
          } else {
            return JumpTableRecoveryMode.success;
          }
        } else if (op.isBranch()) {
          return JumpTableRecoveryMode.success;
        } else {
          if (op.code() === OpCode.CPUI_STORE) return JumpTableRecoveryMode.success;
          if (outhit)
            return JumpTableRecoveryMode.success;
        }
      } else if (op.getEvalType() === PcodeOp.unary) {
        if (outhit) {
          const invn: Varnode = op.getIn(0)!;
          if (invn.getSize() !== vn.getSize()) return JumpTableRecoveryMode.success;
          vn = invn;
        }
      } else if (op.getEvalType() === PcodeOp.binary) {
        if (outhit) {
          const opc: OpCode = op.code();
          if (opc !== OpCode.CPUI_INT_ADD && opc !== OpCode.CPUI_INT_SUB && opc !== OpCode.CPUI_INT_XOR)
            return JumpTableRecoveryMode.success;
          if (!op.getIn(1)!.isConstant()) return JumpTableRecoveryMode.success;
          const invn: Varnode = op.getIn(0)!;
          if (invn.getSize() !== vn.getSize()) return JumpTableRecoveryMode.success;
          vn = invn;
        }
      } else {
        if (outhit)
          return JumpTableRecoveryMode.success;
      }
    }
    return JumpTableRecoveryMode.success;
  }

  /// Recover control-flow destinations for a BRANCHIND.
  /// If an existing and complete JumpTable exists, it is returned immediately.
  /// Otherwise an attempt is made to analyze the current partial function
  /// and recover the set of destination addresses.
  recoverJumpTable(partial: Funcdata, op: PcodeOp, flow: FlowInfo, mode: { value: JumpTableRecoveryMode }): JumpTable | null {
    let jt: JumpTable | null;

    mode.value = JumpTableRecoveryMode.success;
    jt = this.linkJumpTable(op);
    if (jt !== null) {
      if (!jt.isOverride()) {
        if (!jt.isPartial())
          return jt;
      }
      mode.value = this.stageJumpTable(partial, jt, op, flow);
      if (mode.value !== JumpTableRecoveryMode.success)
        return null;
      jt.setIndirectOp(op);
      return jt;
    }

    if ((this.flags & Funcdata.jumptablerecovery_dont) !== 0)
      return null;
    mode.value = this.earlyJumpTableFail(op);
    if (mode.value !== JumpTableRecoveryMode.success)
      return null;
    const trialjt = new JumpTable(this.glb);
    mode.value = this.stageJumpTable(partial, trialjt, op, flow);
    if (mode.value !== JumpTableRecoveryMode.success)
      return null;
    const newjt = JumpTable.copyFrom(trialjt); // Make the jumptable permanent (copy)
    this.jumpvec.push(newjt);
    newjt.setIndirectOp(op);
    return newjt;
  }

  /// For each jump-table, for each address, the corresponding basic
  /// block index is computed.  This also calculates the default branch
  /// for each jump-table.
  switchOverJumpTables(flow: FlowInfo): void {
    for (const jt of this.jumpvec) {
      jt.switchOver(flow);
    }
  }

  installSwitchDefaults(): void {
    for (const jt of this.jumpvec) {
      const indop: PcodeOp = jt.getIndirectOp()!;
      const ind: BlockBasic = indop.getParent()!;
      if (jt.getDefaultBlock() !== -1) {
        ind.setDefaultSwitch(jt.getDefaultBlock());
      }
    }
  }

  /// For the current control-flow graph, (re)calculate the loop structure
  /// and dominance.  The structured hierarchy is also reset.
  structureReset(): void {
    const rootlist: FlowBlock[] = [];

    this.flags &= ~Funcdata.blocks_unreachable;
    this.bblocks.structureLoops(rootlist);
    this.bblocks.calcForwardDominator(rootlist);
    if (rootlist.length > 1) {
      this.flags |= Funcdata.blocks_unreachable;
    }

    // Check for dead jumptables
    const alivejumps: JumpTable[] = [];
    for (const jt of this.jumpvec) {
      const indop: PcodeOp = jt.getIndirectOp()!;
      if (indop.isDead()) {
        this.warningHeader("Recovered jumptable eliminated as dead code");
        // In C++ jt is deleted; in TS we let GC handle it
        continue;
      }
      alivejumps.push(jt);
    }
    this.jumpvec = alivejumps;
    this.sblocks.clear();
    this.heritage.forceRestructure();
  }

  /// Force a specific control-flow edge to be marked as unstructured.
  /// The resulting control-flow structure will have a goto statement
  /// modeling the edge.
  forceGoto(pcop: Address, pcdest: Address): boolean {
    let bl: FlowBlock;
    let bl2: FlowBlock;
    let op: PcodeOp | null;
    let op2: PcodeOp | null;

    for (let i = 0; i < this.bblocks.getSize(); ++i) {
      bl = this.bblocks.getBlock(i);
      op = bl.lastOp();
      if (op === null) continue;
      if (!op.getAddr().equals(pcop)) continue;
      for (let j = 0; j < bl.sizeOut(); ++j) {
        bl2 = bl.getOut(j);
        op2 = bl2.lastOp();
        if (op2 === null) continue;
        if (!op2.getAddr().equals(pcdest)) continue;
        bl.setGotoBranch(j);
        return true;
      }
    }
    return false;
  }

  /// Create a new basic block for holding a merged CBRANCH.
  /// Used by ConditionalJoin to do the low-level control-flow manipulation
  /// to merge identical conditional branches.
  nodeJoinCreateBlock(
    block1: BlockBasic,
    block2: BlockBasic,
    exita: BlockBasic,
    exitb: BlockBasic,
    fora_block1ishigh: boolean,
    forb_block1ishigh: boolean,
    addr: Address
  ): BlockBasic {
    const newblock: BlockBasic = this.bblocks.newBlockBasic(this);
    newblock.setFlag((FlowBlock as any).f_joined_block);
    newblock.setInitialRange(addr, addr);
    let swapa: FlowBlock;
    let swapb: FlowBlock;

    // Delete 2 of the original edges into exita and exitb
    if (fora_block1ishigh) {
      this.bblocks.removeEdge(block1, exita);
      swapa = block2;
    } else {
      this.bblocks.removeEdge(block2, exita);
      swapa = block1;
    }
    if (forb_block1ishigh) {
      this.bblocks.removeEdge(block1, exitb);
      swapb = block2;
    } else {
      this.bblocks.removeEdge(block2, exitb);
      swapb = block1;
    }

    // Move the remaining two from block1,block2 to newblock
    this.bblocks.moveOutEdge(swapa, swapa.getOutIndex(exita), newblock);
    this.bblocks.moveOutEdge(swapb, swapb.getOutIndex(exitb), newblock);

    this.bblocks.addEdge(block1, newblock);
    this.bblocks.addEdge(block2, newblock);
    this.structureReset();
    return newblock;
  }

  /// Split given basic block b along an in edge.
  /// A copy of the block is made, inheriting the same out edges but only
  /// the one indicated in edge, which is removed from the original block.
  nodeSplitBlockEdge(b: BlockBasic, inedge: number): BlockBasic {
    const a: FlowBlock = b.getIn(inedge);

    const bprime: BlockBasic = this.bblocks.newBlockBasic(this);
    bprime.setFlag((FlowBlock as any).f_duplicate_block);
    bprime.copyRange(b);
    this.bblocks.switchEdge(a, b, bprime);
    for (let i = 0; i < b.sizeOut(); ++i) {
      this.bblocks.addEdge(bprime, b.getOut(i));
    }
    return bprime;
  }

  /// Split control-flow into a basic block, duplicating its p-code into
  /// a new block.
  nodeSplit(b: BlockBasic, inedge: number): void {
    if (b.sizeOut() !== 0) {
      throw new LowlevelError("Cannot (currently) nodesplit block with out flow");
    }
    if (b.sizeIn() <= 1) {
      throw new LowlevelError("Cannot nodesplit block with only 1 in edge");
    }
    for (let i = 0; i < b.sizeIn(); ++i) {
      if (b.getIn(i).isMark()) {
        throw new LowlevelError("Cannot nodesplit block with redundant in edges");
      }
      b.setMark();
    }
    for (let i = 0; i < b.sizeIn(); ++i) {
      b.clearMark();
    }

    // Create duplicate block
    const bprime: BlockBasic = this.nodeSplitBlockEdge(b, inedge);
    const cloner = new CloneBlockOps(this);
    cloner.cloneBlock(b, bprime, inedge);

    this.structureReset();
  }

  /// Remove a basic block splitting its control-flow into two distinct paths.
  /// The given block must have 2 inputs and 2 outputs, (and no operations).
  removeFromFlowSplit(bl: BlockBasic, swap: boolean): void {
    if (!bl.emptyOp()) {
      throw new LowlevelError("Can only split the flow for an empty block");
    }
    this.bblocks.removeFromFlowSplit(bl, swap);
    this.bblocks.removeBlock(bl);
    this.structureReset();
  }

  /// Switch an outgoing edge from the given source block to flow into
  /// another block.  This does not adjust MULTIEQUAL data-flow.
  switchEdge(inblock: FlowBlock, outbefore: BlockBasic, outafter: FlowBlock): void {
    this.bblocks.switchEdge(inblock, outbefore, outafter);
    this.structureReset();
  }

  /// The given block must have a single output block, which will be
  /// removed.  The given block has the p-code from the output block
  /// concatenated to its own, and it inherits the output block's out
  /// edges.
  spliceBlockBasic(bl: BlockBasic): void {
    let outbl: BlockBasic | null = null;
    if (bl.sizeOut() === 1) {
      outbl = bl.getOut(0) as BlockBasic;
      if (outbl.sizeIn() !== 1) {
        outbl = null;
      }
    }
    if (outbl === null) {
      throw new LowlevelError("Cannot splice basic blocks");
    }

    // Remove any jump op at the end of bl
    if (!bl.emptyOp()) {
      const jumpop: PcodeOp = bl.op[bl.op.length - 1];
      if (jumpop.isBranch()) {
        this.opDestroy(jumpop);
      }
    }
    if (!outbl.emptyOp()) {
      // Check for MULTIEQUALs
      const firstop: PcodeOp = outbl.op[0];
      if (firstop.code() === OpCode.CPUI_MULTIEQUAL) {
        throw new LowlevelError("Splicing block with MULTIEQUAL");
      }
      firstop.clearFlag(PcodeOp.startbasic);

      // Move ops into bl
      const startIdx = bl.op.length;
      for (const op of outbl.op) {
        op.setParent(bl);
      }
      // Splice all ops from outbl to end of bl
      bl.op.push(...outbl.op);
      // Update basiciter for newly appended ops
      for (let i = startIdx; i < bl.op.length; i++) {
        bl.op[i].setBasicIter(i);
      }
      outbl.op.length = 0;
      bl.setOrder();
    }
    bl.mergeRange(outbl);
    this.bblocks.spliceBlock(bl);
    this.structureReset();
  }

  // =====================================================================
  // funcdata_op.cc — PcodeOp manipulation methods
  // =====================================================================

  /// Set the op-code for a specific PcodeOp
  opSetOpcode(op: PcodeOp, opc: OpCode): void {
    this.obank.changeOpcode(op, this.glb.inst[opc]);
  }

  /// Mark given OpCode.CPUI_RETURN op as a special halt
  opMarkHalt(op: PcodeOp, flag: number): void {
    if (op.code() !== OpCode.CPUI_RETURN) {
      throw new LowlevelError("Only RETURN pcode ops can be marked as halt");
    }
    flag &= (PcodeOp.halt | PcodeOp.badinstruction |
             PcodeOp.unimplemented | PcodeOp.noreturn |
             PcodeOp.missing);
    if (flag === 0) {
      throw new LowlevelError("Bad halt flag");
    }
    op.setFlag(flag);
  }

  /// Remove output Varnode from the given PcodeOp.
  /// The output Varnode becomes free but is not immediately deleted.
  opUnsetOutput(op: PcodeOp): void {
    const vn = op.getOut();
    if (vn === null) return;
    op.setOutput(null);  // This must come before makeFree
    this.vbank.makeFree(vn);
    vn.clearCover();
  }

  /// Set a specific output Varnode for the given PcodeOp
  opSetOutput(op: PcodeOp, vn: Varnode): void {
    if (vn === op.getOut()) return;  // Already set to this vn

    if (op.getOut() !== null) {
      this.opUnsetOutput(op);
    }

    if (vn.getDef() !== null) {  // If this varnode is already an output
      this.opUnsetOutput(vn.getDef()!);
    }
    vn = this.vbank.setDef(vn, op);
    this.setVarnodeProperties(vn);
    op.setOutput(vn);
  }

  /// Clear an input operand slot for the given PcodeOp.
  /// The input Varnode is unlinked from the op.
  opUnsetInput(op: PcodeOp, slot: number): void {
    const vn = op.getIn(slot)!;
    vn.eraseDescend(op);
    op.clearInput(slot);  // Must be called AFTER descend_erase
  }

  /// Set a specific input operand for the given PcodeOp
  opSetInput(op: PcodeOp, vn: Varnode, slot: number): void {
    if (vn === op.getIn(slot)) return;  // Already set to this vn
    if (vn.isConstant()) {  // Constants should have only one descendant
      if (!vn.hasNoDescend()) {
        if (!vn.isSpacebase()) {  // Unless they are a spacebase
          const cvn = this.newConstant(vn.getSize(), vn.getOffset());
          cvn.copySymbol(vn);
          vn = cvn;
        }
      }
    }

    if (op.getIn(slot) !== null) {
      this.opUnsetInput(op, slot);
    }

    vn.addDescend(op);       // Add this op to list of vn's descendants
    op.setInput(vn, slot);   // op must be up to date AFTER calling descend_add
  }


  /// Insert the given PcodeOp at a specific point in a basic block.
  /// The PcodeOp is removed from the dead list and is inserted immediately before
  /// the specified iterator.
  opInsert(op: PcodeOp, bl: BlockBasic, iter: IteratorPosition): void {
    this.obank.markAlive(op);
    bl.insert(iter, op);
  }

  /// Remove the given PcodeOp from its basic block.
  /// The op is taken out of its basic block and put into the dead list.
  /// If the removal is permanent the input and output Varnodes should be unset.
  opUninsert(op: PcodeOp): void {
    this.obank.markDead(op);
    op.getParent()!.removeOp(op);
  }

  /// Unset inputs/output and remove given PcodeOp from its basic block.
  /// The op is extricated from all its Varnode connections to the function's data-flow
  /// and removed from its basic block. This will not change block connections.
  /// The PcodeOp object remains in the dead list.
  opUnlink(op: PcodeOp): void {
    // Unlink input and output varnodes
    this.opUnsetOutput(op);
    for (let i = 0; i < op.numInput(); ++i) {
      this.opUnsetInput(op, i);
    }
    if (op.getParent() !== null) {  // Remove us from basic block
      this.opUninsert(op);
    }
  }

  /// Remove given PcodeOp and destroy its Varnode operands.
  /// All input and output Varnodes to the op are destroyed (their object resources freed),
  /// and the op is permanently moved to the dead list.
  /// To call this routine, make sure that either:
  ///   - The op has no output
  ///   - The op's output has no descendants
  ///   - or all descendants of output are also going to be destroyed
  opDestroy(op: PcodeOp): void {
    if (op.getOut() !== null) {
      this.destroyVarnode(op.getOut()!);
    }
    for (let i = 0; i < op.numInput(); ++i) {
      const vn = op.getIn(i);
      if (vn !== null) {
        this.opUnsetInput(op, i);
      }
    }
    if (op.getParent() !== null) {
      this.obank.markDead(op);
      op.getParent()!.removeOp(op);
    }
  }

  /// Remove a PcodeOp and recursively remove ops producing its inputs.
  /// The given PcodeOp is always removed. PcodeOps are recursively removed if the only data-flow
  /// path of their output is to the given op, and they are not a CALL or are otherwise special.
  opDestroyRecursive(op: PcodeOp, scratch: PcodeOp[]): void {
    scratch.length = 0;
    scratch.push(op);
    let pos = 0;
    while (pos < scratch.length) {
      op = scratch[pos];
      pos += 1;
      for (let i = 0; i < op.numInput(); ++i) {
        const vn = op.getIn(i)!;
        if (!vn!.isWritten() || vn!.isAutoLive()) continue;
        if (vn!.loneDescend() === null) continue;
        const defOp = vn!.getDef()!;
        if (defOp.isCall() || defOp.isIndirectSource()) continue;
        scratch.push(defOp);
      }
      this.opDestroy(op);
    }
  }

  /// Remove the given raw PcodeOp.
  /// This is a specialized routine for deleting an op during flow generation that has
  /// been replaced by something else. The op is expected to be dead with none of its inputs
  /// or outputs linked to anything else. Both the PcodeOp and all the input/output Varnodes are destroyed.
  opDestroyRaw(op: PcodeOp): void {
    for (let i = 0; i < op.numInput(); ++i) {
      this.destroyVarnode(op.getIn(i)!);
    }
    if (op.getOut() !== null) {
      this.destroyVarnode(op.getOut()!);
    }
    this.obank.destroy(op);
  }

  /// Set all input Varnodes for the given PcodeOp simultaneously.
  /// All previously existing input Varnodes are unset. The input slots for the
  /// op are resized and then filled in from the specified array.
  opSetAllInput(op: PcodeOp, vvec: Varnode[]): void {
    for (let i = 0; i < op.numInput(); ++i) {
      if (op.getIn(i) !== null) {
        this.opUnsetInput(op, i);
      }
    }

    op.setNumInputs(vvec.length);

    for (let i = 0; i < op.numInput(); ++i) {
      this.opSetInput(op, vvec[i], i);
    }
  }

  /// Remove a specific input slot for the given PcodeOp.
  /// The Varnode in the specified slot is unlinked from the op and the slot itself
  /// is removed. The slot index for any remaining input Varnodes coming after the
  /// specified slot is decreased by one.
  opRemoveInput(op: PcodeOp, slot: number): void {
    this.opUnsetInput(op, slot);
    op.removeInput(slot);
  }

  /// Insert a new Varnode into the operand list for the given PcodeOp.
  /// The given Varnode is set into the given operand slot. Any existing input Varnodes
  /// with slot indices equal to or greater than the specified slot are pushed into the
  /// next slot.
  opInsertInput(op: PcodeOp, vn: Varnode, slot: number): void {
    op.insertInput(slot);
    this.opSetInput(op, vn, slot);
  }

  /// Allocate a new PcodeOp with Address
  newOp(inputs: number, pc: Address): PcodeOp;
  newOp(inputs: number, sq: SeqNum): PcodeOp;
  newOp(inputs: number, pcOrSq: Address | SeqNum): PcodeOp {
    if (pcOrSq instanceof SeqNum) {
      return this.obank.createFromSeq(inputs, pcOrSq);
    }
    return this.obank.createFromAddr(inputs, pcOrSq);
  }

  /// Insert given PcodeOp before a specific op.
  /// The given PcodeOp is inserted immediately before the follow op except:
  ///  - MULTIEQUALs in a basic block all occur first
  ///  - INDIRECTs occur immediately before their op
  ///  - a branch op must be the very last op in a basic block
  opInsertBefore(op: PcodeOp, follow: PcodeOp): void {
    const parent = follow.getParent();
    if (parent === null || parent === undefined) {
      throw new LowlevelError("opInsertBefore: follow op has no parent block");
    }
    let iter = new ListIter<PcodeOp>(parent.op, follow.getBasicIter());

    if (op.code() !== OpCode.CPUI_INDIRECT) {
      // There should not be an INDIRECT immediately preceding op
      let previousop: PcodeOp;
      while (!iter.equals(parent.beginOp())) {
        iter.prev();
        previousop = iter.get() as PcodeOp;
        if (previousop.code() !== OpCode.CPUI_INDIRECT) {
          iter.next();
          break;
        }
      }
    }
    this.opInsert(op, parent, iter);
  }

  /// Insert given PcodeOp after a specific op.
  /// The given PcodeOp is inserted immediately after the prev op except:
  ///  - MULTIEQUALs in a basic block all occur first
  ///  - INDIRECTs occur immediately before their op
  ///  - a branch op must be the very last op in a basic block
  opInsertAfter(op: PcodeOp, prev: PcodeOp): void {
    if (prev.isMarker()) {
      if (prev.code() === OpCode.CPUI_INDIRECT) {
        const invn = prev.getIn(1)!;
        if (invn.getSpace()!.getType() === IPTR_IOP) {
          const targOp = PcodeOp.getOpFromConst(invn.getAddr());
          if (targOp !== null && targOp !== undefined && !targOp.isDead() && targOp.getParent() !== null) {
            prev = targOp;
          }
        }
      }
    }
    const parent = prev.getParent();
    if (parent === null || parent === undefined) {
      throw new LowlevelError("opInsertAfter: prev op has no parent block");
    }
    const basicIdx = prev.getBasicIter();
    if (basicIdx < 0) {
      throw new LowlevelError("opInsertAfter: prev op has invalid basic block iterator");
    }
    let iter = new ListIter<PcodeOp>(parent.op, basicIdx);

    iter.next();

    if (op.code() !== OpCode.CPUI_MULTIEQUAL) {
      // There should not be a MULTIEQUAL immediately after op
      let nextop: PcodeOp;
      const endOp = parent.endOp();
      while (!iter.equals(endOp)) {
        nextop = iter.get() as PcodeOp;
        iter.next();
        if (nextop.code() !== OpCode.CPUI_MULTIEQUAL) {
          iter.prev();
          break;
        }
      }
    }
    this.opInsert(op, parent, iter);
  }

  /// Insert given PcodeOp at the beginning of a basic block.
  /// The given PcodeOp is inserted as the first op in the basic block except:
  ///  - MULTIEQUALs in a basic block all occur first
  ///  - INDIRECTs occur immediately before their op
  ///  - a branch op must be the very last op in a basic block
  opInsertBegin(op: PcodeOp, bl: BlockBasic): void {
    let iter = bl.beginOp();

    if (op.code() !== OpCode.CPUI_MULTIEQUAL) {
      const endOp = bl.endOp();
      while (!iter.equals(endOp)) {
        if (iter.get().code() !== OpCode.CPUI_MULTIEQUAL) {
          break;
        }
        iter.next();
      }
    }
    this.opInsert(op, bl, iter);
  }

  /// Insert given PcodeOp at the end of a basic block.
  /// The given PcodeOp is inserted as the last op in the basic block except:
  ///  - MULTIEQUALs in a basic block all occur first
  ///  - INDIRECTs occur immediately before their op
  ///  - a branch op must be the very last op in a basic block
  opInsertEnd(op: PcodeOp, bl: BlockBasic): void {
    let iter = bl.endOp();

    if (!iter.equals(bl.beginOp())) {
      iter.prev();
      if (!iter.get().isFlowBreak()) {
        iter.next();
      }
    }
    this.opInsert(op, bl, iter);
  }

  /// Create an INT_ADD PcodeOp calculating an offset to the spacebase register.
  /// The spacebase register is looked up for the given address space, or an optional previously
  /// existing register Varnode can be provided. An insertion point op must be provided,
  /// and newly generated ops can come either before or after this insertion point.
  createStackRef(spc: AddrSpace, off: bigint, op: PcodeOp, stackptr: Varnode | null, insertafter: boolean): Varnode {
    // Calculate CURRENT stackpointer as base for relative offset
    if (stackptr === null) {  // If we are not reusing an old reference to the stack pointer
      stackptr = this.newSpacebasePtr(spc);  // create a new reference
    }
    const addrsize = stackptr.getSize();
    const addop = this.newOp(2, op.getAddr());
    this.opSetOpcode(addop, OpCode.CPUI_INT_ADD);
    let addout = this.newUniqueOut(addrsize, addop);
    this.opSetInput(addop, stackptr, 0);
    off = AddrSpace.byteToAddress(off, spc.getWordSize());
    this.opSetInput(addop, this.newConstant(addrsize, off), 1);
    if (insertafter) {
      this.opInsertAfter(addop, op);
    } else {
      this.opInsertBefore(addop, op);
    }

    const containerid = spc.getContain()!;
    const segdef = this.glb.userops.getSegmentOp(containerid.getIndex());

    if (segdef !== null) {
      const segop = this.newOp(3, op.getAddr());
      this.opSetOpcode(segop, OpCode.CPUI_SEGMENTOP);
      const segout = this.newUniqueOut(containerid.getAddrSize(), segop);
      this.opSetInput(segop, this.newVarnodeSpace(containerid), 0);
      this.opSetInput(segop, this.newConstant(segdef.getBaseSize(), 0n), 1);
      this.opSetInput(segop, addout, 2);
      this.opInsertAfter(segop, addop);  // Make sure segop comes after addop regardless if before/after op
      addout = segout;
    }

    return addout;
  }

  /// Create a STORE expression at an offset relative to a spacebase register for a given address space.
  /// The spacebase register is looked up for the given address space. An insertion point
  /// op must be provided, and newly generated ops can come either before or after this insertion point.
  /// The Varnode value being stored must still be set on the returned PcodeOp.
  opStackStore(spc: AddrSpace, off: bigint, op: PcodeOp, insertafter: boolean): PcodeOp {
    // Calculate CURRENT stackpointer as base for relative offset
    const addout = this.createStackRef(spc, off, op, null, insertafter);

    const storeop = this.newOp(3, op.getAddr());
    this.opSetOpcode(storeop, OpCode.CPUI_STORE);

    this.opSetInput(storeop, this.newVarnodeSpace(spc.getContain()!), 0);
    this.opSetInput(storeop, addout, 1);
    this.opInsertAfter(storeop, addout.getDef()!);  // STORE comes after stack building op, regardless of insertafter
    return storeop;
  }

  /// Create a LOAD expression at an offset relative to a spacebase register for a given address space.
  /// The spacebase register is looked up for the given address space, or an optional previously
  /// existing register Varnode can be provided. An insertion point op must be provided,
  /// and newly generated ops can come either before or after this insertion point.
  opStackLoad(spc: AddrSpace, off: bigint, sz: number, op: PcodeOp, stackref: Varnode | null, insertafter: boolean): Varnode {
    const addout = this.createStackRef(spc, off, op, stackref, insertafter);
    const loadop = this.newOp(2, op.getAddr());
    this.opSetOpcode(loadop, OpCode.CPUI_LOAD);
    this.opSetInput(loadop, this.newVarnodeSpace(spc.getContain()!), 0);
    this.opSetInput(loadop, addout, 1);
    const res = this.newUniqueOut(sz, loadop);
    this.opInsertAfter(loadop, addout.getDef()!);  // LOAD comes after stack building op, regardless of insertafter
    return res;
  }

  /// Construct the boolean negation of a given boolean Varnode into a temporary register
  opBoolNegate(vn: Varnode, op: PcodeOp, insertafter: boolean): Varnode {
    const negateop = this.newOp(1, op.getAddr());
    this.opSetOpcode(negateop, OpCode.CPUI_BOOL_NEGATE);
    const resvn = this.newUniqueOut(1, negateop);
    this.opSetInput(negateop, vn, 0);
    if (insertafter) {
      this.opInsertAfter(negateop, op);
    } else {
      this.opInsertBefore(negateop, op);
    }
    return resvn;
  }

  /// Convert the given OpCode.CPUI_PTRADD into the equivalent OpCode.CPUI_INT_ADD. This may involve inserting a
  /// OpCode.CPUI_INT_MULT PcodeOp. If finalization is requested and a new PcodeOp is needed, the output
  /// Varnode is marked as implicit and has its data-type set.
  opUndoPtradd(op: PcodeOp, finalize: boolean): void {
    const multVn = op.getIn(2)!;
    const multSize = Number(multVn!.getOffset());  // Size the PTRADD thinks we are pointing

    this.opRemoveInput(op, 2);
    this.opSetOpcode(op, OpCode.CPUI_INT_ADD);
    if (multSize === 1) return;  // If no multiplier, we are done
    const offVn = op.getIn(1)!;
    if (offVn!.isConstant()) {
      let newVal = BigInt(multSize) * offVn!.getOffset();
      newVal &= calc_mask(offVn!.getSize());
      const newOffVn = this.newConstant(offVn!.getSize(), newVal);
      if (finalize) {
        newOffVn.updateType(offVn!.getTypeReadFacing(op));
      }
      this.opSetInput(op, newOffVn, 1);
      return;
    }
    const multOp = this.newOp(2, op.getAddr());
    this.opSetOpcode(multOp, OpCode.CPUI_INT_MULT);
    const addVn = this.newUniqueOut(offVn!.getSize(), multOp);
    if (finalize) {
      addVn.updateType(multVn!.getType());
      addVn.setImplied();
    }
    this.opSetInput(multOp, offVn!, 0);
    this.opSetInput(multOp, multVn!, 1);
    this.opSetInput(op, addVn, 1);
    this.opInsertBefore(multOp, op);
  }

  /// Make a clone of the given PcodeOp, copying control-flow properties as well.
  /// The data-type is not cloned.
  cloneOp(op: PcodeOp, seq: SeqNum): PcodeOp {
    const newop = this.newOp(op.numInput(), seq);
    this.opSetOpcode(newop, op.code());
    const fl = op.flags & (PcodeOp.startmark | PcodeOp.startbasic);
    newop.setFlag(fl);
    if (op.getOut() !== null) {
      this.opSetOutput(newop, this.cloneVarnode(op.getOut()!));
    }
    for (let i = 0; i < op.numInput(); ++i) {
      this.opSetInput(newop, this.cloneVarnode(op.getIn(i)!), i);
    }
    return newop;
  }

  /// Return the first OpCode.CPUI_RETURN operation that is not dead or an artificial halt.
  getFirstReturnOp(): PcodeOp | null {
    const iterend = this.endOp(OpCode.CPUI_RETURN);
    for (let iter = this.beginOp(OpCode.CPUI_RETURN); !iter.equals(iterend); iter.next()) {
      const retop = iter.get();
      if (retop.isDead()) continue;
      if (retop.getHaltType() !== 0) continue;
      return retop;
    }
    return null;
  }

  /// Create new PcodeOp with 2 or 3 given operands.
  /// The new op will have a unique space output Varnode and will be inserted before
  /// the given follow op.
  newOpBefore(follow: PcodeOp, opc: OpCode, in1: Varnode, in2: Varnode, in3: Varnode | null = null): PcodeOp {
    const sz = (in3 === null) ? 2 : 3;
    const newop = this.newOp(sz, follow.getAddr());
    this.opSetOpcode(newop, opc);
    this.newUniqueOut(in1.getSize(), newop);
    this.opSetInput(newop, in1, 0);
    this.opSetInput(newop, in2, 1);
    if (sz === 3) {
      this.opSetInput(newop, in3!, 2);
    }
    this.opInsertBefore(newop, follow);
    return newop;
  }

  /// Create a new OpCode.CPUI_INDIRECT around a PcodeOp with an indirect effect.
  /// Typically this is used to annotate data-flow, for the given storage range, passing
  /// through a CALL or STORE. An output Varnode is automatically created.
  newIndirectOp(indeffect: PcodeOp, addr: Address, sz: number, extraFlags: number): PcodeOp {
    const newin = this.newVarnode(sz, addr);
    const newop = this.newOp(2, indeffect.getAddr());
    newop.flags |= extraFlags;
    this.newVarnodeOut(sz, addr, newop);
    this.opSetOpcode(newop, OpCode.CPUI_INDIRECT);
    this.opSetInput(newop, newin, 0);
    this.opSetInput(newop, this.newVarnodeIop(indeffect), 1);
    this.opInsertBefore(newop, indeffect);
    return newop;
  }

  /// Build a OpCode.CPUI_INDIRECT op that indirectly creates a Varnode.
  /// An indirectly created Varnode effectively has no data-flow before the INDIRECT op
  /// that defines it, and the value contained by the Varnode is not explicitly calculable.
  /// The new Varnode is allocated with a given storage range.
  newIndirectCreation(indeffect: PcodeOp, addr: Address, sz: number, possibleout: boolean): PcodeOp {
    const newin = this.newConstant(sz, 0n);
    const newop = this.newOp(2, indeffect.getAddr());
    newop.flags |= PcodeOp.indirect_creation;
    const newout = this.newVarnodeOut(sz, addr, newop);
    if (!possibleout) {
      newin.flags |= Varnode.indirect_creation;
    }
    newout.flags |= Varnode.indirect_creation;
    this.opSetOpcode(newop, OpCode.CPUI_INDIRECT);
    this.opSetInput(newop, newin, 0);
    this.opSetInput(newop, this.newVarnodeIop(indeffect), 1);
    this.opInsertBefore(newop, indeffect);
    return newop;
  }

  /// Convert OpCode.CPUI_INDIRECT into an indirect creation.
  /// Data-flow through the given OpCode.CPUI_INDIRECT op is marked so that the output Varnode
  /// is considered indirectly created.
  markIndirectCreation(indop: PcodeOp, possibleOutput: boolean): void {
    const outvn = indop.getOut()!;
    const in0 = indop.getIn(0)!;

    indop.flags |= PcodeOp.indirect_creation;
    if (!in0!.isConstant()) {
      throw new LowlevelError("Indirect creation not properly formed");
    }
    if (!possibleOutput) {
      in0!.flags |= Varnode.indirect_creation;
    }
    outvn.flags |= Varnode.indirect_creation;
  }

  /// Mark COPY as returning a global value
  markReturnCopy(op: PcodeOp): void {
    op.flags |= PcodeOp.return_copy;
  }

  /// Generate raw p-code for the function.
  /// Follow flow from the entry point generating PcodeOps for each instruction encountered.
  /// The caller can provide a bounding range that constrains where control can flow to.
  followFlow(baddr: Address, eaddr: Address): void {
    if (!this.obank.empty()) {
      if ((this.flags & Funcdata.blocks_generated) === 0) {
        // Function was previously loaded for inlining (obank populated but blocks not generated).
        // Clear the stale analysis so we can proceed with a fresh decompilation.
        this.obank.clear();
        this.vbank.clear();
      } else {
        return;  // Already translated
      }
    }

    let fl: number = 0;
    fl |= this.glb.flowoptions;  // Global flow options
    const flow = new FlowInfo(this, this.obank, this.bblocks, this.qlst);
    flow.setRange(baddr, eaddr);
    flow.setFlags(fl);
    flow.setMaximumInstructions(this.glb.max_instructions);
    flow.generateOps();
    this.size = flow.getSize();

    flow.generateBlocks();
    this.flags |= Funcdata.blocks_generated;
    this.switchOverJumpTables(flow);
    if (flow.hasUnimplemented()) {
      this.flags |= Funcdata.unimplemented_present;
    }
    if (flow.hasBadData()) {
      this.flags |= Funcdata.baddata_present;
    }
  }

  /// Generate a clone with truncated control-flow given a partial function.
  /// Existing p-code is cloned from another function whose flow has not been completely
  /// followed. Artificial halt operators are inserted wherever flow is incomplete and
  /// basic blocks are generated.
  truncatedFlow(fd: Funcdata, flow: FlowInfo): void {
    if (!this.obank.empty()) {
      throw new LowlevelError("Trying to do truncated flow on pre-existing pcode");
    }

    // Clone the raw pcode
    for (let i = fd.obank.beginDead(); i < fd.obank.endDead(); i++) {
      const op = fd.obank.getDeadOp(i);
      this.cloneOp(op, op.getSeqNum());
    }
    this.obank.setUniqId(fd.obank.getUniqId());

    // Clone callspecs
    for (let i = 0; i < fd.qlst.length; ++i) {
      const oldspec = fd.qlst[i];
      const newop = this.findOp(oldspec.getOp().getSeqNum())!;
      const newspec = oldspec.cloneOp(newop);
      const invn0 = newop.getIn(0)!;
      if (invn0.getSpace()!.getType() === IPTR_FSPEC) {  // Replace embedded pointer to callspec
        const newvn0 = this.newVarnodeCallSpecs(newspec);
        this.opSetInput(newop, newvn0, 0);
        this.deleteVarnode(invn0);
      }
      this.qlst.push(newspec);
    }

    // Clone the jumptables
    for (const jt of fd.jumpvec) {
      const indop = jt.getIndirectOp();
      if (indop === null) {  // If indirect op has not been linked, this is probably a jumptable override
        continue;            // that has not been reached by the flow yet, so we ignore/truncate it
      }
      const newop = this.findOp(indop.getSeqNum());
      if (newop === null) {
        throw new LowlevelError("Could not trace jumptable across partial clone");
      }
      const jtclone = new JumpTable(jt);
      jtclone.setIndirectOp(newop);
      this.jumpvec.push(jtclone);
    }

    const partialflow = new FlowInfo(this, this.obank, this.bblocks, this.qlst, flow);  // Clone the flow
    if (partialflow.hasInject()) {
      partialflow.injectPcode();
    }
    // Clear error reporting flags
    // Keep possible unreachable flag
    partialflow.clearFlags(~FlowInfo.possible_unreachable);

    partialflow.generateBlocks();  // Generate basic blocks for partial flow
    this.flags |= Funcdata.blocks_generated;
  }

  /// In-line the p-code from another function into this function.
  /// Raw PcodeOps for the in-line function are generated and then cloned into
  /// this function. Depending on the control-flow complexity of the in-line
  /// function, the PcodeOps are injected as if they are all part of the call site
  /// address (EZModel), or the PcodeOps preserve their address and extra branch
  /// instructions are inserted to integrate control-flow of the in-line into
  /// the calling function.
  /// Returns 0 for a successful inlining with the easy model, 1 for the hard model,
  /// -1 if inlining was not successful.
  inlineFlow(inlinefd: Funcdata, flow: FlowInfo, callop: PcodeOp): number {
    inlinefd.getArch().clearAnalysis(inlinefd);
    const inlineflow = new FlowInfo(inlinefd, inlinefd.obank, inlinefd.bblocks, inlinefd.qlst);
    inlinefd.obank.setUniqId(this.obank.getUniqId());

    // Generate the pcode ops to be inlined
    const inlineSpc = this.baseaddr.getSpace()!;
    const baddr = new Address(inlineSpc, 0n);
    const eaddr = new Address(inlineSpc, inlineSpc.getHighest());
    inlineflow.setRange(baddr, eaddr);
    inlineflow.setFlags(FlowInfo.error_outofbounds | FlowInfo.error_unimplemented |
                        FlowInfo.error_reinterpreted | FlowInfo.flow_forinline);
    inlineflow.forwardRecursion(flow);
    inlineflow.generateOps();

    let res: number;
    if (inlineflow.checkEZModel()) {
      res = 0;
      // With an EZ clone there are no jumptables to clone
      const deadEndBefore = this.obank.endDead();
      flow.inlineEZClone(inlineflow, callop.getAddr());
      const deadEndAfter = this.obank.endDead();
      if (deadEndAfter > deadEndBefore) {  // If there was at least one PcodeOp cloned
        const firstop = this.obank.getDeadOp(deadEndBefore);
        const lastop = this.obank.getDeadOp(deadEndAfter - 1);
        this.obank.moveSequenceDead(firstop, lastop, callop);  // Move cloned sequence to right after callop
        if (callop.isBlockStart()) {
          firstop.setFlag(PcodeOp.startbasic);  // First op of inline inherits callop's startbasic flag
          flow.updateTarget(callop, firstop);
        } else {
          firstop.clearFlag(PcodeOp.startbasic);
        }
      }
      this.opDestroyRaw(callop);
    } else {
      const retaddr: Address = new Address();
      if (!flow.testHardInlineRestrictions(inlinefd, callop, retaddr)) {
        return -1;
      }
      res = 1;
      // Clone any jumptables from inline piece
      for (const jt of inlinefd.jumpvec) {
        const jtclone = new JumpTable(jt);
        this.jumpvec.push(jtclone);
      }
      flow.inlineClone(inlineflow, retaddr);

      // Convert CALL op to a jump
      while (callop.numInput() > 1) {
        this.opRemoveInput(callop, callop.numInput() - 1);
      }

      this.opSetOpcode(callop, OpCode.CPUI_BRANCH);
      const inlineaddr = this.newCodeRef(inlinefd.getAddress());
      this.opSetInput(callop, inlineaddr, 0);
    }

    this.obank.setUniqId(inlinefd.obank.getUniqId());

    return res;
  }

  /// Find the primary branch operation for an instruction.
  /// For machine instructions that branch, this finds the primary PcodeOp that performs
  /// the branch. The instruction is provided as a list of p-code ops, and the caller can
  /// specify whether they expect to see a branch, call, or return operation.
  static findPrimaryBranch(startIdx: number, endIdx: number, obank: PcodeOpBank,
                           findbranch: boolean, findcall: boolean, findreturn: boolean): PcodeOp | null {
    for (let idx = startIdx; idx < endIdx; idx++) {
      const op = obank.getOpAtIndex(idx);
      if (op === null) continue;
      switch (op.code()) {
        case OpCode.CPUI_BRANCH:
        case OpCode.CPUI_CBRANCH:
          if (findbranch) {
            if (!op.getIn(0)!.isConstant()) {  // Make sure this is not an internal branch
              return op;
            }
          }
          break;
        case OpCode.CPUI_BRANCHIND:
          if (findbranch) return op;
          break;
        case OpCode.CPUI_CALL:
        case OpCode.CPUI_CALLIND:
          if (findcall) return op;
          break;
        case OpCode.CPUI_RETURN:
          if (findreturn) return op;
          break;
        default:
          break;
      }
    }
    return null;
  }

  /// Override the control-flow p-code for a particular instruction.
  /// P-code in this function is modified to change the control-flow of
  /// the instruction at the given address, based on the Override type.
  overrideFlow(addr: Address, type: number): void {
    const startIdx = this.obank.beginAtAddr(addr);
    const endIdx = this.obank.endAtAddr(addr);

    let op: PcodeOp | null = null;
    if (type === Override.BRANCH) {
      op = Funcdata.findPrimaryBranch(startIdx, endIdx, this.obank, false, true, true);
    } else if (type === Override.CALL) {
      op = Funcdata.findPrimaryBranch(startIdx, endIdx, this.obank, true, false, true);
    } else if (type === Override.CALL_RETURN) {
      op = Funcdata.findPrimaryBranch(startIdx, endIdx, this.obank, true, true, true);
    } else if (type === Override.RETURN) {
      op = Funcdata.findPrimaryBranch(startIdx, endIdx, this.obank, true, true, false);
    }

    if (op === null || !op.isDead()) {
      throw new LowlevelError("Could not apply flowoverride");
    }

    const opc = op.code();
    if (type === Override.BRANCH) {
      if (opc === OpCode.CPUI_CALL) {
        this.opSetOpcode(op, OpCode.CPUI_BRANCH);
      } else if (opc === OpCode.CPUI_CALLIND) {
        this.opSetOpcode(op, OpCode.CPUI_BRANCHIND);
      } else if (opc === OpCode.CPUI_RETURN) {
        this.opSetOpcode(op, OpCode.CPUI_BRANCHIND);
      }
    } else if (type === Override.CALL || type === Override.CALL_RETURN) {
      if (opc === OpCode.CPUI_BRANCH) {
        this.opSetOpcode(op, OpCode.CPUI_CALL);
      } else if (opc === OpCode.CPUI_BRANCHIND) {
        this.opSetOpcode(op, OpCode.CPUI_CALLIND);
      } else if (opc === OpCode.CPUI_CBRANCH) {
        throw new LowlevelError("Do not currently support CBRANCH overrides");
      } else if (opc === OpCode.CPUI_RETURN) {
        this.opSetOpcode(op, OpCode.CPUI_CALLIND);
      }
      if (type === Override.CALL_RETURN) {  // Insert a new return op after call
        const newReturn = this.newOp(1, addr);
        this.opSetOpcode(newReturn, OpCode.CPUI_RETURN);
        this.opSetInput(newReturn, this.newConstant(1, 0n), 0);
        this.opDeadInsertAfter(newReturn, op);
      }
    } else if (type === Override.RETURN) {
      if (opc === OpCode.CPUI_BRANCH || opc === OpCode.CPUI_CBRANCH || opc === OpCode.CPUI_CALL) {
        throw new LowlevelError("Do not currently support complex overrides");
      } else if (opc === OpCode.CPUI_BRANCHIND) {
        this.opSetOpcode(op, OpCode.CPUI_RETURN);
      } else if (opc === OpCode.CPUI_CALLIND) {
        this.opSetOpcode(op, OpCode.CPUI_RETURN);
      }
    }
  }

  /// Do in-place replacement of
  ///   - `c <= x`   with  `c-1 < x`   OR
  ///   - `x <= c`   with  `x < c+1`
  /// Returns true if a valid replacement was performed.
  replaceLessequal(op: PcodeOp): boolean {
    let vn: Varnode;
    let i: number;
    let val: bigint;
    let diff: bigint;

    if ((vn = op.getIn(0)!).isConstant()) {
      diff = -1n;
      i = 0;
    } else if ((vn = op.getIn(1)!).isConstant()) {
      diff = 1n;
      i = 1;
    } else {
      return false;
    }

    val = vn.getOffset();
    if (op.code() === OpCode.CPUI_INT_SLESSEQUAL) {
      // Check for signed overflow
      if (diff === -1n && val === calc_int_min(vn.getSize())) return false;
      if (diff === 1n && val === calc_int_max(vn.getSize())) return false;
      this.opSetOpcode(op, OpCode.CPUI_INT_SLESS);
    } else {
      // Check for unsigned overflow
      if (diff === -1n && val === 0n) return false;
      if (diff === 1n && val === calc_uint_max(vn.getSize())) return false;
      this.opSetOpcode(op, OpCode.CPUI_INT_LESS);
    }
    const res = (val + diff) & calc_mask(vn.getSize());
    const newvn = this.newConstant(vn.getSize(), res);
    newvn.copySymbol(vn);  // Preserve data-type (and any Symbol info)
    this.opSetInput(op, newvn, i);
    return true;
  }

  /// If a term has a multiplicative coefficient, but the underlying term is still additive,
  /// in some situations we may need to distribute the coefficient before simplifying further.
  /// The given PcodeOp is a INT_MULT where the second input is a constant. We also
  /// know the first input is formed with INT_ADD. Distribute the coefficient to the INT_ADD inputs.
  distributeIntMultAdd(op: PcodeOp): boolean {
    let newvn0: Varnode;
    let newvn1: Varnode;
    const addop = op.getIn(0)!.getDef()!;
    const vn0 = addop.getIn(0)!;
    const vn1 = addop.getIn(1)!;
    if (vn0.isFree() && !vn0.isConstant()) return false;
    if (vn1.isFree() && !vn1.isConstant()) return false;
    const coeff = op.getIn(1)!.getOffset();
    const sz = op.getOut()!.getSize();

    // Do distribution
    if (vn0.isConstant()) {
      let val = coeff * vn0.getOffset();
      val &= calc_mask(sz);
      newvn0 = this.newConstant(sz, val);
    } else {
      const newop0 = this.newOp(2, op.getAddr());
      this.opSetOpcode(newop0, OpCode.CPUI_INT_MULT);
      newvn0 = this.newUniqueOut(sz, newop0);
      this.opSetInput(newop0, vn0, 0);  // To first input of original add
      const newcvn = this.newConstant(sz, coeff);
      this.opSetInput(newop0, newcvn, 1);
      this.opInsertBefore(newop0, op);
    }

    if (vn1.isConstant()) {
      let val = coeff * vn1.getOffset();
      val &= calc_mask(sz);
      newvn1 = this.newConstant(sz, val);
    } else {
      const newop1 = this.newOp(2, op.getAddr());
      this.opSetOpcode(newop1, OpCode.CPUI_INT_MULT);
      newvn1 = this.newUniqueOut(sz, newop1);
      this.opSetInput(newop1, vn1, 0);  // To second input of original add
      const newcvn = this.newConstant(sz, coeff);
      this.opSetInput(newop1, newcvn, 1);
      this.opInsertBefore(newop1, op);
    }

    this.opSetInput(op, newvn0, 0);  // new ADD's inputs are outputs of new MULTs
    this.opSetInput(op, newvn1, 1);
    this.opSetOpcode(op, OpCode.CPUI_INT_ADD);

    return true;
  }

  /// If:
  ///   - The given Varnode is defined by a OpCode.CPUI_INT_MULT.
  ///   - The second input to the INT_MULT is a constant.
  ///   - The first input is defined by another OpCode.CPUI_INT_MULT,
  ///   - This multiply is also by a constant.
  ///
  /// The constants are combined and true is returned.
  /// Otherwise no change is made and false is returned.
  collapseIntMultMult(vn: Varnode): boolean {
    if (!vn.isWritten()) return false;
    const op = vn.getDef()!;
    if (op.code() !== OpCode.CPUI_INT_MULT) return false;
    const constVnFirst = op.getIn(1)!;
    if (!constVnFirst.isConstant()) return false;
    if (!op.getIn(0)!.isWritten()) return false;
    const otherMultOp = op.getIn(0)!.getDef()!;
    if (otherMultOp.code() !== OpCode.CPUI_INT_MULT) return false;
    const constVnSecond = otherMultOp.getIn(1)!;
    if (!constVnSecond.isConstant()) return false;
    const invn = otherMultOp.getIn(0)!;
    if (invn.isFree()) return false;
    const sz = invn.getSize();
    const val = ((constVnFirst.getOffset() as bigint) * (constVnSecond.getOffset() as bigint)) & calc_mask(sz);
    const newvn = this.newConstant(sz, val);
    this.opSetInput(op, newvn, 1);
    this.opSetInput(op, invn, 0);
    return true;
  }

  /// Return a Varnode in the unique space that is defined by a COPY op taking the given Varnode as input.
  /// If a COPY op to a unique already exists, it may be returned. If the preexisting COPY is not usable
  /// at the specified point, it is redefined at an earlier point in the control-flow so that it can be used.
  buildCopyTemp(vn: Varnode, point: PcodeOp): Varnode {
    let otherOp: PcodeOp | null = null;
    let usedCopy: PcodeOp | null = null;

    for (let iter = vn.beginDescend(); iter < vn.endDescend(); iter++) {
      const op = vn.getDescend(iter);
      if (op.code() !== OpCode.CPUI_COPY) continue;
      const outvn = op.getOut()!;
      if (outvn.getSpace()!.getType() === spacetype.IPTR_INTERNAL) {
        if (outvn.isTypeLock()) continue;
        otherOp = op;
        break;
      }
    }

    if (otherOp !== null) {
      if (point.getParent() === otherOp.getParent()) {
        if (point.getSeqNum().getOrder() < otherOp.getSeqNum().getOrder()) {
          usedCopy = null;
        } else {
          usedCopy = otherOp;
        }
      } else {
        let common = FlowBlock.findCommonBlock(point.getParent()!, otherOp.getParent()!) as BlockBasic;
        if (common === point.getParent()) {
          usedCopy = null;
        } else if (common === otherOp.getParent()) {
          usedCopy = otherOp;
        } else {
          // Neither op is ancestor of the other
          usedCopy = this.newOp(1, common.getStop());
          this.opSetOpcode(usedCopy, OpCode.CPUI_COPY);
          this.newUniqueOut(vn.getSize(), usedCopy);
          this.opSetInput(usedCopy, vn, 0);
          this.opInsertEnd(usedCopy, common);
        }
      }
    }

    if (usedCopy === null) {
      usedCopy = this.newOp(1, point.getAddr());
      this.opSetOpcode(usedCopy, OpCode.CPUI_COPY);
      this.newUniqueOut(vn.getSize(), usedCopy);
      this.opSetInput(usedCopy, vn, 0);
      this.opInsertBefore(usedCopy, point);
    }

    if (otherOp !== null && otherOp !== usedCopy) {
      this.totalReplace(otherOp.getOut()!, usedCopy.getOut()!);
      this.opDestroy(otherOp);
    }

    return usedCopy.getOut()!;
  }

  /// Trace a boolean value to a set of PcodeOps that can be changed to flip the boolean value.
  /// The boolean Varnode is either the output of the given PcodeOp or the
  /// first input if the PcodeOp is a CBRANCH. The list of ops that need flipping is
  /// returned in an array.
  /// Returns 0 if the change normalizes, 1 if the change is ambivalent, 2 if the change does not normalize.
  static opFlipInPlaceTest(op: PcodeOp, fliplist: PcodeOp[]): number {
    let vn: Varnode;
    let subtest1: number;
    let subtest2: number;

    switch (op.code()) {
      case OpCode.CPUI_CBRANCH:
        vn = op.getIn(1)!;
        if (vn.loneDescend() !== op) return 2;
        if (!vn.isWritten()) return 2;
        return Funcdata.opFlipInPlaceTest(vn.getDef()!, fliplist);
      case OpCode.CPUI_INT_EQUAL:
      case OpCode.CPUI_FLOAT_EQUAL:
        fliplist.push(op);
        return 1;
      case OpCode.CPUI_BOOL_NEGATE:
      case OpCode.CPUI_INT_NOTEQUAL:
      case OpCode.CPUI_FLOAT_NOTEQUAL:
        fliplist.push(op);
        return 0;
      case OpCode.CPUI_INT_SLESS:
      case OpCode.CPUI_INT_LESS:
        vn = op.getIn(0)!;
        fliplist.push(op);
        if (!vn.isConstant()) return 1;
        return 0;
      case OpCode.CPUI_INT_SLESSEQUAL:
      case OpCode.CPUI_INT_LESSEQUAL:
        vn = op.getIn(1)!;
        fliplist.push(op);
        if (vn.isConstant()) return 1;
        return 0;
      case OpCode.CPUI_BOOL_OR:
      case OpCode.CPUI_BOOL_AND:
        vn = op.getIn(0)!;
        if (vn.loneDescend() !== op) return 2;
        if (!vn.isWritten()) return 2;
        subtest1 = Funcdata.opFlipInPlaceTest(vn.getDef()!, fliplist);
        if (subtest1 === 2) return 2;
        vn = op.getIn(1)!;
        if (vn.loneDescend() !== op) return 2;
        if (!vn.isWritten()) return 2;
        subtest2 = Funcdata.opFlipInPlaceTest(vn.getDef()!, fliplist);
        if (subtest2 === 2) return 2;
        fliplist.push(op);
        return subtest1;  // Front of AND/OR must be normalizing
      default:
        break;
    }
    return 2;
  }

  /// Perform op-code flips (in-place) to change a boolean value.
  /// The precomputed list of PcodeOps have their op-codes modified to
  /// facilitate the flip.
  opFlipInPlaceExecute(fliplist: PcodeOp[]): void {
    let vn: Varnode;
    for (let i = 0; i < fliplist.length; ++i) {
      const op = fliplist[i];
      const { result: opc, reorder: flipyes } = get_booleanflip(op.code());
      if (opc === OpCode.CPUI_COPY) {
        // We remove this (OpCode.CPUI_BOOL_NEGATE) entirely
        vn = op.getIn(0)!;
        const otherop = op.getOut()!.loneDescend()!;  // Must be a lone descendant
        const slot = otherop.getSlot(op.getOut()!);
        this.opSetInput(otherop, vn, slot);  // Propagate vn into otherop
        this.opDestroy(op);
      } else if (opc === OpCode.CPUI_MAX) {
        if (op.code() === OpCode.CPUI_BOOL_AND) {
          this.opSetOpcode(op, OpCode.CPUI_BOOL_OR);
        } else if (op.code() === OpCode.CPUI_BOOL_OR) {
          this.opSetOpcode(op, OpCode.CPUI_BOOL_AND);
        } else {
          throw new LowlevelError("Bad flipInPlace op");
        }
      } else {
        this.opSetOpcode(op, opc);
        if (flipyes) {
          this.opSwapInput(op, 0, 1);
          if (opc === OpCode.CPUI_INT_LESSEQUAL || opc === OpCode.CPUI_INT_SLESSEQUAL) {
            this.replaceLessequal(op);
          }
        }
      }
    }
  }

  /// Find a duplicate calculation of a given PcodeOp reading a specific Varnode.
  /// We only match 1 level of calculation. Additionally the duplicate must occur in the
  /// indicated basic block, earlier than a specified op.
  static cseFindInBlock(op: PcodeOp, vn: Varnode, bl: BlockBasic, earliest: PcodeOp | null): PcodeOp | null {
    for (let iter = vn.beginDescend(); iter < vn.endDescend(); iter++) {
      const res = vn.getDescend(iter);
      if (res === op) continue;  // Must not be op
      if (res.getParent() !== bl) continue;  // Must be in bl
      if (earliest !== null) {
        if (earliest.getSeqNum().getOrder() < res.getSeqNum().getOrder()) continue;  // Must occur earlier than earliest
      }
      const outvn1 = op.getOut();
      const outvn2 = res.getOut();
      if (outvn2 === null) continue;
      const buf1: Varnode[] = new Array(2);
      const buf2: Varnode[] = new Array(2);
      if (functionalEqualityLevel(outvn1!, outvn2, buf1, buf2) === 0) {
        return res;
      }
    }
    return null;
  }

  /// Perform a Common Subexpression Elimination step.
  /// Assuming the two given PcodeOps perform the identical operation on identical operands
  /// (depth 1 functional equivalence) eliminate the redundancy. Return the remaining (dominating)
  /// PcodeOp. If neither op dominates the other, both are eliminated, and a new PcodeOp
  /// is built at a commonly accessible point.
  cseElimination(op1: PcodeOp, op2: PcodeOp): PcodeOp {
    let replace: PcodeOp;

    if (op1.getParent() === op2.getParent()) {
      if (op1.getSeqNum().getOrder() < op2.getSeqNum().getOrder()) {
        replace = op1;
      } else {
        replace = op2;
      }
    } else {
      const common = FlowBlock.findCommonBlock(op1.getParent()!, op2.getParent()!) as BlockBasic;
      if (common === op1.getParent()) {
        replace = op1;
      } else if (common === op2.getParent()) {
        replace = op2;
      } else {
        // Neither op is ancestor of the other
        replace = this.newOp(op1.numInput(), common.getStop());
        this.opSetOpcode(replace, op1.code());
        this.newVarnodeOut(op1.getOut()!.getSize(), op1.getOut()!.getAddr(), replace);
        for (let i = 0; i < op1.numInput(); ++i) {
          if (op1.getIn(i)!.isConstant()) {
            this.opSetInput(replace, this.newConstant(op1.getIn(i)!.getSize(), op1.getIn(i)!.getOffset()), i);
          } else {
            this.opSetInput(replace, op1.getIn(i)!, i);
          }
        }
        this.opInsertEnd(replace, common);
      }
    }
    if (replace !== op1) {
      this.totalReplace(op1.getOut()!, replace.getOut()!);
      this.opDestroy(op1);
    }
    if (replace !== op2) {
      this.totalReplace(op2.getOut()!, replace.getOut()!);
      this.opDestroy(op2);
    }
    return replace;
  }

  /// Perform Common Subexpression Elimination on a list of Varnode descendants.
  /// The list consists of PcodeOp descendants of a single Varnode paired with a hash value.
  /// The hash serves as a primary test for duplicate calculations; if it doesn't match
  /// the PcodeOps aren't common subexpressions. This method searches for hash matches
  /// then does secondary testing and eliminates any redundancy it finds.
  cseEliminateList(list: Array<[number, PcodeOp]>, outlist: Varnode[]): void {
    if (list.length === 0) return;
    list.sort((a, b) => a[0] - b[0]);
    let liter1 = 0;
    let liter2 = 1;
    while (liter2 < list.length) {
      if (list[liter1][0] === list[liter2][0]) {
        const op1 = list[liter1][1];
        const op2 = list[liter2][1];
        if (!op1.isDead() && !op2.isDead() && op1.isCseMatch(op2)) {
          const outvn1 = op1.getOut();
          const outvn2 = op2.getOut();
          if (outvn1 === null || this.isHeritaged(outvn1)) {
            if (outvn2 === null || this.isHeritaged(outvn2)) {
              const resop = this.cseElimination(op1, op2);
              outlist.push(resop.getOut()!);
            }
          }
        }
      }
      liter1++;
      liter2++;
    }
  }

  /// Move given op past lastOp respecting covers if possible.
  /// This routine should be called only after Varnode merging and explicit/implicit attributes have
  /// been calculated. Determine if the given op can be moved (only within its basic block) to
  /// after lastOp. The output of any PcodeOp moved across must not be involved, directly or
  /// indirectly, with any variable in the expression rooted at the given op.
  /// If the move is possible, perform the move.
  moveRespectingCover(op: PcodeOp, lastOp: PcodeOp): boolean {
    if (op === lastOp) return true;  // Nothing to move past
    if (op.isCall()) return false;
    let prevOp: PcodeOp | null = null;
    if (op.code() === OpCode.CPUI_CAST) {
      const vn = op.getIn(0)!;
      if (!vn.isExplicit()) {  // If CAST is part of expression, we need to move the previous op as well
        if (!vn.isWritten()) return false;
        prevOp = vn.getDef()!;
        if (prevOp!.isCall()) return false;
        if (op.previousOp() !== prevOp) return false;  // Previous op must exist and feed into the CAST
      }
    }
    const rootvn = op.getOut()!;
    const highList: HighVariable[] = [];
    const typeVal = HighVariable.markExpression(rootvn, highList);
    let curOp = op;
    do {
      const nextOp = curOp.nextOp()!;
      const opc = nextOp.code();
      if (opc !== OpCode.CPUI_COPY && opc !== OpCode.CPUI_CAST) break;  // Limit to only crossing COPY and CAST ops
      if (rootvn === nextOp.getIn(0)) break;  // Data-flow order dependence
      const copyVn = nextOp.getOut()!;
      if (copyVn.getHigh()!.isMark()) break;  // Direct interference: COPY writes what original op reads
      if (typeVal !== 0 && copyVn.isAddrTied()) break;  // Possible indirect interference
      curOp = nextOp;
    } while (curOp !== lastOp);

    for (let i = 0; i < highList.length; ++i) {  // Clear marks on expression
      highList[i].clearMark();
    }

    if (curOp === lastOp) {  // If we are able to cross everything
      this.opUninsert(op);  // Move op
      this.opInsertAfter(op, lastOp);
      if (prevOp !== null) {  // If there was a CAST, move both ops
        this.opUninsert(prevOp);
        this.opInsertAfter(prevOp, lastOp);
      }
      return true;
    }
    return false;
  }

  // ---- Simple one-liner methods from funcdata.hh (op-related) ----

  /// Free resources for the given dead PcodeOp
  opDeadAndGone(op: PcodeOp): void {
    this.obank.destroy(op);
  }

  /// Mark PcodeOp as not being printed
  opMarkNonPrinting(op: PcodeOp): void {
    op.setFlag(PcodeOp.nonprinting);
  }

  /// Mark PcodeOp as needing special printing
  opMarkSpecialPrint(op: PcodeOp): void {
    op.setAdditionalFlag(PcodeOp.special_print);
  }

  /// Mark PcodeOp as not collapsible
  opMarkNoCollapse(op: PcodeOp): void {
    op.setFlag(PcodeOp.nocollapse);
  }

  /// Mark cpool record was visited
  opMarkCpoolTransformed(op: PcodeOp): void {
    op.setAdditionalFlag(PcodeOp.is_cpool_transformed);
  }

  /// Mark PcodeOp as having boolean output
  opMarkCalculatedBool(op: PcodeOp): void {
    op.setFlag(PcodeOp.calculated_bool);
  }

  /// Mark PcodeOp as starting a basic block
  opMarkStartBasic(op: PcodeOp): void {
    op.setFlag(PcodeOp.startbasic);
  }

  /// Mark PcodeOp as starting its instruction
  opMarkStartInstruction(op: PcodeOp): void {
    op.setFlag(PcodeOp.startmark);
  }

  /// Mark PcodeOp as LOAD/STORE from spacebase ptr
  opMarkSpacebasePtr(op: PcodeOp): void {
    op.setFlag(PcodeOp.spacebase_ptr);
  }

  /// Unmark PcodeOp as using spacebase ptr
  opClearSpacebasePtr(op: PcodeOp): void {
    op.clearFlag(PcodeOp.spacebase_ptr);
  }

  /// Flip output condition of given CBRANCH
  opFlipCondition(op: PcodeOp): void {
    op.flipFlag(PcodeOp.boolean_flip);
  }

  /// Moved given PcodeOp to specified point in the dead list
  opDeadInsertAfter(op: PcodeOp, prev: PcodeOp): void {
    this.obank.insertAfterDead(op, prev);
  }

  /// Mark PcodeOp as a noreturn (within opMarkHalt)
  opMarkNoReturn(op: PcodeOp): void {
    this.opMarkHalt(op, PcodeOp.noreturn);
  }

  /// Find PcodeOp with given sequence number
  findOp(sq: SeqNum): PcodeOp | null {
    return this.obank.findOp(sq);
  }

  /// Look up a PcodeOp by an instruction Address
  target(addr: Address): PcodeOp | null {
    return this.obank.target(addr);
  }

  /// Perform an entire heritage pass linking Varnode reads to writes
  opHeritage(): void {
    this.heritage.heritage();
  }

  // =====================================================================
  // PART 4: Varnode manipulation methods (from funcdata_varnode.cc)
  // =====================================================================

  /// Properties of a given storage location are gathered from symbol information and
  /// applied to the given Varnode.
  setVarnodeProperties(vn: Varnode): void {
    if (!vn.isMapped()) {
      // One more chance to find entry, now that we know usepoint
      let vflags: number = 0;
      const result = this.localmap!.queryProperties(vn.getAddr(), vn.getSize(), vn.getUsePoint(this));
      const entry: SymbolEntry | null = result.entry;
      vflags = result.flags;
      if (entry !== null) {
        // Let entry try to force type
        vn.setSymbolProperties(entry);
      } else {
        vn.setFlags(vflags & ~Varnode.typelock); // typelock set by updateType
      }
    }

    if (vn.cover === null) {
      if (this.isHighOn()) {
        vn.calcCover();
      }
    }
  }

  /// If HighVariables are enabled, make sure the given Varnode has one assigned.
  /// Allocate a dedicated HighVariable, that contains only the one Varnode if necessary.
  assignHigh(vn: Varnode): HighVariable | null {
    if ((this.flags & Funcdata.highlevel_on) !== 0) {
      if (vn.hasCover()) {
        vn.calcCover();
      }
      if (!vn.isAnnotation()) {
        return new HighVariable(vn);
      }
    }
    return null;
  }

  /// A Varnode is allocated which represents the indicated constant value.
  /// Its storage address is in the constant address space.
  newConstant(s: number, constant_val: bigint): Varnode {
    const ct: Datatype = this.glb.types.getBase(s, type_metatype.TYPE_UNKNOWN);
    const vn: Varnode = this.vbank.create(s, this.glb.getConstant(constant_val), ct);
    this.assignHigh(vn);
    // There is no chance of matching localmap
    return vn;
  }

  /// A new temporary register storage location is allocated from the unique
  /// address space.
  newUnique(s: number, ct: Datatype | null = null): Varnode {
    if (ct === null) {
      ct = this.glb.types.getBase(s, type_metatype.TYPE_UNKNOWN);
    }
    const vn: Varnode = this.vbank.createUnique(s, ct);
    this.assignHigh(vn);
    if (s >= this.minLanedSize) {
      this.checkForLanedRegister(s, vn.getAddr());
    }
    // No chance of matching localmap
    return vn;
  }

  /// Create a new Varnode which is already defined as output of a given PcodeOp.
  /// This is more efficient as it avoids the initial insertion of the free form of the
  /// Varnode into the tree, and queryProperties only needs to be called once.
  newVarnodeOut(s: number, m: Address, op: PcodeOp): Varnode {
    const ct: Datatype = this.glb.types.getBase(s, type_metatype.TYPE_UNKNOWN);
    const vn: Varnode = this.vbank.createDef(s, m, ct, op);
    op.setOutput(vn);
    this.assignHigh(vn);

    if (s >= this.minLanedSize) {
      this.checkForLanedRegister(s, m);
    }
    let vflags: number = 0;
    const result = this.localmap!.queryProperties(m, s, op.getAddr());
    const entry: SymbolEntry | null = result.entry;
    vflags = result.flags;
    if (entry !== null) {
      vn.setSymbolProperties(entry);
    } else {
      vn.setFlags(vflags & ~Varnode.typelock); // Typelock set by updateType
    }

    return vn;
  }

  /// Allocate a new register from the unique address space and create a new
  /// Varnode object representing it as an output to the given PcodeOp.
  newUniqueOut(s: number, op: PcodeOp): Varnode {
    const ct: Datatype = this.glb.types.getBase(s, type_metatype.TYPE_UNKNOWN);
    const vn: Varnode = this.vbank.createDefUnique(s, ct, op);
    op.setOutput(vn);
    this.assignHigh(vn);
    if (s >= this.minLanedSize) {
      this.checkForLanedRegister(s, vn.getAddr());
    }
    // No chance of matching localmap
    return vn;
  }

  /// Create a new unattached Varnode object.
  newVarnode(s: number, m: Address, ct: Datatype | null = null): Varnode {
    if (ct === null) {
      ct = this.glb.types.getBase(s, type_metatype.TYPE_UNKNOWN);
    }

    const vn: Varnode = this.vbank.create(s, m, ct);
    this.assignHigh(vn);

    if (s >= this.minLanedSize) {
      this.checkForLanedRegister(s, m);
    }
    let vflags: number = 0;
    const result = this.localmap!.queryProperties(vn.getAddr(), vn.getSize(), new Address());
    const entry: SymbolEntry | null = result.entry;
    vflags = result.flags;
    if (entry !== null) {
      // Let entry try to force type
      vn.setSymbolProperties(entry);
    } else {
      vn.setFlags(vflags & ~Varnode.typelock); // Typelock set by updateType
    }

    return vn;
  }

  /// Create a special annotation Varnode that holds a pointer reference to a specific
  /// PcodeOp. This is used specifically to let a OpCode.CPUI_INDIRECT op refer to the PcodeOp
  /// it is holding an indirect effect for.
  newVarnodeIop(op: PcodeOp): Varnode {
    const ptrSize = 8; // sizeof(pointer) - architecture dependent, typically 8 in 64-bit
    const ct: Datatype = this.glb.types.getBase(ptrSize, type_metatype.TYPE_UNKNOWN);
    const cspc: AddrSpace = this.glb.getIopSpace();
    const timeId = op.getSeqNum().getTime();
    const vn: Varnode = this.vbank.create(ptrSize, new Address(cspc, BigInt(timeId)), ct);
    PcodeOp.registerOpConst(op, timeId);
    this.assignHigh(vn);
    return vn;
  }

  /// A reference to a particular address space is encoded as a constant Varnode.
  /// These are used for LOAD and STORE p-code ops in particular.
  newVarnodeSpace(spc: AddrSpace): Varnode {
    const ptrSize = 8; // sizeof(pointer)
    const ct: Datatype = this.glb.types.getBase(ptrSize, type_metatype.TYPE_UNKNOWN);
    const vn: Varnode = this.vbank.create(ptrSize, this.glb.createConstFromSpace(spc), ct);
    this.assignHigh(vn);
    return vn;
  }

  /// A call specification (FuncCallSpecs) is encoded into an annotation Varnode.
  /// The Varnode is used specifically as an input to OpCode.CPUI_CALL ops to speed up access
  /// to their associated call specification.
  newVarnodeCallSpecs(fc: FuncCallSpecs): Varnode {
    const ptrSize = 8; // sizeof(pointer)
    const ct: Datatype = this.glb.types.getBase(ptrSize, type_metatype.TYPE_UNKNOWN);
    const cspc: AddrSpace = this.glb.getFspecSpace();
    const vn: Varnode = this.vbank.create(ptrSize, new Address(cspc, BigInt((fc as any).getId())), ct);
    this.assignHigh(vn);
    return vn;
  }

  /// A reference to a specific Address is encoded in a Varnode. The Varnode is
  /// an annotation in the sense that it will hold no value in the data-flow; it will
  /// only hold a reference to an address.
  newCodeRef(m: Address): Varnode {
    const ct: Datatype = this.glb.types.getTypeCode();
    const vn: Varnode = this.vbank.create(1, m, ct);
    vn.setFlags(Varnode.annotation);
    this.assignHigh(vn);
    return vn;
  }

  /// Create a new Varnode given an address space and offset.
  newVarnodeFromSpaceOffset(s: number, base: AddrSpace, off: bigint): Varnode {
    return this.newVarnode(s, new Address(base, off));
  }

  /// Internal factory for copying Varnodes from another Funcdata object into this.
  cloneVarnode(vn: Varnode): Varnode {
    const newvn: Varnode = this.vbank.create(vn.getSize(), vn.getAddr(), vn.getType());
    let vflags: number = vn.getFlags();
    // These are the flags we allow to be cloned
    vflags &= (Varnode.annotation | Varnode.externref |
      Varnode.readonly | Varnode.persist |
      Varnode.addrtied | Varnode.addrforce |
      Varnode.indirect_creation | Varnode.incidental_copy |
      Varnode.volatil | Varnode.mapped);
    newvn.setFlags(vflags);
    return newvn;
  }

  /// References to the Varnode are replaced with NULL pointers and the object is freed,
  /// with no possibility of reuse.
  destroyVarnode(vn: Varnode): void {
    for (const op of [...vn.descend]) {
      op.clearInput(op.getSlot(vn));
    }
    if (vn.def !== null) {
      vn.def.setOutput(null);
      vn.def = null;
    }

    vn.destroyDescend();
    this.vbank.destroy(vn);
  }

  /// Check if the given storage range is a potential laned register.
  /// If so, record the storage with the matching laned register record.
  checkForLanedRegister(sz: number, addr: Address): void {
    const lanedRegister: LanedRegister | null = this.glb.getLanedRegister(addr, sz);
    if (lanedRegister === null) return;
    const storage: any = {
      space: addr.getSpace(),
      offset: addr.getOffset(),
      size: sz
    };
    this.lanedMap.set(storage as any, lanedRegister);
  }

  /// Look up the Symbol visible in this function's Scope and return the HighVariable
  /// associated with it. If the Symbol doesn't exist or there is no Varnode holding at least
  /// part of the value of the Symbol, NULL is returned.
  findHigh(nm: string): HighVariable | null {
    const symList: Symbol[] = [];
    this.localmap!.queryByName(nm, symList);
    if (symList.length === 0) return null;
    const sym: Symbol = symList[0];
    const vn: Varnode | null = this.findLinkedVarnode(sym.getFirstWholeMap());
    if (vn !== null) {
      return vn.getHigh();
    }
    return null;
  }

  /// An input Varnode has a special designation within SSA form as not being defined
  /// by a p-code operation and is a formal input to the data-flow of the function.
  setInputVarnode(vn: Varnode): Varnode {
    if (vn.isInput()) return vn; // Already an input

    // First we check if it overlaps any other varnode
    const iter = this.vbank.beginDefFlagAddr(Varnode.input, vn.getAddr().add(BigInt(vn.getSize())));

    // Iter points at first varnode AFTER vn
    if (!iter.equals(this.vbank.beginDef())) {
      iter.prev(); // previous varnode
      const invn: Varnode = iter.value; // comes before vn or intersects
      if (invn.isInput()) {
        if ((-1 !== vn.overlapVarnode(invn)) || (-1 !== invn.overlapVarnode(vn))) {
          if ((vn.getSize() === invn.getSize()) && (vn.getAddr().equals(invn.getAddr())))
            return invn;
          throw new LowlevelError("Overlapping input varnodes");
        }
      }
    }

    vn = this.vbank.setInput(vn);
    this.setVarnodeProperties(vn);
    const effecttype: number = this.funcp.hasEffect(vn.getAddr(), vn.getSize());
    if (effecttype === EffectRecord.unaffected) {
      vn.setUnaffected();
    }
    if (effecttype === EffectRecord.return_address) {
      vn.setUnaffected(); // Should be unaffected over the course of the function
      vn.setReturnAddress();
    }
    return vn;
  }

  /// A new Varnode that covers both the original Varnodes is created and is itself marked
  /// as a function input. Any OpCode.CPUI_PIECE reading the original Varnodes is converted to a
  /// OpCode.CPUI_COPY reading the new Varnode.
  combineInputVarnodes(vnHi: Varnode, vnLo: Varnode): void {
    if (!vnHi.isInput() || !vnLo.isInput()) {
      throw new LowlevelError("Varnodes being combined are not inputs");
    }
    let isContiguous: boolean;
    let addr: Address = vnLo.getAddr();
    if (addr.isBigEndian()) {
      addr = vnHi.getAddr();
      const otheraddr: Address = addr.add(BigInt(vnHi.getSize()));
      isContiguous = otheraddr.equals(vnLo.getAddr());
    } else {
      const otheraddr: Address = addr.add(BigInt(vnLo.getSize()));
      isContiguous = otheraddr.equals(vnHi.getAddr());
    }
    if (!isContiguous) {
      throw new LowlevelError("Input varnodes being combined are not contiguous");
    }
    const pieceList: PcodeOp[] = [];
    let otherOpsHi: boolean = false;
    let otherOpsLo: boolean = false;

    for (const op of vnHi.descend) {
      if (op.code() === OpCode.CPUI_PIECE && op.getIn(0) === vnHi && op.getIn(1) === vnLo) {
        pieceList.push(op);
      } else {
        otherOpsHi = true;
      }
    }
    for (const op of vnLo.descend) {
      if (op.code() !== OpCode.CPUI_PIECE || op.getIn(0) !== vnHi || op.getIn(1) !== vnLo) {
        otherOpsLo = true;
      }
    }
    for (let i = 0; i < pieceList.length; ++i) {
      this.opRemoveInput(pieceList[i], 1);
      this.opUnsetInput(pieceList[i], 0);
    }

    // If there are other PcodeOps besides PIECEs that are directly combining vnHi and vnLo
    // create replacement Varnodes constructed as SUBPIECEs of the new combined Varnode
    let subHi: PcodeOp | null = null;
    let subLo: PcodeOp | null = null;
    if (otherOpsHi) {
      const bb: BlockBasic = this.bblocks.getBlock(0) as BlockBasic;
      subHi = this.newOp(2, bb.getStart());
      this.opSetOpcode(subHi, OpCode.CPUI_SUBPIECE);
      this.opSetInput(subHi, this.newConstant(4, BigInt(vnLo.getSize())), 1);
      const newHi: Varnode = this.newVarnodeOut(vnHi.getSize(), vnHi.getAddr(), subHi);
      this.opInsertBegin(subHi, bb);
      this.totalReplace(vnHi, newHi);
    }
    if (otherOpsLo) {
      const bb: BlockBasic = this.bblocks.getBlock(0) as BlockBasic;
      subLo = this.newOp(2, bb.getStart());
      this.opSetOpcode(subLo, OpCode.CPUI_SUBPIECE);
      this.opSetInput(subLo, this.newConstant(4, 0n), 1);
      const newLo: Varnode = this.newVarnodeOut(vnLo.getSize(), vnLo.getAddr(), subLo);
      this.opInsertBegin(subLo, bb);
      this.totalReplace(vnLo, newLo);
    }
    const outSize: number = vnHi.getSize() + vnLo.getSize();
    this.vbank.destroy(vnHi);
    this.vbank.destroy(vnLo);
    let inVn: Varnode = this.newVarnode(outSize, addr);
    inVn = this.setInputVarnode(inVn);
    for (let i = 0; i < pieceList.length; ++i) {
      this.opSetInput(pieceList[i], inVn, 0);
      this.opSetOpcode(pieceList[i], OpCode.CPUI_COPY);
    }
    if (otherOpsHi) {
      this.opSetInput(subHi!, inVn, 0);
    }
    if (otherOpsLo) {
      this.opSetInput(subLo!, inVn, 0);
    }
  }

  /// Construct a constant Varnode up to 128 bits, using INT_ZEXT and PIECE if necessary.
  /// This method is temporary until we have full extended precision constants.
  newExtendedConstant(s: number, val: bigint[], op: PcodeOp): Varnode {
    if (s <= 8) {
      return this.newConstant(s, val[0]);
    }
    let newConstVn: Varnode;
    if (val[1] === 0n) {
      const extOp: PcodeOp = this.newOp(1, op.getAddr());
      this.opSetOpcode(extOp, OpCode.CPUI_INT_ZEXT);
      newConstVn = this.newUniqueOut(s, extOp);
      this.opSetInput(extOp, this.newConstant(8, val[0]), 0);
      this.opInsertBefore(extOp, op);
    } else {
      const pieceOp: PcodeOp = this.newOp(2, op.getAddr());
      this.opSetOpcode(pieceOp, OpCode.CPUI_PIECE);
      newConstVn = this.newUniqueOut(s, pieceOp);
      this.opSetInput(pieceOp, this.newConstant(8, val[1]), 0); // Most significant piece
      this.opSetInput(pieceOp, this.newConstant(8, val[0]), 1); // Least significant piece
      this.opInsertBefore(pieceOp, op);
    }
    return newConstVn;
  }

  /// Adjust input Varnodes contained in the given range.
  /// After this call, a single input Varnode will exist that fills the given range.
  adjustInputVarnodes(addr: Address, sz: number): void {
    // Ensure addr is a full Address (from address.ts) with justifiedContain
    if (typeof (addr as any).justifiedContain !== 'function') {
      addr = new Address(addr);
    }
    const endaddr: Address = addr.add(BigInt(sz - 1));
    const inlist: Varnode[] = [];
    let iter = this.vbank.beginDefFlagAddr(Varnode.input, addr);
    const enditer = this.vbank.endDefFlagAddr(Varnode.input, endaddr);
    while (!iter.equals(enditer)) {
      const vn: Varnode = iter.get();
      iter.next();
      if (vn.getOffset() + BigInt(vn.getSize() - 1) > endaddr.getOffset()) {
        throw new LowlevelError("Cannot properly adjust input varnodes");
      }
      inlist.push(vn);
    }

    for (let i = 0; i < inlist.length; ++i) {
      const vn: Varnode = inlist[i];
      const sa: number = addr.justifiedContain(sz, vn.getAddr(), vn.getSize(), false);
      if ((!vn.isInput()) || (sa < 0) || (sz <= vn.getSize())) {
        throw new LowlevelError("Bad adjustment to input varnode");
      }
      const subop: PcodeOp = this.newOp(2, this.getAddress());
      this.opSetOpcode(subop, OpCode.CPUI_SUBPIECE);
      this.opSetInput(subop, this.newConstant(4, BigInt(sa)), 1);
      const newvn: Varnode = this.newVarnodeOut(vn.getSize(), vn.getAddr(), subop);
      // newvn must not be free in order to give all vn's descendants
      this.opInsertBegin(subop, this.bblocks.getBlock(0) as BlockBasic);
      this.totalReplace(vn, newvn);
      this.deleteVarnode(vn); // Get rid of old input before creating new input
      inlist[i] = newvn;
    }
    // Now that all the intersecting inputs have been pulled out, we can create the new input
    let invn: Varnode = this.newVarnode(sz, addr);
    invn = this.setInputVarnode(invn);
    // The new input may cause new heritage and "Heritage AFTER dead removal" errors
    // So tell heritage to ignore it
    invn.setWriteMask();
    // Now change all old inputs to be created as SUBPIECE from the new input
    for (let i = 0; i < inlist.length; ++i) {
      const op: PcodeOp = inlist[i].getDef()!;
      this.opSetInput(op, invn, 0);
    }
  }

  /// All p-code ops that read the Varnode are transformed so that they read
  /// a special constant instead (associated with unreachable block removal).
  descend2Undef(vn: Varnode): boolean {
    let res: boolean = false;
    const sz: number = vn.getSize();
    const descendants: PcodeOp[] = [...vn.descend];
    for (const op of descendants) {
      if (op.getParent()!.isDead()) continue;
      if (op.getParent()!.sizeIn() !== 0) res = true;
      const i: number = op.getSlot(vn);
      const badconst: Varnode = this.newConstant(sz, 0xBADDEFn);
      if (op.code() === OpCode.CPUI_MULTIEQUAL) {
        // Cannot put constant directly into MULTIEQUAL
        const inbl: BlockBasic = op.getParent().getIn(i) as BlockBasic;
        const copyop: PcodeOp = this.newOp(1, inbl.getStart());
        const inputvn: Varnode = this.newUniqueOut(sz, copyop);
        this.opSetOpcode(copyop, OpCode.CPUI_COPY);
        this.opSetInput(copyop, badconst, 0);
        this.opInsertEnd(copyop, inbl);
        this.opSetInput(op, inputvn, i);
      } else if (op.code() === OpCode.CPUI_INDIRECT) {
        // Cannot put constant directly into INDIRECT
        const copyop: PcodeOp = this.newOp(1, op.getAddr());
        const inputvn: Varnode = this.newUniqueOut(sz, copyop);
        this.opSetOpcode(copyop, OpCode.CPUI_COPY);
        this.opSetInput(copyop, badconst, 0);
        this.opInsertBefore(copyop, op);
        this.opSetInput(op, inputvn, i);
      } else {
        this.opSetInput(op, badconst, i);
      }
    }
    return res;
  }

  initActiveOutput(): void {
    this.activeoutput = new ParamActive(false);
    let maxdelay: number = this.funcp.getMaxOutputDelay();
    if (maxdelay > 0) {
      maxdelay = 3;
    }
    this.activeoutput.setMaxPass(maxdelay);
  }

  setHighLevel(): void {
    if ((this.flags & Funcdata.highlevel_on) !== 0) return;
    this.flags |= Funcdata.highlevel_on;
    this.high_level_index = this.vbank.getCreateIndex();

    for (let iter = this.vbank.beginLoc(); !iter.equals(this.vbank.endLoc()); iter.next()) {
      this.assignHigh(iter.get());
    }
  }

  /// Copy properties from an existing Varnode to a new Varnode.
  /// The new Varnode is assumed to overlap the storage of the existing Varnode.
  transferVarnodeProperties(vn: Varnode, newVn: Varnode, lsbOffset: number): void {
    let newConsume: bigint = 0xFFFFFFFFFFFFFFFFn; // Make sure any bits shifted in above the precision of Varnode.consume are set
    if (lsbOffset < 8) {
      let fillBits: bigint = 0n;
      if (lsbOffset !== 0) {
        fillBits = newConsume << BigInt(8 * (8 - lsbOffset));
      }
      newConsume = ((vn.getConsume() >> BigInt(8 * lsbOffset)) | fillBits) & calc_mask(newVn.getSize());
    }

    const vnFlags: number = vn.getFlags() & (Varnode.directwrite | Varnode.addrforce);

    newVn.setFlags(vnFlags); // Preserve addrforce setting
    newVn.setConsume(newConsume);
  }

  /// Treat the given Varnode as read-only, look up its value in LoadImage
  /// and replace read references with the value as a constant Varnode.
  fillinReadOnly(vn: Varnode): boolean {
    if (vn.isWritten()) {
      // Can't replace output with constant
      const defop: PcodeOp = vn.getDef()!;
      if (defop.isMarker()) {
        defop.setAdditionalFlag(PcodeOp.warning); // Not a true write, ignore it
      } else if (!defop.isWarning()) {
        // No warning generated before
        defop.setAdditionalFlag(PcodeOp.warning);
        if ((!vn.isAddrForce()) || (!vn.hasNoDescend())) {
          const s = `Read-only address (${vn.getSpace()!.getName()},${vn.getAddr().printRaw()}) is written`;
          this.warning(s, defop.getAddr());
        }
      }
      return false; // No change was made
    }

    if (vn.getSize() > 8) {
      return false; // Constant will exceed precision
    }

    let bytes: Uint8Array;
    try {
      bytes = new Uint8Array(vn.getSize());
      this.glb.loader.loadFill(bytes, vn.getSize(), vn.getAddr());
    } catch (err) {
      // Could not get value from LoadImage
      vn.clearFlags(Varnode.readonly); // Treat as writeable
      return true;
    }

    let res: bigint;
    if (vn.getSpace()!.isBigEndian()) {
      // Big endian
      res = 0n;
      for (let i = 0; i < vn.getSize(); ++i) {
        res <<= 8n;
        res |= BigInt(bytes[i]);
      }
    } else {
      res = 0n;
      for (let i = vn.getSize() - 1; i >= 0; --i) {
        res <<= 8n;
        res |= BigInt(bytes[i]);
      }
    }

    // Replace all references to vn
    let changemade: boolean = false;
    const locktype: Datatype | null = vn.isTypeLock() ? vn.getType() : null;

    const descendants: PcodeOp[] = [...vn.descend];
    for (const op of descendants) {
      const i: number = op.getSlot(vn);
      if (op.isMarker()) {
        // Must be careful putting constants in here
        if ((op.code() !== OpCode.CPUI_INDIRECT) || (i !== 0)) continue;
        const outvn: Varnode = op.getOut()!;
        if (outvn.getAddr().equals(vn.getAddr())) continue; // Ignore indirect to itself
        // Change the indirect to a COPY
        this.opRemoveInput(op, 1);
        this.opSetOpcode(op, OpCode.CPUI_COPY);
      }
      const cvn: Varnode = this.newConstant(vn.getSize(), res);
      if (locktype !== null) {
        cvn.updateType(locktype, true, true); // Try to pass on the locked datatype
      }
      this.opSetInput(op, cvn, i);
      changemade = true;
    }
    return changemade;
  }

  /// The Varnode is assumed not fully linked. The read or write action is
  /// modeled by inserting a special user op that represents the action.
  replaceVolatile(vn: Varnode): boolean {
    let newop: PcodeOp;
    if (vn.isWritten()) {
      // A written value
      const vw_op: UserPcodeOp = this.glb.userops.registerBuiltin(UserPcodeOp.BUILTIN_VOLATILE_WRITE);
      if (!vn.hasNoDescend()) throw new LowlevelError("Volatile memory was propagated");
      const defop: PcodeOp = vn.getDef()!;
      newop = this.newOp(3, defop.getAddr());
      this.opSetOpcode(newop, OpCode.CPUI_CALLOTHER);
      // Create a userop of type specified by vw_op
      this.opSetInput(newop, this.newConstant(4, BigInt(vw_op.getIndex())), 0);
      // The first parameter is the offset of volatile memory location
      const annoteVn: Varnode = this.newCodeRef(vn.getAddr());
      annoteVn.setFlags(Varnode.volatil);
      this.opSetInput(newop, annoteVn, 1);
      // Replace the volatile variable with a temp
      const tmp: Varnode = this.newUnique(vn.getSize());
      this.opSetOutput(defop, tmp);
      // The temp is the second parameter to the userop
      this.opSetInput(newop, tmp, 2);
      this.opInsertAfter(newop, defop); // Insert after defining op
    } else {
      // A read value
      const vr_op: UserPcodeOp = this.glb.userops.registerBuiltin(UserPcodeOp.BUILTIN_VOLATILE_READ);
      if (vn.hasNoDescend()) return false; // Dead
      const readop: PcodeOp | null = vn.loneDescend();
      if (readop === null) {
        throw new LowlevelError("Volatile memory value used more than once");
      }
      newop = this.newOp(2, readop.getAddr());
      this.opSetOpcode(newop, OpCode.CPUI_CALLOTHER);
      // Create a temp to replace the volatile variable
      const tmp: Varnode = this.newUniqueOut(vn.getSize(), newop);
      // Create a userop of type specified by vr_op
      this.opSetInput(newop, this.newConstant(4, BigInt(vr_op.getIndex())), 0);
      // The first parameter is the offset of the volatile memory loc
      const annoteVn: Varnode = this.newCodeRef(vn.getAddr());
      annoteVn.setFlags(Varnode.volatil);
      this.opSetInput(newop, annoteVn, 1);
      this.opSetInput(readop, tmp, readop.getSlot(vn));
      this.opInsertBefore(newop, readop); // Insert before read
      if (vr_op.getDisplay() !== 0) {
        // Unless the display is functional,
        newop.setHoldOutput(); // read value may not be used. Keep it around anyway.
      }
    }
    if (vn.isTypeLock()) {
      // If the original varnode had a type locked on it
      newop.setAdditionalFlag(PcodeOp.special_prop); // Mark this op as doing special propagation
    }
    return true;
  }

  /// Check if the given Varnode only flows into call-based INDIRECT ops.
  /// Flow is only followed through MULTIEQUAL ops.
  static checkIndirectUse(vn: Varnode): boolean {
    const vlist: Varnode[] = [];
    let i = 0;
    vlist.push(vn);
    vn.setMark();
    let result: boolean = true;
    while ((i < vlist.length) && result) {
      vn = vlist[i++];
      for (const op of vn.descend) {
        const opc: OpCode = op.code();
        if (opc === OpCode.CPUI_INDIRECT) {
          if (op.isIndirectStore()) {
            // INDIRECT from a STORE is not a negative result but continue to follow data-flow
            const outvn: Varnode = op.getOut()!;
            if (!outvn.isMark()) {
              vlist.push(outvn);
              outvn.setMark();
            }
          }
        } else if (opc === OpCode.CPUI_MULTIEQUAL) {
          const outvn: Varnode = op.getOut()!;
          if (!outvn.isMark()) {
            vlist.push(outvn);
            outvn.setMark();
          }
        } else {
          result = false;
          break;
        }
      }
    }
    for (let j = 0; j < vlist.length; ++j) {
      vlist[j].clearMark();
    }
    return result;
  }

  /// The illegal inputs are additionally marked as indirectonly and
  /// isIndirectOnly() returns true.
  markIndirectOnly(): void {
    let iter = this.beginDefFlags(Varnode.input);
    const enditer = this.endDefFlags(Varnode.input);
    while (!iter.equals(enditer)) {
      const vn: Varnode = iter.get();
      iter.next();
      if (!vn.isIllegalInput()) continue; // Only check illegal inputs
      if (Funcdata.checkIndirectUse(vn)) {
        vn.setFlags(Varnode.indirectonly);
      }
    }
  }

  /// Free any Varnodes not attached to anything. This is only performed at fixed times so that
  /// editing operations can detach (and then reattach) Varnodes without losing them.
  clearDeadVarnodes(): void {
    const iter = this.vbank.beginLoc();
    while (!iter.equals(this.vbank.endLoc())) {
      const vn: Varnode = iter.get();
      iter.next();
      if (vn.hasNoDescend()) {
        if (vn.isInput() && !vn.isLockedInput()) {
          this.vbank.makeFree(vn);
          vn.clearCover();
        }
        if (vn.isFree()) {
          this.vbank.destroy(vn);
        }
      }
    }
  }

  /// All Varnodes are initialized assuming that all its bits are possibly non-zero. This method
  /// looks for situations where a p-code produces a value that is known to have some bits that are
  /// guaranteed to be zero.
  calcNZMask(): void {
    const opstack: PcodeOpNode[] = [];

    const endAlive = this.endOpAlive();
    for (let oiter = this.beginOpAlive(); !oiter.equals(endAlive); oiter.next()) {
      const op: PcodeOp = oiter.get();
      if (op.isMark()) continue;
      opstack.push(new PcodeOpNode(op, 0));
      op.setMark();

      do {
        // Get next edge
        const node: PcodeOpNode = opstack[opstack.length - 1];
        if (node.slot >= node.op.numInput()) {
          // If no edge left
          const outvn: Varnode | null = node.op.getOut();
          if (outvn !== null) {
            outvn.nzm = node.op.getNZMaskLocal(true);
          }
          opstack.pop(); // Pop a level
          continue;
        }
        const oldslot: number = node.slot;
        node.slot += 1; // Advance to next input
        // Determine if we want to traverse this edge
        if (node.op.code() === OpCode.CPUI_MULTIEQUAL) {
          if (node.op.getParent().isLoopIn(oldslot)) // Clip looping edges
            continue;
        }
        // Traverse edge indicated by slot
        const vn: Varnode = node.op.getIn(oldslot)!;
        if (!vn.isWritten()) {
          if (vn.isConstant()) {
            vn.nzm = vn.getOffset();
          } else {
            vn.nzm = calc_mask(vn.getSize());
            if (vn.isSpacebase()) {
              vn.nzm &= ~(0xFFn); // Treat spacebase input as aligned
            }
          }
        } else if (!vn.getDef()!.isMark()) {
          // If haven't traversed before
          opstack.push(new PcodeOpNode(vn.getDef()!, 0));
          vn.getDef()!.setMark();
        }
      } while (opstack.length > 0);
    }

    const worklist: PcodeOp[] = [];
    // Clear marks and push ops with looping edges onto worklist
    const endAlive2 = this.endOpAlive();
    for (let oiter = this.beginOpAlive(); !oiter.equals(endAlive2); oiter.next()) {
      const op: PcodeOp = oiter.get();
      op.clearMark();
      if (op.code() === OpCode.CPUI_MULTIEQUAL) {
        worklist.push(op);
      }
    }

    // Continue to propagate changes along all edges
    while (worklist.length > 0) {
      const op: PcodeOp = worklist.pop()!;
      const vn: Varnode | null = op.getOut();
      if (vn === null) continue;
      const nzmask: bigint = op.getNZMaskLocal(false);
      if (nzmask !== vn.nzm) {
        vn.nzm = nzmask;
        for (const descOp of vn.descend) {
          worklist.push(descOp);
        }
      }
    }
  }

  /// Update Varnode properties based on (new) Symbol information.
  /// Boolean properties addrtied, addrforce, and nolocalalias for Varnodes are updated
  /// based on new Symbol information they map to.
  syncVarnodesWithSymbols(lm: ScopeLocal, updateDatatypes: boolean, unmappedAliasCheck: boolean): boolean {
    let updateoccurred: boolean = false;
    let ct: Datatype | null;
    let entry: SymbolEntry | null;
    let fl: number;

    let iter = this.beginLoc(lm.getSpaceId());
    const enditer = this.endLoc(lm.getSpaceId());
    while (!iter.equals(enditer)) {
      const vnexemplar: Varnode = iter.get();
      entry = lm.findOverlap(vnexemplar.getAddr(), vnexemplar.getSize());
      ct = null;
      if (entry !== null) {
        fl = entry.getAllFlags();
        if (entry.getSize() >= vnexemplar.getSize()) {
          if (updateDatatypes) {
            ct = entry.getSizedType(vnexemplar.getAddr(), vnexemplar.getSize());
            if ((globalThis as any).__DEBUG_PROPAGATE__ && vnexemplar.getSize() === 16 && vnexemplar.getSpace()?.getName() === 'stack') {
              process.stderr.write(`[syncVarnodes] stack16 addr=${vnexemplar.getAddr().printRaw()} entrySz=${entry.getSize()} symType=${entry.getSymbol().getType().getName()}(meta=${entry.getSymbol().getType().getMetatype()}) ct=${ct?.getName() ?? 'null'}(meta=${ct?.getMetatype() ?? '-'})\n`);
            }
            if (ct !== null && ct.getMetatype() === type_metatype.TYPE_UNKNOWN) {
              ct = null;
            }
          }
        } else {
          // Overlapping but not containing
          fl &= ~(Varnode.typelock | Varnode.namelock);
        }
      } else {
        // Could not find any symbol
        if (lm.inScope(vnexemplar.getAddr(), vnexemplar.getSize(),
          vnexemplar.getUsePoint(this))) {
          fl = Varnode.mapped | Varnode.addrtied;
        } else if (unmappedAliasCheck) {
          fl = lm.isUnmappedUnaliased(vnexemplar) ? Varnode.nolocalalias : 0;
        } else {
          fl = 0;
        }
      }
      if (this.syncVarnodesWithSymbol(iter as any, fl, ct)) {
        updateoccurred = true;
      }
    }
    return updateoccurred;
  }

  /// A Varnode overlaps the given SymbolEntry. Make sure the Varnode is part of the variable
  /// underlying the Symbol. If not, remap things so that the Varnode maps to a distinct Symbol.
  handleSymbolConflict(entry: SymbolEntry, vn: Varnode): Symbol {
    if (vn.isInput() || vn.isAddrTied() ||
      vn.isPersist() || vn.isConstant() || entry.isDynamic()) {
      vn.setSymbolEntry(entry);
      return entry.getSymbol();
    }
    if (!vn.hasHigh()) {
      vn.setSymbolEntry(entry);
      return entry.getSymbol();
    }
    const high: HighVariable = vn.getHigh();
    let otherVn: Varnode;
    let otherHigh: HighVariable | null = null;
    // Look for a conflicting HighVariable
    let iter = this.beginLoc(entry.getSize(), entry.getAddr());
    const endLocIter = this.endLoc();
    while (!iter.equals(endLocIter)) {
      otherVn = iter.get();
      if (otherVn.getSize() !== entry.getSize()) break;
      if (!otherVn.getAddr().equals(entry.getAddr())) break;
      if (!otherVn.hasHigh()) { iter.next(); continue; }
      const tmpHigh: HighVariable = otherVn.getHigh();
      if (tmpHigh !== high) {
        otherHigh = tmpHigh;
        break;
      }
      iter.next();
    }
    if (otherHigh === null) {
      vn.setSymbolEntry(entry);
      return entry.getSymbol();
    }

    // If we reach here, we have a conflicting variable
    this.buildDynamicSymbol(vn);
    return vn.getSymbolEntry()!.getSymbol();
  }

  /// Update properties (and the data-type) for a set of Varnodes associated with one Symbol.
  /// The set of Varnodes with the same size and address all have their boolean properties
  /// updated to the given values.
  private syncVarnodesWithSymbol(iter: any, fl: number, ct: Datatype | null): boolean {
    let vn: Varnode;
    let vnflags: number;
    let updateoccurred: boolean = false;
    // These are the flags we are going to try to update
    let mask: number = Varnode.mapped;
    // We take special care with the addrtied flag
    // We can CLEAR but not SET the addrtied flag
    if ((fl & Varnode.addrtied) === 0) {
      mask |= Varnode.addrtied | Varnode.addrforce;
    }
    // We can set the nolocalalias flag, but not clear it
    if ((fl & Varnode.nolocalalias) !== 0) {
      mask |= Varnode.nolocalalias | Varnode.addrforce;
    }
    fl &= mask;

    vn = iter.get();
    const enditer = this.endLoc(vn.getSize(), vn.getAddr());
    do {
      vn = iter.get();
      iter.next();
      if (vn.isFree()) continue;
      vnflags = vn.getFlags();
      if (vn.mapentry !== null) {
        // If there is already an attached SymbolEntry (dynamic)
        const localMask: number = mask & ~Varnode.mapped;
        const localFlags: number = fl & localMask;
        if ((vnflags & localMask) !== localFlags) {
          updateoccurred = true;
          vn.setFlags(localFlags);
          vn.clearFlags((~localFlags) & localMask);
        }
      } else if ((vnflags & mask) !== fl) {
        // We have a change
        updateoccurred = true;
        vn.setFlags(fl);
        vn.clearFlags((~fl) & mask);
      }
      if (ct !== null) {
        if ((globalThis as any).__DEBUG_PROPAGATE__ && vn.getSize() === 16 && vn.getSpace()?.getName() === 'stack') {
          process.stderr.write(`[syncVarnodesWithSymbol] stack16 addr=${vn.getAddr().printRaw()} ct=${ct.getName()}(meta=${ct.getMetatype()}) vnType=${vn.getType()?.getName()}(meta=${vn.getType()?.getMetatype()}) typeLock=${vn.isTypeLock()}\n`);
        }
        if (vn.updateType(ct)) {
          updateoccurred = true;
        }
      }
    } while (!iter.equals(enditer));
    return updateoccurred;
  }

  /// Remap a Symbol to a given Varnode using a static mapping.
  remapVarnode(vn: Varnode, sym: Symbol, usepoint: Address): void {
    vn.clearSymbolLinks();
    const entry: SymbolEntry = this.localmap!.remapSymbol(sym, vn.getAddr(), usepoint);
    vn.setSymbolEntry(entry);
  }

  /// Remap a Symbol to a given Varnode using a new dynamic mapping.
  remapDynamicVarnode(vn: Varnode, sym: Symbol, usepoint: Address, hash: bigint): void {
    vn.clearSymbolLinks();
    const entry: SymbolEntry = this.localmap!.remapSymbolDynamic(sym, hash, usepoint);
    vn.setSymbolEntry(entry);
  }

  /// PIECE operations put the given Varnode into a larger structure. Find the resulting
  /// whole Varnode, make sure it has a symbol assigned, and then assign the same symbol
  /// to the given Varnode piece.
  linkProtoPartial(vn: Varnode): void {
    const high: HighVariable = vn.getHigh();
    if (high.getSymbol() !== null) return;
    const rootVn: Varnode | null = (PieceNode as any).findRoot(vn);
    if (rootVn === vn) return;

    const rootHigh: HighVariable = rootVn!.getHigh();
    if (!rootHigh.isSameGroup(high)) return;
    const nameRep: Varnode = rootHigh.getNameRepresentative();
    const sym: Symbol | null = this.linkSymbol(nameRep);
    if (sym === null) return;
    rootHigh.establishGroupSymbolOffset();
    const entry: SymbolEntry = sym.getFirstWholeMap();
    vn.setSymbolEntry(entry);
  }

  /// The Symbol is really attached to the Varnode's HighVariable (which must exist).
  /// The only reason a Symbol doesn't get set is if the HighVariable
  /// is global and there is no pre-existing Symbol.
  linkSymbol(vn: Varnode): Symbol | null {
    if (vn.isProtoPartial()) {
      this.linkProtoPartial(vn);
    }
    const high: HighVariable = vn.getHigh();
    let entry: SymbolEntry | null;
    let fl: number = 0;
    let sym: Symbol | null = high.getSymbol();
    if (sym !== null) return sym; // Symbol already assigned

    const usepoint: Address = vn.getUsePoint(this);
    // Find any entry overlapping base address
    const result = this.localmap!.queryProperties(vn.getAddr(), 1, usepoint);
    entry = result.entry;
    fl = result.flags;
    if (entry !== null) {
      sym = this.handleSymbolConflict(entry, vn);
    } else {
      // Must create a symbol entry
      if (!vn.isPersist()) {
        // Only create local symbol
        let entryUsepoint: Address = usepoint;
        if (vn.isAddrTied()) {
          entryUsepoint = new Address();
        }
        entry = this.localmap!.addSymbol("", high.getType(), vn.getAddr(), entryUsepoint);
        sym = entry!.getSymbol();
        vn.setSymbolEntry(entry);
      }
    }

    return sym;
  }

  /// A reference to a symbol (i.e. &varname) is typically stored as a PTRSUB operation.
  /// This method takes the constant Varnode, recovers the symbol it is referring to,
  /// and stores on the HighVariable object attached to the Varnode.
  linkSymbolReference(vn: Varnode): Symbol | null {
    const op: PcodeOp = vn.loneDescend()!;
    const in0: Varnode = op.getIn(0)!;
    const ptype: TypePointer = in0.getHigh().getType() as TypePointer;
    if (ptype.getMetatype() !== type_metatype.TYPE_PTR) return null;
    const sb: TypeSpacebase = ptype.getPtrTo() as TypeSpacebase;
    if (sb.getMetatype() !== type_metatype.TYPE_SPACEBASE) return null;
    const scope: Scope = sb.getMap();
    const addr: Address = sb.getAddress(vn.getOffset(), in0.getSize(), op.getAddr());
    if (addr.isInvalid()) {
      throw new LowlevelError("Unable to generate proper address from spacebase");
    }
    const entry: SymbolEntry | null = scope.queryContainer(addr, 1, new Address());
    if (entry === null) return null;
    const off: number = Number(addr.getOffset() - entry.getAddr().getOffset()) + entry.getOffset();
    vn.setSymbolReference(entry, off);
    return entry.getSymbol();
  }

  /// Return the (first) Varnode that matches the given SymbolEntry.
  findLinkedVarnode(entry: SymbolEntry): Varnode | null {
    if (entry.isDynamic()) {
      const dhash: DynamicHash = new DynamicHash();
      const vn: Varnode | null = dhash.findVarnode(this, entry.getFirstUseAddress(), entry.getHash());
      if (vn === null || vn.isAnnotation()) return null;
      return vn;
    }

    const enditer = this.endLoc(entry.getSize(), entry.getAddr());
    const usestart: Address = entry.getFirstUseAddress();

    if (usestart.isInvalid()) {
      const iter = this.beginLoc(entry.getSize(), entry.getAddr());
      if (iter.equals(enditer)) return null;
      const vn: Varnode = iter.get();
      if (!vn.isAddrTied()) return null;
      return vn;
    }
    let iter = this.vbank.beginLocSizeAddrPcUniq(entry.getSize(), entry.getAddr(), usestart, ~0 >>> 0);
    while (!iter.equals(enditer)) {
      const vn: Varnode = iter.get();
      const usepoint: Address = vn.getUsePoint(this);
      if (entry.inUse(usepoint)) return vn;
      iter.next();
    }
    return null;
  }

  /// Look for Varnodes that are (should be) mapped to the given SymbolEntry and
  /// add them to the end of the result list.
  findLinkedVarnodes(entry: SymbolEntry, res: Varnode[]): void {
    if (entry.isDynamic()) {
      const dhash: DynamicHash = new DynamicHash();
      const vn: Varnode | null = dhash.findVarnode(this, entry.getFirstUseAddress(), entry.getHash());
      if (vn !== null) {
        res.push(vn);
      }
    } else {
      let iter = this.beginLoc(entry.getSize(), entry.getAddr());
      const enditer = this.endLoc(entry.getSize(), entry.getAddr());
      while (!iter.equals(enditer)) {
        const vn: Varnode = iter.get();
        const addr: Address = vn.getUsePoint(this);
        if (entry.inUse(addr)) {
          res.push(vn);
        }
        iter.next();
      }
    }
  }

  /// If a Symbol is already attached, no change is made. Otherwise a special dynamic Symbol is
  /// created that is associated with the Varnode via a hash of its local data-flow.
  buildDynamicSymbol(vn: Varnode): void {
    if (vn.isTypeLock() || vn.isNameLock()) {
      throw new RecovError("Trying to build dynamic symbol on locked varnode");
    }
    if (!this.isHighOn()) {
      throw new RecovError("Cannot create dynamic symbols until decompile has completed");
    }
    const high: HighVariable = vn.getHigh();
    if (high.getSymbol() !== null) return; // Symbol already exists
    const dhash: DynamicHash = new DynamicHash();

    dhash.uniqueHash(vn, this); // Calculate a unique dynamic hash for this varnode
    if (dhash.getHash() === 0n) {
      throw new RecovError("Unable to find unique hash for varnode");
    }

    let sym: Symbol;
    if (vn.isConstant()) {
      sym = this.localmap!.addEquateSymbol("", Symbol.force_hex, vn.getOffset(), dhash.getAddress(), dhash.getHash());
    } else {
      sym = this.localmap!.addDynamicSymbol("", high.getType(), dhash.getAddress(), dhash.getHash());
    }
    vn.setSymbolEntry(sym.getFirstWholeMap());
  }

  /// Given a dynamic mapping, try to find the mapped Varnode, then adjust (type and flags)
  /// to reflect this mapping.
  attemptDynamicMapping(entry: SymbolEntry, dhash: DynamicHash): boolean {
    const sym: Symbol = entry.getSymbol();
    if (sym.getScope() !== this.localmap) {
      throw new LowlevelError("Cannot currently have a dynamic symbol outside the local scope");
    }
    dhash.clear();
    const category: number = sym.getCategory();
    if (category === Symbol.union_facet) {
      return this.applyUnionFacet(entry, dhash);
    }
    const vn: Varnode | null = dhash.findVarnode(this, entry.getFirstUseAddress(), entry.getHash());
    if (vn === null) return false;
    if (vn.getSymbolEntry() !== null) return false; // Varnode is already labeled
    if (category === Symbol.equate) {
      // Is this an equate symbol
      vn.setSymbolEntry(entry);
      return true;
    } else if (entry.getSize() === vn.getSize()) {
      if (vn.setSymbolProperties(entry)) return true;
    }
    return false;
  }

  /// Given a dynamic mapping, try to find the mapped Varnode, then attach the Symbol to the Varnode.
  /// The name of the Symbol is used, but the data-type and possibly other properties are not
  /// put on the Varnode.
  attemptDynamicMappingLate(entry: SymbolEntry, dhash: DynamicHash): boolean {
    dhash.clear();
    const sym: Symbol = entry.getSymbol();
    if (sym.getCategory() === Symbol.union_facet) {
      return this.applyUnionFacet(entry, dhash);
    }
    let vn: Varnode | null = dhash.findVarnode(this, entry.getFirstUseAddress(), entry.getHash());
    if (vn === null) return false;
    if (vn.getSymbolEntry() !== null) return false; // Symbol already applied
    if (sym.getCategory() === Symbol.equate) {
      // Equate symbol does not depend on size
      vn.setSymbolEntry(entry);
      return true;
    }
    if (vn.getSize() !== entry.getSize()) {
      let s = "Unable to use symbol ";
      if (!sym.isNameUndefined()) {
        s += sym.getName() + " ";
      }
      s += ": Size does not match variable it labels";
      this.warningHeader(s);
      return false;
    }

    if (vn.isImplied()) {
      // This should be finding an explicit, but a cast may have been inserted
      let newvn: Varnode | null = null;
      // Look at the "other side" of the cast
      if (vn.isWritten() && (vn.getDef()!.code() === OpCode.CPUI_CAST)) {
        newvn = vn.getDef()!.getIn(0);
      } else {
        const castop: PcodeOp | null = vn.loneDescend();
        if ((castop !== null) && (castop.code() === OpCode.CPUI_CAST)) {
          newvn = castop.getOut();
        }
      }
      // See if the varnode on the other side is explicit
      if ((newvn !== null) && (newvn.isExplicit())) {
        vn = newvn; // in which case we use it
      }
    }

    vn.setSymbolEntry(entry);
    if (!sym.isTypeLocked()) {
      // If the dynamic symbol did not lock its type
      this.localmap!.retypeSymbol(sym, vn.getType()); // use the type propagated into the varnode
    } else if (sym.getType() !== vn.getType()) {
      const s = "Unable to use type for symbol " + sym.getName();
      this.warningHeader(s);
      this.localmap!.retypeSymbol(sym, vn.getType()); // use the type propagated into the varnode
    }
    return true;
  }

  /// Create Varnode (and associated PcodeOp) that will display as a string constant.
  getInternalString(buf: Uint8Array, size: number, ptrType: Datatype, readOp: PcodeOp): Varnode | null {
    if (ptrType.getMetatype() !== type_metatype.TYPE_PTR) return null;
    const charType: Datatype = (ptrType as TypePointer).getPtrTo();

    const addr: Address = readOp.getAddr();
    const hash: bigint = this.glb.stringManager.registerInternalStringData(addr, buf, size, charType);
    if (hash === 0n) return null;
    this.glb.userops.registerBuiltin(UserPcodeOp.BUILTIN_STRINGDATA);
    const stringOp: PcodeOp = this.newOp(2, addr);
    this.opSetOpcode(stringOp, OpCode.CPUI_CALLOTHER);
    stringOp.clearFlag(PcodeOp.call);
    this.opSetInput(stringOp, this.newConstant(4, BigInt(UserPcodeOp.BUILTIN_STRINGDATA)), 0);
    this.opSetInput(stringOp, this.newConstant(8, hash), 1);
    const resVn: Varnode = this.newUniqueOut(ptrType.getSize(), stringOp);
    resVn.updateType(ptrType, true, false);
    this.opInsertBefore(stringOp, readOp);
    return resVn;
  }

  /// Follow the Varnode back to see if it comes from the return address for this function.
  testForReturnAddress(vn: Varnode): boolean {
    const retaddr: VarnodeData = this.glb.defaultReturnAddr;
    if (retaddr.space === null) return false; // No standard storage location to compare to
    while (vn.isWritten()) {
      const op: PcodeOp = vn.getDef()!;
      const opc: OpCode = op.code();
      if (opc === OpCode.CPUI_INDIRECT || opc === OpCode.CPUI_COPY) {
        vn = op.getIn(0)!;
      } else if (opc === OpCode.CPUI_INT_AND) {
        // We only want to allow "alignment" style masking
        if (!op.getIn(1)!.isConstant()) return false;
        vn = op.getIn(0)!;
      } else {
        return false;
      }
    }
    if (vn.getSpace() !== retaddr.space || vn.getOffset() !== retaddr.offset || vn.getSize() !== retaddr.size) {
      return false;
    }
    if (!vn.isInput()) return false;
    return true;
  }

  /// Replace all read references to the first Varnode with a second Varnode.
  totalReplace(vn: Varnode, newvn: Varnode): void {
    const descendants: PcodeOp[] = [...vn.descend];
    for (const op of descendants) {
      const i: number = op.getSlot(vn);
      this.opSetInput(op, newvn, i);
    }
  }

  /// Replace every read reference of the given Varnode with a constant value.
  /// A new constant Varnode is created for each read site.
  totalReplaceConstant(vn: Varnode, val: bigint): void {
    let copyop: PcodeOp | null = null;
    let newrep: Varnode;

    const descendants: PcodeOp[] = [...vn.descend];
    for (const op of descendants) {
      const i: number = op.getSlot(vn);
      if (op.isMarker()) {
        // Do not put constant directly in marker
        if (copyop === null) {
          if (vn.isWritten()) {
            copyop = this.newOp(1, vn.getDef()!.getAddr());
            this.opSetOpcode(copyop, OpCode.CPUI_COPY);
            newrep = this.newUniqueOut(vn.getSize(), copyop);
            this.opSetInput(copyop, this.newConstant(vn.getSize(), val), 0);
            this.opInsertAfter(copyop, vn.getDef()!);
          } else {
            const bb: BlockBasic = this.getBasicBlocks().getBlock(0) as BlockBasic;
            copyop = this.newOp(1, bb.getStart());
            this.opSetOpcode(copyop, OpCode.CPUI_COPY);
            newrep = this.newUniqueOut(vn.getSize(), copyop);
            this.opSetInput(copyop, this.newConstant(vn.getSize(), val), 0);
            this.opInsertBegin(copyop, bb);
          }
        } else {
          newrep = copyop.getOut()!;
        }
      } else {
        newrep = this.newConstant(vn.getSize(), val);
      }
      this.opSetInput(op, newrep, i);
    }
  }

  /// For the given Varnode, duplicate its defining PcodeOp at each read of the Varnode
  /// so that the read becomes a new unique Varnode.
  splitUses(vn: Varnode): void {
    const op: PcodeOp = vn.getDef()!;
    const descendants: PcodeOp[] = [...vn.descend];
    if (descendants.length <= 1) return; // Only one or no descendants

    for (let idx = 0; idx < descendants.length - 1; ++idx) {
      const useop: PcodeOp = descendants[idx];
      const slot: number = useop.getSlot(vn);
      const newop: PcodeOp = this.newOp(op.numInput(), op.getAddr());
      const newvn: Varnode = this.newVarnode(vn.getSize(), vn.getAddr(), vn.getType());
      this.opSetOutput(newop, newvn);
      this.opSetOpcode(newop, op.code());
      for (let i = 0; i < op.numInput(); ++i) {
        this.opSetInput(newop, op.getIn(i)!, i);
      }
      this.opSetInput(useop, newvn, slot);
      this.opInsertBefore(newop, op);
    }
    // Dead-code actions should remove original op
  }

  /// Find the minimal Address range covering the given Varnode that doesn't split other Varnodes.
  findDisjointCover(vn: Varnode): { addr: Address, sz: number } {
    let addr: Address = vn.getAddr();
    let endaddr: Address = addr.add(BigInt(vn.getSize()));
    let iter = vn.lociter!.clone();

    while (!iter.equals(this.beginLoc())) {
      iter.prev();
      const curvn: Varnode = iter.get();
      const curEnd: Address = curvn.getAddr().add(BigInt(curvn.getSize()));
      if (curEnd.getOffset() <= addr.getOffset()) break;
      addr = curvn.getAddr();
    }
    iter = vn.lociter!.clone();
    while (!iter.equals(this.endLoc())) {
      const curvn: Varnode = iter.get();
      iter.next();
      if (endaddr.getOffset() <= curvn.getAddr().getOffset()) break;
      endaddr = curvn.getAddr().add(BigInt(curvn.getSize()));
    }
    const sz: number = Number(endaddr.getOffset() - addr.getOffset());
    return { addr, sz };
  }

  /// Make sure every Varnode in the given list has a Symbol it will link to.
  /// This is used when Varnodes overlap a locked Symbol but extend beyond it.
  coverVarnodes(entry: SymbolEntry, list: Varnode[]): void {
    const scope: Scope = entry.getSymbol().getScope();
    for (let i = 0; i < list.length; ++i) {
      const vn: Varnode = list[i];
      // We only need to check once for all Varnodes at the same Address
      // Of these, pick the biggest Varnode
      if (i + 1 < list.length && list[i + 1].getAddr().equals(vn.getAddr())) continue;
      let usepoint: Address = vn.getUsePoint(this);
      const overlapEntry: SymbolEntry | null = scope.findContainer(vn.getAddr(), vn.getSize(), usepoint);
      if (overlapEntry === null) {
        const diff: number = Number(vn.getOffset() - entry.getAddr().getOffset());
        const s = entry.getSymbol().getName() + "_" + diff;
        if (vn.isAddrTied()) {
          usepoint = new Address();
        }
        scope.addSymbol(s, vn.getHigh().getType(), vn.getAddr(), usepoint);
      }
    }
  }

  /// Cache information from a UnionFacetSymbol.
  /// The symbol forces a particular union field resolution for the associated PcodeOp and slot.
  applyUnionFacet(entry: SymbolEntry, dhash: DynamicHash): boolean {
    const sym: Symbol = entry.getSymbol();
    const op: PcodeOp | null = dhash.findOp(this, entry.getFirstUseAddress(), entry.getHash());
    if (op === null) return false;
    const slot: number = DynamicHash.getSlotFromHash(entry.getHash());
    const fldNum: number = (sym as UnionFacetSymbol).getFieldNumber();
    const resolve: ResolvedUnion = new ResolvedUnion(sym.getType(), fldNum, this.glb.types);
    resolve.setLock(true);
    return this.setUnionField(sym.getType(), op, slot, resolve);
  }

  /// Search for addrtied Varnodes whose storage falls in the global Scope, then
  /// build a new global Symbol if one didn't exist before.
  mapGlobals(): void {
    let entry: SymbolEntry | null;
    let vn: Varnode;
    let maxvn: Varnode;
    let ct: Datatype;
    let fl: number;
    const uncoveredVarnodes: Varnode[] = [];
    let inconsistentuse: boolean = false;

    let iter = this.vbank.beginLoc();
    const enditer = this.vbank.endLoc();
    while (!iter.equals(enditer)) {
      vn = iter.get();
      iter.next();
      if (vn.isFree()) continue;
      if (!vn.isPersist()) continue; // Could be a code ref
      if (vn.getSymbolEntry() !== null) continue;
      maxvn = vn;
      const addr: Address = vn.getAddr();
      let endaddr: Address = addr.add(BigInt(vn.getSize()));
      uncoveredVarnodes.length = 0;
      while (!iter.equals(enditer)) {
        vn = iter.get();
        if (!vn.isPersist()) break;
        if (vn.getAddr().getOffset() < endaddr.getOffset()) {
          // Varnodes at the same base address will get linked to the Symbol at that address
          // even if the size doesn't match, but we check for internal Varnodes that
          // do not have an attached Symbol as these won't get linked to anything
          if (!vn.getAddr().equals(addr) && vn.getSymbolEntry() === null) {
            uncoveredVarnodes.push(vn);
          }
          endaddr = vn.getAddr().add(BigInt(vn.getSize()));
          if (vn.getSize() > maxvn.getSize()) {
            maxvn = vn;
          }
          iter.next();
        } else {
          break;
        }
      }
      if (maxvn.getAddr().equals(addr) && addr.add(BigInt(maxvn.getSize())).equals(endaddr)) {
        ct = maxvn.getHigh().getType();
      } else {
        ct = this.glb.types.getBase(Number(endaddr.getOffset() - addr.getOffset()), type_metatype.TYPE_UNKNOWN);
      }

      fl = 0;
      // Assume existing symbol is addrtied, so use empty usepoint
      const usepoint: Address = new Address();
      // Find any entry overlapping base address
      const result = this.localmap!.queryProperties(addr, 1, usepoint);
      entry = result.entry;
      fl = result.flags;
      if (entry === null) {
        const discover: Scope | null = this.localmap!.discoverScope(addr, ct.getSize(), usepoint);
        if (discover === null) {
          throw new LowlevelError("Could not discover scope");
        }
        let index = 0;
        const symbolname: string = discover.buildVariableName(addr, usepoint, ct, index,
          Varnode.addrtied | Varnode.persist);
        discover.addSymbol(symbolname, ct, addr, usepoint);
      } else if ((addr.getOffset() + BigInt(ct.getSize())) - 1n > (entry.getAddr().getOffset() + BigInt(entry.getSize())) - 1n) {
        inconsistentuse = true;
        if (uncoveredVarnodes.length > 0) {
          // Provide Symbols for any uncovered internal Varnodes
          this.coverVarnodes(entry, uncoveredVarnodes);
        }
      }
    }
    if (inconsistentuse) {
      this.warningHeader("Globals starting with '_' overlap smaller symbols at the same address");
    }
  }

  /// Make sure that if a Varnode exists representing the "this" pointer for the function, that it
  /// is treated as pointer data-type.
  prepareThisPointer(): void {
    const numInputs: number = this.funcp.numParams();
    for (let i = 0; i < numInputs; ++i) {
      const param: ProtoParameter = this.funcp.getParam(i);
      if (param.isThisPointer() && param.isTypeLocked()) return;
    }

    // It's possible that a recommendation for the "this" pointer has already been collected
    if (this.localmap!.hasTypeRecommendations()) return;

    let dt: Datatype = this.glb.types.getTypeVoid();
    const spc: AddrSpace = this.glb.getDefaultDataSpace();
    dt = this.glb.types.getTypePointer(spc.getAddrSize(), dt, spc.getWordSize());
    const addr: Address = this.funcp.getThisPointerStorage(dt);
    this.localmap!.addTypeRecommendation(addr, dt);
  }

  /// Test for legitimate double use of a parameter trial.
  /// The given trial is a putative input to first CALL, but can also trace its data-flow
  /// into a second CALL.
  checkCallDoubleUse(opmatch: PcodeOp, op: PcodeOp, vn: Varnode, fl: number, trial: ParamTrial): boolean {
    const j: number = op.getSlot(vn);
    if (j <= 0) return false; // Flow traces to indirect call variable, definitely not a param
    const fc: FuncCallSpecs = this.getCallSpecs(op)!;
    const matchfc: FuncCallSpecs = this.getCallSpecs(opmatch)!;
    if (op.code() === opmatch.code()) {
      const isdirect: boolean = (opmatch.code() === OpCode.CPUI_CALL);
      if ((isdirect && matchfc.getEntryAddress().equals(fc.getEntryAddress())) ||
        ((!isdirect) && (op.getIn(0) === opmatch.getIn(0)))) {
        // If it is a call to the same function
        const curtrial: ParamTrial = fc.getActiveInput()!.getTrialForInputVarnode(j);
        if (curtrial.getAddress().equals(trial.getAddress())) {
          // Check for same memory location
          if (op.getParent() === opmatch.getParent()) {
            if (opmatch.getSeqNum().getOrder() < op.getSeqNum().getOrder()) {
              return true; // opmatch has dibs, don't reject
            }
            // If use op occurs earlier than match op, we might still need to reject
          } else {
            return true; // Same function, different basic blocks, assume legit doubleuse
          }
        }
      }
    }

    if (fc.isInputActive()) {
      const curtrial: ParamTrial = fc.getActiveInput()!.getTrialForInputVarnode(j);
      if (curtrial.isChecked()) {
        if (curtrial.isActive()) return false;
      } else if (TraverseNode.isAlternatePathValid(vn, fl)) {
        return false;
      }
      return true;
    }
    return false;
  }

  /// Test if the given Varnode seems to only be used by a CALL.
  onlyOpUse(invn: Varnode, opmatch: PcodeOp, trial: ParamTrial, mainFlags: number): boolean {
    const varlist: TraverseNode[] = [];
    let res: boolean = true;

    invn.setMark(); // Marks prevent infinite loops
    varlist.push(new TraverseNode(invn, mainFlags));

    for (let i = 0; i < varlist.length; ++i) {
      const vn: Varnode = varlist[i].vn as Varnode;
      const baseFlags: number = varlist[i].flags;
      for (const op of vn.descend) {
        if (op === opmatch) {
          if (op.getIn(trial.getSlot()) === vn) continue;
        }
        let curFlags: number = baseFlags;
        switch (op.code()) {
          case OpCode.CPUI_BRANCH:
          case OpCode.CPUI_CBRANCH:
          case OpCode.CPUI_BRANCHIND:
          case OpCode.CPUI_LOAD:
          case OpCode.CPUI_STORE:
            res = false;
            break;
          case OpCode.CPUI_CALL:
          case OpCode.CPUI_CALLIND:
            if (this.checkCallDoubleUse(opmatch, op, vn, curFlags, trial)) continue;
            res = false;
            break;
          case OpCode.CPUI_INDIRECT:
            curFlags |= TraverseNode.indirectalt;
            break;
          case OpCode.CPUI_COPY:
            if ((op.getOut()!.getSpace().getType() !== spacetype.IPTR_INTERNAL) && !op.isIncidentalCopy() && !vn.isIncidentalCopy()) {
              curFlags |= TraverseNode.actionalt;
            }
            break;
          case OpCode.CPUI_RETURN:
            if (opmatch.code() === OpCode.CPUI_RETURN) {
              // Are we in a different return
              if (op.getIn(trial.getSlot()) === vn) continue; // But at the same slot
            } else if (this.activeoutput !== null) {
              // Are we in the middle of analyzing returns
              if (op.getIn(0) !== vn) {
                // Unless we hold actual return value
                if (!TraverseNode.isAlternatePathValid(vn, curFlags)) continue;
              }
            }
            res = false;
            break;
          case OpCode.CPUI_MULTIEQUAL:
          case OpCode.CPUI_INT_SEXT:
          case OpCode.CPUI_INT_ZEXT:
          case OpCode.CPUI_CAST:
            break;
          case OpCode.CPUI_PIECE:
            if (op.getIn(0) === vn) {
              // Concatenated as most significant piece
              if ((curFlags & TraverseNode.lsb_truncated) !== 0) {
                continue; // No longer assume this is a possible use
              }
              curFlags |= TraverseNode.concat_high;
            }
            break;
          case OpCode.CPUI_SUBPIECE:
            if (op.getIn(1).getOffset() !== 0n) {
              // Throwing away least significant byte(s)
              if ((curFlags & TraverseNode.concat_high) === 0) {
                curFlags |= TraverseNode.lsb_truncated;
              }
            }
            break;
          default:
            curFlags |= TraverseNode.actionalt;
            break;
        }
        if (!res) break;
        const subvn: Varnode | null = op.getOut();
        if (subvn !== null) {
          if (subvn.isPersist()) {
            res = false;
            break;
          }
          if (!subvn.isMark()) {
            varlist.push(new TraverseNode(subvn, curFlags));
            subvn.setMark();
          }
        }
      }
      if (!res) break;
    }
    for (let i = 0; i < varlist.length; ++i) {
      (varlist[i].vn as Varnode).clearMark();
    }
    return res;
  }

  /// Test if the given trial Varnode is likely only used for parameter passing.
  /// Flow is followed from the Varnode itself and from ancestors the Varnode was copied from.
  ancestorOpUse(maxlevel: number, invn: Varnode, op: PcodeOp, trial: ParamTrial, offset: number, mainFlags: number): boolean {
    if (maxlevel === 0) return false;

    if (!invn.isWritten()) {
      if (!invn.isInput()) return false;
      if (!invn.isTypeLock()) return false;
      // If the input is typelocked this is as good as being written
      return this.onlyOpUse(invn, op, trial, mainFlags); // Test if varnode is only used in op
    }

    const def: PcodeOp = invn.getDef()!;
    switch (def.code()) {
      case OpCode.CPUI_INDIRECT:
        // An indirectCreation is an indication of an output trial, this should not count as
        // an "only use"
        if (def.isIndirectCreation()) return false;
        return this.ancestorOpUse(maxlevel - 1, def.getIn(0)!, op, trial, offset, mainFlags | TraverseNode.indirect);
      case OpCode.CPUI_MULTIEQUAL:
        // Check if there is any ancestor whose only use is in this op
        if (def.isMark()) return false; // Trim the loop
        def.setMark(); // Mark that this MULTIEQUAL is on the path
        for (let i = 0; i < def.numInput(); ++i) {
          if (this.ancestorOpUse(maxlevel - 1, def.getIn(i)!, op, trial, offset, mainFlags)) {
            def.clearMark();
            return true;
          }
        }
        def.clearMark();
        return false;
      case OpCode.CPUI_COPY:
        if ((invn.getSpace()!.getType() === spacetype.IPTR_INTERNAL) || def.isIncidentalCopy() || def.getIn(0)!.isIncidentalCopy()) {
          return this.ancestorOpUse(maxlevel - 1, def.getIn(0)!, op, trial, offset, mainFlags);
        }
        break;
      case OpCode.CPUI_PIECE:
        // Concatenation tends to be artificial, so recurse through piece corresponding later SUBPIECE
        if (offset === 0)
          return this.ancestorOpUse(maxlevel - 1, def.getIn(1)!, op, trial, 0, mainFlags); // Follow into least sig piece
        if (offset === def.getIn(1)!.getSize())
          return this.ancestorOpUse(maxlevel - 1, def.getIn(0)!, op, trial, 0, mainFlags); // Follow into most sig piece
        return false;
      case OpCode.CPUI_SUBPIECE: {
        const newOff: number = Number(def.getIn(1)!.getOffset());
        // This is a rather kludgy way to get around where a DIV (or other similar) instruction
        // causes a register that looks like the high precision piece of the function return
        // to be set with the remainder as a side effect
        if (newOff === 0) {
          const vnCheck: Varnode = def.getIn(0)!;
          if (vnCheck.isWritten()) {
            const remop: PcodeOp = vnCheck.getDef()!;
            if ((remop.code() === OpCode.CPUI_INT_REM) || (remop.code() === OpCode.CPUI_INT_SREM)) {
              trial.setRemFormed();
            }
          }
        }
        if (invn.getSpace()!.getType() === spacetype.IPTR_INTERNAL || def.isIncidentalCopy() ||
          def.getIn(0)!.isIncidentalCopy() ||
          invn.overlapVarnode(def.getIn(0)!) === newOff) {
          return this.ancestorOpUse(maxlevel - 1, def.getIn(0)!, op, trial, offset + newOff, mainFlags);
        }
        break;
      }
      case OpCode.CPUI_CALL:
      case OpCode.CPUI_CALLIND:
        return false; // A call is never a good indication of a single op use
      default:
        break;
    }
    // This varnode must be top ancestor at this point
    return this.onlyOpUse(invn, op, trial, mainFlags); // Test if varnode is only used in op
  }

  /// Delete the given varnode
  deleteVarnode(vn: Varnode): void {
    this.vbank.destroy(vn);
  }

  /// Swap two input operands in the given PcodeOp
  opSwapInput(op: PcodeOp, slot1: number, slot2: number): void {
    const tmp: Varnode = op.getIn(slot1)!;
    op.setInput(op.getIn(slot2)!, slot1);
    op.setInput(tmp, slot2);
  }

  /// Set a Varnode as the mapping for a SymbolEntry
  setVarnodeSymbolEntry(vn: Varnode, entry: SymbolEntry): void {
    vn.setSymbolEntry(entry);
  }

  /// Determine if Varnode descendants are outside the given basic block
  static descendantsOutside(vn: Varnode): boolean {
    const bb: FlowBlock | null = vn.isWritten() ? vn.getDef()!.getParent() : null;
    for (const op of vn.descend) {
      if (op.getParent() !== bb) return true;
    }
    return false;
  }

} // End class Funcdata

// =====================================================================
// CloneBlockOps — helper class for cloning PcodeOps across blocks
// =====================================================================

export class CloneBlockOps {
  private data: Funcdata;
  private cloneList: Array<{ cloneOp: PcodeOp; origOp: PcodeOp }>;
  private origToClone: Map<PcodeOp, PcodeOp>;

  constructor(fd: Funcdata) {
    this.data = fd;
    this.cloneList = [];
    this.origToClone = new Map<PcodeOp, PcodeOp>();
  }

  /// Make a basic clone of the p-code op copying its basic control-flow
  /// properties.  In the case of a branch, null is returned.
  private buildOpClone(op: PcodeOp): PcodeOp | null {
    if (op.isBranch()) {
      if (op.code() !== OpCode.CPUI_BRANCH) {
        throw new LowlevelError("Cannot duplicate 2-way or n-way branch in nodeplit");
      }
      return null;
    }
    const dup: PcodeOp = this.data.newOp(op.numInput(), op.getAddr());
    this.data.opSetOpcode(dup, op.code());
    const fl: number = op.flags & (
      PcodeOp.startbasic | PcodeOp.nocollapse | PcodeOp.startmark |
      PcodeOp.nonprinting | PcodeOp.halt | PcodeOp.badinstruction | PcodeOp.unimplemented |
      PcodeOp.noreturn | PcodeOp.missing | PcodeOp.indirect_creation | PcodeOp.indirect_store |
      PcodeOp.no_indirect_collapse | PcodeOp.calculated_bool | PcodeOp.ptrflow
    );
    dup.setFlag(fl);
    const afl: number = op.addlflags & (
      PcodeOp.special_prop | PcodeOp.special_print | PcodeOp.incidental_copy |
      PcodeOp.is_cpool_transformed | PcodeOp.stop_type_propagation | PcodeOp.store_unmapped
    );
    dup.setAdditionalFlag(afl);

    this.cloneList.push({ cloneOp: dup, origOp: op });
    this.origToClone.set(op, dup);
    return dup;
  }

  /// Make a basic clone of a Varnode and its flags.
  private buildVarnodeOutput(origOp: PcodeOp, cloneOp: PcodeOp): void {
    const opvn: Varnode | null = origOp.getOut();
    if (opvn === null) return;

    const newvn: Varnode = this.data.newVarnodeOut(opvn.getSize(), opvn.getAddr(), cloneOp);
    let vflags: number = opvn.getFlags();
    vflags &= (
      Varnode.externref | Varnode.volatil | Varnode.incidental_copy | Varnode.readonly |
      Varnode.persist | Varnode.addrtied | Varnode.addrforce | Varnode.nolocalalias | Varnode.spacebase |
      Varnode.indirect_creation | Varnode.return_address | Varnode.precislo | Varnode.precishi |
      Varnode.incidental_copy
    );
    newvn.setFlags(vflags);
    let aflags: number = opvn.addlflags;
    aflags &= (Varnode.writemask | Varnode.ptrflow | Varnode.stack_store);
    newvn.addlflags |= aflags;
  }

  /// Clone all p-code ops from a block into its copy.
  cloneBlock(b: BlockBasic, bprime: BlockBasic, inedge: number): void {
    for (const origOp of b.op) {
      const cloneOp: PcodeOp | null = this.buildOpClone(origOp);
      if (cloneOp === null) continue;
      this.buildVarnodeOutput(origOp, cloneOp);
      this.data.opInsertEnd(cloneOp, bprime);
    }
    this.patchInputs(inedge);
  }

  /// Clone p-code ops in an expression, inserting them before followOp.
  cloneExpression(ops: PcodeOp[], followOp: PcodeOp): Varnode {
    let cloneOp: PcodeOp | null = null;
    for (let i = 0; i < ops.length; ++i) {
      const origOp: PcodeOp = ops[i];
      cloneOp = this.buildOpClone(origOp);
      if (cloneOp === null) continue;
      this.buildVarnodeOutput(origOp, cloneOp);
      this.data.opInsertBefore(cloneOp, followOp);
    }
    if (this.cloneList.length === 0) {
      throw new LowlevelError("No expression to clone");
    }
    this.patchInputs(0);
    cloneOp = this.cloneList[this.cloneList.length - 1].cloneOp;
    return cloneOp.getOut()!;
  }

  /// Map Varnodes that are inputs for PcodeOps in the original basic
  /// block to the input slots of the cloned ops.
  private patchInputs(inedge: number): void {
    for (let pos = 0; pos < this.cloneList.length; ++pos) {
      const origOp: PcodeOp = this.cloneList[pos].origOp;
      const cloneOp: PcodeOp = this.cloneList[pos].cloneOp;
      if (origOp.code() === OpCode.CPUI_MULTIEQUAL) {
        cloneOp.setNumInputs(1);
        this.data.opSetOpcode(cloneOp, OpCode.CPUI_COPY);
        this.data.opSetInput(cloneOp, origOp.getIn(inedge)!, 0);
        this.data.opRemoveInput(origOp, inedge);
        if (origOp.numInput() === 1) {
          this.data.opSetOpcode(origOp, OpCode.CPUI_COPY);
        }
      } else if (origOp.code() === OpCode.CPUI_INDIRECT) {
        throw new LowlevelError("Can't clone INDIRECTs");
      } else if (origOp.isCall()) {
        throw new LowlevelError("Can't clone CALLs");
      } else {
        for (let i = 0; i < cloneOp.numInput(); ++i) {
          const origVn: Varnode = origOp.getIn(i)!;
          let cloneVn: Varnode;
          if (origVn.isConstant()) {
            cloneVn = origVn;
          } else if (origVn.isAnnotation()) {
            cloneVn = this.data.newCodeRef(origVn.getAddr());
          } else if (origVn.isFree()) {
            throw new LowlevelError("Can't clone free varnode");
          } else {
            if (origVn.isWritten()) {
              const mapped: PcodeOp | undefined = this.origToClone.get(origVn.getDef()!);
              if (mapped !== undefined) {
                cloneVn = mapped.getOut()!;
              } else {
                cloneVn = origVn;
              }
            } else {
              cloneVn = origVn;
            }
          }
          this.data.opSetInput(cloneOp, cloneVn, i);
        }
      }
    }
  }
}

/// Helper class for determining if Varnodes can trace their value from a legitimate source.
/// Try to determine if a Varnode makes sense as parameter passing (or return value) storage
/// by examining the Varnode's ancestors.
export class AncestorRealistic {
  static readonly enter_node = 0;
  static readonly pop_success = 1;
  static readonly pop_solid = 2;
  static readonly pop_fail = 3;
  static readonly pop_failkill = 4;

  private trial: ParamTrial | null = null;
  private stateStack: AncestorRealisticState[] = [];
  private markedVn: Varnode[] = [];
  private multiDepth: number = 0;
  private allowFailingPath: boolean = false;

  private mark(vn: Varnode): void {
    this.markedVn.push(vn);
    vn.setMark();
  }

  /// Analyze a new node that has just entered, during the depth-first traversal.
  private enterNode(): number {
    const state: AncestorRealisticState = this.stateStack[this.stateStack.length - 1];
    // If the node has already been visited, we truncate the traversal to prevent cycles.
    const stateVn: Varnode = state.op.getIn(state.slot)!;
    if (stateVn.isMark()) return AncestorRealistic.pop_success;
    if (!stateVn.isWritten()) {
      if (stateVn.isInput()) {
        if (stateVn.isUnaffected()) return AncestorRealistic.pop_fail;
        if (stateVn.isPersist()) return AncestorRealistic.pop_success;
        if (!stateVn.isDirectWrite()) return AncestorRealistic.pop_fail;
      }
      return AncestorRealistic.pop_success;
    }
    this.mark(stateVn);
    const op: PcodeOp = stateVn.getDef()!;
    switch (op.code()) {
      case OpCode.CPUI_INDIRECT:
        if (op.isIndirectCreation()) {
          this.trial!.setIndCreateFormed();
          if (op.getIn(0)!.isIndirectZero()) return AncestorRealistic.pop_failkill;
          return AncestorRealistic.pop_success;
        }
        if (!op.isIndirectStore()) {
          if (op.getOut()!.isReturnAddress()) return AncestorRealistic.pop_fail;
          if (this.trial!.isKilledByCall()) return AncestorRealistic.pop_fail;
        }
        this.stateStack.push(new AncestorRealisticState(op, 0));
        return AncestorRealistic.enter_node;
      case OpCode.CPUI_SUBPIECE:
        if (op.getOut()!.getSpace()!.getType() === spacetype.IPTR_INTERNAL
          || op.isIncidentalCopy() || op.getIn(0)!.isIncidentalCopy()
          || (op.getOut()!.overlapVarnode(op.getIn(0)!) === Number(op.getIn(1)!.getOffset()))) {
          this.stateStack.push(AncestorRealisticState.fromSubpiece(op, state));
          return AncestorRealistic.enter_node;
        }
        // For other SUBPIECES, do a minimal traversal
        {
          let walkOp: PcodeOp | null = op;
          do {
            const vn: Varnode = walkOp!.getIn(0)!;
            if ((!vn.isMark()) && (vn.isInput())) {
              if (vn.isUnaffected() || (!vn.isDirectWrite())) return AncestorRealistic.pop_fail;
            }
            walkOp = vn.getDef();
          } while ((walkOp !== null) && ((walkOp.code() === OpCode.CPUI_COPY) || (walkOp.code() === OpCode.CPUI_SUBPIECE)));
        }
        return AncestorRealistic.pop_solid;
      case OpCode.CPUI_COPY: {
        if (op.getOut()!.getSpace()!.getType() === spacetype.IPTR_INTERNAL
          || op.isIncidentalCopy() || op.getIn(0)!.isIncidentalCopy()
          || (op.getOut()!.getAddr().equals(op.getIn(0)!.getAddr()))) {
          this.stateStack.push(new AncestorRealisticState(op, 0));
          return AncestorRealistic.enter_node;
        }
        let vn: Varnode = op.getIn(0)!;
        let walkOp: PcodeOp | null = null;
        for (;;) {
          if ((!vn.isMark()) && (vn.isInput())) {
            if (!vn.isDirectWrite()) return AncestorRealistic.pop_fail;
          }
          if (op.isStoreUnmapped()) return AncestorRealistic.pop_fail;
          walkOp = vn.getDef();
          if (walkOp === null) break;
          const opc: OpCode = walkOp.code();
          if (opc === OpCode.CPUI_COPY || opc === OpCode.CPUI_SUBPIECE) {
            vn = walkOp.getIn(0)!;
          } else if (opc === OpCode.CPUI_PIECE) {
            vn = walkOp.getIn(1)!; // Follow least significant piece
          } else {
            break;
          }
        }
        return AncestorRealistic.pop_solid;
      }
      case OpCode.CPUI_MULTIEQUAL:
        this.multiDepth += 1;
        this.stateStack.push(new AncestorRealisticState(op, 0));
        return AncestorRealistic.enter_node;
      case OpCode.CPUI_PIECE:
        if (stateVn.getSize() > this.trial!.getSize()) {
          if (state.offset === 0 && op.getIn(1)!.getSize() <= this.trial!.getSize()) {
            this.stateStack.push(new AncestorRealisticState(op, 1));
            return AncestorRealistic.enter_node;
          } else if (state.offset === op.getIn(1)!.getSize() && op.getIn(0)!.getSize() <= this.trial!.getSize()) {
            this.stateStack.push(new AncestorRealisticState(op, 0));
            return AncestorRealistic.enter_node;
          }
          if (stateVn.getSpace()!.getType() !== spacetype.IPTR_SPACEBASE) {
            return AncestorRealistic.pop_fail;
          }
        }
        return AncestorRealistic.pop_solid;
      default:
        return AncestorRealistic.pop_solid;
    }
  }

  /// Backtrack into a previously visited node.
  private uponPop(pop_command: number): number {
    const state: AncestorRealisticState = this.stateStack[this.stateStack.length - 1];
    if (state.op.code() === OpCode.CPUI_MULTIEQUAL) {
      const prevstate: AncestorRealisticState = this.stateStack[this.stateStack.length - 2];
      if (pop_command === AncestorRealistic.pop_fail) {
        this.multiDepth -= 1;
        this.stateStack.pop();
        return pop_command;
      } else if ((pop_command === AncestorRealistic.pop_solid) && (this.multiDepth === 1) && (state.op.numInput() === 2)) {
        prevstate.markSolid(state.slot);
      } else if (pop_command === AncestorRealistic.pop_failkill) {
        prevstate.markKill();
      }
      state.slot += 1;
      if (state.slot === state.op.numInput()) {
        if (prevstate.seenSolid()) {
          pop_command = AncestorRealistic.pop_success;
          if (prevstate.seenKill()) {
            if (this.allowFailingPath) {
              if (!this.checkConditionalExe(state)) {
                pop_command = AncestorRealistic.pop_fail;
              } else {
                this.trial!.setCondExeEffect();
              }
            } else {
              pop_command = AncestorRealistic.pop_fail;
            }
          }
        } else if (prevstate.seenKill()) {
          pop_command = AncestorRealistic.pop_failkill;
        } else {
          pop_command = AncestorRealistic.pop_success;
        }
        this.multiDepth -= 1;
        this.stateStack.pop();
        return pop_command;
      }
      return AncestorRealistic.enter_node;
    } else {
      this.stateStack.pop();
      return pop_command;
    }
  }

  /// Check if current Varnode produced by conditional flow.
  private checkConditionalExe(state: AncestorRealisticState): boolean {
    const bl: BlockBasic = state.op.getParent() as BlockBasic;
    if (bl.sizeIn() !== 2) return false;
    const solidBlock: FlowBlock = bl.getIn(state.getSolidSlot());
    if (solidBlock.sizeOut() !== 1) return false;
    return true;
  }

  /// Perform a full ancestor check on a given parameter trial.
  execute(op: PcodeOp, slot: number, t: ParamTrial, allowFail: boolean): boolean {
    this.trial = t;
    this.allowFailingPath = allowFail;
    this.markedVn = [];
    this.stateStack = [];
    this.multiDepth = 0;
    // If the parameter itself is an input, we don't consider this realistic
    if (op.getIn(slot)!.isInput()) {
      if (!this.trial.hasCondExeEffect()) return false;
    }
    // Run the depth first traversal
    let command: number = AncestorRealistic.enter_node;
    this.stateStack.push(new AncestorRealisticState(op, slot));
    while (this.stateStack.length > 0) {
      switch (command) {
        case AncestorRealistic.enter_node:
          command = this.enterNode();
          break;
        case AncestorRealistic.pop_success:
        case AncestorRealistic.pop_solid:
        case AncestorRealistic.pop_fail:
        case AncestorRealistic.pop_failkill:
          command = this.uponPop(command);
          break;
      }
    }
    for (let i = 0; i < this.markedVn.length; ++i) {
      this.markedVn[i].clearMark();
    }
    if (command === AncestorRealistic.pop_success) {
      this.trial.setAncestorRealistic();
      return true;
    } else if (command === AncestorRealistic.pop_solid) {
      this.trial.setAncestorRealistic();
      this.trial.setAncestorSolid();
      return true;
    }
    return false;
  }
}

/// State node for AncestorRealistic depth-first traversal.
class AncestorRealisticState {
  static readonly seen_solid0 = 1;
  static readonly seen_solid1 = 2;
  static readonly seen_kill = 4;

  op: PcodeOp;
  slot: number;
  flags: number;
  offset: number;

  constructor(o: PcodeOp, s: number) {
    this.op = o;
    this.slot = s;
    this.flags = 0;
    this.offset = 0;
  }

  /// Constructor from old state pulled back through a OpCode.CPUI_SUBPIECE.
  static fromSubpiece(o: PcodeOp, oldState: AncestorRealisticState): AncestorRealisticState {
    const state = new AncestorRealisticState(o, 0);
    state.offset = oldState.offset + Number(o.getIn(1)!.getOffset());
    return state;
  }

  getSolidSlot(): number {
    return ((this.flags & AncestorRealisticState.seen_solid0) !== 0) ? 0 : 1;
  }

  markSolid(s: number): void {
    this.flags |= (s === 0) ? AncestorRealisticState.seen_solid0 : AncestorRealisticState.seen_solid1;
  }

  markKill(): void {
    this.flags |= AncestorRealisticState.seen_kill;
  }

  seenSolid(): boolean {
    return ((this.flags & (AncestorRealisticState.seen_solid0 | AncestorRealisticState.seen_solid1)) !== 0);
  }

  seenKill(): boolean {
    return ((this.flags & AncestorRealisticState.seen_kill) !== 0);
  }
}

// Wire up FunctionSymbol.createFuncdata factory to break circular dependency
FunctionSymbol.createFuncdata = (nm, displayNm, sc, addr, sym) => new Funcdata(nm, displayNm, sc, addr, sym);

// Wire up FlowInfo's forward declaration stubs (circular dependency workaround)
// Must be after Funcdata class definition since it references Funcdata
(FlowInfo as any)._FuncdataCtor = Funcdata;
(FlowInfo as any)._getFspecFromConst = (addr: any) => FuncCallSpecs.getFspecFromConst(addr);
