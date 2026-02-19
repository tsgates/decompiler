/**
 * @file unionresolve.ts
 * @description Analyze data-flow to resolve which field of a union data-type is being accessed.
 * Translated from Ghidra's unionresolve.hh / unionresolve.cc
 */

import { Datatype, TypeField, type_metatype, registerUnionResolveClasses } from './type.js';
import { OpCode } from '../core/opcodes.js';

// ---------------------------------------------------------------------------
// Forward type declarations for types from not-yet-written or non-exported modules
// ---------------------------------------------------------------------------

type Funcdata = any;
type TypeFactory = any;
type TypeUnion = any;
type TypePointer = any;
type TypePartialUnion = any;
type FuncCallSpecs = any;
type FloatFormat = any;
type AddrSpace = any;
type Architecture = any;

// Forward-declared imports that would come from other modules
type Varnode = any;
type PcodeOp = any;

// We need TypeOpSubpiece.computeByteOffsetForComposite but it is in typeop.ts
// Forward declare it and import at runtime if available
type TypeOpSubpiece = any;

// ---------------------------------------------------------------------------
// Helper: Import bit_transitions from address module
// We forward-declare since it may not be importable from all build configurations
// ---------------------------------------------------------------------------
let bit_transitions: (val: bigint, sz: number) => number;
try {
  // Dynamic import is not suitable here; we'll define inline
  // This matches the C++ bit_transitions function
  bit_transitions = function (val: bigint, sz: number): number {
    let count = 0;
    let lastBit = val & 1n;
    for (let i = 1; i < sz * 8; i++) {
      val >>= 1n;
      const curBit = val & 1n;
      if (curBit !== lastBit) {
        count++;
        lastBit = curBit;
      }
    }
    return count;
  };
} catch {
  bit_transitions = () => 0;
}

// ---------------------------------------------------------------------------
// ResolvedUnion
// ---------------------------------------------------------------------------

/**
 * A data-type resolved from an associated TypeUnion or TypeStruct.
 *
 * A parent refers to either:
 *   1) A union
 *   2) A structure that is an effective union (1 field filling the entire structure) OR
 *   3) A pointer to a union/structure
 *
 * This object represents a data-type that is resolved via analysis from the parent data-type.
 * The resolved data-type can be either:
 *   1) A specific field of the parent (if the parent is not a pointer)
 *   2) A pointer to a specific field of the underlying union/structure (if the parent is a pointer)
 *   3) The parent data-type itself (either a pointer or not)
 * The fieldNum (if non-negative) selects a particular field of the underlying union/structure.
 * If the parent is a pointer, the resolution is a pointer to the field.
 * If the parent is not a pointer, the resolution is the field itself.
 * A fieldNum of -1 indicates that the parent data-type itself is the resolution.
 */
export class ResolvedUnion {
  resolve: Datatype;           // The resolved data-type
  baseType: Datatype;          // Union or Structure being resolved
  fieldNum: number;            // Index of field referenced by resolve
  private lock: boolean;       // If true, resolution cannot be overridden

  /**
   * Construct a data-type that resolves to itself.
   *
   * The original parent must either be a union, a partial union, a structure with a single field,
   * an array with a single element, or a pointer to one of these data-types.
   * The object is set up initially to resolve to the parent.
   */
  constructor(parent: Datatype);
  /**
   * Construct a reference to a field.
   *
   * The original parent must be a union or structure.
   * @param parent is the original parent
   * @param fldNum is the index of the particular field to resolve to (or -1 to resolve to parent)
   * @param typegrp is a TypeFactory used to construct the resolved data-type of the field
   */
  constructor(parent: Datatype, fldNum: number, typegrp: TypeFactory);
  constructor(parent: Datatype, fldNum?: number, typegrp?: TypeFactory) {
    if (fldNum === undefined) {
      // ResolvedUnion(Datatype *parent)
      this.baseType = parent;
      if (this.baseType.getMetatype() === type_metatype.TYPE_PTR) {
        this.baseType = (this.baseType as TypePointer).getPtrTo();
      }
      this.resolve = parent;
      this.fieldNum = -1;
      this.lock = false;
    } else {
      // ResolvedUnion(Datatype *parent, int4 fldNum, TypeFactory &typegrp)
      if (parent.getMetatype() === type_metatype.TYPE_PARTIALUNION) {
        parent = (parent as TypePartialUnion).getParentUnion();
      }
      this.baseType = parent;
      this.fieldNum = fldNum;
      this.lock = false;
      if (fldNum < 0) {
        this.resolve = parent;
      } else {
        if (parent.getMetatype() === type_metatype.TYPE_PTR) {
          const pointer: TypePointer = parent as TypePointer;
          const field: Datatype = pointer.getPtrTo().getDepend(fldNum);
          this.resolve = typegrp!.getTypePointer(parent.getSize(), field, pointer.getWordSize());
        } else {
          this.resolve = parent.getDepend(fldNum)!;
        }
      }
    }
  }

  /** Get the resolved data-type */
  getDatatype(): Datatype { return this.resolve; }

  /** Get the union or structure being referenced */
  getBase(): Datatype { return this.baseType; }

  /** Get the index of the resolved field or -1 */
  getFieldNum(): number { return this.fieldNum; }

  /** Is this locked against overrides */
  isLocked(): boolean { return this.lock; }

  /** Set whether this resolution is locked against overrides */
  setLock(val: boolean): void { this.lock = val; }
}

// ---------------------------------------------------------------------------
// ResolveEdge
// ---------------------------------------------------------------------------

/**
 * A data-flow edge to which a resolved data-type can be assigned.
 *
 * The edge is associated with the specific data-type that needs to be resolved,
 * which is typically a union or a pointer to a union. The edge collapses different
 * kinds of pointers to the same base union.
 */
export class ResolveEdge {
  private typeId: bigint;    // Id of base data-type being resolved
  private opTime: number;    // Id of PcodeOp edge (uintm -> number)
  private encoding: number;  // Encoding of the slot and pointer-ness

  /**
   * Construct from components.
   * @param parent is a parent data-type that needs to be resolved
   * @param op is the PcodeOp reading/writing the parent data-type
   * @param slot is the slot (>=0 for input, -1 for output) accessing the parent
   */
  constructor(parent: Datatype, op: PcodeOp, slot: number) {
    this.opTime = op.getTime();
    this.encoding = slot;
    if (parent.getMetatype() === type_metatype.TYPE_PTR) {
      this.typeId = (parent as TypePointer).getPtrTo().getId();  // Strip pointer
      this.encoding += 0x1000;  // Encode the fact that a pointer is getting accessed
    } else if (parent.getMetatype() === type_metatype.TYPE_PARTIALUNION) {
      this.typeId = (parent as TypePartialUnion).getParentUnion().getId();
    } else {
      this.typeId = parent.getId();
    }
  }

  /**
   * Compare two edges.
   * Compare based on the data-type, the slot, and the PcodeOp's unique id.
   * @param op2 is the other edge to compare with this
   * @return true if this should be ordered before the other edge
   */
  lessThan(op2: ResolveEdge): boolean {
    if (this.typeId !== op2.typeId)
      return this.typeId < op2.typeId;
    if (this.encoding !== op2.encoding)
      return this.encoding < op2.encoding;
    return this.opTime < op2.opTime;
  }

  /**
   * Compare function for use in sorted containers.
   * Returns negative if this < op2, 0 if equal, positive if this > op2.
   */
  /**
   * Generate a unique string key for use in Map containers.
   */
  toKey(): string {
    return `${this.typeId}:${this.encoding}:${this.opTime}`;
  }

  static compare(a: ResolveEdge, b: ResolveEdge): number {
    if (a.typeId !== b.typeId)
      return a.typeId < b.typeId ? -1 : 1;
    if (a.encoding !== b.encoding)
      return a.encoding < b.encoding ? -1 : 1;
    if (a.opTime !== b.opTime)
      return a.opTime < b.opTime ? -1 : 1;
    return 0;
  }
}

// ---------------------------------------------------------------------------
// ScoreUnionFields
// ---------------------------------------------------------------------------

/** An enumerator to distinguish how an individual trial follows data-flow */
const enum TrialDirection {
  fit_down = 0,   // Only push the fit down with the data-flow
  fit_up = 1      // Only push the fit up against the data-flow
}

/**
 * A trial data-type fitted to a specific place in the data-flow.
 */
class Trial {
  vn: Varnode;                // The Varnode we are testing for data-type fit
  op: PcodeOp | null;        // The PcodeOp reading the Varnode (or null)
  inslot!: number;             // The slot reading the Varnode (or -1)
  direction!: TrialDirection;  // Direction to push fit
  array!: boolean;             // Field can be accessed as an array
  fitType!: Datatype;          // The putative data-type of the Varnode
  scoreIndex!: number;         // The original field being scored by this trial

  /** Construct a downward trial for a Varnode */
  static createDown(o: PcodeOp, slot: number, ct: Datatype, index: number, isArray: boolean): Trial {
    const t = new Trial();
    t.op = o;
    t.inslot = slot;
    t.direction = TrialDirection.fit_down;
    t.fitType = ct;
    t.scoreIndex = index;
    t.vn = o.getIn(slot);
    t.array = isArray;
    return t;
  }

  /** Construct an upward trial for a Varnode */
  static createUp(v: Varnode, ct: Datatype, index: number, isArray: boolean): Trial {
    const t = new Trial();
    t.vn = v;
    t.op = null;
    t.inslot = -1;
    t.direction = TrialDirection.fit_up;
    t.fitType = ct;
    t.scoreIndex = index;
    t.array = isArray;
    return t;
  }
}

/**
 * A mark accumulated when a given Varnode is visited with a specific field index.
 */
class VisitMark {
  vn: Varnode;   // Varnode reached by trial field
  index: number; // Index of the trial field

  constructor(v: Varnode, i: number) {
    this.vn = v;
    this.index = i;
  }

  /**
   * Encode as a string key for use in a Set/Map, since JavaScript Set
   * does not support custom comparison for objects.
   */
  key(): string {
    // Use the Varnode's identity (object reference is unique per varnode instance in JS)
    // We use a WeakMap-based approach below instead, but provide a key method as fallback.
    return `${VisitMark.vnId(this.vn)}_${this.index}`;
  }

  // We use a global counter to assign unique IDs to Varnodes for hashing
  private static _vnIdMap = new WeakMap<object, number>();
  private static _nextId = 0;
  static vnId(vn: any): number {
    let id = VisitMark._vnIdMap.get(vn);
    if (id === undefined) {
      id = VisitMark._nextId++;
      VisitMark._vnIdMap.set(vn, id);
    }
    return id;
  }
}

/**
 * Analyze data-flow to resolve which field of a union data-type is being accessed.
 *
 * A Varnode with a data-type that is either a union, a pointer to union, or a part of a union, can
 * be accessed in multiple ways. Each individual read (or write) of the Varnode may be accessing either
 * a specific field of the union or accessing the union as a whole. The particular access may not be
 * explicitly known but can sometimes be inferred from data-flow near the Varnode. This class scores
 * all the possible fields of a data-type involving a union for a specific Varnode.
 *
 * Because the answer may be different for different accesses, the Varnode must be specified as an
 * access edge, a PcodeOp and a slot. A slot >= 0 indicates the index of a Varnode that is being read
 * by the PcodeOp, a slot == -1 indicates the output Varnode being written by the PcodeOp.
 *
 * The result of scoring is returned as a ResolvedUnion record.
 */
export class ScoreUnionFields {
  private typegrp: TypeFactory;        // The factory containing data-types
  private scores: number[];            // Score for each field, indexed by fieldNum + 1 (whole union is index=0)
  private fields: (Datatype | null)[]; // Field corresponding to each score
  private visited: Set<string>;        // Places that have already been visited (encoded as keys)
  private trialCurrent: Trial[];       // Current trials being pushed
  private trialNext: Trial[];          // Next set of trials
  result: ResolvedUnion;               // The best result
  private trialCount: number;          // Number of trials evaluated so far

  static readonly maxPasses: number = 6;        // Maximum number of levels to score through
  static readonly threshold: number = 256;       // Threshold of trials over which to cancel additional passes
  static readonly maxTrials: number = 1024;      // Maximum number of trials to evaluate

  /**
   * Score a given data-type involving a union against data-flow.
   *
   * The data-type must either be a union or a pointer to union.
   * Set up the initial set of trials based on the given data-flow edge (PcodeOp and slot).
   * @param tgrp is the TypeFactory owning the data-types
   * @param parentType is the given data-type to score
   * @param op is PcodeOp of the given data-flow edge
   * @param slot is slot of the given data-flow edge
   */
  constructor(tgrp: TypeFactory, parentType: Datatype, op: PcodeOp, slot: number);
  /**
   * Score a union data-type against data-flow, where there is a SUBPIECE.
   *
   * A truncation is fit to each union field before doing the fit against data-flow.
   * @param tgrp is the TypeFactory owning the data-types
   * @param unionType is the data-type to score, which must be a TypeUnion
   * @param offset is the given starting offset of the truncation
   * @param op is the SUBPIECE op
   */
  constructor(tgrp: TypeFactory, unionType: Datatype, offset: number, op: PcodeOp);
  /**
   * Score a union data-type against data-flow, where there is an implied truncation.
   *
   * A truncation is fit to each union field before doing the fit against data-flow, starting with
   * the given PcodeOp and input slot.
   * @param tgrp is the TypeFactory owning the data-types
   * @param unionType is the data-type to score, which must be a TypeUnion
   * @param offset is the given starting offset of the truncation
   * @param op is the PcodeOp initially reading/writing the union
   * @param slot is -1 if the op is writing, >= 0 if reading
   */
  constructor(tgrp: TypeFactory, unionType: Datatype, offset: number, op: PcodeOp, slot: number);
  constructor(tgrp: TypeFactory, parentTypeOrUnionType: Datatype, opOrOffset: PcodeOp | number, slotOrOp?: number | PcodeOp, maybeSlot?: number) {
    this.typegrp = tgrp;
    this.scores = [];
    this.fields = [];
    this.visited = new Set<string>();
    this.trialCurrent = [];
    this.trialNext = [];
    this.trialCount = 0;

    if (typeof opOrOffset !== 'number') {
      // Constructor 1: ScoreUnionFields(tgrp, parentType, op, slot)
      const parentType = parentTypeOrUnionType;
      const op = opOrOffset as PcodeOp;
      const slot = slotOrOp as number;
      this.result = new ResolvedUnion(parentType);

      if (this.testSimpleCases(op, slot, parentType))
        return;
      const wordSize: number = (parentType.getMetatype() === type_metatype.TYPE_PTR)
        ? (parentType as TypePointer).getWordSize()
        : 0;
      const numFields: number = this.result.baseType.numDepend();
      this.scores = new Array(numFields + 1).fill(0);
      this.fields = new Array(numFields + 1).fill(null);
      let vn: Varnode;
      if (slot < 0) {
        vn = op.getOut();
        if (vn.getSize() !== parentType.getSize())
          this.scores[0] -= 10;  // Data-type does not even match size of Varnode
        else
          this.trialCurrent.push(Trial.createUp(vn, parentType, 0, false));
      } else {
        vn = op.getIn(slot);
        if (vn.getSize() !== parentType.getSize())
          this.scores[0] -= 10;
        else
          this.trialCurrent.push(Trial.createDown(op, slot, parentType, 0, false));
      }
      this.fields[0] = parentType;
      this.visited.add(new VisitMark(vn, 0).key());
      for (let i = 0; i < numFields; ++i) {
        let fieldType: Datatype = this.result.baseType.getDepend(i)!;
        let isArray = false;
        if (wordSize !== 0) {
          if (fieldType.getMetatype() === type_metatype.TYPE_ARRAY)
            isArray = true;
          fieldType = tgrp.getTypePointerStripArray(parentType.getSize(), fieldType, wordSize);
        }
        if (vn.getSize() !== fieldType.getSize())
          this.scores[i + 1] -= 10;  // Data-type does not even match size of Varnode, don't create trial
        else if (slot < 0) {
          this.trialCurrent.push(Trial.createUp(vn, fieldType, i + 1, isArray));
        } else {
          this.trialCurrent.push(Trial.createDown(op, slot, fieldType, i + 1, isArray));
        }
        this.fields[i + 1] = fieldType;
        this.visited.add(new VisitMark(vn, i + 1).key());
      }
      this.run();
      this.computeBestIndex();
    } else if (maybeSlot === undefined) {
      // Constructor 2: ScoreUnionFields(tgrp, unionType, offset, op)
      const unionType = parentTypeOrUnionType;
      const offset = opOrOffset as number;
      const op = slotOrOp as PcodeOp;
      this.result = new ResolvedUnion(unionType);

      const vn: Varnode = op.getOut();
      const numFields: number = unionType.numDepend();
      this.scores = new Array(numFields + 1).fill(0);
      this.fields = new Array(numFields + 1).fill(null);
      this.fields[0] = unionType;
      this.scores[0] = -10;
      for (let i = 0; i < numFields; ++i) {
        const unionField: TypeField = (unionType as any).getField(i);
        this.fields[i + 1] = unionField.type;
        if (unionField.type.getSize() !== vn.getSize() || unionField.offset !== offset) {
          this.scores[i + 1] = -10;
          continue;
        }
        this.newTrialsDown(vn, unionField.type, i + 1, false);
      }
      // Swap trialNext into trialCurrent
      const temp = this.trialCurrent;
      this.trialCurrent = this.trialNext;
      this.trialNext = temp;
      this.trialNext.length = 0;
      if (this.trialCurrent.length > 1)
        this.run();
      this.computeBestIndex();
    } else {
      // Constructor 3: ScoreUnionFields(tgrp, unionType, offset, op, slot)
      const unionType = parentTypeOrUnionType;
      const offset = opOrOffset as number;
      const op = slotOrOp as PcodeOp;
      const slot = maybeSlot;
      this.result = new ResolvedUnion(unionType);

      const vn: Varnode = (slot < 0) ? op.getOut() : op.getIn(slot);
      const numFields: number = unionType.numDepend();
      this.scores = new Array(numFields + 1).fill(0);
      this.fields = new Array(numFields + 1).fill(null);
      this.fields[0] = unionType;
      this.scores[0] = -10;  // Assume the untruncated entire union is not a good fit
      for (let i = 0; i < numFields; ++i) {
        const unionField: TypeField = (unionType as any).getField(i);
        this.fields[i + 1] = unionField.type;
        // Score the implied truncation
        const ct = this.scoreTruncation(unionField.type, vn, offset - unionField.offset, i + 1);
        if (ct !== null) {
          if (slot < 0)
            this.trialCurrent.push(Trial.createUp(vn, ct, i + 1, false));  // Try to flow backward
          else
            this.trialCurrent.push(Trial.createDown(op, slot, ct, i + 1, false));  // Flow downward
          this.visited.add(new VisitMark(vn, i + 1).key());
        }
      }
      if (this.trialCurrent.length > 1)
        this.run();
      this.computeBestIndex();
    }
  }

  /** Get the resulting best field resolution */
  getResult(): ResolvedUnion { return this.result; }

  // -----------------------------------------------------------------------
  // Private methods
  // -----------------------------------------------------------------------

  /**
   * Check if given PcodeOp is operating on array with union elements.
   *
   * If the op is adding a constant size or a multiple of a constant size to the given input slot,
   * where the size is at least as large as the union, return true.
   */
  private testArrayArithmetic(op: PcodeOp, inslot: number): boolean {
    if (op.code() === OpCode.CPUI_INT_ADD) {
      const vn: Varnode = op.getIn(1 - inslot);
      if (vn.isConstant()) {
        if (vn.getOffset() >= BigInt(this.result.baseType.getSize()))
          return true;  // Array with union elements
      } else if (vn.isWritten()) {
        const multOp: PcodeOp = vn.getDef();
        if (multOp.code() === OpCode.CPUI_INT_MULT) {
          const vn2: Varnode = multOp.getIn(1);
          if (vn2.isConstant() && vn2.getOffset() >= BigInt(this.result.baseType.getSize()))
            return true;  // Array with union elements
        }
      }
    } else if (op.code() === OpCode.CPUI_PTRADD) {
      const vn: Varnode = op.getIn(2);
      if (vn.getOffset() >= BigInt(this.result.baseType.getSize()))
        return true;
    }
    return false;
  }

  /**
   * Preliminary checks before doing full scoring.
   *
   * Identify cases where we know the union shouldn't be resolved to a field.
   * @param op is the PcodeOp manipulating the union variable
   * @param inslot is -1 if the union is the output, >=0 if the union is an input to the op
   * @param parent is the parent union or pointer to union
   * @return true if the union should not be resolved to a field
   */
  private testSimpleCases(op: PcodeOp, inslot: number, parent: Datatype): boolean {
    if (op.isMarker())
      return true;  // Propagate raw union across MULTIEQUAL and INDIRECT
    if (parent.getMetatype() === type_metatype.TYPE_PTR) {
      if (inslot < 0)
        return true;  // Don't resolve pointers "up", there's only 1 possibility for assignment
      if (this.testArrayArithmetic(op, inslot))
        return true;
    }
    if (op.code() !== OpCode.CPUI_COPY)
      return false;  // A more complicated case
    if (inslot < 0)
      return false;  // Generally we don't want to propagate union backward thru COPY
    if (op.getOut().isTypeLock())
      return false;  // Do the full scoring
    return true;     // Assume we don't have to extract a field if copying
  }

  /**
   * Score trial data-type against a locked data-type.
   *
   * A trial that encounters a locked data-type does not propagate through it but scores
   * the trial data-type against the locked data-type.
   */
  private scoreLockedType(ct: Datatype, lockType: Datatype): number {
    let score = 0;

    if (lockType === ct)
      score += 5;  // Perfect match

    while (ct.getMetatype() === type_metatype.TYPE_PTR) {
      if (lockType.getMetatype() !== type_metatype.TYPE_PTR) break;
      score += 5;
      ct = (ct as TypePointer).getPtrTo();
      lockType = (lockType as TypePointer).getPtrTo();
    }

    const ctMeta: type_metatype = ct.getMetatype();
    const vnMeta: type_metatype = lockType.getMetatype();
    if (ctMeta === vnMeta) {
      if (ctMeta === type_metatype.TYPE_STRUCT || ctMeta === type_metatype.TYPE_UNION ||
          ctMeta === type_metatype.TYPE_ARRAY || ctMeta === type_metatype.TYPE_CODE)
        score += 10;
      else
        score += 3;
    } else {
      if ((ctMeta === type_metatype.TYPE_INT && vnMeta === type_metatype.TYPE_UINT) ||
          (ctMeta === type_metatype.TYPE_UINT && vnMeta === type_metatype.TYPE_INT))
        score -= 1;
      else
        score -= 5;
      if (ct.getSize() !== lockType.getSize())
        score -= 2;
    }
    return score;
  }

  /**
   * Score trial data-type against a parameter.
   *
   * Look up the call-specs for the given CALL. If the inputs are locked, find the corresponding
   * parameter and score the trial data-type against it.
   */
  private scoreParameter(ct: Datatype, callOp: PcodeOp, paramSlot: number): number {
    const fd: Funcdata = callOp.getParent().getFuncdata();

    const fc: FuncCallSpecs = fd.getCallSpecs(callOp);
    if (fc !== null && fc.isInputLocked() && fc.numParams() > paramSlot) {
      return this.scoreLockedType(ct, fc.getParam(paramSlot).getType());
    }
    const meta: type_metatype = ct.getMetatype();
    if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
        meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE)
      return -1;  // Vaguely unlikely thing to pass as a param
    return 0;
  }

  /**
   * Score trial data-type against return data-type of function.
   *
   * Look up the call-specs for the given CALL. If the output is locked,
   * score the trial data-type against it.
   */
  private scoreReturnType(ct: Datatype, callOp: PcodeOp): number {
    const fd: Funcdata = callOp.getParent().getFuncdata();

    const fc: FuncCallSpecs = fd.getCallSpecs(callOp);
    if (fc !== null && fc.isOutputLocked()) {
      return this.scoreLockedType(ct, fc.getOutputType());
    }
    const meta: type_metatype = ct.getMetatype();
    if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
        meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE)
      return -1;  // Vaguely unlikely thing to return from a function
    return 0;
  }

  /**
   * Score trial data-type as a pointer to LOAD/STORE.
   *
   * Test if the data-type is a pointer and if the pointed-to data-type is
   * compatible with the size of the value being loaded or stored. A score is
   * passed back for how closely the data-type fits this scenario, and if it
   * does we return the data-type of the pointer value.
   * @param ct is the trial data-type
   * @param vn is the Varnode holding the value being loaded or stored
   * @param scoreRef is used to pass back the score
   * @return the data-type of the value or null
   */
  private derefPointer(ct: Datatype, vn: Varnode, scoreRef: { val: number }): Datatype | null {
    let resType: Datatype | null = null;
    scoreRef.val = 0;
    if (ct.getMetatype() === type_metatype.TYPE_PTR) {
      let ptrto: Datatype | null = (ct as TypePointer).getPtrTo();
      while (ptrto !== null && ptrto.getSize() > vn.getSize()) {
        const newoff = { val: 0n };
        ptrto = ptrto.getSubType(0n, newoff);
      }
      if (ptrto !== null && ptrto.getSize() === vn.getSize()) {
        scoreRef.val = 10;
        resType = ptrto;
      }
    } else {
      scoreRef.val = -10;
    }
    return resType;
  }

  /**
   * Create new trials based on reads of given Varnode.
   *
   * If the Varnode has already been visited, no new trials are created.
   */
  private newTrialsDown(vn: Varnode, ct: Datatype, scoreIndex: number, isArray: boolean): void {
    const markKey = new VisitMark(vn, scoreIndex).key();
    if (this.visited.has(markKey))
      return;  // Already visited this Varnode
    this.visited.add(markKey);
    if (vn.isTypeLock()) {
      this.scores[scoreIndex] += this.scoreLockedType(ct, vn.getType());
      return;  // Don't propagate through locked Varnode
    }
    const endIdx = vn.endDescend();
    for (let piter = vn.beginDescend(); piter < endIdx; ++piter) {
      const op: PcodeOp = vn.getDescend(piter);
      this.trialNext.push(Trial.createDown(op, op.getSlot(vn), ct, scoreIndex, isArray));
    }
  }

  /**
   * Create new trials based on given input slot.
   *
   * If the input slot is a Varnode that has already been visited, no new trial is created.
   */
  private newTrials(op: PcodeOp, slot: number, ct: Datatype, scoreIndex: number, isArray: boolean): void {
    const vn: Varnode = op.getIn(slot);
    const markKey = new VisitMark(vn, scoreIndex).key();
    if (this.visited.has(markKey))
      return;  // Already visited this Varnode
    this.visited.add(markKey);
    if (vn.isTypeLock()) {
      this.scores[scoreIndex] += this.scoreLockedType(ct, vn.getType());
      return;  // Don't propagate through locked Varnode
    }
    this.trialNext.push(Trial.createUp(vn, ct, scoreIndex, isArray));  // Try to fit up
    const endIdx = vn.endDescend();
    for (let iter = vn.beginDescend(); iter < endIdx; ++iter) {
      const readOp: PcodeOp = vn.getDescend(iter);
      const inslot: number = readOp.getSlot(vn);
      if (readOp === op && inslot === slot)
        continue;  // Don't go down PcodeOp we came from
      this.trialNext.push(Trial.createDown(readOp, inslot, ct, scoreIndex, isArray));
    }
  }

  /**
   * Try to fit the given trial following data-flow down.
   *
   * The trial's data-type is fitted to its PcodeOp as the incoming Varnode and a
   * score is computed and added to the score for the trial's union field. The fitting may
   * produce a new data-type which indicates scoring for the trial recurses into the output.
   * This method builds trials for any new data-type unless lastLevel is true.
   */
  private scoreTrialDown(trial: Trial, lastLevel: boolean): void {
    if (trial.direction === TrialDirection.fit_up)
      return;  // Trial doesn't push in this direction
    let resType: Datatype | null = null;  // Assume by default we don't propagate
    const meta: type_metatype = trial.fitType.getMetatype();
    let score = 0;
    switch (trial.op!.code()) {
      case OpCode.CPUI_COPY:
      case OpCode.CPUI_MULTIEQUAL:
      case OpCode.CPUI_INDIRECT:
        resType = trial.fitType;  // No score, but we can propagate
        break;
      case OpCode.CPUI_LOAD: {
        const scoreRef = { val: 0 };
        resType = this.derefPointer(trial.fitType, trial.op!.getOut(), scoreRef);
        score = scoreRef.val;
        break;
      }
      case OpCode.CPUI_STORE:
        if (trial.inslot === 1) {
          const scoreRef = { val: 0 };
          const ptrto = this.derefPointer(trial.fitType, trial.op!.getIn(2), scoreRef);
          score = scoreRef.val;
          if (ptrto !== null) {
            if (!lastLevel)
              this.newTrials(trial.op!, 2, ptrto, trial.scoreIndex, trial.array);  // Propagate to value being STOREd
          }
        } else if (trial.inslot === 2) {
          if (meta === type_metatype.TYPE_CODE)
            score = -5;
          else
            score = 1;
        }
        break;
      case OpCode.CPUI_CBRANCH:
        if (meta === type_metatype.TYPE_BOOL)
          score = 10;
        else
          score = -10;
        break;
      case OpCode.CPUI_BRANCHIND:
        if (meta === type_metatype.TYPE_PTR || meta === type_metatype.TYPE_ARRAY ||
            meta === type_metatype.TYPE_STRUCT || meta === type_metatype.TYPE_UNION ||
            meta === type_metatype.TYPE_CODE || meta === type_metatype.TYPE_FLOAT)
          score = -5;
        else
          score = 1;
        break;
      case OpCode.CPUI_CALL:
      case OpCode.CPUI_CALLOTHER:
        if (trial.inslot > 0)
          score = this.scoreParameter(trial.fitType, trial.op!, trial.inslot - 1);
        break;
      case OpCode.CPUI_CALLIND:
        if (trial.inslot === 0) {
          if (meta === type_metatype.TYPE_PTR) {
            const ptrto: Datatype = (trial.fitType as TypePointer).getPtrTo();
            if (ptrto.getMetatype() === type_metatype.TYPE_CODE) {
              score = 10;
            } else {
              score = -10;
            }
          }
        } else {
          score = this.scoreParameter(trial.fitType, trial.op!, trial.inslot - 1);
        }
        break;
      case OpCode.CPUI_RETURN:
        // We could check for locked return data-type
        if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
            meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE)
          score = -1;
        break;
      case OpCode.CPUI_INT_EQUAL:
      case OpCode.CPUI_INT_NOTEQUAL:
        if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
            meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
            meta === type_metatype.TYPE_FLOAT)
          score = -1;
        else
          score = 1;
        break;
      case OpCode.CPUI_INT_SLESS:
      case OpCode.CPUI_INT_SLESSEQUAL:
      case OpCode.CPUI_INT_SCARRY:
      case OpCode.CPUI_INT_SBORROW:
        if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
            meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
            meta === type_metatype.TYPE_FLOAT)
          score = -5;
        else if (meta === type_metatype.TYPE_PTR || meta === type_metatype.TYPE_UNKNOWN ||
                 meta === type_metatype.TYPE_UINT || meta === type_metatype.TYPE_BOOL)
          score = -1;
        else
          score = 5;
        break;
      case OpCode.CPUI_INT_LESS:
      case OpCode.CPUI_INT_LESSEQUAL:
      case OpCode.CPUI_INT_CARRY:
        if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
            meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
            meta === type_metatype.TYPE_FLOAT)
          score = -5;
        else if (meta === type_metatype.TYPE_PTR || meta === type_metatype.TYPE_UNKNOWN ||
                 meta === type_metatype.TYPE_UINT)
          score = 5;
        else if (meta === type_metatype.TYPE_INT)
          score = -5;
        break;
      case OpCode.CPUI_INT_ZEXT:
        if (meta === type_metatype.TYPE_UINT)
          score = 2;
        else if (meta === type_metatype.TYPE_INT || meta === type_metatype.TYPE_BOOL)
          score = 1;
        else if (meta === type_metatype.TYPE_UNKNOWN)
          score = 0;
        else  // struct,union,ptr,array,code,float
          score = -5;
        break;
      case OpCode.CPUI_INT_SEXT:
        if (meta === type_metatype.TYPE_INT)
          score = 2;
        else if (meta === type_metatype.TYPE_UINT || meta === type_metatype.TYPE_BOOL)
          score = 1;
        else if (meta === type_metatype.TYPE_UNKNOWN)
          score = 0;
        else  // struct,union,ptr,array,code,float
          score = -5;
        break;
      case OpCode.CPUI_INT_ADD:
      case OpCode.CPUI_INT_SUB:
      case OpCode.CPUI_PTRSUB:
        if (meta === type_metatype.TYPE_PTR) {
          if (trial.inslot >= 0) {
            const vn: Varnode = trial.op!.getIn(1 - trial.inslot);
            if (vn.isConstant()) {
              const baseType: TypePointer = trial.fitType as TypePointer;
              const off = { val: vn.getOffset() };
              const par = { val: null as TypePointer | null };
              const parOff = { val: 0n };
              resType = baseType.downChain(off, par, parOff, trial.array, this.typegrp);
              if (resType !== null)
                score = 5;
            } else {
              if (trial.array) {
                score = 1;
                let elSize = 1;
                if (vn.isWritten()) {
                  const multOp: PcodeOp = vn.getDef();
                  if (multOp.code() === OpCode.CPUI_INT_MULT) {
                    const multVn: Varnode = multOp.getIn(1);
                    if (multVn.isConstant())
                      elSize = Number(multVn.getOffset());
                  }
                }
                const baseType: TypePointer = trial.fitType as TypePointer;
                if (baseType.getPtrTo().getAlignSize() === elSize) {
                  score = 5;
                  resType = trial.fitType;
                }
              } else {
                score = 5;  // Indexing into something that is not an array
              }
            }
          }
        } else if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
                   meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
                   meta === type_metatype.TYPE_FLOAT)
          score = -5;
        else
          score = 1;
        break;
      case OpCode.CPUI_INT_2COMP:
        if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
            meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
            meta === type_metatype.TYPE_FLOAT)
          score = -5;
        else if (meta === type_metatype.TYPE_PTR || meta === type_metatype.TYPE_UNKNOWN ||
                 meta === type_metatype.TYPE_BOOL)
          score = -1;
        else if (meta === type_metatype.TYPE_INT)
          score = 5;
        break;
      case OpCode.CPUI_INT_NEGATE:
      case OpCode.CPUI_INT_XOR:
      case OpCode.CPUI_INT_AND:
      case OpCode.CPUI_INT_OR:
      case OpCode.CPUI_POPCOUNT:
      case OpCode.CPUI_LZCOUNT:
        if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
            meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
            meta === type_metatype.TYPE_FLOAT)
          score = -5;
        else if (meta === type_metatype.TYPE_PTR || meta === type_metatype.TYPE_BOOL)
          score = -1;
        else if (meta === type_metatype.TYPE_UINT || meta === type_metatype.TYPE_UNKNOWN)
          score = 2;
        break;
      case OpCode.CPUI_INT_LEFT:
      case OpCode.CPUI_INT_RIGHT:
        if (trial.inslot === 0) {
          if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
              meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
              meta === type_metatype.TYPE_FLOAT)
            score = -5;
          else if (meta === type_metatype.TYPE_PTR || meta === type_metatype.TYPE_BOOL)
            score = -1;
          else if (meta === type_metatype.TYPE_UINT || meta === type_metatype.TYPE_UNKNOWN)
            score = 2;
        } else {
          if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
              meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
              meta === type_metatype.TYPE_FLOAT || meta === type_metatype.TYPE_PTR)
            score = -5;
          else
            score = 1;
        }
        break;
      case OpCode.CPUI_INT_SRIGHT:
        if (trial.inslot === 0) {
          if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
              meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
              meta === type_metatype.TYPE_FLOAT)
            score = -5;
          else if (meta === type_metatype.TYPE_PTR || meta === type_metatype.TYPE_BOOL ||
                   meta === type_metatype.TYPE_UINT || meta === type_metatype.TYPE_UNKNOWN)
            score = -1;
          else
            score = 2;
        } else {
          if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
              meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
              meta === type_metatype.TYPE_FLOAT || meta === type_metatype.TYPE_PTR)
            score = -5;
          else
            score = 1;
        }
        break;
      case OpCode.CPUI_INT_MULT:
        if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
            meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
            meta === type_metatype.TYPE_FLOAT)
          score = -10;
        else if (meta === type_metatype.TYPE_PTR || meta === type_metatype.TYPE_BOOL)
          score = -2;
        else
          score = 5;
        break;
      case OpCode.CPUI_INT_DIV:
      case OpCode.CPUI_INT_REM:
        if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
            meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
            meta === type_metatype.TYPE_FLOAT)
          score = -10;
        else if (meta === type_metatype.TYPE_PTR || meta === type_metatype.TYPE_BOOL)
          score = -2;
        else if (meta === type_metatype.TYPE_UINT || meta === type_metatype.TYPE_UNKNOWN)
          score = 5;
        break;
      case OpCode.CPUI_INT_SDIV:
      case OpCode.CPUI_INT_SREM:
        if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
            meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
            meta === type_metatype.TYPE_FLOAT)
          score = -10;
        else if (meta === type_metatype.TYPE_PTR || meta === type_metatype.TYPE_BOOL)
          score = -2;
        else if (meta === type_metatype.TYPE_INT)
          score = 5;
        break;
      case OpCode.CPUI_BOOL_NEGATE:
      case OpCode.CPUI_BOOL_AND:
      case OpCode.CPUI_BOOL_XOR:
      case OpCode.CPUI_BOOL_OR:
        if (meta === type_metatype.TYPE_BOOL)
          score = 10;
        else if (meta === type_metatype.TYPE_INT || meta === type_metatype.TYPE_UINT ||
                 meta === type_metatype.TYPE_UNKNOWN)
          score = -1;
        else
          score = -10;
        break;
      case OpCode.CPUI_FLOAT_EQUAL:
      case OpCode.CPUI_FLOAT_NOTEQUAL:
      case OpCode.CPUI_FLOAT_LESS:
      case OpCode.CPUI_FLOAT_LESSEQUAL:
      case OpCode.CPUI_FLOAT_NAN:
      case OpCode.CPUI_FLOAT_ADD:
      case OpCode.CPUI_FLOAT_DIV:
      case OpCode.CPUI_FLOAT_MULT:
      case OpCode.CPUI_FLOAT_SUB:
      case OpCode.CPUI_FLOAT_NEG:
      case OpCode.CPUI_FLOAT_ABS:
      case OpCode.CPUI_FLOAT_SQRT:
      case OpCode.CPUI_FLOAT_FLOAT2FLOAT:
      case OpCode.CPUI_FLOAT_TRUNC:
      case OpCode.CPUI_FLOAT_CEIL:
      case OpCode.CPUI_FLOAT_FLOOR:
      case OpCode.CPUI_FLOAT_ROUND:
        if (meta === type_metatype.TYPE_FLOAT)
          score = 10;
        else
          score = -10;
        break;
      case OpCode.CPUI_FLOAT_INT2FLOAT:
        if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
            meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
            meta === type_metatype.TYPE_FLOAT)
          score = -10;
        else if (meta === type_metatype.TYPE_PTR)
          score = -5;
        else if (meta === type_metatype.TYPE_INT)
          score = 5;
        break;
      case OpCode.CPUI_PIECE:
        if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
            meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
            meta === type_metatype.TYPE_FLOAT)
          score = -5;
        break;
      case OpCode.CPUI_SUBPIECE: {
        const offset = ScoreUnionFields.computeByteOffsetForComposite(trial.op!);
        resType = this.scoreTruncation(trial.fitType, trial.op!.getOut(), offset, trial.scoreIndex);
        break;
      }
      case OpCode.CPUI_PTRADD:
        if (meta === type_metatype.TYPE_PTR) {
          if (trial.inslot === 0) {
            const ptrto: Datatype = (trial.fitType as TypePointer).getPtrTo();
            if (ptrto.getAlignSize() === Number(trial.op!.getIn(2).getOffset())) {
              score = 10;
              resType = trial.fitType;
            }
          } else {
            score = -10;
          }
        } else if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
                   meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
                   meta === type_metatype.TYPE_FLOAT)
          score = -5;
        else
          score = 1;
        break;
      case OpCode.CPUI_SEGMENTOP:
        if (trial.inslot === 2) {
          if (meta === type_metatype.TYPE_PTR)
            score = 5;
          else if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
                   meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
                   meta === type_metatype.TYPE_FLOAT)
            score = -5;
          else
            score = -1;
        } else {
          if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
              meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
              meta === type_metatype.TYPE_FLOAT || meta === type_metatype.TYPE_PTR)
            score = -2;
        }
        break;
      default:
        score = -10;  // Doesn't fit
        break;
    }
    this.scores[trial.scoreIndex] += score;
    if (resType !== null && !lastLevel)
      this.newTrialsDown(trial.op!.getOut(), resType, trial.scoreIndex, trial.array);
  }

  /**
   * Try to fit the given trial following data-flow up.
   */
  private scoreTrialUp(trial: Trial, lastLevel: boolean): void {
    if (trial.direction === TrialDirection.fit_down)
      return;  // Trial doesn't push in this direction
    let score = 0;
    if (!trial.vn.isWritten()) {
      if (trial.vn.isConstant())
        this.scoreConstantFit(trial);
      return;  // Nothing to propagate up through
    }
    let resType: Datatype | null = null;  // Assume by default we don't propagate
    let newslot = 0;
    const meta: type_metatype = trial.fitType.getMetatype();
    const def: PcodeOp = trial.vn.getDef();
    switch (def.code()) {
      case OpCode.CPUI_COPY:
      case OpCode.CPUI_MULTIEQUAL:
      case OpCode.CPUI_INDIRECT:
        resType = trial.fitType;  // No score, but we can propagate
        newslot = 0;
        break;
      case OpCode.CPUI_LOAD:
        resType = this.typegrp.getTypePointer(def.getIn(1).getSize(), trial.fitType, 1);
        newslot = 1;  // No score, but we can propagate
        break;
      case OpCode.CPUI_CALL:
      case OpCode.CPUI_CALLOTHER:
      case OpCode.CPUI_CALLIND:
        score = this.scoreReturnType(trial.fitType, def);
        break;
      case OpCode.CPUI_INT_EQUAL:
      case OpCode.CPUI_INT_NOTEQUAL:
      case OpCode.CPUI_INT_SLESS:
      case OpCode.CPUI_INT_SLESSEQUAL:
      case OpCode.CPUI_INT_SCARRY:
      case OpCode.CPUI_INT_SBORROW:
      case OpCode.CPUI_INT_LESS:
      case OpCode.CPUI_INT_LESSEQUAL:
      case OpCode.CPUI_INT_CARRY:
      case OpCode.CPUI_BOOL_NEGATE:
      case OpCode.CPUI_BOOL_AND:
      case OpCode.CPUI_BOOL_XOR:
      case OpCode.CPUI_BOOL_OR:
      case OpCode.CPUI_FLOAT_EQUAL:
      case OpCode.CPUI_FLOAT_NOTEQUAL:
      case OpCode.CPUI_FLOAT_LESS:
      case OpCode.CPUI_FLOAT_LESSEQUAL:
      case OpCode.CPUI_FLOAT_NAN:
        if (meta === type_metatype.TYPE_BOOL)
          score = 10;
        else if (trial.fitType.getSize() === 1)
          score = 1;
        else
          score = -10;
        break;
      case OpCode.CPUI_INT_ADD:
      case OpCode.CPUI_INT_SUB:
      case OpCode.CPUI_PTRSUB:
        if (meta === type_metatype.TYPE_PTR) {
          score = 5;  // Don't try to back up further
        } else if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
                   meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
                   meta === type_metatype.TYPE_FLOAT)
          score = -5;
        else
          score = 1;
        break;
      case OpCode.CPUI_INT_2COMP:
        if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
            meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
            meta === type_metatype.TYPE_FLOAT)
          score = -5;
        else if (meta === type_metatype.TYPE_PTR || meta === type_metatype.TYPE_UNKNOWN ||
                 meta === type_metatype.TYPE_BOOL)
          score = -1;
        else if (meta === type_metatype.TYPE_INT)
          score = 5;
        break;
      case OpCode.CPUI_INT_NEGATE:
      case OpCode.CPUI_INT_XOR:
      case OpCode.CPUI_INT_AND:
      case OpCode.CPUI_INT_OR:
      case OpCode.CPUI_POPCOUNT:
      case OpCode.CPUI_LZCOUNT:
        if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
            meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
            meta === type_metatype.TYPE_FLOAT)
          score = -5;
        else if (meta === type_metatype.TYPE_PTR || meta === type_metatype.TYPE_BOOL)
          score = -1;
        else if (meta === type_metatype.TYPE_UINT || meta === type_metatype.TYPE_UNKNOWN)
          score = 2;
        break;
      case OpCode.CPUI_INT_LEFT:
      case OpCode.CPUI_INT_RIGHT:
        if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
            meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
            meta === type_metatype.TYPE_FLOAT)
          score = -5;
        else if (meta === type_metatype.TYPE_PTR || meta === type_metatype.TYPE_BOOL)
          score = -1;
        else if (meta === type_metatype.TYPE_UINT || meta === type_metatype.TYPE_UNKNOWN)
          score = 2;
        break;
      case OpCode.CPUI_INT_SRIGHT:
        if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
            meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
            meta === type_metatype.TYPE_FLOAT)
          score = -5;
        else if (meta === type_metatype.TYPE_PTR || meta === type_metatype.TYPE_BOOL ||
                 meta === type_metatype.TYPE_UINT || meta === type_metatype.TYPE_UNKNOWN)
          score = -1;
        else
          score = 2;
        break;
      case OpCode.CPUI_INT_MULT:
        if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
            meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
            meta === type_metatype.TYPE_FLOAT)
          score = -10;
        else if (meta === type_metatype.TYPE_PTR || meta === type_metatype.TYPE_BOOL)
          score = -2;
        else
          score = 5;
        break;
      case OpCode.CPUI_INT_DIV:
      case OpCode.CPUI_INT_REM:
        if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
            meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
            meta === type_metatype.TYPE_FLOAT)
          score = -10;
        else if (meta === type_metatype.TYPE_PTR || meta === type_metatype.TYPE_BOOL)
          score = -2;
        else if (meta === type_metatype.TYPE_UINT || meta === type_metatype.TYPE_UNKNOWN)
          score = 5;
        break;
      case OpCode.CPUI_INT_SDIV:
      case OpCode.CPUI_INT_SREM:
        if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
            meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
            meta === type_metatype.TYPE_FLOAT)
          score = -10;
        else if (meta === type_metatype.TYPE_PTR || meta === type_metatype.TYPE_BOOL)
          score = -2;
        else if (meta === type_metatype.TYPE_INT)
          score = 5;
        break;
      case OpCode.CPUI_FLOAT_ADD:
      case OpCode.CPUI_FLOAT_DIV:
      case OpCode.CPUI_FLOAT_MULT:
      case OpCode.CPUI_FLOAT_SUB:
      case OpCode.CPUI_FLOAT_NEG:
      case OpCode.CPUI_FLOAT_ABS:
      case OpCode.CPUI_FLOAT_SQRT:
      case OpCode.CPUI_FLOAT_FLOAT2FLOAT:
      case OpCode.CPUI_FLOAT_CEIL:
      case OpCode.CPUI_FLOAT_FLOOR:
      case OpCode.CPUI_FLOAT_ROUND:
      case OpCode.CPUI_FLOAT_INT2FLOAT:
        if (meta === type_metatype.TYPE_FLOAT)
          score = 10;
        else
          score = -10;
        break;
      case OpCode.CPUI_FLOAT_TRUNC:
        if (meta === type_metatype.TYPE_INT || meta === type_metatype.TYPE_UINT)
          score = 2;
        else
          score = -2;
        break;
      case OpCode.CPUI_PIECE:
        if (meta === type_metatype.TYPE_FLOAT || meta === type_metatype.TYPE_BOOL)
          score = -5;
        else if (meta === type_metatype.TYPE_CODE || meta === type_metatype.TYPE_PTR)
          score = -2;
        break;
      case OpCode.CPUI_SUBPIECE:
        if (meta === type_metatype.TYPE_INT || meta === type_metatype.TYPE_UINT ||
            meta === type_metatype.TYPE_BOOL) {
          if (Number(def.getIn(1).getOffset()) === 0)
            score = 3;  // Likely truncation
          else
            score = 1;
        } else
          score = -5;
        break;
      case OpCode.CPUI_PTRADD:
        if (meta === type_metatype.TYPE_PTR) {
          const ptrto: Datatype = (trial.fitType as TypePointer).getPtrTo();
          if (ptrto.getAlignSize() === Number(def.getIn(2).getOffset()))
            score = 10;
          else
            score = 2;
        } else if (meta === type_metatype.TYPE_ARRAY || meta === type_metatype.TYPE_STRUCT ||
                   meta === type_metatype.TYPE_UNION || meta === type_metatype.TYPE_CODE ||
                   meta === type_metatype.TYPE_FLOAT)
          score = -5;
        else
          score = 1;
        break;
      default:
        score = -10;  // Datatype doesn't fit
        break;
    }
    this.scores[trial.scoreIndex] += score;
    if (resType !== null && !lastLevel) {
      this.newTrials(def, newslot, resType, trial.scoreIndex, trial.array);
    }
  }

  /**
   * Score a truncation in the data-flow.
   *
   * The truncation may be an explicit CPUI_SUBPIECE, or it may be implied.
   * A score is computed for fitting a given data-type to the truncation, and a possible
   * data-type to recurse is also computed.
   * @param ct is the given data-type to truncate
   * @param vn is the Varnode the truncation will fit into
   * @param offset is the number of bytes truncated off the start of the data-type
   * @param scoreIndex is the field being scored
   * @return the data-type to recurse or null
   */
  private scoreTruncation(ct: Datatype, vn: Varnode, offset: number, scoreIndex: number): Datatype | null {
    let score: number;
    if (ct.getMetatype() === type_metatype.TYPE_UNION) {
      const unionDt: TypeUnion = ct as TypeUnion;
      ct = null as any;  // Don't recurse a data-type from truncation of a union
      score = -10;       // Negative score if the union has no field matching the size
      const num: number = unionDt.numDepend();
      for (let i = 0; i < num; ++i) {
        const field: TypeField = unionDt.getField(i);
        if (field.offset === offset && field.type.getSize() === vn.getSize()) {
          score = 10;
          if (this.result.getBase() === unionDt)
            score += 5;
          break;
        }
      }
    } else {
      score = 10;  // If we can find a size match for the truncation
      let curOff: bigint = BigInt(offset);
      while (ct !== null && (curOff !== 0n || ct.getSize() !== vn.getSize())) {
        if (ct.getMetatype() === type_metatype.TYPE_INT || ct.getMetatype() === type_metatype.TYPE_UINT) {
          if (ct.getSize() >= vn.getSize() + Number(curOff)) {
            score = 1;  // Size doesn't match, but still possibly a reasonable operation
            break;
          }
        }
        const newoff = { val: curOff };
        ct = ct.getSubType(curOff, newoff)!;
        curOff = newoff.val;
      }
      if (ct === null)
        score = -10;
    }
    this.scores[scoreIndex] += score;
    return ct;
  }

  /**
   * Score trial data-type against a constant.
   *
   * Assume the constant has no data-type of its own to match against.
   * Evaluate if the constant looks like an integer or pointer etc. and score the trial data-type against that.
   */
  private scoreConstantFit(trial: Trial): void {
    const size: number = trial.vn.getSize();
    const val: bigint = trial.vn.getOffset();
    const meta: type_metatype = trial.fitType.getMetatype();
    let score = 0;
    if (meta === type_metatype.TYPE_BOOL) {
      score = (size === 1 && val < 2n) ? 2 : -2;
    } else if (meta === type_metatype.TYPE_FLOAT) {
      score = -1;
      const format: FloatFormat | null = this.typegrp.getArch().translate.getFloatFormat(size);
      if (format !== null) {
        const exp: number = format.extractExponentCode(val);
        if (exp < 7 && exp > -4)  // Check for common exponent range
          score = 2;
      }
    } else if (meta === type_metatype.TYPE_INT || meta === type_metatype.TYPE_UINT ||
               meta === type_metatype.TYPE_PTR) {
      if (val === 0n) {
        score = 2;  // Zero is equally valid as pointer or integer
      } else {
        const spc: AddrSpace = this.typegrp.getArch().getDefaultDataSpace();
        let looksLikePointer = false;
        if (val >= spc.getPointerLowerBound() && val <= spc.getPointerUpperBound()) {
          if (bit_transitions(val, size) >= 3) {
            looksLikePointer = true;
          }
        }
        if (meta === type_metatype.TYPE_PTR) {
          score = looksLikePointer ? 2 : -2;
        } else {
          score = looksLikePointer ? 1 : 2;
        }
      }
    } else {
      score = -2;
    }
    this.scores[trial.scoreIndex] += score;
  }

  /**
   * Score all the current trials.
   *
   * Run through each trial in the current list and compute a score. If the trial recurses and this is
   * not the final pass, build new trials for the recursion.
   */
  private runOneLevel(lastPass: boolean): void {
    for (let i = 0; i < this.trialCurrent.length; ++i) {
      this.trialCount += 1;
      if (this.trialCount > ScoreUnionFields.maxTrials)
        return;  // Absolute number of trials reached
      const trial = this.trialCurrent[i];
      this.scoreTrialDown(trial, lastPass);
      this.scoreTrialUp(trial, lastPass);
    }
  }

  /**
   * Assuming scoring is complete, compute the best index.
   */
  private computeBestIndex(): void {
    let bestScore = this.scores[0];
    let bestIndex = 0;
    for (let i = 1; i < this.scores.length; ++i) {
      if (this.scores[i] > bestScore) {
        bestScore = this.scores[i];
        bestIndex = i;
      }
    }
    this.result.fieldNum = bestIndex - 1;  // Renormalize score index to field index
    this.result.resolve = this.fields[bestIndex]!;
  }

  /**
   * Calculate best fitting field.
   *
   * Try to fit each possible field over multiple levels of the data-flow.
   * Return the index of the highest scoring field or -1 if the union data-type
   * itself is the best fit.
   */
  private run(): void {
    this.trialCount = 0;
    for (let pass = 0; pass < ScoreUnionFields.maxPasses; ++pass) {
      if (this.trialCurrent.length === 0)
        break;
      if (this.trialCount > ScoreUnionFields.threshold)
        break;  // Threshold reached, don't score any more trials
      if (pass + 1 === ScoreUnionFields.maxPasses) {
        this.runOneLevel(true);
      } else {
        this.runOneLevel(false);
        // Swap trialCurrent and trialNext
        const temp = this.trialCurrent;
        this.trialCurrent = this.trialNext;
        this.trialNext = temp;
        this.trialNext.length = 0;
      }
    }
  }

  /**
   * Static helper to compute the byte offset for composite data-type operations (SUBPIECE).
   * This mirrors TypeOpSubpiece::computeByteOffsetForComposite from typeop.cc.
   */
  static computeByteOffsetForComposite(op: PcodeOp): number {
    const outSize: number = op.getOut().getSize();
    const lsb: number = Number(op.getIn(1).getOffset());
    const vn: Varnode = op.getIn(0);
    if (vn.getSpace().isBigEndian())
      return vn.getSize() - outSize - lsb;
    else
      return lsb;
  }
}

// Register real classes to break circular dependency with type.ts
registerUnionResolveClasses(ScoreUnionFields, ResolvedUnion);
