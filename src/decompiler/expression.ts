/**
 * @file expression.ts
 * @description Classes to collect, analyze, and match expressions within p-code data-flow.
 *
 * Translated from Ghidra's expression.hh / expression.cc
 */

import type { int4, uint4, uintb } from '../core/types.js';
import { OpCode, get_booleanflip } from '../core/opcodes.js';
import { calc_mask, signbit_negative } from '../core/address.js';

// Forward-declare types not yet available as concrete imports
type PcodeOp = any;
type Varnode = any;
type Funcdata = any;
type HighVariable = any;

// ---------------------------------------------------------------------------
// PcodeOpNode
// ---------------------------------------------------------------------------

/**
 * An edge in a data-flow path or graph.
 *
 * A minimal node for traversing expressions in the data-flow.
 */
export class PcodeOpNode {
  /** The p-code end-point of the edge */
  op: PcodeOp | null;
  /** Slot indicating the input Varnode end-point of the edge */
  slot: int4;

  constructor(o?: PcodeOp | null, s?: int4) {
    if (o !== undefined && s !== undefined) {
      this.op = o;
      this.slot = s;
    } else {
      this.op = null;
      this.slot = 0;
    }
  }

  /**
   * Simple comparator for putting edges in a sorted container.
   * Compare PcodeOps (by sequence time) first, then slot.
   * Returns true if `this` should come before `op2`.
   */
  lessThan(op2: PcodeOpNode): boolean {
    if (this.op !== op2.op)
      return (this.op!.getSeqNum().getTime() < op2.op!.getSeqNum().getTime());
    if (this.slot !== op2.slot)
      return (this.slot < op2.slot);
    return false;
  }

  /**
   * Compare Varnodes by their HighVariable.
   * Allow a sorting that groups together input Varnodes with the same HighVariable.
   */
  static compareByHigh(a: PcodeOpNode, b: PcodeOpNode): boolean {
    return a.op!.getIn(a.slot)!.getHigh() < b.op!.getIn(b.slot)!.getHigh();
  }
}

// ---------------------------------------------------------------------------
// TraverseNode
// ---------------------------------------------------------------------------

/**
 * Node for a forward traversal of a Varnode expression.
 */
export class TraverseNode {
  /** Alternate path traverses a solid action or non-incidental COPY */
  static readonly actionalt = 1;
  /** Main path traverses an INDIRECT */
  static readonly indirect = 2;
  /** Alternate path traverses an INDIRECT */
  static readonly indirectalt = 4;
  /** Least significant byte(s) of original value have been truncated */
  static readonly lsb_truncated = 8;
  /** Original value has been concatenated as most significant portion */
  static readonly concat_high = 0x10;

  /** Varnode at the point of traversal */
  vn: Varnode;
  /** Flags associated with the node */
  flags: uint4;

  constructor(v: Varnode, f: uint4) {
    this.vn = v;
    this.flags = f;
  }

  /**
   * Return true if the alternate path looks more valid than the main path.
   *
   * Two different paths from a common Varnode each terminate at a CALL, CALLIND, or RETURN.
   * Evaluate which path most likely represents actual parameter/return value passing,
   * based on traversal information about each path.
   */
  static isAlternatePathValid(vn: Varnode, flags: uint4): boolean {
    if ((flags & (TraverseNode.indirect | TraverseNode.indirectalt)) === TraverseNode.indirect)
      // If main path traversed an INDIRECT but the alternate did not
      return true;
    if ((flags & (TraverseNode.indirect | TraverseNode.indirectalt)) === TraverseNode.indirectalt)
      return false;  // Alternate path traversed INDIRECT, main did not
    if ((flags & TraverseNode.actionalt) !== 0)
      return true;   // Alternate path traversed a dedicated COPY
    if (vn.loneDescend() === null) return false;
    let op: PcodeOp | null = vn.getDef();
    if (op === null) return true;
    while (op!.isIncidentalCopy() && op!.code() === OpCode.CPUI_COPY) {
      // Skip any incidental COPY
      vn = op!.getIn(0);
      if (vn.loneDescend() === null) return false;
      op = vn.getDef();
      if (op === null) return true;
    }
    return !op!.isMarker();  // MULTIEQUAL or INDIRECT indicates multiple values
  }
}

// ---------------------------------------------------------------------------
// BooleanMatch
// ---------------------------------------------------------------------------

/**
 * Static methods for determining if two boolean expressions are the same or complementary.
 *
 * Traverse (up to a specific depth) the two boolean expressions consisting of BOOL_AND, BOOL_OR,
 * and BOOL_XOR operations. Leaf operators in the expression can be other operators with boolean
 * output (INT_LESS, INT_SLESS, etc.).
 */
export class BooleanMatch {
  /** Pair always hold the same value */
  static readonly same = 1;
  /** Pair always hold complementary values */
  static readonly complementary = 2;
  /** Pair values are uncorrelated */
  static readonly uncorrelated = 3;

  /**
   * Test if two operations with same opcode produce complementary boolean values.
   *
   * This only tests for cases where the opcode is INT_LESS or INT_SLESS and one of the
   * inputs is constant.
   */
  private static sameOpComplement(bin1op: PcodeOp, bin2op: PcodeOp): boolean {
    const opcode: OpCode = bin1op.code();
    if ((opcode === OpCode.CPUI_INT_SLESS) || (opcode === OpCode.CPUI_INT_LESS)) {
      // Basically we test for the scenario like:  x < 9   8 < x
      let constslot: int4 = 0;
      if (bin1op.getIn(1)!.isConstant())
        constslot = 1;
      if (!bin1op.getIn(constslot)!.isConstant()) return false;
      if (!bin2op.getIn(1 - constslot)!.isConstant()) return false;
      if (!BooleanMatch.varnodeSame(bin1op.getIn(1 - constslot), bin2op.getIn(constslot))) return false;
      let val1: uintb = bin1op.getIn(constslot)!.getOffset();
      let val2: uintb = bin2op.getIn(1 - constslot)!.getOffset();
      if (constslot !== 0) {
        const tmp = val2;
        val2 = val1;
        val1 = tmp;
      }
      if (val1 + 1n !== val2) return false;
      if ((val2 === 0n) && (opcode === OpCode.CPUI_INT_LESS)) return false; // Corner case for unsigned
      if (opcode === OpCode.CPUI_INT_SLESS) { // Corner case for signed
        const sz: int4 = bin1op.getIn(constslot)!.getSize();
        if (signbit_negative(val2, sz) && (!signbit_negative(val1, sz)))
          return false;
      }
      return true;
    }
    return false;
  }

  /**
   * Do the given Varnodes hold the same value, possibly as constants.
   */
  private static varnodeSame(a: Varnode, b: Varnode): boolean {
    if (a === b) return true;
    if (a.isConstant() && b.isConstant())
      return (a.getOffset() === b.getOffset());
    return false;
  }

  /**
   * Determine if two boolean Varnodes hold related values.
   *
   * The values may be the same, or opposite of each other (complementary).
   * Otherwise the values are uncorrelated. The trees constructing each Varnode
   * are examined up to a maximum depth. If this is exceeded, uncorrelated is returned.
   */
  static evaluate(vn1: Varnode, vn2: Varnode, depth: int4): int4 {
    if (vn1 === vn2) return BooleanMatch.same;
    let op1: PcodeOp | null;
    let op2: PcodeOp | null;
    let opc1: OpCode;
    let opc2: OpCode;
    if (vn1.isWritten()) {
      op1 = vn1.getDef();
      opc1 = op1!.code();
      if (opc1 === OpCode.CPUI_BOOL_NEGATE) {
        let res: int4 = BooleanMatch.evaluate(op1!.getIn(0), vn2, depth);
        if (res === BooleanMatch.same)
          res = BooleanMatch.complementary;
        else if (res === BooleanMatch.complementary)
          res = BooleanMatch.same;
        return res;
      }
    } else {
      op1 = null;                      // Don't give up before checking if op2 is BOOL_NEGATE
      opc1 = OpCode.CPUI_MAX;
    }
    if (vn2.isWritten()) {
      op2 = vn2.getDef();
      opc2 = op2!.code();
      if (opc2 === OpCode.CPUI_BOOL_NEGATE) {
        let res: int4 = BooleanMatch.evaluate(vn1, op2!.getIn(0), depth);
        if (res === BooleanMatch.same)
          res = BooleanMatch.complementary;
        else if (res === BooleanMatch.complementary)
          res = BooleanMatch.same;
        return res;
      }
    } else {
      return BooleanMatch.uncorrelated;
    }
    if (op1 === null)
      return BooleanMatch.uncorrelated;
    if (!op1!.isBoolOutput() || !op2!.isBoolOutput())
      return BooleanMatch.uncorrelated;
    if (depth !== 0 && (opc1! === OpCode.CPUI_BOOL_AND || opc1! === OpCode.CPUI_BOOL_OR || opc1! === OpCode.CPUI_BOOL_XOR)) {
      if (opc2! === OpCode.CPUI_BOOL_AND || opc2! === OpCode.CPUI_BOOL_OR || opc2! === OpCode.CPUI_BOOL_XOR) {
        if (opc1! === opc2! || (opc1! === OpCode.CPUI_BOOL_AND && opc2! === OpCode.CPUI_BOOL_OR) || (opc1! === OpCode.CPUI_BOOL_OR && opc2! === OpCode.CPUI_BOOL_AND)) {
          let pair1: int4 = BooleanMatch.evaluate(op1!.getIn(0), op2!.getIn(0), depth - 1);
          let pair2: int4;
          if (pair1 === BooleanMatch.uncorrelated) {
            pair1 = BooleanMatch.evaluate(op1!.getIn(0), op2!.getIn(1), depth - 1);  // Try other possible pairing (commutative op)
            if (pair1 === BooleanMatch.uncorrelated)
              return BooleanMatch.uncorrelated;
            pair2 = BooleanMatch.evaluate(op1!.getIn(1), op2!.getIn(0), depth - 1);
          } else {
            pair2 = BooleanMatch.evaluate(op1!.getIn(1), op2!.getIn(1), depth - 1);
          }
          if (pair2 === BooleanMatch.uncorrelated)
            return BooleanMatch.uncorrelated;
          if (opc1! === opc2!) {
            if (pair1 === BooleanMatch.same && pair2 === BooleanMatch.same)
              return BooleanMatch.same;
            else if (opc1! === OpCode.CPUI_BOOL_XOR) {
              if (pair1 === BooleanMatch.complementary && pair2 === BooleanMatch.complementary)
                return BooleanMatch.same;
              return BooleanMatch.complementary;
            }
          } else {
            // Must be CPUI_BOOL_AND and CPUI_BOOL_OR
            if (pair1 === BooleanMatch.complementary && pair2 === BooleanMatch.complementary)
              return BooleanMatch.complementary;  // De Morgan's Law
          }
        }
      }
    } else {
      // Two boolean output ops, compare them directly
      if (opc1! === opc2!) {
        let sameOp = true;
        const numInputs: int4 = op1!.numInput();
        for (let i = 0; i < numInputs; ++i) {
          if (!BooleanMatch.varnodeSame(op1!.getIn(i), op2!.getIn(i))) {
            sameOp = false;
            break;
          }
        }
        if (sameOp) {
          return BooleanMatch.same;
        }
        if (BooleanMatch.sameOpComplement(op1!, op2!)) {
          return BooleanMatch.complementary;
        }
        return BooleanMatch.uncorrelated;
      }
      // Check if the binary ops are complements of one another
      const slot1: int4 = 0;
      let slot2: int4 = 0;
      const flipped = get_booleanflip(opc2!);
      if (opc1! !== flipped.result)
        return BooleanMatch.uncorrelated;
      if (flipped.reorder) slot2 = 1;
      if (!BooleanMatch.varnodeSame(op1!.getIn(slot1), op2!.getIn(slot2)))
        return BooleanMatch.uncorrelated;
      if (!BooleanMatch.varnodeSame(op1!.getIn(1 - slot1), op2!.getIn(1 - slot2)))
        return BooleanMatch.uncorrelated;
      return BooleanMatch.complementary;
    }
    return BooleanMatch.uncorrelated;
  }
}

// ---------------------------------------------------------------------------
// BooleanExpressionMatch
// ---------------------------------------------------------------------------

/**
 * A helper class for describing the similarity of the boolean condition between 2 CBRANCH operations.
 *
 * This class determines if two CBRANCHs share the same condition. It also determines if the conditions
 * are complements of each other, and/or they are shared along only one path.
 */
export class BooleanExpressionMatch {
  /** Maximum depth to trace a boolean expression */
  private static readonly maxDepth: int4 = 1;
  /** True if the compared CBRANCH keys on the opposite boolean value of the root */
  private matchflip: boolean = false;

  /**
   * Perform the correlation test on two CBRANCH operations.
   */
  verifyCondition(op: PcodeOp, iop: PcodeOp): boolean {
    const res: int4 = BooleanMatch.evaluate(op.getIn(1), iop.getIn(1), BooleanExpressionMatch.maxDepth);
    if (res === BooleanMatch.uncorrelated)
      return false;
    this.matchflip = (res === BooleanMatch.complementary);
    if (op.isBooleanFlip())
      this.matchflip = !this.matchflip;
    if (iop.isBooleanFlip())
      this.matchflip = !this.matchflip;
    return true;
  }

  /** Get the MULTIEQUAL slot in the critical path */
  getMultiSlot(): int4 { return -1; }

  /** Return true if the expressions are anti-correlated */
  getFlip(): boolean { return this.matchflip; }
}

// ---------------------------------------------------------------------------
// AdditiveEdge
// ---------------------------------------------------------------------------

/**
 * Class representing a term in an additive expression.
 */
export class AdditiveEdge {
  /** Lone descendant reading the term */
  private op: PcodeOp;
  /** The input slot of the term */
  private slot: int4;
  /** The term Varnode */
  private vn: Varnode;
  /** The (optional) multiplier being applied to the term */
  private mult: PcodeOp | null;

  constructor(o: PcodeOp, s: int4, m: PcodeOp | null) {
    this.op = o;
    this.slot = s;
    this.vn = o.getIn(s);
    this.mult = m;
  }

  /** Get the multiplier PcodeOp */
  getMultiplier(): PcodeOp | null { return this.mult; }

  /** Get the component PcodeOp adding in the term */
  getOp(): PcodeOp { return this.op; }

  /** Get the slot reading the term */
  getSlot(): int4 { return this.slot; }

  /** Get the Varnode term */
  getVarnode(): Varnode { return this.vn; }
}

// ---------------------------------------------------------------------------
// TermOrder
// ---------------------------------------------------------------------------

/**
 * A class for ordering Varnode terms in an additive expression.
 *
 * Given the final PcodeOp in a data-flow expression that sums 2 or more
 * Varnode terms, this class collects all the terms then allows
 * sorting of the terms to facilitate constant collapse and factoring simplifications.
 */
export class TermOrder {
  /** The final PcodeOp in the expression */
  private root: PcodeOp;
  /** Collected terms */
  private terms: AdditiveEdge[] = [];
  /** An array of references to terms for quick sorting */
  private sorter: AdditiveEdge[] = [];

  /**
   * A comparison operator for ordering terms in a sum.
   *
   * This is based on Varnode.termOrder which groups constants terms and
   * ignores multiplicative coefficients.
   */
  private static additiveCompare(op1: AdditiveEdge, op2: AdditiveEdge): boolean {
    return (-1 === op1.getVarnode().termOrder(op2.getVarnode()));
  }

  /** Construct given root PcodeOp */
  constructor(rt: PcodeOp) {
    this.root = rt;
  }

  /** Get the number of terms in the expression */
  getSize(): int4 { return this.terms.length; }

  /**
   * Collect all the terms in the expression.
   *
   * Assuming root.getOut() is the root of an expression formed with the
   * CPUI_INT_ADD op, collect all the Varnode terms of the expression.
   */
  collect(): void {
    let curvn: Varnode;
    let curop: PcodeOp;
    let subop: PcodeOp;
    let multop: PcodeOp | null;

    const opstack: PcodeOp[] = [];          // Depth first traversal path
    const multstack: (PcodeOp | null)[] = [];

    opstack.push(this.root);
    multstack.push(null);

    while (opstack.length > 0) {
      curop = opstack.pop()!;
      multop = multstack.pop()!;
      for (let i = 0; i < curop.numInput(); ++i) {
        curvn = curop.getIn(i);               // curvn is a node of the subtree IF
        if (!curvn.isWritten()) {              // curvn is not defined by another operation
          this.terms.push(new AdditiveEdge(curop, i, multop));
          continue;
        }
        if (curvn.loneDescend() === null) {    // curvn has more than one use
          this.terms.push(new AdditiveEdge(curop, i, multop));
          continue;
        }
        subop = curvn.getDef();
        if (subop.code() !== OpCode.CPUI_INT_ADD) {
          // or if curvn is defined with some other type of op
          if ((subop.code() === OpCode.CPUI_INT_MULT) && (subop.getIn(1)!.isConstant())) {
            const addop: PcodeOp | null = subop.getIn(0)!.getDef();
            if ((addop !== null) && (addop.code() === OpCode.CPUI_INT_ADD)) {
              if (addop.getOut()!.loneDescend() !== null) {
                opstack.push(addop);
                multstack.push(subop);
                continue;
              }
            }
          }
          this.terms.push(new AdditiveEdge(curop, i, multop));
          continue;
        }
        opstack.push(subop);
        multstack.push(multop);
      }
    }
  }

  /** Sort the terms using additiveCompare() */
  sortTerms(): void {
    this.sorter = [];
    this.sorter.length = this.terms.length;
    for (let i = 0; i < this.terms.length; ++i) {
      this.sorter[i] = this.terms[i];
    }
    this.sorter.sort((a, b) => {
      if (TermOrder.additiveCompare(a, b)) return -1;
      if (TermOrder.additiveCompare(b, a)) return 1;
      return 0;
    });
  }

  /** Get the sorted list of references */
  getSort(): AdditiveEdge[] { return this.sorter; }
}

// ---------------------------------------------------------------------------
// AddExpression
// ---------------------------------------------------------------------------

/**
 * Class for lightweight matching of two additive expressions.
 *
 * Collect (up to 2) terms along with any constants and coefficients.
 * Determine if two expressions are equivalent.
 */
export class AddExpression {
  /** Collected constants in the expression */
  private constval: uintb = 0n;
  /** Number of terms */
  private numTerms: int4 = 0;
  /** Terms making up the expression (max 2) */
  private terms: AddExpressionTerm[] = [
    new AddExpressionTerm(null, 0n),
    new AddExpressionTerm(null, 0n),
  ];

  /** Add a term to the expression */
  private add(vn: Varnode, coeff: uintb): void {
    if (this.numTerms < 2) {
      this.terms[this.numTerms].set(vn, coeff);
      this.numTerms++;
    }
  }

  /**
   * Gather terms in the expression from a root point.
   *
   * Recursively collect terms, up to the given depth. INT_ADD either contributes to the
   * constant sum, or it is recursively walked. Term coefficients are collected from
   * INT_MULT with a constant.
   */
  private gather(vn: Varnode, coeff: uintb, depth: int4): void {
    if (vn.isConstant()) {
      this.constval = this.constval + coeff * vn.getOffset();
      this.constval &= calc_mask(vn.getSize());
      return;
    }
    if (vn.isWritten()) {
      const op: PcodeOp = vn.getDef();
      if (op.code() === OpCode.CPUI_INT_ADD) {
        if (!op.getIn(1)!.isConstant())
          depth -= 1;
        if (depth >= 0) {
          this.gather(op.getIn(0), coeff, depth);
          this.gather(op.getIn(1), coeff, depth);
          return;
        }
      } else if (op.code() === OpCode.CPUI_INT_MULT) {
        if (op.getIn(1)!.isConstant()) {
          coeff = coeff * op.getIn(1)!.getOffset();
          coeff &= calc_mask(vn.getSize());
          this.gather(op.getIn(0), coeff, depth);
          return;
        }
      }
    }
    this.add(vn, coeff);
  }

  /**
   * Walk expression given two roots being subtracted from one another.
   * Gather up to two non-constant additive terms.
   */
  gatherTwoTermsSubtract(a: Varnode, b: Varnode): void {
    const depth: int4 = (a.isConstant() || b.isConstant()) ? 1 : 0;
    this.gather(a, 1n, depth);
    this.gather(b, calc_mask(b.getSize()), depth);
  }

  /**
   * Walk expression given two roots being added to each other.
   * Gather up to two non-constant additive terms.
   */
  gatherTwoTermsAdd(a: Varnode, b: Varnode): void {
    const depth: int4 = (a.isConstant() || b.isConstant()) ? 1 : 0;
    this.gather(a, 1n, depth);
    this.gather(b, 1n, depth);
  }

  /**
   * Gather up to 2 terms given root Varnode.
   */
  gatherTwoTermsRoot(root: Varnode): void {
    this.gather(root, 1n, 1);
  }

  /**
   * Determine if 2 expressions are equivalent.
   *
   * The value true is returned if it can be proven that the expressions always produce
   * the same value.
   */
  isEquivalent(op2: AddExpression): boolean {
    if (this.constval !== op2.constval)
      return false;
    if (this.numTerms !== op2.numTerms) return false;
    if (this.numTerms === 1) {
      if (this.terms[0].isEquivalent(op2.terms[0]))
        return true;
    } else if (this.numTerms === 2) {
      if (this.terms[0].isEquivalent(op2.terms[0]) && this.terms[1].isEquivalent(op2.terms[1]))
        return true;
      if (this.terms[0].isEquivalent(op2.terms[1]) && this.terms[1].isEquivalent(op2.terms[0]))
        return true;
    }
    return false;
  }
}

/**
 * A term in the AddExpression.
 */
class AddExpressionTerm {
  /** The Varnode representing the term */
  private vn: Varnode | null;
  /** Multiplicative coefficient */
  private coeff: uintb;

  constructor(v: Varnode | null, c: uintb) {
    this.vn = v;
    this.coeff = c;
  }

  /** Set the term's Varnode and coefficient */
  set(v: Varnode, c: uintb): void {
    this.vn = v;
    this.coeff = c;
  }

  /**
   * Compare two terms for functional equivalence.
   *
   * The value true is returned if it can be proven that two terms add the same value
   * to their respective expressions.
   */
  isEquivalent(op2: AddExpressionTerm): boolean {
    if (this.coeff !== op2.coeff) return false;
    return functionalEquality(this.vn, op2.vn);
  }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/**
 * Perform basic comparison of two given Varnodes.
 *
 * Return
 *   - 0 if vn1 and vn2 must hold same value
 *   - -1 if they definitely don't hold same value
 *   - 1 if the same value depends on ops writing to vn1 and vn2
 */
function functionalEqualityLevel0(vn1: Varnode, vn2: Varnode): int4 {
  if (vn1 === vn2) return 0;
  if (vn1.getSize() !== vn2.getSize()) return -1;
  if (vn1.isConstant()) {
    if (vn2.isConstant()) {
      return (vn1.getOffset() === vn2.getOffset()) ? 0 : -1;
    }
    return -1;
  }
  if (vn1.isFree() || vn2.isFree()) return -1;
  return 1;
}

/**
 * Try to determine if vn1 and vn2 contain the same value.
 *
 * Return:
 *    - -1, if they do not, or if it can't be immediately verified
 *    -  0, if they do hold the same value
 *    - >0, if the result is contingent on additional varnode pairs having the same value
 *
 * In the last case, the varnode pairs are returned as [res1[i], res2[i]],
 * where the return value is the number of pairs.
 */
export function functionalEqualityLevel(vn1: Varnode, vn2: Varnode, res1: Varnode[], res2: Varnode[]): int4 {
  let testval: int4 = functionalEqualityLevel0(vn1, vn2);
  if (testval !== 1)
    return testval;
  if (!vn1.isWritten() || !vn2.isWritten()) {
    return -1;    // Did not find at least one level of match
  }
  const op1: PcodeOp = vn1.getDef();
  const op2: PcodeOp = vn2.getDef();
  const opc: OpCode = op1.code();

  if (opc !== op2.code()) return -1;

  let num: int4 = op1.numInput();
  if (num !== op2.numInput()) return -1;
  if (op1.isMarker()) return -1;
  if (op2.isCall()) return -1;
  if (opc === OpCode.CPUI_LOAD) {
    // FIXME: We assume two loads produce the same
    // result if the address is the same and the loads
    // occur in the same instruction
    if (!op1.getAddr().equals(op2.getAddr())) return -1;
  }
  if (num >= 3) {
    if (opc !== OpCode.CPUI_PTRADD) return -1;  // If this is a PTRADD
    if (op1.getIn(2)!.getOffset() !== op2.getIn(2)!.getOffset()) return -1;  // Make sure the elsize constant is equal
    num = 2;  // Otherwise treat as having 2 inputs
  }
  for (let i = 0; i < num; ++i) {
    res1[i] = op1.getIn(i);
    res2[i] = op2.getIn(i);
  }

  testval = functionalEqualityLevel0(res1[0], res2[0]);
  if (testval === 0) {      // A match locks in this comparison ordering
    if (num === 1) return 0;
    testval = functionalEqualityLevel0(res1[1], res2[1]);
    if (testval === 0) return 0;
    if (testval < 0) return -1;
    res1[0] = res1[1];    // Match is contingent on second pair
    res2[0] = res2[1];
    return 1;
  }
  if (num === 1) return testval;
  let testval2: int4 = functionalEqualityLevel0(res1[1], res2[1]);
  if (testval2 === 0) {    // A match locks in this comparison ordering
    return testval;
  }
  let unmatchsize: int4;
  if ((testval === 1) && (testval2 === 1))
    unmatchsize = 2;
  else
    unmatchsize = -1;

  if (!op1.isCommutative()) return unmatchsize;
  // unmatchsize must be 2 or -1 here on a commutative operator,
  // try flipping
  const comm1: int4 = functionalEqualityLevel0(res1[0], res2[1]);
  const comm2: int4 = functionalEqualityLevel0(res1[1], res2[0]);
  if ((comm1 === 0) && (comm2 === 0))
    return 0;
  if ((comm1 < 0) || (comm2 < 0))
    return unmatchsize;
  if (comm1 === 0) {     // AND (comm2==1)
    res1[0] = res1[1];   // Left over unmatch is res1[1] and res2[0]
    return 1;
  }
  if (comm2 === 0) {     // AND (comm1==1)
    res2[0] = res2[1];   // Left over unmatch is res1[0] and res2[1]
    return 1;
  }
  // If we reach here (comm1==1) AND (comm2==1)
  if (unmatchsize === 2)    // If the original ordering wasn't impossible
    return 2;               // Prefer the original ordering
  const tmpvn = res2[0];   // Otherwise swap the ordering
  res2[0] = res2[1];
  res2[1] = tmpvn;
  return 2;
}

/**
 * Determine if two Varnodes hold the same value.
 *
 * Only return true if it can be immediately determined they are equivalent.
 */
export function functionalEquality(vn1: Varnode, vn2: Varnode): boolean {
  const buf1: Varnode[] = [null, null];
  const buf2: Varnode[] = [null, null];
  return (functionalEqualityLevel(vn1, vn2, buf1, buf2) === 0);
}

/**
 * Return true if vn1 and vn2 are verifiably different values.
 *
 * This is actually a rather speculative test.
 */
export function functionalDifference(vn1: Varnode, vn2: Varnode, depth: int4): boolean {
  if (vn1 === vn2) return false;
  if ((!vn1.isWritten()) || (!vn2.isWritten())) {
    if (vn1.isConstant() && vn2.isConstant())
      return !(vn1.getAddr().equals(vn2.getAddr()));
    if (vn1.isInput() && vn2.isInput()) return false;  // Might be the same
    if (vn1.isFree() || vn2.isFree()) return false;    // Might be the same
    return true;
  }
  const op1: PcodeOp = vn1.getDef();
  const op2: PcodeOp = vn2.getDef();
  if (op1.code() !== op2.code()) return true;
  const num: int4 = op1.numInput();
  if (num !== op2.numInput()) return true;
  if (depth === 0) return true;  // Different as far as we can tell
  depth -= 1;
  for (let i = 0; i < num; ++i) {
    if (functionalDifference(op1.getIn(i), op2.getIn(i), depth))
      return true;
  }
  return false;
}
