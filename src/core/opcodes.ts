/**
 * @file opcodes.ts
 * @description All the individual p-code operations, translated from opcodes.hh/cc
 */

/**
 * The op-code defining a specific p-code operation (PcodeOp).
 *
 * These break up into categories:
 *   - Branching operations
 *   - Load and Store
 *   - Comparison operations
 *   - Arithmetic operations
 *   - Logical operations
 *   - Extension and truncation operations
 */
export const enum OpCode {
  CPUI_COPY = 1,           // Copy one operand to another
  CPUI_LOAD = 2,           // Load from a pointer into a specified address space
  CPUI_STORE = 3,          // Store at a pointer into a specified address space

  CPUI_BRANCH = 4,         // Always branch
  CPUI_CBRANCH = 5,        // Conditional branch
  CPUI_BRANCHIND = 6,      // Indirect branch (jumptable)

  CPUI_CALL = 7,           // Call to an absolute address
  CPUI_CALLIND = 8,        // Call through an indirect address
  CPUI_CALLOTHER = 9,      // User-defined operation
  CPUI_RETURN = 10,        // Return from subroutine

  // Integer/bit operations
  CPUI_INT_EQUAL = 11,     // Integer comparison, equality (==)
  CPUI_INT_NOTEQUAL = 12,  // Integer comparison, in-equality (!=)
  CPUI_INT_SLESS = 13,     // Integer comparison, signed less-than (<)
  CPUI_INT_SLESSEQUAL = 14, // Integer comparison, signed less-than-or-equal (<=)
  CPUI_INT_LESS = 15,      // Integer comparison, unsigned less-than (<)
  CPUI_INT_LESSEQUAL = 16, // Integer comparison, unsigned less-than-or-equal (<=)
  CPUI_INT_ZEXT = 17,      // Zero extension
  CPUI_INT_SEXT = 18,      // Sign extension
  CPUI_INT_ADD = 19,       // Addition, signed or unsigned (+)
  CPUI_INT_SUB = 20,       // Subtraction, signed or unsigned (-)
  CPUI_INT_CARRY = 21,     // Test for unsigned carry
  CPUI_INT_SCARRY = 22,    // Test for signed carry
  CPUI_INT_SBORROW = 23,   // Test for signed borrow
  CPUI_INT_2COMP = 24,     // Twos complement
  CPUI_INT_NEGATE = 25,    // Logical/bitwise negation (~)
  CPUI_INT_XOR = 26,       // Logical/bitwise exclusive-or (^)
  CPUI_INT_AND = 27,       // Logical/bitwise and (&)
  CPUI_INT_OR = 28,        // Logical/bitwise or (|)
  CPUI_INT_LEFT = 29,      // Left shift (<<)
  CPUI_INT_RIGHT = 30,     // Right shift, logical (>>)
  CPUI_INT_SRIGHT = 31,    // Right shift, arithmetic (>>)
  CPUI_INT_MULT = 32,      // Integer multiplication, signed and unsigned (*)
  CPUI_INT_DIV = 33,       // Integer division, unsigned (/)
  CPUI_INT_SDIV = 34,      // Integer division, signed (/)
  CPUI_INT_REM = 35,       // Remainder/modulo, unsigned (%)
  CPUI_INT_SREM = 36,      // Remainder/modulo, signed (%)

  CPUI_BOOL_NEGATE = 37,   // Boolean negate (!)
  CPUI_BOOL_XOR = 38,      // Boolean exclusive-or (^^)
  CPUI_BOOL_AND = 39,      // Boolean and (&&)
  CPUI_BOOL_OR = 40,       // Boolean or (||)

  // Floating point operations
  CPUI_FLOAT_EQUAL = 41,        // Floating-point comparison, equality (==)
  CPUI_FLOAT_NOTEQUAL = 42,     // Floating-point comparison, in-equality (!=)
  CPUI_FLOAT_LESS = 43,         // Floating-point comparison, less-than (<)
  CPUI_FLOAT_LESSEQUAL = 44,    // Floating-point comparison, less-than-or-equal (<=)
  // Slot 45 is currently unused
  CPUI_FLOAT_NAN = 46,          // Not-a-number test (NaN)

  CPUI_FLOAT_ADD = 47,          // Floating-point addition (+)
  CPUI_FLOAT_DIV = 48,          // Floating-point division (/)
  CPUI_FLOAT_MULT = 49,         // Floating-point multiplication (*)
  CPUI_FLOAT_SUB = 50,          // Floating-point subtraction (-)
  CPUI_FLOAT_NEG = 51,          // Floating-point negation (-)
  CPUI_FLOAT_ABS = 52,          // Floating-point absolute value (abs)
  CPUI_FLOAT_SQRT = 53,         // Floating-point square root (sqrt)

  CPUI_FLOAT_INT2FLOAT = 54,    // Convert an integer to a floating-point
  CPUI_FLOAT_FLOAT2FLOAT = 55,  // Convert between different floating-point sizes
  CPUI_FLOAT_TRUNC = 56,        // Round towards zero
  CPUI_FLOAT_CEIL = 57,         // Round towards +infinity
  CPUI_FLOAT_FLOOR = 58,        // Round towards -infinity
  CPUI_FLOAT_ROUND = 59,        // Round towards nearest

  // Internal opcodes for simplification
  // Data-flow operations
  CPUI_MULTIEQUAL = 60,   // Phi-node operator
  CPUI_INDIRECT = 61,     // Copy with an indirect effect
  CPUI_PIECE = 62,        // Concatenate
  CPUI_SUBPIECE = 63,     // Truncate

  CPUI_CAST = 64,         // Cast from one data-type to another
  CPUI_PTRADD = 65,       // Index into an array ([])
  CPUI_PTRSUB = 66,       // Drill down to a sub-field (->)
  CPUI_SEGMENTOP = 67,    // Look-up a segmented address
  CPUI_CPOOLREF = 68,     // Recover a value from the constant pool
  CPUI_NEW = 69,          // Allocate a new object (new)
  CPUI_INSERT = 70,       // Insert a bit-range
  CPUI_EXTRACT = 71,      // Extract a bit-range
  CPUI_POPCOUNT = 72,     // Count the 1-bits
  CPUI_LZCOUNT = 73,      // Count the leading 0-bits

  CPUI_MAX = 74,          // Value indicating the end of the op-code values
}

/**
 * Names of operations associated with their opcode number.
 *
 * Some names have been replaced with special placeholder ops for the
 * SLEIGH compiler and interpreter:
 *   MULTIEQUAL = BUILD
 *   INDIRECT   = DELAY_SLOT
 *   PTRADD     = LABEL
 *   PTRSUB     = CROSSBUILD
 */
const opcode_name: string[] = [
  'BLANK', 'COPY', 'LOAD', 'STORE',
  'BRANCH', 'CBRANCH', 'BRANCHIND', 'CALL',
  'CALLIND', 'CALLOTHER', 'RETURN', 'INT_EQUAL',
  'INT_NOTEQUAL', 'INT_SLESS', 'INT_SLESSEQUAL', 'INT_LESS',
  'INT_LESSEQUAL', 'INT_ZEXT', 'INT_SEXT', 'INT_ADD',
  'INT_SUB', 'INT_CARRY', 'INT_SCARRY', 'INT_SBORROW',
  'INT_2COMP', 'INT_NEGATE', 'INT_XOR', 'INT_AND',
  'INT_OR', 'INT_LEFT', 'INT_RIGHT', 'INT_SRIGHT',
  'INT_MULT', 'INT_DIV', 'INT_SDIV', 'INT_REM',
  'INT_SREM', 'BOOL_NEGATE', 'BOOL_XOR', 'BOOL_AND',
  'BOOL_OR', 'FLOAT_EQUAL', 'FLOAT_NOTEQUAL', 'FLOAT_LESS',
  'FLOAT_LESSEQUAL', 'UNUSED1', 'FLOAT_NAN', 'FLOAT_ADD',
  'FLOAT_DIV', 'FLOAT_MULT', 'FLOAT_SUB', 'FLOAT_NEG',
  'FLOAT_ABS', 'FLOAT_SQRT', 'INT2FLOAT', 'FLOAT2FLOAT',
  'TRUNC', 'CEIL', 'FLOOR', 'ROUND',
  'BUILD', 'DELAY_SLOT', 'PIECE', 'SUBPIECE', 'CAST',
  'LABEL', 'CROSSBUILD', 'SEGMENTOP', 'CPOOLREF', 'NEW',
  'INSERT', 'EXTRACT', 'POPCOUNT', 'LZCOUNT',
];

/** Sorted indices for binary search of opcode names */
const opcode_indices: number[] = [
   0, 39, 37, 40, 38,  4,  6, 60,  7,  8,  9, 64,  5, 57,  1, 68, 66,
  61, 71, 55, 52, 47, 48, 41, 43, 44, 49, 46, 51, 42, 53, 50, 58, 70,
  54, 24, 19, 27, 21, 33, 11, 29, 15, 16, 32, 25, 12, 28, 35, 30,
  23, 22, 34, 18, 13, 14, 36, 31, 20, 26, 17, 65,  2, 73, 69, 62, 72, 10, 59,
  67,  3, 63, 56, 45,
];

/**
 * Convert an OpCode to the name as a string.
 */
export function get_opname(opc: OpCode): string {
  return opcode_name[opc];
}

/**
 * Convert a name string to the matching OpCode.
 * Returns 0 (BLANK) if the name isn't found.
 */
export function get_opcode(nm: string): OpCode {
  let min = 1; // Don't include BLANK
  let max = OpCode.CPUI_MAX - 1;

  while (min <= max) {
    const cur = (min + max) >> 1;
    const ind = opcode_indices[cur];
    if (opcode_name[ind] < nm) {
      min = cur + 1;
    } else if (opcode_name[ind] > nm) {
      max = cur - 1;
    } else {
      return ind as OpCode;
    }
  }
  return 0 as OpCode;
}

/**
 * Get the complementary OpCode for comparison operations.
 *
 * Every comparison operation has a complementary form that produces
 * the opposite output on the same inputs. Sets reorder to true if
 * the complementary operation involves reordering the input parameters.
 *
 * @returns [complementary OpCode, reorder flag] or [CPUI_MAX, false] if not a comparison
 */
export function get_booleanflip(opc: OpCode): { result: OpCode; reorder: boolean } {
  switch (opc) {
    case OpCode.CPUI_INT_EQUAL:
      return { result: OpCode.CPUI_INT_NOTEQUAL, reorder: false };
    case OpCode.CPUI_INT_NOTEQUAL:
      return { result: OpCode.CPUI_INT_EQUAL, reorder: false };
    case OpCode.CPUI_INT_SLESS:
      return { result: OpCode.CPUI_INT_SLESSEQUAL, reorder: true };
    case OpCode.CPUI_INT_SLESSEQUAL:
      return { result: OpCode.CPUI_INT_SLESS, reorder: true };
    case OpCode.CPUI_INT_LESS:
      return { result: OpCode.CPUI_INT_LESSEQUAL, reorder: true };
    case OpCode.CPUI_INT_LESSEQUAL:
      return { result: OpCode.CPUI_INT_LESS, reorder: true };
    case OpCode.CPUI_BOOL_NEGATE:
      return { result: OpCode.CPUI_COPY, reorder: false };
    case OpCode.CPUI_FLOAT_EQUAL:
      return { result: OpCode.CPUI_FLOAT_NOTEQUAL, reorder: false };
    case OpCode.CPUI_FLOAT_NOTEQUAL:
      return { result: OpCode.CPUI_FLOAT_EQUAL, reorder: false };
    case OpCode.CPUI_FLOAT_LESS:
      return { result: OpCode.CPUI_FLOAT_LESSEQUAL, reorder: true };
    case OpCode.CPUI_FLOAT_LESSEQUAL:
      return { result: OpCode.CPUI_FLOAT_LESS, reorder: true };
    default:
      return { result: OpCode.CPUI_MAX, reorder: false };
  }
}
