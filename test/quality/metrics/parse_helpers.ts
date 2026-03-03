/** Shared regex counting functions for source-fidelity metrics. */

/** Replace string literals with empty strings and char literals with spaces to avoid false positives. */
export function stripStrings(body: string): string {
  // Replace "..." with "" (non-greedy, handles escaped quotes)
  let result = body.replace(/"(?:[^"\\]|\\.)*"/g, '""');
  // Replace 'X' with ' ' (char literals, including escaped chars)
  result = result.replace(/'(?:[^'\\]|\\.)*'/g, "' '");
  return result;
}

export function countFor(body: string): number {
  return (stripStrings(body).match(/\bfor\s*\(/g) || []).length;
}

/** Count do-while loops: `do` followed by `{` or end-of-line. */
export function countDoWhile(body: string): number {
  return (stripStrings(body).match(/\bdo\s*[\{$]/gm) || []).length;
}

/** Count while loops, excluding do-while trailing `while`. */
export function countWhile(body: string): number {
  const stripped = stripStrings(body);
  const totalWhile = (stripped.match(/\bwhile\s*\(/g) || []).length;
  const doWhileCount = countDoWhile(body);
  return totalWhile - doWhileCount;
}

export function countIf(body: string): number {
  return (stripStrings(body).match(/\bif\s*\(/g) || []).length;
}

export function countElse(body: string): number {
  return (stripStrings(body).match(/\belse\b/g) || []).length;
}

export function countSwitch(body: string): number {
  return (stripStrings(body).match(/\bswitch\s*\(/g) || []).length;
}

export function countCase(body: string): number {
  return (stripStrings(body).match(/\bcase\s+/g) || []).length;
}

export function countGoto(body: string): number {
  return (stripStrings(body).match(/\bgoto\s+\w+/g) || []).length;
}

export function countReturn(body: string): number {
  return (stripStrings(body).match(/\breturn\b/g) || []).length;
}

export function countBreak(body: string): number {
  return (stripStrings(body).match(/\bbreak\s*;/g) || []).length;
}

export function countContinue(body: string): number {
  return (stripStrings(body).match(/\bcontinue\s*;/g) || []).length;
}

export function countIncrement(body: string): number {
  return (stripStrings(body).match(/\+\+/g) || []).length;
}

export function countDecrement(body: string): number {
  return (stripStrings(body).match(/--/g) || []).length;
}

/** Count compound assignments: +=, -=, *=, /=, %=, &=, |=, ^=, <<=, >>= */
export function countCompoundAssign(body: string): number {
  const stripped = stripStrings(body);
  const basic = (stripped.match(/[+\-*/%&|^]=(?!=)/g) || []).length;
  const shift = (stripped.match(/<<=|>>=/g) || []).length;
  return basic + shift;
}

export function countArraySubscript(body: string): number {
  // Count [ followed by non-empty content and ]
  return (stripStrings(body).match(/\w\s*\[/g) || []).length;
}

export function countArrow(body: string): number {
  return (stripStrings(body).match(/->/g) || []).length;
}

export function countTernary(body: string): number {
  // Match ? that is part of ternary (followed by something and :)
  // Exclude ?: which is part of type annotations
  const stripped = stripStrings(body);
  // Simple heuristic: count standalone ? not preceded by another ?
  return (stripped.match(/[^?]\s*\?[^?:]/g) || []).length;
}

/** Count casts given a set of known type names. Pattern: (typeName) or (typeName *) */
export function countCasts(body: string, typeNames: Set<string>): number {
  const stripped = stripStrings(body);
  let count = 0;
  // Match (type), (type *), (type **), (unsigned type), (const type *), etc.
  const re = /\(\s*((?:const\s+|unsigned\s+|signed\s+)?[\w]+(?:\s*\*)*)\s*\)/g;
  let m;
  while ((m = re.exec(stripped)) !== null) {
    const inner = m[1].replace(/\s*\*+$/, '').replace(/^(?:const|unsigned|signed)\s+/, '').trim();
    if (typeNames.has(inner)) {
      count++;
    }
  }
  return count;
}

/** Count statements: total semicolons minus 2 per for-loop (for-header semicolons). */
export function countStatements(body: string): number {
  const stripped = stripStrings(body);
  const semis = (stripped.match(/;/g) || []).length;
  const forCount = countFor(body);
  return semis - 2 * forCount;
}

/** Compute max nesting depth by tracking brace depth. The outermost function braces are depth 0. */
export function maxNestingDepth(body: string): number {
  const stripped = stripStrings(body);
  let depth = 0;
  let maxDepth = 0;
  for (const ch of stripped) {
    if (ch === '{') {
      depth++;
      if (depth > maxDepth) maxDepth = depth;
    } else if (ch === '}') {
      depth--;
    }
  }
  // Subtract 1 for the outer function braces
  return Math.max(0, maxDepth - 1);
}

/** Well-known C source types for cast detection. */
export const SOURCE_TYPES = new Set([
  'int', 'char', 'short', 'long', 'float', 'double', 'void',
  'unsigned', 'signed', 'size_t', 'ssize_t',
  'int8_t', 'int16_t', 'int32_t', 'int64_t',
  'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
  'uintptr_t', 'intptr_t', 'ptrdiff_t',
]);

/** Decompiler output types (standard Ghidra naming). */
export const OUTPUT_TYPES = new Set([
  'int1', 'int2', 'int4', 'int8',
  'uint1', 'uint2', 'uint4', 'uint8',
  'xunknown1', 'xunknown2', 'xunknown4', 'xunknown8',
  'float4', 'float8', 'float10',
  'bool', 'void', 'char', 'ulong', 'long', 'short', 'ushort',
  'undefined', 'undefined1', 'undefined2', 'undefined4', 'undefined8',
]);

/** Enhanced display types. */
export const ENHANCED_TYPES = new Set([
  'i8', 'i16', 'i32', 'i64',
  'u8', 'u16', 'u32', 'u64',
  'unk1', 'unk2', 'unk4', 'unk8',
  'f32', 'f64', 'f80',
  'bool', 'void', 'char',
]);
