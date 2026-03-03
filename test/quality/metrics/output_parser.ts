/** Parse decompiled output into FunctionMetrics. */
import type { FunctionMetrics, FileMetrics } from './types.js';
import {
  countFor, countWhile, countDoWhile, countIf, countElse,
  countSwitch, countCase, countGoto, countReturn, countBreak, countContinue,
  countIncrement, countDecrement, countCompoundAssign, countArraySubscript,
  countArrow, countTernary, countCasts, countStatements, maxNestingDepth,
  stripStrings, OUTPUT_TYPES, ENHANCED_TYPES,
} from './parse_helpers.js';

/** Synthetic function names to skip. */
const SKIP_FUNCTIONS = new Set(['entry', '_entry', '_main']);

interface RawFunction {
  name: string;
  returnType: string;
  params: string;
  body: string;
}

/** Split decompiler output into per-function blocks. */
function splitFunctions(output: string): RawFunction[] {
  const lines = output.split('\n');
  const functions: RawFunction[] = [];

  let i = 0;
  while (i < lines.length) {
    const line = lines[i];

    // Function signature: starts at column 0, not blank, not a keyword
    if (line.length > 0 && /^\S/.test(line)) {
      let sigLine = line;

      // Handle blank line between signature and { (decompiler-specific)
      let next = i + 1;
      while (next < lines.length && lines[next].trim() === '') next++;

      // Check if the signature continues on next line (wrapped params)
      if (!line.includes('(') && next < lines.length && /^\s+\(/.test(lines[next])) {
        sigLine = line.trimEnd() + ' ' + lines[next].trimStart();
        next++;
        while (next < lines.length && lines[next].trim() === '') next++;
      }

      // Must have opening brace
      if (next < lines.length && lines[next].trim() === '{') {
        const sigMatch = sigLine.match(/^([\w\s\*]+?)\s+(\*?\w+)\s*\(([^)]*)\)/);
        if (sigMatch) {
          const returnType = sigMatch[1].trim();
          const name = sigMatch[2].replace(/^\*/, '');
          const params = sigMatch[3].trim();

          // Collect body
          let braceDepth = 1; // for the opening {
          let j = next + 1;
          const bodyLines: string[] = [];
          while (j < lines.length && braceDepth > 0) {
            bodyLines.push(lines[j]);
            for (const ch of lines[j]) {
              if (ch === '{') braceDepth++;
              if (ch === '}') braceDepth--;
            }
            j++;
          }

          if (!SKIP_FUNCTIONS.has(name)) {
            functions.push({ name, returnType, params, body: bodyLines.join('\n') });
          }
          i = j;
          continue;
        }
      }
    }
    i++;
  }

  return functions;
}

/** Parse decompiler output parameter list. */
function parseOutputParams(params: string): { count: number; types: string[] } {
  if (!params || params === 'void') return { count: 0, types: [] };

  const types: string[] = [];
  let depth = 0;
  let current = '';
  for (const ch of params) {
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (ch === ',' && depth === 0) {
      types.push(extractType(current.trim()));
      current = '';
    } else {
      current += ch;
    }
  }
  if (current.trim()) {
    types.push(extractType(current.trim()));
  }
  return { count: types.length, types };
}

function extractType(param: string): string {
  const parts = param.replace(/\s+/g, ' ').trim().split(' ');
  if (parts.length === 1) return parts[0];
  return parts.slice(0, -1).join(' ');
}

/** Count variable declarations in decompiler output body. */
function countVariableDecls(body: string, typeNames: Set<string>): number {
  const lines = body.split('\n');
  let count = 0;
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.endsWith(';')) continue;
    if (!/^\s/.test(line)) continue;

    // Decompiler variables: type name; or type *name;
    const parts = trimmed.replace(';', '').trim().split(/\s+/);
    if (parts.length >= 2) {
      const typePart = parts[0].replace(/\*+$/, '');
      if (typeNames.has(typePart)) {
        // Check it's a declaration (no operators)
        if (!/[=+\-*\/%<>!&|^(]/.test(trimmed.slice(typePart.length).replace(/[\s\*]*\w+;?$/, ''))) {
          count++;
        }
      }
    }
  }
  return count;
}

/** Build FunctionMetrics from a raw decompiler function. */
function buildMetrics(fn: RawFunction, enhanced: boolean): FunctionMetrics {
  const { count: paramCount, types: paramTypes } = parseOutputParams(fn.params);
  const typeNames = enhanced ? ENHANCED_TYPES : OUTPUT_TYPES;
  return {
    name: fn.name,
    returnType: fn.returnType,
    paramCount,
    paramTypes,
    forCount: countFor(fn.body),
    whileCount: countWhile(fn.body),
    doWhileCount: countDoWhile(fn.body),
    ifCount: countIf(fn.body),
    elseCount: countElse(fn.body),
    switchCount: countSwitch(fn.body),
    caseCount: countCase(fn.body),
    gotoCount: countGoto(fn.body),
    returnCount: countReturn(fn.body),
    breakCount: countBreak(fn.body),
    continueCount: countContinue(fn.body),
    variableDeclCount: countVariableDecls(fn.body, typeNames),
    maxNestingDepth: maxNestingDepth(fn.body),
    lineCount: fn.body.split('\n').filter(l => l.trim().length > 0).length,
    statementCount: countStatements(fn.body),
    incrementCount: countIncrement(fn.body),
    decrementCount: countDecrement(fn.body),
    compoundAssignCount: countCompoundAssign(fn.body),
    arraySubscriptCount: countArraySubscript(fn.body),
    arrowCount: countArrow(fn.body),
    ternaryCount: countTernary(fn.body),
    castCount: countCasts(fn.body, typeNames),
  };
}

/** Parse decompiler output text into FileMetrics. */
export function parseOutput(output: string, enhanced: boolean = false): FileMetrics {
  const rawFunctions = splitFunctions(output);
  return {
    filename: '<output>',
    functions: rawFunctions.map(fn => buildMetrics(fn, enhanced)),
  };
}

/** Parse a decompiler output file into FileMetrics. */
export function parseOutputFile(filePath: string, enhanced: boolean = false): FileMetrics {
  const { readFileSync } = require('fs');
  const output = readFileSync(filePath, 'utf8');
  const result = parseOutput(output, enhanced);
  result.filename = filePath;
  return result;
}
