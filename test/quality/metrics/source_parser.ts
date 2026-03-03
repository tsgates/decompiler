/** Parse original C source files into FunctionMetrics. */
import { readFileSync } from 'fs';
import type { FunctionMetrics, FileMetrics } from './types.js';
import {
  countFor, countWhile, countDoWhile, countIf, countElse,
  countSwitch, countCase, countGoto, countReturn, countBreak, countContinue,
  countIncrement, countDecrement, countCompoundAssign, countArraySubscript,
  countArrow, countTernary, countCasts, countStatements, maxNestingDepth,
  stripStrings, SOURCE_TYPES,
} from './parse_helpers.js';

/** Strip C comments (block and line), preprocessor directives. */
function stripCommentsAndPreprocessor(src: string): string {
  // Strip block comments
  let result = src.replace(/\/\*[\s\S]*?\*\//g, '');
  // Strip line comments
  result = result.replace(/\/\/.*$/gm, '');
  // Strip preprocessor lines
  result = result.replace(/^\s*#\s*(include|define|ifdef|ifndef|endif|if|elif|else|pragma|undef).*$/gm, '');
  return result;
}

/** Strip typedef/struct/enum/union blocks and forward declarations. */
function stripTypeDefinitions(src: string): string {
  const lines = src.split('\n');
  const result: string[] = [];
  let braceDepth = 0;
  let inTypedef = false;

  for (const line of lines) {
    const trimmed = line.trim();

    // Detect start of typedef/struct/enum/union block
    if (braceDepth === 0 && !inTypedef) {
      if (/^(?:typedef\s+)?(?:struct|enum|union)\b/.test(trimmed)) {
        inTypedef = true;
        for (const ch of line) {
          if (ch === '{') braceDepth++;
          if (ch === '}') braceDepth--;
        }
        // Single-line typedef (e.g., typedef int (*cmp)(int, int);)
        if (braceDepth === 0 && trimmed.endsWith(';')) {
          inTypedef = false;
        }
        continue;
      }

      // Strip forward declarations: lines with ) followed by ; and no {
      if (/\)\s*;/.test(trimmed) && !trimmed.includes('{') && !trimmed.includes('=')) {
        // But only if it looks like a function declaration (has return type)
        if (/^[\w\s\*]+\s+\*?\w+\s*\(/.test(trimmed)) {
          continue;
        }
      }
    }

    if (inTypedef) {
      for (const ch of line) {
        if (ch === '{') braceDepth++;
        if (ch === '}') braceDepth--;
      }
      if (braceDepth === 0) {
        inTypedef = false;
      }
      continue;
    }

    result.push(line);
  }

  return result.join('\n');
}

interface RawFunction {
  name: string;
  returnType: string;
  params: string;
  body: string;
}

/** Try to parse a function signature from a line, handling nested parens in params. */
function parseFunctionSignature(line: string): { returnType: string; name: string; params: string } | null {
  // Must start at column 0 with a word char
  if (!/^\w/.test(line)) return null;

  // Find the function name and opening paren: "retType funcName("
  const prefixMatch = line.match(/^([\w\s\*]+?)\s+(\*?\w+)\s*\(/);
  if (!prefixMatch) return null;

  const returnType = prefixMatch[1].trim();
  const name = prefixMatch[2].replace(/^\*/, '');

  // Skip keywords
  if (['if', 'while', 'for', 'switch', 'return', 'else'].includes(name)) return null;

  // Extract params by tracking paren depth from the opening paren
  const startIdx = prefixMatch[0].length - 1; // index of '('
  let depth = 1;
  let idx = startIdx + 1;
  while (idx < line.length && depth > 0) {
    if (line[idx] === '(') depth++;
    if (line[idx] === ')') depth--;
    idx++;
  }
  if (depth !== 0) return null;

  const params = line.slice(startIdx + 1, idx - 1).trim();
  return { returnType, name, params };
}

/** Extract top-level function definitions with their bodies. */
function extractFunctions(src: string): RawFunction[] {
  const lines = src.split('\n');
  const functions: RawFunction[] = [];

  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (line.trim().length === 0) { i++; continue; }

    const sig = parseFunctionSignature(line);
    if (sig) {
      // Find the opening brace
      let bodyStart = i;
      let braceDepth = 0;
      let foundBrace = false;
      for (const ch of line) {
        if (ch === '{') { braceDepth++; foundBrace = true; }
        if (ch === '}') braceDepth--;
      }

      if (!foundBrace) {
        // Opening brace on next line
        bodyStart = i + 1;
        while (bodyStart < lines.length && lines[bodyStart].trim() === '') bodyStart++;
        if (bodyStart < lines.length && lines[bodyStart].trim().startsWith('{')) {
          for (const ch of lines[bodyStart]) {
            if (ch === '{') { braceDepth++; foundBrace = true; }
            if (ch === '}') braceDepth--;
          }
        }
      }

      if (!foundBrace) {
        i++;
        continue;
      }

      // Collect body lines until matching }
      const bodyLines: string[] = [];
      let j: number;
      if (line.includes('{') && braceDepth > 0) {
        j = i + 1;
      } else {
        j = bodyStart + 1;
      }

      while (j < lines.length && braceDepth > 0) {
        bodyLines.push(lines[j]);
        for (const ch of lines[j]) {
          if (ch === '{') braceDepth++;
          if (ch === '}') braceDepth--;
        }
        j++;
      }

      functions.push({ name: sig.name, returnType: sig.returnType, params: sig.params, body: bodyLines.join('\n') });
      i = j;
      continue;
    }
    i++;
  }

  return functions;
}

/** Parse parameter list, handling function pointer params. */
function parseParams(params: string): { count: number; types: string[] } {
  if (!params || params === 'void') return { count: 0, types: [] };

  const types: string[] = [];
  let depth = 0;
  let current = '';

  for (const ch of params) {
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (ch === ',' && depth === 0) {
      types.push(extractParamType(current.trim()));
      current = '';
    } else {
      current += ch;
    }
  }
  if (current.trim()) {
    types.push(extractParamType(current.trim()));
  }

  return { count: types.length, types };
}

/** Extract the type part from a parameter declaration. */
function extractParamType(param: string): string {
  // Handle function pointer: int (*fn)(int, int)
  const fpMatch = param.match(/^(.+?)\s*\(\s*\*/);
  if (fpMatch) return fpMatch[1].trim() + ' (*)';

  // Handle array: int arr[]
  const arrMatch = param.match(/^(.+?)\s+\*?\w+\s*\[/);
  if (arrMatch) return arrMatch[1].trim() + '[]';

  // Normal: type name
  const parts = param.replace(/\s+/g, ' ').trim().split(' ');
  if (parts.length === 1) return parts[0];
  // Everything except the last token is the type
  return parts.slice(0, -1).join(' ');
}

/** Count variable declarations in a function body. */
function countVariableDecls(body: string): number {
  const stripped = stripStrings(body);
  const lines = stripped.split('\n');
  let count = 0;
  for (const line of lines) {
    const trimmed = line.trim();
    // Variable declaration: indented, starts with a type, has name, ends with ;
    if (/^\s/.test(line) && trimmed.endsWith(';')) {
      // Looks like: type name = ...; or type name;
      if (/^(?:const\s+)?(?:unsigned\s+|signed\s+)?(?:int|char|short|long|float|double|void|size_t|uint\d+_t|int\d+_t|bool|struct\s+\w+|enum\s+\w+)\s*[\*\s]\s*\w+/.test(trimmed)) {
        // Count comma-separated declarations
        const beforeEq = trimmed.split('=')[0];
        const commas = (beforeEq.match(/,/g) || []).length;
        count += 1 + commas;
      }
    }
    // Also handle for-loop declarations: for (int i = 0; ...)
    const forDeclMatch = trimmed.match(/\bfor\s*\(\s*(?:unsigned\s+|signed\s+)?(?:int|char|short|long|float|double|size_t|uint\d+_t|int\d+_t)\s/);
    if (forDeclMatch) {
      count++;
    }
  }
  return count;
}

/** Build FunctionMetrics from a raw function. */
function buildMetrics(fn: RawFunction): FunctionMetrics {
  const { count: paramCount, types: paramTypes } = parseParams(fn.params);
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
    variableDeclCount: countVariableDecls(fn.body),
    maxNestingDepth: maxNestingDepth(fn.body),
    lineCount: fn.body.split('\n').filter(l => l.trim().length > 0).length,
    statementCount: countStatements(fn.body),
    incrementCount: countIncrement(fn.body),
    decrementCount: countDecrement(fn.body),
    compoundAssignCount: countCompoundAssign(fn.body),
    arraySubscriptCount: countArraySubscript(fn.body),
    arrowCount: countArrow(fn.body),
    ternaryCount: countTernary(fn.body),
    castCount: countCasts(fn.body, SOURCE_TYPES),
  };
}

/** Parse a C source file into FileMetrics. */
export function parseSourceFile(filePath: string): FileMetrics {
  const src = readFileSync(filePath, 'utf8');
  return parseSource(src, filePath);
}

/** Parse C source text into FileMetrics. */
export function parseSource(src: string, filename: string = '<input>'): FileMetrics {
  let cleaned = stripCommentsAndPreprocessor(src);
  cleaned = stripTypeDefinitions(cleaned);
  const rawFunctions = extractFunctions(cleaned);
  return {
    filename,
    functions: rawFunctions.map(buildMetrics),
  };
}
