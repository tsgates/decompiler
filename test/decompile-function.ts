/**
 * Decompile a single function from an exported XML and print C output to stdout.
 *
 * Usage: npx tsx test/decompile-function.ts <exported.xml> <function-name>
 */
import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';

const args = process.argv.slice(2);
const enhance = args.includes('--enhance');
const positional = args.filter(a => a !== '--enhance');
const xmlFile = positional[0];
const funcName = positional[1];

if (!xmlFile || !funcName) {
  process.stderr.write('Usage: npx tsx test/decompile-function.ts [--enhance] <exported.xml> <function-name>\n');
  process.exit(1);
}

startDecompilerLibrary();

const writer = new StringWriter();
const failures: string[] = [];
const tc = new FunctionTestCollection(writer);
tc.loadTest(xmlFile);
if (enhance) {
  tc.applyEnhancedDisplay();
}
tc.runTests(failures);
const fullOutput = tc.getLastOutput();

if (!fullOutput) {
  process.stderr.write(`No decompiler output produced\n`);
  process.exit(1);
}

// Split output into per-function blocks and find the requested one
// Functions start with: <return-type> <name>(
const lines = fullOutput.split('\n');
const functions: Map<string, string[]> = new Map();
let currentName: string | null = null;
let currentLines: string[] = [];

for (const line of lines) {
  // Match function signature: "type funcname(" at start of line
  const m = line.match(/^\S+\s+(\S+?)\s*\(/);
  if (m) {
    // Save previous function
    if (currentName !== null) {
      functions.set(currentName, currentLines);
    }
    currentName = m[1];
    currentLines = [line];
  } else if (currentName !== null) {
    currentLines.push(line);
  }
}
if (currentName !== null) {
  functions.set(currentName, currentLines);
}

const funcLines = functions.get(funcName);
if (funcLines) {
  process.stdout.write(funcLines.join('\n').trimEnd() + '\n');
} else {
  // Try partial match
  const matches = [...functions.keys()].filter(k => k.includes(funcName));
  if (matches.length === 1) {
    const fl = functions.get(matches[0])!;
    process.stdout.write(fl.join('\n').trimEnd() + '\n');
  } else if (matches.length > 1) {
    process.stderr.write(`Function '${funcName}' not found. Multiple partial matches:\n`);
    for (const m of matches) process.stderr.write(`  ${m}\n`);
    process.exit(1);
  } else {
    process.stderr.write(`Function '${funcName}' not found. Available functions:\n`);
    for (const name of functions.keys()) process.stderr.write(`  ${name}\n`);
    process.exit(1);
  }
}
