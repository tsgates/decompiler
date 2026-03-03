/**
 * Decompile a single function from an exported XML and print C output to stdout.
 *
 * Usage: npx tsx test/decompile-function.ts [--enhance] <exported.xml> <function-name>
 *
 * Filters the XML to only include the requested function's <script> block,
 * so large binaries (thousands of functions) don't exhaust the JS heap.
 */
import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';
import { readFileSync } from 'fs';

const args = process.argv.slice(2);
const enhance = args.includes('--enhance');
const positional = args.filter(a => a !== '--enhance');
const xmlFile = positional[0];
const funcName = positional[1];

if (!xmlFile || !funcName) {
  process.stderr.write('Usage: npx tsx test/decompile-function.ts [--enhance] <exported.xml> <function-name>\n');
  process.exit(1);
}

/**
 * Filter XML to only keep <script> and <stringmatch> blocks for the target function.
 * This avoids decompiling all functions in large binaries.
 */
function filterXmlForFunction(xmlPath: string, targetFunc: string): string {
  const xml = readFileSync(xmlPath, 'utf8');

  // Extract <binaryimage>...</binaryimage> (includes bytechunks + symbols)
  const binaryImageMatch = xml.match(/<binaryimage[\s\S]*?<\/binaryimage>/);
  if (!binaryImageMatch) {
    process.stderr.write('Error: No <binaryimage> found in XML\n');
    process.exit(1);
  }

  // Find the <script> block that loads our function: <com>lo fu <funcName></com>
  const scriptRegex = new RegExp(
    `<script>\\s*<com>lo fu ${escapeRegex(targetFunc)}</com>[\\s\\S]*?</script>`,
    'g'
  );
  const scriptMatch = xml.match(scriptRegex);
  if (!scriptMatch) {
    process.stderr.write(`Error: No <script> block found for function '${targetFunc}'\n`);
    // List available functions
    const allFuncs = [...xml.matchAll(/<com>lo fu (\S+)<\/com>/g)].map(m => m[1]);
    if (allFuncs.length > 0) {
      // Try partial match
      const partial = allFuncs.filter(f => f.includes(targetFunc));
      if (partial.length > 0 && partial.length <= 20) {
        process.stderr.write(`Partial matches:\n`);
        for (const f of partial) process.stderr.write(`  ${f}\n`);
      } else {
        process.stderr.write(`Available functions (${allFuncs.length} total):\n`);
        for (const f of allFuncs.slice(0, 30)) process.stderr.write(`  ${f}\n`);
        if (allFuncs.length > 30) process.stderr.write(`  ... and ${allFuncs.length - 30} more\n`);
      }
    }
    process.exit(1);
  }

  // Find matching <stringmatch> for this function (optional)
  const matchRegex = new RegExp(
    `<stringmatch\\s+name="${escapeRegex(targetFunc)}[^"]*"[^>]*>[\\s\\S]*?</stringmatch>`,
    'g'
  );
  const stringMatches = xml.match(matchRegex) || [];

  // Reconstruct minimal XML
  return [
    '<decompilertest>',
    binaryImageMatch[0],
    scriptMatch[0],
    ...stringMatches,
    '</decompilertest>',
  ].join('\n');
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

startDecompilerLibrary();

// Filter XML to single function — critical for large binaries
const filteredXml = filterXmlForFunction(xmlFile, funcName);

const writer = new StringWriter();
const failures: string[] = [];
const tc = new FunctionTestCollection(writer);
tc.loadTestFromString(filteredXml, funcName);
if (enhance) {
  tc.applyEnhancedDisplay();
}
tc.runTests(failures);
const fullOutput = tc.getLastOutput();

if (!fullOutput) {
  process.stderr.write(`No decompiler output produced\n`);
  if (failures.length > 0) {
    process.stderr.write(`Failures:\n`);
    for (const f of failures) process.stderr.write(`  ${f}\n`);
  }
  process.exit(1);
}

process.stdout.write(fullOutput.trimEnd() + '\n');
