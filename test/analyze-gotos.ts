/**
 * Analyze goto patterns in the block tree to understand conversion opportunities.
 * Usage: npx tsx test/analyze-gotos.ts <xml>
 */
import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';
import { block_type, block_flags } from '../src/decompiler/block.js';

startDecompilerLibrary();

const xmlFile = process.argv[2];
if (!xmlFile) { console.log('Usage: npx tsx test/analyze-gotos.ts <xml>'); process.exit(1); }

const w = new StringWriter();
const tc = new FunctionTestCollection(w);
tc.loadTest(xmlFile);
const f: string[] = [];
tc.runTests(f);

// Access internal state to get Funcdata
const dcp = (tc as any).dcp;
const conf = dcp.conf;

// Re-decompile each function to access block tree
// Actually we can't easily get Funcdata after runTests. Let's parse the output instead
// and correlate with what we know about the block tree.
const output = tc.getLastOutput();

// Parse gotos and their contexts
const lines = output.split('\n');
for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  const gotoMatch = line.match(/\bgoto\s+(\w+)/);
  if (gotoMatch) {
    const target = gotoMatch[1];
    // Find the target label
    let targetLine = -1;
    for (let j = 0; j < lines.length; j++) {
      if (lines[j].match(new RegExp(`^\\s*${target}:`))) {
        targetLine = j + 1;
        break;
      }
    }

    // Determine context: count indentation (nesting) of goto and target
    const gotoIndent = (line.match(/^(\s*)/) || [''])[0].length;
    const targetIndent = targetLine > 0 ? (lines[targetLine - 1].match(/^(\s*)/) || [''])[0].length : -1;

    // Walk backwards to find enclosing structures
    const enclosing: string[] = [];
    let depth = 0;
    for (let j = i - 1; j >= 0 && enclosing.length < 5; j--) {
      const l = lines[j];
      if (l.match(/\}\s*(while|$)/)) depth++;
      if (l.match(/\b(do|while|for|if|switch)\b.*\{/)) {
        if (depth > 0) depth--;
        else {
          const m = l.match(/\b(do|while|for|if|switch)\b/);
          if (m) enclosing.push(m[1]);
        }
      }
    }

    // Classify the goto
    let classification = 'unknown';
    if (targetIndent < gotoIndent) {
      classification = 'cross-scope-forward (exits nested scope)';
    } else if (targetIndent === gotoIndent) {
      classification = 'same-scope-forward';
    } else if (targetIndent > gotoIndent) {
      classification = 'cross-scope-into-deeper (enters nested scope)';
    }
    if (targetLine < i + 1 && targetLine > 0) {
      classification = 'backward-jump';
    }

    console.log(`Line ${i+1}: goto ${target}`);
    console.log(`  Goto indent: ${gotoIndent}, Target indent: ${targetIndent} (line ${targetLine})`);
    console.log(`  Classification: ${classification}`);
    console.log(`  Enclosing: ${enclosing.join(' < ')}`);
    console.log();
  }
}
