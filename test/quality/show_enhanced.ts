/**
 * Show enhanced display output for a quality test XML file.
 * Usage: npx tsx test/quality/show_enhanced.ts <xml-file>
 */
import '../../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../../src/console/libdecomp.js';
import { FunctionTestCollection } from '../../src/console/testfunction.js';
import { StringWriter } from '../../src/util/writer.js';

const xmlFile = process.argv[2];
if (!xmlFile) {
  console.error('Usage: npx tsx test/quality/show_enhanced.ts <exported.xml>');
  process.exit(1);
}

startDecompilerLibrary();
const writer = new StringWriter();
const failures: string[] = [];
const tc = new FunctionTestCollection(writer);
tc.loadTest(xmlFile);

// Enable enhanced display (NULL, inplace ops, increment/decrement, signed negatives, etc.)
tc.applyEnhancedDisplay();

tc.runTests(failures);

if (failures.length > 0) {
  console.error("=== FAILURES ===");
  for (const f of failures) console.error("  " + f);
}

console.log(tc.getLastOutput());
