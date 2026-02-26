/**
 * Measure goto counts across all quality test binaries.
 * Reports normal vs enhanced mode goto counts.
 */
import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';
import * as fs from 'fs';
import * as path from 'path';

startDecompilerLibrary();

const cacheDir = 'test/quality/results/.cache';

// Find all exported.xml files, pick latest per binary name
const byName = new Map<string, string>();
for (const entry of fs.readdirSync(cacheDir)) {
  const xmlPath = path.join(cacheDir, entry, 'exported.xml');
  if (!fs.existsSync(xmlPath)) continue;
  const name = entry.replace(/_\d+$/, '');
  const existing = byName.get(name);
  if (!existing || entry > path.basename(path.dirname(existing))) {
    byName.set(name, xmlPath);
  }
}

const sorted = [...byName.entries()].sort((a, b) => a[0].localeCompare(b[0]));

function countGotos(xmlFile: string, enhanced: boolean): number {
  const w = new StringWriter();
  const tc = new FunctionTestCollection(w);
  tc.loadTest(xmlFile);
  if (enhanced) tc.applyEnhancedDisplay();
  tc.runTests([]);
  const out = tc.getLastOutput();
  return (out.match(/\bgoto\b/g) || []).length;
}

let totalNormal = 0, totalEnhanced = 0;
const rows: string[] = [];
let processed = 0;

for (const [name, xmlFile] of sorted) {
  try {
    const normal = countGotos(xmlFile, false);
    const enhanced = countGotos(xmlFile, true);
    if (normal > 0 || enhanced > 0) {
      const diff = normal - enhanced;
      rows.push(`  ${name.padEnd(35)} normal=${String(normal).padStart(2)}  enhanced=${String(enhanced).padStart(2)}  ${diff > 0 ? '(-' + diff + ')' : ''}`);
    }
    totalNormal += normal;
    totalEnhanced += enhanced;
    processed++;
    if (processed % 20 === 0) process.stderr.write(`  processed ${processed}/${sorted.length}\n`);
  } catch (e: any) {
    process.stderr.write(`SKIP ${name}: ${e.message?.substring(0, 80)}\n`);
  }
}

console.log(`Goto counts by binary (${processed} processed, showing only binaries with gotos):`);
for (const row of rows) console.log(row);
console.log('');
const pct = totalNormal > 0 ? ((totalNormal - totalEnhanced) / totalNormal * 100).toFixed(1) : '0';
console.log(`TOTAL: normal=${totalNormal}  enhanced=${totalEnhanced}  reduction=${totalNormal - totalEnhanced} (${pct}%)`);
