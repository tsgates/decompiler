import { XmlDecode } from '../src/core/marshal.js';
import * as fs from 'fs';

const content = fs.readFileSync('/opt/ghidra/Ghidra/Processors/x86/data/languages/x86.ldefs', 'utf-8');
console.log('File length:', content.length);
console.log('First 300 chars:', content.substring(0, 300));

try {
  const decoder = new XmlDecode(null);
  decoder.ingestStream(content);
  console.log('Ingested OK');

  // Try to peek at first element
  const subId = decoder.peekElement();
  console.log('First element ID:', subId);
} catch (e: any) {
  console.log('Error:', e.message || e.explain);
  console.log('Stack:', e.stack?.substring(0, 500));
}
