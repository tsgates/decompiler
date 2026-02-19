import '../src/console/xml_arch.js';
import { SleighArchitecture } from '../src/console/sleigh_arch.js';
import { FormatDecode } from '../src/sleigh/slaformat.js';
import { SourceFileIndexer } from '../src/sleigh/sleighbase.js';
import * as fs from 'fs';

SleighArchitecture.scanForSleighDirectories('/opt/ghidra');

const slaFile = '/opt/ghidra/Ghidra/Processors/x86/data/languages/x86-64.sla';
const data = fs.readFileSync(slaFile);

const decoder = new FormatDecode(null as any);
decoder.ingestStreamFromBytes(data);

// Open root element (SLEIGH)
const el = (decoder as any).openElement();

// Skip root attributes
let attrib = (decoder as any).getNextAttributeId();
while (attrib !== 0) {
  attrib = (decoder as any).getNextAttributeId();
}

// SOURCEFILES
const indexer = new SourceFileIndexer();
indexer.decode(decoder);
console.log('SOURCEFILES OK');

// SPACES - skip with closeElementSkipping
const sp = (decoder as any).openElement();
(decoder as any).closeElementSkipping(sp);
console.log('SPACES skipped OK');

// SYMBOL_TABLE - try the real decode
// First, read symbol table header
const stEl = (decoder as any).openElement();
console.log('SYMBOL_TABLE id:', stEl);

const scopesize = Number((decoder as any).readSignedInteger());
const symbolsize = Number((decoder as any).readSignedInteger());
console.log('scopesize:', scopesize, 'symbolsize:', symbolsize);

// Read scopes
for (let i = 0; i < scopesize; i++) {
  const scEl = (decoder as any).openElement();
  (decoder as any).readUnsignedInteger(); // id
  (decoder as any).readUnsignedInteger(); // parent
  (decoder as any).closeElement(scEl);
}
console.log('Scopes OK');

// Read symbol headers
for (let i = 0; i < symbolsize; i++) {
  const hdrEl = (decoder as any).openElement();
  // Read header attributes
  let a = (decoder as any).getNextAttributeId();
  while (a !== 0) {
    a = (decoder as any).getNextAttributeId();
  }
  (decoder as any).closeElement(hdrEl);
}
console.log('Headers OK');

// Read symbol bodies
let bodyCount = 0;
try {
  while ((decoder as any).peekElement() !== 0) {
    const bodyEl = (decoder as any).openElement();
    // Read the id attribute
    const id = Number((decoder as any).readUnsignedInteger());

    // Check for child elements
    const peek = (decoder as any).peekElement();
    if (peek !== 0) {
      // This symbol has child elements - use closeElementSkipping
      // but first let's see what it is
      if (bodyCount < 5 || peek !== 0) {
        console.log(`  Body ${bodyCount}: id=${id}, elemId=${bodyEl}, has children (peek=${peek})`);
      }
    }

    // Skip all attributes and children
    let a2 = (decoder as any).getNextAttributeId();
    while (a2 !== 0) {
      a2 = (decoder as any).getNextAttributeId();
    }
    // Now check if there are unconsumed children
    const endByte = (decoder as any).buf[(decoder as any).endPos];
    const endHeaderMask = endByte & 0xc0;
    if (endHeaderMask === 0x40) {
      // ELEMENT_START at endPos - there are child elements
      console.log(`  Body ${bodyCount}: id=${id} has unconsumed children at endPos`);
      // Use closeElementSkipping
      (decoder as any).closeElementSkipping(bodyEl);
    } else if (endHeaderMask === 0x80) {
      // ELEMENT_END
      (decoder as any).closeElement(bodyEl);
    } else {
      console.log(`  Body ${bodyCount}: unexpected byte 0x${endByte.toString(16)} at endPos`);
      break;
    }
    bodyCount++;
    if (bodyCount % 5000 === 0) console.log(`  ... ${bodyCount} bodies`);
  }
  console.log('Bodies OK:', bodyCount);
  (decoder as any).closeElement(stEl);
  console.log('SYMBOL_TABLE closed OK!');
  (decoder as any).closeElement(el);
  console.log('ROOT closed OK!');
} catch(e: any) {
  console.error(`Error at body ${bodyCount}:`, e.message);
}
