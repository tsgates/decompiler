import '../src/console/xml_arch.js';
import { SleighArchitecture } from '../src/console/sleigh_arch.js';
import { FormatDecode, SLA_ELEM_SOURCEFILES, SLA_ELEM_SOURCEFILE, SLA_ATTRIB_NAME, SLA_ATTRIB_INDEX } from '../src/sleigh/slaformat.js';
// PackedFormat is not exported from marshal.ts
import * as fs from 'fs';

SleighArchitecture.scanForSleighDirectories('/opt/ghidra');

const slaFile = '/opt/ghidra/Ghidra/Processors/x86/data/languages/x86-64.sla';
const data = fs.readFileSync(slaFile);

const decoder = new FormatDecode(null as any);
decoder.ingestStreamFromBytes(data);

// Open root element (SLA_ELEM_SLEIGH)
(decoder as any).openElement();

// Skip attributes to get to child elements
(decoder as any).rewindAttributes();

// Read root element attributes
let attrib = (decoder as any).getNextAttributeId();
while (attrib !== 0) {
  // Skip each attribute value
  const buf = (decoder as any).buf as Uint8Array;
  const curPos = (decoder as any).curPos;
  const typeByte = buf[curPos];
  const typeCode = typeByte >> 4;
  console.log(`  Root attrib ${attrib}: typeByte=0x${typeByte.toString(16)}, typeCode=${typeCode}`);
  // Read and skip the value
  if (typeCode === 1 || typeCode === 2) { // signed int
    const val = (decoder as any).readSignedInteger();
    console.log(`    Signed int: ${val}`);
  } else if (typeCode === 3) { // unsigned int
    const val = (decoder as any).readUnsignedInteger();
    console.log(`    Unsigned int: ${val}`);
  } else if (typeCode === 0) { // boolean
    const val = (decoder as any).readBool();
    console.log(`    Bool: ${val}`);
  } else if (typeCode === 5) { // string
    const val = (decoder as any).readString();
    console.log(`    String: ${val.substring(0, 50)}`);
  } else {
    console.log('    (unknown type, cannot skip properly)');
    break;
  }
  attrib = (decoder as any).getNextAttributeId();
}

// Now try to open SLA_ELEM_SOURCEFILES
const srcFilesId = (decoder as any).openElement();
console.log('\nChild element ID:', srcFilesId, '(expected', SLA_ELEM_SOURCEFILES.getId(), ')');

// Try to open first SLA_ELEM_SOURCEFILE
const peekId = (decoder as any).peekElement();
console.log('Peeked child:', peekId, '(expected', SLA_ELEM_SOURCEFILE.getId(), ')');

if (peekId === SLA_ELEM_SOURCEFILE.getId()) {
  const srcFileId = (decoder as any).openElement();
  console.log('Opened sourcefile, id:', srcFileId);

  // Check what attributes this element has
  const buf = (decoder as any).buf as Uint8Array;
  const startPos = (decoder as any).startPos;
  const endPos = (decoder as any).endPos;
  console.log('Attributes bytes (startPos to endPos):',
    Array.from(buf.subarray(startPos, Math.min(startPos + 30, endPos))).map(b => '0x' + b.toString(16).padStart(2, '0')));

  // Try reading first attribute
  attrib = (decoder as any).getNextAttributeId();
  console.log('First attrib id:', attrib, '(expected NAME=', SLA_ATTRIB_NAME.getId(), ')');

  // Check the type byte at current position
  if (attrib !== 0) {
    const curPos = (decoder as any).curPos;
    const typeByte = buf[curPos];
    console.log('Type byte at curPos:', '0x' + typeByte.toString(16), 'typeCode:', typeByte >> 4);
  }
}
