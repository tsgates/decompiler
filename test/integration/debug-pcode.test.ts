import { describe, it } from 'vitest';
import * as fs from 'fs';

import '../../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../../src/console/libdecomp.js';
import { FunctionTestCollection } from '../../src/console/testfunction.js';
import { StringWriter } from '../../src/util/writer.js';
import { mainloop } from '../../src/console/ifacedecomp.js';

const TEST_NAME = process.env.TEST_NAME || 'modulo';
describe('Debug pcode', () => {
  it('dump pcode after decompile', { timeout: 30000 }, () => {
    startDecompilerLibrary();

    const consoleOut = new StringWriter();
    const tc = new FunctionTestCollection(consoleOut);

    const xmlContent = fs.readFileSync(
      `ghidra-src/Ghidra/Features/Decompiler/src/decompile/datatests/${TEST_NAME}.xml`, 'utf-8'
    );

    // Load, decompile, then print raw
    const modifiedXml = xmlContent.replace(
      /<script>[\s\S]*?<\/script>/,
      `<script>
  <com>lo fu remtest</com>
  <com>decompile</com>
  <com>print raw</com>
  <com>quit</com>
</script>`
    );

    fs.writeFileSync('/tmp/test-modified.xml', modifiedXml);
    tc.loadTest('/tmp/test-modified.xml');

    const con = (tc as any).console;
    const midBuf = new StringWriter();
    const bulkBuf = new StringWriter();
    const origOptr = con.optr;
    con.optr = midBuf;
    con.fileoptr = bulkBuf;
    mainloop(con);
    con.optr = origOptr;
    con.fileoptr = origOptr;

    const bulk = bulkBuf.toString();
    fs.writeFileSync('/tmp/test-raw-after-decompile.txt', bulk);

    // Search for the multiply and constant patterns
    const lines = bulk.split('\n');
    for (const line of lines) {
      if (line.includes('SEXT') || line.includes('ZEXT') || line.includes('INT_MULT') || line.includes('5555')) {
        console.log(line);
      }
    }
  });
});
