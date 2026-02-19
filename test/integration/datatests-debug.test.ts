import { describe, it } from 'vitest';
import * as path from 'path';
import * as fs from 'fs';

import '../../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../../src/console/libdecomp.js';
import { FunctionTestCollection } from '../../src/console/testfunction.js';
import { StringWriter } from '../../src/util/writer.js';
import { mainloop } from '../../src/console/ifacedecomp.js';

const DATATESTS = 'ghidra-src/Ghidra/Features/Decompiler/src/decompile/datatests';
const TEST_NAME = process.env.TEST_NAME || 'convert';

describe('Debug test', () => {
  it(TEST_NAME, { timeout: 30000 }, () => {
    startDecompilerLibrary('/opt/ghidra');

    const consoleOut = new StringWriter();
    const tc = new FunctionTestCollection(consoleOut);
    tc.loadTest(path.join(DATATESTS, `${TEST_NAME}.xml`));

    // Access internal console to capture bulk output
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
    const mid = midBuf.toString();

    fs.writeFileSync(`/tmp/test-bulk-${TEST_NAME}.txt`, bulk);
    fs.writeFileSync(`/tmp/test-mid-${TEST_NAME}.txt`, mid);

    console.log(`Bulk output (first 3000 chars):\n${bulk.substring(0, 3000)}`);
  });
});
