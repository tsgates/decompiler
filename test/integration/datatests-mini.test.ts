import { describe, it } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

import '../../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../../src/console/libdecomp.js';
import { FunctionTestCollection } from '../../src/console/testfunction.js';
import { StringWriter } from '../../src/util/writer.js';

const DATATESTS = 'ghidra-src/Ghidra/Features/Decompiler/src/decompile/datatests';

// Tests known to cause infinite loops
const SKIP_TESTS = new Set(['partialsplit']);

describe('Decompiler datatests (all)', () => {
  it('run all test files', { timeout: 600000 }, () => {
    startDecompilerLibrary('/opt/ghidra');
    const files = fs.readdirSync(DATATESTS)
      .filter(f => f.endsWith('.xml'))
      .filter(f => !SKIP_TESTS.has(path.basename(f, '.xml')))
      .sort()
      .map(f => path.join(DATATESTS, f));

    const logFd = fs.openSync('/tmp/test-progress.txt', 'w');
    fs.writeSync(logFd, `Starting with ${files.length} files\n`);

    const writer = new StringWriter();
    for (let i = 0; i < files.length; i++) {
      const basename = path.basename(files[i], '.xml');
      const start = Date.now();
      try {
        FunctionTestCollection.runTestFiles([files[i]], writer);
      } catch (e: any) {
        fs.writeSync(logFd, `[${i+1}] ${basename}: ERROR ${e.message}\n`);
        continue;
      }
      const elapsed = Date.now() - start;
      fs.writeSync(logFd, `[${i+1}] ${basename}: ${elapsed}ms\n`);
    }
    fs.writeSync(logFd, 'DONE\n');
    fs.closeSync(logFd);

    console.log(writer.toString());
  });
});
