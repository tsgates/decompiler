/**
 * @file run-datatests.ts
 * @description CLI runner for decompiler data-driven tests.
 *
 * Usage:
 *   npx tsx test/run-datatests.ts [sleighpath] [datatestpath]
 *
 * Defaults:
 *   sleighpath   = /opt/ghidra
 *   datatestpath = ghidra-src/Ghidra/Features/Decompiler/src/decompile/datatests
 */

import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __filename_local = fileURLToPath(import.meta.url);
const __dirname_local = path.dirname(__filename_local);

// Ensure xml_arch module is loaded so the XmlArchitectureCapability singleton
// gets registered before we call startDecompilerLibrary.
import '../src/console/xml_arch.js';

import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { ConsoleWriter } from '../src/util/writer.js';

const sleighpath = process.argv[2] || '/opt/ghidra';
const datatestpath = process.argv[3] || path.join(
  __dirname_local, '..', 'ghidra-src', 'Ghidra', 'Features', 'Decompiler', 'src', 'decompile', 'datatests'
);

// Known-hanging test files to skip
const SKIP_FILES = new Set(process.env.SKIP_TESTS?.split(',') || []);

// Initialize the decompiler library (scans for .ldefs, registers capabilities)
startDecompilerLibrary(sleighpath);

// Gather all .xml test files, filtering out skipped ones
const allFiles = fs.readdirSync(datatestpath)
  .filter(f => f.endsWith('.xml'))
  .filter(f => !SKIP_FILES.has(path.basename(f, '.xml')))
  .sort()
  .map(f => path.join(datatestpath, f));

// Run all tests
const writer = new ConsoleWriter();
const failures = FunctionTestCollection.runTestFiles(allFiles, writer);

process.exit(failures > 0 ? 1 : 0);
