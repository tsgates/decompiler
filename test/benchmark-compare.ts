#!/usr/bin/env npx tsx
/**
 * Benchmark: compare TS vs C++ decompiler performance.
 *
 * Usage: npx tsx test/benchmark-compare.ts [--xml <file> <label>]... [binary...]
 *
 * Accepts raw binaries (auto-exported to XML) and/or pre-exported XML files.
 * Defaults to quality test binaries + system binaries if none specified.
 */
import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';
import { parseBinary, generateXml } from '../src/console/binary_to_xml.js';
import { readFileSync, writeFileSync, mkdirSync, existsSync, statSync, readdirSync } from 'fs';
import { execSync } from 'child_process';
import path from 'path';

const CPP_BIN = 'ghidra-src/Ghidra/Features/Decompiler/src/decompile/cpp/decomp_test_dbg';
const GHIDRA_HOME = process.env.SLEIGHHOME ||
  '/opt/homebrew/Caskroom/ghidra/11.4.2-20250826/ghidra_11.4.2_PUBLIC';

interface BenchInput {
  label: string;
  xmlFile: string;
  sizeKB: number;
}

interface BenchResult {
  label: string;
  sizeKB: number;
  funcCount: number;
  tsTimeSec: number;
  tsRssMB: number;
  cppTimeSec: number;
  cppRssMB: number;
  timeRatio: number;
  memRatio: number;
}

function formatSize(kb: number): string {
  if (kb < 1024) return `${kb}K`;
  return `${(kb / 1024).toFixed(1)}M`;
}

function padR(s: string, w: number): string {
  return s.length >= w ? s.slice(0, w) : s + ' '.repeat(w - s.length);
}
function padL(s: string, w: number): string {
  return s.length >= w ? s : ' '.repeat(w - s.length) + s;
}

/** Find cached XML for a quality test binary prefix. */
function findCachedXml(prefix: string): string | null {
  const cacheBase = 'test/quality/results/.cache';
  if (!existsSync(cacheBase)) return null;
  const dirs = readdirSync(cacheBase).filter(d => d.startsWith(prefix)).sort();
  if (dirs.length === 0) return null;
  const xmlPath = path.join(cacheBase, dirs[dirs.length - 1], 'exported.xml');
  return existsSync(xmlPath) ? xmlPath : null;
}

/** Export a binary to XML (cached). */
function exportBinary(binaryPath: string): string | null {
  const cacheDir = 'output/bench-cache';
  mkdirSync(cacheDir, { recursive: true });
  const realPath = binaryPath; // caller resolves symlinks
  const bname = path.basename(realPath);
  const stat = statSync(realPath);
  const xmlDir = path.join(cacheDir, `${bname}_${Math.floor(stat.mtimeMs / 1000)}`);
  const xmlFile = path.join(xmlDir, 'exported.xml');

  if (!existsSync(xmlFile)) {
    mkdirSync(xmlDir, { recursive: true });
    try {
      const buf = readFileSync(realPath);
      const parsed = parseBinary(buf as Buffer);
      const xml = generateXml(parsed);
      writeFileSync(xmlFile, xml);
    } catch (e: any) {
      process.stderr.write(`Export failed for ${binaryPath}: ${e.message}\n`);
      return null;
    }
  }
  return xmlFile;
}

/** Build default inputs from quality test cache + system/homebrew binaries. */
function buildDefaultInputs(): BenchInput[] {
  const inputs: BenchInput[] = [];

  // Quality test binaries (from cache) — various function counts
  const qualityTests = [
    '01_basic_control_O0',
    '01_basic_control_O2',
    '04_bitwise_O0',
    '04_bitwise_O2',
    '08_string_ops_O0',
    '08_string_ops_O2',
    '18_hash_table_O0',
    '18_hash_table_O2',
    '24_switch_dense_O0',
    '24_switch_dense_O2',
    '29_crypto_simple_O0',
    '29_crypto_simple_O2',
  ];
  for (const prefix of qualityTests) {
    const xml = findCachedXml(prefix);
    if (xml) {
      const binPath = `test/quality/bin/${prefix}`;
      const sizeKB = existsSync(binPath) ? Math.round(statSync(binPath).size / 1024) : 0;
      inputs.push({ label: prefix, xmlFile: xml, sizeKB });
    }
  }

  // System binaries (stripped — few functions but large code)
  const systemBins: [string, string][] = [
    ['/usr/bin/true', 'true'],
    ['/usr/bin/grep', 'grep'],
    ['/usr/bin/awk', 'awk'],
    ['/bin/bash', 'bash(sys)'],
  ];
  for (const [binPath, label] of systemBins) {
    if (!existsSync(binPath)) continue;
    const xml = exportBinary(binPath);
    if (xml) {
      const sizeKB = Math.round(statSync(binPath).size / 1024);
      inputs.push({ label, xmlFile: xml, sizeKB });
    }
  }

  // Homebrew bash (unstripped — many functions)
  const brewBash = '/opt/homebrew/bin/bash';
  if (existsSync(brewBash)) {
    try {
      const realBash = execSync(`realpath "${brewBash}"`, { encoding: 'utf8' }).trim();
      if (existsSync(realBash)) {
        const xml = exportBinary(realBash);
        if (xml) {
          const sizeKB = Math.round(statSync(realBash).size / 1024);
          inputs.push({ label: 'bash(brew)', xmlFile: xml, sizeKB });
        }
      }
    } catch { /* skip */ }
  }

  return inputs;
}

// --- Initialize ---
startDecompilerLibrary();

const hasCpp = existsSync(CPP_BIN) && existsSync(GHIDRA_HOME);
if (!hasCpp) {
  console.error('Warning: C++ decompiler or SLEIGHHOME not found, running TS-only benchmark\n');
}

// Parse args: support --xml <file> <label> and raw binary paths
const inputs: BenchInput[] = [];
const argv = process.argv.slice(2);
let i = 0;
while (i < argv.length) {
  if (argv[i] === '--xml' && i + 2 < argv.length) {
    const xmlFile = argv[i + 1];
    const label = argv[i + 2];
    inputs.push({ label, xmlFile, sizeKB: 0 });
    i += 3;
  } else {
    const binPath = argv[i];
    if (existsSync(binPath)) {
      const xml = exportBinary(binPath);
      if (xml) {
        const sizeKB = Math.round(statSync(binPath).size / 1024);
        inputs.push({ label: path.basename(binPath), xmlFile: xml, sizeKB });
      }
    }
    i++;
  }
}

if (inputs.length === 0) {
  inputs.push(...buildDefaultInputs());
}

if (inputs.length === 0) {
  console.error('No inputs found. Run quality tests first to populate cache.');
  process.exit(1);
}

// --- Header ---
console.log('');
const W_LABEL = 28;
if (hasCpp) {
  console.log(
    padR('Binary', W_LABEL) + padL('Size', 7) + padL('Funcs', 7) +
    padL('TS(s)', 10) + padL('C++(s)', 10) + padL('Ratio', 8) +
    padL('TS_RSS', 10) + padL('C++_RSS', 10) + padL('MemR', 7)
  );
} else {
  console.log(
    padR('Binary', W_LABEL) + padL('Size', 7) + padL('Funcs', 7) +
    padL('TS(s)', 10) + padL('TS_RSS', 10)
  );
}
console.log('─'.repeat(hasCpp ? 97 : 59));

const results: BenchResult[] = [];

for (const input of inputs) {
  const { label, xmlFile, sizeKB } = input;

  const xmlContent = readFileSync(xmlFile, 'utf8');
  const funcCount = (xmlContent.match(/<script>/g) || []).length;

  if (funcCount === 0) {
    console.log(`${padR(label, W_LABEL)} ${padL(formatSize(sizeKB), 7)} ${padL('0', 7)}  (no functions)`);
    continue;
  }

  // Cap at 500 functions for in-process TS run to avoid OOM
  // (TS decompiler accumulates all state in the same V8 heap)
  const MAX_FUNCS = 500;
  if (funcCount > MAX_FUNCS) {
    console.log(`${padR(label, W_LABEL)} ${padL(formatSize(sizeKB), 7)} ${padL(String(funcCount), 7)}  (skipped: >${MAX_FUNCS} funcs, OOM risk)`);
    continue;
  }

  // --- Run TS decompiler ---
  let tsElapsed = 0;
  let tsRss = 0;
  {
    if (global.gc) global.gc();
    const start = performance.now();

    const writer = new StringWriter();
    const tc = new FunctionTestCollection(writer);
    tc.loadTest(xmlFile);
    const failures: string[] = [];
    tc.runTests(failures);

    tsElapsed = (performance.now() - start) / 1000;
    tsRss = process.memoryUsage().rss;
  }
  const tsRssMB = tsRss / (1024 * 1024);

  // --- Run C++ decompiler ---
  let cppElapsed = 0;
  let cppRss = 0;
  if (hasCpp) {
    const dir = path.dirname(xmlFile);
    const base = path.basename(xmlFile);
    try {
      const timeCmd = `/usr/bin/time -l "${CPP_BIN}" -usesleighenv -path "${dir}" datatests ${base} 2>&1`;
      const start = performance.now();
      const output = execSync(timeCmd, {
        env: { ...process.env, SLEIGHHOME: GHIDRA_HOME },
        encoding: 'utf8',
        maxBuffer: 100 * 1024 * 1024,
        timeout: 600_000,
      });
      cppElapsed = (performance.now() - start) / 1000;

      const rssMatch = output.match(/(\d+)\s+maximum resident set size/);
      if (rssMatch) cppRss = parseInt(rssMatch[1]);
    } catch (e: any) {
      const combined = (e.stdout || '') + (e.stderr || '');
      // Still capture timing — execSync wall time is valid even on non-zero exit
      const rssMatch = combined.match(/(\d+)\s+maximum resident set size/);
      if (rssMatch) cppRss = parseInt(rssMatch[1]);
      const realMatch = combined.match(/([\d.]+)\s+real/);
      if (realMatch) cppElapsed = parseFloat(realMatch[1]);
    }
  }
  const cppRssMB = cppRss / (1024 * 1024);

  const timeRatio = cppElapsed > 0 ? tsElapsed / cppElapsed : 0;
  const memRatio = cppRss > 0 ? tsRss / cppRss : 0;

  results.push({
    label, sizeKB, funcCount,
    tsTimeSec: tsElapsed, tsRssMB,
    cppTimeSec: cppElapsed, cppRssMB,
    timeRatio, memRatio,
  });

  // --- Print row ---
  if (hasCpp) {
    console.log(
      padR(label, W_LABEL) +
      padL(sizeKB > 0 ? formatSize(sizeKB) : '', 7) +
      padL(String(funcCount), 7) +
      padL(tsElapsed.toFixed(2) + 's', 10) +
      padL(cppElapsed.toFixed(2) + 's', 10) +
      padL(timeRatio.toFixed(1) + 'x', 8) +
      padL(tsRssMB.toFixed(0) + 'MB', 10) +
      padL(cppRssMB.toFixed(0) + 'MB', 10) +
      padL(memRatio.toFixed(1) + 'x', 7)
    );
  } else {
    console.log(
      padR(label, W_LABEL) +
      padL(sizeKB > 0 ? formatSize(sizeKB) : '', 7) +
      padL(String(funcCount), 7) +
      padL(tsElapsed.toFixed(2) + 's', 10) +
      padL(tsRssMB.toFixed(0) + 'MB', 10)
    );
  }
}

// --- Summary ---
if (results.length > 1) {
  console.log('─'.repeat(hasCpp ? 97 : 59));
  const totalTsTime = results.reduce((s, r) => s + r.tsTimeSec, 0);
  const totalCppTime = results.reduce((s, r) => s + r.cppTimeSec, 0);
  const totalFuncs = results.reduce((s, r) => s + r.funcCount, 0);
  const avgTimeRatio = totalCppTime > 0 ? totalTsTime / totalCppTime : 0;

  if (hasCpp) {
    const validMem = results.filter(r => r.memRatio > 0);
    const avgMemRatio = validMem.length > 0
      ? validMem.reduce((s, r) => s + r.memRatio, 0) / validMem.length
      : 0;
    console.log(
      padR('TOTAL', W_LABEL) +
      padL('', 7) +
      padL(String(totalFuncs), 7) +
      padL(totalTsTime.toFixed(2) + 's', 10) +
      padL(totalCppTime.toFixed(2) + 's', 10) +
      padL(avgTimeRatio.toFixed(1) + 'x', 8) +
      padL('', 10) +
      padL('', 10) +
      padL(avgMemRatio.toFixed(1) + 'x', 7)
    );
  } else {
    console.log(
      padR('TOTAL', W_LABEL) +
      padL('', 7) +
      padL(String(totalFuncs), 7) +
      padL(totalTsTime.toFixed(2) + 's', 10)
    );
  }
}

console.log('');
