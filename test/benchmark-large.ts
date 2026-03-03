#!/usr/bin/env npx tsx
/**
 * Benchmark TS vs C++ decompiler on large binaries.
 *
 * Runs each decompiler as a subprocess to avoid OOM.
 * For TS: spawns per-binary subprocess with run-ts-bench.ts
 * For C++: uses decomp_test_dbg with /usr/bin/time
 *
 * Usage: npx tsx test/benchmark-large.ts [binary...]
 */
import { parseBinary, generateXml } from '../src/console/binary_to_xml.js';
import { readFileSync, writeFileSync, mkdirSync, existsSync, statSync } from 'fs';
import { execSync } from 'child_process';
import path from 'path';

const CPP_BIN = 'ghidra-src/Ghidra/Features/Decompiler/src/decompile/cpp/decomp_test_dbg';
const GHIDRA_HOME = process.env.SLEIGHHOME ||
  '/opt/homebrew/Caskroom/ghidra/11.4.2-20250826/ghidra_11.4.2_PUBLIC';

interface BenchResult {
  label: string;
  sizeKB: number;
  funcCount: number;
  tsTimeSec: number;
  tsRssMB: number;
  cppTimeSec: number;
  cppRssMB: number;
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

function exportBinary(binaryPath: string): string | null {
  const cacheDir = 'output/bench-cache';
  mkdirSync(cacheDir, { recursive: true });
  const bname = path.basename(binaryPath);
  const stat = statSync(binaryPath);
  const xmlDir = path.join(cacheDir, `${bname}_${Math.floor(stat.mtimeMs / 1000)}`);
  const xmlFile = path.join(xmlDir, 'exported.xml');
  if (!existsSync(xmlFile)) {
    mkdirSync(xmlDir, { recursive: true });
    try {
      const buf = readFileSync(binaryPath);
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

const DEFAULT_BINARIES = [
  '/usr/sbin/httpd',        //  1.6M, 1275 funcs
  '/opt/homebrew/bin/bash',  // 1.0M, 2351 funcs (resolves symlink)
  '/opt/homebrew/bin/xgettext', // 13M, 1046 funcs
  '/opt/homebrew/bin/gs',    // 14M, 11304 funcs
];

const binaries = process.argv.slice(2).length > 0
  ? process.argv.slice(2)
  : DEFAULT_BINARIES;

const hasCpp = existsSync(CPP_BIN) && existsSync(GHIDRA_HOME);

// --- Header ---
console.log('');
const W = 20;
console.log(
  padR('Binary', W) + padL('Size', 7) + padL('Funcs', 7) +
  padL('TS(s)', 10) + padL('TS_RSS', 10) +
  (hasCpp ? padL('C++(s)', 10) + padL('C++_RSS', 10) + padL('Ratio', 8) + padL('MemR', 7) : '')
);
console.log('─'.repeat(hasCpp ? 89 : 54));

const results: BenchResult[] = [];

for (const binary of binaries) {
  const realPath = (() => {
    try { return execSync(`realpath "${binary}"`, { encoding: 'utf8' }).trim(); }
    catch { return binary; }
  })();
  if (!existsSync(realPath)) {
    console.log(`${padR(path.basename(binary), W)}  (not found)`);
    continue;
  }

  const bname = path.basename(binary);
  const sizeKB = Math.round(statSync(realPath).size / 1024);

  // Export
  process.stderr.write(`Exporting ${bname}...\n`);
  const xmlFile = exportBinary(realPath);
  if (!xmlFile) continue;

  const xmlContent = readFileSync(xmlFile, 'utf8');
  const funcCount = (xmlContent.match(/<script>/g) || []).length;
  if (funcCount === 0) {
    console.log(`${padR(bname, W)} ${padL(formatSize(sizeKB), 7)} ${padL('0', 7)}  (no functions)`);
    continue;
  }

  const dir = path.dirname(xmlFile);
  const base = path.basename(xmlFile);

  // --- Run TS decompiler as subprocess ---
  process.stderr.write(`  TS decompiling ${funcCount} functions...\n`);
  let tsTimeSec = 0;
  let tsRssMB = 0;
  try {
    // Only set large heap when needed (batching threshold is 500 funcs)
    const needsLargeHeap = funcCount > 500;
    const nodeOpts = needsLargeHeap
      ? `--expose-gc --max-old-space-size=${Math.max(8192, Math.min(funcCount * 5, 24576))}`
      : '';
    const tsCmd = `/usr/bin/time -l node ./node_modules/.bin/tsx test/run-ts-bench.ts "${xmlFile}" 2>&1`;
    const tsOut = execSync(tsCmd, {
      encoding: 'utf8',
      maxBuffer: 200 * 1024 * 1024,
      timeout: 1800_000,
      env: { ...process.env, ...(nodeOpts ? { NODE_OPTIONS: nodeOpts } : {}) },
    });
    const elapsedMatch = tsOut.match(/ELAPSED:([\d.]+)/);
    if (elapsedMatch) tsTimeSec = parseFloat(elapsedMatch[1]);
    const rssMatch = tsOut.match(/(\d+)\s+maximum resident set size/);
    if (rssMatch) tsRssMB = parseInt(rssMatch[1]) / (1024 * 1024);
  } catch (e: any) {
    const combined = (e.stdout || '') + (e.stderr || '');
    const elapsedMatch = combined.match(/ELAPSED:([\d.]+)/);
    if (elapsedMatch) tsTimeSec = parseFloat(elapsedMatch[1]);
    const rssMatch = combined.match(/(\d+)\s+maximum resident set size/);
    if (rssMatch) tsRssMB = parseInt(rssMatch[1]) / (1024 * 1024);
    if (!elapsedMatch) {
      process.stderr.write(`  TS FAILED (exit ${e.status})\n`);
      tsTimeSec = -1;
    }
  }

  // --- Run C++ decompiler ---
  let cppTimeSec = 0;
  let cppRssMB = 0;
  let cppFailed = 0;
  if (hasCpp) {
    process.stderr.write(`  C++ decompiling...\n`);
    const parseCppOutput = (output: string) => {
      const realMatch = output.match(/([\d.]+)\s+real\s+[\d.]+\s+user/);
      if (realMatch) cppTimeSec = parseFloat(realMatch[1]);
      const rssMatch = output.match(/(\d+)\s+maximum resident set size/);
      if (rssMatch) cppRssMB = parseInt(rssMatch[1]) / (1024 * 1024);
      cppFailed = (output.match(/Unable to proceed/g) || []).length;
    };
    try {
      const cppCmd = `/usr/bin/time -l "${CPP_BIN}" -usesleighenv -path "${dir}" datatests ${base} 2>&1`;
      const cppOut = execSync(cppCmd, {
        env: { ...process.env, SLEIGHHOME: GHIDRA_HOME },
        encoding: 'utf8',
        maxBuffer: 200 * 1024 * 1024,
        timeout: 1800_000,
      });
      parseCppOutput(cppOut);
    } catch (e: any) {
      parseCppOutput((e.stdout || '') + (e.stderr || ''));
    }
    if (cppFailed > 0) {
      process.stderr.write(`  C++ failed ${cppFailed}/${funcCount} functions\n`);
    }
  }

  // Invalidate C++ time when >50% of functions fail (fast-fail, not real decompilation)
  const cppValid = cppFailed < funcCount * 0.5;
  const effectiveCppTime = cppValid ? cppTimeSec : 0;

  // Show TS/C++ ratio: <1 means TS is faster, >1 means C++ is faster
  const timeRatio = effectiveCppTime > 0 && tsTimeSec > 0 ? tsTimeSec / effectiveCppTime : 0;
  const memRatio = cppRssMB > 0 && tsRssMB > 0 ? tsRssMB / cppRssMB : 0;

  results.push({ label: bname, sizeKB, funcCount, tsTimeSec, tsRssMB, cppTimeSec: effectiveCppTime, cppRssMB });

  const tsTimeStr = tsTimeSec < 0 ? 'OOM' : tsTimeSec.toFixed(2) + 's';
  const cppTimeStr = !cppValid ? 'FAIL*' : cppTimeSec.toFixed(2) + 's';
  console.log(
    padR(bname, W) +
    padL(formatSize(sizeKB), 7) +
    padL(String(funcCount), 7) +
    padL(tsTimeStr, 10) +
    padL(tsRssMB > 0 ? tsRssMB.toFixed(0) + 'MB' : '-', 10) +
    (hasCpp
      ? padL(cppTimeStr, 10) +
        padL(cppRssMB > 0 ? cppRssMB.toFixed(0) + 'MB' : '-', 10) +
        padL(timeRatio > 0 ? (timeRatio < 0.1 ? timeRatio.toFixed(2) : timeRatio.toFixed(1)) + 'x' : '-', 8) +
        padL(memRatio > 0 ? memRatio.toFixed(1) + 'x' : '-', 7)
      : '')
  );
}

// --- Summary ---
if (results.length > 1) {
  console.log('─'.repeat(hasCpp ? 89 : 54));
  const valid = results.filter(r => r.tsTimeSec > 0 && r.cppTimeSec > 0);
  const totalTs = valid.reduce((s, r) => s + r.tsTimeSec, 0);
  const totalCpp = valid.reduce((s, r) => s + r.cppTimeSec, 0);
  const totalFuncs = valid.reduce((s, r) => s + r.funcCount, 0);
  const ratio = totalCpp > 0 ? totalTs / totalCpp : 0;
  const validMem = valid.filter(r => r.tsRssMB > 0 && r.cppRssMB > 0);
  const avgMem = validMem.length > 0
    ? validMem.reduce((s, r) => s + r.tsRssMB / r.cppRssMB, 0) / validMem.length
    : 0;

  console.log(
    padR('TOTAL', W) +
    padL('', 7) +
    padL(String(totalFuncs), 7) +
    padL(totalTs.toFixed(2) + 's', 10) +
    padL('', 10) +
    (hasCpp
      ? padL(totalCpp.toFixed(2) + 's', 10) +
        padL('', 10) +
        padL(ratio > 0 ? (ratio < 0.1 ? ratio.toFixed(2) : ratio.toFixed(1)) + 'x' : '-', 8) +
        padL(avgMem > 0 ? avgMem.toFixed(1) + 'x' : '-', 7)
      : '')
  );
}

console.log('* FAIL = C++ failed >50% of functions (time invalid for comparison)');
console.log('  Ratio = TS/C++ (lower = TS faster), MemR = TS_RSS/C++_RSS');
console.log('');
