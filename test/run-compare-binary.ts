/**
 * Run both C++ and TS decompilers on an exported XML and compare per-function.
 *
 * Usage: npx tsx test/run-compare-binary.ts <exported.xml> [output-dir]
 */
import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';
import { execSync } from 'child_process';
import { writeFileSync, mkdirSync } from 'fs';
import path from 'path';

const SLEIGH_PATH = process.env.SLEIGH_PATH || '/opt/homebrew/Caskroom/ghidra/11.4.2-20250826/ghidra_11.4.2_PUBLIC';
const xmlFile = process.argv[2] || '/tmp/decomp-test/exported.xml';
const outputDir = process.argv[3] || '';
const CPP_BIN = 'ghidra-src/Ghidra/Features/Decompiler/src/decompile/cpp/decomp_test_dbg';

startDecompilerLibrary(SLEIGH_PATH);

function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// --- Run TS decompiler ---
const tsMemBefore = process.memoryUsage();
const tsStart = performance.now();

const writer = new StringWriter();
const failures: string[] = [];
const tc = new FunctionTestCollection(writer);
tc.loadTest(xmlFile);
tc.runTests(failures);

const tsElapsed = performance.now() - tsStart;
const tsMemAfter = process.memoryUsage();
const tsHeapUsed = tsMemAfter.heapUsed - tsMemBefore.heapUsed;
const tsRss = tsMemAfter.rss;

const tsOutput = tc.getLastOutput().split('\n').map((l: string) => l.trimEnd()).join('\n').trim();

// --- Run C++ decompiler ---
const dir = xmlFile.substring(0, xmlFile.lastIndexOf('/'));
const basename = xmlFile.substring(xmlFile.lastIndexOf('/') + 1);
let cppAllOutput: string;

const cppStart = performance.now();
try {
    // Use /usr/bin/time to capture C++ memory usage
    const timeCmd = process.platform === 'darwin'
        ? `/usr/bin/time -l "${CPP_BIN}" -usesleighenv -path "${dir}" datatests ${basename} 2>&1`
        : `/usr/bin/time -v "${CPP_BIN}" -usesleighenv -path "${dir}" datatests ${basename} 2>&1`;
    cppAllOutput = execSync(timeCmd, {
        env: { ...process.env, SLEIGHHOME: SLEIGH_PATH },
        encoding: 'utf8',
        cwd: process.cwd(),
        maxBuffer: 50 * 1024 * 1024,
    }).toString();
} catch (e: any) {
    cppAllOutput = (e.stderr || '') + (e.stdout || '');
}
const cppElapsed = performance.now() - cppStart;

// Parse C++ peak memory from /usr/bin/time output
let cppPeakMem = 0;
if (process.platform === 'darwin') {
    // macOS: "  NNN  maximum resident set size" (bytes)
    const m = cppAllOutput.match(/(\d+)\s+maximum resident set size/);
    if (m) cppPeakMem = parseInt(m[1]);
} else {
    // Linux: "Maximum resident set size (kbytes): NNN"
    const m = cppAllOutput.match(/Maximum resident set size.*?:\s*(\d+)/);
    if (m) cppPeakMem = parseInt(m[1]) * 1024;
}

const cppMatch = cppAllOutput.match(/=== C\+\+ DECOMPILER OUTPUT ===\n([\s\S]*?)=== END ===/);
const cppOutput = cppMatch ? cppMatch[1].split('\n').map((l: string) => l.trimEnd()).join('\n').trim() : '';

// --- Save raw outputs ---
if (outputDir) {
    mkdirSync(outputDir, { recursive: true });
    writeFileSync(path.join(outputDir, 'ts_output.c'), tsOutput + '\n');
    writeFileSync(path.join(outputDir, 'cpp_output.c'), cppOutput + '\n');
}

// --- Per-function comparison ---
function splitFunctions(output: string): Map<string, string> {
    const funcs = new Map<string, string>();
    // Split on function signatures (type name(...))
    const blocks = output.split(/\n(?=\S+\s+\S+\()/);
    for (const block of blocks) {
        const trimmed = block.trim();
        if (!trimmed) continue;
        // Extract function name from first line
        const m = trimmed.match(/^\S+\s+(\S+?)\s*\(/);
        if (m) {
            funcs.set(m[1], trimmed);
        }
    }
    return funcs;
}

const tsFuncs = splitFunctions(tsOutput);
const cppFuncs = splitFunctions(cppOutput);

let identical = 0;
let different = 0;
let tsOnly = 0;
let cppOnly = 0;
const diffs: string[] = [];
const identicalNames: string[] = [];
const tsOnlyNames: string[] = [];
const cppOnlyNames: string[] = [];

// Compare functions present in both
const allNames = new Set([...tsFuncs.keys(), ...cppFuncs.keys()]);
for (const name of [...allNames].sort()) {
    const ts = tsFuncs.get(name);
    const cpp = cppFuncs.get(name);
    if (ts && cpp) {
        if (ts === cpp) {
            identical++;
            identicalNames.push(name);
        } else {
            different++;
            // Find first differing line
            const tsLines = ts.split('\n');
            const cppLines = cpp.split('\n');
            let firstDiff = '';
            for (let i = 0; i < Math.max(tsLines.length, cppLines.length); i++) {
                if (tsLines[i] !== cppLines[i]) {
                    firstDiff = `line ${i+1}: C++ "${cppLines[i] || '(missing)'}" vs TS "${tsLines[i] || '(missing)'}"`;
                    break;
                }
            }
            diffs.push(`  ${name}: ${firstDiff}`);
        }
    } else if (ts && !cpp) {
        tsOnly++;
        tsOnlyNames.push(name);
    } else {
        cppOnly++;
        cppOnlyNames.push(name);
    }
}

// --- Save per-function diffs ---
if (outputDir && different > 0) {
    const diffDir = path.join(outputDir, 'diffs');
    mkdirSync(diffDir, { recursive: true });
    for (const name of [...allNames].sort()) {
        const ts = tsFuncs.get(name);
        const cpp = cppFuncs.get(name);
        if (ts && cpp && ts !== cpp) {
            writeFileSync(path.join(diffDir, `${name}.cpp.c`), cpp + '\n');
            writeFileSync(path.join(diffDir, `${name}.ts.c`), ts + '\n');
        }
    }
}

const binaryName = path.basename(xmlFile, '.xml');
const total = identical + different;
const pct = total > 0 ? ((identical / total) * 100).toFixed(1) : '0.0';

console.log(`\n=== Decompilation Comparison: ${binaryName} ===`);
console.log(`Functions in C++: ${cppFuncs.size}`);
console.log(`Functions in TS:  ${tsFuncs.size}`);

console.log(`\nPerformance:`);
console.log(`  C++:  ${(cppElapsed / 1000).toFixed(2)}s` + (cppPeakMem > 0 ? `,  peak RSS ${formatBytes(cppPeakMem)}` : ''));
console.log(`  TS:   ${(tsElapsed / 1000).toFixed(2)}s,  peak RSS ${formatBytes(tsRss)},  heap delta ${tsHeapUsed > 0 ? '+' : ''}${formatBytes(tsHeapUsed)}`);
console.log(`  Ratio: ${(tsElapsed / cppElapsed).toFixed(1)}x time` + (cppPeakMem > 0 ? `, ${(tsRss / cppPeakMem).toFixed(1)}x memory` : ''));

console.log(`\nResults:`);
console.log(`  Identical:    ${identical}/${total} (${pct}%)`);
console.log(`  Different:    ${different}`);
console.log(`  TS only:      ${tsOnly}`);
console.log(`  C++ only:     ${cppOnly}`);

if (diffs.length > 0) {
    console.log(`\nDifferences (first diff per function):`);
    for (const d of diffs) console.log(d);
}

if (tsOnlyNames.length > 0) {
    console.log(`\nTS only: ${tsOnlyNames.join(', ')}`);
}
if (cppOnlyNames.length > 0) {
    console.log(`\nC++ only: ${cppOnlyNames.join(', ')}`);
}

if (failures.length > 0) {
    console.log(`\nTS execution failures: ${failures.length}`);
    for (const f of failures) console.log(`  ${f}`);
}

if (outputDir) {
    console.log(`\nOutput saved to: ${outputDir}`);
    console.log(`  ts_output.c   — full TS decompiled output`);
    console.log(`  cpp_output.c  — full C++ decompiled output`);
    if (different > 0) {
        console.log(`  diffs/        — per-function diff pairs (${different} functions)`);
    }
}
