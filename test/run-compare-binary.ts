/**
 * Run both C++ and TS decompilers on an exported XML and compare per-function.
 *
 * Usage: npx tsx test/run-compare-binary.ts [--workers N] [--enhance] [--metrics] <exported.xml> [output-dir]
 *
 * --workers N  Use N worker threads for true multi-core parallelism.
 *              Without this flag, decompilation is sequential (single-threaded).
 * --enhance    Enable enhanced display mode.
 * --metrics    Print per-function and aggregate SAILR metrics table.
 */
import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';
import { WorkerParallelDecompiler } from '../src/decompiler/parallel_workers.js';
import { execSync } from 'child_process';
import { writeFileSync, mkdirSync } from 'fs';
import path from 'path';

// --- Parse arguments ---
let numWorkers = 0;
let enhancedDisplay = false;
let showMetrics = false;
const positional: string[] = [];
for (let i = 2; i < process.argv.length; i++) {
    if (process.argv[i] === '--workers' || process.argv[i] === '-w') {
        i++;
        numWorkers = parseInt(process.argv[i], 10) || 4;
    } else if (process.argv[i] === '--enhance') {
        enhancedDisplay = true;
    } else if (process.argv[i] === '--metrics') {
        showMetrics = true;
    } else {
        positional.push(process.argv[i]);
    }
}

const xmlFile = positional[0] || '/tmp/decomp-test/exported.xml';
const outputDir = positional[1] || '';
const CPP_BIN = 'ghidra-src/Ghidra/Features/Decompiler/src/decompile/cpp/decomp_test_dbg';

function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// --- Run TS decompiler (sequential or worker-parallel) ---
let tsOutput: string;
let tsElapsed: number;
let tsRss: number;
let tsHeapUsed: number;
let failures: string[] = [];

if (numWorkers > 0) {
    // Worker-parallel path
    console.log(`Using ${numWorkers} worker threads...\n`);
    const tsMemBefore = process.memoryUsage();
    const tsStart = performance.now();

    const progressWriter = { write: (s: string) => process.stderr.write(s) };
    const pd = new WorkerParallelDecompiler(xmlFile, numWorkers, progressWriter, enhancedDisplay);
    console.log(`Found ${pd.getFunctionCount()} functions\n`);

    const results = await pd.decompileAll();
    tsElapsed = performance.now() - tsStart;
    const tsMemAfter = process.memoryUsage();
    tsHeapUsed = tsMemAfter.heapUsed - tsMemBefore.heapUsed;
    tsRss = tsMemAfter.rss;

    // Concatenate output in original order
    tsOutput = results
        .map(r => r.output)
        .join('')
        .split('\n')
        .map((l: string) => l.trimEnd())
        .join('\n')
        .trim();

    const failed = results.filter(r => !r.success);
    if (failed.length > 0) {
        for (const r of failed) {
            failures.push(`${r.name}: ${r.error}`);
        }
    }
} else {
    // Sequential path (original behavior)
    startDecompilerLibrary();

    const tsMemBefore = process.memoryUsage();
    const tsStart = performance.now();

    const writer = new StringWriter();
    const tc = new FunctionTestCollection(writer);
    tc.loadTest(xmlFile);
    if (enhancedDisplay) {
        tc.applyEnhancedDisplay();
    }
    tc.runTests(failures);

    tsElapsed = performance.now() - tsStart;
    const tsMemAfter = process.memoryUsage();
    tsHeapUsed = tsMemAfter.heapUsed - tsMemBefore.heapUsed;
    tsRss = tsMemAfter.rss;

    tsOutput = tc.getLastOutput().split('\n').map((l: string) => l.trimEnd()).join('\n').trim();
}

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
        env: { ...process.env },
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
if (numWorkers > 0) {
    console.log(`Mode: ${numWorkers} worker threads`);
}

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

// --- Metrics ---
if (showMetrics) {
    function collectTextMetrics(funcMap: Map<string, string>): { name: string; gotos: number; breaks: number; continues: number; depth: number; whiles: number; dos: number; ifs: number; switches: number; labels: number }[] {
        const results: { name: string; gotos: number; breaks: number; continues: number; depth: number; whiles: number; dos: number; ifs: number; switches: number; labels: number }[] = [];
        for (const [name, body] of funcMap) {
            const gotos = (body.match(/\bgoto\s+\w+/g) || []).length;
            const breaks = (body.match(/\bbreak\s*;/g) || []).length;
            const continues = (body.match(/\bcontinue\s*;/g) || []).length;
            const whiles = (body.match(/\bwhile\s*\(/g) || []).length;
            const dos = (body.match(/\bdo\s*\{/g) || []).length;
            const ifs = (body.match(/\bif\s*\(/g) || []).length;
            const switches = (body.match(/\bswitch\s*\(/g) || []).length;
            const labels = (body.match(/^\s*\w+:/gm) || []).filter(l => !l.match(/^\s*(case|default)\s*:/)).length;
            // Approximate nesting depth from indentation
            let maxDepth = 0;
            let depth = 0;
            for (const ch of body) {
                if (ch === '{') depth++;
                if (ch === '}') depth--;
                if (depth > maxDepth) maxDepth = depth;
            }
            results.push({ name, gotos, breaks, continues, depth: maxDepth, whiles, dos, ifs, switches, labels });
        }
        return results.sort((a, b) => b.gotos - a.gotos);
    }

    function padR(s: string, w: number): string { return s.length >= w ? s.slice(0, w) : s + ' '.repeat(w - s.length); }
    function padL(s: string, w: number): string { return s.length >= w ? s : ' '.repeat(w - s.length) + s; }

    function printMetricsTable(label: string, funcMap: Map<string, string>): void {
        const metrics = collectTextMetrics(funcMap);
        const interesting = metrics.filter(m => m.gotos > 0 || m.depth >= 4);
        console.log(`\n=== ${label} Metrics ===`);
        console.log(
            padR('Function', 40) + padL('Gotos', 7) + padL('Brk', 5) + padL('Cont', 6) +
            padL('Depth', 7) + padL('While', 7) + padL('Do', 5) + padL('If', 5) +
            padL('Swi', 5) + padL('Lbl', 5)
        );
        console.log('-'.repeat(90));
        for (const m of interesting) {
            console.log(
                padR(m.name, 40) + padL(String(m.gotos), 7) + padL(String(m.breaks), 5) +
                padL(String(m.continues), 6) + padL(String(m.depth), 7) +
                padL(String(m.whiles), 7) + padL(String(m.dos), 5) +
                padL(String(m.ifs), 5) + padL(String(m.switches), 5) +
                padL(String(m.labels), 5)
            );
        }
        console.log('-'.repeat(90));
        const totGotos = metrics.reduce((s, m) => s + m.gotos, 0);
        const totBreaks = metrics.reduce((s, m) => s + m.breaks, 0);
        const totConts = metrics.reduce((s, m) => s + m.continues, 0);
        const maxD = metrics.reduce((s, m) => Math.max(s, m.depth), 0);
        const totW = metrics.reduce((s, m) => s + m.whiles, 0);
        const totDo = metrics.reduce((s, m) => s + m.dos, 0);
        const totIf = metrics.reduce((s, m) => s + m.ifs, 0);
        const totSw = metrics.reduce((s, m) => s + m.switches, 0);
        const totLbl = metrics.reduce((s, m) => s + m.labels, 0);
        console.log(
            padR(`TOTAL (${metrics.length} funcs)`, 40) + padL(String(totGotos), 7) +
            padL(String(totBreaks), 5) + padL(String(totConts), 6) + padL(String(maxD), 7) +
            padL(String(totW), 7) + padL(String(totDo), 5) + padL(String(totIf), 5) +
            padL(String(totSw), 5) + padL(String(totLbl), 5)
        );
    }

    printMetricsTable('TS', tsFuncs);
    if (cppFuncs.size > 0) {
        printMetricsTable('C++', cppFuncs);
    }
}
