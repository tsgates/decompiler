/** Generate TSV and Markdown reports from FileComparison data. */
import type { FileComparison } from './types.js';
import path from 'path';

/** Generate TSV report. */
export function generateTSV(comparisons: FileComparison[]): string {
  const lines: string[] = [];
  lines.push('Source\tOptLevel\tFuncRecov\tCFMatch%\tAvgVarRatio\tAvgCastDens\tTotalGotos');

  for (const cmp of comparisons) {
    const basename = path.basename(cmp.sourceFile, '.c').replace(/^.*\//, '');
    const funcRecov = `${cmp.matched.length}/${cmp.matched.length + cmp.unmatchedSource.length}`;

    let cfMatchPct = 0;
    let avgVarRatio = 0;
    let avgCastDens = 0;
    let totalGotos = 0;

    if (cmp.matched.length > 0) {
      const cfMatches = cmp.matched.filter(m => m.controlFlowMatch).length;
      cfMatchPct = Math.round(100 * cfMatches / cmp.matched.length);
      avgVarRatio = cmp.matched.reduce((s, m) => s + m.variableRatio, 0) / cmp.matched.length;
      avgCastDens = cmp.matched.reduce((s, m) => s + m.castDensity, 0) / cmp.matched.length;
    }
    totalGotos = cmp.matched.reduce((s, m) => s + m.gotoIntroduced, 0);

    lines.push(
      `${basename}\t${cmp.optLevel}\t${funcRecov}\t${cfMatchPct}%\t${avgVarRatio.toFixed(1)}\t${avgCastDens.toFixed(2)}\t${totalGotos}`
    );
  }

  return lines.join('\n') + '\n';
}

/** Generate Markdown report. */
export function generateMarkdown(comparisons: FileComparison[]): string {
  const lines: string[] = [];
  lines.push('# Source Fidelity Report');
  lines.push('');

  // Summary table
  lines.push('## Summary');
  lines.push('');
  lines.push('| Source | OptLevel | Func Recovery | CF Match% | Avg Var Ratio | Avg Cast Density | Gotos |');
  lines.push('|--------|----------|---------------|-----------|---------------|------------------|-------|');

  let totalMatched = 0;
  let totalSource = 0;
  let totalCfMatches = 0;
  let totalCfTotal = 0;
  let totalGotos = 0;

  for (const cmp of comparisons) {
    const basename = path.basename(cmp.sourceFile, '.c').replace(/^.*\//, '');
    const srcCount = cmp.matched.length + cmp.unmatchedSource.length;
    const funcRecov = `${cmp.matched.length}/${srcCount}`;

    let cfMatchPct = 0;
    let avgVarRatio = 0;
    let avgCastDens = 0;
    let gotos = 0;

    if (cmp.matched.length > 0) {
      const cfMatches = cmp.matched.filter(m => m.controlFlowMatch).length;
      cfMatchPct = Math.round(100 * cfMatches / cmp.matched.length);
      avgVarRatio = cmp.matched.reduce((s, m) => s + m.variableRatio, 0) / cmp.matched.length;
      avgCastDens = cmp.matched.reduce((s, m) => s + m.castDensity, 0) / cmp.matched.length;
      totalCfMatches += cfMatches;
    }
    gotos = cmp.matched.reduce((s, m) => s + m.gotoIntroduced, 0);

    totalMatched += cmp.matched.length;
    totalSource += srcCount;
    totalCfTotal += cmp.matched.length;
    totalGotos += gotos;

    lines.push(
      `| ${basename} | ${cmp.optLevel} | ${funcRecov} | ${cfMatchPct}% | ${avgVarRatio.toFixed(1)} | ${avgCastDens.toFixed(2)} | ${gotos} |`
    );
  }

  // Aggregate row
  lines.push('');
  lines.push('## Aggregate');
  lines.push('');
  const aggCfPct = totalCfTotal > 0 ? Math.round(100 * totalCfMatches / totalCfTotal) : 0;
  lines.push(`- **Function Recovery**: ${totalMatched}/${totalSource} (${totalSource > 0 ? Math.round(100 * totalMatched / totalSource) : 0}%)`);
  lines.push(`- **Control Flow Match**: ${aggCfPct}%`);
  lines.push(`- **Total Gotos Introduced**: ${totalGotos}`);
  lines.push('');

  return lines.join('\n');
}
