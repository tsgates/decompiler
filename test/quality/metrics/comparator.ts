/** Compare source vs decompiled output metrics. */
import type { FileMetrics, FunctionMetrics, FunctionComparison, FileComparison } from './types.js';

/** Match source function `foo` to output function `_foo`. */
function matchFunctions(
  source: FunctionMetrics[],
  output: FunctionMetrics[],
): { matched: [FunctionMetrics, FunctionMetrics][]; unmatchedSource: string[]; extraOutput: string[] } {
  const outputMap = new Map<string, FunctionMetrics>();
  for (const fn of output) {
    outputMap.set(fn.name, fn);
  }

  const matched: [FunctionMetrics, FunctionMetrics][] = [];
  const unmatchedSource: string[] = [];
  const matchedOutputNames = new Set<string>();

  for (const sfn of source) {
    // Try _name first, then exact name
    const outName = '_' + sfn.name;
    const outFn = outputMap.get(outName) || outputMap.get(sfn.name);
    if (outFn) {
      matched.push([sfn, outFn]);
      matchedOutputNames.add(outFn.name);
    } else {
      unmatchedSource.push(sfn.name);
    }
  }

  const extraOutput = output
    .map(fn => fn.name)
    .filter(name => !matchedOutputNames.has(name));

  return { matched, unmatchedSource, extraOutput };
}

/** Compare a single function pair. */
function compareFunctions(source: FunctionMetrics, output: FunctionMetrics): FunctionComparison {
  const sourceLoops = source.forCount + source.whileCount + source.doWhileCount;
  const outputLoops = output.forCount + output.whileCount + output.doWhileCount;

  const controlFlowMatch =
    source.forCount === output.forCount &&
    source.whileCount === output.whileCount &&
    source.doWhileCount === output.doWhileCount &&
    source.ifCount === output.ifCount &&
    source.switchCount === output.switchCount;

  return {
    sourceName: source.name,
    outputName: output.name,
    paramCountMatch: source.paramCount === output.paramCount,
    controlFlowMatch,
    loopCountDelta: outputLoops - sourceLoops,
    variableRatio: output.variableDeclCount / Math.max(source.variableDeclCount, 1),
    statementRatio: output.statementCount / Math.max(source.statementCount, 1),
    castDensity: output.castCount / Math.max(output.statementCount, 1),
    gotoIntroduced: output.gotoCount,
  };
}

/** Compare source FileMetrics against output FileMetrics. */
export function compareFile(
  source: FileMetrics,
  output: FileMetrics,
  optLevel: string,
): FileComparison {
  const { matched, unmatchedSource, extraOutput } = matchFunctions(
    source.functions,
    output.functions,
  );

  const totalSourceFunctions = source.functions.length;
  const matchedCount = matched.length;

  return {
    sourceFile: source.filename,
    optLevel,
    functionRecoveryRate: totalSourceFunctions > 0 ? matchedCount / totalSourceFunctions : 0,
    matched: matched.map(([s, o]) => compareFunctions(s, o)),
    unmatchedSource,
    extraOutput,
  };
}
