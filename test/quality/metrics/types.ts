/** Shared interfaces for source-fidelity metrics. */

export interface FunctionMetrics {
  name: string;
  returnType: string;
  paramCount: number;
  paramTypes: string[];
  forCount: number;
  whileCount: number;
  doWhileCount: number;
  ifCount: number;
  elseCount: number;
  switchCount: number;
  caseCount: number;
  gotoCount: number;
  returnCount: number;
  breakCount: number;
  continueCount: number;
  variableDeclCount: number;
  maxNestingDepth: number;
  lineCount: number;
  statementCount: number;
  incrementCount: number;
  decrementCount: number;
  compoundAssignCount: number;
  arraySubscriptCount: number;
  arrowCount: number;
  ternaryCount: number;
  castCount: number;
}

export interface FileMetrics {
  filename: string;
  functions: FunctionMetrics[];
}

export interface FunctionComparison {
  sourceName: string;
  outputName: string;
  paramCountMatch: boolean;
  controlFlowMatch: boolean;
  loopCountDelta: number;
  variableRatio: number;
  statementRatio: number;
  castDensity: number;
  gotoIntroduced: number;
}

export interface FileComparison {
  sourceFile: string;
  optLevel: string;
  functionRecoveryRate: number;
  matched: FunctionComparison[];
  unmatchedSource: string[];
  extraOutput: string[];
}
