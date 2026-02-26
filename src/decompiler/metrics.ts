/**
 * @file metrics.ts
 * @description SAILR-inspired metrics collection for decompiled functions.
 *
 * Walks the structured block tree (Funcdata.getStructure()) and collects
 * per-function metrics: goto counts, nesting depth, loop/if/switch counts,
 * boolean condition recovery, and label counts.
 */

import { block_type, block_flags } from './block.js';

// Forward types — same pattern used in printc.ts
type FlowBlock = any;
type BlockGraph = any;
type Funcdata = any;

export interface FunctionMetrics {
  name: string;
  gotoCount: number;         // f_goto_goto only
  breakGotoCount: number;    // f_break_goto
  continueGotoCount: number; // f_continue_goto
  maxNestingDepth: number;
  whileCount: number;
  doWhileCount: number;
  ifCount: number;
  switchCount: number;
  labelCount: number;
  boolConditionCount: number; // BlockCondition (&&/||) nodes
  totalBlocks: number;       // Total structured blocks
  infLoopCount: number;      // Infinite loops (loop { })
}

/**
 * Tracks pre-structuring CFG transformations applied by enhanced display mode.
 */
export interface TransformStats {
  returnDuplications: number;  // Blocks split by eager return duplication
  crossJumpReversals: number;  // Blocks split by cross-jump reversal
}

export function createEmptyMetrics(name: string): FunctionMetrics {
  return {
    name,
    gotoCount: 0,
    breakGotoCount: 0,
    continueGotoCount: 0,
    maxNestingDepth: 0,
    whileCount: 0,
    doWhileCount: 0,
    ifCount: 0,
    switchCount: 0,
    labelCount: 0,
    boolConditionCount: 0,
    totalBlocks: 0,
    infLoopCount: 0,
  };
}

export function createEmptyTransformStats(): TransformStats {
  return {
    returnDuplications: 0,
    crossJumpReversals: 0,
  };
}

/**
 * Collect metrics from a decompiled function's structured block tree.
 */
export function collectFunctionMetrics(fd: Funcdata): FunctionMetrics {
  const name: string = fd.getName();
  const metrics = createEmptyMetrics(name);

  if (!fd.isProcStarted() || fd.hasNoStructBlocks()) {
    return metrics;
  }

  const structure: BlockGraph = fd.getStructure();
  walkBlock(structure, 0, metrics);
  return metrics;
}

function walkBlock(bl: FlowBlock, depth: number, metrics: FunctionMetrics): void {
  if (bl == null) return;

  metrics.totalBlocks++;
  const type: number = bl.getType();

  switch (type) {
    case block_type.t_if: { // 8
      metrics.ifCount++;
      // Check if this if-block has a goto target
      const gotoTarget = bl.getGotoTarget != null ? bl.getGotoTarget() : null;
      if (gotoTarget != null) {
        const gotoType: number = bl.getGotoType != null ? bl.getGotoType() : 0;
        classifyGoto(gotoType, metrics);
      }
      break;
    }

    case block_type.t_whiledo: // 9
      metrics.whileCount++;
      break;

    case block_type.t_dowhile: // 10
      metrics.doWhileCount++;
      break;

    case block_type.t_switch: // 11
      metrics.switchCount++;
      // Check case gotos
      if (bl.getNumCaseBlocks != null) {
        const numCases: number = bl.getNumCaseBlocks();
        for (let i = 0; i < numCases; i++) {
          const caseGotoType: number = bl.getCaseGotoType != null ? bl.getCaseGotoType(i) : 0;
          if (caseGotoType !== 0) {
            classifyGoto(caseGotoType, metrics);
          }
        }
      }
      break;

    case block_type.t_infloop: // 12
      metrics.infLoopCount++;
      break;

    case block_type.t_condition: // 7
      metrics.boolConditionCount++;
      break;

    case block_type.t_goto: { // 4
      // BlockGoto has its own goto type
      const gotoType: number = bl.getGotoType != null ? bl.getGotoType() : 0;
      if (bl.gotoPrints != null && bl.gotoPrints()) {
        classifyGoto(gotoType, metrics);
      }
      break;
    }

    case block_type.t_copy: // 3
      // BlockCopy — check for label (unstructured target)
      if (bl.isUnstructuredTarget != null && bl.isUnstructuredTarget()) {
        metrics.labelCount++;
      }
      break;

    default:
      break;
  }

  // Track nesting depth for structured constructs
  const isNesting = (
    type === block_type.t_if ||
    type === block_type.t_whiledo ||
    type === block_type.t_dowhile ||
    type === block_type.t_switch ||
    type === block_type.t_infloop
  );

  const childDepth = isNesting ? depth + 1 : depth;
  if (childDepth > metrics.maxNestingDepth) {
    metrics.maxNestingDepth = childDepth;
  }

  // Recurse into children for graph-like blocks
  if (bl.getSize != null) {
    const size: number = bl.getSize();
    for (let i = 0; i < size; i++) {
      const child = bl.getBlock(i);
      walkBlock(child, childDepth, metrics);
    }
  }
  // BlockCopy wraps a single block
  else if (bl.subBlock != null && type === block_type.t_copy) {
    walkBlock(bl.subBlock(0), childDepth, metrics);
  }
}

function classifyGoto(gotoType: number, metrics: FunctionMetrics): void {
  switch (gotoType) {
    case block_flags.f_goto_goto: // 1
      metrics.gotoCount++;
      break;
    case block_flags.f_break_goto: // 2
      metrics.breakGotoCount++;
      break;
    case block_flags.f_continue_goto: // 4
      metrics.continueGotoCount++;
      break;
  }
}

/**
 * Aggregate metrics across multiple functions.
 */
export interface AggregateMetrics {
  totalFunctions: number;
  totalGotos: number;
  totalBreakGotos: number;
  totalContinueGotos: number;
  maxNestingDepth: number;
  totalWhile: number;
  totalDoWhile: number;
  totalIf: number;
  totalSwitch: number;
  totalLabels: number;
  totalBoolConditions: number;
  totalBlocks: number;
  totalInfLoops: number;
}

export function aggregateMetrics(funcs: FunctionMetrics[]): AggregateMetrics {
  const agg: AggregateMetrics = {
    totalFunctions: funcs.length,
    totalGotos: 0,
    totalBreakGotos: 0,
    totalContinueGotos: 0,
    maxNestingDepth: 0,
    totalWhile: 0,
    totalDoWhile: 0,
    totalIf: 0,
    totalSwitch: 0,
    totalLabels: 0,
    totalBoolConditions: 0,
    totalBlocks: 0,
    totalInfLoops: 0,
  };

  for (const m of funcs) {
    agg.totalGotos += m.gotoCount;
    agg.totalBreakGotos += m.breakGotoCount;
    agg.totalContinueGotos += m.continueGotoCount;
    if (m.maxNestingDepth > agg.maxNestingDepth) {
      agg.maxNestingDepth = m.maxNestingDepth;
    }
    agg.totalWhile += m.whileCount;
    agg.totalDoWhile += m.doWhileCount;
    agg.totalIf += m.ifCount;
    agg.totalSwitch += m.switchCount;
    agg.totalLabels += m.labelCount;
    agg.totalBoolConditions += m.boolConditionCount;
    agg.totalBlocks += m.totalBlocks;
    agg.totalInfLoops += m.infLoopCount;
  }

  return agg;
}

/**
 * Format a metrics table for console output.
 */
export function formatMetricsTable(funcs: FunctionMetrics[]): string {
  const lines: string[] = [];

  // Header
  lines.push(
    padRight('Function', 40) +
    padLeft('Gotos', 7) +
    padLeft('Brk', 5) +
    padLeft('Cont', 6) +
    padLeft('Depth', 7) +
    padLeft('While', 7) +
    padLeft('Do', 5) +
    padLeft('If', 5) +
    padLeft('Swi', 5) +
    padLeft('Bool', 6) +
    padLeft('Lbl', 5)
  );
  lines.push('-'.repeat(96));

  // Only show functions that have gotos or interesting structure
  const interesting = funcs.filter(m =>
    m.gotoCount > 0 || m.breakGotoCount > 0 || m.continueGotoCount > 0 ||
    m.maxNestingDepth >= 3
  );

  for (const m of interesting) {
    lines.push(
      padRight(m.name, 40) +
      padLeft(String(m.gotoCount), 7) +
      padLeft(String(m.breakGotoCount), 5) +
      padLeft(String(m.continueGotoCount), 6) +
      padLeft(String(m.maxNestingDepth), 7) +
      padLeft(String(m.whileCount), 7) +
      padLeft(String(m.doWhileCount), 5) +
      padLeft(String(m.ifCount), 5) +
      padLeft(String(m.switchCount), 5) +
      padLeft(String(m.boolConditionCount), 6) +
      padLeft(String(m.labelCount), 5)
    );
  }

  // Aggregate
  const agg = aggregateMetrics(funcs);
  lines.push('-'.repeat(96));
  lines.push(
    padRight(`TOTAL (${agg.totalFunctions} functions)`, 40) +
    padLeft(String(agg.totalGotos), 7) +
    padLeft(String(agg.totalBreakGotos), 5) +
    padLeft(String(agg.totalContinueGotos), 6) +
    padLeft(String(agg.maxNestingDepth), 7) +
    padLeft(String(agg.totalWhile), 7) +
    padLeft(String(agg.totalDoWhile), 5) +
    padLeft(String(agg.totalIf), 5) +
    padLeft(String(agg.totalSwitch), 5) +
    padLeft(String(agg.totalBoolConditions), 6) +
    padLeft(String(agg.totalLabels), 5)
  );

  return lines.join('\n');
}

function padRight(s: string, w: number): string {
  return s.length >= w ? s.slice(0, w) : s + ' '.repeat(w - s.length);
}

function padLeft(s: string, w: number): string {
  return s.length >= w ? s : ' '.repeat(w - s.length) + s;
}
