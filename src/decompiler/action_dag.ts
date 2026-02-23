/**
 * @file action_dag.ts
 * @description DAG scheduler for intra-function action parallelism.
 *
 * Declares data dependency regions of Funcdata, allows annotating action
 * phases with read/write sets, builds a DAG, and executes independent
 * phases concurrently within wavefronts.
 *
 * The main fixed-point loop (Heritage → Rules → BlockStructure) must remain
 * sequential, but post-loop phases (merge, naming, casts) can potentially
 * overlap when their dependency regions don't conflict.
 */

// ---------------------------------------------------------------------------
// FuncdataRegion
// ---------------------------------------------------------------------------

/**
 * Named regions of a Funcdata that actions may read from or write to.
 * Used to declare data dependencies between action phases.
 */
export enum FuncdataRegion {
  /** PcodeOp graph (insertions, removals, opcode changes) */
  PCODE_OPS = 'PCODE_OPS',
  /** Varnode storage (creation, destruction, property changes) */
  VARNODES = 'VARNODES',
  /** SSA form (heritage, SSA links, def-use chains) */
  SSA = 'SSA',
  /** Basic block graph structure */
  BLOCK_GRAPH = 'BLOCK_GRAPH',
  /** Data types on varnodes and high variables */
  TYPES = 'TYPES',
  /** Symbol table (local variables, parameters, globals) */
  SYMBOLS = 'SYMBOLS',
  /** Comment database */
  COMMENTS = 'COMMENTS',
  /** HighVariable merge groups */
  HIGH_VARIABLES = 'HIGH_VARIABLES',
  /** Merge state (cover, intersections) */
  MERGE_STATE = 'MERGE_STATE',
  /** Cast operations in the output */
  CASTS = 'CASTS',
}

// ---------------------------------------------------------------------------
// ActionDependencyDecl
// ---------------------------------------------------------------------------

/**
 * Declares the data regions an action phase reads from and writes to.
 */
export interface ActionDependencyDecl {
  /** Name of the action (must match Action.getName()) */
  name: string;
  /** Regions this action reads from */
  reads: FuncdataRegion[];
  /** Regions this action writes to */
  writes: FuncdataRegion[];
}

// ---------------------------------------------------------------------------
// DAGNode (internal)
// ---------------------------------------------------------------------------

interface DAGNode {
  index: number;
  decl: ActionDependencyDecl;
  /** Indices of nodes that must run before this one */
  predecessors: Set<number>;
  /** Indices of nodes that depend on this one */
  successors: Set<number>;
}

// ---------------------------------------------------------------------------
// DAGScheduler
// ---------------------------------------------------------------------------

/**
 * Schedules action phases based on declared data dependencies.
 *
 * Given a list of actions with their read/write dependency declarations,
 * builds a DAG where edges represent data hazards:
 * - Write→Read (RAW): if A writes a region that B reads, A must precede B
 * - Write→Write (WAW): if both A and B write the same region, they must be ordered
 * - Read→Write (WAR): if A reads a region that B writes, A must precede B
 *
 * The scheduler produces a topological ordering grouped into parallel
 * wavefronts: all actions within a wavefront can run concurrently.
 */
export class DAGScheduler {
  private nodes: DAGNode[] = [];
  private wavefronts: number[][] = [];

  /**
   * Build the DAG from a list of dependency declarations.
   *
   * Actions are assumed to be provided in their natural sequential order.
   * Dependencies are computed conservatively: any region overlap creates an edge.
   *
   * @param decls list of action dependency declarations, in sequential order
   */
  build(decls: ActionDependencyDecl[]): void {
    this.nodes = [];
    this.wavefronts = [];

    // Create nodes
    for (let i = 0; i < decls.length; i++) {
      this.nodes.push({
        index: i,
        decl: decls[i],
        predecessors: new Set(),
        successors: new Set(),
      });
    }

    // Build edges: for each pair (i, j) where i < j (natural order),
    // add edge i → j if there is a data hazard
    for (let i = 0; i < decls.length; i++) {
      for (let j = i + 1; j < decls.length; j++) {
        if (this.hasDataHazard(decls[i], decls[j])) {
          this.addEdge(i, j);
        }
      }
    }

    // Compute wavefronts via topological sort
    this.computeWavefronts();
  }

  /**
   * Check if two actions have a data hazard that requires ordering.
   */
  private hasDataHazard(a: ActionDependencyDecl, b: ActionDependencyDecl): boolean {
    // RAW: a writes something b reads
    for (const w of a.writes) {
      if (b.reads.includes(w)) return true;
    }
    // WAW: both write the same region
    for (const w of a.writes) {
      if (b.writes.includes(w)) return true;
    }
    // WAR: a reads something b writes
    for (const r of a.reads) {
      if (b.writes.includes(r)) return true;
    }
    return false;
  }

  /**
   * Add a directed edge from node i to node j.
   */
  private addEdge(i: number, j: number): void {
    this.nodes[i].successors.add(j);
    this.nodes[j].predecessors.add(i);
  }

  /**
   * Compute parallel wavefronts using Kahn's algorithm.
   * Each wavefront contains nodes whose predecessors are all in earlier wavefronts.
   */
  private computeWavefronts(): void {
    const inDegree = new Array<number>(this.nodes.length);
    for (let i = 0; i < this.nodes.length; i++) {
      inDegree[i] = this.nodes[i].predecessors.size;
    }

    const remaining = new Set<number>();
    for (let i = 0; i < this.nodes.length; i++) {
      remaining.add(i);
    }

    while (remaining.size > 0) {
      // Find all nodes with zero in-degree (ready to execute)
      const wavefront: number[] = [];
      for (const i of remaining) {
        if (inDegree[i] === 0) {
          wavefront.push(i);
        }
      }

      if (wavefront.length === 0) {
        // Cycle detected — shouldn't happen with correct declarations
        // Fall back to sequential execution of remaining nodes
        const fallback = Array.from(remaining).sort((a, b) => a - b);
        this.wavefronts.push(fallback);
        break;
      }

      // Sort within wavefront by original index for determinism
      wavefront.sort((a, b) => a - b);
      this.wavefronts.push(wavefront);

      // Remove wavefront nodes and update in-degrees
      for (const i of wavefront) {
        remaining.delete(i);
        for (const j of this.nodes[i].successors) {
          inDegree[j]--;
        }
      }
    }
  }

  /**
   * Get the computed parallel wavefronts.
   * Each wavefront is an array of action indices that can run concurrently.
   * Wavefronts must be executed in order.
   *
   * @returns array of wavefronts, where each wavefront is an array of indices
   *          into the original declarations array
   */
  getWavefronts(): ReadonlyArray<ReadonlyArray<number>> {
    return this.wavefronts;
  }

  /**
   * Get the number of wavefronts.
   */
  getWavefrontCount(): number {
    return this.wavefronts.length;
  }

  /**
   * Get the maximum wavefront width (degree of parallelism).
   */
  getMaxParallelism(): number {
    let max = 0;
    for (const wf of this.wavefronts) {
      if (wf.length > max) max = wf.length;
    }
    return max;
  }

  /**
   * Print the schedule for debugging.
   */
  printSchedule(writer: { write(s: string): void }): void {
    for (let w = 0; w < this.wavefronts.length; w++) {
      const names = this.wavefronts[w].map(i => this.nodes[i].decl.name);
      writer.write(`Wave ${w}: [${names.join(', ')}]\n`);
    }
  }
}

// ---------------------------------------------------------------------------
// Pre-built dependency declarations for the post-loop phases
// ---------------------------------------------------------------------------

/**
 * Dependency declarations for the post-mainloop phases of universalAction().
 *
 * These are the phases after the fullloop (Heritage/Rules/BlockStructure)
 * completes, which perform merging, naming, casts, and final structure.
 *
 * Conservative declarations — some could potentially be relaxed with
 * deeper analysis of each action's actual behavior.
 */
export const POST_LOOP_PHASE_DEPS: ActionDependencyDecl[] = [
  {
    name: 'mappedlocalsync',
    reads: [FuncdataRegion.SYMBOLS, FuncdataRegion.VARNODES],
    writes: [FuncdataRegion.SYMBOLS],
  },
  {
    name: 'startcleanup',
    reads: [FuncdataRegion.VARNODES],
    writes: [FuncdataRegion.VARNODES],
  },
  {
    name: 'cleanup',
    reads: [FuncdataRegion.PCODE_OPS, FuncdataRegion.VARNODES, FuncdataRegion.TYPES],
    writes: [FuncdataRegion.PCODE_OPS, FuncdataRegion.VARNODES],
  },
  {
    name: 'prefercomplement',
    reads: [FuncdataRegion.BLOCK_GRAPH],
    writes: [FuncdataRegion.BLOCK_GRAPH],
  },
  {
    name: 'structuretransform',
    reads: [FuncdataRegion.BLOCK_GRAPH],
    writes: [FuncdataRegion.BLOCK_GRAPH],
  },
  {
    name: 'normalizebranches',
    reads: [FuncdataRegion.BLOCK_GRAPH, FuncdataRegion.PCODE_OPS],
    writes: [FuncdataRegion.BLOCK_GRAPH],
  },
  {
    name: 'assignhigh',
    reads: [FuncdataRegion.VARNODES],
    writes: [FuncdataRegion.HIGH_VARIABLES],
  },
  {
    name: 'mergerequired',
    reads: [FuncdataRegion.HIGH_VARIABLES, FuncdataRegion.VARNODES],
    writes: [FuncdataRegion.MERGE_STATE],
  },
  {
    name: 'markexplicit',
    reads: [FuncdataRegion.VARNODES, FuncdataRegion.PCODE_OPS],
    writes: [FuncdataRegion.VARNODES],
  },
  {
    name: 'markimplied',
    reads: [FuncdataRegion.VARNODES, FuncdataRegion.PCODE_OPS, FuncdataRegion.HIGH_VARIABLES],
    writes: [FuncdataRegion.VARNODES],
  },
  {
    name: 'mergemultientry',
    reads: [FuncdataRegion.HIGH_VARIABLES, FuncdataRegion.MERGE_STATE],
    writes: [FuncdataRegion.MERGE_STATE],
  },
  {
    name: 'mergecopy',
    reads: [FuncdataRegion.HIGH_VARIABLES, FuncdataRegion.MERGE_STATE],
    writes: [FuncdataRegion.MERGE_STATE],
  },
  {
    name: 'dominantcopy',
    reads: [FuncdataRegion.HIGH_VARIABLES, FuncdataRegion.MERGE_STATE],
    writes: [FuncdataRegion.MERGE_STATE],
  },
  {
    name: 'dynamicsymbols1',
    reads: [FuncdataRegion.SYMBOLS, FuncdataRegion.VARNODES],
    writes: [FuncdataRegion.SYMBOLS],
  },
  {
    name: 'markindirectonly',
    reads: [FuncdataRegion.VARNODES, FuncdataRegion.MERGE_STATE],
    writes: [FuncdataRegion.VARNODES],
  },
  {
    name: 'mergeadjacent',
    reads: [FuncdataRegion.HIGH_VARIABLES, FuncdataRegion.MERGE_STATE],
    writes: [FuncdataRegion.MERGE_STATE],
  },
  {
    name: 'mergetype',
    reads: [FuncdataRegion.HIGH_VARIABLES, FuncdataRegion.MERGE_STATE, FuncdataRegion.TYPES],
    writes: [FuncdataRegion.MERGE_STATE],
  },
  {
    name: 'hideshadow',
    reads: [FuncdataRegion.HIGH_VARIABLES, FuncdataRegion.MERGE_STATE],
    writes: [FuncdataRegion.MERGE_STATE],
  },
  {
    name: 'copymarker',
    reads: [FuncdataRegion.VARNODES, FuncdataRegion.PCODE_OPS],
    writes: [FuncdataRegion.PCODE_OPS],
  },
  {
    name: 'outputprototype',
    reads: [FuncdataRegion.SYMBOLS, FuncdataRegion.TYPES],
    writes: [FuncdataRegion.SYMBOLS],
  },
  {
    name: 'inputprototype',
    reads: [FuncdataRegion.SYMBOLS, FuncdataRegion.TYPES],
    writes: [FuncdataRegion.SYMBOLS],
  },
  {
    name: 'mapglobals',
    reads: [FuncdataRegion.SYMBOLS, FuncdataRegion.VARNODES],
    writes: [FuncdataRegion.SYMBOLS],
  },
  {
    name: 'dynamicsymbols2',
    reads: [FuncdataRegion.SYMBOLS, FuncdataRegion.VARNODES],
    writes: [FuncdataRegion.SYMBOLS],
  },
  {
    name: 'namevars',
    reads: [FuncdataRegion.SYMBOLS, FuncdataRegion.HIGH_VARIABLES],
    writes: [FuncdataRegion.SYMBOLS],
  },
  {
    name: 'setcasts',
    reads: [FuncdataRegion.TYPES, FuncdataRegion.PCODE_OPS, FuncdataRegion.VARNODES],
    writes: [FuncdataRegion.CASTS, FuncdataRegion.PCODE_OPS],
  },
  {
    name: 'finalstructure',
    reads: [FuncdataRegion.BLOCK_GRAPH],
    writes: [FuncdataRegion.BLOCK_GRAPH],
  },
  {
    name: 'prototypewarnings',
    reads: [FuncdataRegion.SYMBOLS],
    writes: [FuncdataRegion.COMMENTS],
  },
  {
    name: 'stop',
    reads: [FuncdataRegion.PCODE_OPS, FuncdataRegion.VARNODES],
    writes: [],
  },
];
