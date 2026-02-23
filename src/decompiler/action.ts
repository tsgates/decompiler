/**
 * @file action.ts
 * @description Action, Rule, and other associated classes supporting transformations
 * on function data-flow. Translated from Ghidra's action.hh / action.cc.
 */

import type { int4, uint4 } from '../core/types.js';
import { OPACTION_DEBUG } from '../core/types.js';
import { OpCode } from '../core/opcodes.js';
import { LowlevelError } from '../core/error.js';

// ---------------------------------------------------------------------------
// Forward type declarations for types from not-yet-written modules
// ---------------------------------------------------------------------------

type Funcdata = any;        // From funcdata.ts (not yet written)
type Architecture = any;    // From architecture.ts (not yet written)
type PcodeOp = any;         // From op.ts
type PrintLanguage = any;   // From printlanguage.ts (not yet written)

// ---------------------------------------------------------------------------
// Writer interface (replaces C++ ostream)
// ---------------------------------------------------------------------------

interface Writer {
  write(s: string): void;
}

// ---------------------------------------------------------------------------
// CPUI_MAX constant
// ---------------------------------------------------------------------------

const CPUI_MAX = OpCode.CPUI_MAX;

// ---------------------------------------------------------------------------
// Helper function
// ---------------------------------------------------------------------------

/**
 * Pull the next token from a ':' separated list of Action and Rule names.
 * @param specify the list to pull the token from
 * @returns an object with `token` (the string up to the next ':') and `remain` (what's left)
 */
function nextSpecifyTerm(specify: string): { token: string; remain: string } {
  const res = specify.indexOf(':');
  if (res !== -1) {
    return {
      token: specify.substring(0, res),
      remain: specify.substring(res + 1),
    };
  } else {
    return {
      token: specify,
      remain: '',
    };
  }
}

// ---------------------------------------------------------------------------
// ActionGroupList
// ---------------------------------------------------------------------------

/**
 * The list of groups defining a root Action.
 *
 * Any Rule or leaf Action belongs to a group. This class is a grouplist
 * defined by a collection of these group names. The set of Rule and Action
 * objects belong to any of the groups in this list together form a root Action.
 */
export class ActionGroupList {
  list: Set<string> = new Set<string>();

  /**
   * Check if this ActionGroupList contains a given group.
   * @param nm the given group to check for
   * @returns true if this contains the group
   */
  contains(nm: string): boolean {
    return this.list.has(nm);
  }
}

// ---------------------------------------------------------------------------
// Action
// ---------------------------------------------------------------------------

/**
 * Large scale transformations applied to the varnode/op graph.
 *
 * The base for objects that make changes to the syntax tree of a Funcdata.
 * The action is invoked through the apply(data) method. This base class
 * keeps track of basic statistics about how the action is being applied.
 * Derived classes indicate that a change has been applied by incrementing
 * the count field.
 */
export abstract class Action {
  // Boolean behavior properties governing this particular Action
  static readonly rule_repeatapply = 4;
  static readonly rule_onceperfunc = 8;
  static readonly rule_oneactperfunc = 16;
  static readonly rule_debug = 32;
  static readonly rule_warnings_on = 64;
  static readonly rule_warnings_given = 128;

  // Boolean properties describing the status of an action
  static readonly status_start = 1;
  static readonly status_breakstarthit = 2;
  static readonly status_repeat = 4;
  static readonly status_mid = 8;
  static readonly status_end = 16;
  static readonly status_actionbreak = 32;

  // Break points associated with an Action
  static readonly break_start = 1;
  static readonly tmpbreak_start = 2;
  static readonly break_action = 4;
  static readonly tmpbreak_action = 8;

  protected lcount: number;          // Changes not including last call to apply()
  protected count: number;           // Number of changes made by this action so far
  protected status: number;          // Current status
  protected breakpoint: number;      // Breakpoint properties
  protected flags: number;           // Behavior properties
  protected count_tests: number;     // Number of times apply() has been called
  protected count_apply: number;     // Number of times apply() made changes
  protected name: string;            // Name of the action
  protected basegroup: string;       // Base group this action belongs to

  /**
   * Base constructor for an Action.
   * @param f collection of property flags
   * @param nm Action name
   * @param g Action group
   */
  constructor(f: number, nm: string, g: string) {
    this.flags = f;
    this.status = Action.status_start;
    this.breakpoint = 0;
    this.name = nm;
    this.basegroup = g;
    this.count_tests = 0;
    this.count_apply = 0;
    this.lcount = 0;
    this.count = 0;
  }

  /**
   * Warn that this Action has applied.
   * If enabled, issue a warning that this Action has been applied.
   * @param glb the controlling Architecture
   */
  protected issueWarning(glb: Architecture): void {
    if ((this.flags & (Action.rule_warnings_on | Action.rule_warnings_given)) === Action.rule_warnings_on) {
      this.flags |= Action.rule_warnings_given;
      glb.printMessage("WARNING: Applied action " + this.name);
    }
  }

  /**
   * Check start breakpoint.
   * @returns true if there was a start breakpoint
   */
  protected checkStartBreak(): boolean {
    if ((this.breakpoint & (Action.break_start | Action.tmpbreak_start)) !== 0) {
      this.breakpoint &= ~(Action.tmpbreak_start);
      return true;
    }
    return false;
  }

  /**
   * Check action breakpoint.
   * @returns true if there was an action breakpoint
   */
  protected checkActionBreak(): boolean {
    if ((this.breakpoint & (Action.break_action | Action.tmpbreak_action)) !== 0) {
      this.breakpoint &= ~(Action.tmpbreak_action);
      return true;
    }
    return false;
  }

  /** Enable warnings for this Action */
  protected turnOnWarnings(): void {
    this.flags |= Action.rule_warnings_on;
  }

  /** Disable warnings for this Action */
  protected turnOffWarnings(): void {
    this.flags &= ~Action.rule_warnings_on;
  }

  /**
   * If this Action matches the given name, enable debugging.
   * @param nm the Action name to match
   * @returns true if debugging was enabled
   */
  turnOnDebug(nm: string): boolean {
    if (nm === this.name) {
      this.flags |= Action.rule_debug;
      return true;
    }
    return false;
  }

  /**
   * If this Action matches the given name, disable debugging.
   * @param nm the Action name to match
   * @returns true if debugging was disabled
   */
  turnOffDebug(nm: string): boolean {
    if (nm === this.name) {
      this.flags &= ~Action.rule_debug;
      return true;
    }
    return false;
  }

  /**
   * Dump statistics to stream.
   * @param s the output stream
   */
  printStatistics(s: { write(s: string): void }): void {
    s.write(this.name + " Tested=" + this.count_tests + " Applied=" + this.count_apply + "\n");
  }

  /**
   * Perform this action (if necessary).
   * Run this Action until completion or a breakpoint occurs. Depending
   * on the behavior properties of this instance, the apply() method may
   * get called many times or none. Generally the number of changes made
   * by the action is returned, but if a breakpoint occurs -1 is returned.
   * A successive call to perform() will "continue" from the break point.
   * @param data the function being acted on
   * @returns the number of changes or -1
   */
  perform(data: Funcdata): number {
    let res: number;

    do {
      switch (this.status) {
        case Action.status_start:
          this.count = 0;
          if (this.checkStartBreak()) {
            this.status = Action.status_breakstarthit;
            return -1;
          }
          this.count_tests += 1;
        // fall through
        case Action.status_breakstarthit:
        case Action.status_repeat:
          this.lcount = this.count;
        // fall through
        case Action.status_mid:
          if (OPACTION_DEBUG) {
            data.debugActivate();
          }
          res = this.apply(data);
          if (OPACTION_DEBUG) {
            data.debugModPrint(this.getName());
          }
          if (res < 0) {
            this.status = Action.status_mid;
            return res;
          } else if (this.lcount < this.count) {
            this.issueWarning(data.getArch());
            this.count_apply += 1;
            if (this.checkActionBreak()) {
              this.status = Action.status_actionbreak;
              return -1;
            }
            if (OPACTION_DEBUG) {
              if (data.debugBreak()) {
                this.status = Action.status_actionbreak;
                data.debugHandleBreak();
                return -1;
              }
            }
          }
          break;
        case Action.status_end:
          return 0;
        case Action.status_actionbreak:
          break;
      }
      this.status = Action.status_repeat;
    } while ((this.lcount < this.count) && ((this.flags & Action.rule_repeatapply) !== 0));

    if ((this.flags & (Action.rule_onceperfunc | Action.rule_oneactperfunc)) !== 0) {
      if ((this.count > 0) || ((this.flags & Action.rule_onceperfunc) !== 0))
        this.status = Action.status_end;
      else
        this.status = Action.status_start;
    } else {
      this.status = Action.status_start;
    }

    return this.count;
  }

  /**
   * Set a breakpoint on this action.
   * @param tp type of breakpoint
   * @param specify the (possibly sub)action to apply the break point to
   * @returns true if a breakpoint was successfully set
   */
  setBreakPoint(tp: number, specify: string): boolean {
    const res = this.getSubAction(specify);
    if (res !== null) {
      res.breakpoint |= tp;
      return true;
    }
    const rule = this.getSubRule(specify);
    if (rule !== null) {
      rule.setBreak(tp);
      return true;
    }
    return false;
  }

  /** Clear all breakpoints set on this Action */
  clearBreakPoints(): void {
    this.breakpoint = 0;
  }

  /**
   * Set a warning on this action.
   * @param val toggle value for the warning
   * @param specify name of the action or sub-action to toggle
   * @returns true if the warning was successfully toggled
   */
  setWarning(val: boolean, specify: string): boolean {
    const res = this.getSubAction(specify);
    if (res !== null) {
      if (val)
        res.turnOnWarnings();
      else
        res.turnOffWarnings();
      return true;
    }
    const rule = this.getSubRule(specify);
    if (rule !== null) {
      if (val)
        rule.turnOnWarnings();
      else
        rule.turnOffWarnings();
      return true;
    }
    return false;
  }

  /**
   * Disable a specific Rule within this.
   * @param specify name path
   * @returns true if the Rule is successfully disabled
   */
  disableRule(specify: string): boolean {
    const rule = this.getSubRule(specify);
    if (rule !== null) {
      rule.setDisable();
      return true;
    }
    return false;
  }

  /**
   * Enable a specific Rule within this.
   * @param specify name path
   * @returns true if the Rule is successfully enabled
   */
  enableRule(specify: string): boolean {
    const rule = this.getSubRule(specify);
    if (rule !== null) {
      rule.clearDisable();
      return true;
    }
    return false;
  }

  /** Get the Action's name */
  getName(): string { return this.name; }

  /** Get the Action's group */
  getGroup(): string { return this.basegroup; }

  /** Get the current status of this Action */
  getStatus(): number { return this.status; }

  /** Get the number of times apply() was invoked */
  getNumTests(): number { return this.count_tests; }

  /** Get the number of times apply() made changes */
  getNumApply(): number { return this.count_apply; }

  /**
   * Clone the Action.
   * If this Action is a member of one of the groups in the grouplist,
   * this returns a clone of the Action, otherwise null is returned.
   * @param grouplist the list of groups being cloned
   * @returns the cloned Action or null
   */
  abstract clone(grouplist: ActionGroupList): Action | null;

  /**
   * Reset the Action for a new function.
   * @param data the new function this Action may affect
   */
  reset(data: Funcdata): void {
    this.status = Action.status_start;
    this.flags &= ~Action.rule_warnings_given;
  }

  /** Reset the statistics */
  resetStats(): void {
    this.count_tests = 0;
    this.count_apply = 0;
  }

  /**
   * Make a single attempt to apply this Action.
   * This is the main entry point for applying changes to a function that
   * are specific to this Action. The method can inspect whatever it wants
   * to decide if the Action does or does not apply. Changes are indicated
   * by incrementing the count field.
   * @param data the function to inspect/modify
   * @returns 0 for a complete application, -1 for a partial completion (due to breakpoint)
   */
  abstract apply(data: Funcdata): number;

  /**
   * Print a description of this Action to stream.
   * @param s the output stream
   * @param num starting index to associate with the action
   * @param depth amount of indent necessary before printing
   * @returns the next available index
   */
  print(s: { write(s: string): void }, num: number, depth: number): number {
    const numStr = String(num).padStart(4, ' ');
    s.write(numStr);
    s.write(((this.flags & Action.rule_repeatapply) !== 0) ? " repeat " : "        ");
    s.write(((this.flags & Action.rule_onceperfunc) !== 0) ? '!' : ' ');
    s.write(((this.breakpoint & (Action.break_start | Action.tmpbreak_start)) !== 0) ? 'S' : ' ');
    s.write(((this.breakpoint & (Action.break_action | Action.tmpbreak_action)) !== 0) ? 'A' : ' ');
    for (let i = 0; i < depth * 5 + 2; ++i)
      s.write(' ');
    s.write(this.name);
    return num + 1;
  }

  /**
   * Print status to stream.
   * @param s the output stream
   */
  printState(s: { write(s: string): void }): void {
    s.write(this.name);
    switch (this.status) {
      case Action.status_repeat:
      case Action.status_breakstarthit:
      case Action.status_start:
        s.write(" start");
        break;
      case Action.status_mid:
        s.write(':');
        break;
      case Action.status_end:
        s.write(" end");
        break;
    }
  }

  /**
   * Retrieve a specific sub-action by name.
   * If this Action matches the given name, it is returned.
   * @param specify the action name to match
   * @returns the matching Action or null
   */
  getSubAction(specify: string): Action | null {
    if (this.name === specify) return this;
    return null;
  }

  /**
   * Retrieve a specific sub-rule by name.
   * @param specify the name of the rule
   * @returns the matching sub-rule or null
   */
  getSubRule(specify: string): Rule | null {
    return null;
  }
}

// ---------------------------------------------------------------------------
// ActionGroup
// ---------------------------------------------------------------------------

/**
 * A group of actions (generally) applied in sequence.
 *
 * This is a list of Action objects, which are usually applied in sequence.
 * But the behavior properties of each individual Action may affect this.
 * Properties (like rule_repeatapply) may be put directly to this group
 * that also affect how the Actions are applied.
 */
export class ActionGroup extends Action {
  protected list: Action[] = [];
  protected stateIndex: number = 0;    // Current action index being applied (replaces C++ iterator)

  /**
   * Construct given properties and a name.
   * @param f property flags
   * @param nm group name
   */
  constructor(f: number, nm: string) {
    super(f, nm, "");
  }

  /**
   * Add an Action to the group.
   * To be used only during the construction of this ActionGroup.
   * @param ac the Action to add
   */
  addAction(ac: Action): void {
    this.list.push(ac);
  }

  clearBreakPoints(): void {
    for (const ac of this.list)
      ac.clearBreakPoints();
    super.clearBreakPoints();
  }

  clone(grouplist: ActionGroupList): Action | null {
    let res: ActionGroup | null = null;
    for (const ac of this.list) {
      const cloned = ac.clone(grouplist);
      if (cloned !== null) {
        if (res === null)
          res = new ActionGroup(this.flags, this.getName());
        res.addAction(cloned);
      }
    }
    return res;
  }

  reset(data: Funcdata): void {
    super.reset(data);
    for (const ac of this.list)
      ac.reset(data);
  }

  resetStats(): void {
    super.resetStats();
    for (const ac of this.list)
      ac.resetStats();
  }

  apply(data: Funcdata): number {
    let res: number;

    if (this.status !== Action.status_mid)
      this.stateIndex = 0;
    for (; this.stateIndex < this.list.length; ++this.stateIndex) {
      res = this.list[this.stateIndex].perform(data);
      if (res > 0) {
        this.count += res;
        if (this.checkActionBreak()) {
          ++this.stateIndex;
          return -1;
        }
      } else if (res < 0) {
        return -1;
      }
    }

    return 0;
  }

  print(s: { write(s: string): void }, num: number, depth: number): number {
    num = super.print(s, num, depth);
    s.write("\n");
    for (let i = 0; i < this.list.length; i++) {
      num = this.list[i].print(s, num, depth + 1);
      if (this.stateIndex === i)
        s.write("  <-- ");
      s.write("\n");
    }
    return num;
  }

  printState(s: { write(s: string): void }): void {
    super.printState(s);
    if (this.status === Action.status_mid) {
      const subact = this.list[this.stateIndex];
      subact.printState(s);
    }
  }

  getSubAction(specify: string): Action | null {
    const { token, remain } = nextSpecifyTerm(specify);
    let searchStr: string;
    if (this.name === token) {
      if (remain === '') return this;
      searchStr = remain;
    } else {
      searchStr = specify;
    }

    let lastaction: Action | null = null;
    let matchcount = 0;
    for (const ac of this.list) {
      const testaction = ac.getSubAction(searchStr);
      if (testaction !== null) {
        lastaction = testaction;
        matchcount += 1;
        if (matchcount > 1) return null;
      }
    }
    return lastaction;
  }

  getSubRule(specify: string): Rule | null {
    const { token, remain } = nextSpecifyTerm(specify);
    let searchStr: string;
    if (this.name === token) {
      if (remain === '') return null;
      searchStr = remain;
    } else {
      searchStr = specify;
    }

    let lastrule: Rule | null = null;
    let matchcount = 0;
    for (const ac of this.list) {
      const testrule = ac.getSubRule(searchStr);
      if (testrule !== null) {
        lastrule = testrule;
        matchcount += 1;
        if (matchcount > 1) return null;
      }
    }
    return lastrule;
  }

  turnOnDebug(nm: string): boolean {
    if (super.turnOnDebug(nm))
      return true;
    for (const ac of this.list)
      if (ac.turnOnDebug(nm))
        return true;
    return false;
  }

  turnOffDebug(nm: string): boolean {
    if (super.turnOffDebug(nm))
      return true;
    for (const ac of this.list)
      if (ac.turnOffDebug(nm))
        return true;
    return false;
  }

  printStatistics(s: { write(s: string): void }): void {
    super.printStatistics(s);
    for (const ac of this.list)
      ac.printStatistics(s);
  }
}

// ---------------------------------------------------------------------------
// ActionRestartGroup
// ---------------------------------------------------------------------------

/**
 * Action which checks if restart (sub)actions have been generated and
 * restarts itself.
 *
 * Actions or Rules can request a restart on a Funcdata object by calling
 * setRestartPending(true) on it. This action checks for the request then
 * resets and reruns the group of Actions as appropriate.
 */
export class ActionRestartGroup extends ActionGroup {
  private maxrestarts: number;
  private curstart: number = 0;

  /**
   * Construct providing maximum number of restarts.
   * @param f property flags
   * @param nm group name
   * @param max maximum number of restarts allowed
   */
  constructor(f: number, nm: string, max: number) {
    super(f, nm);
    this.maxrestarts = max;
  }

  clone(grouplist: ActionGroupList): Action | null {
    let res: ActionGroup | null = null;
    for (const ac of this.list) {
      const cloned = ac.clone(grouplist);
      if (cloned !== null) {
        if (res === null)
          res = new ActionRestartGroup(this.flags, this.getName(), this.maxrestarts);
        res.addAction(cloned);
      }
    }
    return res;
  }

  reset(data: Funcdata): void {
    this.curstart = 0;
    super.reset(data);
  }

  apply(data: Funcdata): number {
    let res: number;

    if (this.curstart === -1) return 0;  // Already completed
    for (;;) {
      res = super.apply(data);
      if (res !== 0) return res;
      if (!data.hasRestartPending()) {
        this.curstart = -1;
        return 0;
      }
      if (data.isJumptableRecoveryOn())  // Don't restart within jumptable recovery
        return 0;
      this.curstart += 1;
      if (this.curstart > this.maxrestarts) {
        data.warningHeader("Exceeded maximum restarts with more pending");
        this.curstart = -1;
        return 0;
      }
      data.getArch().clearAnalysis(data);

      // Reset everything but ourselves
      for (const ac of this.list)
        ac.reset(data);
      this.status = Action.status_start;
    }
  }
}

// ---------------------------------------------------------------------------
// Rule
// ---------------------------------------------------------------------------

/**
 * Class for performing a single transformation on a PcodeOp or Varnode.
 *
 * A Rule, through its applyOp() method, is handed a specific PcodeOp as a
 * potential point to apply. It determines if it can apply at that point, then
 * makes any changes. Rules inform the system of what types of PcodeOps they
 * can possibly apply to through the getOpList() method. A set of Rules are
 * pooled together into a single Action via the ActionPool, which efficiently
 * applies each Rule across a whole function. A Rule supports the same
 * breakpoint properties as an Action. A Rule is allowed to keep state that
 * is specific to a given function (Funcdata). The reset() method is invoked
 * to purge this state for each new function to be transformed.
 */
export abstract class Rule {
  // Properties associated with a Rule
  static readonly type_disable = 1;
  static readonly rule_debug = 2;
  static readonly warnings_on = 4;
  static readonly warnings_given = 8;

  private flags: number;
  private breakpoint_: number;
  private name: string;
  private basegroup: string;
  count_tests: number;    // public for ActionPool access (friend in C++)
  count_apply: number;    // public for ActionPool access (friend in C++)

  /**
   * Construct given group, properties, and name.
   * @param g the group name
   * @param fl property flags
   * @param nm rule name
   */
  constructor(g: string, fl: number, nm: string) {
    this.flags = fl;
    this.name = nm;
    this.breakpoint_ = 0;
    this.basegroup = g;
    this.count_tests = 0;
    this.count_apply = 0;
  }

  /** Return the name of this Rule */
  getName(): string { return this.name; }

  /** Return the group this Rule belongs to */
  getGroup(): string { return this.basegroup; }

  /** Get number of attempted applications */
  getNumTests(): number { return this.count_tests; }

  /** Get number of successful applications */
  getNumApply(): number { return this.count_apply; }

  /** Set a breakpoint on this Rule */
  setBreak(tp: number): void { this.breakpoint_ |= tp; }

  /** Clear a breakpoint on this Rule */
  clearBreak(tp: number): void { this.breakpoint_ &= ~tp; }

  /** Clear all breakpoints on this Rule */
  clearBreakPoints(): void { this.breakpoint_ = 0; }

  /** Enable warnings for this Rule */
  turnOnWarnings(): void { this.flags |= Rule.warnings_on; }

  /** Disable warnings for this Rule */
  turnOffWarnings(): void { this.flags &= ~Rule.warnings_on; }

  /** Return true if this Rule is disabled */
  isDisabled(): boolean { return (this.flags & Rule.type_disable) !== 0; }

  /** Disable this Rule (within its pool) */
  setDisable(): void { this.flags |= Rule.type_disable; }

  /** Enable this Rule (within its pool) */
  clearDisable(): void { this.flags &= ~Rule.type_disable; }

  /**
   * Check if an action breakpoint is turned on.
   * This method is called every time the Rule successfully applies. If it
   * returns true, this indicates to the system that an action breakpoint
   * has occurred.
   * @returns true if an action breakpoint should occur
   */
  checkActionBreak(): boolean {
    if ((this.breakpoint_ & (Action.break_action | Action.tmpbreak_action)) !== 0) {
      this.breakpoint_ &= ~(Action.tmpbreak_action);
      return true;
    }
    return false;
  }

  /** Return breakpoint toggles */
  getBreakPoint(): number { return this.breakpoint_; }

  /**
   * If enabled, print a warning that this Rule has been applied.
   * @param glb the Architecture
   */
  issueWarning(glb: Architecture): void {
    if ((this.flags & (Rule.warnings_on | Rule.warnings_given)) === Rule.warnings_on) {
      this.flags |= Rule.warnings_given;
      glb.printMessage("WARNING: Applied rule " + this.name);
    }
  }

  /**
   * Clone the Rule.
   * If this Rule is a member of one of the groups in the grouplist,
   * this returns a clone of the Rule, otherwise null is returned.
   * @param grouplist the list of groups being cloned
   * @returns the cloned Rule or null
   */
  abstract clone(grouplist: ActionGroupList): Rule | null;

  /**
   * List of op codes this rule operates on.
   * Populate the given array with all possible OpCodes this Rule might apply to.
   * By default, this method returns all possible OpCodes.
   * @param oplist the array to populate
   */
  getOpList(oplist: number[]): void {
    for (let i = 0; i < CPUI_MAX; ++i)
      oplist.push(i);
  }

  /**
   * Attempt to apply this Rule.
   * This method contains the main logic for applying the Rule. It must use
   * a given PcodeOp as the point at which the Rule applies. If it does apply,
   * changes are made directly to the function and 1 (non-zero) is returned,
   * otherwise 0 is returned.
   * @param op the given PcodeOp where the Rule may apply
   * @param data the function to which to apply
   * @returns non-zero if the rule applied
   */
  applyOp(op: PcodeOp, data: Funcdata): number { return 0; }

  /**
   * Reset this Rule.
   * Any state that is specific to a particular function is cleared.
   * @param data the new function about to be transformed
   */
  reset(data: Funcdata): void {
    this.flags &= ~Rule.warnings_given;
  }

  /** Reset Rule statistics */
  resetStats(): void {
    this.count_tests = 0;
    this.count_apply = 0;
  }

  /**
   * Print statistics for this Rule.
   * @param s the output stream
   */
  printStatistics(s: { write(s: string): void }): void {
    s.write(this.name + " Tested=" + this.count_tests + " Applied=" + this.count_apply + "\n");
  }

  /**
   * Turn on debugging.
   * @param nm the Rule name to match
   * @returns true if debugging was enabled
   */
  turnOnDebug(nm: string): boolean {
    if (nm === this.name) {
      this.flags |= Rule.rule_debug;
      return true;
    }
    return false;
  }

  /**
   * Turn off debugging.
   * @param nm the Rule name to match
   * @returns true if debugging was disabled
   */
  turnOffDebug(nm: string): boolean {
    if (nm === this.name) {
      this.flags &= ~Rule.rule_debug;
      return true;
    }
    return false;
  }
}

// ---------------------------------------------------------------------------
// ActionPool
// ---------------------------------------------------------------------------

/**
 * A pool of Rules that apply simultaneously.
 *
 * This class groups together a set of Rules as a formal Action.
 * Rules are given an opportunity to apply to every PcodeOp in a function.
 * Usually rule_repeatapply is enabled for this action, which causes
 * all Rules to apply repeatedly until no Rule can make an additional change.
 */
export class ActionPool extends Action {
  private allrules: Rule[] = [];
  private perop: Rule[][] = [];
  private op_state: any = null;     // Iterator state for PcodeOp traversal
  private rule_index: number = 0;

  /**
   * Construct providing properties and name.
   * @param f property flags
   * @param nm pool name
   */
  constructor(f: number, nm: string) {
    super(f, nm, "");
    // Initialize perop arrays for each opcode
    for (let i = 0; i < CPUI_MAX; ++i) {
      this.perop.push([]);
    }
  }

  /**
   * Add a Rule to the pool.
   * This method should only be invoked during construction of this ActionPool.
   * @param rl the Rule to add
   */
  addRule(rl: Rule): void {
    const oplist: number[] = [];
    this.allrules.push(rl);
    rl.getOpList(oplist);
    for (const opc of oplist) {
      this.perop[opc].push(rl);
    }
  }

  /**
   * Apply the next possible Rule to a PcodeOp.
   * This method attempts to apply each Rule to the current PcodeOp.
   * Action breakpoints are checked if the Rule successfully applies.
   * @param op the current PcodeOp
   * @param data the function being transformed
   * @returns 0 if no breakpoint, -1 otherwise
   */
  private processOp(op: PcodeOp, data: Funcdata): number {
    let rl: Rule;
    let res: number;
    let opc: number;

    if (op.isDead()) {
      this.op_state.next();
      data.opDeadAndGone(op);
      this.rule_index = 0;
      return 0;
    }
    opc = op.code();
    while (this.rule_index < this.perop[opc].length) {
      rl = this.perop[opc][this.rule_index++];
      if (rl.isDisabled()) continue;
      if (OPACTION_DEBUG) {
        data.debugActivate();
      }
      rl.count_tests += 1;
      res = rl.applyOp(op, data);
      if (OPACTION_DEBUG) {
        data.debugModPrint(rl.getName());
      }
      if (res > 0) {
        rl.count_apply += 1;
        this.count += res;
        rl.issueWarning(data.getArch());
        if (rl.checkActionBreak())
          return -1;
        if (OPACTION_DEBUG) {
          if (data.debugBreak()) {
            data.debugHandleBreak();
            return -1;
          }
        }
        if (op.isDead()) break;
        if (opc !== op.code()) {
          opc = op.code();
          this.rule_index = 0;
        }
      } else if (opc !== op.code()) {
        data.getArch().printMessage("ERROR: Rule " + rl.getName() + " changed op without returning result of 1!");
        opc = op.code();
        this.rule_index = 0;
      }
    }
    this.op_state.next();
    this.rule_index = 0;

    return 0;
  }

  apply(data: Funcdata): number {
    if (this.status !== Action.status_mid) {
      this.op_state = data.beginOpAll();
      this.rule_index = 0;
    }
    while (!this.op_state.isEnd) {
      const op = this.op_state.get();
      if (this.processOp(op, data) !== 0) return -1;
    }

    return 0;
  }

  clearBreakPoints(): void {
    for (const rl of this.allrules)
      rl.clearBreakPoints();
    super.clearBreakPoints();
  }

  clone(grouplist: ActionGroupList): Action | null {
    let res: ActionPool | null = null;
    for (const rl of this.allrules) {
      const cloned = rl.clone(grouplist);
      if (cloned !== null) {
        if (res === null)
          res = new ActionPool(this.flags, this.getName());
        res.addRule(cloned);
      }
    }
    return res;
  }

  reset(data: Funcdata): void {
    super.reset(data);
    for (const rl of this.allrules)
      rl.reset(data);
  }

  resetStats(): void {
    super.resetStats();
    for (const rl of this.allrules)
      rl.resetStats();
  }

  print(s: { write(s: string): void }, num: number, depth: number): number {
    num = super.print(s, num, depth);
    s.write("\n");
    depth += 1;
    for (const rl of this.allrules) {
      const numStr = String(num).padStart(4, ' ');
      s.write(numStr);
      s.write(rl.isDisabled() ? 'D' : ' ');
      s.write(((rl.getBreakPoint() & (Action.break_action | Action.tmpbreak_action)) !== 0) ? 'A' : ' ');
      for (let i = 0; i < depth * 5 + 2; ++i)
        s.write(' ');
      s.write(rl.getName());
      s.write("\n");
      num += 1;
    }
    return num;
  }

  printState(s: { write(s: string): void }): void {
    super.printState(s);
    if (this.status === Action.status_mid) {
      if (this.op_state !== null && !this.op_state.isEnd) {
        const op = this.op_state.get();
        s.write(' ' + op.getSeqNum().toString());
      }
    }
  }

  getSubRule(specify: string): Rule | null {
    const { token, remain } = nextSpecifyTerm(specify);
    let searchStr: string;
    if (this.name === token) {
      if (remain === '') return null;
      searchStr = remain;
    } else {
      searchStr = specify;
    }

    let lastrule: Rule | null = null;
    let matchcount = 0;
    for (const testrule of this.allrules) {
      if (testrule.getName() === searchStr) {
        lastrule = testrule;
        matchcount += 1;
        if (matchcount > 1) return null;
      }
    }
    return lastrule;
  }

  printStatistics(s: { write(s: string): void }): void {
    super.printStatistics(s);
    for (const rl of this.allrules)
      rl.printStatistics(s);
  }

  turnOnDebug(nm: string): boolean {
    if (super.turnOnDebug(nm))
      return true;
    for (const rl of this.allrules)
      if (rl.turnOnDebug(nm))
        return true;
    return false;
  }

  turnOffDebug(nm: string): boolean {
    if (super.turnOffDebug(nm))
      return true;
    for (const rl of this.allrules)
      if (rl.turnOffDebug(nm))
        return true;
    return false;
  }
}

// ---------------------------------------------------------------------------
// ActionDatabase
// ---------------------------------------------------------------------------

/**
 * Database of root Action objects that can be used to transform a function.
 *
 * This is a container for Action objects. It also manages root Action objects,
 * which encapsulate a complete transformation system that can be applied to
 * functions. Root Action objects are derived from a single universal Action
 * object that has every possible sub-action within it. A root Action has its
 * own name and is derived from the universal via a grouplist, which lists a
 * particular subset of Action and Rule groups to use for the root. A new root
 * Action is created by providing a new grouplist via setGroup() or modifying
 * an existing grouplist. This class is intended to be instantiated as a
 * singleton and keeps track of the current root Action, which is the one that
 * will be actively applied to functions.
 */
export class ActionDatabase {
  private currentact: Action | null = null;
  private currentactname: string = '';
  private groupmap: Map<string, ActionGroupList> = new Map();
  private actionmap: Map<string, Action> = new Map();
  private isDefaultGroups_: boolean = false;

  static readonly universalname: string = "universal";

  constructor() {}

  /**
   * Destructor -- clean up all registered actions.
   * Call this to free resources if needed.
   */
  dispose(): void {
    this.actionmap.clear();
  }

  /**
   * (Re)set the default configuration.
   * Clear out (possibly altered) root Actions. Reset the default groups.
   * Set the default root action "decompile".
   */
  resetDefaults(): void {
    let universalAction: Action | null = null;
    const existing = this.actionmap.get(ActionDatabase.universalname);
    if (existing !== undefined)
      universalAction = existing;
    // Clear out any old (modified) root actions, but keep universal
    this.actionmap.clear();
    if (universalAction !== null)
      this.registerAction(ActionDatabase.universalname, universalAction);

    this.buildDefaultGroups();
    this.setCurrent("decompile");
  }

  /** Get the current root Action */
  getCurrent(): Action | null { return this.currentact; }

  /** Get the name of the current root Action */
  getCurrentName(): string { return this.currentactname; }

  /**
   * Create a fresh deep clone of the current root Action.
   * Unlike getCurrent(), this always returns a NEW independent action tree
   * with reset mutable state. Used for parallel decompilation where each
   * job needs its own action tree to avoid shared mutable state corruption.
   * @returns a fresh clone of the current action tree
   */
  cloneCurrentAction(): Action {
    const curgrp = this.getGroup(this.currentactname);
    const universal = this.actionmap.get(ActionDatabase.universalname);
    if (universal === undefined)
      throw new LowlevelError("No universal action registered");
    const cloned = universal.clone(curgrp);
    if (cloned === null)
      throw new LowlevelError("Failed to clone current action tree");
    return cloned;
  }

  /**
   * Get a specific grouplist by name.
   * @param grp the grouplist name
   * @returns the ActionGroupList
   */
  getGroup(grp: string): ActionGroupList {
    const result = this.groupmap.get(grp);
    if (result === undefined)
      throw new LowlevelError("Action group does not exist: " + grp);
    return result;
  }

  /**
   * Set the current root Action.
   * The Action is specified by name. A grouplist must already exist for this name.
   * If the Action doesn't already exist, it will be derived from the universal
   * action via this grouplist.
   * @param actname the name of the root Action
   * @returns the current Action
   */
  setCurrent(actname: string): Action {
    this.currentactname = actname;
    this.currentact = this.deriveAction(ActionDatabase.universalname, actname);
    return this.currentact;
  }

  /**
   * Toggle a group of Actions within a root Action.
   * A particular group is either added or removed from the grouplist defining
   * a particular root Action. The root Action is then (re)derived from the universal.
   * @param grp the name of the root Action
   * @param basegrp name of group (within the grouplist) to toggle
   * @param val true if the group should be added, false if it should be removed
   * @returns the modified root Action
   */
  toggleAction(grp: string, basegrp: string, val: boolean): Action {
    const act = this.getAction(ActionDatabase.universalname);
    if (val)
      this.addToGroup(grp, basegrp);
    else
      this.removeFromGroup(grp, basegrp);
    const curgrp = this.getGroup(grp);
    const newact = act.clone(curgrp);

    if (newact !== null) {
      this.registerAction(grp, newact);

      if (grp === this.currentactname)
        this.currentact = newact;

      return newact;
    }
    throw new LowlevelError("Failed to toggle action group: " + grp);
  }

  /**
   * Establish a new root Action.
   * (Re)set the grouplist for a particular root Action. Do not use this routine
   * to redefine an existing root Action.
   * @param grp the name of the root Action
   * @param argv a list of group name strings
   */
  setGroup(grp: string, argv: string[]): void {
    let curgrp = this.groupmap.get(grp);
    if (curgrp === undefined) {
      curgrp = new ActionGroupList();
      this.groupmap.set(grp, curgrp);
    }
    curgrp.list.clear();
    for (let i = 0; i < argv.length; ++i) {
      if (argv[i] === '') break;
      curgrp.list.add(argv[i]);
    }
    this.isDefaultGroups_ = false;
  }

  /**
   * Clone a root Action.
   * Copy an existing root Action by copying its grouplist, giving it a new name.
   * @param oldname the name of an existing root Action
   * @param newname the name of the copy
   */
  cloneGroup(oldname: string, newname: string): void {
    const curgrp = this.getGroup(oldname);
    const newgrp = new ActionGroupList();
    for (const g of curgrp.list)
      newgrp.list.add(g);
    this.groupmap.set(newname, newgrp);
    this.isDefaultGroups_ = false;
  }

  /**
   * Add a group to a root Action.
   * @param grp the name of the root Action
   * @param basegroup the group to add
   * @returns true for a new addition, false if the group was already present
   */
  addToGroup(grp: string, basegroup: string): boolean {
    this.isDefaultGroups_ = false;
    let curgrp = this.groupmap.get(grp);
    if (curgrp === undefined) {
      curgrp = new ActionGroupList();
      this.groupmap.set(grp, curgrp);
    }
    const had = curgrp.list.has(basegroup);
    curgrp.list.add(basegroup);
    return !had;
  }

  /**
   * Remove a group from a root Action.
   * @param grp the name of the root Action
   * @param basegrp the group to remove
   * @returns true if the group existed and was removed
   */
  removeFromGroup(grp: string, basegrp: string): boolean {
    this.isDefaultGroups_ = false;
    let curgrp = this.groupmap.get(grp);
    if (curgrp === undefined) {
      curgrp = new ActionGroupList();
      this.groupmap.set(grp, curgrp);
    }
    return curgrp.list.delete(basegrp);
  }

  /**
   * Build the universal action.
   * This is expected to be overridden or populated externally (defined in coreaction.ts).
   * @param glb the Architecture
   */
  universalAction(glb: Architecture): void {
    // Populated by coreaction module
  }

  /**
   * Look up a root Action by name.
   * @param nm the name of the root Action
   * @returns the Action
   */
  private getAction(nm: string): Action {
    const act = this.actionmap.get(nm);
    if (act === undefined)
      throw new LowlevelError("No registered action: " + nm);
    return act;
  }

  /**
   * Register a root Action.
   * Internal method for associating a root Action name with its Action object.
   * @param nm the name to register as
   * @param act the Action object
   */
  private registerAction(nm: string, act: Action): void {
    this.actionmap.set(nm, act);
  }

  /**
   * Derive a root Action.
   * Internal method to build the Action object corresponding to a root Action.
   * The new Action object is created by selectively cloning components from an
   * existing object based on a grouplist.
   * @param baseaction the name of the model Action object to derive from
   * @param grp the name of the grouplist steering the clone
   * @returns the derived Action
   */
  private deriveAction(baseaction: string, grp: string): Action {
    const existing = this.actionmap.get(grp);
    if (existing !== undefined)
      return existing;

    const curgrp = this.getGroup(grp);
    const act = this.getAction(baseaction);
    const newact = act.clone(curgrp);

    if (newact !== null) {
      this.registerAction(grp, newact);
      return newact;
    }
    throw new LowlevelError("Failed to derive action: " + grp);
  }

  /**
   * Set up descriptions of preconfigured root Actions.
   * This is expected to be overridden or populated externally (defined in coreaction.ts).
   */
  protected buildDefaultGroups(): void {
    // Populated by coreaction module
  }
}
