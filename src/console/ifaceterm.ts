/**
 * @file ifaceterm.ts
 * @description Implement the command-line interface on top of a specific input stream.
 *
 * Translated from Ghidra's ifaceterm.hh / ifaceterm.cc
 *
 * The C++ version includes character-by-character terminal editing with raw mode
 * (__TERMINAL__ ifdefs). In this TypeScript translation, we use a simpler
 * line-buffered approach: input is represented as an array of lines (string[]),
 * and readLine() pops the next line from the buffer.  This maps naturally to
 * script-driven usage and can also wrap interactive stdin via a readline-based
 * adapter if needed.
 */

import type { Writer } from '../util/writer.js';

// ---------------------------------------------------------------------------
// Forward type stubs for IfaceStatus and related types that live in
// interface.ts (not yet translated).  Once interface.ts exists these should
// be replaced with real imports:
//   import { IfaceStatus, IfaceCommand, IfaceData, IfaceError, ... } from './interface.js';
// ---------------------------------------------------------------------------

/**
 * An exception specific to the command-line interface.
 */
export class IfaceError extends Error {
  readonly explain: string;

  constructor(s: string) {
    super(s);
    this.name = 'IfaceError';
    this.explain = s;
  }
}

/**
 * An exception describing a parsing error in a command line.
 */
export class IfaceParseError extends IfaceError {
  constructor(s: string) {
    super(s);
    this.name = 'IfaceParseError';
  }
}

/**
 * An exception thrown during the execution of a command.
 */
export class IfaceExecutionError extends IfaceError {
  constructor(s: string) {
    super(s);
    this.name = 'IfaceExecutionError';
  }
}

/**
 * Data specialized for a particular command module.
 */
export interface IfaceData {
  // Marker interface -- concrete modules add their own fields.
}

/**
 * A command that can be executed from the command line.
 */
export abstract class IfaceCommand {
  private com: string[] = [];

  abstract setData(root: IfaceStatus, data: IfaceData | null): void;
  abstract execute(args: string): void;
  abstract getModule(): string;
  abstract createData(): IfaceData | null;

  addWord(temp: string): void {
    this.com.push(temp);
  }

  removeWord(): void {
    this.com.pop();
  }

  getCommandWord(i: number): string {
    return this.com[i];
  }

  addWords(wordlist: string[]): void {
    for (const w of wordlist) {
      this.com.push(w);
    }
  }

  numWords(): number {
    return this.com.length;
  }

  commandString(): string {
    return IfaceStatus.wordsToString(this.com);
  }

  compare(op2: IfaceCommand): number {
    const c1 = this.com;
    const c2 = op2.com;
    const len = Math.min(c1.length, c2.length);
    for (let i = 0; i < len; i++) {
      if (c1[i] < c2[i]) return -1;
      if (c1[i] > c2[i]) return 1;
    }
    if (c1.length < c2.length) return -1;
    if (c1.length > c2.length) return 1;
    return 0;
  }
}

/**
 * A dummy command used during parsing / range restriction.
 */
export class IfaceCommandDummy extends IfaceCommand {
  setData(_root: IfaceStatus, _data: IfaceData | null): void {}
  execute(_args: string): void {}
  getModule(): string { return 'dummy'; }
  createData(): IfaceData | null { return null; }
}

/**
 * Comparator for sorting IfaceCommand pointers (objects).
 */
function compareIfacecommand(a: IfaceCommand, b: IfaceCommand): number {
  return a.compare(b);
}

// ---------------------------------------------------------------------------
// IfaceStatus -- base class for the command-line interface
// ---------------------------------------------------------------------------

/**
 * A generic console mode interface and command executor.
 *
 * Input is provided one command line at a time via readLine().
 * Output goes to a provided Writer (optr).  Bulk output can be redirected
 * via fileoptr.
 */
export abstract class IfaceStatus {
  private promptstack: string[] = [];
  private flagstack: number[] = [];
  private prompt: string;
  private maxhistory: number;
  private curhistory: number = 0;
  private history: string[] = [];
  private sorted: boolean = false;
  private errorisdone: boolean = false;

  protected inerror: boolean = false;
  protected comlist: IfaceCommand[] = [];
  protected datamap: Map<string, IfaceData | null> = new Map();

  done: boolean = false;
  optr: Writer;
  fileoptr: Writer;

  /**
   * @param prmpt - the base command line prompt
   * @param os - the base Writer for output
   * @param mxhist - maximum number of history lines (default 10)
   */
  constructor(prmpt: string, os: Writer, mxhist: number = 10) {
    this.optr = os;
    this.fileoptr = os;
    this.prompt = prmpt;
    this.maxhistory = mxhist;
  }

  /**
   * Read the next command line.
   * Subclasses must implement this to provide input.
   *
   * @param line - object whose `value` field is set to the next command line
   */
  protected abstract readLine(line: { value: string }): void;

  /** Set whether processing should terminate on an error. */
  setErrorIsDone(val: boolean): void {
    this.errorisdone = val;
  }

  /**
   * Push a new script file by name.
   *
   * @param filename - path or content of the script
   * @param newprompt - prompt to use while executing the script
   */
  pushScriptByName(filename: string, newprompt: string): void {
    // In Node.js we read the file contents and push as lines.
    // In browser or pure-TS environments, the caller should provide lines directly.
    let lines: string[];
    try {
      // Attempt dynamic require for Node.js fs module
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const fs = require('fs') as { readFileSync(p: string, e: string): string };
      const content = fs.readFileSync(filename, 'utf-8');
      lines = content.split('\n');
    } catch {
      throw new IfaceParseError('Unable to open script file: ' + filename);
    }
    this.pushScript(lines, newprompt);
  }

  /**
   * Push a new input source onto the script stack.
   *
   * @param iptr - the new input (array of lines)
   * @param newprompt - prompt associated with the new input
   */
  pushScript(iptr: string[], newprompt: string): void {
    this.promptstack.push(this.prompt);
    let flags = 0;
    if (this.errorisdone) flags |= 1;
    this.flagstack.push(flags);
    this.errorisdone = true;
    this.prompt = newprompt;
  }

  /**
   * Return to processing the parent stream.
   */
  popScript(): void {
    this.prompt = this.promptstack[this.promptstack.length - 1];
    this.promptstack.pop();
    const flags = this.flagstack[this.flagstack.length - 1];
    this.flagstack.pop();
    this.errorisdone = (flags & 1) !== 0;
    this.inerror = false;
  }

  /**
   * Pop any existing script streams and return to processing from the base stream.
   */
  reset(): void {
    while (this.promptstack.length > 0) {
      this.popScript();
    }
    this.errorisdone = false;
    this.done = false;
  }

  /** Get depth of script nesting. */
  getNumInputStreamSize(): number {
    return this.promptstack.length;
  }

  /** Write the current command prompt to the output stream. */
  writePrompt(): void {
    this.optr.write(this.prompt);
  }

  /**
   * Register a command with this interface.
   *
   * @param fptr - the IfaceCommand object
   * @param names - one or more tokens that form the command string
   */
  registerCom(fptr: IfaceCommand, ...names: string[]): void {
    for (const nm of names) {
      fptr.addWord(nm);
    }
    this.comlist.push(fptr);
    this.sorted = false;

    const moduleName = fptr.getModule();
    let data: IfaceData | null;
    if (!this.datamap.has(moduleName)) {
      data = fptr.createData();
      this.datamap.set(moduleName, data);
    } else {
      data = this.datamap.get(moduleName) ?? null;
    }
    fptr.setData(this, data);
  }

  /** Get data associated with an IfaceCommand module. */
  getData(nm: string): IfaceData | null {
    return this.datamap.get(nm) ?? null;
  }

  /**
   * Run the next command.
   *
   * A single command line is read and executed.  If the command is successfully
   * executed, the command line is committed to history and true is returned.
   */
  runCommand(): boolean {
    const lineRef: { value: string } = { value: '' };

    if (!this.sorted) {
      this.comlist.sort(compareIfacecommand);
      this.sorted = true;
    }
    this.readLine(lineRef);
    const line = lineRef.value;
    if (line.length === 0) return false;
    this.saveHistory(line);

    const fullcommand: string[] = [];
    const range: { first: number; last: number } = { first: 0, last: this.comlist.length };
    const tokens = line.trim().split(/\s+/);
    let tokenIndex = 0;

    const match = this.expandComFromTokens(fullcommand, tokens, tokenIndex, range);
    if (match === 0) {
      this.optr.write('ERROR: Invalid command\n');
      return false;
    } else if (fullcommand.length === 0) {
      return false;
    } else if (match > 1) {
      if (this.comlist[range.first].numWords() !== fullcommand.length) {
        this.optr.write('ERROR: Incomplete command\n');
        return false;
      }
    } else if (match < 0) {
      this.optr.write('ERROR: Incomplete command\n');
    }

    // Build the remaining arguments string (everything after the command words)
    const cmdWordCount = fullcommand.length;
    const remaining = tokens.slice(cmdWordCount).join(' ');
    this.comlist[range.first].execute(remaining);
    return true;
  }

  /** Store the given command line into history (circular buffer). */
  private saveHistory(line: string): void {
    if (this.history.length < this.maxhistory) {
      this.history.push(line);
    } else {
      this.history[this.curhistory] = line;
    }
    this.curhistory += 1;
    if (this.curhistory === this.maxhistory) {
      this.curhistory = 0;
    }
  }

  /**
   * Get the i-th command line from history.
   * @param i - number of steps back (0 = most recent)
   * @returns the command line, or empty string if out of range
   */
  getHistory(i: number): string {
    if (i >= this.history.length) return '';
    let idx = this.curhistory - 1 - i;
    if (idx < 0) idx += this.maxhistory;
    return this.history[idx];
  }

  /** Get the number of command lines in history. */
  getHistorySize(): number {
    return this.history.length;
  }

  /** Return true if the current stream is finished. */
  abstract isStreamFinished(): boolean;

  /** Return true if the last command failed. */
  isInError(): boolean {
    return this.inerror;
  }

  /** Adjust which stream to process based on last error. */
  evaluateError(): void {
    if (this.errorisdone) {
      this.optr.write('Aborting process\n');
      this.inerror = true;
      this.done = true;
      return;
    }
    if (this.getNumInputStreamSize() !== 0) {
      this.optr.write('Aborting ' + this.prompt + '\n');
      this.inerror = true;
      return;
    }
    this.inerror = false;
  }

  /**
   * Concatenate tokens into a single space-separated string.
   */
  static wordsToString(list: string[]): string {
    return list.join(' ');
  }

  // -- Internal command expansion helpers --

  /**
   * Restrict the range [first, last) of commands to those matching the given input tokens.
   */
  private restrictCom(
    range: { first: number; last: number },
    input: string[]
  ): void {
    const dummy = new IfaceCommandDummy();
    dummy.addWords(input);

    // lower_bound
    let lo = range.first;
    let hi = range.last;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (compareIfacecommand(this.comlist[mid], dummy) < 0) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    const newFirst = lo;

    // Modify dummy: remove last word and add incremented version for upper bound
    dummy.removeWord();
    const lastWord = input[input.length - 1];
    const temp = lastWord.slice(0, -1) +
      String.fromCharCode(lastWord.charCodeAt(lastWord.length - 1) + 1);
    dummy.addWord(temp);

    // upper_bound
    lo = range.first;
    hi = range.last;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (compareIfacecommand(dummy, this.comlist[mid]) < 0) {
        hi = mid;
      } else {
        lo = mid + 1;
      }
    }
    const newLast = lo;

    range.first = newFirst;
    range.last = newLast;
  }

  /**
   * Expand tokens to a full command, returning the match count.
   *
   * Positive return = exact number of matches.
   * Negative return = last word was ambiguous / incomplete.
   * Zero = no match.
   */
  protected expandComFromTokens(
    expand: string[],
    tokens: string[],
    startIdx: number,
    range: { first: number; last: number }
  ): number {
    expand.length = 0;
    let res = true;
    const comlist = this.comlist;

    if (range.first === range.last) return 0;

    for (let pos = 0; ; ++pos) {
      const tokenIdx = startIdx + pos;

      if (range.first === range.last - 1) {
        // Unique subrange
        if (tokenIdx >= tokens.length) {
          // Auto-complete remaining words
          for (let p = pos; p < comlist[range.first].numWords(); ++p) {
            expand.push(comlist[range.first].getCommandWord(p));
          }
        }
        if (comlist[range.first].numWords() === pos) {
          return 1;
        }
      }

      if (!res) {
        if (tokenIdx < tokens.length) {
          return range.last - range.first;
        }
        return range.first - range.last; // Negative: last word incomplete
      }

      if (tokenIdx >= tokens.length) {
        if (expand.length === 0) {
          return range.first - range.last;
        }
        return range.last - range.first;
      }

      const tok = tokens[tokenIdx];
      expand.push(tok);
      this.restrictCom(range, expand);
      if (range.first === range.last) return 0;

      // maxmatch: find maximum common prefix of command words at this position
      const w1 = comlist[range.first].getCommandWord(pos);
      const w2 = comlist[range.last - 1].getCommandWord(pos);
      const maxLen = Math.min(w1.length, w2.length);
      let matched = '';
      res = true;
      for (let c = 0; c < maxLen; ++c) {
        if (w1[c] === w2[c]) {
          matched += w1[c];
        } else {
          res = false;
          break;
        }
      }
      expand[expand.length - 1] = matched;
    }
  }
}

// ---------------------------------------------------------------------------
// IfaceTerm -- concrete terminal/line-buffer implementation
// ---------------------------------------------------------------------------

/**
 * A line source that provides input to IfaceTerm.
 *
 * Implementations can wrap an array of strings (for scripts), standard input,
 * or any other source of lines.
 */
export interface LineSource {
  /** Read the next line, or return null if the source is exhausted. */
  nextLine(): string | null;

  /** Return true if the source has no more lines. */
  isEof(): boolean;
}

/**
 * A LineSource backed by an array of strings (e.g., lines from a script file).
 */
export class ArrayLineSource implements LineSource {
  private lines: string[];
  private pos: number = 0;

  constructor(lines: string[]) {
    this.lines = lines;
  }

  nextLine(): string | null {
    if (this.pos >= this.lines.length) return null;
    return this.lines[this.pos++];
  }

  isEof(): boolean {
    return this.pos >= this.lines.length;
  }
}

/**
 * Implement the command-line interface on top of a specific input stream.
 *
 * An initial input source is provided as the base stream to parse for commands.
 * Additional input sources can be stacked by invoking scripts.
 *
 * The C++ version performs character-by-character terminal editing with raw
 * mode (under #ifdef __TERMINAL__).  This TypeScript version uses a simpler
 * line-buffered approach, reading complete lines from a LineSource.
 */
export class IfaceTerm extends IfaceStatus {
  private sptr: LineSource;
  private inputstack: LineSource[] = [];

  /**
   * @param prmpt - the command prompt string
   * @param input - the initial input source (LineSource)
   * @param output - the Writer for command output
   */
  constructor(prmpt: string, input: LineSource, output: Writer) {
    super(prmpt, output);
    this.sptr = input;
  }

  /**
   * Attempt tab-completion of the current command line.
   *
   * @param line - the current (partial) command line
   * @param cursor - the current cursor position
   * @returns the (possibly updated) cursor position
   */
  private doCompletion(line: { value: string }, cursor: number): number {
    const fullcommand: string[] = [];
    const tokens = line.value.trim().split(/\s+/).filter(t => t.length > 0);
    const range: { first: number; last: number } = {
      first: 0,
      last: this.comlist.length,
    };

    const match = this.expandComFromTokens(fullcommand, tokens, 0, range);
    if (match === 0) {
      this.optr.write('\nInvalid command\n');
      return cursor;
    }

    const oldSize = line.value.length;
    let newLine = IfaceStatus.wordsToString(fullcommand);
    let absMatch = match < 0 ? -match : match;

    if (match > 0) {
      newLine += ' '; // Add trailing space if command word is complete
    }

    // Re-append any extra parameters beyond the command words
    const extra = tokens.slice(fullcommand.length);
    if (extra.length > 0) {
      newLine += extra.join(' ');
    }

    line.value = newLine;

    if (oldSize < newLine.length) {
      return newLine.length;
    }

    if (absMatch > 1) {
      this.optr.write('\n');
      for (let i = range.first; i < range.last; i++) {
        this.optr.write(this.comlist[i].commandString() + '\n');
      }
    } else {
      this.optr.write('\nCommand is complete\n');
    }
    return line.value.length;
  }

  /**
   * Read the next command line from the current input source.
   *
   * In the C++ version this performs character-by-character reading with
   * in-line editing.  Here we simply read the next complete line from the
   * underlying LineSource.
   *
   * @param line - object whose `value` field is set to the next command line
   */
  protected readLine(line: { value: string }): void {
    const result = this.sptr.nextLine();
    if (result === null) {
      line.value = '';
    } else {
      // Strip trailing newline / carriage-return if present
      line.value = result.replace(/[\r\n]+$/, '');
    }
  }

  /**
   * Push a new input source (e.g., a script) onto the stack.
   *
   * The current source is saved and restored when the new source is exhausted.
   *
   * @param iptr - the new input lines
   * @param newprompt - command prompt for the new input level
   */
  pushScript(iptr: string[], newprompt: string): void {
    this.inputstack.push(this.sptr);
    this.sptr = new ArrayLineSource(iptr);
    super.pushScript(iptr, newprompt);
  }

  /**
   * Push a LineSource directly onto the stack.
   *
   * @param source - the new LineSource
   * @param newprompt - command prompt for the new input level
   */
  pushLineSource(source: LineSource, newprompt: string): void {
    this.inputstack.push(this.sptr);
    this.sptr = source;
    // Call IfaceStatus.pushScript with an empty array (we manage the source ourselves)
    super.pushScript([], newprompt);
  }

  /**
   * Restore the previous input source from the stack.
   */
  popScript(): void {
    if (this.inputstack.length === 0) return;
    this.sptr = this.inputstack[this.inputstack.length - 1];
    this.inputstack.pop();
    super.popScript();
  }

  /**
   * Return true if the current stream is finished.
   *
   * Processing is finished if the done flag is set, an error is pending,
   * or the underlying input source has reached EOF.
   */
  isStreamFinished(): boolean {
    if (this.done || this.inerror) return true;
    return this.sptr.isEof();
  }
}
