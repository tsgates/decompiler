/**
 * @file interface.ts
 * @description Classes and utilities for a generic command-line interface.
 * Translated from Ghidra's interface.hh / interface.cc
 */

import * as fs from 'fs';
import { CapabilityPoint } from '../core/capability.js';
import { Writer } from '../util/writer.js';

// ---------------------------------------------------------------------------
// InputStream: replaces C++ istream for command parameter parsing
// ---------------------------------------------------------------------------

/**
 * Simple string-based input stream that replaces C++ istream for command parsing.
 * Commands use this to read additional parameters from the command line.
 */
export class InputStream {
  private str: string;
  private pos: number;

  constructor(s: string) {
    this.str = s;
    this.pos = 0;
  }

  /** Skip whitespace and return true if at end of input. */
  eof(): boolean {
    this.skipWhitespace();
    return this.pos >= this.str.length;
  }

  /** Read the next whitespace-delimited token. Returns empty string if at EOF. */
  readToken(): string {
    this.skipWhitespace();
    if (this.pos >= this.str.length) return '';
    const start = this.pos;
    while (this.pos < this.str.length && !this.isWhitespace(this.str[this.pos])) {
      this.pos++;
    }
    return this.str.substring(start, this.pos);
  }

  /** Read the remaining content (trimmed of leading whitespace). */
  readRest(): string {
    this.skipWhitespace();
    const rest = this.str.substring(this.pos);
    this.pos = this.str.length;
    return rest;
  }

  /**
   * Read next character. Returns empty string if at EOF.
   * Mirrors C++ istream::get(c).
   */
  getChar(): string {
    if (this.pos >= this.str.length) return '';
    return this.str[this.pos++];
  }

  /**
   * Peek at the next character without consuming it.
   * Returns empty string if at EOF.
   * Mirrors C++ istream::peek().
   */
  peek(): string {
    if (this.pos >= this.str.length) return '';
    return this.str[this.pos];
  }

  /** Read the next token as a number. Returns NaN if not a valid number. */
  readNumber(): number {
    const tok = this.readToken();
    if (tok === '') return NaN;
    return parseInt(tok, 10);
  }

  /** Skip whitespace characters, advancing the position. */
  skipWhitespace(): void {
    while (this.pos < this.str.length && this.isWhitespace(this.str[this.pos])) {
      this.pos++;
    }
  }

  private isWhitespace(c: string): boolean {
    return c === ' ' || c === '\t' || c === '\n' || c === '\r';
  }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * An exception specific to the command line interface.
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
 *
 * Thrown when attempting to parse a command line. Options are missing or are in
 * the wrong form etc.
 */
export class IfaceParseError extends IfaceError {
  constructor(s: string) {
    super(s);
    this.name = 'IfaceParseError';
  }
}

/**
 * An exception thrown during the execution of a command.
 *
 * Processing of a specific command has started but has reached an error state.
 */
export class IfaceExecutionError extends IfaceError {
  constructor(s: string) {
    super(s);
    this.name = 'IfaceExecutionError';
  }
}

// ---------------------------------------------------------------------------
// IfaceData
// ---------------------------------------------------------------------------

/**
 * Data specialized for a particular command module.
 *
 * IfaceCommands can have specialized data that is shared with other commands in
 * the same module. This is the root object for all such data.
 */
export class IfaceData {
  // Base class with virtual destructor semantics -- no explicit cleanup needed in TS
}

// ---------------------------------------------------------------------------
// Forward declaration for IfaceStatus (used by IfaceCommand)
// ---------------------------------------------------------------------------

// IfaceStatus is declared below; IfaceCommand references it via the abstract method signature.

// ---------------------------------------------------------------------------
// IfaceCommand
// ---------------------------------------------------------------------------

/**
 * A command that can be executed from the command line.
 *
 * The command has data associated with it (via setData()) and is executed
 * via the execute() method. The command can get additional parameters from
 * the command line by reading the InputStream passed to it.
 * The command is associated with a specific sequence of words (tokens)
 * that should appear at the start of the command line.
 */
export abstract class IfaceCommand {
  private com: string[] = [];

  /**
   * Associate a specific data object with this command.
   * @param root - the interface object this command is registered with
   * @param data - the data object the command should use
   */
  abstract setData(root: IfaceStatus, data: IfaceData | null): void;

  /**
   * Execute this command. Additional state can be read from the given input stream.
   * Otherwise, the command gets its data from its registered IfaceData object.
   * @param s - the input stream from the command line
   */
  abstract execute(s: InputStream): void;

  /**
   * Get the formal module name to which this command belongs.
   * Commands in the same module share data through their registered IfaceData object.
   */
  abstract getModule(): string;

  /**
   * Create a specialized data object for this command (and its module).
   * This method is only called once per module.
   * @returns the newly created data object for the module, or null
   */
  abstract createData(): IfaceData | null;

  /** Add a token to the command line string associated with this command. */
  addWord(temp: string): void {
    this.com.push(temp);
  }

  /** Remove the last token from the associated command line string. */
  removeWord(): void {
    this.com.pop();
  }

  /** Get the i-th command token. */
  getCommandWord(i: number): string {
    return this.com[i];
  }

  /** Add words to the associated command line string. */
  addWords(wordlist: string[]): void {
    for (let i = 0; i < wordlist.length; ++i) {
      this.com.push(wordlist[i]);
    }
  }

  /** Return the number of tokens in the command line string. */
  numWords(): number {
    return this.com.length;
  }

  /** Get the complete command line string. */
  commandString(): string {
    return IfaceStatus.wordsToString(this.com);
  }

  /**
   * Order two commands by their command line strings.
   * @returns negative if this < op2, 0 if equal, positive if this > op2
   */
  compare(op2: IfaceCommand): number {
    const c1 = this.com;
    const c2 = op2.com;
    const len = Math.min(c1.length, c2.length);
    for (let i = 0; i < len; ++i) {
      if (c1[i] < c2[i]) return -1;
      if (c1[i] > c2[i]) return 1;
    }
    if (c1.length < c2.length) return -1;
    if (c1.length > c2.length) return 1;
    return 0;
  }
}

// ---------------------------------------------------------------------------
// IfaceCommandDummy
// ---------------------------------------------------------------------------

/**
 * A dummy command used during parsing.
 */
export class IfaceCommandDummy extends IfaceCommand {
  setData(_root: IfaceStatus, _data: IfaceData | null): void {}
  execute(_s: InputStream): void {}
  getModule(): string { return 'dummy'; }
  createData(): IfaceData | null { return null; }
}

// ---------------------------------------------------------------------------
// compare_ifacecommand
// ---------------------------------------------------------------------------

/**
 * Compare two commands as pointers (references).
 * Returns true if the first command is ordered before the second.
 */
export function compare_ifacecommand(a: IfaceCommand, b: IfaceCommand): boolean {
  return a.compare(b) < 0;
}

/**
 * Comparator suitable for Array.sort().
 */
function ifaceCommandSortComparator(a: IfaceCommand, b: IfaceCommand): number {
  return a.compare(b);
}

// ---------------------------------------------------------------------------
// IfaceCapability
// ---------------------------------------------------------------------------

/**
 * Groups of console commands that are discovered by the loader.
 *
 * Any IfaceCommand that is registered with a grouping derived from this class
 * is automatically made available to any IfaceStatus object just by calling
 * the static registerAllCommands().
 */
export abstract class IfaceCapability extends CapabilityPoint {
  private static thelist: IfaceCapability[] = [];

  protected name: string = '';

  /** Get the name of the capability. */
  getName(): string {
    return this.name;
  }

  initialize(): void {
    IfaceCapability.thelist.push(this);
  }

  /** Register commands for this grouping. */
  abstract registerCommands(status: IfaceStatus): void;

  /** Register all discovered commands with the interface. */
  static registerAllCommands(status: IfaceStatus): void {
    for (let i = 0; i < IfaceCapability.thelist.length; ++i) {
      IfaceCapability.thelist[i].registerCommands(status);
    }
  }
}

// ---------------------------------------------------------------------------
// Binary search helpers (replacing C++ lower_bound / upper_bound)
// ---------------------------------------------------------------------------

/**
 * Find the index of the first element in a sorted array that is not less than the target.
 * Equivalent to C++ std::lower_bound.
 */
function lowerBound(
  arr: IfaceCommand[],
  first: number,
  last: number,
  target: IfaceCommand
): number {
  let lo = first;
  let hi = last;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (compare_ifacecommand(arr[mid], target)) {
      lo = mid + 1;
    } else {
      hi = mid;
    }
  }
  return lo;
}

/**
 * Find the index of the first element in a sorted array that is greater than the target.
 * Equivalent to C++ std::upper_bound.
 */
function upperBound(
  arr: IfaceCommand[],
  first: number,
  last: number,
  target: IfaceCommand
): number {
  let lo = first;
  let hi = last;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (!compare_ifacecommand(target, arr[mid])) {
      lo = mid + 1;
    } else {
      hi = mid;
    }
  }
  return lo;
}

// ---------------------------------------------------------------------------
// maxmatch helper
// ---------------------------------------------------------------------------

/**
 * Compute the maximum common prefix of two strings.
 * @returns an object with the common prefix and whether a full match was found
 */
function maxmatch(op1: string, op2: string): { res: string; full: boolean } {
  const len = Math.min(op1.length, op2.length);
  let res = '';
  for (let i = 0; i < len; ++i) {
    if (op1[i] === op2[i]) {
      res += op1[i];
    } else {
      return { res, full: false };
    }
  }
  return { res, full: true };
}

// ---------------------------------------------------------------------------
// IfaceStatus
// ---------------------------------------------------------------------------

/**
 * Encapsulates the range indices [first, last) within the comlist array,
 * replacing C++ vector<>::const_iterator pairs.
 */
interface CommandRange {
  first: number;
  last: number;
}

/**
 * A generic console mode interface and command executor.
 *
 * Input is provided one command line at a time via readLine().
 * Output goes to a provided Writer, optr. Output to a separate bulk stream
 * can be enabled by setting fileoptr.
 *
 * A derived IfaceCommand is attached to a command string via registerCom():
 * ```
 *   stat.registerCom(new IfcQuit(), "quit");
 *   stat.registerCom(new IfcOpenfileAppend(), "openfile", "append");
 * ```
 *
 * Command words only have to match enough to disambiguate from other commands.
 * A custom history size and command prompt can be passed to the constructor.
 *
 * Applications should inherit from base class IfaceStatus in order to:
 *   - Override the readLine() method
 *   - Override pushScript() and popScript() to allow command scripts
 *   - Get custom data into IfaceCommand callbacks
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
   * @param os - the base Writer to write output to
   * @param mxhist - the maximum number of lines to store in history (default 10)
   */
  constructor(prmpt: string, os: Writer, mxhist: number = 10) {
    this.optr = os;
    this.fileoptr = os;
    this.sorted = false;
    this.inerror = false;
    this.errorisdone = false;
    this.done = false;
    this.prompt = prmpt;
    this.maxhistory = mxhist;
    this.curhistory = 0;
  }

  /** Set if processing should terminate on an error. */
  setErrorIsDone(val: boolean): void {
    this.errorisdone = val;
  }

  /**
   * Push a new file on the script stack.
   *
   * Attempt to open the file, and if we succeed put the content onto the script stack.
   * @param filename - the name of the script file
   * @param newprompt - the command line prompt to associate with the file
   */
  pushScript(filename: string, newprompt: string): void;

  /**
   * Provide new script lines to execute, with an associated command prompt.
   *
   * The new lines are added to a stack and become the primary source for parsing new commands.
   * Once commands from the lines are exhausted, parsing will resume from the previous source.
   * @param lines - the lines of the script
   * @param newprompt - the command line prompt to associate with the new stream
   */
  pushScript(lines: string[], newprompt: string): void;

  pushScript(arg: string | string[], newprompt: string): void {
    if (typeof arg === 'string') {
      // pushScript(filename, newprompt)
      let content: string;
      try {
        content = fs.readFileSync(arg, 'utf-8');
      } catch (_e) {
        throw new IfaceParseError('Unable to open script file: ' + arg);
      }
      const lines = content.split('\n');
      this.pushScript(lines, newprompt);
    } else {
      // pushScript(lines, newprompt)
      this.promptstack.push(this.prompt);
      let flags = 0;
      if (this.errorisdone) {
        flags |= 1;
      }
      this.flagstack.push(flags);
      this.errorisdone = true;  // Abort on first exception in a script
      this.prompt = newprompt;
    }
  }

  /**
   * Return to processing the parent stream.
   *
   * The current input stream, as established by a script, is popped from the stack,
   * along with its command prompt, and processing continues with the previous stream.
   */
  popScript(): void {
    this.prompt = this.promptstack[this.promptstack.length - 1];
    this.promptstack.pop();
    const flags = this.flagstack[this.flagstack.length - 1];
    this.flagstack.pop();
    this.errorisdone = (flags & 1) !== 0;
    this.inerror = false;
  }

  /** Pop any existing script streams and return to processing from the base stream. */
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

  /** Write the current command prompt to the current output stream. */
  writePrompt(): void {
    this.optr.write(this.prompt);
  }

  /**
   * Register a command with this interface.
   *
   * A command object is associated with one or more tokens on the command line.
   * A string containing up to 5 tokens can be associated with the command.
   *
   * @param fptr - the IfaceCommand object
   * @param nm1 - the first token representing the command
   * @param nm2 - the second token (or undefined)
   * @param nm3 - the third token (or undefined)
   * @param nm4 - the fourth token (or undefined)
   * @param nm5 - the fifth token (or undefined)
   */
  registerCom(
    fptr: IfaceCommand,
    nm1: string,
    nm2?: string,
    nm3?: string,
    nm4?: string,
    nm5?: string
  ): void {
    fptr.addWord(nm1);
    if (nm2 !== undefined) fptr.addWord(nm2);
    if (nm3 !== undefined) fptr.addWord(nm3);
    if (nm4 !== undefined) fptr.addWord(nm4);
    if (nm5 !== undefined) fptr.addWord(nm5);

    this.comlist.push(fptr);  // Enter new command
    this.sorted = false;

    const nm = fptr.getModule();  // Name of module this command belongs to
    let data: IfaceData | null;
    if (!this.datamap.has(nm)) {
      data = fptr.createData();
      this.datamap.set(nm, data);
    } else {
      data = this.datamap.get(nm) ?? null;
    }
    fptr.setData(this, data);  // Inform command of its data
  }

  /**
   * Get data associated with an IfaceCommand module.
   * @param nm - the name of the module
   * @returns the IfaceData object or null
   */
  getData(nm: string): IfaceData | null {
    const data = this.datamap.get(nm);
    if (data === undefined) return null;
    return data;
  }

  /**
   * Run the next command.
   *
   * A single command line is read (via readLine) and executed.
   * If the command is successfully executed, the command line is
   * committed to history and true is returned.
   * @returns true if a command successfully executes
   */
  runCommand(): boolean {
    if (!this.sorted) {
      this.comlist.sort(ifaceCommandSortComparator);
      this.sorted = true;
    }
    const line = this.readLine();
    if (line.length === 0) return false;
    this.saveHistory(line);

    const fullcommand: string[] = [];
    const range: CommandRange = { first: 0, last: this.comlist.length };
    const is = new InputStream(line);

    const match = this.expandCom(fullcommand, is, range);  // Try to expand the command
    if (match === 0) {
      this.optr.write('ERROR: Invalid command\n');
      return false;
    } else if (fullcommand.length === 0) {
      // Nothing useful typed
      return false;
    } else if (match > 1) {
      if (this.comlist[range.first].numWords() !== fullcommand.length) {
        // Check for complete but not unique
        this.optr.write('ERROR: Incomplete command\n');
        return false;
      }
    } else if (match < 0) {
      this.optr.write('ERROR: Incomplete command\n');
    }

    this.comlist[range.first].execute(is);  // Try to execute the (first) command
    return true;  // Indicate a command was executed
  }

  /**
   * Get the i-th command line from history.
   * @param i - the number of steps back to go
   * @returns the command line from history, or empty string if too far back
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
      // we have something to pop
      this.optr.write('Aborting ' + this.prompt + '\n');
      this.inerror = true;
      return;
    }
    this.inerror = false;
  }

  /**
   * Concatenate a list of tokens into a single string, separated by a space character.
   */
  static wordsToString(list: string[]): string {
    return list.join(' ');
  }

  // ---- Private / protected methods ----

  /**
   * Read the next command line.
   * Subclasses must implement this to provide input.
   */
  protected abstract readLine(): string;

  /**
   * The line is saved in a circular history buffer.
   * @param line - the command line to save
   */
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
   * Restrict range of possible commands given a list of command line tokens.
   *
   * Given a set of tokens partially describing a command, provide the most narrow
   * range of IfaceCommand objects that could be referred to.
   * @param range - mutated in-place to the narrowed range
   * @param input - the list of command tokens to match on
   */
  private restrictCom(range: CommandRange, input: string[]): void {
    const dummy = new IfaceCommandDummy();
    dummy.addWords(input);

    const newFirst = lowerBound(this.comlist, range.first, range.last, dummy);

    dummy.removeWord();
    let temp = input[input.length - 1];
    // Increment last character to create an upper bound
    temp = temp.substring(0, temp.length - 1) +
      String.fromCharCode(temp.charCodeAt(temp.length - 1) + 1);
    dummy.addWord(temp);

    const newLast = upperBound(this.comlist, range.first, range.last, dummy);

    range.first = newFirst;
    range.last = newLast;
  }

  /**
   * Expand tokens from the given input stream to a full command.
   *
   * A range of possible commands is returned. Processing of the stream
   * stops as soon as at least one complete command is recognized.
   * Tokens partially matching a command are expanded to the full command
   * and passed back.
   * @param expand - filled with the list of expanded tokens
   * @param s - the input stream tokens are read from
   * @param range - mutated in-place to the matching range of commands
   * @returns the number of matching commands (negative means last word incomplete)
   */
  protected expandCom(expand: string[], s: InputStream, range: CommandRange): number {
    expand.length = 0;  // Make sure command list is empty
    let res = true;
    if (range.first === range.last) return 0;  // If subrange is empty, return 0

    for (let pos = 0; ; ++pos) {
      // Skip whitespace is done implicitly by InputStream.eof() / readToken()
      if (range.first === range.last - 1) {
        // If subrange is unique
        if (s.eof()) {
          // Automatically provide missing words
          for (; pos < this.comlist[range.first].numWords(); ++pos) {
            expand.push(this.comlist[range.first].getCommandWord(pos));
          }
        }
        if (this.comlist[range.first].numWords() === pos) {
          // If all words are matched
          return 1;  // Finished
        }
      }
      if (!res) {
        // Last word was ambiguous
        if (!s.eof()) return range.last - range.first;
        return range.first - range.last;  // Negative number to indicate last word incomplete
      }
      if (s.eof()) {
        // If no other words
        if (expand.length === 0) return range.first - range.last;
        return range.last - range.first;  // return number of matches
      }
      const tok = s.readToken();
      expand.push(tok);
      this.restrictCom(range, expand);
      if (range.first === range.last) return 0;  // If subrange is empty, return 0

      const mm = maxmatch(
        this.comlist[range.first].getCommandWord(pos),
        this.comlist[range.last - 1].getCommandWord(pos)
      );
      res = mm.full;
      expand[expand.length - 1] = mm.res;
    }
  }
}

// ---------------------------------------------------------------------------
// IfaceBaseCommand
// ---------------------------------------------------------------------------

/**
 * A root class for a basic set of commands.
 *
 * Commands derived from this class are in the "base" module.
 * They are useful as part of any interface.
 */
export abstract class IfaceBaseCommand extends IfaceCommand {
  protected status!: IfaceStatus;

  setData(root: IfaceStatus, _data: IfaceData | null): void {
    this.status = root;
  }

  getModule(): string {
    return 'base';
  }

  createData(): IfaceData | null {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Built-in commands
// ---------------------------------------------------------------------------

/**
 * Quit command to terminate processing from the given interface.
 */
export class IfcQuit extends IfaceBaseCommand {
  execute(s: InputStream): void {
    if (!s.eof()) {
      throw new IfaceParseError('Too many parameters to quit');
    }
    this.status.done = true;  // Set flag to drop out of mainloop
  }
}

/**
 * History command to list the most recent successful commands.
 */
export class IfcHistory extends IfaceBaseCommand {
  execute(s: InputStream): void {
    let num: number;

    if (!s.eof()) {
      num = s.readNumber();
      if (isNaN(num)) {
        throw new IfaceParseError('Bad number parameter to history');
      }
      if (!s.eof()) {
        throw new IfaceParseError('Too many parameters to history');
      }
    } else {
      num = 10;  // Default number of history lines
    }

    if (num > this.status.getHistorySize()) {
      num = this.status.getHistorySize();
    }

    for (let i = num - 1; i >= 0; --i) {
      // List oldest to newest
      const historyline = this.status.getHistory(i);
      this.status.optr.write(historyline + '\n');
    }
  }
}

/**
 * Open file command to redirect bulk output to a specific file stream.
 */
export class IfcOpenfile extends IfaceBaseCommand {
  execute(s: InputStream): void {
    if (this.status.optr !== this.status.fileoptr) {
      throw new IfaceExecutionError('Output file already opened');
    }
    const filename = s.readToken();
    if (filename.length === 0) {
      throw new IfaceParseError('No filename specified');
    }

    try {
      const fd = fs.openSync(filename, 'w');
      const fileWriter: Writer = {
        write(str: string): void {
          fs.writeSync(fd, str);
        }
      };
      // Attach close method for later cleanup
      (fileWriter as any)._fd = fd;
      (fileWriter as any)._close = (): void => { fs.closeSync(fd); };
      this.status.fileoptr = fileWriter;
    } catch (_e) {
      throw new IfaceExecutionError('Unable to open file: ' + filename);
    }
  }
}

/**
 * Open file command directing bulk output to be appended to a specific file.
 */
export class IfcOpenfileAppend extends IfaceBaseCommand {
  execute(s: InputStream): void {
    if (this.status.optr !== this.status.fileoptr) {
      throw new IfaceExecutionError('Output file already opened');
    }
    const filename = s.readToken();
    if (filename.length === 0) {
      throw new IfaceParseError('No filename specified');
    }

    try {
      const fd = fs.openSync(filename, 'a');
      const fileWriter: Writer = {
        write(str: string): void {
          fs.writeSync(fd, str);
        }
      };
      (fileWriter as any)._fd = fd;
      (fileWriter as any)._close = (): void => { fs.closeSync(fd); };
      this.status.fileoptr = fileWriter;
    } catch (_e) {
      throw new IfaceExecutionError('Unable to open file: ' + filename);
    }
  }
}

/**
 * Close command, closing the current bulk output file.
 *
 * Subsequent bulk output is redirected to the basic interface output stream.
 */
export class IfcClosefile extends IfaceBaseCommand {
  execute(_s: InputStream): void {
    if (this.status.optr === this.status.fileoptr) {
      throw new IfaceExecutionError('No file open');
    }
    const fp = this.status.fileoptr as any;
    if (typeof fp._close === 'function') {
      fp._close();
    }
    this.status.fileoptr = this.status.optr;
  }
}

/**
 * Echo command to echo the current command line to the bulk output stream.
 */
export class IfcEcho extends IfaceBaseCommand {
  execute(s: InputStream): void {
    // Read remaining characters (including whitespace) and echo to fileoptr
    let c = s.getChar();
    while (c !== '') {
      this.status.fileoptr.write(c);
      c = s.getChar();
    }
    this.status.fileoptr.write('\n');
  }
}
