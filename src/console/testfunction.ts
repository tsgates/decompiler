/**
 * @file testfunction.ts
 * @description Framework for decompiler data driven single function tests.
 *
 * Translated from Ghidra's testfunction.hh / testfunction.cc
 */

import * as fs from 'fs';
import { Element, DocumentStorage } from '../core/xml.js';
import { DecoderError, LowlevelError } from '../core/error.js';
import { Writer, StringWriter } from '../util/writer.js';
import {
  IfaceStatus,
  IfaceCapability,
  IfaceParseError,
  IfaceExecutionError,
} from './interface.js';
import { ArchitectureCapability } from '../decompiler/architecture.js';
import { mainloop } from './ifacedecomp.js';

// Forward type declarations for not-yet-wired types
type IfaceDecompData = any;

// ---------------------------------------------------------------------------
// FunctionTestProperty
// ---------------------------------------------------------------------------

/**
 * A single property to be searched for in the output of a function decompilation.
 *
 * This is generally a regular expression run over the characters in the
 * decompiled "source" form of the function.
 * The property may "match" more than once or not at all.
 */
export class FunctionTestProperty {
  private minimumMatch: number = 0;   // Minimum number of times property is expected to match
  private maximumMatch: number = 0;   // Maximum number of times property is expected to match
  private _name: string = '';         // Name of the test, to be printed in test summaries
  private pattern: RegExp[] = [];     // Regular expression(s) to match against a line(s) of output
  private patnum: number = 0;         // Index of current pattern to match against
  private count: number = 0;          // Number of times regular expression has been seen

  /** Get the name of the property. */
  getName(): string {
    return this._name;
  }

  /** Reset "state", counting number of matching lines. */
  startTest(): void {
    this.count = 0;
    this.patnum = 0;
  }

  /** Search through the given line, update state if match found. */
  processLine(line: string): void {
    if (this.pattern[this.patnum].test(line)) {
      this.patnum += 1;
      if (this.patnum >= this.pattern.length) {
        this.count += 1;      // Full pattern has matched. Count it.
        this.patnum = 0;
      }
    } else if (this.patnum > 0) {
      this.patnum = 0;        // Abort current multi-line match, restart trying to match first line
      if (this.pattern[this.patnum].test(line)) {
        this.patnum += 1;
      }
    }
  }

  /** Return results of property search. */
  endTest(): boolean {
    return (this.count >= this.minimumMatch && this.count <= this.maximumMatch);
  }

  /** Reconstruct the property from an XML tag. */
  restoreXml(el: Element): void {
    this._name = el.getAttributeValue('name');
    this.minimumMatch = parseInt(el.getAttributeValue('min'), 10);
    this.maximumMatch = parseInt(el.getAttributeValue('max'), 10);
    let pos: number = 0;
    // Re-encode Unicode codepoints as Latin-1 bytes, then decode as UTF-8.
    // XML entities like &#xc2;&#xa3; produce individual Unicode codepoints (U+00C2, U+00A3)
    // but the C++ decompiler output (and our TS output) writes proper UTF-8 decoded characters.
    // In C++ everything is byte-level so regex matching works. In JS we need this conversion.
    const rawContent: string = el.getContent();
    let line: string;
    const allLatin1 = [...rawContent].every(ch => ch.codePointAt(0)! <= 0xFF);
    if (allLatin1) {
      const bytes = new Uint8Array([...rawContent].map(ch => ch.codePointAt(0)!));
      line = new TextDecoder('utf-8').decode(bytes);
    } else {
      line = rawContent;
    }
    for (;;) {
      // Remove whitespace at front of pattern
      while (pos < line.length && (line[pos] === ' ' || line[pos] === '\t')) {
        pos += 1;
      }
      if (pos >= line.length) {
        break;
      }
      const nextpos: number = line.indexOf('\n', pos);  // A newline indicates a multi-line regex
      let substr: string;
      if (nextpos === -1) {
        substr = line.substring(pos);       // If no (additional) newlines, take all remaining chars
      } else {
        substr = line.substring(pos, nextpos);  // Create a line regex up to newline char
      }
      this.pattern.push(new RegExp(substr));  // Add a regex to list of lines to match
      if (nextpos === -1) {
        break;
      }
      pos = nextpos + 1;  // Skip newline when creating next line regex
    }
  }
}

// ---------------------------------------------------------------------------
// ConsoleCommands
// ---------------------------------------------------------------------------

/**
 * A console command run as part of a test sequence.
 *
 * Provides command lines from a pre-built list rather than from interactive input.
 */
export class ConsoleCommands extends IfaceStatus {
  private commands: string[];    // Sequence of commands
  private pos: number;           // Position of next command to execute

  /**
   * Constructor.
   * @param s - the writer where command output is printed
   * @param comms - the list of commands to be issued
   */
  constructor(s: Writer, comms: string[]) {
    super('> ', s);
    this.commands = comms;
    this.pos = 0;
    IfaceCapability.registerAllCommands(this);
  }

  /** Read the next command line from the command list. */
  protected readLine(): string {
    if (this.pos >= this.commands.length) {
      return '';
    }
    const line = this.commands[this.pos];
    this.pos += 1;
    return line;
  }

  /** Reset console for a new program. */
  reset(): void {
    this.pos = 0;
    this.inerror = false;
    this.done = false;
  }

  /** Return true if all commands have been consumed. */
  isStreamFinished(): boolean {
    return this.pos === this.commands.length;
  }
}

// ---------------------------------------------------------------------------
// FunctionTestCollection
// ---------------------------------------------------------------------------

/**
 * A collection of tests around a single program/function.
 *
 * The collection of tests is loaded from a single XML file via loadTest(),
 * and the tests are run by calling runTests().
 * An entire program is loaded and possibly annotated by a series of
 * console command lines. Decompiler output is also triggered by a command,
 * and then the output is scanned for by the test objects (FunctionTestProperty).
 * Results of passed/failed tests are collected. If the command line script
 * does not complete properly, this is considered a special kind of failure.
 */
export class FunctionTestCollection {
  private dcp: IfaceDecompData;               // Program data for the test collection
  private fileName: string = '';              // Name of the file containing test data
  private testList: FunctionTestProperty[] = [];  // List of tests for this collection
  private commands: string[] = [];            // Sequence of commands for current test
  private console: IfaceStatus;               // Decompiler console for executing scripts
  private consoleOwner: boolean;              // True if this object owns the console
  private numTestsApplied: number = 0;        // Count of tests that were executed
  private numTestsSucceeded: number = 0;      // Count of tests that passed
  private lastOutput: string = '';            // Raw decompiled C output from last runTests()

  /**
   * Constructor.
   * @param s - the writer where output is sent during tests
   */
  constructor(s: Writer);
  /**
   * Constructor with preexisting console.
   * @param con - the existing IfaceStatus console
   */
  constructor(con: IfaceStatus);
  constructor(arg: Writer | IfaceStatus) {
    if (arg instanceof IfaceStatus) {
      // Constructor with preexisting console
      this.console = arg;
      this.consoleOwner = false;
    } else {
      // Constructor with Writer -- create ConsoleCommands
      this.console = new ConsoleCommands(arg, this.commands);
      this.consoleOwner = true;
      this.console.setErrorIsDone(true);
    }
    this.dcp = this.console.getData('decompile') as IfaceDecompData;
    this.numTestsApplied = 0;
    this.numTestsSucceeded = 0;
  }

  /** Get the number of tests executed. */
  getTestsApplied(): number {
    return this.numTestsApplied;
  }

  /** Get the number of tests that passed. */
  getTestsSucceeded(): number {
    return this.numTestsSucceeded;
  }

  /** Get the raw decompiled C output from the last runTests() call. */
  getLastOutput(): string {
    return this.lastOutput;
  }

  /** Get the number of commands in the current script. */
  numCommandsCount(): number {
    return this.commands.length;
  }

  /** Get the i-th command. */
  getCommand(i: number): string {
    return this.commands[i];
  }

  /** Clear any previous architecture and function. */
  private clear(): void {
    this.dcp.clearArchitecture();
    this.commands.length = 0;
    this.testList.length = 0;
    this.console.reset();
  }

  /**
   * Convert any newline character to a space. Remove carriage return characters as well.
   * @param ref - the string to strip
   * @returns the stripped string
   */
  private static stripNewlines(ref: string): string {
    let res = '';
    for (let i = 0; i < ref.length; ++i) {
      const c = ref[i];
      if (c === '\r') continue;     // Remove carriage return
      if (c === '\n') {
        res += ' ';                 // Convert newline to space
      } else {
        res += c;
      }
    }
    return res;
  }

  /**
   * Reconstruct commands from a \<script\> tag.
   * @param el - the root \<script\> tag
   */
  private restoreXmlCommands(el: Element): void {
    const children = el.getChildren();
    for (let i = 0; i < children.length; ++i) {
      const subel = children[i];
      this.commands.push(FunctionTestCollection.stripNewlines(subel.getContent()));
    }
  }

  /**
   * Build program (Architecture) from \<binaryimage\> tag.
   * Instantiate an Architecture object.
   */
  private buildProgram(docStorage: DocumentStorage): void {
    const capa = ArchitectureCapability.getCapability("xml");
    if (capa === null) {
      throw new IfaceExecutionError("Missing XML architecture capability");
    }
    this.dcp.conf = capa.buildArchitecture("test", "", this.console.optr);
    this.dcp.conf.init(docStorage);
    this.dcp.conf.readLoaderSymbols("::");
  }

  /** Initialize each FunctionTestProperty. */
  private startTests(): void {
    for (let i = 0; i < this.testList.length; ++i) {
      this.testList[i].startTest();
    }
  }

  /**
   * Let all tests analyze a line of the results.
   * @param line - the given line of output
   */
  private passLineToTests(line: string): void {
    for (let i = 0; i < this.testList.length; ++i) {
      this.testList[i].processLine(line);
    }
  }

  /**
   * Do the final evaluation of each test.
   *
   * This is called after each test has been fed all lines of output.
   * The result of each test is printed to the console, and then
   * failures are written to the lateStream in order to see a summary.
   * @param lateStream - collects failures to display as a summary
   */
  private evaluateTests(lateStream: string[]): void {
    for (let i = 0; i < this.testList.length; ++i) {
      this.numTestsApplied += 1;
      if (this.testList[i].endTest()) {
        this.console.optr.write('Success -- ' + this.testList[i].getName() + '\n');
        this.numTestsSucceeded += 1;
      } else {
        this.console.optr.write('FAIL -- ' + this.testList[i].getName() + '\n');
        lateStream.push(this.testList[i].getName());
      }
    }
  }

  /**
   * Load a test program, tests, and script.
   *
   * Load the architecture based on the discovered \<binaryimage\> tag.
   * Collect the script commands and the specific tests.
   * @param filename - the XML file holding the test data
   */
  loadTest(filename: string): void {
    this.fileName = filename;
    const docStorage = new DocumentStorage();
    let content: string;
    try {
      content = fs.readFileSync(filename, 'utf-8');
    } catch (_e) {
      throw new IfaceParseError('Unable to open test file: ' + filename);
    }
    const doc = docStorage.parseDocument(content);
    const el = doc.getRoot();
    if (el.getName() === 'decompilertest') {
      this.restoreXml(docStorage, el);
    } else if (el.getName() === 'binaryimage') {
      this.restoreXmlOldForm(docStorage, el);
    } else {
      throw new IfaceParseError(
        'Test file ' + filename + ' has unrecognized XML tag: ' + el.getName()
      );
    }
  }

  /**
   * Load tests from a \<decompilertest\> tag.
   */
  restoreXml(store: DocumentStorage, el: Element): void {
    const children = el.getChildren();
    let sawScript = false;
    let sawTests = false;
    let sawProgram = false;
    for (let i = 0; i < children.length; ++i) {
      const subel = children[i];
      if (subel.getName() === 'script') {
        sawScript = true;
        this.restoreXmlCommands(subel);
      } else if (subel.getName() === 'stringmatch') {
        sawTests = true;
        const prop = new FunctionTestProperty();
        prop.restoreXml(subel);
        this.testList.push(prop);
      } else if (subel.getName() === 'binaryimage') {
        sawProgram = true;
        store.registerTag(subel);
        this.buildProgram(store);
      } else {
        throw new IfaceParseError('Unknown tag in <decompilertest>: ' + subel.getName());
      }
    }
    if (!sawScript) {
      throw new IfaceParseError('Did not see <script> tag in <decompilertest>');
    }
    if (!sawTests) {
      throw new IfaceParseError('Did not see any <stringmatch> tags in <decompilertest>');
    }
    if (!sawProgram) {
      throw new IfaceParseError('No <binaryimage> tag in <decompilertest>');
    }
  }

  /**
   * Load tests from \<binaryimage\> tag (old form).
   * Pull the script and tests from a comment in \<binaryimage\>.
   */
  restoreXmlOldForm(_store: DocumentStorage, _el: Element): void {
    throw new IfaceParseError('Old format test not supported');
  }

  /**
   * Run the script and perform the tests.
   *
   * Run the script commands on the current program.
   * Collect any bulk output, and run tests over the output.
   * Report test failures back to the caller.
   * @param lateStream - collects messages for a final summary
   */
  runTests(lateStream: string[]): void {
    const origStream = this.console.optr;
    this.numTestsApplied = 0;
    this.numTestsSucceeded = 0;
    const midBuffer = new StringWriter();         // Collect command console output
    this.console.optr = midBuffer;
    const bulkout = new StringWriter();
    this.console.fileoptr = bulkout;
    mainloop(this.console);
    this.console.optr = origStream;
    this.console.fileoptr = origStream;
    if (this.console.isInError()) {
      this.console.optr.write('Error: Did not apply tests in ' + this.fileName + '\n');
      this.console.optr.write(midBuffer.toString() + '\n');
      lateStream.push('Execution failed for ' + this.fileName);
      return;
    }
    const result = bulkout.toString();
    this.lastOutput = result;
    if ((globalThis as any).__DUMP_OUTPUT__) {
      process.stderr.write('=== DECOMPILER OUTPUT for ' + this.fileName + ' ===\n' + result + '\n=== END ===\n');
    }

    if (result.length === 0) {
      lateStream.push('No output for ' + this.fileName);
      return;
    }
    this.startTests();
    let prevpos = 0;
    let pos = result.indexOf('\n');
    while (pos !== -1) {
      const line = result.substring(prevpos, pos);
      this.passLineToTests(line);
      prevpos = pos + 1;
      pos = result.indexOf('\n', prevpos);
    }
    if (prevpos !== result.length) {
      const line = result.substring(prevpos);   // Process final line without a newline char
      this.passLineToTests(line);
    }
    this.evaluateTests(lateStream);
  }

  /**
   * Run through all XML files in the given list, processing each in turn.
   * @param testFiles - the given list of test files
   * @param s - the output writer to print results to
   * @returns the number of failed tests
   */
  static runTestFiles(testFiles: string[], s: Writer): number {
    let totalTestsApplied = 0;
    let totalTestsSucceeded = 0;
    const failures: string[] = [];
    const testCollection = new FunctionTestCollection(s);
    for (let i = 0; i < testFiles.length; ++i) {
      try {
        testCollection.clear();
        testCollection.loadTest(testFiles[i]);
        testCollection.runTests(failures);
        totalTestsApplied += testCollection.getTestsApplied();
        totalTestsSucceeded += testCollection.getTestsSucceeded();
      } catch (err: unknown) {
        const explain = (err as any)?.explain ?? (err as any)?.message ?? String(err);
        if (err instanceof IfaceParseError) {
          const msg = 'Error parsing ' + testFiles[i] + ': ' + explain;
          s.write(msg + '\n');
          failures.push(msg);
        } else if (err instanceof IfaceExecutionError) {
          const msg = 'Error executing ' + testFiles[i] + ': ' + explain;
          s.write(msg + '\n');
          failures.push(msg);
        } else if (err instanceof LowlevelError || err instanceof DecoderError) {
          const msg = 'Error loading ' + testFiles[i] + ': ' + explain;
          s.write(msg + '\n');
          failures.push(msg);
        } else {
          const msg = 'Unexpected error in ' + testFiles[i] + ': ' + explain;
          s.write(msg + '\n');
          failures.push(msg);
        }
      }
    }

    s.write('\n');
    s.write('Total tests applied = ' + totalTestsApplied + '\n');
    s.write('Total passing tests = ' + totalTestsSucceeded + '\n');
    s.write('\n');
    if (failures.length > 0) {
      s.write('Failures: \n');
      const limit = Math.min(10, failures.length);
      for (let i = 0; i < limit; ++i) {
        s.write('  ' + failures[i] + '\n');
      }
    }
    return totalTestsApplied - totalTestsSucceeded;
  }
}
