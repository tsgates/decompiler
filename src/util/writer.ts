/**
 * @file writer.ts
 * @description Writer interface replacing C++ ostream for string output.
 */

/**
 * Abstract writer interface that replaces C++ ostream.
 * Implementations can write to strings, files, or other destinations.
 */
export interface Writer {
  write(s: string): void;
}

/**
 * Writer that accumulates output into a string buffer.
 */
export class StringWriter implements Writer {
  private buf: string[] = [];

  write(s: string): void {
    this.buf.push(s);
  }

  toString(): string {
    return this.buf.join('');
  }

  clear(): void {
    this.buf.length = 0;
  }
}

/**
 * Writer that writes to process stdout.
 */
export class ConsoleWriter implements Writer {
  write(s: string): void {
    process.stdout.write(s);
  }
}

/**
 * Utility: write a hex value with optional 0x prefix.
 */
export function writeHex(w: Writer, val: bigint): void {
  w.write('0x');
  w.write(val.toString(16));
}

/**
 * Utility: write a decimal number.
 */
export function writeDec(w: Writer, val: number | bigint): void {
  w.write(val.toString(10));
}
