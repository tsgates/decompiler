/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/// \file compression.ts
/// \brief The Compress and Decompress classes wrapping the deflate and inflate algorithms

import { deflateSync, inflateSync, constants } from 'zlib';

import { LowlevelError } from '../core/error.js';
import type { Writer } from '../util/writer.js';

/// \brief Wrapper for the deflate algorithm
///
/// Initialize/free algorithm resources.  Provide successive arrays of bytes to compress via
/// the input() method.  Compute successive arrays of compressed bytes via the deflate() method.
export class Compress {
  private level: number;                ///< The zlib compression level
  private inputBuffer: Uint8Array | null;  ///< Current input data
  private inputOffset: number;          ///< Current offset into input data

  /// Initialize the deflate algorithm state
  /// The compression level ranges from 1-9 from faster/least compression to slower/most compression.
  /// Use a level of 0 for no compression and -1 for the default compression level.
  /// \param level is the compression level
  constructor(level: number) {
    this.level = level;
    this.inputBuffer = null;
    this.inputOffset = 0;
  }

  /// \brief Provide the next sequence of bytes to be compressed
  ///
  /// \param buffer is the bytes to compress
  /// \param sz is the number of bytes
  input(buffer: Uint8Array, sz: number): void {
    this.inputBuffer = buffer.subarray(0, sz);
    this.inputOffset = 0;
  }

  /// Deflate as much as possible into given buffer.
  /// Return the number of bytes of output space still available.  Output may be limited by the amount
  /// of space in the output buffer or the amount of data available in the current input buffer.
  /// \param buffer is where compressed bytes are stored
  /// \param sz is the size, in bytes, of the buffer
  /// \param finish is set to true if this is the final buffer to add to the stream
  /// \return the number of output bytes still available
  deflate(buffer: Uint8Array, sz: number, finish: boolean): number {
    if (this.inputBuffer === null) {
      return sz;
    }
    const remaining = this.inputBuffer.subarray(this.inputOffset);
    if (remaining.length === 0 && !finish) {
      return sz;
    }
    try {
      const flush = finish ? constants.Z_FINISH : constants.Z_NO_FLUSH;
      const compressed = deflateSync(Buffer.from(remaining), {
        level: this.level,
        flush: flush,
      });
      const copyLen = Math.min(compressed.length, sz);
      buffer.set(compressed.subarray(0, copyLen), 0);
      this.inputOffset += remaining.length;
      return sz - copyLen;
    } catch (e) {
      throw new LowlevelError('Error compressing stream');
    }
  }
}

/// \brief Wrapper for the inflate algorithm
///
/// Initialize/free algorithm resources. Provide successive arrays of compressed bytes via
/// the input() method. Compute successive arrays of uncompressed bytes via the inflate() method.
export class Decompress {
  private _streamFinished: boolean;           ///< Set to true if the end of the compressed stream has been reached
  private pendingChunks: Uint8Array[];        ///< Accumulated compressed input chunks
  private decompressed: Uint8Array | null;    ///< Result of decompression
  private decompressedOffset: number;         ///< Current read offset into decompressed data

  /// Initialize the inflate algorithm state
  constructor() {
    this._streamFinished = false;
    this.pendingChunks = [];
    this.decompressed = null;
    this.decompressedOffset = 0;
  }

  /// \brief Provide the next sequence of compressed bytes
  ///
  /// \param buffer is the compressed bytes
  /// \param sz is the number of bytes
  input(buffer: Uint8Array, sz: number): void {
    this.pendingChunks.push(buffer.slice(0, sz));
  }

  /// Return true if end of compressed stream is reached
  isFinished(): boolean {
    return this._streamFinished;
  }

  /// Inflate as much as possible into given buffer.
  /// Return the number of bytes of output space still available.  Output may be limited by the amount
  /// of space in the output buffer or the amount of data available in the current input buffer.
  /// \param buffer is where uncompressed bytes are stored
  /// \param sz is the size, in bytes, of the buffer
  /// \return the number of output bytes still available
  inflate(buffer: Uint8Array, sz: number): number {
    // If we haven't decompressed yet, do it now from all accumulated input
    if (this.decompressed === null && this.pendingChunks.length > 0) {
      const totalLen = this.pendingChunks.reduce((sum, c) => sum + c.length, 0);
      const combined = new Uint8Array(totalLen);
      let offset = 0;
      for (const chunk of this.pendingChunks) {
        combined.set(chunk, offset);
        offset += chunk.length;
      }
      this.pendingChunks = [];
      try {
        this.decompressed = inflateSync(Buffer.from(combined));
        this.decompressedOffset = 0;
      } catch (e) {
        throw new LowlevelError('Error decompressing stream');
      }
    }

    if (this.decompressed === null) {
      return sz;
    }

    const available = this.decompressed.length - this.decompressedOffset;
    const copyLen = Math.min(available, sz);
    buffer.set(
      this.decompressed.subarray(this.decompressedOffset, this.decompressedOffset + copyLen),
      0
    );
    this.decompressedOffset += copyLen;

    if (this.decompressedOffset >= this.decompressed.length) {
      this._streamFinished = true;
    }

    return sz - copyLen;
  }
}

/// \brief Stream buffer that performs compression
///
/// Provides a writer filter that compresses the stream using the deflate algorithm.
/// The buffer is provided a backing Writer that is the ultimate destination of the compressed bytes.
/// After writing the full sequence of bytes to compress, call flush() to emit the final compressed
/// bytes to the backing writer.
export class CompressBuffer {
  private static readonly IN_BUFFER_SIZE: number = 4096;   ///< Number of bytes in the input buffer
  private static readonly OUT_BUFFER_SIZE: number = 4096;  ///< Number of bytes in the output buffer
  private outWriter: Writer;                ///< The backing writer receiving compressed bytes
  private inBuffer: Uint8Array;             ///< The input buffer
  private outBuffer: Uint8Array;            ///< The output buffer
  private compressor: Compress;             ///< Compressor state
  private inPos: number;                    ///< Current write position in the input buffer

  /// Constructor
  /// \param writer is the backing output writer
  /// \param level is the level of compression
  constructor(writer: Writer, level: number) {
    this.outWriter = writer;
    this.compressor = new Compress(level);
    this.inBuffer = new Uint8Array(CompressBuffer.IN_BUFFER_SIZE);
    this.outBuffer = new Uint8Array(CompressBuffer.OUT_BUFFER_SIZE);
    this.inPos = 0;
  }

  /// Compress the current set of bytes in the input buffer.
  /// The compressor is called repeatedly and its output is written to the backing writer
  /// until the compressor can no longer fill the output buffer.
  /// \param lastBuffer is true if this is the final set of bytes to add to the compressed stream
  private flushInput(lastBuffer: boolean): void {
    const len = this.inPos;
    this.compressor.input(this.inBuffer.subarray(0, len), len);
    let outAvail: number;
    do {
      outAvail = CompressBuffer.OUT_BUFFER_SIZE;
      outAvail = this.compressor.deflate(this.outBuffer, outAvail, lastBuffer);
      const written = CompressBuffer.OUT_BUFFER_SIZE - outAvail;
      if (written > 0) {
        // Convert compressed bytes to a binary string for the Writer
        const bytes = this.outBuffer.subarray(0, written);
        const parts: string[] = [];
        for (let i = 0; i < bytes.length; i++) {
          parts.push(String.fromCharCode(bytes[i]!));
        }
        this.outWriter.write(parts.join(''));
      }
    } while (outAvail === 0);
    this.inPos = 0;
  }

  /// Write a single byte to the buffer
  /// \param c is the byte value to write
  writeByte(c: number): void {
    this.inBuffer[this.inPos] = c;
    this.inPos++;
    if (this.inPos >= CompressBuffer.IN_BUFFER_SIZE) {
      this.flushInput(false);
    }
  }

  /// Write a sequence of bytes to the buffer
  /// \param data is the bytes to write
  writeBytes(data: Uint8Array): void {
    for (let i = 0; i < data.length; i++) {
      this.writeByte(data[i]!);
    }
  }

  /// Flush remaining bytes in the input buffer to the compressor and finalize
  flush(): void {
    this.flushInput(true);
  }
}
