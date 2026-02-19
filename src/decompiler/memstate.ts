/**
 * @file memstate.ts
 * @description Classes for keeping track of memory state during emulation.
 *
 * Translated from Ghidra's memstate.hh / memstate.cc.
 */

import type { int4, uint4, uintb } from '../core/types.js';
import { HOST_ENDIAN } from '../core/types.js';
import { LowlevelError } from '../core/error.js';
import { AddrSpace, spacetype } from '../core/space.js';
import { Address, byte_swap, calc_mask } from '../core/address.js';
import { VarnodeData } from '../core/pcoderaw.js';
import { LoadImage } from './loadimage.js';
import { DataUnavailError } from './loadimage.js';

// Forward declarations for types from not-yet-written modules
type Translate = any;

// ---------------------------------------------------------------------------
// MemoryBank
// ---------------------------------------------------------------------------

/**
 * Memory storage/state for a single AddressSpace.
 *
 * Class for setting and getting memory values within a space.
 * The basic API is to get/set arrays of byte values via offset within the space.
 * Helper functions getValue and setValue easily retrieve/store integers
 * of various sizes from memory, using the endianness encoding specified by the space.
 * Accesses through the public interface are automatically broken down into
 * word accesses, through the private insert/find methods, and page
 * accesses through getPage/setPage. So these are the virtual methods that need
 * to be overridden in the derived classes.
 */
export abstract class MemoryBank {
  private wordsize: number;   // Number of bytes in an aligned word access
  private pagesize: number;   // Number of bytes in an aligned page access
  private space: AddrSpace;   // The address space associated with this memory

  /**
   * Generic constructor for a memory bank.
   * A MemoryBank must be associated with a specific address space, have a preferred or natural
   * wordsize and a natural pagesize. Both the wordsize and pagesize must be a power of 2.
   * @param spc is the associated address space
   * @param ws is the number of bytes in the preferred wordsize
   * @param ps is the number of bytes in a page
   */
  constructor(spc: AddrSpace, ws: number, ps: number) {
    this.space = spc;
    this.wordsize = ws;
    this.pagesize = ps;
  }

  /** Insert a word in memory bank at an aligned location */
  protected abstract insert(addr: bigint, val: bigint): void;

  /** Retrieve a word from memory bank at an aligned location */
  protected abstract find(addr: bigint): bigint;

  /**
   * Retrieve data from a memory page.
   *
   * This routine only retrieves data from a single page in the memory bank. Bytes need not
   * be retrieved from the exact start of a page, but all bytes must come from one page.
   * A page is a fixed number of bytes, and the address of a page is always aligned based
   * on that number of bytes. The default implementation retrieves the page as aligned words
   * using the find method.
   * @param addr is the aligned offset of the desired page
   * @param res is the buffer where fetched data should be written
   * @param skip is the offset into the page to get the bytes from
   * @param size is the number of bytes to retrieve
   */
  protected getPage(addr: bigint, res: Uint8Array, skip: number, size: number): void {
    let ptraddr = addr + BigInt(skip);
    const endaddr = ptraddr + BigInt(size);
    let startalign = ptraddr & ~BigInt(this.wordsize - 1);
    let endalign = endaddr & ~BigInt(this.wordsize - 1);
    if ((endaddr & BigInt(this.wordsize - 1)) !== 0n) {
      endalign += BigInt(this.wordsize);
    }

    const bswap = (((HOST_ENDIAN as number) === 1) !== this.space.isBigEndian());
    let resOffset = 0;
    do {
      let curval = this.find(startalign);
      if (bswap) {
        curval = byte_swap(curval, this.wordsize);
      }
      // Deconstruct curval into a temporary byte array (little-endian layout in memory)
      const wordBytes = new Uint8Array(this.wordsize);
      let tmp = curval;
      for (let b = 0; b < this.wordsize; b++) {
        wordBytes[b] = Number(tmp & 0xFFn);
        tmp >>= 8n;
      }

      let ptrOff = 0;
      let sz = this.wordsize;
      if (startalign < addr) {
        ptrOff += Number(addr - startalign);
        sz = this.wordsize - Number(addr - startalign);
      }
      if (startalign + BigInt(this.wordsize) > endaddr) {
        sz -= Number(startalign + BigInt(this.wordsize) - endaddr);
      }
      for (let i = 0; i < sz; i++) {
        res[resOffset + i] = wordBytes[ptrOff + i];
      }
      resOffset += sz;
      startalign += BigInt(this.wordsize);
    } while (startalign !== endalign);
  }

  /**
   * Write data into a memory page.
   *
   * This routine writes data only to a single page of the memory bank. Bytes need not be
   * written to the exact start of the page, but all bytes must be written to only one page.
   * The default implementation writes the page as a sequence of aligned words, using the
   * insert method.
   * @param addr is the aligned offset of the desired page
   * @param val is a pointer to the bytes to be written into the page
   * @param skip is the offset into the page where bytes will be written
   * @param size is the number of bytes to be written
   */
  protected setPage(addr: bigint, val: Uint8Array, skip: number, size: number): void {
    let ptraddr = addr + BigInt(skip);
    const endaddr = ptraddr + BigInt(size);
    let startalign = ptraddr & ~BigInt(this.wordsize - 1);
    let endalign = endaddr & ~BigInt(this.wordsize - 1);
    if ((endaddr & BigInt(this.wordsize - 1)) !== 0n) {
      endalign += BigInt(this.wordsize);
    }

    const bswap = (((HOST_ENDIAN as number) === 1) !== this.space.isBigEndian());
    let valOffset = 0;
    do {
      let ptrOff = 0;
      let sz = this.wordsize;
      if (startalign < addr) {
        ptrOff += Number(addr - startalign);
        sz = this.wordsize - Number(addr - startalign);
      }
      if (startalign + BigInt(this.wordsize) > endaddr) {
        sz -= Number(startalign + BigInt(this.wordsize) - endaddr);
      }

      let curval: bigint;
      if (sz !== this.wordsize) {
        // Part of word is copied from underlying
        curval = this.find(startalign);
        // Deconstruct curval into temporary bytes
        const wordBytes = new Uint8Array(this.wordsize);
        let tmp = curval;
        for (let b = 0; b < this.wordsize; b++) {
          wordBytes[b] = Number(tmp & 0xFFn);
          tmp >>= 8n;
        }
        // Overwrite partial region from val
        for (let i = 0; i < sz; i++) {
          wordBytes[ptrOff + i] = val[valOffset + i];
        }
        // Reconstruct curval from wordBytes
        curval = 0n;
        for (let b = this.wordsize - 1; b >= 0; b--) {
          curval = (curval << 8n) | BigInt(wordBytes[b]);
        }
      } else {
        // val supplies entire word - read wordsize bytes from val in native byte order
        curval = 0n;
        for (let b = this.wordsize - 1; b >= 0; b--) {
          curval = (curval << 8n) | BigInt(val[valOffset + b]);
        }
      }
      if (bswap) {
        curval = byte_swap(curval, this.wordsize);
      }
      this.insert(startalign, curval);
      valOffset += sz;
      startalign += BigInt(this.wordsize);
    } while (startalign !== endalign);
  }

  /**
   * Get the number of bytes in a word for this memory bank.
   * A MemoryBank is instantiated with a natural word size. Requests for arbitrary byte ranges
   * may be broken down into units of this size.
   */
  getWordSize(): number {
    return this.wordsize;
  }

  /**
   * Get the number of bytes in a page for this memory bank.
   * A MemoryBank is instantiated with a natural page size. Requests for large chunks of data
   * may be broken down into units of this size.
   */
  getPageSize(): number {
    return this.pagesize;
  }

  /**
   * Get the address space associated with this memory bank.
   * A MemoryBank is a contiguous sequence of bytes associated with a particular address space.
   */
  getSpace(): AddrSpace {
    return this.space;
  }

  /**
   * Set the value of a (small) range of bytes.
   *
   * This routine is used to set a single value in the memory bank at an arbitrary address.
   * It takes into account the endianness of the associated address space when encoding the
   * value as bytes in the bank. The value is broken up into aligned pieces of wordsize and
   * the actual write is performed with the insert routine. If only parts of aligned words
   * are written to, then the remaining parts are filled in with the original value, via the
   * find routine.
   * @param offset is the start of the byte range to write
   * @param size is the number of bytes in the range to write
   * @param val is the value to be written
   */
  setValue(offset: bigint, size: number, val: bigint): void {
    const alignmask = BigInt(this.wordsize - 1);
    const ind = offset & (~alignmask);
    const skip = Number(offset & alignmask);
    let size1 = this.wordsize - skip;
    let size2: number;
    let gap: number;
    let val1: bigint;
    let val2: bigint;

    if (size > size1) {
      // We have spill over
      size2 = size - size1;
      val1 = this.find(ind);
      val2 = this.find(ind + BigInt(this.wordsize));
      gap = this.wordsize - size2;
    } else {
      if (size === this.wordsize) {
        this.insert(ind, val);
        return;
      }
      val1 = this.find(ind);
      val2 = 0n;
      gap = size1 - size;
      size1 = size;
      size2 = 0;
    }

    const skipBits = skip * 8;
    const gapBits = gap * 8;
    if (this.space.isBigEndian()) {
      if (size2 === 0) {
        val1 &= ~(calc_mask(size1) << BigInt(gapBits));
        val1 |= val << BigInt(gapBits);
        this.insert(ind, val1);
      } else {
        val1 &= (~0n & 0xFFFFFFFFFFFFFFFFn) << BigInt(8 * size1);
        val1 |= val >> BigInt(8 * size2);
        this.insert(ind, val1);
        val2 &= (~0n & 0xFFFFFFFFFFFFFFFFn) >> BigInt(8 * size2);
        val2 |= val << BigInt(gapBits);
        this.insert(ind + BigInt(this.wordsize), val2);
      }
    } else {
      if (size2 === 0) {
        val1 &= ~(calc_mask(size1) << BigInt(skipBits));
        val1 |= val << BigInt(skipBits);
        this.insert(ind, val1);
      } else {
        val1 &= (~0n & 0xFFFFFFFFFFFFFFFFn) >> BigInt(8 * size1);
        val1 |= val << BigInt(skipBits);
        this.insert(ind, val1);
        val2 &= (~0n & 0xFFFFFFFFFFFFFFFFn) << BigInt(8 * size2);
        val2 |= val >> BigInt(8 * size1);
        this.insert(ind + BigInt(this.wordsize), val2);
      }
    }
  }

  /**
   * Retrieve the value encoded in a (small) range of bytes.
   *
   * This routine gets the value from a range of bytes at an arbitrary address.
   * It takes into account the endianness of the underlying space when decoding the value.
   * The value is constructed by making one or more aligned word queries, using the find method.
   * The desired value may span multiple words and is reconstructed properly.
   * @param offset is the start of the byte range encoding the value
   * @param size is the number of bytes in the range
   * @returns the decoded value
   */
  getValue(offset: bigint, size: number): bigint {
    const alignmask = BigInt(this.wordsize - 1);
    const ind = offset & (~alignmask);
    const skip = Number(offset & alignmask);
    let size1 = this.wordsize - skip;
    let size2: number;
    let gap: number;
    let val1: bigint;
    let val2: bigint;

    if (size > size1) {
      // We have spill over
      size2 = size - size1;
      val1 = this.find(ind);
      val2 = this.find(ind + BigInt(this.wordsize));
      gap = this.wordsize - size2;
    } else {
      val1 = this.find(ind);
      val2 = 0n;
      if (size === this.wordsize) return val1;
      gap = size1 - size;
      size1 = size;
      size2 = 0;
    }

    let res: bigint;
    if (this.space.isBigEndian()) {
      if (size2 === 0) {
        res = val1 >> BigInt(8 * gap);
      } else {
        res = (val1 << BigInt(8 * size2)) | (val2 >> BigInt(8 * gap));
      }
    } else {
      if (size2 === 0) {
        res = val1 >> BigInt(skip * 8);
      } else {
        res = (val1 >> BigInt(skip * 8)) | (val2 << BigInt(size1 * 8));
      }
    }
    res &= calc_mask(size);
    return res;
  }

  /**
   * Set values of an arbitrary sequence of bytes.
   *
   * This is the most general method for writing a sequence of bytes into the memory bank.
   * There is no restriction on the offset to write to or the number of bytes to be written,
   * except that the range must be contained in the address space.
   * @param offset is the start of the byte range to be written
   * @param size is the number of bytes to write
   * @param val is the sequence of bytes to be written into the bank
   */
  setChunk(offset: bigint, size: number, val: Uint8Array): void {
    const pagemask = BigInt(this.pagesize - 1);
    let count = 0;
    let curOffset = offset;
    let valOffset = 0;

    while (count < size) {
      let cursize = this.pagesize;
      const offalign = curOffset & ~pagemask;
      let skip = 0;
      if (offalign !== curOffset) {
        skip = Number(curOffset - offalign);
        cursize -= skip;
      }
      if (size - count < cursize) {
        cursize = size - count;
      }
      this.setPage(offalign, val.subarray(valOffset), skip, cursize);
      count += cursize;
      curOffset += BigInt(cursize);
      valOffset += cursize;
    }
  }

  /**
   * Retrieve an arbitrary sequence of bytes.
   *
   * This is the most general method for reading a sequence of bytes from the memory bank.
   * There is no restriction on the offset or the number of bytes to read, except that the
   * range must be contained in the address space.
   * @param offset is the start of the byte range to read
   * @param size is the number of bytes to read
   * @param res is the buffer where the retrieved bytes should be stored
   */
  getChunk(offset: bigint, size: number, res: Uint8Array): void {
    const pagemask = BigInt(this.pagesize - 1);
    let count = 0;
    let curOffset = offset;
    let resOffset = 0;

    while (count < size) {
      let cursize = this.pagesize;
      const offalign = curOffset & ~pagemask;
      let skip = 0;
      if (offalign !== curOffset) {
        skip = Number(curOffset - offalign);
        cursize -= skip;
      }
      if (size - count < cursize) {
        cursize = size - count;
      }
      this.getPage(offalign, res.subarray(resOffset), skip, cursize);
      count += cursize;
      curOffset += BigInt(cursize);
      resOffset += cursize;
    }
  }

  /**
   * Decode bytes to value.
   *
   * This is a static convenience routine for decoding a value from a sequence of bytes depending
   * on the desired endianness.
   * @param ptr is the byte array to decode
   * @param size is the number of bytes
   * @param bigendian is true if the bytes are encoded in big endian form
   * @returns the decoded value
   */
  static constructValue(ptr: Uint8Array, size: number, bigendian: boolean): bigint {
    let res = 0n;
    if (bigendian) {
      for (let i = 0; i < size; i++) {
        res <<= 8n;
        res += BigInt(ptr[i]);
      }
    } else {
      for (let i = size - 1; i >= 0; i--) {
        res <<= 8n;
        res += BigInt(ptr[i]);
      }
    }
    return res;
  }

  /**
   * Encode value to bytes.
   *
   * This is a static convenience routine for encoding bytes from a given value, depending on
   * the desired endianness.
   * @param ptr is the buffer to write the encoded bytes into
   * @param val is the value to be encoded
   * @param size is the number of bytes to encode
   * @param bigendian is true if a big endian encoding is desired
   */
  static deconstructValue(ptr: Uint8Array, val: bigint, size: number, bigendian: boolean): void {
    let v = val;
    if (bigendian) {
      for (let i = size - 1; i >= 0; i--) {
        ptr[i] = Number(v & 0xFFn);
        v >>= 8n;
      }
    } else {
      for (let i = 0; i < size; i++) {
        ptr[i] = Number(v & 0xFFn);
        v >>= 8n;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// MemoryImage
// ---------------------------------------------------------------------------

/**
 * A kind of MemoryBank which retrieves its data from an underlying LoadImage.
 *
 * Any bytes requested on the bank which lie in the LoadImage are retrieved from
 * the LoadImage. Other addresses in the space are filled in with zero.
 * This bank cannot be written to.
 */
export class MemoryImage extends MemoryBank {
  private loader: LoadImage;

  /**
   * Constructor for a loadimage memorybank.
   * @param spc is the address space associated with the memory bank
   * @param ws is the number of bytes in the preferred wordsize (must be power of 2)
   * @param ps is the number of bytes in a page (must be power of 2)
   * @param ld is the underlying LoadImage
   */
  constructor(spc: AddrSpace, ws: number, ps: number, ld: LoadImage) {
    super(spc, ws, ps);
    this.loader = ld;
  }

  /** Exception is thrown for write attempts */
  protected insert(_addr: bigint, _val: bigint): void {
    throw new LowlevelError('Writing to read-only MemoryBank');
  }

  /**
   * Overridden find method.
   *
   * Find an aligned word from the bank. First an attempt is made to fetch the data from the
   * LoadImage. If this fails, the value is returned as 0.
   * @param addr is the address of the word to fetch
   * @returns the fetched value
   */
  protected find(addr: bigint): bigint {
    let res = 0n;
    const spc = this.getSpace();
    try {
      const wordSize = this.getWordSize();
      const buf = new Uint8Array(wordSize);
      this.loader.loadFill(buf, wordSize, new Address(spc, addr));
      // Reconstruct the value from the loaded bytes.
      // In C++ the bytes are loaded into the appropriate offset within a uintb
      // depending on host endianness. We always treat our buffer as holding the
      // raw bytes in address order and reconstruct accordingly.
      // If host is big-endian, data goes into the high bytes of the word;
      // otherwise it fills from byte 0. Since HOST_ENDIAN is 0 (little-endian)
      // in our environment, we just reconstruct from byte 0 in LE order, then
      // swap if needed below.
      if ((HOST_ENDIAN as number) === 1) {
        // Big-endian host: data placed at high end of word
        for (let i = 0; i < wordSize; i++) {
          res = (res << 8n) | BigInt(buf[i]);
        }
      } else {
        // Little-endian host: data placed at byte 0
        for (let i = wordSize - 1; i >= 0; i--) {
          res = (res << 8n) | BigInt(buf[i]);
        }
      }
    } catch (err) {
      if (err instanceof DataUnavailError) {
        // Pages not mapped in the load image are assumed to be zero
        res = 0n;
      } else {
        throw err;
      }
    }
    if (((HOST_ENDIAN as number) === 1) !== spc.isBigEndian()) {
      res = byte_swap(res, this.getWordSize());
    }
    return res;
  }

  /**
   * Overridden getPage method.
   *
   * Retrieve an aligned page from the bank. First an attempt is made to retrieve the
   * page from the LoadImage, which may do its own zero filling. If the attempt fails, the
   * page is entirely filled in with zeros.
   */
  protected getPage(addr: bigint, res: Uint8Array, skip: number, size: number): void {
    const spc = this.getSpace();
    try {
      this.loader.loadFill(res, size, new Address(spc, addr + BigInt(skip)));
    } catch (err) {
      if (err instanceof DataUnavailError) {
        // Pages not mapped in the load image are assumed to be zero
        for (let i = 0; i < size; i++) {
          res[i] = 0;
        }
      } else {
        throw err;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// MemoryPageOverlay
// ---------------------------------------------------------------------------

/**
 * Memory bank that overlays some other memory bank, using a "copy on write" behavior.
 *
 * Pages are copied from the underlying object only when there is
 * a write. The underlying access routines are overridden to make optimal use
 * of this page implementation. The underlying memory bank can be a null pointer
 * in which case, this memory bank behaves as if it were initially filled with zeros.
 */
export class MemoryPageOverlay extends MemoryBank {
  private underlie: MemoryBank | null;            // Underlying memory object
  private page: Map<bigint, Uint8Array> = new Map(); // Overlayed pages

  /**
   * Constructor for page overlay.
   * @param spc is the address space associated with the memory bank
   * @param ws is the number of bytes in the preferred wordsize (must be power of 2)
   * @param ps is the number of bytes in a page (must be power of 2)
   * @param ul is the underlying MemoryBank (may be null)
   */
  constructor(spc: AddrSpace, ws: number, ps: number, ul: MemoryBank | null) {
    super(spc, ws, ps);
    this.underlie = ul;
  }

  /**
   * Overridden aligned word insert.
   *
   * This derived method looks for a previously cached page of the underlying memory bank.
   * If the cached page does not exist, it creates it and fills in its initial value by
   * retrieving the page from the underlying bank. The new value is then written into
   * the cached page.
   * @param addr is the aligned address of the word to be written
   * @param val is the value to be written at that word
   */
  protected insert(addr: bigint, val: bigint): void {
    const pageaddr = addr & ~BigInt(this.getPageSize() - 1);

    let pageptr: Uint8Array;
    const existing = this.page.get(pageaddr);
    if (existing !== undefined) {
      pageptr = existing;
    } else {
      pageptr = new Uint8Array(this.getPageSize());
      this.page.set(pageaddr, pageptr);
      if (this.underlie === null) {
        // Already zeroed by Uint8Array constructor
      } else {
        (this.underlie as any).getPage(pageaddr, pageptr, 0, this.getPageSize());
      }
    }

    const pageoffset = Number(addr & BigInt(this.getPageSize() - 1));
    MemoryBank.deconstructValue(
      pageptr.subarray(pageoffset),
      val,
      this.getWordSize(),
      this.getSpace().isBigEndian()
    );
  }

  /**
   * Overridden aligned word find.
   *
   * This derived method first looks for the aligned word in the mapped pages. If the
   * address is not mapped, the search is forwarded to the underlying memory bank.
   * If there is no underlying bank, zero is returned.
   * @param addr is the aligned offset of the word
   * @returns the retrieved value
   */
  protected find(addr: bigint): bigint {
    const pageaddr = addr & ~BigInt(this.getPageSize() - 1);

    const existing = this.page.get(pageaddr);
    if (existing === undefined) {
      if (this.underlie === null) return 0n;
      return (this.underlie as any).find(addr);
    }

    const pageoffset = Number(addr & BigInt(this.getPageSize() - 1));
    return MemoryBank.constructValue(
      existing.subarray(pageoffset),
      this.getWordSize(),
      this.getSpace().isBigEndian()
    );
  }

  /**
   * Overridden getPage.
   *
   * The desired page is looked for in the page cache. If it doesn't exist, the
   * request is forwarded to the underlying bank. If there is no underlying bank, the
   * result buffer is filled with zeros.
   * @param addr is the aligned offset of the page
   * @param res is the buffer where retrieved bytes should be stored
   * @param skip is the offset into the page from where bytes should be retrieved
   * @param size is the number of bytes to retrieve
   */
  protected getPage(addr: bigint, res: Uint8Array, skip: number, size: number): void {
    const existing = this.page.get(addr);
    if (existing === undefined) {
      if (this.underlie === null) {
        for (let i = 0; i < size; i++) {
          res[i] = 0;
        }
        return;
      }
      (this.underlie as any).getPage(addr, res, skip, size);
      return;
    }
    res.set(existing.subarray(skip, skip + size));
  }

  /**
   * Overridden setPage.
   *
   * First, a cached version of the desired page is searched for via its address. If it doesn't
   * exist, it is created, and its initial value is filled via the underlying bank. The bytes
   * to be written are then copied into the cached page.
   * @param addr is the aligned offset of the page to write
   * @param val is the bytes to be written into the page
   * @param skip is the offset into the page where bytes should be written
   * @param size is the number of bytes to write
   */
  protected setPage(addr: bigint, val: Uint8Array, skip: number, size: number): void {
    let pageptr: Uint8Array;

    const existing = this.page.get(addr);
    if (existing === undefined) {
      pageptr = new Uint8Array(this.getPageSize());
      this.page.set(addr, pageptr);
      if (size !== this.getPageSize()) {
        if (this.underlie === null) {
          // Already zeroed by Uint8Array constructor
        } else {
          (this.underlie as any).getPage(addr, pageptr, 0, this.getPageSize());
        }
      }
    } else {
      pageptr = existing;
    }

    pageptr.set(val.subarray(0, size), skip);
  }
}

// ---------------------------------------------------------------------------
// MemoryHashOverlay
// ---------------------------------------------------------------------------

/**
 * A memory bank that implements reads and writes using a hash table.
 *
 * The initial state of the bank is taken from an underlying memory bank or is all zero,
 * if this bank is initialized with a null pointer. This implementation will not be very
 * efficient for accessing entire pages.
 */
export class MemoryHashOverlay extends MemoryBank {
  private underlie: MemoryBank | null;  // Underlying memory bank
  private alignshift: number;           // How many LSBs are thrown away from address when doing hash table lookup
  private collideskip: bigint;          // How many slots to skip after a hashtable collision
  private address: bigint[];            // The hashtable addresses
  private value: bigint[];              // The hashtable values

  /**
   * Constructor for hash overlay.
   * @param spc is the address space associated with the memory bank
   * @param ws is the number of bytes in the preferred wordsize (must be power of 2)
   * @param ps is the number of bytes in a page (must be a power of 2)
   * @param hashsize is the maximum number of entries in the hashtable
   * @param ul is the underlying memory bank being overlayed (may be null)
   */
  constructor(spc: AddrSpace, ws: number, ps: number, hashsize: number, ul: MemoryBank | null) {
    super(spc, ws, ps);
    this.underlie = ul;
    this.collideskip = 1023n;

    this.address = new Array(hashsize).fill(0xBADBEEFn);
    this.value = new Array(hashsize).fill(0n);

    let tmp = ws - 1;
    this.alignshift = 0;
    while (tmp !== 0) {
      this.alignshift += 1;
      tmp >>= 1;
    }
  }

  /**
   * Overridden aligned word insert.
   *
   * Write the value into the hashtable, using addr as a key.
   * @param addr is the aligned address of the word being written
   * @param val is the value of the word to write
   */
  protected insert(addr: bigint, val: bigint): void {
    const size = this.address.length;
    let offset = Number((addr >> BigInt(this.alignshift)) % BigInt(size));
    for (let i = 0; i < size; i++) {
      if (this.address[offset] === addr) {
        // Address has been seen before - replace old value
        this.value[offset] = val;
        return;
      } else if (this.address[offset] === 0xBADBEEFn) {
        // Address not seen before - claim this hash slot
        this.address[offset] = addr;
        this.value[offset] = val;
        return;
      }
      offset = Number((BigInt(offset) + this.collideskip) % BigInt(size));
    }
    throw new LowlevelError('Memory state hash_table is full');
  }

  /**
   * Overridden aligned word find.
   *
   * First search for an entry in the hashtable using addr as a key. If there is no
   * entry, forward the query to the underlying memory bank, or return 0 if there is no underlying bank.
   * @param addr is the aligned address of the word to retrieve
   * @returns the retrieved value
   */
  protected find(addr: bigint): bigint {
    const size = this.address.length;
    let offset = Number((addr >> BigInt(this.alignshift)) % BigInt(size));
    for (let i = 0; i < size; i++) {
      if (this.address[offset] === addr) {
        // Address has been seen before
        return this.value[offset];
      } else if (this.address[offset] === 0xBADBEEFn) {
        // Address not seen before
        break;
      }
      offset = Number((BigInt(offset) + this.collideskip) % BigInt(size));
    }

    // We didn't find the address in the hashtable
    if (this.underlie === null) return 0n;
    return (this.underlie as any).find(addr);
  }
}

// ---------------------------------------------------------------------------
// MemoryState
// ---------------------------------------------------------------------------

/**
 * All storage/state for a pcode machine.
 *
 * Every piece of information in a pcode machine is representable as a triple
 * (AddrSpace, offset, size). This class allows getting and setting
 * of all state information of this form.
 */
export class MemoryState {
  protected trans: Translate;                     // Architecture information about memory spaces
  protected memspace: (MemoryBank | null)[] = []; // Memory banks associated with each address space

  /**
   * A constructor for MemoryState.
   *
   * The MemoryState needs a Translate object in order to be able to convert register names
   * into varnodes.
   * @param t is the translator
   */
  constructor(t: Translate) {
    this.trans = t;
  }

  /**
   * Get the Translate object.
   *
   * Retrieve the actual pcode translator being used by this machine state.
   * @returns a reference to the Translate object
   */
  getTranslate(): Translate {
    return this.trans;
  }

  /**
   * Map a memory bank into the state.
   *
   * MemoryBanks associated with specific address spaces must be registered with this MemoryState
   * via this method. Each address space that will be used during emulation must be registered
   * separately. The MemoryState object does not assume responsibility for freeing the MemoryBank.
   * @param bank is the MemoryBank to be registered
   */
  setMemoryBank(bank: MemoryBank): void {
    const spc = bank.getSpace();
    const index = spc.getIndex();

    while (index >= this.memspace.length) {
      this.memspace.push(null);
    }

    this.memspace[index] = bank;
  }

  /**
   * Get a memory bank associated with a particular space.
   *
   * Any MemoryBank that has been registered with this MemoryState can be retrieved via this
   * method if the MemoryBank's associated address space is known.
   * @param spc is the address space of the desired MemoryBank
   * @returns the MemoryBank or null if no bank is associated with spc
   */
  getMemoryBank(spc: AddrSpace): MemoryBank | null {
    const index = spc.getIndex();
    if (index >= this.memspace.length) return null;
    return this.memspace[index];
  }

  /**
   * Set a value on the memory state.
   *
   * This is the main interface for writing values to the MemoryState.
   * If there is no registered MemoryBank for the desired address space, or
   * if there is some other error, an exception is thrown.
   * @param spc is the address space to write to
   * @param off is the offset where the value should be written
   * @param size is the number of bytes to be written
   * @param cval is the value to be written
   */
  setValueSpace(spc: AddrSpace, off: bigint, size: number, cval: bigint): void {
    const mspace = this.getMemoryBank(spc);
    if (mspace === null) {
      throw new LowlevelError('Setting value for unmapped memory space: ' + spc.getName());
    }
    mspace.setValue(off, size, cval);
  }

  /**
   * Retrieve a memory value from the memory state.
   *
   * This is the main interface for reading values from the MemoryState.
   * If there is no registered MemoryBank for the desired address space, or
   * if there is some other error, an exception is thrown.
   * @param spc is the address space being queried
   * @param off is the offset of the value being queried
   * @param size is the number of bytes to query
   * @returns the queried value
   */
  getValueSpace(spc: AddrSpace, off: bigint, size: number): bigint {
    if (spc.getType() === spacetype.IPTR_CONSTANT) return off;
    const mspace = this.getMemoryBank(spc);
    if (mspace === null) {
      throw new LowlevelError('Getting value from unmapped memory space: ' + spc.getName());
    }
    return mspace.getValue(off, size);
  }

  /**
   * Set a value on a named register in the memory state.
   *
   * This is a convenience method for setting registers by name.
   * Any register name known to the Translate object can be used as a write location.
   * The associated address space, offset, and size is looked up and automatically
   * passed to the main setValue routine.
   * @param nm is the name of the register
   * @param cval is the value to write to the register
   */
  setValueName(nm: string, cval: bigint): void {
    const vdata: VarnodeData = this.trans.getRegister(nm);
    this.setValueSpace(vdata.space! as AddrSpace, vdata.offset, vdata.size, cval);
  }

  /**
   * Retrieve a value from a named register in the memory state.
   *
   * This is a convenience method for reading registers by name.
   * Any register name known to the Translate object can be used as a read location.
   * The associated address space, offset, and size is looked up and automatically
   * passed to the main getValue routine.
   * @param nm is the name of the register
   * @returns the value associated with that register
   */
  getValueName(nm: string): bigint {
    const vdata: VarnodeData = this.trans.getRegister(nm);
    return this.getValueSpace(vdata.space! as AddrSpace, vdata.offset, vdata.size);
  }

  /**
   * Set value on a given varnode.
   *
   * A convenience method for setting a value directly on a varnode rather than
   * breaking out the components.
   * @param vn is the varnode to be written
   * @param cval is the value to write into the varnode
   */
  setValueVarnode(vn: VarnodeData, cval: bigint): void {
    this.setValueSpace(vn.space! as AddrSpace, vn.offset, vn.size, cval);
  }

  /**
   * Get a value from a varnode.
   *
   * A convenience method for reading a value directly from a varnode rather
   * than querying for the offset and space.
   * @param vn is the varnode to be read
   * @returns the value read from the varnode
   */
  getValueVarnode(vn: VarnodeData): bigint {
    return this.getValueSpace(vn.space! as AddrSpace, vn.offset, vn.size);
  }

  /**
   * Get a chunk of data from memory state.
   *
   * This is the main interface for reading a range of bytes from the MemoryState.
   * The MemoryBank associated with the address space of the query is looked up
   * and the request is forwarded to the getChunk method on the MemoryBank. If there
   * is no registered MemoryBank or some other error, an exception is thrown.
   * @param res is the result buffer for storing retrieved bytes
   * @param spc is the desired address space
   * @param off is the starting offset of the byte range being queried
   * @param size is the number of bytes being queried
   */
  getChunk(res: Uint8Array, spc: AddrSpace, off: bigint, size: number): void {
    const mspace = this.getMemoryBank(spc);
    if (mspace === null) {
      throw new LowlevelError('Getting chunk from unmapped memory space: ' + spc.getName());
    }
    mspace.getChunk(off, size, res);
  }

  /**
   * Set a chunk of data from memory state.
   *
   * This is the main interface for setting values for a range of bytes in the MemoryState.
   * The MemoryBank associated with the desired address space is looked up and the
   * write is forwarded to the setChunk method on the MemoryBank. If there is no
   * registered MemoryBank or some other error, an exception is thrown.
   * @param val is the byte values to be written into the MemoryState
   * @param spc is the address space being written
   * @param off is the starting offset of the range being written
   * @param size is the number of bytes to write
   */
  setChunk(val: Uint8Array, spc: AddrSpace, off: bigint, size: number): void {
    const mspace = this.getMemoryBank(spc);
    if (mspace === null) {
      throw new LowlevelError('Setting chunk of unmapped memory space: ' + spc.getName());
    }
    mspace.setChunk(off, size, val);
  }
}
