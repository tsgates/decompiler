#!/usr/bin/env tsx
/**
 * Pure TypeScript binary → XML lifter
 *
 * Parses Mach-O and ELF binaries and emits XML compatible with
 * the decompiler's LoadImageXml / datatests format (same as ghidra_export.py).
 *
 * Zero npm dependencies — uses only Node.js built-ins.
 *
 * Usage:
 *   npx tsx src/console/binary_to_xml.ts [options] <binary>
 *     -o, --output <file>     Write to file (default: stdout)
 *     -f, --functions <list>  Comma-separated function names to emit scripts for
 *     --binaryimage-only      Only emit <binaryimage>, no <script> blocks
 */

import { readFileSync, writeFileSync } from 'fs';

// ── Types ──────────────────────────────────────────────────────────────────

interface BinarySection {
  name: string;
  vaddr: bigint;
  data: Uint8Array;
  readonly: boolean;
}

interface BinarySymbol {
  name: string;
  vaddr: bigint;
  isStub?: boolean;
}

interface ParsedBinary {
  arch: string;
  sections: BinarySection[];
  symbols: BinarySymbol[];
  entry: bigint;
}

// ── Constants ──────────────────────────────────────────────────────────────

// Mach-O
const MH_MAGIC_64 = 0xfeedfacf;
const MH_CIGAM_64 = 0xcffaedfe;
const FAT_MAGIC = 0xcafebabe;
const FAT_CIGAM = 0xbebafeca;

const LC_SEGMENT_64 = 0x19;
const LC_SYMTAB = 0x02;
const LC_DYSYMTAB = 0x0b;
const LC_MAIN = 0x80000028;

const INDIRECT_SYMBOL_LOCAL = 0x80000000;
const INDIRECT_SYMBOL_ABS = 0x40000000;

const CPU_TYPE_X86_64 = 0x01000007;
const CPU_TYPE_ARM64 = 0x0100000c;

// ELF
const ELF_MAGIC = 0x7f454c46; // \x7fELF
const ELFCLASS32 = 1;
const ELFCLASS64 = 2;
const ELFDATA2LSB = 1;
const ELFDATA2MSB = 2;

const PT_LOAD = 1;
const SHT_SYMTAB = 2;
const SHT_DYNSYM = 11;

const STT_FUNC = 2;

const EM_386 = 3;
const EM_ARM = 40;
const EM_X86_64 = 62;
const EM_AARCH64 = 183;

const CHUNK_SIZE = 0x10000; // 64KB, matching ghidra_export.py
const S_ATTR_PURE_INSTRUCTIONS = 0x80000000;
const S_ATTR_SOME_INSTRUCTIONS = 0x00000400;

// Mach-O section info for symbol filtering
interface MachOSection {
  sectname: string;
  segname: string;
  addr: bigint;
  size: bigint;
  flags: number;
  index: number; // 1-based section index (matches nlist n_sect)
  reserved1: number; // index into indirect symbol table (for stubs)
  reserved2: number; // stub entry size (for __stubs)
}

// ── Arch mapping ───────────────────────────────────────────────────────────

function machoArchString(cputype: number): string {
  switch (cputype) {
    case CPU_TYPE_ARM64:
      return 'AARCH64:LE:64:v8A:default';
    case CPU_TYPE_X86_64:
      return 'x86:LE:64:default:gcc';
    default:
      throw new Error(`Unsupported Mach-O cputype: 0x${cputype.toString(16)}`);
  }
}

function elfArchString(machine: number, elfClass: number, endian: number): string {
  const e = endian === ELFDATA2LSB ? 'LE' : 'BE';
  switch (machine) {
    case EM_X86_64:
      return `x86:${e}:64:default:gcc`;
    case EM_386:
      return `x86:${e}:32:default:gcc`;
    case EM_AARCH64:
      return `AARCH64:${e}:64:v8A:default`;
    case EM_ARM:
      return `ARM:${e}:32:v7:default`;
    default:
      throw new Error(`Unsupported ELF e_machine: ${machine}`);
  }
}

// ── Mach-O parser ──────────────────────────────────────────────────────────

function parseMachO(buf: Buffer, offset: number = 0): ParsedBinary {
  // Read header
  const magic = buf.readUInt32LE(offset);
  let le: boolean;
  if (magic === MH_MAGIC_64) {
    le = true;
  } else if (magic === MH_CIGAM_64) {
    le = false;
  } else {
    throw new Error(`Not a Mach-O 64-bit file (magic: 0x${magic.toString(16)})`);
  }

  const readU32 = le
    ? (o: number) => buf.readUInt32LE(o)
    : (o: number) => buf.readUInt32BE(o);
  const readU64 = le
    ? (o: number) => buf.readBigUInt64LE(o)
    : (o: number) => buf.readBigUInt64BE(o);

  const cputype = readU32(offset + 4);
  // cpusubtype at +8
  // filetype at +12
  const ncmds = readU32(offset + 16);
  // sizeofcmds at +20
  // flags at +24
  // reserved at +28
  const headerSize = 32; // mach_header_64

  const arch = machoArchString(cputype);
  const sections: BinarySection[] = [];
  const symbols: BinarySymbol[] = [];
  let entry = 0n;

  let symoff = 0;
  let nsyms = 0;
  let stroff = 0;
  let indirectsymoff = 0;
  let nindirectsyms = 0;

  // Track individual Mach-O sections for symbol filtering (1-based index)
  const machoSections: MachOSection[] = [];
  let sectionIndex = 0;

  // Parse load commands
  let cmdOffset = offset + headerSize;
  for (let i = 0; i < ncmds; i++) {
    const cmd = readU32(cmdOffset);
    const cmdsize = readU32(cmdOffset + 4);

    if (cmd === LC_SEGMENT_64) {
      // segment_command_64
      const segname = buf.toString('ascii', cmdOffset + 8, cmdOffset + 24).replace(/\0+$/, '');
      const vmaddr = readU64(cmdOffset + 24);
      const vmsize = readU64(cmdOffset + 32);
      const fileoff = readU64(cmdOffset + 40);
      const filesize = readU64(cmdOffset + 48);
      // maxprot at +56, initprot at +60
      const nsects = readU32(cmdOffset + 64);
      // flags at +68

      // Skip __PAGEZERO (no data) and segments with no file data
      if (segname !== '__PAGEZERO' && filesize > 0n) {
        const foff = Number(fileoff) + offset;
        const fsize = Number(filesize);
        const data = new Uint8Array(buf.buffer, buf.byteOffset + foff, fsize);
        sections.push({
          name: segname,
          vaddr: vmaddr,
          data,
          readonly: true,
        });
      }

      // Parse individual sections within the segment
      let sectOffset = cmdOffset + 72;
      for (let s = 0; s < nsects; s++) {
        sectionIndex++;
        const sectname = buf.toString('ascii', sectOffset, sectOffset + 16).replace(/\0+$/, '');
        const sectSegname = buf.toString('ascii', sectOffset + 16, sectOffset + 32).replace(/\0+$/, '');
        const sectAddr = readU64(sectOffset + 32);
        const sectSize = readU64(sectOffset + 40);
        // offset at +48, align at +52, reloff at +56, nreloc at +60
        const sectFlags = readU32(sectOffset + 64);
        const sectReserved1 = readU32(sectOffset + 68);
        const sectReserved2 = readU32(sectOffset + 72);

        machoSections.push({
          sectname,
          segname: sectSegname,
          addr: sectAddr,
          size: sectSize,
          flags: sectFlags,
          index: sectionIndex,
          reserved1: sectReserved1,
          reserved2: sectReserved2,
        });

        // section_64 struct: 80 bytes
        sectOffset += 80;
      }
    } else if (cmd === LC_SYMTAB) {
      symoff = readU32(cmdOffset + 8);
      nsyms = readU32(cmdOffset + 12);
      stroff = readU32(cmdOffset + 16);
    } else if (cmd === LC_DYSYMTAB) {
      // dysymtab_command: indirectsymoff at offset 56, nindirectsyms at offset 60
      indirectsymoff = readU32(cmdOffset + 56);
      nindirectsyms = readU32(cmdOffset + 60);
    } else if (cmd === LC_MAIN) {
      // entry point offset (from start of __TEXT)
      const entryoff = readU64(cmdOffset + 8);
      // We'll resolve this after finding __TEXT
      entry = entryoff;
    }

    cmdOffset += cmdsize;
  }

  // Resolve LC_MAIN entry offset → virtual address
  // LC_MAIN gives offset from start of __TEXT segment
  if (entry !== 0n) {
    for (const sec of sections) {
      if (sec.name === '__TEXT') {
        entry = sec.vaddr + entry;
        break;
      }
    }
  }

  // Build set of code section indices (sections with executable instructions)
  const codeSectionIndices = new Set<number>();
  for (const sect of machoSections) {
    if (
      sect.flags & S_ATTR_PURE_INSTRUCTIONS ||
      sect.flags & S_ATTR_SOME_INSTRUCTIONS ||
      sect.sectname === '__text' ||
      sect.sectname === '__stubs' ||
      sect.sectname === '__stub_helper'
    ) {
      codeSectionIndices.add(sect.index);
    }
  }

  // Parse symbol table — only include symbols in code sections
  if (nsyms > 0 && symoff > 0) {
    const nlistSize = 16; // nlist_64
    for (let i = 0; i < nsyms; i++) {
      const noff = offset + symoff + i * nlistSize;
      const strIdx = readU32(noff);
      const nType = buf.readUInt8(noff + 4);
      const nSect = buf.readUInt8(noff + 5);
      // n_desc at +6 (uint16)
      const nValue = readU64(noff + 8);

      // N_SECT = 0x0e means symbol is defined in a section
      // Only include symbols in code sections whose address is within the section range
      // (filters out __mh_execute_header which has n_sect=1 but addr outside __text)
      const sect = machoSections[nSect - 1];
      const inCodeSection =
        codeSectionIndices.has(nSect) &&
        sect &&
        nValue >= sect.addr &&
        nValue < sect.addr + sect.size;
      if ((nType & 0x0e) === 0x0e && nSect > 0 && nValue !== 0n && inCodeSection) {
        // Read symbol name from string table
        let nameEnd = offset + stroff + strIdx;
        while (nameEnd < buf.length && buf[nameEnd] !== 0) nameEnd++;
        let name = buf.toString('ascii', offset + stroff + strIdx, nameEnd);
        if (name.length > 0) {
          // Rename _main → entry to match Ghidra convention
          if (name === '_main' && nValue === entry) {
            name = 'entry';
          }
          symbols.push({ name, vaddr: nValue });
        }
      }
    }
  }

  // Resolve stub symbols from indirect symbol table (LC_DYSYMTAB)
  // Stubs live in __stubs or __auth_stubs sections; the indirect symbol table
  // maps each stub entry to an nlist index, giving us the symbol name.
  if (indirectsymoff > 0 && nindirectsyms > 0 && nsyms > 0 && symoff > 0) {
    const nlistSize = 16; // nlist_64
    for (const sect of machoSections) {
      if (sect.sectname !== '__stubs' && sect.sectname !== '__auth_stubs') continue;

      // Determine stub entry size: reserved2 if set, else default by arch
      const stubSize = sect.reserved2 > 0 ? sect.reserved2 : (cputype === CPU_TYPE_ARM64 ? 12 : 6);
      const stubCount = Number(sect.size) / stubSize;
      const firstIndirect = sect.reserved1;

      for (let i = 0; i < stubCount; i++) {
        const indirectIdx = firstIndirect + i;
        if (indirectIdx >= nindirectsyms) break;

        const symIdx = readU32(offset + indirectsymoff + indirectIdx * 4);
        // Skip special indices
        if (symIdx & INDIRECT_SYMBOL_LOCAL || symIdx & INDIRECT_SYMBOL_ABS) continue;
        if (symIdx >= nsyms) continue;

        // Read symbol name from nlist
        const noff = offset + symoff + symIdx * nlistSize;
        const strIdx = readU32(noff);
        let nameEnd = offset + stroff + strIdx;
        while (nameEnd < buf.length && buf[nameEnd] !== 0) nameEnd++;
        const name = buf.toString('ascii', offset + stroff + strIdx, nameEnd);

        if (name.length > 0) {
          const stubAddr = sect.addr + BigInt(i * stubSize);
          symbols.push({ name, vaddr: stubAddr, isStub: true });
        }
      }
    }
  }

  // If no non-stub function symbols found but we have an entry point, synthesize an entry symbol
  const hasNonStubSymbol = symbols.some((s) => !s.isStub);
  if (!hasNonStubSymbol && entry !== 0n) {
    symbols.push({ name: 'entry', vaddr: entry });
  }

  // Sort symbols by address
  symbols.sort((a, b) => (a.vaddr < b.vaddr ? -1 : a.vaddr > b.vaddr ? 1 : 0));

  return { arch, sections, symbols, entry };
}

// ── Fat binary handler ─────────────────────────────────────────────────────

function parseFatBinary(buf: Buffer): ParsedBinary {
  const magic = buf.readUInt32BE(0);
  const le = magic === FAT_CIGAM;
  const readU32 = le
    ? (o: number) => buf.readUInt32LE(o)
    : (o: number) => buf.readUInt32BE(o);

  const nfatArch = readU32(4);

  // fat_arch is 20 bytes each, starting at offset 8
  // Two passes: first look for arm64, then x86_64
  let x86Offset = -1;
  for (let i = 0; i < nfatArch; i++) {
    const faOffset = 8 + i * 20;
    const cputype = readU32(faOffset);
    const sliceOffset = readU32(faOffset + 8);

    if (cputype === CPU_TYPE_ARM64) {
      return parseMachO(buf, sliceOffset);
    }
    if (cputype === CPU_TYPE_X86_64 && x86Offset < 0) {
      x86Offset = sliceOffset;
    }
  }

  if (x86Offset >= 0) {
    return parseMachO(buf, x86Offset);
  }

  // Fall back to first slice
  if (nfatArch > 0) {
    const sliceOffset = readU32(8 + 8);
    return parseMachO(buf, sliceOffset);
  }

  throw new Error('No suitable architecture found in fat binary');
}

// ── ELF parser ─────────────────────────────────────────────────────────────

function parseELF(buf: Buffer): ParsedBinary {
  const elfClass = buf.readUInt8(4); // EI_CLASS
  const elfData = buf.readUInt8(5); // EI_DATA
  const is64 = elfClass === ELFCLASS64;
  const le = elfData === ELFDATA2LSB;

  const readU16 = le
    ? (o: number) => buf.readUInt16LE(o)
    : (o: number) => buf.readUInt16BE(o);
  const readU32 = le
    ? (o: number) => buf.readUInt32LE(o)
    : (o: number) => buf.readUInt32BE(o);
  const readU64 = le
    ? (o: number) => buf.readBigUInt64LE(o)
    : (o: number) => buf.readBigUInt64BE(o);
  const readAddr = is64
    ? (o: number) => readU64(o)
    : (o: number) => BigInt(readU32(o));
  const readOff = readAddr;

  // ELF header
  const eMachine = readU16(18);
  let entry: bigint;
  let phoff: bigint;
  let shoff: bigint;
  let phentsize: number;
  let phnum: number;
  let shentsize: number;
  let shnum: number;
  let shstrndx: number;

  if (is64) {
    entry = readU64(24);
    phoff = readU64(32);
    shoff = readU64(40);
    // flags at 48
    // ehsize at 52
    phentsize = readU16(54);
    phnum = readU16(56);
    shentsize = readU16(58);
    shnum = readU16(60);
    shstrndx = readU16(62);
  } else {
    entry = BigInt(readU32(24));
    phoff = BigInt(readU32(28));
    shoff = BigInt(readU32(32));
    // flags at 36
    // ehsize at 40
    phentsize = readU16(42);
    phnum = readU16(44);
    shentsize = readU16(46);
    shnum = readU16(48);
    shstrndx = readU16(50);
  }

  const arch = elfArchString(eMachine, elfClass, elfData);
  const sections: BinarySection[] = [];
  const symbols: BinarySymbol[] = [];

  // Parse program headers → PT_LOAD segments
  for (let i = 0; i < phnum; i++) {
    const phOff = Number(phoff) + i * phentsize;
    const pType = readU32(phOff);

    if (pType === PT_LOAD) {
      let pOffset: bigint, pVaddr: bigint, pFilesz: bigint, pMemsz: bigint, pFlags: number;
      if (is64) {
        pFlags = readU32(phOff + 4);
        pOffset = readU64(phOff + 8);
        pVaddr = readU64(phOff + 16);
        // p_paddr at +24
        pFilesz = readU64(phOff + 32);
        pMemsz = readU64(phOff + 40);
      } else {
        pOffset = BigInt(readU32(phOff + 4));
        pVaddr = BigInt(readU32(phOff + 8));
        // p_paddr at +12
        pFilesz = BigInt(readU32(phOff + 16));
        pMemsz = BigInt(readU32(phOff + 20));
        pFlags = readU32(phOff + 24);
      }

      if (pFilesz > 0n) {
        const foff = Number(pOffset);
        const fsize = Number(pFilesz);
        const data = new Uint8Array(buf.buffer, buf.byteOffset + foff, fsize);
        sections.push({
          name: `LOAD_${i}`,
          vaddr: pVaddr,
          data,
          readonly: true,
        });
      }
    }
  }

  // Parse section headers → find symbol tables
  if (shnum > 0 && shoff > 0n) {
    // Read section header string table first
    const shstrOff = Number(shoff) + shstrndx * shentsize;
    let shstrTableOffset: number;
    if (is64) {
      shstrTableOffset = Number(readU64(shstrOff + 24));
    } else {
      shstrTableOffset = readU32(shstrOff + 16);
    }

    for (let i = 0; i < shnum; i++) {
      const shOff = Number(shoff) + i * shentsize;
      const shType = readU32(shOff + 4);

      if (shType === SHT_SYMTAB || shType === SHT_DYNSYM) {
        let shOffsetVal: number, shSize: number, shLink: number, shEntsize: number;
        if (is64) {
          shLink = readU32(shOff + 24);
          shOffsetVal = Number(readU64(shOff + 24));
          // Wait, fields for 64-bit:
          // sh_name(4) sh_type(4) sh_flags(8) sh_addr(8) sh_offset(8) sh_size(8)
          // sh_link(4) sh_info(4) sh_addralign(8) sh_entsize(8)
          shOffsetVal = Number(readU64(shOff + 24));
          shSize = Number(readU64(shOff + 32));
          shLink = readU32(shOff + 40);
          shEntsize = Number(readU64(shOff + 56));
        } else {
          // 32-bit: sh_name(4) sh_type(4) sh_flags(4) sh_addr(4) sh_offset(4) sh_size(4)
          // sh_link(4) sh_info(4) sh_addralign(4) sh_entsize(4)
          shOffsetVal = readU32(shOff + 16);
          shSize = readU32(shOff + 20);
          shLink = readU32(shOff + 24);
          shEntsize = readU32(shOff + 36);
        }

        // Get associated string table
        const strSecOff = Number(shoff) + shLink * shentsize;
        let strTabOffset: number;
        if (is64) {
          strTabOffset = Number(readU64(strSecOff + 24));
        } else {
          strTabOffset = readU32(strSecOff + 16);
        }

        // Parse symbol entries
        const numSyms = shEntsize > 0 ? Math.floor(shSize / shEntsize) : 0;
        for (let s = 0; s < numSyms; s++) {
          const symOff = shOffsetVal + s * shEntsize;
          let stName: number, stInfo: number, stValue: bigint;

          if (is64) {
            // Elf64_Sym: st_name(4) st_info(1) st_other(1) st_shndx(2) st_value(8) st_size(8)
            stName = readU32(symOff);
            stInfo = buf.readUInt8(symOff + 4);
            // st_shndx at +6
            stValue = readU64(symOff + 8);
          } else {
            // Elf32_Sym: st_name(4) st_value(4) st_size(4) st_info(1) st_other(1) st_shndx(2)
            stName = readU32(symOff);
            stValue = BigInt(readU32(symOff + 4));
            stInfo = buf.readUInt8(symOff + 12);
          }

          const stType = stInfo & 0x0f;
          if (stType === STT_FUNC && stValue !== 0n) {
            let nameEnd = strTabOffset + stName;
            while (nameEnd < buf.length && buf[nameEnd] !== 0) nameEnd++;
            const name = buf.toString('ascii', strTabOffset + stName, nameEnd);
            if (name.length > 0) {
              symbols.push({ name, vaddr: stValue });
            }
          }
        }
      }
    }
  }

  // Sort symbols by address
  symbols.sort((a, b) => (a.vaddr < b.vaddr ? -1 : a.vaddr > b.vaddr ? 1 : 0));

  return { arch, sections, symbols, entry };
}

// ── Unified parser ─────────────────────────────────────────────────────────

function parseBinary(buf: Buffer): ParsedBinary {
  if (buf.length < 4) throw new Error('File too small to be a valid binary');

  const magic32BE = buf.readUInt32BE(0);
  const magic32LE = buf.readUInt32LE(0);

  // Fat binary (always big-endian magic)
  if (magic32BE === FAT_MAGIC || magic32BE === FAT_CIGAM) {
    return parseFatBinary(buf);
  }

  // Mach-O 64-bit
  if (magic32LE === MH_MAGIC_64 || magic32BE === MH_MAGIC_64) {
    return parseMachO(buf);
  }

  // ELF
  if (magic32BE === ELF_MAGIC) {
    return parseELF(buf);
  }

  throw new Error(
    `Unsupported binary format (magic: 0x${magic32BE.toString(16)} / 0x${magic32LE.toString(16)})`
  );
}

// ── XML generation ─────────────────────────────────────────────────────────

function toHexLines(data: Uint8Array): string[] {
  const lines: string[] = [];
  const hexChars = '0123456789abcdef';
  // Build hex string in chunks to avoid excessive string concatenation
  let hex = '';
  for (let i = 0; i < data.length; i++) {
    const b = data[i];
    hex += hexChars[b >> 4];
    hex += hexChars[b & 0x0f];
    // 64 hex chars = 32 bytes per line
    if (hex.length === 64) {
      lines.push(hex);
      hex = '';
    }
  }
  if (hex.length > 0) {
    lines.push(hex);
  }
  return lines;
}

export function generateXml(
  parsed: ParsedBinary,
  options: {
    functions?: string[];
    binaryimageOnly?: boolean;
  } = {}
): string {
  const xml: string[] = [];

  if (!options.binaryimageOnly) {
    xml.push('<decompilertest>');
  }

  xml.push(`<binaryimage arch="${parsed.arch}">`);

  // Emit bytechunks — chunk at CHUNK_SIZE boundaries, matching ghidra_export.py
  for (const section of parsed.sections) {
    // Skip very large sections (>1MB), same as ghidra_export.py
    if (section.data.length > 0x100000) continue;

    let offset = 0;
    while (offset < section.data.length) {
      const chunkSize = Math.min(CHUNK_SIZE, section.data.length - offset);
      const addr = section.vaddr + BigInt(offset);
      const chunk = section.data.subarray(offset, offset + chunkSize);

      xml.push(`<bytechunk space="ram" offset="0x${addr.toString(16)}" readonly="true">`);
      const hexLines = toHexLines(chunk);
      for (const line of hexLines) {
        xml.push(line);
      }
      xml.push('</bytechunk>');

      offset += chunkSize;
    }
  }

  // Emit symbols — all function symbols (matching ghidra_export.py which emits all non-external)
  for (const sym of parsed.symbols) {
    xml.push(`<symbol space="ram" offset="0x${sym.vaddr.toString(16)}" name="${escapeXml(sym.name)}"/>`);
  }

  xml.push('</binaryimage>');

  // Script blocks (unless binaryimage-only)
  if (!options.binaryimageOnly) {
    // Determine which functions to emit scripts for (exclude stubs — they aren't decompilable)
    let scriptSymbols: BinarySymbol[];
    if (options.functions && options.functions.length > 0) {
      const wanted = new Set(options.functions);
      scriptSymbols = parsed.symbols.filter((s) => wanted.has(s.name) && !s.isStub);
    } else {
      scriptSymbols = parsed.symbols.filter((s) => !s.isStub);
    }

    for (const sym of scriptSymbols) {
      xml.push('<script>');
      xml.push(`  <com>lo fu ${escapeXml(sym.name)}</com>`);
      xml.push('  <com>decompile</com>');
      xml.push('  <com>print C</com>');
      xml.push('  <com>quit</com>');
      xml.push('</script>');
      xml.push(
        `<stringmatch name="${escapeXml(sym.name)} output" min="1" max="100">${escapeXml(sym.name)}</stringmatch>`
      );
    }

    xml.push('</decompilertest>');
  }

  return xml.join('\n');
}

function escapeXml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── Public API ─────────────────────────────────────────────────────────────

export { parseBinary, parseMachO, parseELF, parseFatBinary };
export type { ParsedBinary, BinarySection, BinarySymbol };

// ── CLI ────────────────────────────────────────────────────────────────────

function printUsage(): void {
  console.error(`Usage: npx tsx src/console/binary_to_xml.ts [options] <binary>
  -o, --output <file>     Write to file (default: stdout)
  -f, --functions <list>  Comma-separated function names to emit scripts for
  --binaryimage-only      Only emit <binaryimage>, no <script> blocks`);
}

function main(): void {
  const args = process.argv.slice(2);
  let outputFile: string | null = null;
  let functions: string[] | undefined;
  let binaryimageOnly = false;
  let binaryPath: string | null = null;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '-o' || arg === '--output') {
      outputFile = args[++i];
    } else if (arg === '-f' || arg === '--functions') {
      functions = args[++i].split(',').map((s) => s.trim());
    } else if (arg === '--binaryimage-only') {
      binaryimageOnly = true;
    } else if (arg === '-h' || arg === '--help') {
      printUsage();
      process.exit(0);
    } else if (!arg.startsWith('-')) {
      binaryPath = arg;
    } else {
      console.error(`Unknown option: ${arg}`);
      printUsage();
      process.exit(1);
    }
  }

  if (!binaryPath) {
    printUsage();
    process.exit(1);
  }

  const buf = readFileSync(binaryPath);
  const parsed = parseBinary(buf as Buffer);
  const xml = generateXml(parsed, { functions, binaryimageOnly });

  if (outputFile) {
    writeFileSync(outputFile, xml);
    const symCount = parsed.symbols.length;
    console.error(`Wrote XML (${symCount} symbols, arch=${parsed.arch}) to ${outputFile}`);
  } else {
    process.stdout.write(xml);
    process.stdout.write('\n');
  }
}

// Run CLI if executed directly
const isMainModule =
  typeof require !== 'undefined'
    ? require.main === module
    : process.argv[1]?.endsWith('binary_to_xml.ts') ||
      process.argv[1]?.endsWith('binary_to_xml.js');

if (isMainModule) {
  main();
}
