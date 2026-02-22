# -*- coding: utf-8 -*-
# Ghidra headless script: export as datatests-compatible XML
#
# Usage: run via Ghidra's analyzeHeadless with -postScript
# Set DECOMP_OUTPUT_DIR env var to control output location.
#
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from java.lang.reflect import Array
from java.lang import Byte
import os

output_dir = os.environ.get("DECOMP_OUTPUT_DIR", "/tmp/decomp-test")
xml_output = os.path.join(output_dir, "exported.xml")

monitor = ConsoleTaskMonitor()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

mem = currentProgram.getMemory()
lang_id = currentProgram.getLanguage().getLanguageID().toString()
cspec_id = currentProgram.getCompilerSpec().getCompilerSpecID().toString()
arch = "%s:%s" % (lang_id, cspec_id)

fm = currentProgram.getFunctionManager()
functions = [f for f in fm.getFunctions(True) if not f.isThunk() and not f.isExternal()]

# Build XML
xml = ['<decompilertest>', '<binaryimage arch="%s">' % arch]

# Export ALL initialized memory blocks (not just function bodies)
for block in mem.getBlocks():
    if not block.isInitialized():
        continue
    start = block.getStart()
    space = start.getAddressSpace().getName()
    # Skip non-ram spaces (like HEADER, EXTERNAL, etc.)
    if space != "ram":
        continue
    size = int(block.getSize())
    if size > 0x100000:  # Skip blocks > 1MB
        print("Skipping large block %s at %s (%d bytes)" % (block.getName(), start, size))
        continue
    # Read in chunks to avoid memory issues
    CHUNK = 0x10000
    offset = 0
    while offset < size:
        chunk_size = min(CHUNK, size - offset)
        addr = start.add(offset)
        data = Array.newInstance(Byte.TYPE, chunk_size)
        mem.getBytes(addr, data)
        hex_str = ''.join(['%02x' % (b & 0xff) for b in data])
        xml.append('<bytechunk space="ram" offset="0x%x" readonly="true">' % addr.getOffset())
        for i in range(0, len(hex_str), 64):
            xml.append(hex_str[i:i+64])
        xml.append('</bytechunk>')
        offset += chunk_size

# Export symbols for all functions (including thunks for call resolution)
for func in fm.getFunctions(True):
    if func.isExternal():
        continue
    xml.append('<symbol space="ram" offset="0x%x" name="%s"/>' % (func.getEntryPoint().getOffset(), func.getName()))

xml.append('</binaryimage>')

# Script blocks for non-thunk functions only
for func in functions:
    name = func.getName()
    xml.append('<script>')
    xml.append('  <com>lo fu %s</com>' % name)
    xml.append('  <com>decompile</com>')
    xml.append('  <com>print C</com>')
    xml.append('  <com>quit</com>')
    xml.append('</script>')
    xml.append('<stringmatch name="%s output" min="1" max="100">%s</stringmatch>' % (name, name))

xml.append('</decompilertest>')
with open(xml_output, "w") as f:
    f.write('\n'.join(xml))
print("Wrote XML (%d lines, %d functions) to %s" % (len(xml), len(functions), xml_output))
