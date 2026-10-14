#!/usr/bin/env python3
"""Disassemble the OAuth config builder around the client_id reference."""
from capstone import *

BINARY = "/Applications/Gemini.app/Contents/MacOS/Gemini"
TEXT_VMADDR = 0x100000000

with open(BINARY, 'rb') as f:
    text = f.read(178192384)

# client_id ref pc = 0x10087966c (the ADRP), client_id VA = 0x109e17220
center_pc = 0x10087966c
start_pc = center_pc - 0x600   # 1.5KB before
length = 0xC00                 # 3KB total window

off = start_pc - TEXT_VMADDR
code = text[off:off+length]
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = False

print(f"=== disassembly {start_pc:#x} .. {start_pc+length:#x} ===")
for insn in md.disasm(code, start_pc):
    line = f"{insn.address:#x}: {insn.mnemonic} {insn.op_str}"
    # annotate known addresses
    notes = []
    for name, va in [("CLIENT_ID", 0x109e17220), ("REDACTED_PREFIX", 0x109e1720b),
                     ("REDACTED_CLOSE", 0x109e1721d)]:
        if hex(va)[2:] in insn.op_str:
            notes.append(name)
    if notes:
        line += f"   ; <<< {','.join(notes)}"
    print(line)
