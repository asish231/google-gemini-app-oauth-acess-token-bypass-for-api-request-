#!/usr/bin/env python3
"""Finding 1 — extract the Gemini app's OAuth client_secret from its binary.

The app's Swift OAuth-config builder (createOAuthClientsAsDataAndReturnError in
JanusLibWrapperImpl.mm) computes the secret at runtime from a 35-byte blob in
__DATA_CONST that is XOR'd with 0x5A. Found via:

  1. xref_scan.py  — ARM64 ADRP+ADD scan located the builder at ~0x100879610
  2. disas_oauth.py — the builder calls a provider at 0x1008794bc which does:
        adrp x23, 0x10aa4b000 / add x23, x23, #0x360   ; blob base
        mov  w24, #0x5a                                ; XOR key
        ldrb w26, [x8, #0x20] ; eor w8, w26, w24        ; decode loop, 0x23 bytes

This script re-derives the secret at runtime from a stock binary — nothing is
hardcoded except the *location* of the obfuscation (which is the finding itself).

Usage:
    python3 extract_client_secret.py [--binary /Applications/Gemini.app/Contents/MacOS/Gemini]

Prints the client_id and decoded client_secret (or writes credentials JSON).
"""
import argparse
import json
import struct
import sys

# Offsets reverse-engineered from Gemini.app 1.128.14.1166 (macOS ARM64).
# The Mach-O headers are parsed at runtime below, so these are VIRTUAL addresses
# that stay correct across file offsets.
SECRET_BLOB_VA = 0x10AA4B360      # base of the obfuscated blob (data at +0x20)
SECRET_DATA_OFFSET = 0x20         # blob payload starts 0x20 into the base
SECRET_LENGTH = 0x23              # 35 bytes -> modern GOCSPX-… secret
XOR_KEY = 0x5A                    # single-byte XOR key (the "obfuscation")


def find_data_const_mapping(binary_bytes):
    """Parse Mach-O 64-bit load commands; map __DATA_CONST vmaddr -> fileoff."""
    magic = struct.unpack_from('<I', binary_bytes, 0)[0]
    if magic != 0xFEEDFACF:  # MH_MAGIC_64 | little-endian
        raise SystemExit('Not a little-endian Mach-O 64-bit binary')
    ncmds = struct.unpack_from('<I', binary_bytes, 16)[0]
    off = 32  # skip mach_header_64
    segments = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', binary_bytes, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            segname = binary_bytes[off + 8: off + 24].rstrip(b'\0').decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                '<QQQQ', binary_bytes, off + 24)
            segments.append((segname, vmaddr, vmsize, fileoff, filesize))
        off += cmdsize
    return segments


def va_to_offset(segments, va):
    for segname, vmaddr, vmsize, fileoff, filesize in segments:
        if vmaddr <= va < vmaddr + vmsize:
            return fileoff + (va - vmaddr), segname
    raise SystemExit(f'VA {va:#x} not mapped in any segment')


def extract(binary_path):
    with open(binary_path, 'rb') as f:
        data = f.read()

    segments = find_data_const_mapping(data)
    off, segname = va_to_offset(segments, SECRET_BLOB_VA + SECRET_DATA_OFFSET)
    if segname != '__DATA_CONST':
        print(f'warning: blob found in {segname}, expected __DATA_CONST', file=sys.stderr)

    raw = data[off: off + SECRET_LENGTH]
    secret = bytes(b ^ XOR_KEY for b in raw)

    # Sanity: Google client secrets are printable ASCII starting with GOCSPX-
    if not secret.startswith(b'GOCSPX-') or not all(32 <= b < 127 for b in secret):
        raise SystemExit(f'Decoded blob does not look like a client secret: {secret!r}')

    return {
        'client_id': '839509190550-l232s7lupkp6f57818eshd7u4sl4920h.apps.googleusercontent.com',
        'client_secret': secret.decode('ascii'),
        'source': {
            'binary': binary_path,
            'segment': segname,
            'blob_va': hex(SECRET_BLOB_VA),
            'file_offset': off,
            'xor_key': hex(XOR_KEY),
            'length': SECRET_LENGTH,
        },
    }


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--binary', default='/Applications/Gemini.app/Contents/MacOS/Gemini')
    ap.add_argument('--json', action='store_true', help='emit JSON instead of text')
    args = ap.parse_args()

    result = extract(args.binary)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print('=== Finding 1: OAuth client_secret recovered from binary ===')
        print(f"client_id     : {result['client_id']}")
        print(f"client_secret : {result['client_secret']}")
        print(f"location      : {result['source']['segment']} @ "
              f"VA {result['source']['blob_va']} (file offset {result['source']['file_offset']}), "
              f"{result['source']['length']} bytes XOR {result['source']['xor_key']}")
