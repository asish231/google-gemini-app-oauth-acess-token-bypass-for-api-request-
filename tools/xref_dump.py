#!/usr/bin/env python3
"""Dump ALL string references in the OAuth config builder function."""
import numpy as np

BINARY = "/Applications/Gemini.app/Contents/MacOS/Gemini"
TEXT_VMADDR = 0x100000000
TEXT_FILESIZE = 178192384

with open(BINARY, 'rb') as f:
    text = f.read(TEXT_FILESIZE)

client_id = b"839509190550-l232s7lupkp6f57818eshd7u4sl4920h.apps.googleusercontent.com"
cid_off = text.find(client_id)
cid_va = TEXT_VMADDR + cid_off
cid_page = cid_va & ~0xFFF

n = len(text) - (len(text) % 4)
words = np.frombuffer(text[:n], dtype='<u4').copy()
pcs = TEXT_VMADDR + (np.arange(len(words), dtype=np.uint64) * 4)

is_adrp = (words & np.uint32(0x9F000000)) == np.uint32(0x90000000)
adrp_idx = np.nonzero(is_adrp)[0]
w = words[adrp_idx]
pc = pcs[adrp_idx]
immlo = ((w >> 29) & 3).astype(np.int64)
immhi = ((w >> 5) & 0x7FFFF).astype(np.int64)
imm = ((immhi << 2) | immlo) << 12
neg = (immhi & 0x40000) != 0
imm = np.where(neg, imm - (1 << 33), imm)
target_page = (pc.astype(np.int64) & ~0xFFF) + imm

def try_read_str(va):
    off = va - TEXT_VMADDR
    if off < 0 or off >= len(text):
        return None
    end = text.find(b'\0', off, off + 600)
    if end == -1:
        return None
    s = text[off:end]
    if len(s) == 0:
        return None
    try:
        t = s.decode('utf-8')
        if all(32 <= ord(c) < 127 for c in t):
            return t
    except Exception:
        return None
    return None

# find exact refs to client_id
hits = np.nonzero(target_page == cid_page)[0]
cid_refs = []
for h in hits:
    i = int(adrp_idx[h])
    rd = int(w[h]) & 0x1F
    for j in range(1, 13):
        if i + j >= len(words):
            break
        nw = int(words[i + j])
        if (nw & 0x9F000000) == 0x91000000 and ((nw >> 5) & 0x1F) == rd:
            imm12 = (nw >> 10) & 0xFFF
            sh = (nw >> 22) & 1
            if sh:
                imm12 <<= 12
            va = int(target_page[h]) + imm12
            if va == cid_va:
                cid_refs.append((int(pcs[i]), va))
            break

print(f"exact client_id refs: {cid_refs}")

# For each client_id ref, dump ALL ADRP+ADD string refs in a wide window
for ref_pc, _ in cid_refs:
    print(f"\n=== window around pc={ref_pc:#x} (±16KB) ===")
    lo_i = max(0, int((ref_pc - 16384 - TEXT_VMADDR) // 4))
    hi_i = min(len(words), int((ref_pc + 16384 - TEXT_VMADDR) // 4))
    seen = {}
    for i in range(lo_i, hi_i):
        ww = int(words[i])
        if (ww & 0x9F000000) != 0x90000000:
            continue
        p = int(pcs[i])
        il = (ww >> 29) & 3
        ih = (ww >> 5) & 0x7FFFF
        iv = (((ih << 2) | il) << 12)
        if ih & 0x40000:
            iv -= (1 << 33)
        tp = (p & ~0xFFF) + iv
        rd = ww & 0x1F
        for j in range(1, 13):
            if i + j >= len(words):
                break
            nw = int(words[i + j])
            if (nw & 0x9F000000) == 0x91000000 and (((nw >> 5) & 0x1F) == rd):
                imm12 = (nw >> 10) & 0xFFF
                sh = (nw >> 22) & 1
                if sh:
                    imm12 <<= 12
                sva = tp + imm12
                if sva not in seen:
                    s2 = try_read_str(sva)
                    seen[sva] = s2
                break
    # print interesting ones (not generic logging noise)
    noise_markers = ('googlemac/', 'Caught NSException', 'Caught C++', 'Check failed',
                     'paths.count', '[LibWrapper]', 'Failed to create')
    for sva, s2 in sorted(seen.items()):
        if s2 is None:
            continue
        if any(nm in s2 for nm in noise_markers) and 'REDACTED' not in s2:
            continue
        marker = ' <-- CLIENT_ID' if sva == cid_va else ''
        print(f"  pc@{sva:#x}: {s2[:110]!r}{marker}")
