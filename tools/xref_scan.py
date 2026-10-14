#!/usr/bin/env python3
"""ARM64 cross-reference scanner for the Gemini binary.
Finds ADRP+ADD pairs that reference the OAuth client_id string,
then dumps ALL string references in the surrounding code (the OAuth config
builder) — one of those strings is the client_secret.
"""
import numpy as np

BINARY = "/Applications/Gemini.app/Contents/MacOS/Gemini"
TEXT_VMADDR = 0x100000000   # from otool: __TEXT vmaddr, fileoff 0
TEXT_FILESIZE = 178192384

with open(BINARY, 'rb') as f:
    f.seek(0)
    text = f.read(TEXT_FILESIZE)

# --- locate the client_id string ---
client_id = b"839509190550-l232s7lupkp6f57818eshd7u4sl4920h.apps.googleusercontent.com"
cid_off = text.find(client_id)
assert cid_off != -1
cid_va = TEXT_VMADDR + cid_off
cid_page = cid_va & ~0xFFF
cid_pageoff = cid_va & 0xFFF
print(f"client_id file_off={cid_off:#x} VA={cid_va:#x} page={cid_page:#x} off={cid_pageoff:#x}")

# --- decode all instructions as uint32 ---
n = len(text) - (len(text) % 4)
words = np.frombuffer(text[:n], dtype='<u4').copy()
pc_base = TEXT_VMADDR
pcs = pc_base + (np.arange(len(words), dtype=np.uint64) * 4)

# --- ADRP: w & 0x9F000000 == 0x90000000 ---
is_adrp = (words & np.uint32(0x9F000000)) == np.uint32(0x90000000)
adrp_idx = np.nonzero(is_adrp)[0]
print(f"total ADRP instructions: {len(adrp_idx)}")

w = words[adrp_idx]
pc = pcs[adrp_idx]
immlo = ((w >> 29) & 3).astype(np.int64)
immhi = ((w >> 5) & 0x7FFFF).astype(np.int64)
imm = ((immhi << 2) | immlo) << 12
# sign-extend: imm is 33-bit signed (bit 32 of the raw imm)
neg = (immhi & 0x40000) != 0  # top bit of 19-bit immhi+2bit immlo forms 21-bit value; sign bit is bit 20
imm = np.where(neg, imm - (1 << 33), imm)
target_page = (pc.astype(np.int64) & ~0xFFF) + imm

# --- ADRPs pointing at the client_id's page ---
hits = np.nonzero(target_page == cid_page)[0]
print(f"ADRP hits on client_id page: {len(hits)}")

def try_read_str(va):
    """Read a C string at virtual address va."""
    off = va - TEXT_VMADDR
    if off < 0 or off >= len(text):
        return None
    end = text.find(b'\0', off, off + 512)
    if end == -1:
        return None
    s = text[off:end]
    try:
        t = s.decode('utf-8')
        if all(32 <= ord(c) < 127 for c in t):
            return t
    except Exception:
        pass
    return None

def decode_add_imm(word):
    """ADD (immediate) 64-bit: sf=1 op=0 S=0 100010 sh imm12 Rn Rd
       encoding: 1 00 100010 0 imm12 Rn Rd → 0x91000000 | ..."""
    if (word & 0x9F000000) != 0x91000000:
        return None
    imm12 = (word >> 10) & 0xFFF
    sh = (word >> 22) & 1
    if sh:
        imm12 <<= 12
    return imm12

candidates = []  # (pc, str_va, string)
for h in hits:
    i = adrp_idx[h]           # instruction index of the ADRP
    adrp_pc = pcs[i]
    rd = w[h] & 0x1F
    # scan next 12 instructions for ADD rd, rd, #imm
    str_va = None
    for j in range(1, 13):
        if i + j >= len(words):
            break
        nw = words[i + j]
        if (nw & 0x9F000000) == 0x91000000:
            add_rn = (nw >> 5) & 0x1F
            add_rd = nw & 0x1F
            if add_rn == rd:
                imm12 = decode_add_imm(nw)
                if imm12 is not None:
                    va = target_page[h] + imm12
                    if va == cid_va:
                        str_va = va
                        candidates.append(('CLIENT_ID_REF', adrp_pc, va, client_id.decode()))
                        break
                    else:
                        s = try_read_str(va)
                        if s:
                            candidates.append(('NEARBY', adrp_pc, va, s))
                        break

print(f"\n=== references found: {len(candidates)} ===")
for kind, pc, va, s in candidates:
    print(f"[{kind}] pc={pc:#x} → {va:#x}: {s[:80]!r}")

# --- For each CLIENT_ID_REF, dump ALL ADRP+ADD string refs within ±4KB of code ---
print("\n=== surrounding function string references ===")
seen = set()
for kind, pc, va, s in candidates:
    if kind != 'CLIENT_ID_REF':
        continue
    lo = (pc - 4096) & ~3
    hi = pc + 4096
    lo_i = int((lo - TEXT_VMADDR) // 4)
    hi_i = int((hi - TEXT_VMADDR) // 4)
    lo_i = max(0, lo_i); hi_i = min(len(words), hi_i)
    for i in range(lo_i, hi_i):
        ww = words[i]
        if (ww & 0x9F000000) != 0x90000000:
            continue
        p = pcs[i]
        wv = ww
        il = ((wv >> 29) & 3)
        ih = ((wv >> 5) & 0x7FFFF)
        iv = (((ih << 2) | il) << 12)
        if ih & 0x40000:
            iv -= (1 << 33)
        tp = (int(p) & ~0xFFF) + iv
        rd = wv & 0x1F
        for j in range(1, 13):
            if i + j >= len(words):
                break
            nw = words[i + j]
            if (nw & 0x9F000000) == 0x91000000 and (((nw >> 5) & 0x1F) == rd):
                imm12 = decode_add_imm(nw)
                if imm12 is None:
                    continue
                sva = tp + imm12
                if sva in seen:
                    break
                s2 = try_read_str(sva)
                if s2 and len(s2) >= 6:
                    seen.add(sva)
                    print(f"  pc={p:#x} → {sva:#x}: {s2[:100]!r}")
                break
