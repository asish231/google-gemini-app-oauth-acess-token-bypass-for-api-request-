import lldb

# Get the process
target = lldb.debugger.GetSelectedTarget()
process = target.GetProcess()
print(f"Attached to PID {process.GetID()}")

# Patterns to hunt
patterns = [b'GOCSPX', b'client_secret=', b'839509190550-l232s']
names = ['GOCSPX', 'client_secret=', 'client_id']
results = {n: [] for n in names}

# Enumerate memory regions
regions = process.GetMemoryRegions()
print(f"Memory regions: {regions.GetSize()}")

for i in range(regions.GetSize()):
    region = lldb.SBMemoryRegionInfo()
    regions.GetMemoryRegionAtIndex(i, region)
    # Only scan writable regions (heap where config objects live)
    if not region.IsWritable():
        continue
    start = region.GetRegionBase()
    size = region.GetRegionEnd() - start
    if size > 512 * 1024 * 1024:  # skip giant regions
        continue
    err = lldb.SBError()
    data = process.ReadMemory(start, size, err)
    if not data:
        continue
    for pat, name in zip(patterns, names):
        offset = 0
        while True:
            idx = data.find(pat, offset)
            if idx == -1:
                break
            results[name].append((start + idx, data[max(0,idx-16):idx+200]))
            offset = idx + 1
            if len(results[name]) > 40:
                break

# Report
for name in names:
    hits = results[name]
    print(f"\n=== {name}: {len(hits)} hits ===")
    for addr, ctx in hits[:15]:
        print(f"  @ {addr:#x}: {ctx[:180]}")
