import struct, pefile
data = open('/home/user/Analysis-/Test2.exe','rb').read()
# .vm_sec: RVA 0x1891000, file 0x9BDA00, size 0x8000
off = 0x9BDA00
blob = data[off:off+0x8000]
# find end of meaningful data (non-zero)
last_nz = 0
for i in range(0, len(blob), 4):
    if blob[i:i+4] != b'\x00\x00\x00\x00': last_nz = i+4
print(f".vm_sec meaningful bytes: {last_nz:#x} of {len(blob):#x}")
pairs = []
for i in range(0, last_nz, 8):
    a, b = struct.unpack_from('<II', blob, i)
    pairs.append((a,b))
print(f"pair count (8-byte stride): {len(pairs)}")
for p in pairs[:8]: print(f"  {p[0]:#010x} {p[1]:#010x}  (delta {p[1]-p[0]:#x})")
print("  ...")
for p in pairs[-4:]: print(f"  {p[0]:#010x} {p[1]:#010x}  (delta {p[1]-p[0]:#x})")
# stats: do all satisfy b == a+5?
all5 = all(b == a+5 for a,b in pairs)
print(f"all b==a+5: {all5}")
mn, mx = min(a for a,b in pairs), max(b for a,b in pairs)
print(f"range of values: {mn:#x} .. {mx:#x}  (.winlice VA range = 0x1CA7000..0x34F9000; RVA range 0x18A7000..0x34F9000)")
print(f"sorted unique: {len(set([a for a,b in pairs]+[b for a,b in pairs]))}")
# try 4-byte stride interpretation too
quads = struct.unpack_from('<%dI' % (last_nz//4), blob, 0)
mono = all(quads[i] <= quads[i+1] for i in range(len(quads)-1))
print(f"4-byte stride: {len(quads)} dwords, monotonically sorted: {mono}")
print("first 16 dwords:", [hex(x) for x in quads[:16]])
