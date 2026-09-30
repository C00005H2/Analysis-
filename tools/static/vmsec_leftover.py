import struct, collections
data = open('/home/user/Analysis-/Test2.exe','rb').read()
k = open('/tmp/test2_winlice_unpacked.bin','rb').read()
blob = data[0x9BDA00:0x9BDA00+0x8000]
entries = []
for i in range(0, 0x61d0, 8):
    a,b = struct.unpack_from('<II', blob, i)
    entries.append((a,b))
left = [(i,a,b) for i,(a,b) in enumerate(entries) if a and b and b!=a+5]
print(f"leftover records: {len(left)}; entry-index ranges: {left[0][0]}..{left[-1][0]}")
print("first 20 (idx, a, b):")
for i,a,b in left[:20]: print(f"  [{i:4}] {a:#010x} {b:#010x}  d={b-a:+#x}")
print("last 10:")
for i,a,b in left[-10:]: print(f"  [{i:4}] {a:#010x} {b:#010x}  d={b-a:+#x}")
# structure probes
avals = [a for _,a,_ in left]; bvals = [b for _,_,b in left]
print(f"\na: min={min(avals):#x} max={max(avals):#x}; b: min={min(bvals):#x} max={max(bvals):#x}")
# test: a XOR const -> in .winlice RVA range?
import re
WINLO, WINHI = 0x18A7000, 0x34F9000
def test_xor(shift):
    ok = sum(1 for v in avals if WINLO <= (v ^ shift) < WINHI)
    return ok
best = None
# derive candidate shift from any value: if a^shift = some RVA, shift = a^rva — too many; instead check high bytes
hi_hist = collections.Counter(v>>24 for v in avals)
print("a high-byte histogram:", dict(sorted(hi_hist.items())))
hi_histb = collections.Counter(v>>24 for v in bvals)
print("b high-byte histogram:", dict(sorted(hi_histb.items())))
# maybe they are file offsets? Test2 file size 0x1F586C8
in_file = sum(1 for v in avals if v < 0x1F586C8)
print(f"a values within Test2.exe file size range: {in_file}/{len(avals)}")
# byte-swapped?
bs = sum(1 for v in avals if WINLO <= struct.unpack('<I', struct.pack('>I', v))[0] < WINHI)
print(f"a byte-swapped into .winlice range: {bs}")
# are they VAs without imagebase? .winlice VA range 0x1CA7000..0x34F9000
in_va = sum(1 for v in avals if WINLO+0x400000 <= v < WINHI+0x400000)
print(f"a values in VA range (RVA+0x400000): {in_va}")
# deltas b-a histogram
dh = collections.Counter(b-a for _,a,b in left)
print("delta b-a top:", dh.most_common(6))
# maybe records are 4-byte: check if leftover region is actually a different alignment
print("\nraw dwords around leftover start (entry 437, file offset):")
off = 0x9BDA00 + 437*8
row = data[off:off+64]
print('  ' + ' '.join(f'{x:08x}' for x in struct.unpack('<16I', row)))
