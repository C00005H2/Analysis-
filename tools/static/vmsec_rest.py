import struct
k = open('/tmp/test2_winlice_unpacked.bin','rb').read()
BASE = 0x1CA7000; WINLICE_RVA = 0x18A7000
data = open('/home/user/Analysis-/Test2.exe','rb').read()
blob = data[0x9BDA00:0x9BDA00+0x8000]
entries = []
for i in range(0, 0x61d0, 8):
    a,b = struct.unpack_from('<II', blob, i)
    entries.append((a,b))
nonplus = [(a,b) for a,b in entries if a and b and b!=a+5]
print(f"non-(+5) nonzero entries: {len(nonplus)}")
# hypothesis: (a,b) where a=slot RVA, b=TARGET RVA of a's jmp?
match=0; a_in=0; checked=0
for a,b in nonplus[:400]:
    if 0x18A7000 <= a < 0x34F9000:
        a_in += 1
        off = a - WINLICE_RVA
        if k[off] == 0xE9:
            rel = struct.unpack_from('<i', k, off+1)[0]
            tgt = a + 5 + rel          # target as RVA
            checked += 1
            if tgt == b: match += 1
print(f"  a in .winlice: {a_in}/400; a is E9 slot: {checked}; b == jmp target: {match}")
# alternative: are the entries actually 4-byte records (not 8)? i.e. flat dword list?
# check distribution of all nonzero dwords: in-range vs out
flat = struct.unpack_from('<%dI' % (0x61d0//4), blob, 0)
nzf = [v for v in flat if v]
inr = sum(1 for v in nzf if 0x18A7000 <= v < 0x34F9000)
print(f"flat dwords: {len(flat)}, nonzero: {len(nzf)}, in .winlice RVA range: {inr}")
# maybe the tail (after the +5 pairs) is a second table with different alignment
# find where +5 pairs stop being contiguous
runs = []
cur = None
for i,(a,b) in enumerate(entries):
    ok = a and b==a+5
    if ok and cur is None: cur = i
    if not ok and cur is not None: runs.append((cur, i)); cur=None
if cur is not None: runs.append((cur, len(entries)))
print(f"+5-pair runs (entry index ranges): {runs[:10]}")
