import struct, collections
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
k = open('/tmp/test2_winlice_unpacked.bin','rb').read()
BASE = 0x1CA7000; WINLICE_RVA = 0x18A7000
data = open('/home/user/Analysis-/Test2.exe','rb').read()
blob = data[0x9BDA00:0x9BDA00+0x8000]

# characterise ALL 8-byte entries
entries = []
for i in range(0, 0x61d0, 8):
    a,b = struct.unpack_from('<II', blob, i)
    entries.append((a,b))
delta_hist = collections.Counter(b-a if a and b else None for a,b in entries)
print("delta histogram (top):", delta_hist.most_common(8))
nz = [(a,b) for a,b in entries if a and b]
print(f"nonzero entries: {len(nz)}; of these b==a+5: {sum(1 for a,b in nz if b==a+5)}")
inrange = [(a,b) for a,b in nz if 0x18A7000 <= a < 0x34F9000]
print(f"a within .winlice: {len(inrange)}")

# validate: is each a a 5-byte E9 jmp rel32 in the unpacked image?
pairs = [(a,b) for a,b in nz if b==a+5 and 0x18A7000 <= a < 0x34F9000]
ok=0; targets=[]; bad=[]
for a,b in pairs:
    off = a - WINLICE_RVA
    if k[off] == 0xE9:
        rel = struct.unpack_from('<i', k, off+1)[0]
        tgt = BASE + off + 5 + rel
        targets.append((BASE+off, tgt)); ok+=1
    else: bad.append(a)
print(f"\npairs whose slot X starts with 0xE9 (jmp rel32): {ok}/{len(pairs)}; non-jmp: {len(bad)}")
if bad[:5]: print("  non-jmp sample X:", [hex(x) for x in bad[:5]])

# Build graph: slot -> target. Is the target itself another 5-byte jmp slot?
slotset = set(s for s,_ in targets)
tgt_in_slots = sum(1 for _,t in targets if t in slotset)
print(f"edges: {len(targets)}; targets that are themselves registered slots: {tgt_in_slots}")
tgt_hist = collections.Counter()
for s,t in targets: tgt_hist[(t-BASE)>>20] += 1
print("jmp TARGET histogram (unpacked MB bucket):", dict(sorted(tgt_hist.items())))
# chain detection: follow edges from slots whose target is another slot
chains = 0; longest = 0
for s,t in targets:
    if t in slotset:
        chains += 1
        n=1; cur=t
        seen=set()
        while cur in slotset and cur not in seen:
            seen.add(cur); n+=1
            # find its edge
            nxt = dict(targets).get(cur)
            if nxt is None: break
            cur = nxt
        longest = max(longest, n)
print(f"slots whose target is a slot (chain starts): {chains}; longest chain: {longest}")
# show a couple of concrete chains
shown=0
for s,t in targets:
    if t in slotset:
        chain=[s]; cur=t
        seen=set()
        while cur in slotset and cur not in seen and len(chain)<8:
            seen.add(cur); chain.append(cur)
            nxt = dict(targets).get(cur)
            if nxt is None: break
            cur = nxt
        print(f"  chain: {' -> '.join(hex(x) for x in chain)}")
        shown+=1
        if shown>=4: break
# what are the terminal targets of non-chaining edges? bucket by region
import collections
term = collections.Counter()
d = dict(targets)
for s,t in targets:
    if t not in slotset: term[(t-BASE)>>20]+=1
print("terminal (non-slot) target buckets:", dict(sorted(term.items())))
