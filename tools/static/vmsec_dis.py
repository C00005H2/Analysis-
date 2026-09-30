import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
data = open('/home/user/Analysis-/Test2.exe','rb').read()
k = open('/tmp/test2_winlice_unpacked.bin','rb').read()
BASE = 0x1CA7000          # VA of unpacked offset 0
WINLICE_RVA = 0x18A7000   # RVA of .winlice
md = Cs(CS_ARCH_X86, CS_MODE_32)
blob = data[0x9BDA00:0x9BDA00+0x8000]
pairs = []
for i in range(0, 0x61d0, 8):
    a,b = struct.unpack_from('<II', blob, i)
    if a and a+5==b: pairs.append((a,b))
print(f"valid pairs: {len(pairs)}")
import collections
# where do they point (histogram over 1MB buckets of unpacked offsets)
hist = collections.Counter()
for a,b in pairs: hist[(a-WINLICE_RVA)>>20] += 1
print("targets by 1MB bucket (unpacked offset >> 20):", dict(sorted(hist.items())))
print("\n=== first 6 pair targets, disassembled from unpacked image ===")
for a,b in pairs[:6]:
    off = a - WINLICE_RVA
    print(f"\n-- pair ({a:#x},{b:#x}) -> unpacked+{off:#x} (VA {BASE+off:#x}) --")
    code = k[off-16:off+40]
    for i in md.disasm(code, BASE+off-16):
        mark = '  <== X' if i.address == BASE+off else ('  <== X+5' if i.address == BASE+off+5 else '')
        print(f"  {i.address:#x}: {i.mnemonic:8} {i.op_str}{mark}")
