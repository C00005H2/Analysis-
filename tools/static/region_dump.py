import re, struct
k = open('/tmp/test2_winlice_unpacked.bin','rb').read()
BASE = 0x1CA7000
# All printable strings >=4 in the licensing/config region unpacked 0x1390000..0x13C0000
lo, hi = 0x1390000, 0x13C0000
print(f"=== strings in unpacked {lo:#x}..{hi:#x} (VA {BASE+lo:#x}..{BASE+hi:#x}) ===")
cur = None
for m in re.finditer(rb'[\x20-\x7e]{4,}', k[lo:hi]):
    o = lo + m.start(); s = m.group().decode()
    if cur is None or o - cur > 0: print(f"  +{o:#06x} VA {BASE+o:#x}  {s[:120]}")
    cur = o + len(s)
