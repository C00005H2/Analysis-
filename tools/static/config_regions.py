import re, struct
k = open('/tmp/test2_winlice_unpacked.bin','rb').read()
BASE = 0x1CA7000
def dump_region(lo, hi, label):
    print(f"\n=== {label}: unpacked {lo:#x}..{hi:#x} (VA {BASE+lo:#x}..{BASE+hi:#x}) ===")
    # strings with tight offsets
    strs = [(m.start()+lo, m.group().decode()) for m in re.finditer(rb'[\x20-\x7e]{4,}', k[lo:hi])]
    print("  strings:", [(hex(o), s[:60]) for o,s in strs])
dump_region(0x1396000, 0x1399000, "LICENSING AREA 1 (TMLicenseA1.dat etc.)")
dump_region(0x13b6000, 0x13bc000, "LICENSING AREA 2 (Software\\Company\\Product + CRC table)")
# CRC table verification
tab=[]
for i in range(256):
    c=i
    for _ in range(8): c = (c>>1)^0xEDB88320 if c&1 else c>>1
    tab.append(c)
std = b''.join(struct.pack('<I',x) for x in tab)
t = 0x13b6cbc
print(f"\nCRC32 table @ unpacked+{t:#x} (VA {BASE+t:#x}): full standard table match = {k[t:t+1024]==std}")
# what follows the table?
after = k[t+1024:t+1024+64]
print("after table (+0x13b70bc):", after[:48].hex(), '...')
print("as dwords:", [hex(x) for x in struct.unpack('<12I', after[:48])])
# also check whether OTHER crc tables exist (search table[128] marker 0x2D02EF8D followed/preceded)
pat = struct.pack('<I', 0x2D02EF8D)
hits = [m.start() for m in re.finditer(re.escape(pat), k)]
print(f"\ncount of 0x2D02EF8D (std table last entry): {len(hits)} at {[hex(h) for h in hits]}")
for h in hits:
    if k[h-1020-4:h+4-1020+1024-1024] : pass
    # check if full table precedes
    if h >= 1020 and k[h-1020:h+4] == std[4:1024]: print(f"  -> full standard CRC32 table ends at {h+4:#x} (starts {h-1020:#x})")
