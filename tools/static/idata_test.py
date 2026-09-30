import struct, re
data = open('/home/user/Analysis-/Test2.exe','rb').read()
IDATA_RAW = 0x9C5A00; IDATA_RVA = 0x1899000; SZ = 0x600
idat = data[IDATA_RAW:IDATA_RAW+SZ]
# candidate offsets from .data tables
t1 = [0x2122,0x2106,0x2176,0x2188,0x2198,0x2162,0x21b0,0x21c0,0x21d0,0x214c,0x213a,0x21a4,0x212c,0x21ec]
t2 = [0x20f4,0x21de,0x2010,0x2124,0x21fa,0x2040,0x20ec,0x2220,0x2008,0x20e4]
print("=== testing hypothesis: .data dwords = offsets into .idata ===")
for v in t1[:6] + t2[:3]:
    if v < SZ:
        chunk = idat[v:v+40]
        asc = ''.join(chr(x) if 32<=x<127 else '.' for x in chunk)
        print(f"  .idata+{v:#x} (RVA {IDATA_RVA+v:#x}): {chunk[:24].hex(' ')}  |{asc[:24]}|")
    else:
        print(f"  .idata+{v:#x}: OUT OF RANGE (sz {SZ:#x})")
# full .idata dump of name-bearing area
print("\n=== .idata strings ===")
for m in re.finditer(rb'[\x20-\x7e]{4,}', idat):
    print(f"  .idata+{m.start():#05x}: {m.group().decode()[:60]}")
