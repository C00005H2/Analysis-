import struct, re
k = open('/tmp/test2_winlice_unpacked.bin','rb').read()
BASE = 0x1CA7000
def xrefs(va, label):
    pat = struct.pack('<I', va)
    hits = [m.start() for m in re.finditer(re.escape(pat), k)]
    print(f"{label} (VA {va:#x}): {len(hits)} dword xrefs in kernel at unpacked+{[hex(h) for h in hits[:8]]} (VA {[hex(BASE+h) for h in hits[:8]]})")
    return hits
xrefs(0x303DA3C, 'Software\\MyCompany\\MyProduct')
xrefs(0x305EAB8, 'Software\\Company\\Product')
xrefs(0x303E250, 'WinLicenseDriverVersion')
xrefs(0x303F5AC, '/checkprotection string')   # VA of 0x13985ac
xrefs(0x305D1C4, 'SOFTWARE\\WinLicense (2nd)')
xrefs(0x1CF3D40, 'Themida64_GUI (1st)')
xrefs(0x303D5EC, 'extendkey.dat')
xrefs(0x303E010, 'TMLicenseA1.dat')
xrefs(0x305DEBC, 'CRC table[128] loc')
xrefs(0x305DCBC, 'CRC table start')
xrefs(0x1CBD618, 'PROC_IN format string')
# also .data strings in the packed file referenced from kernel? .data VAs are 0x4E7Cxxx
for va,lbl in [(0x4E7C288,'skeleton.dll string'),(0x4E7C048,'dummy string'),(0x4E7C06C,'kernel32.dll string')]:
    pat = struct.pack('<I', va)
    hits = [m.start() for m in re.finditer(re.escape(pat), k)]
    print(f"{lbl} (VA {va:#x}): {len(hits)} xrefs in kernel")
