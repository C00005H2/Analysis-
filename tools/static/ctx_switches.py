import re
k = open('/tmp/test2_winlice_unpacked.bin','rb').read()
BASE = 0x1CA7000
def dump(lo, hi, label):
    print(f"\n=== {label} (+{lo:#x}..+{hi:#x}) ===")
    for m in re.finditer(rb'[\x20-\x7e]{4,}', k[lo:hi]):
        print(f"  +{lo+m.start():#08x} VA {BASE+lo+m.start():#x}  {m.group().decode()[:90]}")
dump(0x3c80, 0x4180,   "/nosplash + WinLicenseVersion neighborhood")
dump(0x4f00, 0x5200,   "/dis1 neighborhood")
dump(0x34380, 0x34800, "/dumpstatus neighborhood")
dump(0x4bd00, 0x4c600, "/skipactivexreg neighborhood")
dump(0x52900, 0x53600, "/showcode2 neighborhood")
dump(0x4100, 0x4500,   "Software\\WinLicense (1st) neighborhood")
dump(0x56800, 0x57500, "WinLicenseInstance neighborhood")
