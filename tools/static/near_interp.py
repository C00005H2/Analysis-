import re
k = open('/tmp/test2_winlice_unpacked.bin','rb').read()
print("=== strings in unpacked+0x400..0x2000 (interpreter data neighborhood) ===")
for m in re.finditer(rb'[\x20-\x7e]{4,}', k[0x400:0x2000]):
    print(f"  +{0x400+m.start():#06x} VA {0x1CA7000+0x400+m.start():#x}  {m.group().decode()[:80]}")
print("\n=== '/cmdline-switch-like' strings kernel-wide ===")
for m in re.finditer(rb'/[A-Za-z][A-Za-z0-9_]{3,20}', k):
    print(f"  +{m.start():#08x} VA {0x1CA7000+m.start():#x}  {m.group().decode()}")
