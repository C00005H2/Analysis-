import re
k = open('/tmp/test2_winlice_unpacked.bin','rb').read()
print("=== all UTF-16LE strings (93 expected) ===")
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){5,}', k):
    print(f"  +{m.start():#08x} VA {0x1CA7000+m.start():#x}  {m.group().decode('utf-16le')[:100]}")
print("\n=== format-string-like / debug-log strings kernel-wide ===")
pat = re.compile(rb'[\x20-\x7e]*%[dxXsu%][\x20-\x7e]*')
seen=set()
for m in pat.finditer(k):
    s = m.group().decode()
    if len(s)>=6 and s not in seen:
        seen.add(s)
        print(f"  +{m.start():#08x} VA {0x1CA7000+m.start():#x}  {s[:110]}")
