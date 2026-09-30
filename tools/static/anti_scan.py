import re, collections
k = open('/tmp/test2_winlice_unpacked.bin','rb').read()
BASE = 0x1CA7000
pats = {
 'rdtsc (0F 31)': b'\x0f\x31',
 'cpuid (0F A2)': b'\x0f\xa2',
 'int 2d (CD 2D)': b'\xcd\x2d',
 'int 3 (CC)': b'\xcc',
 'icebp/01 (F1)': b'\xf1',
 'sidt (0F 01 /1 forms)': b'\x0f\x01',
 'sgdt (0F 01 /0)': None,
 'str (0F 00 /1)': b'\x0f\x00',
 'sldt (0F 00 /0)': b'\x0f\x00',
 'hlt (F4)': b'\xf4',
 'in al,dx (ED)': b'\xed',
 'rdpmc (0F 33)': b'\x0f\x33',
 'VMCall-ish (0F 01 C1)': b'\x0f\x01\xc1',
 'xor ebp,ebp-ish patterns': None,
}
print("NOTE: raw byte counts include random/junk bytes in 29.7MB image; use as relative signal only")
for name, pat in pats.items():
    if pat is None: continue
    n = len(re.findall(re.escape(pat), k))
    print(f"  {name:28} raw count: {n}")
# better: count specific meaningful sequences
specific = {
 'push ss; pop ss (anti single-step)': b'\x16\x17',
 'far jmp seg (EA)': b'\xea',
 'GetTickCount ordinal?': b'\x00',
}
# search for known anti-debug API name strings in kernel (ascii + utf16)
names = ['IsDebuggerPresent','NtQueryInformationProcess','CheckRemoteDebuggerPresent','NtSetInformationThread',
 'DbgUiRemoteBreakin','DbgBreakPoint','OutputDebugStringA','NtCreateDebugObject','DbgPrint',
 'GetTickCount','QueryPerformanceCounter','NtQuerySystemInformation','NtQueryObject','NtYieldExecution',
 'NtClose','NtQueryPerformanceCounter','GetSystemFirmwareTable','ElfDumpLogEvent','SfcIsKeyProtected']
print("\nAPI-name strings inside kernel:")
for nm in names:
    for enc, lbl in [(nm.encode(),'ascii'), (nm.encode('utf-16le'),'utf16')]:
        if re.search(re.escape(enc), k):
            print(f"  {nm} ({lbl}): FOUND")
# done
