import re
k = open('/tmp/test2_winlice_unpacked.bin','rb').read()
# ASCII strings >= 5
ascii_re = re.compile(rb'[\x20-\x7e]{5,}')
astr = [(m.start(), m.group().decode()) for m in ascii_re.finditer(k)]
# UTF-16LE strings >= 5 chars
u16_re = re.compile(rb'(?:[\x20-\x7e]\x00){5,}')
ustr = [(m.start(), m.group().decode('utf-16le')) for m in u16_re.finditer(k)]
print(f"ascii strings: {len(astr)}, utf16 strings: {len(ustr)}")
open('/tmp/kernel_ascii.txt','w').write('\n'.join(f"{o:#x}\t{s}" for o,s in astr))
open('/tmp/kernel_utf16.txt','w').write('\n'.join(f"{o:#x}\t{s}" for o,s in ustr))
INTERESTING = ['debug','Debug','DEBUG','ntdll','NtQuery','ZwQuery','IsDebugger','ProcessDebug','DebugPort',
 'dbg','olly','Olly','x64','windbg','WinDbg','SoftIce','softice','vmware','VMware','VBOX','VirtualBox',
 'qemu','QEMU','sandbox','Sandbox','Sandboxie','wine','Wine','procmon','Process','Monitor','wireshark',
 'ida','IDA','hexrays','cheat','engine','VirtualAlloc','VirtualProtect','LoadLibrary','GetProcAddress',
 'kernel32','user32','advapi','NTDLL','CreateThread','WriteProcessMemory','ReadProcessMemory','SetWindowsHookEx',
 'driver','Driver','\\.','Device','\\??\\','svc','Service','HKLM','Software\\','CurrentVersion','vxd',
 'BOUNTY','bounty','license','License','licen','Themida','themida','WinLicense','winlicense','Oreans','oreans',
 'SEH','VEH','AddVectored','NtSetInformation','ThreadHideFromDebugger','DbgUi','DbgBreak','NtCreateFile',
 'temp','TEMP','Temp','appdata','APPDATA','dll','.dll','.sys','pdb','PDB','http','HTTP','www','cmd','powershell']
seen = {}
for o,s in astr:
    for t in INTERESTING:
        if t in s:
            seen.setdefault(t, []).append((o,s))
for t in sorted(seen):
    lst = seen[t]
    print(f"\n### '{t}' ({len(lst)} strings):")
    for o,s in lst[:12]:
        print(f"  unpacked+{o:#x} (VA {0x1CA7000+o:#x}): {s[:110]}")
