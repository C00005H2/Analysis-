import re, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
k = open('/tmp/test2_winlice_unpacked.bin','rb').read()
BASE = 0x1CA7000
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = False
pat = bytes.fromhex('b979379e')
hits = [m.start() for m in re.finditer(re.escape(pat), k)]
print(f"TEA delta sites ({len(hits)}):")
for h in hits:
    va = BASE + h
    # disassemble a window starting a bit before to catch the instruction containing the imm
    start = h - 24
    code = k[start:h+12]
    insns = list(md.disasm(code, BASE+start))
    print(f"\n--- unpacked+{h:#x} (VA {va:#x}) ---")
    for i in insns:
        mark = ' <== delta' if (i.address <= BASE+h < i.address+i.size) else ''
        print(f"  {i.address:#x}: {i.mnemonic:8} {i.op_str}{mark}")
# CRC32 table check
t = 0x13b6ebc
tbl = k[t:t+8*4]
vals = struct.unpack('<8I', tbl)
print(f"\nCRC32 table @ unpacked+{t:#x} (VA {BASE+t:#x}), first 8 dwords:")
print('  ' + ' '.join(f'{v:08x}' for v in vals))
expect = [0x00000000,0x77073096,0xEE0E612C,0x990951BA,0x076DC419,0x706AF48F,0xE963A535,0x9E6495A3]
print(f"  matches standard reflected CRC32 table: {list(vals)==expect}")
# how big is the table? standard 1024 bytes
full = struct.unpack('<256I', k[t:t+1024])
print(f"  table complete (256 entries, last={full[255]:#x}, expect DEBB20E3): {full[255]==0xDEBB20E3}")
