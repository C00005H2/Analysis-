import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
k = open('/tmp/test2_winlice_unpacked.bin','rb').read()
BASE = 0x1CA7000
md = Cs(CS_ARCH_X86, CS_MODE_32)
off = 0x12FD4B4  # VA 0x2FA44B4 kernel entry
print(f"=== kernel entry VA 0x2FA44B4 (unpacked+{off:#x}) — first 120 instructions ===")
n=0
for i in md.disasm(k[off:off+0x400], BASE+off):
    print(f"  {i.address:#x}: {i.mnemonic:9} {i.op_str}")
    n+=1
    if n>=120: break
