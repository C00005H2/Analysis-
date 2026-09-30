import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
k = open('/tmp/test2_winlice_unpacked.bin','rb').read()
BASE = 0x1CA7000
md = Cs(CS_ARCH_X86, CS_MODE_32)
vals = [0x20f4,0x21de,0x2010,0x2124,0x21fa,0x2040,0x20ec,0x2220,0x2008,0x20e4,
        0x2122,0x2106,0x2176,0x2188,0x2198,0x2162,0x21b0,0x21c0,0x21d0,0x214c,0x213a,0x21a4,0x212c,0x21ec,
        0x2282,0x2278,0x227c,0x2280,0x228f,0x1147]
print("=== .data dword values tested as .winlice offsets (unpacked+X, VA 0x1CA7000+X) ===")
for v in sorted(set(vals)):
    code = k[v:v+40]
    ins = next(md.disasm(code, BASE+v), None)
    # heuristic: is the first instruction a jmp rel32 (E9) or a plausible prologue?
    b0 = k[v]
    tag = 'E9-jmp' if b0==0xE9 else ('EB-jmp' if b0==0xEB else hex(b0))
    tgt=''
    if b0==0xE9:
        rel = struct.unpack_from('<i', k, v+1)[0]; tgt=f'-> {BASE+v+5+rel:#x}'
    if ins:
        print(f"  +{v:#06x} VA {BASE+v:#x}: [{tag:6}] {ins.mnemonic} {ins.op_str} {tgt}")
    else:
        print(f"  +{v:#06x} VA {BASE+v:#x}: [{tag}] (no decodable insn)")
print("\n=== raw bytes unpacked+0x2000..0x2320, disassembled linearly (first 70 insns) ===")
n=0
for i in md.disasm(k[0x2000:0x2320], BASE+0x2000):
    print(f"  {i.address:#x}: {i.mnemonic:9} {i.op_str}")
    n+=1
    if n>=70: break
