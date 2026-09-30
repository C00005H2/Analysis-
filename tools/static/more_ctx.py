import re
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
k = open('/tmp/test2_winlice_unpacked.bin','rb').read()
BASE = 0x1CA7000
md = Cs(CS_ARCH_X86, CS_MODE_32)
GOOD = ('mov','push','pop','add','sub','xor','cmp','jmp','call','rdtsc','shl','shr','test','and','or','lea','ret','xchg','imul','mul','div','nop','leave','inc','dec','not','neg','rol','ror','cpuid','sidt','sgdt','sldt','str','int','cmpxchg','bswap','sete','setne','movzx','movsx','cdq','cwde','xadd')
def check(pat, want):
    hits = [m.start() for m in re.finditer(re.escape(pat), k)]
    real = 0
    for h in hits:
        for back in range(1, 40):
            chunk = k[h-back:h+40]
            insns = list(md.disasm(chunk, BASE+h-back))
            if any(i.address == BASE+h and i.mnemonic == want for i in insns):
                ctx = [i.mnemonic for i in insns[:6]]
                if sum(1 for m in ctx if m in GOOD) >= 4: real += 1
                break
    print(f"{want}: {len(hits)} byte-occurrences, {real} decode as real instruction in plausible code")
check(b'\x0f\xa2', 'cpuid')
check(b'\xcd\x2d', 'int')
# sidt [mem] forms: 0F 01 0D/15/1D/25/2D/35/3D disp32
for op in [b'\x0f\x01\x0d', b'\x0f\x01\x15', b'\x0f\x01\x1d', b'\x0f\x01\x25', b'\x0f\x01\x2d', b'\x0f\x01\x35', b'\x0f\x01\x3d']:
    n = len(re.findall(re.escape(op), k))
    if n: print(f"sidt [mem] form {op.hex()}: {n}")
for op in [b'\x0f\x01\x01', b'\x0f\x01\x11', b'\x0f\x01\x21', b'\x0f\x01\x31']:
    n = len(re.findall(re.escape(op), k))
    if n: print(f"sgdt [mem] form {op.hex()}: {n}")
