import re, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
k = open('/tmp/test2_winlice_unpacked.bin','rb').read()
BASE = 0x1CA7000
md = Cs(CS_ARCH_X86, CS_MODE_32)
hits = [m.start() for m in re.finditer(b'\x0f\x31', k)]
print(f"rdtsc byte-pair occurrences: {len(hits)}")
# check which ones decode as an actual rdtsc instruction at an instruction boundary going backwards
real = 0; shown = 0
for h in hits:
    # try to find a decode where rdtsc is an instruction: disasm backwards 32 bytes, see if any insn starts exactly at h
    for back in range(1, 40):
        chunk = k[h-back:h+40]
        insns = list(md.disasm(chunk, BASE+h-back))
        ok = any(i.address == BASE+h and i.mnemonic == 'rdtsc' for i in insns)
        if ok:
            # context plausibility: neighbors are mov/push/etc not junk?
            ctx = [i.mnemonic for i in insns[:6]]
            plausible = sum(1 for m in ctx if m in ('mov','push','pop','add','sub','xor','cmp','jmp','call','rdtsc','shl','shr','test','and','or','lea','ret','xchg','imul','mul','div','nop','leave','inc','dec','not','neg','rol','ror')) >= 4
            if plausible:
                real += 1
                if shown < 4:
                    shown += 1
                    print(f"\n--- plausible rdtsc at VA {BASE+h:#x} (unpacked+{h:#x}) ---")
                    for i in insns[:7]:
                        print(f"  {i.address:#x}: {i.mnemonic:8} {i.op_str}")
            break
print(f"\nrdtsc occurrences that decode as real instructions in plausible code context: {real}")
