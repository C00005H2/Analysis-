import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM, X86_OP_REG, X86_OP_MEM
k = open('/tmp/test2_winlice_unpacked.bin','rb').read()
BASE = 0x1CA7000
md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
for tva in (0x1CCCEF7, 0x1CF5C3A, 0x2F966E8, 0x2FC0B5F):
    off = tva - BASE
    insns = list(md.disasm(k[off:off+420], tva))
    print(f"=== handler VA {tva:#x} ===")
    shown = 0
    for i, ins in enumerate(insns):
        if ins.mnemonic in ('call','push','pop','cmp','jbe','jmp') and shown < 14:
            print(f"  {ins.address:#x}: {ins.mnemonic:6} {ins.op_str}")
            shown += 1
        if ins.mnemonic == 'call':
            o = ins.operands[0]
            if o.type == X86_OP_IMM:
                tgt = o.imm
                # what's at the call target?
                toff = tgt - BASE if BASE <= tgt < BASE+len(k) else None
                if toff is not None:
                    first = list(md.disasm(k[toff:toff+24], tgt))[:3]
                    print(f"      -> calls {tgt:#x} (unpacked+{toff:#x}): " + ' ; '.join(f"{x.mnemonic} {x.op_str}" for x in first))
            break
