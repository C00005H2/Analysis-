import struct, collections
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import *
try:
    from capstone import CS_AC_READ, CS_AC_WRITE
except ImportError:
    CS_AC_READ, CS_AC_WRITE = 1, 2
k = open('/tmp/test2_winlice_unpacked.bin','rb').read()
BASE = 0x1CA7000; WINLICE_RVA = 0x18A7000
md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
data = open('/home/user/Analysis-/Test2.exe','rb').read()
blob = data[0x9BDA00:0x9BDA00+0x8000]
# collect the 685 slot->target edges
targets = []
for i in range(0, 0x61d0, 8):
    a,b = struct.unpack_from('<II', blob, i)
    if a and b == a+5 and WINLICE_RVA <= a < 0x34F9000:
        off = a - WINLICE_RVA
        if k[off] == 0xE9:
            rel = struct.unpack_from('<i', k, off+1)[0]
            targets.append(BASE + off + 5 + rel)
uniq = sorted(set(targets))
print(f"edges: {len(targets)}, unique handler targets: {len(uniq)}")

REGS = {X86_REG_EAX:'a',X86_REG_EBX:'b',X86_REG_ECX:'c',X86_REG_EDX:'d',X86_REG_ESI:'si',X86_REG_EDI:'di',X86_REG_EBP:'bp',X86_REG_ESP:'sp'}
def analyze(tva):
    off = tva - BASE
    code = k[off:off+400]
    ctx_reads=set(); ctx_writes=set(); mn=collections.Counter()
    feats=set(); end_jmp=None; n_ins=0
    # symbolic: reg -> offset from ebp (None = unknown)
    sym = {}
    try:
        insns = list(md.disasm(code, tva))
    except Exception:
        return None
    for ins in insns:
        n_ins += 1
        m = ins.mnemonic; mn[m]+=1
        if m in ('rdtsc',): feats.add('rdtsc')
        if m in ('cpuid',): feats.add('cpuid')
        if m == 'int': feats.add('int')
        if m in ('sidt','sgdt','sldt','str'): feats.add('table_reg')
        if m in ('pushfd','popfd','pushf','popf'): feats.add('eflags')
        if m in ('imul','mul'): feats.add('mul')
        if m in ('shl','shr','rol','ror'): feats.add('shift')
        if m == 'call': feats.add('call')
        if m in ('in','out','ins','outs'): feats.add('io')
        # symbolic propagation
        if m == 'mov' and len(ins.operands)==2:
            o0,o1 = ins.operands
            if o0.type == X86_OP_REG and o1.type == X86_OP_REG:
                r0,r1 = REGS.get(o0.reg), REGS.get(o1.reg)
                if r1 is not None:
                    if r1=='bp': sym[r0]=0
                    elif r1 in sym: sym[r0]=sym[r1]
                elif r0 in sym: sym.pop(r0, None)
            if o0.type == X86_OP_REG and o1.type == X86_OP_IMM and REGS.get(o0.reg)=='bp':
                pass
        if m == 'add' and len(ins.operands)==2 and ins.operands[0].type==X86_OP_REG:
            r0 = REGS.get(ins.operands[0].reg); o1 = ins.operands[1]
            if r0 is not None and o1.type == X86_OP_IMM and r0 in sym and sym[r0] is not None:
                v = sym[r0] + (o1.imm & 0xffffffff)
                sym[r0] = v if v <= 0x10000 else None
        if m == 'lea' and len(ins.operands)==2:
            o0,o1 = ins.operands
            if o0.type==X86_OP_REG and o1.type==X86_OP_MEM:
                r1 = REGS.get(o1.mem.base) if o1.mem.base else None
                if r1=='bp': sym[REGS.get(o0.reg)] = o1.mem.disp & 0xffffffff
                elif r1 in sym and sym[r1] is not None: sym[REGS.get(o0.reg)] = sym[r1]+o1.mem.disp
        # memory accesses via ebp-relative regs
        for o in ins.operands:
            if o.type == X86_OP_MEM:
                b = REGS.get(o.mem.base) if o.mem.base else None
                idx = REGS.get(o.mem.index) if o.mem.index else None
                if b == 'bp' or (b in sym and sym.get(b) is not None):
                    if b == 'bp': delta = o.mem.disp & 0xffffffff
                    else: delta = sym[b] + (o.mem.disp & 0xffffffff if o.mem.disp else 0)
                    delta &= 0xffffffff
                    if delta > 0x8000: continue
                    acc = getattr(o, 'access', 3)
                    if acc & CS_AC_READ: ctx_reads.add(delta)
                    if acc & CS_AC_WRITE: ctx_writes.add(delta)
                elif idx in sym:
                    pass
        if m in ('jmp','ret','retn','retf','iretd','jmpf') and len(ins.operands)>=0:
            if m=='jmp' and ins.operands[0].type==X86_OP_IMM:
                end_jmp = ins.operands[0].imm
            break
        if n_ins > 120: break
    return dict(va=tva, n=n_ins, mn=mn, feats=feats, reads=ctx_reads, writes=ctx_writes, end=end_jmp)

res = [r for r in (analyze(t) for t in uniq) if r]
print(f"analyzed: {len(res)} handlers")
# 1) ctx offset frequency across all handlers
freq = collections.Counter()
wfreq = collections.Counter()
for r in res:
    for o in r['reads']: freq[o]+=1
    for o in r['writes']: wfreq[o]+=1
print("\n=== VM-context offsets by usage frequency (reads | writes) ===")
for off,c in freq.most_common(40):
    print(f"  ctx+{off:#06x}: read in {c:3} handlers, written in {wfreq.get(off,0):3}")
# 2) contiguous runs of offsets (register file?)
offs = sorted(freq)
runs=[]; cur=[offs[0]]
for o in offs[1:]:
    if o-cur[-1] in (2,4,6,8): cur.append(o)
    else: runs.append(cur); cur=[o]
runs.append(cur)
print("\n=== contiguous ctx offset runs (>=4 members, step<=8) ===")
for r in runs:
    if len(r)>=4: print(f"  ctx+{r[0]:#x}..ctx+{r[-1]:#x} ({len(r)} fields: {[hex(x) for x in r[:12]]}{'...' if len(r)>12 else ''})")
# 3) feature census
fc = collections.Counter()
for r in res:
    for f in r['feats']: fc[f]+=1
print("\n=== feature census across handlers ===", dict(fc))
# 4) end-jmp destinations
ends = collections.Counter()
for r in res:
    if r['end']: ends[(r['end']-BASE)>>20]+=1
print("=== handler-terminal jmp destination (unpacked MB bucket) ===", dict(sorted(ends.items())))
# 5) save per-handler data
import json
json.dump([{ 'va':r['va'],'n':r['n'],'feats':sorted(r['feats']),'reads':sorted(hex(x) for x in r['reads']),'writes':sorted(hex(x) for x in r['writes']),'end':r['end'],'mn':dict(r['mn'])} for r in res], open('/tmp/handlers.json','w'))
print("\nsaved /tmp/handlers.json")
