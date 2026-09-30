import sys, struct
sys.path.insert(0, '/tmp/retools')
from unicorn import *
from unicorn.x86_const import *
K = open('/tmp/test2_winlice_unpacked.bin','rb').read()
BASE = 0x1CA7000
uc = Uc(UC_ARCH_X86, UC_MODE_32)
uc.mem_map(0x1CA7000, 0x1C52000)      # .winlice
uc.mem_write(0x1CA7000, K)
uc.mem_map(0x200000, 0x200000)        # stack
uc.mem_map(0x50000, 0x1000)           # GDT scratch (not used here)
print("kernel bytes at VA 0x2FA44B4:", K[0x2FA44B4-BASE:0x2FA44B4-BASE+16].hex(' '))
print("kernel bytes at VA 0x2FB44B0:", K[0x2FB44B0-BASE:0x2FB44B0-BASE+16].hex(' '))
print("kernel bytes at VA 0x304F480:", K[0x304F480-BASE:0x304F480-BASE+16].hex(' '))
n=[0]
def hook(uc, addr, size, ud):
    n[0]+=1
    b = bytes(uc.mem_read(addr, min(size,10)))
    print(f'  {n[0]:03d} {addr:#x}: {b.hex(" ")}', flush=True)
    if n[0]>=25: uc.emu_stop()
uc.hook_add(UC_HOOK_CODE, hook)
uc.reg_write(UC_X86_REG_ESP, 0x3F0000-0x100)
uc.reg_write(UC_X86_REG_EBP, 0x3EF800)
try:
    uc.emu_start(0x2FA44B4, 0, count=25)
except UcError as e:
    print('ERR', e, 'eip=', hex(uc.reg_read(UC_X86_REG_EIP)))
