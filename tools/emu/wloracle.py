import re
from unicorn import *
from unicorn.x86_const import *

KERNEL = open('/tmp/test2_winlice_unpacked.bin','rb').read()
BASE = 0x400000
size = ((0x18A7000 + len(KERNEL) + 0xFFF) & ~0xFFF)
uc = Uc(UC_ARCH_X86, UC_MODE_32)
uc.mem_map(BASE, size)
uc.mem_write(BASE + 0x18A7000, KERNEL)
NAME_AT, STACK = 0x40000000, 0x40010000
uc.mem_map(NAME_AT, 0x10000)
uc.mem_map(STACK, 0x10000)
try: uc.mem_map(0x3EF000, 0x2000)
except UcError: pass

trace = []
def hk(uc_, addr, size_, ud):
    trace.append(uc_.reg_read(UC_X86_REG_EAX) + uc_.reg_read(UC_X86_REG_EBX) +
                 uc_.reg_read(UC_X86_REG_ECX) + uc_.reg_read(UC_X86_REG_EDX) +
                 uc_.reg_read(UC_X86_REG_ESI) + uc_.reg_read(UC_X86_REG_EDI))
uc.hook_add(UC_HOOK_CODE, hk, None, 0x307E4D5, 0x307E4D5)

def wl_hash(name):
    b = name.encode('latin1') + b'\0'
    if len(b) > 60: return None
    uc.mem_write(NAME_AT, b)
    del trace[:]
    uc.reg_write(UC_X86_REG_EAX, 0); uc.reg_write(UC_X86_REG_EBX, 0)
    uc.reg_write(UC_X86_REG_ECX, 0xFFFFFFFF); uc.reg_write(UC_X86_REG_EDX, 0xFFFFFFFF)
    uc.reg_write(UC_X86_REG_ESI, NAME_AT); uc.reg_write(UC_X86_REG_EDI, len(b))
    uc.reg_write(UC_X86_REG_EBP, 0x3EFEEC); uc.reg_write(UC_X86_REG_ESP, STACK + 0xF000)
    try:
        uc.emu_start(0x307E4D5, 0x2F8FC65, count=2000000)
    except UcError:
        return None
    return uc.reg_read(UC_X86_REG_EAX)
