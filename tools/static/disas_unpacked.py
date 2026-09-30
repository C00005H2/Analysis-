import sys;sys.path.insert(0,'/tmp/retools');from capstone import *
b=open('/tmp/test2_winlice_unpacked.bin','rb').read();md=Cs(CS_ARCH_X86,CS_MODE_32);md.detail=False;base=0x1ca7000
for off,n in [(0,0x600),(0x12fd4b4,0x1000),(0x56f0,0x400),(0x6bba7,0x400)]:
 print('\n# OFFSET',hex(off),'VA',hex(base+off))
 for x in md.disasm(b[off:off+n],base+off):print(f'{x.address:08x}: {x.mnemonic:<8} {x.op_str}')
