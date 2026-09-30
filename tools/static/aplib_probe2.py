import sys
sys.path.insert(0, '/tmp/retools')
from aplib import APLib
data = open('/home/user/Analysis-/Test2.exe','rb').read()
def try_depack(name, buf, maxout=0x40000):
    try:
        out = APLib(buf).depack()
        printable = sum(1 for b in out[:256] if 32 <= b < 127 or b in (0,9,10,13))
        print(f"{name}: DEPACKED {len(out)} bytes, printable {printable}/256, head={out[:24].hex(' ')}")
        return out
    except Exception as e:
        print(f"{name}: fail ({type(e).__name__}: {str(e)[:60]})")
        return None
# control first
try_depack('CONTROL .boot+1', data[0x9D2A08:0x9D2A08+0x40000])
for name, off in [('s0+0',0x600),('s0+1',0x601),('s1+0',0x5A4800),('s2+0',0x5A9600),('s4+0',0x5BF200),('s9+0',0x5C0200),('s10+0',0x698000)]:
    try_depack(name, data[off:off+0x40000])
