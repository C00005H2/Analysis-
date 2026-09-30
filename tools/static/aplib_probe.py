import sys
sys.path.insert(0, '/tmp/retools')
import aplib
data = open('/home/user/Analysis-/Test2.exe','rb').read()
# aPLib probe: try depacking from the start of each big encrypted section and a few skews
for name, off in [('s0', 0x600), ('s1', 0x5A4800), ('s2', 0x5A9600), ('s9', 0x5C0200), ('s10', 0x698000)]:
    for skew in (0, 1, 2):
        try:
            out = aplib.depack(data[off+skew:off+skew+0x40000])
            printable = sum(1 for b in out[:256] if 32 <= b < 127 or b in (0,9,10,13))
            print(f"{name}+{skew}: DEPACKED {len(out)} bytes! printable {printable}/256 head={out[:24].hex(' ')}")
        except Exception as e:
            print(f"{name}+{skew}: fail ({type(e).__name__}: {str(e)[:50]})")
# known-good control: the .boot stream
try:
    out = aplib.depack(data[0x9D2A07+1:0x9D2A07+1+0x40000])
    print(f"CONTROL .boot+1: depacked {len(out)} bytes, head={out[:16].hex(' ')}")
except Exception as e:
    print(f"CONTROL .boot+1: fail {e}")
