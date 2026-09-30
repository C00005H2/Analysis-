import math, collections
data = open('/home/user/Analysis-/Test2.exe','rb').read()
secs = [  # (name, rawoff, rawsize, vsize)
 ('s0', 0x600, 0x5A4200, 0xFFBFD4), ('s1', 0x5A4800, 0x4E00, 0x916C),
 ('s2', 0x5A9600, 0x15C00, 0x24314), ('s4', 0x5BF200, 0x800, 0x5B78),
 ('s5', 0x5BFA00, 0x400, 0xB34), ('s6', 0x5BFE00, 0x200, 0xB3),
 ('s8', 0x5C0000, 0x200, 0x5D), ('s9', 0x5C0200, 0xD7E00, 0x1820C0),
 ('s10', 0x698000, 0x325800, 0x6CC4E8)]
def H(b):
    c = collections.Counter(b); n=len(b)
    return -sum(v/n*math.log2(v/n) for v in c.values())
for name, off, rs, vs in secs:
    blob = data[off:off+rs]
    print(f"=== {name} raw {off:#x} size {rs:#x} ===")
    print("  first 32:", blob[:32].hex(' '))
    # 64KB block entropy profile (first 12 blocks)
    prof = [round(H(blob[i:i+65536]),2) for i in range(0, min(rs, 12*65536), 65536)]
    print(f"  64KB entropy profile (first {len(prof)} blocks): {prof}")
    # longest zero run + most common 16-byte block
    zr = max((len(r) for r in blob.split(b'\x00') if False), default=0)
    import re
    zruns = sorted((m.end()-m.start() for m in re.finditer(rb'\x00{8,}', blob)), reverse=True)[:3]
    c16 = collections.Counter(blob[i:i+16] for i in range(0, len(blob)-16, 16))
    top16, cnt16 = c16.most_common(1)[0]
    print(f"  zero-runs>=8 top3: {zruns}; most common 16B block repeats x{cnt16}")
    print(f"  whole-section entropy: {H(blob):.3f}")
