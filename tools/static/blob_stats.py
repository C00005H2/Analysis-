import struct, collections, math
data = open('/home/user/Analysis-/Test2.exe','rb').read()
off = 0x5BFA00  # fake delay-import dir (file)
blob = data[off:off+0xB34]
recs = [blob[i*32:(i+1)*32] for i in range(36)]
def H(b):
    c = collections.Counter(b); n = len(b)
    return -sum(v/n*math.log2(v/n) for v in c.values())
print("per-record entropy (36 x 32 bytes):")
for i,r in enumerate(recs):
    nz = len(r.rstrip(b'\x00'))
    print(f"  rec{i:02d}: entropy={H(r):.3f} nonzero_bytes={nz} first8={r[:8].hex(' ')}")
# position-wise statistics across records
print("\nbyte-value diversity per byte-position (0..31) across the 36 records:")
for pos in range(32):
    col = [r[pos] for r in recs]
    c = collections.Counter(col)
    mode, cnt = c.most_common(1)[0]
    print(f"  pos {pos:2}: distinct={len(c):2} mode={mode:#04x} x{cnt}")
# any repeated 4-byte sequences across records?
seqs = collections.Counter()
for r in recs:
    for i in range(0,32,4):
        seqs[struct.unpack_from('<I', r, i)[0]] += 1
reps = {v:c for v,c in seqs.items() if c>1}
print(f"\nrepeated dwords across records: {len(reps)}", dict(list(reps.items())[:10]))
# try XOR-decoding record 0 with candidate keys (0x9E3779B9, CRC poly, etc.)
r0 = recs[0]
for key in (0x9E3779B9, 0xEDB88320, 0x54EC56B9, 0xAB4130, 0xBEEFAD01):
    dec = bytes(b ^ ((key >> ((i%4)*8)) & 0xFF) for i,b in enumerate(r0))
    printable = sum(1 for b in dec if 32<=b<127)
    print(f"  XOR {key:#x} -> printable {printable}/32: {dec[:16].hex(' ')}")
print(f"\nterminator after rec35: {blob[36*32:36*32+16].hex(' ')}")
print(f"total dir size 0xB34 = {0xB34}; 36*32 = {36*32:#x}; trailing {0xB34-36*32} bytes:")
print('  ' + blob[36*32:].hex(' '))
