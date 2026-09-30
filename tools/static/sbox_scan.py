import numpy as np
k = open('/tmp/test2_winlice_unpacked.bin','rb').read()
a = np.frombuffer(k, dtype=np.uint8)
N = len(a); W = 256
print(f"scanning {N:,} bytes for 256-byte permutation windows (custom S-boxes)...")
# rolling distinct-count via bincount updates
cnt = np.zeros(256, dtype=np.int32)
# init window [0,W)
cnt = np.bincount(a[:W], minlength=256).astype(np.int32)
distinct = int(np.count_nonzero(cnt))
hits = []
for i in range(N - W):
    if distinct == W:
        hits.append(i)
        if len(hits) > 400: break
    # slide: remove a[i], add a[i+W]
    out_b = a[i]; in_b = a[i+W]
    if out_b != in_b:
        if cnt[out_b] == 1: distinct -= 1
        cnt[out_b] -= 1
        if cnt[in_b] == 0: distinct += 1
        cnt[in_b] += 1
print(f"permutation windows found: {len(hits)}")
for h in hits[:30]:
    # classify: is it a known S-box? check linearity/affine of S[x]^x
    box = k[h:h+256]
    xor_sum = box[0]  # S-box type heuristics
    fixed = sum(1 for x in range(256) if box[x]==x)
    print(f"  unpacked+{h:#x} (VA {0x1CA7000+h:#x}): fixed points={fixed}, S[0]={box[0]:#04x}, S[1]={box[1]:#04x}, S[255]={box[255]:#04x}")
# merge adjacent hits (same S-box sliding? permutations can't overlap by 1... actually two different windows)
print("note: distinct permutation windows at these offsets")
