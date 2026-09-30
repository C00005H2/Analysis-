import numpy as np
k = open('/tmp/test2_winlice_unpacked.bin','rb').read()
a = np.frombuffer(k, dtype=np.uint8)
N = len(a); W = 256
print(f"scanning {N:,} bytes for 256-byte permutation windows (custom S-boxes)...")
# rolling window distinct-count using np.bincount-like updates in pure numpy loop is slow;
# use trick: positions where byte value v occurs -> diff approach.
# A window [i, i+W) is a permutation iff for every byte value, count in window == 1.
# Equivalent: window contains 256 distinct values (since size 256).
# Efficient method: for each value v, occurrences sorted; a window contains v at most once
# iff no two occurrences of any value are within distance < W.
# Approach: compute min gap between equal bytes: bad positions.
occ_min_gap = W
bad = np.zeros(N, dtype=bool)
# for each pair of consecutive equal-byte positions with gap < W, mark the range of window starts containing both
# window start i contains positions p and q (p<q, q-p<W) iff i <= p and i + W > q, i.e., i in (q-W, p]
# do it vectorized per value is 256 loops:
idx_sorted = np.argsort(a, kind='stable')
svals = a[idx_sorted]
for v in range(256):
    pos = idx_sorted[svals == v]
    if len(pos) < 2: continue
    d = np.diff(pos)
    close = d < W  # pairs both inside some window
    if not close.any(): continue
    p = pos[:-1][close]; q = pos[1:][close]
    # window starts i in [q-W+1, p] are bad
    lo = np.maximum(q - W + 1, 0); hi = np.minimum(p, N-1)
    for l, h in zip(lo, hi):
        bad[l:h+1] = True
good = np.where(~bad[:N-W+1])[0]
print(f"permutation windows found: {len(good)}")
for h in good[:40]:
    box = k[h:h+256]
    fixed = sum(1 for x in range(256) if box[x]==x)
    print(f"  unpacked+{h:#x} (VA {0x1CA7000+h:#x}): fixed_points={fixed} S[0]={box[0]:#04x} S[1]={box[1]:#04x} S[0x80]={box[0x80]:#04x} S[0xff]={box[255]:#04x}")
