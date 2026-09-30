import struct
k = open('/tmp/test2_winlice_unpacked.bin','rb').read()
# build standard reflected CRC32 table
tab=[]
for i in range(256):
    c=i
    for _ in range(8):
        c = (c>>1)^0xEDB88320 if c&1 else c>>1
    tab.append(c)
stdbytes = b''.join(struct.pack('<I',x) for x in tab)
# what did we find at 0x13b6ebc?
t=0x13b6ebc
got = k[t:t+1024]
# is got a subsequence of the standard table?
seq = k[t:t+32]
idx = stdbytes.find(seq)
print(f"first 32 bytes found @0x13b6ebc inside standard table: offset {idx} ({'table['+str(idx//4)+']' if idx>=0 else 'NO MATCH'})")
# maybe the table is a different poly. Recover poly: for a reflected table, tab[128] == poly
tab_got = struct.unpack('<256I', got)
print(f"got[0]={tab_got[0]:#x}  got[1]={tab_got[1]:#x}  got[127]={tab_got[127]:#x}  got[128]={tab_got[128]:#x}  got[255]={tab_got[255]:#x}")
# derive poly from got[128] (for standard construction table[128]=poly when reflected... actually table[0x80]=poly)
poly = tab_got[128]
print(f"implied polynomial (got[128]): {poly:#x}")
# verify: rebuild table with that poly and compare
t2=[]
for i in range(256):
    c=i
    for _ in range(8):
        c = (c>>1)^poly if c&1 else c>>1
    t2.append(c)
print(f"got == rebuild-with-poly({poly:#x}): {t2==list(tab_got)}")
print(f"standard poly 0xEDB88320 table == got: {tab==list(tab_got)}")
