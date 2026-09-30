import sys, hashlib, os, struct, collections, math
sys.path.insert(0,'/tmp/retools')
from aplib import APLib
b=open('Test2.exe','rb').read()
start=0x9d2800+0x206
n=b[start];pos=start+1
print('block count',n,'stream begin',hex(pos))
out=bytearray(); blocks=[]
for i in range(n):
 a=APLib(b[pos:],strict=True)
 try: d=a.depack()
 except Exception as e:
  print('BLOCK ERROR',i,'at',hex(pos),e,'consumed',a.source.tell(),'out',len(a.destination));raise
 c=a.source.tell()
 blocks.append((pos,c,len(d),hashlib.sha256(d).hexdigest(),d[:16].hex()))
 print('%02d src %08x..%08x %8d -> dst %08x..%08x %8d sha256 %s first %s'%(i,pos,pos+c,c,len(out),len(out)+len(d),len(d),hashlib.sha256(d).hexdigest()[:16],d[:16].hex()))
 pos+=c; out+=d
print('end',hex(pos),'packed used',pos-(start+1),'output',len(out),'range valid',len(out)<=0x1c52000)
open('/tmp/test2_winlice_unpacked.bin','wb').write(out)
open('/tmp/test2_unpack_blocks.txt','w').write('\n'.join(map(str,blocks)))
# Content analysis / candidate formats and strings
for x in [b'MZ', b'PE\0\0',b'BSJB',b'PK\x03\x04',b'\x7fELF',b'<?xml',b'http',b'kernel32.dll',b'CreateFile',b'VirtualAlloc',b'WinMain',b'GetProcAddress']:
 print(repr(x), [hex(i) for i in [out.find(x),out.find(x,out.find(x)+1) if out.find(x)>=0 else -1] if i>=0])
# entropy total and 64K lower
ent=lambda d: -sum((v/len(d))*math.log2(v/len(d)) for v in collections.Counter(d).values()) if d else 0
print('unpacked entropy',ent(out),'sha256',hashlib.sha256(out).hexdigest())
# dump the expected jump target offset
for off in [0,0x12fd4b4]:
 print('OFF',hex(off),out[off:off+256].hex())
