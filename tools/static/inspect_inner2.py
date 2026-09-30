import sys,os,struct,hashlib
sys.path.insert(0,'/tmp/retools');import pefile
b=open('/tmp/test2_winlice_unpacked.bin','rb').read()
for j,start in enumerate([0x56f0,0x12eba60]):
 e=struct.unpack_from('<I',b,start+0x3c)[0];n=struct.unpack_from('<H',b,start+e+6)[0];op=struct.unpack_from('<H',b,start+e+20)[0];sh=start+e+24+op
 sec=[]
 for i in range(n):
  q=sh+i*40; name=b[q:q+8].rstrip(b'\0');vs,va,rs,rp=struct.unpack_from('<IIII',b,q+8);sec.append((name,vs,va,rs,rp))
 end=max([rp+rs for _,_,_,rs,rp in sec]+[0x400])
 print('candidate',j,'base offset',hex(start),'file extent',hex(end),'end',hex(start+end),'size',hex(end))
 path=f'/tmp/inner{j}_fixed.exe';open(path,'wb').write(b[start:start+end])
 p=pefile.PE(path); print('warnings',p.get_warnings());print('hash',hashlib.sha256(b[start:start+end]).hexdigest())
 print('imports')
 if hasattr(p,'DIRECTORY_ENTRY_IMPORT'):
  for x in p.DIRECTORY_ENTRY_IMPORT:print(x.dll,[(i.name,i.ordinal,hex(i.address)) for i in x.imports])
 print('dirs',[(d.name,hex(d.VirtualAddress),hex(d.Size))for d in p.OPTIONAL_HEADER.DATA_DIRECTORY])
 print('tls')
 if hasattr(p,'DIRECTORY_ENTRY_TLS'):
  print(p.DIRECTORY_ENTRY_TLS.struct.dump())
  # manually pointer list
  c=p.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks; print('callback VA',hex(c));
  if c:
   r=c-p.OPTIONAL_HEADER.ImageBase; o=p.get_offset_from_rva(r);print('callback values',[hex(struct.unpack_from('<I',p.__data__,o+k*4)[0]) for k in range(8)])
 print('debug')
 if hasattr(p,'DIRECTORY_ENTRY_DEBUG'):
  for d in p.DIRECTORY_ENTRY_DEBUG: print(d.struct.dump(),p.get_data(d.struct.AddressOfRawData,d.struct.SizeOfData))
 print('resources')
 if hasattr(p,'DIRECTORY_ENTRY_RESOURCE'):
  def rid(x):return x.name.string if x.name else x.id
  for a in p.DIRECTORY_ENTRY_RESOURCE.entries:
   for c1 in a.directory.entries:
    for c2 in c1.directory.entries:
     s=c2.data.struct;dat=p.get_data(s.OffsetToData,s.Size);print(rid(a),rid(c1),rid(c2),hex(s.OffsetToData),hex(s.Size),dat[:64])
 print('relocs')
 if hasattr(p,'DIRECTORY_ENTRY_BASERELOC'):
  for r in p.DIRECTORY_ENTRY_BASERELOC:print(r.struct.dump(),[(hex(x.rva),x.type)for x in r.entries])
