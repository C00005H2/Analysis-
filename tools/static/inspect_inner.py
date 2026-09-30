import sys,os,struct,hashlib,datetime
sys.path.insert(0,'/tmp/retools');import pefile
b=open('/tmp/test2_winlice_unpacked.bin','rb').read()
for j,start in enumerate([0x56f0,0x12eba60]):
 # calc end section raw
 e=struct.unpack_from('<I',b,start+0x3c)[0];n=struct.unpack_from('<H',b,start+e+6)[0];op=struct.unpack_from('<H',b,start+e+20)[0];sh=start+e+24+op
 end=max([struct.unpack_from('<II',b,sh+40*i+16)[0]+struct.unpack_from('<I',b,sh+40*i+20)[0] for i in range(n)]+[sh+40*n])
 print('candidate',j,'start',hex(start),'end',hex(end),'size',hex(end-start))
 path=f'/tmp/inner{j}.exe';open(path,'wb').write(b[start:end])
 p=pefile.PE(path);print('warnings',p.get_warnings());print('file',p.FILE_HEADER.dump());print('opt',p.OPTIONAL_HEADER.dump())
 print('sections')
 for s in p.sections:print(s.Name,s.dump())
 print('imports')
 if hasattr(p,'DIRECTORY_ENTRY_IMPORT'):
  for x in p.DIRECTORY_ENTRY_IMPORT:print(x.dll,[(i.name,i.ordinal,hex(i.address)) for i in x.imports])
 print('exports')
 if hasattr(p,'DIRECTORY_ENTRY_EXPORT'):
  print(p.DIRECTORY_ENTRY_EXPORT.struct.dump());print([(z.name,z.ordinal,hex(z.address)) for z in p.DIRECTORY_ENTRY_EXPORT.symbols])
 print('tls')
 if hasattr(p,'DIRECTORY_ENTRY_TLS'):print(p.DIRECTORY_ENTRY_TLS.struct.dump())
 print('resources')
 if hasattr(p,'DIRECTORY_ENTRY_RESOURCE'):
  for a in p.DIRECTORY_ENTRY_RESOURCE.entries: print(a.id,a.name)
 print('relocs')
 if hasattr(p,'DIRECTORY_ENTRY_BASERELOC'):
  print([(hex(x.struct.VirtualAddress),len(x.entries))for x in p.DIRECTORY_ENTRY_BASERELOC])
 print('---')
