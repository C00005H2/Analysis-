import sys, os, json, hashlib, math, collections, struct
sys.path.insert(0,'/tmp/retools')
import pefile
p='Test2.exe'
pe=pefile.PE(p, fast_load=False)
b=open(p,'rb').read()
print('PE_WARNINGS',pe.get_warnings())
print('HEADER')
print('Machine',hex(pe.FILE_HEADER.Machine),'sections',pe.FILE_HEADER.NumberOfSections,'timestamp',pe.FILE_HEADER.TimeDateStamp, 'chars',hex(pe.FILE_HEADER.Characteristics))
print('Magic',hex(pe.OPTIONAL_HEADER.Magic),'entry RVA',hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),'entry VA',hex(pe.OPTIONAL_HEADER.ImageBase+pe.OPTIONAL_HEADER.AddressOfEntryPoint),'base',hex(pe.OPTIONAL_HEADER.ImageBase),'checksum',hex(pe.OPTIONAL_HEADER.CheckSum),'subsystem',pe.OPTIONAL_HEADER.Subsystem,'dllchars',hex(pe.OPTIONAL_HEADER.DllCharacteristics))
print('Sections:')
for s in pe.sections:
 d=s.get_data()
 ent=-sum((x/len(d))*math.log2(x/len(d)) for x in collections.Counter(d).values()) if d else 0
 print('%-10s RVA=%#010x VA=%#010x VSize=%#010x RawOff=%#010x RawSize=%#010x Chars=%#010x Entropy=%.5f MD5=%s' % (s.Name.rstrip(b'\0').decode('latin1'),s.VirtualAddress,pe.OPTIONAL_HEADER.ImageBase+s.VirtualAddress,s.Misc_VirtualSize,s.PointerToRawData,s.SizeOfRawData,s.Characteristics,ent,hashlib.md5(d).hexdigest()))
print('Directories:')
for i,d in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY): print(i,d.name,hex(d.VirtualAddress),hex(d.Size))
print('Imports:')
if hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):
 for im in pe.DIRECTORY_ENTRY_IMPORT:
  print(im.dll, 'desc',hex(im.struct.OriginalFirstThunk),hex(im.struct.FirstThunk))
  for x in im.imports: print(' ',hex(x.address),x.ordinal,x.name)
print('Delay imports')
if hasattr(pe,'DIRECTORY_ENTRY_DELAY_IMPORT'):
 for im in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
  print(im.dll, 'attrs',hex(im.struct.grAttrs),'nameRVA',hex(im.struct.szName),'IAT',hex(im.struct.pIAT))
  for x in im.imports: print(' ',hex(x.address),x.ordinal,x.name)
print('Exports:')
if hasattr(pe,'DIRECTORY_ENTRY_EXPORT'):
 print('DLL',pe.DIRECTORY_ENTRY_EXPORT.name,'base',pe.DIRECTORY_ENTRY_EXPORT.struct.Base)
 for s in pe.DIRECTORY_ENTRY_EXPORT.symbols: print(hex(s.address),s.ordinal,s.name,s.forwarder)
print('TLS')
if hasattr(pe,'DIRECTORY_ENTRY_TLS'):
 t=pe.DIRECTORY_ENTRY_TLS.struct
 print('StartRaw',hex(t.StartAddressOfRawData),'EndRaw',hex(t.EndAddressOfRawData),'Index',hex(t.AddressOfIndex),'Callbacks',hex(t.AddressOfCallBacks),'ZeroFill',hex(t.SizeOfZeroFill),'Chars',hex(t.Characteristics))
 try:
  print('callbacks',pe.DIRECTORY_ENTRY_TLS.callbacks)
 except Exception as e: print('callback parse',repr(e))
print('Resources:')
def rid(x):
 return x.name.string.decode('utf-8','replace') if x.name is not None else x.id
if hasattr(pe,'DIRECTORY_ENTRY_RESOURCE'):
 for a in pe.DIRECTORY_ENTRY_RESOURCE.entries:
  for b2 in a.directory.entries:
   for c in b2.directory.entries:
    ds=c.data.struct
    dat=pe.get_data(ds.OffsetToData,ds.Size)
    ent=-sum((x/len(dat))*math.log2(x/len(dat)) for x in collections.Counter(dat).values()) if dat else 0
    print('type=%r name=%r lang=%r rva=%#x size=%#x codepage=%d entropy=%.5f md5=%s first=%s' % (rid(a),rid(b2),rid(c),ds.OffsetToData,ds.Size,ds.CodePage,ent,hashlib.md5(dat).hexdigest(),dat[:32].hex()))
print('Debug')
if hasattr(pe,'DIRECTORY_ENTRY_DEBUG'):
 for d in pe.DIRECTORY_ENTRY_DEBUG:
  print(d.struct.dump())
print('Load config')
if hasattr(pe,'DIRECTORY_ENTRY_LOAD_CONFIG'):
 print(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.dump())
print('Reloc blocks')
if hasattr(pe,'DIRECTORY_ENTRY_BASERELOC'):
 for r in pe.DIRECTORY_ENTRY_BASERELOC: print(hex(r.struct.VirtualAddress),hex(r.struct.SizeOfBlock),len(r.entries), [(hex(x.rva),x.type) for x in r.entries])
# Find security cert raw
sec=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
print('SecurityRaw',hex(sec.VirtualAddress),hex(sec.Size), 'bytes',b[sec.VirtualAddress:sec.VirtualAddress+16].hex())
