import sys, os
sys.path.insert(0,'/tmp/retools'); import pefile
pe=pefile.PE('Test2.exe')
def rid(x): return x.name.string.decode('utf-8','replace') if x.name else str(x.id)
os.makedirs('/tmp/test2_resources',exist_ok=True)
for a in pe.DIRECTORY_ENTRY_RESOURCE.entries:
 for b in a.directory.entries:
  for c in b.directory.entries:
   s=c.data.struct; dat=pe.get_data(s.OffsetToData,s.Size); fn='/tmp/test2_resources/type_%s_name_%s_lang_%s.bin'%(rid(a),rid(b),rid(c));open(fn,'wb').write(dat);print(fn)
