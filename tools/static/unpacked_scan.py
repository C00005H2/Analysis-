import struct,hashlib,math,collections,re
b=open('/tmp/test2_winlice_unpacked.bin','rb').read();print('len',hex(len(b)))
# real PE validation in unpacked content
hits=[];pos=0
while 1:
 pos=b.find(b'MZ',pos)
 if pos<0:break
 if pos+0x40<=len(b):
  e=struct.unpack_from('<I',b,pos+0x3c)[0]
  if 0x40<=e<0x100000 and pos+e+24<=len(b) and b[pos+e:pos+e+4]==b'PE\0\0':
   ma,n,ts,ps,ns,op,ch=struct.unpack_from('<HHIIIHH',b,pos+e+4)
   if n<=100 and op in [0xe0,0xf0] and pos+e+24+op+40*n<=len(b):hits.append((pos,e,ma,n,ts,op,ch))
 pos+=2
print('validated PEs',[(hex(p),hex(e),hex(m),n,hex(ts),hex(ch)) for p,e,m,n,ts,op,ch in hits])
for pos,e,ma,n,ts,op,ch in hits:
 print('\nPE',hex(pos),'header',hex(e)); opt=pos+e+24;magic=struct.unpack_from('<H',b,opt)[0]; entry=struct.unpack_from('<I',b,opt+16)[0];base=struct.unpack_from('<I',b,opt+28)[0] if magic==0x10b else struct.unpack_from('<Q',b,opt+24)[0];print('magic',hex(magic),'entry',hex(entry),'base',hex(base),'nsect',n)
 for i in range(n):
  q=opt+op+i*40;name=b[q:q+8].rstrip(b'\0');vs,va,rs,rp=struct.unpack_from('<IIII',b,q+8);chars=struct.unpack_from('<I',b,q+36)[0];print(i,name,hex(va),hex(vs),hex(rp),hex(rs),hex(chars))
# String hits legitimate sized
for pat in [rb'(?i)https?://[^\x00\s"<>]{4,}', rb'(?i)[a-z0-9_.-]+\.(?:dll|exe|sys|ini|cfg|json|xml)',rb'(?i)(?:cmd\.exe|powershell|rundll32|regsvr32|schtasks|wininet|winhttp|urlmon|ws2_32|advapi32|kernel32|ntdll|createfile|writefile|virtualalloc|virtualprotect|createremotethread|isdebuggerpresent|outputdebugstring|checkremotedebuggerpresent|ntqueryinformationprocess)']:
 print('\nPAT',pat)
 for x in list(re.finditer(pat,b))[:500]:print(hex(x.start()),x.group().decode('latin1','replace'))
