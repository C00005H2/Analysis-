import struct
# string resource
data=open('/tmp/test2_resources/type_6_name_1_lang_1049.bin','rb').read();p=0
print('RT_STRING block=1, language=0x419')
for i in range(16):
 n=struct.unpack_from('<H',data,p)[0];p+=2;s=data[p:p+n*2].decode('utf-16le');p+=n*2;print(i,repr(s))
# dialog parser
classes={0x80:'BUTTON',0x81:'EDIT',0x82:'STATIC',0x83:'LISTBOX',0x84:'SCROLLBAR',0x85:'COMBOBOX'}
def align4(p):return (p+3)&~3
def rstr(d,p):
 a=struct.unpack_from('<H',d,p)[0];p+=2
 if a==0:return '',p
 if a==0xffff:
  x=struct.unpack_from('<H',d,p)[0];return '#'+str(x),p+2
 chars=[a]
 while 1:
  x=struct.unpack_from('<H',d,p)[0];p+=2
  if not x:break
  chars.append(x)
 return ''.join(map(chr,chars)),p
for n in range(1,5):
 d=open(f'/tmp/test2_resources/type_5_name_{n}_lang_1033.bin','rb').read();p=0
 ver,sig,helpid,ex,style,citems,x,y,cx,cy=struct.unpack_from('<HHIIIHhhhh',d,p);p=26
 menu,p=rstr(d,p);cls,p=rstr(d,p);title,p=rstr(d,p)
 pt=wt=italic=charset=None;font=''
 if style&0x40: # DS_SETFONT
  pt,wt=struct.unpack_from('<HH',d,p);italic=d[p+4];charset=d[p+5];p+=6;font,p=rstr(d,p)
 print('\nDIALOG',n,'ver',ver,'style',hex(style),'items',citems,'rect',(x,y,cx,cy),'menu',menu,'class',cls,'title',title,'font',(pt,wt,italic,charset,font))
 for i in range(citems):
  p=align4(p);helpid,ex,st,x,y,cx,cy,id=struct.unpack_from('<IIIhhhhI',d,p);p+=24;cls,p=rstr(d,p);tit,p=rstr(d,p);extra=struct.unpack_from('<H',d,p)[0];p+=2+extra
  print(' ',i,'id',id,'rect',(x,y,cx,cy),'class',classes.get(int(cls[1:]) if cls.startswith('#') else -1,cls),'title',tit,'style',hex(st),'ex',hex(ex),'help',hex(helpid),'extra',extra)
