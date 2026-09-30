import struct
data = open('/home/user/Analysis-/Test2.exe','rb').read()
off = 0x1F55400  # .data raw
blob = data[off:off+0x400]
def hexdump(b, base):
    for i in range(0, len(b), 16):
        row = b[i:i+16]
        hexs = ' '.join(f'{x:02x}' for x in row)
        asc = ''.join(chr(x) if 32<=x<127 else '.' for x in row)
        print(f"  {base+i:#010x}  {hexs:<48}  {asc}")
print("=== .data (VA 0x4E7C000) first 0x300 bytes ===")
hexdump(blob[:0x300], 0x4E7C000)
