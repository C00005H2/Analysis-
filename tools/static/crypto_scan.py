import re
k = open('/tmp/test2_winlice_unpacked.bin','rb').read()
print(f"kernel size {len(k):#x}")
sigs = {
 'AES S-box (0x63,0x7c,0x77,0x7b...)': bytes([0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5]),
 'AES inverse S-box (0x52,0x09,0x6a...)': bytes([0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38]),
 'AES T-table0 (0xc66363a5...)': bytes.fromhex('a563c6c6847b7bf2'),
 'SHA-256 K[0..] (0x428a2f98...)': bytes.fromhex('982f8a42'),
 'SHA-256 K mid (0xd192e819)': bytes.fromhex('19e892d1'),
 'SHA-1 K (0x5A827999)': bytes.fromhex('9979825a'),
 'SHA-1 K (0x9DC84779)': bytes.fromhex('7947c89d'),
 'MD5 T (0xd76aa478)': bytes.fromhex('78a46ad7'),
 'MD5 sin constant (0xffeff47d)': bytes.fromhex('7df4efff'),
 'CRC32 poly table (0xEDB88320...)': bytes.fromhex('2083b8ed'),
 'CRC32 reflected poly (0x82F63B78)': bytes.fromhex('783bf682'),
 'TEA/XTEA delta 0x9E3779B9': bytes.fromhex('b979379e'),
 'Blowfish P-array (0x243F6A88)': bytes.fromhex('886a3f24'),
 'Twofish MDS (0x01DAEDB5?)': bytes.fromhex('a5fd949b'),
 'ChaCha20 "expand 32-byte k"': b'expand 32-byte k',
 'RC6/RC5 constants (0xB7E15163)': bytes.fromhex('6351e1b7'),
 'Serpent S-box?': bytes.fromhex('0293f6a2'),
 'MD2 S-box (0x29,0x2E,0x43...)': bytes([0x29,0x2E,0x43,0xC9,0xA2,0xD8,0x7C,0x01]),
 'MD4 K (0x5A827999)': bytes.fromhex('9979825a'),
 'Whirlpool S-box (0x18,0x23...)': bytes([0x18,0x23,0xc6,0xe8]),
 'base64 alphabet std': b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
 'base64 alphabet alt (./0-9A-Za-z)': b'./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
 'CRC64 ECMA (0xC96C5795D7870F42)': bytes.fromhex('420f87d795576cc9'),
 'UTF-16 "CryptAcquireContext"': 'CryptAcquireContext'.encode('utf-16le'),
 'UTF-16 "CryptImportKey"': 'CryptImportKey'.encode('utf-16le'),
 'ASCII "Rijndael"': b'Rijndael',
 'ASCII "AES"': b'AES-',
 'ASCII "SHA"': b'SHA-',
 'DES SP1?': bytes([0x0e,0x04,0x0d,0x01,0x02,0x0f,0x0b,0x08]),
}
for name, pat in sigs.items():
    hits = [m.start() for m in re.finditer(re.escape(pat), k)]
    if hits:
        show = [hex(h) for h in hits[:6]]
        print(f"HIT  {name}: {len(hits)} at unpacked+{show} (VA {hex(0x1CA7000+hits[0])} first)")
    else:
        print(f" --  {name}: none")
