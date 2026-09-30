#!/usr/bin/env python3
"""
Static triage for Test2.exe (Themida/WinLicense-protected PE32).
Reproduces the header / section / resource / import / export / Authenticode
findings documented in analysis.md.

    pip install pefile capstone
    python3 tools/triage.py Test2.exe
"""
import sys, hashlib, struct, datetime, re
import pefile

SEC_FLAGS = [(0x20,'CODE'),(0x40,'IDATA'),(0x80,'UDATA'),
             (0x20000000,'X'),(0x40000000,'R'),(0x80000000,'W')]

def flags(c):
    return '|'.join(n for b,n in SEC_FLAGS if c & b)

def main(path):
    raw = open(path,'rb').read()
    print("== hashes ==")
    for a in ('md5','sha1','sha256'):
        print("  %-7s %s" % (a, hashlib.new(a, raw).hexdigest()))
    print("  size    %d (0x%X)" % (len(raw), len(raw)))
    print("  DOS sig %r  (MZP => Borland/Embarcadero linker)" % raw[:3])

    pe = pefile.PE(path)
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    print("\n== PE ==")
    print("  machine        %04X" % fh.Machine)
    print("  sections       %d" % fh.NumberOfSections)
    print("  timestamp      0x%08X  %s UTC" % (fh.TimeDateStamp,
          datetime.datetime.utcfromtimestamp(fh.TimeDateStamp)))
    print("  characteristics 0x%04X" % fh.Characteristics)
    print("  linker         %d.%d" % (oh.MajorLinkerVersion, oh.MinorLinkerVersion))
    print("  ImageBase      0x%08X  EP RVA 0x%08X  SizeOfImage 0x%08X"
          % (oh.ImageBase, oh.AddressOfEntryPoint, oh.SizeOfImage))
    print("  subsystem      %d   DllCharacteristics 0x%04X" % (oh.Subsystem, oh.DllCharacteristics))

    print("\n== sections ==")
    print("  %-2s %-9s %-9s %-9s %-9s %-9s %-7s %s" %
          ('#','name','VA','VSize','RawPtr','RawSize','entropy','flags'))
    for i, s in enumerate(pe.sections):
        n = s.Name.rstrip(b'\x00').decode('latin1') or '(wiped)'
        print("  %-2d %-9s %08X  %08X  %08X  %08X  %6.3f  %s" %
              (i, n, s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData,
               s.SizeOfRawData, s.get_entropy(), flags(s.Characteristics)))

    print("\n== data directories ==")
    for d in oh.DATA_DIRECTORY:
        if d.VirtualAddress or d.Size:
            print("  %-34s VA=%08X Size=%08X" % (d.name, d.VirtualAddress, d.Size))

    print("\n== imports (protector DLL-preload set) ==")
    for e in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
        names = [(i.name.decode() if i.name else 'ord#%d' % i.ordinal) for i in e.imports]
        print("  %-16s %s" % (e.dll.decode(), ', '.join(names)))

    ed = getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None)
    if ed:
        print("\n== exports (copied from the original image) ==")
        print("  module name: %s" % pe.get_string_at_rva(ed.struct.Name).decode())
        for s in ed.symbols:
            print("   ord %d  rva %08X  %s" % (s.ordinal, s.address, s.name.decode()))

    print("\n== resources ==")
    for t in getattr(pe, 'DIRECTORY_ENTRY_RESOURCE', pefile.Structure).entries:
        tn = str(t.name) if t.name is not None else pefile.RESOURCE_TYPE.get(t.id, str(t.id))
        for n in t.directory.entries:
            rn = str(n.name) if n.name is not None else str(n.id)
            for l in n.directory.entries:
                print("  %-16s id=%-10s lang=%-3d size=%d" %
                      (tn, rn, l.data.lang, l.data.struct.Size))

    if hasattr(pe, 'FileInfo'):
        print("\n== version info ==")
        for fi in pe.FileInfo:
            for entry in fi:
                for st in getattr(entry, 'StringTable', []):
                    for k, v in st.entries.items():
                        print("  %-18s %s" % (k.decode(), v.decode(errors='replace')))

    # Authenticode digest
    sd = oh.DATA_DIRECTORY[4]
    if sd.VirtualAddress:
        e_lfanew = pe.DOS_HEADER.e_lfanew
        optoff = e_lfanew + 24
        ck = optoff + 64
        magic = struct.unpack_from('<H', raw, optoff)[0]
        dd = optoff + (96 if magic == 0x10b else 112)
        sdd = dd + 4 * 8
        h = hashlib.sha256()
        h.update(raw[:ck]); h.update(raw[ck+4:sdd]); h.update(raw[sdd+8:sd.VirtualAddress])
        print("\n== Authenticode ==")
        print("  computed SHA-256 PE digest: %s" % h.hexdigest())
        print("  (compare with the OCTET STRING in SpcIndirectDataContent:")
        print("   openssl asn1parse -inform DER -in sig.der -i | head -30 )")
        blob = raw[sd.VirtualAddress:sd.VirtualAddress + sd.Size]
        ln = struct.unpack_from('<I', blob, 0)[0]
        open('sig.der', 'wb').write(blob[8:ln])
        print("  wrote sig.der (%d bytes)" % (ln - 8))

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'Test2.exe')
