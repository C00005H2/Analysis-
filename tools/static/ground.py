import pefile
pe = pefile.PE('/home/user/Analysis-/Test2.exe', fast_load=True)
print(f"ImageBase {pe.OPTIONAL_HEADER.ImageBase:#x}  SizeOfImage {pe.OPTIONAL_HEADER.SizeOfImage:#x}")
print(f"{'#':>2} {'name':10} {'VirtAddr':>10} {'VirtSize':>10} {'RawAddr':>10} {'RawSize':>10} {'Char':>12}")
for i,s in enumerate(pe.sections):
    nm = s.Name.decode(errors='replace').rstrip('\x00')
    print(f"{i:>2} {nm:10} {s.VirtualAddress:#010x} {s.Misc_VirtualSize:#010x} {s.PointerToRawData:#010x} {s.SizeOfRawData:#010x} {s.Characteristics:#012x}")
last = max(s.PointerToRawData + s.SizeOfRawData for s in pe.sections)
import os
print(f"\nfile size {os.path.getsize('/home/user/Analysis-/Test2.exe'):#x}, last section raw end {last:#x}, overlay {os.path.getsize('/home/user/Analysis-/Test2.exe')-last:#x} bytes")
d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
print(f"cert dir: rva(file offset) {d.VirtualAddress:#x} size {d.Size:#x} -> cert spans {d.VirtualAddress:#x}..{d.VirtualAddress+d.Size:#x}")
