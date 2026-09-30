# Analysis tools and artifacts

Supporting material for `analysis.md` (Test2.exe reverse-engineering report).

## `emu/` — Round 4: dynamic emulation (§29)

| File | Purpose |
|---|---|
| `emu1.py` | Unicorn x86-32 emulation harness. Maps the original image + the reconstructed `.winlice` kernel, builds fake Windows modules (kernel32/user32/advapi32/ntdll/shell32/shlwapi + minors) with synthetic export directories, implements ~50 API shims, and drives the WinLicense kernel with full instrumentation (instruction ring, API log, export-walk capture, page-dirty tracking). Requires: Unicorn 2.1.4 (x86-32), capstone, pefile, and the reconstructed kernel image at `/tmp/test2_winlice_unpacked.bin` (see analysis.md Appendix B, steps 1–3, for the reproduction recipe). |
| `wloracle.py` | Offline re-implementation-by-execution of the kernel's export-name hash: runs the real hash code path (0x307E4D5 → 0x2F8FC65) in a scratch Unicorn instance. `wl_hash(name) → uint32`. Validated 124/124 against runtime-captured pairs. Used to brute-force failed export walks (recovered `IsWow64Process2`, hash `0xF5198738`). |
| `probe.py`, `handlers.json` | VM-handler probe and the round-3 handler-classification data. |
| `names/` | Windows 7 export name lists (kernel32 1,352 / advapi32 805 / user32 822) used to build the fake modules. The resolver is case-sensitive; lowercase duplicates of every name are generated at build time. |
| `logs/` | Run outputs: `emu_hashrows.txt` (definitive export-resolution log: every hashed name, walk target hash, match verdict), `emu_thunkres.txt` (executed resolution thunks), `emu_result.json` (status + API census), `emu_oracle_data.json` (oracle validation pairs), `emu_walks.txt` / `emu_scan.txt` / `emu_mod_diag.json` (diagnostics), `emu_ring_tail.txt.gz` (instruction-ring tail from the deepest run). |

Notes / gotchas discovered while building these (also documented in §29 of the report):

* `emu_start(count=N)` returns normally on count exhaustion — completion must be verified via EIP, then emulation resumed from the current EIP.
* The name hash includes the terminating NUL (loop counter = `len(name)+1`).
* This Unicorn build needs a code hook at the hash-loop head that reads all six GPRs; without the forced read a lazy CPU-state-sync quirk silently yields wrong hashes.
* Buffer-writing API shims must actually write their buffers, or the kernel's backward string scans loop forever on the auto-mapped zero pages.

## `static/` — Rounds 1–3: static analysis scripts

The 40 scripts used for the offline unpacking and static passes (§§5–8, 27, 28):
`unpack_boot.py` (aPLib block unpacker), `vmsec*.py` (`.vm_sec` registry parsing/graphing),
`crypto_scan.py` / `crc_check.py` / `tea_sites.py` (crypto-constant inventory),
`sbox_scan.py` / `sbox_np.py` (S-box permutation scan), `handler_tax.py` (685-handler
taxonomy), `strings_scan.py` / `more_strings.py`, `analyze_pe.py`, and the rest.
Each is a standalone script operating on the reconstructed kernel image.
