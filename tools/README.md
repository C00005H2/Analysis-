# Dynamic-analysis environment (Sogen + GDB-remote client)

Set up for dynamic analysis of the crackmes.one challenge
*"exxtruder — VM Crackme Challenge: 1. Moderate VM"* (x86-64, Windows, CRC32 + code
virtualization).

## What is installed

| Component | Location | Notes |
|---|---|---|
| Sogen source (`momo5502/sogen`, main) | `~/tools/sogen-src` | submodules included |
| Sogen `analyzer` binary + backends | `~/tools/sogen/bin/` | unicorn + kvm backends |
| Sogen Linux emulation root | `~/tools/linux-root/root` | from `momo5502/sogen-linux-files` |
| Python venv (cmake, ninja, capstone, pefile) | `~/.venv` | pip-only, no apt in this sandbox |
| GDB-remote debugger client | `tools/rsp_debugger.py` | this repo |

Rebuild from scratch any time with `tools/build_sogen.sh`.

### Build quirks that had to be worked around (Debian 12, no apt, 2 cores)

1. `cmake`/`ninja` are not installed system-wide → installed from PyPI into `~/.venv`.
2. `deps/unicorn`'s bundled qemu `configure` aborts with *"pkg-config binary not found"*.
   A stub `~/bin/pkg-config` that always exits 1 is enough; without it `config-host.h`
   is generated empty and every qemu TU fails with `PROT_READ undeclared`.
3. GCC 12 emits two false-positive `-Wrestrict` / `-Wstringop-overflow` diagnostics in
   `std::string` inlining; Sogen builds with `-Werror`, so `cmake/utils.cmake` is patched
   to drop `-Werror`.
4. Rust, SDL3, LTO and reflection are turned off (`-DSOGEN_ENABLE_*=OFF`) — not needed
   for CLI emulation and they cost build time/RAM.
5. `src/linux-analyzer/main.cpp` passes `network::address{"127.0.0.1:28960", AF_INET}`,
   which goes through `resolve()` with the port still attached and dies with
   *"Unable to resolve hostname"*. Patched locally to `address{"127.0.0.1", 28960}`
   (upstream bug; the Windows analyzer's `--bind`/`--port` path is unaffected).

## Usage

### Windows sample (the crackme)

```bash
# traced run, no debugger
TRACE=1 tools/debug_crackme.sh samples/crackme.exe

# debug run: Sogen waits for a GDB-remote client on port 28960
tools/debug_crackme.sh samples/crackme.exe
# ... in a second shell:
~/.venv/bin/python tools/rsp_debugger.py --port 28960
```

`tools/debug_crackme.sh` expects a Windows **emulation root** in `~/tools/sogen/root`
(`root/filesys/c/windows/...` + `root/registry/*`). It is normally downloaded from
<https://sogen.dev/root.zip>; that host is **not reachable from this sandbox**
(only github.com / pypi.org are allowed), so the zip has to be supplied manually.

### Validating the toolchain without the Windows root

A statically linked Linux binary needs no root at all:

```bash
EMULATOR_LINUX=1 ~/tools/sogen/bin/analyzer --root ~/tools/linux-root/root ~/tools/demo/check
EMULATOR_LINUX=1 ~/tools/sogen/bin/analyzer -d --root ~/tools/linux-root/root ~/tools/demo/check
~/.venv/bin/python tools/rsp_debugger.py            # regs / disasm / breakpoints all verified
```

### Debugger commands

```
r                 registers + disassembly at rip      x <addr> [n]   hexdump
u <addr> [n]      disassemble n instructions          w <addr> <hex> write memory
b/d/bl <addr>     breakpoint set / delete / list      c              continue
s [n]             single-step n times                 trace <n>      step and print each insn
set <reg> <val>   write a register                    str/wstr <a>   read ASCII / UTF-16 string
q                 detach
```

Addresses accept hex (`0x401560`) and register expressions (`$rsp+0x20`).
Scripted runs: `rsp_debugger.py --script cmds.txt --batch`.

Note: Sogen's stub serves a single client and exits when it disconnects — restart the
analyzer for each debugging session.

## Suggested first session on the crackme

```
b <address of the VM dispatch switch>
c
r                      # VM context pointer is usually in rbx/rsi/rdi here
x $rsi 0x80            # dump the virtual register file
trace 200              # watch the handler dispatch sequence
```
The challenge is a VM interpreter with a CRC32-flavoured hash used as a decoy; the
intended solution is to reconstruct the virtual program and find the logic flaw in the
serial check, not to invert the hash (per the author's own comments on crackmes.one).
Patching is not allowed by the challenge rules.
