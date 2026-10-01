# VM crackme analysis workspace

The supplied PE candidates are retained unchanged. Their SHA-256 values are:

| file | SHA-256 |
|---|---|
| `crackmevm1.exe` | `4063b264e7b7283aae41e3c403157207bcfbaf4998fa4f21b15c0f92de0b1986` |
| `test.exe` | `b16e4004dbc2f0e96b708cd908d4b6336af15e2f504fb93a1c26188b9d8af581` |
| `Test2.exe` | `1fe62f8ea1879b34d5cc711a8999e878e3394896dbd761d8bd95b8d8c51f0e27` |

## What is set up

- Upstream `momo5502/sogen` source is checked out at `tools/sogen` with its
  submodules initialized.
- `tools/setup_sogen.sh` creates a local virtual environment, installs the
  upstream Python bindings, and downloads Sogen's Windows emulation root.
- `tools/analyze_crackme.py` runs a selected PE in Sogen's Unicorn backend and
  writes an instruction-execution/module trace. It is observational only: it
  does not patch guest code or memory.

Run:

```bash
./tools/setup_sogen.sh
.venv-sogen/bin/python tools/analyze_crackme.py crackmevm1.exe
```

The trace is JSONL and can be filtered without changing the guest:

```bash
grep '"kind": "module"\|"kind": "entry"' sogen-trace.jsonl
```

## Debugger workflow

Sogen's debugger is emulator-level (outside the guest), so it avoids exposing a
native debugger to anti-debug checks. The upstream source also documents its
GDB protocol and browser debugger. For this challenge, first use the passive
trace to identify the VM dispatch loop, then set an emulator breakpoint in the
upstream Python API (`app.debug.set_breakpoint(address)` where available) or a
`memory_execution_at` hook. Record register and memory observations only; do
not rewrite instructions, return values, or input buffers.

## Current environment limitation

This container has no system CMake/compiler/debugger packages and its Debian apt
index cannot reach the mirror, so the native Sogen extension cannot be built in
this turn. The source and reproducible setup are present; running the setup
script on a host with CMake, Ninja, a C++ compiler, and network access completes
installation. The PE files are Windows x64/Win32 binaries and are not run with
Wine or native Linux tools here.
