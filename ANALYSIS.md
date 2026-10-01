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

## Provisioning status

CMake 4.4.3 and Ninja 1.13.2 were downloaded as Python wheels into the local
`.venv-tools` environment. GCC/G++ and GNU make are already available in the
container. Python build tooling (`pip`, `setuptools`, `wheel`, `nanobind`, and
`libclang`) is also provisioned there.

The Sogen build reached native compilation, but the container does not have the
system Python development headers. I downloaded and configured CPython 3.11
sources as a temporary header workaround; the vendored Unicorn build then hit an
upstream portability compile error. The Sogen root URL is reachable by DNS but
TLS egress to `sogen.dev` is blocked in this sandbox, so `root.zip` could not be
downloaded. `tools/setup_sogen.sh` now performs all of these downloads when run
in an environment with working TLS and Python development headers.
