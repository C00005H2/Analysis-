#!/usr/bin/env python3
"""Load and instrument a Windows PE with Qiling.

The Windows rootfs must contain DLLs and registry hives collected from a
licensed Windows installation; Qiling intentionally does not redistribute them.
"""
from pathlib import Path
import argparse

from qiling import Qiling
from qiling.const import QL_VERBOSE

ROOT = Path(__file__).resolve().parent

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary", nargs="?", default="crackmevm1.exe")
    ap.add_argument("--count", type=int, default=100_000)
    args = ap.parse_args()
    binary = Path(args.binary).resolve()
    rootfs = ROOT / "qiling-rootfs" / "x8664_windows"
    if not binary.exists():
        raise SystemExit(f"binary not found: {binary}")
    if not rootfs.exists():
        raise SystemExit("missing qiling-rootfs; run ./setup_qiling.sh")
    # Qiling's Windows path mapper requires the emulated image to live under rootfs.
    staged = rootfs / "bin" / binary.name
    staged.parent.mkdir(exist_ok=True)
    if staged.resolve() != binary:
        staged.write_bytes(binary.read_bytes())
    print(f"Loading {binary.name} with Qiling (x8664 Windows rootfs)...")
    ql = Qiling([str(staged)], str(rootfs), verbose=QL_VERBOSE.DISABLED)
    executed = 0
    def trace(ql, address, size):
        nonlocal executed
        executed += 1
    ql.hook_code(trace)
    ql.run(count=args.count)
    print(f"OK: emulated {executed} instructions; final PC=0x{ql.arch.regs.arch_pc:x}")

if __name__ == "__main__":
    main()
