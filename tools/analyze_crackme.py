#!/usr/bin/env python3
"""Run a PE under Sogen and collect a deterministic execution trace.

This is intentionally observational: it does not patch the guest or alter its
memory/registers.  The trace is useful for finding the VM entry point and the
verification path before doing a manual/debugger-assisted analysis.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys

try:
    import sogen
except ImportError as exc:
    raise SystemExit("Sogen is not installed; run tools/setup_sogen.sh first") from exc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", type=Path)
    ap.add_argument("--root", type=Path, default=Path("tools/sogen/root"))
    ap.add_argument("--trace", type=Path, default=Path("sogen-trace.jsonl"))
    ap.add_argument("--max-events", type=int, default=200000)
    args = ap.parse_args()
    target = args.target.resolve()
    if not target.is_file():
        ap.error(f"target does not exist: {target}")
    if target.stat().st_size > 100 * 1024 * 1024:
        ap.error("refusing unexpectedly large target")

    events = 0
    out = args.trace.open("w", encoding="utf-8")
    def emit(kind: str, **data):
        nonlocal events
        if events >= args.max_events:
            return
        events += 1
        out.write(json.dumps({"n": events, "kind": kind, **data}, sort_keys=True) + "\n")

    # Sogen uses guest paths, while path_mappings bind them to host files.
    guest = "c:/challenge.exe"
    app = sogen.windows.create_application(
        guest, emulation_root=str(args.root),
        path_mappings={guest: target},
        backend=sogen.Backend.unicorn,
    )

    def on_module(module):
        emit("module", name=module.name, base=hex(module.image_base),
             entry=hex(module.entry_point))
        # Only hook executable entry points; no rewriting is performed.
        if module.name.lower().endswith("challenge.exe"):
            app.hooks.memory_execution_at(module.entry_point,
                lambda address: emit("entry", address=hex(address)))

    app.callbacks.on_module_load = on_module
    # The callback is deliberately a passive observer.  Depending on the
    # installed Sogen build its callback argument is either an address or a
    # small event object, so keep serialization conservative.
    app.hooks.memory_execution(lambda address: emit("execute", address=hex(address) if isinstance(address, int) else repr(address)))
    try:
        app.start()
    finally:
        out.close()
    print(f"exit_status={app.process.exit_status} events={events} trace={args.trace}")
    print(f"sha256={hashlib.sha256(target.read_bytes()).hexdigest()}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
