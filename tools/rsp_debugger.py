#!/usr/bin/env python3
"""
Minimal scriptable GDB-remote (RSP) debugger client for Sogen's GDB stub.

Sogen is started with:   analyzer -d --bind 0.0.0.0 --port 28960 -e <root> <sample>
then:                    python3 tools/rsp_debugger.py --port 28960

Why this instead of gdb?  This sandbox has no system gdb and no apt access, so
this client speaks the GDB remote serial protocol directly.  It supports the
subset needed for dynamic analysis: registers, memory read/write, software
breakpoints, single-step, continue, and capstone-backed disassembly.

Interactive commands (also usable from --script files, one command per line):
  r / regs                 show general purpose registers
  x <addr> [n]             hexdump n bytes (default 64) at addr (hex or $rax+8 style)
  w <addr> <hexbytes>      write bytes
  u <addr> [n]             disassemble n instructions (default 16)
  b <addr>                 set breakpoint       d <addr>  delete breakpoint
  bl                       list breakpoints
  c                        continue             s [n]     step n instructions
  set <reg> <value>        set a register
  str <addr> [n]           read ASCII string    wstr <addr> [n]  read UTF-16 string
  trace <n>                single-step n times, printing each instruction
  q                        detach and quit
"""

import argparse
import re
import socket
import sys

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64

    _MD = Cs(CS_ARCH_X86, CS_MODE_64)
except Exception:  # pragma: no cover
    _MD = None

# x86-64 register order used by GDB's standard 'g' packet layout.
REGS64 = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip",
]
REG32 = ["eflags", "cs", "ss", "ds", "es", "fs", "gs"]


class RSPError(Exception):
    pass


class RSPClient:
    def __init__(self, host="127.0.0.1", port=28960, timeout=30.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""
        self.breakpoints = set()
        self.no_ack = False
        self._handshake()

    # ---------------- transport ----------------
    def _recv(self, n=4096):
        data = self.sock.recv(n)
        if not data:
            raise RSPError("connection closed by stub")
        return data

    def _send_raw(self, payload: bytes):
        csum = sum(payload) & 0xFF
        self.sock.sendall(b"$" + payload + b"#" + b"%02x" % csum)

    def cmd(self, payload, expect_reply=True):
        if isinstance(payload, str):
            payload = payload.encode()
        self._send_raw(payload)
        if not self.no_ack:
            self._read_ack()
        if not expect_reply:
            return b""
        return self._read_packet()

    def _read_ack(self):
        while not self.buf:
            self.buf += self._recv()
        c, self.buf = self.buf[:1], self.buf[1:]
        if c == b"-":
            raise RSPError("stub NAKed the packet")

    def _read_packet(self):
        while True:
            start = self.buf.find(b"$")
            end = self.buf.find(b"#", start + 1)
            if start >= 0 and end >= 0 and len(self.buf) >= end + 3:
                payload = self.buf[start + 1:end]
                self.buf = self.buf[end + 3:]
                if not self.no_ack:
                    self.sock.sendall(b"+")
                return self._decode_rle(self._unescape(payload))
            self.buf += self._recv()

    @staticmethod
    def _unescape(data: bytes) -> bytes:
        out = bytearray()
        i = 0
        while i < len(data):
            if data[i] == 0x7D:  # '}' escape
                out.append(data[i + 1] ^ 0x20)
                i += 2
            else:
                out.append(data[i])
                i += 1
        return bytes(out)

    @staticmethod
    def _decode_rle(data: bytes) -> bytes:
        """Expand GDB run-length encoding: 'X*<c>' == X repeated (c - 29) extra times."""
        out = bytearray()
        i = 0
        while i < len(data):
            if data[i] == 0x2A and out:  # '*'
                repeat = data[i + 1] - 29
                out.extend(out[-1:] * repeat)
                i += 2
            else:
                out.append(data[i])
                i += 1
        return bytes(out)

    def _handshake(self):
        self.cmd("qSupported:multiprocess+;swbreak+;hwbreak+;xmlRegisters=i386")
        try:
            if self.cmd("QStartNoAckMode") == b"OK":
                self.no_ack = True
        except RSPError:
            pass

    # ---------------- state ----------------
    def regs(self):
        raw = bytes.fromhex(self.cmd("g").decode())
        out = {}
        off = 0
        for name in REGS64:
            out[name] = int.from_bytes(raw[off:off + 8], "little")
            off += 8
        for name in REG32:
            if off + 4 <= len(raw):
                out[name] = int.from_bytes(raw[off:off + 4], "little")
                off += 4
        return out

    def set_reg(self, name, value):
        name = name.lower()
        if name in REGS64:
            idx = REGS64.index(name)
            payload = value.to_bytes(8, "little").hex()
        elif name in REG32:
            idx = len(REGS64) + REG32.index(name)
            payload = value.to_bytes(4, "little").hex()
        else:
            raise RSPError(f"unknown register {name}")
        return self.cmd(f"P{idx:x}={payload}")

    def read_mem(self, addr, size):
        out = bytearray()
        while size:
            chunk = min(size, 1024)
            r = self.cmd(f"m{addr + len(out):x},{chunk:x}")
            if r.startswith(b"E") and len(r) <= 3:
                raise RSPError(f"memory read error at {addr + len(out):#x}: {r.decode()}")
            out += bytes.fromhex(r.decode())
            size -= chunk
        return bytes(out)

    def write_mem(self, addr, data: bytes):
        return self.cmd(f"M{addr:x},{len(data):x}:{data.hex()}")

    def add_bp(self, addr, kind=0, size=1):
        r = self.cmd(f"Z{kind},{addr:x},{size}")
        if r == b"OK":
            self.breakpoints.add(addr)
        return r

    def del_bp(self, addr, kind=0, size=1):
        r = self.cmd(f"z{kind},{addr:x},{size}")
        self.breakpoints.discard(addr)
        return r

    def cont(self):
        return self.cmd("c")

    def step(self):
        return self.cmd("s")

    def detach(self):
        try:
            self.cmd("D")
        except Exception:
            pass
        self.sock.close()


# ---------------- helpers ----------------
def hexdump(data, base=0):
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + i:016x}  {hexs}  |{text}|")
    return "\n".join(lines)


def disasm(data, addr, count):
    if _MD is None:
        return "capstone not installed"
    out = []
    for ins in _MD.disasm(data, addr):
        out.append(f"{ins.address:016x}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}")
        if len(out) >= count:
            break
    return "\n".join(out)


def parse_addr(client, token):
    token = token.strip()
    regs = None
    def repl(m):
        nonlocal regs
        if regs is None:
            regs = client.regs()
        return str(regs[m.group(1).lower()])
    expr = re.sub(r"\$(\w+)", repl, token)
    expr = re.sub(r"\b0x[0-9a-fA-F]+\b", lambda m: str(int(m.group(0), 16)), expr)
    try:
        return int(eval(expr, {"__builtins__": {}}, {}))  # noqa: S307 - local tooling
    except Exception:
        return int(token, 16)


def show_regs(c):
    r = c.regs()
    order = REGS64 + [x for x in REG32 if x in r]
    for i, name in enumerate(order):
        print(f"{name:>6} = {r[name]:#018x}", end="\n" if i % 4 == 3 else "   ")
    print()
    try:
        code = c.read_mem(r["rip"], 32)
        print("\n-- at rip --")
        print(disasm(code, r["rip"], 4))
    except RSPError as e:
        print(f"(rip unreadable: {e})")


def handle(c, line):
    parts = line.split()
    if not parts:
        return True
    cmd, args = parts[0], parts[1:]
    if cmd in ("q", "quit", "exit"):
        c.detach()
        return False
    if cmd in ("r", "regs"):
        show_regs(c)
    elif cmd == "x":
        addr = parse_addr(c, args[0])
        n = int(args[1], 0) if len(args) > 1 else 64
        print(hexdump(c.read_mem(addr, n), addr))
    elif cmd == "w":
        addr = parse_addr(c, args[0])
        print(c.write_mem(addr, bytes.fromhex(args[1])).decode())
    elif cmd == "u":
        addr = parse_addr(c, args[0])
        n = int(args[1], 0) if len(args) > 1 else 16
        print(disasm(c.read_mem(addr, n * 15), addr, n))
    elif cmd == "b":
        print(c.add_bp(parse_addr(c, args[0])).decode())
    elif cmd == "d":
        print(c.del_bp(parse_addr(c, args[0])).decode())
    elif cmd == "bl":
        for a in sorted(c.breakpoints):
            print(f"{a:#018x}")
    elif cmd == "c":
        print("stop:", c.cont().decode())
        show_regs(c)
    elif cmd == "s":
        n = int(args[0], 0) if args else 1
        for _ in range(n):
            c.step()
        show_regs(c)
    elif cmd == "trace":
        n = int(args[0], 0)
        for _ in range(n):
            rip = c.regs()["rip"]
            try:
                print(disasm(c.read_mem(rip, 16), rip, 1))
            except RSPError:
                print(f"{rip:016x}  <unreadable>")
            c.step()
    elif cmd == "set":
        print(c.set_reg(args[0], parse_addr(c, args[1])).decode())
    elif cmd == "str":
        addr = parse_addr(c, args[0])
        n = int(args[1], 0) if len(args) > 1 else 128
        data = c.read_mem(addr, n).split(b"\x00")[0]
        print(data.decode("latin1"))
    elif cmd == "wstr":
        addr = parse_addr(c, args[0])
        n = int(args[1], 0) if len(args) > 1 else 256
        data = c.read_mem(addr, n)
        print(data.decode("utf-16-le", "replace").split("\x00")[0])
    else:
        print(f"unknown command: {cmd}")
    return True


def main():
    ap = argparse.ArgumentParser(description="GDB-remote client for Sogen")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=28960)
    ap.add_argument("--script", help="file with commands to run before the prompt")
    ap.add_argument("--batch", action="store_true", help="exit after --script")
    args = ap.parse_args()

    c = RSPClient(args.host, args.port)
    print(f"connected to sogen gdb stub at {args.host}:{args.port}")
    show_regs(c)

    if args.script:
        with open(args.script) as f:
            for line in f:
                line = line.split("#")[0].strip()
                if not line:
                    continue
                print(f"\n(sogen) {line}")
                try:
                    if not handle(c, line):
                        return
                except Exception as e:
                    print(f"error: {e}", file=sys.stderr)
        if args.batch:
            c.detach()
            return

    while True:
        try:
            line = input("(sogen) ").strip()
        except (EOFError, KeyboardInterrupt):
            c.detach()
            print()
            return
        try:
            if not handle(c, line):
                return
        except Exception as e:  # keep the session alive on user errors
            print(f"error: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
