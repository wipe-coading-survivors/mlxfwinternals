#!/usr/bin/env python3
"""PHY-UC script table (ITOC 0x0a/0x0c) pseudo-disassembler (task-4b).

Section format (verified on CX-4 12.23/12.28, CX-4Lx 14.32.1900/1912,
CX-5 16.35.8008/4030):
  - 16-byte slots, 39200 bytes = 2450 slots (0x0a) / 160 slots (0x0c)
  - bytes [0..5] always zero (autocorrelation P=16; w0..w2 == 0 in all
    2450+160 slots)
  - payload = 5 BE16 words at +6: [op][a][b][c][d]
  - op families by byte: 0x60-0x7f write-like (b=block<<12|reg,
    c=register offset, d=value, a=flavor param), 0x50-0x57 read/poll-like,
    0x4000 delay-like (a=count), 0x2000 w/ (c=100..235, d=large/magic),
    0x8520 (b=0x1000, c=0x30..0x70), 0x0000 nop/separator.

Output: listing `IDX  raw16            asm` (IDX = slot index = offset/16).

Usage: python3 phyuc_dis.py FILE [--lo N] [--hi N] [--ops] [--json X]
  --ops    print op census instead of listing
Offline/static tool: no hardware access.
"""
import argparse
import collections
import json
import struct
import sys


def slots(data):
    if len(data) % 16:
        raise ValueError(f"size {len(data):#x} not multiple of 16")
    out = []
    for i in range(0, len(data), 16):
        out.append((i // 16,) + struct.unpack_from(">5H", data, i + 6))
    return out


def op_class(op):
    if op == 0:
        return "nop"
    if op == 0x2000:
        return "op2000"
    if op == 0x4000:
        return "delay"
    if op == 0x8520:
        return "op8520"
    hi = op >> 8
    if 0x50 <= hi <= 0x5f:
        return "read"
    if 0x60 <= hi <= 0x7f:
        return "write"
    return f"op{op >> 12:x}"


def dis(i, op, a, b, c, d):
    kind = op_class(op)
    if kind == "nop":
        return "nop"
    if kind == "delay":
        return f"delay #{a}"
    if kind == "write":
        return f"wr{op:04x} p={a:#04x} blk={b >> 12:#x} reg={b & 0xfff:#05x} " \
               f"addr={c:#06x} val={d:#06x}"
    if kind == "read":
        return f"rd{op:04x} p={a:#04x} blk={b >> 12:#x} reg={b & 0xfff:#05x} " \
               f"addr={c:#06x} val={d:#06x}"
    if kind == "op2000":
        return f"op2000 {c:#06x} -> {d:#06x}"
    if kind == "op8520":
        return f"op8520 p={a:#04x} {b:#06x} {c:#06x}"
    return f"{kind} {a:#x} {b:#x} {c:#x} {d:#x}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--lo", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--hi", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--ops", action="store_true")
    ap.add_argument("--json")
    args = ap.parse_args()
    data = open(args.file, "rb").read()
    S = slots(data)
    if args.ops:
        cen = collections.Counter(op_class(t[1]) for t in S)
        print(json.dumps(dict(cen), indent=1))
        return 0
    hi = args.hi if args.hi is not None else len(S)
    for t in S[args.lo:hi]:
        i, op, a, b, c, d = t
        raw = data[i * 16:i * 16 + 16]
        print(f"{i:04x} {raw.hex(' ', 1)[18:]:35s} {dis(*t)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
