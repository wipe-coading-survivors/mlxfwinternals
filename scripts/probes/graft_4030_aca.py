#!/usr/bin/env python3
# ch3 task-03b: build 4030cda-graft.bin = 4030-CDA base + ACA board profile.
#
# No-boot root cause (2026-10-08, docs/superpowers/journal/
# 2026-10-08-transceiver-ib-ch3-ghidra-gate-task-03b.md): CDA board profile
# (QSFP28 x16 Gen4, boot record 212084-family) does not boot on the ACA
# SFP28 x8 Gen3 board (mirror of docs/750-exp/120-eda-ib-node ch4 case). Fix = transplant the
# ACA board profile from the as-found ri (8008-ACA, known-booting) onto the
# 4030 code base -> "synthetic 4030-ACA".
#
# Board profile (verified stable across releases on the 1012-ACA vendor
# image: 0x08/0x09 and boot record byte-identical):
#   - 0x08 HW_BOOT_CFG  : whole section (PCIe topology x8, max speed 0x87)
#   - 0x09 HW_MAIN_CFG  : whole section (SFP28 port blocks, width, speed
#                         table, PHY tuning 0x86c=30d430d4)
#   - 0x11 FW_BOOT_CFG  : board fields only (0x2d dev, 0x3d sub, 0x47 Gen3,
#                         0x93 cap_index, 0x120/0x123 SR-IOV, 0x127,
#                         0x135); release stamps 0x6/0xd stay from 4030
#   - 0x12 FW_MAIN_CFG  : board fields only (0x2ab/0x2b7 speed masks 25G,
#                         0x39f width x8); release stamps 0x72.. stay 4030
#   - boot record       : 0x100..0x108, 0x10c, 0x10e..0x110 (board id
#                         158054-family), 0x1fd..0x200 (board-tied trailer)
# Kept from base: code sections, ROM, 0x10 IMAGE_INFO, 0x30 ini, DTOC
# (GUID/MAC), PSID MT_0000000013, port1 VPI byte 0x11+0x2bb=07.
#
# Usage:
#   python3 graft_4030_aca.py --base 4030cda-vpi.bin --ref as-found-ri.bin \
#       -o 4030cda-graft.bin
import argparse
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from mlxfwutil import parse_toc, find_all

MERGE_SPEC = [
    (0x08, 0x0, 0x140),
    (0x09, 0x0, 0x980),
    (0x11, 0x2D, 1), (0x11, 0x3D, 1), (0x11, 0x47, 1), (0x11, 0x93, 1),
    (0x11, 0x120, 1), (0x11, 0x123, 1), (0x11, 0x127, 1), (0x11, 0x135, 1),
    (0x12, 0x2AB, 1), (0x12, 0x2B7, 1), (0x12, 0x39F, 1),
]
BOOT_RANGES = [(0x100, 0x108), (0x10C, 0x10D), (0x10E, 0x110), (0x1FD, 0x200)]
EXPECTED = {
    (0x11, 0x2BB): 0x07, (0x11, 0x2B7): 0x0A,
    (0x08, 0x22): 0x00, (0x08, 0x23): 0x87,
    (0x11, 0x2D): 0x17, (0x11, 0x3D): 0x20, (0x11, 0x47): 0x18,
    (0x11, 0x93): 0x43, (0x11, 0x120): 0xA0, (0x11, 0x123): 0x08,
    (0x11, 0x127): 0x05, (0x11, 0x135): 0xCF,
    (0x12, 0x2AB): 0x0B, (0x12, 0x2B7): 0x0B, (0x12, 0x39F): 0x00,
}


def toc_map(buf):
    off = find_all(buf, b"\x49\x54\x4f\x43")[0]
    return {e.type: e for e in parse_toc(buf, off, toc="ITOC", fmt="fs4")
            if e.type != 0xFF}


def crc16_mlx(data):
    # reuse mlxfwutil implementation
    import mlxfwutil
    return mlxfwutil.crc16_mlx(data)


def build(base, ref):
    out = bytearray(base)
    mb, mr = toc_map(base), toc_map(ref)
    for t, o, ln in MERGE_SPEC:
        be, re_ = mb[t], mr[t]
        if be.size != re_.size:
            sys.exit(f"section 0x{t:02x} size mismatch")
        if o + ln > be.size:
            sys.exit(f"range 0x{t:02x}+0x{o:x}+{ln:#x} out of section")
        out[be.addr + o:be.addr + o + ln] = ref[re_.addr + o:re_.addr + o + ln]
    for s, e in BOOT_RANGES:
        out[s:e] = ref[s:e]
    # recompute section CRC + entry CRC for touched sections
    off = find_all(bytes(out), b"\x49\x54\x4f\x43")[0]
    touched = {t for t, _, _ in MERGE_SPEC}
    i = 0
    while True:
        eo = off + 32 + i * 32
        ent = bytearray(out[eo:eo + 32])
        t = ent[0]
        if t == 0xFF:
            break
        if t in touched:
            from mlxfwutil import set_bits
            e = mb[t]
            n_sec = crc16_mlx(bytes(out[e.addr:e.addr + e.size]))
            set_bits(ent, 208, 16, n_sec)
            n_ent = crc16_mlx(bytes(ent[:28]))
            set_bits(ent, 240, 16, n_ent)
            out[eo:eo + 32] = ent
        i += 1
    return bytes(out)


def verify(out, base, ref):
    errs = 0
    mg = toc_map(out)
    for (t, o), exp in EXPECTED.items():
        got = out[mg[t].addr + o]
        if got != exp:
            print(f"  FAIL 0x{t:02x}+0x{o:x} = 0x{got:02x}, want 0x{exp:02x}")
            errs += 1
    for s, e in BOOT_RANGES:
        if out[s:e] != ref[s:e]:
            print(f"  FAIL boot range 0x{s:x}..0x{e:x}")
            errs += 1
    for t in (0x03, 0x02, 0x05, 0x18):
        if out[mg[t].addr:mg[t].addr + mg[t].size] != base[mg[t].addr:mg[t].addr + mg[t].size]:
            print(f"  FAIL code section 0x{t:02x} touched")
            errs += 1
    # CRC of all sections
    off = find_all(out, b"\x49\x54\x4f\x43")[0]
    i = 0
    while True:
        ent = out[off + 32 + i * 32:off + 32 + (i + 1) * 32]
        t = ent[0]
        if t == 0xFF:
            break
        e = mg.get(t)
        if e is not None and e.crcf == 0:
            from mlxfwutil import bits
            if crc16_mlx(out[e.addr:e.addr + e.size]) != bits(ent, 208, 16):
                print(f"  FAIL sec-crc 0x{t:02x}")
                errs += 1
            if crc16_mlx(ent[:28]) != bits(ent, 240, 16):
                print(f"  FAIL ent-crc 0x{t:02x}")
                errs += 1
        i += 1
    print(f"  self-verify: {'PASS' if errs == 0 else f'{errs} FAIL'}")
    return errs == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="4030cda-vpi.bin")
    ap.add_argument("--ref", required=True, help="as-found ACA ri dump")
    ap.add_argument("-o", "--output", required=True)
    a = ap.parse_args()
    base = open(a.base, "rb").read()
    ref = open(a.ref, "rb").read()
    print(f"base: {a.base} md5 {hashlib.md5(base).hexdigest()}")
    print(f"ref : {a.ref} md5 {hashlib.md5(ref).hexdigest()}")
    out = build(base, ref)
    print(f"out : {len(out)} B md5 {hashlib.md5(out).hexdigest()}")
    if not verify(out, base, ref):
        sys.exit(1)
    open(a.output, "wb").write(out)
    print(f"written: {a.output}")


if __name__ == "__main__":
    main()
