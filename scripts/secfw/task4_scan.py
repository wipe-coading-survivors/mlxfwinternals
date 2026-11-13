#!/usr/bin/env python3
"""Воспроизведение выписок/чисел журнала task-04 (§1-§3).

Считает: (1) цензус абсолютных читателей RAM[0xc980] (devinfo dword0,
ld.i imm 0x3260) и RAM[0x2000..0x2020] (окно HCR flash-gateway, ld.i imm
0x800-0x808) по полному дизасму MAIN_CODE 8008-RE-базы; (2) отсутствие
писателей st.i этих ячеек во ВСЕХ кодовых секциях образца (0x02/0x04/0x05/
0x06/0x07 — выгрузки extract, как в extract_main03.py); (3) таблицы
резолвера/классификатора регистра MFPA/MFBA/MFBE (rt 0xb8c81c/0xb8c8b8 →
dc 0x38c81c/0x38c8b8) + 4030-эквивалент; (4) IMAGE_INFO dword0 трёх классов
образов (HPE/Dell/CDA) и их дельты. Запуск из корня репо:

  python3 scripts/secfw/task4_scan.py
"""
import sys
import re
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import mlxfwutil  # noqa: E402
from scripts.irisc import disasm  # noqa: E402

IMG8008 = ("refs/fw/cx-5-6/"
           "fw-ConnectX5-rel-16_35_8008-872726-B21_Ax_Bx-UEFI-14.29.15-"
           "FlexBoot-3.6.902.signed.bin")
IMG4030 = ("refs/fw/cx-5-6/"
           "fw-ConnectX5-rel-16_35_4030-MCX516A-CDA_Ax_Bx-UEFI-14.29.15-"
           "FlexBoot-3.6.902.bin")
IMGDELL = ("refs/fw/cx-5-6/"
           "fw-ConnectX5-rel-16_27_6120-09FTMY_071C1T_Ax-UEFI-14.20.27-"
           "FlexBoot-3.5.903.signed.bin")
BLOB = "build/secfw-main03-dc.bin"


def code_sections(img):
    out = []
    for e in img.entries("ITOC"):
        if e.type in (0x01, 0x02, 0x04, 0x05, 0x06, 0x07):
            out.append((e.type, img.section_data(e)))
    return out


def census(data, imms):
    hits = Counter()
    for off in range(0, len(data) - 3, 4):
        w = int.from_bytes(data[off:off + 4], "big")
        s = disasm(w, off)
        m = re.match(r"^(ld|st)\.i \w+,0x([0-9a-f]+)$", s)
        if m and int(m.group(2), 16) in imms:
            hits[(m.group(1), m.group(2))] += 1
            if m.group(1) == "st":
                print("  !! STORE", hex(off), s)
    return hits


def main():
    # (1) MAIN_CODE census: devinfo + gateway window
    blob = open(BLOB, "rb").read()
    print("== MAIN_CODE 8008: ld.i census (devinfo 0x3260.. / gw 0x800-0x808)")
    h = census(blob, set(range(0x3260, 0x326e)) | set(range(0x800, 0x809)))
    for (op, imm), n in sorted(h.items()):
        tag = "devinfo" if imm.startswith("326") else "gw-window"
        print("  %s.i imm=%s (phys %#x) x%d  [%s]"
              % (op, imm, int(imm, 16) << 2, n, tag))

    # (2) all code sections: no writers
    img = mlxfwutil.Image(open(IMG8008, "rb").read(), IMG8008)
    print("== code sections: store-scan (st.i imm 0x3260 / 0x800-0x808)")
    for t, d in code_sections(img):
        n_st = sum(1 for (op, _imm) in census(d, {0x3260} | set(range(0x800, 0x809)))
                   if op == "st")
        print("  sec %#04x: st-писателей %d" % (t, n_st))

    # (3) resolver/classify tables
    import struct
    print("== resolver table (dc 0x38c81c, cmd 0x9010+i) — MFPA/MFBA/MFBE:")
    for i in (0, 1, 2):
        v = struct.unpack(">I", blob[0x38c81c + 4 * i:0x38c81c + 4 * i + 4])[0]
        print("  cmd %#06x -> rt %#x (dc %#x)" % (0x9010 + i, v, v - 0x800000))

    # (4) IMAGE_INFO dword0
    print("== IMAGE_INFO (ITOC 0x10) dword0:")
    dws = {}
    for tag, p in (("HPE-8008", IMG8008), ("Dell-09FTMY", IMGDELL), ("CDA-4030", IMG4030)):
        im = mlxfwutil.Image(open(p, "rb").read(), p)
        d = im.section_data(im.find_entry("ITOC", 0x10))
        dw = int.from_bytes(d[0:4], "big")
        dws[tag] = dw
        print("  %-11s %#010x bits %s" %
              (tag, dw, [i for i in range(32) if dw >> i & 1]))
    print("  HPE xor Dell = %#x (бит 5 — единственный HPE-эксклюзив)"
          % (dws["HPE-8008"] ^ dws["Dell-09FTMY"]))


if __name__ == "__main__":
    main()
