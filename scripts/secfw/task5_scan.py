#!/usr/bin/env python3
"""Воспроизведение выкладок журнала task-05 (§1-§3).

Считает по MAIN_CODE 8008-RE-базы (build/secfw-main03-dc.bin):
(1) таблицу component_index→класс @dc 0x38b990 (вход диспетчера 0xc6604,
    вызывающего MCDA-хендлер 0x122b90 с кодом класса как r7);
(2) значения max-xfer резолвера 0x1d37b0 (класс→макс. размер MCDA/MCQI/MCC,
    дизасм-выписка §1.2 журнала);
(3) цензус ld.i-читателей devinfo (imm 0x3260-0x32a3) по фнциям MCDA-цепочки
    — отсутствие secure-битовых гейтов (журнал §1.4);
(4) xref-якоря trace-строк («read_data_from_partition» @0x1a468 и др.) —
    пара addi/addi.hi на rt-адрес строки;
(5) контроль пароля cc-семантики: словарь адресов ветвлений из журнала.
Запуск из корня репо:

  python3 scripts/secfw/task5_scan.py
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import struct  # noqa: E402
from scripts.irisc import disasm  # noqa: E402

BLOB = "build/secfw-main03-dc.bin"

MCDA_CHAIN = [
    (0x122b90, 0x122dc0, "mcda-хендлер 0x9063"),
    (0x122554, 0x122594, "mcc_en-гейт"),
    (0x1d5b78, 0x1d5e60, "executor компонент-доступа"),
    (0x1d07e0, 0x1d08a0, "диспетчер направления R/W"),
    (0x1a424, 0x1a4e0, "read_data_from_partition"),
    (0x19208, 0x19400, "сырой flash-read"),
    (0x1cf75c, 0x1cf7a4, "state-check executor'а"),
    (0x1d0604, 0x1d0694, "резолвер экстента компонента"),
    (0x1d382c, 0x1d3a90, "MCQI CAPABILITIES билдер"),
    (0x1cfe6c, 0x1cfe6c + 0x50, "резолвер r21 (rd_en вход)"),
]

STR_ANCHORS = [
    0x381e87,  # read_data_from_partition: offset/length
    0x37641c,  # check_and_exec_access_register
    0x3620da,  # update_component
    0x3737a7,  # pass_component_table
    0x359946,  # fw_burn_generate_update_handle (ASCII-only, пары нет — §0.5)
    0x359977,  # fw_burn_fsm (ASCII-only, пары нет — §0.5)
]


def main():
    data = open(BLOB, "rb").read()

    print("== (1) component_index -> класс @dc 0x38b990 (код -> max-xfer 0x1d37b0)")
    codes = {}
    for i in range(10):
        v = struct.unpack(">I", data[0x38b990 + 4 * i:0x38b994 + 4 * i])[0]
        codes[i] = v
        print("  index %d -> класс %#x" % (i, v))
    maxtbl = {2: 0x1c, 4: 0x80, 5: 0x100}
    for i, c in sorted(codes.items()):
        print("  index %d: max MCDA = %s" % (i, hex(maxtbl[c]) if c in maxtbl
                                             else "0 (доступа нет)"))

    print("== (2) max-xfer резолвер 0x1d37b0 (дизасм-факт)")
    for lo, hi, tag, reg in ((0x1d37b0, 0x1d3830, "значения", None),):
        for off in range(lo, hi, 4):
            s = disasm(int.from_bytes(data[off:off + 4], "big"), off)
            if re.match(r"^addi r\d+,zero,0x(1c|14|80|100|0)$", s):
                print("  %#08x  %s" % (off, s))

    print("== (3) цензус devinfo-читателей в MCDA-цепочке (imm 0x3260-0x32a3)")
    for lo, hi, tag in MCDA_CHAIN:
        hits = []
        for off in range(lo, hi, 4):
            s = disasm(int.from_bytes(data[off:off + 4], "big"), off)
            m = re.match(r"^ld\.i r\d+,0x(32[6-9a][0-9a-f]|32aa)$", s)
            if m:
                hits.append("%#x->phys %#x" % (off, int(m.group(1), 16) << 2))
        print("  %-42s %s" % (tag, hits if hits else "нет (secure-гейта нет)"))

    print("== (4) xref-якоря trace-строк (addi lo16 + addi.hi rt-адрес)")
    words = [int.from_bytes(data[o:o + 4], "big") for o in range(0, len(data), 4)]
    for t in STR_ANCHORS:
        rt = t + 0x800000
        lo16, hi16 = rt & 0xffff, rt >> 16
        if lo16 >= 0x8000:
            lo16 -= 1 << 16
        for i in range(len(words) - 1):
            s1 = disasm(words[i], i * 4)
            if not s1.startswith("addi ") or "zero" not in s1:
                continue
            if not s1.endswith(("0x%x" % (lo16 & 0xffffffff),
                                "0x-{:x}".format(-lo16))):
                continue
            s2 = disasm(words[i + 1], i * 4 + 4)
            if s2.startswith("addi.hi") and ("0x%x" % hi16) in s2:
                print("  str dc %#x <- код %#x" % (t, i * 4))
                break


if __name__ == "__main__":
    main()
