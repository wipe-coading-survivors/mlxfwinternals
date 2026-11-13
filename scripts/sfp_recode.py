"""sfp_recode.py — офлайн-патчер EEPROM SFP/QSFP-модулей.

CLI:
    python3 scripts/sfp_recode.py build IN OUT \
        --set OFF=VAL [OFF=VAL ...] \
        [--cc OFF,LO,HI] \
        [--expect-diff OFF:OLD>NEW [OFF:OLD>NEW ...]]

Все офсеты — ОТНОСИТЕЛЬНО ВХОДНОГО ФАЙЛА (для 64-байтного чанка
bytes 128..191 образа byte 164 модуля — это офсет 36 чанка).

Конвенция CC (live-подтверждена для SFP и QSFP, docs/850-howto/110-transceiver-programming):
CC@OFF := Σ(bytes LO..HI) mod 256; сам CC-офсет OFF из суммы исключается.
Патч, покрывающий байт внутри [LO,HI], применяется до пересчёта; патч,
покрывающий сам OFF при OFF внутри [LO,HI], — неоднозначность → ValueError.

Вывод: `diff bytes: 0x.. 0x..` — hex-офсеты всех изменённых байт.
--expect-diff: несовпадение старого/нового значения → exit 2.
Исходный CC, несогласованный с Σ(LO..HI) — предупреждение в stderr,
файл всё равно строится.
"""
import argparse
import sys


def _parse_int(text):
    return int(text, 0) if text.lower().startswith("0x") else int(text, 10)


def _parse_set(text):
    off, sep, val = text.partition("=")
    if not sep:
        raise ValueError(f"--set: ожидалось OFF=VAL, получено {text!r}")
    return _parse_int(off), _parse_int(val)


def _parse_cc(text):
    parts = text.split(",")
    if len(parts) != 3:
        raise ValueError(f"--cc: ожидалось OFF,LO,HI, получено {text!r}")
    return tuple(_parse_int(p) for p in parts)


def _parse_expect(text):
    off, sep, rest = text.partition(":")
    old, sep2, new = rest.partition(">")
    if not sep or not sep2:
        raise ValueError(f"--expect-diff: ожидалось OFF:OLD>NEW, получено {text!r}")
    return _parse_int(off), _parse_int(old), _parse_int(new)


def build_image(data, patches, cc):
    """Применить точечные патчи и пересчитать CC.

    patches: {offset: new_value}; cc: (OFF, LO, HI) или None.
    Все офсеты относительно data. Возвращает новый bytes.
    """
    buf = bytearray(data)
    if cc is not None:
        off, lo, hi = cc
        if not (0 <= lo <= hi < len(buf)) or not (0 <= off < len(buf)):
            raise ValueError(
                f"CC-диапазон ({off},{lo},{hi}) за пределами файла "
                f"({len(buf)} байт)")
        if off in patches and lo <= off <= hi:
            raise ValueError(
                f"патч покрывает CC-офсет {off} внутри [{lo},{hi}] — "
                "неоднозначность: неизвестно, до или после пересчёта применять")
    for off, val in patches.items():
        if not (0 <= off < len(buf)):
            raise ValueError(f"офсет {off} за пределами файла ({len(buf)} байт)")
        buf[off] = val & 0xFF
    if cc is not None:
        off, lo, hi = cc
        buf[off] = sum(buf[i] for i in range(lo, hi + 1) if i != off) & 0xFF
    return bytes(buf)


def _cc_sum(data, off, lo, hi):
    return sum(data[i] for i in range(lo, hi + 1) if i != off) & 0xFF


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="sfp_recode",
        description="Офлайн-патчер EEPROM SFP/QSFP (byte patches + sum CC).")
    sub = parser.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="пропатчить входной файл в выходной")
    b.add_argument("infile")
    b.add_argument("outfile")
    b.add_argument("--set", action="append", default=[], metavar="OFF=VAL",
                   help="точечная замена байта (hex 0x.. или decimal)")
    b.add_argument("--cc", metavar="OFF,LO,HI",
                   help="пересчитать CC@OFF := Σ(bytes LO..HI) mod 256")
    b.add_argument("--expect-diff", action="append", default=[],
                   metavar="OFF:OLD>NEW",
                   help="проверить ожидаемое старое/новое значение; "
                        "несовпадение → exit 2")
    args = parser.parse_args(argv)

    try:
        patches = dict(_parse_set(s) for s in args.set)
        cc = _parse_cc(args.cc) if args.cc else None
        expects = [_parse_expect(e) for e in args.expect_diff]
    except ValueError as e:
        parser.exit(2, f"sfp_recode: {e}\n")

    data = open(args.infile, "rb").read()

    if cc is not None:
        off, lo, hi = cc
        orig_cc = data[off] if 0 <= off < len(data) else None
        if orig_cc is not None and 0 <= lo <= hi < len(data):
            want = _cc_sum(data, off, lo, hi)
            if orig_cc != want:
                print(f"sfp_recode: warning: исходный CC@{off} = "
                      f"0x{orig_cc:02x}, ожидалось 0x{want:02x} "
                      f"(Σ {lo}..{hi} без OFF) — пересчитываю",
                      file=sys.stderr)

    for off, old, new in expects:
        actual_old = data[off] if 0 <= off < len(data) else None
        if actual_old != old:
            print(f"sfp_recode: expect-diff mismatch @0x{off:x}: "
                  f"старое ожидалось 0x{old:02x}, фактически "
                  f"0x{actual_old:02x}" if actual_old is not None else
                  f"sfp_recode: expect-diff @0x{off:x} вне файла",
                  file=sys.stderr)
            return 2

    try:
        result = build_image(data, patches, cc)
    except ValueError as e:
        print(f"sfp_recode: {e}", file=sys.stderr)
        return 2

    for off, old, new in expects:
        if result[off] != new:
            print(f"sfp_recode: expect-diff mismatch @0x{off:x}: "
                  f"новое ожидалось 0x{new:02x}, получено 0x{result[off]:02x}",
                  file=sys.stderr)
            return 2

    with open(args.outfile, "wb") as f:
        f.write(result)

    diff = sorted(o for o in range(len(result)) if result[o] != data[o])
    print("diff bytes:", " ".join(f"0x{o:x}" for o in diff))
    return 0


if __name__ == "__main__":
    sys.exit(main())
