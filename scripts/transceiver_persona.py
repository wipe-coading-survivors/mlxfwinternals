"""transceiver_persona.py — офлайн-билдер 256-Б образов A0h SFP-25G-SR.

CLI:
    python3 scripts/transceiver_persona.py --pre-dump <file> \
        --module {a0005,a0006,<SN: реестр CARD_CX4LX_XCAT_SN>} --out <image>

Читает 256-Б pre-dump A0h, строит целевой образ (SFF-8636 page 00h
вендорская идентичность + QSFP28-персона для a0006 и модуля-SN),
валидирует (полный манифест + «ничего лишнего не изменилось»
относительно pre-dump), пишет образ и печатает ПОЛНЫЙ манифест:
hex old→new по всем байтам expected_bytes, байты без изменения
помечены.
При ошибке (размер ≠ 256, чужой SN, рассинхрон) — exit 2 с
диагностикой в stderr, образ не пишется.

Спецификация образов — docs/superpowers/specs/
2026-10-17-transceiver-qsa-persona-identity-design.md §4.
Конвенция CC — plain Σ (mod 256), значения считаются от финального
образа: 8472 CC_BASE@63 = Σ(0..62); 8636 CC_BASE@191 = Σ(128..190);
8636 CC_EXT@223 = Σ(192..222).
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import mlxfwutil

SNX = mlxfwutil.hw("CARD_CX4LX_XCAT", "sn").encode()
SN5 = mlxfwutil.hw("XCVR_A0005", "sn").encode()
SN6 = mlxfwutil.hw("XCVR_A0006", "sn").encode()
SN_BY_MODULE = {
    "a0005": SN5,
    "a0006": SN6,
    SNX.decode(): SNX,
}

FULL_PERSONA = frozenset({"a0006", SNX.decode()})

# Слепые побайтовые копии зон SFF-8472 (нижняя половина) →
# SFF-8636 page 00h (верхняя половина): (src, dst, len).
ZONE_COPIES = (
    (20, 148, 16),   # vendor name 20-35 → 148-163
    (37, 165, 3),    # OUI 37-39 → 165-167
    (40, 168, 16),   # PN 40-55 → 168-183
    (68, 196, 16),   # SN 68-83 → 196-211
)


def _check(dump, module):
    if len(dump) != 256:
        raise ValueError(
            f"pre-dump: ожидалось 256 байт, получено {len(dump)}")
    sn = SN_BY_MODULE.get(module)
    if sn is None:
        raise ValueError(
            f"неизвестный модуль {module!r} ({'/'.join(SN_BY_MODULE)})")
    padded = sn + b" " * (16 - len(sn))
    if dump[68:84] != padded:
        raise ValueError(
            f"SN-гейт: dump[68:84] = {dump[68:84]!r}, ожидалось "
            f"{padded!r} (модуль {module})")


def build_persona_image(dump: bytes, module: str) -> bytes:
    """Собрать целевой 256-Б образ A0h из pre-dump.

    Копии зон — всегда; FULL_PERSONA (a0006, SN-модуль) дополнительно:
    byte 0 := 0x11, byte 164 := 0x0f, byte 63 := Σ(0..62). У a0005 персоны
    уже стоят — байты 0/164/63 не трогаются (63 не пересчитывается).
    CC 191/223 — plain Σ от финального образа.
    """
    _check(dump, module)
    img = bytearray(dump)
    for src, dst, ln in ZONE_COPIES:
        img[dst:dst + ln] = dump[src:src + ln]
    if module in FULL_PERSONA:
        img[0] = 0x11
        img[164] = 0x0f
        img[63] = sum(img[0:63]) & 0xFF
    img[191] = sum(img[128:191]) & 0xFF
    img[223] = sum(img[192:223]) & 0xFF
    return bytes(img)


def expected_bytes(dump: bytes, module: str) -> dict[int, int]:
    """Манифест: офсет → ожидаемое финальное значение байта.

    FULL_PERSONA (a0006, SN-модуль): {0, 63, 164} ∪ зоны копий ∪ {191, 223};
    a0005: зоны копий ∪ {191, 223} (0/63/164 не трогаются).
    """
    _check(dump, module)
    img = build_persona_image(dump, module)
    manifest: dict[int, int] = {}
    for _src, dst, ln in ZONE_COPIES:
        for i in range(ln):
            manifest[dst + i] = img[dst + i]
    manifest[191] = img[191]
    manifest[223] = img[223]
    if module in FULL_PERSONA:
        manifest[0] = img[0]
        manifest[63] = img[63]
        manifest[164] = img[164]
    return manifest


def validate_image(dump: bytes, image: bytes, module: str) -> list[str]:
    """Сверить образ: манифест сходится + вне манифеста == pre-dump.

    Пустой список = pass; иначе — строки-описания рассинхронов.
    """
    errors: list[str] = []
    if len(image) != 256:
        errors.append(f"image: ожидалось 256 байт, получено {len(image)}")
        return errors
    manifest = expected_bytes(dump, module)
    for off in sorted(manifest):
        want = manifest[off]
        if image[off] != want:
            errors.append(
                f"@{off} (0x{off:03x}): image 0x{image[off]:02x} != "
                f"манифест 0x{want:02x}")
    for off in range(256):
        if off not in manifest and image[off] != dump[off]:
            errors.append(
                f"@{off} (0x{off:03x}): вне манифеста, image "
                f"0x{image[off]:02x} != pre-dump 0x{dump[off]:02x}")
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="transceiver_persona",
        description="Офлайн-билдер 256-Б образа A0h SFP-25G-SR "
                    "(8636 вендорская идентичность + QSFP28-персона).")
    parser.add_argument("--pre-dump", required=True, metavar="FILE",
                        help="pre-dump A0h, ровно 256 байт")
    parser.add_argument("--module", required=True,
                        choices=tuple(SN_BY_MODULE),
                        help="модуль (SN-гейт и персона-байты)")
    parser.add_argument("--out", required=True, metavar="FILE",
                        help="выходной образ (256 байт)")
    args = parser.parse_args(argv)

    try:
        dump = open(args.pre_dump, "rb").read()
        image = build_persona_image(dump, args.module)
    except ValueError as e:
        print(f"transceiver_persona: {e}", file=sys.stderr)
        return 2

    errors = validate_image(dump, image, args.module)
    if errors:
        for e in errors:
            print(f"transceiver_persona: {e}", file=sys.stderr)
        return 2

    with open(args.out, "wb") as f:
        f.write(image)

    manifest = expected_bytes(dump, args.module)
    for off in sorted(manifest):
        old, new = dump[off], manifest[off]
        mark = "" if old != new else "  (без изменения)"
        print(f"0x{off:03x}: 0x{old:02x} -> 0x{new:02x}{mark}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
