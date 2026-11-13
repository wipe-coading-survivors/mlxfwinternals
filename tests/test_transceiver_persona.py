import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

try:
    import transceiver_persona  # noqa: E402
    from transceiver_persona import (  # noqa: E402
        build_persona_image,
        expected_bytes,
        validate_image,
    )
except FileNotFoundError:
    pytest.skip("hardware.local.md hw registry not present",
                allow_module_level=True)

SN5 = transceiver_persona.SN5
SN6 = transceiver_persona.SN6
SNX = transceiver_persona.SNX    # 12 символов, реальный SN (task-01)
NAME = b"OEM" + b" " * 13          # 16 Б, 8472 name 20-35
OUI = bytes([0x00, 0x17, 0x6a])    # 8472 OUI 37-39
PN = b"SFP-25G-SR" + b" " * 6      # 16 Б, 8472 PN 40-55
PNX = b"SFP28-25G-SR" + b" " * 4   # 16 Б, реальный PN (task-01)


def make_dump(sn: bytes, byte0: int) -> bytearray:
    d = bytearray(256)
    d[0] = byte0
    d[20:36] = NAME
    d[37:40] = OUI
    d[40:56] = PN
    d[68:84] = sn + b" " * (16 - len(sn))
    d[63] = sum(d[0:63]) & 0xFF
    # зонные сентинелы (верхняя половина):
    for o in range(148, 164): d[o] = 0x5A   # name-зона (write)
    for o in (165, 166, 167): d[o] = 0x5A   # OUI-зона (write)
    for o in range(168, 184): d[o] = 0x5A   # PN-зона (write)
    for o in range(196, 212): d[o] = 0x5A   # SN-зона (write)
    d[191] = 0x5A                            # CC_BASE-8636 (write)
    d[223] = 0x5A                            # CC_EXT-8636 (write)
    d[164] = 0x77                            # a0006: write; a0005: НЕ трогаем — см. ниже
    for o in range(128, 148): d[o] = 0x11    # non-write sentinel
    for o in range(192, 196): d[o] = 0x33    # non-write sentinel
    for o in range(212, 223): d[o] = 0x33    # non-write sentinel
    for o in range(224, 256): d[o] = 0x44    # non-write sentinel
    return d


def test_build_a0006_image_fields():
    d = make_dump(SN6, 0x03)
    img = build_persona_image(bytes(d), "a0006")
    assert img[0] == 0x11
    assert img[164] == 0x0f
    assert img[63] == sum(img[0:63]) & 0xFF
    assert img[148:164] == d[20:36]
    assert img[165:168] == d[37:40]
    assert img[168:184] == d[40:56]
    assert img[196:212] == d[68:84]
    assert img[191] == sum(img[128:191]) & 0xFF
    assert img[223] == sum(img[192:223]) & 0xFF


def test_build_a0006_preserves_non_written():
    d = make_dump(SN6, 0x03)
    img = build_persona_image(bytes(d), "a0006")
    for o in list(range(128, 148)) + list(range(192, 196)) \
            + list(range(212, 223)) + list(range(224, 256)):
        assert img[o] == d[o], o
    for o in range(1, 63):          # нижняя половина: кроме 0/63
        assert img[o] == d[o], o
    for o in range(64, 128):
        assert img[o] == d[o], o


def test_build_a0005_image():
    d = make_dump(SN5, 0x11)
    d[164] = 0x0f
    d[63] = sum(d[0:63]) & 0xFF
    img = build_persona_image(bytes(d), "a0005")
    assert img[0] == 0x11           # не трогаем
    assert img[164] == 0x0f         # не трогаем
    assert img[63] == d[63]         # не трогаем (не пересчитываем)
    assert img[148:164] == d[20:36]
    assert img[165:168] == d[37:40]
    assert img[168:184] == d[40:56]
    assert img[196:212] == d[68:84]
    assert img[191] == sum(img[128:191]) & 0xFF
    assert img[223] == sum(img[192:223]) & 0xFF


def test_validate_image_pass():
    for m, sn, b0 in (("a0005", SN5, 0x11), ("a0006", SN6, 0x03)):
        d = make_dump(sn, b0)
        if m == "a0005":
            d[164] = 0x0f
            d[63] = sum(d[0:63]) & 0xFF
        img = build_persona_image(bytes(d), m)
        assert validate_image(bytes(d), img, m) == []


def test_validate_image_catches_in_zone_mismatch():
    d = make_dump(SN6, 0x03)
    img = bytearray(build_persona_image(bytes(d), "a0006"))
    img[200] ^= 0xFF   # 200 — в SN-зоне (196..211), значение вне манифеста
    assert validate_image(bytes(d), bytes(img), "a0006")


def test_validate_image_catches_out_of_zone_change():
    d = make_dump(SN6, 0x03)
    img = bytearray(build_persona_image(bytes(d), "a0006"))
    img[220] ^= 0xFF   # 220 — вне манифеста (212..222 — non-write зона)
    assert validate_image(bytes(d), bytes(img), "a0006")


def test_expected_bytes_manifest_exact():
    d6 = make_dump(SN6, 0x03)
    assert set(expected_bytes(bytes(d6), "a0006")) == \
        {0, 63, 164, *range(148, 164), 165, 166, 167, *range(168, 184),
         191, *range(196, 212), 223}
    d5 = make_dump(SN5, 0x11)
    d5[164] = 0x0f
    assert set(expected_bytes(bytes(d5), "a0005")) == \
        {*range(148, 164), 165, 166, 167, *range(168, 184),
         191, *range(196, 212), 223}


def test_sn_gate():
    d = make_dump(SN5, 0x03)        # SN A0005 в образе «a0006»
    with pytest.raises(ValueError):
        build_persona_image(bytes(d), "a0006")


def test_size_gate():
    with pytest.raises(ValueError):
        build_persona_image(bytes(make_dump(SN6, 0x03))[:128], "a0006")


def test_sn_gate_rejects_non_space_pad():
    d = make_dump(SN6, 0x03)
    d[83] = 0x00   # 14-Б SN: байт 83 вне pad 0x20 — новый 16-Б гейт (R6)
    with pytest.raises(ValueError):
        build_persona_image(bytes(d), "a0006")


def test_build_snx_image_fields():
    d = make_dump(SNX, 0x03)
    d[40:56] = PNX
    img = build_persona_image(bytes(d), SNX.decode())
    assert img[0] == 0x11
    assert img[164] == 0x0f
    assert img[63] == sum(img[0:63]) & 0xFF
    assert img[148:164] == d[20:36]
    assert img[165:168] == d[37:40]
    assert img[168:184] == d[40:56]
    assert img[196:212] == d[68:84]
    assert img[191] == sum(img[128:191]) & 0xFF
    assert img[223] == sum(img[192:223]) & 0xFF


def test_expected_bytes_snx_manifest_exact():
    d = make_dump(SNX, 0x03)
    assert set(expected_bytes(bytes(d), SNX.decode())) == \
        {0, 63, 164, *range(148, 164), 165, 166, 167, *range(168, 184),
         191, *range(196, 212), 223}


def test_sn_gate_snx():
    d = make_dump(SN6, 0x03)   # чужой SN (A0006) в образе SN-модуля
    with pytest.raises(ValueError):
        build_persona_image(bytes(d), SNX.decode())
