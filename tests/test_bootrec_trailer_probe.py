import hashlib
import importlib.util
import struct
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

_spec = importlib.util.spec_from_file_location(
    "bootrec_trailer_probe",
    Path(__file__).resolve().parent.parent / "scripts" / "probes"
    / "securefw-arc-a" / "bootrec_trailer_probe.py")
bootrec_trailer_probe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bootrec_trailer_probe)

CX7_A = (REPO / "refs" / "fw" / "cx-7" / "dumps" / "cx7_firmware_dumps"
         / "28.33.0751" / "orig_firmware.bin")
CX7_B = (REPO / "refs" / "fw" / "cx-7" / "dumps" / "cx7_firmware_dumps"
         / "28.33.0800.bin")
REF_CX6DX = (REPO / "refs" / "fw" / "cx-5-6"
             / "fw-ConnectX6Dx-rel-22_50_1002-MCX623105AC-CDA_Ax-"
             "UEFI-14.43.10-FlexBoot-3.9.101.signed.bin")
REF_CX6 = (REPO / "refs" / "fw" / "cx-5-6"
           / "fw-ConnectX6-rel-20_43_1014-MCX654105A-HCA_Ax-"
           "UEFI-14.36.16-FlexBoot-3.7.500.bin")
REF_CX5 = (REPO / "refs" / "fw" / "cx-5-6"
           / "fw-ConnectX5-rel-16_35_1012-MCX512A-ADA_Ax_Bx-"
           / "UEFI-14.28.15-FlexBoot-3.6.804.bin")


def test_crc16_mlx_golden():
    assert bootrec_trailer_probe.crc16_mlx(b"") == 0x0955
    assert bootrec_trailer_probe.crc16_mlx(
        struct.pack(">I", 0x20400040)) == 0xB2DA


def test_crc16_plain_standard_vectors():
    v = bootrec_trailer_probe.crc16_plain
    # standard check values for b"123456789"
    assert v(b"123456789", poly=0x1021, init=0xFFFF) == 0x29B1  # ccitt-false
    assert v(b"123456789", poly=0x1021, init=0x0000) == 0x31C3  # xmodem
    assert v(b"123456789", poly=0xA001, init=0x0000,
             reflected=True) == 0xBB3D  # arc (reflected)
    assert v(b"123456789", poly=0xA001, init=0xFFFF,
             reflected=True) == 0x4B37  # modbus (reflected)


def test_fletcher16_vector():
    # hand-computed: a/b accumulate mod 255 per byte, result (b<<8)|a
    assert bootrec_trailer_probe.fletcher16(b"\x01") == 0x0101
    assert bootrec_trailer_probe.fletcher16(b"\x01\x02\x03") == 0x0A06


def test_trailer_sweep_hit_body_span():
    region = bytearray(b"\xff" * 0x100)
    struct.pack_into(">I", region, 0, 0x418)
    struct.pack_into(">I", region, 0x10, 0x30D02650)
    body = bytes(region)
    trailer = bootrec_trailer_probe.crc16_plain(
        body, poly=0x1021, init=0xFFFF)
    region.extend(struct.pack(">I", trailer))
    res = bootrec_trailer_probe.trailer_sweep(bytes(region),
                                              trailer_off=0x100)
    assert res["trailer_value"] == trailer
    assert {"variant": "ccitt-false", "span": "body"} in res["hits"]


def test_trailer_sweep_hit_zeroed_span():
    region = bytearray(b"\xff" * 0x80)
    struct.pack_into(">I", region, 0, 0x84)
    zeroed = bytes(region) + b"\x00\x00\x00\x00"
    trailer = bootrec_trailer_probe.crc16_plain(
        zeroed, poly=0x1021, init=0x0000)
    region.extend(struct.pack(">I", trailer))
    res = bootrec_trailer_probe.trailer_sweep(bytes(region),
                                              trailer_off=0x80)
    assert {"variant": "xmodem", "span": "trailer_zeroed"} in res["hits"]


def test_trailer_sweep_miss():
    region = bytearray(b"\xff" * 0x40)
    struct.pack_into(">I", region, 0, 0x418)
    region.extend(struct.pack(">I", 0xDEADBEEF))
    res = bootrec_trailer_probe.trailer_sweep(bytes(region),
                                              trailer_off=0x40)
    assert res["hits"] == []
    assert set(res["spans"]) == {"body", "incl_trailer", "trailer_zeroed"}


def test_trailer_sweep_auto_detect():
    region = bytearray(b"\xff" * 0x40)
    struct.pack_into(">I", region, 0, 1)
    region.extend(struct.pack(">I", 0x00000E67))
    res = bootrec_trailer_probe.trailer_sweep(bytes(region))
    assert res["trailer_off"] == 0x40
    assert res["trailer_value"] == 0x0E67


def test_parse_slot_map():
    buf = bytearray(b"\xff" * 0x200)
    struct.pack_into(">I", buf, 0x00, 0)
    struct.pack_into(">I", buf, 0x04, 0x1FD)
    struct.pack_into(">I", buf, 0x08, 0x3475)
    struct.pack_into(">I", buf, 0x1C, (0x20 << 16) | 0xF0)
    struct.pack_into(">I", buf, 0x24, (0x07 << 16) | 0x130)
    struct.pack_into(">I", buf, 0x2C, 0x00FFFFFF)  # fill -> skipped
    struct.pack_into(">I", buf, 0x34, 0)           # zero -> skipped
    m = bootrec_trailer_probe.parse_slot_map(bytes(buf), ht_off=0)
    assert m == {0x20: 0xF0, 0x07: 0x130}


def test_sha512_slot_check():
    raw = bytes(range(0x40)) * 4
    slot = hashlib.sha512(raw).digest()
    buf = bytearray(b"\xff" * 0x300)
    buf[0x110:0x110 + len(raw)] = raw       # section outside header window
    struct.pack_into(">I", buf, 0x1C, (0x20 << 16) | 0x220)
    buf[0x220:0x260] = slot
    res = bootrec_trailer_probe.sha512_slot_check(
        bytes(buf), {0x20: (0x110, len(raw))}, ht_off=0)
    assert res["slot_base"] == 0
    assert res["checked"] == 1 and res["match"] == [0x20]
    bad = bytearray(buf)
    bad[0x220:0x260] = bytes(0x40)
    res2 = bootrec_trailer_probe.sha512_slot_check(
        bytes(bad), {0x20: (0x110, len(raw))}, ht_off=0)
    assert res2["match"] == [] and res2["miss"] == [0x20]


def test_sha512_slot_check_alt_base():
    raw = bytes(range(0x40)) * 4
    slot = hashlib.sha512(raw).digest()
    buf = bytearray(b"\xff" * 0x400)
    buf[0x110:0x110 + len(raw)] = raw
    struct.pack_into(">I", buf, 0x1C, (0x20 << 16) | 0x220)
    buf[0x320:0x360] = slot               # ht+0x100-relative placement
    ht_rel = bootrec_trailer_probe.sha512_slot_check(
        bytes(buf), {0x20: (0x110, len(raw))}, ht_off=0)
    assert ht_rel["match"] == []          # slot not at ht+0x220
    alt = bootrec_trailer_probe.sha512_slot_check(
        bytes(buf), {0x20: (0x110, len(raw))}, ht_off=0, slot_base=0x100)
    assert alt["slot_base"] == 0x100
    assert alt["checked"] == 1 and alt["match"] == [0x20]


@pytest.mark.slow
def test_real_exclusions_reproduced():
    if not (CX7_A.exists() and CX7_B.exists()):
        pytest.skip("refs cx7 images not available")
    for path, t_off in ((CX7_A, 0x3F0), (CX7_B, 0x3F0),
                        (REF_CX6, 0x3FC), (REF_CX5, 0xFC)):
        if not path.exists():
            continue
        region = path.read_bytes()[0x100:0x500]
        res = bootrec_trailer_probe.trailer_sweep(region,
                                                  trailer_off=t_off)
        assert res["hits"] == [], (path.name, res["hits"])
    for path in (CX7_A, CX7_B):
        buf = path.read_bytes()
        sections = bootrec_trailer_probe.sections_from_itoc(buf)
        # both slot decodings (ht-relative and ht+0x100-relative), all
        # hashable sections of the image — pin the exclusion under both
        for slot_base in (0, 0x100):
            res = bootrec_trailer_probe.sha512_slot_check(
                buf, sections, ht_off=0x7000, slot_base=slot_base)
            assert res["checked"] == 24, (path.name, slot_base,
                                          res["checked"])
            assert res["match"] == [], (path.name, slot_base,
                                        res["match"])
    buf_a = CX7_A.read_bytes()
    m = bootrec_trailer_probe.parse_slot_map(buf_a, ht_off=0x7000)
    assert len(m) == 25
    assert m[0x20] == 0x71B0 and m[0x07] == 0x72F0 and m[0x11] == 0x74F0
