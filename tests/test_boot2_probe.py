import importlib.util
import json
import random
import struct
import sys
import zlib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

_spec = importlib.util.spec_from_file_location(
    "boot2_probe",
    REPO / "scripts" / "probes" / "securefw-arc-a" / "boot2_probe.py")
boot2_probe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(boot2_probe)

from scripts.irisc import disasm  # noqa: E402

CX7_A = (REPO / "refs" / "fw" / "cx-7" / "dumps" / "cx7_firmware_dumps"
         / "28.33.0751" / "orig_firmware.bin")
CX7_B = (REPO / "refs" / "fw" / "cx-7" / "dumps" / "cx7_firmware_dumps"
         / "28.33.0800.bin")
CX6DX_REF = (REPO / "refs" / "fw" / "cx-5-6" /
             "fw-ConnectX6Dx-rel-22_50_1002-MCX623105AC-CDA_Ax-UEFI-"
             "14.43.10-FlexBoot-3.9.101.signed.bin")


def mk_region(body, dw0=0x20400040, trailer=0x20400244):
    region = struct.pack(">II", dw0, len(body) // 4) + body
    region += struct.pack(">I", trailer)
    return region + struct.pack(">I", boot2_probe.crc16_mlx(region))


def test_crc16_mlx_golden():
    assert boot2_probe.crc16_mlx(b"") == 0x0955
    assert boot2_probe.crc16_mlx(struct.pack(">I", 0x20400040)) == 0xB2DA
    body = bytes(range(64))
    reg = struct.pack(">II", 0x20400040, 16) + body + \
        struct.pack(">I", 0x20400244)
    assert boot2_probe.crc16_mlx(reg) == 0xFC2B


def test_parse_boot2_roundtrip_and_crc():
    body = bytes((i * 7) % 256 for i in range(0x100))
    buf = mk_region(body)
    p = boot2_probe.parse_boot2(buf, 0)
    assert p["status"] == "ok"
    assert p["dw0"] == 0x20400040
    assert p["dw1"] == 0x40
    assert p["size"] == len(buf)
    assert p["body"] == body
    assert p["trailer_dw"] == 0x20400244
    assert p["family"] is True
    assert p["crc_ok"] is True
    assert p["crc_dw"] == p["crc_calc"]


def test_parse_boot2_bad_crc_detected():
    buf = bytearray(mk_region(bytes((i * 7) % 256 for i in range(0x100))))
    buf[0x20] ^= 0x01
    p = boot2_probe.parse_boot2(bytes(buf), 0)
    assert p["status"] == "ok"
    assert p["crc_ok"] is False


def test_parse_boot2_error_statuses():
    assert boot2_probe.parse_boot2(b"\x00" * 4, 0)["status"] == "no-window"
    assert boot2_probe.parse_boot2(b"\xff" * 0x100, 0)["status"] == "erased"
    buf = struct.pack(">II", 0x20400040, 0x40) + b"\x00" * 0x40
    assert boot2_probe.parse_boot2(buf, 0)["status"] == "truncated"


def test_entropy_profile_ordering():
    flat = boot2_probe.entropy_profile(b"\x5a" * 0x1000)
    rnd = boot2_probe.entropy_profile(random.Random(1).randbytes(0x1000))
    assert flat["whole"] < 1.0
    assert rnd["whole"] > 7.5
    assert flat["win16_max"] <= 4.0
    assert flat["per4k_min"] <= flat["per4k_max"]


def _known_words(count):
    out = []
    w = 0
    while len(out) < count:
        r = disasm(w, 0)
        if not (r.startswith("op0x") or r.startswith("alu.0x")):
            out.append(w)
        w += 1
    return out


def test_irisc_rate_known_vs_random():
    ws = _known_words(64)
    blob = struct.pack(">%dI" % len(ws), *ws)
    rate = boot2_probe.irisc_rate(blob)
    assert rate["words"] == 64
    assert rate["frac"] == pytest.approx(1.0)
    rnd = random.Random(2).randbytes(0x400)
    rate_r = boot2_probe.irisc_rate(rnd)
    assert 0.2 < rate_r["frac"] < 0.75


def test_lz4_block_literals_and_match():
    assert boot2_probe.lz4_block_decompress(b"\x10A") == b"A"
    block = bytes([0x60]) + b"ABCDEF" + struct.pack("<H", 6)
    assert boot2_probe.lz4_block_decompress(block) == b"ABCDEFABCD"
    ext = bytes([0xF0, 5]) + bytes(range(20))
    assert boot2_probe.lz4_block_decompress(ext) == bytes(range(20))
    with pytest.raises(ValueError):
        boot2_probe.lz4_block_decompress(bytes([0x60]) + b"ABCDEF" + b"\x06")
    with pytest.raises(ValueError):
        boot2_probe.lz4_block_decompress(b"\x70" + b"7-chars!")


def _lz4_frame(flg, blocks, content_size=0, dict_id=0, block_cksum=None,
               content_cksum=b"\x00\x00\x00\x00"):
    # Vectors hand-derived from the LZ4 frame format spec v1.6.x
    # (FLG bits: 5 B.Indep, 4 B.Checksum, 3 C.Size, 2 C.Checksum,
    # 1 reserved=0, 0 DictID); no local lz4 encoder in env (checked:
    # no lz4 CLI, no python lz4 module). Checksum bytes are dummies —
    # the probe skips them without xxh32 verification.
    frame = struct.pack("<I", 0x184D2204) + bytes([flg, 0x40, 0x00])
    if flg & 0x08:
        frame += struct.pack("<Q", content_size)
    if flg & 0x01:
        frame += struct.pack("<I", dict_id)
    for data, uncompressed in blocks:
        size = len(data) | (0x80000000 if uncompressed else 0)
        frame += struct.pack("<I", size) + data
        if flg & 0x10:
            frame += block_cksum or b"\x00\x00\x00\x00"
    frame += struct.pack("<I", 0)
    if flg & 0x04:
        frame += content_cksum
    return frame


_LIT_BLOCK = bytes([0x60]) + b"ABCDEF"
_MATCH_EXT = 0x45C - 4 - 15
_MATCH_BLOCK = (bytes([0x4F]) + b"abcd" + struct.pack("<H", 4)
                + b"\xff" * (_MATCH_EXT // 255) + bytes([_MATCH_EXT % 255]))


def test_lz4_frame_minimal():
    out = boot2_probe.lz4_frame_decompress(
        _lz4_frame(0x40, [(_LIT_BLOCK, False)]))
    assert out == b"ABCDEF"
    with pytest.raises(ValueError):
        boot2_probe.lz4_frame_decompress(b"\x04\x22\x00\x00")


def test_lz4_frame_block_independence_no_skip():
    out = boot2_probe.lz4_frame_decompress(
        _lz4_frame(0x60, [(_LIT_BLOCK, False), (_LIT_BLOCK, False)]))
    assert out == b"ABCDEFABCDEF"


def test_lz4_frame_content_size_dictid_block_checksum():
    raw = b"U" * 0x500
    frame = _lz4_frame(0x59, [(raw, True)], content_size=len(raw),
                       dict_id=0x11223344)
    assert boot2_probe.lz4_frame_decompress(frame) == raw


def test_lz4_frame_content_checksum():
    raw = b"U" * 0x500
    frame = _lz4_frame(0x44, [(raw, True)])
    assert boot2_probe.lz4_frame_decompress(frame) == raw


def test_lz4_frame_reserved_bit_rejected():
    frame = _lz4_frame(0x42, [(_LIT_BLOCK, False)])
    with pytest.raises(ValueError, match="reserved"):
        boot2_probe.lz4_frame_decompress(frame)


def test_lz4_frame_match_expansion():
    out = boot2_probe.lz4_frame_decompress(
        _lz4_frame(0x40, [(_MATCH_BLOCK, False)]))
    assert len(out) == 4 + 0x45C
    assert out == b"abcd" * ((4 + 0x45C) // 4)


def _lz4_legacy(blocks):
    frame = struct.pack("<I", 0x184C2102)
    for data, uncompressed in blocks:
        size = len(data) | (0x80000000 if uncompressed else 0)
        frame += struct.pack("<I", size) + data
    return frame + struct.pack("<I", 0)


def test_lz4_legacy_multiblock():
    raw = b"V" * 0x500
    frame = _lz4_legacy([(_LIT_BLOCK, False), (raw, True)])
    assert boot2_probe.lz4_legacy_decompress(frame) == b"ABCDEF" + raw
    with pytest.raises(ValueError):
        boot2_probe.lz4_legacy_decompress(b"\x02\x21\x4c\x18")


def test_comp_sweep_hits_zlib_and_lz4():
    payload = zlib.compress(b"z-data" * 0x400)
    blob = b"JUNKJUNK" + payload
    hits = boot2_probe.comp_sweep(blob)
    algos = {h[0] for h in hits}
    assert "zlib" in algos
    assert any(h[1] == 8 for h in hits if h[0] == "zlib")
    raw = b"W" * 0x500
    frame = struct.pack("<I", 0x184D2204) + bytes([0x40, 0x40, 0x00])
    frame += struct.pack("<I", 0x80000000 | len(raw)) + raw
    frame += struct.pack("<I", 0)
    hits2 = boot2_probe.comp_sweep(b"JUNK" + frame)
    assert any(h[0] == "lz4-frame" and h[1] == 4 for h in hits2)
    assert boot2_probe.comp_sweep(b"JUNK" + b"\x00" * 0x20) == []


def test_riscv_profile_pattern_level():
    ws = [(0x1D << 2) | ((i & 0x1F) << 7) | (0xAB << 12) for i in range(64)]
    blob = struct.pack("<%dI" % len(ws), *ws)
    rv = boot2_probe.riscv_profile(blob)
    assert rv["frac_major"] == pytest.approx(1.0)
    assert rv["hist_top"][0][0] == 0x1D
    rnd = boot2_probe.riscv_profile(random.Random(3).randbytes(0x400))
    assert rnd["frac_major"] < 0.6


def test_arm_profile_pattern_level():
    blob = b"".join(struct.pack("<H", 0xE800 | (i & 0xFF)) for i in range(64))
    arm = boot2_probe.arm_profile(blob)
    assert arm["t32_prefix_frac"] == pytest.approx(1.0)
    rnd = boot2_probe.arm_profile(random.Random(4).randbytes(0x400))
    assert rnd["t32_prefix_frac"] == pytest.approx(0.094, abs=0.05)
    assert 0.8 < rnd["a32_cond_frac"] <= 1.0


def test_cross_skeleton_headers_and_words():
    body_a = bytes((i * 3) % 256 for i in range(0x80))
    body_b = bytearray(body_a)
    body_b[0x20] ^= 0xFF
    pa = boot2_probe.parse_boot2(mk_region(body_a), 0)
    pb = boot2_probe.parse_boot2(mk_region(bytes(body_b)), 0)
    sk = boot2_probe.cross_skeleton(pa, pb)
    assert sk["dw0_eq"] is True
    assert sk["dw1_a"] == sk["dw1_b"]
    assert sk["head_common"] == 8
    assert sk["word_match_frac"] == pytest.approx(31 / 32, abs=1e-3)
    assert sk["md5_a"] != sk["md5_b"]


def test_cross_skeleton_tiny_bodies_graceful():
    pa = boot2_probe.parse_boot2(mk_region(b"\x11\x22\x33\x44" * 2), 0)
    pb = boot2_probe.parse_boot2(
        mk_region(b"\x11\x22\x33\x44\x00\x00\x00\x01"), 0)
    sk = boot2_probe.cross_skeleton(pa, pb)
    assert sk["dw0_eq"] is True
    assert sk["head_common"] == 3
    assert sk["word_match_frac"] == 0.5


def test_main_smoke_json(tmp_path):
    body = bytes((i * 7) % 256 for i in range(0x100))
    img = b"\xff" * 0x1000 + mk_region(body) + b"\xff" * 0x100
    body2 = bytearray(body)
    body2[0x40] ^= 0x55
    pa = tmp_path / "a.bin"
    pb = tmp_path / "b.bin"
    pa.write_bytes(img)
    pb.write_bytes(b"\xff" * 0x1000 + mk_region(bytes(body2)) + b"\xff")
    out = tmp_path / "report.json"
    rc = boot2_probe.main([str(pa), str(pb), "--json", str(out)])
    assert rc == 0
    rep = json.loads(out.read_text())
    assert rep["a"]["parse"]["status"] == "ok"
    assert rep["a"]["parse"]["crc_ok"] is True
    assert rep["cross_ab"]["dw0_eq"] is True
    for item in (rep["a"], rep["b"]):
        for key in ("entropy", "irisc", "irisc_random", "compress",
                    "riscv", "arm"):
            assert key in item


@pytest.mark.slow
def test_real_cx7_pair_and_ref_shape():
    if not (CX7_A.is_file() and CX7_B.is_file() and CX6DX_REF.is_file()):
        pytest.skip("cx7/cx6dx refs not present")
    rep = boot2_probe.build_report(CX7_A, CX7_B, CX6DX_REF)
    assert rep["a"]["parse"]["dw0"] == 0x20400040
    assert rep["a"]["parse"]["dw1"] == 0x1201
    assert rep["a"]["parse"]["size"] == 0x4814
    assert rep["b"]["parse"]["size"] == 0x4ED4
    assert rep["ref"]["parse"]["size"] == 0x3F2C
    assert rep["a"]["parse"]["crc_ok"] is True
    assert rep["b"]["parse"]["crc_ok"] is True
    assert rep["ref"]["parse"]["crc_ok"] is True
    assert rep["cross_ab"]["dw0_eq"] is True
    assert rep["cross_ref"]["dw0_eq"] is True
