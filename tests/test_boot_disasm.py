import importlib.util
import json
import struct
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

_spec = importlib.util.spec_from_file_location(
    "boot_disasm",
    REPO / "scripts" / "probes" / "securefw-arc-b" / "boot_disasm.py")
boot_disasm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(boot_disasm)

_spec_a = importlib.util.spec_from_file_location(
    "boot2_probe",
    REPO / "scripts" / "probes" / "securefw-arc-a" / "boot2_probe.py")
boot2_probe = importlib.util.module_from_spec(_spec_a)
_spec_a.loader.exec_module(boot2_probe)

from scripts.irisc import assemble  # noqa: E402
from scripts.irisc.profiles import load_profile  # noqa: E402

CX7_A = (REPO / "refs" / "fw" / "cx-7" / "dumps" / "cx7_firmware_dumps"
         / "28.33.0751" / "orig_firmware.bin")
CX7_B = (REPO / "refs" / "fw" / "cx-7" / "dumps" / "cx7_firmware_dumps"
         / "28.33.0800.bin")
CX6DX = (REPO / "refs" / "fw" / "cx-5-6" /
         "fw-ConnectX6Dx-rel-22_50_1002-MCX623435AE-CDA_Ax-UEFI-14.43."
         "10-FlexBoot-3.9.101.bin")

HAVE_REFS = CX7_A.is_file() and CX7_B.is_file()


def asm(text, base=0):
    blob = assemble(text, base=base)
    return struct.unpack(">%dI" % (len(blob) // 4), blob)


def mk_region(body, dw0=0x20400040, trailer=0x20400244):
    region = struct.pack(">II", dw0, len(body) // 4) + body
    region += struct.pack(">I", trailer)
    return region + struct.pack(">I", boot2_probe.crc16_mlx(region))


def test_disasm_region_lines_unknown_and_base():
    words = asm("addi r4,zero,0x34c8\n"
                "op0x36 zero,r5,zero imm=0x0004") + (0xFFFFFFFF,)
    text = boot_disasm.disasm_region(words, 0x20500040, None)
    lines = text.split("\n")
    assert lines[0].startswith("20500040  000434c8  addi r4,zero,0x34c8")
    assert "op0x36" in lines[1]
    assert "alu.0x1ff" in lines[2]
    assert all(len(l.split("  ")[0]) == 8 for l in lines)


def test_disasm_region_profile_annotation():
    prof = load_profile("cx7")
    words = asm("op0x36 zero,r5,zero imm=0x0004")
    text = boot_disasm.disasm_region(words, 0, prof)
    assert "[cx7]" in text


def test_disasm_region_header():
    text = boot_disasm.disasm_region((0x000434C8,), 0, None,
                                     header=["# image: x.bin", "# base: 0x0"])
    assert text.split("\n")[0] == "# image: x.bin"
    assert "addi r4,zero,0x34c8" in text.split("\n")[2]


def test_call_targets_direct():
    words = asm("jump 0x10\ncall 0x18\naddi r1,zero,0x1\ncall 0x100",
                base=0)
    got = boot_disasm.call_targets(words, 0)
    assert [t["kind"] for t in got] == ["jump", "call", "call"]
    assert [t["off"] for t in got] == [0, 4, 12]
    assert [t["target"] for t in got] == [0x10, 0x18, 0x100]
    shifted = boot_disasm.call_targets(words, 0x1000)
    assert [t["target"] for t in shifted] == [0x1010, 0x1018, 0x1100]
    assert boot_disasm.call_targets((0x004434C8, 0x004434C8), 0) == []


def test_xref_constants_addi_idiom():
    words = asm("addi r4,zero,0x34c8\n"
                "or r1,r1,r1\n"
                "addi.hi r4,r4,0x2080")
    got = boot_disasm.xref_constants(words, 0)
    assert got["load_base"] == [{"off": 0, "value": 0x208034C8,
                                 "idiom": "addi/addi.hi"}]


def test_xref_constants_set23_idiom():
    words = asm("set2 r5,zero,0x30d0\n"
                "or r1,r1,r1\n"
                "set3 r6,r5,0x1234")
    got = boot_disasm.xref_constants(words, 0)
    assert got["cr_30d0"] == [{"off": 0, "value": 0x30D01234,
                               "idiom": "set2/set3"}]


def test_xref_constants_window_and_mismatch():
    filler = "or r1,r1,r1\n" * 4
    words = asm("addi r4,zero,0x34c8\n" + filler + "addi.hi r4,r4,0x2080")
    assert boot_disasm.xref_constants(words, 0) == {}
    words = asm("addi r4,zero,0x34c8\naddi.hi r5,r5,0x2080")
    assert boot_disasm.xref_constants(words, 0) == {}


def test_xref_constants_unclassified_value():
    words = asm("set2 r5,zero,0x0\nset3 r6,r5,0x1")
    assert boot_disasm.xref_constants(words, 0) == {}
    words = asm("set2 r5,zero,0x1868\nset3 r6,r5,0x550")
    assert "cr_1868" in boot_disasm.xref_constants(words, 0)
    words = asm("set2 r5,zero,0xc13\nset3 r6,r5,0x6440")
    assert "cr_val_0c1" in boot_disasm.xref_constants(words, 0)
    words = asm("set2 r5,zero,0xe\nset3 r6,r5,0x34fc")
    assert "ram_low" in boot_disasm.xref_constants(words, 0)


def test_load_region_boot2_synthetic_container():
    ws = asm("addi r4,zero,0x34c8\n"
             "addi.hi r4,r4,0x2080\n"
             "call 0x8\n"
             "addi zero,zero,0x1")
    body = struct.pack(">%dI" % len(ws), *ws)
    image = b"\xff" * 0x1000 + mk_region(body) + b"\xff" * 0x100
    reg = boot_disasm.load_region(image, "boot2", boot2_off=0x1000)
    assert reg["status"] == "ok"
    assert reg["base"] == 0
    assert len(reg["words"]) == 4
    assert reg["meta"]["crc_ok"] is True
    assert boot_disasm.disasm_region(reg["words"], reg["base"], None)


def test_cli_boot2_region(tmp_path):
    body = struct.pack(">4I", *asm("addi r4,zero,0x34c8\n"
                                   "addi.hi r4,r4,0x2080\n"
                                   "call 0x8\n"
                                   "addi zero,zero,0x1"))
    image = b"\xff" * 0x1000 + mk_region(body) + b"\xff" * 0x100
    img = tmp_path / "img.bin"
    img.write_bytes(image)
    out = tmp_path / "out.dis.txt"
    calls = tmp_path / "out.calls.json"
    rc = boot_disasm.main(["--image", str(img), "--region", "boot2",
                           "--out", str(out), "--calls-out", str(calls),
                           "--profile", "none"])
    assert rc == 0
    lines = out.read_text().split("\n")
    assert lines[0].startswith("# image:")
    assert "addi r4,zero,0x34c8" in out.read_text()
    data = json.loads(calls.read_text())
    assert data["base"] == 0
    assert data["calls"][0]["kind"] == "call"
    assert data["xref"]["load_base"][0]["value"] == 0x208034C8


@pytest.mark.slow
@pytest.mark.skipif(not HAVE_REFS, reason="refs images absent")
def test_real_boot2_pair_and_cx6dx():
    buf_a = CX7_A.read_bytes()
    reg = boot_disasm.load_region(buf_a, "boot2")
    assert reg["status"] == "ok" and reg["meta"]["crc_ok"] is True
    assert len(reg["words"]) == 4609
    calls = boot_disasm.call_targets(reg["words"], reg["base"])
    assert len(calls) == 192
    assert len({t["target"] for t in calls}) > 50
    xref = boot_disasm.xref_constants(reg["words"], reg["base"])
    assert xref["load_base"]
    assert 0x20710000 in [e["value"] for e in xref["load_base"]]
    reg = boot_disasm.load_region(CX7_B.read_bytes(), "boot2")
    assert len(reg["words"]) == 5041
    assert len(boot_disasm.call_targets(reg["words"], 0)) == 194
    reg = boot_disasm.load_region(CX6DX.read_bytes(), "boot2")
    assert reg["status"] == "ok" and reg["meta"]["crc_ok"] is True
    assert len(reg["words"]) == 4039


@pytest.mark.slow
@pytest.mark.skipif(not HAVE_REFS, reason="refs images absent")
def test_real_sections_boot3_iron():
    img = boot_disasm.open_image(CX7_A.read_bytes(), "A")
    reg = boot_disasm.load_section(img, 0x0F)
    assert reg["meta"]["size"] == 0x2590
    assert reg["base"] == 0x20500040
    assert reg["meta"]["entry"] == 0x20500044
    assert len(reg["words"]) == 0x2590 // 4
    reg = boot_disasm.load_section(boot_disasm.open_image(
        CX7_B.read_bytes(), "B"), 0x0F)
    assert len(reg["words"]) == 0x6A20 // 4
    reg = boot_disasm.load_section(img, 0x05)
    assert len(reg["words"]) == 0x1B574 // 4
    assert reg["base"] == 0x20710000


@pytest.mark.slow
@pytest.mark.skipif(not HAVE_REFS, reason="refs images absent")
def test_real_no_sw_sha_in_boot2_listings():
    for path, n_words in ((CX7_A, 4609), (CX7_B, 5041)):
        buf = path.read_bytes()
        reg = boot_disasm.load_region(buf, "boot2")
        text = boot_disasm.disasm_region(reg["words"], 0, None)
        for word in ("428a2f98", "71374491", "6a09e667", "d728ae22"):
            assert word not in text.lower()
