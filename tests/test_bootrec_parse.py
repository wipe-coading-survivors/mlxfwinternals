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
    "bootrec_parse",
    Path(__file__).resolve().parent.parent / "scripts" / "probes"
    / "securefw-arc-a" / "bootrec_parse.py")
bootrec_parse = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bootrec_parse)

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
           "UEFI-14.28.15-FlexBoot-3.6.804.bin")


def w_at(region, off, value):
    struct.pack_into(">I", region, off, value)


def synth_bootrec(word0=0x418, entries=(), entry_offs=(),
                  config=(), config_off=0x138, trailer=0x0e67,
                  trailer_off=0x3f0, size=0x400):
    """Synthetic boot_record region in the 2026-09-20 journal format:
    sparse BE-DW init table in an erased (0xFF) field."""
    region = bytearray(b"\xff" * size)
    w_at(region, 0, word0)
    for off, (addr, value, count, *rest) in zip(entry_offs, entries):
        w_at(region, off, addr)
        w_at(region, off + 4, value)
        w_at(region, off + 8, count)
        if rest and rest[0] is not None:
            w_at(region, off + 12, rest[0])
    for i, w in enumerate(config):
        w_at(region, config_off + 4 * i, w)
    if trailer is not None:
        w_at(region, trailer_off, trailer)
    return bytes(region)


CX7_ENTRIES = [
    (0x30D02650, 0x0C136440, 5, 0),
    (0x30D03650, 0x0C1B6400, 7, 0),
    (0x30D02D50, 0x0C170A00, 1, 0),
    (0x30D03C50, 0x0C1EB880, 5, 0),
]
CX7_OFFSETS = [0x18, 0x28, 0x38, 0x48]
CX6_ENTRIES = [
    (0x18680550, 0x00058106, 7),
    (0x186804D0, 0x000522D1, 5),
]


def test_sparse_and_nonzero_words():
    region = bytearray(b"\xff" * 0x40)
    w_at(region, 0, 0x418)
    w_at(region, 4, 0)
    w_at(region, 0x10, 0x30D02650)
    sparse = bootrec_parse.sparse_words(bytes(region))
    assert [o for o, _v in sparse] == [0, 4, 0x10]
    assert dict(sparse) == {0: 0x418, 4: 0, 0x10: 0x30D02650}
    nonzero = bootrec_parse.nonzero_words(bytes(region))
    assert [o for o, _v in nonzero] == [0, 0x10]


def test_cr_init_entries_stride4_and_stride3():
    r7 = synth_bootrec(entries=CX7_ENTRIES, entry_offs=CX7_OFFSETS)
    ents = bootrec_parse.cr_init_entries(r7)
    assert len(ents) == 4
    assert ents[0] == {"off": 0x18, "addr": 0x30D02650,
                       "value": 0x0C136440, "count": 5,
                       "addr_class": 0x30D0}
    assert ents[3]["addr"] == 0x30D03C50
    r6 = synth_bootrec(word0=0x84, entries=CX6_ENTRIES,
                       entry_offs=[0x30, 0x3C])
    ents6 = bootrec_parse.cr_init_entries(r6)
    assert len(ents6) == 2
    assert ents6[0]["addr_class"] == 0x1868
    assert ents6[1] == {"off": 0x3C, "addr": 0x186804D0,
                        "value": 0x000522D1, "count": 5,
                        "addr_class": 0x1868}


def test_cr_init_entries_negative():
    region = bytearray(b"\xff" * 0x100)
    w_at(region, 0, 0x15805414)
    w_at(region, 4, 0x50674000)
    w_at(region, 8, 0x41C8F1A8)
    assert bootrec_parse.cr_init_entries(bytes(region)) == []
    # addr word followed by erased value -> no entry
    region2 = bytearray(b"\xff" * 0x40)
    w_at(region2, 0, 0x30D02650)
    assert bootrec_parse.cr_init_entries(bytes(region2)) == []
    # count out of window (0x40) -> no entry
    region3 = bytearray(b"\xff" * 0x40)
    w_at(region3, 0, 0x30D02650)
    w_at(region3, 4, 0x0C136440)
    w_at(region3, 8, 0x40)
    assert bootrec_parse.cr_init_entries(bytes(region3)) == []


def test_nonzero_runs():
    config = [0x58407E80, 0x101AA404, 0x38E244C8, 0x381CB214,
              0x172C8910]
    region = bytearray(synth_bootrec(config=config, config_off=0x138))
    w_at(region, 0x1C0, 0x11223344)
    w_at(region, 0x1C4, 0x55667788)
    runs = bootrec_parse.nonzero_runs(bytes(region), min_words=4)
    spans = [(r["start"], r["end"]) for r in runs]
    assert (0x138, 0x138 + 4 * len(config)) in spans
    assert all(r["nwords"] >= 4 for r in runs)


def test_nonzero_runs_min_threshold():
    region = synth_bootrec()
    buf = bytearray(region)
    for i, off in enumerate((0x200, 0x204, 0x208)):
        w_at(buf, off, 0x10 + i)
    runs = bootrec_parse.nonzero_runs(bytes(buf), min_words=4)
    assert all(r["nwords"] >= 4 for r in runs)
    assert not any(r["start"] == 0x200 for r in runs)
    runs3 = bootrec_parse.nonzero_runs(bytes(buf), min_words=3)
    assert any(r["start"] == 0x200 for r in runs3)


def test_repeated_blobs():
    blob = bytes.fromhex("38bdab49ca307b9ac5a928398a418820")
    region = bytearray(b"\xff" * 0x200)
    region[0xEC:0xFC] = blob
    region[0x100:0x110] = blob
    reps = bootrec_parse.repeated_blobs(bytes(region))
    assert any(r["offs"] == [0xEC, 0x100] for r in reps)
    uni = bytearray(b"\x88" * 0x40)
    assert bootrec_parse.repeated_blobs(bytes(uni)) == []


def test_parse_bootrec_roundtrip():
    config = [0x58407E80, 0x101AA404, 0x38E244C8, 0x381CB214,
              0x172C8910, 0x93204E38, 0xC8538E24, 0x264381C8,
              0x38E172C8]
    r7 = synth_bootrec(entries=CX7_ENTRIES, entry_offs=CX7_OFFSETS,
                       config=config, config_off=0x138)
    res = bootrec_parse.parse_bootrec(r7)
    assert res["word0"] == 0x418
    assert len(res["cr_entries"]) == 4
    assert res["trailer"]["off"] == 0x3F0
    assert res["trailer"]["value"] == 0x0E67
    assert res["trailer"]["tag16_class"] is True
    assert res["extent"] == 0x3F4
    assert res["config_block"]["start"] == 0x138
    assert res["config_block"]["nwords"] == len(config)
    r_big = synth_bootrec(trailer=0x00089559, trailer_off=0xFC)
    assert bootrec_parse.parse_bootrec(r_big)["trailer"]["tag16_class"] is False


def test_diff_pair_sites_and_bytes():
    ra = bytearray(synth_bootrec(entries=CX7_ENTRIES,
                                 entry_offs=CX7_OFFSETS))
    rb = bytearray(synth_bootrec(entries=CX7_ENTRIES,
                                 entry_offs=CX7_OFFSETS))
    w_at(ra, 0x214, 0x00000002)             # written word on both sides
    w_at(rb, 0x18, 0x30D03850)             # 1 byte differs
    w_at(rb, 0x1C, 0x0C1CAC00)             # 3 bytes differ
    w_at(rb, 0x20, 0x00000007)             # 1 byte
    w_at(rb, 0x214, 0x00000003)            # standalone, 1 byte
    w_at(rb, 0x3F0, 0x00007E37)            # trailer, 2 bytes
    d = bootrec_parse.diff_pair(bytes(ra), bytes(rb))
    assert d["words_delta"] == 5
    assert d["bytes_delta"] == 8
    sites = {row["off"]: row["site"] for row in d["rows"]}
    assert sites[0x18] == "cr_entry[0]"
    assert sites[0x1C] == "cr_entry[0]"
    assert sites[0x20] == "cr_entry[0]"
    assert sites[0x214] == "standalone"
    assert sites[0x3F0] == "trailer"


def test_diff_pair_identical():
    r = synth_bootrec()
    d = bootrec_parse.diff_pair(r, r)
    assert d["rows"] == []
    assert d["bytes_delta"] == 0 and d["words_delta"] == 0


def test_fingerprint_fields():
    fp = bootrec_parse.fingerprint(
        synth_bootrec(entries=CX7_ENTRIES, entry_offs=CX7_OFFSETS))
    for key in ("word0", "sparse", "nonzero", "cr_entries",
                "addr_classes", "value_classes", "runs",
                "config_block", "trailer", "extent", "tag16"):
        assert key in fp
    assert fp["addr_classes"] == [0x30D0]
    assert fp["value_classes"] == [0x0C13, 0x0C17, 0x0C1B, 0x0C1E]
    assert fp["extent"] == 0x3F4


def test_longest_common_run():
    a = bytes.fromhex("00112233") + bytes.fromhex("38e244c8") + b"\x01"
    b = bytes.fromhex("ff") + bytes.fromhex("38e244c8") + b"\x02\x03"
    size, ia, ib = bootrec_parse.longest_common_run(a, b)
    assert size == 4 and a[ia:ia + size] == bytes.fromhex("38e244c8")


def test_build_report_smoke(tmp_path):
    ra = synth_bootrec()
    rb = synth_bootrec(trailer=0x00007E37)
    pa = tmp_path / "a.bin"
    pb = tmp_path / "b.bin"
    pa.write_bytes(b"\x00" * 0x100 + ra + b"\xff" * 0x100)
    pb.write_bytes(b"\x00" * 0x100 + rb + b"\xff" * 0x100)
    rep = bootrec_parse.build_report(str(pa), str(pb), [])
    json.dumps(rep)
    assert rep["pair"]["words_delta"] == 1
    assert rep["pair"]["rows"][0]["site"] == "trailer"


@pytest.mark.slow
def test_real_pair_and_refs():
    if not (CX7_A.exists() and CX7_B.exists()):
        pytest.skip("refs cx7 images not available")
    buf_a = CX7_A.read_bytes()
    buf_b = CX7_B.read_bytes()
    ra, rb = buf_a[0x100:0x500], buf_b[0x100:0x500]
    pa = bootrec_parse.parse_bootrec(ra)
    pb = bootrec_parse.parse_bootrec(rb)
    assert pa["word0"] == pb["word0"] == 0x418
    assert len(pa["cr_entries"]) == len(pb["cr_entries"]) == 4
    assert pa["extent"] == pb["extent"] == 0x3F4
    assert pa["trailer"]["tag16_class"] is True
    assert pa["trailer"]["value"] != pb["trailer"]["value"]
    blob = bytes.fromhex("38bdab49ca307b9ac5a928398a418820")
    assert any(bytes.fromhex(r["hex"]) == blob
               for r in pa["repeated_blobs"])
    d = bootrec_parse.diff_pair(ra, rb)
    assert d["bytes_delta"] == 11
    assert d["words_delta"] == 7
    offs = {row["off"] for row in d["rows"]}
    assert offs == {0x18, 0x1C, 0x20, 0x28, 0x2C, 0x214, 0x3F0}
    sites = {row["off"]: row["site"] for row in d["rows"]}
    assert sites[0x18] == "cr_entry[0]" and sites[0x28] == "cr_entry[1]"
    assert sites[0x214] == "standalone" and sites[0x3F0] == "trailer"
    if REF_CX6DX.exists():
        f6dx = bootrec_parse.fingerprint(REF_CX6DX.read_bytes()[0x100:0x500])
        assert f6dx["word0"] == 0x84
        assert f6dx["cr_entries"] == 2
        assert f6dx["addr_classes"] == [0x30D0]
        assert f6dx["extent"] == 0x400
        assert f6dx["trailer"]["tag16_class"] is True
    if REF_CX6.exists():
        f6 = bootrec_parse.fingerprint(REF_CX6.read_bytes()[0x100:0x500])
        assert f6["word0"] == 0x84
        assert f6["cr_entries"] == 2
        assert f6["addr_classes"] == [0x1868]
    if REF_CX5.exists():
        f5 = bootrec_parse.fingerprint(REF_CX5.read_bytes()[0x100:0x500])
        assert f5["cr_entries"] == 0
        assert f5["extent"] == 0x100
        assert f5["trailer"]["tag16_class"] is False
