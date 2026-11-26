"""cx4lx-fdr-gate tests: build_arc_f (arc F / F3 patch candidates).

Pinned targets (T1 verdict, journal
docs/superpowers/journal/2026-11-23-serdes-arc-f-task-01.md + task-02
brief; corpus ground truth re-verified 2026-11-24):

  * base = refs 14.32.1912 MCX4131A-GCA stock (0x12: +0x158=0x30,
    +0x283=0x00, +0x2c5=0x00, lcl +0x30b=0x3b, +0x317=0x00);
  * p1     = single byte  0x12+0x158 0x30->0x10 (FCA-like FDR class);
  * p2     = 3 bytes      +0x158->0x31, +0x283->0x12, +0x2c5->0x10
             (ECA-like EDR class; byte view of the big-endian dwords
             dw@+0x280 / dw@+0x2c4);
  * p2full = p2 + lcl +0x30b/+0x317 from the FCA corpus reference
             (MCX456A-FCA@12_28_4706: 5b/5b);
  * P3 inactive (carrier not refuted), 0x11+0x35 parked (owner).

Gates per image: verify_image + burn_order + fresh 0xA0 + byte-diff
canary whose allowed zones (0x12 entry CRCs, 0xA0 digest slot + entry
CRCs) are enumerated from ITOC metadata, never from the observed diff.
"""
import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "probes" / "cx4lx-fdr-gate"))

import mlxfwutil as fw  # noqa: E402
import build_arc_f as bf  # noqa: E402

CORPUS = REPO / "build" / "corpus"
FCA_REF = "cx4/12_28_4706/MCX456A-FCA"
BASE_REFS = REPO / "refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin"


# ------------------------------------------------------------- mini fixture

def mini_fs3(class_0x158=0x30, lcl0=0x3B, lcl1=0x00, b283=0x00, b2c5=0x00,
             vpi=0x0A):
    """Minimal FS3 image with Lx-GCA-like 0x12 + EN 0x11 + 0xA0 + dev 0xE0."""
    buf = bytearray(b"\xff" * 0x20000)
    buf[0:16] = fw.CNTX_MAGIC
    buf[0x24:0x28] = b"\x03\x17\x01\x01"
    itoc = 0x1000
    hdr = bytearray(32)
    hdr[0:16] = fw.ITOC_HDR
    hdr[0x1E:0x20] = struct.pack(">H", fw.crc16_mlx(bytes(hdr[:28])))
    buf[itoc:itoc + 32] = hdr
    sec12 = bytearray(b"\x00" * 0xC00)
    sec12[0x151] = 0x27
    sec12[0x158] = class_0x158
    sec12[0x159] = 0xC0
    sec12[0x283] = b283
    sec12[0x2C5] = b2c5
    sec12[0x30B] = lcl0
    sec12[0x317] = lcl1
    sec11 = bytearray(b"\x00" * 0x4C0)
    sec11[0x2AF] = vpi
    sig = bytearray(0x40)
    sig[0x20:0x40] = hashlib.sha256(b"stale-placeholder").digest()

    def entry(i, typ, size, addr, rel=1, dev=0, data=None):
        e = bytearray(32)
        e[0] = typ
        fw.set_bits(e, 8, 22, size // 4)
        fw.set_bits(e, 160, 1, rel)
        fw.set_bits(e, 161, 29, addr // 4)
        fw.set_bits(e, 206, 1, dev)
        if data is not None:
            buf[addr:addr + size] = data
        fw.set_bits(e, 208, 16, fw.crc16_mlx(bytes(buf[addr:addr + size])))
        fw.set_bits(e, 240, 16, fw.crc16_mlx(bytes(e[:28])))
        buf[itoc + 32 + i * 32:itoc + 64 + i * 32] = e

    entry(0, 0x12, 0xC00, 0x2000, data=bytes(sec12))
    entry(1, 0x11, 0x4C0, 0x2D00, data=bytes(sec11))
    entry(2, 0xA0, 0x40, 0x3200, data=bytes(sig))
    entry(3, 0xE0, 0x140, 0x10000, rel=0, dev=1, data=b"\x00" * 0x140)
    entry(4, 0xFF, 0, 0)
    return bytes(buf)


# ------------------------------------------------------------ variant table

def test_variant_edits_pins():
    assert bf.variant_edits("p1") == [(0x12, 0x158, b"\x10")]
    assert bf.variant_edits("p2") == [(0x12, 0x158, b"\x31"),
                                      (0x12, 0x283, b"\x12"),
                                      (0x12, 0x2C5, b"\x10")]
    full = bf.variant_edits("p2full", lcl=(0x5B, 0x5B))
    assert full[:3] == bf.variant_edits("p2")
    assert full[3:] == [(0x12, 0x30B, b"\x5b"), (0x12, 0x317, b"\x5b")]


def test_variant_edits_unknown_rejected():
    with pytest.raises(bf.BuildError):
        bf.variant_edits("p3")
    with pytest.raises(bf.BuildError):
        bf.variant_edits("p1full")


def test_variant_p1v_pins():
    # P1v = P1 class byte + VPI byte 0x11+0x2af 0x0a->0x07 (EN->VPI,
    # arc D build_l34.py:88,106-109 VPI_SEC/VPI_OFF/VPI_OLD/VPI_NEW)
    assert bf.variant_edits("p1v") == [(0x12, 0x158, b"\x10"),
                                       (0x11, 0x2AF, b"\x07")]
    assert bf.variant_edits("p1v")[:1] == bf.variant_edits("p1")


def test_p2full_requires_lcl():
    with pytest.raises(bf.BuildError):
        bf.variant_edits("p2full")


def test_expected_base_preconditions_pin():
    assert bf.EXPECTED_BASE == {
        0x12: {0x158: 0x30, 0x283: 0x00, 0x2C5: 0x00,
               0x30B: 0x3B, 0x317: 0x00},
        0x11: {0x2AF: 0x0A},  # EN stock (VPI site, arc D pin)
    }


# ------------------------------------------------------------- build (mini)

def test_check_base_rejects_non_eth_base():
    img = fw.Image(mini_fs3(class_0x158=0x31), "<mini>")
    with pytest.raises(bf.BuildError):
        bf.check_base(img)


def test_check_base_rejects_non_en_vpi():
    img = fw.Image(mini_fs3(vpi=0x07), "<mini>")
    with pytest.raises(bf.BuildError):
        bf.check_base(img)


def test_build_p1_mini_all_gates():
    out, rep = bf.build(mini_fs3(), "p1")
    assert rep["gates"] == {"verify_image": True, "burn_order": True,
                            "sig_fresh": True, "canary": True}
    vimg = fw.Image(out, "<out>")
    assert fw.verify_image(vimg) == []
    assert fw.sig_status(vimg)[0] == "fresh"
    can = rep["canary"]
    assert can["ok"] and can["missing"] == [] and can["extra"] == []
    assert [(c["rel"], c["old"], c["new"]) for c in can["content"]] == [
        (0x158, 0x30, 0x10)]
    # non-tautology: control zones enumerated from ITOC metadata and
    # disjoint from the patch byte
    kinds = {z["kind"] for z in can["zones"]}
    assert kinds == {"patch", "sec_crc", "entry_crc", "digest_slot"}
    for z in can["zones"]:
        if z["kind"] == "patch":
            assert z["rel"] == 0x158 and z["size"] == 1


def test_build_p1v_mini_two_content_bytes():
    out, rep = bf.build(mini_fs3(), "p1v")
    assert all(rep["gates"].values())
    can = rep["canary"]
    assert can["ok"] and can["extra"] == [] and can["missing"] == []
    assert [(c["section"], c["rel"], c["old"], c["new"])
            for c in can["content"]] == [
        ("0x12", 0x158, 0x30, 0x10), ("0x11", 0x2AF, 0x0A, 0x07)]
    # entry-CRC control zones enumerated for BOTH touched sections
    notes = {z.get("note") for z in can["zones"] if z["kind"] == "sec_crc"}
    assert notes == {"0x12 entry sec_crc", "0x11 entry sec_crc",
                     "0xA0 entry sec_crc"}
    vimg = fw.Image(out, "<out>")
    assert fw.verify_image(vimg) == []
    assert fw.sig_status(vimg)[0] == "fresh"


def test_build_p2full_mini_canary_five_bytes():
    out, rep = bf.build(mini_fs3(), "p2full", lcl=(0x5B, 0x5B))
    can = rep["canary"]
    assert can["ok"] and can["extra"] == [] and can["missing"] == []
    assert [(c["rel"], c["old"], c["new"]) for c in can["content"]] == [
        (0x158, 0x30, 0x31), (0x283, 0x00, 0x12), (0x2C5, 0x00, 0x10),
        (0x30B, 0x3B, 0x5B), (0x317, 0x00, 0x5B)]
    assert rep["gates"]["sig_fresh"] is True


def test_build_deterministic():
    a, _ = bf.build(mini_fs3(), "p2")
    b, _ = bf.build(mini_fs3(), "p2")
    assert a == b


# ---------------------------------------------------------------- canary

def test_canary_rejects_unexpected_byte():
    out, _ = bf.build(mini_fs3(), "p1")
    bad = bytearray(out)
    bad[0x2100] ^= 0xFF  # inside 0x12, not a patch offset
    base_img = fw.Image(mini_fs3(), "<base>")
    bad_img = fw.Image(bytes(bad), "<bad>")
    can = bf.byte_diff_canary(base_img, bad_img, bf.variant_edits("p1"))
    assert can["ok"] is False
    assert can["extra"] and can["extra"][0]["abs"] == 0x2100


def test_canary_rejects_missing_patch_byte():
    out, _ = bf.build(mini_fs1 := mini_fs3(), "p1")
    reverted = bytearray(out)
    e = fw.Image(mini_fs1, "<base>").find_entry("ITOC", 0x12)
    a = fw.Image(mini_fs1, "<base>").sec_abs(e)
    reverted[a + 0x158] = 0x30  # undo the class byte, keep CRCs stale
    can = bf.byte_diff_canary(fw.Image(mini_fs1, "<base>"),
                              fw.Image(bytes(reverted), "<rev>"),
                              bf.variant_edits("p1"))
    assert can["ok"] is False and can["missing"]


def test_canary_allows_only_enumerated_crc_digest_zones():
    out, rep = bf.build(mini_fs3(), "p2full", lcl=(0x5B, 0x5B))
    base_img = fw.Image(mini_fs3(), "<base>")
    out_img = fw.Image(out, "<out>")
    can = rep["canary"]
    allowed = [(z["abs"], z["abs"] + z["size"]) for z in can["zones"]]
    diff = [i for i in range(len(out))
            if base_img.buf[i] != out_img.buf[i]]
    # every differing byte is inside some enumerated zone (strict)
    assert diff
    for i in diff:
        assert any(lo <= i < hi for lo, hi in allowed), hex(i)
    # and the digest slot really moved (report is not vacuous)
    assert any(z["kind"] == "digest_slot" and z["changed"]
               for z in can["zones"])


# -------------------------------------------------------------------- CLI

def test_cli_mini(tmp_path):
    base = tmp_path / "base.bin"
    base.write_bytes(mini_fs3())
    out = tmp_path / "arc-f-p1.bin"
    js = tmp_path / "report.json"
    rc = bf.main(["--base", str(base), "--variant", "p1",
                  "--out", str(out), "--json", str(js)])
    assert rc == 0 and out.is_file()
    rep = json.loads(js.read_text())
    assert rep["variant"] == "p1" and all(rep["gates"].values())
    assert rep["md5"] == hashlib.md5(out.read_bytes()).hexdigest()


def test_cli_rejects_wrong_base(tmp_path):
    base = tmp_path / "base.bin"
    base.write_bytes(mini_fs3(class_0x158=0x10))
    rc = bf.main(["--base", str(base), "--variant", "p1",
                  "--out", str(tmp_path / "x.bin")])
    assert rc != 0 and not (tmp_path / "x.bin").exists()


def test_cli_rejects_bad_variant(tmp_path):
    base = tmp_path / "base.bin"
    base.write_bytes(mini_fs3())
    with pytest.raises(SystemExit):
        bf.main(["--base", str(base), "--variant", "p9",
                 "--out", str(tmp_path / "x.bin")])


# ------------------------------------------------- refs/corpus (slow, real)

@pytest.mark.slow
class TestRefsBuilds:
    def _base(self):
        if not BASE_REFS.is_file():
            pytest.skip("refs base image not present")
        return BASE_REFS.read_bytes()

    def test_p1_from_refs(self):
        out, rep = bf.build(self._base(), "p1")
        assert all(rep["gates"].values())
        assert [(c["rel"], c["old"], c["new"]) for c in rep["canary"]["content"]] == [
            (0x158, 0x30, 0x10)]
        again, _ = bf.build(self._base(), "p1")
        assert again == out  # deterministic

    def test_p1v_from_refs(self):
        out, rep = bf.build(self._base(), "p1v")
        assert all(rep["gates"].values())
        got = [(c["section"], c["rel"], c["old"], c["new"])
               for c in rep["canary"]["content"]]
        assert got == [("0x12", 0x158, 0x30, 0x10),
                       ("0x11", 0x2AF, 0x0A, 0x07)]
        again, _ = bf.build(self._base(), "p1v")
        assert again == out  # deterministic

    def test_p2full_from_refs_with_corpus_lcl(self):
        if not (CORPUS / FCA_REF / "sections/12/raw.bin").is_file():
            pytest.skip("corpus FCA reference absent")
        ref = bf.fca_lcl_from_corpus(CORPUS)
        assert ref["class_0x158"] == 0x10  # guard: reference is FCA
        assert (ref["lcl0"], ref["lcl1"]) == (0x5B, 0x5B)
        out, rep = bf.build(self._base(), "p2full",
                            lcl=(ref["lcl0"], ref["lcl1"]))
        assert all(rep["gates"].values())
        got = [(c["rel"], c["old"], c["new"]) for c in rep["canary"]["content"]]
        assert got == [(0x158, 0x30, 0x31), (0x283, 0x00, 0x12),
                       (0x2C5, 0x00, 0x10), (0x30B, 0x3B, 0x5B),
                       (0x317, 0x00, 0x5B)]


@pytest.mark.slow
def test_fca_lcl_reference_values():
    if not (CORPUS / FCA_REF / "sections/12/raw.bin").is_file():
        pytest.skip("corpus FCA reference absent")
    ref = bf.fca_lcl_from_corpus(CORPUS)
    assert ref["class_0x158"] == 0x10
    assert ref["lcl0"] == 0x5B and ref["lcl1"] == 0x5B
