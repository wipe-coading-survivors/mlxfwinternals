"""cx4lx-fdr-gate tests: build_hf2 (arc H-F2 / G2 hf2-max builder).

Pinned targets (plan docs/superpowers/plans/2026-11-25-serdes-arc-hf2.md
task 4; spec 2026-11-24-serdes-arc-hf2 §4; journals
docs/superpowers/journal/2026-11-25-serdes-arc-hf2-task-0{1,2,3}.md):

  * base = refs 14.32.1912 MCX4131A-GCA stock (0x12: +0x158=0x30,
    +0x283=0x00, +0x2c5=0x00, lcl +0x30b=0x3b, +0x317=0x00;
    0x11: +0x2af=0x0a EN);
  * edit set = VPI byte 0x11+0x2af 0x0a->0x07 (arc D pin) + the task-03
    EDR-class tuple 0x12 {+0x158->0x31, +0x283->0x12, +0x2c5->0x10,
    lcl +0x30b->0xfb, +0x317->0xfb} (ECA reference, lcl fb/fb);
  * MAIN_CODE words = task-02 spec hf2-dispatcher-cx4lx-1912.json
    (4 words: dispatcher 0x1be12c + twin 0x1fc488 + polling
    0x1b330c/0x1b335c; 4a043686 -> 00040400) through the cable-gate
    pipeline (decrc -> patch -> clcrc reframe -> ITOC entry CRC);
  * ETH sites = none (task-03 verdict mode=unified, sites=[]);

  * build-ID (Rule 1, exact) right after the ";; Mellanox Technologies
    LTD" line of the 0x30 ini; round-trip extract == edited ini;
  * GUID/MAC = only from explicit CLI args, pinned in the JSON report
    (source: task-01 journal; the real lab identifiers stay in the
    journal / CLI at build time -- tests use synthetic values);
  * canary zones enumerated from ITOC metadata + the relocation plan
    (never from the observed diff): patch bytes, clcrc of the touched
    lines, 0x30 (old erased / new / moved ITOC rows), entry CRCs of the
    touched sections, guides 0xE1/0xE0 uid/mac, 0xA0 digest slot.

Gates per image: verify_image(deep) + burn-order + fresh 0xA0 +
per-line clcrc (explicit for FS3: verify --deep checks clcrc on FS4
only) + 0x30 round-trip + sign idempotency + guides self-verify +
byte-diff canary.
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
import build_hf2 as hf  # noqa: E402

BASE_REFS = (REPO / "refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-MCX4131A-"
             "GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin")
SPEC_REFS = REPO / "scripts/probes/gate-specs/hf2-dispatcher-cx4lx-1912.json"
CORPUS = REPO / "build" / "corpus"
ECA_REL = "cx4/12_28_4706/MCX456A-ECA"

# synthetic identifiers (any valid-format values pin the JSON output;
# the real lab Base GUID/MAC live only in the task-01 journal and are
# passed to the builder via explicit CLI args at build time)
GUID = 0x12345678ABCDEF01
MAC = 0x123456ABCDEF
GUID_STR = "12345678abcdef01"
MAC_STR = "123456abcdef"

BUILD_ID_REF = ("; mlxini hf2-max (2026-11-24, docs/superpowers/specs/"
                "2026-11-24-serdes-arc-hf2-design.md): dispatcher "
                "special-path + EDR-class tuple + ETH 100/56 unlock\n")

W_STOCK = bytes.fromhex("4a043686")
W_PATCH = bytes.fromhex("00040400")


# ------------------------------------------------------------- mini fixture

INI_TEXT = (";; Generated automatically by iniprep tool\n"
            ";; Mellanox Technologies LTD\n"
            "\n"
            "[PS_INFO]\n"
            "prs_name=cx4-lx mini\n"
            "fw_ver=14.32.1912\n")

MINI_MC_DC = (0x00, 0x44, 0x88, 0xCC)


def mini_spec():
    """cable_gate_patch-format spec pinned to the mini MAIN_CODE lines."""
    return {"id": "HF2-MINI", "card": "mini", "section": 3,
            "patches": [
                {"offset": "0x%x" % off, "bytes": "00 04 04 00",
                 "expected_before": "4a 04 36 86", "kind": "code",
                 "note": "mini site %d (line %d, in_line 0x%x)"
                         % (i, off // 64, off % 64)}
                for i, off in enumerate(MINI_MC_DC)]}


def mini_fs3(class_0x158=0x30, lcl0=0x3B, lcl1=0x00, b283=0x00, b2c5=0x00,
             vpi=0x0A, sec30_slack=0):
    """Minimal FS3 image: Lx-GCA-like 0x12/0x11 + clcrc MAIN_CODE 0x03 +
    zlib 0x30 (anchor line) + stale 0xA0 + dev 0xE1/0xE0 (zero uids)."""
    buf = bytearray(b"\xff" * 0x80000)
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
    code = bytearray(b"\x11" * (4 * 64))
    for off in MINI_MC_DC:
        code[off:off + 4] = W_STOCK
    sec03 = fw.clcrc_wrap(bytes(code))
    comp = zlib.compress(INI_TEXT.encode("latin1"), 9)
    comp += b"\x00" * ((4 - len(comp) % 4) % 4)  # DW-aligned section data
    sig = bytearray(0x40)
    sig[0x20:0x40] = hashlib.sha256(b"stale-placeholder").digest()
    di = bytearray(b"\x00" * 0x200)
    di[0:16] = fw.DEVINFO_MAGIC
    di[0x12] = 2          # major1 = ((d[0x11]&1)<<8)|d[0x12] == 2
    mfg = bytearray(b"\x00" * 0x140)
    mfg[fw.MFG3_MAJOR_OFF] = 1
    mfg[fw.MFG3_OVR_OFF] = 0x01

    def entry(i, typ, size, addr, rel=1, dev=0, clcrc=0, data=None):
        e = bytearray(32)
        e[0] = typ
        fw.set_bits(e, 8, 22, size // 4)
        fw.set_bits(e, 160, 1, rel)
        fw.set_bits(e, 161, 29, addr // 4)
        fw.set_bits(e, 206, 1, dev)
        if clcrc:
            fw.set_bits(e, 33, 1, 1)
        if data is not None:
            buf[addr:addr + len(data)] = data
        fw.set_bits(e, 208, 16, fw.crc16_mlx(bytes(buf[addr:addr + size])))
        fw.set_bits(e, 240, 16, fw.crc16_mlx(bytes(e[:28])))
        buf[itoc + 32 + i * 32:itoc + 64 + i * 32] = e

    entry(0, 0x12, 0xC00, 0x2000, data=bytes(sec12))
    entry(1, 0x11, 0x4C0, 0x2D00, data=bytes(sec11))
    entry(2, 0x03, len(sec03), 0x4000, clcrc=1, data=bytes(sec03))
    entry(3, 0x30, len(comp) + sec30_slack, 0x5000, data=bytes(comp))
    entry(4, 0xA0, 0x40, 0x6000, data=bytes(sig))
    entry(5, 0xE1, 0x200, 0x78000, rel=0, dev=1, data=bytes(di))
    entry(6, 0xE0, 0x140, 0x79000, rel=0, dev=1, data=bytes(mfg))
    entry(7, 0xFF, 0, 0)
    return bytes(buf)


# ------------------------------------------------------- edit-set pins

def test_build_id_exact():
    assert hf.BUILD_ID == BUILD_ID_REF
    assert hf.BUILD_ID.startswith("; ")
    assert "\n" in hf.BUILD_ID and not hf.BUILD_ID.startswith("#")


def test_edits_pins():
    assert hf.edits() == [
        (0x11, 0x2AF, b"\x07"),
        (0x12, 0x158, b"\x31"),
        (0x12, 0x283, b"\x12"),
        (0x12, 0x2C5, b"\x10"),
        (0x12, 0x30B, b"\xfb"),
        (0x12, 0x317, b"\xfb"),
    ]


def test_eth_sites_empty_unified():
    # task-03 verdict: mode=unified, sites=[] -- no separate ETH sites
    assert hf.ETH_SITES == ()


def test_expected_base_pins():
    assert hf.EXPECTED_BASE == {
        0x12: {0x158: 0x30, 0x283: 0x00, 0x2C5: 0x00,
               0x30B: 0x3B, 0x317: 0x00},
        0x11: {0x2AF: 0x0A},
    }


def test_spec_path_pins():
    assert hf.SPEC_PATH == SPEC_REFS
    spec = json.loads(SPEC_REFS.read_text())
    assert spec["id"] == "HF2-DISPATCHER-CX4LX-1912"
    assert int(spec["section"]) == 3
    assert [int(p["offset"], 0) for p in spec["patches"]] == [
        0x1BE12C, 0x1FC488, 0x1B330C, 0x1B335C]
    for p in spec["patches"]:
        assert p["bytes"] == "00 04 04 00"
        assert p["expected_before"] == "4a 04 36 86"
        assert p["kind"] == "code"


def test_guid_source_pinned():
    assert "task-01" in hf.GUID_SOURCE


# -------------------------------------------------- EXPECTED_BASE rejections

def test_check_base_rejects_wrong_class():
    img = fw.Image(mini_fs3(class_0x158=0x31), "<mini>")
    with pytest.raises(hf.BuildError):
        hf.check_base(img)


def test_check_base_rejects_wrong_vpi():
    img = fw.Image(mini_fs3(vpi=0x07), "<mini>")
    with pytest.raises(hf.BuildError):
        hf.check_base(img)


def test_check_base_rejects_wrong_lcl():
    img = fw.Image(mini_fs3(lcl0=0x30), "<mini>")
    with pytest.raises(hf.BuildError):
        hf.check_base(img)


def test_check_base_rejects_wrong_tuple_dep():
    img = fw.Image(mini_fs3(b283=0x12), "<mini>")
    with pytest.raises(hf.BuildError):
        hf.check_base(img)


# ---------------------------------------------------- build (mini, relocation)

def test_build_mini_all_gates():
    out, rep = hf.build(mini_fs3(), mini_spec(), GUID, MAC)
    assert rep["gates"] == {"verify_image": True, "burn_order": True,
                            "sig_fresh": True, "clcrc_lines": True,
                            "round_trip": True, "sign_idempotent": True,
                            "guides": True, "canary": True}
    vimg = fw.Image(out, "<out>")
    assert fw.verify_image(vimg, deep=True) == []
    assert fw.sig_status(vimg)[0] == "fresh"
    can = rep["canary"]
    assert can["ok"] and can["extra"] == [] and can["missing"] == []
    assert can["erased_ok"] is True and can["guides_ok"] is True
    got = [(c["section"], c["rel"], c["old"], c["new"])
           for c in can["content"]]
    assert got == [
        ("0x11", 0x2AF, "0a", "07"),
        ("0x12", 0x158, "30", "31"),
        ("0x12", 0x283, "00", "12"),
        ("0x12", 0x2C5, "00", "10"),
        ("0x12", 0x30B, "3b", "fb"),
        ("0x12", 0x317, "00", "fb"),
        ("0x03", 0x00, "4a043686", "00040400"),
        ("0x03", 0x44, "4a043686", "00040400"),
        ("0x03", 0x88, "4a043686", "00040400"),
        ("0x03", 0xCC, "4a043686", "00040400"),
    ]


def test_build_mini_main_code_words():
    out, _rep = hf.build(mini_fs3(), mini_spec(), GUID, MAC)
    img = fw.Image(out, "<out>")
    e = img.find_entry("ITOC", 0x03)
    code, _tail = fw.clcrc_unwrap(img.section_data(e))
    for off in MINI_MC_DC:
        assert code[off:off + 4] == W_PATCH
        assert code[off + 4:off + 8] != W_PATCH  # only the word itself


def test_build_mini_ini30_relocated():
    out, rep = hf.build(mini_fs3(), mini_spec(), GUID, MAC)
    assert rep["ini30"]["relocated"] is True
    assert rep["ini30"]["old"]["abs"] == 0x5000
    assert rep["ini30"]["new"]["abs"] == 0x10000  # 64K-aligned tail
    # old place erased, new place holds the new stream
    img = fw.Image(out, "<out>")
    assert set(out[0x5000:0x5000 + rep["ini30"]["old"]["size"]]) == {0xFF}
    data = fw.extract_section(img, 0x30)
    assert data[:2] == b"\x78\xda"


def test_build_mini_ini30_inplace():
    out, rep = hf.build(mini_fs3(sec30_slack=0x200), mini_spec(), GUID, MAC)
    assert rep["ini30"]["relocated"] is False
    assert rep["ini30"]["new"]["abs"] == 0x5000
    assert all(rep["gates"].values())
    can = rep["canary"]
    assert can["ok"] and can["extra"] == [] and can["missing"] == []
    kinds = {z["kind"] for z in can["zones"]}
    assert "sec30" in kinds and "sec30_old" not in kinds


def test_build_id_round_trip():
    out, rep = hf.build(mini_fs3(), mini_spec(), GUID, MAC)
    img = fw.Image(out, "<out>")
    text = zlib.decompress(fw.extract_section(img, 0x30)).decode("latin1")
    lines = text.splitlines(keepends=True)
    i = lines.index(";; Mellanox Technologies LTD\n")
    assert lines[i + 1] == hf.BUILD_ID
    assert rep["ini30"]["round_trip"] is True
    # key=value lines are intact (dc-parity)
    assert "prs_name=cx4-lx mini\n" in lines
    assert "fw_ver=14.32.1912\n" in lines


def test_guides_embedded():
    out, _rep = hf.build(mini_fs3(), mini_spec(), GUID, MAC)
    img = fw.Image(out, "<out>")
    for t in (0xE1, 0xE0):
        d = img.section_data(img.find_entry("ITOC", t))
        assert d[0x28:0x30] == GUID.to_bytes(8, "big")
        assert d[0x38:0x40] == MAC.to_bytes(8, "big")


def test_build_requires_guid_mac():
    with pytest.raises(hf.BuildError):
        hf.build(mini_fs3(), mini_spec(), None, MAC)
    with pytest.raises(hf.BuildError):
        hf.build(mini_fs3(), mini_spec(), GUID, None)


def test_guid_mac_report_pins():
    out, rep = hf.build(mini_fs3(), mini_spec(), GUID, MAC)
    assert rep["guid"] == GUID_STR
    assert rep["mac"] == MAC_STR
    assert rep["guid_source"] == hf.GUID_SOURCE
    assert "task-01" in rep["guid_source"]


def test_build_deterministic():
    a, _ = hf.build(mini_fs3(), mini_spec(), GUID, MAC)
    b, _ = hf.build(mini_fs3(), mini_spec(), GUID, MAC)
    assert a == b


def test_build_rejects_wrong_base():
    with pytest.raises(hf.BuildError):
        hf.build(mini_fs3(class_0x158=0x31), mini_spec(), GUID, MAC)


def test_build_rejects_bad_spec_before():
    spec = mini_spec()
    spec["patches"][0]["expected_before"] = "00 00 00 00"
    with pytest.raises(hf.BuildError):
        hf.build(mini_fs3(), spec, GUID, MAC)


# -------------------------------------------------------------------- canary

def test_canary_zones_from_itoc_metadata():
    out, rep = hf.build(mini_fs3(), mini_spec(), GUID, MAC)
    base_img = fw.Image(mini_fs3(), "<base>")
    out_img = fw.Image(out, "<out>")
    zones = {(z["kind"], z["abs"]) for z in rep["canary"]["zones"]}
    # byte-edit patch zones from base ITOC metadata
    for t, offs in ((0x11, (0x2AF,)), (0x12, (0x158, 0x283, 0x2C5,
                                                0x30B, 0x317))):
        e = base_img.find_entry("ITOC", t)
        for off in offs:
            assert ("patch", base_img.sec_abs(e) + off) in zones
    # MAIN_CODE framed patch bytes + clcrc of the touched lines
    e03 = base_img.find_entry("ITOC", 0x03)
    a03 = base_img.sec_abs(e03)
    for dc in MINI_MC_DC:
        line, in_line = divmod(dc, 64)
        assert ("patch", a03 + line * 68 + in_line) in zones
        assert ("clcrc", a03 + line * 68 + 66) in zones
    # guides zones from base ITOC metadata
    for t in (0xE1, 0xE0):
        e = base_img.find_entry("ITOC", t)
        assert ("guides", base_img.sec_abs(e) + 0x28) in zones
        assert ("guides", base_img.sec_abs(e) + 0x38) in zones
    # digest slot from base ITOC + SIG_SLOT_OFF
    ea = base_img.find_entry("ITOC", 0xA0)
    assert ("digest_slot", base_img.sec_abs(ea) + fw.SIG_SLOT_OFF) in zones
    # entry-CRC zones at OUT row positions of the touched sections
    for t in (0x03, 0x11, 0x12, 0xA0, 0xE1, 0xE0):
        e = out_img.find_entry("ITOC", t)
        row = out_img.itoc_off + 32 + e.index * 32
        if any(z[0] == "itoc_row" and z[1] <= row < z[1] + 64
               for z in zones):
            continue  # row covered by the move zone
        assert ("sec_crc", row + 0x1A) in zones
        assert ("entry_crc", row + 0x1E) in zones
    # relocation zones: old range (erased) + new range + moved rows
    e30b = base_img.find_entry("ITOC", 0x30)
    e30o = out_img.find_entry("ITOC", 0x30)
    assert ("sec30_old", base_img.sec_abs(e30b)) in zones
    assert ("sec30_new", out_img.sec_abs(e30o)) in zones
    lo = min(e30b.index, e30o.index)
    assert ("itoc_row", base_img.itoc_off + 32 + lo * 32) in zones


def test_canary_rejects_unexpected_byte():
    out, _ = hf.build(mini_fs3(), mini_spec(), GUID, MAC)
    bad = bytearray(out)
    bad[0x4000 + 0x20] ^= 0xFF  # 0x03 line-0 code, not a patch byte
    can = hf.canary(mini_fs3(), bytes(bad), mini_spec(), GUID, MAC)
    assert can["ok"] is False
    assert can["extra"] and can["extra"][0]["abs"] == 0x4020


def test_canary_rejects_missing_patch_byte():
    out, _ = hf.build(mini_fs3(), mini_spec(), GUID, MAC)
    reverted = bytearray(out)
    base_img = fw.Image(mini_fs3(), "<base>")
    e11 = base_img.find_entry("ITOC", 0x11)
    reverted[base_img.sec_abs(e11) + 0x2AF] = 0x0A  # undo the VPI byte
    can = hf.canary(mini_fs3(), bytes(reverted), mini_spec(), GUID, MAC)
    assert can["ok"] is False and can["missing"]


def test_canary_rejects_unerased_old_30():
    out, _ = hf.build(mini_fs3(), mini_spec(), GUID, MAC)
    bad = bytearray(out)
    bad[0x5005] = 0x00  # non-FF inside the erased old 0x30 range
    can = hf.canary(mini_fs3(), bytes(bad), mini_spec(), GUID, MAC)
    assert can["ok"] is False and can["erased_ok"] is False


def test_canary_rejects_wrong_guid_value():
    out, _ = hf.build(mini_fs3(), mini_spec(), GUID, MAC)
    bad = bytearray(out)
    base_img = fw.Image(mini_fs3(), "<base>")
    e1 = base_img.find_entry("ITOC", 0xE1)
    a = base_img.sec_abs(e1) + 0x28
    bad[a:a + 8] = (GUID ^ 1).to_bytes(8, "big")
    can = hf.canary(mini_fs3(), bytes(bad), mini_spec(), GUID, MAC)
    assert can["ok"] is False and can["guides_ok"] is False


def test_canary_digest_value_gated_by_sig_fresh_not_zones():
    # division of labor: the canary is a ZONE gate (byte-diff vs base);
    # a wrong digest VALUE inside the digest_slot zone is caught by
    # sig_fresh / sign --check (Rule 4.5), not by the canary
    out, _ = hf.build(mini_fs3(), mini_spec(), GUID, MAC)
    bad = bytearray(out)
    base_img = fw.Image(mini_fs3(), "<base>")
    ea = base_img.find_entry("ITOC", 0xA0)
    a = base_img.sec_abs(ea) + fw.SIG_SLOT_OFF
    bad[a:a + 32] = hashlib.sha256(b"stale").digest()
    can = hf.canary(mini_fs3(), bytes(bad), mini_spec(), GUID, MAC)
    assert can["ok"] is True  # byte is inside the enumerated zone
    assert fw.sig_status(fw.Image(bytes(bad), "<bad>"))[0] == "stale"


def test_canary_allows_only_enumerated_zones():
    out, rep = hf.build(mini_fs3(), mini_spec(), GUID, MAC)
    base_img = fw.Image(mini_fs3(), "<base>")
    out_img = fw.Image(out, "<out>")
    can = rep["canary"]
    allowed = [(z["abs"], z["abs"] + z["size"]) for z in can["zones"]]
    diff = [i for i in range(len(out))
            if base_img.buf[i] != out_img.buf[i]]
    assert diff
    for i in diff:
        assert any(lo <= i < hi for lo, hi in allowed), hex(i)
    # required zones actually moved (report is not vacuous)
    assert any(z["kind"] == "digest_slot" and z["changed"]
               for z in can["zones"])
    assert any(z["kind"] == "guides" and z["changed"]
               for z in can["zones"])
    assert any(z["kind"] == "clcrc" and z["changed"]
               for z in can["zones"])


# -------------------------------------------------------------------- CLI

def test_cli_mini(tmp_path):
    base = tmp_path / "base.bin"
    base.write_bytes(mini_fs3())
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps(mini_spec()))
    out = tmp_path / "hf2-max.bin"
    js = tmp_path / "report.json"
    rc = hf.main(["--guid", GUID_STR, "--mac", MAC_STR,
                  "--base", str(base), "--spec", str(spec),
                  "--out", str(out), "--json", str(js)])
    assert rc == 0 and out.is_file()
    rep = json.loads(js.read_text())
    assert all(rep["gates"].values())
    assert rep["guid"] == GUID_STR and rep["mac"] == MAC_STR
    assert rep["md5"] == hashlib.md5(out.read_bytes()).hexdigest()


def test_cli_requires_guid_mac(tmp_path):
    base = tmp_path / "base.bin"
    base.write_bytes(mini_fs3())
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps(mini_spec()))
    out = tmp_path / "x.bin"
    with pytest.raises(SystemExit):
        hf.main(["--base", str(base), "--spec", str(spec), "--out", str(out)])
    with pytest.raises(SystemExit):
        hf.main(["--mac", MAC_STR, "--base", str(base),
                 "--spec", str(spec), "--out", str(out)])
    with pytest.raises(SystemExit):
        hf.main(["--guid", GUID_STR, "--base", str(base),
                 "--spec", str(spec), "--out", str(out)])
    assert not out.exists()


def test_cli_rejects_bad_guid_hex(tmp_path):
    base = tmp_path / "base.bin"
    base.write_bytes(mini_fs3())
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps(mini_spec()))
    rc = hf.main(["--guid", "zzz", "--mac", MAC_STR,
                  "--base", str(base), "--spec", str(spec),
                  "--out", str(tmp_path / "x.bin")])
    assert rc != 0 and not (tmp_path / "x.bin").exists()


def test_cli_rejects_wrong_base(tmp_path):
    base = tmp_path / "base.bin"
    base.write_bytes(mini_fs3(class_0x158=0x31))
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps(mini_spec()))
    out = tmp_path / "x.bin"
    rc = hf.main(["--guid", GUID_STR, "--mac", MAC_STR,
                  "--base", str(base), "--spec", str(spec),
                  "--out", str(out)])
    assert rc != 0 and not out.exists()


def test_cli_default_spec_rejects_mini_base(tmp_path):
    # the real dispatcher spec does not fit the mini MAIN_CODE
    base = tmp_path / "base.bin"
    base.write_bytes(mini_fs3())
    rc = hf.main(["--guid", GUID_STR, "--mac", MAC_STR,
                  "--base", str(base),
                  "--out", str(tmp_path / "x.bin")])
    assert rc != 0 and not (tmp_path / "x.bin").exists()


# ------------------------------------------------- refs/corpus (slow, real)

@pytest.mark.slow
class TestRefsBuild:
    def _base(self):
        if not BASE_REFS.is_file():
            pytest.skip("refs base image not present")
        return BASE_REFS.read_bytes()

    def _spec(self):
        if not SPEC_REFS.is_file():
            pytest.skip("dispatcher spec not present")
        return json.loads(SPEC_REFS.read_text())

    def test_full_build_from_refs(self):
        out, rep = hf.build(self._base(), self._spec(), GUID, MAC)
        assert all(rep["gates"].values())
        can = rep["canary"]
        assert can["ok"] and can["extra"] == [] and can["missing"] == []
        got = [(c["section"], c["rel"], c["old"], c["new"])
               for c in can["content"]]
        assert got == [
            ("0x11", 0x2AF, "0a", "07"),
            ("0x12", 0x158, "30", "31"),
            ("0x12", 0x283, "00", "12"),
            ("0x12", 0x2C5, "00", "10"),
            ("0x12", 0x30B, "3b", "fb"),
            ("0x12", 0x317, "00", "fb"),
            ("0x03", 0x1BE12C, "4a043686", "00040400"),
            ("0x03", 0x1FC488, "4a043686", "00040400"),
            ("0x03", 0x1B330C, "4a043686", "00040400"),
            ("0x03", 0x1B335C, "4a043686", "00040400"),
        ]
        assert rep["ini30"]["relocated"] is True  # 1806B > 1700B budget
        assert rep["guid"] == GUID_STR and rep["mac"] == MAC_STR
        assert rep["md5"] == hashlib.md5(out).hexdigest()
        again, _ = hf.build(self._base(), self._spec(), GUID, MAC)
        assert again == out  # deterministic

    def test_main_code_words_patched_in_refs(self):
        out, _ = hf.build(self._base(), self._spec(), GUID, MAC)
        img = fw.Image(out, "<out>")
        e = img.find_entry("ITOC", 0x03)
        code, _tail = fw.clcrc_unwrap(img.section_data(e))
        for off in (0x1BE12C, 0x1FC488, 0x1B330C, 0x1B335C):
            assert code[off:off + 4] == W_PATCH

    def test_guids_embedded_in_refs(self):
        out, _ = hf.build(self._base(), self._spec(), GUID, MAC)
        img = fw.Image(out, "<out>")
        for t in (0xE1, 0xE0):
            d = img.section_data(img.find_entry("ITOC", t))
            assert d[0x28:0x30] == GUID.to_bytes(8, "big")
            assert d[0x38:0x40] == MAC.to_bytes(8, "big")

    def test_build_id_line_in_refs_ini(self):
        out, _ = hf.build(self._base(), self._spec(), GUID, MAC)
        img = fw.Image(out, "<out>")
        text = zlib.decompress(fw.extract_section(img, 0x30)).decode(
            "latin1")
        lines = text.splitlines(keepends=True)
        i = lines.index(";; Mellanox Technologies LTD\n")
        assert lines[i + 1] == hf.BUILD_ID


@pytest.mark.slow
def test_tuple_matches_task03_eth_verdict():
    # cross-check: builder tuple == hf2_reverse.eth_verdict tuple
    if not BASE_REFS.is_file():
        pytest.skip("refs base image not present")
    if not (CORPUS / ECA_REL / "sections" / "12" / "dc.bin").is_file():
        pytest.skip("corpus ECA reference absent")
    import hf2_reverse
    v = hf2_reverse.eth_verdict(str(BASE_REFS))
    assert v["mode"] == "unified" and v["sites"] == []
    rows = {r["offset"]: (r["stock"], r["target"])
            for r in v["tuple"]["bytes"]}
    assert set(rows) == set(hf.TUPLE_0x12)
    for off, (stock, target) in rows.items():
        assert hf.EXPECTED_BASE[0x12][off] == stock
        assert hf.TUPLE_0x12[off] == target
