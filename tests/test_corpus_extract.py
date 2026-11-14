import json
import struct
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from mlxfwutil import Image, clcrc_wrap  # noqa: E402
import scripts.corpus.extract as extract_mod  # noqa: E402
from scripts.corpus.extract import (  # noqa: E402
    DOMAIN_PRIOR,
    PriorDisagreement,
    classify_instance,
    sections_of,
    write_sections,
)
from tests.fixtures.corpus.synth_image import build_synth_image  # noqa: E402


def synth_irisc(n_words=256):
    words = []
    for i in range(n_words):
        op = (0x01, 0x02, 0x03, 0x04)[i % 4]
        words.append((op << 26) | ((i & 0x1F) << 21)
                     | (((i * 7) & 0x1F) << 16) | ((i * 13) & 0xFFFF))
    return struct.pack(">%dI" % n_words, *words)


DATA_BLOB = b"corpus synthetic data blob probe 0123456789 " * 16


def build4():
    payload_cl = synth_irisc(256)
    buf = build_synth_image([
        {"typ": 0x02, "payload": synth_irisc(192),
         "param0": 0x800000, "param1": 0x800104},
        {"typ": 0x03, "payload": payload_cl, "cl": True},
        {"typ": 0x30, "payload": b"\x00" * 256, "zipped": True},
        {"typ": 0x11, "payload": b""},
    ])
    return buf, payload_cl


def test_sections_of_statuses_and_dc():
    buf, payload_cl = build4()
    recs = sections_of(Image(buf))
    assert [r.typ for r in recs] == [0x02, 0x03, 0x30, 0x11]
    assert [r.status for r in recs] == ["OK", "OK", "SKIPPED", "OK"]
    r0, r1, r2, r3 = recs
    assert r0.cl is False
    assert r0.dc == r0.raw
    assert r0.domain == "iRISC"
    assert r0.param0 == 0x800000
    assert r0.param1 == 0x800104
    assert r0.flash_addr == 0x4000
    assert r0.size == len(r0.raw)
    assert r1.cl is True
    assert r1.dc == payload_cl
    assert r1.raw == clcrc_wrap(payload_cl)
    assert r1.domain == "iRISC"
    assert r2.zipped is True
    assert r2.status_reason == "zipped"
    assert r2.dc == b""
    assert r2.raw == b"\x00" * 256
    assert r2.domain == "data"
    assert r3.size == 0
    assert r3.raw == b""
    assert r3.dc == b""
    assert r3.status_reason == ""
    assert r3.domain == "data"


def test_clcrc_corrupt_line_is_error_not_raise():
    buf = bytearray(build_synth_image(
        [{"typ": 0x04, "payload": synth_irisc(256), "cl": True}]))
    img = Image(bytes(buf))
    e = img.entries("ITOC")[0]
    a = img.sec_abs(e)
    buf[a + 66] ^= 0xFF
    recs = sections_of(Image(bytes(buf)))
    assert len(recs) == 1
    r = recs[0]
    assert r.status == "ERROR"
    assert "clcrc" in r.status_reason
    assert r.dc == b""
    assert len(r.raw) == len(clcrc_wrap(synth_irisc(256)))


def test_write_sections_tree(tmp_path):
    buf, _ = build4()
    recs = sections_of(Image(buf))
    write_sections(tmp_path, recs)
    sec = tmp_path / "sections"
    assert sorted(p.name for p in sec.iterdir()) == ["02", "03", "11", "30"]
    for r in recs:
        d = sec / ("%02X" % r.typ)
        assert (d / "raw.bin").read_bytes() == r.raw
        assert (d / "dc.bin").read_bytes() == r.dc
        meta = json.loads((d / "meta.json").read_text())
        assert set(meta) == {
            "typ", "size", "flash_addr", "param0", "param1", "cl", "zipped",
            "dev", "status", "status_reason", "domain", "domain_override",
            "domain_evidence"}
        assert meta["typ"] == r.typ
        assert meta["size"] == r.size
        assert meta["flash_addr"] == r.flash_addr
        assert meta["param0"] == r.param0
        assert meta["param1"] == r.param1
        assert meta["cl"] == r.cl
        assert meta["zipped"] == r.zipped
        assert meta["dev"] == r.dev
        assert meta["status"] == r.status
        assert meta["status_reason"] == r.status_reason
        assert meta["domain"] == r.domain


def test_builder_header_and_entry_crcs():
    buf, _ = build4()
    img = Image(buf)
    assert img.header_crc_ok("ITOC")
    assert all(img.entry_crc_ok(e) for e in img.entries("ITOC"))


def test_classify_instance_irisc_and_data():
    assert classify_instance(synth_irisc(256)) == "iRISC"
    assert classify_instance(DATA_BLOB) == "data"
    assert classify_instance(b"") == "data"
    assert classify_instance(b"\x01\x02\x03") == "data"


def test_rom_prior_skips_instance_check(monkeypatch):
    buf = build_synth_image([{"typ": 0x18, "payload": DATA_BLOB}])
    calls = []
    orig = extract_mod.classify_instance

    def counting(dc):
        calls.append(dc)
        return orig(dc)

    monkeypatch.setattr(extract_mod, "classify_instance", counting)
    recs = sections_of(Image(buf))
    assert calls == []
    assert recs[0].domain == "ROM"
    assert recs[0].status == "OK"


def test_prior_disagreement_on_irisc_candidate():
    buf = build_synth_image([{"typ": 0x03, "payload": DATA_BLOB}])
    with pytest.raises(PriorDisagreement):
        sections_of(Image(buf))


def test_prior_data_with_irisc_payload_not_raised(monkeypatch):
    buf = build_synth_image([{"typ": 0x09, "payload": synth_irisc(256)}])
    calls = []
    orig = extract_mod.classify_instance

    def counting(dc):
        calls.append(dc)
        return orig(dc)

    monkeypatch.setattr(extract_mod, "classify_instance", counting)
    recs = sections_of(Image(buf))
    assert calls == []
    assert recs[0].domain == "data"
    assert recs[0].status == "OK"


def test_family_override_cx6_ace_data_no_raise_with_evidence(tmp_path):
    from scripts.corpus.extract import DOMAIN_PRIOR_OVERRIDE
    assert DOMAIN_PRIOR_OVERRIDE == {
        ("cx6", 0x15): "data",
        ("cx7", 0x0F): "iRISC",
    }
    buf = build_synth_image([{"typ": 0x15, "payload": DATA_BLOB}])
    img = Image(buf)
    recs = sections_of(img, family="cx6")
    r = recs[0]
    assert r.domain == "data"
    assert r.domain_override == "data"
    assert r.status == "OK"
    assert r.domain_evidence["classifier"] == "data"
    assert 0.0 <= r.domain_evidence["code_ratio"] < 0.5
    write_sections(tmp_path, recs)
    meta = json.loads(
        (tmp_path / "sections" / "15" / "meta.json").read_text())
    assert meta["domain"] == "data"
    assert meta["domain_override"] == "data"
    assert meta["domain_evidence"] == r.domain_evidence
    with pytest.raises(PriorDisagreement):
        sections_of(Image(buf), family="cx5")
    with pytest.raises(PriorDisagreement):
        sections_of(Image(buf))


def test_family_override_skips_gate_even_for_irisc_payload():
    buf = build_synth_image([{"typ": 0x15, "payload": synth_irisc(256)}])
    recs = sections_of(Image(buf), family="cx6")
    r = recs[0]
    assert r.domain == "data"
    assert r.domain_override == "data"
    assert r.domain_evidence["classifier"] == "iRISC"
    assert r.domain_evidence["code_ratio"] >= 0.5


def test_family_override_zipped_section_evidence_none():
    buf = build_synth_image([
        {"typ": 0x15, "payload": b"\x00" * 256, "zipped": True}])
    recs = sections_of(Image(buf), family="cx6")
    r = recs[0]
    assert r.domain == "data"
    assert r.domain_override == "data"
    assert r.domain_evidence is None


def test_cx7_0x0f_production_override_builds_irisc():
    buf = build_synth_image([{"typ": 0x0F, "payload": synth_irisc(192),
                              "param0": 0x20500040, "param1": 0x20500044}])
    recs = sections_of(Image(buf), family="cx7")
    r = recs[0]
    assert r.domain == "iRISC"
    assert r.domain_override == "iRISC"
    assert r.status == "OK"
    assert r.domain_evidence["classifier"] == "iRISC"
    assert r.domain_evidence["code_ratio"] > 0.5


def test_cx7_irisc_override_branch_synthetic_stub(monkeypatch):
    from scripts.corpus.extract import DOMAIN_PRIOR_OVERRIDE
    assert DOMAIN_PRIOR_OVERRIDE.get(("cx7", 0x0F)) == "iRISC"
    buf = build_synth_image([{"typ": 0x02, "payload": DATA_BLOB}])
    with pytest.raises(PriorDisagreement):
        sections_of(Image(buf), family="cx7")
    patched = dict(DOMAIN_PRIOR_OVERRIDE)
    patched[("cx7", 0x02)] = "iRISC"
    monkeypatch.setattr(extract_mod, "DOMAIN_PRIOR_OVERRIDE", patched)
    recs = sections_of(Image(buf), family="cx7")
    r = recs[0]
    assert r.domain == "iRISC"
    assert r.domain_override == "iRISC"
    assert r.status == "OK"
    assert r.domain_evidence["classifier"] == "data"
    assert 0.0 <= r.domain_evidence["code_ratio"] < 0.5


def test_domain_prior_map():
    for t in (0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0D, 0x0E, 0x15):
        assert DOMAIN_PRIOR[t] == "iRISC"
    for t in (0x0A, 0x0B, 0x0C):
        assert DOMAIN_PRIOR[t] == "PHY"
    assert DOMAIN_PRIOR[0x18] == "ROM"
    assert set(DOMAIN_PRIOR.values()) == {"iRISC", "PHY", "ROM"}
    for t in (0x01, 0x08, 0x09, 0x20, 0x30, 0x40, 0xA0, 0xE1, 0xFF):
        assert t not in DOMAIN_PRIOR
