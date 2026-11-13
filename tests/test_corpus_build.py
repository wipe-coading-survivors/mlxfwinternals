import hashlib
import json
import struct
import sys
from dataclasses import replace
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from scripts.corpus.build_corpus import (  # noqa: E402
    apply_only,
    build_all,
    diff_trees,
)
from scripts.corpus.extract import PriorDisagreement  # noqa: E402
from scripts.corpus.manifest import CorpusManifestError, ImageRef  # noqa: E402
from tests.fixtures.corpus.synth_image import build_synth_image  # noqa: E402


def synth_irisc(n_words=256):
    words = []
    for i in range(n_words):
        op = (0x01, 0x02, 0x03, 0x04)[i % 4]
        words.append((op << 26) | ((i & 0x1F) << 21)
                     | (((i * 7) & 0x1F) << 16) | ((i * 13) & 0xFFFF))
    return struct.pack(">%dI" % n_words, *words)


DATA_BLOB = b"corpus synthetic data blob probe 0123456789 " * 16

PHY_RECS = [
    (0x6041, 0x000A, 0x59CC, 0x0490, 0x0043),
    (0x4000, 0x0654, 0x0000, 0x0000, 0x0000),
    (0x5064, 0x0640, 0x1200, 0x0100, 0x0010),
    (0x0000, 0x0000, 0x0000, 0x0000, 0x0000),
]


def phy_payload():
    return b"".join(b"\x00" * 6 + struct.pack(">5H", *rec)
                    for rec in PHY_RECS)


ROM_PAYLOAD = b"\x55\xaa" + b"\x90" * 62


def synth_sections():
    return [
        {"typ": 0x02, "payload": synth_irisc(96),
         "param0": 0x800000, "param1": 0x800004},
        {"typ": 0x03, "payload": synth_irisc(64), "cl": True,
         "param0": 0x900000},
        {"typ": 0x0A, "payload": phy_payload()},
        {"typ": 0x18, "payload": ROM_PAYLOAD},
        {"typ": 0x09, "payload": DATA_BLOB},
        {"typ": 0x30, "payload": b"\x00" * 256, "zipped": True},
    ]


def make_ref(tmp_path, family="cx5", ver="16_35_4030", sku="SYNTH",
             sections=None):
    buf = build_synth_image(sections if sections is not None
                            else synth_sections())
    path = tmp_path / "synth.bin"
    path.write_bytes(buf)
    return ImageRef(path, hashlib.md5(buf).hexdigest(), family, ver, sku, 1)


def test_full_run_artifact_tree_and_manifest(tmp_path):
    ref = make_ref(tmp_path)
    out = tmp_path / "corpus"
    manifest = tmp_path / "corpus_manifest.json"
    build_all([ref], out, manifest)

    base = out / "cx5" / "16_35_4030" / "SYNTH" / "sections"
    assert base.is_dir()
    assert sorted(p.name for p in base.iterdir()) == [
        "02", "03", "09", "0A", "18", "30"]
    for typ in ("02", "03", "09", "0A", "18", "30"):
        assert (base / typ / "raw.bin").is_file()
        assert (base / typ / "meta.json").is_file()
    irisc = base / "02"
    for name in ("dc.bin", "disasm.txt", "funcs.tsv", "calls.tsv",
                 "xref.tsv", "consts.tsv", "strings.txt", "pseudo.md"):
        assert (irisc / name).is_file(), name
    assert (base / "03" / "disasm.txt").is_file()

    assert not (base / "0A" / "disasm.txt").exists()
    assert not (base / "0A" / "funcs.tsv").exists()
    slots = (base / "0A" / "slots.tsv").read_text().splitlines()
    assert slots[0] == "idx\top\ta\tb\tc\td\tclass\tasm"
    assert len(slots) == 1 + len(PHY_RECS)
    assert slots[1].split("\t")[1] == "6041"
    assert slots[1].split("\t")[6] == "write"

    assert not (base / "18" / "disasm.txt").exists()
    rom_meta = json.loads((base / "18" / "meta.json").read_text())
    assert rom_meta["rom_signature"] == "pci_oprom"

    assert not (base / "09" / "disasm.txt").exists()
    assert not (base / "30" / "disasm.txt").exists()

    m = json.loads(manifest.read_text())
    assert m["schema"] == 1
    assert len(m["images"]) == 1
    img = m["images"][0]
    assert img["path"] == str(ref.path)
    assert img["md5"] == ref.md5
    assert img["tier"] == 1
    assert img["family"] == "cx5"
    assert img["ver"] == "16_35_4030"
    assert img["sku"] == "SYNTH"
    assert img["status"] == "OK"
    by_type = {s["type"]: s for s in img["sections"]}
    assert [s["type"] for s in img["sections"]] == sorted(by_type)
    assert by_type["02"]["domain"] == "iRISC"
    assert by_type["02"]["status"] == "OK"
    assert by_type["02"]["size"] == 96 * 4
    assert by_type["02"]["cl"] is False
    assert by_type["02"]["words"] == 96
    assert by_type["02"]["md5_raw"] == hashlib.md5(
        (base / "02" / "raw.bin").read_bytes()).hexdigest()
    assert by_type["02"]["md5_dc"] == by_type["02"]["md5_raw"]
    assert set(by_type["02"]["metrics"]) == {
        "words_in_bounds_ratio", "call_targets_on_prologue_ratio",
        "n_funcs", "n_blocks"}
    assert by_type["02"]["profile"] == {
        "name": "cx5", "status": "ok", "drift": False}
    assert by_type["03"]["cl"] is True
    assert by_type["03"]["md5_dc"] != by_type["03"]["md5_raw"]
    assert by_type["0A"]["domain"] == "PHY"
    assert by_type["0A"]["metrics"] is None
    assert by_type["0A"]["profile"] is None
    assert by_type["18"]["domain"] == "ROM"
    assert by_type["09"]["domain"] == "data"
    assert by_type["09"]["md5_dc"] == by_type["09"]["md5_raw"]
    assert by_type["30"]["md5_dc"] is None
    assert by_type["30"]["status"] == "SKIPPED"
    assert by_type["30"]["status_reason"] == "zipped"

    sec_meta = json.loads((irisc / "meta.json").read_text())
    assert sec_meta["words"] == 96
    assert sec_meta["md5_raw"] == by_type["02"]["md5_raw"]
    assert sec_meta["metrics"] == by_type["02"]["metrics"]
    assert sec_meta["profile"] == by_type["02"]["profile"]


def test_rerun_identical_manifest_and_artifacts(tmp_path):
    ref = make_ref(tmp_path)
    m1 = tmp_path / "m1.json"
    m2 = tmp_path / "m2.json"
    c1 = tmp_path / "c1"
    c2 = tmp_path / "c2"
    build_all([ref], c1, m1)
    build_all([ref], c1, m2)
    assert m1.read_bytes() == m2.read_bytes()
    build_all([ref], c2, m1)
    assert m1.read_bytes() == m2.read_bytes()
    assert diff_trees(c1, c2) == []


def _make_refs(tmp_path, n):
    refs = []
    for i in range(n):
        d = tmp_path / ("img%d" % i)
        d.mkdir()
        refs.append(make_ref(
            d, family="cx5", ver="16_35_4030",
            sku="SYNTH%d" % i, sections=synth_sections()))
    return refs


def test_parallel_jobs_output_identical_to_serial(tmp_path):
    refs = _make_refs(tmp_path, 3)
    m_ser = tmp_path / "serial.json"
    m_par = tmp_path / "parallel.json"
    c_ser = tmp_path / "cser"
    c_par = tmp_path / "cpar"
    build_all(refs, c_ser, m_ser, jobs=1)
    build_all(refs, c_par, m_par, jobs=2)
    assert m_ser.read_bytes() == m_par.read_bytes()
    assert diff_trees(c_ser, c_par) == []


def test_parallel_jobs_worker_hard_stop_propagates(tmp_path):
    refs = _make_refs(tmp_path, 2)
    bad_buf = build_synth_image(
        [{"typ": 0x03, "payload": DATA_BLOB}])
    bad_dir = tmp_path / "bad"
    bad_dir.mkdir()
    bad_path = bad_dir / "synth.bin"
    bad_path.write_bytes(bad_buf)
    refs[0] = replace(refs[0], path=bad_path,
                      md5=hashlib.md5(bad_buf).hexdigest())
    with pytest.raises(PriorDisagreement):
        build_all(refs, tmp_path / "corpus", tmp_path / "m.json", jobs=2)


def test_md5_drift_refuses_whole_build(tmp_path):
    ref = make_ref(tmp_path)
    bad = replace(ref, md5="0" * 32)
    with pytest.raises(CorpusManifestError):
        build_all([bad], tmp_path / "corpus", tmp_path / "m.json")


def test_prior_disagreement_hard_stop(tmp_path):
    ref = make_ref(tmp_path, sections=[
        {"typ": 0x03, "payload": DATA_BLOB}])
    with pytest.raises(PriorDisagreement):
        build_all([ref], tmp_path / "corpus", tmp_path / "m.json")


def test_absent_profile_recorded_not_crash(tmp_path, monkeypatch):
    from scripts.corpus import disasm_build
    from scripts.irisc.profiles import ProfileError

    def missing(name):
        raise ProfileError("unknown profile %r" % name)

    monkeypatch.setattr(disasm_build, "load_profile", missing)
    ref = make_ref(tmp_path, family="cx4", ver="12_28_4706")
    out = tmp_path / "corpus"
    build_all([ref], out, tmp_path / "m.json")
    base = out / "cx4" / "12_28_4706" / "SYNTH" / "sections"
    assert (base / "02" / "disasm.txt").is_file()
    assert (base / "02" / "pseudo.md").is_file()
    meta = json.loads((base / "02" / "meta.json").read_text())
    assert meta["profile"] == {
        "name": "cx4-1228", "status": "absent", "drift": False}
    m = json.loads((tmp_path / "m.json").read_text())
    by_type = {s["type"]: s for s in m["images"][0]["sections"]}
    assert by_type["02"]["profile"] == meta["profile"]


def test_image_parse_error_recorded_build_continues(tmp_path):
    good = make_ref(tmp_path)
    bad_buf = b"\xff" * 4096
    bad_path = tmp_path / "broken.bin"
    bad_path.write_bytes(bad_buf)
    bad = ImageRef(bad_path, hashlib.md5(bad_buf).hexdigest(),
                   "cx6", "20_43_1014", "BROKEN", 1)
    summary = build_all([bad, good], tmp_path / "corpus",
                        tmp_path / "m.json")
    assert summary["schema"] == 1
    assert [i["status"] for i in summary["images"]] == ["OK", "ERROR"]
    assert summary["images"][0]["sections"]
    assert summary["images"][1]["sections"] == []
    assert summary["images"][1]["status_reason"]


def test_apply_only_filter():
    refs = [
        ImageRef(Path("a"), "x", "cx5", "16_35_4030", "MCX516A-CDA", 1),
        ImageRef(Path("b"), "y", "cx6", "20_43_1014", "MCX654105A-HCA", 1),
    ]
    assert apply_only(refs, None) == refs
    assert apply_only(refs, "cx5/16_35_4030/MCX516A-CDA") == refs[:1]
    assert apply_only(refs, "cx9/1/2") == []
    with pytest.raises(CorpusManifestError):
        apply_only(refs, "cx5")


def test_diff_trees_reports_differences(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    for root in (a, b):
        (root / "d").mkdir(parents=True)
        (root / "d" / "same.bin").write_bytes(b"\x01\x02")
        (root / "d" / "mut.bin").write_bytes(b"\x03")
    assert diff_trees(a, b) == []
    (b / "d" / "mut.bin").write_bytes(b"\x04")
    assert diff_trees(a, b) == ["differs: d/mut.bin"]
    (a / "extra.bin").write_bytes(b"\x05")
    assert sorted(diff_trees(a, b)) == [
        "differs: d/mut.bin", "only in %s: extra.bin" % a]
