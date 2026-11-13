import json
import struct
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import scripts.irisc.profiles as profiles_mod  # noqa: E402
from scripts.corpus.gen_profile import build_profile_json, census_hist  # noqa: E402
from scripts.irisc.profiles import load_profile  # noqa: E402

HIST = {0x36: 3774, 0x0D: 3393, 0x33: 2115}
DATA_BLOB = b"corpus synthetic data blob probe 0123456789 " * 16


def synth_code_dc(n_words=256, plant_every=8):
    words = []
    for i in range(n_words):
        op = (0x01, 0x02, 0x03, 0x04)[i % 4]
        if plant_every and i % plant_every == 0:
            op = 0x36
        words.append((op << 26) | ((i & 0x1F) << 21)
                     | (((i * 7) & 0x1F) << 16) | ((i * 13) & 0xFFFF))
    return struct.pack(">%dI" % n_words, *words)


def load_via_dir(data, name, tmp_path, monkeypatch):
    (tmp_path / ("%s.json" % name)).write_text(json.dumps(data))
    monkeypatch.setattr(profiles_mod, "_DIR", tmp_path)
    return load_profile(name)


def test_build_profile_json_roundtrip_load_profile(tmp_path, monkeypatch):
    data = build_profile_json(
        HIST, "cx4-1228", "ConnectX-4", 0x800000,
        "refs/fw/cx-4/fw-ConnectX4-rel-12_28_4706-MCX456A-ECA_Ax.bin")
    profile = load_via_dir(data, "cx4-1228", tmp_path, monkeypatch)
    assert profile.name == "cx4-1228"
    assert profile.chip == "ConnectX-4"
    assert profile.verified_on == []
    assert profile.load_base == {"MAIN_CODE": 0x800000}
    assert profile.anchors == {}
    assert profile.census == {
        "0x36": {"count_code": 3774, "note": profile.census["0x36"]["note"]},
        "0x0d": {"count_code": 3393, "note": profile.census["0x0d"]["note"]},
        "0x33": {"count_code": 2115, "note": profile.census["0x33"]["note"]},
    }


def test_build_profile_json_has_all_mandatory_keys():
    data = build_profile_json(HIST, "cx6-2043", "ConnectX-6", 0x800000, "src")
    for key in ("name", "chip", "verified_on", "load_base", "anchors", "forms"):
        assert key in data
    assert data["verified_on"] == []
    assert data["load_base"] == {"MAIN_CODE": 0x800000}


def test_build_profile_json_provisional_status():
    data = build_profile_json(HIST, "cx6lx-2650", "ConnectX-6 Lx", 0x800000,
                              "refs/fw/cx-5-6/fw-ConnectX6Lx-rel-26_50_1002.bin")
    assert data["status"] == "provisional"
    assert data["provisional_reason"] == "corpus-arc-A"
    assert data["source"] == "refs/fw/cx-5-6/fw-ConnectX6Lx-rel-26_50_1002.bin"


def test_build_profile_json_known_forms_not_marked_live(tmp_path, monkeypatch):
    data = build_profile_json(HIST, "cx4-1228", "ConnectX-4", 0x800000, "src")
    assert data["forms"] == {}
    assert "live" not in data["forms"].values()
    profile = load_via_dir(data, "cx4-1228", tmp_path, monkeypatch)
    for form in ("set2", "addi", "call", "ret.r", "ld.d"):
        assert profile.form_status(form) == "assumed"


def test_build_profile_json_census_entries_count_and_note():
    data = build_profile_json(HIST, "cx6-2043", "ConnectX-6", 0x800000, "src")
    for key, entry in data["unknown_ops"].items():
        assert key == "0x%02x" % int(key, 16)
        assert isinstance(entry["count_code"], int)
        assert entry["count_code"] > 0
        assert isinstance(entry["note"], str) and entry["note"]
    assert [e["count_code"] for e in data["unknown_ops"].values()] == [3774, 3393, 2115]


def test_build_profile_json_deterministic_order_and_empty_hist():
    data_a = build_profile_json(HIST, "x", "c", 0, "s")
    data_b = build_profile_json(dict(reversed(list(HIST.items()))), "x", "c", 0, "s")
    assert data_a == data_b
    assert build_profile_json({}, "x", "c", 0, "s")["unknown_ops"] == {}
    assert build_profile_json({}, "x", "c", 0, "s")["anchors"] == []


def test_census_hist_counts_unknown_ops_in_code_regions():
    assert census_hist(synth_code_dc()) == {0x36: 32}
    assert census_hist(synth_code_dc(plant_every=0)) == {}
    assert census_hist(b"") == {}
    assert census_hist(b"\x01\x02\x03") == {}


def test_census_hist_data_words_with_unknown_ops_not_counted():
    from scripts.irisc import recount_codehist as rc

    words = struct.unpack_from(">%dI" % (len(DATA_BLOB) // 4), DATA_BLOB, 0)
    assert any(w >> 26 not in rc.KNOWN30 for w in words)
    assert census_hist(DATA_BLOB) == {}
