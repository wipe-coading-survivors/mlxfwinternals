import hashlib
import sys
from collections import Counter
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from scripts.corpus.manifest import (  # noqa: E402
    T1,
    T2,
    T3,
    IMAGE_TO_PROFILE,
    CorpusManifestError,
    ImageRef,
    verify_md5,
)

T2_COUNTERS = {
    "cx4/12_28_4706": 7,
    "cx4lx/14_32_1912": 6,
    "cx5/16_35_1012": 9,
    "cx5/16_35_8008": 8,
    "cx5/16_35_4030": 4,
    "cx6/20_43_1014": 5,
    "cx6dx/22_50_1002": 11,
    "cx6lx/26_50_1002": 1,
}

T1_KEYS = {
    "cx4/12_28_4706",
    "cx4lx/14_32_1900",
    "cx4lx/14_32_1912",
    "cx5/16_19_1200",
    "cx5/16_35_4030",
    "cx5/16_35_8008",
    "cx6/20_43_1014",
    "cx6dx/22_47_3576",
    "cx6dx/22_50_1002",
    "cx6lx/26_50_1002",
}

T3_COUNTERS = {
    "cx4/12_28_2302": 1,
    "cx5/16_27_6120": 1,
    "cx6/20_43_8002": 2,
    "cx6/20_43_8016": 1,
}

ARC_B_T3_PINS = {
    "refs/fw/cx-5-6/PG171_Ax_NVD0000000014_rel-20_43.8002.bin":
        "c72fa726e35d3f388531465dcffa0a6f",
    "refs/fw/cx-5-6/fw-ConnectX6-rel-20_43_8002-MCX654105A-HCA_Ax-UEFI-14.37.50-FlexBoot-3.7.500.bin":
        "2ade8a0571ba69bb5285ba3178e92d3d",
}

EXPECTED_IMAGE_TO_PROFILE = {
    "cx4/12_28_4706": "cx4-1228",
    "cx4lx/14_32": "cx4lx",
    "cx5/16_35": "cx5",
    "cx5/16_19_1200": "cx5",
    "cx6/20_43": "cx6-2043",
    "cx6dx/22_50": "cx6dx",
    "cx6dx/22_47": "cx6dx",
    "cx6lx/26_50": "cx6lx-2650",
}

EXCLUSION_TOKENS = ("sp_", "bazzite-img", "pre_ri", "dumps/", "DEV", ".pldm")

FAMILY_DIRS = {
    "cx4": "refs/fw/cx-4",
    "cx4lx": "refs/fw/cx-4",
    "cx5": "refs/fw/cx-5-6",
    "cx6": "refs/fw/cx-5-6",
    "cx6dx": "refs/fw/cx-5-6",
    "cx6lx": "refs/fw/cx-5-6",
}

HEX = set("0123456789abcdef")


def key(ref):
    return f"{ref.family}/{ref.ver}"


def profile_keys(family, ver):
    return (f"{family}/{ver}", f"{family}/{'_'.join(ver.split('_')[:2])}")


def test_tier_counters():
    assert len(T1) == 10
    assert len(T2) == sum(T2_COUNTERS.values()) == 51
    assert len(T3) == 5
    assert Counter(map(key, T1)) == {k: 1 for k in T1_KEYS}
    assert Counter(map(key, T2)) == T2_COUNTERS
    assert Counter(map(key, T3)) == T3_COUNTERS
    for ref in T1:
        assert ref.tier == 1
    for ref in T2:
        assert ref.tier == 2
    for ref in T3:
        assert ref.tier == 3


def test_t1_anchors_are_subset_of_t2_revisions_by_path():
    assert {str(r.path) for r in T1 if key(r) in T2_COUNTERS} <= {
        str(r.path) for r in T2
    }


def test_no_excluded_entries():
    for ref in T2 + T3:
        for token in EXCLUSION_TOKENS:
            assert token not in str(ref.path), (token, ref.path)


def test_md5_pinned_full():
    for ref in T1 + T2 + T3:
        assert ref.md5
        assert len(ref.md5) == 32
        assert set(ref.md5) <= HEX
    assert len({str(r.path) for r in T1 + T2 + T3}) == 59


def test_arc_b_t3_witness_pins():
    by_path = {str(r.path): r for r in T3}
    for path, md5 in ARC_B_T3_PINS.items():
        assert path in by_path, path
        ref = by_path[path]
        assert ref.md5 == md5, path
        assert ref.tier == 3
        assert (ref.family, ref.ver) == ("cx6", "20_43_8002")
        assert ref.sku


def test_arc_b_profile_resolves_for_20_43_8002():
    assert any(k in IMAGE_TO_PROFILE for k in profile_keys("cx6", "20_43_8002"))
    assert IMAGE_TO_PROFILE["cx6/20_43"] == "cx6-2043"


def test_verify_md5(tmp_path):
    payload = b"corpus manifest md5 gate probe"
    good = tmp_path / "good.bin"
    good.write_bytes(payload)
    ref = ImageRef(
        path=good,
        md5=hashlib.md5(payload).hexdigest(),
        family="cx5",
        ver="16_35_4030",
        sku="MCX516A-CDA",
        tier=1,
    )
    assert verify_md5(ref) is None
    drifted = ImageRef(
        path=good,
        md5="0" * 32,
        family="cx5",
        ver="16_35_4030",
        sku="MCX516A-CDA",
        tier=1,
    )
    with pytest.raises(CorpusManifestError):
        verify_md5(drifted)
    missing = ImageRef(
        path=tmp_path / "missing.bin",
        md5=hashlib.md5(payload).hexdigest(),
        family="cx5",
        ver="16_35_4030",
        sku="MCX516A-CDA",
        tier=1,
    )
    with pytest.raises(CorpusManifestError):
        verify_md5(missing)


def test_image_to_profile_covers_manifest():
    assert IMAGE_TO_PROFILE == EXPECTED_IMAGE_TO_PROFILE
    for ref in T1 + T2:
        assert any(k in IMAGE_TO_PROFILE for k in profile_keys(ref.family, ref.ver)), (
            ref.family,
            ref.ver,
        )


def test_paths_by_family_dir():
    for ref in T1 + T2 + T3:
        prefix = FAMILY_DIRS[ref.family] + "/"
        assert str(ref.path).startswith(prefix), (ref.family, ref.path)
        assert ref.sku
        assert ref.ver
