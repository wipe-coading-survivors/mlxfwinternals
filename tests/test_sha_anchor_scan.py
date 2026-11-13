"""Tests for scripts/probes/sha_anchor_scan.py (burn-digest-gate task-03).

Synthetic-data tests for the SHA-2/SHA-1 constant-table anchor scanner:
table-prefix detection (>=4 consecutive constants, BE and LE), correct
algo/endian/offset/constant attribution, the >=4 threshold (3 consecutive
constants = noise), and SHA-512 vs SHA-256 width attribution (H512 high
halves collide with H256; K512 high halves collide with K256).
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "probes"))

import sha_anchor_scan as sas  # noqa: E402


def synth_bg(size):
    out = bytearray(size)
    x = 0x1234
    for i in range(size):
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        out[i] = (x >> 16) & 0xFF
    return out


def pack(vals, width, endian):
    return b"".join(v.to_bytes(width, endian) for v in vals)


def test_planted_table_prefixes_found():
    buf = synth_bg(0x400)
    buf[0x40:0x40 + 6 * 4] = pack(sas.K256[:6], 4, "big")
    buf[0x100:0x100 + 8 * 4] = pack(sas.H256, 4, "big")
    buf[0x180:0x180 + 5 * 4] = pack(sas.SHA1_IV, 4, "little")
    buf[0x200:0x200 + 5 * 8] = pack(sas.K512[:5], 8, "big")
    hits = sas.scan(bytes(buf))
    got = {(h.algo, h.endian): h for h in hits}
    assert set(got) == {("sha256_k", "be"), ("sha256_h", "be"),
                        ("sha1_h", "le"), ("sha512_k", "be")}
    k = got[("sha256_k", "be")]
    assert (k.offset, k.constant) == (0x40, 0x428A2F98)
    h = got[("sha256_h", "be")]
    assert (h.offset, h.constant) == (0x100, 0x6A09E667)
    s1 = got[("sha1_h", "le")]
    assert (s1.offset, s1.constant) == (0x180, 0x67452301)
    k5 = got[("sha512_k", "be")]
    assert (k5.offset, k5.constant) == (0x200, 0x428A2F98D728AE22)


def test_no_long_series_empty():
    assert sas.scan(synth_bg(0x400)) == []


def test_below_threshold_is_noise():
    buf = synth_bg(0x200)
    buf[0x40:0x40 + 3 * 4] = pack(sas.K256[:3], 4, "big")
    buf[0x80:0x84] = pack([sas.H256[0]], 4, "big")
    assert sas.scan(bytes(buf)) == []


def test_h512_attributed_by_width_not_h256():
    buf = synth_bg(0x200)
    buf[0x40:0x40 + 8 * 8] = pack(sas.H512, 8, "big")
    hits = sas.scan(bytes(buf))
    assert [(h.algo, h.endian, h.offset, h.constant) for h in hits] == [
        ("sha512_h", "be", 0x40, 0x6A09E667F3BCC908)]
