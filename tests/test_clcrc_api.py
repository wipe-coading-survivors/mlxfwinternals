import struct
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import mlxfwutil  # noqa: E402
from mlxfwutil import clcrc_calc, clcrc_unwrap, clcrc_wrap  # noqa: E402


def synth_payload(nlines):
    out = bytearray()
    x = 0x1234
    for _ in range(nlines * 64):
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        out.append((x >> 16) & 0xFF)
    return bytes(out)


def test_round_trip_synthetic_nonstandard_tail():
    payload = synth_payload(3)
    tail = b"\xde\xad\xbe\xef\x80"
    raw = clcrc_wrap(payload, tail)
    assert len(raw) == 3 * 68 + len(tail)
    assert clcrc_unwrap(raw) == (payload, tail)
    assert clcrc_wrap(*clcrc_unwrap(raw)) == raw


def test_wrap_line_framing():
    payload = synth_payload(2)
    raw = clcrc_wrap(payload)
    for i in range(2):
        line = raw[i * 68:(i + 1) * 68]
        assert line[:64] == payload[i * 64:(i + 1) * 64]
        assert line[64:66] == b"\x00\x00"
        assert line[66:68] == struct.pack("<H", clcrc_calc(line[:66]))


def test_unwrap_tail_verbatim():
    payload = synth_payload(2)
    raw = clcrc_wrap(payload) + b"TAIL"
    got_payload, tail = clcrc_unwrap(raw)
    assert got_payload == payload
    assert tail == b"TAIL"


def test_unwrap_empty_and_tail_only():
    assert clcrc_unwrap(b"") == (b"", b"")
    assert clcrc_unwrap(b"\x01\x02") == (b"", b"\x01\x02")


def test_wrap_empty_payload():
    assert clcrc_wrap(b"") == b""
    assert clcrc_wrap(b"", b"xy") == b"xy"


def test_unwrap_corrupt_stored_clcrc_raises():
    raw = bytearray(clcrc_wrap(synth_payload(3)))
    raw[1 * 68 + 66] ^= 0xFF
    with pytest.raises(ValueError):
        clcrc_unwrap(bytes(raw))


def test_unwrap_corrupt_payload_raises():
    raw = bytearray(clcrc_wrap(synth_payload(3)))
    raw[2 * 68 + 10] ^= 0xFF
    with pytest.raises(ValueError):
        clcrc_unwrap(bytes(raw))


def test_unwrap_error_names_line():
    raw = bytearray(clcrc_wrap(synth_payload(3)))
    raw[2 * 68 + 64] ^= 0xFF
    with pytest.raises(ValueError, match="line 2"):
        clcrc_unwrap(bytes(raw))


def test_wrap_rejects_payload_not_multiple_of_64():
    with pytest.raises(ValueError):
        clcrc_wrap(b"\x00" * 65)
    with pytest.raises(ValueError):
        clcrc_wrap(b"\x00" * 63, b"t")


def test_reexport_from_scripts_irisc():
    from scripts.irisc import clcrc_unwrap as u, clcrc_wrap as w
    assert u is mlxfwutil.clcrc_unwrap
    assert w is mlxfwutil.clcrc_wrap


REAL_IMAGES = (
    "cx-5-6/fw-ConnectX5-rel-16_35_4030-MCX516A-CDA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin",
    "cx-4/fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin",
)


@pytest.mark.slow
@pytest.mark.parametrize("rel", REAL_IMAGES, ids=["4030", "1900-GCA"])
def test_main_code_round_trip_real(rel):
    path = REPO / "refs" / "fw" / rel
    if not path.is_file():
        pytest.skip("image not present: %s" % rel)
    img = mlxfwutil.Image(path.read_bytes(), str(path))
    e = img.find_entry("ITOC", 0x03)
    raw = img.section_data(e)
    assert clcrc_wrap(*clcrc_unwrap(raw)) == raw
