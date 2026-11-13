import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import sfp_recode  # noqa: E402


def run_main(capsys, *argv):
    rc = sfp_recode.main(list(argv))
    out, err = capsys.readouterr()
    return rc, out, err


def make_chunk(fill=0x00, cc_off=63, diff_byte=None, cc_val=None):
    """64-байтный чанк с согласованным CC@cc_off (сумма 0..cc_off-1)."""
    data = bytearray([fill] * 64)
    if diff_byte is not None:
        data[10] = diff_byte
    cc = sum(data[i] for i in range(64) if i != cc_off) & 0xFF
    data[cc_off] = cc_val if cc_val is not None else cc
    return bytes(data)


def test_build_single_byte_patch_diff_output(tmp_path, capsys):
    src = tmp_path / "in.bin"
    dst = tmp_path / "out.bin"
    src.write_bytes(make_chunk(diff_byte=1))
    rc, out, err = run_main(
        capsys, "build", str(src), str(dst),
        "--set", f"20=0x25")
    assert rc == 0
    assert dst.read_bytes()[20] == 0x25
    assert "diff bytes:" in out
    assert "0x14" in out  # офсет 20 в hex
    assert err == ""


def test_cc_recompute_after_patch(tmp_path, capsys):
    src = tmp_path / "in.bin"
    dst = tmp_path / "out.bin"
    src.write_bytes(make_chunk(diff_byte=1))
    rc, out, err = run_main(
        capsys, "build", str(src), str(dst),
        "--set", "10=0x25", "--cc", "63,0,62")
    assert rc == 0
    data = dst.read_bytes()
    assert data[10] == 0x25
    assert data[63] == 0x25  # Σ(0..62) без OFF == 0x25
    assert "warning" not in err.lower()


def test_patch_overlap_cc_offset_raises():
    data = make_chunk(diff_byte=1)
    with pytest.raises(ValueError):
        sfp_recode.build_image(data, {5: 1}, (5, 0, 10))


def test_verify_consistent_cc_no_warning(tmp_path, capsys):
    src = tmp_path / "in.bin"
    dst = tmp_path / "out.bin"
    src.write_bytes(make_chunk(diff_byte=7))
    rc, out, err = run_main(
        capsys, "build", str(src), str(dst),
        "--set", "20=1", "--cc", "63,0,62")
    assert rc == 0
    assert err == ""


def test_verify_bad_cc_warns_but_builds(tmp_path, capsys):
    src = tmp_path / "in.bin"
    dst = tmp_path / "out.bin"
    src.write_bytes(make_chunk(diff_byte=7, cc_val=0x99))
    rc, out, err = run_main(
        capsys, "build", str(src), str(dst),
        "--set", "5=3", "--cc", "63,0,62")
    assert rc == 0
    assert dst.exists()
    assert "warning" in err.lower()
    assert dst.read_bytes()[63] == (7 + 3) & 0xFF


def test_no_cc_passthrough(tmp_path, capsys):
    src = tmp_path / "in.bin"
    dst = tmp_path / "out.bin"
    src.write_bytes(make_chunk(diff_byte=7, cc_val=0x99))
    rc, out, err = run_main(
        capsys, "build", str(src), str(dst), "--set", "5=3")
    assert rc == 0
    assert dst.read_bytes()[63] == 0x99  # CC-байт не тронут
    assert err == ""


def test_expect_diff_match_rc0(tmp_path, capsys):
    src = tmp_path / "in.bin"
    dst = tmp_path / "out.bin"
    src.write_bytes(make_chunk(diff_byte=7))
    rc, out, err = run_main(
        capsys, "build", str(src), str(dst),
        "--set", "10=0x25", "--expect-diff", "10:0x07>0x25")
    assert rc == 0
    assert err == ""


def test_expect_diff_mismatch_exit2(tmp_path, capsys):
    src = tmp_path / "in.bin"
    dst = tmp_path / "out.bin"
    src.write_bytes(make_chunk(diff_byte=7))
    rc, out, err = run_main(
        capsys, "build", str(src), str(dst),
        "--set", "10=0x25", "--expect-diff", "10:0x08>0x25")
    assert rc == 2
    assert "expect" in err.lower()
    assert not dst.exists()


def test_offsets_relative_to_input_file(tmp_path, capsys):
    """64-байтный чанк: byte 164 образа == офсет 36 чанка (семантика чанков)."""
    src = tmp_path / "in.bin"
    dst = tmp_path / "out.bin"
    data = bytearray(64)
    data[36] = 0x07
    data[63] = sum(data[:63]) & 0xFF
    src.write_bytes(bytes(data))
    rc, out, err = run_main(
        capsys, "build", str(src), str(dst),
        "--set", "36=0x27", "--cc", "63,0,62")
    assert rc == 0
    result = dst.read_bytes()
    assert result[36] == 0x27
    assert "0x24" in out  # 36 hex в diff-выводе
    assert result[63] == ((sum(data[:63]) - 0x07 + 0x27) & 0xFF)
