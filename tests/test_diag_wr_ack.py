import importlib.util
import pathlib

spec = importlib.util.spec_from_file_location(
    "diag_wr_ack", pathlib.Path(__file__).resolve().parent.parent / "scripts" / "diag_wr_ack.py")
diag_wr_ack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag_wr_ack)


def test_parse_data_compact():
    assert diag_wr_ack.parse_data("6400") == b"\x64\x00"


def test_parse_data_spaced():
    assert diag_wr_ack.parse_data("00 00 10 11 00 00 00 00") == \
        bytes.fromhex("0000101100000000")


def test_parse_data_commas():
    assert diag_wr_ack.parse_data("64, 00") == b"\x64\x00"
