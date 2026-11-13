import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import mlxfwutil  # noqa: E402

REG = "\n".join([
    "# comment line",
    "CARD_TEST_X_GUID = 0011223344556677",
    "CARD_TEST_X_MAC = 001122334455",
    "CARD_TEST_X_IP = 192.0.2.10",
    "CARD_TEST_X_BMC_IP = 192.0.2.11",
    "CARD_TEST_X_HOSTNAME = card-test-x.lab.example",
    "CARD_OTHER = deadbeef",
    "",
])


def test_hw_lookup(tmp_path):
    f = tmp_path / "hardware.local.md"
    f.write_text(REG)
    assert mlxfwutil.hw("CARD_TEST_X", "guid", path=f) == "0011223344556677"
    assert mlxfwutil.hw("CARD_TEST_X", "GUID", path=f) == "0011223344556677"
    assert mlxfwutil.hw("card_test_x", "mac", path=f) == "001122334455"


def test_hw_net_fields(tmp_path):
    f = tmp_path / "hardware.local.md"
    f.write_text(REG)
    assert mlxfwutil.hw("CARD_TEST_X", "ip", path=f) == "192.0.2.10"
    assert mlxfwutil.hw("CARD_TEST_X", "IP", path=f) == "192.0.2.10"
    assert mlxfwutil.hw("CARD_TEST_X", "bmc_ip", path=f) == "192.0.2.11"
    assert mlxfwutil.hw("CARD_TEST_X", "hostname", path=f) == "card-test-x.lab.example"


def test_hw_missing_key(tmp_path):
    f = tmp_path / "hardware.local.md"
    f.write_text(REG)
    with pytest.raises(KeyError):
        mlxfwutil.hw("CARD_TEST_X", "vuid", path=f)
    with pytest.raises(KeyError):
        mlxfwutil.hw("CARD_NOPE", "guid", path=f)


def test_hw_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        mlxfwutil.hw("CARD_TEST_X", "guid", path=tmp_path / "nope.local.md")
