import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

from publish import transform  # noqa: E402

REAL = {
    "guid": "0200de0300adbeef",
    "mac": "0200deadbeef",
    "ip": "192.0.2.10",
    "bmc_ip": "192.0.2.11",
    "hostname": "card-a.lab.example",
}

_HASHSEED_CODE = (
    "from publish.transform import fake_value; "
    "print(fake_value('CARD_A', 'guid', '0200de0300adbeef'))"
)


def test_fake_value_deterministic():
    for field, real in REAL.items():
        a = transform.fake_value("CARD_A", field, real)
        b = transform.fake_value("CARD_A", field, real)
        assert a == b


def test_fake_value_stable_across_hashseed():
    want = transform.fake_value("CARD_A", "guid", REAL["guid"])
    for seed in ("0", "1", "12345"):
        env = dict(
            os.environ,
            PYTHONPATH=str(REPO / "scripts"),
            PYTHONHASHSEED=seed,
        )
        r = subprocess.run(
            [sys.executable, "-c", _HASHSEED_CODE],
            env=env, capture_output=True, text=True, check=True)
        assert r.stdout.strip() == want


def test_fake_value_injective_per_label_field():
    pairs = [
        (f"CARD_{i}", field)
        for i in range(6)
        for field in ("guid", "mac", "ip", "bmc_ip", "hostname")
    ]
    outs = [
        transform.fake_value(label, field, REAL[field])
        for label, field in pairs
    ]
    assert len(set(outs)) == len(outs)


def test_fake_value_field_case_insensitive():
    assert (transform.fake_value("CARD_A", "MAC", REAL["mac"])
            == transform.fake_value("CARD_A", "mac", REAL["mac"]))


def test_fake_mac_format_oui_in_pool():
    mac = transform.fake_value("CARD_A", "mac", REAL["mac"])
    assert re.fullmatch(r"[0-9a-f]{12}", mac)
    assert mac[:6] in transform.OUI_POOL


def test_fake_oui_not_real_pool_oui():
    real = "0002c9aabbcc"
    mac = transform.fake_value("CARD_B", "mac", real)
    assert mac[:6] in transform.OUI_POOL
    assert mac[:6] != real[:6]


def test_fake_guid_mac_pair_0300_structure():
    label = "CARD_A"
    mac = transform.fake_value(label, "mac", REAL["mac"])
    guid = transform.fake_value(label, "guid", REAL["guid"])
    assert re.fullmatch(r"[0-9a-f]{16}", guid)
    assert guid[:6] == mac[:6]
    assert guid[6:10] == "0300"
    assert guid[10:] == mac[6:]


def test_fake_ip_test_net_3():
    for field in ("ip", "bmc_ip"):
        fake = transform.fake_value("CARD_A", field, REAL[field])
        prefix, _, last = fake.rpartition(".")
        assert prefix == "203.0.113"
        assert 1 <= int(last) <= 254
    assert (transform.fake_value("CARD_A", "ip", REAL["ip"])
            != transform.fake_value("CARD_A", "bmc_ip", REAL["bmc_ip"]))


def test_fake_hostname_format():
    h = transform.fake_value("CARD_A", "hostname", REAL["hostname"])
    assert re.fullmatch(r"node-[0-9a-f]{6}", h)


REG = "\n".join([
    "# comment line",
    "CARD_A_GUID = 0200de0300adbeef",
    "CARD_A_MAC = 0200deadbeef",
    "CARD_A_IP = 192.0.2.10",
    "CARD_A_BMC_IP = 192.0.2.11",
    "CARD_A_HOSTNAME = card-a.lab.example",
    "card_b_mac  =  0200deadbeee",
    "CARD_A_IP = 192.0.2.99",
    "",
])

REGISTRY = {
    "CARD_A_GUID": "0200de0300adbeef",
    "CARD_A_MAC": "0200deadbeef",
    "CARD_A_IP": "192.0.2.10",
    "CARD_A_BMC_IP": "192.0.2.11",
    "CARD_A_HOSTNAME": "card-a.lab.example",
}


def test_load_registry(tmp_path):
    f = tmp_path / "hardware.local.md"
    f.write_text(REG)
    reg = transform.load_registry(f)
    assert reg["CARD_A_GUID"] == "0200de0300adbeef"
    assert reg["card_b_mac"] == "0200deadbeee"
    assert reg["CARD_A_IP"] == "192.0.2.10"
    assert "comment" not in " ".join(reg)
    assert len(reg) == 6


GUID_FORMS = [
    "0200de0300adbeef",
    "0200DE0300ADBEEF",
    "02:00:de:03:00:ad:be:ef",
    "02:00:DE:03:00:AD:BE:EF",
    "02-00-de-03-00-ad-be-ef",
    "02-00-DE-03-00-AD-BE-EF",
]

MAC_FORMS = [
    "0200deadbeef",
    "0200DEADBEEF",
    "02:00:de:ad:be:ef",
    "02:00:DE:AD:BE:EF",
]


def _colon(h):
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def test_transform_tree_all_encodings(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    doc = "\n".join(
        GUID_FORMS + MAC_FORMS
        + ["192.0.2.10", "192.0.2.11", "card-a.lab.example"]) + "\n"
    (root / "doc.md").write_text(doc)
    n = transform.transform_tree(root, REGISTRY)
    assert n == 13
    out = (root / "doc.md").read_text()
    for needle in GUID_FORMS + MAC_FORMS + [
            "192.0.2.10", "192.0.2.11", "card-a.lab.example"]:
        assert needle not in out
    fake_guid = transform.fake_value("CARD_A", "guid", REGISTRY["CARD_A_GUID"])
    fake_mac = transform.fake_value("CARD_A", "mac", REGISTRY["CARD_A_MAC"])
    fake_ip = transform.fake_value("CARD_A", "ip", REGISTRY["CARD_A_IP"])
    fake_bmc = transform.fake_value("CARD_A", "bmc_ip",
                                    REGISTRY["CARD_A_BMC_IP"])
    fake_host = transform.fake_value("CARD_A", "hostname",
                                     REGISTRY["CARD_A_HOSTNAME"])
    assert fake_guid in out
    assert fake_guid.upper() in out
    assert _colon(fake_guid) in out
    assert _colon(fake_guid).upper() in out
    assert fake_mac in out
    assert _colon(fake_mac).upper() in out
    assert fake_ip in out
    assert fake_bmc in out
    assert fake_host in out


def test_transform_tree_files_and_binaries(tmp_path):
    root = tmp_path / "tree"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "nested.py").write_text('G = "0200DE0300ADBEEF"\n')
    (root / "Makefile").write_text("guid := 02:00:de:03:00:ad:be:ef\n")
    (root / "LICENSE").write_text("host card-a.lab.example\n")
    binaries = {
        root / "blob.md": b"\x000200de0300adbeef\xff",
        root / "noext-blob": b"\x000200deadbeef",
        root / "image.png": b"\x89PNG\x00" + b"0200de0300adbeef",
        root / "data.bin": b"192.0.2.10\x00",
    }
    before = {}
    for p, data in binaries.items():
        p.write_bytes(data)
        before[p] = data
    n = transform.transform_tree(root, REGISTRY)
    assert n == 3
    assert (root / "sub" / "nested.py").read_text() == (
        'G = "%s"\n' % transform.fake_value("CARD_A", "guid",
                                            REGISTRY["CARD_A_GUID"]).upper())
    assert _colon(transform.fake_value(
        "CARD_A", "guid", REGISTRY["CARD_A_GUID"])) in (
            root / "Makefile").read_text()
    assert transform.fake_value(
        "CARD_A", "hostname", REGISTRY["CARD_A_HOSTNAME"]) in (
            root / "LICENSE").read_text()
    for p, data in binaries.items():
        assert p.read_bytes() == data


def test_transform_tree_absent_value_zero(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    (root / "doc.md").write_text("nothing sensitive here\n")
    assert transform.transform_tree(root, REGISTRY) == 0
    assert (root / "doc.md").read_text() == "nothing sensitive here\n"


def test_transform_tree_word_boundaries(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    text = "ip 192.0.2.101 and host xcard-a.lab.example stay\n"
    (root / "doc.md").write_text(text)
    assert transform.transform_tree(root, REGISTRY) == 0
    assert (root / "doc.md").read_text() == text


NEW_GUID_FORMS = [
    "0200:de03:00ad:beef",
    "0200:DE03:00AD:BEEF",
    "02.00.de.03.00.ad.be.ef",
    "02.00.DE.03.00.AD.BE.EF",
    "0200.de03.00ad.beef",
    "0200.DE03.00AD.BEEF",
]

NEW_MAC_FORMS = [
    "0200:dead:beef",
    "0200:DEAD:BEEF",
    "02.00.de.ad.be.ef",
    "02.00.DE.AD.BE.EF",
    "0200.dead.beef",
    "0200.DEAD.BEEF",
]


def _grouped(h, sep, size):
    return sep.join(h[i:i + size] for i in range(0, len(h), size))


def test_transform_tree_quad_colon_and_dotted_forms(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    forms = NEW_GUID_FORMS + NEW_MAC_FORMS
    for i, form in enumerate(forms):
        (root / ("form%02d.md" % i)).write_text("id %s end\n" % form)
    n = transform.transform_tree(root, REGISTRY)
    assert n == len(forms)
    joined = "\n".join(p.read_text() for p in sorted(root.iterdir()))
    for form in forms:
        assert form not in joined
    fake_guid = transform.fake_value("CARD_A", "guid", REGISTRY["CARD_A_GUID"])
    fake_mac = transform.fake_value("CARD_A", "mac", REGISTRY["CARD_A_MAC"])
    for fake in (fake_guid, fake_mac):
        for sep, size in ((":", 4), (".", 2), (".", 4)):
            g = _grouped(fake, sep, size)
            assert g in joined
            assert g.upper() in joined


SPACE_GUID_FORMS = [
    "02 00 de 03 00 ad be ef",
    "02 00 DE 03 00 AD BE EF",
]

SPACE_MAC_FORMS = [
    "02 00 de ad be ef",
    "02 00 DE AD BE EF",
]


def test_transform_tree_space_separated_forms(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    forms = SPACE_GUID_FORMS + SPACE_MAC_FORMS
    (root / "space.md").write_text("\n".join(forms) + "\n")
    n = transform.transform_tree(root, REGISTRY)
    assert n == len(forms)
    out = (root / "space.md").read_text()
    for form in forms:
        assert form not in out
    fake_guid = transform.fake_value("CARD_A", "guid", REGISTRY["CARD_A_GUID"])
    fake_mac = transform.fake_value("CARD_A", "mac", REGISTRY["CARD_A_MAC"])
    for fake in (fake_guid, fake_mac):
        g = _grouped(fake, " ", 2)
        assert g in out
        assert g.upper() in out


def test_transform_tree_mixed_forms_fully_cleaned(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    all_forms = GUID_FORMS + NEW_GUID_FORMS + MAC_FORMS + NEW_MAC_FORMS
    (root / "mix.md").write_text("\n".join(all_forms) + "\n")
    n = transform.transform_tree(root, REGISTRY)
    assert n == len(all_forms)
    out = (root / "mix.md").read_text()
    for form in all_forms:
        assert form not in out


def test_transform_tree_packed_colon_dash_regression(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    forms = [
        "0200de0300adbeef",
        "02:00:de:03:00:ad:be:ef",
        "02-00-DE-03-00-AD-BE-EF",
        "0200DEADBEEF",
        "02:00:de:ad:be:ef",
    ]
    (root / "reg.md").write_text("\n".join(forms) + "\n")
    n = transform.transform_tree(root, REGISTRY)
    assert n == len(forms)
    out = (root / "reg.md").read_text()
    for form in forms:
        assert form not in out
