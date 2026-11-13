#!/usr/bin/env python3
"""Set-wide offline introspection: vaults (ITOC 0xA1/0xA4/0xA6) + DTOC cert-class.

Cycle cx6dx-introspection Task 1. Extends vault_inspect.py slot layouts to
the 7-image set of the plan and maps the DTOC cert-class sections
(0xf6/f7/f4/f5/f2/0xed/0xee/0xf3 + 0xd0/0xeb/0xec): presence/addr/size,
content state (erased-FF / zeros / populated), content extraction to
build/introspect/, X.509-DER format detect (openssl x509) for populated
sections, and a whole-image DER/OID marker scan (are there certificates
ANYWHERE outside the DTOC cert-class sections).

Artifacts (git-ignored): build/introspect/<tag>-{vault,dtoc,certs}.txt
plus extracted section blobs build/introspect/<tag>-0xNN.bin.

Control (docs/250-re/110-signing/055-cx6dx-signing.md): VDA vault slots must be root
c55d54e8…/c1da650b… (slot0) + f560c160…/b99b3eb4… (slot1) — rc 1 otherwise.

Usage (from the repo root):

  python3 scripts/cx6secfw/introspect_set.py [image ...]   # default: full set
"""
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import mlxfwutil  # noqa: E402

FW = "refs/fw/cx-5-6"
IMAGES = [
    ("VDA", f"{FW}/fw-ConnectX6Dx-rel-22_50_1002-MCX623435AC-VDA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.signed.bin"),
    ("AN-VDA", f"{FW}/fw-ConnectX6Dx-rel-22_50_1002-MCX623435AN-VDA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.bin"),
    ("AN-CDA", f"{FW}/fw-ConnectX6Dx-rel-22_50_1002-MCX623435AN-CDA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.bin"),
    ("IB-1002", f"{FW}/fw-ConnectX6Dx-rel-22_50_1002-MCX683105AN-HDA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.bin"),
    ("Dell", f"{FW}/fw-ConnectX6Dx-rel-22_32_2004-0F6FXM_08P2T2_Ax-UEFI-14.25.18-FlexBoot-3.6.502.signed.bin"),
    ("623106AS", f"{FW}/fw-ConnectX6Dx-rel-22_27_6008-MCX623106AS-CDA_Ax-UEFI-14.20.25-FlexBoot-3.5.903.signed.bin"),
    ("FB", f"{FW}/FB-BKP/fb/MCX623435MC-CDAE_FB_Ax-ocr-ri.bin"),
]

VENDOR_ROOT_UUID = "c55d54e8"          # docs/250-re/110-signing/055-cx6dx-signing.md (prefix)
VENDOR_ROOT_MODULUS_PREFIX = "c1da650b"
VENDOR_ROOT2_UUID = "f560c160"         # docs/250-re/110-signing/055-cx6dx-signing.md slot1 (prefix)
VENDOR_ROOT2_MODULUS_PREFIX = "b99b3eb4"

LAYOUTS = {  # vault_inspect.py:35 (image_layout_layouts.h:266/287/308)
    0xA1: dict(slot=288, auth=0x00, exp=0x0C, uuid=0x10, mod=0x20, modlen=256),
    0xA4: dict(slot=544, auth=0x00, exp=0x0C, uuid=0x10, mod=0x20, modlen=512),
    0xA6: dict(slot=544, auth=0x214, exp=0x00, uuid=0x04, mod=0x14, modlen=512),
}

AUTH_FLAGS = [  # vault_inspect.py:41
    (31, "fw_en"), (30, "cs_token_en"), (29, "vendor_nvconfig_en"),
    (28, "mlnx_nvconfig_en"), (27, "frc_en"), (26, "btc_token_en"),
    (25, "c_r_token_en"), (23, "vendor_cert_en"), (22, "mlnx_cert_en"),
]

CERT_TYPES = {  # docs/250-re/100-formats/030-fs4.md + mlxfwutil SECT_NAMES
    0xd0: "?", 0xf6: "ROOT_CERTS_1", 0xf7: "ROOT_CERTS_2",
    0xf4: "CERT_CHAINS_1", 0xf5: "CERT_CHAINS_2", 0xf2: "CERT_CHAIN_0",
    0xed: "DIG_CERT_PTR", 0xee: "DIG_CERT_RW", 0xf3: "DIG_CERT_CACERT",
    0xeb: "PROG_HW_FW1", 0xec: "PROG_HW_FW2",
}

DER_MARKERS = {  # X.509/ASN.1 evidence markers, whole-image scan
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01": "OID rsaEncryption",
    b"\x55\x04\x03": "OID commonName (2.5.4.3)",
    b"\x55\x04\x06": "OID countryName (2.5.4.6)",
    b"\x55\x04\x0a": "OID organizationName (2.5.4.10)",
    b"\x30\x82\x30\x82": "DER SEQUENCE>SEQUENCE hdr",
}


def auth_cfg_str(v: int) -> str:
    names = [n for b, n in AUTH_FLAGS if v & (1 << b)]
    return "auth_type=%d %s" % (v & 0xFF, "|".join(names) if names else "-")


def slots(img, typ):
    lay = LAYOUTS[typ]
    data = img.section_data(img.find_entry("ITOC", typ))
    out = []
    for i in range(len(data) // lay["slot"]):
        s = data[i * lay["slot"]:(i + 1) * lay["slot"]]
        if s == b"\xff" * lay["slot"] or s == b"\x00" * lay["slot"]:
            out.append(dict(idx=i, empty=("FF" if s[0] == 0xFF else "00")))
            continue
        out.append(dict(
            idx=i, empty=None,
            auth=int.from_bytes(s[lay["auth"]:lay["auth"] + 4], "big"),
            exp=int.from_bytes(s[lay["exp"]:lay["exp"] + 4], "big"),
            uuid=s[lay["uuid"]:lay["uuid"] + 16].hex(),
            mod8=s[lay["mod"]:lay["mod"] + 8].hex()))
    return out


def vault_report(img) -> list:
    out = []
    for typ in (0xA1, 0xA4, 0xA6):
        try:
            e = img.find_entry("ITOC", typ)
        except KeyError:
            out.append("0x%02X: ABSENT" % typ)
            continue
        out.append("0x%02X @0x%x size=0x%x slots(%dB):" % (
            typ, img.sec_abs(e), e.size, LAYOUTS[typ]["slot"]))
        for s in slots(img, typ):
            if s["empty"]:
                out.append("  slot%d: empty(all-0x%s)" % (s["idx"], s["empty"]))
            else:
                out.append("  slot%d: auth_cfg=0x%08x [%s] exp=%d uuid=%s mod8=%s" % (
                    s["idx"], s["auth"], auth_cfg_str(s["auth"]), s["exp"],
                    s["uuid"], s["mod8"]))
    return out


def content_state(d: bytes) -> str:
    nz = sum(1 for b in d if b not in (0x00, 0xFF))
    if nz:
        return "POPULATED"
    return "erased-FF" if d[0] == 0xFF else "zeros"


def der_blob_detect(d: bytes) -> str:
    """X.509 DER cert candidate at offset 0: SEQUENCE, len>0x100."""
    if len(d) > 4 and d[0] == 0x30 and d[1] == 0x82:
        n = int.from_bytes(d[2:4], "big") + 4
        return "X.509-DER-candidate len=%d" % n
    hits = sum(d.count(m) for m in (b"\x55\x04\x03", b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"))
    return "bundle/DER-markers=%d" % hits if hits else "no-DER-markers"


def openssl_text(path: Path) -> str:
    p = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-text",
                        "-in", str(path)], capture_output=True, text=True)
    if p.returncode == 0:
        return p.stdout
    err = p.stderr.strip().splitlines()[:1]
    return "(openssl x509: not a cert: %s)" % (err[0] if err else "unknown")


def cert_report(img, tag: str, outdir: Path) -> list:
    out = ["DTOC cert-class map (type/name/addr/size/state):"]
    for typ, name in CERT_TYPES.items():
        try:
            e = img.find_entry("DTOC", typ)
        except KeyError:
            out.append("  0x%02x %-13s ABSENT" % (typ, name))
            continue
        d = img.section_data(e)
        state = content_state(d)
        out.append("  0x%02x %-13s addr=0x%06x size=0x%05x %s" % (
            typ, name, img.sec_abs(e), e.size, state))
        if state == "POPULATED":
            f = outdir / ("%s-0x%02x.bin" % (tag, typ))
            f.write_bytes(d)
            out.append("    first32=%s" % d[:32].hex())
            out.append("    detect: %s" % der_blob_detect(d))
            if typ != 0xED:
                out.append("    " + openssl_text(f).replace("\n", "\n    "))
    return out


def dig_cert_ptrs(img) -> list:
    d = img.section_data(img.find_entry("DTOC", 0xED))
    words = [int.from_bytes(d[i:i + 4], "big") for i in range(0, len(d), 4)]
    return ["0xED DIG_CERT_PTR DWs: " + " ".join("%08x" % w for w in words),
            "  parse: DW0=%d, then %d flash addrs (0x%08x..0x%08x)" % (
                words[0], len(words) - 1, words[1], words[-1])]


def der_scan(img) -> list:
    out = ["whole-image DER/OID marker scan:"]
    for m, name in DER_MARKERS.items():
        n = img.buf.count(m)
        out.append("  %-28s %d" % (name, n))
    return out


def vda_control(img, tag) -> bool:
    if tag != "VDA":
        return True
    ok = True
    for typ in (0xA4, 0xA6):
        st = {s["idx"]: s for s in slots(img, typ) if not s["empty"]}
        c = [(0, VENDOR_ROOT_UUID, VENDOR_ROOT_MODULUS_PREFIX),
             (1, VENDOR_ROOT2_UUID, VENDOR_ROOT2_MODULUS_PREFIX)]
        for idx, uuid, mod in c:
            s = st.get(idx)
            if not s or not s["uuid"].startswith(uuid) or not s["mod8"].startswith(mod):
                print("!! CONTROL FAIL 0x%02X slot%d: want uuid=%s mod=%s…, got %s" % (
                    typ, idx, uuid, mod, s))
                ok = False
    print("CONTROL 0xA4/0xA6 slot0/slot1 vs docs/250-re/110-signing/055-cx6dx-signing.md: %s" % ("OK" if ok else "FAIL"))
    return ok


def main(argv):
    imgs = IMAGES if len(argv) < 2 else [("arg%d" % i, p) for i, p in enumerate(argv[1:])]
    outdir = Path("build/introspect")
    outdir.mkdir(parents=True, exist_ok=True)
    rc = 0
    for tag, path in imgs:
        buf = open(path, "rb").read()
        img = mlxfwutil.Image(buf, path)
        vault = vault_report(img)
        certs = cert_report(img, tag, outdir)
        extra = []
        try:
            extra = dig_cert_ptrs(img)
        except KeyError:
            pass
        scan = der_scan(img)
        print("=" * 78)
        print("%s  %s  (len=0x%x itoc=0x%x dtoc=0x%x)" % (
            tag, path, len(buf), img.itoc_off, img.dtoc_off or 0))
        for lines in (vault, certs, extra, scan):
            for ln in lines:
                print(ln)
        (outdir / ("%s-vault.txt" % tag)).write_text("\n".join(vault) + "\n")
        (outdir / ("%s-dtoc.txt" % tag)).write_text("\n".join(certs + extra) + "\n")
        (outdir / ("%s-certs.txt" % tag)).write_text(
            "\n".join(certs + extra + scan) + "\n")
        if not vda_control(img, tag):
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
