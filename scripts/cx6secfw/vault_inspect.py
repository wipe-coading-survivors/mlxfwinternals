#!/usr/bin/env python3
"""Vault-section inspector for CX-6 Dx FS4 images (cycle cx6dx-securefw, T0).

Parses ITOC sections 0xA1/0xA4/0xA6 (public key vaults) plus 0xA3/0xA7
(signature sections) of the given image(s) and prints a per-slot table:

  - 0xA4 = public_keys_2  (8 x 544B: auth_cfg@0x0, reserved@0x4, exp@0xC,
    uuid@0x10, modulus-4096@0x20)   -- tools_layouts/image_layout_layouts.h:287
  - 0xA6 = public_keys_3  (8 x 544B, rotated: exp@0x0, uuid@0x4,
    modulus-4096@0x14, auth_cfg@0x214) -- image_layout_layouts.h:308
  - 0xA1 = public_keys   (8 x 288B: auth_cfg@0x0, reserved@0x4, exp@0xC,
    uuid@0x10, modulus-2048@0x20)   -- image_layout_layouts.h:266

Cross-checks: same key set in 0xA4 and 0xA6; vendor roots
(uuid c55d54e8..., modulus-prefix c1da650b...) localized in both vault
sections; 0xA3 keypair_uuid resolved against the vault.

Usage (from the repo root):

  python3 scripts/cx6secfw/vault_inspect.py <image.bin> [<image2.bin> ...]

Reference images of the cycle:
  refs/fw/cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX623435AC-VDA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.signed.bin
  refs/fw/cx-5-6/FB-BKP/fb/MCX623435MC-CDAE_FB_Ax-ocr-ri.bin
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import mlxfwutil  # noqa: E402

VENDOR_ROOT_UUID = "c55d54e89ea74469b5e8d93572c2ff3d"
VENDOR_ROOT_MODULUS_PREFIX = "c1da650b"

LAYOUTS = {
    0xA1: dict(slot=288, auth=0x00, exp=0x0C, uuid=0x10, mod=0x20, modlen=256),
    0xA4: dict(slot=544, auth=0x00, exp=0x0C, uuid=0x10, mod=0x20, modlen=512),
    0xA6: dict(slot=544, auth=0x214, exp=0x00, uuid=0x04, mod=0x14, modlen=512),
}

AUTH_FLAGS = [
    (31, "fw_en"), (30, "cs_token_en"), (29, "vendor_nvconfig_en"),
    (28, "mlnx_nvconfig_en"), (27, "frc_en"), (26, "btc_token_en"),
    (25, "c_r_token_en"), (23, "vendor_cert_en"), (22, "mlnx_cert_en"),
]


def auth_cfg_str(v: int) -> str:
    names = [n for b, n in AUTH_FLAGS if v & (1 << b)]
    return "auth_type=%d %s" % (v & 0xFF, "|".join(names) if names else "-")


def slots(img, typ):
    lay = LAYOUTS[typ]
    e = img.find_entry("ITOC", typ)
    data = img.section_data(e)
    out = []
    for i in range(len(data) // lay["slot"]):
        s = data[i * lay["slot"]:(i + 1) * lay["slot"]]
        if s == b"\xff" * lay["slot"] or s == b"\x00" * lay["slot"]:
            out.append(dict(idx=i, empty=("FF" if s[0] == 0xFF else "00")))
            continue
        exp = int.from_bytes(s[lay["exp"]:lay["exp"] + 4], "big")
        uuid = s[lay["uuid"]:lay["uuid"] + 16].hex()
        mod = s[lay["mod"]:lay["mod"] + lay["modlen"]]
        auth = int.from_bytes(s[lay["auth"]:lay["auth"] + 4], "big")
        out.append(dict(idx=i, empty=None, auth=auth, exp=exp, uuid=uuid,
                        mod=mod, modhex=mod.hex()))
    return out


def inspect(path: str) -> bool:
    buf = open(path, "rb").read()
    img = mlxfwutil.Image(buf, path)
    print("=" * 78)
    print(path)
    print("fmt=%s ITOC@0x%x  vaults: %s" % (
        img.fmt, img.itoc_off,
        " ".join("0x%02X=%dB" % (t, img.find_entry("ITOC", t).size)
                 for t in (0xA1, 0xA4, 0xA6))))
    vaults = {}
    for typ in (0xA1, 0xA4, 0xA6):
        st = slots(img, typ)
        vaults[typ] = st
        print("-- 0x%02X slots (%dB each):" % (typ, LAYOUTS[typ]["slot"]))
        for s in st:
            if s["empty"]:
                print("   slot%d: empty (all-0x%s)" % (s["idx"], s["empty"]))
                continue
            print("   slot%d: auth_cfg=0x%08x [%s]" % (s["idx"], s["auth"],
                                                       auth_cfg_str(s["auth"])))
            print("          exp=%d (0x%x)  uuid=%s" % (s["exp"], s["exp"], s["uuid"]))
            print("          modulus[0:8]=%s… len=%dB" % (s["modhex"][:16], len(s["mod"])))

    a3 = img.section_data(img.find_entry("ITOC", 0xA3))
    a3_uuid = a3[0x10:0x20].hex()
    print("-- 0xA3 (image_signature_2, %dB): signature_uuid=%s keypair_uuid=%s" % (
        len(a3), a3[0x00:0x10].hex(), a3_uuid))
    a7 = img.section_data(img.find_entry("ITOC", 0xA7))
    nz7 = [a7[o:o + 512] for o in (0x0, 0x200, 0x400)
           if a7[o:o + 512] not in (b"\x00" * 512, b"\xff" * 512)]
    print("-- 0xA7 (secure_boot_signatures, %dB): %d/3 signature blocks populated" % (
        len(a7), len(nz7)))

    ok = True
    keys_a4 = {s["uuid"]: s["modhex"][:16] for s in vaults[0xA4] if not s["empty"]}
    keys_a6 = {s["uuid"]: s["modhex"][:16] for s in vaults[0xA6] if not s["empty"]}
    if keys_a4 != keys_a6:
        print("!! 0xA4 and 0xA6 key sets differ: %s vs %s" % (keys_a4, keys_a6))
        ok = False
    else:
        print("OK  0xA4 == 0xA6 key set: %s" % ", ".join(
            "uuid=%s mod=%s…" % (u, m) for u, m in keys_a4.items()))
    for typ in (0xA4, 0xA6):
        for s in vaults[typ]:
            if s.get("uuid") == VENDOR_ROOT_UUID and s["modhex"].startswith(VENDOR_ROOT_MODULUS_PREFIX):
                break
        else:
            print("!! vendor root (uuid %s… / modulus %s…) NOT found in 0x%02X"
                  % (VENDOR_ROOT_UUID[:8], VENDOR_ROOT_MODULUS_PREFIX, typ))
            ok = False
    if ok:
        print("OK  vendor root uuid=%s… modulus=%s… localized in 0xA4 and 0xA6" % (
            VENDOR_ROOT_UUID[:8], VENDOR_ROOT_MODULUS_PREFIX))
    if a3_uuid not in keys_a4:
        print("!! 0xA3 keypair_uuid %s not present in vault 0xA4" % a3_uuid)
        ok = False
    else:
        print("OK  0xA3 keypair_uuid=%s resolves to vault slot (fw-update sig key)" % a3_uuid)
    return ok


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    rc = 0
    for p in argv[1:]:
        if not inspect(p):
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
