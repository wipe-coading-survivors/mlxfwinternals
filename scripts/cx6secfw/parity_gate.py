#!/usr/bin/env python3
"""РЕШАЮЩИЙ численный formula-parity гейт CX-6 Dx (task-05, спека §2.4).

Проверяет ОБЕ вендорские подписи refs-VDA (22.50.1002 MCX623435AC-VDA)
бит-в-бит воспроизведением подписываемых данных/дайджеста + RSA-verify
хранимой подписи вендорским pubkey (0xA4 slot0, uuid c55d54e8…, e=65537)
с точным EM-match (полная PKCS#1 v1.5 структура, не только дайджест):

(а) 0xA3 fw-update (SignForFwUpdate, SHA-512):
    M = image[0..sizeOfImgData), sizeOfImgData = max(addr+size) по ITOC
    (=0x792880); маски 0xFF: magic16, ITOC-entry(0xA0)+data(0xA0),
    ITOC-entry(0xA3)+data(0xA3). ITOC-записи лежат в таблице
    (itoc_off+0x20+idx*0x20), не «перед данными» (питфолл прецедента
    scripts/secfw/parity_em_pitfall.py).

(б) 0xA7 secure-boot V1 (SignForSecureBoot):
    boot = image[auth_start..auth_end] = [0x0..0x6fff] БЕЗ масок
    (getBootDataForSignVersion1, fs4_ops.cpp:4437);
    critical = ITOC-секции {0x04 PCIE_LINK_CODE, 0x08 HW_BOOT_CFG,
    0x0c PCIE_PHY_UC_CODE} (IsCriticalSection fs3_ops.cpp:4079; ВНИМАНИЕ:
    номера в журнале task-01 были неверны — канон flint_base.h:346-354)
    в порядке таблицы ITOC, каждая + 0xFF-паддинг до GLOBAL_ALIGNMENT 0x80
    (fw_ops.h:66); non_critical = все прочие ITOC-секции КРОМЕ
    0xA0/0xA3/0xA7 (fs4_ops.cpp:5526), тот же паддинг/порядок.

V1/V2: на refs-VDA hashes_table HW-поинтер инвалид (raw 0xFFFFFFFF) ⇒
getSecureBootSignVersion = VERSION_1 (task-01) ⇒ V2-маски НЕ активны.
Реализована ТОЛЬКО RemoveCRCsFromMainSection (fs4_ops.cpp:537; флаг
v2_main_crc ниже) — негатив-контроль: её применение ЛОМАЕТ матч 0xA3
(доказательство формулы образа — V1). MaskBootRecordCRC (:590) НЕ
реализована: на CX-6 V2-путь клиента в принципе недостижим —
getBootRecordSize (:4406) не имеет кейса CX6DX (журнал task-05).
fs4 maskDevToc — no-op (fs4_ops.cpp:4296), DTOC-маски в формуле нет.

Негатив-контроли: снятие любого активного элемента маски/диапазона
ломает матч. Исключение (задокументировано): маска data(0xA0) на
refs-VDA — тождество (секция стёрта 0xFF), в формуле есть, но
ненаблюдаема на этом образе (наблюдаема будет на SS-сборке, где 0xA0
заполнен до маскирования).

Запуск из корня репо:

  python3 scripts/cx6secfw/parity_gate.py [image]

Вердикт: строки "VERDICT 0xA3: PARITY|MISMATCH", "VERDICT 0xA7: …",
"VERDICT boot-anchor: …"; rc=0 только при полном PARITY.
"""
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import mlxfwutil  # noqa: E402

SRC = ("refs/fw/cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX623435AC-VDA_Ax"
       "-UEFI-14.43.10-FlexBoot-3.9.101.signed.bin")

DER_SHA512 = bytes.fromhex("3051300d060960864801650304020305000440")
CRITICAL_TYPES = frozenset((0x04, 0x08, 0x0C))
EXCLUDED_NON_CRIT = frozenset((0xA0, 0xA3, 0xA7))
GLOBAL_ALIGNMENT = 0x80
FS4_HW_PTR_START = 0x18


def rsa_em(sig: bytes, key: bytes, exp: int) -> bytes:
    return pow(int.from_bytes(sig, "big"), exp,
               int.from_bytes(key, "big")).to_bytes(len(key), "big")


def em_exact(em: bytes, digest: bytes) -> bool:
    """Точный EM-match: полная структура PKCS#1 v1.5 + DER + дайджест."""
    t = DER_SHA512 + digest
    want = b"\x00\x01" + b"\xff" * (len(em) - 3 - len(t)) + b"\x00" + t
    return em == want


def em_digest(em: bytes) -> bytes:
    i = em.find(b"\x00", 2)
    if i == -1 or len(em) - i - 1 < len(DER_SHA512) + 64:
        raise ValueError(f"EM has no PKCS#1 v1.5 T-block: {em[:8].hex()}…")
    return em[i + 1 + len(DER_SHA512):]


class Gate:
    def __init__(self, src: str):
        self.src = src
        self.buf = open(src, "rb").read()
        self.img = mlxfwutil.Image(self.buf, src)
        self.ents = self.img.entries("ITOC")
        self.by_type: dict[int, list] = {}
        for e in self.ents:
            self.by_type.setdefault(e.type, []).append(e)
        self.ea0 = self.by_type[0xA0][0]
        self.ea3 = self.by_type[0xA3][0]
        self.ea4 = self.by_type[0xA4][0]
        self.tot = max(e.addr + e.size for e in self.ents)
        slot = self.img.section_data(self.ea4)[0:544]
        self.key0 = slot[0x20:0x220]
        self.exp0 = int.from_bytes(slot[0xC:0x10], "big")
        self.uuid0 = slot[0x10:0x20]
        self.a3 = self.img.section_data(self.ea3)
        self.a7 = self.img.section_data(self.by_type[0xA7][0])
        self.ok = True

    def entry_off(self, e) -> int:
        return self.img.itoc_off + 0x20 + e.index * 0x20

    def hw_ptr(self, idx: int) -> int:
        raw = int.from_bytes(
            self.buf[FS4_HW_PTR_START + idx * 8:FS4_HW_PTR_START + idx * 8 + 4],
            "big")
        return raw & 0xFFFFFFFF if raw != 0xFFFFFFFF else 0

    def fail(self, msg: str):
        self.ok = False
        print(msg)

    def mk_0xa3(self, mask_magic=True, mask_ea0=True, mask_da0=True,
                mask_ea3=True, mask_da3=True, v2_main_crc=False,
                tail=None) -> bytes:
        m = bytearray(self.buf[:self.tot if tail is None else tail])
        if mask_magic:
            m[0:0x10] = b"\xff" * 0x10
        if mask_ea0:
            m[self.entry_off(self.ea0):self.entry_off(self.ea0) + 0x20] = \
                b"\xff" * 0x20
        if mask_da0:
            m[self.ea0.addr:self.ea0.addr + self.ea0.size] = \
                b"\xff" * self.ea0.size
        if mask_ea3:
            m[self.entry_off(self.ea3):self.entry_off(self.ea3) + 0x20] = \
                b"\xff" * 0x20
        if mask_da3:
            m[self.ea3.addr:self.ea3.addr + self.ea3.size] = \
                b"\xff" * self.ea3.size
        if v2_main_crc:
            e03 = self.by_type[0x03][0]
            out = bytearray()
            prev = 0
            for off in range(0, e03.size, 68):
                ls = e03.addr + off
                out += m[prev:ls]
                take = 64 if off + 68 <= e03.size else e03.size - off
                out += m[ls:ls + take]
                prev = ls + (68 if off + 68 <= e03.size else e03.size - off)
            out += m[prev:]
            m = out
        return bytes(m)

    def check_sig(self, label: str, sig: bytes, data: bytes) -> bool:
        em = rsa_em(sig, self.key0, self.exp0)
        dig = hashlib.sha512(data).digest()
        exact = em_exact(em, dig)
        print(f"  {label:34s} len={len(data):#9x} "
              f"sha512={dig.hex()[:16]}… EM-exact={exact}")
        if not exact:
            self.fail(f"  !! {label}: EM mismatch")
        return exact

    def run(self) -> int:
        print(f"image: {self.src}")
        print(f"  itoc_off={self.img.itoc_off:#x} sizeOfImgData"
              f"(max addr+size)={self.tot:#x}")
        print(f"  vault slot0: uuid={self.uuid0.hex()} exp={self.exp0:#x} "
              f"mod={self.key0[:8].hex()}…")
        print(f"  0xA3: sig_uuid={self.a3[0:0x10].hex()} "
              f"keypair_uuid={self.a3[0x10:0x20].hex()}")
        assert self.a3[0x10:0x20] == self.uuid0, \
            "0xA3.keypair_uuid != 0xA4.slot0.uuid"

        print("\n== (a) 0xA3 fw-update signature (SHA-512, V1 formula) ==")
        sig_fw = self.a3[0x20:0x220]
        em = rsa_em(sig_fw, self.key0, self.exp0)
        target = em_digest(em)
        print(f"  stored-sig EM digest: {target.hex()[:24]}… "
              f"DER-ok={em[len(em) - 83:len(em) - 64] == DER_SHA512}")
        full = hashlib.sha512(self.mk_0xa3()).digest()
        m_a3 = em_exact(em, full)
        print(f"  full formula (all masks, range [0..{self.tot:#x})): "
              f"digest-match={full == target} EM-exact={m_a3}")
        if not m_a3:
            self.fail("  !! 0xA3 full formula does not reproduce EM")
        neg = {
            "neg: no-magic16": dict(mask_magic=False),
            "neg: no-0xA0-entry-mask": dict(mask_ea0=False),
            "neg: no-0xA0-data-mask": dict(mask_da0=False),
            "neg: no-0xA3-entry-mask": dict(mask_ea3=False),
            "neg: no-0xA3-data-mask": dict(mask_da3=False),
            "neg: 4MB-cap-range": dict(tail=0x400000),
            "neg: V2 remove-main-CRC (must break: V1 image)":
                dict(v2_main_crc=True),
        }
        for name, kw in neg.items():
            h = hashlib.sha512(self.mk_0xa3(**kw)).digest()
            broke = h != target
            note = "" if broke else \
                "  (UNOBSERVABLE: 0xA0 erased=0xFF on refs-VDA — mask " \
                "identity, active per client formula)"
            if not broke and "0xA0-data" not in name:
                self.fail(f"  !! {name}: still matches — mask not active?!")
            print(f"  {name:46s} broke={broke}{note}")

        print("\n== (b) 0xA7 secure-boot V1 signatures ==")
        auth_start = self.hw_ptr(4)
        auth_end = self.hw_ptr(5)
        ht = "INVALID(raw 0xFFFFFFFF)" if self.hw_ptr(15) == 0 \
            else hex(self.hw_ptr(15))
        print(f"  hw-pointers: auth_start={auth_start:#x} "
              f"auth_end={auth_end:#x} "
              f"public_key(idx12)={self.hw_ptr(12):#x} "
              f"(=0xA6 addr {self.by_type[0xA6][0].addr:#x}) "
              f"digest(idx6)={self.hw_ptr(6):#x} "
              f"(=0xA7 addr {self.by_type[0xA7][0].addr:#x}) "
              f"hashes_table(idx15)={ht} -> VERSION_1")
        boot = self.buf[auth_start:auth_end + 1]
        sigs = {"boot_signature": self.a7[0:0x200],
                "critical_signature": self.a7[0x200:0x400],
                "non_critical_signature": self.a7[0x400:0x600]}
        m_boot = self.check_sig("boot [auth_start..auth_end]",
                                sigs["boot_signature"], boot)

        def concat(select_crit: bool) -> bytes:
            out = b""
            for e in sorted(self.ents, key=lambda x: x.index):
                if e.type in EXCLUDED_NON_CRIT:
                    continue
                if (e.type in CRITICAL_TYPES) != select_crit:
                    continue
                d = self.img.section_data(e)
                pad = (GLOBAL_ALIGNMENT - len(d) % GLOBAL_ALIGNMENT) \
                    % GLOBAL_ALIGNMENT
                out += d + b"\xff" * pad
            return out

        crit, noncrit = concat(True), concat(False)
        crit_types = [hex(e.type) for e in sorted(self.ents, key=lambda x: x.index)
                      if e.type in CRITICAL_TYPES]
        print(f"  critical sections (ITOC table order): {crit_types}")
        m_crit = self.check_sig("critical concat (pad 0xFF->0x80)",
                                sigs["critical_signature"], crit)
        m_noncrit = self.check_sig("non-critical concat (excl 0xA0/A3/A7)",
                                   sigs["non_critical_signature"], noncrit)

        print("  -- 0xA7 negative controls --")
        negb = {
            "boot range [0..0x6ffe] (-1 byte)":
                (self.buf[0:0x6fff], sigs["boot_signature"]),
            "boot range [0..0x7000] (+1 byte)":
                (self.buf[0:0x7001], sigs["boot_signature"]),
            "boot data byte flipped @0x5004 (ITOC hdr)":
                (self.buf[0:0x5004] + bytes([self.buf[0x5004] ^ 1])
                 + self.buf[0x5005:0x7000], sigs["boot_signature"]),
            "critical w/o 0xFF padding":
                (b"".join(self.img.section_data(e) for e in
                          sorted(self.ents, key=lambda x: x.index)
                          if e.type in CRITICAL_TYPES),
                 sigs["critical_signature"]),
            "critical incl. excluded 0xA3 data":
                (crit + self.img.section_data(self.ea3),
                 sigs["critical_signature"]),
            "non-critical incl. excluded 0xA0 data":
                (noncrit + self.img.section_data(self.ea0),
                 sigs["non_critical_signature"]),
        }
        for name, (data, sig) in negb.items():
            em = rsa_em(sig, self.key0, self.exp0)
            broke = not em_exact(em, hashlib.sha512(data).digest())
            if not broke:
                self.fail(f"  !! {name}: still matches?!")
            print(f"  {name:46s} broke={broke}")

        print("\n== verdicts ==")
        print(f"VERDICT 0xA3: {'PARITY' if m_a3 else 'MISMATCH'}")
        v_a7 = m_boot and m_crit and m_noncrit
        print(f"VERDICT 0xA7 (boot+critical+non-critical): "
              f"{'PARITY' if v_a7 else 'MISMATCH'}")
        print(f"VERDICT formula (0xA3+0xA7, V1 mask set): "
              f"{'PARITY' if (m_a3 and v_a7 and self.ok) else 'MISMATCH'}")
        return 0 if (m_a3 and v_a7 and self.ok) else 1


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else SRC
    sys.exit(Gate(src).run())


if __name__ == "__main__":
    main()
