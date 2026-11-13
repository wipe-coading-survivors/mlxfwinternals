#!/usr/bin/env python3
"""mlxfwutil — FS4 (CX-5/CX-6) firmware image toolkit.

Формат: docs/250-re/100-formats/. CRC-16 — цикл mstflint Crc16
(docs/250-re/100-formats/025-crc.md), НЕ стандартный параметризуемый CRC-16.
"""
import argparse
import hashlib
import struct
import sys
import zlib
from array import array
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

FS4_MAGIC = bytes.fromhex("4D544657ABCDEF00FADE12345678DEAD")
ITOC_HDR = bytes.fromhex("49544F43" "04081516" "2342CAFA" "BACAFE00")
CNTX_MAGIC = bytes.fromhex("4D5446578CDFD000DEAD92704154BEEF")
DTOC_HDR = bytes.fromhex("44544F43" "04081516" "2342CAFA" "BACAFE00")

SECT_NAMES = {
    0x01: "BOOT_CODE", 0x02: "PCI_CODE", 0x03: "MAIN_CODE", 0x04: "PCIE_LINK_CODE",
    0x05: "IRON_PREP_CODE", 0x06: "POST_IRON_BOOT", 0x07: "UPGRADE_CODE",
    0x08: "HW_BOOT_CFG", 0x09: "HW_MAIN_CFG", 0x0A: "PHY_UC_CODE",
    0x0B: "PHY_UC_CONSTS", 0x0C: "PCIE_PHY_UC_CODE", 0x0D: "CCIR_INFRA",
    0x0E: "CCIR_ALGO", 0x0F: "FS4_BOOT3_CODE", 0x10: "IMAGE_INFO",
    0x11: "FW_BOOT_CFG", 0x12: "FW_MAIN_CFG", 0x14: "APU_KERNEL", 0x15: "ACE_CODE",
    0x17: "ISSU_NOTCH_CFG", 0x18: "ROM_CODE", 0x20: "RESET_INFO",
    0x21: "PROG_FW_META", 0x22: "PROG_FW_BIN", 0x2A: "PRE_LINK_CODE",
    0x2B: "PRE_LINK_DATA", 0x2C: "POST_LINK_CODE", 0x2D: "POST_LINK_DATA",
    0x30: "DBG_FW_INI", 0x32: "DBG_FW_PARAMS", 0x33: "FW_ADB", 0x34: "GB_FW_CODE",
    0x35: "TILE_FW_CODE", 0x36: "FS4_FW_TILE_INI", 0x37: "FS4_HW_TILE_INI",
    0x39: "FS4_ISSU_MAIN_UID", 0x3A: "FS4_TILE_UID", 0x40: "SLOT_DEPENDENT_INI",
    0xA0: "SIG_256", 0xA1: "PUB_KEYS_2048", 0xA2: "FORBIDDEN_VER", 0xA3: "SIG_512",
    0xA4: "PUB_KEYS_4096", 0xA5: "HMAC_DIGEST", 0xA6: "FS4_RSA_PUB_KEY",
    0xA7: "FS4_RSA4096_SIGS", 0xA9: "ENC_KEY_TRANS", 0xAA: "FS4_PXIR_INI",
    0xAB: "FS4_PXIR_INI2", 0xAD: "NVDA_ROT_CERTS", 0xE0: "MFG_INFO",
    0xE1: "DEV_INFO", 0xE2: "NV_DATA1", 0xE3: "VPD_R0", 0xE4: "NV_DATA2",
    0xE5: "FW_NV_LOG", 0xE6: "NV_DATA0", 0xE7: "FS4_DEV_INFO1",
    0xE8: "FS4_DEV_INFO2", 0xE9: "CRDUMP_MASK", 0xEA: "FW_INTERNAL_USAGE",
    0xEB: "PROG_HW_FW1", 0xEC: "PROG_HW_FW2", 0xED: "DIG_CERT_PTR",
    0xEE: "DIG_CERT_RW", 0xF9: "TOOLS_AREA", 0xFA: "HASHES_TABLE",
    0xFB: "HW_PTR", 0xFC: "FW_DEBUG_DUMP", 0xFF: "END",
}


def _crc_step(crc: int, bit: int) -> int:
    msb = (crc >> 15) & 1
    crc = ((crc << 1) | bit) & 0xFFFF
    return crc ^ 0x100B if msb else crc


_CRC_L8 = None
_CRC_L16 = None
_CRC_T = None


def _crc_tables():
    global _CRC_L8, _CRC_L16, _CRC_T
    if _CRC_L8 is None:
        l8 = array("H", (0,) * 65536)
        for i in range(65536):
            c = i
            for _ in range(8):
                c = _crc_step(c, 0)
            l8[i] = c
        _CRC_L8 = l8
        _CRC_L16 = array("H", (l8[l8[i]] for i in range(65536)))
        t = array("H", (0,) * 256)
        for b in range(256):
            c = 0
            for i in range(7, -1, -1):
                c = _crc_step(c, (b >> i) & 1)
            t[b] = c
        _CRC_T = t
    return _CRC_L8, _CRC_L16, _CRC_T


def crc16_mlx(data: bytes) -> int:
    l8, l16, t = _crc_tables()
    crc = 0xFFFF
    for b in data:
        crc = l8[crc] ^ t[b]
    return l16[crc] ^ 0xFFFF


# HW pointers: 16 x 8B entry на фиксированном offset 0x18 образа
# (FS4_HW_PTR_START): ptr u32 BE + pad u16 + crc u16 BE. crc — lower-16
# второго DW (байты [6:8] entry): mstflint unpack читает crc на бите 48
# (image_layout_layouts.c:986-994), проверка берёт lower-16 DW1 (fs4_ops.cpp:322-327).
HW_PTR_OFF = 0x18
HW_PTR_COUNT = 16
HW_PTR_NAMES = [
    "boot_record_ptr", "boot2_ptr", "toc_ptr", "tools_ptr",
    "authentication_start_pointer", "authentication_end_pointer",
    "digest_pointer", "digest_recovery_key_pointer",
    "fw_window_start_pointer", "fw_window_end_pointer",
    "image_info_section_pointer", "image_signature_pointer",
    "public_key_pointer", "fw_security_version_pointer",
    "gcm_iv_delta_pointer", "hashes_table_pointer",
]

# reflect-таблица полинома 0xD008 — НЕ 0xA001 (эквивалент crc16table2
# из refs/src/mstflint/mft_utils/calc_hw_crc.c); генерируется
def _hw_crc_tbl():
    tbl = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0xD008 if c & 1 else c >> 1
        tbl.append(c)
    return tuple(tbl)


_HW_CRC_TBL = _hw_crc_tbl()


def calc_hw_crc(data: bytes) -> int:
    crc = 0xFFFF
    for i, b in enumerate(data):
        if i < 2:
            b = ~b & 0xFF
        crc = ((crc >> 8) ^ _HW_CRC_TBL[(crc ^ b) & 0xFF]) & 0xFFFF
    return ((crc << 8) & 0xFF00) | ((crc >> 8) & 0xFF)


CLCRC_LINE = 68


def clcrc_calc(data: bytes) -> int:
    crc = 0
    for b in data:
        crc = (crc >> 8) ^ _HW_CRC_TBL[(b ^ crc) & 0xFF]
    return crc


def clcrc_lines_errors(raw: bytes) -> list:
    errs = []
    for i in range(len(raw) // CLCRC_LINE):
        off = i * CLCRC_LINE
        line = raw[off:off + CLCRC_LINE]
        exp = int.from_bytes(line[66:68], "little")
        act = clcrc_calc(line[:66])
        if act != exp:
            errs.append((i, exp, act))
    return errs


def clcrc_unwrap(raw: bytes) -> tuple:
    payload = bytearray()
    nlines = len(raw) // CLCRC_LINE
    for i in range(nlines):
        off = i * CLCRC_LINE
        line = raw[off:off + CLCRC_LINE]
        exp = int.from_bytes(line[66:68], "little")
        act = clcrc_calc(line[:66])
        if act != exp:
            raise ValueError(
                f"clcrc_unwrap: line {i}: stored 0x{exp:04x} != calc 0x{act:04x}")
        payload += line[:64]
    return bytes(payload), raw[nlines * CLCRC_LINE:]


def clcrc_wrap(payload: bytes, tail: bytes = b"") -> bytes:
    if len(payload) % 64:
        raise ValueError(
            f"clcrc_wrap: payload size {len(payload)} is not a multiple of 64")
    out = bytearray()
    for i in range(len(payload) // 64):
        line = payload[i * 64:(i + 1) * 64] + b"\x00\x00"
        out += line + struct.pack("<H", clcrc_calc(line))
    return bytes(out) + tail


_HW_REGISTRY = Path(__file__).resolve().parent / "hardware.local.md"


def hw(label: str, field: str, path: Optional[Path] = None) -> str:
    """Идентификатор карты из локального реестра (hardware.local.md).

    Ярлыки карт — docs/050-hardware/100-inventory.md; формат и правила
    внесения — hardware.local.md.example. field: "guid" | "mac" | "ip" |
    "bmc_ip" | "hostname" (регистронезависимо) -> ключ <LABEL>_<FIELD>;
    whitelist'а нет — ключ строится генерически для любого field.
    Значение — как в реестре (guid/mac — hex без разделителей, как
    печатает mstflint q).
    """
    p = Path(path) if path is not None else _HW_REGISTRY
    key = f"{label}_{field}".upper()
    if not p.is_file():
        raise FileNotFoundError(
            f"hw registry missing: {p} (see hardware.local.md.example)")
    for line in p.read_text().splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, _, v = s.partition("=")
        if k.strip() == key:
            return v.strip()
    raise KeyError(f"{key} not in {p}")


def hw_ptr_crc_ok(entry: bytes) -> tuple:
    # crc принимается в обеих задокументированных позициях: struct-заголовок
    # ставит его на offset 4 (image_layout_layouts.h:382-391), unpack и
    # проверка mstflint читают lower-16 второго DW (байты [6:8]). На всех
    # локальных образах pad [4:6] = 0x0000/0xFFFF — вердикт не меняется.
    sw = crc16_mlx(entry[0:4])
    hw = calc_hw_crc(entry[0:4] + bytes(2))
    c1 = int.from_bytes(entry[4:6], "big")
    c2 = int.from_bytes(entry[6:8], "big")
    return (c1 == sw or c2 == sw, c1 == hw or c2 == hw)


def hw_pointers(buf: bytes, base: int = 0) -> dict:
    out = {}
    for i, name in enumerate(HW_PTR_NAMES):
        entry = bytes(buf[base + HW_PTR_OFF + i * 8:base + HW_PTR_OFF + i * 8 + 8])
        ptr = int.from_bytes(entry[0:4], "big")
        crc = int.from_bytes(entry[6:8], "big")
        sw_ok, hw_ok = hw_ptr_crc_ok(entry)
        out[name] = (ptr, crc, ptr not in (0, 0xFFFFFFFF) and (sw_ok or hw_ok))
    return out


class HashesTable:
    def __init__(self, data: bytes, ptr: int):
        self.data = bytearray(data)
        self.ptr = ptr
        self.version = int.from_bytes(data[12:16], "big")
        self.num = data[16]
        self.hash_type = data[17]
        self.hash_size = int.from_bytes(data[18:20], "big")
        self.max_num = (len(data) - 36) // (8 + self.hash_size)
        self.entries = []
        for i in range(self.num):
            dw = int.from_bytes(data[28 + i * 8:28 + i * 8 + 4], "big")
            self.entries.append(((dw >> 16) & 0xFF, dw & 0xFFFF))

    @classmethod
    def from_bytes(cls, data: bytes, ptr: int):
        return cls(data, ptr)

    @classmethod
    def from_image(cls, img: "Image"):
        base = getattr(img, "base", 0)  # Image.base добавляется в Task 7; до него — 0 (slot A)
        p, c, v = hw_pointers(img.buf, base)["hashes_table_pointer"]
        if not v:
            return None
        ap = base + p  # абсолютный offset таблицы в buf
        max_num = 64 if int.from_bytes(img.buf[ap + 12:ap + 16], "big") == 1 else 28
        hsize = int.from_bytes(img.buf[ap + 18:ap + 20], "big")
        size = 12 + 16 + max_num * (8 + hsize) + 8
        return cls(bytes(img.buf[ap:ap + size]), ap)

    def header_crc_ok(self) -> bool:
        return int.from_bytes(self.data[10:12], "big") == crc16_mlx(self.data[0:8])

    def data_crc_ok(self) -> bool:
        return int.from_bytes(self.data[-2:], "big") == crc16_mlx(self.data[0:len(self.data) - 4])

    def hash_addr(self, i: int) -> int:
        return self.ptr + 12 + self.entries[i][1]

    def entry_by_type(self, t: int):
        for i, (et, off) in enumerate(self.entries):
            if et == t:
                return i, off
        return None

    SKIP_TYPES = {0xA0, 0xA1, 0xA3, 0xA4, 0xA7}

    def _sync(self):
        self.data[16] = self.num
        for i in range(self.max_num):
            if i < len(self.entries):
                t, off = self.entries[i]
                dw = (t << 16) | off
            else:
                dw = 0
            self.data[28 + i * 8:28 + i * 8 + 4] = struct.pack(">I", dw)

    def update_into(self, buf: bytearray, changed: dict, itoc_types: set):
        for t, newdata in changed.items():
            if t in self.SKIP_TYPES or t not in itoc_types:
                continue
            hit = self.entry_by_type(t)
            if hit is None:
                if self.num >= self.max_num:
                    raise ValueError("hashes table: no free entry")
                off = 16 + self.max_num * 8 + self.num * self.hash_size
                self.entries.append((t, off))
                self.num += 1
                self._sync()
            else:
                off = hit[1]
            self.data[12 + off:12 + off + self.hash_size] = hashlib.sha512(newdata).digest()
        self.data[-4:] = struct.pack(">I", crc16_mlx(bytes(self.data[0:len(self.data) - 4])))
        buf[self.ptr:self.ptr + len(self.data)] = self.data


def bits(buf: bytes, off: int, n: int) -> int:
    v = 0
    for i in range(n):
        p = off + i
        v = (v << 1) | ((buf[p >> 3] >> (7 - (p & 7))) & 1)
    return v


def set_bits(ent: bytearray, off: int, n: int, val: int) -> None:
    for i in range(n):
        b = (val >> (n - 1 - i)) & 1
        p = off + i
        if b:
            ent[p >> 3] |= 1 << (7 - (p & 7))
        else:
            ent[p >> 3] &= ~(1 << (7 - (p & 7)))


def find_all(buf: bytes, pat: bytes):
    out, i = [], buf.find(pat)
    while i != -1:
        out.append(i)
        i = buf.find(pat, i + 1)
    return out


def parse_toc(buf: bytes, off: int, toc: str = "", fmt: str = "fs4") -> list:
    out = []
    i = 0
    while True:
        e = off + 32 + i * 32
        if e + 32 > len(buf):
            break
        ent = buf[e:e + 32]
        typ = bits(ent, 0, 8)
        if fmt == "fs3":
            out.append(TocEntry(
                i, toc, typ,
                bits(ent, 8, 22) * 4,
                bits(ent, 161, 29) * 4,
                bits(ent, 32, 1), bits(ent, 33, 1),
                bits(ent, 144, 16), bits(ent, 192, 1),
                bits(ent, 207, 1),
                bits(ent, 208, 16), bits(ent, 240, 16), ent,
                bits(ent, 160, 1), bits(ent, 206, 1),
                param0=bits(ent, 34, 30), param1=bits(ent, 64, 32)))
        else:
            out.append(TocEntry(
                i, toc, typ,
                bits(ent, 8, 22) * 4,
                bits(ent, 161, 29) * 4,
                bits(ent, 32, 1), bits(ent, 33, 1),
                bits(ent, 144, 16), bits(ent, 192, 1),
                bits(ent, 205, 3),
                bits(ent, 208, 16), bits(ent, 240, 16), ent,
                param0=bits(ent, 34, 30), param1=bits(ent, 64, 32)))
        if typ == 0xFF:
            break
        i += 1
    return out


@dataclass
class TocHeader:
    version: int
    flv: Optional[int] = None
    num_entries: Optional[int] = None


def parse_toc_header(hdr: bytes, fmt: str) -> TocHeader:
    if fmt == "fs4":
        return TocHeader(bits(hdr, 152, 8),
                         flv=bits(hdr, 128, 8),
                         num_entries=bits(hdr, 184, 8))
    return TocHeader(bits(hdr, 152, 8))


@dataclass
class TocEntry:
    index: int
    toc: str
    type: int
    size: int
    addr: int
    zipped: int
    clcrc: int
    ver: int
    enc: int
    crcf: int
    sec_crc: int
    entry_crc: int
    raw: bytes
    rel: int = 0
    dev: int = 0
    param0: int = 0
    param1: int = 0


class Image:
    def __init__(self, buf: bytes, path: str = "<mem>", base: int = 0, fmt: str = None):
        if len(buf) < 0x4000:
            raise ValueError(f"{path}: too small for a firmware image")
        if fmt is None:
            m = buf[base:base + 16]
            if m == FS4_MAGIC:
                fmt = "fs4"
            elif m == CNTX_MAGIC:
                fmt = "fs3"
            else:
                raise ValueError(f"{path}: not an FS4/FS3 image (magic at 0x{base:x})")
        self.buf = buf
        self.path = path
        self.base = base
        self.fmt = fmt
        self.itoc_off = self._find_itoc()
        self.itoc_hdr = buf[self.itoc_off:self.itoc_off + 32]
        self.itoc_header = parse_toc_header(self.itoc_hdr, self.fmt)
        self.itoc = self._parse(self.itoc_off, "ITOC")
        if fmt == "fs3":
            self.dtoc_off = None
            self.dtoc_hdr = None
            self.dtoc_header = None
            self.dtoc = []
        else:
            self.dtoc_off = self._find(DTOC_HDR, "DTOC", 0)
            self.dtoc_hdr = buf[self.dtoc_off:self.dtoc_off + 32]
            self.dtoc_header = parse_toc_header(self.dtoc_hdr, self.fmt)
            self.dtoc = self._parse(self.dtoc_off, "DTOC")

    def _find_itoc(self) -> int:
        if self.fmt == "fs4":
            return self._find(ITOC_HDR, "ITOC", self.base)
        offs = find_all(self.buf, ITOC_HDR)
        for o in offs:
            hdr = self.buf[o:o + 32]
            if len(hdr) >= 0x20 and crc16_mlx(hdr[:28]) == int.from_bytes(hdr[0x1E:0x20], "big"):
                return o
        if offs:
            raise ValueError(f"{self.path}: ITOC signature at "
                             f"{[hex(o) for o in offs]} but no valid header CRC")
        raise ValueError(f"{self.path}: ITOC not found")

    def _find(self, hdr: bytes, name: str, region_base: int = 0) -> int:
        region = self.buf[region_base:region_base + SLOT_SIZE] if region_base else self.buf
        offs = find_all(region, hdr)
        if not offs:
            raise ValueError(f"{self.path}: {name} not found")
        return region_base + offs[0]

    def _parse(self, off: int, name: str):
        return parse_toc(self.buf, off, name, self.fmt)

    def entries(self, toc: str):
        return [e for e in (self.itoc if toc == "ITOC" else self.dtoc) if e.type != 0xFF]

    def find_entry(self, toc: str, typ: int):
        for e in self.entries(toc):
            if e.type == typ:
                return e
        raise KeyError(f"{self.path}: section 0x{typ:02x} not in {toc}")

    def entry_at(self, toc: str, index: int):
        for e in (self.itoc if toc == "ITOC" else self.dtoc):
            if e.index == index:
                return e
        raise KeyError(f"{self.path}: {toc}[{index}] not found")

    def sec_abs(self, e) -> int:
        if self.fmt == "fs3":
            return e.addr + (self.base if e.rel else 0)
        return e.addr + (self.base if e.toc == "ITOC" else 0)

    def section_data(self, e) -> bytes:
        a = self.sec_abs(e)
        return self.buf[a:a + e.size]

    def header_crc_ok(self, toc: str) -> bool:
        hdr = self.itoc_hdr if toc == "ITOC" else self.dtoc_hdr
        return crc16_mlx(hdr[:28]) == bits(hdr, 240, 16)

    def entry_crc_ok(self, e) -> bool:
        return crc16_mlx(e.raw[:28]) == bits(e.raw, 240, 16)


def extract_section(img: Image, typ: int, toc: str = None) -> bytes:
    for t in ([toc] if toc else ("ITOC", "DTOC")):
        try:
            return img.section_data(img.find_entry(t, typ))
        except KeyError:
            pass
    raise KeyError(f"{img.path}: section 0x{typ:02x} not found")


# Подпись секции 0xA0 (SIG_256): SHA-256-дест по клиентской маске mstflint
# sign без ключей (FwInsertSHA256 -> GetImageDataForSign, fs3_ops.cpp:3571;
# FS4 наследует). Маски: magic 16B -> FF; ITOC-entry 0xA0 (32B) и data(0xA0)
# -> FF (MaskItocSectionAndEntry, fs3_ops.cpp:3628); FS3 — дополнительно все
# ITOC-записи с device_data -> FF, entry а не данные (maskDevToc,
# fs3_ops.cpp:3659; в FS4 — no-op, fs4_ops.cpp:4296). Диапазон —
# sizeOfImgData = max(sec_abs+size) по ITOC-записям, в FS3 — только
# relative (fs3_ops.cpp:654-660). Доказано бит-эквивом 56/56 стоков
# (builder-check 2026-10-28); спека mlxini-sign §3.
SIG_SLOT_OFF = 0x20
SIG_KEYPAIR_OFF = 0x10
SIG_KEYPAIR_LEN = 16


def sha256_digest(img: Image) -> bytes:
    ents = img.entries("ITOC")
    fs3 = img.fmt == "fs3"
    end = img.base
    for e in ents:
        if fs3 and not e.rel:
            continue
        end = max(end, img.sec_abs(e) + e.size)
    zones = [(img.base, 16)]
    for e in ents:
        ent_off = img.itoc_off + 32 + e.index * 32
        if e.type == 0xA0:
            zones.append((ent_off, 32))
            zones.append((img.sec_abs(e), e.size))
        if fs3 and e.dev:
            zones.append((ent_off, 32))
    buf = bytearray(img.buf[img.base:end])
    for off, size in zones:
        lo = max(off - img.base, 0)
        hi = min(off - img.base + size, len(buf))
        if hi > lo:
            buf[lo:hi] = b"\xff" * (hi - lo)
    return hashlib.sha256(bytes(buf)).digest()


def sig_status(img: Image) -> tuple:
    # Статус 0xA0 (спека §4), порядок: v2 -> missing -> rsa -> empty ->
    # fresh/stale. Возвращает (status, stored, calc): stored — 32B слот
    # @+0x20 (если читается), calc — дест (fresh/stale).
    if img.fmt == "fs4":
        ptr, crc, valid = hw_pointers(img.buf, img.base)["hashes_table_pointer"]
        if valid:
            return ("v2", None, None)
    try:
        e = img.find_entry("ITOC", 0xA0)
    except KeyError:
        return ("missing", None, None)
    data = img.section_data(e)
    if any(data[SIG_KEYPAIR_OFF:SIG_KEYPAIR_OFF + SIG_KEYPAIR_LEN]):
        stored = data[SIG_SLOT_OFF:SIG_SLOT_OFF + 32] if e.size >= 0x40 else None
        return ("rsa", stored, None)
    if e.size < 0x40:
        return ("empty", None, None)
    stored = data[SIG_SLOT_OFF:SIG_SLOT_OFF + 32]
    if set(stored) <= {0x00, 0xFF}:
        return ("empty", stored, None)
    calc = sha256_digest(img)
    if stored == calc:
        return ("fresh", stored, calc)
    return ("stale", stored, calc)


# Инвариант burn-order (спека repack-burn-safety §2.1-§2.2, разведка
# 2026-10-31 §3): клиентский write-путь mstflint (Flash::write,
# flint_io.cpp:742-752) режет запись на чанки по границе сектора; при смене
# кэшированного _curr_sector стирается ВЕСЬ сектор без сохранения соседей
# (без RMW), затем чанк программируется (NOR: биты только 1->0). Burn пишет
# boot-область [base+0x10, itoc_off+0x1000), затем ITOC-секции В ПОРЯДКЕ
# ЗАПИСЕЙ, а не адресов (fs4_ops.cpp:2706-2724); пустые записи (size=0)
# пропускаются. DTOC пишется через RMW (соседи сохраняются) — не моделируется.
# Вендорский инвариант: порядок записей == монотонный рост адресов, тогда
# каждый сектор входит в write-поток ровно один раз. Повторный вход в
# посещённый сектор = erase уничтожает уже написанные данные соседей.
DEFAULT_SECTOR = 0x10000


@dataclass
class BurnOrderViolation:
    entry: TocEntry       # запись-виновник (повторный вход в сектор)
    victims: list         # уже написанные записи, пересекающие стираемый сектор
    sector: int           # начало повторно стираемого сектора
    explanation: str


@dataclass
class DamagePrediction:
    entry: TocEntry       # пострадавшая запись
    data: bytes           # результирующие данные секции после burn
    erased_ranges: list   # (offset, size) внутри data: диапазоны 0xFF
    crc16: int            # crc16_mlx(data) — ожидание in-FNP verify


def _burn_writes(img: Image):
    # (start, end, entry) в порядке write-потока burn; entry=None — boot-область
    yield img.base + 0x10, img.itoc_off + 0x1000, None
    for e in img.entries("ITOC"):
        if e.size:
            yield img.sec_abs(e), img.sec_abs(e) + e.size, e


def burn_order_check(img: Image, sector_size: int = DEFAULT_SECTOR) -> list:
    violations = []
    visited = set()
    written = []  # (start, end, entry) уже написанных секций
    curr = None
    for start, end, e in _burn_writes(img):
        s = start
        while s < end:
            sect = s & ~(sector_size - 1)
            if sect != curr:
                curr = sect
                if sect in visited and e is not None:
                    victims = [w for a, b, w in written
                               if a < sect + sector_size and b > sect]
                    whom = ", ".join(
                        f"ITOC[{v.index}] 0x{v.type:02x} "
                        f"{SECT_NAMES.get(v.type, '?')} @0x{img.sec_abs(v):x}"
                        for v in victims)
                    violations.append(BurnOrderViolation(
                        e, victims, sect,
                        f"ITOC[{e.index}] 0x{e.type:02x} "
                        f"{SECT_NAMES.get(e.type, '?')} @0x{img.sec_abs(e):x}"
                        f" re-enters sector 0x{sect:x}: sector erase (no RMW)"
                        f" destroys already written data"
                        + (f" of {whom}" if whom else "")))
                visited.add(sect)
            s = min(end, sect + sector_size)
        if e is not None:
            written.append((start, end, e))
    return violations


def burn_damage_predict(img: Image, sector_size: int = DEFAULT_SECTOR) -> list:
    # Побайтовая симуляция write-потока поверх FF-флеша: сектор при первом
    # входе всё равно стирается, поэтому pre-state не влияет на итоговое
    # состояние секций (модель burn_sim.py, сверена с live: 0x408a/0xbd51).
    flash = bytearray(b"\xff" * len(img.buf))
    blank = b"\xff" * sector_size
    curr = None
    for start, end, e in _burn_writes(img):
        data = img.buf[start:end]
        s, p, n = start, 0, len(data)
        while p < n:
            sect = s & ~(sector_size - 1)
            chunk = min(n - p, sect + sector_size - s)
            if sect != curr:
                curr = sect
                hi = min(sect + sector_size, len(flash))
                if hi > sect:
                    flash[sect:hi] = blank[:hi - sect]
            piece = data[p:p + chunk]
            seg = flash[s:s + chunk]
            if seg.count(0xFF) != chunk:
                piece = bytes(a & b for a, b in zip(seg, piece))
            flash[s:s + chunk] = piece
            s += chunk
            p += chunk
    out = []
    for e in img.entries("ITOC"):
        if not e.size:
            continue
        a = img.sec_abs(e)
        orig = img.buf[a:a + e.size]
        res = bytes(flash[a:a + e.size])
        if res == orig:
            continue
        erased = []  # максимальные прогоны 0xFF результата — как на флеше
        i = 0
        while i < len(res):
            if res[i] == 0xFF:
                j = i
                while j < len(res) and res[j] == 0xFF:
                    j += 1
                erased.append((i, j - i))
                i = j
            else:
                i += 1
        out.append(DamagePrediction(e, res, erased, crc16_mlx(res)))
    return out


def _burn_order_refusal(out: bytes, base: int = 0, fmt: str = None) -> bool:
    # Предзаписный гейт inject/repack (обе ветки): ФИНАЛЬНЫЙ in-memory образ
    # прогоняется чекером ДО записи файла — нарушение = отказ rc 2, выходной
    # файл не пишется (спека repack-burn-safety §2.2). Безусловен: не
    # обходится --repack-force (§2.5); research-обход --unsafe-relocation —
    # вне этого гейта (Task 4). True = отказ.
    violations = burn_order_check(Image(out, "<out>", base=base, fmt=fmt))
    for v in violations:
        print(f"error: burn-order violation, output not written: {v.explanation}",
              file=sys.stderr)
    return bool(violations)


# Автознак 0xA0 после релокации — слой CLI-команд (спека repack-burn-safety
# §2.4): core-функции sign-нейтральны; cmd_inject и cmd_repack (legacy- и
# --base/--swap-ветки, включая _reflow-fallback) прогоняют финальный образ
# через гварды cmd_sign: fresh/stale -> пересчёт слота @+0x20 (выход всегда
# MCC-ready); rsa/v2/missing/empty -> отказ rc 2 без записи файла
# (--no-autosign — research-обход с предупреждением). Триггер — любая
# релокация (перенос/переупорядочение ITOC-записей); in-place правка без
# переноса не триггерит (спека: «после любой релокации»).
def _relocated_after(before: Image, out: bytes) -> bool:
    after = Image(out, before.path, base=before.base, fmt=before.fmt)

    def layout(im):
        return [(e.type, im.sec_abs(e)) for e in im.entries("ITOC")]

    return layout(before) != layout(after)


def autosign_after_relocation(out: bytes, base: int = 0, fmt: str = None) -> tuple:
    """(status, buf, digest): fresh/stale — слот 0xA0 @+0x20 финального
    образа пересчитан по семантике cmd_sign (FS3 crcf=0 — sec/entry CRC
    0xA0-записи обновлены); rsa/v2/missing/empty — buf None, отказ."""
    img = Image(out, "<out>", base=base, fmt=fmt)
    status, _stored, _calc = sig_status(img)
    if status not in ("fresh", "stale"):
        return status, None, None
    e = img.find_entry("ITOC", 0xA0)
    a = img.sec_abs(e)
    buf = bytearray(out)
    digest = sha256_digest(img)
    buf[a + SIG_SLOT_OFF:a + SIG_SLOT_OFF + 32] = digest
    if img.fmt == "fs3" and e.crcf == 0:
        sec_crc = crc16_mlx(bytes(buf[a:a + e.size]))
        ent_off = img.itoc_off + 32 + e.index * 32
        ent = bytearray(buf[ent_off:ent_off + 32])
        set_bits(ent, 208, 16, sec_crc)
        set_bits(ent, 240, 16, crc16_mlx(bytes(ent[:28])))
        buf[ent_off:ent_off + 32] = ent
    return status, bytes(buf), digest


def _autosign_gate(before: Image, out: bytes, no_autosign: bool) -> bytes | None:
    """Общий хвост cmd_inject/cmd_repack ПОСЛЕ инвариант-гейта: релокация
    была — автознак (или --no-autosign с предупреждением; 0xA0 нетронут).
    Отказ — None (rc 2, файл не пишется)."""
    if not _relocated_after(before, out):
        return out
    if no_autosign:
        print("warning: --no-autosign: 0xA0 digest NOT recomputed after "
              "relocation - image is not MCC-ready", file=sys.stderr)
        return out
    status, signed, digest = autosign_after_relocation(out, before.base,
                                                       before.fmt)
    if signed is None:
        print(f"error: 0xA0 {status}: autosign not possible - output not "
              "written (image would not be MCC-ready); "
              "use --no-autosign for research", file=sys.stderr)
        return None
    print(f"autosign: 0xA0 {status} -> digest {digest.hex()}")
    return signed


def cmd_extract(img: Image, args) -> int:
    data = extract_section(img, args.section)
    if args.section == 0x30 and not args.raw and data[:2] == b"\x78\xda":
        data = zlib.decompress(data)
    if args.output is None:
        sys.stdout.buffer.write(data)
        return 0
    Path(args.output).write_bytes(data)
    print(f"{args.output}: {len(data)} bytes")
    return 0


@dataclass
class DiffResult:
    toc: str
    index: int
    type: int
    size_a: int
    size_b: int
    diff_bytes: int
    ranges: list
    annotations: list
    only: str


ANNOTATIONS = [
    (0x08, 0x23, "HW_BOOT_CFG+0x23 max PCIe speed (0x07=Gen3, 0x0f=Gen4)"),
    (0x09, 0x245, "HW_MAIN_CFG+0x245 port0 PCIe gen (16.35 layout)"),
    (0x09, 0x285, "HW_MAIN_CFG+0x285 port1 PCIe gen (16.35 layout)"),
    (0x09, 0x404, "HW_MAIN_CFG+0x404+ speed tables (16.35 layout)"),
    (0x10, 0x1C, "IMAGE_INFO+0x1c pci_device_id (BE u16)"),
    (0x10, 0x24, "IMAGE_INFO+0x24 psid[17]"),
    (0x10, 0x1C0, "IMAGE_INFO+0x1c0 prod_ver[17]"),
    (0x10, 0x1D0, "IMAGE_INFO+0x1d0 description[257]"),
    (0x10, 0x340, "IMAGE_INFO+0x340 name[65]"),
    (0x10, 0x380, "IMAGE_INFO+0x380 prs_name[129]"),
    (0x11, 0x2D, "FW_BOOT_CFG+0x2d device_id low byte |0x1000 (16.35 layout)"),
    (0x11, 0x3D, "FW_BOOT_CFG+0x3d subsystem_id low byte"),
    (0x11, 0x93, "FW_BOOT_CFG+0x93 PCIe cap_index (0x45=Gen3, 0x47=Gen4)"),
    (0x12, 0x2AB, "FW_MAIN_CFG+0x2ab lcl[0] speed mask (56G bit)"),
    (0x12, 0x2B7, "FW_MAIN_CFG+0x2b7 lcl[1] speed mask (56G bit)"),
]


def diff_sections(a: Image, b: Image, max_ranges: int = 24):
    ea = [(e.toc, e.index) for e in a.itoc + a.dtoc if e.type != 0xFF]
    eb = [(e.toc, e.index) for e in b.itoc + b.dtoc if e.type != 0xFF]
    ka, kb = set(ea), set(eb)
    order = ea + [k for k in eb if k not in ka]
    out = []
    for key in order:
        toc, index = key
        ra = DiffResult(toc, index, 0, 0, 0, 0, [], [], "")
        ea_ = a.entry_at(toc, index) if key in ka else None
        eb_ = b.entry_at(toc, index) if key in kb else None
        if ea_ is None or eb_ is None:
            e = ea_ or eb_
            ra.type = e.type
            ra.size_a = e.size if ea_ else 0
            ra.size_b = e.size if eb_ else 0
            ra.only = "A" if ea_ else "B"
            out.append(ra)
            continue
        da = a.section_data(ea_)
        db = b.section_data(eb_)
        n = min(len(da), len(db))
        diff = [i for i in range(n) if da[i] != db[i]]
        ranges = []
        if diff:
            s = p = diff[0]
            for x in diff[1:]:
                if x == p + 1:
                    p = x
                else:
                    ranges.append((s, p - s + 1))
                    s = p = x
            ranges.append((s, p - s + 1))
        ann = [(off, text) for (st, off, text) in ANNOTATIONS
               if st == ea_.type and off < n and da[off] != db[off]]
        out.append(DiffResult(toc, index, ea_.type, len(da), len(db),
                              len(diff), ranges[:max_ranges], ann, ""))
    return out


def cmd_diff(a: Image, b: Image, max_ranges: int = 24) -> int:
    if a.fmt != b.fmt:
        print(f"error: diff: format mismatch ({a.fmt} vs {b.fmt})", file=sys.stderr)
        return 2
    print(f"== diff: A={a.path}  B={b.path}")
    for r in diff_sections(a, b, max_ranges):
        name = SECT_NAMES.get(r.type, "?")
        tag = f"[{r.toc}[{r.index}]] 0x{r.type:02x} {name:<16}"
        if r.only:
            print(f"  {tag} only in {r.only}")
            continue
        if r.size_a != r.size_b:
            print(f"  {tag} SIZE {r.size_a:#x} vs {r.size_b:#x}; "
                  f"{r.diff_bytes} diff bytes in overlap")
        elif r.diff_bytes == 0:
            print(f"  {tag} identical ({r.size_a:#x})")
        else:
            print(f"  {tag} {r.diff_bytes} diff bytes, {len(r.ranges)} ranges")
        for off, ln in r.ranges:
            marks = [text for (o, text) in r.annotations if off <= o < off + ln]
            m = f"  <- {'; '.join(marks)}" if marks else ""
            print(f"      @{off:#06x}..{off + ln - 1:#06x} ({ln} B){m}")
    return 0


II_PSID = (0x24, 17)
II_PROD_VER = (0x1C0, 17)
II_DESC = (0x1D0, 257)
II_NAME = (0x340, 64)  # not 65: byte 0x380 starts prs_name (II_PRS)
II_PRS = (0x380, 128)


def image_info_fields(data: bytes) -> dict:
    def s(off, ln):
        return data[off:off + ln].split(b"\x00")[0].decode("latin1")
    return {"psid": s(*II_PSID), "prod_ver": s(*II_PROD_VER),
            "description": s(*II_DESC), "name": s(*II_NAME), "prs_name": s(*II_PRS)}


def set_image_info_fields(data: bytes, psid=None, name=None, description=None) -> bytes:
    out = bytearray(data)
    for off, ln, val in ((II_PSID[0], II_PSID[1], psid),
                         (II_NAME[0], II_NAME[1], name),
                         (II_DESC[0], II_DESC[1], description)):
        if val is None:
            continue
        b = val.encode("latin1")
        if len(b) > ln - 1:
            raise ValueError(f"field too long: {len(b)} bytes > {ln - 1}")
        out[off:off + ln] = b.ljust(ln, b"\x00")
    return bytes(out)


MFG_PSID = (0x00, 16)


def _rewrite_section(img: Image, out: bytearray, e, new_data: bytes) -> None:
    a = img.sec_abs(e)
    out[a:a + e.size] = new_data
    ent = bytearray(e.raw)
    set_bits(ent, 208, 16, crc16_mlx(new_data) if e.crcf == 0 else 0x0000)
    set_bits(ent, 240, 16, crc16_mlx(bytes(ent[:28])))
    off = img.itoc_off + 32 + e.index * 32
    out[off:off + 32] = ent


def set_psid(img: Image, psid=None, name=None, description=None) -> bytes:
    out = bytearray(img.buf)
    e = img.find_entry("ITOC", 0x10)
    _rewrite_section(img, out, e,
                     set_image_info_fields(img.section_data(e), psid, name, description))
    if img.fmt == "fs3" and psid is not None:
        b = psid.encode("latin1")
        if len(b) > MFG_PSID[1] - 1:
            raise ValueError(f"psid too long for MFG_INFO: {len(b)} > {MFG_PSID[1] - 1}")
        em = img.find_entry("ITOC", 0xE0)
        mfg = bytearray(img.section_data(em))
        mfg[MFG_PSID[0]:MFG_PSID[1]] = b.ljust(MFG_PSID[1], b"\x00")
        _rewrite_section(img, out, em, bytes(mfg))
    return bytes(out)


def cmd_psid(img: Image, args) -> int:
    if args.psid is None and args.name is None and args.description is None:
        print("at least one of --psid/--name/--description is required", file=sys.stderr)
        return 2
    old = image_info_fields(img.section_data(img.find_entry("ITOC", 0x10)))
    out = set_psid(img, args.psid, args.name, args.description)
    vimg = Image(out, img.path, base=img.base, fmt=img.fmt)
    errs = verify_image(vimg)
    if errs:
        for e in errs:
            print(f"self-verify FAIL: {e}", file=sys.stderr)
        return 1
    Path(args.output).write_bytes(out)
    new = image_info_fields(vimg.section_data(vimg.find_entry("ITOC", 0x10)))
    for k in ("psid", "name", "description"):
        if old[k] != new[k]:
            print(f"{k}: {old[k]!r} -> {new[k]!r}")
    if img.fmt == "fs3":
        em = vimg.find_entry("ITOC", 0xE0)
        mfg_psid = vimg.section_data(em)[MFG_PSID[0]:MFG_PSID[1]].split(b"\x00")[0].decode("latin1")
        print(f"0xE0 MFG_INFO psid -> {mfg_psid!r}")
    print(f"{args.output}: 0x10 sec_crc/entry_crc recomputed")
    return 0


def _inject_ini_legacy(img: Image, e, data: bytes, out: bytearray) -> int:
    """До-цикловый align4-tail аллокатор grow-ветки inject — режим
    --unsafe-relocation (спека repack-burn-safety §2.5; git 9d2f418,
    mlxfwutil.py:761-779): данные на align4(max(end)) по current-семантике,
    запись ITOC ОСТАЁТСЯ на своём месте, старое место зачищается 0xFF.
    Возвращает new_addr в слот-координатах записи (общий хвост inject_ini
    допишет строку по индексу). Выход burn-опасен (mid-list) — гарантия
    воспроизводимости исторических артефактов, не для продакшн-прошивок."""
    if img.fmt == "fs3":
        start = max(img.sec_abs(x) + x.size for x in img.entries("ITOC") if x.rel)
        bound = min((img.sec_abs(x) for x in img.entries("ITOC") if not x.rel),
                    default=len(img.buf))
    else:
        start = max(img.sec_abs(x) + x.size for x in img.entries("ITOC"))
        bound = min([img.sec_abs(x) for x in img.entries("DTOC")]
                    + [img.base + SLOT_SIZE])
    new_abs = (start + 3) & ~3
    if new_abs + len(data) > bound:
        raise ValueError(f"0x30: new size {len(data):#x} does not fit in tail gap "
                         f"0x{new_abs:x}..0x{bound:x}")
    if any(b != 0xFF for b in out[new_abs:new_abs + len(data)]):
        raise ValueError(f"0x30: tail gap at 0x{new_abs:x} not erased (0xFF)")
    old_abs = img.sec_abs(e)
    out[old_abs:old_abs + e.size] = b"\xFF" * e.size
    out[new_abs:new_abs + len(data)] = data
    if img.fmt == "fs3":
        return new_abs - (img.base if e.rel else 0)
    return new_abs - img.base


def inject_ini(img: Image, ini_text: str, force: bool = False,
               unsafe_relocation: bool = False) -> bytes:
    data = zlib.compress(ini_text.encode("latin1"), 9)
    data += b"\x00" * ((4 - len(data) % 4) % 4)
    e = img.find_entry("ITOC", 0x30)
    out = bytearray(img.buf)
    if len(data) <= e.size:
        new_abs = img.sec_abs(e)
        out[new_abs:new_abs + e.size] = b"\xFF" * e.size
        out[new_abs:new_abs + len(data)] = data
        new_addr = e.addr
    else:
        if not force:
            raise ValueError(f"0x30: new size {len(data):#x} > section size {e.size:#x}; "
                             "relocation requires --repack-force")
        if unsafe_relocation:
            new_addr = _inject_ini_legacy(img, e, data, out)
        else:
            plan = plan_relocations(img, [(e, data, None)])
            apply_relocations(img, out, plan)
            _hashes_update(img, out, {0x30: data})
            return bytes(out)
    ent = bytearray(e.raw)
    set_bits(ent, 8, 22, len(data) // 4)
    set_bits(ent, 161, 29, new_addr // 4)
    set_bits(ent, 208, 16, crc16_mlx(data) if e.crcf == 0 else 0x0000)
    set_bits(ent, 240, 16, crc16_mlx(bytes(ent[:28])))
    off = img.itoc_off + 32 + e.index * 32
    out[off:off + 32] = ent
    _hashes_update(img, out, {0x30: data})
    return bytes(out)


# mstflint читает ITOC-секции файла через 8MiB-half-конвертер (cont2phys,
# flint_io.h:211, log2=23): cont [0x800000, 0x1000000) мапится за 16MiB
# (FImage::read, flint_io.cpp:245, отказывает) — все ITOC-секции обязаны
# кончаться ниже этой границы. Граница слот-относительная: base!=0 / slot B —
# валидные раскладки (гвард считает end - base, не сырой офсет buf).
HALF = 0x800000


# Безопасная релокация — единый планировщик (спека repack-burn-safety §2.3).
# tail-placement: релоцируемая запись уходит в КОНЕЦ REL-БЛОКА массива
# ITOC-записей (FS3 — до non-relative/dev-data строк, FS4 — в конец таблицы:
# dev-data там вне ITOC-компонента), данные ложатся последовательно после
# max(end) уже спланированного; старт 64K-выровнен — без выравнивания новая
# секция разделит сектор с хвостом предыдущей и её запись сотрёт этот хвост
# (erase без RMW, инвариант burn_order_check, спека §1.1-§1.2). FS3: max(end)
# только по relative-записям, граница — non-relative (dev-data, прецедент
# выше в inject_ini). Порядок «rel-блок до dev-строк» обязателен для FS3:
# MCC-компонент несёт dev-строки, замаскированные в 0xFF (maskDevToc,
# fs3_ops.cpp:3659), а строка type==0xFF — FS3_END-терминатор ITOC-обхода
# (fs3_ops.cpp:616): rel-строка после dev-блока невидима FW-side walk, её
# конец не попадает в digest-диапазон VERIFY_COMPONENT -> MCC 0x2 «The
# Digest in the signature is wrong» (live 2026-11-12, img-G4a; все 24
# вендорских FS3 образов корпуса держат порядок rel-блок -> dev-блок -> END).
# До-цикловая семантика grow-ветки inject (align4-хвост после max(end),
# запись остаётся на своём месте ITOC) сохранена в git-истории
# (коммит 01d282e, mlxfwutil.py inject_ini) — эталон для legacy-режима
# --unsafe-relocation.
@dataclass
class RelocMove:
    entry: TocEntry
    data: bytes            # новые данные либо собственные данные записи
    src_raw: bytes | None  # 32B эталон строки ITOC (None — своя строка)
    new_abs: int           # абсолютный офсет данных в buf
    old_abs: int
    old_size: int


class RelocNoRoom(ValueError):
    """Хвост не влезает (нехватка места до bound/HALF) — единственный повод
    для swap_repack уйти в _reflow fallback (спека §2.3: «при нехватки
    хвоста»). Интегрити-отказы (нестёртый gap и пр.) остаются голым
    ValueError и НЕ глотаются fallback'ом."""


@dataclass
class RelocPlan:
    order: list            # итоговый порядок ITOC (без END): FS3 — релоцируемые
                           # в конце rel-блока (до dev-строк), FS4 — в конце
    moves: list            # RelocMove в порядке хвостов


def _itoc_reloc_order(img: Image, stay: list, moved: list) -> list:
    """Итоговый порядок ITOC-строк после релокации. FS3: moved вставляются
    перед первой non-relative (dev-data) строкой — в MCC-компоненте dev-строки
    замаскированы в 0xFF (= FS3_END), FW-side TOC-walk обрывается на них, и
    rel-строка после dev-блока выпадает из digest-диапазона VERIFY_COMPONENT
    (MCC 0x2, live 2026-11-12). FS4: в конец таблицы (dev-data вне
    ITOC-компонента — замаскированных строк нет, «конец» == «конец
    rel-блока»)."""
    if img.fmt != "fs3":
        return stay + moved
    cut = next((i for i, e in enumerate(stay) if not e.rel), len(stay))
    return stay[:cut] + moved + stay[cut:]


def _reloc_bounds(img: Image) -> tuple:
    # (max(end) уложенного, граница хвостового gap) в абсолютных офсетах buf
    ents = img.entries("ITOC")
    if img.fmt == "fs3":
        start = max((img.sec_abs(e) + e.size for e in ents if e.rel),
                    default=img.base)
        bound = min((img.sec_abs(e) for e in ents if not e.rel),
                    default=len(img.buf))
    else:
        start = max((img.sec_abs(e) + e.size for e in ents), default=img.base)
        bound = min([img.sec_abs(e) for e in img.entries("DTOC")]
                    + [img.base + SLOT_SIZE])
    return start, bound


def plan_relocations(img: Image, moves: list) -> RelocPlan:
    """Строит все новые адреса и итоговый порядок ITOC до какой-либо записи.
    moves = [(entry, new_data | None, src_raw | None)]; new_data None —
    переносятся собственные данные записи. Отказы: RelocNoRoom (подкласс
    ValueError — хвост не влезает до HALF/bound, повод для _reflow fallback
    у swap_repack) и голый ValueError для интегрити-отказов (нестёртый gap,
    не-DW-выравненные данные и пр.)."""
    resolved, seen = [], set()
    for entry, new_data, src_raw in moves:
        if not any(e is entry for e in img.itoc):
            raise ValueError(f"0x{entry.type:02x}: entry not in ITOC of {img.path}")
        if id(entry) in seen:
            raise ValueError(f"0x{entry.type:02x}: duplicated relocation move")
        seen.add(id(entry))
        data = new_data if new_data is not None else img.section_data(entry)
        if len(data) % 4:
            raise ValueError(f"0x{entry.type:02x}: size {len(data)} not DW-aligned")
        resolved.append((entry, data, src_raw))
    end_entry = img.itoc[-1] if img.itoc and img.itoc[-1].type == 0xFF else None
    if end_entry is None:
        raise ValueError(f"missing END entry in ITOC of {img.path}")
    cur, bound = _reloc_bounds(img)
    out_moves = []
    for entry, data, src_raw in resolved:
        new_abs = (cur + 0xFFFF) & ~0xFFFF
        end = new_abs + len(data)
        slot_base = img.base if (img.fmt == "fs4" or entry.rel) else 0
        if end - slot_base >= HALF:
            raise RelocNoRoom(f"0x{entry.type:02x}: relocation end "
                              f"0x{end - slot_base:x} crosses the 8MiB half "
                              f"boundary 0x{HALF:x} (cont2phys)")
        if end > bound:
            raise RelocNoRoom(f"0x{entry.type:02x}: relocation end 0x{end:x} "
                              f"exceeds tail bound 0x{bound:x}")
        if any(b != 0xFF for b in img.buf[new_abs:end]):
            raise ValueError(f"0x{entry.type:02x}: tail gap at 0x{new_abs:x} "
                             "not erased (0xFF)")
        out_moves.append(RelocMove(entry, data, src_raw, new_abs,
                                   img.sec_abs(entry), entry.size))
        cur = end
    order = _itoc_reloc_order(
        img, [e for e in img.itoc if e.type != 0xFF and id(e) not in seen],
        [m.entry for m in out_moves])
    return RelocPlan(order, out_moves)


def apply_relocations(img: Image, out: bytearray, plan: RelocPlan) -> None:
    """Перенос данных по плану, зачистка освобождённых мест 0xFF, перезапись
    ITOC (итоговый порядок + addr/size/CRC; нерелоцируемые строки — как есть).
    In-place правки данных/строк вызывающий делает после этого вызова."""
    moves_by_id = {id(m.entry): m for m in plan.moves}
    rows = {}
    for e in img.itoc:
        off = img.itoc_off + 32 + e.index * 32
        rows[id(e)] = bytes(img.buf[off:off + 32])
    for m in plan.moves:
        out[m.new_abs:m.new_abs + len(m.data)] = m.data
    for m in plan.moves:
        out[m.old_abs:m.old_abs + m.old_size] = b"\xFF" * m.old_size
    end_entry = img.itoc[-1]
    for i, e in enumerate(plan.order):
        m = moves_by_id.get(id(e))
        if m is None:
            row = rows[id(e)]
        else:
            raw = bytearray(m.src_raw if m.src_raw is not None else rows[id(e)])
            crcf = bits(raw, 205, 3) if img.fmt == "fs4" else bits(raw, 207, 1)
            slot_base = img.base if (img.fmt == "fs4" or e.rel) else 0
            set_bits(raw, 8, 22, len(m.data) // 4)
            set_bits(raw, 161, 29, (m.new_abs - slot_base) // 4)
            set_bits(raw, 208, 16, crc16_mlx(m.data) if crcf == 0 else 0x0000)
            set_bits(raw, 240, 16, crc16_mlx(bytes(raw[:28])))
            row = bytes(raw)
        off = img.itoc_off + 32 + i * 32
        out[off:off + 32] = row
    off = img.itoc_off + 32 + len(plan.order) * 32
    out[off:off + 32] = end_entry.raw


def cmd_inject(args) -> int:
    img = _image(args.image)
    try:
        ini_text = Path(args.ini).read_text(encoding="latin1")
        out = inject_ini(img, ini_text, force=args.repack_force,
                         unsafe_relocation=args.unsafe_relocation)
    except ValueError as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 2
    errs = verify_image(Image(out, img.path, base=img.base, fmt=img.fmt))
    if errs:
        for e in errs:
            print(f"self-verify FAIL: {e}", file=sys.stderr)
        return 1
    if args.unsafe_relocation:
        # research-режим (спека §2.5): обход ПРЕДЗАПИСНОГО инвариант-гейта;
        # self-verify остаётся, verify на таком выходе всё равно FAIL
        print("warning: --unsafe-relocation: legacy pre-cycle relocation "
              "(ITOC entry stays mid-list, align4 tail) - output WILL be "
              "damaged by burn (burn-order gate bypassed); research use only",
              file=sys.stderr)
    elif _burn_order_refusal(out, base=img.base, fmt=img.fmt):
        return 2
    out = _autosign_gate(img, out, args.no_autosign)
    if out is None:
        return 2
    Path(args.output).write_bytes(out)
    print(f"{args.output}: 0x30 re-injected, md5 {hashlib.md5(out).hexdigest()}")
    return 0


def parse_set_spec(spec: str) -> tuple:
    sect, _, rest = spec.partition("+")
    off, _, hexdata = rest.partition("=")
    if not sect or not off or not hexdata:
        raise ValueError(f"bad --set spec {spec!r} (want 0xNN+0xOFF=HEXBYTES)")
    try:
        t = int(sect, 0)
        o = int(off, 0)
        data = bytes.fromhex(hexdata)
    except ValueError:
        raise ValueError(f"bad --set spec {spec!r} (want 0xNN+0xOFF=HEXBYTES)")
    if not (0 < t < 0x100) or o < 0:
        raise ValueError(f"bad --set spec {spec!r} (want 0xNN+0xOFF=HEXBYTES)")
    return t, o, data


def parse_merge_spec(spec: str) -> list:
    out = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            raise ValueError(f"bad --spec entry {part!r} (want 0xNN+0xOFF+LEN)")
        sect, _, rest = part.partition("+")
        off, _, length = rest.partition("+")
        if not sect or not off or not length:
            raise ValueError(f"bad --spec entry {part!r} (want 0xNN+0xOFF+LEN)")
        try:
            t, o, ln = int(sect, 0), int(off, 0), int(length, 0)
        except ValueError:
            raise ValueError(f"bad --spec entry {part!r} (want 0xNN+0xOFF+LEN)")
        if not (0 < t < 0x100) or o < 0 or ln <= 0:
            raise ValueError(f"bad --spec entry {part!r} (want 0xNN+0xOFF+LEN)")
        out.append((t, o, ln))
    return out


def _hashes_update(img: Image, out: bytearray, changed: dict) -> None:
    if not changed or img.fmt != "fs4":
        return
    ht = HashesTable.from_image(img)
    if ht is None:
        return
    itoc_types = {e.type for e in img.entries("ITOC")}
    ht.update_into(out, changed, itoc_types)


def patch_sections(img: Image, edits: list) -> bytes:
    out = bytearray(img.buf)
    by_sect = {}
    for t, o, data in edits:
        by_sect.setdefault(t, []).append((o, data))
    changed = {}
    for t, ed in by_sect.items():
        e = img.find_entry("ITOC", t)
        sec = bytearray(img.section_data(e))
        for off, data in ed:
            if off + len(data) > e.size:
                raise ValueError(f"0x{t:02x}: edit 0x{off:x}+{len(data)}B exceeds section size {e.size:#x}")
            sec[off:off + len(data)] = data
        new = bytes(sec)
        if new == img.section_data(e):
            continue
        changed[t] = new
        a = img.sec_abs(e)
        out[a:a + e.size] = new
        ent = bytearray(e.raw)
        set_bits(ent, 208, 16, crc16_mlx(new) if e.crcf == 0 else 0x0000)
        set_bits(ent, 240, 16, crc16_mlx(bytes(ent[:28])))
        ent_off = img.itoc_off + 32 + e.index * 32
        out[ent_off:ent_off + 32] = ent
    _hashes_update(img, out, changed)
    return bytes(out)


def cmd_patch(img: Image, args) -> int:
    edits = [parse_set_spec(s) for s in args.sets]
    out = patch_sections(img, edits)
    errs = verify_image(Image(out, img.path, base=img.base, fmt=img.fmt))
    if errs:
        for e in errs:
            print(f"self-verify FAIL: {e}", file=sys.stderr)
        return 1
    Path(args.output).write_bytes(out)
    print(f"{args.output}: {len(edits)} edit(s), md5 {hashlib.md5(out).hexdigest()}")
    return 0


def merge_fields(base: Image, src: Image, fields: list) -> bytes:
    edits = []
    if base.fmt != src.fmt:
        raise ValueError(f"merge: format mismatch ({base.fmt} vs {src.fmt})")
    for t, o, ln in fields:
        if o < 0:
            raise ValueError(f"0x{t:02x}: offset {o} is negative")
        try:
            be = base.find_entry("ITOC", t)
        except KeyError as ex:
            raise ValueError(f"base: {ex}") from ex
        try:
            se = src.find_entry("ITOC", t)
        except KeyError as ex:
            raise ValueError(f"src: {ex}") from ex
        if base.fmt == "fs4":
            for name, e in (("base", be), ("src", se)):
                if e.addr + e.size > SLOT_SIZE:
                    raise ValueError(
                        f"{name} 0x{t:02x}: section 0x{e.addr:x}+{e.size:#x} crosses 8MiB half")
        if o + ln > se.size:
            raise ValueError(f"src 0x{t:02x}: range 0x{o:x}+{ln}B exceeds section size {se.size:#x}")
        if o + ln > be.size:
            raise ValueError(f"base 0x{t:02x}: range 0x{o:x}+{ln}B exceeds section size {be.size:#x}")
        edits.append((t, o, src.section_data(se)[o:o + ln]))
    return patch_sections(base, edits)


def cmd_merge(args) -> int:
    fields = parse_merge_spec(args.spec)
    base = _image(args.base)
    try:
        out = merge_fields(base, _image(args.src), fields)
    except ValueError as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 2
    errs = verify_image(Image(out, base.path, base=base.base, fmt=base.fmt))
    if errs:
        for e in errs:
            print(f"self-verify FAIL: {e}", file=sys.stderr)
        return 1
    Path(args.output).write_bytes(out)
    print(f"{args.output}: {len(fields)} field range(s) merged, md5 {hashlib.md5(out).hexdigest()}")
    return 0


SLOT_SIZE = 0x800000
SLOT_MTCF_OFF = 0x790000
SLOT_DTOC_OFF = 0x7FF000


@dataclass
class SlotState:
    name: str
    base: int
    magic: str
    itoc_off: int
    entries: int
    psid: str
    prod_ver: str
    dtoc_off: int
    mtcf: bool


def _magic_state(sl: bytes) -> str:
    m = sl[:16]
    if m == FS4_MAGIC:
        return "intact"
    if m == CNTX_MAGIC:
        return "intact" if sl[0x24:0x25] == b"\x03" else "corrupt"
    if m[:4] == b"\x00" * 4 and m[4:] in (FS4_MAGIC[4:], CNTX_MAGIC[4:]):
        return "zeroed4"
    if m == b"\x00" * 16:
        return "zeroed16"
    if m == b"\xFF" * 16:
        return "erased"
    return "corrupt"


def _fs3_itoc_off(sl: bytes) -> int:
    for o in find_all(sl, ITOC_HDR):
        hdr = sl[o:o + 32]
        if len(hdr) == 32 and crc16_mlx(hdr[:28]) == bits(hdr, 240, 16):
            return o
    return -1


def _slot_magic_state(buf: bytes, off: int):
    m = buf[off:off + 16]
    if m == FS4_MAGIC:
        return "fs4"
    if m == CNTX_MAGIC:
        return "fs3" if buf[off + 0x24] == 3 else "fs2"
    return None


def detect_format(buf: bytes) -> tuple:
    if len(buf) == 2 * SLOT_SIZE:
        a = _slot_magic_state(buf, 0x0)
        b = _slot_magic_state(buf, SLOT_SIZE)
        for st, base in ((a, 0x0), (b, SLOT_SIZE)):
            if st in ("fs3", "fs4"):
                return st, base
        if "fs2" in (a, b):
            raise ValueError("FS2 is not supported (CNTX magic, version byte @0x24 = 0)")
        raise ValueError("no intact slot (FS4/FS3 magic not found at 0x0 or 0x800000)")
    if len(buf) < 0x40:
        raise ValueError(f"buffer too small ({len(buf)} bytes)")
    st = _slot_magic_state(buf, 0x0)
    if st == "fs2":
        raise ValueError("FS2 is not supported (CNTX magic, version byte @0x24 = 0)")
    if st in ("fs3", "fs4"):
        return st, 0x0
    raise ValueError("unknown image format (magic at 0x0)")


def detect_slot(buf: bytes) -> int:
    # Legacy FS4-обёртка: базовый offset intact-слота в 16MiB-дамп
    # (0x0 / 0x800000). Образ меньше 16MiB — всегда slot A (0x0).
    if len(buf) != 2 * SLOT_SIZE:
        return 0x0
    fmt, base = detect_format(buf)
    if fmt != "fs4":
        raise ValueError(f"no intact FS4 slot (format: {fmt})")
    return base


# mDevInfo (DTOC 0xE1, image_layout_device_info): сигнатура 16B,
# guid @0x28, mac @0x38, vsd_vendor_id @0x6C, версия DW @0x10,
# INSECTION CRC16 в последние 2 байта (по sec[:-4]).
DEVINFO_MAGIC = bytes.fromhex("6d446576496e666f2342cafabacafe00")
MDEVINFO_UID_OFF = 0x28
MDEVINFO_MAC_OFF = 0x38
MFG3_MAJOR_OFF = 0x1C
MFG3_OVR_OFF = 0x1F
MFG4_OVR_OFF = 0x1C
MFG4_MAJOR_OFF = 0x1F


def devinfo_sig_ok(sec: bytes) -> bool:
    return len(sec) >= 16 and sec[0:16] == DEVINFO_MAGIC


def find_valid_devinfo(img: "Image") -> list:
    return [e for e in img.entries("DTOC") if e.type == 0xE1 and devinfo_sig_ok(img.section_data(e))]


class MDevInfo:
    def __init__(self, sec: bytes):
        self.sec = bytearray(sec)

    @classmethod
    def parse(cls, sec: bytes) -> "MDevInfo":
        return cls(sec)

    @property
    def version(self) -> int:
        return int.from_bytes(self.sec[0x10:0x14], "big")

    @property
    def guid(self) -> int:
        return int.from_bytes(self.sec[MDEVINFO_UID_OFF:MDEVINFO_UID_OFF + 8], "big")

    @property
    def mac(self) -> int:
        return int.from_bytes(self.sec[MDEVINFO_MAC_OFF:MDEVINFO_MAC_OFF + 8], "big")

    @property
    def vsd_vendor_id(self) -> int:
        return int.from_bytes(self.sec[0x6C:0x6E], "big")

    def ensure_valid(self):
        self.sec[0:16] = DEVINFO_MAGIC
        if self.sec[0x10:0x14] == b"\x00" * 4:
            self.sec[0x10:0x14] = (0x00000200).to_bytes(4, "big")
        if self.sec[0x6C:0x6E] == b"\x00" * 2:
            self.sec[0x6C:0x6E] = (0x15B3).to_bytes(2, "big")

    def write_uids(self, guid: int, mac: int) -> bytes:
        if len(self.sec) < 0x40:
            raise ValueError(f"mDevInfo: section {len(self.sec):#x}B too small for uids (need >= 0x40)")
        self.sec[MDEVINFO_UID_OFF:MDEVINFO_UID_OFF + 8] = guid.to_bytes(8, "big")
        self.sec[MDEVINFO_MAC_OFF:MDEVINFO_MAC_OFF + 8] = mac.to_bytes(8, "big")
        self.sec[-2:] = crc16_mlx(bytes(self.sec[:-4])).to_bytes(2, "big")
        return bytes(self.sec)

    def crc_ok(self) -> bool:
        return int.from_bytes(self.sec[-2:], "big") == crc16_mlx(bytes(self.sec[:-4]))


def _flash_layout(size: int):
    if size == FLASH_SIZE:
        return SLOT_SIZE, (0x0, SLOT_SIZE)
    if size == FLASH_SIZE_32M:
        return SLOT_SIZE_32M, (0x0, SLOT_SIZE_32M)
    raise ValueError(f"raw dump must be 16MiB or 32MiB, got {size}")


def ab_state(raw: bytes) -> dict:
    slot_size, bases = _flash_layout(len(raw))
    out = {}
    for name, base in (("A", bases[0]), ("B", bases[1])):
        sl = raw[base:base + slot_size]
        if _slot_magic_state(sl, 0) == "fs3":
            itoc_off = _fs3_itoc_off(sl)
            nent, psid, prod_ver = 0, "", ""
            if itoc_off != -1:
                ents = parse_toc(sl, itoc_off, "ITOC", "fs3")
                nent = len([e for e in ents if e.type != 0xFF])
                for e in ents:
                    if e.type == 0x10:
                        f = image_info_fields(sl[e.addr:e.addr + e.size])
                        psid, prod_ver = f["psid"], f["prod_ver"]
                        break
            out[name] = SlotState(name, base, _magic_state(sl), itoc_off, nent,
                                  psid, prod_ver, -1, False)
        else:
            itoc_off = -1
            for cand in (0x4000, 0x5000):
                if sl[cand:cand + 16] == ITOC_HDR[:16]:
                    itoc_off = cand
                    break
            if itoc_off == -1:
                offs = find_all(sl, ITOC_HDR)
                itoc_off = offs[0] if offs else -1
            nent, psid, prod_ver = 0, "", ""
            if itoc_off != -1:
                ents = parse_toc(sl, itoc_off, name)
                nent = len([e for e in ents if e.type != 0xFF])
                for e in ents:
                    if e.type == 0x10:
                        f = image_info_fields(sl[e.addr:e.addr + e.size])
                        psid, prod_ver = f["psid"], f["prod_ver"]
                        break
            d = find_all(sl, DTOC_HDR)
            out[name] = SlotState(name, base, _magic_state(sl), itoc_off, nent,
                                  psid, prod_ver, d[0] if d else -1,
                                  sl[SLOT_MTCF_OFF:SLOT_MTCF_OFF + 4] == b"MTCF")
    return out


def ab_diff(a: bytes, b: bytes) -> dict:
    if len(a) != len(b):
        raise ValueError("dumps must be the same size")
    slot_size, bases = _flash_layout(len(a))
    out = {"total": 0}
    for name, base in (("A", bases[0]), ("B", bases[1])):
        d = [i for i in range(slot_size) if a[base + i] != b[base + i]]
        out[name] = {"bytes": len(d), "first": d[0] if d else None, "last": d[-1] if d else None}
        out["total"] += len(d)
    return out


def ab_devtail(raw: bytes, slots: dict) -> dict:
    intact = [n for n in ("A", "B") if slots[n].magic == "intact" and slots[n].itoc_off != -1]
    if not intact:
        return {}
    first = intact[0]
    sl = raw[slots[first].base:slots[first].base + SLOT_SIZE]
    dev = {e.type: e for e in parse_toc(sl, slots[first].itoc_off, "ITOC", "fs3")
           if e.dev and e.type != 0xFF}
    out = {"slot": first, "warn": None}
    if len(intact) == 2:
        other = "B" if first == "A" else "A"
        sl2 = raw[slots[other].base:slots[other].base + SLOT_SIZE]
        dev2 = {e.type: e for e in parse_toc(sl2, slots[other].itoc_off, "ITOC", "fs3")
                if e.dev and e.type != 0xFF}
        for t in sorted(dev):
            if t in dev2 and dev[t].addr != dev2[t].addr:
                out["warn"] = (f"dev section 0x{t:02x} address mismatch: "
                               f"slot {first} @0x{dev[t].addr:x} vs slot {other} @0x{dev2[t].addr:x}")
                break
    e0 = dev.get(0xE0)
    if e0 is not None:
        d0 = raw[e0.addr:e0.addr + e0.size]
        out["mfg"] = {"addr": e0.addr,
                      "psid": d0[0:16].split(b"\x00")[0].decode("ascii", "replace"),
                      "override_en": d0[0x1F] & 1,
                      "guid": int.from_bytes(d0[0x28:0x30], "big"),
                      "mac": int.from_bytes(d0[0x38:0x40], "big")}
    e1 = dev.get(0xE1)
    if e1 is not None:
        d1 = raw[e1.addr:e1.addr + e1.size]
        out["devinfo"] = {"addr": e1.addr,
                          "sig_ok": devinfo_sig_ok(d1),
                          "major": ((d1[0x11] & 1) << 8) | d1[0x12],
                          "guid": int.from_bytes(d1[0x28:0x30], "big"),
                          "mac": int.from_bytes(d1[0x38:0x40], "big")}
    return out


def ab_devtail_fs4(raw: bytes) -> dict:
    off = -1
    for cand in find_all(raw, DTOC_HDR):
        hdr = raw[cand:cand + 32]
        if len(hdr) == 32 and crc16_mlx(hdr[:28]) == bits(hdr, 240, 16):
            off = cand
            break
    if off == -1:
        return {}
    ents = [e for e in parse_toc(raw, off, "DTOC") if e.type != 0xFF]
    out = {"dtoc_off": off, "mfg": None, "devinfos": []}
    e0s = [e for e in ents if e.type == 0xE0]
    if e0s:
        e0 = e0s[0]
        d0 = raw[e0.addr:e0.addr + e0.size]
        if len(d0) >= 0x40:
            out["mfg"] = {"addr": e0.addr,
                          "psid": d0[0:16].split(b"\x00")[0].decode("ascii", "replace"),
                          "override_en": d0[MFG4_OVR_OFF] & 1,
                          "major": d0[MFG4_MAJOR_OFF],
                          "guid": int.from_bytes(d0[MDEVINFO_UID_OFF:MDEVINFO_UID_OFF + 8], "big"),
                          "mac": int.from_bytes(d0[MDEVINFO_MAC_OFF:MDEVINFO_MAC_OFF + 8], "big")}
    for e in sorted((e for e in ents if e.type == 0xE1), key=lambda e: e.addr):
        d1 = raw[e.addr:e.addr + e.size]
        if len(d1) < 0x40:
            out["devinfos"].append({"addr": e.addr, "sig_ok": False,
                                    "major": 0, "crc_ok": False,
                                    "guid": 0, "mac": 0})
            continue
        out["devinfos"].append({
            "addr": e.addr,
            "sig_ok": devinfo_sig_ok(d1),
            "major": ((d1[0x11] & 1) << 8) | d1[0x12],
            "crc_ok": int.from_bytes(d1[-2:], "big") == crc16_mlx(d1[:-4]),
            "guid": int.from_bytes(d1[MDEVINFO_UID_OFF:MDEVINFO_UID_OFF + 8], "big"),
            "mac": int.from_bytes(d1[MDEVINFO_MAC_OFF:MDEVINFO_MAC_OFF + 8], "big")})
    return out


LOG_STEP_OFF = 0x10B
LOG_STEP_32M = 24


def ab_truncated(raw: bytes, st: dict) -> str | None:
    if len(raw) != FLASH_SIZE:
        return None
    for n in ("A", "B"):
        s = st[n]
        if s.magic != "intact" or s.itoc_off == -1:
            continue
        sl = raw[s.base:s.base + SLOT_SIZE]
        for e in parse_toc(sl, s.itoc_off, n):
            if e.type == 0x10:
                if e.size >= LOG_STEP_OFF + 1 and sl[e.addr + LOG_STEP_OFF] == LOG_STEP_32M:
                    return ("warning: 16MiB dump of 32MiB flash (IMAGE_INFO log_step=24): "
                            "'slot B @0x800000' is the second half of slot A; "
                            "real slot B @0x1000000 not in dump")
                return None
    return None


def cmd_ab(args) -> int:
    raw = Path(args.raw_dump).read_bytes()
    st = ab_state(raw)
    _, bases = _flash_layout(len(raw))
    fs3 = any(_slot_magic_state(raw, b) == "fs3" for b in bases)
    print(f"== ab: {args.raw_dump}")
    if not fs3:
        t = ab_truncated(raw, st)
        if t:
            print(t, file=sys.stderr)
    for name in ("A", "B"):
        s = st[name]
        i = f"@0x{s.itoc_off:x}" if s.itoc_off != -1 else "none"
        if fs3:
            d, m = "n/a", "n/a"
        else:
            d = f"@0x{s.dtoc_off:x}" if s.dtoc_off != -1 else "none"
            m = "yes" if s.mtcf else "no"
        print(f"  slot {s.name} @0x{s.base:x}: magic={s.magic} ITOC={i} ({s.entries} ent) "
              f"psid={s.psid or '-'} ver={s.prod_ver or '-'} DTOC={d} MTCF={m}")
    if fs3:
        tail = ab_devtail(raw, st)
        if tail.get("warn"):
            print(f"warning: {tail['warn']}", file=sys.stderr)
        if tail:
            print(f"  dev tail (shared, entries from slot {tail['slot']}):")
            mfg = tail.get("mfg")
            if mfg:
                print(f"    0xE0 MFG_INFO @0x{mfg['addr']:x}: psid={mfg['psid']} "
                      f"override_en={mfg['override_en']} guid=0x{mfg['guid']:x} mac=0x{mfg['mac']:x}")
            di = tail.get("devinfo")
            if di:
                print(f"    0xE1 DEV_INFO @0x{di['addr']:x}: sig={'OK' if di['sig_ok'] else 'NG'} "
                      f"major={di['major']} guid=0x{di['guid']:x} mac=0x{di['mac']:x}")
    else:
        tail = ab_devtail_fs4(raw)
        if tail:
            print(f"  dev tail (shared, DTOC @0x{tail['dtoc_off']:x}):")
            mfg = tail.get("mfg")
            if mfg:
                print(f"    0xE0 MFG_INFO @0x{mfg['addr']:x}: psid={mfg['psid']} "
                      f"override_en={mfg['override_en']} major={mfg['major']} "
                      f"guid=0x{mfg['guid']:x} mac=0x{mfg['mac']:x}")
            for di in tail.get("devinfos", []):
                print(f"    0xE1 DEV_INFO @0x{di['addr']:x}: "
                      f"sig={'OK' if di['sig_ok'] else 'NG'} major={di['major']} "
                      f"crc={'OK' if di['crc_ok'] else 'NG'} "
                      f"guid=0x{di['guid']:x} mac=0x{di['mac']:x}")
    valid = [n for n in ("A", "B") if st[n].magic == "intact"]
    print(f"  verdict: valid slots = {','.join(valid) if valid else 'NONE'}")
    if args.diff:
        other = Path(args.diff).read_bytes()
        d = ab_diff(raw, other)
        print(f"== ab --diff: {args.raw_dump} vs {args.diff}")
        for name in ("A", "B"):
            x = d[name]
            if x["bytes"]:
                print(f"  slot {name}: {x['bytes']} diff bytes (first 0x{x['first']:x}, last 0x{x['last']:x})")
            else:
                print(f"  slot {name}: identical")
        print(f"  total: {d['total']} diff bytes")
    return 0


MERGE_TYPES = (0x08, 0x09, 0x11, 0x12)
FLASH_SIZE = 16 * 1024 * 1024
FLASH_SIZE_32M = 32 * 1024 * 1024
SLOT_SIZE_32M = 0x1000000


def merge_section(prio: bytes, other: bytes) -> bytes:
    if len(prio) == len(other) or len(prio) > len(other):
        return prio
    return prio + other[len(prio):]


def repack(new_path: str, old_path: str, prio: str) -> bytes:
    if prio not in ("new", "old"):
        raise ValueError("prio must be 'new' or 'old'")
    new = Image(Path(new_path).read_bytes(), str(new_path))
    old = Image(Path(old_path).read_bytes(), str(old_path))
    if new.fmt != old.fmt or new.fmt not in ("fs3", "fs4"):
        raise ValueError(f"repack requires two FS3 or two FS4 images "
                         f"(got {new.fmt}/{old.fmt})")
    out = bytearray(new.buf)

    def pick(toc: str, e):
        oe_list = old.entries(toc)
        if e.index >= len(oe_list) or oe_list[e.index].type != e.type:
            raise ValueError(f"{toc}[{e.index}]: 0x{e.type:02x} missing in --old image "
                             f"(or TOC order mismatch)")
        oe = oe_list[e.index]
        nd = new.section_data(e)
        od = old.section_data(oe)
        if e.type == 0x10:
            f = image_info_fields(od)
            return set_image_info_fields(nd, f["psid"], f["name"], f["description"]), e
        if e.type in MERGE_TYPES:
            if prio == "new":
                return merge_section(nd, od), (e if len(nd) >= len(od) else oe)
            return merge_section(od, nd), (oe if len(od) >= len(nd) else e)
        if e.type == 0x30 or 0xE0 <= e.type <= 0xEF:
            return od, oe
        return nd, e

    itoc_plan = [(e, *pick("ITOC", e)) for e in new.itoc if e.type != 0xFF]
    dtoc_plan = [(e, new.section_data(e), e) for e in new.dtoc if e.type != 0xFF]
    for e, data, src in itoc_plan + dtoc_plan:
        if len(data) % 4:
            raise ValueError(f"0x{e.type:02x}: size {len(data)} not DW-aligned")

    # выросшие секции — безопасная релокация (tail-placement, конец ITOC);
    # инвариант burn-order и HALF-гвард — по построению (спека §2.3/§2.6).
    # FS3: rel=0 (dev-data) не релоцируется — фиксированный адрес (§9.2)
    relocated, moved_ids = [], set()
    for e, data, src in itoc_plan:
        if data != new.section_data(e) and len(data) > e.size:
            if new.fmt == "fs3" and not e.rel:
                raise ValueError(f"0x{e.type:02x}: grown device-data section "
                                 "(rel=0) cannot relocate (FS3 fixed address)")
            moved_ids.add(id(e))
            relocated.append((e, data, src))
    if relocated:
        plan = plan_relocations(new, [(e, data, src.raw)
                                      for e, data, src in relocated])
        apply_relocations(new, out, plan)

    # нерелоцированные: на месте (обновлённые данные поверх старых);
    # FS3-минификация — хвост старого экстента зачищается (паритет swap)
    for e, data, src in itoc_plan:
        if id(e) in moved_ids or data == new.section_data(e):
            continue
        a = new.sec_abs(e)
        out[a:a + len(data)] = data
        if new.fmt == "fs3" and len(data) < e.size:
            out[a + len(data):a + e.size] = b"\xFF" * (e.size - len(data))

    def write_toc(toc_off, plan, end_raw):
        n = len(plan)
        for i, (e, data, src) in enumerate(plan):
            raw = bytearray(src.raw)
            set_bits(raw, 8, 22, len(data) // 4)
            set_bits(raw, 161, 29, e.addr // 4)
            set_bits(raw, 208, 16, crc16_mlx(data) if src.crcf == 0 else 0x0000)
            set_bits(raw, 240, 16, crc16_mlx(bytes(raw[:28])))
            out[toc_off + 32 + i * 32:toc_off + 64 + i * 32] = raw
        out[toc_off + 32 + n * 32:toc_off + 64 + n * 32] = end_raw

    itoc_end = new.itoc[-1] if new.itoc and new.itoc[-1].type == 0xFF else None
    dtoc_end = new.dtoc[-1] if new.fmt == "fs4" and new.dtoc and new.dtoc[-1].type == 0xFF else None
    if itoc_end is None or (new.fmt == "fs4" and dtoc_end is None):
        raise ValueError("missing END entry in source TOC")
    # строки нерелоцированных — по итоговому порядку (сдвиг индексов после
    # переноса релоцированных; FS3 — в конец rel-блока до dev-строк); их
    # строки уже записаны apply
    data_of = {id(e): (data, src) for e, data, src in itoc_plan}
    order = _itoc_reloc_order(
        new, [e for e in new.itoc if e.type != 0xFF and id(e) not in moved_ids],
        [e for e, _, _ in relocated])
    for i, e in enumerate(order):
        if id(e) in moved_ids:
            continue
        data, src = data_of[id(e)]
        raw = bytearray(src.raw)
        set_bits(raw, 8, 22, len(data) // 4)
        set_bits(raw, 161, 29, e.addr // 4)
        set_bits(raw, 208, 16, crc16_mlx(data) if src.crcf == 0 else 0x0000)
        set_bits(raw, 240, 16, crc16_mlx(bytes(raw[:28])))
        out[new.itoc_off + 32 + i * 32:new.itoc_off + 64 + i * 32] = raw
    out[new.itoc_off + 32 + len(order) * 32:new.itoc_off + 64 + len(order) * 32] = itoc_end.raw
    if new.fmt == "fs4":
        write_toc(new.dtoc_off, dtoc_plan, dtoc_end.raw)
    changed = {e.type: data for e, data, src in itoc_plan if data != new.section_data(e)}
    _hashes_update(new, out, changed)
    return bytes(out)


def cmd_repack(args) -> int:
    if args.base is not None:
        if args.new or args.old or args.prio:
            print("--base/--swap is incompatible with --new/--old/--prio", file=sys.stderr)
            return 2
        if not args.swap:
            print("--base requires at least one --swap", file=sys.stderr)
            return 2
        try:
            out = swap_repack(args.base, [parse_swap_spec(s) for s in args.swap])
        except ValueError as ex:
            print(f"error: {ex}", file=sys.stderr)
            return 2
    else:
        if not (args.new and args.old and args.prio):
            print("either --base + --swap or --new + --old + --prio is required", file=sys.stderr)
            return 2
        try:
            out = repack(args.new, args.old, args.prio)
        except ValueError as ex:
            print(f"error: {ex}", file=sys.stderr)
            return 2
    if _burn_order_refusal(out):
        return 2
    before = _image(args.base if args.base is not None else args.new)
    out = _autosign_gate(before, out, args.no_autosign)
    if out is None:
        return 2
    Path(args.output).write_bytes(out)
    print(f"{args.output}: {len(out)} bytes, md5 {hashlib.md5(out).hexdigest()}")
    return 0


def parse_swap_spec(spec: str) -> tuple:
    src, _, secs = spec.partition(":")
    if not src or not secs:
        raise ValueError(f"bad --swap spec {spec!r} (want SRC:0xNN[,0xNN...])")
    out = []
    for s in secs.split(","):
        t = int(s, 0)
        if not (0 < t < 0x100):
            raise ValueError(f"bad section {s!r} in --swap spec {spec!r}")
        out.append(t)
    return src, out


SWAP_FORBIDDEN = (0xA0, 0xA1, 0xA2, 0xA3, 0xA4)


def _reflow(base: Image, srcs: dict, plan_src: dict) -> bytes:
    """Плотная переупаковка всех ITOC-секций от минимального адреса секции:
    все секции кончаются ниже 0x800000 (HALF). Swapped-секции берут
    содержимое из src, остальные — base. ITOC-записи переписываются, DTOC
    не трогается (читается identity-конвертером); освобождённые старые
    места секций (не занятые новой укладкой) зачищаются 0xFF."""
    out = bytearray(base.buf)
    entries = [e for e in base.itoc if e.type != 0xFF]
    start = min(e.addr for e in entries)
    if start < base.itoc_off + 32:
        raise ValueError(f"reflow: first section at 0x{start:x} overlaps the ITOC header")
    cur = start
    plan = []
    for e in entries:
        if e.type in plan_src:
            s = srcs[plan_src[e.type]]
            se = s.find_entry("ITOC", e.type)
            data = s.section_data(se)
        else:
            data = base.section_data(e)
        if len(data) % 4:
            raise ValueError(f"0x{e.type:02x}: size {len(data)} not DW-aligned")
        cur = (cur + 3) & ~3
        if cur + len(data) >= HALF:
            raise ValueError(f"reflow: 0x{e.type:02x} end 0x{cur + len(data):x} >= 0x{HALF:x}")
        out[cur:cur + len(data)] = data
        plan.append((e, data, cur))
        cur += len(data)
    # зачистка освобождённых мест: старые размещения минус новая укладка
    new_ranges = sorted((addr, addr + len(data)) for _, data, addr in plan)
    for e in entries:
        s, t = e.addr, e.addr + e.size
        for ns, ne in new_ranges:
            if ne <= s or ns >= t:
                continue
            if ns > s:
                out[s:ns] = b"\xFF" * (ns - s)
            s = max(s, ne)
        if s < t:
            out[s:t] = b"\xFF" * (t - s)
    itoc_end = base.itoc[-1] if base.itoc and base.itoc[-1].type == 0xFF else None
    if itoc_end is None:
        raise ValueError("missing END entry in base TOC")
    for i, (e, data, addr) in enumerate(plan):
        raw = bytearray(e.raw)
        set_bits(raw, 8, 22, len(data) // 4)
        set_bits(raw, 161, 29, addr // 4)
        set_bits(raw, 208, 16, crc16_mlx(data) if e.crcf == 0 else 0x0000)
        set_bits(raw, 240, 16, crc16_mlx(bytes(raw[:28])))
        off = base.itoc_off + 32 + i * 32
        out[off:off + 32] = raw
    out[base.itoc_off + 32 + len(plan) * 32:base.itoc_off + 64 + len(plan) * 32] = itoc_end.raw
    changed = {e.type: data for e, data, addr in plan if data != base.section_data(e)}
    _hashes_update(base, out, changed)
    return bytes(out)


def swap_repack(base_path: str, swaps: list) -> bytes:
    base = Image(Path(base_path).read_bytes(), str(base_path))
    if base.fmt not in ("fs3", "fs4"):
        raise ValueError(f"repack supports FS3/FS4 only (got {base.fmt})")
    srcs, plan_src = {}, {}
    for src_path, types in swaps:
        if src_path not in srcs:
            srcs[src_path] = Image(Path(src_path).read_bytes(), str(src_path))
        for t in types:
            if t in SWAP_FORBIDDEN:
                raise ValueError(f"0x{t:02x}: signature section (0xa0-0xa4) not swappable")
            if plan_src.get(t) not in (None, src_path):
                raise ValueError(f"0x{t:02x}: listed in two different --swap specs")
            plan_src[t] = src_path
    for t, src_path in plan_src.items():
        srcs[src_path].find_entry("ITOC", t)
    if base.fmt == "fs3":
        # FS3-паритет FS4 (dev-data физически вне ITOC-swap): dev=1 записи
        # не свапаются — фиксированные адреса, identity через guides (§9.2)
        for t in plan_src:
            try:
                e = base.find_entry("ITOC", t)
            except KeyError:
                continue
            if not e.rel:
                raise ValueError(f"0x{t:02x}: device-data section (dev=1) "
                                 "not swappable in FS3 (fixed address)")

    def src_data(e):
        if e.type not in plan_src:
            return base.section_data(e)
        s = srcs[plan_src[e.type]]
        se = s.find_entry("ITOC", e.type)
        data = s.section_data(se)
        if len(data) % 4:
            raise ValueError(f"0x{e.type:02x}: source size {len(data)} not DW-aligned")
        return data

    # Сначала план (без записи): выросшие секции — безопасная релокация
    # (tail-placement, конец ITOC; bound/HALF — в планировщике). Не хватает
    # хвостового места (RelocNoRoom) — полный reflow всех ITOC-секций;
    # интегрити-отказы планировщика (нестёртый gap и пр.) — ошибка, fallback
    # их не глотает (до-цикловое поведение "base gap not erased").
    itoc_plan, grown = [], []
    for e in base.itoc:
        if e.type == 0xFF:
            continue
        data = src_data(e)
        if data == base.section_data(e) or len(data) <= e.size:
            itoc_plan.append((e, data))
            continue
        grown.append((e, data))

    if grown:
        try:
            plan = plan_relocations(base, [(e, data, None) for e, data in grown])
        except RelocNoRoom:
            # FS3: reflow-fallback нет (плотная укладка трогала бы dev-секции
            # с фиксированными адресами) — отказ honest (§9.2)
            if base.fmt == "fs4":
                return _reflow(base, srcs, plan_src)
            raise
    else:
        plan = None

    out = bytearray(base.buf)
    if plan is not None:
        apply_relocations(base, out, plan)
    moved_ids = {id(e) for e, _ in grown}
    for e, data in itoc_plan:
        if data == base.section_data(e):
            continue
        a = base.sec_abs(e)
        out[a:a + len(data)] = data
        if len(data) < e.size:
            out[a + len(data):a + e.size] = b"\xFF" * (e.size - len(data))
    dtoc_plan = [(e, base.section_data(e), e.addr) for e in base.dtoc
                 if e.type != 0xFF] if base.fmt == "fs4" else []

    def write_toc(toc_off, plan_rows, end_raw):
        for i, (e, data, addr) in enumerate(plan_rows):
            raw = bytearray(e.raw)
            set_bits(raw, 8, 22, len(data) // 4)
            set_bits(raw, 161, 29, addr // 4)
            set_bits(raw, 208, 16, crc16_mlx(data) if e.crcf == 0 else 0x0000)
            set_bits(raw, 240, 16, crc16_mlx(bytes(raw[:28])))
            out[toc_off + 32 + i * 32:toc_off + 64 + i * 32] = raw
        out[toc_off + 32 + len(plan_rows) * 32:toc_off + 64 + len(plan_rows) * 32] = end_raw

    itoc_end = base.itoc[-1] if base.itoc and base.itoc[-1].type == 0xFF else None
    dtoc_end = base.dtoc[-1] if base.fmt == "fs4" and base.dtoc and base.dtoc[-1].type == 0xFF else None
    if itoc_end is None or (base.fmt == "fs4" and dtoc_end is None):
        raise ValueError("missing END entry in base TOC")
    # итоговый порядок ITOC: нерелоцированные на местах (строки пересчитаны),
    # релоцированные — FS3 в конце rel-блока (до dev-строк), FS4 в конце
    # (строки записаны apply_relocations), END — после всех записей
    data_of = {id(e): data for e, data in itoc_plan}
    order = _itoc_reloc_order(
        base, [e for e in base.itoc if e.type != 0xFF and id(e) not in moved_ids],
        [e for e, _ in grown])
    for i, e in enumerate(order):
        if id(e) in moved_ids:
            continue
        data = data_of[id(e)]
        raw = bytearray(e.raw)
        set_bits(raw, 8, 22, len(data) // 4)
        set_bits(raw, 161, 29, e.addr // 4)
        set_bits(raw, 208, 16, crc16_mlx(data) if e.crcf == 0 else 0x0000)
        set_bits(raw, 240, 16, crc16_mlx(bytes(raw[:28])))
        out[base.itoc_off + 32 + i * 32:base.itoc_off + 64 + i * 32] = raw
    n_all = len(order)
    out[base.itoc_off + 32 + n_all * 32:base.itoc_off + 64 + n_all * 32] = itoc_end.raw
    if base.fmt == "fs4":
        write_toc(base.dtoc_off, dtoc_plan, dtoc_end.raw)
    changed = {e.type: data for e, data in itoc_plan + grown
               if data != base.section_data(e)}
    _hashes_update(base, out, changed)
    return bytes(out)


def repack_resize(img: Image, section_type: int, new_payload: bytes) -> bytes:
    """Resize одной ITOC-секции новым payload (FS3-leg arc D, спека
    repack-burn-safety §9.2): уменьшение/равный размер — in-place (данные
    поверх, хвост старого экстента 0xFF, строка ITOC на месте — релокации
    нет, автознак не триггерит); рост — tail-placement планировщиком §2.3
    (запись в конец массива ITOC, данные с align64k(max rel end), старое
    место 0xFF). Payload — «сырые» данные секции (zlib/clcrc-фрейминг —
    забота вызывающего; гейт — verify --deep); DW-выравнивание обязательно.
    Флаги строки (rel/dev/zipped/clcrc/crcf) сохраняются, sec/entry CRC
    пересчитываются. Core sign-нейтрален (гейты — CLI cmd_resize)."""
    e = img.find_entry("ITOC", section_type)
    if len(new_payload) % 4:
        raise ValueError(f"0x{section_type:02x}: size {len(new_payload)} "
                         "not DW-aligned")
    out = bytearray(img.buf)
    if len(new_payload) <= e.size:
        a = img.sec_abs(e)
        out[a:a + e.size] = b"\xFF" * e.size
        out[a:a + len(new_payload)] = new_payload
        raw = bytearray(e.raw)
        set_bits(raw, 8, 22, len(new_payload) // 4)
        set_bits(raw, 208, 16, crc16_mlx(new_payload) if e.crcf == 0 else 0x0000)
        set_bits(raw, 240, 16, crc16_mlx(bytes(raw[:28])))
        off = img.itoc_off + 32 + e.index * 32
        out[off:off + 32] = raw
    else:
        if img.fmt == "fs3" and not e.rel:
            raise ValueError(f"0x{section_type:02x}: grown device-data section "
                             "(rel=0) cannot resize (FS3 fixed address)")
        plan = plan_relocations(img, [(e, new_payload, None)])
        apply_relocations(img, out, plan)
    _hashes_update(img, out, {section_type: new_payload})
    return bytes(out)


def cmd_resize(args) -> int:
    img = _image(args.image)
    payload = Path(args.payload).read_bytes()
    try:
        out = repack_resize(img, args.section, payload)
    except (ValueError, KeyError) as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 2
    errs = verify_image(Image(out, img.path, base=img.base, fmt=img.fmt))
    if errs:
        for e in errs:
            print(f"self-verify FAIL: {e}", file=sys.stderr)
        return 1
    if _burn_order_refusal(out, base=img.base, fmt=img.fmt):
        return 2
    out = _autosign_gate(img, out, args.no_autosign)
    if out is None:
        return 2
    Path(args.output).write_bytes(out)
    print(f"{args.output}: 0x{args.section:02x} resized to {len(payload):#x}, "
          f"md5 {hashlib.md5(out).hexdigest()}")
    return 0


def cmd_info(img: Image) -> int:
    print(f"== {img.path} ({len(img.buf)} bytes)")
    toc_blocks = [("ITOC", img.itoc_off, img.itoc_hdr, img.itoc)]
    if img.fmt == "fs4":
        toc_blocks.append(("DTOC", img.dtoc_off, img.dtoc_hdr, img.dtoc))
    for toc, off, hdr, ents in toc_blocks:
        hok = "OK" if img.header_crc_ok(toc) else "NG"
        th = img.itoc_header if toc == "ITOC" else img.dtoc_header
        if img.fmt == "fs4":
            print(f"  {toc} @ {off:#x}: flash_layout_ver={th.flv} "
                  f"ver={th.version} num_entries={th.num_entries} "
                  f"hdr_crc={hok}")
        else:
            print(f"  {toc} @ {off:#x}: ver={th.version} hdr_crc={hok}")
        for e in ents:
            if e.type == 0xFF:
                print(f"    [{e.index:2d}] END")
                continue
            eok = "OK" if img.entry_crc_ok(e) else "NG"
            st, exp, act = section_crc_status(img, e)
            if st == "OK":
                sc = f"OK (0x{exp:04x})"
            elif st == "IGNORED":
                sc = f"IGNORED (crcf={e.crcf})"
            else:
                sc = f"WRONG (exp:0x{exp:04x}, act:0x{act:04x})"
            if img.fmt == "fs3":
                tail = f"z={e.zipped} cl={e.clcrc} rel={e.rel} dev={e.dev} ncrc={e.crcf}"
            else:
                tail = f"z={e.zipped} cl={e.clcrc} ver={e.ver:#05x} enc={e.enc} crcf={e.crcf}"
            print(f"    [{e.index:2d}] 0x{e.type:02x} {SECT_NAMES.get(e.type, '?'):<16} "
                  f"size={e.size:#010x} addr={e.addr:#011x} "
                  f"sec_crc={sc} entry_crc={e.entry_crc:#06x}({eok}) {tail}")
    if img.fmt == "fs4":
        ht = HashesTable.from_image(img)
        if ht is None:
            p = hw_pointers(img.buf, getattr(img, "base", 0))["hashes_table_pointer"][0]
            print(f"  hashes table: present=no (ptr=0x{p:08x})")
        else:
            hok = "OK" if ht.header_crc_ok() else "NG"
            dok = "OK" if ht.data_crc_ok() else "NG"
            print(f"  hashes table: present=yes abs=0x{ht.ptr:x} ver={ht.version} "
                  f"num={ht.num}/{ht.max_num} hash_size={ht.hash_size} hdr_crc={hok} data_crc={dok}")
            for i, (t, off) in enumerate(ht.entries):
                print(f"    [{i}] 0x{t:02x} {SECT_NAMES.get(t, '?'):<16} hash_offset=0x{off:x}")
    ram = [e for e in list(img.itoc) + list(img.dtoc)
           if e.type != 0xFF and (e.param0 or e.param1)]
    if ram:
        print("  RAM map (param0/param1, non-zero only):")
        for e in ram:
            print(f"    [{e.toc} {e.index:2d}] 0x{e.type:02x} "
                  f"{SECT_NAMES.get(e.type, '?'):<16} "
                  f"load=0x{e.param0:08x} jump=0x{e.param1:08x}")
    return 0


def section_insection_crc(sec: bytes) -> tuple:
    total_dw = len(sec) // 4
    stored = int.from_bytes(sec[-2:], "big")          # lower-16 последнего DW = последние 2 байта
    calc = crc16_mlx(sec[0:(total_dw - 1) * 4])        # по первым size-1 DW
    return stored, calc


def section_crc_status(img: "Image", e) -> tuple:
    if e.crcf == 1:
        return ("IGNORED", 0, 0)
    if e.crcf == 2:
        if not (e.type == 0xE1 and devinfo_sig_ok(img.section_data(e))):
            return ("IGNORED", 0, 0)
        stored, calc = section_insection_crc(img.section_data(e))
        return (("OK" if stored == calc else "WRONG"), calc, stored)
    if e.crcf == 0:
        calc = crc16_mlx(img.section_data(e))
        return (("OK" if calc == e.sec_crc else "WRONG"), e.sec_crc, calc)
    return ("IGNORED", 0, 0)


def verify_image(img: "Image", deep: bool = False) -> list:
    errs = []
    tocs = ("ITOC",) if img.fmt == "fs3" else ("ITOC", "DTOC")
    for toc in tocs:
        if not img.header_crc_ok(toc):
            errs.append(f"{toc} header CRC NG")
        for e in img.entries(toc):
            st, exp, act = section_crc_status(img, e)
            if st == "WRONG":
                errs.append(f"{toc}[{e.index}] 0x{e.type:02x} {SECT_NAMES.get(e.type, '?')} "
                            f"section CRC WRONG (exp:0x{exp:04x}, act:0x{act:04x})")
            if not img.entry_crc_ok(e):
                errs.append(f"{toc}[{e.index}] 0x{e.type:02x} {SECT_NAMES.get(e.type, '?')} entry CRC NG")
            if e.addr + e.size > len(img.buf):
                errs.append(f"{toc}[{e.index}] 0x{e.type:02x} section past EOF")
    if img.fmt == "fs4":
        dv = find_valid_devinfo(img)
        if len(dv) != 1:
            errs.append(f'DEV_INFO: expected exactly one valid mDevInfo, found {len(dv)}')
        ht = HashesTable.from_image(img)
        if ht is not None:
            if not ht.header_crc_ok():
                errs.append("hashes table header CRC NG")
            if not ht.data_crc_ok():
                errs.append("hashes table data CRC NG")
        if deep and ht is not None:
            for i, (t, off) in enumerate(ht.entries):
                e = img.find_entry("ITOC", t)
                if hashlib.sha512(img.section_data(e)).digest() != bytes(ht.data[12 + off:12 + off + ht.hash_size]):
                    errs.append(f"hashes table: 0x{t:02x} hash mismatch (deep)")
        if deep:
            for e in img.entries("ITOC"):
                if not e.clcrc or e.zipped or e.size < CLCRC_LINE:
                    continue
                bad = clcrc_lines_errors(img.section_data(e))
                if bad:
                    i, exp, act = bad[0]
                    errs.append(f"ITOC[{e.index}] 0x{e.type:02x} {SECT_NAMES.get(e.type, '?')} "
                                f"per-line clcrc WRONG: {len(bad)}/{e.size // CLCRC_LINE} lines "
                                f"(first: line {i} exp:0x{exp:04x} act:0x{act:04x})")
    else:
        if not any(e.type == 0xE0 for e in img.entries("ITOC")):
            errs.append("MFG_INFO (0xE0) section missing (FS3)")
        dev_seen = False
        for e in img.entries("ITOC"):
            if e.type == 0xFF:
                continue
            if not e.rel:
                dev_seen = True
            elif dev_seen:
                errs.append(f"ITOC[{e.index}] 0x{e.type:02x} relative section "
                            "after device-data rows: invisible to the FW-side "
                            "MCC TOC walk (masked dev rows are FS3_END) - "
                            "digest gate would reject (MCC 0x2)")
    return errs


def verify_warnings(img: Image) -> list:
    if img.fmt != "fs4":
        return []
    warns = []
    for toc in ("ITOC", "DTOC"):
        th = img.itoc_header if toc == "ITOC" else img.dtoc_header
        n = th.num_entries
        actual = len(img.entries(toc))
        if n is not None and n != 0 and n != actual:
            warns.append(f"{toc} header num_of_entries={n} != {actual} "
                         f"entries (excluding END)")
    if img.dtoc_header.flv < img.itoc_header.flv:
        warns.append(f"flash_layout_version: ITOC={img.itoc_header.flv} > "
                     f"DTOC={img.dtoc_header.flv} (mstflint would require "
                     f"device-section alignment)")
    return warns


def cmd_verify(img: Image, deep: bool = False,
               sector_size: int = DEFAULT_SECTOR) -> int:
    if sector_size < 1 or sector_size & (sector_size - 1):
        print(f"error: --sector-size must be a power of two, got {sector_size:#x}",
              file=sys.stderr)
        return 2
    errs = verify_image(img, deep=deep)
    for line in errs:
        print(line)
    for w in verify_warnings(img):
        print(f"warning: {w}", file=sys.stderr)
    violations = burn_order_check(img, sector_size=sector_size)
    for v in violations:
        print(f"burn-order: image will be damaged by burn: {v.explanation}")
    status, _stored, calc = sig_status(img)
    line = f"signature 0xA0: {status}"
    if calc is not None:
        line += f" {calc.hex()[:8]}"
    print(line)
    if errs or violations:
        print(f"RESULT: FAIL ({len(errs) + len(violations)} errors)")
        return 1
    print(f"RESULT: PASS (ITOC {len(img.entries('ITOC'))} + DTOC {len(img.entries('DTOC'))} "
          f"sections, all CRC OK)")
    return 0


def cmd_sign(args) -> int:
    img = _image(args.image)
    status, stored, calc = sig_status(img)
    if args.check:
        line = f"signature 0xA0: {status}"
        if status in ("fresh", "stale"):
            line += f" digest {calc.hex()}"
        print(line)
        return {"fresh": 0, "stale": 1}.get(status, 2)
    if status == "v2":
        print("error: secure-boot V2 image: mask not implemented", file=sys.stderr)
        return 2
    if status == "missing":
        print("error: no SIG_256 (0xA0) section", file=sys.stderr)
        return 2
    if status == "rsa" and not args.force:
        # RSA-подпись в 0xA0 не затираем молча (паритет с mstflint: --force
        # нормализует секцию целиком, uuid-поля -> 0)
        print("error: RSA-signed image; --force to overwrite", file=sys.stderr)
        return 2
    if status == "empty":
        print("error: 0xA0 digest slot is empty (all 0x00/0xFF)", file=sys.stderr)
        return 2
    e = img.find_entry("ITOC", 0xA0)
    a = img.sec_abs(e)
    if e.size < SIG_SLOT_OFF + 32:
        print(f"error: 0xA0 section too small ({e.size:#x}) for a 32B digest slot",
              file=sys.stderr)
        return 2
    out = bytearray(img.buf)
    if status == "rsa":
        out[a:a + e.size] = b"\x00" * e.size
    digest = sha256_digest(img)
    out[a + SIG_SLOT_OFF:a + SIG_SLOT_OFF + 32] = digest
    if img.fmt == "fs3" and e.crcf == 0:
        sec_crc = crc16_mlx(bytes(out[a:a + e.size]))
        ent_off = img.itoc_off + 32 + e.index * 32
        ent = bytearray(out[ent_off:ent_off + 32])
        set_bits(ent, 208, 16, sec_crc)
        set_bits(ent, 240, 16, crc16_mlx(bytes(ent[:28])))
        out[ent_off:ent_off + 32] = ent
    vimg = Image(bytes(out), img.path, base=img.base, fmt=img.fmt)
    errs = verify_image(vimg)
    if errs:
        for x in errs:
            print(f"self-verify FAIL: {x}", file=sys.stderr)
        return 1
    Path(args.image).write_bytes(bytes(out))
    old_hex = stored.hex() if stored is not None else "-"
    print(f"{args.image}: 0xA0 digest {old_hex} -> {digest.hex()}")
    print(f"{args.image}: signed in-place ({len(out)} bytes), "
          f"md5 {hashlib.md5(bytes(out)).hexdigest()}")
    return 0


def cmd_guides(args) -> int:
    buf = Path(args.image).read_bytes()
    fmt, base = detect_format(buf)
    if fmt == "fs3":
        return cmd_guides_fs3(args, buf, base)
    if fmt != "fs4":
        print(f"error: guides supports FS4 only (got {fmt})", file=sys.stderr)
        return 2
    img = Image(buf, args.image, base=base)
    if args.output is None:
        args.output = str(Path(args.image).with_suffix(".inject"))
    buf = bytearray(img.buf)
    valid = find_valid_devinfo(img)
    if len(valid) > 1:
        addrs = ", ".join(f"0x{e.addr:x}" for e in valid)
        print(f"error: {len(valid)} valid mDevInfo sections ({addrs}); resolve manually", file=sys.stderr)
        return 1
    if valid:
        target = valid[0]
        created = False
    else:
        cands = [e for e in img.entries("DTOC") if e.type == 0xE1]
        if not cands:
            print("error: no DEV_INFO (0xE1) section in DTOC", file=sys.stderr)
            return 1
        target = min(cands, key=lambda e: e.addr)
        created = True
    m = MDevInfo.parse(img.section_data(target))
    m.ensure_valid()
    new_di = m.write_uids(args.guid, args.mac)
    buf[target.addr:target.addr + target.size] = new_di[:target.size]
    changes = [f"DEV_INFO @0x{target.addr:x}: guid=0x{args.guid:x} mac=0x{args.mac:x}"
               + (" (created)" if created else "")
               + f", CRC=0x{int.from_bytes(new_di[-2:], 'big'):04x}"]
    try:
        e0 = img.find_entry("DTOC", 0xE0)
    except KeyError:
        print("warning: no MFG_INFO (0xE0) section; skipping guid/mac copy", file=sys.stderr)
        e0 = None
    if e0 is not None:
        e0d = bytearray(img.section_data(e0))
        e0d[0x28:0x30] = args.guid.to_bytes(8, "big")
        e0d[0x38:0x40] = args.mac.to_bytes(8, "big")
        buf[e0.addr:e0.addr + e0.size] = e0d
        if e0.crcf == 0:
            sec_crc = crc16_mlx(bytes(e0d))
            ent_off = img.dtoc_off + 32 + e0.index * 32
            ent = bytearray(buf[ent_off:ent_off + 32])
            set_bits(ent, 208, 16, sec_crc)
            set_bits(ent, 240, 16, crc16_mlx(bytes(ent[:28])))
            buf[ent_off:ent_off + 32] = ent
            changes.append(f"MFG_INFO @0x{e0.addr:x}: guid+mac, sec_crc 0x{e0.sec_crc:04x}->0x{sec_crc:04x}, entry_crc updated")
        else:
            print(f"warning: MFG_INFO crcf={e0.crcf} — sec CRC not updated", file=sys.stderr)
            changes.append(f"MFG_INFO @0x{e0.addr:x}: guid+mac (crcf={e0.crcf}, no CRC)")
    vimg = Image(bytes(buf), img.path, base=base)
    errs = verify_image(vimg)
    if errs:
        for e in errs:
            print(f"self-verify FAIL: {e}", file=sys.stderr)
        return 1
    out = bytes(buf)
    Path(args.output).write_bytes(out)
    for c in changes:
        print(f"  {c}")
    print(f"{args.output}: {len(out)} bytes, md5 {hashlib.md5(out).hexdigest()}")
    return 0


def cmd_guides_fs3(args, buf: bytes, base: int) -> int:
    img = Image(buf, args.image, base=base)
    if args.output is None:
        args.output = str(Path(args.image).with_suffix(".inject"))
    try:
        e1 = img.find_entry("ITOC", 0xE1)
        e0 = img.find_entry("ITOC", 0xE0)
    except KeyError as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 1
    d1 = bytearray(img.section_data(e1))
    if not devinfo_sig_ok(bytes(d1)):
        print("error: DEV_INFO (0xE1) signature not OK", file=sys.stderr)
        return 1
    major1 = ((d1[0x11] & 1) << 8) | d1[0x12]
    if major1 != 2:
        print(f"error: DEV_INFO major_version {major1} (need 2, cx4fw layout; old layout not supported)",
              file=sys.stderr)
        return 1
    d0 = bytearray(img.section_data(e0))
    if d0[MFG3_MAJOR_OFF] != 1:
        print(f"error: MFG_INFO major_version {d0[MFG3_MAJOR_OFF]} (need 1, cx4fw layout; old layout not supported)",
              file=sys.stderr)
        return 1
    if d0[MFG3_OVR_OFF] & 1 == 0:
        print("warning: MFG_INFO guids_override_en=0 (mstflint setguid would require -ocr); "
              "writing both nodes anyway", file=sys.stderr)
    b = bytearray(buf)
    g = args.guid.to_bytes(8, "big")
    m = args.mac.to_bytes(8, "big")
    changes = []
    for e, d in ((e1, d1), (e0, d0)):
        name = "DEV_INFO" if e is e1 else "MFG_INFO"
        a = img.sec_abs(e)
        d[0x28:0x30] = g
        d[0x38:0x40] = m
        b[a:a + e.size] = bytes(d)
        if e.crcf == 1:
            print(f"warning: {name} (0x{e.type:02x}) no_crc=1 — sec CRC not updated", file=sys.stderr)
            changes.append(f"{name} @0x{e.addr:x}: guid=0x{args.guid:x} mac=0x{args.mac:x} (no_crc=1, no CRC)")
        else:
            sec_crc = crc16_mlx(bytes(d))
            ent_off = img.itoc_off + 32 + e.index * 32
            ent = bytearray(b[ent_off:ent_off + 32])
            set_bits(ent, 208, 16, sec_crc)
            set_bits(ent, 240, 16, crc16_mlx(bytes(ent[:28])))
            b[ent_off:ent_off + 32] = ent
            changes.append(f"{name} @0x{e.addr:x}: guid=0x{args.guid:x} mac=0x{args.mac:x}, "
                           f"sec_crc 0x{e.sec_crc:04x}->0x{sec_crc:04x}, entry_crc updated")
    vimg = Image(bytes(b), img.path, base=base)
    errs = verify_image(vimg)
    if errs:
        for e in errs:
            print(f"self-verify FAIL: {e}", file=sys.stderr)
        return 1
    out = bytes(b)
    Path(args.output).write_bytes(out)
    for c in changes:
        print(f"  {c}")
    print(f"{args.output}: {len(out)} bytes, md5 {hashlib.md5(out).hexdigest()}")
    return 0


def _image(path: str) -> Image:
    buf = Path(path).read_bytes()
    fmt, base = detect_format(buf)
    return Image(buf, path, base=base, fmt=fmt)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="mlxfwutil.py", description="FS4 firmware image toolkit")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("info", help="ITOC/DTOC dump (type/addr/size/CRC)")
    p.add_argument("image")
    p.set_defaults(func=lambda a: cmd_info(_image(a.image)))

    p = sub.add_parser("verify", help="CRC check of all sections")
    p.add_argument("image")
    p.add_argument("--deep", action="store_true",
                   help="also compare section SHA-512 against the hashes table and "
                        "verify per-line clcrc of clcrc=1 sections "
                        "(mstflint does not do this)")
    p.add_argument("--sector-size", type=lambda s: int(s, 0), default=DEFAULT_SECTOR,
                   help="burn-order sector erase granularity for the burn-order "
                        "gate (default 0x10000; plain burn forces Fwm_64KB)")
    p.set_defaults(func=lambda a: cmd_verify(_image(a.image), deep=a.deep,
                                             sector_size=a.sector_size))

    p = sub.add_parser("sign",
                       help="recompute & write 0xA0 SHA-256 digest in-place (mstflint sign parity)")
    p.add_argument("image")
    p.add_argument("--check", action="store_true",
                   help="verify digest only, no write (rc 0 fresh / 1 stale / 2 N/A)")
    p.add_argument("--force", action="store_true",
                   help="allow overwriting an RSA-signed 0xA0 section (zeroes uuid fields; mstflint parity)")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("guides", help="GUID/MAC injection into mDevInfo + MFG_INFO (self-verify)")
    p.add_argument("image")
    p.add_argument("--guid", required=True, type=lambda s: int(s, 0))
    p.add_argument("--mac", required=True, type=lambda s: int(s, 0))
    p.add_argument("-o", "--out", "--output", dest="output", default=None,
                   help="output file (default: <image>.inject)")
    p.set_defaults(func=cmd_guides)

    p = sub.add_parser("extract", help="section -> file (0x30: zlib -> ini text)")
    p.add_argument("image")
    p.add_argument("-s", "--section", required=True, type=lambda s: int(s, 0))
    p.add_argument("-o", "--output")
    p.add_argument("--raw", action="store_true")
    p.set_defaults(func=lambda a: cmd_extract(_image(a.image), a))

    p = sub.add_parser("diff", help="per-section byte diff of two images")
    p.add_argument("image_a")
    p.add_argument("image_b")
    p.add_argument("--max-ranges", type=int, default=24)
    p.set_defaults(func=lambda a: cmd_diff(_image(a.image_a), _image(a.image_b), a.max_ranges))

    p = sub.add_parser("psid", help="IMAGE_INFO 0x10: set PSID/name/description (+CRC)")
    p.add_argument("image")
    p.add_argument("--psid")
    p.add_argument("--name")
    p.add_argument("--description")
    p.add_argument("-o", "--output", required=True)
    p.set_defaults(func=lambda a: cmd_psid(_image(a.image), a))

    p = sub.add_parser("inject", help="re-inject ini text into 0x30 DBG_FW_INI (zlib lvl9, +CRC, self-verify)")
    p.add_argument("image")
    p.add_argument("ini")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--repack-force", action="store_true",
                   help="allow 0x30 relocation to tail gap when new ini exceeds section size")
    p.add_argument("--unsafe-relocation", action="store_true",
                   help="research: legacy pre-cycle relocation (align4 tail, ITOC entry "
                        "stays mid-list; output WILL be damaged by burn; bypasses the "
                        "pre-write burn-order gate only; requires --repack-force)")
    p.add_argument("--no-autosign", action="store_true",
                   help="skip the automatic 0xA0 digest recompute after relocation "
                        "(image will not be MCC-ready)")
    p.set_defaults(func=cmd_inject)

    p = sub.add_parser("patch", help="in-place byte patch of ITOC sections (+CRC recompute)")
    p.add_argument("image")
    p.add_argument("--set", dest="sets", action="append", required=True,
                   metavar="0xNN+0xOFF=HEXBYTES")
    p.add_argument("-o", "--output", required=True)
    p.set_defaults(func=lambda a: cmd_patch(_image(a.image), a))

    p = sub.add_parser("merge",
                       help="field-range merge: copy field ranges from SRC ITOC sections into BASE (+CRC recompute)")
    p.add_argument("--base", required=True)
    p.add_argument("--src", required=True)
    p.add_argument("--spec", required=True, metavar="0xNN+0xOFF+LEN[,...]")
    p.add_argument("-o", "--output", required=True)
    p.set_defaults(func=cmd_merge)

    p = sub.add_parser("ab", help="decode raw 16MiB/32MiB flash dump: A/B slot state (+diff)")
    p.add_argument("raw_dump")
    p.add_argument("--diff", metavar="OTHER_RAW", help="byte diff vs another raw dump")
    p.set_defaults(func=cmd_ab)

    p = sub.add_parser("repack", help="repack FS3/FS4 image: legacy merge (--new/--old/--prio) or section swap (--base/--swap)")
    p.add_argument("--new", help="legacy: newer FW image (code base)")
    p.add_argument("--old", help="legacy: older FW image")
    p.add_argument("--prio", choices=["new", "old"], help="legacy: merge priority for config sections")
    p.add_argument("--base", help="swap mode: base image (everything not swapped stays byte-identical)")
    p.add_argument("--swap", action="append", default=[], metavar="SRC:0xNN[,0xNN...]",
                    help="swap mode: replace listed ITOC sections from SRC (repeatable)")
    p.add_argument("--no-autosign", action="store_true",
                   help="skip the automatic 0xA0 digest recompute after relocation "
                        "(image will not be MCC-ready)")
    p.add_argument("-o", "--output", required=True)
    p.set_defaults(func=cmd_repack)

    p = sub.add_parser("resize",
                       help="resize an ITOC section with a new payload "
                            "(in-place or safe tail relocation, +CRC, self-verify)")
    p.add_argument("image")
    p.add_argument("-s", "--section", required=True, type=lambda s: int(s, 0),
                   metavar="0xNN")
    p.add_argument("-p", "--payload", required=True,
                   help="file with the new raw section payload (DW-aligned; "
                        "zlib/clcrc framing is the caller's responsibility)")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--no-autosign", action="store_true",
                   help="skip the automatic 0xA0 digest recompute after relocation "
                        "(image will not be MCC-ready)")
    p.set_defaults(func=cmd_resize)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
