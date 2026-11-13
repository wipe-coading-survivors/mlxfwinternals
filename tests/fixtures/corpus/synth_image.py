import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from mlxfwutil import CNTX_MAGIC, ITOC_HDR, clcrc_wrap, crc16_mlx, set_bits

ITOC_OFF = 0x2000
DATA_START = 0x4000
DATA_ALIGN = 0x40
VERSION_WORD = b"\x03\x17\x01\x01"


def _entry(typ, data_len, addr, cl=False, zipped=False, param0=0, param1=0,
           sec_crc=0):
    ent = bytearray(32)
    set_bits(ent, 0, 8, typ)
    set_bits(ent, 8, 22, data_len // 4)
    set_bits(ent, 32, 1, 1 if zipped else 0)
    set_bits(ent, 33, 1, 1 if cl else 0)
    set_bits(ent, 34, 30, param0)
    set_bits(ent, 64, 32, param1)
    set_bits(ent, 160, 1, 1)
    set_bits(ent, 161, 29, addr // 4)
    set_bits(ent, 208, 16, sec_crc)
    set_bits(ent, 240, 16, crc16_mlx(bytes(ent[:28])))
    return bytes(ent)


def build_synth_image(sections: list) -> bytes:
    placed = []
    cursor = DATA_START
    for spec in sections:
        payload = spec.get("payload", b"")
        cl = spec.get("cl", False)
        data = clcrc_wrap(payload) if cl and payload else payload
        placed.append((spec["typ"], data, cursor, cl,
                       spec.get("zipped", False),
                       spec.get("param0", 0), spec.get("param1", 0)))
        cursor = (cursor + len(data) + DATA_ALIGN - 1) & ~(DATA_ALIGN - 1)
    itoc_end = ITOC_OFF + 32 + 32 * (len(placed) + 1)
    total = max(cursor, itoc_end, DATA_START + 0x400)
    buf = bytearray(b"\xff" * total)
    buf[0:16] = CNTX_MAGIC
    buf[0x24:0x28] = VERSION_WORD
    hdr = bytearray(32)
    hdr[0:16] = ITOC_HDR
    hdr[0x1E:0x20] = struct.pack(">H", crc16_mlx(bytes(hdr[:28])))
    buf[ITOC_OFF:ITOC_OFF + 32] = hdr
    for i, (typ, data, addr, cl, zipped, param0, param1) in enumerate(placed):
        ent = _entry(typ, len(data), addr, cl=cl, zipped=zipped,
                     param0=param0, param1=param1, sec_crc=crc16_mlx(data))
        off = ITOC_OFF + 32 + i * 32
        buf[off:off + 32] = ent
        if data:
            buf[addr:addr + len(data)] = data
    end = _entry(0xFF, 0, 0)
    off = ITOC_OFF + 32 + len(placed) * 32
    buf[off:off + 32] = end
    return bytes(buf)
