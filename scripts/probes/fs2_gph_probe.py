#!/usr/bin/env python3
# Минимальный FS2-парсер для docs/journal 2026-10-24-cx3-pcie-lineage-re:
# цепочка GPH-секций (docs/250-re/100-formats/010-fs2.md, референс refs/src/BeTeP-STH_mft-scripts/
# fs2_update_ini.py): GPH = '>IIII' type,size(DW),param,next; полная секция
# = 16 + size*4 + 4 (CRC BE u32). Поддержка: list / extract (по типу или
# индексу) / dump-all.
import struct, sys, zlib

GPH_STRUCT = '>IIII'
GPH_SIZE = 16
GPH_TYPES = 'UNKNOWN DDR CNF JMP EMT ROM GUID BOARD_ID USER_DATA FW_CONF IMG_INFO DDRZ HASH_FILE LAST'.split()
FS2_BOOT_START = 0x38
LASTNEXT = 0xff000000
CNTX = bytes.fromhex('4D5446578CDFD000DEAD92704154BEEF')


def crc16_mlx(data: bytes) -> int:
    def step(crc, bit):
        msb = (crc >> 15) & 1
        crc = ((crc << 1) | bit) & 0xFFFF
        if msb:
            crc ^= 0x100B
        return crc
    crc = 0xFFFF
    for b in data:
        for i in range(7, -1, -1):
            crc = step(crc, (b >> i) & 1)
    for _ in range(16):
        crc = step(crc, 0)
    return crc ^ 0xFFFF


def parse_sections(buf):
    sections = []
    off = FS2_BOOT_START
    while 0 < off < len(buf):
        typ, size, param, nxt = struct.unpack_from(GPH_STRUCT, buf, off)
        # size в DW; полная секция = GPH + size*4 + CRC; для known-типов
        # fs2_update_ini добавляет +4 к size*4 (CRC), поэтому:
        total = GPH_SIZE + size * 4 + (4 if 0 < typ < len(GPH_TYPES) else 0)
        gph = dict(offset=off, type=typ, typename=GPH_TYPES[typ] if typ < len(GPH_TYPES) else f'?{typ:#x}',
                   size_dw=size, param=param, next=nxt, total=total,
                   data_off=off + GPH_SIZE, data_len=total - GPH_SIZE - 4)
        gph['crc_off'] = off + total - 4
        if gph['crc_off'] + 4 <= len(buf):
            gph['crc'] = struct.unpack_from('>I', buf, gph['crc_off'])[0] & 0xFFFF
            gph['crc_calc'] = crc16_mlx(buf[off:off + total - 4])
        else:
            gph['crc'] = None
        sections.append(gph)
        if nxt == LASTNEXT or nxt == 0:
            break
        off = gph['crc_off'] + 4
    return sections


def main():
    if len(sys.argv) < 3:
        print(f"Usage:\n\t{sys.argv[0]} list <bin>...\n"
              f"\t{sys.argv[0]} extract <bin> <type|idx> <out>\n"
              f"\t{sys.argv[0]} dump-all <bin> <dir>")
        sys.exit(1)
    cmd, path = sys.argv[1], sys.argv[2]
    buf = open(path, 'rb').read()
    assert buf[:16] == CNTX and buf[0x24] != 3, "not an FS2 image"
    secs = parse_sections(buf)
    if cmd == 'list':
        print(f"== {path} ({len(buf)} bytes, FS2)")
        for i, s in enumerate(secs):
            if s['crc'] is None:
                ok = '?'
            elif s['crc'] == s['crc_calc']:
                ok = 'OK'
            else:
                ok = f"BAD {s['crc']:#x}/{s['crc_calc']:#x}"
            print(f"  [{i:2d}] {s['typename']:<10} @{s['offset']:#08x} dw={s['size_dw']:#8x} "
                  f"bytes={s['data_len']:#8x} param={s['param']:#010x} next={s['next']:#010x} crc={ok}")
    elif cmd == 'extract':
        sel = sys.argv[3]
        s = next((x for x in secs if x['typename'] == sel), None) if not sel.isdigit() else secs[int(sel)]
        assert s is not None, f"section not found: {sel}"
        data = buf[s['data_off']:s['data_off'] + s['data_len']]
        if data[:2] == b'\x78\xda' or s['typename'] in ('DDRZ', 'FW_CONF'):
            try:
                data = zlib.decompress(data)
                sys.stderr.write(f"[zlib-inflated {len(data)} bytes]\n")
            except zlib.error:
                pass
        open(sys.argv[4], 'wb').write(data)
        print(f"{s['typename']} -> {sys.argv[4]} ({len(data)} bytes)")
    elif cmd == 'dump-all':
        import os
        os.makedirs(sys.argv[3], exist_ok=True)
        for i, s in enumerate(secs):
            fn = f"{sys.argv[3]}/{i:02d}-{s['typename']}@{s['offset']:x}.bin"
            open(fn, 'wb').write(buf[s['data_off']:s['data_off'] + s['data_len']])
        print(f"dumped {len(secs)} sections to {sys.argv[3]}/")


if __name__ == '__main__':
    main()
