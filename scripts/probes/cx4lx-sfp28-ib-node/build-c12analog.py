#!/usr/bin/env python3
"""cx4lx-sfp28-ib-node task-04b/04h: build C12-analog image from fresh ri
(build/c1-00-ri.bin; VPI byte already on card, GUID/MAC/PSID native):
MAIN_CODE word raw 0x37e0f0 fcb1c083 -> --after (default 0x0011001f;
0x07 iteration 2026-10-11: 0x00110007, SDR/DDR/QDR), optional second word
--patch-a (task-04h: F1 assert-suppress per RE(c) 2026-10-11, dc 0x18c0c8
0x94002d2b -> 0x95000029; raw re-derived via ITOC 0x03 + de-frame, not
trusted from the journal), optional build-ID line in 0x30 DBG_FW_INI
right after the iniprep banner (mellanox-fw-build R1/R2: in-place only,
budget <= e.size-32, ;;-comment trim, no relocation/--repack-force).
Gates [0]..[13] with die() on any deviation ([13] = --regress-diff vs a
reference image); no-args run byte-reproduces the 0x1f image
(md5 daf609ec...)."""
import argparse
import hashlib
import os
import re
import struct
import subprocess
import sys
import tempfile
import zlib

REPO = os.path.expanduser('~/git/IMPLEMENTATION/mlxini')
BASE = REPO + '/build/c1-00-ri.bin'
BASE_MD5 = 'dacbcf0e1cbc1bed3d5e916520fe6803'
RAW_OFF = 0x37e0f0
NEXT_OFF = 0x37e0f4
BEFORE = 0xfcb1c083
NEXT_WORD = 0x6430000a
AFTER_DEFAULT = 0x0011001f
OUT_DEFAULT = REPO + '/build/c1-1900vpi-c12analog.bin'
SEC_ADDR = 0x16d000
SEC_SIZE = 0x34e8c0
BANNER = ';; Mellanox Technologies LTD'
INI_MARGIN = 32
CARD_BDF = '0000:c1:00.0'

# HW CRC-16: reflect-таблица poly 0xD008 (эквивалент crc16table2 из
# mstflint mft_utils/calc_hw_crc.c); генерируется
HW_CRC_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0xD008 if _c & 1 else _c >> 1
    HW_CRC_TABLE.append(_c)

def calc_hwcrc(crc, data):
    for b in data:
        crc = (crc >> 8) ^ HW_CRC_TABLE[(b ^ (crc & 0xFF)) & 0xFF]
    return crc

def clcrc(code, tail=b''):
    assert len(code) % 64 == 0
    out = bytearray()
    for i in range(len(code) // 64):
        line = bytearray(code[i*64:(i+1)*64]) + b'\x00\x00'
        line += struct.pack('<H', calc_hwcrc(0x0000, bytes(line)))
        out += line
    return bytes(out) + tail

def decrc(data):
    out = bytearray()
    for i in range(len(data) // 68):
        out += data[i*68:i*68+64]
    return bytes(out)

def die(msg):
    print('FATAL: ' + msg)
    sys.exit(1)

def w32be(b, o):
    return struct.unpack_from('>I', b, o)[0]

sys.path.insert(0, REPO)
sys.path.insert(0, REPO + '/scripts/probes')
import mlxfwutil

def padded_zlib_len(text):
    c = zlib.compress(text.encode('latin1'), 9)
    return len(c) + (4 - len(c) % 4) % 4

def build_id_step(img, step1, build_id):
    """R1/R2: build-ID into 0x30 in-place; trim ;; comments on overbudget."""
    e30 = img.find_entry('ITOC', 0x30)
    data30 = img.section_data(e30)
    if data30[:2] != b'\x78\xda':
        die('0x30 is not zlib-compressed (no 78da magic) - unexpected, STOP')
    text = zlib.decompress(data30).decode('latin1')
    lines = text.split('\n')
    if BANNER not in lines:
        die('banner line %r not found in 0x30 ini - STOP' % BANNER)
    banner_idx = lines.index(BANNER)
    lines.insert(banner_idx + 1, build_id)
    budget = e30.size - INI_MARGIN
    removed = []
    cur = '\n'.join(lines)
    while padded_zlib_len(cur) > budget:
        cands = [i for i, l in enumerate(lines)
                 if l.startswith(';;') and i != banner_idx]
        if not cands:
            die('FATAL: 0x30 budget %d B (e.size-32) exceeded after all '
                ';;-comment trims; relocation/--repack-force forbidden '
                'in this task (R2) - STOP' % budget)
        victim = max(cands, key=lambda i: (len(lines[i]), -i))
        removed.append(lines[victim])
        del lines[victim]
        banner_idx = lines.index(BANNER)
        cur = '\n'.join(lines)
    final_text = cur
    s1 = mlxfwutil.Image(step1, 'step1', base=img.base, fmt=img.fmt)
    final = mlxfwutil.inject_ini(s1, final_text, force=False)
    return final, removed, final_text, e30

def q_identity(out):
    guid = mac = None
    for l in out.splitlines():
        m = re.match(r'\s*Base GUID:\s+([0-9a-fA-F]{16})', l)
        if m:
            guid = m.group(1).lower()
        m = re.match(r'\s*Base MAC:\s+([0-9a-fA-F]{12})', l)
        if m:
            mac = m.group(1).lower()
    return guid, mac

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--after', default='0x%08x' % AFTER_DEFAULT,
                    help='32-bit word to patch at raw 0x%x (hex)' % RAW_OFF)
    ap.add_argument('--out', default=OUT_DEFAULT, help='output image path')
    ap.add_argument('--build-id', default='',
                    help='build-ID line for 0x30 (iniprep ";" syntax); '
                         'empty = no build-ID')
    ap.add_argument('--patch-a', action='store_true',
                    help='task-04h: also patch the F1 assert-suppress word '
                         '(RE(c): dc 0x18c0c8 0x94002d2b -> 0x95000029)')
    ap.add_argument('--patch-a-dc', default='0x18c0c8',
                    help='dc (de-clcrc) offset of the PATCH A word (hex)')
    ap.add_argument('--patch-a-before', default='0x94002d2b',
                    help='original word expected at PATCH A dc (hex)')
    ap.add_argument('--patch-a-after', default='0x95000029',
                    help='replacement word at PATCH A dc (hex)')
    ap.add_argument('--regress-diff', default='',
                    help='gate [13]: byte-diff final vs this reference '
                         'image; allowed = PATCH A zone + 0x30 zone only')
    args = ap.parse_args()
    after = int(args.after, 0)
    if not 0 <= after <= 0xFFFFFFFF:
        die('--after not a 32-bit word: %r' % args.after)
    patch_a = args.patch_a
    dc_a = before_a = after_a = raw_a = line_a = None
    if patch_a:
        dc_a = int(args.patch_a_dc, 0)
        before_a = int(args.patch_a_before, 0)
        after_a = int(args.patch_a_after, 0)
    if args.regress_diff and not patch_a:
        die('--regress-diff requires --patch-a')
    out_path = args.out
    build_id = args.build_id
    if build_id.startswith(';;'):
        die('--build-id must use ";" (iniprep), not ";;" (a ;; line is a '
            'trim candidate)')

    buf = open(BASE, 'rb').read()
    if hashlib.md5(buf).hexdigest() != BASE_MD5:
        die('base md5 mismatch')

    img = mlxfwutil.Image(buf, BASE)
    e11 = img.find_entry('ITOC', 0x11)
    if img.section_data(e11)[0x2b3] != 0x07:
        die('base VPI byte 0x11+0x2b3 != 0x07 - anomaly, STOP')
    print('[0] base VPI OK (0x11+0x2b3 = 07)')
    e = img.find_entry('ITOC', 0x03)
    if (e.addr, e.size, e.clcrc) != (SEC_ADDR, SEC_SIZE, 1):
        die('MAIN_CODE header mismatch: %x %x %d' % (e.addr, e.size, e.clcrc))
    print('[1] MAIN_CODE: addr=0x%x size=0x%x clcrc=%d' % (e.addr, e.size, e.clcrc))

    if w32be(buf, RAW_OFF) != BEFORE or w32be(buf, NEXT_OFF) != NEXT_WORD:
        die('site mismatch: %08x/%08x' % (w32be(buf, RAW_OFF), w32be(buf, NEXT_OFF)))
    print('[2] site OK: word@0x%x=%08x next=%08x' % (RAW_OFF, BEFORE, NEXT_WORD))

    if patch_a:
        if not (0 <= dc_a < (SEC_SIZE // 68) * 64):
            die('PATCH A dc 0x%x outside MAIN_CODE code range' % dc_a)
        line_a, within_a = divmod(dc_a, 64)
        raw_a = e.addr + line_a * 68 + within_a
        if within_a + 4 > 64:
            die('PATCH A dc 0x%x crosses clcrc line' % dc_a)
        got_a = w32be(buf, raw_a)
        if got_a != before_a:
            die('PATCH A pre-patch word @raw 0x%x = %08x != %08x - dc->raw '
                'mapping wrong or base not as expected - STOP'
                % (raw_a, got_a, before_a))
        print('[2a] PATCH A pre-patch OK: dc 0x%x -> raw 0x%x word=%08x '
              '(re-derived via ITOC 0x03 + de-frame; RE(c) journal raw 0x311cd4)'
              % (dc_a, raw_a, got_a))

    raw = img.section_data(e)
    line, within = divmod(RAW_OFF - SEC_ADDR, 68)
    dc = line * 64 + within
    print('[3] raw 0x%x -> line %d within %d -> dc 0x%x' % (RAW_OFF, line, within, dc))

    code = decrc(raw)
    tail = raw[(len(code)//64)*68:]
    if clcrc(code, tail) != raw:
        die('round-trip de-clcrc/re-clcrc failed')
    print('[4] round-trip OK (%d lines)' % (len(code)//64))

    if struct.unpack_from('>I', code, dc)[0] != BEFORE:
        die('de-clcrc word mismatch at dc 0x%x' % dc)
    pcode = bytearray(code)
    struct.pack_into('>I', pcode, dc, after)
    if patch_a:
        if struct.unpack_from('>I', code, dc_a)[0] != before_a:
            die('PATCH A de-clcrc word mismatch at dc 0x%x' % dc_a)
        struct.pack_into('>I', pcode, dc_a, after_a)
    pcode = bytes(pcode)
    praw = clcrc(pcode, tail)
    want_lines = sorted(set([line] + ([line_a] if patch_a else [])))
    diff_lines = [i for i in range(len(code)//64) if raw[i*68:(i+1)*68] != praw[i*68:(i+1)*68]]
    if diff_lines != want_lines:
        die('unexpected changed-line set: %s' % diff_lines)
    if patch_a:
        print('[5] patch: changed lines %s only '
              '(dc 0x%x word -> %08x; dc 0x%x word -> %08x)'
              % (want_lines, dc, after, dc_a, after_a))
    else:
        print('[5] patch: changed line %d only (word -> %08x)' % (line, after))

    edits = [(0x03, line*68, praw[line*68:line*68+68])]
    if patch_a:
        edits.append((0x03, line_a*68, praw[line_a*68:line_a*68+68]))
    step1 = mlxfwutil.patch_sections(img, edits)
    errs = mlxfwutil.verify_image(mlxfwutil.Image(step1, 'step1', base=img.base, fmt=img.fmt), deep=True)
    if errs:
        die('verify(deep) failed: %s' % errs)
    print('[6] step1 verify(deep): PASS')

    checks = [
        ('word@0x%x' % RAW_OFF, '%08x' % w32be(step1, RAW_OFF), '%08x' % after),
    ]
    if patch_a:
        checks.append(('word@0x%x' % raw_a,
                       '%08x' % w32be(step1, raw_a), '%08x' % after_a))
    for name, got, want in checks:
        if got != want:
            die('%s = %s != %s' % (name, got, want))
        print('[7] %s = %s OK' % (name, got))

    ent_off3 = img.itoc_off + 32 + e.index * 32
    allowed = set(range(RAW_OFF, RAW_OFF + 4))
    allowed |= {SEC_ADDR + line*68 + 66, SEC_ADDR + line*68 + 67}
    allowed |= set(range(ent_off3 + 0x1a, ent_off3 + 0x20))
    if patch_a:
        allowed |= set(range(raw_a, raw_a + 4))
        allowed |= {SEC_ADDR + line_a*68 + 66, SEC_ADDR + line_a*68 + 67}
    diffs = [i for i in range(len(step1)) if step1[i] != buf[i]]
    stray = [hex(i) for i in diffs if i not in allowed]
    print('[8] byte-diff vs ri: %d bytes, strays: %s' % (len(diffs), stray or 'none'))
    if stray:
        die('stray diff bytes: %s' % stray)

    fd, step1_path = tempfile.mkstemp(prefix='c12analog-step1-', suffix='.bin')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(step1)
        r = subprocess.run(['mstflint', '-i', step1_path, 'verify'], capture_output=True, text=True)
        print('[9] mstflint verify rc=%d' % r.returncode)
        if r.returncode != 0:
            die('mstflint verify failed: %s' % (r.stderr.strip()))
        r = subprocess.run(['mstflint', '-i', step1_path, 'q'], capture_output=True, text=True)
        for l in (r.stdout + r.stderr).splitlines():
            if any(k in l for k in ('Image type', 'FW Version', 'PSID', 'Base GUID', 'Base MAC', 'Device ID')):
                print('    ' + l.strip())
    finally:
        os.unlink(step1_path)

    if not build_id:
        open(out_path, 'wb').write(step1)
        print('DONE %s md5=%s' % (out_path, hashlib.md5(step1).hexdigest()))
        return 0

    final, removed, final_text, e30 = build_id_step(img, step1, build_id)
    fimg = mlxfwutil.Image(final, out_path, base=img.base, fmt=img.fmt)
    e30f = fimg.find_entry('ITOC', 0x30)
    if (e30f.addr, e30f.rel) != (e30.addr, e30.rel):
        die('[10] 0x30 ITOC entry moved: %x/%s -> %x/%s (R2: relocation '
            'forbidden)' % (e30.addr, e30.rel, e30f.addr, e30f.rel))
    if e30f.size > e30.size:
        die('[10] 0x30 new size 0x%x > old size 0x%x' % (e30f.size, e30.size))
    rt = zlib.decompress(fimg.section_data(e30f)).decode('latin1')
    if rt != final_text:
        die('[10] round-trip extract(final) != injected text')
    rlines = rt.split('\n')
    if rlines[rlines.index(BANNER) + 1] != build_id:
        die('[10] build-ID line is not right after banner')
    errs = mlxfwutil.verify_image(fimg, deep=True)
    if errs:
        die('[10] final verify(deep) failed: %s' % errs)
    fd, final_tmp = tempfile.mkstemp(prefix='c12analog-final-', suffix='.bin')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(final)
        r = subprocess.run(['mstflint', '-i', final_tmp, 'verify'], capture_output=True, text=True)
        if r.returncode != 0:
            die('[10] final mstflint verify failed: %s' % (r.stderr.strip()))
    finally:
        os.unlink(final_tmp)
    print('[10] R2 OK: 0x30 addr 0x%x unchanged, size 0x%x -> 0x%x, '
          'round-trip OK, build-ID after banner, final verify(deep) PASS, '
          'final mstflint verify OK' % (e30.addr, e30.size, e30f.size))
    if removed:
        print('[10] trimmed %d ;;-comment line(s):' % len(removed))
        for l in removed:
            print('      - %s' % l)

    allowed11 = set(allowed)
    allowed11 |= set(range(img.sec_abs(e30), img.sec_abs(e30) + e30.size))
    ent_off30 = img.itoc_off + 32 + e30.index * 32
    allowed11 |= set(range(ent_off30, ent_off30 + 32))
    if img.fmt == 'fs4':
        ht = mlxfwutil.HashesTable.from_image(img)
        if ht is not None:
            allowed11 |= set(range(ht.ptr, ht.ptr + len(ht.data)))
    diffs11 = [i for i in range(len(final)) if final[i] != buf[i]]
    stray11 = [hex(i) for i in diffs11 if i not in allowed11]
    print('[11] byte-diff final vs ri: %d bytes, strays: %s'
          % (len(diffs11), stray11 or 'none'))
    if stray11:
        die('stray diff bytes: %s' % stray11)

    if args.regress_diff:
        ref = open(args.regress_diff, 'rb').read()
        if len(ref) != len(final):
            die('[13] regression ref size %d != final size %d'
                % (len(ref), len(final)))
        allowed13 = set(range(raw_a, raw_a + 4))
        allowed13 |= {SEC_ADDR + line_a*68 + 66, SEC_ADDR + line_a*68 + 67}
        allowed13 |= set(range(ent_off3 + 0x1a, ent_off3 + 0x20))
        allowed13 |= set(range(img.sec_abs(e30), img.sec_abs(e30) + e30.size))
        allowed13 |= set(range(ent_off30, ent_off30 + 32))
        diffs13 = [i for i in range(len(final)) if final[i] != ref[i]]
        stray13 = [hex(i) for i in diffs13 if i not in allowed13]
        print('[13] regression diff vs %s: %d bytes, strays: %s'
              % (args.regress_diff, len(diffs13), stray13 or 'none'))
        if stray13:
            die('[13] stray regression-diff bytes: %s' % stray13)

    open(out_path, 'wb').write(final)

    r = subprocess.run(['mstflint', '-i', out_path, 'q'], capture_output=True, text=True)
    if r.returncode != 0:
        die('[12] mstflint -i q failed: %s' % r.stderr.strip())
    i_guid, i_mac = q_identity(r.stdout + r.stderr)
    r = subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15',
                        'root-mellanox', 'mstflint -d %s q' % CARD_BDF],
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        die('[12] card q failed: %s' % r.stderr.strip())
    c_guid, c_mac = q_identity(r.stdout + r.stderr)
    print('[12] image Base GUID %s / MAC %s; card Base GUID %s / MAC %s'
          % (i_guid, i_mac, c_guid, c_mac))
    if (i_guid, i_mac) != (c_guid, c_mac):
        die('[12] Base GUID/MAC image != card - run `mlxfwutil.py guides` + '
            'self-verify, then repeat [6]/[9] (R3)')
    print('[12] R3 OK: image GUID/MAC == card')

    print('DONE %s md5=%s' % (out_path, hashlib.md5(final).hexdigest()))
    return 0

if __name__ == '__main__':
    sys.exit(main())
