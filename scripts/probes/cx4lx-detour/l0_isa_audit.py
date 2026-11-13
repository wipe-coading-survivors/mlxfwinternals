#!/usr/bin/env python3
"""cx4lx-detour L0: ISA control audit of CX-4 Lx 14.32 MAIN_CODE vs the
CX-5 16.35.4030 baseline (roadmap-irisc Phase I0 / journal 2026-09-23).

Gates and outputs:
  [1] base image md5
  [2] MAIN_CODE ITOC 0x03 header (index/addr/size/clcrc, param0/param1)
  [3] de-clcrc (64+2+2 lines) + byte-identical re-clcrc round-trip
  [4] full canonical decode (scripts/irisc/irisc_dis.py) -> op histogram
  [5] code-vs-data classifier (recount 2026-09-23 method, verbatim rules)
      + anchors + cross-check + clean mask/strict/data histogram
  [6] 4030 baseline comparison (counts, per-100k-code-word rates, op sets)
  [7] golden encode->decode round-trip (scripts/irisc/enc.py -> irisc_dis)
"""
import collections
import hashlib
import struct
import sys
from pathlib import Path

WT = Path(__file__).resolve().parents[3]
BASE = WT / 'refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin'
RAW = WT / 'build/cx4lx-detour-l0-main03-raw.bin'
DC = WT / 'build/cx4lx-detour-l0-main03-dc.bin'
BASE_MD5 = '3bd3230b1deae0cf74a08e31d59021d9'
SEC_TYPE = 0x03
SEC_INDEX = 18
SEC_ADDR = 0x16d000
SEC_SIZE = 0x34e8c0
RUNTIME_BASE = 0x800000

B4030_MASK = {0x36: 3774, 0x0d: 3393, 0x33: 2115, 0x34: 1492, 0x16: 65,
              0x1d: 32, 0x38: 28, 0x22: 15, 0x39: 10, 0x3c: 11, 0x20: 6,
              0x3a: 6, 0x2d: 4, 0x24: 5, 0x15: 4, 0x21: 3, 0x23: 3,
              0x14: 3, 0x1f: 3, 0x31: 3, 0x0f: 2, 0x3b: 2}
B4030_STRICT = {0x36: 3767, 0x0d: 2386, 0x33: 1646, 0x34: 1084, 0x16: 40,
                0x1d: 18, 0x38: 25, 0x22: 13, 0x39: 7, 0x3c: 5, 0x20: 4,
                0x3a: 3, 0x2d: 1, 0x3b: 1}
B4030_NOISE = {0x0f, 0x10, 0x11, 0x14, 0x15, 0x1f, 0x21, 0x23, 0x24, 0x26,
               0x27, 0x2c, 0x2e, 0x2f, 0x30, 0x31, 0x35, 0x37, 0x3d, 0x3e}
B4030_WORDS = 941936
B4030_CODE_WORDS = 856480
B4030_MASK_TOTAL = 10995
B4030_STRICT_TOTAL = 9000

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


PRINTABLE = set(range(0x20, 0x7f)) | {0x09, 0x0a, 0x0d}
W = 64
S = 8
TH_ZERO = 0.25
TH_ASCII = 0.30
TH_KNOWN = 0.62
TH_MONO = 0.85
TH_ANCH = 2


def word_features(w):
    op = w >> 26
    rs = (w >> 21) & 0x1f
    rd = (w >> 16) & 0x1f
    b = (w & 0xff, (w >> 8) & 0xff, (w >> 16) & 0xff, (w >> 24) & 0xff)
    is_zero = (w == 0)
    is_str = all(x in PRINTABLE or x == 0 for x in b) and sum(x in PRINTABLE for x in b) >= 3
    is_cf = op in (0x25, 0x28, 0x29, 0x2a, 0x2b)
    is_call = (op == 0x25 and ((w >> 24) & 1) == 0)
    is_ret = (op == 0x3f and (w & 0x1ff) in (0x25, 0x2d))
    is_plg = (op == 0x12 and ((w >> 25) & 1) == 0 and (w & 0x7ff) == 0xbc and rd != 0)
    is_epl = (op == 0x13 and (w & 0x7ff) == 0xbc)
    is_frm = (op == 0x1c and rs == 1)
    return op, is_zero, is_str, is_cf, is_call, is_ret, is_plg, is_epl, is_frm


def cf_target(w, off):
    op = w >> 26
    if op == 0x25:
        o = w & 0xffffff
        if o & 0x800000:
            o -= 0x1000000
    else:
        o = w & 0xffff
        if o & 0x8000:
            o -= 0x10000
    return off + o * 4


def main():
    sys.path.insert(0, str(WT))
    sys.path.insert(0, str(WT / 'scripts/irisc'))
    import mlxfwutil
    import irisc_dis
    import enc

    buf = BASE.read_bytes()
    md5 = hashlib.md5(buf).hexdigest()
    print('[1] base md5=%s size=%d' % (md5, len(buf)))
    if md5 != BASE_MD5:
        die('base md5 mismatch')

    img = mlxfwutil.Image(buf, str(BASE))
    e = img.find_entry('ITOC', SEC_TYPE)
    print('[2] MAIN_CODE: type=0x%02x index=%d addr=0x%x size=0x%x clcrc=%d param0=0x%x param1=0x%x' % (
        e.type, e.index, e.addr, e.size, e.clcrc, e.param0, e.param1))
    if (e.index, e.addr, e.size, e.clcrc) != (SEC_INDEX, SEC_ADDR, SEC_SIZE, 1):
        die('MAIN_CODE header mismatch')

    raw = RAW.read_bytes()
    sec = img.section_data(e)
    if raw != sec:
        die('CLI extract raw != img.section_data (%d vs %d bytes)' % (len(raw), len(sec)))
    code = decrc(raw)
    tail = raw[(len(code)//64)*68:]
    rt = clcrc(code, tail)
    if rt != raw:
        die('round-trip de-clcrc/re-clcrc failed')
    print('[3] round-trip OK: raw=%d B (%d lines + tail %d B) -> dc=%d B; raw==section_data OK' % (
        len(raw), len(code)//64, len(tail), len(code)))
    if len(code) % 4:
        die('dc buffer not word aligned')
    DC.write_bytes(code)

    n = len(code) // 4
    words = struct.unpack_from('>%dI' % n, code, 0)
    feat = [word_features(w) for w in words]
    ops = [f[0] for f in feat]
    unknown = [irisc_dis.dis(w, i*4).startswith('op0x') for i, w in enumerate(words)]
    hist_all = collections.Counter(op for op, u in zip(ops, unknown) if u)
    total_unknown = sum(hist_all.values())
    print('[4] full decode: %d words; unknown-op words %d (%.2f%% of file)' % (
        n, total_unknown, 100.0*total_unknown/n))
    print('    zero words: %d' % sum(1 for w in words if w == 0))

    known = [0 if u else 1 for u in unknown]
    zero = [1 if f[1] else 0 for f in feat]
    astr = [1 if f[2] else 0 for f in feat]
    anch = [1 if (f[4] or f[5] or f[6] or f[7] or f[8]) else 0 for f in feat]
    functs = [(w & 0x1ff) if (w >> 26) == 0x3f else None for w in words]
    votes = [0]*n
    cover = [0]*n
    for start in range(0, n-W+1, S):
        sl = slice(start, start+W)
        kf = sum(known[sl])/W
        zf = sum(zero[sl])/W
        af = sum(astr[sl])/W
        na = sum(anch[sl])
        oc = collections.Counter(ops[sl])
        top_op, top_cnt = oc.most_common(1)[0]
        mono = top_cnt/W >= TH_MONO
        if mono and top_op == 0x3f:
            fs = set(f for f in functs[sl] if f is not None)
            mono = len(fs) <= 3
        is_code = not (zf >= TH_ZERO or af >= TH_ASCII
                       or (mono and na < TH_ANCH)
                       or (kf < TH_KNOWN and na < TH_ANCH))
        for i in range(start, start+W):
            cover[i] += 1
            if is_code:
                votes[i] += 1
    codemask = [votes[i]*2 >= cover[i] for i in range(n)]
    ncode = sum(codemask)
    print('[5] classifier: code words %d / %d (%.1f%%), data %d (%.1f%%)' % (
        ncode, n, 100.0*ncode/n, n-ncode, 100.0*(n-ncode)/n))

    code_anchors = [
        (0x1b88c0, 0x24, 'AN-FSM chosen-mask block (live, cx4lx-an task-03 9.1)'),
        (0x1b9d50, 0x200, 'init_ib_an_fsm region (cx4lx-an)'),
    ]
    if e.param0 == RUNTIME_BASE:
        entry_dc = e.param1 - RUNTIME_BASE
        if 0 <= entry_dc < len(code):
            code_anchors.append((entry_dc, 0x20, 'ITOC entry dc (param1-0x800000)'))
            print('    entry decode preview (L1 input):')
            for i in range(entry_dc//4, entry_dc//4+6):
                print('      %08x  %08x  %s' % (i*4, words[i], irisc_dis.dis(words[i], i*4)))
    for off, ln, name in code_anchors:
        i0, i1 = off//4, (off+ln)//4
        frac = sum(codemask[i0:i1])/max(1, i1-i0)
        print('    CODE? %#08x+%#06x %-48s code_frac=%.3f %s' % (
            off, ln, name, frac, 'PASS' if frac >= 0.95 else 'FAIL'))

    zruns = []
    i = 0
    while i < n:
        if words[i] == 0:
            j = i
            while j < n and words[j] == 0:
                j += 1
            if (j-i)*4 >= 256:
                zruns.append((i*4, (j-i)*4))
            i = j
        else:
            i += 1
    zruns.sort(key=lambda t: -t[1])
    for off, ln in zruns[:3]:
        i0, i1 = off//4, (off+ln)//4
        frac = sum(codemask[i0:i1])/max(1, i1-i0)
        print('    DATA? %#08x+%#06x %-48s code_frac=%.3f %s' % (
            off, ln, 'zero run', frac, 'PASS' if frac <= 0.05 else 'FAIL'))
    aruns = []
    i = 0
    while i < len(code):
        if code[i] in PRINTABLE:
            j = i
            while j < len(code) and code[j] in PRINTABLE:
                j += 1
            if j-i >= 64:
                aruns.append((i, j-i))
            i = j
        else:
            i += 1
    aruns.sort(key=lambda t: -t[1])
    for off, ln in aruns[:3]:
        i0, i1 = off//4, (off+ln)//4
        frac = sum(codemask[i0:i1])/max(1, i1-i0)
        print('    DATA? %#08x+%#06x "%-40s" code_frac=%.3f %s' % (
            off, ln, code[off:off+24].decode('ascii', 'replace'), frac,
            'PASS' if frac <= 0.05 else 'FAIL'))

    tot = 0
    in_code = 0
    out_file = 0
    for i, w in enumerate(words):
        if not codemask[i]:
            continue
        op = w >> 26
        if op in (0x25, 0x28, 0x29, 0x2a, 0x2b):
            t = cf_target(w, i*4)
            tot += 1
            if not (0 <= t < len(code)):
                out_file += 1
            elif codemask[t//4]:
                in_code += 1
    print('    cross-check: cf insns in code %d; targets in code %d (%.1f%%); out-of-file %d' % (
        tot, in_code, 100.0*in_code/max(1, tot), out_file))

    mask_h = collections.Counter()
    data_h = collections.Counter()
    strict_h = collections.Counter()
    lo_hi = 8
    for i in range(n):
        op = ops[i]
        if not unknown[i]:
            continue
        if codemask[i]:
            mask_h[op] += 1
        else:
            data_h[op] += 1
    for i in range(n):
        op = ops[i]
        if not unknown[i] or not codemask[i]:
            continue
        i0 = max(0, i-lo_hi)
        i1 = min(n, i+lo_hi+1)
        win = range(i0, i1)
        lk = sum(known[j] for j in win if j != i)/max(1, (i1-i0-1))
        br = any(feat[j][3] for j in win)
        ptrs = sum(1 for j in win if RUNTIME_BASE <= words[j] < RUNTIME_BASE + len(code))
        pdense = ptrs/max(1, i1-i0) >= 0.25
        if lk >= 0.75 and br and not pdense:
            strict_h[op] += 1
    print('[6] clean histogram (unknown ops): op | mask | strict | data | 4030 mask | 4030 strict')
    all_ops = sorted(set(mask_h) | set(data_h) | set(B4030_MASK))
    for op in all_ops:
        b4030_cls = 'NOISE' if op in B4030_NOISE else ''
        print('    0x%02x  %-7d %-7d %-7d %-9d %-9d %s' % (
            op, mask_h.get(op, 0), strict_h.get(op, 0), data_h.get(op, 0),
            B4030_MASK.get(op, 0), B4030_STRICT.get(op, 0), b4030_cls))
    mask_total = sum(mask_h.values())
    strict_total = sum(strict_h.values())
    print('    totals: mask %d, strict %d, data %d (file total unknown %d)' % (
        mask_total, strict_total, sum(data_h.values()), total_unknown))
    print('    share of unknown in code: mask %.2f%% / strict %.2f%% of code words; 4030: mask %.2f%% (10995/856480)' % (
        100.0*mask_total/ncode, 100.0*strict_total/ncode, 100.0*B4030_MASK_TOTAL/B4030_CODE_WORDS))
    r14 = {op: 1e5*mask_h.get(op, 0)/ncode for op in mask_h}
    r40 = {op: 1e5*B4030_MASK.get(op, 0)/B4030_CODE_WORDS for op in B4030_MASK}
    print('    rates per 100k code words (14.32 vs 4030), top-10 by 14.32 mask:')
    for op, c in mask_h.most_common(10):
        print('      0x%02x  %8.1f  vs  %8.1f  (ratio %.2f)' % (op, r14[op], r40.get(op, 0.0), r14[op]/r40[op] if r40.get(op) else float('inf')))
    new_ops = sorted(set(mask_h) - set(B4030_MASK))
    gone_ops = sorted(set(B4030_MASK) - set(mask_h) - set(B4030_NOISE))
    print('    ops with mask>0 on 14.32 absent from 4030 mask table: %s' % (
        ' '.join('0x%02x' % o for o in new_ops) or '(none)'))
    print('    non-noise 4030 ops with mask=0 on 14.32: %s' % (
        ' '.join('0x%02x' % o for o in gone_ops) or '(none)'))

    golden = [
        ('set2 r5 lo (docs/250-re/120-irisc/025-boot-injection.md)', enc.set2(5, 0x0000), 0x24050000, 0x38d730, 'set2 r5,zero,0x0'),
        ('set3 r5 hi (docs/250-re/120-irisc/025-boot-injection.md)', enc.set3(5, 5, 0x23f0), 0x20a523f0, 0x38d734, 'set3 r5,r5,0x23f0'),
        ('set2 r6 hi (docs/250-re/120-irisc/025-boot-injection.md)', enc.set2(6, 0xbadc), 0x2406badc, 0x38d738, 'set2 r6,zero,0xbadc'),
        ('set3 r6 lo (docs/250-re/120-irisc/025-boot-injection.md)', enc.set3(6, 6, 0x0001), 0x20c60001, 0x38d73c, 'set3 r6,r6,0x1'),
        ('st.d marker (docs/250-re/120-irisc/025-boot-injection.md)', enc.st_d(6, 5, 0), 0x6ca03002, 0x38d740, 'st.d r6,r5,0x0'),
        ('jump resume (docs/250-re/120-irisc/025-boot-injection.md)', enc.jump(0x38d744, 0x1e10c), 0x95f24272, 0x38d744, 'jump 0x1e10c'),
        ('call detour (docs/250-re/120-irisc/025-boot-injection.md)', enc.call(0x1d594, 0x38d730), 0x940dc067, 0x1d594, 'call 0x38d730'),
        ('addi live 14.32 (task-03 9.2)', enc.addi(5, 0, 0xf), 0x0005000f, 0x1b88c8, 'addi r5,zero,0xf'),
        ('set3 live 14.32 (task-03 9.2)', enc.set3(5, 4, 0xf), 0x2085000f, 0x1b88d0, 'set3 r5,r4,0xf'),
        ('b.t live 14.32 (task-03 9.2)', enc.b_t(0x0a, 0x1b88cc, 0x1b88d4), 0xa00a0002, 0x1b88cc, 'b.t.0xa zero,0x1b88d4'),
        ('b.f live 14.32 (task-03 9.2)', enc.b_f(0x0a, 0x1b88cc, 0x1b88d4), 0xa40a0002, 0x1b88cc, 'b.f.0xa zero,0x1b88d4'),
    ]
    npass = 0
    print('[7] golden encode->decode round-trip:')
    for name, w, ref, pc, want in golden:
        d = irisc_dis.dis(w, pc)
        ok_ref = (ref is None or w == ref)
        ok_dis = (d == want)
        if ok_ref and ok_dis:
            npass += 1
        print('    %-32s %08x  ref=%s  dis="%s"  %s%s' % (
            name, w, 'OK' if ok_ref else 'MISMATCH', d,
            'PASS' if (ok_ref and ok_dis) else 'FAIL',
            '' if ok_dis else ' (want "%s")' % want))
    if npass != len(golden):
        die('golden round-trip %d/%d' % (npass, len(golden)))
    print('GOLDEN ROUND-TRIP: %d/%d PASS' % (npass, len(golden)))
    print('DONE')


if __name__ == '__main__':
    main()
