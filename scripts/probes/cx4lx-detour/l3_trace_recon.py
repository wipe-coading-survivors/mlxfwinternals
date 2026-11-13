#!/usr/bin/env python3
"""cx4lx-detour L3: RE of the iTrace trace-core on CX-4 Lx FW 14.32 (offline).

Formalizes Part A of the L3 task (spec 2026-10-11-cx4lx-detour-design.md s4):
  [T1] trace-core family decode + gate mechanics (mask/level local RAM w2/w3)
  [T2] stock trace-site pattern (GATE -> bool -> r4=str -> params -> emit)
  [T3] unlock-reader 0xd4c8c hook safety: body self-contained, 36 call sites,
       caller-saved ABI scan (r3/r7..r9 and r10 dead after call), no indirect
  [T4] marker string choice + deadness (no constant loader, no raw word)
  [T5] cave layout v2 (v1 block + 14-word emit stub) with decode-verified
       words; changed clcrc lines {507, 13612, 50990, 50991}
Log: build/cx4lx-detour-l3-recon.log
"""
import struct
import sys
from pathlib import Path

WT = Path(__file__).resolve().parents[3]
BASE = WT / 'refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin'
DCBUF = WT / 'build/cx4lx-detour-l0-main03-dc.bin'
LOG = WT / 'build/cx4lx-detour-l3-recon.log'
BASE_MD5 = '3bd3230b1deae0cf74a08e31d59021d9'
RT = 0x800000
GATE = 0x5f90
EMIT1 = 0x603c
EMITS = {0x603c: 1, 0x6064: 2, 0x6090: 3, 0x6008: 4, 0x6188: 0}
CORE = 0x6124
READER = 0xd4c8c
READER_BODY = [0x2404badc, 0x20850ffe, 0x4a0608fc, 0x00040001,
               0xfca53005, 0xa4000002, 0x00040000, 0xfc00002d]
STR_RT = 0x00ada612
STR_DC = STR_RT - RT
STR_TEXT = b'got an unexpected memory profile value, memory_profile = 0x%x'
PARAM = 0x0bad
CAVE_DC = 0x31cba0
CAVE_END = 0x31cc00
STUB_DC = 0x31cbb8
V1_WORDS = [0x24050000, 0x20a523f0, 0x2406badc, 0x20c60001, 0x6ca03002, 0x95f3accf]


def decrc(data):
    out = bytearray()
    for i in range(len(data) // 68):
        out += data[i*68:i*68+64]
    return bytes(out)


def s16(v):
    v &= 0xffff
    return v - 0x10000 if v & 0x8000 else v


def s24(v):
    v &= 0xffffff
    return v - 0x1000000 if v & 0x800000 else v


def call(pc, tgt):
    return 0x94000000 | (((tgt - pc) // 4) & 0xffffff)


def jump(pc, tgt):
    return 0x95000000 | (((tgt - pc) // 4) & 0xffffff)


def stub_words():
    lo = STR_RT & 0xffff
    hi = (STR_RT >> 16) + (1 if lo & 0x8000 else 0)
    w = [0x480a00bc,
         0x00040000 | lo,
         0x08840000 | hi,
         0x00050000 | PARAM]
    w.append(call(STUB_DC + 16, EMIT1))
    w.append(0x4d4000bc)
    w += READER_BODY
    return w


class Out:
    def __init__(self):
        self.lines = []

    def __call__(self, s=''):
        self.lines.append(s)
        print(s)


def main():
    sys.path.insert(0, str(WT))
    sys.path.insert(0, str(WT / 'scripts/irisc'))
    import hashlib
    import re
    import mlxfwutil
    import irisc_dis

    o = Out()

    def fail(msg):
        o('FATAL: ' + msg)
        open(LOG, 'w').write('\n'.join(o.lines) + '\n')
        sys.exit(1)

    buf = BASE.read_bytes()
    if hashlib.md5(buf).hexdigest() != BASE_MD5:
        fail('base md5 mismatch')
    img = mlxfwutil.Image(buf, str(BASE))
    e = img.find_entry('ITOC', 0x03)
    code = DCBUF.read_bytes()
    if code != decrc(img.section_data(e)):
        fail('dc buffer != de-clcrc(section)')
    n = len(code) // 4
    words = struct.unpack('>%dI' % n, code)

    def dw(off):
        return words[off // 4]

    def dis(off):
        return irisc_dis.dis(dw(off), off)

    def dis_range(lo, hi, tag):
        o('--- %s [0x%x..0x%x)' % (tag, lo, hi))
        for off in range(lo, hi, 4):
            o('  %08x  %08x  %s' % (off, dw(off), dis(off)))

    o('[T0] base md5 OK; dc %d words' % n)

    # T1: gate + emit family + core
    dis_range(GATE, GATE + 0x74, 'GATE 0x5f90 (r4=class, r5=level -> r4 bool)')
    checks = [
        (0x5fa4, 'subsi r7,r5,0x1', 'gate: level>1 test'),
        (0x5fa8, 'b.t.0x1 zero,0x5fbc', 'gate: L>=2 mask bypass'),
        (0x5fac, 'ld.i r6,0x2', 'gate: mask = local RAM word 2'),
        (0x5fc0, 'ld.i r4,0x3', 'gate: stored level = local RAM word 3'),
        (0x5fcc, 'ands r6,r4,0xff', 'gate: stored level = byte0 of word 3'),
        (0x5fd4, 'b.t.0x2 zero,0x5ff4', 'gate: borrow reject (level<stored)'),
        (0x5ff4, 'or r4,r23,r23', 'gate: return bool in r4'),
    ]
    for off, want, why in checks:
        if dis(off) != want:
            fail('gate decode %s: "%s" != "%s"' % (why, dis(off), want))
    o('[T1] GATE key words verified: mask=w2, level=w3, L>=2 bypass, bool->r4')

    for addr, npar in sorted(EMITS.items()):
        lo = addr
        hi = addr + 0x30
        o('--- emit%d 0x%x' % (npar, addr))
        for off in range(lo, hi, 4):
            o('  %08x  %08x  %s' % (off, dw(off), dis(off)))
            if dis(off).startswith('ret.r'):
                break
        prologue_ok = dis(addr) == 'csr.r r3,csr0xbc'
        cnt = None
        for off in range(addr, addr + 0x30, 4):
            d = dis(off)
            if d.startswith('addi r5,zero,'):
                cnt = int(d.split(',')[2], 0)
            if d.startswith('call 0x6124'):
                if not prologue_ok or cnt != npar:
                    fail('emit%d @0x%x convention broken (cnt=%s)' % (npar, addr, cnt))
                o('[T1] emit%d @0x%x: r4=str passthrough, %d param(s), call CORE 0x6124' % (npar, addr, npar))
                break
    dis_range(CORE, CORE + 0x60, 'CORE writer 0x6124')
    for off, want, why in [
            (CORE, 'csr.r r7,csr0x8', 'core: read trace write-pointer CSR'),
            (CORE + 0x34, 'csr.w r8,zero,0x8', 'core: write pointer CSR'),
            (CORE + 0x4c, 'csr.w r9,zero,0xc', 'core: write data CSR'),
            (CORE + 0x38, 'subsi r9,r7,0x0', 'core: i==0 -> first word is r4 (string)')]:
        if dis(off) != want:
            fail('core decode %s: "%s" != "%s"' % (why, dis(off), want))
    o('[T1] CORE: record = [r4 str, params...]; NO class/level in record -> direct emit bypasses mask/level entirely')

    # T2: stock site pattern at init_ib_an_fsm
    dis_range(0x1b9d74, 0x1b9da8, 'stock site: init_ib_an_fsm trace')
    pat = [(0x1b9d74, 'addi r4,zero,0x40', 'class = 0x40 PHY_IB'),
           (0x1b9d78, 'addi r5,zero,0x1', 'level 1'),
           (0x1b9d7c, 'call 0x5f90', 'gate call'),
           (0x1b9d94, 'addi r4,zero,0x-33aa', 'str lo'),
           (0x1b9d98, 'addi.hi r4,r4,0xaf', 'str hi -> rt 0xaecc56'),
           (0x1b9da4, 'call 0x6008', 'emit4 call')]
    for off, want, why in pat:
        if dis(off) != want:
            fail('site pattern %s: "%s" != "%s"' % (why, dis(off), want))
    o('[T2] stock site pattern verified (GATE -> bool -> r4=str via addi/addi.hi -> params r5.. -> emitN)')

    # T3: reader hook safety
    dis_range(READER - 4, READER + 0x24, 'unlock-reader 0xd4c8c (flash write-protect check)')
    body = [dw(READER + 4 * i) for i in range(8)]
    if body != READER_BODY:
        fail('reader body words changed')
    calls = [i * 4 for i in range(n) if (dw(i * 4) >> 26) == 0x25
             and i * 4 + s24(dw(i * 4)) * 4 == READER]
    o('[T3] reader body verified (8 words, ret.d leaf); %d direct call sites' % len(calls))
    if len(calls) != 36:
        fail('expected 36 call sites, got %d' % len(calls))
    ind = []
    for i in range(n):
        d = irisc_dis.dis(dw(i * 4), i * 4)
        if (d.startswith('jump 0xd4c8c') or d.startswith('jump 0xd4c90')
                or d.startswith('call 0xd4c90')):
            ind.append((hex(i * 4), d))
    if ind:
        fail('indirect branch into reader entry/word1: %s' % ind)
    for val in (READER, READER + RT):
        if struct.pack('>I', val) in code:
            fail('raw pointer 0x%x found in image' % val)
    o('[T3] no jumps to reader word0/word1, no raw dc/rt pointers -> only the 36 call sites reach it')

    RW = re.compile(r'\b(r\d+)\b')
    WR_OPS = ('addi', 'addi.hi', 'set2', 'set3', 'or', 'subs', 'subsi', 'ands',
              'and', 'shr', 'shl', 'ld.i', 'ld.d', 'ld.w', 'lw.r', 'mask32',
              'alu', 'op', 'add')
    for r in (3, 7, 8, 9, 10):
        bad = []
        for s in calls:
            off = s + 4
            end = min(s + 4 + 0x200, n * 4)
            while off < end:
                d = irisc_dis.dis(dw(off), off)
                if d.startswith('ret'):
                    break
                rs = [int(x[1:]) for x in RW.findall(d)]
                if r in rs:
                    tok = d.split()[0]
                    if not (tok in WR_OPS and rs[0] == r):
                        bad.append((hex(s), hex(off), d))
                    break
                off += 4
        if bad:
            fail('r%d read-before-write after reader call at %s' % (r, bad[:2]))
        o('[T3] r%d: dead (write-first) after call at all %d sites' % (r, len(calls)))
    o('[T3] emit clobber set {r3,r5..r9} + link-save reg r10 all caller-saved-dead -> hook safe')

    # T4: marker string
    raw = code[STR_DC:STR_DC + len(STR_TEXT) + 1]
    if raw != STR_TEXT + b'\x00':
        fail('marker string bytes mismatch: %r' % raw[:60])
    loaded = set()
    for i in range(n - 1):
        d0 = irisc_dis.dis(dw(i * 4), i * 4)
        d1 = irisc_dis.dis(dw((i + 1) * 4), (i + 1) * 4)
        if d0.startswith('addi r') and ',zero,' in d0 and d1.startswith('addi.hi r'):
            r0 = d0.split()[1].split(',')[0]
            r1 = d1.split()[1].split(',')[0]
            if r0 == r1:
                try:
                    lo = int(d0.split(',zero,')[1].replace('0x', ''), 16) & 0xffff
                    hi = int(d1.split(',')[2].replace('0x', ''), 16) & 0xffff
                except ValueError:
                    continue
                loaded.add((s16(lo) + (hi << 16)) & 0xffffffff)
    if STR_RT in loaded:
        fail('marker rt loaded somewhere in MAIN_CODE')
    if struct.pack('>I', STR_RT) in code:
        fail('marker rt appears as raw data word')
    o('[T4] marker string @rt 0x%08x (dc 0x%x) bytes OK; DEAD: 0 constant loaders, 0 raw words; param=0x%x'
      % (STR_RT, STR_DC, PARAM))

    # T5: cave layout v2
    sw = stub_words()
    if len(V1_WORDS) + len(sw) > 24:
        fail('cave overflow: %d words' % (len(V1_WORDS) + len(sw)))
    want_dis = ['csr.r r10,csr0xbc',
                'addi r4,zero,0x-59ee', 'addi.hi r4,r4,0xae', 'addi r5,zero,0xbad',
                'call 0x603c', 'csr.w r10,zero,0xbc',
                'set2 r4,zero,0xbadc', 'set3 r5,r4,0xffe', 'ld.i r6,0x8fc',
                'addi r4,zero,0x1', 'subs r5,r5,r6', 'b.f.0x0 zero,0x31cbec',
                'addi r4,zero,0x0', 'ret.d zero,zero,zero']
    o('--- v2 stub @0x%x (%d words)' % (STUB_DC, len(sw)))
    for i, (w, want) in enumerate(zip(sw, want_dis)):
        d = irisc_dis.dis(w, STUB_DC + 4 * i)
        o('  %08x  %08x  %s' % (STUB_DC + 4 * i, w, d))
        if d != want:
            fail('stub word %d decode "%s" != "%s"' % (i, d, want))
    # string-pair value check: s16(lo) + hi<<16 == STR_RT
    lo = sw[1] & 0xffff
    if (s16(lo) + ((sw[2] & 0xffff) << 16)) & 0xffffffff != STR_RT:
        fail('string addi/addi.hi pair does not compose to rt 0x%08x' % STR_RT)
    patch = jump(READER, STUB_DC)
    pd = irisc_dis.dis(patch, READER)
    if pd != 'jump 0x31cbb8':
        fail('patch word decode "%s"' % pd)
    o('[T5] stub decodes 1:1 (14 words, ends 0x%x <= cave end 0x%x); pair composes to rt; patch word %08x @0x%x = %s'
      % (STUB_DC + 4 * len(sw), CAVE_END, patch, READER, pd))
    lines = sorted({0x7ee4 // 64, READER // 64, CAVE_DC // 64, (CAVE_END - 4) // 64})
    o('[T5] changed clcrc lines: %s (507 injection, %d reader-word0, 50990/50991 cave)' % (lines, READER // 64))

    open(LOG, 'w').write('\n'.join(o.lines) + '\n')
    o('DONE log=%s' % LOG)


if __name__ == '__main__':
    main()
