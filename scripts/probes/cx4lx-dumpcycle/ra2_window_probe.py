#!/usr/bin/env python3
"""R-A2 (phase IX): CR-window VSEC probe for CX-4 Lx — mapped-scan + write-probe.

Card: bazzite 04:00.0 (MCX4131A, FW 14.32.1900, PSID MT_2430110032), image an5.

Mechanism (docs/250-re/120-irisc/025-boot-injection.md, pc3_probe.py precedent, crates/mlxscope vsec.rs):
  - VSEC standard cap 0x09 walked from config 0x34.
  - CTRL  base+0x04 = 0x20000002 selects CR space (space=2 in low16, keep 0x2000 hi).
  - Semaphore base+0x0c / counter base+0x08: ticket take, release by writing 0 —
    held around every data-port access (vsec.rs discipline).
  - Read:  ADDR base+0x10 = off, poll bit31 -> 1, DATA base+0x14.
  - Write: DATA base+0x14 = value, ADDR = off | bit31, poll bit31 -> 0.

Verdict rule: unmapped slot reads back off/4 (word index). A mapped word could
coincidentally equal its index: "stable across sweeps AND == index" is reported
as UNMAPPED-SUSPECT, never silently counted as mapped.

HYGIENE: write mode refuses every offset outside
  reserve 0x2314..0x23e4 / inline 0x2014..0x2310
and always restores the pre-probe value. Never touches 0x2000..0x2010,
0x23e8/0x23ec, 0x23f4, 0x23f8, 0x23fc.
"""
import argparse
import os
import struct
import sys
import time

DEV = '/sys/bus/pci/devices/0000:04:00.0/config'
CTRL_SPACE_CR = 0x20000002
POLL_LIMIT = 20000

RESERVE_FIRST, RESERVE_LAST = 0x2314, 0x23e4      # words 0x8c5..0x8f9 (53)
INLINE_FIRST, INLINE_LAST = 0x2014, 0x2310        # words 0x805..0x8c4
NEVER_WRITE = set(range(0x2000, 0x2011)) | {0x23e8, 0x23ec, 0x23f4, 0x23f8, 0x23fc}


class Vsec:
    def __init__(self, dev=DEV):
        self.fd = os.open(dev, os.O_RDWR)
        self.base = self._find_vsec()
        self.ctrl = self.base + 0x04
        self.counter = self.base + 0x08
        self.sem = self.base + 0x0c
        self.addr = self.base + 0x10
        self.data = self.base + 0x14

    def r32(self, off):
        os.lseek(self.fd, off, os.SEEK_SET)
        return struct.unpack('<I', os.read(self.fd, 4))[0]

    def w32(self, off, val):
        os.lseek(self.fd, off, os.SEEK_SET)
        os.write(self.fd, struct.pack('<I', val))

    def r8(self, off):
        os.lseek(self.fd, off, os.SEEK_SET)
        return os.read(self.fd, 1)[0]

    def _find_vsec(self) -> int:
        ptr = self.r8(0x34)
        seen = 0
        while ptr and 0x40 <= ptr < 0x1000 and seen < 64:
            if (self.r32(ptr) & 0xff) == 0x09:
                return ptr
            ptr = (self.r32(ptr) >> 8) & 0xff
            seen += 1
        raise RuntimeError('VSEC cap 0x09 not found')

    def baseline(self):
        return tuple(self.r32(a) for a in
                     (self.ctrl, self.counter, self.sem, self.addr, self.data))

    def sem_take(self):
        for _ in range(1024):
            s = self.r32(self.sem)
            if s != 0:
                time.sleep(0.001)
                continue
            c = self.r32(self.counter)
            self.w32(self.sem, c)
            if self.r32(self.sem) == c:
                return
        raise RuntimeError('vsec semaphore busy')

    def sem_release(self):
        self.w32(self.sem, 0)

    def set_cr_space(self):
        self.sem_take()
        try:
            self.w32(self.ctrl, CTRL_SPACE_CR)
            ctrl = self.r32(self.ctrl)
            if (ctrl >> 29) & 0x7 == 0:
                raise RuntimeError('CR space not supported (ctrl=0x%08x)' % ctrl)
        finally:
            self.sem_release()

    def restore_ctrl(self, value):
        self.w32(self.ctrl, value)

    def read_cr(self, off):
        self.sem_take()
        try:
            self.w32(self.addr, off & 0x3fffffff)
            polls = 0
            while True:
                a = self.r32(self.addr)
                if a & 0x80000000:
                    break
                polls += 1
                if polls > POLL_LIMIT:
                    raise RuntimeError('read poll timeout @0x%x' % off)
            return self.r32(self.data)
        finally:
            self.sem_release()

    def write_cr(self, off, val):
        self.sem_take()
        try:
            self.w32(self.data, val)
            self.w32(self.addr, (off & 0x3fffffff) | 0x80000000)
            polls = 0
            while True:
                a = self.r32(self.addr)
                if not (a & 0x80000000):
                    break
                polls += 1
                if polls > POLL_LIMIT:
                    raise RuntimeError('write poll timeout @0x%x' % off)
        finally:
            self.sem_release()


def word_list():
    words = list(range(RESERVE_FIRST // 4, RESERVE_LAST // 4 + 1))
    words += [0x223f0 // 4, 0x23f0 // 4]          # unmapped/mapped controls
    words += [0x23e8 // 4, 0x23ec // 4, 0x23f4 // 4, 0x23f8 // 4, 0x23fc // 4]
    return sorted(set(words))


def cmd_scan(v, args):
    words = word_list()
    sweeps = []
    t0 = time.monotonic()
    for s in range(args.sweeps):
        row = {}
        for w in words:
            row[w] = v.read_cr(4 * w)
        sweeps.append(row)
        print('sweep %d: %d reads in %.2fs' % (s + 1, len(words), time.monotonic() - t0))
        if s + 1 < args.sweeps:
            time.sleep(args.gap_s)
    print()
    print('== word  CR-off   ' + '  '.join('s%d        ' % (i + 1) for i in range(len(sweeps))) + 'verdict ==')
    reserve_words = set(range(RESERVE_FIRST // 4, RESERVE_LAST // 4 + 1))
    verdicts = {}
    for w in words:
        vals = [sw[w] for sw in sweeps]
        uniq = set(vals)
        if len(uniq) > 1:
            verdict = 'MAPPED-live'          # value mutates: live register
        elif vals[0] != w:
            verdict = 'MAPPED-stable'        # stable, off default
        else:
            verdict = 'UNMAPPED-SUSPECT' if w in reserve_words else 'UNMAPPED'
        verdicts[w] = verdict
        print('0x%04x  0x%04x  %s  %s' % (
            w, 4 * w,
            '  '.join('%08x' % x for x in vals),
            verdict))
    print()
    ms = sorted(w for w in reserve_words
                if verdicts.get(w, '').startswith('MAPPED'))
    runs = []
    prev = 0
    for w in ms:
        if not runs or w != prev + 1:
            runs.append([w, w])
        else:
            runs[-1][1] = w
        prev = w
    print('== reserve mapped runs (>=8 contiguous words => D-channel B) ==')
    if not runs:
        print('(none)')
    for a, b in runs:
        print('words 0x%04x-0x%04x  CR 0x%04x-0x%04x  len=%d' % (a, b, 4 * a, 4 * b, b - a + 1))
    best = max((b - a + 1 for a, b in runs), default=0)
    print('mapped total=%d/%d  max contiguous run=%d' % (len(ms), len(reserve_words), best))


def write_allowed(off):
    in_reserve = RESERVE_FIRST <= off <= RESERVE_LAST
    in_inline = INLINE_FIRST <= off <= INLINE_LAST
    return (in_reserve or in_inline) and off not in NEVER_WRITE


def cmd_write(v, args):
    off = args.offset
    if not write_allowed(off):
        print('REFUSED: offset 0x%04x outside allowlist (reserve 0x2314..0x23e4 / '
              'inline 0x2014..0x2310) or in never-write set' % off)
        sys.exit(2)
    pre = v.read_cr(off)
    print('pre     0x%04x = 0x%08x' % (off, pre))
    v.write_cr(off, args.value)
    print('write   0x%04x <- 0x%08x' % (off, args.value))
    rb = v.read_cr(off)
    print('readback 0x%04x = 0x%08x  %s' % (off, rb,
          'MATCH' if rb == args.value else 'MISMATCH (write no-op or filtered)'))
    for i in range(args.recheck):
        time.sleep(args.recheck_ms / 1000.0)
        rv = v.read_cr(off)
        print('recheck %d (%d ms): 0x%04x = 0x%08x  %s' % (
            i + 1, args.recheck_ms, off, rv,
            'held' if rv == args.value else 'changed (raced/cleared)' if rv != rb else ''))
        rb = rv
    v.write_cr(off, pre)
    print('restore 0x%04x <- 0x%08x (pre-probe value)' % (off, pre))
    post = v.read_cr(off)
    ok = post == pre
    print('verify  0x%04x = 0x%08x  %s' % (off, post,
          'RESTORED-OK' if ok else 'RESTORE-FAILED: still 0x%08x' % post))
    print('VERDICT-offset-0x%04x write=%s restore=%s' % (
        off, 'works' if rb == args.value else 'no', 'ok' if ok else 'FAIL'))
    if not ok:
        sys.exit(1)


def cmd_racetest(v, args):
    import subprocess
    off = args.offset
    if not write_allowed(off):
        print('REFUSED: offset 0x%04x outside allowlist' % off)
        sys.exit(2)
    pre = v.read_cr(off)
    print('pre     0x%04x = 0x%08x' % (off, pre))
    v.write_cr(off, args.value)
    rb = v.read_cr(off)
    print('seeded  0x%04x = 0x%08x  %s' % (off, rb,
          'OK' if rb == args.value else 'SEED-FAILED'))
    rc = subprocess.call(args.cmd, shell=True)
    print('cmd     %r -> rc=%d' % (args.cmd, rc))
    post = v.read_cr(off)
    print('post    0x%04x = 0x%08x  %s' % (off, post,
          'SURVIVED (no race)' if post == args.value else 'RACED/CLEARED by traffic'))
    v.write_cr(off, pre)
    fin = v.read_cr(off)
    print('restore 0x%04x <- 0x%08x; verify = 0x%08x  %s' % (
        off, pre, fin, 'RESTORED-OK' if fin == pre else 'RESTORE-FAILED'))
    if fin != pre:
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    sc = sub.add_parser('scan')
    sc.add_argument('--sweeps', type=int, default=3)
    sc.add_argument('--gap-s', type=float, default=1.0)
    wc = sub.add_parser('write')
    wc.add_argument('--offset', type=lambda x: int(x, 0), required=True)
    wc.add_argument('--value', type=lambda x: int(x, 0), default=0x600D0002)
    wc.add_argument('--recheck', type=int, default=3)
    wc.add_argument('--recheck-ms', type=int, default=500)
    rt = sub.add_parser('racetest')
    rt.add_argument('--offset', type=lambda x: int(x, 0), required=True)
    rt.add_argument('--value', type=lambda x: int(x, 0), default=0x600D0002)
    rt.add_argument('--cmd', required=True)
    args = ap.parse_args()

    v = Vsec()
    b = v.baseline()
    print('VSEC base=0x%x  baseline: CTRL=%08x COUNTER=%08x SEM=%08x ADDR=%08x DATA=%08x'
          % (v.base, *b))
    v.set_cr_space()
    print('CTRL set to %08x' % CTRL_SPACE_CR)
    try:
        if args.cmd == 'scan':
            cmd_scan(v, args)
        elif args.cmd == 'write':
            cmd_write(v, args)
        else:
            cmd_racetest(v, args)
    finally:
        v.restore_ctrl(b[0])
        print('CTRL restored to %08x; final: CTRL=%08x COUNTER=%08x SEM=%08x'
              % (b[0], v.r32(v.ctrl), v.r32(v.counter), v.r32(v.sem)))


if __name__ == '__main__':
    main()
