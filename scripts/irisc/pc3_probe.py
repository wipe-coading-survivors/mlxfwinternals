#!/usr/bin/env python3
import os, struct, time, sys

DEV = '/sys/bus/pci/devices/0000:81:00.0/config'
fd = os.open(DEV, os.O_RDWR)

def r32(off):
    os.lseek(fd, off, os.SEEK_SET)
    return struct.unpack('<I', os.read(fd, 4))[0]

def w32(off, val):
    os.lseek(fd, off, os.SEEK_SET)
    os.write(fd, struct.pack('<I', val))

def r8(off):
    os.lseek(fd, off, os.SEEK_SET)
    return os.read(fd, 1)[0]

def find_vsec():
    ptr = r8(0x34)
    seen = 0
    while ptr and ptr < 1024 and seen < 64:
        if (r32(ptr) & 0xff) == 0x09:
            return ptr
        ptr = (r32(ptr) >> 8) & 0xff
        seen += 1
    return None

base = find_vsec()
if base is None:
    print('FATAL: VSEC cap 0x09 not found'); sys.exit(1)
CTRL, COUNTER, SEM, ADDR, DATA = base + 4, base + 8, base + 0xc, base + 0x10, base + 0x14
print('VSEC base=0x%x  CTRL=0x%x COUNTER=0x%x SEM=0x%x ADDR=0x%x DATA=0x%x'
      % (base, CTRL, COUNTER, SEM, ADDR, DATA))
b0 = (r32(CTRL), r32(COUNTER), r32(SEM), r32(ADDR), r32(DATA))
print('baseline: CTRL=%08x COUNTER=%08x SEM=%08x ADDR=%08x DATA=%08x' % b0)

READY_TIMEOUT = 2000
def read_cr(off):
    w32(CTRL, 0x20000002)
    w32(ADDR, off & 0x7fffffff)
    for _ in range(READY_TIMEOUT):
        if r32(ADDR) & 0x80000000:
            break
    return r32(DATA)

CANDS = [int(x, 16) for x in __CANDS__.split(',')]
extra = set()
extra.update(range(0x8e0, 0x941))          # neighborhood of known 0x8fc
extra.update([0x88fc, 0x8e89, 0x100, 0x555, 0xffff])  # controls
probe = sorted(set(CANDS) | extra)
probe = [w for w in probe if w > 0]
print('probe set: %d slots (%d cands + %d extra)' % (len(probe), len(CANDS), len(extra)))

t0 = time.monotonic()
rows = []
for w in probe:
    v = read_cr(4 * w)
    mapped = (v != w)
    rows.append((w, v, mapped))
t1 = time.monotonic()
print('probe done: %d slots in %.2fs (%.0f slots/s)' % (len(rows), t1 - t0, len(rows) / (t1 - t0)))

mapped_rows = [r for r in rows if r[2]]
unmapped_rows = [r for r in rows if not r[2]]
print('MAPPED: %d   UNMAPPED: %d' % (len(mapped_rows), len(unmapped_rows)))
print()
print('== MAPPED slots: word-idx CR-offset value ==')
for w, v, _ in mapped_rows:
    tag = ''
    if w == 0x8fc: tag = '  <-- known (marker 0xbadc0001)'
    print('0x%04x  0x%05x  0x%08x%s' % (w, 4 * w, v, tag))
print()
print('== unmapped controls (expect value == word-idx) ==')
for w, v, _ in unmapped_rows:
    if w in (0x88fc, 0x8e89, 0x100, 0x555, 0xffff):
        print('0x%04x  0x%05x  0x%08x  %s' % (w, 4 * w, v, 'OK-default' if v == w else 'NOT-DEFAULT'))

# contiguity among MAPPED (for multi-word channel)
ms = sorted(w for w, _, _ in mapped_rows)
runs = []
s = p = None
for w in ms:
    if s is None:
        s = p = w
    elif w == p + 1:
        p = w
    else:
        runs.append((s, p)); s = p = w
if s is not None:
    runs.append((s, p))
print()
print('== MAPPED runs (contiguous word ranges) ==')
for a, b in runs:
    print('words 0x%04x-0x%04x  CR 0x%05x-0x%05x  len=%d words' % (a, b, 4 * a, 4 * b, b - a + 1))

# throughput: N sequential reads of consecutive CR offsets (dense block 0x800-0x8ff)
def tput(N, start_word):
    t = time.monotonic()
    for i in range(N):
        read_cr(4 * (start_word + i))
    dt = time.monotonic() - t
    ops = 5 * N  # CTRL-w, ADDR-w, poll(>=1), DATA-r, (+poll) ~ 4-5
    return dt, dt / N, N / dt, 4 * N / dt, ops / dt

for N, sw in ((64, 0x800), (256, 0x800), (256, 0x1000)):
    dt, per, wps, bps, opsps = tput(N, sw)
    print('TPUT N=%-4d start=0x%04x  total=%.3fs  per-read=%.1f us  words/s=%.0f  B/s=%.0f  cfgops/s=%.0f'
          % (N, sw, dt, per * 1e6, wps, bps, opsps))

# restore CTRL baseline
w32(CTRL, b0[0])
print('CTRL restored to %08x; final: CTRL=%08x COUNTER=%08x SEM=%08x ADDR=%08x DATA=%08x'
      % (b0[0], r32(CTRL), r32(COUNTER), r32(SEM), r32(ADDR), r32(DATA)))
