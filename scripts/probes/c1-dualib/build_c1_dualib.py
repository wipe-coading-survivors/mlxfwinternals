#!/usr/bin/env python3
"""c1-dualib: dual-port VPI def-IB image for c1:00.x (CX-4 Lx MCX4121A).

Base = build/c1-1900vpi-c12analog-0x07.bin (md5-gated, the image currently
on the card) - stock 1900 + VPI port1 0x11+0x2b3=0x07 (from c1-ri) + C12
analog word 0x37e0f0=00110007 (r17:=0x07: SDR/DDR/QDR, no FDR/EDR; owner
decision 2026-10-19: speed without EDR for now). Single config patch:
VPI port0 byte 0x11+0x2af 0x0a (EN-only) -> 0x07 (VPI def-IB) => both
ports VPI default IB (same mode; owner's dual experiments: no assert).
No other traps: bound word 0x3d5074 stays stock (no 04z1 bounded-wait),
no F1 hook/patch. Plus the 0x30 build-ID (skill R1/R2: replaces the
c12analog-0x07 line, section in place, no growth, round-trip).

Gates: base md5 / entry invariants (VPI pair, C12 word, stock bound,
MAIN_CODE geometry) / patch via the mlxfwutil CLI (ITOC sec/entry CRC
recompute, canary) / 0x30 extract-edit-inject (exactly one "; mlxini "
line, no growth, round-trip == edited text, no relocation) /
verify --deep / byte-diff vs base = expected set only / mstflint verify
bootable / mstflint q identity (invariant vs base: GUID/MAC embedded,
R3) / mstflint dc build-ID first content line.
"""
import hashlib
import os
import struct
import subprocess
import sys
import zlib

REPO = os.path.expanduser('~/git/IMPLEMENTATION/mlxini')
sys.path.insert(0, REPO)
import mlxfwutil

BASE = REPO + '/build/c1-1900vpi-c12analog-0x07.bin'
BASE_MD5 = '5946cfdf579407c639beb9a8196eb471'
OUT = sys.argv[1] if len(sys.argv) > 1 else REPO + '/build/c1-1900vpi-c12analog-0x07-dualib.bin'
STEP1 = OUT + '.step1'
INI = OUT + '.ini'
VPI_PORT0_WANT = 0x07
VPI_PORT1_WANT = 0x07
C12_WANT = 0x00110007
BOUND_STOCK = 0x14a60009
OLD_ID = 'mlxini c12analog-0x07'
NEW_ID = '; mlxini c1-dualib (2026-10-19, 5946cfdf): c12analog-0x07 + VPI port0 0x11+0x2af=0x07 (dual def-IB)'


def die(msg):
    print('FAIL: ' + msg)
    sys.exit(1)


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO)
    print('$ ' + ' '.join(cmd))
    for stream in (r.stdout, r.stderr):
        for line in stream.strip().splitlines():
            print('    ' + line)
    if r.returncode != 0:
        die('rc=%d: %s' % (r.returncode, ' '.join(cmd)))
    return r


def zw_pad(text):
    d = zlib.compress(text.encode('latin1'), 9)
    return len(d) + (4 - len(d) % 4) % 4


buf = open(BASE, 'rb').read()
if hashlib.md5(buf).hexdigest() != BASE_MD5:
    die('base md5 mismatch')
print('[0] base md5 OK (%d B)' % len(buf))

img = mlxfwutil.Image(buf, BASE)
e11 = img.find_entry('ITOC', 0x11)
s11 = img.section_data(e11)
if s11[0x2af] != 0x0a:
    die('port0 VPI byte = %02x, expected 0x0a (EN-only)' % s11[0x2af])
if s11[0x2b3] != VPI_PORT1_WANT:
    die('port1 VPI byte = %02x, expected 0x07 (VPI def-IB)' % s11[0x2b3])
print('[1] VPI bytes: 0x2af=%02x 0x2b3=%02x OK' % (s11[0x2af], s11[0x2b3]))

e = img.find_entry('ITOC', 0x03)
if (e.addr, e.size, e.clcrc) != (0x16d000, 0x34e8c0, 1):
    die('MAIN_CODE header mismatch: %x %x %d' % (e.addr, e.size, e.clcrc))
if struct.unpack_from('>I', buf, 0x37e0f0)[0] != C12_WANT:
    die('C12 word mismatch at raw 0x37e0f0 (want %08x)' % C12_WANT)
if struct.unpack_from('>I', buf, 0x3d5074)[0] != BOUND_STOCK:
    die('bound word at raw 0x3d5074 = %08x, expected stock %08x'
        % (struct.unpack_from('>I', buf, 0x3d5074)[0], BOUND_STOCK))
print('[2] invariants OK (C12 0x07 word, stock bound, MAIN_CODE geometry)')

run(['python3', 'mlxfwutil.py', 'patch', BASE, '--set',
     '0x11+0x2af=%02x' % VPI_PORT0_WANT, '-o', STEP1])
s1 = open(STEP1, 'rb').read()
if s1[0x172af] != VPI_PORT0_WANT:
    die('port0 byte after patch = %02x, want 07' % s1[0x172af])
ent11 = img.itoc_off + 32 + e11.index * 32
crc_diffs = [i for i in range(ent11 + 0x1a, ent11 + 0x20) if s1[i] != buf[i]]
if not 2 <= len(crc_diffs) <= 8:
    die('ITOC 0x11 CRC zone: %d changed byte(s), expect 2..8 (canary)' % len(crc_diffs))
print('[3] patch OK: raw 0x172af=%02x, ITOC CRC changed %d B' % (s1[0x172af], len(crc_diffs)))

run(['python3', 'mlxfwutil.py', 'extract', STEP1, '-s', '0x30', '-o', INI])
text = open(INI).read()
lines = text.splitlines(keepends=True)
ids = [i for i, l in enumerate(lines) if l.startswith('; mlxini ')]
if len(ids) != 1:
    die('expected exactly one "; mlxini " build-ID line, got %d' % len(ids))
if OLD_ID not in lines[ids[0]]:
    die('build-ID line is not the c12analog-0x07 one: %r' % lines[ids[0]])
e30_old = img.find_entry('ITOC', 0x30)
body = list(lines)
body[ids[0]] = NEW_ID + '\n'
ini_final = ''.join(body)
n_final = zw_pad(ini_final)
print('[4a] 0x30: e.size=0x%x; zlib9+DWpad final=%d (delta vs base %d)%s'
      % (e30_old.size, n_final, n_final - zw_pad(text),
         '' if n_final <= e30_old.size else ' OVERFLOW'))
if n_final > e30_old.size:
    die('0x30 would grow beyond e.size (no --repack-force, R2)')
open(INI, 'w').write(ini_final)
run(['python3', 'mlxfwutil.py', 'inject', STEP1, INI, '-o', OUT])
out = open(OUT, 'rb').read()
oimg = mlxfwutil.Image(out, OUT)
e30_new = oimg.find_entry('ITOC', 0x30)
if e30_new.addr != e30_old.addr:
    die('0x30 relocated: 0x%x -> 0x%x' % (e30_old.addr, e30_new.addr))
if e30_new.size > e30_old.size:
    die('0x30 grew: 0x%x -> 0x%x' % (e30_old.size, e30_new.size))
run(['python3', 'mlxfwutil.py', 'extract', OUT, '-s', '0x30', '-o', INI + '.rt'])
if open(INI + '.rt').read() != ini_final:
    die('0x30 round-trip mismatch')
print('[4b] 0x30: in place @0x%x, size 0x%x -> 0x%x, round-trip OK'
      % (e30_new.addr, e30_old.size, e30_new.size))

run(['python3', 'mlxfwutil.py', 'verify', '--deep', OUT])
print('[5] verify --deep: PASS')

ent30 = img.itoc_off + 32 + e30_old.index * 32
allowed = {0x172af}
allowed |= set(range(ent11 + 0x1a, ent11 + 0x20))
a30 = img.sec_abs(e30_old)
allowed |= set(range(a30, a30 + e30_old.size))
allowed |= set(range(ent30, ent30 + 32))
diffs = [i for i in range(len(out)) if out[i] != buf[i]]
stray = [hex(i) for i in diffs if i not in allowed]
print('[6] byte-diff vs base: %d bytes, strays: %s' % (len(diffs), stray or 'none'))
if stray:
    die('stray diff bytes: %s' % stray)
if 0x172af not in diffs:
    die('0x172af not in the diff (patch did not land)')

r = subprocess.run(['mstflint', '-i', OUT, 'verify'], capture_output=True, text=True)
if r.returncode != 0 or 'bootable' not in (r.stdout + r.stderr):
    die('mstflint verify failed: %s' % (r.stdout + r.stderr).strip())
print('[7] mstflint -i verify: bootable')


def identity(path):
    r = subprocess.run(['mstflint', '-i', path, 'q'], capture_output=True, text=True)
    got = {}
    for l in (r.stdout + r.stderr).splitlines():
        for k in ('FW Version', 'PSID:', 'Base GUID', 'Base MAC'):
            if k in l:
                got[k] = l.strip()
    return got


ib, iout = identity(BASE), identity(OUT)
for k in ib:
    if iout.get(k) != ib[k]:
        die('identity changed vs base: %r: %r -> %r' % (k, ib[k], iout.get(k)))
for k, v in iout.items():
    print('    ' + v)
print('[8] identity OK vs base (GUID/MAC embedded, PSID invariant)')

r = subprocess.run(['mstflint', '-i', OUT, 'dc'], capture_output=True, text=True)
dl = [l.rstrip() for l in (r.stdout + r.stderr).splitlines()]
NOISE = ('-E-', '-W-', '-I-', '-')
try:
    mi = next(i for i, l in enumerate(dl) if NEW_ID in l)
except StopIteration:
    mi = -1
if mi < 0:
    die('mstflint dc does not show the build-ID marker')
pre = [l for l in dl[:mi] if l.strip() and not l.startswith(NOISE)]
if any(not l.startswith(';;') for l in pre) or len(pre) > 1:
    die('build-ID is not the first content line of dc (pre-content: %r)' % pre)
print('[9] mstflint dc: build-ID is the first content line')

for p in (STEP1, INI):
    os.unlink(p)
print('DONE %s md5=%s' % (OUT, hashlib.md5(out).hexdigest()))
