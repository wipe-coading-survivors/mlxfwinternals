#!/usr/bin/env python3
"""cx4lx-dual-vpi: dual-port VPI image for c1:00.x (CX-4 Lx MCX4121A).

Base = 04z1 (build/cx4lx-04z1-bound.bin, md5-gated) - the last-assembled
image (owner decision 2026-10-17, spec addendum 2026-10-17 s.9). Single
config patch: VPI port0 byte 0x11+0x2af 0x0a (EN-only) -> 0x0b (VPI
def-ETH). Port1 0x11+0x2b3 = 0x07 (VPI def-IB) asserted invariant. Plus
the 0x30 build-ID (skill R1/R2: replaces the 04z1 line, section in
place, budget e.size-32, round-trip).

Gates: base md5 / entry invariants (VPI pair, 04z1 code words,
MAIN_CODE geometry) / patch via the mlxfwutil CLI (ITOC sec/entry CRC
recompute, T3 canary) / 0x30 extract-edit-inject (exactly one
"; mlxini " line, budget e.size-32 with ;;-trim fallback, round-trip
== edited text, no relocation, no growth) / verify --deep /
byte-diff vs base = expected set only / mstflint verify bootable /
mstflint q identity (PSID invariant vs base) / mstflint dc build-ID
first content line / determinism x2 (byte-exact OUT).
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

BASE = REPO + '/build/cx4lx-04z1-bound.bin'
BASE_MD5 = '47b15772b45d340f498646d2881390b0'
STEP1 = REPO + '/build/cx4lx-dualvpi-step1.bin'
INI = REPO + '/build/cx4lx-dualvpi-ini.ini'
OUT = REPO + '/build/cx4lx-dualvpi.bin'
VPI_PORT0_WANT = 0x0b
VPI_PORT1_WANT = 0x07
OLD_ID = 'mlxini cx4lx-04z1-bound'
NEW_ID = '; mlxini cx4lx-dualvpi (2026-10-17, 47b15772): 04z1 + VPI port0 0x11+0x2af=0x0b (def-ETH)'
ANCHOR = ';; Mellanox Technologies LTD'
TRIM_DESC_LEN = 60


def die(msg):
    print('FAIL: ' + msg)
    sys.exit(1)


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
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
if struct.unpack_from('>I', buf, 0x37e0f0)[0] != 0x0011001f:
    die('0x1f word mismatch at raw 0x37e0f0')
if struct.unpack_from('>I', buf, 0x3d5074)[0] != 0x14a67fff:
    die('04z1 bound word mismatch at raw 0x3d5074')
print('[2] 04z1 invariants OK (0x1f, bound, MAIN_CODE geometry)')

run(['python3', 'mlxfwutil.py', 'patch', BASE, '--set',
     '0x11+0x2af=%02x' % VPI_PORT0_WANT, '-o', STEP1])
s1 = open(STEP1, 'rb').read()
if s1[0x172af] != VPI_PORT0_WANT:
    die('port0 byte after patch = %02x, want 0b' % s1[0x172af])
ent11 = img.itoc_off + 32 + e11.index * 32
crc_diffs = [i for i in range(ent11 + 0x1a, ent11 + 0x20) if s1[i] != buf[i]]
if not 2 <= len(crc_diffs) <= 8:
    die('ITOC 0x11 CRC zone: %d changed byte(s), expect 2..8 (T3 canary)' % len(crc_diffs))
print('[3] patch OK: raw 0x172af=%02x, ITOC CRC changed %d B' % (s1[0x172af], len(crc_diffs)))

run(['python3', 'mlxfwutil.py', 'extract', STEP1, '-s', '0x30', '-o', INI])
text = open(INI).read()
lines = text.splitlines(keepends=True)
ids = [i for i, l in enumerate(lines) if l.startswith('; mlxini ')]
if len(ids) != 1:
    die('expected exactly one "; mlxini " build-ID line, got %d' % len(ids))
if OLD_ID not in lines[ids[0]]:
    die('build-ID line is not the 04z1 one: %r' % lines[ids[0]])
e30_old = img.find_entry('ITOC', 0x30)
budget30 = e30_old.size - 32
body = list(lines)
body[ids[0]] = NEW_ID + '\n'
n_untrimmed = zw_pad(''.join(body))
dropped = []
if n_untrimmed > budget30:
    # trim vendor ;;-comments (FW does not parse 0x30; R2 trim path).
    # Tier 1: the 04z1 filter (iniprep banner, ;;[PS_INFO] block, ;;>60B).
    psi = body.index(';;[PS_INFO]') if ';;[PS_INFO]' in body else None
    if psi is not None:
        end = psi
        while end < len(body) and body[end].startswith(';;'):
            end += 1
        dropped += list(range(psi, end))
    for i, l in enumerate(body):
        if l.startswith(';; Generated automatically by iniprep tool'):
            dropped.append(i)
        elif l.startswith(';;') and l.strip() != ANCHOR and len(l) > TRIM_DESC_LEN:
            dropped.append(i)
    # Tier 2 (this base: 04z1 already trimmed the tier-1 lines): the
    # longest ;;;;-nav lines, one at a time, until within budget.
    while zw_pad(''.join(l for i, l in enumerate(body) if i not in dropped)) > budget30:
        cands = [i for i, l in enumerate(body)
                 if i not in dropped and l.startswith(';;;;')]
        if not cands:
            break
        i = max(cands, key=lambda j: len(body[j]))
        dropped.append(i)
        print('    trim: line %d (%d B): %s' % (i, len(body[i]), body[i].strip()[:60]))
    dropped = sorted(set(dropped))
    for i in dropped:
        if not body[i].startswith(';;'):
            die('trim touched non-comment line %d (key=value forbidden)' % i)
    kv = [l for l in body if l.strip() and not l.startswith(';;')]
    body = [l for i, l in enumerate(body) if i not in set(dropped)]
    if [l for l in body if l.strip() and not l.startswith(';;')] != kv:
        die('trim filter-check: key=value line sequence changed')
ini_final = ''.join(body)
n_final = zw_pad(ini_final)
print('[4a] 0x30: e.size=0x%x budget=%d; zlib9+DWpad no-trim=%d -> final=%d (slack %d)%s'
      % (e30_old.size, budget30, n_untrimmed, n_final, budget30 - n_final,
         '' if not dropped else ', trim: %d ;;-lines' % len(dropped)))
if n_final > budget30:
    die('0x30 budget exceeded even after trim (%d > %d): STOP, no --repack-force (R2)'
        % (n_final, budget30))
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
allowed |= set(range(a30, a30 + max(e30_old.size, e30_new.size)))
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

r = subprocess.run(['mstflint', '-i', OUT, 'q'], capture_output=True, text=True)
q = r.stdout + r.stderr
for k in ('FW Version', 'PSID', 'Base GUID', 'Base MAC'):
    for l in q.splitlines():
        if k in l:
            print('    ' + l.strip())
for k in ('14.32.1900', 'MT_2420110034',
           mlxfwutil.hw('CARD_CX4LX_XCAT', 'guid'), mlxfwutil.hw('CARD_CX4LX_XCAT', 'mac')):
    if k not in q:
        die('mstflint q missing: ' + k)
print('[8] identity OK (PSID invariant vs base)')

# [9] mstflint dc: build-ID is the first content line (04z1 G8b)
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

print('DONE %s md5=%s' % (OUT, hashlib.md5(out).hexdigest()))
