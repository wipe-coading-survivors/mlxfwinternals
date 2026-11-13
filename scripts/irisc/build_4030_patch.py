#!/usr/bin/env python3
# Build patched 4030 CDA image: boot-injection at dc 0x1d598 + shellcode in
# free region dc 0x38d730..0x38d747 (marker 0xbadc0001 -> CR-space 0x23f0 via
# iRISC RAM window). Pipeline: de-clcrc -> round-trip -> patch -> re-clcrc ->
# line-diff -> mlxfwutil.patch_sections (sec/entry CRC + hashes) -> verify.
import os, struct, hashlib, sys

REPO = os.path.expanduser('~/git/IMPLEMENTATION/mlxini')
IMG = REPO + '/refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_4030-MCX516A-CDA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin'

sys.path.insert(0, REPO)
import mlxfwutil

def be32(w): return struct.pack('>I', w)
def u32(b, o): return struct.unpack_from('>I', b, o)[0]

def die(msg):
    print('FATAL: ' + msg)
    sys.exit(1)

# ============ 1. extract raw MAIN_CODE ============
img = mlxfwutil.Image(open(IMG, 'rb').read(), IMG)
e = img.find_entry('ITOC', 0x03)
raw = img.section_data(e)
assert e.size == 0x3d15a0 and e.clcrc == 1 and e.addr == 0x1c748, (hex(e.size), e.clcrc, hex(e.addr))
assert e.param0 == 0x800000 and e.param1 == 0x81d58c
md5_raw = hashlib.md5(raw).hexdigest()
print('[1] raw MAIN_CODE: size=0x%x addr=0x%x clcrc=1 p0=0x%x p1=0x%x md5=%s' % (
    len(raw), e.addr, e.param0, e.param1, md5_raw))
if md5_raw != 'bcfe0526b43de4abf324b5056f91c112':
    die('raw md5 mismatch vs journal 1')

# ============ 2. de-clcrc ============
code, tail = mlxfwutil.clcrc_unwrap(raw)
assert len(code) == 0x397dc0, hex(len(code))
md5_code = hashlib.md5(code).hexdigest()
print('[2] de-clcrc code: size=0x%x md5=%s' % (len(code), md5_code))
if md5_code != '1b73520497bd20f49fe4e5200a6c86dd':
    die('code md5 mismatch vs journal 1')
nlines = len(code) // 64
print('[2] lines=%d tail(4B)=%s' % (nlines, tail.hex()))

# ============ 3. ROUND TRIP (pre-patch) ============
rt = mlxfwutil.clcrc_wrap(code, tail)
if rt != raw:
    first = next(i for i in range(len(raw)) if rt[i] != raw[i])
    ln = first // 68
    print('ROUND-TRIP MISMATCH at raw byte 0x%x (line %d)' % (first, ln))
    print('  orig: %s' % raw[max(0,first-8):first+8].hex())
    print('  rt:   %s' % rt[max(0,first-8):first+8].hex())
    die('round-trip failed')
print('[3] ROUND-TRIP: re-clcrc(code)+tail == raw (0x%x bytes) IDENTICAL' % len(raw))

# ============ 4. decode-verify the final words ============
def decode_word(w, pc):
    op = w >> 26
    rd, rs, rt_ = (w>>16)&0x1f, (w>>21)&0x1f, (w>>11)&0x1f
    if op == 0x09: return 'set2 r%d, r%d, 0x%04x' % (rd, rs, w & 0xffff)
    if op == 0x08: return 'set3 r%d, r%d, 0x%04x' % (rd, rs, w & 0xffff)
    if op == 0x12 and not (w>>25)&1:
        return 'csr.r r%d, csr0x%x' % (rd, w & 0x7ff)
    if op == 0x12 and (w>>25)&1:
        return 'ld.i r%d, 0x%x' % (rd, w & 0xffff)
    if op == 0x13 and (w>>16)&0x1f == 0x1b:
        return 'st.i r%d, 0x%03x' % (rt_, w & 0x7ff)
    if op == 0x1b and (w&3) == 2:
        off = (((w>>16)&0x1f)<<11) | (((w>>2)&0x1ff)<<2)
        return 'st.d r%d, r%d, OFF=0x%x' % (rt_, rs, off)
    if op == 0x25:
        rel = w & 0xffffff
        if rel & 0x800000: rel -= 0x1000000
        tgt = (pc + 4) + rel*4
        return ('jump' if (w>>24)&1 else 'call') + ' 0x%x (rel=%+d)' % (tgt, rel)
    return '?? op=0x%02x' % op

INJ_PC, INJ_WORD = 0x1d598, 0x950dc065
SC_BASE = 0x38d730
SC_WORDS = [0x2403BADC, 0x20630001, 0x4C1B18FC, 0x95F23F93]
EXPECTED = [
    'set2 r3, r0, 0xbadc',
    'set3 r3, r3, 0x0001',
    'st.i r3, 0x8fc',
    'jump 0x1d59c (rel=-901229)',
]
print('[4] decode-verify:')
d = decode_word(INJ_WORD, INJ_PC)
print('    0x%06x  0x%08x  %s' % (INJ_PC, INJ_WORD, d))
assert d == 'jump 0x38d730 (rel=901221)', d
for i, (w, exp) in enumerate(zip(SC_WORDS, EXPECTED)):
    pc = SC_BASE + 4*i
    d = decode_word(w, pc)
    print('    0x%06x  0x%08x  %s' % (pc, w, d))
    assert d == exp, (d, exp)
print('    [4] all 5 words decode as intended: PASS')

# ============ 5. apply patch to code ============
assert u32(code, INJ_PC) == 0x95000000, 'injection site not 0x95000000: %x' % u32(code, INJ_PC)
free = code[SC_BASE:0x38dbe9]
assert all(b == 0 for b in free), 'free region 0x38d730-0x38dbe9 not all zeros'
code = bytearray(code)
code[INJ_PC:INJ_PC+4] = be32(INJ_WORD)
for i, w in enumerate(SC_WORDS):
    code[SC_BASE+4*i:SC_BASE+4*i+4] = be32(w)
code = bytes(code)
open(REPO + '/build/4030cda-main03-code-patched.bin', 'wb').write(code)
print('[5] patch applied: inj 0x%06x + shellcode 0x%06x..0x%06x; free region was all-zero' % (
    INJ_PC, SC_BASE, SC_BASE + 16))

# ============ 6. re-clcrc + line diff ============
praw = mlxfwutil.clcrc_wrap(code, tail)
assert len(praw) == len(raw) == 0x3d15a0
diff_lines = [i for i in range(nlines) if raw[i*68:(i+1)*68] != praw[i*68:(i+1)*68]]
exp_lines = [0x1d580//64, 0x38d700//64]
print('[6] changed 68B lines: %s (expected %s)' % (diff_lines, exp_lines))
if diff_lines != exp_lines:
    die('unexpected changed-line set')
for i in diff_lines:
    o = i*68
    oldc = struct.unpack('<H', raw[o+66:o+68])[0]
    newc = struct.unpack('<H', praw[o+66:o+68])[0]
    print('    line %5d raw 0x%06x..0x%06x: code delta + clcrc 0x%04x -> 0x%04x' % (
        i, o, o+68, oldc, newc))
open(REPO + '/build/4030cda-main03-raw-patched.bin', 'wb').write(praw)
print('[6] patched raw: 0x%x bytes, only 2 lines changed, all others byte-identical' % len(praw))

# sanity: no firmware store to the marker register
# (a) st.i imm11==0x8fc  (b) base-zero store of any width with off16/14/15 == 0x23f0
hits_sti = [i*4 for i in range(len(code)//4)
            if (u32(code, i*4) >> 26) == 0x13 and ((u32(code, i*4) >> 16) & 0x1f) == 0x1b and (u32(code, i*4) & 0x7ff) == 0x8fc]
hits_bz = []
for i in range(len(code)//4):
    x = u32(code, i*4); op = x >> 26
    if op in (0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f) and ((x >> 21) & 0x1f) == 0:
        hi, lo11 = (x >> 16) & 0x1f, x & 0x7ff
        if hi == 4 and lo11 in (0x3F0, 0xFC, 0x1F8):
            hits_bz.append((i*4, x))
print('[6] firmware st.i -> RAM[0x23f0]: %s' % ([hex(h) for h in hits_sti] or 'none'))
print('[6] firmware base-zero stores to 0x23f0: %s' % (hits_bz or 'none'))
assert not hits_sti and not hits_bz

# ============ 7. build image via mlxfwutil.patch_sections ============
edits = []
for i in diff_lines:
    o = i*68
    edits.append((0x03, o, praw[o:o+68]))
out = mlxfwutil.patch_sections(img, edits)
md5_out = hashlib.md5(out).hexdigest()
open(REPO + '/build/4030-cda-patched.bin', 'wb').write(out)
print('[7] image built: md5=%s' % md5_out)

# ============ 8. verify ============
pimg = mlxfwutil.Image(out, 'patched', base=img.base, fmt=img.fmt)
errs = mlxfwutil.verify_image(pimg, deep=True)
berrs = mlxfwutil.verify_image(img, deep=False)
print('[8] baseline verify (original): %s' % ('PASS' if not berrs else berrs))
print('[8] patched verify (deep): %s' % ('PASS' if not errs else errs))
if errs:
    die('verify failed')
print('DONE build/4030-cda-patched.bin md5=' + md5_out)
