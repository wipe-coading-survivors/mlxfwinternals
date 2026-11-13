import os, struct, hashlib, sys
sys.path.insert(0, os.path.expanduser('~/git/IMPLEMENTATION/mlxini'))
sys.path.insert(0, os.path.expanduser('~/git/IMPLEMENTATION/mlxini/scripts/probes'))
import mlxfwutil
from iron_boot_probe import decrc
u32 = lambda b,o: struct.unpack_from('>I', b, o)[0]

S0 = open(os.path.expanduser('~/git/IMPLEMENTATION/mlxini/build/4030-cda-patched3.bin'),'rb').read()
S1f = open('/tmp/opencode/s1/4030-cda-s1-fixed.bin','rb').read()
S1old = open('/tmp/opencode/s1/4030-cda-s1.bin','rb').read()
ghidra = open(os.path.expanduser('~/git/IMPLEMENTATION/mlxini/build/ghidra-4030cda-main03-ac-dc.bin'),'rb').read()

def code_of(imgb):
    img = mlxfwutil.Image(imgb, 'x')
    e = img.find_entry('ITOC', 0x03)
    return decrc(img.section_data(e))

c0, c1f, c1o = code_of(S0), code_of(S1f), code_of(S1old)
print('code sizes:', hex(len(c0)), hex(len(c1f)), hex(len(c1o)))

# 1. S0 vs S1-fixed: word diff
d01 = [a//4 for a in range(0, len(c0), 4) if c0[a:a+4] != c1f[a:a+4]]
print('S0 vs S1fixed: %d word positions differ'%len(d01))
exp = ([0x090b7c+4*i for i in range(3)] + [0x090be4+4*i for i in range(3)] +
       [0x0d3cf4+4*i for i in range(3)] + [0x38d750+4*i for i in range(63)] +
       [0x38d84c+4*i for i in range(42)])
print('expected 114 word positions:', len(exp), 'match:', sorted(d01)==sorted(exp))

# 2. S0 code == ghidra(stock) + 7 S0 words?
g = bytearray(ghidra)
g[0x1d594:0x1d598] = struct.pack('>I', 0x940dc067)
for i,w in enumerate([0x24050000,0x20a523f0,0x2406badc,0x20c60001,0x6ca03002,0x95f24272]):
    g[0x38d730+4*i:0x38d730+4*i+4] = struct.pack('>I', w)
print('S0 code == stock-ghidra + 7 S0 words:', bytes(g)==c0, ' md5(s0code)=%s'%hashlib.md5(c0).hexdigest())

# 3. old S1 vs new S1-fixed: word diff
doo = [a//4 for a in range(0, len(c1o), 4) if c1o[a:a+4] != c1f[a:a+4]]
print('oldS1 vs newS1: %d word positions differ'%len(doo))
# expected: hook w0 x3 + old LOC 93w [0x38d750..0x38d8c4) vs new 63w + new TAB@0x38d84c vs old TAB@0x38d8c4 + old TAB tail [0x38d8f4..0x38d96c) -> zero
in_hook = [a for a in doo if a in (0x090b7c,0x090be4,0x0d3cf4)]
in_loc_tab = [a for a in doo if 0x38d750 <= a < 0x38d96c]
other = [a for a in doo if a not in (0x090b7c,0x090be4,0x0d3cf4) and not (0x38d750 <= a < 0x38d96c)]
print('  hook w0 x3:', in_hook==[0x090b7c,0x090be4,0x0d3cf4] or sorted(in_hook)==[0x090b7c,0x090be4,0x0d3cf4])
print('  in [0x38d750,0x38d96c): %d words (old LOC+TAB zone)'%len(in_loc_tab))
print('  outside both: %s'%(['%06x'%a for a in other] if other else 'NONE'))
# old TAB tail must be zero now
tail_old = [u32(c1f, a) for a in range(0x38d8f4, 0x38d96c, 4)]
print('  old TAB tail [0x38d8f4,0x38d96c) now all zero:', all(w==0 for w in tail_old))
# hook w0 changed 703f0fc2 -> 00000000
for h in (0x090b7c,0x090be4,0x0d3cf4):
    print('  hook %06x: oldS1=%08x newS1=%08x'%(h, u32(c1o,h), u32(c1f,h)))

# 4. image-level: S0 marker + injection intact (S0 image vs S1fixed image)
sec_off = 0x1c748
mk = [S0[sec_off+0x38d730+4*i:sec_off+0x38d730+4*i+4] for i in range(6)]
mkf = [S1f[sec_off+0x38d730+4*i:sec_off+0x38d730+4*i+4] for i in range(6)]
print('image S0 marker 6 words intact in S1fixed:', mk==mkf, mkf and ' '.join(struct.unpack('>I',b)[0:1] and '%08x'%struct.unpack('>I',b)[0] for b in mkf))
inj0 = S0[sec_off+0x1d594:sec_off+0x1d598]; injf = S1f[sec_off+0x1d594:sec_off+0x1d598]
print('image S0 injection dc 0x1d594 intact:', inj0==injf, 'word=%08x'%struct.unpack('>I',injf)[0])

# 5. final S1fixed image: hook + L_OP words as decoded
print('final image words:')
for a in (0x090b7c,0x090b80,0x090b84,0x090be4,0x0d3cf4,0x0d3cf8,0x0d3cfc):
    print('  %06x %08x'%(a, u32(c1f,a)))
print('  L_OP 0x38d774 %08x (want ld.d r11,r6,0x1c = 64cb0072)'%u32(c1f,0x38d774))
print('  DONE 0x38d814 %08x (bbc2 -> C2)'%u32(c1f,0x38d814))
print('md5 S1fixed image:', hashlib.md5(S1f).hexdigest(), 'size', len(S1f))
print('md5 S1fixed code :', hashlib.md5(c1f).hexdigest())
