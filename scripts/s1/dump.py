import os, struct, sys, importlib.util
spec = importlib.util.spec_from_file_location(
    "iriscdis", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.pardir, "irisc", "irisc_dis.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
dis = m.dis

def s14(v):
    v &= 0x3fff
    return v - 0x4000 if v & 0x2000 else v

def memoff(w):
    # correct 14-bit offset for ld/st immediate (ops 0x17-0x1e): hi=bits20-16, lo=bits2-10
    hi = (w >> 16) & 0x1f
    lo = (w >> 2) & 0x1ff
    return s14((hi << 9) | lo) * 4

buf = open(sys.argv[1], 'rb').read()
lo, hi = int(sys.argv[2], 0), int(sys.argv[3], 0)
for off in range(lo, hi, 4):
    if off >= len(buf):
        break
    w = struct.unpack_from('>I', buf, off)[0]
    op = w >> 26
    extra = ''
    if op in (0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1e):
        extra = '  [byteoff=0x%x]' % memoff(w)
    print('%08x  %08x  %s%s' % (off, w, dis(w, off), extra))
