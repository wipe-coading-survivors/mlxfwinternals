import struct, sys
buf = open(sys.argv[1], 'rb').read()
words = struct.unpack('>%dI' % (len(buf) // 4), buf[: (len(buf) // 4) * 4])
PROLOG = 0x480300bc   # csr.r r3,csr0xbc
STDRET = 0xfd001825   # ret.r zero,r8,r3
starts = [int(x, 16) for x in sys.argv[2].split(',')]
for s in starts:
    si = s // 4
    # next prologue after s
    end = None
    for i in range(si + 1, len(words)):
        if words[i] == PROLOG:
            end = i * 4
            break
    # stdrets inside [s, end)
    ei = (end // 4) if end else len(words)
    rets = [i * 4 for i in range(si + 1, ei) if words[i] == STDRET]
    print('fn start=0x%08x end(=next prolog)=0x%08x size=0x%x' % (s, end if end else 0, (end - s) if end else 0))
    print('  stdret count=%d last=0x%08x all=%s' % (len(rets), rets[-1] if rets else 0,
          ' '.join('0x%08x' % r for r in rets[-6:])))
