# Tách header NSIS (non-solid deflate) ra file thô để phân tích tiếp
import sys, struct, zlib
d = open(sys.argv[1],'rb').read()
i = d.find(b'\xef\xbe\xad\xdeNullsoftInst')
assert i > 0
off = i - 4
flags, sig, magic, hlen, total = struct.unpack_from('<II12sII', d, off)
print('firstheader@', hex(off), 'flags', flags, 'hdrlen', hlen, 'total', total)
p = off + 28
sz = struct.unpack_from('<I', d, p)[0]
comp = bool(sz & 0x80000000); sz &= 0x7fffffff
print('block0 size', sz, 'compressed', comp)
raw = d[p+4:p+4+sz]
h = zlib.decompressobj(-15).decompress(raw) if comp else raw
print('header len', len(h))
open(sys.argv[2],'wb').write(h)
