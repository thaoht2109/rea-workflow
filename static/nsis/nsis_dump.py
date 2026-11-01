# Dump bảng entries + strings của header NSIS3 Unicode (32-bit)
import sys, struct
h = open(sys.argv[1],'rb').read()
flags = struct.unpack_from('<I', h, 0)[0]
blocks = [struct.unpack_from('<II', h, 4+8*k) for k in range(8)]
names = ['pages','sections','entries','strings','langtables','ctlcolors','bgfont','data']
for n,(o,c) in zip(names, blocks): print(f'{n:10} off={o:#x} num={c}')
str_off = blocks[3][0]
VARS = [f'${k}' for k in range(10)] + [f'$R{k}' for k in range(10)] + ['$CMDLINE','$INSTDIR','$OUTDIR','$EXEDIR','$LANGUAGE','$TEMP','$PLUGINSDIR','$EXEPATH','$EXEFILE','$HWNDPARENT','$_CLICK','$_OUTDIR']
def S(idx):
    if idx < 0: return f'<lang {idx}>'
    p = str_off + idx*2; out = []
    while p+1 < len(h):
        c = struct.unpack_from('<H', h, p)[0]; p += 2
        if c == 0: break
        if c in (1,2,3):
            n = struct.unpack_from('<H', h, p)[0]; p += 2
            if c == 3:
                v = ((n & 0x7F00) >> 1) | (n & 0x7F); out.append(VARS[v] if v < len(VARS) else f"$V{v-32}")
            elif c == 2: out.append(f'$SHELL({n & 0xff},{n >> 8 & 0x7f})')
            else: out.append(f'$(LANG{n & 0x7fff})')
        elif c == 4:
            out.append(chr(struct.unpack_from('<H', h, p)[0])); p += 2
        else: out.append(chr(c))
    return ''.join(out)
eo, en = blocks[2]
for k in range(en):
    w = struct.unpack_from('<7i', h, eo + 28*k)
    args = []
    for a in w[1:]:
        s = S(a) if 0 < a < (len(h)-str_off)//2 else ''
        args.append(f'{a}' + (f'"{s}"' if s and s.isprintable() else ''))
    print(f'{k:4} op={w[0]:3} ' + ' | '.join(args))
