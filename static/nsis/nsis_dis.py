# Disassembler tối giản cho header NSIS3 Unicode 32-bit (đủ dùng cho mẫu này)
import sys, struct
h = open(sys.argv[1],'rb').read()
blocks = [struct.unpack_from('<II', h, 4+8*k) for k in range(8)]
str_off = blocks[3][0]
VARS = [f'${k}' for k in range(10)] + [f'$R{k}' for k in range(10)] + ['$CMDLINE','$INSTDIR','$OUTDIR','$EXEDIR','$LANGUAGE','$TEMP','$PLUGINSDIR','$EXEPATH','$EXEFILE','$HWNDPARENT','$_CLICK','$_OUTDIR']
def V(i): return VARS[i] if 0 <= i < len(VARS) else f'$V{i-32}'
def S(idx):
    if idx < 0: return f'<lang{idx}>'
    p = str_off + idx*2; out = []
    while p+1 < len(h):
        c = struct.unpack_from('<H', h, p)[0]; p += 2
        if c == 0: break
        if c in (1,2,3,4):
            n = struct.unpack_from('<H', h, p)[0]; p += 2
            if c == 3: out.append(V(((n & 0x7F00) >> 1) | (n & 0x7F)))
            elif c == 2: out.append(f'$SHELL({n & 0xff},{n >> 8 & 0x7f})')
            elif c == 1: out.append(f'$(LANG{n & 0x7fff})')
            else: out.append(chr(n))
        else: out.append(chr(c))
    return repr(''.join(out))
def J(a): return f'@{a-1}' if a else 'next'
INTOPS = ['+','-','*','/','|','&','^','!','||','&&','%','<<','>>','>>>']
def dis(k, w):
    op, a = w[0], w[1:]
    if op == 1: return 'Return'
    if op == 2: return f'Goto {J(a[0])}'
    if op == 4: return 'Quit'
    if op == 5: return f'Call {J(a[0])}' if a[0] >= 0 else f'Call {S(-a[0]-1)}'
    if op == 11: return f'CreateDir {S(a[0])} outdir={a[1]}'
    if op == 12: return f'IfFileExists {S(a[0])} ? {J(a[1])} : {J(a[2])}'
    if op == 13: return f'SetFlag {a[0]} {S(a[1])} ({a[2]})'
    if op == 14: return f'IfFlag on={J(a[0])} off={J(a[1])} flag={a[2]} mask={a[3]}'
    if op == 20: return f'File {S(a[1])} dataoff={a[2]}'
    if op == 24: return f'StrLen {V(a[0])} {S(a[1])}'
    if op == 25: return f'StrCpy {V(a[0])} {S(a[1])} len={S(a[2]) if a[2] else ""} start={S(a[3]) if a[3] else ""}'
    if op == 26: return f'StrCmp{"S" if a[4] else ""} {S(a[0])} {S(a[1])} eq={J(a[2])} ne={J(a[3])}'
    if op == 28: return f'IntCmp {S(a[0])} {S(a[1])} eq={J(a[2])} lt={J(a[3])} gt={J(a[4])} fl={a[5]}'
    if op == 29: return f'IntOp {V(a[0])} = {S(a[1])} {INTOPS[a[3]] if 0<=a[3]<len(INTOPS) else a[3]} {S(a[2])}'
    if op == 31:
        if a[2]: return f'Exch {a[2]}'
        return f'Pop {V(a[0])}' if a[1] else f'Push {S(a[0])}'
    if op == 39: return f'ShowWindow {S(a[0])} {S(a[1])}'
    if op == 44: return f'CallInstDLL {S(a[0])} {S(a[1])} noUnload={a[2]}'
    if op == 54: return f'FileClose {V(a[0])}'
    if op == 55: return f'FileOpen {V(a[0])} {S(a[3])} acc={a[1]:#x} disp={a[2]}'
    if op == 56: return f'FileWrite {S(a[0])} {S(a[1])}'
    if op == 57: return f'FileRead {S(a[0])} -> {V(a[1])} max={S(a[2])} byte={a[3]}'
    if op == 58: return f'FileSeek {S(a[0])} off={S(a[2])} mode={a[3]} out={V(a[1]) if a[1]>=0 else "-"}'
    if op == 69: return f'FileReadUTF16LE {S(a[0])} -> {V(a[1])} max={S(a[2])}'
    if op == 68: return f'FileWriteUTF16LE {S(a[0])} {S(a[1])}'
    return f'op{op} ' + ' '.join(str(x) for x in a)
eo, en = blocks[2]
W = [struct.unpack_from('<7i', h, eo + 28*k) for k in range(en)]
# sections
so, sn = blocks[1]
for k in range(sn):
    nm, it, fl, code, csz, kb = struct.unpack_from('<6i', h, so + 2072*k)
    print(f'; section {k} name={S(nm) if nm else ""} code={code} size={csz}')
po, pn = blocks[0]
for k in range(pn):
    print('; page', k, struct.unpack_from('<16i', h, po + 64*k)[:8])
cb = struct.unpack_from('<10i', h, 4+64+4*10)
print('; callbacks onInit/InstSuccess/InstFailed/UserAbort/GUIInit/GUIEnd/MouseOver/VerifyDir/SelChange/RebootFailed =', [c for c in cb])
for k, w in enumerate(W):
    if w[0]: print(f'{k:4}  {dis(k, w)}')
