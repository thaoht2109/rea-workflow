#!/usr/bin/env python3
# Sinh static/data/syscalls_<abi>.json từ header kernel (asm/unistd_*.h) trên máy có linux-libc-dev. Chạy khi cần cập nhật bảng:
#   python3 static/syscalls_gen.py
import re, os, json
HERE = os.path.dirname(os.path.abspath(__file__))
SRC = {'mips_o32': ('/usr/include/mipsel-linux-gnu/asm/unistd_o32.h', 4000), 'x86_64': ('/usr/include/x86_64-linux-gnu/asm/unistd_64.h', 0),
       'i386': ('/usr/include/i386-linux-gnu/asm/unistd_32.h', 0)}
for abi, (h, base) in SRC.items():
    t = {}
    for l in open(h):
        m = re.match(r'#define __NR_(\w+)\s+\(__NR_Linux \+ (\d+)\)', l) or re.match(r'#define __NR_(\w+)\s+(\d+)\s*$', l)
        if m: t[int(m.group(2)) + (base if '__NR_Linux' in l else 0)] = m.group(1)
    json.dump({'abi': abi, 'source': os.path.basename(h), 'names': {str(k): v for k, v in sorted(t.items())}}, open(os.path.join(HERE, 'data', f'syscalls_{abi}.json'), 'w'), indent=0)
    print(abi, len(t))
