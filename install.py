#!/usr/bin/env python3
# Cài bộ rea-flow cho các AI agent trong workspace (thư mục chứa tools/). Chạy lại bao nhiêu lần cũng được.
#   python3 tools/install.py [--agents all|claude,codex,cursor,copilot,gemini]   ghi file hướng dẫn cho từng agent, tạo rea.env, chạy doctor
#   python3 tools/install.py --pack OUT.sh [--with-pylib]   đóng gói thành 1 file cài đặt tự giải nén: bash OUT.sh <thư mục đích>
#   python3 tools/install.py --export DIR                   bản sạch làm repo skill cho `npx skills add` (bỏ rea.env, pylib)
#   python3 <thư mục skill>/install.py --workspace DIR      sau `npx skills add`: tạo DIR/tools -> thư mục skill rồi cài như trên
# Nội dung quy tắc lấy từ tools/SKILL.md (đoạn rules:begin..rules:end): sửa ở đó rồi chạy lại.
import os, sys, re, io, shutil, tarfile, base64, argparse, subprocess

T = os.path.dirname(os.path.abspath(__file__)); W = os.path.dirname(T)
B, E = '<!-- rea-flow:begin (sinh bởi tools/install.py; sửa tools/SKILL.md rồi chạy lại) -->', '<!-- rea-flow:end -->'
SKIP = {'__pycache__', 'rea.env', '.tmp'}
PRIVATE = {'pylib'}   # 56 MB, cài lại bằng pip theo gợi ý của doctor

def rules():
    s = open(os.path.join(T, 'SKILL.md'), encoding='utf-8').read()
    r = s.split('<!-- rules:begin -->')[1].split('<!-- rules:end -->')[0].strip()
    return (f'# Workspace dịch ngược mã độc (rea-flow)\n\nĐọc `tools/SKILL.md` trước khi làm việc trong thư mục này; '
            f'quy trình chi tiết ở `tools/FLOW.md`.\n\n{r}\n')

def put_block(p, body):
    """Ghi body vào giữa cặp marker; file đã có nội dung khác thì giữ nguyên phần ngoài marker."""
    os.makedirs(os.path.dirname(p), exist_ok=True)
    s = open(p, encoding='utf-8').read() if os.path.exists(p) else ''
    blk = f'{B}\n{body}{E}\n'
    s = re.sub(re.escape(B) + r'.*?' + re.escape(E) + r'\n?', lambda _: blk, s, flags=re.S) if B in s else (s.rstrip() + '\n\n' if s.strip() else '') + blk
    open(p, 'w', encoding='utf-8').write(s); print(f'  ghi {os.path.relpath(p, W)}')

def link(dst):
    if os.path.lexists(dst): print(f'  skill {dst}: đã có (npx skills hoặc lần cài trước), giữ nguyên'); return
    os.makedirs(os.path.dirname(dst), exist_ok=True); os.symlink(T, dst); print(f'  skill {dst} -> {T}')

AGENTS = {   # agent -> các file hướng dẫn nó tự đọc khi mở workspace
    'codex':   lambda r: put_block(os.path.join(W, 'AGENTS.md'), r),   # AGENTS.md: Codex, Cursor, Copilot coding agent và nhiều agent khác
    'claude':  lambda r: (put_block(os.path.join(W, 'CLAUDE.md'), r), link(os.path.expanduser('~/.claude/skills/rea-flow'))),
    'cursor':  lambda r: put_block(os.path.join(W, '.cursor', 'rules', 'rea-flow.mdc'), r),
    'copilot': lambda r: put_block(os.path.join(W, '.github', 'copilot-instructions.md'), r),
    'gemini':  lambda r: put_block(os.path.join(W, 'GEMINI.md'), r),
}

def install(agents):
    sys.stdout.reconfigure(line_buffering=True)   # in đúng thứ tự trước output của doctor
    r = rules()
    print(f'workspace: {W}')
    for a in agents:
        print(f'[{a}]'); AGENTS[a](r)
    mdc = os.path.join(W, '.cursor', 'rules', 'rea-flow.mdc')
    if 'cursor' in agents and not open(mdc, encoding='utf-8').read().startswith('---'):   # Cursor cần frontmatter để luôn áp dụng
        s = open(mdc, encoding='utf-8').read(); open(mdc, 'w', encoding='utf-8').write('---\ndescription: rea-flow\nalwaysApply: true\n---\n' + s)
    env = os.path.join(T, 'rea.env')
    if not os.path.exists(env): shutil.copy(os.path.join(T, 'rea.env.example'), env); print('  tạo tools/rea.env từ rea.env.example: sửa đường dẫn cho máy này')
    os.makedirs(os.path.join(W, '.tmp'), exist_ok=True)
    print('\n[doctor]'); rc = subprocess.run([sys.executable, os.path.join(W, 'tools', 'reacfg.py')]).returncode   # qua W/tools để workspace = W
    if rc: print('\nCòn thiếu mục bắt buộc: cài/sửa tools/rea.env rồi chạy `python3 tools/flow.py doctor`. '
                  'unicorn thiếu thì: python3 -m pip install --target tools/pylib unicorn==2.1.4')
    return rc

def pack(out, pylib):
    buf = io.BytesIO()
    def filt(ti):
        parts = ti.name.split('/')
        return None if SKIP & set(parts) or (not pylib and 'pylib' in parts[1:2]) else ti
    with tarfile.open(fileobj=buf, mode='w:gz') as tf: tf.add(T, arcname='tools', filter=filt)
    hdr = ('#!/usr/bin/env bash\n# Bộ cài rea-flow tự giải nén. Dùng: bash ' + os.path.basename(out) + ' [thư mục workspace] [--agents ...]\n'
           'set -euo pipefail\nD=${1:-$PWD/REA}; shift || true\nmkdir -p "$D"\n'
           '[ -f "$D/tools/rea.env" ] && cp "$D/tools/rea.env" "$D/.rea.env.keep"\n'
           'sed \'1,/^__ARCHIVE__$/d\' "$0" | base64 -d | tar xz -C "$D"\n'
           '[ -f "$D/.rea.env.keep" ] && mv "$D/.rea.env.keep" "$D/tools/rea.env"\n'
           'exec python3 "$D/tools/install.py" "$@"\n__ARCHIVE__\n')
    open(out, 'w').write(hdr + base64.encodebytes(buf.getvalue()).decode())
    os.chmod(out, 0o755); print(f'{out}: {os.path.getsize(out) >> 10} KiB' + ('' if pylib else ' (không kèm pylib/unicorn)'))

def export(d):
    ign = lambda _, ns: [n for n in ns if n in SKIP | PRIVATE]
    shutil.copytree(T, d, ignore=ign, dirs_exist_ok=True)
    open(os.path.join(d, '.gitignore'), 'w').write('rea.env\n__pycache__/\npylib/\n')
    print(f'{d}: repo skill sẵn sàng (git init && git add . && git commit; đẩy lên https://github.com/thaoht2109/rea-flow rồi `npx skills add thaoht2109/rea-flow`)')

def workspace(d):
    global W
    W = os.path.abspath(d); t = os.path.join(W, 'tools'); os.makedirs(W, exist_ok=True)
    if not os.path.lexists(t): os.symlink(T, t); print(f'  {t} -> {T}')
    elif os.path.realpath(t) != os.path.realpath(T): raise SystemExit(f'{t} đã có và không trỏ về {T}')

if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='Cài/đóng gói bộ rea-flow cho AI agent')
    ap.add_argument('--agents', default='all', help='all hoặc danh sách: ' + ','.join(AGENTS))
    ap.add_argument('--pack', metavar='OUT.sh'); ap.add_argument('--export', metavar='DIR'); ap.add_argument('--workspace', metavar='DIR'); ap.add_argument('--with-pylib', action='store_true')
    a = ap.parse_args()
    if a.pack: pack(a.pack, a.with_pylib); sys.exit(0)
    if a.export: export(a.export); sys.exit(0)
    if a.workspace: workspace(a.workspace)
    ag = list(AGENTS) if a.agents == 'all' else a.agents.split(',')
    if set(ag) - set(AGENTS): ap.error('agent lạ: ' + ','.join(set(ag) - set(AGENTS)))
    sys.exit(install(ag))
