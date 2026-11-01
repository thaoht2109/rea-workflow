#!/usr/bin/env python3
# Cấu hình theo máy của rea-flow. Thứ tự ưu tiên: biến môi trường > ~/.config/rea-flow/rea.env (hoặc $REA_ENV) > mặc định dưới đây.
# Không bắt buộc: mặc định đủ cho máy có công cụ trên PATH. Kiểm bằng `python3 <skill>/flow.py doctor`.
# Workspace (nơi chứa các case) là thư mục hiện tại, hoặc $REA_WORKSPACE.
import os, sys, shlex, shutil, tempfile, importlib.util

TOOLS = os.path.dirname(os.path.abspath(__file__))
REA = os.path.abspath(os.environ.get('REA_WORKSPACE') or os.getcwd())
FILE = os.environ.get('REA_ENV') or os.path.join(os.environ.get('XDG_CONFIG_HOME') or os.path.expanduser('~/.config'), 'rea-flow', 'rea.env')   # ngoài thư mục skill: cập nhật skill không mất cấu hình

def _load(p):
    d = {}
    if os.path.exists(p):
        for l in open(p, encoding='utf-8'):
            l = l.strip()
            if l and not l.startswith('#') and '=' in l:
                k, v = l.split('=', 1); d[k.strip()] = v.strip().strip('"\'')
    return d
_F = _load(FILE)

def get(k, d='', path=True):
    v = os.environ.get(k) or _F.get(k) or d
    if not path: return v   # lệnh có tham số: để shlex tách, không đổi đường dẫn
    v = os.path.expanduser(os.path.expandvars(v))
    if not v or os.path.isabs(v) or (os.sep not in v and not v.startswith('.')): return v   # trống, tuyệt đối, hoặc tên lệnh trên PATH
    return os.path.join(REA, v)   # đường dẫn tương đối tính từ workspace

TMP = get('REA_TMP', '.tmp')                     # TMPDIR cho rea/Ghidra; đặt trên đĩa thật nếu /tmp là tmpfs nhỏ
REVIEW_WS_DIR = get('REVIEW_WS_DIR', '/var/tmp')  # thư mục làm việc của phiên phản biện lớp 2; phải nằm ngoài cây project
GHIDRA = get('GHIDRA_INSTALL_DIR')               # thư mục cài Ghidra (có support/analyzeHeadless); trống = không dùng Ghidra
JAVA_HOME = get('JAVA_HOME')                     # JDK 21 cho Ghidra; trống = Ghidra tự tìm java trên PATH
PYLIB = get('REA_PYLIB', os.path.join(TOOLS, 'pylib'))          # thư mục chứa unicorn cho winemu
WINE_DLL_DIR = get('WINE_DLL_DIR', '/usr/lib/x86_64-linux-gnu/wine')   # chỉ đọc tên export DLL builtin, không chạy wine
REVIEW_LLM_CMD = get('REVIEW_LLM_CMD', path=False)          # lớp 2 bằng LLM khác: lệnh không tương tác, prompt qua stdin, JSON ra stdout; trống = claude -p
ANALYST_LLM_CMD = get('ANALYST_LLM_CMD', path=False)        # phiên sửa fact cho review-loop khi dùng LLM khác; trống = agent hiện tại tự sửa
REA_BIN, UPX, SEVENZ, CLAUDE = get('REA_BIN', 'rea'), get('UPX_BIN', 'upx'), get('SEVENZ_BIN', '7z'), get('CLAUDE_BIN', 'claude')

if os.path.isdir(PYLIB) and PYLIB not in sys.path: sys.path.insert(0, PYLIB)

def tmpenv(**kw): return dict(os.environ, TMPDIR=TMP, **kw)

def doctor():
    """In trạng thái từng mục; rc=1 nếu thiếu mục bắt buộc."""
    bad = 0
    def row(ok, k, v, use, req=True):
        nonlocal bad
        bad += (not ok) and req
        print(f"{'OK   ' if ok else ('THIẾU' if req else 'WARN ')} {k:<18} {v or '(trống)'}  [{use}]")
    print(f"workspace: {REA}\ncấu hình: {FILE if _F else f'(chưa có {FILE}: dùng biến môi trường/mặc định; mẫu ở {TOOLS}/rea.env.example)'}")
    for k, p in (('REA_TMP', TMP), ('REVIEW_WS_DIR', REVIEW_WS_DIR)):
        try:
            os.makedirs(p, exist_ok=True); tempfile.TemporaryFile(dir=p).close()
            free = shutil.disk_usage(p).free >> 30
            row(free >= 2, k, f'{p} (trống {free} GiB)', 'ghi được, nên trống >= 2 GiB')
        except OSError as e: row(False, k, f'{p}: {e.strerror}', 'phải ghi được')
    ws, home = os.path.realpath(REVIEW_WS_DIR), os.path.realpath(os.path.expanduser('~/.claude'))
    up, d = None, ws
    while True:   # agent nạp file hướng dẫn từ cwd đi lên: thư mục phản biện không được có file nào như vậy phía trên
        hit = [f for f in ('CLAUDE.md', 'AGENTS.md', 'GEMINI.md', '.cursor', '.github/copilot-instructions.md') if os.path.exists(os.path.join(d, f))]
        if d != home and hit: up = f'{d}/{hit[0]}'; break
        if d == os.path.dirname(d): break
        d = os.path.dirname(d)
    row(not up, 'cô lập lớp 2', f'có {up}' if up else ws, 'REVIEW_WS_DIR phải nằm ngoài thư mục có file hướng dẫn agent')
    for k, b, use, req in (('SEVENZ_BIN', SEVENZ, 'giải nén mẫu', True), ('CLAUDE_BIN', CLAUDE, 'review --llm, review-loop', not REVIEW_LLM_CMD),
                           ('REA_BIN', REA_BIN, 'flow.py dec', False), ('UPX_BIN', UPX, 'bóc UPX', False)):
        row(bool(shutil.which(b)), k, shutil.which(b) or b, use, req)
    row(bool(GHIDRA) and os.path.exists(os.path.join(GHIDRA, 'support', 'analyzeHeadless')), 'GHIDRA_INSTALL_DIR', GHIDRA,
        'dec khi rea không hỗ trợ kiến trúc', False)
    row(not JAVA_HOME or os.path.exists(os.path.join(JAVA_HOME, 'bin', 'java')), 'JAVA_HOME', JAVA_HOME, 'JDK 21 cho Ghidra', False)
    for m, req in (('pefile', True), ('unicorn', False), ('capstone', False)):
        row(importlib.util.find_spec(m) is not None, 'python:' + m, PYLIB if m == 'unicorn' else '', 'triage/winemu', req)
    if REVIEW_LLM_CMD:
        exe = shlex.split(REVIEW_LLM_CMD)[0]; row(bool(shutil.which(exe)), 'REVIEW_LLM_CMD', REVIEW_LLM_CMD, 'lớp 2 bằng LLM khác (cô lập partial)')
    row(os.path.isdir(WINE_DLL_DIR), 'WINE_DLL_DIR', WINE_DLL_DIR, 'tên export cho DLL giả của winemu', False)
    print('Đăng nhập claude: kiểm bằng `claude -p hi` (dùng chung tài khoản, không cần API key riêng; cần mạng tới api.anthropic.com)')
    return 1 if bad else 0

if __name__ == '__main__': sys.exit(doctor())
