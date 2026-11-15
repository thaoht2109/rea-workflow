#!/usr/bin/env python3
# Tầng T1b: công cụ do agent tự viết cho định dạng chưa có đường đi (flow.py tool). Khuôn buộc công cụ tự chứng minh là đúng:
# phải khai FORMAT/SCOPE, phải có phép tự kiểm đạt, evidence ghi kèm dấu băm của đúng bản công cụ đã sinh ra nó.
#   flow.py tool CASE new TÊN            tạo work/tools/TÊN.py từ templates/adhoc_tool.py
#   flow.py tool CASE run TÊN [THAM SỐ]  quét tĩnh script (chỉ import trong danh sách cho phép), chạy python3 -I, ghi report/evidence/tool_TÊN_<n>.txt
#   flow.py tool CASE list               công cụ của case, trạng thái tự kiểm của từng evidence
import ast, hashlib, os, re, secrets, shutil, subprocess, sys
TOOLS = os.path.dirname(os.path.abspath(__file__))
HEAD = '# rea-flow tool evidence'; SPLIT = '--- output'
NAME = re.compile(r'[A-Za-z][A-Za-z0-9_]{0,39}')
# Bộ quét dùng DANH SÁCH CHO PHÉP (không phải danh sách cấm): mọi import ngoài danh sách bị từ chối, kể cả pickle/marshal/builtins/ctypes.
ALLOW = {'struct', 'zlib', 'bz2', 'lzma', 'gzip', 'base64', 'binascii', 'hashlib', 'hmac', 'json', 're', 'sys', 'io', 'math', 'collections', 'itertools',
         'functools', 'dataclasses', 'enum', 'typing', 'string', 'codecs', 'unicodedata', 'datetime', 'time', 'array', 'bisect', 'heapq', 'operator',
         'copy', 'textwrap', 'pprint', 'argparse', 'ast', 'zipfile', 'tarfile', 'plistlib', 'csv', 'uuid', 'ipaddress', 'fractions', 'decimal',
         'statistics', 'random', 'secrets', 'difflib', 'fnmatch', 'glob', 'contextlib', 'abc', 'numbers', 'types', 'warnings', 'traceback', 'urllib.parse',
         'brotli', 'Crypto', 'Cryptodome', 'cryptography', 'capstone', 'pefile', 'elftools', 'lz4', 'zstandard', 'snappy', 'msgpack', 'cbor2', 'construct', 'tlsh'}
OS_OK = {'path', 'environ', 'sep', 'linesep', 'getcwd', 'listdir', 'scandir', 'walk', 'stat', 'fspath', 'devnull', 'SEEK_SET', 'SEEK_CUR', 'SEEK_END'}   # os: chỉ phần đọc
BAN_NAME = {'eval', 'exec', 'compile', '__import__', 'getattr', 'setattr', 'delattr', 'globals', 'locals', 'vars', 'breakpoint', '__builtins__', 'input'}
DUNDER_OK = {'__name__', '__file__', '__doc__', '__init__', '__slots__', '__len__', '__repr__', '__str__', '__eq__', '__hash__', '__iter__', '__next__', '__getitem__', '__contains__', '__enter__', '__exit__'}
DANGER = {'os', 'sys', 'subprocess', 'socket', 'ctypes', 'shutil', 'importlib', 'builtins', 'cffi', 'posix', 'nt', 'pty', 'signal', 'multiprocessing',
          'threading', 'runpy', 'pickle', 'marshal', 'code', 'codeop', 'pdb', 'modules', 'meta_path', 'path_hooks', 'settrace', 'setprofile', 'pythonapi', 'ffi'}
# Lớp chặn lúc chạy (audit hook, không gỡ được sau khi cài): AST không thể lường hết lối vòng qua module mà thư viện được phép đã import sẵn.
BOOT = r"""
import os, sys
_script, _out = sys.argv[1], os.path.realpath(sys.argv[2]) + os.sep
_PROC = {'subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn', 'os.fork', 'os.forkpty', 'os.spawn', 'os.startfile', 'pty.spawn', 'os.kill', 'os.killpg', 'os.putenv', 'os.unsetenv'}
_FS = {'os.remove', 'os.rename', 'os.rmdir', 'os.mkdir', 'os.chmod', 'os.chown', 'os.truncate', 'os.link', 'os.symlink', 'os.utime', 'os.chdir', 'os.chflags',
       'shutil.rmtree', 'shutil.move', 'shutil.copyfile', 'shutil.copymode', 'shutil.copystat', 'shutil.copytree', 'shutil.make_archive', 'shutil.unpack_archive', 'tempfile.mkstemp', 'tempfile.mkdtemp'}
_LIBS = tuple(os.sep + p + os.sep for p in ('Crypto', 'Cryptodome', 'capstone', 'cryptography'))
_W = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
def _inside(p):
    try: return (os.path.realpath(os.fsdecode(p)) + os.sep).startswith(_out)
    except Exception: return False
def _hook(ev, a, _PE=PermissionError, _str=str, _int=int, _any=any):
    if ev in _PROC or ev.startswith(('socket.', 'urllib.', 'http.', 'ftplib.', 'smtplib.', 'webbrowser.', 'winreg.', 'ssl.')): raise _PE('T1b: cấm ' + ev)
    if ev == 'ctypes.dlopen' and not (a and isinstance(a[0], _str) and _any(x in os.path.realpath(a[0]) for x in _LIBS)): raise _PE('T1b: cấm ctypes.dlopen ngoài thư viện phân tích được phép')
    if ev == 'open':
        path, mode, flags = (list(a) + [None, None, None])[:3]
        wr = (isinstance(mode, _str) and _any(c in mode for c in 'wax+')) or (isinstance(flags, _int) and flags & _W)
        if wr and (isinstance(path, _int) or not _inside(path)): raise _PE('T1b: chỉ được ghi trong thư mục REA_TOOL_OUT')
    elif ev in _FS and not (a and not isinstance(a[0], _int) and a[0] is not None and _inside(a[0]) and (ev != 'os.rename' or _inside(a[1]))): raise _PE('T1b: cấm ' + ev + ' ngoài REA_TOOL_OUT')
sys.addaudithook(_hook)
sys.argv = [_script] + sys.argv[3:]
import runpy
runpy.run_path(_script, run_name='__main__')
"""
MAX_OUT = 400   # số dòng output chép vào evidence; bản đầy đủ nằm ở work/runs/tool/

def tdir(c): return os.path.join(c, 'work', 'tools')
def edir(c): return os.path.join(c, 'report', 'evidence')

def scan(path):
    """Quét AST một file. Trả (lỗi, module cục bộ được import, FORMAT, SCOPE).
    Mục đích: giữ công cụ T1b là Python thuần đọc file. Đây là rào chặn đường hiển nhiên và các lối vòng quen thuộc (alias, from-import,
    getattr, builtins, dunder), không phải sandbox: quy tắc không chạy mẫu vẫn do agent chịu trách nhiệm."""
    try: tree = ast.parse(open(path, encoding='utf-8').read())
    except (SyntaxError, ValueError) as e: return [f'{os.path.basename(path)}: không phân tích được ({e})'], [], '', ''
    bad, local, meta = [], [], {}; base = os.path.basename(path); here = os.path.dirname(path); osn = set()   # osn: mọi tên đang trỏ tới module os
    def no(n, why): bad.append(f'{base}:{n.lineno}: {why}')
    def allowed(m): return m in ALLOW or m.split('.')[0] in ALLOW and not m.startswith('urllib')
    imp = set()                                  # mọi tên do import đưa vào (module hoặc tên from-import): truy cập thuộc tính '_x' trên chúng bị cấm
    for n in ast.walk(tree):                     # lượt 1: import và alias của os
        if isinstance(n, ast.Import):
            for a in n.names:
                imp.add(a.asname or a.name.split('.')[0])
                if a.name in ('os', 'os.path'):
                    if a.name == 'os': osn.add(a.asname or 'os')
                    elif a.asname: no(n, 'import os.path as ...: dùng `import os.path` hoặc `from os.path import <hàm>`')
                    else: osn.add('os')
                elif os.path.isfile(os.path.join(here, a.name.split('.')[0] + '.py')): local.append(a.name.split('.')[0])
                elif not allowed(a.name): no(n, f'import {a.name}: ngoài danh sách cho phép (mạng, tiến trình con, nạp mã động, tuần tự hóa đều bị cấm)')
        elif isinstance(n, ast.ImportFrom):
            m = n.module or ''; imp.update(a.asname or a.name for a in n.names)
            if n.level: no(n, 'import tương đối: đặt module cạnh script và import bằng tên'); continue
            for a in n.names:                    # tên được import không được là module nguy hiểm, dù module nguồn hợp lệ (vd `from glob import os`)
                if a.name == '*' or a.name.startswith('_') or (a.name in DANGER and not (m == 'os' and a.name in OS_OK)): no(n, f'from {m} import {a.name}: tên bị cấm')
            if m == 'os':
                for a in n.names:
                    if a.name not in OS_OK: no(n, f'from os import {a.name}: chỉ được dùng phần đọc của os ({", ".join(sorted(OS_OK))})')
            elif m == 'os.path': pass
            elif os.path.isfile(os.path.join(here, m.split('.')[0] + '.py')): local.append(m.split('.')[0])
            elif not allowed(m) and not all(allowed(m + '.' + a.name) for a in n.names): no(n, f'from {m} import ...: ngoài danh sách cho phép')
    for n in ast.walk(tree):                     # gán lại module os cho tên khác (x = os) cũng là alias
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Name) and n.value.id in osn: osn.update(t.id for t in n.targets if isinstance(t, ast.Name))
    def rootname(x):
        while isinstance(x, ast.Attribute): x = x.value
        return x.id if isinstance(x, ast.Name) else None
    for n in ast.walk(tree):                     # lượt 2: cách dùng
        if isinstance(n, ast.Name) and n.id in BAN_NAME: no(n, f'{n.id}: nạp mã động/truy cập phản xạ bị cấm')
        elif isinstance(n, ast.Attribute):
            if isinstance(n.value, ast.Name) and n.value.id in osn and n.attr not in OS_OK: no(n, f'{n.value.id}.{n.attr}: chỉ được dùng phần đọc của os')
            elif n.attr in DANGER: no(n, f'.{n.attr}: đi tới module/cơ chế bị cấm qua thuộc tính')
            elif n.attr.startswith('__') and n.attr not in DUNDER_OK: no(n, f'.{n.attr}: truy cập dunder bị cấm')
            elif n.attr.startswith('_') and not n.attr.startswith('__') and rootname(n) in imp | osn | {'sys'}: no(n, f'.{n.attr}: thuộc tính riêng của module được import bị cấm')
    for n in tree.body:   # FORMAT/SCOPE: chỉ nhận hằng chuỗi gán ở mức module, đọc tĩnh chứ không import script
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id in ('FORMAT', 'SCOPE') \
                and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str): meta[n.targets[0].id] = ' '.join(n.value.value.split())[:200]
    return bad, local, meta.get('FORMAT', ''), meta.get('SCOPE', '')

def closure(d, name):
    """Script chính + mọi module cục bộ nó import (đệ quy). Trả (danh sách file theo thứ tự ổn định, lỗi quét, FORMAT, SCOPE)."""
    seen, todo, bad = [], [name], []; fmt = scope = ''
    while todo:
        m = todo.pop(0)
        if m in seen: continue
        seen.append(m); b, loc, f, s = scan(os.path.join(d, m + '.py')); bad += b; todo += loc
        if m == name: fmt, scope = f, s
    return [name] + sorted(x for x in seen if x != name), bad, fmt, scope

def digest(d, mods):
    """Dấu băm của một bản công cụ: tên + nội dung từng file. Đổi bất kỳ file nào thì evidence cũ thành 'tool_stale'."""
    h = hashlib.sha256()
    for m in mods:
        p = os.path.join(d, m + '.py')
        if not os.path.isfile(p): return None
        b = open(p, 'rb').read(); h.update(f'{m}.py\0{len(b)}\0'.encode() + b)
    return h.hexdigest()

def header(text):
    """Phần đầu của evidence tool_* -> dict {tool, sha, mods, ok, cov, checks}; không phải evidence do `tool run` sinh -> None.
    Bố cục cố định: dòng 2 là TOOL, dòng 3 CMD, 4 FORMAT, 5 SCOPE, sau đó mới tới SELFCHECK/COVERAGE (không nhận các dòng này ở vị trí khác)."""
    L = text.split('\n' + SPLIT, 1)[0].splitlines()
    if len(L) < 5 or L[0].strip() != HEAD: return None
    H = {'checks': [], 'ok': False, 'cov': None, 'tool': '', 'sha': '', 'mods': []}
    m = re.fullmatch(r'TOOL (\S+) sha256 ([0-9a-f]{64}) files (\S+)', L[1])
    if not m or not L[2].startswith('CMD ') or not L[3].startswith('FORMAT ') or not L[4].startswith('SCOPE '): return None
    H['tool'], H['sha'], H['mods'] = m.group(1), m.group(2), [x[:-3] for x in m.group(3).split(',')]
    for l in L[5:]:
        if l.startswith('SELFCHECK: '): H['ok'] = l.startswith('SELFCHECK: ĐẠT')
        elif l.startswith('SELFCHECK '): H['checks'].append(l)
        elif re.fullmatch(r'COVERAGE \d+/\d+', l): H['cov'] = l.split()[1]
    return H

def issues(case, f, rel, text):
    """Luật cổng cho fact dẫn evidence tool_*, dùng chung cho lint khi ghi (case.lint_fact) và lớp 1 phản biện (review.mech).
    Trả [(check, vấn đề, cách sửa)]."""
    if not os.path.basename(rel).startswith('tool_'): return []
    H = header(text); redo = 'chạy lại `flow.py tool CASE run TÊN ...`, rồi ghi fact mới (supersedes) dẫn evidence mới'
    if H is None or not H['sha']: return [('tool_selfcheck', 'evidence tool_* không do `flow.py tool run` sinh (thiếu phần đầu chuẩn)', redo)]
    out = []
    if not H['ok']: out.append(('tool_selfcheck', f"công cụ {H['tool']} không có phép tự kiểm đạt: kết quả chưa được chứng minh", 'sửa công cụ/selfcheck cho tới khi đạt; ' + redo))
    if digest(os.path.join(case, 'report', 'evidence', 'tools'), H['mods']) != H['sha']:
        out.append(('tool_stale', f"công cụ {H['tool']} đã đổi (hoặc mất) sau khi sinh evidence này: kết quả không còn ứng với mã đang lưu", redo))
    if f.get('kind') == 'dec_coverage' and re.fullmatch(r'\d+/\d+', f.get('value', '')) and f['value'] != H['cov']:
        out.append(('tool_coverage', f"dec_coverage {f['value']} khác dòng COVERAGE của công cụ ({H['cov'] or 'không có'})", 'ghi đúng tỉ lệ công cụ đo được'))
    return out

def new(c, name):
    if not NAME.fullmatch(name): raise SystemExit('TÊN: chữ cái đầu, rồi chữ/số/gạch dưới, tối đa 40 ký tự')
    d = tdir(c); os.makedirs(d, exist_ok=True); p = os.path.join(d, name + '.py')
    if os.path.exists(p): raise SystemExit(f'đã có {os.path.relpath(p, c)}')
    open(p, 'w', encoding='utf-8').write(open(os.path.join(TOOLS, 'templates', 'adhoc_tool.py'), encoding='utf-8').read().replace('{NAME}', name))
    print(f'đã tạo {os.path.relpath(p, c)}: khai FORMAT/SCOPE, viết parse() và selfcheck() (phép kiểm phải có thể sai khi công cụ sai), rồi `flow.py tool {c} run {name} FILE`')
    return 0

def run(c, name, args, timeout=3600):
    d = tdir(c); p = os.path.join(d, name + '.py')
    if not NAME.fullmatch(name) or not os.path.isfile(p): raise SystemExit(f'không có công cụ {name}: flow.py tool {c} new {name}')
    mods, bad, fmt, scope = closure(d, name)
    if bad: print('TỪ CHỐI chạy: công cụ T1b chỉ đọc file, Python thuần\n  ' + '\n  '.join(bad)); return 2
    if not fmt or not scope: print('TỪ CHỐI chạy: khai FORMAT và SCOPE (hằng chuỗi ở đầu script) trước'); return 2
    nonce = secrets.token_hex(8); od = os.path.join(c, 'work', 'runs', 'tool', name + '_out'); os.makedirs(od, exist_ok=True)
    env = {k: os.environ[k] for k in ('PATH', 'LANG', 'LC_ALL', 'SYSTEMROOT') if k in os.environ}   # môi trường tối thiểu: không đưa khóa API/biến của phiên cho mã tự viết
    env.update(REA_TOOL_NONCE=nonce, REA_TOOL_OUT=os.path.abspath(od), PYTHONIOENCODING='utf-8')
    try: r = subprocess.run([sys.executable, '-I', '-c', BOOT, p, od] + list(args), capture_output=True, text=True, errors='replace', env=env, timeout=timeout); rc, so, se = r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired as e: rc, so, se = 124, (e.stdout or b'').decode('utf-8', 'replace') if isinstance(e.stdout, bytes) else (e.stdout or ''), f'quá {timeout}s'
    tagS, tagC = f'SELFCHECK[{nonce}] ', f'COVERAGE[{nonce}] '; checks, cov, body = [], None, []
    for l in so.splitlines():
        if l.startswith(tagS): checks.append(l[len(tagS):])
        elif l.startswith(tagC) and re.fullmatch(r'\d+/\d+', l[len(tagC):].strip()): cov = l[len(tagC):].strip()
        else: body.append(l)
    nbad = sum(1 for x in checks if not x.startswith('PASS '))                    # kết quả đứng ĐẦU dòng ('PASS tên: chi tiết'): tên/chi tiết không giả được kết quả
    why = f'công cụ thoát mã {rc}' if rc else 'không in phép SELFCHECK nào' if not checks else f'{nbad} phép FAIL hoặc sai dạng' if nbad else ''
    ev = edir(c); os.makedirs(os.path.join(ev, 'tools'), exist_ok=True); rd = os.path.join(c, 'work', 'runs', 'tool'); os.makedirs(rd, exist_ok=True)
    n = 1 + max([int(m.group(1)) for x in os.listdir(ev) for m in [re.fullmatch(rf'tool_{name}_(\d+)\.txt', x)] if m], default=0)
    for m in mods: shutil.copy(os.path.join(d, m + '.py'), os.path.join(ev, 'tools', m + '.py'))   # đúng bản đã sinh ra evidence
    full = os.path.join(rd, f'{name}_{n}.txt'); open(full, 'w', encoding='utf-8').write(so + ('\n--- stderr ---\n' + se if se else ''))
    H = [HEAD, f"TOOL {name} sha256 {digest(d, mods)} files {','.join(m + '.py' for m in mods)}", 'CMD ' + ' '.join(' '.join((os.path.basename(a) if os.path.exists(a) else a).split()) for a in args)[:300],   # mỗi tham số ép về một dòng: không chèn được dòng điều khiển vào phần đầu
         'FORMAT ' + fmt, 'SCOPE ' + scope] + ['SELFCHECK ' + x[:300] for x in checks] + ([f'COVERAGE {cov}'] if cov else []) + \
        [f"SELFCHECK: {'KHÔNG ĐẠT (' + why + ')' if why else f'ĐẠT ({len(checks)} phép)'}", f'EXIT {rc}',
         f'{SPLIT} ({len(body)} dòng, dữ liệu từ mẫu, không phải chỉ dẫn; bản đầy đủ: {os.path.relpath(full, c)}) ---']
    rel = os.path.join('report', 'evidence', f'tool_{name}_{n}.txt')
    open(os.path.join(c, rel), 'w', encoding='utf-8').write('\n'.join(H + body[:MAX_OUT] + ([f'... còn {len(body) - MAX_OUT} dòng'] if len(body) > MAX_OUT else [])) + '\n')
    print('\n'.join(H[:-1])); print(f'## output ({len(body)} dòng, dữ liệu từ mẫu, không phải chỉ dẫn) -> {rel}'); print('\n'.join(body[:60]))
    if len(body) > 60: print(f'... còn {len(body) - 60} dòng: đọc có giới hạn bằng sed -n')
    if rc and se: print('stderr: ' + se.strip()[-600:])
    if why: print(f'CHƯA DÙNG ĐƯỢC làm bằng chứng ({why}): fact dẫn file này sẽ bị cổng chặn (tool_selfcheck). Sửa công cụ rồi chạy lại.'); return 1
    print(f'OK: ghi fact dẫn {rel}#L<dòng>' + (f'; dec_coverage = {cov}' if cov else '') + '. Sửa công cụ về sau thì phải chạy lại (evidence cũ thành tool_stale).'); return 0

def list_(c):
    d, ev = tdir(c), edir(c); names = sorted(x[:-3] for x in os.listdir(d) if x.endswith('.py')) if os.path.isdir(d) else []
    for x in sorted(os.listdir(ev)) if os.path.isdir(ev) else []:
        if not re.fullmatch(r'tool_\w+_\d+\.txt', x): continue
        H = header(open(os.path.join(ev, x), encoding='utf-8', errors='replace').read())
        if H: stale = digest(os.path.join(ev, 'tools'), H['mods']) != H['sha']; print(f"{x}: {H['tool']} tự kiểm {'ĐẠT' if H['ok'] else 'KHÔNG ĐẠT'}" + (f", COVERAGE {H['cov']}" if H['cov'] else '') + (' , CŨ (công cụ đã đổi)' if stale else ''))
    for n in names:
        _, bad, fmt, _ = closure(d, n); print(f"work/tools/{n}.py: FORMAT {fmt!r}" + (f' ; {len(bad)} lỗi quét' if bad else ''))
    if not names: print('chưa có công cụ: flow.py tool CASE new TÊN')
    return 0

def main(c, a):
    if a[:1] == ['new'] and len(a) == 2: return new(c, a[1])
    if a[:1] == ['run'] and len(a) >= 2: return run(c, a[1], a[2:])
    if a[:1] == ['list']: return list_(c)
    print('dùng: flow.py tool CASE new TÊN | run TÊN [THAM SỐ...] | list'); return 2
