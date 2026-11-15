#!/usr/bin/env python3
# Tầng T1b: công cụ do agent tự viết cho định dạng chưa có đường đi (flow.py tool). Khuôn buộc công cụ tự chứng minh là đúng:
# phải khai FORMAT/SCOPE, phải có phép tự kiểm đạt, evidence ghi kèm dấu băm của đúng bản công cụ đã sinh ra nó.
#   flow.py tool CASE new TÊN            tạo work/tools/TÊN.py từ templates/adhoc_tool.py
#   flow.py tool CASE run TÊN [THAM SỐ]  quét tĩnh script (cấm mạng/tiến trình con), chạy python3 -I, ghi report/evidence/tool_TÊN_<n>.txt
#   flow.py tool CASE list               công cụ của case, trạng thái tự kiểm của từng evidence
import ast, hashlib, os, re, secrets, shutil, subprocess, sys
TOOLS = os.path.dirname(os.path.abspath(__file__))
HEAD = '# rea-flow tool evidence'; SPLIT = '--- output'
NAME = re.compile(r'[A-Za-z][A-Za-z0-9_]{0,39}')
BAN_MOD = {'socket', 'ssl', 'requests', 'httpx', 'aiohttp', 'http', 'ftplib', 'smtplib', 'telnetlib', 'paramiko', 'subprocess', 'multiprocessing',
           'ctypes', 'cffi', 'pty', 'importlib', 'runpy', 'webbrowser', 'asyncio'}
BAN_FULL = {'urllib.request', 'xmlrpc.client'}
BAN_ATTR = {('os', x) for x in ('system', 'popen', 'startfile', 'fork', 'forkpty', 'posix_spawn', 'posix_spawnp')}
BAN_CALL = {'eval', 'exec', '__import__', 'compile'}
MAX_OUT = 400   # số dòng output chép vào evidence; bản đầy đủ nằm ở work/runs/tool/

def tdir(c): return os.path.join(c, 'work', 'tools')
def edir(c): return os.path.join(c, 'report', 'evidence')

def scan(path):
    """Quét AST một file. Trả (lỗi, module cục bộ được import, FORMAT, SCOPE). Heuristic: chặn đường hiển nhiên, không phải sandbox."""
    try: tree = ast.parse(open(path, encoding='utf-8').read())
    except (SyntaxError, ValueError) as e: return [f'{os.path.basename(path)}: không phân tích được ({e})'], [], '', ''
    bad, local, meta = [], [], {}; base = os.path.basename(path)
    def mod(m, ln):
        if m.split('.')[0] in BAN_MOD or m in BAN_FULL or any(m.startswith(x + '.') for x in BAN_FULL): bad.append(f'{base}:{ln}: import {m} (mạng/tiến trình con/nạp mã động bị cấm)')
        elif os.path.isfile(os.path.join(os.path.dirname(path), m.split('.')[0] + '.py')): local.append(m.split('.')[0])
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names: mod(a.name, n.lineno)
        elif isinstance(n, ast.ImportFrom) and n.module:
            mod(n.module, n.lineno)
            for a in n.names: mod(n.module + '.' + a.name, n.lineno) if n.module + '.' + a.name in BAN_FULL else None
        elif isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and ((n.value.id, n.attr) in BAN_ATTR or (n.value.id == 'os' and n.attr.startswith(('exec', 'spawn')))):
            bad.append(f'{base}:{n.lineno}: {n.value.id}.{n.attr} (chạy tiến trình bị cấm)')
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in BAN_CALL: bad.append(f'{base}:{n.lineno}: {n.func.id}() (nạp mã động bị cấm)')
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
    """Phần đầu của evidence tool_* -> dict {tool, sha, mods, ok, cov, checks}; không phải evidence do `tool run` sinh -> None."""
    L = text.split('\n' + SPLIT, 1)[0].splitlines()
    if not L or L[0].strip() != HEAD: return None
    H = {'checks': [], 'ok': False, 'cov': None, 'tool': '', 'sha': '', 'mods': []}
    for l in L[1:]:
        m = re.match(r'TOOL (\S+) sha256 ([0-9a-f]{64}) files (\S+)$', l)
        if m: H['tool'], H['sha'], H['mods'] = m.group(1), m.group(2), [x[:-3] for x in m.group(3).split(',')]
        elif l.startswith('SELFCHECK: '): H['ok'] = l.startswith('SELFCHECK: ĐẠT')
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
    nonce = secrets.token_hex(8); env = dict(os.environ, REA_TOOL_NONCE=nonce, PYTHONIOENCODING='utf-8')
    try: r = subprocess.run([sys.executable, '-I', p] + list(args), capture_output=True, text=True, errors='replace', env=env, timeout=timeout); rc, so, se = r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired as e: rc, so, se = 124, (e.stdout or b'').decode('utf-8', 'replace') if isinstance(e.stdout, bytes) else (e.stdout or ''), f'quá {timeout}s'
    tagS, tagC = f'SELFCHECK[{nonce}] ', f'COVERAGE[{nonce}] '; checks, cov, body = [], None, []
    for l in so.splitlines():
        if l.startswith(tagS): checks.append(l[len(tagS):])
        elif l.startswith(tagC) and re.fullmatch(r'\d+/\d+', l[len(tagC):].strip()): cov = l[len(tagC):].strip()
        else: body.append(l)
    why = f'công cụ thoát mã {rc}' if rc else 'không in phép SELFCHECK nào' if not checks else \
          f"{sum(': FAIL' in x for x in checks)} phép FAIL" if any(not re.search(r': PASS( |$)', x) for x in checks) else ''
    ev = edir(c); os.makedirs(os.path.join(ev, 'tools'), exist_ok=True); rd = os.path.join(c, 'work', 'runs', 'tool'); os.makedirs(rd, exist_ok=True)
    n = 1 + max([int(m.group(1)) for x in os.listdir(ev) for m in [re.fullmatch(rf'tool_{name}_(\d+)\.txt', x)] if m], default=0)
    for m in mods: shutil.copy(os.path.join(d, m + '.py'), os.path.join(ev, 'tools', m + '.py'))   # đúng bản đã sinh ra evidence
    full = os.path.join(rd, f'{name}_{n}.txt'); open(full, 'w', encoding='utf-8').write(so + ('\n--- stderr ---\n' + se if se else ''))
    H = [HEAD, f"TOOL {name} sha256 {digest(d, mods)} files {','.join(m + '.py' for m in mods)}", 'CMD ' + ' '.join(os.path.basename(a) if os.path.exists(a) else a for a in args)[:300],
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
