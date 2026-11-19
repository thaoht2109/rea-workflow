#!/usr/bin/env python3
# Tầng T1b: công cụ do agent tự viết cho định dạng chưa có đường đi (flow.py tool). Skill KHÔNG chạy công cụ: agent tự chạy như mọi
# script phân tích khác; skill chỉ cấp khuôn và niêm phong kết quả để fact dẫn tới nó kiểm được bằng máy:
# công cụ phải khai FORMAT/SCOPE, phải có phép tự kiểm đạt (khuôn tự thử đột biến và đáp án biết trước), không dùng thành phần bị cấm, evidence ghi dấu băm của đúng bản công cụ đã sinh ra nó.
#   flow.py tool CASE new TÊN            tạo work/tools/TÊN.py từ templates/adhoc_tool.py
#   flow.py tool CASE seal TÊN [OUTPUT]  niêm phong output của lần chạy cuối (mặc định work/runs/tool/TÊN.out) thành report/evidence/tool_TÊN_<n>.txt
#   flow.py tool CASE list               công cụ của case, trạng thái tự kiểm của từng evidence
import ast, hashlib, json, os, re, shutil, sys
TOOLS = os.path.dirname(os.path.abspath(__file__))
HEAD = '# rea-flow tool evidence'; SPLIT = '--- output'
NAME = re.compile(r'[A-Za-z][A-Za-z0-9_]{0,39}')
RISKY = {'socket', 'ssl', 'requests', 'httpx', 'aiohttp', 'http', 'ftplib', 'smtplib', 'paramiko', 'subprocess', 'multiprocessing', 'pty', 'urllib',
         'ctypes', 'cffi', 'marshal', 'pickle', 'shelve', 'importlib', 'imp', 'runpy', 'code', 'codeop'}   # mạng, tiến trình con, nạp/chạy mã động: `seal` đánh KHÔNG ĐẠT
BADCALL = {'exec', 'eval', '__import__'}; BADOS = {'system', 'popen', 'fork', 'forkpty', 'startfile'}   # os.<tên>, os.exec*, os.spawn*, os.posix_spawn*
def bados(x): return x in BADOS or x.startswith(('exec', 'spawn', 'posix_spawn'))
MAX_OUT = 400   # số dòng output chép vào evidence; bản đầy đủ nằm ở work/runs/tool/

def tdir(c): return os.path.join(c, 'work', 'tools')
def edir(c): return os.path.join(c, 'report', 'evidence')
def one(x, n=300): return ' '.join(str(x).split())[:n]   # ép về một dòng: không chèn được dòng điều khiển vào phần đầu evidence

def scan(path):
    """Đọc tĩnh một file công cụ (không import, không chạy). Trả (ghi chú, module cục bộ được import, FORMAT, SCOPE).
    Module nạp động (importlib, __import__ với tên tính lúc chạy) không lần ra được nên không vào dấu băm: đừng dùng trong công cụ.
    Ghi chú liệt kê import/gọi bị cấm (mạng, tiến trình con, nạp mã động, exec/eval, os.system...): `seal` đánh KHÔNG ĐẠT. Đây là lưới bắt sai sót vô ý, không phải
    hộp cát (tên dựng động lách được): skill không chạy công cụ; cô lập thật là việc của vỏ bwrap mà `tool new` hướng dẫn."""
    try: tree = ast.parse(open(path, encoding='utf-8').read())
    except (OSError, SyntaxError, ValueError) as e: return [f'{os.path.basename(path)}: không phân tích được ({type(e).__name__})'], [], '', ''
    note, local, meta = [], [], {}; base = os.path.basename(path); here = os.path.dirname(path)
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name) and f.id in BADCALL: note.append(f'{base}:{n.lineno}: gọi {f.id}()')
            elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == 'os' and bados(f.attr): note.append(f'{base}:{n.lineno}: gọi os.{f.attr}()')
        mods = [a.name for a in n.names] if isinstance(n, ast.Import) else []
        if isinstance(n, ast.ImportFrom): mods = ([n.module] if n.module else []) + ([a.name for a in n.names] if n.level or not n.module else [])   # cả `from . import x`, `from .x import y`
        if isinstance(n, ast.ImportFrom) and n.module == 'os' and not n.level: note += [f'{base}:{n.lineno}: from os import {x.name}' for x in n.names if bados(x.name)]
        for m in mods:
            if m == 'urllib' and isinstance(n, ast.ImportFrom) and not n.level and {x.name for x in n.names} <= {'parse'}: continue      # from urllib import parse = urllib.parse
            top = m.split('.')[0]
            if os.path.isfile(os.path.join(here, top + '.py')): local.append(top)
            elif top in RISKY and m != 'urllib.parse': note.append(f'{base}:{n.lineno}: import {m}')
    for n in tree.body:   # FORMAT/SCOPE: chỉ nhận hằng chuỗi gán ở mức module
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id in ('FORMAT', 'SCOPE') \
                and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str): meta[n.targets[0].id] = one(n.value.value, 200)
    return note, local, meta.get('FORMAT', ''), meta.get('SCOPE', '')

def closure(d, name):
    """Script chính + mọi module cục bộ nó import (đệ quy). Trả (danh sách file theo thứ tự ổn định, ghi chú, FORMAT, SCOPE)."""
    seen, todo, note = [], [name], []; fmt = scope = ''
    while todo:
        m = todo.pop(0)
        if m in seen: continue
        seen.append(m); b, loc, f, s = scan(os.path.join(d, m + '.py')); note += b; todo += loc
        if m == name: fmt, scope = f, s
    return [name] + sorted(x for x in seen if x != name), note, fmt, scope

def digest(d, mods):
    """Dấu băm của một bản công cụ: tên + nội dung từng file. Đổi bất kỳ file nào thì evidence cũ thành 'tool_stale'."""
    h = hashlib.sha256()
    for m in mods:
        p = os.path.join(d, m + '.py')
        if not os.path.isfile(p): return None
        b = open(p, 'rb').read(); h.update(f'{m}.py\0{len(b)}\0'.encode() + b)
    return h.hexdigest()

def header(text):
    """Phần đầu của evidence tool_* -> dict {tool, sha, mods, ok, cov, checks}; không phải evidence do `tool seal` sinh -> None.
    Bố cục cố định: dòng 2 là TOOL, dòng 3 CMD, 4 FORMAT, 5 SCOPE, sau đó mới tới SELFCHECK/COVERAGE (không nhận các dòng này ở vị trí khác)."""
    L = text.split('\n' + SPLIT, 1)[0].splitlines()
    if len(L) < 5 or L[0].strip() != HEAD: return None
    H = {'checks': [], 'ok': False, 'cov': None, 'out': None, 'tool': '', 'sha': '', 'mods': [], 'mut': None, 'kat': None, 'katw': None, 'net': None}
    m = re.fullmatch(r'TOOL (\S+) sha256 ([0-9a-f]{64}) files (\S+)', L[1])
    if not m or not L[2].startswith('CMD ') or not L[3].startswith('FORMAT ') or not L[4].startswith('SCOPE '): return None
    H['tool'], H['sha'], H['mods'] = m.group(1), m.group(2), [x[:-3] for x in m.group(3).split(',')]
    for l in L[5:]:
        if l.startswith('SELFCHECK: '): H['ok'] = l.startswith('SELFCHECK: ĐẠT')
        elif l.startswith('SELFCHECK '): H['checks'].append(l)
        elif re.fullmatch(r'COVERAGE \d+/\d+', l): H['cov'] = l.split()[1]
        elif re.fullmatch(r'OUT sha256 [0-9a-f]{64}', l): H['out'] = l.split()[2]
        elif re.fullmatch(r'MUTATION \d+/\d+', l): H['mut'] = tuple(map(int, l.split()[1].split('/')))
        elif re.fullmatch(r'KAT \d+/\d+', l): H['kat'] = tuple(map(int, l.split()[1].split('/')))
        elif l.startswith('KAT n/a: '): H['katw'] = l[9:]
        elif l.startswith('ISOLATION net='): H['net'] = l[14:]
    return H

def fsha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''): h.update(b)
    return h.hexdigest()

def body_sha(text):
    """Dấu băm phần output của evidence (mọi dòng sau dòng SPLIT), chuẩn hóa theo dòng để lint (đọc theo dòng) và cổng (đọc cả file) ra cùng giá trị."""
    tail = text.split('\n' + SPLIT, 1)[1:]; lines = tail[0].split('\n')[1:] if tail else []
    while lines and not lines[-1]: lines.pop()
    return hashlib.sha256('\n'.join(lines).encode('utf-8', 'replace')).hexdigest()

def sealed(case, rel, text):
    """File này có phải evidence của `tool seal` không. Một tiêu chí cho cả lint, review.mech và review.gate:
    mang phần đầu của seal, HOẶC tên tool_<TÊN>_<n>.txt mà case có công cụ TÊN (xóa dòng đầu không thoát được luật).
    File tên tool_* có từ trước, không ứng với công cụ nào của case, không bị áp luật."""
    if text.startswith(HEAD): return True
    m = re.fullmatch(r'tool_(\w+)_\d+\.txt', os.path.basename(rel))
    return bool(m) and any(os.path.isfile(os.path.join(d, m.group(1) + '.py')) for d in (os.path.join(edir(case), 'tools'), tdir(case)))

def notes(case, f, rel, text):
    """Cảnh báo (không chặn cổng) cho fact dẫn evidence tool_*: công cụ chạy khi còn thấy giao diện mạng (không trong vỏ bwrap).
    Trả [(check, vấn đề, cách sửa)]; lint ghi mức warn, lớp 1 phản biện ghi weak."""
    if not sealed(case, rel, text): return []
    H = header(text)
    if H is None or not str(H.get('net', '')).startswith('có'): return []
    return [('tool_isolation', f"công cụ {H['tool']} chạy khi còn thấy giao diện mạng (ISOLATION net={H['net']}): không trong vỏ không mạng",
             'chạy lại bằng lệnh bwrap mà `tool new` in ra (file dẫn xuất ghi vào OUT_DIR = work/runs/tool/TÊN/), seal lại, ghi fact mới (supersedes); '
             'không chạy lại được thì nêu ở mục hạn chế của báo cáo')]

def issues(case, f, rel, text):
    """Luật cổng cho fact dẫn evidence tool_*, dùng chung cho lint khi ghi (case.lint_fact) và lớp 1 phản biện (review.mech).
    Trả [(check, vấn đề, cách sửa)]."""
    if not sealed(case, rel, text): return []
    H = header(text); redo = 'chạy lại công cụ, `flow.py tool CASE seal TÊN`, rồi ghi fact mới (supersedes) dẫn evidence mới'
    if H is None: return [('tool_selfcheck', 'evidence tool_* không do `flow.py tool seal` sinh (thiếu phần đầu chuẩn)', redo)]
    out = []
    if not H['ok']: out.append(('tool_selfcheck', f"công cụ {H['tool']} không có phép tự kiểm đạt: kết quả chưa được chứng minh", 'sửa công cụ/selfcheck cho tới khi đạt; ' + redo))
    if digest(os.path.join(case, 'report', 'evidence', 'tools'), H['mods']) != H['sha']:
        out.append(('tool_stale', f"công cụ {H['tool']} đã đổi (hoặc mất) sau khi sinh evidence này: kết quả không còn ứng với mã đang lưu", redo))
    elif H['out'] != body_sha(text):
        out.append(('tool_stale', f"phần output của evidence đã bị sửa sau khi niêm phong (dấu băm OUT {'thiếu' if not H['out'] else 'khác'})", redo))
    if H['mut'] and H['mut'][1] and H['mut'][0] == 0: out.append(('tool_mutation', f"công cụ {H['tool']}: phép tự kiểm không phát hiện được byte nào bị sửa (MUTATION {H['mut'][0]}/{H['mut'][1]}): không phân biệt được dữ liệu đúng với dữ liệu hỏng", 'viết lại selfcheck() cho phụ thuộc vào dữ liệu mẫu; ' + redo))
    if H['kat'] and H['kat'][0] < H['kat'][1]: out.append(('tool_kat', f"công cụ {H['tool']} sai đáp án biết trước (KAT {H['kat'][0]}/{H['kat'][1]})", 'sửa công cụ cho đúng các ca known_answers(); ' + redo))
    cv = re.search(r'\d+/\d+', f.get('value', '')) if f.get('kind') == 'dec_coverage' else None   # tỉ lệ đầu tiên trong value, kể cả khi có chữ kèm theo ('9/9 chuỗi')
    if cv and cv.group(0) != H['cov']:
        out.append(('tool_coverage', f"dec_coverage {cv.group(0)} khác dòng COVERAGE của công cụ ({H['cov'] or 'không có'})", 'ghi đúng tỉ lệ công cụ đo được'))
    return out

def shadow(name):
    """Tên trùng module chuẩn: không dùng cho file trong work/tools (script chạy từ thư mục đó sẽ che module thật, lỗi khó hiểu)."""
    return name in getattr(sys, 'stdlib_module_names', ()) or name in ('brotli', 'Crypto', 'capstone', 'pefile')

def new(c, name):
    if not NAME.fullmatch(name): raise SystemExit('TÊN: chữ cái đầu, rồi chữ/số/gạch dưới, tối đa 40 ký tự')
    if shadow(name): raise SystemExit(f'TÊN {name} trùng module chuẩn/thư viện: chọn tên khác')
    def head(x):
        with open(os.path.join(edir(c), x), encoding='utf-8', errors='replace') as fh: return fh.read(len(HEAD))
    old = [x for x in (sorted(os.listdir(edir(c))) if os.path.isdir(edir(c)) else []) if re.fullmatch(rf'tool_{name}_\d+\.txt', x) and head(x) != HEAD]
    if old: raise SystemExit(f'TÊN {name}: report/evidence đã có {old[0]} không do `tool seal` sinh; tạo công cụ tên này sẽ khiến fact dẫn file đó bị luật T1b chặn. Chọn tên khác.')
    d = tdir(c); os.makedirs(d, exist_ok=True); p = os.path.join(d, name + '.py')
    if os.path.exists(p): raise SystemExit(f'đã có {os.path.relpath(p, c)}')
    open(p, 'w', encoding='utf-8').write(open(os.path.join(TOOLS, 'templates', 'adhoc_tool.py'), encoding='utf-8').read().replace('{NAME}', name))
    os.makedirs(os.path.join(c, 'work', 'runs', 'tool'), exist_ok=True)   # để lệnh chuyển hướng stdout trong hướng dẫn chạy được ngay
    print(f'đã tạo {os.path.relpath(p, c)}. Khai FORMAT/SCOPE, viết parse() và selfcheck() (phép kiểm phải có thể sai khi công cụ sai).\n'
          f'Tự chạy (skill không chạy công cụ; quy tắc không chạy mẫu vẫn nguyên): python3 -I {os.path.relpath(p, c)} FILE > work/runs/tool/{name}.out\n'
          f'File dẫn xuất chỉ ghi vào OUT_DIR = work/runs/tool/{name}/ (vỏ chỉ cho ghi work/runs/tool/).\n'
          f'Chạy trong vỏ không mạng (net=có thì bị cảnh báo tool_isolation), từ thư mục case (agent tự chạy; case không nằm dưới /tmp): bwrap --unshare-all --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --bind "$PWD/work/runs/tool" "$PWD/work/runs/tool" python3 -I {os.path.relpath(p, c)} FILE > work/runs/tool/{name}.out\n'
          f'Khuôn tự thử đột biến (lật byte của file, selfcheck phải báo hỏng) và chạy known_answers() (dữ liệu tổng hợp có đáp án biết trước, dựng bằng thư viện chuẩn): viết known_answers() hoặc khai KAT_WAIVER.\n'
          f'Rồi niêm phong: flow.py tool {c} seal {name}')
    return 0

def seal(c, name, out=None):
    """Niêm phong lần chạy cuối của công cụ thành evidence. Không chạy gì: chỉ đọc file trạng thái và output do agent đã sinh."""
    d = tdir(c); p = os.path.join(d, name + '.py'); rd = os.path.join(c, 'work', 'runs', 'tool')
    if not NAME.fullmatch(name) or not os.path.isfile(p): raise SystemExit(f'không có công cụ {name}: flow.py tool {c} new {name}')
    mods, note, fmt, scope = closure(d, name); out = out or os.path.join(rd, name + '.out'); sp = os.path.join(rd, name + '.status.json')
    if not fmt or not scope: print('TỪ CHỐI: khai FORMAT và SCOPE (hằng chuỗi ở đầu script) rồi chạy lại công cụ'); return 2
    if not os.path.isfile(out): print(f'TỪ CHỐI: chưa có output {os.path.relpath(out, c)} (chạy công cụ, chuyển stdout vào đó)'); return 2
    try: st = json.load(open(sp, encoding='utf-8')); checks = [(one(n, 120).replace(':', ';'), bool(ok), one(det)) for n, ok, det in st['checks']]; ran = float(st['time'])
    except (OSError, ValueError, KeyError, TypeError): st, checks, ran = {}, [], 0.0
    newest = max(os.path.getmtime(os.path.join(d, m + '.py')) for m in mods)
    if st and ran < newest: print('TỪ CHỐI: công cụ đã sửa sau lần chạy cuối, output không còn ứng với mã hiện tại. Chạy lại công cụ rồi seal.'); return 2
    if st and st.get('out_sha256') != hashlib.sha256(open(out, 'rb').read()).hexdigest():   # ràng buộc chính xác: output phải đúng là stdout của lần chạy đã ghi trạng thái
        print('TỪ CHỐI: file output không phải stdout của lần chạy đã ghi trạng thái tự kiểm (dấu băm khác). Chạy lại công cụ, chuyển thẳng stdout vào file output, rồi seal.'); return 2
    root = os.path.realpath(c) + os.sep; ins = []      # file đầu vào: phải nằm trong case và chưa đổi từ lúc chạy, để evidence không lấy nhầm kết quả của file cùng tên ở nơi khác
    for x in st.get('inputs') if isinstance(st.get('inputs'), list) else []:
        if not (isinstance(x, list) and len(x) == 2 and all(isinstance(y, str) for y in x) and re.fullmatch(r'[0-9a-f]{64}', x[1])): continue
        rp = os.path.realpath(x[0])
        if rp.startswith(root) and not os.path.isfile(rp): print(f'TỪ CHỐI: file đầu vào {os.path.relpath(rp, root)} đã mất sau lần chạy. Đặt lại file, chạy lại công cụ rồi seal.'); return 2
        if rp.startswith(root):
            if fsha(rp) != x[1]: print(f'TỪ CHỐI: file đầu vào {os.path.relpath(rp, root)} đã đổi sau lần chạy. Chạy lại công cụ rồi seal.'); return 2
            ins.append((x[1], os.path.relpath(rp, root)))
    first = st.get('first') if isinstance(st.get('first'), str) else ''; oldtpl = bool(st) and ('inputs' not in st or 'mutation' not in st)
    def pair(v): return f'{int(v[0])}/{int(v[1])}' if isinstance(v, list) and len(v) == 2 and all(isinstance(x, int) and x >= 0 for x in v) else None
    mut = pair(st.get('mutation')); kat = st.get('kat') if isinstance(st.get('kat'), list) else []
    kat = [(one(x[0], 80), bool(x[1])) for x in kat if isinstance(x, list) and len(x) == 2]; katw = one(st.get('kat_waiver') or '', 200)
    net = st.get('net'); net = 'không rõ' if net is None else 'không' if not net else 'có (' + one(','.join(map(str, net)), 60) + ')'
    cov = st.get('coverage'); cov = f'{int(cov[0])}/{int(cov[1])}' if isinstance(cov, list) and len(cov) == 2 and all(isinstance(x, int) for x in cov) else None
    why = 'không có file trạng thái tự kiểm (công cụ thoát lỗi, hoặc main() không gọi status())' if not st else 'không có phép tự kiểm nào' if not checks else \
          f'{sum(not ok for _, ok, _ in checks)} phép FAIL' if any(not ok for _, ok, _ in checks) else \
          'công cụ viết theo khuôn cũ, không ghi dấu băm file đầu vào hoặc kết quả thử đột biến: chép các hàm từ status_path() trở xuống của templates/adhoc_tool.py vào công cụ rồi chạy lại' if oldtpl else \
          'file đầu vào (tham số đầu) không nằm trong thư mục case: chép nó vào work/extract/ rồi chạy lại' if not first or os.path.relpath(os.path.realpath(first), root) not in [r for _, r in ins] else \
          f"thử đột biến vô hiệu: {one(st.get('mut_note'), 200)}" if st.get('mut_note') else \
          'file đầu vào rỗng: không thử đột biến được' if st.get('empty') else \
          'chưa chạy thử đột biến: main() phải gọi status(checks, cov, _trials(path, dt)) như khuôn' if st.get('mutation') is None else \
          f'thử đột biến: selfcheck không phát hiện byte nào bị sửa ({mut}): phép kiểm không phụ thuộc dữ liệu mẫu, viết lại' + (f" ({int(st['mut_late'])} lần thử quá giờ không tính)" if isinstance(st.get('mut_late'), int) and st['mut_late'] > 0 else '') if not mut or mut.startswith('0/') else \
          f"sai đáp án biết trước: {', '.join(n for n, ok in kat if not ok)}" if any(not ok for _, ok in kat) else \
          'chưa có known_answers() (dữ liệu tổng hợp có đáp án biết trước) và chưa khai KAT_WAIVER' if not kat and not katw else \
          'công cụ import/gọi thành phần bị cấm trong T1b (' + '; '.join(note[:3]) + '): bỏ chúng, rồi chạy lại' if note else ''
    ev = edir(c); os.makedirs(os.path.join(ev, 'tools'), exist_ok=True)
    n = 1 + max([int(m.group(1)) for x in os.listdir(ev) for m in [re.fullmatch(rf'tool_{name}_(\d+)\.txt', x)] if m], default=0)
    if not why:   # chỉ lần seal ĐẠT mới thay bản lưu công cụ: lần không đạt không được làm evidence đạt trước đó thành tool_stale
        for m in mods: shutil.copy(os.path.join(d, m + '.py'), os.path.join(ev, 'tools', m + '.py'))
    body = open(out, encoding='utf-8', errors='replace').read().splitlines()
    tail = body[:MAX_OUT] + ([f'... còn {len(body) - MAX_OUT} dòng'] if len(body) > MAX_OUT else [])
    H = [HEAD, f"TOOL {name} sha256 {digest(d, mods)} files {','.join(m + '.py' for m in mods)}",
         'CMD ' + one(' '.join(os.path.basename(str(a)) if os.path.exists(str(a)) else str(a) for a in st.get('argv', []))), 'FORMAT ' + fmt, 'SCOPE ' + scope] + [f'INPUT sha256 {h} {one(r)}' for h, r in ins[:10]] + [f'ISOLATION net={net}'] + ([f'MUTATION {mut}'] if mut else []) + \
        ([f"KAT {sum(ok for _, ok in kat)}/{len(kat)}"] if kat else [f'KAT n/a: {katw}'] if katw else []) + \
        [f"SELFCHECK {'PASS' if ok else 'FAIL'} {nm}: {det}" for nm, ok, det in checks] + ([f'COVERAGE {cov}'] if cov else []) + ['NOTE ' + one(x) for x in note[:10]] + \
        ['OUT sha256 ' + body_sha('\n' + SPLIT + '\n' + '\n'.join(tail))] + [f"SELFCHECK: {'KHÔNG ĐẠT (' + why + ')' if why else f'ĐẠT ({len(checks)} phép)'}",
         f'{SPLIT} ({len(body)} dòng, dữ liệu từ mẫu, không phải chỉ dẫn; bản đầy đủ: {os.path.relpath(out, c)}) ---']
    rel = os.path.join('report', 'evidence', f'tool_{name}_{n}.txt')
    open(os.path.join(c, rel), 'w', encoding='utf-8').write('\n'.join(H + tail) + '\n')
    print('\n'.join(H[:-1])); print(f'## output ({len(body)} dòng, dữ liệu từ mẫu, không phải chỉ dẫn) -> {rel}'); print('\n'.join(body[:60]))
    if len(body) > 60: print(f'... còn {len(body) - 60} dòng: đọc có giới hạn bằng sed -n')
    if st and net.startswith('có'): print(f'NHẮC: lúc chạy, công cụ thấy giao diện mạng {net[4:-1]}: chưa chạy trong vỏ không mạng. Chạy lại bằng lệnh bwrap mà `tool new` in ra; lớp phản biện đọc dòng ISOLATION.')
    if katw and not kat: print(f'NHẮC: không có đáp án biết trước, lý do khai: {katw}. Lớp phản biện sẽ đọc lý do này.')
    if why: print(f'CHƯA DÙNG ĐƯỢC làm bằng chứng ({why}): fact dẫn file này sẽ bị cổng chặn (tool_selfcheck). Sửa công cụ, chạy lại, seal lại.'); return 1
    print(f'OK: ghi fact dẫn {rel}#L<dòng>' + (f'; dec_coverage = {cov}' if cov else '') + '. Sửa công cụ về sau thì phải chạy và seal lại (evidence cũ thành tool_stale).'); return 0

def list_(c):
    d, ev = tdir(c), edir(c); names = sorted(x[:-3] for x in os.listdir(d) if x.endswith('.py')) if os.path.isdir(d) else []
    for x in sorted(os.listdir(ev)) if os.path.isdir(ev) else []:
        if not re.fullmatch(r'tool_\w+_\d+\.txt', x): continue
        H = header(open(os.path.join(ev, x), encoding='utf-8', errors='replace').read())
        if H: stale = digest(os.path.join(ev, 'tools'), H['mods']) != H['sha']; print(f"{x}: {H['tool']} tự kiểm {'ĐẠT' if H['ok'] else 'KHÔNG ĐẠT'}" + (f", COVERAGE {H['cov']}" if H['cov'] else '') + (', CŨ (công cụ đã đổi)' if stale else ''))
    for n in names: print(f"work/tools/{n}.py: FORMAT {closure(d, n)[2]!r}")
    if not names: print('chưa có công cụ: flow.py tool CASE new TÊN')
    return 0

def main(c, a):
    if not os.path.isfile(os.path.join(c, 'facts.jsonl')): raise SystemExit(f'không phải thư mục case (thiếu facts.jsonl): {c}')
    if a[:1] == ['new'] and len(a) == 2: return new(c, a[1])
    if a[:1] == ['seal'] and len(a) in (2, 3): return seal(c, a[1], a[2] if len(a) == 3 else None)
    if a[:1] == ['list']: return list_(c)
    print('dùng: flow.py tool CASE new TÊN | seal TÊN [OUTPUT] | list'); return 2
