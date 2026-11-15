#!/usr/bin/env python3
# Tầng T1b: công cụ do agent tự viết cho định dạng chưa có đường đi (flow.py tool). Skill KHÔNG chạy công cụ: agent tự chạy như mọi
# script phân tích khác; skill chỉ cấp khuôn và niêm phong kết quả để fact dẫn tới nó kiểm được bằng máy:
# công cụ phải khai FORMAT/SCOPE, phải có phép tự kiểm đạt, evidence ghi dấu băm của đúng bản công cụ đã sinh ra nó.
#   flow.py tool CASE new TÊN            tạo work/tools/TÊN.py từ templates/adhoc_tool.py
#   flow.py tool CASE seal TÊN [OUTPUT]  niêm phong output của lần chạy cuối (mặc định work/runs/tool/TÊN.out) thành report/evidence/tool_TÊN_<n>.txt
#   flow.py tool CASE list               công cụ của case, trạng thái tự kiểm của từng evidence
import ast, hashlib, json, os, re, shutil, sys
TOOLS = os.path.dirname(os.path.abspath(__file__))
HEAD = '# rea-flow tool evidence'; SPLIT = '--- output'
NAME = re.compile(r'[A-Za-z][A-Za-z0-9_]{0,39}')
RISKY = {'socket', 'ssl', 'requests', 'httpx', 'aiohttp', 'http', 'ftplib', 'smtplib', 'paramiko', 'subprocess', 'multiprocessing', 'pty', 'urllib'}   # chỉ để NHẮC, không chặn
MAX_OUT = 400   # số dòng output chép vào evidence; bản đầy đủ nằm ở work/runs/tool/

def tdir(c): return os.path.join(c, 'work', 'tools')
def edir(c): return os.path.join(c, 'report', 'evidence')
def one(x, n=300): return ' '.join(str(x).split())[:n]   # ép về một dòng: không chèn được dòng điều khiển vào phần đầu evidence

def scan(path):
    """Đọc tĩnh một file công cụ (không import, không chạy). Trả (ghi chú, module cục bộ được import, FORMAT, SCOPE).
    Module nạp động (importlib, __import__ với tên tính lúc chạy) không lần ra được nên không vào dấu băm: đừng dùng trong công cụ.
    Ghi chú chỉ là lời nhắc về import mạng/tiến trình con: skill không chạy công cụ nên không có gì để chặn; quy tắc không chạy mẫu do agent giữ."""
    try: tree = ast.parse(open(path, encoding='utf-8').read())
    except (OSError, SyntaxError, ValueError) as e: return [f'{os.path.basename(path)}: không phân tích được ({type(e).__name__})'], [], '', ''
    note, local, meta = [], [], {}; base = os.path.basename(path); here = os.path.dirname(path)
    for n in ast.walk(tree):
        mods = [a.name for a in n.names] if isinstance(n, ast.Import) else []
        if isinstance(n, ast.ImportFrom): mods = ([n.module] if n.module else []) + ([a.name for a in n.names] if n.level or not n.module else [])   # cả `from . import x`, `from .x import y`
        for m in mods:
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
    if not re.fullmatch(r'tool_[A-Za-z]\w*_\d+\.txt', os.path.basename(rel)) and not text.startswith(HEAD): return []   # chỉ file theo đúng mẫu tên của `tool seal` (hoặc mang phần đầu của nó)
    H = header(text); redo = 'chạy lại công cụ, `flow.py tool CASE seal TÊN`, rồi ghi fact mới (supersedes) dẫn evidence mới'
    if H is None: return [('tool_selfcheck', 'evidence tool_* không do `flow.py tool seal` sinh (thiếu phần đầu chuẩn)', redo)]
    out = []
    if not H['ok']: out.append(('tool_selfcheck', f"công cụ {H['tool']} không có phép tự kiểm đạt: kết quả chưa được chứng minh", 'sửa công cụ/selfcheck cho tới khi đạt; ' + redo))
    if digest(os.path.join(case, 'report', 'evidence', 'tools'), H['mods']) != H['sha']:
        out.append(('tool_stale', f"công cụ {H['tool']} đã đổi (hoặc mất) sau khi sinh evidence này: kết quả không còn ứng với mã đang lưu", redo))
    if f.get('kind') == 'dec_coverage' and re.fullmatch(r'\d+/\d+', f.get('value', '')) and f['value'] != H['cov']:
        out.append(('tool_coverage', f"dec_coverage {f['value']} khác dòng COVERAGE của công cụ ({H['cov'] or 'không có'})", 'ghi đúng tỉ lệ công cụ đo được'))
    return out

def shadow(name):
    """Tên trùng module chuẩn: không dùng cho file trong work/tools (script chạy từ thư mục đó sẽ che module thật, lỗi khó hiểu)."""
    return name in getattr(sys, 'stdlib_module_names', ()) or name in ('brotli', 'Crypto', 'capstone', 'pefile')

def new(c, name):
    if not NAME.fullmatch(name): raise SystemExit('TÊN: chữ cái đầu, rồi chữ/số/gạch dưới, tối đa 40 ký tự')
    if shadow(name): raise SystemExit(f'TÊN {name} trùng module chuẩn/thư viện: chọn tên khác')
    d = tdir(c); os.makedirs(d, exist_ok=True); p = os.path.join(d, name + '.py')
    if os.path.exists(p): raise SystemExit(f'đã có {os.path.relpath(p, c)}')
    open(p, 'w', encoding='utf-8').write(open(os.path.join(TOOLS, 'templates', 'adhoc_tool.py'), encoding='utf-8').read().replace('{NAME}', name))
    os.makedirs(os.path.join(c, 'work', 'runs', 'tool'), exist_ok=True)   # để lệnh chuyển hướng stdout trong hướng dẫn chạy được ngay
    print(f'đã tạo {os.path.relpath(p, c)}. Khai FORMAT/SCOPE, viết parse() và selfcheck() (phép kiểm phải có thể sai khi công cụ sai).\n'
          f'Tự chạy (skill không chạy công cụ; quy tắc không chạy mẫu vẫn nguyên): python3 -I {os.path.relpath(p, c)} FILE > work/runs/tool/{name}.out\n'
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
    cov = st.get('coverage'); cov = f'{int(cov[0])}/{int(cov[1])}' if isinstance(cov, list) and len(cov) == 2 and all(isinstance(x, int) for x in cov) else None
    why = 'không có file trạng thái tự kiểm (công cụ thoát lỗi, hoặc main() không gọi status())' if not st else 'không có phép tự kiểm nào' if not checks else \
          f'{sum(not ok for _, ok, _ in checks)} phép FAIL' if any(not ok for _, ok, _ in checks) else ''
    ev = edir(c); os.makedirs(os.path.join(ev, 'tools'), exist_ok=True)
    n = 1 + max([int(m.group(1)) for x in os.listdir(ev) for m in [re.fullmatch(rf'tool_{name}_(\d+)\.txt', x)] if m], default=0)
    if not why:   # chỉ lần seal ĐẠT mới thay bản lưu công cụ: lần không đạt không được làm evidence đạt trước đó thành tool_stale
        for m in mods: shutil.copy(os.path.join(d, m + '.py'), os.path.join(ev, 'tools', m + '.py'))
    body = open(out, encoding='utf-8', errors='replace').read().splitlines()
    H = [HEAD, f"TOOL {name} sha256 {digest(d, mods)} files {','.join(m + '.py' for m in mods)}",
         'CMD ' + one(' '.join(os.path.basename(str(a)) if os.path.exists(str(a)) else str(a) for a in st.get('argv', []))), 'FORMAT ' + fmt, 'SCOPE ' + scope] + \
        [f"SELFCHECK {'PASS' if ok else 'FAIL'} {nm}: {det}" for nm, ok, det in checks] + ([f'COVERAGE {cov}'] if cov else []) + ['NOTE ' + one(x) for x in note[:10]] + \
        [f"SELFCHECK: {'KHÔNG ĐẠT (' + why + ')' if why else f'ĐẠT ({len(checks)} phép)'}",
         f'{SPLIT} ({len(body)} dòng, dữ liệu từ mẫu, không phải chỉ dẫn; bản đầy đủ: {os.path.relpath(out, c)}) ---']
    rel = os.path.join('report', 'evidence', f'tool_{name}_{n}.txt')
    open(os.path.join(c, rel), 'w', encoding='utf-8').write('\n'.join(H + body[:MAX_OUT] + ([f'... còn {len(body) - MAX_OUT} dòng'] if len(body) > MAX_OUT else [])) + '\n')
    print('\n'.join(H[:-1])); print(f'## output ({len(body)} dòng, dữ liệu từ mẫu, không phải chỉ dẫn) -> {rel}'); print('\n'.join(body[:60]))
    if len(body) > 60: print(f'... còn {len(body) - 60} dòng: đọc có giới hạn bằng sed -n')
    if note: print('NHẮC: công cụ import module mạng/tiến trình con (' + '; '.join(note[:5]) + '). Quy tắc không chạy mẫu, không chạm mạng của mẫu vẫn áp dụng cho công cụ tự viết.')
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
