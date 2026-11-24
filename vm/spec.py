#!/usr/bin/env python3
# Tầng T5 (VM): đặc tả môi trường chạy mẫu, sinh TẤT ĐỊNH từ fact (kind env/observe) và triage. Skill không chứa mã gửi hay chạy mẫu:
# file này không mở kết nối mạng nào, không ghi bản chép nào của mẫu, không biết địa chỉ hay API của sandbox. Gửi mẫu là việc của cầu nối
# do người dùng tự cài ngoài skill (VM_BRIDGE_CMD); bản này chưa gọi cầu nối.
#   build(case)            work/vm/rN/vmspec.json + vm_task.md (cần cổng phản biện PASS khớp facts.jsonl hiện tại)
#   run(case, dry=True)    dựng lại đặc tả để so với bản trên đĩa (cổng, trần VM_*, hash mẫu); in yêu cầu sẽ giao cho cầu nối
#   next_hint(case)        dòng dẫn đường cho `flow.py next` khi case có câu hỏi cần VM trả lời
import os, re, sys, json, glob, shlex, hashlib

TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, TOOLS); import case as C, reacfg as CFG   # noqa: E402

VMDIR = lambda c: os.path.join(c, 'work', 'vm')
NETQ = {'dns', 'tls_sni', 'http', 'payload'}   # câu hỏi cần guest có mạng (ít nhất là bộ hứng)
DEF_DIR = {'windows': r'%USERPROFILE%\Downloads', 'linux': '/opt/sample'}   # thư mục TRONG GUEST khi không có fact layout
DEF_TIME = 300
_ELF = {('x86_64', 'LE', '64'): 'x64', ('x86', 'LE', '32'): 'x86', ('MIPS', 'BE', '32'): 'mips', ('MIPS', 'LE', '32'): 'mipsel',
        ('ARM', 'LE', '32'): 'arm', ('AArch64', 'LE', '64'): 'aarch64'}

def sha(p): return hashlib.sha256(open(p, 'rb').read()).hexdigest()
def die(msg): raise SystemExit('CHẶN vm: ' + msg)
UNSAFE = re.compile(r'[\x00-\x1f\x7f`]')
def safe(x): return UNSAFE.sub('?', str(x))[:200]   # tên lấy từ mẫu khi in ra: không xuống dòng, không dấu ` (dòng in là dẫn đường cho agent)
def net_rank(m): return C.NET_MODES.index(m) if m in C.NET_MODES else len(C.NET_MODES)   # mức lạ (cấu hình gõ sai): coi như cao nhất, không bao giờ được chọn làm trần

def guest_of(t):
    """Nền của guest suy từ chuỗi `type` của triage ('PE32+', 'ELF32 MIPS BE EXEC'…); không suy được thì None (cần fact env t=guest)."""
    if t.startswith('PE32+'): return dict(os='windows', arch='x64')
    if t.startswith('PE32'): return dict(os='windows', arch='x86')
    m = re.match(r'ELF(32|64) (\S+) (LE|BE)\b', t)
    a = m and _ELF.get((m[2], m[3], m[1]))
    return dict(os='linux', arch=a) if a else None

def triage_types(c):
    """sha256 -> type, đọc từ evidence triage_*.json của case (triage tự ghi)."""
    r = {}
    for p in sorted(glob.glob(os.path.join(c, 'report', 'evidence', 'triage_*.json'))):
        try: d = json.load(open(p, encoding='utf-8'))
        except (OSError, ValueError): continue
        if isinstance(d, dict) and isinstance(d.get('sha256'), str) and isinstance(d.get('type'), str): r[d['sha256']] = d['type']
    return r

def facts(c):
    """Fact env/observe đang hiệu lực (active), theo id. Fact sai lược đồ làm dừng: tham số VM không được đoán."""
    F = sorted((f for f in C.load(c).values() if f['status'] == 'active' and f['kind'] in ('env', 'observe')), key=lambda f: f['id'])
    bad = [(safe(f['id']), C.env_issue(f)[0]) for f in F if C.env_issue(f)] + [(safe(f['id']), 'id có ký tự điều khiển, dấu ` hoặc khoảng trắng') for f in F if UNSAFE.search(f['id']) or re.search(r'\s', f['id'])]
    if bad: die('fact sai lược đồ: ' + '; '.join(f'{i}: {p}' for i, p in bad) + ' -> ghi fact mới (supersedes)')
    return [(f, json.loads(f['value'])) for f in F]

def observes(c):
    """id các fact observe active đúng lược đồ (câu hỏi cần VM trả lời). Không ném lỗi: dùng cho dòng dẫn đường."""
    return sorted(safe(f['id']) for f in C.load(c).values() if f['status'] == 'active' and f['kind'] == 'observe' and not C.env_issue(f))

def resolve(c, names):
    """Tên file trong layout -> file thật trong work/sample|extract (không theo symlink): khớp đường dẫn tương đối trước, rồi tên tệp duy nhất."""
    pool = [(p, os.path.relpath(p, os.path.join(c, 'work', d)).replace(os.sep, '/')) for d in ('sample', 'extract') for p in C.work_files(c, (d,), limit=1 << 62)]; out = []
    for n in names:
        key = n.replace('\\', '/')
        hit = [p for p, r in pool if r == key] or [p for p, r in pool if os.path.basename(r) == os.path.basename(key)]
        if UNSAFE.search(n) or len(n) > 300: die(f'tên file mẫu có ký tự điều khiển, dấu ` hoặc quá dài ({safe(n)}): không đưa vào đặc tả VM được; báo người dùng đổi tên bản chép trong work/sample')
        if len(hit) != 1: die(f'layout.files `{n}`: ' + ('không có trong work/sample|extract' if not hit else f'trùng {len(hit)} file, ghi đường dẫn tương đối trong work/sample'))
        src = os.path.relpath(hit[0], c).replace(os.sep, '/')
        if UNSAFE.search(src): die(f'đường dẫn file mẫu có ký tự điều khiển hoặc dấu ` ({safe(src)}): báo người dùng đổi tên bản chép trong work/sample')
        out.append(dict(name=n, src=src, sha256=sha(hit[0]), size=os.path.getsize(hit[0])))
    return out

def rounds(c):
    """(số vòng đã gửi, vòng đang soạn). Vòng đã gửi có task.json (ghi khi gọi cầu nối); vòng chưa gửi được sinh lại tại chỗ."""
    sent = [int(m[1]) for m in (re.fullmatch(r'r(\d+)', n) for n in (os.listdir(VMDIR(c)) if os.path.isdir(VMDIR(c)) else []))
            if m and os.path.exists(os.path.join(VMDIR(c), m[0], 'task.json'))]
    return (max(sent) if sent else 0), (max(sent) if sent else 0) + 1

def make(c):
    """vmspec dạng dict, chưa ghi đĩa. Mọi tham số có nguồn: fact (derived_from) hoặc triage; mặc định được ghi rõ trong `defaults`."""
    import review
    ok, why = review.gate(c)
    if not ok: die(f'cổng phản biện chưa đạt ({why}): tham số VM lấy từ fact nên fact phải qua phản biện trước -> flow.py review {shlex.quote(c)} --llm --detach')
    FV = facts(c); by = lambda t: [(f, v) for f, v in FV if f['kind'] == 'env' and v['t'] == t]
    obs = [(f, v) for f, v in FV if f['kind'] == 'observe']
    if not obs: die("chưa có fact observe active: VM phải có câu hỏi cần trả lời (kind=observe value='{\"q\":\"process_tree\"}', src S/E, evidence nêu vì sao tầng tĩnh/giả lập không lấy được)")
    defaults = []
    for t in ('guest', 'layout', 'time'):
        if len(by(t)) > 1: die(f"có {len(by(t))} fact env t={t} active ({', '.join(f['id'] for f, _ in by(t))}): chỉ được một, rút bớt bằng supersedes")
    lay = by('layout')
    if lay: layout = dict(dir=lay[0][1]['dir'], main=lay[0][1]['main']); names = lay[0][1]['files']
    else:
        smp = C.work_files(c, ('sample',), limit=1 << 62)
        if len(smp) != 1: die(f'case có {len(smp)} file mẫu mà chưa có fact env t=layout (thư mục đặt, danh sách file, file chạy chính)')
        names = [os.path.relpath(smp[0], os.path.join(c, 'work', 'sample')).replace(os.sep, '/')]; layout = dict(dir=None, main=names[0]); defaults.append('layout: một mẫu, thư mục mặc định theo nền')
    files = resolve(c, names)
    g = by('guest')
    if g: guest = dict(os=g[0][1]['os'], arch=g[0][1]['arch'])
    else:
        msha = next(x['sha256'] for x in files if x['name'] == layout['main'])
        guest = guest_of(triage_types(c).get(msha, ''))
        if not guest: die(f"không suy được nền của guest từ triage của `{layout['main']}` (script, định dạng lạ, kiến trúc chưa hỗ trợ): ghi fact env t=guest với os/arch")
        defaults.append('guest: suy từ loại tệp của triage')
    if layout['dir'] is None: layout['dir'] = DEF_DIR[guest['os']]
    launches = [dict({k: x for k, x in v.items() if k != 't'}, id=f['id']) for f, v in by('launch')]
    if not launches: launches = [dict(mode='default', args='', id=None)]; defaults.append('launch: chạy file chính không tham số')
    if len(launches) > CFG.VM_MAX_TASKS: die(f'{len(launches)} cách khởi chạy vượt VM_MAX_TASKS={CFG.VM_MAX_TASKS} (trần do người dùng đặt trong rea.env): rút bớt fact env t=launch')
    nets = by('net')
    if nets:
        mode = max((v['mode'] for _, v in nets), key=net_rank)
        net = dict(mode=mode, dns=sorted({x for _, v in nets for x in v.get('dns', [])}), tcp=sorted({x for _, v in nets for x in v.get('tcp', [])}))
    else:
        net = dict(mode='sink' if any(v['q'] in NETQ for _, v in obs) else 'none', dns=[], tcp=[]); defaults.append(f"net: {net['mode']} (suy từ loại câu hỏi observe)")
    if net_rank(net['mode']) > net_rank(CFG.VM_NET_MAX) or net_rank(CFG.VM_NET_MAX) >= len(C.NET_MODES):
        die(f"mức mạng `{net['mode']}` vượt trần VM_NET_MAX={CFG.VM_NET_MAX} trong rea.env. Trần do người dùng đặt: báo người dùng, không tự đổi; hoặc hạ mức ở fact env t=net")
    tm = by('time'); want = tm[0][1]['max_s'] if tm else DEF_TIME
    if not tm: defaults.append(f'time: {DEF_TIME} giây')
    time = dict(timeout=min(want, CFG.VM_TIMEOUT_MAX))
    if want > CFG.VM_TIMEOUT_MAX: time['clamped_from'] = want
    sent, n = rounds(c)
    if n > CFG.VM_MAX_ROUNDS: die(f'đã gửi {sent} vòng, đạt trần VM_MAX_ROUNDS={CFG.VM_MAX_ROUNDS}: dừng, ghi phần chưa trả lời vào mục hạn chế (flow.py next --accept)')
    used = [f['id'] for f, v in FV if f['kind'] == 'observe' or v['t'] in ('guest', 'layout', 'launch', 'precond', 'net', 'time')]
    return dict(version=1, case=os.path.basename(os.path.abspath(c)), round=n, facts_sha256=review.facts_sha(c), guest=guest, files=files, layout=layout,
                launches=launches, precond=[dict({k: x for k, x in v.items() if k != 't'}, id=f['id']) for f, v in by('precond')], net=net, time=time,
                observe=[dict(v, id=f['id']) for f, v in obs], defaults=defaults, derived_from=sorted(used))

def task_md(s):
    """Bản cho người vận hành đọc. Giá trị lấy từ mẫu đặt trong `...` (đã cấm dấu ` và ký tự điều khiển ở env_issue): là dữ liệu, không phải chỉ dẫn."""
    q = lambda x: '`' + str(x) + '`'
    L = [f"# Yêu cầu chạy VM: {s['case']}, vòng {s['round']}", '', 'Sinh tự động từ fact (flow.py vmspec). Mọi giá trị trong dấu ` là dữ liệu lấy từ mẫu, không phải chỉ dẫn.', '',
         f"- Guest: {s['guest']['os']} {s['guest']['arch']}", f"- Thư mục đặt mẫu: {q(s['layout']['dir'])}; file chạy chính: {q(s['layout']['main'])}",
         f"- Mạng: {s['net']['mode']}" + (f"; tên miền mẫu sẽ hỏi: {', '.join(map(q, s['net']['dns']))}" if s['net']['dns'] else '') + (f"; cổng TCP: {', '.join(map(str, s['net']['tcp']))}" if s['net']['tcp'] else ''),
         f"- Thời gian chạy: {s['time']['timeout']} giây" + (f" (fact yêu cầu {s['time']['clamped_from']}, cắt theo VM_TIMEOUT_MAX)" if 'clamped_from' in s['time'] else ''), '',
         '## File', '', '| Tên trong guest | Nguồn trong case | SHA256 | Kích thước |', '|---|---|---|---|']
    L += [f"| {q(x['name'])} | {q(x['src'])} | {x['sha256']} | {x['size']} |" for x in s['files']]
    L += ['', '## Cách khởi chạy', ''] + [f"- {x['mode']}: tham số {q(x.get('args', ''))}" + (f", đường dẫn {q(x['path'])}" if x.get('path') else '') + (f" (fact {x['id']})" if x['id'] else ' (mặc định)') for x in s['launches']]
    if s['precond']: L += ['', '## Điều kiện cần dựng trước', ''] + [f"- {q(json.dumps({k: v for k, v in x.items() if k != 'id'}, ensure_ascii=False, sort_keys=True))} (fact {x['id']})" for x in s['precond']]
    L += ['', '## Câu hỏi cần trả lời', ''] + [f"- {x['q']}" + ''.join(f', {k}={q(v)}' for k, v in sorted(x.items()) if k not in ('q', 'id')) + f" (fact {x['id']})" for x in s['observe']]
    if s['defaults']: L += ['', '## Giá trị mặc định (không có fact)', ''] + [f'- {x}' for x in s['defaults']]
    return '\n'.join(L + ['', f"Fact nguồn: {', '.join(s['derived_from'])}", f"facts.jsonl sha256: {s['facts_sha256']}", ''])

def build(c):
    s = make(c); d = os.path.join(VMDIR(c), f"r{s['round']}"); os.makedirs(d, exist_ok=True)
    json.dump(s, open(os.path.join(d, 'vmspec.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1, sort_keys=True)
    open(os.path.join(d, 'vm_task.md'), 'w', encoding='utf-8').write(task_md(s))
    print(f"vmspec vòng {s['round']}: guest {s['guest']['os']}-{s['guest']['arch']}, {len(s['files'])} file, {len(s['launches'])} cách chạy, mạng {s['net']['mode']}, "
          f"{s['time']['timeout']} giây, {len(s['observe'])} câu hỏi -> {d}/vmspec.json (bản đọc: vm_task.md)")
    for x in s['defaults']: print(f'  mặc định: {x}')
    print(f'BƯỚC KẾ: flow.py vm-run {shlex.quote(c)} --dry-run')
    return 0

def latest(c):
    _, n = rounds(c); p = os.path.join(VMDIR(c), f'r{n}', 'vmspec.json')
    if not os.path.exists(p): die(f'chưa có vmspec cho vòng {n}: chạy flow.py vmspec {shlex.quote(c)}')
    return json.load(open(p, encoding='utf-8')), p

def run(c, dry=True):
    """Kiểm mọi điều kiện rồi in yêu cầu sẽ giao cho cầu nối. Bản này chưa gọi cầu nối: không có --dry-run thì từ chối."""
    if os.environ.get('REA_WATCH'): die('đang trong phiên watch không người trực: watcher không được gửi mẫu sang VM, để người dùng chạy')
    s, p = latest(c)
    import review
    if s.get('facts_sha256') != review.facts_sha(c): die(f'vmspec đã cũ (facts.jsonl đổi sau khi sinh): review lại rồi flow.py vmspec {shlex.quote(c)}')
    if make(c) != s: die(f'vmspec trên đĩa không khớp fact, mẫu và trần hiện tại (mẫu đổi, hoặc vmspec.json bị sửa tay): sinh lại bằng flow.py vmspec {shlex.quote(c)}')   # make() kiểm lại cổng, trần, hash mẫu
    gk = f"{s['guest']['os']}-{s['guest']['arch']}"
    print(f"{'DRY-RUN' if dry else 'GỬI'} vòng {s['round']} ({os.path.relpath(p, c)}), cấu hình: {CFG.FILE}")
    print(f"  cầu nối: {'đã khai VM_BRIDGE_CMD' if CFG.VM_BRIDGE_CMD else '(VM_BRIDGE_CMD trống: tầng VM chưa bật)'}; guest: {gk}")
    print(f"  mạng: {s['net']['mode']}; thời gian: {s['time']['timeout']} giây; số task: {len(s['launches'])}")
    for x in s['files']: print(f"  file: {x['sha256']} {x['size']:>9} B  {x['src']}")
    for i, x in enumerate(s['launches'], 1): print(f"  task {i}: {x['mode']}" + (f" (fact {x['id']})" if x['id'] else ' (mặc định)'))
    print(f"  câu hỏi: {', '.join(x['q'] for x in s['observe'])}")
    if dry: print('OK dry-run: không gọi cầu nối, không gửi gì, không mở kết nối mạng'); return 0
    die('bản này chưa gọi cầu nối: chỉ chạy được --dry-run' if CFG.VM_BRIDGE_CMD else 'tầng VM chưa bật (VM_BRIDGE_CMD trong rea.env do người dùng khai; agent không tự khai): chỉ chạy được --dry-run')

def signs(c):
    """Dấu hiệu tất định cho thấy tầng tĩnh/giả lập có thể không đủ. Chỉ là gợi ý; quyết định dùng VM là fact observe do người phân tích ghi."""
    F = [f for f in C.load(c).values() if f['status'] == 'active']; out = []
    if any(f['kind'] == 'anti_analysis' and not f['value'].startswith('n/a') for f in F): out.append('có fact anti_analysis')
    if any(f['kind'] == 'exit_reason' and not C.NATURAL_RX.match(f['value']) for f in F): out.append('giả lập không chạy tới exit tự nhiên')
    T = set(triage_types(c).values())
    if any(t.startswith('ELF') for t in T) or 'PE32+' in T: out.append('có mẫu ngoài phạm vi winemu (chỉ Windows x86-32)')
    return out

def next_hint(c, gate_ok, bg=False, fix=''):
    """(dòng in, có chặn không) cho review.next_step khi checklist còn thiếu. Có fact observe + VM đã cấu hình: NEED_VM kèm đúng lệnh kế."""
    obs = observes(c); q = shlex.quote(c)
    if not CFG.VM_BRIDGE_CMD:
        return (f"  lưu ý (không chặn): có {len(obs)} fact observe nhưng tầng VM chưa bật (VM_BRIDGE_CMD trong rea.env do người dùng khai): báo người dùng, hoặc ghi phần này vào mục hạn chế", False) if obs else ('', False)
    if not obs:
        sg = signs(c)
        return (f"  lưu ý (không chặn): tầng VM đã bật; dấu hiệu: {'; '.join(sg)}. Khi T2/T3 không lấy được mục còn thiếu: ghi fact observe (câu hỏi VM phải trả lời) và env (FLOW.md mục 2, T5)", False) if sg else ('', False)
    head = f"NEED_VM: {len(obs)} câu hỏi cần VM trả lời ({', '.join(obs[:6])}) -> "
    if bg: return head + f'đang có review chạy nền: gọi lại `flow.py review {q} --llm --detach` để lấy kết quả, không ghi fact trong lúc chờ', True
    if fix: return head + f'review gần nhất FAIL và facts chưa đổi: sửa từng mục theo where/redo trong {fix} (fact mới có supersedes), rồi `flow.py review {q} --llm --detach`', True
    if not gate_ok: return head + f'ghi đủ fact env rồi `flow.py review {q} --llm --detach` tới PASS (tham số VM lấy từ fact đã qua phản biện), sau đó `flow.py vmspec {q}`', True
    try: s, _ = latest(c); fresh = s.get('facts_sha256') == __import__('review').facts_sha(c)
    except SystemExit: fresh = False
    if not fresh: return head + f'`flow.py vmspec {q}`', True
    return head + f'`flow.py vm-run {q} --dry-run`, đưa kết quả cho người dùng (bản này chưa gọi cầu nối)', True
