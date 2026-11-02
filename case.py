#!/usr/bin/env python3
# Dữ liệu một case phân tích: facts.jsonl (chỉ ghi thêm), checklist C1–C11, sinh bảng báo cáo, đối chiếu evidence.
#   case.py add CASE id=.. kind=.. value=.. src=S|E|V evidence=report/evidence/F[#Ln] [status=..] [verified_by=S,E] [supersedes=..] [stage=..] [note=..] [--strict]
#   case.py show CASE [kind]     case.py check CASE     case.py report CASE     case.py audit CASE     case.py --selftest
#   add chạy lint_fact() trước khi ghi: evidence tồn tại/đúng dòng, src khớp loại evidence, hash tính lại,
#   value phải có trong đoạn evidence được trỏ (±WINDOW dòng khi có #L), số liệu phải có trong evidence.
#   Mặc định chỉ in cảnh báo; --strict từ chối ghi nếu có lỗi mức fail.
import sys, os, json, re, glob, hashlib, datetime

KINDS = {'hash', 'filetype', 'container', 'entry', 'anti_analysis', 'str_algo', 'str_key', 'string', 'config',
         'url', 'ua', 'c2', 'inject', 'persistence', 'mutex', 'file', 'registry', 'process',
         'payload_fmt', 'payload_key', 'payload_hash', 'family', 'exit_reason', 'api_unused', 'dec_coverage', 'coverage'}
IOC_KINDS = ['hash', 'url', 'ua', 'c2', 'mutex', 'file', 'registry', 'process', 'str_key', 'payload_key', 'payload_hash', 'family']
PERSIST_API = re.compile(r'Reg(Set|Create)|CopyFile|MoveFile|CreateService|SchTask|Startup', re.I)
EV = 'report/evidence/'
REVIEW_RULE_VERSION = 2   # 2: fail ở check bằng chứng cứng luôn high; state.json cũ hết hiệu lực
# lint khi ghi fact (xem lint_fact)
LITERAL_KINDS = {'c2', 'url', 'ua', 'mutex', 'file', 'registry', 'process', 'persistence',
                 'str_key', 'payload_key', 'config', 'string'}
TOKEN = re.compile(r'[A-Za-z0-9_.\\/%:$-]{5,}')
NUMTOK = re.compile(r'(?<![0-9A-Za-z])(0x[0-9a-fA-F]{4,}|\d{3,})(?![0-9A-Za-z])')
DATE = re.compile(r'\b\d{4}-\d{2}-\d{2}(?:[T ][\d:.]+)?\b')
LOG_LINES = 40   # evidence dài hơn mức này phải trỏ #L hoặc tách đoạn trích
WINDOW = 5       # có #L: value phải xuất hiện trong ±WINDOW dòng quanh đó

def _normnum(s): return re.sub(r'(?<=\d)[.,](?=\d{3}(?!\d))', '', s)

def _work_hashes(case):
    hs = set()
    for d in ('sample', 'extract'):
        for p in glob.glob(os.path.join(case, 'work', d, '**', '*'), recursive=True):
            if os.path.isfile(p) and os.path.getsize(p) < 64 << 20:
                hs.add(hashlib.sha256(open(p, 'rb').read()).hexdigest())
    return hs

def lint_fact(case, f):
    """Kiểm tra lớp 1 ngay khi ghi fact. Trả list {level, check, problem, redo}.
    level 'fail' = mâu thuẫn rõ; 'warn' = nên sửa nhưng chưa chắc sai."""
    out = []
    def bad(level, check, problem, redo): out.append(dict(level=level, check=check, problem=problem, redo=redo))
    rel, full = ev_path(case, f['evidence'])
    if not os.path.isfile(full):
        bad('fail', 'evidence_exists', f'file evidence không tồn tại: {rel}', 'chép bằng chứng vào report/evidence/')
        return out
    lines = open(full, encoding='utf-8', errors='replace').read().splitlines()
    whole = _normnum('\n'.join(lines)).replace('\\\\', '\\').lower()
    base = os.path.basename(rel)
    if f['src'] == 'S' and base.startswith(('emu_', 'vm_')):
        bad('fail', 'src_vs_evidence', 'src=S nhưng evidence sinh từ giả lập/VM', 'đổi src hoặc dẫn evidence tĩnh')
    if f['src'] == 'V' and not base.startswith('vm_'):
        bad('fail', 'src_vs_evidence', 'src=V nhưng evidence không phải kết quả VM', 'dẫn evidence vm_* hoặc đổi src')
    scope, anchor = whole, None
    m = re.search(r'#L(\d+)$', f['evidence'])
    if m:
        ln = int(m.group(1))
        if ln > len(lines):
            bad('fail', 'evidence_line', f'dòng {ln} vượt quá file ({len(lines)} dòng)', 'trỏ đúng dòng chứa bằng chứng')
        else:
            anchor = ln
            scope = _normnum('\n'.join(lines[max(0, ln - 1 - WINDOW): ln + WINDOW])).replace('\\\\', '\\').lower()
    elif len(lines) > LOG_LINES and rel.lower().endswith(('.txt', '.log')):
        bad('warn', 'evidence_scope', f'evidence dài {len(lines)} dòng: dẫn cả file nên không neo được đoạn chứng minh',
            'thêm #L<dòng> hoặc tách đoạn trích vào file riêng')
    if f['kind'] in ('hash', 'payload_hash'):
        hs = None
        for h in re.findall(r'\b[0-9a-f]{64}\b', f['value']):
            if h in whole: continue
            hs = hs if hs is not None else _work_hashes(case)
            if h not in hs:
                bad('fail', 'hash_recompute', f'sha256 {h[:12]}… không có trong evidence và không khớp file nào trong work/sample|extract',
                    'tính lại sha256 từ file gốc rồi chép vào evidence')
    elif f['kind'] in LITERAL_KINDS and not f['value'].startswith('n/a'):
        toks = [t.strip('.,;:)(\'"`').lower() for t in TOKEN.findall(f['value'].replace('\\\\', '\\'))]
        toks = [t for t in toks if len(t) >= 5 and not t.isdigit()]
        if toks and not any(t in scope for t in toks):
            where = f'±{WINDOW} dòng quanh #L{anchor}' if anchor else 'file evidence'
            bad('fail', 'value_in_evidence', f'không token nào của value xuất hiện trong {where}',
                'chép đoạn chứa giá trị vào evidence, hoặc chỉnh #L/nới WINDOW' if anchor else
                'chép đoạn chứa giá trị vào evidence hoặc sửa giá trị')
    miss = [n for n in NUMTOK.findall(_normnum(DATE.sub(' ', f['value']))) if n.lower() not in scope]
    if miss:
        bad('warn', 'number_in_evidence', f'số {", ".join(miss[:5])} không có trong evidence',
            'đưa output script chứa đúng con số vào evidence, hoặc sửa số')
    return out

def ev_path(case, ev):
    rel = os.path.normpath(ev.split('#')[0])
    return rel, os.path.join(case, rel)

def add(case, strict=False, lint=False, **f):
    for k in ('id', 'kind', 'value', 'src', 'evidence'):
        if not f.get(k): raise ValueError(f'thiếu {k}')
    if f['kind'] not in KINDS: raise ValueError(f'kind lạ: {f["kind"]} (thêm vào KINDS nếu thật sự cần)')
    if f['src'] not in ('S', 'E', 'V'): raise ValueError('src phải là S, E hoặc V')
    f.setdefault('status', 'active')
    if f['status'] not in ('active', 'hypothesis', 'retracted'): raise ValueError('status lạ')
    rel, full = ev_path(case, f['evidence'])
    if not rel.startswith(EV): raise ValueError(f'evidence phải nằm trong {EV}: {rel}')
    if not os.path.isfile(full): raise ValueError(f'evidence không tồn tại: {rel}')
    vb = f.get('verified_by') or [f['src']]
    f['verified_by'] = sorted(set(vb.split(',') if isinstance(vb, str) else vb))
    f.setdefault('supersedes', None); f.setdefault('stage', ''); f.setdefault('note', '')
    f['ts'] = datetime.datetime.now().isoformat(timespec='seconds')
    issues = lint_fact(case, f) if lint else []
    fails = [i for i in issues if i['level'] == 'fail']
    if strict and fails:
        raise ValueError('lint từ chối fact: ' + '; '.join(f"{i['check']}: {i['problem']}" for i in fails))
    with open(os.path.join(case, 'facts.jsonl'), 'a') as fh: fh.write(json.dumps(f, ensure_ascii=False) + '\n')
    for i in issues:
        print(f"lint {i['level']}: {i['check']}: {i['problem']} -> {i['redo']}")

def history(case):
    p = os.path.join(case, 'facts.jsonl')
    return [json.loads(l) for l in open(p, encoding='utf-8') if l.strip()] if os.path.exists(p) else []

def load(case):
    cur = {}
    for f in history(case): cur[f['id']] = f
    for f in list(cur.values()):           # fact bị thay thế thì không còn hiệu lực
        if f.get('supersedes') in cur: cur[f['supersedes']] = dict(cur[f['supersedes']], status='retracted')
    return cur

def review_status(case):
    """C0: kết quả cổng phản biện (review.py). ok = review cuối PASS khớp hash facts.jsonl hiện tại."""
    sp = os.path.join(case, 'work', 'review', 'state.json')
    if not os.path.exists(sp) or not os.path.exists(os.path.join(case, 'facts.jsonl')): return 'missing'
    s = json.load(open(sp)); cur = hashlib.sha256(open(os.path.join(case, 'facts.jsonl'), 'rb').read()).hexdigest()
    ov = os.path.join(case, 'work', 'review', 'OVERRIDE')
    if os.path.exists(ov) and f'facts_sha256={cur}' in open(ov).read(): return 'ok(override)'
    if s.get('rule_version') != REVIEW_RULE_VERSION: return 'missing'   # state theo luật cũ: phải review lại
    if s.get('stopped') and s.get('reset_for') == cur: return 'fail(stopped)'
    last = s['rounds'][-1] if s['rounds'] else None
    if not last or last['facts_sha256'] != cur: return 'missing'     # review đã cũ: facts đổi sau lần review cuối
    return ('partial' if last.get('weak') else 'ok') if last['verdict'] == 'PASS' else 'partial'

def check(case):
    F = [f for f in load(case).values() if f['status'] != 'retracted']
    act = lambda *ks: [f for f in F if f['kind'] in ks and f['status'] == 'active']
    hyp = lambda *ks: [f for f in F if f['kind'] in ks and f['status'] == 'hypothesis']
    exits = act('exit_reason')   # mọi tiến trình phải thoát tự nhiên; 'stop_at'/lỗi giả lập nghĩa là còn phần chưa chạy tới
    natural = exits and all('natural' in f['value'] for f in exits)
    unused = ' '.join(f['value'] for f in act('api_unused'))
    # độ phủ: giả lập chạy tới exit tự nhiên (E), hoặc fact 'coverage' khẳng định đã duyệt tĩnh hết các hàm dùng API nhạy cảm (S)
    c11 = 'ok' if (natural and act('api_unused') and act('dec_coverage')) or act('coverage') else \
          'partial' if act('exit_reason', 'api_unused') else 'missing'
    cov = [tuple(map(int, f['value'].split('/'))) for f in act('dec_coverage') if re.fullmatch(r'\d+/\d+', f['value'])]
    gate = lambda has: ('ok' if c11 == 'ok' else 'partial') if has else 'missing'
    R = {
        'C0 Phản biện': review_status(case),
        'C1 Nhận dạng': 'ok' if act('hash') and act('filetype') else 'partial' if act('hash', 'filetype') else 'missing',
        'C2 Delivery và điểm vào': 'ok' if act('container') and act('entry') else 'partial' if act('container', 'entry') else 'missing',
        'C3 Chống phân tích': gate(act('anti_analysis')),
        'C4 Giải mã chuỗi/config': ('ok' if cov and all(a >= b for a, b in cov) else 'partial') if act('str_algo') and act('str_key')
                                   else 'partial' if act('str_algo', 'str_key') else 'missing',
        'C5 IOC mạng': gate(act('url', 'c2', 'ua')),
        'C6 Tiêm mã': 'ok' if act('inject') and not hyp('inject') else 'partial' if act('inject') or hyp('inject') else 'missing',
        'C7 Persistence': 'ok' if act('persistence') else 'partial' if PERSIST_API.search(unused) or hyp('persistence') or c11 != 'ok'
                          else 'n/a(không thấy, giả lập đã chạy hết)',
        'C8 Payload: định dạng và khóa': ('ok' if act('payload_hash') else 'partial') if act('payload_fmt') and act('payload_key')
                                         else 'partial' if act('payload_fmt', 'payload_key') else 'missing',
        'C9 Payload cuối': 'ok' if act('payload_hash') else 'missing',
        'C10 Họ mã độc': 'ok' if act('family') else 'partial' if hyp('family') else 'missing',
        'C11 Độ phủ': c11,
    }
    NEXT = {'C0': 'flow.py review CASE [--llm] (tối đa 2 lần); stopped thì đọc work/review/STOP_REPORT.md', 'C1': 'T0 flow.py triage', 'C2': 'T0/T1 bóc vỏ; ghi entry (hàm/offset bắt đầu mã độc)',
            'C3': 'T2 tìm anti-debug/anti-VM quanh import nhạy cảm; T3 nếu chạy được',
            'C4': 'T2 tìm hàm giải mã chuỗi/config (xref chuỗi rác, vòng XOR); hoặc fact n/a nếu chuỗi rõ',
            'C5': 'T2 xref các hàm mạng và ioc_candidates trong report/evidence/triage_*.json (ứng viên chưa phải fact); T3 nếu chạy được', 'C6': 'T2/T3: CreateProcess/WriteProcessMemory/ptrace/LD_PRELOAD; hoặc n/a',
            'C7': 'T2: registry/service/cron/systemd/rc.local/ghi file hệ thống; hoặc n/a', 'C8': 'T3 --fake-dl rồi T4; hoặc n/a nếu không tải payload',
            'C9': 'T4 (cần payload thật) hoặc n/a', 'C10': 'đối chiếu kỹ thuật/chuỗi với họ đã biết; T4 + T0 trên payload',
            'C11': 'E: giả lập tới exit tự nhiên; S: fact coverage liệt kê đã duyệt mọi xref của import nhạy cảm'}
    return [(k, v, '' if v == 'ok' or v.startswith('n/a') else NEXT[k.split()[0]]) for k, v in R.items()]

def sha(p): return hashlib.sha256(open(p, 'rb').read()).hexdigest()

def ev_files(case):
    root = os.path.join(case, EV)
    return sorted(os.path.relpath(os.path.join(d, n), root) for d, _, ns in os.walk(root) for n in ns)

def report(case):
    cur, H = load(case), history(case)
    L = ['<!-- Sinh tự động bởi rea-flow case.py report: không sửa tay, sửa facts.jsonl rồi chạy lại -->', '', '## IOC', '',
         '| Loại | Giá trị | Nguồn | Evidence |', '|---|---|---|---|']
    L += [f"| {f['kind']} | `{f['value']}` | {'+'.join(f['verified_by'])} | `{f['evidence']}` |"
          for k in IOC_KINDS for f in cur.values() if f['kind'] == k and f['status'] == 'active']
    L += ['', '## Phát hiện theo nguồn (S tĩnh, E giả lập CPU, V VM)', '', '| id | Loại | Trạng thái | Nguồn | Kiểm chứng chéo | Ghi chú |', '|---|---|---|---|---|---|']
    L += [f"| {f['id']} | {f['kind']} | {f['status']} | {f['src']} | {'có' if len(f['verified_by']) > 1 else 'không'} | {f['note']} |"
          for f in cur.values() if f['status'] != 'retracted']
    L += ['', '## Đính chính', '', '| id | Trước | Sau | Vòng |', '|---|---|---|---|']
    prev = {}
    for f in H:
        p = prev.get(f['id'])
        if p and (p['value'], p['status']) != (f['value'], f['status']):
            L.append(f"| {f['id']} | {p['value']} ({p['status']}) | {f['value']} ({f['status']}) | {f.get('round', '')} |")
        if f.get('supersedes') in prev:
            o = prev[f['supersedes']]; L.append(f"| {o['id']} → {f['id']} | {o['value']} | {f['value']} | {f.get('round', '')} |")
        prev[f['id']] = f
    i0 = L.index('## Đính chính') + 4; L[i0:] = list(dict.fromkeys(L[i0:]))   # một fact supersede được ghi lại nhiều lần -> một dòng
    refs = {ev_path(case, f['evidence'])[0][len(EV):] for f in cur.values()}
    L += ['', '## Evidence trên đĩa', '', '| File | Byte | sha256 | Fact tham chiếu |', '|---|---|---|---|']
    L += [f"| `{r}` | {os.path.getsize(os.path.join(case, EV, r))} | `{sha(os.path.join(case, EV, r))[:16]}…` | {'có' if r in refs else '—'} |"
          for r in ev_files(case)]
    open(os.path.join(case, 'report', 'GENERATED.md'), 'w', encoding='utf-8').write('\n'.join(L) + '\n')
    return L

def audit(case):
    """README §Evidence phải khớp đĩa; fact không được trỏ tới file mất."""
    problems, disk = [], ev_files(case)
    txt = open(os.path.join(case, 'report', 'README.md'), encoding='utf-8').read()
    m = re.search(r'^## [^\n]*Evidence[^\n]*\n(.*?)(?=^## |\Z)', txt, re.M | re.S)
    toks = {t for row in (m.group(1).splitlines() if m else []) if row.startswith('|')
            for t in re.findall(r'`([^`]+)`', row.split('|')[1])}
    names = {os.path.basename(t) for t in toks} | toks
    problems += [f'README thiếu: {r}' for r in disk if r not in names and os.path.basename(r) not in names]
    problems += [f'README có mà đĩa không có: {t}' for t in toks
                 if not any(r == t or os.path.basename(r) == os.path.basename(t) for r in disk)]
    problems += [f'fact {f["id"]} trỏ tới file mất: {f["evidence"]}' for f in load(case).values()
                 if not os.path.isfile(ev_path(case, f['evidence'])[1])]
    return problems

def selftest():
    import tempfile
    c = tempfile.mkdtemp(); os.makedirs(os.path.join(c, EV)); os.makedirs(os.path.join(c, 'work'))
    open(os.path.join(c, EV, 'a.log'), 'w').write('x'); open(os.path.join(c, 'work', 'b.log'), 'w').write('x')
    for bad in [dict(evidence=EV + 'nope.log'), dict(evidence='work/b.log'), dict(evidence=EV + '../../work/b.log'), dict(kind='lạ')]:
        try: add(c, **{**dict(id='x', kind='url', value='u', src='E', evidence=EV + 'a.log'), **bad}); raise AssertionError(bad)
        except ValueError: pass
    add(c, id='u1', kind='url', value='http://a', src='E', evidence=EV + 'a.log#L3')
    add(c, id='i1', kind='inject', value='hollowing', src='E', evidence=EV + 'a.log', status='hypothesis')
    add(c, id='k1', kind='payload_key', value='old', src='E', evidence=EV + 'a.log')
    add(c, id='k2', kind='payload_key', value='new', src='E', evidence=EV + 'a.log', supersedes='k1')
    add(c, id='u1', kind='url', value='http://a', src='E', evidence=EV + 'a.log', status='retracted')
    cur, ck = load(c), dict((k.split()[0], v) for k, v, _ in check(c))
    assert cur['u1']['status'] == 'retracted' and cur['k1']['status'] == 'retracted', cur
    assert ck['C5'] == 'missing' and ck['C6'] == 'partial' and ck['C8'] == 'partial' and ck['C11'] == 'missing', ck
    L = report(c)
    assert any('k1 → k2' in l for l in L) and any('| u1 | http://a (active) | http://a (retracted)' in l for l in L), L
    print('OK selftest')

if __name__ == '__main__':
    a = sys.argv[1:]
    if not a or a[0] == '--selftest': selftest(); sys.exit()
    cmd, case = a[0], a[1]
    if cmd == 'add':
        rest = a[2:]
        add(case, strict='--strict' in rest, lint=True,
            **dict(x.split('=', 1) for x in rest if not x.startswith('--'))); print('OK')
    elif cmd == 'show':
        for f in load(case).values():
            if len(a) < 3 or f['kind'] == a[2]: print(f"{f['id']:<18} {f['kind']:<13} {f['status']:<10} {f['src']} {f['value'][:90]}")
    elif cmd == 'check':
        for k, v, n in check(case): print(f'{k:<34} {v:<10} {"next: " + n if n else ""}')
    elif cmd == 'report': print(f'{len(report(case))} dòng -> {case}/report/GENERATED.md')
    elif cmd == 'audit':
        p = audit(case); print('\n'.join(p) if p else 'OK audit'); sys.exit(1 if p else 0)
