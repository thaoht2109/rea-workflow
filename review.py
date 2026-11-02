#!/usr/bin/env python3
# Cổng phản biện facts.jsonl và điểm dừng sớm (FLOW.md §3b). Không bao giờ chạy mẫu.
#   review.py review CASE [--llm]     lớp 1 (máy) [+ lớp 2: reviewer.py, mọi LLM: claude/codex/gemini/copilot/cursor/api/cmd/manual]; tối đa 2 lần review; mã 4 = chờ manual
#   review.py review-loop CASE        review -> sửa lại fact lỗi (phiên phân tích) -> review lần 2, tự động, dừng nếu vẫn FAIL
#   review.py gate CASE               mã thoát 0 khi review PASS khớp hash facts.jsonl hiện tại (hoặc có OVERRIDE khớp)
#   review.py next CASE [--accept C4=lý do,...]   DONE khi checklist đủ và cổng đạt: có thể báo cáo và đóng, không cần VM
#   review.py --selftest
import sys, os, re, json, glob, shlex, shutil, hashlib, tempfile, subprocess, datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import case as C, reacfg as CFG

MAX_ROUNDS = 2
GATING = set(C.IOC_KINDS) | {'persistence', 'inject', 'entry', 'container', 'payload_fmt'}   # fact sai ở đây làm sai IOC/kết luận -> high
HARD_CHECKS = {'evidence_exists', 'evidence_line', 'src_vs_evidence', 'hash_recompute',
               'value_in_evidence', 'value_vs_evidence', 'source', 'recompute'}   # mâu thuẫn bằng chứng -> high, bất kể kind
LITERAL = {'c2', 'url', 'ua', 'mutex', 'file', 'registry', 'process', 'persistence', 'str_key', 'payload_key', 'config', 'string'}
HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN = re.compile(r'[A-Za-z0-9_.\\/%:$-]{5,}')
DIR = lambda c: os.path.join(c, 'work', 'review')

def sha_file(p): return hashlib.sha256(open(p, 'rb').read()).hexdigest()
def facts_sha(c): return sha_file(os.path.join(c, 'facts.jsonl'))
def now(): return datetime.datetime.now().isoformat(timespec='seconds')

# ---------- lớp 1: kiểm tra máy ----------
def work_hashes(c):
    hs = set()
    for d in ('sample', 'extract'):
        for p in glob.glob(os.path.join(c, 'work', d, '**', '*'), recursive=True):
            if os.path.isfile(p) and os.path.getsize(p) < 64 << 20: hs.add(sha_file(p))
    return hs

def mech(c):
    cur, items, hs = C.load(c), [], None
    F = list(cur.values())
    unused = ' '.join(f['value'] for f in F if f['kind'] == 'api_unused' and f['status'] != 'retracted')
    for f in F:
        if f['status'] == 'retracted': continue
        i, k = f['id'], f['kind']
        def bad(v, check, problem, redo, where=None):
            items.append(dict(id=i, verdict=v, severity=severity(k, v, check), check=check, claim=f['value'][:160],
                              problem=problem, where=where or f['evidence'], redo=redo, layer='mech'))
        rel, full = C.ev_path(c, f['evidence'])
        if not os.path.isfile(full): bad('fail', 'evidence_exists', 'file evidence không tồn tại', 'chép bằng chứng vào report/evidence/'); continue
        txt = open(full, encoding='utf-8', errors='replace').read()
        m = re.search(r'#L(\d+)$', f['evidence'])
        if m and int(m.group(1)) > txt.count('\n') + 1:
            bad('fail', 'evidence_line', f'dòng {m.group(1)} vượt quá file ({txt.count(chr(10)) + 1} dòng)', 'trỏ đúng dòng chứa bằng chứng')
        base = os.path.basename(rel)
        if f['src'] == 'S' and base.startswith(('emu_', 'vm_')): bad('fail', 'src_vs_evidence', 'src=S nhưng evidence sinh từ giả lập/VM', 'đổi src hoặc dẫn evidence tĩnh')
        if f['src'] == 'V' and not base.startswith('vm_'): bad('fail', 'src_vs_evidence', 'src=V nhưng evidence không phải kết quả VM', 'đổi src hoặc dẫn evidence vm_*')
        n = txt.replace('\\\\', '\\').lower()
        if k in ('hash', 'payload_hash'):
            hx = re.findall(r'\b[0-9a-f]{64}\b', f['value'])
            hs = hs if hs is not None else work_hashes(c)
            for h in hx:
                if h not in n and h not in hs: bad('fail', 'hash_recompute', f'sha256 {h[:12]}… không có trong evidence và không khớp file nào trong work/sample|extract', 'tính lại sha256 từ file gốc')
        elif k in LITERAL and not f['value'].startswith('n/a'):
            toks = [t.strip('.,;:)(\'"`').lower() for t in TOKEN.findall(f['value'].replace('\\\\', '\\'))]
            toks = [t for t in toks if len(t) >= 5 and not t.isdigit()]
            if toks and not any(t in n for t in toks):
                bad('fail', 'value_in_evidence', 'không token nào của giá trị xuất hiện trong evidence', 'chép đoạn chứa giá trị vào evidence hoặc sửa giá trị', where=f['evidence'])
        if f['status'] == 'active' and re.search(r'\b(chưa|có thể|nghi)\b', f['note'], re.I):
            bad('weak', 'status_vs_note', 'status active nhưng note còn nghi ngờ', 'hạ xuống hypothesis hoặc bổ sung bằng chứng')
        if k == 'persistence' and f['src'] == 'E' and any(a in unused for a in re.findall(r'Reg\w+|CopyFile\w*|MoveFile\w*', f['value'])):
            bad('weak', 'api_unused_inference', 'API persistence nằm trong api_unused: có thể là import của payload, chưa chắc là hành vi', 'đối chiếu import của PE đã giải mã')
    return items

# lớp 2: reviewer.py (hồ sơ tự chứa + giao thức thao tác chỉ đọc, chạy trên mọi LLM)

# ---------- trạng thái và vòng ----------
def state(c):
    p = os.path.join(DIR(c), 'state.json')
    return json.load(open(p)) if os.path.exists(p) else {'rounds': [], 'stopped': False}

def save_state(c, s):
    s['rule_version'] = C.REVIEW_RULE_VERSION
    os.makedirs(DIR(c), exist_ok=True); json.dump(s, open(os.path.join(DIR(c), 'state.json'), 'w'), ensure_ascii=False, indent=1)

def severity(kind, v, check):
    """Mức high/low do luật quyết định, không tin severity do model trả."""
    if v != 'fail': return 'low'
    return 'high' if (kind in GATING or check in HARD_CHECKS) else 'low'

def verdict(items): return 'FAIL' if any(i['verdict'] == 'fail' and i['severity'] == 'high' for i in items) else 'PASS'

def stop_report(c, s):
    r1, r2 = (json.load(open(os.path.join(DIR(c), f'r{n}', 'review.json'))) for n in (1, 2))
    f1 = {i['id']: i for i in r1['items'] if i['verdict'] == 'fail'}
    L = [f'# Phản biện không đạt: {c}', '', f'Dừng sau {MAX_ROUNDS} lần review ({now()}). Các bước vmspec/vm-run/report --final bị chặn.', '',
         '## Fact còn fail sau review 2', '', '| id | Mức | Lỗi | Vị trí | Cách kiểm lại |', '|---|---|---|---|---|']
    fl = [i for i in r2['items'] if i['verdict'] == 'fail']
    L += [f"| {i['id']} | {i['severity']} | {i['problem']} | `{i['where']}` | {i['redo']} |" for i in fl]
    L += ['', '## Diễn biến từng fact', '']
    for i in fl:
        L.append(f"- **{i['id']}**: review 1: {f1[i['id']]['problem'] if i['id'] in f1 else '(chưa bị chỉ ra, lỗi mới do lượt sửa)'} → review 2: {i['problem']}")
    new = [i['id'] for i in fl if i['id'] not in f1]
    L += ['', f"Fact lỗi mới phát sinh sau lượt sửa: {', '.join(new) or 'không'}", '', '## Tác động', '']
    cur = C.load(c)
    L += [f"- {i['id']} ({cur[i['id']]['kind']}) đang treo: {cur[i['id']]['value'][:100]}" for i in fl if i['id'] in cur]
    L += ['', '## Việc tiếp theo (người quyết định)', '', '1. Phân tích tay các fact trên rồi chạy lại `review.py review` (mở bộ đếm mới).',
          '2. Hạ fact xuống `hypothesis`/`retracted` bằng fact mới có `supersedes`.',
          f'3. Chấp nhận rủi ro: tạo `{DIR(c)}/OVERRIDE` có dòng `facts_sha256={facts_sha(c)}`, `approved_by=`, `reason=`, và ghi vào mục hạn chế của báo cáo.']
    open(os.path.join(DIR(c), 'STOP_REPORT.md'), 'w', encoding='utf-8').write('\n'.join(L) + '\n')
    return fl

def review(c, llm=False, force=False):
    s, h = state(c), facts_sha(c)
    if s.get('rule_version') != C.REVIEW_RULE_VERSION:   # luật cổng đổi: review cũ hết hiệu lực, mở bộ đếm mới
        s = {'rounds': [], 'stopped': False, 'reset_for': None}
        save_state(c, s)
    if s['stopped'] and not (os.path.exists(os.path.join(DIR(c), 'OVERRIDE')) or s.get('reset_for') != h):
        print(f'STOPPED: xem {DIR(c)}/STOP_REPORT.md'); return 2
    if s['stopped'] and s.get('reset_for') != h: s.update(stopped=False, rounds=[])
    if s['rounds'] and s['rounds'][-1]['facts_sha256'] == h and not force:
        last = s['rounds'][-1]; print(f"facts chưa đổi từ review {last['n']}: {last['verdict']} (không tính thêm lần)"); return 0 if last['verdict'] == 'PASS' else 1
    k = len(s['rounds']) + 1
    items = mech(c)
    miss, iso = [], None
    if llm:
        ids = [i for i, f in C.load(c).items() if f['status'] != 'retracted']
        import reviewer
        try: li, miss, iso = reviewer.run(c, k, ids, items)
        except reviewer.Pending as e: print(f'CHỜ (manual): {e}'); return 4
        if iso['valid']: items += li
    v = verdict(items)
    if llm and not iso['valid']: v = 'FAIL'
    os.makedirs(os.path.join(DIR(c), f'r{k}'), exist_ok=True)
    json.dump(dict(round=k, facts_sha256=h, reviewer='mech' + ('+' + iso['backend'] if llm else ''), verdict=v, items=items, missing=miss, isolation=iso, ts=now()),
              open(os.path.join(DIR(c), f'r{k}', 'review.json'), 'w'), ensure_ascii=False, indent=1)
    weak = sum(1 for i in items if i['verdict'] == 'weak')
    s['rounds'].append(dict(n=k, facts_sha256=h, verdict=v, weak=weak))
    fl = [i for i in items if i['verdict'] == 'fail']
    print(f'review {k}/{MAX_ROUNDS}: {v}  (fail {len(fl)}, weak {weak}' + (f", lớp 2 {iso['backend']}: {iso['turns']} lượt, {iso['requests']} thao tác, " + ('cô lập OK' if iso['valid'] else 'KHÔNG HỢP LỆ: ' + '; '.join(iso['invalid_reasons'])) if iso else '') + ')')
    for i in fl[:15]: print(f"  FAIL {i['id']} [{i['severity']}] {i['problem']} @ {i['where']} -> {i['redo']}")
    code = 0
    if v == 'FAIL' and k >= MAX_ROUNDS:
        s['stopped'], s['reset_for'] = True, h; save_state(c, s); stop_report(c, s)
        hi = sum(1 for i in fl if i['severity'] == 'high')
        print('\n' + '=' * 60 + f"\nSTOPPED {c}: phản biện không đạt sau {MAX_ROUNDS} lần review\nfail mức high: {hi}, low: {len(fl) - hi}\nbáo cáo: {DIR(c)}/STOP_REPORT.md\n" + '=' * 60)
        return 2
    save_state(c, s)
    return 0 if v == 'PASS' else 1

def analyst(c, k):
    """Phiên phân tích sửa lại đúng các fact fail/weak của review k. Kiểm tra facts.jsonl chỉ được nối thêm, mẫu không đổi."""
    rj = json.load(open(os.path.join(DIR(c), f'r{k}', 'review.json')))
    todo = [{x: i.get(x) for x in ('id', 'verdict', 'severity', 'problem', 'where', 'redo')} for i in rj['items'] if i['verdict'] in ('fail', 'weak')]
    fp = os.path.join(c, 'facts.jsonl'); before = open(fp, 'rb').read()
    samples = {p: sha_file(p) for p in glob.glob(os.path.join(c, 'work', 'sample', '*'))}
    name = os.path.basename(os.path.abspath(c))
    sysp = open(os.path.join(HERE, 'review', 'analyst.md'), encoding='utf-8').read().replace('CASE', name).replace('{SKILL}', HERE)
    prm = open(os.path.join(HERE, 'review', 'analyst_prompt.tmpl'), encoding='utf-8').read().replace('{CASE}', name).replace('{SKILL}', HERE).replace('{ROUND}', str(k)).replace(
        '{ITEMS}', json.dumps(todo, ensure_ascii=False, indent=1))
    if CFG.ANALYST_LLM_CMD: cmd, prm = shlex.split(CFG.ANALYST_LLM_CMD), sysp + '\n\n---\n\n' + prm   # agent khác có quyền sửa file, chạy không tương tác
    else:
        cmd = [CFG.CLAUDE, '-p', '--no-session-persistence', '--strict-mcp-config', '--mcp-config', '{"mcpServers":{}}', '--settings', '{"disableAllHooks":true}',
               '--disable-slash-commands', '--system-prompt', sysp, '--permission-mode', 'acceptEdits',
               '--allowedTools', 'Read,Grep,Edit,Write,Bash(python3:*),Bash(sed:*),Bash(grep:*),Bash(cat:*),Bash(ls:*),Bash(head:*),Bash(tail:*)',
               '--disallowedTools', 'Agent,WebFetch,WebSearch,Bash(wine:*),Bash(*winemu*)', '--output-format', 'text']
    r = subprocess.run(cmd, input=prm, cwd=CFG.REA, capture_output=True, text=True, timeout=3600)
    open(os.path.join(DIR(c), f'r{k}', 'analyst_out.txt'), 'w').write(r.stdout + r.stderr)
    after = open(fp, 'rb').read()
    bad = [f'phiên sửa fact lỗi (mã {r.returncode}): {(r.stdout + r.stderr).strip()[-200:]}'] if r.returncode else []   # vd hết hạn mức LLM
    if not after.startswith(before): bad.append('facts.jsonl bị sửa/xóa dòng cũ (chỉ được nối thêm)')
    bad += [f'mẫu đổi: {p}' for p, h in samples.items() if not os.path.exists(p) or sha_file(p) != h]
    if bad:
        open(fp, 'wb').write(before); print('PHÂN TÍCH LẠI BỊ HỦY, đã khôi phục facts.jsonl: ' + '; '.join(bad))
    return not bad, len(todo), after != before

def loop(c, llm=True):
    """review -> (FAIL) phân tích lại đúng các fact lỗi -> review lần 2 -> (FAIL) dừng + STOP_REPORT. Không cần người xác nhận giữa chừng."""
    code = review(c, llm)
    while code == 1:
        k = len(state(c)['rounds'])
        if CFG.review_backend() != 'claude' and not CFG.ANALYST_LLM_CMD:   # không có phiên analyst riêng: agent đang chạy flow tự sửa (SKILL.md, vòng phản biện bước 2)
            print(f'HANDOFF: agent hiện tại sửa các mục fail/weak ở trên theo where/redo, rồi chạy lại `flow.py review {c} --llm`'); return 3
        print(f'-- phân tích lại sau review {k}...')
        ok, n, changed = analyst(c, k)
        print(f'-- phân tích lại: {n} mục, facts {"đã đổi" if changed else "KHÔNG đổi"}' + ('' if ok else ', bị hủy'))
        if not ok or not changed:   # không tiêu lần review 2 cho facts không đổi; chạy lại review-loop sẽ tiếp từ bước sửa
            print('DỪNG: phân tích lại không tạo thay đổi hợp lệ; xem work/review/r%d/analyst_out.txt rồi chạy lại review-loop' % k); return 5
        code = review(c, llm, force=True)
    return code

def gate(c):
    """(ok, lý do). Dùng cho vmspec/report --final."""
    s = state(c)
    if not os.path.exists(os.path.join(c, 'facts.jsonl')): return False, 'chưa có facts.jsonl'
    h = facts_sha(c)
    ov = os.path.join(DIR(c), 'OVERRIDE')
    if os.path.exists(ov) and f'facts_sha256={h}' in open(ov).read(): return True, 'OVERRIDE do người dùng duyệt'
    if s.get('rule_version') != C.REVIEW_RULE_VERSION: return False, 'cổng đổi luật severity: chạy lại review'
    if s['stopped'] and s.get('reset_for') == h: return False, 'đã STOPPED sau 2 lần review'
    if s['rounds'] and s['rounds'][-1]['facts_sha256'] == h and s['rounds'][-1]['verdict'] == 'PASS': return True, f"review {s['rounds'][-1]['n']} PASS"
    return False, 'chưa có review PASS khớp facts.jsonl hiện tại'

# ---------- điểm dừng sớm ----------
def accepted(c):
    p = os.path.join(c, 'work', 'accepted.json')
    return json.load(open(p)) if os.path.exists(p) else {}

def next_step(c, accept=''):
    acc = accepted(c)
    for kv in filter(None, map(str.strip, re.split(r'[;,]\s*(?=C\d+=)', accept))):   # tách trước 'Cx=' nên lý do được chứa dấu phẩy
        k, _, why = kv.partition('=')
        if not why: raise SystemExit(f'--accept {k} cần lý do: {k}=lý do')
        acc[k] = why
    if accept: json.dump(acc, open(os.path.join(c, 'work', 'accepted.json'), 'w'), ensure_ascii=False, indent=1)
    rows = C.check(c)
    todo = [(k, v, n) for k, v, n in rows if not (v == 'ok' or v.startswith('n/a')) and k.split()[0] not in acc and k.split()[0] != 'C0']
    ok, why = gate(c)
    for k, v, n in todo: print(f'  còn thiếu: {k:<30} {v:<8} next: {n}')
    for k, why_ in acc.items(): print(f'  chấp nhận hạn chế: {k}: {why_}')
    if todo: print('NEED_MORE: quay lại tầng rẻ hơn (T2/T3) cho các mục trên; chỉ cân nhắc VM khi mục còn thiếu mà tầng rẻ không lấy được'); return 1
    if not ok: print(f'NEED_REVIEW: {why}'); return 1
    print('DONE: checklist đủ và phản biện đạt -> flow.py report --final rồi đóng case. KHÔNG cần chạy VM.' + (' Ghi các mục chấp nhận vào mục hạn chế.' if acc else ''))
    return 0

# ---------- selftest ----------
def selftest():
    c = tempfile.mkdtemp(); E = os.path.join(c, 'report', 'evidence'); os.makedirs(E); os.makedirs(os.path.join(c, 'work', 'sample'))
    open(os.path.join(c, 'work', 'sample', 'a.bin'), 'wb').write(b'abc')
    real = hashlib.sha256(b'abc').hexdigest()
    open(os.path.join(E, 'emu_x.txt'), 'w').write('host evil-c2.example.com:443\nHKCU\\\\Software\\\\Run\n')
    open(os.path.join(E, 'tri.txt'), 'w').write('nothing relevant\nfixed\n')
    A = lambda **kw: C.add(c, **kw)
    A(id='ok1', kind='c2', value='evil-c2.example.com:443', src='E', evidence='report/evidence/emu_x.txt#L1')
    A(id='h1', kind='hash', value=real + ' a.bin', src='S', evidence='report/evidence/tri.txt')
    A(id='bad_h', kind='hash', value='0' * 64, src='S', evidence='report/evidence/tri.txt')            # sai hash
    A(id='bad_c2', kind='c2', value='other-host.example.net', src='E', evidence='report/evidence/emu_x.txt')   # không có trong evidence
    A(id='bad_src', kind='file', value='whatever.dat', src='S', evidence='report/evidence/emu_x.txt')   # S dẫn evidence giả lập
    A(id='bad_line', kind='c2', value='evil-c2.example.com', src='E', evidence='report/evidence/emu_x.txt#L99')
    A(id='bad_low', kind='string', value='lowkind-token-zzz', src='S', evidence='report/evidence/tri.txt')   # kind không gating
    A(id='weak1', kind='family', value='x', src='S', evidence='report/evidence/tri.txt', note='có thể là họ X')
    its = mech(c); by = {i['id'] for i in its}; ck = {(i['id'], i['check']) for i in its}
    assert 'ok1' not in by and 'h1' not in by, its
    assert ('bad_h', 'hash_recompute') in ck and all(i['severity'] == 'high' for i in its if i['id'] == 'bad_h'), its
    assert {('bad_c2', 'value_in_evidence'), ('bad_src', 'src_vs_evidence'), ('bad_line', 'evidence_line')} <= ck, its
    assert all(i['severity'] == 'high' for i in its if i['id'] == 'bad_low'), its   # fail check cứng luôn high
    assert ('weak1', 'status_vs_note') in ck
    assert review(c) == 1 and review(c) == 1                      # facts chưa đổi: không tính thêm lần
    assert len(state(c)['rounds']) == 1 and not gate(c)[0]
    A(id='noise', kind='string', value='abcde-fghij', src='S', evidence='report/evidence/tri.txt', status='retracted')   # đổi facts, vẫn lỗi
    assert review(c) == 2 and state(c)['stopped'] and os.path.exists(os.path.join(DIR(c), 'STOP_REPORT.md'))
    assert not gate(c)[0] and review(c) == 2
    assert dict((k.split()[0], v) for k, v, _ in C.check(c))['C0'].startswith('fail(stopped)')
    for i in ('bad_h', 'bad_c2', 'bad_src', 'bad_line', 'bad_low'): A(id=i + '2', kind='string', value='fixed', src='S', evidence='report/evidence/tri.txt', supersedes=i)
    assert review(c) == 0 and gate(c)[0], mech(c)                  # sửa hết -> bộ đếm mới, PASS
    assert dict((k.split()[0], v) for k, v, _ in C.check(c))['C0'] in ('ok', 'partial')
    assert next_step(c) == 1                                       # checklist còn thiếu nhiều mục

    # luật cũ (state không có rule_version) phải bị coi là chưa review
    st = state(c); st.pop('rule_version', None); json.dump(st, open(os.path.join(DIR(c), 'state.json'), 'w'))
    assert not gate(c)[0] and dict((k.split()[0], v) for k, v, _ in C.check(c))['C0'] == 'missing'
    assert review(c, force=True) == 0 and gate(c)[0]               # review mở bộ đếm mới theo luật hiện tại
    print('OK selftest')

if __name__ == '__main__':
    a = sys.argv[1:]
    if not a or a[0] == '--selftest': selftest(); sys.exit()
    cmd, c = a[0], a[1]
    if cmd == 'review': sys.exit(review(c, '--llm' in a))
    elif cmd == 'review-loop': sys.exit(loop(c, '--no-llm' not in a))
    elif cmd == 'gate': ok, why = gate(c); print(('OK ' if ok else 'CHẶN ') + why); sys.exit(0 if ok else 1)
    elif cmd == 'next': sys.exit(next_step(c, a[a.index('--accept') + 1] if '--accept' in a else ''))
    else: raise SystemExit(f'lệnh lạ: {cmd}')
