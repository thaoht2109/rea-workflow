#!/usr/bin/env python3
# Điều phối flow phân tích dịch ngược cho mọi mẫu (FLOW.md). Không bao giờ thực thi mẫu.
#   flow.py new CASE MẪU...            tạo case, chép/giải nén mẫu vào work/sample (0400), README từ template, triage tất cả
#   flow.py triage CASE [FILE...]      triage tĩnh (tự upx -d bản sao nếu là UPX), ghi fact src=S
#   flow.py dec CASE FILE HÀM...       decompile từng hàm (rea; kiến trúc rea không hỗ trợ thì Ghidra headless),
#                                      'list:CHUỖI' liệt kê hàm; lưu work/runs/dec/, in tối đa 80 dòng mỗi hàm
#   flow.py status CASE                checklist C1–C11 + bước kế tiếp từ triage
#   flow.py resume CASE                tóm tắt để làm tiếp sau khi ngữ cảnh bị nén/clear: tính từ facts, không lưu file riêng
#   flow.py report CASE [--final] | audit CASE   sinh report/GENERATED.md (--final: chỉ khi phản biện đạt) | đối chiếu evidence README với đĩa
#   flow.py doctor                     kiểm cấu hình theo máy (rea.env) trước khi chạy trên server mới
#   flow.py rules [--global|--project [DIR]] [--check|--remove]   chép 'Quy tắc bắt buộc' vào CLAUDE.md/AGENTS.md (mặc định theo phạm vi cài skill)
#   flow.py review-loop CASE   review -> tự sửa fact lỗi -> review lần 2 -> dừng nếu vẫn FAIL
#   flow.py review CASE [--llm] [--detach] | gate CASE | next CASE [--accept Cx=lý do]   cổng phản biện facts (tối đa 2 lần) | kiểm cổng | dừng sớm khi đủ
import sys, os, re, json, shutil, datetime, subprocess

TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOLS); import case, reacfg as CFG   # cấu hình theo máy: reacfg.py
TMP = CFG.TMP

def sh(*a, **kw): return subprocess.run(a, check=True, **kw)

def samples(c):
    root = os.path.join(c, 'work', 'sample')
    return sorted(os.path.join(d, n) for d, _, ns in os.walk(root) for n in ns)

def new(c, srcs):
    sd = os.path.join(c, 'work', 'sample')
    for d in (sd, os.path.join(c, 'work', 'runs'), os.path.join(c, 'report', 'evidence')): os.makedirs(d, exist_ok=True)
    for s in srcs:
        head = open(s, 'rb').read(8)
        if head.startswith((b'PK\x03\x04', b'7z\xbc\xaf', b'Rar!')):
            for pw in ('', 'infected', 'malware'):   # mật khẩu quy ước của kho mẫu; 7z chỉ giải nén, không chạy gì
                r = subprocess.run([CFG.SEVENZ, 'x', '-y', f'-p{pw}', f'-o{sd}', s], capture_output=True)
                if r.returncode == 0: print(f'giải nén {s} (mật khẩu {pw!r})'); break
            else: raise SystemExit(f'không giải nén được {s}: cần mật khẩu')
        else: shutil.copy2(s, sd)
    for p in samples(c): os.chmod(p, 0o400)
    rd = os.path.join(c, 'report', 'README.md')
    if not os.path.exists(rd):
        t = open(os.path.join(TOOLS, 'templates', 'README.md'), encoding='utf-8').read()
        open(rd, 'w', encoding='utf-8').write(t.replace('{CASE}', os.path.basename(os.path.abspath(c)))
                                              .replace('{DATE}', datetime.date.today().isoformat()))
    triage(c, samples(c))

def triage(c, files):
    for f in files:
        out = os.path.join(c, 'work', 'runs', 'triage_' + re.sub(r'\W+', '_', os.path.basename(f))[:40])
        print(f'===== {os.path.relpath(f, c)}')
        sh(sys.executable, '-I', os.path.join(TOOLS, 'static', 'triage.py'), f, '--out', out, '--facts', c)
        R = json.load(open(os.path.join(out, 'triage.json')))
        if 'UPX' in R['flags'] and not f.endswith('.unupx'):
            u = f + '.unupx'   # upx -d là giải nén tĩnh, không chạy mẫu
            if not os.path.exists(u) and subprocess.run([CFG.UPX, '-d', '-q', '-o', u, f], capture_output=True).returncode == 0:
                os.chmod(u, 0o400)
            if os.path.exists(u): triage(c, [u])
            else: print('upx -d thất bại (UPX bị sửa header?): tìm stub giải nén bằng T2/T3')


def show(fn, code, p, c):
    lines = code.strip().splitlines()
    print(f'## {fn} ({len(lines)} dòng) -> {os.path.relpath(p, c)}'); print('\n'.join(lines[:80]))
    if len(lines) > 80: print(f'... còn {len(lines) - 80} dòng: đọc có giới hạn bằng sed -n')

def ghidra_dec(c, f, funcs, od, tag):
    """Ghidra headless cho kiến trúc rea không hỗ trợ. Project giữ ở work/ghidra/: lần đầu phân tích cả file (chậm), sau đó -noanalysis."""
    if not CFG.GHIDRA: print('Chưa khai báo GHIDRA_INSTALL_DIR (rea.env)'); return
    pd = os.path.join(os.path.abspath(c), 'work', 'ghidra'); os.makedirs(pd, exist_ok=True)
    out = os.path.join(os.path.abspath(od), tag + '_ghidra.c')
    mode = ['-process', os.path.basename(f), '-noanalysis'] if os.path.exists(os.path.join(pd, tag + '.gpr')) else ['-import', os.path.abspath(f)]
    log, names = os.path.join(pd, tag + '.log'), os.path.join(pd, tag + '.gonames')
    pre = []
    if not os.path.exists(names):   # Go bị strip: Ghidra không tự khôi phục tên trên MIPS… -> lấy từ .gopclntab
        r = subprocess.run([sys.executable, '-I', os.path.join(TOOLS, 'static', 'gopclntab.py'), f], capture_output=True, text=True)
        open(names, 'w').write(r.stdout if r.returncode == 0 else '')
    if os.path.getsize(names) and mode[0] == '-import': pre = ['-postScript', 'ApplyNames.java', names]
    with open(log, 'w') as lf:
        r = subprocess.run([os.path.join(CFG.GHIDRA, 'support', 'analyzeHeadless'), pd, tag, *mode, '-scriptPath',
                            os.path.join(TOOLS, 'static', 'ghidra'), *pre, '-postScript', 'ExportDecomp.java', out, *funcs],
                           stdout=lf, stderr=subprocess.STDOUT, env=CFG.tmpenv(JAVA_TOOL_OPTIONS=f'-Djava.io.tmpdir={TMP}', **({'JAVA_HOME': CFG.JAVA_HOME} if CFG.JAVA_HOME else {})))
    if r.returncode or not os.path.exists(out): print(f'Ghidra lỗi (rc={r.returncode}), xem {os.path.relpath(log, c)}'); return
    body = ''.join(l for l in open(out) if not l.startswith('// fn '))
    for part in body.split('// ===== ')[1:]:
        fn = part.split(' ', 1)[0].split(':')[0]
        p = os.path.join(od, re.sub(r'\W+', '_', f'{tag}_{fn}') + '.c'); open(p, 'w').write('// ' + part)
        show(fn, part, p, c)
    lst = [l for l in open(out) if l.startswith('// fn ')]
    if lst: print(f'{len(lst)} hàm khớp list: (tối đa 60 dòng)'); print(''.join(lst[:60]), end='')

def dec(c, f, funcs):
    os.makedirs(TMP, exist_ok=True); od = os.path.join(c, 'work', 'runs', 'dec'); os.makedirs(od, exist_ok=True)
    tag = re.sub(r'\W+', '_', os.path.basename(f))
    snap = os.path.join(c, 'work', 'rea_' + tag + '.snapshot')
    env = CFG.tmpenv()
    if not any(x.startswith('list:') for x in funcs):
        run = lambda fn: subprocess.run([CFG.REA_BIN, 'decompile', f, '--procedure=' + fn, '--snapshot', snap, '--format', 'json'],
                                        capture_output=True, text=True, env=env)
        from concurrent.futures import ThreadPoolExecutor   # mỗi lần rea phân tích lại cả file (~30 s, 2 lõi): chạy song song
        with ThreadPoolExecutor(3) as ex: res = list(ex.map(run, funcs))
        left = []
        for fn, r in zip(funcs, res):
            try: j = json.loads(r.stdout)
            except ValueError: print(f'## {fn}: rea lỗi\n{(r.stdout + r.stderr)[-800:]}'); continue
            if 'error' in j:
                if j['code'] == 'capability_unavailable': left.append(fn); continue
                dg = j.get('details', {}).get('diagnostics', {})
                print(f"## {fn}: {j['code']}: {dg.get('failure_message') or j.get('message')}"); continue
            code = j['normalized_result'] if isinstance(j['normalized_result'], str) else json.dumps(j['normalized_result'], ensure_ascii=False, indent=1)
            p = os.path.join(od, re.sub(r'\W+', '_', f'{tag}_{fn}') + '.c'); open(p, 'w').write(code)
            show(fn, code, p, c)
        funcs = left
    if funcs:
        print(f'rea không hỗ trợ kiến trúc này hoặc cần list: -> Ghidra headless cho: {" ".join(funcs)}')
        ghidra_dec(c, f, funcs, od, tag)

def status(c):
    for k, v, n in case.check(c): print(f'{k:<34} {v:<10} {"next: " + n if n else ""}')
    for d in sorted(os.listdir(os.path.join(c, 'work', 'runs'))):
        p = os.path.join(c, 'work', 'runs', d, 'triage.json')
        if d.startswith('triage_') and os.path.exists(p):
            R = json.load(open(p)); print(f"triage {R['file']}: {R['type']} {' '.join(R['flags'])} -> {R['next']}")

def resume(c):
    """Working state tính lại từ nguồn chân lý (facts.jsonl, checklist, cổng): không có file state riêng nên không thể lệch."""
    import review
    F, acc, (ok, why) = case.load(c), review.accepted(c), review.gate(c)
    act = [f for f in F.values() if f['status'] == 'active']; hyp = [f for f in F.values() if f['status'] == 'hypothesis']
    print(f'# resume {c}: {len(act)} fact active, {len(hyp)} hypothesis. Nguồn chân lý: {c}/facts.jsonl; tra lại: case.py show {c} --id ID | case.py search {c} TỪ')
    todo = [(k, v, n) for k, v, n in case.check(c) if not (v == 'ok' or v.startswith('n/a')) and k.split()[0] not in acc]
    print('## Việc kế tiếp' + ('' if todo else ': checklist đủ'))
    for k, v, n in todo[:6]: print(f'- {k} ({v}): {n}')
    print(f"## Cổng phản biện: {'OK' if ok else 'CHẶN'} ({why})")
    for k, w in acc.items(): print(f'- chấp nhận hạn chế {k}: {w}')
    key = [f for f in act if f['kind'] in review.GATING | {'family'} and f['kind'] != 'hash']   # hash chỉ đếm: dài, ít khi cần để suy luận
    nh = sum(f['kind'] == 'hash' for f in act)
    print(f'## Fact kết luận (nguyên văn, {len(key)})' + (f'; {nh} hash: case.py show {c} hash' if nh else ''))
    for f in key[:25]: print(f"- {f['id']} [{f['kind']} {f['src']}] {f['value'][:200]} @ {f['evidence']}")
    if len(key) > 25: print(f'- (+{len(key) - 25}: case.py show {c} <kind>)')
    print(f'## Giả thuyết còn mở ({len(hyp)})')
    for f in hyp[:12]: print(f"- {f['id']} [{f['kind']}] {f['value'][:160]}")
    if len(hyp) > 12: print(f'- (+{len(hyp) - 12}: case.py search {c} --all)')

# ---------- chép "Quy tắc bắt buộc" của SKILL.md vào file hướng dẫn agent ----------
RB, RE_ = '<!-- rea-flow:rules:begin (sinh bởi flow.py rules; sửa SKILL.md rồi chạy lại) -->', '<!-- rea-flow:rules:end -->'

def rules_scope():
    """Đoán phạm vi theo nơi skill được cài: ~/.<agent>/skills/rea-flow -> global; <project>/.<agent>/skills/rea-flow -> project."""
    p, home = os.path.realpath(TOOLS), os.path.realpath(os.path.expanduser('~'))
    m = re.match(r'(.*?)/\.[^/]+/(?:[^/]+/)*skills/[^/]+$', p)
    return None if not m else ('global', home) if m.group(1) == home else ('project', m.group(1))

def rules_targets(scope, root):
    if scope == 'project':   # AGENTS.md: Codex, Cursor, Copilot…; CLAUDE.md: Claude Code; GEMINI.md chỉ khi project đã dùng
        return [os.path.join(root, f) for f in ('AGENTS.md', 'CLAUDE.md')] + [p for p in [os.path.join(root, 'GEMINI.md')] if os.path.exists(p)]
    return [os.path.join(root, d, f) for d, f in (('.claude', 'CLAUDE.md'), ('.codex', 'AGENTS.md'), ('.gemini', 'GEMINI.md'))
            if os.path.isdir(os.path.join(root, d))]   # chỉ agent đã cài trên máy

def rules(a):
    """flow.py rules [--global | --project [DIR]] [--check | --remove]. Mặc định: phạm vi theo nơi cài skill."""
    if '--global' in a: sc = ('global', os.path.expanduser('~'))
    elif '--project' in a:
        i = a.index('--project'); sc = ('project', os.path.abspath(a[i + 1] if i + 1 < len(a) and not a[i + 1].startswith('-') else '.'))
    else: sc = rules_scope()
    if not sc: print('Không đoán được phạm vi (skill không nằm trong thư mục skills của agent): dùng --global hoặc --project [DIR]'); return 2
    T = os.path.realpath(TOOLS)   # đường dẫn ổn định dù gọi qua symlink nào
    sk = open(os.path.join(T, 'SKILL.md'), encoding='utf-8').read()
    body = sk.split('## Quy tắc bắt buộc', 1)[1].split('\n## ', 1)[0].strip().replace('$SKILL', T)
    blk = (f'{RB}\n## rea-flow: quy tắc bắt buộc khi phân tích mã độc\n\nÁp dụng mỗi khi làm việc với mẫu mã độc hoặc case dịch ngược '
           f'(skill rea-flow tại `{T}`, lệnh và quy trình trong `{T}/SKILL.md`).\n\n{body}\n{RE_}\n')
    pat = re.compile(re.escape(RB) + r'.*?' + re.escape(RE_) + r'\n?', re.S)
    bad = 0
    print(f'phạm vi: {sc[0]} ({sc[1]})')
    for p in rules_targets(*sc):
        s = open(p, encoding='utf-8').read() if os.path.exists(p) else ''
        if '--check' in a:
            ok = blk in s; bad += not ok; print(f"  {'OK   ' if ok else 'THIẾU'} {p}"); continue
        new = pat.sub('', s).rstrip() + '\n' if '--remove' in a else pat.sub(lambda _: blk, s) if RB in s else (s.rstrip() + '\n\n' if s.strip() else '') + blk
        if new.strip() != s.strip():
            if new.strip(): os.makedirs(os.path.dirname(p), exist_ok=True); open(p, 'w', encoding='utf-8').write(new)
            elif os.path.exists(p): os.remove(p)   # file chỉ có khối của rea-flow
            print(f"  {'gỡ' if '--remove' in a else 'ghi'} {p}")
        else: print(f'  không đổi {p}')
    return 1 if bad else 0

if __name__ == '__main__':
    a = sys.argv[1:]
    if a[:1] == ['doctor']: sys.exit(CFG.doctor())
    if a[:1] == ['rules']: sys.exit(rules(a[1:]))
    if len(a) < 2: raise SystemExit(__doc__ or open(__file__).read().split('import')[0])
    cmd, c = a[0], a[1]
    if cmd == 'new': new(c, a[2:])
    elif cmd == 'triage': triage(c, a[2:] or samples(c))
    elif cmd == 'dec': dec(c, a[2], a[3:])
    elif cmd == 'status': status(c)
    elif cmd == 'resume': resume(c)
    elif cmd == 'report':
        if '--final' in a:   # báo cáo cuối chỉ khi cổng phản biện đạt (review.py)
            import review; ok, why = review.gate(c)
            if not ok: raise SystemExit(f'CHẶN report --final: {why}')
        print(f'{len(case.report(c))} dòng -> {c}/report/GENERATED.md')
    elif cmd in ('review', 'review-loop') and '--detach' in a: import review; sys.exit(review.detach(c, cmd, [x for x in a[2:] if x != '--detach']))
    elif cmd == 'review': import review; sys.exit(review.review(c, '--llm' in a))
    elif cmd == 'review-loop': import review; sys.exit(review.loop(c, '--no-llm' not in a))
    elif cmd == 'next': import review; sys.exit(review.next_step(c, a[a.index('--accept') + 1] if '--accept' in a else ''))
    elif cmd == 'gate':
        import review; ok, why = review.gate(c); print(('OK ' if ok else 'CHẶN ') + why); sys.exit(0 if ok else 1)
    elif cmd == 'audit':
        p = case.audit(c); print('\n'.join(p) if p else 'OK audit'); sys.exit(1 if p else 0)
    else: raise SystemExit(f'lệnh lạ: {cmd}')
