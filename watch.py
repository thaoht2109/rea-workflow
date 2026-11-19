#!/usr/bin/env python3
# flow.py watch: theo dõi thư mục mẫu; mẫu mới (theo sha256) thành case, rồi đẩy case qua quy trình bằng các phiên `claude -p` riêng,
# mỗi phiên làm một mốc theo `flow.py next` rồi thoát. Không bao giờ thực thi mẫu.
# Trạng thái nằm trong case (work/watch.json) nên dừng/chạy lại không mất gì; khóa flock theo case nên chạy nhiều watcher song song được.
# Không có người duyệt: an toàn dựa vào allowlist công cụ + hậu kiểm lệnh Bash của từng phiên. Nên chạy trong VM không có mạng ra ngoài.
import os, re, sys, glob, json, time, fcntl, shlex, shutil, hashlib, datetime, subprocess

TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOLS); import case as C, reacfg as CFG   # noqa: E402
from evals.run import ALLOWED, GENERIC, POS, exec_rules, parse, run_agent   # noqa: E402  cùng allowlist/bộ đọc transcript với bộ eval

FLOW = os.path.join(TOOLS, 'flow.py')
num = lambda k, d: int(CFG.get(k, d, path=False))
MAXS, STALL, INTERVAL, TIMEOUT, SETTLE = (num('REA_WATCH_MAX_SESSIONS', '10'), num('REA_WATCH_STALL', '3'), num('REA_WATCH_INTERVAL', '60'),
                                          num('REA_WATCH_TIMEOUT', '1800'), num('REA_WATCH_SETTLE', '10'))
MAXT = num('REA_WATCH_MAX_TURNS', '80')   # số lượt tối đa của một phiên claude -p (một mốc phân tích)
MAXN = num('REA_WATCH_MAX_NEW', '20')     # số case mới tối đa mỗi vòng quét: thư mục giải nén nhiều file không đẻ hàng trăm case một lúc
ALIAS = CFG.get('REA_WATCH_ALIAS_SUFFIX', '', path=False)   # X<hậu tố>/ là bản giải nén của X/ cùng cấp: chỉ quét bản giải nén, báo cáo về X/
STATES = r'^(STOPPED|NEED_MORE|NEED_FIX|NEED_REVIEW|NEED_REPORT|DONE)\b'
PROMPT = ('Phiên tự động do `flow.py watch` mở cho case `{c}`: không có người trả lời, đừng hỏi. Chạy `python3 {F} resume {c}` rồi `python3 {F} next {c}` '
          'và làm MỘT mốc theo kết quả (NEED_MORE: phân tích tiếp; NEED_FIX: sửa fact theo where/redo; NEED_REPORT: cập nhật báo cáo viết tay). '
          'Không thực thi mẫu. Hậu kiểm tự động sẽ DỪNG case nếu thấy lệnh có dạng chạy mẫu, kể cả khi chỉ đọc: chạy công cụ phân tích trực tiếp '
          '`python3 -I work/tools/X.py <mẫu> ...` (ghi kết quả bằng `>`), KHÔNG gọi công cụ qua subprocess/os.system/os.popen/runpy/pty trên cùng dòng có tên mẫu. '
          'Công cụ tự viết (work/tools, tầng T1b) chạy bằng `python3 -I work/tools/X.py ...` (allowlist không có `bwrap`), file dẫn xuất chỉ ghi vào '
          'OUT_DIR = work/runs/tool/<TÊN>/ (evidence ghi ISOLATION net=có thì bị cảnh báo tool_isolation: chấp nhận, cô lập thật nhờ chạy watcher trong VM không mạng). '
          'KHÔNG đưa đường dẫn mẫu vào `python3 -c` hay heredoc `python3 - <<EOF` (kể cả chỉ để đọc byte: dùng công cụ trong work/tools, xxd, strings), không `python3 -m … <mẫu>`, không `chmod +x`, không `./<mẫu>`, `sh|bash|python <mẫu>`, `< <mẫu>`, `<mẫu> | sh`. '
          'Không chạy `flow.py review`, `review-loop`, `report --final` (bộ theo dõi lo) hay `flow.py watch`, không gọi skill rea-workflow:auto. '
          'Ghi hết kết luận thành fact, chạy `python3 {F} checkpoint {c}` rồi kết thúc.')

def say(c, m): print(f'{datetime.datetime.now():%F %T} [{c or "watch"}] {m}', flush=True)
def flow(*a): return subprocess.run([sys.executable, FLOW, *a], capture_output=True, text=True)
def wj(c): return os.path.join(c, 'work', 'watch.json')
def load(c):
    try: return json.load(open(wj(c), encoding='utf-8'))
    except (OSError, ValueError): return {}
def save(c, st): open(wj(c) + '.tmp', 'w', encoding='utf-8').write(json.dumps(st, ensure_ascii=False, indent=1)); os.replace(wj(c) + '.tmp', wj(c))
def stop(c, st, why):
    st['stop'] = why; save(c, st)
    say(c, ('XONG: ' if why.startswith('DONE') else 'DỪNG, cần người: ') + why + ('' if why.startswith('DONE') else f'. Chạy tiếp: xóa khóa "stop" trong {wj(c)} (và đặt "stall"/"sessions" về 0 nếu dừng vì chúng)'))

def lock(c):
    f = open(os.path.join(c, 'work', '.watch.lock'), 'a')
    try: fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB); return f
    except BlockingIOError: f.close(); return None   # phiên/watcher khác đang giữ case

def fp(c):
    """Dấu vân tay tiến độ: facts + báo cáo viết tay (NEED_REPORT chỉ sửa báo cáo)."""
    h = hashlib.sha256()
    for p in (os.path.join(c, 'facts.jsonl'), C.report_md(c)):
        if os.path.exists(p): h.update(open(p, 'rb').read())
    return h.hexdigest()

def exec_pats(c):
    """Lệnh có dấu hiệu chạy mẫu: cùng luật với bộ eval (evals/run.py exec_rules), theo tên mẫu thật của case."""
    names = {n for _, _, ns in os.walk(os.path.join(c, 'work', 'sample')) for n in ns}
    return [re.compile(p) for p in GENERIC + [r for n in map(re.escape, names) for r in exec_rules(n)]]

NESTED = re.compile(POS + r'(?:\S*/)?(?:python[\d.]*\s+(?:-\S+\s+)*)?\S*flow\.py\s+watch(?![\w.])'   # watch.py không có __main__
                    r'|' + POS + r'(?:\S*/)?python[\d.]*\s+(?:-\S+\s+)*-[A-Za-z]*c\b[^\n]*(?:\bwatch\.main\s*\(|\b(?:import|from)\s+watch\b)'
                    r'''|(?:subprocess|os\.system|os\.exec|os\.spawn|popen|runpy)[^\n]*flow\.py['"]?\s*,?\s*['"]?watch(?![\w.])''')
RUN_TOOL = re.compile(r'capture|debug|spawn|attach|instrument|frida|run_?target|execute', re.I)   # tool MCP chạy target

def tool_names(out):
    """Tên mọi tool_use trong transcript stream-json (kể cả lời gọi bị từ chối: ý định chạy mẫu cũng là vi phạm)."""
    r = []
    for l in out.splitlines():
        try: e = json.loads(l)
        except ValueError: continue
        if isinstance(e, dict) and e.get('type') == 'assistant':
            r += [b.get('name', '') for b in (e.get('message') or {}).get('content', []) if isinstance(b, dict) and b.get('type') == 'tool_use']
    return r

def models(help_text):
    """Alias model mà CLI claude đang cài khai trong `claude --help` (vd 'fable', 'opus', 'sonnet')."""
    m = re.search(r'--model <model>(.*?)\n\s*-', help_text, re.S)
    return re.findall(r"'([\w.-]+)'", m[1]) if m else []

def pick_model(a):
    """--model > REA_WATCH_MODEL > hỏi (chỉ khi có terminal) > trống = mặc định của claude."""
    if '--model' in a:
        i = a.index('--model'); return a[i + 1] if i + 1 < len(a) and not a[i + 1].startswith('-') else None
    m = CFG.get('REA_WATCH_MODEL', '', path=False)
    if m or not sys.stdin.isatty(): return m
    try: ms = models(subprocess.run([CFG.CLAUDE, '--help'], capture_output=True, text=True, timeout=30).stdout)
    except (OSError, subprocess.TimeoutExpired): ms = []
    print('Model cho phiên phân tích:\n  0) mặc định của claude\n' + ''.join(f'  {i}) {x}\n' for i, x in enumerate(ms, 1)) + '  hoặc gõ tên model đầy đủ')
    x = input('chọn [0]: ').strip()
    return ms[int(x) - 1] if x.isdigit() and 0 < int(x) <= len(ms) else '' if x in ('', '0') else x

def session(c, st, model):
    r = flow('session', '--print')
    if r.returncode: return stop(c, st, f'không mở được phiên: {(r.stdout + r.stderr).strip()[-300:]}')
    argv = shlex.split(r.stdout.strip().splitlines()[-1])
    if '--mcp-config' in argv: argv[argv.index('--mcp-config') + 1] = '{"mcpServers":{}}'   # không MCP: tool frida/rea chạy mẫu không qua hậu kiểm Bash
    argv += ['-p', PROMPT.format(c=c, F=FLOW), '--output-format', 'stream-json', '--verbose', '--no-session-persistence', '--permission-mode', 'default',
             '--allowedTools', ALLOWED, '--disallowedTools', 'WebFetch,WebSearch,Agent', '--max-turns', str(MAXT)] + (['--model', model] if model else [])
    n = st['sessions'] = st.get('sessions', 0) + 1; save(c, st)
    before = fp(c); say(c, f'phiên {n}/{MAXS}')
    out = run_agent(argv, os.getcwd(), TIMEOUT)
    d = os.path.join(c, 'work', 'runs', 'watch'); os.makedirs(d, exist_ok=True)
    open(os.path.join(d, f's{n:02d}.jsonl'), 'w', encoding='utf-8').write(out)
    cmds, _, init = parse(out)
    bad = ([x for x in cmds if any(p.search(x) for p in exec_pats(c)) or NESTED.search(x)]   # chạy mẫu hoặc mở watcher lồng (ngoài trần phiên)
           + [t for t in tool_names(out) if t.startswith('mcp__') and RUN_TOOL.search(t)])
    st['stall'] = 0 if fp(c) != before else st.get('stall', 0) + 1
    say(c, f"phiên {n} xong: facts/báo cáo {'đổi' if not st['stall'] else 'không đổi'}" + (f", lỗi: {init['_error']}" if init['_error'] else ''))
    why = (f'hậu kiểm: lệnh bị cấm (chạy mẫu hoặc watch lồng) ở phiên {n}: {bad[0][:200]}' if bad else f"{st['stall']} phiên liên tiếp không đổi facts/báo cáo" if st['stall'] >= STALL
           else f'đủ {MAXS} phiên' if n >= MAXS else '')
    stop(c, st, why) if why else save(c, st)

def step(c, model, report=None):
    f = lock(c)
    if not f: return
    with f:
        st = load(c)
        if st.get('stop'): return
        r = flow('next', c); k = (re.search(STATES, r.stdout, re.M) or [None, None])[1]
        if k == 'STOPPED': stop(c, st, f'STOPPED: phản biện FAIL 2 lần, xem {c}/work/review/STOP_REPORT.md')
        elif k == 'DONE':
            r = flow('report', c, '--final')
            if r.returncode: return stop(c, st, f'report --final lỗi: {(r.stdout + r.stderr).strip()[-300:]}')
            try:
                out = publish(c, st, report)
                if out: st['published'] = out
                stop(c, st, 'DONE: đã report --final' + (f', báo cáo chép vào {out}' if out else ''))
            except OSError as e: stop(c, st, f'DONE: đã report --final nhưng chép báo cáo lỗi: {e}')
        elif k == 'NEED_REVIEW':   # review nền tự chống chạy trùng; gọi lại mỗi vòng để lấy kết quả (mã 6 = đang chạy)
            r = flow('review', c, '--llm', '--detach')
            if r.returncode in (4, 7): stop(c, st, f'review lớp 2 cần người (mã {r.returncode}): {r.stdout.strip()[-300:]}')
            elif r.returncode != 6: say(c, f'review xong (mã {r.returncode})')
        elif k: session(c, st, model)
        else: stop(c, st, f'next không ra trạng thái: {(r.stdout + r.stderr).strip()[-300:]}')

NOTE_EXT, NOTE_MAX = ('.txt', '.log', '.md', '.note', '.notes'), 256 * 1024
SUMS = re.compile(r'(?:^|[._-])(?:sha256sums?|sha256)(?:\.txt)?$', re.I)
SCRIPT = re.compile(r'\A#!|\|\s*(?:ba|z|da)?sh\b|\b(?:curl|wget|powershell|iex|Invoke-\w+|certutil|bitsadmin|nc|ncat|socat)\b|base64\s+-d|\beval\b', re.I)
ARCH = re.compile(r'\.(?:tar\.gz|tar\.bz2|tar\.xz|tgz|tar|gz|bz2|xz|zip|7z|rar)$', re.I)
NOTES_LOG = '.watch_notes.tsv'   # trong workspace: các file bị coi là ghi chú, không thành case (thời điểm, đường dẫn, lý do)
_HASH, _NOTED = {}, set()   # _HASH: đường dẫn -> (mtime, size, sha256), không băm lại file không đổi mỗi vòng

def stem(name): return ARCH.sub('', name) or name   # tên thư mục báo cáo của mẫu: bỏ đuôi nén (x.tar.gz -> x)

def sha(p):
    s = os.stat(p); k = (s.st_mtime_ns, s.st_size)
    if _HASH.get(p, (None,))[:2] != k:
        h = hashlib.sha256()
        with open(p, 'rb') as f:
            for b in iter(lambda: f.read(1 << 20), b''): h.update(b)
        _HASH[p] = k + (h.hexdigest(),)
    return _HASH[p][2]

def report_root(inbox, name):
    """Thư mục nhận báo cáo khi watch chạy với --report: Report_<TÊN> cạnh INBOX (cùng thư mục cha), hoặc đúng đường dẫn TÊN nếu có dấu /."""
    if not name: return None
    return os.path.abspath(name) if os.sep in name else os.path.join(os.path.dirname(os.path.abspath(inbox)), 'Report_' + name)

def samples(inbox, skip=()):
    """Mọi file mẫu trong INBOX và thư mục con. Bỏ file/thư mục ẩn, symlink, thư mục Report_*, các thư mục trong skip (workspace, thư mục báo cáo)
    và thư mục case nếu chúng nằm trong INBOX. Có REA_WATCH_ALIAS_SUFFIX thì X/ bị bỏ khi cùng cấp có X<hậu tố>/ (bản giải nén của X)."""
    skip = {os.path.abspath(x) for x in skip if x}
    for d, ds, fs in os.walk(os.path.abspath(inbox)):
        ds[:] = sorted(x for x in ds if not x.startswith('.') and not x.startswith('Report_') and os.path.join(d, x) not in skip
                       and not os.path.exists(os.path.join(d, x, 'work', 'watch.json')) and not (ALIAS and x + ALIAS in ds))
        for n in sorted(fs):
            p = os.path.join(d, n)
            if not n.startswith('.') and os.path.isfile(p) and not os.path.islink(p): yield p

def _text(p):
    try:
        if os.path.getsize(p) > NOTE_MAX: return None
        b = open(p, 'rb').read()
    except OSError: return None
    if b'\0' in b[:8192]: return None
    try: return b.decode('utf-8')
    except UnicodeDecodeError: return None

def note_of(p):
    """Lý do (chuỗi khác rỗng) nếu p là ghi chú thu mẫu đi kèm, không phải mẫu: SHA256SUMS/*.sha256, hoặc file text đuôi .txt/.log/.md/.note(s) mà tên bắt đầu bằng
    tên (bỏ đuôi) của một file cùng thư mục, hoặc nội dung nhắc sha256 của một file cùng thư mục. File cùng thư mục được dùng để đối chiếu
    phải là file không mang đuôi ghi chú: hai ghi chú cạnh nhau (x.txt, x.log) không làm nhau thành ghi chú. Script thật (install.sh) vẫn là mẫu."""
    n, d = os.path.basename(p), os.path.dirname(p)
    if SUMS.search(n): return 'tên dạng SHA256SUMS'
    if not n.lower().endswith(NOTE_EXT): return ''
    t = _text(p)
    if t is None or SCRIPT.search(t): return ''   # nội dung trông như script (shebang, | sh, curl, base64 -d...): coi là mẫu
    sib = [os.path.join(d, x) for x in os.listdir(d) if x != n and not x.startswith('.') and not x.lower().endswith(NOTE_EXT)
           and not SUMS.search(x) and os.path.isfile(os.path.join(d, x))]
    for q in sib:
        if n.startswith(os.path.splitext(os.path.basename(q))[0] + '.'): return f'tên bắt đầu bằng tên của {os.path.basename(q)}'
    if not re.search(r'\b[0-9a-f]{64}\b', t): return ''
    for q in sib:
        try:
            if sha(q) in t: return f'nhắc sha256 của {os.path.basename(q)}'
        except OSError: pass
    return ''

def reported(root):
    """sha256 các mẫu đã có báo cáo trong thư mục báo cáo (dòng đầu README.txt của <mẫu>_data/): mẫu đã xong không bị phân tích lại,
    kể cả khi thư mục case đã xóa sau khi xuất."""
    out = set()
    for r in glob.glob(os.path.join(glob.escape(root), '**', '*_data', 'README.txt'), recursive=True):
        try: m = re.search(r'\(sha256 ([0-9a-f]{64})\)', open(r, encoding='utf-8', errors='replace').readline())
        except OSError: continue
        if m: out.add(m.group(1))
    return out

def publish(c, st, report=None):
    """Case DONE và watch chạy với --report: chép báo cáo vào <thư mục báo cáo>/<đường dẫn tương đối của mẫu trong INBOX>/<tên mẫu>_data/.
    Mẫu nằm thẳng trong INBOX hoặc trong thư mục cấp một (INBOX/U/x.tar.gz) thì thêm thư mục riêng theo tên mẫu bỏ đuôi nén (U/x/).
    Có REA_WATCH_ALIAS_SUFFIX thì X<hậu tố>/a ra X/a, chung chỗ với file nén gốc X/. Trả thư mục chứa <mẫu>_data, hoặc '' nếu không xuất."""
    src, name_ = st.get('source'), st.get('report') or report
    if not src or not name_: return ''
    src = os.path.abspath(src); inbox = os.path.abspath(st.get('inbox') or os.path.dirname(src))
    rel = os.path.relpath(os.path.dirname(src), inbox)
    parts = [] if rel == '.' or rel.startswith('..') else rel.split(os.sep)
    if parts and ALIAS and parts[0].endswith(ALIAS) and len(parts[0]) > len(ALIAS): parts[0] = parts[0][:-len(ALIAS)]
    if len(parts) < 2: parts.append(stem(os.path.basename(src)))
    out = os.path.join(report_root(inbox, name_), *parts); name = os.path.basename(src); d = os.path.join(out, name + '_data')
    os.makedirs(d, exist_ok=True)
    for f, x in ((C.report_md(c), '.md'), (C.report_html(c), '.html')):
        if os.path.isfile(f): shutil.copyfile(f, os.path.join(d, name + x))
    h = st.get('sha256') or sha(src)
    open(os.path.join(d, 'README.txt'), 'w', encoding='utf-8').write(   # dòng đầu: reported() đọc sha256 ở đây
        f'Dữ liệu phân tích của mẫu {name} (sha256 {h}), chép từ case {os.path.basename(os.path.abspath(c))}.\n\n'
        f'{name}.md, {name}.html  báo cáo của mẫu (bản HTML để xem)\n')
    return out

def ingest(inbox, report=None):
    root = report_root(inbox, report)
    known = {load(os.path.dirname(os.path.dirname(p))).get('sha256') for p in glob.glob('*/work/watch.json')} | (reported(root) if root else set())
    new = 0
    for p in samples(inbox, (os.getcwd(), root)):
        try:
            if time.time() - os.stat(p).st_mtime < SETTLE: continue   # còn đang chép
            why = note_of(p)
            if why:
                if p not in _NOTED:   # ghi lại để người kiểm: một mẫu dạng text bị nhận nhầm là ghi chú thì thấy được ở đây
                    _NOTED.add(p); say('', f'bỏ qua {p}: ghi chú thu mẫu đi kèm ({why}), không phải mẫu')
                    with open(NOTES_LOG, 'a', encoding='utf-8') as f: f.write(f'{datetime.datetime.now():%F %T}\t{p}\t{why}\n')
                continue
            h = sha(p)
        except OSError: continue
        if h in known: continue
        if new >= MAXN: say('', f'đã nhận {MAXN} mẫu mới trong vòng này (REA_WATCH_MAX_NEW), phần còn lại để vòng sau'); return
        n = os.path.basename(p); c = (re.sub(r'\W+', '_', os.path.splitext(n)[0]).strip('_')[:40] or 'sample') + '_' + h[:8]
        try: os.mkdir(c)
        except FileExistsError:   # watcher khác vừa nhận mẫu này, hoặc thư mục trùng tên không do watch tạo / watcher chết giữa chừng
            if not os.path.exists(wj(c)) and time.time() - os.path.getmtime(c) > 60: say(c, f'bỏ qua {p}: thư mục {c} đã có nhưng không có {wj(c)}; xem rồi xóa hoặc đổi tên')
            continue
        os.makedirs(os.path.join(c, 'work')); known.add(h); new += 1
        with lock(c):
            st = {'sha256': h, 'source': p, 'inbox': os.path.abspath(inbox), 'sessions': 0, **({'report': report} if report else {})}
            save(c, st); say(c, f'mẫu mới {p}')
            r = flow('new', c, p)
            if r.returncode: stop(c, st, f'flow.py new lỗi: {(r.stdout + r.stderr).strip()[-300:]}')

def main(a):
    if not a or a[0].startswith('-') or not os.path.isdir(a[0]):
        print('dùng: flow.py watch INBOX [--once] [--model M] [--report [TÊN]]   (chạy ở workspace; case tạo trong thư mục hiện tại; quét cả thư mục con)'); return 2
    model = pick_model(a)
    if model is None: print('--model cần tên model'); return 2
    report = None
    if '--report' in a:   # không có TÊN: Report_<tên INBOX>
        i = a.index('--report'); report = a[i + 1] if i + 1 < len(a) and not a[i + 1].startswith('-') else os.path.basename(os.path.abspath(a[0]))
    root = report_root(a[0], report)
    if os.path.realpath(os.getcwd()) == os.path.realpath(a[0]):
        print('workspace không được trùng INBOX (file do watcher sinh và case sẽ bị nhận làm mẫu): chạy từ một thư mục khác' + (f', ví dụ {root}/.cases' if root else '')); return 2
    if (os.path.abspath(os.getcwd()) + os.sep).startswith(os.path.abspath(a[0]) + os.sep):
        say('', f'CẢNH BÁO: workspace {os.getcwd()} nằm trong INBOX: case và file tạm ghi vào cây mẫu gốc; nên chạy từ một thư mục ngoài INBOX'
                + (f', ví dụ {root}/.cases' if root else ''))
    say('', f"theo dõi {a[0]} (cả thư mục con), workspace {os.getcwd()}, model {model or 'mặc định của claude'}, trần {MAXS} phiên x {MAXT} lượt / {STALL} lần không đổi, "
            + (f'báo cáo vào {root}' if root else 'không xuất báo cáo (--report)'))
    while True:
        ingest(a[0], report)   # ponytail: các case chạy tuần tự trong một watcher; song song thì mở thêm watcher (khóa theo case)
        for w in sorted(glob.glob('*/work/watch.json')): step(os.path.dirname(os.path.dirname(w)), model, report)
        if '--once' in a: return 0
        time.sleep(INTERVAL)
