#!/usr/bin/env python3
# flow.py watch: theo dõi thư mục mẫu; mẫu mới (theo sha256) thành case, rồi đẩy case qua quy trình bằng các phiên `claude -p` riêng,
# mỗi phiên làm một mốc theo `flow.py next` rồi thoát. Không bao giờ thực thi mẫu.
# Trạng thái nằm trong case (work/watch.json) nên dừng/chạy lại không mất gì; khóa flock theo case nên chạy nhiều watcher song song được.
# Không có người duyệt: an toàn dựa vào allowlist công cụ + hậu kiểm lệnh Bash của từng phiên. Nên chạy trong VM không có mạng ra ngoài.
import os, re, sys, glob, json, time, fcntl, shlex, hashlib, datetime, subprocess

TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOLS); import case as C, reacfg as CFG   # noqa: E402
from evals.run import ALLOWED, POS, parse, run_agent   # noqa: E402  cùng allowlist/bộ đọc transcript với bộ eval

FLOW = os.path.join(TOOLS, 'flow.py')
num = lambda k, d: int(CFG.get(k, d, path=False))
MAXS, STALL, INTERVAL, TIMEOUT, SETTLE = (num('REA_WATCH_MAX_SESSIONS', '10'), num('REA_WATCH_STALL', '3'), num('REA_WATCH_INTERVAL', '60'),
                                          num('REA_WATCH_TIMEOUT', '1800'), num('REA_WATCH_SETTLE', '10'))
STATES = r'^(STOPPED|NEED_MORE|NEED_FIX|NEED_REVIEW|NEED_REPORT|DONE)\b'
PROMPT = ('Phiên tự động do `flow.py watch` mở cho case `{c}`: không có người trả lời, đừng hỏi. Chạy `python3 {F} resume {c}` rồi `python3 {F} next {c}` '
          'và làm MỘT mốc theo kết quả (NEED_MORE: phân tích tiếp; NEED_FIX: sửa fact theo where/redo; NEED_REPORT: cập nhật báo cáo viết tay). '
          'Không thực thi mẫu. Không chạy `flow.py review`, `review-loop` hay `report --final` (bộ theo dõi lo). '
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
    say(c, ('XONG: ' if why.startswith('DONE') else 'DỪNG, cần người: ') + why + ('' if why.startswith('DONE') else f'. Chạy tiếp: xóa khóa "stop" trong {wj(c)}'))

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
    """Lệnh có dấu hiệu chạy mẫu (cùng ý với evals/run.py EXEC, theo tên mẫu thật của case)."""
    names = {n for _, _, ns in os.walk(os.path.join(c, 'work', 'sample')) for n in ns}
    end = r'''(?=[\s;&|)`'"]|$)'''
    ps = [POS + r'(?:\S*/)?wine(?:64)?\b', POS + r'(?:\S*/)?qemu-\w', POS + r'chmod\b[^;&|\n]*\+x', POS + r'(?:\S*/)?rea\s+(?:capture-|debug-with-)']
    for n in map(re.escape, names):
        ps += [r'(?:subprocess|os\.system|os\.exec|os\.spawn|popen|pty\.spawn|runpy)[^\n]*' + n,
               POS + r'(?:\S*/)?(?:sh|bash|dash|zsh|ksh|source|python[\d.]*|node|perl|ruby|pwsh|powershell|mono|java)\s+(?:-\S+\s+)*(?:\S*/)?' + n + end,
               POS + r'\.\s+\S*' + n + end, POS + r'(?:\./|/|[\w.-]+/)\S*' + n + end]
    return [re.compile(p) for p in ps]

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
    argv +=['-p', PROMPT.format(c=c, F=FLOW), '--output-format', 'stream-json', '--verbose', '--no-session-persistence', '--permission-mode', 'default',
             '--allowedTools', ALLOWED, '--disallowedTools', 'WebFetch,WebSearch,Agent', '--max-turns', '40'] + (['--model', model] if model else [])
    n = st['sessions'] = st.get('sessions', 0) + 1; save(c, st)
    before = fp(c); say(c, f'phiên {n}/{MAXS}')
    out = run_agent(argv, os.getcwd(), TIMEOUT)
    d = os.path.join(c, 'work', 'runs', 'watch'); os.makedirs(d, exist_ok=True)
    open(os.path.join(d, f's{n:02d}.jsonl'), 'w', encoding='utf-8').write(out)
    cmds, _, init = parse(out)
    bad = [x for x in cmds if any(p.search(x) for p in exec_pats(c))] + [t for t in tool_names(out) if t.startswith('mcp__') and RUN_TOOL.search(t)]
    st['stall'] = 0 if fp(c) != before else st.get('stall', 0) + 1
    say(c, f"phiên {n} xong: facts/báo cáo {'đổi' if not st['stall'] else 'không đổi'}" + (f", lỗi: {init['_error']}" if init['_error'] else ''))
    why = (f'hậu kiểm: lệnh nghi chạy mẫu ở phiên {n}: {bad[0][:200]}' if bad else f"{st['stall']} phiên liên tiếp không đổi facts/báo cáo" if st['stall'] >= STALL
           else f'đủ {MAXS} phiên' if n >= MAXS else '')
    stop(c, st, why) if why else save(c, st)

def step(c, model):
    f = lock(c)
    if not f: return
    with f:
        st = load(c)
        if st.get('stop'): return
        r = flow('next', c); k = (re.search(STATES, r.stdout, re.M) or [None, None])[1]
        if k == 'STOPPED': stop(c, st, f'STOPPED: phản biện FAIL 2 lần, xem {c}/work/review/STOP_REPORT.md')
        elif k == 'DONE':
            r = flow('report', c, '--final'); stop(c, st, 'DONE: đã report --final' if r.returncode == 0 else f'report --final lỗi: {(r.stdout + r.stderr).strip()[-300:]}')
        elif k == 'NEED_REVIEW':   # review nền tự chống chạy trùng; gọi lại mỗi vòng để lấy kết quả (mã 6 = đang chạy)
            r = flow('review', c, '--llm', '--detach')
            if r.returncode in (4, 7): stop(c, st, f'review lớp 2 cần người (mã {r.returncode}): {r.stdout.strip()[-300:]}')
            elif r.returncode != 6: say(c, f'review xong (mã {r.returncode})')
        elif k: session(c, st, model)
        else: stop(c, st, f'next không ra trạng thái: {(r.stdout + r.stderr).strip()[-300:]}')

def ingest(inbox):
    known = {load(os.path.dirname(os.path.dirname(p))).get('sha256') for p in glob.glob('*/work/watch.json')}
    for n in sorted(os.listdir(inbox)):
        p = os.path.abspath(os.path.join(inbox, n))
        if n.startswith('.') or not os.path.isfile(p) or time.time() - os.path.getmtime(p) < SETTLE: continue   # còn đang chép
        h = hashlib.sha256(open(p, 'rb').read()).hexdigest()   # ponytail: băm lại cả inbox mỗi vòng; cache theo (tên, mtime) nếu inbox lớn
        if h in known: continue
        c = (re.sub(r'\W+', '_', os.path.splitext(n)[0]).strip('_')[:40] or 'sample') + '_' + h[:8]
        try: os.mkdir(c)
        except FileExistsError:   # watcher khác vừa nhận mẫu này, hoặc thư mục trùng tên không do watch tạo / watcher chết giữa chừng
            if not os.path.exists(wj(c)) and time.time() - os.path.getmtime(c) > 60: say(c, f'bỏ qua {p}: thư mục {c} đã có nhưng không có {wj(c)}; xem rồi xóa hoặc đổi tên')
            continue
        os.makedirs(os.path.join(c, 'work')); known.add(h)
        with lock(c):
            st = {'sha256': h, 'source': p, 'sessions': 0}; save(c, st); say(c, f'mẫu mới {p}')
            r = flow('new', c, p)
            if r.returncode: stop(c, st, f'flow.py new lỗi: {(r.stdout + r.stderr).strip()[-300:]}')

def main(a):
    if not a or a[0].startswith('-') or not os.path.isdir(a[0]):
        print('dùng: flow.py watch INBOX [--once] [--model M]   (chạy ở workspace; case tạo trong thư mục hiện tại)'); return 2
    model = pick_model(a)
    if model is None: print('--model cần tên model'); return 2
    say('', f"theo dõi {a[0]}, workspace {os.getcwd()}, model {model or 'mặc định của claude'}, trần {MAXS} phiên / {STALL} lần không đổi")
    while True:
        ingest(a[0])   # ponytail: các case chạy tuần tự trong một watcher; song song thì mở thêm watcher (khóa theo case)
        for w in sorted(glob.glob('*/work/watch.json')): step(os.path.dirname(os.path.dirname(w)), model)
        if '--once' in a: return 0
        time.sleep(INTERVAL)
