#!/usr/bin/env python3
# flow.py watch: theo dõi thư mục mẫu; mẫu mới (theo sha256) thành case, rồi đẩy case qua quy trình bằng các phiên `claude -p` riêng,
# mỗi phiên làm một mốc theo `flow.py next` rồi thoát. Không bao giờ thực thi mẫu.
# Trạng thái nằm trong case (work/watch.json) nên dừng/chạy lại không mất gì; khóa flock theo case nên chạy nhiều watcher song song được.
# Không có người duyệt: an toàn dựa vào allowlist công cụ + hậu kiểm lệnh Bash của từng phiên. Nên chạy trong VM không có mạng ra ngoài.
import os, re, sys, glob, json, time, fcntl, shlex, hashlib, datetime, threading, subprocess
from concurrent.futures import ThreadPoolExecutor, wait

TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOLS); import case as C, reacfg as CFG   # noqa: E402
from evals.run import ALLOWED, POS, derived, exec_patterns, parse, run_agent   # noqa: E402  cùng allowlist/bộ đọc transcript với bộ eval

FLOW = os.path.join(TOOLS, 'flow.py')
num = lambda k, d: int(CFG.get(k, d, path=False))
MAXS, STALL, INTERVAL, TIMEOUT, SETTLE = (num('REA_WATCH_MAX_SESSIONS', '10'), num('REA_WATCH_STALL', '3'), num('REA_WATCH_INTERVAL', '60'),
                                          num('REA_WATCH_TIMEOUT', '1800'), num('REA_WATCH_SETTLE', '10'))
MAXT = num('REA_WATCH_MAX_TURNS', '80')   # số lượt tối đa của một phiên claude -p (một mốc phân tích)
SOFT = num('REA_WATCH_SOFT', '5')          # số phiên liên tiếp chưa ra fact mới (facts/báo cáo không đổi, kể cả khi có đổi work/; NOTES.md không tính) thì dừng
MAXN = num('REA_WATCH_MAX_NEW', '20')     # số case mới tối đa mỗi vòng quét: thư mục giải nén nhiều file không đẻ hàng trăm case một lúc
PUBFAIL = 10           # số vòng liên tiếp chép báo cáo lỗi thì dừng case, báo người (thay vì thử lại mãi)
REPORTED_TTL = 600     # giây giữa hai lần quét cả cây thư mục báo cáo (reported)
LIMIT_WAIT = num('REA_WATCH_LIMIT_WAIT', '900')   # giây tạm nghỉ khi claude báo hết hạn mức (429) mà không kèm giờ hết hạn
PARALLEL = max(1, num('REA_WATCH_PARALLEL', '1'))   # số case xử lý cùng lúc trong một watcher (mỗi case một phiên claude -p riêng; tốn hạn mức tỉ lệ thuận)
_QUIT = threading.Event()   # Ctrl-C ở luồng chính: worker đang chạy không ghi khóa stop giả (flow.py con chết vì SIGINT) và không mở phiên claude mới
_LIMIT = [0.0]        # hạn mức của tài khoản dùng chung mọi case: chạm ở một case thì case khác trong watcher này cũng nghỉ
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
          'NGÂN SÁCH PHIÊN: tối đa {T} lượt và {M} phút; hết là bị cắt ngang và mất phần chưa ghi. Khi đã dùng khoảng 3/4 (khoảng {T3} lượt hoặc {M3} phút) thì dừng mở rộng, ghi nốt fact/hypothesis, cập nhật NOTES.md rồi chạy checkpoint; việc dở để phiên sau. '
          'Ghi hết kết luận thành fact (ý còn nghi thì status=hypothesis). Trước khi kết thúc, cập nhật work/NOTES.md (ghi chú vận hành cho phiên sau: '
          'lệnh và tham số nạp lại snapshot/giả lập, công cụ đã viết, việc kế tiếp; không chép chuỗi lấy từ mẫu vào đó), '
          'chạy `python3 {F} checkpoint {c}` rồi kết thúc.')

def say(c, m): print(f'{datetime.datetime.now():%F %T} [{c or "watch"}] {m}', flush=True)
def flow(*a): return subprocess.run([sys.executable, FLOW, *a], capture_output=True, text=True)
def wj(c): return os.path.join(c, 'work', 'watch.json')
_BAD = set()
def load(c):
    """Trạng thái của case. Chưa có file: {}. File hỏng (sửa tay gõ sai): None, báo một lần, không ghi đè (mất khóa stop/sessions)."""
    try: st = json.load(open(wj(c), encoding='utf-8'))
    except FileNotFoundError: return {}
    except (OSError, ValueError) as e: st = e
    if isinstance(st, dict): _BAD.discard(c); return st
    if c not in _BAD: _BAD.add(c); say(c, f'BỎ QUA case: {wj(c)} không đọc được ({str(st)[:120] if isinstance(st, Exception) else "không phải object JSON"}); sửa file thì vòng sau chạy tiếp')
    return None
def save(c, st): open(wj(c) + '.tmp', 'w', encoding='utf-8').write(json.dumps(st, ensure_ascii=False, indent=1)); os.replace(wj(c) + '.tmp', wj(c))
def stop(c, st, why):
    st['stop'] = why; save(c, st)
    say(c, ('XONG: ' if why.startswith('DONE') else 'DỪNG, cần người: ') + why + ('' if why.startswith('DONE') else
        f'. Chạy tiếp: xóa khóa "stop" trong {wj(c)} (và đặt "stall"/"soft" về 0, hoặc tăng "max_sessions" của case, nếu dừng vì chúng)'))

def lock(c):
    f = open(os.path.join(c, 'work', '.watch.lock'), 'a')
    try: fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB); return f
    except BlockingIOError: f.close(); return None   # phiên/watcher khác đang giữ case

def soft_fp(c):
    """Dấu vân tay tiến độ mềm: tên, kích thước, mtime của file trong work/ (hook, công cụ, snapshot, kết quả giả lập),
    trừ những thứ đổi ở mọi phiên (transcript watch, review, watch.json, checkpoint, khóa, NOTES.md mà prompt bắt cập nhật). Không đọc nội dung: snapshot lớn."""
    w = os.path.join(c, 'work'); h = hashlib.sha256()
    skip = {os.path.join(w, x) for x in ('runs/watch', 'review', 'sample')}
    for d, ds, fs in os.walk(w):
        ds[:] = sorted(x for x in ds if os.path.join(d, x) not in skip)
        for n in sorted(fs):
            if n in ('watch.json', 'watch.json.tmp', '.watch.lock', 'checkpoint.json') or (d == w and n == 'NOTES.md'): continue   # NOTES.md đổi ở mọi phiên
            try: s = os.stat(os.path.join(d, n))
            except OSError: continue
            h.update(f'{os.path.relpath(os.path.join(d, n), w)}\0{s.st_size}\0{s.st_mtime_ns}\n'.encode())
    return h.hexdigest()

def fp(c):
    """Dấu vân tay tiến độ: facts + báo cáo viết tay (NEED_REPORT chỉ sửa báo cáo)."""
    h = hashlib.sha256()
    for p in (os.path.join(c, 'facts.jsonl'), C.report_md(c)):
        if os.path.exists(p): h.update(open(p, 'rb').read())
    return h.hexdigest()

def sample_names(c): return {n for _, _, ns in os.walk(os.path.join(c, 'work', 'sample')) for n in ns}
def exec_pats(c, copies=None, cmds=()):
    """Lệnh có dấu hiệu chạy mẫu: cùng luật với bộ eval (evals/run.py exec_rules), theo tên mẫu thật của case; tên bản chép
    (`copies`: watch.json "derived" + suy từ phiên này) áp riêng, bắt buộc đứng riêng."""
    return exec_patterns(sample_names(c), cmds, copies)

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
    if _QUIT.is_set(): return
    if r.returncode: return stop(c, st, f'không mở được phiên: {(r.stdout + r.stderr).strip()[-300:]}')
    argv = shlex.split(r.stdout.strip().splitlines()[-1])
    if '--mcp-config' in argv: argv[argv.index('--mcp-config') + 1] = '{"mcpServers":{}}'   # không MCP: tool frida/rea chạy mẫu không qua hậu kiểm Bash
    argv += ['-p', PROMPT.format(c=c, F=FLOW, T=MAXT, T3=MAXT * 3 // 4, M=TIMEOUT // 60, M3=TIMEOUT // 80), '--output-format', 'stream-json', '--verbose', '--no-session-persistence', '--permission-mode', 'default',
             '--allowedTools', ALLOWED, '--disallowedTools', 'WebFetch,WebSearch,Agent', '--max-turns', str(MAXT)] + (['--model', model] if model else [])
    v = st.get('max_sessions')   # trần riêng của case (sửa tay watch.json): sai kiểu thì chỉ dừng case này, không làm sập watcher
    if v and (isinstance(v, bool) or not re.fullmatch(r'\s*[1-9]\d*\s*', str(v))): return stop(c, st, f'"max_sessions" trong watch.json phải là số nguyên dương, đang là {v!r}')
    maxs = int(v) if v else max(1, MAXS); n = st['sessions'] = st.get('sessions', 0) + 1; save(c, st)
    before, sbefore = fp(c), soft_fp(c); say(c, f'phiên {n}/{maxs}')
    out = run_agent(argv, os.getcwd(), TIMEOUT)
    d = os.path.join(c, 'work', 'runs', 'watch'); os.makedirs(d, exist_ok=True)
    tp = os.path.join(d, f's{n:02d}.jsonl'); open(tp, 'w', encoding='utf-8').write(out)
    cmds, _, init = parse(out)
    prev = st.get('derived'); prev = {x for x in prev if isinstance(x, str) and x.strip()} if isinstance(prev, list) else set()   # sửa tay sai kiểu: bỏ
    known = prev | derived(cmds, sample_names(c) | prev)   # bản chép mẫu mang tên khác: suy một lần, nhớ sang phiên sau
    if known: st['derived'] = sorted(known)
    else: st.pop('derived', None)
    P = exec_pats(c, known)
    bad = ([x for x in cmds if any(p.search(x) for p in P) or NESTED.search(x)]   # chạy mẫu hoặc mở watcher lồng (ngoài trần phiên)
           + [t for t in tool_names(out) if t.startswith('mcp__') and RUN_TOOL.search(t)])
    hard, soft = fp(c) != before, soft_fp(c) != sbefore   # facts/báo cáo đổi: tiến độ thật; chỉ work/ đổi: tiến độ mềm (viết hook, giả lập tiếp)
    lim = 0 if bad else limit_until(out)   # hết hạn mức của claude: không phải lỗi của case
    if lim:
        _LIMIT[0] = max(_LIMIT[0], lim); st['wait_until'] = int(lim) + 30
        if not (hard or soft):   # bị từ chối trước khi làm được gì: không tính vào trần phiên, stall, soft (trước đây 3 phiên 5 giây là dừng case)
            st['sessions'] = n - 1; save(c, st)
            os.replace(tp, os.path.join(d, f's{n:02d}-limit-{int(time.time())}.jsonl'))   # phiên sau dùng lại số n: giữ transcript lần bị từ chối
            return say(c, f"phiên {n} bị claude từ chối vì hạn mức ({init['_error'] or 'rate limit'}): không tính phiên, "
                          f"tạm nghỉ tới {datetime.datetime.fromtimestamp(st['wait_until']):%F %T}")
    if init['_error'] and not bad and (not lim or hard or soft): cut_notes(c, n, init['_error'])   # phiên bị cắt (hết giờ/lượt/CLI lỗi): chốt phần dở cho phiên sau
    st['stall'] = 0 if hard or soft else st.get('stall', 0) + 1
    st['soft'] = 0 if hard else st.get('soft', 0) + 1   # mọi phiên chưa ra fact, kể cả phiên không đổi gì: xen kẽ hai loại vẫn chạm trần
    say(c, f"phiên {n} xong: " + ('facts/báo cáo đổi' if hard else ('chỉ work/ đổi' if soft else 'không đổi') + f", {st['soft']}/{SOFT} phiên chưa ra fact")
        + (f", lỗi: {init['_error']}" if init['_error'] else ''))
    why = (f'hậu kiểm: lệnh bị cấm (chạy mẫu hoặc watch lồng) ở phiên {n}: {bad[0][:200]}' if bad else f"{st['stall']} phiên liên tiếp không đổi gì" if st['stall'] >= STALL
           else f"{st['soft']} phiên liên tiếp chưa ra fact mới (chỉ đổi work/: hook, công cụ, snapshot; hoặc không đổi gì)" if st['soft'] >= SOFT
           else f'đủ {maxs} phiên' if n >= maxs else '')
    stop(c, st, why) if why else save(c, st)

def cut_notes(c, n, why):
    """Phiên n kết thúc bất thường nên agent chưa kịp checkpoint/ghi NOTES: chạy checkpoint thay và ghi vào work/NOTES.md những gì phiên sau phải xử lý
    trước (kết quả chạy mới hơn fact cuối, evidence chưa có fact, fact lỗi/lệch)."""
    r = flow('checkpoint', c); L = [x.strip() for x in (r.stdout + r.stderr).splitlines() if re.match(r'\s*(CHƯA GHI\?|lưu ý:|FAIL|LỆCH)', x) and 'runs/watch' not in x]
    np = os.path.join(c, 'work', 'NOTES.md'); old = open(np, encoding='utf-8').read() if os.path.exists(np) else ''
    with open(np, 'w', encoding='utf-8') as f:   # ghi lên ĐẦU file: resume chỉ in phần đầu NOTES.md
        f.write(f'\n## Phiên {n} bị cắt ({why[:120]}), watcher tự checkpoint\nXử lý trước khi làm tiếp (kết quả đã có trên đĩa nhưng chưa thành fact):\n' + ''.join(f'- {x[:300]}\n' for x in L[:12]) if L else
                f'\n## Phiên {n} bị cắt ({why[:120]}), watcher tự checkpoint\nKhông thấy kết quả nào chưa ghi.\n')
        f.write('\n' + old)

def limit_until(out):
    """Thời điểm (epoch) hết giới hạn dùng nếu phiên kết thúc lỗi vì hạn mức của claude (result cuối is_error, kèm lỗi API 429 hoặc
    rate_limit_event status=rejected không dùng overage); không thì 0. Sự kiện rejected mà phiên vẫn chạy tiếp (result không lỗi) không tính.
    Ưu tiên resetsAt của sự kiện; không có (hoặc vô lý) thì nghỉ LIMIT_WAIT giây."""
    now, reset, fall, err = time.time(), 0.0, 0.0, False
    for ln in out.splitlines():
        if '"result"' not in ln and 'rate_limit' not in ln: continue
        try: e = json.loads(ln)
        except ValueError: continue
        if not isinstance(e, dict): continue
        if e.get('type') == 'result': err = bool(e.get('is_error'))   # result cuối quyết định phiên có kết thúc lỗi không
        i = e.get('rate_limit_info') if e.get('type') == 'rate_limit_event' else None
        if isinstance(i, dict) and i.get('status') == 'rejected' and not i.get('isUsingOverage'):
            r = i.get('resetsAt')
            if isinstance(r, (int, float)) and not isinstance(r, bool) and now < r < now + 7 * 86400: reset = max(reset, float(r))
            else: fall = now + LIMIT_WAIT
        elif e.get('type') == 'result' and e.get('is_error') and e.get('api_error_status') == 429: fall = now + LIMIT_WAIT
    return (reset or fall) if err else 0

def step(c, model, report=None):
    f = lock(c)
    if not f: return
    with f:
        st = load(c)
        if st is None or st.get('stop'): return
        r = flow('next', c)
        if _QUIT.is_set(): return
        k =(re.search(STATES, r.stdout, re.M) or [None, None])[1]
        if k != 'DONE' and st.pop('final', None): save(c, st)   # case mở lại (facts/báo cáo đổi): report --final phải chạy lại
        if k == 'STOPPED': stop(c, st, f'STOPPED: phản biện FAIL 2 lần, xem {c}/work/review/STOP_REPORT.md')
        elif k == 'DONE':
            if not st.get('final'):
                r = flow('report', c, '--final')
                if _QUIT.is_set(): return
                if r.returncode: return stop(c, st, f'report --final lỗi: {(r.stdout + r.stderr).strip()[-300:]}')
                st['final'] = True; save(c, st)
            try: out = publish(c, st, report)
            except Exception as e:   # chép lỗi (đĩa đầy, quyền, facts hỏng...): chưa đóng case, vòng sau chép lại; quá PUBFAIL lần thì dừng báo người
                n = st['publish_fail'] = st.get('publish_fail', 0) + 1; st['publish_error'] = f'{type(e).__name__}: {e}'
                if n >= PUBFAIL: st.pop('publish_fail'); return stop(c, st, f"report --final xong nhưng chép báo cáo lỗi {n} lần liên tiếp: {st['publish_error'][:300]}")   # mở lại thì đếm lại từ 0
                save(c, st); return say(c, f'report --final xong nhưng chép báo cáo lỗi ({n}/{PUBFAIL}), vòng sau thử lại: {e}')
            st.pop('publish_error', None); st.pop('publish_fail', None)
            if out: st['published'] = out
            stop(c, st, 'DONE: đã report --final' + (f', báo cáo chép vào {out}' if out else ''))
        elif k == 'NEED_REVIEW':   # review nền tự chống chạy trùng; gọi lại mỗi vòng để lấy kết quả (mã 6 = đang chạy)
            r = flow('review', c, '--llm', '--detach')
            if r.returncode in (4, 7): stop(c, st, f'review lớp 2 cần người (mã {r.returncode}): {r.stdout.strip()[-300:]}')
            elif r.returncode != 6: say(c, f'review xong (mã {r.returncode})')
        elif k:
            w = st.get('wait_until'); w = max(_LIMIT[0], w if isinstance(w, (int, float)) and not isinstance(w, bool) else 0)
            if w > time.time(): return   # đang chờ hết hạn mức (đã báo lúc chạm)
            if st.pop('wait_until', None) is not None: save(c, st)
            if _QUIT.is_set(): return
            session(c, st, model)
        else: stop(c, st, f'next không ra trạng thái: {(r.stdout + r.stderr).strip()[-300:]}')

from export import NOTE_EXT, NOTE_MAX, SUMS, SCRIPT, CMD   # noqa: E402  một tiêu chí ghi chú/script cho watch (nhận mẫu) và export (gom ghi chú)
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
    skip = {os.path.realpath(x) for x in skip if x}   # realpath như kiểm workspace trùng INBOX: symlink không làm lọt workspace
    for d, ds, fs in os.walk(os.path.abspath(inbox)):
        for x in ds:   # thư mục Report_* (báo cáo của lần chạy khác) bị bỏ: ghi lại một lần để người vận hành thấy
            q = os.path.join(d, x)
            if x.startswith('Report_') and os.path.realpath(q) not in skip and q not in _NOTED:
                _NOTED.add(q); say('', f'bỏ qua thư mục {q}: tên Report_* là thư mục báo cáo')
                with open(NOTES_LOG, 'a', encoding='utf-8') as f: f.write(f'{datetime.datetime.now():%F %T}\t{q}/\tthư mục Report_*\n')
        ds[:] = sorted(x for x in ds if not x.startswith('.') and not x.startswith('Report_') and os.path.realpath(os.path.join(d, x)) not in skip
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
    if SUMS.search(n):   # tên dạng SHA256SUMS: chỉ là ghi chú khi nội dung đúng là danh sách `<sha256>  tên`
        t = _text(p)
        return 'danh sách sha256' if t is not None and re.search(r'(?m)^[0-9a-fA-F]{64}[ \t]+\*?\S', t) else ''
    if not n.lower().endswith(NOTE_EXT): return ''
    t = _text(p)
    if t is None or SCRIPT.search(t): return ''   # nội dung trông như script (shebang, | sh, curl, base64 -d...): coi là mẫu
    sib = [os.path.join(d, x) for x in os.listdir(d) if x != n and not x.startswith('.') and not x.lower().endswith(NOTE_EXT)
           and not SUMS.search(x) and os.path.isfile(os.path.join(d, x))]
    for q in sib:
        if n.startswith(os.path.splitext(os.path.basename(q))[0] + '.'): return f'tên bắt đầu bằng tên của {os.path.basename(q)}'
    L = t.splitlines()
    for ln in L:
        m = CMD.match(ln)
        if m and any(os.path.basename(m[1]) == os.path.basename(q) for q in sib): return f'ghi lại lệnh thu mẫu trên {os.path.basename(m[1])}'
    if not re.search(r'\b[0-9a-f]{64}\b', t): return ''
    for q in sib:
        try:
            if sha(q) in t: return f'nhắc sha256 của {os.path.basename(q)}'
        except OSError: pass
    return ''

_REPORTED = {}
def reported(root):
    """sha256 các mẫu đã có báo cáo trong thư mục báo cáo (dòng đầu README.txt của <mẫu>_data/): mẫu đã xong không bị phân tích lại,
    kể cả khi thư mục case đã xóa sau khi xuất. Quét cả cây tối đa mỗi REPORTED_TTL giây (cây báo cáo lớn); publish tự thêm sha mới."""
    t, hs = _REPORTED.get(root, (0, None))
    if hs is None or time.time() - t > REPORTED_TTL:
        hs = {h for h in map(reported_sha, glob.glob(os.path.join(glob.escape(root), '**', '*_data'), recursive=True)) if h}
        _REPORTED[root] = (time.time(), hs)
    return set(hs)

def reported_sha(d):
    """sha256 ghi ở dòng đầu <d>/README.txt (do publish ghi), hoặc ''."""
    try: m = re.search(r'\(sha256 ([0-9a-f]{64})\)', open(os.path.join(d, 'README.txt'), encoding='utf-8', errors='replace').readline())
    except OSError: return ''
    return m.group(1) if m else ''

def publish(c, st, report=None):
    """Case DONE và watch chạy với --report: xuất case (export.py: báo cáo, facts, evidence, work, 7z mẫu) vào <thư mục báo cáo>/<đường dẫn
    tương đối của mẫu trong INBOX>/<tên mẫu>_data/.
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
    h = st.get('sha256') or sha(src)
    old = reported_sha(d)
    if old and old != h: d = os.path.join(out, f'{name}_{h[:8]}_data')   # mẫu khác cùng tên (bản thay thế): không ghi đè báo cáo cũ
    os.makedirs(out, exist_ok=True)
    import export   # dữ liệu case + 7z mẫu/payload + báo cáo có thông tin mẫu; README.txt dòng đầu có sha256 (reported() đọc)
    export.write(c, dict(st, source=src, inbox=inbox, sha256=h), d)
    if report_root(inbox, name_) in _REPORTED: _REPORTED[report_root(inbox, name_)][1].add(h)
    return out

def _noted_load():
    """Nạp đường dẫn đã ghi trong .watch_notes.tsv: khởi động lại watcher không ghi lặp."""
    try: _NOTED.update(ln.split('\t')[1].rstrip('/') for ln in open(NOTES_LOG, encoding='utf-8') if ln.count('\t') >= 2)
    except OSError: pass

def ingest(inbox, report=None):
    if not _NOTED: _noted_load()
    root = report_root(inbox, report)
    known = {(load(os.path.dirname(os.path.dirname(p))) or {}).get('sha256') for p in glob.glob('*/work/watch.json')} | (reported(root) if root else set())
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

def run_round(cases, model, report):
    """Mỗi case một bước. PARALLEL > 1: tối đa PARALLEL case chạy cùng lúc (khóa flock theo case, hạn mức dùng chung _LIMIT); case lỗi không làm
    mất bước của case khác: chờ xong cả vòng rồi mới ném lỗi đầu tiên."""
    if PARALLEL <= 1 or len(cases) <= 1:
        for c in cases: step(c, model, report)
        return
    ex = ThreadPoolExecutor(max_workers=PARALLEL); fs = [ex.submit(step, c, model, report) for c in cases]
    try: wait(fs)
    except BaseException: _QUIT.set(); ex.shutdown(wait=False, cancel_futures=True); raise   # Ctrl-C: case còn trong hàng đợi không bắt đầu phiên mới (khác `with`, vốn chạy hết hàng đợi)
    ex.shutdown()
    for f in fs: f.result()

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
    say('', f"theo dõi {a[0]} (cả thư mục con), workspace {os.getcwd()}, model {model or 'mặc định của claude'}, song song {PARALLEL}, trần {MAXS} phiên x {MAXT} lượt / {STALL} lần không đổi, "
            + (f'báo cáo vào {root}' if root else 'không xuất báo cáo (--report)'))
    while True:
        ingest(a[0], report)
        run_round(sorted(os.path.dirname(os.path.dirname(w)) for w in glob.glob('*/work/watch.json')), model, report)
        if '--once' in a: return 0
        time.sleep(INTERVAL)
