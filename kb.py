#!/usr/bin/env python3
# Kho tra chéo giữa các case (flow.py kb). Chỉ đọc case, chỉ ghi vào REA_KB; không ghi gì vào case, không tạo fact.
#   samples.jsonl      đặc trưng của mọi file đã triage (imphash, rich, PDB, chứng thư, md5 section, export, TLSH) + hash/IOC
#                      trong fact đang hiệu lực. `kb match` dùng để GỢI Ý mẫu tương tự. Gợi ý không phải fact: không chép vào
#                      evidence, không trích vào báo cáo; muốn dùng thì chứng minh lại trên chính mẫu của case (không quy kết chéo).
#                      Không lưu kết luận họ mã độc (fact family) của case khác: gợi ý chỉ nói đặc trưng nào trùng.
#   corrections.jsonl  mọi fact bị thay bằng supersedes -> `kb corrections` thống kê lỗi hay gặp. Chỉ để theo dõi, làm dữ liệu
#                      quyết định luật lint sau này; không đổi luật nào của case.py/review.py.
# Dữ liệu chứa IOC: REA_KB mặc định ~/.cache/rea-flow/kb (XDG_CACHE_HOME; mất thì `kb build` dựng lại), không được nằm trong thư mục skill.
#   export.jsonl.gz    `kb export` xuất bản ghi của máy này (không có mẫu) để chép sang server khác, đưa vào backup; `kb import`
#                      nạp vào kho máy kia dưới tên nguồn (bản ghi nhập không bị dựng lại hay tự xóa; nhập lại cùng tên thì thay).
#   flow.py kb build | match CASE | corrections [--since YYYY-MM-DD] [--all] | export FILE [--name TÊN] | import FILE [--name TÊN]
# Không cần chạy tay lần đầu: new/triage tự dựng khi kho chưa có workspace này, report --final dựng lại khi đóng case.
# Dựng tăng dần: file không đổi (kích thước, mtime, phiên bản đặc trưng, thư viện tùy chọn) dùng lại bản ghi cũ, không đọc lại mẫu.
import sys, os, re, json, glob, gzip, socket, datetime, collections, tempfile, importlib.util
TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [TOOLS, os.path.join(TOOLS, 'static')]
import reacfg as CFG, case   # noqa: E402
MAX_FILE = 256 << 20
PIVOT_VER = 2   # đổi cách tính đặc trưng thì tăng: bản ghi cũ bị tính lại
LIBS = ','.join(m for m in ('tlsh', 'cryptography') if importlib.util.find_spec(m))   # thư viện tùy chọn có mặt: đổi thì tính lại
EXPORT_KIND, EXPORT_VER, MAX_IMPORT = 'rea-kb-export', 1, 512 << 20
COMMON = 3   # giá trị xuất hiện ở từ chừng này case trở lên (tính cả case đang xét) là phổ biến -> gợi ý yếu
NET = {'c2', 'url', 'ua'}
ATOM_KINDS = NET | {'mutex', 'str_key', 'payload_key', 'registry'}
HEX = re.compile(r'(?<![0-9a-fA-F])([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])')
NETTOK = re.compile(r'(?:[a-z][a-z0-9+.-]*://[^\s"\'<>()]+|(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?(?![\w.])'
                    r'|(?<![\w.-])(?:[a-z0-9-]+\.)+[a-z]{2,24}(?::\d{2,5})?(?![\w-]))', re.I)
LITTOK = re.compile(r'[^\s,;()"\'`]{6,}')
CTRL = re.compile(r'[\x00-\x1f\x7f]')

def kb_dir():
    """Thư mục kho; None = tắt (REA_KB=off). Từ chối nếu nằm trong thư mục skill: repo public, kho có IOC."""
    if CFG.KB.lower() in ('off', '0', 'none', 'no'): return None
    d, t = os.path.realpath(CFG.KB), os.path.realpath(TOOLS)
    if d == t or d.startswith(t + os.sep): raise SystemExit(f'REA_KB={CFG.KB} nằm trong thư mục skill (repo public): đặt ra ngoài')
    return d

def ws_of(c):   # workspace của case: chỉ resolve thư mục cha (case có thể là symlink), khớp realpath(ws) trong build
    return os.path.realpath(os.path.dirname(os.path.abspath(c)))

def safe(x, n=80): return CTRL.sub('?', str(x))[:n]

def cases(ws):
    return sorted(d for d in (os.path.join(ws, n) for n in os.listdir(ws))
                  if os.path.isfile(os.path.join(d, 'facts.jsonl')) and os.path.isdir(os.path.join(d, 'work')))

def files_of(c):
    """Mẫu trong work/sample và mọi file đã triage (payload bóc ra) còn nằm trong case."""
    rc, out = os.path.realpath(c), {}
    cand = [os.path.join(d, n) for d, _, ns in os.walk(os.path.join(c, 'work', 'sample')) for n in ns]
    for t in glob.glob(os.path.join(c, 'work', 'runs', 'triage_*', 'triage.json')):
        try: cand.append(json.load(open(t, encoding='utf-8')).get('path') or '')
        except (OSError, ValueError): pass
    for p in cand:
        r = os.path.realpath(p) if p else ''
        if r.startswith(rc + os.sep) and os.path.isfile(r) and os.path.getsize(r) <= MAX_FILE: out.setdefault(r, p)
    return sorted(out)

def file_rec(c, p):
    import triage
    st = os.stat(p); R = triage.pivot_of(p); P = R.get('pivot', {}); leaf = triage.leaf_cert(P.get('certs'))
    junk = {None, 'd41d8cd98f00b204e9800998ecf8427e'}   # md5 rỗng
    return {'case': os.path.basename(c), 'file': os.path.relpath(p, os.path.realpath(c)), 'sha256': R['sha256'], 'type': R['type'],
            'size': R['size'], 'imp_n': len(R.get('imported_funcs', [])), 'exports': sorted(set(R.get('exports', [])))[:200],
            'sec_md5': sorted({s['md5'] for s in R.get('sections', []) if s.get('md5') not in junk and s.get('raw', 0) >= 512}),
            'certs': sorted({f"{x['issuer']}|{x['serial']}" for x in P.get('certs') or []}), 'signer': leaf['subject'] if leaf else None,
            'mtime_ns': st.st_mtime_ns, 'pv': PIVOT_VER, 'libs': LIBS,
            **{k: P.get(k) for k in ('imphash', 'rich', 'pdb', 'pdb_guid', 'build_id', 'impfuncs_md5', 'tlsh')}}

def atoms(kind, value):
    v = str(value)
    if v.lower().startswith('n/a'): return set()
    if kind in NET: return {m.lower().rstrip('.,/') for m in NETTOK.findall(v)}
    return {m for m in LITTOK.findall(v) if re.search(r'[\d\\/{}_:.-]', m) and not re.fullmatch(r'[\d.,:-]+', m)}   # bỏ từ thường, số trần

def case_rec(c):
    """Hash và IOC trong fact đang hiệu lực (không lấy family, không lấy fact giả thuyết/đã rút)."""
    hashes, at = set(), collections.defaultdict(set)
    for f in case.load(c).values():
        if f.get('status') != 'active': continue
        if f['kind'] in ('hash', 'payload_hash'): hashes |= {h.lower() for h in HEX.findall(str(f['value']))}
        if f['kind'] in ATOM_KINDS: at[f['kind']] |= atoms(f['kind'], f['value'])
    return {'case': os.path.basename(c), 'kind': 'case', 'hashes': sorted(hashes), 'atoms': {k: sorted(v) for k, v in at.items() if v}}

def corrections(c):
    H = case.history(c); last, out = {}, []
    flagged = set()   # id bị lớp phản biện chấm fail/weak ở bất kỳ vòng nào
    for r in glob.glob(os.path.join(c, 'work', 'review', 'r*', 'review.json')):
        try: flagged |= {i.get('id') for i in json.load(open(r, encoding='utf-8')).get('items', []) if i.get('verdict') in ('fail', 'weak')}
        except (OSError, ValueError, AttributeError): pass
    for f in H:
        o = last.get(f.get('supersedes')) if f.get('supersedes') else None
        if o is not None:
            nv, st = str(f.get('value', '')), f.get('status', 'active')
            typ = ('rút lại' if st == 'retracted' or nv.lower().startswith('n/a') else 'hạ về giả thuyết' if st == 'hypothesis' and o.get('status') != 'hypothesis'
                   else 'nâng thành active' if o.get('status') == 'hypothesis' and st == 'active' else 'đổi kind' if o['kind'] != f['kind'] else 'sửa giá trị')
            auto = o['id'].startswith('s.') and 'triage_' in str(o.get('evidence', ''))
            try: lag = round((datetime.datetime.fromisoformat(f['ts']) - datetime.datetime.fromisoformat(o['ts'])).total_seconds() / 3600, 1)
            except (KeyError, TypeError, ValueError): lag = None
            out.append({'case': os.path.basename(c), 'id': f['id'], 'old_id': o['id'], 'kind': f['kind'], 'old_kind': o['kind'], 'type': typ,
                        'old_status': o.get('status'), 'status': st, 'old_src': o.get('src'), 'src': f.get('src'),
                        'origin': 'triage tự ghi' if auto else 'phân tích', 'caught': 'phản biện' if o['id'] in flagged else 'tự sửa',
                        'ts': f.get('ts'), 'lag_h': lag, 'note': safe(f.get('note', ''), 160)})
        last[f['id']] = f
    return out

def gone(ws):   # chỉ tự bỏ workspace tạm đã xóa (test); ổ ngoài/NFS chưa mount thì giữ bản ghi
    t = os.path.realpath(tempfile.gettempdir())
    return not os.path.exists(ws) and os.path.realpath(ws).startswith(t + os.sep)

def write_jsonl(p, rows):
    fd, t = tempfile.mkstemp(dir=os.path.dirname(p), prefix='.part-')   # tên riêng: hai build chạy cùng lúc không đụng nhau; 0600 vì có IOC
    try:
        with open(fd, 'w', encoding='utf-8') as fh:
            for r in rows: fh.write(json.dumps(r, ensure_ascii=False) + '\n')
        os.replace(t, p)
    except BaseException:
        if os.path.exists(t): os.unlink(t)
        raise

def read_jsonl(p):
    try: return [json.loads(l) for l in open(p, encoding='utf-8') if l.strip()] if os.path.exists(p) else []
    except (OSError, ValueError): return []

def locked(d):
    import fcntl
    lk = open(os.path.join(d, '.lock'), 'a'); fcntl.flock(lk, fcntl.LOCK_EX); return lk   # đọc-gộp-ghi trong khóa: hai lệnh cùng lúc không làm mất phần của nhau

def save(d, S, K, ws=''):
    write_jsonl(os.path.join(d, 'samples.jsonl'), S); write_jsonl(os.path.join(d, 'corrections.jsonl'), K)
    write_jsonl(os.path.join(d, 'meta.json'), [{'built': datetime.datetime.now().isoformat(timespec='seconds'), 'workspace': ws,
                                                 'cases': len({(r.get('peer'), r.get('ws'), r['case']) for r in S}), 'files': sum(r.get('kind') != 'case' for r in S),
                                                 'imported': sorted({r['peer'] for r in S if r.get('peer')}), 'corrections': len(K)}])   # một dòng JSON, ghi atomic

def writable(d):
    try: os.makedirs(d, mode=0o700, exist_ok=True); tempfile.TemporaryFile(dir=d).close()
    except OSError as e: raise SystemExit(f'không ghi được kho {d} ({e.strerror}): đặt REA_KB tới thư mục ghi được, hoặc REA_KB=off')

def build(ws=None, quiet=False):
    d = kb_dir()
    if not d: print('REA_KB=off: không dựng kho'); return 0
    writable(d)
    ws = os.path.realpath(ws or CFG.REA)   # symlink tới cùng workspace: một khóa duy nhất
    prev = {(r['case'], r['file']): r for r in read_jsonl(os.path.join(d, 'samples.jsonl'))   # dựng tăng dần: bản ghi cũ của workspace này
            if r.get('ws') == ws and not r.get('peer') and r.get('kind') != 'case' and 'file' in r}
    S, K, err, reuse = [], [], 0, 0
    for c in cases(ws):
        rc = os.path.realpath(c)
        for p in files_of(c):
            try:
                st, o = os.stat(p), prev.get((os.path.basename(c), os.path.relpath(p, rc)))
                if o and (o.get('size'), o.get('mtime_ns'), o.get('pv'), o.get('libs')) == (st.st_size, st.st_mtime_ns, PIVOT_VER, LIBS):
                    S.append(dict(o)); reuse += 1
                else: S.append(file_rec(c, p))
            except Exception as e: err += 1; print(f'  bỏ {safe(os.path.relpath(p, ws), 100)}: {type(e).__name__}', file=sys.stderr)
        S.append(case_rec(c)); K += corrections(c)
    for r in S + K: r['ws'] = ws
    def keep(old):   # kho dùng chung: giữ bản ghi nhập từ máy khác và của workspace khác, chỉ thay phần của workspace đang dựng
        return [r for r in old if r.get('peer') or (r.get('ws') and os.path.realpath(r['ws']) != ws and not gone(r['ws']))]   # bỏ workspace tạm đã xóa
    with locked(d):
        S = keep(read_jsonl(os.path.join(d, 'samples.jsonl'))) + S; K = keep(read_jsonl(os.path.join(d, 'corrections.jsonl'))) + K
        save(d, S, K, ws)
    mine = [r for r in S if r.get('ws') == ws and not r.get('peer')]; n = sum(r.get('kind') != 'case' for r in mine)
    if not quiet: print(f'kb: workspace {len(mine) - n} case, {n} file ({reuse} dùng lại, {n - reuse} tính mới), cả kho {len(S) - sum(r.get("kind") == "case" for r in S)} file, '
                        f'{len(K)} đính chính -> {d}' + (f' ({err} file lỗi)' if err else ''))
    return 0

def load_kb(d):
    p = os.path.join(d, 'samples.jsonl')
    return read_jsonl(p) if os.path.exists(p) else None

def clean_name(s): return re.sub(r'[^\w.-]', '_', str(s or ''))[:40].strip('._')

def outside_skill(p):
    r, t = os.path.realpath(p), os.path.realpath(TOOLS)
    if r == t or r.startswith(t + os.sep): raise SystemExit(f'{p} nằm trong thư mục skill (repo public, file có IOC): chọn nơi khác')

def export(path, name=None):
    """Xuất bản ghi của máy này (không gồm bản ghi đã nhập từ máy khác, không có mẫu) ra jsonl nén. File chứa hash/IOC."""
    d = kb_dir()
    if not d: raise SystemExit('REA_KB=off: không có kho để xuất')
    outside_skill(path); name = clean_name(name or socket.gethostname()) or 'rea'
    S = [r for r in read_jsonl(os.path.join(d, 'samples.jsonl')) if not r.get('peer')]
    K = [r for r in read_jsonl(os.path.join(d, 'corrections.jsonl')) if not r.get('peer')]
    if not S: raise SystemExit(f'kho {d} chưa có bản ghi nào của máy này: chạy flow.py kb build trước')
    fd, t = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)) or '.', prefix='.kbexp-')
    try:
        with gzip.open(open(fd, 'wb'), 'wt', encoding='utf-8') as fh:
            fh.write(json.dumps({'kind': EXPORT_KIND, 'ver': EXPORT_VER, 'name': name, 'ts': datetime.datetime.now().isoformat(timespec='seconds'),
                                 'samples': len(S), 'corrections': len(K)}) + '\n')
            for tag, rows in (('s', S), ('c', K)):
                for r in rows: fh.write(json.dumps(dict(r, t=tag), ensure_ascii=False) + '\n')
        os.replace(t, path)   # mkstemp: 0600
    except BaseException:
        if os.path.exists(t): os.unlink(t)
        raise
    print(f"kb export {name}: {sum(r.get('kind') != 'case' for r in S)} file, {sum(r.get('kind') == 'case' for r in S)} case, {len(K)} đính chính -> {path}"
          '\n  file chứa hash và IOC, không có mẫu: chỉ chép qua kênh tin cậy, không đưa lên repo public')
    return 0

def import_(path, name=None):
    """Nạp file của kb export vào kho dưới tên nguồn. Dữ liệu từ máy khác chỉ là dữ liệu: kiểm dạng, giới hạn kích thước, không chạy gì."""
    d = kb_dir()
    if not d: raise SystemExit('REA_KB=off: không nhập')
    writable(d); S, K, size = [], [], 0
    try:
        with gzip.open(path, 'rt', encoding='utf-8') as fh:
            hdr = json.loads(fh.readline() or '{}')
            if not isinstance(hdr, dict) or hdr.get('kind') != EXPORT_KIND or not isinstance(hdr.get('ver'), int) or hdr['ver'] > EXPORT_VER:
                raise SystemExit(f'{path}: không phải file kb export hợp lệ (hoặc bản mới hơn skill này)')
            for l in fh:
                size += len(l)
                if size > MAX_IMPORT: raise SystemExit(f'{path}: lớn hơn {MAX_IMPORT >> 20} MiB sau giải nén, dừng')
                r = json.loads(l)
                if not isinstance(r, dict) or not isinstance(r.get('case'), str) or r.get('t') not in ('s', 'c'): continue
                if r['t'] == 's' and r.get('kind') != 'case' and not re.fullmatch(r'[0-9a-f]{64}', str(r.get('sha256', ''))): continue
                (S if r.pop('t') == 's' else K).append(r)
    except (OSError, ValueError, EOFError) as e: raise SystemExit(f'không đọc được {path}: {type(e).__name__}: {safe(e, 100)}')
    name = clean_name(name or hdr.get('name'))
    if not name: raise SystemExit('file không có tên nguồn: thêm --name TÊN')
    for r in S + K: r['peer'] = name; r['case'] = clean_name(r['case']) or '?'
    with locked(d):
        oldS = [r for r in read_jsonl(os.path.join(d, 'samples.jsonl')) if r.get('peer') != name]
        oldK = [r for r in read_jsonl(os.path.join(d, 'corrections.jsonl')) if r.get('peer') != name]
        meta = (read_jsonl(os.path.join(d, 'meta.json')) or [{}])[0]
        save(d, oldS + S, oldK + K, meta.get('workspace', ''))
    print(f"kb import {name}: {sum(r.get('kind') != 'case' for r in S)} file, {sum(r.get('kind') == 'case' for r in S)} case, {len(K)} đính chính"
          f" (xuất lúc {safe(hdr.get('ts', '?'), 20)}; nhập lại cùng tên sẽ thay)")
    return 0

def tlsh_diff(a, b):
    try: import tlsh; return tlsh.diff(a, b)
    except Exception: return None

def compare(n, o, freq):
    """Đặc trưng trùng giữa file mới n và file trong kho o: [(tên, mức)]; mức: mạnh | vừa | yếu."""
    hit = []
    if n['sha256'] == o['sha256']:
        k = freq['sha256'][n['sha256']]; sg = n.get('signer') or o.get('signer')
        if k >= COMMON: return [(f'trùng sha256, có ở {k - 1} case khác: thư viện/runtime dùng chung?', 'yếu')]
        if sg: return [(f'trùng sha256, file ký số {safe(sg.split(",")[0], 50)}: có thể là phần mềm hợp lệ dùng chung', 'vừa')]
        return [('trùng sha256', 'mạnh')]
    if n.get('imphash') and n['imphash'] == o.get('imphash'):
        hit.append(('imphash', 'yếu' if n.get('imp_n', 0) < 5 or freq['imphash'][n['imphash']] >= 3 else 'mạnh'))
    for k, lab, lv in (('pdb_guid', 'PDB GUID', 'mạnh'), ('build_id', 'GNU build-id', 'mạnh'), ('rich', 'rich header', 'vừa'),
                       ('impfuncs_md5', 'bộ hàm import', 'yếu')):
        if n.get(k) and n[k] == o.get(k): hit.append((lab, 'yếu' if freq[k][n[k]] >= 3 else lv))
    if n.get('pdb') and not n.get('pdb_guid') and n['pdb'].lower() == (o.get('pdb') or '').lower(): hit.append(('đường dẫn PDB', 'vừa'))
    cs = set(n.get('certs', [])) & set(o.get('certs', []))
    if cs: hit.append((f'chung {len(cs)} chứng thư', 'yếu'))   # phần mềm hợp lệ cùng hãng cũng trùng: chỉ là ngữ cảnh
    sm = set(n.get('sec_md5', [])) & set(o.get('sec_md5', []))
    if sm:
        rare = {m for m in sm if freq['sec_md5'][m] < COMMON}
        hit.append((f'chung {len(sm)} section' + ('' if rare else ' (phổ biến)'), 'vừa' if rare else 'yếu'))
    ex, eo = set(n.get('exports', [])), set(o.get('exports', []))
    if len(ex & eo) >= 3 and len(ex & eo) / len(ex | eo) >= 0.6: hit.append((f'export trùng {len(ex & eo)}/{len(ex | eo)}', 'vừa'))
    if n.get('tlsh') and o.get('tlsh'):
        dd = tlsh_diff(n['tlsh'], o['tlsh'])
        if dd is not None and dd <= 70: hit.append((f'TLSH cách {dd}', 'vừa' if dd <= 40 else 'yếu'))
    return hit

RANK = {'mạnh': 0, 'vừa': 1, 'yếu': 2}

def match(c, limit=40, header=True):
    """In gợi ý tương đồng giữa CASE và các case khác trong kho. Trả về số gợi ý."""
    d = kb_dir()
    if not d: return 0
    K = load_kb(d)
    if K is None:
        if header: print(f'kb: chưa có kho ở {d}: chạy flow.py kb build')
        return 0
    me, mws = os.path.basename(os.path.abspath(c)), ws_of(c)
    # bỏ chính case này (cả bản nhập lại từ backup cùng đường dẫn) và workspace tạm đã xóa; case trùng tên ở workspace/máy khác vẫn so
    K = [r for r in K if (r['case'], r.get('ws', mws)) != (me, mws) and (r.get('peer') or not gone(r.get('ws', mws)))]
    for r in K:
        if r.get('peer'): r['case'] = f"{r['peer']}:{r['case']}"   # nhập từ máy khác
        elif r.get('ws', mws) != mws: r['case'] = f"{os.path.basename(r['ws'])}:{r['case']}"   # workspace khác trên máy này
    F = [r for r in K if r.get('kind') != 'case']; C = [r for r in K if r.get('kind') == 'case']
    freq = collections.defaultdict(collections.Counter)
    for k in ('imphash', 'pdb_guid', 'build_id', 'rich', 'impfuncs_md5', 'sha256', 'sec_md5'):
        seen = collections.defaultdict(set)
        for r in F:
            for v in (r.get(k) if isinstance(r.get(k), list) else [r.get(k)]):
                if v: seen[v].add(r['case'])
        freq[k] = collections.Counter({v: len(s) + 1 for v, s in seen.items()})   # +1: tính cả case đang xét
    mine = [file_rec(c, p) for p in files_of(c)]; cr = case_rec(c)
    rows = []
    for n in mine:
        for o in F:
            h = compare(n, o, freq)
            if h: rows.append((min(RANK[lv] for _, lv in h), f"{safe(n['file'], 60)} ~ {o['case']}/{safe(o['file'], 60)}: " +
                               ', '.join(f'{lab} ({lv})' for lab, lv in sorted(h, key=lambda x: RANK[x[1]]))))
        for o in C:
            if n['sha256'] in o.get('hashes', []): rows.append((0, f"{safe(n['file'], 60)}: sha256 có trong fact hash/payload_hash của {o['case']} (mạnh)"))
    for o in C:
        theirs = set(o.get('hashes', [])) | {r['sha256'] for r in F if r['case'] == o['case']}
        extra = (set(cr['hashes']) - {n['sha256'] for n in mine}) & theirs   # payload/hash ghi trong fact, không phải file đã so ở trên
        if extra: rows.append((0, f"{len(extra)} hash trong fact của case này cũng là mẫu/hash của {o['case']} (mạnh)"))
        for k, vs in cr['atoms'].items():
            same = set(vs) & set(o.get('atoms', {}).get(k, []))
            if same: rows.append((0 if k in NET else 1, f"{k} trùng với {o['case']}: " + ' '.join(safe(x, 60) for x in sorted(same)[:4]) +
                                  (f' (+{len(same) - 4})' if len(same) > 4 else '')))
    rows = sorted(set(rows))
    if header or rows:
        meta = os.path.join(d, 'meta.json'); built = (json.loads(open(meta).read() or '{}').get('built', '?') if os.path.exists(meta) else '?')
        print(f'kb match {me}: {len(mine)} file so với {len(F)} file / {len(C)} case khác (kho dựng {built})')
    if rows:
        print('GỢI Ý, không phải fact: không chép vào evidence hay báo cáo; muốn dùng thì tự chứng minh lại trên mẫu của case này.')
        for _, t in rows[:limit]: print('  ' + t)
        if len(rows) > limit: print(f'  ... còn {len(rows) - limit} gợi ý: flow.py kb match {me}')
    elif header: print('  không có gợi ý tương đồng')
    return len(rows)

def hint(c):
    """Sau new/triage: kho chưa có hoặc chưa có workspace này (server mới, workspace mới) thì tự dựng, rồi in gợi ý.
    Lỗi kho không được làm hỏng triage."""
    try:
        d = kb_dir()
        if not d: return
        K, ws = load_kb(d), ws_of(c)
        cs = cases(ws)
        if cs and (K is None or not any(r.get('ws') == ws and not r.get('peer') for r in K)):   # workspace chưa có case hợp lệ thì chưa dựng (khỏi dựng lại mỗi lần)
            print(f'kb: workspace này chưa có trong kho, đang dựng từ {len(cs)} case...', flush=True)
            build(ws, quiet=True); print(f'kb: đã dựng {d}')
        match(c, limit=8, header=False)
    except SystemExit as e: print(f'kb: {e}')
    except Exception as e: print(f'kb: bỏ qua gợi ý ({type(e).__name__}: {safe(e, 100)})')

def refresh(c):
    """Sau report --final: dựng lại kho để case vừa đóng vào dữ liệu tra chéo và thống kê đính chính."""
    try:
        if kb_dir(): build(ws_of(c), quiet=True); print(f'kb: đã cập nhật {kb_dir()}')
    except SystemExit as e: print(f'kb: {e}')
    except Exception as e: print(f'kb: không cập nhật được ({type(e).__name__}: {safe(e, 100)})')

def stats(since='', everything=False):
    if everything:   # cả bản ghi nhập từ máy khác (kho), thay vì tính trực tiếp từ workspace hiện tại
        d = kb_dir(); K = read_jsonl(os.path.join(d, 'corrections.jsonl')) if d else []
        K = [dict(r, case=f"{r['peer']}:{r['case']}" if r.get('peer') else r['case']) for r in K if (r.get('ts') or '') >= since]
    else: K = [r for c in cases(CFG.REA) for r in corrections(c) if (r.get('ts') or '') >= since]
    print(f"Đính chính: {len(K)} fact bị thay ở {len({r['case'] for r in K})} case" + (f' (từ {since})' if since else '') + (' (cả kho, gồm máy khác)' if everything else ''))
    if not K: return 0
    cnt = lambda k: ', '.join(f'{v} {n}' for v, n in collections.Counter(r[k] for r in K).most_common(10))
    for lab, k in (('theo loại', 'type'), ('theo kind cũ', 'old_kind'), ('nguồn gốc fact cũ', 'origin'), ('phát hiện bởi', 'caught'), ('theo case', 'case')):
        print(f'  {lab}: {cnt(k)}')
    by = collections.defaultdict(set); n = collections.Counter()
    for r in K: by[(r['old_kind'], r['type'])].add(r['case']); n[(r['old_kind'], r['type'])] += 1
    cand = [(k, t, n[(k, t)], len(by[(k, t)])) for k, t in n if n[(k, t)] >= 3 and len(by[(k, t)]) >= 2]
    print('Mẫu lặp lại (>= 3 lần, >= 2 case): ứng viên luật lint, CHỈ THEO DÕI, chưa áp dụng')
    for k, t, m, cs in sorted(cand, key=lambda x: (-x[3], -x[2])): print(f'  {k} / {t}: {m} lần ở {cs} case')
    if not cand: print('  chưa có')
    return 0

def main(a):
    if a[:1] == ['build']: return build()
    if a[:1] == ['match'] and len(a) > 1: match(a[1]); return 0
    if a[:1] == ['corrections']: return stats(a[a.index('--since') + 1] if '--since' in a else '', '--all' in a)
    nm = a[a.index('--name') + 1] if '--name' in a and a.index('--name') + 1 < len(a) else None
    if a[:1] == ['export'] and len(a) > 1: return export(a[1], nm)
    if a[:1] == ['import'] and len(a) > 1: return import_(a[1], nm)
    print('flow.py kb build | match CASE | corrections [--since YYYY-MM-DD] [--all] | export FILE [--name TÊN] | import FILE [--name TÊN]'); return 2

if __name__ == '__main__': sys.exit(main(sys.argv[1:]))
