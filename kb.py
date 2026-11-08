#!/usr/bin/env python3
# Kho tra chéo giữa các case (flow.py kb). Chỉ đọc case, chỉ ghi vào REA_KB; không ghi gì vào case, không tạo fact.
#   samples.jsonl      đặc trưng của mọi file đã triage (imphash, rich, PDB, chứng thư, md5 section, export, TLSH) + hash/IOC
#                      trong fact đang hiệu lực. `kb match` dùng để GỢI Ý mẫu tương tự. Gợi ý không phải fact: không chép vào
#                      evidence, không trích vào báo cáo; muốn dùng thì chứng minh lại trên chính mẫu của case (không quy kết chéo).
#                      Không lưu kết luận họ mã độc (fact family) của case khác: gợi ý chỉ nói đặc trưng nào trùng.
#   corrections.jsonl  mọi fact bị thay bằng supersedes -> `kb corrections` thống kê lỗi hay gặp. Chỉ để theo dõi, làm dữ liệu
#                      quyết định luật lint sau này; không đổi luật nào của case.py/review.py.
# Dữ liệu chứa IOC: REA_KB mặc định ~/.local/share/rea-flow/kb, không được nằm trong thư mục skill (repo public).
#   flow.py kb build | match CASE | corrections [--since YYYY-MM-DD]
import sys, os, re, json, glob, datetime, collections
TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [TOOLS, os.path.join(TOOLS, 'static')]
import reacfg as CFG, case   # noqa: E402
MAX_FILE = 256 << 20
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
    R = triage.pivot_of(p); P = R.get('pivot', {})
    junk = {None, 'd41d8cd98f00b204e9800998ecf8427e'}   # md5 rỗng
    return {'case': os.path.basename(c), 'file': os.path.relpath(p, os.path.realpath(c)), 'sha256': R['sha256'], 'type': R['type'],
            'size': R['size'], 'imp_n': len(R.get('imported_funcs', [])), 'exports': sorted(set(R.get('exports', [])))[:200],
            'sec_md5': sorted({s['md5'] for s in R.get('sections', []) if s.get('md5') not in junk and s.get('raw', 0) >= 512}),
            'certs': sorted({f"{x['issuer']}|{x['serial']}" for x in P.get('certs') or []}),
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

def write_jsonl(p, rows):
    t = p + '.part'
    with open(os.open(t, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w', encoding='utf-8') as fh:   # có IOC: chỉ chủ sở hữu đọc
        for r in rows: fh.write(json.dumps(r, ensure_ascii=False) + '\n')
    os.replace(t, p)

def build(ws=None, quiet=False):
    d = kb_dir()
    if not d: print('REA_KB=off: không dựng kho'); return 0
    ws = ws or CFG.REA; os.makedirs(d, mode=0o700, exist_ok=True)
    S, K, err = [], [], 0
    for c in cases(ws):
        for p in files_of(c):
            try: S.append(file_rec(c, p))
            except Exception as e: err += 1; print(f'  bỏ {safe(os.path.relpath(p, ws), 100)}: {type(e).__name__}', file=sys.stderr)
        S.append(case_rec(c)); K += corrections(c)
    ws = os.path.abspath(ws)
    for r in S + K: r['ws'] = ws
    def keep(name):   # kho dùng chung: giữ bản ghi của workspace khác, chỉ thay phần của workspace đang dựng
        p = os.path.join(d, name)
        try: old = [json.loads(l) for l in open(p, encoding='utf-8') if l.strip()] if os.path.exists(p) else []
        except Exception: old = []
        return [r for r in old if r.get('ws') not in (None, ws)]
    S = keep('samples.jsonl') + S; K = keep('corrections.jsonl') + K
    write_jsonl(os.path.join(d, 'samples.jsonl'), S); write_jsonl(os.path.join(d, 'corrections.jsonl'), K)
    n = len({r['case'] for r in S})
    json.dump({'built': datetime.datetime.now().isoformat(timespec='seconds'), 'workspace': ws, 'cases': n,
               'files': sum(r.get('kind') != 'case' for r in S), 'corrections': len(K)}, open(os.path.join(d, 'meta.json'), 'w'), indent=1)
    if not quiet: print(f'kb: {n} case, {sum(r.get("kind") != "case" for r in S)} file, {len(K)} đính chính -> {d}' + (f' ({err} file lỗi)' if err else ''))
    return 0

def load_kb(d):
    p = os.path.join(d, 'samples.jsonl')
    return [json.loads(l) for l in open(p, encoding='utf-8') if l.strip()] if os.path.exists(p) else None

def tlsh_diff(a, b):
    try: import tlsh; return tlsh.diff(a, b)
    except Exception: return None

def compare(n, o, freq):
    """Đặc trưng trùng giữa file mới n và file trong kho o: [(tên, mức)]; mức: mạnh | vừa | yếu."""
    hit = []
    if n['sha256'] == o['sha256']: return [('trùng sha256', 'mạnh')]
    if n.get('imphash') and n['imphash'] == o.get('imphash'):
        hit.append(('imphash', 'yếu' if n.get('imp_n', 0) < 5 or freq['imphash'][n['imphash']] >= 3 else 'mạnh'))
    for k, lab, lv in (('pdb_guid', 'PDB GUID', 'mạnh'), ('build_id', 'GNU build-id', 'mạnh'), ('rich', 'rich header', 'vừa'),
                       ('impfuncs_md5', 'bộ hàm import', 'yếu')):
        if n.get(k) and n[k] == o.get(k): hit.append((lab, 'yếu' if freq[k][n[k]] >= 3 else lv))
    if n.get('pdb') and not n.get('pdb_guid') and n['pdb'].lower() == (o.get('pdb') or '').lower(): hit.append(('đường dẫn PDB', 'vừa'))
    cs = set(n.get('certs', [])) & set(o.get('certs', []))
    if cs: hit.append((f'chung {len(cs)} chứng thư', 'yếu'))   # phần mềm hợp lệ cùng hãng cũng trùng: chỉ là ngữ cảnh
    sm = set(n.get('sec_md5', [])) & set(o.get('sec_md5', []))
    if sm: hit.append((f'chung {len(sm)} section', 'vừa'))
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
    me, mws = os.path.basename(os.path.abspath(c)), os.path.dirname(os.path.abspath(c))
    K = [r for r in K if (r['case'], r.get('ws', mws)) != (me, mws)]   # bỏ chính case này; case trùng tên ở workspace khác vẫn so
    for r in K:
        if r.get('ws', mws) != mws: r['case'] = f"{os.path.basename(r['ws'])}:{r['case']}"   # nêu rõ workspace khác
    F = [r for r in K if r.get('kind') != 'case']; C = [r for r in K if r.get('kind') == 'case']
    freq = collections.defaultdict(collections.Counter)
    for k in ('imphash', 'pdb_guid', 'build_id', 'rich', 'impfuncs_md5'):
        seen = collections.defaultdict(set)
        for r in F:
            if r.get(k): seen[r[k]].add(r['case'])
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
        meta = os.path.join(d, 'meta.json'); built = json.load(open(meta)).get('built', '?') if os.path.exists(meta) else '?'
        print(f'kb match {me}: {len(mine)} file so với {len(F)} file / {len(C)} case khác (kho dựng {built})')
    if rows:
        print('GỢI Ý, không phải fact: không chép vào evidence hay báo cáo; muốn dùng thì tự chứng minh lại trên mẫu của case này.')
        for _, t in rows[:limit]: print('  ' + t)
        if len(rows) > limit: print(f'  ... còn {len(rows) - limit} gợi ý: flow.py kb match {me}')
    elif header: print('  không có gợi ý tương đồng')
    return len(rows)

def hint(c):
    """Sau new/triage: in gợi ý nếu kho đã có; lỗi kho không được làm hỏng triage."""
    try: match(c, limit=8, header=False)
    except SystemExit as e: print(f'kb: {e}')
    except Exception as e: print(f'kb: bỏ qua gợi ý ({type(e).__name__}: {safe(e, 100)})')

def refresh(c):
    """Sau report --final: dựng lại kho để case vừa đóng vào dữ liệu tra chéo và thống kê đính chính."""
    try:
        if kb_dir(): build(os.path.dirname(os.path.abspath(c)), quiet=True); print(f'kb: đã cập nhật {kb_dir()}')
    except SystemExit as e: print(f'kb: {e}')
    except Exception as e: print(f'kb: không cập nhật được ({type(e).__name__}: {safe(e, 100)})')

def stats(since=''):
    K = [r for c in cases(CFG.REA) for r in corrections(c) if (r.get('ts') or '') >= since]
    print(f"Đính chính: {len(K)} fact bị thay ở {len({r['case'] for r in K})} case" + (f' (từ {since})' if since else ''))
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
    if a[:1] == ['corrections']: return stats(a[a.index('--since') + 1] if '--since' in a else '')
    print('flow.py kb build | match CASE | corrections [--since YYYY-MM-DD]'); return 2

if __name__ == '__main__': sys.exit(main(sys.argv[1:]))
