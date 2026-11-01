# Tóm tắt events.jsonl của winemu thành vài chục dòng (đọc cái này thay vì log thô).
#   python3 summarize.py OUT/events.jsonl [--facts CASE]
#   --facts: chép các event làm bằng chứng sang CASE/report/evidence/emu_<run>.jsonl rồi ghi fact src=E
import sys, os, json, collections

ev = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
by = collections.defaultdict(list)
for e in ev: by[e['proc']].append(e)

def uniq(seq):
    seen = set()
    return [x for x in seq if not (x in seen or seen.add(x))]

for proc, es in by.items():
    k = collections.defaultdict(list)
    for e in es: k[e['kind']].append(e)
    print(f'## {proc}')
    for e in k['start']: print(f'- start eip={e["eip"]} (+{e["off"]}) mode={e["mode"]}')
    if k['module']: print('- modules:', ', '.join(uniq(e['name'] for e in k['module'])))
    for e in k['veh'][:2]: print(f'- VEH handler {e["handler"]} (+{e["off"]})')
    for e in k['str_key'][:1]: print(f'- khóa chuỗi @+{e["key_off"]} ({e["keylen"]} B): {e["key"]}')
    strs = uniq([e['s'] for e in k['str']] + [e['s'] for e in k['argstr']])
    if strs:
        print(f'- chuỗi ({len(strs)}):')
        for s in strs[:60]: print(f'    {s[:120]!r}' + (f' …(+{len(s) - 120} ký tự)' if len(s) > 120 else ''))
    net = uniq(json.dumps({x: y for x, y in e.items() if x not in ('proc', 'kind', 'buf', 'total')}, ensure_ascii=False) for e in k['net'])
    if net:
        print(f'- mạng ({len(k["net"])} lần gọi, {len(net)} khác nhau):')
        for s in net[:20]: print('    ' + s)
    for kind in ('anti', 'file', 'env', 'proc_create', 'proc_kill', 'child_alloc', 'child_write', 'child_read', 'map_view',
                 'section', 'child_setcontext', 'child_resume', 'alloc', 'ui', 'chain_child', 'snapshot', 'stop_at',
                 'exc_no_veh', 'veh_unhandled', 'intr', 'prerun_end', 'exit'):
        rows = uniq(json.dumps({x: y for x, y in e.items() if x not in ('proc', 'kind')}, ensure_ascii=False) for e in k[kind])
        if rows:
            print(f'- {kind} ({len(k[kind])}):' + ('' if len(rows) > 1 else ' ' + rows[0]))
            if len(rows) > 1:
                for s in rows[:8]: print('    ' + s)
    for e in k['api']:
        if e.get('unhandled'): print(f'- API CHƯA HỖ TRỢ: {e["dll"]}!{e["name"]} args={e["args"]} caller={e["caller"]} (+{e["coff"]})')
    for e in k['end']:
        print(f'- end: {e["reason"]} eip={e["eip"]} api={e["api_calls"]} veh={e["veh"]} t={e["seconds"]}s exc={e["exceptions"]}')
        print('  top API: ' + ', '.join(f'{n}×{c}' for n, c in e['top_api']))
    print()

def to_facts(case_dir, path):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import case
    run = os.path.basename(os.path.dirname(os.path.abspath(path)))
    keep = [e for e in ev if e['kind'] in ('net', 'str_key', 'anti', 'proc_create', 'child_write', 'child_resume', 'chain_child',
                                            'map_view', 'file', 'section', 'exit', 'stop_at', 'veh_unhandled', 'exc_no_veh', 'end')]
    rel = f'report/evidence/emu_{run}.jsonl'
    with open(os.path.join(case_dir, rel), 'w') as f:
        for e in keep: f.write(json.dumps(e, ensure_ascii=False) + '\n')
    have = {(f['kind'], f['value']) for f in case.load(case_dir).values() if f['status'] != 'retracted'}
    n, h = [0], lambda v: __import__('hashlib').sha1(v.encode()).hexdigest()[:8]
    def add(kind, value, line, **kw):   # id theo nội dung: chạy lại không đè fact cũ
        if (kind, value) in have: return
        have.add((kind, value)); n[0] += 1
        case.add(case_dir, id=f'e.{run}.{kind}.{h(value)}', kind=kind, value=value, src='E', evidence=f'{rel}#L{line}', **kw)
    stops = {e['proc']: e for e in keep if e['kind'] == 'stop_at'}
    exits = {e['proc']: e for e in keep if e['kind'] == 'exit'}
    errs = {e['proc']: e for e in keep if e['kind'] in ('veh_unhandled', 'exc_no_veh')}
    for i, e in enumerate(keep, 1):
        k = e['kind']
        if k == 'net' and e.get('url'): add('url', e['url'], i)
        if k == 'net' and e.get('ua'): add('ua', e['ua'], i)
        if k == 'net' and e.get('host'): add('c2', f"{e['host']}:{e.get('port')}", i)
        if k == 'str_key': add('str_key', e.get('sha256') or e['key'], i, note=f"{e['keylen']} B @+{e['key_off']}")
        if k == 'anti': add('anti_analysis', e['what'], i)
        if k == 'child_write' and e['n'] > 0x100000: add('inject', f"{e['proc']}: ghi {e['n']:#x} B vào tiến trình con", i)
        if k == 'end':
            p = e['proc']
            r = f"natural: {exits[p]['api']}" if p in exits else f"stop_at: {stops[p]['api']}" if p in stops else \
                f"emu_error: {errs[p]['kind']} {errs[p].get('code')} @ {errs[p].get('addr')}" if p in errs else e['reason']
            add('exit_reason', f'{p}: {r}', i)
            if e.get('api_unused'): add('api_unused', f"{p}: " + ' '.join(e['api_unused']), i,
                                        note='đối chiếu với import table của payload vừa giải mã trước khi kết luận hành vi')
    print(f'{n[0]} fact mới -> {case_dir}/facts.jsonl (evidence {rel}, {len(keep)} event)')

if '--facts' in sys.argv: to_facts(sys.argv[sys.argv.index('--facts') + 1], sys.argv[1])
