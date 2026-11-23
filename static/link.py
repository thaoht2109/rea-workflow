#!/usr/bin/env python3
# Đối chiếu chéo tĩnh giữa các mẫu của một case (từ hai mẫu trở lên): loại/kiến trúc, thời điểm tệp, định danh của mẫu này có xuất hiện trong mẫu kia không, chuỗi chung.
# Kết quả là evidence để ghi fact kind=relation; nó KHÔNG kết luận quan hệ: không có tham chiếu chéo không loại trừ liên hệ lúc chạy. Chỉ đọc file.
import os, re, sys, json, hashlib, datetime
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import case as C   # noqa: E402
from static import quick   # noqa: E402

GENERIC = re.compile(r'^(?:/dev/(?:null|zero|u?random|tty\w*|shm/?|stdin|stdout|stderr)|/proc/?(?:self/\w+)?|/sys/?|/tmp/?|/etc/(?:resolv\.conf|hosts|nsswitch\.conf|services|localtime|passwd|group|'
                     r'ld\.so\.\w+|netsvc\.conf|svc\.conf|zoneinfo/?)|/usr/(?:share/zoneinfo/?|lib/?|local/?)|/var/(?:run|tmp)/?|/bin/sh|/lib/?)$')
HOST = re.compile(r'(?i)^(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})(?:[:/]|$)')

MAX_SAMPLES = 12   # đối chiếu từng cặp: giới hạn số mẫu, lấy các tệp lớn nhất

def _files(case):
    """([(tên mẫu, đường dẫn bản gốc, đường dẫn bản để phân tích)], [mẫu bị bỏ qua kèm lý do]). Bản để phân tích là bản gỡ UPX (<tên>.unupx) nếu có."""
    sd = os.path.join(case, 'work', 'sample'); out, skip = [], []
    for n in C.sources(case):
        p = os.path.join(sd, n)
        if n.endswith('/'): skip.append(f'{n} (mẫu dạng thư mục)')
        elif os.path.isfile(p) and not os.path.islink(p): out.append((n, p, p + '.unupx' if os.path.isfile(p + '.unupx') else p))
        else: skip.append(f'{n} (không còn trong work/sample)')
    if len(out) > MAX_SAMPLES:
        out.sort(key=lambda x: -os.path.getsize(x[1])); skip += [f'{n} (vượt giới hạn {MAX_SAMPLES} mẫu lớn nhất)' for n, _, _ in out[MAX_SAMPLES:]]; out = sorted(out[:MAX_SAMPLES])
    return out, skip

def _triage(case, sha):
    """triage.json của tệp có sha256 này trong report/evidence (tên file do triage đặt: cắt 32 ký tự, có thể kèm hậu tố), tìm theo nội dung chứ không đoán tên."""
    ev = os.path.join(case, 'report', 'evidence')
    for f in sorted(os.listdir(ev)) if os.path.isdir(ev) else []:
        if f.startswith('triage_') and f.endswith('.json'):
            try: R = json.load(open(os.path.join(ev, f), encoding='utf-8'))
            except (OSError, ValueError): continue
            if isinstance(R, dict) and R.get('sha256') == sha: return R
    return None

def _idents(name, G):
    """Định danh riêng của một mẫu để tìm trong mẫu khác: tên tệp, host/URL, đường dẫn không phổ biến, tham số dòng lệnh."""
    ids = []
    stem = os.path.splitext(os.path.basename(name))[0]
    if len(stem) >= 4: ids.append(stem)
    for l in G['net']:
        m = HOST.match(l.strip()); ids.append(m.group(1) if m else l.strip())
    ids += [l.strip() for l in G['path'] if len(l.strip()) >= 8 and ' ' not in l.strip() and not GENERIC.match(l.strip())]
    ids += [l.strip().split('=')[0] + '=' for l in G['cli'] if re.match(r'\s*-{1,2}[A-Za-z][\w-]{3,}=', l)]
    return [x for x in dict.fromkeys(ids) if len(x) >= 4][:25]

def build(case):
    F, skipped = _files(case)
    if len(F) < 2: raise ValueError(f'case có {len(F)} mẫu dạng tệp trong work/sources.json: cần từ hai mẫu trở lên để đối chiếu (mẫu thêm bằng `flow.py new CASE MẪU...`)')
    D = {n: open(a, 'rb').read() for n, _, a in F}; T = {}; G = {}
    for n, p, a in F:
        R = _triage(case, hashlib.sha256(D[n]).hexdigest())
        st = os.stat(p); T[n] = dict(size=st.st_size, mtime=st.st_mtime, sha256=hashlib.sha256(open(p, 'rb').read()).hexdigest(), type=' '.join([R['type']] + R.get('flags', [])) if R and R.get('type') else None, unp=a != p)
        G[n] = quick.groups(quick.build(a, D[n])[0])
    L = [f'# đối chiếu chéo tĩnh giữa {len(F)} mẫu của case (không chạy mẫu): ' + ', '.join(n for n, _, _ in F),
         '# giới hạn: chỉ so chuỗi rõ và siêu dữ liệu tệp; không có tham chiếu chéo KHÔNG loại trừ liên hệ lúc chạy (lệnh từ máy chủ, script khởi động ngoài bộ mẫu).',
         '# mtime là của bản chép trong work/sample (giữ từ tệp nguồn khi tạo case), không phải thời điểm trên thiết bị gốc.', '## Bộ mẫu']
    for n, _, _ in F:
        t = T[n]; L.append(f"{n}: {t['size']} B, sha256 {t['sha256']}, mtime {datetime.datetime.fromtimestamp(t['mtime']).isoformat(timespec='seconds')}, loại {t['type'] or 'không rõ (thiếu triage: chạy flow.py triage CASE)'}" + (' (đối chiếu trên bản đã gỡ UPX)' if t['unp'] else ''))
    if skipped: L.append('bỏ qua, không đối chiếu: ' + '; '.join(skipped))
    ms = [T[n]['mtime'] for n, _, _ in F]; L.append('## Thời điểm tệp'); L.append(f'chênh lệch mtime lớn nhất giữa các mẫu: {max(ms) - min(ms):.1f} giây')
    L.append('## Loại và kiến trúc')
    if any(T[n]['type'] is None for n, _, _ in F): L.append('không so được: có mẫu chưa rõ loại (thiếu triage)')   # không khẳng định giống/khác khi thiếu dữ liệu
    else:
        arch = {n: ' '.join(T[n]['type'].split()[:3]) if T[n]['type'].startswith('ELF') else T[n]['type'].split()[0] for n, _, _ in F}   # ELF: lớp, máy, endian (vd ELF32 MIPS BE)
        L.append(('cùng định dạng và kiến trúc: ' + next(iter(arch.values()))) if len(set(arch.values())) == 1 else 'khác định dạng/kiến trúc: ' + ' | '.join(f'{n}: {a}' for n, a in arch.items()))
        L += [f"{n}: {T[n]['type']}" for n, _, _ in F]
    L.append('## Định danh của mẫu này trong mẫu kia (số lần xuất hiện, không phân biệt hoa thường)')
    for a, _, _ in F:
        ids = _idents(a, G[a])
        for b, _, _ in F:
            if a == b: continue
            hits = [(x, len(re.findall(re.escape(x.encode('utf-8')), D[b], re.I))) for x in ids if x.encode('utf-8')]   # UTF-8: tên không phải Latin không bị cắt thành mẫu rỗng
            L.append(f'{b} chứa định danh của {a}: ' + (', '.join(f'"{x}" {c} lần' for x, c in hits if c) or 'không có') + f' (đã thử {len(ids)} định danh: {", ".join(ids[:8])}{"…" if len(ids) > 8 else ""})')
    L.append('## Chuỗi chung đáng chú ý (URL/tên miền, đường dẫn không phổ biến, tham số dòng lệnh có ở từ hai mẫu trở lên)')
    seen = {}
    for n, _, _ in F:
        for l in dict.fromkeys(G[n]['net'] + G[n]['path'] + G[n]['cli']):
            l = l.strip()
            if len(l) >= 6 and not GENERIC.match(l): seen.setdefault(l, []).append(n)
    common = [(l, ns) for l, ns in seen.items() if len(ns) >= 2]
    L += [f'{l}  [{", ".join(ns)}]' for l, ns in common[:30]] or ['(không có)']
    return '\n'.join(L) + '\n'

if __name__ == '__main__':
    try: print(build(sys.argv[1]), end='')
    except ValueError as e: raise SystemExit(str(e))
