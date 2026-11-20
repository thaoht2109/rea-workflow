#!/usr/bin/env python3
# flow.py export CASE OUT: gói dữ liệu phân tích của một case thành thư mục tự đủ <tên mẫu>_data/ để chia sẻ hoặc lưu, xóa được case sau đó.
# Chỉ đọc case (facts, báo cáo trong case không đổi); không bao giờ chạy mẫu.
#   <tên mẫu>_data/  <tên mẫu>.md|.html (báo cáo + mục "Thông tin mẫu" + liên kết chi tiết), README.txt, MANIFEST.sha256, facts.jsonl,
#                    report/ (evidence, GENERATED.md), work/ (runs, tools, review...), ghi_chu_thu_mau/, mau_va_payload.7z
# Mẫu và mọi thứ có thể là mã độc KHÔNG chép dạng rõ, gói vào mau_va_payload.7z (mật khẩu infected, -mhe=on mã hóa cả tên file):
#   - theo vị trí: work/sample, work/extract, work/unpacked* (mẫu, file giải nén, payload bóc ra, kể cả script dạng text);
#   - theo nội dung: mọi file không phải văn bản (ELF/PE, bản dump bộ nhớ không header, snapshot giả lập, blob giải mã...).
# Không chép: .claude/, __pycache__/, .git/, work/ghidra/ (dự án Ghidra, lớn, dựng lại được), .watch.lock, symlink.
# Nội dung ghi chú thu mẫu đến từ máy bị thu: luôn escape trong HTML, không thành liên kết.
import os, re, sys, html, json, codecs, shutil, hashlib, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import case as C, reacfg as CFG   # noqa: E402

ZIP_PW, ZIP = 'infected', 'mau_va_payload.7z'
PACK_DIRS = ('work/sample', 'work/extract', 'work/unpacked')   # tiền tố đường dẫn: luôn gói, kể cả file text
SKIP_DIRS = ('.claude', '__pycache__', '.git', 'work/ghidra')
SKIP_FILES = ('.watch.lock',)
NOTE_EXT, NOTE_MAX = ('.txt', '.log', '.md', '.note', '.notes'), 256 * 1024
SUMS = re.compile(r'(?:^|[._-])(?:sha256sums?|sha256)(?:\.txt)?$', re.I)
SCRIPT = re.compile(r'\A#!|\|\s*(?:ba|z|da)?sh\b|\b(?:curl|wget|powershell|iex|Invoke-\w+|certutil|bitsadmin|nc|ncat|socat)\b|base64\s+-d|\beval\b|CreateObject|WScript|Add-Type|FromBase64String|<script|\bfunction\b|\bimport\s+\w|\brequire\s*\(', re.I)   # nội dung giống script: là mẫu, không phải ghi chú
SUMLINE = re.compile(r'(?m)^[0-9a-fA-F]{64}[ \t]+\*?\S')   # dòng của danh sách sha256sum
HDR_KV = re.compile(r'([\w.-]+)=(.*?)(?=\s+[\w.-]+=|$)')
CMD = re.compile(r'^\$\s+\S+(?:\s+-\S+)*\s+(\S+)\s*$')
HEX64 = re.compile(r'\b([0-9a-f]{64})\b')
HEAD = 'Dữ liệu phân tích của mẫu '   # dòng đầu README.txt; watch.reported() đọc "(sha256 <hex>)" ở dòng này
e = lambda s: html.escape(str(s), quote=True)

def sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''): h.update(b)
    return h.hexdigest()

def text_of(p, limit=NOTE_MAX):
    """Nội dung UTF-8 nếu p là file văn bản (không NUL, giải mã được, không quá limit byte), không thì None."""
    try:
        if limit and os.path.getsize(p) > limit: return None
        with open(p, 'rb') as f: b = f.read(limit or -1)
    except OSError: return None
    if b'\0' in b[:65536]: return None
    try: return b.decode('utf-8')
    except UnicodeDecodeError: return None

def is_text(p):
    """Cả file là văn bản UTF-8 không có NUL (đọc hết theo khối, không chỉ phần đầu: blob nhị phân nối sau phần text vẫn bị gói)."""
    dec = codecs.getincrementaldecoder('utf-8')()
    try:
        with open(p, 'rb') as f:
            for b in iter(lambda: f.read(1 << 20), b''):
                if b'\0' in b: return False
                dec.decode(b)
        dec.decode(b'', final=True); return True
    except (OSError, UnicodeDecodeError): return False

def packed(rel, p):
    """File này phải nằm trong 7z, không chép dạng rõ: theo vị trí (PACK_DIRS, OUT_DIR của công cụ T1b work/runs/tool/<TÊN>/),
    file không phải văn bản, và file văn bản ngoài report/ và facts.jsonl có nội dung giống script (payload text bóc ra)."""
    r = rel.replace(os.sep, '/'); parts = r.split('/')
    if any(r == d or r.startswith(d) for d in PACK_DIRS) or (len(parts) >= 5 and parts[:3] == ['work', 'runs', 'tool']): return True
    if not is_text(p): return True
    if parts[0] in ('report', 'facts.jsonl'): return False
    t = text_of(p, 0)
    return t is None or bool(SCRIPT.search(t))

def parse_note(t, h):
    lines = t.splitlines()
    hdr = HDR_KV.findall(lines[0].lstrip('#').strip()) if lines and lines[0].startswith('#') and '=' in lines[0] else []
    path = next((m.group(1) for ln in lines if (m := CMD.match(ln))), '')
    shas = sorted(set(HEX64.findall(t)))
    match = 'khớp' if h in shas else ('không khớp: ' + ', '.join(shas)) if shas else 'không có sha256'
    return {'hdr': hdr, 'path': path, 'sha': match, 'text': t}

def _inbox_files(inbox, skip):
    for d, ds, fs in os.walk(inbox):
        ds[:] = sorted(x for x in ds if not x.startswith('.') and not x.startswith('Report_') and os.path.realpath(os.path.join(d, x)) not in skip
                       and not os.path.exists(os.path.join(d, x, 'work', 'watch.json')) and not ours(os.path.join(d, x)))   # bản xuất trong INBOX: không phải ghi chú
        for n in sorted(fs):
            p = os.path.join(d, n)
            if not n.startswith('.') and os.path.isfile(p) and not os.path.islink(p): yield p

def collect(c, st=None):
    """Thông tin mẫu của case c. st: watch.json (source, inbox, sha256) nếu case do watch nhận; không có thì lấy file trong work/sample."""
    st = st or {}; c = os.path.abspath(c)
    smp = sorted(os.path.join(d, n) for d, _, ns in os.walk(os.path.join(c, 'work', 'sample')) for n in ns)
    src = os.path.abspath(st['source']) if st.get('source') else (smp[0] if smp else '')
    if not src: raise OSError(f'{c}: không có mẫu (work/sample trống, watch.json không có source)')
    loc = src if os.path.isfile(src) else next((p for p in smp if os.path.basename(p) == os.path.basename(src)), smp[0] if smp else '')
    h = st.get('sha256') or (sha(loc) if loc else '')
    try: size = os.path.getsize(loc)
    except OSError: size = None
    F = C.load(c) if os.path.exists(os.path.join(c, 'facts.jsonl')) else {}
    ftype = '; '.join(sorted({f['value'] for f in F.values() if f.get('kind') == 'filetype' and f.get('status') == 'active'}))
    inbox = os.path.abspath(st['inbox']) if st.get('inbox') and os.path.isdir(st['inbox']) else ''
    aliases, notes, sums = [], [], []
    if inbox:
        texts = []
        for p in _inbox_files(inbox, {os.path.realpath(c), os.path.realpath(os.getcwd())}):
            if p == src: continue
            try: sz = os.path.getsize(p)
            except OSError: continue
            if size is not None and sz == size and sha(p) == h: aliases.append(p); continue
            if p.lower().endswith(NOTE_EXT) or SUMS.search(os.path.basename(p)):
                t = text_of(p)   # cùng tiêu chí với watch.note_of: nội dung giống script là mẫu (có case riêng), không gom làm ghi chú
                if t is not None and not SCRIPT.search(t) and (not SUMS.search(os.path.basename(p)) or SUMLINE.search(t)): texts.append((p, t))
        stems = {(os.path.dirname(x), os.path.splitext(os.path.basename(x))[0]) for x in [src] + aliases}
        for p, t in texts:
            base = os.path.basename(p)
            if SUMS.search(base):
                ls = [ln for ln in t.splitlines() if h in ln or any(s and s in ln for _, s in stems)]
                if ls: sums.append((p, ls))
            elif h in t or any(os.path.dirname(p) == d and base.startswith(s + '.') for d, s in stems):
                notes.append(dict(parse_note(t, h), file=p))
    return {'name': os.path.basename(src), 'src': src, 'inbox': inbox, 'sha256': h, 'size': size, 'ftype': ftype,
            'aliases': aliases, 'notes': notes, 'sums': sums, 'case': c}

def ours(d):
    """d do export sinh (dòng đầu README.txt đúng mẫu): được phép xóa để xuất lại."""
    try:
        with open(os.path.join(d, 'README.txt'), encoding='utf-8', errors='replace') as f: first = f.readline()
    except OSError: return False
    return first.startswith(HEAD) and '(sha256 ' in first

def export(info, d):
    """Chép dữ liệu case vào d (thư mục <tên mẫu>_data); mẫu và file có thể là mã độc vào 7z. Trả danh sách đường dẫn đã gói.
    Dựng trong thư mục tạm ẩn .<tên>.part cạnh d rồi mới thay d: lỗi giữa chừng (7z hỏng, đĩa đầy) không để lại d dở dang."""
    c = info['case']
    if os.path.lexists(d) and not ours(d): raise OSError(f'{d} đã có nhưng không do export sinh (README.txt không đúng mẫu): không xóa, xem rồi dời đi')
    final, d = d, os.path.join(os.path.dirname(d), '.' + os.path.basename(d) + '.part')
    if os.path.lexists(d): shutil.rmtree(d)   # bản dở của lần trước (tên do hàm này đặt)
    os.makedirs(d); pack = []
    for root, ds, fs in os.walk(c):
        r = os.path.relpath(root, c)
        ds[:] = sorted(x for x in ds if os.path.normpath(os.path.join(r, x)).replace(os.sep, '/') not in SKIP_DIRS and x not in ('.claude', '__pycache__', '.git')
                       and not os.path.islink(os.path.join(root, x)))
        for n in sorted(fs):
            p = os.path.join(root, n); rel = os.path.normpath(os.path.join(r, n))
            if n in SKIP_FILES or os.path.islink(p) or not os.path.isfile(p): continue
            if packed(rel, p): pack.append(rel); continue
            q = os.path.join(d, rel); os.makedirs(os.path.dirname(q), exist_ok=True); shutil.copyfile(p, q); os.chmod(q, 0o644)
    for p in [n['file'] for n in info['notes']] + [p for p, _ in info['sums']]:   # giữ đường dẫn tương đối trong INBOX: hai SHA256SUMS ở hai thư mục không đè nhau
        r = os.path.relpath(p, info['inbox']) if info['inbox'] else os.path.basename(p)
        q = os.path.join(d, 'ghi_chu_thu_mau', os.path.basename(p) if r.startswith('..') else r); os.makedirs(os.path.dirname(q), exist_ok=True); shutil.copyfile(p, q); os.chmod(q, 0o644)
    rows = [(sha(os.path.join(dp, n)), os.path.relpath(os.path.join(dp, n), d)) for dp, _, ns in os.walk(d) for n in ns]
    if pack:
        z = os.path.join(d, ZIP)
        lst = d + '.list'   # danh sách qua file (@list, -spd tắt wildcard): case nhiều file không vượt giới hạn argv
        with open(lst, 'w', encoding='utf-8') as f: f.write(''.join(x + '\n' for x in pack))
        try: r = subprocess.run([CFG.SEVENZ, 'a', '-t7z', '-p' + ZIP_PW, '-mhe=on', '-y', '-spd', '-scsUTF-8', z, '@' + lst], cwd=c, capture_output=True, text=True)
        except OSError as x: raise OSError(f'không chạy được 7z ({CFG.SEVENZ}): {x}; đặt SEVENZ_BIN trong rea.env')
        finally: os.remove(lst)
        if r.returncode or not os.path.isfile(z): raise OSError(f'7z lỗi: {(r.stdout + r.stderr)[-300:]}')
        rows += [(sha(os.path.join(c, x)), f'{ZIP}:{x}') for x in pack] + [(sha(z), ZIP)]
    with open(os.path.join(d, 'MANIFEST.sha256'), 'w', encoding='utf-8') as f: f.write(''.join(f'{h}  {n}\n' for h, n in sorted(rows, key=lambda x: x[1])))
    with open(os.path.join(d, 'README.txt'), 'w', encoding='utf-8') as f: f.write(
        f"{HEAD}{info['name']} (sha256 {info['sha256']}), chép từ case {os.path.basename(c)}.\n\n"
        f"{info['name']}.html  báo cáo của mẫu (mở file này); {info['name']}.md cùng nội dung dạng Markdown\n"
        "facts.jsonl            nguồn chân lý: mọi kết luận (src S/E/V, evidence)\n"
        "report/                báo cáo viết tay, GENERATED.md (bảng từ facts), evidence/ (trích dẫn #L)\n"
        "work/                  kết quả trung gian: runs/, tools/, review/ (không có work/ghidra, mẫu và payload)\n"
        + ("ghi_chu_thu_mau/       ghi chú thu mẫu đi kèm trong INBOX (bản chép)\n" if info['notes'] or info['sums'] else '')
        + "MANIFEST.sha256        sha256 mọi file; dòng 'mau_va_payload.7z:<đường dẫn>' là file nằm trong 7z\n"
        + (f"{ZIP}      mẫu sống, file giải nén, payload và file nhị phân; mật khẩu `{ZIP_PW}`. Chỉ giải nén trên máy phân tích cô lập, không thực thi.\n" if pack else ''))
    if os.path.lexists(final): shutil.rmtree(final)
    os.rename(d, final)
    return pack

def _size(n): return '' if n is None else f'{n:,} byte'.replace(',', '.')

def _rel_src(info): return os.path.relpath(info['src'], os.path.dirname(info['inbox'])) if info['inbox'] else info['name']

def _links(info, d):
    L = [(x, t) for x, t in (('report/evidence', 'mọi file bằng chứng (trích dẫn #L trong báo cáo)'), ('facts.jsonl', 'nguồn chân lý: mọi kết luận kèm src S/E/V và evidence'),
                              ('report/GENERATED.md', 'bảng sinh từ facts: hash, IOC, đính chính'), ('work', 'kết quả trung gian: runs/, tools/, review/'),
                              ('ghi_chu_thu_mau', 'ghi chú thu mẫu đi kèm (bản chép)'), ('MANIFEST.sha256', 'sha256 mọi file, kể cả file trong 7z'),
                              (ZIP, f'mẫu và payload, mật khẩu {ZIP_PW}; chỉ giải nén trên máy phân tích cô lập')) if os.path.exists(os.path.join(d, x))]
    ev = os.path.join(d, 'report', 'evidence')
    return L, (sorted(os.listdir(ev)) if os.path.isdir(ev) else [])

def _rows(info):
    r = [('Tên file', info['name'], True), ('Đường dẫn trong INBOX', _rel_src(info), True), ('SHA-256', info['sha256'], True), ('Kích thước', _size(info['size']), False)]
    if info['ftype']: r.append(('Loại file', info['ftype'], False))
    r += [('Bản trùng hash', os.path.relpath(a, os.path.dirname(info['inbox'])) + ' (cùng mẫu, dùng chung báo cáo này)', True) for a in info['aliases']]
    return r + [('Case phân tích', os.path.basename(info['case']), True)]

def mdc(s):
    """Ô Markdown cho dữ liệu không tin cậy (tên file, ghi chú từ máy bị thu): escape HTML, | và `, một dòng."""
    return html.escape(str(s), quote=False).replace('|', '\\|').replace('`', "'").replace('\r', ' ').replace('\n', ' ')

def md_section(info):
    L = ['## Thông tin mẫu', '', '| Mục | Giá trị |', '|---|---|'] + [f"| {k} | {'`' + mdc(v) + '`' if code else mdc(v)} |" for k, v, code in _rows(info)]
    if info['notes']:
        L += ['', '### Ghi chú thu mẫu (do người thu cung cấp, chưa kiểm chứng trong case)', '', '| File ghi chú | Thông tin đầu file | Đường dẫn gốc | SHA-256 trong ghi chú |', '|---|---|---|---|']
        L += [f"| `{mdc(os.path.basename(n['file']))}` | {mdc('; '.join(f'{k}={v}' for k, v in n['hdr']))} | `{mdc(n['path'])}` | {mdc(n['sha'])} |" for n in info['notes']]
    for p, ls in info['sums']: L += ['', f"`{mdc(os.path.basename(p))}`:", '```'] + [ln.replace('`', "'") for ln in ls] + ['```']   # không để ``` đóng khối sớm
    return '\n'.join(L) + '\n'

def md_details(info, d):
    L, ev = _links(info, d)
    out = ['## Chi tiết: dữ liệu phân tích', '', f"Dữ liệu nằm cùng thư mục với báo cáo này (case gốc `{os.path.basename(info['case'])}`). Mẫu và payload chỉ nằm trong `{ZIP}` (mật khẩu `{ZIP_PW}`), không thực thi.", '']
    out += [f'- [{x}]({x}): {t}' for x, t in L]
    if ev: out += ['', 'File evidence:', ''] + [f'- [{n}](report/evidence/{n})' for n in ev]
    return '\n'.join(out) + '\n'

CSS = ('.si td:first-child{white-space:nowrap;font-weight:600}.si code{word-break:break-all}'
       'details.note{margin:8px 0}details.note pre{white-space:pre-wrap;max-height:420px;overflow:auto}')

def html_section(info):
    H = ['<section><h2 id="thong-tin-mau">Thông tin mẫu</h2><div class="tw"><table class="si"><tbody>']
    H += [f"<tr><td>{e(k)}</td><td>{'<code>' + e(v) + '</code>' if code else e(v)}</td></tr>" for k, v, code in _rows(info)] + ['</tbody></table></div>']
    if info['notes']:
        H.append('<h3>Ghi chú thu mẫu</h3><p class="note">Do người thu mẫu cung cấp; chưa kiểm chứng trong case. Nội dung hiển thị nguyên văn dạng chữ.</p>'
                 '<div class="tw"><table><thead><tr><th>File ghi chú</th><th>Thông tin đầu file</th><th>Đường dẫn gốc</th><th>SHA-256 trong ghi chú</th></tr></thead><tbody>')
        H += [f"<tr><td><code>{e(os.path.basename(n['file']))}</code></td><td>{e('; '.join(f'{k}={v}' for k, v in n['hdr']))}</td>"
              f"<td><code>{e(n['path'])}</code></td><td>{e(n['sha'])}</td></tr>" for n in info['notes']]
        H.append('</tbody></table></div>')
        H += [f"<details class=\"note\"><summary>Nguyên văn <code>{e(os.path.basename(n['file']))}</code></summary><pre>{e(n['text'])}</pre></details>" for n in info['notes']]
    for p, ls in info['sums']: H.append(f"<p><code>{e(os.path.basename(p))}</code></p><pre>{e(chr(10).join(ls))}</pre>")
    return ''.join(H) + '</section>'

def html_details(info, d):
    L, ev = _links(info, d)
    H = ['<section><h2 id="chi-tiet">Chi tiết: dữ liệu phân tích</h2>',
         f"<p class=\"note\">Dữ liệu nằm cùng thư mục với báo cáo này (case gốc <code>{e(os.path.basename(info['case']))}</code>). Mẫu và payload chỉ nằm trong <code>{ZIP}</code> (mật khẩu <code>{ZIP_PW}</code>), không thực thi.</p><ul>"]
    H += [f'<li><a href="{e(x)}">{e(x)}</a>: {e(t)}</li>' for x, t in L] + ['</ul>']
    if ev: H += ['<h3>File evidence</h3><ul>'] + [f'<li><a href="report/evidence/{e(n)}">{e(n)}</a></li>' for n in ev] + ['</ul>']
    return ''.join(H) + '</section>'

def rebase(t, c, d, kind):
    """Liên kết tương đối của báo cáo gốc (tính từ <case>/report/) trỏ lại vào bản chép trong d; file chỉ có trong 7z thì trỏ vào 7z.
    Liên kết neo, tuyệt đối, có scheme hoặc tới file không tồn tại thì giữ nguyên."""
    base = os.path.join(c, 'report')
    def fix(m):
        u = html.unescape(m.group(2)) if kind == 'html' else m.group(2); path, sep, frag = u.partition('#')
        if not path or re.match(r'^[a-z][a-z0-9+.-]*:', path, re.I) or path.startswith('/'): return m.group(0)
        tgt = os.path.normpath(os.path.join(base, path)); rel = os.path.relpath(tgt, c)
        if rel.startswith('..') or not os.path.exists(tgt): return m.group(0)
        v = rel if os.path.exists(os.path.join(d, rel)) else ZIP if os.path.exists(os.path.join(d, ZIP)) else None
        if v is None: return m.group(0)
        v = v.replace(os.sep, '/') + (sep + frag if sep else '')
        return m.group(1) + (e(v) if kind == 'html' else v) + m.group(3)
    return re.sub(r'(href=")([^"]+)(")' if kind == 'html' else r'(\]\()([^)\s]+)(\))', fix, t)

def augment(info, d):
    """Báo cáo của mẫu trong d: chép .md/.html của case, chỉnh liên kết, chèn "Thông tin mẫu" trước mục đầu và "Chi tiết" ở cuối."""
    c, name = info['case'], info['name']
    md, ht = C.report_md(c), C.report_html(c)
    if os.path.isfile(md):
        t = rebase(open(md, encoding='utf-8', errors='replace').read(), c, d, 'md')
        m = re.search(r'^## ', t, re.M)
        t = t[:m.start()] + md_section(info) + '\n' + t[m.start():] if m else t + '\n' + md_section(info)
        with open(os.path.join(d, name + '.md'), 'w', encoding='utf-8') as f: f.write(t.rstrip('\n') + '\n\n' + md_details(info, d))
    if os.path.isfile(ht):
        t = rebase(open(ht, encoding='utf-8', errors='replace').read(), c, d, 'html').replace('</style>', CSS + '</style>', 1)
        t = re.sub(r'(<nav><div class="t">.*?</div>)', lambda m: m.group(1) + '<a href="#thong-tin-mau">Thông tin mẫu</a>', t, count=1, flags=re.S)
        t = t.replace('</nav>', '<a href="#chi-tiet">Chi tiết</a></nav>', 1)
        i = t.find('<section>'); sec = html_section(info)
        t = t[:i] + sec + t[i:] if i >= 0 else t.replace('</main>', sec + '</main>', 1) if '</main>' in t else t + sec
        j = t.rfind('</main>'); det = html_details(info, d)
        t = t[:j] + det + t[j:] if j >= 0 else t + det
        with open(os.path.join(d, name + '.html'), 'w', encoding='utf-8') as f: f.write(t)

def write(c, st, d):
    """Gói case c vào d (<tên mẫu>_data): dữ liệu + 7z + báo cáo có thông tin mẫu. Trả info."""
    info = collect(c, st); export(info, d); augment(info, d); return info

def main(c, a):
    """flow.py export CASE OUT: ghi OUT/<tên mẫu>_data/."""
    if not a: print('dùng: flow.py export CASE OUT   (ghi OUT/<tên mẫu>_data/; mẫu và payload trong 7z mật khẩu infected)'); return 2
    try: st = json.load(open(os.path.join(c, 'work', 'watch.json'), encoding='utf-8'))
    except (OSError, ValueError): st = {}
    try:
        info = collect(c, st); d = os.path.join(os.path.abspath(a[0]), info['name'] + '_data')
        export(info, d); augment(info, d)
    except OSError as x: print(f'export lỗi: {x}'); return 1
    print(f'{d}: báo cáo {info["name"]}.html, MANIFEST.sha256' + (f', {ZIP} (mật khẩu {ZIP_PW})' if os.path.exists(os.path.join(d, ZIP)) else ''))
    return 0
