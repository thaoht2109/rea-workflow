#!/usr/bin/env python3
# Bản HTML của báo cáo case (report/report-<ngày>.html), do case.report() sinh mỗi lần chạy `flow.py report`.
# Gộp: tóm tắt số liệu + checklist C0–C11 + báo cáo viết tay (report-<ngày>.md) + bảng sinh từ facts (GENERATED.md).
# Chỉ để xem: nguồn chân lý vẫn là facts.jsonl và file .md. Không thư viện ngoài, không tải tài nguyên mạng
# (CSP chặn mọi request), liên kết ngoài (URL/IOC trong báo cáo) không bấm được, chỉ đường dẫn tương đối mới thành link.
import re, html, datetime

esc = lambda s: html.escape(s, quote=True)

def slug(t, used):
    s = re.sub(r'[^\w]+', '-', html.unescape(re.sub(r'<[^>]+>', '', t)).lower(), flags=re.U).strip('-') or 'muc'
    k, i = s, 2
    while k in used: k, i = f'{s}-{i}', i + 1
    used.add(k); return k

def _href(u):
    """Chỉ nhận đường dẫn tương đối (evidence/, GENERATED.md, #mục). URL có scheme, đường tuyệt đối, //host hay /\\host (trình duyệt
    chuẩn hóa thành //host: file:// -> UNC/SMB) thì không thành link: tránh bấm nhầm vào hạ tầng mã độc. Ký tự điều khiển/khoảng trắng
    bị trình duyệt bỏ khi phân tích URL nên bỏ trước khi kiểm (\\x01javascript: -> javascript:)."""
    u = re.sub(r'[\x00-\x20\x7f]', '', u).replace('\\', '/')
    if not u or u.startswith('/') or re.match(r'^[^/?#]*:', u): return None
    if u.split('#')[0] == 'GENERATED.md': return '#phu-luc'
    return u[len('report/'):] if u.startswith('report/evidence/') else u

def _code(c):
    m = re.match(r'^report/(evidence/[^\s#`]+)(#L\d+(?:-L?\d+)?)?$', c)   # nhãn bỏ tiền tố report/evidence/ cho cột hẹp; đường dẫn đủ ở title
    return f'<a class="ev" href="{esc(m.group(1))}" title="{esc(c)}"><code>{esc(c[len("report/evidence/"):])}</code></a>' if m else f'<code>{esc(c)}</code>'

def inline(t):
    """Mã và link thay bằng chỗ giữ trước (không định dạng bên trong mã), rồi escape + đậm/nghiêng cả dòng, cuối cùng trả chỗ giữ."""
    keep = []
    def k(h): keep.append(h); return f'\x00{len(keep) - 1}\x00'
    def link(m):
        h = _href(m.group(2)); label = fmt(m.group(1))
        return k(f'<a href="{esc(h)}">{label}</a>' if h else f'{label} (<code>{esc(m.group(2))}</code>)')
    t = re.sub(r'(`+)(.+?)\1', lambda m: k(_code(m.group(2).strip())), t.replace('\x00', ''))
    t = fmt(re.sub(r'!?\[([^\]]*)\]\(([^)\s]+)\)', link, t))
    while '\x00' in t: t = re.sub(r'\x00(\d+)\x00', lambda m: keep[int(m.group(1))], t)
    return t

def fmt(s):
    s = esc(s)
    s = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', s)
    s = re.sub(r'(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])', r'<em>\1</em>', s)
    return re.sub(r'(?<![\w])_(?!\s)(.+?)(?<!\s)_(?![\w])', r'<em>\1</em>', s)

def cells(row):
    row = row.strip()
    if row.startswith('|'): row = row[1:]
    if row.endswith('|') and not row.endswith('\\|'): row = row[:-1]
    out, cur, tick = [], '', False
    for i, ch in enumerate(row):
        if ch == '`': tick = not tick
        if ch == '|' and not tick and (i == 0 or row[i - 1] != '\\'): out.append(cur); cur = ''
        else: cur += ch
    return [c.strip().replace('\\|', '|') for c in out + [cur]]

SEP = re.compile(r'^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$')
LI = re.compile(r'^(\s*)([-*+]|\d+[.)])\s+(.*)$')

def md(text, shift=0, used=None, toc=None):
    """Markdown tối giản (tiêu đề, đoạn, bảng, danh sách, trích dẫn, khối mã, đường kẻ) -> HTML đã escape."""
    used = set() if used is None else used
    text = re.sub(r'<!--.*?-->', '', text, flags=re.S)
    L, i, out = text.splitlines(), 0, []
    while i < len(L):
        ln = L[i]
        if not ln.strip(): i += 1; continue
        m = re.match(r'^\s*(```+|~~~+)\s*(\S*)', ln)
        if m:
            fence, j, buf = m.group(1), i + 1, []
            while j < len(L) and not L[j].strip().startswith(fence): buf.append(L[j]); j += 1
            out.append(f'<pre><code>{esc(chr(10).join(buf))}</code></pre>'); i = j + 1; continue
        m = re.match(r'^(#{1,6})\s+(.*?)\s*#*\s*$', ln)
        if m:
            lv = min(len(m.group(1)) + shift, 6); body = inline(m.group(2)); a = slug(body, used)
            if toc is not None and lv == 2: toc.append((a, html.unescape(re.sub(r'<[^>]+>', '', body))))
            out.append(f'<h{lv} id="{a}">{body}</h{lv}>'); i += 1; continue
        if re.match(r'^\s*([-*_])(\s*\1){2,}\s*$', ln): out.append('<hr>'); i += 1; continue
        if ln.lstrip().startswith('|') and i + 1 < len(L) and SEP.match(L[i + 1]):
            head, j, rows = cells(ln), i + 2, []
            while j < len(L) and L[j].strip().startswith('|'): rows.append(cells(L[j])); j += 1
            h = ''.join(f'<th>{inline(c)}</th>' for c in head)
            b = ''.join('<tr>' + ''.join(f'<td>{inline(c)}</td>' for c in r + [''] * (len(head) - len(r))) + '</tr>' for r in rows)
            out.append(f'<div class="tw"><table><thead><tr>{h}</tr></thead><tbody>{b}</tbody></table></div>'); i = j; continue
        if ln.lstrip().startswith('>'):
            j, buf = i, []
            while j < len(L) and L[j].lstrip().startswith('>'): buf.append(re.sub(r'^\s*>\s?', '', L[j])); j += 1
            out.append(f'<blockquote>{md(chr(10).join(buf), shift, used)}</blockquote>'); i = j; continue
        if LI.match(ln):
            j, items = i, []
            while j < len(L) and (LI.match(L[j]) or (L[j].startswith((' ', '\t')) and L[j].strip() and items)):
                m = LI.match(L[j])
                if m: items.append([len(m.group(1).expandtabs(4)), m.group(2), m.group(3)])
                else: items[-1][2] += ' ' + L[j].strip()
                j += 1
            out.append(_list(items)); i = j; continue
        j, buf = i, []
        while j < len(L) and L[j].strip() and not re.match(r'^(#{1,6}\s|\s*```|\s*~~~|\s*>|\s*\|)', L[j]) and not LI.match(L[j]):
            buf.append(L[j].strip()); j += 1
        out.append(f'<p>{inline(" ".join(buf))}</p>'); i = max(j, i + 1)
    return '\n'.join(out)

def _list(items):
    """items: [thụt lề, dấu, nội dung]. Thụt sâu hơn mục trước thì lồng vào mục đó."""
    out, stack = [], []
    for ind, mark, body in items:
        tag = 'ol' if mark[0].isdigit() else 'ul'
        while stack and ind < stack[-1][0]: out.append(f'</li></{stack.pop()[1]}>')
        if not stack or ind > stack[-1][0]: out.append(f'<{tag}>'); stack.append((ind, tag))
        else: out.append('</li>')
        out.append(f'<li>{inline(body)}')
    while stack: out.append(f'</li></{stack.pop()[1]}>')
    return ''.join(out)

def badge(v):
    k = 'ok' if v.startswith('ok') else 'na' if v.startswith(('n/a', 'chấp nhận')) else 'fail' if v.startswith('fail') else 'partial' if v.startswith('partial') else 'missing'
    return f'<span class="b {k}">{esc(v)}</span>'

CSS = """
:root{--bg:#f7f7f5;--fg:#1d1d1f;--mut:#6b6b70;--card:#fff;--line:#e3e3e0;--acc:#2f5bd3;--code:#f0f0ec;
--ok:#1f7a3d;--okb:#e3f3e8;--pa:#8a5a00;--pab:#fbf0d9;--mi:#a12a2a;--mib:#f9e3e3;--na:#555;--nab:#ececec}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#151517;--fg:#e8e8ea;--mut:#9a9aa2;--card:#1e1e21;--line:#323236;
--acc:#8aa8ff;--code:#2a2a2e;--ok:#7fd59a;--okb:#16321f;--pa:#f0c46a;--pab:#3a2e14;--mi:#ff9a9a;--mib:#3d1a1a;--na:#bbb;--nab:#2c2c30}}
:root[data-theme="dark"]{--bg:#151517;--fg:#e8e8ea;--mut:#9a9aa2;--card:#1e1e21;--line:#323236;--acc:#8aa8ff;--code:#2a2a2e;
--ok:#7fd59a;--okb:#16321f;--pa:#f0c46a;--pab:#3a2e14;--mi:#ff9a9a;--mib:#3d1a1a;--na:#bbb;--nab:#2c2c30}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans",sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:24px 16px 64px;display:grid;grid-template-columns:230px minmax(0,1fr);gap:28px}
nav{position:sticky;top:16px;align-self:start;max-height:calc(100vh - 32px);overflow:auto;font-size:13.5px}
nav a{display:block;color:var(--mut);text-decoration:none;padding:3px 8px;border-left:2px solid var(--line)}
nav a:hover{color:var(--acc);border-color:var(--acc)}nav .t{font-weight:600;color:var(--fg);margin:0 0 8px 8px}
main{min-width:0}header{margin-bottom:20px}h1{font-size:26px;line-height:1.25;margin:0 0 6px}
.verdict{margin:10px 0 12px;padding:10px 14px;border:2px solid;border-radius:10px}.verdict span{display:inline-block;padding:3px 12px;border-radius:999px;color:#fff;font-weight:700}.verdict div{margin-top:6px;font-size:.92em}
.meta{color:var(--mut);font-size:13.5px}.draft{display:inline-block;margin-top:8px;padding:4px 10px;border-radius:6px;background:var(--pab);color:var(--pa);font-weight:600;font-size:13px}
.final{background:var(--okb);color:var(--ok)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:18px 0}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 14px}.stat b{display:block;font-size:22px}.stat span{color:var(--mut);font-size:12.5px}
section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:6px 22px 18px;margin:0 0 18px}
h2{font-size:20px;margin:22px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}h3{font-size:17px;margin:20px 0 8px}h4,h5,h6{font-size:15px}
a{color:var(--acc)}code{font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--code);padding:1px 5px;border-radius:4px;word-break:break-word;overflow-wrap:anywhere}
pre{background:var(--code);padding:12px 14px;border-radius:8px;overflow:auto}pre code{padding:0;background:none;word-break:normal;overflow-wrap:normal}
blockquote{margin:12px 0;padding:4px 16px;border-left:3px solid var(--acc);color:var(--mut)}
.tw{overflow-x:auto;margin:10px 0}table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{border:1px solid var(--line);padding:6px 9px;text-align:left;vertical-align:top}th{background:var(--code);font-weight:600}
a.ev code{white-space:nowrap;word-break:normal}tr.hide{display:none}.b{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;white-space:nowrap}
.b.ok{background:var(--okb);color:var(--ok)}.b.partial{background:var(--pab);color:var(--pa)}.b.missing,.b.fail{background:var(--mib);color:var(--mi)}.b.na{background:var(--nab);color:var(--na)}
.filter{width:100%;max-width:420px;padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);font:inherit;margin:8px 0}
.note{color:var(--mut);font-size:13px}.tools{float:right}.tools button{font:inherit;font-size:12.5px;background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:3px 9px;cursor:pointer}
@media (max-width:860px){.wrap{grid-template-columns:minmax(0,1fr)}nav{position:static;max-height:none}section{padding:4px 14px 14px}}
@media print{nav,.filter,.tools{display:none}.wrap{display:block}section{border:0;padding:0}body{background:#fff;color:#000}}
"""

JS = """
(function(){var r=document.documentElement,b=document.getElementById('theme');
b.onclick=function(){var d=r.getAttribute('data-theme')||(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');r.setAttribute('data-theme',d==='dark'?'light':'dark')};
var f=document.getElementById('filter');if(!f)return;f.oninput=function(){var q=f.value.toLowerCase();
document.querySelectorAll('#phu-luc-body tbody tr').forEach(function(t){t.classList.toggle('hide',q&&t.textContent.toLowerCase().indexOf(q)<0)})}})();
"""

VERDICT_BLOCK = re.compile(r'<div id="phan-loai".*?</div></div>', re.S)

def verdict_html(v):
    """Khối nhãn phân loại (case.verdict) đặt dưới <h1>: màu cố định của từng mức, chữ trắng. export thay khối này khi xuất."""
    src_ = f"suy tạm từ fact {v['id']} (family), chưa có fact verdict" if v['inferred'] else (f"fact {v['id']}" if v['id'] else 'không có fact')
    return (f'<div id="phan-loai" class="verdict" style="border-color:{v["color"]}"><span style="background:{v["color"]}">PHÂN LOẠI: {esc(v["label"])}</span>'
            f'<div>Căn cứ: {esc(src_)}' + (f': {esc(v["why"][:300])}' if v['why'] else '') + '</div></div>')

def render(case, date, body_md, gen_md, checklist, stats, gate=None, src=None, verdict=None):
    """checklist: [(mục, trạng thái, gợi ý)] từ case.check(); stats: active/hypothesis/retracted/ioc/evidence;
    gate: (ok, lý do) của review.gate (cùng điều kiện với report --final); không có thì suy từ C0."""
    used, toc = {'tom-tat', 'checklist', 'phu-luc'}, []
    body = md(re.sub(r'\A\s*#\s[^\n]*\n', '', body_md), 0, used, toc) if body_md.strip() else '<p class="note">Chưa có báo cáo viết tay (report/report-&lt;ngày&gt;.md).</p>'
    gen = md(gen_md, 1, used)
    c0 = next((v for k, v, _ in checklist if k.startswith('C0')), 'missing')
    done, why = gate if gate else (c0.startswith('ok'), c0)
    rows = ''.join(f'<tr><td>{esc(k)}</td><td>{badge(v)}</td><td>{esc(n)}</td></tr>' for k, v, n in checklist)
    S = [('active', 'fact hiệu lực'), ('hypothesis', 'giả thuyết'), ('retracted', 'đã rút/thay'), ('ioc', 'IOC'), ('evidence', 'file evidence')]
    stat = ''.join(f'<div class="stat"><b>{stats.get(k, 0)}</b><span>{t}</span></div>' for k, t in S)
    nav = ''.join(f'<a href="#{a}">{esc(t)}</a>' for a, t in [('checklist', 'Checklist C0–C11')] + toc + [('phu-luc', 'Phụ lục: bảng sinh từ facts')])
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
    vd = verdict_html(verdict) if verdict else ''
    return f"""<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<meta name="referrer" content="no-referrer"><title>Báo cáo {esc(case)}</title><style>{CSS}</style></head>
<body><div class="wrap"><nav><div class="t">{esc(case)}</div>{nav}</nav><main>
<header><div class="tools"><button id="theme" type="button">Sáng/tối</button></div><h1>Báo cáo phân tích: {esc(case)}</h1>{vd}
<div class="meta">Ngày phân tích {esc(date)} · sinh lúc {now} bởi rea-workflow · nguồn: <code>facts.jsonl</code>, <code>{esc(src or f'report-{date}.md')}</code></div>
<div class="draft{' final' if done else ''}">{'Cổng phản biện: đạt (' + esc(why) + ')' if done else 'BẢN NHÁP: cổng phản biện chưa đạt (' + esc(why) + ')'}</div>
<div class="stats" id="tom-tat">{stat}</div></header>
<section><h2 id="checklist">Checklist C0–C11</h2><div class="tw"><table><thead><tr><th>Mục</th><th>Trạng thái</th><th>Việc còn lại</th></tr></thead><tbody>{rows}</tbody></table></div></section>
<section>{body}</section>
<section><h2 id="phu-luc">Phụ lục: bảng sinh từ facts</h2><p class="note">Sinh từ <code>facts.jsonl</code> (cùng nội dung <code>GENERATED.md</code>). Liên kết ngoài bị vô hiệu: URL/IOC chỉ hiện dạng chữ.</p>
<input id="filter" class="filter" type="search" placeholder="Lọc dòng trong các bảng phụ lục…"><div id="phu-luc-body">{gen}</div></section>
</main></div><script>{JS}</script></body></html>
"""

if __name__ == '__main__':
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); import case
    if len(sys.argv) != 2: raise SystemExit('dùng: htmlreport.py CASE  (thường gọi qua flow.py report CASE)')
    case.report(sys.argv[1]); print(case.report_html(sys.argv[1]))
