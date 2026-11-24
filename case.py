#!/usr/bin/env python3
# Dữ liệu một case phân tích: facts.jsonl (chỉ ghi thêm), checklist C1–C12, sinh bảng báo cáo, đối chiếu evidence.
#   case.py add CASE id=.. kind=.. value=.. src=S|E|V evidence=report/evidence/F[#Ln] [status=..] [verified_by=S,E] [supersedes=..] [stage=..] [note=..] [recompute=..] [--strict]
#   recompute: phép đếm lại con số trong value, máy chạy lại mỗi lần lint/review: '<count|distinct> <regex> report/evidence/F[#La-Lb] = <N>',
#   nhiều phép nối bằng ' && '. count = số dòng khớp; distinct = số giá trị khác nhau (nhóm 1 nếu có). N phải có trong value.
#   case.py show CASE [kind] | show CASE --id ID | search CASE TỪ... [--src S] [--all]     case.py check CASE     case.py report CASE     case.py audit CASE     case.py --selftest
#   Báo cáo viết tay: report/report-<ngày phân tích>.md (report_md); report sinh GENERATED.md và report-<ngày>.html (bản gộp để xem).
#   add chạy lint_fact() trước khi ghi: evidence tồn tại/đúng dòng, src khớp loại evidence, hash tính lại,
#   value phải có trong đoạn evidence được trỏ (±WINDOW dòng khi có #L), số liệu phải có trong evidence.
#   Mặc định chỉ in cảnh báo; --strict từ chối ghi nếu có lỗi mức fail.
import sys, os, json, re, shlex, hashlib, datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); import adhoc   # noqa: E402  luật cho evidence tool_* (tầng T1b)

KINDS = {'hash', 'filetype', 'container', 'entry', 'anti_analysis', 'str_algo', 'str_key', 'string', 'config',
         'url', 'ua', 'c2', 'inject', 'persistence', 'mutex', 'file', 'registry', 'process',
         'payload_fmt', 'payload_key', 'payload_hash', 'family', 'exit_reason', 'api_unused', 'dec_coverage', 'coverage', 'verdict', 'relation', 'env', 'observe'}
# Tầng T5 (VM): fact `env` = đặc tả môi trường mẫu cần để chạy, `observe` = câu hỏi VM phải trả lời. value là JSON một dòng, vẫn cần src S/E và evidence.
# env: khóa `t` chọn loại, kèm các khóa bắt buộc dưới đây. observe: khóa `q`. vm/spec.py gộp chúng thành vmspec.json.
ENV_T = {'guest': ('os', 'arch'), 'layout': ('dir', 'files', 'main'), 'launch': ('mode',), 'precond': ('type',), 'net': ('mode',), 'time': ('max_s',)}
NET_MODES = ('none', 'sink', 'internet')   # tăng dần: không mạng < DNS giả + bộ hứng chỉ ghi < ra Internet qua đường riêng của sandbox
GUEST_OS, GUEST_ARCH = ('windows', 'linux'), ('x86', 'x64', 'mips', 'mipsel', 'arm', 'aarch64')
OBSERVE_Q = ('process_tree', 'child', 'dns', 'tls_sni', 'http', 'file', 'registry', 'mutex', 'memdump', 'payload')
ENV_EX = """ví dụ value='{"t":"layout","dir":"C:\\\\Users\\\\Public","files":["a.exe","b.dll"],"main":"a.exe"}' | '{"t":"launch","mode":"default","args":""}' | '{"t":"net","mode":"sink","dns":["host"]}' | '{"t":"time","max_s":600}'; observe: '{"q":"process_tree"}' (FLOW.md mục 2, T5)"""
def env_leaves(v):
    """Mọi chuỗi lá của value JSON (kể cả trong danh sách/đối tượng lồng), theo thứ tự khóa."""
    if isinstance(v, str): return [v]
    if isinstance(v, dict): return [x for k in sorted(v) for x in env_leaves(v[k])]
    if isinstance(v, list): return [x for i in v for x in env_leaves(i)]
    return []
def env_strings(v):
    """Mọi chuỗi trong value JSON, cả khóa lẫn giá trị ở mọi cấp: thứ sẽ được in ra hoặc chép vào vmspec."""
    if isinstance(v, str): return [v]
    if isinstance(v, dict): return [x for k in sorted(v) for x in [k] + env_strings(v[k])]
    if isinstance(v, list): return [x for i in v for x in env_strings(i)]
    return []
def env_value(f):
    """value JSON của fact env/observe đã qua kiểm, hoặc None nếu sai dạng (env_issue nói vì sao)."""
    return None if env_issue(f) else json.loads(f['value'])
def env_issue(f):
    """Fact env/observe: value phải là đối tượng JSON đúng lược đồ. Trả (vấn đề, cách sửa) hoặc None. Dùng chung cho lint khi ghi, lớp 1 của cổng và vm/spec.py.
    Chuỗi trong value đi thẳng vào vmspec và vào dòng dẫn đường của agent: cấm ký tự điều khiển, giới hạn độ dài."""
    k = f['kind']
    if k not in ('env', 'observe'): return None
    try: v = json.loads(f['value'])
    except ValueError: return f'value của fact {k} không phải JSON', ENV_EX
    if not isinstance(v, dict): return f'value của fact {k} phải là một đối tượng JSON', ENV_EX
    L = env_strings(v)
    if any(len(x) > 300 or re.search(r'[\x00-\x1f\x7f`]', x) for x in L): return 'chuỗi trong value dài quá 300 ký tự hoặc có ký tự điều khiển/dấu `', 'rút gọn, bỏ ký tự điều khiển'
    if k == 'observe':
        return None if isinstance(v.get('q'), str) and v['q'] in OBSERVE_Q else (f"observe cần khóa q thuộc: {', '.join(OBSERVE_Q)}", ENV_EX)
    t = v.get('t')
    if not isinstance(t, str) or t not in ENV_T: return f"env cần khóa t thuộc: {', '.join(ENV_T)}", ENV_EX
    miss = [x for x in ENV_T[t] if x not in v]
    if miss: return f"env t={t} thiếu khóa: {', '.join(miss)}", ENV_EX
    S = lambda x: isinstance(x, str) and bool(x.strip())
    if t == 'guest' and (v['os'] not in GUEST_OS or v['arch'] not in GUEST_ARCH): return f"guest: os thuộc {'|'.join(GUEST_OS)}, arch thuộc {'|'.join(GUEST_ARCH)}", ENV_EX
    if t == 'net':
        if v['mode'] not in NET_MODES: return f"net.mode chỉ nhận {'|'.join(NET_MODES)}", ENV_EX
        d = v.get('dns', [])
        if not isinstance(d, list) or not all(S(x) for x in d): return 'net.dns phải là danh sách tên miền', ENV_EX
        if not isinstance(v.get('tcp', []), list) or not all(isinstance(x, int) and not isinstance(x, bool) and 0 < x < 65536 for x in v.get('tcp', [])): return 'net.tcp phải là danh sách cổng (số nguyên 1-65535)', ENV_EX
    if t == 'time' and (not isinstance(v['max_s'], int) or isinstance(v['max_s'], bool) or v['max_s'] <= 0): return 'time.max_s phải là số nguyên dương (giây)', ENV_EX
    if t == 'launch' and (not S(v['mode']) or not isinstance(v.get('args', ''), str)): return 'launch.mode phải là chuỗi không rỗng, launch.args (nếu có) là chuỗi', ENV_EX
    if t == 'precond' and not S(v['type']): return 'precond.type phải là chuỗi không rỗng', ENV_EX
    if t == 'layout':
        fs = v['files']
        if not S(v['dir']) or not isinstance(fs, list) or not fs or not all(S(x) for x in fs): return 'layout cần dir và danh sách files không rỗng', ENV_EX
        if any(x.startswith(('/', '\\')) or re.match(r'[A-Za-z]:', x) or '..' in re.split(r'[\\/]', x) for x in fs): return 'layout.files là tên tương đối trong dir (không tuyệt đối, không ..)', ENV_EX
        if len(set(fs)) != len(fs) or v['main'] not in fs: return 'layout.main phải là một mục của files, files không lặp', ENV_EX
ENV_CTRL = ('t', 'mode', 'type', 'os', 'arch', 'q')   # khóa điều khiển: giá trị thuộc bảng cố định của skill, không lấy từ mẫu
def env_data(f):
    """Chuỗi dữ liệu của fact env lấy từ mẫu (tên file, thư mục, tham số, khóa registry, tên miền): mọi chuỗi lá trừ giá trị của khóa điều khiển ở cấp đầu, bỏ chuỗi rỗng."""
    try: v = json.loads(f['value'])
    except ValueError: return []
    return [x for x in env_leaves({k: x for k, x in v.items() if k not in ENV_CTRL}) if x.strip()] if f['kind'] == 'env' and isinstance(v, dict) else []
def env_missing(f, scope):
    """Chuỗi dữ liệu của fact env KHÔNG có nguyên văn trong scope (văn bản evidence đã chuẩn hóa như ev_scope). Fact env quyết định tham số chạy mẫu,
    nên kiểm chặt hơn kind chữ thường: TỪNG chuỗi phải có trong evidence, không chỉ một token (một tên file thật không đỡ được cho tham số bịa)."""
    n = lambda x: x.replace('\\\\', '\\').lower()
    return [x for x in env_data(f) if n(x) not in scope and _normnum(n(x)) not in scope]

IOC_KINDS = ['hash', 'url', 'ua', 'c2', 'mutex', 'file', 'registry', 'process', 'str_key', 'payload_key', 'payload_hash', 'family']
# Phân loại cả mẫu (kind=verdict): value = '<khóa>: lý do'. Nhãn đặt trên đầu báo cáo HTML, GENERATED.md và bản export.
VERDICT = {'malicious': ('MÃ ĐỘC / CÔNG CỤ TẤN CÔNG', '#cf222e'), 'suspicious': ('NGHI VẤN / CHƯA KẾT LUẬN ĐƯỢC', '#bc4c00'),
           'nofind': ('KHÔNG THẤY HÀNH VI ĐỘC HẠI (trong phạm vi đã phân tích)', '#9a6700'), 'benign': ('KHÔNG PHẢI MÃ ĐỘC / LÀNH TÍNH', '#1a7f37'),
           'unknown': ('CHƯA XÁC ĐỊNH', '#57606a')}
VERDICT_RX = re.compile(r'(malicious|suspicious|nofind|benign)(?:\s*:\s*(\S.*))?\Z', re.S)
# Case chưa có fact verdict (tạo trước khi có kind này): suy tạm từ fact family, khớp hẹp, ghi rõ là suy luận
_BENIGN = re.compile(r'^\s*(?:n/a\s*:\s*)?(?:không (?:phải|có|chứa) mã độc|lành tính|benign)\b', re.I)   # chỉ khi đứng đầu value
_NOFIND = re.compile(r'^\s*(?:n/a\s*:\s*)?không (?:thấy|tìm thấy|có) hành vi độc hại', re.I)
_MALWARE = re.compile(r'backdoor|sniffer|trojan|rootkit|implant|web ?shell|reverse.?shell|bind.?shell|ransomware|\bminer\b|stealer|keylogger'
                      r'|botnet|loader|dropper|\bRAT\b|\bC2\b|cửa hậu|công cụ tấn công', re.I)

_NEGFILL = r'(?:là|một|các|bất kỳ|dấu hiệu|thành phần|hoạt động|kết nối|máy chủ|module|mã|hành vi|chức năng|tới|đến|với)'   # từ được chen giữa
_NEG = re.compile(r'(?:\b(?:không|chẳng|chưa)\s+(?:phải|có|thấy|chứa|tìm thấy|phát hiện)(?:\s+' + _NEGFILL + r')*'   # danh sách cố định: không lan sang mệnh đề sau
                  r'|\b(?:not|no|without)(?:\s+(?:a|an|any|the))?)\s*$', re.I)
def _mal(t):
    """Có từ khóa mã độc không bị phủ định ngay trước nó ("không phải backdoor", "không thấy kết nối C2", "not a trojan" không tính;
    "mẫu không đóng gói là trojan", "không có packer nhưng là trojan", "không có packer dropper tải payload" vẫn tính)."""
    return any(not _NEG.search(t[:m.start()]) for m in _MALWARE.finditer(t))

def verdict(case, cur=None):
    """Phân loại mẫu: fact verdict hiệu lực mới nhất; không có thì suy tạm từ fact family hiệu lực (inferred=True); không có nữa thì unknown."""
    cur = load(case) if cur is None else cur
    act = lambda k: sorted((f for f in cur.values() if f['kind'] == k and f['status'] == 'active'), key=lambda f: f.get('ts', ''))
    v = act('verdict')
    if v:
        f = v[-1]; m = VERDICT_RX.match(f['value'].strip()); k = m.group(1) if m else 'unknown'
        return dict(key=k, label=VERDICT[k][0], color=VERDICT[k][1], id=f['id'], why=(m.group(2) or '') if m else f['value'], inferred=False)
    fam = act('family')
    if not fam: return dict(key='unknown', label=VERDICT['unknown'][0], color=VERDICT['unknown'][1], id='', why='chưa có fact verdict hay family hiệu lực', inferred=False)
    def one(t):
        mal, ben, nof = _mal(t), _BENIGN.search(t), _NOFIND.search(t)   # từ khóa mã độc (không bị phủ định) xét trước; có cả hai chiều thì nghi vấn
        return ('suspicious' if ben or nof else 'malicious') if mal else 'benign' if ben else 'nofind' if nof else 'suspicious'
    rank = ('benign', 'nofind', 'suspicious', 'malicious')   # case nhiều mẫu: mỗi mẫu một fact family, nhãn suy tạm theo mẫu NẶNG NHẤT (cùng mức thì fact mới nhất)
    k, f = max(((one(x['value']), x) for x in fam), key=lambda p: (rank.index(p[0]), p[1].get('ts', '')))
    return dict(key=k, label=VERDICT[k][0], color=VERDICT[k][1], id=f['id'], why=f['value'], inferred=True)

def verdict_line(v):
    """Một dòng Markdown cho nhãn phân loại (GENERATED.md, bản export)."""
    src = f"suy tạm từ fact `{v['id']}` (family), chưa có fact verdict" if v['inferred'] else (f"fact `{v['id']}`" if v['id'] else 'không có fact')
    why = v['why'][:200].replace('|', '/').replace('\n', ' ')
    return f"> **PHÂN LOẠI: {v['label']}**. Căn cứ: {src}" + (f": {why}" if why else '')

PERSIST_API = re.compile(r'Reg(Set|Create)|CopyFile|MoveFile|CreateService|SchTask|Startup', re.I)
EV = 'report/evidence/'
REVIEW_RULE_VERSION = 3   # 2: fail ở check bằng chứng cứng luôn high. 3: fact verdict thuộc nhóm chặn, lookup_content là check cứng. Đổi số: state.json cũ hết hiệu lực
# lint khi ghi fact (xem lint_fact)
LITERAL_KINDS = {'c2', 'url', 'ua', 'mutex', 'file', 'registry', 'process', 'persistence',
                 'str_key', 'payload_key', 'config', 'string'}
TOKEN = re.compile(r'[A-Za-z0-9_.\\/%:$-]{5,}')
NUMTOK = re.compile(r'(?<![0-9A-Za-z])(0x[0-9a-fA-F]{4,}|\d{3,})(?![0-9A-Za-z])')
DATE = re.compile(r'\b\d{4}-\d{2}-\d{2}(?:[T ][\d:.]+)?\b')
LOG_LINES = 40   # evidence dài hơn mức này phải trỏ #L hoặc tách đoạn trích
WINDOW = 5       # có #L: value phải xuất hiện trong ±WINDOW dòng quanh đó

NATURAL_RX = re.compile(r'\s*(?:[^:\n]{1,60}:\s*)?natural\b')   # exit_reason đạt: '[tiến trình: ]natural…'; 'unnatural', 'chưa natural' không tính
def _normnum(s): return re.sub(r'(?<=\d)[.,](?=\d{3}(?!\d))', '', s)
def _line_id(t): return hashlib.sha256(t.strip().encode('utf-8', 'replace')).hexdigest()[:12]
def _relocate(lines, ln, lid):
    """Dòng mang dấu vân tay lid hiện ở đâu: ln nếu còn nguyên (hoặc fact cũ không có dấu), vị trí mới nếu đã dời và chỉ có
    đúng một dòng trùng dấu, None nếu mất, trùng nhiều dòng, hoặc ln ngoài phạm vi mà không có dấu để tìm."""
    inside = 1 <= ln <= len(lines)
    if not lid: return ln if inside else None
    if inside and _line_id(lines[ln - 1]) == lid: return ln
    hit = [i + 1 for i, t in enumerate(lines) if _line_id(t) == lid]
    return hit[0] if len(hit) == 1 else None      # dòng trùng nội dung (dòng trống, '}'): không đoán, coi như không tìm lại được
def evidence_now(case, f):
    """Con trỏ evidence của fact theo vị trí hiện tại của dòng: '#Ln' được đổi sang dòng mới nếu dòng đã dời và tìm lại được.
    Dùng ở mọi nơi trích đoạn evidence theo #L (hồ sơ phản biện), để đoạn trích không lệch khi file bị sửa sau lúc ghi fact."""
    m = re.search(r'#L(\d+)$', f['evidence'])
    if not m or not f.get('ev_line') or not ev_path(case, f['evidence'])[0].startswith(os.path.join('report', 'evidence') + os.sep): return f['evidence']   # ngoài report/evidence: không mở file
    try: lines = open(ev_path(case, f['evidence'])[1], encoding='utf-8', errors='replace').read().splitlines()
    except OSError: return f['evidence']
    mv = _relocate(lines, int(m.group(1)), f['ev_line'])
    return f['evidence'][:m.start()] + f'#L{mv}' if mv else f['evidence']
LOOKUP_MAX = 2048
LOOKUP_SEP = b'\n--- body ---\n'   # FLOW.md mục 0: phần đầu (lệnh, URL, thời điểm, mã trạng thái) rồi dòng này rồi thân trả về
LOOKUP_LINE = re.compile(rb'[A-Za-z0-9][A-Za-z0-9_.:/@?&=%+,#~-]{0,199}')   # một dòng cấu hình: URL, tên miền, IP, khóa=giá trị; không khoảng trắng
LOOKUP_LINES = 10
def lookup_issue(base, full):
    """Evidence lookup_* (tra cứu thụ động) theo DANH SÁCH CHO PHÉP: thân trả về (sau dòng '--- body ---', không có dòng đó thì cả file) chỉ gồm tối đa 10 dòng,
    tổng ≤ 2 KiB, mỗi dòng là một token cấu hình (URL, tên miền, IP, khóa=giá trị; không khoảng trắng, ≤ 200 ký tự). Còn rủi ro nhỏ: một mảnh dữ liệu mã hóa dưới 2 KiB vẫn qua. Mọi thứ khác (script, base64, hex, JSON dài, nhị phân)
    đi vào work/extract (export đóng 7z), evidence chỉ giữ sha256, kích thước, content-type và trích đoạn. Dùng chung cho lint và cổng phản biện."""
    if not base.lower().startswith('lookup_'): return None
    raw = open(full, 'rb').read().replace(b'\r\n', b'\n'); head, _, body = raw.partition(LOOKUP_SEP) if LOOKUP_SEP in raw else (b'', b'', raw)
    hl = [x for x in head.split(b'\n') if x.strip()]   # phần đầu chỉ là metadata ngắn: lệnh, URL, thời điểm, mã trạng thái
    if len(hl) > 6 or len(head) > 1024 or any(len(x) > 300 or x.lstrip().startswith(b'#!') or re.search(rb'[|;`$]', x) for x in hl) or re.search(rb'[^\x20-\x7e\n\r\t]', head):
        return (f'phần đầu lookup_* ({len(head)} B, {len(hl)} dòng) không phải metadata ngắn: tối đa 6 dòng, 1 KiB, ASCII in được, không shebang, không ký tự | ; ` $',
                'phần đầu chỉ ghi lệnh, URL, thời điểm UTC, mã trạng thái; nội dung trả về đặt sau dòng --- body --- hoặc ở work/extract/')
    lines = [x.rstrip(b'\r') for x in body.split(b'\n') if x.strip(b'\r')]
    if len(body) > LOOKUP_MAX or len(lines) > LOOKUP_LINES or not all(LOOKUP_LINE.fullmatch(x) for x in lines):
        return (f'thân lookup_* ({len(body)} B, {len(lines)} dòng) không phải cấu hình ngắn: chỉ nhận tối đa {LOOKUP_LINES} dòng, mỗi dòng một token (URL, tên miền, IP, khóa=giá trị) không khoảng trắng',
                'thân thật lưu ở work/extract/ (0400); lookup_*.txt chỉ giữ sha256, kích thước, content-type và trích đoạn ngắn đã lọc (RDAP/API: jq lấy trường cần). Thân giống payload thì dừng hỏi người dùng')
def src_evidence_issue(src, base):
    """Luật nguồn/evidence dùng chung cho lint khi ghi và lớp 1 của cổng phản biện. Trả (vấn đề, cách sửa) hoặc None.
    host_*: quan sát trên máy thật do người thu mẫu cung cấp (ảnh chụp, log), không do phiên phân tích chạy mẫu."""
    if src == 'S' and base.startswith(('emu_', 'vm_', 'host_')): return 'src=S nhưng evidence sinh từ giả lập/VM/quan sát máy thật', 'đổi src hoặc dẫn evidence tĩnh'
    if base.lower().startswith('lookup_') and src != 'S': return 'evidence lookup_* là tra cứu thụ động bên ngoài (không phải giả lập/VM) nhưng src khác S', 'ghi src=S, note nêu tra cứu thụ động và ngày tra'
    if src == 'V' and not base.startswith(('vm_', 'host_')): return 'src=V nhưng evidence không phải kết quả VM hay quan sát máy thật', 'dẫn evidence vm_* / host_* hoặc đổi src'

def work_files(case, dirs=('sample', 'extract'), limit=64 << 20):
    """File thường trong work/<dirs>, đã sắp xếp. Không theo symlink: cả file lẫn thư mục link (glob '**' đi vào thư mục link, os.walk thì không),
    vì mẫu không tin cậy có thể có link trỏ ra file của máy phân tích."""
    return [p for d in dirs for p in sorted(os.path.join(r, n) for r, _, ns in os.walk(os.path.join(case, 'work', d)) for n in ns)   # thứ tự theo dirs: sample trước extract
            if os.path.isfile(p) and not os.path.islink(p) and os.path.getsize(p) < limit]

def _work_hashes(case): return {hashlib.sha256(open(p, 'rb').read()).hexdigest() for p in work_files(case)}

def ev_scope(lines, f):
    """(scope, anchor) để so value với evidence: có `#L` hợp lệ thì ±WINDOW dòng quanh dòng đó (theo vị trí mới nếu dòng đã dời), không thì cả file.
    Văn bản đã qua _normnum, gộp `\\\\`, chữ thường. MỘT luật cho lint khi ghi (lint_fact) và lớp 1 của cổng (review.mech)."""
    norm = lambda L: _normnum('\n'.join(L)).replace('\\\\', '\\').lower()
    m = re.search(r'#L(\d+)$', f['evidence'])
    if not m: return norm(lines), None
    ln = int(m.group(1)); moved = _relocate(lines, ln, f.get('ev_line'))
    if moved is None and not 1 <= ln <= len(lines): return norm(lines), None
    ln = moved or ln
    return norm(lines[max(0, ln - 1 - WINDOW): ln + WINDOW]), ln

def literal_issue(f, full, scope, anchor):
    """Fact kind chữ (LITERAL_KINDS): ít nhất một token của value phải có trong scope. Trả (level, problem, redo) hoặc None.
    Evidence nhị phân (khóa, blob) không so được token: chỉ 'warn' khi value không ghi sha256 của file."""
    if f['kind'] not in LITERAL_KINDS or f['value'].startswith('n/a'): return None
    toks = [t.strip('.,;:)(\'"`').lower() for t in TOKEN.findall(f['value'].replace('\\\\', '\\'))]
    toks = [t for t in toks if len(t) >= 5 and not t.isdigit()]
    if not toks or any(t in scope or _normnum(t) in scope for t in toks): return None   # scope đã qua _normnum (bỏ dấu ngăn nghìn): IP như 10.20.300.4 bị đổi dạng
    if b'\0' in open(full, 'rb').read(4096):
        if hashlib.sha256(open(full, 'rb').read()).hexdigest() in f['value'].lower(): return None
        return ('warn', 'evidence nhị phân: không so được token; value nên ghi sha256 của file evidence', 'ghi sha256 của file vào value hoặc dẫn evidence dạng text')
    where = f'±{WINDOW} dòng quanh #L{anchor}' if anchor else 'file evidence'
    return ('fail', f'không token nào của value xuất hiện trong {where}',
            'chép đoạn chứa giá trị vào evidence, hoặc chỉnh #L/nới WINDOW' if anchor else 'chép đoạn chứa giá trị vào evidence hoặc sửa giá trị')

def lint_fact(case, f):
    """Kiểm tra lớp 1 ngay khi ghi fact. Trả list {level, check, problem, redo}.
    level 'fail' = mâu thuẫn rõ; 'warn' = nên sửa nhưng chưa chắc sai."""
    out = []
    def bad(level, check, problem, redo): out.append(dict(level=level, check=check, problem=problem, redo=redo))
    if f['kind'] == 'verdict' and not VERDICT_RX.match(f['value'].strip()):
        bad('fail', 'verdict_value', f"verdict phải là '{'|'.join(k for k in VERDICT if k != 'unknown')}: lý do', có: {f['value'][:60]}",
            "ghi lại value='malicious: <lý do>' (hoặc suspicious/nofind/benign)")
    ei = env_issue(f)
    if ei: bad('fail', 'env_value', *ei)
    if f['kind'] == 'relation' and f['value'].startswith('n/a') and not re.match(r'n/a:\s*\S', f['value']):
        bad('warn', 'relation_na', "fact relation 'n/a' phải kèm lý do: 'n/a: lý do'", "ghi value='n/a: <vì sao không thấy liên hệ>'")
    if f['kind'] == 'relation' and not f['value'].startswith('n/a') and not RELATION_RX.match(f['value']):
        bad('warn', 'relation_level', "fact relation phải mở đầu bằng mức nhận định: " + ' | '.join(RELATION) + " rồi ': căn cứ'", "ví dụ value='context: cùng thiết bị nhưng không có định danh chéo, khác hạ tầng' (ý nghĩa từng mức: FLOW.md mục C12)")
    if f['kind'] == 'relation' and not f['value'].startswith('n/a'):
        src_ = sources(case)   # so theo tên tệp (bỏ thư mục cha), thư mục thì theo tên thư mục
        named = [n for n in src_ if re.search(r'(?<![\w.])' + re.escape(os.path.basename(n.rstrip('/'))) + r'(?![\w])', f['value'])]
        if len(src_) >= 2 and len(named) < 2:
            bad('warn', 'relation_samples', f"fact relation nên nêu tên ít nhất hai mẫu của case ({', '.join(src_[:6])}); đang nêu {len(named)}", 'ghi rõ quan hệ giữa mẫu nào với mẫu nào')
    rel, full = ev_path(case, f['evidence'])
    if not os.path.isfile(full):
        bad('fail', 'evidence_exists', f'file evidence không tồn tại: {rel}', 'chép bằng chứng vào report/evidence/')
        return out
    if ev_has_link(case, rel):   # phiên phản biện chép workspace bỏ symlink (file hoặc thư mục cha) nên sẽ không thấy file này
        bad('fail', 'evidence_exists', f'evidence nằm trong/là symlink: {rel}', 'chép nội dung thật vào report/evidence/ thay vì liên kết')
        return out
    lines = open(full, encoding='utf-8', errors='replace').read().splitlines()
    whole = _normnum('\n'.join(lines)).replace('\\\\', '\\').lower()
    base = os.path.basename(rel)
    sv = src_evidence_issue(f['src'], base)
    if sv: bad('fail', 'src_vs_evidence', *sv)
    li = lookup_issue(base, full)
    if li: bad('fail', 'lookup_content', *li)
    for ck, pb, rd in adhoc.issues(case, f, rel, '\n'.join(lines)): bad('fail', ck, pb, rd)   # evidence của công cụ tự viết: phải tự kiểm đạt, công cụ chưa đổi
    for ck, pb, rd in adhoc.notes(case, f, rel, '\n'.join(lines)): bad('warn', ck, pb, rd)    # chạy không trong vỏ không mạng: cảnh báo
    scope, anchor = ev_scope(lines, f)   # cùng hàm với lớp 1 của cổng
    m = re.search(r'#L(\d+)$', f['evidence'])
    if m:
        ln = int(m.group(1)); moved = _relocate(lines, ln, f.get('ev_line')); inside = 1 <= ln <= len(lines)
        if not inside and moved is None:
            bad('fail', 'evidence_line', f'dòng {ln} vượt quá file ({len(lines)} dòng)' if ln > len(lines) else f'#L{ln} không hợp lệ (dòng tính từ 1)', 'trỏ đúng dòng chứa bằng chứng')
        else:
            if moved is None: bad('warn', 'evidence_moved', f'nội dung dòng {ln} đã đổi so với lúc ghi fact và không tìm thấy dòng cũ trong file', 'kiểm lại bằng chứng, ghi fact mới (supersedes) trỏ đúng dòng')
            elif moved != ln:
                bad('warn', 'evidence_moved', f'dòng bằng chứng đã dời từ #L{ln} sang #L{moved} (evidence bị sửa sau khi ghi fact); đang kiểm theo dòng mới', f'ghi fact mới (supersedes) trỏ #L{moved}, hoặc chỉ thêm vào CUỐI file evidence')
    elif len(lines) > LOG_LINES and rel.lower().endswith(('.txt', '.log')):
        bad('warn', 'evidence_scope', f'evidence dài {len(lines)} dòng: dẫn cả file nên không neo được đoạn chứng minh',
            'thêm #L<dòng> hoặc tách đoạn trích vào file riêng')
    if f['kind'] in ('hash', 'payload_hash'):
        hs = None
        for h in re.findall(r'\b[0-9a-f]{64}\b', f['value']):
            if h in whole: continue
            hs = hs if hs is not None else _work_hashes(case)
            if h not in hs:
                bad('fail', 'hash_recompute', f'sha256 {h[:12]}… không có trong evidence và không khớp file nào trong work/sample|extract',
                    'tính lại sha256 từ file gốc rồi chép vào evidence')
    else:
        vi = literal_issue(f, full, scope, anchor)
        if vi: bad(vi[0], 'value_in_evidence', *vi[1:])
        em = env_missing(f, scope)
        if em: bad('fail', 'value_in_evidence', f"fact env: {len(em)} chuỗi không có nguyên văn trong {f'±{WINDOW} dòng quanh #L{anchor}' if anchor else 'file evidence'}: " + ', '.join(repr(x)[:40] for x in em[:4]),
                   'tham số chạy mẫu phải có căn cứ: chép đoạn chứa đúng từng giá trị vào evidence (cùng đoạn với #L), hoặc bỏ giá trị không có căn cứ')
    for p, r in recompute(case, f): bad('fail', 'recompute', p, r)
    miss = [n for n in NUMTOK.findall(_normnum(DATE.sub(' ', f['value']))) if n.lower() not in scope]
    if miss:
        bad('warn', 'number_in_evidence', f'số {", ".join(miss[:5])} không có trong evidence',
            'đưa output script chứa đúng con số vào evidence, hoặc sửa số')
    return out

RECOMPUTE = re.compile(r'^(count|distinct)\s+(.+?)\s+(\S+)\s*=\s*(\d+)$')

def recompute(case, f):
    """Chạy lại các phép đếm trong f['recompute']. Trả list (problem, redo) cho mỗi phép sai; rỗng nếu khớp hoặc không có."""
    out, val = [], _normnum(f['value'])
    for spec in filter(None, (s.strip() for s in (f.get('recompute') or '').split(' && '))):
        m = RECOMPUTE.match(spec)
        if not m: out.append((f'cú pháp recompute sai: {spec}', "viết '<count|distinct> <regex> report/evidence/F[#La-Lb] = N'")); continue
        op, rx, ev, n = m.groups()
        rel, full = ev_path(case, ev)
        if not rel.startswith(EV) or not os.path.isfile(full): out.append((f'recompute trỏ tới file không có trong {EV}: {rel}', 'chép output vào evidence')); continue
        if ev_has_link(case, rel): out.append((f'recompute trỏ tới evidence là/nằm trong symlink: {rel}', 'chép nội dung thật vào report/evidence/ (phiên phản biện không thấy link)')); continue
        try: R = re.compile(rx)
        except re.error as e: out.append((f'regex lỗi trong recompute: {e}', 'sửa regex')); continue
        L = open(full, encoding='utf-8', errors='replace').read().splitlines()
        r = re.search(r'#L(\d+)(?:-L?(\d+))?$', ev)
        if r: L = L[int(r.group(1)) - 1:int(r.group(2) or r.group(1))]
        got = sum(1 for l in L if R.search(l)) if op == 'count' else \
              len({(x.group(1) if R.groups else x.group(0)) for l in L for x in R.finditer(l)})
        if got != int(n): out.append((f'{op} {rx} trên {ev} ra {got}, fact ghi {n}', f'sửa con số trong value thành {got} (và recompute) hoặc sửa phép đếm'))
        elif not re.search(rf'(?<![\d.]){n}(?![\d])', val): out.append((f'value không chứa con số {n} của recompute', 'ghi con số bằng chữ số trong value'))
    return out

def ev_path(case, ev):
    rel = os.path.normpath(ev.split('#')[0])
    return rel, os.path.join(case, rel)

def ev_has_link(case, rel):
    """True nếu evidence (đường dẫn rel tính từ case) đi qua symlink ở bất kỳ cấp nào, kể cả thư mục cha: phiên phản biện chép workspace bỏ link nên không thấy file."""
    p = case
    for part in rel.split(os.sep):
        p = os.path.join(p, part)
        if os.path.islink(p): return True
    return False

def add(case, strict=False, lint=False, **f):
    for k in ('id', 'kind', 'value', 'src', 'evidence'):
        if not f.get(k): raise ValueError(f'thiếu {k}')
    if f['kind'] not in KINDS: raise ValueError(f'kind lạ: {f["kind"]} (thêm vào KINDS nếu thật sự cần)')
    if f['src'] not in ('S', 'E', 'V'): raise ValueError('src phải là S, E hoặc V')
    f.setdefault('status', 'active')
    if f['status'] not in ('active', 'hypothesis', 'retracted'): raise ValueError('status lạ')
    rel, full = ev_path(case, f['evidence'])
    if not rel.startswith(EV): raise ValueError(f'evidence phải nằm trong {EV}: {rel}')
    if not os.path.isfile(full): raise ValueError(f'evidence không tồn tại: {rel}')
    vb = f.get('verified_by') or [f['src']]
    f['verified_by'] = sorted(set(vb.split(',') if isinstance(vb, str) else vb))
    f.setdefault('supersedes', None); f.setdefault('stage', ''); f.setdefault('note', '')
    f['ts'] = datetime.datetime.now().isoformat(timespec='seconds')
    m = re.search(r'#L(\d+)$', f['evidence'])
    f.pop('ev_line', None)   # dấu vân tay luôn tính từ file evidence, không nhận giá trị người gọi truyền vào
    if m:   # dấu vân tay dòng được trỏ: lint tìm lại được dòng khi evidence bị chèn dòng về sau
        try:
            ls = open(full, encoding='utf-8', errors='replace').read().splitlines(); n = int(m.group(1))
            if 1 <= n <= len(ls): f['ev_line'] = _line_id(ls[n - 1])
        except OSError: pass
    issues = lint_fact(case, f) if lint else []
    fails = [i for i in issues if i['level'] == 'fail']
    if strict and fails:
        raise ValueError('lint từ chối fact: ' + '; '.join(f"{i['check']}: {i['problem']}" for i in fails))
    p = os.path.join(case, 'facts.jsonl')
    with open(p, 'ab') as fh:   # chỉ nối thêm; dòng cuối bị cụt (thiếu \n) thì xuống dòng trước để fact mới không dính vào mảnh cụt
        if os.path.getsize(p):
            with open(p, 'rb') as r: r.seek(-1, 2); last = r.read(1)
            if last != b'\n': fh.write(b'\n')
        fh.write((json.dumps(f, ensure_ascii=False) + '\n').encode('utf-8'))
    for i in issues:
        print(f"lint {i['level']}: {i['check']}: {i['problem']} -> {i['redo']}")

_CUT_WARNED = set()

def history(case):
    """Mọi dòng của facts.jsonl theo thứ tự ghi. Dòng bị cụt do tiến trình bị giết giữa lúc ghi (bắt đầu bằng `{` nhưng JSON không
    trọn) thì bỏ qua và cảnh báo một lần; dòng hỏng kiểu khác (sửa tay) thì báo lỗi kèm số dòng, không im lặng bỏ."""
    p = os.path.join(case, 'facts.jsonl')
    if not os.path.exists(p): return []
    out = []
    for i, l in enumerate(open(p, encoding='utf-8', errors='replace'), 1):
        if not l.strip(): continue
        try: out.append(json.loads(l))
        except ValueError:
            t = l.strip()
            if not (t.startswith('{') and not t.endswith('}')):   # bắt đầu bằng { mà vẫn hỏng: có thể là dòng cụt tình cờ dừng sau một } trong chuỗi
                raise ValueError(f'{p}:{i}: dòng không phải JSON (sửa tay?' + (' hoặc dòng cụt: xóa dòng này rồi ghi lại fact đó' if t.startswith('{') else '') + f'): {t[:80]}')
            if (p, i) not in _CUT_WARNED:
                _CUT_WARNED.add((p, i)); print(f'CẢNH BÁO {p}:{i}: dòng fact bị cụt (tiến trình bị giết lúc ghi), bỏ qua; ghi lại fact đó nếu cần', file=sys.stderr)
    return out

# Nhận định quan hệ giữa các mẫu (kind=relation): value = '<mức>: căn cứ'. Mức dựa trên KẾT QUẢ DỊCH NGƯỢC, không dựa riêng vào bối cảnh thu mẫu.
RELATION = {'direct': 'liên hệ kỹ thuật trực tiếp (mẫu này tham chiếu, khởi chạy, tải hay cấu hình mẫu kia; chung C2, khóa hoặc giao thức riêng)',
            'shared': 'chung mã hoặc hạ tầng nhưng không tham chiếu nhau (cùng họ/builder, chuỗi hay đặc trưng riêng trùng nhau)',
            'context': 'chỉ có bối cảnh thu mẫu (cùng thiết bị, thời điểm gần, người thu mẫu nghi); dịch ngược không thấy liên hệ kỹ thuật',
            'unrelated': 'dịch ngược cho thấy không liên quan (khác tác giả, hạ tầng, mục đích); trùng bối cảnh là ngẫu nhiên'}
RELATION_RX = re.compile(r'(direct|shared|context|unrelated)\s*:\s*\S')

def sources(case):
    """Tên các mẫu người dùng đưa vào `flow.py new` (work/sources.json). Case cũ không có file này: danh sách rỗng."""
    try: L = json.load(open(os.path.join(case, 'work', 'sources.json'), encoding='utf-8'))
    except (OSError, ValueError): return []
    return [str(x) for x in L] if isinstance(L, list) else []

def add_sources(case, names):
    """Gộp tên mẫu vào work/sources.json (mỗi mục ở gốc work/sample; thư mục kết thúc bằng /), giữ thứ tự cũ, không lặp."""
    p = os.path.join(case, 'work', 'sources.json'); cur = sources(case)
    out = cur + [n for n in dict.fromkeys(names) if n and n not in cur]
    if out and (out != cur or not os.path.exists(p)):
        os.makedirs(os.path.dirname(p), exist_ok=True)
        json.dump(out, open(p, 'w', encoding='utf-8'), ensure_ascii=False)
    return out

def mode(case):
    """'light' (mẫu đơn giản: chỉ tầng tĩnh, không giả lập/công cụ ad-hoc/V8) hoặc 'full'. Cổng phản biện giống nhau ở cả hai."""
    try: m = json.load(open(os.path.join(case, 'work', 'mode.json'), encoding='utf-8')).get('mode')
    except (OSError, ValueError, AttributeError): return 'full'
    return m if m in ('light', 'full') else 'full'

def set_mode(case, m):
    os.makedirs(os.path.join(case, 'work'), exist_ok=True)
    json.dump({'mode': m}, open(os.path.join(case, 'work', 'mode.json'), 'w', encoding='utf-8'))

def load(case):
    cur = {}
    for f in history(case): cur[f['id']] = f
    for f in list(cur.values()):           # fact bị thay thế thì không còn hiệu lực
        if f.get('supersedes') in cur: cur[f['supersedes']] = dict(cur[f['supersedes']], status='retracted')
    return cur

def review_status(case):
    """C0: kết quả cổng phản biện (review.py). ok = review cuối PASS khớp hash facts.jsonl hiện tại."""
    sp = os.path.join(case, 'work', 'review', 'state.json')
    if not os.path.exists(sp) or not os.path.exists(os.path.join(case, 'facts.jsonl')): return 'missing'
    s = json.load(open(sp)); cur = hashlib.sha256(open(os.path.join(case, 'facts.jsonl'), 'rb').read()).hexdigest()
    ov = os.path.join(case, 'work', 'review', 'OVERRIDE')
    if os.path.exists(ov) and f'facts_sha256={cur}' in open(ov).read(): return 'ok(override)'
    if s.get('rule_version') != REVIEW_RULE_VERSION: return 'missing'   # state theo luật cũ: phải review lại
    if s.get('stopped') and s.get('reset_for') == cur: return 'fail(stopped)'
    last = s['rounds'][-1] if s['rounds'] else None
    if not last or last['facts_sha256'] != cur: return 'missing'     # review đã cũ: facts đổi sau lần review cuối
    return ('partial' if last.get('weak') else 'ok') if last['verdict'] == 'PASS' else 'partial'

def check(case, shown=None):   # shown: chữ điền vào chỗ CASE trong gợi ý (HTML dùng tên case để không lộ đường dẫn máy)
    F = [f for f in load(case).values() if f['status'] != 'retracted']
    act = lambda *ks: [f for f in F if f['kind'] in ks and f['status'] == 'active']
    hyp = lambda *ks: [f for f in F if f['kind'] in ks and f['status'] == 'hypothesis']
    exits = act('exit_reason')   # mọi tiến trình phải thoát tự nhiên; 'stop_at'/lỗi giả lập nghĩa là còn phần chưa chạy tới
    natural = exits and all(NATURAL_RX.match(f['value']) for f in exits)
    unused = ' '.join(f['value'] for f in act('api_unused'))
    # độ phủ: giả lập chạy tới exit tự nhiên (E), hoặc fact 'coverage' khẳng định đã duyệt tĩnh hết các hàm dùng API nhạy cảm (S)
    # dec_coverage hợp lệ: 'a/b' (số chuỗi đã giải / số call-site của hàm giải mã) hoặc 'n/a: lý do' (không có hàm giải mã); chữ tự do không tính
    cov = [tuple(map(int, f['value'].split('/'))) for f in act('dec_coverage') if re.fullmatch(r'\d+/\d+', f['value'])]
    na = lambda v: re.match(r'n/a:\s*\S', v)   # 'n/a: lý do': phải có lý do sau dấu hai chấm
    # n/a của dec_coverage chỉ hợp lệ khi không có thuật toán giải mã (mọi str_algo cũng n/a); có thuật toán thì phải đo a/b, cho cả C4 lẫn C11
    dec_na = any(na(f['value']) for f in act('dec_coverage')) and bool(act('str_algo')) and all(na(f['value']) for f in act('str_algo'))
    c11 = 'ok' if (natural and act('api_unused') and (cov or dec_na)) or act('coverage') else \
          'partial' if act('exit_reason', 'api_unused') else 'missing'
    gate = lambda has: ('ok' if c11 == 'ok' else 'partial') if has else 'missing'
    R = {
        'C0 Phản biện': review_status(case),
        'C1 Nhận dạng': 'ok' if act('hash') and act('filetype') else 'partial' if act('hash', 'filetype') else 'missing',
        'C2 Delivery và điểm vào': 'ok' if act('container') and act('entry') else 'partial' if act('container', 'entry') else 'missing',
        'C3 Chống phân tích': gate(act('anti_analysis')),
        'C4 Giải mã chuỗi/config': ('ok' if (all(a >= b for a, b in cov) if cov else dec_na) else 'partial') if act('str_algo') and act('str_key')
                                   else 'partial' if act('str_algo', 'str_key') else 'missing',
        'C5 IOC mạng': gate(act('url', 'c2', 'ua')),
        'C6 Tiêm mã': 'ok' if act('inject') and not hyp('inject') else 'partial' if act('inject') or hyp('inject') else 'missing',
        'C7 Persistence': 'ok' if act('persistence') else 'partial' if PERSIST_API.search(unused) or hyp('persistence') or c11 != 'ok'
                          else 'n/a(không thấy, giả lập đã chạy hết)',
        'C8 Payload: định dạng và khóa': ('ok' if act('payload_hash') else 'partial') if act('payload_fmt') and act('payload_key')
                                         else 'partial' if act('payload_fmt', 'payload_key') else 'missing',
        'C9 Payload cuối': 'ok' if act('payload_hash') else 'missing',
        'C10 Họ mã độc': 'ok' if act('family') else 'partial' if hyp('family') else 'missing',
        'C11 Độ phủ': c11,
        # C12 đạt khi có NHẬN ĐỊNH dựa trên dịch ngược: fact relation active, nguồn S hoặc E, mở đầu bằng mức (direct|shared|context|unrelated), hoặc 'n/a: lý do'.
        # Fact nguồn V (lời người thu mẫu về bối cảnh) và fact chưa nêu mức chỉ là dữ liệu đầu vào: chưa đủ.
        'C12 Quan hệ giữa các mẫu': 'n/a(một mẫu)' if len(sources(case)) < 2 else 'ok' if any((RELATION_RX.match(f['value']) and f['src'] in ('S', 'E')) or na(f['value']) for f in act('relation'))
                                    else 'partial' if hyp('relation') or act('relation') else 'missing',   # relation 'n/a' không kèm ': lý do' chưa đủ
    }
    NEXT = {'C0': 'flow.py review CASE [--llm] (tối đa 2 lần); stopped thì đọc work/review/STOP_REPORT.md', 'C1': 'T0 flow.py triage', 'C2': 'T0/T1 bóc vỏ; ghi entry (hàm/offset bắt đầu mã độc)',
            'C3': 'T2 tìm anti-debug/anti-VM quanh import nhạy cảm; T3 nếu chạy được',
            'C4': 'T2 tìm hàm giải mã chuỗi/config (xref chuỗi rác, vòng XOR); hoặc fact n/a nếu chuỗi rõ',
            'C5': 'T2 xref các hàm mạng và ioc_candidates trong report/evidence/triage_*.json (ứng viên chưa phải fact); T3 nếu chạy được', 'C6': 'T2/T3: CreateProcess/WriteProcessMemory/ptrace/LD_PRELOAD; hoặc n/a',
            'C7': 'T2: registry/service/cron/systemd/rc.local/ghi file hệ thống; hoặc n/a', 'C8': 'T3 --fake-dl rồi T4; hoặc n/a nếu không tải payload',
            'C9': 'T4 (cần payload thật) hoặc n/a', 'C10': 'đối chiếu kỹ thuật/chuỗi với họ đã biết; T4 + T0 trên payload',
            'C11': 'E: giả lập tới exit tự nhiên; S: fact coverage liệt kê đã duyệt mọi xref của import nhạy cảm',
            'C12': "flow.py link CASE (đối chiếu chéo các mẫu); sau khi dịch ngược từng mẫu, ghi NHẬN ĐỊNH: fact relation src=S value='direct|shared|context|unrelated: căn cứ từ dịch ngược' (active khi có bằng chứng, mức mạnh hơn chưa chứng minh thì hypothesis); bối cảnh do người thu mẫu cung cấp ghi riêng src=V"}
    FACT = {'C1': 'hash, filetype', 'C2': 'container, entry', 'C3': 'anti_analysis', 'C4': "str_algo, str_key, dec_coverage dạng 'a/b' (có hàm giải mã) hoặc 'n/a: lý do' (chỉ khi mọi str_algo cũng 'n/a: lý do')",
            'C5': 'c2 | url | ua', 'C6': 'inject', 'C7': 'persistence', 'C8': 'payload_fmt, payload_key, payload_hash', 'C9': 'payload_hash', 'C10': 'family',
            'C11': "coverage (S) hoặc exit_reason natural + api_unused + dec_coverage dạng 'a/b' hoặc 'n/a: lý do' như C4 (E)",
            'C12': 'relation active, src S/E, mở đầu bằng mức direct|shared|context|unrelated, nêu tên các mẫu'}   # kind cần ghi để mục đạt ok; không áp dụng: value='n/a: lý do'
    q = shlex.quote(case if shown is None else shown)
    hint = lambda k: NEXT[k].replace('CASE', q) + (f' [fact: {FACT[k]}]' if k in FACT else '')
    return [(k, v, '' if v == 'ok' or v.startswith('n/a') else hint(k.split()[0])) for k, v in R.items()]

def sha(p): return hashlib.sha256(open(p, 'rb').read()).hexdigest()

RPT = re.compile(r'^report-(\d{4}-\d{2}-\d{2})\.md$')

def report_md(case):
    """Báo cáo viết tay: report/report-<ngày phân tích>.md (nhiều bản thì lấy ngày mới nhất). Case tạo trước khi đổi tên: report/README.md."""
    d = os.path.join(case, 'report')
    L = sorted(n for n in (os.listdir(d) if os.path.isdir(d) else []) if RPT.match(n))
    return os.path.join(d, L[-1] if L else 'README.md')

def analysis_date(case, txt=''):
    """Ngày phân tích: dòng 'Ngày bắt đầu:' của báo cáo, không có thì ngày của fact đầu tiên, không có nữa thì hôm nay."""
    m = re.search(r'Ngày bắt đầu:\s*(\d{4}-\d{2}-\d{2})', txt)
    ts = [h['ts'][:10] for h in history(case) if re.match(r'\d{4}-\d{2}-\d{2}', str(h.get('ts', '')))]
    return m.group(1) if m else min(ts) if ts else datetime.date.today().isoformat()

def migrate_report(case):
    """Đổi report/README.md của case cũ thành report/report-<ngày phân tích>.md (một lần). Trả đường dẫn mới, hoặc None nếu không cần."""
    old = os.path.join(case, 'report', 'README.md')
    if not os.path.isfile(old) or report_md(case) != old: return None
    new = os.path.join(case, 'report', f"report-{analysis_date(case, open(old, encoding='utf-8', errors='replace').read())}.md")
    os.rename(old, new); return new

def report_html(case):
    m = RPT.match(os.path.basename(report_md(case)))
    return os.path.join(case, 'report', f"report-{m.group(1) if m else analysis_date(case)}.html")

def ev_files(case):
    root = os.path.join(case, EV)
    return sorted(os.path.relpath(os.path.join(d, n), root) for d, _, ns in os.walk(root) for n in ns)

def report(case):
    cur, H = load(case), history(case)
    vd = verdict(case, cur)
    L = ['<!-- Sinh tự động bởi rea-workflow case.py report: không sửa tay, sửa facts.jsonl rồi chạy lại -->', '', verdict_line(vd), '', '## IOC', '',
         '| Loại | Giá trị | Nguồn | Evidence |', '|---|---|---|---|']
    L += [f"| {f['kind']} | `{f['value']}` | {'+'.join(f['verified_by'])} | `{f['evidence']}` |"
          for k in IOC_KINDS for f in cur.values() if f['kind'] == k and f['status'] == 'active']
    L += ['', '## Phát hiện theo nguồn (S tĩnh, E giả lập CPU, V VM)', '', '| id | Loại | Trạng thái | Nguồn | Kiểm chứng chéo | Ghi chú |', '|---|---|---|---|---|---|']
    L += [f"| {f['id']} | {f['kind']} | {f['status']} | {f['src']} | {'có' if len(f['verified_by']) > 1 else 'không'} | {f['note']} |"
          for f in cur.values() if f['status'] != 'retracted']
    L += ['', '## Đính chính', '', '| id | Trước | Sau |', '|---|---|---|']
    prev = {}
    for f in H:
        p = prev.get(f['id'])
        if p and (p['value'], p['status']) != (f['value'], f['status']):
            L.append(f"| {f['id']} | {p['value']} ({p['status']}) | {f['value']} ({f['status']}) |")
        if f.get('supersedes') in prev:
            o = prev[f['supersedes']]; L.append(f"| {o['id']} → {f['id']} | {o['value']} | {f['value']} |")
        prev[f['id']] = f
    i0 = L.index('## Đính chính') + 4; L[i0:] = list(dict.fromkeys(L[i0:]))   # một fact supersede được ghi lại nhiều lần -> một dòng
    refs = {ev_path(case, f['evidence'])[0][len(EV):] for f in cur.values()}
    L += ['', '## Evidence trên đĩa', '', '| File | Byte | sha256 | Fact tham chiếu |', '|---|---|---|---|']
    L += [f"| `{r}` | {os.path.getsize(os.path.join(case, EV, r))} | `{sha(os.path.join(case, EV, r))[:16]}…` | {'có' if r in refs else '—'} |"
          for r in ev_files(case)]
    open(os.path.join(case, 'report', 'GENERATED.md'), 'w', encoding='utf-8').write('\n'.join(L) + '\n')
    import htmlreport, review   # bản HTML gộp báo cáo viết tay + bảng sinh từ fact + checklist: chỉ để xem, nguồn vẫn là .md và facts.jsonl
    rm, name = report_md(case), os.path.basename(os.path.abspath(case)); body = open(rm, encoding='utf-8', errors='replace').read() if os.path.isfile(rm) else ''
    F = list(cur.values()); n = {s: sum(f['status'] == s for f in F) for s in ('active', 'hypothesis', 'retracted')}
    m = RPT.match(os.path.basename(rm)); gate = review.gate(case); todo = review.report_todo(case) if gate[0] else []
    if todo: gate = (False, 'báo cáo viết tay chưa nhắc fact đã sửa: ' + ', '.join(x['id'] for x in todo))   # cùng điều kiện chặn report --final
    blank = review.report_blank(case) if gate[0] else []
    if blank: gate = (False, f'báo cáo viết tay còn {len(blank)} dòng giữ chỗ của template')   # cùng điều kiện chặn report --final
    acc = review.accepted(case)   # mục chưa đạt nhưng đã chấp nhận là hạn chế (next --accept): hiện lý do thay cho việc còn lại
    rows = [(k, f'chấp nhận: {v}', 'Hạn chế đã chấp nhận: ' + acc[k.split()[0]]) if k.split()[0] in acc and k.split()[0] != 'C0'
            and not (v == 'ok' or v.startswith('n/a')) else (k, v, h) for k, v, h in check(case, shown=name)]
    open(report_html(case), 'w', encoding='utf-8').write(htmlreport.render(   # ngày và tên nguồn theo đúng file báo cáo đang dùng
        name, m.group(1) if m else analysis_date(case, body), body, '\n'.join(L), rows,   # file HTML để chia sẻ: gợi ý điền tên case, không lộ đường dẫn máy
        dict(n, ioc=sum(f['kind'] in IOC_KINDS and f['status'] == 'active' for f in F), evidence=len(ev_files(case))), gate, os.path.basename(rm), vd))
    return L

def audit(case):
    """Mục Evidence của báo cáo (report_md) phải khớp đĩa; fact không được trỏ tới file mất."""
    problems, disk = [], ev_files(case)
    rm = report_md(case)
    if not os.path.isfile(rm): return [f'thiếu báo cáo {os.path.relpath(rm, case)} (report/report-<ngày phân tích>.md)']
    txt = open(rm, encoding='utf-8').read()
    m = re.search(r'^## [^\n]*Evidence[^\n]*\n(.*?)(?=^## |\Z)', txt, re.M | re.S)
    toks = {t for row in (m.group(1).splitlines() if m else []) if row.startswith('|')
            for t in re.findall(r'`([^`]+)`', row.split('|')[1])}
    names = {os.path.basename(t) for t in toks} | toks
    miss = [r for r in disk if r not in names and os.path.basename(r) not in names]
    if miss and m and any(re.search(r'(?<![\w.-])' + re.escape(os.path.basename(r)) + r'(?![\w-])', m.group(1)) for r in miss):      # tên có trong mục nhưng không ở dòng bảng: nói thẳng định dạng
        problems.append('báo cáo §Evidence chỉ nhận bảng Markdown: mỗi file một dòng `| `tên` | nội dung |` (tên trong cột đầu); danh sách văn xuôi không được tính')
    problems += [f'báo cáo thiếu: {r}' for r in miss]
    problems += [f'báo cáo có mà đĩa không có: {t}' for t in toks
                 if not any(r == t or os.path.basename(r) == os.path.basename(t) for r in disk)]
    problems += [f'fact {f["id"]} trỏ tới file mất: {f["evidence"]}' for f in load(case).values()
                 if not os.path.isfile(ev_path(case, f['evidence'])[1])]
    return problems

def selftest():
    import tempfile
    c = tempfile.mkdtemp(); os.makedirs(os.path.join(c, EV)); os.makedirs(os.path.join(c, 'work'))
    open(os.path.join(c, EV, 'a.log'), 'w').write('x'); open(os.path.join(c, 'work', 'b.log'), 'w').write('x')
    for bad in [dict(evidence=EV + 'nope.log'), dict(evidence='work/b.log'), dict(evidence=EV + '../../work/b.log'), dict(kind='lạ')]:
        try: add(c, **{**dict(id='x', kind='url', value='u', src='E', evidence=EV + 'a.log'), **bad}); raise AssertionError(bad)
        except ValueError: pass
    add(c, id='u1', kind='url', value='http://a', src='E', evidence=EV + 'a.log#L3')
    add(c, id='i1', kind='inject', value='hollowing', src='E', evidence=EV + 'a.log', status='hypothesis')
    add(c, id='k1', kind='payload_key', value='old', src='E', evidence=EV + 'a.log')
    add(c, id='k2', kind='payload_key', value='new', src='E', evidence=EV + 'a.log', supersedes='k1')
    add(c, id='u1', kind='url', value='http://a', src='E', evidence=EV + 'a.log', status='retracted')
    # recompute: đếm lại con số trong value; sai số hoặc thiếu số trong value -> fail
    open(os.path.join(c, EV, 'scan.txt'), 'w').write('host WIN-A ok\nhost WIN-B ok\nhost WIN-A fail\nnoise\n')
    rc = lambda v, r: [i['check'] for i in lint_fact(c, dict(id='n', kind='string', value=v, src='S', evidence=EV + 'scan.txt', recompute=r)) if i['level'] == 'fail']
    assert rc('2 máy WIN-*', r'distinct WIN-\w+ report/evidence/scan.txt = 2') == []
    assert rc('3 máy WIN-*', r'distinct WIN-\w+ report/evidence/scan.txt = 3') == ['recompute']          # thật ra 2
    assert rc('hai máy', r'distinct WIN-\w+ report/evidence/scan.txt = 2') == ['recompute']              # số phải viết bằng chữ số
    assert rc('2 dòng ok', r'count \bok$ report/evidence/scan.txt#L1-L2 = 2') == []
    assert rc('3 dòng ok', r'count ok report/evidence/scan.txt#L1-L2 = 3') == ['recompute']
    assert rc('1 x', 'count x /etc/passwd = 1') == ['recompute'] and rc('1 x', 'đếm x') == ['recompute']
    cur, ck = load(c), dict((k.split()[0], v) for k, v, _ in check(c))
    assert cur['u1']['status'] == 'retracted' and cur['k1']['status'] == 'retracted', cur
    assert ck['C5'] == 'missing' and ck['C6'] == 'partial' and ck['C8'] == 'partial' and ck['C11'] == 'missing', ck
    # C4/C11: dec_coverage chỉ tính dạng a/b hoặc n/a; có a/b thì a/b quyết định (a < b -> partial); chữ tự do không tính cho C11
    def ck2(*decs, emu=True):
        d = tempfile.mkdtemp(); os.makedirs(os.path.join(d, EV)); open(os.path.join(d, EV, 'e.log'), 'w').write('x')
        for i, (k, v) in enumerate([('str_algo', 'n/a: chuỗi rõ'), ('str_key', 'n/a: chuỗi rõ')] + ([('exit_reason', 'natural'), ('api_unused', 'RegSetValueExA')] if emu else [])
                                   + [('dec_coverage', x) for x in decs]):
            add(d, id=f'f{i}', kind=k, value=v, src='E', evidence=EV + 'e.log')
        r = dict((k.split()[0], v) for k, v, _ in check(d)); return r['C4'], r['C11']
    assert ck2('n/a: không có hàm giải mã') == ('ok', 'ok') and ck2('4/4') == ('ok', 'ok') and ck2('3/4') == ('partial', 'ok')
    assert ck2('đã decompile hết') == ('partial', 'partial') and ck2() == ('partial', 'partial') and ck2('n/a: x', '3/4') == ('partial', 'ok')
    assert ck2('n/a: không có hàm giải mã', emu=False) == ('ok', 'missing') and ck2('n/a') == ('partial', 'partial') and ck2('n/abc') == ('partial', 'partial')
    d = tempfile.mkdtemp(); os.makedirs(os.path.join(d, EV)); open(os.path.join(d, EV, 'e.log'), 'w').write('x')   # có thuật toán thật mà dec_coverage n/a: C4 không ok
    for i, (k, v) in enumerate([('str_algo', 'XOR 1 byte'), ('str_key', '0x5a'), ('dec_coverage', 'n/a: không đếm'), ('exit_reason', 'natural'), ('api_unused', 'x')]):
        add(d, id=f'g{i}', kind=k, value=v, src='E', evidence=EV + 'e.log')
    r = dict((k.split()[0], v) for k, v, _ in check(d)); assert (r['C4'], r['C11']) == ('partial', 'partial'), r
    add(d, id='g9', kind='str_algo', value='n/a', src='E', evidence=EV + 'e.log', supersedes='g0')   # 'n/a' trơn không phải 'n/a: lý do'
    r = dict((k.split()[0], v) for k, v, _ in check(d)); assert (r['C4'], r['C11']) == ('partial', 'partial'), r
    L = report(c)
    assert any('k1 → k2' in l for l in L) and any('| u1 | http://a (active) | http://a (retracted)' in l for l in L), L
    print('OK selftest')

if __name__ == '__main__':
    a = sys.argv[1:]
    if not a or a[0] == '--selftest': selftest(); sys.exit()
    cmd, case = a[0], a[1]
    if cmd == 'add':
        rest = a[2:]
        add(case, strict='--strict' in rest, lint=True,
            **dict(x.split('=', 1) for x in rest if not x.startswith('--'))); print('OK')
    elif cmd == 'show' and '--id' in a:   # một fact đầy đủ + lịch sử đính chính (recall sau khi ngữ cảnh bị nén)
        i = a[a.index('--id') + 1]; cur = load(case)
        if i not in cur: raise SystemExit(f'không có fact id={i}')
        print(json.dumps(cur[i], ensure_ascii=False, indent=1))
        for h in history(case):
            if h['id'] != i and h.get('supersedes') == i: print(f"bị thay bởi {h['id']} ({h['status']}): {h['value'][:160]}")
        old = [h for h in history(case) if h['id'] == i][:-1]
        if old: print(f'{len(old)} bản ghi cũ cùng id; bản cuối thắng')
    elif cmd == 'show':
        for f in load(case).values():
            if len(a) < 3 or f['kind'] == a[2]: print(f"{f['id']:<18} {f['kind']:<13} {f['status']:<10} {f['src']} {f['value'][:90]}")
    elif cmd == 'search':   # mọi từ phải khớp (không phân biệt hoa thường) trên id/kind/value/note/evidence
        q = [x.lower() for x in a[2:] if not x.startswith('--') and x != (a[a.index('--src') + 1] if '--src' in a else None)]
        src = a[a.index('--src') + 1] if '--src' in a else None
        hit = [f for f in load(case).values() if ('--all' in a or f['status'] != 'retracted') and (not src or f['src'] == src)
               and all(w in ' '.join(str(f.get(k, '')) for k in ('id', 'kind', 'value', 'note', 'evidence')).lower() for w in q)]
        for f in hit[:20]: print(f"{f['id']:<18} {f['kind']:<13} {f['status']:<10} {f['src']} {f['value'][:90]}  @{f['evidence']}")
        print(f'{len(hit)} fact khớp' + (' (in 20 đầu)' if len(hit) > 20 else ''))
    elif cmd == 'check':
        for k, v, n in check(case): print(f'{k:<34} {v:<10} {"next: " + n if n else ""}')
    elif cmd == 'report':
        m = migrate_report(case)
        if m: print(f'đổi tên report/README.md -> {os.path.relpath(m, case)}')
        print(f'{len(report(case))} dòng -> {case}/report/GENERATED.md, {os.path.relpath(report_html(case), case)}')
    elif cmd == 'audit':
        p = audit(case); print('\n'.join(p) if p else 'OK audit'); sys.exit(1 if p else 0)
