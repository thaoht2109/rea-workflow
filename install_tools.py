#!/usr/bin/env python3
# Kiểm và cài công cụ phân tích cho rea-workflow. Mặc định chỉ kiểm và in kế hoạch; --yes mới cài.
#   python3 install_tools.py [--yes] [--no-ghidra]      (hoặc: flow.py setup [--yes] [--no-ghidra])
# Gói hệ thống cài bằng apt-get (Debian/Ubuntu/Kali, cần sudo); thư viện Python cài vào REA_PYLIB (pip --target, không cần sudo);
# Ghidra tải bản đã kiểm từ GitHub, đối chiếu sha256 rồi giải nén vào ~/.local/share/rea-flow; rea cài từ npm (rea-agents).
# Công cụ hệ thống (binutils, go, cargo, rustc...) chỉ cài bằng apt; apt không có hoặc không cài được thì DỪNG và in gói cần cài tay (không tự tải trực tiếp).
# Không bao giờ cài hay cấu hình wine: winemu chỉ cần tên export của DLL, mà wine có thể tự chạy file .exe qua binfmt.
import sys, os, types, re, json, shutil, hashlib, zipfile, subprocess, importlib.util, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import reacfg as CFG

GHIDRA_VER, GHIDRA_TAG = '12.1.4', 'Ghidra_12.1.4_build'   # bản đã kiểm với flow.py dec
REA_PKG = 'rea-agents@6.7.0'                                # bản đã kiểm (CLI `rea`)
NODE_MIN = (22, 20)
SHARE = os.path.join(os.environ.get('XDG_DATA_HOME') or os.path.expanduser('~/.local/share'), 'rea-flow')

def out(*a):
    try: r = subprocess.run(a, capture_output=True, text=True, timeout=30); return r.stdout + r.stderr
    except (OSError, subprocess.TimeoutExpired): return ''

def ver(s, n=2):
    m = re.search(r'(\d+)\.(\d+)(?:\.(\d+))?', s or '')
    return tuple(int(x or 0) for x in m.groups())[:n] if m else None

def java_major():
    j = os.path.join(CFG.JAVA_HOME, 'bin', 'java') if CFG.JAVA_HOME else shutil.which('java')
    m = re.search(r'version "(\d+)', out(j, '-version')) if j else None
    return int(m.group(1)) if m else 0

def has_mod(m): return importlib.util.find_spec(m) is not None

def unicorn_ok():
    try: import unicorn; return (ver(unicorn.__version__, 3) or (0,)) >= (2, 1, 4)
    except Exception: return False

def rust_ok():
    """Lõi Rust của winemu đã có (cùng hàm dò với winemu và doctor)."""
    wd = os.path.join(HERE, 'winemu'); sys.path.insert(0, wd)
    try:
        import rcore; return rcore.load_lib()[0] is not None
    except Exception: return False
    finally:
        if wd in sys.path: sys.path.remove(wd)

def cargo_ok():
    """cargo và rustc đều có trên PATH và cargo >= 1.56 (edition 2021)."""
    return bool(shutil.which('cargo') and shutil.which('rustc')) and (ver(out('cargo', '--version')) or (0,)) >= (1, 56)

def kb_ready():
    """Kho tra chéo đã có dữ liệu, hoặc cố ý tắt (REA_KB=off) / không có nguồn để kéo."""
    try:
        import kb; d = kb.kb_dir()
    except BaseException: return True   # kho đặt sai chỗ: để doctor báo, không phải việc của setup
    return d is None or os.path.exists(os.path.join(d, 'samples.jsonl'))

def kb_install():
    """Tạo thư mục kho và kéo bản đã công bố (kb update: https, kiểm sha256). Tùy chọn: mất mạng, chưa có bản phát hành, REA_KB_UPSTREAM=off
    chỉ in cảnh báo, không chặn cài công cụ khác."""
    try:
        import kb; d = kb.kb_dir()
        if not d: return
        kb.writable(d); print(f'  kho tri thức: {d}')
        if (CFG.KB_UPSTREAM or '').lower() in ('', 'off', '0', 'none', 'no'): print('  REA_KB_UPSTREAM=off: không kéo kho đã công bố'); return
        kb.update()
    except BaseException as e:
        if isinstance(e, KeyboardInterrupt): raise
        print(f'  bỏ qua kéo kho đã công bố: {e if isinstance(e, SystemExit) else type(e).__name__ + ": " + str(e)} (chạy lại sau: flow.py kb update)')

def checks():
    """(tên, đã có?, bắt buộc?, gói apt, gói pip, bước riêng, dùng cho)"""
    node = ver(out('node', '--version'))
    return [
        ('7z', any(map(shutil.which, (CFG.SEVENZ, '7z', '7zz'))), True, ['7zip'], None, None, 'giải nén mẫu và file nén'),
        ('readelf (binutils)', bool(shutil.which('readelf')), True, ['binutils'], None, None, 'triage ELF: section, import, symbol (thiếu thì ELF ra trống mà không báo lỗi)'),
        ('python: pefile', has_mod('pefile'), True, ['python3-pefile'], 'pefile', None, 'triage PE'),
        ('python: capstone', has_mod('capstone'), True, ['python3-capstone'], 'capstone', None, 'disassembly, winemu'),
        ('python: unicorn 2.1.4', unicorn_ok(), True, [], 'unicorn==2.1.4', None, 'giả lập CPU (winemu, tầng T3)'),
        ('python: py-tlsh', has_mod('tlsh'), False, [], 'py-tlsh', None, 'flow.py kb: so khớp mờ mẫu tương tự (TLSH)'),
        ('python: brotli', has_mod('brotli'), False, ['python3-brotli'], 'brotli', None, 'flow.py v8: gỡ lớp brotli của code cache V8 (.jsc)'),
        ('python: cryptography', has_mod('cryptography'), False, ['python3-cryptography'], 'cryptography', None, 'triage/kb: chủ thể, serial chứng thư'),
        ('go', bool(shutil.which('go')), False, ['golang-go'], None, None, 'triage Go: `go version -m` đọc buildinfo (thiếu thì mẫu Go không được gắn cờ Go)'),
        ('rust: cargo + rustc >= 1.56', cargo_ok() or rust_ok(), False, [] if shutil.which('cargo') else ['cargo', 'rustc'], None, None, 'dựng lõi Rust của winemu và triage (đã có thư viện dựng sẵn thì không cần; cargo cũ hơn 1.56 thì cài rustup, apt không nâng được; edition 2021; bản apt đủ dùng, Cargo.lock giữ version 3)'),
        ('winemu: lõi Rust', rust_ok(), False, [] if shutil.which('cargo') else ['cargo'], None, 'rust', 'hook block của winemu nhanh ~6 lần (tùy chọn: thiếu thì tự dùng Python, cùng kết quả)'),
        ('kho tri thức (kb)', kb_ready(), False, [], None, 'kb', 'flow.py kb: gợi ý từ mẫu đã phân tích; kéo kho đã công bố (tùy chọn: thiếu thì chỉ không có gợi ý chéo)'),
        ('upx', bool(shutil.which(CFG.UPX)), False, ['upx-ucl'], None, None, 'bóc vỏ UPX'),
        ('JDK 21', java_major() >= 21, True, ['openjdk-21-jdk-headless'], None, None, 'chạy Ghidra'),
        (f'Ghidra {GHIDRA_VER}', bool(CFG.GHIDRA) and os.path.exists(os.path.join(CFG.GHIDRA, 'support', 'analyzeHeadless')), True,
         [], None, 'ghidra', 'decompile (rea dùng Ghidra trên Linux; Ghidra headless cho MIPS/PPC)'),
        ('Node.js >= 22.20', bool(node) and node >= NODE_MIN, True, [], None, 'node', 'chạy rea và bộ cài skill'),
        ('rea (rea-agents)', bool(shutil.which(CFG.REA_BIN)), True, [], None, 'rea', 'flow.py dec: decompile nhanh x86/x64/ARM'),
    ]

def ghidra_install():
    """Tải bản Ghidra đã kiểm, đối chiếu sha256 do GitHub công bố, giải nén vào SHARE và ghi GHIDRA_INSTALL_DIR vào rea.env."""
    rel = json.load(urllib.request.urlopen(f'https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/{GHIDRA_TAG}', timeout=60))
    a = next(x for x in rel['assets'] if x['name'].endswith('.zip'))
    want = (a.get('digest') or '').removeprefix('sha256:')
    os.makedirs(SHARE, exist_ok=True); z = os.path.join(SHARE, a['name'])
    if not os.path.exists(z):
        print(f'  tải {a["name"]} ({a["size"] >> 20} MiB)...'); urllib.request.urlretrieve(a['browser_download_url'], z + '.part'); os.replace(z + '.part', z)
    h = hashlib.sha256()
    with open(z, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''): h.update(b)
    if want and h.hexdigest() != want: os.remove(z); raise SystemExit(f'sha256 Ghidra không khớp ({h.hexdigest()} != {want}): đã xoá file tải về')
    with zipfile.ZipFile(z) as zf:
        top = zf.namelist()[0].split('/')[0]; zf.extractall(SHARE)
        for i in zf.infolist():   # zipfile không giữ quyền thực thi: lấy lại từ thuộc tính Unix trong zip
            if i.external_attr >> 16 & 0o111: os.chmod(os.path.join(SHARE, i.filename), (i.external_attr >> 16) & 0o777)
    os.remove(z)
    gd = os.path.join(SHARE, top); set_env('GHIDRA_INSTALL_DIR', gd); return gd

def set_env(k, v):
    """Ghi/thay một dòng K=V trong rea.env (tạo từ mẫu nếu chưa có)."""
    p = CFG.FILE; os.makedirs(os.path.dirname(p), exist_ok=True)
    s = open(p, encoding='utf-8').read() if os.path.exists(p) else open(os.path.join(HERE, 'rea.env.example'), encoding='utf-8').read()
    s = re.sub(rf'^#?\s*{k}=.*$', f'{k}={v}', s, flags=re.M) if re.search(rf'^#?\s*{k}=', s, re.M) else s.rstrip('\n') + f'\n{k}={v}\n'
    open(p, 'w', encoding='utf-8').write(s); print(f'  ghi {k}={v} vào {p}')

def rust_build(d=None):
    """Dựng lõi Rust và chép vào SHARE/lib (sống qua lần cập nhật skill). Mọi lỗi (thiếu cargo, build lỗi, không ghi được) chỉ in cảnh báo:
    bước này tùy chọn, không được chặn cài Ghidra/rea; winemu tự dùng Python."""
    try:
        if not shutil.which('cargo'): print('  bỏ qua lõi Rust: chưa có cargo (apt install cargo hoặc rustup); winemu dùng Python'); return
        d = d or os.path.join(HERE, 'rust', 'rea_hook')
        if not os.path.isdir(d): print(f'  bỏ qua lõi Rust: không có {d}'); return
        if subprocess.run(['cargo', 'build', '--release', '--locked'], cwd=d).returncode: print('  build lõi Rust lỗi: winemu dùng Python'); return
        wd = os.path.join(HERE, 'winemu'); sys.path.insert(0, wd)
        try: import rcore
        finally: sys.path.remove(wd)
        src = os.path.join(d, 'target', 'release', rcore.NAME); dst = os.path.join(SHARE, 'lib', rcore.NAME)
        if not os.path.exists(src): print(f'  không thấy {src}: winemu dùng Python'); return
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        tmp = dst + '.tmp'   # thay nguyên tử: tiến trình đang map bản cũ không bị ghi đè tại chỗ
        try: shutil.copy2(src, tmp); os.replace(tmp, dst)
        finally:
            if os.path.exists(tmp): os.remove(tmp)   # chép lỗi giữa chừng thì không để sót file tạm
        print(f'  đã chép lõi Rust vào {dst}')
    except Exception as e: print(f'  lõi Rust lỗi ({type(e).__name__}: {e}): winemu dùng Python')

def rea_install():
    npm = shutil.which('npm')
    if not npm: raise SystemExit('cần npm (Node.js >= 22.20) để cài rea')
    pre = (out(npm, 'config', 'get', 'prefix').strip().splitlines() or [''])[0]
    argv = [npm, 'install', '-g', REA_PKG] + ([] if pre and os.access(pre, os.W_OK) else ['--prefix', os.path.expanduser('~/.local')])
    print('  $', ' '.join(argv)); subprocess.run(argv, check=True)
    if '--prefix' in argv and os.path.expanduser('~/.local/bin') not in os.environ.get('PATH', '').split(':'):
        print('  lưu ý: thêm ~/.local/bin vào PATH để gọi được `rea`')

def apt_stop(why, left):
    """Công cụ hệ thống cần cho phân tích mà apt không cài được: không tự tải trực tiếp, dừng và nói rõ gói cần cài tay. Trả mã 1."""
    print(f'\nDỪNG: {why}. Các công cụ sau cần cho quá trình phân tích:')
    for c in left: print(f'  - {c[0]}: gói apt {" ".join(c[3])} [{c[6]}]')
    print('Cài tay (bản phân phối khác thì dùng gói tương ứng hoặc nguồn chính thức: Go https://go.dev/dl, Rust https://rustup.rs), rồi chạy lại: python3 flow.py setup --yes')
    print('Chưa cài tiếp Ghidra, rea, kho tri thức, lõi Rust cho tới khi đủ các công cụ trên.'); return 1

def main(a):
    yes, apt = '--yes' in a, shutil.which('apt-get')
    C = checks(); miss = [c for c in C if not c[1]]
    for name, ok, req, *_ , use in C:
        print(f"{'OK   ' if ok else ('THIẾU' if req else 'WARN ')} {name:<24} [{use}]")
    if not miss: print('Đủ công cụ. Kiểm cấu hình: python3 flow.py doctor'); return 0
    apt_pkgs = list(dict.fromkeys(p for c in miss for p in c[3])) if apt else []   # bỏ gói trùng, giữ thứ tự
    pip_pkgs = [c[4] for c in miss if c[4] and not (apt and c[3])]
    steps = [c[5] for c in miss if c[5] and not (c[5] == 'ghidra' and '--no-ghidra' in a)]
    print('\nKế hoạch cài:')
    if apt_pkgs: print('  sudo apt-get install -y ' + ' '.join(apt_pkgs))
    elif any(c[3] for c in miss): print('  (không có apt-get) cài tay: ' + ', '.join(c[0] for c in miss if c[3]))
    if pip_pkgs: print(f'  python3 -m pip install --target {CFG.PYLIB} ' + ' '.join(pip_pkgs))
    for s in steps:
        print({'ghidra': f'  tải Ghidra {GHIDRA_VER} từ GitHub (~550 MiB, kiểm sha256) vào {SHARE}, ghi GHIDRA_INSTALL_DIR vào {CFG.FILE}',
               'node': '  Node.js >= 22.20: cài tay (https://nodejs.org hoặc nvm); apt của nhiều bản phân phối còn bản cũ',
               'rust': f'  cargo build --release trong rust/rea_hook rồi chép thư viện vào {SHARE}/lib/ (không cần mạng, không phụ thuộc crate ngoài)',
               'kb': f'  tạo kho tri thức ({CFG.KB}) và kéo bản đã công bố từ {CFG.KB_UPSTREAM} (https, kiểm sha256; lỗi thì bỏ qua)',
               'rea': f'  npm install -g {REA_PKG} (prefix không ghi được thì --prefix ~/.local)'}[s])
    if not yes: print('\nChưa cài gì. Chạy lại với --yes để cài (apt cần sudo). Bỏ Ghidra: --no-ghidra.'); return 1
    need = [c for c in miss if c[2] and c[3] and not c[4]]   # công cụ hệ thống BẮT BUỘC chỉ cài được bằng gói hệ điều hành (gói Python có đường pip riêng)
    if need and not apt: return apt_stop('máy không có apt-get nên không tự cài được', need)
    if not apt:
        for c in miss:
            if c[3] and not c[4]: print(f'  CẢNH BÁO: chưa có {c[0]} (tùy chọn): cài tay gói {" ".join(c[3])} nếu cần [{c[6]}]')
    if apt_pkgs:
        subprocess.run(['sudo', 'apt-get', 'update'], check=False)
        req = list(dict.fromkeys(p for c in miss if c[2] for p in c[3])); opt = [p for p in apt_pkgs if p not in req]   # gói tùy chọn cài riêng: thiếu trong kho không làm hỏng lệnh cài gói bắt buộc
        if req and subprocess.run(['sudo', 'apt-get', 'install', '-y'] + req).returncode and '7zip' in req:   # bản cũ: p7zip-full
            subprocess.run(['sudo', 'apt-get', 'install', '-y'] + [('p7zip-full' if p == '7zip' else p) for p in req])
        for p in opt: subprocess.run(['sudo', 'apt-get', 'install', '-y', p], check=False)
        now = [c for c in checks() if not c[1] and c[3] and not c[4]]
        left = [c for c in now if c[2]]
        if left: return apt_stop('apt-get không cài được hết', left)
        for c in now: print(f'  CẢNH BÁO: chưa có {c[0]} (tùy chọn): cài tay gói apt {" ".join(c[3])} nếu cần [{c[6]}]')   # tùy chọn: chỉ nhắc, không chặn pip/Ghidra/rea
    req_pip = [c[4] for c in miss if c[4] in pip_pkgs and c[2]]
    for grp in ([req_pip] if req_pip else []) + [[c[4]] for c in miss if c[4] in pip_pkgs and not c[2]]:   # gói tùy chọn cài riêng: build lỗi (py-tlsh cần trình biên dịch) không kéo theo gói bắt buộc
        subprocess.run([sys.executable, '-m', 'pip', 'install', '--target', CFG.PYLIB] + grp, check=False)
    if 'rust' in steps: rust_build()
    if 'kb' in steps: kb_install()
    if 'ghidra' in steps: ghidra_install()
    node = ver(out('node', '--version'))
    if 'rea' in steps and node and node >= NODE_MIN: rea_install()
    elif 'rea' in steps: print('  bỏ qua rea: cần Node.js >= 22.20 trước')
    left = [c[0] for c in checks() if c[2] and not c[1]]
    print('\nCòn thiếu (bắt buộc): ' + ', '.join(left) if left else '\nXong. Kiểm cấu hình: python3 flow.py doctor'); return 1 if left else 0

def selftest():
    assert ver('v24.22.0') == (24, 22) and ver('2.1.4', 3) == (2, 1, 4) and ver('') is None
    import tempfile
    t = tempfile.mkdtemp(); CFG.FILE = os.path.join(t, 'rea.env')
    set_env('GHIDRA_INSTALL_DIR', '/opt/g1'); set_env('GHIDRA_INSTALL_DIR', '/opt/g2')   # thay dòng, không thêm trùng
    s = open(CFG.FILE).read(); assert s.count('GHIDRA_INSTALL_DIR=') == 1 and 'GHIDRA_INSTALL_DIR=/opt/g2' in s, s
    C = checks(); assert all(len(c) == 7 for c in C) and any(c[2] for c in C)
    old = {k: os.environ.get(k) for k in ('REA_CORE_LIB', 'PATH')}
    try:   # lõi Rust là tùy chọn: thiếu thư viện thì mục THIẾU không bắt buộc; không có cargo thì rust_build bỏ qua, không lỗi
        os.environ['REA_CORE_LIB'] = os.path.join(t, 'khong-co'); os.environ['PATH'] = t
        r = [c for c in checks() if c[5] == 'rust']; assert len(r) == 1 and not r[0][1] and not r[0][2] and r[0][3] == ['cargo'], r   # PATH rỗng: không có cargo nên cần gói apt
        rust_build()
        C0 = {c[0].split(' ')[0]: c for c in checks()}   # PATH rỗng: thiếu go, readelf, cargo/rustc; chỉ readelf bắt buộc
        assert not C0['go'][1] and not C0['go'][2] and C0['go'][3] == ['golang-go'], C0['go']
        assert not C0['readelf'][1] and C0['readelf'][2] and C0['readelf'][3] == ['binutils'], C0['readelf']
        assert not C0['rust:'][1] and not C0['rust:'][2] and C0['rust:'][3] == ['cargo', 'rustc'], C0['rust:']
        fb0 = os.path.join(t, 'oldbin'); os.makedirs(fb0)   # cargo cũ (< 1.56) trên PATH: apt không nâng được, không thêm gói apt
        for b in ('cargo', 'rustc'): open(os.path.join(fb0, b), 'w').write('#!/bin/sh\necho "cargo 1.40.0"\n'); os.chmod(os.path.join(fb0, b), 0o700)
        os.environ['PATH'] = fb0; C1 = {c[0].split(' ')[0]: c for c in checks()}
        assert not C1['rust:'][1] and C1['rust:'][3] == [], C1['rust:']
    finally:
        for k, v in old.items():
            if v is None: os.environ.pop(k, None)
            else: os.environ[k] = v
    global SHARE
    sh0 = SHARE
    try:   # nhánh có cargo (giả) build xong: chép vào SHARE/lib, thay nguyên tử, không để lại .tmp
        wd = os.path.join(HERE, 'winemu'); sys.path.insert(0, wd)
        try: import rcore
        finally: sys.path.remove(wd)
        fb = os.path.join(t, 'bin'); os.makedirs(fb); cd = os.path.join(t, 'crate'); os.makedirs(cd)
        open(os.path.join(fb, 'cargo'), 'w').write(f'#!/bin/sh\nmkdir -p target/release && echo moi > target/release/{rcore.NAME}\n'); os.chmod(os.path.join(fb, 'cargo'), 0o700)
        SHARE = os.path.join(t, 'share'); os.environ['PATH'] = fb + ':' + (old['PATH'] or '')
        os.makedirs(os.path.join(SHARE, 'lib')); open(os.path.join(SHARE, 'lib', rcore.NAME), 'w').write('cu')
        rust_build(cd)
        assert open(os.path.join(SHARE, 'lib', rcore.NAME)).read() == 'moi\n' and os.listdir(os.path.join(SHARE, 'lib')) == [rcore.NAME]
        open(os.path.join(fb, 'cargo'), 'w').write('#!/bin/sh\nexit 1\n'); rust_build(cd)   # build lỗi: không ném ngoại lệ
        SHARE = '/proc/khong-ghi-duoc'; open(os.path.join(fb, 'cargo'), 'w').write(f'#!/bin/sh\nmkdir -p target/release && echo x > target/release/{rcore.NAME}\n'); rust_build(cd)   # không ghi được: không ném
    finally:
        SHARE = sh0
        for k, v in old.items():
            if v is None: os.environ.pop(k, None)
            else: os.environ[k] = v
    calls = []   # --yes: gói bắt buộc một lệnh apt riêng, mỗi gói tùy chọn một lệnh riêng (thiếu trong kho không làm hỏng gói bắt buộc)
    real_checks, real_run, real_which = globals()['checks'], subprocess.run, shutil.which
    try:
        globals()['checks'] = lambda: [('a', False, True, ['binutils'], None, None, 'x'), ('b', False, False, ['golang-go'], None, None, 'x'), ('c', False, False, ['cargo', 'rustc', 'golang-go'], None, None, 'x')]
        subprocess.run = lambda cmd, **k: calls.append(cmd) or types.SimpleNamespace(returncode=0, stdout='', stderr='')
        shutil.which = lambda n, *a, **k: '/usr/bin/apt-get' if n == 'apt-get' else real_which(n)
        main(['--yes'])
    finally: globals()['checks'], subprocess.run, shutil.which = real_checks, real_run, real_which
    ins = [c[4:] for c in calls if c[:4] == ['sudo', 'apt-get', 'install', '-y']]
    assert ins == [['binutils'], ['golang-go'], ['cargo'], ['rustc']], ins
    assert all(c[:2] == ['sudo', 'apt-get'] for c in calls), calls   # apt không cài được: dừng, không chạy bước nào khác (pip, rust, ghidra, rea)
    import io, contextlib
    def run_main(fake_checks, has_apt=True):
        calls.clear(); real = (globals()['checks'], subprocess.run, shutil.which); buf = io.StringIO()
        try:
            globals()['checks'] = fake_checks
            subprocess.run = lambda cmd, **k: calls.append(cmd) or types.SimpleNamespace(returncode=0, stdout='', stderr='')
            shutil.which = lambda n, *a, **k: ('/usr/bin/apt-get' if has_apt else None) if n == 'apt-get' else real_which(n)
            with contextlib.redirect_stdout(buf): rc = main(['--yes'])
        finally: globals()['checks'], subprocess.run, shutil.which = real
        return rc, buf.getvalue()
    miss2 = lambda: [('binutils-tool', False, True, ['binutils'], None, None, 'dùng cho X'), ('pyx', False, True, ['python3-pyx'], 'pyx', None, 'dùng cho Y')]
    rc, o = run_main(miss2, has_apt=False)   # không có apt: dừng ngay, không gọi lệnh nào, nêu gói cần cài; gói Python có đường pip thì không chặn
    assert rc == 1 and not [c for c in calls if c[:1] == ['sudo']] and 'DỪNG' in o and 'binutils' in o and 'pyx' not in o.split('DỪNG')[1], (rc, o, calls)
    rc, o = run_main(miss2); assert rc == 1 and 'apt-get không cài được hết' in o and 'binutils-tool' in o, o
    ok_after = lambda: [('binutils-tool', any(c[:4] == ['sudo', 'apt-get', 'install', '-y'] for c in calls), True, ['binutils'], None, None, 'dùng cho X')]
    rc, o = run_main(ok_after); assert rc == 0 and 'DỪNG' not in o, (rc, o)   # apt cài được: chạy tiếp bình thường
    opt = ('go', False, False, ['golang-go'], None, None, 'x'); pipreq = ('pyx', False, True, ['python3-pyx'], 'pyx', None, 'dùng cho Y')
    for has in (False, True):   # mục tùy chọn apt-only luôn thiếu không được chặn pip của mục bắt buộc
        rc, o = run_main(lambda: [opt, pipreq], has_apt=has)
        assert 'DỪNG' not in o and 'CẢNH BÁO' in o and (has or any('pip' in c for c in calls if isinstance(c, list))), (has, rc, o, calls)   # có apt thì gói Python cài bằng apt, không có thì bằng pip
    shutil.rmtree(t); print('OK install_tools selftest')

if __name__ == '__main__':
    if sys.argv[1:] == ['--selftest']: selftest()
    else: sys.exit(main(sys.argv[1:]))
