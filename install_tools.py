#!/usr/bin/env python3
# Kiểm và cài công cụ phân tích cho rea-workflow. Mặc định chỉ kiểm và in kế hoạch; --yes mới cài.
#   python3 install_tools.py [--yes] [--no-ghidra]      (hoặc: flow.py setup [--yes] [--no-ghidra])
# Gói hệ thống cài bằng apt-get (Debian/Ubuntu/Kali, cần sudo); thư viện Python cài vào REA_PYLIB (pip --target, không cần sudo);
# Ghidra tải bản đã kiểm từ GitHub, đối chiếu sha256 rồi giải nén vào ~/.local/share/rea-flow; rea cài từ npm (rea-agents).
# Go và Rust: ưu tiên apt; apt không có hoặc cargo quá cũ thì tự tải Go (go.dev) và rustup-init (static.rust-lang.org), đối chiếu sha256,
# cài vào ~/.local/share/rea-flow/{go,rust}, không cần sudo, không sửa shell profile (Go ghi GO_BIN vào rea.env).
# Không bao giờ cài hay cấu hình wine: winemu chỉ cần tên export của DLL, mà wine có thể tự chạy file .exe qua binfmt.
import sys, os, types, re, json, shutil, hashlib, zipfile, tarfile, tempfile, platform, subprocess, importlib.util, urllib.request

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

def rust_env():
    """Môi trường chạy cargo: có toolchain rustup do skill tự cài (SHARE/rust) thì đặt CARGO_HOME, RUSTUP_HOME và PATH tới đó."""
    ch = os.path.join(SHARE, 'rust', 'cargo'); e = dict(os.environ)
    if os.access(os.path.join(ch, 'bin', 'cargo'), os.X_OK):
        e.update(CARGO_HOME=ch, RUSTUP_HOME=os.path.join(SHARE, 'rust', 'rustup'), PATH=os.path.join(ch, 'bin') + os.pathsep + e.get('PATH', ''))
    return e

def cargo_bin(): return shutil.which('cargo', path=rust_env()['PATH'])

def cargo_ok():
    """cargo và rustc đều có (trên PATH hoặc toolchain tự cài) và cargo >= 1.56 (edition 2021)."""
    e = rust_env(); c = shutil.which('cargo', path=e['PATH'])
    if not (c and shutil.which('rustc', path=e['PATH'])): return False
    try: v = subprocess.run([c, '--version'], capture_output=True, text=True, timeout=60, env=e)
    except (OSError, subprocess.TimeoutExpired): return False
    return (ver(v.stdout + v.stderr) or (0,)) >= (1, 56)

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
        ('go', bool(shutil.which(CFG.GO)), False, ['golang-go'], None, 'go', 'triage Go: `go version -m` đọc buildinfo (thiếu thì mẫu Go không được gắn cờ Go)'),
        ('rust: cargo + rustc >= 1.56', cargo_ok() or rust_ok(), False, [] if shutil.which('cargo') else ['cargo', 'rustc'], None, 'rustup', 'dựng lõi Rust của winemu và triage (đã có thư viện dựng sẵn thì không cần; cargo cũ hơn 1.56 thì cài rustup, apt không nâng được; edition 2021; bản apt đủ dùng, Cargo.lock giữ version 3)'),
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
        cargo = cargo_bin()
        if not cargo: print('  bỏ qua lõi Rust: chưa có cargo (apt install cargo hoặc rustup); winemu dùng Python'); return
        d = d or os.path.join(HERE, 'rust', 'rea_hook')
        if not os.path.isdir(d): print(f'  bỏ qua lõi Rust: không có {d}'); return
        if subprocess.run([cargo, 'build', '--release', '--locked'], cwd=d, env=rust_env()).returncode: print('  build lõi Rust lỗi: winemu dùng Python'); return
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

def fetch(url, timeout=120):
    with urllib.request.urlopen(url, timeout=timeout) as r: return r.read()

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''): h.update(b)
    return h.hexdigest()

def download_verified(url, want, dest):
    """Tải về dest và đối chiếu sha256; không khớp thì xoá file và dừng."""
    tmp = dest + '.part'
    with urllib.request.urlopen(url, timeout=120) as r, open(tmp, 'wb') as f: shutil.copyfileobj(r, f)
    got = sha256_of(tmp)
    if got != want: os.remove(tmp); raise SystemExit(f'sha256 không khớp cho {url} ({got} != {want}): đã xoá file tải về')
    os.replace(tmp, dest)

def safe_extract(tf, dest):
    """Giải tar không cho đường dẫn thoát khỏi dest (tuyệt đối, .., liên kết trỏ ra ngoài)."""
    root = os.path.realpath(dest)
    for m in tf.getmembers():
        t = os.path.realpath(os.path.join(root, m.name))
        if t != root and not t.startswith(root + os.sep): raise SystemExit(f'tar chứa đường dẫn ngoài thư mục đích: {m.name}')
        if (m.issym() or m.islnk()) and not os.path.realpath(os.path.join(os.path.dirname(t), m.linkname) if m.issym() else os.path.join(root, m.linkname)).startswith(root + os.sep):
            raise SystemExit(f'tar chứa liên kết trỏ ra ngoài: {m.name}')
    tf.extractall(dest)

def go_install():
    """Tải Go bản ổn định mới nhất từ go.dev (sha256 do go.dev công bố), giải vào SHARE/go, ghi GO_BIN vào rea.env. Không cần sudo.
    Tùy chọn: lỗi chỉ in cảnh báo (triage không gắn cờ Go khi thiếu)."""
    try:
        arch = {'x86_64': 'amd64', 'amd64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine().lower())
        if not arch or not sys.platform.startswith('linux'): print(f'  bỏ qua Go: chưa hỗ trợ tự tải cho {sys.platform}/{platform.machine()} (cài tay từ https://go.dev/dl)'); return
        f = next((dict(f, version=r['version']) for r in json.loads(fetch('https://go.dev/dl/?mode=json')) if r.get('stable') for f in r['files']
                  if f['os'] == 'linux' and f['arch'] == arch and f['kind'] == 'archive'), None)
        if not f: print('  bỏ qua Go: go.dev không có bản phù hợp'); return
        os.makedirs(SHARE, exist_ok=True); work = tempfile.mkdtemp(dir=SHARE, prefix='.go-')
        try:
            tgz = os.path.join(work, f['filename']); print(f'  tải {f["filename"]} ({f.get("size", 0) >> 20} MiB) từ go.dev...')
            download_verified('https://go.dev/dl/' + f['filename'], f['sha256'], tgz)
            with tarfile.open(tgz) as tf: safe_extract(tf, work)
            dst = os.path.join(SHARE, 'go'); new = os.path.join(work, 'go')
            if not os.path.exists(os.path.join(new, 'bin', 'go')): print('  bỏ qua Go: gói tải về không có bin/go'); return
            if os.path.exists(dst): shutil.rmtree(dst)
            os.replace(new, dst)
        finally: shutil.rmtree(work, ignore_errors=True)
        set_env('GO_BIN', os.path.join(dst, 'bin', 'go')); print(f'  đã cài Go {f["version"]} vào {dst}')
    except BaseException as e:
        if isinstance(e, KeyboardInterrupt): raise
        print(f'  bỏ qua Go: {e if isinstance(e, SystemExit) else type(e).__name__ + ": " + str(e)}')

def rustup_install():
    """Tải rustup-init từ static.rust-lang.org (đối chiếu sha256 do chính nơi đó công bố), cài toolchain stable tối giản vào SHARE/rust
    (CARGO_HOME, RUSTUP_HOME riêng; --no-modify-path: không sửa shell profile). Không cần sudo. Tùy chọn: lỗi chỉ in cảnh báo."""
    try:
        triple = {'x86_64': 'x86_64-unknown-linux-gnu', 'amd64': 'x86_64-unknown-linux-gnu', 'aarch64': 'aarch64-unknown-linux-gnu', 'arm64': 'aarch64-unknown-linux-gnu'}.get(platform.machine().lower())
        if not triple or not sys.platform.startswith('linux'): print(f'  bỏ qua rustup: chưa hỗ trợ tự tải cho {sys.platform}/{platform.machine()} (xem https://rustup.rs)'); return
        base = f'https://static.rust-lang.org/rustup/dist/{triple}/rustup-init'
        want = fetch(base + '.sha256').decode().split()[0]
        os.makedirs(SHARE, exist_ok=True); work = tempfile.mkdtemp(dir=SHARE, prefix='.rustup-')
        try:
            ri = os.path.join(work, 'rustup-init'); print('  tải rustup-init từ static.rust-lang.org...')
            download_verified(base, want, ri); os.chmod(ri, 0o700)
            ch, rh = os.path.join(SHARE, 'rust', 'cargo'), os.path.join(SHARE, 'rust', 'rustup'); os.makedirs(ch, exist_ok=True); os.makedirs(rh, exist_ok=True)
            e = dict(os.environ, CARGO_HOME=ch, RUSTUP_HOME=rh)
            if subprocess.run([ri, '-y', '--profile', 'minimal', '--no-modify-path', '--default-toolchain', 'stable'], env=e).returncode: print('  rustup-init lỗi: winemu/triage dùng Python'); return
        finally: shutil.rmtree(work, ignore_errors=True)
        print(f'  đã cài toolchain Rust vào {os.path.join(SHARE, "rust")}')
    except BaseException as e:
        if isinstance(e, KeyboardInterrupt): raise
        print(f'  bỏ qua rustup: {e if isinstance(e, SystemExit) else type(e).__name__ + ": " + str(e)}')

def rea_install():
    npm = shutil.which('npm')
    if not npm: raise SystemExit('cần npm (Node.js >= 22.20) để cài rea')
    pre = (out(npm, 'config', 'get', 'prefix').strip().splitlines() or [''])[0]
    argv = [npm, 'install', '-g', REA_PKG] + ([] if pre and os.access(pre, os.W_OK) else ['--prefix', os.path.expanduser('~/.local')])
    print('  $', ' '.join(argv)); subprocess.run(argv, check=True)
    if '--prefix' in argv and os.path.expanduser('~/.local/bin') not in os.environ.get('PATH', '').split(':'):
        print('  lưu ý: thêm ~/.local/bin vào PATH để gọi được `rea`')

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
               'go': f'  Go: nếu apt không cài được (hoặc không có apt) thì tải bản ổn định từ go.dev (kiểm sha256) vào {SHARE}/go, ghi GO_BIN vào {CFG.FILE}; không cần sudo',
               'rustup': f'  Rust: nếu apt không cài được (hoặc cargo quá cũ) thì tải rustup-init từ static.rust-lang.org (kiểm sha256) và cài toolchain tối giản vào {SHARE}/rust; không sửa shell profile, không cần sudo',
               'rust': f'  cargo build --release trong rust/rea_hook rồi chép thư viện vào {SHARE}/lib/ (không cần mạng, không phụ thuộc crate ngoài)',
               'kb': f'  tạo kho tri thức ({CFG.KB}) và kéo bản đã công bố từ {CFG.KB_UPSTREAM} (https, kiểm sha256; lỗi thì bỏ qua)',
               'rea': f'  npm install -g {REA_PKG} (prefix không ghi được thì --prefix ~/.local)'}[s])
    if not yes: print('\nChưa cài gì. Chạy lại với --yes để cài (apt cần sudo). Bỏ Ghidra: --no-ghidra.'); return 1
    if apt_pkgs:
        subprocess.run(['sudo', 'apt-get', 'update'], check=False)
        req = list(dict.fromkeys(p for c in miss if c[2] for p in c[3])); opt = [p for p in apt_pkgs if p not in req]   # gói tùy chọn cài riêng: thiếu trong kho không làm hỏng lệnh cài gói bắt buộc
        if req and subprocess.run(['sudo', 'apt-get', 'install', '-y'] + req).returncode and '7zip' in req:   # bản cũ: p7zip-full
            subprocess.run(['sudo', 'apt-get', 'install', '-y'] + [('p7zip-full' if p == '7zip' else p) for p in req])
        for p in opt: subprocess.run(['sudo', 'apt-get', 'install', '-y', p], check=False)
    req_pip = [c[4] for c in miss if c[4] in pip_pkgs and c[2]]
    for grp in ([req_pip] if req_pip else []) + [[c[4]] for c in miss if c[4] in pip_pkgs and not c[2]]:   # gói tùy chọn cài riêng: build lỗi (py-tlsh cần trình biên dịch) không kéo theo gói bắt buộc
        subprocess.run([sys.executable, '-m', 'pip', 'install', '--target', CFG.PYLIB] + grp, check=False)
    if 'go' in steps and not shutil.which(CFG.GO): go_install()   # apt không có hoặc không cài được
    if 'rustup' in steps and not cargo_ok(): rustup_install()
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
    global SHARE
    SHARE0 = SHARE; SHARE = os.path.join(t, 'share0')   # không dùng toolchain/Go thật của máy dev
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
    # tải Go và rustup: giả mạng; sha256 đúng thì cài, sai thì không cài gì; tar thoát thư mục đích bị từ chối
    import io
    real_fetch, real_urlopen, real_machine = fetch, urllib.request.urlopen, platform.machine
    try:
        platform.machine = lambda: 'x86_64'
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tf:
            gi = tarfile.TarInfo('go/bin/go'); gi.size = 3; gi.mode = 0o755; tf.addfile(gi, io.BytesIO(b'#!x'))
        tgz = buf.getvalue(); good = hashlib.sha256(tgz).hexdigest()
        rinit = b'#!/bin/sh\nmkdir -p "$CARGO_HOME/bin"; printf "#!/bin/sh\\necho cargo 1.90.0\\n" > "$CARGO_HOME/bin/cargo"; cp "$CARGO_HOME/bin/cargo" "$CARGO_HOME/bin/rustc"; chmod +x "$CARGO_HOME/bin/cargo" "$CARGO_HOME/bin/rustc"\n'
        state = {'sha': good}
        class R:
            def __init__(self, b): self.b = io.BytesIO(b)
            def read(self, n=-1): return self.b.read(n)
            def __enter__(self): return self
            def __exit__(self, *a): return False
        def fake_open(url, timeout=None):
            u = url if isinstance(url, str) else url.full_url
            return R(rinit if u.endswith('rustup-init') else tgz)
        def fake_fetch(url, timeout=120):
            if 'mode=json' in url: return json.dumps([{'version': 'go1.99', 'stable': True, 'files': [{'os': 'linux', 'arch': 'amd64', 'kind': 'archive', 'filename': 'go1.99.linux-amd64.tar.gz', 'sha256': state['sha'], 'size': len(tgz)}]}]).encode()
            return (hashlib.sha256(rinit).hexdigest() + '  rustup-init/rustup-init\n').encode() if url.endswith('.sha256') else b''
        globals()['fetch'] = fake_fetch; urllib.request.urlopen = fake_open
        SHARE = os.path.join(t, 'dl'); CFG.FILE = os.path.join(t, 'rea2.env')
        state['sha'] = 'f' * 64; go_install(); assert not os.path.exists(os.path.join(SHARE, 'go')), 'sha256 sai không được cài'
        state['sha'] = good; go_install()
        assert os.access(os.path.join(SHARE, 'go', 'bin', 'go'), os.X_OK) and f"GO_BIN={os.path.join(SHARE, 'go', 'bin', 'go')}" in open(CFG.FILE).read()
        assert not [d for d in os.listdir(SHARE) if d.startswith('.go-')], 'không để lại thư mục tạm'
        old_path = os.environ['PATH']; os.environ['PATH'] = '/usr/bin:/bin'
        try:
            assert not cargo_ok() or shutil.which('cargo'), 'máy dev có cargo thật: bỏ qua kiểm tra này'
            rustup_install(); assert cargo_ok() and cargo_bin().startswith(os.path.join(SHARE, 'rust')), 'rustup giả phải cho cargo dùng được'
        finally: os.environ['PATH'] = old_path
        assert not [d for d in os.listdir(SHARE) if d.startswith('.rustup-')]
        evil = io.BytesIO()
        with tarfile.open(fileobj=evil, mode='w') as tf:
            ei = tarfile.TarInfo('../thoat.txt'); ei.size = 1; tf.addfile(ei, io.BytesIO(b'x'))
        evil.seek(0); d2 = os.path.join(t, 'ex'); os.makedirs(d2)
        try:
            with tarfile.open(fileobj=evil) as tf: safe_extract(tf, d2)
            raise AssertionError('tar thoát thư mục đích phải bị từ chối')
        except SystemExit as e: assert 'ngoài thư mục đích' in str(e)
    finally:
        globals()['fetch'] = real_fetch; urllib.request.urlopen = real_urlopen; platform.machine = real_machine; SHARE = SHARE0
    shutil.rmtree(t); print('OK install_tools selftest')

if __name__ == '__main__':
    if sys.argv[1:] == ['--selftest']: selftest()
    else: sys.exit(main(sys.argv[1:]))
