#!/usr/bin/env python3
# Kiểm và cài công cụ phân tích cho rea-flow. Mặc định chỉ kiểm và in kế hoạch; --yes mới cài.
#   python3 install_tools.py [--yes] [--no-ghidra]      (hoặc: flow.py setup [--yes] [--no-ghidra])
# Gói hệ thống cài bằng apt-get (Debian/Ubuntu/Kali, cần sudo); thư viện Python cài vào REA_PYLIB (pip --target, không cần sudo);
# Ghidra tải bản đã kiểm từ GitHub, đối chiếu sha256 rồi giải nén vào ~/.local/share/rea-flow; rea cài từ npm (rea-agents).
# Không bao giờ cài hay cấu hình wine: winemu chỉ cần tên export của DLL, mà wine có thể tự chạy file .exe qua binfmt.
import sys, os, re, json, shutil, hashlib, zipfile, subprocess, importlib.util, urllib.request

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

def checks():
    """(tên, đã có?, bắt buộc?, gói apt, gói pip, bước riêng, dùng cho)"""
    node = ver(out('node', '--version'))
    return [
        ('7z', any(map(shutil.which, (CFG.SEVENZ, '7z', '7zz'))), True, ['7zip'], None, None, 'giải nén mẫu và file nén'),
        ('python: pefile', has_mod('pefile'), True, ['python3-pefile'], 'pefile', None, 'triage PE'),
        ('python: capstone', has_mod('capstone'), True, ['python3-capstone'], 'capstone', None, 'disassembly, winemu'),
        ('python: unicorn 2.1.4', unicorn_ok(), True, [], 'unicorn==2.1.4', None, 'giả lập CPU (winemu, tầng T3)'),
        ('python: py-tlsh', has_mod('tlsh'), False, [], 'py-tlsh', None, 'flow.py kb: so khớp mờ mẫu tương tự (TLSH)'),
        ('python: cryptography', has_mod('cryptography'), False, ['python3-cryptography'], 'cryptography', None, 'triage/kb: chủ thể, serial chứng thư'),
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
    apt_pkgs = [p for c in miss for p in c[3]] if apt else []
    pip_pkgs = [c[4] for c in miss if c[4] and not (apt and c[3])]
    steps = [c[5] for c in miss if c[5] and not (c[5] == 'ghidra' and '--no-ghidra' in a)]
    print('\nKế hoạch cài:')
    if apt_pkgs: print('  sudo apt-get install -y ' + ' '.join(apt_pkgs))
    elif any(c[3] for c in miss): print('  (không có apt-get) cài tay: ' + ', '.join(c[0] for c in miss if c[3]))
    if pip_pkgs: print(f'  python3 -m pip install --target {CFG.PYLIB} ' + ' '.join(pip_pkgs))
    for s in steps:
        print({'ghidra': f'  tải Ghidra {GHIDRA_VER} từ GitHub (~550 MiB, kiểm sha256) vào {SHARE}, ghi GHIDRA_INSTALL_DIR vào {CFG.FILE}',
               'node': '  Node.js >= 22.20: cài tay (https://nodejs.org hoặc nvm); apt của nhiều bản phân phối còn bản cũ',
               'rea': f'  npm install -g {REA_PKG} (prefix không ghi được thì --prefix ~/.local)'}[s])
    if not yes: print('\nChưa cài gì. Chạy lại với --yes để cài (apt cần sudo). Bỏ Ghidra: --no-ghidra.'); return 1
    if apt_pkgs:
        subprocess.run(['sudo', 'apt-get', 'update'], check=False)
        if subprocess.run(['sudo', 'apt-get', 'install', '-y'] + apt_pkgs).returncode and '7zip' in apt_pkgs:   # bản cũ: p7zip-full
            subprocess.run(['sudo', 'apt-get', 'install', '-y'] + [('p7zip-full' if p == '7zip' else p) for p in apt_pkgs])
    req_pip = [c[4] for c in miss if c[4] in pip_pkgs and c[2]]
    for grp in ([req_pip] if req_pip else []) + [[c[4]] for c in miss if c[4] in pip_pkgs and not c[2]]:   # gói tùy chọn cài riêng: build lỗi (py-tlsh cần trình biên dịch) không kéo theo gói bắt buộc
        subprocess.run([sys.executable, '-m', 'pip', 'install', '--target', CFG.PYLIB] + grp, check=False)
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
    shutil.rmtree(t); print('OK install_tools selftest')

if __name__ == '__main__':
    if sys.argv[1:] == ['--selftest']: selftest()
    else: sys.exit(main(sys.argv[1:]))
