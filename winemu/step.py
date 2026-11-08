# Một bước giả lập nối tiếp: chạy lượt kế <prefix>N+1, resume từ snap_unhandled.bin của lượt <prefix>N.
# Vòng làm việc: lượt dừng vì API X chưa hỗ trợ -> thêm hook X vào plugin -> chạy lại đúng lệnh này.
# Không phải chạy lại từ đầu (lớp vỏ có thể mất vài phút), không phải tự đặt tên thư mục hay nhớ snapshot nào.
#   python3 step.py --out-dir DIR [--prefix r] [--resume SNAP] [--summarize] -- <tham số winemu>
# Lượt đầu (chưa có <prefix>1): chạy từ đầu, hoặc từ --resume. --resume luôn thắng snapshot tự tìm.
# Lượt quá --timeout hoặc winemu chết (không có event end) bị đổi tên thành <prefix>N.timeout/.noend: lần gọi sau resume lại từ lượt trước.
# Không hỗ trợ --chain-child (tiến trình con chạy lại qua execv, không có snapshot): chạy con riêng bằng --child/--entry.
# Mã thoát: 0 = xong (dừng không phải vì API thiếu/lỗi; có thể đã qua OEP), 1 = lỗi chạy hoặc lỗi giả lập (reason 'error …'),
#           2 = dừng ở API thiếu mới (thêm hook rồi chạy lại), 3 = cùng API thiếu như lượt trước (hook chưa có tác dụng).
import sys, os, re, json, subprocess, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
W, SUM = os.path.join(HERE, 'winemu.py'), os.path.join(HERE, 'summarize.py')
AP = argparse.ArgumentParser(allow_abbrev=False)
AP.add_argument('--out-dir', required=True, help='thư mục cha chứa các lượt (vd CASE/work)')
AP.add_argument('--prefix', default='r', help='tiền tố tên lượt: <prefix>1, <prefix>2…')
AP.add_argument('--resume', help='snapshot để chạy tiếp (mặc định: snap_unhandled.bin của lượt cuối)')
AP.add_argument('--timeout', type=int, default=900, help='giây tối đa cho lượt này')
AP.add_argument('--summarize', action='store_true', help='in summarize.py của lượt vừa chạy')
AP.add_argument('rest', nargs=argparse.REMAINDER, help='-- rồi tham số winemu (không truyền --out/--resume/--snap-unhandled)')
A = AP.parse_args()
rest = A.rest[1:] if A.rest[:1] == ['--'] else A.rest
if not rest: sys.exit('thiếu tham số winemu sau --')
bad = [x for x in rest if x.split('=')[0] in ('--out', '--resume', '--snap-unhandled')]
if bad: sys.exit(f'{" ".join(bad)}: step.py tự đặt cho từng lượt, bỏ khỏi tham số winemu')
# tiến trình con (execv) không nhận --snap-unhandled và resume sẽ sai bộ nạp: chạy con riêng bằng --child/--entry
if '--chain-child' in rest: sys.exit('--chain-child: step.py không hỗ trợ (con không có snap_unhandled); chạy riêng với --child/--entry theo event chain_child')

def events(p):
    """events.jsonl -> list dict; dòng hỏng (lượt bị giết giữa chừng) bỏ qua."""
    out = []
    if os.path.exists(p):
        for l in open(p, encoding='utf-8', errors='replace'):
            try: out.append(json.loads(l))
            except ValueError: pass
    return out

def end_of(d):
    return next((e for e in reversed(events(os.path.join(d, 'events.jsonl'))) if e.get('kind') == 'end'), None)

rx = re.compile(re.escape(A.prefix) + r'(\d+)$')
done = sorted(int(m.group(1)) for x in (os.listdir(A.out_dir) if os.path.isdir(A.out_dir) else []) if (m := rx.match(x)))
n = (done[-1] if done else 0) + 1
prev = os.path.join(A.out_dir, f'{A.prefix}{done[-1]}') if done else None
pend = end_of(prev) if prev else None
snap = A.resume
if not snap and prev:
    s = os.path.join(prev, 'snap_unhandled.bin')
    if not (pend and pend.get('unhandled')):
        print(f'{os.path.basename(prev)} không dừng vì API thiếu ({(pend or {}).get("reason", "không có event end")}): '
              'không có gì để chạy tiếp; muốn chạy từ snapshot khác thì truyền --resume'); sys.exit(0 if pend else 1)
    if not os.path.exists(s): sys.exit(f'{os.path.basename(prev)} dừng ở {pend["unhandled"]} nhưng thiếu {s}: lượt đó chạy không có --snap-unhandled?')
    snap = s

def park(out, why):
    """Lượt không có event end (quá giờ, winemu chết): đổi tên để regex lượt bỏ qua nó, lần gọi sau tự resume lại từ lượt trước."""
    if not os.path.exists(out): return out
    dst, k = f'{out}.{why}', 1
    while os.path.exists(dst): k += 1; dst = f'{out}.{why}{k}'
    os.rename(out, dst); return dst

name = f'{A.prefix}{n}'; out = os.path.join(A.out_dir, name)
cmd = [sys.executable, W, '--out', out, '--snap-unhandled', *rest] + (['--resume', snap] if snap else [])
print(f'{name}: ' + (f'resume {snap}' if snap else 'chạy từ đầu'))
try: r = subprocess.run(cmd, capture_output=True, text=True, timeout=A.timeout)
except subprocess.TimeoutExpired:
    d = park(out, 'timeout')
    sys.exit(f'{name}: quá {A.timeout}s, dừng; kết quả dở chuyển sang {os.path.basename(d)}. Chạy lại lệnh này (tăng --timeout) sẽ resume lại từ '
             + (os.path.basename(os.path.dirname(snap)) if snap else 'đầu'))
end = end_of(out)
if end is None:   # winemu chết trước finish(): in đuôi stderr để biết vì sao
    d = park(out, 'noend')
    print(f'{name}: winemu không ghi event end (rc={r.returncode}), chuyển sang {os.path.basename(d)}\n' + (r.stderr or r.stdout)[-1500:]); sys.exit(1)
oep = any(e.get('kind') == 'oep' for e in events(os.path.join(out, 'events.jsonl')))
un = end.get('unhandled')
print(f'{name}: {end.get("reason", "?")}' + (f' | API thiếu: {un}' if un else '') +
      f' | {end.get("api_calls", "?")} lệnh gọi API, {end.get("seconds", "?")}s' + (' | OEP' if oep else ''))
if A.summarize: subprocess.run([sys.executable, SUM, os.path.join(out, 'events.jsonl')])
if str(end.get('reason', '')).startswith('error'): print(f'{name}: giả lập lỗi, không phải API thiếu: xem {name}/*.log (--ring để thấy lệnh trước đó)'); sys.exit(1)
if not un: print('xong: ' + ('tới OEP' if oep else 'hết API thiếu')); sys.exit(0)
# API thiếu xếp trước OEP: plugin chạy tiếp qua OEP (go=1) vẫn ghi event oep, lượt dừng ở API thiếu thì chưa xong
if pend and pend.get('unhandled') == un and snap and not A.resume:
    print(f'{un} vẫn thiếu như {os.path.basename(prev)}: hook chưa có tác dụng (sai tên API/DLL trong API_HOOKS, hoặc hook trả None)'); sys.exit(3)
print(f'thêm hook cho {un} vào plugin rồi chạy lại đúng lệnh này (sẽ resume từ {name}/snap_unhandled.bin)'); sys.exit(2)
