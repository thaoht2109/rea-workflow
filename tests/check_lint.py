#!/usr/bin/env python3
"""Test lint khi ghi fact (case.py add): #L ±5 dòng, src vs evidence, dòng vượt, số liệu, --strict.
Chạy: python3 tests/check_lint.py
"""
import os, sys, json, tempfile, subprocess, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.normpath(os.path.join(HERE, '..'))
CASE = 'TMPCASE'

def mkcase():
    c = tempfile.mkdtemp(prefix='rea-lint-')
    os.makedirs(os.path.join(c, 'report', 'evidence'))
    os.makedirs(os.path.join(c, 'work', 'sample'))
    lines = [f'dòng {i}: không liên quan' for i in range(1, 51)]
    lines[9] = 'dòng 10: địa chỉ 0x1802a87f8'
    lines[29] = 'dòng 30: chuỗi ZoomUnifyChannel một mình'
    open(os.path.join(c, 'report', 'evidence', 'emu_long.txt'), 'w').write('\n'.join(lines) + '\n')
    open(os.path.join(c, 'report', 'evidence', 's.txt'), 'w').write(
        'sha256=5a72733d11bd89a2f8ea2c5f8fda8a7b047ac99a53d9fe317a8976246d339a56\nđếm 25400 lệnh\n')
    open(os.path.join(c, 'report', 'evidence', 'emu_x.txt'), 'w').write('log giả lập\n')
    return c

def run(c, *args):
    return subprocess.run([sys.executable, os.path.join(SKILL, 'case.py'), 'add', c] + list(args),
                          capture_output=True, text=True)

def facts(c):
    p = os.path.join(c, 'facts.jsonl')
    return [json.loads(l) for l in open(p)] if os.path.exists(p) else []

def main():
    ok = 0
    c = mkcase()
    try:
        # 1. value nằm ngoài ±5 dòng quanh #L -> fail
        r = run(c, 'id=f1', 'kind=string', 'value=ZoomUnifyChannel', 'src=E', 'evidence=report/evidence/emu_long.txt#L30')
        assert 'lint' not in r.stdout, r.stdout          # L30 chứa chuỗi -> không cảnh báo
        r = run(c, 'id=f2', 'kind=string', 'value=ZoomUnifyChannel', 'src=E', 'evidence=report/evidence/emu_long.txt#L10')
        assert 'value_in_evidence' in r.stdout, r.stdout
        ok += 1

        # 2. --strict từ chối, facts không đổi
        before = len(facts(c))
        r = run(c, 'id=f3', 'kind=string', 'value=KhongCoChuoiNay', 'src=E',
                'evidence=report/evidence/emu_long.txt#L10', '--strict')
        assert r.returncode != 0 and 'lint từ chối' in (r.stderr + r.stdout), (r.returncode, r.stderr, r.stdout)
        assert len(facts(c)) == before
        ok += 1

        # 3. src=S dẫn evidence emu_ -> fail
        r = run(c, 'id=f4', 'kind=file', 'value=abc.dat', 'src=S', 'evidence=report/evidence/emu_x.txt')
        assert 'src_vs_evidence' in r.stdout, r.stdout
        ok += 1

        # 4. #L vượt số dòng
        r = run(c, 'id=f5', 'kind=string', 'value=abcde', 'src=E', 'evidence=report/evidence/emu_long.txt#L99')
        assert 'evidence_line' in r.stdout, r.stdout
        ok += 1

        # 5. evidence dài, không #L -> warn evidence_scope
        r = run(c, 'id=f6', 'kind=string', 'value=ZoomUnifyChannel', 'src=E', 'evidence=report/evidence/emu_long.txt')
        assert 'evidence_scope' in r.stdout, r.stdout
        ok += 1

        # 6. số liệu: "25.400" khớp "25400" trong evidence; "67" thiếu -> warn
        r = run(c, 'id=f7', 'kind=string', 'value=đếm 25.400 lệnh', 'src=S', 'evidence=report/evidence/s.txt')
        assert 'number_in_evidence' not in r.stdout, r.stdout
        r = run(c, 'id=f8', 'kind=string', 'value=giải 6712 tên API', 'src=S', 'evidence=report/evidence/s.txt')
        assert 'number_in_evidence' in r.stdout, r.stdout
        ok += 1

        # 7. hash đúng -> không fail; hash sai -> fail
        h = '5a72733d11bd89a2f8ea2c5f8fda8a7b047ac99a53d9fe317a8976246d339a56'
        r = run(c, 'id=f9', 'kind=hash', 'value=' + h + ' x.dll', 'src=S', 'evidence=report/evidence/s.txt')
        assert 'hash_recompute' not in r.stdout, r.stdout
        r = run(c, 'id=f10', 'kind=hash', 'value=' + '0' * 64 + ' y.dll', 'src=S', 'evidence=report/evidence/s.txt')
        assert 'hash_recompute' in r.stdout, r.stdout
        ok += 1

        # 8. fact sạch không in lint
        r = run(c, 'id=f11', 'kind=string', 'value=ZoomUnifyChannel', 'src=E', 'evidence=report/evidence/emu_long.txt#L30')
        assert 'lint' not in r.stdout and r.returncode == 0, (r.returncode, r.stdout)
        ok += 1

        # 9. IP trong value: scope bị chuẩn hóa số (bỏ dấu ngăn nghìn) không được làm trượt token
        E = os.path.join(c, 'report', 'evidence')
        open(os.path.join(E, 'net.txt'), 'w').write('kết nối tới 10.20.300.4 cổng 443\n')
        r = run(c, 'id=f12', 'kind=c2', 'value=10.20.300.4', 'src=S', 'evidence=report/evidence/net.txt#L1')
        assert 'value_in_evidence' not in r.stdout, r.stdout
        r = run(c, 'id=f13', 'kind=c2', 'value=10.20.300.5', 'src=S', 'evidence=report/evidence/net.txt#L1')
        assert 'value_in_evidence' in r.stdout, r.stdout
        ok += 1

        # 10. src=V: nhận vm_* và host_* (quan sát máy thật do người thu mẫu cung cấp); src=S không được dẫn host_*
        open(os.path.join(E, 'host_proc.txt'), 'w').write('svchost.exe -> powershell.exe -> runtime.exe\n')
        r = run(c, 'id=f14', 'kind=process', 'value=powershell.exe -> runtime.exe', 'src=V', 'evidence=report/evidence/host_proc.txt#L1')
        assert 'lint' not in r.stdout, r.stdout
        r = run(c, 'id=f15', 'kind=process', 'value=powershell.exe', 'src=S', 'evidence=report/evidence/host_proc.txt#L1')
        assert 'src_vs_evidence' in r.stdout, r.stdout
        r = run(c, 'id=f16', 'kind=process', 'value=powershell.exe', 'src=V', 'evidence=report/evidence/net.txt#L1')
        assert 'src_vs_evidence' in r.stdout, r.stdout
        sys.path.insert(0, SKILL); import review          # lớp 1 của cổng phản biện phải áp cùng luật với lint khi ghi
        sv = {x['id'] for x in review.mech(c) if x['check'] == 'src_vs_evidence'}
        assert 'f14' not in sv and {'f15', 'f16'} <= sv, sv
        ok += 1

        # 11. #L neo theo nội dung: chèn dòng vào evidence sau khi ghi fact -> lint tìm lại dòng, chỉ warn evidence_moved
        sys.path.insert(0, SKILL); import case
        open(os.path.join(E, 'cfg.txt'), 'w').write('\n'.join(f'dòng đệm {i}' for i in range(1, 21)) + '\nkhóa cấu hình ALPHA_BRAVO_KEY ở đây\n')
        r = run(c, 'id=f17', 'kind=config', 'value=ALPHA_BRAVO_KEY', 'src=S', 'evidence=report/evidence/cfg.txt#L21')
        f17 = [f for f in facts(c) if f['id'] == 'f17'][0]
        assert 'lint' not in r.stdout and len(f17.get('ev_line', '')) == 12, (r.stdout, f17)
        body = open(os.path.join(E, 'cfg.txt')).read()
        open(os.path.join(E, 'cfg.txt'), 'w').write('\n'.join(f'chèn thêm {i}' for i in range(12)) + '\n' + body)   # dòng đích dời 21 -> 33
        iss = case.lint_fact(c, f17)
        assert [i['check'] for i in iss] == ['evidence_moved'] and iss[0]['level'] == 'warn' and '#L33' in iss[0]['problem'], iss
        old = dict(f17); old.pop('ev_line')                          # fact cũ không có dấu vân tay: hành vi như trước (fail vì lệch dòng)
        assert any(i['check'] == 'value_in_evidence' and i['level'] == 'fail' for i in case.lint_fact(c, old))
        open(os.path.join(E, 'cfg.txt'), 'w').write('nội dung khác hẳn\n' * 30)   # dòng cũ mất: warn + fail vì giá trị không còn
        ch = [i['check'] for i in case.lint_fact(c, f17)]
        assert 'evidence_moved' in ch and 'value_in_evidence' in ch, ch
        # xóa dòng phía trên làm #L vượt độ dài file: vẫn tìm lại theo dấu vân tay, chỉ warn; cổng review cũng không fail evidence_line
        open(os.path.join(E, 'cfg.txt'), 'w').write('đầu file\nkhóa cấu hình ALPHA_BRAVO_KEY ở đây\n')
        iss = case.lint_fact(c, f17)
        assert [(i['check'], i['level']) for i in iss] == [('evidence_moved', 'warn')] and '#L2' in iss[0]['problem'], iss
        assert not any(x['id'] == 'f17' and x['check'] == 'evidence_line' for x in review.mech(c))
        assert any(i['check'] == 'evidence_line' for i in case.lint_fact(c, old))            # không có dấu: vẫn fail như trước
        # #L0 và file rỗng: trả lỗi lint, không ném ngoại lệ; add không lưu dấu vân tay cho dòng không hợp lệ
        r = run(c, 'id=f18', 'kind=config', 'value=ALPHA_BRAVO_KEY', 'src=S', 'evidence=report/evidence/cfg.txt#L0')
        f18 = [f for f in facts(c) if f['id'] == 'f18'][0]
        assert 'evidence_line' in r.stdout and 'ev_line' not in f18, (r.stdout, f18)
        open(os.path.join(E, 'cfg.txt'), 'w').close()
        assert any(i['check'] == 'evidence_line' for i in case.lint_fact(c, f18)) and any(i['check'] == 'evidence_line' for i in case.lint_fact(c, f17))
        ok += 1
    finally:
        shutil.rmtree(c, ignore_errors=True)
    print(f'OK test_lint ({ok}/11 nhóm)')

if __name__ == '__main__':
    main()
