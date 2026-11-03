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
    finally:
        shutil.rmtree(c, ignore_errors=True)
    print(f'OK test_lint ({ok}/8 nhóm)')

if __name__ == '__main__':
    main()
