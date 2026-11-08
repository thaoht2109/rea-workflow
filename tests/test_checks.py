"""Chạy từng tests/check_*.py (script độc lập, không cần mẫu) như một test pytest."""
import glob, os, subprocess, sys
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))

@pytest.mark.parametrize('script', sorted(glob.glob(os.path.join(HERE, 'check_*.py'))), ids=os.path.basename)
def test_check(script):
    env = dict(os.environ, REA_KB=os.environ.get('REA_KB_TEST', 'off'))   # report --final trong workspace tạm không được ghi vào kho thật của máy
    r = subprocess.run([sys.executable, script], capture_output=True, text=True, timeout=300, env=env)
    assert r.returncode == 0, (r.stdout + r.stderr)[-2000:]
