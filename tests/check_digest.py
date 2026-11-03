#!/usr/bin/env python3
"""Test reviewer.digest: fact literal có #L chỉ nhạy với cửa sổ dòng được trích; fact phủ định/không #L/kind khác nhạy với cả file."""
import os, sys, tempfile, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, '..')))
import case as C, reviewer

c = tempfile.mkdtemp(prefix='rea-digest-')
try:
    os.makedirs(os.path.join(c, 'report', 'evidence'))
    p = os.path.join(c, 'report', 'evidence', 'e.txt')
    def write(far=0, near=0):
        L = [f'line{i}' for i in range(1, 41)]; L[19] = 'host evil.example.com'
        if far: L[0] += ' changed'
        if near: L[21] += ' changed'
        open(p, 'w').write('\n'.join(L) + '\n')
    E = 'report/evidence/e.txt'; write()
    C.add(c, id='lit', kind='c2', value='evil.example.com', src='S', evidence=E + '#L20')
    C.add(c, id='neg', kind='c2', value='không có host nào khác', src='S', evidence=E + '#L20')
    C.add(c, id='noL', kind='c2', value='evil.example.com', src='S', evidence=E)
    C.add(c, id='cov', kind='coverage', value='evil.example.com', src='S', evidence=E + '#L20')
    def dig(): reviewer._raw.clear(); cur = C.load(c); return {i: reviewer.digest(c, cur[i]) for i in cur}
    write(); base = dig()
    write(far=1); far = dig()
    assert far['lit'] == base['lit'], 'sửa dòng xa cửa sổ không được làm đổi digest fact literal'
    assert not [i for i in ('neg', 'noL', 'cov') if far[i] == base[i]], [i for i in ('neg', 'noL', 'cov') if far[i] == base[i]]
    write(near=1); near = dig()
    assert near['lit'] != base['lit'], 'sửa trong cửa sổ phải đổi digest'
    print('OK test_digest')
finally: shutil.rmtree(c, ignore_errors=True)
