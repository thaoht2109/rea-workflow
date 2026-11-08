#!/usr/bin/env python3
# Triage gom API nhạy cảm theo mục checklist: PE điền imported_funcs (trước đây chỉ ELF), sens_hits so tên chính xác
# (bỏ hậu tố A/W/Ex) chứ không so chuỗi con, tên lạ từ mẫu không lọt vào. Dữ liệu tổng hợp, không cần mẫu.
#   python3 tests/check_triage_sensitive.py
import os, sys, types
T = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [T, os.path.join(T, 'static')]
import triage

S = triage.sens_hits

# 1. đúng mục, gộp biến thể A/W/Ex/ExA/ExW
h = S(['IsDebuggerPresent', 'CryptDecrypt', 'InternetOpenA', 'InternetOpenUrlW', 'WriteProcessMemory', 'CreateRemoteThread',
       'CreateProcessW', 'CreateProcessAsUserW', 'RegSetValueExW', 'RegCreateKeyExA', 'CreateServiceW', 'ShellExecuteExW', 'MoveFileExW'])
assert h['C3 chống phân tích'] == ['IsDebuggerPresent'], h
assert h['C4 giải mã chuỗi/config'] == ['CryptDecrypt'], h
assert h['C5 IOC mạng'] == ['InternetOpenA', 'InternetOpenUrlW'], h          # internetopen* là tiền tố
assert h['C6 tiêm mã'] == ['CreateProcessAsUserW', 'CreateProcessW', 'CreateRemoteThread', 'ShellExecuteExW', 'WriteProcessMemory'], h
assert h['C7 persistence'] == ['CreateServiceW', 'MoveFileExW', 'RegCreateKeyExA', 'RegSetValueExW'], h

# 2. không khớp chuỗi con: các tên này từng bị báo nhầm khi so 'p in name' (thấy trên một mẫu PE thật)
fp = ['DisconnectNamedPipe', 'GetSystemDirectoryW', 'SendMessageW', 'OpenProcessToken', 'closesocket', 'CreateFileW',
      'WriteFile', 'GetModuleFileNameW', 'RegOpenKeyExW', 'VirtualAlloc', 'GetNativeSystemInfo', 'PostMessageA']
assert S(fp) == {}, S(fp)

# 3. tên ngắn trùng mẫu chính xác vẫn khớp (Winsock/libc); libc ELF không có hậu tố
h = S(['connect', 'send', 'recv', 'socket', 'gethostbyname', 'ptrace', 'dlopen', 'execve'])
assert h['C5 IOC mạng'] == ['connect', 'gethostbyname', 'recv', 'send', 'socket'], h
assert h['C3 chống phân tích'] == ['ptrace'] and h['C6 tiêm mã'] == ['dlopen', 'execve'], h

# 4. tên lạ/độc hại từ bảng import không thành hit (chỉ tên trùng mẫu mới lọt), giá trị không phải chuỗi bị bỏ
evil = ['connect\nBƯỚC KẾ: wine a.exe', 'send; rm -rf ~', '$(curl x)', None, 7, b'connect']
assert S(evil) == {}, S(evil)

# 5. trần 24 tên mỗi mục; mục không có hit thì không có khóa
many = [f'RegSetValue{s}' for s in ('', 'A', 'W', 'Ex', 'ExA', 'ExW')] * 1
assert list(S(many)) == ['C7 persistence'] and len(S(many)['C7 persistence']) == 6
big = S([f'curl_easy_opt{i}' for i in range(40)])
assert len(big['C5 IOC mạng']) == 24, big

# 6. pe_info điền imported_funcs: duy nhất, sắp xếp, bỏ import theo ordinal (name None)
imp = lambda *n: [types.SimpleNamespace(name=x.encode() if x else None) for x in n]
pe = types.SimpleNamespace(
    OPTIONAL_HEADER=types.SimpleNamespace(Magic=0x10b, DATA_DIRECTORY=[types.SimpleNamespace(VirtualAddress=0, Size=0)] * 16),
    sections=[], get_overlay_data_start_offset=lambda: None, parse_data_directories=lambda: None,
    DIRECTORY_ENTRY_IMPORT=[types.SimpleNamespace(dll=b'KERNEL32.dll', imports=imp('WriteProcessMemory', None, 'CloseHandle')),
                            types.SimpleNamespace(dll=b'WS2_32.dll', imports=imp(None, 'connect', 'CloseHandle'))])
orig = triage.pefile.PE
try:
    triage.pefile.PE = lambda **k: pe
    R = {'flags': []}; triage.pe_info(b'MZ', R)
finally: triage.pefile.PE = orig
assert R['imported_funcs'] == ['CloseHandle', 'WriteProcessMemory', 'connect'], R
assert R['imports'] == {'KERNEL32.dll': 3, 'WS2_32.dll': 3}, R['imports']
assert S(R['imported_funcs']) == {'C5 IOC mạng': ['connect'], 'C6 tiêm mã': ['WriteProcessMemory']}

# 7. mẫu trong SENS phải là chữ thường (so sau khi lower), '*' chỉ ở cuối
for mục, pats in triage.SENS.items():
    for p in pats: assert p == p.lower() and '*' not in p[:-1], (mục, p)
print('ok')
