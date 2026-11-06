# winemu: giả lập shellcode/loader Windows x86-32 bị làm rối nặng

Phát triển từ phân tích loader GuLoader. Dùng khi Ghidra/IDA không đọc được vì mã tự giải mã và điều khiển luồng bằng ngoại lệ. Công cụ cho mã độc tự chạy trong một môi trường Windows giả: **không chạy mẫu thật, không có mạng thật**, mọi API mạng chỉ được ghi lại.

## Cài đặt

```bash
# unicorn 2.1.4: python3 -m pip install --target ~/.local/share/rea-flow/pylib unicorn==2.1.4 (winemu tự thêm vào sys.path; đổi bằng REA_PYLIB)
# capstone: gói Python hệ thống (không có apt thì flow.py setup cài vào REA_PYLIB). DLL giả lấy tên export từ WINE_DLL_DIR (mặc định /usr/lib/x86_64-linux-gnu/wine)
```

## OPSEC (bắt buộc)

- **Cấm chạy mẫu bằng `wine`/`wine64`** (máy có cài wine chỉ để lấy tên export). `update-binfmts --display wine` phải báo
  "not in database", để exe không tự chạy qua wine.
- Mẫu đặt ở `<case>/work/sample/` với quyền `0400`. Không đưa mẫu lên git.
- Snapshot dùng `pickle`: chỉ `--resume` snapshot do chính mình sinh ra, không nạp snapshot lấy từ nơi khác.
- Không mạng thật: mọi API mạng chỉ được ghi lại. Tải payload thật chỉ khi người dùng cho phép, qua đường cô lập.

## Quy trình (đọc tóm tắt, không đọc log thô)

```bash
# 1. chạy: stage giải mã thuần chạy trần (--prerun, vài giây) rồi vào môi trường Windows
python3 $SKILL/winemu/winemu.py --blob SHELLCODE --blob-off 1200 --size 0x27e2000 --prerun --out OUT --chain-child \
    --exe work/sample/mau.exe --exe-path 'C:\Users\admin\Downloads\mau.exe' \
    [--plugin $SKILL/winemu/plugins/guloader.py:dec=0x...,s2=0x...,s2len=0x...]   # --plugin tính từ thư mục hiện tại
# 2. đọc kết quả: vài chục dòng gồm chuỗi giải mã, mạng, tạo tiến trình, tiêm mã, API chưa hỗ trợ, lý do dừng
python3 $SKILL/winemu/summarize.py OUT/events.jsonl
# 3. ghi fact src=E: chép evidence report/evidence/emu_<tên OUT>.jsonl, ghi url/ua/c2/str_key/anti_analysis/inject/exit_reason/api_unused
#    (exit_reason, api_unused là căn cứ của C11)
python3 $SKILL/winemu/summarize.py OUT/events.jsonl --facts CASE
```

- **Chuỗi:** `argstr` lấy mọi chuỗi in được truyền vào API (URL, User-Agent, tên DLL), không cần biết hàm giải mã. Plugin `str` bắt cả chuỗi chưa dùng tới API.
- **Gặp `API CHƯA HỖ TRỢ`:** thêm một nhánh vào `api()` trong `winemu.py`, hoặc thêm `API_HOOKS['Ten'] = f` trong plugin. Sau đó chạy lại từ snapshot.
- **Bước chống phân tích dài** (quét bộ nhớ khoảng 27 phút): `--snap-at API[:N]` lưu `OUT/snap_API.bin` rồi dừng. Lần sau chạy `--resume OUT/snap_API.bin` với cùng tham số nạp (`--blob` hoặc `--child`).
- **Xem đoạn mã ngay trước một API hoặc lỗi:** dùng `--ring 3000 --stop-at API:N`, ring được in vào `OUT/<tag>.log`.
- **Tiến trình con bị tiêm:** cha ghi buffer lớn (> 1 MB) thành `OUT/child_mem.bin`. Điểm vào là giá trị 4 byte cuối cùng cha ghi vào tiến trình con mà trỏ vào buffer đó. `--chain-child` tự chạy tiếp tiến trình con với tag `child`.
- **Lấy keystream giải mã payload:** dùng `--fake-dl 0x80000` để `InternetReadFile` trả về toàn byte 0. Kết hợp `--fake-dl-file` nếu mã độc kiểm tra kích thước hoặc nội dung.

## Bẫy đã xử lý (đừng sửa lại từ đầu)

| Hiện tượng | Cách xử lý trong `winemu.py` |
|---|---|
| Stage giải mã thuần chạy hàng trăm triệu lệnh | `--prerun`: chạy trước khi gắn hook, dừng ở lần đọc `fs:[0x30]` đầu tiên |
| Lệnh đặc quyền (`invd`, `lmsw`, `lldt`, `clts`…) phải gây `PRIVILEGED_INSTRUCTION` | Chuyển xuống ring 3 bằng `iretd`. `#GP`/`#DF` được ánh xạ thành `0xC0000096` |
| Unicorn không bẫy single-step (TF) tin cậy sau `popfd` và ở lệnh nhảy | Block hook dừng lại, chạy 1 lệnh, tự tính nhánh JCC, rồi phát `SINGLE_STEP`. Windows xóa TF trong `CONTEXT`. Nếu chính lệnh mang TF gây lỗi thì TF được giữ lại |
| Unicorn dừng im lặng ở lệnh không hợp lệ | Không chạy khối nào thì coi là `ILLEGAL_INSTRUCTION` |
| Handler AV đọc `ExceptionInformation[0..1]` | Điền loại truy cập và địa chỉ lỗi |
| Mã độc cố tình gây AV ở địa chỉ < 0x10000 | GDT đặt ở 0x7FE00000, vùng thấp để trống |
| Handler kiểm tra Dr0–Dr7 | `CONTEXT` có Dr = 0 |
| Gọi `API+5` để né hook (tự làm prologue, hoặc wrapper `push` một dword) | `on_stub` nhận slot+5: khôi phục EBP nếu EBP==ESP, nếu không thì bỏ dword đã push |
| Dựng lại số syscall bằng cách dò mẫu `90 90 90 90 B8 .. BA <KiFastSystemCall> .. C2` | Stub Nt/Zw đúng mẫu đó. Số SSN k là stub Nt/Zw thứ k (`NTLIST`) |
| Quét toàn bộ không gian nhớ bằng `NtQueryVirtualMemory` | Trả MBI thật theo `mem_regions()` (có cache) |
| Tìm section `.data` của ntdll theo tên để vá con trỏ | DLL giả có 7 section như DLL thật |
| Đọc `windir=`/`TEMP=` từ khối environment | Khối environment UTF-16 ở `PEB->ProcessParameters+0x48` |
| Cha chờ con trỏ trong ntdll của con đổi giá trị (`Kernel32ThreadInitThunkFunction`) | Sau `NtResumeThread`, lần đọc 4 byte thứ 4 trở đi được XOR với `--poll-xor` |
| Loader đọc PE header của chính exe (EntryPoint, e_lfanew) rồi ghi vào `ImageBase-1` → AV không ai xử lý | Luôn truyền `--exe` là file exe gốc. Thiếu `--exe` thì winemu in cảnh báo |
| `--chain-child` dùng `execv`, nên `atexit` của tiến trình cha không chạy | Gọi `atexit._run_exitfuncs()` trước `execv` |
| `--ring` ghi lại từng lệnh, làm vòng quét bộ nhớ chậm hơn nhiều lần (cha chạy hơn 1 giờ 40 phút thay vì khoảng 27 phút) | Chỉ bật `--ring` khi `--resume` từ snapshot ngay trước điểm cần xem, không bật cho cả lần chạy |
| `api_unused` sau khi loader giải mã payload chứa cả `Reg*`/`CopyFileW`… | Đó thường là **import table của payload** do loader tự resolve, không phải hành vi của loader. Phải đối chiếu với import của PE vừa giải mã (bằng pefile) trước khi kết luận persistence. |
| `/tmp` (tmpfs) đầy | Đặt `--out` trên đĩa thật. Snapshot và `child_mem.bin` mỗi file khoảng 27 MB |

## Kiểm tra

Sau mỗi lần sửa lõi, chạy lại bài hồi quy trên một mẫu chuẩn đã có mốc kết quả (hash stage giải mã, URL, chuỗi). Bài hồi quy cần mẫu thật nên giữ ngoài skill. Kết quả lệch so với mốc nghĩa là bản sửa đã làm hỏng thứ khác.

## Giới hạn

- Chỉ hỗ trợ x86-32. Loader 64-bit cần thêm TEB/PEB 64-bit và hàm gọi theo quy ước x64.
- DLL là DLL giả: chỉ có tên export, không có mã. API nào cần kết quả thật phải tự mô phỏng trong `api()`.
- Hành vi phụ thuộc môi trường (đếm cửa sổ, thời gian, phần cứng) có thể khác máy thật. Báo cáo cần ghi rõ phần nào quan sát qua giả lập.
