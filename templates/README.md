# Báo cáo phân tích: `{CASE}`

> Ngày bắt đầu: {DATE}. Quy trình: `tools/FLOW.md`.
>
> Phương pháp (mỗi kết luận ghi rõ một trong các nguồn sau):
> - **S**: phân tích tĩnh trên file gốc (triage, rea/Ghidra, script tự viết).
> - **E**: phân tích động bằng giả lập CPU (winemu/Unicorn, OS giả, không mạng). Nếu đọc tĩnh trên artefact do giả lập sinh ra (bản dump, keystream) thì vẫn ghi E.
> - **V**: VM/sandbox bên ngoài.
>
> Không chạy mẫu trên hệ điều hành thật. Không gửi request nào tới C2 hay hạ tầng phát tán.
>
> Trạng thái: _(đang phân tích / hoàn tất tới …)_. Xem `tools/flow.py status` để biết mục nào còn thiếu.

## 1. Tóm tắt

| Mục | Kết quả | Nguồn |
|---|---|---|
| Loại / họ mã độc | | |
| Cơ chế chính | | |
| IOC mạng | | |
| Persistence | | |

## 2. Mẫu và hash

Bảng hash đầy đủ nằm trong [`GENERATED.md`](GENERATED.md) (sinh từ `../facts.jsonl`).

## 3. Chuỗi thực thi

```
(sơ đồ từ điểm vào tới payload cuối)
```

## 4. Phân tích chi tiết

_(mỗi mục ghi nguồn S/E/V và trỏ tới file evidence + dòng)_

## 5. Bảng rà soát và đính chính

| Vòng | Nội dung trước | Kết luận sau rà soát |
|---|---|---|

Phần đính chính sinh tự động từ các fact `retracted`/`supersedes` nằm trong `GENERATED.md`.

## 6. IOC

Xem `GENERATED.md` (mục IOC). IOC ứng viên lấy từ strings mà chưa được chứng minh thì để `hypothesis`, không đưa vào danh sách chặn.

## 7. Khuyến nghị

## 8. Hạn chế và OPSEC

- Phần nào chỉ có nguồn E thì ghi rõ: hành vi trong giả lập có thể khác trên máy thật.
- Liệt kê các mục checklist còn `partial`/`missing` và lý do.
- OPSEC: đã/chưa có request mạng nào, có dùng nguồn ngoài nào.

## 9. Evidence (`report/evidence/`)

| File | Nội dung |
|---|---|
