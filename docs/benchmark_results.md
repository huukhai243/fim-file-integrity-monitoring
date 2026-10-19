# Kết quả kiểm thử & đo đạc FIM

## Môi trường đo

| Thông số | Giá trị |
|---|---|
| Thời điểm đo | 2026-10-17 00:28 |
| Hệ điều hành | Windows-11-10.0.26200-SP0 |
| CPU | Intel64 Family 6 Model 189 Stepping 1, GenuineIntel (8 luồng) |
| Python | 3.13.15 |
| SQLite | 3.50.4 |
| watchdog | 6.0.0 |
| Flask | 3.1.3 |
| FIM | 2.0.0 |

## 1. Hiệu năng quét

Full scan = đọc và tính SHA-256 toàn bộ file (dùng cho `init`, `scan`, `accept`). Quick scan = chỉ hash lại file có size/mtime thay đổi (dùng khi `monitor` nhận sự kiện). Đo khi file đã nằm trong page cache của hệ điều hành. Với file nhỏ, chi phí mở file chiếm phần lớn (trên Windows còn bị phần mềm diệt virus quét khi mở file), nên tốc độ tính theo file/s quan trọng hơn MB/s.

| Số file | Kích thước/file | Tổng dung lượng | Full scan (s) | Tốc độ (file/s) | Thông lượng (MB/s) | Quick scan (s) | Quick nhanh hơn |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 100 | 4 KB | 0.4 MB | 0.073 | 1,369 | 5.3 | 0.005 | 14.4x |
| 500 | 4 KB | 2.0 MB | 0.385 | 1,299 | 5.1 | 0.009 | 43.4x |
| 1,000 | 4 KB | 3.9 MB | 0.998 | 1,002 | 3.9 | 0.255 | 3.9x |
| 5,000 | 4 KB | 19.5 MB | 5.762 | 868 | 3.4 | 0.112 | 51.4x |
| 10,000 | 4 KB | 39.1 MB | 11.819 | 846 | 3.3 | 0.251 | 47.0x |
| 20 | 5 MB | 100.0 MB | 0.146 | 137 | 686.6 | 0.001 | 134.5x |

## 2. Độ trễ phát hiện

Từ lúc ghi vào `etc/app.conf` đến lúc sự kiện xuất hiện trong bảng `events`. `debounce_seconds = 0.5`, `poll_interval_seconds = 1.0`.

| Cơ chế | Số lần đo | Phát hiện | Min (s) | Trung bình (s) | Trung vị (s) | P95 (s) | Max (s) |
|---|---:|---:|---:|---:|---:|---:|---:|
| watchdog (ReadDirectoryChangesW) | 20 | 20/20 | 0.529 | 0.621 | 0.602 | 0.704 | 0.727 |
| polling | 20 | 20/20 | 0.023 | 0.467 | 0.453 | 0.940 | 1.016 |

## 3. Độ chính xác phân loại

Mỗi kịch bản chạy trên môi trường sạch: tạo baseline → thực hiện hành động → `scan`. `work_hours = [0, 24]` để loại yếu tố giờ làm việc.

| # | Kịch bản | Mong đợi | Thực tế | Điểm | Kết quả |
|---:|---|---|---|---:|:---:|
| 1 | Tạo ghi chú mới trong home | CREATED / LEGITIMATE | CREATED / LEGITIMATE | 1 | ✅ |
| 2 | Sửa ghi chú trong home | MODIFIED / LEGITIMATE | MODIFIED / LEGITIMATE | 2 | ✅ |
| 3 | Ứng dụng ghi thêm log | MODIFIED / LEGITIMATE | MODIFIED / LEGITIMATE | 2 | ✅ |
| 4 | Tạo file log mới (log rotation) | CREATED / LEGITIMATE | CREATED / LEGITIMATE | 1 | ✅ |
| 5 | Tạo file tạm *.tmp (whitelist ignore) | không có sự kiện | không có sự kiện | - | ✅ |
| 6 | touch: chỉ cập nhật thời gian sửa | TIMESTAMP_CHANGED / LEGITIMATE | TIMESTAMP_CHANGED / LEGITIMATE | 0 | ✅ |
| 7 | Sửa file cấu hình trong etc | MODIFIED / SUSPICIOUS | MODIFIED / SUSPICIOUS | 7 | ✅ |
| 8 | Tạo file cấu hình mới trong etc | CREATED / SUSPICIOUS | CREATED / SUSPICIOUS | 6 | ✅ |
| 9 | Thay thế chương trình trong bin | MODIFIED / SUSPICIOUS | MODIFIED / SUSPICIOUS | 9 | ✅ |
| 10 | Xóa chương trình trong bin | DELETED / SUSPICIOUS | DELETED / SUSPICIOUS | 10 | ✅ |
| 11 | Tạo file ẩn (backdoor) trong home | CREATED / SUSPICIOUS | CREATED / SUSPICIOUS | 3 | ✅ |
| 12 | Đổi tên file sang .locked (ransomware) | MOVED / SUSPICIOUS | MOVED / SUSPICIOUS | 8 | ✅ |
| 13 | Tạo 12 file .enc cùng lúc | CREATED / SUSPICIOUS | CREATED / SUSPICIOUS | 8 | ✅ |
| 14 | Xóa file log (xóa dấu vết) | DELETED / SUSPICIOUS | DELETED / SUSPICIOUS | 3 | ✅ |
| 15 | Làm rỗng file log (xóa dấu vết) | MODIFIED / SUSPICIOUS | MODIFIED / SUSPICIOUS | 4 | ✅ |
| 16 | Lùi thời gian sửa về 2020 (timestomp) | TIMESTAMP_CHANGED / SUSPICIOUS | TIMESTAMP_CHANGED / SUSPICIOUS | 9 | ✅ |
| 17 | chmod 600 ghi chú (thu hẹp quyền) | PERMISSION_CHANGED / LEGITIMATE | *chỉ chạy trên Linux* | - | N/A |
| 18 | chmod +x file trong home | PERMISSION_CHANGED / SUSPICIOUS | *chỉ chạy trên Linux* | - | N/A |
| 19 | chmod u+s script trong bin (setuid) | PERMISSION_CHANGED / SUSPICIOUS | *chỉ chạy trên Linux* | - | N/A |
| 20 | chown đổi chủ sở hữu file cấu hình | OWNER_CHANGED / SUSPICIOUS | *cần quyền root* | - | N/A |

**Ma trận nhầm lẫn** (16 kịch bản đã chạy, bỏ qua 4 kịch bản cần Linux hoặc quyền root):

| | Hệ thống báo SUSPICIOUS | Hệ thống báo LEGITIMATE / không báo |
|---|---:|---:|
| **Thực tế là tấn công** | TP = 10 | FN = 0 |
| **Thực tế là hợp lệ** | FP = 0 | TN = 6 |

- Accuracy = 100%  ·  Precision = 100%  ·  Recall = 100%
- Số kịch bản đúng hoàn toàn (đúng cả loại sự kiện và kết luận): 16/16
- Lưu ý: bộ kịch bản được thiết kế cùng với các luật heuristic, nên kết quả cho thấy các luật hoạt động đúng như thiết kế, không phản ánh khả năng phát hiện kỹ thuật tấn công mới chưa có luật.

### Chỉ so mã băm (hash-only) so với mã băm + metadata

Hash-only chỉ so mã băm nội dung và sự có mặt của file; hệ thống hiện tại so thêm quyền, chủ sở hữu và thời gian sửa. Bảng chỉ liệt kê các kịch bản mà hai cách cho kết quả khác nhau.

| Kịch bản | Thực tế | Hash-only | Hash + metadata |
|---|---|---|---|
| touch: chỉ cập nhật thời gian sửa | hợp lệ | không phát hiện | TIMESTAMP_CHANGED / LEGITIMATE |
| Lùi thời gian sửa về 2020 (timestomp) | tấn công | không phát hiện | TIMESTAMP_CHANGED / SUSPICIOUS |

- Kịch bản tấn công được phát hiện: hash-only 9/10, hash + metadata 10/10.

## 4. RQ1: giám sát thời gian thực và quét toàn bộ định kỳ

Mỗi cấu hình thực hiện liên tiếp 10 thao tác cho mỗi loại tạo, sửa, xóa, đổi tên, cùng 10 lần sửa "lén" (ghi nội dung khác nhưng cùng kích thước, rồi trả lại đúng thời gian sửa cũ). Quick scan dựa vào kích thước và thời gian sửa để quyết định có băm lại file hay không.

| Cấu hình | Tạo | Sửa | Xóa | Đổi tên | Sửa lén | Bỏ sót | Độ trễ TB (thường) | Độ trễ TB (lén) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| A. Chỉ thời gian thực | 10/10 | 10/10 | 10/10 | 10/10 | 0/10 | 10/50 | 0.82 s | – |
| B. Thời gian thực + quét toàn bộ mỗi 4 s | 10/10 | 10/10 | 10/10 | 10/10 | 10/10 | 0/50 | 0.90 s | 2.69 s |

## 5. RQ2: M0 so với M1

M0 = phát hiện thay đổi bằng hash + metadata, mọi thay đổi đều là cảnh báo. M1 = M0 + whitelist + chấm điểm rủi ro + quy trình accept. Khối lượng công việc mô phỏng một ngày: 34 thao tác (mỗi thao tác cách nhau 10 phút giả lập).

| Nhóm thao tác | Số thao tác | Cảnh báo M0 | Cảnh báo M1 |
|---|---:|---:|---:|
| Thường ngày (không cần cảnh báo) | 25 | 25 | 0 |
| Bảo trì có kế hoạch (cần xem, rồi accept) | 2 | 2 | 2 |
| Tấn công (bắt buộc cảnh báo) | 7 | 18 | 18 |
| **Tổng** | 34 | **45** | **20** |

- Giảm số cảnh báo cần xem xét: **56%** (từ 45 xuống 20); 18/20 cảnh báo của M1 ở mức HIGH.
- Thay đổi nhạy cảm (bảo trì + tấn công) bị bỏ sót: **0**.
- Thao tác thường ngày bị cảnh báo nhầm: **0**.
- Kiểm tra định kỳ cuối ngày (đối chiếu baseline): M0 báo 32 khác biệt, M1 báo 18 cảnh báo; 2 thay đổi bảo trì đã được accept nên không bị báo lại.

<details><summary>Chi tiết từng thao tác</summary>

| # | Thao tác | Nhóm | M0 | M1 |
|---:|---|---|---:|---:|
| 1 | Ứng dụng ghi log lần 1 | routine | 1 | 0 |
| 2 | Ứng dụng ghi log lần 2 | routine | 1 | 0 |
| 3 | Ứng dụng ghi log lần 3 | routine | 1 | 0 |
| 4 | Ứng dụng ghi log lần 4 | routine | 1 | 0 |
| 5 | Ứng dụng ghi log lần 5 | routine | 1 | 0 |
| 6 | Ứng dụng ghi log lần 6 | routine | 1 | 0 |
| 7 | Ứng dụng ghi log lần 7 | routine | 1 | 0 |
| 8 | Ứng dụng ghi log lần 8 | routine | 1 | 0 |
| 9 | Ứng dụng ghi log lần 9 | routine | 1 | 0 |
| 10 | Ứng dụng ghi log lần 10 | routine | 1 | 0 |
| 11 | Tạo log mới access.log | routine | 1 | 0 |
| 12 | Tạo log mới error.log | routine | 1 | 0 |
| 13 | Người dùng sửa tài liệu d0 | routine | 1 | 0 |
| 14 | Người dùng sửa tài liệu d1 | routine | 1 | 0 |
| 15 | Người dùng sửa tài liệu d2 | routine | 1 | 0 |
| 16 | Người dùng sửa tài liệu d3 | routine | 1 | 0 |
| 17 | Người dùng sửa tài liệu d4 | routine | 1 | 0 |
| 18 | Người dùng sửa tài liệu d5 | routine | 1 | 0 |
| 19 | Trình soạn thảo tạo file tạm d0.txt.swp | routine | 1 | 0 |
| 20 | Trình soạn thảo tạo file tạm d1.txt.swp | routine | 1 | 0 |
| 21 | Trình soạn thảo tạo file tạm build.tmp | routine | 1 | 0 |
| 22 | Trình soạn thảo tạo file tạm cache.tmp | routine | 1 | 0 |
| 23 | touch tài liệu d4 | routine | 1 | 0 |
| 24 | touch tài liệu d5 | routine | 1 | 0 |
| 25 | Người dùng tạo tài liệu mới | routine | 1 | 0 |
| 26 | Bảo trì: cập nhật etc/ntp.conf | maintenance | 1 | 1 |
| 27 | Bảo trì: cập nhật bin/backup.sh | maintenance | 1 | 1 |
| 28 | Tấn công: bật PermitRootLogin | attack | 1 | 1 |
| 29 | Tấn công: tạo etc/evil.conf | attack | 1 | 1 |
| 30 | Tấn công: file ẩn .backdoor | attack | 1 | 1 |
| 31 | Tấn công: đổi tên sang .locked | attack | 1 | 1 |
| 32 | Tấn công: mã hóa 12 file .enc | attack | 12 | 12 |
| 33 | Tấn công: làm rỗng app.log | attack | 1 | 1 |
| 34 | Tấn công: lùi thời gian sửa etc/ntp.conf | attack | 1 | 1 |

</details>

## 6. RQ3: CPU và RAM của tiến trình monitor

*Chỉ đo được trên Linux (đọc /proc). Xem kết quả đo trong Docker: `docs/benchmark_results_linux.md`.*
