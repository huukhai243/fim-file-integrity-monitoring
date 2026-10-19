# FIM Project v2.0

**Đề tài 5:** Hệ thống giám sát toàn vẹn file & phát hiện thay đổi bất thường (File Integrity Monitoring - FIM)

## Đối chiếu yêu cầu

| Phần | Yêu cầu | Hiện thực | Module |
|---|---|---|---|
| 1 | Baseline hash toàn bộ file quan trọng | SHA-256 + size/mtime/permission/chủ sở hữu (uid, gid), lưu SQLite | `fim/core.py`, `fim/database.py` |
| 1 | Theo dõi thay đổi (inotify/polling) | `watchdog` (dùng inotify trên Linux), tự chuyển sang polling nếu thiếu; quét lại toàn bộ định kỳ | `fim/service.py` |
| 2 | Phân loại hợp lệ vs đáng ngờ | Heuristic chấm điểm → `LEGITIMATE` / `SUSPICIOUS` | `fim/rules.py` |
| 2 | Whitelist | `ignore` (không theo dõi) và `allow` (thay đổi được phép, không cảnh báo) | `fim/rules.py`, `fim/database.py` |
| 2 | Tạo alert | Bảng `alerts` (NEW/ACK), console có màu, `logs/fim.log`, `logs/alerts.log` (JSON lines) | `fim/service.py` |
| 3 | Scope theo thư mục hệ thống | Nhiều `watch_paths`, đánh dấu `critical`; có sẵn `config.linux.json` cho `/etc`, `/bin`, `/usr/bin`, `/boot`... | `config*.json` |
| 3 | Quản lý whitelist | CLI `whitelist add/remove/list` + trang Whitelist trên dashboard | `fim/cli.py`, `fim/dashboard.py` |
| 3 | Dashboard lịch sử thay đổi | Web Flask: tổng quan, biểu đồ, lịch sử có bộ lọc, alert, whitelist, phạm vi | `fim/dashboard.py`, `fim/templates/` |

## Kiến trúc
```text
                 watch_paths (etc, bin, var/log, home ...)
                                  │
             watchdog/inotify ────┤──── polling (fallback)
                                  ▼
  Scanner (core.py) ── SHA-256 + metadata ── whitelist ignore
                                  │
  Compare với baseline / current state ──► CREATED | MODIFIED | DELETED | MOVED
                                           PERMISSION_CHANGED | OWNER_CHANGED | TIMESTAMP_CHANGED
                                  │
  Rules (rules.py): heuristic score ─► LOW/MEDIUM/HIGH ─► whitelist allow? ─► LEGITIMATE | SUSPICIOUS
                                  │
  SQLite (events, alerts, whitelist, baseline) ─► CLI  /  Web dashboard  /  fim.log  /  alerts.log
```

## Chạy bằng Docker (môi trường nộp bài)
Cần Docker Desktop (Windows) hoặc Docker Engine (Ubuntu). Container chạy trên nhân Linux nên dùng được inotify và kiểm tra quyền Unix (setuid, chmod).
```bash
docker compose up -d --build                      # build image, chạy 2 container: fim-monitor, fim-dashboard
docker compose logs -f monitor                    # xem cảnh báo thời gian thực (Ctrl+C để thoát xem log)
# Dashboard: http://127.0.0.1:5000
docker compose exec monitor sh tools/demo_attack.sh        # kịch bản vận hành: 8 thay đổi hợp lệ + tấn công
docker compose exec monitor python main.py alerts          # mọi lệnh CLI chạy được qua exec
docker compose exec monitor python -m unittest discover -s tests
docker run --rm -v "${PWD}/docs:/out" fim-project:2.0 python tools/benchmark.py --out /out/benchmark_results_linux.md   # đo đạc trên Linux (đủ 20 kịch bản, RQ1-RQ3)
docker compose exec monitor cat /etc/os-release            # phiên bản hệ điều hành cho báo cáo
docker compose down                               # dừng
docker compose down -v                            # dừng và xóa dữ liệu: DB, log, thư mục demo về trạng thái gốc
```
Thư mục giám sát trong container là volume `fim-watch` (bản sao của `test_folder`), nên muốn tạo thay đổi thì dùng `docker compose exec`, sửa `test_folder` trên máy host không ảnh hưởng tới container.

## Cài đặt không dùng Docker
Ubuntu:
```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip
cd FIM_Project
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```
Windows PowerShell:
```powershell
cd FIM_Project
py -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Lệnh
| Lệnh | Mô tả |
|---|---|
| `python main.py init` | Tạo baseline |
| `python main.py scan [--record]` | So sánh với baseline (`--record`: ghi vào lịch sử + tạo alert) |
| `python main.py monitor` | Giám sát thời gian thực |
| `python main.py events [--limit N] [--level HIGH] [--verdict SUSPICIOUS]` | Lịch sử thay đổi |
| `python main.py alerts [--all]` | Cảnh báo (mặc định chỉ hiện NEW) |
| `python main.py ack ID... \| --all` | Đánh dấu đã xử lý alert |
| `python main.py accept --path FILE \| --all` | Chấp nhận thay đổi vào baseline |
| `python main.py whitelist [list]` | Xem whitelist |
| `python main.py whitelist add "*.bak" [--kind allow --events MODIFIED --note "..."]` | Thêm rule |
| `python main.py whitelist remove ID` | Xóa rule |
| `python main.py scope` | Các thư mục giám sát + số file trong baseline |
| `python main.py dashboard [--port 5000]` | Web dashboard tại http://127.0.0.1:5000 |

Dùng config khác: `python main.py --config config.linux.json <lệnh>`.

## Phân loại & chấm điểm

| Heuristic | Điểm |
|---|---:|
| CREATED / MODIFIED / MOVED / DELETED | +1 / +2 / +2 / +3 |
| PERMISSION_CHANGED / OWNER_CHANGED (chown) | +2 / +3 |
| Thời gian sửa bị lùi về quá khứ (timestomp, MITRE T1070.006) | +4 |
| Chỉ thời gian sửa tiến lên, nội dung giữ nguyên (`touch`) | 0, `LEGITIMATE` |
| Nằm trong thư mục `critical` (vd. `/etc`, `/bin`) | +2 |
| Đường dẫn nhạy cảm (`*.conf`, `passwd`, `shadow`, `sudoers`, `authorized_keys`...) | +3 |
| File thực thi / script (`.sh`, `.py`, `.so`...) | +2 |
| Đuôi kiểu ransomware (`.locked`, `.encrypted`...) | +4 |
| Đổi đuôi file khi đổi tên | +2 |
| File ẩn mới (tên bắt đầu bằng `.`) | +2 |
| File bị làm rỗng (size → 0) | +2 |
| Thêm quyền thực thi / setuid-setgid / world-writable *(Linux)* | +3 / +4 / +3 |
| Ngoài giờ làm việc (`work_hours`, mặc định 7h-19h) | +1 |
| Thay đổi hàng loạt (≥ `mass_change_threshold` file đổi trong cửa sổ `mass_change_window_seconds`, mặc định 10 file / 60 giây) | +3 |

- Mức: `0-2 LOW`, `3-4 MEDIUM`, `≥5 HIGH`.
- Kết luận: `SUSPICIOUS` nếu điểm ≥ `suspicious_threshold` (mặc định 3, tức MEDIUM trở lên) → **tạo alert**. Ngược lại `LEGITIMATE`.
- Rule whitelist `allow` khớp (pattern + loại sự kiện) → `LEGITIMATE`, vẫn ghi vào lịch sử nhưng không alert. Ví dụ `*.log` với `CREATED,MODIFIED`: log được ghi thêm là bình thường, nhưng **xóa** log vẫn bị cảnh báo.
- Whitelist **không che được** 4 dấu hiệu nghiêm trọng: làm rỗng file, bật setuid/setgid, đuôi kiểu ransomware, lùi thời gian sửa. Ví dụ làm rỗng `app.log` (xóa dấu vết) vẫn bị cảnh báo dù khớp `allow *.log`.
- Rule `ignore`: file không được đưa vào baseline (file tạm, cache...).

## Kịch bản demo (Ubuntu, dùng `test_folder`)
`test_folder` mô phỏng cây thư mục hệ thống: `etc/` và `bin/` là critical, `var/log/` và `home/` là thường.

```bash
python main.py init
python main.py monitor            # Terminal 1
python main.py dashboard          # Terminal 2, mở http://127.0.0.1:5000
```
Terminal 3:
```bash
echo "note" > test_folder/home/user/todo.txt            # LEGITIMATE / LOW
echo "more" >> test_folder/var/log/app.log               # LEGITIMATE (whitelist allow *.log)
echo "PermitRootLogin yes" >> test_folder/etc/config.conf # SUSPICIOUS / HIGH
chmod u+s test_folder/bin/script.sh                       # SUSPICIOUS / HIGH (setuid)
echo "x" > test_folder/home/user/.backdoor                # file ẩn
mv test_folder/home/user/README.txt test_folder/home/user/README.txt.locked   # MOVED + ransomware ext
for i in $(seq 1 12); do echo $i > test_folder/home/user/f$i.txt; done       # mass change
rm test_folder/var/log/app.log                            # xóa log -> vẫn alert
```
Sau đó trên dashboard: xem Tổng quan → Cảnh báo (bấm *Xác nhận* hoặc *Chấp nhận vào baseline*) → Lịch sử (lọc SUSPICIOUS) → Whitelist (thêm rule) → Phạm vi giám sát.

CLI tương đương: `python main.py alerts`, `python main.py events --verdict SUSPICIOUS`, `python main.py ack --all`.

## Giám sát thư mục hệ thống thật (Ubuntu)
```bash
sudo .venv/bin/python main.py --config config.linux.json init
sudo .venv/bin/python main.py --config config.linux.json monitor
sudo .venv/bin/python main.py --config config.linux.json dashboard
# thử: sudo touch /etc/fim_test.conf ; sudo chmod 777 /etc/fim_test.conf ; sudo rm /etc/fim_test.conf
```
Cần `sudo` để đọc được `/etc/shadow`, `/root/.ssh`... File không đọc được sẽ bị bỏ qua và ghi vào log. Nếu giám sát nhiều thư mục mà gặp lỗi giới hạn inotify: `sudo sysctl fs.inotify.max_user_watches=524288`.

## Kiểm thử & đo đạc
```bash
python -m unittest discover -s tests -v     # 46 unit test
python tools/benchmark.py                   # đo đạc (khoảng 8 phút), ghi kết quả ra docs/benchmark_results.md (--quick: bản nhanh)
```
`tools/benchmark.py` gồm 6 phần:
1. Tốc độ quét: full / quick scan với 100 đến 10.000 file.
2. Độ trễ phát hiện: watchdog so với polling, 20 lần đo mỗi loại.
3. Độ chính xác phân loại trên 20 kịch bản hợp lệ / tấn công (4 kịch bản về quyền, chủ sở hữu chỉ chạy trên Linux; chown cần root), kèm so sánh với cách chỉ so mã băm.
4. RQ1: chỉ giám sát thời gian thực so với thời gian thực + quét toàn bộ định kỳ, với thay đổi "lén" (giữ nguyên kích thước, trả lại thời gian sửa cũ).
5. RQ2: M0 (mọi thay đổi đều là cảnh báo) so với M1 (thêm whitelist, chấm điểm, accept) trên khối lượng công việc mô phỏng một ngày.
6. RQ3: CPU và RAM của tiến trình monitor với 100 / 500 / 1.000 / 5.000 file (chỉ Linux).

## Tài liệu cho báo cáo
- `docs/diagrams.md`: mã nguồn Mermaid của sơ đồ kiến trúc, triển khai, tuần tự, hoạt động, cơ sở dữ liệu.
- `docs/diagrams/*.svg`: 4 sơ đồ use case (tổng quan + 3 phân rã), chèn thẳng vào Word.
- `docs/benchmark_results_linux.md`: kết quả đo trong Docker (Debian 13, inotify), đủ 20 kịch bản và RQ1-RQ3, dùng cho báo cáo.
- `docs/benchmark_results.md`: kết quả đo trên máy phát triển Windows (để so sánh).

## Ghi chú kỹ thuật
- **Quick scan / full scan:** khi `monitor` phát hiện sự kiện, file có size + mtime không đổi sẽ dùng lại hash cũ để nhanh hơn. Cứ mỗi `full_scan_interval_seconds` hệ thống hash lại toàn bộ để bắt trường hợp kẻ tấn công giả mạo mtime. `init` / `scan` / `accept` luôn hash lại toàn bộ.
- **Debounce có giới hạn:** monitor chờ các sự kiện lắng xuống `debounce_seconds` rồi mới quét, nhưng không chờ quá `max_event_delay_seconds` (mặc định 2 giây). Nhờ vậy một file bị ghi liên tục (log) không làm monitor trì hoãn việc quét mãi mãi.
- **Dashboard chống CSRF:** mọi form POST có token lưu trong phiên (cookie `SameSite=Strict`), nên một trang web lạ mở trong cùng trình duyệt không thể gửi lệnh chấp nhận baseline hay thêm whitelist.
- **So sánh inotify và polling:** đặt `"force_polling": true` trong config để buộc `monitor` dùng polling.
- **Phát hiện đổi tên:** một file bị xóa và một file mới có cùng SHA-256 trong cùng lần quét → `MOVED`.
- **Chủ sở hữu và thời gian sửa:** baseline lưu uid/gid, đổi chủ sở hữu → `OWNER_CHANGED`. Nếu chỉ thời gian sửa thay đổi → `TIMESTAMP_CHANGED`: tiến lên (`touch`) là hợp lệ, lùi về quá khứ là dấu hiệu che giấu thay đổi (timestomp) và luôn bị cảnh báo.
- **Thay đổi hàng loạt theo cửa sổ thời gian:** đếm số file có thời gian sửa cách nhau không quá `mass_change_window_seconds`, không đếm cả lần quét. Nhờ vậy `scan` đối chiếu baseline sau nhiều ngày không coi các thay đổi rải rác là "hàng loạt".
- **Bảo vệ CSDL:** trên Linux, file CSDL chỉ chủ sở hữu đọc/ghi được (quyền 600). Monitor chỉ ghi lại các dòng thay đổi của bảng `current_state` thay vì ghi lại cả bảng sau mỗi lần quét.
- Trên Windows, `st_mode` không phản ánh quyền thật nên các heuristic về quyền chỉ bật trên Linux (`check_unix_permissions`).
- Dashboard chỉ lắng nghe `127.0.0.1` và không có đăng nhập. Đây là công cụ nội bộ, không nên mở ra mạng ngoài.
- DB của phiên bản cũ được tự nâng cấp (thêm cột) khi mở; file trong baseline cũ chưa có uid/gid sẽ không bị báo nhầm là đổi chủ sở hữu.

## Phạm vi
Đây là prototype học tập, không thay thế AIDE/Tripwire/Wazuh hoặc giải pháp FIM doanh nghiệp. Hạn chế: không chống được root đã chiếm quyền (có thể sửa cả DB baseline), chưa ký/kiểm tra toàn vẹn chính DB, chưa gửi cảnh báo qua email/Telegram.
