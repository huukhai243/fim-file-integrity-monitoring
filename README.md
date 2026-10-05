# FIM — Hệ thống giám sát toàn vẹn file

Phát hiện file hệ thống bị sửa đổi trái phép, phân biệt thay đổi hợp lệ với thay
đổi đáng ngờ, và hiển thị lịch sử trên dashboard.

Cùng họ với Tripwire / AIDE / OSSEC, nhưng gọn hơn và **giải thích được**: mỗi
cảnh báo luôn kèm danh sách luật đã khớp cùng điểm số, nên người vận hành biết
chính xác *vì sao* một thay đổi bị coi là nguy hiểm.

---

## Chạy thử trong 30 giây

```bash
pip install -r requirements.txt
python scripts/demo.py
```

Demo dựng một cây thư mục giả trong `%TEMP%`, chốt baseline, rồi mô phỏng 7 thay
đổi — 2 hợp lệ và 5 đáng ngờ — và in ra kết quả phân loại. Không đụng vào file
hệ thống thật, không cần quyền quản trị.

Kết quả mong đợi:

```
MỨC        ĐIỂM  LOẠI      ĐƯỜNG DẪN
critical     95  modified  /usr/bin/helper          ← sửa nội dung, giữ nguyên mtime
critical     85  deleted   /etc/hosts               ← xoá file trọng yếu
critical     85  modified  /root/.ssh/authorized_keys ← cài khoá SSH lạ
high         65  created   /etc/cron.d/backup       ← cron job mới
low          25  created   /tmp/update.sh           ← script thực thi mới
info          0  modified  /var/log/app.log         ← ghi log, hợp lệ
info          0  modified  /etc/app.conf            ← đổi cấu hình, hợp lệ
```

---

## Phân chia công việc

Ba người làm song song trên ba package tách biệt. Ranh giới giữa các package là
các kiểu dữ liệu trong [`models.py`](src/fim/models.py) — **đổi file đó phải báo
cả nhóm**, còn sửa bên trong package của mình thì không ảnh hưởng ai.

```
Người 1 (collector)  ──►  Người 2 (analysis)  ──►  Người 3 (scope + web)
 phát hiện thay đổi        phân loại + cảnh báo      lưu trữ + hiển thị
```

### Người 1 — Baseline hash và theo dõi thay đổi

📁 [`src/fim/collector/`](src/fim/collector/)

| File | Nội dung |
|---|---|
| [`hashing.py`](src/fim/collector/hashing.py) | Băm file theo khối, chụp metadata, entropy, nhận diện magic bytes |
| [`baseline.py`](src/fim/collector/baseline.py) | Quét toàn bộ phạm vi, băm song song nhiều luồng, ghi baseline |
| [`differ.py`](src/fim/collector/differ.py) | So trạng thái hiện tại với baseline → sinh `ChangeEvent` |
| [`watcher.py`](src/fim/collector/watcher.py) | Theo dõi realtime (inotify / ReadDirectoryChangesW) và polling |

Điểm cần nắm:

- **Không đi theo symlink.** Một symlink bị trỏ sang nơi khác chính là thay đổi
  cần bắt; đi theo nó sẽ băm nhầm file đích và bỏ lọt tấn công. Digest của
  symlink được tính từ chính đường dẫn đích.
- **Realtime vẫn quét lại định kỳ.** inotify có hạn mức watch của nhân và có thể
  rơi sự kiện khi hàng đợi tràn, nên `rescan_after` là lưới an toàn bắt buộc.
- **Gộp sự kiện (debounce).** Một lần lưu file của trình soạn thảo sinh ra cả
  chuỗi create/modify/rename; không gộp thì một thao tác thành 4–5 cảnh báo.
- Lỗi đọc một file không làm hỏng cả lần quét — ghi vào `FileRecord.error` rồi đi tiếp.

### Người 2 — Phân loại hợp lệ / đáng ngờ và cảnh báo

📁 [`src/fim/analysis/`](src/fim/analysis/)

| File | Nội dung |
|---|---|
| [`heuristics.py`](src/fim/analysis/heuristics.py) | 21 luật chấm điểm, đăng ký qua decorator |
| [`classifier.py`](src/fim/analysis/classifier.py) | Whitelist → chạy luật → cộng điểm → ra mức nghiêm trọng |
| [`alerting.py`](src/fim/analysis/alerting.py) | Tạo cảnh báo và phát ra console / JSONL / webhook |

**Mô hình chấm điểm** thay vì if/else lồng nhau. Mỗi luật độc lập, trả về trọng
số; tổng trọng số ra điểm; điểm ra mức. Chọn cách này vì ba lý do:

1. *Giải trình được* — dashboard hiện đúng luật nào đã khớp, không chỉ phán "đáng ngờ".
2. *Chỉnh được* — báo sai nhiều thì hạ trọng số, không phải sửa logic.
3. *Bằng chứng hai chiều* — trọng số âm kéo điểm xuống, nên file vốn hay thay đổi
   không leo lên mức cao chỉ vì trùng một luật phụ.

Ngưỡng mặc định: `≥30` medium · `≥60` high · `≥85` critical.

Vài luật đáng chú ý (xem đủ bằng `fim rules`):

| ID | Trọng số | Ý nghĩa |
|---|---|---|
| **H020** | +55 | Nội dung đổi nhưng mtime **y nguyên** → timestomping |
| **H010** | +50 | File được gán bit setuid/setgid → leo thang đặc quyền |
| **H003** | +45 | Chạm cron / systemd / authorized_keys → duy trì quyền truy cập |
| **H013** | +45 | File thường bị thay bằng symlink |
| **H001** | +40 | Sửa file trong danh sách trọng yếu |
| **H023** | +40 | Nhiều file đổi cùng lúc → nghi ransomware |
| **H090** | **−60** | Hash trùng danh sách đã duyệt → bằng chứng hợp lệ |
| **H091** | **−20** | Đường dẫn log/cache vốn hay biến động |

> **Vì sao H020 so mtime *bằng chính xác* chứ không dùng sai lệch 1 giây?**
> NTFS và ext4 lưu mtime tới nano giây, nên hai lần ghi khác nhau gần như không
> bao giờ trùng khớp tuyệt đối. Ngược lại, kẻ tấn công gọi `utime()` để khôi phục
> mốc thời gian cũ sẽ tạo ra đúng giá trị y nguyên. Dùng ngưỡng "lệch dưới 1 giây"
> sẽ báo động giả với mọi lần ghi bình thường diễn ra ngay sau lần quét trước.
> Trên POSIX còn kiểm tra thêm ctime — `utime()` đặt lại được mtime nhưng không
> đặt được ctime, nên mtime đứng yên trong khi ctime nhảy là bằng chứng mạnh nhất.

### Người 3 — Phạm vi, whitelist, dashboard

📁 [`src/fim/scope/`](src/fim/scope/) và [`src/fim/web/`](src/fim/web/)

| File | Nội dung |
|---|---|
| [`profiles.py`](src/fim/scope/profiles.py) | Hồ sơ thư mục hệ thống dựng sẵn cho Linux và Windows |
| [`scope.py`](src/fim/scope/scope.py) | Giải include/exclude, duyệt cây thư mục có cắt tỉa |
| [`whitelist.py`](src/fim/scope/whitelist.py) | Nạp YAML, lưu CSDL, tra cứu khi phân loại |
| [`web/app.py`](src/fim/web/app.py) | API FastAPI |
| [`web/static/`](src/fim/web/static/) | Dashboard (HTML/CSS/JS thuần, không framework) |

**Ba quy tắc whitelist** — vi phạm là biến whitelist thành lỗ hổng:

1. **Bắt buộc có `reason`.** Mục không giải thích được sẽ bị sao chép mù sang hệ
   thống khác. Code từ chối mục thiếu lý do.
2. **Viết hẹp nhất có thể.** Ưu tiên `rule_id` để tắt đúng một luật gây nhiễu,
   thay vì miễn trừ cả file — các luật còn lại vẫn bảo vệ file đó.
3. **Ngoại lệ tạm thì đặt `expires_at`** để không quên thu hồi.

Ví dụ quy tắc 2 — logrotate cắt log về 0 byte theo lịch, chỉ tắt luật kích thước:

```yaml
- id: wl-logrotate-size
  match:
    path_glob: "/var/log/**"
    rule_id: H032          # chỉ tắt luật "kích thước bất thường"
  reason: "logrotate cắt log về 0 byte theo lịch"
```

---

## Cài đặt và sử dụng

```bash
pip install -r requirements.txt
python scripts/check_env.py          # kiểm tra môi trường và phạm vi
```

Quy trình thường dùng:

```bash
python -m fim.cli init          # xem phạm vi sẽ giám sát những đâu
python -m fim.cli baseline      # chốt mốc so sánh
python -m fim.cli watch         # theo dõi liên tục
python -m fim.cli serve         # dashboard ở http://127.0.0.1:8000
```

### Toàn bộ lệnh

| Lệnh | Việc |
|---|---|
| `init` | Tạo CSDL, liệt kê thư mục sẽ giám sát |
| `baseline [-l NHÃN]` | Chốt baseline hash |
| `scan` | Quét một lần, so với baseline |
| `watch` | Theo dõi liên tục cho tới khi Ctrl+C |
| `status` | Tình trạng hệ thống |
| `events [-s MỨC] [-p ĐƯỜNG_DẪN] [-H GIỜ]` | Lịch sử thay đổi |
| `explain <ID>` | Giải thích vì sao một sự kiện bị chấm điểm như vậy |
| `approve <ID>...` | Chấp nhận thay đổi, cập nhật vào baseline |
| `alerts [--ack ID]` | Xem và xử lý cảnh báo |
| `rules` | Liệt kê 21 luật kèm trọng số |
| `whitelist list\|add\|remove\|export\|reload` | Quản lý whitelist |
| `serve [--port N]` | Chạy dashboard |

`scan` trả **exit code 2** khi có phát hiện mức critical — dùng được trong cron
hoặc CI để job đỏ khi có bất thường.

### Chấp nhận thay đổi hợp lệ

Sau khi vá hệ thống, baseline phải bắt kịp, nếu không mọi lần quét sau đều báo
lại đúng những thay đổi đó và người vận hành sẽ quen tay bỏ qua cảnh báo thật:

```bash
python -m fim.cli events                 # xem có gì đổi
python -m fim.cli explain 42             # đọc căn cứ
python -m fim.cli approve 42 43 44       # chấp nhận → baseline cập nhật
```

---

## Cấu hình

Toàn bộ nằm ở [`configs/default.yaml`](configs/default.yaml), có chú thích từng
khoá. Vài chỗ hay chỉnh:

```yaml
scope:
  profile: auto              # auto | linux-system | windows-system | custom
  include: ["/opt/myapp"]    # bổ sung thêm vào hồ sơ dựng sẵn
  critical: ["/opt/myapp/config/**"]   # chấm điểm nặng hơn khi đổi

analysis:
  threshold_medium: 30       # nâng lên = ít cảnh báo hơn
  disabled_rules: ["H024"]   # tắt luật "ngoài giờ làm việc"
  rule_weights: {H024: 5}    # hoặc chỉ hạ trọng số

alert:
  min_severity: medium       # thấp hơn thì chỉ lưu, không cảnh báo
  webhook_url: ""            # nối vào Slack/Teams/SIEM
```

Đường dẫn tương đối tính từ thư mục gốc project, không phải thư mục hiện hành.

---

## Kiến trúc

```
                    ┌──────────────┐
   thư mục hệ thống │  Scope       │  Người 3: giám sát ở đâu
                    │  (profiles)  │
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │  Collector   │  Người 1: baseline + phát hiện
                    │ hash/watch   │
                    └──────┬───────┘
                           │ ChangeEvent
                           ▼
                    ┌──────────────┐    ┌───────────┐
                    │  Analysis    │◄───│ Whitelist │  Người 3
                    │ 21 heuristic │    └───────────┘
                    └──────┬───────┘
                           │ Verdict + Alert     Người 2
                           ▼
                    ┌──────────────┐
                    │  SQLite      │
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │  Dashboard   │  Người 3
                    └──────────────┘
```

[`engine.py`](src/fim/engine.py) là nơi duy nhất ghép ba phần lại.
[`store.py`](src/fim/store.py) là kho dữ liệu chung.

Dùng SQLite vì FIM chạy ngay trên máy được giám sát: không thêm dịch vụ ngoài,
file CSDL đi kèm được, và chế độ WAL cho phép dashboard đọc trong khi bộ quét
đang ghi.

---

## Dashboard

```bash
python -m fim.cli serve
```

Năm tab: **Lịch sử thay đổi** (lọc + chọn nhiều để chấp nhận hàng loạt),
**Cảnh báo** (tiếp nhận / đã xử lý / báo sai), **Whitelist** (thêm ngay từ một sự
kiện), **Bộ luật**, **Phạm vi**. Bấm một dòng để mở ngăn chi tiết hiện đầy đủ
trước → sau và từng luật đã cộng/trừ bao nhiêu điểm.

Ghi chú về biểu đồ: biểu đồ chỉ tách **hợp lệ / đáng ngờ** chứ không vẽ đủ 5 mức.
Năm màu mức nằm cạnh nhau không đạt ngưỡng phân biệt tối thiểu — kể cả với người
nhìn màu bình thường, cặp `medium`↔`high` chỉ đạt ΔE 13.6 (sàn là 15). Hai series
hiện dùng đã qua kiểm định đầy đủ ở cả chế độ sáng và tối. Chi tiết từng mức nằm
ở bảng, nơi mỗi nhãn đều có **chữ kèm màu** nên không bao giờ phải đoán qua màu.

> ⚠️ Dashboard **không có xác thực**. Mặc định chỉ nghe `127.0.0.1`. Muốn mở ra
> mạng thì phải đặt sau reverse proxy có xác thực.

---

## Kiểm thử

```bash
python -m pytest -q          # 242 test
```

| File | Phạm vi |
|---|---|
| [`test_util.py`](tests/test_util.py) | Chuẩn hoá đường dẫn, khớp glob `**` |
| [`test_collector.py`](tests/test_collector.py) | Băm, entropy, magic bytes, baseline, differ |
| [`test_analysis.py`](tests/test_analysis.py) | Từng luật một, chấm điểm, whitelist, cảnh báo |
| [`test_scope.py`](tests/test_scope.py) | Hồ sơ, duyệt cây, whitelist YAML |
| [`test_store.py`](tests/test_store.py) | CSDL, truy vấn, thống kê, ghi đa luồng |
| [`test_engine.py`](tests/test_engine.py) | Tích hợp ba module |
| [`test_api.py`](tests/test_api.py) | Toàn bộ endpoint dashboard |

Test dùng khung giờ làm việc `[0, 24]` để luật H024 không làm kết quả dao động
theo thời điểm chạy.

---

## Giới hạn đã biết

- **Chưa gắn được thay đổi với tiến trình gây ra nó.** Muốn biết *ai* sửa file
  thì cần auditd (Linux) hoặc ETW (Windows). Hiện chỉ trả lời "cái gì đổi", chưa
  trả lời "ai đổi".
- **Polling có khe hở.** Kẻ tấn công sửa rồi khôi phục file giữa hai lần quét sẽ
  lọt lưới — đây chính là lý do chế độ realtime vẫn đáng dùng.
- **File lớn hơn `max_file_size` (mặc định 512 MiB) không được băm**, chỉ theo dõi
  metadata: vẫn phát hiện đổi kích thước và quyền, nhưng không phát hiện sửa nội
  dung tại chỗ.
- **Chính CSDL của FIM chưa được bảo vệ.** Kẻ tấn công có quyền root xoá được
  `data/fim.db`. Hệ thống thật cần đẩy baseline và sự kiện sang máy khác.
- **Chưa hỗ trợ ACL và extended attributes** — mới theo dõi quyền POSIX cơ bản.
