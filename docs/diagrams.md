# Sơ đồ báo cáo FIM

Nguồn của các hình trong báo cáo. Hình 2, 7 đến 10 viết bằng Mermaid (xem được trên GitHub, mermaid.live hoặc VS Code có extension Mermaid). Hình 1 và Hình 3 đến 6 là file SVG trong `docs/diagrams/`, chèn thẳng vào Word bằng Insert → Pictures.

## Hình 1. Kiến trúc phân tầng

![Hình 1](diagrams/kien_truc.svg)

## Hình 2. Mô hình triển khai Docker

```mermaid
flowchart LR
  subgraph HOST["Máy host · Windows 11 hoặc Ubuntu"]
    BR["Trình duyệt<br/>127.0.0.1:5000"]
    TERM["Terminal<br/>lệnh docker compose"]
    subgraph ENG["Docker Engine · nhân Linux, có inotify"]
      MONC["Container fim-monitor<br/>image fim-project:2.0 · python:3.13-slim<br/>python main.py monitor"]
      DASH["Container fim-dashboard<br/>image fim-project:2.0 · Flask 3.1.3<br/>python main.py dashboard"]
      VW[("Volume fim-watch<br/>/app/test_folder")]
      VD[("Volume fim-data<br/>/app/data/fim.db")]
      VL[("Volume fim-logs<br/>/app/logs")]
    end
  end
  BR -- "HTTP, cổng 5000" --> DASH
  TERM -- "xem log, chạy kịch bản" --> MONC
  MONC -- "inotify + SHA-256" --> VW
  MONC -- "ghi events, alerts" --> VD
  MONC -- "ghi log" --> VL
  DASH -- "đọc, ack, whitelist" --> VD
  DASH -- "accept: băm lại file" --> VW
```

## Hình 3. Hệ thống giám sát toàn vẹn file (FIM)

![Hình 3](diagrams/usecase_tong_quan.svg)

## Hình 4. Phân rã: Giám sát thời gian thực

![Hình 4](diagrams/usecase_giam_sat.svg)

## Hình 5. Phân rã: Quản lý cảnh báo

![Hình 5](diagrams/usecase_canh_bao.svg)

## Hình 6. Phân rã: Quản lý whitelist

![Hình 6](diagrams/usecase_whitelist.svg)

## Hình 7. Sơ đồ tuần tự: phát hiện thay đổi và tạo cảnh báo

```mermaid
sequenceDiagram
  autonumber
  actor KT as Kẻ tấn công
  participant OS as Hệ điều hành<br/>(inotify)
  participant MON as service.py<br/>monitor()
  participant CORE as core.py
  participant RU as rules.py
  participant DB as database.py<br/>(SQLite)
  KT->>OS: Sửa etc/config.conf
  OS-->>MON: Sự kiện modified
  MON->>MON: Đặt dirty = True,<br/>chờ debounce 0.5 s
  MON->>DB: load_current(), ignore_patterns()
  DB-->>MON: Trạng thái trước
  MON->>CORE: scan_tree(prev)
  CORE->>CORE: sha256_file()<br/>file đổi size/mtime
  CORE-->>MON: Trạng thái hiện tại
  MON->>CORE: compare_states()
  CORE-->>MON: Change MODIFIED
  MON->>DB: allow_rules()
  DB-->>MON: Rule whitelist allow
  MON->>RU: classify(change)
  RU-->>MON: SUSPICIOUS, HIGH, điểm 7
  MON->>DB: record(change, verdict)
  Note over DB: INSERT events<br/>INSERT alerts (NEW)
  DB-->>MON: event_id, alert_id
  MON->>MON: Log CRITICAL,<br/>ghi alerts.log
  MON->>DB: update_current()
```

## Hình 8. Sơ đồ tuần tự: quản trị viên xử lý cảnh báo

```mermaid
sequenceDiagram
  autonumber
  actor AD as Quản trị viên
  participant WEB as dashboard.py<br/>(Flask)
  participant SVC as service.py<br/>accept()
  participant CORE as core.py
  participant DB as database.py<br/>(SQLite)
  AD->>WEB: GET /alerts
  WEB->>DB: alerts("NEW")
  DB-->>WEB: Danh sách cảnh báo mới
  WEB-->>AD: Trang Cảnh báo
  alt Thay đổi hợp lệ
    AD->>WEB: POST /alerts/1/accept
    WEB->>SVC: accept(path)
    SVC->>CORE: sha256_file(path)
    CORE-->>SVC: Mã băm mới
    SVC->>DB: set_baseline_file()
    WEB->>DB: ack_alert(1)
    WEB-->>AD: Đã chấp nhận vào baseline
  else Xác định là tấn công
    AD->>WEB: POST /alerts/1/ack
    WEB->>DB: ack_alert(1)
    WEB-->>AD: Đã xác nhận cảnh báo
  end
```

## Hình 9. Sơ đồ hoạt động luồng chính

```mermaid
flowchart TD
  S((" ")) --> A1["Nhận sự kiện inotify, chờ debounce 0.5 giây"]
  A1 --> A3["Quick scan, so sánh với current_state"]
  A3 --> D1{"Có thay đổi?"}
  D1 -- "Không" --> E1(((" ")))
  D1 -- "Có" --> A4["Tính điểm heuristic"]
  A4 --> D2{"Whitelist cho phép?"}
  D2 -- "Có" --> A5["LEGITIMATE: ghi events"]
  D2 -- "Không" --> D3{"Điểm ≥ 3?"}
  D3 -- "Không" --> A5
  D3 -- "Có" --> A6["SUSPICIOUS: ghi events,<br/>tạo alert, ghi log"]
  A5 --> E1
  A6 --> A7["Quản trị viên xem cảnh báo"]
  A7 --> D4{"Thay đổi hợp lệ?"}
  D4 -- "Có" --> A8["Chấp nhận vào baseline,<br/>xác nhận ACK"]
  D4 -- "Không" --> A9["Xác nhận ACK,<br/>điều tra sự cố"]
  A8 --> E2(((" ")))
  A9 --> E2
  classDef term fill:#1f2328,stroke:#1f2328,color:#1f2328
  class S,E1,E2 term
```

## Hình 10. Sơ đồ cơ sở dữ liệu

```mermaid
erDiagram
  BASELINE {
    TEXT path PK "đường dẫn tuyệt đối"
    TEXT sha256 "băm SHA-256 nội dung"
    INTEGER size "kích thước, byte"
    INTEGER mtime_ns "thời điểm sửa, ns"
    INTEGER mode "quyền Unix"
    INTEGER uid "chủ sở hữu"
    INTEGER gid "nhóm sở hữu"
  }
  CURRENT_STATE {
    TEXT path PK "đường dẫn tuyệt đối"
    TEXT sha256 "băm SHA-256 nội dung"
    INTEGER size "kích thước, byte"
    INTEGER mtime_ns "thời điểm sửa, ns"
    INTEGER mode "quyền Unix"
    INTEGER uid "chủ sở hữu"
    INTEGER gid "nhóm sở hữu"
  }
  EVENTS {
    INTEGER id PK "tự tăng"
    TEXT timestamp "ISO 8601"
    TEXT path "file thay đổi"
    TEXT event_type "CREATED, MODIFIED, OWNER_CHANGED... ghép bằng +"
    INTEGER risk_score "điểm heuristic"
    TEXT risk_level "LOW, MEDIUM, HIGH"
    TEXT details "lý do chấm điểm"
    TEXT verdict "LEGITIMATE, SUSPICIOUS"
    TEXT source "monitor, scan"
    TEXT old_path "đường dẫn cũ khi MOVED"
  }
  ALERTS {
    INTEGER id PK "tự tăng"
    INTEGER event_id FK "tham chiếu events.id"
    TEXT timestamp "ISO 8601"
    TEXT path "file liên quan"
    TEXT severity "MEDIUM, HIGH"
    TEXT message "nội dung cảnh báo"
    TEXT status "NEW, ACK"
    TEXT acked_at "thời điểm xác nhận"
  }
  WHITELIST {
    INTEGER id PK "tự tăng"
    TEXT pattern UK "glob, ví dụ *.log"
    TEXT kind UK "ignore, allow"
    TEXT events "* hoặc MODIFIED,CREATED"
    TEXT note "ghi chú"
    TEXT created_at "ISO 8601"
  }
  META {
    TEXT key PK "baseline_at, last_scan_at, whitelist_seeded"
    TEXT value "giá trị"
  }
  EVENTS ||--o| ALERTS : "sinh cảnh báo khi SUSPICIOUS"
  BASELINE |o..o| CURRENT_STATE : "đối chiếu theo path"
```
