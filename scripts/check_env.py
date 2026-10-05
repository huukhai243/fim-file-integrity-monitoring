"""Kiểm tra môi trường trước khi chạy FIM.

    python scripts/check_env.py
"""

from __future__ import annotations

import importlib
import os
import platform
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from fim.util import enable_utf8_output  # noqa: E402

REQUIRED = [
    ("yaml", "PyYAML", "đọc cấu hình và whitelist"),
    ("fastapi", "fastapi", "dashboard"),
    ("uvicorn", "uvicorn", "chạy dashboard"),
]
OPTIONAL = [
    ("watchdog", "watchdog", "theo dõi realtime (thiếu thì lùi về polling)"),
    ("pytest", "pytest", "chạy test"),
    ("httpx", "httpx", "test API"),
]


def main() -> int:
    enable_utf8_output()
    print(f"Python  : {sys.version.split()[0]}  ({platform.python_implementation()})")
    print(f"Hệ điều hành: {platform.system()} {platform.release()}")
    problems = 0

    print("\nThư viện bắt buộc:")
    for module, package, why in REQUIRED:
        try:
            importlib.import_module(module)
            print(f"  ✓ {package:<12} {why}")
        except ImportError:
            print(f"  ✗ {package:<12} THIẾU — pip install {package}")
            problems += 1

    print("\nThư viện tuỳ chọn:")
    for module, package, why in OPTIONAL:
        try:
            importlib.import_module(module)
            print(f"  ✓ {package:<12} {why}")
        except ImportError:
            print(f"  - {package:<12} chưa có — {why}")

    print("\nKiểm tra phạm vi giám sát:")
    try:
        from fim.config import load_config
        from fim.scope.scope import Scope

        cfg = load_config()
        scope = Scope(cfg.scope)
        print(f"  Hồ sơ    : {scope.profile.name}")
        print(f"  Gốc có mặt: {len(scope.roots)}")
        for root in scope.roots[:8]:
            print(f"    ✓ {root}")
        if len(scope.roots) > 8:
            print(f"    … và {len(scope.roots) - 8} thư mục nữa")
        if not scope.roots:
            print("    ✗ Không có thư mục nào — thêm vào scope.include")
            problems += 1
    except Exception as exc:                                # noqa: BLE001
        print(f"  ✗ Lỗi khi nạp cấu hình: {exc}")
        problems += 1

    # Hạn mức inotify chỉ có ý nghĩa trên Linux.
    limit_file = Path("/proc/sys/fs/user/max_inotify_watches")
    legacy = Path("/proc/sys/fs/inotify/max_user_watches")
    for path in (limit_file, legacy):
        if path.exists():
            try:
                limit = int(path.read_text().strip())
                print(f"\nHạn mức inotify watch: {limit:,}")
                if limit < 65536:
                    print("  Cảnh báo: hạn mức thấp, phạm vi lớn có thể không theo dõi đủ.")
                    print("  Tăng bằng: sudo sysctl fs.inotify.max_user_watches=524288")
            except (OSError, ValueError):
                pass
            break

    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        print("\nLưu ý: không chạy bằng root — một số file hệ thống sẽ không đọc được.")

    print()
    if problems:
        print(f"Còn {problems} vấn đề cần xử lý.")
        return 1
    print("Môi trường sẵn sàng. Bước tiếp: python -m fim.cli baseline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
