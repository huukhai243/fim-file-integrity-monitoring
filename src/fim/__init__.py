"""FIM — hệ thống giám sát toàn vẹn file và phát hiện thay đổi bất thường.

Kiến trúc chia theo ba vai trò:

``fim.collector``
    Người 1 — băm baseline, theo dõi thay đổi bằng inotify hoặc polling.
``fim.analysis``
    Người 2 — phân loại hợp lệ/đáng ngờ bằng heuristic + whitelist, tạo cảnh báo.
``fim.scope`` và ``fim.web``
    Người 3 — phạm vi thư mục hệ thống, quản lý whitelist, dashboard lịch sử.

``fim.models`` chứa các kiểu dữ liệu ba module trao đổi với nhau;
``fim.engine`` là nơi ghép chúng lại.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .config import Config, load_config
from .models import (
    Alert,
    AlertStatus,
    ChangeEvent,
    ChangeType,
    Classification,
    FileRecord,
    RuleHit,
    Severity,
    Verdict,
    WhitelistEntry,
)

__all__ = [
    "__version__",
    "Config",
    "load_config",
    "Alert",
    "AlertStatus",
    "ChangeEvent",
    "ChangeType",
    "Classification",
    "FileRecord",
    "RuleHit",
    "Severity",
    "Verdict",
    "WhitelistEntry",
]
