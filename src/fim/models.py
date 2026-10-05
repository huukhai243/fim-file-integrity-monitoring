"""Các kiểu dữ liệu dùng chung — đây là "hợp đồng" giữa 3 module.

Người 1 sinh ra :class:`FileRecord` và :class:`ChangeEvent`.
Người 2 tiêu thụ ``ChangeEvent`` và sinh ra :class:`Verdict` / :class:`Alert`.
Người 3 hiển thị tất cả và quản lý :class:`WhitelistEntry`.

Không module nào được đổi các trường ở đây mà không báo 2 người còn lại.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class ChangeType(str, Enum):
    """Loại thay đổi phát hiện được trên một đường dẫn."""

    CREATED = "created"
    MODIFIED = "modified"      # nội dung đổi (hash khác)
    ATTR_CHANGED = "attr"      # metadata đổi (quyền/chủ sở hữu), nội dung giữ nguyên
    DELETED = "deleted"
    RENAMED = "renamed"


class Classification(str, Enum):
    """Kết luận của bộ phân loại (Người 2)."""

    BENIGN = "benign"          # thay đổi hợp lệ
    UNKNOWN = "unknown"        # chưa đủ căn cứ, cần người xem
    SUSPICIOUS = "suspicious"  # đáng ngờ
    MALICIOUS = "malicious"    # gần như chắc chắn độc hại


class Severity(str, Enum):
    """Mức độ nghiêm trọng, suy ra từ điểm số."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self.value]


_SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

#: Thứ tự tăng dần, dùng khi cần lấy mức cao nhất trong một nhóm.
SEVERITY_ORDER: list[Severity] = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


@dataclass
class FileRecord:
    """Ảnh chụp trạng thái một file tại thời điểm quét (Người 1).

    ``digest`` có thể là ``None`` khi file vượt ngưỡng kích thước cho phép hoặc
    không đọc được (thiếu quyền) — khi đó chỉ so sánh được metadata.
    """

    path: str
    size: int = 0
    mtime: float = 0.0
    ctime: float = 0.0
    mode: int = 0
    uid: int = 0
    gid: int = 0
    digest: str | None = None
    is_symlink: bool = False
    link_target: str | None = None
    scanned_at: float = field(default_factory=time.time)
    error: str | None = None          # lý do không hash được, nếu có

    @property
    def permissions(self) -> str:
        """Quyền dạng bát phân 4 chữ số, ví dụ ``0644`` hoặc ``4755`` (setuid)."""
        return format(self.mode & 0o7777, "04o")

    def content_equals(self, other: FileRecord | None) -> bool:
        """So sánh nội dung. Thiếu digest thì lùi về so sánh (size, mtime)."""
        if other is None:
            return False
        if self.digest is not None and other.digest is not None:
            return self.digest == other.digest
        return self.size == other.size and self.mtime == other.mtime

    def metadata_equals(self, other: FileRecord | None) -> bool:
        """So sánh metadata bảo mật: quyền và chủ sở hữu."""
        if other is None:
            return False
        return (self.mode, self.uid, self.gid) == (other.mode, other.uid, other.gid)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileRecord:
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class ChangeEvent:
    """Một thay đổi đã phát hiện, kèm trạng thái trước/sau (Người 1 -> Người 2)."""

    path: str
    change: ChangeType
    source: str = "scan"                     # "scan" (polling) hoặc "realtime"
    ts: float = field(default_factory=time.time)
    before: FileRecord | None = None
    after: FileRecord | None = None
    old_path: str | None = None              # chỉ dùng cho RENAMED
    id: int | None = None                    # do CSDL cấp sau khi lưu

    @property
    def record(self) -> FileRecord | None:
        """Bản ghi đại diện: ưu tiên trạng thái sau; file bị xoá thì lấy trạng thái trước."""
        return self.after or self.before

    @property
    def size_delta(self) -> int:
        after = self.after.size if self.after else 0
        before = self.before.size if self.before else 0
        return after - before

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "path": self.path,
            "change": self.change.value,
            "source": self.source,
            "ts": self.ts,
            "old_path": self.old_path,
            "before": self.before.to_dict() if self.before else None,
            "after": self.after.to_dict() if self.after else None,
        }


@dataclass
class RuleHit:
    """Một luật heuristic đã khớp (Người 2).

    ``weight`` dương = bằng chứng đáng ngờ, âm = bằng chứng cho thấy hợp lệ.
    """

    rule_id: str
    title: str
    weight: int
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Verdict:
    """Kết luận phân loại cho một ``ChangeEvent`` (Người 2)."""

    classification: Classification
    severity: Severity
    score: int
    hits: list[RuleHit] = field(default_factory=list)
    whitelisted: bool = False
    whitelist_id: str | None = None
    event_id: int | None = None
    created_at: float = field(default_factory=time.time)

    @property
    def reason(self) -> str:
        """Tóm tắt một dòng vì sao có kết luận này — dùng cho alert và dashboard."""
        if self.whitelisted:
            return f"Khớp whitelist {self.whitelist_id}"
        if not self.hits:
            return "Không có luật nào khớp"
        top = sorted(self.hits, key=lambda h: -abs(h.weight))[:3]
        return "; ".join(f"{h.title} ({h.weight:+d})" for h in top)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "classification": self.classification.value,
            "severity": self.severity.value,
            "score": self.score,
            "whitelisted": self.whitelisted,
            "whitelist_id": self.whitelist_id,
            "hits": [h.to_dict() for h in self.hits],
            "reason": self.reason,
            "created_at": self.created_at,
        }


class AlertStatus(str, Enum):
    NEW = "new"
    ACK = "ack"                      # đã tiếp nhận
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


@dataclass
class Alert:
    """Cảnh báo gửi tới người vận hành (Người 2 tạo, Người 3 hiển thị)."""

    event_id: int
    severity: Severity
    title: str
    summary: str
    path: str = ""
    status: AlertStatus = AlertStatus.NEW
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    note: str | None = None
    id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "event_id": self.event_id,
            "severity": self.severity.value,
            "title": self.title,
            "summary": self.summary,
            "path": self.path,
            "status": self.status.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "note": self.note,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


@dataclass
class WhitelistEntry:
    """Một mục whitelist (Người 3 quản lý, Người 2 tra cứu).

    Các tiêu chí trong cùng một mục là **AND**: điền càng nhiều thì phạm vi càng hẹp.
    Ít nhất một trong ``path_glob`` / ``digest`` phải có giá trị.
    """

    id: str
    path_glob: str | None = None
    digest: str | None = None
    rule_id: str | None = None        # chỉ tắt đúng một luật, thay vì bỏ qua cả file
    change: ChangeType | None = None  # chỉ áp cho một loại thay đổi
    reason: str = ""
    added_by: str = ""
    created_at: float = field(default_factory=time.time)
    expires_at: float | None = None
    enabled: bool = True
    hit_count: int = 0

    def is_active(self, now: float | None = None) -> bool:
        """Còn hiệu lực không? Mục hết hạn tự động ngừng áp dụng."""
        if not self.enabled:
            return False
        if self.expires_at is None:
            return True
        return (now if now is not None else time.time()) < self.expires_at

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["change"] = self.change.value if self.change else None
        data["active"] = self.is_active()
        return data
