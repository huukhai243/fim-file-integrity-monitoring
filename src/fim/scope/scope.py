"""Giải phạm vi giám sát và duyệt cây thư mục (Người 3).

:class:`Scope` trả lời hai câu hỏi cho hai người còn lại:

* Người 1: *"những file nào cần đưa vào baseline?"* -> :meth:`Scope.walk`
* Người 2: *"đường dẫn này có trọng yếu không?"*    -> :meth:`Scope.is_critical`
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Iterator

from ..config import ScopeConfig
from ..util import absolute_path, any_glob_match, glob_match, normalize_path
from .profiles import ScopeProfile, get_profile


@dataclass
class WalkStats:
    """Số liệu một lần duyệt — hữu ích để chẩn đoán phạm vi quá rộng/quá hẹp."""

    files: int = 0
    dirs: int = 0
    skipped_excluded: int = 0
    skipped_depth: int = 0
    skipped_fs: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "files": self.files, "dirs": self.dirs,
            "skipped_excluded": self.skipped_excluded,
            "skipped_depth": self.skipped_depth,
            "skipped_fs": self.skipped_fs,
            "errors": len(self.errors),
        }


class Scope:
    """Phạm vi đã giải xong: hồ sơ dựng sẵn + phần người dùng khai báo thêm."""

    def __init__(self, config: ScopeConfig | None = None) -> None:
        self.config = config or ScopeConfig()
        self.profile: ScopeProfile = get_profile(self.config.profile)

        # Hồ sơ là nền, cấu hình người dùng bồi thêm lên trên (không thay thế).
        self.include: list[str] = _dedupe(
            [absolute_path(p) for p in self.profile.include]
            + [absolute_path(p) for p in self.config.include]
        )
        self.exclude: list[str] = _dedupe(
            [normalize_path(p) for p in self.profile.exclude]
            + [normalize_path(p) for p in self.config.exclude]
        )
        self.critical: list[str] = _dedupe(
            [normalize_path(p) for p in self.profile.critical]
            + [normalize_path(p) for p in self.config.critical]
        )

        # Chỉ giữ gốc thực sự tồn tại: hồ sơ Linux trên máy Windows sẽ rỗng hết.
        self.roots: list[str] = [p for p in self.include if os.path.exists(p)]
        self.missing_roots: list[str] = [p for p in self.include if not os.path.exists(p)]

    # -- kiểm tra thành viên ------------------------------------------
    def is_excluded(self, path: str) -> str | None:
        """Trả về mẫu loại trừ đã khớp, hoặc ``None``."""
        return any_glob_match(normalize_path(path), self.exclude)

    def is_critical(self, path: str) -> str | None:
        """Trả về mẫu trọng yếu đã khớp, hoặc ``None``. Người 2 gọi hàm này."""
        return any_glob_match(normalize_path(path), self.critical)

    def in_scope(self, path: str) -> bool:
        """Đường dẫn có thuộc phạm vi giám sát không (nằm dưới một gốc, không bị loại)."""
        norm = absolute_path(path)
        if self.is_excluded(norm):
            return False
        return any(
            norm == root or norm.startswith(root.rstrip("/") + "/") or glob_match(norm, root)
            for root in self.include
        )

    # -- duyệt ---------------------------------------------------------
    def walk(self, stats: WalkStats | None = None) -> Iterator[str]:
        """Sinh ra mọi đường dẫn file thuộc phạm vi.

        Cắt tỉa ngay ở cấp thư mục (sửa ``dirnames`` tại chỗ) thay vì lọc sau —
        loại ``/proc`` sớm giúp không phải duyệt hàng vạn mục vô nghĩa.
        """
        stats = stats if stats is not None else WalkStats()
        seen: set[str] = set()

        for root in self.roots:
            root_dev = _device_of(root) if not self.config.cross_filesystem else None
            root_depth = root.count("/")

            for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
                norm_dir = normalize_path(dirpath)
                stats.dirs += 1

                if norm_dir.count("/") - root_depth >= self.config.max_depth:
                    stats.skipped_depth += len(dirnames)
                    dirnames[:] = []
                    continue

                kept: list[str] = []
                for name in dirnames:
                    child = f"{norm_dir}/{name}"
                    if self.is_excluded(child):
                        stats.skipped_excluded += 1
                        continue
                    if root_dev is not None and _device_of(child) not in (root_dev, None):
                        stats.skipped_fs += 1        # không vượt sang phân vùng khác
                        continue
                    kept.append(name)
                dirnames[:] = kept

                for name in filenames:
                    path = f"{norm_dir}/{name}"
                    if self.is_excluded(path):
                        stats.skipped_excluded += 1
                        continue
                    if path in seen:                 # các gốc lồng nhau có thể trùng
                        continue
                    seen.add(path)
                    stats.files += 1
                    yield path

    def summary(self) -> dict[str, object]:
        """Mô tả gọn để lưu kèm baseline và hiển thị trên dashboard."""
        return {
            "profile": self.profile.name,
            "description": self.profile.description,
            "include": self.include,
            "exclude": self.exclude,
            "critical": self.critical,
            "roots_present": self.roots,
            "roots_missing": self.missing_roots,
            "max_depth": self.config.max_depth,
            "cross_filesystem": self.config.cross_filesystem,
        }


def _dedupe(items: list[str]) -> list[str]:
    """Bỏ trùng nhưng giữ nguyên thứ tự — thứ tự quyết định mẫu nào được báo cáo."""
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _device_of(path: str) -> int | None:
    """ID thiết bị chứa ``path``; ``None`` nếu không stat được."""
    try:
        return os.stat(path, follow_symlinks=False).st_dev
    except OSError:
        return None
