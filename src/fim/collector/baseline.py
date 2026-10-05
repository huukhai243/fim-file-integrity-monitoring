"""Chốt baseline: băm toàn bộ file trong phạm vi rồi lưu làm mốc so sánh (Người 1)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from ..config import BaselineConfig
from ..models import FileRecord
from ..scope.scope import Scope, WalkStats
from ..store import Store
from .hashing import build_records


@dataclass
class BaselineResult:
    """Kết quả một lần chốt baseline."""

    baseline_id: int
    label: str
    file_count: int = 0
    total_bytes: int = 0
    error_count: int = 0
    duration: float = 0.0
    walk: WalkStats = field(default_factory=WalkStats)
    errors: list[tuple[str, str]] = field(default_factory=list)

    @property
    def throughput(self) -> float:
        """File/giây — để so tốc độ giữa các lần chạy."""
        return self.file_count / self.duration if self.duration > 0 else 0.0

    def as_dict(self) -> dict[str, object]:
        return {
            "baseline_id": self.baseline_id,
            "label": self.label,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "error_count": self.error_count,
            "duration": round(self.duration, 2),
            "throughput": round(self.throughput, 1),
            "walk": self.walk.as_dict(),
        }


class BaselineBuilder:
    """Dựng baseline cho một :class:`Scope` đã cho."""

    #: Ghi CSDL theo lô — mỗi lô một transaction thay vì mỗi file một transaction.
    BATCH_SIZE = 500

    def __init__(
        self,
        store: Store,
        scope: Scope,
        config: BaselineConfig | None = None,
    ) -> None:
        self.store = store
        self.scope = scope
        self.config = config or BaselineConfig()

    def build(
        self,
        label: str | None = None,
        *,
        make_active: bool = True,
        progress: Callable[[int, FileRecord], None] | None = None,
    ) -> BaselineResult:
        """Quét toàn bộ phạm vi và ghi baseline mới.

        ``make_active=True`` sẽ lưu trữ các baseline cũ — chỉ một bản được coi là
        mốc hiện hành, tránh chuyện so nhầm với bản đã lỗi thời.
        """
        started = time.time()
        label = label or f"baseline-{time.strftime('%Y%m%d-%H%M%S')}"
        scope_summary = self.scope.summary()

        baseline_id = self.store.create_baseline(label, self.config.algo, scope_summary)
        scan_id = self.store.start_scan("baseline", baseline_id)
        result = BaselineResult(baseline_id=baseline_id, label=label)

        try:
            paths = list(self.scope.walk(result.walk))
            batch: list[FileRecord] = []

            for index, record in enumerate(
                build_records(
                    paths,
                    workers=self.config.workers,
                    algo=self.config.algo,
                    digest_size=self.config.digest_size,
                    chunk_size=self.config.chunk_size,
                    max_file_size=self.config.max_file_size,
                    follow_symlinks=self.config.follow_symlinks,
                ),
                1,
            ):
                batch.append(record)
                result.file_count += 1
                result.total_bytes += record.size
                if record.error:
                    result.error_count += 1
                    if len(result.errors) < 100:      # chặn trần, tránh phình bộ nhớ
                        result.errors.append((record.path, record.error))
                if progress:
                    progress(index, record)
                if len(batch) >= self.BATCH_SIZE:
                    self.store.add_files(baseline_id, batch)
                    batch.clear()

            if batch:
                self.store.add_files(baseline_id, batch)

            self.store.finalize_baseline(baseline_id)
            if make_active:
                self.store.archive_baselines(keep_id=baseline_id)

            result.duration = time.time() - started
            self.store.finish_scan(scan_id, result.file_count, 0, "ok")
            return result

        except Exception as exc:                       # noqa: BLE001 — cần ghi nhận rồi ném tiếp
            self.store.finish_scan(scan_id, result.file_count, 0, "error", str(exc))
            raise


def snapshot_paths(
    paths: list[str], config: BaselineConfig | None = None
) -> dict[str, FileRecord]:
    """Chụp nhanh một danh sách đường dẫn, trả về ánh xạ path -> record.

    Bộ so sánh dùng hàm này để lấy trạng thái *hiện tại* mà không đụng CSDL.
    """
    cfg = config or BaselineConfig()
    return {
        record.path: record
        for record in build_records(
            paths,
            workers=cfg.workers,
            algo=cfg.algo,
            digest_size=cfg.digest_size,
            chunk_size=cfg.chunk_size,
            max_file_size=cfg.max_file_size,
            follow_symlinks=cfg.follow_symlinks,
        )
    }
