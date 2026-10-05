"""So sánh trạng thái hiện tại với baseline để sinh ``ChangeEvent`` (Người 1).

Bộ so sánh là trái tim của FIM theo kiểu polling: quét lại phạm vi, đối chiếu
từng file với baseline, và kết luận file nào **thêm / sửa / đổi quyền / mất**.

Điểm tinh tế: một file có thể vừa đổi nội dung vừa đổi quyền. Khi đó chỉ phát
một sự kiện ``MODIFIED`` (nội dung nặng hơn), còn chi tiết quyền vẫn nằm trong
``before``/``after`` để Người 2 chấm điểm được cả hai khía cạnh.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator

from ..config import BaselineConfig
from ..models import ChangeEvent, ChangeType, FileRecord
from ..scope.scope import Scope, WalkStats
from ..store import Store
from .hashing import build_record


@dataclass
class DiffResult:
    """Tổng hợp một lần so sánh."""

    events: list[ChangeEvent] = field(default_factory=list)
    files_checked: int = 0
    duration: float = 0.0
    walk: WalkStats = field(default_factory=WalkStats)

    def count(self, change: ChangeType) -> int:
        return sum(1 for e in self.events if e.change == change)

    def as_dict(self) -> dict[str, object]:
        return {
            "files_checked": self.files_checked,
            "changes": len(self.events),
            "created": self.count(ChangeType.CREATED),
            "modified": self.count(ChangeType.MODIFIED),
            "attr": self.count(ChangeType.ATTR_CHANGED),
            "deleted": self.count(ChangeType.DELETED),
            "duration": round(self.duration, 2),
        }


def compare_records(
    before: FileRecord | None,
    after: FileRecord | None,
    *,
    source: str = "scan",
    ts: float | None = None,
) -> ChangeEvent | None:
    """So hai bản ghi của cùng một đường dẫn. Trả về ``None`` nếu không đổi gì.

    Thứ tự ưu tiên khi cả nội dung lẫn metadata cùng đổi: nội dung thắng, vì sửa
    nội dung một nhị phân hệ thống nguy hiểm hơn là đổi quyền của nó.
    """
    now = ts if ts is not None else time.time()

    if before is None and after is None:
        return None
    if before is None:
        return ChangeEvent(
            path=after.path, change=ChangeType.CREATED, source=source, ts=now, after=after
        )
    if after is None:
        return ChangeEvent(
            path=before.path, change=ChangeType.DELETED, source=source, ts=now, before=before
        )

    if not after.content_equals(before):
        return ChangeEvent(
            path=after.path, change=ChangeType.MODIFIED, source=source, ts=now,
            before=before, after=after,
        )
    if not after.metadata_equals(before):
        return ChangeEvent(
            path=after.path, change=ChangeType.ATTR_CHANGED, source=source, ts=now,
            before=before, after=after,
        )
    return None


class Differ:
    """So sánh phạm vi hiện tại với một baseline đã lưu."""

    def __init__(
        self,
        store: Store,
        scope: Scope,
        baseline_id: int | None = None,
        config: BaselineConfig | None = None,
    ) -> None:
        self.store = store
        self.scope = scope
        self.config = config or BaselineConfig()
        resolved = baseline_id if baseline_id is not None else store.active_baseline_id()
        if resolved is None:
            raise ValueError(
                "Chưa có baseline nào. Chạy 'fim baseline' trước khi so sánh."
            )
        self.baseline_id: int = resolved

    def diff(
        self, *, progress: Callable[[int, ChangeEvent | None], None] | None = None
    ) -> DiffResult:
        """Quét lại toàn bộ phạm vi và trả về danh sách thay đổi."""
        started = time.time()
        result = DiffResult()

        # Nạp baseline vào dict: tra cứu O(1) và biết ngay file nào đã biến mất.
        remaining: dict[str, FileRecord] = {
            record.path: record for record in self.store.iter_files(self.baseline_id)
        }

        for path in self.scope.walk(result.walk):
            result.files_checked += 1
            before = remaining.pop(path, None)
            after = build_record(
                path,
                algo=self.config.algo,
                digest_size=self.config.digest_size,
                chunk_size=self.config.chunk_size,
                max_file_size=self.config.max_file_size,
                follow_symlinks=self.config.follow_symlinks,
            )
            event = compare_records(before, after)
            if event is not None:
                result.events.append(event)
            if progress:
                progress(result.files_checked, event)

        # Còn sót trong baseline mà không gặp khi duyệt = đã bị xoá.
        for path, record in remaining.items():
            result.events.append(
                ChangeEvent(
                    path=path, change=ChangeType.DELETED, source="scan", before=record
                )
            )

        result.duration = time.time() - started
        return result

    def diff_paths(self, paths: Iterable[str]) -> Iterator[ChangeEvent]:
        """So sánh một tập đường dẫn cụ thể — bộ theo dõi realtime dùng hàm này.

        Khác :meth:`diff` ở chỗ không suy ra được "đã xoá" cho file ngoài danh
        sách; file không còn tồn tại trong ``paths`` mới bị coi là xoá.
        """
        for path in paths:
            before = self.store.get_file(self.baseline_id, path)
            try:
                after = build_record(
                    path,
                    algo=self.config.algo,
                    digest_size=self.config.digest_size,
                    chunk_size=self.config.chunk_size,
                    max_file_size=self.config.max_file_size,
                    follow_symlinks=self.config.follow_symlinks,
                )
                if after.error and after.error.startswith("stat:"):
                    after = None                 # không stat được = coi như đã biến mất
            except OSError:
                after = None

            event = compare_records(before, after, source="realtime")
            if event is not None:
                yield event

    def apply_to_baseline(self, events: Iterable[ChangeEvent]) -> int:
        """Ghi các thay đổi đã chấp nhận vào baseline (thao tác "approve").

        Sau khi vá hệ thống hợp lệ, chạy hàm này để baseline bắt kịp, nếu không
        mọi lần quét sau đều báo lại đúng những thay đổi đó.
        """
        count = 0
        for event in events:
            if event.change == ChangeType.DELETED:
                self.store.delete_file(self.baseline_id, event.path)
            elif event.after is not None:
                self.store.update_file(self.baseline_id, event.after)
            else:
                continue
            count += 1
        if count:
            self.store.finalize_baseline(self.baseline_id)
        return count
