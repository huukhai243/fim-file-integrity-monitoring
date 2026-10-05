"""Theo dõi thay đổi: realtime (inotify/ReadDirectoryChangesW) hoặc polling (Người 1).

Hai chế độ bù khuyết cho nhau:

realtime
    Độ trễ gần như bằng 0, nhưng inotify có hạn mức watch của nhân
    (``/proc/sys/fs/inotify/max_user_watches``) và có thể mất sự kiện khi hàng
    đợi tràn. Vì vậy chế độ này vẫn quét lại toàn bộ theo chu kỳ ``rescan_after``.

polling
    Không phụ thuộc nhân, chạy ở đâu cũng được, nhưng tốn I/O và chỉ phát hiện
    thay đổi ở lần quét kế tiếp. Kẻ tấn công sửa rồi khôi phục giữa hai lần quét
    sẽ lọt lưới — đây là lý do realtime vẫn đáng dùng.

Cả hai đều đẩy ``ChangeEvent`` vào cùng một callback nên phần phía sau không cần
biết nguồn sự kiện đến từ đâu.
"""

from __future__ import annotations

import queue
import threading
import time
from typing import Callable, Protocol

from ..config import BaselineConfig, WatchConfig
from ..models import ChangeEvent
from ..scope.scope import Scope
from ..store import Store
from ..util import normalize_path, parse_duration
from .differ import Differ

EventCallback = Callable[[ChangeEvent], None]


class Watcher(Protocol):
    """Giao diện chung cho hai chế độ theo dõi."""

    def start(self) -> None: ...
    def stop(self) -> None: ...
    def join(self, timeout: float | None = None) -> None: ...


class _Debouncer:
    """Gộp nhiều sự kiện trên cùng một đường dẫn trong một cửa sổ thời gian.

    Trình soạn thảo ghi file thường tạo ra cả chuỗi create/modify/rename chỉ cho
    một lần lưu. Không gộp lại thì một thao tác lưu sinh ra 4–5 cảnh báo trùng.
    """

    def __init__(self, delay: float) -> None:
        self.delay = delay
        self._pending: dict[str, float] = {}
        self._lock = threading.Lock()

    def touch(self, path: str) -> None:
        with self._lock:
            self._pending[normalize_path(path)] = time.monotonic()

    def collect(self) -> list[str]:
        """Trả về các đường dẫn đã "nguội" (không còn sự kiện mới trong ``delay``)."""
        cutoff = time.monotonic() - self.delay
        with self._lock:
            ready = [p for p, ts in self._pending.items() if ts <= cutoff]
            for path in ready:
                del self._pending[path]
        return ready

    def __len__(self) -> int:
        with self._lock:
            return len(self._pending)


class PollingWatcher:
    """Quét lại toàn bộ phạm vi theo chu kỳ cố định."""

    def __init__(
        self,
        store: Store,
        scope: Scope,
        on_event: EventCallback,
        watch_config: WatchConfig | None = None,
        baseline_config: BaselineConfig | None = None,
        baseline_id: int | None = None,
    ) -> None:
        self.store = store
        self.scope = scope
        self.on_event = on_event
        self.config = watch_config or WatchConfig()
        self.interval = parse_duration(self.config.poll_interval)
        self.differ = Differ(store, scope, baseline_id, baseline_config)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def run_once(self) -> int:
        """Một chu kỳ quét. Trả về số thay đổi phát hiện được."""
        scan_id = self.store.start_scan("polling", self.differ.baseline_id)
        try:
            result = self.differ.diff()
            for event in result.events:
                self.on_event(event)
            self.store.finish_scan(
                scan_id, result.files_checked, len(result.events), "ok"
            )
            return len(result.events)
        except Exception as exc:                       # noqa: BLE001
            self.store.finish_scan(scan_id, 0, 0, "error", str(exc))
            raise

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception as exc:                   # noqa: BLE001
                print(f"[watcher] lỗi khi quét: {exc}")
            self._stop.wait(self.interval)             # wait() thoát ngay khi stop()

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="fim-polling", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def join(self, timeout: float | None = None) -> None:
        if self._thread:
            self._thread.join(timeout)


class RealtimeWatcher:
    """Theo dõi tức thời bằng ``watchdog``.

    ``watchdog`` tự chọn backend của hệ điều hành: inotify trên Linux,
    ReadDirectoryChangesW trên Windows, FSEvents trên macOS.
    """

    def __init__(
        self,
        store: Store,
        scope: Scope,
        on_event: EventCallback,
        watch_config: WatchConfig | None = None,
        baseline_config: BaselineConfig | None = None,
        baseline_id: int | None = None,
    ) -> None:
        self.store = store
        self.scope = scope
        self.on_event = on_event
        self.config = watch_config or WatchConfig()
        self.differ = Differ(store, scope, baseline_id, baseline_config)

        self.debouncer = _Debouncer(parse_duration(self.config.debounce))
        self.rescan_interval = parse_duration(self.config.rescan_after)
        self._queue: queue.Queue[str] = queue.Queue(maxsize=self.config.queue_size)
        self._stop = threading.Event()
        self._observer = None
        self._worker: threading.Thread | None = None
        self.dropped = 0            # số sự kiện rơi do hàng đợi đầy
        self.watched_roots: list[str] = []

    # -- cầu nối sang watchdog ----------------------------------------
    def _build_handler(self):
        from watchdog.events import FileSystemEventHandler

        outer = self

        class _Handler(FileSystemEventHandler):
            def on_any_event(self, event) -> None:      # noqa: ANN001
                if event.is_directory:
                    return
                for attr in ("src_path", "dest_path"):
                    path = getattr(event, attr, None)
                    if not path:
                        continue
                    norm = normalize_path(path)
                    if outer.scope.is_excluded(norm):
                        continue
                    try:
                        outer._queue.put_nowait(norm)
                    except queue.Full:
                        outer.dropped += 1              # rescan định kỳ sẽ vá chỗ này

        return _Handler()

    def _drain(self) -> None:
        """Chuyển sự kiện thô từ hàng đợi sang bộ gộp, rồi so sánh khi đã nguội."""
        last_rescan = time.monotonic()

        while not self._stop.is_set():
            try:
                path = self._queue.get(timeout=0.25)
                self.debouncer.touch(path)
            except queue.Empty:
                pass

            ready = self.debouncer.collect()
            if ready:
                for event in self.differ.diff_paths(ready):
                    self.on_event(event)

            # Lưới an toàn: quét đầy đủ định kỳ để bắt sự kiện bị rơi.
            if time.monotonic() - last_rescan >= self.rescan_interval:
                last_rescan = time.monotonic()
                try:
                    self.full_rescan()
                except Exception as exc:                # noqa: BLE001
                    print(f"[watcher] rescan lỗi: {exc}")

    def full_rescan(self) -> int:
        scan_id = self.store.start_scan("rescan", self.differ.baseline_id)
        try:
            result = self.differ.diff()
            for event in result.events:
                self.on_event(event)
            self.store.finish_scan(scan_id, result.files_checked, len(result.events), "ok")
            return len(result.events)
        except Exception as exc:                        # noqa: BLE001
            self.store.finish_scan(scan_id, 0, 0, "error", str(exc))
            raise

    def start(self) -> None:
        from watchdog.observers import Observer

        self._stop.clear()
        self._observer = Observer()
        handler = self._build_handler()

        for root in self.scope.roots:
            try:
                self._observer.schedule(handler, root, recursive=True)
                self.watched_roots.append(root)
            except OSError as exc:
                # Thường gặp: hết hạn mức inotify watch của nhân.
                print(f"[watcher] không theo dõi được {root}: {exc}")

        if not self.watched_roots:
            raise RuntimeError(
                "Không đăng ký được thư mục nào để theo dõi. "
                "Kiểm tra lại scope.include và quyền truy cập."
            )

        self._observer.start()
        self._worker = threading.Thread(target=self._drain, name="fim-realtime", daemon=True)
        self._worker.start()

    def stop(self) -> None:
        self._stop.set()
        if self._observer is not None:
            self._observer.stop()

    def join(self, timeout: float | None = None) -> None:
        if self._observer is not None:
            self._observer.join(timeout)
        if self._worker is not None:
            self._worker.join(timeout)


def create_watcher(
    store: Store,
    scope: Scope,
    on_event: EventCallback,
    watch_config: WatchConfig | None = None,
    baseline_config: BaselineConfig | None = None,
    baseline_id: int | None = None,
) -> Watcher:
    """Tạo bộ theo dõi theo cấu hình. ``mode="auto"`` ưu tiên realtime, lùi về polling."""
    config = watch_config or WatchConfig()
    args = (store, scope, on_event, config, baseline_config, baseline_id)

    if config.mode == "polling":
        return PollingWatcher(*args)
    if config.mode == "realtime":
        return RealtimeWatcher(*args)
    if config.mode != "auto":
        raise ValueError(f"watch.mode không hợp lệ: {config.mode} (auto|realtime|polling)")

    try:
        import watchdog  # noqa: F401
    except ImportError:
        print("[watcher] không có watchdog, dùng chế độ polling")
        return PollingWatcher(*args)
    return RealtimeWatcher(*args)
