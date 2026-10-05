"""Ghép ba module thành một hệ thống chạy được.

Đây là điểm tích hợp duy nhất — mỗi người làm việc trong package của mình, còn
file này nối chúng lại:

    Người 1 (collector)  ->  Người 2 (analysis)  ->  Người 3 (store + web)
      phát hiện thay đổi     phân loại + cảnh báo    lưu trữ + hiển thị

Nhờ vậy ba người phát triển song song được: chỉ cần giữ nguyên các kiểu dữ liệu
trong ``models.py`` thì đổi gì bên trong package của mình cũng không ảnh hưởng
hai người còn lại.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Callable

from .analysis.alerting import AlertManager
from .analysis.classifier import Classifier
from .collector.baseline import BaselineBuilder, BaselineResult
from .collector.differ import Differ
from .collector.watcher import Watcher, create_watcher
from .config import Config, load_config
from .models import Alert, ChangeEvent, Verdict
from .scope.scope import Scope
from .scope.whitelist import Whitelist, sync_yaml_to_store
from .store import Store

#: Gọi sau mỗi sự kiện đã xử lý — CLI dùng để in, test dùng để thu thập.
ProcessedHook = Callable[[ChangeEvent, Verdict, "Alert | None"], None]


@dataclass
class EngineStats:
    events_processed: int = 0
    alerts_raised: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_classification: dict[str, int] = field(default_factory=dict)

    def record(self, verdict: Verdict, alert: Alert | None) -> None:
        self.events_processed += 1
        sev = verdict.severity.value
        cls = verdict.classification.value
        self.by_severity[sev] = self.by_severity.get(sev, 0) + 1
        self.by_classification[cls] = self.by_classification.get(cls, 0) + 1
        if alert is not None:
            self.alerts_raised += 1

    def as_dict(self) -> dict[str, object]:
        return {
            "events_processed": self.events_processed,
            "alerts_raised": self.alerts_raised,
            "by_severity": dict(self.by_severity),
            "by_classification": dict(self.by_classification),
        }


class Engine:
    """Vòng đời đầy đủ của FIM: chốt baseline, quét, theo dõi liên tục."""

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or load_config()

        # -- Người 3: lưu trữ, phạm vi, whitelist --------------------
        self.store = Store(self.config.db_path)
        self.scope = Scope(self.config.scope)
        if self.config.whitelist.autoload:
            sync_yaml_to_store(
                self.config.resolve(self.config.whitelist.path), self.store
            )
        self.whitelist = Whitelist(self.store)

        # -- Người 2: phân loại và cảnh báo ---------------------------
        self.classifier = Classifier(self.config.analysis, self.scope, self.whitelist)
        self.alerts = AlertManager.from_config(self.config.alert, self.config.root)

        self.stats = EngineStats()
        self._hooks: list[ProcessedHook] = []
        self._lock = threading.Lock()
        self._watcher: Watcher | None = None

    # ------------------------------------------------------------------
    # Xử lý một sự kiện — đường đi chung của mọi chế độ
    # ------------------------------------------------------------------

    def on_hook(self, hook: ProcessedHook) -> None:
        self._hooks.append(hook)

    def process(self, event: ChangeEvent) -> tuple[Verdict, Alert | None]:
        """Lưu sự kiện, phân loại, cảnh báo nếu cần.

        Có khoá vì bộ theo dõi realtime gọi hàm này từ luồng riêng, trong khi
        :class:`Classifier` giữ cửa sổ trượt dùng chung cho luật burst.
        """
        with self._lock:
            baseline_id = self.store.active_baseline_id()
            self.store.add_event(event, baseline_id)

            verdict = self.classifier.classify(event)
            verdict.event_id = event.id
            self.store.add_verdict(verdict)

            alert = self.alerts.dispatch(event, verdict)
            if alert is not None:
                self.store.add_alert(alert)

            self.stats.record(verdict, alert)

        for hook in self._hooks:
            hook(event, verdict, alert)
        return verdict, alert

    # ------------------------------------------------------------------
    # Các thao tác cấp cao
    # ------------------------------------------------------------------

    def build_baseline(
        self, label: str | None = None, progress: Callable[[int, object], None] | None = None
    ) -> BaselineResult:
        """Chốt baseline mới cho phạm vi hiện tại (Người 1)."""
        builder = BaselineBuilder(self.store, self.scope, self.config.baseline)
        return builder.build(label, progress=progress)  # type: ignore[arg-type]

    def scan_once(self) -> EngineStats:
        """Quét một lần, xử lý mọi thay đổi tìm được."""
        differ = Differ(self.store, self.scope, None, self.config.baseline)
        scan_id = self.store.start_scan("scan", differ.baseline_id)
        try:
            result = differ.diff()
            for event in result.events:
                self.process(event)
            self.store.finish_scan(
                scan_id, result.files_checked, len(result.events), "ok"
            )
            return self.stats
        except Exception as exc:                        # noqa: BLE001
            self.store.finish_scan(scan_id, 0, 0, "error", str(exc))
            raise

    def watch(self) -> Watcher:
        """Bắt đầu theo dõi liên tục ở chế độ đã cấu hình. Không chặn luồng gọi."""
        self._watcher = create_watcher(
            self.store, self.scope, lambda e: self.process(e),
            self.config.watch, self.config.baseline,
        )
        self._watcher.start()
        return self._watcher

    def stop(self) -> None:
        if self._watcher is not None:
            self._watcher.stop()
            self._watcher.join(timeout=5)
            self._watcher = None

    def approve(self, event_ids: list[int]) -> int:
        """Chấp nhận các thay đổi: cập nhật baseline để lần quét sau không báo lại."""
        differ = Differ(self.store, self.scope, None, self.config.baseline)
        events = [e for e in (self.store.get_event(i) for i in event_ids) if e is not None]
        return differ.apply_to_baseline(events)

    def reload_whitelist(self) -> int:
        """Nạp lại whitelist sau khi Người 3 sửa qua dashboard hoặc CLI."""
        if self.config.whitelist.autoload:
            sync_yaml_to_store(
                self.config.resolve(self.config.whitelist.path), self.store
            )
        return self.whitelist.reload()

    def close(self) -> None:
        self.stop()
        self.store.close()

    def __enter__(self) -> "Engine":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
