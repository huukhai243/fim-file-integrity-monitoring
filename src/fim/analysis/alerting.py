"""Tạo và phát cảnh báo (Người 2).

Tách rõ hai việc:

* **Tạo** cảnh báo — quyết định sự kiện nào đáng báo động (theo ``min_severity``)
  và viết nội dung cho người đọc.
* **Phát** cảnh báo — đẩy ra console, file JSONL, webhook… Mỗi đích là một
  :class:`AlertSink`; thêm đích mới chỉ cần viết thêm một lớp.

Một sink hỏng (webhook timeout) không được chặn các sink còn lại, và tuyệt đối
không được làm sập bộ quét — cảnh báo là đầu ra phụ, giám sát mới là việc chính.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Protocol

from ..config import AlertConfig
from ..models import Alert, AlertStatus, ChangeEvent, Severity, Verdict
from ..util import ensure_parent, iso
from .classifier import summarize_event


class AlertSink(Protocol):
    """Một đích nhận cảnh báo."""

    name: str

    def emit(self, alert: Alert, event: ChangeEvent, verdict: Verdict) -> None: ...


class ConsoleSink:
    """In ra terminal, có tô màu ANSI khi đầu ra là terminal thật."""

    name = "console"

    _COLORS = {
        Severity.INFO: "\033[36m",       # cyan
        Severity.LOW: "\033[32m",        # xanh lá
        Severity.MEDIUM: "\033[33m",     # vàng
        Severity.HIGH: "\033[31m",       # đỏ
        Severity.CRITICAL: "\033[1;37;41m",  # trắng trên nền đỏ
    }
    _RESET = "\033[0m"

    def __init__(self, color: bool | None = None) -> None:
        if color is None:
            import sys
            color = sys.stdout.isatty()
        self.color = color

    def emit(self, alert: Alert, event: ChangeEvent, verdict: Verdict) -> None:
        stamp = time.strftime("%H:%M:%S", time.localtime(alert.created_at))
        line = f"{stamp}  {alert.title}"
        if self.color:
            tint = self._COLORS.get(alert.severity, "")
            line = f"{tint}{line}{self._RESET}"
        print(line)
        if verdict.hits:
            for h in sorted(verdict.hits, key=lambda x: -abs(x.weight))[:3]:
                print(f"           └─ [{h.rule_id}] {h.title}: {h.detail}")


class JsonlSink:
    """Ghi mỗi cảnh báo thành một dòng JSON.

    Định dạng JSONL để công cụ khác (Splunk, Elastic, ``jq``) đọc trực tiếp mà
    không phải phân tích cú pháp riêng.
    """

    name = "jsonl"

    def __init__(self, path: str | Path) -> None:
        self.path = ensure_parent(path)

    def emit(self, alert: Alert, event: ChangeEvent, verdict: Verdict) -> None:
        payload = {
            **alert.to_dict(),
            "created_at_iso": iso(alert.created_at),
            "event": event.to_dict(),
            "verdict": verdict.to_dict(),
        }
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=False) + "\n")


class WebhookSink:
    """POST JSON tới một URL — để nối vào Slack, Teams hoặc SIEM."""

    name = "webhook"

    def __init__(self, url: str, timeout: float = 5.0) -> None:
        self.url = url
        self.timeout = timeout

    def emit(self, alert: Alert, event: ChangeEvent, verdict: Verdict) -> None:
        body = json.dumps(
            {
                "text": alert.title,
                "alert": alert.to_dict(),
                "event": event.to_dict(),
                "verdict": verdict.to_dict(),
            },
            ensure_ascii=False,
        ).encode("utf-8")
        request = urllib.request.Request(
            self.url, data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        urllib.request.urlopen(request, timeout=self.timeout).close()


class AlertManager:
    """Quyết định có cảnh báo hay không, rồi phát ra mọi sink đã cấu hình."""

    def __init__(self, config: AlertConfig | None = None, sinks: list[AlertSink] | None = None) -> None:
        self.config = config or AlertConfig()
        self.min_severity = Severity(self.config.min_severity)
        self.sinks: list[AlertSink] = sinks if sinks is not None else []
        self.errors: list[tuple[str, str]] = []      # (tên sink, lỗi) để dashboard hiển thị
        self.emitted = 0
        self.suppressed = 0

    @classmethod
    def from_config(cls, config: AlertConfig, root: str | Path = ".") -> "AlertManager":
        sinks: list[AlertSink] = []
        if config.console:
            sinks.append(ConsoleSink())
        if config.jsonl_path:
            path = Path(config.jsonl_path)
            sinks.append(JsonlSink(path if path.is_absolute() else Path(root) / path))
        if config.webhook_url:
            sinks.append(WebhookSink(config.webhook_url, config.webhook_timeout))
        return cls(config, sinks)

    def should_alert(self, verdict: Verdict) -> bool:
        """Chỉ cảnh báo khi đủ nghiêm trọng và không bị whitelist miễn trừ."""
        if verdict.whitelisted:
            return False
        return verdict.severity.rank >= self.min_severity.rank

    def build_alert(self, event: ChangeEvent, verdict: Verdict) -> Alert:
        return Alert(
            event_id=event.id or 0,
            severity=verdict.severity,
            title=summarize_event(event, verdict),
            summary=self._build_summary(event, verdict),
            path=event.path,
            status=AlertStatus.NEW,
        )

    @staticmethod
    def _build_summary(event: ChangeEvent, verdict: Verdict) -> str:
        """Phần thân cảnh báo: đủ thông tin để xử lý mà không cần mở dashboard."""
        lines = [
            f"Đường dẫn: {event.path}",
            f"Loại thay đổi: {event.change.value}",
            f"Thời điểm: {iso(event.ts)}",
            f"Điểm rủi ro: {verdict.score} ({verdict.severity.value})",
        ]
        before, after = event.before, event.after
        if before and after:
            if before.digest != after.digest:
                lines.append(
                    f"Hash: {(before.digest or '-')[:16]}… -> {(after.digest or '-')[:16]}…"
                )
            if before.size != after.size:
                lines.append(f"Kích thước: {before.size} -> {after.size} byte")
            if before.mode != after.mode:
                lines.append(f"Quyền: {before.permissions} -> {after.permissions}")
            if (before.uid, before.gid) != (after.uid, after.gid):
                lines.append(
                    f"Chủ sở hữu: {before.uid}:{before.gid} -> {after.uid}:{after.gid}"
                )
        elif after:
            lines.append(f"Hash: {(after.digest or '-')[:16]}…")
            lines.append(f"Kích thước: {after.size} byte, quyền {after.permissions}")

        if verdict.hits:
            lines.append("")
            lines.append("Căn cứ:")
            for h in sorted(verdict.hits, key=lambda x: -abs(x.weight)):
                lines.append(f"  [{h.rule_id}] {h.weight:+d} {h.title} — {h.detail}")
        return "\n".join(lines)

    def dispatch(self, event: ChangeEvent, verdict: Verdict) -> Alert | None:
        """Tạo và phát cảnh báo nếu đủ ngưỡng. Trả về ``None`` nếu bị bỏ qua."""
        if not self.should_alert(verdict):
            self.suppressed += 1
            return None

        alert = self.build_alert(event, verdict)
        for sink in self.sinks:
            try:
                sink.emit(alert, event, verdict)
            except (OSError, urllib.error.URLError, ValueError) as exc:
                # Sink hỏng thì ghi nhận rồi đi tiếp: không để mất cả cảnh báo.
                self.errors.append((sink.name, str(exc)))
                if len(self.errors) > 100:
                    self.errors = self.errors[-100:]
        self.emitted += 1
        return alert

    def stats(self) -> dict[str, object]:
        return {
            "emitted": self.emitted,
            "suppressed": self.suppressed,
            "min_severity": self.min_severity.value,
            "sinks": [s.name for s in self.sinks],
            "errors": self.errors[-10:],
        }
