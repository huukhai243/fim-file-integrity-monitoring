"""Chuyển ``ChangeEvent`` thành ``Verdict``: hợp lệ hay đáng ngờ (Người 2).

Luồng xử lý một sự kiện:

1. Tra whitelist trước — khớp thì dừng, kết luận benign và ghi rõ mục nào phủ nó.
2. Chạy bộ luật heuristic, cộng trọng số thành điểm.
3. Ánh xạ điểm sang mức nghiêm trọng, rồi sang phân loại.

Whitelist đặt trước bộ luật (chứ không phải sau) vì hai lý do: tiết kiệm việc
đọc file để tính entropy/magic, và giúp dashboard phân biệt rõ "không có luật
nào khớp" với "có khớp nhưng đã được miễn trừ".
"""

from __future__ import annotations

import time
from collections import deque
from typing import Callable

from ..config import AnalysisConfig
from ..models import (
    ChangeEvent,
    ChangeType,
    Classification,
    RuleHit,
    Severity,
    Verdict,
)
from ..scope.scope import Scope
from ..scope.whitelist import Whitelist
from ..util import parse_duration
from .heuristics import RuleContext, evaluate


class Classifier:
    """Bộ phân loại có trạng thái.

    Giữ trạng thái vì luật ``H023`` (thay đổi hàng loạt) cần biết bao nhiêu sự
    kiện vừa xảy ra trong cửa sổ gần đây — một sự kiện đơn lẻ không nói lên điều
    đó, nhưng 50 sự kiện trong 60 giây thì có.
    """

    def __init__(
        self,
        config: AnalysisConfig | None = None,
        scope: Scope | None = None,
        whitelist: Whitelist | None = None,
    ) -> None:
        self.config = config or AnalysisConfig()
        self.scope = scope
        self.whitelist = whitelist
        self.burst_window = parse_duration(self.config.burst_window)
        self._recent: deque[float] = deque()          # mốc thời gian các sự kiện gần đây

        self._is_critical: Callable[[str], str | None] = (
            scope.is_critical if scope is not None else (lambda _p: None)
        )

    # -- cửa sổ trượt cho luật burst -----------------------------------
    def _record_and_count(self, ts: float) -> int:
        self._recent.append(ts)
        cutoff = ts - self.burst_window
        while self._recent and self._recent[0] < cutoff:
            self._recent.popleft()
        return len(self._recent)

    # -- ánh xạ điểm -> mức --------------------------------------------
    def severity_for(self, score: int) -> Severity:
        cfg = self.config
        if score >= cfg.threshold_critical:
            return Severity.CRITICAL
        if score >= cfg.threshold_high:
            return Severity.HIGH
        if score >= cfg.threshold_medium:
            return Severity.MEDIUM
        if score >= cfg.threshold_low:
            return Severity.LOW
        return Severity.INFO

    def classification_for(self, severity: Severity, hits: list[RuleHit]) -> Classification:
        """Mức nghiêm trọng -> phân loại cuối cùng.

        ``MALICIOUS`` dành riêng cho CRITICAL: ở mức đó phải có nhiều luật nặng
        cùng khớp, khó giải thích bằng hoạt động bình thường.
        """
        floor = Severity(self.config.suspicious_from)
        if severity.rank >= Severity.CRITICAL.rank:
            return Classification.MALICIOUS
        if severity.rank >= floor.rank:
            return Classification.SUSPICIOUS
        if not hits or all(h.weight <= 0 for h in hits):
            return Classification.BENIGN
        return Classification.UNKNOWN

    # -- API chính -----------------------------------------------------
    def classify(self, event: ChangeEvent) -> Verdict:
        """Phân loại một sự kiện. Không bao giờ ném lỗi — luôn trả về một kết luận."""
        burst = self._record_and_count(event.ts)

        if self.whitelist is not None:
            match = self.whitelist.match(event)
            if match is not None:
                return Verdict(
                    classification=Classification.BENIGN,
                    severity=Severity.INFO,
                    score=0,
                    hits=[
                        RuleHit(
                            rule_id="WL",
                            title="Được whitelist miễn trừ",
                            weight=0,
                            detail=f"{match.id}: {match.reason}",
                        )
                    ],
                    whitelisted=True,
                    whitelist_id=match.id,
                    event_id=event.id,
                )

        ctx = RuleContext(
            config=self.config,
            is_critical=self._is_critical,
            burst_count=burst,
            now=time.time(),
        )
        hits = evaluate(event, ctx)

        # Whitelist theo từng luật: bỏ đúng luật bị miễn trừ, giữ các luật còn lại.
        if self.whitelist is not None and hits:
            kept: list[RuleHit] = []
            muted: str | None = None
            for h in hits:
                match = self.whitelist.match(event, rule_id=h.rule_id)
                if match is not None and match.rule_id == h.rule_id:
                    muted = match.id
                    continue
                kept.append(h)
            if muted is not None:
                hits = kept
                hits.append(
                    RuleHit("WL", "Một số luật bị whitelist tắt", 0, f"mục {muted}")
                )

        score = max(0, sum(h.weight for h in hits))
        severity = self.severity_for(score)
        return Verdict(
            classification=self.classification_for(severity, hits),
            severity=severity,
            score=score,
            hits=hits,
            event_id=event.id,
        )

    def explain(self, event: ChangeEvent) -> str:
        """Diễn giải nhiều dòng cho một sự kiện — dùng khi debug bộ luật."""
        verdict = self.classify(event)
        lines = [
            f"Đường dẫn : {event.path}",
            f"Thay đổi  : {event.change.value} (nguồn: {event.source})",
            f"Điểm      : {verdict.score} -> {verdict.severity.value.upper()}"
            f" / {verdict.classification.value}",
        ]
        if verdict.whitelisted:
            lines.append(f"Whitelist : {verdict.whitelist_id}")
        if verdict.hits:
            lines.append("Luật khớp :")
            for h in sorted(verdict.hits, key=lambda x: -abs(x.weight)):
                lines.append(f"  [{h.rule_id}] {h.weight:+4d}  {h.title} — {h.detail}")
        else:
            lines.append("Luật khớp : (không có)")
        return "\n".join(lines)


def summarize_event(event: ChangeEvent, verdict: Verdict) -> str:
    """Một dòng tóm tắt, dùng cho tiêu đề cảnh báo và log dòng lệnh."""
    verbs = {
        ChangeType.CREATED: "đã tạo",
        ChangeType.MODIFIED: "đã sửa nội dung",
        ChangeType.ATTR_CHANGED: "đã đổi quyền",
        ChangeType.DELETED: "đã bị xoá",
        ChangeType.RENAMED: "đã đổi tên",
    }
    return (
        f"[{verdict.severity.value.upper()}] {event.path} "
        f"{verbs.get(event.change, event.change.value)} — {verdict.reason}"
    )
