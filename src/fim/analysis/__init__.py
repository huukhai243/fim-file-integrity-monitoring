"""Người 2 — phân tích: phân loại thay đổi và phát cảnh báo."""

from __future__ import annotations

from .alerting import AlertManager, AlertSink, ConsoleSink, JsonlSink, WebhookSink
from .classifier import Classifier, summarize_event
from .heuristics import Rule, RuleContext, all_rules, evaluate

__all__ = [
    "AlertManager", "AlertSink", "ConsoleSink", "JsonlSink", "WebhookSink",
    "Classifier", "summarize_event",
    "Rule", "RuleContext", "all_rules", "evaluate",
]
