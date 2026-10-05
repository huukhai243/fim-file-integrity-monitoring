"""Người 1 — thu thập: băm baseline và phát hiện thay đổi."""

from __future__ import annotations

from .baseline import BaselineBuilder, BaselineResult, snapshot_paths
from .differ import Differ, DiffResult, compare_records
from .hashing import (
    build_record,
    build_records,
    detect_magic,
    hash_bytes,
    hash_file,
    is_executable,
    sample_entropy,
    shannon_entropy,
    stat_file,
)
from .watcher import PollingWatcher, RealtimeWatcher, create_watcher

__all__ = [
    "BaselineBuilder", "BaselineResult", "snapshot_paths",
    "Differ", "DiffResult", "compare_records",
    "build_record", "build_records", "hash_file", "hash_bytes", "stat_file",
    "detect_magic", "is_executable", "sample_entropy", "shannon_entropy",
    "PollingWatcher", "RealtimeWatcher", "create_watcher",
]
