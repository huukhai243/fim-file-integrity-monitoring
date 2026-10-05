"""Fixture dùng chung cho toàn bộ test."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from fim.config import (
    AlertConfig,
    AnalysisConfig,
    BaselineConfig,
    Config,
    ScopeConfig,
    StorageConfig,
    WhitelistConfig,
)
from fim.scope.scope import Scope
from fim.store import Store


@pytest.fixture
def tmp_tree(tmp_path: Path) -> Path:
    """Cây thư mục nhỏ mô phỏng hệ thống, dùng cho hầu hết test."""
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "bin").mkdir()
    (root / "var/log").mkdir(parents=True)

    (root / "etc/passwd").write_text("root:x:0:0::/root:/bin/sh\n", encoding="utf-8")
    (root / "etc/app.conf").write_text("mode = normal\n", encoding="utf-8")
    (root / "bin/tool").write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    (root / "var/log/app.log").write_text("bắt đầu\n", encoding="utf-8")
    return root


@pytest.fixture
def store(tmp_path: Path) -> Store:
    """Store trên file thật (không :memory:) vì mã dùng nhiều kết nối theo luồng."""
    s = Store(tmp_path / "test.db")
    yield s
    s.close()


@pytest.fixture
def scope(tmp_tree: Path) -> Scope:
    posix = str(tmp_tree).replace("\\", "/")
    return Scope(
        ScopeConfig(
            profile="custom",
            include=[posix],
            critical=[f"{posix}/etc/passwd", f"{posix}/bin/**"],
        )
    )


@pytest.fixture
def config(tmp_path: Path, tmp_tree: Path) -> Config:
    """Cấu hình đầy đủ trỏ vào cây tạm — dùng cho test Engine và API."""
    posix = str(tmp_tree).replace("\\", "/")
    return Config(
        root=tmp_path,
        storage=StorageConfig(db_path=str(tmp_path / "engine.db")),
        baseline=BaselineConfig(workers=1),
        scope=ScopeConfig(
            profile="custom",
            include=[posix],
            critical=[f"{posix}/etc/passwd", f"{posix}/bin/**"],
        ),
        whitelist=WhitelistConfig(autoload=False),
        # Khung giờ 0–24 để luật H024 (ngoài giờ) không làm kết quả test dao động
        # theo thời điểm chạy CI.
        analysis=AnalysisConfig(business_hours=[0, 24]),
        alert=AlertConfig(console=False, jsonl_path=str(tmp_path / "alerts.jsonl")),
    )


@pytest.fixture
def posix_root(tmp_tree: Path) -> str:
    return str(tmp_tree).replace("\\", "/")


def skip_on_windows(reason: str = "chỉ áp dụng cho POSIX"):
    return pytest.mark.skipif(os.name == "nt", reason=reason)
