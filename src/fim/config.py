"""Đọc và hợp nhất cấu hình từ YAML + override dòng lệnh.

Mỗi nhóm cấu hình thuộc về một người:

* :class:`ScopeConfig`, :class:`WhitelistConfig`, :class:`WebConfig` — Người 3
* :class:`BaselineConfig`, :class:`WatchConfig`                      — Người 1
* :class:`AnalysisConfig`, :class:`AlertConfig`                      — Người 2
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any

import yaml

# Thư mục gốc của project (…/fim), tính ngược từ file này.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "configs" / "default.yaml"


# ---------------------------------------------------------------------------
# Người 1 — thu thập baseline & theo dõi
# ---------------------------------------------------------------------------


@dataclass
class BaselineConfig:
    """Cách tính baseline hash."""

    algo: str = "blake2b"          # blake2b (nhanh) | sha256 (chuẩn phổ biến)
    digest_size: int = 32          # chỉ áp dụng cho blake2b, tính bằng byte
    chunk_size: int = 1 << 20      # đọc file theo khối 1 MiB
    max_file_size: int = 512 << 20  # >512 MiB thì bỏ qua hash, chỉ theo dõi metadata
    follow_symlinks: bool = False  # KHÔNG bật: symlink là vector tấn công, cần thấy chính nó
    workers: int = 4               # số luồng hash song song


@dataclass
class WatchConfig:
    """Cách phát hiện thay đổi."""

    mode: str = "auto"             # auto | realtime | polling
    poll_interval: str = "5m"      # chu kỳ quét lại khi chạy polling
    debounce: str = "1.5s"         # gộp nhiều sự kiện trên cùng file trong khoảng này
    rescan_after: str = "1h"       # realtime vẫn quét toàn bộ định kỳ để bắt sự kiện lọt
    queue_size: int = 10000        # hàng đợi sự kiện realtime


# ---------------------------------------------------------------------------
# Người 3 — phạm vi giám sát & whitelist
# ---------------------------------------------------------------------------


@dataclass
class ScopeConfig:
    """Phạm vi giám sát: giám sát cái gì, bỏ qua cái gì."""

    profile: str = "auto"                     # auto | linux-system | windows-system | custom
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    # Các đường dẫn coi là trọng yếu — Người 2 chấm điểm nặng hơn khi chúng đổi.
    critical: list[str] = field(default_factory=list)
    max_depth: int = 64
    cross_filesystem: bool = False            # không đi sang phân vùng khác (tránh lạc vào mount mạng)


@dataclass
class WhitelistConfig:
    path: str = "configs/whitelist.yaml"
    autoload: bool = True                     # nạp file YAML vào CSDL khi khởi động
    allow_expiry: bool = True                 # cho phép mục có hạn dùng


# ---------------------------------------------------------------------------
# Người 2 — phân loại & cảnh báo
# ---------------------------------------------------------------------------


@dataclass
class AnalysisConfig:
    """Ngưỡng điểm và tham số cho bộ luật heuristic."""

    # Điểm tối thiểu để rơi vào từng mức. Tăng ngưỡng = ít cảnh báo hơn.
    threshold_low: int = 1
    threshold_medium: int = 30
    threshold_high: int = 60
    threshold_critical: int = 85
    # Từ mức này trở lên thì coi là đáng ngờ (không còn là benign).
    suspicious_from: str = "medium"

    burst_window: str = "60s"      # cửa sổ đếm thay đổi hàng loạt
    burst_threshold: int = 25      # quá số này trong cửa sổ -> nghi ransomware/xoá dấu vết
    entropy_sample: int = 262144   # số byte đọc để tính entropy (256 KiB)
    entropy_threshold: float = 7.5  # >7.5 bit/byte: nhiều khả năng nén/mã hoá
    future_mtime_skew: str = "5m"  # mtime vượt hiện tại quá mức này là bất thường
    business_hours: list[int] = field(default_factory=lambda: [8, 18])  # [bắt đầu, kết thúc)
    known_good_hashes: list[str] = field(default_factory=list)
    disabled_rules: list[str] = field(default_factory=list)
    rule_weights: dict[str, int] = field(default_factory=dict)  # ghi đè trọng số từng luật


@dataclass
class AlertConfig:
    """Nơi gửi cảnh báo."""

    min_severity: str = "medium"   # thấp hơn mức này thì chỉ lưu, không cảnh báo
    console: bool = True
    jsonl_path: str = "data/alerts.jsonl"
    webhook_url: str = ""          # để trống là tắt
    webhook_timeout: float = 5.0


# ---------------------------------------------------------------------------
# Người 3 — dashboard
# ---------------------------------------------------------------------------


@dataclass
class WebConfig:
    host: str = "127.0.0.1"        # chỉ lắng nghe nội bộ; đổi sang 0.0.0.0 là tự chịu rủi ro
    port: int = 8000
    page_size: int = 50
    cors_origins: list[str] = field(default_factory=list)


@dataclass
class StorageConfig:
    db_path: str = "data/fim.db"
    retention_days: int = 90        # dọn sự kiện cũ hơn ngưỡng này; 0 = giữ vĩnh viễn


@dataclass
class Config:
    """Cấu hình tổng."""

    storage: StorageConfig = field(default_factory=StorageConfig)
    baseline: BaselineConfig = field(default_factory=BaselineConfig)
    watch: WatchConfig = field(default_factory=WatchConfig)
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    whitelist: WhitelistConfig = field(default_factory=WhitelistConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    alert: AlertConfig = field(default_factory=AlertConfig)
    web: WebConfig = field(default_factory=WebConfig)

    #: Thư mục gốc để giải các đường dẫn tương đối trong cấu hình.
    root: Path = field(default=PROJECT_ROOT)

    def resolve(self, path: str) -> str:
        """Đường dẫn tương đối trong config được tính từ gốc project, không phải CWD."""
        p = Path(path)
        return str(p if p.is_absolute() else (self.root / p))

    @property
    def db_path(self) -> str:
        return self.resolve(self.storage.db_path)


# ---------------------------------------------------------------------------
# Nạp cấu hình
# ---------------------------------------------------------------------------


def _merge_into(obj: Any, data: dict[str, Any], where: str) -> None:
    """Gán đệ quy dict vào dataclass, báo lỗi rõ ràng nếu gặp khoá lạ."""
    valid = {f.name: f for f in fields(obj)}
    for key, value in data.items():
        if key not in valid:
            raise ValueError(
                f"Khoá cấu hình không hợp lệ: {where}.{key}. "
                f"Các khoá hợp lệ: {', '.join(sorted(valid))}"
            )
        current = getattr(obj, key)
        if is_dataclass(current) and isinstance(value, dict):
            _merge_into(current, value, f"{where}.{key}")
        else:
            setattr(obj, key, value)


def load_config(path: str | Path | None = None, **overrides: Any) -> Config:
    """Đọc YAML rồi áp override.

    ``overrides`` nhận khoá phẳng dạng ``"web.port"`` hoặc ``"web__port"`` để
    tiện gắn vào argparse. Giá trị ``None`` bị bỏ qua, nhờ vậy argparse có thể
    truyền thẳng namespace mà không ghi đè YAML bằng các giá trị chưa đặt.
    """
    cfg = Config()
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH

    if config_path.exists():
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            raise ValueError(f"{config_path} phải là một ánh xạ YAML ở cấp cao nhất")
        _merge_into(cfg, raw, "config")
        cfg.root = config_path.resolve().parent.parent
    elif path is not None:
        raise FileNotFoundError(f"Không tìm thấy file cấu hình: {config_path}")

    for flat_key, value in overrides.items():
        if value is None:
            continue
        target: Any = cfg
        parts = flat_key.replace("__", ".").split(".")
        for part in parts[:-1]:
            target = getattr(target, part)
        if not hasattr(target, parts[-1]):
            raise ValueError(f"Override không hợp lệ: {flat_key}")
        setattr(target, parts[-1], value)

    return cfg
