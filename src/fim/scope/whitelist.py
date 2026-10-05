"""Quản lý whitelist: nạp từ YAML, lưu CSDL, tra cứu khi phân loại (Người 3).

Nguyên tắc thiết kế: **whitelist phải hẹp và giải trình được**.

* Mỗi mục bắt buộc có ``reason`` — whitelist không giải thích được là whitelist
  sẽ bị sao chép mù sang hệ thống khác rồi trở thành lỗ hổng.
* Ưu tiên ``rule_id`` hơn là bỏ qua cả file: tắt đúng một luật gây nhiễu vẫn giữ
  được khả năng phát hiện mọi luật còn lại trên chính file đó.
* Có ``expires_at`` để cấp ngoại lệ tạm trong cửa sổ bảo trì mà không quên thu hồi.
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any, Iterable

import yaml

from ..models import ChangeEvent, ChangeType, WhitelistEntry
from ..store import Store
from ..util import ensure_parent, glob_match, normalize_path, parse_duration


class WhitelistError(ValueError):
    """Mục whitelist không hợp lệ."""


def _parse_expiry(value: Any) -> float | None:
    """Chấp nhận epoch, chuỗi ISO, hoặc khoảng tương đối kiểu ``"7d"``."""
    if value in (None, "", False):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if text.startswith("+"):
        return time.time() + parse_duration(text[1:])
    try:
        return parse_duration(text) + time.time()
    except ValueError:
        pass
    from datetime import datetime

    return datetime.fromisoformat(text).timestamp()


def entry_from_dict(data: dict[str, Any]) -> WhitelistEntry:
    """Dựng :class:`WhitelistEntry` từ YAML/JSON, có kiểm tra hợp lệ."""
    match = data.get("match", data)          # cho phép cả dạng phẳng lẫn lồng "match:"
    path_glob = match.get("path_glob") or match.get("path")
    digest = match.get("digest") or match.get("sha256") or match.get("hash")

    if not path_glob and not digest:
        raise WhitelistError(
            f"Mục {data.get('id', '<không tên>')} phải có ít nhất path_glob hoặc digest"
        )
    reason = (data.get("reason") or "").strip()
    if not reason:
        raise WhitelistError(
            f"Mục {data.get('id', '<không tên>')} thiếu 'reason' — bắt buộc phải giải thích"
        )

    change_raw = match.get("change")
    return WhitelistEntry(
        id=str(data.get("id") or f"wl-{uuid.uuid4().hex[:8]}"),
        path_glob=normalize_path(path_glob) if path_glob else None,
        digest=str(digest).lower() if digest else None,
        rule_id=match.get("rule_id"),
        change=ChangeType(change_raw) if change_raw else None,
        reason=reason,
        added_by=str(data.get("added_by") or ""),
        created_at=float(data.get("created_at") or time.time()),
        expires_at=_parse_expiry(data.get("expires_at")),
        enabled=bool(data.get("enabled", True)),
    )


class Whitelist:
    """Tập whitelist đang hiệu lực, có thể tra cứu.

    Đọc từ CSDL một lần rồi giữ trong bộ nhớ: bộ phân loại tra cứu trên từng sự
    kiện, truy vấn SQL mỗi lần sẽ thành nút thắt cổ chai khi quét hàng loạt.
    Gọi :meth:`reload` sau khi Người 3 sửa whitelist qua dashboard.
    """

    def __init__(self, store: Store | None = None, entries: Iterable[WhitelistEntry] = ()) -> None:
        self.store = store
        self._entries: list[WhitelistEntry] = list(entries)
        if store is not None and not self._entries:
            self.reload()

    # -- nạp / lưu -----------------------------------------------------
    def reload(self) -> int:
        """Đọc lại từ CSDL. Trả về số mục còn hiệu lực."""
        if self.store is None:
            return len(self._entries)
        self._entries = self.store.list_whitelist(only_active=True)
        return len(self._entries)

    @property
    def entries(self) -> list[WhitelistEntry]:
        return list(self._entries)

    def add(self, entry: WhitelistEntry) -> WhitelistEntry:
        if self.store is not None:
            self.store.upsert_whitelist(entry)
        self._entries = [e for e in self._entries if e.id != entry.id]
        if entry.is_active():
            self._entries.append(entry)
        return entry

    def remove(self, entry_id: str) -> bool:
        removed = self.store.delete_whitelist(entry_id) if self.store else False
        before = len(self._entries)
        self._entries = [e for e in self._entries if e.id != entry_id]
        return removed or len(self._entries) < before

    # -- tra cứu -------------------------------------------------------
    def match(self, event: ChangeEvent, rule_id: str | None = None) -> WhitelistEntry | None:
        """Tìm mục đầu tiên phủ sự kiện này.

        ``rule_id`` là tên luật đang xét. Mục có ``rule_id`` chỉ khớp khi trùng
        đúng luật đó; mục không có ``rule_id`` phủ mọi luật cho file đã chỉ định.
        """
        now = time.time()
        record = event.record
        digest = record.digest if record else None

        for entry in self._entries:
            if not entry.is_active(now):
                continue
            if entry.rule_id is not None and entry.rule_id != rule_id:
                continue
            if entry.change is not None and entry.change != event.change:
                continue
            if entry.digest is not None and (digest or "").lower() != entry.digest:
                continue
            if entry.path_glob is not None and not glob_match(event.path, entry.path_glob):
                continue
            if self.store is not None:
                self.store.bump_whitelist_hit(entry.id)
            entry.hit_count += 1
            return entry
        return None

    def covers_path(self, path: str) -> WhitelistEntry | None:
        """Kiểm tra nhanh chỉ theo đường dẫn — dùng cho công cụ dòng lệnh."""
        for entry in self._entries:
            if entry.is_active() and entry.path_glob and glob_match(path, entry.path_glob):
                return entry
        return None

    def __len__(self) -> int:
        return len(self._entries)


# ---------------------------------------------------------------------------
# Đồng bộ YAML <-> CSDL
# ---------------------------------------------------------------------------


def load_yaml(path: str | Path) -> list[WhitelistEntry]:
    """Đọc file whitelist YAML. File không tồn tại thì trả về danh sách rỗng."""
    p = Path(path)
    if not p.exists():
        return []
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if isinstance(raw, list):                 # cho phép viết tắt: chỉ một danh sách
        raw = {"entries": raw}
    entries_raw = raw.get("entries") or []
    if not isinstance(entries_raw, list):
        raise WhitelistError(f"{p}: 'entries' phải là một danh sách")

    out, errors = [], []
    for index, item in enumerate(entries_raw):
        try:
            out.append(entry_from_dict(item))
        except (WhitelistError, ValueError) as exc:
            errors.append(f"  entries[{index}]: {exc}")
    if errors:
        raise WhitelistError(f"{p} có mục không hợp lệ:\n" + "\n".join(errors))
    return out


def sync_yaml_to_store(path: str | Path, store: Store) -> int:
    """Nạp whitelist YAML vào CSDL. Trả về số mục đã nạp.

    Đây là chiều một hướng: YAML là nguồn sự thật cho các mục quản lý bằng
    Git, còn dashboard thêm thẳng vào CSDL. Hai nguồn chung sống nhờ khác ``id``.
    """
    entries = load_yaml(path)
    for entry in entries:
        store.upsert_whitelist(entry)
    return len(entries)


def export_to_yaml(store: Store, path: str | Path) -> int:
    """Xuất whitelist trong CSDL ra YAML để đưa vào Git."""
    entries = store.list_whitelist()
    payload = {
        "version": 1,
        "entries": [
            {
                "id": e.id,
                "match": {
                    k: v for k, v in (
                        ("path_glob", e.path_glob),
                        ("digest", e.digest),
                        ("rule_id", e.rule_id),
                        ("change", e.change.value if e.change else None),
                    ) if v is not None
                },
                "reason": e.reason,
                "added_by": e.added_by,
                "created_at": e.created_at,
                "expires_at": e.expires_at,
                "enabled": e.enabled,
            }
            for e in entries
        ],
    }
    target = ensure_parent(path)
    target.write_text(
        yaml.safe_dump(payload, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    return len(entries)
