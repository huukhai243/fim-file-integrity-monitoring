"""Tầng lưu trữ SQLite — kho dữ liệu chung của cả 3 module.

Người 1 ghi ``baselines`` / ``files`` / ``events``.
Người 2 ghi ``verdicts`` / ``alerts``.
Người 3 đọc tất cả và ghi ``whitelist``.

Dùng SQLite vì FIM chạy trên chính máy được giám sát: không thêm dịch vụ ngoài,
file CSDL đi kèm được, và WAL cho phép dashboard đọc trong khi bộ quét đang ghi.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

from .models import (
    Alert,
    AlertStatus,
    ChangeEvent,
    ChangeType,
    Classification,
    FileRecord,
    RuleHit,
    Severity,
    Verdict,
    WhitelistEntry,
)
from .util import ensure_parent, normalize_path

SCHEMA_VERSION = 1

_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Một lần chốt baseline. Giữ nhiều bản để so được "trước/sau khi vá hệ thống".
CREATE TABLE IF NOT EXISTS baselines (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    label       TEXT    NOT NULL,
    created_at  REAL    NOT NULL,
    algo        TEXT    NOT NULL,
    scope_json  TEXT    NOT NULL,
    file_count  INTEGER NOT NULL DEFAULT 0,
    total_bytes INTEGER NOT NULL DEFAULT 0,
    status      TEXT    NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS files (
    baseline_id  INTEGER NOT NULL REFERENCES baselines(id) ON DELETE CASCADE,
    path         TEXT    NOT NULL,
    size         INTEGER NOT NULL,
    mtime        REAL    NOT NULL,
    ctime        REAL    NOT NULL,
    mode         INTEGER NOT NULL,
    uid          INTEGER NOT NULL,
    gid          INTEGER NOT NULL,
    digest       TEXT,
    is_symlink   INTEGER NOT NULL DEFAULT 0,
    link_target  TEXT,
    scanned_at   REAL    NOT NULL,
    error        TEXT,
    PRIMARY KEY (baseline_id, path)
);
CREATE INDEX IF NOT EXISTS idx_files_digest ON files(digest);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL    NOT NULL,
    baseline_id INTEGER REFERENCES baselines(id) ON DELETE SET NULL,
    path        TEXT    NOT NULL,
    change      TEXT    NOT NULL,
    source      TEXT    NOT NULL,
    old_path    TEXT,
    before_json TEXT,
    after_json  TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_path ON events(path);

CREATE TABLE IF NOT EXISTS verdicts (
    event_id       INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
    classification TEXT    NOT NULL,
    severity       TEXT    NOT NULL,
    score          INTEGER NOT NULL,
    whitelisted    INTEGER NOT NULL DEFAULT 0,
    whitelist_id   TEXT,
    hits_json      TEXT    NOT NULL,
    created_at     REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verdicts_sev   ON verdicts(severity);
CREATE INDEX IF NOT EXISTS idx_verdicts_class ON verdicts(classification);

CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id   INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    severity   TEXT    NOT NULL,
    title      TEXT    NOT NULL,
    summary    TEXT    NOT NULL,
    path       TEXT    NOT NULL DEFAULT '',
    status     TEXT    NOT NULL DEFAULT 'new',
    created_at REAL    NOT NULL,
    updated_at REAL    NOT NULL,
    note       TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, created_at DESC);

CREATE TABLE IF NOT EXISTS whitelist (
    id         TEXT    PRIMARY KEY,
    path_glob  TEXT,
    digest     TEXT,
    rule_id    TEXT,
    change     TEXT,
    reason     TEXT    NOT NULL DEFAULT '',
    added_by   TEXT    NOT NULL DEFAULT '',
    created_at REAL    NOT NULL,
    expires_at REAL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    hit_count  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    baseline_id   INTEGER REFERENCES baselines(id) ON DELETE SET NULL,
    mode          TEXT    NOT NULL,
    started_at    REAL    NOT NULL,
    finished_at   REAL,
    files_scanned INTEGER NOT NULL DEFAULT 0,
    changes_found INTEGER NOT NULL DEFAULT 0,
    status        TEXT    NOT NULL DEFAULT 'running',
    error         TEXT
);
"""


def _json_or_none(value: Any) -> str | None:
    return None if value is None else json.dumps(value, ensure_ascii=False)


def _record_from_json(text: str | None) -> FileRecord | None:
    if not text:
        return None
    return FileRecord.from_dict(json.loads(text))


class Store:
    """Bọc SQLite, an toàn khi dùng từ nhiều luồng.

    Mỗi luồng có kết nối riêng (``threading.local``) vì đối tượng ``Connection``
    của SQLite không dùng chung giữa các luồng được — bộ theo dõi realtime chạy
    trên luồng riêng còn dashboard chạy trên luồng của uvicorn.
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self._local = threading.local()
        self._write_lock = threading.Lock()
        if self.db_path != ":memory:":
            ensure_parent(self.db_path)
        self._init_schema()

    # -- kết nối -------------------------------------------------------
    @property
    def conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA busy_timeout = 30000")
            self._local.conn = conn
        return conn

    def _init_schema(self) -> None:
        with self._write_lock:
            self.conn.executescript(_SCHEMA)
            self.conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            self.conn.commit()

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Baseline (Người 1)
    # ------------------------------------------------------------------

    def create_baseline(self, label: str, algo: str, scope: dict[str, Any]) -> int:
        with self._write_lock:
            cur = self.conn.execute(
                "INSERT INTO baselines(label, created_at, algo, scope_json) VALUES(?,?,?,?)",
                (label, time.time(), algo, json.dumps(scope, ensure_ascii=False)),
            )
            self.conn.commit()
            return int(cur.lastrowid)

    def add_files(self, baseline_id: int, records: Iterable[FileRecord]) -> int:
        """Ghi hàng loạt bản ghi file vào baseline. Trả về số dòng đã ghi."""
        rows = [
            (
                baseline_id, normalize_path(r.path), r.size, r.mtime, r.ctime, r.mode,
                r.uid, r.gid, r.digest, int(r.is_symlink), r.link_target, r.scanned_at,
                r.error,
            )
            for r in records
        ]
        if not rows:
            return 0
        with self._write_lock:
            self.conn.executemany(
                "INSERT OR REPLACE INTO files(baseline_id, path, size, mtime, ctime, mode,"
                " uid, gid, digest, is_symlink, link_target, scanned_at, error)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                rows,
            )
            self.conn.commit()
        return len(rows)

    def finalize_baseline(self, baseline_id: int) -> None:
        """Chốt số liệu tổng hợp sau khi nạp xong file."""
        with self._write_lock:
            self.conn.execute(
                "UPDATE baselines SET file_count = (SELECT COUNT(*) FROM files WHERE baseline_id = ?),"
                " total_bytes = (SELECT COALESCE(SUM(size),0) FROM files WHERE baseline_id = ?)"
                " WHERE id = ?",
                (baseline_id, baseline_id, baseline_id),
            )
            self.conn.commit()

    def active_baseline_id(self) -> int | None:
        row = self.conn.execute(
            "SELECT id FROM baselines WHERE status = 'active' ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        return int(row["id"]) if row else None

    def get_baseline(self, baseline_id: int) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM baselines WHERE id = ?", (baseline_id,)).fetchone()
        if not row:
            return None
        data = dict(row)
        data["scope"] = json.loads(data.pop("scope_json"))
        return data

    def list_baselines(self) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM baselines ORDER BY created_at DESC").fetchall()
        out = []
        for row in rows:
            data = dict(row)
            data["scope"] = json.loads(data.pop("scope_json"))
            out.append(data)
        return out

    def archive_baselines(self, keep_id: int | None = None) -> None:
        """Đánh dấu mọi baseline khác là lưu trữ — chỉ một bản được 'active'."""
        with self._write_lock:
            if keep_id is None:
                self.conn.execute("UPDATE baselines SET status = 'archived'")
            else:
                self.conn.execute(
                    "UPDATE baselines SET status = 'archived' WHERE id != ?", (keep_id,)
                )
            self.conn.commit()

    def get_file(self, baseline_id: int, path: str) -> FileRecord | None:
        row = self.conn.execute(
            "SELECT * FROM files WHERE baseline_id = ? AND path = ?",
            (baseline_id, normalize_path(path)),
        ).fetchone()
        return self._row_to_record(row) if row else None

    def iter_files(self, baseline_id: int) -> Iterator[FileRecord]:
        """Duyệt từng bản ghi — dùng cursor để không nạp cả baseline vào RAM."""
        cur = self.conn.execute(
            "SELECT * FROM files WHERE baseline_id = ? ORDER BY path", (baseline_id,)
        )
        for row in cur:
            yield self._row_to_record(row)

    def file_paths(self, baseline_id: int) -> set[str]:
        rows = self.conn.execute(
            "SELECT path FROM files WHERE baseline_id = ?", (baseline_id,)
        ).fetchall()
        return {row["path"] for row in rows}

    def update_file(self, baseline_id: int, record: FileRecord) -> None:
        """Cập nhật baseline sau khi một thay đổi đã được chấp nhận."""
        self.add_files(baseline_id, [record])

    def delete_file(self, baseline_id: int, path: str) -> None:
        with self._write_lock:
            self.conn.execute(
                "DELETE FROM files WHERE baseline_id = ? AND path = ?",
                (baseline_id, normalize_path(path)),
            )
            self.conn.commit()

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> FileRecord:
        return FileRecord(
            path=row["path"], size=row["size"], mtime=row["mtime"], ctime=row["ctime"],
            mode=row["mode"], uid=row["uid"], gid=row["gid"], digest=row["digest"],
            is_symlink=bool(row["is_symlink"]), link_target=row["link_target"],
            scanned_at=row["scanned_at"], error=row["error"],
        )

    # ------------------------------------------------------------------
    # Sự kiện (Người 1 ghi, Người 2 & 3 đọc)
    # ------------------------------------------------------------------

    def add_event(self, event: ChangeEvent, baseline_id: int | None = None) -> int:
        with self._write_lock:
            cur = self.conn.execute(
                "INSERT INTO events(ts, baseline_id, path, change, source, old_path,"
                " before_json, after_json) VALUES(?,?,?,?,?,?,?,?)",
                (
                    event.ts, baseline_id, normalize_path(event.path), event.change.value,
                    event.source, event.old_path,
                    _json_or_none(event.before.to_dict() if event.before else None),
                    _json_or_none(event.after.to_dict() if event.after else None),
                ),
            )
            self.conn.commit()
        event.id = int(cur.lastrowid)
        return event.id

    def get_event(self, event_id: int) -> ChangeEvent | None:
        row = self.conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        return self._row_to_event(row) if row else None

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> ChangeEvent:
        return ChangeEvent(
            id=row["id"], ts=row["ts"], path=row["path"],
            change=ChangeType(row["change"]), source=row["source"], old_path=row["old_path"],
            before=_record_from_json(row["before_json"]),
            after=_record_from_json(row["after_json"]),
        )

    def query_events(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        severity: str | None = None,
        classification: str | None = None,
        change: str | None = None,
        path_like: str | None = None,
        since: float | None = None,
        until: float | None = None,
        include_whitelisted: bool = True,
    ) -> list[dict[str, Any]]:
        """Truy vấn sự kiện kèm kết luận — nguồn dữ liệu chính của dashboard."""
        where, params = self._event_filters(
            severity, classification, change, path_like, since, until, include_whitelisted
        )
        sql = (
            "SELECT e.*, v.classification, v.severity, v.score, v.whitelisted,"
            " v.whitelist_id, v.hits_json"
            " FROM events e LEFT JOIN verdicts v ON v.event_id = e.id"
            f" {where} ORDER BY e.ts DESC, e.id DESC LIMIT ? OFFSET ?"
        )
        rows = self.conn.execute(sql, (*params, limit, offset)).fetchall()
        return [self._row_to_event_dict(row) for row in rows]

    def count_events(
        self,
        *,
        severity: str | None = None,
        classification: str | None = None,
        change: str | None = None,
        path_like: str | None = None,
        since: float | None = None,
        until: float | None = None,
        include_whitelisted: bool = True,
    ) -> int:
        where, params = self._event_filters(
            severity, classification, change, path_like, since, until, include_whitelisted
        )
        sql = (
            "SELECT COUNT(*) AS n FROM events e"
            f" LEFT JOIN verdicts v ON v.event_id = e.id {where}"
        )
        return int(self.conn.execute(sql, params).fetchone()["n"])

    @staticmethod
    def _event_filters(
        severity: str | None,
        classification: str | None,
        change: str | None,
        path_like: str | None,
        since: float | None,
        until: float | None,
        include_whitelisted: bool,
    ) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if severity:
            clauses.append("v.severity = ?")
            params.append(severity)
        if classification:
            clauses.append("v.classification = ?")
            params.append(classification)
        if change:
            clauses.append("e.change = ?")
            params.append(change)
        if path_like:
            clauses.append("e.path LIKE ?")
            params.append(f"%{path_like}%")
        if since is not None:
            clauses.append("e.ts >= ?")
            params.append(since)
        if until is not None:
            clauses.append("e.ts <= ?")
            params.append(until)
        if not include_whitelisted:
            clauses.append("COALESCE(v.whitelisted, 0) = 0")
        return ("WHERE " + " AND ".join(clauses)) if clauses else "", params

    @staticmethod
    def _row_to_event_dict(row: sqlite3.Row) -> dict[str, Any]:
        keys = set(row.keys())
        data: dict[str, Any] = {
            "id": row["id"],
            "ts": row["ts"],
            "path": row["path"],
            "change": row["change"],
            "source": row["source"],
            "old_path": row["old_path"],
            "before": json.loads(row["before_json"]) if row["before_json"] else None,
            "after": json.loads(row["after_json"]) if row["after_json"] else None,
        }
        if "severity" in keys and row["severity"]:
            hits = json.loads(row["hits_json"]) if row["hits_json"] else []
            data["verdict"] = {
                "classification": row["classification"],
                "severity": row["severity"],
                "score": row["score"],
                "whitelisted": bool(row["whitelisted"]),
                "whitelist_id": row["whitelist_id"],
                "hits": hits,
            }
        else:
            data["verdict"] = None
        return data

    # ------------------------------------------------------------------
    # Kết luận & cảnh báo (Người 2)
    # ------------------------------------------------------------------

    def add_verdict(self, verdict: Verdict) -> None:
        if verdict.event_id is None:
            raise ValueError("Verdict phải có event_id trước khi lưu")
        with self._write_lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO verdicts(event_id, classification, severity, score,"
                " whitelisted, whitelist_id, hits_json, created_at) VALUES(?,?,?,?,?,?,?,?)",
                (
                    verdict.event_id, verdict.classification.value, verdict.severity.value,
                    verdict.score, int(verdict.whitelisted), verdict.whitelist_id,
                    json.dumps([h.to_dict() for h in verdict.hits], ensure_ascii=False),
                    verdict.created_at,
                ),
            )
            self.conn.commit()

    def get_verdict(self, event_id: int) -> Verdict | None:
        row = self.conn.execute(
            "SELECT * FROM verdicts WHERE event_id = ?", (event_id,)
        ).fetchone()
        if not row:
            return None
        return Verdict(
            event_id=row["event_id"],
            classification=Classification(row["classification"]),
            severity=Severity(row["severity"]),
            score=row["score"],
            whitelisted=bool(row["whitelisted"]),
            whitelist_id=row["whitelist_id"],
            hits=[RuleHit(**h) for h in json.loads(row["hits_json"])],
            created_at=row["created_at"],
        )

    def add_alert(self, alert: Alert) -> int:
        with self._write_lock:
            cur = self.conn.execute(
                "INSERT INTO alerts(event_id, severity, title, summary, path, status,"
                " created_at, updated_at, note) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    alert.event_id, alert.severity.value, alert.title, alert.summary,
                    alert.path, alert.status.value, alert.created_at, alert.updated_at,
                    alert.note,
                ),
            )
            self.conn.commit()
        alert.id = int(cur.lastrowid)
        return alert.id

    def query_alerts(
        self, *, status: str | None = None, severity: str | None = None,
        limit: int = 50, offset: int = 0,
    ) -> list[dict[str, Any]]:
        clauses, params = [], []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self.conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
        return [dict(row) for row in rows]

    def update_alert_status(
        self, alert_id: int, status: AlertStatus, note: str | None = None
    ) -> bool:
        with self._write_lock:
            cur = self.conn.execute(
                "UPDATE alerts SET status = ?, updated_at = ?,"
                " note = COALESCE(?, note) WHERE id = ?",
                (status.value, time.time(), note, alert_id),
            )
            self.conn.commit()
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Whitelist (Người 3)
    # ------------------------------------------------------------------

    def upsert_whitelist(self, entry: WhitelistEntry) -> None:
        with self._write_lock:
            self.conn.execute(
                "INSERT INTO whitelist(id, path_glob, digest, rule_id, change, reason,"
                " added_by, created_at, expires_at, enabled, hit_count)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(id) DO UPDATE SET path_glob=excluded.path_glob,"
                " digest=excluded.digest, rule_id=excluded.rule_id, change=excluded.change,"
                " reason=excluded.reason, added_by=excluded.added_by,"
                " expires_at=excluded.expires_at, enabled=excluded.enabled",
                (
                    entry.id, entry.path_glob, entry.digest, entry.rule_id,
                    entry.change.value if entry.change else None, entry.reason,
                    entry.added_by, entry.created_at, entry.expires_at,
                    int(entry.enabled), entry.hit_count,
                ),
            )
            self.conn.commit()

    def list_whitelist(self, *, only_active: bool = False) -> list[WhitelistEntry]:
        rows = self.conn.execute("SELECT * FROM whitelist ORDER BY id").fetchall()
        entries = [
            WhitelistEntry(
                id=row["id"], path_glob=row["path_glob"], digest=row["digest"],
                rule_id=row["rule_id"],
                change=ChangeType(row["change"]) if row["change"] else None,
                reason=row["reason"], added_by=row["added_by"],
                created_at=row["created_at"], expires_at=row["expires_at"],
                enabled=bool(row["enabled"]), hit_count=row["hit_count"],
            )
            for row in rows
        ]
        return [e for e in entries if e.is_active()] if only_active else entries

    def delete_whitelist(self, entry_id: str) -> bool:
        with self._write_lock:
            cur = self.conn.execute("DELETE FROM whitelist WHERE id = ?", (entry_id,))
            self.conn.commit()
        return cur.rowcount > 0

    def bump_whitelist_hit(self, entry_id: str) -> None:
        """Đếm số lần một mục whitelist được dùng — mục 0 lượt dùng là mục nên xoá."""
        with self._write_lock:
            self.conn.execute(
                "UPDATE whitelist SET hit_count = hit_count + 1 WHERE id = ?", (entry_id,)
            )
            self.conn.commit()

    # ------------------------------------------------------------------
    # Lần quét & thống kê
    # ------------------------------------------------------------------

    def start_scan(self, mode: str, baseline_id: int | None) -> int:
        with self._write_lock:
            cur = self.conn.execute(
                "INSERT INTO scans(baseline_id, mode, started_at) VALUES(?,?,?)",
                (baseline_id, mode, time.time()),
            )
            self.conn.commit()
            return int(cur.lastrowid)

    def finish_scan(
        self, scan_id: int, files_scanned: int, changes_found: int,
        status: str = "ok", error: str | None = None,
    ) -> None:
        with self._write_lock:
            self.conn.execute(
                "UPDATE scans SET finished_at = ?, files_scanned = ?, changes_found = ?,"
                " status = ?, error = ? WHERE id = ?",
                (time.time(), files_scanned, changes_found, status, error, scan_id),
            )
            self.conn.commit()

    def recent_scans(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]

    def stats(self, since: float | None = None) -> dict[str, Any]:
        """Số liệu tổng hợp cho các thẻ trên dashboard."""
        params: Sequence[Any] = (since,) if since is not None else ()
        time_filter = "WHERE e.ts >= ?" if since is not None else ""

        by_severity = {
            row["severity"]: row["n"]
            for row in self.conn.execute(
                "SELECT v.severity, COUNT(*) AS n FROM verdicts v"
                " JOIN events e ON e.id = v.event_id"
                f" {time_filter} GROUP BY v.severity",
                params,
            ).fetchall()
        }
        by_class = {
            row["classification"]: row["n"]
            for row in self.conn.execute(
                "SELECT v.classification, COUNT(*) AS n FROM verdicts v"
                " JOIN events e ON e.id = v.event_id"
                f" {time_filter} GROUP BY v.classification",
                params,
            ).fetchall()
        }
        by_change = {
            row["change"]: row["n"]
            for row in self.conn.execute(
                f"SELECT e.change, COUNT(*) AS n FROM events e {time_filter} GROUP BY e.change",
                params,
            ).fetchall()
        }

        baseline_id = self.active_baseline_id()
        baseline = self.get_baseline(baseline_id) if baseline_id else None
        last_scan = self.conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT 1"
        ).fetchone()

        return {
            "events_total": self.count_events(since=since),
            "by_severity": by_severity,
            "by_classification": by_class,
            "by_change": by_change,
            "alerts_open": int(
                self.conn.execute(
                    "SELECT COUNT(*) AS n FROM alerts WHERE status = 'new'"
                ).fetchone()["n"]
            ),
            "whitelist_active": sum(1 for e in self.list_whitelist(only_active=True)),
            "baseline": {
                "id": baseline["id"],
                "label": baseline["label"],
                "created_at": baseline["created_at"],
                "file_count": baseline["file_count"],
                "total_bytes": baseline["total_bytes"],
            } if baseline else None,
            "last_scan": dict(last_scan) if last_scan else None,
        }

    def timeline(self, *, hours: int = 24, buckets: int = 24) -> list[dict[str, Any]]:
        """Chuỗi thời gian số sự kiện theo mức nghiêm trọng, cho biểu đồ dashboard."""
        end = time.time()
        start = end - hours * 3600
        width = (end - start) / max(buckets, 1)

        rows = self.conn.execute(
            "SELECT e.ts, COALESCE(v.severity, 'info') AS severity FROM events e"
            " LEFT JOIN verdicts v ON v.event_id = e.id WHERE e.ts >= ?",
            (start,),
        ).fetchall()

        series = [
            {
                "start": start + i * width,
                "end": start + (i + 1) * width,
                "info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0, "total": 0,
            }
            for i in range(buckets)
        ]
        for row in rows:
            idx = min(int((row["ts"] - start) / width), buckets - 1)
            if idx < 0:
                continue
            bucket = series[idx]
            bucket[row["severity"]] = bucket.get(row["severity"], 0) + 1
            bucket["total"] += 1
        return series

    def top_paths(self, limit: int = 10, since: float | None = None) -> list[dict[str, Any]]:
        """Các đường dẫn thay đổi nhiều nhất — thường lộ ra whitelist còn thiếu."""
        where, params = ("WHERE e.ts >= ?", [since]) if since is not None else ("", [])
        rows = self.conn.execute(
            "SELECT e.path, COUNT(*) AS n, MAX(e.ts) AS last_ts,"
            " MAX(COALESCE(v.score, 0)) AS max_score FROM events e"
            f" LEFT JOIN verdicts v ON v.event_id = e.id {where}"
            " GROUP BY e.path ORDER BY n DESC LIMIT ?",
            (*params, limit),
        ).fetchall()
        return [dict(row) for row in rows]

    def purge_old_events(self, older_than_days: int) -> int:
        """Xoá sự kiện quá hạn lưu trữ. Verdict/alert đi kèm bị xoá theo (ON DELETE CASCADE)."""
        if older_than_days <= 0:
            return 0
        cutoff = time.time() - older_than_days * 86400
        with self._write_lock:
            cur = self.conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
            self.conn.commit()
        return cur.rowcount
