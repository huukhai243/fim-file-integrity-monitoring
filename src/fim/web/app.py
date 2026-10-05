"""Dashboard lịch sử thay đổi — API + trang tĩnh (Người 3).

Dashboard chỉ đọc CSDL, không tự quét: bộ quét chạy độc lập (``fim watch``) và
ghi vào cùng file SQLite. Nhờ WAL, dashboard đọc được trong khi bộ quét đang ghi.

Ngoại lệ duy nhất là ``POST /api/scan``: kích hoạt một lần quét thủ công, chạy
trong luồng nền để không chặn HTTP.

Lưu ý bảo mật: dashboard **không có xác thực**. Mặc định chỉ nghe 127.0.0.1.
Muốn mở ra mạng thì phải đặt sau reverse proxy có xác thực.
"""

from __future__ import annotations

import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ..analysis.heuristics import all_rules
from ..config import Config, load_config
from ..engine import Engine
from ..models import AlertStatus, ChangeType
from ..scope.whitelist import WhitelistError, entry_from_dict
from ..util import iso

STATIC_DIR = Path(__file__).parent / "static"


# ---------------------------------------------------------------------------
# Lược đồ dữ liệu vào
# ---------------------------------------------------------------------------


class WhitelistIn(BaseModel):
    """Mục whitelist gửi từ dashboard."""

    id: str | None = None
    path_glob: str | None = None
    digest: str | None = None
    rule_id: str | None = None
    change: str | None = None
    reason: str = Field(..., min_length=3, description="bắt buộc: vì sao thay đổi này an toàn")
    added_by: str = "dashboard"
    expires_at: str | None = None


class AlertUpdateIn(BaseModel):
    status: str
    note: str | None = None


class ApproveIn(BaseModel):
    event_ids: list[int] = Field(..., min_length=1)


# ---------------------------------------------------------------------------
# Ứng dụng
# ---------------------------------------------------------------------------


def create_app(config: Config | None = None) -> FastAPI:
    cfg = config or load_config()
    engine = Engine(cfg)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        """Đóng kết nối CSDL khi dashboard tắt.

        Dùng lifespan thay cho ``@app.on_event`` — hàm kia đã bị FastAPI đánh dấu
        loại bỏ.
        """
        yield
        engine.close()

    app = FastAPI(
        title="FIM Dashboard",
        description="Giám sát toàn vẹn file — lịch sử thay đổi và cảnh báo",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.engine = engine
    app.state.config = cfg
    app.state.scan_lock = threading.Lock()
    app.state.scan_running = False

    if cfg.web.cors_origins:
        from fastapi.middleware.cors import CORSMiddleware

        app.add_middleware(
            CORSMiddleware,
            allow_origins=cfg.web.cors_origins,
            allow_methods=["GET", "POST", "DELETE"],
            allow_headers=["*"],
        )

    # -- Tổng quan -----------------------------------------------------
    @app.get("/api/stats", tags=["tổng quan"])
    def get_stats(hours: float | None = Query(None, ge=0)) -> dict[str, Any]:
        """Số liệu cho các thẻ tổng quan trên đầu dashboard."""
        since = time.time() - hours * 3600 if hours else None
        stats = engine.store.stats(since)
        stats["scope"] = {
            "profile": engine.scope.profile.name,
            "roots": len(engine.scope.roots),
            "roots_missing": len(engine.scope.missing_roots),
            "critical_patterns": len(engine.scope.critical),
        }
        stats["watch_mode"] = cfg.watch.mode
        stats["scan_running"] = app.state.scan_running
        return stats

    @app.get("/api/timeline", tags=["tổng quan"])
    def get_timeline(
        hours: int = Query(24, ge=1, le=720),
        buckets: int = Query(24, ge=4, le=96),
    ) -> list[dict[str, Any]]:
        """Chuỗi thời gian số sự kiện theo mức nghiêm trọng."""
        return engine.store.timeline(hours=hours, buckets=buckets)

    @app.get("/api/top-paths", tags=["tổng quan"])
    def get_top_paths(
        limit: int = Query(10, ge=1, le=100),
        hours: float | None = Query(None, ge=0),
    ) -> list[dict[str, Any]]:
        """Đường dẫn thay đổi nhiều nhất — thường lộ ra whitelist còn thiếu."""
        since = time.time() - hours * 3600 if hours else None
        return engine.store.top_paths(limit, since)

    # -- Lịch sử thay đổi ----------------------------------------------
    @app.get("/api/events", tags=["lịch sử"])
    def list_events(
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
        severity: str | None = None,
        classification: str | None = None,
        change: str | None = None,
        path: str | None = None,
        hours: float | None = Query(None, ge=0),
        include_whitelisted: bool = True,
    ) -> dict[str, Any]:
        since = time.time() - hours * 3600 if hours else None
        filters = dict(
            severity=severity, classification=classification, change=change,
            path_like=path, since=since, include_whitelisted=include_whitelisted,
        )
        items = engine.store.query_events(limit=limit, offset=offset, **filters)
        for item in items:
            item["ts_iso"] = iso(item["ts"])
        return {
            "items": items,
            "total": engine.store.count_events(**filters),
            "limit": limit,
            "offset": offset,
        }

    @app.get("/api/events/{event_id}", tags=["lịch sử"])
    def get_event(event_id: int) -> dict[str, Any]:
        event = engine.store.get_event(event_id)
        if event is None:
            raise HTTPException(404, f"Không tìm thấy sự kiện {event_id}")
        verdict = engine.store.get_verdict(event_id)
        return {
            "event": event.to_dict(),
            "ts_iso": iso(event.ts),
            "verdict": verdict.to_dict() if verdict else None,
        }

    @app.post("/api/events/approve", tags=["lịch sử"])
    def approve_events(payload: ApproveIn) -> dict[str, Any]:
        """Chấp nhận thay đổi: cập nhật baseline để lần quét sau không báo lại."""
        count = engine.approve(payload.event_ids)
        return {"updated": count, "requested": len(payload.event_ids)}

    # -- Cảnh báo ------------------------------------------------------
    @app.get("/api/alerts", tags=["cảnh báo"])
    def list_alerts(
        status: str | None = None,
        severity: str | None = None,
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> list[dict[str, Any]]:
        alerts = engine.store.query_alerts(
            status=status, severity=severity, limit=limit, offset=offset
        )
        for alert in alerts:
            alert["created_at_iso"] = iso(alert["created_at"])
        return alerts

    @app.post("/api/alerts/{alert_id}", tags=["cảnh báo"])
    def update_alert(alert_id: int, payload: AlertUpdateIn) -> dict[str, Any]:
        try:
            status = AlertStatus(payload.status)
        except ValueError:
            raise HTTPException(
                400, f"Trạng thái không hợp lệ: {payload.status}. "
                f"Chọn: {', '.join(s.value for s in AlertStatus)}"
            )
        if not engine.store.update_alert_status(alert_id, status, payload.note):
            raise HTTPException(404, f"Không tìm thấy cảnh báo {alert_id}")
        return {"id": alert_id, "status": status.value}

    # -- Whitelist -----------------------------------------------------
    @app.get("/api/whitelist", tags=["whitelist"])
    def list_whitelist() -> list[dict[str, Any]]:
        return [e.to_dict() for e in engine.store.list_whitelist()]

    @app.post("/api/whitelist", tags=["whitelist"])
    def add_whitelist(payload: WhitelistIn) -> dict[str, Any]:
        try:
            entry = entry_from_dict({
                "id": payload.id,
                "match": {
                    k: v for k, v in (
                        ("path_glob", payload.path_glob), ("digest", payload.digest),
                        ("rule_id", payload.rule_id), ("change", payload.change),
                    ) if v
                },
                "reason": payload.reason,
                "added_by": payload.added_by,
                "expires_at": payload.expires_at,
            })
        except (WhitelistError, ValueError) as exc:
            raise HTTPException(400, str(exc))
        engine.whitelist.add(entry)
        return entry.to_dict()

    @app.delete("/api/whitelist/{entry_id}", tags=["whitelist"])
    def remove_whitelist(entry_id: str) -> dict[str, Any]:
        if not engine.whitelist.remove(entry_id):
            raise HTTPException(404, f"Không tìm thấy mục {entry_id}")
        return {"id": entry_id, "deleted": True}

    @app.post("/api/whitelist/reload", tags=["whitelist"])
    def reload_whitelist() -> dict[str, Any]:
        return {"active": engine.reload_whitelist()}

    # -- Phạm vi & luật ------------------------------------------------
    @app.get("/api/scope", tags=["cấu hình"])
    def get_scope() -> dict[str, Any]:
        return engine.scope.summary()

    @app.get("/api/rules", tags=["cấu hình"])
    def get_rules() -> list[dict[str, Any]]:
        disabled = set(cfg.analysis.disabled_rules)
        return [
            {
                "rule_id": r.rule_id,
                "title": r.title,
                "weight": cfg.analysis.rule_weights.get(r.rule_id, r.weight),
                "description": (r.description or "").strip(),
                "enabled": r.rule_id not in disabled,
            }
            for r in all_rules()
        ]

    @app.get("/api/baselines", tags=["cấu hình"])
    def list_baselines() -> list[dict[str, Any]]:
        items = engine.store.list_baselines()
        for item in items:
            item["created_at_iso"] = iso(item["created_at"])
        return items

    @app.get("/api/scans", tags=["cấu hình"])
    def list_scans(limit: int = Query(20, ge=1, le=100)) -> list[dict[str, Any]]:
        return engine.store.recent_scans(limit)

    @app.post("/api/scan", tags=["cấu hình"])
    def trigger_scan() -> dict[str, Any]:
        """Chạy một lần quét ở luồng nền.

        Khoá lại để không có hai lần quét chồng nhau — chúng sẽ tranh nhau ghi
        CSDL và sinh sự kiện trùng.
        """
        if not app.state.scan_lock.acquire(blocking=False):
            raise HTTPException(409, "Đang có một lần quét chạy dở")

        if engine.store.active_baseline_id() is None:
            app.state.scan_lock.release()
            raise HTTPException(400, "Chưa có baseline. Chạy 'fim baseline' trước.")

        def run() -> None:
            app.state.scan_running = True
            try:
                engine.scan_once()
            except Exception as exc:                    # noqa: BLE001
                print(f"[dashboard] quét lỗi: {exc}")
            finally:
                app.state.scan_running = False
                app.state.scan_lock.release()

        threading.Thread(target=run, name="fim-manual-scan", daemon=True).start()
        return {"started": True}

    @app.get("/api/health", tags=["cấu hình"])
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "baseline": engine.store.active_baseline_id(),
            "alerts": engine.alerts.stats(),
        }

    # -- Trang tĩnh ----------------------------------------------------
    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    return app


app = None  # tạo bằng create_app() trong cli.serve, tránh mở CSDL khi chỉ import
