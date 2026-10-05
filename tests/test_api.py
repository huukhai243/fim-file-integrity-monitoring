"""Test API dashboard (Người 3)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from fim.config import Config
from fim.web.app import create_app


@pytest.fixture
def client(config: Config, tmp_tree: Path) -> TestClient:
    """Client kèm dữ liệu sẵn: một baseline và vài thay đổi đã phân loại."""
    app = create_app(config)
    engine = app.state.engine
    engine.build_baseline("b1")

    (tmp_tree / "etc/app.conf").write_text("da doi\n", encoding="utf-8")
    (tmp_tree / "etc/passwd").write_text(
        "root:x:0:0::/root:/bin/sh\nevil:x:0:0::/root:/bin/sh\n", encoding="utf-8"
    )
    engine.scan_once()

    with TestClient(app) as c:
        yield c


class TestHealth:
    def test_health_ok(self, client: TestClient):
        data = client.get("/api/health").json()
        assert data["status"] == "ok"
        assert data["baseline"] is not None

    def test_trang_chu_tra_ve_html(self, client: TestClient):
        res = client.get("/")
        assert res.status_code == 200
        assert "text/html" in res.headers["content-type"]

    def test_tai_duoc_file_tinh(self, client: TestClient):
        assert client.get("/static/app.js").status_code == 200
        assert client.get("/static/style.css").status_code == 200


class TestStats:
    def test_thong_ke_co_du_khoa(self, client: TestClient):
        data = client.get("/api/stats").json()
        for key in ("events_total", "by_severity", "by_change", "alerts_open",
                    "baseline", "scope", "watch_mode"):
            assert key in data

    def test_dem_dung_so_su_kien(self, client: TestClient):
        assert client.get("/api/stats").json()["events_total"] == 2

    def test_loc_theo_gio(self, client: TestClient):
        assert client.get("/api/stats?hours=24").json()["events_total"] == 2
        # Cửa sổ 0 giờ nghĩa là "không lọc" (hours=0 là falsy), nên vẫn đủ 2.
        assert client.get("/api/stats?hours=0").json()["events_total"] == 2

    def test_thong_tin_pham_vi(self, client: TestClient):
        scope = client.get("/api/stats").json()["scope"]
        assert scope["profile"] == "custom"
        assert scope["roots"] == 1


class TestEvents:
    def test_liet_ke_kem_verdict(self, client: TestClient):
        data = client.get("/api/events").json()
        assert data["total"] == 2
        assert len(data["items"]) == 2
        assert data["items"][0]["verdict"] is not None
        assert "ts_iso" in data["items"][0]

    def test_loc_theo_muc(self, client: TestClient):
        # /etc/passwd là file trọng yếu nên phải có ít nhất một sự kiện medium+.
        all_events = client.get("/api/events").json()["items"]
        severities = {e["verdict"]["severity"] for e in all_events}
        target = next(s for s in ("critical", "high", "medium") if s in severities)

        filtered = client.get(f"/api/events?severity={target}").json()
        assert filtered["total"] >= 1
        assert all(e["verdict"]["severity"] == target for e in filtered["items"])

    def test_loc_theo_duong_dan(self, client: TestClient):
        data = client.get("/api/events?path=passwd").json()
        assert data["total"] == 1
        assert "passwd" in data["items"][0]["path"]

    def test_loc_theo_loai_thay_doi(self, client: TestClient):
        data = client.get("/api/events?change=modified").json()
        assert all(e["change"] == "modified" for e in data["items"])

    def test_phan_trang(self, client: TestClient):
        page1 = client.get("/api/events?limit=1&offset=0").json()
        page2 = client.get("/api/events?limit=1&offset=1").json()
        assert page1["total"] == page2["total"] == 2
        assert page1["items"][0]["id"] != page2["items"][0]["id"]

    def test_limit_vuot_nguong_bi_tu_choi(self, client: TestClient):
        assert client.get("/api/events?limit=9999").status_code == 422

    def test_chi_tiet_mot_su_kien(self, client: TestClient):
        event_id = client.get("/api/events").json()["items"][0]["id"]
        data = client.get(f"/api/events/{event_id}").json()
        assert data["event"]["id"] == event_id
        assert data["verdict"] is not None
        assert "hits" in data["verdict"]

    def test_su_kien_khong_ton_tai_tra_404(self, client: TestClient):
        assert client.get("/api/events/99999").status_code == 404


class TestApprove:
    def test_chap_nhan_thay_doi(self, client: TestClient):
        ids = [e["id"] for e in client.get("/api/events").json()["items"]]
        res = client.post("/api/events/approve", json={"event_ids": ids})
        assert res.status_code == 200
        assert res.json()["updated"] == len(ids)

    def test_danh_sach_rong_bi_tu_choi(self, client: TestClient):
        assert client.post("/api/events/approve", json={"event_ids": []}).status_code == 422


class TestAlerts:
    def test_liet_ke_canh_bao(self, client: TestClient):
        alerts = client.get("/api/alerts").json()
        assert isinstance(alerts, list)
        if alerts:
            assert "created_at_iso" in alerts[0]

    def test_doi_trang_thai(self, client: TestClient):
        alerts = client.get("/api/alerts?status=new").json()
        if not alerts:
            pytest.skip("không có cảnh báo nào để cập nhật")
        alert_id = alerts[0]["id"]
        res = client.post(f"/api/alerts/{alert_id}",
                          json={"status": "ack", "note": "dang xem"})
        assert res.status_code == 200
        assert client.get("/api/alerts?status=ack").json()[0]["note"] == "dang xem"

    def test_trang_thai_sai_tra_400(self, client: TestClient):
        alerts = client.get("/api/alerts").json()
        if not alerts:
            pytest.skip("không có cảnh báo nào")
        res = client.post(f"/api/alerts/{alerts[0]['id']}", json={"status": "khong-ton-tai"})
        assert res.status_code == 400
        assert "không hợp lệ" in res.json()["detail"]

    def test_canh_bao_khong_ton_tai_tra_404(self, client: TestClient):
        assert client.post("/api/alerts/99999", json={"status": "ack"}).status_code == 404


class TestWhitelist:
    def test_them_va_liet_ke(self, client: TestClient):
        res = client.post("/api/whitelist", json={
            "path_glob": "/var/log/**",
            "reason": "log thay đổi liên tục theo thiết kế",
        })
        assert res.status_code == 200
        entry_id = res.json()["id"]
        assert any(e["id"] == entry_id for e in client.get("/api/whitelist").json())

    def test_thieu_reason_bi_tu_choi(self, client: TestClient):
        # Bảo vệ quan trọng: whitelist không giải thích được không được tồn tại.
        res = client.post("/api/whitelist", json={"path_glob": "/x/**"})
        assert res.status_code == 422

    def test_reason_qua_ngan_bi_tu_choi(self, client: TestClient):
        res = client.post("/api/whitelist", json={"path_glob": "/x/**", "reason": "x"})
        assert res.status_code == 422

    def test_thieu_ca_path_va_digest_tra_400(self, client: TestClient):
        res = client.post("/api/whitelist", json={"reason": "co ly do day du"})
        assert res.status_code == 400

    def test_xoa(self, client: TestClient):
        entry_id = client.post("/api/whitelist", json={
            "path_glob": "/tmp/**", "reason": "de xoa thu",
        }).json()["id"]
        assert client.delete(f"/api/whitelist/{entry_id}").status_code == 200
        assert not any(e["id"] == entry_id for e in client.get("/api/whitelist").json())

    def test_xoa_muc_khong_ton_tai_tra_404(self, client: TestClient):
        assert client.delete("/api/whitelist/khong-ton-tai").status_code == 404

    def test_reload(self, client: TestClient):
        assert "active" in client.post("/api/whitelist/reload").json()

    def test_whitelist_anh_huong_lan_quet_sau(self, client: TestClient, tmp_tree: Path):
        posix = str(tmp_tree).replace("\\", "/")
        client.post("/api/whitelist", json={
            "path_glob": f"{posix}/etc/**",
            "reason": "thu muc cau hinh da duoc duyet",
        })
        (tmp_tree / "etc/new2.conf").write_text("x\n", encoding="utf-8")

        engine = client.app.state.engine
        engine.scan_once()

        newest = client.get("/api/events?limit=1").json()["items"][0]
        assert newest["verdict"]["whitelisted"]


class TestConfigEndpoints:
    def test_pham_vi(self, client: TestClient):
        scope = client.get("/api/scope").json()
        for key in ("profile", "include", "exclude", "critical", "roots_present"):
            assert key in scope

    def test_bo_luat(self, client: TestClient):
        rules = client.get("/api/rules").json()
        assert len(rules) >= 20
        ids = {r["rule_id"] for r in rules}
        assert {"H001", "H020", "H090"} <= ids
        assert all({"rule_id", "title", "weight", "description", "enabled"} <= set(r)
                   for r in rules)

    def test_danh_sach_baseline(self, client: TestClient):
        baselines = client.get("/api/baselines").json()
        assert len(baselines) == 1
        assert baselines[0]["status"] == "active"
        assert "created_at_iso" in baselines[0]

    def test_danh_sach_lan_quet(self, client: TestClient):
        scans = client.get("/api/scans").json()
        assert any(s["mode"] in ("baseline", "scan") for s in scans)

    def test_timeline(self, client: TestClient):
        series = client.get("/api/timeline?hours=24&buckets=12").json()
        assert len(series) == 12
        assert sum(b["total"] for b in series) == 2

    def test_timeline_gioi_han_tham_so(self, client: TestClient):
        assert client.get("/api/timeline?hours=99999").status_code == 422
        assert client.get("/api/timeline?buckets=1").status_code == 422

    def test_top_paths(self, client: TestClient):
        paths = client.get("/api/top-paths?limit=5").json()
        assert len(paths) <= 5
        assert all({"path", "n", "last_ts"} <= set(p) for p in paths)


class TestScanTrigger:
    def test_quet_thu_cong(self, client: TestClient, tmp_tree: Path):
        (tmp_tree / "etc/trigger.conf").write_text("x\n", encoding="utf-8")
        assert client.post("/api/scan").json()["started"] is True

    def test_khong_co_baseline_tra_400(self, config: Config):
        app = create_app(config)                    # không chốt baseline
        with TestClient(app) as c:
            res = c.post("/api/scan")
            assert res.status_code == 400
            assert "baseline" in res.json()["detail"]
