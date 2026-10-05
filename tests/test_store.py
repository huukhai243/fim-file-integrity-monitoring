"""Test tầng lưu trữ — kho dữ liệu chung của cả ba module."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from fim.models import (
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
from fim.store import Store


@pytest.fixture
def baseline(store: Store) -> int:
    bid = store.create_baseline("b1", "blake2b", {"profile": "custom"})
    store.add_files(bid, [
        FileRecord(path="/etc/passwd", size=100, mtime=1.0, digest="a", mode=0o100644),
        FileRecord(path="/etc/hosts", size=50, mtime=2.0, digest="b", mode=0o100644),
    ])
    store.finalize_baseline(bid)
    return bid


class TestBaselineStorage:
    def test_tao_va_doc_lai(self, store: Store, baseline: int):
        data = store.get_baseline(baseline)
        assert data["label"] == "b1"
        assert data["file_count"] == 2
        assert data["total_bytes"] == 150
        assert data["scope"]["profile"] == "custom"

    def test_baseline_moi_nhat_la_active(self, store: Store):
        first = store.create_baseline("b1", "blake2b", {})
        second = store.create_baseline("b2", "blake2b", {})
        store.archive_baselines(keep_id=second)
        assert store.active_baseline_id() == second
        assert store.get_baseline(first)["status"] == "archived"

    def test_ghi_lai_cung_duong_dan_thi_thay_the(self, store: Store, baseline: int):
        store.add_files(baseline, [FileRecord(path="/etc/passwd", size=999, digest="moi")])
        assert store.get_file(baseline, "/etc/passwd").digest == "moi"
        assert len(store.file_paths(baseline)) == 2      # không sinh thêm dòng

    def test_chuan_hoa_duong_dan_khi_ghi(self, store: Store, baseline: int):
        store.add_files(baseline, [FileRecord(path=r"C:\Windows\x", digest="w")])
        assert store.get_file(baseline, "c:/Windows/x") is not None
        assert store.get_file(baseline, r"C:\Windows\x") is not None

    def test_xoa_file(self, store: Store, baseline: int):
        store.delete_file(baseline, "/etc/hosts")
        assert store.get_file(baseline, "/etc/hosts") is None

    def test_iter_files_theo_thu_tu_duong_dan(self, store: Store, baseline: int):
        paths = [r.path for r in store.iter_files(baseline)]
        assert paths == sorted(paths)

    def test_xoa_baseline_keo_theo_file(self, store: Store, baseline: int):
        store.conn.execute("DELETE FROM baselines WHERE id = ?", (baseline,))
        store.conn.commit()
        assert store.file_paths(baseline) == set()


class TestEventStorage:
    def test_luu_va_doc_lai_su_kien(self, store: Store):
        before = FileRecord(path="/etc/x", digest="a", size=10, mode=0o100644)
        after = FileRecord(path="/etc/x", digest="b", size=20, mode=0o100644)
        e = ChangeEvent(path="/etc/x", change=ChangeType.MODIFIED,
                        before=before, after=after)
        event_id = store.add_event(e)

        loaded = store.get_event(event_id)
        assert loaded.change == ChangeType.MODIFIED
        assert loaded.before.digest == "a"
        assert loaded.after.size == 20

    def test_add_event_gan_id_vao_doi_tuong(self, store: Store):
        e = ChangeEvent(path="/x", change=ChangeType.CREATED)
        assert store.add_event(e) == e.id

    def test_loc_theo_muc_nghiem_trong(self, store: Store):
        for i, severity in enumerate([Severity.LOW, Severity.HIGH, Severity.HIGH]):
            e = ChangeEvent(path=f"/x{i}", change=ChangeType.MODIFIED)
            store.add_event(e)
            store.add_verdict(Verdict(Classification.SUSPICIOUS, severity, 50,
                                      event_id=e.id))
        assert len(store.query_events(severity="high")) == 2
        assert store.count_events(severity="high") == 2

    def test_loc_theo_duong_dan(self, store: Store):
        for path in ("/etc/a", "/etc/b", "/var/c"):
            store.add_event(ChangeEvent(path=path, change=ChangeType.MODIFIED))
        assert len(store.query_events(path_like="/etc/")) == 2

    def test_loc_theo_thoi_gian(self, store: Store):
        now = time.time()
        store.add_event(ChangeEvent(path="/cu", change=ChangeType.MODIFIED,
                                    ts=now - 7200))
        store.add_event(ChangeEvent(path="/moi", change=ChangeType.MODIFIED, ts=now))
        recent = store.query_events(since=now - 3600)
        assert len(recent) == 1 and recent[0]["path"] == "/moi"

    def test_loai_bo_muc_da_whitelist(self, store: Store):
        for i, whitelisted in enumerate([True, False]):
            e = ChangeEvent(path=f"/x{i}", change=ChangeType.MODIFIED)
            store.add_event(e)
            store.add_verdict(Verdict(Classification.BENIGN, Severity.INFO, 0,
                                      whitelisted=whitelisted, event_id=e.id))
        assert len(store.query_events(include_whitelisted=False)) == 1
        assert len(store.query_events(include_whitelisted=True)) == 2

    def test_phan_trang(self, store: Store):
        for i in range(10):
            store.add_event(ChangeEvent(path=f"/x{i}", change=ChangeType.MODIFIED))
        page1 = store.query_events(limit=4, offset=0)
        page2 = store.query_events(limit=4, offset=4)
        assert len(page1) == len(page2) == 4
        assert {e["id"] for e in page1}.isdisjoint({e["id"] for e in page2})

    def test_su_kien_moi_nhat_len_dau(self, store: Store):
        now = time.time()
        store.add_event(ChangeEvent(path="/cu", change=ChangeType.MODIFIED, ts=now - 100))
        store.add_event(ChangeEvent(path="/moi", change=ChangeType.MODIFIED, ts=now))
        assert store.query_events()[0]["path"] == "/moi"

    def test_su_kien_chua_phan_loai_van_truy_van_duoc(self, store: Store):
        store.add_event(ChangeEvent(path="/x", change=ChangeType.MODIFIED))
        assert store.query_events()[0]["verdict"] is None


class TestVerdictStorage:
    def test_luu_va_doc_lai_kem_cac_luat(self, store: Store):
        e = ChangeEvent(path="/etc/x", change=ChangeType.MODIFIED)
        store.add_event(e)
        store.add_verdict(Verdict(
            Classification.MALICIOUS, Severity.CRITICAL, 95,
            hits=[RuleHit("H020", "Timestomp", 55, "mtime không đổi"),
                  RuleHit("H001", "File trọng yếu", 40, "")],
            event_id=e.id,
        ))
        loaded = store.get_verdict(e.id)
        assert loaded.score == 95
        assert len(loaded.hits) == 2
        assert loaded.hits[0].rule_id == "H020"

    def test_khong_co_event_id_thi_bao_loi(self, store: Store):
        with pytest.raises(ValueError, match="event_id"):
            store.add_verdict(Verdict(Classification.BENIGN, Severity.INFO, 0))

    def test_luu_lai_thi_thay_the(self, store: Store):
        e = ChangeEvent(path="/x", change=ChangeType.MODIFIED)
        store.add_event(e)
        store.add_verdict(Verdict(Classification.BENIGN, Severity.LOW, 10, event_id=e.id))
        store.add_verdict(Verdict(Classification.SUSPICIOUS, Severity.HIGH, 70,
                                  event_id=e.id))
        assert store.get_verdict(e.id).score == 70

    def test_xoa_su_kien_keo_theo_verdict(self, store: Store):
        e = ChangeEvent(path="/x", change=ChangeType.MODIFIED)
        store.add_event(e)
        store.add_verdict(Verdict(Classification.BENIGN, Severity.INFO, 0, event_id=e.id))
        store.conn.execute("DELETE FROM events WHERE id = ?", (e.id,))
        store.conn.commit()
        assert store.get_verdict(e.id) is None


class TestAlertStorage:
    def test_luu_va_loc_theo_trang_thai(self, store: Store):
        e = ChangeEvent(path="/x", change=ChangeType.MODIFIED)
        store.add_event(e)
        alert_id = store.add_alert(Alert(event_id=e.id, severity=Severity.HIGH,
                                         title="t", summary="s", path="/x"))
        assert len(store.query_alerts(status="new")) == 1

        assert store.update_alert_status(alert_id, AlertStatus.ACK, "đang xem")
        assert store.query_alerts(status="new") == []
        acked = store.query_alerts(status="ack")
        assert len(acked) == 1 and acked[0]["note"] == "đang xem"

    def test_cap_nhat_id_khong_ton_tai(self, store: Store):
        assert not store.update_alert_status(999, AlertStatus.ACK)

    def test_note_none_khong_ghi_de_note_cu(self, store: Store):
        e = ChangeEvent(path="/x", change=ChangeType.MODIFIED)
        store.add_event(e)
        aid = store.add_alert(Alert(event_id=e.id, severity=Severity.HIGH,
                                    title="t", summary="s"))
        store.update_alert_status(aid, AlertStatus.ACK, "ghi chu goc")
        store.update_alert_status(aid, AlertStatus.RESOLVED, None)
        assert store.query_alerts(status="resolved")[0]["note"] == "ghi chu goc"


class TestWhitelistStorage:
    def test_upsert_cap_nhat_thay_vi_them_moi(self, store: Store):
        store.upsert_whitelist(WhitelistEntry(id="w1", path_glob="/a/**", reason="dau"))
        store.upsert_whitelist(WhitelistEntry(id="w1", path_glob="/b/**", reason="sau"))
        entries = store.list_whitelist()
        assert len(entries) == 1
        assert entries[0].path_glob == "/b/**" and entries[0].reason == "sau"

    def test_only_active_bo_qua_muc_tat_va_het_han(self, store: Store):
        store.upsert_whitelist(WhitelistEntry(id="on", path_glob="/a", reason="r"))
        store.upsert_whitelist(WhitelistEntry(id="off", path_glob="/b", reason="r",
                                             enabled=False))
        store.upsert_whitelist(WhitelistEntry(id="exp", path_glob="/c", reason="r",
                                             expires_at=time.time() - 1))
        assert {e.id for e in store.list_whitelist(only_active=True)} == {"on"}
        assert len(store.list_whitelist()) == 3

    def test_dem_luot_dung(self, store: Store):
        store.upsert_whitelist(WhitelistEntry(id="w1", path_glob="/a", reason="r"))
        store.bump_whitelist_hit("w1")
        store.bump_whitelist_hit("w1")
        assert store.list_whitelist()[0].hit_count == 2

    def test_upsert_khong_lam_mat_hit_count(self, store: Store):
        store.upsert_whitelist(WhitelistEntry(id="w1", path_glob="/a", reason="r"))
        store.bump_whitelist_hit("w1")
        store.upsert_whitelist(WhitelistEntry(id="w1", path_glob="/a", reason="sua"))
        assert store.list_whitelist()[0].hit_count == 1


class TestStats:
    def test_thong_ke_tong_hop(self, store: Store, baseline: int):
        for severity in (Severity.LOW, Severity.HIGH, Severity.HIGH):
            e = ChangeEvent(path="/x", change=ChangeType.MODIFIED)
            store.add_event(e)
            store.add_verdict(Verdict(Classification.SUSPICIOUS, severity, 50,
                                      event_id=e.id))
        stats = store.stats()
        assert stats["events_total"] == 3
        assert stats["by_severity"]["high"] == 2
        assert stats["by_change"]["modified"] == 3
        assert stats["baseline"]["file_count"] == 2

    def test_thong_ke_khi_csdl_trong(self, store: Store):
        stats = store.stats()
        assert stats["events_total"] == 0
        assert stats["baseline"] is None
        assert stats["last_scan"] is None

    def test_timeline_chia_du_o(self, store: Store):
        store.add_event(ChangeEvent(path="/x", change=ChangeType.MODIFIED))
        series = store.timeline(hours=24, buckets=12)
        assert len(series) == 12
        assert sum(b["total"] for b in series) == 1
        assert all({"start", "end", "total"} <= set(b) for b in series)

    def test_top_paths_sap_theo_so_lan(self, store: Store):
        for _ in range(3):
            store.add_event(ChangeEvent(path="/hay/doi", change=ChangeType.MODIFIED))
        store.add_event(ChangeEvent(path="/it/doi", change=ChangeType.MODIFIED))
        top = store.top_paths(limit=5)
        assert top[0]["path"] == "/hay/doi" and top[0]["n"] == 3

    def test_lan_quet_duoc_ghi_nhan(self, store: Store):
        scan_id = store.start_scan("polling", None)
        store.finish_scan(scan_id, 100, 5, "ok")
        scan = store.recent_scans(1)[0]
        assert scan["files_scanned"] == 100
        assert scan["changes_found"] == 5
        assert scan["status"] == "ok"

    def test_don_su_kien_qua_han(self, store: Store):
        old = time.time() - 100 * 86400
        store.add_event(ChangeEvent(path="/cu", change=ChangeType.MODIFIED, ts=old))
        store.add_event(ChangeEvent(path="/moi", change=ChangeType.MODIFIED))
        assert store.purge_old_events(90) == 1
        assert store.count_events() == 1

    def test_retention_bang_khong_thi_giu_het(self, store: Store):
        store.add_event(ChangeEvent(path="/x", change=ChangeType.MODIFIED,
                                    ts=time.time() - 1000 * 86400))
        assert store.purge_old_events(0) == 0
        assert store.count_events() == 1


class TestConcurrency:
    def test_ghi_tu_nhieu_luong(self, tmp_path: Path):
        """Bộ theo dõi realtime ghi từ luồng riêng trong khi dashboard đọc."""
        store = Store(tmp_path / "concurrent.db")
        errors: list[Exception] = []

        def writer(offset: int) -> None:
            try:
                for i in range(20):
                    store.add_event(
                        ChangeEvent(path=f"/t{offset}/f{i}", change=ChangeType.MODIFIED)
                    )
            except Exception as exc:                     # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert store.count_events() == 80
        store.close()
