"""Test phần Người 2: bộ luật heuristic, phân loại, cảnh báo.

Đây là bộ test quan trọng nhất của project: nếu bộ phân loại sai, FIM hoặc ngập
báo động giả (người vận hành sẽ tắt nó) hoặc bỏ lọt tấn công thật.
"""

from __future__ import annotations

import stat
import time
from pathlib import Path

import pytest

from fim.analysis.alerting import AlertManager, JsonlSink
from fim.analysis.classifier import Classifier
from fim.analysis.heuristics import RuleContext, all_rules, evaluate
from fim.config import AlertConfig, AnalysisConfig
from fim.models import (
    ChangeEvent,
    ChangeType,
    Classification,
    FileRecord,
    Severity,
    Verdict,
    WhitelistEntry,
)
from fim.scope.whitelist import Whitelist


# ---------------------------------------------------------------------------
# Trợ giúp
# ---------------------------------------------------------------------------


def ctx(critical: list[str] | None = None, **overrides) -> RuleContext:
    """RuleContext với khung giờ 0–24 để luật H024 không gây dao động theo giờ chạy."""
    config = AnalysisConfig(business_hours=[0, 24], **overrides)
    patterns = critical or []
    from fim.util import any_glob_match

    return RuleContext(
        config=config,
        is_critical=lambda p: any_glob_match(p, patterns),
    )


def event(
    path: str,
    change: ChangeType = ChangeType.MODIFIED,
    before: FileRecord | None = None,
    after: FileRecord | None = None,
) -> ChangeEvent:
    return ChangeEvent(path=path, change=change, before=before, after=after)


def rule_ids(hits) -> set[str]:
    return {h.rule_id for h in hits}


# ---------------------------------------------------------------------------
# Từng luật
# ---------------------------------------------------------------------------


class TestPathRules:
    def test_h001_file_trong_yeu(self):
        e = event("/etc/passwd",
                  before=FileRecord(path="/etc/passwd", digest="a"),
                  after=FileRecord(path="/etc/passwd", digest="b"))
        assert "H001" in rule_ids(evaluate(e, ctx(["/etc/passwd"])))

    def test_h001_khong_no_khi_khong_trong_yeu(self):
        e = event("/tmp/scratch",
                  before=FileRecord(path="/tmp/scratch", digest="a"),
                  after=FileRecord(path="/tmp/scratch", digest="b"))
        assert "H001" not in rule_ids(evaluate(e, ctx(["/etc/passwd"])))

    def test_h002_thu_muc_nhi_phan(self):
        e = event("/usr/bin/ssh",
                  before=FileRecord(path="/usr/bin/ssh", digest="a"),
                  after=FileRecord(path="/usr/bin/ssh", digest="b"))
        assert "H002" in rule_ids(evaluate(e, ctx()))

    @pytest.mark.parametrize("path", [
        "/etc/cron.d/backup",
        "/etc/systemd/system/evil.service",
        "/root/.ssh/authorized_keys",
        "/etc/ld.so.preload",
        "/home/u/.bashrc",
    ])
    def test_h003_co_che_persistence(self, path):
        e = event(path, ChangeType.CREATED, after=FileRecord(path=path, digest="a"))
        assert "H003" in rule_ids(evaluate(e, ctx()))

    def test_h004_file_thuc_thi_trong_tmp(self):
        after = FileRecord(path="/tmp/payload.sh", mode=0o100755, digest="a")
        e = event("/tmp/payload.sh", ChangeType.CREATED, after=after)
        assert "H004" in rule_ids(evaluate(e, ctx()))

    def test_h004_khong_no_voi_file_thuong_trong_tmp(self):
        after = FileRecord(path="/tmp/note.txt", mode=0o100644, digest="a")
        e = event("/tmp/note.txt", ChangeType.CREATED, after=after)
        assert "H004" not in rule_ids(evaluate(e, ctx()))


class TestPermissionRules:
    def test_h010_setuid_moi_duoc_gan(self):
        before = FileRecord(path="/usr/bin/x", mode=0o100755, digest="a")
        after = FileRecord(path="/usr/bin/x", mode=0o104755, digest="a")  # +setuid
        hits = evaluate(event("/usr/bin/x", ChangeType.ATTR_CHANGED, before, after), ctx())
        assert "H010" in rule_ids(hits)

    def test_h010_khong_no_khi_setuid_von_da_co(self):
        # File setuid sẵn từ đầu không phải thay đổi — báo lại sẽ thành nhiễu.
        before = FileRecord(path="/usr/bin/sudo", mode=0o104755, digest="a")
        after = FileRecord(path="/usr/bin/sudo", mode=0o104755, digest="b")
        hits = evaluate(event("/usr/bin/sudo", ChangeType.MODIFIED, before, after), ctx())
        assert "H010" not in rule_ids(hits)

    def test_h011_tro_nen_ai_cung_ghi_duoc(self):
        before = FileRecord(path="/etc/x", mode=0o100644, digest="a")
        after = FileRecord(path="/etc/x", mode=0o100646, digest="a")      # +o+w
        hits = evaluate(event("/etc/x", ChangeType.ATTR_CHANGED, before, after), ctx())
        assert "H011" in rule_ids(hits)

    def test_h012_doi_chu_so_huu(self):
        before = FileRecord(path="/etc/x", uid=0, gid=0, digest="a")
        after = FileRecord(path="/etc/x", uid=1000, gid=1000, digest="a")
        hits = evaluate(event("/etc/x", ChangeType.ATTR_CHANGED, before, after), ctx())
        assert "H012" in rule_ids(hits)

    def test_h013_file_thuong_thanh_symlink(self):
        before = FileRecord(path="/etc/x", is_symlink=False, digest="a")
        after = FileRecord(path="/etc/x", is_symlink=True, link_target="/tmp/evil", digest="b")
        hits = evaluate(event("/etc/x", ChangeType.MODIFIED, before, after), ctx())
        assert "H013" in rule_ids(hits)


class TestAntiForensicsRules:
    def test_h020_timestomp_giu_nguyen_mtime(self):
        # Dấu hiệu mạnh nhất trong cả bộ luật: nội dung đổi mà mtime không đổi.
        before = FileRecord(path="/usr/bin/x", digest="aaa", mtime=1000.0)
        after = FileRecord(path="/usr/bin/x", digest="bbb", mtime=1000.0)
        hits = evaluate(event("/usr/bin/x", ChangeType.MODIFIED, before, after), ctx())
        hit = next(h for h in hits if h.rule_id == "H020")
        assert hit.weight == 55

    def test_h020_mtime_lui_ve_qua_khu(self):
        before = FileRecord(path="/etc/x", digest="aaa", mtime=2000.0)
        after = FileRecord(path="/etc/x", digest="bbb", mtime=1000.0)
        hits = evaluate(event("/etc/x", ChangeType.MODIFIED, before, after), ctx())
        hit = next(h for h in hits if h.rule_id == "H020")
        assert hit.weight == 45          # nhẹ hơn trường hợp giữ y nguyên mtime

    def test_h020_khong_no_khi_mtime_tien_binh_thuong(self):
        before = FileRecord(path="/etc/x", digest="aaa", mtime=1000.0)
        after = FileRecord(path="/etc/x", digest="bbb", mtime=2000.0)
        hits = evaluate(event("/etc/x", ChangeType.MODIFIED, before, after), ctx())
        assert "H020" not in rule_ids(hits)

    def test_h020_khong_ket_luan_khi_thieu_digest(self):
        before = FileRecord(path="/etc/x", digest=None, mtime=1000.0)
        after = FileRecord(path="/etc/x", digest=None, mtime=1000.0)
        hits = evaluate(event("/etc/x", ChangeType.MODIFIED, before, after), ctx())
        assert "H020" not in rule_ids(hits)

    def test_h021_mtime_o_tuong_lai(self):
        after = FileRecord(path="/etc/x", digest="a", mtime=time.time() + 86400)
        hits = evaluate(event("/etc/x", ChangeType.CREATED, after=after), ctx())
        assert "H021" in rule_ids(hits)

    def test_h022_xoa_file_trong_yeu(self):
        before = FileRecord(path="/etc/passwd", digest="a")
        hits = evaluate(
            event("/etc/passwd", ChangeType.DELETED, before=before), ctx(["/etc/passwd"])
        )
        assert "H022" in rule_ids(hits)

    def test_h023_thay_doi_hang_loat(self):
        c = ctx(burst_threshold=5)
        c.burst_count = 10
        after = FileRecord(path="/etc/x", digest="a")
        assert "H023" in rule_ids(evaluate(event("/etc/x", after=after), c))

    def test_h023_duoi_nguong_thi_im(self):
        c = ctx(burst_threshold=25)
        c.burst_count = 3
        after = FileRecord(path="/etc/x", digest="a")
        assert "H023" not in rule_ids(evaluate(event("/etc/x", after=after), c))

    def test_h024_ngoai_gio_lam_viec(self):
        from fim.util import any_glob_match

        c = RuleContext(
            config=AnalysisConfig(business_hours=[8, 18]),
            is_critical=lambda p: any_glob_match(p, []),
        )
        # 3 giờ sáng hôm nay, chắc chắn ngoài khung 8–18.
        night = time.localtime()
        ts = time.mktime((night.tm_year, night.tm_mon, night.tm_mday, 3, 0, 0, 0, 0, -1))
        e = ChangeEvent(path="/etc/x", change=ChangeType.MODIFIED, ts=ts,
                        after=FileRecord(path="/etc/x", digest="a"))
        assert "H024" in rule_ids(evaluate(e, c))


class TestContentRules:
    def test_h030_noi_dung_khong_khop_phan_mo_rong(self, tmp_path: Path):
        f = tmp_path / "readme.txt"
        f.write_bytes(b"\x7fELF\x02\x01" + b"\x00" * 100)   # ELF mang mặt nạ .txt
        after = FileRecord(path=str(f).replace("\\", "/"), size=106, digest="a")
        e = event(after.path, ChangeType.CREATED, after=after)
        assert "H030" in rule_ids(evaluate(e, ctx()))

    def test_h030_van_ban_that_khong_no(self, tmp_path: Path):
        f = tmp_path / "readme.txt"
        f.write_text("chi la van ban binh thuong\n", encoding="utf-8")
        after = FileRecord(path=str(f).replace("\\", "/"), size=30, digest="a")
        e = event(after.path, ChangeType.CREATED, after=after)
        assert "H030" not in rule_ids(evaluate(e, ctx()))

    def test_h032_file_bi_cat_ve_khong(self):
        before = FileRecord(path="/etc/x", size=5000, digest="a")
        after = FileRecord(path="/etc/x", size=0, digest="b")
        hits = evaluate(event("/etc/x", ChangeType.MODIFIED, before, after), ctx())
        assert "H032" in rule_ids(hits)

    def test_h032_phinh_gap_nhieu_lan(self):
        before = FileRecord(path="/etc/x", size=100, digest="a")
        after = FileRecord(path="/etc/x", size=50000, digest="b")
        hits = evaluate(event("/etc/x", ChangeType.MODIFIED, before, after), ctx())
        assert "H032" in rule_ids(hits)

    def test_h032_thay_doi_nho_khong_no(self):
        before = FileRecord(path="/etc/x", size=1000, digest="a")
        after = FileRecord(path="/etc/x", size=1100, digest="b")
        hits = evaluate(event("/etc/x", ChangeType.MODIFIED, before, after), ctx())
        assert "H032" not in rule_ids(hits)

    def test_h033_file_thuc_thi_moi(self):
        after = FileRecord(path="/opt/app/run", mode=0o100755, digest="a")
        hits = evaluate(event("/opt/app/run", ChangeType.CREATED, after=after), ctx())
        assert "H033" in rule_ids(hits)


class TestBenignEvidenceRules:
    def test_h090_hash_da_duyet_tru_diem_manh(self):
        after = FileRecord(path="/usr/bin/x", digest="deadbeef")
        c = ctx(known_good_hashes=["DEADBEEF"])        # so sánh không phân biệt hoa thường
        hits = evaluate(event("/usr/bin/x", ChangeType.MODIFIED, after=after), c)
        hit = next(h for h in hits if h.rule_id == "H090")
        assert hit.weight == -60

    def test_h091_duong_dan_hay_bien_dong(self):
        after = FileRecord(path="/var/log/app.log", digest="a")
        hits = evaluate(event("/var/log/app.log", ChangeType.MODIFIED, after=after), ctx())
        hit = next(h for h in hits if h.rule_id == "H091")
        assert hit.weight < 0

    def test_h092_chi_doi_metadata(self):
        before = FileRecord(path="/etc/x", digest="a", mode=0o100644)
        after = FileRecord(path="/etc/x", digest="a", mode=0o100640)
        hits = evaluate(event("/etc/x", ChangeType.ATTR_CHANGED, before, after), ctx())
        assert "H092" in rule_ids(hits)


class TestRuleRegistry:
    def test_moi_luat_co_id_duy_nhat(self):
        ids = [r.rule_id for r in all_rules()]
        assert len(ids) == len(set(ids))

    def test_moi_luat_co_tieu_de_va_mo_ta(self):
        for rule in all_rules():
            assert rule.title, f"{rule.rule_id} thiếu tiêu đề"
            assert rule.description.strip(), f"{rule.rule_id} thiếu mô tả"

    def test_luat_h09x_co_trong_so_am(self):
        # Quy ước: nhóm H09x là bằng chứng hợp lệ, phải kéo điểm xuống.
        for rule in all_rules():
            if rule.rule_id.startswith("H09"):
                assert rule.weight < 0, f"{rule.rule_id} phải có trọng số âm"

    def test_luat_khac_co_trong_so_duong(self):
        for rule in all_rules():
            if not rule.rule_id.startswith("H09"):
                assert rule.weight > 0, f"{rule.rule_id} phải có trọng số dương"


# ---------------------------------------------------------------------------
# Bộ phân loại
# ---------------------------------------------------------------------------


class TestClassifier:
    def test_diem_anh_xa_dung_muc(self):
        c = Classifier(AnalysisConfig())
        assert c.severity_for(0) == Severity.INFO
        assert c.severity_for(10) == Severity.LOW
        assert c.severity_for(30) == Severity.MEDIUM
        assert c.severity_for(60) == Severity.HIGH
        assert c.severity_for(85) == Severity.CRITICAL
        assert c.severity_for(200) == Severity.CRITICAL

    def test_khong_luat_nao_khop_thi_benign(self):
        c = Classifier(AnalysisConfig(business_hours=[0, 24]))
        before = FileRecord(path="/opt/data/x.dat", digest="a", mtime=1.0)
        after = FileRecord(path="/opt/data/x.dat", digest="b", mtime=2.0)
        verdict = c.classify(event("/opt/data/x.dat", ChangeType.MODIFIED, before, after))
        assert verdict.classification == Classification.BENIGN
        assert verdict.score == 0

    def test_timestomp_tren_file_trong_yeu_thanh_critical(self):
        from fim.config import ScopeConfig
        from fim.scope.scope import Scope

        scope = Scope(ScopeConfig(profile="custom", critical=["/usr/bin/**"]))
        c = Classifier(AnalysisConfig(business_hours=[0, 24]), scope)
        before = FileRecord(path="/usr/bin/sshd", digest="aaa", mtime=1000.0)
        after = FileRecord(path="/usr/bin/sshd", digest="bbb", mtime=1000.0)
        verdict = c.classify(event("/usr/bin/sshd", ChangeType.MODIFIED, before, after))
        # H020 (55) + H001 (40) + H002 (35) = 130 -> critical
        assert verdict.severity == Severity.CRITICAL
        assert verdict.classification == Classification.MALICIOUS

    def test_diem_khong_bao_gio_am(self):
        # Trọng số âm không được đẩy điểm xuống dưới 0 — sẽ làm ngưỡng vô nghĩa.
        c = Classifier(AnalysisConfig(business_hours=[0, 24],
                                      known_good_hashes=["cafe"]))
        after = FileRecord(path="/var/log/x.log", digest="cafe")
        verdict = c.classify(event("/var/log/x.log", ChangeType.MODIFIED, after=after))
        assert verdict.score == 0

    def test_ghi_de_trong_so_qua_cau_hinh(self):
        c = Classifier(AnalysisConfig(business_hours=[0, 24], rule_weights={"H002": 5}))
        before = FileRecord(path="/usr/bin/x", digest="a", mtime=1.0)
        after = FileRecord(path="/usr/bin/x", digest="b", mtime=2.0)
        verdict = c.classify(event("/usr/bin/x", ChangeType.MODIFIED, before, after))
        assert next(h for h in verdict.hits if h.rule_id == "H002").weight == 5

    def test_tat_luat_qua_cau_hinh(self):
        c = Classifier(AnalysisConfig(business_hours=[0, 24], disabled_rules=["H002"]))
        before = FileRecord(path="/usr/bin/x", digest="a", mtime=1.0)
        after = FileRecord(path="/usr/bin/x", digest="b", mtime=2.0)
        verdict = c.classify(event("/usr/bin/x", ChangeType.MODIFIED, before, after))
        assert "H002" not in rule_ids(verdict.hits)

    def test_whitelist_toan_bo_file(self):
        wl = Whitelist(entries=[
            WhitelistEntry(id="w1", path_glob="/usr/bin/**", reason="test")
        ])
        c = Classifier(AnalysisConfig(business_hours=[0, 24]), whitelist=wl)
        before = FileRecord(path="/usr/bin/x", digest="aaa", mtime=1000.0)
        after = FileRecord(path="/usr/bin/x", digest="bbb", mtime=1000.0)
        verdict = c.classify(event("/usr/bin/x", ChangeType.MODIFIED, before, after))
        assert verdict.whitelisted
        assert verdict.classification == Classification.BENIGN
        assert verdict.severity == Severity.INFO

    def test_whitelist_chi_tat_mot_luat(self):
        """Đây là hành vi quan trọng nhất của whitelist: tắt hẹp, không tắt cả file."""
        wl = Whitelist(entries=[
            WhitelistEntry(id="w1", path_glob="/usr/bin/**", rule_id="H002",
                           reason="chỉ tắt luật thư mục nhị phân")
        ])
        c = Classifier(AnalysisConfig(business_hours=[0, 24]), whitelist=wl)
        before = FileRecord(path="/usr/bin/x", digest="aaa", mtime=1000.0)
        after = FileRecord(path="/usr/bin/x", digest="bbb", mtime=1000.0)
        verdict = c.classify(event("/usr/bin/x", ChangeType.MODIFIED, before, after))

        assert not verdict.whitelisted           # không miễn trừ toàn bộ
        assert "H002" not in rule_ids(verdict.hits)
        assert "H020" in rule_ids(verdict.hits)  # timestomp vẫn bị bắt
        assert verdict.severity.rank >= Severity.MEDIUM.rank

    def test_whitelist_het_han_khong_con_tac_dung(self):
        wl = Whitelist(entries=[
            WhitelistEntry(id="w1", path_glob="/usr/bin/**", reason="tạm",
                           expires_at=time.time() - 10)
        ])
        c = Classifier(AnalysisConfig(business_hours=[0, 24]), whitelist=wl)
        before = FileRecord(path="/usr/bin/x", digest="aaa", mtime=1000.0)
        after = FileRecord(path="/usr/bin/x", digest="bbb", mtime=1000.0)
        assert not c.classify(event("/usr/bin/x", ChangeType.MODIFIED, before, after)).whitelisted

    def test_cua_so_burst_truot_theo_thoi_gian(self):
        c = Classifier(AnalysisConfig(business_hours=[0, 24], burst_window="1s",
                                      burst_threshold=3))
        after = FileRecord(path="/etc/x", digest="a")
        for _ in range(5):
            c.classify(event("/etc/x", ChangeType.MODIFIED, after=after))
        assert len(c._recent) == 5

        time.sleep(1.1)                     # cửa sổ 1 giây đã trôi qua
        c.classify(event("/etc/x", ChangeType.MODIFIED, after=after))
        assert len(c._recent) == 1          # các mốc cũ bị loại khỏi cửa sổ

    def test_explain_tra_ve_van_ban_co_ich(self):
        c = Classifier(AnalysisConfig(business_hours=[0, 24]))
        before = FileRecord(path="/usr/bin/x", digest="aaa", mtime=1000.0)
        after = FileRecord(path="/usr/bin/x", digest="bbb", mtime=1000.0)
        text = c.explain(event("/usr/bin/x", ChangeType.MODIFIED, before, after))
        assert "H020" in text and "/usr/bin/x" in text


# ---------------------------------------------------------------------------
# Cảnh báo
# ---------------------------------------------------------------------------


class TestAlerting:
    def test_duoi_nguong_thi_khong_canh_bao(self):
        mgr = AlertManager(AlertConfig(min_severity="medium", console=False,
                                       jsonl_path=""), sinks=[])
        verdict = Verdict(Classification.BENIGN, Severity.LOW, 10, event_id=1)
        assert mgr.dispatch(ChangeEvent(path="/x", change=ChangeType.MODIFIED, id=1),
                            verdict) is None
        assert mgr.suppressed == 1

    def test_dat_nguong_thi_canh_bao(self):
        mgr = AlertManager(AlertConfig(min_severity="medium", console=False,
                                       jsonl_path=""), sinks=[])
        verdict = Verdict(Classification.SUSPICIOUS, Severity.HIGH, 70, event_id=1)
        alert = mgr.dispatch(ChangeEvent(path="/x", change=ChangeType.MODIFIED, id=1),
                             verdict)
        assert alert is not None and alert.severity == Severity.HIGH

    def test_whitelist_khong_bao_gio_canh_bao(self):
        mgr = AlertManager(AlertConfig(min_severity="info", console=False,
                                       jsonl_path=""), sinks=[])
        verdict = Verdict(Classification.BENIGN, Severity.CRITICAL, 100,
                          whitelisted=True, whitelist_id="w1", event_id=1)
        assert mgr.dispatch(ChangeEvent(path="/x", change=ChangeType.MODIFIED, id=1),
                            verdict) is None

    def test_jsonl_ghi_mot_dong_moi_canh_bao(self, tmp_path: Path):
        import json

        target = tmp_path / "alerts.jsonl"
        mgr = AlertManager(AlertConfig(min_severity="low", console=False, jsonl_path=""),
                           sinks=[JsonlSink(target)])
        for i in (1, 2):
            mgr.dispatch(
                ChangeEvent(path=f"/x{i}", change=ChangeType.MODIFIED, id=i),
                Verdict(Classification.SUSPICIOUS, Severity.HIGH, 70, event_id=i),
            )
        lines = target.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0])["event_id"] == 1

    def test_sink_hong_khong_lam_mat_canh_bao(self):
        class BrokenSink:
            name = "broken"

            def emit(self, alert, event, verdict):
                raise OSError("đích không truy cập được")

        mgr = AlertManager(AlertConfig(min_severity="low", console=False, jsonl_path=""),
                           sinks=[BrokenSink()])
        alert = mgr.dispatch(
            ChangeEvent(path="/x", change=ChangeType.MODIFIED, id=1),
            Verdict(Classification.SUSPICIOUS, Severity.HIGH, 70, event_id=1),
        )
        assert alert is not None            # vẫn tạo được cảnh báo
        assert mgr.errors and mgr.errors[0][0] == "broken"

    def test_summary_chua_thong_tin_can_de_xu_ly(self):
        mgr = AlertManager(AlertConfig(console=False, jsonl_path=""), sinks=[])
        before = FileRecord(path="/etc/x", digest="a" * 32, size=100, mode=0o100644)
        after = FileRecord(path="/etc/x", digest="b" * 32, size=200, mode=0o100777)
        e = ChangeEvent(path="/etc/x", change=ChangeType.MODIFIED,
                        before=before, after=after, id=1)
        verdict = Verdict(Classification.SUSPICIOUS, Severity.HIGH, 70, event_id=1)
        summary = mgr.build_alert(e, verdict).summary
        assert "0644" in summary and "0777" in summary        # quyền trước/sau
        assert "100" in summary and "200" in summary          # kích thước trước/sau
