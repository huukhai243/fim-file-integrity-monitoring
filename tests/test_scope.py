"""Test phần Người 3: phạm vi giám sát và whitelist."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
import yaml

from fim.config import ScopeConfig
from fim.models import ChangeEvent, ChangeType, FileRecord, WhitelistEntry
from fim.scope.profiles import PROFILES, detect_profile, get_profile
from fim.scope.scope import Scope, WalkStats
from fim.scope.whitelist import (
    Whitelist,
    WhitelistError,
    entry_from_dict,
    export_to_yaml,
    load_yaml,
    sync_yaml_to_store,
)
from fim.store import Store


class TestProfiles:
    def test_ba_ho_so_dung_san(self):
        assert set(PROFILES) == {"linux-system", "windows-system", "custom"}

    def test_auto_tra_ve_ho_so_ton_tai(self):
        assert get_profile("auto").name in PROFILES

    def test_detect_khop_he_dieu_hanh(self):
        import os

        expected = "windows-system" if os.name == "nt" else None
        if expected:
            assert detect_profile() == expected

    def test_ho_so_la_bao_loi_ro_rang(self):
        with pytest.raises(ValueError, match="Hồ sơ không tồn tại"):
            get_profile("solaris")

    def test_linux_liet_ke_duong_dan_trong_yeu_quan_trong(self):
        critical = get_profile("linux-system").critical
        for must in ("/etc/shadow", "/etc/sudoers", "/etc/ld.so.preload"):
            assert any(must in p for p in critical), f"thiếu {must}"

    def test_windows_liet_ke_hosts_va_startup(self):
        critical = " ".join(get_profile("windows-system").critical)
        assert "hosts" in critical
        assert "StartUp" in critical


class TestScope:
    def test_walk_tim_het_file(self, scope: Scope):
        assert len(list(scope.walk())) == 4

    def test_loai_tru_cat_bot_file(self, tmp_tree: Path):
        posix = str(tmp_tree).replace("\\", "/")
        s = Scope(ScopeConfig(profile="custom", include=[posix],
                              exclude=[f"{posix}/var/**"]))
        names = {p.rsplit("/", 1)[-1] for p in s.walk()}
        assert "app.log" not in names
        assert "passwd" in names

    def test_loai_tru_theo_phan_mo_rong(self, tmp_tree: Path):
        posix = str(tmp_tree).replace("\\", "/")
        s = Scope(ScopeConfig(profile="custom", include=[posix], exclude=["**/*.log"]))
        assert not any(p.endswith(".log") for p in s.walk())

    def test_is_critical_tra_ve_mau_da_khop(self, scope: Scope, posix_root: str):
        pattern = scope.is_critical(f"{posix_root}/etc/passwd")
        assert pattern is not None and "passwd" in pattern
        assert scope.is_critical(f"{posix_root}/etc/app.conf") is None

    def test_goc_khong_ton_tai_duoc_ghi_nhan_rieng(self, tmp_tree: Path):
        posix = str(tmp_tree).replace("\\", "/")
        s = Scope(ScopeConfig(profile="custom", include=[posix, "/khong/ton/tai"]))
        assert len(s.roots) == 1
        assert len(s.missing_roots) == 1

    def test_thong_ke_duyet(self, tmp_tree: Path):
        posix = str(tmp_tree).replace("\\", "/")
        s = Scope(ScopeConfig(profile="custom", include=[posix],
                              exclude=[f"{posix}/var/**"]))
        stats = WalkStats()
        list(s.walk(stats))
        assert stats.files == 3
        assert stats.skipped_excluded >= 1

    def test_max_depth_cat_duoi_sau(self, tmp_path: Path):
        deep = tmp_path / "a/b/c/d/e"
        deep.mkdir(parents=True)
        (deep / "sau.txt").write_text("x", encoding="utf-8")
        (tmp_path / "nong.txt").write_text("x", encoding="utf-8")

        posix = str(tmp_path).replace("\\", "/")
        s = Scope(ScopeConfig(profile="custom", include=[posix], max_depth=2))
        names = {p.rsplit("/", 1)[-1] for p in s.walk()}
        assert "nong.txt" in names
        assert "sau.txt" not in names

    def test_in_scope(self, scope: Scope, posix_root: str):
        assert scope.in_scope(f"{posix_root}/etc/passwd")
        assert not scope.in_scope("/hoan/toan/khac")

    def test_goc_long_nhau_khong_tra_ve_trung(self, tmp_tree: Path):
        posix = str(tmp_tree).replace("\\", "/")
        s = Scope(ScopeConfig(profile="custom", include=[posix, f"{posix}/etc"]))
        paths = list(s.walk())
        assert len(paths) == len(set(paths))

    def test_summary_du_thong_tin_luu_kem_baseline(self, scope: Scope):
        summary = scope.summary()
        for key in ("profile", "include", "exclude", "critical", "roots_present"):
            assert key in summary


class TestWhitelistEntry:
    def test_thieu_reason_bi_tu_choi(self):
        # Whitelist không giải thích được sẽ bị sao chép mù sang hệ thống khác.
        with pytest.raises(WhitelistError, match="reason"):
            entry_from_dict({"id": "w1", "match": {"path_glob": "/x/**"}})

    def test_thieu_ca_path_va_digest_bi_tu_choi(self):
        with pytest.raises(WhitelistError, match="path_glob hoặc digest"):
            entry_from_dict({"id": "w1", "reason": "co ly do"})

    def test_tu_sinh_id_khi_khong_khai_bao(self):
        entry = entry_from_dict({"match": {"path_glob": "/x/**"}, "reason": "ly do"})
        assert entry.id.startswith("wl-")

    def test_chap_nhan_dang_phang(self):
        entry = entry_from_dict({"id": "w1", "path_glob": "/x/**", "reason": "ly do"})
        assert entry.path_glob == "/x/**"

    def test_alias_sha256_va_hash(self):
        assert entry_from_dict({"match": {"sha256": "ABC"}, "reason": "r"}).digest == "abc"
        assert entry_from_dict({"match": {"hash": "DEF"}, "reason": "r"}).digest == "def"

    def test_het_han_tuong_doi(self):
        entry = entry_from_dict({"match": {"path_glob": "/x"}, "reason": "r",
                                 "expires_at": "+1h"})
        assert 3500 < entry.expires_at - time.time() < 3700

    def test_het_han_dang_iso(self):
        entry = entry_from_dict({"match": {"path_glob": "/x"}, "reason": "r",
                                 "expires_at": "2030-01-01T00:00:00"})
        assert entry.expires_at > time.time()

    def test_is_active(self):
        assert WhitelistEntry(id="w", path_glob="/x", reason="r").is_active()
        assert not WhitelistEntry(id="w", path_glob="/x", reason="r",
                                  enabled=False).is_active()
        assert not WhitelistEntry(id="w", path_glob="/x", reason="r",
                                  expires_at=time.time() - 1).is_active()


class TestWhitelistMatching:
    @staticmethod
    def _event(path: str, change=ChangeType.MODIFIED, digest="abc") -> ChangeEvent:
        return ChangeEvent(path=path, change=change,
                           after=FileRecord(path=path, digest=digest))

    def test_khop_theo_glob(self):
        wl = Whitelist(entries=[WhitelistEntry(id="w", path_glob="/var/log/**", reason="r")])
        assert wl.match(self._event("/var/log/app.log")) is not None
        assert wl.match(self._event("/etc/passwd")) is None

    def test_khop_theo_digest(self):
        wl = Whitelist(entries=[WhitelistEntry(id="w", digest="abc", reason="r")])
        assert wl.match(self._event("/bat/ky", digest="abc")) is not None
        assert wl.match(self._event("/bat/ky", digest="xyz")) is None

    def test_cac_tieu_chi_la_and(self):
        wl = Whitelist(entries=[
            WhitelistEntry(id="w", path_glob="/var/**", digest="abc", reason="r")
        ])
        assert wl.match(self._event("/var/x", digest="abc")) is not None
        assert wl.match(self._event("/var/x", digest="xyz")) is None   # sai digest
        assert wl.match(self._event("/etc/x", digest="abc")) is None   # sai đường dẫn

    def test_muc_co_rule_id_chi_khop_dung_luat_do(self):
        wl = Whitelist(entries=[
            WhitelistEntry(id="w", path_glob="/etc/**", rule_id="H001", reason="r")
        ])
        assert wl.match(self._event("/etc/x"), rule_id="H001") is not None
        assert wl.match(self._event("/etc/x"), rule_id="H020") is None
        assert wl.match(self._event("/etc/x")) is None     # không nêu luật thì không khớp

    def test_muc_khong_co_rule_id_phu_moi_luat(self):
        wl = Whitelist(entries=[WhitelistEntry(id="w", path_glob="/etc/**", reason="r")])
        assert wl.match(self._event("/etc/x"), rule_id="H001") is not None
        assert wl.match(self._event("/etc/x")) is not None

    def test_loc_theo_loai_thay_doi(self):
        wl = Whitelist(entries=[
            WhitelistEntry(id="w", path_glob="/etc/**",
                           change=ChangeType.CREATED, reason="r")
        ])
        assert wl.match(self._event("/etc/x", ChangeType.CREATED)) is not None
        assert wl.match(self._event("/etc/x", ChangeType.DELETED)) is None

    def test_dem_luot_dung(self):
        entry = WhitelistEntry(id="w", path_glob="/etc/**", reason="r")
        wl = Whitelist(entries=[entry])
        wl.match(self._event("/etc/a"))
        wl.match(self._event("/etc/b"))
        assert entry.hit_count == 2


class TestWhitelistYaml:
    def test_nap_file_mau_cua_project(self):
        path = Path(__file__).resolve().parents[1] / "configs" / "whitelist.yaml"
        entries = load_yaml(path)
        assert len(entries) >= 5
        # Mọi mục trong file mẫu phải có lý do — đây là quy tắc của project.
        assert all(e.reason for e in entries)

    def test_file_khong_ton_tai_tra_ve_rong(self, tmp_path: Path):
        assert load_yaml(tmp_path / "khong-co.yaml") == []

    def test_muc_sai_bao_loi_kem_so_dong(self, tmp_path: Path):
        f = tmp_path / "wl.yaml"
        f.write_text(
            yaml.safe_dump({"entries": [{"id": "w1", "path_glob": "/x"}]}),
            encoding="utf-8",
        )
        with pytest.raises(WhitelistError, match=r"entries\[0\]"):
            load_yaml(f)

    def test_dang_viet_tat_chi_mot_danh_sach(self, tmp_path: Path):
        f = tmp_path / "wl.yaml"
        f.write_text(
            yaml.safe_dump([{"id": "w1", "path_glob": "/x/**", "reason": "r"}]),
            encoding="utf-8",
        )
        assert len(load_yaml(f)) == 1

    def test_dong_bo_vao_csdl(self, tmp_path: Path, store: Store):
        f = tmp_path / "wl.yaml"
        f.write_text(
            yaml.safe_dump({"entries": [
                {"id": "w1", "path_glob": "/a/**", "reason": "r1"},
                {"id": "w2", "path_glob": "/b/**", "reason": "r2"},
            ]}),
            encoding="utf-8",
        )
        assert sync_yaml_to_store(f, store) == 2
        assert {e.id for e in store.list_whitelist()} == {"w1", "w2"}

    def test_dong_bo_lai_khong_tao_ban_trung(self, tmp_path: Path, store: Store):
        f = tmp_path / "wl.yaml"
        f.write_text(
            yaml.safe_dump({"entries": [{"id": "w1", "path_glob": "/a/**", "reason": "r"}]}),
            encoding="utf-8",
        )
        sync_yaml_to_store(f, store)
        sync_yaml_to_store(f, store)
        assert len(store.list_whitelist()) == 1

    def test_xuat_ra_yaml_doc_lai_duoc(self, tmp_path: Path, store: Store):
        store.upsert_whitelist(
            WhitelistEntry(id="w1", path_glob="/a/**", reason="ly do", rule_id="H001")
        )
        out = tmp_path / "export.yaml"
        assert export_to_yaml(store, out) == 1

        reloaded = load_yaml(out)
        assert reloaded[0].id == "w1"
        assert reloaded[0].rule_id == "H001"


class TestWhitelistStore:
    def test_them_va_xoa(self, store: Store):
        wl = Whitelist(store)
        wl.add(WhitelistEntry(id="w1", path_glob="/a/**", reason="r"))
        assert len(wl) == 1
        assert wl.remove("w1")
        assert len(wl) == 0

    def test_reload_lay_lai_tu_csdl(self, store: Store):
        wl = Whitelist(store)
        store.upsert_whitelist(WhitelistEntry(id="w1", path_glob="/a/**", reason="r"))
        assert wl.reload() == 1

    def test_reload_bo_qua_muc_het_han(self, store: Store):
        store.upsert_whitelist(
            WhitelistEntry(id="cu", path_glob="/a/**", reason="r",
                           expires_at=time.time() - 10)
        )
        store.upsert_whitelist(WhitelistEntry(id="moi", path_glob="/b/**", reason="r"))
        wl = Whitelist(store)
        assert len(wl) == 1 and wl.entries[0].id == "moi"
