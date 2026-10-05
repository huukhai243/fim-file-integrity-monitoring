"""Test chuẩn hoá đường dẫn và khớp glob — nền tảng của scope và whitelist."""

from __future__ import annotations

import pytest

from fim.util import (
    glob_match,
    human_size,
    is_within,
    normalize_path,
    parse_duration,
)


class TestNormalizePath:
    def test_backslash_thanh_slash(self):
        assert normalize_path(r"C:\Windows\System32") == "c:/Windows/System32"

    def test_o_dia_viet_thuong(self):
        # Windows không phân biệt hoa thường ở tên ổ đĩa, nên phải chuẩn hoá
        # để "C:/x" và "c:/x" không bị coi là hai file khác nhau.
        assert normalize_path("C:/x") == normalize_path("c:/x")

    def test_gop_slash_lap(self):
        assert normalize_path("/etc//ssl///certs") == "/etc/ssl/certs"

    def test_giu_tien_to_unc(self):
        assert normalize_path(r"\\server\share\file") == "//server/share/file"

    def test_bo_slash_cuoi(self):
        assert normalize_path("/etc/ssl/") == "/etc/ssl"

    def test_giu_slash_goc(self):
        assert normalize_path("/") == "/"
        assert normalize_path("c:/") == "c:/"


class TestGlobMatch:
    def test_sao_don_khong_vuot_slash(self):
        assert glob_match("/etc/passwd", "/etc/*")
        assert not glob_match("/etc/ssl/cert.pem", "/etc/*")

    def test_sao_doi_bac_cau_nhieu_cap(self):
        assert glob_match("/etc/ssl/certs/ca.pem", "/etc/**")
        assert glob_match("/etc/ssl/certs/ca.pem", "/etc/**/*.pem")

    def test_sao_doi_khop_ca_khong_cap_nao(self):
        # "/etc/**/x" phải khớp cả "/etc/x" — đây là lỗi kinh điển khi tự viết
        # bộ dịch glob, nên có test riêng.
        assert glob_match("/etc/x", "/etc/**/x")
        assert glob_match("/etc/a/b/x", "/etc/**/x")

    def test_mau_thu_muc_khop_ben_trong(self):
        assert glob_match("/etc/ssl/cert.pem", "/etc/ssl")

    def test_dau_hoi_mot_ky_tu(self):
        assert glob_match("/etc/rc1.d", "/etc/rc?.d")
        assert not glob_match("/etc/rc12.d", "/etc/rc?.d")

    def test_lop_ky_tu(self):
        assert glob_match("/etc/rc3.d", "/etc/rc[0-6].d")
        assert not glob_match("/etc/rc9.d", "/etc/rc[0-6].d")

    def test_khop_duoc_ca_hai_kieu_slash(self):
        assert glob_match(r"C:\Windows\System32\drivers\etc\hosts", "**/System32/**")

    def test_khong_khop_thu_muc_khac(self):
        assert not glob_match("/var/log/app.log", "/etc/**")


class TestIsWithin:
    def test_con_nam_trong_cha(self):
        assert is_within("/etc/ssl/cert.pem", "/etc")

    def test_chinh_no(self):
        assert is_within("/etc", "/etc")

    def test_khong_bi_lua_boi_tien_to_ten(self):
        # "/etcetera" không nằm trong "/etc" dù chuỗi bắt đầu giống nhau.
        assert not is_within("/etcetera/x", "/etc")


class TestParseDuration:
    @pytest.mark.parametrize(
        "text,expected",
        [("30s", 30), ("15m", 900), ("2h", 7200), ("7d", 604800), ("1w", 604800),
         ("1.5s", 1.5), ("45", 45)],
    )
    def test_cac_don_vi(self, text, expected):
        assert parse_duration(text) == expected

    def test_don_vi_la_thi_bao_loi(self):
        with pytest.raises(ValueError):
            parse_duration("10 nam")


def test_human_size():
    assert human_size(0) == "0 B"
    assert human_size(512) == "512 B"
    assert human_size(1536) == "1.5 KB"
    assert human_size(5 * 1024**3) == "5.0 GB"
