"""Test phần Người 1: băm, baseline, phát hiện thay đổi."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from fim.collector.baseline import BaselineBuilder
from fim.collector.differ import Differ, compare_records
from fim.collector.hashing import (
    build_record,
    detect_magic,
    hash_bytes,
    hash_file,
    is_executable,
    shannon_entropy,
    stat_file,
)
from fim.config import BaselineConfig
from fim.models import ChangeType, FileRecord
from fim.store import Store


class TestHashing:
    def test_cung_noi_dung_cung_hash(self, tmp_path: Path):
        a, b = tmp_path / "a", tmp_path / "b"
        a.write_bytes(b"noi dung giong nhau")
        b.write_bytes(b"noi dung giong nhau")
        assert hash_file(str(a)) == hash_file(str(b))

    def test_khac_mot_byte_khac_hash(self, tmp_path: Path):
        a, b = tmp_path / "a", tmp_path / "b"
        a.write_bytes(b"noi dung A")
        b.write_bytes(b"noi dung B")
        assert hash_file(str(a)) != hash_file(str(b))

    def test_doc_theo_khoi_cho_ket_qua_giong_doc_mot_lan(self, tmp_path: Path):
        # Ranh giới khối là chỗ dễ sai nhất khi băm theo chunk.
        payload = os.urandom(300_000)
        f = tmp_path / "big.bin"
        f.write_bytes(payload)
        assert hash_file(str(f), chunk_size=4096) == hash_bytes(payload)

    def test_thuat_toan_la_bao_loi(self, tmp_path: Path):
        f = tmp_path / "x"
        f.write_bytes(b"x")
        with pytest.raises(ValueError, match="không hỗ trợ"):
            hash_file(str(f), algo="crc32")

    def test_file_qua_lon_khong_bam_nhung_van_theo_doi(self, tmp_path: Path):
        f = tmp_path / "big"
        f.write_bytes(b"x" * 5000)
        record = build_record(str(f), max_file_size=100)
        assert record.digest is None
        assert record.error is not None and "ngưỡng" in record.error
        assert record.size == 5000          # vẫn biết kích thước để so sánh

    def test_file_khong_ton_tai_tra_ve_record_co_loi(self, tmp_path: Path):
        record = build_record(str(tmp_path / "khong-co"))
        assert record.error is not None
        assert record.digest is None       # không ném exception, để lần quét chạy tiếp


class TestEntropy:
    def test_du_lieu_lap_lai_entropy_thap(self):
        assert shannon_entropy(b"A" * 1000) == 0.0

    def test_du_lieu_ngau_nhien_entropy_cao(self):
        assert shannon_entropy(os.urandom(20000)) > 7.5

    def test_van_ban_entropy_trung_binh(self):
        text = ("log_level = info\nworkers = 4\n" * 50).encode()
        assert 3.0 < shannon_entropy(text) < 5.5

    def test_rong_tra_ve_khong(self):
        assert shannon_entropy(b"") == 0.0


class TestMagicBytes:
    def test_nhan_dien_elf(self, tmp_path: Path):
        f = tmp_path / "bin"
        f.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 50)
        assert detect_magic(str(f)) == "elf"

    def test_nhan_dien_pe(self, tmp_path: Path):
        f = tmp_path / "app.exe"
        f.write_bytes(b"MZ\x90\x00" + b"\x00" * 50)
        assert detect_magic(str(f)) == "pe"

    def test_nhan_dien_shebang(self, tmp_path: Path):
        f = tmp_path / "s.sh"
        f.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
        assert detect_magic(str(f)) == "script"

    def test_van_ban_thuong_khong_khop(self, tmp_path: Path):
        f = tmp_path / "note.txt"
        f.write_text("chi la van ban\n", encoding="utf-8")
        assert detect_magic(str(f)) is None


class TestIsExecutable:
    def test_theo_phan_mo_rong_windows(self):
        assert is_executable(FileRecord(path="c:/x/app.exe"))
        assert is_executable(FileRecord(path="c:/x/run.ps1"))
        assert not is_executable(FileRecord(path="c:/x/note.txt"))

    def test_theo_bit_quyen_posix(self):
        assert is_executable(FileRecord(path="/usr/bin/tool", mode=0o100755))
        assert not is_executable(FileRecord(path="/etc/conf", mode=0o100644))


class TestCompareRecords:
    def test_khong_doi_tra_ve_none(self):
        a = FileRecord(path="/x", size=10, mtime=100.0, digest="abc")
        b = FileRecord(path="/x", size=10, mtime=100.0, digest="abc")
        assert compare_records(a, b) is None

    def test_tao_moi(self):
        after = FileRecord(path="/x", digest="abc")
        event = compare_records(None, after)
        assert event is not None and event.change == ChangeType.CREATED

    def test_xoa(self):
        before = FileRecord(path="/x", digest="abc")
        event = compare_records(before, None)
        assert event is not None and event.change == ChangeType.DELETED

    def test_doi_noi_dung(self):
        before = FileRecord(path="/x", digest="abc", mtime=1.0)
        after = FileRecord(path="/x", digest="xyz", mtime=2.0)
        event = compare_records(before, after)
        assert event is not None and event.change == ChangeType.MODIFIED

    def test_chi_doi_quyen(self):
        before = FileRecord(path="/x", digest="abc", mode=0o100644)
        after = FileRecord(path="/x", digest="abc", mode=0o100777)
        event = compare_records(before, after)
        assert event is not None and event.change == ChangeType.ATTR_CHANGED

    def test_doi_ca_hai_thi_noi_dung_thang(self):
        # Sửa nội dung nhị phân hệ thống nguy hiểm hơn đổi quyền của nó, nên
        # MODIFIED phải thắng ATTR_CHANGED khi cả hai cùng xảy ra.
        before = FileRecord(path="/x", digest="abc", mode=0o100644)
        after = FileRecord(path="/x", digest="xyz", mode=0o100777)
        event = compare_records(before, after)
        assert event is not None and event.change == ChangeType.MODIFIED
        assert event.before.mode != event.after.mode   # chi tiết quyền vẫn còn đủ

    def test_thieu_digest_thi_lui_ve_size_mtime(self):
        before = FileRecord(path="/x", size=10, mtime=1.0, digest=None)
        after = FileRecord(path="/x", size=20, mtime=2.0, digest=None)
        event = compare_records(before, after)
        assert event is not None and event.change == ChangeType.MODIFIED


class TestBaselineAndDiffer:
    def test_baseline_ghi_du_file(self, store: Store, scope, tmp_tree: Path):
        result = BaselineBuilder(store, scope, BaselineConfig(workers=1)).build("b1")
        assert result.file_count == 4                 # 4 file trong tmp_tree
        assert store.active_baseline_id() == result.baseline_id
        assert len(store.file_paths(result.baseline_id)) == 4

    def test_khong_thay_doi_thi_khong_co_su_kien(self, store: Store, scope):
        BaselineBuilder(store, scope, BaselineConfig(workers=1)).build("b1")
        result = Differ(store, scope, config=BaselineConfig(workers=1)).diff()
        assert result.events == []

    def test_phat_hien_sua_tao_xoa(self, store: Store, scope, tmp_tree: Path):
        BaselineBuilder(store, scope, BaselineConfig(workers=1)).build("b1")

        (tmp_tree / "etc/app.conf").write_text("mode = changed\n", encoding="utf-8")
        (tmp_tree / "etc/new.conf").write_text("moi\n", encoding="utf-8")
        (tmp_tree / "var/log/app.log").unlink()

        result = Differ(store, scope, config=BaselineConfig(workers=1)).diff()
        kinds = {e.path.rsplit("/", 1)[-1]: e.change for e in result.events}
        assert kinds["app.conf"] == ChangeType.MODIFIED
        assert kinds["new.conf"] == ChangeType.CREATED
        assert kinds["app.log"] == ChangeType.DELETED

    def test_chua_co_baseline_thi_bao_loi_ro_rang(self, store: Store, scope):
        with pytest.raises(ValueError, match="Chưa có baseline"):
            Differ(store, scope)

    def test_approve_cap_nhat_baseline(self, store: Store, scope, tmp_tree: Path):
        BaselineBuilder(store, scope, BaselineConfig(workers=1)).build("b1")
        (tmp_tree / "etc/app.conf").write_text("da duyet\n", encoding="utf-8")

        differ = Differ(store, scope, config=BaselineConfig(workers=1))
        first = differ.diff()
        assert len(first.events) == 1

        differ.apply_to_baseline(first.events)

        # Sau khi chấp nhận, lần quét kế tiếp phải im lặng — nếu không, mọi thay
        # đổi hợp lệ sẽ báo lại mãi và người vận hành sẽ bỏ qua cảnh báo thật.
        assert Differ(store, scope, config=BaselineConfig(workers=1)).diff().events == []

    def test_chi_mot_baseline_active(self, store: Store, scope):
        builder = BaselineBuilder(store, scope, BaselineConfig(workers=1))
        first = builder.build("b1")
        second = builder.build("b2")
        assert store.active_baseline_id() == second.baseline_id
        assert store.get_baseline(first.baseline_id)["status"] == "archived"


@pytest.mark.skipif(os.name == "nt", reason="symlink cần quyền đặc biệt trên Windows")
class TestSymlink:
    def test_symlink_bam_theo_dich_khong_theo_noi_dung(self, tmp_path: Path):
        target = tmp_path / "real"
        target.write_text("noi dung", encoding="utf-8")
        link = tmp_path / "link"
        link.symlink_to(target)

        record = build_record(str(link))
        assert record.is_symlink
        # Đổi đích symlink phải đổi digest, kể cả khi nội dung file đích y nguyên.
        assert record.digest == hash_bytes(str(target).replace("\\", "/").encode())

    def test_doi_dich_symlink_bi_phat_hien(self, tmp_path: Path):
        a, b = tmp_path / "a", tmp_path / "b"
        a.write_text("A", encoding="utf-8")
        b.write_text("B", encoding="utf-8")
        link = tmp_path / "link"

        link.symlink_to(a)
        before = build_record(str(link))
        link.unlink()
        link.symlink_to(b)
        after = build_record(str(link))

        assert compare_records(before, after).change == ChangeType.MODIFIED
