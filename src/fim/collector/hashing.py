"""Băm file và chụp metadata — nền tảng của baseline (Người 1).

Điểm cần nhớ khi đọc code này:

* Đọc theo khối, không nạp cả file vào RAM — baseline có thể gặp file vài GB.
* Symlink **không** được đi theo. Một symlink trỏ tới nơi khác chính là thay đổi
  cần phát hiện; đi theo nó sẽ băm nhầm file đích và bỏ lọt tấn công.
* Lỗi đọc (thiếu quyền, file đang bị khoá) không làm hỏng cả lần quét: ghi vào
  ``FileRecord.error`` rồi đi tiếp.
"""

from __future__ import annotations

import hashlib
import math
import os
import stat
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable, Iterator

from ..models import FileRecord
from ..util import normalize_path

#: Các thuật toán được phép. Giới hạn danh sách để baseline luôn so sánh được
#: với nhau — đổi thuật toán đồng nghĩa phải chốt lại baseline.
SUPPORTED_ALGOS = ("blake2b", "sha256", "sha1", "md5")


def new_hasher(algo: str = "blake2b", digest_size: int = 32):
    """Tạo đối tượng hash. ``blake2b`` nhanh hơn sha256 đáng kể trên CPU 64-bit."""
    algo = algo.lower()
    if algo not in SUPPORTED_ALGOS:
        raise ValueError(
            f"Thuật toán không hỗ trợ: {algo}. Chọn một trong: {', '.join(SUPPORTED_ALGOS)}"
        )
    if algo == "blake2b":
        return hashlib.blake2b(digest_size=digest_size)
    return hashlib.new(algo)


def hash_file(
    path: str,
    algo: str = "blake2b",
    digest_size: int = 32,
    chunk_size: int = 1 << 20,
) -> str:
    """Băm nội dung file, đọc theo khối ``chunk_size``."""
    hasher = new_hasher(algo, digest_size)
    with open(path, "rb", buffering=0) as fh:
        while True:
            block = fh.read(chunk_size)
            if not block:
                break
            hasher.update(block)
    return hasher.hexdigest()


def hash_bytes(data: bytes, algo: str = "blake2b", digest_size: int = 32) -> str:
    hasher = new_hasher(algo, digest_size)
    hasher.update(data)
    return hasher.hexdigest()


def stat_file(path: str, follow_symlinks: bool = False) -> FileRecord:
    """Chụp metadata mà không đọc nội dung — rẻ, dùng cho vòng lọc sơ bộ."""
    norm = normalize_path(path)
    st = os.stat(path, follow_symlinks=follow_symlinks)
    is_link = stat.S_ISLNK(st.st_mode)
    target: str | None = None
    if is_link:
        try:
            target = normalize_path(os.readlink(path))
        except OSError:
            target = None
    return FileRecord(
        path=norm,
        size=st.st_size,
        mtime=st.st_mtime,
        ctime=st.st_ctime,
        mode=st.st_mode,
        uid=getattr(st, "st_uid", 0),
        gid=getattr(st, "st_gid", 0),
        is_symlink=is_link,
        link_target=target,
    )


def build_record(
    path: str,
    *,
    algo: str = "blake2b",
    digest_size: int = 32,
    chunk_size: int = 1 << 20,
    max_file_size: int = 512 << 20,
    follow_symlinks: bool = False,
) -> FileRecord:
    """Chụp metadata **và** băm nội dung. Không ném lỗi — ghi vào ``record.error``.

    File vượt ``max_file_size`` được giữ trong baseline nhưng không băm: vẫn phát
    hiện được đổi kích thước/quyền, chỉ là không phát hiện được sửa nội dung tại chỗ.
    """
    try:
        record = stat_file(path, follow_symlinks=follow_symlinks)
    except OSError as exc:
        return FileRecord(path=normalize_path(path), error=f"stat: {exc.strerror or exc}")

    if record.is_symlink:
        # Băm chính đường dẫn đích: symlink bị trỏ lại chỗ khác sẽ đổi digest.
        record.digest = hash_bytes(
            (record.link_target or "").encode("utf-8", "surrogateescape"), algo, digest_size
        )
        return record

    if not stat.S_ISREG(record.mode):
        record.error = "không phải file thường"       # socket, FIFO, device…
        return record

    if record.size > max_file_size:
        record.error = f"vượt ngưỡng hash ({record.size} byte)"
        return record

    try:
        record.digest = hash_file(path, algo, digest_size, chunk_size)
    except OSError as exc:
        record.error = f"read: {exc.strerror or exc}"
    return record


def build_records(
    paths: Iterable[str],
    *,
    workers: int = 4,
    progress: Callable[[int, FileRecord], None] | None = None,
    **kwargs: object,
) -> Iterator[FileRecord]:
    """Băm nhiều file song song.

    Băm là tác vụ nghẽn I/O nên thread hiệu quả hơn process ở đây, lại không tốn
    chi phí pickle. ``workers <= 1`` chạy tuần tự, tiện khi debug.
    """
    path_list = list(paths)
    if workers <= 1:
        for index, path in enumerate(path_list, 1):
            record = build_record(path, **kwargs)  # type: ignore[arg-type]
            if progress:
                progress(index, record)
            yield record
        return

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(build_record, p, **kwargs) for p in path_list]  # type: ignore[arg-type]
        for index, future in enumerate(futures, 1):
            record = future.result()
            if progress:
                progress(index, record)
            yield record


# ---------------------------------------------------------------------------
# Phân tích nội dung — Người 2 dùng cho heuristic
# ---------------------------------------------------------------------------


def shannon_entropy(data: bytes) -> float:
    """Entropy Shannon theo bit/byte, thang 0–8.

    Văn bản thường nằm khoảng 4–5; file nén, mã hoá hoặc đã đóng gói (packed)
    tiệm cận 8. Một file cấu hình đột nhiên đạt entropy ~8 là dấu hiệu đáng ngờ.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum(
        (count / total) * math.log2(count / total) for count in counts.values()
    )


def sample_entropy(path: str, sample_size: int = 262144) -> float | None:
    """Entropy của ``sample_size`` byte đầu file. ``None`` nếu không đọc được."""
    try:
        with open(path, "rb", buffering=0) as fh:
            return shannon_entropy(fh.read(sample_size))
    except OSError:
        return None


#: Chữ ký magic bytes -> loại file. Chỉ liệt kê những loại có ý nghĩa với FIM:
#: file thực thi, script và kho lưu trữ.
_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "elf"),              # nhị phân Linux
    (b"MZ", "pe"),                    # .exe/.dll Windows
    (b"\xca\xfe\xba\xbe", "macho"),   # Mach-O universal (macOS)
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\xfe\xed\xfa\xce", "macho"),
    (b"PK\x03\x04", "zip"),           # cả .jar/.docx/.apk
    (b"\x1f\x8b", "gzip"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
    (b"#!", "script"),                # shebang
    (b"\xed\xab\xee\xdb", "rpm"),
    (b"%PDF", "pdf"),
)


def detect_magic(path: str) -> str | None:
    """Đoán loại file từ vài byte đầu. ``None`` nếu không khớp chữ ký nào."""
    try:
        with open(path, "rb", buffering=0) as fh:
            head = fh.read(16)
    except OSError:
        return None
    for signature, kind in _MAGIC:
        if head.startswith(signature):
            return kind
    return None


def is_executable(record: FileRecord) -> bool:
    """File có thể chạy được không — xét cả bit quyền (POSIX) lẫn phần mở rộng (Windows)."""
    if record.mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        return True
    suffix = record.path.rsplit(".", 1)[-1].lower() if "." in record.path else ""
    return suffix in {"exe", "dll", "com", "bat", "cmd", "ps1", "scr", "msi", "sys"}
