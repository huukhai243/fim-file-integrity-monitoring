"""Tiện ích dùng chung: chuẩn hoá đường dẫn, khớp glob, định dạng hiển thị."""

from __future__ import annotations

import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

# ---------------------------------------------------------------------------
# Đường dẫn
# ---------------------------------------------------------------------------


def normalize_path(path: str | os.PathLike[str]) -> str:
    """Đưa đường dẫn về dạng chuẩn để so sánh và lưu CSDL.

    Luôn dùng dấu ``/`` kể cả trên Windows, để một whitelist viết bằng ``/``
    chạy được trên cả hai hệ điều hành. Ổ đĩa Windows được viết thường
    (``C:/Windows`` -> ``c:/Windows``) vì Windows không phân biệt hoa thường
    ở tên ổ đĩa.
    """
    text = str(path).replace("\\", "/")
    # Gộp các dấu / lặp, nhưng giữ tiền tố UNC "//server/share".
    prefix = "//" if text.startswith("//") else ""
    text = prefix + re.sub(r"/{2,}", "/", text[len(prefix):])
    # Bỏ dấu / thừa ở cuối, trừ khi đó là gốc ("/" hoặc "c:/").
    if len(text) > 1 and text.endswith("/") and not text.endswith(":/"):
        text = text.rstrip("/")
    if re.match(r"^[A-Za-z]:", text):
        text = text[0].lower() + text[1:]
    return text


def absolute_path(path: str | os.PathLike[str]) -> str:
    """Tuyệt đối hoá rồi chuẩn hoá. Không giải symlink (FIM cần thấy chính symlink)."""
    return normalize_path(os.path.abspath(str(path)))


def path_parts(path: str) -> tuple[str, ...]:
    return PurePosixPath(normalize_path(path)).parts


def is_within(path: str, parent: str) -> bool:
    """``path`` có nằm trong cây thư mục ``parent`` không (hoặc chính là nó)?"""
    p, par = normalize_path(path), normalize_path(parent)
    if p == par:
        return True
    return p.startswith(par.rstrip("/") + "/")


# ---------------------------------------------------------------------------
# Khớp glob
# ---------------------------------------------------------------------------

_GLOB_CACHE: dict[tuple[str, bool], re.Pattern[str]] = {}


def _compile_glob(pattern: str, case_sensitive: bool) -> re.Pattern[str]:
    """Dịch glob sang regex, có hỗ trợ ``**`` bắc cầu qua nhiều cấp thư mục.

    ``fnmatch`` không phân biệt ``*`` với ``**`` (``*`` của nó nuốt cả dấu ``/``),
    nên phải tự dịch. Quy ước giống .gitignore:

    * ``*``     — khớp trong một cấp, không vượt qua ``/``
    * ``**``    — khớp nhiều cấp, kể cả không cấp nào
    * ``?``     — đúng một ký tự, không phải ``/``
    * ``[abc]`` — lớp ký tự
    """
    key = (pattern, case_sensitive)
    cached = _GLOB_CACHE.get(key)
    if cached is not None:
        return cached

    out: list[str] = ["^"]
    i, n = 0, len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "*":
            if pattern.startswith("**", i):
                i += 2
                # "/**/" phải khớp được cả "/" (không có cấp nào ở giữa).
                if pattern.startswith("/", i) and out and out[-1] == "/":
                    out.pop()
                    out.append("(?:/.*)?/" if i + 1 < n else "(?:/.*)?")
                    i += 1
                else:
                    out.append(".*")
            else:
                out.append("[^/]*")
                i += 1
        elif ch == "?":
            out.append("[^/]")
            i += 1
        elif ch == "[":
            end = pattern.find("]", i + 1)
            if end == -1:                      # "[" lẻ -> ký tự thường
                out.append(re.escape(ch))
                i += 1
            else:
                body = pattern[i + 1:end]
                body = body.replace("\\", "\\\\")
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body + "]")
                i = end + 1
        else:
            out.append(re.escape(ch))
            i += 1
    out.append("$")

    flags = 0 if case_sensitive else re.IGNORECASE
    compiled = re.compile("".join(out), flags)
    _GLOB_CACHE[key] = compiled
    return compiled


def glob_match(path: str, pattern: str, case_sensitive: bool | None = None) -> bool:
    """``path`` có khớp ``pattern`` không.

    Mặc định phân biệt hoa thường trên Linux/macOS và không phân biệt trên Windows,
    đúng như hành vi của hệ thống tệp bên dưới.
    """
    if case_sensitive is None:
        case_sensitive = os.name != "nt"
    target = normalize_path(path)
    pat = normalize_path(pattern)
    if _compile_glob(pat, case_sensitive).match(target):
        return True
    # Mẫu trỏ tới thư mục thì khớp luôn mọi thứ bên trong: "/etc/ssl" ~ "/etc/ssl/x.pem".
    if not pat.endswith("*"):
        return bool(_compile_glob(pat.rstrip("/") + "/**", case_sensitive).match(target))
    return False


def any_glob_match(path: str, patterns: list[str]) -> str | None:
    """Trả về mẫu đầu tiên khớp, hoặc ``None``. Trả về mẫu để log được lý do."""
    for pattern in patterns:
        if glob_match(path, pattern):
            return pattern
    return None


# ---------------------------------------------------------------------------
# Thời gian & định dạng
# ---------------------------------------------------------------------------


def now() -> float:
    return time.time()


def iso(ts: float | None) -> str:
    """Epoch -> chuỗi ISO-8601 UTC. Dashboard tự đổi sang giờ địa phương."""
    if ts is None:
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


def parse_duration(text: str) -> float:
    """``"30s"``, ``"15m"``, ``"2h"``, ``"7d"`` -> số giây. Số trần = giây."""
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smhdw]?)\s*", str(text), re.IGNORECASE)
    if not match:
        raise ValueError(f"Không hiểu khoảng thời gian: {text!r}")
    value = float(match.group(1))
    return value * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[
        match.group(2).lower()
    ]


def human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size) < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def ensure_parent(path: str | os.PathLike[str]) -> Path:
    """Tạo thư mục cha nếu chưa có, trả về ``Path`` của chính file."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def enable_utf8_output() -> None:
    """Buộc stdout/stderr dùng UTF-8.

    Console Windows mặc định là cp1252, không mã hoá được tiếng Việt: mọi lệnh in
    ra sẽ vỡ với ``UnicodeEncodeError``. Gọi hàm này ở đầu mỗi điểm vào (CLI,
    script) trước khi in bất cứ thứ gì.

    Dùng ``errors="replace"`` để nếu terminal vẫn không hiển thị được ký tự thì
    thay bằng dấu hỏi, chứ không làm chương trình dừng giữa lúc đang báo cáo.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass          # stream đã bị chuyển hướng sang thứ không cấu hình được
