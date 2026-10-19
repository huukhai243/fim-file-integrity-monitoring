"""Baseline hash & so sánh trạng thái file."""
from __future__ import annotations
import fnmatch, functools, hashlib, os, re, stat
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FileState:
    path: str
    sha256: str
    size: int
    mtime_ns: int
    mode: int
    uid: int | None = None   # chủ sở hữu; None = chưa ghi nhận (baseline tạo từ phiên bản cũ)
    gid: int | None = None


@dataclass
class Change:
    path: str
    # CREATED / DELETED / MOVED, hoặc ghép bằng '+' từ MODIFIED, PERMISSION_CHANGED, OWNER_CHANGED;
    # TIMESTAMP_CHANGED khi chỉ thời gian sửa thay đổi còn nội dung, quyền, chủ sở hữu giữ nguyên
    event_type: str
    old: FileState | None
    new: FileState | None


def sha256_file(path: Path, chunk_size=1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        while True:
            b = f.read(chunk_size)
            if not b: break
            h.update(b)
    return h.hexdigest()


@functools.lru_cache(maxsize=64)
def _compile(patterns: tuple[str, ...]):
    """Gộp các pattern thành một regex. Hàm matches được gọi cho mọi file ở mỗi lần quét; gọi fnmatch cho từng
    cặp (pattern, chuỗi) chiếm phần lớn thời gian quét. Trên Windows, giống fnmatch: không phân biệt hoa thường
    và coi \\ như / (các đường dẫn so khớp luôn dùng /)."""
    if not patterns: return None
    nt = os.name == 'nt'
    return re.compile('|'.join(fnmatch.translate(p.replace('\\', '/') if nt else p) for p in patterns),
                      re.IGNORECASE if nt else 0)


def matches(patterns, *candidates) -> bool:
    """True nếu một trong các chuỗi (đường dẫn tuyệt đối, tương đối, tên file; dùng dấu /) khớp một pattern."""
    rx = _compile(tuple(patterns))
    return rx is not None and any(rx.match(c) for c in candidates if c)


def rel_path(key: str, roots: list[str]) -> str:
    """Đường dẫn tương đối so với thư mục giám sát chứa file (root dài nhất khớp)."""
    best = ''
    for r in roots:
        r = r.rstrip('/')
        if key.startswith(r + '/') and len(r) > len(best): best = r
    return key[len(best) + 1:] if best else key


def is_ignored(key: str, roots: list[str], ignore: list[str]) -> bool:
    return matches(ignore, key, rel_path(key, roots), key.rsplit('/', 1)[-1])


def scan_tree(roots: list[str], ignore=(), prev: dict[str, FileState] | None = None):
    """Quét các thư mục giám sát, trả về (states, errors).

    Nếu truyền `prev` (quick scan), file có size + mtime không đổi sẽ dùng lại hash cũ
    thay vì đọc lại toàn bộ nội dung. Full scan (prev=None) luôn hash lại mọi file.
    """
    ignore = list(ignore); states: dict[str, FileState] = {}; errors: list[str] = []
    for root in roots:
        rootp = Path(root)
        if not rootp.is_dir():
            errors.append(f'{root}: thư mục không tồn tại'); continue
        base = rootp.as_posix().rstrip('/')
        for dirpath, dirnames, filenames in os.walk(rootp, onerror=lambda e: errors.append(f'{e.filename}: {e.strerror}')):
            # Ghép đường dẫn bằng chuỗi: Path.relative_to cho từng file rất chậm khi thư mục có hàng nghìn file
            cur = Path(dirpath).as_posix().rstrip('/'); sub = cur[len(base) + 1:]
            prefix = sub + '/' if sub else ''
            dirnames[:] = [d for d in dirnames if not matches(ignore, f'{prefix}{d}/', d + '/')]
            for name in filenames:
                key = f'{cur}/{name}'; rel = prefix + name
                if matches(ignore, key, rel, name): continue
                try:
                    st = os.stat(key)
                    if not stat.S_ISREG(st.st_mode): continue   # bỏ qua socket, FIFO, device...
                    old = prev.get(key) if prev else None
                    if old and old.size == st.st_size and old.mtime_ns == st.st_mtime_ns:
                        digest = old.sha256
                    else:
                        digest = sha256_file(Path(key))
                    states[key] = FileState(key, digest, st.st_size, st.st_mtime_ns, st.st_mode & 0o7777, st.st_uid, st.st_gid)
                except OSError as e:
                    errors.append(f'{key}: {e.strerror or e}')
    return states, errors


def compare_states(old: dict[str, FileState], new: dict[str, FileState]) -> list[Change]:
    out = []; a = set(old); b = set(new)
    created = sorted(b - a); deleted = sorted(a - b)
    # File bị xóa + file mới có cùng nội dung => đổi tên / di chuyển
    by_hash: dict[str, list[str]] = {}
    for p in deleted:
        if old[p].size > 0: by_hash.setdefault(old[p].sha256, []).append(p)
    moved_from = set()
    for p in created:
        src = by_hash.get(new[p].sha256)
        if src:
            q = src.pop(0); moved_from.add(q); out.append(Change(p, 'MOVED', old[q], new[p]))
        else:
            out.append(Change(p, 'CREATED', None, new[p]))
    for p in deleted:
        if p not in moved_from: out.append(Change(p, 'DELETED', old[p], None))
    for p in sorted(a & b):
        o, n = old[p], new[p]
        kinds = []
        if o.sha256 != n.sha256 or o.size != n.size: kinds.append('MODIFIED')
        if o.mode != n.mode: kinds.append('PERMISSION_CHANGED')
        if None not in (o.uid, n.uid) and (o.uid, o.gid) != (n.uid, n.gid): kinds.append('OWNER_CHANGED')
        if not kinds and o.mtime_ns != n.mtime_ns: kinds.append('TIMESTAMP_CHANGED')
        if kinds: out.append(Change(p, '+'.join(kinds), o, n))
    return out
