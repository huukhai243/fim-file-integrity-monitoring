from __future__ import annotations
import json
from pathlib import Path


class FimError(Exception):
    pass


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _abs(p, root: Path) -> str:
    p = Path(p).expanduser()
    if not p.is_absolute(): p = root / p
    return p.resolve().as_posix()


def load_config(config_path="config.json") -> dict:
    root = project_root()
    path = Path(config_path)
    if not path.is_absolute() and not path.exists(): path = root / path
    if not path.exists(): raise FimError(f'Không tìm thấy file cấu hình: {config_path}')
    try:
        with path.open("r", encoding="utf-8") as f: cfg = json.load(f)
    except json.JSONDecodeError as e:
        raise FimError(f'Config {path} không phải JSON hợp lệ: {e}')
    # Tương thích bản cũ: "watch_root": "folder"
    watch = cfg.get('watch_paths') or ([cfg['watch_root']] if cfg.get('watch_root') else [])
    if not watch: raise FimError('Config cần "watch_paths" (danh sách thư mục giám sát).')
    if any(isinstance(w, dict) and not w.get('path') for w in watch):
        raise FimError('Mỗi mục trong "watch_paths" cần có khóa "path".')
    # Gộp các mục trỏ tới cùng một thư mục sau khi giải symlink (vd. /bin -> /usr/bin trên Debian, Ubuntu mới),
    # tránh quét và hiển thị một thư mục hai lần; giữ nhãn của mục đầu, critical nếu một trong các mục là critical
    merged: dict[str, dict] = {}
    for w in watch:
        w = dict(w, path=_abs(w['path'], root)) if isinstance(w, dict) else {'path': _abs(w, root)}
        if w['path'] in merged:
            merged[w['path']]['critical'] = bool(merged[w['path']].get('critical') or w.get('critical'))
        else:
            merged[w['path']] = w
    cfg['watch_paths'] = list(merged.values())
    for key, default in (("database", "data/fim.db"), ("log_file", "logs/fim.log")):
        cfg[key] = _abs(cfg.get(key, default), root)
    cfg['_config_path'] = str(path.resolve())
    return cfg


def short(path: str) -> str:
    """Đường dẫn hiển thị: tương đối nếu nằm trong project, ngược lại giữ tuyệt đối."""
    base = project_root().as_posix().rstrip('/') + '/'
    return path[len(base):] if path and path.startswith(base) else path


def roots(cfg) -> list[str]:
    return [w['path'] for w in cfg['watch_paths']]
