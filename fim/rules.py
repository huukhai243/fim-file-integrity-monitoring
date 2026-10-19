"""Phân loại thay đổi hợp lệ / đáng ngờ (heuristic + whitelist)."""
from __future__ import annotations
import bisect, os, time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from .core import Change, matches, rel_path

LEGITIMATE, SUSPICIOUS = 'LEGITIMATE', 'SUSPICIOUS'
BASE_SCORE = {'DELETED': 3, 'MODIFIED': 2, 'MOVED': 2, 'CREATED': 1}
DEFAULT_SUSPICIOUS_EXT = ['.locked', '.encrypted', '.enc', '.crypt', '.crypto', '.ransom']
# Dấu hiệu luôn bị cảnh báo kể cả khi file khớp whitelist 'allow'
# (vd. allow '*.log' cho phép ghi thêm log, nhưng làm rỗng log = xóa dấu vết)
NON_WHITELISTABLE = {'file truncated to 0 bytes', 'setuid/setgid bit set', 'ransomware-like extension',
                     'timestamp moved backwards (timestomp)'}


@dataclass
class Verdict:
    score: int
    level: str               # LOW / MEDIUM / HIGH
    verdict: str             # LEGITIMATE / SUSPICIOUS
    reasons: list[str] = field(default_factory=list)

    @property
    def details(self): return ', '.join(self.reasons)


def level_of(score: int) -> str:
    return 'LOW' if score <= 2 else ('MEDIUM' if score <= 4 else 'HIGH')


def watch_entry(path: str, cfg: dict) -> dict | None:
    """Thư mục giám sát (trong cfg['watch_paths']) chứa file này."""
    best = None
    for w in cfg.get('watch_paths', []):
        r = w['path'].rstrip('/')
        if path.startswith(r + '/') and (best is None or len(r) > len(best['path'])): best = w
    return best


def allow_rule(change: Change, cfg: dict, allow: list[dict]) -> dict | None:
    """Rule whitelist loại 'allow' khớp với thay đổi (pattern + loại sự kiện)."""
    roots = [w['path'] for w in cfg.get('watch_paths', [])]
    p = change.path; rel = rel_path(p, roots); name = p.rsplit('/', 1)[-1]
    kinds = set(change.event_type.split('+'))
    for rule in allow:
        evs = {e.strip().upper() for e in (rule.get('events') or '*').split(',') if e.strip()}
        if matches([rule['pattern']], p, rel, name) and ('*' in evs or kinds & evs):
            return rule
    return None


def burst_sizes(changes: list[Change], window_s: float = 60.0) -> list[int]:
    """Với mỗi thay đổi: số thay đổi (kể cả nó) có thời điểm sửa cách nhau không quá `window_s` giây.
    Ransomware đặc trưng bởi nhiều file đổi trong thời gian ngắn; đếm cả lô sẽ khiến một lần `scan`
    đối chiếu baseline sau nhiều ngày coi mọi thay đổi bình thường là "hàng loạt". File bị xóa không còn
    mtime nên lấy thời điểm phát hiện."""
    now = time.time_ns(); w = int(window_s * 1e9)
    ts = [c.new.mtime_ns if c.new else now for c in changes]; order = sorted(ts)
    return [bisect.bisect_right(order, t + w) - bisect.bisect_left(order, t - w) for t in ts]


def classify(change: Change, cfg: dict, allow=(), batch_size=1, now: datetime | None = None) -> Verdict:
    score = 0; reasons = []
    kinds = change.event_type.split('+')
    # Thời gian sửa bị lùi về quá khứ là dấu hiệu che giấu thay đổi (MITRE ATT&CK T1070.006 Timestomp).
    # Đổi tên/di chuyển giữ nguyên mtime nên không xét.
    backdated = bool(change.old and change.new and kinds[0] != 'MOVED' and change.new.mtime_ns < change.old.mtime_ns)
    if kinds == ['TIMESTAMP_CHANGED'] and not backdated:      # touch: nội dung, quyền, chủ sở hữu giữ nguyên
        return Verdict(0, 'LOW', LEGITIMATE, ['timestamp updated, content unchanged'])
    if backdated: score += 4; reasons.append('timestamp moved backwards (timestomp)')
    for k in ('DELETED', 'MODIFIED', 'MOVED', 'CREATED'):
        if k in kinds:
            score += BASE_SCORE[k]; reasons.append({'DELETED': 'file deleted', 'MODIFIED': 'content changed',
                                                    'MOVED': 'file moved/renamed', 'CREATED': 'new file'}[k]); break
    if 'PERMISSION_CHANGED' in kinds: score += 2; reasons.append('permission changed')
    if 'OWNER_CHANGED' in kinds: score += 3; reasons.append('owner changed')

    p = change.path.replace('\\', '/'); name = p.rsplit('/', 1)[-1]; suffix = Path(name).suffix.lower()
    roots = [w['path'] for w in cfg.get('watch_paths', [])]; rel = rel_path(p, roots)

    # 1. Phạm vi: thư mục hệ thống quan trọng
    w = watch_entry(p, cfg)
    if w and w.get('critical'): score += 2; reasons.append(f"critical directory ({w.get('label') or w['path']})")
    # 2. Đường dẫn nhạy cảm / file thực thi
    if matches(cfg.get('sensitive_paths', []), p, rel, name): score += 3; reasons.append('sensitive path')
    if suffix in {x.lower() for x in cfg.get('executable_extensions', [])}: score += 2; reasons.append('executable/script file')
    # 3. Dấu hiệu ransomware / che giấu
    if suffix in {x.lower() for x in cfg.get('suspicious_extensions', DEFAULT_SUSPICIOUS_EXT)}:
        score += 4; reasons.append('ransomware-like extension')
    if kinds[0] in ('CREATED', 'MOVED') and name.startswith('.'): score += 2; reasons.append('hidden file')
    if kinds[0] == 'MOVED' and change.old and Path(change.old.path).suffix.lower() != suffix:
        score += 2; reasons.append(f'extension changed ({Path(change.old.path).suffix or "none"} -> {suffix or "none"})')
    if 'MODIFIED' in kinds and change.old and change.new and change.old.size > 0 and change.new.size == 0:
        score += 2; reasons.append('file truncated to 0 bytes')
    # 4. Quyền Unix (trên Windows st_mode không phản ánh quyền thật nên mặc định tắt)
    if cfg.get('check_unix_permissions', os.name == 'posix') and change.new:
        o = change.old.mode if change.old else 0; n = change.new.mode
        if change.old and (n & ~o) & 0o111: score += 3; reasons.append('execute permission added')
        if (n & ~o) & 0o6000: score += 4; reasons.append('setuid/setgid bit set')
        if (n & ~o) & 0o002: score += 3; reasons.append('world-writable')
    # 5. Ngữ cảnh: ngoài giờ làm việc, thay đổi hàng loạt
    now = now or datetime.now()
    start, end = cfg.get('work_hours', [7, 19])
    if not (start <= now.hour < end): score += 1; reasons.append(f'outside work hours ({start}h-{end}h)')
    threshold = int(cfg.get('mass_change_threshold', 10))
    if batch_size >= threshold: score += 3; reasons.append(f'mass change ({batch_size} files at once)')

    level = level_of(score)
    rule = allow_rule(change, cfg, list(allow))
    strong = [r for r in reasons if r in NON_WHITELISTABLE]
    if rule and not strong:
        reasons.append(f"allowed by whitelist '{rule['pattern']}'")
        return Verdict(score, level, LEGITIMATE, reasons)
    if rule:   # whitelist không được che các dấu hiệu tấn công rõ ràng
        reasons.append(f"whitelist '{rule['pattern']}' overridden")
    verdict = SUSPICIOUS if score >= int(cfg.get('suspicious_threshold', 3)) else LEGITIMATE
    return Verdict(score, level, verdict, reasons)
