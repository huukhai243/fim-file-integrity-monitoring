from __future__ import annotations
import json, logging, os, sys, time
from pathlib import Path
from .config import load_config, roots, short, FimError
from .core import FileState, scan_tree, compare_states, is_ignored, sha256_file
from .database import FimDB, now_iso
from .rules import classify, burst_sizes, SUSPICIOUS

# watchdog (inotify trên Linux) phát cả sự kiện mở/đóng file; chính việc hash file khi quét
# sẽ sinh ra các sự kiện này => bỏ qua để tránh vòng lặp quét liên tục.
IGNORED_WATCHDOG_EVENTS = {'opened', 'closed', 'closed_no_write'}


class _ColorFormatter(logging.Formatter):
    COLORS = {logging.WARNING: '\033[33m', logging.ERROR: '\033[31m', logging.CRITICAL: '\033[1;41;97m'}

    def format(self, record):
        s = super().format(record); c = self.COLORS.get(record.levelno)
        return f'{c}{s}\033[0m' if c else s


def logger_for(path):
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    lg = logging.getLogger('fim'); lg.setLevel(logging.INFO); lg.propagate = False
    for h in lg.handlers: h.close()
    lg.handlers.clear()
    fmt = '%(asctime)s | %(levelname)s | %(message)s'
    fh = logging.FileHandler(p, encoding='utf-8'); fh.setFormatter(logging.Formatter(fmt)); lg.addHandler(fh)
    sh = logging.StreamHandler()
    if sys.stderr.isatty():
        if os.name == 'nt': os.system('')          # bật màu ANSI trên console Windows
        sh.setFormatter(_ColorFormatter(fmt))
    else:
        sh.setFormatter(logging.Formatter(fmt))
    lg.addHandler(sh)
    return lg


def open_db(cfg) -> FimDB:
    db = FimDB(cfg['database']); db.seed_whitelist(cfg); return db


def _require_baseline(db):
    if not db.get_meta('baseline_at'):
        raise FimError('Chưa có baseline. Hãy chạy: python main.py init')


def _full_scan(cfg, db, lg=None):
    states, errors = scan_tree(roots(cfg), db.ignore_patterns())
    for e in errors[:20]:
        if lg: lg.warning('Scan error: %s', e)
    if lg and len(errors) > 20: lg.warning('... và %d lỗi khác', len(errors) - 20)
    return states, errors


def _drop_ignored(states, cfg, ignore):
    """Bỏ các file vừa được thêm vào whitelist ignore, tránh báo nhầm là DELETED."""
    rs = roots(cfg)
    return {k: v for k, v in states.items() if not is_ignored(k, rs, ignore)}


def evaluate(cfg, db, changes, source, lg=None, record=True):
    allow = db.allow_rules(); results = []
    alert_file = Path(cfg['log_file']).with_name('alerts.log')
    bursts = burst_sizes(changes, float(cfg.get('mass_change_window_seconds', 60)))
    for ch, burst in zip(changes, bursts):
        v = classify(ch, cfg, allow, batch_size=burst); results.append((ch, v))
        if not record: continue
        event_id, alert_id = db.record(ch, v, source)
        if lg:
            frm = f' (from {short(ch.old.path)})' if ch.event_type == 'MOVED' else ''
            msg = '[%s/%s] %s | %s%s | score=%d | %s'
            args = (v.verdict, v.level, ch.event_type, short(ch.path), frm, v.score, v.details)
            if v.verdict == SUSPICIOUS:
                lg.log(logging.CRITICAL if v.level == 'HIGH' else logging.WARNING, 'ALERT #%d ' + msg, alert_id, *args)
            else:
                lg.info(msg, *args)
        if alert_id:   # JSON lines - dễ đẩy sang SIEM (Wazuh, ELK...)
            with alert_file.open('a', encoding='utf-8') as f:
                f.write(json.dumps({'alert_id': alert_id, 'event_id': event_id, 'time': now_iso(), 'path': ch.path,
                                    'event': ch.event_type, 'severity': v.level, 'score': v.score,
                                    'reasons': v.reasons}, ensure_ascii=False) + '\n')
    return results


def initialize(config='config.json'):
    cfg = load_config(config); lg = logger_for(cfg['log_file']); db = open_db(cfg)
    try:
        s, errors = _full_scan(cfg, db, lg); db.replace_baseline(s); db.replace_current(s)
        lg.info('Baseline initialized: %d file(s) in %d watch path(s)', len(s), len(cfg['watch_paths']))
        return len(s), errors
    finally: db.close()


def scan_baseline(config='config.json', record=False):
    """So sánh trạng thái đĩa hiện tại với baseline (full hash)."""
    cfg = load_config(config); db = open_db(cfg); lg = logger_for(cfg['log_file']) if record else None
    try:
        _require_baseline(db)
        cur, errors = _full_scan(cfg, db)
        base = _drop_ignored(db.load_baseline(), cfg, db.ignore_patterns())
        results = evaluate(cfg, db, compare_states(base, cur), 'scan', lg, record)
        db.set_meta('last_scan_at', now_iso())
        return cfg, results, errors
    finally: db.close()


def process_once(cfg, db, lg, full=False):
    ignore = db.ignore_patterns(); stored = db.load_current()
    prev = _drop_ignored(stored, cfg, ignore)
    cur, errors = scan_tree(roots(cfg), ignore, prev=None if full else prev)
    results = evaluate(cfg, db, compare_states(prev, cur), 'monitor', lg)
    db.update_current(cur, stored); db.set_meta('last_scan_at', now_iso())
    return results


def scan_due(now, dirty, first, last, debounce, max_wait):
    """Đã đến lúc quét chưa: các sự kiện đã lắng xuống đủ `debounce` giây, hoặc sự kiện đầu tiên đã chờ quá
    `max_wait` giây. Điều kiện thứ hai tránh trường hợp một file bị ghi liên tục (log) làm monitor không bao giờ quét."""
    return dirty and (now - last >= debounce or now - first >= max_wait)


def _process_safely(cfg, db, lg, full=False):
    """Một lần quét lỗi (vd. CSDL đang bị khóa) không được làm dừng monitor."""
    try:
        process_once(cfg, db, lg, full=full)
    except Exception:
        lg.exception('Quét thất bại, sẽ thử lại ở lần sau')


def monitor(config='config.json'):
    cfg = load_config(config); lg = logger_for(cfg['log_file']); db = open_db(cfg)
    try:
        if not db.get_meta('baseline_at'):
            s, _ = _full_scan(cfg, db, lg); db.replace_baseline(s); db.replace_current(s)
            lg.info('No baseline found - created baseline with %d file(s)', len(s))
        elif not db.load_current():
            db.replace_current(db.load_baseline())
        watch = [r for r in roots(cfg) if Path(r).is_dir()]
        for r in set(roots(cfg)) - set(watch): lg.warning('Watch path missing: %s', r)
        full_every = float(cfg.get('full_scan_interval_seconds', 600))
        # Bỏ qua sự kiện do chính FIM ghi DB/log (tránh vòng lặp nếu DB/log nằm trong thư mục giám sát).
        # Chỉ so khớp đúng các file này (+ hậu tố -wal/-shm/.1...), không bỏ qua cả thư mục chứa chúng.
        log = Path(cfg['log_file'])
        skip = (cfg['database'], log.as_posix(), log.with_name('alerts.log').as_posix())
        try:
            if cfg.get('force_polling'): raise ImportError   # dùng để đo/so sánh với polling
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer
        except ImportError:
            Observer = None
        if Observer:
            class H(FileSystemEventHandler):
                def __init__(self): self.dirty = True; self.first = self.last = 0.0
                def on_any_event(self, event):
                    if event.event_type in IGNORED_WATCHDOG_EVENTS: return
                    if str(event.src_path).replace('\\', '/').startswith(skip): return
                    now = time.time()
                    if not self.dirty: self.first = now      # sự kiện đầu tiên kể từ lần quét trước
                    self.dirty = True; self.last = now
            h = H(); obs = Observer()
            for r in watch: obs.schedule(h, r, recursive=True)
            obs.start(); lg.info('Monitoring (watchdog) %d path(s): %s', len(watch), ', '.join(map(short, watch)))
            debounce = float(cfg.get('debounce_seconds', 0.5)); last_full = time.time()
            max_wait = float(cfg.get('max_event_delay_seconds', 2.0))
            try:
                while True:
                    time.sleep(0.2); now = time.time()
                    # Hạ cờ dirty TRƯỚC khi quét: sự kiện xảy ra trong lúc quét sẽ được xử lý ở vòng sau
                    if now - last_full >= full_every:
                        h.dirty = False; _process_safely(cfg, db, lg, full=True); last_full = time.time()
                    elif scan_due(now, h.dirty, h.first, h.last, debounce, max_wait):
                        h.dirty = False; _process_safely(cfg, db, lg)
            except KeyboardInterrupt: lg.info('Monitoring stopped.')
            finally: obs.stop(); obs.join()
        else:
            delay = float(cfg.get('poll_interval_seconds', 1.0)); last_full = 0.0
            lg.warning('%s; polling mỗi %.1fs', 'force_polling=true' if cfg.get('force_polling') else 'watchdog chưa được cài', delay)
            try:
                while True:
                    full = time.time() - last_full >= full_every
                    _process_safely(cfg, db, lg, full=full)
                    if full: last_full = time.time()
                    time.sleep(delay)
            except KeyboardInterrupt: lg.info('Monitoring stopped.')
    finally: db.close()


def accept(config='config.json', path=None):
    """Chấp nhận thay đổi vào baseline: toàn bộ (path=None), một file, hoặc danh sách file
    (vd. cảnh báo MOVED: chấp nhận đường dẫn mới và xóa đường dẫn cũ khỏi baseline)."""
    cfg = load_config(config); lg = logger_for(cfg['log_file']); db = open_db(cfg)
    try:
        _require_baseline(db)
        if path is None:
            s, _ = _full_scan(cfg, db, lg); db.replace_baseline(s); db.replace_current(s)
            lg.info('Accepted current state as new baseline: %d file(s)', len(s)); return len(s)
        paths = [path] if isinstance(path, (str, os.PathLike)) else list(path)
        known = set(db.load_baseline()) | set(db.load_current())
        for one in paths:
            key = Path(one).expanduser().resolve().as_posix()
            if key not in known and not any(key.startswith(r.rstrip('/') + '/') for r in roots(cfg)):
                raise FimError(f'{key} không nằm trong thư mục giám sát nào.')
            p = Path(key)
            if p.is_file():
                st = p.stat()
                db.set_baseline_file(key, FileState(key, sha256_file(p), st.st_size, st.st_mtime_ns, st.st_mode & 0o7777,
                                                    st.st_uid, st.st_gid))
                lg.info('Accepted into baseline: %s', short(key))
            else:
                db.set_baseline_file(key, None); lg.info('Removed from baseline (file no longer exists): %s', short(key))
        return len(paths)
    finally: db.close()
