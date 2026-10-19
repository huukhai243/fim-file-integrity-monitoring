from __future__ import annotations
import os, sqlite3
from datetime import datetime, timezone
from pathlib import Path
from .core import FileState, Change

STATE_COLS = 'path,sha256,size,mtime_ns,mode,uid,gid'
SCHEMA = """
CREATE TABLE IF NOT EXISTS baseline(path TEXT PRIMARY KEY, sha256 TEXT, size INTEGER, mtime_ns INTEGER, mode INTEGER,
    uid INTEGER, gid INTEGER);
CREATE TABLE IF NOT EXISTS current_state(path TEXT PRIMARY KEY, sha256 TEXT, size INTEGER, mtime_ns INTEGER, mode INTEGER,
    uid INTEGER, gid INTEGER);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, path TEXT, event_type TEXT,
    risk_score INTEGER, risk_level TEXT, details TEXT, verdict TEXT, source TEXT, old_path TEXT);
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER REFERENCES events(id),
    timestamp TEXT, path TEXT, severity TEXT, message TEXT, status TEXT DEFAULT 'NEW', acked_at TEXT);
CREATE TABLE IF NOT EXISTS whitelist(id INTEGER PRIMARY KEY AUTOINCREMENT, pattern TEXT NOT NULL, kind TEXT NOT NULL,
    events TEXT DEFAULT '*', note TEXT, created_at TEXT, UNIQUE(pattern, kind));
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
"""


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')


class FimDB:
    def __init__(self, db_path):
        p = Path(db_path); p.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(p, timeout=10, check_same_thread=False); self.conn.row_factory = sqlite3.Row
        self.conn.execute('PRAGMA journal_mode=WAL')   # dashboard đọc song song khi monitor đang ghi
        self.conn.executescript(SCHEMA); self._migrate(); self.conn.commit()
        if os.name == 'posix':                         # baseline chỉ chủ sở hữu được đọc/ghi
            try: os.chmod(p, 0o600)
            except OSError: pass

    def _migrate(self):
        """Thêm cột mới cho DB tạo từ phiên bản cũ."""
        cols = {r['name'] for r in self.conn.execute('PRAGMA table_info(events)')}
        for c in ('verdict', 'source', 'old_path'):
            if c not in cols: self.conn.execute(f'ALTER TABLE events ADD COLUMN {c} TEXT')
        for table in ('baseline', 'current_state'):
            cols = {r['name'] for r in self.conn.execute(f'PRAGMA table_info({table})')}
            for c in ('uid', 'gid'):
                if c not in cols: self.conn.execute(f'ALTER TABLE {table} ADD COLUMN {c} INTEGER')

    def close(self): self.conn.close()

    # ---- baseline / current state ----
    @staticmethod
    def _row(s: FileState): return (s.path, s.sha256, s.size, s.mtime_ns, s.mode, s.uid, s.gid)

    def _replace(self, table, states):
        c = self.conn.cursor(); c.execute(f'DELETE FROM {table}')
        c.executemany(f'INSERT INTO {table}({STATE_COLS}) VALUES(?,?,?,?,?,?,?)', [self._row(s) for s in states.values()])
        self.conn.commit()

    def replace_baseline(self, s):   # baseline luôn được tạo từ một lần quét đầy đủ
        self._replace('baseline', s); ts = now_iso(); self.set_meta('baseline_at', ts); self.set_meta('last_scan_at', ts)
    def replace_current(self, s): self._replace('current_state', s)

    def update_current(self, states, stored):
        """Chỉ ghi các dòng khác với trạng thái đã lưu `stored`. Monitor gọi hàm này sau mỗi lần quét
        (polling: mỗi giây), nên không xóa và ghi lại cả bảng khi không có gì thay đổi."""
        gone = [(p,) for p in stored.keys() - states.keys()]
        dirty = [self._row(s) for p, s in states.items() if stored.get(p) != s]
        if not gone and not dirty: return 0
        c = self.conn.cursor(); c.executemany('DELETE FROM current_state WHERE path=?', gone)
        c.executemany(f'INSERT OR REPLACE INTO current_state({STATE_COLS}) VALUES(?,?,?,?,?,?,?)', dirty)
        self.conn.commit(); return len(gone) + len(dirty)

    def _load(self, table):
        rows = self.conn.execute(f'SELECT {STATE_COLS} FROM {table}').fetchall()
        return {r['path']: FileState(*r) for r in rows}

    def load_baseline(self): return self._load('baseline')
    def load_current(self): return self._load('current_state')

    def set_baseline_file(self, path, state: FileState | None):
        self.conn.execute('DELETE FROM baseline WHERE path=?', (path,))
        if state:
            self.conn.execute(f'INSERT INTO baseline({STATE_COLS}) VALUES(?,?,?,?,?,?,?)', self._row(state))
        self.conn.commit()

    # ---- meta ----
    def set_meta(self, key, value):
        self.conn.execute('INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)', (key, str(value))); self.conn.commit()

    def get_meta(self, key, default=None):
        r = self.conn.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
        return r['value'] if r else default

    # ---- events & alerts ----
    def record(self, ch: Change, v, source='monitor'):
        """Ghi sự kiện; nếu SUSPICIOUS thì tạo alert. Trả về (event_id, alert_id|None)."""
        ts = now_iso(); old_path = ch.old.path if ch.old and ch.old.path != ch.path else None
        cur = self.conn.execute(
            'INSERT INTO events(timestamp,path,event_type,risk_score,risk_level,details,verdict,source,old_path) '
            'VALUES(?,?,?,?,?,?,?,?,?)',
            (ts, ch.path, ch.event_type, v.score, v.level, v.details, v.verdict, source, old_path))
        event_id = cur.lastrowid; alert_id = None
        if v.verdict == 'SUSPICIOUS':
            msg = f'{ch.event_type} {ch.path}' + (f' (from {old_path})' if old_path else '') + f' - {v.details}'
            alert_id = self.conn.execute('INSERT INTO alerts(event_id,timestamp,path,severity,message) VALUES(?,?,?,?,?)',
                                         (event_id, ts, ch.path, v.level, msg)).lastrowid
        self.conn.commit()
        return event_id, alert_id

    @staticmethod
    def _event_filter(level=None, verdict=None, event_type=None, q=None, source=None):
        where, args = [], []
        if level: where.append('risk_level=?'); args.append(level)
        if verdict: where.append('verdict=?'); args.append(verdict)
        if event_type: where.append('event_type LIKE ?'); args.append(f'%{event_type}%')
        if source: where.append('source=?'); args.append(source)
        if q: where.append('(path LIKE ? OR details LIKE ?)'); args += [f'%{q}%', f'%{q}%']
        return (' WHERE ' + ' AND '.join(where) if where else ''), args

    def events(self, limit=20, offset=0, **filters):
        w, args = self._event_filter(**filters)
        return self.conn.execute(f'SELECT * FROM events{w} ORDER BY id DESC LIMIT ? OFFSET ?', args + [limit, offset]).fetchall()

    def count_events(self, **filters):
        w, args = self._event_filter(**filters)
        return self.conn.execute(f'SELECT COUNT(*) FROM events{w}', args).fetchone()[0]

    def alerts(self, status=None, limit=100):
        if status:
            return self.conn.execute('SELECT * FROM alerts WHERE status=? ORDER BY id DESC LIMIT ?', (status, limit)).fetchall()
        return self.conn.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT ?', (limit,)).fetchall()

    def ack_alert(self, alert_id):
        n = self.conn.execute("UPDATE alerts SET status='ACK', acked_at=? WHERE id=? AND status='NEW'",
                              (now_iso(), alert_id)).rowcount
        self.conn.commit(); return n

    def ack_all(self):
        n = self.conn.execute("UPDATE alerts SET status='ACK', acked_at=? WHERE status='NEW'", (now_iso(),)).rowcount
        self.conn.commit(); return n

    # ---- whitelist ----
    def seed_whitelist(self, cfg):
        """Nạp whitelist mặc định từ config vào DB (chỉ lần đầu)."""
        if self.get_meta('whitelist_seeded'): return
        for pat in cfg.get('whitelist', []): self.whitelist_add(pat, 'ignore', note='from config')
        for r in cfg.get('allowed_changes', []):
            self.whitelist_add(r['pattern'], 'allow', r.get('events', '*'), r.get('note', 'from config'))
        self.set_meta('whitelist_seeded', '1')

    def whitelist(self, kind=None):
        if kind: return self.conn.execute('SELECT * FROM whitelist WHERE kind=? ORDER BY id', (kind,)).fetchall()
        return self.conn.execute('SELECT * FROM whitelist ORDER BY kind, id').fetchall()

    def whitelist_add(self, pattern, kind='ignore', events='*', note=''):
        if kind not in ('ignore', 'allow'): raise ValueError('kind must be ignore or allow')
        cur = self.conn.execute('INSERT OR IGNORE INTO whitelist(pattern,kind,events,note,created_at) VALUES(?,?,?,?,?)',
                                (pattern.strip(), kind, (events or '*').upper().replace(' ', ''), note, now_iso()))
        self.conn.commit(); return cur.rowcount

    def whitelist_remove(self, wid):
        n = self.conn.execute('DELETE FROM whitelist WHERE id=?', (wid,)).rowcount; self.conn.commit(); return n

    def ignore_patterns(self): return [r['pattern'] for r in self.whitelist('ignore')]
    def allow_rules(self): return [dict(r) for r in self.whitelist('allow')]

    # ---- thống kê cho dashboard ----
    def stats(self, days=14):
        one = lambda sql, *a: self.conn.execute(sql, a).fetchone()[0]
        by = lambda col: {r[0]: r[1] for r in self.conn.execute(f'SELECT {col}, COUNT(*) FROM events GROUP BY {col}')}
        per_day = self.conn.execute(
            "SELECT substr(timestamp,1,10) d, COUNT(*) total, SUM(verdict='SUSPICIOUS') susp FROM events "
            "GROUP BY d ORDER BY d DESC LIMIT ?", (days,)).fetchall()
        top = self.conn.execute(
            "SELECT path, COUNT(*) n, MAX(risk_score) max_score FROM events GROUP BY path ORDER BY n DESC LIMIT 8").fetchall()
        return {
            'total_events': one('SELECT COUNT(*) FROM events'),
            'new_alerts': one("SELECT COUNT(*) FROM alerts WHERE status='NEW'"),
            'total_alerts': one('SELECT COUNT(*) FROM alerts'),
            'baseline_files': one('SELECT COUNT(*) FROM baseline'),
            'by_level': by('risk_level'), 'by_verdict': by('verdict'), 'by_type': by('event_type'),
            'per_day': list(reversed(per_day)), 'top_paths': top,
            'baseline_at': self.get_meta('baseline_at'), 'last_scan_at': self.get_meta('last_scan_at'),
        }
