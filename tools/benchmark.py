"""Kịch bản kiểm thử & đo đạc FIM, gồm các thí nghiệm trả lời câu hỏi nghiên cứu RQ1–RQ3 của đề tài.

  1. Hiệu năng quét: full scan / quick scan theo số lượng và dung lượng file
  2. Độ trễ phát hiện: watchdog (inotify trên Linux) so với polling
  3. Độ chính xác phân loại trên bộ kịch bản hợp lệ / tấn công (ma trận nhầm lẫn); so sánh với cách chỉ so mã băm
  4. RQ1: chỉ giám sát thời gian thực so với thời gian thực + quét toàn bộ định kỳ, với thay đổi "lén"
     (sửa nội dung nhưng giữ nguyên kích thước và trả lại thời gian sửa cũ)
  5. RQ2: M0 (mọi thay đổi phát hiện được đều là cảnh báo) so với M1 (M0 + whitelist + chấm điểm + accept):
     mức giảm số cảnh báo cần xem xét và số thay đổi nhạy cảm bị bỏ sót
  6. RQ3: CPU và RAM của tiến trình monitor ở 100 / 500 / 1.000 / 5.000 file (chỉ Linux, đọc /proc)

Chạy:  python tools/benchmark.py            (đầy đủ, khoảng 6–8 phút; nên chạy trong Docker để có đủ phần Linux)
       python tools/benchmark.py --quick    (nhanh, ít lần đo hơn)
"""
from __future__ import annotations
import argparse, contextlib, io, json, logging, os, platform, random, shutil, sqlite3, statistics, subprocess, sys, tempfile, time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from fim import service, __version__            # noqa: E402
from fim.core import scan_tree, compare_states   # noqa: E402

IS_LINUX = sys.platform.startswith('linux')
IS_ROOT = hasattr(os, 'geteuid') and os.geteuid() == 0


def quiet(fn, *args, **kw):
    """Gọi hàm của service mà không in log ra màn hình."""
    with contextlib.redirect_stderr(io.StringIO()):
        try: return fn(*args, **kw)
        finally: close_logs()


def close_logs():
    for h in logging.getLogger('fim').handlers: h.close()
    logging.getLogger('fim').handlers.clear()


def version_of(mod):
    try:
        from importlib.metadata import version
        return version(mod)
    except Exception:
        return '-'


def env_info():
    return {
        'Thời điểm đo': datetime.now().strftime('%Y-%m-%d %H:%M'),
        'Hệ điều hành': platform.platform(),
        'CPU': f'{platform.processor() or platform.machine()} ({os.cpu_count()} luồng)',
        'Python': platform.python_version(),
        'SQLite': sqlite3.sqlite_version,
        'watchdog': version_of('watchdog'),
        'Flask': version_of('flask'),
        'FIM': __version__,
    }


def make_env(tmp: Path, extra=None):
    """Cây thư mục mô phỏng etc, bin, var/log, home và config tương ứng."""
    w = tmp / 'w'
    for p, content in {'etc/app.conf': 'port=80\n', 'bin/tool.sh': '#!/bin/sh\necho hi\n',
                       'var/log/app.log': 'boot ok\n', 'home/user/notes.txt': 'hello\n'}.items():
        f = w / p; f.parent.mkdir(parents=True, exist_ok=True); f.write_text(content)
    cfg = {
        'watch_paths': [{'path': (w / 'etc').as_posix(), 'label': 'etc', 'critical': True},
                        {'path': (w / 'bin').as_posix(), 'label': 'bin', 'critical': True},
                        {'path': (w / 'var/log').as_posix(), 'label': 'log'},
                        {'path': (w / 'home').as_posix(), 'label': 'home'}],
        'database': (tmp / 'fim.db').as_posix(), 'log_file': (tmp / 'fim.log').as_posix(),
        'whitelist': ['*.tmp', '*.swp'],
        'allowed_changes': [{'pattern': '*.log', 'events': 'CREATED,MODIFIED'}],
        'sensitive_paths': ['*.conf', '*.sh'], 'executable_extensions': ['.sh'],
        'suspicious_threshold': 3, 'mass_change_threshold': 10,
        'work_hours': [0, 24],          # loại bỏ yếu tố giờ làm việc để kết quả lặp lại được
        'debounce_seconds': 0.5, 'poll_interval_seconds': 1.0, 'full_scan_interval_seconds': 3600,
    }
    cfg.update(extra or {})
    cfgp = tmp / 'config.json'; cfgp.write_text(json.dumps(cfg))
    return w, cfgp


def start_monitor(cfgp: Path, tmp: Path):
    proc = subprocess.Popen([sys.executable, str(ROOT / 'main.py'), '--config', str(cfgp), 'monitor'],
                            cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log = tmp / 'fim.log'; deadline = time.time() + 20
    while time.time() < deadline:
        if log.exists() and any(k in log.read_text('utf-8') for k in ('Monitoring', 'polling')): break
        time.sleep(0.1)
    return proc


def stop_monitor(proc):
    if not proc: return
    proc.terminate()
    try: proc.wait(10)
    except subprocess.TimeoutExpired: proc.kill()


def pct(xs, p):
    xs = sorted(xs); k = (len(xs) - 1) * p / 100; f = int(k)
    return xs[f] + (xs[min(f + 1, len(xs) - 1)] - xs[f]) * (k - f)


# ---------------------------------------------------------------- 1. hiệu năng quét
def bench_scan(cases):
    rows = []
    for n, size in cases:
        tmp = Path(tempfile.mkdtemp(prefix='fimbench_'))
        try:
            for i in range(n):
                d = tmp / f'd{i // 100:03d}'
                if i % 100 == 0: d.mkdir()
                (d / f'f{i:05d}.bin').write_bytes(os.urandom(size))
            t = time.perf_counter(); states, _ = scan_tree([tmp.as_posix()]); full = time.perf_counter() - t
            t = time.perf_counter(); scan_tree([tmp.as_posix()], prev=states); quick = time.perf_counter() - t
            mb = n * size / 1024 / 1024
            rows.append({'files': n, 'size': size, 'mb': mb, 'full': full, 'quick': quick, 'fps': n / full, 'mbps': mb / full})
            print(f'  scan {n:>6} x {size // 1024:>5} KB: full {full:.3f}s  quick {quick:.3f}s')
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return rows


# ---------------------------------------------------------------- 2. độ trễ phát hiện
def bench_latency(mode, trials):
    tmp = Path(tempfile.mkdtemp(prefix='fimlat_')); proc = None
    try:
        w, cfgp = make_env(tmp, {'force_polling': mode == 'polling'})
        quiet(service.initialize, str(cfgp))
        proc = start_monitor(cfgp, tmp); time.sleep(1.5)
        conn = sqlite3.connect(tmp / 'fim.db', timeout=10)
        last = lambda: conn.execute('SELECT COALESCE(MAX(id),0) FROM events').fetchone()[0]
        lat = []
        for i in range(trials):
            before = last(); t0 = time.perf_counter()
            with open(w / 'etc/app.conf', 'a') as f: f.write(f'k{i}=v\n')
            while time.perf_counter() - t0 < 10:
                if last() > before: lat.append(time.perf_counter() - t0); break
                time.sleep(0.01)
            time.sleep(random.uniform(0.6, 1.6))      # khoảng nghỉ ngẫu nhiên: tránh trùng pha với chu kỳ polling
        conn.close()
        print(f'  latency {mode:<8}: n={len(lat)}/{trials} avg {statistics.mean(lat):.3f}s' if lat else f'  latency {mode}: no events')
        return lat, trials
    finally:
        stop_monitor(proc); time.sleep(0.5); shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------- 3. độ chính xác phân loại
def _mass(w):
    for i in range(12): (w / f'home/user/doc{i}.txt.enc').write_text('x')


def _touch(path):
    time.sleep(0.05); os.utime(path, None)            # thời gian sửa tiến lên "bây giờ"


SCENARIOS = [
    # (mô tả, hành động, (loại sự kiện, kết luận) mong đợi hoặc None = không có sự kiện, yêu cầu: None | 'posix' | 'root')
    ('Tạo ghi chú mới trong home',             lambda w: (w / 'home/user/todo.txt').write_text('a'),            ('CREATED', 'LEGITIMATE'), None),
    ('Sửa ghi chú trong home',                 lambda w: (w / 'home/user/notes.txt').write_text('edited'),      ('MODIFIED', 'LEGITIMATE'), None),
    ('Ứng dụng ghi thêm log',                  lambda w: open(w / 'var/log/app.log', 'a').write('more\n'),      ('MODIFIED', 'LEGITIMATE'), None),
    ('Tạo file log mới (log rotation)',        lambda w: (w / 'var/log/app2.log').write_text('new'),           ('CREATED', 'LEGITIMATE'), None),
    ('Tạo file tạm *.tmp (whitelist ignore)',  lambda w: (w / 'home/user/x.tmp').write_text('t'),               None, None),
    ('touch: chỉ cập nhật thời gian sửa',      lambda w: _touch(w / 'etc/app.conf'),                            ('TIMESTAMP_CHANGED', 'LEGITIMATE'), None),
    ('Sửa file cấu hình trong etc',            lambda w: open(w / 'etc/app.conf', 'a').write('PermitRootLogin yes\n'), ('MODIFIED', 'SUSPICIOUS'), None),
    ('Tạo file cấu hình mới trong etc',        lambda w: (w / 'etc/evil.conf').write_text('x'),                 ('CREATED', 'SUSPICIOUS'), None),
    ('Thay thế chương trình trong bin',        lambda w: (w / 'bin/tool.sh').write_text('#!/bin/sh\nrm -rf /\n'), ('MODIFIED', 'SUSPICIOUS'), None),
    ('Xóa chương trình trong bin',             lambda w: (w / 'bin/tool.sh').unlink(),                          ('DELETED', 'SUSPICIOUS'), None),
    ('Tạo file ẩn (backdoor) trong home',      lambda w: (w / 'home/user/.backdoor').write_text('nc'),          ('CREATED', 'SUSPICIOUS'), None),
    ('Đổi tên file sang .locked (ransomware)', lambda w: (w / 'home/user/notes.txt').rename(w / 'home/user/notes.txt.locked'), ('MOVED', 'SUSPICIOUS'), None),
    ('Tạo 12 file .enc cùng lúc',              _mass,                                                          ('CREATED', 'SUSPICIOUS'), None),
    ('Xóa file log (xóa dấu vết)',             lambda w: (w / 'var/log/app.log').unlink(),                      ('DELETED', 'SUSPICIOUS'), None),
    ('Làm rỗng file log (xóa dấu vết)',        lambda w: (w / 'var/log/app.log').write_text(''),                ('MODIFIED', 'SUSPICIOUS'), None),
    ('Lùi thời gian sửa về 2020 (timestomp)',  lambda w: os.utime(w / 'etc/app.conf', (1577836800, 1577836800)), ('TIMESTAMP_CHANGED', 'SUSPICIOUS'), None),
    ('chmod 600 ghi chú (thu hẹp quyền)',      lambda w: os.chmod(w / 'home/user/notes.txt', 0o600),            ('PERMISSION_CHANGED', 'LEGITIMATE'), 'posix'),
    ('chmod +x file trong home',               lambda w: os.chmod(w / 'home/user/notes.txt', 0o755),            ('PERMISSION_CHANGED', 'SUSPICIOUS'), 'posix'),
    ('chmod u+s script trong bin (setuid)',    lambda w: os.chmod(w / 'bin/tool.sh', 0o4755),                   ('PERMISSION_CHANGED', 'SUSPICIOUS'), 'posix'),
    ('chown đổi chủ sở hữu file cấu hình',     lambda w: os.chown(w / 'etc/app.conf', 1000, 1000),              ('OWNER_CHANGED', 'SUSPICIOUS'), 'root'),
]


# Các loại thay đổi mà cách chỉ so mã băm (hash-only) cũng thấy: nội dung đổi, file xuất hiện hoặc mất đi
CONTENT_KINDS = {'CREATED', 'DELETED', 'MODIFIED', 'MOVED'}


def _runnable(req):
    return req is None or (req == 'posix' and os.name == 'posix') or (req == 'root' and IS_ROOT)


def bench_accuracy():
    rows = []
    for name, act, expected, req in SCENARIOS:
        if not _runnable(req):
            rows.append({'name': name, 'expected': expected, 'got': None, 'ok': None, 'req': req}); continue
        tmp = Path(tempfile.mkdtemp(prefix='fimacc_'))
        try:
            w, cfgp = make_env(tmp)
            if os.name == 'posix':
                for f in w.rglob('*'):
                    if f.is_file(): os.chmod(f, 0o644)
            quiet(service.initialize, str(cfgp))
            act(w)
            _, results, _ = quiet(service.scan_baseline, str(cfgp))
            got = sorted({(c.event_type, v.verdict) for c, v in results})
            ok = (not results) if expected is None else (bool(results) and all(t == expected for t in got))
            rows.append({'name': name, 'expected': expected, 'got': got, 'ok': ok, 'req': req,
                         'scores': sorted({v.score for _, v in results}),
                         'hash_only': any(k in CONTENT_KINDS for c, _ in results for k in c.event_type.split('+'))})
        finally:
            close_logs(); shutil.rmtree(tmp, ignore_errors=True)
        print(f"  {'PASS' if rows[-1]['ok'] else 'FAIL'}  {name}")
    return rows


# ---------------------------------------------------------------- 4. RQ1: thời gian thực và quét định kỳ
RQ1_GROUPS = ('CREATED', 'MODIFIED', 'DELETED', 'MOVED', 'STEALTH')


def bench_rq1(n=10, interval=4.0):
    """Mỗi cấu hình thực hiện liên tiếp n thao tác cho mỗi loại tạo, sửa, xóa, đổi tên, cùng n lần sửa "lén":
    ghi nội dung khác nhưng cùng kích thước rồi trả lại đúng thời gian sửa cũ."""
    rows = []
    for label, full_every in (('A. Chỉ thời gian thực', 3600.0), (f'B. Thời gian thực + quét toàn bộ mỗi {interval:g} s', interval)):
        tmp = Path(tempfile.mkdtemp(prefix='fimrq1_')); proc = None
        try:
            w, cfgp = make_env(tmp, {'full_scan_interval_seconds': full_every})
            d = w / 'home/user'
            for i in range(n):
                for pre in 'mdvs': (d / f'{pre}{i}.txt').write_text(f'{pre}{i}:' + 'A' * 60)   # nội dung khác nhau để ghép MOVED đúng
            quiet(service.initialize, str(cfgp))
            proc = start_monitor(cfgp, tmp); time.sleep(1.5)
            key = lambda name: (d / name).resolve().as_posix()
            expect = {}                                    # đường dẫn -> (nhóm thao tác, loại sự kiện phải thấy)
            t0 = time.time()
            for i in range(n):
                (d / f'c{i}.txt').write_text(f'new {i}'); expect[key(f'c{i}.txt')] = ('CREATED', 'CREATED')
                with open(d / f'm{i}.txt', 'a') as f: f.write('more')
                expect[key(f'm{i}.txt')] = ('MODIFIED', 'MODIFIED')
                (d / f'd{i}.txt').unlink(); expect[key(f'd{i}.txt')] = ('DELETED', 'DELETED')
                (d / f'v{i}.txt').rename(d / f'v{i}.bak'); expect[key(f'v{i}.bak')] = ('MOVED', 'MOVED')
                p = d / f's{i}.txt'; st = p.stat()
                p.write_text(f's{i}:' + 'B' * 60)                          # nội dung khác, cùng kích thước
                os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))          # trả lại đúng thời gian sửa cũ
                expect[key(f's{i}.txt')] = ('STEALTH', 'MODIFIED')
            found = {}; conn = sqlite3.connect(tmp / 'fim.db', timeout=10)
            while time.time() < t0 + 2 * interval + 4 and len(found) < len(expect):
                for path, et in conn.execute('SELECT path, event_type FROM events'):
                    if path in expect and et.split('+')[0] == expect[path][1]: found.setdefault(path, time.time() - t0)
                time.sleep(0.1)
            conn.close()
            det = {g: sum(1 for p, (grp, _) in expect.items() if grp == g and p in found) for g in RQ1_GROUPS}
            normal = [t for p, t in found.items() if expect[p][0] != 'STEALTH']
            stealth = [t for p, t in found.items() if expect[p][0] == 'STEALTH']
            rows.append({'label': label, 'n': n, 'det': det, 'missed': len(expect) - len(found), 'total': len(expect),
                         'normal_lat': statistics.mean(normal) if normal else None,
                         'stealth_lat': statistics.mean(stealth) if stealth else None})
            print(f"  RQ1 {label}: " + ', '.join(f'{g} {det[g]}/{n}' for g in RQ1_GROUPS))
        finally:
            stop_monitor(proc); close_logs(); time.sleep(0.5); shutil.rmtree(tmp, ignore_errors=True)
    return rows


# ---------------------------------------------------------------- 5. RQ2: M0 so với M1
SIM_STEP = 600   # mỗi thao tác cách nhau 10 phút "giả lập" để mô phỏng một ngày làm việc


def _rq2_ops(w):
    """Khối lượng công việc gồm thao tác thường ngày, bảo trì có kế hoạch và tấn công.
    Mỗi phần tử: (mô tả, nhóm, hàm thực hiện, yêu cầu). Nhóm: routine (không cần cảnh báo),
    maintenance (thay đổi nhạy cảm hợp lệ, cần quản trị viên xem rồi accept), attack (bắt buộc phải cảnh báo)."""
    log, docs = w / 'var/log', w / 'home/user'
    def app(path, text):
        with open(path, 'a') as f: f.write(text)
    ops = []
    for i in range(10): ops.append((f'Ứng dụng ghi log lần {i + 1}', 'routine', lambda i=i: app(log / 'app.log', f'req {i}\n'), None))
    ops += [('Tạo log mới access.log', 'routine', lambda: (log / 'access.log').write_text('GET /\n'), None),
            ('Tạo log mới error.log', 'routine', lambda: (log / 'error.log').write_text('none\n'), None)]
    for i in range(6): ops.append((f'Người dùng sửa tài liệu d{i}', 'routine', lambda i=i: app(docs / f'd{i}.txt', 'edit\n'), None))
    ops += [(f'Trình soạn thảo tạo file tạm {n}', 'routine', lambda n=n: (docs / n).write_text('~'), None)
            for n in ('d0.txt.swp', 'd1.txt.swp', 'build.tmp', 'cache.tmp')]
    ops += [('touch tài liệu d4', 'routine', lambda: None, None), ('touch tài liệu d5', 'routine', lambda: None, None),
            ('Người dùng tạo tài liệu mới', 'routine', lambda: (docs / 'report.txt').write_text('new\n'), None),
            ('Bảo trì: cập nhật etc/ntp.conf', 'maintenance', lambda: app(w / 'etc/ntp.conf', 'server time.vn\n'), None),
            ('Bảo trì: cập nhật bin/backup.sh', 'maintenance', lambda: app(w / 'bin/backup.sh', '# v2\n'), None),
            ('Tấn công: bật PermitRootLogin', 'attack', lambda: app(w / 'etc/app.conf', 'PermitRootLogin yes\n'), None),
            ('Tấn công: tạo etc/evil.conf', 'attack', lambda: (w / 'etc/evil.conf').write_text('x'), None),
            ('Tấn công: setuid bin/tool.sh', 'attack', lambda: os.chmod(w / 'bin/tool.sh', 0o4755), 'posix'),
            ('Tấn công: file ẩn .backdoor', 'attack', lambda: (docs / '.backdoor').write_text('nc'), None),
            ('Tấn công: đổi tên sang .locked', 'attack', lambda: (docs / 'notes.txt').rename(docs / 'notes.txt.locked'), None),
            ('Tấn công: mã hóa 12 file .enc', 'attack', lambda: _mass(w), None),
            ('Tấn công: làm rỗng app.log', 'attack', lambda: (log / 'app.log').write_text(''), None),
            ('Tấn công: lùi thời gian sửa etc/ntp.conf', 'attack', lambda: os.utime(w / 'etc/ntp.conf', (1577836800, 1577836800)), None),
            ('Tấn công: chown etc/app.conf', 'attack', lambda: os.chown(w / 'etc/app.conf', 1000, 1000), 'root')]
    return ops


def bench_rq2():
    tmp = Path(tempfile.mkdtemp(prefix='fimrq2_'))
    try:
        w, cfgp = make_env(tmp)
        (w / 'etc/ntp.conf').write_text('server pool.ntp.org\n'); (w / 'bin/backup.sh').write_text('#!/bin/sh\ntar czf b.tgz .\n')
        for i in range(6): (w / f'home/user/d{i}.txt').write_text(f'doc {i}\n')
        if os.name == 'posix':
            for f in w.rglob('*'):
                if f.is_file(): os.chmod(f, 0o644)
        quiet(service.initialize, str(cfgp))
        cfg = service.load_config(str(cfgp)); db = service.open_db(cfg)
        with contextlib.redirect_stderr(io.StringIO()): lg = service.logger_for(cfg['log_file'])
        roots = [x['path'] for x in cfg['watch_paths']]
        m0_base, _ = scan_tree(roots); m0_prev = m0_base           # M0: không whitelist, không chấm điểm
        t_sim = time.time(); rows = []
        for k, (label, group, fn, req) in enumerate(_rq2_ops(w)):
            if not _runnable(req): continue
            t_sim += SIM_STEP
            before = {p: s.mtime_ns for p, s in scan_tree(roots)[0].items()}
            fn()
            if label.startswith('touch'):
                os.utime(w / f"home/user/{label.split()[-1]}.txt", (t_sim, t_sim))
            else:   # gán thời điểm giả lập cho file vừa thay đổi (trừ thao tác cố ý lùi thời gian)
                for p, s in scan_tree(roots)[0].items():
                    if before.get(p) != s.mtime_ns and 'lùi thời gian' not in label: os.utime(p, (t_sim, t_sim))
            m0_cur, _ = scan_tree(roots); m0 = len(compare_states(m0_prev, m0_cur)); m0_prev = m0_cur
            with contextlib.redirect_stderr(io.StringIO()): res = service.process_once(cfg, db, lg)
            m1 = sum(v.verdict == 'SUSPICIOUS' for _, v in res)
            high = sum(v.verdict == 'SUSPICIOUS' and v.level == 'HIGH' for _, v in res)
            if group == 'maintenance':      # quản trị viên xem cảnh báo của thay đổi đã lên kế hoạch và chấp nhận
                quiet(service.accept, str(cfgp), [c.path for c, _ in res]); lg = quiet_logger(cfg)
            rows.append({'label': label, 'group': group, 'm0': m0, 'm1': m1, 'high': high})
        # Kiểm tra định kỳ cuối ngày: đối chiếu với baseline
        cur_all, _ = scan_tree(roots); m0_audit = len(compare_states(m0_base, cur_all))
        _, audit, _ = quiet(service.scan_baseline, str(cfgp))
        m1_audit = sum(v.verdict == 'SUSPICIOUS' for _, v in audit)
        accepted = sum(1 for r in rows if r['group'] == 'maintenance')
        db.close(); close_logs()
        tot = lambda key, grp=None: sum(r[key] for r in rows if grp is None or r['group'] == grp)
        missed = [r['label'] for r in rows if r['group'] != 'routine' and r['m1'] == 0]
        false_alert = [r['label'] for r in rows if r['group'] == 'routine' and r['m1'] > 0]
        summary = {'rows': rows, 'm0': tot('m0'), 'm1': tot('m1'), 'high': tot('high'), 'missed': missed, 'false_alert': false_alert,
                   'm0_audit': m0_audit, 'm1_audit': m1_audit, 'accepted': accepted,
                   'routine': (tot('m0', 'routine'), tot('m1', 'routine')),
                   'maintenance': (tot('m0', 'maintenance'), tot('m1', 'maintenance')),
                   'attack': (tot('m0', 'attack'), tot('m1', 'attack'))}
        print(f"  RQ2: M0 {summary['m0']} cảnh báo, M1 {summary['m1']}; bỏ sót {len(missed)}; audit M0 {m0_audit} / M1 {m1_audit}")
        return summary
    finally:
        close_logs(); shutil.rmtree(tmp, ignore_errors=True)


def quiet_logger(cfg):
    with contextlib.redirect_stderr(io.StringIO()): return service.logger_for(cfg['log_file'])


# ---------------------------------------------------------------- 6. RQ3: CPU và RAM của monitor
def proc_cpu_rss(pid):
    """(giây CPU đã dùng, RSS MB) của tiến trình, đọc từ /proc (Linux)."""
    with open(f'/proc/{pid}/stat') as f: rest = f.read().rsplit(')', 1)[1].split()
    cpu = (int(rest[11]) + int(rest[12])) / os.sysconf('SC_CLK_TCK')
    with open(f'/proc/{pid}/status') as f: rss = next(int(l.split()[1]) for l in f if l.startswith('VmRSS:')) / 1024
    return cpu, rss


def bench_rq3(levels, idle_s=10, edits=20):
    rows = []
    for n in levels:
        for mode in ('watchdog', 'polling'):
            tmp = Path(tempfile.mkdtemp(prefix='fimrq3_')); proc = None
            try:
                w, cfgp = make_env(tmp, {'force_polling': mode == 'polling'})
                data = w / 'home/data'
                for i in range(n):
                    d = data / f'd{i // 100:03d}'
                    if i % 100 == 0: d.mkdir(parents=True)
                    (d / f'f{i:05d}.txt').write_bytes(os.urandom(4096))
                quiet(service.initialize, str(cfgp))
                proc = start_monitor(cfgp, tmp); time.sleep(2.5)
                c0, r0 = proc_cpu_rss(proc.pid); time.sleep(idle_s); c1, r1 = proc_cpu_rss(proc.pid)
                conn = sqlite3.connect(tmp / 'fim.db', timeout=10)
                last = lambda: conn.execute('SELECT COALESCE(MAX(id),0) FROM events').fetchone()[0]
                peak = max(r0, r1); lat = []; t_load = time.time()
                for i in range(edits):
                    before = last(); t0 = time.perf_counter()
                    with open(data / f'd{i // 100:03d}' / f'f{i:05d}.txt', 'a') as f: f.write('x')
                    while time.perf_counter() - t0 < 8:
                        if last() > before: lat.append(time.perf_counter() - t0); break
                        time.sleep(0.02)
                    peak = max(peak, proc_cpu_rss(proc.pid)[1])
                    time.sleep(random.uniform(0.2, 0.8))       # nghỉ ngẫu nhiên: tránh trùng pha với chu kỳ polling
                c2, r2 = proc_cpu_rss(proc.pid); load_s = time.time() - t_load; conn.close()
                rows.append({'n': n, 'mode': mode, 'idle_cpu': (c1 - c0) / idle_s * 100, 'load_cpu': (c2 - c1) / load_s * 100,
                             'rss': max(peak, r2), 'lat': statistics.mean(lat) if lat else None, 'detected': len(lat), 'edits': edits})
                print(f"  RQ3 {n:>5} file {mode:<8}: CPU nghỉ {rows[-1]['idle_cpu']:.1f}%  CPU tải {rows[-1]['load_cpu']:.1f}%  RAM {rows[-1]['rss']:.0f} MB")
            finally:
                stop_monitor(proc); close_logs(); time.sleep(0.5); shutil.rmtree(tmp, ignore_errors=True)
    return rows


# ---------------------------------------------------------------- báo cáo
def report(env, scan, lat, acc, rq1, rq2, rq3, out: Path):
    L = ['# Kết quả kiểm thử & đo đạc FIM', '', '## Môi trường đo', '', '| Thông số | Giá trị |', '|---|---|']
    L += [f'| {k} | {v} |' for k, v in env.items()]

    L += ['', '## 1. Hiệu năng quét', '',
          'Full scan = đọc và tính SHA-256 toàn bộ file (dùng cho `init`, `scan`, `accept`). '
          'Quick scan = chỉ hash lại file có size/mtime thay đổi (dùng khi `monitor` nhận sự kiện). '
          'Đo khi file đã nằm trong page cache của hệ điều hành. Với file nhỏ, chi phí mở file chiếm phần lớn '
          '(trên Windows còn bị phần mềm diệt virus quét khi mở file), nên tốc độ tính theo file/s quan trọng hơn MB/s.', '',
          '| Số file | Kích thước/file | Tổng dung lượng | Full scan (s) | Tốc độ (file/s) | Thông lượng (MB/s) | Quick scan (s) | Quick nhanh hơn |',
          '|---:|---:|---:|---:|---:|---:|---:|---:|']
    for r in scan:
        size = f"{r['size'] // 1024} KB" if r['size'] < 1024 * 1024 else f"{r['size'] // 1024 // 1024} MB"
        L.append(f"| {r['files']:,} | {size} | {r['mb']:.1f} MB | {r['full']:.3f} | {r['fps']:,.0f} | {r['mbps']:.1f} | "
                 f"{r['quick']:.3f} | {r['full'] / max(r['quick'], 1e-9):.1f}x |")

    L += ['', '## 2. Độ trễ phát hiện', '',
          'Từ lúc ghi vào `etc/app.conf` đến lúc sự kiện xuất hiện trong bảng `events`. '
          '`debounce_seconds = 0.5`, `poll_interval_seconds = 1.0`.', '',
          '| Cơ chế | Số lần đo | Phát hiện | Min (s) | Trung bình (s) | Trung vị (s) | P95 (s) | Max (s) |',
          '|---|---:|---:|---:|---:|---:|---:|---:|']
    for mode, (xs, n) in lat.items():
        L.append(f'| {mode} | {n} | {len(xs)}/{n} | {min(xs):.3f} | {statistics.mean(xs):.3f} | {statistics.median(xs):.3f} | '
                 f'{pct(xs, 95):.3f} | {max(xs):.3f} |' if xs else f'| {mode} | {n} | 0/{n} | - | - | - | - | - |')

    L += ['', '## 3. Độ chính xác phân loại', '',
          'Mỗi kịch bản chạy trên môi trường sạch: tạo baseline → thực hiện hành động → `scan`. '
          '`work_hours = [0, 24]` để loại yếu tố giờ làm việc.', '',
          '| # | Kịch bản | Mong đợi | Thực tế | Điểm | Kết quả |', '|---:|---|---|---|---:|:---:|']
    for i, r in enumerate(acc, 1):
        exp = 'không có sự kiện' if r['expected'] is None else f"{r['expected'][0]} / {r['expected'][1]}"
        if r['ok'] is None:
            need = 'cần quyền root' if r['req'] == 'root' else 'chỉ chạy trên Linux'
            L.append(f"| {i} | {r['name']} | {exp} | *{need}* | - | N/A |"); continue
        got = ', '.join(f'{t} / {v}' for t, v in r['got']) or 'không có sự kiện'
        L.append(f"| {i} | {r['name']} | {exp} | {got} | {', '.join(map(str, r['scores'])) or '-'} | {'✅' if r['ok'] else '❌'} |")
    ran = [r for r in acc if r['ok'] is not None]
    attack = lambda r: r['expected'] is not None and r['expected'][1] == 'SUSPICIOUS'
    flagged = lambda r: any(v == 'SUSPICIOUS' for _, v in (r['got'] or []))
    tp = sum(attack(r) and flagged(r) for r in ran); fn = sum(attack(r) and not flagged(r) for r in ran)
    fp = sum(not attack(r) and flagged(r) for r in ran); tn = sum(not attack(r) and not flagged(r) for r in ran)
    prec = tp / (tp + fp) if tp + fp else 0; rec = tp / (tp + fn) if tp + fn else 0
    skipped = len(acc) - len(ran)
    L += ['', f'**Ma trận nhầm lẫn** ({len(ran)} kịch bản đã chạy' + (f', bỏ qua {skipped} kịch bản cần Linux hoặc quyền root' if skipped else '') + '):', '',
          '| | Hệ thống báo SUSPICIOUS | Hệ thống báo LEGITIMATE / không báo |', '|---|---:|---:|',
          f'| **Thực tế là tấn công** | TP = {tp} | FN = {fn} |', f'| **Thực tế là hợp lệ** | FP = {fp} | TN = {tn} |', '',
          f'- Accuracy = {(tp + tn) / len(ran):.0%}  ·  Precision = {prec:.0%}  ·  Recall = {rec:.0%}',
          f'- Số kịch bản đúng hoàn toàn (đúng cả loại sự kiện và kết luận): {sum(r["ok"] for r in ran)}/{len(ran)}',
          '- Lưu ý: bộ kịch bản được thiết kế cùng với các luật heuristic, nên kết quả cho thấy các luật hoạt động đúng như thiết kế, '
          'không phản ánh khả năng phát hiện kỹ thuật tấn công mới chưa có luật.']

    attacks = [r for r in ran if attack(r)]
    L += ['', '### Chỉ so mã băm (hash-only) so với mã băm + metadata', '',
          'Hash-only chỉ so mã băm nội dung và sự có mặt của file; hệ thống hiện tại so thêm quyền, chủ sở hữu và thời gian sửa. '
          'Bảng chỉ liệt kê các kịch bản mà hai cách cho kết quả khác nhau.', '',
          '| Kịch bản | Thực tế | Hash-only | Hash + metadata |', '|---|---|---|---|']
    for r in ran:
        if r['expected'] is None or r['hash_only']: continue
        L.append(f"| {r['name']} | {'tấn công' if attack(r) else 'hợp lệ'} | không phát hiện | "
                 + ', '.join(f'{t} / {v}' for t, v in r['got']) + ' |')
    L += ['', f"- Kịch bản tấn công được phát hiện: hash-only {sum(r['hash_only'] for r in attacks)}/{len(attacks)}, "
          f"hash + metadata {sum(bool(r['got']) for r in attacks)}/{len(attacks)}."]

    L += ['', '## 4. RQ1: giám sát thời gian thực và quét toàn bộ định kỳ', '',
          f'Mỗi cấu hình thực hiện liên tiếp {rq1[0]["n"]} thao tác cho mỗi loại tạo, sửa, xóa, đổi tên, cùng {rq1[0]["n"]} lần sửa "lén" '
          '(ghi nội dung khác nhưng cùng kích thước, rồi trả lại đúng thời gian sửa cũ). '
          'Quick scan dựa vào kích thước và thời gian sửa để quyết định có băm lại file hay không.', '',
          '| Cấu hình | Tạo | Sửa | Xóa | Đổi tên | Sửa lén | Bỏ sót | Độ trễ TB (thường) | Độ trễ TB (lén) |',
          '|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    for r in rq1:
        f = lambda x: f'{x:.2f} s' if x is not None else '–'
        L.append(f"| {r['label']} | " + ' | '.join(f"{r['det'][g]}/{r['n']}" for g in RQ1_GROUPS)
                 + f" | {r['missed']}/{r['total']} | {f(r['normal_lat'])} | {f(r['stealth_lat'])} |")

    s = rq2
    red = (s['m0'] - s['m1']) / s['m0'] if s['m0'] else 0
    L += ['', '## 5. RQ2: M0 so với M1', '',
          'M0 = phát hiện thay đổi bằng hash + metadata, mọi thay đổi đều là cảnh báo. '
          'M1 = M0 + whitelist + chấm điểm rủi ro + quy trình accept. '
          f'Khối lượng công việc mô phỏng một ngày: {len(s["rows"])} thao tác (mỗi thao tác cách nhau 10 phút giả lập).', '',
          '| Nhóm thao tác | Số thao tác | Cảnh báo M0 | Cảnh báo M1 |', '|---|---:|---:|---:|']
    for grp, name in (('routine', 'Thường ngày (không cần cảnh báo)'), ('maintenance', 'Bảo trì có kế hoạch (cần xem, rồi accept)'),
                      ('attack', 'Tấn công (bắt buộc cảnh báo)')):
        cnt = sum(1 for r in s['rows'] if r['group'] == grp)
        L.append(f"| {name} | {cnt} | {s[grp][0]} | {s[grp][1]} |")
    L += [f"| **Tổng** | {len(s['rows'])} | **{s['m0']}** | **{s['m1']}** |", '',
          f"- Giảm số cảnh báo cần xem xét: **{red:.0%}** (từ {s['m0']} xuống {s['m1']}); "
          f"{s['high']}/{s['m1']} cảnh báo của M1 ở mức HIGH.",
          f"- Thay đổi nhạy cảm (bảo trì + tấn công) bị bỏ sót: **{len(s['missed'])}**" + (f" ({', '.join(s['missed'])})" if s['missed'] else '') + '.',
          f"- Thao tác thường ngày bị cảnh báo nhầm: **{len(s['false_alert'])}**" + (f" ({', '.join(s['false_alert'])})" if s['false_alert'] else '') + '.',
          f"- Kiểm tra định kỳ cuối ngày (đối chiếu baseline): M0 báo {s['m0_audit']} khác biệt, M1 báo {s['m1_audit']} cảnh báo; "
          f"{s['accepted']} thay đổi bảo trì đã được accept nên không bị báo lại.", '',
          '<details><summary>Chi tiết từng thao tác</summary>', '', '| # | Thao tác | Nhóm | M0 | M1 |', '|---:|---|---|---:|---:|']
    L += [f"| {i} | {r['label']} | {r['group']} | {r['m0']} | {r['m1']} |" for i, r in enumerate(s['rows'], 1)]
    L += ['', '</details>']

    L += ['', '## 6. RQ3: CPU và RAM của tiến trình monitor', '']
    if rq3:
        L += ['CPU tính theo % một nhân. "Nghỉ": không có thay đổi trong 10 giây. "Tải": sửa liên tiếp các file, '
              'chờ phát hiện từng thay đổi. RAM là RSS lớn nhất của tiến trình.', '',
              '| Số file | Cơ chế | CPU khi nghỉ | CPU khi có tải | RAM (MB) | Độ trễ TB | Phát hiện |', '|---:|---|---:|---:|---:|---:|---:|']
        for r in rq3:
            L.append(f"| {r['n']:,} | {r['mode']} | {r['idle_cpu']:.1f}% | {r['load_cpu']:.1f}% | {r['rss']:.0f} | "
                     f"{r['lat']:.2f} s | {r['detected']}/{r['edits']} |" if r['lat'] is not None else
                     f"| {r['n']:,} | {r['mode']} | {r['idle_cpu']:.1f}% | {r['load_cpu']:.1f}% | {r['rss']:.0f} | – | 0/{r['edits']} |")
    else:
        L.append('*Chỉ đo được trên Linux (đọc /proc). Xem kết quả đo trong Docker: `docs/benchmark_results_linux.md`.*')
    out.parent.mkdir(parents=True, exist_ok=True); out.write_text('\n'.join(L) + '\n', encoding='utf-8')
    return '\n'.join(L)


def main():
    ap = argparse.ArgumentParser(description='FIM benchmark')
    ap.add_argument('--quick', action='store_true', help='ít file và ít lần đo hơn')
    ap.add_argument('--out', default=str(ROOT / 'docs' / 'benchmark_results.md'))
    args = ap.parse_args()
    env = env_info()
    print('[1/6] Hiệu năng quét')
    scan = bench_scan([(100, 4096), (1000, 4096)] if args.quick else
                      [(100, 4096), (500, 4096), (1000, 4096), (5000, 4096), (10000, 4096), (20, 5 * 1024 * 1024)])
    print('[2/6] Độ trễ phát hiện')
    trials = 5 if args.quick else 20
    backend = {'linux': 'inotify', 'win32': 'ReadDirectoryChangesW', 'darwin': 'FSEvents'}.get(sys.platform, sys.platform)
    lat = {f'watchdog ({backend})': bench_latency('watchdog', trials), 'polling': bench_latency('polling', trials)}
    print('[3/6] Độ chính xác phân loại')
    acc = bench_accuracy()
    print('[4/6] RQ1: thời gian thực và quét định kỳ')
    rq1 = bench_rq1(n=5 if args.quick else 10)
    print('[5/6] RQ2: M0 so với M1')
    rq2 = bench_rq2()
    print('[6/6] RQ3: CPU và RAM')
    rq3 = bench_rq3([100, 1000] if args.quick else [100, 500, 1000, 5000],
                    idle_s=5 if args.quick else 10, edits=5 if args.quick else 20) if IS_LINUX else []
    report(env, scan, lat, acc, rq1, rq2, rq3, Path(args.out))
    print(f'\nĐã ghi kết quả: {args.out}')


if __name__ == '__main__':
    main()
