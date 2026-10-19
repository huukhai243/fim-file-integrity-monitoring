"""Web dashboard: lịch sử thay đổi, alert, whitelist, phạm vi giám sát."""
from __future__ import annotations
import os, secrets
from pathlib import Path
from flask import Flask, g, render_template, request, redirect, url_for, flash, session
from .config import load_config, FimError, short
from .service import open_db, accept

PAGE_SIZE = 50


def create_app(config='config.json') -> Flask:
    cfg = load_config(config)
    app = Flask(__name__)
    # ký cookie phiên (flash message, CSRF token); sinh ngẫu nhiên mỗi lần chạy, có thể đặt cố định qua biến môi trường
    app.secret_key = os.environ.get('FIM_SECRET_KEY') or os.urandom(24)
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict')

    def db():
        if 'db' not in g: g.db = open_db(cfg)
        return g.db

    def back(default='alerts'):
        """Quay lại trang trước, chỉ khi trang đó thuộc chính dashboard."""
        ref = request.referrer or ''
        return redirect(ref if ref.startswith(request.host_url) else url_for(default))

    # Chống CSRF: một trang web lạ mở trong cùng trình duyệt không thể gửi lệnh POST (chấp nhận baseline,
    # thêm whitelist...) tới dashboard, vì không biết token lưu trong phiên.
    def csrf_token():
        if 'csrf' not in session: session['csrf'] = secrets.token_hex(16)
        return session['csrf']

    app.jinja_env.globals['csrf_token'] = csrf_token

    @app.before_request
    def _check_csrf():
        if request.method == 'POST':
            token = session.get('csrf')
            if not token or not secrets.compare_digest(token, request.form.get('csrf', '')):
                flash('Phiên làm việc không hợp lệ hoặc đã hết hạn, thao tác chưa được thực hiện. Hãy thử lại.', 'error')
                return redirect(url_for('overview'))

    @app.teardown_appcontext
    def _close(_exc):
        d = g.pop('db', None)
        if d: d.close()

    @app.context_processor
    def _inject():
        if request.endpoint == 'static': return {}
        return {'new_alerts': db().conn.execute("SELECT COUNT(*) FROM alerts WHERE status='NEW'").fetchone()[0]}

    @app.route('/')
    def overview():
        st = db().stats()
        return render_template('overview.html', st=st, alerts=db().alerts('NEW', 8), cfg=cfg,
                               max_day=max([r['total'] for r in st['per_day']] or [1]))

    @app.route('/events')
    def events():
        f = {k: request.args.get(k) or None for k in ('level', 'verdict', 'event_type', 'q', 'source')}
        page = max(1, request.args.get('page', 1, type=int))
        total = db().count_events(**f)
        rows = db().events(PAGE_SIZE, (page - 1) * PAGE_SIZE, **f)
        return render_template('events.html', rows=rows, f=f, qs={k: v for k, v in f.items() if v}, page=page, total=total,
                               pages=max(1, -(-total // PAGE_SIZE)))

    @app.route('/alerts')
    def alerts():
        status = request.args.get('status', 'NEW')
        return render_template('alerts.html', rows=db().alerts(None if status == 'ALL' else status, 200), status=status)

    @app.post('/alerts/<int:aid>/ack')
    def ack(aid):
        db().ack_alert(aid); flash(f'Alert #{aid} đã được xác nhận.')
        return back()

    @app.post('/alerts/ack-all')
    def ack_all():
        flash(f'Đã xác nhận {db().ack_all()} alert.'); return redirect(url_for('alerts'))

    @app.post('/alerts/<int:aid>/accept')
    def accept_alert(aid):
        row = db().conn.execute('SELECT a.path, e.old_path FROM alerts a LEFT JOIN events e ON e.id = a.event_id '
                                'WHERE a.id=?', (aid,)).fetchone()
        if row:
            # MOVED: chấp nhận đường dẫn mới và đồng thời bỏ đường dẫn cũ khỏi baseline
            paths = [row['path']] + ([row['old_path']] if row['old_path'] else [])
            try:
                accept(cfg['_config_path'], paths); db().ack_alert(aid)
                flash(f'Đã chấp nhận {short(row["path"])} vào baseline và xác nhận alert #{aid}.')
            except FimError as e: flash(str(e), 'error')
        return back()

    @app.route('/whitelist')
    def whitelist():
        return render_template('whitelist.html', rows=db().whitelist())

    @app.post('/whitelist/add')
    def whitelist_add():
        pat = request.form.get('pattern', '').strip()
        if not pat: flash('Pattern không được để trống.', 'error')
        elif request.form.get('kind', 'ignore') not in ('ignore', 'allow'): flash('Loại rule phải là ignore hoặc allow.', 'error')
        else:
            ok = db().whitelist_add(pat, request.form.get('kind', 'ignore'), request.form.get('events') or '*',
                                    request.form.get('note', ''))
            flash(f'Đã thêm "{pat}".' if ok else f'"{pat}" đã tồn tại.', None if ok else 'error')
        return redirect(url_for('whitelist'))

    @app.post('/whitelist/<int:wid>/delete')
    def whitelist_delete(wid):
        db().whitelist_remove(wid); flash(f'Đã xóa rule #{wid}.'); return redirect(url_for('whitelist'))

    @app.route('/scope')
    def scope():
        base = db().load_baseline(); items = []
        for w in cfg['watch_paths']:
            r = w['path'].rstrip('/') + '/'
            files = [s for k, s in base.items() if k.startswith(r)]
            items.append(dict(w, exists=Path(w['path']).is_dir(), files=len(files), size=sum(s.size for s in files)))
        return render_template('scope.html', items=items, st=db().stats(), cfg=cfg)

    @app.post('/baseline/accept')
    def baseline_accept():
        try: flash(f'Đã cập nhật baseline: {accept(cfg["_config_path"])} file.')
        except FimError as e: flash(str(e), 'error')
        return redirect(url_for('scope'))

    app.add_template_filter(short, 'short')

    @app.template_filter('size')
    def _size(n):
        for u in ('B', 'KB', 'MB', 'GB'):
            if n < 1024: return f'{n:.0f} {u}' if u == 'B' else f'{n:.1f} {u}'
            n /= 1024
        return f'{n:.1f} TB'

    return app
