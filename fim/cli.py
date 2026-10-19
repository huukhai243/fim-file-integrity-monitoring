from __future__ import annotations
import argparse, sys
from pathlib import Path
from .config import load_config, FimError, short
from .service import initialize, scan_baseline, monitor, accept, open_db


def _utf8_console():
    """Console Windows (cp1252/cp437) hoặc khi chuyển hướng output ra file/pipe không mã hóa được tiếng Việt
    -> UnicodeEncodeError. Ép stdout/stderr dùng UTF-8."""
    for st in (sys.stdout, sys.stderr):
        try: st.reconfigure(encoding='utf-8', errors='replace')
        except (AttributeError, ValueError): pass


def show(results, errors=()):
    if not results: print('No changes detected.')
    else:
        print(f"{'VERDICT':<11} {'LEVEL':<7} {'SCORE':<5} {'EVENT':<28} PATH"); print('-' * 100)
        for ch, v in results:
            print(f'{v.verdict:<11} {v.level:<7} {v.score:<5} {ch.event_type:<28} {short(ch.path)}')
            if ch.event_type == 'MOVED': print(' ' * 25 + f'from: {short(ch.old.path)}')
            if v.reasons: print(' ' * 25 + 'reason: ' + v.details)
        n = sum(v.verdict == 'SUSPICIOUS' for _, v in results)
        print(f'\n{len(results)} change(s), {n} suspicious.')
    if errors: print(f'{len(errors)} path(s) skipped (missing or not readable). First: {errors[0]}')


def _db(args):
    cfg = load_config(args.config); return cfg, open_db(cfg)


def cmd_events(args):
    cfg, db = _db(args)
    try:
        rows = db.events(args.limit, level=args.level, verdict=args.verdict)
        if not rows: print('No events recorded.')
        for r in rows:
            print(f"#{r['id']} {r['timestamp']} [{r['verdict'] or '-'}|{r['risk_level']}/{r['risk_score']}] "
                  f"{r['event_type']} {short(r['path'])}")
            if r['old_path']: print('    from: ' + short(r['old_path']))
            if r['details']: print('    ' + r['details'])
    finally: db.close()


def cmd_alerts(args):
    cfg, db = _db(args)
    try:
        rows = db.alerts(None if args.all else 'NEW', args.limit)
        if not rows: print('No alerts.' if args.all else 'No new alerts.')
        for r in rows:
            print(f"#{r['id']} {r['timestamp']} [{r['severity']}] {r['status']:<4} {short(r['path'])}")
            print('    ' + r['message'].split(' - ', 1)[-1])
    finally: db.close()


def cmd_ack(args):
    cfg, db = _db(args)
    try:
        if args.all: print(f'Acknowledged {db.ack_all()} alert(s).')
        elif args.ids: print(f'Acknowledged {sum(db.ack_alert(i) for i in args.ids)} alert(s).')
        else: raise FimError('Use: python main.py ack ID [ID...]  hoặc  python main.py ack --all')
    finally: db.close()


def cmd_whitelist(args):
    cfg, db = _db(args)
    try:
        if args.action == 'add':
            ok = db.whitelist_add(args.pattern, args.kind, args.events, args.note or '')
            print('Added.' if ok else 'Pattern already exists.')
        elif args.action == 'remove':
            print('Removed.' if db.whitelist_remove(args.id) else f'No whitelist entry #{args.id}.')
        else:
            rows = db.whitelist()
            if not rows: print('Whitelist is empty.')
            print(f"{'ID':<4} {'KIND':<7} {'EVENTS':<18} {'PATTERN':<30} NOTE")
            for r in rows: print(f"{r['id']:<4} {r['kind']:<7} {r['events']:<18} {r['pattern']:<30} {r['note'] or ''}")
            print('\nignore = không theo dõi file;  allow = vẫn ghi nhận nhưng coi là thay đổi hợp lệ (không alert)')
    finally: db.close()


def cmd_scope(args):
    cfg, db = _db(args)
    try:
        base = db.load_baseline()
        print(f"{'CRITICAL':<9} {'FILES':<6} {'LABEL':<25} PATH")
        for w in cfg['watch_paths']:
            r = w['path'].rstrip('/') + '/'; n = sum(k.startswith(r) for k in base)
            miss = '' if Path(w['path']).is_dir() else '  (MISSING)'
            print(f"{'yes' if w.get('critical') else 'no':<9} {n:<6} {w.get('label', ''):<25} {short(w['path'])}{miss}")
        print(f"\nBaseline: {db.get_meta('baseline_at') or 'chưa có'} | Last scan: {db.get_meta('last_scan_at') or '-'}")
    finally: db.close()


def main():
    _utf8_console()
    p = argparse.ArgumentParser(description='Lightweight File Integrity Monitoring (FIM)')
    p.add_argument('--config', default='config.json')
    sub = p.add_subparsers(dest='cmd', required=True)
    sub.add_parser('init', help='tạo baseline')
    s = sub.add_parser('scan', help='so sánh với baseline'); s.add_argument('--record', action='store_true', help='ghi kết quả vào lịch sử/alert')
    sub.add_parser('monitor', help='giám sát thời gian thực')
    e = sub.add_parser('events', help='lịch sử thay đổi'); e.add_argument('--limit', type=int, default=20)
    e.add_argument('--level', choices=['LOW', 'MEDIUM', 'HIGH']); e.add_argument('--verdict', choices=['LEGITIMATE', 'SUSPICIOUS'])
    a = sub.add_parser('alerts', help='danh sách cảnh báo'); a.add_argument('--all', action='store_true'); a.add_argument('--limit', type=int, default=50)
    k = sub.add_parser('ack', help='đánh dấu đã xử lý alert'); k.add_argument('ids', nargs='*', type=int); k.add_argument('--all', action='store_true')
    ac = sub.add_parser('accept', help='chấp nhận thay đổi vào baseline'); g = ac.add_mutually_exclusive_group(required=True)
    g.add_argument('--all', action='store_true'); g.add_argument('--path')
    w = sub.add_parser('whitelist', help='quản lý whitelist'); ws = w.add_subparsers(dest='action')
    ws.add_parser('list'); wa = ws.add_parser('add'); wa.add_argument('pattern')
    wa.add_argument('--kind', choices=['ignore', 'allow'], default='ignore')
    wa.add_argument('--events', default='*', help='vd: MODIFIED,CREATED (chỉ dùng cho allow)'); wa.add_argument('--note')
    wr = ws.add_parser('remove'); wr.add_argument('id', type=int)
    sub.add_parser('scope', help='các thư mục đang giám sát')
    d = sub.add_parser('dashboard', help='web dashboard'); d.add_argument('--host', default='127.0.0.1'); d.add_argument('--port', type=int, default=5000)
    args = p.parse_args()

    try:
        if args.cmd == 'init':
            n, errors = initialize(args.config); print(f'Baseline created successfully for {n} file(s).')
            if errors: print(f'{len(errors)} path(s) skipped (see log).')
        elif args.cmd == 'scan':
            cfg, results, errors = scan_baseline(args.config, args.record); show(results, errors)
        elif args.cmd == 'monitor': monitor(args.config)
        elif args.cmd == 'events': cmd_events(args)
        elif args.cmd == 'alerts': cmd_alerts(args)
        elif args.cmd == 'ack': cmd_ack(args)
        elif args.cmd == 'accept':
            n = accept(args.config, None if args.all else args.path)
            print('Current state accepted as the new baseline.' if args.all else f'Baseline updated for {args.path}.')
        elif args.cmd == 'whitelist': cmd_whitelist(args)
        elif args.cmd == 'scope': cmd_scope(args)
        elif args.cmd == 'dashboard':
            from .dashboard import create_app
            print(f'Dashboard: http://{args.host}:{args.port}  (Ctrl+C để dừng)')
            create_app(args.config).run(host=args.host, port=args.port, debug=False)
    except FimError as ex:
        raise SystemExit(f'Error: {ex}')
