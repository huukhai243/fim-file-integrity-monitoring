"""Giao diện dòng lệnh của FIM.

Các lệnh:

    fim init                  Tạo CSDL và kiểm tra phạm vi giám sát
    fim baseline              Chốt baseline hash cho toàn bộ phạm vi
    fim scan                  Quét một lần, so với baseline
    fim watch                 Theo dõi liên tục (realtime hoặc polling)
    fim status                Xem tình trạng hệ thống
    fim events                Liệt kê lịch sử thay đổi
    fim explain <id>          Giải thích vì sao một sự kiện bị chấm điểm như vậy
    fim approve <id>...       Chấp nhận thay đổi, cập nhật vào baseline
    fim whitelist ...         Quản lý whitelist
    fim rules                 Liệt kê bộ luật heuristic
    fim serve                 Chạy dashboard web
"""

from __future__ import annotations

import argparse
import signal
import sys
import time
from pathlib import Path

from .analysis.heuristics import all_rules
from .config import load_config
from .engine import Engine
from .models import AlertStatus, ChangeType, Severity
from .scope.scope import Scope
from .scope.whitelist import entry_from_dict, export_to_yaml
from .util import enable_utf8_output, human_size, iso

# ---------------------------------------------------------------------------
# Hỗ trợ hiển thị
# ---------------------------------------------------------------------------

_SEVERITY_TINT = {
    "info": "\033[36m", "low": "\033[32m", "medium": "\033[33m",
    "high": "\033[31m", "critical": "\033[1;37;41m",
}
_RESET = "\033[0m"


def _tint(text: str, severity: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{_SEVERITY_TINT.get(severity, '')}{text}{_RESET}"


def _table(rows: list[list[str]], headers: list[str]) -> str:
    """Bảng văn bản đơn giản — tránh phụ thuộc rich cho các lệnh cơ bản."""
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    out = [line, "  ".join("-" * w for w in widths)]
    for row in rows:
        out.append("  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)))
    return "\n".join(out)


def _short(path: str, width: int = 58) -> str:
    return path if len(path) <= width else "…" + path[-(width - 1):]


# ---------------------------------------------------------------------------
# Các lệnh
# ---------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    scope = Scope(cfg.scope)

    print(f"Hồ sơ phạm vi : {scope.profile.name} — {scope.profile.description}")
    print(f"CSDL          : {cfg.db_path}")
    print()
    print(f"Thư mục gốc có mặt ({len(scope.roots)}):")
    for root in scope.roots:
        print(f"  ✓ {root}")
    if scope.missing_roots:
        print(f"\nKhông tồn tại trên máy này ({len(scope.missing_roots)}):")
        for root in scope.missing_roots:
            print(f"  ✗ {root}")

    if not scope.roots:
        print(
            "\nKhông có thư mục nào để giám sát.\n"
            "Thêm đường dẫn vào scope.include trong configs/default.yaml.",
            file=sys.stderr,
        )
        return 1

    with Engine(cfg) as engine:
        print(f"\nĐã tạo CSDL, whitelist đang có {len(engine.whitelist)} mục hiệu lực.")
    print("\nBước tiếp theo:  fim baseline")
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    with Engine(cfg) as engine:
        if not engine.scope.roots:
            print("Phạm vi rỗng. Chạy 'fim init' để kiểm tra cấu hình.", file=sys.stderr)
            return 1

        print(f"Đang chốt baseline cho {len(engine.scope.roots)} thư mục gốc…")
        last = [0.0]

        def progress(index: int, record: object) -> None:
            now = time.time()
            if now - last[0] >= 0.5:                  # cập nhật tối đa 2 lần/giây
                last[0] = now
                print(f"\r  đã băm {index} file…", end="", flush=True)

        result = engine.build_baseline(args.label, progress=progress)
        print("\r" + " " * 40 + "\r", end="")

        print(f"Baseline #{result.baseline_id} — {result.label}")
        print(f"  File          : {result.file_count:,}")
        print(f"  Tổng dung lượng: {human_size(result.total_bytes)}")
        print(f"  Thời gian     : {result.duration:.1f}s ({result.throughput:.0f} file/s)")
        if result.error_count:
            print(f"  Không đọc được: {result.error_count}")
            for path, err in result.errors[:5]:
                print(f"    - {_short(path)}: {err}")
            if result.error_count > 5:
                print(f"    … và {result.error_count - 5} file khác")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    with Engine(cfg) as engine:
        if engine.store.active_baseline_id() is None:
            print("Chưa có baseline. Chạy 'fim baseline' trước.", file=sys.stderr)
            return 1

        print("Đang quét…")
        started = time.time()
        stats = engine.scan_once()
        elapsed = time.time() - started

        print(f"\nHoàn tất trong {elapsed:.1f}s")
        print(f"  Thay đổi phát hiện: {stats.events_processed}")
        print(f"  Cảnh báo phát ra  : {stats.alerts_raised}")
        if stats.by_severity:
            print("  Theo mức:")
            for sev in ("critical", "high", "medium", "low", "info"):
                count = stats.by_severity.get(sev, 0)
                if count:
                    print(f"    {_tint(sev.ljust(9), sev)} {count}")
        if stats.events_processed and not args.quiet:
            print("\nXem chi tiết:  fim events")
    return 0 if stats.by_severity.get("critical", 0) == 0 else 2


def cmd_watch(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    with Engine(cfg) as engine:
        if engine.store.active_baseline_id() is None:
            print("Chưa có baseline. Chạy 'fim baseline' trước.", file=sys.stderr)
            return 1

        stop = {"flag": False}

        def handle_signal(signum: int, frame: object) -> None:
            stop["flag"] = True
            print("\nĐang dừng…")

        signal.signal(signal.SIGINT, handle_signal)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, handle_signal)

        watcher = engine.watch()
        mode = type(watcher).__name__.replace("Watcher", "").lower()
        print(f"Đang theo dõi ({mode}). Nhấn Ctrl+C để dừng.")
        print(f"  Thư mục gốc: {len(engine.scope.roots)}")
        print(f"  Whitelist  : {len(engine.whitelist)} mục")
        print()

        try:
            while not stop["flag"]:
                time.sleep(0.5)
        finally:
            engine.stop()

        print(f"Đã xử lý {engine.stats.events_processed} thay đổi, "
              f"phát {engine.stats.alerts_raised} cảnh báo.")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    with Engine(cfg) as engine:
        stats = engine.store.stats()
        baseline = stats["baseline"]

        print("=== FIM — tình trạng hệ thống ===\n")
        if baseline:
            print(f"Baseline #{baseline['id']} ({baseline['label']})")
            print(f"  Chốt lúc : {iso(baseline['created_at'])}")
            print(f"  File     : {baseline['file_count']:,}"
                  f"  ({human_size(baseline['total_bytes'])})")
        else:
            print("Baseline : chưa có — chạy 'fim baseline'")

        print(f"\nPhạm vi   : {engine.scope.profile.name}, "
              f"{len(engine.scope.roots)} thư mục gốc")
        print(f"Whitelist : {stats['whitelist_active']} mục hiệu lực")
        print(f"Sự kiện   : {stats['events_total']:,}")
        print(f"Cảnh báo chưa xử lý: {stats['alerts_open']}")

        by_sev = stats["by_severity"]
        if by_sev:
            print("\nSự kiện theo mức:")
            for sev in ("critical", "high", "medium", "low", "info"):
                if by_sev.get(sev):
                    print(f"  {_tint(sev.ljust(9), sev)} {by_sev[sev]:,}")

        last = stats["last_scan"]
        if last:
            status = last["status"]
            print(f"\nLần quét gần nhất: {iso(last['started_at'])} "
                  f"[{last['mode']}] — {status}")
            if last["finished_at"]:
                print(f"  {last['files_scanned']:,} file, "
                      f"{last['changes_found']} thay đổi")
    return 0


def cmd_events(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    with Engine(cfg) as engine:
        since = time.time() - args.hours * 3600 if args.hours else None
        events = engine.store.query_events(
            limit=args.limit, severity=args.severity,
            classification=args.classification, path_like=args.path,
            since=since, include_whitelisted=args.all,
        )
        if not events:
            print("Không có sự kiện nào khớp bộ lọc.")
            return 0

        rows = []
        for e in events:
            verdict = e["verdict"] or {}
            sev = verdict.get("severity", "-")
            rows.append([
                str(e["id"]),
                time.strftime("%m-%d %H:%M", time.localtime(e["ts"])),
                _tint(sev.ljust(8), sev),
                e["change"][:8],
                _short(e["path"], 50),
                str(verdict.get("score", "-")),
            ])
        print(_table(rows, ["ID", "Thời điểm", "Mức", "Loại", "Đường dẫn", "Điểm"]))
        print(f"\n{len(events)} sự kiện. Giải thích chi tiết: fim explain <ID>")
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    with Engine(cfg) as engine:
        event = engine.store.get_event(args.event_id)
        if event is None:
            print(f"Không tìm thấy sự kiện #{args.event_id}", file=sys.stderr)
            return 1

        verdict = engine.store.get_verdict(args.event_id)
        print(f"=== Sự kiện #{event.id} ===")
        print(f"Đường dẫn : {event.path}")
        print(f"Thay đổi  : {event.change.value}  (nguồn: {event.source})")
        print(f"Thời điểm : {iso(event.ts)}")

        if event.before and event.after:
            b, a = event.before, event.after
            print("\nTrước -> Sau:")
            if b.digest != a.digest:
                print(f"  hash  : {(b.digest or '-')[:20]}… -> {(a.digest or '-')[:20]}…")
            if b.size != a.size:
                print(f"  size  : {b.size:,} -> {a.size:,} byte")
            if b.mode != a.mode:
                print(f"  quyền : {b.permissions} -> {a.permissions}")
            if (b.uid, b.gid) != (a.uid, a.gid):
                print(f"  chủ sở hữu: {b.uid}:{b.gid} -> {a.uid}:{a.gid}")
            if abs(b.mtime - a.mtime) > 0.5:
                print(f"  mtime : {iso(b.mtime)} -> {iso(a.mtime)}")

        if verdict is None:
            print("\n(chưa phân loại)")
            return 0

        print(f"\nKết luận: {_tint(verdict.severity.value.upper(), verdict.severity.value)}"
              f" / {verdict.classification.value} — điểm {verdict.score}")
        if verdict.whitelisted:
            print(f"Được whitelist '{verdict.whitelist_id}' miễn trừ.")
        if verdict.hits:
            print("\nCác luật đã khớp:")
            for h in sorted(verdict.hits, key=lambda x: -abs(x.weight)):
                print(f"  [{h.rule_id}] {h.weight:+4d}  {h.title}")
                if h.detail:
                    print(f"           {h.detail}")
        else:
            print("\nKhông luật nào khớp.")
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    with Engine(cfg) as engine:
        count = engine.approve(args.event_ids)
        print(f"Đã cập nhật {count} mục vào baseline.")
        if count < len(args.event_ids):
            print(f"({len(args.event_ids) - count} ID không tìm thấy hoặc không áp dụng được)")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    rows = [
        [r.rule_id, f"{r.weight:+d}", r.title, (r.description or "").strip().split("\n")[0][:60]]
        for r in all_rules()
    ]
    print(_table(rows, ["ID", "Trọng số", "Tên luật", "Mô tả"]))
    print(f"\n{len(rows)} luật. Tắt bớt qua analysis.disabled_rules, "
          f"đổi trọng số qua analysis.rule_weights.")
    return 0


def cmd_whitelist(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    with Engine(cfg) as engine:
        if args.wl_action == "list":
            entries = engine.store.list_whitelist()
            if not entries:
                print("Whitelist trống.")
                return 0
            rows = [
                [
                    e.id,
                    "✓" if e.is_active() else "✗",
                    _short(e.path_glob or (e.digest or "")[:20], 38),
                    e.rule_id or "*",
                    str(e.hit_count),
                    e.reason[:40],
                ]
                for e in entries
            ]
            print(_table(rows, ["ID", "Bật", "Mẫu khớp", "Luật", "Lượt", "Lý do"]))
            unused = [e for e in entries if e.hit_count == 0]
            if unused:
                print(f"\n{len(unused)} mục chưa từng khớp — cân nhắc xoá: "
                      f"{', '.join(e.id for e in unused[:5])}")
            return 0

        if args.wl_action == "add":
            entry = entry_from_dict({
                "id": args.id,
                "match": {
                    k: v for k, v in (
                        ("path_glob", args.path), ("digest", args.digest),
                        ("rule_id", args.rule), ("change", args.change),
                    ) if v
                },
                "reason": args.reason,
                "added_by": args.by,
                "expires_at": args.expires,
            })
            engine.whitelist.add(entry)
            print(f"Đã thêm '{entry.id}'.")
            return 0

        if args.wl_action == "remove":
            ok = engine.whitelist.remove(args.id)
            print(f"Đã xoá '{args.id}'." if ok else f"Không tìm thấy '{args.id}'.")
            return 0 if ok else 1

        if args.wl_action == "export":
            count = export_to_yaml(engine.store, args.output)
            print(f"Đã xuất {count} mục ra {args.output}")
            return 0

        if args.wl_action == "reload":
            count = engine.reload_whitelist()
            print(f"Đã nạp lại, {count} mục đang hiệu lực.")
            return 0
    return 1


def cmd_serve(args: argparse.Namespace) -> int:
    cfg = load_config(args.config, **{"web.host": args.host, "web.port": args.port})
    try:
        import uvicorn
    except ImportError:
        print("Cần cài uvicorn:  pip install 'uvicorn[standard]'", file=sys.stderr)
        return 1

    from .web.app import create_app

    app = create_app(cfg)
    print(f"Dashboard: http://{cfg.web.host}:{cfg.web.port}")
    if cfg.web.host not in ("127.0.0.1", "localhost"):
        print("CẢNH BÁO: đang lắng nghe ngoài localhost — dashboard không có xác thực.")
    uvicorn.run(app, host=cfg.web.host, port=cfg.web.port, log_level="warning")
    return 0


def cmd_alerts(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    with Engine(cfg) as engine:
        if args.ack is not None:
            ok = engine.store.update_alert_status(args.ack, AlertStatus.ACK, args.note)
            print(f"Đã tiếp nhận cảnh báo #{args.ack}." if ok else "Không tìm thấy.")
            return 0 if ok else 1

        alerts = engine.store.query_alerts(status=args.status, limit=args.limit)
        if not alerts:
            print("Không có cảnh báo nào.")
            return 0
        rows = [
            [
                str(a["id"]),
                time.strftime("%m-%d %H:%M", time.localtime(a["created_at"])),
                _tint(a["severity"].ljust(8), a["severity"]),
                a["status"],
                _short(a["path"], 48),
            ]
            for a in alerts
        ]
        print(_table(rows, ["ID", "Thời điểm", "Mức", "Trạng thái", "Đường dẫn"]))
    return 0


# ---------------------------------------------------------------------------
# Phân tích tham số
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fim",
        description="Giám sát toàn vẹn file và phát hiện thay đổi bất thường",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Quy trình thường dùng:\n"
            "  fim init            kiểm tra phạm vi\n"
            "  fim baseline        chốt mốc so sánh\n"
            "  fim watch           theo dõi liên tục\n"
            "  fim serve           mở dashboard\n"
        ),
    )
    parser.add_argument("-c", "--config", help="đường dẫn file cấu hình YAML")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="tạo CSDL và kiểm tra phạm vi").set_defaults(func=cmd_init)

    p = sub.add_parser("baseline", help="chốt baseline hash")
    p.add_argument("-l", "--label", help="nhãn cho baseline này")
    p.set_defaults(func=cmd_baseline)

    p = sub.add_parser("scan", help="quét một lần và so với baseline")
    p.add_argument("-q", "--quiet", action="store_true")
    p.set_defaults(func=cmd_scan)

    sub.add_parser("watch", help="theo dõi liên tục").set_defaults(func=cmd_watch)
    sub.add_parser("status", help="xem tình trạng hệ thống").set_defaults(func=cmd_status)
    sub.add_parser("rules", help="liệt kê bộ luật heuristic").set_defaults(func=cmd_rules)

    p = sub.add_parser("events", help="liệt kê lịch sử thay đổi")
    p.add_argument("-n", "--limit", type=int, default=30)
    p.add_argument("-s", "--severity", choices=[s.value for s in Severity])
    p.add_argument("-C", "--classification")
    p.add_argument("-p", "--path", help="lọc theo chuỗi con trong đường dẫn")
    p.add_argument("-H", "--hours", type=float, help="chỉ lấy N giờ gần đây")
    p.add_argument("-a", "--all", action="store_true", help="kể cả mục đã whitelist")
    p.set_defaults(func=cmd_events)

    p = sub.add_parser("explain", help="giải thích một sự kiện")
    p.add_argument("event_id", type=int)
    p.set_defaults(func=cmd_explain)

    p = sub.add_parser("approve", help="chấp nhận thay đổi, cập nhật baseline")
    p.add_argument("event_ids", type=int, nargs="+")
    p.set_defaults(func=cmd_approve)

    p = sub.add_parser("alerts", help="xem và xử lý cảnh báo")
    p.add_argument("-n", "--limit", type=int, default=30)
    p.add_argument("-s", "--status", choices=[s.value for s in AlertStatus])
    p.add_argument("--ack", type=int, metavar="ID", help="đánh dấu đã tiếp nhận")
    p.add_argument("--note")
    p.set_defaults(func=cmd_alerts)

    p = sub.add_parser("serve", help="chạy dashboard web")
    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("whitelist", help="quản lý whitelist")
    wl = p.add_subparsers(dest="wl_action", required=True)
    wl.add_parser("list")
    wl.add_parser("reload")

    add = wl.add_parser("add")
    add.add_argument("--id")
    add.add_argument("--path", help="mẫu glob đường dẫn")
    add.add_argument("--digest")
    add.add_argument("--rule", help="chỉ tắt một luật, ví dụ H024")
    add.add_argument("--change", choices=[c.value for c in ChangeType])
    add.add_argument("--reason", required=True, help="bắt buộc: vì sao an toàn")
    add.add_argument("--by", default="cli")
    add.add_argument("--expires", help="ví dụ +7d hoặc 2026-12-31T00:00:00")

    rm = wl.add_parser("remove")
    rm.add_argument("id")

    ex = wl.add_parser("export")
    ex.add_argument("output", type=Path)

    p.set_defaults(func=cmd_whitelist)
    return parser


def main(argv: list[str] | None = None) -> int:
    enable_utf8_output()          # phải gọi trước mọi lệnh print (console Windows là cp1252)
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("\nĐã huỷ.")
        return 130
    except (ValueError, FileNotFoundError, RuntimeError) as exc:
        print(f"Lỗi: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
