"""Bộ luật heuristic phân biệt thay đổi hợp lệ với thay đổi đáng ngờ (Người 2).

Mô hình chấm điểm thay vì if/else lồng nhau: mỗi luật độc lập xem xét một
``ChangeEvent`` và trả về :class:`RuleHit` kèm trọng số. Tổng trọng số ra điểm,
điểm ra mức nghiêm trọng.

Vì sao chọn cách này:

* **Giải trình được** — dashboard hiện đúng những luật nào đã khớp, thay vì chỉ
  phán "đáng ngờ". Người vận hành cần biết *vì sao* mới xử lý được.
* **Chỉnh được** — sai nhiều thì hạ trọng số một luật, không phải sửa logic.
* **Bằng chứng hai chiều** — trọng số âm (ví dụ ``H020`` với thư mục log) kéo
  điểm xuống, nên một file vốn hay thay đổi không leo lên mức cao chỉ vì trùng
  một luật phụ.

Trọng số được đặt theo mức độ khó giải thích của thay đổi bằng hoạt động bình
thường: sửa nội dung mà giữ nguyên mtime (``H006``) gần như chắc chắn là cố ý
xoá dấu vết, nên nặng nhất.
"""

from __future__ import annotations

import stat
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Iterable

from ..config import AnalysisConfig
from ..models import ChangeEvent, ChangeType, FileRecord, RuleHit
from ..util import glob_match, parse_duration
from ..collector.hashing import detect_magic, is_executable, sample_entropy


@dataclass
class RuleContext:
    """Thông tin phụ mà các luật cần ngoài bản thân sự kiện."""

    config: AnalysisConfig
    is_critical: Callable[[str], str | None]
    #: Số thay đổi trong cửa sổ gần đây — dùng cho luật phát hiện thay đổi hàng loạt.
    burst_count: int = 0
    now: float = 0.0

    def __post_init__(self) -> None:
        if not self.now:
            self.now = time.time()


#: Hàm luật: nhận (event, ctx) và trả về RuleHit nếu khớp.
RuleFn = Callable[[ChangeEvent, RuleContext], RuleHit | None]


@dataclass
class Rule:
    rule_id: str
    title: str
    weight: int
    fn: RuleFn
    description: str = ""


_REGISTRY: dict[str, Rule] = {}


def rule(rule_id: str, title: str, weight: int, description: str = ""):
    """Decorator đăng ký một luật vào sổ đăng ký toàn cục."""

    def wrapper(fn: RuleFn) -> RuleFn:
        _REGISTRY[rule_id] = Rule(rule_id, title, weight, fn, description or (fn.__doc__ or ""))
        return fn

    return wrapper


def hit(rule_id: str, detail: str = "", weight: int | None = None) -> RuleHit:
    """Tạo :class:`RuleHit` từ metadata đã đăng ký."""
    meta = _REGISTRY[rule_id]
    return RuleHit(
        rule_id=rule_id,
        title=meta.title,
        weight=meta.weight if weight is None else weight,
        detail=detail,
    )


def all_rules() -> list[Rule]:
    return sorted(_REGISTRY.values(), key=lambda r: r.rule_id)


# ===========================================================================
# Nhóm 1 — vị trí file: chạm vào đâu quan trọng hơn chạm thế nào
# ===========================================================================


@rule("H001", "Sửa file trọng yếu", 40,
      "Đường dẫn nằm trong danh sách critical của scope (passwd, sudoers, sshd_config…)")
def _critical_path(event: ChangeEvent, ctx: RuleContext) -> RuleHit | None:
    pattern = ctx.is_critical(event.path)
    return hit("H001", f"khớp mẫu trọng yếu {pattern}") if pattern else None


_BINARY_DIRS = (
    "/bin/**", "/sbin/**", "/usr/bin/**", "/usr/sbin/**",
    "/usr/local/bin/**", "/usr/local/sbin/**", "/lib/**", "/usr/lib/**",
    "**/System32/**", "**/SysWOW64/**",
)


@rule("H002", "Thay đổi trong thư mục nhị phân hệ thống", 35,
      "File thực thi hệ thống chỉ nên đổi khi cập nhật gói phần mềm")
def _binary_dir(event: ChangeEvent, ctx: RuleContext) -> RuleHit | None:
    for pattern in _BINARY_DIRS:
        if glob_match(event.path, pattern):
            return hit("H002", f"nằm trong {pattern}")
    return None


_PERSISTENCE_PATHS = (
    "/etc/cron*/**", "/var/spool/cron/**", "/etc/systemd/system/**",
    "/lib/systemd/system/**", "/etc/init.d/**", "/etc/rc*.d/**",
    "**/.ssh/authorized_keys", "**/.bashrc", "**/.bash_profile", "**/.profile",
    "/etc/ld.so.preload", "/etc/ld.so.conf*", "/etc/profile.d/**",
    "**/Start Menu/Programs/StartUp/**", "**/System32/Tasks/**", "**/Windows/Tasks/**",
)


@rule("H003", "Chạm vào cơ chế duy trì quyền truy cập", 45,
      "Cron, systemd unit, authorized_keys, StartUp — nơi mã độc tự khởi động lại")
def _persistence(event: ChangeEvent, ctx: RuleContext) -> RuleHit | None:
    for pattern in _PERSISTENCE_PATHS:
        if glob_match(event.path, pattern):
            return hit("H003", f"cơ chế persistence: {pattern}")
    return None


_TEMP_DIRS = ("/tmp/**", "/var/tmp/**", "/dev/shm/**", "**/Temp/**", "**/AppData/Local/Temp/**")


@rule("H004", "File thực thi xuất hiện trong thư mục tạm", 30,
      "Thư mục tạm ai cũng ghi được — chỗ dựng trại quen thuộc của payload")
def _exec_in_temp(event: ChangeEvent, ctx: RuleContext) -> RuleHit | None:
    if event.change not in (ChangeType.CREATED, ChangeType.MODIFIED):
        return None
    record = event.after
    if record is None or not is_executable(record):
        return None
    for pattern in _TEMP_DIRS:
        if glob_match(event.path, pattern):
            return hit("H004", f"file thực thi trong {pattern}")
    return None


@rule("H005", "File ẩn được tạo trong thư mục hệ thống", 20,
      "Tên bắt đầu bằng dấu chấm ở nơi vốn không có file ẩn")
def _hidden_file(event: ChangeEvent, ctx: RuleContext) -> RuleHit | None:
    if event.change != ChangeType.CREATED:
        return None
    name = event.path.rsplit("/", 1)[-1]
    if not name.startswith(".") or name in (".", ".."):
        return None
    if ctx.is_critical(event.path) or glob_match(event.path, "/etc/**"):
        return hit("H005", f"file ẩn mới: {name}")
    return None


# ===========================================================================
# Nhóm 2 — quyền và chủ sở hữu
# ===========================================================================


@rule("H010", "File được gán bit setuid/setgid", 50,
      "setuid cho phép chạy với quyền chủ sở hữu — đường leo thang đặc quyền cổ điển")
def _setuid(event: ChangeEvent, ctx: RuleContext) -> RuleHit | None:
    after = event.after
    if after is None:
        return None
    special = after.mode & (stat.S_ISUID | stat.S_ISGID)
    if not special:
        return None
    before_special = event.before.mode & (stat.S_ISUID | stat.S_ISGID) if event.before else 0
    if event.change == ChangeType.CREATED:
        return hit("H010", f"file mới có quyền {after.permissions}")
    if special != before_special:
        return hit("H010", f"quyền đổi {event.before.permissions} -> {after.permissions}")
    return None


@rule("H011", "File trở nên ai cũng ghi được", 25,
      "Quyền o+w trên file hệ thống cho phép người dùng thường sửa nội dung")
def _world_writable(event: ChangeEvent, ctx: RuleContext) -> RuleHit | None:
    after = event.after
    if after is None or not (after.mode & stat.S_IWOTH):
        return None
    if event.before is not None and (event.before.mode & stat.S_IWOTH):
        return None                                  # vốn đã như vậy, không phải thay đổi
    return hit("H011", f"quyền {after.permissions} cho phép mọi người ghi")


@rule("H012", "Chủ sở hữu file bị đổi", 25,
      "Đổi uid/gid thường đi kèm thao tác chiếm quyền kiểm soát file")
def _owner_change(event: ChangeEvent, ctx: RuleContext) -> RuleHit | None:
    before, after = event.before, event.after
    if before is None or after is None:
        return None
    if (before.uid, before.gid) == (after.uid, after.gid):
        return None
    return hit(
        "H012", f"uid/gid {before.uid}:{before.gid} -> {after.uid}:{after.gid}"
    )


@rule("H013", "File thường bị thay bằng symlink", 45,
      "Kỹ thuật chuyển hướng ghi sang file khác (symlink attack)")
def _became_symlink(event: ChangeEvent, ctx: RuleContext) -> RuleHit | None:
    before, after = event.before, event.after
    if before is None or after is None:
        return None
    if not before.is_symlink and after.is_symlink:
        return hit("H013", f"nay trỏ tới {after.link_target}")
    if before.is_symlink and after.is_symlink and before.link_target != after.link_target:
        return hit("H013", f"đích đổi {before.link_target} -> {after.link_target}")
    return None


# ===========================================================================
# Nhóm 3 — dấu hiệu che giấu dấu vết
# ===========================================================================


@rule("H020", "Nội dung đổi nhưng mtime giữ nguyên", 55,
      "Timestomping: sửa file rồi đặt lại thời gian để qua mặt kiểm tra theo mtime")
def _timestomp(event: ChangeEvent, ctx: RuleContext) -> RuleHit | None:
    before, after = event.before, event.after
    if before is None or after is None:
        return None
    if before.digest is None or after.digest is None:
        return None                                  # không có digest thì không kết luận được
    if before.digest == after.digest:
        return None

    if after.mtime < before.mtime:
        return hit("H020", "mtime bị lùi về quá khứ", weight=45)

    # So *bằng chính xác*, không dùng sai lệch. Dùng ngưỡng kiểu "lệch dưới 1 giây"
    # sẽ báo động giả với mọi lần ghi bình thường diễn ra ngay sau lần quét trước:
    # NTFS và ext4 lưu mtime tới nano giây, nên hai lần ghi khác nhau gần như
    # không bao giờ cho mtime trùng khớp tuyệt đối. Ngược lại, kẻ tấn công gọi
    # ``utime()`` để khôi phục mốc thời gian cũ sẽ tạo ra đúng giá trị y nguyên.
    if after.mtime != before.mtime:
        return None

    # Trên POSIX, ``utime()`` đặt lại được mtime nhưng **không** đặt được ctime
    # (thời điểm inode thay đổi) — ctime nhảy trong khi mtime đứng yên là bằng
    # chứng mạnh nhất. Trên Windows st_ctime là thời điểm tạo file nên không có
    # tín hiệu này; khi đó riêng việc mtime trùng khớp tuyệt đối đã đủ đáng ngờ.
    ctime_delta = after.ctime - before.ctime
    if ctime_delta > 1.0:
        return hit(
            "H020",
            f"mtime giữ nguyên ({after.mtime:.0f}) nhưng ctime nhảy {ctime_delta:.0f}s",
        )
    return hit("H020", f"digest đổi nhưng mtime vẫn là {after.mtime:.0f}")


@rule("H021", "mtime nằm ở tương lai", 30,
      "Thời gian sửa đổi vượt quá hiện tại — dấu hiệu bị đặt tay hoặc lệch đồng hồ")
def _future_mtime(event: ChangeEvent, ctx: RuleContext) -> RuleHit | None:
    after = event.after
    if after is None:
        return None
    skew = parse_duration(ctx.config.future_mtime_skew)
    if after.mtime > ctx.now + skew:
        delta = after.mtime - ctx.now
        return hit("H021", f"mtime lệch tới {delta / 3600:.1f} giờ ở tương lai")
    return None


@rule("H022", "File trọng yếu bị xoá", 45,
      "Xoá nhật ký hoặc cấu hình bảo mật thường là bước dọn dẹp sau tấn công")
def _critical_deleted(event: ChangeEvent, ctx: RuleContext) -> RuleHit | None:
    if event.change != ChangeType.DELETED:
        return None
    pattern = ctx.is_critical(event.path)
    return hit("H022", f"đã xoá, khớp {pattern}") if pattern else None


@rule("H023", "Thay đổi hàng loạt trong thời gian ngắn", 40,
      "Nhiều file đổi cùng lúc: ransomware mã hoá, hoặc xoá dấu vết diện rộng")
def _burst(event: ChangeEvent, ctx: RuleContext) -> RuleHit | None:
    if ctx.burst_count < ctx.config.burst_threshold:
        return None
    return hit(
        "H023",
        f"{ctx.burst_count} thay đổi trong {ctx.config.burst_window} "
        f"(ngưỡng {ctx.config.burst_threshold})",
    )


@rule("H024", "Thay đổi ngoài giờ làm việc", 10,
      "Bảo trì hợp lệ thường diễn ra trong giờ hành chính")
def _off_hours(event: ChangeEvent, ctx: RuleContext) -> RuleHit | None:
    hours = ctx.config.business_hours
    if not hours or len(hours) != 2:
        return None
    start, end = hours
    hour = datetime.fromtimestamp(event.ts).hour
    if start <= hour < end:
        return None
    return hit("H024", f"xảy ra lúc {hour:02d}:00, ngoài khung {start:02d}–{end:02d}")


# ===========================================================================
# Nhóm 4 — nội dung file
# ===========================================================================


@rule("H030", "Nội dung không khớp phần mở rộng", 35,
      "File .txt/.log nhưng bên trong là nhị phân thực thi (ELF/PE)")
def _magic_mismatch(event: ChangeEvent, ctx: RuleContext) -> RuleHit | None:
    after = event.after
    if after is None or event.change == ChangeType.DELETED or after.is_symlink:
        return None
    suffix = after.path.rsplit(".", 1)[-1].lower() if "." in after.path else ""
    if suffix not in {"txt", "log", "conf", "cfg", "ini", "json", "yaml", "yml", "md", "csv"}:
        return None
    kind = detect_magic(after.path)
    if kind in ("elf", "pe", "macho"):
        return hit("H030", f".{suffix} nhưng nội dung là {kind.upper()}")
    return None


@rule("H031", "Entropy bất thường trong file cấu hình", 20,
      "Entropy tiệm cận 8 bit/byte: nội dung đã nén, mã hoá hoặc đóng gói")
def _entropy(event: ChangeEvent, ctx: RuleContext) -> RuleHit | None:
    after = event.after
    if after is None or after.is_symlink or after.size < 512:
        return None
    if not glob_match(after.path, "/etc/**") and not glob_match(after.path, "**/*.conf"):
        return None
    value = sample_entropy(after.path, ctx.config.entropy_sample)
    if value is not None and value >= ctx.config.entropy_threshold:
        return hit("H031", f"entropy {value:.2f} bit/byte")
    return None


@rule("H032", "Kích thước thay đổi bất thường", 15,
      "File co về 0 hoặc phình gấp nhiều lần so với baseline")
def _size_anomaly(event: ChangeEvent, ctx: RuleContext) -> RuleHit | None:
    before, after = event.before, event.after
    if before is None or after is None or before.size == 0:
        return None
    if after.size == 0:
        return hit("H032", f"bị cắt về 0 byte (trước: {before.size})")
    ratio = after.size / before.size
    if ratio >= 10 or ratio <= 0.1:
        return hit("H032", f"kích thước {before.size} -> {after.size} ({ratio:.1f}x)")
    return None


@rule("H033", "File thực thi mới được tạo", 25,
      "Nhị phân hoặc script mới xuất hiện trong phạm vi giám sát")
def _new_executable(event: ChangeEvent, ctx: RuleContext) -> RuleHit | None:
    if event.change != ChangeType.CREATED:
        return None
    after = event.after
    if after is None or after.is_symlink or not is_executable(after):
        return None
    kind = detect_magic(after.path)
    return hit("H033", f"file thực thi mới ({kind or 'không rõ loại'})")


# ===========================================================================
# Nhóm 5 — bằng chứng cho thấy thay đổi là hợp lệ (trọng số âm)
# ===========================================================================


@rule("H090", "Hash nằm trong danh sách đã biết là tốt", -60,
      "Nội dung sau thay đổi trùng một hash đã được duyệt trước")
def _known_good(event: ChangeEvent, ctx: RuleContext) -> RuleHit | None:
    after = event.after
    if after is None or not after.digest:
        return None
    known = {h.lower() for h in ctx.config.known_good_hashes}
    if after.digest.lower() in known:
        return hit("H090", f"digest {after.digest[:16]}… đã được duyệt")
    return None


_CHURN_PATHS = (
    "**/*.log", "**/*.log.*", "**/logs/**", "**/cache/**", "**/.cache/**",
    "/var/log/**", "/var/cache/**", "/var/lib/**/*.db", "**/*.pid", "**/*.lock",
)


@rule("H091", "Đường dẫn vốn thay đổi thường xuyên", -20,
      "Log, cache, pid — thay đổi liên tục là hành vi bình thường")
def _churn_path(event: ChangeEvent, ctx: RuleContext) -> RuleHit | None:
    for pattern in _CHURN_PATHS:
        if glob_match(event.path, pattern):
            return hit("H091", f"đường dẫn hay biến động: {pattern}")
    return None


@rule("H092", "Chỉ metadata đổi, nội dung giữ nguyên", -10,
      "Nội dung không đổi thì rủi ro thấp hơn hẳn")
def _attr_only(event: ChangeEvent, ctx: RuleContext) -> RuleHit | None:
    if event.change != ChangeType.ATTR_CHANGED:
        return None
    return hit("H092", "digest không đổi")


# ===========================================================================
# Chạy bộ luật
# ===========================================================================


def evaluate(
    event: ChangeEvent,
    ctx: RuleContext,
    *,
    skip_rules: Iterable[str] = (),
) -> list[RuleHit]:
    """Chạy toàn bộ luật đang bật, trả về danh sách luật đã khớp.

    Một luật ném lỗi (file biến mất giữa chừng, thiếu quyền đọc) không được làm
    hỏng cả lần phân loại — bỏ qua luật đó và chạy tiếp.
    """
    disabled = set(ctx.config.disabled_rules) | set(skip_rules)
    overrides = ctx.config.rule_weights
    hits: list[RuleHit] = []

    for rule_obj in all_rules():
        if rule_obj.rule_id in disabled:
            continue
        try:
            result = rule_obj.fn(event, ctx)
        except (OSError, ValueError):
            continue
        if result is None:
            continue
        if rule_obj.rule_id in overrides:
            result.weight = int(overrides[rule_obj.rule_id])
        hits.append(result)

    return hits
