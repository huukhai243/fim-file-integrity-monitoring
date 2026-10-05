"""Hồ sơ phạm vi giám sát dựng sẵn theo hệ điều hành (Người 3).

FIM chỉ có giá trị khi giám sát đúng chỗ. Quét cả ổ đĩa thì baseline phình to,
nhiễu ngập đầu và bỏ sót cái quan trọng. Các hồ sơ dưới đây gom sẵn những thư
mục mà kẻ tấn công thực sự phải chạm vào để **duy trì quyền truy cập** hoặc
**leo thang đặc quyền**.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field


@dataclass
class ScopeProfile:
    """Một bộ include/exclude/critical dựng sẵn."""

    name: str
    description: str
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    critical: list[str] = field(default_factory=list)


# Thư mục ảo và dữ liệu biến động liên tục — quét chúng chỉ tạo nhiễu.
_COMMON_EXCLUDE = [
    "**/__pycache__/**",
    "**/*.pyc",
    "**/.git/**",
    "**/node_modules/**",
    "**/.cache/**",
    "**/*.swp",
    "**/*.tmp",
    "**/~*",
]

LINUX_SYSTEM = ScopeProfile(
    name="linux-system",
    description="Nhị phân hệ thống, cấu hình và cơ chế khởi động của Linux",
    include=[
        "/etc",          # toàn bộ cấu hình hệ thống
        "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
        "/lib/systemd/system", "/etc/systemd/system",   # unit khởi động
        "/boot",         # kernel + initramfs + bootloader
        "/root/.ssh",
        "/var/spool/cron",
    ],
    exclude=[
        *_COMMON_EXCLUDE,
        "/proc/**", "/sys/**", "/dev/**", "/run/**",    # hệ thống tệp ảo
        "/etc/mtab",                                     # symlink tới /proc, đổi liên tục
        "/etc/resolv.conf",                              # DHCP ghi lại thường xuyên
        "/etc/ld.so.cache",                              # sinh lại sau mỗi ldconfig
        "/var/log/**",
        "/boot/**/*.log",
    ],
    critical=[
        "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
        "/etc/sudoers", "/etc/sudoers.d/**",
        "/etc/ssh/sshd_config", "/etc/ssh/ssh_config",
        "/etc/pam.d/**", "/etc/security/**",
        "/etc/crontab", "/etc/cron.*/**", "/var/spool/cron/**",
        "/etc/systemd/system/**", "/lib/systemd/system/**",
        "/etc/rc.local", "/etc/profile", "/etc/profile.d/**", "/etc/bash.bashrc",
        "/etc/ld.so.preload",        # kỹ thuật cài rootkit kinh điển
        "/etc/hosts", "/etc/hosts.allow", "/etc/hosts.deny",
        "/root/.ssh/**", "/home/*/.ssh/authorized_keys",
        "/boot/**",
        "/bin/**", "/sbin/**", "/usr/bin/**", "/usr/sbin/**",
    ],
)

WINDOWS_SYSTEM = ScopeProfile(
    name="windows-system",
    description="Thư mục hệ thống, cơ chế tự khởi động và cấu hình mạng của Windows",
    include=[
        "C:/Windows/System32",
        "C:/Windows/SysWOW64",
        "C:/Windows/System32/drivers/etc",
        "C:/Windows/Tasks",
        "C:/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp",
    ],
    exclude=[
        *_COMMON_EXCLUDE,
        "C:/Windows/System32/config/**",        # registry hive: bị khoá, đổi liên tục
        "C:/Windows/System32/winevt/**",        # nhật ký sự kiện
        "C:/Windows/System32/LogFiles/**",
        "C:/Windows/System32/spool/**",
        "C:/Windows/System32/catroot2/**",
        "C:/Windows/System32/DriverStore/**",   # rất lớn, Windows Update tự quản
        "**/*.etl", "**/*.evtx",
    ],
    critical=[
        "C:/Windows/System32/drivers/etc/hosts",
        "C:/Windows/System32/drivers/**",       # driver nhân = quyền cao nhất
        "C:/Windows/System32/Tasks/**",
        "C:/Windows/Tasks/**",
        "**/Start Menu/Programs/StartUp/**",
        "C:/Windows/System32/*.exe",
        "C:/Windows/System32/*.dll",
    ],
)

#: Hồ sơ nhẹ để demo/kiểm thử: chỉ giám sát thư mục người dùng chỉ định.
CUSTOM = ScopeProfile(
    name="custom",
    description="Tự khai báo include/exclude trong configs/default.yaml",
    include=[],
    exclude=list(_COMMON_EXCLUDE),
    critical=[],
)

PROFILES: dict[str, ScopeProfile] = {
    p.name: p for p in (LINUX_SYSTEM, WINDOWS_SYSTEM, CUSTOM)
}


def detect_profile() -> str:
    """Chọn hồ sơ theo hệ điều hành đang chạy."""
    if sys.platform.startswith("win") or os.name == "nt":
        return "windows-system"
    if sys.platform.startswith(("linux", "freebsd")):
        return "linux-system"
    return "custom"          # macOS và phần còn lại: tự khai báo cho chắc


def get_profile(name: str) -> ScopeProfile:
    """Lấy hồ sơ theo tên. ``"auto"`` sẽ tự dò theo hệ điều hành."""
    key = detect_profile() if name == "auto" else name
    if key not in PROFILES:
        raise ValueError(
            f"Hồ sơ không tồn tại: {name}. Chọn một trong: "
            f"{', '.join(sorted(PROFILES))} hoặc 'auto'"
        )
    return PROFILES[key]
