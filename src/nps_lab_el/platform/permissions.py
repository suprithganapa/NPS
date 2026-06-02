import os
import sys
from pathlib import Path


def is_admin() -> bool:
    if sys.platform == "win32":
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return os.geteuid() == 0


def has_cap_net_raw() -> bool:
    if sys.platform == "win32":
        return False
    try:
        status = Path("/proc/self/status").read_text()
        for line in status.splitlines():
            if line.startswith("CapEff:"):
                cap_eff = int(line.split(":")[1].strip(), 16)
                return bool(cap_eff & (1 << 13))
    except Exception:
        return False
    return False


def check_capture_ready() -> tuple[bool, str]:
    if sys.platform == "win32":
        npcap_paths = [
            Path(r"C:\Windows\System32\Npcap\wpcap.dll"),
            Path(r"C:\Windows\SysWOW64\Npcap\wpcap.dll"),
        ]
        if any(p.exists() for p in npcap_paths):
            return True, "Npcap detected."
        if Path(r"C:\Windows\System32\wpcap.dll").exists():
            return True, "WinPcap detected."
        return False, (
            "No packet capture library found. "
            "Install Npcap from https://npcap.com/ (recommended) or WinPcap."
        )
    else:
        import ctypes.util
        if ctypes.util.find_library("pcap"):
            return True, "libpcap detected."
        return False, (
            "libpcap not found. Install it with your package manager, "
            "e.g. 'sudo apt install libpcap-dev' or 'sudo dnf install libpcap-devel'."
        )


def require_privileges(simulation: bool = False) -> None:
    if simulation:
        return
    if is_admin() or has_cap_net_raw():
        return
    if sys.platform == "win32":
        msg = "Administrator privileges required. Run the terminal as Administrator."
    else:
        msg = (
            "Root privileges or CAP_NET_RAW capability required. "
            "Run with sudo or set the capability: "
            "sudo setcap cap_net_raw+ep <executable>"
        )
    raise PermissionError(msg)
