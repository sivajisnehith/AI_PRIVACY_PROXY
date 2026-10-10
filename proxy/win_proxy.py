from __future__ import annotations

import atexit
import ctypes
import os
import signal
import subprocess
import sys
import winreg
from pathlib import Path
from typing import Tuple

INTERNET_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37


def is_admin() -> bool:
    """Return True if the current process has Administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def refresh_wininet() -> None:
    """Notify Windows system and browsers that Internet Settings have changed."""
    try:
        ctypes.windll.wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        ctypes.windll.wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
    except Exception as e:
        print(f"[!] Warning: Could not notify WinINet: {e}")


def enable_system_proxy(server: str = "127.0.0.1:8080", override: str = "<-loopback>;<local>") -> bool:
    """Configure and enable Windows system proxy settings."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, server)
            if override:
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, override)
        refresh_wininet()
        return True
    except Exception as e:
        print(f"[!] Error enabling Windows proxy: {e}")
        return False


def disable_system_proxy() -> bool:
    """Disable Windows system proxy settings and restore direct connection."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        refresh_wininet()
        return True
    except Exception as e:
        print(f"[!] Error disabling Windows proxy: {e}")
        return False


def get_proxy_status() -> Tuple[bool, str]:
    """Get the current Windows proxy status and server."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_READ) as key:
            enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
            try:
                server, _ = winreg.QueryValueEx(key, "ProxyServer")
            except FileNotFoundError:
                server = ""
            return bool(enabled), str(server)
    except Exception:
        return False, ""


def get_mitmproxy_ca_path() -> Path:
    """Return the path to the mitmproxy CA certificate on Windows."""
    home = Path.home()
    return home / ".mitmproxy" / "mitmproxy-ca-cert.cer"


def is_ca_installed(cert_name: str = "mitmproxy") -> bool:
    """Check if the mitmproxy certificate is installed in the Windows Root store."""
    try:
        res = subprocess.run(
            ["certutil.exe", "-user", "-verifystore", "Root", cert_name],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode == 0:
            return True
        # Also check LocalMachine Root if run as admin or previously installed there
        res_lm = subprocess.run(
            ["certutil.exe", "-verifystore", "Root", cert_name],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return res_lm.returncode == 0
    except Exception:
        return False


def install_ca_certificate(cert_path: Path | None = None) -> bool:
    """Install the CA certificate into the Windows Root Certificate Store."""
    if cert_path is None:
        cert_path = get_mitmproxy_ca_path()

    if not cert_path.exists():
        print(f"[!] Certificate not found at {cert_path}")
        return False

    if is_ca_installed():
        return True

    cmd = ["certutil.exe"]
    if is_admin():
        # Elevated: add silently to LocalMachine Root
        cmd.extend(["-addstore", "-f", "Root", str(cert_path)])
    else:
        # Standard user: add to CurrentUser Root (Windows may display a confirmation dialog)
        cmd.extend(["-user", "-addstore", "-f", "Root", str(cert_path)])

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return res.returncode == 0
    except Exception as e:
        print(f"[!] Failed to install root certificate: {e}")
        return False


_registered_cleanup = False


def register_proxy_cleanup() -> None:
    """Register exit handlers to ensure system proxy is always restored upon exit."""
    global _registered_cleanup
    if _registered_cleanup:
        return
    _registered_cleanup = True

    def _cleanup(*_args):
        print("\n[+] Restoring Windows Internet Settings...")
        disable_system_proxy()

    atexit.register(_cleanup)

    # Windows signals
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, lambda s, f: sys.exit(0))
        except Exception:
            pass

    if hasattr(signal, "SIGBREAK"):
        try:
            signal.signal(signal.SIGBREAK, lambda s, f: sys.exit(0))
        except Exception:
            pass
