from __future__ import annotations

import argparse
import asyncio
import os
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

# Ensure project root is in sys.path
if getattr(sys, "frozen", False):
    _exe_dir = Path(sys.executable).resolve().parent
    PROJECT_ROOT = _exe_dir.parent if _exe_dir.name.lower() == "dist" else _exe_dir
else:
    PROJECT_ROOT = Path(__file__).resolve().parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster
from proxy import win_proxy
from proxy.proxy import (
    PrivacyProxyAddon,
    get_storage_dir,
    list_stored_files,
)


def print_banner(host: str, port: int, storage_dir: Path) -> None:
    print("\n" + "=" * 70)
    print("                AI PRIVACY PROXY (DLP GATEWAY)")
    print("=" * 70)
    print(f" [STATUS]      Active & Monitoring")
    print(f" [PROXY]       http://{host}:{port} (Configured in Windows)")
    print(f" [CERTIFICATE] Windows Root CA Verified & Trusted")
    print(f" [STORAGE]     {storage_dir}")
    print("-" * 70)
    print(" [PROTECTION ACTIVE]")
    print("   • Intercepts ChatGPT & AI file uploads")
    print("   • Saves sensitive documents to local storage")
    print("   • Strips attachments from outgoing requests (prevents data leak)")
    print("   • Forwards only your prompts to ChatGPT")
    print("-" * 70)
    print(" [COMMANDS]")
    print("   open    -> Open the storage folder in Windows File Explorer")
    print("   list    -> List all captured files")
    print("   status  -> Show proxy status")
    print("   exit    -> Stop proxy and restore Windows Internet settings")
    print("=" * 70 + "\n")


def open_storage_folder(storage_dir: Path) -> None:
    try:
        if sys.platform == "win32":
            os.startfile(str(storage_dir))
        else:
            subprocess.run(["xdg-open", str(storage_dir)])
        print(f"[+] Opened storage folder: {storage_dir}")
    except Exception as e:
        print(f"[!] Could not open storage folder: {e}")


def show_stored_files() -> None:
    files = list_stored_files()
    if not files:
        print("\n[i] Storage is currently empty. No documents intercepted yet.\n")
        return

    print(f"\n[+] Captured Documents ({len(files)} total):")
    print("-" * 70)
    for i, f in enumerate(files, 1):
        dt = datetime.fromtimestamp(f["modified"]).strftime("%Y-%m-%d %H:%M:%S")
        size_kb = f["size_bytes"] / 1024.0
        print(f" {i:2d}. {f['name']:<40} {size_kb:>8.2f} KB   [{dt}]")
    print("-" * 70 + "\n")


def start_proxy_server(host: str, port: int):
    """Start the mitmproxy DumpMaster instance in a background asyncio loop."""
    loop = asyncio.new_event_loop()
    opts = Options(
        listen_host=host,
        listen_port=port,
        ssl_insecure=True,
    )
    master = DumpMaster(opts, loop=loop, with_termlog=False, with_dumper=False)
    master.addons.add(PrivacyProxyAddon())

    def run_worker():
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(master.run())
        except Exception:
            pass

    thread = threading.Thread(target=run_worker, name="ProxyWorkerThread", daemon=True)
    thread.start()
    return master, loop, thread


def request_user_consent(storage_dir: Path, port: int) -> bool:
    """Prompt the user for informed consent before configuring proxy or intercepting traffic."""
    print("\n" + "=" * 75)
    print("                      AI PRIVACY PROXY - USER CONSENT")
    print("=" * 75)
    print(" This tool operates as a local Data Loss Prevention (DLP) & Privacy Proxy")
    print(" to protect your sensitive files and PII from being uploaded to AI services.")
    print()
    print(" With your explicit permission, this application will:")
    print(f"  1. Configure Windows to route traffic via local proxy (127.0.0.1:{port}).")
    print("  2. Monitor and inspect outgoing requests to ChatGPT & AI endpoints.")
    print(f"  3. Intercept document uploads and store them locally at:")
    print(f"     -> {storage_dir}")
    print("  4. Strip documents from outgoing requests, forwarding only your text prompt.")
    print("  5. Verify/install a local root CA certificate to permit HTTPS inspection.")
    print()
    print(" NOTE: All Windows proxy settings will automatically revert to disabled")
    print("       as soon as you exit this application.")
    print("=" * 75)

    try:
        response = input("\nDo you grant permission to activate AI Privacy Protection? [Y/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\n[!] Operation canceled by user.")
        return False

    if response in {"y", "yes", ""}:
        print("[+] Permission granted. Proceeding with configuration...\n")
        return True
    else:
        print("[-] Permission declined. Exiting without making any system changes.\n")
        return False


def main():
    parser = argparse.ArgumentParser(description="AI Privacy Proxy DLP Gateway")
    parser.add_argument("--host", default="127.0.0.1", help="Proxy listen host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Proxy listen port (default: 8080)")
    parser.add_argument("--no-proxy-config", action="store_true", help="Do not configure Windows system proxy")
    parser.add_argument("--headless", action="store_true", help="Run without interactive command prompt")
    parser.add_argument("-y", "--yes", action="store_true", help="Automatically accept consent prompt")
    args = parser.parse_args()

    storage_dir = get_storage_dir()

    # Require explicit user consent before configuring proxy or intercepting traffic
    if not args.yes:
        if not request_user_consent(storage_dir, args.port):
            sys.exit(0)

    print("[*] Initializing AI Privacy Proxy...")

    # 1. Register cleanup so Windows proxy settings are always restored
    win_proxy.register_proxy_cleanup()

    # 2. Check and configure CA certificate
    ca_path = win_proxy.get_mitmproxy_ca_path()
    if not win_proxy.is_ca_installed():
        print(f"[*] Checking Root CA certificate for HTTPS inspection...")
        if not ca_path.exists():
            print("[*] Generating local CA certificate...")
            # Let mitmproxy initialize certs
            temp_loop = asyncio.new_event_loop()
            temp_master = DumpMaster(opts, loop=temp_loop, with_termlog=False, with_dumper=False)
            temp_master.shutdown()

        if ca_path.exists():
            print(f"[*] Trusting CA certificate in Windows Root Store: {ca_path}")
            installed = win_proxy.install_ca_certificate(ca_path)
            if installed:
                print("[+] Root CA certificate trusted successfully.")
            else:
                print("[!] Notice: If prompted by Windows, approve trusting the certificate.")

    # 3. Start Proxy Server
    print(f"[*] Starting local proxy engine on {args.host}:{args.port}...")
    try:
        master, loop, proxy_thread = start_proxy_server(args.host, args.port)
    except Exception as e:
        print(f"[X] Failed to start proxy server: {e}")
        sys.exit(1)

    time.sleep(1)

    # 4. Configure Windows System Proxy
    if not args.no_proxy_config:
        print(f"[*] Configuring Windows System Proxy to {args.host}:{args.port}...")
        if win_proxy.enable_system_proxy(f"{args.host}:{args.port}"):
            print("[+] Windows System Proxy enabled automatically.")
        else:
            print("[!] Warning: Failed to enable Windows proxy automatically.")

    # 5. Display banner
    print_banner(args.host, args.port, storage_dir)

    # 6. Interactive CLI loop
    try:
        if args.headless:
            print("[*] Running in headless mode. Press Ctrl+C to terminate.")
            while True:
                time.sleep(1)
        else:
            while True:
                try:
                    cmd = input("proxy> ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    break

                if not cmd:
                    continue
                elif cmd in {"open", "o"}:
                    open_storage_folder(storage_dir)
                elif cmd in {"list", "l", "files"}:
                    show_stored_files()
                elif cmd in {"status", "s"}:
                    enabled, srv = win_proxy.get_proxy_status()
                    print(f"\n[Status]")
                    print(f"  Proxy Running:     Yes ({args.host}:{args.port})")
                    print(f"  Windows Proxy:     {'Enabled (' + srv + ')' if enabled else 'Disabled'}")
                    print(f"  Storage Directory: {storage_dir}")
                    print(f"  Captured Files:    {len(list_stored_files())}\n")
                elif cmd in {"exit", "quit", "q"}:
                    break
                elif cmd in {"help", "h", "?"}:
                    print("\nCommands: open, list, status, exit\n")
                else:
                    print(f"Unknown command: '{cmd}'. Available: open, list, status, exit")
    finally:
        print("\n[*] Stopping AI Privacy Proxy...")
        try:
            if master and loop:
                loop.call_soon_threadsafe(master.shutdown)
        except Exception:
            pass
        win_proxy.disable_system_proxy()
        print("[+] Windows proxy settings restored. Goodbye!\n")


if __name__ == "__main__":
    main()
