#!/usr/bin/env python3
# filename: adrest_launcher.py
#
# Be your own help: plain names, kind errors, clear intention.
#
"""
AdREST Service Launcher – example client for start_site_server's dynamic port manager.

Usage:
  python adrest_launcher.py [SERVICE_KEY]

  SERVICE_KEY defaults to "com.workspace.supersystem".

This script:
  1. Reads the per‑user port‑registry file.
  2. If the requested service is already running, opens it in the browser.
  3. If not, offers to start start_site_server.py (which will become the
     AdREST manager or register with the existing one) and then opens the browser.

Place this file in the same directory as start_site_server.py.
Customise SERVICE_KEY if you are launching a different project.
"""

import json
import os
import platform
import socket
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

# ── Configuration (change these or override via environment) ─────────────
DEFAULT_SERVICE_KEY = "com.workspace.supersystem"
SERVER_SCRIPT_NAME  = "start_site_server.py"   # expected in the same directory

# ── Cross‑platform registry path ─────────────────────────────────────────
def get_registry_path():
    if platform.system() == "Windows":
        base = Path(os.environ.get("APPDATA",
                    Path.home() / "AppData" / "Roaming"))
    elif platform.system() == "Darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME",
                    Path.home() / ".local" / "share"))
    return base / "workspace-server" / "port-registry.json"

# ── Helpers ───────────────────────────────────────────────────────────────
def read_registry():
    """Return the full registry dict, or an empty dict."""
    reg_path = get_registry_path()
    if not reg_path.exists():
        return {}
    try:
        return json.loads(reg_path.read_text())
    except json.JSONDecodeError:
        return {}

def is_port_alive(port):
    """Return True if something is listening on 127.0.0.1:<port>."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        s.connect(('127.0.0.1', port))
        s.close()
        return True
    except Exception:
        return False

def launch_server():
    """Start start_site_server.py as a detached background process."""
    server_script = Path(__file__).resolve().parent / SERVER_SCRIPT_NAME
    if not server_script.exists():
        print(f"Cannot find {SERVER_SCRIPT_NAME}.")
        print("Make sure it is in the same folder as this launcher.")
        sys.exit(1)

    subprocess.Popen(
        [sys.executable, str(server_script)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

def open_url(entry):
    """Open the best available URL (HTTPS preferred) for a registry entry."""
    http_port  = entry.get("http_port")
    https_port = entry.get("https_port", 0)
    if https_port and https_port != http_port:
        url = f"https://127.0.0.1:{https_port}"
    else:
        url = f"http://127.0.0.1:{http_port}" if http_port else None

    if url:
        print(f"Opening {url} …")
        webbrowser.open(url)
    else:
        print("Could not determine a URL from the registry entry.")

# ── Main ──────────────────────────────────────────────────────────────────
def main():
    service_key = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SERVICE_KEY
    print(f"Looking for service '{service_key}' …")

    registry = read_registry()
    entry = registry.get(service_key)

    if entry and is_port_alive(entry["http_port"]):
        print("Service already running.")
        open_url(entry)
        return

    print("The service is not running.")
    choice = input("Start the server now? (y/n): ").strip().lower()
    if choice != "y":
        print("You can start the server manually by running start_site_server.py.")
        sys.exit(0)

    print("Launching server …")
    launch_server()

    # Wait up to 10 seconds for the registry to be written
    for _ in range(20):
        time.sleep(0.5)
        entry = read_registry().get(service_key)
        if entry and is_port_alive(entry["http_port"]):
            print("Server is ready.")
            open_url(entry)
            sys.exit(0)

    print("The server started but did not publish its port in time. "
          "Please try again in a moment.")
    sys.exit(1)

if __name__ == "__main__":
    main()
