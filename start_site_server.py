#!/usr/bin/env python3
# start_site_server.py
# -*- coding: utf-8 -*-
"""
Serves a local folder as a website.

IMPORTANT: HTTPS service may require restarting the web browser if a security warning is present after this script tries to create and install a local certificate.

This file consolidates all core server logic, including dependency management.
Extensions such as /api/<name> are handled by site_endpoints.py (if present).
Master functionality for managing and launching other local server instances (and client registration)
is handled by site_manager.py (if present).
- Optional HTTPS (SECURE_SITE) with inline Local CA + signed localhost leaf
- Optional HTTP->HTTPS redirect on separate port
- Minimal cryptography dependency handles
- Certificate management is encapsulated in CertificateManager for easy removal.
"""
# VERSION => see ServerConfig
# author: Andrew Kingdom, Copyright(C)2025-2026, All rights reserved, MIT License (CC-BY).
# the connection URL is shown when the script runs successfully.
# Future: We could detect failed HTTPS cert by fetching a file from HTTP and checking failure error (CORS, Cert, etc) and display user instructions accordingly.


# --- RECOMMENDATION: use site_config.py to create/update site_config.yaml ---
# --- Edit site_config.yaml to customise; start_site_server.py will load it. ---

from dataclasses import dataclass, field
from typing import List
# --- EDITABLE SERVER CONFIGURATION ---
@dataclass
class ServerConfig:
    # ── Version and external config ─────────────────────────────────────
    VERSION_note = "Application version (do not change)"
    VERSION: str = "2.1.1"                 # CHANGED: version bumped

    # ── Network ports ──────────────────────────────────────────────────
    HTTP_PORT_note = "TCP Port for HTTP traffic (will redirect to HTTPS_PORT if SECURE_SITE = True)"
    HTTP_PORT: int = 9000

    HTTPS_PORT_note = "TCP Port for HTTPS traffic"
    HTTPS_PORT: int = 9001

    # ── Static content ─────────────────────────────────────────────────
    SITE_FOLDER_note = "Folder containing web-site files. This site folder must be in the same 'parent' folder that contains this start_site.py script."
    SITE_FOLDER: str = 'live'

    DEFAULT_FILE_note = "Name of the preferred file to open when a web client doesn't specify a filename."
    DEFAULT_FILE: str = 'index.html'

    ALLOWED_SYMLINK_TARGETS_note = (
        "A list of allowed symlink target *directories*.\n"
        "Each entry may be absolute or relative to the start_site_server.py location.\n"
        "e.g.     \"live/assets\",       # relative to SITE_FOLDER\n"
        "e.g.     \"/Users/fred/assets/images\",  # absolute"
    )
    ALLOWED_SYMLINK_TARGETS: List[str] = field(default_factory=lambda: ['../../js'])

    # ── Security (HTTPS) ───────────────────────────────────────────────
    SECURE_SITE_note = "True for HTTPS/SSL traffic with HTTP redirect, else False for plain HTTP."
    SECURE_SITE: bool = False

    FORCE_CERTIFICATE_REGENERATION_note = (
        "Set to True to force regeneration of SSL certificates on startup, even if valid.\n"
        "Set to False (default) to only regenerate if missing or expired."
    )
    FORCE_CERTIFICATE_REGENERATION: bool = False

    # ── User experience ─────────────────────────────────────────────────
    AUTO_OPEN_DEFAULT_note = (
        "Set to True to auto-open the default page in a web browser on server startup\n"
        "Set to False (default) if a web page or app will be opened independent of this script"
    )
    AUTO_OPEN_DEFAULT: bool = False

    AUTO_OPEN_DELAY_SECONDS_note = "Optional delay (seconds) to avoid racing any already-open clients. Only relevant if AUTO_OPEN_DEFAULT is True."
    AUTO_OPEN_DELAY_SECONDS: int = 1

    # ── Port management (AdREST) ───────────────────────────────────────
    ADREST_ENABLED_note = "Enable AdREST dynamic port management. Set to False to run as a standalone server with specific port numbers."
    ADREST_ENABLED: bool = True

    # ── Runtime behaviour ──────────────────────────────────────────────
    SHUTDOWN_TIMEOUT_note = "Time in seconds to graciously (safely, politely) shutdown the server when the user presses Control-C on keyboard"
    SHUTDOWN_TIMEOUT: int = 5

    ENABLE_LIFESPAN_note = "Enable Uvicorn lifespan events (startup/shutdown). Default off."
    ENABLE_LIFESPAN: bool = True

    SSL_CERT_FILE_note = (
        "Custom SSL certificate and key file paths. If empty, the server\n"
        "auto‑generates a self‑signed certificate via CertificateManager."
    )
    SSL_CERT_FILE: str = ''
    SSL_KEY_FILE: str = ''

    SERVE_STATIC_FILES_note = "Whether to serve static files from SITE_FOLDER.\nSet to False for a pure API / WebSocket server."
    SERVE_STATIC_FILES: bool = True

    ENABLE_LOOPBACK_ONLY_note = "Hide from other devices on your network (recommended = True)"
    ENABLE_LOOPBACK_ONLY: bool = True

    DIAGNOSTICS_ENABLED_note = (
        "Enable per‑service Markdown diagnostic snapshots to be written.\n"
        "Set to False to disable file‑based diagnostics.\n"
        "(the /api/diagnostics endpoint remains active regardless)."
    )
    DIAGNOSTICS_ENABLED: bool = True
# --- END EDITABLE SERVER CONFIGURATION ---

# --- END RECOMMENDATION ---


from dataclasses import dataclass, field, fields, asdict
from typing import List, Optional, Any, Dict, Tuple, Callable, Type, TypeVar
from datetime import datetime, timedelta, timezone
import asyncio
import hashlib
import importlib
import importlib.util
import ipaddress
import json
import logging
import os
import platform
import re
import signal
import socket
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

# --- cryptography imports (modern style) ---
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# --- Signal handling for graceful shutdown ---
#     Guarantee the lifespan shutdown and lock release run
_should_exit = False
def _shutdown_handler(signum, frame):
    global _should_exit
    if _should_exit:
        # Already shutting down – force exit
        sys.exit(1)
    _should_exit = True
    print("Received shutdown signal, cancelling all tasks...")
    # Cancel all asyncio tasks (will stop the server)
    for task in asyncio.all_tasks():
        task.cancel()
signal.signal(signal.SIGTERM, _shutdown_handler)
signal.signal(signal.SIGINT, _shutdown_handler)   # also handle Ctrl+C gracefully

# Get the directory where the script is located
script_dir = os.path.dirname(os.path.abspath(__file__))

# Change the current working directory to the script's directory
os.chdir(script_dir)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Shared Session-Level State ---
# Global variable to remember user's choice for auto-installation during the session
_AUTO_INSTALL_CHOICE: Optional[bool] = None # None: not asked, True: auto-install, False: do not auto-install

# Global flag to track if certificate trust store check has been performed this session
_CERT_TRUST_CHECK_DONE_THIS_SESSION = False


# --- Server Core and Dependency Management ---
# The goal of ServerCore here is primarily to:
# 1. Hold the ServerConfig.
# 2. Centralize runtime dependency checking/auto-install.
# 3. Provide a common context object for other modules (site_endpoints, site_manager).
class ServerCore:
    """
    A shared context object for the server instance, containing imported modules
    and core utilities.
    """
    def __init__(self, config: ServerConfig): # For tracking successfully imported modules
        self.config = config # Reference to the ServerConfig object
        self._imported_modules_cache: Dict[str, Any] = {} # Populated by _ensure_dependencies. For tracking successfully imported modules.
        
        # References to original modules/classes, populated after successful dependency check
        # These will be directly assigned from the import attempts.
        self.netifaces_module: Optional[Any] = None
        self.uvicorn_module: Optional[Any] = None
        self.fastapi_module: Optional[Any] = None

        # Directly exposed callable/class references, if needed by other parts of the system
        # These are now pulled from where they are naturally imported, not forced under fastapi_module.
        self.FastAPI: Optional[Callable] = None
        self.Request: Optional[Callable] = None
        self.HTTPException: Optional[Callable] = None
        self.FileResponse: Optional[Callable] = None
        self.RedirectResponse: Optional[Callable] = None
        self.StaticFiles: Optional[Callable] = None
        self.APIRouter: Optional[Callable] = None # ADDED: For site_manager to use APIRouter from FastAPI

    def _ensure_dependencies(self, required_modules: Dict[str, Tuple[str, bool]], interactive: bool = True) -> Tuple[bool, str]:
        """
        Internal method to check for and optionally install required Python modules.
        Note that calling this is a convenience, not a requirement.
        Args:
            required_modules: A dictionary where keys are module names (e.g., "fastapi")
                              and values are tuples (pip_install_name, is_critical_boolean).

        Returns:
            Tuple[bool, str]: (True if all critical dependencies are met, error_message if not).
        """
        global _AUTO_INSTALL_CHOICE
        missing_critical_for_install = []
        missing_optional = []
        for module_name, (pip_name, is_critical) in required_modules.items():
            if module_name in self._imported_modules_cache:
                continue
            try:
                mod = importlib.import_module(module_name)
                self._imported_modules_cache[module_name] = mod
            except ImportError:
                if is_critical:
                    missing_critical_for_install.append(pip_name)
                else:
                    missing_optional.append(pip_name)

        if missing_critical_for_install:
            if not interactive:
                return False, f"❌ Missing dependencies: {', '.join(missing_critical_for_install)}. Please install them manually."
            pip_install_cmd = "pip install " + " ".join(missing_critical_for_install)
            logging.info(f"Critical dependencies missing: {', '.join(missing_critical_for_install)}")
            logging.info(f"Recommended installation command: {pip_install_cmd}")
            if _AUTO_INSTALL_CHOICE is None:
                if not sys.stdin.isatty():
                    # non‑interactive – print the command and fail gracefully
                    print(f"❌ Critical dependencies missing: {', '.join(missing_critical_for_install)}")
                    print(f"   Install them manually: pip install {' '.join(missing_critical_for_install)}")
                    return False, "Non‑interactive environment – please install missing dependencies manually."
                while True:
                    try:
                        choice = input("Critical dependencies are missing. Do you want to attempt automatic installation? (y/n/q for quit): ").lower().strip()
                    except Exception:
                        # Non-interactive environment: default to not auto-install
                        choice = "n"
                    if choice == 'y':
                        _AUTO_INSTALL_CHOICE = True
                        break
                    elif choice == 'n':
                        _AUTO_INSTALL_CHOICE = False
                        break
                    elif choice == 'q':
                        return False, "User chose to quit due to missing critical dependencies."
                    else:
                        print("Invalid input. Please enter 'y', 'n', or 'q'.")
            if _AUTO_INSTALL_CHOICE:
                logging.info(f"Attempting to install critical dependencies: {' '.join(missing_critical_for_install)}")
                try:
                    result = subprocess.run([sys.executable, "-m", "pip", "install", *missing_critical_for_install], capture_output=True, text=True, check=False)
                    if result.returncode != 0:
                        error_msg = f"❌  Failed to install dependencies: {result.stderr.strip()}"
                        logging.error(error_msg)
                        logging.error("Please install them manually: " + pip_install_cmd)
                        return False, error_msg
                    logging.info("Installation attempt finished. Re-checking dependencies...")
                    # Re-attempt import for newly installed critical modules
                    for module_name, (pip_name, is_critical) in required_modules.items():
                        if is_critical and pip_name in missing_critical_for_install: # Only re-check critical ones that were just installed
                            try:
                                mod = importlib.import_module(module_name)
                                self._imported_modules_cache[module_name] = mod
                            except ImportError:
                                pass # Still missing, will be caught by final_missing_critical check
                except Exception as e:
                    error_msg = f"❌  An unexpected error occurred during installation: {e}"
                    logging.error(error_msg)
                    logging.error("Please install dependencies manually: " + pip_install_cmd)
                    return False, error_msg
            else:
                error_msg = "❌  User chose not to automatically install critical dependencies."
                logging.error(error_msg)
                logging.error("Please install them manually: " + pip_install_cmd)
                return False, error_msg

        final_missing_critical = []
        for module_name, (pip_name, is_critical) in required_modules.items():
            if is_critical and module_name not in self._imported_modules_cache:
                final_missing_critical.append(pip_name)

        if final_missing_critical:
            error_msg = f"❌ Critical dependencies are still missing: {', '.join(final_missing_critical)}"
            logging.error(error_msg)
            logging.error("The server cannot start. Please install them manually: pip install " + " ".join(final_missing_critical))
            return False, error_msg
        if missing_optional:
            logging.warning(f"⚠️ Optional dependencies are missing: {', '.join(missing_optional)}")
            logging.warning("Some features may be unavailable. Install with: pip install " + " ".join(missing_optional))
        # --- Dynamic attribute assignment ---
        # Attach imported modules to self with safe attribute names for dot-access.
        # e.g., 'numpy' -> self.numpy_module, 'fastapi.responses' -> self.fastapi_responses_module
        for mod_name, mod_obj in list(self._imported_modules_cache.items()):
            # Prefer a short attribute name using the last dotted segment, e.g. 'numpy' -> 'numpy_module'
            short = mod_name.split('.')[-1].replace('-', '_')
            attr_name = f"{short}_module"
            # Avoid overwriting explicit attributes like FastAPI, FileResponse, etc.
            if hasattr(self, attr_name):
                # If attribute exists, try a more specific name
                attr_name = mod_name.replace('.', '_').replace('-', '_') + "_module"
            try:
                setattr(self, attr_name, mod_obj)
                logging.debug(f"Attached module {mod_name} as attribute {attr_name} on ServerCore")
            except Exception as e:
                logging.debug(f"Could not attach module {mod_name} to ServerCore: {e}")
                pass
        return True, ""

    load_endpoint_modules = _ensure_dependencies  # convenience alias
    
    def get_module(self, name: str):
        """Convenience Module Getter for endpoints.
           e.g. numpy_mod = svr_core.get_module("numpy")
        """
        try:
            return self._imported_modules_cache[name]
        except KeyError:
            raise RuntimeError(f"Module {name!r} not loaded")

    def ensure_server_core_dependencies(self) -> Tuple[bool, str]:
        """Checks and loads core server dependencies."""
        _REQUIRED_MODULES = {
            "uvicorn": ("uvicorn", True),
            "fastapi": ("fastapi", True),
            # Important: Based on your previous working code, StaticFiles comes from fastapi.staticfiles
            # and FileResponse/RedirectResponse from fastapi.responses.
            # We explicitly list these as separate "modules" for importlib to check,
            # but they are part of the 'fastapi' pip package.
            "fastapi.responses": ("fastapi", True), # Ensures fastapi is installed for responses
            "fastapi.staticfiles": ("fastapi", True), # Ensures fastapi is installed for staticfiles
            "fastapi.routing": ("fastapi", True), # ADDED: Explicitly check for APIRouter parent module
            "fastapi.encoders": ("fastapi", True), # ADDED: Ensure fastapi is installed for jsonable_encoder
        }
        if self.config.SECURE_SITE:
            # Only import the directly loadable sub-modules for cryptography
            _REQUIRED_MODULES["cryptography"] = ("cryptography", True)
            _REQUIRED_MODULES["cryptography.x509"] = ("cryptography", True)
            _REQUIRED_MODULES["cryptography.hazmat.primitives"] = ("cryptography", True)
            _REQUIRED_MODULES["cryptography.hazmat.backends"] = ("cryptography", True)
        _REQUIRED_MODULES["netifaces"] = ("netifaces", False) # Netifaces is optional for IP detection
        success, msg = self._ensure_dependencies(_REQUIRED_MODULES)
        if success:
            self.uvicorn_module = self._imported_modules_cache["uvicorn"]
            self.fastapi_module = self._imported_modules_cache["fastapi"]
            # Assign the components as they were originally imported
            self.FastAPI = self.fastapi_module.FastAPI
            self.Request = self.fastapi_module.Request
            self.HTTPException = self.fastapi_module.HTTPException
            self.FileResponse = self._imported_modules_cache["fastapi.responses"].FileResponse
            self.RedirectResponse = self._imported_modules_cache["fastapi.responses"].RedirectResponse
            self.StaticFiles = self._imported_modules_cache["fastapi.staticfiles"].StaticFiles
            self.APIRouter = self._imported_modules_cache["fastapi.routing"].APIRouter # ADDED: Store APIRouter reference
            # ADDED: Make jsonable_encoder available through the fastapi_module as well
            # It's not a class to be stored directly on self, but accessed via module.
            # self.jsonable_encoder = self._imported_modules_cache["fastapi.encoders"].jsonable_encoder # This line is not needed here as it's accessed via `fastapi_module.encoders.jsonable_encoder`
            self.netifaces_module = self._imported_modules_cache.get("netifaces")
            # Correctly assign cryptography components by getting imported module objects
            if self.config.SECURE_SITE:
                # Ensure all necessary cryptography sub-modules were successfully imported and cached
                if all(key in self._imported_modules_cache for key in [
                    "cryptography.x509",
                    "cryptography.hazmat.primitives",
                    "cryptography.hazmat.backends"
                ]):
                    x509_module = self._imported_modules_cache["cryptography.x509"]
                    primitives_module = self._imported_modules_cache["cryptography.hazmat.primitives"]
                    backends_module = self._imported_modules_cache["cryptography.hazmat.backends"]

                    self.cryptography_x509 = x509_module
                    self.cryptography_NameOID = x509_module.oid.NameOID
                    self.cryptography_hashes = primitives_module.hashes
                    self.cryptography_serialization = primitives_module.serialization
                    self.cryptography_rsa = primitives_module.asymmetric.rsa
                    self.cryptography_default_backend = backends_module.default_backend
                else:
                    # If any sub-module failed to load, mark all as None and report an issue
                    # This case should ideally be caught by _ensure_dependencies, but as a safeguard.
                    logging.error("❌  Not all required cryptography sub-modules could be imported, even after initial checks.")
                    success = False
                    msg = "Incomplete cryptography setup."

        return success, msg

    # ── timestamp helper ──────────────────────────────────────────────────────
    @staticmethod
    def _now_iso() -> str:
        """Return current UTC timestamp as ISO‑8601 string with explicit UTC marker."""
        return datetime.now(timezone.utc).isoformat() + "Z"

    # ── end ServerCore class ───


# --- Helper: dict with notes from dataclass ---   # CHANGED: added
def _asdict_with_notes(cls_or_inst) -> Dict[str, Any]:
    """Convert a dataclass instance or class to a dict including its _note fields."""
    if isinstance(cls_or_inst, type):
        inst = cls_or_inst()
    else:
        inst = cls_or_inst
    d = asdict(inst)
    for f in fields(inst):
        note_key = f.name + "_note"
        if hasattr(inst.__class__, note_key):
            d[note_key] = getattr(inst.__class__, note_key)
    return d


# --- Helper functions (no globals) ---
# ADDED: Function to extract PYKELET metadata from HTML.
# This needs to be defined at the top-level of start_site_server.py
# because it's passed as a callable to site_manager.
def get_pykelet_metadata(html_content: str) -> Optional[Dict]:
    """
    Replicates the getPykeletFromComment JS function in Python.
    Extracts PYKELET metadata pairs from an HTML content string.
    Returns a dictionary of metadata (e.g., {"FILENAME": "index.html"}) or None if not found.
    """
    # Regex to find the entire PYKELET comment block
    pykelet_comment_pattern = re.compile(r'<!--\s*PYKELET\b(.*?)-->', re.DOTALL)
    match = pykelet_comment_pattern.search(html_content)

    if match:
        # The captured group (.*?) is the content between 'PYKELET' and '-->'
        raw_comment_content = match.group(1)
        pykelet_meta = {}
        # Split by newlines and process each line
        lines = raw_comment_content.strip().split('\n')
        for line in lines:
            line_parts = line.strip().split(':', 1) # Split only on the first colon
            if len(line_parts) == 2:
                key = line_parts[0].strip().upper()
                value = line_parts[1].strip()
                if key: # Ensure key is not empty
                    pykelet_meta[key] = value
        return pykelet_meta if pykelet_meta else None
    return None # No PYKELET comment found

# ── Path + Diagnostic helpers ────────────────────────────────────────────────
def _user_data_dir():
    """Return the per‑user data directory for workspace runtime files."""
    if platform.system() == "Windows":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif platform.system() == "Darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "workspace-server"

def _get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def _port_is_free(port):
    """Return True if port can be bound on 127.0.0.1."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", port))
            return True
    except OSError:
        return False

def _check_identity(port, expected_key):
    import urllib.request, urllib.error
    try:
        url = f"http://127.0.0.1:{port}/api/identity"
        with urllib.request.urlopen(url, timeout=1.0) as resp:
            data = json.loads(resp.read().decode())
            return data.get("key") == expected_key
    except Exception:
        return False

# ── Helper to reuse a port if still free, else allocate a new one ─
def _reuse_or_allocate_port(registry, key, label="port"):
    port = None
    entry = registry.get(key)
    if entry:
        candidate = entry.get("http_port")
        if candidate and _port_is_free(candidate):
            port = candidate
            logging.info("Reusing previous %s %d", label, port)
    if port is None:
        port = _get_free_port()
        logging.info("Allocated new %s %d", label, port)
    return port

def _diagnostics_dir():
    """Return the path to the diagnostics snapshot directory."""
    return _user_data_dir() / "diagnostics"


def _atomic_write_md(path: Path, content: str) -> None:
    """Atomically write a Markdown diagnostic file (temp + rename)."""
    tmp = path.with_suffix(".tmp")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)


def _stale_pid(pid: int) -> bool:
    """Return True if the given PID is not currently running."""
    if pid <= 0:
        return True
    try:
        os.kill(pid, 0)  # signal 0 checks existence only
        return False
    except (OSError, ProcessLookupError):
        return True

def write_diagnostics_snapshot(svr_core, registry, our_key, cert_info=None):
    """Write (or update) the Markdown diagnostic file for this service."""
    if not svr_core.config.DIAGNOSTICS_ENABLED:
        return

    diag_dir = _diagnostics_dir()
    diag_dir.mkdir(parents=True, exist_ok=True)
    diag_path = diag_dir / f"{our_key}.md"
    server_path = os.path.dirname(os.path.abspath(__file__))

    http_port = svr_core.config.HTTP_PORT
    https_port = svr_core.config.HTTPS_PORT if svr_core.config.SECURE_SITE else 0
    pid = os.getpid()
    uptime = int(time.time() - _svr_start_time) if '_svr_start_time' in globals() else 0
    lines = [f"# {our_key} — Service State", f"**Reported at:** {svr_core._now_iso()}", "", "## Server",
             f"- Server Folder: {server_path}", f"- Status: **running**", f"- PID: {pid}",
             f"- Ports: HTTP {http_port}" + (f", HTTPS {https_port}" if https_port else ""),
             f"- Secure site: {'yes' if svr_core.config.SECURE_SITE else 'no'}",
             f"- Uptime: {uptime // 3600}h {(uptime % 3600) // 60}m {uptime % 60}s",
             f"- Python: {sys.version.split()[0]}", f"- Platform: {platform.system()}-{platform.release()}",
             f"- Version: {svr_core.config.VERSION}", ""]
    if cert_info:
        lines.extend(["## SSL Certificate", f"- Valid: {'yes' if cert_info.get('valid') else '**NO — EXPIRED OR INVALID**'}",
                     f"- Expires: {cert_info['expires']}" if cert_info.get('expires') else "",
                     f"- CA trusted: {'yes' if cert_info.get('ca_trusted') else '**no — browser may warn**'}", ""])
    if registry:
        lines.append("## Registry (from port-registry.json)")
        lines.append("| Service | HTTP Port | HTTPS Port | Alive |")
        lines.append("|---------|-----------|------------|-------|")
        for key, entry in sorted(registry.items()):
            http = entry.get("http_port", "—")
            https = entry.get("https_port", 0)
            https_str = str(https) if https else "—"
            alive = "✅" if not _stale_pid(entry.get("pid", -1)) else "❌"
            lines.append(f"| {key} | {http} | {https_str} | {alive} |")
        lines.append("")
    content = "\n".join(lines) + "\n"
    _atomic_write_md(diag_path, content)

def _cleanup_diagnostics(registry):
    """Remove diagnostic files for services not in the live registry."""
    diag_dir = _diagnostics_dir()
    if not diag_dir.exists():
        return
    live_keys = set(registry.keys())
    for md_file in diag_dir.glob("*.md"):
        key = md_file.stem
        if key not in live_keys:
            # also check PID staleness as a double-check
            try:
                content = md_file.read_text(encoding="utf-8")
                pid_match = re.search(r"PID:\s*(\d+)", content)
                if pid_match and _stale_pid(int(pid_match.group(1))):
                    md_file.unlink()
                    logging.info("Removed stale diagnostic file: %s", md_file.name)
            except Exception:
                pass

def get_lan_ip():
    """Gets the LAN IP address using netifaces or falls back to socket."""
    # This function is used inside CertificateManager, which runs after svr_core is set.
    # We use the global svr_core (set in __main__ after init).
    global svr_core
    if svr_core and svr_core.netifaces_module:
        try:
            for interface in svr_core.netifaces_module.interfaces():
                addresses = svr_core.netifaces_module.ifaddresses(interface)
                if svr_core.netifaces_module.AF_INET in addresses:
                    for addr_info in addresses[svr_core.netifaces_module.AF_INET]:
                        ip = addr_info['addr']
                        if ip != '127.0.0.1':
                            return ip
                if svr_core.netifaces_module.AF_INET6 in addresses:
                    for addr_info in addresses[svr_core.netifaces_module.AF_INET6]:
                        ip = addr_info['addr']
                        if not ip.startswith('fe80') and ip != '::1':
                            return ip
        except Exception as e:
            logging.warning(f"⚠️ Error using netifaces: {e}")

    try:
        # Fallback to socket if netifaces fails or is not installed
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        logging.warning(f"⚠️ Error getting IP: {e}")
        return "127.0.0.1"


# ── Certificate Manager (encapsulates all certificate activities) ─────────
class CertificateManager:
    """
    Manages local CA and SSL certificate generation / installation.
    All primary certificate logic is contained here for easy excision.
    """
    def __init__(self):
        pass

    @staticmethod
    def _cert_fingerprint(path):
        """Return sha256 fingerprint of file contents in hex (lowercase)."""
        import hashlib
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    @staticmethod
    def _cert_is_valid(cert_path):
        """Return True if cert exists and is not expired (uses stdlib ssl parser)."""
        import ssl
        try:
            cert = ssl._ssl._test_decode_cert(cert_path)
            not_after_str = cert.get("notAfter")
            if not not_after_str:
                return False
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            return datetime.utcnow() < not_after
        except Exception:
            return False

    @classmethod
    def ensure_certificate_exists_and_valid(cls, cert_path, key_path):
        """True if both files exist and cert is not expired."""
        if not (os.path.exists(cert_path) and os.path.exists(key_path)):
            return False
        if not cls._cert_is_valid(cert_path):
            return False
        return True

    @staticmethod
    def system_has_cert_with_fingerprint(common_name, local_fp):
        """
        macOS: fetch PEM from keychain and compare SHA-256 digest.
        Returns True if a cert with the given CN and identical digest exists.
        """
        try:
            out = subprocess.check_output(["security", "find-certificate", "-c", common_name, "-p", "/Library/Keychains/System.keychain"], stderr=subprocess.STDOUT)
            sys_fp = hashlib.sha256(out).hexdigest()
            return sys_fp == local_fp
        except subprocess.CalledProcessError:
            return False
        except FileNotFoundError:
            return False
        except Exception:
            return False

    @classmethod
    def install_certificate_if_needed(cls, ca_cert_path, common_name="Local Dev CA"):
        """
        Install CA root into system trust store only if not present or mismatched fingerprint.
        macOS only. (Linux/Windows handled by your generator’s platform branches if needed.)
        """
        local_fp = cls._cert_fingerprint(ca_cert_path)

        if cls.system_has_cert_with_fingerprint(common_name, local_fp):
            print("✓ CA certificate already trusted in system keychain — skipping install.")
            return

        print("→ Installing CA certificate into system trust store (will prompt for sudo)...")
        subprocess.check_call([
            "sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot",
            "-k", "/Library/Keychains/System.keychain", str(ca_cert_path)
        ])
        print("✓ CA certificate installed and trusted.")

    @classmethod
    def generate_self_signed_cert(cls, cert_path="cert.pem", key_path="key.pem", force_regenerate: bool = False):
        """
        Generate a *CA-signed* localhost certificate (drop-in replacement).
        - Ensures a local root CA exists under ~/.localdev/ca/
        - Attempts to install the CA into system trust (best-effort, once per session)
        - Issues a leaf certificate signed by the CA with correct EKU/KU and SANs
        - Regenerates leaf if missing, near expiry, or force_regenerate True
    
        Returns (cert_path_str, key_path_str)
        """
        global _CERT_TRUST_CHECK_DONE_THIS_SESSION
        cert_path = str(cert_path)
        key_path = str(key_path)
        # --- CA storage paths ---
        ca_base = Path.home() / ".localdev" / "ca"
        ca_key_path = ca_base / "ca.key.pem"
        ca_cert_path = ca_base / "ca.cert.pem"
        ca_base.mkdir(parents=True, exist_ok=True)
        def _write_pem(path: Path, data: bytes, mode: int = 0o600):
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "wb") as f:
                f.write(data)
            try:
                os.chmod(path, mode)
            except Exception:
                pass
        # Create CA if missing (persistent, long-lived)
        def _create_ca_if_missing(force: bool = False):
            if ca_key_path.exists() and ca_cert_path.exists() and not force:
                logging.debug("LocalCA: existing CA found")
                return
            logging.info("LocalCA: Generating root CA...")
            ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "Local Dev CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local Development"),
            ])
            now = datetime.utcnow()
            ca_cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).add_extension(x509.KeyUsage(digital_signature=False, key_encipherment=False, content_commitment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True).add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False).sign(ca_key, hashes.SHA256()))
            _write_pem(ca_key_path, ca_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))
            _write_pem(ca_cert_path, ca_cert.public_bytes(serialization.Encoding.PEM))
            logging.info("LocalCA: Root CA created at %s", ca_cert_path)
        # Ensure CA exists
        _create_ca_if_missing()
        # Attempt to install CA once per session (fingerprint-aware helper)
        if not _CERT_TRUST_CHECK_DONE_THIS_SESSION:
            try:
                cls.install_certificate_if_needed(ca_cert_path, common_name="Local Dev CA")
            except Exception as e:
                logging.warning("⚠️ LocalCA: CA install failed or requires manual import: %s", e)
            _CERT_TRUST_CHECK_DONE_THIS_SESSION = True
        # --- Decide whether to (re)create the leaf cert ---
        need_create = True
        if os.path.exists(cert_path) and os.path.exists(key_path) and not force_regenerate:
            try:
                existing = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
                if existing.not_valid_after_utc > datetime.now(timezone.utc) + timedelta(days=7):
                    need_create = False
                    logging.info("LocalCA: existing leaf cert valid until %s; skipping regen.", existing.not_valid_after_utc.isoformat())
            except Exception:
                logging.warning("⚠️ LocalCA: existing cert present but failed to parse; regenerating.")
        if need_create:
            logging.info("LocalCA: Creating new leaf certificate signed by local CA...")
            # Load CA key and cert
            ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
            ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
            # Create leaf key
            leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            # Subject for leaf
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
            now = datetime.utcnow()
            builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=365)))
            # SANs
            san_list = [x509.DNSName("localhost")]
            try:
                san_list.append(x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")))
                san_list.append(x509.IPAddress(ipaddress.IPv6Address("::1")))
            except Exception:
                pass

            if not svr_core.config.ENABLE_LOOPBACK_ONLY:
                try:
                    lan_ip = get_lan_ip()
                    if lan_ip and lan_ip not in ("127.0.0.1", "::1", "0.0.0.0"):
                        if ":" in lan_ip:
                            san_list.append(x509.IPAddress(ipaddress.IPv6Address(lan_ip)))
                        else:
                            san_list.append(x509.IPAddress(ipaddress.IPv4Address(lan_ip)))
                except Exception:
                    logging.debug("LocalCA: get_lan_ip failed or returned non-IP")
                    pass
            builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)
            builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            builder = builder.add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=False, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
            try:
                builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
            except Exception:
                try:
                    ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
                    builder = builder.add_extension(x509.AuthorityKeyIdentifier(key_identifier=ca_ski, authority_cert_issuer=None, authority_cert_serial_number=None), critical=False)
                except Exception:
                    logging.debug("LocalCA: Could not add AKI; continuing without explicit AKI.")
                    pass
            cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
            _write_pem(Path(key_path), leaf_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
            _write_pem(Path(cert_path), cert.public_bytes(serialization.Encoding.PEM))
            logging.info("LocalCA: Wrote signed leaf cert %s and key %s", cert_path, key_path)
        else:
            logging.info("LocalCA: Using existing certificate: %s", cert_path)
        logging.warning("⚠️ If your browser still warns, import the CA root (%s) manually into the System keychain and mark as trusted.", ca_cert_path)
        return cert_path, key_path


# --- Global variables (will be set in __main__ after config loading) ---
app = None
redirect_app = None
_svr_start_time = None
svr_core = None

# --- Path security function (uses svr_core.config) ---
def secure_filepath(filepath):
    site_root = os.path.realpath(svr_core.config.SITE_FOLDER)
    real = os.path.realpath(filepath)
    if not hasattr(secure_filepath, "_printed"):
        print("\n--- Symlink whitelist resolution ---")
        print("SITE ROOT:", site_root)
        for target in svr_core.config.ALLOWED_SYMLINK_TARGETS:
            allowed_real = os.path.realpath(
                target if os.path.isabs(target)
                else os.path.join(site_root, target)
            )
            print(f"  ALLOWED: {target}  →  {allowed_real}")
        secure_filepath._printed = True
        print("\n")
    # 1. Allow anything inside live/ directly
    if real == site_root or real.startswith(site_root + os.sep):
        return real
    # 2. Check whitelisted symlink target dirs
    for allowed in svr_core.config.ALLOWED_SYMLINK_TARGETS:
        allowed_real = os.path.realpath(
            allowed if os.path.isabs(allowed)
            else os.path.join(site_root, allowed)
        )
        if real == allowed_real or real.startswith(allowed_real + os.sep):
            return real
    # 3. Reject everything else
    print("SECURITY BLOCKED PATH:")
    print("  site root:", site_root)
    print("  real path:", real)
    raise svr_core.HTTPException(403, "Forbidden symlink target")


# --- Initialization function that depends on svr_core ---
# Create FastAPI apps, routes, middleware, and security helpers after config is loaded."""
def init_server(core: ServerCore):
    global app, redirect_app, _svr_start_time, svr_core
    svr_core = core
    # svr_core is already set by the caller before calling this function.
    # We assign it here for completeness, but the caller already set the global.
    _svr_start_time = time.time()
    app = core.FastAPI()
    redirect_app = core.FastAPI()

    # Exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request, exc):
        logging.exception("Unhandled exception")
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=500,
            content={"message": "Something went wrong. Check the diagnostic snapshot for details."}
        )

    # Middleware
    @app.middleware("http")
    async def add_index_html(request: svr_core.Request, call_next):
        response = await call_next(request)
        if response.status_code == 404:
            path = request.url.path.lstrip("/")
            full_path = os.path.join(svr_core.config.SITE_FOLDER, path)
            if os.path.isdir(full_path):
                index_path = os.path.join(full_path, svr_core.config.DEFAULT_FILE)
                if os.path.exists(index_path):
                    try:
                        secure_filepath(index_path)  # Security check
                        return svr_core.FileResponse(index_path)
                    except svr_core.HTTPException as e:
                        raise e
        return response

    # HTTP Redirect logic (only if SECURE_SITE is True)
    if svr_core.config.SECURE_SITE:
        @redirect_app.middleware("http")
        async def redirect_to_https(request: svr_core.Request, call_next):
            if request.url.scheme == "http":
                new_url = request.url.replace(scheme="https", port=svr_core.config.HTTPS_PORT)
                return svr_core.RedirectResponse(url=new_url, status_code=301)
            return await call_next(request)

# --- Functions that use global svr_core and app (defined after init_server) ---
def _load_site_endpoints(app_instance, core):
    """Load site_endpoints.py after ports have been finalised.
       Uses core.merged_config (if present) to build an EndpointsConfig.
    """
    try:
        if os.path.exists("site_endpoints.py"):
            import site_endpoints
            logging.info("site_endpoints initialising on ports http %d / https %d",
                         core.config.HTTP_PORT,
                         core.config.HTTPS_PORT)
            # If we have a merged config, try to build EndpointsConfig
            if hasattr(core, 'merged_config') and core.merged_config:
                # Extract fields that belong to EndpointsConfig
                endpoint_fields = {f.name for f in fields(site_endpoints.EndpointsConfig)}
                endpoint_dict = {k: v for k, v in core.merged_config.items() if k in endpoint_fields}
                if endpoint_dict:
                    endpoint_config = site_endpoints.EndpointsConfig(**endpoint_dict)
                    site_endpoints.init(app_instance, core, endpoint_config=endpoint_config)
                else:
                    site_endpoints.init(app_instance, core)
            else:
                site_endpoints.init(app_instance, core)
            logging.info("site_endpoints active")
        else:
            logging.info("site_endpoints unused (not found)")
    except ImportError as e:
        logging.warning("⚠️ site_endpoints unused (import error): %s", e)
    except Exception as e:
        logging.error("❌  site_endpoints unused (other error): %s", e)

def auto_open_default_page():
    try:
        scheme = "https" if svr_core.config.SECURE_SITE else "http"
        port = svr_core.config.HTTPS_PORT if svr_core.config.SECURE_SITE else svr_core.config.HTTP_PORT
        url = f"{scheme}://localhost:{port}/{svr_core.config.DEFAULT_FILE}"
        logging.info(f"[server] Auto-opening {url}")
        webbrowser.open(url)
    except Exception as e:
        logging.warning(f"⚠️ Auto-open failed: {e}")

async def run_servers(manager_config=None):
    ip = "127.0.0.1" if svr_core.config.ENABLE_LOOPBACK_ONLY else get_lan_ip()
    cert_path, key_path = None, None
    ssl_params = {}

    # ── Define SecureStaticFiles (local to this function) ──
    class SecureStaticFiles(svr_core.StaticFiles):
        def __init__(self, *args, allowed_symlink_targets=None, **kwargs):
            self.allowed_symlink_targets = allowed_symlink_targets or []
            super().__init__(*args, **kwargs)

        async def get_response(self, path: str, scope):
            joined = os.path.join(self.directory, path)
            real_path = os.path.realpath(joined)
            site_root = os.path.realpath(self.directory)
            secure_filepath(real_path)  # uses the global secure_filepath defined in init_server
            is_inside_site_root = real_path.startswith(site_root + os.sep)
            if not is_inside_site_root:
                if not os.path.exists(real_path):
                    raise svr_core.HTTPException(404, "File not found")
                resp = svr_core.FileResponse(real_path)
            else:
                resp = await super().get_response(path, scope)

            # GZIP / BROTLI handling (unchanged)
            if path.endswith(".gz"):
                resp.headers["Content-Encoding"] = "gzip"
                resp.headers.pop("content-length", None)
                if path.endswith(".js.gz"):
                    resp.headers["Content-Type"] = "application/javascript"
                elif path.endswith(".css.gz"):
                    resp.headers["Content-Type"] = "text/css"
                else:
                    import mimetypes
                    base, _ = os.path.splitext(path)
                    mime, _ = mimetypes.guess_type(base)
                    if mime:
                        resp.headers["Content-Type"] = mime
            elif path.endswith(".br"):
                resp.headers["Content-Encoding"] = "br"
                resp.headers.pop("content-length", None)
                if path.endswith(".js.br"):
                    resp.headers["Content-Type"] = "application/javascript"
                elif path.endswith(".css.br"):
                    resp.headers["Content-Type"] = "text/css"
                else:
                    import mimetypes
                    base, _ = os.path.splitext(path)
                    mime, _ = mimetypes.guess_type(base)
                    if mime:
                        resp.headers["Content-Type"] = mime
            return resp

    # ── Mount static files (after routes have been added) ──
    if svr_core.config.SERVE_STATIC_FILES:
        app.mount("/", SecureStaticFiles(
            directory=svr_core.config.SITE_FOLDER,
            html=False,
            allowed_symlink_targets=svr_core.config.ALLOWED_SYMLINK_TARGETS
        ), name="static")

    if svr_core.config.SECURE_SITE:
        # Use custom certificate files if provided, otherwise generate via CertificateManager
        if svr_core.config.SSL_CERT_FILE and svr_core.config.SSL_KEY_FILE:
            cert_path = svr_core.config.SSL_CERT_FILE
            key_path = svr_core.config.SSL_KEY_FILE
            if not os.path.exists(cert_path) or not os.path.exists(key_path):
                raise FileNotFoundError("Custom SSL certificate files not found")
            logging.info("Using custom SSL certificate: %s", cert_path)
        else:
            cert_path, key_path = CertificateManager.generate_self_signed_cert(
                cert_path="cert.pem",
                key_path="key.pem",
                force_regenerate=svr_core.config.FORCE_CERTIFICATE_REGENERATION
            )
        ssl_params = {"ssl_certfile": cert_path, "ssl_keyfile": key_path}

    if svr_core.config.SECURE_SITE:
        print(f"\nServing web files\n from '{svr_core.config.SITE_FOLDER}' directory\n"
              f" Connect to 'https://{ip}:{svr_core.config.HTTPS_PORT}'\n"
              f" (or https://localhost:{svr_core.config.HTTPS_PORT})\n"
              f" (ver {svr_core.config.VERSION})")
        print(f"HTTP redirects from 'http://{ip}:{svr_core.config.HTTP_PORT}' to HTTPS.")
    else:
        print(f"\nServing web files\n from '{svr_core.config.SITE_FOLDER}' directory\n"
              f" Connect to 'http://{ip}:{svr_core.config.HTTP_PORT}'\n"
              f" (ver {svr_core.config.VERSION})")

    print("=== FastAPI routes ===")
    for route in app.routes:
        if hasattr(route, "endpoint"):
            module_name = route.endpoint.__module__.split('.')[-1] if route.endpoint.__module__ else 'unknown'
            print(f"{route.path:<20} → {route.endpoint.__name__} (from {module_name}.py)")
        elif hasattr(route, "app"):
            if route.path == '/api/manager':
                print(f"{route.path:<20} ↪ mounted app: AdREST Manager API")
            else:
                print(f"{route.path:<20} ↪ mounted app: {type(route.app).__name__}")
        else:
            print(f"{route.path:<20} ↪ [unknown route type]")

    server_configs = []
    lifespan_mode = "on" if svr_core.config.ENABLE_LIFESPAN else "off"

    if svr_core.config.SECURE_SITE:
        server_configs.append(
            svr_core.uvicorn_module.Config(redirect_app, host=ip, port=svr_core.config.HTTP_PORT, lifespan="off", timeout_graceful_shutdown=svr_core.config.SHUTDOWN_TIMEOUT)
        )
        server_configs.append(
            svr_core.uvicorn_module.Config(app, host=ip, port=svr_core.config.HTTPS_PORT, lifespan=lifespan_mode, timeout_graceful_shutdown=svr_core.config.SHUTDOWN_TIMEOUT, **ssl_params)
        )
    else:
        server_configs.append(
            svr_core.uvicorn_module.Config(app, host=ip, port=svr_core.config.HTTP_PORT, lifespan=lifespan_mode, timeout_graceful_shutdown=svr_core.config.SHUTDOWN_TIMEOUT)
        )

    if manager_config is not None:
        server_configs.append(manager_config)

    if svr_core.config.AUTO_OPEN_DEFAULT:
        async def _delayed_open():
            await asyncio.sleep(svr_core.config.AUTO_OPEN_DELAY_SECONDS)
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, auto_open_default_page)
        asyncio.create_task(_delayed_open())

    servers = [svr_core.uvicorn_module.Server(config) for config in server_configs]
    await asyncio.gather(*[server.serve() for server in servers])


# --- Main entry point ---
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Serve a local folder as a website.")
    parser.add_argument("--port", type=int, default=None, help="Override HTTP_PORT from config.")
    parser.add_argument("--https-port", type=int, default=None, help="Override HTTPS_PORT from config.")
    parser.add_argument("--secure", type=str, default=None, help="Override SECURE_SITE (true/false).")
    parser.add_argument("--force-cert-regen", action="store_true", help="Force SSL certificate regeneration.")
    parser.add_argument("--auto-open", action="store_true", help="Auto-open the default page on startup.")
    parser.add_argument("--open-delay", type=int, default=None, help="Seconds to delay before auto-opening.")
    parser.add_argument("--disable-adrest", action="store_true", help="Disable AdREST dynamic port management for this run.")
    parser.add_argument("--config", help="Path to external config file")  # DEPRECATED – kept for backward compatibility

    args = parser.parse_args()

    logging.warning("️❤️️  Starting ─── ")

    # 1. Load default ServerConfig dict with notes
    server_dict = _asdict_with_notes(ServerConfig)

    # 2. Load dependencies first (so we can import site_endpoints safely)
    svr_config = ServerConfig()  # temporary, will be replaced later
    svr_core_handover = ServerCore(svr_config)
    success, message = svr_core_handover.ensure_server_core_dependencies()
    if not success:
        print(f"\nFATAL ERROR: {message}")
        sys.exit(1)

    # 3. Load EndpointsConfig if site_endpoints exists
    endpoints_dict = None
    try:
        import site_endpoints
        if hasattr(site_endpoints, 'EndpointsConfig'):
            endpoints_dict = _asdict_with_notes(site_endpoints.EndpointsConfig)
    except ImportError:
        logging.info("site_endpoints.py not found; skipping endpoint config.")
    except Exception as e:
        logging.warning("⚠️  Failed to import site_endpoints for config: %s", e)

    # 4. Merge: endpoints overrides server
    merged_dict = server_dict.copy()
    if endpoints_dict:
        for k, v in endpoints_dict.items():
            merged_dict[k] = v

    # 5. Apply YAML overrides from site_config.yaml (if site_config.py exists)
    yaml_loaded = False
    try:
        import site_config
        if hasattr(site_config, 'load_config'):
            yaml_overrides = site_config.load_config()
            if yaml_overrides:
                # Check version parity
                yaml_version = yaml_overrides.get('VERSION')
                if yaml_version and yaml_version != ServerConfig.VERSION:
                    print(f"⚠️  External config version {yaml_version} does not match script version {ServerConfig.VERSION} – some fields may be outdated.")
                for k, v in yaml_overrides.items():
                    merged_dict[k] = v
                logging.info("Applied overrides from site_config.yaml")
                yaml_loaded = True
    except ImportError:
        logging.info("site_config.py not found; no YAML overrides.")
    except Exception as e:
        logging.warning("⚠️ Error loading site_config: %s", e)
    # If no YAML config was loaded, suggest creating one
    if not yaml_loaded and not Path("site_config.yaml").exists():
        print("\n💡 No site_config.yaml found. To customise settings, create one with:")
        print("   python site_config.py --create")
        print("   Then edit site_config.yaml to your preferences.\n")

    # 6. Apply CLI overrides
    if args.port is not None:
        merged_dict['HTTP_PORT'] = args.port
    if args.https_port is not None:
        merged_dict['HTTPS_PORT'] = args.https_port
    if args.secure is not None:
        merged_dict['SECURE_SITE'] = args.secure.lower() == 'true'
    if args.force_cert_regen:
        merged_dict['FORCE_CERTIFICATE_REGENERATION'] = True
    if args.auto_open:
        merged_dict['AUTO_OPEN_DEFAULT'] = True
    if args.open_delay is not None:
        merged_dict['AUTO_OPEN_DELAY_SECONDS'] = args.open_delay
    if args.disable_adrest:
        merged_dict['ADREST_ENABLED'] = False

    # 7. Construct final ServerConfig
    server_fields = {f.name for f in fields(ServerConfig)}
    server_final = {}
    for k, v in merged_dict.items():
        if k in server_fields:
            server_final[k] = v
    final_server_config = ServerConfig(**server_final)

    # 8. Handover to global svr_core and init server
    svr_core = ServerCore(final_server_config)
    # Carry over loaded modules from the temporary core
    svr_core._imported_modules_cache = svr_core_handover._imported_modules_cache
    svr_core.uvicorn_module = svr_core_handover.uvicorn_module
    svr_core.fastapi_module = svr_core_handover.fastapi_module
    svr_core.FastAPI = svr_core_handover.FastAPI
    svr_core.Request = svr_core_handover.Request
    svr_core.HTTPException = svr_core_handover.HTTPException
    svr_core.FileResponse = svr_core_handover.FileResponse
    svr_core.RedirectResponse = svr_core_handover.RedirectResponse
    svr_core.StaticFiles = svr_core_handover.StaticFiles
    svr_core.APIRouter = svr_core_handover.APIRouter
    svr_core.netifaces_module = svr_core_handover.netifaces_module
    if hasattr(svr_core_handover, 'cryptography_x509'):
        svr_core.cryptography_x509 = svr_core_handover.cryptography_x509
        svr_core.cryptography_NameOID = svr_core_handover.cryptography_NameOID
        svr_core.cryptography_hashes = svr_core_handover.cryptography_hashes
        svr_core.cryptography_serialization = svr_core_handover.cryptography_serialization
        svr_core.cryptography_rsa = svr_core_handover.cryptography_rsa
        svr_core.cryptography_default_backend = svr_core_handover.cryptography_default_backend

    # Store merged config for later use by _load_site_endpoints
    svr_core.merged_config = merged_dict

    init_server(svr_core)

    # 5. Validate site folder
    site = Path(svr_core.config.SITE_FOLDER)
    if not site.is_dir():
        sys.exit(f"SITE_FOLDER '{site}' does not exist or is not a directory.")

    # Validate symlink targets
    site_root = os.path.realpath(svr_core.config.SITE_FOLDER)
    for target in svr_core.config.ALLOWED_SYMLINK_TARGETS:
        allowed_real = os.path.realpath(target if os.path.isabs(target) else os.path.join(site_root, target))
        # Check if allowed_real is inside site_root (basic security)
        # (No commonpath check needed because secure_filepath will block later; just warn)
        if not os.path.commonpath([site_root, allowed_real]) == site_root:
            logging.warning("⚠️ Symlink target %s resolves outside site root (%s) → may be misconfigured.", target, allowed_real)

    # 6. AdREST dynamic port assignment (if enabled) – unchanged from your original
    explicit_ports = (args.port is not None) or (args.https_port is not None)
    manager_config = None

    if svr_config.ADREST_ENABLED and not explicit_ports:
        # ── cross‑platform file locking ─────────────────────────────────
        if platform.system() == "Windows":
            import msvcrt
            def _lock_file(fh):
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            def _unlock_file(fh):
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            def _lock_file(fh):
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            def _unlock_file(fh):
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

        # ── per‑user registry files ─────────────────────────────────────
        data_dir = _user_data_dir()
        data_dir.mkdir(parents=True, exist_ok=True)
        registry_path = data_dir / "port-registry.json"
        lock_path = data_dir / "port-registry.lock"

        manager_key = "services.adrest"
        our_key = os.environ.get("WORKSPACE_SERVICE_KEY", "com.workspace.supersystem")

        # Every managed server exposes its identity
        @app.get("/api/identity")
        async def _identity():
            return {"key": our_key}

        # ── acquire / fail to acquire the user‑level lock ────────────────
        lock_file = open(lock_path, "a")
        try:
            _lock_file(lock_file)
            we_are_manager = True
        except (IOError, OSError):
            we_are_manager = False

        if we_are_manager:
            # ── WE ARE THE ADREST MANAGER ────────────────────────────────
            registry = {}
            if registry_path.exists():
                try:
                    registry = json.loads(registry_path.read_text())
                except json.JSONDecodeError:
                    pass

            # Remove stale entries
            for key in list(registry.keys()):
                entry = registry[key]
                port = entry.get("http_port")
                if port and not _check_identity(port, key):
                    logging.info("Removing stale registry entry '%s'", key)
                    del registry[key]

            # Reuse or allocate main HTTP/HTTPS ports
            http_port = _reuse_or_allocate_port(registry, our_key, "HTTP port")
            if svr_config.SECURE_SITE:
                # HTTPS port reuse
                https_port = None
                existing = registry.get(our_key)
                if existing and existing.get("https_port") and _port_is_free(existing["https_port"]):
                    https_port = existing["https_port"]
                    logging.info("Reusing previous HTTPS port %d", https_port)
                if https_port is None:
                    https_port = _get_free_port()
                    logging.info("Allocated new HTTPS port %d", https_port)
            else:
                https_port = http_port  # unused field in registry but kept for consistency

            # Reuse or allocate AdREST manager port
            adrest_port = _reuse_or_allocate_port(registry, manager_key, "AdREST manager port")

            now = datetime.now(timezone.utc).isoformat()
            # Update registry
            registry[manager_key] = {
                "http_port": adrest_port,
                "pid": os.getpid(),
                "last_seen": now,
            }
            registry[our_key] = {
                "http_port": http_port,
                "https_port": https_port,
                "pid": os.getpid(),
                "last_seen": now,
            }
            registry_path.write_text(json.dumps(registry, indent=2, ensure_ascii=False))

            svr_core.config.HTTP_PORT = http_port
            if svr_config.SECURE_SITE:
                svr_core.config.HTTPS_PORT = https_port

            _load_site_endpoints(app, svr_core)

            diag_dir = _diagnostics_dir()
            diag_dir.mkdir(parents=True, exist_ok=True)
            logging.info("Diagnostics: %s", diag_dir / f"{our_key}.md")
            write_diagnostics_snapshot(svr_core, registry, our_key, cert_info=None)

            def _release_lock():
                try:
                    lock_file.close()
                except Exception:
                    pass
            
            import atexit
            atexit.register(_release_lock)
            
            # ── lifespan + manager app ─────────────────────────────────
            from contextlib import asynccontextmanager
            @asynccontextmanager
            async def lifespan(app: svr_core.FastAPI):
                yield
                print(f"\nCommencing graceful shutdown (within {svr_core.config.SHUTDOWN_TIMEOUT} seconds)\n")
                _release_lock()

            manager_app = svr_core.FastAPI(lifespan=lifespan)

            @manager_app.post("/api/manager/register")
            async def _register_service(request: svr_core.Request):
                body = await request.json()
                key = body.get("key")
                if not key:
                    raise svr_core.HTTPException(400, detail="'key' is required.")
                reg = json.loads(registry_path.read_text()) if registry_path.exists() else {}
                if key in reg:
                    existing = reg[key]
                    if _check_identity(existing["http_port"], key):
                        raise svr_core.HTTPException(409, detail=f"Service '{key}' is already registered.")
                    else:
                        del reg[key]
                new_http = _get_free_port()
                new_https = _get_free_port() if svr_config.SECURE_SITE else 0
                reg[key] = {
                    "http_port": new_http,
                    "https_port": new_https,
                    "pid": -1,
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                }
                registry_path.write_text(json.dumps(reg, indent=2, ensure_ascii=False))
                logging.info("Registered service '%s' on ports %d/%d", key, new_http, new_https)
                return {"http_port": new_http, "https_port": new_https}

            @manager_app.delete("/api/manager/unregister")
            async def _unregister_service(request: svr_core.Request):
                body = await request.json()
                key = body.get("key")
                if not key:
                    raise svr_core.HTTPException(400, detail="'key' is required.")
                if key == manager_key:
                    raise svr_core.HTTPException(400, detail="Cannot unregister the manager.")
                reg = json.loads(registry_path.read_text()) if registry_path.exists() else {}
                reg.pop(key, None)
                registry_path.write_text(json.dumps(reg, indent=2, ensure_ascii=False))
                return {"status": "ok"}

            @manager_app.get("/api/manager/status")
            async def _manager_status():
                reg = json.loads(registry_path.read_text()) if registry_path.exists() else {}
                return {"registry": reg}

            manager_config = svr_core.uvicorn_module.Config(
                manager_app, host="127.0.0.1", port=adrest_port, lifespan="on",
                timeout_graceful_shutdown=svr_core.config.SHUTDOWN_TIMEOUT
            )
            app.state.workspace_lock_file = lock_file

            logging.info(
                "AdREST manager active on ports %d (HTTP) / %d (HTTPS), manager HTTP on %d",
                http_port, https_port, adrest_port
            )

        else:
            # ── WE ARE A CLIENT ─────────────────────────────────────────
            lock_file.close()
            import urllib.request
            import urllib.error

            reg = {}
            if registry_path.exists():
                try:
                    reg = json.loads(registry_path.read_text())
                except json.JSONDecodeError:
                    pass
            manager_entry = reg.get(manager_key)
            if not manager_entry:
                raise RuntimeError("No AdREST manager found in registry. Start the first server without explicit ports first.")
            manager_port = manager_entry.get("http_port")
            if not manager_port:
                raise RuntimeError("AdREST manager entry is missing port information.")

            manager_url = f"http://127.0.0.1:{manager_port}/api/manager/register"
            try:
                data = json.dumps({"key": our_key}).encode("utf-8")
                req = urllib.request.Request(manager_url, data=data, method="POST",
                                             headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    if resp.status != 200:
                        raise RuntimeError(f"Registration failed: {resp.read().decode()}")
                    result = json.loads(resp.read().decode())
                    svr_core.config.HTTP_PORT = result["http_port"]
                    svr_core.config.HTTPS_PORT = result["https_port"]
                    logging.info("Registered as '%s' on ports %d/%d", our_key, result["http_port"], result["https_port"])

                    _load_site_endpoints(app, svr_core)

                    diag_dir = _diagnostics_dir()
                    diag_dir.mkdir(parents=True, exist_ok=True)
                    logging.info("Diagnostics: %s", diag_dir / f"{our_key}.md")
                    write_diagnostics_snapshot(svr_core, reg, our_key, cert_info=None)
            except urllib.error.HTTPError as e:
                raise RuntimeError(f"Registration failed: {e.read().decode()}") from e
            except urllib.error.URLError as e:
                raise RuntimeError(f"Cannot contact the AdREST manager on port {manager_port}. "
                                   "Is the first server instance running?") from e

    else:
        # Standalone mode – no AdREST
        _load_site_endpoints(app, svr_core)

    # 7. Run the server
    try:
        asyncio.run(run_servers(manager_config=manager_config))
    except asyncio.CancelledError:
        logging.info("Server cancelled due to termination signal (SIGTERM).")
    except KeyboardInterrupt:
        logging.info("Server manually stopped via Ctrl+C. Exiting gracefully.")
    except Exception as e:
        logging.critical(f"An unexpected error occurred during server runtime: {e}")
        sys.exit(1)
    finally:
        logging.info("Application finished.")
        pass
