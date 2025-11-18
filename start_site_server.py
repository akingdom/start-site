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
"""
VERSION = "1.0.14"
# author: Andrew Kingdom, Copyright(C)2025, All rights reserved, MIT License (CC-BY).
# the connection URL is shown when the script runs successfully.
# Future: We could detect failed HTTPS cert by fetching a file from HTTP and checking failure error (CORS, Cert, etc) and display user instructions accordingly.

# --- EDITABLE SERVER CONFIGURATION ---
class ServerConfig:
    def __init__(self):
        # TCP Port for HTTP traffic (will redirect to HTTPS_PORT if SECURE_SITE = True)
        self.HTTP_PORT: int = 8002
        # TCP Port for HTTPS traffic
        self.HTTPS_PORT: int = 8003
        # Folder containing web-site files. This site folder must be in the same 'parent' folder that contains this start_site.py script.
        self.SITE_FOLDER: str = "live"
        # Name of the preferred file to open when a web client doesn't specify a filename.
        self.DEFAULT_FILE: str = "index.html"
        # True for HTTPS/SSL traffic with HTTP redirect, else False for plain HTTP.
        self.SECURE_SITE: bool = True
        # Set to True to force regeneration of SSL certificates on startup, even if valid.
        # Set to False (default) to only regenerate if missing or expired.
        self.FORCE_CERTIFICATE_REGENERATION: bool = False
        # Set to True to auto-open the default page in a web browser on server startup
        # Set to False (default) if a web page or app will be opened independent of this script
        self.AUTO_OPEN_DEFAULT: bool = True
        # Optional delay (seconds) to avoid racing any already-open clients. Only relevant if AUTO_OPEN_DEFAULT is True.
        self.AUTO_OPEN_DELAY_SECONDS: int = 1
        # A fixed, well-known base port for the master server across all instances (used by site_manager.py). Generally this should never change.
        self.BASE_PORT: int = 8001
        # Application version number. Note: Leave this as-is, as it reflects the version above.
        self.VERSION: str = VERSION

# --- END EDITABLE SERVER CONFIGURATION ---


import os
import socket #obsolete?
import sys
import importlib
import asyncio
import webbrowser
import ipaddress
from datetime import datetime, timedelta, timezone
import subprocess
from pathlib import Path
import logging # Added for consistent logging
import re
from typing import Dict, Tuple, Any, Optional, Callable # Added for type hinting

# --- cryptography imports (modern style) ---
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

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

    def _ensure_dependencies(self, required_modules: Dict[str, Tuple[str, bool]]) -> Tuple[bool, str]:
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
            pip_install_cmd = "pip install " + " ".join(missing_critical_for_install)
            logging.info(f"Critical dependencies missing: {', '.join(missing_critical_for_install)}")
            logging.info(f"Recommended installation command: {pip_install_cmd}")

            if _AUTO_INSTALL_CHOICE is None:
                while True:
                    choice = input(
                        "Critical dependencies are missing. "
                        "Do you want to attempt automatic installation? (y/n/q for quit): "
                    ).lower().strip()
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
                    result = subprocess.run(
                        [sys.executable, "-m", "pip", "install", *missing_critical_for_install],
                        capture_output=True, text=True, check=False
                    )
                    
                    if result.returncode != 0:
                        error_msg = f"Failed to install dependencies: {result.stderr.strip()}"
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
                    error_msg = f"An unexpected error occurred during installation: {e}"
                    logging.error(error_msg)
                    logging.error("Please install dependencies manually: " + pip_install_cmd)
                    return False, error_msg
            else:
                error_msg = "User chose not to automatically install critical dependencies."
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
                    logging.error("Not all required cryptography sub-modules could be imported, even after initial checks.")
                    success = False
                    msg = "Incomplete cryptography setup."


        return success, msg

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
    # It looks for ''
    pykelet_comment_pattern = re.compile(r'', re.DOTALL)
    
    match = pykelet_comment_pattern.search(html_content)

    if match:
        # The captured group (.*?) is the content between 'PYKELET' and '-->'
        raw_comment_content = match.group(1)
        
        metadata = {}
        # Split by newlines and process each line
        lines = raw_comment_content.strip().split('\n')
        
        for line in lines:
            line_parts = line.strip().split(':', 1) # Split only on the first colon
            if len(line_parts) == 2:
                key = line_parts[0].strip().upper()
                value = line_parts[1].strip()
                if key: # Ensure key is not empty
                    metadata[key] = value
    
        return pykelet_meta if pykelet_meta else None
    return None # No PYKELET comment found


# --- Initialize ServerConfig and ServerCore ---
svr_config = ServerConfig()
svr_core = ServerCore(svr_config)

# --- Run initial dependency check for start_site_server ---
success, message = svr_core.ensure_server_core_dependencies()

if not success:
    print(f"\nFATAL ERROR: {message}")
    print("\nPlease resolve the dependency issues to run the server.")
    sys.exit(1)


# --- FastAPI App Initialization ---
app = svr_core.FastAPI() # Main FastAPI app for serving content
redirect_app = svr_core.FastAPI() # Separate FastAPI app for the HTTP redirect


# --- Load Site Endpoints (if site_endpoints.py exists) ---
try:
    if os.path.exists("site_endpoints.py"):
        import site_endpoints
        site_endpoints.init(app, svr_core)
        logging.info("site_endpoints are active")
    else:
        logging.info("site_endpoints unused (not found)")
except ImportError as e:
    logging.warning(f"site_endpoints unused (import error): {e}")
except Exception as e:
    logging.error(f"site_endpoints unused (other error): {e}")

# --- Load Site Manager (if site_manager.py exists) ---
try:
    if os.path.exists("site_manager.py"): # Check if the file exists
        import site_manager
        # Pass the main app, svr_core, and the necessary config values and functions
        # This makes site_manager truly self-contained after its init.
        site_manager.init(
            app,
            svr_core,
            config_file="registered_sites.json", # Consistent filename for registered sites
            base_port=svr_core.config.BASE_PORT, # Use the BASE_PORT from svr_core's config
            get_pykelet_func=get_pykelet_metadata # Pass the function to site_manager
        )
        logging.info("site_manager is active")
    else:
        # LOGGING CORRECTION: The message "No module named 'site_manager'" is a symptom
        # of the file not being found/imported, not the cause.
        logging.info("site_manager.py not found. Running as a standalone server.")
except ImportError as e:
    # This might happen if site_manager.py is present but has syntax errors etc.
    logging.warning(f"site_manager unused (import error): {e}")
except Exception as e:
    logging.error(f"site_manager unused (other error): {e}")


# 1.0.5 - now correctly handles subfolders
def secure_filepath(filepath):
    """Checks if a filepath is within the SITE_FOLDER."""
    normalized_site_path = os.path.abspath(os.path.normpath(svr_core.config.SITE_FOLDER))
    normalized_filepath = os.path.abspath(os.path.normpath(filepath))
    if not normalized_filepath.startswith(normalized_site_path):
        print(normalized_site_path)
        print(normalized_filepath)
        raise svr_core.HTTPException(status_code=403, detail="Forbidden")
    return normalized_filepath

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
                    secure_filepath(index_path) #Security check
                    return svr_core.FileResponse(index_path)
                except svr_core.HTTPException as e:
                    # Return HTTPException to ensure FastAPI handles it correctly
                    return svr_core.HTTPException(status_code=e.status_code, detail=e.detail)
    return response

class SecureStaticFiles(svr_core.StaticFiles): # Inherits from svr_core.StaticFiles
    async def get_response(self, path: str, scope):
        full_path = os.path.join(self.directory, path)
        try:
            secure_filepath(full_path)
            response = await super().get_response(path, scope)
            if path.endswith(".gz"):
                response.headers["Content-Encoding"] = "gzip"
                if "content-length" in response.headers:
                    del response.headers["content-length"]
                if path.endswith(".js.gz"):
                    response.headers["Content-Type"] = "application/javascript"
                elif path.endswith(".css.gz"):
                    response.headers["Content-Type"] = "text/css"
                else:
                    import mimetypes # mimetypes is standard, no need to put in svr_core
                    base_path, _ = os.path.splitext(path) # Get file without .gz
                    mime_type, _ = mimetypes.guess_type(base_path)
                    if mime_type:
                        response.headers["Content-Type"] = mime_type
            elif path.endswith(".br"):
                response.headers["Content-Encoding"] = "br"
                if "content-length" in response.headers:
                    del response.headers["content-length"]
                if path.endswith(".js.br"):
                    response.headers["Content-Type"] = "application/javascript"
                elif path.endswith(".css.br"):
                    response.headers["Content-Type"] = "text/css"
                else:
                    import mimetypes
                    base_path, _ = os.path.splitext(path) # Get file without .br
                    mime_type, _ = mimetypes.guess_type(base_path)
                    if mime_type:
                        response.headers["Content-Type"] = mime_type
            return response
        except svr_core.HTTPException as e:
            # Return HTTPException to ensure FastAPI handles it correctly
            return svr_core.HTTPException(status_code=e.status_code, detail=e.detail)

app.mount("/", SecureStaticFiles(directory=svr_core.config.SITE_FOLDER, html=False), name="static")


def get_lan_ip():
    """Gets the LAN IP address using netifaces or falls back to socket."""
    if svr_core.netifaces_module: # Use svr_core's reference
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
            logging.warning(f"Error using netifaces: {e}")

    try:
        # Fallback to socket if netifaces fails or is not installed
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        logging.warning(f"Error getting IP: {e}")
        return "127.0.0.1"

# SSL Certificate Generation (only if SECURE_SITE is True)
if svr_core.config.SECURE_SITE:
    def generate_self_signed_cert(cert_path="cert.pem", key_path="key.pem", force_regenerate: bool = False):
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
            ca_cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(ca_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=False,
                        key_encipherment=False,
                        content_commitment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=True,
                        crl_sign=True,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True
                )
                # Add a subject key identifier for CA
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
                .sign(ca_key, hashes.SHA256())
            )

            _write_pem(ca_key_path, ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
            _write_pem(ca_cert_path, ca_cert.public_bytes(serialization.Encoding.PEM))
            logging.info("LocalCA: Root CA created at %s", ca_cert_path)

        # Try installing CA to system trust (best-effort)
        def _install_ca_system_trust_once():
            if not ca_cert_path.exists():
                logging.error("LocalCA: CA cert not present for install attempt.")
                return False
            try:
                if sys.platform == "darwin":
                    cmd = ["sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot",
                           "-k", "/Library/Keychains/System.keychain", str(ca_cert_path)]
                    logging.info("LocalCA: Installing CA into macOS System keychain (may prompt for sudo)...")
                    subprocess.run(cmd, check=True, capture_output=True, text=True)
                    return True
                elif sys.platform == "win32":
                    cmd = ["certutil", "-addstore", "Root", str(ca_cert_path)]
                    logging.info("LocalCA: Installing CA into Windows Root store (requires admin)...")
                    subprocess.run(cmd, check=True, capture_output=True, text=True)
                    return True
                else:
                    dest = Path("/usr/local/share/ca-certificates") / (ca_cert_path.stem + ".crt")
                    logging.info("LocalCA: Installing CA into Linux trust store (may prompt for sudo)...")
                    subprocess.run(["sudo", "cp", str(ca_cert_path), str(dest)], check=True)
                    subprocess.run(["sudo", "update-ca-certificates"], check=True)
                    logging.info("LocalCA: update-ca-certificates completed.")
                    return True
            except subprocess.CalledProcessError as e:
                logging.error("LocalCA: system trust install failed: %s", getattr(e, "stderr", str(e)))
                return False
            except FileNotFoundError as e:
                logging.error("LocalCA: required system tool missing for install: %s", e)
                return False
            except Exception as e:
                logging.error("LocalCA: unexpected error during CA install: %s", e)
                return False

        # Ensure CA exists
        _create_ca_if_missing()

        # Attempt to install CA once per session (will set session flag afterwards)
        if not _CERT_TRUST_CHECK_DONE_THIS_SESSION:
            installed = _install_ca_system_trust_once()
            if installed:
                logging.info("LocalCA: CA install attempted (reported success).")
            else:
                logging.warning("LocalCA: CA install did not complete automatically; you may need to import %s manually.", ca_cert_path)
            _CERT_TRUST_CHECK_DONE_THIS_SESSION = True

        # --- Decide whether to (re)create the leaf cert ---
        need_create = True
        if os.path.exists(cert_path) and os.path.exists(key_path) and not force_regenerate:
            try:
                existing = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
                if existing.not_valid_after > datetime.utcnow() + timedelta(days=7):
                    need_create = False
                    logging.info("LocalCA: existing leaf cert valid until %s; skipping regen.", existing.not_valid_after.isoformat())
            except Exception:
                logging.warning("LocalCA: existing cert present but failed to parse; regenerating.")

        if need_create:
            logging.info("LocalCA: Creating new leaf certificate signed by local CA...")

            # Load CA key and cert
            ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
            ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())

            # Create leaf key
            leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            # Subject for leaf
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ])
            now = datetime.utcnow()
            builder = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(ca_cert.subject)
                .public_key(leaf_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=365))
            )

            # SANs
            san_list = [x509.DNSName("localhost")]
            try:
                san_list.append(x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")))
                san_list.append(x509.IPAddress(ipaddress.IPv6Address("::1")))
            except Exception:
                pass

            try:
                lan_ip = get_lan_ip()
                if lan_ip and lan_ip not in ("127.0.0.1", "::1", "0.0.0.0"):
                    if ":" in lan_ip:
                        san_list.append(x509.IPAddress(ipaddress.IPv6Address(lan_ip)))
                    else:
                        san_list.append(x509.IPAddress(ipaddress.IPv4Address(lan_ip)))
            except Exception:
                logging.debug("LocalCA: get_lan_ip failed or returned non-IP")

            builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)

            # Basic constraints: leaf is not a CA
            builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            # KeyUsage and EKU
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)

            # SKI from leaf public key
            builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)

            # AKI referencing the CA
            try:
                builder = builder.add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
                    critical=False
                )
            except Exception:
                # Fallback: if helper not available, create by matching CA's SKI if present
                try:
                    ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
                    builder = builder.add_extension(
                        x509.AuthorityKeyIdentifier(key_identifier=ca_ski, authority_cert_issuer=None, authority_cert_serial_number=None),
                        critical=False
                    )
                except Exception:
                    logging.debug("LocalCA: Could not add AKI by helper or CA SKI; continuing without explicit AKI (not ideal).")

            # Sign using the CA private key
            cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

            # write key + cert
            _write_pem(Path(key_path), leaf_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            _write_pem(Path(cert_path), cert.public_bytes(serialization.Encoding.PEM))
            logging.info("LocalCA: Wrote signed leaf cert %s and key %s", cert_path, key_path)
        else:
            logging.info("LocalCA: Using existing certificate: %s", cert_path)

        # Final note to user
        logging.warning("If your browser still warns, import the CA root (%s) manually into the System keychain and mark as trusted.", ca_cert_path)
        return cert_path, key_path


# HTTP Redirect Logic (only if SECURE_SITE is True)
if svr_core.config.SECURE_SITE:
    @redirect_app.middleware("http")
    async def redirect_to_https(request: svr_core.Request, call_next):
        if request.url.scheme == "http":
            new_url = request.url.replace(scheme="https", port=svr_core.config.HTTPS_PORT)
            return svr_core.RedirectResponse(url=new_url, status_code=301)
        return await call_next(request)


def auto_open_default_page():
    try:
        scheme = "https" if svr_core.config.SECURE_SITE else "http"
        port = svr_core.config.HTTPS_PORT if svr_core.config.SECURE_SITE else svr_core.config.HTTP_PORT
        url = f"{scheme}://localhost:{port}/{svr_core.config.DEFAULT_FILE}"
        logging.info(f"[server] Auto-opening {url}")
        webbrowser.open(url)
    except Exception as e:
        logging.warning(f"Auto-open failed: {e}")

async def run_servers():
    ip = get_lan_ip()
    cert_path, key_path = None, None
    ssl_params = {}

    if svr_core.config.SECURE_SITE:
        cert_path, key_path = generate_self_signed_cert(force_regenerate=svr_core.config.FORCE_CERTIFICATE_REGENERATION)
        ssl_params = {"ssl_certfile": cert_path, "ssl_keyfile": key_path}
        print(f"\nServing web files\n from '{svr_core.config.SITE_FOLDER}' directory\n Connect to 'https://{ip}:{svr_core.config.HTTPS_PORT}'\n (or https://localhost:{svr_core.config.HTTPS_PORT})\n (ver {svr_core.config.VERSION})")
        print(f"HTTP redirects from 'http://{ip}:{svr_core.config.HTTP_PORT}' to HTTPS.")
    else:
        print(f"\nServing web files\n from '{svr_core.config.SITE_FOLDER}' directory\n Connect to 'http://{ip}:{svr_core.config.HTTP_PORT}'\n (ver {svr_core.config.VERSION})")

    print("=== FastAPI routes ===")
    for route in app.routes:
        if hasattr(route, "endpoint"):
            # For routes attached to APIRouter, the endpoint's __module__ helps identify origin.
            module_name = route.endpoint.__module__.split('.')[-1] if route.endpoint.__module__ else 'unknown'
            print(f"{route.path:<20} → {route.endpoint.__name__} (from {module_name}.py)")
        elif hasattr(route, "app"): # e.g., for StaticFiles mount and APIRouter mounts
            # For mounted APIRouters, the route.app will be an instance of FastAPI, but we want the APIRouter's name.
            # This is a heuristic; direct inspection of APIRouter's name isn't always straightforward post-mount.
            # We can imply it if it's a known pattern like '/api/manager'
            if route.path == '/api/manager':
                 print(f"{route.path:<20} ↪ mounted app: Site Manager API")
            else:
                print(f"{route.path:<20} ↪ mounted app: {type(route.app).__name__}")
        else:
            print(f"{route.path:<20} ↪ [unknown route type]")

    server_configs = [
        # Main HTTPS server
        # Use uvicorn_module from svr_core. This assumes uvicorn.Config and uvicorn.Server are accessible via it.
        svr_core.uvicorn_module.Config(app, host="0.0.0.0", port=svr_core.config.HTTPS_PORT, lifespan="off", **ssl_params)
    ]

    if svr_core.config.SECURE_SITE:
        # HTTP redirect server
        server_configs.append(
            svr_core.uvicorn_module.Config(redirect_app, host="0.0.0.0", port=svr_core.config.HTTP_PORT, lifespan="off")
        )

    if svr_core.config.AUTO_OPEN_DEFAULT:
        async def _delayed_open():
            await asyncio.sleep(svr_core.config.AUTO_OPEN_DELAY_SECONDS)
            # Run sync webbrowser.open without blocking event loop
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, auto_open_default_page)
        asyncio.create_task(_delayed_open())

    servers = [svr_core.uvicorn_module.Server(config) for config in server_configs]

    await asyncio.gather(*[server.serve() for server in servers])
 

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Serve a local folder as a website.")
    parser.add_argument("--port", type=int, default=None, help="Override HTTP_PORT from config.")
    parser.add_argument("--https-port", type=int, default=None, help="Override HTTPS_PORT from config.")
    parser.add_argument("--secure", type=str, default=None, help="Override SECURE_SITE (true/false).")
    parser.add_argument("--force-cert-regen", action="store_true", help="Force SSL certificate regeneration.")
    parser.add_argument("--auto-open", action="store_true", help="Auto-open the default page on startup.")
    parser.add_argument("--open-delay", type=int, default=None, help="Seconds to delay before auto-opening.")

    args = parser.parse_args()

    # Apply command line overrides
    if args.port is not None:
        svr_config.HTTP_PORT = args.port
    if args.https_port is not None:
        svr_config.HTTPS_PORT = args.https_port
    if args.secure is not None:
        svr_config.SECURE_SITE = args.secure.lower() == 'true'
    if args.force_cert_regen:
        svr_config.FORCE_CERTIFICATE_REGENERATION = True
    if args.auto_open:
        svr_config.AUTO_OPEN_DEFAULT = True
    if args.open_delay is not None:
        svr_config.AUTO_OPEN_DELAY_SECONDS = args.open_delay

    # Check if this server instance is being launched by the master (site_manager)
    # This is a simple heuristic based on command-line arguments.
    # If both --port and --secure are provided, assume it's a client instance.
    is_client_instance = args.port is not None and args.secure is not None
    
    if not is_client_instance:
        # Only if not a client instance, attempt to register with a master.
        # This part assumes a master is running on BASE_PORT.
        # This is where a client would attempt to register itself with the master server.
        # The master server would then assign it a specific port.
        master_server_url = f"http://127.0.0.1:{svr_config.BASE_PORT}/api/manager/register_site"
        logging.info(f"Attempting to connect to master server at {master_server_url} for registration...")
        
        # This part requires an async call, but we are in a sync context.
        # A simple non-blocking HTTP client or a separate thread could be used.
        # For simplicity in this example, we will just log the attempt.
        # In a real-world scenario, you'd use a library like 'httpx' or 'requests' (in a thread/asyncio.run).
        
        # Note: If start_site_server.py *is* the master (i.e., site_manager.py exists
        # and it's being run directly without --port/--secure), it won't try to register with itself.
        # The logic below is for when a *different* instance is the master.
        
        # For a truly robust system, this registration might be:
        # 1. An HTTP request to the master from the client
        # 2. The master's responsibility to monitor and launch clients (as site_manager does)
        # 
        # Given the current design, if *this* instance is meant to be the master,
        # it should just proceed to run run_servers() and `site_manager` handles things.
        # If it's a client, it should register *then* run run_servers() with its assigned port.
        #
        # For now, we'll assume the master is launched separately, and client instances
        # launched by the master will receive --port and --secure.
        # If this instance is NOT a client instance (i.e., it's a standalone or the master itself),
        # it just runs the server as configured.
        
        # You would typically have a dedicated client-side registration function here
        # that uses something like `httpx` to send the registration request.
        # For now, we'll just log if it's *not* a client instance.
        
        if not os.path.exists("site_manager.py"):
             logging.info("Not running as a site manager. This instance is a standalone server.")
        else:
             logging.info("Site manager found. This instance is acting as the master server.")
        
    #TODO - check if we still need this stub
    # Check if the HTTP redirect is still needed based on potentially updated SECURE_SITE
    # If hub logic changed SECURE_SITE to False, the redirect server should not run
    #if not svr_core.config.SECURE_SITE and redirect_app in [c.app for c in server_configs if hasattr(c, 'app')]:
    #    # This part is tricky. If svr_core.config.SECURE_SITE changed during hub logic,
    #    # the run_servers function needs to be re-evaluated or adjusted.
    #    # For simplicity, we'll let run_servers handle it based on the final svr_core.config.SECURE_SITE.
    #    pass 

    # If hub logic modified ports/secure status, reflect that in run_servers arguments
    # No, run_servers directly accesses svr_core.config, so changes made to svr_core.config.HTTP_PORT
    # and svr_core.config.SECURE_SITE by the hub logic will automatically be picked up.
    # In start_site_server.py, around where you call asyncio.run
    try:
        asyncio.run(run_servers())
    except KeyboardInterrupt:
        logging.info("Server manually stopped via Ctrl+C. Exiting gracefully.")
        # Add any *additional* cleanup code here that needs to run
        # after asyncio.run finishes due to KeyboardInterrupt
        pass # No extra cleanup needed if Uvicorn handles it all
    except Exception as e:
        logging.critical(f"An unexpected error occurred during server runtime: {e}")
        sys.exit(1)
    finally:
        # This block *always* runs, whether an error occurred or not,
        # and whether KeyboardInterrupt was caught or not.
        # Good for ensuring final resources are released.
        logging.info("Application finished.")
