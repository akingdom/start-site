#!/usr/bin/env python3
# start_site_server.py
"""
Serves a local folder as a website.
This file consolidates all core server logic, including dependency management.
Extensions such as /api/<name> are handled by site_endpoints.py (if present).
Master functionality for managing and launching other local server instances (and client registration)
is handled by site_manager.py (if present).
"""
VERSION = "1.0.11"
# author: Andrew Kingdom, Copyright(C)2025, All rights reserved, MIT License (CC-BY).
# the connection URL is shown when the script runs successfully.

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
        # A fixed, well-known base port for the master server across all instances (used by site_manager.py). Generally this should never change.
        self.BASE_PORT: int = 8001
        # Application version number. Note: Leave this as-is, as it reflects the version above.
        self.VERSION: str = VERSION

# --- END EDITABLE SERVER CONFIGURATION ---


import os
import socket
import sys
import importlib
import asyncio
from datetime import datetime, timedelta, timezone
import subprocess
import logging # Added for consistent logging
import re
from typing import Dict, Tuple, Any, Optional, Callable # Added for type hinting

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

        # Cryptography components are now directly referenced from the main 'cryptography' import
        self.cryptography_x509: Optional[Any] = None
        self.cryptography_NameOID: Optional[Any] = None
        self.cryptography_hashes: Optional[Any] = None
        self.cryptography_serialization: Optional[Any] = None
        self.cryptography_rsa: Optional[Any] = None
        self.cryptography_default_backend: Optional[Any] = None

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
        Generates a self-signed SSL certificate and private key.
        Only generates if:
        1. `force_regenerate` is True.
        2. The files don't already exist.
        3. The existing cert is expired.
        Then attempts to add it to the system trust store *only once per session*.
        Returns the path to the certificate and key.
        """
        global _CERT_TRUST_CHECK_DONE_THIS_SESSION # Declare global to modify it

        # Access cryptography components via svr_core's direct attributes
        _x509 = svr_core.cryptography_x509
        _NameOID = svr_core.cryptography_NameOID
        _hashes = svr_core.cryptography_hashes
        _serialization = svr_core.cryptography_serialization
        _rsa = svr_core.cryptography_rsa
        _default_backend = svr_core.cryptography_default_backend

        # Check if cryptography components are actually loaded
        if not all([_x509, _NameOID, _hashes, _serialization, _rsa, _default_backend]):
            logging.error("Cryptography components failed to load. Cannot generate SSL certificate.")
            sys.exit(1) # Exit cleanly as SSL will fail.

        cert_exists = os.path.exists(cert_path) and os.path.exists(key_path)
        cert_expired = True # Assume expired until proven otherwise

        if cert_exists:
            try:
                with open(cert_path, "rb") as f:
                    cert_data = f.read()
                cert = _x509.load_pem_x509_certificate(cert_data, _default_backend())
                
                # Check expiration date
                if datetime.now(timezone.utc) < cert.not_valid_after_utc:
                    cert_expired = False
                    logging.info(f"🔐 Existing SSL certificate found and is valid until {cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}.")  # Added time for precision
                    # If cert is valid, we assume it's already trusted or user will handle it.
                    # Set the flag so we don't prompt for trust installation again this session.
                    _CERT_TRUST_CHECK_DONE_THIS_SESSION = True
                else:
                    logging.warning(f"⚠️ Existing SSL certificate expired on {cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}. Generating a new one.")
            except Exception as e:
                logging.warning(f"⚠️ Could not load or parse existing certificate ({e}). Generating a new one.")
                cert_expired = True # Force regeneration if load fails

        # --- Decide whether to generate ---
        should_generate = force_regenerate or not cert_exists or cert_expired

        if should_generate:
            if force_regenerate:
                logging.info("♻️ Force regenerating SSL certificate and key as requested...")
            else:
                logging.info("Generating new self-signed SSL certificate and key (missing or expired)...")
            
            # Generate a new private key
            key = _rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=_default_backend()
            )

            # Generate a self-signed certificate
            subject = issuer = _x509.Name([
                _x509.NameAttribute(_NameOID.COUNTRY_NAME, "AU"),
                _x509.NameAttribute(_NameOID.STATE_OR_PROVINCE_NAME, "Victoria"),
                _x509.NameAttribute(_NameOID.LOCALITY_NAME, "Melbourne"),
                _x509.NameAttribute(_NameOID.ORGANIZATION_NAME, "Local Development"),
                _x509.NameAttribute(_NameOID.COMMON_NAME, "localhost"), # Important for local dev
            ])
            cert = (
                _x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(_x509.random_serial_number())
                .not_valid_before(datetime.utcnow())
                .not_valid_after(datetime.utcnow() + timedelta(days=365)) # Valid for 1 year
                .add_extension(_x509.SubjectAlternativeName([_x509.DNSName("localhost")]), critical=False)
                .add_extension(_x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(key, _hashes.SHA256(), _default_backend())
            )

            # Write our key and certificate to disk
            with open(key_path, "wb") as f:
                f.write(key.private_bytes(
                    encoding=_serialization.Encoding.PEM,
                    format=_serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=_serialization.NoEncryption()
                ))
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(_serialization.Encoding.PEM))

            logging.info(f"✅ Generated SSL certificate and key: {cert_path}, {key_path}")
            # If a new cert was generated, we should definitely attempt to trust it
            _CERT_TRUST_CHECK_DONE_THIS_SESSION = False # Reset flag to ensure trust attempt
        else:
            # If no generation was needed, just use the existing files.
            # This path is taken if force_regenerate is False, cert_exists is True, and cert_expired is False.
            pass # Logging for valid cert already handled above.

        # --- Attempt to add to system trust store ONLY IF not done this session ---
        # This part runs regardless of whether a new cert was generated, but only once per session.
        # It's here because even if an old valid cert exists, the user might want to re-attempt trust.
        if not _CERT_TRUST_CHECK_DONE_THIS_SESSION:
            logging.info("\nAttempting to add certificate to system trust store. This is a SSL certificate to allow local web pages to talk to the server via HTTPS (which is needed for certain web page functions such as Cut/Paste/Copy access)...")
            try:
                if sys.platform == "darwin": # macOS
                    subprocess.run(
                        ["sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", cert_path],
                        check=True,
                        capture_output=True,
                        text=True
                    )
                    logging.info("🎉 macOS: Certificate successfully added to System Keychain (may require 'Always Trust' manual setting in Keychain Access).")
                elif sys.platform == "win32": # Windows
                    subprocess.run(
                        ["certutil", "-addstore", "Root", cert_path],
                        check=True,
                        capture_output=True,
                        text=True
                    )
                    logging.info("🎉 Windows: Certificate successfully added to Trusted Root Certification Authorities store (may require UAC confirmation).")
                else:
                    logging.info("ℹ️ Automatic certificate trust not supported on this OS. Please trust it manually.")

            except subprocess.CalledProcessError as e:
                logging.error(f"❌ Failed to add certificate to system trust store:")
                logging.error(f"   Command: {' '.join(e.cmd)}")
                logging.error(f"   Return Code: {e.returncode}")
                if e.stdout: logging.error(f"   Stdout: {e.stdout.strip()}")
                if e.stderr: logging.error(f"   Stderr: {e.stderr.strip()}")
                logging.error("   Please add the certificate to your system's trust store manually.")
                logging.error("   See previous messages for manual instructions for macOS/Windows.")
            except FileNotFoundError as e:
                logging.error(f"❌ Command not found: {e.strerror}. Ensure 'sudo'/'security' (macOS) or 'certutil' (Windows) are in your PATH.")
            except Exception as e:
                logging.error(f"❌ An unexpected error occurred while adding certificate: {e}")
            
            _CERT_TRUST_CHECK_DONE_THIS_SESSION = True # Mark as attempted for this session

        logging.warning("⚠️ You may still need to accept a security warning in your browser for this self-signed certificate, or explicitly mark it as 'Always Trust' in your OS/browser's certificate manager.")
        return cert_path, key_path

# HTTP Redirect Logic (only if SECURE_SITE is True)
if svr_core.config.SECURE_SITE:
    @redirect_app.middleware("http")
    async def redirect_to_https(request: svr_core.Request, call_next):
        if request.url.scheme == "http":
            new_url = request.url.replace(scheme="https", port=svr_core.config.HTTPS_PORT)
            return svr_core.RedirectResponse(url=new_url, status_code=301)
        return await call_next(request)


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

    servers = [svr_core.uvicorn_module.Server(config) for config in server_configs]

    await asyncio.gather(*[server.serve() for server in servers])


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Serve a local folder as a website.")
    parser.add_argument("--port", type=int, default=None, help="Override HTTP_PORT from config.")
    parser.add_argument("--https-port", type=int, default=None, help="Override HTTPS_PORT from config.")
    parser.add_argument("--secure", type=str, default=None, help="Override SECURE_SITE (true/false).")
    parser.add_argument("--force-cert-regen", action="store_true", help="Force SSL certificate regeneration.")
    
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
