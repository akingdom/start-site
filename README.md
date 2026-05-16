# start-site

A single‑file local web server for quick testing, workspace prototyping, and multi‑user development.  
It serves a static folder, optionally over HTTPS, and can run multiple independent instances without port collisions thanks to its built‑in **AdREST** dynamic port manager.

---

## Prerequisites

- [Python 3.8+](https://www.python.org/downloads/)  
- `pip install --upgrade pip`

---

## Quickstart

1. **Clone the repository**
   ```bash
   git clone https://github.com/akingdom/start-site.git
   cd start-site
   ```

2. **Run the server**
   ```bash
   python3 start_site_server.py
   ```

3. **Open your browser**  
   The server prints the address (e.g. `https://localhost:8003`) and opens it automatically if `AUTO_OPEN_DEFAULT` is `True`.

4. **Add your files**  
   Place HTML, CSS, JS, and other assets inside the `live/` folder. These are served directly.

---

## Important

- **HTTPS** may require restarting the browser the first time if a security warning appears – the server creates a local CA and installs it automatically (macOS). On other platforms you may need to accept the self‑signed certificate manually.
- If you already have your own SSL certificate, set `SSL_CERT_FILE` and `SSL_KEY_FILE` in the configuration. The server will use them instead of generating a self‑signed one.
- The server runs from its own directory; change the current working directory to the script’s location before starting.

---

## Basic HTTP Setup (no encryption)

If you don't need HTTPS, simply set `SECURE_SITE = False` and (optionally) `ADREST_ENABLED = False` for a plain HTTP server:

```python
class ServerConfig:
    def __init__(self):
        self.HTTP_PORT = 8002
        self.SECURE_SITE = False
        self.ADREST_ENABLED = False   # if you want a fixed port
        # ... rest of your settings
```

Then run `python3 start_site_server.py`. The server will start on `http://localhost:8002`.  
You can still use AdREST with HTTP – just leave `ADREST_ENABLED = True` and the manager will assign free ports automatically.

---

## Built‑in Dynamic Port Management (AdREST)

When multiple users (or multiple projects) want to run `start_site_server.py` on the same machine, port conflicts can happen.  
**AdREST** solves this automatically:

1. The **first instance** that starts (without explicit `--port` and `--https-port` arguments) becomes the *AdREST manager*.  
   - It picks free ports for the main HTTP/HTTPS server **and** a free port for the manager API.  
   - The manager port is stored in a per‑user registry file (`~/.local/share/workspace-server/port-registry.json`) under the key `"services.adrest"`.  
   - The manager API (`/api/manager/*`) runs on its own isolated port, bound to `127.0.0.1`, so it is never accessible from the browser or external network.

2. **Subsequent instances** read the registry to discover the manager’s port, then call `POST /api/manager/register` on that port to receive unique HTTP/HTTPS ports – no collisions, no manual configuration.

3. **Standalone mode**  
   Pass `--port` and `--https-port` on the command line, or set `ADREST_ENABLED = False` in the configuration, to disable AdREST entirely. The server will then use the ports you specify (or the defaults) and ignore the manager.

> **Tip:** On shared machines each user gets their own registry file, so multiple users can run their own manager without interference.  
> The manager and workspace ports are **reused** on restart if still free, keeping addresses stable.

---

## Settings

Edit the `ServerConfig` class inside `start_site_server.py` to customise behaviour.

```python
# --- EDITABLE SERVER CONFIGURATION ---
class ServerConfig:
    def __init__(self):
        # TCP Port for HTTP traffic (will redirect to HTTPS_PORT if SECURE_SITE = True)
        self.HTTP_PORT: int = 8002
        # TCP Port for HTTPS traffic
        self.HTTPS_PORT: int = 8003
        # Folder containing web-site files.
        self.SITE_FOLDER: str = "live"
        # Name of the preferred file to open when a web client doesn't specify a filename.
        self.DEFAULT_FILE: str = "index.html"
        # A list of allowed symlink target *directories*.  Relative paths are
        # relative to SITE_FOLDER.
        self.ALLOWED_SYMLINK_TARGETS: list[str] = ["../../js"]
        # True for HTTPS/SSL traffic with HTTP redirect, else False for plain HTTP.
        self.SECURE_SITE: bool = True
        # Force regeneration of SSL certificates on every startup.
        self.FORCE_CERTIFICATE_REGENERATION: bool = False
        # Automatically open the default page in a web browser on startup.
        self.AUTO_OPEN_DEFAULT: bool = True
        # Optional delay (seconds) before auto‑opening the browser.
        self.AUTO_OPEN_DELAY_SECONDS: int = 1
        # Enable AdREST dynamic port management. Set to False to run as a standalone server.
        self.ADREST_ENABLED: bool = True
        # Time in seconds to graciously (safely, politely) shutdown the server when the user presses Control-C on keyboard
        self.SHUTDOWN_TIMEOUT: int = 5

        # ── New configuration fields (v1.2.0+) ───────────────────────
        # Enable Uvicorn lifespan events (startup/shutdown).  Default off.
        self.ENABLE_LIFESPAN: bool = False
        # Custom SSL certificate and key file paths.  If empty, the server
        # auto‑generates a self‑signed certificate via CertificateManager.
        self.SSL_CERT_FILE: str = ""
        self.SSL_KEY_FILE: str = ""
        # Whether to serve static files from SITE_FOLDER.
        # Set to False for a pure API / WebSocket server.
        self.SERVE_STATIC_FILES: bool = True

        # Application version number.  Leave as‑is.
        self.VERSION: str = VERSION
# --- END EDITABLE SERVER CONFIGURATION ---
```

### Certificate management
All certificate operations (CA creation, self‑signed cert generation, system trust store installation) are now encapsulated in the `CertificateManager` class. If you want to remove certificate functionality entirely, you can delete that class and the corresponding `SECURE_SITE` logic without affecting the rest of the server.

---

## Extending the server (`site_endpoints.py`)

You can add custom API endpoints without modifying the core script.

1. Create a file named `site_endpoints.py` in the same directory.
2. Define an `init(app, svr_core)` function. The server calls it after creating the FastAPI app, so you can add routes, middleware, or background tasks.

Example (`site_endpoints.py`):
```python
def init(app, svr_core):
    @app.get("/api/hello")
    async def hello():
        return {"message": "Hello from site_endpoints!"}

    # You can also adjust server configuration from here
    svr_core.config.ENABLE_LIFESPAN = True       # if your endpoints need lifespan events
    svr_core.config.SERVE_STATIC_FILES = False   # if you only need WebSocket/API
```

The file is optional – if it doesn’t exist, the server runs without extra endpoints.

---

## Command‑line options

| Flag | Description |
|------|-------------|
| `--port PORT` | Override `HTTP_PORT` setting. |
| `--https-port PORT` | Override `HTTPS_PORT` setting. |
| `--secure true/false` | Toggle `SECURE_SITE`. |
| `--force-cert-regen` | Force regeneration of SSL certificates. |
| `--auto-open` | Open the default page automatically. |
| `--open-delay SECONDS` | Delay before auto‑opening. |
| `--disable-adrest` | Disable AdREST dynamic port manager for this run. |

---

## `live/` folder structure

```
live/
├── index.html          # Served at /
├── projects/           # (optional) sub‑project folders
│   └── hello/
│       └── index.html
├── js/                 # symlinked if ALLOWED_SYMLINK_TARGETS includes it
└── .data/              # (created by extensions) private project data
```

The server blocks direct HTTP access to any `.data` directory – use the API endpoints provided by your extension.

---

## Licence

MIT License – see `LICENSE` file.  
© 2025 Andrew Kingdom, All rights reserved.
