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
   On first run, a template `ServerConfig.py` is created (if missing).  
   Edit it to change settings without touching the main script.

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

## Configuration (without editing the script)

To keep `start_site_server.py` completely **immutable** (easy to upgrade), use an external `ServerConfig.py` file.

1. **Generate a template** (if missing):  
   ```bash
   python3 start_site_server.py --write-config
   ```
   This creates `ServerConfig.py` with all fields **commented out** except `VERSION` (which is required for version checks).

2. **Edit the file**:  
   - Uncomment any line you want to change.  
   - Full documentation is included as comments above each field.  
   - Example:  
     ```python
     # TCP Port for HTTP traffic (will redirect to HTTPS_PORT if SECURE_SITE = True)
     HTTP_PORT: int = 8080
     ```

3. **Run the server** – external values automatically override the internal defaults.  
   If the external file’s `VERSION` differs from the script’s version, you’ll see a warning.

### Internal defaults (inside `start_site_server.py`)

The built‑in `ServerConfig` is a dataclass with inline comments (`_note` variables). It provides sensible defaults:

```python
@dataclass
class ServerConfig:
    VERSION_note = "Application version (do not change)"
    VERSION: str = "2.0.4"

    EXTERNAL_CONFIG_PATH_note = "Path to external config file (empty = no overrides)"
    EXTERNAL_CONFIG_PATH: str = "ServerConfig.py"

    HTTP_PORT_note = "TCP Port for HTTP traffic (will redirect to HTTPS_PORT if SECURE_SITE = True)"
    HTTP_PORT: int = 9000

    HTTPS_PORT_note = "TCP Port for HTTPS traffic"
    HTTPS_PORT: int = 9001

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

    SECURE_SITE_note = "True for HTTPS/SSL traffic with HTTP redirect, else False for plain HTTP."
    SECURE_SITE: bool = False

    FORCE_CERTIFICATE_REGENERATION_note = (
        "Set to True to force regeneration of SSL certificates on startup, even if valid.\n"
        "Set to False (default) to only regenerate if missing or expired."
    )
    FORCE_CERTIFICATE_REGENERATION: bool = False

    AUTO_OPEN_DEFAULT_note = (
        "Set to True to auto-open the default page in a web browser on server startup\n"
        "Set to False (default) if a web page or app will be opened independent of this script"
    )
    AUTO_OPEN_DEFAULT: bool = False

    AUTO_OPEN_DELAY_SECONDS_note = "Optional delay (seconds) to avoid racing any already-open clients. Only relevant if AUTO_OPEN_DEFAULT is True."
    AUTO_OPEN_DELAY_SECONDS: int = 1

    ADREST_ENABLED_note = "Enable AdREST dynamic port management. Set to False to run as a standalone server with specific port numbers."
    ADREST_ENABLED: bool = True

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
```

You never need to edit this block – customise via `ServerConfig.py`.

### Command‑line options for configuration

| Flag | Description |
|------|-------------|
| `--config PATH` | Use an external config file (default: `ServerConfig.py`). |
| `--write-config` | Generate a template `ServerConfig.py` and exit. |
| `--port PORT` | Override `HTTP_PORT` setting (takes precedence). |
| `--https-port PORT` | Override `HTTPS_PORT` setting. |
| `--secure true/false` | Toggle `SECURE_SITE`. |
| `--force-cert-regen` | Force SSL certificate regeneration. |
| `--auto-open` | Open the default page automatically. |
| `--open-delay SECONDS` | Delay before auto‑opening. |
| `--disable-adrest` | Disable AdREST dynamic port manager for this run. |

### Version checks

The external config file includes an **active** `VERSION` field. When the server loads it, the script compares that version with its own internal version. If they differ, a warning is printed (the server still runs, using the external values where possible). To update, regenerate the template with `--write-config` and manually merge your changes.

---

## Basic HTTP Setup (no encryption)

If you don't need HTTPS, set `SECURE_SITE = False` and (optionally) `ADREST_ENABLED = False` for a plain HTTP server:

```python
# In ServerConfig.py
SECURE_SITE = False
ADREST_ENABLED = False   # if you want a fixed port
```

Then run `python3 start_site_server.py`. The server will start on `http://localhost:8002` (or the port you configured).  
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

## Extending the server (`site_endpoints.py`)

It is strongly recommended to make no changes to the `start_site_server` script, treating it as *immutable*, apart from customising settings in `ServerConfig.py` or using the built‑in extension system.

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

### Site Agents

The server supports different backend agents (e.g., `browser_agent` for pure web, `tauri_agent` for native integration).  
The agent is selected via the environment variable `EDER_SITE_AGENT` (default: `browser_agent`).  
Agents are automatically discovered from the `site_agents/` folder and registered using a decorator:

```python
from site_agents.base import register_agent

@register_agent("my_agent")
class MySiteAgent:
    async def create_window(self, payload):
        # …
```

The loader finds the concrete class via the registry, avoiding naming conflicts.  
You can add your own agent by placing a Python file in `site_agents/` and registering it.

---

## Launching a registered service

Use the included `adrest_launcher.py` to open any AdREST‑registered service in your browser without knowing its port:

```bash
python adrest_launcher.py com.workspace.supersystem
```

If the service isn’t running, the script will offer to start `start_site_server.py` and then open the browser automatically.

---

## Diagnostics

When something goes wrong, the server writes a **state snapshot** to a plain Markdown file.  
You can open it in any editor — no browser required.

**Location (cross‑platform):**

| OS | Path |
|----|------|
| Linux | `~/.local/share/workspace-server/diagnostics/com.workspace.supersystem.md` |
| macOS | `~/Library/Application Support/workspace-server/diagnostics/com.workspace.supersystem.md` |
| Windows | `%APPDATA%/workspace-server/diagnostics/com.workspace.supersystem.md` |

The file is regenerated at startup and updated when important events occur. It answers:

- **"Is the server running?"** — status, PID, ports, uptime.
- **"Is SSL working?"** — certificate validity and trust status.
- **"What services are registered?"** — live registry table with alive/dead flags.
- **"Which projects are broken?"** — per‑project health (requires `site_endpoints.py`).

A companion file `workspace.md` in the same directory shows per‑project health (requires the `site_endpoints.py` that ships with the Super‑System).

The diagnostics directory is private (`0700` permissions). Each file is less than 5 KB and is pruned automatically when services stop. No user data is ever included — only metadata (ports, PIDs, project names, dependency lists).

> **Before suggesting any fix, check the diagnostic file.** It should tell you exactly which component failed.

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

## Upgrading

Because all custom settings are stored in a separate `ServerConfig.py` file (and optional `site_endpoints.py`), you can safely replace `start_site_server.py` with a newer version without losing your configuration.  
If the new script introduces changed or removed fields, the version comparison will warn you; simply run `--write-config` to generate a fresh template and merge your changes manually.

---

## License

MIT License – see `LICENSE` file.  
© 2025-2026 Andrew Kingdom, All rights reserved.
