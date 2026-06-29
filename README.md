## start‑site

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
   On first run, the server will prompt you to create a `site_config.yaml` file – or you can generate it manually:
   ```bash
   python3 site_config.py --create
   ```
   Then edit `site_config.yaml` to change settings (see [Configuration](#configuration) below).

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

To keep `start_site_server.py` easy to upgrade (by being completely **immutable**), use the external YAML configuration file `site_config.yaml`.

1. **Generate a default configuration** (if missing):  
   ```bash
   python3 site_config.py --create
   ```
   This creates `site_config.yaml` with all fields and their comment documentation.

2. **Edit the file**:  
   - Uncomment or change any value.  
   - Full documentation is included as YAML comments (`_note` fields).  
   - Example:
     ```yaml
     # TCP Port for HTTP traffic (will redirect to HTTPS_PORT if SECURE_SITE = True)
     HTTP_PORT: 8080

     # Enable HTTPS/SSL
     SECURE_SITE: true
     ```

3. **Run the server** – YAML values automatically override the internal defaults.  
   If the YAML file’s `VERSION` differs from the script’s version, you’ll see a warning (the server still runs, but some fields may be outdated).

`site_config.py` can be omitted. Only `start_site_server.py` is needed to run the server.

### Internal defaults (inside `start_site_server.py`)

The built‑in `ServerConfig` dataclass provides sensible defaults (see the source for the full list).  
You never need to edit this block – customise via `site_config.yaml`.

### Endpoints configuration (`site_endpoints.py`)

If you use `site_endpoints.py` to add custom API routes, you can also configure its behaviour via YAML.  
`site_config.py --create` includes all fields from `EndpointsConfig` (defined in `site_endpoints.py`) alongside the server fields.  
Example:
```yaml
# Root folder for project directories.
PROJECTS_ROOT: "live/projects"

# If True, disables all write operations (PUT, POST, DELETE, PATCH).
READONLY: false
```

The endpoints configuration is merged with the server configuration – endpoint settings override server settings if there are name conflicts.

### Upgrading existing `ServerConfig.py`

If you previously used the old `ServerConfig.py`, you can migrate to the new YAML system:

1. **Generate a fresh YAML file**:
   ```bash
   python3 site_config.py --create
   ```
2. **Copy your custom values** from the old `ServerConfig.py` into `site_config.yaml`.
3. **Remove or rename** `ServerConfig.py` – it will be ignored.
4. **Test** the server with your custom settings.

The old `--write-config` flag no longer exists; use `site_config.py` instead.

### Command‑line options for configuration

| Flag | Description |
|------|-------------|
| `--config PATH` | *(Deprecated)* Path to a legacy Python config file – use `site_config.yaml` instead. |
| `--port PORT` | Override `HTTP_PORT` setting (takes precedence). |
| `--https-port PORT` | Override `HTTPS_PORT` setting. |
| `--secure true/false` | Toggle `SECURE_SITE`. |
| `--force-cert-regen` | Force SSL certificate regeneration. |
| `--auto-open` | Open the default page automatically. |
| `--open-delay SECONDS` | Delay before auto‑opening. |
| `--disable-adrest` | Disable AdREST dynamic port manager for this run. |

### Version checks

The YAML config includes an active `VERSION` field. When the server loads it, it compares that version with its own internal version. If they differ, a warning is printed (the server still runs, using the external values where possible). To update, regenerate the template with `site_config.py --create` and manually merge your changes, or use `site_config.py --update` to add any new fields while preserving your existing values.

---

## Basic HTTP Setup (no encryption)

If you don't need HTTPS, set `SECURE_SITE: false` and (optionally) `ADREST_ENABLED: false` for a plain HTTP server:

```yaml
# In site_config.yaml
SECURE_SITE: false
ADREST_ENABLED: false   # if you want a fixed port
```

Then run `python3 start_site_server.py`. The server will start on `http://localhost:8002` (or the port you configured).  
You can still use AdREST with HTTP – just leave `ADREST_ENABLED: true` and the manager will assign free ports automatically.

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
   Pass `--port` and `--https-port` on the command line, or set `ADREST_ENABLED: false` in the configuration, to disable AdREST entirely. The server will then use the ports you specify (or the defaults) and ignore the manager.

> **Tip:** On shared machines each user gets their own registry file, so multiple users can run their own manager without interference.  
> The manager and workspace ports are **reused** on restart if still free, keeping addresses stable.

---

## Extending the server (`site_endpoints.py`)

It is strongly recommended to make no changes to the `start_site_server` script, treating it as *immutable*, apart from customising settings in `site_config.yaml` or using the built‑in extension system.

You can add custom API endpoints without modifying the core script.

1. Create a file named `site_endpoints.py` in the same directory.
2. Define an `EndpointsConfig` dataclass (optional – see `site_endpoints.py` for the default) and an `init(app, svr_core, endpoint_config=None)` function. The server calls it after creating the FastAPI app, so you can add routes, middleware, or background tasks.

Example (`site_endpoints.py`):
```python
def init(app, svr_core, endpoint_config=None):
    @app.get("/api/hello")
    async def hello():
        return {"message": "Hello from site_endpoints!"}

    # You can also adjust server configuration from here
    svr_core.config.ENABLE_LIFESPAN = True       # if your endpoints need lifespan events
    svr_core.config.SERVE_STATIC_FILES = False   # if you only need WebSocket/API
```

The file is optional – if it doesn’t exist, the server runs without extra endpoints.

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

Because all custom settings are stored in a separate `site_config.yaml` file (and optional `site_endpoints.py`), you can safely replace `start_site_server.py` with a newer version without losing your configuration.  
If the new script introduces changed or removed fields, the version comparison will warn you; simply run `site_config.py --create` to generate a fresh template and merge your changes manually.

---

## License

MIT License – see `LICENSE` file.  
© 2025-2026 Andrew Kingdom, All rights reserved.
