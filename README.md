# start‑site – A Local Web Server for Development

**One script. Zero config. HTTPS for local development. Sane port management.**

`start‑site` is a single‑file Python web server built for local development, secure prototyping, and team collaboration. It handles HTTPS automatically, manages multiple instances without port conflicts, and lets you extend it with custom endpoints – all without editing the core script.

**What it is:**
- A secure local server for frontend and API development
- A zero‑configuration HTTPS solution for testing modern web features
- A tool that runs multiple instances side‑by‑side without manual port juggling

**What it is not:**
- A production web server for high‑volume public internet traffic
- A replacement for Nginx, Apache, or cloud load balancers

For production use, deploy your application behind a reverse proxy. For local development, prototyping, and team demos, `start‑site` is ready to go.

---

## Quickstart

```bash
git clone https://github.com/akingdom/start-site.git
cd start-site
python3 start_site_server.py
```

On first run, the server creates a `site_config.yaml` file and prints its address. Place your static assets in the `live/` folder, and they are served immediately.

**That's it.** No configuration required. HTTPS and port management are enabled by default.

---

## Prerequisites

- [Python 3.8+](https://www.python.org/downloads/)  
- `pip install --upgrade pip`

---

## What's in This Repository?

| File | Purpose | Optional? |
|------|---------|-----------|
| `start_site_server.py` | The main server script. Immutable core. | **Required** |
| `site_config.py` | Command‑line tool to create/update `site_config.yaml`. | ✅ Optional |
| `site_endpoints.py` | Example extension file – adds custom API routes. | ✅ Optional |
| `adrest_launcher.py` | Helper to launch any AdREST‑registered service. | ✅ Optional |
| `live/` | Default static folder (served at `/`). | ✅ Optional (you can change `SITE_FOLDER`) |
| `site_config.yaml` | External configuration file (auto‑generated). | ✅ Optional (generated if missing) |
| `README.md` | This documentation. | – |

**Only `start_site_server.py` is required.** Everything else is optional.

---

## Why `start‑site`?

| Feature | `python -m http.server` | Apache / Nginx | **start‑site** |
|---------|--------------------------|----------------|----------------|
| HTTPS | ❌ Manual & complex | ✅ (complex setup) | ✅ **Automatic** |
| Multiple instances | ❌ Manual port juggling | ❌ Manual | ✅ **Automatic (AdREST)** |
| Extensible | ❌ No | ✅ | ✅ **Plug‑in system** |
| Single file | ✅ | ❌ | ✅ |
| Cross‑platform | ✅ | ✅ | ✅ |
| Zero config | ✅ | ❌ | ✅ |
| Loopback‑only (secure by default) | ❌ (binds all interfaces) | ❌ (binds all interfaces) | ✅ **Enabled by default** |

`start‑site` is built for developers who need a **secure, hassle‑free, disposable local server** – whether for rapid prototyping, running multiple microservices, sharing a demo across a team, or as a foundation for larger toolchains.

---

## Key Features

### 🔒 Automatic HTTPS with a Local CA
- No need for `openssl` or manual certificate generation.
- The server creates a root CA and a signed certificate for `localhost` on first run.
- On macOS, the CA is installed automatically. On other platforms, a simple one‑time acceptance is required.
- Custom certificates can be used by specifying `SSL_CERT_FILE` and `SSL_KEY_FILE`.

### 🚦 AdREST – Dynamic Port Management
When multiple users or projects run `start‑site` on the same machine, port conflicts are handled automatically:

- The **first instance** becomes a manager, assigning free HTTP/HTTPS ports to subsequent instances.
- Ports are reused across restarts when available.
- Works seamlessly for teams – each user has their own registry file.

### 🔧 Immutable Core & External Configuration
- All settings live in `site_config.yaml` – never edit the script.
- Upgrading is safe: replace the script, keep your config.
- Command‑line flags override YAML for quick one‑offs.

### 🧩 Pluggable Extension System
Add custom endpoints, middleware, or background tasks without forking the script.  
Create `site_endpoints.py` next to the script. The server calls two optional functions if they exist:

- `init(app, svr_core)` – called during startup to mount routes.
- `about_to_start(svr_core)` – called just before the main event loop starts (useful for pre‑flight checks or warming caches).

**Example 1 – Simple endpoint:**
```python
def init(app, svr_core):
    @app.get("/api/hello")
    async def hello():
        return {"message": "Hello from site_endpoints!"}

async def about_to_start(svr_core):
    print("📋 Server is about to start – running pre‑flight checks.")
```

**Example 2 – Full boilerplate (with config and dependency loading):**
```python
from dataclasses import dataclass, field

@dataclass
class EndpointsConfig:
    GREETING: str = "Hello"

REQUIRED_ENDPOINT_MODULES = {
    "numpy": ("numpy", True),   # package name, critical
}

_svr_core_ref = None

async def about_to_start(svr_core):
    print("📋 Server is about to start – pre‑flight checks complete.")

def init(app, svr_core):
    global _svr_core_ref
    _svr_core_ref = svr_core

    # ── Forced override: open the default page on startup ──────────────
    svr_core.config.AUTO_OPEN_DEFAULT = True  # demonstration: auto-open index.html

    svr_core.load_endpoint_modules(REQUIRED_ENDPOINT_MODULES)

    JSONResponse = svr_core.fastapi_module.responses.JSONResponse
    numpy_mod = svr_core.numpy_module

    @app.get("/api/add")
    async def add(a: float, b: float):
        try:
            result = numpy_mod.add(a, b).item()
            return JSONResponse({"result": result})
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=400)

    print("[site_endpoints] Loaded endpoint: GET /api/add")
```

The server’s `EndpointsConfig` dataclass (if defined) is merged into the main configuration, so any fields like `GREETING` can be set in `site_config.yaml` and accessed via `svr_core.config`.

> **Tip:** You can force the server to open the default page on startup by setting `svr_core.config.AUTO_OPEN_DEFAULT = True` inside `init()`. This is especially useful for demos or to automatically show your project's index page.

### 📋 Built‑in Diagnostics
A plain‑text Markdown snapshot is written to a well‑known location (`~/.local/share/workspace-server/diagnostics/`). It shows:
- Server status, PID, uptime, ports.
- SSL certificate validity and trust.
- Active AdREST registry entries.
- Project health (if using `site_endpoints.py` with custom endpoints).

**Check this file first when something goes wrong – it tells you exactly what broke.**

### 🔒 Loopback‑Only by Default
By default, the server binds only to `127.0.0.1` (localhost). This prevents accidental exposure to other devices on your network and keeps your development environment secure.

If you need to share your server with others on the same network, you can disable this by setting `ENABLE_LOOPBACK_ONLY: false` in `site_config.yaml`. **Enabling this exposes your server to other devices on the network – only use this in trusted environments or when you understand the security implications.**

---

## Why HTTPS Matters for Local Development

Many modern web APIs **require a secure context (HTTPS)**, even when running locally. With `start‑site`, you get HTTPS out of the box, so you can test:

- **Service Workers** – for offline support and PWA features.
- **Geolocation API** – for location‑aware apps.
- **WebUSB, WebBluetooth, WebHID** – for hardware interaction.
- **MediaDevices (getUserMedia)** – for camera/microphone access.
- **Secure cookies** – with `Secure` and `SameSite=None` flags.
- **Payment Request API** – for web payments.
- **Server‑Sent Events / WebSockets** – over TLS.

With `http.server`, you'd have to set up a complex proxy or self‑signed certificates. `start‑site` does it for you.

---

## Configuration – Without Editing the Script

All settings are defined in `site_config.yaml`, which is auto‑generated on first run. The file is fully documented with comments – uncomment and change only what you need.

```yaml
HTTP_PORT: 8080
SECURE_SITE: true
```

### Generating or Updating `site_config.yaml` (Optional Tool)

The included `site_config.py` script helps you create or update the YAML configuration file:

- **Create a fresh config:**  
  ```bash
  python site_config.py --create
  ```
- **Update an existing config** with new default values (preserving your custom values and comments):  
  ```bash
  python site_config.py --update
  ```

If `site_config.py` is absent, the server still works – it will generate a default `site_config.yaml` on startup.

Command‑line flags override YAML values:
- `--port PORT` – override HTTP port.
- `--secure true/false` – toggle HTTPS.
- `--disable-adrest` – run in standalone mode (fixed ports).
- `--auto-open` – automatically open the default page.

---

## Extending the Server – `site_endpoints.py`

You can add custom endpoints without modifying the core script. See the examples in the [Key Features](#-pluggable-extension-system) section.

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

## Launching a Registered Service

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

## Upgrading

Because the core script is **immutable** and all configuration is externalised, upgrading is safe and simple:

1. Download the new `start_site_server.py`.
2. Replace the old file – your `site_config.yaml` and `site_endpoints.py` remain untouched.
3. If the new version introduces new configuration fields, the version check will warn you. Run `python site_config.py --create` to generate a fresh template and merge your changes.

---

## Use Cases

- **Frontend development** – serve static assets with HTTPS for testing Service Workers, Geolocation, or secure cookies.
- **Microservice prototyping** – run multiple services on the same machine without port conflicts.
- **Demo sharing** – start a temporary server to share a prototype with colleagues (HTTPS ensures modern APIs work).
- **Workspace tooling** – used as the foundation for the Super‑System, providing a local API server for project‑oriented development.

---

## Requirements

- Python 3.8+
- Optional: `cryptography` (auto‑installed on first run if needed for certificate generation).

---

## License

MIT License – see `LICENSE` file.  
© 2025-2026 Andrew Kingdom, All rights reserved.

---

## Contribute

`start‑site` is a core component of the Super‑System ecosystem but is designed to be **completely standalone**. Contributions that improve stability, add platform support, or extend the extension system are welcome. Please ensure changes keep the script single‑file and immutable‑by‑design.
