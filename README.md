# start‑site – A Modern Local Web Server

**One script. Zero config. Development‑ready HTTPS. Sane port management.**

`start‑site` is a single‑file Python web server designed for local development, secure prototyping, and multi‑user collaboration. It gives you a full‑featured server with automatic HTTPS, dynamic port allocation, and a plug‑in extension system – all without editing a single line of configuration.

Think of it as `python -m http.server` – but with the security and convenience of a production server.

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

## Quickstart

```bash
git clone https://github.com/akingdom/start-site.git
cd start-site
python3 start_site_server.py
```

On first run, the server creates a `site_config.yaml` file and prints its address. Place your static assets in the `live/` folder, and they are served immediately.

**That's it.** No configuration required. HTTPS and port management are enabled by default.

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

**Example 2 – Full boilerplate (matching the included `site_endpoints.py` sample):**
```python
from dataclasses import dataclass, field
from typing import Optional, List

@dataclass
class EndpointsConfig:
    GREETING: str = "Hello"

# Declare dependencies – the server will load them before calling init.
REQUIRED_ENDPOINT_MODULES = {
    "numpy": ("numpy", True),   # package name, critical
}

_svr_core_ref = None

async def about_to_start(svr_core):
    """Called just before the main event loop starts."""
    print("📋 Server is about to start – running pre‑flight checks.")
    print(f"   Greeting is: {svr_core.config.GREETING if hasattr(svr_core.config, 'GREETING') else 'Not set'}")

def init(app, svr_core):
    global _svr_core_ref
    _svr_core_ref = svr_core

    # Load numpy before defining the endpoint
    svr_core.load_endpoint_modules(REQUIRED_ENDPOINT_MODULES)

    JSONResponse = svr_core.fastapi_module.responses.JSONResponse
    numpy_mod   = svr_core.numpy_module

    @app.get("/api/add")
    async def add(a: float, b: float):
        """Add two numbers using numpy."""
        try:
            result = numpy_mod.add(a, b).item()
            return JSONResponse({"result": result})
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=400)

    print("[site_endpoints] Loaded endpoint: GET /api/add")
```

The server’s `EndpointsConfig` dataclass (if defined) is merged into the main configuration, so any fields like `GREETING` can be set in `site_config.yaml` and accessed via `svr_core.config`.

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

Command‑line flags override YAML values:
- `--port PORT` – override HTTP port.
- `--secure true/false` – toggle HTTPS.
- `--disable-adrest` – run in standalone mode (fixed ports).
- `--auto-open` – automatically open the default page.

---

## Upgrading

Because the core script is **immutable** and all configuration is externalised, upgrading is safe and simple:

1. Download the new `start_site_server.py`.
2. Replace the old file – your `site_config.yaml` and `site_endpoints.py` remain untouched.
3. If the new version introduces new configuration fields, the version check will warn you. Run `python site_config.py --create` to generate a fresh template and merge your changes.

---

## How It Works Under the Hood

- **FastAPI + Uvicorn** – modern, async‑first web stack.
- **AdREST** – a per‑user registry file (`~/.local/share/workspace-server/port-registry.json`) manages port allocation.
- **Certificate Manager** – creates a local CA and signed leaf certificate with SANs for `localhost`, `127.0.0.1`, `::1`, and your LAN IP (when loopback‑only is disabled).
- **Symlink security** – only whitelisted symlink targets are followed, preventing path traversal attacks.
- **Diagnostics** – writes a Markdown snapshot on startup and on significant events.

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
