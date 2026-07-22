# site_endpoints.py — Boilerplate for add endpoint
#
# This module is loaded by start_site_server.py via:
#     import site_endpoints
#     site_endpoints.init(app, svr_core)
# Keep the signature: def init(app: FastAPI, svr_core) -> None:

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

    # Forced override: open the default page on startup
    svr_core.config.AUTO_OPEN_DEFAULT = True

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
