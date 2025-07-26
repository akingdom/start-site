# site_endpoints.py — Boilerplate for add endpoint

# Declare numpy dependency
REQUIRED_ENDPOINT_MODULES = {
    "numpy": ("numpy", True),
}

_svr_core_ref = None

def init(app, svr_core):
    global _svr_core_ref
    _svr_core_ref = svr_core

    # Load numpy before defining the endpoint
    svr_core.load_endpoint_modules(REQUIRED_ENDPOINT_MODULES)

    JSONResponse = svr_core.get_module("fastapi").responses.JSONResponse
    numpy_mod   = svr_core.get_module("numpy")

    @app.get("/api/add")
    async def add(a: float, b: float):
        """Add two numbers using numpy."""
        try:
            result = numpy_mod.add(a, b).item()
            return JSONResponse({"result": result})
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=400)

    print("[site_endpoints] Loaded endpoint: GET /api/add")
