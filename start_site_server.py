#!/usr/bin/env python3
# start_site.py
VERSION = "1.0.4"
# Serves a local folder as a website.
#
# author: Andrew Kingdom, Copyright(C)2025, All rights reserved, MIT License (CC-BY).
# the connection URL is shown when the script runs successfully.
#
# SETTINGS ==========================================
# PORT = TCP Port ()
PORT = 8000
# SITE_FOLDER = Name of the folder that contains the web-site files. This site folder must be in the same 'parent' folder that contains this start_site.py script.
SITE_FOLDER = "live"
# DEFAULT_FILE = Name of the preferred file to open when a web client doens't specify a filename.
DEFAULT_FILE = "index.html"
# SETTINGS-END ======================================
#
import os
import socket
import sys

try:
    import netifaces
except ImportError:
    netifaces = None
    sys.exit("netifaces not found. Install with:\n\n  pip install netifaces\n")

try:
    import uvicorn
except ImportError:
    uvicorn = None
    sys.exit("uvicorn not found. Install with:\n\n  pip install uvicorn\n")

try:
    from fastapi import FastAPI, Request, HTTPException
    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles
except ImportError:
    fastapi = None
    FastAPI = None
    sys.exit("fastapi not found. Install with:\n\n  pip install fastapi\n")

app = FastAPI()

def secure_filepath(filepath):
    """Checks if a filepath is within the SITE_FOLDER."""
    normalized_site_path = os.path.normpath(SITE_FOLDER)
    normalized_filepath = os.path.normpath(filepath)
    if not normalized_filepath.startswith(normalized_site_path):
        raise HTTPException(status_code=403, detail="Forbidden")
    return normalized_filepath

@app.middleware("http")
async def add_index_html(request: Request, call_next):
    response = await call_next(request)
    if response.status_code == 404:
        path = request.url.path.lstrip("/")
        full_path = os.path.join(SITE_FOLDER, path)
        if os.path.isdir(full_path):
            index_path = os.path.join(full_path, DEFAULT_FILE)
            if os.path.exists(index_path):
                try:
                    secure_filepath(index_path) #Security check
                    return FileResponse(index_path)
                except HTTPException as e:
                    return e.detail, e.status_code
    return response

class SecureStaticFiles(StaticFiles):
    async def get_response(self, path: str, scope):
        full_path = os.path.join(self.directory, path)
        try:
            secure_filepath(full_path)
            response = await super().get_response(path, scope)
            if path.endswith(".gz"):
                # Inform the browser that the file is brotli-compressed.
                response.headers["Content-Encoding"] = "gzip"
                # Remove Content-Length header, since decompressed size may differ.
                if "content-length" in response.headers:
                    del response.headers["content-length"]
                # Ensure the proper MIME type is set.
                if path.endswith(".js.gz"):
                    response.headers["Content-Type"] = "application/javascript"
                elif path.endswith(".css.gz"):
                    response.headers["Content-Type"] = "text/css"
                else:
                    import mimetypes
                    mime_type, _ = mimetypes.guess_type(path)
                    if mime_type:
                        response.headers["Content-Type"] = mime_type
            elif path.endswith(".br"):
                # Inform the browser that the file is brotli-compressed.
                response.headers["Content-Encoding"] = "br"
                # Remove Content-Length header, since decompressed size may differ.
                if "content-length" in response.headers:
                    del response.headers["content-length"]
                # Ensure the proper MIME type is set.
                if path.endswith(".js.br"):
                    response.headers["Content-Type"] = "application/javascript"
                elif path.endswith(".css.br"):
                    response.headers["Content-Type"] = "text/css"
                else:
                    import mimetypes
                    mime_type, _ = mimetypes.guess_type(path)
                    if mime_type:
                        response.headers["Content-Type"] = mime_type
            return response
        except HTTPException as e:
            return e.detail, e.status_code

app.mount("/", SecureStaticFiles(directory=SITE_FOLDER, html=False), name="static")

def get_lan_ip():
    """Gets the LAN IP address using netifaces or falls back to socket."""
    if netifaces:
        try:
            for interface in netifaces.interfaces():
                addresses = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addresses:
                    for addr_info in addresses[netifaces.AF_INET]:
                        ip = addr_info['addr']
                        if ip != '127.0.0.1':
                            return ip
                if netifaces.AF_INET6 in addresses:
                    for addr_info in addresses[netifaces.AF_INET6]:
                        ip = addr_info['addr']
                        if ip.startswith('fe80') == False and ip != '::1':
                            return ip
        except Exception as e:
            print(f"Error using netifaces: {e}")

    try:
        # Fallback to socket if netifaces fails or is not installed
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        print(f"Error getting IP: {e}")
        return "127.0.0.1"

if __name__ == "__main__":
    ip = get_lan_ip()
    print(f"serving web files\n from '{SITE_FOLDER}' directory\n connect to 'http://{ip}:{PORT}'")
    uvicorn.run(app, host="0.0.0.0", port=PORT, lifespan="off") #important lifespan = off usage

