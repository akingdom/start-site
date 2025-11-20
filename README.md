# start-site
Serves a local folder as a website. Useful for when you need a customisable web server for quick testing. 

## Prerequisites

- [Install Python 3.8+](https://www.python.org/downloads/)
- `pip install --upgrade pip`

## Installation

1. Clone:

```python
git clone https://github.com/akingdom/start-site.git
cd start-site
```

## Usage

Run the script.
`python3 start_site_server.py`

### Important

HTTPS service may require *restarting the web browser* if a security warning is present after this script tries to create and install a local certificate.

## Settings

There are several settings you can customise in the `start_site_server.py` file.
```python
# --- EDITABLE SERVER CONFIGURATION ---
class ServerConfig:
    def __init__(self):
        self.HTTP_PORT: int = 8002  # TCP Port for HTTP traffic (will redirect to HTTPS_PORT if SECURE_SITE = True)
        self.HTTPS_PORT: int = 8003  # TCP Port for HTTPS traffic
        self.SITE_FOLDER: str = "live"  # Folder containing web-site files. This site folder must be in the same 'parent' folder that contains this start_site.py script.
        self.DEFAULT_FILE: str = "index.html"  # Name of the preferred file to open when a web client doesn't specify a filename.
        self.SECURE_SITE: bool = True  # True for HTTPS/SSL traffic with HTTP redirect, else False for plain HTTP.
        self.FORCE_CERTIFICATE_REGENERATION: bool = False  # Set to True to force regeneration of SSL certificates on startup, even if valid. Set to False (default) to only regenerate if missing or expired.
        self.BASE_PORT: int = 8001  # A fixed, well-known base port for the master server across all instances (used by site_manager.py). Generally this should never change.
        self.VERSION: str = VERSION  # Application version number. Note: Leave this as-is, as it reflects the version above.
        ...
# --- END EDITABLE SERVER CONFIGURATION ---
```


