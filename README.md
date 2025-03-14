# start-site
Serves a local folder as a website. Useful for when you need a web server for quick testing

## Usage

(Install Python 3)[https://www.python.org/downloads/]

Run the script.
`python3 start_site.py`

## Settings

There are several settings you can customise in the `start_site.py` file.
```python
# SETTINGS ==========================================
# PORT = TCP Port ()
PORT = 8000
# SITE_FOLDER = Name of the folder that contains the web-site files. This site folder must be in the same 'parent' folder that contains this start_site.py script.
SITE_FOLDER = "live"
# DEFAULT_FILE = Name of the preferred file to open when a web client doens't specify a filename.
DEFAULT_FILE = "index.html"
# SETTINGS-END ======================================
```
