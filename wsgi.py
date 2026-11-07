"""Production entry point for WSGI servers.

    gunicorn -w 3 -b 0.0.0.0:8000 wsgi:app          (Linux)
    waitress-serve --listen=0.0.0.0:8000 wsgi:app   (Windows)

Importing ``run`` also loads the ``.env`` file.
"""
from run import app  # noqa: F401
