"""Local, read-only browser UI over cached receipts and cache entries.

A plain stdlib http.server -- no framework. The dashboard HTML/CSS/JS is a
static template file (templates/dashboard.html, loaded once per server via
runtime.resource_path() so it works both from source and from a future
PyInstaller-frozen binary), not a Python string; it takes no server-side
data, everything is fetched client-side from /api/cache.
"""

import json
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
import webbrowser

from ...runtime import resource_path
from .payloads import build_ui_payload


def _dashboard_html() -> str:
    return resource_path("presentation/web/templates/dashboard.html").read_text(encoding="utf-8")


def _make_handler():
    html_bytes = _dashboard_html().encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path in {"", "/"}:
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html_bytes)))
                self.end_headers()
                self.wfile.write(html_bytes)
                return

            if parsed.path == "/api/cache":
                payload = json.dumps(build_ui_payload(), indent=2, sort_keys=True).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return

            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Not found")

        def log_message(self, format, *args):
            return

    return Handler


def create_ui_server(host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), _make_handler())


def local_url(server: ThreadingHTTPServer) -> str:
    host, port = server.server_address[:2]
    return f"http://{host}:{port}/"


def _can_open_browser() -> bool:
    try:
        webbrowser.get()
    except webbrowser.Error:
        return False
    return True


def serve_ui(host: str = "127.0.0.1", port: int = 0, open_browser: bool = True, echo=print) -> str:
    server = create_ui_server(host=host, port=port)
    url = local_url(server)
    echo(f"depshieldx UI running at {url}")
    echo("Press Ctrl-C to stop.")
    if open_browser:
        if _can_open_browser():
            webbrowser.open(url)
        else:
            echo("Browser open unavailable in this environment. Open the URL manually.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        echo("\nStopping depshieldx UI...")
    finally:
        server.server_close()
    return url


def port_is_available(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True
