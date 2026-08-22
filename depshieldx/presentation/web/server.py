"""Local, browser UI over cached receipts and cache entries.

A plain stdlib http.server -- no framework. The dashboard HTML/CSS/JS is a
static template file (templates/dashboard.html, loaded once per server via
runtime.resource_path() so it works both from source and from a future
PyInstaller-frozen binary), not a Python string; it takes no server-side
data, everything is fetched client-side from /api/cache.

Mostly read-only, with one exception: DELETE /api/receipts/<id> lets the
dashboard's own per-row delete button remove a single receipt --
delete_receipt() itself validates the id shape before it ever reaches a
filesystem path (see storage/receipts.py), so this handler only needs to
route the request, not re-validate.
"""

import json
import re
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
import webbrowser

from ...core.runtime import resource_path
from ...storage.receipts import delete_receipt
from .payloads import build_ui_payload

_RECEIPT_DELETE_PATH = re.compile(r"^/api/receipts/([^/]+)$")


def _dashboard_html() -> str:
    return resource_path("presentation/web/templates/dashboard.html").read_text(encoding="utf-8")


def _make_handler():
    html_bytes = _dashboard_html().encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def _send_json(self, status: int, payload: dict) -> None:
            body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

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
                self._send_json(200, build_ui_payload())
                return

            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Not found")

        def do_DELETE(self):
            parsed = urlparse(self.path)
            match = _RECEIPT_DELETE_PATH.match(parsed.path)
            if not match:
                self.send_response(404)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Not found")
                return

            receipt_id = match.group(1)
            if delete_receipt(receipt_id):
                self._send_json(200, {"deleted": True, "receipt_id": receipt_id})
            else:
                self._send_json(404, {"deleted": False, "receipt_id": receipt_id, "error": "receipt not found"})

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
