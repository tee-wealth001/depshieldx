import json
import os
import threading
import urllib.error
import urllib.request
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from depshieldx.presentation.web.payloads import build_ui_payload
from depshieldx.presentation.web.server import create_ui_server, serve_ui
from depshieldx.receipts import list_receipts, write_receipt


class UiTests(unittest.TestCase):
    def test_build_ui_payload_collects_receipts_bundle_and_provenance_entries(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_root = Path(temp_dir) / "cache"
            receipts_root = Path(temp_dir) / "receipts"
            cache_root.mkdir()
            receipts_root.mkdir()
            (cache_root / "provenance").mkdir()

            receipt_payload = {
                "receipt_id": "receipt123",
                "created_at": "2026-03-31T13:47:19+00:00",
                "decision": "allowed",
                "package": "fastapi",
                "package_version": "0.135.2",
                "mode": "fast",
                "requested_target": "fastapi",
                "summary": {
                    "package": {"project_url": "https://pypi.org/project/fastapi/0.135.2/"},
                    "install": {"target": "fastapi==0.135.2"},
                },
            }
            (receipts_root / "receipt.json").write_text(json.dumps(receipt_payload))

            npm_receipt_payload = {
                "receipt_id": "receipt456",
                "created_at": "2026-03-31T13:48:19+00:00",
                "decision": "allowed",
                "ecosystem": "npm",
                "package": "left-pad",
                "package_version": "1.3.0",
                "mode": "fast",
                "requested_target": "left-pad",
                "summary": {},
            }
            (receipts_root / "receipt-npm.json").write_text(json.dumps(npm_receipt_payload))

            bundle_dir = cache_root / "bundlefingerprint"
            bundle_dir.mkdir()
            (bundle_dir / "depshieldx-lock.txt").write_text("fastapi==0.135.2\n")
            (bundle_dir / "metadata.json").write_text(
                json.dumps(
                    {
                        "cached_at": "2026-03-31T13:47:19+00:00",
                        "success": True,
                        "downloaded_files": ["fastapi.whl"],
                        "artifact_hashes": {"fastapi.whl": "abc"},
                        "isolation": {"backend": "docker"},
                    }
                )
            )

            provenance_payload = {
                "cached_at": "2026-03-31T13:47:19+00:00",
                "result": {
                    "package": "fastapi",
                    "version": "0.135.2",
                    "block": False,
                    "warnings": [],
                    "infos": ["resolved release has no PyPI attestations"],
                    "signals": {
                        "selected_file_count": 2,
                        "attested_file_count": 1,
                        "verified_attestation_count": 1,
                    },
                },
            }
            (cache_root / "provenance" / "fastapi.json").write_text(json.dumps(provenance_payload))

            with patch.dict(
                os.environ,
                {
                    "DEPSHIELDX_CACHE_DIR": str(cache_root),
                    "DEPSHIELDX_RECEIPTS_DIR": str(receipts_root),
                },
                clear=False,
            ):
                payload = build_ui_payload()

        self.assertEqual(payload["summary"]["receipt_count"], 2)
        self.assertEqual(payload["summary"]["bundle_count"], 1)
        self.assertEqual(payload["summary"]["provenance_count"], 1)
        receipts_by_package = {row["package"]: row for row in payload["receipts"]}
        self.assertEqual(receipts_by_package["fastapi"]["ecosystem"], "pypi")
        self.assertEqual(receipts_by_package["left-pad"]["ecosystem"], "npm")
        self.assertEqual(payload["bundles"][0]["backend"], "docker")
        self.assertEqual(payload["provenance"][0]["package"], "fastapi")

    @patch("depshieldx.presentation.web.server._can_open_browser", return_value=True)
    @patch("depshieldx.presentation.web.server.webbrowser.open")
    @patch("depshieldx.presentation.web.server.create_ui_server")
    def test_serve_ui_announces_url_and_closes_server(
        self,
        mock_create_ui_server,
        mock_browser_open,
        _mock_can_open_browser,
    ):
        server = Mock()
        server.server_address = ("127.0.0.1", 43123)
        server.serve_forever.side_effect = KeyboardInterrupt()
        mock_create_ui_server.return_value = server
        messages = []

        url = serve_ui(port=0, open_browser=True, echo=messages.append)

        self.assertEqual(url, "http://127.0.0.1:43123/")
        self.assertIn("depshieldx UI running at http://127.0.0.1:43123/", messages[0])
        mock_browser_open.assert_called_once_with("http://127.0.0.1:43123/")
        server.server_close.assert_called_once()


class ReceiptDeleteEndpointTests(unittest.TestCase):
    """Exercises DELETE /api/receipts/<id> through a real ephemeral
    ThreadingHTTPServer (not a mocked handler) -- the only way to cover
    do_DELETE's actual request-parsing/response-writing behavior, the
    same way a real browser fetch() would hit it."""

    def _start_server(self):
        server = create_ui_server(port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        # addCleanup runs LIFO -- registered in the order that stops
        # serve_forever's loop (shutdown) before closing the socket out
        # from under it (server_close), confirmed directly the reverse
        # order races serve_forever's select() against server_close() on
        # Windows ("An operation was attempted on something that is not
        # a socket").
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        host, port = server.server_address[:2]
        return f"http://{host}:{port}"

    def test_delete_removes_existing_receipt_and_returns_200(self):
        report = {
            "package": "flask",
            "mode": "fast",
            "requested_at": "2026-03-26T12:00:00+00:00",
            "resolution": {
                "install_target": "Flask==3.1.3",
                "requested_targets": ["flask"],
                "resolved_versions": {"Flask": "3.1.3"},
                "packages": ["Flask"],
                "source_type": "package",
                "resolution_succeeded": True,
            },
            "scan": {"block": False, "warnings": [], "infos": []},
            "provenance": {"block": False, "warnings": [], "infos": [], "details": []},
            "install": {"attempted": True, "success": True, "target": "Flask==3.1.3"},
        }
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as key_dir:
            with patch.dict(
                os.environ,
                {"DEPSHIELDX_RECEIPTS_DIR": temp_dir, "DEPSHIELDX_SIGNING_KEY_DIR": key_dir},
                clear=False,
            ):
                written = write_receipt(report)
                base_url = self._start_server()

                request = urllib.request.Request(f"{base_url}/api/receipts/{written['receipt_id']}", method="DELETE")
                with urllib.request.urlopen(request) as response:
                    status = response.status
                    body = json.loads(response.read())

                remaining = list_receipts()

        self.assertEqual(status, 200)
        self.assertTrue(body["deleted"])
        self.assertEqual(body["receipt_id"], written["receipt_id"])
        self.assertEqual(remaining, [])

    def test_delete_unknown_receipt_returns_404(self):
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as key_dir:
            with patch.dict(
                os.environ,
                {"DEPSHIELDX_RECEIPTS_DIR": temp_dir, "DEPSHIELDX_SIGNING_KEY_DIR": key_dir},
                clear=False,
            ):
                base_url = self._start_server()
                request = urllib.request.Request(f"{base_url}/api/receipts/0123456789abcdef", method="DELETE")
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(request)

        self.assertEqual(ctx.exception.code, 404)
        body = json.loads(ctx.exception.read())
        self.assertFalse(body["deleted"])

    def test_delete_with_extra_path_segments_returns_404_not_found(self):
        # Not a receipt-not-found 404 (which still returns a JSON body) --
        # a real routing miss, confirming the handler doesn't loosely
        # match anything starting with "/api/receipts/".
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as key_dir:
            with patch.dict(
                os.environ,
                {"DEPSHIELDX_RECEIPTS_DIR": temp_dir, "DEPSHIELDX_SIGNING_KEY_DIR": key_dir},
                clear=False,
            ):
                base_url = self._start_server()
                request = urllib.request.Request(f"{base_url}/api/receipts/abc/extra", method="DELETE")
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(request)

        self.assertEqual(ctx.exception.code, 404)
        self.assertEqual(ctx.exception.getheader("Content-Type"), "text/plain; charset=utf-8")
