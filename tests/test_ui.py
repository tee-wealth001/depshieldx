import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from depshieldx.presentation.web.payloads import build_ui_payload
from depshieldx.presentation.web.server import serve_ui


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
