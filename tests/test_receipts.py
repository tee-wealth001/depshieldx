import os
import json
import tempfile
import unittest
from unittest.mock import patch

from depshieldx.receipts import (
    ReceiptUnavailableError,
    _signing_key_path,
    delete_receipt,
    delete_receipts,
    list_receipts,
    verify_receipt,
    write_receipt,
)


class ReceiptTests(unittest.TestCase):
    def test_write_verify_and_list_receipt_round_trip(self):
        report = {
            "package": "flask",
            "mode": "fast",
            "requested_at": "2026-03-26T12:00:00+00:00",
            "resolution": {
                "install_target": "Flask==3.1.3",
                "packages": ["Flask"],
                "source_type": "package",
                "resolution_succeeded": True,
            },
            "scan": {"block": False, "warnings": [], "infos": ["reputation note"]},
            "provenance": {"block": False, "warnings": [], "infos": []},
            "sandbox": {"success": None, "error_type": None, "isolation": {}, "trust": {}},
            "install": {"attempted": True, "success": True, "target": "Flask==3.1.3"},
        }

        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as key_dir:
            with patch.dict(
                os.environ,
                {"DEPSHIELDX_RECEIPTS_DIR": temp_dir, "DEPSHIELDX_SIGNING_KEY_DIR": key_dir},
                clear=False,
            ):
                written = write_receipt(report)
                verified = verify_receipt(written["path"])
                listed = list_receipts()

        self.assertEqual(written["decision"], "allowed")
        self.assertTrue(verified["valid"])
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["receipt_id"], written["receipt_id"])
        self.assertEqual(listed[0]["package"], "flask")
        self.assertIn("key_id", verified["receipt"]["signature"])

    def test_write_receipt_creates_per_requested_package_receipts(self):
        report = {
            "package": "langchain, requests",
            "mode": "deep",
            "requested_at": "2026-03-26T12:00:00+00:00",
            "resolution": {
                "install_target": "langchain, requests",
                "requested_targets": ["langchain", "requests"],
                "resolved_versions": {"langchain": "1.2.13", "requests": "2.33.1", "httpx": "0.28.1"},
                "selected_artifacts": {
                    "langchain": [{"filename": "langchain-1.2.13-py3-none-any.whl"}],
                    "requests": [{"filename": "requests-2.33.1-py3-none-any.whl"}],
                },
                "packages": ["langchain", "requests"],
                "source_type": "packages",
                "resolution_succeeded": True,
            },
            "scan": {
                "block": False,
                "warnings": [],
                "infos": [],
                "threat_intelligence": {
                    "multi_source_cves": {
                        "langchain": {
                            "current": [],
                            "historical": [
                                {
                                    "cve_id": "CVE-2024-0001",
                                    "source": "osv",
                                    "affected_versions": ["<1.2.0"],
                                    "fixed_in_version": "1.2.0",
                                    "severity": "HIGH",
                                    "summary": "historical example",
                                    "aliases": ["GHSA-demo"],
                                }
                            ],
                        },
                        "requests": {"current": [], "historical": []},
                    }
                },
            },
            "provenance": {
                "block": False,
                "warnings": [],
                "infos": ["langchain==1.2.13: resolved release has no PyPI attestations"],
                "details": [
                    {"package": "langchain", "signals": {"selected_file_count": 1, "attested_file_count": 0}},
                    {"package": "requests", "signals": {"selected_file_count": 1, "attested_file_count": 1}},
                ],
            },
            "sandbox": {"success": True, "error_type": None, "isolation": {"backend": "docker"}},
            "install": {"attempted": True, "success": True, "target": "langchain, requests"},
        }

        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as key_dir:
            with patch.dict(
                os.environ,
                {"DEPSHIELDX_RECEIPTS_DIR": temp_dir, "DEPSHIELDX_SIGNING_KEY_DIR": key_dir},
                clear=False,
            ):
                written = write_receipt(report)
                listed = list_receipts()
                langchain_receipt = next(entry for entry in written["receipts"] if entry["package"] == "langchain")
                payload = json.loads(open(langchain_receipt["path"], encoding="utf-8").read())

        self.assertEqual(written["receipt_count"], 2)
        self.assertEqual(len(written["receipts"]), 2)
        self.assertEqual(len(listed), 2)
        self.assertTrue(any("langchain-1.2.13" in entry["path"] for entry in written["receipts"]))
        self.assertTrue(any("requests-2.33.1" in entry["path"] for entry in written["receipts"]))
        self.assertEqual(payload["summary"]["package"]["project_url"], "https://pypi.org/project/langchain/1.2.13/")
        self.assertIn("historical_fixed", payload["summary"]["scan"])
        self.assertEqual(payload["summary"]["scan"]["historical_fixed"][0]["cve_id"], "CVE-2024-0001")

    def test_delete_receipts_removes_all_receipt_files(self):
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
                write_receipt(report)
                deleted = delete_receipts()
                listed = list_receipts()

        self.assertEqual(deleted, 1)
        self.assertEqual(listed, [])

    def test_delete_receipt_removes_only_the_matching_one(self):
        flask_report = {
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
        requests_report = {
            "package": "requests",
            "mode": "fast",
            "requested_at": "2026-03-26T12:00:00+00:00",
            "resolution": {
                "install_target": "requests==2.33.1",
                "requested_targets": ["requests"],
                "resolved_versions": {"requests": "2.33.1"},
                "packages": ["requests"],
                "source_type": "package",
                "resolution_succeeded": True,
            },
            "scan": {"block": False, "warnings": [], "infos": []},
            "provenance": {"block": False, "warnings": [], "infos": [], "details": []},
            "install": {"attempted": True, "success": True, "target": "requests==2.33.1"},
        }

        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as key_dir:
            with patch.dict(
                os.environ,
                {"DEPSHIELDX_RECEIPTS_DIR": temp_dir, "DEPSHIELDX_SIGNING_KEY_DIR": key_dir},
                clear=False,
            ):
                flask_written = write_receipt(flask_report)
                write_receipt(requests_report)
                deleted = delete_receipt(flask_written["receipt_id"])
                listed = list_receipts()

        self.assertTrue(deleted)
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["package"], "requests")

    def test_delete_receipt_returns_false_for_unknown_id(self):
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as key_dir:
            with patch.dict(
                os.environ,
                {"DEPSHIELDX_RECEIPTS_DIR": temp_dir, "DEPSHIELDX_SIGNING_KEY_DIR": key_dir},
                clear=False,
            ):
                deleted = delete_receipt("0123456789abcdef")

        self.assertFalse(deleted)

    def test_delete_receipt_rejects_malformed_ids_without_touching_disk(self):
        # Confirmed directly this matters: receipt_id comes straight from
        # an HTTP request path segment (server.py's do_DELETE) -- a
        # traversal-shaped id must be rejected by shape before it ever
        # reaches glob(), not merely fail to match a real file by luck.
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as key_dir:
            with patch.dict(
                os.environ,
                {"DEPSHIELDX_RECEIPTS_DIR": temp_dir, "DEPSHIELDX_SIGNING_KEY_DIR": key_dir},
                clear=False,
            ):
                for malformed in ("../../etc/passwd", "", "not-hex-zzzzzzzz", "toolongtobearealreceiptid00"):
                    self.assertFalse(delete_receipt(malformed), msg=f"expected rejection for {malformed!r}")

    @patch("depshieldx.receipts._receipts_root_candidates", return_value=[])
    def test_list_receipts_returns_empty_when_store_is_unavailable(self, _mock_candidates):
        self.assertEqual(list_receipts(), [])

    def test_verify_receipt_rejects_insecure_signing_key_permissions(self):
        report = {
            "package": "flask",
            "mode": "fast",
            "requested_at": "2026-03-26T12:00:00+00:00",
            "resolution": {
                "install_target": "Flask==3.1.3",
                "packages": ["Flask"],
                "source_type": "package",
                "resolution_succeeded": True,
            },
            "scan": {"block": False, "warnings": [], "infos": []},
            "provenance": {"block": False, "warnings": [], "infos": []},
            "install": {"attempted": True, "success": True, "target": "Flask==3.1.3"},
        }

        with tempfile.TemporaryDirectory() as receipts_dir, tempfile.TemporaryDirectory() as key_dir:
            with patch.dict(
                os.environ,
                {"DEPSHIELDX_RECEIPTS_DIR": receipts_dir, "DEPSHIELDX_SIGNING_KEY_DIR": key_dir},
                clear=False,
            ):
                written = write_receipt(report)
                key_path = _signing_key_path()
                os.chmod(key_path, 0o644)
                if os.name == "nt":
                    self.skipTest("POSIX permission check not applicable on Windows")
                with self.assertRaises(ReceiptUnavailableError):
                    verify_receipt(written["path"])
