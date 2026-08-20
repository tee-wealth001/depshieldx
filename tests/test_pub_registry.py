import unittest
from unittest.mock import patch

import pytest

from depshieldx.ecosystems.pub.registry import check_provenance_batch, check_release


class CheckProvenanceBatchTests(unittest.TestCase):
    def test_empty_resolved_versions_returns_no_block(self):
        result = check_provenance_batch({})

        self.assertFalse(result["block"])
        self.assertEqual(result["details"], [])

    @patch("depshieldx.ecosystems.pub.registry.check_release")
    def test_aggregates_warnings_and_infos_per_package(self, mock_check_release):
        mock_check_release.return_value = {
            "package": "demo_package",
            "version": "1.0.0",
            "block": False,
            "reason": None,
            "warnings": ["package is discontinued -- suggested replacement: demo_package_plus"],
            "infos": ["resolved artifact has a verified SHA-256 checksum against the registry-reported hash"],
            "signals": {},
        }

        result = check_provenance_batch({"demo_package": "1.0.0"})

        self.assertFalse(result["block"])
        self.assertEqual(len(result["details"]), 1)
        self.assertTrue(any("demo_package@1.0.0" in warning for warning in result["warnings"]))
        self.assertTrue(any("demo_package@1.0.0" in info for info in result["infos"]))

    @patch("depshieldx.ecosystems.pub.registry.check_release")
    def test_blocks_on_checksum_mismatch(self, mock_check_release):
        mock_check_release.return_value = {
            "package": "demo_package",
            "version": "1.0.0",
            "block": True,
            "reason": "downloaded artifact checksum does not match the registry-reported hash -- possible tampering",
            "warnings": [],
            "infos": [],
            "signals": {"checksum_verified": False},
        }

        result = check_provenance_batch({"demo_package": "1.0.0"})

        self.assertTrue(result["block"])
        self.assertIn("demo_package@1.0.0", result["reason"])


@patch("depshieldx.ecosystems.pub.registry._store_cached_result")
@patch("depshieldx.ecosystems.pub.registry._load_cached_result", return_value=None)
class CheckReleaseChecksumVerificationTests(unittest.TestCase):
    """A checksum MISMATCH is already a hard block; this covers the
    different, previously-established-pattern case (see nuget/registry.py's
    own equivalent test class): verification couldn't even be attempted --
    no checksum published, or a real error while trying -- which must
    surface as a real "verification_unavailable" signal rather than being
    indistinguishable from a clean, fully-verified result."""

    @patch("depshieldx.ecosystems.pub.registry.fetch_package_data")
    def test_missing_checksum_metadata_surfaces_verification_unavailable(
        self, mock_fetch_data, _mock_load_cache, _mock_store_cache
    ):
        mock_fetch_data.return_value = {
            "name": "demo_package",
            "latest": {"version": "1.0.0"},
            "versions": [{"version": "1.0.0", "archive_url": None, "archive_sha256": None}],
        }

        result = check_release("demo_package", "1.0.0")

        self.assertFalse(result["block"])
        self.assertFalse(result["signals"]["checksum_verified"])
        self.assertIsNotNone(result["signals"]["verification_unavailable"])

    @patch("depshieldx.ecosystems.pub.registry.fetch_archive")
    @patch("depshieldx.ecosystems.pub.registry.fetch_package_data")
    def test_verification_error_surfaces_verification_unavailable(
        self, mock_fetch_data, mock_fetch_archive, _mock_load_cache, _mock_store_cache
    ):
        mock_fetch_data.return_value = {
            "name": "demo_package",
            "latest": {"version": "1.0.0"},
            "versions": [
                {
                    "version": "1.0.0",
                    "archive_url": "https://pub.dev/api/archives/demo_package-1.0.0.tar.gz",
                    "archive_sha256": "abc123",
                }
            ],
        }
        mock_fetch_archive.side_effect = RuntimeError("simulated network failure")

        result = check_release("demo_package", "1.0.0")

        self.assertFalse(result["block"])
        self.assertFalse(result["signals"]["checksum_verified"])
        self.assertIsNotNone(result["signals"]["verification_unavailable"])
        self.assertIn("simulated network failure", result["signals"]["verification_unavailable"]["error"])

    @patch("depshieldx.ecosystems.pub.registry.fetch_archive")
    @patch("depshieldx.ecosystems.pub.registry.fetch_package_data")
    def test_successful_verification_has_no_verification_unavailable_signal(
        self, mock_fetch_data, mock_fetch_archive, _mock_load_cache, _mock_store_cache
    ):
        import hashlib

        archive_bytes = b"fake-archive-bytes"
        digest = hashlib.sha256(archive_bytes).hexdigest()
        mock_fetch_data.return_value = {
            "name": "demo_package",
            "latest": {"version": "1.0.0"},
            "versions": [
                {
                    "version": "1.0.0",
                    "archive_url": "https://pub.dev/api/archives/demo_package-1.0.0.tar.gz",
                    "archive_sha256": digest,
                }
            ],
        }
        mock_fetch_archive.return_value = archive_bytes

        result = check_release("demo_package", "1.0.0")

        self.assertFalse(result["block"])
        self.assertTrue(result["signals"]["checksum_verified"])
        self.assertIsNone(result["signals"]["verification_unavailable"])

    @patch("depshieldx.ecosystems.pub.registry.fetch_package_data")
    def test_discontinued_package_produces_warning(self, mock_fetch_data, _mock_load_cache, _mock_store_cache):
        mock_fetch_data.return_value = {
            "name": "connectivity",
            "isDiscontinued": True,
            "replacedBy": "connectivity_plus",
            "latest": {"version": "3.0.6"},
            "versions": [
                {
                    "version": "3.0.6",
                    "archive_url": "https://pub.dev/api/archives/connectivity-3.0.6.tar.gz",
                    "archive_sha256": None,
                }
            ],
        }

        result = check_release("connectivity", "3.0.6")

        self.assertFalse(result["block"])
        self.assertTrue(any("discontinued" in warning for warning in result["warnings"]))
        self.assertEqual(result["signals"]["replaced_by"], "connectivity_plus")

    @patch("depshieldx.ecosystems.pub.registry.fetch_package_data")
    def test_retracted_version_produces_warning(self, mock_fetch_data, _mock_load_cache, _mock_store_cache):
        mock_fetch_data.return_value = {
            "name": "demo_package",
            "latest": {"version": "1.0.1"},
            "versions": [
                {"version": "1.0.0", "retracted": True, "archive_url": None, "archive_sha256": None},
            ],
        }

        result = check_release("demo_package", "1.0.0")

        self.assertFalse(result["block"])
        self.assertTrue(any("retracted" in warning for warning in result["warnings"]))
        self.assertTrue(result["signals"]["retracted"])


@pytest.mark.live
class PubRegistryLiveTests(unittest.TestCase):
    """Hits the real pub.dev. Marked live -- excluded from the default CI
    run (`pytest -m "not live"`)."""

    def test_fetch_package_data_reports_real_shape(self):
        from depshieldx.ecosystems.pub.registry import fetch_package_data

        data = fetch_package_data("http")

        self.assertEqual(data.get("name"), "http")
        self.assertIn("version", data.get("latest") or {})
        self.assertTrue(data.get("versions"))

    def test_latest_version_resolves_a_real_package(self):
        from depshieldx.ecosystems.pub.registry import latest_version

        version = latest_version("http")

        self.assertIsNotNone(version)

    def test_check_release_verifies_real_checksum(self):
        from depshieldx.ecosystems.pub.registry import fetch_package_data, check_release

        data = fetch_package_data("http")
        version = data["latest"]["version"]

        result = check_release("http", version)

        self.assertFalse(result["block"])
        self.assertTrue(result["signals"]["checksum_verified"])

    def test_check_release_reports_real_discontinued_package(self):
        from depshieldx.ecosystems.pub.registry import check_release

        result = check_release("connectivity", "3.0.6")

        self.assertTrue(result["signals"]["discontinued"])
        self.assertEqual(result["signals"]["replaced_by"], "connectivity_plus")


if __name__ == "__main__":
    unittest.main()
