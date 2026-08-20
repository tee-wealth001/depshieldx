import unittest
from unittest.mock import patch

import pytest

from depshieldx.ecosystems.nuget.registry import (
    check_provenance_batch,
    check_release,
    flat_container_nupkg_url,
)


class FlatContainerNupkgUrlTests(unittest.TestCase):
    def test_lowercases_id_and_version(self):
        self.assertEqual(
            flat_container_nupkg_url("Newtonsoft.Json", "13.0.3"),
            "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg",
        )


class CheckProvenanceBatchTests(unittest.TestCase):
    def test_empty_resolved_versions_returns_no_block(self):
        result = check_provenance_batch({})

        self.assertFalse(result["block"])
        self.assertEqual(result["details"], [])

    @patch("depshieldx.ecosystems.nuget.registry.check_release")
    def test_aggregates_warnings_and_infos_per_package(self, mock_check_release):
        mock_check_release.return_value = {
            "package": "Demo.Package",
            "version": "1.0.0",
            "block": False,
            "reason": None,
            "warnings": ["resolved version is marked deprecated: use Demo.Package.V2 instead"],
            "infos": ["resolved artifact has a verified SHA512 checksum against the registry-reported hash"],
            "signals": {},
        }

        result = check_provenance_batch({"Demo.Package": "1.0.0"})

        self.assertFalse(result["block"])
        self.assertEqual(len(result["details"]), 1)
        self.assertTrue(any("Demo.Package@1.0.0" in warning for warning in result["warnings"]))
        self.assertTrue(any("Demo.Package@1.0.0" in info for info in result["infos"]))

    @patch("depshieldx.ecosystems.nuget.registry.check_release")
    def test_blocks_on_checksum_mismatch(self, mock_check_release):
        mock_check_release.return_value = {
            "package": "Demo.Package",
            "version": "1.0.0",
            "block": True,
            "reason": "downloaded artifact checksum does not match the registry-reported hash -- possible tampering",
            "warnings": [],
            "infos": [],
            "signals": {"checksum_verified": False},
        }

        result = check_provenance_batch({"Demo.Package": "1.0.0"})

        self.assertTrue(result["block"])
        self.assertIn("Demo.Package@1.0.0", result["reason"])


@patch("depshieldx.ecosystems.nuget.registry._store_cached_result")
@patch("depshieldx.ecosystems.nuget.registry._load_cached_result", return_value=None)
class CheckReleaseChecksumVerificationTests(unittest.TestCase):
    """A checksum MISMATCH is already a hard block (see
    CheckProvenanceBatchTests.test_blocks_on_checksum_mismatch). This
    covers the different, previously-silent case: verification couldn't
    even be attempted -- no checksum published, or a real error while
    trying -- which must now surface as a real "verification_unavailable"
    signal (the same shape npm's own attestation-verification-unavailable
    case uses, so cli/output.py already renders it) rather than being an
    info-only message no worse than a clean, fully-verified result."""

    @patch("depshieldx.ecosystems.nuget.registry.fetch_catalog_entry")
    def test_missing_checksum_metadata_surfaces_verification_unavailable(
        self, mock_catalog, _mock_load_cache, _mock_store_cache
    ):
        mock_catalog.return_value = {"listed": True, "deprecation": None, "packageHash": None, "packageHashAlgorithm": None}

        result = check_release("Test.ChecksumMissing", "1.0.0")

        self.assertFalse(result["block"])
        self.assertFalse(result["signals"]["checksum_verified"])
        self.assertIsNotNone(result["signals"]["verification_unavailable"])
        self.assertEqual(result["signals"]["verification_unavailable"]["filename"], "Test.ChecksumMissing.1.0.0.nupkg")

    @patch("depshieldx.ecosystems.nuget.registry.fetch_nupkg")
    @patch("depshieldx.ecosystems.nuget.registry.fetch_catalog_entry")
    def test_verification_error_surfaces_verification_unavailable(
        self, mock_catalog, mock_fetch_nupkg, _mock_load_cache, _mock_store_cache
    ):
        mock_catalog.return_value = {
            "listed": True,
            "deprecation": None,
            "packageHash": "abc123",
            "packageHashAlgorithm": "SHA512",
        }
        mock_fetch_nupkg.side_effect = RuntimeError("simulated network failure")

        result = check_release("Test.ChecksumError", "1.0.0")

        self.assertFalse(result["block"])
        self.assertFalse(result["signals"]["checksum_verified"])
        self.assertIsNotNone(result["signals"]["verification_unavailable"])
        self.assertIn("simulated network failure", result["signals"]["verification_unavailable"]["error"])

    @patch("depshieldx.ecosystems.nuget.registry.has_repository_signature", return_value=True)
    @patch("depshieldx.ecosystems.nuget.registry.fetch_nupkg", return_value=b"fake-nupkg-bytes")
    @patch("depshieldx.ecosystems.nuget.registry.fetch_catalog_entry")
    def test_successful_verification_has_no_verification_unavailable_signal(
        self, mock_catalog, _mock_fetch_nupkg, _mock_signed, _mock_load_cache, _mock_store_cache
    ):
        import base64
        import hashlib

        digest = hashlib.sha512(b"fake-nupkg-bytes").digest()
        mock_catalog.return_value = {
            "listed": True,
            "deprecation": None,
            "packageHash": base64.b64encode(digest).decode("ascii"),
            "packageHashAlgorithm": "SHA512",
        }

        result = check_release("Test.ChecksumOk", "1.0.0")

        self.assertFalse(result["block"])
        self.assertTrue(result["signals"]["checksum_verified"])
        self.assertIsNone(result["signals"]["verification_unavailable"])


@pytest.mark.live
class NuGetRegistryLiveTests(unittest.TestCase):
    """Hits the real api.nuget.org and azuresearch-usnc.nuget.org. Marked
    live -- excluded from the default CI run (`pytest -m "not live"`)."""

    def test_fetch_catalog_entry_reports_real_checksum(self):
        from depshieldx.ecosystems.nuget.registry import fetch_catalog_entry

        entry = fetch_catalog_entry("Newtonsoft.Json", "13.0.3")

        self.assertEqual(entry.get("packageHashAlgorithm"), "SHA512")
        self.assertTrue(entry.get("packageHash"))

    def test_check_release_verifies_real_checksum_and_signature(self):
        from depshieldx.ecosystems.nuget.registry import check_release

        result = check_release("Newtonsoft.Json", "13.0.3")

        self.assertFalse(result["block"])
        self.assertTrue(result["signals"]["checksum_verified"])
        self.assertTrue(result["signals"]["repository_signed"])

    def test_check_release_reports_real_deprecation(self):
        from depshieldx.ecosystems.nuget.registry import check_release

        result = check_release("Microsoft.IdentityModel.JsonWebTokens", "5.6.0")

        self.assertFalse(result["block"])
        self.assertTrue(result["signals"]["deprecated"])
        self.assertTrue(any("deprecated" in warning for warning in result["warnings"]))

    def test_search_latest_version_resolves_a_real_package(self):
        from depshieldx.ecosystems.nuget.registry import search_latest_version

        version = search_latest_version("Newtonsoft.Json")

        self.assertIsNotNone(version)
        self.assertRegex(version, r"^\d+\.\d+")


if __name__ == "__main__":
    unittest.main()
