import unittest
from unittest.mock import patch

import pytest

from depshieldx.ecosystems.nuget.registry import (
    check_provenance_batch,
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
