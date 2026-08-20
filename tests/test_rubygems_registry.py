import unittest
from unittest.mock import MagicMock, patch

import pytest
import requests

from depshieldx.ecosystems.rubygems.registry import check_provenance_batch, check_release


class CheckProvenanceBatchTests(unittest.TestCase):
    def test_empty_resolved_versions_returns_no_block(self):
        result = check_provenance_batch({})

        self.assertFalse(result["block"])
        self.assertEqual(result["details"], [])

    @patch("depshieldx.ecosystems.rubygems.registry.check_release")
    def test_aggregates_warnings_and_infos_per_package(self, mock_check_release):
        mock_check_release.return_value = {
            "package": "demo_gem",
            "version": "1.0.0",
            "block": False,
            "reason": None,
            "warnings": ["resolved version has been yanked by its publisher"],
            "infos": ["resolved artifact has a verified SHA-256 checksum against the registry-reported hash"],
            "signals": {},
        }

        result = check_provenance_batch({"demo_gem": "1.0.0"})

        self.assertFalse(result["block"])
        self.assertEqual(len(result["details"]), 1)
        self.assertTrue(any("demo_gem@1.0.0" in warning for warning in result["warnings"]))
        self.assertTrue(any("demo_gem@1.0.0" in info for info in result["infos"]))

    @patch("depshieldx.ecosystems.rubygems.registry.check_release")
    def test_blocks_on_checksum_mismatch(self, mock_check_release):
        mock_check_release.return_value = {
            "package": "demo_gem",
            "version": "1.0.0",
            "block": True,
            "reason": "downloaded artifact checksum does not match the registry-reported hash -- possible tampering",
            "warnings": [],
            "infos": [],
            "signals": {"checksum_verified": False},
        }

        result = check_provenance_batch({"demo_gem": "1.0.0"})

        self.assertTrue(result["block"])
        self.assertIn("demo_gem@1.0.0", result["reason"])


def _http_error(status_code):
    response = MagicMock(status_code=status_code)
    error = requests.HTTPError(response=response)
    return error


@patch("depshieldx.ecosystems.rubygems.registry._store_cached_result")
@patch("depshieldx.ecosystems.rubygems.registry._load_cached_result", return_value=None)
class CheckReleaseTests(unittest.TestCase):
    """Mirrors nuget/registry.py's and pub/registry.py's own equivalent
    test classes: a checksum MISMATCH is already a hard block; this covers
    the different case where verification couldn't even be attempted."""

    @patch("depshieldx.ecosystems.rubygems.registry.fetch_version_data")
    def test_404_surfaces_as_non_blocking_verification_unavailable_not_a_confirmed_yank(
        self, mock_fetch_version, _mock_load_cache, _mock_store_cache
    ):
        # The real, confirmed-directly finding this module is built
        # around: a 404 from the per-version endpoint is genuinely
        # ambiguous between "never existed" and "yanked and purged" (see
        # registry.py's module docstring, and the real 2019 rest-client
        # 1.6.10-1.6.13 hijack incident this was confirmed against) -- it
        # must never be asserted as a confirmed yank.
        mock_fetch_version.side_effect = _http_error(404)

        result = check_release("rest-client", "1.6.13")

        self.assertFalse(result["block"])
        self.assertFalse(result["signals"]["checksum_verified"])
        self.assertIsNotNone(result["signals"]["verification_unavailable"])
        # Hedged ("may have been yanked"), never asserted as fact ("has
        # been yanked") -- and no "yanked" signal key is set at all here,
        # unlike the real yanked:true case covered separately below.
        self.assertTrue(any("may have been yanked" in warning for warning in result["warnings"]))
        self.assertNotIn("yanked", result["signals"])

    @patch("depshieldx.ecosystems.rubygems.registry.fetch_version_data")
    def test_non_404_http_error_reports_generic_fetch_failure(
        self, mock_fetch_version, _mock_load_cache, _mock_store_cache
    ):
        mock_fetch_version.side_effect = _http_error(500)

        result = check_release("demo_gem", "1.0.0")

        self.assertFalse(result["block"])
        self.assertTrue(any("could not fetch package metadata" in warning for warning in result["warnings"]))
        self.assertEqual(result["signals"], {})

    @patch("depshieldx.ecosystems.rubygems.registry.fetch_version_data")
    def test_yanked_true_produces_warning(self, mock_fetch_version, _mock_load_cache, _mock_store_cache):
        # A version still tracked by the registry (yanked recently enough
        # not to have been purged yet) surfaces a real, confirmed
        # "yanked": true payload -- confirmed directly against rubygems.
        # org's own API documentation example response.
        mock_fetch_version.return_value = {
            "name": "demo_gem",
            "version": "1.0.0",
            "yanked": True,
            "sha": None,
            "gem_uri": None,
        }

        result = check_release("demo_gem", "1.0.0")

        self.assertFalse(result["block"])
        self.assertTrue(any("yanked" in warning for warning in result["warnings"]))
        self.assertTrue(result["signals"]["yanked"])

    @patch("depshieldx.ecosystems.rubygems.registry.fetch_version_data")
    def test_missing_checksum_metadata_surfaces_verification_unavailable(
        self, mock_fetch_version, _mock_load_cache, _mock_store_cache
    ):
        mock_fetch_version.return_value = {
            "name": "demo_gem",
            "version": "1.0.0",
            "yanked": False,
            "sha": None,
            "gem_uri": None,
        }

        result = check_release("demo_gem", "1.0.0")

        self.assertFalse(result["block"])
        self.assertFalse(result["signals"]["checksum_verified"])
        self.assertIsNotNone(result["signals"]["verification_unavailable"])

    @patch("depshieldx.ecosystems.rubygems.registry.fetch_archive")
    @patch("depshieldx.ecosystems.rubygems.registry.fetch_version_data")
    def test_verification_error_surfaces_verification_unavailable(
        self, mock_fetch_version, mock_fetch_archive, _mock_load_cache, _mock_store_cache
    ):
        mock_fetch_version.return_value = {
            "name": "demo_gem",
            "version": "1.0.0",
            "yanked": False,
            "sha": "abc123",
            "gem_uri": "https://rubygems.org/gems/demo_gem-1.0.0.gem",
        }
        mock_fetch_archive.side_effect = RuntimeError("simulated network failure")

        result = check_release("demo_gem", "1.0.0")

        self.assertFalse(result["block"])
        self.assertFalse(result["signals"]["checksum_verified"])
        self.assertIsNotNone(result["signals"]["verification_unavailable"])
        self.assertIn("simulated network failure", result["signals"]["verification_unavailable"]["error"])

    @patch("depshieldx.ecosystems.rubygems.registry.fetch_archive")
    @patch("depshieldx.ecosystems.rubygems.registry.fetch_version_data")
    def test_checksum_mismatch_blocks(self, mock_fetch_version, mock_fetch_archive, _mock_load_cache, _mock_store_cache):
        mock_fetch_version.return_value = {
            "name": "demo_gem",
            "version": "1.0.0",
            "yanked": False,
            "sha": "not-the-real-hash",
            "gem_uri": "https://rubygems.org/gems/demo_gem-1.0.0.gem",
        }
        mock_fetch_archive.return_value = b"fake-archive-bytes"

        result = check_release("demo_gem", "1.0.0")

        self.assertTrue(result["block"])
        self.assertIn("possible tampering", result["reason"])

    @patch("depshieldx.ecosystems.rubygems.registry.fetch_archive")
    @patch("depshieldx.ecosystems.rubygems.registry.fetch_version_data")
    def test_successful_verification_has_no_verification_unavailable_signal(
        self, mock_fetch_version, mock_fetch_archive, _mock_load_cache, _mock_store_cache
    ):
        import hashlib

        archive_bytes = b"fake-archive-bytes"
        digest = hashlib.sha256(archive_bytes).hexdigest()
        mock_fetch_version.return_value = {
            "name": "demo_gem",
            "version": "1.0.0",
            "yanked": False,
            "sha": digest,
            "gem_uri": "https://rubygems.org/gems/demo_gem-1.0.0.gem",
        }
        mock_fetch_archive.return_value = archive_bytes

        result = check_release("demo_gem", "1.0.0")

        self.assertFalse(result["block"])
        self.assertTrue(result["signals"]["checksum_verified"])
        self.assertIsNone(result["signals"]["verification_unavailable"])


@pytest.mark.live
class RubyGemsRegistryLiveTests(unittest.TestCase):
    """Hits the real rubygems.org. Marked live -- excluded from the
    default CI run (`pytest -m "not live"`)."""

    def test_latest_version_resolves_a_real_gem(self):
        from depshieldx.ecosystems.rubygems.registry import latest_version

        version = latest_version("json")

        self.assertIsNotNone(version)

    def test_latest_version_returns_none_for_nonexistent_gem(self):
        from depshieldx.ecosystems.rubygems.registry import latest_version

        version = latest_version("this-gem-definitely-does-not-exist-xyz123")

        self.assertIsNone(version)

    def test_check_release_verifies_real_checksum(self):
        result = check_release("json", "2.9.0")

        self.assertFalse(result["block"])
        self.assertTrue(result["signals"]["checksum_verified"])

    def test_check_release_reports_real_purged_yank_as_unavailable_not_a_crash(self):
        # The real 2019 rest-client hijack incident (1.6.10-1.6.13) --
        # confirmed directly this 404s on the per-version endpoint rather
        # than returning "yanked": true.
        result = check_release("rest-client", "1.6.13")

        self.assertFalse(result["block"])
        self.assertIsNotNone(result["signals"]["verification_unavailable"])


if __name__ == "__main__":
    unittest.main()
