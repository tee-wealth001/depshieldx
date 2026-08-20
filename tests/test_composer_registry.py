import unittest
from unittest.mock import patch

import pytest

from depshieldx.ecosystems.composer.registry import check_provenance_batch, check_release


class CheckProvenanceBatchTests(unittest.TestCase):
    def test_empty_resolved_versions_returns_no_block(self):
        result = check_provenance_batch({})

        self.assertFalse(result["block"])
        self.assertEqual(result["details"], [])

    @patch("depshieldx.ecosystems.composer.registry.check_release")
    def test_aggregates_warnings_and_infos_per_package(self, mock_check_release):
        mock_check_release.return_value = {
            "package": "demo/package",
            "version": "1.0.0",
            "block": False,
            "reason": None,
            "warnings": ["package is abandoned -- suggested replacement: demo/package-plus"],
            "infos": ["no checksum published for the resolved artifact -- pinned by git reference only"],
            "signals": {},
        }

        result = check_provenance_batch({"demo/package": "1.0.0"})

        self.assertFalse(result["block"])
        self.assertEqual(len(result["details"]), 1)
        self.assertTrue(any("demo/package@1.0.0" in warning for warning in result["warnings"]))
        self.assertTrue(any("demo/package@1.0.0" in info for info in result["infos"]))

    @patch("depshieldx.ecosystems.composer.registry.check_release")
    def test_blocks_on_checksum_mismatch(self, mock_check_release):
        mock_check_release.return_value = {
            "package": "demo/package",
            "version": "1.0.0",
            "block": True,
            "reason": "downloaded artifact checksum does not match the registry-reported hash -- possible tampering",
            "warnings": [],
            "infos": [],
            "signals": {"checksum_verified": False},
        }

        result = check_provenance_batch({"demo/package": "1.0.0"})

        self.assertTrue(result["block"])
        self.assertIn("demo/package@1.0.0", result["reason"])


@patch("depshieldx.ecosystems.composer.registry._store_cached_result")
@patch("depshieldx.ecosystems.composer.registry._load_cached_result", return_value=None)
class CheckReleaseTests(unittest.TestCase):
    """Mirrors nuget/registry.py's, pub/registry.py's, and rubygems/
    registry.py's own equivalent test classes -- a checksum MISMATCH is
    already a hard block; this covers Composer's own real, weaker
    reality: no checksum published at all is the *common* case, not an
    anomaly, and is never refused on."""

    @patch("depshieldx.ecosystems.composer.registry.fetch_package_data")
    def test_missing_checksum_is_the_common_case_not_an_error(
        self, mock_fetch_data, _mock_load_cache, _mock_store_cache
    ):
        mock_fetch_data.return_value = {
            "package": {
                "name": "demo/package",
                "abandoned": False,
                "versions": {
                    "1.0.0": {
                        "version": "1.0.0",
                        "dist": {"url": "https://api.github.com/repos/demo/package/zipball/abc123", "reference": "abc123", "shasum": ""},
                        "source": {"reference": "abc123"},
                    }
                },
            }
        }

        result = check_release("demo/package", "1.0.0")

        self.assertFalse(result["block"])
        self.assertFalse(result["signals"]["checksum_verified"])
        self.assertIsNotNone(result["signals"]["verification_unavailable"])
        self.assertEqual(result["signals"]["reference"], "abc123")

    @patch("depshieldx.ecosystems.composer.registry.fetch_package_data")
    def test_version_not_found_surfaces_as_non_blocking_anomaly(
        self, mock_fetch_data, _mock_load_cache, _mock_store_cache
    ):
        mock_fetch_data.return_value = {"package": {"name": "demo/package", "abandoned": False, "versions": {}}}

        result = check_release("demo/package", "9.9.9")

        self.assertFalse(result["block"])
        self.assertIsNotNone(result["signals"]["verification_unavailable"])
        self.assertTrue(any("was not found" in warning for warning in result["warnings"]))

    @patch("depshieldx.ecosystems.composer.registry.fetch_package_data")
    def test_abandoned_boolean_produces_warning(self, mock_fetch_data, _mock_load_cache, _mock_store_cache):
        mock_fetch_data.return_value = {
            "package": {
                "name": "demo/package",
                "abandoned": True,
                "versions": {
                    "1.0.0": {
                        "version": "1.0.0",
                        "dist": {"url": "https://api.github.com/repos/demo/package/zipball/abc123", "reference": "abc123", "shasum": ""},
                    }
                },
            }
        }

        result = check_release("demo/package", "1.0.0")

        self.assertFalse(result["block"])
        self.assertTrue(any("abandoned" in warning for warning in result["warnings"]))
        self.assertTrue(result["signals"]["abandoned"])
        self.assertIsNone(result["signals"]["abandoned_replacement"])

    @patch("depshieldx.ecosystems.composer.registry.fetch_package_data")
    def test_abandoned_replacement_string_is_recorded(self, mock_fetch_data, _mock_load_cache, _mock_store_cache):
        # Confirmed directly against a real abandoned package
        # (swiftmailer/swiftmailer): "abandoned" can be a string naming
        # the recommended replacement, not just a boolean.
        mock_fetch_data.return_value = {
            "package": {
                "name": "swiftmailer/swiftmailer",
                "abandoned": "symfony/mailer",
                "versions": {
                    "6.2.3": {
                        "version": "6.2.3",
                        "dist": {"url": "https://api.github.com/repos/swiftmailer/swiftmailer/zipball/abc123", "reference": "abc123", "shasum": ""},
                    }
                },
            }
        }

        result = check_release("swiftmailer/swiftmailer", "6.2.3")

        self.assertTrue(any("symfony/mailer" in warning for warning in result["warnings"]))
        self.assertEqual(result["signals"]["abandoned_replacement"], "symfony/mailer")

    @patch("depshieldx.ecosystems.composer.registry.fetch_archive")
    @patch("depshieldx.ecosystems.composer.registry.fetch_package_data")
    def test_checksum_mismatch_blocks_when_a_real_shasum_is_published(
        self, mock_fetch_data, mock_fetch_archive, _mock_load_cache, _mock_store_cache
    ):
        # Confirmed directly this is real, if uncommon (see module
        # docstring) -- when it does happen, a mismatch is still a real,
        # hard block, the same as every other ecosystem's registry.py.
        mock_fetch_data.return_value = {
            "package": {
                "name": "demo/package",
                "abandoned": False,
                "versions": {
                    "1.0.0": {
                        "version": "1.0.0",
                        "dist": {
                            "url": "https://example.com/demo-package-1.0.0.zip",
                            "reference": "abc123",
                            "shasum": "not-the-real-hash",
                        },
                    }
                },
            }
        }
        mock_fetch_archive.return_value = b"fake-archive-bytes"

        result = check_release("demo/package", "1.0.0")

        self.assertTrue(result["block"])
        self.assertIn("possible tampering", result["reason"])

    @patch("depshieldx.ecosystems.composer.registry.fetch_archive")
    @patch("depshieldx.ecosystems.composer.registry.fetch_package_data")
    def test_successful_checksum_verification_when_published(
        self, mock_fetch_data, mock_fetch_archive, _mock_load_cache, _mock_store_cache
    ):
        import hashlib

        archive_bytes = b"fake-archive-bytes"
        digest = hashlib.sha1(archive_bytes).hexdigest()
        mock_fetch_data.return_value = {
            "package": {
                "name": "demo/package",
                "abandoned": False,
                "versions": {
                    "1.0.0": {
                        "version": "1.0.0",
                        "dist": {"url": "https://example.com/demo-package-1.0.0.zip", "reference": "abc123", "shasum": digest},
                    }
                },
            }
        }
        mock_fetch_archive.return_value = archive_bytes

        result = check_release("demo/package", "1.0.0")

        self.assertFalse(result["block"])
        self.assertTrue(result["signals"]["checksum_verified"])
        self.assertIsNone(result["signals"]["verification_unavailable"])


@pytest.mark.live
class ComposerRegistryLiveTests(unittest.TestCase):
    """Hits the real Packagist. Marked live -- excluded from the default
    CI run (`pytest -m "not live"`)."""

    def test_check_release_reports_no_checksum_for_a_real_package(self):
        result = check_release("monolog/monolog", "3.10.0")

        self.assertFalse(result["block"])
        self.assertFalse(result["signals"]["checksum_verified"])
        self.assertIsNotNone(result["signals"]["verification_unavailable"])
        self.assertIsNotNone(result["signals"]["reference"])

    def test_check_release_reports_a_real_abandoned_package(self):
        result = check_release("swiftmailer/swiftmailer", "6.2.3")

        self.assertTrue(result["signals"]["abandoned"])
        self.assertEqual(result["signals"]["abandoned_replacement"], "symfony/mailer")


if __name__ == "__main__":
    unittest.main()
