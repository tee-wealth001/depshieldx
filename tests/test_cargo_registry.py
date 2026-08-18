import os
import tempfile
import unittest
from unittest.mock import patch

import pytest

from depshieldx.ecosystems.cargo.registry import check_provenance_batch, check_release


@pytest.mark.live
class CargoRegistryLiveTests(unittest.TestCase):
    """Hits the real crates.io registry. Marked live -- excluded from the
    default CI run (`pytest -m "not live"`) since it depends on a
    third-party service's availability and data, unlike the rest of this
    suite which mocks network calls."""

    def test_check_release_reports_no_trustpub_data_for_serde(self):
        result = check_release("serde", "1.0.219")

        self.assertFalse(result["block"], result)
        self.assertFalse(result["signals"]["has_trustpub_data"])
        self.assertFalse(result["signals"]["yanked"])
        self.assertTrue(result["signals"]["has_checksum"])
        # Never implies cryptographic verification -- crates.io has no
        # attestation infrastructure at all (see module docstring).
        self.assertFalse(result["signals"]["verification_available"])
        self.assertFalse(result["signals"]["trusted_publisher"])

    def test_check_release_reports_real_trustpub_data_for_release_plz(self):
        # release-plz/release-plz publishes via GitHub Actions Trusted
        # Publishing -- confirmed directly against the live API during
        # development.
        result = check_release("release-plz", "0.3.160")

        self.assertFalse(result["block"], result)
        self.assertTrue(result["signals"]["has_trustpub_data"])
        self.assertEqual(result["signals"]["trustpub_provider"], "github")
        self.assertEqual(result["signals"]["trustpub_repository"], "release-plz/release-plz")
        self.assertIsNotNone(result["signals"]["trustpub_run_id"])
        # Structural only -- never cryptographically verified.
        self.assertFalse(result["signals"]["verification_available"])

    def test_check_release_blocks_on_a_real_yanked_version(self):
        # serde 1.0.95 is really yanked on crates.io -- confirmed directly
        # against the live API during development.
        result = check_release("serde", "1.0.95")

        self.assertTrue(result["block"])
        self.assertEqual(result["reason"], "resolved release is yanked on crates.io")
        self.assertTrue(result["signals"]["yanked"])

    def test_check_release_handles_missing_version_gracefully(self):
        result = check_release("serde", "999.999.999")

        self.assertFalse(result["block"])
        self.assertTrue(result["signals"]["unavailable"])


class CargoRegistryCacheTests(unittest.TestCase):
    @patch("depshieldx.ecosystems.cargo.registry._throttle")
    def test_check_release_uses_cache_on_second_call(self, _mock_throttle):
        with tempfile.TemporaryDirectory() as cache_dir:
            with patch.dict(os.environ, {"DEPSHIELDX_CACHE_DIR": cache_dir}, clear=False):
                with patch("depshieldx.ecosystems.cargo.registry.fetch_version_metadata") as mock_fetch:
                    mock_fetch.return_value = {
                        "version": {"num": "1.0.0", "checksum": "abc123", "yanked": False, "trustpub_data": None}
                    }
                    first = check_release("fixturecrate", "1.0.0")
                    second = check_release("fixturecrate", "1.0.0")

                self.assertEqual(mock_fetch.call_count, 1)
                self.assertEqual(first, second)

    @patch("depshieldx.ecosystems.cargo.registry._throttle")
    def test_network_failure_is_not_cached(self, _mock_throttle):
        with tempfile.TemporaryDirectory() as cache_dir:
            with patch.dict(os.environ, {"DEPSHIELDX_CACHE_DIR": cache_dir}, clear=False):
                with patch(
                    "depshieldx.ecosystems.cargo.registry.fetch_version_metadata", side_effect=RuntimeError("network down")
                ) as mock_fetch:
                    first = check_release("fixturecrate", "1.0.0")
                    second = check_release("fixturecrate", "1.0.0")

                self.assertTrue(first["signals"]["unavailable"])
                self.assertTrue(second["signals"]["unavailable"])
                self.assertEqual(mock_fetch.call_count, 2)


class CargoRegistryBlockingTests(unittest.TestCase):
    @patch("depshieldx.ecosystems.cargo.registry._throttle")
    def test_yanked_release_blocks(self, _mock_throttle):
        with tempfile.TemporaryDirectory() as cache_dir:
            with patch.dict(os.environ, {"DEPSHIELDX_CACHE_DIR": cache_dir}, clear=False):
                with patch("depshieldx.ecosystems.cargo.registry.fetch_version_metadata") as mock_fetch:
                    mock_fetch.return_value = {
                        "version": {"num": "1.0.0", "checksum": "abc123", "yanked": True, "trustpub_data": None}
                    }
                    result = check_release("evilcrate", "1.0.0")

        self.assertTrue(result["block"])
        self.assertEqual(result["reason"], "resolved release is yanked on crates.io")

    @patch("depshieldx.ecosystems.cargo.registry._throttle")
    def test_trustpub_data_never_blocks_and_never_claims_verification(self, _mock_throttle):
        with tempfile.TemporaryDirectory() as cache_dir:
            with patch.dict(os.environ, {"DEPSHIELDX_CACHE_DIR": cache_dir}, clear=False):
                with patch("depshieldx.ecosystems.cargo.registry.fetch_version_metadata") as mock_fetch:
                    mock_fetch.return_value = {
                        "version": {
                            "num": "1.0.0",
                            "checksum": "abc123",
                            "yanked": False,
                            "trustpub_data": {
                                "provider": "github",
                                "repository": "owner/repo",
                                "run_id": "123",
                                "sha": "deadbeef",
                            },
                        }
                    }
                    result = check_release("pkg", "1.0.0")

        self.assertFalse(result["block"])
        self.assertTrue(result["signals"]["has_trustpub_data"])
        self.assertFalse(result["signals"]["verification_available"])
        self.assertFalse(result["signals"]["trusted_publisher"])

    @patch("depshieldx.ecosystems.cargo.registry.check_release")
    def test_check_provenance_batch_blocks_on_first_failure(self, mock_check_release):
        mock_check_release.side_effect = [
            {
                "package": "evilcrate",
                "version": "1.0.0",
                "block": True,
                "reason": "resolved release is yanked on crates.io",
                "warnings": [],
                "infos": [],
                "signals": {},
            }
        ]

        result = check_provenance_batch({"evilcrate": "1.0.0"})

        self.assertTrue(result["block"])
        self.assertIn("evilcrate@1.0.0", result["reason"])

    def test_check_provenance_batch_empty_input(self):
        result = check_provenance_batch({})

        self.assertFalse(result["block"])
        self.assertEqual(result["details"], [])


if __name__ == "__main__":
    unittest.main()
