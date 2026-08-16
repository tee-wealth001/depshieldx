import os
import tempfile
import unittest
from unittest.mock import patch

from depshieldx.npm_registry import check_provenance_batch, check_release


class NpmRegistryLiveTests(unittest.TestCase):
    """Hits the real npm registry -- matches this suite's existing pattern for
    provenance/CVE-source tests (test_provenance.py, test_threat_intel.py)."""

    def test_check_release_reports_real_attestations_for_sigstore(self):
        result = check_release("sigstore", "5.0.0")

        self.assertFalse(result["block"])
        self.assertTrue(result["signals"]["has_attestations"])
        self.assertEqual(result["signals"]["attestation_predicate_type"], "https://slsa.dev/provenance/v1")

    def test_check_release_reports_deprecated_and_no_attestations_for_left_pad(self):
        result = check_release("left-pad", "1.3.0")

        self.assertFalse(result["block"])
        self.assertTrue(result["signals"]["deprecated"])
        self.assertFalse(result["signals"]["has_attestations"])

    def test_check_release_handles_missing_version_gracefully(self):
        result = check_release("left-pad", "999.999.999")

        self.assertFalse(result["block"])
        self.assertTrue(result["signals"]["unavailable"])

    def test_check_provenance_batch_never_blocks_on_structural_signals_alone(self):
        # Structural-only provenance (final-plan.md Phase 1 scoping) never blocks by
        # itself -- there's no cryptographic verification backing a block decision yet.
        result = check_provenance_batch({"left-pad": "1.3.0"})

        self.assertFalse(result["block"])
        self.assertEqual(len(result["details"]), 1)


class NpmRegistryCacheTests(unittest.TestCase):
    def test_check_release_uses_cache_on_second_call(self):
        with tempfile.TemporaryDirectory() as cache_dir:
            with patch.dict(os.environ, {"DEPSHIELDX_CACHE_DIR": cache_dir}, clear=False):
                with patch("depshieldx.npm_registry.fetch_package_metadata") as mock_fetch:
                    mock_fetch.return_value = {
                        "versions": {"1.0.0": {"dist": {"integrity": "sha512-fake=="}}},
                        "dist-tags": {"latest": "1.0.0"},
                    }
                    first = check_release("fixturepkg", "1.0.0")
                    second = check_release("fixturepkg", "1.0.0")

                self.assertEqual(mock_fetch.call_count, 1)
                self.assertEqual(first, second)

    def test_network_failure_is_not_cached(self):
        with tempfile.TemporaryDirectory() as cache_dir:
            with patch.dict(os.environ, {"DEPSHIELDX_CACHE_DIR": cache_dir}, clear=False):
                with patch(
                    "depshieldx.npm_registry.fetch_package_metadata", side_effect=RuntimeError("network down")
                ) as mock_fetch:
                    first = check_release("fixturepkg", "1.0.0")
                    second = check_release("fixturepkg", "1.0.0")

                self.assertTrue(first["signals"]["unavailable"])
                self.assertTrue(second["signals"]["unavailable"])
                self.assertEqual(mock_fetch.call_count, 2)


if __name__ == "__main__":
    unittest.main()
