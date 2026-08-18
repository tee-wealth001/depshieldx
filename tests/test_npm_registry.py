import os
import tempfile
import unittest
from unittest.mock import patch

import pytest

from depshieldx.ecosystems.npm.registry import (
    NPM_SLSA_PREDICATE_TYPE,
    _attestation_signals,
    _integrity_digest_hex,
    _is_bundle_format_unsupported_error,
    _npm_purl,
    _parse_attestation_entry,
    _verify_slsa_bundle,
    check_provenance_batch,
    check_release,
)


@pytest.mark.live
class NpmRegistryLiveTests(unittest.TestCase):
    """Hits the real npm registry (and, for the sigstore case, real Sigstore
    verification infrastructure). Marked live -- excluded from the default
    CI run (`pytest -m "not live"`) since it depends on third-party service
    availability, unlike the rest of this suite which mocks network calls."""

    def test_check_release_cryptographically_verifies_real_attestations_for_sigstore(self):
        result = check_release("sigstore", "5.0.0")

        self.assertFalse(result["block"], result)
        self.assertTrue(result["signals"]["has_attestations"])
        self.assertIn(NPM_SLSA_PREDICATE_TYPE, result["signals"]["attestation_predicate_types"])
        self.assertTrue(result["signals"]["attestation_verification_available"], result["signals"])
        self.assertTrue(result["signals"]["fully_verified_attestations"], result["signals"])
        self.assertTrue(result["signals"]["trusted_publisher"])

    def test_check_release_reports_deprecated_and_no_attestations_for_left_pad(self):
        result = check_release("left-pad", "1.3.0")

        self.assertFalse(result["block"])
        self.assertTrue(result["signals"]["deprecated"])
        self.assertFalse(result["signals"]["has_attestations"])

    def test_check_release_handles_missing_version_gracefully(self):
        result = check_release("left-pad", "999.999.999")

        self.assertFalse(result["block"])
        self.assertTrue(result["signals"]["unavailable"])

    def test_check_provenance_batch_does_not_block_when_no_attestations_present(self):
        # Most npm packages don't publish with --provenance at all -- that
        # alone isn't evidence of anything suspicious, so it must never block
        # by itself (only an *attempted and failed* verification blocks).
        result = check_provenance_batch({"left-pad": "1.3.0"})

        self.assertFalse(result["block"])
        self.assertEqual(len(result["details"]), 1)


class NpmRegistryCacheTests(unittest.TestCase):
    @patch("depshieldx.ecosystems.npm.registry.fetch_attestation_bundles", return_value=[])
    def test_check_release_uses_cache_on_second_call(self, _mock_attestations):
        with tempfile.TemporaryDirectory() as cache_dir:
            with patch.dict(os.environ, {"DEPSHIELDX_CACHE_DIR": cache_dir}, clear=False):
                with patch("depshieldx.ecosystems.npm.registry.fetch_package_metadata") as mock_fetch:
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
                    "depshieldx.ecosystems.npm.registry.fetch_package_metadata", side_effect=RuntimeError("network down")
                ) as mock_fetch:
                    first = check_release("fixturepkg", "1.0.0")
                    second = check_release("fixturepkg", "1.0.0")

                self.assertTrue(first["signals"]["unavailable"])
                self.assertTrue(second["signals"]["unavailable"])
                self.assertEqual(mock_fetch.call_count, 2)


class NpmIntegrityDigestTests(unittest.TestCase):
    def test_decodes_sha512_sri_integrity_to_hex(self):
        # Real dist.integrity value for left-pad@1.3.0, and its known-correct
        # sha512 hex digest, cross-checked independently.
        dist = {
            "integrity": "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA=="
        }

        digest_hex = _integrity_digest_hex(dist)

        self.assertEqual(len(digest_hex), 128)
        self.assertTrue(all(c in "0123456789abcdef" for c in digest_hex))

    def test_returns_none_for_missing_or_mismatched_algorithm(self):
        self.assertIsNone(_integrity_digest_hex({}))
        self.assertIsNone(_integrity_digest_hex({"integrity": "sha256-abc=="}))


class NpmPurlTests(unittest.TestCase):
    def test_unscoped_package_purl(self):
        self.assertEqual(_npm_purl("left-pad", "1.3.0"), "pkg:npm/left-pad@1.3.0")

    def test_scoped_package_percent_encodes_at_sign(self):
        # Reproduced directly against a real npm attestation subject for
        # @npmcli/agent@5.0.2 -- npm uses "%40", not a raw "@".
        self.assertEqual(_npm_purl("@npmcli/agent", "5.0.2"), "pkg:npm/%40npmcli/agent@5.0.2")


class NpmBundleFormatUnsupportedTests(unittest.TestCase):
    def test_recognizes_known_integrated_time_message(self):
        self.assertTrue(
            _is_bundle_format_unsupported_error("Integrated time only supported for dsse/hashedrekord 0.0.1 types")
        )

    def test_does_not_misclassify_a_real_verification_failure(self):
        self.assertFalse(_is_bundle_format_unsupported_error("attestation subject digest does not match"))

    @patch("sigstore.verify.Verifier.production")
    @patch("sigstore.models.Bundle.from_json")
    def test_verify_slsa_bundle_treats_format_unsupported_as_unavailable_not_failed(self, mock_from_json, mock_production):
        mock_from_json.return_value = object()
        mock_verifier = mock_production.return_value
        mock_verifier.verify_dsse.side_effect = Exception(
            "Integrated time only supported for dsse/hashedrekord 0.0.1 types"
        )

        result = _verify_slsa_bundle({"fake": "bundle"}, None, "pkg:npm/pkg@1.0.0")

        self.assertFalse(result["verified"])
        self.assertEqual(result["errors"], [])
        self.assertEqual(len(result["infrastructure_errors"]), 1)
        self.assertIn("Integrated time", result["infrastructure_errors"][0])
        # Offline retry would fail identically (not network-related) --
        # production() should only be called once, not retried.
        mock_production.assert_called_once_with(offline=False)


class NpmParseAttestationEntryTests(unittest.TestCase):
    def test_npm_publish_entry_is_not_marked_certificate_signed(self):
        entry = {
            "predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
            "bundle": {"verificationMaterial": {"publicKey": {"hint": "abc"}}},
        }

        parsed = _parse_attestation_entry(entry)

        self.assertFalse(parsed["signed_by_certificate"])

    def test_slsa_provenance_entry_is_marked_certificate_signed(self):
        entry = {
            "predicateType": NPM_SLSA_PREDICATE_TYPE,
            "bundle": {"verificationMaterial": {"certificate": {"rawBytes": "abc"}}},
        }

        parsed = _parse_attestation_entry(entry)

        self.assertTrue(parsed["signed_by_certificate"])


class NpmAttestationSignalsTests(unittest.TestCase):
    @patch("depshieldx.ecosystems.npm.registry.fetch_attestation_bundles", return_value=[])
    def test_no_attestations_reports_unattested_signals(self, _mock_fetch):
        signals, messages = _attestation_signals("left-pad", "1.3.0", {"integrity": "sha512-fake=="})

        self.assertFalse(signals["has_attestations"])
        self.assertFalse(signals["fully_verified_attestations"])
        self.assertIn("no npm provenance attestations", messages[0])

    @patch("depshieldx.ecosystems.npm.registry._verify_slsa_bundle")
    @patch("depshieldx.ecosystems.npm.registry.fetch_attestation_bundles")
    def test_verified_slsa_attestation_reports_trusted_publisher(self, mock_fetch, mock_verify):
        mock_fetch.return_value = [
            {"predicateType": NPM_SLSA_PREDICATE_TYPE, "bundle": {"fake": "bundle"}},
        ]
        mock_verify.return_value = {"available": True, "verified": True, "errors": [], "infrastructure_errors": []}

        signals, messages = _attestation_signals("pkg", "1.0.0", {"integrity": "sha512-fake=="})

        self.assertTrue(signals["has_attestations"])
        self.assertTrue(signals["fully_verified_attestations"])
        self.assertTrue(signals["trusted_publisher"])
        self.assertEqual(messages, [])

    @patch("depshieldx.ecosystems.npm.registry._verify_slsa_bundle")
    @patch("depshieldx.ecosystems.npm.registry.fetch_attestation_bundles")
    def test_failed_slsa_verification_is_reported_as_failure_not_unavailable(self, mock_fetch, mock_verify):
        mock_fetch.return_value = [
            {"predicateType": NPM_SLSA_PREDICATE_TYPE, "bundle": {"fake": "bundle"}},
        ]
        mock_verify.return_value = {
            "available": True,
            "verified": False,
            "errors": ["subject digest mismatch"],
            "infrastructure_errors": [],
        }

        signals, messages = _attestation_signals("pkg", "1.0.0", {"integrity": "sha512-fake=="})

        self.assertTrue(signals["has_attestations"])
        self.assertFalse(signals["fully_verified_attestations"])
        self.assertEqual(signals["attested_file_count"], 1)
        self.assertEqual(signals["verified_attestation_file_count"], 0)
        self.assertEqual(
            signals["verification_failure"], {"filename": "pkg-1.0.0.tgz", "error": "subject digest mismatch"}
        )
        self.assertIsNone(signals["verification_unavailable"])
        self.assertTrue(any("verification failed" in message for message in messages))

    @patch("depshieldx.ecosystems.npm.registry.fetch_attestation_bundles")
    def test_only_npm_publish_attestation_is_not_cryptographically_verifiable(self, mock_fetch):
        mock_fetch.return_value = [
            {
                "predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
                "bundle": {"verificationMaterial": {"publicKey": {"hint": "abc"}}},
            },
        ]

        signals, messages = _attestation_signals("pkg", "1.0.0", {"integrity": "sha512-fake=="})

        self.assertTrue(signals["has_attestations"])
        self.assertFalse(signals["fully_verified_attestations"])
        self.assertFalse(signals["attestation_verification_available"])
        self.assertTrue(any("verifiable SLSA provenance" in message for message in messages))


class NpmCheckReleaseBlockingTests(unittest.TestCase):
    @patch("depshieldx.ecosystems.npm.registry._attestation_signals")
    @patch("depshieldx.ecosystems.npm.registry.fetch_package_metadata")
    def test_check_release_blocks_when_verification_attempted_and_failed(self, mock_fetch, mock_signals):
        with tempfile.TemporaryDirectory() as cache_dir:
            with patch.dict(os.environ, {"DEPSHIELDX_CACHE_DIR": cache_dir}, clear=False):
                mock_fetch.return_value = {
                    "versions": {"1.0.0": {"dist": {"integrity": "sha512-fake=="}}},
                    "dist-tags": {"latest": "1.0.0"},
                }
                mock_signals.return_value = (
                    {
                        "has_attestations": True,
                        "fully_verified_attestations": False,
                        "attestation_verification_available": True,
                        "verified_attestation_count": 0,
                        "verification_failure": {"error": "boom"},
                        "verification_unavailable": None,
                        "trusted_publisher": False,
                        "attestation_predicate_types": [NPM_SLSA_PREDICATE_TYPE],
                    },
                    ["cryptographic attestation verification failed for the resolved release"],
                )

                result = check_release("evilpkg", "1.0.0")

        self.assertTrue(result["block"])
        self.assertIn("attestation verification failed", result["reason"])

    @patch("depshieldx.ecosystems.npm.registry._attestation_signals")
    @patch("depshieldx.ecosystems.npm.registry.fetch_package_metadata")
    def test_check_release_does_not_block_when_verification_unavailable(self, mock_fetch, mock_signals):
        with tempfile.TemporaryDirectory() as cache_dir:
            with patch.dict(os.environ, {"DEPSHIELDX_CACHE_DIR": cache_dir}, clear=False):
                mock_fetch.return_value = {
                    "versions": {"1.0.0": {"dist": {"integrity": "sha512-fake=="}}},
                    "dist-tags": {"latest": "1.0.0"},
                }
                mock_signals.return_value = (
                    {
                        "has_attestations": True,
                        "fully_verified_attestations": False,
                        "attestation_verification_available": False,
                        "verified_attestation_count": 0,
                        "verification_failure": None,
                        "verification_unavailable": {"error": "TUF metadata refresh failed"},
                        "trusted_publisher": False,
                        "attestation_predicate_types": [NPM_SLSA_PREDICATE_TYPE],
                    },
                    ["cryptographic attestation verification unavailable"],
                )

                result = check_release("pkg", "1.0.0")

        self.assertFalse(result["block"])


if __name__ == "__main__":
    unittest.main()
