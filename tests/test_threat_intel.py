import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from depshieldx.intelligence.cisa_kev import fetch_cisa_kev
from depshieldx.intelligence.common import _normalize_name
from depshieldx.intelligence.deps_dev import fetch_deps_dev_insights
from depshieldx.intelligence.github_advisories import fetch_github_advisories
from depshieldx.intelligence.local_feed import check_threat_intelligence


class ThreatIntelTests(unittest.TestCase):
    def test_package_feed_hit_blocks_install(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            feed_path = Path(temp_dir) / "feed.json"
            feed_path.write_text(
                """
                {
                  "packages": {
                    "evilpkg": {
                      "severity": "block",
                      "reason": "known malicious package"
                    }
                  }
                }
                """
            )

            result = check_threat_intelligence(["evilpkg"], [str(feed_path)])

        self.assertTrue(result["block"])
        self.assertEqual(result["hits"][0]["package"], "evilpkg")
        self.assertIn("known malicious package", result["reason"])

    def test_pattern_feed_hit_warns_without_blocking(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            feed_path = Path(temp_dir) / "feed.json"
            feed_path.write_text(
                """
                {
                  "patterns": [
                    {
                      "pattern": "^temp_.*$",
                      "severity": "warn",
                      "reason": "matches suspicious temporary-package naming pattern"
                    }
                  ]
                }
                """
            )

            result = check_threat_intelligence(["temp_loader"], [str(feed_path)])

        self.assertFalse(result["block"])
        self.assertEqual(result["hits"][0]["matched_on"], "pattern")
        self.assertEqual(
            result["warnings"],
            ["temp_loader threat-intelligence warning: matches suspicious temporary-package naming pattern"],
        )

    @patch("depshieldx.intelligence.local_feed.requests.get", side_effect=RuntimeError("network down"))
    def test_unavailable_feed_warns_without_blocking(self, _mock_get):
        result = check_threat_intelligence(["flask"], ["https://feeds.example.test/malware.json"])

        self.assertFalse(result["block"])
        self.assertEqual(result["hits"], [])
        self.assertEqual(len(result["warnings"]), 1)
        self.assertIn("threat intelligence feed unavailable", result["warnings"][0])

    @patch("depshieldx.intelligence.github_advisories.requests.get")
    def test_fetch_github_advisories_returns_hits_for_affected_version(self, mock_get):
        mock_response = SimpleNamespace(
            json=lambda: [
                {
                    "ghsa_id": "GHSA-1234",
                    "cve_id": "CVE-2024-1234",
                    "severity": "high",
                    "summary": "serious issue",
                    "epss": [],
                    "vulnerabilities": [
                        {
                            "package": {"name": "Flask"},
                            "vulnerable_version_range": "< 3.1.3",
                            "first_patched_version": {"identifier": "3.1.3"},
                        }
                    ],
                }
            ],
            raise_for_status=lambda: None,
        )
        mock_get.return_value = mock_response

        result = fetch_github_advisories(["flask"], resolved_versions={"Flask": "3.1.2"})

        self.assertEqual(result["hits"][0]["package"], "flask")
        self.assertEqual(result["hits"][0]["severity"], "HIGH")
        self.assertEqual(result["hits"][0]["ghsa_id"], "GHSA-1234")

    @patch("depshieldx.intelligence.github_advisories.requests.get")
    def test_fetch_github_advisories_skips_unaffected_version(self, mock_get):
        mock_response = SimpleNamespace(
            json=lambda: [
                {
                    "ghsa_id": "GHSA-1234",
                    "cve_id": "CVE-2024-1234",
                    "severity": "high",
                    "summary": "serious issue",
                    "epss": [],
                    "vulnerabilities": [
                        {
                            "package": {"name": "Werkzeug"},
                            "vulnerable_version_range": "< 3.1.0",
                            "first_patched_version": {"identifier": "3.1.0"},
                        }
                    ],
                }
            ],
            raise_for_status=lambda: None,
        )
        mock_get.return_value = mock_response

        result = fetch_github_advisories(["werkzeug"], resolved_versions={"Werkzeug": "3.1.7"})

        self.assertEqual(result["hits"], [])

    @patch("depshieldx.intelligence.cisa_kev.requests.get")
    def test_fetch_cisa_kev_filters_requested_cves(self, mock_get):
        mock_response = SimpleNamespace(
            json=lambda: {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2024-1234",
                        "vendorProject": "Pallets",
                        "product": "Flask",
                        "vulnerabilityName": "Flask issue",
                        "dateAdded": "2026-01-01",
                        "knownRansomwareCampaignUse": "Unknown",
                    }
                ]
            },
            raise_for_status=lambda: None,
        )
        mock_get.return_value = mock_response

        result = fetch_cisa_kev(["CVE-2024-1234", "CVE-2024-9999"])

        self.assertEqual(len(result["hits"]), 1)
        self.assertEqual(result["hits"][0]["cve_id"], "CVE-2024-1234")

    @patch("depshieldx.intelligence.deps_dev.requests.get")
    def test_fetch_deps_dev_insights_returns_version_metadata(self, mock_get):
        mock_response = SimpleNamespace(
            json=lambda: {
                "dependencies": [{"package": "click"}, {"package": "werkzeug"}],
                "advisories": [
                    {
                        "sourceID": "GHSA-1234",
                        "title": "demo advisory",
                    }
                ],
            },
            raise_for_status=lambda: None,
        )
        mock_get.return_value = mock_response

        result = fetch_deps_dev_insights(["flask"], resolved_versions={"Flask": "3.1.3"})

        self.assertEqual(result["source"], "deps_dev")
        self.assertEqual(result["hits"][0]["package"], "flask")
        self.assertEqual(result["hits"][0]["package_version"], "3.1.3")
        self.assertEqual(result["hits"][0]["dependency_count"], 2)
        self.assertEqual(result["hits"][0]["advisory_count"], 1)
        self.assertEqual(result["hits"][0]["advisories"][0]["id"], "GHSA-1234")

    @patch("depshieldx.intelligence.deps_dev.requests.get", side_effect=RuntimeError("network down"))
    def test_fetch_deps_dev_insights_warns_when_lookup_unavailable(self, _mock_get):
        result = fetch_deps_dev_insights(["flask"], resolved_versions={"Flask": "3.1.3"})

        self.assertEqual(result["hits"], [])
        self.assertEqual(len(result["warnings"]), 1)
        self.assertIn("deps.dev lookup unavailable", result["warnings"][0])

    def test_normalize_name_folds_hyphens_for_pypi(self):
        # PyPI/PEP 503 treats "-" and "_" as equivalent.
        self.assertEqual(_normalize_name("Left-Pad", ecosystem="pypi"), "left_pad")

    def test_normalize_name_preserves_hyphens_for_npm(self):
        # npm package names are hyphen-significant -- "left-pad" is not "left_pad".
        # Folding these together (the PyPI default) would silently break every npm lookup.
        self.assertEqual(_normalize_name("left-pad", ecosystem="npm"), "left-pad")

    @patch("depshieldx.intelligence.github_advisories.requests.get")
    def test_fetch_github_advisories_uses_npm_ecosystem_and_preserves_hyphens(self, mock_get):
        mock_response = SimpleNamespace(
            json=lambda: [
                {
                    "ghsa_id": "GHSA-npm-demo",
                    "cve_id": "CVE-2024-9999",
                    "severity": "high",
                    "summary": "demo npm advisory",
                    "epss": [],
                    "vulnerabilities": [
                        {
                            "package": {"name": "left-pad"},
                            "vulnerable_version_range": "< 2.0.0",
                            "first_patched_version": {"identifier": "2.0.0"},
                        }
                    ],
                }
            ],
            raise_for_status=lambda: None,
        )
        mock_get.return_value = mock_response

        result = fetch_github_advisories(["left-pad"], resolved_versions={"left-pad": "1.3.0"}, ecosystem="npm")

        self.assertEqual(mock_get.call_args.kwargs["params"]["ecosystem"], "npm")
        self.assertEqual(result["hits"][0]["package"], "left-pad")
        self.assertEqual(result["hits"][0]["ghsa_id"], "GHSA-npm-demo")

    @patch("depshieldx.intelligence.deps_dev.requests.get")
    def test_fetch_deps_dev_insights_uses_npm_system_in_url(self, mock_get):
        mock_response = SimpleNamespace(
            json=lambda: {"dependencies": [], "advisories": []},
            raise_for_status=lambda: None,
        )
        mock_get.return_value = mock_response

        fetch_deps_dev_insights(["left-pad"], resolved_versions={"left-pad": "1.3.0"}, ecosystem="npm")

        requested_url = mock_get.call_args.args[0]
        self.assertIn("/systems/npm/", requested_url)
        self.assertNotIn("/systems/pypi/", requested_url)

    @patch("depshieldx.intelligence.github_advisories.requests.get")
    def test_fetch_github_advisories_uses_rust_ecosystem_for_cargo(self, mock_get):
        mock_response = SimpleNamespace(
            json=lambda: [
                {
                    "ghsa_id": "GHSA-cargo-demo",
                    "cve_id": "CVE-2024-8888",
                    "severity": "moderate",
                    "summary": "demo cargo advisory",
                    "epss": [],
                    "vulnerabilities": [
                        {
                            "package": {"name": "serde"},
                            "vulnerable_version_range": "< 1.0.219",
                            "first_patched_version": {"identifier": "1.0.219"},
                        }
                    ],
                }
            ],
            raise_for_status=lambda: None,
        )
        mock_get.return_value = mock_response

        result = fetch_github_advisories(["serde"], resolved_versions={"serde": "1.0.100"}, ecosystem="cargo")

        # GitHub's advisory ecosystem enum for Rust is "rust", not "cargo" --
        # confirmed directly against the live API during development.
        self.assertEqual(mock_get.call_args.kwargs["params"]["ecosystem"], "rust")
        self.assertEqual(result["hits"][0]["ghsa_id"], "GHSA-cargo-demo")

    @patch("depshieldx.intelligence.deps_dev.requests.get")
    def test_fetch_deps_dev_insights_uses_cargo_system_in_url(self, mock_get):
        mock_response = SimpleNamespace(
            json=lambda: {"dependencies": [], "advisories": []},
            raise_for_status=lambda: None,
        )
        mock_get.return_value = mock_response

        fetch_deps_dev_insights(["serde"], resolved_versions={"serde": "1.0.219"}, ecosystem="cargo")

        requested_url = mock_get.call_args.args[0]
        self.assertIn("/systems/cargo/", requested_url)
        self.assertNotIn("/systems/pypi/", requested_url)
