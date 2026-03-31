import unittest
from unittest.mock import patch

from depshieldx.scanner import scan_vulnerabilities


class ScannerTests(unittest.TestCase):
    @patch(
        "depshieldx.scanner.fetch_all_sources_for_packages",
        return_value={
            "osv_results": {
                "Flask": {"current": [], "historical": []},
                "Werkzeug": {
                    "current": [
                        {
                            "cve_id": "CVE-2026-1234",
                            "source": "osv",
                            "severity": "HIGH",
                            "summary": "dependency vulnerability",
                            "aliases": ["CVE-2026-1234"],
                        }
                    ],
                    "historical": [],
                },
            },
            "cisa_kev_results": {},
            "github_advisories": {"hits": [], "warnings": []},
            "deps_dev": {"hits": [], "warnings": []},
        },
    )
    def test_scan_vulnerabilities_blocks_on_dependency_vulnerability(self, _mock_all_sources):
        result = scan_vulnerabilities(
            ["Flask", "Werkzeug"],
            resolved_versions={"Flask": "3.1.3", "Werkzeug": "3.1.7"},
        )

        self.assertTrue(result["block"])
        self.assertIn("Werkzeug==3.1.7", result["reason"])
        self.assertIn("CVE-2026-1234", result["reason"])
        self.assertEqual(result["blocked_package"], "Werkzeug")
        self.assertEqual(result["blocked_source"], "osv")

    @patch(
        "depshieldx.scanner.fetch_all_sources_for_packages",
        return_value={
            "osv_results": {},
            "cisa_kev_results": {},
            "github_advisories": {
                "hits": [
                    {
                        "package": "flask",
                        "package_version": "3.1.3",
                        "ghsa_id": "GHSA-abcd",
                        "cve_id": "CVE-2026-9999",
                        "severity": "MODERATE",
                        "source": "github_advisories",
                    }
                ],
                "warnings": [],
            },
            "deps_dev": {"hits": [], "warnings": []},
        },
    )
    def test_scan_vulnerabilities_blocks_on_github_advisory_hit(self, _mock_all_sources):
        result = scan_vulnerabilities(
            ["Flask"],
            resolved_versions={"Flask": "3.1.3"},
        )

        self.assertTrue(result["block"])
        self.assertEqual(result["reason"], "flask==3.1.3 has GitHub advisory GHSA-abcd")
        self.assertEqual(result["blocked_source"], "github-advisories")

    @patch(
        "depshieldx.scanner.fetch_all_sources_for_packages",
        return_value={
            "osv_results": {},
            "cisa_kev_results": {},
            "github_advisories": {"hits": [], "warnings": []},
            "deps_dev": {
                "hits": [
                    {
                        "package": "flask",
                        "package_version": "3.1.3",
                        "advisory_count": 2,
                        "advisories": [{"id": "GHSA-1"}, {"id": "GHSA-2"}],
                        "source": "deps_dev",
                    }
                ],
                "warnings": [],
            },
        },
    )
    def test_scan_vulnerabilities_blocks_on_deps_dev_advisories(self, _mock_all_sources):
        result = scan_vulnerabilities(
            ["Flask"],
            resolved_versions={"Flask": "3.1.3"},
        )

        self.assertTrue(result["block"])
        self.assertEqual(
            result["reason"],
            "flask==3.1.3 has deps.dev advisory reference(s): GHSA-1, GHSA-2",
        )
        self.assertEqual(result["blocked_source"], "deps-dev")

    @patch(
        "depshieldx.scanner.fetch_all_sources_for_packages",
        return_value={
            "osv_results": {"six": {"current": [], "historical": []}},
            "cisa_kev_results": {
                "six": {
                    "current": [],
                    "historical": [],
                    "unverified": [
                        {
                            "cve_id": "CVE-2022-24112",
                            "source": "cisa-kev",
                            "severity": "HIGH",
                            "summary": "Matched product text only",
                        }
                    ],
                }
            },
            "github_advisories": {"hits": [], "warnings": []},
            "deps_dev": {"hits": [], "warnings": []},
        },
    )
    def test_scan_vulnerabilities_does_not_block_on_unverified_cisa_kev_matches(self, _mock_all_sources):
        result = scan_vulnerabilities(
            ["six"],
            resolved_versions={"six": "1.17.0"},
        )

        self.assertFalse(result["block"])
        cisa_kev = result["threat_intelligence"]["cisa_kev"]
        self.assertEqual(len(cisa_kev["hits"]), 0)
        self.assertEqual(len(cisa_kev["unverified_hits"]), 1)
