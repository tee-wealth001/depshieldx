import asyncio
import unittest
from unittest.mock import patch

from depshieldx.intelligence.cisa_kev import _async_fetch_cisa_kev_cves
from depshieldx.intelligence.orchestrator import (
    _fetch_all_sources_for_packages_concurrent,
    fetch_all_sources_for_packages,
)
from depshieldx.intelligence.osv import _async_fetch_osv_cves
from depshieldx.scanner import scan_vulnerabilities


class OsvFailOpenTests(unittest.TestCase):
    """A lookup failure must surface as a warning, not silently become
    "checked OSV, found nothing" -- OSV is a blocking source."""

    def test_exception_from_inner_fetch_becomes_a_warning_not_a_silent_empty_result(self):
        with patch(
            "depshieldx.intelligence.osv._async_fetch_osv_cves_inner",
            side_effect=RuntimeError("simulated network failure"),
        ):
            source, vulns, warnings = asyncio.run(_async_fetch_osv_cves("some-package"))
        self.assertEqual(source, "osv")
        self.assertEqual(vulns, [])
        self.assertEqual(len(warnings), 1)
        self.assertIn("OSV lookup unavailable for some-package", warnings[0])
        self.assertIn("simulated network failure", warnings[0])

    def test_success_produces_no_warnings(self):
        with patch(
            "depshieldx.intelligence.osv._async_fetch_osv_cves_inner",
            return_value=[],
        ):
            source, vulns, warnings = asyncio.run(_async_fetch_osv_cves("some-package"))
        self.assertEqual(source, "osv")
        self.assertEqual(vulns, [])
        self.assertEqual(warnings, [])


class CisaKevFailOpenTests(unittest.TestCase):
    def test_exception_from_inner_fetch_becomes_a_warning_not_a_silent_empty_result(self):
        with patch(
            "depshieldx.intelligence.cisa_kev._async_fetch_cisa_kev_cves_inner",
            side_effect=RuntimeError("simulated network failure"),
        ):
            source, vulns, warnings = asyncio.run(_async_fetch_cisa_kev_cves("some-package"))
        self.assertEqual(source, "cisa-kev")
        self.assertEqual(vulns, [])
        self.assertEqual(len(warnings), 1)
        self.assertIn("CISA KEV lookup unavailable for some-package", warnings[0])
        self.assertIn("simulated network failure", warnings[0])


class OrchestratorFailOpenTests(unittest.TestCase):
    def test_one_package_osv_failure_is_aggregated_without_dropping_other_packages(self):
        async def fake_osv(pkg, ecosystem="pypi"):
            if pkg == "broken-package":
                return "osv", [], [f"OSV lookup unavailable for {pkg}: boom"]
            return "osv", [], []

        async def fake_cisa(pkg):
            return "cisa-kev", [], []

        async def fake_github(packages, resolved_versions, ecosystem="pypi"):
            return "github-advisories", {"hits": [], "warnings": []}

        async def fake_deps_dev(packages, resolved_versions, ecosystem="pypi"):
            return "deps-dev", {"hits": [], "warnings": []}

        with patch("depshieldx.intelligence.orchestrator._async_fetch_osv_cves", side_effect=fake_osv), patch(
            "depshieldx.intelligence.orchestrator._async_fetch_cisa_kev_cves", side_effect=fake_cisa
        ), patch(
            "depshieldx.intelligence.orchestrator._async_fetch_github_advisories", side_effect=fake_github
        ), patch(
            "depshieldx.intelligence.orchestrator._async_fetch_deps_dev_cves", side_effect=fake_deps_dev
        ):
            result = asyncio.run(
                _fetch_all_sources_for_packages_concurrent(["broken-package", "fine-package"])
            )

        self.assertEqual(len(result["osv_warnings"]), 1)
        self.assertIn("broken-package", result["osv_warnings"][0])
        self.assertEqual(result["cisa_kev_warnings"], [])
        # The failing package's own per-package entry should still exist (empty), not
        # vanish from the results entirely.
        self.assertIn("broken-package", result["per_package"])
        self.assertIn("fine-package", result["per_package"])


class ScanVulnerabilitiesFailOpenTests(unittest.TestCase):
    """The end-to-end path scanner.py exposes to the CLI: a failed OSV lookup
    must be visible in the returned info/warning text, not just disappear."""

    @patch(
        "depshieldx.scanner.fetch_all_sources_for_packages",
        return_value={
            "osv_results": {"requests": {"current": [], "historical": []}},
            "cisa_kev_results": {"requests": {"current": [], "historical": [], "unverified": []}},
            "github_advisories": {"hits": [], "warnings": []},
            "deps_dev": {"hits": [], "warnings": []},
            "osv_warnings": ["OSV lookup unavailable for requests: simulated outage"],
            "cisa_kev_warnings": [],
        },
    )
    def test_osv_lookup_failure_surfaces_as_info_not_silently_dropped(self, mock_fetch):
        result = scan_vulnerabilities(["requests"], resolved_versions={"requests": "2.31.0"}, ecosystem="pypi")
        self.assertFalse(result["block"])
        self.assertTrue(
            any("OSV lookup unavailable for requests" in msg for msg in result["infos"]),
            f"expected OSV failure message in infos, got: {result['infos']!r} / warnings: {result['warnings']!r}",
        )


if __name__ == "__main__":
    unittest.main()
