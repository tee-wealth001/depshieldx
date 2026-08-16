import unittest

from depshieldx.intelligence.models import (
    VersionVulnerability,
    _cargo_satisfies,
    _cargo_satisfies_clause,
    _npm_satisfies,
    _npm_satisfies_clause,
)
from depshieldx.intelligence.osv import OSV_ECOSYSTEM_NAMES


class OsvEcosystemNamesTests(unittest.TestCase):
    def test_pypi_maps_to_osv_pypi_identifier(self):
        # OSV's ecosystem enum is case-sensitive; confirmed against the real API.
        self.assertEqual(OSV_ECOSYSTEM_NAMES["pypi"], "PyPI")

    def test_npm_maps_to_osv_npm_identifier(self):
        self.assertEqual(OSV_ECOSYSTEM_NAMES["npm"], "npm")

    def test_cargo_maps_to_osv_crates_io_identifier(self):
        # Confirmed directly against the real OSV API (a real query for the
        # "time" crate's RUSTSEC-2026-0009 advisory only returns results
        # under ecosystem="crates.io", not "cargo" or "Cargo").
        self.assertEqual(OSV_ECOSYSTEM_NAMES["cargo"], "crates.io")


class NpmSatisfiesClauseTests(unittest.TestCase):
    """Unit coverage for the low-level semver comparator, independent of
    VersionVulnerability -- see findings.md #11 for the bug this replaces
    (PEP 440 mis-ordering/rejecting real npm prerelease versions)."""

    def test_gte_boundary(self):
        self.assertTrue(_npm_satisfies_clause("1.2.3", ">=1.2.3"))
        self.assertFalse(_npm_satisfies_clause("1.2.2", ">=1.2.3"))

    def test_lt_boundary(self):
        self.assertTrue(_npm_satisfies_clause("1.9.9", "<2.0.0"))
        self.assertFalse(_npm_satisfies_clause("2.0.0", "<2.0.0"))

    def test_lte_boundary(self):
        self.assertTrue(_npm_satisfies_clause("2.0.0", "<=2.0.0"))
        self.assertFalse(_npm_satisfies_clause("2.0.1", "<=2.0.0"))

    def test_bare_version_is_exact_match(self):
        self.assertTrue(_npm_satisfies_clause("1.2.3", "1.2.3"))
        self.assertFalse(_npm_satisfies_clause("1.2.4", "1.2.3"))

    def test_double_equals_is_exact_match(self):
        self.assertTrue(_npm_satisfies_clause("1.2.3", "==1.2.3"))
        self.assertFalse(_npm_satisfies_clause("1.2.4", "==1.2.3"))

    def test_invalid_boundary_returns_false_not_raise(self):
        self.assertFalse(_npm_satisfies_clause("1.2.3", ">=not-a-version"))

    def test_npm_satisfies_ands_comma_separated_clauses(self):
        self.assertTrue(_npm_satisfies("1.5.0", ">=1.2.3,<2.0.0"))
        self.assertFalse(_npm_satisfies("2.0.0", ">=1.2.3,<2.0.0"))
        self.assertFalse(_npm_satisfies("1.0.0", ">=1.2.3,<2.0.0"))


class CargoSatisfiesClauseTests(unittest.TestCase):
    """Unit coverage for the low-level SemVer 2.0.0 comparator, independent
    of VersionVulnerability. Rust/Cargo versions strictly follow real
    SemVer 2.0.0 (unlike npm's historically loose validation), so this uses
    the `semver` package's spec-compliant ordering directly rather than a
    hand-rolled comparator -- verified directly against real OSV crates.io
    advisory data (the `time` crate's RUSTSEC-2026-0009) during
    development."""

    def test_gte_boundary(self):
        self.assertTrue(_cargo_satisfies_clause("1.2.3", ">=1.2.3"))
        self.assertFalse(_cargo_satisfies_clause("1.2.2", ">=1.2.3"))

    def test_lt_boundary(self):
        self.assertTrue(_cargo_satisfies_clause("1.9.9", "<2.0.0"))
        self.assertFalse(_cargo_satisfies_clause("2.0.0", "<2.0.0"))

    def test_lte_boundary(self):
        self.assertTrue(_cargo_satisfies_clause("2.0.0", "<=2.0.0"))
        self.assertFalse(_cargo_satisfies_clause("2.0.1", "<=2.0.0"))

    def test_bare_version_is_exact_match(self):
        self.assertTrue(_cargo_satisfies_clause("1.2.3", "1.2.3"))
        self.assertFalse(_cargo_satisfies_clause("1.2.4", "1.2.3"))

    def test_double_equals_is_exact_match(self):
        self.assertTrue(_cargo_satisfies_clause("1.2.3", "==1.2.3"))
        self.assertFalse(_cargo_satisfies_clause("1.2.4", "==1.2.3"))

    def test_invalid_boundary_returns_false_not_raise(self):
        self.assertFalse(_cargo_satisfies_clause("1.2.3", ">=not-a-version"))

    def test_cargo_satisfies_ands_comma_separated_clauses(self):
        self.assertTrue(_cargo_satisfies("1.5.0", ">=1.2.3,<2.0.0"))
        self.assertFalse(_cargo_satisfies("2.0.0", ">=1.2.3,<2.0.0"))
        self.assertFalse(_cargo_satisfies("1.0.0", ">=1.2.3,<2.0.0"))

    def test_real_rustsec_2026_0009_range(self):
        # Real range from OSV for the "time" crate's RUSTSEC-2026-0009 --
        # confirmed directly against the live OSV API during development.
        self.assertTrue(_cargo_satisfies("0.3.6", ">=0.3.6,<0.3.47"))
        self.assertTrue(_cargo_satisfies("0.3.46", ">=0.3.6,<0.3.47"))
        self.assertFalse(_cargo_satisfies("0.3.47", ">=0.3.6,<0.3.47"))
        self.assertFalse(_cargo_satisfies("0.3.5", ">=0.3.6,<0.3.47"))


class VersionVulnerabilityNpmTests(unittest.TestCase):
    """Regression coverage for findings.md #11. Each case here is one that
    was empirically confirmed (via a real comparison against PEP 440's
    packaging.version.Version) to behave wrong under the old PyPI-only
    comparison path before this fix."""

    def test_prerelease_numeric_tag_is_not_inverted(self):
        # The core bug: PEP 440 normalizes "1.2.3-0" to "1.2.3.post0" (a
        # POST-release, sorting AFTER 1.2.3) where semver correctly treats
        # "-0" as a PRE-release tag (sorting BEFORE 1.2.3). A vulnerability
        # affecting versions up to (but not including) 1.2.3 must catch
        # "1.2.3-0" under real semver ordering.
        vuln = VersionVulnerability(cve_id="CVE-TEST-1", source="osv", affected_versions=[">=1.2.0,<1.2.3"])
        self.assertTrue(vuln.is_current_version_vulnerable("1.2.3-0", ecosystem="npm"))

    def test_complex_prerelease_identifier_does_not_raise(self):
        # Multi-segment prerelease identifiers like "x.7.z.92" are valid
        # semver but not valid PEP 440 -- packaging.version.Version() raises
        # InvalidVersion for this, which previously made the check fall back
        # to "assume vulnerable" for the *installed* version universally,
        # masking the real range-matching logic entirely.
        vuln = VersionVulnerability(cve_id="CVE-TEST-2", source="osv", affected_versions=["<2.0.0"])
        self.assertTrue(vuln.is_current_version_vulnerable("1.0.0-x.7.z.92", ecosystem="npm"))
        # A prerelease of 1.0.0 correctly sorts *before* 1.0.0 itself under semver,
        # so it's still "affected" by a "<1.0.0" range -- use a range it's genuinely
        # outside of to prove the complex identifier doesn't just always match.
        vuln_safe = VersionVulnerability(cve_id="CVE-TEST-3", source="osv", affected_versions=["<1.0.0-x.7.z.10"])
        self.assertFalse(vuln_safe.is_current_version_vulnerable("1.0.0-x.7.z.92", ecosystem="npm"))

    def test_version_in_range_is_flagged(self):
        vuln = VersionVulnerability(cve_id="CVE-TEST-4", source="osv", affected_versions=[">=1.2.3,<2.0.0"])
        self.assertTrue(vuln.is_current_version_vulnerable("1.5.0", ecosystem="npm"))

    def test_version_outside_range_is_not_flagged(self):
        vuln = VersionVulnerability(cve_id="CVE-TEST-5", source="osv", affected_versions=[">=1.2.3,<2.0.0"])
        self.assertFalse(vuln.is_current_version_vulnerable("2.5.0", ecosystem="npm"))

    def test_fixed_in_version_uses_semver_ordering(self):
        vuln = VersionVulnerability(cve_id="CVE-TEST-6", source="osv", fixed_in_version="1.2.3")
        self.assertTrue(vuln.is_current_version_vulnerable("1.2.3-0", ecosystem="npm"))
        self.assertFalse(vuln.is_current_version_vulnerable("1.2.3", ecosystem="npm"))
        self.assertFalse(vuln.is_current_version_vulnerable("1.5.0", ecosystem="npm"))

    def test_unparseable_installed_version_assumes_vulnerable(self):
        vuln = VersionVulnerability(cve_id="CVE-TEST-7", source="osv", affected_versions=["<2.0.0"])
        self.assertTrue(vuln.is_current_version_vulnerable("not-a-real-version", ecosystem="npm"))

    def test_pypi_default_behavior_is_unchanged(self):
        # Same scenario as test_version_in_range_is_flagged, but confirming
        # the default (pypi) path -- unmodified by this fix -- still works.
        vuln = VersionVulnerability(cve_id="CVE-TEST-8", source="osv", affected_versions=[">=1.2.3,<2.0.0"])
        self.assertTrue(vuln.is_current_version_vulnerable("1.5.0"))
        self.assertFalse(vuln.is_current_version_vulnerable("2.5.0"))


class VersionVulnerabilityCargoTests(unittest.TestCase):
    """ecosystem="cargo" routes through real SemVer 2.0.0 comparison (the
    `semver` package), not PEP 440 -- confirmed directly against real OSV
    crates.io advisory data (the "time" crate's RUSTSEC-2026-0009,
    introduced=0.3.6/fixed=0.3.47) during development."""

    def test_real_rustsec_2026_0009_range(self):
        vuln = VersionVulnerability(cve_id="RUSTSEC-2026-0009", source="osv", affected_versions=[">=0.3.6,<0.3.47"])
        self.assertTrue(vuln.is_current_version_vulnerable("0.3.6", ecosystem="cargo"))
        self.assertTrue(vuln.is_current_version_vulnerable("0.3.46", ecosystem="cargo"))
        self.assertFalse(vuln.is_current_version_vulnerable("0.3.47", ecosystem="cargo"))
        self.assertFalse(vuln.is_current_version_vulnerable("0.3.5", ecosystem="cargo"))

    def test_fixed_in_version_uses_semver_ordering(self):
        vuln = VersionVulnerability(cve_id="CVE-TEST-CARGO-1", source="osv", fixed_in_version="1.2.3")
        self.assertTrue(vuln.is_current_version_vulnerable("1.2.2", ecosystem="cargo"))
        self.assertFalse(vuln.is_current_version_vulnerable("1.2.3", ecosystem="cargo"))
        self.assertFalse(vuln.is_current_version_vulnerable("1.5.0", ecosystem="cargo"))

    def test_prerelease_ordering_matches_real_semver_2_0_0_spec(self):
        # Real SemVer 2.0.0 spec example (section 11): 1.0.0-alpha sorts
        # before 1.0.0-beta, which sorts before the final 1.0.0 release --
        # verified directly against the semver library before trusting it.
        vuln = VersionVulnerability(cve_id="CVE-TEST-CARGO-2", source="osv", affected_versions=["<1.0.0"])
        self.assertTrue(vuln.is_current_version_vulnerable("1.0.0-alpha", ecosystem="cargo"))
        self.assertTrue(vuln.is_current_version_vulnerable("1.0.0-beta", ecosystem="cargo"))
        self.assertFalse(vuln.is_current_version_vulnerable("1.0.0", ecosystem="cargo"))

    def test_unparseable_installed_version_assumes_vulnerable(self):
        vuln = VersionVulnerability(cve_id="CVE-TEST-CARGO-3", source="osv", affected_versions=["<2.0.0"])
        self.assertTrue(vuln.is_current_version_vulnerable("not-a-real-version", ecosystem="cargo"))

    def test_version_outside_range_is_not_flagged(self):
        vuln = VersionVulnerability(cve_id="CVE-TEST-CARGO-4", source="osv", affected_versions=[">=1.2.3,<2.0.0"])
        self.assertFalse(vuln.is_current_version_vulnerable("2.5.0", ecosystem="cargo"))


if __name__ == "__main__":
    unittest.main()
