import unittest

from depshieldx.intelligence.models import (
    VersionVulnerability,
    _cargo_satisfies,
    _cargo_satisfies_clause,
    _maven_compare,
    _maven_satisfies,
    _maven_satisfies_clause,
    _normalize_nuget_version,
    _npm_satisfies,
    _npm_satisfies_clause,
    _nuget_compare,
    _nuget_satisfies,
    _nuget_satisfies_clause,
    _pub_compare,
    _pub_satisfies,
    _pub_satisfies_clause,
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

    def test_maven_maps_to_osv_maven_identifier(self):
        # Confirmed directly against the real OSV API (a real query for
        # org.apache.logging.log4j:log4j-core only returns results under
        # ecosystem="Maven").
        self.assertEqual(OSV_ECOSYSTEM_NAMES["maven"], "Maven")

    def test_nuget_maps_to_osv_nuget_identifier(self):
        # Confirmed directly against the real OSV API (a real query for
        # Microsoft.IdentityModel.JsonWebTokens only returns results under
        # ecosystem="NuGet", exact casing).
        self.assertEqual(OSV_ECOSYSTEM_NAMES["nuget"], "NuGet")


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


class MavenCompareTests(unittest.TestCase):
    """Unit coverage for the low-level Maven ComparableVersion-derived
    comparator, independent of VersionVulnerability. Every case here was
    verified directly against real Maven's own comparison tool
    (`java -cp maven-artifact-*.jar
    org.apache.maven.artifact.versioning.ComparableVersion <versions...>`),
    not derived from the algorithm description alone -- see
    models.py's _maven_tokenize docstring."""

    def test_release_sorts_after_prerelease_qualifier(self):
        self.assertEqual(_maven_compare("1.0", "1.0-alpha"), 1)

    def test_numeric_extension_sorts_after_qualifier(self):
        self.assertEqual(_maven_compare("1.0-alpha", "1.0.0"), -1)

    def test_release_sorts_after_snapshot(self):
        self.assertEqual(_maven_compare("1.0.0", "1.0-SNAPSHOT"), 1)

    def test_snapshot_sorts_after_release_candidate(self):
        self.assertEqual(_maven_compare("1.0-SNAPSHOT", "1.0-rc1"), 1)

    def test_release_candidate_sorts_after_beta(self):
        self.assertEqual(_maven_compare("1.0-rc1", "1.0-beta"), 1)

    def test_major_version_number_wins_regardless_of_qualifier(self):
        self.assertEqual(_maven_compare("1.0-beta", "2.0-alpha1"), -1)

    def test_unrecognized_qualifier_sorts_after_release(self):
        # Real Guava-style build-flavor suffix, not a Maven release qualifier.
        self.assertEqual(_maven_compare("33.4.0-jre", "33.4.0"), 1)

    def test_release_qualifier_aliases_are_equivalent_to_no_qualifier(self):
        self.assertEqual(_maven_compare("5.3.4.RELEASE", "5.3.4"), 0)


class MavenSatisfiesClauseTests(unittest.TestCase):
    def test_gte_boundary(self):
        self.assertTrue(_maven_satisfies_clause("1.2.3", ">=1.2.3"))
        self.assertFalse(_maven_satisfies_clause("1.2.2", ">=1.2.3"))

    def test_lt_boundary(self):
        self.assertTrue(_maven_satisfies_clause("1.9.9", "<2.0.0"))
        self.assertFalse(_maven_satisfies_clause("2.0.0", "<2.0.0"))

    def test_bare_version_is_exact_match(self):
        self.assertTrue(_maven_satisfies_clause("1.2.3", "1.2.3"))
        self.assertFalse(_maven_satisfies_clause("1.2.4", "1.2.3"))

    def test_maven_satisfies_ands_comma_separated_clauses(self):
        self.assertTrue(_maven_satisfies("1.5.0", ">=1.2.3,<2.0.0"))
        self.assertFalse(_maven_satisfies("2.0.0", ">=1.2.3,<2.0.0"))
        self.assertFalse(_maven_satisfies("1.0.0", ">=1.2.3,<2.0.0"))

    def test_real_log4j_core_range(self):
        # Real range from OSV for org.apache.logging.log4j:log4j-core --
        # confirmed directly against the live OSV API during development.
        self.assertTrue(_maven_satisfies("2.0-alpha1", ">=2.0-alpha1,<2.25.4"))
        self.assertTrue(_maven_satisfies("2.14.1", ">=2.0-alpha1,<2.25.4"))
        self.assertFalse(_maven_satisfies("2.25.4", ">=2.0-alpha1,<2.25.4"))


class VersionVulnerabilityMavenTests(unittest.TestCase):
    def test_real_log4j_core_range(self):
        vuln = VersionVulnerability(cve_id="GHSA-TEST-MAVEN-1", source="osv", affected_versions=[">=2.0-alpha1,<2.25.4"])
        self.assertTrue(vuln.is_current_version_vulnerable("2.14.1", ecosystem="maven"))
        self.assertFalse(vuln.is_current_version_vulnerable("2.25.4", ecosystem="maven"))

    def test_fixed_in_version_uses_maven_ordering(self):
        vuln = VersionVulnerability(cve_id="CVE-TEST-MAVEN-2", source="osv", fixed_in_version="1.2.3")
        self.assertTrue(vuln.is_current_version_vulnerable("1.2.2", ecosystem="maven"))
        self.assertFalse(vuln.is_current_version_vulnerable("1.2.3", ecosystem="maven"))
        self.assertFalse(vuln.is_current_version_vulnerable("1.5.0", ecosystem="maven"))

    def test_release_qualifier_alias_treated_as_no_qualifier(self):
        vuln = VersionVulnerability(cve_id="CVE-TEST-MAVEN-3", source="osv", fixed_in_version="5.3.4")
        self.assertFalse(vuln.is_current_version_vulnerable("5.3.4.RELEASE", ecosystem="maven"))

    def test_version_outside_range_is_not_flagged(self):
        vuln = VersionVulnerability(cve_id="CVE-TEST-MAVEN-4", source="osv", affected_versions=[">=1.2.3,<2.0.0"])
        self.assertFalse(vuln.is_current_version_vulnerable("2.5.0", ecosystem="maven"))

    def test_unparseable_installed_version_assumes_vulnerable(self):
        vuln = VersionVulnerability(cve_id="CVE-TEST-MAVEN-5", source="osv", affected_versions=["<2.0.0"])
        self.assertTrue(vuln.is_current_version_vulnerable("!!!", ecosystem="maven"))


class NormalizeNugetVersionTests(unittest.TestCase):
    """Each case here was verified directly against real NuGet version
    strings/OSV boundaries encountered during development -- see
    models.py's _normalize_nuget_version docstring."""

    def test_pads_short_versions(self):
        self.assertEqual(_normalize_nuget_version("0"), "0.0.0")
        self.assertEqual(_normalize_nuget_version("1.2"), "1.2.0")

    def test_folds_fourth_segment_into_build_metadata(self):
        # Real Microsoft.IdentityModel.JsonWebTokens release.
        self.assertEqual(_normalize_nuget_version("4.0.2.202250630"), "4.0.2+202250630")

    def test_preserves_prerelease_suffix(self):
        self.assertEqual(_normalize_nuget_version("7.0.0-preview"), "7.0.0-preview")
        self.assertEqual(_normalize_nuget_version("5.0.0-beta7-208241120"), "5.0.0-beta7-208241120")

    def test_leaves_ordinary_three_segment_version_unchanged(self):
        self.assertEqual(_normalize_nuget_version("13.0.3"), "13.0.3")


class NugetSatisfiesClauseTests(unittest.TestCase):
    def test_gte_boundary(self):
        self.assertTrue(_nuget_satisfies_clause("1.2.3", ">=1.2.3"))
        self.assertFalse(_nuget_satisfies_clause("1.2.2", ">=1.2.3"))

    def test_lt_boundary(self):
        self.assertTrue(_nuget_satisfies_clause("1.9.9", "<2.0.0"))
        self.assertFalse(_nuget_satisfies_clause("2.0.0", "<2.0.0"))

    def test_bare_version_is_exact_match(self):
        self.assertTrue(_nuget_satisfies_clause("1.2.3", "1.2.3"))
        self.assertFalse(_nuget_satisfies_clause("1.2.4", "1.2.3"))

    def test_nuget_satisfies_ands_comma_separated_clauses(self):
        self.assertTrue(_nuget_satisfies("1.5.0", ">=1.2.3,<2.0.0"))
        self.assertFalse(_nuget_satisfies("2.0.0", ">=1.2.3,<2.0.0"))
        self.assertFalse(_nuget_satisfies("1.0.0", ">=1.2.3,<2.0.0"))

    def test_real_jsonwebtokens_range_with_bare_zero_lower_bound(self):
        # Real range from OSV for Microsoft.IdentityModel.JsonWebTokens
        # (GHSA-59j7-ghrg-fj52) -- confirmed directly against the live OSV
        # API during development. "introduced": "0" is a real, bare
        # placeholder boundary OSV uses for "no meaningful lower bound".
        self.assertTrue(_nuget_satisfies("4.0.2.202250630", ">=0,<5.7.0"))
        self.assertFalse(_nuget_satisfies("5.7.0", ">=0,<5.7.0"))

    def test_real_prerelease_boundary_range(self):
        self.assertTrue(_nuget_satisfies("7.0.0-preview", ">=7.0.0-preview,<7.1.2"))
        self.assertFalse(_nuget_satisfies("7.1.2", ">=7.0.0-preview,<7.1.2"))


class NugetRevisionTieBreakTests(unittest.TestCase):
    """The 4th+ numeric segment lives in semver build-metadata, which
    SemVer 2.0.0 explicitly excludes from precedence -- without a real
    tie-breaker, "1.0.0.1" and "1.0.0.2" would compare as exactly equal."""

    def test_fourth_segment_breaks_a_tie_semver_alone_would_call_equal(self):
        self.assertEqual(_nuget_compare("1.0.0.1", "1.0.0.2"), -1)
        self.assertEqual(_nuget_compare("1.0.0.2", "1.0.0.1"), 1)
        self.assertEqual(_nuget_compare("1.0.0.1", "1.0.0.1"), 0)

    def test_major_minor_patch_still_takes_precedence_over_revision(self):
        # A higher patch always wins regardless of revision.
        self.assertEqual(_nuget_compare("1.0.1.0", "1.0.0.99"), 1)

    def test_bare_version_compares_equal_to_explicit_zero_revision(self):
        self.assertEqual(_nuget_compare("1.0.0", "1.0.0.0"), 0)

    def test_missing_revision_treated_as_lower_than_a_present_one(self):
        self.assertEqual(_nuget_compare("1.0.0", "1.0.0.1"), -1)

    def test_satisfies_clause_now_distinguishes_revisions(self):
        self.assertTrue(_nuget_satisfies_clause("1.0.0.2", ">1.0.0.1"))
        self.assertFalse(_nuget_satisfies_clause("1.0.0.1", ">1.0.0.1"))

    def test_unparseable_version_returns_none_not_a_crash(self):
        self.assertIsNone(_nuget_compare("not-a-version", "1.0.0"))

    def test_revision_plus_prerelease_combo_does_not_crash(self):
        # _normalize_nuget_version's "+<revision>" + "-<prerelease>" ordering
        # means a version combining both folds the prerelease's leading "-"
        # into semver's build-metadata field instead of parsing it
        # separately (a real, narrower pre-existing quirk this tie-breaker
        # doesn't try to fix -- see _nuget_revision_segments's docstring).
        # What matters here is that the non-numeric build string this
        # produces is handled defensively, not that ordering is perfect.
        result = _nuget_compare("1.0.0.5-beta", "1.0.0.5-beta")
        self.assertEqual(result, 0)


class VersionVulnerabilityNuGetTests(unittest.TestCase):
    def test_real_jsonwebtokens_range(self):
        vuln = VersionVulnerability(cve_id="CVE-2024-21319", source="osv", affected_versions=[">=0,<5.7.0"])
        self.assertTrue(vuln.is_current_version_vulnerable("5.6.0", ecosystem="nuget"))
        self.assertFalse(vuln.is_current_version_vulnerable("5.7.0", ecosystem="nuget"))

    def test_fixed_in_version_uses_nuget_ordering(self):
        vuln = VersionVulnerability(cve_id="CVE-TEST-NUGET-1", source="osv", fixed_in_version="1.2.3")
        self.assertTrue(vuln.is_current_version_vulnerable("1.2.2", ecosystem="nuget"))
        self.assertFalse(vuln.is_current_version_vulnerable("1.2.3", ecosystem="nuget"))
        self.assertFalse(vuln.is_current_version_vulnerable("1.5.0", ecosystem="nuget"))

    def test_version_outside_range_is_not_flagged(self):
        vuln = VersionVulnerability(cve_id="CVE-TEST-NUGET-2", source="osv", affected_versions=[">=1.2.3,<2.0.0"])
        self.assertFalse(vuln.is_current_version_vulnerable("2.5.0", ecosystem="nuget"))

    def test_unparseable_installed_version_assumes_vulnerable(self):
        vuln = VersionVulnerability(cve_id="CVE-TEST-NUGET-3", source="osv", affected_versions=["<2.0.0"])
        self.assertTrue(vuln.is_current_version_vulnerable("!!!", ecosystem="nuget"))


class PubCompareTests(unittest.TestCase):
    """Confirmed directly against pub_semver's own Version.compareTo/
    _compareLists source -- Dart's build-metadata ordering deliberately
    differs from strict SemVer 2.0.0, which Python's semver library
    follows by default (see _pub_compare's own docstring)."""

    def test_prerelease_ordering_matches_standard_semver(self):
        self.assertEqual(_pub_compare("2.0.0-beta", "2.0.0"), -1)
        self.assertEqual(_pub_compare("1.0.0-alpha", "1.0.0-beta"), -1)

    def test_build_metadata_breaks_a_tie_strict_semver_would_call_equal(self):
        self.assertEqual(_pub_compare("1.2.3+1", "1.2.3+2"), -1)
        self.assertEqual(_pub_compare("1.2.3+2", "1.2.3+1"), 1)
        self.assertEqual(_pub_compare("1.2.3+1", "1.2.3+1"), 0)

    def test_no_build_is_lower_than_has_build_the_opposite_of_prerelease(self):
        # Confirmed directly: pub_semver's own comment is literally
        # "Builds always come after no build string" -- the reverse of
        # "no prerelease beats has prerelease".
        self.assertEqual(_pub_compare("1.2.3", "1.2.3+1"), -1)
        self.assertEqual(_pub_compare("1.2.3+1", "1.2.3"), 1)

    def test_build_identifiers_compare_numerically_not_lexically(self):
        self.assertEqual(_pub_compare("1.2.3+10", "1.2.3+9"), 1)

    def test_major_minor_patch_takes_precedence_over_build(self):
        self.assertEqual(_pub_compare("1.0.1+0", "1.0.0+99"), 1)

    def test_satisfies_clause_uses_pub_ordering(self):
        self.assertTrue(_pub_satisfies_clause("1.2.3+2", ">1.2.3+1"))
        self.assertFalse(_pub_satisfies_clause("1.2.3+1", ">1.2.3+1"))

    def test_unparseable_version_returns_none_not_a_crash(self):
        self.assertIsNone(_pub_compare("not-a-version", "1.0.0"))


class PubSatisfiesClauseTests(unittest.TestCase):
    def test_gte_boundary(self):
        self.assertTrue(_pub_satisfies_clause("1.2.3", ">=1.2.3"))
        self.assertFalse(_pub_satisfies_clause("1.2.2", ">=1.2.3"))

    def test_lt_boundary(self):
        self.assertTrue(_pub_satisfies_clause("1.9.9", "<2.0.0"))
        self.assertFalse(_pub_satisfies_clause("2.0.0", "<2.0.0"))

    def test_bare_version_is_exact_match(self):
        self.assertTrue(_pub_satisfies_clause("1.2.3", "1.2.3"))
        self.assertFalse(_pub_satisfies_clause("1.2.4", "1.2.3"))

    def test_pub_satisfies_ands_comma_separated_clauses(self):
        self.assertTrue(_pub_satisfies("1.5.0", ">=1.2.3,<2.0.0"))
        self.assertFalse(_pub_satisfies("2.0.0", ">=1.2.3,<2.0.0"))
        self.assertFalse(_pub_satisfies("1.0.0", ">=1.2.3,<2.0.0"))


class VersionVulnerabilityPubTests(unittest.TestCase):
    def test_fixed_in_version_uses_pub_ordering(self):
        vuln = VersionVulnerability(cve_id="CVE-TEST-PUB-1", source="osv", fixed_in_version="1.2.3")
        self.assertTrue(vuln.is_current_version_vulnerable("1.2.2", ecosystem="pub"))
        self.assertFalse(vuln.is_current_version_vulnerable("1.2.3", ecosystem="pub"))
        self.assertFalse(vuln.is_current_version_vulnerable("1.5.0", ecosystem="pub"))

    def test_version_outside_range_is_not_flagged(self):
        vuln = VersionVulnerability(cve_id="CVE-TEST-PUB-2", source="osv", affected_versions=[">=1.2.3,<2.0.0"])
        self.assertFalse(vuln.is_current_version_vulnerable("2.5.0", ecosystem="pub"))

    def test_unparseable_installed_version_assumes_vulnerable(self):
        vuln = VersionVulnerability(cve_id="CVE-TEST-PUB-3", source="osv", affected_versions=["<2.0.0"])
        self.assertTrue(vuln.is_current_version_vulnerable("!!!", ecosystem="pub"))


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
