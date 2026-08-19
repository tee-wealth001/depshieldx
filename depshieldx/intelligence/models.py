"""Data structures shared across the intelligence-source clients."""

from __future__ import annotations

import re
from typing import List, Optional

import nodesemver
import semver
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

# operator prefix -> nodesemver comparator, used to evaluate the ">=X,<Y"-style
# range clauses osv.py builds against npm (semver) versions instead of PyPI
# (PEP 440) ones -- see VersionVulnerability.is_current_version_vulnerable's
# npm branch.
_NPM_COMPARATORS = {
    ">=": nodesemver.gte,
    "<=": nodesemver.lte,
    ">": nodesemver.gt,
    "<": nodesemver.lt,
    "==": nodesemver.eq,
}


def _npm_satisfies_clause(version: str, clause: str) -> bool:
    """True if `version` satisfies one "<op><boundary>" clause, using semver
    (not PEP 440) ordering. A bare version with no operator prefix (npm's
    exact-match fallback, see the "==" version list built in
    osv._async_fetch_osv_cves_inner) is treated as an exact match.

    Deliberately does NOT use nodesemver's own Range/satisfies() -- those
    implement npm's dependency-resolution-specific "a prerelease version
    only satisfies a range whose boundary shares its exact [major, minor,
    patch] tuple" rule, which would silently exclude real prerelease
    versions from vulnerability ranges (a false negative) rather than
    doing the plain ordering comparison a security check needs.
    """
    clause = clause.strip()
    # Longer prefixes first so ">=" isn't mistaken for ">". A clause with no
    # recognized operator prefix is npm's exact-match fallback (see the "=="
    # version list built in osv._async_fetch_osv_cves_inner's `versions`
    # branch -- bare there too, "==" is just this module's own PyPI-oriented
    # spelling of "exact match").
    for prefix in (">=", "<=", "==", ">", "<"):
        if clause.startswith(prefix):
            operator, boundary = prefix, clause[len(prefix):].strip()
            break
    else:
        operator, boundary = "==", clause

    if not nodesemver.valid(boundary, False):
        return False
    return _NPM_COMPARATORS[operator](version, boundary, False)


def _npm_satisfies(version: str, spec: str) -> bool:
    """AND across the comma-separated clauses in one affected_versions entry."""
    return all(_npm_satisfies_clause(version, clause) for clause in spec.split(","))


def _cargo_satisfies_clause(version: str, clause: str) -> bool:
    """True if `version` satisfies one "<op><boundary>" clause, using real
    SemVer 2.0.0 ordering (Rust/Cargo versions strictly follow semver.org
    2.0.0, unlike npm's historically loose validation, and unlike PEP 440,
    which has materially different prerelease-ordering rules -- see
    findings.md #11 for the exact npm/PEP-440 mismatch this already burned
    once). A bare version with no operator prefix is treated as an exact
    match, mirroring the npm branch's convention above.

    Deliberately compares via semver.Version's plain ordering operators
    (>=, <=, etc.), not a requirement-range/caret-satisfaction check --
    same reasoning as the npm branch: Cargo's own caret-default
    requirement-resolution rules are for dependency *declarations* in
    Cargo.toml, not a general-purpose vulnerability-range ordering check.
    Verified directly against real OSV crates.io advisory data (e.g. the
    `time` crate's RUSTSEC-2026-0009) -- semver.Version.parse() correctly
    handles the "X.Y.Z" and "X.Y.Z-0"-style boundaries OSV actually
    produces.
    """
    clause = clause.strip()
    for prefix in (">=", "<=", "==", ">", "<"):
        if clause.startswith(prefix):
            operator, boundary = prefix, clause[len(prefix):].strip()
            break
    else:
        operator, boundary = "==", clause

    try:
        current = semver.Version.parse(version)
        target = semver.Version.parse(boundary)
    except ValueError:
        return False

    if operator == ">=":
        return current >= target
    if operator == "<=":
        return current <= target
    if operator == ">":
        return current > target
    if operator == "<":
        return current < target
    return current == target


def _cargo_satisfies(version: str, spec: str) -> bool:
    """AND across the comma-separated clauses in one affected_versions entry."""
    return all(_cargo_satisfies_clause(version, clause) for clause in spec.split(","))


def _strip_go_version_prefix(version: str) -> str:
    return version[1:] if version[:1] in ("v", "V") else version


def _go_satisfies_clause(version: str, clause: str) -> bool:
    """True if `version` satisfies one "<op><boundary>" clause, using real
    SemVer 2.0.0 ordering -- Go module versions are semver (confirmed
    directly against go.dev/ref/mod), just written with a leading "v"
    ("v1.2.3") that semver.Version.parse() rejects, so it's stripped from
    both sides first. Confirmed directly against real OSV Go advisory data
    (golang.org/x/crypto's GHSA-3vm4-22fp-5rfm): OSV's own `introduced`/
    `fixed` boundary values for the Go ecosystem have no "v" prefix at all
    (e.g. "fixed": "0.0.0-20201216223049-8b5274cf687f"), unlike the
    resolved versions depshieldx compares them against -- both sides are
    normalized the same way here so the mismatched convention doesn't
    matter. A bare boundary like OSV's "introduced": "0" isn't valid
    SemVer either way and simply fails to parse -- that one clause is
    skipped (mirrors the cargo branch's identical accepted failure mode
    for any unparseable boundary), not treated as a crash.
    """
    clause = clause.strip()
    for prefix in (">=", "<=", "==", ">", "<"):
        if clause.startswith(prefix):
            operator, boundary = prefix, clause[len(prefix):].strip()
            break
    else:
        operator, boundary = "==", clause

    try:
        current = semver.Version.parse(_strip_go_version_prefix(version))
        target = semver.Version.parse(_strip_go_version_prefix(boundary))
    except ValueError:
        return False

    if operator == ">=":
        return current >= target
    if operator == "<=":
        return current <= target
    if operator == ">":
        return current > target
    if operator == "<":
        return current < target
    return current == target


def _go_satisfies(version: str, spec: str) -> bool:
    """AND across the comma-separated clauses in one affected_versions entry."""
    return all(_go_satisfies_clause(version, clause) for clause in spec.split(","))


# Maven's real version-precedence qualifier table (org.apache.maven.
# artifact.versioning.ComparableVersion) confirmed directly by running
# that exact class's own comparison tool -- `java -cp maven-artifact-*.jar
# org.apache.maven.artifact.versioning.ComparableVersion <versions...>` --
# against a real Maven install: alpha < beta < milestone < rc/cr <
# snapshot < (no qualifier/ga/final/release) < sp. Confirmed the same way:
# any *unrecognized* qualifier (e.g. real Central examples like Guava's
# "-jre"/"-android" flavor suffixes) sorts after even the release tier
# ("33.4.0-jre" > "33.4.0").
_MAVEN_QUALIFIER_RANK = {
    "alpha": 0, "beta": 1, "milestone": 2, "rc": 3, "cr": 3,
    "snapshot": 4, "": 5, "ga": 5, "final": 5, "release": 5, "sp": 6,
}
_MAVEN_TOKEN = re.compile(r"\d+|[a-zA-Z]+")


def _maven_tokenize(version: str) -> list[tuple[int, int | str]]:
    """Flat token list for one Maven version, splitting on '.'/'-' and on
    every digit<->letter transition (e.g. "1.0-rc1" -> ["1", "0", "rc",
    "1"]) -- mirrors ComparableVersion's own tokenization for the common
    case. Each token becomes (0, rank) for a recognized qualifier,
    (1, int) for a numeric run, or (2, text) for an unrecognized
    qualifier; the tier ordering (known-qualifier < numeric < unrecognized
    -qualifier) is confirmed directly, see the module comment above.

    Deliberately doesn't reproduce ComparableVersion's full recursive
    nested-list structure (a '-' after a qualifier starts a genuinely
    nested sub-list in the real algorithm, e.g. "1.0-rc1" internally is
    [1, [rc, [1]]], not a flat 4-token list) -- getting the common,
    real-world case (release/pre-release/snapshot qualifiers, unrecognized
    build-flavor suffixes) exactly right, confirmed against real `mvn`
    output, was judged a better tradeoff than a full reimplementation with
    unverified edge-case behavior for something this security-sensitive.
    """
    tokens: list[tuple[int, int | str]] = []
    for raw in _MAVEN_TOKEN.findall(version.strip()):
        if raw.isdigit():
            tokens.append((1, int(raw)))
        else:
            lowered = raw.lower()
            if lowered in _MAVEN_QUALIFIER_RANK:
                tokens.append((0, _MAVEN_QUALIFIER_RANK[lowered]))
            else:
                tokens.append((2, lowered))
    return tokens


def _maven_compare(version_a: str, version_b: str) -> int:
    """-1/0/1 the way Maven's own ComparableVersion orders two version
    strings, for the common case -- see _maven_tokenize's docstring for
    exactly what's confirmed directly and what's simplified. Missing
    trailing tokens are padded to match the *other* side's token type at
    that position (a missing qualifier-position token pads as the
    release/"" qualifier, rank 5; a missing numeric-position token pads
    as 0) -- confirmed directly this reproduces real Maven's null-padding
    rule (e.g. "5.3.4.RELEASE" == "5.3.4", "1.0" > "1.0-alpha").
    """
    tokens_a = _maven_tokenize(version_a)
    tokens_b = _maven_tokenize(version_b)
    for index in range(max(len(tokens_a), len(tokens_b))):
        token_a = tokens_a[index] if index < len(tokens_a) else None
        token_b = tokens_b[index] if index < len(tokens_b) else None
        if token_a is None:
            token_a = (1, 0) if token_b[0] == 1 else (0, 5)
        if token_b is None:
            token_b = (1, 0) if token_a[0] == 1 else (0, 5)
        if token_a != token_b:
            return -1 if token_a < token_b else 1
    return 0


def _maven_satisfies_clause(version: str, clause: str) -> bool:
    """True if `version` satisfies one "<op><boundary>" clause, using
    _maven_compare. A bare version with no operator prefix is treated as
    an exact match, mirroring the npm/cargo/go branches' identical
    convention."""
    clause = clause.strip()
    for prefix in (">=", "<=", "==", ">", "<"):
        if clause.startswith(prefix):
            operator, boundary = prefix, clause[len(prefix):].strip()
            break
    else:
        operator, boundary = "==", clause

    comparison = _maven_compare(version, boundary)
    if operator == ">=":
        return comparison >= 0
    if operator == "<=":
        return comparison <= 0
    if operator == ">":
        return comparison > 0
    if operator == "<":
        return comparison < 0
    return comparison == 0


def _maven_satisfies(version: str, spec: str) -> bool:
    """AND across the comma-separated clauses in one affected_versions entry."""
    return all(_maven_satisfies_clause(version, clause) for clause in spec.split(","))


class VersionVulnerability:
    """Represents a vulnerability with version-specific information."""

    def __init__(
        self,
        cve_id: str,
        source: str,
        affected_versions: Optional[List[str]] = None,
        fixed_in_version: Optional[str] = None,
        severity: str = "UNKNOWN",
        summary: str = "",
        aliases: Optional[List[str]] = None,
    ):
        self.cve_id = cve_id
        self.source = source
        self.affected_versions = affected_versions or []
        self.fixed_in_version = fixed_in_version
        self.severity = severity
        self.summary = summary
        self.aliases = aliases or []

    def is_current_version_vulnerable(self, version: str, ecosystem: str = "pypi") -> bool:
        """Check if a specific version is affected by this vulnerability.

        `affected_versions`/`fixed_in_version` are built by osv.py as
        ">=X,<Y"-style comparator strings regardless of ecosystem -- only the
        *comparison engine* differs below, not that string format. npm uses
        semver ordering (nodesemver), not PEP 440/PyPI's -- see findings.md
        #11 for why this matters: PEP 440 silently mis-orders some real npm
        prerelease versions (e.g. "1.2.3-0" sorts as a *post*-release under
        PEP 440's normalization, the opposite of semver's pre-release
        ordering) and outright rejects others (e.g. "1.0.0-x.7.z.92"), both
        of which previously caused this check to silently under- or
        over-report npm vulnerabilities.
        """
        if not self.affected_versions and not self.fixed_in_version:
            return True  # Unknown range, assume vulnerable

        if ecosystem == "npm":
            return self._is_current_version_vulnerable_npm(version)

        if ecosystem == "cargo":
            return self._is_current_version_vulnerable_cargo(version)

        if ecosystem == "go":
            return self._is_current_version_vulnerable_go(version)

        if ecosystem == "maven":
            return self._is_current_version_vulnerable_maven(version)

        try:
            check_version = Version(version)
        except InvalidVersion:
            return True

        # Check affected versions list
        for affected_range in self.affected_versions:
            try:
                spec_set = SpecifierSet(affected_range)
                if check_version in spec_set:
                    return True
            except Exception:
                pass

        # Check if version is before fix
        if self.fixed_in_version:
            try:
                fixed_version = Version(self.fixed_in_version)
                if check_version < fixed_version:
                    return True
            except InvalidVersion:
                pass

        return False

    def _is_current_version_vulnerable_npm(self, version: str) -> bool:
        if not nodesemver.valid(version, False):
            return True  # Unparseable installed version, assume vulnerable -- mirrors the PyPI branch above

        for affected_range in self.affected_versions:
            try:
                if _npm_satisfies(version, affected_range):
                    return True
            except Exception:
                pass

        if self.fixed_in_version and nodesemver.valid(self.fixed_in_version, False):
            try:
                if nodesemver.lt(version, self.fixed_in_version, False):
                    return True
            except Exception:
                pass

        return False

    def _is_current_version_vulnerable_cargo(self, version: str) -> bool:
        try:
            current_version = semver.Version.parse(version)
        except ValueError:
            return True  # Unparseable installed version, assume vulnerable -- mirrors the PyPI/npm branches above

        for affected_range in self.affected_versions:
            try:
                if _cargo_satisfies(version, affected_range):
                    return True
            except Exception:
                pass

        if self.fixed_in_version:
            try:
                if current_version < semver.Version.parse(self.fixed_in_version):
                    return True
            except ValueError:
                pass

        return False

    def _is_current_version_vulnerable_go(self, version: str) -> bool:
        try:
            current_version = semver.Version.parse(_strip_go_version_prefix(version))
        except ValueError:
            return True  # Unparseable installed version, assume vulnerable -- mirrors the PyPI/npm/cargo branches above

        for affected_range in self.affected_versions:
            try:
                if _go_satisfies(version, affected_range):
                    return True
            except Exception:
                pass

        if self.fixed_in_version:
            try:
                if current_version < semver.Version.parse(_strip_go_version_prefix(self.fixed_in_version)):
                    return True
            except ValueError:
                pass

        return False

    def _is_current_version_vulnerable_maven(self, version: str) -> bool:
        if not _MAVEN_TOKEN.findall(version.strip()):
            return True  # No parseable version content at all, assume vulnerable -- mirrors the branches above

        for affected_range in self.affected_versions:
            try:
                if _maven_satisfies(version, affected_range):
                    return True
            except Exception:
                pass

        if self.fixed_in_version:
            try:
                if _maven_compare(version, self.fixed_in_version) < 0:
                    return True
            except Exception:
                pass

        return False

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "source": self.source,
            "affected_versions": self.affected_versions,
            "fixed_in_version": self.fixed_in_version,
            "severity": self.severity,
            "summary": self.summary,
            "aliases": self.aliases,
        }
