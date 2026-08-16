"""Data structures shared across the intelligence-source clients."""

from __future__ import annotations

from typing import List, Optional

import nodesemver
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
