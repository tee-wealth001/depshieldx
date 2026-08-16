"""Data structures shared across the intelligence-source clients."""

from __future__ import annotations

from typing import List, Optional

from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version


class VersionVulnerability:
    """Represents a vulnerability with version-specific information.

    NOTE: is_current_version_vulnerable() parses both the installed version
    and each affected-version range as PEP 440 (packaging.version/
    SpecifierSet) -- PyPI's version scheme, not npm's semver. This class is
    already constructed for npm results too (the OSV async fetcher accepts
    an ecosystem parameter and is used for both), and a semver range like
    "^1.2.3" or a prerelease tag like "1.2.3-beta.1" will usually fail to
    parse as a PEP 440 specifier -- silently caught below and skipped rather
    than matched, which likely produces false negatives for npm CVEs today.
    See findings.md #11. Not fixed here -- this needs real per-ecosystem
    version-comparison support, not a rename or a docstring alone.
    """

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

    def is_current_version_vulnerable(self, version: str) -> bool:
        """Check if a specific version is affected by this vulnerability."""
        if not self.affected_versions and not self.fixed_in_version:
            return True  # Unknown range, assume vulnerable

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
