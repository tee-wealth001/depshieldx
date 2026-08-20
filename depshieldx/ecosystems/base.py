"""Ecosystem-neutral package model and the adapter interface each package
ecosystem (PyPI today; npm/cargo/go in later phases) implements.

This is the seam final-plan.md's Phase 0 calls for: the shared engine (CVE
lookup, policy decisions, receipts) should operate on PackageRecord and the
Ecosystem interface, not on pip/PyPI specifics directly.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..core.resolver import ResolutionResult


@dataclass
class PackageRecord:
    """A single resolved package, represented the same way regardless of
    which ecosystem it came from. Used for CVE lookups, receipts, caching."""

    ecosystem: str
    name: str
    version: str
    source: str | None = None
    purl: str | None = None
    digest: str | None = None
    direct: bool = True


def _normalize_pypi_name(name: str) -> str:
    return name.strip().lower().replace("_", "-") if name else ""


def _normalize_name_for_ecosystem(name: str, ecosystem: str) -> str:
    # PyPI/PEP 503 treats "-"/"_" as equivalent; npm's package names are
    # hyphen-significant. crates.io also treats "-"/"_" as interchangeable
    # for name-uniqueness purposes (its own index rejects publishing a crate
    # whose name only differs from an existing one by that substitution),
    # so it gets the same folding as PyPI.
    if ecosystem in ("pypi", "cargo"):
        return _normalize_pypi_name(name)
    if ecosystem in ("go", "maven", "nuget", "pub", "rubygems"):
        # Go module paths are case-sensitive canonical identifiers
        # (confirmed directly against go.dev/ref/mod's module-path rules)
        # -- unlike every other ecosystem here, lowercasing would fold
        # together genuinely different modules and would silently break
        # matching against external vulnerability sources, which document
        # their Go package-name field as the exact module path (see
        # go_registry.py's module docstring). Only whitespace is trimmed.
        # Maven groupId/artifactId coordinates get the same treatment --
        # Maven Central's own repository layout (registry.py's
        # group_path()) is case-sensitive, and OSV/deps.dev/GitHub
        # Advisories all key Maven entries by the exact "groupId:
        # artifactId" coordinate (confirmed directly against real OSV
        # query responses). NuGet package IDs are a real, easy-to-get-
        # wrong exception to the pattern otherwise suggested by ecosystem
        # tooling: nuget.org's own resolution is case-*insensitive*
        # (confirmed directly the flat-container API even requires a
        # lowercased URL path), but OSV's NuGet-ecosystem matching is
        # case-*sensitive* on the package's exact canonical casing
        # (confirmed directly: a real query for "Microsoft.IdentityModel.
        # JsonWebTokens" returns real results, the all-lowercase variant
        # returns none) -- lowercasing here would silently break CVE
        # matching. `dotnet restore` always normalizes PackageReference
        # casing to the exact canonical form in the generated packages.
        # lock.json regardless of what casing was requested (confirmed
        # directly), so resolved_versions is already correctly cased by
        # the time it reaches here. Pub package names are constrained to
        # `^[a-zA-Z0-9_]+$` and, by convention, published in lowercase --
        # but that convention is enforced going forward, not retroactively
        # (confirmed directly against dart-lang/pub-dev's own
        # `knownMixedCasePackages` allowlist of real, still-live, mixed-
        # case packages grandfathered in from before the convention was
        # enforced), so case is preserved rather than folded, the same
        # "case genuinely matters, don't fold it" treatment as Go/Maven.
        # RubyGems gem names are case-sensitive too (confirmed directly:
        # a real lowercase "json" resolves, the uppercase "JSON" 404s),
        # and OSV/GHSA/deps.dev all key RubyGems entries by that exact
        # casing (confirmed directly against real query responses), so
        # they get the same "preserve, don't fold" treatment.
        return name.strip() if name else ""
    # Composer/Packagist package names fall through to here deliberately
    # (not a special case above): confirmed directly Packagist's own
    # lookup is case-insensitive but its canonical form is always
    # lowercase ("Monolog/Monolog" and "monolog/monolog" both resolve to
    # the same real package, always reported back as lowercase), and
    # OSV's own Packagist-ecosystem matching is confirmed directly case-
    # *sensitive* on that lowercase form -- the same "the registry's own
    # canonical form already IS case-folded" situation PyPI/Cargo have,
    # not the "case genuinely matters, preserve it" one Go/Maven/NuGet/
    # Pub/RubyGems have.
    return name.strip().lower() if name else ""


def _strip_version_spec(target: str, ecosystem: str) -> str:
    if ecosystem == "pypi":
        return target.split("[", 1)[0].split("==", 1)[0]
    if ecosystem == "npm":
        # "left-pad@1.3.0" -> "left-pad"; "@babel/core@^7.0.0" -> "@babel/core".
        # Scoped packages have a leading "@" that must be skipped when searching
        # for the name/version separator "@" (same rule as npm_lockfiles.py's
        # yarn.lock parsing).
        search_from = 1 if target.startswith("@") else 0
        at_index = target.find("@", search_from)
        return target[:at_index] if at_index != -1 else target
    if ecosystem in ("cargo", "go", "nuget", "pub", "rubygems", "composer"):
        # "serde@=1.0.219" -> "serde"; "github.com/pkg/errors@v0.9.1" ->
        # "github.com/pkg/errors"; "Newtonsoft.Json@13.0.3" ->
        # "Newtonsoft.Json"; "http@1.6.0" -> "http"; "rack@3.2.7" ->
        # "rack"; "monolog/monolog@3.10.0" -> "monolog/monolog" --
        # crate/module/package/gem/composer-package names have no
        # scoping prefix to skip past, unlike npm's "@scope/name" (a
        # Composer "vendor/package" coordinate's own "/" never collides
        # with the "@version" separator).
        at_index = target.find("@")
        return target[:at_index] if at_index != -1 else target
    if ecosystem == "maven":
        # "org.apache.commons:commons-lang3:3.17.0" ->
        # "org.apache.commons:commons-lang3"; a bare "groupId:artifactId"
        # target (no version) is returned unchanged -- Maven coordinates
        # use ":" as both the groupId/artifactId separator and the
        # artifactId/version separator, so (unlike cargo/go's "@") this
        # can't just split on the first occurrence of the separator.
        parts = target.split(":")
        return ":".join(parts[:2]) if len(parts) >= 3 else target
    return target


def package_records(ecosystem: str, resolution: ResolutionResult) -> list[PackageRecord]:
    """Build ecosystem-neutral records from a resolver's ResolutionResult."""
    direct_names = {
        _normalize_name_for_ecosystem(_strip_version_spec(target, ecosystem), ecosystem)
        for target in resolution.requested_targets
    }
    records = []
    for name, version in resolution.resolved_versions.items():
        artifacts = (resolution.selected_artifacts or {}).get(name) or []
        digest = (artifacts[0].get("digests") or {}).get("sha256") if artifacts else None
        if ecosystem == "maven" and version:
            # purl's Maven type uses "groupId" as the namespace segment and
            # "artifactId" as the name segment (pkg:maven/namespace/name@
            # version, confirmed directly against a real OSV response's
            # own "purl" field) -- not the colon-joined "groupId:
            # artifactId" coordinate depshieldx uses internally as `name`
            # everywhere else in this module.
            group_id, _, artifact_id = name.partition(":")
            purl = f"pkg:maven/{group_id}/{artifact_id}@{version}"
        else:
            purl = f"pkg:{ecosystem}/{name}@{version}" if version else None
        records.append(
            PackageRecord(
                ecosystem=ecosystem,
                name=name,
                version=version,
                source={
                    "pypi": "pypi.org",
                    "npm": "npmjs.org",
                    "cargo": "crates.io",
                    "go": "pkg.go.dev",
                    "maven": "repo1.maven.org",
                    "nuget": "nuget.org",
                    "pub": "pub.dev",
                    "rubygems": "rubygems.org",
                    "composer": "packagist.org",
                }.get(ecosystem),
                purl=purl,
                digest=digest,
                direct=_normalize_name_for_ecosystem(name, ecosystem) in direct_names,
            )
        )
    return records


class Ecosystem(Protocol):
    """Interface every package-manager ecosystem adapter implements.

    This is deliberately one combined interface for now, with PyPiEcosystem
    implementing every capability -- matching the "even if PyPiEcosystem
    implements all of them initially" allowance in final-plan.md. Splitting
    this into separate Resolver/LockfileParser/ArtifactProvider/
    ProvenanceChecker/Installer capabilities is real future work, but doing
    it now with only one ecosystem to validate the split against would be
    speculative. Revisit when the npm adapter (Phase 1) needs a genuinely
    different capability combination than PyPI's.
    """

    name: str
    cve_ecosystem_name: str
    lockfile_patterns: tuple[str, ...]

    def resolve(
        self,
        manager_args: list[str],
        requested_targets: list[str],
        install_target: str,
        source_type: str = "package",
    ) -> ResolutionResult: ...

    def check_provenance(
        self,
        resolved_versions: dict[str, str],
        selected_artifacts: dict[str, list[dict]] | None = None,
        verbose: bool = False,
    ) -> dict: ...

    def fetch_artifact(self, artifact: dict, destination: Path) -> Path: ...

    def selected_artifact_entries(self, resolution: ResolutionResult) -> list[tuple[str, str, dict]]: ...

    def install_command(self, artifact_paths: list[str]) -> list[str]: ...

    def host_install_command(self, resolution: ResolutionResult) -> AbstractContextManager[list[str]]: ...

    def uninstall_command(self, package_names: list[str]) -> list[str]: ...
