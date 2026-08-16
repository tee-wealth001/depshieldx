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

from ..resolver import ResolutionResult


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
    if ecosystem == "cargo":
        # "serde@=1.0.219" -> "serde"; crate names have no scoping prefix
        # to skip past, unlike npm's "@scope/name".
        at_index = target.find("@")
        return target[:at_index] if at_index != -1 else target
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
        records.append(
            PackageRecord(
                ecosystem=ecosystem,
                name=name,
                version=version,
                source={"pypi": "pypi.org", "npm": "npmjs.org", "cargo": "crates.io"}.get(ecosystem),
                purl=f"pkg:{ecosystem}/{name}@{version}" if version else None,
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
