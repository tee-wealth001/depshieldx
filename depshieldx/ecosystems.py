"""Ecosystem-neutral package model and the adapter interface each package
ecosystem (PyPI today; npm/cargo/go in later phases) implements.

This is the seam final-plan.md's Phase 0 calls for: the shared engine (CVE
lookup, policy decisions, receipts) should operate on PackageRecord and the
Ecosystem interface, not on pip/PyPI specifics directly. PyPiEcosystem wraps
the existing, already-tested resolver/provenance/artifact-fetch logic rather
than rewriting it -- the seam is the new part, not the underlying behavior.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import tempfile
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import unquote, urlparse
from urllib.request import url2pathname

import requests

from .npm_lockfiles import parse_lockfile, parse_package_lock_json
from .npm_registry import check_provenance_batch as npm_check_provenance_batch, fetch_package_metadata
from .provenance import check_provenance_batch
from .resolver import ResolutionResult, resolve_dependencies, resolve_install_inputs
from .runtime import pip_command


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
    # PyPI/PEP 503 treats "-"/"_" as equivalent; other ecosystems (npm's package
    # names are hyphen-significant) don't share that convention.
    if ecosystem == "pypi":
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
                source="pypi.org" if ecosystem == "pypi" else ("npmjs.org" if ecosystem == "npm" else None),
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


class PyPiEcosystem:
    """The Python/pip ecosystem adapter."""

    name = "pypi"
    cve_ecosystem_name = "PyPI"
    lockfile_patterns = ("requirements*.txt", "uv.lock", "pyproject.toml")

    def resolve(
        self,
        manager_args: list[str],
        requested_targets: list[str],
        install_target: str,
        source_type: str = "package",
    ) -> ResolutionResult:
        if source_type == "package":
            return resolve_dependencies(requested_targets[0])
        return resolve_install_inputs(manager_args, requested_targets, install_target, source_type=source_type)

    def check_provenance(
        self,
        resolved_versions: dict[str, str],
        selected_artifacts: dict[str, list[dict]] | None = None,
        verbose: bool = False,
    ) -> dict:
        return check_provenance_batch(resolved_versions, selected_artifacts=selected_artifacts, verbose=verbose)

    def selected_artifact_entries(self, resolution: ResolutionResult) -> list[tuple[str, str, dict]]:
        selected_artifacts = resolution.selected_artifacts or {}
        artifact_lookup: dict[str, list[dict]] = {}
        for package_name, artifacts in selected_artifacts.items():
            artifact_lookup[_normalize_pypi_name(package_name)] = artifacts or []

        entries = []
        seen = set()
        for package_name, version in resolution.resolved_versions.items():
            artifacts = artifact_lookup.get(_normalize_pypi_name(package_name)) or []
            if not artifacts:
                raise RuntimeError(f"missing selected artifact for resolved package {package_name}=={version}")
            artifact = artifacts[0]
            url = artifact.get("url")
            filename = artifact.get("filename")
            if not url or not filename:
                raise RuntimeError(f"resolved artifact metadata incomplete for {package_name}=={version}")
            key = (filename, url)
            if key in seen:
                continue
            seen.add(key)
            entries.append((package_name, version, artifact))
        return entries

    def fetch_artifact(self, artifact: dict, destination: Path) -> Path:
        url = artifact["url"]
        filename = artifact["filename"]
        destination_path = destination / filename
        parsed = urlparse(url)

        if parsed.scheme in {"", "file"}:
            source_path = Path(url2pathname(parsed.path) if parsed.scheme == "file" else unquote(url)).expanduser()
            if not source_path.exists():
                raise RuntimeError(f"selected artifact path does not exist: {source_path}")
            shutil.copy2(source_path, destination_path)
            return destination_path

        expected_sha256 = ((artifact.get("digests") or {}).get("sha256") or "").strip()
        if not expected_sha256:
            raise RuntimeError(f"selected artifact for {filename} is missing sha256 metadata")

        response = requests.get(url, timeout=30)
        response.raise_for_status()
        artifact_bytes = response.content
        actual_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
        if actual_sha256 != expected_sha256:
            raise RuntimeError(
                f"downloaded artifact hash mismatch for {filename}: expected {expected_sha256}, got {actual_sha256}"
            )
        destination_path.write_bytes(artifact_bytes)
        return destination_path

    @contextmanager
    def host_install_command(self, resolution: ResolutionResult):
        artifact_entries = self.selected_artifact_entries(resolution)
        with tempfile.TemporaryDirectory(prefix="depshieldx_host_install_") as temp_dir:
            temp_path = Path(temp_dir)
            artifact_paths = [str(self.fetch_artifact(artifact, temp_path)) for _, _, artifact in artifact_entries]
            if not artifact_paths:
                raise RuntimeError("no selected artifacts were available for host install")
            yield self.install_command(artifact_paths)

    def install_command(self, artifact_paths: list[str]) -> list[str]:
        return pip_command(["install", "--no-deps", *artifact_paths])

    def uninstall_command(self, package_names: list[str]) -> list[str]:
        return pip_command(["uninstall", "-y", *package_names])


PYPI_ECOSYSTEM = PyPiEcosystem()


def resolve_node_tool(name: str) -> str:
    """Resolve an npm/yarn/pnpm-style Node.js tool via PATH.

    On Windows these ship as .cmd shims (npm.cmd, not npm), which Python's
    subprocess -- unlike a real shell -- will not find from a bare "npm"
    argument: CreateProcess doesn't search PATHEXT the way cmd.exe does.
    shutil.which() does the same PATHEXT-aware search a shell would, so it
    correctly returns the .cmd path on Windows and the plain name on POSIX.
    Reproduced directly: subprocess.run(["npm", ...]) raised
    "[WinError 2] The system cannot find the file specified" even with npm
    genuinely installed and on PATH.
    """
    resolved = shutil.which(name)
    if not resolved:
        raise RuntimeError(f"{name!r} was not found on PATH. Install Node.js/{name} to use the npm ecosystem.")
    return resolved


class NpmEcosystem:
    """The npm/yarn/pnpm ecosystem adapter (Phase 1, fast mode).

    Provenance checks are structural only -- see npm_registry.py's module
    docstring for why full Sigstore bundle verification isn't done here yet.

    npm itself is a separate runtime (Node.js) -- unlike pip, this has
    nothing to do with depshieldx's own frozen/non-frozen state, so
    runtime.py's Python interpreter resolution doesn't apply here. It still
    needs its own PATH resolution, though -- see resolve_node_tool.
    """

    name = "npm"
    cve_ecosystem_name = "npm"
    lockfile_patterns = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")

    def resolve(
        self,
        manager_args: list[str],
        requested_targets: list[str],
        install_target: str,
        source_type: str = "package",
    ) -> ResolutionResult:
        if source_type == "lockfile" and requested_targets:
            try:
                resolved_versions = parse_lockfile(requested_targets[0])
            except Exception as exc:
                return self._failed_resolution(install_target, requested_targets, source_type, str(exc))
            return self._succeeded_resolution(install_target, requested_targets, source_type, resolved_versions)

        if source_type in ("package", "packages") and requested_targets:
            try:
                resolved_versions = self._resolve_via_npm_registry(requested_targets)
            except Exception as exc:
                return self._failed_resolution(install_target, requested_targets, source_type, str(exc))
            return self._succeeded_resolution(install_target, requested_targets, source_type, resolved_versions)

        return self._failed_resolution(
            install_target,
            requested_targets,
            source_type,
            "npm resolution supports a lockfile (package-lock.json, yarn.lock, pnpm-lock.yaml) "
            "or one or more package names",
        )

    @staticmethod
    def _failed_resolution(install_target, requested_targets, source_type, error):
        return ResolutionResult(
            packages=[],
            install_target=install_target,
            resolved_versions={},
            requested_targets=requested_targets[:],
            source_type=source_type,
            resolution_succeeded=False,
            resolution_error=error,
        )

    @staticmethod
    def _succeeded_resolution(install_target, requested_targets, source_type, resolved_versions):
        return ResolutionResult(
            packages=list(resolved_versions.keys()),
            install_target=install_target,
            resolved_versions=resolved_versions,
            requested_targets=requested_targets[:],
            source_type=source_type,
            resolution_succeeded=True,
        )

    def _resolve_via_npm_registry(self, package_targets: list[str]) -> dict[str, str]:
        """Resolve one or more ad-hoc npm package targets (and their full
        transitive dependency tree) by shelling out to npm's own resolver in
        an isolated temp project, mirroring why PyPiEcosystem shells out to
        pip's --report for the same reason: reimplementing npm's dependency
        resolution algorithm ourselves would be complex and likely subtly
        wrong. --package-lock-only (without --dry-run, which was found to
        suppress the lockfile write entirely rather than just previewing it)
        writes a real, accurate lockfile without installing anything to disk
        -- verified directly against the real npm registry during development.
        """
        with tempfile.TemporaryDirectory(prefix="depshieldx_npm_resolve_") as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "package.json").write_text(
                json.dumps({"name": "depshieldx-resolve", "version": "0.0.0", "private": True})
            )
            result = subprocess.run(
                [
                    resolve_node_tool("npm"),
                    "install",
                    *package_targets,
                    "--package-lock-only",
                    "--no-audit",
                    "--no-fund",
                ],
                cwd=temp_dir,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "").strip()
                raise RuntimeError(f"npm could not resolve {', '.join(package_targets)}: {detail}")
            lockfile_path = temp_path / "package-lock.json"
            if not lockfile_path.exists():
                raise RuntimeError(f"npm did not produce a lockfile while resolving {', '.join(package_targets)}")
            return parse_package_lock_json(lockfile_path)

    def check_provenance(
        self,
        resolved_versions: dict[str, str],
        selected_artifacts: dict[str, list[dict]] | None = None,
        verbose: bool = False,
    ) -> dict:
        return npm_check_provenance_batch(resolved_versions, selected_artifacts=selected_artifacts, verbose=verbose)

    def selected_artifact_entries(self, resolution: ResolutionResult) -> list[tuple[str, str, dict]]:
        entries = []
        for package_name, version in resolution.resolved_versions.items():
            try:
                metadata = fetch_package_metadata(package_name)
            except Exception as exc:
                raise RuntimeError(f"could not fetch registry metadata for {package_name}@{version}: {exc}") from exc
            version_meta = (metadata.get("versions") or {}).get(version)
            if not version_meta:
                raise RuntimeError(f"registry has no metadata for {package_name}@{version}")
            dist = version_meta.get("dist") or {}
            tarball = dist.get("tarball")
            if not tarball:
                raise RuntimeError(f"registry metadata for {package_name}@{version} is missing a tarball URL")
            artifact = {
                "url": tarball,
                "filename": f"{package_name.replace('/', '-')}-{version}.tgz",
                "integrity": dist.get("integrity"),
            }
            entries.append((package_name, version, artifact))
        return entries

    def fetch_artifact(self, artifact: dict, destination: Path) -> Path:
        url = artifact["url"]
        filename = artifact["filename"]
        destination_path = destination / filename

        response = requests.get(url, timeout=30)
        response.raise_for_status()
        artifact_bytes = response.content

        integrity = (artifact.get("integrity") or "").strip()
        algorithm, _, expected_b64 = integrity.partition("-")
        hasher = {"sha512": hashlib.sha512, "sha256": hashlib.sha256, "sha1": hashlib.sha1}.get(algorithm)
        if hasher and expected_b64:
            actual_b64 = base64.b64encode(hasher(artifact_bytes).digest()).decode("ascii")
            if actual_b64 != expected_b64:
                raise RuntimeError(f"downloaded artifact integrity mismatch for {filename}")

        destination_path.write_bytes(artifact_bytes)
        return destination_path

    @contextmanager
    def host_install_command(self, resolution: ResolutionResult):
        # Unlike pip, npm doesn't install from a list of individually-downloaded
        # artifact paths -- it installs from package.json/the lockfile already on
        # disk (lockfile flow) or by re-resolving pinned name@version targets
        # against the registry itself (ad-hoc package flow). Fetching (and
        # integrity-checking) each artifact here still proves the resolved set
        # is real and intact before yielding the real install command, even
        # though the fetched files themselves aren't passed to it.
        artifact_entries = self.selected_artifact_entries(resolution)
        with tempfile.TemporaryDirectory(prefix="depshieldx_host_install_") as temp_dir:
            temp_path = Path(temp_dir)
            for _, _, artifact in artifact_entries:
                self.fetch_artifact(artifact, temp_path)
            if resolution.source_type in ("package", "packages"):
                # A bare "npm install" only reinstalls what's already in
                # package.json -- it wouldn't add a brand-new package. Pin each
                # requested target to the exact version verified above so the
                # install can't drift to a version published after the scan.
                pinned_targets = []
                for target in resolution.requested_targets:
                    name = _strip_version_spec(target, "npm")
                    version = resolution.resolved_versions.get(name)
                    pinned_targets.append(f"{name}@{version}" if version else target)
                yield [resolve_node_tool("npm"), "install", *pinned_targets]
            else:
                yield self.install_command([])

    def install_command(self, artifact_paths: list[str]) -> list[str]:
        return [resolve_node_tool("npm"), "install"]

    def uninstall_command(self, package_names: list[str]) -> list[str]:
        return [resolve_node_tool("npm"), "uninstall", *package_names]


NPM_ECOSYSTEM = NpmEcosystem()

ECOSYSTEMS: dict[str, Ecosystem] = {
    PYPI_ECOSYSTEM.name: PYPI_ECOSYSTEM,
    NPM_ECOSYSTEM.name: NPM_ECOSYSTEM,
}


def ecosystem_for_name(name: str) -> Ecosystem:
    try:
        return ECOSYSTEMS[name]
    except KeyError:
        raise ValueError(f"unknown ecosystem: {name!r} (known: {sorted(ECOSYSTEMS)})") from None
