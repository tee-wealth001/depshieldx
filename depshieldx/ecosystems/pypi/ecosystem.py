"""The Python/pip ecosystem adapter.

PyPiEcosystem wraps the existing, already-tested resolver/provenance/
artifact-fetch logic rather than rewriting it -- the seam is the new part,
not the underlying behavior.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import unquote, urlparse
from urllib.request import url2pathname

import requests

from ...security.provenance import check_provenance_batch
from ...core.resolver import ResolutionResult, resolve_dependencies, resolve_install_inputs
from ...core.runtime import pip_command
from ..base import _normalize_pypi_name


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
