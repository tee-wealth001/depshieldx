"""The npm/yarn/pnpm ecosystem adapter (Phase 1, fast mode)."""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

import requests

from ..npm_lockfiles import parse_lockfile, parse_package_lock_json
from ..npm_registry import check_provenance_batch as npm_check_provenance_batch, fetch_package_metadata
from ..resolver import ResolutionResult
from .base import _strip_version_spec


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

    def direct_dependency_names_for_lockfile(self, lockfile_path: str) -> list[str]:
        """The names a user would expect `depshieldx uninstall --lockfile ...`
        to remove: the packages actually declared in package.json, not every
        transitively-resolved name the lockfile also lists.

        None of the three lockfile formats package_lockfiles.py parses
        reliably distinguish direct from transitive dependencies on their
        own -- package-lock.json's root "" entry does, but yarn.lock (a
        flat, format-agnostic listing) and pnpm-lock.yaml's "packages" map
        don't. package.json's own "dependencies"/"devDependencies" keys are
        the one source of truth all three package managers agree on, and
        it's the file real npm/yarn/pnpm "uninstall"/"remove" commands
        themselves update -- so read that instead of trying to infer
        directness per lockfile format.
        """
        package_json_path = Path(lockfile_path).parent / "package.json"
        if not package_json_path.exists():
            raise RuntimeError(
                f"no package.json found next to {lockfile_path} -- can't determine which "
                "packages are direct dependencies to uninstall"
            )
        manifest = json.loads(package_json_path.read_text(encoding="utf-8"))
        names = []
        seen = set()
        for section in ("dependencies", "devDependencies"):
            for name in (manifest.get(section) or {}):
                if name not in seen:
                    seen.add(name)
                    names.append(name)
        return names


NPM_ECOSYSTEM = NpmEcosystem()
