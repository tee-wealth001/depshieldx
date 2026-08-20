"""The NuGet/.NET ecosystem adapter.

Provenance combines a real cryptographic checksum check (the registry's
own reported SHA-512 of the exact bytes served, verified against a fresh
download) with structural signals (unlisted status, deprecation) --
NuGet.org repository-signs every package, but with an X.509/Authenticode
signature chain this codebase has no trust-root/chain-validation story
for anywhere else, so that's recorded as presence only -- see
nuget_registry.py's module docstring for the full reasoning.

"Install" means `dotnet add package` -- adding the package to your
project's real .csproj (and, if it opts into one, packages.lock.json) --
mirroring CargoEcosystem/GoEcosystem's "install means edit my real
project", not PyPiEcosystem's "prime a shared cache" framing. Real,
confirmed-directly constraint this adapter's host_install_command has
that cargo's/go's don't: `dotnet add package` only accepts ONE package
name per invocation (confirmed directly -- passing multiple names is a
CLI usage error), unlike `cargo add crate1 crate2`/`go get mod1 mod2`.
Rather than risk hand-editing an arbitrary real .csproj's XML directly to
work around that (a real, structurally complex file this codebase can't
safely round-trip for every real-world shape), host installs here are
scoped to exactly one originally-requested target -- a real, honestly
documented limitation, not a silent behavior change, mirroring this
codebase's own precedent for MavenEcosystem's uninstall_command.
Multi-target *scanning* has no such limit: resolve() computes the full
transitive graph for any number of targets via a scratch .csproj
(verified directly this restores multiple pinned PackageReference
entries correctly in one `dotnet restore`), the same scratch-project
pattern CargoEcosystem/GoEcosystem/MavenEcosystem all use.

A real, accepted consequence of delegating the single-target host
install to `dotnet add package` rather than pinning the full resolved
set: only the top-level target is pinned exactly; its *transitive*
dependencies are resolved fresh by NuGet's own resolver at install
time, not forced to the exact versions selected_artifact_entries()
fetched during the scan. Cargo/Go/Maven's host_install_command
eliminates this drift entirely by pinning every resolved package --
transitive included -- as a direct dependency; that guarantee doesn't
carry over here, since `dotnet add package` has no equivalent "pin this
whole graph" input. In practice this window is narrow (nuget.org
packages are immutable once published -- a transitive dependency's
already-resolved version can't change retroactively, only a *newer*
version could have been published in the interim), but it's a real,
narrower guarantee than the other three ecosystems provide, not
identical to them.

dotnet itself is a separate toolchain -- like cargo/go/maven, this has
nothing to do with depshieldx's own frozen/non-frozen state, so
runtime.py's Python interpreter resolution doesn't apply here, only PATH
resolution (see resolve_dotnet_tool).
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from xml.sax.saxutils import escape as _xml_escape

import requests

from .lockfiles import parse_packages_lock
from .registry import (
    NUGET_USER_AGENT,
    check_provenance_batch as nuget_check_provenance_batch,
    fetch_catalog_entry,
    flat_container_nupkg_url,
    search_latest_version,
)
from ...core.resolver import ResolutionResult
from ...core.runtime import subprocess_env

# Current .NET LTS target framework (Long Term Support, supported through
# Nov 2026, confirmed directly against Microsoft's own .NET support
# policy page) -- fixed rather than left to whatever TFM the ambient
# installed SDK defaults new projects to, since dependency resolution can
# genuinely differ by target framework (some packages ship framework-
# conditional dependencies), and depshieldx's own resolve/install
# behavior shouldn't silently vary by whichever dotnet SDK version
# happens to be on a given host's PATH.
_SCRATCH_TARGET_FRAMEWORK = "net8.0"
_SCRATCH_PROJECT_NAME = "depshieldx-resolve"


def resolve_dotnet_tool(name: str) -> str:
    """Resolve a dotnet-toolchain binary via PATH. Mirrors ecosystems/
    maven.py's resolve_maven_tool -- dotnet ships as a real, directly-
    executable binary on every platform, so shutil.which() is the
    correct portable PATH lookup here too."""
    resolved = shutil.which(name)
    if not resolved:
        raise RuntimeError(f"{name!r} was not found on PATH. Install the .NET SDK to use the nuget ecosystem.")
    return resolved


def _run(args: list[str], cwd: str) -> subprocess.CompletedProcess:
    # env=subprocess_env() strips sys._MEIPASS back out of PATH before an
    # external toolchain subprocess inherits it -- see core/runtime.py's
    # module docstring for the real, confirmed DLL-resolution conflict
    # this prevents.
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, env=subprocess_env())


def _command_error(result: subprocess.CompletedProcess, action: str) -> str:
    detail = (result.stderr or result.stdout or "").strip()
    return f"{action}: {detail}" if detail else action


def _normalize_target_package(target: str) -> tuple[str, str]:
    """"Newtonsoft.Json@13.0.3" -> ("Newtonsoft.Json", "13.0.3"); a bare
    "Newtonsoft.Json" (no version) is resolved to its latest stable
    release via NuGet's own search API (registry.py's
    search_latest_version, confirmed directly against real nuget.org
    data) -- unlike cargo add/go get, NuGet's own restore machinery
    needs an already-known version constraint, it doesn't do "give me
    whatever's latest" resolution itself the way cargo/go's tools do."""
    package_id, _, version = target.partition("@")
    package_id = package_id.strip()
    version = version.strip()
    if not package_id:
        raise RuntimeError(f"{target!r} is not a valid NuGet package target -- expected PackageId[@version]")
    if not version:
        version = search_latest_version(package_id)
        if not version:
            raise RuntimeError(f"could not determine the latest version of {package_id} -- pass an explicit {package_id}@version")
    return package_id, version


def _build_scratch_csproj(packages: list[tuple[str, str]]) -> str:
    package_references = "\n".join(
        f'    <PackageReference Include="{_xml_escape(package_id)}" Version="[{_xml_escape(version)}]" />'
        for package_id, version in packages
    )
    return (
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        "  <PropertyGroup>\n"
        f"    <TargetFramework>{_SCRATCH_TARGET_FRAMEWORK}</TargetFramework>\n"
        "    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>\n"
        "    <EnableDefaultCompileItems>false</EnableDefaultCompileItems>\n"
        "  </PropertyGroup>\n"
        "  <ItemGroup>\n"
        f"{package_references}\n"
        "  </ItemGroup>\n"
        "</Project>\n"
    )


class NuGetEcosystem:
    """The NuGet/.NET ecosystem adapter."""

    name = "nuget"
    cve_ecosystem_name = "NuGet"
    lockfile_patterns = ("packages.lock.json",)

    def resolve(
        self,
        manager_args: list[str],
        requested_targets: list[str],
        install_target: str,
        source_type: str = "package",
    ) -> ResolutionResult:
        if source_type == "lockfile" and requested_targets:
            try:
                resolved_versions = parse_packages_lock(requested_targets[0])
            except Exception as exc:
                return self._failed_resolution(install_target, requested_targets, source_type, str(exc))
            return self._succeeded_resolution(install_target, requested_targets, source_type, resolved_versions)

        if source_type in ("package", "packages") and requested_targets:
            try:
                resolved_versions = self._resolve_via_scratch_restore(requested_targets)
            except Exception as exc:
                return self._failed_resolution(install_target, requested_targets, source_type, str(exc))
            return self._succeeded_resolution(install_target, requested_targets, source_type, resolved_versions)

        return self._failed_resolution(
            install_target,
            requested_targets,
            source_type,
            "nuget resolution supports a packages.lock.json lockfile or one or more PackageId[@version] targets",
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

    def _resolve_via_scratch_restore(self, package_targets: list[str]) -> dict[str, str]:
        """Resolve one or more ad-hoc package targets (and their full
        transitive dependency graph) by shelling out to dotnet's own
        resolver against a scratch .csproj, mirroring CargoEcosystem/
        GoEcosystem/MavenEcosystem's scratch-project resolve flow --
        reimplementing NuGet's dependency resolution ourselves would be
        complex and likely subtly wrong.
        """
        direct_packages = [_normalize_target_package(target) for target in package_targets]
        with tempfile.TemporaryDirectory(prefix="depshieldx_nuget_resolve_") as temp_dir:
            csproj_path = Path(temp_dir) / f"{_SCRATCH_PROJECT_NAME}.csproj"
            csproj_path.write_bytes(_build_scratch_csproj(direct_packages).encode("utf-8"))

            result = _run([resolve_dotnet_tool("dotnet"), "restore", str(csproj_path)], cwd=temp_dir)
            if result.returncode != 0:
                raise RuntimeError(_command_error(result, f"dotnet could not resolve {', '.join(package_targets)}"))

            lockfile_path = Path(temp_dir) / "packages.lock.json"
            if not lockfile_path.exists():
                raise RuntimeError(f"dotnet did not produce a lock file while resolving {', '.join(package_targets)}")
            return parse_packages_lock(str(lockfile_path))

    def check_provenance(
        self,
        resolved_versions: dict[str, str],
        selected_artifacts: dict[str, list[dict]] | None = None,
        verbose: bool = False,
    ) -> dict:
        return nuget_check_provenance_batch(resolved_versions, selected_artifacts=selected_artifacts, verbose=verbose)

    def selected_artifact_entries(self, resolution: ResolutionResult) -> list[tuple[str, str, dict]]:
        entries = []
        for package_id, version in resolution.resolved_versions.items():
            try:
                catalog_entry = fetch_catalog_entry(package_id, version)
            except Exception as exc:
                raise RuntimeError(f"could not fetch registration metadata for {package_id}@{version}: {exc}") from exc

            artifact = {
                "url": flat_container_nupkg_url(package_id, version),
                "filename": f"{package_id}.{version}.nupkg",
                "checksum_algorithm": catalog_entry.get("packageHashAlgorithm"),
                "checksum": catalog_entry.get("packageHash"),
            }
            entries.append((package_id, version, artifact))
        return entries

    def fetch_artifact(self, artifact: dict, destination: Path) -> Path:
        url = artifact["url"]
        filename = artifact["filename"]
        destination_path = destination / filename

        response = requests.get(url, headers={"User-Agent": NUGET_USER_AGENT}, timeout=60)
        response.raise_for_status()
        artifact_bytes = response.content

        algorithm = artifact.get("checksum_algorithm")
        expected_checksum = (artifact.get("checksum") or "").strip()
        if not (algorithm and expected_checksum):
            # NuGet.org's registration API publishes a packageHash/
            # packageHashAlgorithm for every real published package
            # (confirmed directly) -- an unexpectedly missing checksum
            # here is itself an anomaly worth refusing on, the same way
            # a real mismatch already is below, rather than silently
            # writing unverified bytes to disk with no signal at all.
            raise RuntimeError(
                f"no registry-published checksum available to verify {filename} -- refusing to trust it unverified"
            )
        digest = hashlib.new(algorithm.lower(), artifact_bytes).digest()
        actual_checksum = base64.b64encode(digest).decode("ascii")
        if actual_checksum != expected_checksum:
            raise RuntimeError(f"downloaded artifact checksum mismatch for {filename}")

        destination_path.write_bytes(artifact_bytes)
        return destination_path

    @contextmanager
    def host_install_command(self, resolution: ResolutionResult):
        # Fetching each artifact here (via fetch_artifact, which itself
        # checksum-verifies and raises on any mismatch or missing hash)
        # still proves the resolved set is real, fetchable, and
        # verified before yielding the real install command.
        artifact_entries = self.selected_artifact_entries(resolution)
        with tempfile.TemporaryDirectory(prefix="depshieldx_host_install_") as temp_dir:
            temp_path = Path(temp_dir)
            for _, _, artifact in artifact_entries:
                self.fetch_artifact(artifact, temp_path)

            if resolution.source_type in ("package", "packages"):
                # See module docstring: `dotnet add package` only
                # accepts one package per invocation (confirmed
                # directly), incompatible with pinning more than one
                # resolved package -- transitive included -- the way
                # CargoEcosystem/GoEcosystem's host_install_command does.
                # Scoped to exactly one originally-requested target
                # rather than risk hand-editing an arbitrary real
                # .csproj's XML to work around it.
                if len(resolution.requested_targets) != 1:
                    raise RuntimeError(
                        "nuget host install only supports one package at a time -- "
                        "`dotnet add package` accepts a single package per invocation, "
                        "install one package per depshieldx invocation"
                    )
                package_id, version = next(iter(resolution.resolved_versions.items()))
                yield [resolve_dotnet_tool("dotnet"), "add", "package", package_id, "--version", f"[{version}]"]
            else:
                yield self.install_command([])

    def install_command(self, artifact_paths: list[str]) -> list[str]:
        # Restores every package already pinned in an existing
        # packages.lock.json without allowing it to change and without
        # compiling anything -- confirmed directly this exits 0 without
        # invoking the C# compiler. Compilation is deliberately out of
        # scope for fast-mode install; deep mode's future behavioral
        # tracing is where that would happen.
        return [resolve_dotnet_tool("dotnet"), "restore", "--locked-mode"]

    def uninstall_command(self, package_names: list[str]) -> list[str]:
        if len(package_names) != 1:
            raise RuntimeError(
                "nuget uninstall only supports one package at a time -- "
                "`dotnet remove package` accepts a single package per invocation"
            )
        return [resolve_dotnet_tool("dotnet"), "remove", "package", package_names[0]]

    def direct_dependency_names_for_lockfile(self, lockfile_path: str) -> list[str]:
        """The package names a user would expect `depshieldx uninstall
        --lockfile packages.lock.json ...` to remove: packages recorded
        with "type": "Direct" in the lock file, not every transitively-
        resolved package it also lists -- confirmed directly this field
        is how a real packages.lock.json distinguishes the two, no
        separate manifest (.csproj) read needed the way Cargo.toml/
        go.mod are for their own ecosystems."""
        payload = json.loads(Path(lockfile_path).read_text(encoding="utf-8"))
        dependencies_by_framework = payload.get("dependencies") or {}
        names = []
        seen = set()
        for framework_entries in dependencies_by_framework.values():
            for package_id, entry in framework_entries.items():
                if entry.get("type") == "Direct" and package_id not in seen:
                    seen.add(package_id)
                    names.append(package_id)
        return names


NUGET_ECOSYSTEM = NuGetEcosystem()
