"""The Pub/Dart-Flutter ecosystem adapter.

Provenance combines a real cryptographic checksum check (the registry's
own reported SHA-256 of the exact archive bytes served, verified against
a fresh download) with structural signals (discontinued packages,
retracted versions) -- pub.dev has no Sigstore/PGP/X.509 signing scheme
of its own, so there's no cryptographic-signature-presence layer the way
Maven's/NuGet's provenance has; see registry.py's module docstring for
the full reasoning.

"Install" means `dart pub add` -- adding the package(s) to the project's
real pubspec.yaml/pubspec.lock, the same "install means edit my real
project" framing CargoEcosystem/GoEcosystem/NuGetEcosystem already use,
not PyPiEcosystem's "prime a shared cache" one. Unlike NuGet's `dotnet
add package` (confirmed directly to accept only one package per
invocation), `dart pub add foo bar baz` accepts any number of packages in
one call (confirmed directly), and promotes an already-transitive
dependency to direct correctly when also named explicitly (confirmed
directly: adding a package already resolved transitively updates its
pubspec.yaml entry from absent to "from transitive dependency to direct
dependency" rather than erroring) -- so, mirroring CargoEcosystem's
host_install_command exactly rather than NuGetEcosystem's single-target
one, every resolved package here (transitive included) is pinned as a
direct dependency in one `dart pub add` call, eliminating the
scan-to-install drift window NuGet's own narrower guarantee can't fully
close.

`dart pub add name@version` (bare version, no caret) writes an *exact*
version constraint to pubspec.yaml -- confirmed directly (`http: 1.5.0`,
not `http: ^1.5.0`) -- the same "bare version = exact pin" convention
Cargo's `=`-prefixed exact-version operator and npm's plain `name@version`
already give this codebase.

dart itself is a separate toolchain -- like cargo/go/maven/dotnet, this
has nothing to do with depshieldx's own frozen/non-frozen state, so
runtime.py's Python interpreter resolution doesn't apply here, only PATH
resolution (see resolve_dart_tool). Only the standalone Dart SDK is
required, not the full Flutter SDK -- confirmed directly `dart pub
get`/`dart pub add`/`dart pub remove` all work identically against a bare
Dart SDK install for hosted (pub.dev) dependencies, since `flutter pub`
is the same underlying pub client with extra Flutter-specific tooling
layered on top that this adapter's scan/install flow never needs.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

import requests

from .lockfiles import direct_dependency_names, parse_pubspec_lock
from .registry import (
    PUB_USER_AGENT,
    check_provenance_batch as pub_check_provenance_batch,
    fetch_package_data,
    find_version_info,
    latest_version,
)
from ...core.resolver import ResolutionResult
from ...core.runtime import subprocess_env

# A broad, standard Dart 3.x environment constraint -- confirmed directly
# real, current Dart SDKs (3.13.1 during development) satisfy it, and
# real published packages commonly declare a similarly wide range rather
# than pinning to one exact SDK patch. Unlike NuGet's TargetFramework
# (where resolution genuinely can differ by target framework), Pub has no
# equivalent multi-targeting axis for hosted dependency resolution, so
# there's no analogous need to pin an exact single value the way NuGet's
# adapter deliberately does.
_SCRATCH_SDK_CONSTRAINT = ">=3.0.0 <4.0.0"
_SCRATCH_PROJECT_NAME = "depshieldx_resolve"


def resolve_dart_tool(name: str) -> str:
    """Resolve a dart-toolchain binary via PATH. Mirrors ecosystems/
    nuget/ecosystem.py's resolve_dotnet_tool -- dart ships as a real,
    directly-executable binary on every platform, so shutil.which() is
    the correct portable PATH lookup here too."""
    resolved = shutil.which(name)
    if not resolved:
        raise RuntimeError(f"{name!r} was not found on PATH. Install the Dart SDK to use the pub ecosystem.")
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
    """"http@1.6.0" -> ("http", "1.6.0"); a bare "http" (no version) is
    resolved to its latest stable release via pub.dev's own package API
    (registry.py's latest_version, confirmed directly against real
    pub.dev data) -- unlike cargo add/go get, the scratch pubspec.yaml
    this adapter writes needs an already-known version, it doesn't do
    "give me whatever's latest" resolution itself the way cargo/go's
    tools do against a bare manifest entry."""
    package_name, _, version = target.partition("@")
    package_name = package_name.strip()
    version = version.strip()
    if not package_name:
        raise RuntimeError(f"{target!r} is not a valid Pub package target -- expected package_name[@version]")
    if not version:
        version = latest_version(package_name)
        if not version:
            raise RuntimeError(
                f"could not determine the latest version of {package_name} -- pass an explicit {package_name}@version"
            )
    return package_name, version


def _build_scratch_pubspec(packages: list[tuple[str, str]]) -> str:
    dependencies = "\n".join(f'  {name}: "{version}"' for name, version in packages)
    return (
        f"name: {_SCRATCH_PROJECT_NAME}\n"
        "environment:\n"
        f"  sdk: '{_SCRATCH_SDK_CONSTRAINT}'\n"
        "dependencies:\n"
        f"{dependencies}\n"
    )


class PubEcosystem:
    """The Pub/Dart-Flutter ecosystem adapter."""

    name = "pub"
    cve_ecosystem_name = "Pub"
    lockfile_patterns = ("pubspec.lock",)

    def resolve(
        self,
        manager_args: list[str],
        requested_targets: list[str],
        install_target: str,
        source_type: str = "package",
    ) -> ResolutionResult:
        if source_type == "lockfile" and requested_targets:
            try:
                resolved_versions = parse_pubspec_lock(requested_targets[0])
            except Exception as exc:
                return self._failed_resolution(install_target, requested_targets, source_type, str(exc))
            return self._succeeded_resolution(install_target, requested_targets, source_type, resolved_versions)

        if source_type in ("package", "packages") and requested_targets:
            try:
                resolved_versions = self._resolve_via_scratch_pub(requested_targets)
            except Exception as exc:
                return self._failed_resolution(install_target, requested_targets, source_type, str(exc))
            return self._succeeded_resolution(install_target, requested_targets, source_type, resolved_versions)

        return self._failed_resolution(
            install_target,
            requested_targets,
            source_type,
            "pub resolution supports a pubspec.lock lockfile or one or more package_name[@version] targets",
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

    def _resolve_via_scratch_pub(self, package_targets: list[str]) -> dict[str, str]:
        """Resolve one or more ad-hoc package targets (and their full
        transitive dependency graph) by shelling out to dart's own
        resolver against a scratch pubspec.yaml, mirroring
        CargoEcosystem/GoEcosystem/MavenEcosystem/NuGetEcosystem's own
        scratch-project resolve flow -- reimplementing Pub's dependency
        resolution ourselves would be complex and likely subtly wrong.
        """
        direct_packages = [_normalize_target_package(target) for target in package_targets]
        with tempfile.TemporaryDirectory(prefix="depshieldx_pub_resolve_") as temp_dir:
            pubspec_path = Path(temp_dir) / "pubspec.yaml"
            pubspec_path.write_text(_build_scratch_pubspec(direct_packages), encoding="utf-8")

            result = _run([resolve_dart_tool("dart"), "pub", "get"], cwd=temp_dir)
            if result.returncode != 0:
                raise RuntimeError(_command_error(result, f"dart pub could not resolve {', '.join(package_targets)}"))

            lockfile_path = Path(temp_dir) / "pubspec.lock"
            if not lockfile_path.exists():
                raise RuntimeError(f"dart pub did not produce a lock file while resolving {', '.join(package_targets)}")
            return parse_pubspec_lock(str(lockfile_path))

    def check_provenance(
        self,
        resolved_versions: dict[str, str],
        selected_artifacts: dict[str, list[dict]] | None = None,
        verbose: bool = False,
    ) -> dict:
        return pub_check_provenance_batch(resolved_versions, selected_artifacts=selected_artifacts, verbose=verbose)

    def selected_artifact_entries(self, resolution: ResolutionResult) -> list[tuple[str, str, dict]]:
        entries = []
        for package_name, version in resolution.resolved_versions.items():
            try:
                package_data = fetch_package_data(package_name)
            except Exception as exc:
                raise RuntimeError(f"could not fetch registry metadata for {package_name}@{version}: {exc}") from exc

            version_info = find_version_info(package_data, version) or {}
            artifact = {
                "url": version_info.get("archive_url"),
                "filename": f"{package_name}-{version}.tar.gz",
                "checksum_algorithm": "sha256" if version_info.get("archive_sha256") else None,
                "checksum": version_info.get("archive_sha256"),
            }
            entries.append((package_name, version, artifact))
        return entries

    def fetch_artifact(self, artifact: dict, destination: Path) -> Path:
        url = artifact.get("url")
        filename = artifact["filename"]
        destination_path = destination / filename
        if not url:
            raise RuntimeError(f"no registry-published archive URL available to fetch {filename}")

        response = requests.get(url, headers={"User-Agent": PUB_USER_AGENT}, timeout=60)
        response.raise_for_status()
        artifact_bytes = response.content

        algorithm = artifact.get("checksum_algorithm")
        expected_checksum = (artifact.get("checksum") or "").strip()
        if not (algorithm and expected_checksum):
            # pub.dev publishes archive_sha256 for every real published
            # version (confirmed directly) -- an unexpectedly missing
            # checksum here is itself an anomaly worth refusing on, the
            # same way a real mismatch already is below, rather than
            # silently writing unverified bytes to disk with no signal
            # at all.
            raise RuntimeError(
                f"no registry-published checksum available to verify {filename} -- refusing to trust it unverified"
            )
        actual_checksum = hashlib.new(algorithm, artifact_bytes).hexdigest()
        if actual_checksum != expected_checksum:
            raise RuntimeError(f"downloaded artifact checksum mismatch for {filename}")

        destination_path.write_bytes(artifact_bytes)
        return destination_path

    @contextmanager
    def host_install_command(self, resolution: ResolutionResult):
        # Fetching each artifact here (via fetch_artifact, which itself
        # checksum-verifies and raises on any mismatch or missing hash)
        # still proves the resolved set is real, fetchable, and verified
        # before yielding the real install command.
        artifact_entries = self.selected_artifact_entries(resolution)
        with tempfile.TemporaryDirectory(prefix="depshieldx_host_install_") as temp_dir:
            temp_path = Path(temp_dir)
            for _, _, artifact in artifact_entries:
                self.fetch_artifact(artifact, temp_path)

            if resolution.source_type in ("package", "packages"):
                # Unlike NuGetEcosystem (limited to one package per
                # `dotnet add package` invocation), `dart pub add`
                # accepts any number of packages in one call (confirmed
                # directly) -- every resolved package here, transitive
                # included, is pinned as a direct dependency, the same
                # "eliminate scan-to-install drift entirely" guarantee
                # CargoEcosystem/GoEcosystem already provide. See module
                # docstring.
                pinned_targets = [f"{name}@{version}" for name, version in resolution.resolved_versions.items()]
                yield [resolve_dart_tool("dart"), "pub", "add", *pinned_targets]
            else:
                yield self.install_command([])

    def install_command(self, artifact_paths: list[str]) -> list[str]:
        # Resolves against an existing pubspec.lock, failing rather than
        # silently drifting if pubspec.yaml's constraints would require a
        # different resolution or if any hosted package's content hash
        # has changed -- confirmed directly this is real dart tooling
        # (--enforce-lockfile), the same "fail closed if the lock can't
        # be honored exactly" guarantee `dotnet restore --locked-mode`/
        # `cargo fetch --locked` already give. Compilation is out of
        # scope for fast-mode install either way; deep mode's future
        # behavioral tracing is where that would happen.
        return [resolve_dart_tool("dart"), "pub", "get", "--enforce-lockfile"]

    def uninstall_command(self, package_names: list[str]) -> list[str]:
        return [resolve_dart_tool("dart"), "pub", "remove", *package_names]

    def direct_dependency_names_for_lockfile(self, lockfile_path: str) -> list[str]:
        return direct_dependency_names(lockfile_path)


PUB_ECOSYSTEM = PubEcosystem()
