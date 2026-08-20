"""The RubyGems/Bundler ecosystem adapter.

Provenance combines a real cryptographic checksum check (the registry's
own reported SHA-256 of the exact .gem file bytes served, verified
against a fresh download) with a structural yank signal -- rubygems.org
has no default, always-present cryptographic signing scheme of its own
(Sigstore support is still opt-in/in-progress, the older X.509 `gem cert`
scheme is opt-in and rarely used), so there's no signature-presence layer
the way Maven's/NuGet's provenance has; see registry.py's module
docstring for the full reasoning, including the yank-detection design
this module is built around.

"Install" means `bundle add` -- adding the gem(s) to the project's real
Gemfile/Gemfile.lock, the same "install means edit my real project"
framing CargoEcosystem/GoEcosystem/PubEcosystem already use. Unlike those
tools' own "name@version" per-target syntax, `bundle add gem1 gem2
--version X` applies ONE shared version constraint to *every* named gem
in the call (confirmed directly) -- there's no way to pin more than one
independently-resolved exact version in a single invocation. Since every
resolved gem (transitive included) needs pinning for the same drift-
prevention reasons as Cargo/Go/Pub's own host_install_command, this loops
one real `bundle add <gem> --version <v>` call per resolved gem instead
(confirmed directly this works cleanly with no conflicts, correctly
accumulating into the same real Gemfile/Gemfile.lock across repeated
calls) -- see host_install_command's own comment for why this can't just
mirror MavenEcosystem's scratch-manifest workaround instead (`bundle add`
is Cargo/Pub's "edit my real project" verb, not Maven's "resolve into a
shared, detached local repository" one).

`bundle add <gem> --version X` (bare version, no "~>") writes an *exact*
version constraint to the Gemfile -- confirmed directly (`gem "rack",
"3.2.7"`, not `gem "rack", "~> 3.2.7"`) -- the same "bare version = exact
pin" convention Cargo's `=`-prefixed operator/npm's/Pub's plain
"name@version" already give this codebase.

Ruby/Bundler is a separate toolchain -- like cargo/go/dart, this has
nothing to do with depshieldx's own frozen/non-frozen state, so
runtime.py's Python interpreter resolution doesn't apply here, only PATH
resolution (see resolve_bundle_tool). `bundle` (not the lower-level `gem`
command) is used throughout, mirroring how Cargo/Go/Dart's own dependency-
manager-level tool (not a lower-level primitive) is what every other
adapter here shells out to.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

import requests

from .lockfiles import direct_dependency_names, parse_gemfile_lock
from .registry import (
    RUBYGEMS_USER_AGENT,
    check_provenance_batch as rubygems_check_provenance_batch,
    fetch_version_data,
    latest_version,
)
from ...core.resolver import ResolutionResult

_SCRATCH_GEMFILE_NAME = "Gemfile"


def resolve_bundle_tool(name: str) -> str:
    """Resolve a bundle-toolchain binary via PATH. Mirrors ecosystems/
    pub/ecosystem.py's resolve_dart_tool -- bundle ships as a real,
    directly-executable binary/shim on every platform once Ruby (with
    Bundler, a default gem on modern Ruby installs) is installed, so
    shutil.which() is the correct portable PATH lookup here too."""
    resolved = shutil.which(name)
    if not resolved:
        raise RuntimeError(f"{name!r} was not found on PATH. Install Ruby (with Bundler) to use the rubygems ecosystem.")
    return resolved


def _run(args: list[str], cwd: str) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


def _command_error(result: subprocess.CompletedProcess, action: str) -> str:
    detail = (result.stderr or result.stdout or "").strip()
    return f"{action}: {detail}" if detail else action


def _normalize_target_package(target: str) -> tuple[str, str]:
    """"rack@3.2.7" -> ("rack", "3.2.7"); a bare "rack" (no version) is
    resolved to its latest release via rubygems.org's own gem API
    (registry.py's latest_version, confirmed directly against real
    rubygems.org data) -- unlike cargo add/go get, the scratch Gemfile
    this adapter locks needs an already-known version, it doesn't do
    "give me whatever's latest" resolution itself the way cargo/go's
    tools do against a bare manifest entry."""
    package_name, _, version = target.partition("@")
    package_name = package_name.strip()
    version = version.strip()
    if not package_name:
        raise RuntimeError(f"{target!r} is not a valid RubyGems package target -- expected package_name[@version]")
    if not version:
        version = latest_version(package_name)
        if not version:
            raise RuntimeError(
                f"could not determine the latest version of {package_name} -- pass an explicit {package_name}@version"
            )
    return package_name, version


def _build_scratch_gemfile(packages: list[tuple[str, str]]) -> str:
    lines = ['source "https://rubygems.org"']
    for name, version in packages:
        lines.append(f'gem "{name}", "{version}"')
    return "\n".join(lines) + "\n"


class RubyGemsEcosystem:
    """The RubyGems/Bundler ecosystem adapter."""

    name = "rubygems"
    cve_ecosystem_name = "RubyGems"
    lockfile_patterns = ("Gemfile.lock",)

    def resolve(
        self,
        manager_args: list[str],
        requested_targets: list[str],
        install_target: str,
        source_type: str = "package",
    ) -> ResolutionResult:
        if source_type == "lockfile" and requested_targets:
            try:
                resolved_versions = parse_gemfile_lock(requested_targets[0])
            except Exception as exc:
                return self._failed_resolution(install_target, requested_targets, source_type, str(exc))
            return self._succeeded_resolution(install_target, requested_targets, source_type, resolved_versions)

        if source_type in ("package", "packages") and requested_targets:
            try:
                resolved_versions = self._resolve_via_scratch_bundle(requested_targets)
            except Exception as exc:
                return self._failed_resolution(install_target, requested_targets, source_type, str(exc))
            return self._succeeded_resolution(install_target, requested_targets, source_type, resolved_versions)

        return self._failed_resolution(
            install_target,
            requested_targets,
            source_type,
            "rubygems resolution supports a Gemfile.lock lockfile or one or more package_name[@version] targets",
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

    def _resolve_via_scratch_bundle(self, package_targets: list[str]) -> dict[str, str]:
        """Resolve one or more ad-hoc package targets (and their full
        transitive dependency graph) by shelling out to bundle's own
        resolver against a scratch Gemfile, mirroring CargoEcosystem/
        GoEcosystem/PubEcosystem's own scratch-project resolve flow --
        reimplementing Bundler's dependency resolution ourselves would be
        complex and likely subtly wrong."""
        direct_packages = [_normalize_target_package(target) for target in package_targets]
        with tempfile.TemporaryDirectory(prefix="depshieldx_rubygems_resolve_") as temp_dir:
            gemfile_path = Path(temp_dir) / _SCRATCH_GEMFILE_NAME
            gemfile_path.write_text(_build_scratch_gemfile(direct_packages), encoding="utf-8")

            result = _run([resolve_bundle_tool("bundle"), "lock"], cwd=temp_dir)
            if result.returncode != 0:
                raise RuntimeError(_command_error(result, f"bundle could not resolve {', '.join(package_targets)}"))

            lockfile_path = Path(temp_dir) / "Gemfile.lock"
            if not lockfile_path.exists():
                raise RuntimeError(f"bundle did not produce a lock file while resolving {', '.join(package_targets)}")
            return parse_gemfile_lock(str(lockfile_path))

    def check_provenance(
        self,
        resolved_versions: dict[str, str],
        selected_artifacts: dict[str, list[dict]] | None = None,
        verbose: bool = False,
    ) -> dict:
        return rubygems_check_provenance_batch(resolved_versions, selected_artifacts=selected_artifacts, verbose=verbose)

    def selected_artifact_entries(self, resolution: ResolutionResult) -> list[tuple[str, str, dict]]:
        entries = []
        for package_name, version in resolution.resolved_versions.items():
            try:
                version_data = fetch_version_data(package_name, version)
            except Exception as exc:
                raise RuntimeError(f"could not fetch registry metadata for {package_name}@{version}: {exc}") from exc

            artifact = {
                "url": version_data.get("gem_uri"),
                "filename": f"{package_name}-{version}.gem",
                "checksum_algorithm": "sha256" if version_data.get("sha") else None,
                "checksum": version_data.get("sha"),
            }
            entries.append((package_name, version, artifact))
        return entries

    def fetch_artifact(self, artifact: dict, destination: Path) -> Path:
        url = artifact.get("url")
        filename = artifact["filename"]
        destination_path = destination / filename
        if not url:
            raise RuntimeError(f"no registry-published archive URL available to fetch {filename}")

        response = requests.get(url, headers={"User-Agent": RUBYGEMS_USER_AGENT}, timeout=60)
        response.raise_for_status()
        artifact_bytes = response.content

        algorithm = artifact.get("checksum_algorithm")
        expected_checksum = (artifact.get("checksum") or "").strip()
        if not (algorithm and expected_checksum):
            # rubygems.org publishes a sha256 for every real published
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
        # before running/yielding any real install command.
        artifact_entries = self.selected_artifact_entries(resolution)
        with tempfile.TemporaryDirectory(prefix="depshieldx_host_install_") as temp_dir:
            temp_path = Path(temp_dir)
            for _, _, artifact in artifact_entries:
                self.fetch_artifact(artifact, temp_path)

            if resolution.source_type in ("package", "packages"):
                # See module docstring: `bundle add` can't pin more than
                # one independently-resolved exact version in a single
                # call, unlike cargo/go/pub's own multi-target syntax.
                # This can't reuse MavenEcosystem's scratch-manifest
                # workaround either -- `dependency:resolve` there only
                # ever downloads into a shared, detached local repository
                # (~/.m2), never touching a real project file, so a
                # scratch pom is fine; `bundle add` is Cargo/Pub's own
                # "edit my real project" verb, so it has to run in the
                # caller's actual directory against the real Gemfile, not
                # a detached scratch one. All but the last resolved gem
                # are added here as a real, checked side effect (mirroring
                # fetch_artifact's own verify-before-yield pattern above);
                # only the final `bundle add` is yielded, so the caller's
                # normal command-echoing/error-reporting still applies to
                # at least one real, visible invocation -- confirmed
                # directly that looping single-gem `bundle add <gem>
                # --version <v>` calls this way works cleanly with no
                # conflicts, correctly accumulating into the same real
                # Gemfile/Gemfile.lock across repeated calls.
                pending = list(resolution.resolved_versions.items())
                for name, version in pending[:-1]:
                    command = [resolve_bundle_tool("bundle"), "add", name, "--version", version]
                    result = subprocess.run(command, capture_output=True, text=True)
                    if result.returncode != 0:
                        raise RuntimeError(_command_error(result, f"bundle add could not pin {name}@{version}"))
                last_name, last_version = pending[-1]
                yield [resolve_bundle_tool("bundle"), "add", last_name, "--version", last_version]
            else:
                yield self.install_command([])

    def install_command(self, artifact_paths: list[str]) -> list[str]:
        # `bundle install` has no direct CLI flag equivalent to `cargo
        # fetch --locked`/`dotnet restore --locked-mode`/`dart pub get
        # --enforce-lockfile` in this Bundler version -- confirmed
        # directly against a real `bundle install --help` (no such flag
        # in its SYNOPSIS). "frozen" mode (fail rather than silently
        # update Gemfile.lock when it can't be honored exactly) is
        # instead a persistent local-config setting next to the Gemfile
        # (`.bundle/config`) -- confirmed directly that `bundle config
        # set frozen true` followed by `bundle install` produces a hard
        # failure instead of a silent lockfile update (e.g. when the
        # current platform isn't already recorded in the lockfile's
        # PLATFORMS list). Setting it here is a real, idempotent side
        # effect (just rewrites the same local config value on repeat
        # calls) -- the same "fail closed if the lock can't be honored
        # exactly" guarantee every other ecosystem's install_command
        # already gives, just reached via config instead of a flag.
        # Compilation/native-extension `extconf.rb` execution is
        # deliberately out of scope for fast-mode install either way;
        # deep mode's future behavioral tracing is where that would
        # happen.
        subprocess.run(
            [resolve_bundle_tool("bundle"), "config", "set", "frozen", "true"],
            capture_output=True,
            text=True,
        )
        return [resolve_bundle_tool("bundle"), "install"]

    def uninstall_command(self, package_names: list[str]) -> list[str]:
        return [resolve_bundle_tool("bundle"), "remove", *package_names]

    def direct_dependency_names_for_lockfile(self, lockfile_path: str) -> list[str]:
        return direct_dependency_names(lockfile_path)


RUBYGEMS_ECOSYSTEM = RubyGemsEcosystem()
