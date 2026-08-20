"""The Composer/Packagist (PHP) ecosystem adapter.

Provenance is the weakest of any ecosystem here, and honestly so: no
cryptographic checksum verification in the common case (Packagist's own
`dist.shasum` is empty for the overwhelming majority of real packages --
see registry.py's module docstring), no signing scheme of any kind. The
real, always-present content pin is the git `reference` (commit SHA)
Packagist records for the resolved dist archive -- the closest analogue
to a checksum this ecosystem has. Structural signal: Packagist's own
`abandoned` field (package-level, confirmed directly against a real
abandoned package -- swiftmailer/swiftmailer reports `"abandoned":
"symfony/mailer"`, a string naming the replacement, not just a boolean).

"Install" means `composer require` -- adding the package(s) to the
project's real composer.json/composer.lock, the same "install means edit
my real project" framing CargoEcosystem/GoEcosystem/PubEcosystem/
RubyGemsEcosystem already use. Unlike RubyGems' `bundle add` (one shared
--version across every named gem in a call, confirmed directly), a real
`composer require pkg1:v1 pkg2:v2 ...` accepts any number of packages in
one call, each with its own independent exact version pin via colon
syntax (confirmed directly) -- so, mirroring CargoEcosystem's/
GoEcosystem's/PubEcosystem's own host_install_command exactly rather
than RubyGemsEcosystem's per-package-call workaround, every resolved
package here (transitive included) is pinned as a direct dependency in
one `composer require` call.

Composer has a real, confirmed-directly built-in safety mechanism this
adapter deliberately leans on rather than works around: as of Composer
2.2+, installing any package containing a Composer plugin (a real,
significant code-execution surface -- a "composer-plugin"-type package
registers a PHP class Composer instantiates and calls automatically) is
*blocked by default* unless explicitly allow-listed in the project's own
`config.allow-plugins` -- confirmed directly with a real, common plugin
package (composer/installers): a plain `composer require` without any
extra flag raises `PluginBlockedException` rather than silently
activating it. `--no-plugins`/`--no-scripts` are passed explicitly
anyway throughout this module as defense in depth (the same "cheap,
explicit, documented-intent" reasoning ecosystems/pub/ecosystem.py's own
`--suppress-analytics` flag already uses), not because either flag was
observed to change the outcome for a plain scratch resolve.

`composer` itself is a separate toolchain -- like cargo/go/dart/bundle,
this has nothing to do with depshieldx's own frozen/non-frozen state, so
runtime.py's Python interpreter resolution doesn't apply here, only PATH
resolution (see resolve_composer_tool). On Windows, `composer` ships as
a `.bat` shim (confirmed directly against a real Windows Composer
install, the same PATHEXT-search gap `resolve_node_tool`'s own docstring
documents for npm's `.cmd` shim), so `shutil.which()` -- not a bare
subprocess call -- is required here too.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

import requests

from .lockfiles import parse_composer_lock
from .registry import (
    PACKAGIST_USER_AGENT,
    check_provenance_batch as composer_check_provenance_batch,
    fetch_package_data,
    find_version_info,
)
from ...core.resolver import ResolutionResult

_SCRATCH_PACKAGE_NAME = "depshieldx/scratch-resolve"


def resolve_composer_tool(name: str) -> str:
    """Resolve a composer-toolchain binary via PATH. Mirrors ecosystems/
    npm/ecosystem.py's resolve_node_tool -- confirmed directly composer
    ships as a real `.bat` shim on Windows (not a bare `composer.exe`),
    so shutil.which() is the correct portable PATH lookup here too."""
    resolved = shutil.which(name)
    if not resolved:
        raise RuntimeError(f"{name!r} was not found on PATH. Install PHP + Composer to use the composer ecosystem.")
    return resolved


def _run(args: list[str], cwd: str) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


def _command_error(result: subprocess.CompletedProcess, action: str) -> str:
    detail = (result.stderr or result.stdout or "").strip()
    return f"{action}: {detail}" if detail else action


def _normalize_target_package(target: str) -> tuple[str, str | None]:
    """"monolog/monolog@3.10.0" -> ("monolog/monolog", "3.10.0");
    "monolog/monolog" -> ("monolog/monolog", None). Unlike Pub/RubyGems,
    no separate registry lookup is needed to resolve a bare package name
    to a version -- confirmed directly `composer require vendor/pkg`
    (with no version at all) already resolves and pins the latest stable
    release itself (`composer add`'s own real behavior, the same "the
    tool already does this" reasoning CargoEcosystem's/GoEcosystem's own
    bare-target handling already relies on), so a bare target is passed
    straight through with no version segment at all rather than pre-
    resolving one here."""
    package_name, _, version = target.partition("@")
    package_name = package_name.strip()
    version = version.strip()
    if not package_name:
        raise RuntimeError(f"{target!r} is not a valid Composer package target -- expected vendor/package[@version]")
    return package_name, version or None


def _to_composer_require_arg(name: str, version: str | None) -> str:
    # Composer's own CLI syntax uses ":" (not "@") to separate a package
    # name from an explicit version constraint -- confirmed directly
    # (`composer require monolog/monolog:3.10.0`). depshieldx's own
    # "name@version" target convention is translated to that here, not
    # used as this ecosystem's own native syntax -- Composer package
    # names never contain "@", so there's no ambiguity either way.
    return f"{name}:{version}" if version else name


class ComposerEcosystem:
    """The Composer/Packagist (PHP) ecosystem adapter."""

    name = "composer"
    cve_ecosystem_name = "Composer"
    lockfile_patterns = ("composer.lock",)

    def resolve(
        self,
        manager_args: list[str],
        requested_targets: list[str],
        install_target: str,
        source_type: str = "package",
    ) -> ResolutionResult:
        if source_type == "lockfile" and requested_targets:
            try:
                resolved_versions = parse_composer_lock(requested_targets[0])
            except Exception as exc:
                return self._failed_resolution(install_target, requested_targets, source_type, str(exc))
            return self._succeeded_resolution(install_target, requested_targets, source_type, resolved_versions)

        if source_type in ("package", "packages") and requested_targets:
            try:
                resolved_versions = self._resolve_via_composer_require(requested_targets)
            except Exception as exc:
                return self._failed_resolution(install_target, requested_targets, source_type, str(exc))
            return self._succeeded_resolution(install_target, requested_targets, source_type, resolved_versions)

        return self._failed_resolution(
            install_target,
            requested_targets,
            source_type,
            "composer resolution supports a composer.lock lockfile or one or more vendor/package[@version] targets",
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

    def _resolve_via_composer_require(self, package_targets: list[str]) -> dict[str, str]:
        """Resolve one or more ad-hoc package targets (and their full
        transitive dependency graph) by shelling out to composer's own
        resolver against a scratch composer.json, mirroring
        CargoEcosystem's/GoEcosystem's/PubEcosystem's/RubyGemsEcosystem's
        own scratch-project resolve flow -- reimplementing Composer's
        dependency resolution ourselves would be complex and likely
        subtly wrong.

        `--no-install` is required, not cosmetic: confirmed directly a
        plain `composer require` (which normally also extracts and
        "installs" -- including activating any allow-listed plugins --
        after updating the lock) still successfully writes a real,
        correctly resolved composer.lock even when the *install* half
        fails outright (confirmed directly with a real plugin package,
        composer/installers: `PluginBlockedException`) -- `--no-install`
        skips straight past that entire extract/activate step, so this
        scratch resolve never has anything to gain from -- or risk on --
        it succeeding. `--no-plugins`/`--no-scripts` are real, confirmed-
        directly flags too, kept as explicit defense in depth (see
        module docstring).
        """
        direct_packages = [_normalize_target_package(target) for target in package_targets]
        with tempfile.TemporaryDirectory(prefix="depshieldx_composer_resolve_") as temp_dir:
            manifest_path = Path(temp_dir) / "composer.json"
            manifest_path.write_text(
                f'{{"name": "{_SCRATCH_PACKAGE_NAME}", "require": {{}}}}\n', encoding="utf-8"
            )

            require_args = [_to_composer_require_arg(name, version) for name, version in direct_packages]
            result = _run(
                [
                    resolve_composer_tool("composer"),
                    "require",
                    *require_args,
                    "--no-interaction",
                    "--no-plugins",
                    "--no-scripts",
                    "--no-install",
                ],
                cwd=temp_dir,
            )
            if result.returncode != 0:
                raise RuntimeError(_command_error(result, f"composer could not resolve {', '.join(package_targets)}"))

            lockfile_path = Path(temp_dir) / "composer.lock"
            if not lockfile_path.exists():
                raise RuntimeError(f"composer did not produce a lock file while resolving {', '.join(package_targets)}")
            return parse_composer_lock(str(lockfile_path))

    def check_provenance(
        self,
        resolved_versions: dict[str, str],
        selected_artifacts: dict[str, list[dict]] | None = None,
        verbose: bool = False,
    ) -> dict:
        return composer_check_provenance_batch(resolved_versions, selected_artifacts=selected_artifacts, verbose=verbose)

    def selected_artifact_entries(self, resolution: ResolutionResult) -> list[tuple[str, str, dict]]:
        entries = []
        for package_name, version in resolution.resolved_versions.items():
            try:
                package_data = fetch_package_data(package_name)
            except Exception as exc:
                raise RuntimeError(f"could not fetch registry metadata for {package_name}@{version}: {exc}") from exc

            version_info = find_version_info(package_data, version) or {}
            dist = version_info.get("dist") or {}
            shasum = (dist.get("shasum") or "").strip()
            artifact = {
                "url": dist.get("url"),
                "filename": f"{package_name.replace('/', '-')}-{version}.zip",
                "checksum_algorithm": "sha1" if shasum else None,
                "checksum": shasum or None,
                "reference": dist.get("reference") or (version_info.get("source") or {}).get("reference"),
            }
            entries.append((package_name, version, artifact))
        return entries

    def fetch_artifact(self, artifact: dict, destination: Path) -> Path:
        url = artifact.get("url")
        filename = artifact["filename"]
        destination_path = destination / filename
        if not url:
            raise RuntimeError(f"no registry-published archive URL available to fetch {filename}")

        response = requests.get(url, headers={"User-Agent": PACKAGIST_USER_AGENT}, timeout=60)
        response.raise_for_status()
        artifact_bytes = response.content

        algorithm = artifact.get("checksum_algorithm")
        expected_checksum = (artifact.get("checksum") or "").strip()
        if algorithm and expected_checksum:
            # The common case has no checksum at all (see registry.py's
            # module docstring) -- unlike every other ecosystem here,
            # that is *not* refused on: it's this ecosystem's own normal,
            # confirmed-directly reality, not an anomaly. When a real
            # checksum genuinely is published, it's still verified for
            # real, the same way every other ecosystem's fetch_artifact
            # already does.
            actual_checksum = hashlib.new(algorithm, artifact_bytes).hexdigest()
            if actual_checksum != expected_checksum:
                raise RuntimeError(f"downloaded artifact checksum mismatch for {filename}")

        destination_path.write_bytes(artifact_bytes)
        return destination_path

    @contextmanager
    def host_install_command(self, resolution: ResolutionResult):
        # Fetching each artifact here (via fetch_artifact, which itself
        # checksum-verifies when a hash is actually published, and
        # raises on any real mismatch) still proves the resolved set is
        # real and fetchable before yielding the real install command.
        artifact_entries = self.selected_artifact_entries(resolution)
        with tempfile.TemporaryDirectory(prefix="depshieldx_host_install_") as temp_dir:
            temp_path = Path(temp_dir)
            for _, _, artifact in artifact_entries:
                self.fetch_artifact(artifact, temp_path)

            if resolution.source_type in ("package", "packages"):
                # Unlike RubyGemsEcosystem (bundle add's one-shared-
                # version-per-call limitation), a real `composer require
                # pkg1:v1 pkg2:v2 ...` accepts any number of independently
                # exact-pinned packages in one call (confirmed directly)
                # -- every resolved package here, transitive included, is
                # pinned as a direct dependency in one real invocation,
                # the same stronger scan-to-install drift guarantee
                # Cargo/Go/Pub already have.
                pinned_targets = [
                    _to_composer_require_arg(name, version) for name, version in resolution.resolved_versions.items()
                ]
                yield [
                    resolve_composer_tool("composer"),
                    "require",
                    *pinned_targets,
                    "--no-interaction",
                    "--no-plugins",
                    "--no-scripts",
                ]
            else:
                yield self.install_command([])

    def install_command(self, artifact_paths: list[str]) -> list[str]:
        # Resolves against an existing composer.lock, failing rather
        # than silently drifting if composer.json's requirements would
        # need a different resolution -- confirmed directly this is real
        # Composer behavior with no extra flag needed (unlike NuGet's
        # `--locked-mode`/Cargo's `--locked`): a real `composer install`
        # against a composer.lock that's missing a newly-required
        # package exits non-zero (confirmed directly, exit code 4)
        # rather than silently re-resolving. `--no-plugins`/`--no-
        # scripts` keep this consistent with every other ecosystem's own
        # "fast mode never executes untrusted code" guarantee -- unlike
        # RubyGems, Composer has no analogous "installation itself is
        # the real code-execution surface" problem to work around, since
        # plugin activation is opt-in (allow-plugins) and blocked by
        # default, and script execution is explicitly disabled here.
        return [resolve_composer_tool("composer"), "install", "--no-interaction", "--no-plugins", "--no-scripts"]

    def uninstall_command(self, package_names: list[str]) -> list[str]:
        return [resolve_composer_tool("composer"), "remove", *package_names, "--no-interaction"]

    def direct_dependency_names_for_lockfile(self, lockfile_path: str) -> list[str]:
        """The names a user would expect `depshieldx uninstall --lockfile
        composer.lock ...` to remove: the packages actually declared in
        composer.json, not every transitively-resolved name the lockfile
        also lists. Mirrors CargoEcosystem's own direct_dependency_names_
        for_lockfile exactly -- composer.lock alone doesn't distinguish
        direct from transitive dependencies any more than Cargo.lock
        does (confirmed directly: no per-entry marker exists in either
        the "packages" or "packages-dev" array), but composer.json's own
        "require"/"require-dev" tables are the one source of truth
        `composer require`/`composer remove` themselves read and write.
        """
        import json

        manifest_path = Path(lockfile_path).parent / "composer.json"
        if not manifest_path.exists():
            raise RuntimeError(
                f"no composer.json found next to {lockfile_path} -- can't determine which "
                "packages are direct dependencies to uninstall"
            )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        names = []
        seen = set()
        for section in ("require", "require-dev"):
            for name in manifest.get(section) or {}:
                if name == "php" or name.startswith("ext-") or name.startswith("lib-"):
                    # Platform requirements (the PHP runtime itself, or a
                    # PHP extension/library) aren't real Packagist
                    # packages -- confirmed directly these use the same
                    # "require" table but are never present in
                    # composer.lock's own "packages"/"packages-dev"
                    # arrays at all.
                    continue
                if name not in seen:
                    seen.add(name)
                    names.append(name)
        return names


COMPOSER_ECOSYSTEM = ComposerEcosystem()
