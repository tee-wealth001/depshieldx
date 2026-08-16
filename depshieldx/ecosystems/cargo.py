"""The cargo/crates.io ecosystem adapter.

Provenance is structural only, never cryptographic -- see cargo_registry.py's
module docstring for why (crates.io has no Sigstore/SLSA attestation
infrastructure at all today, confirmed against the real Trusted Publishing
RFC).

"Install" means `cargo add` (adding to a project's Cargo.toml/Cargo.lock),
not `cargo install` (which only installs binary/CLI crates, a narrow
minority of crates.io) -- most crates.io packages are libraries, and
depshieldx's "vet this before it touches my project" value proposition maps
onto `cargo add` far better. Real, accepted consequence, confirmed directly
against a real `cargo add` run: unlike bare `pip install`/`npm install`,
`cargo add` needs an actual source file to exist (src/lib.rs or
src/main.rs), not just a `[package]` table in Cargo.toml -- "no targets
specified in the manifest" otherwise. The scratch-resolution flow below
creates one.

cargo itself is a separate toolchain -- like npm, this has nothing to do
with depshieldx's own frozen/non-frozen state, so runtime.py's Python
interpreter resolution doesn't apply here, only PATH resolution (see
resolve_cargo_tool).
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
import tomllib
from contextlib import contextmanager
from pathlib import Path

import requests

from ..cargo_lockfiles import parse_cargo_lock
from ..cargo_registry import (
    CRATES_IO_BASE_URL,
    CRATES_IO_USER_AGENT,
    check_provenance_batch as cargo_check_provenance_batch,
    fetch_version_metadata,
)
from ..resolver import ResolutionResult

# The scratch project's own manifest name, used only for the bare
# "resolve a package name with no existing project" flow -- excluded from
# the parsed Cargo.lock afterward since it isn't a real dependency (it's
# the throwaway root package itself, confirmed directly to appear in the
# real Cargo.lock cargo produces, the same way a real project's own root
# package would).
_SCRATCH_PACKAGE_NAME = "depshieldx-resolve"
# Cargo's current stable default edition as of development time (confirmed
# directly via `cargo new` against a real, current cargo) -- affects
# resolver behavior (edition >=2021 uses Cargo's resolver v2, which changes
# transitive feature unification), not just cosmetics. Revisit when a newer
# edition becomes the real default.
_SCRATCH_PACKAGE_EDITION = "2024"


def resolve_cargo_tool(name: str) -> str:
    """Resolve a cargo-toolchain binary via PATH. Mirrors
    ecosystems/npm.py's resolve_node_tool -- cargo ships as a real,
    directly-executable binary on every platform (no Windows .cmd-shim
    complication the way npm has), but shutil.which() is still the correct
    portable PATH lookup either way."""
    resolved = shutil.which(name)
    if not resolved:
        raise RuntimeError(f"{name!r} was not found on PATH. Install the Rust toolchain (rustup) to use the cargo ecosystem.")
    return resolved


class CargoEcosystem:
    """The cargo/crates.io ecosystem adapter."""

    name = "cargo"
    cve_ecosystem_name = "crates.io"
    lockfile_patterns = ("Cargo.lock",)

    def resolve(
        self,
        manager_args: list[str],
        requested_targets: list[str],
        install_target: str,
        source_type: str = "package",
    ) -> ResolutionResult:
        if source_type == "lockfile" and requested_targets:
            try:
                resolved_versions = parse_cargo_lock(requested_targets[0])
            except Exception as exc:
                return self._failed_resolution(install_target, requested_targets, source_type, str(exc))
            return self._succeeded_resolution(install_target, requested_targets, source_type, resolved_versions)

        if source_type in ("package", "packages") and requested_targets:
            try:
                resolved_versions = self._resolve_via_cargo_add(requested_targets)
            except Exception as exc:
                return self._failed_resolution(install_target, requested_targets, source_type, str(exc))
            return self._succeeded_resolution(install_target, requested_targets, source_type, resolved_versions)

        return self._failed_resolution(
            install_target,
            requested_targets,
            source_type,
            "cargo resolution supports a Cargo.lock lockfile or one or more crate names",
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

    def _resolve_via_cargo_add(self, crate_targets: list[str]) -> dict[str, str]:
        """Resolve one or more ad-hoc crate targets (and their full
        transitive dependency tree) by shelling out to cargo's own resolver
        in an isolated scratch project, mirroring why NpmEcosystem shells
        out to npm's own resolver and PyPiEcosystem shells out to pip's --
        reimplementing dependency resolution ourselves would be complex and
        likely subtly wrong. `cargo add --dry-run` writes nothing to disk
        (confirmed), so a real (non-dry-run) `cargo add` against a scratch
        manifest is used instead -- it resolves against the live index and
        writes a real Cargo.lock, the same way NpmEcosystem's
        --package-lock-only does for npm.
        """
        with tempfile.TemporaryDirectory(prefix="depshieldx_cargo_resolve_") as temp_dir:
            temp_path = Path(temp_dir)
            src_dir = temp_path / "src"
            src_dir.mkdir()
            (src_dir / "lib.rs").write_text("")
            manifest_path = temp_path / "Cargo.toml"
            manifest_path.write_text(
                f'[package]\nname = "{_SCRATCH_PACKAGE_NAME}"\nversion = "0.0.0"\nedition = "{_SCRATCH_PACKAGE_EDITION}"\n'
            )
            result = subprocess.run(
                [
                    resolve_cargo_tool("cargo"),
                    "add",
                    *crate_targets,
                    "--manifest-path",
                    str(manifest_path),
                ],
                cwd=temp_dir,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                # Confirmed directly: cargo add's error output goes entirely
                # to stderr, stdout is empty on failure.
                detail = (result.stderr or result.stdout or "").strip()
                raise RuntimeError(f"cargo could not resolve {', '.join(crate_targets)}: {detail}")
            lockfile_path = temp_path / "Cargo.lock"
            if not lockfile_path.exists():
                raise RuntimeError(f"cargo did not produce a lockfile while resolving {', '.join(crate_targets)}")
            resolved_versions = parse_cargo_lock(lockfile_path)
            resolved_versions.pop(_SCRATCH_PACKAGE_NAME, None)
            return resolved_versions

    def check_provenance(
        self,
        resolved_versions: dict[str, str],
        selected_artifacts: dict[str, list[dict]] | None = None,
        verbose: bool = False,
    ) -> dict:
        return cargo_check_provenance_batch(resolved_versions, selected_artifacts=selected_artifacts, verbose=verbose)

    def selected_artifact_entries(self, resolution: ResolutionResult) -> list[tuple[str, str, dict]]:
        entries = []
        for name, version in resolution.resolved_versions.items():
            try:
                metadata = fetch_version_metadata(name, version)
            except requests.exceptions.HTTPError:
                # Not every resolved entry is a real crates.io-hosted crate:
                # path/git/workspace-member dependencies (and, for the
                # scratch-resolve flow, the scratch project's own root
                # package if it wasn't already filtered out) simply don't
                # exist in the registry -- confirmed directly against a real
                # multi-crate workspace lockfile (ripgrep's), which has
                # exactly this for its own workspace-member crates. Skip
                # rather than raise; there's nothing to fetch or verify for
                # these.
                continue
            except Exception as exc:
                raise RuntimeError(f"could not fetch crates.io metadata for {name}@{version}: {exc}") from exc

            version_meta = metadata.get("version") or {}
            checksum = version_meta.get("checksum")
            dl_path = version_meta.get("dl_path")
            if not checksum or not dl_path:
                continue
            artifact = {
                "url": f"{CRATES_IO_BASE_URL}{dl_path}",
                "filename": f"{name}-{version}.crate",
                "checksum": checksum,
            }
            entries.append((name, version, artifact))
        return entries

    def fetch_artifact(self, artifact: dict, destination: Path) -> Path:
        url = artifact["url"]
        filename = artifact["filename"]
        destination_path = destination / filename

        # crates.io's crawler policy (see cargo_registry.py) applies to its
        # JSON API, not tarball downloads served from its CDN -- no
        # additional throttling here, matching how cargo_registry.py's own
        # _throttle() is only applied to the metadata endpoint.
        response = requests.get(url, headers={"User-Agent": CRATES_IO_USER_AGENT}, timeout=30)
        response.raise_for_status()
        artifact_bytes = response.content

        expected_checksum = (artifact.get("checksum") or "").strip()
        if expected_checksum:
            actual_checksum = hashlib.sha256(artifact_bytes).hexdigest()
            if actual_checksum != expected_checksum:
                raise RuntimeError(f"downloaded artifact checksum mismatch for {filename}")

        destination_path.write_bytes(artifact_bytes)
        return destination_path

    @contextmanager
    def host_install_command(self, resolution: ResolutionResult):
        # Like npm, cargo doesn't install from a list of individually-
        # downloaded artifact paths -- `cargo add` re-resolves against the
        # registry itself. Fetching (and checksum-verifying) each artifact
        # here still proves the resolved set is real and intact before
        # yielding the real install command, even though the fetched files
        # themselves aren't passed to it.
        artifact_entries = self.selected_artifact_entries(resolution)
        with tempfile.TemporaryDirectory(prefix="depshieldx_host_install_") as temp_dir:
            temp_path = Path(temp_dir)
            for _, _, artifact in artifact_entries:
                self.fetch_artifact(artifact, temp_path)
            if resolution.source_type in ("package", "packages"):
                # `cargo add name@version` writes a caret requirement
                # ("^version") by default -- confirmed directly. Pin with
                # the exact-version operator ("=") so the install can't
                # drift, the same intent as npm's exact name@version
                # pinning -- confirmed directly that
                # `cargo add serde@=1.0.219` writes `serde = "=1.0.219"` to
                # Cargo.toml, not a caret range.
                #
                # Unlike npm (which only pins the originally-requested
                # targets and lets its own resolver work out transitive
                # versions against package-lock.json), every resolved
                # package here -- transitive included -- is pinned as a
                # direct dependency, not just the requested targets. This is
                # deliberate, not copied loosely from npm's shape: a fresh
                # `cargo add` run has no existing Cargo.lock to consult, so
                # pinning only the top-level target would let Cargo's own
                # resolver pick transitive versions independently at
                # install time, which could drift from what was actually
                # scanned. Cargo.toml ends up listing transitive
                # dependencies as direct entries, which looks unusual for a
                # hand-written manifest, but it's the only way to guarantee
                # the exact resolved set (not just the top-level version)
                # can't drift between scan and install.
                pinned_targets = [f"{name}@={version}" for name, version in resolution.resolved_versions.items()]
                yield [resolve_cargo_tool("cargo"), "add", *pinned_targets]
            else:
                yield self.install_command([])

    def install_command(self, artifact_paths: list[str]) -> list[str]:
        # Reconciles the local cache with an already-locked Cargo.lock
        # without compiling anything -- confirmed directly this downloads
        # every locked dependency and exits 0 without invoking rustc.
        # Compilation (and the build.rs/proc-macro attack surface it
        # entails) is deliberately out of scope for fast-mode install; deep
        # mode's behavioral tracing is where that happens.
        return [resolve_cargo_tool("cargo"), "fetch", "--locked"]

    def uninstall_command(self, package_names: list[str]) -> list[str]:
        return [resolve_cargo_tool("cargo"), "remove", *package_names]

    def direct_dependency_names_for_lockfile(self, lockfile_path: str) -> list[str]:
        """The names a user would expect `depshieldx uninstall --lockfile
        Cargo.lock ...` to remove: the crates actually declared in
        Cargo.toml, not every transitively-resolved name the lockfile also
        lists. Mirrors NpmEcosystem's direct_dependency_names_for_lockfile
        exactly -- Cargo.lock alone doesn't reliably distinguish direct from
        transitive dependencies any more than npm's lockfiles do, but
        Cargo.toml's own dependency tables are the one source of truth
        `cargo add`/`cargo remove` themselves read and write.
        """
        manifest_path = Path(lockfile_path).parent / "Cargo.toml"
        if not manifest_path.exists():
            raise RuntimeError(
                f"no Cargo.toml found next to {lockfile_path} -- can't determine which "
                "crates are direct dependencies to uninstall"
            )
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        names = []
        seen = set()
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            for name in manifest.get(section) or {}:
                if name not in seen:
                    seen.add(name)
                    names.append(name)
        return names


CARGO_ECOSYSTEM = CargoEcosystem()
