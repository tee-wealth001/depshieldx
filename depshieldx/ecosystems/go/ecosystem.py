"""The Go modules ecosystem adapter.

Provenance combines the one real signal Go's own toolchain doesn't
surface as an install-time block (the `retract` directive, go.mod's
yanked-release equivalent) with the fact that checksum-transparency
verification (go.sum vs. sum.golang.org) already happens transparently
inside the real `go` toolchain during resolution/fetch -- see
go_registry.py's module docstring for the full reasoning and the two
Hash1 algorithms confirmed directly against real data.

"Install" means `go get` (adding/pinning a requirement in
go.mod/go.sum), mirroring CargoEcosystem's "install means `cargo add`,
not `cargo install`" -- `go install` only builds and places a binary in
GOBIN and deliberately never touches go.mod (confirmed directly against
the real Go 1.17+ get/install split: `go get` no longer builds or
installs anything as of Go 1.18), the same narrow-minority-of-modules
carve-out cargo's binary-crate split is.

go.sum alone can't reconstruct the resolved module graph (see
go_lockfiles.py's module docstring) -- both the lockfile and the bare
module-name resolution paths below shell out to `go list -m -json all`
for the real, Minimal-Version-Selection-computed answer, mirroring why
CargoEcosystem/NpmEcosystem shell out to their own tool's resolver rather
than reimplementing it.

go itself is a separate toolchain -- like npm/cargo, this has nothing to
do with depshieldx's own frozen/non-frozen state, so runtime.py's Python
interpreter resolution doesn't apply here, only PATH resolution (see
resolve_go_tool).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote

import requests

from .lockfiles import parse_go_list_module_output
from .registry import (
    GOPROXY_BASE_URL,
    check_provenance_batch as go_check_provenance_batch,
    escape_module_path,
    fetch_module_checksum,
    fetch_version_metadata,
    hash1_of_zip,
)
from ...core.resolver import ResolutionResult

# The scratch module's own name, used only for the bare "resolve a module
# path with no existing project" flow -- excluded from the parsed `go
# list -m -json all` output via that command's own "Main": true field on
# the root module entry (confirmed directly), the same role
# _SCRATCH_PACKAGE_NAME plays for CargoEcosystem, just filtered a
# different way since `go list -m` already marks the main module for us.
_SCRATCH_MODULE_NAME = "depshieldx-resolve"


def resolve_go_tool(name: str) -> str:
    """Resolve a go-toolchain binary via PATH. Mirrors
    ecosystems/cargo.py's resolve_cargo_tool -- go ships as a real,
    directly-executable binary on every platform, but shutil.which() is
    still the correct portable PATH lookup either way."""
    resolved = shutil.which(name)
    if not resolved:
        raise RuntimeError(f"{name!r} was not found on PATH. Install the Go toolchain to use the go ecosystem.")
    return resolved


def _run(args: list[str], cwd: str) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


def _command_error(result: subprocess.CompletedProcess, action: str) -> str:
    detail = (result.stderr or result.stdout or "").strip()
    return f"{action}: {detail}" if detail else action


class GoEcosystem:
    """The Go modules ecosystem adapter."""

    name = "go"
    cve_ecosystem_name = "Go"
    lockfile_patterns = ("go.sum",)

    def resolve(
        self,
        manager_args: list[str],
        requested_targets: list[str],
        install_target: str,
        source_type: str = "package",
    ) -> ResolutionResult:
        if source_type == "lockfile" and requested_targets:
            try:
                resolved_versions = self._resolve_from_lockfile(requested_targets[0])
            except Exception as exc:
                return self._failed_resolution(install_target, requested_targets, source_type, str(exc))
            return self._succeeded_resolution(install_target, requested_targets, source_type, resolved_versions)

        if source_type in ("package", "packages") and requested_targets:
            try:
                resolved_versions = self._resolve_via_go_get(requested_targets)
            except Exception as exc:
                return self._failed_resolution(install_target, requested_targets, source_type, str(exc))
            return self._succeeded_resolution(install_target, requested_targets, source_type, resolved_versions)

        return self._failed_resolution(
            install_target,
            requested_targets,
            source_type,
            "go resolution supports a go.sum lockfile or one or more module paths",
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

    def _resolve_from_lockfile(self, lockfile_path: str) -> dict[str, str]:
        project_dir = Path(lockfile_path).parent
        if not (project_dir / "go.mod").exists():
            raise RuntimeError(f"no go.mod found next to {lockfile_path} -- can't determine the resolved module graph")
        result = _run([resolve_go_tool("go"), "list", "-m", "-json", "all"], cwd=str(project_dir))
        if result.returncode != 0:
            raise RuntimeError(_command_error(result, "go could not list the resolved module graph"))
        return parse_go_list_module_output(result.stdout)

    def _resolve_via_go_get(self, module_targets: list[str]) -> dict[str, str]:
        """Resolve one or more ad-hoc module targets (and their full
        transitive dependency graph) by shelling out to go's own Minimal
        Version Selection resolver in an isolated scratch module,
        mirroring CargoEcosystem._resolve_via_cargo_add -- reimplementing
        MVS ourselves would be complex and likely subtly wrong.
        """
        with tempfile.TemporaryDirectory(prefix="depshieldx_go_resolve_") as temp_dir:
            init_result = _run([resolve_go_tool("go"), "mod", "init", _SCRATCH_MODULE_NAME], cwd=temp_dir)
            if init_result.returncode != 0:
                raise RuntimeError(_command_error(init_result, "go could not initialize a scratch module"))

            get_result = _run([resolve_go_tool("go"), "get", *module_targets], cwd=temp_dir)
            if get_result.returncode != 0:
                raise RuntimeError(_command_error(get_result, f"go could not resolve {', '.join(module_targets)}"))

            list_result = _run([resolve_go_tool("go"), "list", "-m", "-json", "all"], cwd=temp_dir)
            if list_result.returncode != 0:
                raise RuntimeError(_command_error(list_result, "go could not list the resolved module graph"))
            return parse_go_list_module_output(list_result.stdout)

    def check_provenance(
        self,
        resolved_versions: dict[str, str],
        selected_artifacts: dict[str, list[dict]] | None = None,
        verbose: bool = False,
    ) -> dict:
        return go_check_provenance_batch(resolved_versions, selected_artifacts=selected_artifacts, verbose=verbose)

    def selected_artifact_entries(self, resolution: ResolutionResult) -> list[tuple[str, str, dict]]:
        entries = []
        for module, version in resolution.resolved_versions.items():
            try:
                fetch_version_metadata(module, version)
            except requests.exceptions.HTTPError:
                # Not every resolved entry is fetchable this way -- a
                # `replace`-directive target pointing at a local
                # filesystem path has no real proxy-hosted version.
                # Mirrors CargoEcosystem's skip-rather-than-raise for
                # path/git/workspace entries.
                continue
            except Exception as exc:
                raise RuntimeError(f"could not fetch module metadata for {module}@{version}: {exc}") from exc

            checksum = fetch_module_checksum(module, version)
            artifact = {
                "url": f"{GOPROXY_BASE_URL}/{escape_module_path(module)}/@v/{quote(version, safe='')}.zip",
                "filename": f"{module.replace('/', '_')}@{version}.zip",
                "checksum": checksum,
            }
            entries.append((module, version, artifact))
        return entries

    def fetch_artifact(self, artifact: dict, destination: Path) -> Path:
        url = artifact["url"]
        filename = artifact["filename"]
        destination_path = destination / filename

        response = requests.get(url, timeout=60)
        response.raise_for_status()
        artifact_bytes = response.content

        expected_checksum = (artifact.get("checksum") or "").strip()
        if expected_checksum:
            actual_checksum = hash1_of_zip(artifact_bytes)
            if actual_checksum != expected_checksum:
                raise RuntimeError(f"downloaded artifact checksum mismatch for {filename}")

        destination_path.write_bytes(artifact_bytes)
        return destination_path

    @contextmanager
    def host_install_command(self, resolution: ResolutionResult):
        # Like npm/cargo, go doesn't install from a list of individually-
        # downloaded artifact paths -- `go get` re-resolves against the
        # module proxy itself. Fetching (and Hash1-verifying) each
        # artifact here still proves the resolved set is real and intact
        # before yielding the real install command, even though the
        # fetched files themselves aren't passed to it.
        artifact_entries = self.selected_artifact_entries(resolution)
        with tempfile.TemporaryDirectory(prefix="depshieldx_host_install_") as temp_dir:
            temp_path = Path(temp_dir)
            for _, _, artifact in artifact_entries:
                self.fetch_artifact(artifact, temp_path)
            if resolution.source_type in ("package", "packages"):
                # Every resolved module -- transitive included -- is
                # pinned exactly, the same reasoning as
                # CargoEcosystem.host_install_command: a fresh `go get`
                # run has no existing go.sum to consult, so pinning only
                # the top-level target would let go's own MVS resolver
                # pick transitive versions independently at install time,
                # which could drift from what was actually scanned.
                pinned_targets = [f"{module}@{version}" for module, version in resolution.resolved_versions.items()]
                yield [resolve_go_tool("go"), "get", *pinned_targets]
            else:
                yield self.install_command([])

    def install_command(self, artifact_paths: list[str]) -> list[str]:
        # Downloads every module in the existing go.sum's build list into
        # the local module cache and verifies it against go.sum, without
        # compiling anything -- confirmed directly this exits 0 without
        # invoking the compiler. Compilation (and the build.rs-equivalent
        # attack surface of `go generate`/build-time code execution) is
        # deliberately out of scope for fast-mode install; deep mode's
        # future behavioral tracing is where that would happen.
        return [resolve_go_tool("go"), "mod", "download"]

    def uninstall_command(self, package_names: list[str]) -> list[str]:
        # `go get module@none` is the real, confirmed-directly way to
        # drop a requirement from go.mod/go.sum (Go has no separate
        # "remove" subcommand the way cargo does).
        return [resolve_go_tool("go"), "get", *[f"{name}@none" for name in package_names]]

    def direct_dependency_names_for_lockfile(self, lockfile_path: str) -> list[str]:
        """The module paths a user would expect `depshieldx uninstall
        --lockfile go.sum ...` to remove: the modules actually required
        directly in go.mod, not every transitively-resolved path go.sum
        also lists. Mirrors CargoEcosystem's
        direct_dependency_names_for_lockfile exactly, using `go mod edit
        -json`'s structured `Require[].Indirect` field (confirmed
        directly against a real go.mod) rather than hand-parsing the
        require block the way go_registry.py's retract parser has to for
        a *remote* module's go.mod (which `go mod edit` can't target)."""
        project_dir = Path(lockfile_path).parent
        manifest_path = project_dir / "go.mod"
        if not manifest_path.exists():
            raise RuntimeError(
                f"no go.mod found next to {lockfile_path} -- can't determine which "
                "modules are direct dependencies to uninstall"
            )
        result = _run([resolve_go_tool("go"), "mod", "edit", "-json"], cwd=str(project_dir))
        if result.returncode != 0:
            raise RuntimeError(_command_error(result, "go could not read go.mod"))

        payload = json.loads(result.stdout)
        names = []
        seen = set()
        for entry in payload.get("Require") or []:
            path = entry.get("Path")
            if path and not entry.get("Indirect") and path not in seen:
                seen.add(path)
                names.append(path)
        return names


GO_ECOSYSTEM = GoEcosystem()
