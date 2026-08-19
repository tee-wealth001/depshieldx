"""The Maven/Maven Central ecosystem adapter.

Provenance combines checksum verification with (where available) real
Sigstore signature verification -- see registry.py's module docstring for
the full checksum-era and Sigstore-adoption reasoning confirmed directly
against real Central artifacts.

"Install" has no `cargo add`/`go get` equivalent to shell out to -- Maven
has no single-artifact "add this dependency to my project" command that
also does live resolution the way cargo/go's tools do (confirmed
directly: `mvn dependency:get -Dartifact=` fetches exactly one
already-versioned coordinate into the local repository, `mvn dependency:list`).
So both resolution and install here go through a scratch pom.xml built by
this module -- `dependency:list` to resolve the full transitive graph (an
untried version resolves via search_latest_version() first, since Maven's
plugin goals require an already-known version, unlike cargo add/go get's
own live version resolution), and `dependency:resolve` to actually
download the resolved set into the local repository (~/.m2).

Confirmed directly: `mvn dependency:get -Dartifact=a,b,c` (comma-joined,
the natural way to try passing multiple coordinates to a single-artifact
CLI flag) fails outright -- Maven parses the whole string as one
malformed coordinate and raises a DependencyResolutionException, not a
per-item loop. That's incompatible with host_install_command's interface
(a single `list[str]` command, confirmed via ecosystems/base.py's
Protocol and cli/engine.py's single `with ... as install_command:` call
site) once more than one package is resolved -- which, given every
resolved package (transitive included) is pinned as a direct dependency
here for the same drift-prevention reasons as CargoEcosystem/GoEcosystem,
is effectively always. `dependency:resolve` against a scratch pom listing
every resolved coordinate as a direct <dependency> was confirmed directly
to download all of them into ~/.m2 in one real Maven invocation instead,
run from any working directory via `-f <pom-path>`.

Maven has no canonical lockfile (lockfile_patterns is empty) -- unlike
Cargo.lock/go.sum/package-lock.json, there's no single Maven-native file
that records resolved versions the way those do; `mvn dependency:tree`
resolves live against whatever the project's pom.xml (and any parent
poms) currently declare. Lockfile-shaped input (e.g. a `--pom pom.xml`
manifest source) is real future work, not implemented here.

Maven itself is a separate toolchain -- like cargo/go, this has nothing
to do with depshieldx's own frozen/non-frozen state, so runtime.py's
Python interpreter resolution doesn't apply here, only PATH resolution
(see resolve_maven_tool).
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from xml.sax.saxutils import escape as _xml_escape

import requests

from .registry import (
    MAVEN_USER_AGENT,
    artifact_directory_url,
    check_provenance_batch as maven_check_provenance_batch,
    fetch_best_checksum,
    search_latest_version,
)
from ...core.resolver import ResolutionResult

# The scratch project's own coordinate, used only for the "resolve one or
# more ad-hoc coordinates with no existing project" flow -- unlike Cargo's
# scratch package (which shows up as a real entry in the Cargo.lock it
# produces and must be filtered out), `mvn dependency:list`/`dependency:
# resolve` never list the project's own coordinate among the dependencies
# they report, so no equivalent filtering is needed here.
_SCRATCH_GROUP_ID = "depshieldx.scratch"
_SCRATCH_ARTIFACT_ID = "depshieldx-resolve"

# Matches one "groupId:artifactId:packaging:version:scope" line from real
# `mvn dependency:list` output (confirmed directly, e.g. "[INFO]    org.
# apache.commons:commons-lang3:jar:3.17.0:compile -- module org.apache.
# commons.lang3") -- the trailing "-- module ..." JPMS-module-name suffix
# (present only for some artifacts) is simply left unmatched past the 5th
# group. Other `[INFO]` lines (banners, the goal header, which itself
# contains one colon-separated-looking segment like "dependency:3.7.0:
# list") never have 4 colons across 5 non-whitespace groups, so they don't
# false-positive-match.
_LIST_LINE = re.compile(r"^\[INFO\]\s+(\S+):(\S+):(\S+):(\S+):(\S+)")


def resolve_maven_tool(name: str) -> str:
    """Resolve a Maven-toolchain binary via PATH. Mirrors ecosystems/
    go.py's resolve_go_tool -- mvn ships as a real, directly-executable
    (wrapper) script/binary on every platform, so shutil.which() is the
    correct portable PATH lookup here too."""
    resolved = shutil.which(name)
    if not resolved:
        raise RuntimeError(f"{name!r} was not found on PATH. Install Maven to use the maven ecosystem.")
    return resolved


def _run(args: list[str], cwd: str) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


def _command_error(result: subprocess.CompletedProcess, action: str) -> str:
    detail = (result.stderr or result.stdout or "").strip()
    return f"{action}: {detail}" if detail else action


def _normalize_target_coordinate(target: str) -> tuple[str, str, str]:
    """"groupId:artifactId:version" is used as-is; a bare "groupId:
    artifactId" is resolved to its latest release via Maven Central's
    search API (registry.py's search_latest_version, confirmed directly
    against real Central data) -- unlike cargo add/go get, Maven's own
    resolution plugins require an already-known version, they don't do
    "give me whatever's latest" resolution themselves."""
    parts = target.split(":")
    if len(parts) == 3:
        group_id, artifact_id, version = (part.strip() for part in parts)
        if not group_id or not artifact_id or not version:
            raise RuntimeError(f"{target!r} is not a valid Maven coordinate -- expected groupId:artifactId[:version]")
        return group_id, artifact_id, version
    if len(parts) == 2:
        group_id, artifact_id = (part.strip() for part in parts)
        if not group_id or not artifact_id:
            raise RuntimeError(f"{target!r} is not a valid Maven coordinate -- expected groupId:artifactId[:version]")
        version = search_latest_version(group_id, artifact_id)
        if not version:
            raise RuntimeError(f"could not determine the latest version of {target} -- pass an explicit groupId:artifactId:version")
        return group_id, artifact_id, version
    raise RuntimeError(f"{target!r} is not a valid Maven coordinate -- expected groupId:artifactId[:version]")


def _build_scratch_pom(coordinates: list[tuple[str, str, str]]) -> str:
    dependency_blocks = "\n".join(
        "    <dependency>\n"
        f"      <groupId>{_xml_escape(group_id)}</groupId>\n"
        f"      <artifactId>{_xml_escape(artifact_id)}</artifactId>\n"
        f"      <version>{_xml_escape(version)}</version>\n"
        "    </dependency>"
        for group_id, artifact_id, version in coordinates
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <modelVersion>4.0.0</modelVersion>\n"
        f"  <groupId>{_SCRATCH_GROUP_ID}</groupId>\n"
        f"  <artifactId>{_SCRATCH_ARTIFACT_ID}</artifactId>\n"
        "  <version>0.0.0</version>\n"
        "  <dependencies>\n"
        f"{dependency_blocks}\n"
        "  </dependencies>\n"
        "</project>\n"
    )


def _parse_dependency_list(output: str) -> dict[str, str]:
    resolved: dict[str, str] = {}
    for line in output.splitlines():
        match = _LIST_LINE.match(line)
        if not match:
            continue
        group_id, artifact_id, _packaging, version, _scope = match.groups()
        resolved[f"{group_id}:{artifact_id}"] = version
    return resolved


class MavenEcosystem:
    """The Maven/Maven Central ecosystem adapter."""

    name = "maven"
    cve_ecosystem_name = "Maven"
    lockfile_patterns = ()

    def resolve(
        self,
        manager_args: list[str],
        requested_targets: list[str],
        install_target: str,
        source_type: str = "package",
    ) -> ResolutionResult:
        if source_type in ("package", "packages") and requested_targets:
            try:
                resolved_versions = self._resolve_via_dependency_list(requested_targets)
            except Exception as exc:
                return self._failed_resolution(install_target, requested_targets, source_type, str(exc))
            return self._succeeded_resolution(install_target, requested_targets, source_type, resolved_versions)

        return self._failed_resolution(
            install_target,
            requested_targets,
            source_type,
            "maven resolution supports one or more groupId:artifactId[:version] coordinates -- "
            "Maven has no canonical lockfile to resolve from",
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

    def _resolve_via_dependency_list(self, coordinate_targets: list[str]) -> dict[str, str]:
        """Resolve one or more ad-hoc coordinates (and their full
        transitive dependency tree) by shelling out to Maven's own
        resolver against a scratch pom.xml, mirroring CargoEcosystem/
        GoEcosystem's scratch-project resolve flow -- reimplementing
        Maven dependency mediation ourselves would be complex and likely
        subtly wrong.
        """
        direct_coordinates = [_normalize_target_coordinate(target) for target in coordinate_targets]
        with tempfile.TemporaryDirectory(prefix="depshieldx_maven_resolve_") as temp_dir:
            pom_path = Path(temp_dir) / "pom.xml"
            pom_path.write_bytes(_build_scratch_pom(direct_coordinates).encode("utf-8"))

            result = _run([resolve_maven_tool("mvn"), "-B", "-f", str(pom_path), "dependency:list"], cwd=temp_dir)
            if result.returncode != 0:
                raise RuntimeError(_command_error(result, f"maven could not resolve {', '.join(coordinate_targets)}"))

            resolved_versions = _parse_dependency_list(result.stdout)
            if not resolved_versions:
                raise RuntimeError(f"maven resolved no dependencies for {', '.join(coordinate_targets)}")
            return resolved_versions

    def check_provenance(
        self,
        resolved_versions: dict[str, str],
        selected_artifacts: dict[str, list[dict]] | None = None,
        verbose: bool = False,
    ) -> dict:
        return maven_check_provenance_batch(resolved_versions, selected_artifacts=selected_artifacts, verbose=verbose)

    def selected_artifact_entries(self, resolution: ResolutionResult) -> list[tuple[str, str, dict]]:
        entries = []
        for coordinate, version in resolution.resolved_versions.items():
            group_id, _, artifact_id = coordinate.partition(":")
            checksum = fetch_best_checksum(group_id, artifact_id, version)
            if not checksum:
                # Mirrors CargoEcosystem's skip-rather-than-raise for
                # entries with nothing to verify against -- rare (see
                # registry.py's module docstring on the two checksum
                # eras) but not itself evidence of tampering.
                continue
            algorithm, digest = checksum
            artifact = {
                "url": f"{artifact_directory_url(group_id, artifact_id, version)}/{artifact_id}-{version}.jar",
                "filename": f"{artifact_id}-{version}.jar",
                "checksum_algorithm": algorithm,
                "checksum": digest,
            }
            entries.append((coordinate, version, artifact))
        return entries

    def fetch_artifact(self, artifact: dict, destination: Path) -> Path:
        url = artifact["url"]
        filename = artifact["filename"]
        destination_path = destination / filename

        response = requests.get(url, headers={"User-Agent": MAVEN_USER_AGENT}, timeout=60)
        response.raise_for_status()
        artifact_bytes = response.content

        algorithm = artifact.get("checksum_algorithm")
        expected_checksum = (artifact.get("checksum") or "").strip()
        if algorithm and expected_checksum:
            actual_checksum = hashlib.new(algorithm, artifact_bytes).hexdigest()
            if actual_checksum != expected_checksum:
                raise RuntimeError(f"downloaded artifact checksum mismatch for {filename}")

        destination_path.write_bytes(artifact_bytes)
        return destination_path

    @contextmanager
    def host_install_command(self, resolution: ResolutionResult):
        # Fetching (and checksum-verifying) each artifact here still
        # proves the resolved set is real and intact before yielding the
        # real install command, even though the fetched files themselves
        # aren't passed to it -- mirrors CargoEcosystem/GoEcosystem's
        # host_install_command exactly.
        artifact_entries = self.selected_artifact_entries(resolution)
        with tempfile.TemporaryDirectory(prefix="depshieldx_host_install_") as temp_dir:
            temp_path = Path(temp_dir)
            for _, _, artifact in artifact_entries:
                self.fetch_artifact(artifact, temp_path)

            # Every resolved coordinate -- transitive included -- is
            # written into the scratch pom as a direct <dependency>, the
            # same pin-everything reasoning as CargoEcosystem/GoEcosystem's
            # host_install_command: there's no existing lockfile to
            # consult, so declaring only the originally-requested targets
            # would let Maven's own dependency mediation pick transitive
            # versions independently at install time, which could drift
            # from what was actually scanned.
            coordinates = []
            for coordinate, version in resolution.resolved_versions.items():
                group_id, _, artifact_id = coordinate.partition(":")
                coordinates.append((group_id, artifact_id, version))

            pom_path = temp_path / "pom.xml"
            pom_path.write_bytes(_build_scratch_pom(coordinates).encode("utf-8"))

            # See module docstring: `dependency:get` only accepts one
            # coordinate per invocation (confirmed directly), incompatible
            # with pinning more than one resolved package in a single
            # yielded command. `dependency:resolve` against this scratch
            # pom downloads every declared dependency into the local
            # repository (~/.m2) in one real invocation instead (confirmed
            # directly against a real two-artifact scratch pom, run via
            # `-f <path>` from an unrelated working directory).
            yield [resolve_maven_tool("mvn"), "-B", "-f", str(pom_path), "dependency:resolve"]

    def install_command(self, artifact_paths: list[str]) -> list[str]:
        # Only reachable if a future lockfile-shaped resolution path is
        # added (see module docstring) -- today resolve() never produces
        # a source_type host_install_command would fall back to this for,
        # since maven has no lockfile_patterns. Raising rather than
        # guessing at a command keeps that honest instead of shipping an
        # untested path.
        raise RuntimeError("maven has no lockfile-based install path yet -- resolve a package coordinate instead")

    def uninstall_command(self, package_names: list[str]) -> list[str]:
        # `dependency:get`/`dependency:resolve` only ever download into
        # the local repository (~/.m2) -- unlike `cargo remove`/`go get
        # @none`, neither edits a pom.xml, so there's nothing well-defined
        # to reverse. cli/commands/uninstall.py already catches this
        # RuntimeError and reports it as a clean usage error.
        raise RuntimeError(
            "maven has no uninstall equivalent -- `mvn dependency:get`/`dependency:resolve` only "
            "download artifacts into the local repository, they never edit a pom.xml the way "
            "`cargo remove`/`go get @none` edit their manifests, so there's nothing well-defined to reverse"
        )


MAVEN_ECOSYSTEM = MavenEcosystem()
