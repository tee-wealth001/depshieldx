import os
import shutil
import subprocess
import tarfile
import tempfile
import uuid
from dataclasses import dataclass
import json
import hashlib
from pathlib import Path
from typing import Any, List, Optional

import click
from packaging.utils import canonicalize_name, parse_sdist_filename, parse_wheel_filename

from ..artifact_analysis import analyze_artifacts
from ...storage.cache import fingerprint_artifacts, load_cache_entry, store_cache_entry
from ...ecosystems import PYPI_ECOSYSTEM
from ...ecosystems.go.registry import (
    escape_module_path,
    fetch_go_mod_text,
    fetch_module_zip,
    fetch_version_metadata,
    hash1_of_go_mod,
    hash1_of_zip,
)
from ...ecosystems.maven.ecosystem import _build_scratch_pom
from ...ecosystems.maven.registry import (
    fetch_pom_text,
    group_path,
    parse_bom_import_coordinates,
    parse_parent_coordinate,
)
from ...ecosystems.nuget.ecosystem import _build_scratch_csproj, resolve_dotnet_tool
from ...ecosystems.pub.ecosystem import _build_scratch_pubspec, resolve_dart_tool
from ...ecosystems.rubygems.ecosystem import _build_scratch_gemfile
from ...ecosystems.rubygems.lockfiles import write_gemfile_lock
from ...core.resolver import ResolutionResult
from ...core.runtime import pip_command, resource_path, system_python_executable
from ..trivy import scan_filesystem

DOCKER_IMAGE = "python:3.11"
# Built locally from security/sandbox/docker/npm_sandbox.Dockerfile (node:20 + strace) the
# first time npm deep mode runs -- plain node:20 has no strace (confirmed
# directly: `which strace` -> not found), and the sandbox container's
# rootfs runs --read-only, so it can't be apt-get installed at container
# run time either. No external registry involved.
NPM_SANDBOX_IMAGE_TAG = "depshieldx-npm-sandbox:node20"
# Same reasoning as NPM_SANDBOX_IMAGE_TAG -- built locally from
# security/sandbox/docker/cargo_sandbox.Dockerfile (rust:1-slim + strace + python3, the
# latter confirmed missing from the base image too, unlike python:3.11
# which already has an interpreter for PyPI's own wrapper).
CARGO_SANDBOX_IMAGE_TAG = "depshieldx-cargo-sandbox:rust1"
# Same reasoning as CARGO_SANDBOX_IMAGE_TAG -- built locally from
# security/sandbox/docker/go_sandbox.Dockerfile (golang:1-bookworm +
# strace + python3). There is no "golang:1-slim" tag (confirmed directly
# against Docker Hub's real tag list), unlike rust:1-slim/node:20 --
# golang:1-bookworm is the closest equivalent, and already ships python3
# in its base layer (confirmed directly), though the Dockerfile still
# installs it explicitly for robustness, matching the other two images.
GO_SANDBOX_IMAGE_TAG = "depshieldx-go-sandbox:go1"
# Same reasoning as GO_SANDBOX_IMAGE_TAG -- built locally from
# security/sandbox/docker/maven_sandbox.Dockerfile (maven:3-eclipse-
# temurin-21 + strace + python3, both confirmed missing from the base
# image, plus a build-time-only pre-warmed plugin cache -- see that
# Dockerfile's own docstring for why Maven's sandbox needs one and
# cargo/go's don't).
MAVEN_SANDBOX_IMAGE_TAG = "depshieldx-maven-sandbox:maven3"
# Same reasoning as MAVEN_SANDBOX_IMAGE_TAG -- built locally from
# security/sandbox/docker/nuget_sandbox.Dockerfile (mcr.microsoft.com/
# dotnet/sdk:8.0 + strace + python3, both confirmed missing from the
# base image). Unlike Maven, no build-time pre-warming is needed --
# confirmed directly `dotnet restore` needs nothing beyond what the .NET
# SDK itself already ships.
NUGET_SANDBOX_IMAGE_TAG = "depshieldx-nuget-sandbox:sdk8"
# Same reasoning as NUGET_SANDBOX_IMAGE_TAG -- built locally from
# security/sandbox/docker/pub_sandbox.Dockerfile (dart:3 + strace +
# python3, both confirmed missing from the base image). Like NuGet, no
# build-time pre-warming is needed -- confirmed directly `dart pub get
# --offline` needs nothing beyond what the Dart SDK itself already
# ships, once $PUB_CACHE is writable (see that Dockerfile's own
# docstring for the one real wrinkle there).
PUB_SANDBOX_IMAGE_TAG = "depshieldx-pub-sandbox:dart3"
# Unlike every other *_SANDBOX_IMAGE_TAG here, built from plain `ruby:3`
# rather than a `-slim`/minimal variant -- confirmed directly `ruby:3`
# already ships gcc/make (needed for real native-extension gems to build
# successfully inside the sandbox) and python3 (unlike node:20/rust:1-
# slim/dart:3, which all needed it installed explicitly), only strace is
# missing. See rubygems_sandbox.Dockerfile's own module docstring for the
# full reasoning, including why `bundle install` never runs host-side.
RUBYGEMS_SANDBOX_IMAGE_TAG = "depshieldx-rubygems-sandbox:ruby3"
SANDBOX_USER = "65534:65534"


@dataclass
class DownloadBundle:
    temp_dir: str
    downloaded_files: List[str]
    artifact_hashes: dict[str, str]
    requirements_path: str
    static_analysis: dict
    fingerprint: str
    cleanup: bool = True


@dataclass
class SandboxResult:
    success: bool
    downloaded_files: List[str]
    error: Optional[str]
    error_type: Optional[str]
    isolation: dict
    evidence: Optional[dict]
    static_analysis: Optional[dict]
    bundle: Optional[DownloadBundle]
    cache: Optional[dict]
    trivy_results: Optional[dict] = None


REPORT_PREFIX = "DEPSHIELDX_SANDBOX_REPORT="
TEXT_SUBPROCESS_KWARGS = {
    "text": True,
    "encoding": "utf-8",
    "errors": "replace",
}


def _run_command(command: List[str], verbose: bool = False) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            **TEXT_SUBPROCESS_KWARGS,
        )
    except subprocess.CalledProcessError as exc:
        if verbose:
            _emit_command_output(exc.stdout, exc.stderr)
        raise
    if verbose:
        _emit_command_output(result.stdout, result.stderr)
    return result


def _emit_command_output(stdout: Optional[str], stderr: Optional[str], suppress_prefixes: tuple[str, ...] = ()) -> None:
    for stream in (stdout, stderr):
        if not stream:
            continue
        for line in stream.splitlines():
            if any(line.startswith(prefix) for prefix in suppress_prefixes):
                continue
            print(line)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact_identity(path: Path) -> Optional[tuple[str, str]]:
    try:
        if path.suffix == ".whl":
            name, version, _, _ = parse_wheel_filename(path.name)
            return canonicalize_name(str(name)), str(version)
        if path.suffixes[-2:] == [".tar", ".gz"] or path.suffix == ".zip":
            name, version = parse_sdist_filename(path.name)
            return canonicalize_name(str(name)), str(version)
    except Exception:
        return None
    return None


def _build_locked_requirements(temp_dir: str, resolved_versions: dict[str, str]) -> tuple[str, dict[str, str]]:
    package_dir = Path(temp_dir)
    artifacts = [path for path in package_dir.iterdir() if path.is_file()]
    artifact_hashes = {path.name: _sha256_file(path) for path in artifacts}
    artifacts_by_key: dict[tuple[str, str], Path] = {}

    for artifact in artifacts:
        identity = _artifact_identity(artifact)
        if not identity:
            continue
        existing = artifacts_by_key.get(identity)
        if existing is None or (artifact.suffix == ".whl" and existing.suffix != ".whl"):
            artifacts_by_key[identity] = artifact

    locked_requirements = []
    versions = {canonicalize_name(name): version for name, version in resolved_versions.items() if version}
    if not versions:
        for (name, version), artifact in sorted(artifacts_by_key.items()):
            locked_requirements.append(
                f"{name}=={version} --hash=sha256:{artifact_hashes[artifact.name]}"
            )
    else:
        missing = []
        for name, version in sorted(versions.items()):
            artifact = artifacts_by_key.get((name, version))
            if artifact is None:
                missing.append(f"{name}=={version}")
                continue
            locked_requirements.append(
                f"{name}=={version} --hash=sha256:{artifact_hashes[artifact.name]}"
            )
        if missing:
            raise RuntimeError(
                "downloaded artifact set does not match resolved packages: " + ", ".join(missing)
            )

    requirements_path = str(package_dir / "depshieldx-lock.txt")
    Path(requirements_path).write_text("\n".join(locked_requirements) + "\n")
    return requirements_path, artifact_hashes


def _extract_report(output: str) -> Optional[dict[str, Any]]:
    for line in output.splitlines():
        if line.startswith(REPORT_PREFIX):
            try:
                return json.loads(line[len(REPORT_PREFIX):])
            except json.JSONDecodeError:
                return None
    return None


def _sandbox_cache_fingerprint(
    artifact_hashes: dict[str, str],
    backend: str,
    require_docker: bool = False,
    block_on_static_analysis: bool = True,
    block_on_trivy: bool = False,
    ecosystem: str = "pypi",
) -> str:
    return fingerprint_artifacts(
        {
            **artifact_hashes,
            "__sandbox_backend__": backend,
            "__require_docker__": str(require_docker).lower(),
            "__block_on_static_analysis__": str(block_on_static_analysis).lower(),
            "__block_on_trivy__": str(block_on_trivy).lower(),
            "__ecosystem__": ecosystem,
        }
    )


def _docker_daemon_available() -> tuple[bool, Optional[str]]:
    try:
        result = subprocess.run(
            ["docker", "info"],
            check=True,
            capture_output=True,
            **TEXT_SUBPROCESS_KWARGS,
        )
        return True, None
    except FileNotFoundError:
        return False, "Docker CLI not found. Install Docker Desktop or Docker Engine to use deep mode."
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or str(exc)).strip()
        return False, f"Docker daemon unavailable: {detail}"


def _ensure_npm_sandbox_image(verbose: bool = False) -> None:
    """Build depshieldx's node:20 + strace image if it isn't already
    present locally. `docker build` is a no-op-fast if the image (and its
    layers) already exist, but `docker image inspect` avoids even that
    overhead on the common case."""
    inspect = subprocess.run(
        ["docker", "image", "inspect", NPM_SANDBOX_IMAGE_TAG],
        capture_output=True,
        **TEXT_SUBPROCESS_KWARGS,
    )
    if inspect.returncode == 0:
        return

    dockerfile = resource_path("security/sandbox/docker/npm_sandbox.Dockerfile")
    build_command = [
        "docker",
        "build",
        "-f",
        str(dockerfile),
        "-t",
        NPM_SANDBOX_IMAGE_TAG,
        str(dockerfile.parent),
    ]
    _run_command(build_command, verbose=verbose)


def _ensure_cargo_sandbox_image(verbose: bool = False) -> None:
    """Build depshieldx's rust:1-slim + strace + python3 image if it isn't
    already present locally. Mirrors _ensure_npm_sandbox_image exactly."""
    inspect = subprocess.run(
        ["docker", "image", "inspect", CARGO_SANDBOX_IMAGE_TAG],
        capture_output=True,
        **TEXT_SUBPROCESS_KWARGS,
    )
    if inspect.returncode == 0:
        return

    dockerfile = resource_path("security/sandbox/docker/cargo_sandbox.Dockerfile")
    build_command = [
        "docker",
        "build",
        "-f",
        str(dockerfile),
        "-t",
        CARGO_SANDBOX_IMAGE_TAG,
        str(dockerfile.parent),
    ]
    _run_command(build_command, verbose=verbose)


def _ensure_go_sandbox_image(verbose: bool = False) -> None:
    """Build depshieldx's golang:1-bookworm + strace + python3 image if it
    isn't already present locally. Mirrors _ensure_cargo_sandbox_image
    exactly."""
    inspect = subprocess.run(
        ["docker", "image", "inspect", GO_SANDBOX_IMAGE_TAG],
        capture_output=True,
        **TEXT_SUBPROCESS_KWARGS,
    )
    if inspect.returncode == 0:
        return

    dockerfile = resource_path("security/sandbox/docker/go_sandbox.Dockerfile")
    build_command = [
        "docker",
        "build",
        "-f",
        str(dockerfile),
        "-t",
        GO_SANDBOX_IMAGE_TAG,
        str(dockerfile.parent),
    ]
    _run_command(build_command, verbose=verbose)


def _ensure_maven_sandbox_image(verbose: bool = False) -> None:
    """Build depshieldx's maven:3-eclipse-temurin-21 + strace + python3 +
    pre-warmed plugin cache image if it isn't already present locally.
    Mirrors _ensure_go_sandbox_image exactly."""
    inspect = subprocess.run(
        ["docker", "image", "inspect", MAVEN_SANDBOX_IMAGE_TAG],
        capture_output=True,
        **TEXT_SUBPROCESS_KWARGS,
    )
    if inspect.returncode == 0:
        return

    dockerfile = resource_path("security/sandbox/docker/maven_sandbox.Dockerfile")
    build_command = [
        "docker",
        "build",
        "-f",
        str(dockerfile),
        "-t",
        MAVEN_SANDBOX_IMAGE_TAG,
        str(dockerfile.parent),
    ]
    _run_command(build_command, verbose=verbose)


def _ensure_nuget_sandbox_image(verbose: bool = False) -> None:
    """Build depshieldx's dotnet/sdk:8.0 + strace + python3 image if it
    isn't already present locally. Mirrors _ensure_maven_sandbox_image,
    minus the plugin-cache pre-warming Maven's own version needs (see
    nuget_sandbox.Dockerfile's docstring for why NuGet doesn't)."""
    inspect = subprocess.run(
        ["docker", "image", "inspect", NUGET_SANDBOX_IMAGE_TAG],
        capture_output=True,
        **TEXT_SUBPROCESS_KWARGS,
    )
    if inspect.returncode == 0:
        return

    dockerfile = resource_path("security/sandbox/docker/nuget_sandbox.Dockerfile")
    build_command = [
        "docker",
        "build",
        "-f",
        str(dockerfile),
        "-t",
        NUGET_SANDBOX_IMAGE_TAG,
        str(dockerfile.parent),
    ]
    _run_command(build_command, verbose=verbose)


def _ensure_pub_sandbox_image(verbose: bool = False) -> None:
    """Build depshieldx's dart:3 + strace + python3 image if it isn't
    already present locally. Mirrors _ensure_nuget_sandbox_image -- no
    plugin-cache pre-warming needed (see pub_sandbox.Dockerfile's
    docstring)."""
    inspect = subprocess.run(
        ["docker", "image", "inspect", PUB_SANDBOX_IMAGE_TAG],
        capture_output=True,
        **TEXT_SUBPROCESS_KWARGS,
    )
    if inspect.returncode == 0:
        return

    dockerfile = resource_path("security/sandbox/docker/pub_sandbox.Dockerfile")
    build_command = [
        "docker",
        "build",
        "-f",
        str(dockerfile),
        "-t",
        PUB_SANDBOX_IMAGE_TAG,
        str(dockerfile.parent),
    ]
    _run_command(build_command, verbose=verbose)


def _ensure_rubygems_sandbox_image(verbose: bool = False) -> None:
    """Build depshieldx's ruby:3 + strace image if it isn't already
    present locally. Mirrors _ensure_pub_sandbox_image -- no pre-warming
    needed (see rubygems_sandbox.Dockerfile's docstring)."""
    inspect = subprocess.run(
        ["docker", "image", "inspect", RUBYGEMS_SANDBOX_IMAGE_TAG],
        capture_output=True,
        **TEXT_SUBPROCESS_KWARGS,
    )
    if inspect.returncode == 0:
        return

    dockerfile = resource_path("security/sandbox/docker/rubygems_sandbox.Dockerfile")
    build_command = [
        "docker",
        "build",
        "-f",
        str(dockerfile),
        "-t",
        RUBYGEMS_SANDBOX_IMAGE_TAG,
        str(dockerfile.parent),
    ]
    _run_command(build_command, verbose=verbose)


def _run_local_sandbox(bundle: DownloadBundle, install_targets: list[str], verbose: bool) -> subprocess.CompletedProcess:
    command = [
        system_python_executable(),
        "-I",
        str(resource_path("security/sandbox/sandbox_wrapper.py")),
        bundle.temp_dir,
        *install_targets,
    ]
    result = _run_command(command, verbose=False)
    if verbose:
        _emit_command_output(result.stdout, result.stderr, suppress_prefixes=(REPORT_PREFIX,))
    return result


def download_packages(install_targets: list[str], temp_dir: str, verbose: bool = False) -> None:
    """
    Download the target package and dependencies inside the same Linux image
    used for sandbox installation so wheel selection matches the sandbox.
    """
    docker_command = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{temp_dir}:/tmp/packages",
        DOCKER_IMAGE,
        "python",
        "-m",
        "pip",
        "download",
        "--dest",
        "/tmp/packages",
        *install_targets,
    ]
    _run_command(docker_command, verbose=verbose)


def download_packages_local(install_targets: list[str], temp_dir: str, verbose: bool = False) -> None:
    """
    Download host-compatible artifacts directly on the current interpreter.
    Used when Docker is unavailable and the sandbox falls back to a local guarded subprocess.
    """
    _run_command(
        pip_command(["download", "--dest", temp_dir, *install_targets]),
        verbose=verbose,
    )


def prepare_download_bundle(
    install_targets: list[str],
    resolved_versions: Optional[dict[str, str]] = None,
    verbose: bool = False,
    download_via_host: bool = False,
) -> DownloadBundle:
    temp_dir = tempfile.mkdtemp(prefix="depshieldx_")
    try:
        if download_via_host:
            download_packages_local(install_targets, temp_dir, verbose=verbose)
        else:
            download_packages(install_targets, temp_dir, verbose=verbose)
        downloaded_files = sorted(
            path.name
            for path in Path(temp_dir).iterdir()
            if path.is_file() and path.name != "depshieldx-lock.txt"
        )
        static_analysis = analyze_artifacts(temp_dir)
        requirements_path, artifact_hashes = _build_locked_requirements(
            temp_dir,
            resolved_versions or {},
        )
        return DownloadBundle(
            temp_dir=temp_dir,
            downloaded_files=downloaded_files,
            artifact_hashes=artifact_hashes,
            requirements_path=requirements_path,
            static_analysis=static_analysis,
            fingerprint=fingerprint_artifacts(artifact_hashes),
        )
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def cleanup_download_bundle(bundle: DownloadBundle) -> None:
    if bundle.cleanup:
        shutil.rmtree(bundle.temp_dir, ignore_errors=True)


def prepare_npm_download_bundle(ecosystem, resolved_versions: dict[str, str]) -> DownloadBundle:
    """npm's counterpart to prepare_download_bundle -- downloads (and, via
    fetch_artifact, SRI-integrity-verifies) every resolved package's real
    tarball on the host, entirely outside the network-isolated sandbox
    container, mirroring why PyPI's download step also happens before the
    isolated container starts. No pip-style hash-locked requirements file is
    needed here -- npm's own registry-provided SRI digests already give the
    same guarantee fetch_artifact already checked; depshieldx-lock.txt is
    still written (as a plain name@version list, not a real npm format) so
    the shared DownloadBundle/caching code has something to round-trip.
    """
    temp_dir = tempfile.mkdtemp(prefix="depshieldx_")
    try:
        resolution = ResolutionResult(
            packages=list(resolved_versions.keys()),
            install_target="",
            resolved_versions=resolved_versions,
        )
        for _, _, artifact in ecosystem.selected_artifact_entries(resolution):
            ecosystem.fetch_artifact(artifact, Path(temp_dir))

        downloaded_files = sorted(path.name for path in Path(temp_dir).iterdir() if path.is_file())
        static_analysis = analyze_artifacts(temp_dir)
        artifact_hashes = {path.name: _sha256_file(path) for path in Path(temp_dir).iterdir() if path.is_file()}

        requirements_path = str(Path(temp_dir) / "depshieldx-lock.txt")
        Path(requirements_path).write_text(
            "\n".join(f"{name}@{version}" for name, version in sorted(resolved_versions.items())) + "\n"
        )

        return DownloadBundle(
            temp_dir=temp_dir,
            downloaded_files=downloaded_files,
            artifact_hashes=artifact_hashes,
            requirements_path=requirements_path,
            static_analysis=static_analysis,
            fingerprint=fingerprint_artifacts(artifact_hashes),
        )
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def prepare_cargo_download_bundle(ecosystem, resolved_versions: dict[str, str]) -> DownloadBundle:
    """cargo's counterpart to prepare_npm_download_bundle -- downloads (and,
    via fetch_artifact, checksum-verifies) every resolved crate's real
    .crate tarball on the host, same as npm's version. Also builds a Cargo
    "directory source" vendor tree (each tarball extracted into its own
    <name>-<version>/ subdirectory with a minimal .cargo-checksum.json),
    since that's cargo's actual supported offline-install mechanism --
    reproduced directly that cargo has no equivalent of npm's "install from
    a local tarball path" verb, and always needs to resolve against *some*
    source, live registry or a local directory replacement. The raw
    checksum accuracy inside .cargo-checksum.json doesn't matter for our
    security model: each tarball's own bytes were already SHA256-verified
    against crates.io's registry-reported checksum in fetch_artifact before
    ever being extracted here, which is the same guarantee real vendor
    checksums would provide -- confirmed directly this minimal/unverified
    form doesn't block `cargo fetch --offline` from working.

    The vendor directory lives at <temp_dir>/vendor -- a fixed, predictable
    subpath, so run_sandbox() doesn't need a new DownloadBundle field to
    find it.
    """
    temp_dir = tempfile.mkdtemp(prefix="depshieldx_")
    try:
        resolution = ResolutionResult(
            packages=list(resolved_versions.keys()),
            install_target="",
            resolved_versions=resolved_versions,
        )
        for name, version, artifact in ecosystem.selected_artifact_entries(resolution):
            artifact_path = ecosystem.fetch_artifact(artifact, Path(temp_dir))
            vendor_entry = Path(temp_dir) / "vendor" / f"{name}-{version}"
            vendor_entry.mkdir(parents=True, exist_ok=True)
            with tarfile.open(artifact_path, "r:gz") as archive:
                # filter="data" (path-traversal/symlink hardening, PEP 706)
                # was backported to Python 3.11.4 -- confirmed directly
                # against the official 3.11 changelog -- which is exactly
                # this project's own requires-python floor (pyproject.toml),
                # so every supported interpreter has it. Deliberately no
                # except/fallback here: silently downgrading to unfiltered
                # extractall on any TypeError would turn a real
                # path-traversal defense into a no-op the moment it's
                # needed, for a case that isn't actually reachable on a
                # supported interpreter anyway.
                archive.extractall(vendor_entry, filter="data")
            # .crate tarballs contain one top-level "<name>-<version>/" dir
            # (confirmed directly) -- flatten it so vendor_entry's contents
            # match the layout `cargo vendor` itself produces.
            nested = list(vendor_entry.iterdir())
            if len(nested) == 1 and nested[0].is_dir():
                for child in nested[0].iterdir():
                    child.rename(vendor_entry / child.name)
                nested[0].rmdir()
            (vendor_entry / ".cargo-checksum.json").write_text('{"files":{},"package":""}')

        downloaded_files = sorted(
            path.name for path in Path(temp_dir).iterdir() if path.is_file()
        )
        static_analysis = analyze_artifacts(temp_dir)
        artifact_hashes = {
            path.name: _sha256_file(path) for path in Path(temp_dir).iterdir() if path.is_file()
        }

        requirements_path = str(Path(temp_dir) / "depshieldx-lock.txt")
        Path(requirements_path).write_text(
            "\n".join(f"{name}@{version}" for name, version in sorted(resolved_versions.items())) + "\n"
        )

        return DownloadBundle(
            temp_dir=temp_dir,
            downloaded_files=downloaded_files,
            artifact_hashes=artifact_hashes,
            requirements_path=requirements_path,
            static_analysis=static_analysis,
            fingerprint=fingerprint_artifacts(artifact_hashes),
        )
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def prepare_go_download_bundle(ecosystem, resolved_versions: dict[str, str]) -> DownloadBundle:
    """Go's counterpart to prepare_cargo_download_bundle -- downloads every
    resolved module's real .info/.mod/.zip content from the real GOPROXY
    (proxy.golang.org, via ecosystems/go/registry.py's already-verified
    fetchers) and lays it out host-side exactly as Go's own file-based
    GOPROXY protocol expects (<escaped-module>/@v/<version>.{info,mod,zip}
    under a "goproxy/" subdirectory), so the sandboxed `go mod download`
    (sandbox_wrapper_go.py) can resolve entirely offline via
    GOPROXY=file://... -- confirmed directly against a real Docker
    container under this project's full isolation posture (--network none,
    --read-only, --cap-drop ALL, non-root user).

    Also writes go.mod (every resolved module as a direct requirement,
    same "pin everything, not just the requested targets" reasoning as
    prepare_cargo_download_bundle) and go.sum host-side, computed directly
    from the just-downloaded zip/mod bytes via go_registry.py's Hash1
    reimplementation -- avoiding a second network round-trip to
    sum.golang.org's lookup endpoint for the same values
    fetch_module_checksum() would return, since the exact bytes are
    already on hand and the algorithm's correctness is independently
    verified (see ecosystems/go/registry.py's module docstring). The .info
    file's content isn't part of any go.sum hash (confirmed directly --
    only the .zip and .mod hashes are), so re-serializing its parsed JSON
    rather than storing the exact original bytes is safe.

    Every downloaded .zip is also copied flat into temp_dir's root (not
    just the nested goproxy/ layout) so analyze_artifacts() finds it the
    same way it already finds .whl/.crate files -- Go module zips are
    plain zip archives (confirmed directly), so the existing generic
    zip-extraction branch in artifact_analysis.py needs no Go-specific
    code, only ".go" added to TEXT_EXTENSIONS.
    """
    temp_dir = tempfile.mkdtemp(prefix="depshieldx_")
    try:
        proxy_dir = Path(temp_dir) / "goproxy"
        go_sum_lines: List[str] = []
        for module, version in resolved_versions.items():
            # The local file-based proxy follows the same "!"-escaping the
            # real network GOPROXY protocol requires for uppercase-letter
            # module paths (confirmed directly for the network path in
            # ecosystems/go/registry.py; both share the same underlying
            # module-fetcher code in the real `go` toolchain).
            module_v_dir = proxy_dir / escape_module_path(module) / "@v"
            module_v_dir.mkdir(parents=True, exist_ok=True)

            info_payload = fetch_version_metadata(module, version)
            (module_v_dir / f"{version}.info").write_bytes(json.dumps(info_payload).encode("utf-8"))

            mod_text = fetch_go_mod_text(module, version)
            if mod_text is None:
                raise RuntimeError(f"could not fetch go.mod for {module}@{version}")
            # write_bytes, not write_text: write_text silently translates
            # "\n" to the platform newline (CRLF on Windows), which changes
            # the file's actual on-disk bytes relative to whatever was
            # hashed below -- confirmed directly this causes a real
            # "checksum mismatch" SECURITY ERROR from `go mod download`
            # itself when this bundle is built on a Windows host, since the
            # go.sum hash is computed from the original (LF) mod_text
            # string but the file on disk had been silently rewritten to
            # CRLF.
            mod_bytes = mod_text.encode("utf-8")
            (module_v_dir / f"{version}.mod").write_bytes(mod_bytes)

            zip_bytes = fetch_module_zip(module, version)
            (module_v_dir / f"{version}.zip").write_bytes(zip_bytes)
            (module_v_dir / "list").write_bytes((version + "\n").encode("utf-8"))

            flat_name = f"{module.replace('/', '_')}@{version}.zip"
            (Path(temp_dir) / flat_name).write_bytes(zip_bytes)

            go_sum_lines.append(f"{module} {version} {hash1_of_zip(zip_bytes)}")
            go_sum_lines.append(f"{module} {version}/go.mod {hash1_of_go_mod(mod_bytes)}")

        go_mod_lines = ["module depshieldx-sandbox", "", "go 1.21", ""]
        go_mod_lines.extend(
            f"require {module} {version}" for module, version in sorted(resolved_versions.items())
        )
        (Path(temp_dir) / "go.mod").write_bytes(("\n".join(go_mod_lines) + "\n").encode("utf-8"))
        (Path(temp_dir) / "go.sum").write_bytes(("\n".join(sorted(go_sum_lines)) + "\n").encode("utf-8"))

        downloaded_files = sorted(path.name for path in Path(temp_dir).iterdir() if path.is_file())
        static_analysis = analyze_artifacts(temp_dir)
        artifact_hashes = {path.name: _sha256_file(path) for path in Path(temp_dir).iterdir() if path.is_file()}

        requirements_path = str(Path(temp_dir) / "depshieldx-lock.txt")
        Path(requirements_path).write_text(
            "\n".join(f"{name}@{version}" for name, version in sorted(resolved_versions.items())) + "\n"
        )

        return DownloadBundle(
            temp_dir=temp_dir,
            downloaded_files=downloaded_files,
            artifact_hashes=artifact_hashes,
            requirements_path=requirements_path,
            static_analysis=static_analysis,
            fingerprint=fingerprint_artifacts(artifact_hashes),
        )
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def prepare_maven_download_bundle(ecosystem, resolved_versions: dict[str, str]) -> DownloadBundle:
    """Maven's counterpart to prepare_go_download_bundle -- downloads (and,
    via fetch_artifact, checksum-verifies) every resolved coordinate's real
    .jar and fetches its real .pom on the host, laying both out host-side
    exactly as a real Maven local repository expects (<group-path>/
    <artifactId>/<version>/<artifactId>-<version>.{jar,pom}), so the
    sandboxed `mvn --offline dependency:resolve`
    (sandbox_wrapper_maven.py) can resolve entirely offline via
    -Dmaven.repo.local=... -- confirmed directly against a real Docker
    container under this project's full isolation posture (--network
    none, --read-only, --cap-drop ALL, non-root user).

    Also recursively walks and fetches every resolved artifact's real
    <parent> POM chain AND every <dependencyManagement> BOM import
    (registry.py's parse_parent_coordinate/parse_bom_import_coordinates),
    writing those into the same repository layout (POM only -- neither is
    a real jar: parent POMs are metadata-only inheritance, BOM imports are
    packaging=pom dependency-version catalogs). Confirmed directly both
    are required, not optional: Maven's dependency collector fails
    outright on a missing parent POM or BOM import even when the child
    artifact's own jar+pom are both present and correct -- two real
    examples confirmed directly: com.google.errorprone:error_prone_
    annotations:2.27.0's parent (error_prone_parent:2.27.0), and org.
    apache.commons:commons-lang3:3.17.0's parent chain importing org.
    junit:junit-bom as dependency-management (neither is ever itself a
    `dependency:list` entry). Every fetched POM is itself walked the same
    way (a BOM can have its own parent; a parent can itself import
    further BOMs), with a shared `fetched` set for cycle-safety and to
    avoid re-fetching. Fetched over plain HTTPS without a separate
    checksum/Sigstore re-verification pass -- they're pure XML build-graph
    metadata (no executable code), unlike the actual installable jars
    Stage 1's provenance check already covers; TLS already gives
    transport integrity for that narrower purpose.

    Real, accepted coverage gap (see parse_bom_import_coordinates'
    docstring): a BOM import's version is sometimes a "${property}"
    placeholder resolved only against that same POM's own <properties>
    block, not the fuller cross-file property-inheritance Maven's real
    resolver supports. An unresolvable entry is skipped rather than
    guessed at -- if it turns out to be genuinely required, the sandboxed
    `mvn --offline` step still fails with a clear, real Maven error naming
    exactly what's missing (verified directly: this is what happens today
    for that exact case), not a silently wrong resolution.

    Also writes a scratch pom.xml (every resolved coordinate as a direct
    dependency, reusing ecosystems/maven/ecosystem.py's own
    _build_scratch_pom -- same "pin everything, not just the requested
    targets" reasoning as prepare_cargo_download_bundle/
    prepare_go_download_bundle) for the sandboxed dependency:resolve to
    run against.

    Every downloaded .jar is also copied flat into temp_dir's root (group-
    id-prefixed to avoid same-artifactId-different-group collisions,
    e.g. "com.example_widget-1.0.0.jar") so analyze_artifacts() finds it
    the same way it already finds .whl/.crate/.zip files -- real jars are
    plain zip archives (confirmed directly), so the existing generic
    zip-extraction branch in artifact_analysis.py only needs ".jar" added
    to the top-level archive-suffix check, no new extraction code.
    """
    temp_dir = tempfile.mkdtemp(prefix="depshieldx_")
    try:
        m2_repo = Path(temp_dir) / "m2-repo"
        fetched_metadata_poms: set[tuple[str, str, str]] = set()

        def _write_pom(group_id: str, artifact_id: str, version: str, pom_text: str) -> Path:
            entry_dir = m2_repo / group_path(group_id) / artifact_id / version
            entry_dir.mkdir(parents=True, exist_ok=True)
            pom_path = entry_dir / f"{artifact_id}-{version}.pom"
            pom_path.write_bytes(pom_text.encode("utf-8"))
            return entry_dir

        def _fetch_pom_metadata_chain(pom_text: str) -> None:
            # Both directions -- <parent> inheritance and <dependencyManagement>
            # BOM imports -- can each lead to further POMs needing the same
            # treatment (a BOM can have its own parent; a parent can itself
            # import further BOMs), so every newly-fetched POM's text is
            # walked the same way, not just the top-level artifact's.
            candidates = list(parse_bom_import_coordinates(pom_text))
            parent = parse_parent_coordinate(pom_text)
            if parent is not None:
                candidates.append(parent)

            for group_id, artifact_id, version in candidates:
                if (group_id, artifact_id, version) in fetched_metadata_poms:
                    continue
                fetched_metadata_poms.add((group_id, artifact_id, version))
                try:
                    metadata_pom_text = fetch_pom_text(group_id, artifact_id, version)
                except Exception:
                    # See module docstring: an unresolvable BOM/parent
                    # reference (e.g. a property that isn't defined
                    # locally) is skipped rather than crashing bundle
                    # prep -- the sandboxed offline resolve step still
                    # fails with a clear, real error if it turns out to
                    # have been required.
                    continue
                _write_pom(group_id, artifact_id, version, metadata_pom_text)
                _fetch_pom_metadata_chain(metadata_pom_text)

        resolution = ResolutionResult(
            packages=list(resolved_versions.keys()),
            install_target="",
            resolved_versions=resolved_versions,
        )
        resolved_coordinates: List[tuple[str, str, str]] = []
        for coordinate, version, artifact in ecosystem.selected_artifact_entries(resolution):
            group_id, _, artifact_id = coordinate.partition(":")
            resolved_coordinates.append((group_id, artifact_id, version))

            entry_dir = m2_repo / group_path(group_id) / artifact_id / version
            entry_dir.mkdir(parents=True, exist_ok=True)
            ecosystem.fetch_artifact(artifact, entry_dir)

            pom_text = fetch_pom_text(group_id, artifact_id, version)
            (entry_dir / f"{artifact_id}-{version}.pom").write_bytes(pom_text.encode("utf-8"))

            flat_name = f"{group_id}_{artifact_id}-{version}.jar"
            (Path(temp_dir) / flat_name).write_bytes((entry_dir / f"{artifact_id}-{version}.jar").read_bytes())

            fetched_metadata_poms.add((group_id, artifact_id, version))
            _fetch_pom_metadata_chain(pom_text)

        pom_path = Path(temp_dir) / "pom.xml"
        pom_path.write_bytes(_build_scratch_pom(resolved_coordinates).encode("utf-8"))

        downloaded_files = sorted(path.name for path in Path(temp_dir).iterdir() if path.is_file())
        static_analysis = analyze_artifacts(temp_dir)
        artifact_hashes = {path.name: _sha256_file(path) for path in Path(temp_dir).iterdir() if path.is_file()}

        requirements_path = str(Path(temp_dir) / "depshieldx-lock.txt")
        Path(requirements_path).write_text(
            "\n".join(f"{name}@{version}" for name, version in sorted(resolved_versions.items())) + "\n"
        )

        return DownloadBundle(
            temp_dir=temp_dir,
            downloaded_files=downloaded_files,
            artifact_hashes=artifact_hashes,
            requirements_path=requirements_path,
            static_analysis=static_analysis,
            fingerprint=fingerprint_artifacts(artifact_hashes),
        )
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


# The container-side bind-mount path every ecosystem's bundle directory is
# mounted at (confirmed directly against the other three deep-mode
# ecosystems' own run_sandbox() branches below) -- baked into the host-
# side NuGet.Config here since sandbox_wrapper_nuget.py just copies that
# file as-is, it doesn't rewrite paths itself.
_NUGET_SANDBOX_BUNDLE_MOUNT_PATH = "/tmp/packages"


def _build_nuget_config(source_path: str) -> str:
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<configuration>\n"
        "  <packageSources>\n"
        "    <clear />\n"
        f'    <add key="local" value="{source_path}" />\n'
        "  </packageSources>\n"
        "</configuration>\n"
    )


def prepare_nuget_download_bundle(ecosystem, resolved_versions: dict[str, str]) -> DownloadBundle:
    """NuGet's counterpart to prepare_maven_download_bundle -- downloads
    (and, via fetch_artifact, checksum-verifies against the registry's
    own reported hash) every resolved package's real .nupkg directly into
    temp_dir's root, laid out exactly as NuGet's own local-folder package-
    source mechanism expects (a flat directory of .nupkg files, no
    hierarchical extraction needed -- confirmed directly against a real
    Docker container under this project's full isolation posture), so the
    sandboxed `dotnet restore` (sandbox_wrapper_nuget.py) can resolve
    entirely offline via a NuGet.Config with `<clear/>` and a single
    local-folder source.

    Unlike prepare_maven_download_bundle, no parent-POM-equivalent walk
    is needed -- NuGet has no analogous "second POM required just to
    resolve" construct (confirmed directly: package dependency metadata
    lives entirely in the .nuspec each .nupkg already carries, no
    separate ancestor-package fetch required).

    Also writes a scratch .csproj (every resolved package as a direct
    dependency, reusing ecosystems/nuget/ecosystem.py's own
    _build_scratch_csproj -- same "pin everything, not just the
    requested targets" reasoning as prepare_cargo_download_bundle/
    prepare_go_download_bundle/prepare_maven_download_bundle), then runs
    a real (networked, host-side) `dotnet restore` against it -- the
    same real toolchain call MavenEcosystem's own scratch-resolve flow
    already makes, not a new privileged action -- purely to produce a
    real packages.lock.json. This is required, not optional, and
    confirmed directly: Trivy's own NuGet scanner detects nothing at all
    from a bare .csproj (real test: "Number of language-specific files
    num=0"), only from a real packages.lock.json (confirmed directly
    against three genuine CVEs, including two real HIGH-severity ones,
    correctly detected once one is present). This restore is a separate
    concern from the sandboxed one sandbox_wrapper_nuget.py runs inside
    the isolated container -- it runs on the trusted host purely to
    produce a Trivy-scannable artifact, not to prove offline
    installability (the checksum-verified .nupkg fetch above already
    independently proves artifact integrity regardless of what this
    restore does). NuGet.Config -- the sandboxed restore's own offline,
    local-folder-only source list -- is written only *after* this real
    restore completes, so the networked restore isn't accidentally
    constrained by it.

    Every downloaded .nupkg already sits flat in temp_dir's root (no
    separate flat-copy step needed the way Maven's nested m2-repo layout
    requires) so analyze_artifacts() finds it the same way it already
    finds .whl/.crate/.jar files -- real .nupkg files are plain zip
    archives (confirmed directly), so the existing generic zip-archive
    handler in artifact_analysis.py only needs ".nupkg" added to the
    top-level suffix check, no new extraction code. .NET assembly DLLs
    inside get no new detection code either -- NATIVE_BINARY_SUFFIXES
    already recognizes ".dll" for the unrelated reason Windows PE
    binaries already needed it.
    """
    temp_dir = tempfile.mkdtemp(prefix="depshieldx_")
    try:
        resolution = ResolutionResult(
            packages=list(resolved_versions.keys()),
            install_target="",
            resolved_versions=resolved_versions,
        )
        for package_id, version, artifact in ecosystem.selected_artifact_entries(resolution):
            ecosystem.fetch_artifact(artifact, Path(temp_dir))

        csproj_path = Path(temp_dir) / "scratch.csproj"
        csproj_path.write_bytes(_build_scratch_csproj(list(resolved_versions.items())).encode("utf-8"))

        lock_file_result = subprocess.run(
            [resolve_dotnet_tool("dotnet"), "restore", str(csproj_path)],
            cwd=temp_dir,
            capture_output=True,
            text=True,
        )
        if lock_file_result.returncode != 0:
            detail = (lock_file_result.stderr or lock_file_result.stdout or "").strip()
            raise RuntimeError(f"dotnet could not produce a lock file for the resolved package set: {detail}")

        nuget_config_path = Path(temp_dir) / "NuGet.Config"
        nuget_config_path.write_bytes(_build_nuget_config(_NUGET_SANDBOX_BUNDLE_MOUNT_PATH).encode("utf-8"))

        downloaded_files = sorted(path.name for path in Path(temp_dir).iterdir() if path.is_file())
        static_analysis = analyze_artifacts(temp_dir)
        artifact_hashes = {path.name: _sha256_file(path) for path in Path(temp_dir).iterdir() if path.is_file()}

        requirements_path = str(Path(temp_dir) / "depshieldx-lock.txt")
        Path(requirements_path).write_text(
            "\n".join(f"{name}@{version}" for name, version in sorted(resolved_versions.items())) + "\n"
        )

        return DownloadBundle(
            temp_dir=temp_dir,
            downloaded_files=downloaded_files,
            artifact_hashes=artifact_hashes,
            requirements_path=requirements_path,
            static_analysis=static_analysis,
            fingerprint=fingerprint_artifacts(artifact_hashes),
        )
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def prepare_pub_download_bundle(ecosystem, resolved_versions: dict[str, str]) -> DownloadBundle:
    """Pub's counterpart to prepare_nuget_download_bundle -- downloads
    (and, via fetch_artifact, checksum-verifies against the registry's
    own reported hash) every resolved package's real .tar.gz archive
    flat into temp_dir's root (same layout analyze_artifacts() already
    finds .crate/.whl/.jar/.nupkg files at -- confirmed directly real
    pub.dev archives are plain tar+gzip, the same format .crate files
    use, so artifact_analysis.py's existing tar+gzip handler needs no
    new suffix added), then *also* extracts each one directly into a
    pub-cache-shaped layout (hosted/pub.dev/<name>-<version>/, confirmed
    directly this matches the real $PUB_CACHE layout -- no flattening
    needed the way Cargo's .crate archives need, real pub.dev archives
    have no wrapping top-level directory) so the sandboxed `dart pub get
    --offline` (sandbox_wrapper_pub.py) can resolve entirely offline.

    Also writes a scratch pubspec.yaml (every resolved package as a
    direct dependency, reusing ecosystems/pub/ecosystem.py's own
    _build_scratch_pubspec -- same "pin everything, not just the
    requested targets" reasoning as prepare_cargo_download_bundle/
    prepare_go_download_bundle/prepare_maven_download_bundle/
    prepare_nuget_download_bundle), then runs a real `dart pub get
    --offline` against it *using the pub-cache this function just
    built* -- unlike NuGet (which needs a separate real *networked*
    restore to produce a lock file, since its local-folder source
    mechanism doesn't need extraction), Pub's own offline cache is
    already fully self-contained at this point, so no extra network
    round-trip is needed to produce a real pubspec.lock. This is
    required, not optional, confirmed directly the same way NuGet's own
    lock-file requirement was: Trivy's Pub scanner reads pubspec.lock
    natively (confirmed directly: "[pub] Detecting vulnerabilities...").
    """
    temp_dir = tempfile.mkdtemp(prefix="depshieldx_")
    try:
        resolution = ResolutionResult(
            packages=list(resolved_versions.keys()),
            install_target="",
            resolved_versions=resolved_versions,
        )
        cache_root = Path(temp_dir) / "pub-cache" / "hosted" / "pub.dev"
        for package_name, version, artifact in ecosystem.selected_artifact_entries(resolution):
            artifact_path = ecosystem.fetch_artifact(artifact, Path(temp_dir))
            extract_dir = cache_root / f"{package_name}-{version}"
            extract_dir.mkdir(parents=True, exist_ok=True)
            with tarfile.open(artifact_path, "r:gz") as archive:
                archive.extractall(extract_dir, filter="data")

        pubspec_path = Path(temp_dir) / "pubspec.yaml"
        pubspec_path.write_bytes(_build_scratch_pubspec(list(resolved_versions.items())).encode("utf-8"))

        env = dict(os.environ)
        env["PUB_CACHE"] = str(Path(temp_dir) / "pub-cache")
        lock_file_result = subprocess.run(
            [resolve_dart_tool("dart"), "pub", "get", "--offline"],
            cwd=temp_dir,
            capture_output=True,
            text=True,
            env=env,
        )
        if lock_file_result.returncode != 0:
            detail = (lock_file_result.stderr or lock_file_result.stdout or "").strip()
            raise RuntimeError(f"dart could not produce a lock file for the resolved package set: {detail}")

        downloaded_files = sorted(path.name for path in Path(temp_dir).iterdir() if path.is_file())
        static_analysis = analyze_artifacts(temp_dir)
        artifact_hashes = {path.name: _sha256_file(path) for path in Path(temp_dir).iterdir() if path.is_file()}

        requirements_path = str(Path(temp_dir) / "depshieldx-lock.txt")
        Path(requirements_path).write_text(
            "\n".join(f"{name}@{version}" for name, version in sorted(resolved_versions.items())) + "\n"
        )

        return DownloadBundle(
            temp_dir=temp_dir,
            downloaded_files=downloaded_files,
            artifact_hashes=artifact_hashes,
            requirements_path=requirements_path,
            static_analysis=static_analysis,
            fingerprint=fingerprint_artifacts(artifact_hashes),
        )
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def prepare_rubygems_download_bundle(ecosystem, resolved_versions: dict[str, str]) -> DownloadBundle:
    """RubyGems' counterpart to prepare_pub_download_bundle -- downloads
    (and, via fetch_artifact, checksum-verifies against the registry's
    own reported hash) every resolved gem's real .gem archive flat into
    temp_dir's root (analyze_artifacts() gets a new ".gem" suffix
    dispatch for this -- see artifact_analysis.py, a real .gem file is a
    plain uncompressed tar containing a nested gzipped data.tar.gz, not
    the same shape a suffix-to-mode mapping alone could handle), then
    *also* copies each one, byte-identical, into a vendor/cache-shaped
    layout (a flat directory of raw <name>-<version>.gem files --
    confirmed directly this matches the real vendor/cache layout `bundle
    cache` itself produces) so the sandboxed `bundle install --local`
    (sandbox_wrapper_rubygems.py) can install entirely offline.

    Also writes a scratch Gemfile (every resolved gem as an exact-pinned
    direct dependency, reusing ecosystems/rubygems/ecosystem.py's own
    _build_scratch_gemfile -- same "pin everything, not just the
    requested targets" reasoning as prepare_cargo_download_bundle/
    prepare_go_download_bundle/prepare_maven_download_bundle/
    prepare_nuget_download_bundle/prepare_pub_download_bundle) alongside
    a matching Gemfile.lock this function writes *directly* from the
    already-known resolved_versions via write_gemfile_lock, rather than
    invoking `bundle` to produce one.

    Deliberately never invokes `bundle install`/`bundle lock` itself
    here -- confirmed directly (see rubygems_sandbox.Dockerfile's module
    docstring) that `bundle install` triggers real native-extension
    compilation (a resolved gem's own extconf.rb) as an unavoidable part
    of installing a gem that has one, unlike every other ecosystem's own
    host-side "restore"/"fetch" equivalent, none of which invoke a
    compiler. The resolution itself is already real and trustworthy (it
    came from ecosystems/rubygems/ecosystem.py's own real `bundle lock`
    scratch resolve, or from parsing a real Gemfile.lock) -- this only
    materializes that already-confirmed result into the file Trivy needs
    (confirmed directly: Trivy natively parses Gemfile.lock, "[bundler]
    Detecting vulnerabilities..."), it doesn't re-derive it. A separate,
    ALSO real `bundle install --local` run happens only inside the
    fully-isolated sandbox container itself (sandbox_wrapper_rubygems.py)
    -- untrusted native-extension build code executing inside a
    --network none/--read-only/--cap-drop ALL/non-root container is
    exactly the isolation this project's sandbox already exists for,
    unlike the same code running unguarded on the host.
    """
    temp_dir = tempfile.mkdtemp(prefix="depshieldx_")
    try:
        resolution = ResolutionResult(
            packages=list(resolved_versions.keys()),
            install_target="",
            resolved_versions=resolved_versions,
        )
        cache_dir = Path(temp_dir) / "vendor" / "cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        for package_name, version, artifact in ecosystem.selected_artifact_entries(resolution):
            artifact_path = ecosystem.fetch_artifact(artifact, Path(temp_dir))
            shutil.copy2(artifact_path, cache_dir / f"{package_name}-{version}.gem")

        gemfile_path = Path(temp_dir) / "Gemfile"
        gemfile_path.write_text(_build_scratch_gemfile(list(resolved_versions.items())), encoding="utf-8")

        gemfile_lock_path = Path(temp_dir) / "Gemfile.lock"
        gemfile_lock_path.write_text(write_gemfile_lock(resolved_versions), encoding="utf-8")

        downloaded_files = sorted(path.name for path in Path(temp_dir).iterdir() if path.is_file())
        static_analysis = analyze_artifacts(temp_dir)
        artifact_hashes = {path.name: _sha256_file(path) for path in Path(temp_dir).iterdir() if path.is_file()}

        requirements_path = str(Path(temp_dir) / "depshieldx-lock.txt")
        Path(requirements_path).write_text(
            "\n".join(f"{name}@{version}" for name, version in sorted(resolved_versions.items())) + "\n"
        )

        return DownloadBundle(
            temp_dir=temp_dir,
            downloaded_files=downloaded_files,
            artifact_hashes=artifact_hashes,
            requirements_path=requirements_path,
            static_analysis=static_analysis,
            fingerprint=fingerprint_artifacts(artifact_hashes),
        )
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def _scan_host_install_dir(host_install_dir: str) -> Optional[dict]:
    """
    Run Trivy directly against the host directory the sandbox container's
    install destination was bind-mounted to. Not a `docker cp` from the
    container after it exits: reproduced directly against a real container
    that content written to the container's --tmpfs /tmp mount (where
    installs previously happened) is torn down the instant the container
    process exits, before any post-run `docker cp` could ever read it --
    silently scanning an empty directory every time. Bind-mounting a host
    directory as the install destination instead means the files are
    already on the host, real and inspectable, once the container exits
    normally.

    trivy.py's scan_filesystem() itself has no ecosystem-specific code --
    it already understands node_modules natively, same as site-packages --
    so nothing else here needs to vary by ecosystem.
    """
    try:
        should_block, vulns, warnings = scan_filesystem(
            host_install_dir,
            severity="HIGH"
        )
        return {
            "should_block": should_block,
            "vulnerabilities": vulns,
            "warnings": warnings,
            "scanned": True,
        }
    except Exception as e:
        # Graceful degradation if Trivy scan fails
        return {
            "should_block": False,
            "vulnerabilities": [],
            "warnings": [f"Trivy sandbox scan failed: {str(e)}"],
            "scanned": False,
        }


def run_sandbox(
    install_targets,
    resolved_versions: Optional[dict[str, str]] = None,
    keep_bundle: bool = False,
    cache_enabled: bool = True,
    verbose: bool = False,
    require_docker: bool = True,
    block_on_static_analysis: bool = True,
    block_on_trivy: bool = False,
    ecosystem=PYPI_ECOSYSTEM,
) -> SandboxResult:
    """
    Test-install a package offline inside an isolated Docker container.

    npm/Cargo/Go/Maven/NuGet support (ecosystem=NPM_ECOSYSTEM etc.) only
    target the Docker backend -- the local_subprocess fallback below is
    pip/sandbox_wrapper.py-specific. It's also, in practice, unreachable
    from the real CLI flow anyway: cli/engine.py's _run_deep_flow always
    calls this with require_docker=True explicitly, which returns before
    the fallback branch is ever taken, for every ecosystem. require_docker
    defaults to True here too (secure by default) -- the local_subprocess
    backend runs on the bare host with only sandbox_wrapper.py's own
    in-process sys.addaudithook guards, not real OS-level container
    isolation, so a caller has to opt into that explicitly rather than
    silently getting it by omission.
    """
    is_npm = ecosystem.name == "npm"
    is_cargo = ecosystem.name == "cargo"
    is_go = ecosystem.name == "go"
    is_maven = ecosystem.name == "maven"
    is_nuget = ecosystem.name == "nuget"
    is_pub = ecosystem.name == "pub"
    is_rubygems = ecosystem.name == "rubygems"
    docker_image = (
        NPM_SANDBOX_IMAGE_TAG
        if is_npm
        else CARGO_SANDBOX_IMAGE_TAG
        if is_cargo
        else GO_SANDBOX_IMAGE_TAG
        if is_go
        else MAVEN_SANDBOX_IMAGE_TAG
        if is_maven
        else NUGET_SANDBOX_IMAGE_TAG
        if is_nuget
        else PUB_SANDBOX_IMAGE_TAG
        if is_pub
        else RUBYGEMS_SANDBOX_IMAGE_TAG if is_rubygems else DOCKER_IMAGE
    )
    if isinstance(install_targets, str):
        install_targets = [install_targets]
    else:
        install_targets = list(install_targets)
    bundle = None
    isolation = {
        "backend": "docker",
        "image": docker_image,
        "network": "none",
        "read_only_rootfs": True,
        "no_new_privileges": True,
        "cap_drop": ["ALL"],
        "user": SANDBOX_USER,
        "pids_limit": 64,
        "memory": "512m",
        "cpus": "1.0",
        "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=256m"],
    }
    try:
        docker_ok, docker_error = _docker_daemon_available()
        backend = "docker" if docker_ok else "local_subprocess"
        if not docker_ok:
            if require_docker:
                return SandboxResult(
                    success=False,
                    downloaded_files=[],
                    error=docker_error or "docker is unavailable",
                    error_type="environment",
                    isolation={
                        "backend": "docker",
                        "image": docker_image,
                        "docker_error": docker_error,
                    },
                    evidence=None,
                    static_analysis=None,
                    bundle=None,
                    cache=None,
                    trivy_results=None,
                )
            isolation = {
                "backend": "local_subprocess",
                "python": system_python_executable(),
                "mode": "offline_guarded_subprocess",
                "network": "guarded_by_wrapper",
                "filesystem": "host_process_with_write_guards",
                "processes": "guarded_subprocess_policy",
                "docker_error": docker_error,
            }

        if is_npm:
            bundle = prepare_npm_download_bundle(ecosystem, resolved_versions or {})
        elif is_cargo:
            bundle = prepare_cargo_download_bundle(ecosystem, resolved_versions or {})
        elif is_go:
            bundle = prepare_go_download_bundle(ecosystem, resolved_versions or {})
        elif is_maven:
            bundle = prepare_maven_download_bundle(ecosystem, resolved_versions or {})
        elif is_nuget:
            bundle = prepare_nuget_download_bundle(ecosystem, resolved_versions or {})
        elif is_pub:
            bundle = prepare_pub_download_bundle(ecosystem, resolved_versions or {})
        elif is_rubygems:
            bundle = prepare_rubygems_download_bundle(ecosystem, resolved_versions or {})
        else:
            bundle = prepare_download_bundle(
                install_targets,
                resolved_versions,
                verbose=verbose,
                download_via_host=(backend != "docker"),
            )
        cache_fingerprint = _sandbox_cache_fingerprint(
            bundle.artifact_hashes,
            backend,
            require_docker=require_docker,
            block_on_static_analysis=block_on_static_analysis,
            block_on_trivy=block_on_trivy,
            ecosystem=ecosystem.name,
        )
        bundle.fingerprint = cache_fingerprint
        cache_entry = load_cache_entry(cache_fingerprint) if cache_enabled else None
        if cache_entry:
            cleanup_download_bundle(bundle)
            metadata = cache_entry.metadata
            cached_bundle = DownloadBundle(
                temp_dir=cache_entry.path,
                downloaded_files=metadata["downloaded_files"],
                artifact_hashes=metadata["artifact_hashes"],
                requirements_path=str(Path(cache_entry.path) / "depshieldx-lock.txt"),
                static_analysis=metadata["static_analysis"],
                fingerprint=cache_entry.fingerprint,
                cleanup=False,
            )
            return SandboxResult(
                success=bool(metadata.get("success")),
                downloaded_files=cached_bundle.downloaded_files,
                error=metadata.get("error"),
                error_type=metadata.get("error_type"),
                isolation=metadata.get("isolation") or isolation,
                evidence=metadata.get("evidence"),
                static_analysis=cached_bundle.static_analysis,
                bundle=cached_bundle if keep_bundle else None,
                cache={"hit": True, "fingerprint": cache_entry.fingerprint},
                trivy_results=metadata.get("trivy_results"),
            )
        if block_on_static_analysis and bundle.static_analysis["blocked"]:
            return SandboxResult(
                success=False,
                downloaded_files=bundle.downloaded_files,
                error="Static analysis found high-severity indicators in the downloaded artifacts.",
                error_type="static_analysis",
                isolation=isolation,
                evidence=None,
                static_analysis=bundle.static_analysis,
                bundle=bundle if keep_bundle else None,
                cache={"hit": False, "fingerprint": cache_fingerprint},
                trivy_results=None,
            )
        if backend == "docker":
            # Create a unique container name for cleanup purposes
            container_name = f"depshieldx_{uuid.uuid4().hex[:12]}"
            # The install destination is bind-mounted from the host (not left
            # under the container's --tmpfs /tmp) so Trivy can scan it after
            # the container exits. Reproduced directly against a real
            # container: content written to a --tmpfs mount is torn down the
            # instant the container process exits, before any post-run
            # `docker cp` could read it -- the previous docker-cp-after-exit
            # approach was silently scanning nothing on every deep-mode run,
            # for both ecosystems.
            host_install_dir = tempfile.mkdtemp(prefix="depshieldx_sandbox_install_")
            # Base directory Trivy scans after the container exits. Defaults
            # to the bind-mounted install dir above; cargo overrides this
            # below to point at the host-side vendor directory instead, since
            # nothing new needs to be written back out for cargo (see the
            # is_cargo branch's comment).
            scan_base_dir = host_install_dir
            # Extra --tmpfs mounts beyond the shared noexec /tmp above.
            # Populated for cargo only -- see the is_cargo branch's comment.
            extra_tmpfs_args: list[str] = []

            env_args = []
            if is_npm:
                container_entrypoint = [
                    "node",
                    "/depshieldx/sandbox_wrapper_npm.js",
                    "/tmp/packages",
                ]
                wrapper_mount = f"{resource_path('security/sandbox/sandbox_wrapper_npm.js').parent}:/depshieldx:ro"
                # Bind-mounted at the whole project dir (not just
                # .../node_modules): mounting only the node_modules subpath
                # left its parent as a plain directory Docker auto-creates as
                # the (root-owned) mount point, which SANDBOX_USER can't
                # write package.json into -- reproduced directly. Mounting
                # the parent itself means package.json and node_modules both
                # land inside the one bind-mounted, host-owned directory.
                container_install_path = "/tmp/depshieldx-npm-install"
                host_scan_subpath = "node_modules"
                # SANDBOX_USER (65534, "nobody") has no home directory in the
                # node:20 image, so npm's cache/log writes fail outright
                # (ENOENT against the nonexistent default HOME) -- reproduced
                # directly against a real container. /tmp is the one writable
                # path (the tmpfs mount below), so point HOME there.
                env_args = ["-e", "HOME=/tmp"]
                # No --cap-add SYS_PTRACE needed: strace here only traces
                # its own direct child process tree (npm -> node -> lifecycle
                # scripts), and a process can always ptrace its own
                # descendants regardless of capabilities or ptrace_scope --
                # CAP_SYS_PTRACE is only required to trace *unrelated*
                # processes. Verified directly under the full --cap-drop ALL
                # posture (no capabilities added back at all): strace still
                # traced a real multi-generation fork tree (npm -> node ->
                # sh -c -> node) and caught a real network exfiltration
                # attempt from a postinstall script without it.
                _ensure_npm_sandbox_image(verbose=verbose)
            elif is_cargo:
                container_entrypoint = [
                    "python3",
                    "/depshieldx/sandbox_wrapper_cargo.py",
                    "/tmp/packages/vendor",
                    *[f"{name}@={version}" for name, version in sorted((resolved_versions or {}).items())],
                ]
                wrapper_mount = f"{resource_path('security/sandbox/sandbox_wrapper_cargo.py').parent}:/depshieldx:ro"
                # prepare_cargo_download_bundle already built the vendor
                # directory host-side, before the container ever runs, and
                # neither `cargo fetch --offline` nor a full `cargo build
                # --offline` against a directory source writes anything back
                # into it (confirmed directly for both). `cargo build` does
                # attempt a few best-effort cache-lock writes under
                # $CARGO_HOME, but those land on the image's read-only
                # rootfs and fail harmlessly (EROFS/ENOENT) without blocking
                # the build -- see sandbox_wrapper_cargo.py's docstring. So
                # unlike npm/PyPI there's no new output that needs to
                # survive tmpfs teardown via a bind-mounted install dir:
                # host_install_dir/
                # container_install_path below stay unused for cargo, and
                # Trivy scans the host-side vendor directory directly
                # (already bind-mounted read-only at /tmp/packages/vendor,
                # since bundle.temp_dir itself is mounted at /tmp/packages).
                container_install_path = "/tmp/depshieldx-cargo-unused"
                host_scan_subpath = None
                scan_base_dir = str(Path(bundle.temp_dir) / "vendor")
                # A real `cargo build` (Stage 3) compiles and then *executes*
                # build-script binaries and proc-macro dylibs out of its own
                # target/ directory -- reproduced directly that this fails
                # with "Permission denied" under the shared --tmpfs
                # /tmp:...,noexec above (fine for Stage 2's fetch-only
                # posture, incompatible with actually building). Fix: give
                # the whole scratch project directory (not just target/,
                # which hits the exact same auto-created-root-owned-parent
                # bug already solved for npm's node_modules mount above) its
                # own exec-permitted tmpfs, layered over the still-noexec
                # outer /tmp -- confirmed directly this lets a real
                # proc-macro-heavy build (serde+serde_derive+syn) complete
                # while the vendor directory and everything else under /tmp
                # stays non-executable.
                extra_tmpfs_args = [
                    "--tmpfs",
                    "/tmp/depshieldx-cargo-install:rw,nosuid,nodev,exec,size=256m",
                ]
                _ensure_cargo_sandbox_image(verbose=verbose)
            elif is_go:
                container_entrypoint = [
                    "python3",
                    "/depshieldx/sandbox_wrapper_go.py",
                    "/tmp/packages",
                    *[f"{name}@{version}" for name, version in sorted((resolved_versions or {}).items())],
                ]
                wrapper_mount = f"{resource_path('security/sandbox/sandbox_wrapper_go.py').parent}:/depshieldx:ro"
                # prepare_go_download_bundle already built the go.mod/
                # go.sum/goproxy/ layout host-side, before the container
                # ever runs, and `go mod download` against a local file://
                # proxy with GOFLAGS=-mod=readonly writes nothing back into
                # the read-only-mounted bundle (confirmed directly) -- it
                # only writes into $GOPATH/$GOCACHE, which
                # sandbox_wrapper_go.py itself points at its own writable
                # work directory below. So, like cargo, there's no new
                # output that needs to survive tmpfs teardown via a
                # bind-mounted install dir: host_install_dir/
                # container_install_path stay unused for Go, and Trivy
                # scans the host-side bundle directory directly (already
                # bind-mounted read-only at /tmp/packages, since
                # bundle.temp_dir itself is mounted there) -- Trivy's own
                # Go support reads go.mod/go.sum natively, needing no
                # extracted source tree the way cargo's Cargo.lock-less
                # vendor directory does (confirmed directly: a real
                # `trivy fs` scan of exactly this go.mod/go.sum layout
                # correctly reported real CVEs for a known-vulnerable
                # module).
                container_install_path = "/tmp/depshieldx-go-unused"
                host_scan_subpath = None
                scan_base_dir = bundle.temp_dir
                # sandbox_wrapper_go.py copies go.mod/go.sum into its own
                # writable work directory and points $GOPATH/$GOCACHE
                # there too (confirmed directly `go mod download`/`go
                # build` need writable locations for their own
                # bookkeeping and compiled-package cache, unlike cargo's
                # directory-source fetch) -- needs its own exec-permitted
                # tmpfs for the same auto-created-root-owned-parent
                # reasoning as npm's/cargo's mounts above. 256m, matching
                # cargo's own build-stage size -- a real `go build`
                # populates $GOCACHE with compiled package objects, not
                # just fetched module sources the way Stage 2's plain
                # `go mod download` did.
                extra_tmpfs_args = [
                    "--tmpfs",
                    "/tmp/depshieldx-go-work:rw,nosuid,nodev,exec,size=256m",
                ]
                env_args = ["-e", "HOME=/tmp"]
                _ensure_go_sandbox_image(verbose=verbose)
            elif is_maven:
                container_entrypoint = [
                    "python3",
                    "/depshieldx/sandbox_wrapper_maven.py",
                    "/tmp/packages",
                    *[f"{name}@{version}" for name, version in sorted((resolved_versions or {}).items())],
                ]
                wrapper_mount = f"{resource_path('security/sandbox/sandbox_wrapper_maven.py').parent}:/depshieldx:ro"
                # prepare_maven_download_bundle already built the m2-repo/
                # pom.xml layout host-side, before the container ever
                # runs. sandbox_wrapper_maven.py copies it (merged with
                # the image's own pre-warmed plugin cache) into its own
                # writable tmpfs work directory rather than resolving
                # directly against the read-only bind mount -- confirmed
                # directly Maven writes small bookkeeping files into
                # whatever -Dmaven.repo.local path it's given regardless
                # of whether real work is needed, which fails outright
                # against a real read-only mount. So, like cargo/go,
                # there's no new output that needs to survive tmpfs
                # teardown via a bind-mounted install dir: host_install_dir/
                # container_install_path stay unused for Maven, and Trivy
                # scans the host-side bundle directory directly (already
                # bind-mounted read-only at /tmp/packages, since
                # bundle.temp_dir itself is mounted there) -- Trivy's own
                # Java/Maven support reads a real m2-repo-shaped local
                # repository natively, needing no extracted source tree.
                container_install_path = "/tmp/depshieldx-maven-unused"
                host_scan_subpath = None
                scan_base_dir = bundle.temp_dir
                # sandbox_wrapper_maven.py's merged local repository (and
                # jansi's native-library extraction, see that file's
                # docstring) both need a writable, exec-permitted
                # location separate from the shared noexec outer /tmp --
                # same auto-created-root-owned-parent reasoning as the
                # other three ecosystems' extra mounts. 256m: the merged
                # local repo (pre-warmed plugin cache + per-run project
                # coordinates) is small in practice (confirmed directly,
                # under 20MB for the plugin cache alone) but sized to
                # match cargo/go's own build-stage tmpfs rather than
                # tuned to the single case observed.
                extra_tmpfs_args = [
                    "--tmpfs",
                    "/tmp/depshieldx-maven-work:rw,nosuid,nodev,exec,size=256m",
                ]
                env_args = ["-e", "HOME=/tmp"]
                _ensure_maven_sandbox_image(verbose=verbose)
            elif is_nuget:
                container_entrypoint = [
                    "python3",
                    "/depshieldx/sandbox_wrapper_nuget.py",
                    "/tmp/packages",
                    *[f"{name}@{version}" for name, version in sorted((resolved_versions or {}).items())],
                ]
                wrapper_mount = f"{resource_path('security/sandbox/sandbox_wrapper_nuget.py').parent}:/depshieldx:ro"
                # prepare_nuget_download_bundle already built the flat
                # .nupkg/scratch.csproj/NuGet.Config layout host-side,
                # before the container ever runs. Unlike Maven, no
                # plugin-cache merge is needed -- confirmed directly
                # `dotnet restore` needs nothing beyond what the .NET SDK
                # itself already ships. So, like the other three
                # ecosystems, there's no new output that needs to
                # survive tmpfs teardown via a bind-mounted install dir:
                # host_install_dir/container_install_path stay unused
                # for NuGet, and Trivy scans the host-side bundle
                # directory directly (already bind-mounted read-only at
                # /tmp/packages, since bundle.temp_dir itself is mounted
                # there) -- Trivy's own NuGet support reads a real
                # packages.lock.json natively (confirmed directly: a bare
                # .csproj alone gets zero detection), which
                # prepare_nuget_download_bundle already generated
                # host-side via a real (networked) restore.
                container_install_path = "/tmp/depshieldx-nuget-unused"
                host_scan_subpath = None
                scan_base_dir = bundle.temp_dir
                # sandbox_wrapper_nuget.py points $HOME (and so NuGet's
                # own default global packages folder, $HOME/.nuget/
                # packages) at its own writable work directory --
                # confirmed directly SANDBOX_USER's real default HOME
                # has nothing writable to extract packages into
                # otherwise. 256m matches the other three ecosystems'
                # own build-stage tmpfs sizing rather than being tuned to
                # the single case observed.
                extra_tmpfs_args = [
                    "--tmpfs",
                    "/tmp/depshieldx-nuget-work:rw,nosuid,nodev,exec,size=256m",
                ]
                env_args = ["-e", "HOME=/tmp"]
                _ensure_nuget_sandbox_image(verbose=verbose)
            elif is_pub:
                container_entrypoint = [
                    "python3",
                    "/depshieldx/sandbox_wrapper_pub.py",
                    "/tmp/packages",
                    *[f"{name}@{version}" for name, version in sorted((resolved_versions or {}).items())],
                ]
                wrapper_mount = f"{resource_path('security/sandbox/sandbox_wrapper_pub.py').parent}:/depshieldx:ro"
                # prepare_pub_download_bundle already built the flat
                # .tar.gz/pubspec.yaml/pubspec.lock/pub-cache layout
                # host-side, before the container ever runs. Like
                # NuGet/Maven, no plugin-cache merge is needed. So, like
                # the other four ecosystems, there's no new output that
                # needs to survive tmpfs teardown via a bind-mounted
                # install dir: host_install_dir/container_install_path
                # stay unused for Pub, and Trivy scans the host-side
                # bundle directory directly (already bind-mounted
                # read-only at /tmp/packages, since bundle.temp_dir
                # itself is mounted there) -- Trivy's own Pub support
                # reads a real pubspec.lock natively (confirmed directly:
                # "[pub] Detecting vulnerabilities..."), which
                # prepare_pub_download_bundle already generated host-side
                # via a real `dart pub get --offline` against the same
                # pub-cache this mount carries.
                container_install_path = "/tmp/depshieldx-pub-unused"
                host_scan_subpath = None
                scan_base_dir = bundle.temp_dir
                # sandbox_wrapper_pub.py copies the mounted, pre-built
                # pub-cache into its own writable work directory before
                # pointing $PUB_CACHE there -- confirmed directly `dart
                # pub get` writes its own bookkeeping (an "active_roots"
                # directory) into $PUB_CACHE even in --offline mode,
                # which fails outright against a real read-only mount
                # (see pub_sandbox.Dockerfile's docstring). 256m matches
                # the other ecosystems' own build-stage tmpfs sizing
                # rather than being tuned to the single case observed.
                extra_tmpfs_args = [
                    "--tmpfs",
                    "/tmp/depshieldx-pub-work:rw,nosuid,nodev,exec,size=256m",
                ]
                env_args = ["-e", "HOME=/tmp"]
                _ensure_pub_sandbox_image(verbose=verbose)
            elif is_rubygems:
                container_entrypoint = [
                    "python3",
                    "/depshieldx/sandbox_wrapper_rubygems.py",
                    "/tmp/packages",
                    *[f"{name}@{version}" for name, version in sorted((resolved_versions or {}).items())],
                ]
                wrapper_mount = f"{resource_path('security/sandbox/sandbox_wrapper_rubygems.py').parent}:/depshieldx:ro"
                # prepare_rubygems_download_bundle already built the flat
                # .gem/Gemfile/Gemfile.lock/vendor-cache layout host-side,
                # before the container ever runs -- no plugin-cache merge
                # needed, same as NuGet/Maven/Pub. So, like those, there's
                # no new output that needs to survive tmpfs teardown via a
                # bind-mounted install dir: host_install_dir/
                # container_install_path stay unused for RubyGems, and
                # Trivy scans the host-side bundle directory directly
                # (already bind-mounted read-only at /tmp/packages, since
                # bundle.temp_dir itself is mounted there) -- Trivy's own
                # Bundler support reads a real Gemfile.lock natively
                # (confirmed directly), which prepare_rubygems_download_
                # bundle already wrote host-side directly from the
                # already-known resolution, without ever invoking bundle
                # (see that function's own docstring for why).
                container_install_path = "/tmp/depshieldx-rubygems-unused"
                host_scan_subpath = None
                scan_base_dir = bundle.temp_dir
                # sandbox_wrapper_rubygems.py copies the mounted,
                # pre-built vendor/cache (plus Gemfile/Gemfile.lock) into
                # its own writable work directory before running `bundle
                # install --local` there -- Bundler needs to write real
                # bookkeeping (installed gemspecs, extension build
                # output, its own vendor/cache updates) a read-only bind
                # mount can't accommodate, the same "copy into a writable
                # location before use" pattern sandbox_wrapper_maven.py/
                # sandbox_wrapper_pub.py already use for their own state.
                # 256m matches the other ecosystems' own build-stage
                # tmpfs sizing rather than being tuned to the single case
                # observed -- native-extension compilation in particular
                # (confirmed directly this is a real, unavoidable part of
                # `bundle install` for gems that have one, see
                # rubygems_sandbox.Dockerfile's module docstring) can
                # produce real build output under this tmpfs.
                extra_tmpfs_args = [
                    "--tmpfs",
                    "/tmp/depshieldx-rubygems-work:rw,nosuid,nodev,exec,size=256m",
                ]
                env_args = ["-e", "HOME=/tmp"]
                _ensure_rubygems_sandbox_image(verbose=verbose)
            else:
                container_entrypoint = [
                    "python",
                    "/depshieldx/sandbox_wrapper.py",
                    "/tmp/packages",
                    *install_targets,
                ]
                wrapper_mount = f"{resource_path('security/sandbox/sandbox_wrapper.py').parent}:/depshieldx:ro"
                # Fixed (not tempfile.mkdtemp-random) so the host bind mount
                # below can target it; must stay under the "/tmp/site-packages"
                # prefix sandbox_wrapper.py's write-guard allowlist already
                # checks against.
                container_install_path = "/tmp/site-packages-sandbox"
                host_scan_subpath = None
                env_args = env_args + ["-e", f"DEPSHIELDX_SANDBOX_TARGET_DIR={container_install_path}"]

            docker_command = [
                "docker",
                "run",
                "--name",
                container_name,
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "64",
                "--memory",
                "512m",
                "--cpus",
                "1.0",
                "--user",
                SANDBOX_USER,
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=256m",
                *extra_tmpfs_args,
                "--workdir",
                "/tmp",
                *env_args,
                "-v",
                f"{bundle.temp_dir}:/tmp/packages:ro",
                "-v",
                wrapper_mount,
                "-v",
                f"{host_install_dir}:{container_install_path}:rw",
                docker_image,
                *container_entrypoint,
            ]
            trivy_results = None
            try:
                result = _run_command(docker_command, verbose=False)
                if verbose:
                    _emit_command_output(result.stdout, result.stderr, suppress_prefixes=(REPORT_PREFIX,))

                # Scan the bind-mounted host directory directly -- it already
                # holds whatever the container installed, no docker cp needed.
                # (For cargo, scan_base_dir points at the host-side vendor
                # directory instead of host_install_dir -- see is_cargo branch.)
                scan_dir = (
                    str(Path(scan_base_dir) / host_scan_subpath) if host_scan_subpath else scan_base_dir
                )
                trivy_results = _scan_host_install_dir(scan_dir)
            finally:
                # Clean up the container and the host install dir (whether
                # scan succeeded or not)
                try:
                    subprocess.run(
                        ["docker", "rm", "--force", container_name],
                        capture_output=True,
                        timeout=30,
                    )
                except Exception:
                    pass  # Container cleanup is best-effort
                shutil.rmtree(host_install_dir, ignore_errors=True)
        else:
            result = _run_local_sandbox(bundle, install_targets, verbose=verbose)
            trivy_results = None
        evidence = _extract_report(result.stdout)
        if block_on_trivy:
            trivy_failed = not trivy_results or not trivy_results.get("scanned")
            trivy_blocked = bool(trivy_results and trivy_results.get("should_block"))
            if trivy_failed or trivy_blocked:
                error = "Trivy scan could not be completed."
                if trivy_blocked:
                    error = "Trivy found HIGH/CRITICAL vulnerabilities or secrets in the sandboxed installation."
                if cache_enabled:
                    store_cache_entry(
                        bundle,
                        {
                            "success": False,
                            "error": error,
                            "error_type": "trivy",
                            "isolation": isolation,
                            "evidence": evidence,
                            "trivy_results": trivy_results,
                        },
                    )
                return SandboxResult(
                    success=False,
                    downloaded_files=bundle.downloaded_files,
                    error=error,
                    error_type="trivy",
                    isolation=isolation,
                    evidence=evidence,
                    static_analysis=bundle.static_analysis,
                    bundle=bundle if keep_bundle else None,
                    cache={"hit": False, "fingerprint": cache_fingerprint},
                    trivy_results=trivy_results,
                )
        if cache_enabled:
            store_cache_entry(
                bundle,
                {
                    "success": True,
                    "error": None,
                    "error_type": None,
                    "isolation": isolation,
                    "evidence": evidence,
                    "trivy_results": trivy_results,
                },
            )
        return SandboxResult(
            success=True,
            downloaded_files=bundle.downloaded_files,
            error=None,
            error_type=None,
            isolation=isolation,
            evidence=evidence,
            static_analysis=bundle.static_analysis,
            bundle=bundle if keep_bundle else None,
            cache={"hit": False, "fingerprint": cache_fingerprint},
            trivy_results=trivy_results,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, RuntimeError) as exc:
        detail = str(exc)
        evidence = None
        static_analysis = bundle.static_analysis if bundle else None
        if isinstance(exc, subprocess.CalledProcessError):
            detail = (exc.stderr or exc.stdout or str(exc)).strip()
            evidence = _extract_report((exc.stdout or "") + "\n" + (exc.stderr or ""))
        click.secho(f"Sandbox failed: {detail}", fg="red")
        return SandboxResult(
            success=False,
            downloaded_files=bundle.downloaded_files if bundle else [],
            error=detail,
            error_type="integrity" if isinstance(exc, RuntimeError) else "sandbox",
            isolation=isolation,
            evidence=evidence,
            static_analysis=static_analysis,
            bundle=bundle if keep_bundle else None,
            cache={"hit": False, "fingerprint": bundle.fingerprint} if bundle else None,
            trivy_results=None,
        )
    finally:
        if bundle and not keep_bundle:
            cleanup_download_bundle(bundle)
