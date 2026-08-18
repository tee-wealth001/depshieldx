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
                # filter="data" (path-traversal/symlink hardening) only
                # exists from Python 3.12 -- this codebase supports 3.11+
                # (pyproject.toml), so fall back cleanly on older
                # interpreters rather than crash with TypeError.
                try:
                    archive.extractall(vendor_entry, filter="data")
                except TypeError:
                    archive.extractall(vendor_entry)
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
    require_docker: bool = False,
    block_on_static_analysis: bool = True,
    block_on_trivy: bool = False,
    ecosystem=PYPI_ECOSYSTEM,
) -> SandboxResult:
    """
    Test-install a package offline inside an isolated Docker container.

    npm support (ecosystem=NPM_ECOSYSTEM) only targets the Docker backend --
    the local_subprocess fallback below is pip/sandbox_wrapper.py-specific
    and, in practice, unreachable from the real CLI flow anyway: cli/engine.py's
    _run_deep_flow always calls this with require_docker=True, which returns
    before the fallback branch is ever taken, for either ecosystem.
    """
    is_npm = ecosystem.name == "npm"
    is_cargo = ecosystem.name == "cargo"
    is_go = ecosystem.name == "go"
    docker_image = (
        NPM_SANDBOX_IMAGE_TAG
        if is_npm
        else CARGO_SANDBOX_IMAGE_TAG if is_cargo else GO_SANDBOX_IMAGE_TAG if is_go else DOCKER_IMAGE
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
                # there too (confirmed directly `go mod download` needs
                # writable locations for its own bookkeeping, unlike
                # cargo's directory-source fetch) -- needs its own
                # exec-permitted tmpfs for the same auto-created-root-
                # owned-parent reasoning as npm's/cargo's mounts above.
                extra_tmpfs_args = [
                    "--tmpfs",
                    "/tmp/depshieldx-go-work:rw,nosuid,nodev,exec,size=128m",
                ]
                env_args = ["-e", "HOME=/tmp"]
                _ensure_go_sandbox_image(verbose=verbose)
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
