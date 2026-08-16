import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
import json
import hashlib
from pathlib import Path
from typing import Any, List, Optional

import click
from packaging.utils import canonicalize_name, parse_sdist_filename, parse_wheel_filename

from .artifact_analysis import analyze_artifacts
from .cache import fingerprint_artifacts, load_cache_entry, store_cache_entry
from .ecosystems import PYPI_ECOSYSTEM
from .resolver import ResolutionResult
from .runtime import pip_command, resource_path, system_python_executable
from .trivy import scan_filesystem

DOCKER_IMAGE = "python:3.11"
# Built locally from docker/npm_sandbox.Dockerfile (node:20 + strace) the
# first time npm deep mode runs -- plain node:20 has no strace (confirmed
# directly: `which strace` -> not found), and the sandbox container's
# rootfs runs --read-only, so it can't be apt-get installed at container
# run time either. No external registry involved.
NPM_SANDBOX_IMAGE_TAG = "depshieldx-npm-sandbox:node20"
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

    dockerfile = resource_path("docker/npm_sandbox.Dockerfile")
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


def _run_local_sandbox(bundle: DownloadBundle, install_targets: list[str], verbose: bool) -> subprocess.CompletedProcess:
    command = [
        system_python_executable(),
        "-I",
        str(resource_path("sandbox_wrapper.py")),
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
    docker_image = NPM_SANDBOX_IMAGE_TAG if is_npm else DOCKER_IMAGE
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

            env_args = []
            if is_npm:
                container_entrypoint = [
                    "node",
                    "/depshieldx/sandbox_wrapper_npm.js",
                    "/tmp/packages",
                ]
                wrapper_mount = f"{resource_path('sandbox_wrapper_npm.js').parent}:/depshieldx:ro"
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
            else:
                container_entrypoint = [
                    "python",
                    "/depshieldx/sandbox_wrapper.py",
                    "/tmp/packages",
                    *install_targets,
                ]
                wrapper_mount = f"{resource_path('sandbox_wrapper.py').parent}:/depshieldx:ro"
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
                scan_dir = (
                    str(Path(host_install_dir) / host_scan_subpath) if host_scan_subpath else host_install_dir
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
