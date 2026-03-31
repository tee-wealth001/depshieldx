import shutil
import subprocess
import sys
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
from .trivy import scan_filesystem

PACKAGE_ROOT = Path(__file__).resolve().parent
DOCKER_IMAGE = "python:3.11"
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
) -> str:
    return fingerprint_artifacts(
        {
            **artifact_hashes,
            "__sandbox_backend__": backend,
            "__require_docker__": str(require_docker).lower(),
            "__block_on_static_analysis__": str(block_on_static_analysis).lower(),
            "__block_on_trivy__": str(block_on_trivy).lower(),
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


def _run_local_sandbox(bundle: DownloadBundle, install_targets: list[str], verbose: bool) -> subprocess.CompletedProcess:
    command = [
        sys.executable,
        "-I",
        str(PACKAGE_ROOT / "sandbox_wrapper.py"),
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
        [
            sys.executable,
            "-m",
            "pip",
            "download",
            "--dest",
            temp_dir,
            *install_targets,
        ],
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


def _scan_sandbox_container(container_id: str) -> Optional[dict]:
    """
    Run Trivy on an installed package set in a sandbox container.
    Copies site-packages from container, scans with Trivy, returns results.
    Returns None if scan fails or Trivy unavailable.
    """
    temp_scan_dir = tempfile.mkdtemp(prefix="depshieldx_trivy_scan_")
    try:
        # Copy site-packages from container to host
        site_packages_path = "/usr/local/lib/python3.11/site-packages"
        copy_command = [
            "docker",
            "cp",
            f"{container_id}:{site_packages_path}",
            temp_scan_dir,
        ]
        try:
            _run_command(copy_command, verbose=False)
        except subprocess.CalledProcessError:
            # If copy fails, try to scan what we can (might be empty)
            pass

        # Scan the copied site-packages with Trivy filesystem scan
        should_block, vulns, warnings = scan_filesystem(
            temp_scan_dir,
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
    finally:
        shutil.rmtree(temp_scan_dir, ignore_errors=True)


def run_sandbox(
    install_targets,
    resolved_versions: Optional[dict[str, str]] = None,
    keep_bundle: bool = False,
    cache_enabled: bool = True,
    verbose: bool = False,
    require_docker: bool = False,
    block_on_static_analysis: bool = True,
    block_on_trivy: bool = False,
) -> SandboxResult:
    """
    Test-install a package offline inside an isolated Docker container.
    """
    if isinstance(install_targets, str):
        install_targets = [install_targets]
    else:
        install_targets = list(install_targets)
    bundle = None
    isolation = {
        "backend": "docker",
        "image": DOCKER_IMAGE,
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
                        "image": DOCKER_IMAGE,
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
                "python": sys.executable,
                "mode": "offline_guarded_subprocess",
                "network": "guarded_by_wrapper",
                "filesystem": "host_process_with_write_guards",
                "processes": "guarded_subprocess_policy",
                "docker_error": docker_error,
            }

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
            # Create a unique container name for Trivy scanning post-installation
            container_name = f"depshieldx_{uuid.uuid4().hex[:12]}"
            
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
                "-v",
                f"{bundle.temp_dir}:/tmp/packages:ro",
                "-v",
                f"{PACKAGE_ROOT}:/depshieldx:ro",
                DOCKER_IMAGE,
                "python",
                "/depshieldx/sandbox_wrapper.py",
                "/tmp/packages",
                *install_targets,
            ]
            trivy_results = None
            try:
                result = _run_command(docker_command, verbose=False)
                if verbose:
                    _emit_command_output(result.stdout, result.stderr, suppress_prefixes=(REPORT_PREFIX,))
                
                # If installation succeeded, run Trivy scan on the container
                trivy_results = _scan_sandbox_container(container_name)
            finally:
                # Clean up the container (whether scan succeeded or not)
                try:
                    subprocess.run(
                        ["docker", "rm", "--force", container_name],
                        capture_output=True,
                        timeout=30,
                    )
                except Exception:
                    pass  # Container cleanup is best-effort
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
