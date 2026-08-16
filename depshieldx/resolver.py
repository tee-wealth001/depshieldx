# import subprocess

# def resolve_dependencies(package):
#     """Resolve package dependencies using pip."""
#     try:
#         result = subprocess.run(
#             ["pip", "download", package, "--dry-run", "--json"],
#             capture_output=True, text=True
#         )
#         # For simplicity, include top-level package only
#         packages = [package]
#         return packages
#     except:
#         return [package]


import json
from pathlib import Path
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import List
from urllib.parse import urlparse

from .runtime import pip_command


@dataclass
class ResolutionResult:
    packages: List[str]
    install_target: str
    resolved_versions: dict[str, str]
    selected_artifacts: dict[str, list[dict]] = field(default_factory=dict)
    install_args: List[str] = field(default_factory=list)
    requested_targets: List[str] = field(default_factory=list)
    source_type: str = "package"
    resolution_succeeded: bool = True
    resolution_error: str | None = None


def _resolution_error_detail(exc: subprocess.CalledProcessError) -> str:
    detail = (exc.stderr or exc.stdout or "").strip()
    if detail:
        return detail
    return str(exc)


def _looks_like_direct_reference(target: str) -> bool:
    value = target.strip()
    if not value:
        return False
    if value.startswith(("file:", "http://", "https://", "./", "../", "/", "~")):
        return True
    if "/" in value or "\\" in value:
        return True
    path = Path(value)
    if path.suffix in {".whl", ".zip", ".tar", ".tgz"}:
        return True
    if path.suffixes[-2:] == [".tar", ".gz"]:
        return True
    return False


def _build_install_target(package_name: str, report: dict) -> str:
    requested = package_name.strip()
    requested_name = requested.split("[", 1)[0].split("==", 1)[0].split(">=", 1)[0]

    for item in report.get("install", []):
        metadata = item.get("metadata", {})
        if metadata.get("name", "").lower() == requested_name.lower():
            version = metadata.get("version")
            if version:
                return f"{metadata['name']}=={version}"
    if _looks_like_direct_reference(requested):
        for item in report.get("install", []):
            metadata = item.get("metadata", {})
            name = metadata.get("name")
            version = metadata.get("version")
            if name and version:
                return f"{name}=={version}"
    return package_name


def _build_resolution_result(
    report: dict,
    install_target: str,
    fallback_packages: list[str],
    install_args: list[str],
    requested_targets: list[str],
    source_type: str,
) -> ResolutionResult:
    packages = []
    resolved_versions = {}
    selected_artifacts: dict[str, list[dict]] = {}
    for item in report.get("install", []):
        metadata = item.get("metadata", {})
        name = metadata.get("name")
        if name and name not in packages:
            packages.append(name)
        if name and metadata.get("version"):
            resolved_versions[name] = metadata["version"]
        selected = _selected_artifact(item)
        if name and selected:
            selected_artifacts.setdefault(name, []).append(selected)
    if not packages:
        packages = fallback_packages
    if not resolved_versions:
        resolved_versions = {package: "" for package in fallback_packages}

    direct_reference = any(_looks_like_direct_reference(item) for item in install_args)
    exact_install_args = []
    if not direct_reference:
        for item in report.get("install", []):
            metadata = item.get("metadata", {})
            name = metadata.get("name")
            version = metadata.get("version")
            if name and version:
                exact_install_args.append(f"{name}=={version}")
    if not exact_install_args:
        exact_install_args = install_args[:]

    return ResolutionResult(
        packages=packages,
        install_target=install_target,
        resolved_versions=resolved_versions,
        selected_artifacts=selected_artifacts,
        install_args=exact_install_args,
        requested_targets=requested_targets,
        source_type=source_type,
    )


def _load_pip_report(report_path: Path) -> dict:
    return json.loads(report_path.read_text(encoding="utf-8-sig"))


def _selected_artifact(item: dict) -> dict | None:
    download_info = item.get("download_info") or {}
    url = download_info.get("url")
    if not url:
        return None

    filename = Path(urlparse(url).path).name
    if not filename:
        return None

    archive_info = download_info.get("archive_info") or {}
    sha256_digest = (archive_info.get("hashes") or {}).get("sha256")
    if not sha256_digest:
        hash_value = archive_info.get("hash") or ""
        if hash_value.startswith("sha256="):
            sha256_digest = hash_value.split("=", 1)[1]

    return {
        "filename": filename,
        "url": url,
        "digests": {"sha256": sha256_digest} if sha256_digest else {},
        "packagetype": _packagetype_for_filename(filename),
    }


def _packagetype_for_filename(filename: str) -> str | None:
    path = Path(filename)
    if path.suffix == ".whl":
        return "bdist_wheel"
    if path.suffix == ".zip" or path.suffix == ".tar" or path.suffix == ".tgz" or path.suffixes[-2:] == [".tar", ".gz"]:
        return "sdist"
    return None


def resolve_install_inputs(
    pip_args: list[str],
    requested_targets: list[str],
    install_target: str,
    source_type: str = "package",
) -> ResolutionResult:
    """
    Resolve dependency names with pip's dry-run report output.
    Falls back to the top-level package if resolution fails.
    """
    report_path = None
    try:
        with tempfile.NamedTemporaryFile(prefix="depshieldx_report_", suffix=".json", delete=False) as report_file:
            report_path = Path(report_file.name)
        subprocess.run(
            pip_command(
                [
                    "install",
                    "--quiet",
                    "--dry-run",
                    "--ignore-installed",
                    "--report",
                    str(report_path),
                    *pip_args,
                ]
            ),
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        if report_path:
            report_path.unlink(missing_ok=True)
        return ResolutionResult(
            packages=[],
            install_target=install_target,
            resolved_versions={},
            install_args=pip_args[:],
            requested_targets=requested_targets[:],
            source_type=source_type,
            resolution_succeeded=False,
            resolution_error=_resolution_error_detail(exc),
        )

    try:
        report = _load_pip_report(report_path)
        if source_type == "package" and requested_targets:
            install_target = _build_install_target(requested_targets[0], report)
        return _build_resolution_result(
            report,
            install_target=install_target,
            fallback_packages=requested_targets[:],
            install_args=pip_args[:],
            requested_targets=requested_targets[:],
            source_type=source_type,
        )
    except Exception as exc:
        return ResolutionResult(
            packages=[],
            install_target=install_target,
            resolved_versions={},
            install_args=pip_args[:],
            requested_targets=requested_targets[:],
            source_type=source_type,
            resolution_succeeded=False,
            resolution_error=f"failed to parse pip resolution report: {exc}",
        )
    finally:
        if report_path:
            report_path.unlink(missing_ok=True)


def resolve_dependencies(package_name: str) -> ResolutionResult:
    return resolve_install_inputs(
        [package_name],
        [package_name],
        package_name,
        source_type="package",
    )
