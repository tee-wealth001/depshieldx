from contextlib import redirect_stderr, redirect_stdout
import io
import json
import re
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
import tempfile
from typing import Dict

import requests

from ..storage.cache import get_cache_root


PRE_RELEASE_PATTERN = re.compile(r"(a|b|rc|dev)\d*$", re.IGNORECASE)
PYPI_RELEASE_URL = "https://pypi.org/pypi/{package}/{version}/json"
PYPI_PROJECT_URL = "https://pypi.org/pypi/{package}/json"
PYPI_INTEGRITY_URL = "https://pypi.org/integrity/{package}/{version}/{filename}/provenance"
PROVENANCE_CACHE_VERSION = 3
PROVENANCE_CACHE_TTL = timedelta(hours=24)
def _normalize_name(name: str) -> str:
    return name.strip().lower().replace("-", "_")


def _attestation_verifier_cache_token() -> str:
    try:
        import pypi_attestations
    except Exception:
        return "attestation_verifier:unavailable"
    return f"attestation_verifier:{getattr(pypi_attestations, '__version__', 'unknown')}"


def _selected_artifact_cache_token(selected_files: list[dict] | None) -> str:
    if not selected_files:
        return "selected_artifacts:all_release_files"
    filenames = sorted(
        file_info.get("filename", "")
        for file_info in selected_files
        if file_info.get("filename")
    )
    return "selected_artifacts:" + ",".join(filenames)


def _cache_key(package_name: str, version: str | None, selected_files: list[dict] | None = None) -> str:
    # "pypi" is hardcoded, not threaded through as a parameter, because this whole module is
    # PyPI-specific today (hardcoded PyPI URLs throughout). It's here so a future ecosystem's
    # own cache entries can never collide with these, even if that ecosystem's adapter ends up
    # sharing this cache directory rather than using its own -- see final-plan.md Phase 0
    # definition of done, item 7.
    payload = (
        f"pypi|{_normalize_name(package_name)}=={version or ''}|"
        f"{_attestation_verifier_cache_token()}|"
        f"{_selected_artifact_cache_token(selected_files)}"
    )
    return sha256(payload.encode("utf-8")).hexdigest()


def _cache_path(package_name: str, version: str | None, selected_files: list[dict] | None = None) -> Path:
    return get_cache_root() / "provenance" / f"{_cache_key(package_name, version, selected_files)}.json"


def _load_cached_result(package_name: str, version: str | None, selected_files: list[dict] | None = None) -> dict | None:
    try:
        path = _cache_path(package_name, version, selected_files)
        if not path.exists():
            return None
        payload = json.loads(path.read_text())
        if payload.get("cache_version") != PROVENANCE_CACHE_VERSION:
            return None
        cached_at = payload.get("cached_at")
        if not cached_at:
            return None
        cached_time = datetime.fromisoformat(cached_at)
        if datetime.now(timezone.utc) - cached_time > PROVENANCE_CACHE_TTL:
            return None
        return payload.get("result")
    except Exception:
        return None


def _store_cached_result(package_name: str, version: str | None, result: dict, selected_files: list[dict] | None = None) -> None:
    try:
        path = _cache_path(package_name, version, selected_files)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "cache_version": PROVENANCE_CACHE_VERSION,
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "result": result,
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    except Exception:
        return


def _get_json(url: str) -> dict | None:
    response = requests.get(url, timeout=4)
    response.raise_for_status()
    return response.json()


def _release_payload(package_name: str, version: str | None) -> tuple[dict | None, str | None]:
    try:
        if version:
            return _get_json(PYPI_RELEASE_URL.format(package=package_name, version=version)), None
        project_data = _get_json(PYPI_PROJECT_URL.format(package=package_name))
        resolved_version = project_data.get("info", {}).get("version")
        if not resolved_version:
            return project_data, None
        return _get_json(PYPI_RELEASE_URL.format(package=package_name, version=resolved_version)), None
    except Exception as exc:
        return None, str(exc)


def _parse_integrity_bundle(bundle: dict) -> dict:
    publisher = bundle.get("publisher") or {}
    if publisher:
        attestations = bundle.get("attestations") or []
        verification_material = ((attestations[0] or {}).get("verification_material") or {}) if attestations else {}
        kind = publisher.get("kind")
        repository = publisher.get("repository")
        workflow = publisher.get("workflow") or publisher.get("workflow_filepath")
        issuer = verification_material.get("issuer")
        subject = None
    else:
        verification_material = (bundle.get("verification_material") or {}).get("certificate") or {}
        identity = verification_material.get("identity") or {}
        kind = identity.get("kind")
        repository = identity.get("repository")
        workflow = identity.get("workflow")
        issuer = verification_material.get("issuer")
        subject = bundle.get("subject")
    return {
        "publisher_kind": kind,
        "publisher_repository": repository,
        "publisher_workflow": workflow,
        "issuer": issuer,
        "subject": subject,
        "attestation_count": len(bundle.get("attestations") or []),
    }


def _count_attestations(payload: dict) -> int:
    return sum(len(bundle.get("attestations") or []) for bundle in payload.get("attestation_bundles", []))


def _artifact_path_from_download(temp_dir: str, file_info: dict) -> Path:
    filename = file_info.get("filename") or "artifact"
    url = file_info.get("url")
    if not url:
        raise ValueError("release metadata is missing artifact download URL")

    response = requests.get(url, timeout=10)
    response.raise_for_status()
    artifact_bytes = response.content
    expected_sha256 = (file_info.get("digests") or {}).get("sha256")
    if expected_sha256 and sha256(artifact_bytes).hexdigest() != expected_sha256:
        raise ValueError(f"downloaded artifact hash mismatch for {filename}")

    artifact_path = Path(temp_dir) / filename
    artifact_path.write_bytes(artifact_bytes)
    return artifact_path


def _load_attestation_verifier():
    try:
        import pypi_attestations
    except Exception as exc:
        return None, str(exc)
    return pypi_attestations, None


def _is_attestation_infrastructure_error(message: str) -> bool:
    lowered = message.lower()
    indicators = (
        "failed to refresh tuf metadata",
        "tuf metadata",
        "connection",
        "timeout",
        "timed out",
        "temporary failure",
        "name resolution",
        "nodename nor servname",
        "dns",
        "ssl",
        "certificate verify failed",
        "network is unreachable",
        "connection refused",
    )
    return any(indicator in lowered for indicator in indicators)


def _run_verification_call(func, *, suppress_output: bool = True):
    if not suppress_output:
        return func()
    sink = io.StringIO()
    with redirect_stdout(sink), redirect_stderr(sink):
        return func()


def _cryptographically_verify_attestations(file_info: dict, payload: dict, verbose: bool = False) -> dict:
    attestation_count = _count_attestations(payload)
    verifier_module, import_error = _load_attestation_verifier()
    if import_error:
        return {
            "available": False,
            "verified": False,
            "attestation_count": attestation_count,
            "verified_attestation_count": 0,
            "errors": [f"pypi-attestations unavailable: {import_error}"],
        }
    if attestation_count == 0:
        return {
            "available": False,
            "verified": False,
            "attestation_count": 0,
            "verified_attestation_count": 0,
            "errors": ["provenance payload does not contain verifiable attestation statements"],
        }

    verified_attestation_count = 0
    verification_errors = []
    infrastructure_errors = []
    try:
        provenance = verifier_module.Provenance.model_validate(payload)
        with tempfile.TemporaryDirectory(prefix="depshieldx_attestation_") as temp_dir:
            artifact_path = _artifact_path_from_download(temp_dir, file_info)
            distribution = verifier_module.Distribution.from_file(artifact_path)
            for bundle in provenance.attestation_bundles:
                publisher = bundle.publisher
                for attestation in bundle.attestations:
                    try:
                        _run_verification_call(
                            lambda: attestation.verify(identity=publisher, dist=distribution),
                            suppress_output=not verbose,
                        )
                        verified_attestation_count += 1
                    except Exception as exc:
                        message = str(exc)
                        if _is_attestation_infrastructure_error(message):
                            try:
                                _run_verification_call(
                                    lambda: attestation.verify(identity=publisher, dist=distribution, offline=True),
                                    suppress_output=not verbose,
                                )
                                verified_attestation_count += 1
                                continue
                            except Exception as offline_exc:
                                offline_message = str(offline_exc)
                                if _is_attestation_infrastructure_error(offline_message):
                                    infrastructure_errors.append(offline_message)
                                else:
                                    verification_errors.append(offline_message)
                        else:
                            verification_errors.append(message)
    except Exception as exc:
        message = str(exc)
        if _is_attestation_infrastructure_error(message):
            infrastructure_errors.append(message)
        else:
            verification_errors.append(message)

    verified = verified_attestation_count > 0
    available = bool(verified or verification_errors)
    return {
        "available": available,
        "verified": verified,
        "attestation_count": attestation_count,
        "verified_attestation_count": verified_attestation_count,
        "errors": [] if verified else verification_errors[:3],
        "infrastructure_errors": [] if verified else infrastructure_errors[:3],
    }


def _check_file_provenance(package_name: str, version: str, file_info: dict, verbose: bool = False) -> dict:
    filename = file_info.get("filename", "")
    try:
        payload = _get_json(PYPI_INTEGRITY_URL.format(package=package_name, version=version, filename=filename))
    except Exception:
        return {
            "filename": filename,
            "attested": False,
            "bundles": [],
            "verification": {
                "available": False,
                "verified": False,
                "attestation_count": 0,
                "verified_attestation_count": 0,
                "errors": [],
                "infrastructure_errors": [],
            },
        }

    bundles = [_parse_integrity_bundle(bundle) for bundle in payload.get("attestation_bundles", [])]
    verification = _cryptographically_verify_attestations(file_info, payload, verbose=verbose) if bundles else {
        "available": False,
        "verified": False,
        "attestation_count": 0,
        "verified_attestation_count": 0,
        "errors": [],
        "infrastructure_errors": [],
    }
    return {
        "filename": filename,
        "attested": bool(bundles),
        "bundles": bundles,
        "verification": verification,
    }


def _first_verification_failure(attested_checks: list[dict]) -> dict | None:
    for item in attested_checks:
        verification = item.get("verification") or {}
        if verification.get("verified"):
            continue
        errors = verification.get("errors") or []
        if not errors:
            continue
        return {
            "filename": item.get("filename"),
            "error": errors[0],
        }
    return None


def _first_verification_unavailable(attested_checks: list[dict]) -> dict | None:
    for item in attested_checks:
        verification = item.get("verification") or {}
        infrastructure_errors = verification.get("infrastructure_errors") or []
        if not infrastructure_errors:
            continue
        return {
            "filename": item.get("filename"),
            "error": infrastructure_errors[0],
        }
    return None


def _attestation_signals(package_name: str, version: str, files: list[dict], verbose: bool = False) -> tuple[dict, list[str]]:
    if not files:
        return {
            "has_attestations": False,
            "fully_attested": False,
            "attested_file_count": 0,
            "verified_attestation_file_count": 0,
            "fully_verified_attestations": False,
            "attestation_verification_available": False,
            "verified_attestation_count": 0,
            "verification_failure": None,
            "verification_unavailable": None,
            "trusted_publisher": False,
            "trusted_publisher_count": 0,
            "publisher_kinds": [],
            "publisher_repositories": [],
        }, []

    artifact_files = [file_info for file_info in files if file_info.get("filename")]
    # Keep cryptographic attestation verification on the main thread. The verifier stack
    # pulls in native code, and concurrent cold-cache verification has been observed to
    # terminate the process instead of raising a Python exception.
    provenance_checks = [
        _check_file_provenance(package_name, version, file_info, verbose=verbose)
        for file_info in artifact_files
    ]
    attested = [item for item in provenance_checks if item["attested"]]
    verification_checks = [item.get("verification") or {} for item in attested]
    verification_available = any(item.get("available") for item in verification_checks)
    verified_files = [item for item in attested if (item.get("verification") or {}).get("verified")]
    verification_failure = _first_verification_failure(attested)
    verification_unavailable = _first_verification_unavailable(attested)
    publisher_kinds = sorted(
        {
            bundle["publisher_kind"]
            for item in attested
            for bundle in item["bundles"]
            if bundle.get("publisher_kind")
        }
    )
    publisher_repositories = sorted(
        {
            bundle["publisher_repository"]
            for item in attested
            for bundle in item["bundles"]
            if bundle.get("publisher_repository")
        }
    )
    trusted_publisher_count = sum(
        1
        for item in attested
        for bundle in item["bundles"]
        if bundle.get("publisher_kind") and bundle.get("publisher_repository")
    )
    verified_attestation_count = sum(item.get("verified_attestation_count", 0) for item in verification_checks)
    messages = []
    if not attested:
        messages.append("resolved release has no PyPI attestations")
    elif len(attested) < len(files):
        messages.append(
            f"resolved release has attestations for only {len(attested)} of {len(files)} file(s)"
        )
    if attested and trusted_publisher_count == 0:
        messages.append("resolved release attestations do not include a Trusted Publisher identity")
    if attested and not verification_available:
        messages.append("cryptographic attestation verification unavailable")
    elif attested and len(verified_files) < len(attested):
        messages.append(
            f"cryptographic attestation verification failed for {len(attested) - len(verified_files)} attested file(s)"
        )

    return (
        {
            "has_attestations": bool(attested),
            "fully_attested": bool(attested) and len(attested) == len(files),
            "attested_file_count": len(attested),
            "verified_attestation_file_count": len(verified_files),
            "fully_verified_attestations": bool(attested) and len(verified_files) == len(attested),
            "attestation_verification_available": verification_available,
            "verified_attestation_count": verified_attestation_count,
            "verification_failure": verification_failure,
            "verification_unavailable": verification_unavailable,
            "trusted_publisher": trusted_publisher_count > 0,
            "trusted_publisher_count": trusted_publisher_count,
            "publisher_kinds": publisher_kinds,
            "publisher_repositories": publisher_repositories,
            "selected_file_count": len(files),
        },
        messages,
    )


def _select_release_files(release_files: list[dict], selected_files: list[dict] | None) -> list[dict]:
    if not selected_files:
        return release_files

    selected_by_filename = {
        item.get("filename"): item
        for item in selected_files
        if item.get("filename")
    }
    matched = []
    for file_info in release_files:
        filename = file_info.get("filename")
        if filename in selected_by_filename:
            merged = dict(file_info)
            selected = selected_by_filename[filename]
            if selected.get("url"):
                merged["url"] = selected["url"]
            if selected.get("digests"):
                merged["digests"] = selected["digests"]
            matched.append(merged)
    return matched or selected_files


def _check_release(package_name: str, version: str | None, selected_files: list[dict] | None = None, verbose: bool = False) -> dict:
    cached = _load_cached_result(package_name, version, selected_files)
    if cached is not None:
        return cached

    data, error = _release_payload(package_name, version)
    if error or not data:
        return {
            "package": package_name,
            "version": version,
            "block": False,
            "warnings": [],
            "infos": ["resolved release metadata is missing on PyPI"],
            "signals": {"unavailable": True},
        }

    info = data.get("info", {})
    resolved_version = version or info.get("version")
    files = data.get("urls", [])
    warnings = []
    infos = []
    block = False
    reason = None

    if not files:
        infos.append("resolved release metadata is missing on PyPI")
        has_wheel = False
        has_sdist = False
    else:
        if any(file_info.get("yanked") for file_info in files):
            block = True
            reason = "resolved release is yanked on PyPI"

        has_wheel = any(file_info.get("packagetype") == "bdist_wheel" for file_info in files)
        has_sdist = any(file_info.get("packagetype") == "sdist" for file_info in files)
        if has_sdist and not has_wheel:
            infos.append("resolved release is source-only")

        if not any(file_info.get("digests", {}).get("sha256") for file_info in files):
            infos.append("resolved release is missing sha256 digests in metadata")

    pre_release = bool(resolved_version and PRE_RELEASE_PATTERN.search(resolved_version))
    if pre_release:
        infos.append("resolved version is a pre-release")

    has_homepage = bool(info.get("home_page") or info.get("project_urls"))
    if not has_homepage:
        infos.append("project metadata has no homepage or project URLs")

    has_contact = bool(info.get("author_email") or info.get("maintainer_email"))
    if not has_contact:
        infos.append("project metadata has no author or maintainer email")

    selected_release_files = _select_release_files(files, selected_files)
    attestation_signals, attestation_warnings = _attestation_signals(
        package_name,
        resolved_version,
        selected_release_files,
        verbose=verbose,
    )
    infos.extend(attestation_warnings)
    if (
        attestation_signals["attestation_verification_available"]
        and attestation_signals["has_attestations"]
        and not attestation_signals["fully_verified_attestations"]
    ):
        block = True
        reason = "resolved release attestation verification failed"

    result = {
        "package": package_name,
        "version": resolved_version,
        "block": block,
        "reason": reason,
        "warnings": warnings,
        "infos": infos,
        "signals": {
            "has_homepage": has_homepage,
            "has_contact": has_contact,
            "source_only": bool(files) and has_sdist and not has_wheel,
            "pre_release": pre_release,
            "release_file_count": len(files),
            "unavailable": False,
            **attestation_signals,
        },
    }
    _store_cached_result(package_name, resolved_version, result, selected_files)
    return result


def _check_provenance_batch(
    resolved_versions: Dict[str, str],
    selected_artifacts: Dict[str, list[dict]] | None = None,
    verbose: bool = False,
) -> dict:
    if not resolved_versions:
        return {
            "block": False,
            "warnings": [],
            "infos": [],
            "details": [],
        }

    ordered_items = list(resolved_versions.items())
    results_by_package = {
        package_name: _check_release(
            package_name,
            version,
            (selected_artifacts or {}).get(package_name),
            verbose=verbose,
        )
        for package_name, version in ordered_items
    }

    details = []
    warnings = []
    infos = []
    for package_name, version in ordered_items:
        result = results_by_package[package_name]
        details.append(result)
        if result["block"]:
            return {
                "block": True,
                "reason": f"{package_name}=={version} {result['reason']}",
                "warnings": warnings,
                "infos": infos,
                "details": details,
            }
        warnings.extend([f"{package_name}=={version}: {warning}" for warning in result["warnings"]])
        infos.extend([f"{package_name}=={version}: {info}" for info in result.get("infos", [])])

    return {
        "block": False,
        "warnings": warnings,
        "infos": infos,
        "details": details,
    }


def check_provenance_batch(
    resolved_versions: Dict[str, str],
    selected_artifacts: Dict[str, list[dict]] | None = None,
    verbose: bool = False,
) -> dict:
    return _check_provenance_batch(resolved_versions, selected_artifacts=selected_artifacts, verbose=verbose)
