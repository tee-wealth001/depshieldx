"""npm registry client: package metadata fetch + structural provenance signals.

Provenance here is intentionally structural, not cryptographic -- it checks
whether attestations exist and their predicate type, not full Sigstore bundle
verification (Fulcio certificate chain, Rekor transparency-log inclusion
proof). npm's real provenance attestations are full Sigstore bundles
(confirmed against the live registry API); verifying them properly is
real, separate future work, matching the same honest scoping already used
for crates.io in final-plan.md's Phase 2. Never claim cryptographic
verification happened when only structural signals were checked.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from .cache import get_cache_root

NPM_REGISTRY_PACKAGE_URL = "https://registry.npmjs.org/{package}"
NPM_PROVENANCE_CACHE_VERSION = 1
NPM_PROVENANCE_CACHE_TTL = timedelta(hours=24)


def _cache_key(package_name: str, version: str | None) -> str:
    from hashlib import sha256

    payload = f"npm|{package_name}=={version or ''}"
    return sha256(payload.encode("utf-8")).hexdigest()


def _cache_path(package_name: str, version: str | None) -> Path:
    return get_cache_root() / "provenance" / f"{_cache_key(package_name, version)}.json"


def _load_cached_result(package_name: str, version: str | None) -> dict | None:
    try:
        path = _cache_path(package_name, version)
        if not path.exists():
            return None
        payload = json.loads(path.read_text())
        if payload.get("cache_version") != NPM_PROVENANCE_CACHE_VERSION:
            return None
        cached_at = payload.get("cached_at")
        if not cached_at:
            return None
        cached_time = datetime.fromisoformat(cached_at)
        if datetime.now(timezone.utc) - cached_time > NPM_PROVENANCE_CACHE_TTL:
            return None
        return payload.get("result")
    except Exception:
        return None


def _store_cached_result(package_name: str, version: str | None, result: dict) -> None:
    try:
        path = _cache_path(package_name, version)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "cache_version": NPM_PROVENANCE_CACHE_VERSION,
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "result": result,
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    except Exception:
        return


def fetch_package_metadata(package_name: str) -> dict:
    """Raises on network/HTTP failure; caller decides how to treat that."""
    response = requests.get(NPM_REGISTRY_PACKAGE_URL.format(package=package_name), timeout=5)
    response.raise_for_status()
    return response.json()


def _unavailable_result(package_name: str, version: str | None) -> dict:
    return {
        "package": package_name,
        "version": version,
        "block": False,
        "reason": None,
        "warnings": [],
        "infos": ["resolved release metadata is missing on the npm registry"],
        "signals": {"unavailable": True},
    }


def check_release(package_name: str, version: str | None = None) -> dict:
    cached = _load_cached_result(package_name, version)
    if cached is not None:
        return cached

    try:
        data = fetch_package_metadata(package_name)
    except Exception:
        # Don't cache network failures -- they should be retried on the next run.
        return _unavailable_result(package_name, version)

    versions = data.get("versions") or {}
    resolved_version = version or (data.get("dist-tags") or {}).get("latest")
    version_meta = versions.get(resolved_version) if resolved_version else None

    if not version_meta:
        result = _unavailable_result(package_name, resolved_version)
        _store_cached_result(package_name, version, result)
        return result

    infos: list[str] = []
    dist = version_meta.get("dist") or {}

    deprecated_message = version_meta.get("deprecated")
    if deprecated_message:
        infos.append(f"resolved version is deprecated: {deprecated_message}")

    has_homepage = bool(version_meta.get("homepage") or version_meta.get("repository"))
    if not has_homepage:
        infos.append("package metadata has no homepage or repository URL")

    has_contact = bool(version_meta.get("author") or version_meta.get("maintainers"))
    if not has_contact:
        infos.append("package metadata has no author or maintainer contact")

    attestations = dist.get("attestations") or {}
    has_attestations = bool(attestations)
    attestation_predicate_type = (attestations.get("provenance") or {}).get("predicateType")
    if not has_attestations:
        infos.append("resolved release has no npm provenance attestations")

    has_integrity = bool(dist.get("integrity") or dist.get("shasum"))
    if not has_integrity:
        infos.append("resolved release is missing an integrity/shasum digest")

    result = {
        "package": package_name,
        "version": resolved_version,
        # Structural checks only (see module docstring) -- never block on these alone.
        "block": False,
        "reason": None,
        "warnings": [],
        "infos": infos,
        "signals": {
            "has_homepage": has_homepage,
            "has_contact": has_contact,
            "deprecated": bool(deprecated_message),
            "has_attestations": has_attestations,
            "attestation_predicate_type": attestation_predicate_type,
            "has_integrity_digest": has_integrity,
            "unavailable": False,
        },
    }
    _store_cached_result(package_name, version, result)
    return result


def check_provenance_batch(
    resolved_versions: dict[str, str],
    selected_artifacts: dict[str, list[dict]] | None = None,
    verbose: bool = False,
) -> dict:
    if not resolved_versions:
        return {"block": False, "warnings": [], "infos": [], "details": []}

    ordered_items = list(resolved_versions.items())
    details = []
    warnings: list[str] = []
    infos: list[str] = []
    for package_name, version in ordered_items:
        result = check_release(package_name, version)
        details.append(result)
        warnings.extend([f"{package_name}@{version}: {message}" for message in result["warnings"]])
        infos.extend([f"{package_name}@{version}: {message}" for message in result.get("infos", [])])

    return {"block": False, "warnings": warnings, "infos": infos, "details": details}
