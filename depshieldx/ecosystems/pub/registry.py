"""pub.dev registry client: artifact/checksum fetch, plus structural
provenance signals.

`GET https://pub.dev/api/packages/<name>` is the one real endpoint this
module needs -- confirmed directly against the authoritative response
model (`pkg/_pub_shared/lib/data/package_api.dart` in dart-lang/pub-dev)
and cross-checked against real live responses during development. It
returns `{name, isDiscontinued?, replacedBy?, latest: VersionInfo,
versions: [VersionInfo], advisoriesUpdated?}` where each `VersionInfo` is
`{version, retracted?, pubspec, archive_url, archive_sha256, published?}`.
Fields are declared `@JsonSerializable(includeIfNull: false)` server-side,
so an absent key means "not set" (confirmed directly: a non-discontinued
package's response has no `isDiscontinued`/`replacedBy` keys at all,
rather than `null` values) -- `.get(...)` with a falsy default handles
this correctly throughout this module. Unlike NuGet, there's no separate
search API needed for "give me the latest version" -- `latest.version` on
this same response already provides it.

Checksum verification: `archive_sha256` is a real SHA-256 hex digest of
the exact `archive_url` tarball bytes -- confirmed directly by
downloading a real archive and reproducing the hash locally, and cross-
validated against the *same* value pub itself records in a real
`pubspec.lock`'s `description.sha256` field for that version (see
lockfiles.py's module docstring). Verifying a freshly-downloaded artifact
against the registry's own reported hash is the same pattern
cargo_registry.py/go's registry.py/maven's/nuget's registry.py already
use.

Provenance signals, and why there's no cryptographic signing story here:
no evidence of a Sigstore/PGP/X.509 package-signing scheme for pub.dev
turned up anywhere in this module's research (unlike Maven's Sigstore/PGP
or NuGet's repository-signing) -- pub.dev's own integrity story rests on
this SHA-256 content hash alone, not an independent signature. Structural
signals instead: `isDiscontinued`/`replacedBy` (package-level, an author
or pub.dev admin marking an entire package unmaintained, confirmed
directly against the real `connectivity` package which points to
`connectivity_plus`) and `retracted` (version-level -- a publisher can
retract a version within 7 days of publishing it, confirmed directly
against dart.dev's own publishing docs) -- the closest analogues among
this codebase's ecosystems to npm deprecate/PyPI yank/Cargo yank and,
respectively, Go's retract directive specifically.
"""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from ...storage.cache import get_cache_root

PUB_BASE_URL = "https://pub.dev"
PUB_USER_AGENT = "depshieldx (https://github.com/tee-wealth001/depshieldx)"
PUB_PROVENANCE_CACHE_VERSION = 1
PUB_PROVENANCE_CACHE_TTL = timedelta(hours=24)


def fetch_package_data(package_name: str) -> dict:
    response = requests.get(
        f"{PUB_BASE_URL}/api/packages/{package_name}",
        headers={"User-Agent": PUB_USER_AGENT},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def latest_version(package_name: str) -> str | None:
    try:
        data = fetch_package_data(package_name)
        return (data.get("latest") or {}).get("version")
    except Exception:
        return None


def find_version_info(package_data: dict, version: str) -> dict | None:
    for entry in package_data.get("versions") or []:
        if entry.get("version") == version:
            return entry
    return None


def fetch_archive(archive_url: str) -> bytes:
    response = requests.get(archive_url, headers={"User-Agent": PUB_USER_AGENT}, timeout=60)
    response.raise_for_status()
    return response.content


def _cache_key(package_name: str, version: str | None) -> str:
    payload = f"pub|{package_name}=={version or ''}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _cache_path(package_name: str, version: str | None) -> Path:
    return get_cache_root() / "provenance" / f"{_cache_key(package_name, version)}.json"


def _load_cached_result(package_name: str, version: str | None) -> dict | None:
    try:
        path = _cache_path(package_name, version)
        if not path.exists():
            return None
        payload = json.loads(path.read_text())
        if payload.get("cache_version") != PUB_PROVENANCE_CACHE_VERSION:
            return None
        cached_at = payload.get("cached_at")
        if not cached_at:
            return None
        cached_time = datetime.fromisoformat(cached_at)
        if datetime.now(timezone.utc) - cached_time > PUB_PROVENANCE_CACHE_TTL:
            return None
        return payload.get("result")
    except Exception:
        return None


def _store_cached_result(package_name: str, version: str | None, result: dict) -> None:
    try:
        path = _cache_path(package_name, version)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "cache_version": PUB_PROVENANCE_CACHE_VERSION,
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "result": result,
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    except Exception:
        return


def check_release(package_name: str, version: str, verbose: bool = False) -> dict:
    cached = _load_cached_result(package_name, version)
    if cached is not None:
        return cached

    infos: list[str] = []
    warnings: list[str] = []

    try:
        package_data = fetch_package_data(package_name)
    except Exception as exc:
        result = {
            "package": package_name,
            "version": version,
            "block": False,
            "reason": None,
            "warnings": [f"could not fetch package metadata: {exc}"],
            "infos": [],
            "signals": {},
        }
        _store_cached_result(package_name, version, result)
        return result

    is_discontinued = bool(package_data.get("isDiscontinued"))
    replaced_by = package_data.get("replacedBy")
    if is_discontinued:
        suffix = f" -- suggested replacement: {replaced_by}" if replaced_by else ""
        warnings.append(f"package is discontinued{suffix}")

    version_info = find_version_info(package_data, version)
    filename = f"{package_name}-{version}.tar.gz"
    if version_info is None:
        # A legitimately dart-pub-resolved version should always be in
        # pub.dev's own versions list -- this is a real anomaly, but not
        # tampering by itself, so it's treated the same non-blocking way
        # as an unreachable/erroring checksum check below, not a hard
        # block.
        result = {
            "package": package_name,
            "version": version,
            "block": False,
            "reason": None,
            "warnings": warnings + [f"version {version} was not found in pub.dev's published version list for {package_name}"],
            "infos": infos,
            "signals": {
                "checksum_verified": False,
                "discontinued": is_discontinued,
                "replaced_by": replaced_by,
                "verification_unavailable": {"filename": filename, "error": "resolved version not found in registry metadata"},
            },
        }
        _store_cached_result(package_name, version, result)
        return result

    retracted = bool(version_info.get("retracted"))
    if retracted:
        warnings.append("resolved version has been retracted by its publisher")

    checksum_verified = False
    verification_unavailable = None
    archive_sha256 = version_info.get("archive_sha256")
    archive_url = version_info.get("archive_url")
    if archive_sha256 and archive_url:
        try:
            archive_bytes = fetch_archive(archive_url)
            actual_hash = hashlib.sha256(archive_bytes).hexdigest()
            checksum_verified = actual_hash == archive_sha256
            if not checksum_verified:
                return {
                    "package": package_name,
                    "version": version,
                    "block": True,
                    "reason": "downloaded artifact checksum does not match the registry-reported hash -- possible tampering",
                    "warnings": warnings,
                    "infos": infos,
                    "signals": {"checksum_verified": False, "discontinued": is_discontinued, "retracted": retracted},
                }
            infos.append("resolved artifact has a verified SHA-256 checksum against the registry-reported hash")
        except Exception as exc:
            # A real hash MISMATCH above is a hard block ("possible
            # tampering"); this is the different, non-tampering case
            # where verification simply couldn't complete (network
            # error, ...). Recorded via the same "verification_unavailable"
            # signal shape npm's own attestation-verification-unavailable
            # case and nuget_registry.py's own checksum check already
            # use -- cli/output.py's existing generic display code picks
            # it up automatically, no pub-specific UI work needed.
            infos.append(f"could not verify artifact checksum: {exc}")
            verification_unavailable = {"filename": filename, "error": str(exc)}
    else:
        infos.append("no checksum published for the resolved artifact")
        verification_unavailable = {"filename": filename, "error": "no checksum published by the registry"}

    result = {
        "package": package_name,
        "version": version,
        "block": False,
        "reason": None,
        "warnings": warnings,
        "infos": infos,
        "signals": {
            "checksum_verified": checksum_verified,
            "checksum_algorithm": "SHA256" if archive_sha256 else None,
            "discontinued": is_discontinued,
            "replaced_by": replaced_by,
            "retracted": retracted,
            "verification_unavailable": verification_unavailable,
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

    details = []
    warnings: list[str] = []
    infos: list[str] = []
    for package_name, version in resolved_versions.items():
        result = check_release(package_name, version, verbose=verbose)
        details.append(result)
        if result["block"]:
            return {
                "block": True,
                "reason": f"{package_name}@{version} {result['reason']}",
                "warnings": warnings,
                "infos": infos,
                "details": details,
            }
        warnings.extend([f"{package_name}@{version}: {message}" for message in result["warnings"]])
        infos.extend([f"{package_name}@{version}: {message}" for message in result.get("infos", [])])

    return {"block": False, "warnings": warnings, "infos": infos, "details": details}
