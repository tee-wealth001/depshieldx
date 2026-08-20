"""NuGet.org registry client: artifact/checksum fetch, plus structural
provenance signals.

Base URLs below are hardcoded rather than discovered from the real v3
service index (https://api.nuget.org/v3/index.json) -- confirmed directly
this is nuget.org's own documented indirection mechanism (resource URLs
are, in principle, free to change over time), but every other registry
client in this codebase (Maven Central, crates.io, the Go module proxy)
hardcodes its base URL the same pragmatic way, and these specific URLs
are nuget.org's own long-stable, widely-documented endpoints, confirmed
directly against a real service-index fetch during development.

Checksum verification: NuGet has no per-package ".nupkg.sha512" sidecar
file reliably served from the flat-container endpoint (confirmed
directly -- a real request for a real, currently-published package
returned 404 BlobNotFound). The registration/catalog API's own
"packageHash"/"packageHashAlgorithm" fields are the real source of
truth instead -- confirmed directly this is SHA-512 of the *exact*
bytes served from packageContent (byte-for-byte reproduced locally
against a real download). This is deliberately NOT the same value as a
real packages.lock.json's own "contentHash" field for the same package
version (confirmed directly these differ) -- contentHash is computed by
the NuGet client via a different, signature-aware algorithm this module
doesn't need to reproduce, since verifying a freshly-downloaded artifact
against the registry's own reported hash (the same pattern
cargo_registry.py/go's registry.py/maven's registry.py all already use)
is the correct check here, not reproducing a lockfile-internal value.

Provenance signals, and why the model differs from Maven's cryptographic
Sigstore/PGP split: NuGet.org repository-signs every package on upload
(an X.509/Authenticode-based signature chain -- confirmed directly via a
real downloaded .nupkg's zip listing containing a ".signature.p7s"
entry), not a Sigstore/transparency-log scheme -- no Sigstore
infrastructure for NuGet.org turned up anywhere in this module's
research. Verifying an arbitrary X.509 signature chain would require a
trust-root/certificate-chain-validation story this codebase has nothing
comparable to elsewhere (unlike Sigstore's Fulcio-issued, OIDC-bound
certificates PyPI/npm/Maven already verify), so signature presence is
recorded structurally only, the same "presence, not verification" choice
npm_registry.py already makes for npm's own non-Sigstore "publish"
attestation.

"Unlisted" (NuGet's real, structural yank-equivalent -- `nuget delete`
hides a version from search/default restore without deleting it,
confirmed directly the registration API's own "listed" field reflects
this for a real unlisted package) and "deprecation" (a real, structural
signal with a message/alternatePackage/reasons -- confirmed directly
against a real deprecated package's catalog entry) are both surfaced
directly by the same registration/catalog fetch that provides the
checksum, no separate API call needed.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from ...storage.cache import get_cache_root

NUGET_FLAT_CONTAINER_BASE_URL = "https://api.nuget.org/v3-flatcontainer"
NUGET_REGISTRATION_BASE_URL = "https://api.nuget.org/v3/registration5-gz-semver2"
NUGET_SEARCH_URL = "https://azuresearch-usnc.nuget.org/query"
NUGET_USER_AGENT = "depshieldx (https://github.com/tee-wealth001/depshieldx)"
NUGET_SIGNATURE_ENTRY_NAME = ".signature.p7s"
NUGET_PROVENANCE_CACHE_VERSION = 1
NUGET_PROVENANCE_CACHE_TTL = timedelta(hours=24)


def _lower(value: str) -> str:
    return value.strip().lower()


def flat_container_nupkg_url(package_id: str, version: str) -> str:
    # PackageBaseAddress (flat-container) requires lowercase id/version
    # path segments -- confirmed directly, an uppercase-cased request
    # 404s while the lowercased one resolves.
    lowered_id, lowered_version = _lower(package_id), _lower(version)
    return f"{NUGET_FLAT_CONTAINER_BASE_URL}/{lowered_id}/{lowered_version}/{lowered_id}.{lowered_version}.nupkg"


def fetch_nupkg(package_id: str, version: str) -> bytes:
    response = requests.get(
        flat_container_nupkg_url(package_id, version),
        headers={"User-Agent": NUGET_USER_AGENT},
        timeout=60,
    )
    response.raise_for_status()
    return response.content


def fetch_catalog_entry(package_id: str, version: str) -> dict:
    """Raises on network/HTTP failure; caller decides how to treat that.
    Returns the registration API's full catalog entry -- packageHash,
    packageHashAlgorithm, listed, and deprecation (when present) all
    live here, confirmed directly against real registration responses
    for a normal package, an unlisted package, and a deprecated package."""
    registration_response = requests.get(
        f"{NUGET_REGISTRATION_BASE_URL}/{_lower(package_id)}/{_lower(version)}.json",
        headers={"User-Agent": NUGET_USER_AGENT},
        timeout=10,
    )
    registration_response.raise_for_status()
    catalog_url = registration_response.json()["catalogEntry"]

    catalog_response = requests.get(catalog_url, headers={"User-Agent": NUGET_USER_AGENT}, timeout=10)
    catalog_response.raise_for_status()
    return catalog_response.json()


def search_latest_version(package_id: str) -> str | None:
    try:
        response = requests.get(
            NUGET_SEARCH_URL,
            params={"q": f"packageid:{package_id}", "prerelease": "false", "take": 1},
            headers={"User-Agent": NUGET_USER_AGENT},
            timeout=10,
        )
        response.raise_for_status()
        docs = response.json().get("data") or []
        return docs[0].get("version") if docs else None
    except Exception:
        return None


def has_repository_signature(nupkg_bytes: bytes) -> bool:
    """Structural only -- see module docstring for why this isn't (and,
    without an X.509 trust-chain validation story this codebase has
    nowhere else, can't responsibly be) cryptographically verified."""
    import zipfile
    from io import BytesIO

    try:
        with zipfile.ZipFile(BytesIO(nupkg_bytes)) as archive:
            return NUGET_SIGNATURE_ENTRY_NAME in archive.namelist()
    except Exception:
        return False


def _cache_key(package_id: str, version: str | None) -> str:
    from hashlib import sha256

    payload = f"nuget|{package_id}=={version or ''}"
    return sha256(payload.encode("utf-8")).hexdigest()


def _cache_path(package_id: str, version: str | None) -> Path:
    return get_cache_root() / "provenance" / f"{_cache_key(package_id, version)}.json"


def _load_cached_result(package_id: str, version: str | None) -> dict | None:
    try:
        path = _cache_path(package_id, version)
        if not path.exists():
            return None
        payload = json.loads(path.read_text())
        if payload.get("cache_version") != NUGET_PROVENANCE_CACHE_VERSION:
            return None
        cached_at = payload.get("cached_at")
        if not cached_at:
            return None
        cached_time = datetime.fromisoformat(cached_at)
        if datetime.now(timezone.utc) - cached_time > NUGET_PROVENANCE_CACHE_TTL:
            return None
        return payload.get("result")
    except Exception:
        return None


def _store_cached_result(package_id: str, version: str | None, result: dict) -> None:
    try:
        path = _cache_path(package_id, version)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "cache_version": NUGET_PROVENANCE_CACHE_VERSION,
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "result": result,
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    except Exception:
        return


def check_release(package_id: str, version: str, verbose: bool = False) -> dict:
    cached = _load_cached_result(package_id, version)
    if cached is not None:
        return cached

    infos: list[str] = []
    warnings: list[str] = []

    try:
        catalog_entry = fetch_catalog_entry(package_id, version)
    except Exception as exc:
        result = {
            "package": package_id,
            "version": version,
            "block": False,
            "reason": None,
            "warnings": [f"could not fetch registration metadata: {exc}"],
            "infos": [],
            "signals": {},
        }
        _store_cached_result(package_id, version, result)
        return result

    listed = catalog_entry.get("listed")
    if listed is False:
        warnings.append("resolved version is unlisted on NuGet.org -- hidden from search/default restore, but still resolvable when pinned exactly")

    deprecation = catalog_entry.get("deprecation")
    if deprecation:
        message = deprecation.get("message") or "no message provided"
        warnings.append(f"resolved version is marked deprecated: {message}")

    checksum_verified = False
    package_hash = catalog_entry.get("packageHash")
    package_hash_algorithm = catalog_entry.get("packageHashAlgorithm")
    signed = False
    filename = f"{package_id}.{version}.nupkg"
    verification_unavailable = None
    if package_hash and package_hash_algorithm:
        try:
            import base64
            import hashlib

            nupkg_bytes = fetch_nupkg(package_id, version)
            digest = hashlib.new(package_hash_algorithm.lower(), nupkg_bytes).digest()
            actual_hash = base64.b64encode(digest).decode("ascii")
            checksum_verified = actual_hash == package_hash
            if not checksum_verified:
                return {
                    "package": package_id,
                    "version": version,
                    "block": True,
                    "reason": "downloaded artifact checksum does not match the registry-reported hash -- possible tampering",
                    "warnings": warnings,
                    "infos": infos,
                    "signals": {"checksum_verified": False, "listed": listed},
                }
            signed = has_repository_signature(nupkg_bytes)
            infos.append(f"resolved artifact has a verified {package_hash_algorithm} checksum against the registry-reported hash")
            if signed:
                infos.append("resolved artifact has a repository signature (X.509/Authenticode-based, presence only -- see module docstring for why this isn't cryptographically verified)")
        except Exception as exc:
            # A real hash MISMATCH above is a hard block ("possible
            # tampering"); this is the different, non-tampering case
            # where verification simply couldn't complete (network
            # error, unrecognized hash algorithm, ...). Recorded via the
            # same "verification_unavailable" signal shape npm's own
            # attestation-verification-unavailable case already uses
            # (see ecosystems/npm/registry.py) -- cli/output.py already
            # renders that shape as a dedicated "Attestation
            # infrastructure issue" summary line for any ecosystem, no
            # NuGet-specific display code needed.
            infos.append(f"could not verify artifact checksum: {exc}")
            verification_unavailable = {"filename": filename, "error": str(exc)}
    else:
        infos.append("no checksum published for the resolved artifact")
        verification_unavailable = {"filename": filename, "error": "no checksum published by the registry"}

    result = {
        "package": package_id,
        "version": version,
        "block": False,
        "reason": None,
        "warnings": warnings,
        "infos": infos,
        "signals": {
            "checksum_verified": checksum_verified,
            "checksum_algorithm": package_hash_algorithm,
            "listed": listed,
            "deprecated": bool(deprecation),
            "repository_signed": signed,
            "verification_unavailable": verification_unavailable,
        },
    }
    _store_cached_result(package_id, version, result)
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
    for package_id, version in resolved_versions.items():
        result = check_release(package_id, version, verbose=verbose)
        details.append(result)
        if result["block"]:
            return {
                "block": True,
                "reason": f"{package_id}@{version} {result['reason']}",
                "warnings": warnings,
                "infos": infos,
                "details": details,
            }
        warnings.extend([f"{package_id}@{version}: {message}" for message in result["warnings"]])
        infos.extend([f"{package_id}@{version}: {message}" for message in result.get("infos", [])])

    return {"block": False, "warnings": warnings, "infos": infos, "details": details}
