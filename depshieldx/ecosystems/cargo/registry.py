"""crates.io registry client: package metadata fetch + structural
(non-cryptographic) provenance signals.

crates.io currently has no Sigstore/SLSA attestation infrastructure at all
-- confirmed directly against the real crates.io "Trusted Publishing" RFC
(rust-lang/rfcs#3691), which explicitly lists "provenance verification of
published crates (e.g. sigstore or other signing mechanisms)" as out of
scope. The only real signal is a `trustpub_data` field on the per-version API
response (confirmed via live API calls -- e.g. release-plz/release-plz,
which publishes via GitHub Actions Trusted Publishing, returns
{"provider": "github", "repository": "release-plz/release-plz",
"run_id": "...", "sha": "..."}) -- self-reported metadata the registry
records at publish time, with no signature, certificate, or transparency-log
entry backing it. Nothing here is cryptographically verified, and this
module must never imply otherwise. Recorded structurally only, the same
spirit as how npm's non-cryptographic "publish" attestation is recorded in
npm_registry.py without being verified -- never blocked on.

crates.io's documented crawler policy requires a descriptive User-Agent (the
application's name plus a way to reach its maintainer, not a bare HTTP
client's default) and expects automated clients to stay within roughly one
request per second -- both stricter than what npm's/PyPI's registries
require of depshieldx today.
"""

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from ...storage.cache import get_cache_root

CRATES_IO_VERSION_URL = "https://crates.io/api/v1/crates/{name}/{version}"
CRATES_IO_BASE_URL = "https://crates.io"
CRATES_IO_USER_AGENT = "depshieldx (https://github.com/tee-wealth001/depshieldx)"
CRATES_IO_MIN_REQUEST_INTERVAL = 1.0
CARGO_PROVENANCE_CACHE_VERSION = 1
CARGO_PROVENANCE_CACHE_TTL = timedelta(hours=24)

_last_request_monotonic = 0.0


def _throttle() -> None:
    """crates.io's crawler policy asks automated clients to stay within
    ~1 request/second -- unlike npm_registry.py/provenance.py, which don't
    need this for their registries. check_provenance_batch's loop below is
    sequential (same as npm's), so a simple module-level last-request
    timestamp is enough to keep every crates.io call, across an entire
    batch, spaced out correctly."""
    global _last_request_monotonic
    elapsed = time.monotonic() - _last_request_monotonic
    if elapsed < CRATES_IO_MIN_REQUEST_INTERVAL:
        time.sleep(CRATES_IO_MIN_REQUEST_INTERVAL - elapsed)
    _last_request_monotonic = time.monotonic()


def _cache_key(name: str, version: str | None) -> str:
    from hashlib import sha256

    payload = f"cargo|{name}=={version or ''}"
    return sha256(payload.encode("utf-8")).hexdigest()


def _cache_path(name: str, version: str | None) -> Path:
    return get_cache_root() / "provenance" / f"{_cache_key(name, version)}.json"


def _load_cached_result(name: str, version: str | None) -> dict | None:
    try:
        path = _cache_path(name, version)
        if not path.exists():
            return None
        payload = json.loads(path.read_text())
        if payload.get("cache_version") != CARGO_PROVENANCE_CACHE_VERSION:
            return None
        cached_at = payload.get("cached_at")
        if not cached_at:
            return None
        cached_time = datetime.fromisoformat(cached_at)
        if datetime.now(timezone.utc) - cached_time > CARGO_PROVENANCE_CACHE_TTL:
            return None
        return payload.get("result")
    except Exception:
        return None


def _store_cached_result(name: str, version: str | None, result: dict) -> None:
    try:
        path = _cache_path(name, version)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "cache_version": CARGO_PROVENANCE_CACHE_VERSION,
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "result": result,
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    except Exception:
        return


def fetch_version_metadata(name: str, version: str) -> dict:
    """Raises on network/HTTP failure; caller decides how to treat that."""
    _throttle()
    response = requests.get(
        CRATES_IO_VERSION_URL.format(name=name, version=version),
        headers={"User-Agent": CRATES_IO_USER_AGENT},
        timeout=5,
    )
    response.raise_for_status()
    return response.json()


def _unavailable_result(name: str, version: str | None) -> dict:
    return {
        "package": name,
        "version": version,
        "block": False,
        "reason": None,
        "warnings": [],
        "infos": ["resolved release metadata is missing on crates.io"],
        "signals": {"unavailable": True},
    }


def check_release(name: str, version: str, verbose: bool = False) -> dict:
    cached = _load_cached_result(name, version)
    if cached is not None:
        return cached

    try:
        data = fetch_version_metadata(name, version)
    except Exception:
        # Don't cache network failures -- they should be retried on the next run.
        return _unavailable_result(name, version)

    version_meta = data.get("version") or {}
    if not version_meta:
        result = _unavailable_result(name, version)
        _store_cached_result(name, version, result)
        return result

    infos: list[str] = []

    trustpub = version_meta.get("trustpub_data")
    has_trustpub = bool(trustpub)
    if not has_trustpub:
        infos.append("resolved release has no Trusted Publishing metadata")
    else:
        infos.append(
            "resolved release published via Trusted Publishing "
            f"({trustpub.get('provider')}: {trustpub.get('repository')})"
        )

    yanked = bool(version_meta.get("yanked"))
    if yanked:
        infos.append("resolved release is yanked on crates.io")

    checksum = version_meta.get("checksum")
    has_checksum = bool(checksum)
    if not has_checksum:
        infos.append("resolved release is missing a checksum digest")

    block = False
    reason = None
    if yanked:
        # Mirrors provenance.py's exact PyPI policy for yanked releases --
        # crates.io's "yanked" is the same concept (registry marks a
        # specific version as not to be newly depended upon, without
        # deleting it), unlike npm's "deprecated" (an author advisory,
        # treated as informational-only in npm_registry.py) -- this is a
        # real, independent safety signal, not part of the "no cryptographic
        # provenance" limitation.
        block = True
        reason = "resolved release is yanked on crates.io"

    result = {
        "package": name,
        "version": version,
        "block": block,
        "reason": reason,
        "warnings": [],
        "infos": infos,
        "signals": {
            "has_trustpub_data": has_trustpub,
            "trustpub_provider": trustpub.get("provider") if trustpub else None,
            "trustpub_repository": trustpub.get("repository") if trustpub else None,
            "trustpub_run_id": trustpub.get("run_id") if trustpub else None,
            "trustpub_sha": trustpub.get("sha") if trustpub else None,
            # Always False -- crates.io has no attestation infrastructure to
            # verify against (see module docstring). Never reuse npm's
            # Fulcio-verified "trusted_publisher" semantics here.
            "verification_available": False,
            "trusted_publisher": False,
            "yanked": yanked,
            "has_checksum": has_checksum,
            "unavailable": False,
        },
    }
    _store_cached_result(name, version, result)
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
    for name, version in ordered_items:
        result = check_release(name, version, verbose=verbose)
        details.append(result)
        if result["block"]:
            return {
                "block": True,
                "reason": f"{name}@{version} {result['reason']}",
                "warnings": warnings,
                "infos": infos,
                "details": details,
            }
        warnings.extend([f"{name}@{version}: {message}" for message in result["warnings"]])
        infos.extend([f"{name}@{version}: {message}" for message in result.get("infos", [])])

    return {"block": False, "warnings": warnings, "infos": infos, "details": details}
