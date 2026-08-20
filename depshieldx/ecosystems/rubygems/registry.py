"""RubyGems.org registry client: artifact/checksum fetch, plus structural
provenance signals (yank detection).

Two real, distinct endpoints this module needs, both confirmed directly
against live rubygems.org responses:

`GET https://rubygems.org/api/v1/gems/<name>.json` -> the LATEST version's
full metadata (used only for "give me the latest version" resolution --
no separate search API is needed, mirroring pub.dev's own `latest.version`
shortcut). Returns `{name, version, platform, sha, dependencies, ...}` for
that latest release. A nonexistent gem name 404s cleanly (confirmed
directly: "This rubygem could not be found."), so latest_version()'s
try/except-None below is a real "doesn't exist" signal, not a guess.

`GET https://rubygems.org/api/v2/rubygems/<name>/versions/<version>.json`
-> one SPECIFIC version's metadata: `{name, version, platform, yanked,
sha, spec_sha, gem_uri, dependencies, ...}`. Confirmed directly this
defaults to the platform-agnostic "ruby" variant when a gem publishes
multiple platform-specific builds (e.g. nokogiri ships separate x86_64-
linux/x64-mingw-ucrt/java/... builds with different sha256 hashes each) --
matching what a real `bundle lock` on this same system also resolved to
by default with no extra flags. See lockfiles.py's module docstring for
the platform-selection tradeoff this mirrors; platform-specific artifact
selection is out of scope for this module.

Checksum verification: `sha` is a real SHA-256 hex digest of the exact
`gem_uri` .gem file's bytes -- confirmed directly by downloading a real
.gem file and reproducing the hash locally, and cross-validated against
the *same* value a real Gemfile.lock's own CHECKSUMS section records for
that gem@version (on by default in Bundler 4.0.16, confirmed directly --
see lockfiles.py). Verifying a freshly-downloaded artifact against the
registry's own reported hash is the same pattern every other ecosystem's
registry.py here already uses.

Yank detection -- the one genuinely surprising finding this module is
built around: unlike NuGet's "unlisted" (still resolvable/queryable when
pinned exactly, just hidden from search) or Pub's "retracted" (the
version stays in the registry's own versions list forever, just flagged),
a RubyGems version that was yanked long enough ago is removed outright --
confirmed directly against the real 2019 rest-client 1.6.10-1.6.13
hijack incident: both the full `GET /api/v1/versions/rest-client.json`
list and the per-version `GET /api/v2/rubygems/rest-client/versions/
1.6.13.json` endpoint have no record of it at all (a plain 404, "This
version could not be found.", not a `{"yanked": true}` payload). The API
schema does support a `yanked` boolean field for versions it still
tracks (confirmed directly against rubygems.org's own API documentation
example response) -- so a version yanked recently enough may still
surface `yanked: true` here. But a 404 is genuinely ambiguous between
"this exact version never existed" (a typo, or a lockfile referencing
something that was never published) and "this version was yanked long
enough ago to be fully purged" -- and depshieldx has no reliable way to
tell those apart from this API alone. Rather than overclaim a specific
cause, a 404 here is surfaced as an honest "could not verify this version
against the registry" warning (verification_unavailable), the same
non-blocking treatment Pub's own "version not found in registry metadata"
case already gets -- not asserted as a confirmed yank.

Provenance signals, and why there's no cryptographic signing story here:
Sigstore support for rubygems.org exists but is still opt-in/in-progress,
and the older `gem cert`/`gem build --sign` X.509 scheme is opt-in and
rarely used in practice -- no evidence of a default, always-present
cryptographic signature the way PyPI/npm/Maven's Sigstore or NuGet's
repository-signing provide turned up for the general case, so (mirroring
Pub's own reasoning) this module's integrity story rests on the SHA-256
content hash alone.
"""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from ...storage.cache import get_cache_root

RUBYGEMS_BASE_URL = "https://rubygems.org"
RUBYGEMS_USER_AGENT = "depshieldx (https://github.com/tee-wealth001/depshieldx)"
RUBYGEMS_PROVENANCE_CACHE_VERSION = 1
RUBYGEMS_PROVENANCE_CACHE_TTL = timedelta(hours=24)


def fetch_latest_version_data(package_name: str) -> dict:
    response = requests.get(
        f"{RUBYGEMS_BASE_URL}/api/v1/gems/{package_name}.json",
        headers={"User-Agent": RUBYGEMS_USER_AGENT},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def latest_version(package_name: str) -> str | None:
    try:
        data = fetch_latest_version_data(package_name)
        return data.get("version")
    except Exception:
        return None


def fetch_version_data(package_name: str, version: str) -> dict:
    response = requests.get(
        f"{RUBYGEMS_BASE_URL}/api/v2/rubygems/{package_name}/versions/{version}.json",
        headers={"User-Agent": RUBYGEMS_USER_AGENT},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def fetch_archive(gem_uri: str) -> bytes:
    response = requests.get(gem_uri, headers={"User-Agent": RUBYGEMS_USER_AGENT}, timeout=60)
    response.raise_for_status()
    return response.content


def _cache_key(package_name: str, version: str | None) -> str:
    payload = f"rubygems|{package_name}=={version or ''}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _cache_path(package_name: str, version: str | None) -> Path:
    return get_cache_root() / "provenance" / f"{_cache_key(package_name, version)}.json"


def _load_cached_result(package_name: str, version: str | None) -> dict | None:
    try:
        path = _cache_path(package_name, version)
        if not path.exists():
            return None
        payload = json.loads(path.read_text())
        if payload.get("cache_version") != RUBYGEMS_PROVENANCE_CACHE_VERSION:
            return None
        cached_at = payload.get("cached_at")
        if not cached_at:
            return None
        cached_time = datetime.fromisoformat(cached_at)
        if datetime.now(timezone.utc) - cached_time > RUBYGEMS_PROVENANCE_CACHE_TTL:
            return None
        return payload.get("result")
    except Exception:
        return None


def _store_cached_result(package_name: str, version: str | None, result: dict) -> None:
    try:
        path = _cache_path(package_name, version)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "cache_version": RUBYGEMS_PROVENANCE_CACHE_VERSION,
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
    filename = f"{package_name}-{version}.gem"

    try:
        version_data = fetch_version_data(package_name, version)
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else None
        if status == 404:
            # Genuinely ambiguous between "never existed" and "yanked and
            # purged" -- see module docstring's "Yank detection" section.
            # Not asserted as a confirmed yank.
            result = {
                "package": package_name,
                "version": version,
                "block": False,
                "reason": None,
                "warnings": warnings + [
                    f"version {version} was not found on rubygems.org for {package_name} "
                    "-- it may never have existed, or may have been yanked"
                ],
                "infos": infos,
                "signals": {
                    "checksum_verified": False,
                    "verification_unavailable": {
                        "filename": filename,
                        "error": "version not found in registry metadata (nonexistent or yanked)",
                    },
                },
            }
            _store_cached_result(package_name, version, result)
            return result
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

    yanked = bool(version_data.get("yanked"))
    if yanked:
        warnings.append("resolved version has been yanked by its publisher")

    checksum_verified = False
    verification_unavailable = None
    sha256 = version_data.get("sha")
    gem_uri = version_data.get("gem_uri")
    if sha256 and gem_uri:
        try:
            archive_bytes = fetch_archive(gem_uri)
            actual_hash = hashlib.sha256(archive_bytes).hexdigest()
            checksum_verified = actual_hash == sha256
            if not checksum_verified:
                return {
                    "package": package_name,
                    "version": version,
                    "block": True,
                    "reason": "downloaded artifact checksum does not match the registry-reported hash -- possible tampering",
                    "warnings": warnings,
                    "infos": infos,
                    "signals": {"checksum_verified": False, "yanked": yanked},
                }
            infos.append("resolved artifact has a verified SHA-256 checksum against the registry-reported hash")
        except Exception as exc:
            # A real hash MISMATCH above is a hard block ("possible
            # tampering"); this is the different, non-tampering case
            # where verification simply couldn't complete (network
            # error, ...) -- same "verification_unavailable" signal shape
            # every other ecosystem's registry.py already uses.
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
            "checksum_algorithm": "SHA256" if sha256 else None,
            "yanked": yanked,
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
