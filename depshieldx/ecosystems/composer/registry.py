"""Packagist registry client: artifact fetch, plus structural provenance
signals.

`GET https://packagist.org/packages/<vendor>/<package>.json` -- confirmed
directly this is the one real endpoint this module needs, and confirmed
directly it is NOT the "minified" differential-encoded format the
repo.packagist.org/p2/... metadata API Composer itself consults uses
(where most fields are omitted on every version entry after the first) --
every version entry here carries its own full `dist`/`source`/`version`
fields regardless of position, confirmed directly across every version of
several real, popular packages. Returns `{"package": {"name", "abandoned"?,
"versions": {"<version>": {"version", "dist": {...}, "source": {...},
...}}}}`. Package name lookups are confirmed directly case-insensitive
("Monolog/Monolog" and "monolog/monolog" both resolve to the same real
package), but the canonical form Packagist itself always returns is
lowercase, and OSV's own Packagist-ecosystem matching is confirmed
directly case-*sensitive* on that lowercase form (a real query for
"monolog/monolog" returns real results, "Monolog/Monolog" returns none) --
so, unlike Go/Maven/NuGet/Pub/RubyGems, Composer package names are folded
to lowercase here, the same "the registry's own canonical form already IS
case-folded" treatment PyPI/Cargo already get, not the "case genuinely
matters, preserve it" treatment those five have.

Checksum verification: confirmed directly (repeatedly, across several
real, popular, different packages -- monolog/monolog, symfony/console,
guzzlehttp/guzzle, laravel/framework) that `dist.shasum` is empty for
every real version checked, matching this ecosystem's own long-standing,
unresolved public issue asking for real dist checksum support
(composer/composer#5940) -- Packagist mostly points `dist` at a VCS
host's own commit-addressed zipball (a GitHub/GitLab/Bitbucket archive
URL keyed by the exact git `reference`, not a registry-computed content
hash), so there is no registry-published hash to verify a fresh download
against the way every other ecosystem's registry.py here has. The git
`reference` itself (embedded in both `dist.url` and `dist.reference`) is
the real, always-present content pin -- the closest analogue to a
checksum this ecosystem has, analogous to how git-sourced dependencies
are already handled in the npm/Cargo adapters here, not analogous to a
registry-checksum path. When `dist.shasum` *is* non-empty (confirmed
directly this is a real, if uncommon, possibility -- Packagist's own
schema documents it as a SHA-1 hash, not SHA-256), it is verified for
real; when it's empty (the common case), that's surfaced as an honest
"no checksum published" signal, the same non-blocking treatment NuGet's/
Pub's own registry.py already use for their own missing-checksum cases,
never invented or skipped silently.

Provenance signals, and why there's no cryptographic signing story here:
no evidence of a Sigstore/PGP/X.509/TUF package-signing scheme for
Packagist turned up anywhere in this module's research (checked both
Composer's own official documentation and Packagist's own "about" page
directly) -- Packagist trusts HTTPS plus whatever the underlying VCS
host provides, not an independent signature, so (mirroring Pub's own
reasoning) this module's integrity story rests on the git-reference pin
alone. Structural signal instead: Packagist's own `abandoned` field on
the package (confirmed directly against a real abandoned package,
swiftmailer/swiftmailer, which reports `"abandoned": "symfony/mailer"`
-- a string naming the recommended replacement, not just a boolean) --
Composer's real, package-level analogue to npm deprecate/PyPI yank/
Cargo yank/Go retract/Pub discontinued.
"""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from ...storage.cache import get_cache_root

PACKAGIST_BASE_URL = "https://packagist.org"
PACKAGIST_USER_AGENT = "depshieldx (https://github.com/tee-wealth001/depshieldx)"
COMPOSER_PROVENANCE_CACHE_VERSION = 1
COMPOSER_PROVENANCE_CACHE_TTL = timedelta(hours=24)


def fetch_package_data(package_name: str) -> dict:
    response = requests.get(
        f"{PACKAGIST_BASE_URL}/packages/{package_name}.json",
        headers={"User-Agent": PACKAGIST_USER_AGENT},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def find_version_info(package_data: dict, version: str) -> dict | None:
    versions = (package_data.get("package") or {}).get("versions") or {}
    return versions.get(version)


def fetch_archive(dist_url: str) -> bytes:
    response = requests.get(dist_url, headers={"User-Agent": PACKAGIST_USER_AGENT}, timeout=60)
    response.raise_for_status()
    return response.content


def _cache_key(package_name: str, version: str | None) -> str:
    payload = f"composer|{package_name}=={version or ''}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _cache_path(package_name: str, version: str | None) -> Path:
    return get_cache_root() / "provenance" / f"{_cache_key(package_name, version)}.json"


def _load_cached_result(package_name: str, version: str | None) -> dict | None:
    try:
        path = _cache_path(package_name, version)
        if not path.exists():
            return None
        payload = json.loads(path.read_text())
        if payload.get("cache_version") != COMPOSER_PROVENANCE_CACHE_VERSION:
            return None
        cached_at = payload.get("cached_at")
        if not cached_at:
            return None
        cached_time = datetime.fromisoformat(cached_at)
        if datetime.now(timezone.utc) - cached_time > COMPOSER_PROVENANCE_CACHE_TTL:
            return None
        return payload.get("result")
    except Exception:
        return None


def _store_cached_result(package_name: str, version: str | None, result: dict) -> None:
    try:
        path = _cache_path(package_name, version)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "cache_version": COMPOSER_PROVENANCE_CACHE_VERSION,
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

    abandoned = (package_data.get("package") or {}).get("abandoned")
    if abandoned:
        suffix = f" -- suggested replacement: {abandoned}" if isinstance(abandoned, str) else ""
        warnings.append(f"package is abandoned{suffix}")

    version_info = find_version_info(package_data, version)
    filename = f"{package_name.replace('/', '-')}-{version}.zip"
    if version_info is None:
        # A legitimately composer-resolved version should always be in
        # Packagist's own versions list -- this is a real anomaly, but
        # not tampering by itself, so it's treated the same non-blocking
        # way as an unreachable/missing checksum below, not a hard block
        # -- the same "anomaly, not a confirmed cause" honesty Pub's own
        # "version not found in registry metadata" case already uses.
        result = {
            "package": package_name,
            "version": version,
            "block": False,
            "reason": None,
            "warnings": warnings + [f"version {version} was not found in Packagist's published version list for {package_name}"],
            "infos": infos,
            "signals": {
                "checksum_verified": False,
                "abandoned": bool(abandoned),
                "abandoned_replacement": abandoned if isinstance(abandoned, str) else None,
                "verification_unavailable": {"filename": filename, "error": "resolved version not found in registry metadata"},
            },
        }
        _store_cached_result(package_name, version, result)
        return result

    checksum_verified = False
    verification_unavailable = None
    dist = version_info.get("dist") or {}
    shasum = (dist.get("shasum") or "").strip()
    dist_url = dist.get("url")
    reference = dist.get("reference") or (version_info.get("source") or {}).get("reference")
    if shasum and dist_url:
        try:
            archive_bytes = fetch_archive(dist_url)
            actual_hash = hashlib.sha1(archive_bytes).hexdigest()
            checksum_verified = actual_hash == shasum
            if not checksum_verified:
                return {
                    "package": package_name,
                    "version": version,
                    "block": True,
                    "reason": "downloaded artifact checksum does not match the registry-reported hash -- possible tampering",
                    "warnings": warnings,
                    "infos": infos,
                    "signals": {"checksum_verified": False, "abandoned": bool(abandoned), "reference": reference},
                }
            infos.append("resolved artifact has a verified SHA-1 checksum against the registry-reported hash")
        except Exception as exc:
            infos.append(f"could not verify artifact checksum: {exc}")
            verification_unavailable = {"filename": filename, "error": str(exc)}
    else:
        # The common case, confirmed directly across several real,
        # popular packages -- Packagist's own dist.shasum is empty for
        # VCS-hosted (GitHub/GitLab/Bitbucket) zipballs, which is most of
        # Packagist. Not an error, just this ecosystem's real, weaker
        # integrity story -- see module docstring.
        infos.append("no checksum published for the resolved artifact -- pinned by git reference only")
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
            "checksum_algorithm": "SHA1" if shasum else None,
            "abandoned": bool(abandoned),
            "abandoned_replacement": abandoned if isinstance(abandoned, str) else None,
            "reference": reference,
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
