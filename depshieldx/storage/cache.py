import json
import os
import shutil
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

CACHE_SCHEMA_VERSION = 3

# Mirrors the 24h logical TTL every ecosystem's own provenance registry.py
# already enforces at read time (security/provenance.py's
# PROVENANCE_CACHE_TTL and each ecosystems/*/registry.py's own
# {ECOSYSTEM}_PROVENANCE_CACHE_TTL, all identically timedelta(hours=24)) --
# a stale provenance entry is already ignored/re-fetched past this point,
# so physically removing it at the same threshold doesn't change behavior,
# only reclaims disk space sooner than the entry would otherwise just sit
# unused forever.
PROVENANCE_CACHE_PRUNE_TTL = timedelta(hours=24)

# Deep-scan bundle cache entries have no existing lifecycle policy to
# mirror (unlike provenance) -- this is a new, deliberately generous
# default given a bundle entry is expensive to regenerate (a full Docker
# sandbox + Trivy run, not a single API call).
BUNDLE_CACHE_DEFAULT_MAX_AGE_DAYS = 30

_NON_BUNDLE_CACHE_ROOT_ENTRIES = {"receipts", "provenance", "keys", "routing"}


@dataclass
class CacheEntry:
    fingerprint: str
    path: str
    metadata: dict


def get_cache_root() -> Path:
    override = os.environ.get("DEPSHIELDX_CACHE_DIR")
    if override:
        return Path(override)
    return Path.home() / ".depshieldx-cache"


def fingerprint_artifacts(artifact_hashes: dict[str, str]) -> str:
    payload = json.dumps(
        {
            "schema_version": CACHE_SCHEMA_VERSION,
            "artifact_hashes": artifact_hashes,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(payload.encode("utf-8")).hexdigest()


def _entry_dir(fingerprint: str) -> Path:
    return get_cache_root() / fingerprint


def load_cache_entry(fingerprint: str) -> CacheEntry | None:
    entry_dir = _entry_dir(fingerprint)
    metadata_path = entry_dir / "metadata.json"
    lock_path = entry_dir / "depshieldx-lock.txt"
    if not metadata_path.exists() or not lock_path.exists():
        return None

    metadata = json.loads(metadata_path.read_text())
    if metadata.get("cache_schema_version") != CACHE_SCHEMA_VERSION:
        return None
    for artifact_name in metadata.get("downloaded_files", []):
        if not (entry_dir / artifact_name).exists():
            return None
    return CacheEntry(fingerprint=fingerprint, path=str(entry_dir), metadata=metadata)


def store_cache_entry(bundle, result_payload: dict) -> CacheEntry:
    fingerprint = bundle.fingerprint
    entry_dir = _entry_dir(fingerprint)
    entry_dir.mkdir(parents=True, exist_ok=True)

    for artifact_name in bundle.downloaded_files:
        shutil.copy2(Path(bundle.temp_dir) / artifact_name, entry_dir / artifact_name)
    shutil.copy2(bundle.requirements_path, entry_dir / "depshieldx-lock.txt")

    metadata = {
        "cache_schema_version": CACHE_SCHEMA_VERSION,
        "cached_at": datetime.now(timezone.utc).isoformat(),
        "downloaded_files": bundle.downloaded_files,
        "artifact_hashes": bundle.artifact_hashes,
        "static_analysis": bundle.static_analysis,
        **result_payload,
    }
    (entry_dir / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    return CacheEntry(fingerprint=fingerprint, path=str(entry_dir), metadata=metadata)


def _is_older_than(cached_at: str | None, max_age: timedelta) -> bool:
    if not cached_at:
        return False
    try:
        cached_time = datetime.fromisoformat(cached_at)
    except ValueError:
        return False
    return datetime.now(timezone.utc) - cached_time > max_age


def prune_bundle_cache(max_age: timedelta = timedelta(days=BUNDLE_CACHE_DEFAULT_MAX_AGE_DAYS)) -> list[str]:
    """Removes deep-scan bundle cache entries (whole fingerprint
    directories, same shape store_cache_entry writes) older than max_age.
    Mirrors load_cache_entry's own validation (a real metadata.json with a
    parseable cached_at) rather than removing anything that merely looks
    like a stale directory -- an entry missing/malformed metadata is left
    alone here (load_cache_entry already treats it as a cache miss, so
    it's inert, not actively harmful to leave behind)."""
    cache_root = get_cache_root()
    if not cache_root.exists():
        return []

    removed = []
    for entry_dir in sorted(cache_root.iterdir()):
        if not entry_dir.is_dir() or entry_dir.name in _NON_BUNDLE_CACHE_ROOT_ENTRIES:
            continue
        metadata_path = entry_dir / "metadata.json"
        if not metadata_path.exists():
            continue
        try:
            metadata = json.loads(metadata_path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if not _is_older_than(metadata.get("cached_at"), max_age):
            continue
        shutil.rmtree(entry_dir, ignore_errors=True)
        removed.append(entry_dir.name)
    return removed


def prune_provenance_cache(max_age: timedelta = PROVENANCE_CACHE_PRUNE_TTL) -> list[str]:
    """Removes provenance cache files (get_cache_root()/provenance/*.json,
    the same files security/provenance.py's/each ecosystem's own
    registry.py's own _load_cached_result already treats as stale past
    this same TTL at read time) older than max_age -- reclaims the disk
    space an already-ignored entry would otherwise occupy forever."""
    provenance_root = get_cache_root() / "provenance"
    if not provenance_root.exists():
        return []

    removed = []
    for path in sorted(provenance_root.glob("*.json")):
        try:
            payload = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if not _is_older_than(payload.get("cached_at"), max_age):
            continue
        try:
            path.unlink()
            removed.append(path.stem)
        except OSError:
            continue
    return removed
