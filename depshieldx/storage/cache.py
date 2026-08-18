import json
import os
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

CACHE_SCHEMA_VERSION = 3


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
