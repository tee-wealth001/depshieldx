"""Parser for Cargo.lock, producing a normalized {name: version} map.

Format grounded against a real Cargo.lock (ripgrep's, lockfile version 4,
fetched from https://github.com/BurntSushi/ripgrep during development) rather
than guessed from memory: repeated `[[package]]` tables with `name`,
`version`, `source`, `checksum`, `dependencies` keys -- close enough to
input_sources.py's existing `_parse_uv_lock`'s `[[package]]` shape that
tomllib (stdlib) is directly sufficient, no new TOML dependency needed.
"""

import tomllib
from pathlib import Path

import semver


def parse_cargo_lock(path) -> dict[str, str]:
    """Parse Cargo.lock and retain the newest version per crate name."""
    payload = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    resolved: dict[str, str] = {}
    for entry in payload.get("package", []):
        name = entry.get("name")
        version = entry.get("version")
        if not name or not version:
            continue
        existing = resolved.get(name)
        if existing is None or _is_newer(version, existing):
            resolved[name] = version
    return resolved


def _is_newer(candidate: str, existing: str) -> bool:
    try:
        return semver.Version.parse(candidate) > semver.Version.parse(existing)
    except ValueError:
        # A malformed/non-standard version string shouldn't crash lockfile
        # parsing -- fall back to keeping whichever was seen first.
        return False
