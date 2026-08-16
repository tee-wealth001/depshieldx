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
    """Cargo legitimately allows the same crate name at two different
    resolved versions simultaneously in one lockfile (e.g. a project
    depending on both `syn` 2.x and 3.x transitively, because different
    dependencies pin different major versions) -- confirmed directly against
    ripgrep's real Cargo.lock, which has exactly this for "syn". Unlike PyPI
    (one environment, one version) or npm's lockfile parsers (which already
    silently flatten this the same way), a plain dict[str, str] can't
    represent two versions of one name at once. When a name repeats here,
    the newest version wins -- matching what a fresh `cargo add` on that
    name would resolve to today -- and the older entry is silently dropped
    from the returned map. This is an accepted, documented limitation, not
    an oversight.

    Path/workspace-member/git-sourced dependency entries have no "checksum"
    field and often no "source" field either -- confirmed directly against
    ripgrep's own workspace-member crates (e.g. "grep", "globset"), which
    have neither. There is no crates.io tarball or checksum to fetch/verify
    for these; callers (selected_artifact_entries/fetch_artifact) must
    detect and skip them rather than assume every resolved package has a
    fetchable registry artifact.
    """
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
