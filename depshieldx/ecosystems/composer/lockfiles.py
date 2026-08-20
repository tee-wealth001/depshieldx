"""Parses `composer.lock` -- real JSON (confirmed directly: a real
`composer require`-produced lockfile parses cleanly with the standard
library's `json` module, no custom parser needed, unlike Bundler's
Gemfile.lock or Cargo.lock's own TOML-like format), shaped like:

```json
{
    "content-hash": "...",
    "packages": [
        {
            "name": "monolog/monolog",
            "version": "3.10.0",
            "source": {"type": "git", "url": "...", "reference": "b321dd..."},
            "dist": {"type": "zip", "url": "...", "reference": "b321dd...", "shasum": ""}
        }
    ],
    "packages-dev": [...]
}
```

Confirmed directly the top-level `content-hash` field is a hash of the
*requirements in composer.json* (used to detect a stale lockfile), not a
per-artifact integrity hash -- a genuinely different purpose from Cargo.
lock's/packages.lock.json's own checksums, not read by this module at
all. `packages`/`packages-dev` are flat lists (production vs. `require-
dev` dependencies), not a dict keyed by name -- and confirmed directly
neither one marks its own entries as direct vs. transitive the way
NuGet's packages.lock.json "type": "Direct" field or Gemfile.lock's
"DEPENDENCIES" section do; composer.lock alone can't tell direct from
transitive, the same "need the sibling manifest" case Cargo.lock/go.sum
already are in this codebase (see ecosystem.py's own
direct_dependency_names_for_lockfile, which reads the sibling
composer.json directly, mirroring CargoEcosystem's own).
"""

import json


def parse_composer_lock(lockfile_path: str) -> dict[str, str]:
    with open(lockfile_path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    resolved_versions: dict[str, str] = {}
    for section in ("packages", "packages-dev"):
        for entry in payload.get(section) or []:
            name = entry.get("name")
            version = entry.get("version")
            if name and version:
                resolved_versions[name] = version
    return resolved_versions
