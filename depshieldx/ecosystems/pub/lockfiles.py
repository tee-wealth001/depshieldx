"""Parses `pubspec.lock` -- real YAML (confirmed directly: PyYAML parses
it with no special-casing needed, unlike Cargo.lock's own TOML-like
custom parser or NuGet's JSON), shaped like:

```yaml
packages:
  http:
    dependency: "direct main"
    description:
      name: http
      sha256: "87721a4a50b19c7f1d49001e51409bddc46303966ce89a65af4f4e6004896412"
      url: "https://pub.dev"
    source: hosted
    version: "1.6.0"
sdks:
  dart: ">=3.13.1 <4.0.0"
```

`description.sha256` is a real, per-package SHA-256 hex digest -- confirmed
directly this is the exact same value pub.dev's own `/api/packages/<name>`
response reports as `archive_sha256` for that version (registry.py's
module docstring), not a lockfile-internal value the way NuGet's
`contentHash` differs from the registry's `packageHash`.

`source: hosted` is the only entry shape this module resolves against the
real registry -- `source: git`/`source: path`/`source: sdk` entries
(confirmed directly these are real, valid pubspec.lock source kinds, the
same "not every entry is registry-fetchable" case Cargo's/npm's git-
sourced dependencies already are) have no registry checksum to verify
against and are skipped, mirroring how those other ecosystems already
treat non-registry-sourced dependencies as out of scope for checksum
verification rather than guessing at one.

`dependency` distinguishes "direct main"/"direct dev" (declared in the
project's own pubspec.yaml) from "transitive" -- confirmed directly this
is pub's real equivalent of NuGet's packages.lock.json "type": "Direct"
field, used the same way by direct_dependency_names_for_lockfile().
"""

import yaml


def parse_pubspec_lock(lockfile_path: str) -> dict[str, str]:
    with open(lockfile_path, "r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}

    resolved_versions: dict[str, str] = {}
    for name, entry in (payload.get("packages") or {}).items():
        if not isinstance(entry, dict) or entry.get("source") != "hosted":
            continue
        version = entry.get("version")
        if version:
            resolved_versions[name] = str(version)
    return resolved_versions


def direct_dependency_names(lockfile_path: str) -> list[str]:
    """Names a user would expect `depshieldx uninstall --lockfile
    pubspec.lock ...` to remove: packages recorded as "direct main" or
    "direct dev", not every transitively-resolved package the lockfile
    also lists -- mirrors NuGetEcosystem.direct_dependency_names_for_lockfile
    exactly, using pub's own analogous field."""
    with open(lockfile_path, "r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}

    names = []
    for name, entry in (payload.get("packages") or {}).items():
        if isinstance(entry, dict) and str(entry.get("dependency", "")).startswith("direct"):
            names.append(name)
    return names
