"""Parses NuGet's real opt-in lockfile, packages.lock.json (enabled via
`<RestorePackagesWithLockFile>true</...>` in the .csproj, or `dotnet
restore --use-lock-file`).

Format confirmed directly against real, freshly-generated lockfiles:

```json
{
  "version": 1,
  "dependencies": {
    "net9.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.3, 13.0.3]",
        "resolved": "13.0.3",
        "contentHash": "HrC5BXdl00IP9zeV+0Z848QWPAoCr9P3bDEZguI+gkLcBKAOxix/tLEAAHC+UvDNPv4a2d18lOReHMOagPa+zQ=="
      }
    }
  }
}
```

A multi-targeted project (multiple `<TargetFrameworks>`) produces one
top-level key per framework under "dependencies" -- confirmed directly
against a real net8.0;net9.0 multi-target restore, each with its own
independently-resolved package set (a real project's resolved versions
CAN differ across frameworks, since some packages ship framework-
conditional dependencies). Mirrors CargoEcosystem's own precedent for an
analogous "same package pinned at two different versions" case: when a
package resolves to different versions across framework sections here,
the newest one is kept and the rest are silently dropped, not merged or
errored on.

"contentHash" is deliberately not read/verified here -- confirmed
directly this is NOT the same value nuget_registry.py's checksum
verification uses (a real package's contentHash and its registry-
reported packageHash are different values, computed by different,
signature-aware-vs-not algorithms) -- see nuget/registry.py's module
docstring for why verifying against the registry's own reported hash,
not this lockfile-internal one, is the correct check.
"""

import json
from pathlib import Path


def parse_packages_lock(lockfile_path: str) -> dict[str, str]:
    payload = json.loads(Path(lockfile_path).read_text(encoding="utf-8"))
    dependencies_by_framework = payload.get("dependencies") or {}

    resolved_versions: dict[str, str] = {}
    for framework_entries in dependencies_by_framework.values():
        for package_id, entry in framework_entries.items():
            version = entry.get("resolved")
            if not version:
                continue
            existing = resolved_versions.get(package_id)
            if existing is None or _is_newer(version, existing):
                resolved_versions[package_id] = version
    return resolved_versions


def _is_newer(candidate: str, existing: str) -> bool:
    try:
        import semver

        return semver.Version.parse(_normalize(candidate)) > semver.Version.parse(_normalize(existing))
    except Exception:
        # Unparseable as strict semver (NuGet versions aren't always
        # SemVer 2.0.0-strict, e.g. real 4-segment versions like
        # "1.0.0.1") -- fall back to a plain string comparison rather
        # than crashing lockfile parsing over a version-format edge case.
        return candidate > existing


def _normalize(version: str) -> str:
    # NuGet versions may have 4 numeric segments (e.g. "1.0.0.1"), which
    # strict SemVer 2.0.0 rejects -- confirmed directly real packages use
    # this. Folding a 4th segment into build metadata keeps the first
    # three (the part that matters for ordering in practice) comparable.
    parts = version.split(".")
    if len(parts) > 3:
        return ".".join(parts[:3]) + "+" + ".".join(parts[3:])
    return version
