"""Parsers for npm/yarn/pnpm lockfiles, producing a normalized {name: version} map.

Formats grounded against real lockfiles generated with npm 11 / yarn 1.22 / pnpm 9
during development (not guessed from memory) -- see final-plan.md Phase 1.
"""

import json
from pathlib import Path

import yaml


def parse_package_lock_json(path) -> dict[str, str]:
    """npm's own lockfile. Supports lockfileVersion 2/3 (the "packages" map);
    lockfileVersion 1 (npm 5/6, nested "dependencies" tree only, no "packages"
    key) is not supported in this pass -- npm has defaulted to v2/v3 since
    npm 7 (2021)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    packages = data.get("packages")
    if packages is None:
        raise ValueError(
            'package-lock.json has no "packages" key -- looks like lockfileVersion 1 '
            "(npm 5/6), which isn't supported yet. Regenerate with a current npm to get "
            "lockfileVersion 2 or 3."
        )

    resolved: dict[str, str] = {}
    for package_path, meta in packages.items():
        if package_path == "":
            continue  # the root project itself, not a dependency
        name = package_path.rsplit("node_modules/", 1)[-1]
        version = (meta or {}).get("version")
        if name and version:
            resolved[name] = version
    return resolved


def parse_yarn_lock(path) -> dict[str, str]:
    """Yarn classic (v1) lockfile format -- not YAML despite convention, a
    custom indentation-based format. Yarn Berry (v2+) uses a different, real
    YAML format and is not handled by this parser."""
    text = Path(path).read_text(encoding="utf-8")
    resolved: dict[str, str] = {}
    current_names: list[str] = []

    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        if not line[0].isspace():
            # A new block header, e.g.: `chalk@^6.0.0:` or multiple comma-separated
            # specs sharing one resolved version:
            # `"@babel/helper-validator-identifier@^8.0.0", "@babel/helper-validator-identifier@^8.0.4":`
            header = line.rstrip().rstrip(":")
            current_names = [
                name for name in (_yarn_spec_to_name(spec) for spec in _split_yarn_specs(header)) if name
            ]
            continue
        stripped = line.strip()
        if stripped.startswith("version "):
            version = stripped.split(" ", 1)[1].strip().strip('"')
            for name in current_names:
                resolved[name] = version
    return resolved


def _split_yarn_specs(header: str) -> list[str]:
    return [part.strip().strip('"') for part in header.split(",") if part.strip()]


def _yarn_spec_to_name(spec: str) -> str | None:
    # Scoped packages ("@scope/name@range") have a leading "@" that must be skipped
    # when searching for the name/range separator "@".
    search_from = 1 if spec.startswith("@") else 0
    at_index = spec.find("@", search_from)
    if at_index == -1:
        return None
    return spec[:at_index]


def parse_pnpm_lock_yaml(path) -> dict[str, str]:
    """pnpm-lock.yaml (lockfileVersion 9, pnpm 9+). Older pnpm lockfile
    versions may use a different "packages" key shape and aren't handled by
    this parser."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    packages = data.get("packages") or {}

    resolved: dict[str, str] = {}
    for key in packages:
        name, version = _pnpm_key_to_name_version(key)
        if name and version:
            resolved[name] = version
    return resolved


def _pnpm_key_to_name_version(key: str) -> tuple[str | None, str | None]:
    # Keys look like "left-pad@1.3.0" or "@babel/core@8.0.1"; pnpm appends
    # peer-dependency resolution info after "(" for some packages, e.g.
    # "pkg@1.0.0(peer@2.0.0)" -- strip that before splitting name/version.
    key = key.split("(", 1)[0]
    at_index = key.rfind("@")
    if at_index < 1:
        return None, None
    return key[:at_index], key[at_index + 1 :]


LOCKFILE_PARSERS = {
    "package-lock.json": parse_package_lock_json,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock_yaml,
}


def parse_lockfile(path) -> dict[str, str]:
    filename = Path(path).name
    parser = LOCKFILE_PARSERS.get(filename)
    if parser is None:
        raise ValueError(f"unsupported npm lockfile: {filename}")
    return parser(path)
