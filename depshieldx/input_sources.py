from dataclasses import dataclass
from pathlib import Path
import tomllib


@dataclass
class InputSource:
    source_type: str
    label: str
    requested_targets: list[str]
    pip_args: list[str]


def _parse_requirements_file(path: str) -> list[str]:
    requirements = []
    for raw_line in Path(path).read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        requirements.append(line)
    return requirements


def _parse_uv_lock(path: str) -> list[str]:
    payload = tomllib.loads(Path(path).read_text())
    packages = []
    for item in payload.get("package", []):
        name = item.get("name")
        version = item.get("version")
        if name and version:
            packages.append(f"{name}=={version}")
    return packages


def _parse_pyproject(path: str) -> list[str]:
    payload = tomllib.loads(Path(path).read_text())
    project = payload.get("project") or {}
    dependencies = project.get("dependencies")
    if isinstance(dependencies, list) and dependencies:
        return [item.strip() for item in dependencies if isinstance(item, str) and item.strip()]

    poetry_dependencies = (((payload.get("tool") or {}).get("poetry") or {}).get("dependencies") or {})
    packages = []
    for name, value in poetry_dependencies.items():
        if name == "python":
            continue
        if isinstance(value, str):
            normalized = value.strip()
            if not normalized or normalized == "*":
                packages.append(name)
            else:
                packages.append(f"{name}{normalized}")
    return packages


def load_input_source(
    targets: tuple[str, ...],
    requirement_file: str | None = None,
    lockfile: str | None = None,
    pyproject_file: str | None = None,
) -> InputSource:
    if sum(bool(item) for item in [requirement_file, lockfile, pyproject_file]) > 1:
        raise ValueError("Use only one of requirement_file, lockfile, or pyproject_file")

    normalized_targets = [target.strip() for target in targets if target.strip()]
    if requirement_file:
        requested_targets = _parse_requirements_file(requirement_file)
        return InputSource(
            source_type="requirements",
            label=Path(requirement_file).name,
            requested_targets=requested_targets,
            pip_args=["-r", requirement_file],
        )
    if lockfile:
        if Path(lockfile).name == "uv.lock":
            requested_targets = _parse_uv_lock(lockfile)
        else:
            requested_targets = _parse_requirements_file(lockfile)
        return InputSource(
            source_type="lockfile",
            label=Path(lockfile).name,
            requested_targets=requested_targets,
            pip_args=requested_targets[:],
        )
    if pyproject_file:
        requested_targets = _parse_pyproject(pyproject_file)
        return InputSource(
            source_type="pyproject",
            label=Path(pyproject_file).name,
            requested_targets=requested_targets,
            pip_args=requested_targets[:],
        )
    if not normalized_targets:
        raise ValueError("Provide at least one package, a requirement file, a lockfile, or a pyproject file")
    if len(normalized_targets) == 1:
        return InputSource(
            source_type="package",
            label=normalized_targets[0],
            requested_targets=normalized_targets,
            pip_args=normalized_targets,
        )
    return InputSource(
        source_type="packages",
        label=", ".join(normalized_targets),
        requested_targets=normalized_targets,
        pip_args=normalized_targets[:],
    )
