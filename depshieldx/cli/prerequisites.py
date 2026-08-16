"""Runtime prerequisite checks -- blocks early if the local Python/pip are too old."""

import sys
from importlib import metadata

from packaging.version import InvalidVersion, Version

from .output import _echo_error, _finish

MIN_SECURE_PYTHON = (3, 11, 4)
MIN_SECURE_PYTHON_LABEL = "3.11.4"
MIN_SECURE_PIP_VERSION = Version("25.3")
MIN_SECURE_PIP_LABEL = "25.3"


def _runtime_environment_report():
    python_version = ".".join(str(part) for part in sys.version_info[:3])
    python_ok = sys.version_info >= MIN_SECURE_PYTHON
    python_requirement = f"Python>={MIN_SECURE_PYTHON_LABEL}"

    pip_version = None
    pip_ok = False
    pip_error = None
    try:
        pip_version = metadata.version("pip")
        pip_ok = Version(pip_version) >= MIN_SECURE_PIP_VERSION
    except metadata.PackageNotFoundError:
        pip_error = "pip is not installed in this interpreter environment"
    except InvalidVersion:
        pip_error = f"pip has an unrecognized version string: {pip_version!r}"

    issues = []
    if not python_ok:
        issues.append(f"requires {python_requirement} (running {python_version})")
    if pip_error:
        issues.append(pip_error)
    elif not pip_ok:
        issues.append(
            f"requires pip>={MIN_SECURE_PIP_LABEL} because depshieldx shells out to the local pip (running {pip_version})"
        )

    return {
        "block": bool(issues),
        "reason": "; ".join(issues) if issues else None,
        "python": {
            "version": python_version,
            "required": python_requirement,
            "ok": python_ok,
        },
        "pip": {
            "version": pip_version,
            "required": f"pip>={MIN_SECURE_PIP_LABEL}",
            "ok": pip_ok,
            "error": pip_error,
        },
    }


def _enforce_runtime_prerequisites(report, output_mode):
    environment = _runtime_environment_report()
    report["environment"] = environment
    if not environment.get("block"):
        return
    _echo_error(f"Runtime prerequisite failed: {environment['reason']}")
    report["install"] = {
        "attempted": False,
        "success": False,
        "blocked": True,
        "reason": "environment",
    }
    _finish(report, output_mode)
