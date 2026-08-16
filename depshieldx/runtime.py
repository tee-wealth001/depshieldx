"""Runtime execution policy: locate real interpreters and bundled resources
whether depshieldx is running as a normal Python install or as a
PyInstaller-frozen standalone binary.

Inside a frozen binary, sys.executable is the frozen depshieldx exe itself,
not a real Python interpreter -- `-m pip` and `-m depshieldx.cli` don't work
against it. Every host-side subprocess call that needs a real interpreter or
a bundled script file must go through here rather than trusting
sys.executable directly. See findings.md #4 for how this was discovered.
"""

import shutil
import sys
from pathlib import Path


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def system_python_executable() -> str:
    """A real Python interpreter -- sys.executable when not frozen, otherwise
    located on PATH. Never the frozen depshieldx binary itself."""
    if not is_frozen():
        return sys.executable
    for candidate in ("python3", "python"):
        found = shutil.which(candidate)
        if found:
            return found
    raise RuntimeError(
        "depshieldx is running as a standalone binary and could not find a system "
        "Python interpreter on PATH. This feature needs Python installed to run pip "
        "against the target environment."
    )


def pip_command(args: list[str]) -> list[str]:
    """The correct way to invoke pip, whether frozen or not."""
    return [system_python_executable(), "-m", "pip", *args]


def self_invoke_command(args: list[str]) -> list[str]:
    """Re-invoke depshieldx itself with the given CLI args (e.g. from the
    routing shim). A frozen binary is its own entry point and does not
    support `-m depshieldx.cli`."""
    if is_frozen():
        return [sys.executable, *args]
    return [sys.executable, "-m", "depshieldx.cli", *args]


def resource_path(relative: str) -> Path:
    """Locate a bundled resource file (e.g. sandbox_wrapper.py) whether
    running from source or as a PyInstaller-frozen binary. PyInstaller
    extracts bundled data files under sys._MEIPASS at runtime."""
    if is_frozen():
        base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    else:
        base = Path(__file__).resolve().parent
    return base / relative
