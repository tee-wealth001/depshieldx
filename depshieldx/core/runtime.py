"""Runtime execution policy: locate real interpreters and bundled resources
whether depshieldx is running as a normal Python install or as a
PyInstaller-frozen standalone binary.

Inside a frozen binary, sys.executable is the frozen depshieldx exe itself,
not a real Python interpreter -- `-m pip` and `-m depshieldx.cli` don't work
against it. Every host-side subprocess call that needs a real interpreter or
a bundled script file must go through here rather than trusting
sys.executable directly. See findings.md #4 for how this was discovered.

subprocess_env() below was written to fix a real Windows packaging bug: a
real external toolchain subprocess (confirmed with composer -> php.exe)
resolving depshieldx's own bundled vcruntime140.dll instead of a
compatible system one, and failing outright on the version mismatch. The
original theory -- that PyInstaller's onefile bootloader prepends
sys._MEIPASS to the process's own PATH environment variable, inherited
unchanged by subprocess.run()'s default os.environ inheritance -- turned
out to be wrong, confirmed directly two ways: a real frozen process's own
os.environ['PATH'] never contains _MEIPASS at all, and handing
subprocess.run() a completely empty PATH does not fix the bug either. The
real mechanism (see packaging/rthook_reset_dll_directory.py's own
docstring for the full investigation) is a process-wide DLL search
directory the bootloader sets via the Win32 SetDllDirectory API, which is
not PATH-based and is not something a subprocess call's own env=
argument can affect at all -- the actual fix is that runtime hook calling
SetDllDirectoryW(None) once, early, before any of depshieldx's own code
runs.

subprocess_env() itself is kept below as harmless, no-op-in-practice
defense in depth for any other, genuinely PATH-based leak (confirmed
directly it strips nothing in the one real case investigated, since
_MEIPASS was never on PATH to begin with) -- every subprocess call to an
external toolchain (composer, npm, cargo, go, mvn, dotnet, dart, bundle,
docker, trivy, pip, ...) still passes it explicitly for that reason, not
because it's confirmed to matter.
"""

import os
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


def subprocess_env() -> dict:
    """Environment dict for subprocess calls to *external* toolchains --
    see this module's own docstring for why this exists and why it's a
    copy, not a mutation of os.environ itself. A no-op (returns
    os.environ unchanged, as a plain dict) when not frozen, since
    sys._MEIPASS doesn't exist there at all."""
    env = dict(os.environ)
    if not is_frozen():
        return env
    meipass = getattr(sys, "_MEIPASS", None)
    if not meipass:
        return env
    normalized_meipass = os.path.normcase(os.path.normpath(meipass))
    path_entries = env.get("PATH", "").split(os.pathsep)
    filtered_entries = [
        entry for entry in path_entries if os.path.normcase(os.path.normpath(entry)) != normalized_meipass
    ]
    env["PATH"] = os.pathsep.join(filtered_entries)
    return env


def resource_path(relative: str) -> Path:
    """Locate a bundled resource file (e.g. sandbox_wrapper.py) whether
    running from source or as a PyInstaller-frozen binary. PyInstaller
    extracts bundled data files under sys._MEIPASS at runtime."""
    if is_frozen():
        base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    else:
        # runtime.py lives under depshieldx/core, while bundled resources
        # remain rooted at the package directory for source and PyInstaller
        # execution alike.
        base = Path(__file__).resolve().parent.parent
    return base / relative
