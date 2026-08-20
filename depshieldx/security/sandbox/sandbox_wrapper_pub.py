"""Runs inside the Docker sandbox container for Pub deep-mode installs --
the Pub counterpart to sandbox_wrapper_nuget.py/sandbox_wrapper_maven.py/
sandbox_wrapper_go.py/sandbox_wrapper_cargo.py/sandbox_wrapper_npm.js.

Stage 2 (this file, fetch-only): proves the resolved package set can be
resolved entirely offline against a pre-built local $PUB_CACHE,
reproducing prepare_pub_download_bundle's own host-side `dart pub get
--offline` run, but this time fully sandboxed (--network none,
--read-only rootfs, --cap-drop ALL, non-root user).

One real wrinkle, confirmed directly and documented in both
pub_sandbox.Dockerfile and runner.py's own container-mount comment for
Pub: `dart pub get` writes its own bookkeeping (an "active_roots"
directory) into $PUB_CACHE itself, even in --offline mode -- a real,
reproduced-directly "Read-only file system" error results from pointing
$PUB_CACHE straight at the read-only bundle mount the way NuGet's local-
folder NuGet.Config can be read directly. So this wrapper copies the
mounted, pre-built pub-cache into its own writable tmpfs work directory
first, the same "copy into a writable location before use" pattern
sandbox_wrapper_maven.py already uses for its own merged local
repository.

--enforce-lockfile (rather than a bare `dart pub get --offline`) proves
the *exact* resolution prepare_pub_download_bundle's own host-side run
already produced (and Trivy already scanned) is reproducible purely from
this sandboxed cache -- if it weren't, that would itself be a real,
worth-surfacing inconsistency between what was scanned and what the
sandbox can actually resolve.

Prints the same DEPSHIELDX_SANDBOX_REPORT=<json> line sandbox.py's
_extract_report() already expects, with the same minimal Stage-2 shape
(download_exit_code/suspicious) sandbox_wrapper_nuget.py's own Stage 2
version used before Stage 3 behavioral tracing replaced it -- no
strace-based evidence yet, that's this ecosystem's own future Stage 3.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

REPORT_PREFIX = "DEPSHIELDX_SANDBOX_REPORT="
WORK_DIR = Path("/tmp/depshieldx-pub-work")


def _prepare_work_env(bundle_dir: Path) -> dict:
    import os

    work_pub_cache = WORK_DIR / "pub-cache"
    work_pub_cache.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(bundle_dir / "pub-cache", work_pub_cache)

    shutil.copy2(bundle_dir / "pubspec.yaml", WORK_DIR / "pubspec.yaml")
    shutil.copy2(bundle_dir / "pubspec.lock", WORK_DIR / "pubspec.lock")

    env = dict(os.environ)
    env["PUB_CACHE"] = str(work_pub_cache)
    # $HOME needs to be writable too -- SANDBOX_USER's real default HOME
    # has nothing writable in it (confirmed directly the same way every
    # other ecosystem's own wrapper here already documents for its own
    # toolchain).
    env["HOME"] = str(WORK_DIR)
    return env


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: sandbox_wrapper_pub.py <bundle_dir> [<package_name@version>...]", file=sys.stderr)
        return 2

    bundle_dir = Path(sys.argv[1])
    install_targets = sys.argv[2:]

    env = _prepare_work_env(bundle_dir)

    result = subprocess.run(
        ["dart", "pub", "get", "--offline", "--enforce-lockfile"],
        cwd=str(WORK_DIR),
        env=env,
        capture_output=True,
        text=True,
    )
    exit_code = result.returncode
    suspicious = exit_code != 0

    report = {
        "download_exit_code": exit_code,
        "suspicious": suspicious,
        "vendored_targets": install_targets,
        "build_stdout_tail": result.stdout[-2000:] if suspicious else "",
        "build_stderr_tail": result.stderr[-2000:] if suspicious else "",
    }
    print(REPORT_PREFIX + json.dumps(report))
    return 1 if suspicious else 0


if __name__ == "__main__":
    sys.exit(main())
