"""Runs inside the Docker sandbox container for Composer deep-mode
installs -- the Composer counterpart to sandbox_wrapper_nuget.py/
sandbox_wrapper_pub.py/sandbox_wrapper_rubygems.py.

This stage proves the resolved package set can be installed entirely
offline against a pre-fetched, checksum-verified local package source,
using Composer's own real "artifact" repository mechanism -- confirmed
directly (against a real Docker container matching this project's exact
isolation posture: --network none, --read-only rootfs, --cap-drop ALL,
non-root user) to work correctly end to end, including with
`"packagist.org": false` correctly suppressing the default remote
repository entirely (confirmed directly: composer's own command log goes
straight from "Loading composer repositories with package information"
to "Found package ... in file ..." against the local artifact directory,
no network repository ever consulted). No behavioral tracing here yet --
this only proves the install itself completes correctly offline. Unlike
RubyGems' `bundle install` (which triggers real native-extension
compilation as an unavoidable part of installing a gem that has one),
Composer has no comparable code-execution-during-install surface of its
own: no compiler step, no code that runs merely by being extracted onto
disk, and `--no-plugins --no-scripts` here block the two real
opt-in-only execution surfaces Composer does have (a project's own
script hooks, and a package registering itself as a Composer plugin --
already blocked by default as of Composer 2.2+, see ecosystems/composer/
ecosystem.py's module docstring). A future behavioral-tracing stage,
wrapping a build/script-hook-permitting install the way NuGet's Stage 3
wraps `dotnet build`, is where that narrower, opt-in execution surface
would be traced.

prepare_composer_download_bundle already built the flat artifacts/*.zip
directory and a scratch composer.json (pointing its own "artifact"
repository entry at "./artifacts/", a path relative to composer.json
itself) host-side, before the container ever runs -- both are copied
here into this script's own writable work directory (Composer needs to
write real bookkeeping of its own: vendor/, composer.lock, an autoload
cache, and its cache/config dir under $HOME -- confirmed directly the
read-only bundle mount and SANDBOX_USER's nonexistent default HOME can't
accommodate any of that), preserving the same relative layout so the
copied composer.json's own "./artifacts/" reference still resolves
correctly.

Prints the same DEPSHIELDX_SANDBOX_REPORT=<json> line sandbox.py's
_extract_report() already expects, with the same key shape cli/output.py's
summary formatter reads -- all empty/zero until behavioral tracing
populates them for real, mirroring sandbox_wrapper_nuget.py's own
original Stage 2 shape.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPORT_PREFIX = "DEPSHIELDX_SANDBOX_REPORT="
WORK_DIR = Path("/tmp/depshieldx-composer-work")


def _prepare_work_env(bundle_dir: Path) -> dict:
    scratch_dir = WORK_DIR / "scratch"
    scratch_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(bundle_dir / "composer.json", scratch_dir / "composer.json")
    shutil.copytree(bundle_dir / "artifacts", scratch_dir / "artifacts")

    env = dict(os.environ)
    # $HOME/.composer (Linux default) is Composer's own real cache/config
    # root -- pointing HOME at this script's own writable work directory
    # keeps that cache guaranteed-empty (proving the offline install
    # isn't silently succeeding from stale cache) and writable (confirmed
    # directly the default HOME under SANDBOX_USER has nothing writable
    # to extract packages into otherwise).
    env["HOME"] = str(WORK_DIR)
    return env


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: sandbox_wrapper_composer.py <bundle_dir> [<vendor/package@version>...]", file=sys.stderr)
        return 2

    bundle_dir = Path(sys.argv[1])
    install_targets = sys.argv[2:]

    env = _prepare_work_env(bundle_dir)

    result = subprocess.run(
        ["composer", "install", "--no-interaction", "--no-plugins", "--no-scripts"],
        cwd=str(WORK_DIR / "scratch"),
        env=env,
        capture_output=True,
        text=True,
    )
    install_exit_code = result.returncode
    suspicious = install_exit_code != 0

    report = {
        "download_exit_code": install_exit_code,
        "suspicious": suspicious,
        "vendored_targets": install_targets,
        "download_stdout_tail": result.stdout[-2000:] if suspicious else "",
        "download_stderr_tail": result.stderr[-2000:] if suspicious else "",
        "write_count": 0,
        "write_buckets": {},
        "write_samples": [],
        "syscall_counts": {"filesystem_mutation": 0, "process_exec": 0, "network": 0},
        "syscall_samples": [],
        "allowed_subprocesses": [],
        "imported_modules": [],
        "import_failures": [],
        "risky_import_failures": [],
        "environmental_import_failures": [],
        "skipped_imports": [],
        "blocked_events": [],
        "events": [],
        "verdicts": [],
    }
    print(REPORT_PREFIX + json.dumps(report))
    return 1 if suspicious else 0


if __name__ == "__main__":
    sys.exit(main())
