"""Runs inside the Docker sandbox container for RubyGems deep-mode
installs -- the RubyGems counterpart to sandbox_wrapper_pub.py/
sandbox_wrapper_nuget.py/sandbox_wrapper_maven.py/sandbox_wrapper_go.py/
sandbox_wrapper_cargo.py/sandbox_wrapper_npm.js.

Stage 2 (this file, fetch-only): proves the resolved package set can be
installed entirely offline against a pre-built local vendor/cache,
reproducing prepare_rubygems_download_bundle's own host-side Gemfile.lock,
but this time fully sandboxed (--network none, --read-only rootfs,
--cap-drop ALL, non-root user) -- including, unlike every other
ecosystem's own Stage 2 wrapper here, real native-extension compilation
(a resolved gem's own extconf.rb), since Bundler has no clean "fetch
only, don't build" mode the way `cargo fetch`/`go mod download`/`dotnet
restore`/`dart pub get` do (confirmed directly -- see
rubygems_sandbox.Dockerfile's module docstring). This is exactly the kind
of untrusted build-time code execution this project's sandbox isolation
exists for -- unlike prepare_rubygems_download_bundle's own host-side
code, which deliberately never invokes `bundle install` at all.

Real, confirmed-directly wrinkle mirroring sandbox_wrapper_pub.py's own:
Bundler needs to write real bookkeeping (installed gemspecs, extension
build output, its own vendor/cache updates) that a read-only bind mount
of the pre-built bundle can't accommodate -- so this wrapper copies the
mounted bundle into its own writable tmpfs work directory first, the
same "copy into a writable location before use" pattern
sandbox_wrapper_maven.py/sandbox_wrapper_pub.py already use.

`bundle install --local` proves the *exact* resolution
prepare_rubygems_download_bundle's own host-side write already produced
(and Trivy already scanned) is reproducible purely from this sandboxed
vendor/cache -- confirmed directly end-to-end under the project's full
isolation posture (--network none, --read-only rootfs, --cap-drop ALL,
non-root user), including a real native-extension gem (json) building
successfully. If a resolved gem's install genuinely fails here, that's
itself a real, worth-surfacing inconsistency between what was scanned
and what the sandbox can actually install.

Prints the same DEPSHIELDX_SANDBOX_REPORT=<json> line sandbox.py's
_extract_report() already expects, with the same minimal Stage-2 shape
(download_exit_code/suspicious) sandbox_wrapper_nuget.py's own Stage 2
version used before Stage 3 behavioral tracing replaced it -- no
strace-based evidence yet, that's this ecosystem's own future Stage 3.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPORT_PREFIX = "DEPSHIELDX_SANDBOX_REPORT="
WORK_DIR = Path("/tmp/depshieldx-rubygems-work")


def _prepare_work_env(bundle_dir: Path) -> dict:
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copytree(bundle_dir / "vendor", WORK_DIR / "vendor")
    shutil.copy2(bundle_dir / "Gemfile", WORK_DIR / "Gemfile")
    shutil.copy2(bundle_dir / "Gemfile.lock", WORK_DIR / "Gemfile.lock")

    env = dict(os.environ)
    # $HOME needs to be writable too -- SANDBOX_USER's real default HOME
    # has nothing writable in it (confirmed directly the same way every
    # other ecosystem's own wrapper here already documents for its own
    # toolchain).
    env["HOME"] = str(WORK_DIR)
    env["GEM_HOME"] = str(WORK_DIR / "gem_home")
    env["BUNDLE_PATH"] = str(WORK_DIR / "bundle_path")
    return env


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: sandbox_wrapper_rubygems.py <bundle_dir> [<gem_name@version>...]", file=sys.stderr)
        return 2

    bundle_dir = Path(sys.argv[1])
    install_targets = sys.argv[2:]

    env = _prepare_work_env(bundle_dir)

    result = subprocess.run(
        ["bundle", "install", "--local"],
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
