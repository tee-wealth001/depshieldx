"""Runs inside the Docker sandbox container for Maven deep-mode installs --
the Maven counterpart to sandbox_wrapper.py/sandbox_wrapper_npm.js/
sandbox_wrapper_cargo.py/sandbox_wrapper_go.py.

This stage proves the resolved coordinate set can be fetched entirely
offline against a pre-vendored local Maven repository, using Maven's own
`-Dmaven.repo.local` override. No behavioral tracing here yet -- this only
proves the fetch/resolve itself completes correctly offline. Maven has no
close analogue of build.rs/proc-macros/init() that runs automatically
during `dependency:resolve` -- annotation processors and any real code
only execute during an actual `mvn compile`, not plain dependency
resolution (mirrors GoEcosystem's Stage 2 reasoning exactly).

The one genuinely Maven-specific problem cargo/go's sandboxes don't have:
`dependency:resolve` is itself a Maven *plugin* goal, and just loading a
project descriptor makes Maven resolve the full default-lifecycle plugin
set for its packaging (resources/compiler/jar/surefire/install/deploy/
site, plus the dependency plugin itself) -- confirmed directly this needs
~51 plugin/dependency jars from a clean local repository before
`dependency:resolve` can run at all, none of which can come from the
per-run, host-provided project-dependency set. maven_sandbox.Dockerfile
pre-warms exactly that plugin closure into a world-readable, build-time
local repository (/opt/depshieldx-maven-plugin-cache). `-Dmaven.repo.
local` only accepts one path, and points-at-a-read-only-directory doesn't
work either way (Maven writes small bookkeeping files -- _remote.
repositories, resolution-status markers -- into whatever local repo path
it's given, confirmed directly this fails outright against a real
read-only bind mount), so this script copies both the pre-warmed plugin
cache and the host-provided, per-run project coordinates into one merged,
writable local repository under its own tmpfs work directory before
running `mvn --offline` against it -- the same "writable tmpfs, separate
from the read-only bundle mount" shape as $GOPATH/$GOCACHE in
sandbox_wrapper_go.py, just needed for a different underlying reason.

Parent POM chains: prepare_maven_download_bundle() already walked and
fetched every resolved artifact's real <parent> POM chain host-side (see
that function's docstring for why -- Maven's own dependency collector
needs each ancestor POM to resolve inherited versions/properties, and a
missing parent POM fails resolution outright even when the artifact's own
jar+pom are present, confirmed directly against a real example: com.
google.errorprone:error_prone_annotations:2.27.0's parent, error_prone_
parent:2.27.0, isn't a `dependency:list` entry, but is required for the
child to resolve). Nothing extra to do here -- the parent POMs already
sit in the host-provided m2-repo bind mount at their normal repository
coordinates, exactly where Maven's own resolver looks for them.

Prints the same DEPSHIELDX_SANDBOX_REPORT=<json> line sandbox.py's
_extract_report() already expects, with the same key shape cli/output.py's
summary formatter reads -- all empty/zero until behavioral tracing
populates them for real, mirroring sandbox_wrapper_go.py's Stage 2.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPORT_PREFIX = "DEPSHIELDX_SANDBOX_REPORT="
PLUGIN_CACHE_DIR = "/opt/depshieldx-maven-plugin-cache"
WORK_DIR = Path("/tmp/depshieldx-maven-work")


def _prepare_work_env(bundle_dir: Path) -> tuple[Path, dict]:
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    local_repo = WORK_DIR / "m2-repo"
    # copytree, not a bind mount or symlink: both the plugin cache and the
    # host-provided bundle need to end up looking like ONE local
    # repository to Maven, and `-Dmaven.repo.local` only accepts a single
    # path -- confirmed directly there's no supported way to layer two
    # local-repository directories for one Maven invocation.
    shutil.copytree(PLUGIN_CACHE_DIR, local_repo)
    shutil.copytree(bundle_dir / "m2-repo", local_repo, dirs_exist_ok=True)
    shutil.copy2(bundle_dir / "pom.xml", WORK_DIR / "pom.xml")

    env = dict(os.environ)
    env["HOME"] = "/tmp"
    # jansi (Maven's CLI colorization library) extracts a native .so into
    # java.io.tmpdir and dlopen()s it -- confirmed directly this fails
    # with UnsatisfiedLinkError against the shared, noexec outer /tmp
    # mount (the same tmpfs every other ecosystem's sandbox also mounts
    # noexec). Pointing java.io.tmpdir at this script's own exec-permitted
    # work directory instead fixes it without loosening the shared /tmp
    # mount's noexec posture for every other ecosystem.
    env["MAVEN_OPTS"] = f"-Djava.io.tmpdir={WORK_DIR}"
    return local_repo, env


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: sandbox_wrapper_maven.py <bundle_dir> [<groupId:artifactId@version>...]", file=sys.stderr)
        return 2

    bundle_dir = Path(sys.argv[1])
    install_targets = sys.argv[2:]

    local_repo, env = _prepare_work_env(bundle_dir)

    result = subprocess.run(
        ["mvn", "-B", "--offline", f"-Dmaven.repo.local={local_repo}", "-f", str(WORK_DIR / "pom.xml"), "dependency:resolve"],
        cwd=str(WORK_DIR),
        env=env,
        capture_output=True,
        text=True,
    )
    resolve_exit_code = result.returncode
    suspicious = resolve_exit_code != 0

    report = {
        "download_exit_code": resolve_exit_code,
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
