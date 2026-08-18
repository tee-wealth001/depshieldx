"""Runs inside the Docker sandbox container for Go deep-mode installs --
the Go counterpart to sandbox_wrapper.py/sandbox_wrapper_npm.js/
sandbox_wrapper_cargo.py.

This stage proves the resolved module set can be fetched entirely offline
against a pre-vendored local module proxy, using Go's own file-based
GOPROXY mechanism -- confirmed directly (against a real Docker container,
matching this project's exact isolation posture: --network none,
--read-only rootfs, --cap-drop ALL, non-root user) to work correctly
end to end. No behavioral tracing here yet -- this only proves the fetch
itself completes correctly offline. `init()` functions and //go:generate
directives are Go's closest equivalent to cargo's build.rs/proc-macro
attack surface, and only run during a real `go build`, not during
`go mod download` alone.

Why a local file-based GOPROXY, not cargo's "directory source" vendoring
or npm's "install from local tarball paths": reproduced directly that Go
has no "install from this local tarball path" verb either, but unlike
cargo it has a first-class, standard offline mechanism that needs no
reinterpretation -- GOPROXY accepts a "file://" URL pointing at a
directory laid out exactly like a real module proxy
(<module>/@v/<version>.{info,mod,zip} -- the same escaped-path format
prepare_go_download_bundle() builds host-side, reusing the exact encoding
ecosystems/go/registry.py's escape_module_path() already implements for
the real network path). `go mod download <module>...` against it, combined
with a host-written go.sum (using the same dirhash Hash1 algorithm already
verified byte-for-byte against real data), needs no network at all --
confirmed directly with GOSUMDB=off and --network none together. Explicit
module names are passed (not a bare `go mod download`/`go mod download
all`): the scratch go.mod has a require block but no real .go source
files importing anything, so there is no import graph for Go's own
download-selection logic to walk -- confirmed directly that a bare
`go mod download` against exactly this shape downloads nothing.

$HOME/$GOPATH/$GOCACHE: unlike cargo's directory-source fetch (which
touches neither $CARGO_HOME nor $HOME), `go mod download` needs writable
locations for its own bookkeeping -- confirmed directly. All three are
pointed at the writable tmpfs this script itself sets up, mirrored from
the read-only bundle mount rather than assumed to already exist there.

Prints the same DEPSHIELDX_SANDBOX_REPORT=<json> line sandbox.py's
_extract_report() already expects, with the same key shape cli/output.py's
summary formatter reads (write_count, syscall_counts, allowed_subprocesses,
imported_modules, import_failures, skipped_imports, blocked_events,
verdicts) -- all empty/zero until behavioral tracing populates them for
real, so downstream report rendering works unchanged across all four
ecosystems.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

REPORT_PREFIX = "DEPSHIELDX_SANDBOX_REPORT="


def _prepare_work_env(bundle_dir: Path) -> tuple[Path, dict]:
    work_dir = Path("/tmp/depshieldx-go-work")
    work_dir.mkdir(parents=True, exist_ok=True)
    (work_dir / "go.mod").write_bytes((bundle_dir / "go.mod").read_bytes())
    (work_dir / "go.sum").write_bytes((bundle_dir / "go.sum").read_bytes())

    env = dict(os.environ)
    env["GOPROXY"] = f"file://{bundle_dir}/goproxy"
    env["GOSUMDB"] = "off"
    env["GOFLAGS"] = "-mod=readonly"
    env["GOPATH"] = str(work_dir / "gopath")
    env["GOCACHE"] = str(work_dir / "gocache")
    env["HOME"] = "/tmp"
    return work_dir, env


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: sandbox_wrapper_go.py <bundle_dir> [<module@version>...]", file=sys.stderr)
        return 2

    bundle_dir = Path(sys.argv[1])
    install_targets = sys.argv[2:]
    module_names = [target.split("@", 1)[0] for target in install_targets]

    work_dir, env = _prepare_work_env(bundle_dir)

    result = subprocess.run(
        ["go", "mod", "download", "-x", *module_names],
        cwd=str(work_dir),
        env=env,
        capture_output=True,
        text=True,
    )
    download_exit_code = result.returncode
    suspicious = download_exit_code != 0

    report = {
        "download_exit_code": download_exit_code,
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
