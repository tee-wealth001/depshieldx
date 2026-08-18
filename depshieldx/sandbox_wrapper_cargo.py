"""Runs inside the Docker sandbox container for cargo deep-mode installs --
the cargo counterpart to sandbox_wrapper.py/sandbox_wrapper_npm.js.

Stage 2 (this file, initial version): proves the resolved crate set can be
fetched entirely offline against pre-vendored crate sources, using Cargo's
own "directory source" mechanism -- confirmed directly (see below) to be the
correct offline-install analogue for cargo, distinct from both PyPI's
"install from pre-downloaded wheel files" and npm's "install from
pre-downloaded tarball paths" approaches. No behavioral tracing here yet --
this only proves the fetch itself completes correctly offline. Stage 3 adds
real syscall-level tracing around the actual `cargo build` step (build.rs
scripts and proc-macros -- cargo's equivalent attack surface to npm's
postinstall lifecycle scripts -- only execute during a real build, not
during fetch alone).

Why vendoring, not "install from local tarball paths" (npm's Stage 2
approach): reproduced directly that a live `cargo add`/`cargo fetch` against
--network none fails outright (cargo always needs to resolve against a
registry index, even for a single already-known dependency) -- unlike npm,
cargo has no direct "install from this local tarball path" verb. Cargo's own
supported offline mechanism is a "directory source": a `.cargo/config.toml`
that redirects the crates-io source to a local directory of *extracted*
crate sources (not raw .crate tarballs), each with a `.cargo-checksum.json`
marker file. sandbox.py's prepare_cargo_download_bundle() builds this vendor
directory on the host (downloading and SRI-checksum-verifying every raw
.crate tarball via ecosystems/cargo.py's already-verified fetch_artifact,
then extracting each one) -- this script only has to point a scratch
project's config at that pre-built, already-mounted vendor directory and
run `cargo fetch --offline`, confirmed directly to work fully offline as a
non-root, homeless sandbox user.

$CARGO_HOME: unlike npm (which needed HOME=/tmp set explicitly, or
ENOENT'd), reproduced directly that `cargo fetch --offline` against a
vendored/directory-replaced source does NOT touch $CARGO_HOME at all -- no
`.cargo` directory appears anywhere under it during a real traced run. Not
relying on this being true in every future cargo version, though: nothing
here assumes a writable $CARGO_HOME is unnecessary, it simply isn't given
one, and the real container run already proved that's fine for this
specific fetch-offline-from-vendored-sources operation.

Prints the same DEPSHIELDX_SANDBOX_REPORT=<json> line sandbox.py's
_extract_report() already expects, with the same key shape cli/output.py's
summary formatter reads (write_count, syscall_counts, allowed_subprocesses,
imported_modules, import_failures, skipped_imports, blocked_events,
verdicts) -- all empty/zero until Stage 3 populates them for real, so
downstream report rendering works unchanged across all three ecosystems.
"""

import json
import subprocess
import sys
from pathlib import Path

REPORT_PREFIX = "DEPSHIELDX_SANDBOX_REPORT="


def _write_scratch_project(install_dir: Path, vendor_dir: str, install_targets: list[str]) -> None:
    src_dir = install_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "lib.rs").write_text("")

    lines = [
        "[package]",
        'name = "depshieldx-sandbox"',
        'version = "0.0.0"',
        'edition = "2024"',
        "",
        "[dependencies]",
    ]
    for target in install_targets:
        # "<name>@=<version>" (the exact-pin syntax host_install_command
        # already uses) -- avoids re-deriving name/version by parsing
        # vendor directory names back apart, which is unreliable for
        # prerelease versions containing their own "-" (e.g. "1.0.0-alpha").
        name, _, requirement = target.partition("@")
        lines.append(f'{name} = "{requirement}"')
    (install_dir / "Cargo.toml").write_text("\n".join(lines) + "\n")

    cargo_dir = install_dir / ".cargo"
    cargo_dir.mkdir(exist_ok=True)
    (cargo_dir / "config.toml").write_text(
        '[source.crates-io]\nreplace-with = "vendored-sources"\n\n'
        f'[source.vendored-sources]\ndirectory = "{vendor_dir}"\n'
    )


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: sandbox_wrapper_cargo.py <vendor_dir> <name@=version> [<name@=version>...]", file=sys.stderr)
        return 2

    vendor_dir = sys.argv[1]
    install_targets = sys.argv[2:]

    install_dir = Path("/tmp/depshieldx-cargo-install")
    _write_scratch_project(install_dir, vendor_dir, install_targets)

    result = subprocess.run(
        ["cargo", "fetch", "--offline"],
        cwd=str(install_dir),
        capture_output=True,
        text=True,
    )
    fetch_exit_code = result.returncode
    suspicious = fetch_exit_code != 0

    report = {
        "fetch_exit_code": fetch_exit_code,
        "suspicious": suspicious,
        "vendored_targets": install_targets,
        "fetch_stdout_tail": result.stdout[-2000:] if suspicious else "",
        "fetch_stderr_tail": result.stderr[-2000:] if suspicious else "",
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
