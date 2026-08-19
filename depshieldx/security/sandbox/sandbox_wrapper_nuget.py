"""Runs inside the Docker sandbox container for NuGet deep-mode installs --
the NuGet counterpart to sandbox_wrapper.py/sandbox_wrapper_npm.js/
sandbox_wrapper_cargo.py/sandbox_wrapper_go.py/sandbox_wrapper_maven.py.

This stage proves the resolved package set can be fetched entirely
offline against a pre-vendored local package source, using NuGet's own
local-folder package-source mechanism -- confirmed directly (against a
real Docker container matching this project's exact isolation posture:
--network none, --read-only rootfs, --cap-drop ALL, non-root user) to
work correctly end to end. No behavioral tracing here yet -- this only
proves the fetch/resolve itself completes correctly offline. Unlike
Cargo's build.rs or Go's init(), a jar-equivalent .nupkg consumed as a
plain PackageReference has no code that runs automatically during
`dotnet restore` alone -- confirmed directly with a real, hand-built
test package whose build/*.targets file defines both a
`BeforeTargets="Restore"` hook and a `BeforeTargets="Build"` hook (each
just an `<Exec>` of a distinctive echo command): `dotnet restore`
correctly writes the real `<Import Project="...Test.Injection.targets">`
wiring into obj/*.nuget.g.targets (proving the package's targets file
genuinely was resolved and referenced), but the Restore-bound hook's
echo never appears in restore's own output -- only a separate, later
`dotnet build` actually imports and evaluates that generated file from
its own start, and only then does the Build-bound hook's echo appear. A
future behavioral-tracing stage, wrapping `dotnet build` the way Maven's
Stage 3 wraps `mvn compile`, is where that real execution surface would
be traced.

Unlike Maven, no build-time plugin pre-warming is baked into the sandbox
image here -- confirmed directly `dotnet restore` needs nothing beyond
what the .NET SDK itself already ships, unlike `mvn dependency:resolve`,
which is itself a plugin goal needing its own dependency closure resolved
from network first.

NuGet.Config's `<clear/>` + a single local-folder `<add>` entry is what
makes this fully offline -- confirmed directly this is the correct,
real mechanism (not a reinterpretation): a local folder feed accepts flat
.nupkg files placed directly in it, no hierarchical extraction needed,
and restoring against `<clear/>`+local-only with the global packages
folder cache empty (this script always points $HOME at its own writable
work directory, guaranteeing an empty one) proves the resolve doesn't
silently succeed from some other, already-cached source.

Prints the same DEPSHIELDX_SANDBOX_REPORT=<json> line sandbox.py's
_extract_report() already expects, with the same key shape cli/output.py's
summary formatter reads -- all empty/zero until behavioral tracing
populates them for real, mirroring sandbox_wrapper_maven.py's own Stage 2.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

REPORT_PREFIX = "DEPSHIELDX_SANDBOX_REPORT="
WORK_DIR = Path("/tmp/depshieldx-nuget-work")


def _prepare_work_env(bundle_dir: Path) -> dict:
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    (WORK_DIR / "scratch.csproj").write_bytes((bundle_dir / "scratch.csproj").read_bytes())
    (WORK_DIR / "NuGet.Config").write_bytes((bundle_dir / "NuGet.Config").read_bytes())

    env = dict(os.environ)
    # $HOME/.nuget/packages is NuGet's real default global packages
    # folder (its own extraction/cache location) -- pointing HOME at
    # this script's own writable work directory keeps that cache
    # guaranteed-empty (proving the offline resolve isn't silently
    # succeeding from stale cache) and writable (confirmed directly the
    # default HOME under SANDBOX_USER has no real home directory to
    # write into either way).
    env["HOME"] = str(WORK_DIR)
    return env


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: sandbox_wrapper_nuget.py <bundle_dir> [<PackageId@version>...]", file=sys.stderr)
        return 2

    bundle_dir = Path(sys.argv[1])
    install_targets = sys.argv[2:]

    env = _prepare_work_env(bundle_dir)

    result = subprocess.run(
        ["dotnet", "restore", str(WORK_DIR / "scratch.csproj")],
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
