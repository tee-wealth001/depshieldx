"""Runs inside the Docker sandbox container for cargo deep-mode installs --
the cargo counterpart to sandbox_wrapper.py/sandbox_wrapper_npm.js.

Stage 2 (fetch-only): proved the resolved crate set can be fetched entirely
offline against pre-vendored crate sources, using Cargo's own "directory
source" mechanism -- confirmed directly to be the correct offline-install
analogue for cargo, distinct from both PyPI's "install from pre-downloaded
wheel files" and npm's "install from pre-downloaded tarball paths"
approaches.

Stage 3 (this file, current version): adds real behavioral tracing around
an actual `cargo build --offline`, not just `cargo fetch`. build.rs scripts
and proc-macros -- cargo's equivalent attack surface to npm's postinstall
lifecycle scripts -- only execute during a real build, not during dependency
fetch alone. Ports sandbox_wrapper_npm.js's strace-log-parsing approach
(regex-based SYSCALL_LINE parsing into the same evidence/verdict shape)
rather than a from-scratch design, since the same `strace -f` observation
model applies: this doesn't *block* individual syscalls in real time
(ptrace-based interception is a much bigger undertaking than observation) --
filesystem isolation and network denial are already enforced by the
container itself (--read-only rootfs, --network none, plus the read-only
vendor-directory bind mount specific to cargo), so a malicious build.rs's
writes/connects fail at the OS level regardless; strace's job is to notice
that it tried, the same way sandbox_wrapper_npm.js reports a *blocked*
network attempt as evidence rather than preventing it itself.

Why `cargo build`, not `cargo check`: reproduced directly (outside the
sandbox, via a throwaway host-side scratch project with a marker-writing
build.rs) that `cargo check` executes build.rs identically to `cargo
build` -- both need it, since build scripts can affect the compilation
itself (cfg flags, generated code). A real timing comparison against the
serde+serde_derive dependency graph (proc-macro-heavy, the same shape as a
typical real-world crate) showed no meaningful time difference between the
two (~5.6s cold, both ways) -- most of the cost is compiling the
proc-macro/build-script dependencies themselves, which happens identically
under both commands. Given no speed advantage, `cargo build` is strictly
more faithful to what a real consumer of the crate actually experiences
(full codegen, not just type-checking), so there's no reason to prefer
`cargo check`.

Why the scratch project needs its own exec-permitted tmpfs, layered over
the container's shared noexec /tmp: reproduced directly that a real `cargo
build --offline` fails with a "Permission denied" executing
`target/debug/build/<crate>-<hash>/build-script-build` under the sandbox's
inherited `--tmpfs /tmp:...,noexec,...` (fine for Stage 2's fetch-only
posture, which never executes anything freshly written to disk, but
fundamentally incompatible with `cargo build`, whose entire job is to
compile and then run code -- build-script binaries and proc-macro dylibs
included). The fix (mirroring the exact bug class already found and fixed
for npm's node_modules parent-directory mount, see sandbox.py's is_npm
branch): mount the *whole* scratch project directory as its own
`exec`-permitted tmpfs (not just its `target/` subdirectory) -- mounting
only a nested subpath left the parent directory auto-created by Docker as a
root-owned mount point the sandbox user couldn't write into. The vendor
directory bind mount stays under the outer, still-`noexec` /tmp, since
nothing needs to execute out of it.

$CARGO_HOME: Stage 2's `cargo fetch --offline` doesn't touch $CARGO_HOME at
all (reproduced directly). A full `cargo build --offline` is different --
reproduced directly that cargo attempts a handful of best-effort
global-cache-lock writes under $CARGO_HOME (`.package-cache`,
`.global-cache`, `registry/CACHEDIR.TAG`), which land on the image's
read-only rootfs (the default $CARGO_HOME, `/usr/local/cargo`, is baked in
at image-build time, not bind-mounted). Each attempt fails with EROFS/ENOENT
in the trace, and cargo tolerates the failure silently -- the build
completes successfully regardless. Not relying on this graceful-failure
behavior being guaranteed by every future cargo version, though: nothing
here makes $CARGO_HOME writable to "fix" it, since the real container runs
already proved a failing cache-lock attempt doesn't block the build. These
attempts get bucketed under write_buckets["other"] below, not flagged as
suspicious -- they're cargo's own internal housekeeping, not vendor tamper
or a build.rs/proc-macro doing something to the sandbox.

--cap-add SYS_PTRACE: not needed, confirmed directly under the exact
sandbox posture (--cap-drop ALL, no capabilities added back at all) --
strace traced the full `cargo -> rustc` process tree (22000+ log lines for
a 7-crate build) without issue, matching npm's own finding that a process
can always ptrace its own descendants regardless of capabilities.

Malicious build.rs detection verified directly with a real fixture: a
build.rs that attempts `TcpStream::connect` to a real external address
during the build step. The connection failed with ENETUNREACH (proof
--network none is doing its job) *and* showed up in the strace log as a
`connect()` call, recorded here as a blocked_events entry the same way
sandbox_wrapper_npm.js's `network_denied` category works.

Prints the same DEPSHIELDX_SANDBOX_REPORT=<json> line sandbox.py's
_extract_report() already expects, with the same key shape cli/output.py's
summary formatter reads (write_count, syscall_counts, allowed_subprocesses,
imported_modules, import_failures, skipped_imports, blocked_events,
verdicts) -- so downstream report rendering works unchanged across all
three ecosystems.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

REPORT_PREFIX = "DEPSHIELDX_SANDBOX_REPORT="
STRACE_LOG_PATH = "/tmp/depshieldx-strace.log"
INSTALL_DIR = "/tmp/depshieldx-cargo-install"
VENDOR_MOUNT_PREFIX = "/tmp/packages/vendor"

MAX_SAMPLES = 12
MAX_SUBPROCESSES = 8
MAX_WRITE_SAMPLES = 8

WRITE_OPEN_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
MUTATION_SYSCALLS = {
    "unlink",
    "unlinkat",
    "rmdir",
    "mkdir",
    "mkdirat",
    "rename",
    "renameat",
    "renameat2",
    "symlink",
    "symlinkat",
    "chmod",
    "fchmodat",
}
OPEN_SYSCALLS = {"open", "openat"}
EXEC_SYSCALLS = {"execve", "execveat"}

# strace line shape (with -f, multi-process): "<pid>  <syscall>(<args>) = <retval> [errno text]"
# e.g. `319   connect(5, {sa_family=AF_INET, ...}, 16) = -1 ENETUNREACH (Network is unreachable)`
SYSCALL_LINE = re.compile(r"^\s*(\d+)\s+(\w+)\((.*)\)\s*=\s*(-?\d+|0x[0-9a-f]+)(.*)$")
QUOTED_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')
ARGV_BRACKET = re.compile(r"\[(.*?)\]")
AF_INET_PATTERN = re.compile(r"sa_family=AF_INET6?\b")


def _extract_first_quoted_string(text: str) -> str | None:
    match = QUOTED_STRING.search(text)
    return match.group(1) if match else None


def _extract_argv(text: str) -> list[str]:
    match = ARGV_BRACKET.search(text)
    if not match:
        return []
    return QUOTED_STRING.findall(match.group(1))


def _classify_write_path(raw_path: str) -> str:
    normalized = raw_path.replace("\\", "/")
    # The vendor directory is bind-mounted read-only -- any write attempt
    # against it necessarily fails at the OS level (same as npm's blocked
    # network connect()s), but a real attempt is still meaningful evidence
    # of a build.rs/proc-macro trying to tamper with its own already
    # checksum-verified source.
    if normalized.startswith(VENDOR_MOUNT_PREFIX):
        return "vendor_source_tamper_attempt"
    if "/target/" in normalized or normalized.endswith("/target"):
        return "build_output"
    if normalized.startswith(INSTALL_DIR):
        return "project_files"
    return "other"


def _is_remote_connect(args_text: str) -> bool:
    return bool(AF_INET_PATTERN.search(args_text))


def _run_straced_build() -> subprocess.CompletedProcess:
    strace_args = [
        "strace",
        "-f",
        "-s",
        "200",
        "-e",
        "trace=file,process,network",
        "-o",
        STRACE_LOG_PATH,
        "cargo",
        "build",
        "--offline",
        # Cargo defaults -j to the visible core count (nproc), which on a
        # many-core host reproduced a real crash: LLVM's own linker thread
        # pool exhausted the container's --pids-limit cgroup and `ld` died
        # with SIGABRT mid-build -- a false "build failed" verdict
        # completely unrelated to anything malicious. --cpus already caps
        # the container's actual CPU budget regardless of job count, so
        # capping -j to a small, host-independent constant avoids chasing a
        # pids-limit number that would otherwise have to scale with
        # whatever machine happens to run this. Confirmed directly (twice,
        # to rule out a one-off) that -j 2 builds the same proc-macro-heavy
        # dependency graph cleanly under the sandbox's pids-limit.
        "-j",
        "2",
    ]
    return subprocess.run(strace_args, cwd=INSTALL_DIR, capture_output=True, text=True)


def _parse_strace_log(log_path: str) -> dict:
    evidence = {
        "write_count": 0,
        "write_samples": [],
        "write_buckets": {
            "project_files": 0,
            "build_output": 0,
            "vendor_source_tamper_attempt": 0,
            "other": 0,
        },
        "syscall_counts": {"filesystem_mutation": 0, "process_exec": 0, "network": 0},
        "syscall_samples": [],
        "subprocesses": [],
        "blocked_events": [],
    }

    try:
        log_text = Path(log_path).read_text(errors="replace")
    except OSError:
        return evidence

    seen_subprocesses = set()

    for line in log_text.splitlines():
        match = SYSCALL_LINE.match(line)
        if not match:
            continue
        _pid, syscall, args_text, retval, _rest = match.groups()

        if syscall in OPEN_SYSCALLS:
            if not any(flag in args_text for flag in WRITE_OPEN_FLAGS):
                continue
            file_path = _extract_first_quoted_string(args_text)
            evidence["syscall_counts"]["filesystem_mutation"] += 1
            if len(evidence["syscall_samples"]) < MAX_SAMPLES:
                evidence["syscall_samples"].append(
                    {"category": "syscall:filesystem_mutation", "detail": {"call": syscall, "path": file_path}}
                )
            if file_path:
                evidence["write_count"] += 1
                if len(evidence["write_samples"]) < MAX_WRITE_SAMPLES and file_path not in evidence["write_samples"]:
                    evidence["write_samples"].append(file_path)
                bucket = _classify_write_path(file_path)
                evidence["write_buckets"][bucket] += 1
                if bucket == "vendor_source_tamper_attempt":
                    evidence["blocked_events"].append(
                        {
                            "category": "vendor_tamper_denied",
                            "detail": {"call": syscall, "path": file_path, "retval": retval},
                        }
                    )
            continue

        if syscall in MUTATION_SYSCALLS:
            file_path = _extract_first_quoted_string(args_text)
            evidence["syscall_counts"]["filesystem_mutation"] += 1
            if len(evidence["syscall_samples"]) < MAX_SAMPLES:
                evidence["syscall_samples"].append(
                    {"category": "syscall:filesystem_mutation", "detail": {"call": syscall, "path": file_path}}
                )
            if file_path and _classify_write_path(file_path) == "vendor_source_tamper_attempt":
                evidence["blocked_events"].append(
                    {
                        "category": "vendor_tamper_denied",
                        "detail": {"call": syscall, "path": file_path, "retval": retval},
                    }
                )
            continue

        if syscall in EXEC_SYSCALLS:
            evidence["syscall_counts"]["process_exec"] += 1
            argv = _extract_argv(args_text)
            command = argv if argv else [value for value in [_extract_first_quoted_string(args_text)] if value]
            if len(evidence["syscall_samples"]) < MAX_SAMPLES:
                evidence["syscall_samples"].append(
                    {"category": "syscall:process_exec", "detail": {"call": syscall, "command": command}}
                )
            key = json.dumps(command)
            if command and key not in seen_subprocesses and len(evidence["subprocesses"]) < MAX_SUBPROCESSES:
                seen_subprocesses.add(key)
                evidence["subprocesses"].append(command)
            continue

        if syscall == "connect" and _is_remote_connect(args_text):
            evidence["syscall_counts"]["network"] += 1
            detail = {"call": syscall, "args": args_text.strip(), "retval": retval}
            if len(evidence["syscall_samples"]) < MAX_SAMPLES:
                evidence["syscall_samples"].append({"category": "syscall:network", "detail": detail})
            evidence["blocked_events"].append({"category": "network_denied", "detail": detail})

    return evidence


def _build_verdicts(evidence: dict, build_exit_code: int) -> list[dict]:
    verdicts = []

    network_blocks = [e for e in evidence["blocked_events"] if e["category"] == "network_denied"]
    if network_blocks:
        verdicts.append(
            {
                "severity": "high",
                "code": "network_attempt_blocked",
                "message": "Package attempted network access during sandboxed build.",
            }
        )

    tamper_blocks = [e for e in evidence["blocked_events"] if e["category"] == "vendor_tamper_denied"]
    if tamper_blocks:
        verdicts.append(
            {
                "severity": "high",
                "code": "vendor_source_tamper_attempted",
                "message": "Package attempted to write into its own read-only vendored source during sandboxed build.",
            }
        )

    if build_exit_code != 0 and not evidence["blocked_events"]:
        verdicts.append(
            {
                "severity": "medium",
                "code": "build_failed",
                "message": "The sandboxed build failed without triggering an explicit policy block.",
            }
        )

    if evidence["syscall_counts"]["process_exec"] > 0:
        verdicts.append(
            {
                "severity": "info",
                "code": "subprocess_execs_traced",
                "message": "The build spawned subprocesses (rustc, build scripts, proc-macros) during sandboxed compilation.",
            }
        )

    if evidence["syscall_counts"]["filesystem_mutation"] > 0:
        verdicts.append(
            {
                "severity": "info",
                "code": "filesystem_mutations_traced",
                "message": "Low-level filesystem mutation calls were traced during sandboxed build.",
            }
        )

    return verdicts


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

    install_dir = Path(INSTALL_DIR)
    _write_scratch_project(install_dir, vendor_dir, install_targets)

    result = _run_straced_build()
    build_exit_code = result.returncode

    evidence = _parse_strace_log(STRACE_LOG_PATH)
    verdicts = _build_verdicts(evidence, build_exit_code)
    suspicious = build_exit_code != 0 or any(v["severity"] == "high" for v in verdicts)

    report = {
        "build_exit_code": build_exit_code,
        "suspicious": suspicious,
        "vendored_targets": install_targets,
        "build_stdout_tail": result.stdout[-2000:] if build_exit_code != 0 else "",
        "build_stderr_tail": result.stderr[-2000:] if build_exit_code != 0 else "",
        "write_count": evidence["write_count"],
        "write_buckets": evidence["write_buckets"],
        "write_samples": evidence["write_samples"],
        "syscall_counts": evidence["syscall_counts"],
        "syscall_samples": evidence["syscall_samples"],
        "allowed_subprocesses": evidence["subprocesses"],
        "imported_modules": [],
        "import_failures": [],
        "risky_import_failures": [],
        "environmental_import_failures": [],
        "skipped_imports": [],
        "blocked_events": evidence["blocked_events"],
        "events": [],
        "verdicts": verdicts,
    }
    print(REPORT_PREFIX + json.dumps(report))
    return 1 if suspicious else 0


if __name__ == "__main__":
    sys.exit(main())
