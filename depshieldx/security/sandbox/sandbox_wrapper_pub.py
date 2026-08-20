"""Runs inside the Docker sandbox container for Pub deep-mode installs --
the Pub counterpart to sandbox_wrapper_nuget.py/sandbox_wrapper_maven.py/
sandbox_wrapper_go.py/sandbox_wrapper_cargo.py/sandbox_wrapper_npm.js.

Stage 2 (fetch-only): proved the resolved package set can be resolved
entirely offline against a pre-built local $PUB_CACHE.

Stage 3 (this file, current version): adds real behavioral tracing
around an actual `dart run`, not just `dart pub get`. Pub's own real
code-execution surface -- confirmed directly, not assumed, and genuinely
different from every other ecosystem here -- is the "hooks" mechanism
(`hook/build.dart`, part of Dart's official Native Assets feature,
dart.dev/tools/hooks): a package can ship a `hook/build.dart` file
containing arbitrary Dart code (a real `void main(List<String> args)`
entry point) that the toolchain invokes for the root package *and every
transitive dependency* whenever building/running a consuming project --
Pub's real analogue to Cargo's `build.rs`, Maven's annotation
processors, or NuGet's build/*.targets.

Real, confirmed-directly findings this design is built on:
- `dart pub get`/`dart pub get --offline` alone never triggers hooks
  (verified directly with a hand-built test package: no hook activity
  during resolution) -- the same "resolve never executes code" property
  every other ecosystem here already has, so Stage 2's plain offline
  `pub get` stays safe to run un-straced.
- `dart run <file>` and `dart test` *do* trigger hooks for every
  resolved package, confirmed directly against a hand-built package
  whose hook writes a detectable marker -- and confirmed directly this
  fires even when the entry-point file doesn't import the package at
  all, the same "presence in the dependency graph is enough" pattern
  Maven's annotation processors and NuGet's build/*.targets already
  have.
- `dart compile exe` does **not** run hooks -- it fails outright with an
  explicit "'dart compile' does not support build hooks, use 'dart
  build' instead" error (confirmed directly) -- a real trap avoided by
  using `dart run` here instead.
- No toolchain-level network noise (the NuGetAudit/workload-verification
  surprise NuGet's own Stage 3 hit) turned up here: confirmed directly
  with a real container under this project's full isolation posture
  that a clean package's `dart run` makes zero AF_INET connection
  attempts, with or without --suppress-analytics. The flag is kept
  anyway as cheap, explicit, documented-intent defense in depth, not
  because it was observed to matter.
- Confirmed directly with a hand-built malicious hook (a real outbound
  `Socket.connect` to an external IP) that `dart run` invoking it inside
  this project's full isolation posture (--network none, --read-only
  rootfs, --cap-drop ALL, non-root user) produces a real, strace-visible
  blocked AF_INET connect attempt -- the same detection this wrapper's
  _is_remote_connect/blocked_events machinery already looks for.

Like NuGet, `dart run` itself needs $PUB_CACHE writable (see
sandbox_wrapper's own Stage 2 docstring / pub_sandbox.Dockerfile), so
this wrapper copies the mounted, pre-built cache into its own writable
tmpfs work directory first, the same as Stage 2 already does -- Stage 3
only adds the straced `dart run` step and a trivial probe.dart on top.

Ports sandbox_wrapper_cargo.py/sandbox_wrapper_go.py/
sandbox_wrapper_maven.py/sandbox_wrapper_nuget.py's strace-log-parsing
approach unchanged (same evidence/verdict shape, same regex-based
syscall parsing) -- filesystem isolation and network denial are already
enforced by the container itself, strace only needs to notice an
attempt.

Prints the same DEPSHIELDX_SANDBOX_REPORT=<json> line sandbox.py's
_extract_report() already expects, with the same key shape cli/output.py's
summary formatter reads.
"""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPORT_PREFIX = "DEPSHIELDX_SANDBOX_REPORT="
STRACE_LOG_PATH = "/tmp/depshieldx-strace.log"
WORK_DIR = Path("/tmp/depshieldx-pub-work")
BUNDLE_MOUNT_PREFIX = "/tmp/packages"

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
    # The bundle directory (flat .tar.gz/pubspec.yaml/pubspec.lock/
    # pub-cache) is bind-mounted read-only -- any write attempt against
    # it necessarily fails at the OS level (same as the other
    # ecosystems' blocked writes/connects), but a real attempt is still
    # meaningful evidence of a hook trying to tamper with its own
    # already checksum-verified source.
    if normalized.startswith(BUNDLE_MOUNT_PREFIX):
        return "bundle_source_tamper_attempt"
    work_dir_str = str(WORK_DIR).replace("\\", "/")
    if normalized.startswith(f"{work_dir_str}/.dart_tool"):
        return "build_output"
    if normalized.startswith(work_dir_str):
        return "project_files"
    return "other"


def _is_remote_connect(args_text: str) -> bool:
    return bool(AF_INET_PATTERN.search(args_text))


def _prepare_work_env(bundle_dir: Path) -> dict:
    work_pub_cache = WORK_DIR / "pub-cache"
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copytree(bundle_dir / "pub-cache", work_pub_cache)
    shutil.copy2(bundle_dir / "pubspec.yaml", WORK_DIR / "pubspec.yaml")
    shutil.copy2(bundle_dir / "pubspec.lock", WORK_DIR / "pubspec.lock")
    (WORK_DIR / "probe.dart").write_bytes(b"void main() {}\n")

    env = dict(os.environ)
    env["PUB_CACHE"] = str(work_pub_cache)
    env["HOME"] = str(WORK_DIR)
    return env


def _run_offline_get(env: dict) -> subprocess.CompletedProcess:
    """Deliberately un-straced: confirmed directly `dart pub get` never
    triggers hooks (Pub's own real code-execution surface, see module
    docstring) -- there is nothing here worth tracing, the same
    "restore/resolve alone can't run package code" property every other
    ecosystem here already has."""
    return subprocess.run(
        ["dart", "pub", "get", "--offline", "--enforce-lockfile"],
        cwd=str(WORK_DIR),
        env=env,
        capture_output=True,
        text=True,
    )


def _run_straced_run(env: dict) -> subprocess.CompletedProcess:
    strace_args = [
        "strace",
        "-f",
        "-s",
        "200",
        "-e",
        "trace=file,process,network",
        "-o",
        STRACE_LOG_PATH,
        "dart",
        "run",
        "probe.dart",
        # Confirmed directly this run makes zero network attempts of its
        # own either way (with or without this flag) under this
        # project's full isolation posture -- kept as cheap, explicit
        # defense in depth against Dart's own analytics/telemetry
        # mechanism (dart --help lists --enable-analytics/--disable-
        # analytics/--suppress-analytics as real flags), not because it
        # was observed to change anything here.
        "--suppress-analytics",
    ]
    return subprocess.run(strace_args, cwd=str(WORK_DIR), env=env, capture_output=True, text=True)


def _parse_strace_log(log_path: str) -> dict:
    evidence = {
        "write_count": 0,
        "write_samples": [],
        "write_buckets": {
            "project_files": 0,
            "build_output": 0,
            "bundle_source_tamper_attempt": 0,
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
                if bucket == "bundle_source_tamper_attempt":
                    evidence["blocked_events"].append(
                        {
                            "category": "bundle_tamper_denied",
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
            if file_path and _classify_write_path(file_path) == "bundle_source_tamper_attempt":
                evidence["blocked_events"].append(
                    {
                        "category": "bundle_tamper_denied",
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
                "message": "Package attempted network access during sandboxed run.",
            }
        )

    tamper_blocks = [e for e in evidence["blocked_events"] if e["category"] == "bundle_tamper_denied"]
    if tamper_blocks:
        verdicts.append(
            {
                "severity": "high",
                "code": "bundle_source_tamper_attempted",
                "message": "Package attempted to write into its own read-only bundle directory during sandboxed run.",
            }
        )

    # A hook failing to produce a valid build output (this wrapper's own
    # trivial probe.dart included, since it imports nothing) is common
    # and not itself suspicious -- real hooks fail offline for benign
    # reasons too (e.g. genuinely needing a native toolchain unavailable
    # in this image). Only a real, observed policy block is escalated.
    if build_exit_code != 0 and not evidence["blocked_events"]:
        verdicts.append(
            {
                "severity": "info",
                "code": "run_failed",
                "message": "The sandboxed `dart run` did not complete successfully, without triggering an explicit policy block.",
            }
        )

    if evidence["syscall_counts"]["process_exec"] > 0:
        verdicts.append(
            {
                "severity": "info",
                "code": "subprocess_execs_traced",
                "message": "The run spawned subprocesses (a package's own build hook, or similar) during sandboxed execution.",
            }
        )

    if evidence["syscall_counts"]["filesystem_mutation"] > 0:
        verdicts.append(
            {
                "severity": "info",
                "code": "filesystem_mutations_traced",
                "message": "Low-level filesystem mutation calls were traced during the sandboxed run.",
            }
        )

    return verdicts


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: sandbox_wrapper_pub.py <bundle_dir> [<package_name@version>...]", file=sys.stderr)
        return 2

    bundle_dir = Path(sys.argv[1])
    install_targets = sys.argv[2:]

    env = _prepare_work_env(bundle_dir)

    _run_offline_get(env)
    result = _run_straced_run(env)
    build_exit_code = result.returncode

    evidence = _parse_strace_log(STRACE_LOG_PATH)
    verdicts = _build_verdicts(evidence, build_exit_code)
    suspicious = any(v["severity"] == "high" for v in verdicts)

    report = {
        "download_exit_code": build_exit_code,
        "build_exit_code": build_exit_code,
        "suspicious": suspicious,
        "vendored_targets": install_targets,
        "build_stdout_tail": result.stdout[-2000:] if suspicious else "",
        "build_stderr_tail": result.stderr[-2000:] if suspicious else "",
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
