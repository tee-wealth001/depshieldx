"""Runs inside the Docker sandbox container for Go deep-mode installs --
the Go counterpart to sandbox_wrapper.py/sandbox_wrapper_npm.js/
sandbox_wrapper_cargo.py.

Stage 2 (fetch-only): proved the resolved module set can be fetched
entirely offline against a pre-vendored local module proxy, using Go's
own file-based GOPROXY mechanism.

Stage 3 (this file, current version): adds real behavioral tracing around
an actual `go build`, not just `go mod download`. init() functions and
//go:generate-produced code -- Go's equivalent attack surface to cargo's
build.rs/proc-macros -- only execute during a real build, not during
`go mod download` alone. Ports sandbox_wrapper_cargo.py's strace-log-
parsing approach (regex-based SYSCALL_LINE parsing into the same
evidence/verdict shape) rather than a from-scratch design: this doesn't
*block* individual syscalls in real time (ptrace-based interception is a
much bigger undertaking than observation) -- filesystem isolation and
network denial are already enforced by the container itself
(--read-only rootfs, --network none, plus the read-only bundle-directory
bind mount), so a malicious init() function's writes/connects fail at the
OS level regardless; strace's job is to notice that it tried.

The one genuinely Go-specific problem cargo's model doesn't have: Cargo
compiles every crate declared in Cargo.toml's [dependencies] regardless of
whether the scratch crate's own source actually `use`s it (crate-level
compilation happens ahead of use-analysis). Go's build model is stricter
and finer-grained -- only actually-imported packages get compiled at all
(confirmed directly: a module listed in go.mod's require block but never
imported produces zero compiler activity for it). So a scratch main.go
here blank-imports (`_ "modulepath"`) every resolved module's bare path to
force real compilation the way cargo gets "for free". This surfaces a
second, real constraint: not every module has an importable root package
-- confirmed directly against a real multi-package library
(golang.org/x/crypto has none, only subpackages like .../bcrypt), which
fails to blank-import with Go's own "no required module provides package"
error. Forcing the whole build to fail over this would make Stage 3 nearly
useless in practice, since root-package-less multi-package modules are
extremely common in real dependency graphs -- so a fast, untraced
`go build` probe runs first purely to discover which resolved modules
fail this way, those get dropped from the real (straced) build's import
list, and the drop is recorded in the report as `skipped_modules` rather
than silently pretended away. This is a real, accepted coverage gap, not
a bug: those modules' own root-level code (if any) simply isn't exercised
by this stage. There is no cargo equivalent to document here, since Cargo
never had this problem to begin with.

-p 2: mirrors cargo's `-j 2` fix for the exact same underlying problem --
reproduced directly there that letting the build tool default to the host
core count could exhaust the container's --pids-limit cgroup on a
many-core host and crash mid-build with an unrelated-looking failure.
Capping Go's own build parallelism the same defensive way up front avoids
having to rediscover that failure mode a second time.

$HOME/$GOPATH/$GOCACHE: unlike cargo's directory-source fetch (which
touches neither $CARGO_HOME nor $HOME), `go build` needs writable
locations for its own bookkeeping and compiled-package cache -- confirmed
directly. All three are pointed at this script's own writable work
directory, not assumed to already exist there.

--cap-add SYS_PTRACE: not needed here either, same reasoning already
confirmed for npm/cargo -- a process can always ptrace its own
descendants regardless of capabilities or ptrace_scope.

Prints the same DEPSHIELDX_SANDBOX_REPORT=<json> line sandbox.py's
_extract_report() already expects, with the same key shape cli/output.py's
summary formatter reads (write_count, syscall_counts, allowed_subprocesses,
imported_modules, import_failures, skipped_imports, blocked_events,
verdicts), so downstream report rendering works unchanged across all four
ecosystems.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPORT_PREFIX = "DEPSHIELDX_SANDBOX_REPORT="
STRACE_LOG_PATH = "/tmp/depshieldx-strace.log"
WORK_DIR = Path("/tmp/depshieldx-go-work")
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
# Confirmed directly against the real `go build` error text for a module
# with no importable root package. The GOFLAGS=-mod=readonly this script
# always sets (see _prepare_work_env) changes the exact wording -- without
# it, Go suggests "no required module provides package X; to add it:";
# under readonly mode, which is what this sandbox actually runs under, the
# real message is "cannot find module providing package X: import lookup
# disabled by -mod=readonly" instead. Both are matched since either could
# plausibly appear depending on how this script is invoked.
MISSING_PACKAGE_PATTERN = re.compile(
    r"(?:no required module provides package|cannot find module providing package) (\S+)[:;]"
)


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
    # The bundle directory (go.mod/go.sum/goproxy) is bind-mounted
    # read-only -- any write attempt against it necessarily fails at the
    # OS level (same as npm's/cargo's blocked writes/connects), but a real
    # attempt is still meaningful evidence of an init() function trying to
    # tamper with its own already checksum-verified source.
    if normalized.startswith(BUNDLE_MOUNT_PREFIX):
        return "bundle_source_tamper_attempt"
    work_dir_str = str(WORK_DIR).replace("\\", "/")
    if normalized.startswith(f"{work_dir_str}/gocache") or normalized.startswith(f"{work_dir_str}/gopath"):
        return "build_output"
    if normalized.startswith(work_dir_str):
        return "project_files"
    return "other"


def _is_remote_connect(args_text: str) -> bool:
    return bool(AF_INET_PATTERN.search(args_text))


def _write_main_go(module_names: list[str]) -> None:
    lines = ["package main", ""]
    if module_names:
        lines.append("import (")
        for name in module_names:
            lines.append(f'\t_ "{name}"')
        lines.append(")")
    lines.append("")
    lines.append("func main() {}")
    (WORK_DIR / "main.go").write_bytes(("\n".join(lines) + "\n").encode("utf-8"))


def _discover_buildable_modules(module_names: list[str], env: dict) -> tuple[list[str], list[str]]:
    """Best-effort: not every resolved module has an importable root
    package (confirmed directly). A fast, untraced `go build` probes the
    full candidate list; any "no required module provides package X"
    failures identify modules to drop before the real (straced) build."""
    _write_main_go(module_names)
    probe = subprocess.run(["go", "build", "."], cwd=str(WORK_DIR), env=env, capture_output=True, text=True)
    if probe.returncode == 0:
        return module_names, []

    unbuildable = set(MISSING_PACKAGE_PATTERN.findall(probe.stdout + probe.stderr))
    buildable = [name for name in module_names if name not in unbuildable]
    skipped = [name for name in module_names if name in unbuildable]
    _write_main_go(buildable)
    return buildable, skipped


def _run_straced_build(env: dict) -> subprocess.CompletedProcess:
    strace_args = [
        "strace",
        "-f",
        "-s",
        "200",
        "-e",
        "trace=file,process,network",
        "-o",
        STRACE_LOG_PATH,
        "go",
        "build",
        # Mirrors cargo's -j 2 fix for the same underlying problem:
        # capping build parallelism up front avoids exhausting the
        # container's --pids-limit cgroup on a many-core host.
        "-p",
        "2",
        ".",
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
                "message": "Package attempted network access during sandboxed build.",
            }
        )

    tamper_blocks = [e for e in evidence["blocked_events"] if e["category"] == "bundle_tamper_denied"]
    if tamper_blocks:
        verdicts.append(
            {
                "severity": "high",
                "code": "bundle_source_tamper_attempted",
                "message": "Package attempted to write into its own read-only bundle directory during sandboxed build.",
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
                "message": "The build spawned subprocesses (the go compiler/linker, init()-triggered commands) during sandboxed compilation.",
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


def _prepare_work_env(bundle_dir: Path) -> dict:
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    (WORK_DIR / "go.mod").write_bytes((bundle_dir / "go.mod").read_bytes())
    (WORK_DIR / "go.sum").write_bytes((bundle_dir / "go.sum").read_bytes())

    env = dict(os.environ)
    env["GOPROXY"] = f"file://{bundle_dir}/goproxy"
    env["GOSUMDB"] = "off"
    env["GOFLAGS"] = "-mod=readonly"
    env["GOPATH"] = str(WORK_DIR / "gopath")
    env["GOCACHE"] = str(WORK_DIR / "gocache")
    env["HOME"] = "/tmp"
    return env


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: sandbox_wrapper_go.py <bundle_dir> [<module@version>...]", file=sys.stderr)
        return 2

    bundle_dir = Path(sys.argv[1])
    install_targets = sys.argv[2:]
    module_names = [target.split("@", 1)[0] for target in install_targets]

    env = _prepare_work_env(bundle_dir)
    buildable_modules, skipped_modules = _discover_buildable_modules(module_names, env)

    result = _run_straced_build(env)
    build_exit_code = result.returncode

    evidence = _parse_strace_log(STRACE_LOG_PATH)
    verdicts = _build_verdicts(evidence, build_exit_code)
    suspicious = build_exit_code != 0 or any(v["severity"] == "high" for v in verdicts)

    report = {
        "download_exit_code": build_exit_code,
        "build_exit_code": build_exit_code,
        "suspicious": suspicious,
        "vendored_targets": install_targets,
        "traced_modules": buildable_modules,
        # Modules with no importable root package (e.g. golang.org/x/crypto)
        # -- a real, accepted coverage gap, not silently pretended away.
        # See module docstring.
        "skipped_modules": skipped_modules,
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
