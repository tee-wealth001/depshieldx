"""Runs inside the Docker sandbox container for NuGet deep-mode installs --
the NuGet counterpart to sandbox_wrapper.py/sandbox_wrapper_npm.js/
sandbox_wrapper_cargo.py/sandbox_wrapper_go.py/sandbox_wrapper_maven.py.

Stage 2 (fetch-only): proved the resolved package set can be fetched
entirely offline against a pre-vendored local package source, using
NuGet's own local-folder package-source mechanism.

Stage 3 (this file, current version): adds real behavioral tracing around
an actual `dotnet build`, not just `dotnet restore`. Confirmed directly
this is the right place code can run: a jar-equivalent .nupkg consumed
as a plain PackageReference has no code that runs automatically during
`dotnet restore` alone (Stage 2's own fetch-only proof), but a package
that ships a `build/*.targets` or `build/*.props` file gets it imported
and evaluated during `dotnet build` -- verified directly with a real,
hand-built test package whose targets file defines a
`BeforeTargets="Build"` hook (an `<Exec>` of a distinctive echo command):
the hook's output only appeared once a real `dotnet build` ran, never
during `dotnet restore` alone. Unlike Maven's narrower "only annotation-
processor-registering dependencies get a real execution hook" case, this
is NuGet's own, broader equivalent surface -- any package shipping
build-time MSBuild logic, not just a narrow processor-registration
mechanism.

A trivial scratch source file (DepshieldxProbe.cs, containing nothing
that references any resolved package) is enough to give `dotnet build`
something to compile -- confirmed directly this triggers every resolved
package's build/*.targets import+evaluation regardless of whether the
compiled source actually uses the package's types, the same "classpath/
build-graph presence alone is enough" pattern already confirmed for
Maven's annotation processors.

Real, confirmed-directly detail worth documenting: MSBuild's `<Exec>`
task does not run its command as a literal `sh -c "<command>"` argv on
Linux -- it writes the command text into a temporary script file (e.g.
`/tmp/MSBuildTempXXXXXX/tmpYYYYYYYY.exec.cmd`) and executes `sh -c
". <path>"` (source, not direct execve of the file) instead. Confirmed
directly against a real strace log: the traced execve args show the
temp-file path, not the original command text. This means
allowed_subprocesses below faithfully shows *that* a shell ran a
generated script during the build (a real, meaningful signal on its
own), but not always the literal command text for Exec-task-driven
subprocesses specifically -- direct child-process invocations (a real
compiler, a directly-exec'd tool) still show full, real argv the same as
every other ecosystem's tracing does. `-p:UseSharedCompilation=false
/nodeReuse:false` are passed to keep the build's own process tree fully
self-contained in a one-shot sandboxed context (no lingering background
compiler-server/build-node processes to reason about), even though
neither flag was what explained the temp-file-indirection behavior above
-- confirmed directly during development, not assumed.

Ports sandbox_wrapper_cargo.py/sandbox_wrapper_go.py/
sandbox_wrapper_maven.py's strace-log-parsing approach unchanged (same
evidence/verdict shape, same regex-based syscall parsing) -- filesystem
isolation and network denial are already enforced by the container
itself, strace only needs to notice an attempt.

Real, confirmed-directly detail worth documenting: the .NET SDK performs
its own workload-manifest verification on a process's first `dotnet`
invocation against a given $HOME (visible as repeated failed
connect()s to port 53 -- a DNS lookup attempt -- and, on stderr, "An
issue was encountered verifying workloads"). This is genuinely
independent of the NuGetAudit feature below: confirmed directly it is
NOT disabled by `-p:NuGetAudit=false` alone, nor by the
`DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE` or
`DOTNET_SKIP_WORKLOAD_INTEGRITY_CHECK` environment variables (the
latter silences the stderr message but not the underlying connect()
attempts -- tried both directly against a real container). What does
work, confirmed directly: this check only fires on a $HOME's *first*
`dotnet` invocation in a fresh environment, not on subsequent ones. So
`main()` below runs a first, deliberately un-straced `dotnet restore`
before the straced `dotnet build --no-restore` -- safe because Stage
2 already proved restore alone never executes a package's own code,
so moving it off-camera doesn't weaken tracing, and it absorbs both
this one-time SDK noise and the (also real, separately confirmed)
NuGetAudit network attempt documented below, before the traced build
ever starts.

Prints the same DEPSHIELDX_SANDBOX_REPORT=<json> line sandbox.py's
_extract_report() already expects, with the same key shape cli/output.py's
summary formatter reads. "imported_modules"/"skipped_modules" have no
NuGet analogue (unlike Go, every resolved package is unconditionally on
the compile classpath, no per-artifact buildability distinction) and stay
empty.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPORT_PREFIX = "DEPSHIELDX_SANDBOX_REPORT="
STRACE_LOG_PATH = "/tmp/depshieldx-strace.log"
WORK_DIR = Path("/tmp/depshieldx-nuget-work")
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
    # The bundle directory (flat .nupkg/scratch.csproj/NuGet.Config) is
    # bind-mounted read-only -- any write attempt against it necessarily
    # fails at the OS level (same as the other ecosystems' blocked
    # writes/connects), but a real attempt is still meaningful evidence
    # of a build-time hook trying to tamper with its own already
    # checksum-verified source.
    if normalized.startswith(BUNDLE_MOUNT_PREFIX):
        return "bundle_source_tamper_attempt"
    work_dir_str = str(WORK_DIR).replace("\\", "/")
    if normalized.startswith(f"{work_dir_str}/scratch/bin") or normalized.startswith(f"{work_dir_str}/scratch/obj"):
        return "build_output"
    if normalized.startswith(work_dir_str):
        return "project_files"
    return "other"


def _is_remote_connect(args_text: str) -> bool:
    return bool(AF_INET_PATTERN.search(args_text))


def _write_probe_source() -> None:
    (WORK_DIR / "scratch" / "DepshieldxProbe.cs").write_bytes(b"public class DepshieldxProbe {}\n")


def _augment_scratch_csproj_with_probe_source(csproj_text: str) -> str:
    """Adds a <Compile Include="DepshieldxProbe.cs" /> item to the shared
    scratch .csproj text (unchanged from ecosystems/nuget/ecosystem.py's
    own _build_scratch_csproj, which Stage 1/2 don't need a real source
    file for) -- simple text insertion rather than touching that shared
    function, the same "wrapper adds what it specifically needs, shared
    artifact-builder stays stage-agnostic" split sandbox_wrapper_maven.py
    uses for its own DepshieldxProbe.java."""
    probe_item_group = '  <ItemGroup>\n    <Compile Include="DepshieldxProbe.cs" />\n  </ItemGroup>\n'
    return csproj_text.replace("</Project>", probe_item_group + "</Project>")


def _run_offline_restore(env: dict) -> subprocess.CompletedProcess:
    """Deliberately un-straced: absorbs the .NET SDK's first-invocation
    workload-manifest check and the NuGetAudit network attempt (both
    documented in the module docstring) before tracing starts. Safe
    because Stage 2 already proved `dotnet restore` alone never executes
    a package's own code -- there is nothing here worth tracing."""
    restore_args = ["dotnet", "restore", "-p:NuGetAudit=false"]
    return subprocess.run(restore_args, cwd=str(WORK_DIR / "scratch"), env=env, capture_output=True, text=True)


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
        "dotnet",
        "build",
        # Restore already ran (un-straced, see _run_offline_restore) --
        # confirmed directly this doesn't skip build/*.targets import
        # and evaluation, only the separate Restore MSBuild target.
        "--no-restore",
        # Keeps the build's process tree fully self-contained in this
        # one-shot sandboxed context -- confirmed directly neither flag
        # explains the temp-file Exec-task indirection documented in the
        # module docstring, but both are still good practice here: no
        # lingering background compiler-server/build-node process to
        # reason about once this one straced invocation exits.
        "-p:UseSharedCompilation=false",
        "/nodeReuse:false",
        # Disables the .NET SDK's own built-in NuGet vulnerability-audit
        # feature (confirmed directly: without this, restore attempts a
        # real AF_INET connect to api.nuget.org's vulnerabilities index).
        # Redundant with --no-restore in principle, kept for defense in
        # depth since it's free.
        "-p:NuGetAudit=false",
    ]
    return subprocess.run(strace_args, cwd=str(WORK_DIR / "scratch"), env=env, capture_output=True, text=True)


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
                "message": "The build spawned subprocesses (the C# compiler, a package's own build-time MSBuild targets) during sandboxed compilation.",
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
    scratch_dir = WORK_DIR / "scratch"
    scratch_dir.mkdir(parents=True, exist_ok=True)

    csproj_text = (bundle_dir / "scratch.csproj").read_text(encoding="utf-8")
    (scratch_dir / "scratch.csproj").write_text(
        _augment_scratch_csproj_with_probe_source(csproj_text), encoding="utf-8"
    )
    (WORK_DIR / "NuGet.Config").write_bytes((bundle_dir / "NuGet.Config").read_bytes())
    _write_probe_source()

    env = dict(os.environ)
    # $HOME/.nuget/packages is NuGet's real default global packages
    # folder -- pointing HOME at this script's own writable work
    # directory keeps that cache guaranteed-empty (proving the offline
    # build isn't silently succeeding from stale cache) and writable
    # (confirmed directly the default HOME under SANDBOX_USER has
    # nothing writable to extract packages into otherwise).
    env["HOME"] = str(WORK_DIR)
    return env


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: sandbox_wrapper_nuget.py <bundle_dir> [<PackageId@version>...]", file=sys.stderr)
        return 2

    bundle_dir = Path(sys.argv[1])
    install_targets = sys.argv[2:]

    env = _prepare_work_env(bundle_dir)

    _run_offline_restore(env)
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
