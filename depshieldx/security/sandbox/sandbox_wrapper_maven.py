"""Runs inside the Docker sandbox container for Maven deep-mode installs --
the Maven counterpart to sandbox_wrapper.py/sandbox_wrapper_npm.js/
sandbox_wrapper_cargo.py/sandbox_wrapper_go.py.

Stage 2 (fetch-only): proved the resolved coordinate set can be fetched
entirely offline against a pre-vendored local Maven repository, using
Maven's own `-Dmaven.repo.local` override.

Stage 3 (this file, current version): adds real behavioral tracing around
an actual `mvn compile`, not just `dependency:resolve`. Confirmed
directly this is the right (and, for plain library dependencies, the
*only*) place code can run: unlike cargo's build.rs (always runs for
every crate) or Go's init()/go:generate (run for every buildable
package), a jar consumed as a normal Maven <dependency> has no universal
"executes automatically" hook at all -- merely being resolved or even
sitting on the compile classpath runs none of its own code, confirmed
directly (Stage 2's dependency:resolve proves fetch-only). The one real,
confirmed-directly exception: a jar that registers itself via
`META-INF/services/javax.annotation.processing.Processor` (Lombok,
MapStruct, Dagger, AutoValue, ...) gets its processor auto-discovered and
invoked by javac's annotation-processing machinery during *any* compile
it's present for -- verified directly with `javac -XprintRounds` against
a real Lombok jar and a source file using zero Lombok annotations: "Note:
Annotation processing is enabled because one or more processors were
found on the class path" and multiple real processing rounds ran. So a
trivial scratch source file (no import of, or reference to, any resolved
coordinate needed) with every resolved coordinate on the compile
classpath is enough to exercise this real surface -- for the (large)
majority of ordinary library dependencies that register no processor,
this traces genuinely zero activity, an accurate "nothing executes here"
verdict, not a coverage gap to apologize for.

Ports sandbox_wrapper_cargo.py/sandbox_wrapper_go.py's strace-log-parsing
approach (regex-based SYSCALL_LINE parsing into the same evidence/verdict
shape) rather than a from-scratch design -- this doesn't *block*
individual syscalls in real time, filesystem isolation and network denial
are already enforced by the container itself (--read-only rootfs,
--network none, plus the read-only bundle-directory bind mount), so a
malicious annotation processor's writes/connects fail at the OS level
regardless; strace's job is to notice that it tried.

Real, Maven-specific problem cargo/go's sandboxes don't have: both
`dependency:resolve` and `compile` are themselves Maven *plugin* goals,
and just loading a project descriptor makes Maven resolve its full
default-lifecycle plugin set -- confirmed directly a real `compile` needs
~71 plugin/dependency jars (not just Stage 2's ~51) from a clean local
repository before it can do anything. maven_sandbox.Dockerfile's current
version pre-warms exactly that closure (via a real `compile`, not just
`dependency:resolve`) into a world-readable, build-time local repository.
`-Dmaven.repo.local` only accepts one path, and pointing it at a
read-only directory doesn't work either way (Maven writes small
bookkeeping files into whatever local repo path it's given, confirmed
directly this fails against a real read-only bind mount), so this script
still copies both the pre-warmed plugin cache and the host-provided,
per-run project coordinates into one merged, writable local repository
under its own tmpfs work directory before running `mvn --offline compile`
against it, same as Stage 2.

Parent POM chains and BOM imports: prepare_maven_download_bundle()
already walked and fetched these host-side (see that function's
docstring) -- nothing extra to do here.

Prints the same DEPSHIELDX_SANDBOX_REPORT=<json> line sandbox.py's
_extract_report() already expects, with the same key shape cli/output.py's
summary formatter reads (write_count, syscall_counts, allowed_subprocesses,
imported_modules, import_failures, skipped_imports, blocked_events,
verdicts), so downstream report rendering works unchanged across all four
ecosystems. "imported_modules"/"skipped_modules" have no Maven analogue
(unlike Go, there's no per-artifact "does it have a buildable root"
distinction -- every resolved coordinate is unconditionally on the
compile classpath) and stay empty.
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
PLUGIN_CACHE_DIR = "/opt/depshieldx-maven-plugin-cache"
WORK_DIR = Path("/tmp/depshieldx-maven-work")
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
    # The bundle directory (m2-repo/pom.xml) is bind-mounted read-only --
    # any write attempt against it necessarily fails at the OS level
    # (same as cargo's/go's blocked writes/connects), but a real attempt
    # is still meaningful evidence of an annotation processor trying to
    # tamper with its own already checksum-verified source.
    if normalized.startswith(BUNDLE_MOUNT_PREFIX):
        return "bundle_source_tamper_attempt"
    work_dir_str = str(WORK_DIR).replace("\\", "/")
    if normalized.startswith(f"{work_dir_str}/m2-repo"):
        return "build_output"
    if normalized.startswith(work_dir_str):
        return "project_files"
    return "other"


def _is_remote_connect(args_text: str) -> bool:
    return bool(AF_INET_PATTERN.search(args_text))


def _run_straced_compile(env: dict) -> subprocess.CompletedProcess:
    strace_args = [
        "strace",
        "-f",
        "-s",
        "200",
        "-e",
        "trace=file,process,network",
        "-o",
        STRACE_LOG_PATH,
        "mvn",
        "-B",
        "--offline",
        f"-Dmaven.repo.local={WORK_DIR / 'm2-repo'}",
        "-f",
        str(WORK_DIR / "pom.xml"),
        "compile",
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


def _build_verdicts(evidence: dict, compile_exit_code: int) -> list[dict]:
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

    if compile_exit_code != 0 and not evidence["blocked_events"]:
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
                "message": "The build spawned subprocesses (the Java compiler, an annotation processor) during sandboxed compilation.",
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
    local_repo = WORK_DIR / "m2-repo"
    # copytree, not a bind mount or symlink: both the plugin cache and the
    # host-provided bundle need to end up looking like ONE local
    # repository to Maven, and `-Dmaven.repo.local` only accepts a single
    # path -- confirmed directly there's no supported way to layer two
    # local-repository directories for one Maven invocation.
    shutil.copytree(PLUGIN_CACHE_DIR, local_repo)
    shutil.copytree(bundle_dir / "m2-repo", local_repo, dirs_exist_ok=True)
    shutil.copy2(bundle_dir / "pom.xml", WORK_DIR / "pom.xml")

    # Trivial scratch source file -- deliberately imports/references
    # nothing from the resolved coordinates (confirmed directly this
    # isn't needed: an annotation processor registered via META-INF/
    # services on the compile classpath is auto-discovered and invoked
    # by javac regardless of whether the compiled source uses its target
    # annotations at all, see module docstring).
    src_dir = WORK_DIR / "src" / "main" / "java"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "DepshieldxProbe.java").write_bytes(b"public class DepshieldxProbe {}\n")

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
    return env


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: sandbox_wrapper_maven.py <bundle_dir> [<groupId:artifactId@version>...]", file=sys.stderr)
        return 2

    bundle_dir = Path(sys.argv[1])
    install_targets = sys.argv[2:]

    env = _prepare_work_env(bundle_dir)

    result = _run_straced_compile(env)
    compile_exit_code = result.returncode

    evidence = _parse_strace_log(STRACE_LOG_PATH)
    verdicts = _build_verdicts(evidence, compile_exit_code)
    suspicious = compile_exit_code != 0 or any(v["severity"] == "high" for v in verdicts)

    report = {
        "download_exit_code": compile_exit_code,
        "build_exit_code": compile_exit_code,
        "suspicious": suspicious,
        "vendored_targets": install_targets,
        "build_stdout_tail": result.stdout[-2000:] if compile_exit_code != 0 else "",
        "build_stderr_tail": result.stderr[-2000:] if compile_exit_code != 0 else "",
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
