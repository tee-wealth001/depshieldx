"""Runs inside the Docker sandbox container for RubyGems deep-mode
installs -- the RubyGems counterpart to sandbox_wrapper_pub.py/
sandbox_wrapper_nuget.py/sandbox_wrapper_maven.py/sandbox_wrapper_go.py/
sandbox_wrapper_cargo.py/sandbox_wrapper_npm.js.

Stage 2 (fetch-only): proved the resolved gem set could be installed
entirely offline against a pre-built local vendor/cache.

Stage 3 (this file, current version): adds real behavioral tracing
around the SAME `bundle install --local` Stage 2 already ran. Unlike
every other ecosystem's own Stage 3 here, RubyGems' real code-execution
surface (a native-extension gem's own extconf.rb) is triggered by
*installation itself*, not a separate later "run"/"build" step -- so
there's no clean split between "install, unstraced" and "run/build,
straced" the way Pub's pub-get-then-dart-run or NuGet's restore-then-
build splits have (confirmed directly, see rubygems_sandbox.
Dockerfile's module docstring: `bundle install` IS the code-execution
surface). The whole install is straced directly instead, the same
single-straced-command structure sandbox_wrapper_cargo.py/
sandbox_wrapper_go.py already use (neither has a network-noise-avoidance
reason to split either).

Real, confirmed-directly finding: unlike NuGet's own Stage 3 (a real
.NET SDK workload-manifest network check that had to be isolated into a
separate unstraced restore step to avoid a false-positive network-block
verdict), a real straced `bundle install --local` against a native-
extension gem (json) made zero connect() attempts of any kind under this
project's full isolation posture -- no analogous toolchain-level
telemetry/verification noise to work around here.

A separate, later-discovered edge case (also confirmed directly): that
zero-network-attempts finding depended on the lockfile's own PLATFORMS
section already matching the container's real running platform. A
lockfile listing only write_gemfile_lock's own placeholder "ruby"
platform is NOT accepted by this Bundler version as equivalent to an
exact match -- `bundle install --local` decides the lockfile is missing
the current platform and triggers a real re-resolve against the
registry, which this sandbox's own --network none isolation then
blocks, producing a real (if misleading) network_attempt_blocked
verdict for a completely benign install. _pin_lockfile_to_current_
platform below (called from _prepare_work_env) is the fix: it rewrites
PLATFORMS to the real Gem::Platform.local queried fresh from inside
this exact container before `bundle install --local` ever runs.

Also confirmed directly this produces a real, large, legitimate
subprocess tree for a native-extension gem -- ruby -> gcc -> cc1/as/
collect2/ld, plus make -- none of which is itself suspicious (this is
exactly what a successful, non-malicious native-extension build looks
like); only an *unexpected* write outside the sandboxed work directory
or a real network attempt is escalated, the same "syscall activity is
evidence, isolation already enforces the policy" split every other
ecosystem's wrapper here already uses. Confirmed directly with a hand-
built malicious extconf.rb (one that writes into the read-only bundle
mount and attempts a real outbound TCP connect) that both are correctly
traced and flagged by this wrapper's own _classify_write_path/
_is_remote_connect machinery.

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
WORK_DIR = Path("/tmp/depshieldx-rubygems-work")
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
    # The bundle directory (flat .gem/Gemfile/Gemfile.lock/vendor-cache)
    # is bind-mounted read-only -- any write attempt against it
    # necessarily fails at the OS level (same as the other ecosystems'
    # blocked writes/connects), but a real attempt is still meaningful
    # evidence of a build script trying to tamper with its own already
    # checksum-verified source.
    if normalized.startswith(BUNDLE_MOUNT_PREFIX):
        return "bundle_source_tamper_attempt"
    work_dir_str = str(WORK_DIR).replace("\\", "/")
    # Native-extension compilation output and unpacked gem contents both
    # land under gem_home/bundle_path -- confirmed directly against a
    # real straced `bundle install --local` run against a native-
    # extension gem.
    if normalized.startswith(f"{work_dir_str}/gem_home") or normalized.startswith(f"{work_dir_str}/bundle_path"):
        return "build_output"
    if normalized.startswith(work_dir_str):
        return "project_files"
    return "other"


def _is_remote_connect(args_text: str) -> bool:
    return bool(AF_INET_PATTERN.search(args_text))


def _current_gem_platform() -> str:
    """The exact platform string `bundle install` itself requires the
    lockfile's own PLATFORMS section to already list -- confirmed
    directly against this real image that a lockfile listing only the
    generic "ruby" placeholder (write_gemfile_lock's own emitted value)
    does NOT satisfy Bundler's "lockfile has the current platform"
    check, since Gem::Platform.local here is "x86_64-linux", never
    literally "ruby". That mismatch sends `bundle install --local` down
    a real re-resolve path that reaches out to the registry over the
    network -- exactly what this sandbox's own --network none isolation
    then blocks, surfacing as a misleading "suspicious network attempt"
    verdict for a completely benign install. Queried fresh from inside
    this exact container rather than guessed/hardcoded host-side, so it
    stays correct regardless of the sandbox image's own architecture."""
    result = subprocess.run(
        ["ruby", "-e", "puts Gem::Platform.local.to_s"],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _pin_lockfile_to_current_platform(lockfile_path: Path) -> None:
    """Replaces write_gemfile_lock's own placeholder "PLATFORMS: ruby"
    with the real current platform (see _current_gem_platform) --
    confirmed directly end to end this matches what a genuine `bundle
    lock` run itself produces (PLATFORMS listing only the specific
    current platform, never "ruby" alongside it) and is what a real
    `bundle install --local` run needs to skip the network re-resolve
    entirely; confirmed directly that *adding* the specific platform
    alongside "ruby" instead of replacing it breaks local gem lookup
    with Bundler::GemNotFound. Every resolved spec entry itself is left
    untouched -- depshieldx never resolves a platform-specific gem
    variant to begin with (see lockfiles.py's own module docstring), so
    a plain, unsuffixed spec entry is already correct for any platform.
    Only this container-local copy is rewritten, never the host-side
    bundle directory (mounted read-only, and irrelevant to Trivy's own
    scan, which only reads gem name/version pairs)."""
    text = lockfile_path.read_text(encoding="utf-8")
    text = text.replace("PLATFORMS\n  ruby\n", f"PLATFORMS\n  {_current_gem_platform()}\n")
    lockfile_path.write_text(text, encoding="utf-8")


def _prepare_work_env(bundle_dir: Path) -> dict:
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copytree(bundle_dir / "vendor", WORK_DIR / "vendor")
    shutil.copy2(bundle_dir / "Gemfile", WORK_DIR / "Gemfile")
    shutil.copy2(bundle_dir / "Gemfile.lock", WORK_DIR / "Gemfile.lock")
    _pin_lockfile_to_current_platform(WORK_DIR / "Gemfile.lock")

    env = dict(os.environ)
    # $HOME needs to be writable too -- SANDBOX_USER's real default HOME
    # has nothing writable in it (confirmed directly the same way every
    # other ecosystem's own wrapper here already documents for its own
    # toolchain).
    env["HOME"] = str(WORK_DIR)
    env["GEM_HOME"] = str(WORK_DIR / "gem_home")
    env["BUNDLE_PATH"] = str(WORK_DIR / "bundle_path")
    return env


def _run_straced_install(env: dict) -> subprocess.CompletedProcess:
    strace_args = [
        "strace",
        "-f",
        "-s",
        "200",
        "-e",
        "trace=file,process,network",
        "-o",
        STRACE_LOG_PATH,
        "bundle",
        "install",
        "--local",
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
                "message": "Package attempted network access during sandboxed install.",
            }
        )

    tamper_blocks = [e for e in evidence["blocked_events"] if e["category"] == "bundle_tamper_denied"]
    if tamper_blocks:
        verdicts.append(
            {
                "severity": "high",
                "code": "bundle_source_tamper_attempted",
                "message": "Package attempted to write into its own read-only bundle directory during sandboxed install.",
            }
        )

    # A native-extension build failing (missing dev headers, an
    # unrelated compiler quirk, ...) is common and not itself suspicious
    # -- real builds fail offline for benign reasons too. Only a real,
    # observed policy block is escalated. Mirrors every other
    # ecosystem's own "info, not high" treatment for a plain build
    # failure (see sandbox_wrapper_pub.py's own identical reasoning).
    if build_exit_code != 0 and not evidence["blocked_events"]:
        verdicts.append(
            {
                "severity": "info",
                "code": "install_failed",
                "message": "The sandboxed `bundle install` did not complete successfully, without triggering an explicit policy block.",
            }
        )

    if evidence["syscall_counts"]["process_exec"] > 0:
        verdicts.append(
            {
                "severity": "info",
                "code": "subprocess_execs_traced",
                "message": "The install spawned subprocesses (a gem's own native-extension build, or similar) during sandboxed execution.",
            }
        )

    if evidence["syscall_counts"]["filesystem_mutation"] > 0:
        verdicts.append(
            {
                "severity": "info",
                "code": "filesystem_mutations_traced",
                "message": "Low-level filesystem mutation calls were traced during the sandboxed install.",
            }
        )

    return verdicts


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: sandbox_wrapper_rubygems.py <bundle_dir> [<gem_name@version>...]", file=sys.stderr)
        return 2

    bundle_dir = Path(sys.argv[1])
    install_targets = sys.argv[2:]

    env = _prepare_work_env(bundle_dir)
    result = _run_straced_install(env)
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
