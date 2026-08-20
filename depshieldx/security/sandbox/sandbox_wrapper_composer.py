"""Runs inside the Docker sandbox container for Composer deep-mode
installs -- the Composer counterpart to sandbox_wrapper_nuget.py/
sandbox_wrapper_maven.py/sandbox_wrapper_rubygems.py.

Stage 2 (fetch-only): proved the resolved package set can be installed
entirely offline against a pre-fetched, checksum-verified local package
source, using Composer's own real "artifact" repository mechanism.

Stage 3 (this file, current version): adds real behavioral tracing
around a deliberately trivial PHP probe script, not just `composer
install`. Confirmed directly this is the right place code can run:
`composer install --no-plugins --no-scripts` (Stage 2's own posture,
unchanged here) never executes a dependency's own code at all --
verified directly with a real, hand-built test plugin package (Composer
2.2+ blocks any package containing a Composer plugin by default unless
explicitly allow-listed in the ROOT project's own config.allow-plugins,
confirmed via a real PluginBlockedException; depshieldx's own scratch
project never allow-lists anything, so this surface never activates in
depshieldx's real flow, unlike every other ecosystem here it is not
traced). Composer's own script hooks are root-project-only by design
(a dependency's own "scripts" section is never executed automatically,
confirmed against real Composer docs and this project's own Stage 1
research) -- so unlike NuGet's build/*.targets or Maven's annotation
processors, neither of Composer's two per-project opt-in mechanisms is
depshieldx's own real, always-on risk surface.

The real, always-on, non-opt-in surface -- confirmed directly with a
real, hand-built test dependency package (no plugin, no scripts, just a
plain composer.json declaring `"autoload": {"files": ["bootstrap.php"]}`,
the same real, documented technique already cited in real PHP supply-
chain-attack writeups): `composer install` alone does NOT execute a
"files" autoload entry (confirmed directly: no output file materializes
until later), but the *moment* anything actually `require`s the
generated vendor/autoload.php -- even with zero explicit reference to
the dependency's own classes or functions at all -- every installed
package's own "files" autoload entries run unconditionally. This is
genuinely different from PSR-4 class autoloading (confirmed directly:
lazy, only loads a class that's actually referenced), and is Composer's
own precise analogue to NuGet's "needs a real `dotnet build`, not just
`dotnet restore`"/Go's "needs `go build`, not `go mod download`" finding
-- just booting the autoloader, with nothing else, is enough.

A trivial scratch probe script (DepshieldxProbe.php, containing nothing
but `require __DIR__.'/vendor/autoload.php';`) is enough to trigger
every resolved package's own "files" autoload entries regardless of
whether anything actually uses the package's classes -- confirmed
directly, the same "presence on the load path alone is enough" pattern
already confirmed for Maven's annotation processors and NuGet's build
targets.

`composer install` itself stays un-straced here (Stage 2 already proved
it never executes dependency code, the same reasoning sandbox_wrapper_
nuget.py's own first, un-straced `dotnet restore` call uses) -- only the
later probe script actually loading the autoloader is straced.

Ports sandbox_wrapper_nuget.py's/sandbox_wrapper_maven.py's strace-log-
parsing approach unchanged (same evidence/verdict shape, same regex-
based syscall parsing) -- filesystem isolation and network denial are
already enforced by the container itself, strace only needs to notice
an attempt.

Prints the same DEPSHIELDX_SANDBOX_REPORT=<json> line sandbox.py's
_extract_report() already expects, with the same key shape cli/output.py's
summary formatter reads. "imported_modules"/"skipped_modules" have no
Composer analogue (unlike Go, there's no per-artifact buildability
distinction here) and stay empty.
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
WORK_DIR = Path("/tmp/depshieldx-composer-work")
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
    # The bundle directory (flat .zip/composer.json/composer.lock/
    # artifacts/) is bind-mounted read-only -- any write attempt against
    # it necessarily fails at the OS level (same as the other
    # ecosystems' blocked writes/connects), but a real attempt is still
    # meaningful evidence of a "files" autoload hook trying to tamper
    # with its own already checksum-verified source.
    if normalized.startswith(BUNDLE_MOUNT_PREFIX):
        return "bundle_source_tamper_attempt"
    work_dir_str = str(WORK_DIR).replace("\\", "/")
    if normalized.startswith(f"{work_dir_str}/scratch/vendor"):
        return "vendor_files"
    if normalized.startswith(work_dir_str):
        return "project_files"
    return "other"


def _is_remote_connect(args_text: str) -> bool:
    return bool(AF_INET_PATTERN.search(args_text))


def _write_probe_source() -> None:
    (WORK_DIR / "scratch" / "DepshieldxProbe.php").write_text(
        "<?php\nrequire __DIR__ . '/vendor/autoload.php';\n", encoding="utf-8"
    )


def _run_offline_install(env: dict) -> subprocess.CompletedProcess:
    """Deliberately un-straced: Stage 2 already proved `composer install
    --no-plugins --no-scripts` alone never executes a dependency's own
    code (see module docstring) -- there is nothing here worth tracing,
    the same reasoning sandbox_wrapper_nuget.py's own first, un-straced
    `dotnet restore` call uses."""
    install_args = ["composer", "install", "--no-interaction", "--no-plugins", "--no-scripts"]
    return subprocess.run(install_args, cwd=str(WORK_DIR / "scratch"), env=env, capture_output=True, text=True)


def _run_straced_probe(env: dict) -> subprocess.CompletedProcess:
    strace_args = [
        "strace",
        "-f",
        "-s",
        "200",
        "-e",
        "trace=file,process,network",
        "-o",
        STRACE_LOG_PATH,
        "php",
        "DepshieldxProbe.php",
    ]
    return subprocess.run(strace_args, cwd=str(WORK_DIR / "scratch"), env=env, capture_output=True, text=True)


def _parse_strace_log(log_path: str) -> dict:
    evidence = {
        "write_count": 0,
        "write_samples": [],
        "write_buckets": {
            "project_files": 0,
            "vendor_files": 0,
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


def _build_verdicts(evidence: dict, probe_exit_code: int) -> list[dict]:
    verdicts = []

    network_blocks = [e for e in evidence["blocked_events"] if e["category"] == "network_denied"]
    if network_blocks:
        verdicts.append(
            {
                "severity": "high",
                "code": "network_attempt_blocked",
                "message": "Package attempted network access when the autoloader was loaded.",
            }
        )

    tamper_blocks = [e for e in evidence["blocked_events"] if e["category"] == "bundle_tamper_denied"]
    if tamper_blocks:
        verdicts.append(
            {
                "severity": "high",
                "code": "bundle_source_tamper_attempted",
                "message": "Package attempted to write into its own read-only bundle directory when the autoloader was loaded.",
            }
        )

    if probe_exit_code != 0 and not evidence["blocked_events"]:
        verdicts.append(
            {
                "severity": "medium",
                "code": "autoload_probe_failed",
                "message": "Loading the generated autoloader failed without triggering an explicit policy block.",
            }
        )

    if evidence["syscall_counts"]["process_exec"] > 0:
        verdicts.append(
            {
                "severity": "info",
                "code": "subprocess_execs_traced",
                "message": "A package's own \"files\" autoload entry spawned subprocesses when the autoloader was loaded.",
            }
        )

    if evidence["syscall_counts"]["filesystem_mutation"] > 0:
        verdicts.append(
            {
                "severity": "info",
                "code": "filesystem_mutations_traced",
                "message": "Low-level filesystem mutation calls were traced while loading the autoloader.",
            }
        )

    return verdicts


def _prepare_work_env(bundle_dir: Path) -> dict:
    scratch_dir = WORK_DIR / "scratch"
    scratch_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(bundle_dir / "composer.json", scratch_dir / "composer.json")
    shutil.copytree(bundle_dir / "artifacts", scratch_dir / "artifacts")
    _write_probe_source()

    env = dict(os.environ)
    # $HOME/.composer (Linux default) is Composer's own real cache/config
    # root -- pointing HOME at this script's own writable work directory
    # keeps that cache guaranteed-empty (proving the offline install
    # isn't silently succeeding from stale cache) and writable (confirmed
    # directly the default HOME under SANDBOX_USER has nothing writable
    # to extract packages into otherwise).
    env["HOME"] = str(WORK_DIR)
    return env


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: sandbox_wrapper_composer.py <bundle_dir> [<vendor/package@version>...]", file=sys.stderr)
        return 2

    bundle_dir = Path(sys.argv[1])
    install_targets = sys.argv[2:]

    env = _prepare_work_env(bundle_dir)

    install_result = _run_offline_install(env)
    if install_result.returncode != 0:
        # Installation itself failing (e.g. an unresolvable requirement)
        # is a real, meaningful outcome on its own -- report it directly
        # rather than tracing a probe against a vendor/ directory that
        # was never actually populated.
        report = {
            "download_exit_code": install_result.returncode,
            "suspicious": True,
            "vendored_targets": install_targets,
            "download_stdout_tail": install_result.stdout[-2000:],
            "download_stderr_tail": install_result.stderr[-2000:],
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
        return 1

    probe_result = _run_straced_probe(env)
    probe_exit_code = probe_result.returncode

    evidence = _parse_strace_log(STRACE_LOG_PATH)
    verdicts = _build_verdicts(evidence, probe_exit_code)
    suspicious = probe_exit_code != 0 or any(v["severity"] == "high" for v in verdicts)

    report = {
        "download_exit_code": probe_exit_code,
        "build_exit_code": probe_exit_code,
        "suspicious": suspicious,
        "vendored_targets": install_targets,
        "build_stdout_tail": probe_result.stdout[-2000:] if suspicious else "",
        "build_stderr_tail": probe_result.stderr[-2000:] if suspicious else "",
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
