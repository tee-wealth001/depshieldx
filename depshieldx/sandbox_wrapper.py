import builtins
import csv
import importlib
import json
import os
import socket
import subprocess
import sys
import tempfile
from functools import wraps
from pathlib import Path


REPORT_PREFIX = "DEPSHIELDX_SANDBOX_REPORT="
ALLOWED_WRITE_PREFIXES = (
    "/tmp/site-packages",
    "/tmp/pip-target-",
    "/tmp/pip-ephem-wheel-cache-",
    "/tmp/pip-build-tracker-",
    "/tmp/pip-install-",
    "/tmp/pip-unpack-",
    "/tmp/pip-metadata-",
    "/tmp/pip-modern-metadata-",
    "/tmp/pip-wheel-",
    "/tmp/tmp",
)
TEMP_ROOT_PREFIXES = (
    "/tmp",
    "/var/tmp",
    "/usr/tmp",
)
ALLOWED_DEVICE_WRITE_PATHS = {
    "/dev/null",
    # os.path.abspath(os.devnull) on Windows -- the platform's equivalent of /dev/null, needed
    # for the same subprocess.DEVNULL piping pattern (e.g. CPython <3.12's platform.win32_ver()
    # opens it for stdin/stderr when shelling out to "ver").
    "\\\\.\\nul",
}
SUSPICIOUS_AUDIT_EVENTS = {
    "subprocess.Popen",
    "socket.connect",
    "socket.getaddrinfo",
    "os.mkdir",
    "os.remove",
    "os.rename",
    "os.replace",
    "os.rmdir",
    "os.symlink",
    "os.link",
    "os.chmod",
    "os.system",
    "os.exec",
    "os.spawnv",
    "os.spawnve",
}
ALLOWED_SUBPROCESS_PREFIXES = {
    ("lsb_release", "-a"),
    ("uname", "-rs"),
    ("uname", "-m"),
    # pip itself probes for a Rust toolchain unconditionally at the start of every install
    # (observed on every OS, before any package-specific processing begins), independent of
    # whether the package being installed actually needs one.
    ("rustc", "--version"),
    # CPython <3.12's platform.win32_ver() shells out to "ver" (via `shell=True`, so Popen sees
    # the bare string) to read the Windows version for pip's truststore SSL setup. Blocking it
    # doesn't just get flagged like the rustc probe above -- it crashes pip's SSL context setup
    # outright on Windows + Python <3.12. CPython 3.12+ no longer uses this subprocess path.
    ("ver",),
}
WRITE_BUCKET_KEYS = (
    "package_files",
    "metadata_files",
    "entrypoint_scripts",
    "native_extensions",
    "other",
)
SYSCALL_BUCKET_KEYS = (
    "filesystem_mutation",
    "process_exec",
    "network",
)
ENVIRONMENTAL_IMPORT_ERROR_INDICATORS = (
    "failed to map segment from shared object",
    "cannot map segment from shared object",
)


def _path_variants(path):
    normalized = os.path.normpath(path).replace("\\", "/")
    resolved = os.path.realpath(path).replace("\\", "/")
    return {normalized.rstrip("/"), resolved.rstrip("/")}


SYSTEM_TEMP_ROOT_PREFIXES = tuple(
    sorted(
        {
            variant
            for candidate in (*TEMP_ROOT_PREFIXES, tempfile.gettempdir())
            for variant in _path_variants(candidate)
        }
    )
)
ALLOWED_TEMP_WRITE_SEGMENTS = tuple(
    prefix[len("/tmp/"):]
    for prefix in ALLOWED_WRITE_PREFIXES
    if prefix.startswith("/tmp/")
)
ALLOWED_WRITE_PREFIX_VARIANTS = tuple(
    sorted(
        {
            variant
            for candidate in (
                *ALLOWED_WRITE_PREFIXES,
                *(
                    os.path.join(root, segment)
                    for root in SYSTEM_TEMP_ROOT_PREFIXES
                    for segment in ALLOWED_TEMP_WRITE_SEGMENTS
                ),
            )
            for variant in _path_variants(candidate)
        }
    )
)


def _json_safe(value):
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(val) for key, val in value.items()}
    return repr(value)


def _normalize_command(command):
    if isinstance(command, (list, tuple)):
        return tuple(str(part) for part in command)
    if isinstance(command, str):
        return tuple(command.split())
    return (repr(command),)


def _classify_write_path(path):
    normalized = path.replace("\\", "/")
    if "/.dist-info/" in normalized:
        return "metadata_files"
    if "/bin/" in normalized:
        return "entrypoint_scripts"
    if normalized.endswith((".so", ".pyd", ".dylib")):
        return "native_extensions"
    if "/lib/python/" in normalized:
        return "package_files"
    return "other"


def _normalize_distribution_name(name):
    return name.strip().lower().replace("-", "_")


def _is_environmental_import_failure(detail) -> bool:
    if not isinstance(detail, dict):
        return False
    message = str(detail.get("message") or "").lower()
    return any(indicator in message for indicator in ENVIRONMENTAL_IMPORT_ERROR_INDICATORS)


def _is_allowed_write_path(path):
    if path in ALLOWED_DEVICE_WRITE_PATHS:
        return True
    variants = _path_variants(path)
    if any(
        variant.startswith(prefix)
        for variant in variants
        for prefix in ALLOWED_WRITE_PREFIX_VARIANTS
    ):
        return True

    parents = {os.path.dirname(variant) for variant in variants}
    return any(parent in SYSTEM_TEMP_ROOT_PREFIXES for parent in parents)


def _extract_path_arguments(args, kwargs):
    dir_fd = kwargs.get("dir_fd")
    base_dir = None
    if isinstance(dir_fd, int):
        try:
            base_dir = os.path.realpath(f"/dev/fd/{dir_fd}")
            if base_dir.startswith("/dev/fd/"):
                base_dir = None
        except OSError:
            base_dir = None

    values = []
    for key, value in list(enumerate(args)) + list(kwargs.items()):
        if key == "dir_fd":
            continue
        try:
            raw_path = os.fspath(value)
        except TypeError:
            continue
        if os.path.isabs(raw_path):
            path = os.path.abspath(raw_path)
        elif isinstance(dir_fd, int) and not base_dir:
            continue
        elif not base_dir:
            path = os.path.abspath(raw_path)
        else:
            path = os.path.abspath(os.path.join(base_dir, raw_path))
        values.append(path)
    return values


def _os_open_is_write(flags):
    write_flags = (
        os.O_WRONLY,
        os.O_RDWR,
        os.O_APPEND,
        os.O_CREAT,
        os.O_TRUNC,
    )
    return any(flags & flag for flag in write_flags)


def _audit_category(event):
    if event.startswith("socket."):
        return "network"
    if event.startswith("subprocess.") or event.startswith("os.exec") or event.startswith("os.spawn"):
        return "process_exec"
    if event.startswith("os.") and event not in {"os.system", "os.exec", "os.spawnv", "os.spawnve"}:
        return "filesystem_mutation"
    return "other"


def _discover_import_targets(site_packages_dir, requested_package):
    site_packages = Path(site_packages_dir)
    targets = []
    skipped = []
    seen = set()

    for dist_info in sorted(site_packages.glob("*.dist-info")):
        top_level = dist_info / "top_level.txt"
        record = dist_info / "RECORD"
        has_native_extensions = False

        if record.exists():
            with record.open(newline="") as record_file:
                reader = csv.reader(record_file)
                for row in reader:
                    if row and row[0].endswith((".so", ".pyd", ".dylib")):
                        has_native_extensions = True
                        break

        if not top_level.exists():
            continue

        names = []
        for line in top_level.read_text().splitlines():
            candidate = line.strip().replace("-", "_")
            if candidate.isidentifier():
                names.append(candidate)

        for name in names:
            normalized = _normalize_distribution_name(name)
            if normalized in seen:
                continue
            seen.add(normalized)
            if has_native_extensions:
                skipped.append({"module": name, "reason": "native_extension_distribution"})
            else:
                targets.append(name)

    fallback = requested_package.strip().split("[", 1)[0].split("==", 1)[0].replace("-", "_")
    if fallback.isidentifier() and _normalize_distribution_name(fallback) not in seen:
        targets.append(fallback)

    return targets, skipped


class EvidenceCollector:
    def __init__(self) -> None:
        self.events = []
        self.blocked = []
        self.write_count = 0
        self.write_samples = []
        self.allowed_subprocesses = []
        self.write_buckets = {key: 0 for key in WRITE_BUCKET_KEYS}
        self.syscall_counts = {key: 0 for key in SYSCALL_BUCKET_KEYS}
        self.syscall_samples = []
        self.imported_modules = []
        self.import_failures = []
        self.skipped_imports = []

    def add_event(self, category: str, detail) -> None:
        safe_detail = _json_safe(detail)
        if category == "write_attempt":
            self.write_count += 1
            path = safe_detail.get("path") if isinstance(safe_detail, dict) else None
            if path and path not in self.write_samples and len(self.write_samples) < 8:
                self.write_samples.append(path)
            if path:
                bucket = _classify_write_path(path)
                self.write_buckets[bucket] += 1
            return
        if category.startswith("syscall:"):
            syscall_kind = category.split(":", 1)[1]
            if syscall_kind in self.syscall_counts:
                self.syscall_counts[syscall_kind] += 1
            if len(self.syscall_samples) < 12:
                self.syscall_samples.append({"category": category, "detail": safe_detail})
            return
        if category == "subprocess_allowed":
            command = safe_detail.get("command") if isinstance(safe_detail, dict) else safe_detail
            if command not in self.allowed_subprocesses and len(self.allowed_subprocesses) < 8:
                self.allowed_subprocesses.append(command)
        if category == "import_ok":
            module = safe_detail.get("module") if isinstance(safe_detail, dict) else safe_detail
            if module not in self.imported_modules and len(self.imported_modules) < 12:
                self.imported_modules.append(module)
            return
        if category == "import_failed":
            if len(self.import_failures) < 12:
                self.import_failures.append(safe_detail)
            return
        if category == "import_skipped":
            if len(self.skipped_imports) < 12:
                self.skipped_imports.append(safe_detail)
            return
        if len(self.events) < 25:
            self.events.append({"category": category, "detail": safe_detail})

    def add_blocked(self, category: str, detail) -> None:
        self.blocked.append({"category": category, "detail": _json_safe(detail)})
        self.add_event(category, detail)

    def _build_verdicts(self, pip_exit_code: int):
        verdicts = []
        environmental_import_failures = [
            item for item in self.import_failures if _is_environmental_import_failure(item)
        ]
        risky_import_failures = [
            item for item in self.import_failures if not _is_environmental_import_failure(item)
        ]
        for blocked_event in self.blocked:
            category = blocked_event["category"]
            if category == "network_denied":
                verdicts.append(
                    {
                        "severity": "high",
                        "code": "network_attempt_blocked",
                        "message": "Package attempted network access during sandboxed install.",
                    }
                )
            elif category in {"subprocess_denied", "os_system_denied"}:
                verdicts.append(
                    {
                        "severity": "high",
                        "code": "unexpected_subprocess_blocked",
                        "message": "Package attempted to launch a subprocess during sandboxed install.",
                    }
                )
            elif category == "write_denied":
                verdicts.append(
                    {
                        "severity": "high",
                        "code": "unexpected_write_blocked",
                        "message": "Package attempted to write outside the allowed sandbox install area.",
                    }
                )
            elif category == "pip_exception":
                verdicts.append(
                    {
                        "severity": "medium",
                        "code": "pip_exception",
                        "message": "The install raised an exception under sandbox monitoring.",
                    }
                )

        if pip_exit_code != 0 and not self.blocked:
            verdicts.append(
                {
                    "severity": "medium",
                    "code": "install_failed",
                    "message": "The sandboxed install failed without triggering an explicit policy block.",
                }
            )

        if self.write_buckets["native_extensions"] > 0:
            verdicts.append(
                {
                    "severity": "info",
                    "code": "native_extensions_present",
                    "message": "The package install wrote native extension binaries inside the target environment.",
                }
            )

        if self.write_buckets["entrypoint_scripts"] > 0:
            verdicts.append(
                {
                    "severity": "info",
                    "code": "entrypoint_scripts_created",
                    "message": "The package install created executable entrypoint scripts.",
                }
            )

        if self.allowed_subprocesses:
            verdicts.append(
                {
                    "severity": "info",
                    "code": "runtime_probes_allowed",
                    "message": "Only known benign platform-detection subprocess probes were allowed.",
                }
            )

        if risky_import_failures:
            verdicts.append(
                {
                    "severity": "medium",
                    "code": "post_install_import_failures",
                    "message": "One or more post-install import checks failed inside the sandbox.",
                }
            )

        if environmental_import_failures:
            verdicts.append(
                {
                    "severity": "info",
                    "code": "post_install_import_environment_limitations",
                    "message": "One or more post-install import checks hit sandbox environment limitations.",
                }
            )

        if self.imported_modules:
            verdicts.append(
                {
                    "severity": "info",
                    "code": "post_install_import_checks_run",
                    "message": "Post-install import checks completed for discovered top-level modules.",
                }
            )

        if self.syscall_counts["filesystem_mutation"] > 0:
            verdicts.append(
                {
                    "severity": "info",
                    "code": "filesystem_mutations_traced",
                    "message": "Low-level filesystem mutation calls were traced during sandboxed install.",
                }
            )

        return verdicts

    def report(self, pip_exit_code: int) -> dict:
        verdicts = self._build_verdicts(pip_exit_code)
        suspicious = any(verdict["severity"] == "high" for verdict in verdicts)
        environmental_import_failures = [
            item for item in self.import_failures if _is_environmental_import_failure(item)
        ]
        risky_import_failures = [
            item for item in self.import_failures if not _is_environmental_import_failure(item)
        ]
        return {
            "pip_exit_code": pip_exit_code,
            "suspicious": suspicious,
            "write_count": self.write_count,
            "write_buckets": self.write_buckets,
            "write_samples": self.write_samples,
            "syscall_counts": self.syscall_counts,
            "syscall_samples": self.syscall_samples,
            "allowed_subprocesses": self.allowed_subprocesses,
            "imported_modules": self.imported_modules,
            "import_failures": self.import_failures,
            "risky_import_failures": risky_import_failures,
            "environmental_import_failures": environmental_import_failures,
            "skipped_imports": self.skipped_imports,
            "blocked_events": self.blocked,
            "events": self.events,
            "verdicts": verdicts,
        }


def _install_guards(evidence: EvidenceCollector) -> None:
    real_open = builtins.open
    real_os_open = os.open
    real_os_mkdir = os.mkdir
    real_os_remove = os.remove
    real_os_unlink = os.unlink
    real_os_rename = os.rename
    real_os_replace = os.replace
    real_os_rmdir = os.rmdir
    real_os_symlink = os.symlink
    real_os_link = os.link
    real_os_chmod = os.chmod
    real_socket = socket.socket
    real_create_connection = socket.create_connection
    real_popen = subprocess.Popen
    real_system = os.system

    def guarded_open(file, mode="r", *args, **kwargs):
        if any(flag in mode for flag in ("w", "a", "+", "x")):
            path = os.path.abspath(os.fspath(file))
            evidence.add_event("write_attempt", {"path": path, "mode": mode})
            if not _is_allowed_write_path(path):
                evidence.add_blocked("write_denied", {"path": path, "mode": mode})
                raise PermissionError(f"write outside allowed temp area blocked: {path}")
        return real_open(file, mode, *args, **kwargs)

    def guard_mutating_path_call(name, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            paths = _extract_path_arguments(args, kwargs)
            for path in paths:
                evidence.add_event("syscall:filesystem_mutation", {"call": name, "path": path})
                if not _is_allowed_write_path(path):
                    evidence.add_blocked("write_denied", {"path": path, "mode": name})
                    raise PermissionError(f"{name} outside allowed temp area blocked: {path}")
            return func(*args, **kwargs)

        return wrapper

    def guarded_os_open(path, flags, mode=0o777, *, dir_fd=None):
        normalized_path = os.path.abspath(os.fspath(path))
        if _os_open_is_write(flags):
            evidence.add_event("syscall:filesystem_mutation", {"call": "os.open", "path": normalized_path})
            evidence.add_event("write_attempt", {"path": normalized_path, "mode": f"os.open:{flags}"})
            if not _is_allowed_write_path(normalized_path):
                evidence.add_blocked("write_denied", {"path": normalized_path, "mode": "os.open"})
                raise PermissionError(f"os.open outside allowed temp area blocked: {normalized_path}")
        return real_os_open(path, flags, mode, dir_fd=dir_fd)

    class GuardedSocket(real_socket):
        def connect(self, address):
            evidence.add_event("syscall:network", {"call": "socket.connect", "address": _json_safe(address)})
            evidence.add_blocked("network_denied", {"address": _json_safe(address)})
            raise OSError("network access blocked in sandbox")

    def guarded_create_connection(address, *args, **kwargs):
        evidence.add_event("syscall:network", {"call": "socket.create_connection", "address": _json_safe(address)})
        evidence.add_blocked("network_denied", {"address": _json_safe(address)})
        raise OSError("network access blocked in sandbox")

    def guarded_popen(*args, **kwargs):
        command = args[0] if args else kwargs.get("args")
        normalized = _normalize_command(command)
        evidence.add_event("syscall:process_exec", {"call": "subprocess.Popen", "command": list(normalized)})
        if normalized in ALLOWED_SUBPROCESS_PREFIXES:
            evidence.add_event("subprocess_allowed", {"command": list(normalized)})
            return real_popen(*args, **kwargs)
        evidence.add_blocked("subprocess_denied", {"command": _json_safe(command)})
        raise RuntimeError("subprocess execution blocked in sandbox")

    def guarded_system(command):
        evidence.add_event("syscall:process_exec", {"call": "os.system", "command": command})
        evidence.add_blocked("os_system_denied", {"command": command})
        raise RuntimeError("os.system blocked in sandbox")

    def audit_hook(event, args):
        if event in SUSPICIOUS_AUDIT_EVENTS:
            evidence.add_event(f"audit:{event}", args)
            category = _audit_category(event)
            if category in SYSCALL_BUCKET_KEYS:
                evidence.add_event(f"syscall:{category}", {"event": event, "args": _json_safe(args)})

    builtins.open = guarded_open
    os.open = guarded_os_open
    os.mkdir = guard_mutating_path_call("os.mkdir", real_os_mkdir)
    os.remove = guard_mutating_path_call("os.remove", real_os_remove)
    os.unlink = guard_mutating_path_call("os.unlink", real_os_unlink)
    os.rename = guard_mutating_path_call("os.rename", real_os_rename)
    os.replace = guard_mutating_path_call("os.replace", real_os_replace)
    os.rmdir = guard_mutating_path_call("os.rmdir", real_os_rmdir)
    os.symlink = guard_mutating_path_call("os.symlink", real_os_symlink)
    os.link = guard_mutating_path_call("os.link", real_os_link)
    os.chmod = guard_mutating_path_call("os.chmod", real_os_chmod)
    socket.socket = GuardedSocket
    socket.create_connection = guarded_create_connection
    subprocess.Popen = guarded_popen
    os.system = guarded_system
    sys.addaudithook(audit_hook)


def _create_target_dir() -> str:
    return tempfile.mkdtemp(prefix="site-packages-")


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: sandbox_wrapper.py <packages_dir> <install_target> [<install_target>...]", file=sys.stderr)
        return 2

    packages_dir = sys.argv[1]
    install_targets = sys.argv[2:]
    target_dir = _create_target_dir()
    evidence = EvidenceCollector()
    _install_guards(evidence)

    pip_args = [
        "install",
        "--no-index",
        f"--find-links={packages_dir}",
        "--isolated",
        "--ignore-installed",
        "--no-cache-dir",
        "--no-compile",
        "--target",
        target_dir,
        *install_targets,
    ]

    pip_exit_code = 1
    try:
        from pip._internal.cli.main import main as pip_main

        pip_exit_code = int(pip_main(pip_args))
        if pip_exit_code == 0:
            import_targets, skipped_imports = _discover_import_targets(target_dir, install_targets[0])
            for item in skipped_imports:
                evidence.add_event("import_skipped", item)
            if import_targets:
                if target_dir not in sys.path:
                    sys.path.insert(0, target_dir)
                importlib.invalidate_caches()
                for module_name in import_targets:
                    try:
                        importlib.import_module(module_name)
                        evidence.add_event("import_ok", {"module": module_name})
                    except Exception as exc:
                        evidence.add_event(
                            "import_failed",
                            {
                                "module": module_name,
                                "type": type(exc).__name__,
                                "message": str(exc),
                            },
                        )
    except Exception as exc:
        evidence.add_blocked("pip_exception", {"type": type(exc).__name__, "message": str(exc)})

    report = evidence.report(pip_exit_code)
    print(REPORT_PREFIX + json.dumps(report, sort_keys=True))

    if report["suspicious"]:
        return 1
    return pip_exit_code


if __name__ == "__main__":
    raise SystemExit(main())
