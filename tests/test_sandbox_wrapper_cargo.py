import tempfile
import unittest
from pathlib import Path

from depshieldx.sandbox_wrapper_cargo import (
    INSTALL_DIR,
    VENDOR_MOUNT_PREFIX,
    _build_verdicts,
    _classify_write_path,
    _parse_strace_log,
    _write_scratch_project,
)


class ClassifyWritePathTests(unittest.TestCase):
    def test_vendor_directory_write_is_tamper_attempt(self):
        self.assertEqual(
            _classify_write_path(f"{VENDOR_MOUNT_PREFIX}/serde-1.0.219/src/lib.rs"),
            "vendor_source_tamper_attempt",
        )

    def test_target_directory_write_is_build_output(self):
        self.assertEqual(
            _classify_write_path(f"{INSTALL_DIR}/target/debug/build/serde-abc/output"),
            "build_output",
        )

    def test_install_dir_write_is_project_files(self):
        self.assertEqual(_classify_write_path(f"{INSTALL_DIR}/Cargo.lock"), "project_files")

    def test_unrelated_path_is_other(self):
        # Cargo's own best-effort global-cache-lock writes under $CARGO_HOME
        # land here -- confirmed directly they fail harmlessly (EROFS) against
        # the read-only rootfs without affecting the build outcome.
        self.assertEqual(_classify_write_path("/usr/local/cargo/.package-cache"), "other")


class ParseStraceLogTests(unittest.TestCase):
    def _write_log(self, content: str) -> str:
        handle = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
        handle.write(content)
        handle.close()
        return handle.name

    def test_missing_log_file_returns_empty_evidence(self):
        evidence = _parse_strace_log("/nonexistent/path/does-not-exist.log")
        self.assertEqual(evidence["write_count"], 0)
        self.assertEqual(evidence["blocked_events"], [])

    def test_remote_connect_is_recorded_as_blocked_network_event(self):
        log_path = self._write_log(
            '319   connect(5, {sa_family=AF_INET, sin_port=htons(80), '
            'sin_addr=inet_addr("93.184.216.34")}, 16) = -1 ENETUNREACH (Network is unreachable)\n'
        )
        evidence = _parse_strace_log(log_path)
        self.assertEqual(evidence["syscall_counts"]["network"], 1)
        self.assertEqual(len(evidence["blocked_events"]), 1)
        self.assertEqual(evidence["blocked_events"][0]["category"], "network_denied")

    def test_write_into_vendor_directory_is_recorded_as_tamper_attempt(self):
        log_path = self._write_log(
            f'14   openat(AT_FDCWD, "{VENDOR_MOUNT_PREFIX}/serde-1.0.219/src/lib.rs", '
            "O_WRONLY|O_CREAT|O_TRUNC, 0666) = -1 EACCES (Permission denied)\n"
        )
        evidence = _parse_strace_log(log_path)
        self.assertEqual(evidence["write_buckets"]["vendor_source_tamper_attempt"], 1)
        self.assertEqual(len(evidence["blocked_events"]), 1)
        self.assertEqual(evidence["blocked_events"][0]["category"], "vendor_tamper_denied")

    def test_normal_target_write_is_not_blocked(self):
        log_path = self._write_log(
            f'14   openat(AT_FDCWD, "{INSTALL_DIR}/target/debug/.cargo-build-lock", '
            "O_RDWR|O_CREAT, 0666) = 5\n"
        )
        evidence = _parse_strace_log(log_path)
        self.assertEqual(evidence["write_buckets"]["build_output"], 1)
        self.assertEqual(evidence["blocked_events"], [])

    def test_execve_calls_are_deduplicated_into_subprocesses(self):
        log_path = self._write_log(
            '15   execve("/usr/local/cargo/bin/cargo", ["cargo", "build", "--offline"], 0x0 /* 1 vars */) = 0\n'
            '17   execve("/usr/local/cargo/bin/cargo", ["cargo", "build", "--offline"], 0x0 /* 1 vars */) = 0\n'
            '19   execve("/usr/bin/rustc", ["rustc", "-vV"], 0x0 /* 1 vars */) = 0\n'
        )
        evidence = _parse_strace_log(log_path)
        self.assertEqual(evidence["syscall_counts"]["process_exec"], 3)
        self.assertEqual(len(evidence["subprocesses"]), 2)
        self.assertIn(["cargo", "build", "--offline"], evidence["subprocesses"])
        self.assertIn(["rustc", "-vV"], evidence["subprocesses"])

    def test_non_syscall_lines_are_ignored(self):
        log_path = self._write_log("   Compiling serde v1.0.219\nnot a syscall line at all\n")
        evidence = _parse_strace_log(log_path)
        self.assertEqual(evidence["write_count"], 0)
        self.assertEqual(evidence["syscall_counts"], {"filesystem_mutation": 0, "process_exec": 0, "network": 0})


class BuildVerdictsTests(unittest.TestCase):
    def _empty_evidence(self):
        return {
            "write_count": 0,
            "write_buckets": {"project_files": 0, "build_output": 0, "vendor_source_tamper_attempt": 0, "other": 0},
            "syscall_counts": {"filesystem_mutation": 0, "process_exec": 0, "network": 0},
            "blocked_events": [],
        }

    def test_network_attempt_produces_high_severity_verdict(self):
        evidence = self._empty_evidence()
        evidence["blocked_events"] = [{"category": "network_denied", "detail": {}}]
        verdicts = _build_verdicts(evidence, build_exit_code=0)
        codes = {v["code"]: v["severity"] for v in verdicts}
        self.assertEqual(codes["network_attempt_blocked"], "high")

    def test_vendor_tamper_produces_high_severity_verdict(self):
        evidence = self._empty_evidence()
        evidence["blocked_events"] = [{"category": "vendor_tamper_denied", "detail": {}}]
        verdicts = _build_verdicts(evidence, build_exit_code=0)
        codes = {v["code"]: v["severity"] for v in verdicts}
        self.assertEqual(codes["vendor_source_tamper_attempted"], "high")

    def test_build_failure_without_block_is_medium(self):
        evidence = self._empty_evidence()
        verdicts = _build_verdicts(evidence, build_exit_code=101)
        codes = {v["code"]: v["severity"] for v in verdicts}
        self.assertEqual(codes["build_failed"], "medium")

    def test_build_failure_with_block_does_not_also_report_build_failed(self):
        # A build that fails *because* a blocked syscall interrupted it
        # shouldn't also get the generic "unexplained failure" verdict --
        # the high-severity block verdict is the more specific, useful signal.
        evidence = self._empty_evidence()
        evidence["blocked_events"] = [{"category": "network_denied", "detail": {}}]
        verdicts = _build_verdicts(evidence, build_exit_code=101)
        codes = {v["code"] for v in verdicts}
        self.assertNotIn("build_failed", codes)

    def test_clean_successful_build_has_no_high_or_medium_verdicts(self):
        evidence = self._empty_evidence()
        evidence["syscall_counts"] = {"filesystem_mutation": 5, "process_exec": 3, "network": 0}
        verdicts = _build_verdicts(evidence, build_exit_code=0)
        severities = {v["severity"] for v in verdicts}
        self.assertNotIn("high", severities)
        self.assertNotIn("medium", severities)


class WriteScratchProjectTests(unittest.TestCase):
    def test_writes_manifest_and_vendored_source_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            install_dir = Path(tmp) / "install"
            _write_scratch_project(install_dir, "/tmp/packages/vendor", ["serde@=1.0.219", "syn@=3.0.3"])

            manifest = (install_dir / "Cargo.toml").read_text()
            self.assertIn('serde = "=1.0.219"', manifest)
            self.assertIn('syn = "=3.0.3"', manifest)

            config = (install_dir / ".cargo" / "config.toml").read_text()
            self.assertIn('replace-with = "vendored-sources"', config)
            self.assertIn('directory = "/tmp/packages/vendor"', config)

            self.assertTrue((install_dir / "src" / "lib.rs").exists())


if __name__ == "__main__":
    unittest.main()
