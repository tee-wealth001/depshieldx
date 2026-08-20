import tempfile
import unittest

from depshieldx.security.sandbox.sandbox_wrapper_pub import (
    BUNDLE_MOUNT_PREFIX,
    WORK_DIR,
    _build_verdicts,
    _classify_write_path,
    _parse_strace_log,
)


class ClassifyWritePathTests(unittest.TestCase):
    def test_bundle_directory_write_is_tamper_attempt(self):
        self.assertEqual(
            _classify_write_path(f"{BUNDLE_MOUNT_PREFIX}/http-1.6.0.tar.gz"),
            "bundle_source_tamper_attempt",
        )

    def test_dart_tool_write_is_build_output(self):
        self.assertEqual(
            _classify_write_path(f"{WORK_DIR}/.dart_tool/hooks_runner/evil_hook_pkg/6b4ebf10e7/hook.dill"),
            "build_output",
        )

    def test_work_dir_write_is_project_files(self):
        self.assertEqual(_classify_write_path(f"{WORK_DIR}/probe.dart"), "project_files")

    def test_unrelated_path_is_other(self):
        self.assertEqual(_classify_write_path("/tmp/hsperfdata_nobody/1"), "other")


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
            '9   connect(9, {sa_family=AF_INET, sin_port=htons(443), '
            'sin_addr=inet_addr("8.8.8.8")}, 16) = -1 ENETUNREACH (Network is unreachable)\n'
        )
        evidence = _parse_strace_log(log_path)
        self.assertEqual(evidence["syscall_counts"]["network"], 1)
        self.assertEqual(len(evidence["blocked_events"]), 1)
        self.assertEqual(evidence["blocked_events"][0]["category"], "network_denied")

    def test_write_into_bundle_directory_is_recorded_as_tamper_attempt(self):
        log_path = self._write_log(
            f'14   openat(AT_FDCWD, "{BUNDLE_MOUNT_PREFIX}/http-1.6.0.tar.gz", '
            "O_WRONLY|O_CREAT|O_TRUNC, 0666) = -1 EACCES (Permission denied)\n"
        )
        evidence = _parse_strace_log(log_path)
        self.assertEqual(evidence["write_buckets"]["bundle_source_tamper_attempt"], 1)
        self.assertEqual(len(evidence["blocked_events"]), 1)
        self.assertEqual(evidence["blocked_events"][0]["category"], "bundle_tamper_denied")

    def test_normal_work_dir_write_is_not_blocked(self):
        log_path = self._write_log(
            f'14   openat(AT_FDCWD, "{WORK_DIR}/probe.dart", '
            "O_WRONLY|O_CREAT|O_TRUNC, 0666) = 5\n"
        )
        evidence = _parse_strace_log(log_path)
        self.assertEqual(evidence["write_buckets"]["project_files"], 1)
        self.assertEqual(evidence["blocked_events"], [])

    def test_execve_calls_are_deduplicated_into_subprocesses(self):
        log_path = self._write_log(
            '15   execve("/usr/lib/dart/bin/dart", ["dart", "run", "probe.dart"], 0x0 /* 1 vars */) = 0\n'
            '17   execve("/usr/lib/dart/bin/dart", ["dart", "run", "probe.dart"], 0x0 /* 1 vars */) = 0\n'
            '19   execve("/usr/lib/dart/bin/dartaotruntime", ["dartaotruntime"], 0x0 /* 1 vars */) = 0\n'
        )
        evidence = _parse_strace_log(log_path)
        self.assertEqual(evidence["syscall_counts"]["process_exec"], 3)
        self.assertEqual(len(evidence["subprocesses"]), 2)
        self.assertIn(["dart", "run", "probe.dart"], evidence["subprocesses"])
        self.assertIn(["dartaotruntime"], evidence["subprocesses"])

    def test_non_syscall_lines_are_ignored(self):
        log_path = self._write_log("Resolving dependencies...\nnot a syscall line at all\n")
        evidence = _parse_strace_log(log_path)
        self.assertEqual(evidence["write_count"], 0)
        self.assertEqual(evidence["syscall_counts"], {"filesystem_mutation": 0, "process_exec": 0, "network": 0})


class BuildVerdictsTests(unittest.TestCase):
    def _empty_evidence(self):
        return {
            "write_count": 0,
            "write_buckets": {"project_files": 0, "build_output": 0, "bundle_source_tamper_attempt": 0, "other": 0},
            "syscall_counts": {"filesystem_mutation": 0, "process_exec": 0, "network": 0},
            "blocked_events": [],
        }

    def test_network_attempt_produces_high_severity_verdict(self):
        evidence = self._empty_evidence()
        evidence["blocked_events"] = [{"category": "network_denied", "detail": {}}]
        verdicts = _build_verdicts(evidence, build_exit_code=0)
        codes = {v["code"]: v["severity"] for v in verdicts}
        self.assertEqual(codes["network_attempt_blocked"], "high")

    def test_bundle_tamper_produces_high_severity_verdict(self):
        evidence = self._empty_evidence()
        evidence["blocked_events"] = [{"category": "bundle_tamper_denied", "detail": {}}]
        verdicts = _build_verdicts(evidence, build_exit_code=0)
        codes = {v["code"]: v["severity"] for v in verdicts}
        self.assertEqual(codes["bundle_source_tamper_attempted"], "high")

    def test_run_failure_without_block_is_info_not_high(self):
        # Deliberately different from Maven/NuGet's "medium build_failed":
        # confirmed directly Dart's own Native Assets hooks commonly need
        # a native toolchain (a real C/Rust compiler) this minimal
        # sandbox image doesn't ship -- a benign, offline-environment
        # failure mode the other ecosystems' fully self-contained compile
        # toolchains don't share. Only a real, observed policy block
        # (network/tamper) should make a run "suspicious".
        evidence = self._empty_evidence()
        verdicts = _build_verdicts(evidence, build_exit_code=1)
        codes = {v["code"]: v["severity"] for v in verdicts}
        self.assertEqual(codes["run_failed"], "info")

    def test_run_failure_with_block_does_not_also_report_run_failed(self):
        evidence = self._empty_evidence()
        evidence["blocked_events"] = [{"category": "network_denied", "detail": {}}]
        verdicts = _build_verdicts(evidence, build_exit_code=1)
        codes = {v["code"] for v in verdicts}
        self.assertNotIn("run_failed", codes)

    def test_clean_successful_run_has_no_high_severity_verdicts(self):
        evidence = self._empty_evidence()
        evidence["syscall_counts"] = {"filesystem_mutation": 5, "process_exec": 3, "network": 0}
        verdicts = _build_verdicts(evidence, build_exit_code=0)
        severities = {v["severity"] for v in verdicts}
        self.assertNotIn("high", severities)


if __name__ == "__main__":
    unittest.main()
