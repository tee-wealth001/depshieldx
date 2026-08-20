import tempfile
import unittest

from depshieldx.security.sandbox.sandbox_wrapper_rubygems import (
    BUNDLE_MOUNT_PREFIX,
    WORK_DIR,
    _build_verdicts,
    _classify_write_path,
    _parse_strace_log,
)


class ClassifyWritePathTests(unittest.TestCase):
    def test_bundle_directory_write_is_tamper_attempt(self):
        self.assertEqual(
            _classify_write_path(f"{BUNDLE_MOUNT_PREFIX}/demo_gem-1.0.0.gem"),
            "bundle_source_tamper_attempt",
        )

    def test_gem_home_write_is_build_output(self):
        self.assertEqual(
            _classify_write_path(f"{WORK_DIR}/gem_home/gems/demo_gem-1.0.0/lib/demo_gem.rb"),
            "build_output",
        )

    def test_bundle_path_write_is_build_output(self):
        self.assertEqual(
            _classify_write_path(f"{WORK_DIR}/bundle_path/ruby/3.4.0/extensions/demo_gem.so"),
            "build_output",
        )

    def test_work_dir_write_is_project_files(self):
        self.assertEqual(_classify_write_path(f"{WORK_DIR}/Gemfile.lock"), "project_files")

    def test_unrelated_path_is_other(self):
        self.assertEqual(_classify_write_path("/tmp/ccBJWOTk.s"), "other")


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
            '9   connect(9, {sa_family=AF_INET, sin_port=htons(80), '
            'sin_addr=inet_addr("93.184.216.34")}, 16) = -1 ENETUNREACH (Network is unreachable)\n'
        )
        evidence = _parse_strace_log(log_path)
        self.assertEqual(evidence["syscall_counts"]["network"], 1)
        self.assertEqual(len(evidence["blocked_events"]), 1)
        self.assertEqual(evidence["blocked_events"][0]["category"], "network_denied")

    def test_write_into_bundle_directory_is_recorded_as_tamper_attempt(self):
        log_path = self._write_log(
            f'14   openat(AT_FDCWD, "{BUNDLE_MOUNT_PREFIX}/pwned.txt", '
            "O_WRONLY|O_CREAT|O_TRUNC, 0666) = -1 EACCES (Permission denied)\n"
        )
        evidence = _parse_strace_log(log_path)
        self.assertEqual(evidence["write_buckets"]["bundle_source_tamper_attempt"], 1)
        self.assertEqual(len(evidence["blocked_events"]), 1)
        self.assertEqual(evidence["blocked_events"][0]["category"], "bundle_tamper_denied")

    def test_normal_work_dir_write_is_not_blocked(self):
        log_path = self._write_log(
            f'14   openat(AT_FDCWD, "{WORK_DIR}/Gemfile.lock", '
            "O_WRONLY|O_CREAT|O_TRUNC, 0666) = 5\n"
        )
        evidence = _parse_strace_log(log_path)
        self.assertEqual(evidence["write_buckets"]["project_files"], 1)
        self.assertEqual(evidence["blocked_events"], [])

    def test_execve_calls_are_deduplicated_into_subprocesses(self):
        log_path = self._write_log(
            '15   execve("/usr/bin/gcc", ["gcc", "-c", "evilgem.c"], 0x0 /* 1 vars */) = 0\n'
            '17   execve("/usr/bin/gcc", ["gcc", "-c", "evilgem.c"], 0x0 /* 1 vars */) = 0\n'
            '19   execve("/usr/bin/make", ["make"], 0x0 /* 1 vars */) = 0\n'
        )
        evidence = _parse_strace_log(log_path)
        self.assertEqual(evidence["syscall_counts"]["process_exec"], 3)
        self.assertEqual(len(evidence["subprocesses"]), 2)
        self.assertIn(["gcc", "-c", "evilgem.c"], evidence["subprocesses"])
        self.assertIn(["make"], evidence["subprocesses"])

    def test_non_syscall_lines_are_ignored(self):
        log_path = self._write_log("Installing evilgem 0.0.1 with native extensions\nnot a syscall line at all\n")
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

    def test_install_failure_without_block_is_info_not_high(self):
        # A native-extension build failing offline (missing dev headers,
        # an unrelated compiler quirk, ...) is common and not itself
        # suspicious -- confirmed directly with a real json gem build
        # succeeding in this project's sandbox image, but a different
        # gem needing e.g. libssl-dev the image doesn't ship would fail
        # for entirely benign reasons. Only a real, observed policy
        # block (network/tamper) should make an install "suspicious" --
        # mirrors sandbox_wrapper_pub.py's identical "info, not high"
        # treatment for its own analogous run failure.
        evidence = self._empty_evidence()
        verdicts = _build_verdicts(evidence, build_exit_code=1)
        codes = {v["code"]: v["severity"] for v in verdicts}
        self.assertEqual(codes["install_failed"], "info")

    def test_install_failure_with_block_does_not_also_report_install_failed(self):
        evidence = self._empty_evidence()
        evidence["blocked_events"] = [{"category": "network_denied", "detail": {}}]
        verdicts = _build_verdicts(evidence, build_exit_code=1)
        codes = {v["code"] for v in verdicts}
        self.assertNotIn("install_failed", codes)

    def test_clean_successful_run_has_no_high_severity_verdicts(self):
        evidence = self._empty_evidence()
        evidence["syscall_counts"] = {"filesystem_mutation": 91, "process_exec": 41, "network": 0}
        verdicts = _build_verdicts(evidence, build_exit_code=0)
        severities = {v["severity"] for v in verdicts}
        self.assertNotIn("high", severities)


if __name__ == "__main__":
    unittest.main()
