import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from depshieldx.security.sandbox.sandbox_wrapper_go import (
    BUNDLE_MOUNT_PREFIX,
    WORK_DIR,
    MISSING_PACKAGE_PATTERN,
    _build_verdicts,
    _classify_write_path,
    _discover_buildable_modules,
    _parse_strace_log,
    _write_main_go,
)


class ClassifyWritePathTests(unittest.TestCase):
    def test_bundle_directory_write_is_tamper_attempt(self):
        self.assertEqual(
            _classify_write_path(f"{BUNDLE_MOUNT_PREFIX}/go.sum"),
            "bundle_source_tamper_attempt",
        )

    def test_gocache_write_is_build_output(self):
        self.assertEqual(
            _classify_write_path(f"{WORK_DIR}/gocache/00/abcdef-d"),
            "build_output",
        )

    def test_gopath_write_is_build_output(self):
        self.assertEqual(
            _classify_write_path(f"{WORK_DIR}/gopath/pkg/mod/cache/download/lock"),
            "build_output",
        )

    def test_work_dir_write_is_project_files(self):
        self.assertEqual(_classify_write_path(f"{WORK_DIR}/main.go"), "project_files")

    def test_unrelated_path_is_other(self):
        # Go's own telemetry housekeeping ($HOME/.config/go/telemetry) lands
        # here -- confirmed directly against a real traced build, legitimate
        # toolchain activity, not vendor tamper or a build-time attack.
        self.assertEqual(_classify_write_path("/tmp/.config/go/telemetry/local/go@go1.26.6.count"), "other")


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

    def test_write_into_bundle_directory_is_recorded_as_tamper_attempt(self):
        log_path = self._write_log(
            f'14   openat(AT_FDCWD, "{BUNDLE_MOUNT_PREFIX}/go.sum", '
            "O_WRONLY|O_CREAT|O_TRUNC, 0666) = -1 EACCES (Permission denied)\n"
        )
        evidence = _parse_strace_log(log_path)
        self.assertEqual(evidence["write_buckets"]["bundle_source_tamper_attempt"], 1)
        self.assertEqual(len(evidence["blocked_events"]), 1)
        self.assertEqual(evidence["blocked_events"][0]["category"], "bundle_tamper_denied")

    def test_normal_gocache_write_is_not_blocked(self):
        log_path = self._write_log(
            f'14   openat(AT_FDCWD, "{WORK_DIR}/gocache/lock", '
            "O_RDWR|O_CREAT, 0666) = 5\n"
        )
        evidence = _parse_strace_log(log_path)
        self.assertEqual(evidence["write_buckets"]["build_output"], 1)
        self.assertEqual(evidence["blocked_events"], [])

    def test_execve_calls_are_deduplicated_into_subprocesses(self):
        log_path = self._write_log(
            '15   execve("/usr/local/go/bin/go", ["go", "build", "-p", "2", "."], 0x0 /* 1 vars */) = 0\n'
            '17   execve("/usr/local/go/bin/go", ["go", "build", "-p", "2", "."], 0x0 /* 1 vars */) = 0\n'
            '19   execve("/usr/local/go/pkg/tool/linux_amd64/compile", ["compile", "-V=full"], 0x0 /* 1 vars */) = 0\n'
        )
        evidence = _parse_strace_log(log_path)
        self.assertEqual(evidence["syscall_counts"]["process_exec"], 3)
        self.assertEqual(len(evidence["subprocesses"]), 2)
        self.assertIn(["go", "build", "-p", "2", "."], evidence["subprocesses"])
        self.assertIn(["compile", "-V=full"], evidence["subprocesses"])

    def test_non_syscall_lines_are_ignored(self):
        log_path = self._write_log("   go: downloading github.com/pkg/errors\nnot a syscall line at all\n")
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

    def test_build_failure_without_block_is_medium(self):
        evidence = self._empty_evidence()
        verdicts = _build_verdicts(evidence, build_exit_code=1)
        codes = {v["code"]: v["severity"] for v in verdicts}
        self.assertEqual(codes["build_failed"], "medium")

    def test_build_failure_with_block_does_not_also_report_build_failed(self):
        evidence = self._empty_evidence()
        evidence["blocked_events"] = [{"category": "network_denied", "detail": {}}]
        verdicts = _build_verdicts(evidence, build_exit_code=1)
        codes = {v["code"] for v in verdicts}
        self.assertNotIn("build_failed", codes)

    def test_clean_successful_build_has_no_high_or_medium_verdicts(self):
        evidence = self._empty_evidence()
        evidence["syscall_counts"] = {"filesystem_mutation": 5, "process_exec": 3, "network": 0}
        verdicts = _build_verdicts(evidence, build_exit_code=0)
        severities = {v["severity"] for v in verdicts}
        self.assertNotIn("high", severities)
        self.assertNotIn("medium", severities)


class MissingPackagePatternTests(unittest.TestCase):
    def test_matches_non_readonly_error_format(self):
        text = "main.go:5:2: no required module provides package golang.org/x/crypto; to add it:"
        self.assertEqual(MISSING_PACKAGE_PATTERN.findall(text), ["golang.org/x/crypto"])

    def test_matches_readonly_mode_error_format(self):
        # Confirmed directly this is the real error text under
        # GOFLAGS=-mod=readonly, which _prepare_work_env always sets --
        # the non-readonly wording above never actually occurs in this
        # sandbox, but both are matched defensively.
        text = "main.go:5:2: cannot find module providing package golang.org/x/crypto: import lookup disabled by -mod=readonly"
        self.assertEqual(MISSING_PACKAGE_PATTERN.findall(text), ["golang.org/x/crypto"])


class WriteMainGoTests(unittest.TestCase):
    def test_writes_blank_imports_for_every_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("depshieldx.security.sandbox.sandbox_wrapper_go.WORK_DIR", Path(tmp)):
                _write_main_go(["github.com/pkg/errors", "golang.org/x/text"])
                content = (Path(tmp) / "main.go").read_text()

        self.assertIn('_ "github.com/pkg/errors"', content)
        self.assertIn('_ "golang.org/x/text"', content)
        self.assertIn("package main", content)
        self.assertIn("func main() {}", content)

    def test_no_modules_still_writes_valid_buildable_main(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("depshieldx.security.sandbox.sandbox_wrapper_go.WORK_DIR", Path(tmp)):
                _write_main_go([])
                content = (Path(tmp) / "main.go").read_text()

        self.assertNotIn("import (", content)
        self.assertIn("func main() {}", content)


class DiscoverBuildableModulesTests(unittest.TestCase):
    @patch("depshieldx.security.sandbox.sandbox_wrapper_go.subprocess.run")
    @patch("depshieldx.security.sandbox.sandbox_wrapper_go._write_main_go")
    def test_all_modules_buildable_when_probe_succeeds(self, mock_write, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""

        buildable, skipped = _discover_buildable_modules(["github.com/pkg/errors"], {})

        self.assertEqual(buildable, ["github.com/pkg/errors"])
        self.assertEqual(skipped, [])
        mock_write.assert_called_once_with(["github.com/pkg/errors"])

    @patch("depshieldx.security.sandbox.sandbox_wrapper_go.subprocess.run")
    @patch("depshieldx.security.sandbox.sandbox_wrapper_go._write_main_go")
    def test_unbuildable_module_is_dropped_and_reported_as_skipped(self, mock_write, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = (
            "main.go:5:2: cannot find module providing package golang.org/x/crypto: "
            "import lookup disabled by -mod=readonly"
        )

        buildable, skipped = _discover_buildable_modules(
            ["github.com/pkg/errors", "golang.org/x/crypto"], {}
        )

        self.assertEqual(buildable, ["github.com/pkg/errors"])
        self.assertEqual(skipped, ["golang.org/x/crypto"])
        # _write_main_go is called twice: once with every candidate for the
        # probe, once more with only the buildable subset for the real
        # (straced) build that follows.
        self.assertEqual(mock_write.call_count, 2)
        mock_write.assert_called_with(["github.com/pkg/errors"])


if __name__ == "__main__":
    unittest.main()
