import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from depshieldx.cli import cli
from depshieldx.cli.engine import _load_cli_input


class CliGoDispatchTests(unittest.TestCase):
    """Proves the CLI actually routes go.sum lockfile/bare-module-path
    input to GoEcosystem end to end, mirroring test_cli_cargo_dispatch.py's
    coverage for cargo. The real-toolchain scan test is marked live; the
    rest are offline."""

    @pytest.mark.live
    def test_scan_bare_module_with_ecosystem_go_flag(self):
        runner = CliRunner()
        result = runner.invoke(
            cli, ["scan", "github.com/pkg/errors", "--ecosystem", "go", "--fast", "--output", "json"]
        )

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["ecosystem"], "go")
        self.assertEqual(payload["resolution"]["source_type"], "package")
        self.assertIn("github.com/pkg/errors", payload["resolution"]["resolved_versions"])

    def test_scan_with_go_sum_lockfile_reports_go_ecosystem(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project_dir = Path(temp_dir)
            (project_dir / "go.mod").write_text("module demo\n\ngo 1.26\n", encoding="utf-8")
            lockfile = project_dir / "go.sum"
            lockfile.write_text("", encoding="utf-8")

            fake_result = MagicMock(
                returncode=0,
                stdout='{"Path": "github.com/pkg/errors", "Version": "v0.9.1"}\n',
                stderr="",
            )
            with patch("depshieldx.ecosystems.go.resolve_go_tool", return_value="/usr/local/bin/go"):
                with patch("depshieldx.ecosystems.go._run", return_value=fake_result):
                    with patch("depshieldx.cli.engine._run_fast_checks") as mock_checks:
                        mock_checks.return_value = (
                            {"block": False, "reason": None, "warnings": [], "infos": []},
                            {"block": False, "reason": None, "warnings": [], "infos": [], "threat_intelligence": {}},
                        )
                        runner = CliRunner()
                        result = runner.invoke(
                            cli, ["scan", "--lockfile", str(lockfile), "--fast", "--output", "json"]
                        )

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["ecosystem"], "go")
        self.assertEqual(payload["resolution"]["resolved_versions"]["github.com/pkg/errors"], "v0.9.1")

    def test_load_cli_input_honors_ecosystem_go_flag(self):
        input_source = _load_cli_input(("github.com/pkg/errors",), ecosystem="go")

        self.assertEqual(input_source.ecosystem, "go")

    def test_go_sum_lockfile_is_auto_detected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "go.sum"
            lockfile.write_text("", encoding="utf-8")

            input_source = _load_cli_input((), lockfile=str(lockfile))

        self.assertEqual(input_source.ecosystem, "go")
        self.assertEqual(input_source.source_type, "lockfile")

    def test_uninstall_go_sum_lockfile_without_go_mod_fails_clearly(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "go.sum"
            lockfile.write_text("", encoding="utf-8")

            runner = CliRunner()
            result = runner.invoke(cli, ["uninstall", "--lockfile", str(lockfile)])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("no go.mod found", str(result.output) + str(result.exception))

    @patch("depshieldx.cli.commands.uninstall._run_cli_command")
    def test_uninstall_go_sum_lockfile_uses_direct_dependencies_from_go_mod(self, mock_run_cli):
        with tempfile.TemporaryDirectory() as temp_dir:
            project_dir = Path(temp_dir)
            (project_dir / "go.mod").write_text("module demo\n\ngo 1.26\n", encoding="utf-8")
            lockfile = project_dir / "go.sum"
            lockfile.write_text("", encoding="utf-8")

            payload = {"Require": [{"Path": "github.com/pkg/errors", "Version": "v0.9.1", "Indirect": False}]}
            fake_result = MagicMock(returncode=0, stdout=json.dumps(payload), stderr="")
            with patch("depshieldx.ecosystems.go.resolve_go_tool", return_value="/usr/local/bin/go"):
                with patch("depshieldx.ecosystems.go._run", return_value=fake_result):
                    runner = CliRunner()
                    result = runner.invoke(cli, ["uninstall", "--lockfile", str(lockfile)])

        self.assertEqual(result.exit_code, 0, result.output)
        uninstall_command = mock_run_cli.call_args.args[0]
        self.assertEqual(uninstall_command, ["/usr/local/bin/go", "get", "github.com/pkg/errors@none"])

    @patch("depshieldx.cli.commands.uninstall._run_cli_command")
    def test_uninstall_go_bare_module_paths_with_ecosystem_flag(self, mock_run_cli):
        with patch("depshieldx.ecosystems.go.resolve_go_tool", return_value="/usr/local/bin/go"):
            runner = CliRunner()
            result = runner.invoke(
                cli, ["uninstall", "github.com/pkg/errors", "golang.org/x/text", "--ecosystem", "go"]
            )

        self.assertEqual(result.exit_code, 0, result.output)
        uninstall_command = mock_run_cli.call_args.args[0]
        self.assertEqual(uninstall_command[0], "/usr/local/bin/go")
        self.assertEqual(uninstall_command[1], "get")
        self.assertCountEqual(
            uninstall_command[2:], ["github.com/pkg/errors@none", "golang.org/x/text@none"]
        )


if __name__ == "__main__":
    unittest.main()
