import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from depshieldx.cli import cli
from depshieldx.cli.engine import _load_cli_input
from depshieldx.cli.commands.routing import _extract_simple_dotnet_add_package_target


class CliNuGetDispatchTests(unittest.TestCase):
    """Proves the CLI actually routes PackageId[@version] targets and
    packages.lock.json input to NuGetEcosystem end to end, mirroring
    test_cli_maven_dispatch.py's coverage for Maven. The real-toolchain
    scan test is marked live; the rest are offline."""

    @pytest.mark.live
    def test_scan_bare_target_with_ecosystem_nuget_flag(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["scan", "Newtonsoft.Json@13.0.3", "--ecosystem", "nuget", "--fast", "--output", "json"],
        )

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["ecosystem"], "nuget")
        self.assertEqual(payload["resolution"]["source_type"], "package")
        self.assertIn("Newtonsoft.Json", payload["resolution"]["resolved_versions"])

    def test_scan_bare_target_reports_nuget_ecosystem(self):
        fake_result = MagicMock(returncode=0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile_path = Path(temp_dir) / "packages.lock.json"
            lockfile_path.write_text(
                '{"version": 1, "dependencies": {"net8.0": {"Newtonsoft.Json": '
                '{"type": "Direct", "resolved": "13.0.3"}}}}',
                encoding="utf-8",
            )
            with patch("depshieldx.ecosystems.nuget.ecosystem.resolve_dotnet_tool", return_value="/usr/local/bin/dotnet"):
                with patch("depshieldx.ecosystems.nuget.ecosystem._run", return_value=fake_result):
                    with patch("depshieldx.ecosystems.nuget.ecosystem.tempfile.TemporaryDirectory") as mock_tempdir:
                        mock_tempdir.return_value.__enter__.return_value = temp_dir
                        with patch("depshieldx.cli.engine._run_fast_checks") as mock_checks:
                            mock_checks.return_value = (
                                {"block": False, "reason": None, "warnings": [], "infos": []},
                                {"block": False, "reason": None, "warnings": [], "infos": [], "threat_intelligence": {}},
                            )
                            runner = CliRunner()
                            result = runner.invoke(
                                cli,
                                ["scan", "Newtonsoft.Json@13.0.3", "--ecosystem", "nuget", "--fast", "--output", "json"],
                            )

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["ecosystem"], "nuget")
        self.assertEqual(payload["resolution"]["resolved_versions"]["Newtonsoft.Json"], "13.0.3")

    def test_load_cli_input_honors_ecosystem_nuget_flag(self):
        input_source = _load_cli_input(("Newtonsoft.Json@13.0.3",), ecosystem="nuget")

        self.assertEqual(input_source.ecosystem, "nuget")

    def test_packages_lock_json_is_auto_detected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "packages.lock.json"
            lockfile.write_text('{"version": 1, "dependencies": {}}', encoding="utf-8")

            input_source = _load_cli_input((), lockfile=str(lockfile))

        self.assertEqual(input_source.ecosystem, "nuget")
        self.assertEqual(input_source.source_type, "lockfile")

    @patch("depshieldx.cli.commands.uninstall._run_cli_command")
    def test_uninstall_nuget_bare_target_with_ecosystem_flag(self, mock_run_cli):
        with patch("depshieldx.ecosystems.nuget.ecosystem.resolve_dotnet_tool", return_value="/usr/local/bin/dotnet"):
            runner = CliRunner()
            result = runner.invoke(cli, ["uninstall", "Serilog", "--ecosystem", "nuget"])

        self.assertEqual(result.exit_code, 0, result.output)
        uninstall_command = mock_run_cli.call_args.args[0]
        self.assertEqual(uninstall_command, ["/usr/local/bin/dotnet", "remove", "package", "Serilog"])

    @patch("depshieldx.cli.commands.uninstall._run_cli_command")
    def test_uninstall_nuget_multiple_targets_fails_clearly(self, mock_run_cli):
        with patch("depshieldx.ecosystems.nuget.ecosystem.resolve_dotnet_tool", return_value="/usr/local/bin/dotnet"):
            runner = CliRunner()
            result = runner.invoke(
                cli, ["uninstall", "Serilog", "Newtonsoft.Json", "--ecosystem", "nuget"]
            )

        self.assertNotEqual(result.exit_code, 0)
        mock_run_cli.assert_not_called()
        self.assertIn("one package at a time", str(result.output) + str(result.exception))


class RouteDotnetTests(unittest.TestCase):
    """Unit coverage for the routing shim's own interception heuristic,
    independent of the CLI -- mirrors test_cli_go_dispatch.py's coverage
    style for its own _extract_simple_go_get_targets."""

    def test_intercepts_plain_add_package(self):
        self.assertEqual(_extract_simple_dotnet_add_package_target(["add", "package", "Serilog"]), "Serilog")

    def test_intercepts_add_package_with_version(self):
        self.assertEqual(
            _extract_simple_dotnet_add_package_target(["add", "package", "Serilog", "--version", "4.2.0"]),
            "Serilog@4.2.0",
        )

    def test_does_not_intercept_other_dotnet_commands(self):
        self.assertIsNone(_extract_simple_dotnet_add_package_target(["build"]))
        self.assertIsNone(_extract_simple_dotnet_add_package_target(["restore"]))
        self.assertIsNone(_extract_simple_dotnet_add_package_target(["--version"]))

    def test_does_not_intercept_add_reference(self):
        self.assertIsNone(_extract_simple_dotnet_add_package_target(["add", "reference", "../Other.csproj"]))

    def test_does_not_intercept_with_project_positional(self):
        self.assertIsNone(_extract_simple_dotnet_add_package_target(["add", "MyProj.csproj", "package", "Serilog"]))

    def test_does_not_intercept_with_extra_flags(self):
        self.assertIsNone(
            _extract_simple_dotnet_add_package_target(["add", "package", "Serilog", "--prerelease"])
        )


if __name__ == "__main__":
    unittest.main()
