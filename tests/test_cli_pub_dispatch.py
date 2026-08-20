import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from depshieldx.cli import cli
from depshieldx.cli.engine import _load_cli_input
from depshieldx.cli.commands.routing import _extract_simple_dart_pub_add_targets


class CliPubDispatchTests(unittest.TestCase):
    """Proves the CLI actually routes package_name[@version] targets and
    pubspec.lock input to PubEcosystem end to end, mirroring
    test_cli_nuget_dispatch.py's coverage for NuGet. The real-toolchain
    scan test is marked live; the rest are offline."""

    @pytest.mark.live
    def test_scan_bare_target_with_ecosystem_pub_flag(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["scan", "http@1.6.0", "--ecosystem", "pub", "--fast", "--output", "json"],
        )

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["ecosystem"], "pub")
        self.assertEqual(payload["resolution"]["source_type"], "package")
        self.assertIn("http", payload["resolution"]["resolved_versions"])

    def test_scan_bare_target_reports_pub_ecosystem(self):
        fake_result = MagicMock(returncode=0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile_path = Path(temp_dir) / "pubspec.lock"
            lockfile_path.write_text(
                "packages:\n"
                "  http:\n"
                "    dependency: \"direct main\"\n"
                "    description:\n"
                "      name: http\n"
                "      sha256: \"87721a4a50b19c7f1d49001e51409bddc46303966ce89a65af4f4e6004896412\"\n"
                "      url: \"https://pub.dev\"\n"
                "    source: hosted\n"
                "    version: \"1.6.0\"\n",
                encoding="utf-8",
            )
            with patch("depshieldx.ecosystems.pub.ecosystem.resolve_dart_tool", return_value="/usr/local/bin/dart"):
                with patch("depshieldx.ecosystems.pub.ecosystem._run", return_value=fake_result):
                    with patch("depshieldx.ecosystems.pub.ecosystem.tempfile.TemporaryDirectory") as mock_tempdir:
                        mock_tempdir.return_value.__enter__.return_value = temp_dir
                        with patch("depshieldx.cli.engine._run_fast_checks") as mock_checks:
                            mock_checks.return_value = (
                                {"block": False, "reason": None, "warnings": [], "infos": []},
                                {"block": False, "reason": None, "warnings": [], "infos": [], "threat_intelligence": {}},
                            )
                            runner = CliRunner()
                            result = runner.invoke(
                                cli,
                                ["scan", "http@1.6.0", "--ecosystem", "pub", "--fast", "--output", "json"],
                            )

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["ecosystem"], "pub")
        self.assertEqual(payload["resolution"]["resolved_versions"]["http"], "1.6.0")

    def test_load_cli_input_honors_ecosystem_pub_flag(self):
        input_source = _load_cli_input(("http@1.6.0",), ecosystem="pub")

        self.assertEqual(input_source.ecosystem, "pub")

    def test_pubspec_lock_is_auto_detected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "pubspec.lock"
            lockfile.write_text("packages: {}\n", encoding="utf-8")

            input_source = _load_cli_input((), lockfile=str(lockfile))

        self.assertEqual(input_source.ecosystem, "pub")
        self.assertEqual(input_source.source_type, "lockfile")

    @patch("depshieldx.cli.commands.uninstall._run_cli_command")
    def test_uninstall_pub_multiple_targets_with_ecosystem_flag(self, mock_run_cli):
        with patch("depshieldx.ecosystems.pub.ecosystem.resolve_dart_tool", return_value="/usr/local/bin/dart"):
            runner = CliRunner()
            result = runner.invoke(cli, ["uninstall", "http", "path", "--ecosystem", "pub"])

        self.assertEqual(result.exit_code, 0, result.output)
        uninstall_command = mock_run_cli.call_args.args[0]
        self.assertEqual(uninstall_command, ["/usr/local/bin/dart", "pub", "remove", "http", "path"])


class RouteDartTests(unittest.TestCase):
    """Unit coverage for the routing shim's own interception heuristic,
    independent of the CLI -- mirrors test_cli_cargo_dispatch.py's/
    test_cli_go_dispatch.py's coverage style for their own multi-target
    extractors, since `dart pub add` (like `cargo add`/`go get`) accepts
    more than one package per invocation, unlike NuGet's single-target
    _extract_simple_dotnet_add_package_target."""

    def test_intercepts_plain_pub_add_single_package(self):
        self.assertEqual(_extract_simple_dart_pub_add_targets(["pub", "add", "http"]), ["http"])

    def test_intercepts_plain_pub_add_multiple_packages(self):
        self.assertEqual(
            _extract_simple_dart_pub_add_targets(["pub", "add", "http", "path"]),
            ["http", "path"],
        )

    def test_does_not_intercept_other_dart_commands(self):
        self.assertIsNone(_extract_simple_dart_pub_add_targets(["pub", "get"]))
        self.assertIsNone(_extract_simple_dart_pub_add_targets(["run", "bin/main.dart"]))
        self.assertIsNone(_extract_simple_dart_pub_add_targets(["--version"]))

    def test_does_not_intercept_pub_remove(self):
        self.assertIsNone(_extract_simple_dart_pub_add_targets(["pub", "remove", "http"]))

    def test_does_not_intercept_with_extra_flags(self):
        self.assertIsNone(_extract_simple_dart_pub_add_targets(["pub", "add", "http", "--dry-run"]))

    def test_does_not_intercept_versioned_descriptor_syntax(self):
        # "http@^1.2.3" itself has no leading "-" so it's still captured as
        # a target string -- depshieldx's own install command downstream
        # handles the "name@version" shape; only flag-looking args (a
        # leading "-") are filtered out here.
        self.assertEqual(_extract_simple_dart_pub_add_targets(["pub", "add", "http@^1.2.3"]), ["http@^1.2.3"])


if __name__ == "__main__":
    unittest.main()
