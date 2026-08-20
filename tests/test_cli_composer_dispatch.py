import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from depshieldx.cli import cli
from depshieldx.cli.engine import _load_cli_input
from depshieldx.cli.commands.routing import _extract_simple_composer_require_targets


class CliComposerDispatchTests(unittest.TestCase):
    """Proves the CLI actually routes vendor/package[:version] targets and
    composer.lock input to ComposerEcosystem end to end, mirroring
    test_cli_rubygems_dispatch.py's coverage for RubyGems. The real-
    toolchain scan test is marked live; the rest are offline."""

    @pytest.mark.live
    def test_scan_bare_target_with_ecosystem_composer_flag(self):
        # 3.10.0 confirmed directly to have no reported CVEs at the time
        # this test was written -- a version with real vulnerabilities
        # would legitimately block the scan (exit code 10), which isn't
        # what this test is checking.
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["scan", "monolog/monolog@3.10.0", "--ecosystem", "composer", "--fast", "--output", "json"],
        )

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["ecosystem"], "composer")
        self.assertEqual(payload["resolution"]["source_type"], "package")
        self.assertEqual(payload["resolution"]["resolved_versions"]["monolog/monolog"], "3.10.0")

    def test_scan_bare_target_reports_composer_ecosystem(self):
        fake_result = MagicMock(returncode=0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile_path = Path(temp_dir) / "composer.lock"
            lockfile_path.write_text(
                json.dumps({"packages": [{"name": "monolog/monolog", "version": "3.10.0"}], "packages-dev": []}),
                encoding="utf-8",
            )
            with patch("depshieldx.ecosystems.composer.ecosystem.resolve_composer_tool", return_value="/usr/local/bin/composer"):
                with patch("depshieldx.ecosystems.composer.ecosystem._run", return_value=fake_result):
                    with patch("depshieldx.ecosystems.composer.ecosystem.tempfile.TemporaryDirectory") as mock_tempdir:
                        mock_tempdir.return_value.__enter__.return_value = temp_dir
                        with patch("depshieldx.cli.engine._run_fast_checks") as mock_checks:
                            mock_checks.return_value = (
                                {"block": False, "reason": None, "warnings": [], "infos": []},
                                {"block": False, "reason": None, "warnings": [], "infos": [], "threat_intelligence": {}},
                            )
                            runner = CliRunner()
                            result = runner.invoke(
                                cli,
                                ["scan", "monolog/monolog@3.10.0", "--ecosystem", "composer", "--fast", "--output", "json"],
                            )

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["ecosystem"], "composer")
        self.assertEqual(payload["resolution"]["resolved_versions"]["monolog/monolog"], "3.10.0")

    def test_load_cli_input_honors_ecosystem_composer_flag(self):
        input_source = _load_cli_input(("monolog/monolog@3.10.0",), ecosystem="composer")

        self.assertEqual(input_source.ecosystem, "composer")

    def test_composer_lock_is_auto_detected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "composer.lock"
            lockfile.write_text(json.dumps({"packages": [], "packages-dev": []}), encoding="utf-8")

            input_source = _load_cli_input((), lockfile=str(lockfile))

        self.assertEqual(input_source.ecosystem, "composer")
        self.assertEqual(input_source.source_type, "lockfile")

    @patch("depshieldx.cli.commands.uninstall._run_cli_command")
    def test_uninstall_composer_multiple_targets_with_ecosystem_flag(self, mock_run_cli):
        with patch("depshieldx.ecosystems.composer.ecosystem.resolve_composer_tool", return_value="/usr/local/bin/composer"):
            runner = CliRunner()
            result = runner.invoke(cli, ["uninstall", "monolog/monolog", "psr/log", "--ecosystem", "composer"])

        self.assertEqual(result.exit_code, 0, result.output)
        uninstall_command = mock_run_cli.call_args.args[0]
        self.assertEqual(
            uninstall_command,
            ["/usr/local/bin/composer", "remove", "monolog/monolog", "psr/log", "--no-interaction"],
        )


class RouteComposerTests(unittest.TestCase):
    """Unit coverage for the routing shim's own interception heuristic,
    independent of the CLI, plus CLI-level `route-composer` invocation
    tests -- mirrors test_cli_cargo_routing.py's coverage style, adapted
    for `composer require`'s vendor/package:constraint colon syntax."""

    def test_intercepts_plain_require_single_package(self):
        self.assertEqual(
            _extract_simple_composer_require_targets(["require", "monolog/monolog"]),
            ["monolog/monolog"],
        )

    def test_intercepts_plain_require_multiple_packages(self):
        self.assertEqual(
            _extract_simple_composer_require_targets(["require", "monolog/monolog", "psr/log"]),
            ["monolog/monolog", "psr/log"],
        )

    def test_intercepts_exact_version_constraints(self):
        # A leading "v" is accepted by the shape check but not stripped --
        # it's passed through as-is into the "name@version" target
        # (Composer's own comparator strips leading v/V itself, confirmed
        # directly against its real VersionParser).
        self.assertEqual(
            _extract_simple_composer_require_targets(["require", "monolog/monolog:3.10.0", "psr/log:v3.0.2"]),
            ["monolog/monolog@3.10.0", "psr/log@v3.0.2"],
        )

    def test_does_not_intercept_range_constraints(self):
        # Composer's own "name:constraint" syntax accepts arbitrary
        # ranges/aliases -- depshieldx's "name@version" convention means
        # an exact pin everywhere else in this codebase, so a non-exact
        # shape must bail out entirely rather than silently misrepresent
        # a range as a pin.
        self.assertIsNone(_extract_simple_composer_require_targets(["require", "monolog/monolog:^3.0"]))

    def test_does_not_intercept_branch_alias_constraints(self):
        self.assertIsNone(_extract_simple_composer_require_targets(["require", "monolog/monolog:dev-main"]))

    def test_does_not_intercept_other_composer_commands(self):
        self.assertIsNone(_extract_simple_composer_require_targets(["install"]))
        self.assertIsNone(_extract_simple_composer_require_targets(["remove", "monolog/monolog"]))
        self.assertIsNone(_extract_simple_composer_require_targets([]))

    def test_does_not_intercept_with_other_flags(self):
        self.assertIsNone(_extract_simple_composer_require_targets(["require", "monolog/monolog", "--dev"]))
        self.assertIsNone(_extract_simple_composer_require_targets(["require", "monolog/monolog", "--no-update"]))

    def test_bare_require_returns_none(self):
        self.assertIsNone(_extract_simple_composer_require_targets(["require"]))

    def test_route_composer_requires_single_package_through_depshieldx(self):
        with patch("depshieldx.cli.commands.routing.self_invoke_command") as mock_self_invoke:
            mock_self_invoke.return_value = ["echo", "fake-depshieldx-install"]
            with patch("depshieldx.cli.commands.routing.subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                runner = CliRunner()
                result = runner.invoke(cli, ["route-composer", "require", "monolog/monolog"])

        self.assertEqual(result.exit_code, 0)
        mock_self_invoke.assert_called_once_with(["install", "monolog/monolog", "--ecosystem", "composer"])
        mock_run.assert_called_once_with(["echo", "fake-depshieldx-install"], check=False)

    def test_route_composer_requires_multiple_packages_with_versions_through_depshieldx(self):
        with patch("depshieldx.cli.commands.routing.self_invoke_command") as mock_self_invoke:
            mock_self_invoke.return_value = ["echo", "fake-depshieldx-install"]
            with patch("depshieldx.cli.commands.routing.subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                runner = CliRunner()
                result = runner.invoke(
                    cli, ["route-composer", "require", "monolog/monolog:3.10.0", "psr/log:3.0.2"]
                )

        self.assertEqual(result.exit_code, 0)
        mock_self_invoke.assert_called_once_with(
            ["install", "monolog/monolog@3.10.0", "psr/log@3.0.2", "--ecosystem", "composer"]
        )

    def test_route_composer_passes_through_range_constraint(self):
        with patch("depshieldx.cli.commands.routing.resolve_composer_tool", return_value="/usr/local/bin/composer"):
            with patch("depshieldx.cli.commands.routing.subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                runner = CliRunner()
                result = runner.invoke(cli, ["route-composer", "require", "monolog/monolog:^3.0"])

        self.assertEqual(result.exit_code, 0)
        mock_run.assert_called_once_with(
            ["/usr/local/bin/composer", "require", "monolog/monolog:^3.0"], check=False
        )

    def test_route_composer_passes_through_other_subcommands(self):
        with patch("depshieldx.cli.commands.routing.resolve_composer_tool", return_value="/usr/local/bin/composer"):
            with patch("depshieldx.cli.commands.routing.subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                runner = CliRunner()
                result = runner.invoke(cli, ["route-composer", "install"])

        self.assertEqual(result.exit_code, 0)
        mock_run.assert_called_once_with(["/usr/local/bin/composer", "install"], check=False)


if __name__ == "__main__":
    unittest.main()
