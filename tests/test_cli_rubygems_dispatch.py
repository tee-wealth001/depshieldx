import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from depshieldx.cli import cli
from depshieldx.cli.engine import _load_cli_input
from depshieldx.cli.commands.routing import _extract_simple_bundle_add_targets


class CliRubyGemsDispatchTests(unittest.TestCase):
    """Proves the CLI actually routes package_name[@version] targets and
    Gemfile.lock input to RubyGemsEcosystem end to end, mirroring
    test_cli_pub_dispatch.py's coverage for Pub. The real-toolchain scan
    test is marked live; the rest are offline."""

    @pytest.mark.live
    def test_scan_bare_target_with_ecosystem_rubygems_flag(self):
        # 2.21.2 confirmed directly to have no reported CVEs at the time
        # this test was written, unlike the older 2.9.0 used elsewhere in
        # this file for shape-only (mocked) assertions -- a version with
        # real vulnerabilities would legitimately block the scan (exit
        # code 10), which isn't what this test is checking.
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["scan", "json@2.21.2", "--ecosystem", "rubygems", "--fast", "--output", "json"],
        )

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["ecosystem"], "rubygems")
        self.assertEqual(payload["resolution"]["source_type"], "package")
        self.assertIn("json", payload["resolution"]["resolved_versions"])

    def test_scan_bare_target_reports_rubygems_ecosystem(self):
        fake_result = MagicMock(returncode=0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile_path = Path(temp_dir) / "Gemfile.lock"
            lockfile_path.write_text(
                "GEM\n"
                "  remote: https://rubygems.org/\n"
                "  specs:\n"
                "    json (2.9.0)\n"
                "\n"
                "PLATFORMS\n"
                "  x64-mingw-ucrt\n"
                "\n"
                "DEPENDENCIES\n"
                "  json (= 2.9.0)\n"
                "\n"
                "BUNDLED WITH\n"
                "   4.0.16\n",
                encoding="utf-8",
            )
            with patch("depshieldx.ecosystems.rubygems.ecosystem.resolve_bundle_tool", return_value="/usr/local/bin/bundle"):
                with patch("depshieldx.ecosystems.rubygems.ecosystem._run", return_value=fake_result):
                    with patch("depshieldx.ecosystems.rubygems.ecosystem.tempfile.TemporaryDirectory") as mock_tempdir:
                        mock_tempdir.return_value.__enter__.return_value = temp_dir
                        with patch("depshieldx.cli.engine._run_fast_checks") as mock_checks:
                            mock_checks.return_value = (
                                {"block": False, "reason": None, "warnings": [], "infos": []},
                                {"block": False, "reason": None, "warnings": [], "infos": [], "threat_intelligence": {}},
                            )
                            runner = CliRunner()
                            result = runner.invoke(
                                cli,
                                ["scan", "json@2.9.0", "--ecosystem", "rubygems", "--fast", "--output", "json"],
                            )

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["ecosystem"], "rubygems")
        self.assertEqual(payload["resolution"]["resolved_versions"]["json"], "2.9.0")

    def test_load_cli_input_honors_ecosystem_rubygems_flag(self):
        input_source = _load_cli_input(("json@2.9.0",), ecosystem="rubygems")

        self.assertEqual(input_source.ecosystem, "rubygems")

    def test_gemfile_lock_is_auto_detected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "Gemfile.lock"
            lockfile.write_text("GEM\n  remote: https://rubygems.org/\n  specs:\n\nBUNDLED WITH\n   4.0.16\n", encoding="utf-8")

            input_source = _load_cli_input((), lockfile=str(lockfile))

        self.assertEqual(input_source.ecosystem, "rubygems")
        self.assertEqual(input_source.source_type, "lockfile")

    @patch("depshieldx.cli.commands.uninstall._run_cli_command")
    def test_uninstall_rubygems_multiple_targets_with_ecosystem_flag(self, mock_run_cli):
        with patch("depshieldx.ecosystems.rubygems.ecosystem.resolve_bundle_tool", return_value="/usr/local/bin/bundle"):
            runner = CliRunner()
            result = runner.invoke(cli, ["uninstall", "rack", "json", "--ecosystem", "rubygems"])

        self.assertEqual(result.exit_code, 0, result.output)
        uninstall_command = mock_run_cli.call_args.args[0]
        self.assertEqual(uninstall_command, ["/usr/local/bin/bundle", "remove", "rack", "json"])


class RouteBundleTests(unittest.TestCase):
    """Unit coverage for the routing shim's own interception heuristic,
    independent of the CLI -- mirrors test_cli_pub_dispatch.py's
    RouteDartTests coverage style, adapted for `bundle add`'s different
    (shared single --version across multiple gems) CLI shape."""

    def test_intercepts_plain_bundle_add_single_gem(self):
        self.assertEqual(_extract_simple_bundle_add_targets(["add", "rack"]), ["rack"])

    def test_intercepts_plain_bundle_add_multiple_gems(self):
        self.assertEqual(
            _extract_simple_bundle_add_targets(["add", "rack", "json"]),
            ["rack", "json"],
        )

    def test_intercepts_single_gem_with_version_flag(self):
        self.assertEqual(
            _extract_simple_bundle_add_targets(["add", "rack", "--version", "3.2.7"]),
            ["rack@3.2.7"],
        )

    def test_does_not_intercept_multiple_gems_with_shared_version_flag(self):
        # `bundle add rack json --version 3.2.7` would apply the SAME
        # version to both (confirmed directly) -- not a safe target to
        # rewrite into per-gem depshieldx targets, so this passes through.
        self.assertIsNone(_extract_simple_bundle_add_targets(["add", "rack", "json", "--version", "3.2.7"]))

    def test_does_not_intercept_other_bundle_commands(self):
        self.assertIsNone(_extract_simple_bundle_add_targets(["install"]))
        self.assertIsNone(_extract_simple_bundle_add_targets(["remove", "rack"]))
        self.assertIsNone(_extract_simple_bundle_add_targets([]))

    def test_does_not_intercept_with_other_flags(self):
        self.assertIsNone(_extract_simple_bundle_add_targets(["add", "rack", "--skip-install"]))
        self.assertIsNone(_extract_simple_bundle_add_targets(["add", "rack", "--group", "test"]))


if __name__ == "__main__":
    unittest.main()
