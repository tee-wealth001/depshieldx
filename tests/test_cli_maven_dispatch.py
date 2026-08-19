import json
import unittest
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from depshieldx.cli import cli
from depshieldx.cli.engine import _load_cli_input


class CliMavenDispatchTests(unittest.TestCase):
    """Proves the CLI actually routes groupId:artifactId[:version]
    coordinate input to MavenEcosystem end to end, mirroring
    test_cli_go_dispatch.py's coverage for go. The real-toolchain scan
    test is marked live; the rest are offline."""

    @pytest.mark.live
    def test_scan_coordinate_with_ecosystem_maven_flag(self):
        # 3.18.0 is the real fixed release for CVE-2025-48924 (confirmed
        # directly against a real OSV query) -- an unaffected version is
        # used here so this test asserts on ecosystem routing, not on
        # today's vulnerability data for a specific old release.
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                "org.apache.commons:commons-lang3:3.18.0",
                "--ecosystem",
                "maven",
                "--fast",
                "--output",
                "json",
            ],
        )

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["ecosystem"], "maven")
        self.assertEqual(payload["resolution"]["source_type"], "package")
        self.assertIn("org.apache.commons:commons-lang3", payload["resolution"]["resolved_versions"])

    def test_scan_bare_coordinate_reports_maven_ecosystem(self):
        fake_result = MagicMock(
            returncode=0,
            stdout="[INFO]    org.apache.commons:commons-lang3:jar:3.17.0:compile -- module org.apache.commons.lang3\n",
            stderr="",
        )
        with patch("depshieldx.ecosystems.maven.ecosystem.resolve_maven_tool", return_value="/usr/local/bin/mvn"):
            with patch("depshieldx.ecosystems.maven.ecosystem._run", return_value=fake_result):
                with patch("depshieldx.cli.engine._run_fast_checks") as mock_checks:
                    mock_checks.return_value = (
                        {"block": False, "reason": None, "warnings": [], "infos": []},
                        {"block": False, "reason": None, "warnings": [], "infos": [], "threat_intelligence": {}},
                    )
                    runner = CliRunner()
                    result = runner.invoke(
                        cli,
                        [
                            "scan",
                            "org.apache.commons:commons-lang3:3.17.0",
                            "--ecosystem",
                            "maven",
                            "--fast",
                            "--output",
                            "json",
                        ],
                    )

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["ecosystem"], "maven")
        self.assertEqual(payload["resolution"]["resolved_versions"]["org.apache.commons:commons-lang3"], "3.17.0")

    def test_load_cli_input_honors_ecosystem_maven_flag(self):
        input_source = _load_cli_input(("org.apache.commons:commons-lang3:3.17.0",), ecosystem="maven")

        self.assertEqual(input_source.ecosystem, "maven")

    @patch("depshieldx.cli.commands.uninstall._run_cli_command")
    def test_uninstall_maven_coordinate_fails_clearly_with_no_equivalent(self, mock_run_cli):
        with patch("depshieldx.ecosystems.maven.ecosystem.resolve_maven_tool", return_value="/usr/local/bin/mvn"):
            runner = CliRunner()
            result = runner.invoke(
                cli, ["uninstall", "org.apache.commons:commons-lang3", "--ecosystem", "maven"]
            )

        self.assertNotEqual(result.exit_code, 0)
        mock_run_cli.assert_not_called()
        self.assertIn("no uninstall equivalent", str(result.output) + str(result.exception))


if __name__ == "__main__":
    unittest.main()
