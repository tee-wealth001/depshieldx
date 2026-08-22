import unittest
from unittest.mock import patch

from click.testing import CliRunner

from depshieldx.cli import cli
from depshieldx.cli.output import EXIT_BLOCKED, EXIT_OK

_OK_ENVIRONMENT = {
    "block": False,
    "reason": None,
    "python": {"version": "3.11.4", "required": "Python>=3.11.4", "ok": True},
    "pip": {"version": "25.3", "required": "pip>=25.3", "ok": True, "error": None},
}

_BLOCKED_ENVIRONMENT = {
    "block": True,
    "reason": "requires Python>=3.11.4 (running 3.10.0)",
    "python": {"version": "3.10.0", "required": "Python>=3.11.4", "ok": False},
    "pip": {"version": "25.3", "required": "pip>=25.3", "ok": True, "error": None},
}


def _patch_all_toolchains_ok():
    return [
        patch(f"depshieldx.cli.commands.doctor.{name}", return_value="/usr/bin/tool")
        for name in (
            "resolve_cargo_tool",
            "resolve_composer_tool",
            "resolve_go_tool",
            "resolve_maven_tool",
            "resolve_node_tool",
            "resolve_dotnet_tool",
            "resolve_dart_tool",
            "resolve_bundle_tool",
        )
    ]


class DoctorCommandTests(unittest.TestCase):
    def test_all_checks_passing_exits_ok(self):
        patches = _patch_all_toolchains_ok()
        for p in patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in patches])

        with patch("depshieldx.cli.commands.doctor._runtime_environment_report", return_value=_OK_ENVIRONMENT):
            with patch("depshieldx.cli.commands.doctor._docker_daemon_available", return_value=(True, None)):
                with patch("depshieldx.cli.commands.doctor._is_trivy_installed", return_value=True):
                    result = CliRunner().invoke(cli, ["doctor"])

        self.assertEqual(result.exit_code, EXIT_OK)
        self.assertIn("Python 3.11.4", result.output)
        self.assertNotIn("MISSING", result.output)

    def test_missing_ecosystem_toolchain_is_reported_but_not_blocking(self):
        patches = _patch_all_toolchains_ok()
        for p in patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in patches])

        with patch("depshieldx.cli.commands.doctor._runtime_environment_report", return_value=_OK_ENVIRONMENT):
            with patch("depshieldx.cli.commands.doctor._docker_daemon_available", return_value=(True, None)):
                with patch("depshieldx.cli.commands.doctor._is_trivy_installed", return_value=True):
                    with patch(
                        "depshieldx.cli.commands.doctor.resolve_dart_tool",
                        side_effect=RuntimeError("'dart' was not found on PATH."),
                    ):
                        result = CliRunner().invoke(cli, ["doctor"])

        self.assertEqual(result.exit_code, EXIT_OK)
        self.assertIn("pub (dart)", result.output)
        self.assertIn("MISSING", result.output)
        self.assertIn("'dart' was not found on PATH.", result.output)

    def test_docker_and_trivy_unavailable_are_reported_but_not_blocking(self):
        patches = _patch_all_toolchains_ok()
        for p in patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in patches])

        with patch("depshieldx.cli.commands.doctor._runtime_environment_report", return_value=_OK_ENVIRONMENT):
            with patch(
                "depshieldx.cli.commands.doctor._docker_daemon_available",
                return_value=(False, "Docker CLI not found."),
            ):
                with patch("depshieldx.cli.commands.doctor._is_trivy_installed", return_value=False):
                    result = CliRunner().invoke(cli, ["doctor"])

        self.assertEqual(result.exit_code, EXIT_OK)
        self.assertIn("Docker CLI not found.", result.output)
        self.assertIn("Trivy", result.output)

    def test_blocked_runtime_environment_exits_blocked(self):
        patches = _patch_all_toolchains_ok()
        for p in patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in patches])

        with patch("depshieldx.cli.commands.doctor._runtime_environment_report", return_value=_BLOCKED_ENVIRONMENT):
            with patch("depshieldx.cli.commands.doctor._docker_daemon_available", return_value=(True, None)):
                with patch("depshieldx.cli.commands.doctor._is_trivy_installed", return_value=True):
                    result = CliRunner().invoke(cli, ["doctor"])

        self.assertEqual(result.exit_code, EXIT_BLOCKED)
        self.assertIn("Blocked:", result.output)


if __name__ == "__main__":
    unittest.main()
