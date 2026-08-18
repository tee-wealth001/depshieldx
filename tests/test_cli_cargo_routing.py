import unittest
from unittest.mock import patch

from click.testing import CliRunner

from depshieldx.cli import cli
from depshieldx.cli.commands.routing import _extract_simple_cargo_add_targets


class ExtractSimpleCargoAddTargetsTests(unittest.TestCase):
    def test_single_crate(self):
        self.assertEqual(_extract_simple_cargo_add_targets(["add", "serde"]), ["serde"])

    def test_multiple_crates(self):
        self.assertEqual(_extract_simple_cargo_add_targets(["add", "serde", "tokio"]), ["serde", "tokio"])

    def test_versioned_crate(self):
        self.assertEqual(_extract_simple_cargo_add_targets(["add", "serde@1.0"]), ["serde@1.0"])

    def test_bare_add_returns_none(self):
        self.assertIsNone(_extract_simple_cargo_add_targets(["add"]))

    def test_crate_mixed_with_flags_returns_none(self):
        self.assertIsNone(_extract_simple_cargo_add_targets(["add", "serde", "--dev"]))

    def test_non_add_subcommand_returns_none(self):
        self.assertIsNone(_extract_simple_cargo_add_targets(["build"]))

    def test_cargo_install_returns_none(self):
        self.assertIsNone(_extract_simple_cargo_add_targets(["install", "ripgrep"]))

    def test_empty_args_returns_none(self):
        self.assertIsNone(_extract_simple_cargo_add_targets([]))


class RouteCargoCommandTests(unittest.TestCase):
    def test_route_cargo_adds_single_crate_through_depshieldx(self):
        with patch("depshieldx.cli.commands.routing.self_invoke_command") as mock_self_invoke:
            mock_self_invoke.return_value = ["echo", "fake-depshieldx-install"]
            with patch("depshieldx.cli.commands.routing.subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                runner = CliRunner()
                result = runner.invoke(cli, ["route-cargo", "add", "serde"])

        self.assertEqual(result.exit_code, 0)
        mock_self_invoke.assert_called_once_with(["install", "serde", "--ecosystem", "cargo"])
        mock_run.assert_called_once_with(["echo", "fake-depshieldx-install"], check=False)

    def test_route_cargo_adds_multiple_crates_through_depshieldx(self):
        with patch("depshieldx.cli.commands.routing.self_invoke_command") as mock_self_invoke:
            mock_self_invoke.return_value = ["echo", "fake-depshieldx-install"]
            with patch("depshieldx.cli.commands.routing.subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                runner = CliRunner()
                result = runner.invoke(cli, ["route-cargo", "add", "serde", "tokio"])

        self.assertEqual(result.exit_code, 0)
        mock_self_invoke.assert_called_once_with(["install", "serde", "tokio", "--ecosystem", "cargo"])

    def test_route_cargo_passes_through_when_naming_a_crate_with_flags(self):
        with patch("depshieldx.cli.commands.routing.resolve_cargo_tool", return_value="/usr/bin/cargo"):
            with patch("depshieldx.cli.commands.routing.subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                runner = CliRunner()
                result = runner.invoke(cli, ["route-cargo", "add", "serde", "--dev"])

        self.assertEqual(result.exit_code, 0)
        mock_run.assert_called_once_with(["/usr/bin/cargo", "add", "serde", "--dev"], check=False)

    def test_route_cargo_passes_through_cargo_install(self):
        # cargo install (binary crates) has no depshieldx equivalent and must
        # never be silently rewritten into a dependency-crate `install`.
        with patch("depshieldx.cli.commands.routing.resolve_cargo_tool", return_value="/usr/bin/cargo"):
            with patch("depshieldx.cli.commands.routing.subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                runner = CliRunner()
                result = runner.invoke(cli, ["route-cargo", "install", "ripgrep"])

        self.assertEqual(result.exit_code, 0)
        mock_run.assert_called_once_with(["/usr/bin/cargo", "install", "ripgrep"], check=False)

    def test_route_cargo_passes_through_other_subcommands(self):
        with patch("depshieldx.cli.commands.routing.resolve_cargo_tool", return_value="/usr/bin/cargo"):
            with patch("depshieldx.cli.commands.routing.subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                runner = CliRunner()
                result = runner.invoke(cli, ["route-cargo", "build"])

        self.assertEqual(result.exit_code, 0)
        mock_run.assert_called_once_with(["/usr/bin/cargo", "build"], check=False)


if __name__ == "__main__":
    unittest.main()
