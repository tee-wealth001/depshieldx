import unittest
from unittest.mock import patch

from click.testing import CliRunner

from depshieldx.cli import cli
from depshieldx.cli.commands.routing import _extract_simple_go_get_targets


class ExtractSimpleGoGetTargetsTests(unittest.TestCase):
    def test_single_module(self):
        self.assertEqual(_extract_simple_go_get_targets(["get", "github.com/pkg/errors"]), ["github.com/pkg/errors"])

    def test_multiple_modules(self):
        self.assertEqual(
            _extract_simple_go_get_targets(["get", "github.com/pkg/errors", "golang.org/x/text"]),
            ["github.com/pkg/errors", "golang.org/x/text"],
        )

    def test_versioned_module(self):
        self.assertEqual(
            _extract_simple_go_get_targets(["get", "github.com/pkg/errors@v0.9.1"]),
            ["github.com/pkg/errors@v0.9.1"],
        )

    def test_bare_get_returns_none(self):
        self.assertIsNone(_extract_simple_go_get_targets(["get"]))

    def test_module_mixed_with_flags_returns_none(self):
        self.assertIsNone(_extract_simple_go_get_targets(["get", "github.com/pkg/errors", "-u"]))

    def test_non_get_subcommand_returns_none(self):
        self.assertIsNone(_extract_simple_go_get_targets(["build"]))

    def test_go_install_returns_none(self):
        self.assertIsNone(_extract_simple_go_get_targets(["install", "golang.org/x/tools/cmd/goimports@latest"]))

    def test_empty_args_returns_none(self):
        self.assertIsNone(_extract_simple_go_get_targets([]))


class RouteGoCommandTests(unittest.TestCase):
    def test_route_go_gets_single_module_through_depshieldx(self):
        with patch("depshieldx.cli.commands.routing.self_invoke_command") as mock_self_invoke:
            mock_self_invoke.return_value = ["echo", "fake-depshieldx-install"]
            with patch("depshieldx.cli.commands.routing.subprocess.run") as mock_run:
                with patch("depshieldx.cli.commands.routing.subprocess_env", return_value={"FAKE_ENV": "1"}):
                    mock_run.return_value.returncode = 0
                    runner = CliRunner()
                    result = runner.invoke(cli, ["route-go", "get", "github.com/pkg/errors"])

        self.assertEqual(result.exit_code, 0)
        mock_self_invoke.assert_called_once_with(["install", "github.com/pkg/errors", "--ecosystem", "go"])
        mock_run.assert_called_once_with(["echo", "fake-depshieldx-install"], check=False, env={"FAKE_ENV": "1"})

    def test_route_go_gets_multiple_modules_through_depshieldx(self):
        with patch("depshieldx.cli.commands.routing.self_invoke_command") as mock_self_invoke:
            mock_self_invoke.return_value = ["echo", "fake-depshieldx-install"]
            with patch("depshieldx.cli.commands.routing.subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                runner = CliRunner()
                result = runner.invoke(cli, ["route-go", "get", "github.com/pkg/errors", "golang.org/x/text"])

        self.assertEqual(result.exit_code, 0)
        mock_self_invoke.assert_called_once_with(
            ["install", "github.com/pkg/errors", "golang.org/x/text", "--ecosystem", "go"]
        )

    def test_route_go_passes_through_when_naming_a_module_with_flags(self):
        with patch("depshieldx.cli.commands.routing.resolve_go_tool", return_value="/usr/bin/go"):
            with patch("depshieldx.cli.commands.routing.subprocess.run") as mock_run:
                with patch("depshieldx.cli.commands.routing.subprocess_env", return_value={"FAKE_ENV": "1"}):
                    mock_run.return_value.returncode = 0
                    runner = CliRunner()
                    result = runner.invoke(cli, ["route-go", "get", "github.com/pkg/errors", "-u"])

        self.assertEqual(result.exit_code, 0)
        mock_run.assert_called_once_with(
            ["/usr/bin/go", "get", "github.com/pkg/errors", "-u"], check=False, env={"FAKE_ENV": "1"}
        )

    def test_route_go_passes_through_go_install(self):
        # go install (binary programs) has no depshieldx equivalent and must
        # never be silently rewritten into a dependency-module `install`.
        with patch("depshieldx.cli.commands.routing.resolve_go_tool", return_value="/usr/bin/go"):
            with patch("depshieldx.cli.commands.routing.subprocess.run") as mock_run:
                with patch("depshieldx.cli.commands.routing.subprocess_env", return_value={"FAKE_ENV": "1"}):
                    mock_run.return_value.returncode = 0
                    runner = CliRunner()
                    result = runner.invoke(cli, ["route-go", "install", "golang.org/x/tools/cmd/goimports@latest"])

        self.assertEqual(result.exit_code, 0)
        mock_run.assert_called_once_with(
            ["/usr/bin/go", "install", "golang.org/x/tools/cmd/goimports@latest"],
            check=False,
            env={"FAKE_ENV": "1"},
        )

    def test_route_go_passes_through_other_subcommands(self):
        with patch("depshieldx.cli.commands.routing.resolve_go_tool", return_value="/usr/bin/go"):
            with patch("depshieldx.cli.commands.routing.subprocess.run") as mock_run:
                with patch("depshieldx.cli.commands.routing.subprocess_env", return_value={"FAKE_ENV": "1"}):
                    mock_run.return_value.returncode = 0
                    runner = CliRunner()
                    result = runner.invoke(cli, ["route-go", "build"])

        self.assertEqual(result.exit_code, 0)
        mock_run.assert_called_once_with(["/usr/bin/go", "build"], check=False, env={"FAKE_ENV": "1"})


if __name__ == "__main__":
    unittest.main()
