import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from depshieldx.cli import (
    _extract_simple_npm_family_install_targets,
    _is_plain_npm_family_install,
    cli,
)

SAMPLE_PACKAGE_LOCK_JSON = {
    "name": "sample-app",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "requires": True,
    "packages": {
        "": {"name": "sample-app", "version": "1.0.0", "dependencies": {"left-pad": "^1.3.0"}},
        "node_modules/left-pad": {
            "version": "1.3.0",
            "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            "integrity": "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==",
        },
    },
}


class IsPlainNpmFamilyInstallTests(unittest.TestCase):
    def test_plain_install_is_intercepted(self):
        self.assertTrue(_is_plain_npm_family_install(["install"]))
        self.assertTrue(_is_plain_npm_family_install(["i"]))
        self.assertTrue(_is_plain_npm_family_install(["ci"]))

    def test_install_with_flags_only_is_still_intercepted(self):
        self.assertTrue(_is_plain_npm_family_install(["install", "--no-audit"]))

    def test_install_with_named_package_is_not_plain(self):
        # Naming a package is handled separately, by
        # _extract_simple_npm_family_install_targets -- not by this helper.
        self.assertFalse(_is_plain_npm_family_install(["install", "left-pad"]))

    def test_non_install_subcommand_passes_through(self):
        self.assertFalse(_is_plain_npm_family_install(["run", "build"]))

    def test_empty_args_pass_through(self):
        self.assertFalse(_is_plain_npm_family_install([]))


class ExtractSimpleNpmFamilyInstallTargetsTests(unittest.TestCase):
    def test_single_package(self):
        self.assertEqual(_extract_simple_npm_family_install_targets(["install", "left-pad"]), ["left-pad"])

    def test_multiple_packages(self):
        self.assertEqual(
            _extract_simple_npm_family_install_targets(["install", "left-pad", "is-odd"]),
            ["left-pad", "is-odd"],
        )

    def test_scoped_package(self):
        self.assertEqual(_extract_simple_npm_family_install_targets(["install", "@types/node"]), ["@types/node"])

    def test_short_form_i_is_supported(self):
        self.assertEqual(_extract_simple_npm_family_install_targets(["i", "left-pad"]), ["left-pad"])

    def test_ci_is_not_supported(self):
        self.assertIsNone(_extract_simple_npm_family_install_targets(["ci", "left-pad"]))

    def test_bare_install_returns_none(self):
        self.assertIsNone(_extract_simple_npm_family_install_targets(["install"]))

    def test_package_mixed_with_flags_returns_none(self):
        self.assertIsNone(_extract_simple_npm_family_install_targets(["install", "left-pad", "--save-dev"]))

    def test_non_install_subcommand_returns_none(self):
        self.assertIsNone(_extract_simple_npm_family_install_targets(["run", "build"]))

    def test_empty_args_returns_none(self):
        self.assertIsNone(_extract_simple_npm_family_install_targets([]))


class RouteNpmFamilyCommandTests(unittest.TestCase):
    def test_route_npm_installs_through_depshieldx_when_lockfile_present(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "package-lock.json"
            lockfile.write_text(json.dumps(SAMPLE_PACKAGE_LOCK_JSON), encoding="utf-8")

            with patch("depshieldx.cli.Path.cwd", return_value=Path(temp_dir)):
                with patch("depshieldx.cli.self_invoke_command") as mock_self_invoke:
                    mock_self_invoke.return_value = ["echo", "fake-depshieldx-install"]
                    with patch("depshieldx.cli.subprocess.run") as mock_run:
                        mock_run.return_value.returncode = 0
                        runner = CliRunner()
                        result = runner.invoke(cli, ["route-npm", "install"])

        self.assertEqual(result.exit_code, 0)
        mock_self_invoke.assert_called_once_with(["install", "--lockfile", str(lockfile)])
        mock_run.assert_called_once_with(["echo", "fake-depshieldx-install"], check=False)

    def test_route_npm_installs_named_package_through_depshieldx(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            (Path(temp_dir) / "package-lock.json").write_text(json.dumps(SAMPLE_PACKAGE_LOCK_JSON), encoding="utf-8")

            with patch("depshieldx.cli.Path.cwd", return_value=Path(temp_dir)):
                with patch("depshieldx.cli.self_invoke_command") as mock_self_invoke:
                    mock_self_invoke.return_value = ["echo", "fake-depshieldx-install"]
                    with patch("depshieldx.cli.subprocess.run") as mock_run:
                        mock_run.return_value.returncode = 0
                        runner = CliRunner()
                        result = runner.invoke(cli, ["route-npm", "install", "left-pad"])

        self.assertEqual(result.exit_code, 0)
        mock_self_invoke.assert_called_once_with(["install", "left-pad", "--ecosystem", "npm"])
        mock_run.assert_called_once_with(["echo", "fake-depshieldx-install"], check=False)

    def test_route_npm_installs_multiple_named_packages_through_depshieldx(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("depshieldx.cli.Path.cwd", return_value=Path(temp_dir)):
                with patch("depshieldx.cli.self_invoke_command") as mock_self_invoke:
                    mock_self_invoke.return_value = ["echo", "fake-depshieldx-install"]
                    with patch("depshieldx.cli.subprocess.run") as mock_run:
                        mock_run.return_value.returncode = 0
                        runner = CliRunner()
                        result = runner.invoke(cli, ["route-npm", "install", "left-pad", "is-odd"])

        self.assertEqual(result.exit_code, 0)
        mock_self_invoke.assert_called_once_with(["install", "left-pad", "is-odd", "--ecosystem", "npm"])

    def test_route_npm_passes_through_when_naming_a_package_with_flags(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("depshieldx.cli.Path.cwd", return_value=Path(temp_dir)):
                with patch("depshieldx.cli.resolve_node_tool", return_value="/usr/bin/npm"):
                    with patch("depshieldx.cli.subprocess.run") as mock_run:
                        mock_run.return_value.returncode = 0
                        runner = CliRunner()
                        result = runner.invoke(cli, ["route-npm", "install", "left-pad", "--save-dev"])

        self.assertEqual(result.exit_code, 0)
        mock_run.assert_called_once_with(["/usr/bin/npm", "install", "left-pad", "--save-dev"], check=False)

    def test_route_yarn_passes_through_when_naming_a_package(self):
        # Ad-hoc resolution is npm-specific in this phase -- yarn/pnpm named
        # installs still pass through untouched rather than silently
        # switching the user's package manager.
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("depshieldx.cli.Path.cwd", return_value=Path(temp_dir)):
                with patch("depshieldx.cli.resolve_node_tool", return_value="/usr/bin/yarn"):
                    with patch("depshieldx.cli.subprocess.run") as mock_run:
                        mock_run.return_value.returncode = 0
                        runner = CliRunner()
                        result = runner.invoke(cli, ["route-yarn", "install", "left-pad"])

        self.assertEqual(result.exit_code, 0)
        mock_run.assert_called_once_with(["/usr/bin/yarn", "install", "left-pad"], check=False)

    def test_route_npm_passes_through_when_no_lockfile_present(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("depshieldx.cli.Path.cwd", return_value=Path(temp_dir)):
                with patch("depshieldx.cli.resolve_node_tool", return_value="/usr/bin/npm"):
                    with patch("depshieldx.cli.subprocess.run") as mock_run:
                        mock_run.return_value.returncode = 0
                        runner = CliRunner()
                        result = runner.invoke(cli, ["route-npm", "install"])

        self.assertEqual(result.exit_code, 0)
        mock_run.assert_called_once_with(["/usr/bin/npm", "install"], check=False)

    def test_route_yarn_uses_yarn_lock(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "yarn.lock"
            lockfile.write_text("# yarn lockfile v1\n", encoding="utf-8")

            with patch("depshieldx.cli.Path.cwd", return_value=Path(temp_dir)):
                with patch("depshieldx.cli.self_invoke_command") as mock_self_invoke:
                    mock_self_invoke.return_value = ["echo", "fake"]
                    with patch("depshieldx.cli.subprocess.run") as mock_run:
                        mock_run.return_value.returncode = 0
                        runner = CliRunner()
                        result = runner.invoke(cli, ["route-yarn", "install"])

        self.assertEqual(result.exit_code, 0)
        mock_self_invoke.assert_called_once_with(["install", "--lockfile", str(lockfile)])

    def test_route_pnpm_uses_pnpm_lock_yaml(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "pnpm-lock.yaml"
            lockfile.write_text("lockfileVersion: '9.0'\n", encoding="utf-8")

            with patch("depshieldx.cli.Path.cwd", return_value=Path(temp_dir)):
                with patch("depshieldx.cli.self_invoke_command") as mock_self_invoke:
                    mock_self_invoke.return_value = ["echo", "fake"]
                    with patch("depshieldx.cli.subprocess.run") as mock_run:
                        mock_run.return_value.returncode = 0
                        runner = CliRunner()
                        result = runner.invoke(cli, ["route-pnpm", "install"])

        self.assertEqual(result.exit_code, 0)
        mock_self_invoke.assert_called_once_with(["install", "--lockfile", str(lockfile)])


if __name__ == "__main__":
    unittest.main()
