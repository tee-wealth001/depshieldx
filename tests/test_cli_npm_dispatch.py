import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from depshieldx.cli import cli
from depshieldx.cli.engine import _load_cli_input

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


class CliNpmDispatchTests(unittest.TestCase):
    """Proves the CLI actually routes npm lockfile input to NpmEcosystem end to
    end. The scan test below is marked live (real resolution + provenance/CVE
    lookups against the real npm registry/OSV/GHSA/deps.dev, excluded from the
    default CI run); the --deep/uninstall rejection tests fail fast on a
    UsageError before any network call happens, so they don't need marking."""

    @pytest.mark.live
    def test_scan_with_npm_lockfile_reports_npm_ecosystem_in_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "package-lock.json"
            lockfile.write_text(json.dumps(SAMPLE_PACKAGE_LOCK_JSON), encoding="utf-8")

            runner = CliRunner()
            result = runner.invoke(cli, ["scan", "--lockfile", str(lockfile), "--fast", "--output", "json"])

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["ecosystem"], "npm")
        self.assertEqual(payload["resolution"]["resolved_versions"]["left-pad"], "1.3.0")
        self.assertEqual(payload["resolution"]["package_records"][0]["purl"], "pkg:npm/left-pad@1.3.0")

    @patch("depshieldx.cli.engine.run_sandbox")
    @patch("depshieldx.cli.engine._run_fast_checks")
    def test_scan_deep_runs_sandbox_with_npm_ecosystem_for_npm_lockfile(self, mock_run_fast_checks, mock_run_sandbox):
        from depshieldx.sandbox import SandboxResult

        mock_run_fast_checks.return_value = (
            {"block": False, "reason": None},
            {"block": False, "reason": None},
        )
        mock_run_sandbox.return_value = SandboxResult(
            success=True,
            downloaded_files=["left-pad-1.3.0.tgz"],
            error=None,
            error_type=None,
            isolation={"backend": "docker", "image": "node:20"},
            evidence={},
            static_analysis={"blocked": False, "findings": []},
            bundle=None,
            cache={"hit": False, "fingerprint": "abc"},
            trivy_results={"scanned": True, "should_block": False},
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "package-lock.json"
            lockfile.write_text(json.dumps(SAMPLE_PACKAGE_LOCK_JSON), encoding="utf-8")

            runner = CliRunner()
            result = runner.invoke(cli, ["scan", "--lockfile", str(lockfile), "--deep"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(mock_run_sandbox.called)
        _, call_kwargs = mock_run_sandbox.call_args
        self.assertEqual(call_kwargs["ecosystem"].name, "npm")

    @pytest.mark.live
    def test_scan_bare_package_with_ecosystem_npm_flag(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "left-pad", "--ecosystem", "npm", "--fast", "--output", "json"])

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["ecosystem"], "npm")
        self.assertEqual(payload["resolution"]["source_type"], "package")
        self.assertEqual(payload["resolution"]["resolved_versions"]["left-pad"], "1.3.0")

    def test_load_cli_input_defaults_to_pypi_without_ecosystem_flag(self):
        input_source = _load_cli_input(("some-package",))

        self.assertEqual(input_source.ecosystem, "pypi")

    def test_load_cli_input_honors_ecosystem_npm_flag(self):
        input_source = _load_cli_input(("left-pad",), ecosystem="npm")

        self.assertEqual(input_source.ecosystem, "npm")

    def test_install_rejects_invalid_ecosystem_choice(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["install", "left-pad", "--ecosystem", "cargo"])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Invalid value", result.output)

    def test_uninstall_npm_lockfile_without_package_json_fails_clearly(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "pnpm-lock.yaml"
            lockfile.write_text("lockfileVersion: '9.0'\n", encoding="utf-8")

            runner = CliRunner()
            result = runner.invoke(cli, ["uninstall", "--lockfile", str(lockfile)])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("no package.json found", str(result.output) + str(result.exception))

    @patch("depshieldx.cli.commands.uninstall._run_cli_command")
    def test_uninstall_npm_lockfile_uses_direct_dependencies_from_package_json(self, mock_run_cli):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "package-lock.json"
            lockfile.write_text(json.dumps(SAMPLE_PACKAGE_LOCK_JSON), encoding="utf-8")
            (Path(temp_dir) / "package.json").write_text(
                json.dumps(
                    {
                        "name": "sample-app",
                        "dependencies": {"left-pad": "^1.3.0"},
                        "devDependencies": {"@babel/core": "^8.0.0"},
                    }
                ),
                encoding="utf-8",
            )

            runner = CliRunner()
            result = runner.invoke(cli, ["uninstall", "--lockfile", str(lockfile)])

        self.assertEqual(result.exit_code, 0, result.output)
        uninstall_command = mock_run_cli.call_args.args[0]
        self.assertEqual(uninstall_command[0].lower().endswith(("npm", "npm.cmd")), True)
        self.assertEqual(uninstall_command[1], "uninstall")
        self.assertEqual(set(uninstall_command[2:]), {"left-pad", "@babel/core"})

    @patch("depshieldx.cli.commands.uninstall._run_cli_command")
    def test_uninstall_npm_bare_package_names_with_ecosystem_flag(self, mock_run_cli):
        runner = CliRunner()
        result = runner.invoke(cli, ["uninstall", "left-pad", "@babel/core", "--ecosystem", "npm"])

        self.assertEqual(result.exit_code, 0, result.output)
        uninstall_command = mock_run_cli.call_args.args[0]
        self.assertEqual(uninstall_command[1:], ["uninstall", "left-pad", "@babel/core"])


if __name__ == "__main__":
    unittest.main()
