import json
import tempfile
import unittest
from pathlib import Path

from click.testing import CliRunner

from depshieldx.cli import cli

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
    end -- real resolution, real provenance/CVE lookups against the live npm
    registry and OSV/GHSA/deps.dev, matching this suite's existing pattern of
    verifying real API behavior rather than only mocking."""

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

    def test_install_deep_rejected_for_npm_lockfile(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "package-lock.json"
            lockfile.write_text(json.dumps(SAMPLE_PACKAGE_LOCK_JSON), encoding="utf-8")

            runner = CliRunner()
            result = runner.invoke(cli, ["install", "--lockfile", str(lockfile), "--deep"])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not supported yet", str(result.output) + str(result.exception))

    def test_scan_deep_rejected_for_npm_lockfile(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "yarn.lock"
            lockfile.write_text("# yarn lockfile v1\n", encoding="utf-8")

            runner = CliRunner()
            result = runner.invoke(cli, ["scan", "--lockfile", str(lockfile), "--deep"])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not supported yet", str(result.output) + str(result.exception))

    def test_uninstall_rejected_for_npm_lockfile(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "pnpm-lock.yaml"
            lockfile.write_text("lockfileVersion: '9.0'\n", encoding="utf-8")

            runner = CliRunner()
            result = runner.invoke(cli, ["uninstall", "--lockfile", str(lockfile)])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not supported yet", str(result.output) + str(result.exception))


if __name__ == "__main__":
    unittest.main()
