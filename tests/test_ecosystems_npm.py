import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from depshieldx.ecosystems import NPM_ECOSYSTEM

# A minimal, real-shaped package-lock.json (lockfileVersion 3), matching the format
# verified against actual npm 11 output during development -- see final-plan.md Phase 1.
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
        "node_modules/@babel/core": {
            "version": "8.0.1",
            "resolved": "https://registry.npmjs.org/@babel/core/-/core-8.0.1.tgz",
            "integrity": "sha512-5FgxM4dLQpMJHSiVATk8foW263dVHQHBVpXYiimNECVWG01f4nFyEbQixeT6Mwvg7TayREJ2gpKl3o2RoMdnqw==",
        },
    },
}


class NpmEcosystemResolveTests(unittest.TestCase):
    def test_resolve_from_package_lock_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "package-lock.json"
            lockfile.write_text(json.dumps(SAMPLE_PACKAGE_LOCK_JSON), encoding="utf-8")

            resolution = NPM_ECOSYSTEM.resolve([], [str(lockfile)], str(lockfile), source_type="lockfile")

        self.assertTrue(resolution.resolution_succeeded)
        self.assertEqual(resolution.resolved_versions["left-pad"], "1.3.0")
        self.assertEqual(resolution.resolved_versions["@babel/core"], "8.0.1")
        self.assertIn("left-pad", resolution.packages)

    def test_resolve_reports_error_for_missing_lockfile_target(self):
        resolution = NPM_ECOSYSTEM.resolve([], [], "unused", source_type="package")

        self.assertFalse(resolution.resolution_succeeded)
        self.assertIn("lockfile", resolution.resolution_error)

    def test_resolve_reports_error_for_unparseable_lockfile(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "package-lock.json"
            lockfile.write_text("{not valid json", encoding="utf-8")

            resolution = NPM_ECOSYSTEM.resolve([], [str(lockfile)], str(lockfile), source_type="lockfile")

        self.assertFalse(resolution.resolution_succeeded)
        self.assertIsNotNone(resolution.resolution_error)


class NpmEcosystemLiveRegistryTests(unittest.TestCase):
    """Hits the real npm registry, matching this suite's existing pattern of
    verifying against real PyPI/provenance data rather than only mocks."""

    def test_check_provenance_reports_real_structural_signals(self):
        result = NPM_ECOSYSTEM.check_provenance({"left-pad": "1.3.0"})

        self.assertFalse(result["block"])
        detail = result["details"][0]
        self.assertEqual(detail["package"], "left-pad")
        self.assertFalse(detail["signals"]["has_attestations"])
        self.assertTrue(detail["signals"]["deprecated"])

    def test_selected_artifact_entries_and_fetch_artifact_round_trip(self):
        from depshieldx.resolver import ResolutionResult

        resolution = ResolutionResult(
            packages=["left-pad"],
            install_target="left-pad@1.3.0",
            resolved_versions={"left-pad": "1.3.0"},
        )
        entries = NPM_ECOSYSTEM.selected_artifact_entries(resolution)
        self.assertEqual(len(entries), 1)
        package_name, version, artifact = entries[0]
        self.assertEqual(package_name, "left-pad")
        self.assertEqual(version, "1.3.0")
        self.assertTrue(artifact["url"].endswith(".tgz"))
        self.assertTrue(artifact["integrity"].startswith("sha512-"))

        with tempfile.TemporaryDirectory() as temp_dir:
            destination = NPM_ECOSYSTEM.fetch_artifact(artifact, Path(temp_dir))
            self.assertTrue(destination.exists())
            self.assertGreater(destination.stat().st_size, 0)


class NpmToolResolutionTests(unittest.TestCase):
    """Regression coverage for a real bug: subprocess.run(["npm", ...]) fails on
    Windows with WinError 2 even when npm is genuinely installed, because npm
    ships as npm.cmd and Python's subprocess (unlike a shell) won't find a .cmd
    shim from a bare "npm" argument."""

    @patch("depshieldx.ecosystems.shutil.which", return_value=r"C:\Program Files\nodejs\npm.cmd")
    def test_install_command_uses_resolved_path_not_bare_name(self, mock_which):
        command = NPM_ECOSYSTEM.install_command([])

        mock_which.assert_called_with("npm")
        self.assertEqual(command[0], r"C:\Program Files\nodejs\npm.cmd")
        self.assertNotEqual(command[0], "npm")

    @patch("depshieldx.ecosystems.shutil.which", return_value="/usr/local/bin/npm")
    def test_uninstall_command_uses_resolved_path(self, _mock_which):
        command = NPM_ECOSYSTEM.uninstall_command(["left-pad"])

        self.assertEqual(command, ["/usr/local/bin/npm", "uninstall", "left-pad"])

    @patch("depshieldx.ecosystems.shutil.which", return_value=None)
    def test_raises_clear_error_when_npm_not_on_path(self, _mock_which):
        with self.assertRaises(RuntimeError):
            NPM_ECOSYSTEM.install_command([])


if __name__ == "__main__":
    unittest.main()
