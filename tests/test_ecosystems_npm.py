import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

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


@pytest.mark.live
class NpmEcosystemLiveRegistryTests(unittest.TestCase):
    """Hits the real npm registry. Marked live -- excluded from the default CI
    run (`pytest -m "not live"`) since it depends on a third-party service's
    availability and data, unlike the rest of this suite which mocks network
    calls (see test_provenance.py, test_threat_intel.py)."""

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


class NpmAdHocResolveTests(unittest.TestCase):
    def test_resolve_reports_error_for_missing_package_targets(self):
        resolution = NPM_ECOSYSTEM.resolve([], [], "unused", source_type="package")

        self.assertFalse(resolution.resolution_succeeded)

    @patch("depshieldx.ecosystems.NpmEcosystem._resolve_via_npm_registry")
    def test_resolve_single_package_uses_registry_resolution(self, mock_resolve):
        mock_resolve.return_value = {"left-pad": "1.3.0"}

        resolution = NPM_ECOSYSTEM.resolve([], ["left-pad"], "left-pad", source_type="package")

        mock_resolve.assert_called_once_with(["left-pad"])
        self.assertTrue(resolution.resolution_succeeded)
        self.assertEqual(resolution.packages, ["left-pad"])
        self.assertEqual(resolution.resolved_versions, {"left-pad": "1.3.0"})
        self.assertEqual(resolution.source_type, "package")

    @patch("depshieldx.ecosystems.NpmEcosystem._resolve_via_npm_registry")
    def test_resolve_multiple_packages_uses_registry_resolution(self, mock_resolve):
        mock_resolve.return_value = {"left-pad": "1.3.0", "is-odd": "3.0.1"}

        resolution = NPM_ECOSYSTEM.resolve(
            [], ["left-pad", "is-odd"], "left-pad, is-odd", source_type="packages"
        )

        mock_resolve.assert_called_once_with(["left-pad", "is-odd"])
        self.assertTrue(resolution.resolution_succeeded)
        self.assertCountEqual(resolution.packages, ["left-pad", "is-odd"])

    @patch("depshieldx.ecosystems.NpmEcosystem._resolve_via_npm_registry")
    def test_resolve_reports_registry_failure(self, mock_resolve):
        mock_resolve.side_effect = RuntimeError("npm could not resolve does-not-exist-xyz: 404 Not Found")

        resolution = NPM_ECOSYSTEM.resolve([], ["does-not-exist-xyz"], "does-not-exist-xyz", source_type="package")

        self.assertFalse(resolution.resolution_succeeded)
        self.assertIn("does-not-exist-xyz", resolution.resolution_error)


@pytest.mark.live
class NpmAdHocLiveResolveTests(unittest.TestCase):
    """Hits the real npm registry via a throwaway temp project, verifying the
    exact command shape (--package-lock-only without --dry-run) still writes
    a real, parseable lockfile -- see NpmEcosystem._resolve_via_npm_registry's
    docstring for why --dry-run was found to suppress the lockfile entirely."""

    def test_resolve_single_ad_hoc_package_against_real_registry(self):
        resolution = NPM_ECOSYSTEM.resolve([], ["left-pad"], "left-pad", source_type="package")

        self.assertTrue(resolution.resolution_succeeded)
        self.assertEqual(resolution.resolved_versions["left-pad"], "1.3.0")


class NpmHostInstallCommandTests(unittest.TestCase):
    """host_install_command must pin ad-hoc package installs to the exact
    scanned version (npm install <name>@<version>) rather than a bare
    "npm install", which would silently do nothing for a brand-new package
    not already listed in the cwd's package.json."""

    def _resolution(self, source_type, requested_targets, resolved_versions):
        from depshieldx.resolver import ResolutionResult

        return ResolutionResult(
            packages=list(resolved_versions.keys()),
            install_target=", ".join(requested_targets),
            resolved_versions=resolved_versions,
            requested_targets=requested_targets,
            source_type=source_type,
        )

    @patch("depshieldx.ecosystems.shutil.which", return_value="/usr/local/bin/npm")
    @patch.object(NPM_ECOSYSTEM, "fetch_artifact")
    @patch.object(NPM_ECOSYSTEM, "selected_artifact_entries", return_value=[])
    def test_ad_hoc_single_package_install_is_pinned(self, _mock_entries, _mock_fetch, _mock_which):
        resolution = self._resolution("package", ["left-pad"], {"left-pad": "1.3.0"})

        with NPM_ECOSYSTEM.host_install_command(resolution) as command:
            self.assertEqual(command, ["/usr/local/bin/npm", "install", "left-pad@1.3.0"])

    @patch("depshieldx.ecosystems.shutil.which", return_value="/usr/local/bin/npm")
    @patch.object(NPM_ECOSYSTEM, "fetch_artifact")
    @patch.object(NPM_ECOSYSTEM, "selected_artifact_entries", return_value=[])
    def test_ad_hoc_multi_package_install_is_pinned(self, _mock_entries, _mock_fetch, _mock_which):
        resolution = self._resolution(
            "packages", ["left-pad", "is-odd"], {"left-pad": "1.3.0", "is-odd": "3.0.1"}
        )

        with NPM_ECOSYSTEM.host_install_command(resolution) as command:
            self.assertEqual(command, ["/usr/local/bin/npm", "install", "left-pad@1.3.0", "is-odd@3.0.1"])

    @patch("depshieldx.ecosystems.shutil.which", return_value="/usr/local/bin/npm")
    @patch.object(NPM_ECOSYSTEM, "fetch_artifact")
    @patch.object(NPM_ECOSYSTEM, "selected_artifact_entries", return_value=[])
    def test_ad_hoc_scoped_package_install_is_pinned(self, _mock_entries, _mock_fetch, _mock_which):
        resolution = self._resolution("package", ["@babel/core"], {"@babel/core": "8.0.1"})

        with NPM_ECOSYSTEM.host_install_command(resolution) as command:
            self.assertEqual(command, ["/usr/local/bin/npm", "install", "@babel/core@8.0.1"])

    @patch("depshieldx.ecosystems.shutil.which", return_value="/usr/local/bin/npm")
    @patch.object(NPM_ECOSYSTEM, "fetch_artifact")
    @patch.object(NPM_ECOSYSTEM, "selected_artifact_entries", return_value=[])
    def test_lockfile_install_stays_bare(self, _mock_entries, _mock_fetch, _mock_which):
        resolution = self._resolution("lockfile", ["package-lock.json"], {"left-pad": "1.3.0"})

        with NPM_ECOSYSTEM.host_install_command(resolution) as command:
            self.assertEqual(command, ["/usr/local/bin/npm", "install"])


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
