import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from depshieldx.core.resolver import ResolutionResult
from depshieldx.ecosystems import RUBYGEMS_ECOSYSTEM
from depshieldx.ecosystems.rubygems.ecosystem import (
    _build_scratch_gemfile,
    _normalize_target_package,
)


class NormalizeTargetPackageTests(unittest.TestCase):
    def test_name_at_version_used_as_is(self):
        self.assertEqual(_normalize_target_package("rack@3.2.7"), ("rack", "3.2.7"))

    @patch("depshieldx.ecosystems.rubygems.ecosystem.latest_version", return_value="3.2.7")
    def test_bare_name_resolves_latest_version(self, mock_latest):
        result = _normalize_target_package("rack")

        self.assertEqual(result, ("rack", "3.2.7"))
        mock_latest.assert_called_once_with("rack")

    @patch("depshieldx.ecosystems.rubygems.ecosystem.latest_version", return_value=None)
    def test_bare_name_raises_when_no_version_found(self, _mock_latest):
        with self.assertRaises(RuntimeError):
            _normalize_target_package("does_not_exist")

    def test_empty_name_raises(self):
        with self.assertRaises(RuntimeError):
            _normalize_target_package("@3.2.7")


class FetchArtifactChecksumTests(unittest.TestCase):
    @patch("depshieldx.ecosystems.rubygems.ecosystem.requests.get")
    def test_missing_checksum_metadata_raises_instead_of_silently_skipping(self, mock_get):
        mock_get.return_value = MagicMock(content=b"fake-archive-bytes", raise_for_status=lambda: None)
        artifact = {
            "url": "https://rubygems.org/gems/demo_gem-1.0.0.gem",
            "filename": "demo_gem-1.0.0.gem",
            "checksum_algorithm": None,
            "checksum": None,
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(RuntimeError):
                RUBYGEMS_ECOSYSTEM.fetch_artifact(artifact, Path(temp_dir))
            self.assertFalse((Path(temp_dir) / "demo_gem-1.0.0.gem").exists())

    def test_missing_url_raises(self):
        artifact = {
            "url": None,
            "filename": "demo_gem-1.0.0.gem",
            "checksum_algorithm": "sha256",
            "checksum": "abc123",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(RuntimeError):
                RUBYGEMS_ECOSYSTEM.fetch_artifact(artifact, Path(temp_dir))

    @patch("depshieldx.ecosystems.rubygems.ecosystem.requests.get")
    def test_checksum_mismatch_raises(self, mock_get):
        mock_get.return_value = MagicMock(content=b"fake-archive-bytes", raise_for_status=lambda: None)
        artifact = {
            "url": "https://rubygems.org/gems/demo_gem-1.0.0.gem",
            "filename": "demo_gem-1.0.0.gem",
            "checksum_algorithm": "sha256",
            "checksum": "not-the-real-hash",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(RuntimeError):
                RUBYGEMS_ECOSYSTEM.fetch_artifact(artifact, Path(temp_dir))

    @patch("depshieldx.ecosystems.rubygems.ecosystem.requests.get")
    def test_matching_checksum_writes_the_file(self, mock_get):
        import hashlib

        archive_bytes = b"fake-archive-bytes"
        digest = hashlib.sha256(archive_bytes).hexdigest()
        mock_get.return_value = MagicMock(content=archive_bytes, raise_for_status=lambda: None)
        artifact = {
            "url": "https://rubygems.org/gems/demo_gem-1.0.0.gem",
            "filename": "demo_gem-1.0.0.gem",
            "checksum_algorithm": "sha256",
            "checksum": digest,
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            destination = RUBYGEMS_ECOSYSTEM.fetch_artifact(artifact, Path(temp_dir))
            self.assertTrue(destination.exists())
            self.assertEqual(destination.read_bytes(), archive_bytes)


class BuildScratchGemfileTests(unittest.TestCase):
    def test_includes_every_package_as_exact_pinned_reference(self):
        gemfile = _build_scratch_gemfile([("rack", "3.2.7"), ("json", "2.9.0")])

        self.assertIn('gem "rack", "3.2.7"', gemfile)
        self.assertIn('gem "json", "2.9.0"', gemfile)
        self.assertIn('source "https://rubygems.org"', gemfile)


class RubyGemsAdHocResolveTests(unittest.TestCase):
    @patch("depshieldx.ecosystems.rubygems.ecosystem.resolve_bundle_tool", return_value="/usr/local/bin/bundle")
    @patch("depshieldx.ecosystems.rubygems.ecosystem._run")
    def test_resolve_uses_scratch_bundle_lock(self, mock_run, _mock_which):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile_path = Path(temp_dir) / "Gemfile.lock"
            lockfile_path.write_text(
                "GEM\n"
                "  remote: https://rubygems.org/\n"
                "  specs:\n"
                "    rack (3.2.7)\n"
                "\n"
                "PLATFORMS\n"
                "  x64-mingw-ucrt\n"
                "\n"
                "DEPENDENCIES\n"
                "  rack (= 3.2.7)\n"
                "\n"
                "BUNDLED WITH\n"
                "   4.0.16\n",
                encoding="utf-8",
            )

            with patch("depshieldx.ecosystems.rubygems.ecosystem.tempfile.TemporaryDirectory") as mock_tempdir:
                mock_tempdir.return_value.__enter__.return_value = temp_dir
                resolution = RUBYGEMS_ECOSYSTEM.resolve([], ["rack@3.2.7"], "rack@3.2.7", source_type="package")

        self.assertTrue(resolution.resolution_succeeded)
        self.assertEqual(resolution.resolved_versions, {"rack": "3.2.7"})
        args = mock_run.call_args.args[0]
        self.assertEqual(args[0], "/usr/local/bin/bundle")
        self.assertIn("lock", args)

    @patch("depshieldx.ecosystems.rubygems.ecosystem.resolve_bundle_tool", return_value="/usr/local/bin/bundle")
    @patch("depshieldx.ecosystems.rubygems.ecosystem._run")
    def test_resolve_reports_bundle_failure(self, mock_run, _mock_which):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Could not find gem 'does_not_exist'...")

        resolution = RUBYGEMS_ECOSYSTEM.resolve(
            [], ["does_not_exist@1.0.0"], "does_not_exist@1.0.0", source_type="package"
        )

        self.assertFalse(resolution.resolution_succeeded)
        self.assertIn("does_not_exist", resolution.resolution_error)

    def test_resolve_reports_error_for_missing_package_targets(self):
        resolution = RUBYGEMS_ECOSYSTEM.resolve([], [], "unused", source_type="package")

        self.assertFalse(resolution.resolution_succeeded)


class RubyGemsToolResolutionTests(unittest.TestCase):
    @patch("depshieldx.ecosystems.rubygems.ecosystem.shutil.which", return_value=None)
    def test_raises_clear_error_when_bundle_not_on_path(self, _mock_which):
        from depshieldx.ecosystems.rubygems.ecosystem import resolve_bundle_tool

        with self.assertRaises(RuntimeError):
            resolve_bundle_tool("bundle")

    @patch("depshieldx.ecosystems.rubygems.ecosystem.shutil.which", return_value="/usr/local/bin/bundle")
    def test_uninstall_command_supports_multiple_packages(self, _mock_which):
        command = RUBYGEMS_ECOSYSTEM.uninstall_command(["rack", "json"])

        self.assertEqual(command, ["/usr/local/bin/bundle", "remove", "rack", "json"])

    @patch("depshieldx.ecosystems.rubygems.ecosystem.subprocess.run")
    @patch("depshieldx.ecosystems.rubygems.ecosystem.shutil.which", return_value="/usr/local/bin/bundle")
    def test_install_command_sets_frozen_config_then_returns_install(self, _mock_which, mock_run):
        command = RUBYGEMS_ECOSYSTEM.install_command([])

        self.assertEqual(command, ["/usr/local/bin/bundle", "install"])
        config_call = mock_run.call_args.args[0]
        self.assertEqual(config_call, ["/usr/local/bin/bundle", "config", "set", "frozen", "true"])


class RubyGemsHostInstallCommandTests(unittest.TestCase):
    def _resolution(self, requested_targets, resolved_versions, source_type="package"):
        return ResolutionResult(
            packages=list(resolved_versions.keys()),
            install_target=", ".join(requested_targets),
            resolved_versions=resolved_versions,
            requested_targets=requested_targets,
            source_type=source_type,
        )

    @patch("depshieldx.ecosystems.rubygems.ecosystem.resolve_bundle_tool", return_value="/usr/local/bin/bundle")
    @patch.object(RUBYGEMS_ECOSYSTEM, "fetch_artifact")
    @patch.object(RUBYGEMS_ECOSYSTEM, "selected_artifact_entries", return_value=[])
    def test_single_resolved_package_yields_one_bundle_add_call(self, _mock_entries, _mock_fetch, _mock_which):
        resolution = self._resolution(["rack@3.2.7"], {"rack": "3.2.7"})

        with RUBYGEMS_ECOSYSTEM.host_install_command(resolution) as command:
            self.assertEqual(
                command, ["/usr/local/bin/bundle", "add", "rack", "--version", "3.2.7"]
            )

    @patch("depshieldx.ecosystems.rubygems.ecosystem.subprocess.run")
    @patch("depshieldx.ecosystems.rubygems.ecosystem.resolve_bundle_tool", return_value="/usr/local/bin/bundle")
    @patch.object(RUBYGEMS_ECOSYSTEM, "fetch_artifact")
    @patch.object(RUBYGEMS_ECOSYSTEM, "selected_artifact_entries", return_value=[])
    def test_multiple_resolved_packages_pin_every_gem_via_separate_calls(
        self, _mock_entries, _mock_fetch, _mock_which, mock_run
    ):
        # `bundle add` can't pin more than one independently-resolved
        # exact version in a single call (confirmed directly) -- every
        # resolved gem, transitive included, still gets pinned via one
        # real `bundle add <gem> --version <v>` call each; all but the
        # last run as a real side effect here, only the last is yielded.
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        resolution = self._resolution(["rack@3.2.7"], {"rack": "3.2.7", "json": "2.9.0"})

        with RUBYGEMS_ECOSYSTEM.host_install_command(resolution) as command:
            self.assertEqual(command, ["/usr/local/bin/bundle", "add", "json", "--version", "2.9.0"])

        side_effect_call = mock_run.call_args_list[0].args[0]
        self.assertEqual(side_effect_call, ["/usr/local/bin/bundle", "add", "rack", "--version", "3.2.7"])

    @patch("depshieldx.ecosystems.rubygems.ecosystem.subprocess.run")
    @patch("depshieldx.ecosystems.rubygems.ecosystem.resolve_bundle_tool", return_value="/usr/local/bin/bundle")
    @patch.object(RUBYGEMS_ECOSYSTEM, "fetch_artifact")
    @patch.object(RUBYGEMS_ECOSYSTEM, "selected_artifact_entries", return_value=[])
    def test_side_effect_failure_raises_before_yielding(self, _mock_entries, _mock_fetch, _mock_which, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="could not resolve")
        resolution = self._resolution(["rack@3.2.7"], {"rack": "3.2.7", "json": "2.9.0"})

        with self.assertRaises(RuntimeError):
            with RUBYGEMS_ECOSYSTEM.host_install_command(resolution):
                pass


class DirectDependencyNamesForLockfileTests(unittest.TestCase):
    def test_reads_dependencies_section_only(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "Gemfile.lock"
            lockfile.write_text(
                "GEM\n"
                "  remote: https://rubygems.org/\n"
                "  specs:\n"
                "    rack-test (2.1.0)\n"
                "      rack (>= 1.3)\n"
                "    rack (3.2.7)\n"
                "\n"
                "PLATFORMS\n"
                "  x64-mingw-ucrt\n"
                "\n"
                "DEPENDENCIES\n"
                "  rack-test (= 2.1.0)\n"
                "\n"
                "BUNDLED WITH\n"
                "   4.0.16\n",
                encoding="utf-8",
            )

            names = RUBYGEMS_ECOSYSTEM.direct_dependency_names_for_lockfile(str(lockfile))

        self.assertEqual(names, ["rack-test"])


@pytest.mark.live
class RubyGemsEcosystemLiveResolveTests(unittest.TestCase):
    """Hits the real rubygems.org and shells out to the real `bundle`
    toolchain. Marked live -- excluded from the default CI run."""

    def test_resolve_real_package_via_scratch_bundle_lock(self):
        resolution = RUBYGEMS_ECOSYSTEM.resolve([], ["json@2.9.0"], "json@2.9.0", source_type="package")

        self.assertTrue(resolution.resolution_succeeded, resolution.resolution_error)
        self.assertEqual(resolution.resolved_versions.get("json"), "2.9.0")

    def test_selected_artifact_entries_and_fetch_artifact_round_trip(self):
        resolution = ResolutionResult(
            packages=["json"],
            install_target="json@2.9.0",
            resolved_versions={"json": "2.9.0"},
        )
        entries = RUBYGEMS_ECOSYSTEM.selected_artifact_entries(resolution)
        self.assertEqual(len(entries), 1)
        package_name, version, artifact = entries[0]
        self.assertEqual(package_name, "json")
        self.assertEqual(version, "2.9.0")
        self.assertTrue(artifact["url"].endswith(".gem"))

        with tempfile.TemporaryDirectory() as temp_dir:
            destination = RUBYGEMS_ECOSYSTEM.fetch_artifact(artifact, Path(temp_dir))
            self.assertTrue(destination.exists())
            self.assertGreater(destination.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
