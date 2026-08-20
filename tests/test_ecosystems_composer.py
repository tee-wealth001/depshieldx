import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from depshieldx.core.resolver import ResolutionResult
from depshieldx.ecosystems import COMPOSER_ECOSYSTEM
from depshieldx.ecosystems.composer.ecosystem import (
    _normalize_target_package,
    _to_composer_require_arg,
)


class NormalizeTargetPackageTests(unittest.TestCase):
    def test_name_at_version_used_as_is(self):
        self.assertEqual(_normalize_target_package("monolog/monolog@3.10.0"), ("monolog/monolog", "3.10.0"))

    def test_bare_name_has_no_version(self):
        # Unlike Pub/RubyGems, no separate registry lookup happens here
        # -- a bare target's version resolution is deferred entirely to
        # `composer require` itself (confirmed directly it resolves and
        # pins the latest stable release on its own).
        self.assertEqual(_normalize_target_package("monolog/monolog"), ("monolog/monolog", None))

    def test_empty_name_raises(self):
        with self.assertRaises(RuntimeError):
            _normalize_target_package("@3.10.0")


class ToComposerRequireArgTests(unittest.TestCase):
    def test_with_version_uses_colon_syntax(self):
        self.assertEqual(_to_composer_require_arg("monolog/monolog", "3.10.0"), "monolog/monolog:3.10.0")

    def test_without_version_is_bare_name(self):
        self.assertEqual(_to_composer_require_arg("monolog/monolog", None), "monolog/monolog")


class FetchArtifactChecksumTests(unittest.TestCase):
    @patch("depshieldx.ecosystems.composer.ecosystem.requests.get")
    def test_missing_checksum_writes_the_file_unverified(self, mock_get):
        # Unlike every other ecosystem here, a missing checksum is
        # Composer's own normal reality (see registry.py's module
        # docstring), not refused on -- the file is still written,
        # pinned by git reference alone.
        mock_get.return_value = MagicMock(content=b"fake-archive-bytes", raise_for_status=lambda: None)
        artifact = {
            "url": "https://api.github.com/repos/demo/package/zipball/abc123",
            "filename": "demo-package-1.0.0.zip",
            "checksum_algorithm": None,
            "checksum": None,
            "reference": "abc123",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            destination = COMPOSER_ECOSYSTEM.fetch_artifact(artifact, Path(temp_dir))
            self.assertTrue(destination.exists())
            self.assertEqual(destination.read_bytes(), b"fake-archive-bytes")

    def test_missing_url_raises(self):
        artifact = {"url": None, "filename": "demo-package-1.0.0.zip", "checksum_algorithm": None, "checksum": None}
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(RuntimeError):
                COMPOSER_ECOSYSTEM.fetch_artifact(artifact, Path(temp_dir))

    @patch("depshieldx.ecosystems.composer.ecosystem.requests.get")
    def test_checksum_mismatch_raises_when_a_real_shasum_is_published(self, mock_get):
        mock_get.return_value = MagicMock(content=b"fake-archive-bytes", raise_for_status=lambda: None)
        artifact = {
            "url": "https://example.com/demo-package-1.0.0.zip",
            "filename": "demo-package-1.0.0.zip",
            "checksum_algorithm": "sha1",
            "checksum": "not-the-real-hash",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(RuntimeError):
                COMPOSER_ECOSYSTEM.fetch_artifact(artifact, Path(temp_dir))

    @patch("depshieldx.ecosystems.composer.ecosystem.requests.get")
    def test_matching_checksum_writes_the_file(self, mock_get):
        import hashlib

        archive_bytes = b"fake-archive-bytes"
        digest = hashlib.sha1(archive_bytes).hexdigest()
        mock_get.return_value = MagicMock(content=archive_bytes, raise_for_status=lambda: None)
        artifact = {
            "url": "https://example.com/demo-package-1.0.0.zip",
            "filename": "demo-package-1.0.0.zip",
            "checksum_algorithm": "sha1",
            "checksum": digest,
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            destination = COMPOSER_ECOSYSTEM.fetch_artifact(artifact, Path(temp_dir))
            self.assertTrue(destination.exists())
            self.assertEqual(destination.read_bytes(), archive_bytes)


class ComposerAdHocResolveTests(unittest.TestCase):
    @patch("depshieldx.ecosystems.composer.ecosystem.resolve_composer_tool", return_value="/usr/local/bin/composer")
    @patch("depshieldx.ecosystems.composer.ecosystem._run")
    def test_resolve_uses_scratch_composer_require(self, mock_run, _mock_which):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile_path = Path(temp_dir) / "composer.lock"
            lockfile_path.write_text(
                json.dumps({"packages": [{"name": "monolog/monolog", "version": "3.10.0"}], "packages-dev": []}),
                encoding="utf-8",
            )

            with patch("depshieldx.ecosystems.composer.ecosystem.tempfile.TemporaryDirectory") as mock_tempdir:
                mock_tempdir.return_value.__enter__.return_value = temp_dir
                resolution = COMPOSER_ECOSYSTEM.resolve(
                    [], ["monolog/monolog@3.10.0"], "monolog/monolog@3.10.0", source_type="package"
                )

        self.assertTrue(resolution.resolution_succeeded)
        self.assertEqual(resolution.resolved_versions, {"monolog/monolog": "3.10.0"})
        args = mock_run.call_args.args[0]
        self.assertEqual(args[0], "/usr/local/bin/composer")
        self.assertIn("require", args)
        self.assertIn("monolog/monolog:3.10.0", args)
        self.assertIn("--no-install", args)
        self.assertIn("--no-plugins", args)
        self.assertIn("--no-scripts", args)

    @patch("depshieldx.ecosystems.composer.ecosystem.resolve_composer_tool", return_value="/usr/local/bin/composer")
    @patch("depshieldx.ecosystems.composer.ecosystem._run")
    def test_resolve_reports_composer_failure(self, mock_run, _mock_which):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Your requirements could not be resolved...")

        resolution = COMPOSER_ECOSYSTEM.resolve(
            [], ["does-not/exist@1.0.0"], "does-not/exist@1.0.0", source_type="package"
        )

        self.assertFalse(resolution.resolution_succeeded)
        self.assertIn("does-not/exist", resolution.resolution_error)

    def test_resolve_reports_error_for_missing_package_targets(self):
        resolution = COMPOSER_ECOSYSTEM.resolve([], [], "unused", source_type="package")

        self.assertFalse(resolution.resolution_succeeded)


class ComposerToolResolutionTests(unittest.TestCase):
    @patch("depshieldx.ecosystems.composer.ecosystem.shutil.which", return_value=None)
    def test_raises_clear_error_when_composer_not_on_path(self, _mock_which):
        from depshieldx.ecosystems.composer.ecosystem import resolve_composer_tool

        with self.assertRaises(RuntimeError):
            resolve_composer_tool("composer")

    @patch("depshieldx.ecosystems.composer.ecosystem.shutil.which", return_value="/usr/local/bin/composer")
    def test_uninstall_command_supports_multiple_packages(self, _mock_which):
        command = COMPOSER_ECOSYSTEM.uninstall_command(["monolog/monolog", "psr/log"])

        self.assertEqual(command, ["/usr/local/bin/composer", "remove", "monolog/monolog", "psr/log", "--no-interaction"])

    @patch("depshieldx.ecosystems.composer.ecosystem.shutil.which", return_value="/usr/local/bin/composer")
    def test_install_command_disables_plugins_and_scripts(self, _mock_which):
        command = COMPOSER_ECOSYSTEM.install_command([])

        self.assertEqual(
            command, ["/usr/local/bin/composer", "install", "--no-interaction", "--no-plugins", "--no-scripts"]
        )


class ComposerHostInstallCommandTests(unittest.TestCase):
    def _resolution(self, requested_targets, resolved_versions, source_type="package"):
        return ResolutionResult(
            packages=list(resolved_versions.keys()),
            install_target=", ".join(requested_targets),
            resolved_versions=resolved_versions,
            requested_targets=requested_targets,
            source_type=source_type,
        )

    @patch("depshieldx.ecosystems.composer.ecosystem.resolve_composer_tool", return_value="/usr/local/bin/composer")
    @patch.object(COMPOSER_ECOSYSTEM, "fetch_artifact")
    @patch.object(COMPOSER_ECOSYSTEM, "selected_artifact_entries", return_value=[])
    def test_host_install_pins_every_resolved_package_in_one_call(self, _mock_entries, _mock_fetch, _mock_which):
        # Unlike RubyGemsEcosystem (bundle add's one-shared-version-per-
        # call limitation), a real `composer require pkg1:v1 pkg2:v2` is
        # confirmed directly to accept multiple independently-versioned
        # targets in a single call -- every resolved package, transitive
        # included, is pinned as a direct dependency in one real
        # invocation, mirroring CargoEcosystem's own host_install_command.
        resolution = self._resolution(
            ["monolog/monolog@3.10.0"],
            {"monolog/monolog": "3.10.0", "psr/log": "3.0.2"},
        )

        with COMPOSER_ECOSYSTEM.host_install_command(resolution) as command:
            self.assertEqual(command[:2], ["/usr/local/bin/composer", "require"])
            self.assertIn("monolog/monolog:3.10.0", command)
            self.assertIn("psr/log:3.0.2", command)
            self.assertIn("--no-plugins", command)
            self.assertIn("--no-scripts", command)


class DirectDependencyNamesForLockfileTests(unittest.TestCase):
    def test_reads_require_and_require_dev_only(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest = Path(temp_dir) / "composer.json"
            manifest.write_text(
                json.dumps(
                    {
                        "name": "test/scratch",
                        "require": {"php": ">=8.1", "monolog/monolog": "3.10.0"},
                        "require-dev": {"phpunit/phpunit": "^11.0"},
                    }
                ),
                encoding="utf-8",
            )
            lockfile = Path(temp_dir) / "composer.lock"
            lockfile.write_text(
                json.dumps(
                    {
                        "packages": [{"name": "monolog/monolog", "version": "3.10.0"}, {"name": "psr/log", "version": "3.0.2"}],
                        "packages-dev": [{"name": "phpunit/phpunit", "version": "11.0.0"}],
                    }
                ),
                encoding="utf-8",
            )

            names = COMPOSER_ECOSYSTEM.direct_dependency_names_for_lockfile(str(lockfile))

        self.assertEqual(sorted(names), ["monolog/monolog", "phpunit/phpunit"])
        self.assertNotIn("psr/log", names)
        self.assertNotIn("php", names)

    def test_raises_when_sibling_manifest_is_missing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "composer.lock"
            lockfile.write_text(json.dumps({"packages": [], "packages-dev": []}), encoding="utf-8")

            with self.assertRaises(RuntimeError):
                COMPOSER_ECOSYSTEM.direct_dependency_names_for_lockfile(str(lockfile))


@pytest.mark.live
class ComposerEcosystemLiveResolveTests(unittest.TestCase):
    """Hits the real Packagist and shells out to the real `composer`
    toolchain. Marked live -- excluded from the default CI run."""

    def test_resolve_real_package_via_scratch_composer_require(self):
        resolution = COMPOSER_ECOSYSTEM.resolve(
            [], ["monolog/monolog@3.10.0"], "monolog/monolog@3.10.0", source_type="package"
        )

        self.assertTrue(resolution.resolution_succeeded, resolution.resolution_error)
        self.assertEqual(resolution.resolved_versions.get("monolog/monolog"), "3.10.0")

    def test_selected_artifact_entries_and_fetch_artifact_round_trip(self):
        resolution = ResolutionResult(
            packages=["monolog/monolog"],
            install_target="monolog/monolog@3.10.0",
            resolved_versions={"monolog/monolog": "3.10.0"},
        )
        entries = COMPOSER_ECOSYSTEM.selected_artifact_entries(resolution)
        self.assertEqual(len(entries), 1)
        package_name, version, artifact = entries[0]
        self.assertEqual(package_name, "monolog/monolog")
        self.assertEqual(version, "3.10.0")
        self.assertTrue(artifact["url"])

        with tempfile.TemporaryDirectory() as temp_dir:
            destination = COMPOSER_ECOSYSTEM.fetch_artifact(artifact, Path(temp_dir))
            self.assertTrue(destination.exists())
            self.assertGreater(destination.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
