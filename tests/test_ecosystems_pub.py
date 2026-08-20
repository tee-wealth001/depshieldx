import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from depshieldx.core.resolver import ResolutionResult
from depshieldx.ecosystems import PUB_ECOSYSTEM
from depshieldx.ecosystems.pub.ecosystem import (
    _build_scratch_pubspec,
    _normalize_target_package,
)


class NormalizeTargetPackageTests(unittest.TestCase):
    def test_name_at_version_used_as_is(self):
        self.assertEqual(_normalize_target_package("http@1.6.0"), ("http", "1.6.0"))

    @patch("depshieldx.ecosystems.pub.ecosystem.latest_version", return_value="1.6.0")
    def test_bare_name_resolves_latest_version(self, mock_latest):
        result = _normalize_target_package("http")

        self.assertEqual(result, ("http", "1.6.0"))
        mock_latest.assert_called_once_with("http")

    @patch("depshieldx.ecosystems.pub.ecosystem.latest_version", return_value=None)
    def test_bare_name_raises_when_no_version_found(self, _mock_latest):
        with self.assertRaises(RuntimeError):
            _normalize_target_package("does_not_exist")

    def test_empty_name_raises(self):
        with self.assertRaises(RuntimeError):
            _normalize_target_package("@1.6.0")


class FetchArtifactChecksumTests(unittest.TestCase):
    @patch("depshieldx.ecosystems.pub.ecosystem.requests.get")
    def test_missing_checksum_metadata_raises_instead_of_silently_skipping(self, mock_get):
        mock_get.return_value = MagicMock(content=b"fake-archive-bytes", raise_for_status=lambda: None)
        artifact = {
            "url": "https://pub.dev/api/archives/demo_package-1.0.0.tar.gz",
            "filename": "demo_package-1.0.0.tar.gz",
            "checksum_algorithm": None,
            "checksum": None,
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(RuntimeError):
                PUB_ECOSYSTEM.fetch_artifact(artifact, Path(temp_dir))
            self.assertFalse((Path(temp_dir) / "demo_package-1.0.0.tar.gz").exists())

    def test_missing_url_raises(self):
        artifact = {
            "url": None,
            "filename": "demo_package-1.0.0.tar.gz",
            "checksum_algorithm": "sha256",
            "checksum": "abc123",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(RuntimeError):
                PUB_ECOSYSTEM.fetch_artifact(artifact, Path(temp_dir))

    @patch("depshieldx.ecosystems.pub.ecosystem.requests.get")
    def test_checksum_mismatch_raises(self, mock_get):
        mock_get.return_value = MagicMock(content=b"fake-archive-bytes", raise_for_status=lambda: None)
        artifact = {
            "url": "https://pub.dev/api/archives/demo_package-1.0.0.tar.gz",
            "filename": "demo_package-1.0.0.tar.gz",
            "checksum_algorithm": "sha256",
            "checksum": "not-the-real-hash",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(RuntimeError):
                PUB_ECOSYSTEM.fetch_artifact(artifact, Path(temp_dir))

    @patch("depshieldx.ecosystems.pub.ecosystem.requests.get")
    def test_matching_checksum_writes_the_file(self, mock_get):
        import hashlib

        archive_bytes = b"fake-archive-bytes"
        digest = hashlib.sha256(archive_bytes).hexdigest()
        mock_get.return_value = MagicMock(content=archive_bytes, raise_for_status=lambda: None)
        artifact = {
            "url": "https://pub.dev/api/archives/demo_package-1.0.0.tar.gz",
            "filename": "demo_package-1.0.0.tar.gz",
            "checksum_algorithm": "sha256",
            "checksum": digest,
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            destination = PUB_ECOSYSTEM.fetch_artifact(artifact, Path(temp_dir))
            self.assertTrue(destination.exists())
            self.assertEqual(destination.read_bytes(), archive_bytes)


class BuildScratchPubspecTests(unittest.TestCase):
    def test_includes_every_package_as_exact_pinned_reference(self):
        pubspec = _build_scratch_pubspec([("http", "1.6.0"), ("path", "1.9.1")])

        self.assertIn('http: "1.6.0"', pubspec)
        self.assertIn('path: "1.9.1"', pubspec)
        self.assertIn("environment:", pubspec)
        self.assertIn("dependencies:", pubspec)


class PubAdHocResolveTests(unittest.TestCase):
    @patch("depshieldx.ecosystems.pub.ecosystem.resolve_dart_tool", return_value="/usr/local/bin/dart")
    @patch("depshieldx.ecosystems.pub.ecosystem._run")
    def test_resolve_uses_scratch_pub_get(self, mock_run, _mock_which):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile_path = Path(temp_dir) / "pubspec.lock"
            lockfile_path.write_text(
                "packages:\n"
                "  http:\n"
                "    dependency: \"direct main\"\n"
                "    description:\n"
                "      name: http\n"
                "      sha256: \"87721a4a50b19c7f1d49001e51409bddc46303966ce89a65af4f4e6004896412\"\n"
                "      url: \"https://pub.dev\"\n"
                "    source: hosted\n"
                "    version: \"1.6.0\"\n",
                encoding="utf-8",
            )

            with patch("depshieldx.ecosystems.pub.ecosystem.tempfile.TemporaryDirectory") as mock_tempdir:
                mock_tempdir.return_value.__enter__.return_value = temp_dir
                resolution = PUB_ECOSYSTEM.resolve([], ["http@1.6.0"], "http@1.6.0", source_type="package")

        self.assertTrue(resolution.resolution_succeeded)
        self.assertEqual(resolution.resolved_versions, {"http": "1.6.0"})
        args = mock_run.call_args.args[0]
        self.assertEqual(args[0], "/usr/local/bin/dart")
        self.assertIn("get", args)

    @patch("depshieldx.ecosystems.pub.ecosystem.resolve_dart_tool", return_value="/usr/local/bin/dart")
    @patch("depshieldx.ecosystems.pub.ecosystem._run")
    def test_resolve_reports_dart_failure(self, mock_run, _mock_which):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Because no versions of does_not_exist...")

        resolution = PUB_ECOSYSTEM.resolve([], ["does_not_exist@1.0.0"], "does_not_exist@1.0.0", source_type="package")

        self.assertFalse(resolution.resolution_succeeded)
        self.assertIn("does_not_exist", resolution.resolution_error)

    def test_resolve_reports_error_for_missing_package_targets(self):
        resolution = PUB_ECOSYSTEM.resolve([], [], "unused", source_type="package")

        self.assertFalse(resolution.resolution_succeeded)


class PubToolResolutionTests(unittest.TestCase):
    @patch("depshieldx.ecosystems.pub.ecosystem.shutil.which", return_value=None)
    def test_raises_clear_error_when_dart_not_on_path(self, _mock_which):
        from depshieldx.ecosystems.pub.ecosystem import resolve_dart_tool

        with self.assertRaises(RuntimeError):
            resolve_dart_tool("dart")

    @patch("depshieldx.ecosystems.pub.ecosystem.shutil.which", return_value="/usr/local/bin/dart")
    def test_uninstall_command_supports_multiple_packages(self, _mock_which):
        command = PUB_ECOSYSTEM.uninstall_command(["http", "path"])

        self.assertEqual(command, ["/usr/local/bin/dart", "pub", "remove", "http", "path"])

    @patch("depshieldx.ecosystems.pub.ecosystem.shutil.which", return_value="/usr/local/bin/dart")
    def test_install_command_enforces_lockfile(self, _mock_which):
        command = PUB_ECOSYSTEM.install_command([])

        self.assertEqual(command, ["/usr/local/bin/dart", "pub", "get", "--enforce-lockfile"])


class PubHostInstallCommandTests(unittest.TestCase):
    def _resolution(self, requested_targets, resolved_versions, source_type="package"):
        return ResolutionResult(
            packages=list(resolved_versions.keys()),
            install_target=", ".join(requested_targets),
            resolved_versions=resolved_versions,
            requested_targets=requested_targets,
            source_type=source_type,
        )

    @patch("depshieldx.ecosystems.pub.ecosystem.resolve_dart_tool", return_value="/usr/local/bin/dart")
    @patch.object(PUB_ECOSYSTEM, "fetch_artifact")
    @patch.object(PUB_ECOSYSTEM, "selected_artifact_entries", return_value=[])
    def test_host_install_pins_every_resolved_package_including_transitive(
        self, _mock_entries, _mock_fetch, _mock_which
    ):
        # Unlike NuGet (limited to one package per `dotnet add package`
        # invocation), `dart pub add` accepts multiple packages in one
        # call -- every resolved package, transitive included, is pinned
        # as a direct dependency, mirroring CargoEcosystem's own
        # host_install_command.
        resolution = self._resolution(
            ["http@1.6.0"],
            {"http": "1.6.0", "async": "2.13.1"},
        )

        with PUB_ECOSYSTEM.host_install_command(resolution) as command:
            self.assertEqual(command[:3], ["/usr/local/bin/dart", "pub", "add"])
            self.assertIn("http@1.6.0", command)
            self.assertIn("async@2.13.1", command)


class DirectDependencyNamesForLockfileTests(unittest.TestCase):
    def test_reads_direct_entries_only(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "pubspec.lock"
            lockfile.write_text(
                "packages:\n"
                "  http:\n"
                "    dependency: \"direct main\"\n"
                "    description:\n"
                "      name: http\n"
                "      sha256: \"87721a4a50b19c7f1d49001e51409bddc46303966ce89a65af4f4e6004896412\"\n"
                "      url: \"https://pub.dev\"\n"
                "    source: hosted\n"
                "    version: \"1.6.0\"\n"
                "  async:\n"
                "    dependency: transitive\n"
                "    description:\n"
                "      name: async\n"
                "      sha256: e2eb0491ba5ddb6177742d2da23904574082139b07c1e33b8503b9f46f3e1a37\n"
                "      url: \"https://pub.dev\"\n"
                "    source: hosted\n"
                "    version: \"2.13.1\"\n",
                encoding="utf-8",
            )

            names = PUB_ECOSYSTEM.direct_dependency_names_for_lockfile(str(lockfile))

        self.assertEqual(names, ["http"])


@pytest.mark.live
class PubEcosystemLiveResolveTests(unittest.TestCase):
    """Hits the real pub.dev and shells out to the real `dart` toolchain.
    Marked live -- excluded from the default CI run."""

    def test_resolve_real_package_via_scratch_pub_get(self):
        resolution = PUB_ECOSYSTEM.resolve([], ["http@1.6.0"], "http@1.6.0", source_type="package")

        self.assertTrue(resolution.resolution_succeeded, resolution.resolution_error)
        self.assertEqual(resolution.resolved_versions.get("http"), "1.6.0")

    def test_selected_artifact_entries_and_fetch_artifact_round_trip(self):
        resolution = ResolutionResult(
            packages=["http"],
            install_target="http@1.6.0",
            resolved_versions={"http": "1.6.0"},
        )
        entries = PUB_ECOSYSTEM.selected_artifact_entries(resolution)
        self.assertEqual(len(entries), 1)
        package_name, version, artifact = entries[0]
        self.assertEqual(package_name, "http")
        self.assertEqual(version, "1.6.0")
        self.assertTrue(artifact["url"].endswith(".tar.gz"))

        with tempfile.TemporaryDirectory() as temp_dir:
            destination = PUB_ECOSYSTEM.fetch_artifact(artifact, Path(temp_dir))
            self.assertTrue(destination.exists())
            self.assertGreater(destination.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
