import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from depshieldx.core.resolver import ResolutionResult
from depshieldx.ecosystems import NUGET_ECOSYSTEM
from depshieldx.ecosystems.nuget.ecosystem import (
    _build_scratch_csproj,
    _normalize_target_package,
)


class NormalizeTargetPackageTests(unittest.TestCase):
    def test_name_at_version_used_as_is(self):
        self.assertEqual(_normalize_target_package("Newtonsoft.Json@13.0.3"), ("Newtonsoft.Json", "13.0.3"))

    @patch("depshieldx.ecosystems.nuget.ecosystem.search_latest_version", return_value="13.0.4")
    def test_bare_name_resolves_latest_version(self, mock_search):
        result = _normalize_target_package("Newtonsoft.Json")

        self.assertEqual(result, ("Newtonsoft.Json", "13.0.4"))
        mock_search.assert_called_once_with("Newtonsoft.Json")

    @patch("depshieldx.ecosystems.nuget.ecosystem.search_latest_version", return_value=None)
    def test_bare_name_raises_when_no_version_found(self, _mock_search):
        with self.assertRaises(RuntimeError):
            _normalize_target_package("Does.Not.Exist")

    def test_empty_name_raises(self):
        with self.assertRaises(RuntimeError):
            _normalize_target_package("@13.0.3")


class FetchArtifactChecksumTests(unittest.TestCase):
    """A real mismatch already raised before this fix (see
    module docstring history); this covers the previously-silent case
    where checksum metadata is simply missing -- fetch_artifact used to
    write the bytes to disk completely unverified, with zero signal."""

    @patch("depshieldx.ecosystems.nuget.ecosystem.requests.get")
    def test_missing_checksum_metadata_raises_instead_of_silently_skipping(self, mock_get):
        mock_get.return_value = MagicMock(content=b"fake-nupkg-bytes", raise_for_status=lambda: None)
        artifact = {
            "url": "https://api.nuget.org/v3-flatcontainer/demo/1.0.0/demo.1.0.0.nupkg",
            "filename": "demo.1.0.0.nupkg",
            "checksum_algorithm": None,
            "checksum": None,
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(RuntimeError):
                NUGET_ECOSYSTEM.fetch_artifact(artifact, Path(temp_dir))
            self.assertFalse((Path(temp_dir) / "demo.1.0.0.nupkg").exists())

    @patch("depshieldx.ecosystems.nuget.ecosystem.requests.get")
    def test_checksum_mismatch_raises(self, mock_get):
        mock_get.return_value = MagicMock(content=b"fake-nupkg-bytes", raise_for_status=lambda: None)
        artifact = {
            "url": "https://api.nuget.org/v3-flatcontainer/demo/1.0.0/demo.1.0.0.nupkg",
            "filename": "demo.1.0.0.nupkg",
            "checksum_algorithm": "SHA512",
            "checksum": "not-the-real-hash",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(RuntimeError):
                NUGET_ECOSYSTEM.fetch_artifact(artifact, Path(temp_dir))

    @patch("depshieldx.ecosystems.nuget.ecosystem.requests.get")
    def test_matching_checksum_writes_the_file(self, mock_get):
        import base64
        import hashlib

        artifact_bytes = b"fake-nupkg-bytes"
        digest = hashlib.sha512(artifact_bytes).digest()
        mock_get.return_value = MagicMock(content=artifact_bytes, raise_for_status=lambda: None)
        artifact = {
            "url": "https://api.nuget.org/v3-flatcontainer/demo/1.0.0/demo.1.0.0.nupkg",
            "filename": "demo.1.0.0.nupkg",
            "checksum_algorithm": "SHA512",
            "checksum": base64.b64encode(digest).decode("ascii"),
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            destination = NUGET_ECOSYSTEM.fetch_artifact(artifact, Path(temp_dir))
            self.assertTrue(destination.exists())
            self.assertEqual(destination.read_bytes(), artifact_bytes)


class BuildScratchCsprojTests(unittest.TestCase):
    def test_includes_every_package_as_exact_pinned_reference(self):
        csproj = _build_scratch_csproj([("Newtonsoft.Json", "13.0.3")])

        self.assertIn('Include="Newtonsoft.Json"', csproj)
        self.assertIn('Version="[13.0.3]"', csproj)
        self.assertIn("<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>", csproj)

    def test_escapes_xml_special_characters(self):
        csproj = _build_scratch_csproj([("A<B&C", "1.0.0")])

        self.assertIn("A&lt;B&amp;C", csproj)
        self.assertNotIn("A<B&C", csproj)


class NuGetAdHocResolveTests(unittest.TestCase):
    @patch("depshieldx.ecosystems.nuget.ecosystem.resolve_dotnet_tool", return_value="/usr/local/bin/dotnet")
    @patch("depshieldx.ecosystems.nuget.ecosystem._run")
    def test_resolve_uses_scratch_restore(self, mock_run, _mock_which):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile_path = Path(temp_dir) / "packages.lock.json"
            lockfile_path.write_text(
                '{"version": 1, "dependencies": {"net8.0": {"Newtonsoft.Json": '
                '{"type": "Direct", "resolved": "13.0.3"}}}}',
                encoding="utf-8",
            )

            with patch("depshieldx.ecosystems.nuget.ecosystem.tempfile.TemporaryDirectory") as mock_tempdir:
                mock_tempdir.return_value.__enter__.return_value = temp_dir
                resolution = NUGET_ECOSYSTEM.resolve(
                    [], ["Newtonsoft.Json@13.0.3"], "Newtonsoft.Json@13.0.3", source_type="package"
                )

        self.assertTrue(resolution.resolution_succeeded)
        self.assertEqual(resolution.resolved_versions, {"Newtonsoft.Json": "13.0.3"})
        args = mock_run.call_args.args[0]
        self.assertEqual(args[0], "/usr/local/bin/dotnet")
        self.assertIn("restore", args)

    @patch("depshieldx.ecosystems.nuget.ecosystem.resolve_dotnet_tool", return_value="/usr/local/bin/dotnet")
    @patch("depshieldx.ecosystems.nuget.ecosystem._run")
    def test_resolve_reports_dotnet_failure(self, mock_run, _mock_which):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error NU1101: Unable to find package")

        resolution = NUGET_ECOSYSTEM.resolve(
            [], ["Does.Not.Exist@1.0.0"], "Does.Not.Exist@1.0.0", source_type="package"
        )

        self.assertFalse(resolution.resolution_succeeded)
        self.assertIn("NU1101", resolution.resolution_error)

    def test_resolve_reports_error_for_missing_package_targets(self):
        resolution = NUGET_ECOSYSTEM.resolve([], [], "unused", source_type="package")

        self.assertFalse(resolution.resolution_succeeded)


class NuGetToolResolutionTests(unittest.TestCase):
    @patch("depshieldx.ecosystems.nuget.ecosystem.shutil.which", return_value=None)
    def test_raises_clear_error_when_dotnet_not_on_path(self, _mock_which):
        from depshieldx.ecosystems.nuget.ecosystem import resolve_dotnet_tool

        with self.assertRaises(RuntimeError):
            resolve_dotnet_tool("dotnet")

    @patch("depshieldx.ecosystems.nuget.ecosystem.shutil.which", return_value="/usr/local/bin/dotnet")
    def test_uninstall_command_uses_dotnet_remove(self, _mock_which):
        command = NUGET_ECOSYSTEM.uninstall_command(["Serilog"])

        self.assertEqual(command, ["/usr/local/bin/dotnet", "remove", "package", "Serilog"])

    def test_uninstall_command_raises_for_multiple_packages(self):
        with self.assertRaises(RuntimeError):
            NUGET_ECOSYSTEM.uninstall_command(["Serilog", "Newtonsoft.Json"])

    @patch("depshieldx.ecosystems.nuget.ecosystem.shutil.which", return_value="/usr/local/bin/dotnet")
    def test_install_command_uses_locked_mode(self, _mock_which):
        command = NUGET_ECOSYSTEM.install_command([])

        self.assertEqual(command, ["/usr/local/bin/dotnet", "restore", "--locked-mode"])


class NuGetHostInstallCommandTests(unittest.TestCase):
    def _resolution(self, requested_targets, resolved_versions, source_type="package"):
        return ResolutionResult(
            packages=list(resolved_versions.keys()),
            install_target=", ".join(requested_targets),
            resolved_versions=resolved_versions,
            requested_targets=requested_targets,
            source_type=source_type,
        )

    @patch("depshieldx.ecosystems.nuget.ecosystem.resolve_dotnet_tool", return_value="/usr/local/bin/dotnet")
    @patch.object(NUGET_ECOSYSTEM, "fetch_artifact")
    @patch.object(NUGET_ECOSYSTEM, "selected_artifact_entries", return_value=[])
    def test_host_install_delegates_to_real_dotnet_add_package_for_one_target(
        self, _mock_entries, _mock_fetch, _mock_which
    ):
        resolution = self._resolution(["Serilog@4.2.0"], {"Serilog": "4.2.0"})

        with NUGET_ECOSYSTEM.host_install_command(resolution) as command:
            self.assertEqual(
                command,
                ["/usr/local/bin/dotnet", "add", "package", "Serilog", "--version", "[4.2.0]"],
            )

    @patch("depshieldx.ecosystems.nuget.ecosystem.resolve_dotnet_tool", return_value="/usr/local/bin/dotnet")
    @patch.object(NUGET_ECOSYSTEM, "fetch_artifact")
    @patch.object(NUGET_ECOSYSTEM, "selected_artifact_entries", return_value=[])
    def test_host_install_raises_for_multiple_requested_targets(self, _mock_entries, _mock_fetch, _mock_which):
        resolution = self._resolution(
            ["Serilog@4.2.0", "Newtonsoft.Json@13.0.3"],
            {"Serilog": "4.2.0", "Newtonsoft.Json": "13.0.3"},
        )

        with self.assertRaises(RuntimeError):
            with NUGET_ECOSYSTEM.host_install_command(resolution):
                pass


class DirectDependencyNamesForLockfileTests(unittest.TestCase):
    def test_reads_direct_type_entries_only(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "packages.lock.json"
            lockfile.write_text(
                """{
                    "version": 1,
                    "dependencies": {
                        "net8.0": {
                            "Serilog": {"type": "Direct", "resolved": "4.2.0"},
                            "System.Runtime": {"type": "Transitive", "resolved": "4.3.1"}
                        }
                    }
                }""",
                encoding="utf-8",
            )

            names = NUGET_ECOSYSTEM.direct_dependency_names_for_lockfile(str(lockfile))

        self.assertEqual(names, ["Serilog"])
        self.assertNotIn("System.Runtime", names)


@pytest.mark.live
class NuGetEcosystemLiveResolveTests(unittest.TestCase):
    """Hits the real api.nuget.org and shells out to the real `dotnet`
    toolchain. Marked live -- excluded from the default CI run."""

    def test_resolve_real_package_via_scratch_restore(self):
        resolution = NUGET_ECOSYSTEM.resolve(
            [], ["Newtonsoft.Json@13.0.3"], "Newtonsoft.Json@13.0.3", source_type="package"
        )

        self.assertTrue(resolution.resolution_succeeded, resolution.resolution_error)
        self.assertEqual(resolution.resolved_versions.get("Newtonsoft.Json"), "13.0.3")

    def test_selected_artifact_entries_and_fetch_artifact_round_trip(self):
        resolution = ResolutionResult(
            packages=["Newtonsoft.Json"],
            install_target="Newtonsoft.Json@13.0.3",
            resolved_versions={"Newtonsoft.Json": "13.0.3"},
        )
        entries = NUGET_ECOSYSTEM.selected_artifact_entries(resolution)
        self.assertEqual(len(entries), 1)
        package_id, version, artifact = entries[0]
        self.assertEqual(package_id, "Newtonsoft.Json")
        self.assertEqual(version, "13.0.3")
        self.assertTrue(artifact["url"].endswith(".nupkg"))

        with tempfile.TemporaryDirectory() as temp_dir:
            destination = NUGET_ECOSYSTEM.fetch_artifact(artifact, Path(temp_dir))
            self.assertTrue(destination.exists())
            self.assertGreater(destination.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
