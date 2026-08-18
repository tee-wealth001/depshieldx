import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from depshieldx.ecosystems import GO_ECOSYSTEM


class GoEcosystemLockfileResolveTests(unittest.TestCase):
    def test_resolve_from_lockfile_runs_go_list(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project_dir = Path(temp_dir)
            (project_dir / "go.mod").write_text("module demo\n\ngo 1.26\n", encoding="utf-8")
            lockfile = project_dir / "go.sum"
            lockfile.write_text("", encoding="utf-8")

            fake_result = MagicMock(returncode=0, stdout='{"Path": "github.com/pkg/errors", "Version": "v0.9.1"}\n', stderr="")
            with patch("depshieldx.ecosystems.go.resolve_go_tool", return_value="/usr/local/bin/go"):
                with patch("depshieldx.ecosystems.go._run", return_value=fake_result) as mock_run:
                    resolution = GO_ECOSYSTEM.resolve([], [str(lockfile)], str(lockfile), source_type="lockfile")

            self.assertTrue(resolution.resolution_succeeded)
            self.assertEqual(resolution.resolved_versions["github.com/pkg/errors"], "v0.9.1")
            mock_run.assert_called_once_with(
                ["/usr/local/bin/go", "list", "-m", "-json", "all"], cwd=str(project_dir)
            )

    def test_resolve_from_lockfile_fails_without_sibling_go_mod(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "go.sum"
            lockfile.write_text("", encoding="utf-8")

            resolution = GO_ECOSYSTEM.resolve([], [str(lockfile)], str(lockfile), source_type="lockfile")

        self.assertFalse(resolution.resolution_succeeded)
        self.assertIn("go.mod", resolution.resolution_error)

    def test_resolve_from_lockfile_reports_go_list_failure(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project_dir = Path(temp_dir)
            (project_dir / "go.mod").write_text("module demo\n\ngo 1.26\n", encoding="utf-8")
            lockfile = project_dir / "go.sum"
            lockfile.write_text("", encoding="utf-8")

            fake_result = MagicMock(returncode=1, stdout="", stderr="go: some resolution error")
            with patch("depshieldx.ecosystems.go.resolve_go_tool", return_value="/usr/local/bin/go"):
                with patch("depshieldx.ecosystems.go._run", return_value=fake_result):
                    resolution = GO_ECOSYSTEM.resolve([], [str(lockfile)], str(lockfile), source_type="lockfile")

            self.assertFalse(resolution.resolution_succeeded)
            self.assertIn("some resolution error", resolution.resolution_error)

    def test_resolve_reports_error_for_missing_package_targets(self):
        resolution = GO_ECOSYSTEM.resolve([], [], "unused", source_type="package")

        self.assertFalse(resolution.resolution_succeeded)


class GoAdHocResolveTests(unittest.TestCase):
    @patch("depshieldx.ecosystems.go.resolve_go_tool", return_value="/usr/local/bin/go")
    @patch("depshieldx.ecosystems.go._run")
    def test_resolve_single_module_uses_go_get(self, mock_run, _mock_which):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="", stderr=""),  # go mod init
            MagicMock(returncode=0, stdout="", stderr=""),  # go get
            MagicMock(
                returncode=0,
                stdout='{"Path": "depshieldx-resolve", "Main": true}\n'
                '{"Path": "github.com/pkg/errors", "Version": "v0.9.1"}\n',
                stderr="",
            ),  # go list -m -json all
        ]

        resolution = GO_ECOSYSTEM.resolve([], ["github.com/pkg/errors"], "github.com/pkg/errors", source_type="package")

        self.assertTrue(resolution.resolution_succeeded)
        self.assertEqual(resolution.resolved_versions, {"github.com/pkg/errors": "v0.9.1"})
        self.assertEqual(mock_run.call_count, 3)

    @patch("depshieldx.ecosystems.go.resolve_go_tool", return_value="/usr/local/bin/go")
    @patch("depshieldx.ecosystems.go._run")
    def test_resolve_reports_go_get_failure(self, mock_run, _mock_which):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="", stderr=""),  # go mod init
            MagicMock(returncode=1, stdout="", stderr="go: module not found"),  # go get fails
        ]

        resolution = GO_ECOSYSTEM.resolve([], ["example.com/does-not-exist"], "example.com/does-not-exist", source_type="package")

        self.assertFalse(resolution.resolution_succeeded)
        self.assertIn("module not found", resolution.resolution_error)

    @patch("depshieldx.ecosystems.go.resolve_go_tool", return_value="/usr/local/bin/go")
    @patch("depshieldx.ecosystems.go._run")
    def test_resolve_reports_scratch_module_init_failure(self, mock_run, _mock_which):
        mock_run.side_effect = [MagicMock(returncode=1, stdout="", stderr="go: init failed")]

        resolution = GO_ECOSYSTEM.resolve([], ["github.com/pkg/errors"], "github.com/pkg/errors", source_type="package")

        self.assertFalse(resolution.resolution_succeeded)
        self.assertIn("init failed", resolution.resolution_error)


class GoToolResolutionTests(unittest.TestCase):
    @patch("depshieldx.ecosystems.go.shutil.which", return_value="/usr/local/bin/go")
    def test_install_command_uses_resolved_path(self, mock_which):
        command = GO_ECOSYSTEM.install_command([])

        mock_which.assert_called_with("go")
        self.assertEqual(command, ["/usr/local/bin/go", "mod", "download"])

    @patch("depshieldx.ecosystems.go.shutil.which", return_value="/usr/local/bin/go")
    def test_uninstall_command_appends_none_per_module(self, _mock_which):
        command = GO_ECOSYSTEM.uninstall_command(["github.com/pkg/errors", "golang.org/x/text"])

        self.assertEqual(
            command,
            ["/usr/local/bin/go", "get", "github.com/pkg/errors@none", "golang.org/x/text@none"],
        )

    @patch("depshieldx.ecosystems.go.shutil.which", return_value=None)
    def test_raises_clear_error_when_go_not_on_path(self, _mock_which):
        with self.assertRaises(RuntimeError):
            GO_ECOSYSTEM.install_command([])


class GoHostInstallCommandTests(unittest.TestCase):
    def _resolution(self, source_type, requested_targets, resolved_versions):
        from depshieldx.resolver import ResolutionResult

        return ResolutionResult(
            packages=list(resolved_versions.keys()),
            install_target=", ".join(requested_targets),
            resolved_versions=resolved_versions,
            requested_targets=requested_targets,
            source_type=source_type,
        )

    @patch("depshieldx.ecosystems.go.shutil.which", return_value="/usr/local/bin/go")
    @patch.object(GO_ECOSYSTEM, "fetch_artifact")
    @patch.object(GO_ECOSYSTEM, "selected_artifact_entries", return_value=[])
    def test_ad_hoc_install_pins_every_resolved_module(self, _mock_entries, _mock_fetch, _mock_which):
        resolution = self._resolution(
            "package", ["github.com/pkg/errors"], {"github.com/pkg/errors": "v0.9.1", "golang.org/x/text": "v0.14.0"}
        )

        with GO_ECOSYSTEM.host_install_command(resolution) as command:
            self.assertEqual(command[:2], ["/usr/local/bin/go", "get"])
            self.assertCountEqual(command[2:], ["github.com/pkg/errors@v0.9.1", "golang.org/x/text@v0.14.0"])

    @patch("depshieldx.ecosystems.go.shutil.which", return_value="/usr/local/bin/go")
    @patch.object(GO_ECOSYSTEM, "fetch_artifact")
    @patch.object(GO_ECOSYSTEM, "selected_artifact_entries", return_value=[])
    def test_lockfile_install_uses_go_mod_download(self, _mock_entries, _mock_fetch, _mock_which):
        resolution = self._resolution("lockfile", ["go.sum"], {"github.com/pkg/errors": "v0.9.1"})

        with GO_ECOSYSTEM.host_install_command(resolution) as command:
            self.assertEqual(command, ["/usr/local/bin/go", "mod", "download"])


class GoDirectDependencyNamesForLockfileTests(unittest.TestCase):
    def test_reads_direct_requires_via_go_mod_edit_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project_dir = Path(temp_dir)
            (project_dir / "go.mod").write_text("module demo\n\ngo 1.26\n", encoding="utf-8")
            lockfile = project_dir / "go.sum"
            lockfile.write_text("", encoding="utf-8")

            payload = {
                "Require": [
                    {"Path": "github.com/pkg/errors", "Version": "v0.9.1", "Indirect": False},
                    {"Path": "golang.org/x/text", "Version": "v0.14.0", "Indirect": True},
                ]
            }
            fake_result = MagicMock(returncode=0, stdout=json.dumps(payload), stderr="")
            with patch("depshieldx.ecosystems.go.resolve_go_tool", return_value="/usr/local/bin/go"):
                with patch("depshieldx.ecosystems.go._run", return_value=fake_result) as mock_run:
                    names = GO_ECOSYSTEM.direct_dependency_names_for_lockfile(str(lockfile))

            self.assertEqual(names, ["github.com/pkg/errors"])
            self.assertNotIn("golang.org/x/text", names)
            mock_run.assert_called_once_with(
                ["/usr/local/bin/go", "mod", "edit", "-json"], cwd=str(project_dir)
            )

    def test_missing_go_mod_raises_clear_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "go.sum"
            lockfile.write_text("", encoding="utf-8")

            with self.assertRaises(RuntimeError) as ctx:
                GO_ECOSYSTEM.direct_dependency_names_for_lockfile(str(lockfile))

        self.assertIn("no go.mod found", str(ctx.exception))


@pytest.mark.live
class GoEcosystemLiveResolveTests(unittest.TestCase):
    """Hits the real Go module proxy and shells out to the real `go`
    toolchain. Marked live -- excluded from the default CI run."""

    def test_resolve_real_module_via_go_get(self):
        resolution = GO_ECOSYSTEM.resolve([], ["github.com/pkg/errors"], "github.com/pkg/errors", source_type="package")

        self.assertTrue(resolution.resolution_succeeded, resolution.resolution_error)
        self.assertEqual(resolution.resolved_versions.get("github.com/pkg/errors"), "v0.9.1")

    def test_selected_artifact_entries_and_fetch_artifact_round_trip(self):
        from depshieldx.resolver import ResolutionResult

        resolution = ResolutionResult(
            packages=["github.com/pkg/errors"],
            install_target="github.com/pkg/errors@v0.9.1",
            resolved_versions={"github.com/pkg/errors": "v0.9.1"},
        )
        entries = GO_ECOSYSTEM.selected_artifact_entries(resolution)
        self.assertEqual(len(entries), 1)
        module, version, artifact = entries[0]
        self.assertEqual(module, "github.com/pkg/errors")
        self.assertEqual(version, "v0.9.1")
        self.assertTrue(artifact["url"].endswith(".zip"))
        self.assertEqual(artifact["checksum"], "h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=")

        with tempfile.TemporaryDirectory() as temp_dir:
            destination = GO_ECOSYSTEM.fetch_artifact(artifact, Path(temp_dir))
            self.assertTrue(destination.exists())
            self.assertGreater(destination.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
