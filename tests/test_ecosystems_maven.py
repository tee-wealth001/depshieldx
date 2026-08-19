import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from depshieldx.core.resolver import ResolutionResult
from depshieldx.ecosystems import MAVEN_ECOSYSTEM
from depshieldx.ecosystems.maven.ecosystem import (
    _build_scratch_pom,
    _normalize_target_coordinate,
    _parse_dependency_list,
)


class NormalizeTargetCoordinateTests(unittest.TestCase):
    def test_three_part_coordinate_used_as_is(self):
        self.assertEqual(
            _normalize_target_coordinate("org.apache.commons:commons-lang3:3.17.0"),
            ("org.apache.commons", "commons-lang3", "3.17.0"),
        )

    @patch("depshieldx.ecosystems.maven.ecosystem.search_latest_version", return_value="3.17.0")
    def test_bare_coordinate_resolves_latest_version(self, mock_search):
        result = _normalize_target_coordinate("org.apache.commons:commons-lang3")

        self.assertEqual(result, ("org.apache.commons", "commons-lang3", "3.17.0"))
        mock_search.assert_called_once_with("org.apache.commons", "commons-lang3")

    @patch("depshieldx.ecosystems.maven.ecosystem.search_latest_version", return_value=None)
    def test_bare_coordinate_raises_when_no_version_found(self, _mock_search):
        with self.assertRaises(RuntimeError):
            _normalize_target_coordinate("org.example:missing")

    def test_invalid_coordinate_raises(self):
        with self.assertRaises(RuntimeError):
            _normalize_target_coordinate("not-a-valid-coordinate")


class BuildScratchPomTests(unittest.TestCase):
    def test_includes_every_coordinate_as_a_dependency(self):
        pom = _build_scratch_pom([("org.apache.commons", "commons-lang3", "3.17.0")])

        self.assertIn("<groupId>org.apache.commons</groupId>", pom)
        self.assertIn("<artifactId>commons-lang3</artifactId>", pom)
        self.assertIn("<version>3.17.0</version>", pom)

    def test_escapes_xml_special_characters(self):
        pom = _build_scratch_pom([("org.example", "a<b&c", "1.0.0")])

        self.assertIn("a&lt;b&amp;c", pom)
        self.assertNotIn("a<b&c", pom)


class ParseDependencyListTests(unittest.TestCase):
    def test_parses_real_dependency_list_output(self):
        output = (
            "[INFO] Scanning for projects...\n"
            "[INFO] --- dependency:3.7.0:list (default-cli) @ depshieldx-resolve ---\n"
            "[INFO] The following files have been resolved:\n"
            "[INFO]    org.apache.commons:commons-lang3:jar:3.17.0:compile -- module org.apache.commons.lang3\n"
            "[INFO]    com.google.guava:guava:jar:33.4.0-jre:compile -- module com.google.common [auto]\n"
            "[INFO] BUILD SUCCESS\n"
        )

        resolved = _parse_dependency_list(output)

        self.assertEqual(
            resolved,
            {
                "org.apache.commons:commons-lang3": "3.17.0",
                "com.google.guava:guava": "33.4.0-jre",
            },
        )

    def test_non_dependency_lines_are_ignored(self):
        output = "[INFO] ------------------------------------------------------------------------\n"

        self.assertEqual(_parse_dependency_list(output), {})


class MavenAdHocResolveTests(unittest.TestCase):
    @patch("depshieldx.ecosystems.maven.ecosystem.resolve_maven_tool", return_value="/usr/local/bin/mvn")
    @patch("depshieldx.ecosystems.maven.ecosystem._run")
    def test_resolve_uses_dependency_list_against_scratch_pom(self, mock_run, _mock_which):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="[INFO]    org.apache.commons:commons-lang3:jar:3.17.0:compile -- module org.apache.commons.lang3\n",
            stderr="",
        )

        resolution = MAVEN_ECOSYSTEM.resolve(
            [], ["org.apache.commons:commons-lang3:3.17.0"], "org.apache.commons:commons-lang3:3.17.0", source_type="package"
        )

        self.assertTrue(resolution.resolution_succeeded)
        self.assertEqual(resolution.resolved_versions, {"org.apache.commons:commons-lang3": "3.17.0"})
        args = mock_run.call_args.args[0]
        self.assertEqual(args[0], "/usr/local/bin/mvn")
        self.assertIn("dependency:list", args)

    @patch("depshieldx.ecosystems.maven.ecosystem.resolve_maven_tool", return_value="/usr/local/bin/mvn")
    @patch("depshieldx.ecosystems.maven.ecosystem._run")
    def test_resolve_reports_maven_failure(self, mock_run, _mock_which):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="BUILD FAILURE")

        resolution = MAVEN_ECOSYSTEM.resolve(
            [], ["org.example:missing:1.0.0"], "org.example:missing:1.0.0", source_type="package"
        )

        self.assertFalse(resolution.resolution_succeeded)
        self.assertIn("BUILD FAILURE", resolution.resolution_error)

    def test_resolve_reports_error_for_missing_package_targets(self):
        resolution = MAVEN_ECOSYSTEM.resolve([], [], "unused", source_type="package")

        self.assertFalse(resolution.resolution_succeeded)

    def test_resolve_reports_error_for_lockfile_source_type(self):
        # Maven has no canonical lockfile (lockfile_patterns is empty).
        resolution = MAVEN_ECOSYSTEM.resolve([], ["pom.xml"], "pom.xml", source_type="lockfile")

        self.assertFalse(resolution.resolution_succeeded)


class MavenToolResolutionTests(unittest.TestCase):
    @patch("depshieldx.ecosystems.maven.ecosystem.shutil.which", return_value=None)
    def test_raises_clear_error_when_mvn_not_on_path(self, _mock_which):
        from depshieldx.ecosystems.maven.ecosystem import resolve_maven_tool

        with self.assertRaises(RuntimeError):
            resolve_maven_tool("mvn")

    def test_uninstall_command_raises_no_equivalent(self):
        with self.assertRaises(RuntimeError):
            MAVEN_ECOSYSTEM.uninstall_command(["org.apache.commons:commons-lang3"])

    def test_install_command_raises_no_lockfile_path(self):
        with self.assertRaises(RuntimeError):
            MAVEN_ECOSYSTEM.install_command([])


class MavenHostInstallCommandTests(unittest.TestCase):
    def _resolution(self, requested_targets, resolved_versions):
        return ResolutionResult(
            packages=list(resolved_versions.keys()),
            install_target=", ".join(requested_targets),
            resolved_versions=resolved_versions,
            requested_targets=requested_targets,
            source_type="package",
        )

    @patch("depshieldx.ecosystems.maven.ecosystem.resolve_maven_tool", return_value="/usr/local/bin/mvn")
    @patch.object(MAVEN_ECOSYSTEM, "fetch_artifact")
    @patch.object(MAVEN_ECOSYSTEM, "selected_artifact_entries", return_value=[])
    def test_host_install_builds_scratch_pom_with_every_resolved_coordinate(self, _mock_entries, _mock_fetch, _mock_which):
        resolution = self._resolution(
            ["org.apache.commons:commons-lang3:3.17.0"],
            {
                "org.apache.commons:commons-lang3": "3.17.0",
                "org.apache.commons:commons-text": "1.12.0",
            },
        )

        with MAVEN_ECOSYSTEM.host_install_command(resolution) as command:
            self.assertEqual(command[0], "/usr/local/bin/mvn")
            self.assertIn("dependency:resolve", command)
            pom_path = Path(command[command.index("-f") + 1])
            pom_text = pom_path.read_text(encoding="utf-8")

        self.assertIn("<artifactId>commons-lang3</artifactId>", pom_text)
        self.assertIn("<artifactId>commons-text</artifactId>", pom_text)


@pytest.mark.live
class MavenEcosystemLiveResolveTests(unittest.TestCase):
    """Hits the real repo1.maven.org and shells out to the real `mvn`
    toolchain. Marked live -- excluded from the default CI run."""

    def test_resolve_real_coordinate_via_dependency_list(self):
        resolution = MAVEN_ECOSYSTEM.resolve(
            [], ["org.apache.commons:commons-lang3:3.17.0"], "org.apache.commons:commons-lang3:3.17.0", source_type="package"
        )

        self.assertTrue(resolution.resolution_succeeded, resolution.resolution_error)
        self.assertEqual(resolution.resolved_versions.get("org.apache.commons:commons-lang3"), "3.17.0")

    def test_selected_artifact_entries_and_fetch_artifact_round_trip(self):
        resolution = ResolutionResult(
            packages=["org.apache.commons:commons-lang3"],
            install_target="org.apache.commons:commons-lang3:3.17.0",
            resolved_versions={"org.apache.commons:commons-lang3": "3.17.0"},
        )
        entries = MAVEN_ECOSYSTEM.selected_artifact_entries(resolution)
        self.assertEqual(len(entries), 1)
        coordinate, version, artifact = entries[0]
        self.assertEqual(coordinate, "org.apache.commons:commons-lang3")
        self.assertEqual(version, "3.17.0")
        self.assertTrue(artifact["url"].endswith(".jar"))

        with tempfile.TemporaryDirectory() as temp_dir:
            destination = MAVEN_ECOSYSTEM.fetch_artifact(artifact, Path(temp_dir))
            self.assertTrue(destination.exists())
            self.assertGreater(destination.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
