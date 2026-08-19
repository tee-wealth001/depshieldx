import unittest
from unittest.mock import patch

import pytest

from depshieldx.ecosystems.maven.registry import (
    artifact_directory_url,
    check_provenance_batch,
    group_path,
    parse_bom_import_coordinates,
    parse_parent_coordinate,
)


class GroupPathTests(unittest.TestCase):
    def test_dots_become_slashes(self):
        self.assertEqual(group_path("com.fasterxml.jackson.core"), "com/fasterxml/jackson/core")

    def test_no_dots_is_unchanged(self):
        self.assertEqual(group_path("junit"), "junit")


class ArtifactDirectoryUrlTests(unittest.TestCase):
    def test_builds_real_central_layout(self):
        self.assertEqual(
            artifact_directory_url("org.apache.commons", "commons-lang3", "3.17.0"),
            "https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.17.0",
        )


class CheckProvenanceBatchTests(unittest.TestCase):
    def test_empty_resolved_versions_returns_no_block(self):
        result = check_provenance_batch({})

        self.assertFalse(result["block"])
        self.assertEqual(result["details"], [])

    @patch("depshieldx.ecosystems.maven.registry.check_release")
    def test_aggregates_warnings_and_infos_per_coordinate(self, mock_check_release):
        mock_check_release.return_value = {
            "package": "org.example:demo",
            "version": "1.0.0",
            "block": False,
            "reason": None,
            "warnings": ["resolved artifact has no PGP signature -- unusual for a real Central Repository release"],
            "infos": ["no Sigstore bundle published for the resolved artifact -- PGP-only, the common case today"],
            "signals": {},
        }

        result = check_provenance_batch({"org.example:demo": "1.0.0"})

        self.assertFalse(result["block"])
        self.assertEqual(len(result["details"]), 1)
        self.assertTrue(any("org.example:demo@1.0.0" in warning for warning in result["warnings"]))
        self.assertTrue(any("org.example:demo@1.0.0" in info for info in result["infos"]))

    @patch("depshieldx.ecosystems.maven.registry.check_release")
    def test_splits_coordinate_on_first_colon_only(self, mock_check_release):
        mock_check_release.return_value = {
            "package": "com.fasterxml.jackson.core:jackson-databind",
            "version": "2.19.1",
            "block": False,
            "reason": None,
            "warnings": [],
            "infos": [],
            "signals": {},
        }

        check_provenance_batch({"com.fasterxml.jackson.core:jackson-databind": "2.19.1"})

        mock_check_release.assert_called_once_with(
            "com.fasterxml.jackson.core", "jackson-databind", "2.19.1", verbose=False
        )


class ParseParentCoordinateTests(unittest.TestCase):
    def test_extracts_real_parent_coordinate(self):
        # Real shape confirmed directly against gson-2.11.0.pom.
        pom_text = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>com.google.code.gson</groupId>
    <artifactId>gson-parent</artifactId>
    <version>2.11.0</version>
  </parent>
  <artifactId>gson</artifactId>
</project>
"""
        self.assertEqual(
            parse_parent_coordinate(pom_text),
            ("com.google.code.gson", "gson-parent", "2.11.0"),
        )

    def test_returns_none_when_no_parent(self):
        pom_text = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.junit</groupId>
  <artifactId>junit-bom</artifactId>
  <version>5.11.0</version>
</project>
"""
        self.assertIsNone(parse_parent_coordinate(pom_text))


class ParseBomImportCoordinatesTests(unittest.TestCase):
    def test_extracts_real_bom_import_with_literal_version(self):
        pom_text = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.junit</groupId>
        <artifactId>junit-bom</artifactId>
        <version>5.11.0</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
"""
        self.assertEqual(
            parse_bom_import_coordinates(pom_text),
            [("org.junit", "junit-bom", "5.11.0")],
        )

    def test_resolves_property_placeholder_version_from_same_pom(self):
        # Real shape confirmed directly against commons-parent:73's pom --
        # the BOM's own <version> is "${commons.junit.version}", defined
        # in that same pom's <properties> block, not a literal string.
        pom_text = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <properties>
    <commons.junit.version>5.11.0</commons.junit.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.junit</groupId>
        <artifactId>junit-bom</artifactId>
        <version>${commons.junit.version}</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
"""
        self.assertEqual(
            parse_bom_import_coordinates(pom_text),
            [("org.junit", "junit-bom", "5.11.0")],
        )

    def test_skips_entry_with_unresolvable_property(self):
        pom_text = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.junit</groupId>
        <artifactId>junit-bom</artifactId>
        <version>${not.defined.anywhere}</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
"""
        self.assertEqual(parse_bom_import_coordinates(pom_text), [])

    def test_ignores_non_import_dependency_management_entries(self):
        pom_text = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.example</groupId>
        <artifactId>example-lib</artifactId>
        <version>1.0.0</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
"""
        self.assertEqual(parse_bom_import_coordinates(pom_text), [])

    def test_no_dependency_management_returns_empty_list(self):
        pom_text = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <artifactId>gson</artifactId>
</project>
"""
        self.assertEqual(parse_bom_import_coordinates(pom_text), [])


@pytest.mark.live
class MavenRegistryLiveTests(unittest.TestCase):
    """Hits the real repo1.maven.org and search.maven.org. Marked live --
    excluded from the default CI run (`pytest -m "not live"`)."""

    def test_fetch_best_checksum_prefers_sha256_for_recent_artifact(self):
        from depshieldx.ecosystems.maven.registry import fetch_best_checksum

        result = fetch_best_checksum("com.fasterxml.jackson.core", "jackson-databind", "2.19.1")

        self.assertIsNotNone(result)
        algorithm, digest = result
        self.assertEqual(algorithm, "sha256")
        self.assertEqual(len(digest), 64)

    def test_fetch_best_checksum_falls_back_to_sha1_for_old_artifact(self):
        from depshieldx.ecosystems.maven.registry import fetch_best_checksum

        result = fetch_best_checksum("junit", "junit", "4.13.2")

        self.assertIsNotNone(result)
        algorithm, _digest = result
        self.assertEqual(algorithm, "sha1")

    def test_check_release_verifies_real_sigstore_bundle(self):
        from depshieldx.ecosystems.maven.registry import check_release

        result = check_release("org.leplus", "ristretto", "2.0.0")

        self.assertFalse(result["block"])
        self.assertTrue(result["signals"]["sigstore_verified"])
        self.assertEqual(result["signals"]["sigstore_recognized_issuer"], "https://token.actions.githubusercontent.com")

    def test_search_latest_version_resolves_a_real_coordinate(self):
        from depshieldx.ecosystems.maven.registry import search_latest_version

        version = search_latest_version("org.apache.commons", "commons-lang3")

        self.assertIsNotNone(version)
        self.assertRegex(version, r"^\d+\.\d+")

    def test_parse_parent_coordinate_against_real_gson_pom(self):
        from depshieldx.ecosystems.maven.registry import fetch_pom_text

        pom_text = fetch_pom_text("com.google.code.gson", "gson", "2.11.0")

        self.assertEqual(
            parse_parent_coordinate(pom_text),
            ("com.google.code.gson", "gson-parent", "2.11.0"),
        )

    def test_parse_bom_import_coordinates_against_real_commons_parent_pom(self):
        from depshieldx.ecosystems.maven.registry import fetch_pom_text

        pom_text = fetch_pom_text("org.apache.commons", "commons-parent", "73")

        self.assertIn(("org.junit", "junit-bom", "5.11.0"), parse_bom_import_coordinates(pom_text))


if __name__ == "__main__":
    unittest.main()
