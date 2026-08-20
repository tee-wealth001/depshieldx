import tempfile
import unittest

from depshieldx.ecosystems.rubygems.lockfiles import direct_dependency_names, parse_gemfile_lock


class ParseGemfileLockTests(unittest.TestCase):
    def _write_lockfile(self, text: str) -> str:
        handle = tempfile.NamedTemporaryFile(mode="w", suffix=".lock", delete=False)
        handle.write(text)
        handle.close()
        return handle.name

    def test_parses_real_hosted_entry(self):
        # Real shape confirmed directly against a real `bundle lock` run
        # during development.
        lockfile_path = self._write_lockfile(
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "    json (2.9.0)\n"
            "    rack (3.2.7)\n"
            "\n"
            "PLATFORMS\n"
            "  x64-mingw-ucrt\n"
            "\n"
            "DEPENDENCIES\n"
            "  json (= 2.9.0)\n"
            "  rack (= 3.2.7)\n"
            "\n"
            "BUNDLED WITH\n"
            "   4.0.16\n"
        )

        resolved = parse_gemfile_lock(lockfile_path)

        self.assertEqual(resolved, {"json": "2.9.0", "rack": "3.2.7"})

    def test_skips_nested_dependency_requirement_lines(self):
        # Confirmed directly against a real `bundle lock` for a gem with
        # transitive dependencies (activesupport): 6-space-indented lines
        # nested under a spec are that gem's own requirement annotations,
        # not separately resolved packages -- some have no version/
        # requirement at all ("      base64").
        lockfile_path = self._write_lockfile(
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "    activesupport (7.1.0)\n"
            "      base64\n"
            "      concurrent-ruby (~> 1.0, >= 1.0.2)\n"
            "    base64 (0.3.0)\n"
            "    concurrent-ruby (1.3.8)\n"
            "\n"
            "PLATFORMS\n"
            "  x64-mingw-ucrt\n"
            "\n"
            "DEPENDENCIES\n"
            "  activesupport (= 7.1.0)\n"
            "\n"
            "BUNDLED WITH\n"
            "   4.0.16\n"
        )

        resolved = parse_gemfile_lock(lockfile_path)

        self.assertEqual(
            resolved,
            {"activesupport": "7.1.0", "base64": "0.3.0", "concurrent-ruby": "1.3.8"},
        )

    def test_skips_git_and_path_sourced_sections(self):
        # Real, valid Gemfile.lock section kinds -- git-/path-sourced
        # gems have their own top-level "GIT"/"PATH" sections with the
        # exact same nested "specs:" shape (confirmed directly against a
        # real git-sourced Gemfile.lock), but no registry checksum to
        # verify against, mirroring how pubspec.lock's `source: hosted`-
        # only filtering already treats non-registry sources as out of
        # scope.
        lockfile_path = self._write_lockfile(
            "GIT\n"
            "  remote: https://github.com/rack/rack\n"
            "  revision: 09f2f66ac1bb392ae58fd531dcb0acd01c9680be\n"
            "  tag: v3.1.8\n"
            "  specs:\n"
            "    rack (3.1.8)\n"
            "\n"
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "    json (2.9.0)\n"
            "\n"
            "PLATFORMS\n"
            "  x64-mingw-ucrt\n"
            "\n"
            "DEPENDENCIES\n"
            "  json (= 2.9.0)\n"
            "  rack!\n"
            "\n"
            "BUNDLED WITH\n"
            "   4.0.16\n"
        )

        resolved = parse_gemfile_lock(lockfile_path)

        self.assertEqual(resolved, {"json": "2.9.0"})

    def test_platform_suffixed_spec_entry_keeps_bare_version(self):
        # A real, documented Gemfile.lock shape (a gem shipping platform-
        # specific prebuilt binaries) -- not reproduced by a real `bundle
        # lock` on the development system even when forced (see
        # lockfiles.py's module docstring), so handled defensively here:
        # the platform tag is dropped, the bare version is kept.
        lockfile_path = self._write_lockfile(
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "    nokogiri (1.16.0-x86_64-linux)\n"
            "\n"
            "PLATFORMS\n"
            "  x86_64-linux\n"
            "\n"
            "DEPENDENCIES\n"
            "  nokogiri (= 1.16.0)\n"
            "\n"
            "BUNDLED WITH\n"
            "   4.0.16\n"
        )

        resolved = parse_gemfile_lock(lockfile_path)

        self.assertEqual(resolved, {"nokogiri": "1.16.0"})

    def test_empty_lockfile_returns_empty_dict(self):
        lockfile_path = self._write_lockfile("")

        resolved = parse_gemfile_lock(lockfile_path)

        self.assertEqual(resolved, {})


class DirectDependencyNamesTests(unittest.TestCase):
    def _write_lockfile(self, text: str) -> str:
        handle = tempfile.NamedTemporaryFile(mode="w", suffix=".lock", delete=False)
        handle.write(text)
        handle.close()
        return handle.name

    def test_reads_dependencies_section_only(self):
        lockfile_path = self._write_lockfile(
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "    activesupport (7.1.0)\n"
            "      concurrent-ruby (~> 1.0)\n"
            "    concurrent-ruby (1.3.8)\n"
            "    rack-test (2.1.0)\n"
            "      rack (>= 1.3)\n"
            "    rack (3.2.7)\n"
            "\n"
            "PLATFORMS\n"
            "  x64-mingw-ucrt\n"
            "\n"
            "DEPENDENCIES\n"
            "  activesupport (= 7.1.0)\n"
            "  rack-test (= 2.1.0)\n"
            "\n"
            "BUNDLED WITH\n"
            "   4.0.16\n"
        )

        names = direct_dependency_names(lockfile_path)

        self.assertEqual(sorted(names), ["activesupport", "rack-test"])

    def test_strips_non_default_source_marker(self):
        # Confirmed directly: a git-/path-sourced direct dependency gets
        # a bare "name!" entry with no parenthesized requirement at all.
        lockfile_path = self._write_lockfile(
            "GIT\n"
            "  remote: https://github.com/rack/rack\n"
            "  specs:\n"
            "    rack (3.1.8)\n"
            "\n"
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "    json (2.9.0)\n"
            "\n"
            "PLATFORMS\n"
            "  x64-mingw-ucrt\n"
            "\n"
            "DEPENDENCIES\n"
            "  json (= 2.9.0)\n"
            "  rack!\n"
            "\n"
            "BUNDLED WITH\n"
            "   4.0.16\n"
        )

        names = direct_dependency_names(lockfile_path)

        self.assertEqual(sorted(names), ["json", "rack"])


if __name__ == "__main__":
    unittest.main()
