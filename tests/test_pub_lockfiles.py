import tempfile
import unittest

from depshieldx.ecosystems.pub.lockfiles import direct_dependency_names, parse_pubspec_lock


class ParsePubspecLockTests(unittest.TestCase):
    def _write_lockfile(self, text: str) -> str:
        handle = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        handle.write(text)
        handle.close()
        return handle.name

    def test_parses_real_hosted_entry(self):
        # Real shape confirmed directly against a real `dart pub add http`
        # run's pubspec.lock during development.
        lockfile_path = self._write_lockfile(
            """
packages:
  http:
    dependency: "direct main"
    description:
      name: http
      sha256: "87721a4a50b19c7f1d49001e51409bddc46303966ce89a65af4f4e6004896412"
      url: "https://pub.dev"
    source: hosted
    version: "1.6.0"
sdks:
  dart: ">=3.13.1 <4.0.0"
"""
        )

        resolved = parse_pubspec_lock(lockfile_path)

        self.assertEqual(resolved, {"http": "1.6.0"})

    def test_includes_transitive_dependencies(self):
        lockfile_path = self._write_lockfile(
            """
packages:
  http:
    dependency: "direct main"
    description:
      name: http
      sha256: "87721a4a50b19c7f1d49001e51409bddc46303966ce89a65af4f4e6004896412"
      url: "https://pub.dev"
    source: hosted
    version: "1.6.0"
  async:
    dependency: transitive
    description:
      name: async
      sha256: e2eb0491ba5ddb6177742d2da23904574082139b07c1e33b8503b9f46f3e1a37
      url: "https://pub.dev"
    source: hosted
    version: "2.13.1"
"""
        )

        resolved = parse_pubspec_lock(lockfile_path)

        self.assertEqual(resolved, {"http": "1.6.0", "async": "2.13.1"})

    def test_skips_non_hosted_sources(self):
        # Real, valid pubspec.lock source kinds -- git/path/sdk dependencies
        # have no registry checksum to verify against, mirroring how Cargo's
        # own git-sourced dependencies are already out of scope for
        # checksum verification.
        lockfile_path = self._write_lockfile(
            """
packages:
  http:
    dependency: "direct main"
    description:
      name: http
      sha256: "87721a4a50b19c7f1d49001e51409bddc46303966ce89a65af4f4e6004896412"
      url: "https://pub.dev"
    source: hosted
    version: "1.6.0"
  my_local_pkg:
    dependency: "direct main"
    description:
      path: ../my_local_pkg
      relative: true
    source: path
    version: "0.0.1"
  my_git_pkg:
    dependency: "direct main"
    description:
      url: "https://github.com/example/my_git_pkg"
      ref: HEAD
      resolved-ref: "abc123"
    source: git
    version: "1.0.0"
"""
        )

        resolved = parse_pubspec_lock(lockfile_path)

        self.assertEqual(resolved, {"http": "1.6.0"})

    def test_empty_lockfile_returns_empty_dict(self):
        lockfile_path = self._write_lockfile("packages: {}\nsdks:\n  dart: '>=3.0.0 <4.0.0'\n")

        resolved = parse_pubspec_lock(lockfile_path)

        self.assertEqual(resolved, {})


class DirectDependencyNamesTests(unittest.TestCase):
    def _write_lockfile(self, text: str) -> str:
        handle = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        handle.write(text)
        handle.close()
        return handle.name

    def test_reads_direct_main_and_direct_dev_only(self):
        lockfile_path = self._write_lockfile(
            """
packages:
  http:
    dependency: "direct main"
    description:
      name: http
      sha256: "87721a4a50b19c7f1d49001e51409bddc46303966ce89a65af4f4e6004896412"
      url: "https://pub.dev"
    source: hosted
    version: "1.6.0"
  lints:
    dependency: "direct dev"
    description:
      name: lints
      sha256: "12f842a479589fea194fe5c5a3095abc7be0c1f2ddfa9a0e76aed1dbd26a87df"
      url: "https://pub.dev"
    source: hosted
    version: "6.1.0"
  async:
    dependency: transitive
    description:
      name: async
      sha256: e2eb0491ba5ddb6177742d2da23904574082139b07c1e33b8503b9f46f3e1a37
      url: "https://pub.dev"
    source: hosted
    version: "2.13.1"
"""
        )

        names = direct_dependency_names(lockfile_path)

        self.assertEqual(sorted(names), ["http", "lints"])


if __name__ == "__main__":
    unittest.main()
