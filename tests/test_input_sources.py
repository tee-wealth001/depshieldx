import tempfile
import unittest
from pathlib import Path

from depshieldx.input_sources import load_input_source


class InputSourceTests(unittest.TestCase):
    def test_load_input_source_for_multiple_packages(self):
        source = load_input_source(("flask", "requests"))

        self.assertEqual(source.source_type, "packages")
        self.assertEqual(source.requested_targets, ["flask", "requests"])
        self.assertEqual(source.pip_args, ["flask", "requests"])

    def test_load_input_source_for_requirements_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "requirements.txt"
            path.write_text("flask==3.1.3\n# comment\nrequests>=2.0\n")

            source = load_input_source((), requirement_file=str(path))

        self.assertEqual(source.source_type, "requirements")
        self.assertEqual(source.label, "requirements.txt")
        self.assertEqual(source.requested_targets, ["flask==3.1.3", "requests>=2.0"])
        self.assertEqual(source.pip_args, ["-r", str(path)])

    def test_load_input_source_for_uv_lock(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "uv.lock"
            path.write_text(
                'version = 1\n\n'
                '[[package]]\nname = "flask"\nversion = "3.1.3"\n\n'
                '[[package]]\nname = "click"\nversion = "8.3.1"\n'
            )

            source = load_input_source((), lockfile=str(path))

        self.assertEqual(source.source_type, "lockfile")
        self.assertEqual(source.label, "uv.lock")
        self.assertEqual(source.requested_targets, ["flask==3.1.3", "click==8.3.1"])
        self.assertEqual(source.ecosystem, "pypi")

    def test_load_input_source_defaults_to_pypi_ecosystem(self):
        source = load_input_source(("flask",))

        self.assertEqual(source.ecosystem, "pypi")

    def test_load_input_source_detects_package_lock_json_as_npm(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "package-lock.json"
            path.write_text("{}")

            source = load_input_source((), lockfile=str(path))

        self.assertEqual(source.source_type, "lockfile")
        self.assertEqual(source.ecosystem, "npm")
        self.assertEqual(source.label, "package-lock.json")
        # The lockfile path is passed through unparsed -- NpmEcosystem.resolve()
        # parses it directly, unlike PyPI's lockfile handling above.
        self.assertEqual(source.requested_targets, [str(path)])

    def test_load_input_source_detects_yarn_lock_as_npm(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "yarn.lock"
            path.write_text("# yarn lockfile v1\n")

            source = load_input_source((), lockfile=str(path))

        self.assertEqual(source.ecosystem, "npm")

    def test_load_input_source_detects_pnpm_lock_yaml_as_npm(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "pnpm-lock.yaml"
            path.write_text("lockfileVersion: '9.0'\n")

            source = load_input_source((), lockfile=str(path))

        self.assertEqual(source.ecosystem, "npm")

    def test_load_input_source_for_pyproject(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "pyproject.toml"
            path.write_text(
                "[project]\n"
                'dependencies = ["flask==3.1.3", "requests>=2.0"]\n'
            )

            source = load_input_source((), pyproject_file=str(path))

        self.assertEqual(source.source_type, "pyproject")
        self.assertEqual(source.label, "pyproject.toml")
        self.assertEqual(source.requested_targets, ["flask==3.1.3", "requests>=2.0"])
