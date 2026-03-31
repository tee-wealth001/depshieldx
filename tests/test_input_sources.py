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
