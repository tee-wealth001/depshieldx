import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from depshieldx.runtime import (
    is_frozen,
    pip_command,
    resource_path,
    self_invoke_command,
    system_python_executable,
)


class RuntimeTests(unittest.TestCase):
    def test_is_frozen_false_by_default(self):
        self.assertFalse(is_frozen())

    @patch("depshieldx.runtime.sys")
    def test_is_frozen_true_when_sys_frozen_set(self, mock_sys):
        mock_sys.frozen = True
        self.assertTrue(is_frozen())

    def test_system_python_executable_is_sys_executable_when_not_frozen(self):
        self.assertEqual(system_python_executable(), sys.executable)

    @patch("depshieldx.runtime.shutil.which", return_value="/usr/bin/python3")
    @patch("depshieldx.runtime.is_frozen", return_value=True)
    def test_system_python_executable_locates_interpreter_when_frozen(self, _mock_frozen, mock_which):
        self.assertEqual(system_python_executable(), "/usr/bin/python3")
        mock_which.assert_any_call("python3")

    @patch("depshieldx.runtime.shutil.which", return_value=None)
    @patch("depshieldx.runtime.is_frozen", return_value=True)
    def test_system_python_executable_raises_when_frozen_and_nothing_found(self, _mock_frozen, _mock_which):
        with self.assertRaises(RuntimeError):
            system_python_executable()

    def test_pip_command_uses_module_invocation(self):
        command = pip_command(["install", "--no-deps", "pkg.whl"])
        self.assertEqual(command, [sys.executable, "-m", "pip", "install", "--no-deps", "pkg.whl"])

    def test_self_invoke_command_not_frozen_uses_module_invocation(self):
        command = self_invoke_command(["install", "flask"])
        self.assertEqual(command, [sys.executable, "-m", "depshieldx.cli", "install", "flask"])

    @patch("depshieldx.runtime.is_frozen", return_value=True)
    def test_self_invoke_command_frozen_calls_own_executable_directly(self, _mock_frozen):
        command = self_invoke_command(["install", "flask"])
        self.assertEqual(command, [sys.executable, "install", "flask"])

    def test_resource_path_not_frozen_resolves_relative_to_package(self):
        path = resource_path("sandbox_wrapper.py")
        self.assertEqual(path, Path(__file__).resolve().parent.parent / "depshieldx" / "sandbox_wrapper.py")
        self.assertTrue(path.exists())

    @patch("depshieldx.runtime.sys")
    @patch("depshieldx.runtime.is_frozen", return_value=True)
    def test_resource_path_frozen_uses_meipass(self, _mock_frozen, mock_sys):
        mock_sys._MEIPASS = "/frozen/extracted"
        path = resource_path("sandbox_wrapper.py")
        self.assertEqual(path, Path("/frozen/extracted") / "sandbox_wrapper.py")


if __name__ == "__main__":
    unittest.main()
