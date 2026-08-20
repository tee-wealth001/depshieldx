import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from depshieldx.runtime import (
    is_frozen,
    pip_command,
    resource_path,
    self_invoke_command,
    subprocess_env,
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
        path = resource_path("security/sandbox/sandbox_wrapper.py")
        self.assertEqual(path, Path(__file__).resolve().parent.parent / "depshieldx" / "security" / "sandbox" / "sandbox_wrapper.py")
        self.assertTrue(path.exists())

    @patch("depshieldx.runtime.sys")
    @patch("depshieldx.runtime.is_frozen", return_value=True)
    def test_resource_path_frozen_uses_meipass(self, _mock_frozen, mock_sys):
        mock_sys._MEIPASS = "/frozen/extracted"
        path = resource_path("security/sandbox/sandbox_wrapper.py")
        self.assertEqual(path, Path("/frozen/extracted") / "security" / "sandbox" / "sandbox_wrapper.py")

    def test_subprocess_env_not_frozen_matches_os_environ(self):
        # Confirmed directly this is a no-op when not frozen -- sys._MEIPASS
        # doesn't exist there at all, so there's nothing to strip.
        env = subprocess_env()
        self.assertEqual(env, dict(os.environ))
        self.assertIsNot(env, os.environ)

    # Fake path segments deliberately use forward slashes and no drive
    # letter/colon, on every platform including Windows -- confirmed
    # directly this is what broke the first version of these tests on
    # real Linux/macOS CI runners: os.pathsep is ":" there, which
    # collides with a Windows-style "C:\\..." drive-letter colon and
    # mangles a hardcoded Windows path joined with it. subprocess_env()
    # itself doesn't care what a path segment looks like, only whether
    # two *whole* segments match after os.path.normcase(os.path.normpath(
    # ...)) -- these fake segments exercise that without accidentally
    # depending on which platform the test itself happens to run on.
    FAKE_MEIPASS = "/fake/meipass"
    FAKE_TOOL_A = "/fake/real/tool"
    FAKE_TOOL_B = "/fake/another/real/tool"

    @patch("depshieldx.runtime.sys")
    @patch("depshieldx.runtime.is_frozen", return_value=True)
    def test_subprocess_env_frozen_without_meipass_attribute_is_unchanged(self, _mock_frozen, mock_sys):
        # getattr(sys, "_MEIPASS", None) -- a real PyInstaller frozen
        # process always has this set, but the lookup is defensive rather
        # than assumed.
        del mock_sys._MEIPASS
        mock_sys._MEIPASS = None
        fake_path = os.pathsep.join([self.FAKE_TOOL_A, self.FAKE_TOOL_B])
        with patch.dict(os.environ, {"PATH": fake_path}, clear=False):
            env = subprocess_env()
            self.assertEqual(env["PATH"], os.environ["PATH"])

    @patch("depshieldx.runtime.sys")
    @patch("depshieldx.runtime.is_frozen", return_value=True)
    def test_subprocess_env_frozen_strips_meipass_from_path(self, _mock_frozen, mock_sys):
        # Confirmed directly against a real Windows release binary: this
        # is the real, reproduced mechanism behind a genuine packaging
        # bug (composer -> php.exe resolving depshieldx's own bundled
        # VCRUNTIME140.dll instead of its real one) -- see this module's
        # own docstring.
        mock_sys._MEIPASS = self.FAKE_MEIPASS
        fake_path = os.pathsep.join([self.FAKE_MEIPASS, self.FAKE_TOOL_A, self.FAKE_TOOL_B])
        with patch.dict(os.environ, {"PATH": fake_path}, clear=False):
            env = subprocess_env()
        path_entries = env["PATH"].split(os.pathsep)
        self.assertNotIn(self.FAKE_MEIPASS, path_entries)
        self.assertIn(self.FAKE_TOOL_A, path_entries)
        self.assertIn(self.FAKE_TOOL_B, path_entries)

    @patch("depshieldx.runtime.sys")
    @patch("depshieldx.runtime.is_frozen", return_value=True)
    def test_subprocess_env_strips_meipass_regardless_of_trailing_slash(self, _mock_frozen, mock_sys):
        # os.path.normpath(...) is required, not cosmetic -- confirmed
        # directly a real _MEIPASS and the matching PATH entry don't
        # always agree on a trailing separator.
        mock_sys._MEIPASS = self.FAKE_MEIPASS
        fake_path = os.pathsep.join([self.FAKE_MEIPASS + "/", self.FAKE_TOOL_A])
        with patch.dict(os.environ, {"PATH": fake_path}, clear=False):
            env = subprocess_env()
        self.assertEqual(env["PATH"], self.FAKE_TOOL_A)

    @unittest.skipUnless(sys.platform == "win32", "case-insensitive path comparison is Windows-specific")
    @patch("depshieldx.runtime.sys")
    @patch("depshieldx.runtime.is_frozen", return_value=True)
    def test_subprocess_env_strips_meipass_regardless_of_case_on_windows(self, _mock_frozen, mock_sys):
        # os.path.normcase(...) is required, not cosmetic -- confirmed
        # directly a real _MEIPASS and the matching PATH entry don't
        # always agree on letter case on Windows, where paths are
        # case-insensitive (os.path.normcase is a no-op on POSIX, so this
        # is genuinely platform-specific, not a portable property of
        # subprocess_env() itself).
        mock_sys._MEIPASS = "C:\\Users\\steph\\AppData\\Local\\Temp\\_MEI123456"
        fake_path = os.pathsep.join(["c:\\users\\steph\\appdata\\local\\temp\\_mei123456", "C:\\real\\tool"])
        with patch.dict(os.environ, {"PATH": fake_path}, clear=False):
            env = subprocess_env()
        self.assertEqual(env["PATH"], "C:\\real\\tool")

    @patch("depshieldx.runtime.sys")
    @patch("depshieldx.runtime.is_frozen", return_value=True)
    def test_subprocess_env_frozen_without_meipass_in_path_is_unchanged(self, _mock_frozen, mock_sys):
        mock_sys._MEIPASS = self.FAKE_MEIPASS
        fake_path = os.pathsep.join([self.FAKE_TOOL_A, self.FAKE_TOOL_B])
        with patch.dict(os.environ, {"PATH": fake_path}, clear=False):
            env = subprocess_env()
        self.assertEqual(env["PATH"], fake_path)

    @patch("depshieldx.runtime.sys")
    @patch("depshieldx.runtime.is_frozen", return_value=True)
    def test_subprocess_env_does_not_mutate_os_environ(self, _mock_frozen, mock_sys):
        mock_sys._MEIPASS = self.FAKE_MEIPASS
        fake_path = os.pathsep.join([self.FAKE_MEIPASS, self.FAKE_TOOL_A])
        with patch.dict(os.environ, {"PATH": fake_path}, clear=False):
            subprocess_env()
            self.assertEqual(os.environ["PATH"], fake_path)


if __name__ == "__main__":
    unittest.main()
