"""Tests for packaging/rthook_reset_dll_directory.py -- the PyInstaller
runtime hook that fixes a real, confirmed Windows-only bug: composer ->
php.exe (and potentially other external toolchains) resolving depshieldx's
own bundled vcruntime140.dll instead of a compatible system one, because
PyInstaller's onefile bootloader sets a process-wide DLL search directory
that leaks to child processes. See that module's own docstring for the
full, confirmed-directly investigation.

This module is loaded as a PyInstaller runtime hook (executed for its
side effect at import time), not through depshieldx's own package
namespace -- these tests load it directly by file path.
"""

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

RTHOOK_PATH = Path(__file__).resolve().parent.parent / "packaging" / "rthook_reset_dll_directory.py"


def _load_rthook_module():
    spec = importlib.util.spec_from_file_location("rthook_reset_dll_directory", RTHOOK_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ResetDllDirectoryRuntimeHookTests(unittest.TestCase):
    def test_file_exists_and_is_referenced_by_the_spec(self):
        self.assertTrue(RTHOOK_PATH.exists())
        spec_text = (RTHOOK_PATH.parent / "depshieldx.spec").read_text(encoding="utf-8")
        self.assertIn("rthook_reset_dll_directory.py", spec_text)

    def test_is_a_no_op_on_non_windows_platforms(self):
        # Confirmed directly this bug and its fix are both Windows-only
        # (composer -> php.exe DLL resolution is a Windows DLL-search-
        # order concern) -- must not attempt any ctypes.windll access at
        # all on POSIX, where that attribute doesn't exist.
        with patch.object(sys, "platform", "linux"):
            try:
                _load_rthook_module()
            except AttributeError as exc:
                self.fail(f"runtime hook touched ctypes.windll on a non-Windows platform: {exc}")

    def test_calls_set_dll_directory_with_none_on_windows(self):
        # SetDllDirectoryW(None) is required, not cosmetic -- confirmed
        # directly against a real Windows release binary and a series of
        # minimal repro builds that this exact call (reached only after
        # depshieldx's own bundled DLLs have already loaded successfully)
        # is what stops a real external toolchain subprocess from
        # resolving depshieldx's own bundled vcruntime140.dll instead of
        # a real, compatible one.
        fake_kernel32 = MagicMock()
        fake_windll = MagicMock(kernel32=fake_kernel32)
        fake_ctypes_module = MagicMock(windll=fake_windll)

        with patch.object(sys, "platform", "win32"):
            with patch.dict(sys.modules, {"ctypes": fake_ctypes_module}):
                _load_rthook_module()

        fake_kernel32.SetDllDirectoryW.assert_called_once_with(None)


if __name__ == "__main__":
    unittest.main()
