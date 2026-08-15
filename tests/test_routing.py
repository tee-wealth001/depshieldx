import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from depshieldx.routing import disable_routing, enable_routing, get_routing_status


class RoutingTests(unittest.TestCase):
    def test_enable_routing_writes_posix_shim(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(os.environ, {"DEPSHIELDX_CACHE_DIR": temp_dir}, clear=False):
                with patch("depshieldx.routing._is_windows", return_value=False):
                    status = enable_routing()
                    shim_path = Path(status["shim_path"])

                    self.assertTrue(status["enabled"])
                    self.assertEqual(shim_path.name, "pip")
                    self.assertTrue(shim_path.exists())
                    self.assertEqual(
                        shim_path.read_text(),
                        "#!/bin/sh\nexec depshieldx route-pip \"$@\"\n",
                    )
                    self.assertEqual(
                        status["activation_hint"],
                        f'export PATH="{shim_path.parent}:$PATH"',
                    )

    def test_enable_routing_writes_windows_batch_shim(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(os.environ, {"DEPSHIELDX_CACHE_DIR": temp_dir}, clear=False):
                with patch("depshieldx.routing._is_windows", return_value=True):
                    status = enable_routing()
                    shim_path = Path(status["shim_path"])

                    self.assertTrue(status["enabled"])
                    self.assertEqual(shim_path.name, "pip.bat")
                    self.assertTrue(shim_path.exists())
                    self.assertEqual(
                        shim_path.read_text(),
                        "@echo off\ndepshieldx route-pip %*\n",
                    )
                    self.assertEqual(
                        status["activation_hint"],
                        f'PowerShell: $env:PATH = "{shim_path.parent};$env:PATH"'
                        f" | cmd.exe: set PATH={shim_path.parent};%PATH%",
                    )

    def test_disable_routing_removes_existing_shims(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(os.environ, {"DEPSHIELDX_CACHE_DIR": temp_dir}, clear=False):
                shim_dir = Path(temp_dir) / "routing" / "shims"
                shim_dir.mkdir(parents=True, exist_ok=True)
                (shim_dir / "pip").write_text("old-posix")
                (shim_dir / "pip.bat").write_text("old-windows")

                status = disable_routing()

                self.assertFalse(status["enabled"])
                self.assertFalse((shim_dir / "pip").exists())
                self.assertFalse((shim_dir / "pip.bat").exists())

    def test_get_routing_status_is_enabled_when_windows_shim_exists(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(os.environ, {"DEPSHIELDX_CACHE_DIR": temp_dir}, clear=False):
                routing_root = Path(temp_dir) / "routing"
                shim_dir = routing_root / "shims"
                shim_dir.mkdir(parents=True, exist_ok=True)
                (routing_root / "state.json").write_text(
                    '{\n  "enabled": true,\n  "prompt_dismissed": false,\n  "state_version": 2\n}\n'
                )
                (shim_dir / "pip.bat").write_text("@echo off\n")

                with patch("depshieldx.routing._is_windows", return_value=True):
                    status = get_routing_status()

                self.assertTrue(status["enabled"])
                self.assertTrue(status["shim_path"].endswith("pip.bat"))


if __name__ == "__main__":
    unittest.main()
